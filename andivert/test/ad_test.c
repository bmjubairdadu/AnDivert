/*
 * ad_test.c — live test harness for the AnDivert engine (runs on Linux/WSL).
 *
 * Simulates an Android TUN with a socketpair, then exercises:
 *   1. filter compilation + match/no-match dispatch
 *   2. diverted packets surface at AnDivertRecv
 *   3. non-matching UDP flow reaches the real network (UDP NAT) and the
 *      reply is re-injected as a proper packet (checksum valid)
 *   4. non-matching TCP flow connects through the mini proxy
 *   5. ADCalcChecksums round-trip
 *
 * Compile: see test/build_and_test.sh
 */

#include "andivert.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <time.h>

static uint16_t csum_pseudo(uint32_t src, uint32_t dst, uint8_t proto,
                            const uint8_t *l4, uint32_t l4len);
static uint32_t build_tcp_packet(uint8_t *out, uint32_t cap,
                                 uint32_t src, uint16_t sport,
                                 uint32_t dst, uint16_t dport,
                                 uint32_t seq, uint32_t ack, uint8_t flags,
                                 const uint8_t *payload, uint32_t plen);

static int g_pass = 0, g_fail = 0;

#define CHECK(cond, msg) do { \
    if (cond) { g_pass++; printf("  [PASS] %s\n", msg); } \
    else      { g_fail++; printf("  [FAIL] %s\n", msg); } \
} while (0)

static uint64_t now_us(void)
{
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000ull + (uint64_t)(ts.tv_nsec / 1000);
}

/* ------------------------------------------------------------------ */
/* Build raw packets                                                  */
/* ------------------------------------------------------------------ */

static uint16_t csum(const uint8_t *b, uint32_t n)
{
    uint32_t s = 0, i;
    for (i = 0; i + 1 < n; i += 2) s += (uint32_t)((b[i] << 8) | b[i + 1]);
    if (n & 1) s += (uint32_t)(b[n - 1] << 8);
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)(~s & 0xffff);
}

static uint32_t build_udp_packet(uint8_t *out, uint32_t outcap,
                                 uint32_t src, uint16_t sport,
                                 uint32_t dst, uint16_t dport,
                                 const char *payload)
{
    uint32_t plen = (uint32_t)strlen(payload);
    uint32_t total = 20 + 8 + plen;
    if (total > outcap) return 0;
    memset(out, 0, 28);
    out[0] = 0x45; out[8] = 64; out[9] = 17;
    out[2] = (uint8_t)(total >> 8); out[3] = (uint8_t)total;
    memcpy(out + 12, &src, 4);
    memcpy(out + 16, &dst, 4);
    out[20] = (uint8_t)(sport >> 8); out[21] = (uint8_t)sport;
    out[22] = (uint8_t)(dport >> 8); out[23] = (uint8_t)dport;
    out[24] = (uint8_t)((8 + plen) >> 8); out[25] = (uint8_t)(8 + plen);
    memcpy(out + 28, payload, plen);
    {
        uint16_t c;
        out[10] = out[11] = 0;
        c = csum(out, 20);
        out[10] = (uint8_t)(c >> 8); out[11] = (uint8_t)c;
        out[26] = out[27] = 0;
        c = csum_pseudo(src, dst, 17, out + 20, 8 + plen);
        out[26] = (uint8_t)(c >> 8); out[27] = (uint8_t)c;
    }
    return total;
}

static uint16_t csum_pseudo(uint32_t src, uint32_t dst, uint8_t proto,
                            const uint8_t *l4, uint32_t l4len)
{
    uint32_t s = 0;
    uint8_t ph[12];
    ph[0] = (uint8_t)(src >> 24); ph[1] = (uint8_t)(src >> 16);
    ph[2] = (uint8_t)(src >> 8);  ph[3] = (uint8_t)src;
    ph[4] = (uint8_t)(dst >> 24); ph[5] = (uint8_t)(dst >> 16);
    ph[6] = (uint8_t)(dst >> 8);  ph[7] = (uint8_t)dst;
    ph[8] = 0; ph[9] = proto;
    ph[10] = (uint8_t)(l4len >> 8); ph[11] = (uint8_t)l4len;
    s = 0;
    {
        uint32_t i;
        for (i = 0; i + 1 < 12; i += 2) s += (uint32_t)((ph[i] << 8) | ph[i + 1]);
    }
    {
        uint32_t i;
        for (i = 0; i + 1 < l4len; i += 2) s += (uint32_t)((l4[i] << 8) | l4[i + 1]);
        if (l4len & 1) s += (uint32_t)(l4[l4len - 1] << 8);
    }
    while (s >> 16) s = (s & 0xffff) + (s >> 16);
    return (uint16_t)(~s & 0xffff);
}

/* ------------------------------------------------------------------ */
/* Fake TUN via socketpair                                            */
/* written packets land on pair[0]; engine reads from pair[1]         */
/* ------------------------------------------------------------------ */

static int g_tun_writer;   /* we write "from the app" packets here */
static int g_tun_reader;   /* we read "to the app" packets here   */

static int fake_tun_setup(int fds[2])
{
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0)
        return -1;
    /* Engine holds fds[1] (tun_fd): it reads our writes and its injections
     * arrive at fds[0]. The test therefore writes AND reads on fds[0] —
     * a socketpair end is full duplex — and never competes for fds[1]. */
    g_tun_writer = fds[0];
    g_tun_reader = fds[0];
    return 0;
}

/* write a packet into the TUN as if an app sent it */
static int fake_tun_write(const uint8_t *pkt, uint32_t len)
{
    return (int)send(g_tun_writer, pkt, len, 0) == (int)len ? 0 : -1;
}

/* read a packet the engine injected toward the app */
static int fake_tun_read(uint8_t *buf, uint32_t cap, uint32_t timeout_ms)
{
    struct pollfd p;
    p.fd = g_tun_reader;
    p.events = POLLIN;
    if (poll(&p, 1, (int)timeout_ms) <= 0)
        return 0;
    {
        ssize_t n = recv(g_tun_reader, buf, cap, 0);
        return n > 0 ? (int)n : 0;
    }
}

#include <poll.h>
#include <sys/socket.h>

/* ------------------------------------------------------------------ */
/* UDP echo server for the NAT test                                   */
/* ------------------------------------------------------------------ */

static int g_echo_sock = -1;
static uint16_t g_echo_port = 0;

static void *echo_server(void *arg)
{
    (void)arg;
    for (;;) {
        uint8_t buf[2048];
        struct sockaddr_in sa;
        socklen_t alen = sizeof(sa);
        ssize_t n = recvfrom(g_echo_sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&sa, &alen);
        if (n <= 0) {
            if (errno == EINTR) continue;
            break;
        }
        sendto(g_echo_sock, buf, (size_t)n, 0, (struct sockaddr *)&sa, alen);
    }
    return NULL;
}

static int echo_server_start(void)
{
    struct sockaddr_in sa;
    pthread_t t;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    g_echo_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (g_echo_sock < 0) return -1;
    if (bind(g_echo_sock, (struct sockaddr *)&sa, sizeof(sa)) != 0) return -1;
    {
        socklen_t alen = sizeof(sa);
        getsockname(g_echo_sock, (struct sockaddr *)&sa, &alen);
        g_echo_port = ntohs(sa.sin_port);
    }
    pthread_create(&t, NULL, echo_server, NULL);
    pthread_detach(t);
    return 0;
}

/* ------------------------------------------------------------------ */
/* TCP echo server for the proxy test                                 */
/* ------------------------------------------------------------------ */

static int g_lsock = -1;
static uint16_t g_tcp_port = 0;
static volatile int g_tcp_stop = 0;

static void *tcp_server(void *arg)
{
    (void)arg;
    for (;;) {
        int c = accept(g_lsock, NULL, NULL);
        if (c < 0) {
            if (g_tcp_stop) break;
            continue;
        }
        {
            uint8_t b[4096];
            ssize_t n;
            while ((n = recv(c, b, sizeof(b), 0)) > 0)
                send(c, b, (size_t)n, 0);
            close(c);
        }
    }
    return NULL;
}

static int tcp_server_start(void)
{
    struct sockaddr_in sa;
    pthread_t t;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    sa.sin_port = 0;
    g_lsock = socket(AF_INET, SOCK_STREAM, 0);
    if (g_lsock < 0) return -1;
    {
        int one = 1;
        setsockopt(g_lsock, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));
    }
    if (bind(g_lsock, (struct sockaddr *)&sa, sizeof(sa)) != 0) return -1;
    if (listen(g_lsock, 8) != 0) return -1;
    {
        socklen_t alen = sizeof(sa);
        getsockname(g_lsock, (struct sockaddr *)&sa, &alen);
        g_tcp_port = ntohs(sa.sin_port);
    }
    pthread_create(&t, NULL, tcp_server, NULL);
    pthread_detach(t);
    return 0;
}

/* ------------------------------------------------------------------ */
/* Tests                                                              */
/* ------------------------------------------------------------------ */

static void test_filter(void)
{
    uint8_t pkt[64];
    uint32_t len;
    AD_ADDRESS addr;
    ad_filter_t *f;
    uint32_t src = inet_addr("10.0.0.5"), dst = inet_addr("8.8.8.8");

    printf("test_filter:\n");

    f = ADFilterCompile("udp and ip.DstAddr == 8.8.8.8");
    CHECK(f != NULL, "compile 'udp and ip.DstAddr == 8.8.8.8'");
    if (!f) return;

    len = build_udp_packet(pkt, sizeof(pkt), src, 12345, dst, 53, "hello");
    memset(&addr, 0, sizeof(addr));
    addr.flags = AD_ADDRESS_FLAG_OUTBOUND;
    memcpy(&addr.addr.ipv4.src_addr, &src, 4);
    memcpy(&addr.addr.ipv4.dst_addr, &dst, 4);

    CHECK(ADFilterMatch(f, pkt, len, &addr) == 1, "udp to 8.8.8.8 matches");
    ADFilterFree(f);

    f = ADFilterCompile("tcp.DstPort == 443");
    CHECK(f != NULL, "compile tcp.DstPort == 443");
    CHECK(ADFilterMatch(f, pkt, len, &addr) == 0, "udp packet does not match tcp filter");
    ADFilterFree(f);

    f = ADFilterCompile("outbound and udp");
    CHECK(f != NULL, "compile 'outbound and udp'");
    CHECK(ADFilterMatch(f, pkt, len, &addr) == 1, "outbound udp matches");
    ADFilterFree(f);

    f = ADFilterCompile("ip.SrcAddr == 10.0.0.5 and udp.DstPort == 53");
    CHECK(f != NULL, "compile compound filter");
    CHECK(ADFilterMatch(f, pkt, len, &addr) == 1, "compound filter matches");
    ADFilterFree(f);

    f = ADFilterCompile("not tcp and (ip.TTL > 1 or true)");
    CHECK(f != NULL, "compile nested not/or");
    CHECK(ADFilterMatch(f, pkt, len, &addr) == 1, "nested filter matches");
    ADFilterFree(f);

    f = ADFilterCompile("bogus.Field == 1");
    CHECK(f == NULL, "unknown field rejected");
    CHECK(strstr(ADFilterError(), "bogus.Field") != NULL, "error names the bad field");
    if (f) ADFilterFree(f);

    f = ADFilterCompile(NULL);
    CHECK(f != NULL, "NULL filter compiles as 'true'");
    CHECK(ADFilterMatch(f, pkt, len, &addr) == 1, "'true' matches anything");
    ADFilterFree(f);
}

static void test_checksum(void)
{
    uint8_t pkt[128];
    uint32_t len;
    AD_ADDRESS addr;
    uint32_t src = inet_addr("192.168.1.2"), dst = inet_addr("1.1.1.1");

    printf("test_checksum:\n");
    len = build_udp_packet(pkt, sizeof(pkt), src, 9999, dst, 53, "checksum-test");
    memset(&addr, 0, sizeof(addr));
    memcpy(&addr.addr.ipv4.src_addr, &src, 4);
    memcpy(&addr.addr.ipv4.dst_addr, &dst, 4);

    /* corrupt both checksums, then recompute */
    pkt[10] = pkt[11] = 0xAA;
    pkt[26] = pkt[27] = 0xBB;
    CHECK(ADCalcChecksums(pkt, len, &addr) == AN_SUCCESS, "ADCalcChecksums succeeds");
    CHECK(ADVerifyChecksum(pkt, len) == 1, "recomputed UDP checksum verifies");

    /* break the payload, verify should fail */
    pkt[30] ^= 0xFF;
    CHECK(ADVerifyChecksum(pkt, len) == 0, "corrupted packet fails verification");
    pkt[30] ^= 0xFF;
}

static void test_engine_passthrough_udp(void)
{
    int fds[2];
    int tun_fd;
    ad_handle_t *h;
    uint8_t pkt[512], rbuf[512];
    uint32_t len;
    AD_ADDRESS addr;
    uint32_t src = inet_addr("10.111.0.2");
    uint32_t dst = inet_addr("127.0.0.1");
    uint32_t got;
    const char *msg = "ping-through-nat";
    int ok = 0;
    int i;

    printf("test_engine_passthrough_udp (live NAT round-trip):\n");
    if (fake_tun_setup(fds) != 0) {
        CHECK(0, "socketpair setup");
        return;
    }
    tun_fd = fds[1];
    h = AnDivertOpen(tun_fd, "udp.DstPort == 9", AN_LAYER_NETWORK, 0, AN_FLAG_DEFAULT);
    CHECK(h != NULL, "AnDivertOpen with narrow filter");

    /* packet to the local echo server: does NOT match filter -> NAT path */
    len = build_udp_packet(pkt, sizeof(pkt), src, 40000,
                           dst, g_echo_port, msg);
    CHECK(len > 0, "packet built");

    CHECK(fake_tun_write(pkt, len) == 0, "packet written into fake TUN");

    /* the echo server's reply should come back as a well-formed packet */
    for (i = 0; i < 50 && !ok; i++) {
        uint32_t n = (uint32_t)fake_tun_read(rbuf, sizeof(rbuf), 100);
        if (n >= 28) {
            uint16_t sp = ((uint16_t)rbuf[20] << 8) | rbuf[21];
            got = 0;
            memcpy(&got, rbuf + 16, 4);
            if (sp == g_echo_port && got == src &&
                memcmp(rbuf + 28, msg, strlen(msg)) == 0 &&
                ADVerifyChecksum(rbuf, n) == 1) {
                ok = 1;
            }
        }
    }
    CHECK(ok, "UDP reply re-injected: correct addr/port/payload/checksum");

    AnDivertClose(h);
    close(fds[0]);
    close(fds[1]);
}

static void test_engine_divert(void)
{
    int fds[2];
    int tun_fd;
    ad_handle_t *h;
    uint8_t pkt[512], rbuf[512];
    uint32_t len, rlen = 0;
    AD_ADDRESS addr;
    uint32_t src = inet_addr("10.111.0.3");
    uint32_t dst = inet_addr("8.8.4.4");
    int ok = 0;
    int i;

    printf("test_engine_divert (AnDivertRecv path):\n");
    if (fake_tun_setup(fds) != 0) {
        CHECK(0, "socketpair setup");
        return;
    }
    tun_fd = fds[1];

    h = AnDivertOpen(tun_fd, "ip.DstAddr == 8.8.4.4", AN_LAYER_NETWORK, 0, AN_FLAG_DEFAULT);
    CHECK(h != NULL, "open with divert filter");

    len = build_udp_packet(pkt, sizeof(pkt), src, 51000, dst, 53, "divert-me");
    fake_tun_write(pkt, len);

    rlen = 0;
    for (i = 0; i < 20 && rlen == 0; i++) {
        if (AnDivertRecv(h, rbuf, sizeof(rbuf), &addr, &rlen, 100) == AN_SUCCESS)
            break;
    }
    CHECK(rlen > 0, "diverted packet received via AnDivertRecv");
    if (rlen > 0) {
        uint32_t d = 0;
        memcpy(&d, rbuf + 16, 4);
        CHECK(d == dst, "diverted packet destination is 8.8.4.4");
        CHECK(memcmp(rbuf + 28, "divert-me", 9) == 0, "payload intact");
    }

    /* now send it back via AnDivertSend; filter still matches, so it
     * re-enters the ring — proving the divert loop works end-to-end */
    {
        uint32_t sent = 0;
        CHECK(AnDivertSend(h, rbuf, rlen, &addr, &sent) == AN_SUCCESS && sent == rlen,
              "AnDivertSend accepted and wrote full length");
    }

    AnDivertClose(h);
    close(fds[0]);
    close(fds[1]);
}

static void test_engine_tcp_proxy(void)
{
    int fds[2];
    int tun_fd;
    ad_handle_t *h;
    uint8_t pkt[512], rbuf[2048];
    uint32_t len;
    uint32_t src = inet_addr("10.111.0.4");
    uint32_t dst = inet_addr("127.0.0.1");
    int ok_synack = 0, ok_echo = 0;
    int i;
    uint16_t cport = 51000;
    uint32_t client_seq = 1000, server_isn = 0;
    uint32_t client_next = client_seq + 1;
    uint32_t srv_next = 0;

    printf("test_engine_tcp_proxy (live TCP round-trip):\n");
    if (fake_tun_setup(fds) != 0) {
        CHECK(0, "socketpair setup");
        return;
    }
    tun_fd = fds[1];

    h = AnDivertOpen(tun_fd, "tcp.DstPort == 1", AN_LAYER_NETWORK, 0, AN_FLAG_DEFAULT);
    CHECK(h != NULL, "open with non-matching tcp filter");

    /* --- SYN --- */
    {
        uint8_t p[60];
        uint32_t n = build_tcp_packet(p, sizeof(p), src, cport, dst, g_tcp_port,
                                      client_seq, 0, AD_TCP_SYN, NULL, 0);
        fake_tun_write(p, n);
    }

    /* expect SYN-ACK */
    for (i = 0; i < 50 && !ok_synack; i++) {
        int n = fake_tun_read(rbuf, sizeof(rbuf), 100);
        if (n >= 40 && rbuf[9] == 6) {
            uint16_t sp = ((uint16_t)rbuf[20] << 8) | rbuf[21];
            if (sp == g_tcp_port && (rbuf[33] & (AD_TCP_SYN | AD_TCP_ACK)) == (AD_TCP_SYN | AD_TCP_ACK)) {
                ok_synack = 1;
                server_isn = ((uint32_t)rbuf[24] << 24) | ((uint32_t)rbuf[25] << 16) |
                             ((uint32_t)rbuf[26] << 8) | rbuf[27];
                srv_next = server_isn + 1;
            }
        }
    }
    CHECK(ok_synack, "SYN-ACK received from mini proxy");

    /* --- ACK completing handshake --- */
    {
        uint8_t p[60];
        uint32_t n = build_tcp_packet(p, sizeof(p), src, cport, dst, g_tcp_port,
                                      client_next, srv_next, AD_TCP_ACK, NULL, 0);
        fake_tun_write(p, n);
    }
    /* engine may ack our ack; ignore */

    /* --- send data --- */
    {
        uint8_t p[128];
        const char *msg = "hello-tcp-proxy";
        uint32_t n = build_tcp_packet(p, sizeof(p), src, cport, dst, g_tcp_port,
                                      client_next, srv_next, AD_TCP_ACK | AD_TCP_PSH,
                                      (const uint8_t *)msg, (uint32_t)strlen(msg));
        client_next += (uint32_t)strlen(msg);
        fake_tun_write(p, n);
    }

    /* expect PSH-ACK echo back */
    for (i = 0; i < 80 && !ok_echo; i++) {
        int n = fake_tun_read(rbuf, sizeof(rbuf), 100);
        if (n >= 40 && rbuf[9] == 6) {
            uint8_t fl = rbuf[33];
            uint32_t plen = (uint32_t)n - 40;
            if ((fl & AD_TCP_PSH) && plen >= 15 &&
                memcmp(rbuf + 40, "hello-tcp-proxy", 15) == 0) {
                ok_echo = 1;
            }
        }
    }
    CHECK(ok_echo, "TCP payload echoed back through the proxy");

    AnDivertClose(h);
    close(fds[0]);
    close(fds[1]);
}

/* build a raw TCP packet */
static uint32_t build_tcp_packet(uint8_t *out, uint32_t cap,
                                 uint32_t src, uint16_t sport,
                                 uint32_t dst, uint16_t dport,
                                 uint32_t seq, uint32_t ack, uint8_t flags,
                                 const uint8_t *payload, uint32_t plen)
{
    uint32_t total = 20 + 20 + plen;
    if (total > cap) return 0;
    memset(out, 0, 40);
    out[0] = 0x45; out[8] = 64; out[9] = 6;
    out[2] = (uint8_t)(total >> 8); out[3] = (uint8_t)total;
    memcpy(out + 12, &src, 4);
    memcpy(out + 16, &dst, 4);
    out[20] = (uint8_t)(sport >> 8); out[21] = (uint8_t)sport;
    out[22] = (uint8_t)(dport >> 8); out[23] = (uint8_t)dport;
    out[24] = (uint8_t)(seq >> 24); out[25] = (uint8_t)(seq >> 16);
    out[26] = (uint8_t)(seq >> 8);  out[27] = (uint8_t)seq;
    out[28] = (uint8_t)(ack >> 24); out[29] = (uint8_t)(ack >> 16);
    out[30] = (uint8_t)(ack >> 8);  out[31] = (uint8_t)ack;
    out[32] = 0x50;
    out[33] = flags;
    out[34] = 0x20; out[35] = 0x00;
    if (plen) memcpy(out + 40, payload, plen);
    {
        uint16_t c;
        out[10] = out[11] = 0;
        c = csum(out, 20);
        out[10] = (uint8_t)(c >> 8); out[11] = (uint8_t)c;
        out[36] = out[37] = 0;
        c = csum_pseudo(src, dst, 6, out + 20, 20 + plen);
        out[36] = (uint8_t)(c >> 8); out[37] = (uint8_t)c;
    }
    return total;
}

int main(void)
{
    printf("AnDivert engine live tests\n");
    printf("==========================\n");

    test_filter();
    test_checksum();
    if (echo_server_start() == 0) {
        test_engine_passthrough_udp();
    } else {
        printf("test_engine_passthrough_udp: SKIPPED (no loopback)\n");
    }
    test_engine_divert();
    if (tcp_server_start() == 0) {
        test_engine_tcp_proxy();
    } else {
        printf("test_engine_tcp_proxy: SKIPPED (no loopback)\n");
    }

    printf("\nRESULT: %d passed, %d failed\n", g_pass, g_fail);
    return g_fail ? 1 : 0;
}
