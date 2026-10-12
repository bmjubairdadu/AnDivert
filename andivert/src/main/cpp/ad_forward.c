/*
 * ad_forward.c — user-mode forwarding stack for non-matching packets.
 *
 * Traffic that does NOT match the developer's filter must still flow,
 * because on Android the TUN swallows *all* traffic once the VPN is up.
 * This file re-implements the minimal plumbing NetGuard/PCAPdroid use:
 *
 *   UDP  -> per-flow NAT: one protected datagram socket per virtual flow,
 *           replies are rewritten back into a packet addressed to the
 *           virtual client and injected into the TUN.
 *   TCP  -> a client-side mini TCP state machine terminating the app's
 *           connection and relaying bytes over a protected stream socket.
 *   ICMP -> echo requests answered directly, everything else dropped.
 *
 * All sockets should be protected from the VPN loop by the JNI layer via
 * the registered ad_set_protect_fn() hook (VpnService.protect()).
 */

#include "ad_internal.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>
#include <poll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <fcntl.h>

/* Optional JNI hook: int protect(int fd). Set from Java/JNI side. */
static int (*g_protect_fn)(int fd) = NULL;

void ad_set_protect_fn(int (*fn)(int fd))
{
    g_protect_fn = fn;
}

/* ------------------------------------------------------------------ */
/* Small helpers                                                      */
/* ------------------------------------------------------------------ */

static uint32_t now_s(void)
{
    return (uint32_t)time(NULL);
}

static int ad_make_socket(int udp)
{
    int fd = socket(AF_INET, udp ? SOCK_DGRAM : SOCK_STREAM, 0);
    if (fd < 0)
        return -1;
    if (g_protect_fn && g_protect_fn(fd) != 0) {
        ad_log_warn("protect(fd=%d) failed", fd);
    }
    {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0)
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    if (!udp) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags >= 0)
            fcntl(fd, F_SETFL, flags | O_NONBLOCK);
    }
    return fd;
}

static int ad_sock_sendto(int fd, uint32_t ip_be, uint16_t port_h,
                          const uint8_t *data, uint32_t len)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ip_be;
    sa.sin_port = htons(port_h);
    return (int)sendto(fd, data, len, 0, (struct sockaddr *)&sa, sizeof(sa));
}

static int ad_sock_connect(int fd, uint32_t ip_be, uint16_t port_h)
{
    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = ip_be;
    sa.sin_port = htons(port_h);
    return connect(fd, (struct sockaddr *)&sa, sizeof(sa));
}

/* Inject an IPv4+UDP packet into the TUN. */
static void ad_inject_udp(ad_handle_t *h, uint32_t src_ip, uint16_t sport,
                          uint32_t dst_ip, uint16_t dport,
                          const uint8_t *payload, uint32_t plen)
{
    uint8_t buf[AD_MAX_PACKET];
    uint32_t total = 20 + 8 + plen;
    AD_ADDRESS addr;

    if (total > AD_MAX_PACKET || total > (uint32_t)h->vpn_mtu)
        return;
    memset(buf, 0, 20 + 8);
    buf[0] = 0x45;
    buf[2] = (uint8_t)(total >> 8);
    buf[3] = (uint8_t)(total & 0xff);
    buf[4] = (uint8_t)((h->stats.bytes_out >> 8) & 0xff);  /* id, whatever */
    buf[6] = 0x40;              /* DF */
    buf[8] = 64;                /* TTL */
    buf[9] = 17;                /* UDP */
    memcpy(buf + 12, &src_ip, 4);
    memcpy(buf + 16, &dst_ip, 4);
    buf[20] = (uint8_t)(sport >> 8);
    buf[21] = (uint8_t)(sport & 0xff);
    buf[22] = (uint8_t)(dport >> 8);
    buf[23] = (uint8_t)(dport & 0xff);
    buf[24] = (uint8_t)((8 + plen) >> 8);
    buf[25] = (uint8_t)((8 + plen) & 0xff);
    if (plen)
        memcpy(buf + 28, payload, plen);

    memset(&addr, 0, sizeof(addr));
    addr.flags = AD_ADDRESS_FLAG_INBOUND;
    addr.layer = AN_LAYER_NETWORK;
    memcpy(&addr.addr.ipv4.src_addr, &src_ip, 4);
    memcpy(&addr.addr.ipv4.dst_addr, &dst_ip, 4);
    ADCalcChecksums(buf, total, &addr);

    if (write(h->tun_fd, buf, total) == (ssize_t)total) {
        pthread_mutex_lock(&h->stats_lock);
        h->stats.bytes_out += total;
        pthread_mutex_unlock(&h->stats_lock);
    }
}

/* Inject an IPv4+TCP packet into the TUN using connection bookkeeping. */
static void ad_inject_tcp(ad_handle_t *h, ad_tcp_conn_t *c, uint8_t flags,
                          const uint8_t *payload, uint32_t plen)
{
    uint8_t buf[AD_MAX_PACKET];
    uint32_t total = 20 + 20 + plen;
    AD_ADDRESS addr;

    if (total > AD_MAX_PACKET)
        return;
    if (plen && total > (uint32_t)h->vpn_mtu)
        plen = (uint32_t)h->vpn_mtu - 40, total = 20 + 20 + plen;

    memset(buf, 0, 40);
    buf[0] = 0x45;
    buf[2] = (uint8_t)(total >> 8);
    buf[3] = (uint8_t)(total & 0xff);
    buf[6] = 0x40;
    buf[8] = 64;
    buf[9] = 6;
    memcpy(buf + 12, &c->dst_ip, 4);
    memcpy(buf + 16, &c->client_ip, 4);

    buf[20] = (uint8_t)(c->dst_port >> 8);
    buf[21] = (uint8_t)(c->dst_port & 0xff);
    buf[22] = (uint8_t)(c->client_port >> 8);
    buf[23] = (uint8_t)(c->client_port & 0xff);
    buf[24] = (uint8_t)(c->vseq >> 24);
    buf[25] = (uint8_t)(c->vseq >> 16);
    buf[26] = (uint8_t)(c->vseq >> 8);
    buf[27] = (uint8_t)(c->vseq);
    buf[28] = (uint8_t)(c->vack >> 24);
    buf[29] = (uint8_t)(c->vack >> 16);
    buf[30] = (uint8_t)(c->vack >> 8);
    buf[31] = (uint8_t)(c->vack);
    buf[32] = 0x50;
    buf[33] = flags;
    buf[34] = 0x20; buf[35] = 0x00;   /* window 8192 */
    if (plen)
        memcpy(buf + 40, payload, plen);

    memset(&addr, 0, sizeof(addr));
    addr.flags = AD_ADDRESS_FLAG_INBOUND;
    addr.layer = AN_LAYER_NETWORK;
    memcpy(&addr.addr.ipv4.src_addr, &c->dst_ip, 4);
    memcpy(&addr.addr.ipv4.dst_addr, &c->client_ip, 4);
    ADCalcChecksums(buf, total, &addr);

    if (write(h->tun_fd, buf, total) == (ssize_t)total) {
        c->vseq += plen;
        pthread_mutex_lock(&h->stats_lock);
        h->stats.bytes_out += total;
        pthread_mutex_unlock(&h->stats_lock);
    }
}

/* ------------------------------------------------------------------ */
/* UDP NAT                                                            */
/* ------------------------------------------------------------------ */

static ad_udp_flow_t *ad_udp_flow_get(ad_handle_t *h, uint32_t cip,
                                      uint16_t cport, uint8_t proto)
{
    int i, slot = -1, oldest = -1;
    uint32_t oldest_t = 0xFFFFFFFFu;

    pthread_mutex_lock(&h->nat_lock);
    for (i = 0; i < AD_MAX_UDP_FLOWS; i++) {
        ad_udp_flow_t *f = &h->udp_flows[i];
        if (!f->in_use) {
            if (slot < 0) slot = i;
            continue;
        }
        if (f->client_ip == cip && f->client_port == cport && f->proto == proto) {
            f->last_used = now_s();
            pthread_mutex_unlock(&h->nat_lock);
            return f;
        }
        if (f->last_used < oldest_t) { oldest_t = f->last_used; oldest = i; }
    }
    if (slot < 0 && oldest >= 0) {
        ad_udp_flow_t *f = &h->udp_flows[oldest];
        if (f->sock >= 0) close(f->sock);
        memset(f, 0, sizeof(*f));
        slot = oldest;
    }
    if (slot < 0) {
        pthread_mutex_unlock(&h->nat_lock);
        return NULL;
    }
    {
        ad_udp_flow_t *f = &h->udp_flows[slot];
        int fd = ad_make_socket(1);
        if (fd < 0) {
            pthread_mutex_unlock(&h->nat_lock);
            return NULL;
        }
        struct sockaddr_in sa;
        socklen_t alen = sizeof(sa);
        memset(&sa, 0, sizeof(sa));
        sa.sin_family = AF_INET;
        sa.sin_addr.s_addr = htonl(INADDR_ANY);
        sa.sin_port = 0;
        if (bind(fd, (struct sockaddr *)&sa, sizeof(sa)) != 0 ||
            getsockname(fd, (struct sockaddr *)&sa, &alen) != 0) {
            close(fd);
            pthread_mutex_unlock(&h->nat_lock);
            return NULL;
        }
        f->in_use = 1;
        f->sock = fd;
        f->client_ip = cip;
        f->client_port = cport;
        f->proto = proto;
        f->local_port = ntohs(sa.sin_port);
        f->last_used = now_s();
        pthread_mutex_unlock(&h->nat_lock);
        return f;
    }
}

void ad_forward_udp(ad_handle_t *h, const uint8_t *pkt, uint32_t len)
{
    int off = ad_transport_offset(pkt, len);
    uint32_t dst_ip;
    uint16_t dport, cport;
    const uint8_t *payload;
    uint32_t plen;
    ad_udp_flow_t *f;
    uint32_t cip;

    if (off < 0 || len < (uint32_t)off + 8)
        return;
    memcpy(&dst_ip, pkt + 16, 4);
    memcpy(&cip, pkt + 12, 4);
    dport = ((uint16_t)pkt[off + 2] << 8) | pkt[off + 3];
    cport = ((uint16_t)pkt[off] << 8) | pkt[off + 1];
    plen = ((uint32_t)pkt[off + 4] << 8 | pkt[off + 5]) - 8;
    if (plen > len - (uint32_t)off - 8)
        plen = len - (uint32_t)off - 8;
    payload = pkt + off + 8;

    f = ad_udp_flow_get(h, cip, cport, 17);
    if (!f) {
        ad_log_warn("udp flow table full, packet dropped");
        return;
    }
    if (ad_sock_sendto(f->sock, dst_ip, dport, payload, plen) < 0) {
        if (errno != EAGAIN && errno != EWOULDBLOCK)
            ad_log_warn("udp sendto failed: %s", strerror(errno));
    }
}

/* relay: poll all udp sockets and inject replies */
static void ad_udp_relay(ad_handle_t *h)
{
    int i;
    uint8_t buf[65536];

    pthread_mutex_lock(&h->nat_lock);
    for (i = 0; i < AD_MAX_UDP_FLOWS; i++) {
        ad_udp_flow_t *f = &h->udp_flows[i];
        struct sockaddr_in sa;
        socklen_t alen = sizeof(sa);
        ssize_t n;

        if (!f->in_use || f->sock < 0)
            continue;
        n = recvfrom(f->sock, buf, sizeof(buf), 0,
                     (struct sockaddr *)&sa, &alen);
        if (n < 0)
            continue;
        pthread_mutex_unlock(&h->nat_lock);
        ad_inject_udp(h, sa.sin_addr.s_addr, ntohs(sa.sin_port),
                      f->client_ip, f->client_port, buf, (uint32_t)n);
        pthread_mutex_lock(&h->nat_lock);
    }
    pthread_mutex_unlock(&h->nat_lock);
}

/* ------------------------------------------------------------------ */
/* TCP mini-proxy                                                     */
/* ------------------------------------------------------------------ */

static ad_tcp_conn_t *ad_tcp_conn_get(ad_handle_t *h, uint32_t cip,
                                      uint16_t cport, uint32_t sip,
                                      uint16_t sport)
{
    int i, slot = -1, oldest = -1;
    uint32_t oldest_t = 0xFFFFFFFFu;

    pthread_mutex_lock(&h->nat_lock);
    for (i = 0; i < AD_MAX_TCP_CONNS; i++) {
        ad_tcp_conn_t *c = &h->tcp_conns[i];
        if (!c->in_use) {
            if (slot < 0) slot = i;
            continue;
        }
        if (c->client_ip == cip && c->client_port == cport &&
            c->dst_ip == sip && c->dst_port == sport) {
            c->last_used = now_s();
            pthread_mutex_unlock(&h->nat_lock);
            return c;
        }
        if (c->last_used < oldest_t) { oldest_t = c->last_used; oldest = i; }
    }
    if (slot < 0 && oldest >= 0) {
        ad_tcp_conn_t *c = &h->tcp_conns[oldest];
        if (c->sock >= 0) close(c->sock);
        /* keep c->lock: it lives for the whole handle lifetime */
        c->in_use = 0;
        c->state = AD_TCP_CLOSED;
        c->sock = -1;
        c->client_ip = 0;
        c->client_port = 0;
        c->dst_ip = 0;
        c->dst_port = 0;
        c->vseq = 0;
        c->vack = 0;
        c->last_used = 0;
        slot = oldest;
    }
    if (slot < 0) {
        pthread_mutex_unlock(&h->nat_lock);
        return NULL;
    }
    pthread_mutex_unlock(&h->nat_lock);
    return &h->tcp_conns[slot];
}

void ad_forward_tcp(ad_handle_t *h, const uint8_t *pkt, uint32_t len)
{
    int off = ad_transport_offset(pkt, len);
    uint32_t cip, sip;
    uint16_t cport, sport;
    uint8_t flags;
    uint32_t seq, ack;
    uint32_t hdr, plen;
    const uint8_t *payload;
    ad_tcp_conn_t *c;

    if (off < 0 || len < (uint32_t)off + 20)
        return;
    memcpy(&cip, pkt + 12, 4);
    memcpy(&sip, pkt + 16, 4);
    cport = ((uint16_t)pkt[off] << 8) | pkt[off + 1];
    sport = ((uint16_t)pkt[off + 2] << 8) | pkt[off + 3];
    hdr   = (uint32_t)(pkt[off + 12] >> 4) * 4;
    if (hdr < 20 || len < (uint32_t)off + hdr)
        return;
    flags = pkt[off + 13];
    seq   = ((uint32_t)pkt[off + 4] << 24) | ((uint32_t)pkt[off + 5] << 16) |
            ((uint32_t)pkt[off + 6] << 8) | pkt[off + 7];
    ack   = ((uint32_t)pkt[off + 8] << 24) | ((uint32_t)pkt[off + 9] << 16) |
            ((uint32_t)pkt[off + 10] << 8) | pkt[off + 11];
    plen  = len - (uint32_t)off - hdr;
    payload = pkt + off + hdr;

    c = ad_tcp_conn_get(h, cip, cport, sip, sport);
    if (!c) {
        ad_log_warn("tcp table full, connection reset");
        return;
    }
    pthread_mutex_lock(&c->lock);

    if (flags & AD_TCP_SYN) {
        /* new or retransmitted handshake */
        if (c->in_use && (c->state == AD_TCP_SYN_RCVD || c->state == AD_TCP_ESTABLISHED)) {
            /* retransmitted SYN on live conn: re-send SYN-ACK */
            if (c->state == AD_TCP_SYN_RCVD) {
                c->vack = seq + 1;
                ad_inject_tcp(h, c, AD_TCP_SYN | AD_TCP_ACK, NULL, 0);
            }
            pthread_mutex_unlock(&c->lock);
            return;
        }
        /* fresh connection (mutex already initialized at handle creation) */
        c->in_use = 1;
        c->state = AD_TCP_SYN_RCVD;
        c->client_ip = cip;
        c->client_port = cport;
        c->dst_ip = sip;
        c->dst_port = sport;
        c->vseq = 0x10000000u;      /* fixed ISS; no middlebox sees it */
        c->vack = seq + 1;
        c->sock = ad_make_socket(0);
        c->last_used = now_s();
        if (c->sock >= 0) {
            /* nonblocking connect; completion polled in relay thread */
            ad_sock_connect(c->sock, sip, sport);
        }
        ad_inject_tcp(h, c, AD_TCP_SYN | AD_TCP_ACK, NULL, 0);
        pthread_mutex_unlock(&c->lock);
        return;
    }

    if (!c->in_use) {
        /* stray segment for unknown conn */
        pthread_mutex_unlock(&c->lock);
        return;
    }

    if (flags & AD_TCP_RST) {
        c->state = AD_TCP_CLOSED;
        if (c->sock >= 0) { close(c->sock); c->sock = -1; }
        c->in_use = 0;
        pthread_mutex_unlock(&c->lock);
        return;
    }

    if (flags & AD_TCP_FIN) {
        c->vack = ack;          /* client acked our data up to `ack` */
        if (c->state == AD_TCP_ESTABLISHED || c->state == AD_TCP_SYN_RCVD) {
            c->vack = seq + plen + 1;
            if (c->sock >= 0)
                shutdown(c->sock, SHUT_WR);
            c->state = AD_TCP_CLOSE_WAIT;
            /* ACK the FIN */
            ad_inject_tcp(h, c, AD_TCP_ACK, NULL, 0);
        } else if (c->state == AD_TCP_FIN_WAIT) {
            c->vack = seq + plen + 1;
            ad_inject_tcp(h, c, AD_TCP_ACK, NULL, 0);
            c->state = AD_TCP_CLOSED;
            if (c->sock >= 0) { close(c->sock); c->sock = -1; }
            c->in_use = 0;
        }
        pthread_mutex_unlock(&c->lock);
        return;
    }

    /* pure ACK */
    if (c->state == AD_TCP_SYN_RCVD) {
        if (c->sock >= 0) {
            int err = 0;
            socklen_t elen = sizeof(err);
            if (getsockopt(c->sock, SOL_SOCKET, SO_ERROR, &err, &elen) == 0 &&
                (err == 0 || err == EINPROGRESS || err == EWOULDBLOCK)) {
                /* connect still completing is fine: data send() below will
                 * return EAGAIN until it is done (nonblocking socket) */
                c->state = AD_TCP_ESTABLISHED;
            } else {
                /* upstream connect failed */
                ad_inject_tcp(h, c, AD_TCP_RST | AD_TCP_ACK, NULL, 0);
                c->state = AD_TCP_CLOSED;
                if (c->sock >= 0) { close(c->sock); c->sock = -1; }
                c->in_use = 0;
                pthread_mutex_unlock(&c->lock);
                return;
            }
        }
    }

    if (plen > 0 && c->state == AD_TCP_ESTABLISHED) {
        if (seq == c->vack) {
            ssize_t n = send(c->sock, payload, plen, 0);
            if (n < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                ad_inject_tcp(h, c, AD_TCP_RST | AD_TCP_ACK, NULL, 0);
                c->state = AD_TCP_CLOSED;
                if (c->sock >= 0) { close(c->sock); c->sock = -1; }
                c->in_use = 0;
                pthread_mutex_unlock(&c->lock);
                return;
            }
            c->vack += plen;
            ad_inject_tcp(h, c, AD_TCP_ACK, NULL, 0);
        }
        /* out-of-order or retransmit: drop; ACK already sent */
    } else if (plen == 0) {
        /* pure ACK: nothing to retransmit; vack tracks the client's
         * data sequence only, so leave it untouched here */
    }

    pthread_mutex_unlock(&c->lock);
}

/* relay: read upstream data for established connections and inject */
static void ad_tcp_relay(ad_handle_t *h)
{
    int i;
    uint8_t buf[16384];

    pthread_mutex_lock(&h->nat_lock);
    for (i = 0; i < AD_MAX_TCP_CONNS; i++) {
        ad_tcp_conn_t *c = &h->tcp_conns[i];
        ssize_t n;

        if (!c->in_use || c->sock < 0 || c->state != AD_TCP_ESTABLISHED)
            continue;
        n = recv(c->sock, buf, sizeof(buf), MSG_DONTWAIT);
        if (n > 0) {
            pthread_mutex_lock(&c->lock);
            ad_inject_tcp(h, c, AD_TCP_ACK | AD_TCP_PSH, buf, (uint32_t)n);
            pthread_mutex_unlock(&c->lock);
        } else if (n == 0) {
            /* upstream closed: forward FIN */
            pthread_mutex_lock(&c->lock);
            ad_inject_tcp(h, c, AD_TCP_ACK | AD_TCP_FIN, NULL, 0);
            c->vseq += 1;
            c->state = AD_TCP_FIN_WAIT;
            close(c->sock);
            c->sock = -1;
            pthread_mutex_unlock(&c->lock);
        } else if (errno != EAGAIN && errno != EWOULDBLOCK) {
            pthread_mutex_lock(&c->lock);
            ad_inject_tcp(h, c, AD_TCP_RST | AD_TCP_ACK, NULL, 0);
            c->state = AD_TCP_CLOSED;
            close(c->sock);
            c->sock = -1;
            c->in_use = 0;
            pthread_mutex_unlock(&c->lock);
        }
    }
    pthread_mutex_unlock(&h->nat_lock);
}

/* ------------------------------------------------------------------ */
/* ICMP + misc                                                        */
/* ------------------------------------------------------------------ */

void ad_forward_icmp(ad_handle_t *h, const uint8_t *pkt, uint32_t len)
{
    uint8_t buf[AD_MAX_PACKET];
    uint32_t total;
    AD_ADDRESS addr;

    if (len < 20 + 8 || len > sizeof(buf))
        return;
    if (pkt[20] != 8 || pkt[21] != 0)   /* only echo request */
        return;

    total = len;
    memcpy(buf, pkt, len);
    /* swap addresses */
    {
        uint8_t tmp[4];
        memcpy(tmp, buf + 12, 4);
        memcpy(buf + 12, buf + 16, 4);
        memcpy(buf + 16, tmp, 4);
    }
    buf[20] = 0;   /* echo reply */
    {
        /* recompute icmp checksum */
        uint32_t sum = 0, i;
        buf[22] = 0; buf[23] = 0;
        for (i = 20; i + 1 < total; i += 2)
            sum += (uint32_t)((buf[i] << 8) | buf[i + 1]);
        if (total & 1)
            sum += (uint32_t)(buf[total - 1] << 8);
        while (sum >> 16)
            sum = (sum & 0xffffu) + (sum >> 16);
        sum = ~sum & 0xffffu;
        buf[22] = (uint8_t)(sum >> 8);
        buf[23] = (uint8_t)(sum & 0xff);
    }
    /* fix ipv4 checksum */
    {
        uint32_t sum = 0, i;
        buf[10] = 0; buf[11] = 0;
        for (i = 0; i + 1 < 20; i += 2)
            sum += (uint32_t)((buf[i] << 8) | buf[i + 1]);
        while (sum >> 16)
            sum = (sum & 0xffffu) + (sum >> 16);
        sum = ~sum & 0xffffu;
        buf[10] = (uint8_t)(sum >> 8);
        buf[11] = (uint8_t)(sum & 0xff);
    }
    memset(&addr, 0, sizeof(addr));
    addr.flags = AD_ADDRESS_FLAG_INBOUND;
    memcpy(&addr.addr.ipv4.src_addr, buf + 12, 4);
    memcpy(&addr.addr.ipv4.dst_addr, buf + 16, 4);
    if (write(h->tun_fd, buf, total) == (ssize_t)total) {
        pthread_mutex_lock(&h->stats_lock);
        h->stats.bytes_out += total;
        pthread_mutex_unlock(&h->stats_lock);
    }
}

/* ------------------------------------------------------------------ */
/* Dispatch + maintenance                                             */
/* ------------------------------------------------------------------ */

void ad_nat_cleanup(ad_handle_t *h)
{
    int i;
    uint32_t now = now_s();

    pthread_mutex_lock(&h->nat_lock);
    for (i = 0; i < AD_MAX_UDP_FLOWS; i++) {
        ad_udp_flow_t *f = &h->udp_flows[i];
        if (f->in_use && now - f->last_used > AD_UDP_FLOW_TTL_S) {
            if (f->sock >= 0) close(f->sock);
            f->in_use = 0;
        }
    }
    for (i = 0; i < AD_MAX_TCP_CONNS; i++) {
        ad_tcp_conn_t *c = &h->tcp_conns[i];
        if (c->in_use && c->state == AD_TCP_CLOSED) {
            if (c->sock >= 0) { close(c->sock); c->sock = -1; }
            c->in_use = 0;
        }
        /* hard timeout for stuck connections */
        if (c->in_use && now - c->last_used > 600) {
            if (c->sock >= 0) { close(c->sock); c->sock = -1; }
            pthread_mutex_lock(&c->lock);
            ad_inject_tcp(h, c, AD_TCP_RST | AD_TCP_ACK, NULL, 0);
            pthread_mutex_unlock(&c->lock);
            c->in_use = 0;
        }
    }
    pthread_mutex_unlock(&h->nat_lock);
}

void ad_relay_poll(ad_handle_t *h, int timeout_ms)
{
    ad_udp_relay(h);
    ad_tcp_relay(h);
    ad_nat_cleanup(h);
    (void)timeout_ms;
}
