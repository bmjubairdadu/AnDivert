/*
 * andivert.h — Android Packet Divert (AnDivert)
 *
 * A WinDivert-inspired user-mode packet interception API for Android.
 *
 * BACKGROUND
 * ----------
 * WinDivert (https://github.com/basil00/WinDivert) works by installing a WFP
 * callout driver (WinDivert.sys) below the Windows network stack. Android has
 * no equivalent installable kernel hook available to normal apps, so AnDivert
 * uses the platform-sanctioned path instead: an Android VpnService-created TUN
 * interface. Every IP packet routed into the TUN is delivered to user space,
 * where this engine can inspect / filter / drop / modify / re-inject it —
 * the same conceptual model as WinDivertRecv/WinDivertSend.
 *
 * API MAPPING (WinDivert -> AnDivert)
 * -----------------------------------
 *   WinDivertOpen(filter, layer, priority, flags)  ->  AnDivertOpen(...)
 *   WinDivertRecv(handle, buf, len, &addr, &recvLen)  ->  AnDivertRecv(...)
 *   WinDivertSend(handle, buf, len, &addr, &sendLen)  ->  AnDivertSend(...)
 *   WinDivertClose(handle)                            ->  AnDivertClose(...)
 *   WINDIVERT_IPHDR / WINDIVERT_TCPHDR               ->  AD_IPHDR / AD_TCPHDR
 *
 * LICENSE NOTE: This is an independent reimplementation of the *concept*; it
 * shares no code with WinDivert (which is LGPLv3/GPLv2). It reuses that
 * project's public error-code shapes for developer familiarity only.
 */

#ifndef ANDIVERT_H
#define ANDIVERT_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Version                                                            */
/* ------------------------------------------------------------------ */

#define AN_DIVERT_VERSION_MAJOR 1
#define AN_DIVERT_VERSION_MINOR 0

/* ------------------------------------------------------------------ */
/* Error codes (mirrors WinDivert's WINDIVERT_ERROR_* shape)          */
/* ------------------------------------------------------------------ */

typedef enum {
    AN_SUCCESS          = 0,
    AN_ERROR_INVALID    = -1,  /* invalid argument                  */
    AN_ERROR_OPEN       = -2,  /* cannot open the specified filter  */
    AN_ERROR_IO         = -3,  /* TUN read/write failure            */
    AN_ERROR_NOBUF      = -4,  /* buffer too small / queue full     */
    AN_ERROR_NOTFOUND   = -5,  /* no matching packet / bad handle   */
    AN_ERROR_TIMEOUT    = -6,  /* operation timed out               */
    AN_ERROR_NOMEM      = -7,  /* out of memory                     */
    AN_ERROR_CLOSED     = -8,  /* handle already closed             */
    AN_ERROR_UNSUPPORTED= -9,  /* unsupported feature/address family*/
} AnDivertError;

/* ------------------------------------------------------------------ */
/* Open flags (bitwise) — same spirit as WINDIVERT_FLAG_*             */
/* ------------------------------------------------------------------ */

#define AN_FLAG_SNIFF     0x0001u  /* observe only; do not consume     */
#define AN_FLAG_DROP      0x0002u  /* drop every matching packet       */
#define AN_FLAG_READONLY  0x0004u  /* recv only, never send             */
#define AN_FLAG_DEFAULT   0x0000u

/* Layer constants (WinDivert compat names) */
enum {
    AN_LAYER_NETWORK       = 0,
    AN_LAYER_NETWORK_FORWARD= 1,
};

/* ------------------------------------------------------------------ */
/* Opaque handle                                                      */
/* ------------------------------------------------------------------ */

typedef struct ad_handle ad_handle_t;

/* ------------------------------------------------------------------ */
/* Packet headers — packed, little/big-endian agnostic accessors      */
/* ------------------------------------------------------------------ */

#pragma pack(push, 1)
typedef struct {
    uint8_t  hdr_len : 4;   /* header length in 32-bit words */
    uint8_t  version : 4;   /* 4 or 6 */
    uint8_t  tos;
    uint16_t total_len;     /* network byte order */
    uint16_t id;
    uint16_t frag_off;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t checksum;
    uint32_t src_addr;      /* network byte order */
    uint32_t dst_addr;      /* network byte order */
} AD_IPHDR;

typedef struct {
    uint16_t src_port;      /* network byte order */
    uint16_t dst_port;
    uint32_t seq_num;
    uint32_t ack_num;
    uint8_t  reserved1 : 4;
    uint8_t  data_offset : 4; /* TCP header length in 32-bit words */
    uint8_t  flags;           /* TCP_FIN..TCP_URG */
    uint16_t window;
    uint16_t checksum;
    uint16_t urgent_ptr;
} AD_TCPHDR;

typedef struct {
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;         /* includes header */
    uint16_t checksum;
} AD_UDPHDR;

typedef struct {
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
    uint32_t rest;
} AD_ICMPHDR;

typedef struct {
    uint32_t src_addr[4];    /* network byte order */
    uint32_t dst_addr[4];
    uint32_t flow_label : 20;
    uint8_t  traffic_class;
    uint8_t  hop_limit;
    uint8_t  next_header;
} AD_IPV6HDR;

typedef struct {
    uint32_t src_addr[4];
    uint32_t dst_addr[4];
    uint32_t identification;
    uint16_t frag_off;
    uint8_t  zero;
    uint8_t  next_header;
    uint8_t  hop_limit;
    uint8_t  traffic_class;
    uint32_t flow_label : 20;
} AD_IPV6FRAGHDR;
#pragma pack(pop)

/* TCP flag bits (matches WinDivert naming) */
#define AD_TCP_FIN 0x01
#define AD_TCP_SYN 0x02
#define AD_TCP_RST 0x04
#define AD_TCP_PSH 0x08
#define AD_TCP_ACK 0x10
#define AD_TCP_URG 0x20

/* ------------------------------------------------------------------ */
/* Address — same role as WINDIVERT_ADDRESS                           */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t timestamp_us;   /* monotonic capture time            */
    uint32_t flags;          /* bit0 = outbound, bit1 = inbound  */
    uint32_t if_idx;
    uint8_t  layer;          /* AN_LAYER_*                        */
    uint8_t  event;          /* 0=read 1=write 2=lost 3=drop      */
    union {
        struct { uint32_t src_addr; uint32_t dst_addr; } ipv4;
        struct { uint32_t src_addr[4]; uint32_t dst_addr[4]; } ipv6;
    } addr;
} AD_ADDRESS;

#define AD_ADDRESS_FLAG_OUTBOUND 0x01u
#define AD_ADDRESS_FLAG_INBOUND  0x02u

/* ------------------------------------------------------------------ */
/* Lifecycle                                                          */
/* ------------------------------------------------------------------ */

/*
 * AnDivertOpen — compile `filter` and attach to an already-established TUN fd.
 *
 * `tun_fd`  : a TUN file descriptor obtained by the VpnService layer.
 * `filter`  : AnDivert filter expression, e.g.
 *                "outbound and tcp.DstPort == 443"
 *                "ip.SrcAddr == 10.0.0.5 or udp"
 *                "true"
 *             Pass NULL or "true" to match everything.
 * `priority`: higher values are considered first; reserved for future use.
 * `flags`   : AN_FLAG_* bitmask.
 *
 * Returns a handle on success, NULL on failure (errno not set; use
 * AnDivertLastError()).
 */
ad_handle_t *AnDivertOpen(int tun_fd, const char *filter, int layer,
                          int priority, uint64_t flags);

/*
 * AnDivertRecv — block until a matching packet is available.
 *
 * On success, copies up to `len` bytes of the packet into `buf`, writes the
 * number of bytes copied to *recv_len and fills `addr`. Returns AN_SUCCESS.
 * Returns AN_ERROR_TIMEOUT if `timeout_ms` elapses with no packet (0 = block
 * forever), AN_ERROR_NOBUF if the packet is larger than `len`.
 */
int AnDivertRecv(ad_handle_t *h, void *buf, uint32_t len,
                 AD_ADDRESS *addr, uint32_t *recv_len, uint32_t timeout_ms);

/*
 * AnDivertSend — inject `len` bytes from `buf` back into the network stack
 * via the TUN. This is the re-injection path (WinDivertSend equivalent).
 */
int AnDivertSend(ad_handle_t *h, const void *buf, uint32_t len,
                 const AD_ADDRESS *addr, uint32_t *send_len);

int AnDivertClose(ad_handle_t *h);

/*
 * AnDivertSetProtectFn — register the socket-protection hook.
 * On Android this MUST be wired to VpnService.protect(fd) through JNI,
 * otherwise the forwarder's own sockets would loop back into the TUN.
 * Returns 0 on success. Passing NULL clears the hook.
 */
int AnDivertSetProtectFn(int (*fn)(int fd));

int AnDivertLastError(void);
const char *AnDivertStrError(int err);

/* ------------------------------------------------------------------ */
/* Statistics                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    uint64_t packets_divered;   /* matched + delivered to user space */
    uint64_t packets_passed;    /* non-matching + auto re-injected   */
    uint64_t packets_dropped;   /* matched + dropped by flag/verdict */
    uint64_t bytes_in;          /* total bytes read from TUN         */
    uint64_t bytes_out;         /* total bytes written to TUN        */
    uint32_t queue_len;         /* current pending packets           */
    uint32_t queue_max;
} AD_STATS;

int AnDivertGetStats(ad_handle_t *h, AD_STATS *stats);

/* ------------------------------------------------------------------ */
/* Packet helpers (public, reusable)                                  */
/* ------------------------------------------------------------------ */

/* Parse a raw IP buffer. Returns 0 on success. */
int ADParsePacket(const void *pkt, uint32_t len, AD_ADDRESS *addr);

/* Recompute IPv4 header checksum + L4 checksum (TCP/UDP/ICMP). */
int ADCalcChecksums(void *pkt, uint32_t len, const AD_ADDRESS *addr);

/* Validate transport checksum; returns 1 valid, 0 invalid, -1 not checked. */
int ADVerifyChecksum(const void *pkt, uint32_t len);

/* Filter compilation standalone (useful for unit tests). */
typedef struct ad_filter ad_filter_t;
ad_filter_t *ADFilterCompile(const char *expr);
int ADFilterMatch(const ad_filter_t *f, const void *pkt, uint32_t len,
                  const AD_ADDRESS *addr);
void ADFilterFree(ad_filter_t *f);
const char *ADFilterError(void);

#ifdef __cplusplus
}
#endif

#endif /* ANDIVERT_H */
