/*
 * ad_internal.h — internal structures shared by the AnDivert engine.
 * Not part of the public API.
 */

#ifndef AD_INTERNAL_H
#define AD_INTERNAL_H

#include "andivert.h"
#include <pthread.h>
#include <time.h>

#define AD_MAX_PACKET      65536
#define AD_RING_CAPACITY   1024    /* pending diverted packets           */
#define AD_MAX_UDP_FLOWS   512     /* concurrent UDP NAT entries         */
#define AD_MAX_TCP_CONNS   128     /* concurrent TCP proxy connections   */
#define AD_UDP_FLOW_TTL_S  120
#define AD_EPHEMERAL_MIN   20000
#define AD_EPHEMERAL_MAX   65000

/* ------------------------------------------------------------------ */
/* Ring of diverted packets                                           */
/* ------------------------------------------------------------------ */

typedef struct {
    uint8_t  data[AD_MAX_PACKET];
    uint32_t len;
    AD_ADDRESS addr;
    uint64_t seq;          /* global arrival order */
} ad_ring_item_t;

typedef struct {
    ad_ring_item_t items[AD_RING_CAPACITY];
    int      head;
    int      tail;
    int      count;
    uint64_t next_seq;
    pthread_mutex_t lock;
    pthread_cond_t  cond;
} ad_ring_t;

void ad_ring_init(ad_ring_t *r);
void ad_ring_destroy(ad_ring_t *r);
/* returns 0 ok, -1 full (oldest is NOT dropped; caller decides) */
int  ad_ring_push(ad_ring_t *r, const uint8_t *data, uint32_t len,
                  const AD_ADDRESS *addr);
/* timeout_ms < 0 => block forever; returns 0 ok, AN_ERROR_TIMEOUT, AN_ERROR_CLOSED */
int  ad_ring_pop(ad_ring_t *r, ad_ring_item_t *out, int32_t timeout_ms,
                 const volatile int *closed_flag);
void ad_ring_wake(ad_ring_t *r);

/* ------------------------------------------------------------------ */
/* UDP NAT flow                                                       */
/* ------------------------------------------------------------------ */

typedef struct {
    int      in_use;
    int      sock;                  /* protected upstream socket, -1 none */
    uint32_t client_ip;              /* virtual client ip (network order)  */
    uint16_t client_port;            /* virtual client port (host order)   */
    uint16_t local_port;             /* allocated local port (host order)  */
    uint8_t  proto;                  /* IPPROTO_UDP                        */
    time_t   last_used;
} ad_udp_flow_t;

/* ------------------------------------------------------------------ */
/* TCP proxy connection (client-side mini state machine)              */
/* ------------------------------------------------------------------ */

enum {
    AD_TCP_CLOSED = 0,
    AD_TCP_SYN_RCVD,     /* got SYN, sent SYN-ACK, waiting ACK   */
    AD_TCP_ESTABLISHED,
    AD_TCP_CLOSE_WAIT,   /* got FIN from client                  */
    AD_TCP_LAST_ACK,     /* we sent FIN, waiting final ACK       */
    AD_TCP_FIN_WAIT,     /* we sent FIN to client                */
    AD_TCP_RESET
};

typedef struct {
    int      in_use;
    int      state;
    int      sock;                    /* upstream protected socket or -1  */
    uint32_t client_ip;                /* virtual ip (network order)       */
    uint16_t client_port;              /* host order                       */
    uint32_t dst_ip;                   /* real destination (network order) */
    uint16_t dst_port;                 /* host order                       */
    uint32_t vseq;                     /* our seq toward the client        */
    uint32_t vack;                     /* next expected seq from client    */
    pthread_mutex_t lock;
    time_t   last_used;
} ad_tcp_conn_t;

/* ------------------------------------------------------------------ */
/* Handle                                                             */
/* ------------------------------------------------------------------ */

struct ad_handle {
    int      tun_fd;
    int      layer;
    int      priority;
    uint64_t flags;
    volatile int running;
    volatile int closed;

    ad_filter_t *filter;
    char         filter_expr[512];

    ad_ring_t ring;

    /* virtual network config (filled by JNI layer) */
    uint32_t vpn_ip;         /* TUN local address, network order   */
    uint32_t vpn_dns;        /* DNS server handed to the system    */
    int      vpn_mtu;

    /* forwarder */
    int      protect_fd;     /* fd used with VpnService.protect(), -1 if none */
    ad_udp_flow_t  udp_flows[AD_MAX_UDP_FLOWS];
    ad_tcp_conn_t  tcp_conns[AD_MAX_TCP_CONNS];
    pthread_mutex_t nat_lock;
    pthread_t engine_thread;
    pthread_t relay_thread;

    AD_STATS stats;
    pthread_mutex_t stats_lock;
    int last_error;
};

/* engine internals (andivert.c) */
void *ad_engine_main(void *arg);
void *ad_relay_main(void *arg);
void  ad_forward_packet(ad_handle_t *h, const uint8_t *pkt, uint32_t len);
void  ad_forward_udp(ad_handle_t *h, const uint8_t *pkt, uint32_t len);
void  ad_forward_tcp(ad_handle_t *h, const uint8_t *pkt, uint32_t len);
void  ad_forward_icmp(ad_handle_t *h, const uint8_t *pkt, uint32_t len);
void  ad_relay_poll(ad_handle_t *h, int timeout_ms);
void  ad_nat_cleanup(ad_handle_t *h);

/* packet helpers (ad_packet.c) */
int   ad_ip_header_len(const uint8_t *pkt, uint32_t len);
int   ad_transport_offset(const uint8_t *pkt, uint32_t len);
int   ad_is_ipv6(const uint8_t *pkt, uint32_t len);

/* logging (ad_log.c) */
void  ad_log_info(const char *fmt, ...);
void  ad_log_warn(const char *fmt, ...);
void  ad_log_error(const char *fmt, ...);

#endif /* AD_INTERNAL_H */
