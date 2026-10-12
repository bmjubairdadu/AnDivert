/*
 * ad_packet.c — IP packet parsing helpers.
 */

#include "ad_internal.h"
#include <string.h>

int ad_is_ipv6(const uint8_t *pkt, uint32_t len)
{
    return pkt != NULL && len >= 1 && (pkt[0] >> 4) == 6;
}

int ad_ip_header_len(const uint8_t *pkt, uint32_t len)
{
    if (pkt == NULL || len < 1)
        return -1;
    switch (pkt[0] >> 4) {
    case 4:
        if (len < 20)
            return -1;
        return (pkt[0] & 0x0f) * 4;
    case 6:
        return 40;
    default:
        return -1;
    }
}

/* Offset of the first transport header (skipping IPv6 extension headers). */
int ad_transport_offset(const uint8_t *pkt, uint32_t len)
{
    uint32_t off, nh;

    if (pkt == NULL || len < 1)
        return -1;
    if ((pkt[0] >> 4) == 4) {
        int ihl = ad_ip_header_len(pkt, len);
        if (ihl < 20 || (uint32_t)ihl > len)
            return -1;
        return ihl;
    }
    if ((pkt[0] >> 4) != 6)
        return -1;
    if (len < 40)
        return -1;
    off = 40;
    nh = pkt[6];
    while (nh == 0 || nh == 43 || nh == 60) {
        uint8_t ext_len;
        if (len < off + 2)
            return -1;
        nh = pkt[off];
        ext_len = pkt[off + 1];
        off += 8 + (uint32_t)ext_len * 8;
        if (off >= len)
            return -1;
    }
    return (int)off;
}

/*
 * ADParsePacket — fill AD_ADDRESS from a raw IP packet.
 * Mirrors the fields a WinDivert program would see.
 */
int ADParsePacket(const void *pkt, uint32_t len, AD_ADDRESS *addr)
{
    const uint8_t *p = (const uint8_t *)pkt;
    uint8_t proto;

    if (pkt == NULL || addr == NULL)
        return AN_ERROR_INVALID;
    memset(addr, 0, sizeof(*addr));
    addr->timestamp_us = 0;  /* caller fills */

    if (len < 1)
        return AN_ERROR_INVALID;

    if ((p[0] >> 4) == 4) {
        uint32_t ihl;
        if (len < 20)
            return AN_ERROR_INVALID;
        ihl = (uint32_t)(p[0] & 0x0f) * 4;
        if (ihl < 20 || len < ihl)
            return AN_ERROR_INVALID;
        proto = p[9];
        memcpy(&addr->addr.ipv4.src_addr, p + 12, 4);
        memcpy(&addr->addr.ipv4.dst_addr, p + 16, 4);
        addr->layer = AN_LAYER_NETWORK;
    } else if ((p[0] >> 4) == 6) {
        if (len < 40)
            return AN_ERROR_INVALID;
        proto = p[6];
        memcpy(addr->addr.ipv6.src_addr, p + 8, 16);
        memcpy(addr->addr.ipv6.dst_addr, p + 24, 16);
        addr->layer = AN_LAYER_NETWORK;
    } else {
        return AN_ERROR_INVALID;
    }

    /* annotate flags for TCP SYN etc. consumers */
    switch (proto) {
    case 1:  addr->event = 0; break;   /* ICMP  */
    case 6:  addr->event = 0; break;   /* TCP   */
    case 17: addr->event = 0; break;   /* UDP   */
    default: addr->event = 0; break;
    }
    return AN_SUCCESS;
}
