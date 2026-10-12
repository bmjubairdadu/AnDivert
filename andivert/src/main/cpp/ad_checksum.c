/*
 * ad_checksum.c — IPv4/IPv6 header and TCP/UDP/ICMP checksum helpers.
 * RFC 1071 style, big-endian (network order) aware.
 */

#include "ad_internal.h"
#include <string.h>

static uint16_t ad_checksum_final(uint32_t sum)
{
    while (sum >> 16)
        sum = (sum & 0xffffu) + (sum >> 16);
    return (uint16_t)(~sum & 0xffffu);
}

/* Carry-in variant used to accumulate across chunks. */
static uint32_t ad_checksum_add(const uint8_t *data, uint32_t len, uint32_t sum)
{
    uint32_t i;
    for (i = 0; i + 1 < len; i += 2)
        sum += (uint32_t)((data[i] << 8) | data[i + 1]);
    if (len & 1)
        sum += (uint32_t)(data[len - 1] << 8);  /* pad odd byte */
    return sum;
}

/* ------------------------------------------------------------------ */
/* Public: full IPv4 header checksum write                            */
/* ------------------------------------------------------------------ */

uint16_t ad_ip4_checksum(const uint8_t *iph, uint32_t ihl_bytes)
{
    uint32_t sum = ad_checksum_add(iph, ihl_bytes, 0);
    return ad_checksum_final(sum);
}

/* ------------------------------------------------------------------ */
/* Public: TCP/UDP checksum including pseudo-header.                  */
/* src/dst are byte arrays of addresses (4 bytes for v4, 16 for v6).  */
/* Returns the checksum to store in the header.                       */
/* ------------------------------------------------------------------ */

uint16_t ad_l4_checksum(const uint8_t *src, const uint8_t *dst,
                        uint8_t addr_len, uint8_t proto,
                        const uint8_t *l4, uint32_t l4_len)
{
    uint32_t sum = 0;
    uint32_t total = l4_len;

    sum = ad_checksum_add(src, addr_len, sum);
    sum = ad_checksum_add(dst, addr_len, sum);
    sum += proto;
    sum += (total >> 16) & 0xffffu;
    sum += total & 0xffffu;
    sum = ad_checksum_add(l4, l4_len, sum);
    return ad_checksum_final(sum);
}

/* ------------------------------------------------------------------ */
/* Recalculate all checksums of a packet before re-injection.         */
/* ------------------------------------------------------------------ */

int ADCalcChecksums(void *pkt, uint32_t len, const AD_ADDRESS *addr)
{
    uint8_t *p = (uint8_t *)pkt;
    uint32_t ihl, l4_off, l4_len;
    uint8_t proto;
    const uint8_t *src, *dst;
    uint8_t addr_len;

    if (pkt == NULL || len < 20)
        return AN_ERROR_INVALID;

    if ((p[0] >> 4) == 4) {
        ihl = (uint32_t)(p[0] & 0x0f) * 4;
        if (ihl < 20 || len < ihl)
            return AN_ERROR_INVALID;
        proto = p[9];
        src = p + 12;
        dst = p + 16;
        addr_len = 4;

        /* IPv4 header checksum: zero then compute */
        memset(p + 10, 0, 2);
        {
            uint16_t c = ad_ip4_checksum(p, ihl);
            p[10] = (uint8_t)(c >> 8);
            p[11] = (uint8_t)(c & 0xff);
        }
        l4_off = ihl;
    } else if ((p[0] >> 4) == 6) {
        if (len < 40)
            return AN_ERROR_INVALID;
        proto = p[6];           /* next header */
        src = p + 8;
        dst = p + 24;
        addr_len = 16;
        l4_off = 40;
        /* IPv6 has no header checksum */
    } else {
        return AN_ERROR_INVALID;
    }

    /* walk to the real transport header, skipping extension headers */
    {
        uint32_t off = l4_off;
        uint8_t  nh  = proto;
        while (nh == 0 || nh == 43 || nh == 60) {   /* hopopt / routing / dstopts */
            if (len < off + 2)
                return AN_ERROR_INVALID;
            nh = p[off];
            {
                uint8_t ext_len = p[off + 1];
                off += 8 + (uint32_t)ext_len * 8;
            }
            if (off >= len)
                return AN_ERROR_INVALID;
        }
        l4_off = off;
        proto  = nh;
    }

    if (len <= l4_off)
        return AN_ERROR_INVALID;

    switch (proto) {
    case 6: {  /* TCP */
        if (len < l4_off + 20)
            return AN_ERROR_INVALID;
        l4_len = len - l4_off;
        memset(p + l4_off + 16, 0, 2);
        {
            uint16_t c = ad_l4_checksum(src, dst, addr_len, 6,
                                        p + l4_off, l4_len);
            p[l4_off + 16] = (uint8_t)(c >> 8);
            p[l4_off + 17] = (uint8_t)(c & 0xff);
        }
        break;
    }
    case 17: { /* UDP */
        uint32_t ulen;
        if (len < l4_off + 8)
            return AN_ERROR_INVALID;
        ulen = ((uint32_t)p[l4_off + 4] << 8) | p[l4_off + 5];
        if (ulen < 8 || l4_off + ulen > len)
            ulen = len - l4_off;
        memset(p + l4_off + 6, 0, 2);
        {
            uint16_t c = ad_l4_checksum(src, dst, addr_len, 17,
                                        p + l4_off, ulen);
            if (c == 0)
                c = 0xffff;         /* UDP: 0 means "no checksum" */
            p[l4_off + 6] = (uint8_t)(c >> 8);
            p[l4_off + 7] = (uint8_t)(c & 0xff);
        }
        break;
    }
    case 1:    /* ICMP */
    case 58: { /* ICMPv6 */
        if (len < l4_off + 4)
            return AN_ERROR_INVALID;
        if (proto == 58) {
            /* ICMPv6 uses pseudo-header too */
            l4_len = len - l4_off;
            memset(p + l4_off + 2, 0, 2);
            {
                uint16_t c = ad_l4_checksum(src, dst, addr_len, 58,
                                            p + l4_off, l4_len);
                p[l4_off + 2] = (uint8_t)(c >> 8);
                p[l4_off + 3] = (uint8_t)(c & 0xff);
            }
        } else {
            l4_len = len - l4_off;
            memset(p + l4_off + 2, 0, 2);
            {
                uint32_t sum = ad_checksum_add(p + l4_off, l4_len, 0);
                uint16_t c = ad_checksum_final(sum);
                p[l4_off + 2] = (uint8_t)(c >> 8);
                p[l4_off + 3] = (uint8_t)(c & 0xff);
            }
        }
        break;
    }
    default:
        return AN_ERROR_UNSUPPORTED;
    }
    (void)addr;
    return AN_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Verify transport checksum. Returns 1 valid, 0 invalid, -1 skip.    */
/* ------------------------------------------------------------------ */

int ADVerifyChecksum(const void *pkt, uint32_t len)
{
    const uint8_t *p = (const uint8_t *)pkt;
    uint32_t ihl, l4_off, l4_len;
    uint8_t proto;
    const uint8_t *src, *dst;
    uint8_t addr_len;

    if (pkt == NULL || len < 20)
        return -1;
    if ((p[0] >> 4) == 4) {
        ihl = (uint32_t)(p[0] & 0x0f) * 4;
        if (ihl < 20 || len < ihl)
            return -1;
        proto = p[9];
        src = p + 12;
        dst = p + 16;
        addr_len = 4;
        l4_off = ihl;
    } else if ((p[0] >> 4) == 6) {
        if (len < 40)
            return -1;
        proto = p[6];
        src = p + 8;
        dst = p + 24;
        addr_len = 16;
        l4_off = 40;
    } else {
        return -1;
    }

    switch (proto) {
    case 6:
    case 17: {
        uint16_t got;
        if (proto == 17) {
            uint32_t ulen;
            if (len < l4_off + 8)
                return -1;
            ulen = ((uint32_t)p[l4_off + 4] << 8) | p[l4_off + 5];
            if (ulen < 8 || l4_off + ulen > len)
                return -1;
            l4_len = ulen;
            got = (uint16_t)((p[l4_off + 6] << 8) | p[l4_off + 7]);
            if (got == 0)
                return 1;   /* UDP "no checksum" is legal for IPv4 */
        } else {
            if (len < l4_off + 20)
                return -1;
            l4_len = len - l4_off;
            got = (uint16_t)((p[l4_off + 16] << 8) | p[l4_off + 17]);
        }
        if (ad_l4_checksum(src, dst, addr_len, proto, p + l4_off, l4_len) == 0)
            return 1;
        return 0;
    }
    default:
        return -1;
    }
}
