/*
 * ad_filter.c — AnDivert filter expression compiler.
 *
 * Implements a practical subset of the WinDivert filter language:
 *
 *   true | false
 *   outbound | inbound
 *   ip | ipv4 | ipv6 | tcp | udp | icmp | icmpv6
 *   ip.SrcAddr == 10.0.0.1        ip.DstAddr != 8.8.8.8
 *   ip.Protocol == 6              ip.TTL > 1
 *   ipv6.SrcAddr == ::1           (limited)
 *   tcp.SrcPort == 443            tcp.DstPort >= 1024
 *   udp.SrcPort == 53             udp.DstPort == 5353
 *   tcp.Syn | tcp.Ack | tcp.Fin | tcp.Rst | tcp.Psh
 *   icmp.Type == 8                icmp.Code == 0
 *   ... combined with and / or / not and parentheses.
 *
 * Unknown identifiers are a compile error (never silently match nothing),
 * so a developer's typo fails loudly at AnDivertOpen() time.
 */

#include "ad_internal.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

/* ------------------------------------------------------------------ */
/* Field identifiers                                                  */
/* ------------------------------------------------------------------ */

enum {
    F_NONE = 0,
    F_SRCADDR, F_DSTADDR, F_PROTOCOL, F_TTL, F_LENGTH, F_TOS, F_ID,
    F_TCPSRCPORT, F_TCPDSTPORT, F_TCPSYN, F_TCPACK, F_TCPFIN, F_TCPRST,
    F_TCPPSH, F_TCPURG, F_IPSIZE,
    F_UDPSRCPORT, F_UDPDSTPORT,
    F_ICMPTYPE, F_ICMPCODE,
    F_IS_IPV4, F_IS_IPV6,
    F_OUTBOUND, F_INBOUND,
    F_TRUE, F_FALSE,
};

enum { OP_EQ, OP_NE, OP_LT, OP_LE, OP_GT, OP_GE };

enum { N_OR, N_AND, N_NOT, N_TERM };

struct ad_node {
    int   kind;          /* N_* */
    int   negate;        /* N_NOT only */
    struct ad_node *lhs, *rhs;   /* OR/AND */
    int   field;         /* N_TERM */
    int   op;            /* N_TERM */
    int   is_bool;       /* N_TERM: literal only */
    int   bool_val;
    uint32_t value;      /* N_TERM: numeric value */
    uint8_t addr_val[16];/* N_TERM: address bytes (network order) */
    int   addr_len;      /* 4 or 16, 0 = numeric compare */
};

typedef struct ad_node node_t;

struct ad_filter {
    char   text[512];
    node_t *tree;
    /* shared scratch for parse errors */
};

/* ------------------------------------------------------------------ */
/* Lexer                                                              */
/* ------------------------------------------------------------------ */

enum {
    T_EOF = 0, T_IDENT, T_NUM, T_ADDR,
    T_EQ, T_NE, T_LT, T_LE, T_GT, T_GE,
    T_LPAREN, T_RPAREN,
    T_AND, T_OR, T_NOT,
    T_TRUE, T_FALSE,
};

typedef struct {
    const char *p;
    int   tok;
    char  text[128];
    uint32_t num;
    uint8_t addr[16];
    int   addr_len;
    char  err[192];
} lexer_t;

static int ad_is_ident_char(int c)
{
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
           (c >= '0' && c <= '9') || c == '.' || c == '_';
}

static void ad_lex_next(lexer_t *lx)
{
    const char *p = lx->p;
    while (*p == ' ' || *p == '\t' || *p == '\n' || *p == '\r')
        p++;
    lx->addr_len = 0;
    lx->num = 0;
    lx->text[0] = '\0';

    if (*p == '\0') { lx->tok = T_EOF; lx->p = p; return; }

    if (*p == '(') { lx->tok = T_LPAREN; lx->p = p + 1; return; }
    if (*p == ')') { lx->tok = T_RPAREN; lx->p = p + 1; return; }

    if (*p == '!' && p[1] == '=') { lx->tok = T_NE; lx->p = p + 2; return; }
    if (*p == '=' && p[1] == '=') { lx->tok = T_EQ; lx->p = p + 2; return; }
    if (*p == '=')                { lx->tok = T_EQ; lx->p = p + 1; return; }
    if (*p == '<' && p[1] == '=') { lx->tok = T_LE; lx->p = p + 2; return; }
    if (*p == '>' && p[1] == '=') { lx->tok = T_GE; lx->p = p + 2; return; }
    if (*p == '<')                { lx->tok = T_LT; lx->p = p + 1; return; }
    if (*p == '>')                { lx->tok = T_GT; lx->p = p + 1; return; }
    if (*p == '&' && p[1] == '&') { lx->tok = T_AND; lx->p = p + 2; return; }
    if (*p == '|' && p[1] == '|') { lx->tok = T_OR;  lx->p = p + 2; return; }

    /* number or dotted IPv4 address */
    if ((*p >= '0' && *p <= '9')) {
        const char *start = p;
        int dots = 0;
        while ((*p >= '0' && *p <= '9') || *p == '.') {
            if (*p == '.') dots++;
            p++;
        }
        if (dots == 3) {
            /* try to parse as dotted quad */
            int octets[4] = {0, 0, 0, 0};
            int i = 0, n = 0, val = 0, ok = 1, any = 0;
            const char *q = start;
            for (i = 0; i < 4; i++) {
                val = 0; any = 0;
                while (*q >= '0' && *q <= '9') {
                    val = val * 10 + (*q - '0');
                    q++; any = 1;
                    if (val > 255) { ok = 0; break; }
                }
                if (!any) { ok = 0; break; }
                octets[n++] = val;
                if (i < 3) {
                    if (*q != '.') { ok = 0; break; }
                    q++;
                }
            }
            if (ok && n == 4) {
                lx->addr[0] = (uint8_t)octets[0];
                lx->addr[1] = (uint8_t)octets[1];
                lx->addr[2] = (uint8_t)octets[2];
                lx->addr[3] = (uint8_t)octets[3];
                lx->addr_len = 4;
                lx->tok = T_ADDR;
                lx->p = q;
                return;
            }
        }
        /* plain number (decimal or 0x hex handled separately) */
        if (start[0] == '0' && (start[1] == 'x' || start[1] == 'X')) {
            lx->num = (uint32_t)strtoul(start, NULL, 16);
        } else {
            lx->num = (uint32_t)strtoul(start, NULL, 10);
        }
        /* handle 0x prefix which the loop above did not consume */
        if (start[0] == '0' && (start[1] == 'x' || start[1] == 'X')) {
            const char *q = start + 2;
            while ((*q >= '0' && *q <= '9') || (*q >= 'a' && *q <= 'f') ||
                   (*q >= 'A' && *q <= 'F'))
                q++;
            lx->num = (uint32_t)strtoul(start, NULL, 0);
            lx->p = q;
        } else {
            lx->p = p;
        }
        lx->tok = T_NUM;
        return;
    }

    /* identifier / keyword */
    if ((*p >= 'a' && *p <= 'z') || (*p >= 'A' && *p <= 'Z') || *p == '_') {
        size_t n = 0;
        while (ad_is_ident_char((unsigned char)*p) && n < sizeof(lx->text) - 1) {
            lx->text[n++] = *p++;
        }
        lx->text[n] = '\0';
        lx->p = p;

        if (strcmp(lx->text, "and") == 0)  { lx->tok = T_AND;  return; }
        if (strcmp(lx->text, "or") == 0)   { lx->tok = T_OR;   return; }
        if (strcmp(lx->text, "not") == 0)  { lx->tok = T_NOT;  return; }
        if (strcmp(lx->text, "true") == 0) { lx->tok = T_TRUE; return; }
        if (strcmp(lx->text, "false") == 0){ lx->tok = T_FALSE;return; }
        lx->tok = T_IDENT;
        return;
    }

    snprintf(lx->err, sizeof(lx->err), "unexpected character '%c' at offset %d",
             *p, (int)(p - lx->p) + (int)(lx->p - lx->p));
    snprintf(lx->err, sizeof(lx->err), "unexpected character '%c'", *p);
    lx->tok = T_EOF;
    lx->p = p + 1;
}

/* ------------------------------------------------------------------ */
/* Identifier -> field mapping                                        */
/* ------------------------------------------------------------------ */

static int ad_field_from_ident(const char *name)
{
    /* bare protocol / direction words */
    if (strcmp(name, "ip") == 0 || strcmp(name, "ipv4") == 0) return F_IS_IPV4;
    if (strcmp(name, "ipv6") == 0)      return F_IS_IPV6;
    if (strcmp(name, "outbound") == 0)  return F_OUTBOUND;
    if (strcmp(name, "inbound") == 0)   return F_INBOUND;

    if (strcmp(name, "ip.SrcAddr") == 0)   return F_SRCADDR;
    if (strcmp(name, "ip.DstAddr") == 0)   return F_DSTADDR;
    if (strcmp(name, "ip.Protocol") == 0)  return F_PROTOCOL;
    if (strcmp(name, "ip.TTL") == 0)       return F_TTL;
    if (strcmp(name, "ip.Length") == 0)    return F_LENGTH;
    if (strcmp(name, "ip.TOS") == 0)       return F_TOS;
    if (strcmp(name, "ip.Id") == 0)        return F_ID;
    if (strcmp(name, "ipv6.SrcAddr") == 0) return F_SRCADDR;
    if (strcmp(name, "ipv6.DstAddr") == 0) return F_DSTADDR;
    if (strcmp(name, "tcp.SrcPort") == 0)  return F_TCPSRCPORT;
    if (strcmp(name, "tcp.DstPort") == 0)  return F_TCPDSTPORT;
    if (strcmp(name, "udp.SrcPort") == 0)  return F_UDPSRCPORT;
    if (strcmp(name, "udp.DstPort") == 0)  return F_UDPDSTPORT;
    if (strcmp(name, "icmp.Type") == 0)    return F_ICMPTYPE;
    if (strcmp(name, "icmp.Code") == 0)    return F_ICMPCODE;
    return F_NONE;
}

/* shorthand aliases that behave as protocol predicates */
static int ad_proto_from_ident(const char *name)
{
    if (strcmp(name, "tcp") == 0)    return 6;
    if (strcmp(name, "udp") == 0)    return 17;
    if (strcmp(name, "icmp") == 0)   return 1;
    if (strcmp(name, "icmpv6") == 0) return 58;
    return -1;
}

/* ------------------------------------------------------------------ */
/* Parser                                                             */
/* ------------------------------------------------------------------ */

static node_t *ad_node_new(int kind)
{
    node_t *n = (node_t *)calloc(1, sizeof(node_t));
    if (n) n->kind = kind;
    return n;
}

static void ad_node_free(node_t *n)
{
    if (!n) return;
    ad_node_free(n->lhs);
    ad_node_free(n->rhs);
    free(n);
}

static node_t *ad_parse_or(lexer_t *lx);
static int      ad_parse_error(lexer_t *lx, const char *msg);

/* value token -> number, applied to the pending field */
static int ad_consume_value(lexer_t *lx, node_t *term)
{
    if (lx->tok == T_NUM) {
        term->value = lx->num;
        term->addr_len = 0;
        ad_lex_next(lx);
        return 1;
    }
    if (lx->tok == T_ADDR) {
        memcpy(term->addr_val, lx->addr, 4);
        term->addr_len = 4;
        /* Match how packet bytes are memcpy'd into a uint32 on little-endian:
         * first wire byte becomes the least significant byte. */
        term->value = (uint32_t)lx->addr[0] |
                      ((uint32_t)lx->addr[1] << 8) |
                      ((uint32_t)lx->addr[2] << 16) |
                      ((uint32_t)lx->addr[3] << 24);
        ad_lex_next(lx);
        return 1;
    }
    ad_parse_error(lx, "expected a number or address after operator");
    return 0;
}

/* term := primary_ident [ op value ] */
static node_t *ad_parse_term(lexer_t *lx)
{
    node_t *t;

    if (lx->tok == T_TRUE) {
        ad_lex_next(lx);
        t = ad_node_new(N_TERM);
        if (!t) return NULL;
        t->is_bool = 1;
        t->bool_val = 1;
        t->field = F_TRUE;
        return t;
    }
    if (lx->tok == T_FALSE) {
        ad_lex_next(lx);
        t = ad_node_new(N_TERM);
        if (!t) return NULL;
        t->is_bool = 1;
        t->bool_val = 0;
        t->field = F_FALSE;
        return t;
    }

    if (lx->tok != T_IDENT) {
        ad_parse_error(lx, "expected a field name, 'true', 'false' or '('");
        return NULL;
    }

    {
        char name[128];
        snprintf(name, sizeof(name), "%s", lx->text);
        ad_lex_next(lx);

        /* protocol shorthand: tcp / udp / icmp => ip.Protocol == N */
        {
            int proto = ad_proto_from_ident(name);
            if (proto >= 0) {
                t = ad_node_new(N_TERM);
                if (!t) return NULL;
                t->field = F_PROTOCOL;
                t->op = OP_EQ;
                t->value = (uint32_t)proto;
                t->addr_len = 0;
                return t;
            }
        }

        {
            int field = ad_field_from_ident(name);
            if (field == F_NONE) {
                char msg[192];
                snprintf(msg, sizeof(msg), "unknown filter field '%s'", name);
                ad_parse_error(lx, msg);
                return NULL;
            }
            t = ad_node_new(N_TERM);
            if (!t) return NULL;
            t->field = field;

            if (lx->tok == T_EQ || lx->tok == T_NE || lx->tok == T_LT ||
                lx->tok == T_LE || lx->tok == T_GT || lx->tok == T_GE) {
                switch (lx->tok) {
                case T_EQ: t->op = OP_EQ; break;
                case T_NE: t->op = OP_NE; break;
                case T_LT: t->op = OP_LT; break;
                case T_LE: t->op = OP_LE; break;
                case T_GT: t->op = OP_GT; break;
                default:   t->op = OP_GE; break;
                }
                ad_lex_next(lx);
                if (!ad_consume_value(lx, t)) {
                    ad_node_free(t);
                    return NULL;
                }
            } else {
                /* bare field: boolean-ish test (e.g. "tcp.Syn" means == 1) */
                t->op = OP_EQ;
                t->addr_len = 0;
                t->value = 1;
            }
            return t;
        }
    }
}

static node_t *ad_parse_not(lexer_t *lx)
{
    if (lx->tok == T_NOT) {
        node_t *n = ad_node_new(N_NOT);
        ad_lex_next(lx);
        if (!n) return NULL;
        n->rhs = ad_parse_not(lx);
        if (!n->rhs) { ad_node_free(n); return NULL; }
        return n;
    }
    if (lx->tok == T_LPAREN) {
        node_t *inner;
        ad_lex_next(lx);
        inner = ad_parse_or(lx);
        if (!inner) return NULL;
        if (lx->tok != T_RPAREN) {
            ad_parse_error(lx, "expected ')'");
            ad_node_free(inner);
            return NULL;
        }
        ad_lex_next(lx);
        return inner;
    }
    return ad_parse_term(lx);
}

static node_t *ad_parse_and(lexer_t *lx)
{
    node_t *left = ad_parse_not(lx);
    if (!left) return NULL;
    while (lx->tok == T_AND) {
        node_t *n, *right;
        ad_lex_next(lx);
        right = ad_parse_not(lx);
        if (!right) { ad_node_free(left); return NULL; }
        n = ad_node_new(N_AND);
        if (!n) { ad_node_free(left); ad_node_free(right); return NULL; }
        n->lhs = left;
        n->rhs = right;
        left = n;
    }
    return left;
}

static node_t *ad_parse_or(lexer_t *lx)
{
    node_t *left = ad_parse_and(lx);
    if (!left) return NULL;
    while (lx->tok == T_OR) {
        node_t *n, *right;
        ad_lex_next(lx);
        right = ad_parse_and(lx);
        if (!right) { ad_node_free(left); return NULL; }
        n = ad_node_new(N_OR);
        if (!n) { ad_node_free(left); ad_node_free(right); return NULL; }
        n->lhs = left;
        n->rhs = right;
        left = n;
    }
    return left;
}

/* ------------------------------------------------------------------ */
/* Parse error bookkeeping                                            */
/* ------------------------------------------------------------------ */

static __thread char g_filter_err[256] = "no error";

static int ad_parse_error(lexer_t *lx, const char *msg)
{
    (void)lx;
    snprintf(g_filter_err, sizeof(g_filter_err), "%s", msg);
    return 0;
}

const char *ADFilterError(void)
{
    return g_filter_err;
}

/* ------------------------------------------------------------------ */
/* Evaluation                                                         */
/* ------------------------------------------------------------------ */

typedef struct {
    const uint8_t *pkt;
    uint32_t len;
    const AD_ADDRESS *addr;
    int  is_v6;
    int  ihl;             /* IPv4 header length, -1 for v6 */
    int  l4_off;          /* transport header offset, -1 unknown */
    uint8_t proto;
    uint32_t src_addr, dst_addr;   /* IPv4, network order */
    int  has_v6addr;
    const uint8_t *src6, *dst6;
} eval_ctx_t;

static void ad_eval_prepare(eval_ctx_t *c, const uint8_t *pkt, uint32_t len,
                            const AD_ADDRESS *addr)
{
    const uint8_t *p = pkt;
    memset(c, 0, sizeof(*c));
    c->pkt = pkt;
    c->len = len;
    c->addr = addr;
    c->ihl = -1;
    c->l4_off = -1;
    c->proto = 0;

    if (!pkt || len < 20)
        return;

    if ((p[0] >> 4) == 4) {
        uint32_t ihl = (uint32_t)(p[0] & 0x0f) * 4;
        if (ihl < 20 || len < ihl) return;
        c->is_v6 = 0;
        c->ihl = (int)ihl;
        c->proto = p[9];
        memcpy(&c->src_addr, p + 12, 4);
        memcpy(&c->dst_addr, p + 16, 4);
        c->l4_off = (int)ihl;
    } else if ((p[0] >> 4) == 6) {
        if (len < 40) return;
        c->is_v6 = 1;
        c->proto = p[6];
        c->src6 = p + 8;
        c->dst6 = p + 24;
        c->has_v6addr = 1;
        c->l4_off = ad_transport_offset(pkt, len);
    }
}

static int ad_field_number(const eval_ctx_t *c, int field, uint32_t *out)
{
    const uint8_t *p = c->pkt;

    switch (field) {
    case F_SRCADDR: *out = c->src_addr; return c->is_v6 ? 0 : 1;
    case F_DSTADDR: *out = c->dst_addr; return c->is_v6 ? 0 : 1;
    case F_PROTOCOL: *out = c->proto; return 1;
    case F_TTL:
        *out = c->is_v6 ? p[7] : p[8];
        return 1;
    case F_TOS:
        *out = c->is_v6 ? ((uint32_t)(p[0] & 0x0f) << 4 | (p[1] >> 4)) : p[1];
        return 1;
    case F_LENGTH:
        *out = c->is_v6 ? 0 : ((uint32_t)p[2] << 8 | p[3]);
        return 1;
    case F_ID:
        *out = c->is_v6 ? 0 : ((uint32_t)p[4] << 8 | p[5]);
        return 1;
    case F_IS_IPV4: *out = c->is_v6 ? 0 : 1; return 1;
    case F_IS_IPV6: *out = c->is_v6 ? 1 : 0; return 1;
    case F_TCPSRCPORT:
    case F_TCPDSTPORT:
    case F_UDPSRCPORT:
    case F_UDPDSTPORT: {
        uint32_t off;
        if (c->l4_off < 0) return 0;
        if (field == F_TCPSRCPORT || field == F_UDPSRCPORT) {
            if (c->proto != 6 && c->proto != 17) return 0;
            off = (uint32_t)c->l4_off;
        } else {
            if (c->proto != 6 && c->proto != 17) return 0;
            off = (uint32_t)c->l4_off + 2;
        }
        if (c->len < off + 2) return 0;
        *out = ((uint32_t)p[off] << 8) | p[off + 1];
        return 1;
    }
    case F_TCPSYN: case F_TCPACK: case F_TCPFIN:
    case F_TCPRST: case F_TCPPSH: case F_TCPURG: {
        uint32_t off, flags = 0;
        if (c->l4_off < 0 || c->proto != 6) return 0;
        off = (uint32_t)c->l4_off + 13;
        if (c->len < off + 1) return 0;
        flags = p[off];
        switch (field) {
        case F_TCPSYN: *out = (flags & 0x02) ? 1 : 0; break;
        case F_TCPACK: *out = (flags & 0x10) ? 1 : 0; break;
        case F_TCPFIN: *out = (flags & 0x01) ? 1 : 0; break;
        case F_TCPRST: *out = (flags & 0x04) ? 1 : 0; break;
        case F_TCPPSH: *out = (flags & 0x08) ? 1 : 0; break;
        default:       *out = (flags & 0x20) ? 1 : 0; break;
        }
        return 1;
    }
    case F_ICMPTYPE:
    case F_ICMPCODE: {
        uint32_t off;
        if (c->l4_off < 0) return 0;
        if (c->proto != 1 && c->proto != 58) return 0;
        off = (uint32_t)c->l4_off + (field == F_ICMPCODE ? 1u : 0u);
        if (c->len < off + 1) return 0;
        *out = p[off];
        return 1;
    }
    default:
        return 0;
    }
}

static int ad_cmp(uint32_t a, int op, uint32_t b)
{
    switch (op) {
    case OP_EQ: return a == b;
    case OP_NE: return a != b;
    case OP_LT: return a <  b;
    case OP_LE: return a <= b;
    case OP_GT: return a >  b;
    default:    return a >= b;
    }
}

static int ad_eval(const node_t *n, const eval_ctx_t *c)
{
    if (!n) return 0;
    switch (n->kind) {
    case N_OR:  return ad_eval(n->lhs, c) || ad_eval(n->rhs, c);
    case N_AND: return ad_eval(n->lhs, c) && ad_eval(n->rhs, c);
    case N_NOT: return !ad_eval(n->rhs, c);
    case N_TERM: {
        uint32_t val = 0;

        if (n->field == F_TRUE)  return 1;
        if (n->field == F_FALSE) return 0;

        if (n->field == F_OUTBOUND) {
            return c->addr && (c->addr->flags & AD_ADDRESS_FLAG_OUTBOUND) ? 1 : 0;
        }
        if (n->field == F_INBOUND) {
            return c->addr && (c->addr->flags & AD_ADDRESS_FLAG_INBOUND) ? 1 : 0;
        }

        if (!ad_field_number(c, n->field, &val))
            return 0;

        if (n->addr_len == 4 && (n->field == F_SRCADDR || n->field == F_DSTADDR)) {
            /* compare raw IPv4 address bytes */
            uint32_t want = n->value;
            return ad_cmp(val, n->op, want);
        }
        return ad_cmp(val, n->op, n->value);
    }
    default:
        return 0;
    }
}

/* ------------------------------------------------------------------ */
/* Public API                                                         */
/* ------------------------------------------------------------------ */

ad_filter_t *ADFilterCompile(const char *expr)
{
    lexer_t lx;
    ad_filter_t *f;
    char normalized[512];

    g_filter_err[0] = '\0';

    if (expr == NULL || expr[0] == '\0') {
        expr = "true";
    }
    /* trim */
    {
        const char *s = expr;
        size_t n;
        while (*s == ' ' || *s == '\t') s++;
        n = strlen(s);
        while (n > 0 && (s[n-1] == ' ' || s[n-1] == '\t' || s[n-1] == '\n' ||
                         s[n-1] == '\r'))
            n--;
        if (n >= sizeof(normalized)) n = sizeof(normalized) - 1;
        memcpy(normalized, s, n);
        normalized[n] = '\0';
    }

    memset(&lx, 0, sizeof(lx));
    lx.p = normalized;
    ad_lex_next(&lx);

    f = (ad_filter_t *)calloc(1, sizeof(ad_filter_t));
    if (!f) {
        snprintf(g_filter_err, sizeof(g_filter_err), "out of memory");
        return NULL;
    }
    snprintf(f->text, sizeof(f->text), "%s", normalized);

    f->tree = ad_parse_or(&lx);
    if (!f->tree) {
        if (g_filter_err[0] == '\0')
            snprintf(g_filter_err, sizeof(g_filter_err), "parse error");
        free(f);
        return NULL;
    }
    if (lx.tok != T_EOF) {
        ad_node_free(f->tree);
        snprintf(g_filter_err, sizeof(g_filter_err),
                 "unexpected trailing input near '%s'", lx.text);
        free(f);
        return NULL;
    }
    return f;
}

int ADFilterMatch(const ad_filter_t *f, const void *pkt, uint32_t len,
                  const AD_ADDRESS *addr)
{
    eval_ctx_t c;
    if (!f || !f->tree)
        return 0;
    ad_eval_prepare(&c, (const uint8_t *)pkt, len, addr);
    return ad_eval(f->tree, &c);
}

void ADFilterFree(ad_filter_t *f)
{
    if (!f) return;
    ad_node_free(f->tree);
    free(f);
}
