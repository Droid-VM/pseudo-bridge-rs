// pseudo-bridge ebpf datapath. tc clsact programs, offset-based skb access (no
// direct packet pointer arithmetic -> simple verifier). ARCHITECTURE.md tables.
// One arch-independent object; loaded by aya. ND is fixed in-kernel (csum) and
// forwarded (no drop/reinject); the ringbuf only carries learn tuples.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

static void *(*bpf_map_lookup_elem)(void *, const void *) = (void *)1;
static long (*bpf_map_update_elem)(void *, const void *, const void *, __u64) = (void *)2;
static long (*bpf_skb_store_bytes)(struct __sk_buff *, __u32, const void *, __u32, __u64) = (void *)9;
static long (*bpf_l4_csum_replace)(struct __sk_buff *, __u32, __u64, __u64, __u64) = (void *)11;
static long (*bpf_clone_redirect)(struct __sk_buff *, __u32, __u64) = (void *)13;
static long (*bpf_redirect)(__u32, __u64) = (void *)23;
static long (*bpf_skb_load_bytes)(const void *, __u32, void *, __u32) = (void *)26;
static __s64 (*bpf_csum_diff)(__be32 *, __u32, __be32 *, __u32, __wsum) = (void *)28;
static long (*bpf_ringbuf_output)(void *, void *, __u64, __u64) = (void *)130;

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

struct cfg {
    __u8 hostmac[6];
    __u8 brmac[6];
    __u8 has_brmac;
    __u8 _pad[3]; /* explicit: keep layout byte-identical with the Rust Cfg */
    __u32 up0_ifx;
    __u32 fwd0_ifx;
};
struct in6 { __u8 a[16]; };
struct mac { __u8 a[6]; };
struct copy_evt { __u8 mac[6]; __u8 fam; __u8 _pad; __u8 ip[16]; };

struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct cfg); } config __attribute__((section(".maps"), used));
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __type(key, __u32); __type(value, __u8); } host4 __attribute__((section(".maps"), used));
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256);
    __type(key, struct in6); __type(value, __u8); } host6 __attribute__((section(".maps"), used));
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
    __type(key, __u32); __type(value, struct mac); } ip2mac4 __attribute__((section(".maps"), used));
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 8192);
    __type(key, struct in6); __type(value, struct mac); } ip2mac6 __attribute__((section(".maps"), used));
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 4096);
    __type(key, __u32); __type(value, __u8); } seen4 __attribute__((section(".maps"), used));
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 8192);
    __type(key, struct in6); __type(value, __u8); } seen6 __attribute__((section(".maps"), used));
struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 18); }
    events __attribute__((section(".maps"), used));

#define hs(x) __builtin_bswap16(x)
#define PACKET_BROADCAST 1
#define PACKET_MULTICAST 2
// offsets (L2 header = 14)
#define O_ETH_DST 0
#define O_ETH_SRC 6
#define O_ETHTYPE 12
#define O_V4_PROTO 23
#define O_V4_SRC 26
#define O_V4_DST 30
#define O_V6_NH 20
#define O_V6_SRC 22
#define O_V6_DST 38
#define O_ICMP6 54
#define O_ICMP6_CSUM 56
#define O_NSNA_TGT 62
#define O_NSNA_OPT 78
#define O_RS_OPT 62
#define O_ARP_OP 20
#define O_ARP_SHA 22
#define O_ARP_SPA 28
#define O_ARP_THA 32
#define O_ARP_TPA 38
#define O_UDP_SPORT 34
#define O_UDP_DPORT 36
#define O_UDP_CSUM 40
#define O_BOOTP_FLAGS 52

static __always_inline struct cfg *getcfg(void) {
    __u32 k = 0;
    return bpf_map_lookup_elem(&config, &k);
}
static __always_inline int mac_eq(const __u8 *a, const __u8 *b) {
    for (int i = 0; i < 6; i++) if (a[i] != b[i]) return 0;
    return 1;
}
static __always_inline void mark_seen4(__u32 ip) { __u8 one = 1; bpf_map_update_elem(&seen4, &ip, &one, 0); }
static __always_inline void mark_seen6(struct in6 *ip) { __u8 one = 1; bpf_map_update_elem(&seen6, ip, &one, 0); }
static __always_inline void learn4(__u32 ip, const __u8 *mac) {
    struct copy_evt ev = {}; for (int i=0;i<6;i++) ev.mac[i]=mac[i]; ev.fam=4;
    __builtin_memcpy(ev.ip, &ip, 4);
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}
static __always_inline void learn6(struct in6 *ip, const __u8 *mac) {
    struct copy_evt ev = {}; for (int i=0;i<6;i++) ev.mac[i]=mac[i]; ev.fam=6;
    for (int i=0;i<16;i++) ev.ip[i]=ip->a[i];
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}
static __always_inline int is_unspec16(const struct in6 *a) {
    for (int i = 0; i < 16; i++) if (a->a[i]) return 0;
    return 1;
}

// Rewrite an ND LLA option to HOSTMAC and fix the ICMPv6 csum. opt_off = option
// start (type,len,mac). Returns 1 if rewritten.
static __always_inline int nd_rewrite(struct __sk_buff *skb, __u32 opt_off, __u8 want_type, const __u8 *hostmac) {
    __u8 oldopt[8], newopt[8];
    if (bpf_skb_load_bytes(skb, opt_off, oldopt, 8) < 0) return 0;
    if (oldopt[0] != want_type) return 0;
    if (mac_eq(&oldopt[2], hostmac)) return 0; // already HOSTMAC (idempotent)
    for (int i = 0; i < 8; i++) newopt[i] = oldopt[i];
    for (int i = 0; i < 6; i++) newopt[2 + i] = hostmac[i];
    __s64 diff = bpf_csum_diff((__be32 *)oldopt, 8, (__be32 *)newopt, 8, 0);
    bpf_l4_csum_replace(skb, O_ICMP6_CSUM, 0, diff, 0);
    bpf_skb_store_bytes(skb, opt_off + 2, hostmac, 6, 0);
    return 1;
}

// shared OUT logic. redirect_to: if nonzero, bpf_redirect there; else TC_ACT_OK.
static __always_inline int out_common(struct __sk_buff *skb, int is_direct) {
    struct cfg *c = getcfg();
    if (!c) return TC_ACT_OK;
    __u8 src[6];
    if (bpf_skb_load_bytes(skb, O_ETH_SRC, src, 6) < 0) return TC_ACT_OK;
    __u32 to = is_direct ? 0 : c->up0_ifx;
#define TERM (is_direct ? TC_ACT_OK : bpf_redirect(to, 0))

    if (mac_eq(src, c->hostmac)) {
        if (is_direct) return (skb->ingress_ifindex == 0) ? TC_ACT_OK : TC_ACT_SHOT;
        return TC_ACT_SHOT;
    }
    if (!is_direct && c->has_brmac && mac_eq(src, c->brmac)) return TC_ACT_SHOT;

    __u16 proto;
    if (bpf_skb_load_bytes(skb, O_ETHTYPE, &proto, 2) < 0) return TERM;

    if (proto == hs(ETH_P_IP)) {
        __u8 l4 = 0;
        bpf_skb_load_bytes(skb, O_V4_PROTO, &l4, 1);
        if (l4 == 17) {
            __u16 sp = 0, dp = 0;
            bpf_skb_load_bytes(skb, O_UDP_SPORT, &sp, 2);
            bpf_skb_load_bytes(skb, O_UDP_DPORT, &dp, 2);
            if (sp == hs(68) && dp == hs(67)) {
                __u8 bf[2] = {0x80, 0x00};
                bpf_skb_store_bytes(skb, O_BOOTP_FLAGS, bf, 2, 0);
                __u8 z[2] = {0, 0};
                bpf_skb_store_bytes(skb, O_UDP_CSUM, z, 2, 0);
                bpf_skb_store_bytes(skb, O_ETH_SRC, c->hostmac, 6, 0);
                return TERM;
            }
        }
        __u32 ip;
        bpf_skb_load_bytes(skb, O_V4_SRC, &ip, 4);
        struct mac *m = bpf_map_lookup_elem(&ip2mac4, &ip);
        if (m && mac_eq(m->a, src)) {
            mark_seen4(ip);
            bpf_skb_store_bytes(skb, O_ETH_SRC, c->hostmac, 6, 0);
            return TERM;
        }
        learn4(ip, src);
        bpf_skb_store_bytes(skb, O_ETH_SRC, c->hostmac, 6, 0);
        return TERM;
    }
    if (proto == hs(ETH_P_ARP)) {
        bpf_skb_store_bytes(skb, O_ARP_SHA, c->hostmac, 6, 0);
        __u32 spa;
        bpf_skb_load_bytes(skb, O_ARP_SPA, &spa, 4);
        learn4(spa, src);
        mark_seen4(spa);
        bpf_skb_store_bytes(skb, O_ETH_SRC, c->hostmac, 6, 0);
        return TERM;
    }
    if (proto == hs(ETH_P_IPV6)) {
        __u8 nh = 0;
        bpf_skb_load_bytes(skb, O_V6_NH, &nh, 1);
        struct in6 s6;
        bpf_skb_load_bytes(skb, O_V6_SRC, &s6, 16);
        if (nh == 58) {
            __u8 t = 0;
            bpf_skb_load_bytes(skb, O_ICMP6, &t, 1);
            if (t == 135) { // NS
                if (is_unspec16(&s6)) { // DAD: learn target, no rewrite
                    struct in6 tgt; bpf_skb_load_bytes(skb, O_NSNA_TGT, &tgt, 16);
                    learn6(&tgt, src); mark_seen6(&tgt);
                    bpf_skb_store_bytes(skb, O_ETH_SRC, c->hostmac, 6, 0);
                    return TERM;
                }
                nd_rewrite(skb, O_NSNA_OPT, 1, c->hostmac);
                learn6(&s6, src); mark_seen6(&s6);
                bpf_skb_store_bytes(skb, O_ETH_SRC, c->hostmac, 6, 0);
                return TERM;
            }
            if (t == 136) { // NA: learn target
                nd_rewrite(skb, O_NSNA_OPT, 2, c->hostmac);
                struct in6 tgt; bpf_skb_load_bytes(skb, O_NSNA_TGT, &tgt, 16);
                learn6(&tgt, src); mark_seen6(&tgt);
                bpf_skb_store_bytes(skb, O_ETH_SRC, c->hostmac, 6, 0);
                return TERM;
            }
            if (t == 133) { // RS
                if (!is_unspec16(&s6)) {
                    nd_rewrite(skb, O_RS_OPT, 1, c->hostmac);
                    learn6(&s6, src); mark_seen6(&s6);
                }
                bpf_skb_store_bytes(skb, O_ETH_SRC, c->hostmac, 6, 0);
                return TERM;
            }
        }
        // valid / else
        struct mac *m = bpf_map_lookup_elem(&ip2mac6, &s6);
        if (m && mac_eq(m->a, src)) {
            mark_seen6(&s6);
            bpf_skb_store_bytes(skb, O_ETH_SRC, c->hostmac, 6, 0);
            return TERM;
        }
        if (!is_unspec16(&s6)) learn6(&s6, src);
        bpf_skb_store_bytes(skb, O_ETH_SRC, c->hostmac, 6, 0);
        return TERM;
    }
    return TERM;
#undef TERM
}

static __always_inline int in_common(struct __sk_buff *skb, int is_direct) {
    struct cfg *c = getcfg();
    if (!c) return TC_ACT_OK;
    __u8 dst[6];
    if (bpf_skb_load_bytes(skb, O_ETH_DST, dst, 6) < 0) return TC_ACT_OK;
    int dst_is_host = mac_eq(dst, c->hostmac);
    __u32 fwd0 = c->fwd0_ifx;
    __u16 proto;
    if (bpf_skb_load_bytes(skb, O_ETHTYPE, &proto, 2) < 0) return TC_ACT_OK;

    // host accept
    if (proto == hs(ETH_P_IP) && dst_is_host) {
        __u32 ip; bpf_skb_load_bytes(skb, O_V4_DST, &ip, 4);
        if (bpf_map_lookup_elem(&host4, &ip)) return TC_ACT_OK;
    }
    if (proto == hs(ETH_P_ARP)) {
        __u32 tpa; bpf_skb_load_bytes(skb, O_ARP_TPA, &tpa, 4);
        if (bpf_map_lookup_elem(&host4, &tpa)) return TC_ACT_OK;
    }
    if (proto == hs(ETH_P_IPV6) && dst_is_host) {
        struct in6 ip; bpf_skb_load_bytes(skb, O_V6_DST, &ip, 16);
        if (bpf_map_lookup_elem(&host6, &ip)) return TC_ACT_OK;
    }
    // bcast/mcast -> dup to guest side (fwd mode only; direct lets bridge flood)
    if (!is_direct) {
        if (skb->pkt_type == PACKET_BROADCAST || skb->pkt_type == PACKET_MULTICAST) {
            bpf_clone_redirect(skb, fwd0, 0);
            return TC_ACT_OK;
        }
    }
    // demux
    if (proto == hs(ETH_P_IP) && dst_is_host) {
        __u32 ip; bpf_skb_load_bytes(skb, O_V4_DST, &ip, 4);
        struct mac *m = bpf_map_lookup_elem(&ip2mac4, &ip);
        if (m) {
            bpf_skb_store_bytes(skb, O_ETH_DST, m->a, 6, 0);
            return is_direct ? TC_ACT_OK : bpf_redirect(fwd0, 0);
        }
    }
    if (proto == hs(ETH_P_IPV6) && dst_is_host) {
        struct in6 ip; bpf_skb_load_bytes(skb, O_V6_DST, &ip, 16);
        struct mac *m = bpf_map_lookup_elem(&ip2mac6, &ip);
        if (m) {
            bpf_skb_store_bytes(skb, O_ETH_DST, m->a, 6, 0);
            return is_direct ? TC_ACT_OK : bpf_redirect(fwd0, 0);
        }
    }
    if (proto == hs(ETH_P_ARP) && dst_is_host) {
        __u32 tpa; bpf_skb_load_bytes(skb, O_ARP_TPA, &tpa, 4);
        struct mac *m = bpf_map_lookup_elem(&ip2mac4, &tpa);
        if (m) {
            bpf_skb_store_bytes(skb, O_ARP_THA, m->a, 6, 0);
            bpf_skb_store_bytes(skb, O_ETH_DST, m->a, 6, 0);
            return is_direct ? TC_ACT_OK : bpf_redirect(fwd0, 0);
        }
    }
    return TC_ACT_OK;
}

__attribute__((section("classifier/fwd_out"), used))
int fwd_out(struct __sk_buff *skb) { return out_common(skb, 0); }
__attribute__((section("classifier/fwd_in"), used))
int fwd_in(struct __sk_buff *skb) { return in_common(skb, 0); }
__attribute__((section("classifier/direct_out"), used))
int direct_out(struct __sk_buff *skb) { return out_common(skb, 1); }
__attribute__((section("classifier/direct_in"), used))
int direct_in(struct __sk_buff *skb) { return in_common(skb, 1); }

__attribute__((section("classifier/egress_guard"), used))
int egress_guard(struct __sk_buff *skb) {
    struct cfg *c = getcfg();
    if (!c) return TC_ACT_OK;
    __u8 src[6];
    if (bpf_skb_load_bytes(skb, O_ETH_SRC, src, 6) < 0) return TC_ACT_OK;
    if (!mac_eq(src, c->hostmac)) bpf_skb_store_bytes(skb, O_ETH_SRC, c->hostmac, 6, 0);

    // Discovery dup: a host-originated ARP-request / NS for an unknown target is cloned to
    // fwd0 so a *silent* guest (static IP, no traffic yet) replies and gets learned — then
    // host->guest works on retry via the /32-/128 vmroute. Clone (not redirect): the original
    // still goes upstream so the gateway is still resolved. Only host-originated: if the
    // source IP is already a learned guest (in ip2mac), it's guest ARP/NS that was redirected
    // here, so we don't echo it back.
    __u16 proto;
    if (bpf_skb_load_bytes(skb, O_ETHTYPE, &proto, 2) < 0) return TC_ACT_OK;
    if (proto == hs(ETH_P_ARP)) {
        __u16 op = 0;
        bpf_skb_load_bytes(skb, O_ARP_OP, &op, 2);
        if (op == hs(1)) { // request
            __u32 spa = 0;
            bpf_skb_load_bytes(skb, O_ARP_SPA, &spa, 4);
            // spa != 0: skip RFC 5227 ACD probes (v4 analog of the NS src != :: DAD guard
            // below). Else the guest's own probe is cloned back over the bridge and read as a
            // conflict, so the guest declines every DHCP offer.
            if (spa != 0 && !bpf_map_lookup_elem(&ip2mac4, &spa))
                bpf_clone_redirect(skb, c->fwd0_ifx, 0);
        }
    } else if (proto == hs(ETH_P_IPV6)) {
        __u8 nh = 0;
        bpf_skb_load_bytes(skb, O_V6_NH, &nh, 1);
        if (nh == 58) {
            __u8 t = 0;
            bpf_skb_load_bytes(skb, O_ICMP6, &t, 1);
            if (t == 135) { // NS
                struct in6 s6;
                bpf_skb_load_bytes(skb, O_V6_SRC, &s6, 16);
                if (!is_unspec16(&s6) && !bpf_map_lookup_elem(&ip2mac6, &s6))
                    bpf_clone_redirect(skb, c->fwd0_ifx, 0);
            }
        }
    }
    return TC_ACT_OK;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
