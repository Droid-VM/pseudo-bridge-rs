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
static __u64 (*bpf_get_current_pid_tgid)(void) = (void *)14;
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
struct copy_evt { __u8 mac[6]; __u8 kind; __u8 fam; __u8 ip[16]; };

/* APF watchdog config. Deliberately NOT part of `config`: that map's layout is a
 * fixed ABI shared with the Rust `Cfg` struct, and the datapath reads it per packet.
 * enabled=0 makes the kprobe a single map lookup + return.
 */
struct wdcfg {
    __u32 enabled;
    __u32 self_tgid; /* pbridge's own TGID: its APF transactions must not self-trigger */
};

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
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1);
    __type(key, __u32); __type(value, struct wdcfg); } apf_wd __attribute__((section(".maps"), used));

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
#define O_BOOTP_OP 42
#define O_BOOTP_YIADDR 58
#define O_BOOTP_CHADDR 70
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
    struct copy_evt ev = {}; for (int i=0;i<6;i++) ev.mac[i]=mac[i]; ev.kind=0; ev.fam=4;
    __builtin_memcpy(ev.ip, &ip, 4);
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}
static __always_inline void learn6(struct in6 *ip, const __u8 *mac) {
    struct copy_evt ev = {}; for (int i=0;i<6;i++) ev.mac[i]=mac[i]; ev.kind=0; ev.fam=6;
    for (int i=0;i<16;i++) ev.ip[i]=ip->a[i];
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}
// Upstream ARP request for an installed guest. ip[0..4] is the target guest IP,
// ip[4..8] is the requester IP. Keep the original request flowing as a fallback.
static __always_inline void arp_request4(__u32 target, __u32 requester, const __u8 *mac) {
    if (!requester || !bpf_map_lookup_elem(&ip2mac4, &target)) return;
    struct copy_evt ev = {};
    for (int i = 0; i < 6; i++) ev.mac[i] = mac[i];
    ev.kind = 1; ev.fam = 4;
    __builtin_memcpy(&ev.ip[0], &target, 4);
    __builtin_memcpy(&ev.ip[4], &requester, 4);
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}
static __always_inline int is_unspec16(const struct in6 *a) {
    for (int i = 0; i < 16; i++) if (a->a[i]) return 0;
    return 1;
}

static __always_inline void dhcp_request4(const __u8 *src);
static __always_inline void dhcp_ack4(struct __sk_buff *skb);

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
        // direct: OUT is up0 egress, so a locally generated skb (ingress_ifindex == 0) is
        // the host itself and passes; a bridged copy from a guest port does not.
        // fwd: OUT is fwd0 INGRESS, where ingress_ifindex is never 0. Host-originated
        // frames demuxed into fwd0 by egress_guard leave through fwd0 egress into fwd1 and
        // never come back here, so anything with src == HOSTMAC on this hook is a bridge
        // flood copy or a guest forging our MAC: always drop.
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
                dhcp_request4(src);
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

static __always_inline int dhcp_is_ack(struct __sk_buff *skb) {
    // DHCP magic cookie ends at offset 282. Avoid variable stack indexing (rejected by
    // Android's verifier), but accept the two common layouts: message type first, or
    // a 4-byte server-id option followed by message type.
    __u8 opts[9] = {};
    if (bpf_skb_load_bytes(skb, 282, opts, sizeof(opts)) < 0) return 0;
    if (opts[0] == 53 && opts[1] == 1 && opts[2] == 5) return 1;
    return opts[0] == 54 && opts[1] == 4 && opts[6] == 53
        && opts[7] == 1 && opts[8] == 5;
}

static __always_inline void dhcp_request4(const __u8 *src) {
    struct copy_evt ev = {};
    // OUT already established UDP 68→67; do not reparse variable DHCP options here.
    // The following ACK still carries the authoritative option-53=ACK + yiaddr.
    for (int i = 0; i < 6; i++) ev.mac[i] = src[i];
    ev.kind = 4; ev.fam = 4;
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}

static __always_inline void dhcp_ack4(struct __sk_buff *skb) {
    // BOOTP starts at UDP payload offset 42. A DHCPACK is BOOTREPLY(op=2),
    // server port 67 -> client port 68, and option 53 == 5. The device verifier
    // requires the option to be at the first post-cookie slot; unknown layouts
    // fail closed rather than expanding automatic APF access.
    // chaddr is copied as the client identity; userspace bounds the automatic
    // lease set and accepts it only in explicit `--apf-watchdog` DHCP mode.
    __u8 op = 0;
    __u32 yiaddr = 0;
    struct copy_evt ev = {};
    if (bpf_skb_load_bytes(skb, O_BOOTP_OP, &op, 1) < 0 || op != 2) return;
    if (bpf_skb_load_bytes(skb, O_BOOTP_YIADDR, &yiaddr, 4) < 0 || !yiaddr) return;
    if (!dhcp_is_ack(skb)) return;
    if (bpf_skb_load_bytes(skb, O_BOOTP_CHADDR, ev.mac, 6) < 0) return;
    ev.kind = 3; ev.fam = 4;
    __builtin_memcpy(&ev.ip, &yiaddr, 4);
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
}

static __always_inline int in_common(struct __sk_buff *skb, int is_direct) {
    struct cfg *c = getcfg();
    if (!c) return TC_ACT_OK;
    __u8 dst[6], src[6];
    if (bpf_skb_load_bytes(skb, O_ETH_DST, dst, 6) < 0) return TC_ACT_OK;
    if (bpf_skb_load_bytes(skb, O_ETH_SRC, src, 6) < 0) return TC_ACT_OK;
    // Reflected self-frame guard: a Wi-Fi AP echoes a STA's own transmissions back
    // down (broadcasts at the next DTIM, unicast-to-own-mac via hairpin), so frames
    // with src == HOSTMAC can and do arrive on up0 ingress. They are always copies of
    // something we sent; processing them is poison — a reflected GARP/keepalive would
    // be dup'd into the guest bridge and repoint the host's own neighbour entry for a
    // guest to HOSTMAC (host->guest then dies on the OUT src-drop), and a hairpinned
    // ARP reply would be demuxed back to a guest, teaching it host-ip -> HOSTMAC.
    if (mac_eq(src, c->hostmac)) return TC_ACT_SHOT;
    int dst_is_host = mac_eq(dst, c->hostmac);
    __u32 fwd0 = c->fwd0_ifx;
    __u16 proto;
    if (bpf_skb_load_bytes(skb, O_ETHTYPE, &proto, 2) < 0) return TC_ACT_OK;
    // DHCPACK is an inbound server->client packet. Surface it before host accept / multicast
    // duplication so an unlearned DHCP guest gets a real binding as soon as it acquires its
    // lease; normal bridge flooding still delivers the packet unchanged.
    if (proto == hs(ETH_P_IP)) {
        __u8 l4 = 0;
        __u16 sp = 0, dp = 0;
        bpf_skb_load_bytes(skb, O_V4_PROTO, &l4, 1);
        if (l4 == 17) {
            bpf_skb_load_bytes(skb, O_UDP_SPORT, &sp, 2);
            bpf_skb_load_bytes(skb, O_UDP_DPORT, &dp, 2);
            if (sp == hs(67) && dp == hs(68)) dhcp_ack4(skb);
        }
    }

    // host accept
    if (proto == hs(ETH_P_IP) && dst_is_host) {
        __u32 ip; bpf_skb_load_bytes(skb, O_V4_DST, &ip, 4);
        if (bpf_map_lookup_elem(&host4, &ip)) return TC_ACT_OK;
    }
    if (proto == hs(ETH_P_ARP)) {
        __u32 tpa; bpf_skb_load_bytes(skb, O_ARP_TPA, &tpa, 4);
        if (bpf_map_lookup_elem(&host4, &tpa)) return TC_ACT_OK;
        __u16 op = 0;
        bpf_skb_load_bytes(skb, O_ARP_OP, &op, 2);
        if (op == hs(1)) {
            __u8 sha[6];
            __u32 spa = 0;
            bpf_skb_load_bytes(skb, O_ARP_SHA, sha, 6);
            bpf_skb_load_bytes(skb, O_ARP_SPA, &spa, 4);
            if (mac_eq(sha, src)) arp_request4(tpa, spa, src);
        }
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

// A host-originated packet can briefly keep the connected up0 route that was selected
// before the guest learned. Its up0 neighbour is filled with HOSTMAC by the control plane;
// demux the packet here so that queued traffic still reaches the guest instead of leaving
// wlan0 with a destination of HOSTMAC. Packets redirected from fwd0 have a non-zero
// ingress_ifindex and are deliberately left on the normal upstream path (guest-to-guest
// traffic must not loop back into fwd0).
static __always_inline int host_egress_demux(struct __sk_buff *skb, struct cfg *c, __u16 proto) {
    if (skb->ingress_ifindex != 0 || c->fwd0_ifx == 0) return 0;
    if (proto == hs(ETH_P_IP)) {
        __u32 dst;
        if (bpf_skb_load_bytes(skb, O_V4_DST, &dst, 4) < 0) return 0;
        struct mac *m = bpf_map_lookup_elem(&ip2mac4, &dst);
        if (m) {
            bpf_skb_store_bytes(skb, O_ETH_DST, m->a, 6, 0);
            return bpf_redirect(c->fwd0_ifx, 0);
        }
    } else if (proto == hs(ETH_P_IPV6)) {
        struct in6 dst;
        if (bpf_skb_load_bytes(skb, O_V6_DST, &dst, 16) < 0) return 0;
        struct mac *m = bpf_map_lookup_elem(&ip2mac6, &dst);
        if (m) {
            bpf_skb_store_bytes(skb, O_ETH_DST, m->a, 6, 0);
            return bpf_redirect(c->fwd0_ifx, 0);
        }
    }
    return 0;
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
    // fwd0 so a *silent* guest (static IP, no traffic yet) replies and gets learned. The host
    // egress demux handles a packet that was queued on up0 while learning completed. Clone
    // (not redirect): the original
    // still goes upstream so the gateway is still resolved. Only host-originated: if the
    // source IP is already a learned guest (in ip2mac), it's guest ARP/NS that was redirected
    // here, so we don't echo it back.
    //
    // The clone is made ADDRESS-ANONYMOUS before it enters the guest bridge (ARP: spa=0,
    // the RFC 5227 probe form; NS: src=:: + SLLAO neutralized, the DAD form) and the
    // original is restored right after (clone_redirect snapshots the current skb). A clone
    // carrying "host-ip @ HOSTMAC" teaches every guest that mapping — correct on the wire
    // but wrong on the bridge segment (there the host is the bridge's mac), so a guest
    // would send all host-bound traffic out the uplink instead. Guests still answer the
    // anonymous probe (defend/DAD reply), the reply is addressed to sha/L2 = HOSTMAC, so
    // it crosses fwd0 and gets learned exactly as before. Only broadcast (ARP) /
    // solicited-node multicast (NS) solicitations are cloned — a unicast NUD probe cannot
    // discover a silent guest, and the kernel falls back to multicast resolution anyway.
    __u16 proto;
    if (bpf_skb_load_bytes(skb, O_ETHTYPE, &proto, 2) < 0) return TC_ACT_OK;
    int host_demux = host_egress_demux(skb, c, proto);
    if (host_demux) return host_demux;
    __u8 dst[6];
    if (bpf_skb_load_bytes(skb, O_ETH_DST, dst, 6) < 0) return TC_ACT_OK;
    if (proto == hs(ETH_P_ARP)) {
        __u8 bcast[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
        __u16 op = 0;
        bpf_skb_load_bytes(skb, O_ARP_OP, &op, 2);
        if (op == hs(1) && mac_eq(dst, bcast)) { // broadcast request
            __u32 spa = 0;
            bpf_skb_load_bytes(skb, O_ARP_SPA, &spa, 4);
            // spa != 0: skip RFC 5227 ACD probes (v4 analog of the NS src != :: DAD guard
            // below). Else the guest's own probe is cloned back over the bridge and read as a
            // conflict, so the guest declines every DHCP offer.
            if (spa != 0 && !bpf_map_lookup_elem(&ip2mac4, &spa)) {
                __u32 zero = 0;
                bpf_skb_store_bytes(skb, O_ARP_SPA, &zero, 4, 0); // ACD-ize (no ARP csum)
                bpf_clone_redirect(skb, c->fwd0_ifx, 0);
                bpf_skb_store_bytes(skb, O_ARP_SPA, &spa, 4, 0); // restore for the wire
            }
        }
    } else if (proto == hs(ETH_P_IPV6)) {
        __u8 nh = 0;
        bpf_skb_load_bytes(skb, O_V6_NH, &nh, 1);
        // dst 33:33:* = IPv6 multicast mac (solicited-node resolution NS)
        if (nh == 58 && dst[0] == 0x33 && dst[1] == 0x33) {
            __u8 t = 0;
            bpf_skb_load_bytes(skb, O_ICMP6, &t, 1);
            if (t == 135) { // NS
                struct in6 s6;
                __u8 o4[4]; // first ND option: type, len, mac[0..2]
                bpf_skb_load_bytes(skb, O_V6_SRC, &s6, 16);
                if (!is_unspec16(&s6) && !bpf_map_lookup_elem(&ip2mac6, &s6) &&
                    bpf_skb_load_bytes(skb, O_NSNA_OPT, o4, 4) == 0 && o4[0] == 1) {
                    // DAD-ize the clone: src -> ::, SLLAO type -> unassigned(200) so
                    // receivers ignore it (a DAD NS must carry no SLLAO; RFC 4861 §7.1.1
                    // only rejects a *recognized* source-lladdr option, unknown options
                    // are skipped). Both edits are ICMPv6-csum-covered (src via the
                    // pseudo-header) — incremental fix, then undo everything post-clone.
                    struct in6 zero6 = {};
                    __u8 n4[4] = {200, o4[1], o4[2], o4[3]};
                    __s64 dsrc = bpf_csum_diff((__be32 *)s6.a, 16, (__be32 *)zero6.a, 16, 0);
                    __s64 dopt = bpf_csum_diff((__be32 *)o4, 4, (__be32 *)n4, 4, 0);
                    bpf_l4_csum_replace(skb, O_ICMP6_CSUM, 0, dsrc, 0);
                    bpf_l4_csum_replace(skb, O_ICMP6_CSUM, 0, dopt, 0);
                    bpf_skb_store_bytes(skb, O_V6_SRC, zero6.a, 16, 0);
                    bpf_skb_store_bytes(skb, O_NSNA_OPT, n4, 1, 0);
                    bpf_clone_redirect(skb, c->fwd0_ifx, 0);
                    __s64 rsrc = bpf_csum_diff((__be32 *)zero6.a, 16, (__be32 *)s6.a, 16, 0);
                    __s64 ropt = bpf_csum_diff((__be32 *)n4, 4, (__be32 *)o4, 4, 0);
                    bpf_l4_csum_replace(skb, O_ICMP6_CSUM, 0, rsrc, 0);
                    bpf_l4_csum_replace(skb, O_ICMP6_CSUM, 0, ropt, 0);
                    bpf_skb_store_bytes(skb, O_V6_SRC, s6.a, 16, 0);
                    bpf_skb_store_bytes(skb, O_NSNA_OPT, o4, 1, 0);
                }
            }
        }
    }
    return TC_ACT_OK;
}

// APF watchdog notification. wlan_hdd_cfg80211_apf_offload() is the driver's ONLY
// entry point for QCA_NL80211_VENDOR_SUBCMD_PACKET_FILTER, so this one probe covers
// every sub-command: legacy SET (what NetworkStack currently uses), APF 3.0
// WRITE/READ, and enable/disable. We deliberately do NOT inspect the sub-command:
// the arguments are a cfg80211 wiphy/wdev + an unparsed nlattr blob, and reading them
// would buy nothing — userspace debounces anyway and any external touch of the APF
// path is a reason to re-verify the program.
//
// Self-filter by TGID: pbridge's own transaction is four vendor commands
// (disable/read/write/enable). Without the filter each of them would re-arm the
// watchdog and the process would spin forever repatching its own work.
//
// Only bpf_get_current_pid_tgid() is used — no argument reads, no kallsyms lookups,
// no CO-RE relocations — so this is safe on Android GKI where module symbol addresses
// read as 0 and KASLR is on. If the symbol does not exist, attach() fails at init and
// pbridge exits rather than pretending the watchdog is armed.
__attribute__((section("kprobe/wlan_hdd_cfg80211_apf_offload"), used))
int apf_offload_probe(void *ctx) {
    __u32 k = 0;
    struct wdcfg *w = bpf_map_lookup_elem(&apf_wd, &k);
    if (!w || !w->enabled) return 0;
    __u32 tgid = bpf_get_current_pid_tgid() >> 32;
    if (tgid == w->self_tgid) return 0;
    struct copy_evt ev = {};
    ev.kind = 2; /* EVT_APF_EXTERNAL_WRITE */
    __builtin_memcpy(ev.ip, &tgid, 4);
    bpf_ringbuf_output(&events, &ev, sizeof(ev), 0);
    return 0;
}

char _license[] __attribute__((section("license"), used)) = "GPL";
