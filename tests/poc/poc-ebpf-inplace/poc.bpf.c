// PoC: can ebpf (tc/cls_bpf) do in-place L2 rewrite, incl. ND LLA + ICMPv6 csum?
// On a0 ingress: rewrite eth.src (+ ARP sha / ND SLLAO mac) to cfg.mac, fix the
// ICMPv6 checksum incrementally (bpf_csum_diff + bpf_l4_csum_replace), then
// bpf_redirect to cfg.ifx (observe port). Verifies the §offload "ebpf in-place"
// premise for ARP/ND in ARCHITECTURE.md.
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/pkt_cls.h>

static void *(*bpf_map_lookup_elem)(void *map, const void *key) = (void *)1;
static long (*bpf_skb_store_bytes)(struct __sk_buff *, __u32, const void *, __u32, __u64) = (void *)9;
static long (*bpf_l4_csum_replace)(struct __sk_buff *, __u32, __u64, __u64, __u64) = (void *)10;
static long (*bpf_redirect)(__u32, __u64) = (void *)23;
static long (*bpf_skb_load_bytes)(const void *, __u32, void *, __u32) = (void *)26;
static __s64 (*bpf_csum_diff)(__be32 *, __u32, __be32 *, __u32, __wsum) = (void *)28;

#define __uint(name, val) int (*name)[val]
#define __type(name, val) typeof(val) *name

struct cfg { __u32 ifx; __u8 mac[6]; __u8 pad[2]; };
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct cfg);
} config __attribute__((section(".maps"), used));

#define ETH 14
#define hs(x) __builtin_bswap16(x)

__attribute__((section("tc"), used))
int poc(struct __sk_buff *skb) {
    __u32 k = 0;
    struct cfg *c = bpf_map_lookup_elem(&config, &k);
    if (!c) return TC_ACT_OK;

    __u16 proto;
    if (bpf_skb_load_bytes(skb, 12, &proto, 2) < 0) return TC_ACT_OK;

    if (proto == hs(ETH_P_ARP)) {
        bpf_skb_store_bytes(skb, 6, c->mac, 6, 0);         // eth.src
        bpf_skb_store_bytes(skb, ETH + 8, c->mac, 6, 0);   // arp.sha (payload off 8)
        return bpf_redirect(c->ifx, 0);
    }
    if (proto == hs(ETH_P_IPV6)) {
        __u8 nh;
        if (bpf_skb_load_bytes(skb, ETH + 6, &nh, 1) == 0 && nh == 58) {
            __u32 icmp = ETH + 40;          // 54
            __u8 type;
            if (bpf_skb_load_bytes(skb, icmp, &type, 1) == 0 && (type == 135 || type == 136)) {
                __u32 opt = icmp + 24;       // 78  (NS/NA option start)
                __u32 csum_off = icmp + 2;   // 56  (ICMPv6 checksum)
                __u8 oldopt[8], newopt[8];
                if (bpf_skb_load_bytes(skb, opt, oldopt, 8) == 0 && (oldopt[0] == 1 || oldopt[0] == 2)) {
                    for (int i = 0; i < 8; i++) newopt[i] = oldopt[i];
                    for (int i = 0; i < 6; i++) newopt[2 + i] = c->mac[i];
                    __s64 diff = bpf_csum_diff((void *)oldopt, 8, (void *)newopt, 8, 0);
                    bpf_l4_csum_replace(skb, csum_off, 0, diff, 0);  // size=0 → to is the diff
                    bpf_skb_store_bytes(skb, opt + 2, c->mac, 6, 0); // ND LLA mac
                    bpf_skb_store_bytes(skb, 6, c->mac, 6, 0);       // eth.src
                }
            }
        }
        return bpf_redirect(c->ifx, 0);
    }
    return bpf_redirect(c->ifx, 0);
}
char _license[] __attribute__((section("license"), used)) = "GPL";
