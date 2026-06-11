# Survey:四件 kernel 層操作在 stock android15-6.6 上如何做到

對象:KernelSU v2.1.2 `android15-6.6.98_2025-09-boot.img`(= `Linux 6.6.98-android15-8`)。
config 由 `Image15` 內嵌 IKCONFIG 抽出(`kernel15.config`)。

目標解耦後的 kernel 層四件事(指定 interface 上):
1. out:match src mac, ip → 改寫 mac
2. out:match src mac → 攔截到 userspace
3. in:match dst mac, ip → 改寫 mac
4. in:match dst mac + DHCP/ARP/ND → 攔截到 userspace

## 機制可用性(實測)

| 機制 | android15-6.6 |
|---|---|
| nftables `NF_TABLES`/netdev/bridge/`NFT_FWD_NETDEV` | ❌ not set |
| ebtables `BRIDGE_NF_EBTABLES` / `BRIDGE_EBT_T_NAT` | ❌ not set |
| tc `NET_ACT_PEDIT`(改 packet bytes) | ❌ not set |
| tc `NET_CLS_FLOWER`(高階 L2/L3 match) | ❌ not set |
| **eBPF**:`BPF_SYSCALL`/`BPF_JIT`/`DEBUG_INFO_BTF`/`NET_CLS_BPF`/`NET_ACT_BPF` | ✅ y |
| iptables `NETFILTER_XTABLES`/`IP_NF_IPTABLES` | ✅ y |
| **NFQUEUE** `NETFILTER_NETLINK_QUEUE`/`XT_TARGET_NFQUEUE` | ✅ y |
| `xt_mac`(`-m mac --mac-source`,僅 source) | ✅ y |
| tc `NET_SCHED`/`NET_SCH_INGRESS`(clsact)/`NET_CLS_ACT` | ✅ y |
| tc `NET_CLS_U32`/`MATCHALL`/`BASIC`/`FW` | ✅ y |
| tc `NET_ACT_MIRRED`/`SKBEDIT`/`GACT` | ✅ y |
| `PACKET`(AF_PACKET)/`TUN`/`IFB`/`DUMMY`/`VETH`/`BRIDGE` | ✅ y |
| nf hooks `NETFILTER_INGRESS`/`EGRESS` | ✅ y |

**關鍵**:能「改 MAC bytes」的 in-kernel 機制(nft / ebtables-nat / tc-pedit)**全被砍**;唯一剩下的是 **eBPF**(`bpf_skb_store_bytes`)。攔截(redirect 到 userspace)則 classic tc 就能做。

## 四件事的對應

| Op | match | 改寫/攔截 | stock 做法 |
|---|---|---|---|
| 1 out rewrite | `u32`(ether src @ -8/-14、ip)| 改 mac | **僅 eBPF** `cls_bpf`/`act_bpf` + `bpf_skb_store_bytes` |
| 2 out intercept | `u32`(ether src)| redirect | `tc clsact egress + u32 + act_mirred egress redirect dev <tap>` → userspace AF_PACKET |
| 3 in rewrite | `u32`(ether dst、ip)| 改 mac | **僅 eBPF**(同 op1)|
| 4 in intercept | `u32`(ether dst + ethertype 0x0806 ARP / udp 67,68,546,547 DHCP / icmpv6 ND)| redirect | `tc clsact ingress + u32 + act_mirred` → tap;或 iptables `-j NFQUEUE`(僅補 L3:DHCP/ND;dst-mac、ARP 不行)|

→ **攔截(op2/4)可無 eBPF;改寫(op1/3)在 stock 上唯一 in-kernel 路是 eBPF。**

## 三條路線(取捨)

**P1 — eBPF(stock 上唯一能 in-kernel 改寫)**
- `tc qdisc add dev IF clsact` + ingress/egress 掛 `cls_bpf`(direct-action)。
- BPF prog:parse eth/ip → 查 BPF map(ip→mac、valid pair、hostmac)→ `bpf_skb_store_bytes` 改 mac;`bpf_redirect` 轉發;攔截走 `bpf_redirect` 到 tap 或 ringbuf/perf 給 userspace。**maps 取代 nft set/map**,等於 nft 設計的 eBPF 版。
- 障礙:Android **SELinux 限制 `bpf()`**(僅 bpfloader/netd 等域)。KernelSU(root+可注入 sepolicy)才有機會放行。原本「避開 eBPF」的理由現在反轉——nft 沒了,eBPF 是 stock 上唯一的 in-kernel 改寫。

**P2 — stock 無 eBPF(攔截在 kernel,改寫退 userspace)**
- `tc clsact + u32 + act_mirred → tap`:把要處理的類別(含要改寫的 data)導去 userspace;userspace 改 mac 後用 **AF_PACKET 重送**回真 IF(src=HOSTMAC)。
- 因為 stock 無 in-kernel mangle,**op1/3 也只能退到 userspace** → 實質「全資料面在 userspace」(tc/AF_PACKET 只負責 steering)。等同 AF_PACKET+cBPF 方案。
- 優點:**不需 eBPF、不需重編 kernel**;缺點:userspace-bound(手機 radio-bound 場景可接受)。

**P3 — custom kernel(既然 KernelSU 本就 patched kernel)**
- build android15-6.6 / android16-6.12 + config fragment,二選一:
  - 開 `NF_TABLES`+`NF_TABLES_NETDEV`+`NF_TABLES_BRIDGE`+`NFT_FWD_NETDEV` → **沿用現有 nft 設計(PLAN 原樣)**,無 eBPF、最乾淨。
  - 或開 `NET_CLS_FLOWER`+`NET_ACT_PEDIT` → classic tc 設計(flower match mac+ip、pedit 改 mac、mirred/queue 攔截),無 eBPF。
- 在「你本來就在 patch kernel」前提下,**多開幾個 CONFIG 遠比改寫成 eBPF/userspace 省事**。

## 建議
- **能重編 kernel(KernelSU 情境)→ P3 開 nftables**:沿用現有設計,無 eBPF、效能與正確性最佳。**首選**。
- **只能 stock、且能調 sepolicy → P1 eBPF**:stock 上唯一 in-kernel 改寫。
- **只能 stock、連 sepolicy 都不想碰 → P2**:tc/AF_PACKET 全 userspace,慢但可行(Wi-Fi radio-bound 可接受)。
