# pseudo-bridge 架構

multi-guest 共用一個「只認得單一 mac」的上游口(Wi-Fi STA、或被交換機限制 src-mac 的有線口)上網,做法類似 macOS 的 pseudo-bridge / MAC-NAT。

## 說明

指定上游網卡 `up0`,對它的出入封包做 L2 改寫 + demux:

    out:guest 封包 src mac → HOSTMAC(up0 對外的 mac)後送出 up0
    in :從 up0 回來的封包,用 dst-ip demux 回正確的 guest mac

封包轉發、改寫、(要 learn 的)複製到 userspace 全在 kernel hook 做;userspace(rust)只當控制層:learn、caps、老化、把狀態 reconcile 進 kernel。

**部署約束:產物在 Android 上跑**(在 Android host 上,給 pKVM 的 VM guest 共用單一上游),故 pbridge **一律不 shell out 任何 CLI 工具**(`ip` / `brctl` / `bpftool` / `tc` / `nft` 都不呼叫)—— 全部改用 Rust 封裝好的庫 / 直接 syscall:link·addr·route 用 **rtnetlink**、ebpf 載入 + map 操作用 **libbpf-rs / aya**、nft ruleset/set/map 用 **netlink(rustables / nftnl)**、L2 收送(ND 補發)用 **AF_PACKET(libc)**。理由:Android 上這些 binary 不保證存在、版本/行為不一,且要避開對外部執行檔及其 SELinux/權限介面的依賴(測試 harness 不受此限,可自由用 CLI)。

### cli 參數

    -i  --interface         上游網卡,下文簡稱 up0
    -e  --offload-engine    nft | ebpf
    -m  --mode              direct | fwd | fwd-with-offload(= fwd + ND/ARP offload 繞道預設開 v4,v6;見 §ND/ARP offload 繞道)
    -fi --fwd-device-if     fwd mode 的 veth 名稱,下文簡稱 fwd0(預設 {ifname[:12]}-if)
    -fb --fwd-device-br     fwd mode 的 veth 名稱,下文簡稱 fwd1(預設 {ifname[:12]}-br)
        --nflog-group       nft NFLOG group(下文 <g>);預設 32123
        --timeout           entry idle 老化秒數;預設 30s
        --max-cap           entry 上限 = v4_per_mac, v6_per_mac, v4_global, v6_global;預設 16,64,256,1024
        --offload-workaround       ND/ARP offload 繞道,逗號子集 v4,v6,v6ll(僅 fwd mode 生效;見 §ND/ARP offload 繞道)
        --offload-workaround-magic 上述繞道在 up0 上代理位址的 IFA_RT_PRIORITY 魔術標記;預設 4243672773(接受十進位或 0x 十六進位)
        --arp-keepalive     週期性 v4 ARP keepalive 秒數;`0`=關(預設)。對 up0 每個 v4 鄰居替每個已學 guest v4 發單播 ARP reply
                            (+ 週期 GARP),讓上游鄰居快取常駐 REACHABLE、永不需要對 guest 發 ARP request——繞過 Wi-Fi 韌體
                            「v4 ARP offload 只有單一 slot、powersave 下丟其他 ARP request」的限制(見 §ARP keepalive)。Android Wi-Fi 建議 10
        --vmroute-table     per-guest vmroute 寫入的 table(配下面 iif lo rule;用**專用** table,別用 local/main);`-1`=不寫 vmroute、數字=該 table、名稱=查 rt_tables(查不到 error);預設 `200`
        --vmroute-rule      `iif lo lookup <vmroute-table>` 規則的 priority(只有本機發起的流量查這張表);`-1`=不下規則(指到本就被查的 table 如 local 時)、數字=該 prio;預設 `11000`

### 術語

    up0       上游真口,其對外 mac = HOSTMAC。rust 以 netlink 動態監測:消失 → 撤回所有 kernel 變更(回未初始化),出現 → 重新 init
    fwd0/fwd1 fwd mode 用的 veth pair(pbridge 建並 up,但**不碰 bridge**);fwd1 由操作者 enslave 進 bridge(面向 guest)、fwd0 pbridge 獨佔
              兩端都設成**純 L2 transport**:`addr_gen_mode=1`(不自生 LL)+ `accept_ra=0`,且不綁任何位址——只讓封包通過,不跑自己的 ND/RS
    br        **唯一 pin 的是 up0**;br 不固定指定,而是動態追蹤(direct=`up0.master`、fwd=`fwd1.master`)。操作者可隨時 attach/換/detach,rust netlink 監測即時跟上
    entry     ip → { mac, createat }:「某 guest ip 屬於哪個 guest mac」。createat 供 caps FIFO 驅逐;衝突由 syncer 同步時自動跳過
    HOSTMAC   出向所有 guest 封包的 src mac。 = (direct && up0 有 master)? master(bridge) mac : up0 mac。rust netlink 動態監測(隨 MAC randomization / roaming 變)
    host_ips  host 自有 IP = up0.IPs ∪ (有 master 時) master.IPs。用途:in 方向「提早 accept」放行 host 自己的封包(hostip 最優先,vm 用相同 IP 會被無視)。rust netlink 動態監測
              ⚠ 啟用 `--offload-workaround` 時,**排除** up0 上帶 magic metric 的 proxy 位址(那是裝給 APF 看的 guest 位址,非 host 真位址;見 §ND/ARP offload 繞道)
    copy      kernel→userspace 把要 learn 的封包複製上來的機制:ebpf `bpf_ringbuf` / nft `NFLOG`(見 §userspace path)

---

## 限制

### 環境 → 兩個 backend

    android (stock GKI)  : 無 nftables、有 ebpf(KernelSU 放行 sepolicy)      → ebpf mode
    linux container      : 有 nftables、無 ebpf 權限(bpf() syscall 被擋)      → nft mode

兩 backend 共用同一套 userspace 控制層(learn / caps / 老化 / syncer);差別只在 kernel 怎麼改包與複製。nft path 完全不用 ebpf,ebpf path 完全不用 nftables。
**版本下限**:nft 的 netdev **egress** hook 需 kernel ≥ 5.16(direct mode 的 OUT 鏈、fwd 的 egress_guard 用到;fwd 的 OUT/IN 全掛 ingress,無此需求)。

### kernel 能力(決定什麼 in-kernel、什麼留 userspace)

改 mac 不動 IP/L4 csum;改 payload 才要管 csum。各協定:

    ARP : 無 csum                          → nft / ebpf 都能 set(`arp saddr/daddr ether set`)
    DHCP: UDP csum 可歸零(IPv4 optional)  → nft `udp checksum set 0` / ebpf 歸零,兩者都能
    ND  : ICMPv6 csum 必填、不可歸零        → nft set lla 後不重算(壞);只有 ebpf `l4_csum_replace` 或 userspace 能修

設計取捨:

    modify  : kernel 能 set 的都 in-kernel set(連 ND lla 都 raw-set)。要 learn 的封包先複製(snapshot)再改,複製保住原始 guest mac
    learn   : 一律 userspace —— dict + 事前 caps + 衝突。kernel 自學沒有 per-mac 事前上限、anti-flood 弱,不採
    ND csum : ebpf in-kernel 增量更新(update_csum);nft 改不了 → 該包 drop,由 userspace 重算 csum 後補發

### 傳輸:複製用 NFLOG / ringbuf,不用 nfqueue

    netdev hook 無 queue verdict(EOPNOTSUPP);out 封包 dstmac=gateway≠HOSTMAC(PACKET_OTHERHOST)進不了 ip prerouting;
    ARP 走 arp_rcv 也不進;nfqueue 是 L3-mangle+reinject 模型,與「改 L2 後送指定 port」的 demux 不合。
    ⇒ 複製用 nft `NFLOG`(netlink)/ ebpf `bpf_ringbuf`(map),封包本身仍 in-kernel 轉發(複製不擋路)。

實作補述(NFLOG 細節,實測):
    - subsys = `NFNL_SUBSYS_ULOG`(= **4**),非 ipset 的 6;`NFULNL_MSG_CONFIG` bind group + `NFULNL_COPY_PACKET`。
    - **ingress hook**(fwd OUT、所有 IN):`NFULA_HWHEADER` 帶完整 L2(src mac 在 byte 6..12、ethertype 在 12..14)、`NFULA_PAYLOAD` = L3;src mac 亦可從 `NFULA_HWADDR` 取。
    - **egress hook**(direct OUT):**無** `NFULA_HWADDR`/`NFULA_HWHEADER`,`NFULA_PAYLOAD` = **整個 L2 frame**(dst|src|ethertype|L3)。
      ⇒ userspace 讀 copy 要分兩路:有 HWHEADER → 取 L3+HWHEADER;無 → payload 即 frame,自 payload[6..12] 取 guest mac、payload[14..] 取 L3。
    - **reinject vs learn-only 用 `log prefix` 分流**:ND-drop 路徑寫 `prefix "R"`(userspace fix_csum + AF_PACKET 補發 + learn),ARP / 未學 IP / DAD-NS 等轉發路徑寫 `prefix "L"`(只 learn)。否則 userspace 無法區分「被 drop 要補發的 ND」與「已 in-kernel 轉發、只需 learn 的包」。

### 轉發效能 / 為何不用 AF_XDP

    tc fwd(bpf_redirect)  : skb-level redirect,搬 skb 不複製 payload(zero-copy);改 mac 只寫 6 bytes header
    tc dup(clone_redirect): payload 共享、clone skb head(一份給 guest、一份進 host stack)
    AF_XDP                : 用不到 —— 它是「零拷貝送 userspace」,而 offload 是 kernel→kernel 不進 userspace;
                            slow path 雖進 userspace,但只低頻控制封包,吞吐用不上
    XDP-層 redirect       : 唯一更快的路(pre-skb、免 skb alloc),但需來源 dev 有 native XDP;
                            up0=wlan0(mac80211)多半沒有 → 主場景不適用。tc redirect 是務實上限

---

## kernel path

兩拓樸、各 **2 個 hook**:

    fwd mode(up0 = IFF_DONT_BRIDGE,如 wlan0 STA,不能進 bridge):
        pbridge 建 veth fwd0╌fwd1(建好先設 `addr_gen_mode=1`+`accept_ra=0` 再 up → 純 L2 transport、不自生位址);**操作者** enslave fwd1 進 bridge(與 guest 同 L2 段)、fwd0 pbridge 獨佔
        ▸ fwd0 ingress = OUT(guest→up0):改寫 → 複製(learn)→ set(eth.src,HOSTMAC) → fwd(up0)
        ▸ up0  ingress = IN (wire→guest):demux(set eth.dst)→ fwd(fwd0) / dup(fwd0) / accept
        # fwd1 是純 bridge port、不掛 hook

    direct mode(一般有線口,但交換機限制 src-mac;up0 自己進 bridge):
        ▸ up0 egress  = OUT(guest→up0):改寫 → 複製(learn)→ set(eth.src,HOSTMAC) → accept(交 kernel bridge 送)
        ▸ up0 ingress = IN (wire→guest):demux(set eth.dst)→ accept(轉發/flood 交 kernel bridge)
        # 轉發/flood 全交 kernel bridge(不 fwd、不 dup)

兩拓樸只差「轉發誰做」:fwd mode pbridge 在 up0↔fwd0 間自己搬(fwd/dup);direct mode 交 kernel bridge。

### 規則表讀法

每表「由上到下、首個命中者執行」,3 欄:**condition**(人類可讀 pseudo,只用 nft/ebpf 皆可實現的 match:ethertype / ip / port / icmpv6 type / `@th` 偏移 / set 成員)、**ebpf action**、**nft action**。表只列 kernel 做的事(learn 全在 userspace)。

ebpf 速記:`store(off,v)`=`bpf_skb_store_bytes`、`redirect(d)`=`bpf_redirect(d,0)`、`clone(d)`=`bpf_clone_redirect`、`ringbuf(t)`=`bpf_ringbuf_output`、`update_csum()`=`bpf_csum_diff`+`bpf_l4_csum_replace`、`lookup/update(map,…)`、`return OK/SHOT/REDIR`。

動作約定:

- **`copy`**(表內寫 `ringbuf(...)` / `log group <g>`)= kernel 把封包複製到 userspace 供 learn。ebpf 送 `{ip, guest-mac}` tuple;nft `NFLOG` 送整包(ND 補發要用)。複製是 **snapshot**(複製後再改封包不影響已複製內容),故同一條規則可「**先複製、再 `set(eth.src)`**」——userspace 拿到的是改前的原始 guest mac(取自 `eth.src`:ebpf 直讀;nft **ingress** 從 `NFULA_HWADDR`/`NFULA_HWHEADER` 讀,**egress**(direct OUT)NFLOG 無這兩個 attr,改從 payload 內嵌的 L2 frame `src@6..12` 讀——見 §傳輸 實作補述)。複製是 **lossy**:掉了只少學一次,下個封包再學。`<g>` = `--nflog-group`;ebpf ringbuf 是 map fd(無全域 id)。
- **`set(eth.src,HOSTMAC)`** = srcmac 正規化,在 OUT hook 內、**複製之後**做(各 backend 用自己的原語:nft `ether saddr set HOSTMAC` / ebpf `store`)。
- **`update_csum()`** = in-kernel 增量更新 ICMPv6 csum(delta、非重算、csum-offload 安全),**只 ebpf**;nft 無此能力 → ND 改走 `drop`,userspace 補。
- **`mark(ip)`**(表內 `update(seen)` / `update @seen`)= 標記 liveness,**僅 out**(guest 主動送才算活)。valid / ARP / ND 規則**都要 mark**:userspace `learn()` 對已知 (ip,mac) 是 no-op 不刷 seen,若只有 valid mark,只發 ARP/ND 的安靜 guest 會被週期性誤老化再重學(中間 inbound 短暫黑洞)。
- 大方向:**ebpf** 全 in-kernel(含 csum + srcmac),userspace 純讀;**nft** 除 ICMPv6 csum 外全 in-kernel,ND 需 userspace fix_csum + 補發。

### fwd mode

**OUT — fwd0 ingress**(guest→up0)。狀態 `HOSTMAC / BRMAC / host4,6 / ip2mac4,6 / valid4,6 / seen4,6` 由 syncer 寫(ebpf=map、nft=set/map)。

| condition(pseudo) | ebpf action | nft action |
|---|---|---|
| `eth.src == HOSTMAC` | `return SHOT` | `drop` |
| `eth.src == BRMAC`(host 經 br 的 flood 副本) | `return SHOT` | `drop` |
| `udp.sport=68 & dport=67`(DHCPv4) | `store(@bootp.flags,0x8000)`<br>`store(@udp.csum,0)`<br>`store(@eth.src,HOSTMAC)`<br>`redirect(up0)` | `@th,144,16 set 0x8000`<br>`udp checksum set 0`<br>`ether saddr set HOSTMAC`<br>`fwd to "up0"` |
| `icmpv6 type ∈ {133,135,136}`(ND dispatch,**必在 valid 前**) | `goto nd-out`(同 prog 內 if 分支) | `jump nd-out` |
| `(ip.src,eth.src) ∈ valid` | `update(seen,ip.src)`<br>`store(@eth.src,HOSTMAC)`<br>`redirect(up0)` | `update @seen {ip saddr}`<br>`ether saddr set HOSTMAC`<br>`fwd to "up0"` |
| `arp` | `store(@arp.sha,HOSTMAC)`<br>`ringbuf({arp.spa,eth.src})`<br>`update(seen,arp.spa)`<br>`store(@eth.src,HOSTMAC)`<br>`redirect(up0)` | `arp saddr ether set HOSTMAC`<br>`update @seen4 {arp saddr ip}`<br>`log group <g>`<br>`ether saddr set HOSTMAC`<br>`fwd to "up0"` |
| else(未學 IP / DAD NS / RS-from-::) | `ringbuf({ip.src,eth.src})`<br>`store(@eth.src,HOSTMAC)`<br>`redirect(up0)` | `log group <g>`<br>`ether saddr set HOSTMAC`<br>`fwd to "up0"` |

**nd-out 子表**(NS/NA/RS;guard 不命中 → fall through 回主表,自 valid 繼續走,nft `jump` 天然如此):

| condition(pseudo) | ebpf action | nft action |
|---|---|---|
| `NS`:t135 & `ip6.src≠::` & `@th,192,8==1` & `@th,208,48≠HOSTMAC` | `store(@th208,HOSTMAC)`<br>`update_csum()`<br>`ringbuf({ip6.src,eth.src})`<br>`update(seen,ip6.src)`<br>`store(@eth.src,HOSTMAC)`<br>`redirect(up0)` | `@th,208,48 set HOSTMAC`<br>`update @seen6 {ip6 saddr}`<br>`log group <g>`<br>`drop` |
| `NA`:t136 & `@th,192,8==2` & `@th,208,48≠HOSTMAC` | `store(@th208,HOSTMAC)`<br>`update_csum()`<br>`ringbuf({nd.target,eth.src})`<br>`update(seen,ip6.src)`<br>`store(@eth.src,HOSTMAC)`<br>`redirect(up0)` | `@th,208,48 set HOSTMAC`<br>`update @seen6 {ip6 saddr}`<br>`log group <g>`<br>`drop` |
| `RS`:t133 & `ip6.src≠::` & `@th,64,8==1` & `@th,80,48≠HOSTMAC` | `store(@th80,HOSTMAC)`<br>`update_csum()`<br>`ringbuf({ip6.src,eth.src})`<br>`update(seen,ip6.src)`<br>`store(@eth.src,HOSTMAC)`<br>`redirect(up0)` | `@th,80,48 set HOSTMAC`<br>`update @seen6 {ip6 saddr}`<br>`log group <g>`<br>`drop` |

> **ND 必須在 valid 之前**:已學 guest 的 NUD NS / 回應 NA(`ip6.src ∈ valid`)若先命中 valid,S/TLLAO 不會被改寫 → router 依 RFC 4861 從 LLAO 更新 neighbor cache 成 guest 真 mac → inbound 改送 guest mac、被上游濾掉,**v6 學表後即斷且不自癒**。dispatch 寫法下 unicast fast path 只多一次 l4proto 比較(ebpf 即 if 分支,零成本)。
> **BRMAC** = fwd1.master(br)的 mac(syncer 同步;br_present 才裝此規則;br.mac==HOSTMAC 時首條已涵蓋):bridge 會把 host 經 br 的 broadcast / 未知 unicast flood 複製進 fwd1 → fwd0,不擋的話 br 的 LL ND 會被 learn 成 guest entry(br 的 LL 不在 host_ips、br.mac≠HOSTMAC,reconcile 的 skip 擋不住)、host 流量副本也會漏到 up0。drop 無副作用:給 guest 的真正投遞由 bridge 走 tap port,fwd0 收到的只是 flood 副本。
> nft 規則 = 把 condition 譯成 match,再接 nft action(例 NS:`icmpv6 type 135 ip6 saddr != :: @th,192,8 1 @th,208,48 != HOSTMAC` + action)。**nft ND** 改不了 ICMPv6 csum,故 `log group <g>` + `drop`:userspace 重算 csum + learn + AF_PACKET 補發 up0。NA 的 seen 標 `ip6.src`(通常 == target;raw `@th` 不能當 nft set update key,多標無害——rust 只看 alive 與 entries 的交集)。

**IN — up0 ingress**(wire→guest)。in 不 mark;demux 只改 mac、無 learn/csum。

| condition(pseudo) | ebpf action | nft action |
|---|---|---|
| `eth.dst==HOSTMAC & ip.dst ∈ host` | `return OK` | `accept` |
| `arp.tpa ∈ host` | `return OK` | `accept` |
| `pkttype ∈ {bcast,mcast}` | `clone(fwd0)`<br>`return OK` | `dup to "fwd0"` |
| `eth.dst==HOSTMAC & ip.dst ∈ ip2mac`(IP/NA/uRA) | `store(@eth.dst, ip2mac[ip.dst])`<br>`redirect(fwd0)` | `ether daddr set ip daddr map @ip2mac`<br>`fwd to "fwd0"` |
| `eth.dst==HOSTMAC & arp.tpa ∈ ip2mac` | `store(@arp.tha,m)`<br>`store(@eth.dst,m)`<br>`redirect(fwd0)` | `arp daddr ether set arp daddr ip map @ip2mac4`<br>`ether daddr set arp daddr ip map @ip2mac4`<br>`fwd to "fwd0"` |
| else(`eth.dst==HOSTMAC`,非 host/ip2mac) | `return OK` | `accept` |

> 前兩列把 host 自有 IP 最先放行(hostip 最優先;vm 用相同 IP 會被無視)。末列把未知 `dst==HOSTMAC` 交給 host stack(見 §host 共存 ⚠)。

### direct mode

**OUT — up0 egress**(guest→up0;改完 accept 交 kernel bridge 送)。複製走 egress:ebpf = tc-egress `ringbuf`;nft = egress `NFLOG`(netdev egress hook 需 kernel ≥ 5.16,見 §環境)。

| condition(pseudo) | ebpf action(tc egress) | nft action(egress chain) |
|---|---|---|
| `eth.src==HOSTMAC`(host / 補發回包) | `ingress_ifindex==0`<br>`? return OK : return SHOT`(⚠ 見下) | `accept`(⚠ 信任假設,見下) |
| `udp.sport=68 & dport=67 & src≠HOSTMAC`(DHCP) | `store(@bootp.flags,0x8000)`<br>`store(@udp.csum,0)`<br>`store(@eth.src,HOSTMAC)`<br>`return OK` | `@th,144,16 set 0x8000`<br>`udp checksum set 0`<br>`ether saddr set HOSTMAC`<br>`accept` |
| `icmpv6 type ∈ {133,135,136}`(ND dispatch,**必在 valid 前**) | `goto nd-out` | `jump nd-out` |
| `(ip.src,eth.src) ∈ valid` | `update(seen,ip.src)`<br>`store(@eth.src,HOSTMAC)`<br>`return OK` | `update @seen {ip saddr}`<br>`ether saddr set HOSTMAC`<br>`accept` |
| `arp` | `store(@arp.sha,HOSTMAC)`<br>`ringbuf({arp.spa,eth.src})`<br>`update(seen,arp.spa)`<br>`store(@eth.src,HOSTMAC)`<br>`return OK` | `arp saddr ether set HOSTMAC`<br>`update @seen4 {arp saddr ip}`<br>`log group <g>`<br>`ether saddr set HOSTMAC`<br>`accept` |
| else(未學 IP / DAD NS / RS-from-::) | `ringbuf({ip.src,eth.src})`<br>`store(@eth.src,HOSTMAC)`<br>`return OK` | `log group <g>`<br>`ether saddr set HOSTMAC`<br>`accept` |

> **nd-out 子表同 fwd-out**(condition / guard / 改寫 / mark / 複製全同),僅終結動作換:ebpf `redirect(up0)` → `return OK`;nft 的 NS/NA/RS 仍 `log group <g>` + `drop`(userspace 補發)。
> ⚠ **src==HOSTMAC 放行的信任假設**:nft egress 分不出封包從哪個 bridge port 進來 → guest 偽造 HOSTMAC 即可冒充 host 出站(已知限制,須文件化)。ebpf 用 `skb->ingress_ifindex` 收緊:0 = host 本地產生 / AF_PACKET 補發 → 放行;非 0 = 從 guest port 橋接而來 → drop。fwd mode 無此問題(首條直接 drop)。

**IN — up0 ingress**(wire→guest;改完 accept,轉發/flood 交 kernel bridge)。in 不 mark。

| condition(pseudo) | ebpf action | nft action |
|---|---|---|
| `eth.dst==HOSTMAC & ip.dst ∈ host` | `return OK` | `accept` |
| `arp.tpa ∈ host` | `return OK` | `accept` |
| `eth.dst==HOSTMAC & ip.dst ∈ ip2mac`(IP/NA/uRA) | `store(@eth.dst, ip2mac[ip.dst])`<br>`return OK` | `ether daddr set ip daddr map @ip2mac`<br>`accept` |
| `eth.dst==HOSTMAC & arp.tpa ∈ ip2mac` | `store(@arp.tha,m)`<br>`store(@eth.dst,m)`<br>`return OK` | `arp daddr ether set arp daddr ip map @ip2mac4`<br>`ether daddr set arp daddr ip map @ip2mac4`<br>`accept` |
| else(`eth.dst==HOSTMAC` 非 host/ip2mac;multicast;PACKET_OTHERHOST) | `return OK` | `accept`(交 host stack / bridge flood) |

> direct demux 改 `eth.dst` 後 `accept` → kernel bridge 查 FDB 送對 port;multicast 不 dup(bridge 自己 flood)。

### 為什麼 out 的 ARP / ND / 未學 IP 走 userspace

- `learn` 要**原始 guest mac**(留在 `eth.src`):OUT 規則複製之後才把 `eth.src` 改成 HOSTMAC;複製是 snapshot,原始 mac 保得住。learn 還要**事前** caps / 衝突管理,kernel 自學辦不到 → 放 userspace。
- **ebpf**:modify + `update_csum` + srcmac 全 in-kernel,`ringbuf` 只送 learn tuple → userspace 純讀。
- **nft**:能改的 in-kernel 改 + `NFLOG` 複製 learn;唯 ICMPv6 csum 改不了 → ND 走 `NFLOG` + `drop`,userspace 修正(fix_csum)+ 學習(learn)+ 補發(AF_PACKET 注入 up0)。ARP / 未學 IP 無 csum 問題 → 直接 fwd + NFLOG learn。
- ⇒ 走 userspace 的只有 **out 的 ARP / ND / 未學 IP**(為 learn);其餘(已學 demux、in demux、DHCP、multicast、host 放行)全 in-kernel。

### ND 改寫規則(NS / NA / RS)

- guest 自己的 mac 在 **NS/RS 的 SLLAO**、**NA 的 TLLAO**。NS 與 NA 的 LLA mac 同在 `@th,208`(out 用兩條 type-gated rule、共用同 offset);RS 的 SLLAO 在 `@th,80`、RA 在 `@th,144`(各型不同)。
- **NS/NA/RS 必須排在 valid 之前**(主表一條 `icmpv6 type ∈ {133,135,136}` dispatch → nd-out 子表):已學 guest 的 NUD NS / NA 其 `ip6.src ∈ valid`,若 valid 先命中會跳過 LLAO 改寫 → router cache 被原始 guest mac 污染 → inbound 斷且不自癒(詳見 fwd-out 表注)。
- 改 LLA → HOSTMAC + `update_csum()`(ebpf;nft 留 userspace)。guard:NS/RS 加 `ip6.src≠::` 擋 DAD(DAD 無 SLLAO;連「DAD 帶非-LLA option 如 SEND nonce」也擋,否則 `@th,208` 會誤改別的 option);`@th,off≠HOSTMAC` 兼當長度/冪等 guard(OOB payload 讀=不命中,自動跳過太短封包)。**option-type guard 必加,非可選**(NS `@th,192,8==1`、NA `@th,192,8==2`、RS `@th,64,8==1`):ND option 順序無規範,第一個 option 非 LLAO(SEND CGA、nonce …)時沒 guard 會把別的 option 內容改成 HOSTMAC(封包損毀);有 guard 則該包落回主表 else——只轉發 + learn、不損毀(代價:該包 LLA 留 guest mac、該流 demux 可能失敗,lossy 可接受)。
- **DAD NS / 其他 ND** 落 else:照常轉發 + 複製只 learn(DAD 從 target 學;無 LLA 改寫、無 csum 問題)。
- **RS 要轉發**(理由見「RA 回程」):改 SLLAO@th,80 → HOSTMAC + learn(guest-ll → eth.src),讓 router 把 guest-ll cache 成 HOSTMAC、unicast RA 回得到 HOSTMAC,且因學了 guest-ll 而能 in demux 回 guest。RS-from-:: 無 SLLAO → 落 else 只轉發,router 只能 multicast RA。
- **RA 回程**:unsolicited/週期 RA = multicast `ff02::1`(in `pkttype mcast → dup` 收);solicited RA 由 router 決定 unicast(到 RS 的 SLLAO)或 multicast。
- **IN 的 RA 不改 payload**:RA 的 SLLAO 是 router 真實 mac(guest 連 gateway 要),比照 inbound NS/NA 不動 remote LLA。unicast RA(`dst=guest-ll`、`L2=HOSTMAC`)走 in demux 列(只改 eth.dst、無 csum;靠 learn 來的 `ip2mac6[guest-ll]`);multicast RA 走 dup → 不需新增 IN 規則。
- guest 發 RA / Redirect 是 router-only 行為,正常不會;若發則落 else 只 learn。

### host 共存(⚠)

- `fwd`/`dup`/`redirect` 把封包搬走/複製(不進 host stack)。host 自己要收的(`dst∈host_ips` / `arp.tpa∈host_ips`)必先 `accept`/`return OK`,**絕不能 fwd/redirect 走或被當 guest demux**,否則 host 斷網。
- **IN 對 `dst==HOSTMAC` 但未知(非 host_ips、非 ip2mac)一律 `accept` 交 host stack,不 `drop`**:涵蓋 host 自己未列入 `host_ips` 的 IP(如 **ipvlan**:多 IP 共用 HOSTMAC、難全枚舉)。真未知 IP host stack 自會丟;未學的 guest IP 也上 host stack(host 無此 IP→丟,反正 guest 學到前本來就收不到)。
- **`accept` 不繞過 host 防火牆**:它是 `NF_ACCEPT`,只結束本 netdev base chain,封包照常往後續 hook(`prerouting → input`)跑 → host 的 `inet`/`ip filter` 照常生效。真正帶離 host stack 的只有 `fwd`(`NF_STOLEN`)與 `drop`(`NF_DROP`);`dup` 是複製(原包續跑)。
- **fwd 的 host flood 副本**:host 經 br 的 broadcast / 未知 unicast 會被 bridge 複製進 fwd1 → fwd0 OUT,靠主表第 2 條 `src==BRMAC drop` 擋掉;否則 br 的 LL 會被 learn 成 guest entry、host 流量副本漏到 up0(詳見 fwd-out 表注)。
- **direct 的 HOSTMAC 偽造**:OUT 首條對 `src==HOSTMAC` 放行,nft 分不出來源 port → guest 偽造 HOSTMAC 可冒充 host(已知信任假設);ebpf 以 `ingress_ifindex==0` 限縮成只放 host 本地產生。fwd 無此問題(首條 drop)。

### backend 原語對應

- **nft**:netdev chain;`set` / `update @seen` / `fwd to` / `dup to`(需 `NFT_DUP_NETDEV`)/ `… set … map @ip2mac`(demux);複製 `log group <g>`。
- **ebpf**:tc prog,attach 用 **TCX**(kernel ≥ 6.6;aya 在 ≥6.6 預設走 TCX 而非 legacy clsact filter,GKI 6.6 有 `CONFIG_NET_XGRESS`);`bpf_skb_store_bytes`(set)/ `bpf_redirect(,0)` / `bpf_clone_redirect`(dup);`update_csum()`=`bpf_csum_diff`+`bpf_l4_csum_replace`(helper id 11);demux `bpf_map_lookup`;複製 `bpf_ringbuf_output`。封包用 `bpf_skb_load/store_bytes`(offset-based,免 data/data_end 邊界證明)。BPF 物件 **架構無關**,x64 與 aarch64 共用同一 `.o`(build.rs 用 clang 編,`include_bytes!` 嵌入時需 8-byte 對齊 wrapper,否則 aya ELF parse 失敗)。
- **srcmac 正規化**:OUT hook 內、複製之後 inline `set(eth.src,HOSTMAC)`(各 backend 自己改);`drop` 的(nft-ND)由 userspace 補發時設。
- **kernel 狀態**(syncer 寫,非 learn):`HOSTMAC`、`BRMAC`(僅 fwd,flood 副本 drop)、`host4/6`(放行)、`ip2mac`/`valid`(demux / 已學比對)、`seen`(liveness)。
  - **`valid` 只 nft 需要,且就是 `ip2mac` 的同源資料**:OUT「`(ip.src,eth.src) ∈ valid`」要比對「映射到的 mac == eth.src」。nft 表達式**無法 reg↔reg 比較**,故用 concat set `valid4/6 {ip . mac}` 做成員測試(實作:`payload ip.src→reg1`、`eth.src→reg9(v4,4B 後)/reg2(v6,16B 填滿 NFT_REG_1 後)`、`lookup @valid`;key_type=`(ipv4=7|ipv6=8)<<6 | ether=9`)。**ebpf 無 valid map**:直接 `m = ip2mac[ip.src]; if (m && m==eth.src)`(C 可比暫存器),省一份 map。⇒ `valid` 是 nft-only 構件,語意上等同 ebpf 的「ip2mac 命中且 mac 相符」。
- **egress_guard(no-leak 兜底,defense-in-depth)**:up0 egress 一條 `ether saddr != HOSTMAC → counter + set HOSTMAC`(非終結正規化;沿用老 ruleset `pbridge-fwd.nft` 的語意)。所有正常路徑都已 inline 正規化 src,此 guard 只攔實作 bug:正常流量不命中,counter > 0 = 有路徑漏了正規化但被接住(供案例 13/14 驗證)。
  - **nft**:獨立 egress base chain,priority 排在 OUT 之後;`accept` 是 `NF_ACCEPT`,只終結**本** base chain,guard chain 仍會跑 → 兩 mode 都掛(nft 需 kernel ≥ 5.16)。
  - **ebpf(實作修訂)**:TCX 下 `TC_ACT_OK == TCX_PASS` **會終結整條 program chain**(不是只結束本 prog),故 OUT 之後接不到 guard。⇒ ebpf 的 egress_guard **只在 fwd mode 掛**(up0 egress 上單獨一支,攔 `redirect(up0)` 過來的副本);**direct mode 不另掛**——`direct_out` 本身就在 up0 egress,且**每條終結路徑都 inline `store(eth.src,HOSTMAC)`**,等同把 guard 做進去了(case 14「學表故障也不洩漏」對 ebpf 天然成立:inline set 與 ringbuf learn 解耦,learn 掛了 src 照樣正規化)。
  - userspace 補發包 src==HOSTMAC 不命中 → 不迴圈。

- **silent-VM discovery dup(僅 fwd,掛在 up0 egress = ebpf egress_guard / nft guard chain,排在正規化之後)**:解決「VM 靜默配 IP(static、沒 DHCP/DAD/gratuitous)→ 沒 entry、沒 /32·/128 vmroute → host 連 VM 時在 up0 的連線 prefix 上解析 → ARP/NS 送去 gateway 而非 VM → 連不上」。
  - 觀察:datapath OUT 本來就會 learn VM 的 ARP-reply(`spa`)/ NA(target)/ NS。所以只要**讓 host 的查詢觸達 VM**,VM 一回應就被學到、vmroute 就建起來。
  - 演算法(up0 egress,正規化 src 之後):

        if (ARP request 或 NS) and srcip ∉ ip2mac(host 發起,非已學 guest):
            clone_redirect(skb, fwd0)            # **clone 不 redirect**:原包仍出 up0 → gateway 照樣解析得到
        # NS 額外 guard:src ≠ ::(不 clone DAD);srcip ∉ ip2mac 用 ebpf map lookup / nft lookup_inv 反向成員測試

  - 流程:host ARP/NS G(出 up0)→ clone 到 fwd0→fwd1→vmbr→VM → VM 回 ARP-reply/NA(進 fwd0 ingress = OUT)→ **learn G→vmmac**、建 vmroute G/128→br → host **重試**(ping/TCP re-tx)時 /32·/128 比 up0 的連線 prefix 更specific → 改在 br 上解析 → 連上。原查詢那次因回應沒進 host stack 會逾時,靠重試成立(延遲約一個 retry)。
  - 只 clone **host 發起**(srcip 非 guest)的用意是**去重,不是防迴圈**:迴圈本來就不會發生(bridge hairpin off,注入 fwd0 egress→fwd1 ingress 不會再被 flood 回 fwd1)。但若不檢查,guest 自己廣播的 ARP/NS(被 redirect 到 up0)會被 clone 回 vmbr → 其他 VM 收到兩份(VM 多時廣播翻倍)。故 srcip 已在 ip2mac → 不 clone。
  - 成本可忽略:`lookup`(ebpf map / nft `lookup_inv` 反向成員測試)**只在 ARP-request / NS 上做**(被 ethertype / icmp-type 前置條件擋著),資料快路徑(TCP/UDP、甚至 ICMPv6 echo/NA)完全不碰。host 與 guest-forwarded 出向 src mac 都已是 HOSTMAC,唯一能分辨的就是 src IP,故這個 lookup 無可省。
  - direct mode 不需要(VM 與 host 同在 br0,host 直接在 br0 上解析)。

### 老化規則(liveness / aging)

out 命中時 `mark(ip)` 標記存活(僅 out)。兩 backend 對 rust 暴露同一介面 `flush()`,rust 每 `--timeout` 秒呼叫一次,回傳當下 kernel 仍存活的 ip 集合:

    nft : mark = `update @seen { ip }`(`@seen` 是 dynamic set 帶 `timeout=--timeout`,每次刷新)
          flush() = 讀 `@seen`(kernel 已自動踢掉 idle>timeout)→ 回傳剩下的
          # 粒度 ≈ timeout(per-entry、kernel 自動)

    ebpf: mark = `seen[ip] = 1`(map 無時間老化 → second-chance / clock)
          flush() = 逐 entry:`seen==1 → seen=0`(存活、再給一輪)、`seen==0 → 刪`(idle 滿一輪)→ 回傳這輪存活的
          # 粒度 ∈ [timeout, 2×timeout)(每次呼叫推進一格)

rust 端不分 backend、統一處理:

    每 --timeout 秒:
        alive = backend.flush()
        for ip in entries:
            if ip ∉ alive:
                entries.remove(ip); syncer.notify(ip)   # entries=真相;reconcile 見 entry 沒了 → 撤 kernel

新 entry 的 grace:learn 封包在 kernel 不 mark seen(那時還沒 entry),故 syncer 寫 entry 時**一併初始化 seen=alive**(nft `add @seen {ip}` / ebpf `seen[ip]=1`),給滿一輪 timeout,免首次 flush 前未被 out-hit 就誤刪。

**offload 模式的 keepalive(probe / flush 交替)**:offload 下 entry 被踢 → up0 proxy 被移除 → 上游(APF)再也解析不到該 guest,且**無重探路徑**(APF 直接答/丟 gw 的 NS,不會 flood 到 bridge;不像 plain fwd 靠 flood / discovery dup 自癒)。但靜默-但-仍持有-IP 的 guest 不該被踢。故 offload 啟用時 aging 改成:

    timer 週期 = timeout/2,交替 probe / flush(probe 一拍、flush 下一拍,相差 timeout/2):
      probe 拍:對每個 proxied guest 由 **fwd0 注入**(userspace AF_PACKET,**非 ebpf**——nft 路線同樣可用)一個
                ARP-request(v4)/ NS(v6),sender = 同 family 的 host IP,送進 vmbr。
      flush 拍:同上「每 timeout 秒」的老化(此時距上次 probe 才 timeout/2)。

    - guest 仍持有 IP → 回 ARP-reply/NA → 進 fwd0 ingress(OUT path)→ `mark(seen)`(nft `update @seen` / ebpf `seen=1`,
      和一般 guest 流量同路徑;**已確認 ARP-reply 用 spa、NA 用 target/saddr 都會 mark**)→ flush 時仍存活 → **不被踢**(proxy 續命)。
      副效:該 reply 經 OUT MAC-NAT 成 `G@HOSTMAC` 轉去上游 → 順帶刷新 gateway 的鄰居快取(直接緩解 v4 flap)。
    - guest 釋放了 IP → 不回應 probe → seen 自然過期 → ~timeout 後 flush 踢掉、proxy 移除。
    - 只 probe **proxied**(`nd_proxied`)entry;plain fwd / direct 不開 probe(維持每 timeout 一次 flush,無多餘 ARP/NS)。

---

## userspace path

userspace 是控制層(rust),**不在資料路徑上**(除 nft-ND 補發)。**packet processor** 每收到一筆 copy 跑下面流程,更新 entries 並 `notify(ip)` 給 syncer。`engine` / `HOSTMAC` / `up0` 為行程狀態,`max_cap` 來自 `--max-cap`。

```
# packet processor —— 每筆從 copy(ebpf ringbuf / nft NFLOG)收到的封包
on_copy(pkt):
    type = classify(pkt)                         # arp | nd(NS/NA/RS/DAD) | ip | ipv6

    # 1. 改包(只 nft-ND 需要;ebpf 全在 kernel 做完 → 純讀)
    if engine == nft and type == nd:
        fix_csum(pkt.icmp6)                      # nft 改不了 ICMPv6 csum;kernel 已 set LLA + drop 原包
        pkt.eth.src = HOSTMAC                     # 補發包自帶 HOSTMAC
        af_packet_send(up0, pkt)                 # 補發;不迴圈:補發包 src==HOSTMAC —— fwd up0 egress 只有 egress_guard(不命中)、direct up0-egress 首條 accept

    # 2. 抽要學的 (ip, mac);mac 一律 = 原始 eth.src
    (ip, mac) = switch type:
        arp           -> (arp.spa,   eth.src)    # spa==0(ARP probe)→ ip=None
        nd & src≠::   -> (ip6.src,   eth.src)    # NS/RS resolution
        nd & src==::  -> (nd.target, eth.src)    # DAD-NS;NA 也取 target
        ip | ipv6     -> (ip.src,    eth.src)
    if ip is None or not is_unicast(ip):         # 跳 multicast(ff00::/8、224/4)/unspecified;fe80 unicast 可學
        return

    # 3. entry 流程
    learn(ip, mac)

learn(ip, mac):
    e = entries.get(ip)
    if e:
        if e.mac == mac: return                  # 已知,no-op(liveness 由 kernel seen 管)
        e.mac = mac                              # op2 取代:ip 的 mac 變了(createat 不動)
        syncer.notify(ip); return
    # op1 新 entry —— 先過 caps(超則 FIFO 踢出)
    fam = family(ip)                             # v4 | v6
    if per_mac_count(fam, mac) >= max_cap.per_mac(fam):
        syncer.notify(evict_oldest(fam, mac))    # 踢「該 mac」最舊同型
    if global_count(fam)       >= max_cap.global(fam):
        syncer.notify(evict_oldest(fam, None))   # 踢「全域」最舊同型
    entries[ip] = { mac, createat: now() }
    syncer.notify(ip)

evict_oldest(fam, scope_mac) -> ip:              # FIFO:createat 最小者
    victim = min(entries by createat where family(ip)==fam and (scope_mac is None or e.mac==scope_mac))
    del entries[victim]; return victim
```

DHCP 不進 userspace(kernel 已 set flag + udp.csum 0);in demux / multicast 全 in-kernel。copy lossy(掉了下個封包再學;nft-ND 掉了該 ND 丟,guest 會重試)。`syncer.notify(ip)` 只是「這個 ip 動了去 reconcile」,寫不寫 kernel / 衝突跳過全由 syncer 判。

### host → VM 路由

    用途:只有「host 自己主動連 VM、且 host↔VM 不在同一 L2 段」才需要。外部↔VM 全是純 L2 / offload,不碰路由。

    ── direct mode:不需要寫任何路由 ──────────────────────────────────────
    up0 enslave 進 br、不綁 IP;IP/CIDR(+ kernel 自動的 connected route)綁在 br 上。
    VM 也在 br 內(tap enslave)、與 br 同子網 → VM 天生 on-link:
        host 連 vm-ip → 命中 br 的 connected route → dev br、src=br.IP、ARP/橋接直達 VM 真實 mac、回程對稱。
    => best practice = up0 無 IP、IP+prefixroute 放 br;host↔VM 零路由、零維護。
       (PoC tests/poc/poc-direct-no-route:沒加任何 route,host↔VM v4/v6 雙向通)
    例外:VM-IP 不在 br 子網(真跨網)才需 /32,但那已超出本機制。

    ── fwd mode ──────────────────────────────────────────────────────
    up0 保留 IP、不進 br;br 是另一段、guest 不在 host 任何 connected route 上。分兩種需求:

    (a) 不需要 host↔VM(只 VM↔外部):br 不綁 IP、不寫任何 route。最簡。

    (b) 需要 host↔VM:**br 必須鏡像 host 在該子網的「整組」IP(含 secondary,noprefixroute)** —— 否則 IPv6 雙向全斷、v4 也脆弱。
        核心原則:**「擁有權」是 per-IP、且必須在 br 段上**(guest 要連的每個 host IP 都得在 br 上有);
                  「路由 + src」才是 per-guest。兩者分開。
        為何 IP-less / 只鏡像一個不行:沒在 br 上的 host IP(如 secondary 50.11),VM 在 br 段解它時——
            v4 ARP:host 靠 `arp_ignore=0`(跨介面回)勉強能答,但 `arp_ignore ≥ 1` 即失效;
            v6 ND :無 arp_ignore 等價物,host **不會**跨介面答 NS → 該 IP 的 v6 **雙向全斷**
                    (回程恆需 VM 在 br 段解到 host 的 IP,故兩個方向都中)。
        做法:把 host 在該子網的**整組** IP(primary + 所有 secondary)鏡像到 br + noprefixroute
              (同 IP 綁兩介面合法,local 表每 dev 一筆):
            - noprefixroute = 只保留 local /32(host 擁有 → 回 ARP+ND、可當 src),**不建** connected route。
            - host 在 br 段原生擁有該 IP、用 br 的 mac 回 ARP+ND → **v4+v6 雙向皆通、arp_ignore 隨意、strict rp_filter**。
              各 dev 在自己那段用自己 mac 回應:VM 段解到 br mac、上游段解到 up0 mac(=HOSTMAC),不互相污染。
            - 回程對稱(VM 回 br.IP 就在 br)→ 不需放鬆 rp_filter。**不佔額外 LAN 位址**(直接鏡像 up0 的)。
            - 代價:syncer **單向**鏡像 up0 的整組 IP → br(noprefixroute, nodad;缺 add / 多 del),
              隨 up0 位址變動(漫遊 / DHCP 續約)同步。up0=唯一真相、br 不回饋(詳見 syncer 章)。
        br 的 IPv6 **link-local 不可少**(v6 ND 的前提,host 要在 br 段收送 NS/NA 全靠它),但**用鏡來的 up0 fe80、非 br 自生**:
            **實作(br mirror-only 定址)**:偵測到 br attach 時 → `addr_gen_mode=1`(不自生 LL)+ `accept_ra=0`,
              **並先把 br 自己的位址全清掉**(所有 non-noprefixroute 的:auto LL + 使用者/殘留 IP)——否則那些 normal 位址會
              生出競爭的 connected route、且讓 VM 看到與上游不一致的 host IP;reconcile_mirror 接著只把 up0 的 global+fe80
              鏡上去(noprefixroute, nodad)⇒ br 上只剩鏡來的 host IP,VM 與 ext-neighbor 看到同一個。
              **可逆**:清掉的 global 位址存起來,detach/teardown 時連同兩個 sysctl 一起復原(auto LL 由 kernel 依還原的 addr_gen_mode 自生)。
              (procfs 寫 `/proc/sys/net/ipv6/conf/<br>/{addr_gen_mode,accept_ra}`,非 shell out。)
            為何 accept_ra=0:br 是 host 側橋,位址只該來自鏡像,不該被 guest/上游漏進來的 RA 自動配址污染。
            br **固定 mac** 仍建議:br mac 預設取首個 enslave port、隨 port churn 可能跳動 → 固定後 host 在 VM 段 L2 身分穩定。

        host↔VM 需要的每個(非衝突)entry 寫一條:  ip route add <vm-ip>/32 dev br src <shared-ip>
            放獨立 table(預設 200)+ ip rule(prio 在 local=0 與 main=32766 間;v6 需 ip -6 rule)
            **per-entry pin src(src selector)** —— 從 host_ips(= up0 全部 IP)挑:
                ① most-precise:取「subnet 含 vm-ip」者中 **prefix 最長**的;
                ② tie(prefix 長度相同):取**數字最小**的 IP;
                ③ 無任何 subnet 含 vm-ip(真跨網):**不填 src**,交 kernel 自選。
              (noprefixroute 砍掉 connected route 的 prefsrc → kernel 不會自動 per-subnet 選,故須手動;
               且 host 回包路由也靠這條 /32,否則會落到 up0 的 connected route 從 up0 漏出。)
            不寫進 table local(255):會破壞 host own-address 投遞
            link-local(fe80::/10):只進 ip2mac6 供 ND demux,**不寫 /128**(fe80 scope link、不可路由);
              host↔VM 的 LL 連線一律 `-I <iface>`(靠 kernel 自動的 `fe80::/64 dev X` on-link route;
              不給 scope 會因多介面 fe80::/64 歧義而失敗)。br 的 LL 維持自動(**不加 noprefixroute**)。
            host_ips 須存帶 prefix 的 CIDR;vm-ip 不落任何 host 子網 = 真跨網,本機制不適用

    ⚠ br 鏡像的 IP **必須加 noprefixroute**(綁「同子網的一般 IP」會壞):
        一般 IP 會多一條同子網 connected route → host 解 default-gw 的出口變成 up0/br 二選一
        (由 ifindex/插入序決定、不可控);若落到 br,gw ARP 從 br 送出但回應走 up0
        → br 的 gw neighbor 永遠解不出 → host 自身外網流量卡死。noprefixroute 砍掉那條 route 即可避免。

    PoC:tests/poc/poc-fwd-ipless-vm2host(matrix:IP-less → host↔VM v6 雙向 FAIL、v4 靠 arp_ignore=0;
        鏡像 noprefixroute 後 → 4 向 v4+v6 全通、arp_ignore=1 仍穩)、
        tests/poc/poc-fwd-mirror-srcsel(多子網各選對 src v4+v6、normal 流量留 up0、strict rp_filter 全通)、
        tests/poc/poc-fwd-mirror-full(通則全測:host/VM 皆同子網多 IP + 跨子網、v4+v6、strict rp_filter、
            VM 連 host secondary 全通、IPv6 LL 不寫 /128 route、僅 -I 可達、無 -I 因 scope 歧義而失敗)、
        tests/poc/poc-fwd-peer-addr(peer 位址 = ownership+route+prefsrc 一條;多 VM 共用 local、refcount 生命週期)、
        tests/poc/poc-fwd-secondary-ip(host 有 secondary 50.11:peer-only → guest 連 50.11 v6 斷/v4 脆;鏡像後 v4+v6 通)、
        tests/poc/poc-noprefixroute(noprefixroute 原語)。

---

## syncer

syncer 是**唯一寫/撤 kernel offload 狀態的人**。維護兩份 state、由三類事件驅動、把 entries reconcile 進 kernel(衝突自動跳過)。

### state

    kernel-side —— 衍生值,由 recompute() 從 raw link/addr 算(不獨立追蹤;rust netlink 觀測):
        raw           : up0 link(present, mac)+ addrs;以及 up0.master(direct)/fwd1.master(fwd) 的 link(present, mac)+ addrs
        # br.addrs 在 fwd 是「鏡像輸出」:只讀來當 reconcile_mirror() 的 have 集(算 diff),**不進 host_ips**
        #   (host_ips 在 fwd 唯一真相是 up0;direct 才用 br.IPs)。br.link(present, mac)仍要讀 → 算 br_present / 在 direct 取 HOSTMAC
        ── recompute() ──
        up0_present
        br       = direct? master(up0) : master(fwd1)        # 它存在 = br_present
        HOSTMAC  = (direct && br_present)? br.mac : up0.mac
        BRMAC    = (fwd && br_present)? br.mac : ∅           # fwd OUT 的 src==BRMAC drop 用;direct 不需(= HOSTMAC)
        host_ips = direct? (br_present? br.IPs : ∅) : up0.IPs   # fwd 只看 up0 全部 IP(br 是 up0 的單向鏡像=輸出端,不回饋 host_ips)
        # ⚠ --offload-workaround 啟用時:up0.IPs / 鏡像來源都**排除 metric==magic 的 proxy 位址**(那是裝給 APF 的 guest 位址)

    userspace-side(packet processor 餵):
        entries[ip] : { mac, createat }                       # 衝突由 reconcile 自動跳過,不存 flag

### 事件 → 動作

三類事件:

    notify(ip)          (packet processor)  → reconcile(ip)
    timer(--timeout)                        → flush 老化(見 §老化規則)
    netlink link/addr   (kernel-side 變)    → recompute + diff(下)

**netlink → recompute + diff(level-triggered)** —— netlink 噪音多,先過濾出碰到 `up0 / up0.master / fwd1 / fwd1.master` 的才動:

    snap' = recompute();  diff = snap' vs snap;  snap = snap'
    # 一次 recompute 吸收關聯變化,例:direct 的 up0.master null → br-eth0
    #   ⇒ HOSTMAC 從 up0.mac 遷成 br.mac、host_ips 從 up0 搬到 br,同一個 diff 一起出現

    diff → 動作(只動有變的;br_changed ≝ br_index 變 ∨ fwd0_index 變):
        up0_present T→F  : teardown 全部 kernel 狀態 → 回未初始化(等 up0 回來)
        up0_present F→T(或尚未 initialized): init session
        HOSTMAC  變      : backend.set_hostmac(ebpf 寫 config map / nft 重建 ruleset+重灌 elements);
                           每 entry 廣播 guest-ip → 新 HOSTMAC(v4 grat-ARP / v6 unsolicited-NA override)
                           # gap:gateway cache 更新前送 dst=舊 mac 的封包會被 up0 NIC filter 丟 → 廣播縮短此窗
                           # 實測補述:對「學習型 switch/AP」上游,GARP/unsol-NA 立即生效(它本就靠 src mac 學 FDB);
                           #   但對「Linux host 當 gateway」上游,它對 REACHABLE 鄰居的 GARP 預設**不更新**(反 ARP 欺騙),
                           #   要等 NUD 逾時才重解 → 窗口可達數秒。pbridge 行為正確(送了 GARP、egress 全 new mac、demux 正確),
                           #   此延遲純粹是該上游的鄰居策略;測試環境用 `arp_accept=1` + change 後 flush gateway neigh 來模擬 switch。
        BRMAC    變      : backend.set_brmac(僅 fwd;隨 br port churn / 固定 mac 設定變,無需廣播)
        host_ips 變      : backend.set_host_ips(重 program kernel host set)
        (fwd) br_changed : withdraw_all_host_routes()——舊 br 的 /32·/128 全撤;下面 reconcile_all 經新 br 重建
        (fwd) host_ips ∨ br_changed : 若 br 存在 → 補 ip rule(`iif lo lookup <vmroute-table>`,v4+v6 同 prio,idempotent;
                                      僅當 --vmroute-table 與 --vmroute-rule 皆非 -1 時才下);reconcile_mirror()(up0→br 單向鏡像,見上)
        HOSTMAC ∨ host_ips ∨ br_changed : reconcile_all()——全量逐 entry reconcile(衝突 skip/restore 自動翻轉)

    # init/teardown 立即 return(不跑下面的 diff);其餘旗標可同一個 diff 並存,依序套用。
    # diff 很輕(重查 up0+master link/addr、比小 struct);過濾後頻率低,不怕 netlink 噪音。

**syncer 實際安裝/撤除的 kernel 狀態(每個動作對應的 netlink/offload 寫入)**:

    init session(fwd)      : create_veth(fwd0,fwd1) + disable_dev_autoconf 兩端(addr_gen_mode=1,accept_ra=0,刪 auto LL)+ link up
                             → backend.init(注入器+offload 規則)→ ensure_vmroute_rules(`iif lo`,見下)→ reconcile_mirror → reconcile_all
    reconcile(ip) write    : backend.write_entry(ip,mac)= ip2mac/valid + seen=alive
                             (fwd 且非 link-local 且 --vmroute-table≠-1) route_add(ip/{32|128} dev=br_index,prefsrc=select_src(ip,host_ips),table=vmroute-table)
                             (offload-workaround,fwd) proxy(ip)= addr_add_tagged(up0, ip/{32|128}, metric=magic, noprefixroute,[nodad,deprecated])
    reconcile(ip) withdraw : backend.withdraw_entry(ip) + (fwd) route_del(ip,vmroute-table) + (workaround) unproxy(ip)= addr_del(up0,ip)
    reconcile_mirror()     : addr_add/del 於 br(global+fe80,noprefixroute nodad);apply/restore_bridge_cfg(addr_gen_mode/accept_ra)
    teardown               : withdraw_all_host_routes + unproxy_all(撤所有 up0 proxy 位址)+ clean_mirror + restore_bridge_cfg
                             + backend.teardown + (fwd) link_del(fwd0)(連帶刪 veth pair)
    # 唯一寫 route 的是 fwd 的 per-guest /32·/128(table=--vmroute-table,預設專用 table 200,scope link,prefsrc=host 同段 IP);direct 不寫(VM 經 br connected route on-link)。
    #   這條 vmroute **只給本機發起(host→guest)的流量用**:外部流量一律由 ebpf/nft 的 IN demux 在 tc-ingress 就 redirect 進 bridge 走 switching,根本不過 routing table。
    #   故配一條 `iif lo lookup <table>` rule(預設 prio 11000)——只有 host 本機產生的封包查這張表,不是 `from all`。
    #   (注意 `local` table 不是「本機發起的表」而是 kernel 對**所有**封包最先查的「本機交付」表;要「只給本機發起」必須用 iif lo rule 指到專用 table。)
    # proxy 位址不是 route 而是「裝在 up0 上的位址」(供上游 ND/ARP offload 替它回 HOSTMAC);詳見 §ND/ARP offload 繞道。
    # level-triggered → 漏接事件也沒關係:下次任何相關 event 的 recompute 都收斂到當前真相(自我修復)。

### reconcile(ip)

    e = entries.get(ip)
    skip = (e is None)            # 已刪/踢
         or (ip ∈ host_ips)       # 撞 host 自有 IP → host 最優先(vm 用同 IP 被無視)
         or (e.mac == HOSTMAC)    # 撞 HOSTMAC
    if skip: withdraw(ip)         # 撤 ip2mac / valid / seen / host-route(沒寫過 = no-op)+ unproxy(ip)
    else:    write(ip, e.mac)     # ip2mac[ip]=mac + valid(ip,mac) + seen=alive + (僅 fwd)/32·/128 route + proxy(ip)
    # idempotent diff:既有不變 → 不動(免 churn)。衝突是「reconcile 時算出來的 skip」,不存 enable flag
    # → host_ips/HOSTMAC 一變即全量 re-reconcile,skip/restore 自動翻轉
    # proxy(ip)/unproxy(ip):僅當 offload 繞道生效(`--offload-workaround` 或 `-m fwd-with-offload`)才動;見 §ND/ARP offload 繞道。
    #   注意「撞 host_ips 即 skip」這條本身就是反劫持核心:guest 偽冒 host 自有 IP 時 ip ∈ host_ips → skip → 永不寫 demux、永不代理

### reconcile_mirror()  ——  僅 fwd;單向 up0 → br(=fwd1.master)

把 up0 的整組 IP 鏡像到 br,讓 host 在 VM 段擁有同一組位址(回 ARP+ND、當 src);up0 是唯一真相、br 不回饋。

    want = { (a.ip, a.plen) for a in up0.addrs if a.scope ∈ {global, link} }   # global + link-local(fe80);排除 host-scope
    have = { (a.ip, a.plen) for a in br.addrs  if a.noprefixroute               # 「我們管的」= br 上 noprefixroute 的
                                              and a.scope ∈ {global, link} }     #   (br 自動 LL 非 noprefixroute → 不在內)
    for (ip,plen) in want - have:  ip addr add ip/plen dev br noprefixroute nodad
    for (ip,plen) in have - want:  ip addr del ip/plen dev br
    # 只動 noprefixroute 的位址 → 永不碰 br 自己的位址 / 自動 LL;idempotent(只動 diff);單向、br 不回饋
    # 實作修訂:**link-local(fe80)也鏡**——host 要在 VM 段被它的 fe80 解到(v6 ND)、且要與上游段看到的是同一個 host fe80。
    #   仍**不寫任何 route**(rest of host→VM route 是 per-guest-entry、且 skip link-local);鏡的只是「位址」。
    # br 設定(attach 改、detach 復原,見下「br mirror-only 定址」):addr_gen_mode=1 + accept_ra=0,
    #   **並先清掉 br 自己所有 non-noprefixroute 位址**(auto LL + 使用者/殘留 IP)再 mirror ⇒ br 上只剩鏡來的 up0 IP;
    #   清掉的 global 位址存起來,detach 時復原。
    # 觸發:session init + host_ips(= up0.IPs)變 + **br 出現/變更/消失**(fwd1.master 變)
    #   ⚠ pbridge **不建、不 enslave、不碰任何 bridge**——唯一 pin 的是 up0;fwd 的 br = fwd1.master,
    #     由操作者隨時 attach/換/detach(`brctl addif testbr {if}-br` 或 `ip link set {if}-br master testbr` / `nomaster`),
    #     rust netlink 監測即時跟上。三種轉場都要處理:
    #       attach(None→A):apply_bridge_cfg(A)(存原值、addr_gen_mode=1+accept_ra=0、刪 A 自生 auto LL)→ mirror 到 A(global+fe80)→ ensure_vmroute_rules(`iif lo lookup <table>`,預設 table 200 / prio 11000)。
    #       change(A→B):**先清 A**(刪 A 上鏡的 noprefixroute 位址)+ **復原 A 的 sysctl** → apply_bridge_cfg(B) + mirror 到 B;host route 撤舊、reconcile_all 經 B 重建。
    #       detach(A→None):清 A + 復原 A sysctl、撤所有 host route、撤 BRMAC drop 規則。teardown(up0 消失)同樣清 mirror + 復原 sysctl。
    #     實作:Core 記 `mirrored_br`(上次鏡到哪個 br)+ `saved_br_cfg`(該 br 原本的 addr_gen_mode/accept_ra),
    #     reconcile_mirror() 比對 target≠mirrored_br 就先 clean+restore 舊的、再 apply+mirror 新的——
    #     clean 只刪 noprefixroute 的位址,不碰操作者自己的 IP。
    #     ⇒ 「br 變」這條 diff 必須觸發 reconcile_mirror;只看 host_ips(=up0.IPs,不隨 br 變)會漏掉 attach/detach。
    # IPv4 secondary 一樣鏡(scope 仍 global);plen 照抄 up0(供 src selector 的 most-precise 比對)

### ND/ARP offload 繞道(`--offload-workaround` / `-m fwd-with-offload`;僅 fwd)

> 開法兩種:`-m fwd --offload-workaround v4,v6`,或預設 preset `-m fwd-with-offload`(= fwd + 預設開 v4,v6,可被顯式 `--offload-workaround` 覆寫)。

**問題**:某些上游網卡(實測 Android Wi-Fi 的 **APF** — Android Packet Filter,韌體內的封包過濾程式)會做 **ND/ARP offload**:對「目標不是本機自有位址」的 NS/ARP-request 直接在韌體丟掉(`DROPPED_IPV6_NS_OTHER_HOST` / `DROPPED_ARP_OTHER_HOST`),host 的 kernel/hook 根本收不到。MAC-NAT 下 guest 的位址不在 up0 上 → 上游解析 guest 的 NS 全被丟 → 回程封包永遠送不到。

- 這**不是** kernel/driver 層的 multicast filter(實測 `IFF_ALLMULTI`、`ip maddr add` 的 L2 過濾項、甚至真正的 MLD 加入 `ff02::1:ffXX:XXXX` 都無效——APF 是看「本機位址表」而非已加入的群組),也**不是** `WifiMulticastLock`/`RXFILTER`(那是 multicast filter,與 ND offload 無關)。
- **v6 = 一開始就不通(hard fail)**:IPv6 預設路由 next-hop 是 gateway 的 **link-local**(RA 給的),所以 guest 解析 gateway 是 **LL→LL**,gateway 只學到 `guest_LL→HOSTMAC`,**永遠學不到 global**;要回 guest 的 global 流量就得主動 solicit global → 被 APF 丟 → 從頭就不通。
- **v4 = 會「閃斷」(flap),不是不受影響**(實測必須開):guest 解析 gateway 用 ARP-request,sender = `guest_v4@HOSTMAC`,gateway 身為 target 依 RFC 826 快取它 → **初次會通**。但該 entry 會老化(`STALE`→`PROBE`),gateway 一旦**主動重解**(對 `guest_v4` 發 ARP probe / request)就被 APF 丟(`ARP_OTHER_HOST`)→ entry 走 `INCOMPLETE`/`FAILED`;只有等 guest **自己**下次又 re-ARP gateway 才被重新教會。兩個老化週期獨立 → entry 在 REACHABLE 與 FAILED 間擺盪(OpenWrt 上看到的 INCOMPLETE/FAILED 切換)。裝上 proxy 後 APF 會替它回 ARP probe → entry 常駐 REACHABLE。
- **故 `--offload-workaround` 兩者都要(`v4,v6`)**:v6 立即失敗、v4 閃斷,皆需繞道。`v6ll` 通常不需(on-link 鄰居才解 LL,gateway 不解 guest LL)。

**解法(順著 offload 而非對抗)**:把學到的 guest 位址**安裝到 up0 自己身上**,使其成為「本機自有位址」 → APF 改為**直接用 HOSTMAC(=up0 mac)替它回 NA/ARP-reply**(韌體 offload,零延遲、零喚醒)。**外部**回程資料封包到 up0 後,既有 IN demux 在 **tc-ingress**(早於 routing/local-delivery)就 `bpf_redirect → fwd0`,因此 up0「擁有」該位址**不影響**外部轉發。純 netlink、逐 guest 隨學隨裝,無需 framework / SELinux 介入。

- **但 host→guest(本機發起)會被 local route 吃掉**:配位址時 kernel 會在 `local` 表自動加 `local <G> dev up0`(type RTN_LOCAL;`noprefixroute` 只擋 prefix route,**擋不掉 local route**),host 本機送往 G 就被 local-deliver 給自己,不再經 vmroute 轉給 guest。**解**:proxy 安裝後**刪掉那條 local route**(`del_local_route`,table local + type=local,scope/proto 用 NoWhere/Unspec 萬用比對才匹配得到)→ host 發起的 G 流量改走 vmroute 轉給 guest;位址仍**保留**(APF 照樣回 ND/ARP——回應只看位址有沒有配,與 route 無關)。
  - v4 的 local route 同步建立、可即刻刪;**v6 的 local route 在 addr-add 回來後才非同步插入**,故 `del_local_route` 每次 reconcile 都對 proxied 位址重試(idempotent)——addr-add 觸發的後續 reconcile 會補刪到。

**安裝形式(magic-metric 標記)**:proxy 位址用 `IFA_RT_PRIORITY = <magic>`(預設 4243672773)當**唯一身份標記**——kernel 會原樣存回並回報,即使 `/128 noprefixroute` 也照存(不建任何 prefix route)。

    proxy 位址 = up0 上 `metric == magic` 者         # 我們裝的(guest 位址)
    host_ips / 鏡像來源 = up0 上 `metric != magic` 者  # host 真位址(SLAAC/DHCP/admin,metric=0)

    安裝:ip addr add G/{32|128} dev up0 metric <magic> noprefixroute [nodad] [deprecated]
          # v4 → /32;v6(global+ll)→ /128 + nodad + deprecated(preferred_lft 0,host 永不拿它當 src)

**演算法**(掛在 `reconcile(ip)`,僅 fwd 型 mode 且該 family 在生效集合內 — 生效集合 = 顯式 `--offload-workaround`,否則 `-m fwd-with-offload` 預設 v4,v6):

    proxy(ip):   # 在 reconcile 的 write 分支(該 ip 已是有效 guest entry)
      family 選擇:ip 之 family ∈ --offload-workaround(v4 / v6=global / v6ll=link-local)否則不裝
      guard:① ip ∉ 預設閘道(default_gw6,避免劫持上游 router)
            ② link-local 視為 on-link 直接過;否則 ip 必落在某 host on-link prefix 內(避免代理跨段/亂送)
            ③(隱含)ip ∉ host_ips、e.mac ≠ HOSTMAC ← reconcile 的 skip 已擋,host 位址永不進 proxy 集
      未裝過 → addr_add_tagged(up0, …) 記入 nd_proxied;之後(每次)→ del_local_route(ip)(刪 kernel 自動的 local route,host→guest 改走 vmroute;v6 非同步故重試)
    unproxy(ip): # 在 reconcile 的 skip 分支(踢/刪/撞 host)
      若 nd_proxied 有 ip → addr_del(up0, ip, {32|128}) 並移除追蹤
      # 刪 /128(或 /32)永不會誤刪 host 同 IP 的 /64(kernel 刪除比對 prefix-len);故 host-wins 衝突天生安全

**host vs guest 之辨(反劫持)**:身份完全由 magic-metric 決定,不靠旗標組合臆測。
- guest 偽冒 host 自有 IP `H`:`H` 是 host 真位址(metric≠magic)∈ host_ips → reconcile **skip** → 永不寫 demux、永不代理。
- proxy 集只在 write 分支加入(其前提即「不在 host_ips」)→ host 位址永不會被當成 proxy;recompute 又把 metric==magic 者排除在 host_ips 之外 → 兩集合結構性互斥、host 永遠優先。
- 殘留邊角(bootstrap race):guest 先搶了 host **未來**才會配的位址 → 我們的 `/128` 會 EEXIST 擋住 host 配置。但 host 位址在關聯時就先配好(早於 guest 出現),且 privacy 位址隨機不可預測 → 實務上不可能,故僅記錄不特別處理。

**模式/位置**:**僅 fwd**(up0 獨立站,APF 掛在實體網卡、看 up0 自己的位址表)。direct mode 下 up0 是 bridge port(有線情境,Wi-Fi STA 無法 bridge),kernel 對 bridge port 設 `allmulti`、NS 經 bridge 自然到 guest,**不需此繞道**;且 guest 已在該 bridge 上、位址不能再裝到 up0.master(撞重)。故 direct mode 此旗標**惰性忽略**(啟動時 warn 一行)。teardown 時 `unproxy_all()` 全撤。

### ARP keepalive(`--arp-keepalive`;v4 出向鄰居快取保活)

**問題(實機診斷,高通 Wi-Fi)**:offload 繞道把 guest 位址裝上 up0 後,「醒著時」kernel/APF 答得了 ARP;但 powersave 下接手的是韌體原生 **WMI ARP offload**(`WMI_SET_ARP_NS_OFFLOAD_CMDID`,driver 路徑 `hdd_populate_ipv4_addr → ucfg_dp_set_ipv4_addr`),它的 **v4 只有一個 slot**(host primary;v6 NS offload 多 slot,故 v6 不受害)。睡眠中對「tpa ≠ 該 slot」的 ARP request(廣播 INCOMPLETE 解析與單播 NUD probe 都算)**直接丟**,只有零星醒著的窗口放行 → 實測 guest v4 的 ARP request 丟包 ~99%,gateway 對 guest 的 neigh entry 在 `INCOMPLETE→FAILED→STALE→DELAY→PROBE` 間擺盪,v4 時好時壞;`powersave off` 全好但整機耗電。

**解法(順著 powersave,不對抗)**:把「inbound ARP 能不能進來」翻轉成「**outbound 定期送**」——STA 發送不受 powersave 影響。依據 Linux `arp_process()`:**單播 ARP reply(`PACKET_HOST`)即使 unsolicited 也把對方 entry 設成 `NUD_REACHABLE`**;廣播 reply(GARP)與 request 最多 STALE、且 `arp_accept=0` 時不建新 entry(kernel 原文註解 "Broadcast replies and request packets do not assert neighbour reachability")。⇒ 對 up0 鄰居表中每個 v4 鄰居、替每個已學 guest v4 週期發 unsolicited 單播 reply:對方 entry **常駐 REACHABLE、永不進 DELAY/PROBE、永不發 request** → 韌體丟不丟 inbound ARP 變得無關;另補週期 GARP 給「不在 host 鄰居表、但自己快取過 guest」的 LAN peer(刷成 STALE,best-effort)。已存在的 `INCOMPLETE`/`FAILED` entry(對方試圖送 guest 而解析失敗時自動建立)也會被單播 reply 直接解開(lladdr 填入 → REACHABLE → 排隊封包放行)。

**模組落點**:

    cli      : --arp-keepalive <secs>(0=off 預設;Android Wi-Fi 建議 10)
    netlink  : default_gw4()(同 default_gw6 的 v4 版)+ neighbours_v4(ifindex, exclude_lladdr=HOSTMAC)
               (RTM_GETNEIGH dump:取有 lladdr 且 state ∈ REACHABLE/STALE/DELAY/PROBE/PERMANENT、且 lladdr ≠ HOSTMAC 者)
    afpacket : build_arp_reply(spa=G, sha=HOSTMAC, tpa=n.ip, tha=n.mac, L2dst=n.mac)(單播);GARP 用既有 build_garp
    core     : 獨立 interval timer(MissedTickBehavior::Delay),經 up0 Injector(AF_PACKET)注入

```
# 每 --arp-keepalive 秒(0=off;未 initialized 不跑)
on_arp_keepalive():
    guests = { v4 ∈ installed }                    # 已過 reconcile 的有效 entry(host-wins 已 skip)
    if guests 空: return
    tick += 1
    neigh = neighbours_v4(up0, 濾掉 lladdr==HOSTMAC) # 自己人(host 自有位址、MAC-NAT 後的 guest)的
                                                     #   鄰居項必指 HOSTMAC → 掃描時直接排除,免事後集合相減
    for gw in default_gw4() − neigh:               # gateway 被 GC(host 久無流量)→ 補解析
        send(up0, arp_request(tpa=gw, spa=host_v4, sha=HOSTMAC))
        # 回覆 tpa∈host → IN 提早 accept 進 host stack → kernel 自己補鄰居表;下一拍即覆蓋
    for G in guests:
        for n in neigh:
            send(up0, arp_reply(spa=G, sha=HOSTMAC → n))   # 對方 entry → NUD_REACHABLE
        if tick % 3 == 0:                          # 廣播禮貌:廣播會喚醒整個 WLAN 的 PS client
            send(up0, garp(G))
```

- **迴圈安全(天然成立)**:注入 frame `src==HOSTMAC` → egress_guard 不命中;`op=reply` → discovery-dup 只 clone `op==request`,不會被回灌 vmbr。GARP 同(op=2)。
- **涵蓋範圍**:gateway 100%(host 自身流量使其常駐鄰居表 + 缺席補解析);「只跟 VM 講話、不跟 host 講話」的 LAN peer 不在 host 鄰居表,僅靠 GARP best-effort(STALE 可用但會 flaky)——上限,文件化。
- **範圍限定 v4**:v6 NS offload 多 slot 無此問題;且 RFC 4861 下 unsolicited NA 不 assert REACHABLE(只有 solicited NA 會),發了沒有等價效果。
- **mode 無關**(fwd/direct 都可開;頻率與 entry 數成本 = entries × (鄰居數+1) 個 60B frame/拍,可忽略),目標場景是 fwd(Wi-Fi STA)。
- 成本/功耗:radio 本就每 beacon/DTIM 醒;多送幾個小 frame 遠低於 `powersave off`(常醒)或週期 toggle powersave。
- 驗證:`func-arp-keepalive.sh`(案例 18)。

### entry 生命週期(4 操作 × kernel/rust)

決策全在 rust(entries);kernel 只被 syncer 寫/撤 + nft 自動偵測 idle:

| 操作 | 觸發 | rust 做 | kernel(由 syncer 執行) |
|---|---|---|---|
| 1 新增 | learn 新 ip(過 admission) | dict add | 寫 `ip2mac`/`valid` + `seen=alive` + (fwd)/32·/128 route |
| 2 取代(mac 變) | learn (ip, 新 mac) | dict 改 mac、per-mac 計數 ±1 | `ip2mac`/`valid` `del+add`、`seen` 刷新 |
| 3 刪除(timeout) | idle | `flush()` 取存活集 → dict `del` | 撤 `ip2mac`/`valid`/(fwd)route(`seen`:nft 自動、ebpf flush 刪) |
| 4 踢(cap) | learn 超上限 | 選最舊(FIFO)→ evict → admit 新 | 撤被踢者 `ip2mac`/`valid`/(fwd)route |

- 兩 backend **唯一差異 = op3 偵測 idle**(nft `@seen` kernel-timeout / ebpf `flush()` second-chance);op1/2/4 與 op3 的實際撤除完全相同。
  - **實作補述(nft 撤除原子性)**:撤一個 entry 要刪 `ip2mac` + `valid` + `seen` 三個 element。`seen` 是 kernel 自動逾時的 dynamic set,撤除時它**可能已被踢掉** → `DELSETELEM` 回 `ENOENT`。若三刪同放一個 atomic batch,`seen` 的 ENOENT 會**回滾**整批 → `ip2mac`/`valid` 沒刪掉、殘留髒 demux。故拆兩段:`ip2mac`+`valid` 一批(live entry 必在、保證成功)、`seen` 另一批 best-effort(吞 ENOENT)。
- **op4 踢人 = rust FIFO by `createat`**(kernel 做不到:nft set 滿是「拒插」非踢最舊;ebpf `LRU_HASH` 是 LRU≠FIFO、且與事前 admission 衝突 → 用普通 `HASH`,rust 踢)。per-mac 超 → 踢該 mac 最舊同型(guest 自我輪替不擴張);global 超 → 踢全域最舊同型。FIFO 比 LRU 簡單(免追蹤 access)。
- **host route 僅 fwd mode**:direct mode 的 VM 經 br 的 connected route 天生 on-link,op1/2/3/4 都不寫/撤 host route(其餘 `ip2mac`/`valid`/`seen` 照舊)。

落點(都不在 syncer 決策,只是它的輸入/輸出):learn / caps 在 packet processor;**衝突**在 `reconcile` 自動 skip;**liveness** 由 timer 的 `flush()` 驅動。一句話:syncer 持兩份 state、三類事件驅動、單向寫 kernel、衝突自動跳過。

---

## 驗證

### kernel 能力 PoC(設計前提,皆已實測 — `tests/poc/poc-*`)

    [poc-nflog]        NFLOG 在 netdev ingress + egress 都可(NFQUEUE 在 netdev 不行/EOPNOTSUPP);
                       帶原始 src mac(`NFULA_HWADDR`);複製是 snapshot(log 後改包不影響 copy)
    [poc-nft-nd-guard] ND 改寫:NS/NA @th,208、RS @th,80;`ip6.src≠::` + `@th≠HOSTMAC` guard 正確(含 DAD-with-option)
    [poc-nft-modify]   nft `set` arp.sha/tha、nd.lla(raw @th)、map demux、`update` 自學;確認 ND csum 要 userspace
    [poc-nft-dhcpcsum] nft `@th,144,16 set` + `udp checksum set 0`
    [poc-nft-dup]      nft `dup to`(NFT_DUP_NETDEV)複製 bcast/mcast 到 guest 側、且非終結(原包續走 host)
    [poc-ebpf-inplace] ebpf in-place 改 ND lla + ICMPv6 csum(`update_csum`)—— host k6.17 + 真 GKI 6.6
    [poc-bridge-queue] bridge-family queue 收得到 bridged frame(NFLOG 之外的備選)

### host → VM 路由 PoC(皆已實測 — 對應「host → VM 路由」章)

    [poc-direct-no-route]    direct:零路由,VM 經 br connected route on-link,host↔VM v4+v6 雙向
    [poc-fwd-ipless-vm2host] fwd IP-less br:host↔VM v6 雙向 FAIL、v4 僅靠 arp_ignore=0;br 鏡像後 4 向全通
    [poc-fwd-mirror-full]    fwd 通則(mirror 整組 noprefixroute + per-guest route pin src):host/VM 皆同子網多 IP
                             + 跨子網、v4+v6、strict rp_filter、VM 連 secondary 全通、IPv6 LL 不寫 route 僅 -I
    [poc-fwd-mirror-srcsel]  多子網 src 各選對(v4+v6)、normal 流量留 up0
    [poc-fwd-peer-addr]      peer 位址 = ownership+route+prefsrc 一條;同子網多 VM 共用 local、refcount
    [poc-fwd-secondary-ip]   host secondary 需在 br own 才通(否則 v6 斷、v4 脆)
    [poc-noprefixroute]      noprefixroute 原語(保 local /32 ownership、不建 connected route)

### 測試環境(netns)

    ns-up(上游)══ ns-host(pbridge:up0 + br + fwd0╌fwd1)══ ns-g1 / ns-g2(guests)
    **關鍵:上游 netns 必須模擬「只認單一 MAC」**(只放行 src==HOSTMAC,其餘 drop)—— 否則軟體 bridge flood
      unknown-unicast、測不出 MAC-NAT 的價值。**實作改用 `tc flower src_mac <HOSTMAC> action ok` + `matchall drop`,不用 nft**:
      stock GKI 既沒 `NF_TABLES` 也沒 `NET_CLS_FLOWER`,故 flower 載不上時就**跳過強制**(只加 drop 會把全部擋掉),
      改靠案例 13 的 on-wire 抓包(guest mac 不得作 src 出現)驗正確性。
    **HOSTMAC 變更測試**:gateway 設 `arp_accept=1`,change 後 flush 其 neigh,模擬學習型 switch 立即重學(見 §syncer gap 補述)。
    服務:dnsmasq(DHCPv4 + DHCPv6 + RA);工具:udhcpc(busybox)、tcpdump -e、ping(v4+v6)。
    **同一套 netns 套件三個 env 都跑**:x64 直接在 host 跑(nft 在 **bpf-blocked seccomp wrapper `noebpf` 下跑** = 「無 ebpf 權限」、
      證 nft path 0 bpf;ebpf 在開 bpf 權限下跑)、aarch64 在 QEMU GKI 內跑 ebpf(見矩陣)。
    harness:`build.sh`(repo 根)+ tests/finaltest/{smoke.sh, matrix.sh, noebpf.c, run-android.sh, run-redroid-pbridge.sh}
      (matrix.sh 已整併舊 func-*.sh 的各案例;舊 netns-smoke.sh/func-*.sh 為前一版控制層、已被取代)。

### 功能案例(每個 config 都要綠)

| # | 案例 | 斷言 |
|---|---|---|
| 1 | DHCPv4 | guest 取 lease;上游見 DISCOVER `src mac=HOSTMAC, chaddr=guest`;`ip2mac4[ip]==guest mac`;通(須 broadcast bit) |
| 2 | DHCPv6 / SLAAC | guest 取 IA_NA / 自組 global(DAD NS 學);`ip2mac6` 正確;ping6 通 |
| 3 | ARP 出/入 | 出:上游見 `arp_sha=HOSTMAC`;入:gateway 學 `ip→HOSTMAC`、guest 收還原 reply(`tha=guest`) |
| 4 | ND 出/入 | NS/NA/RS 出向改 LLA=HOSTMAC + csum 正確;RA 不改 router 真 LLA;solicited RA 經 in demux 回 guest |
| 5 | guest 換 IP | 新 ip 首包學進表、連通;舊 ip 過 timeout 從 ip2mac/valid/seen 消失 |
| 6 | guest 換 MAC | miss 包進 userspace、短時間 ip2mac/valid 更新;入向改送 new mac;連通不中斷 |
| 7 | timeout / eviction | 靜默 > timeout → entry 移除;再發話重新學 |
| 8 | guest 隔離 + 多 guest | g1↔g2 的 unicast 流量(bridge FDB 學成後)不經 up0;broadcast ARP / FDB 未學前的 flood 副本會出現在 up0 屬預期(其 src 仍須 == HOSTMAC);各自身分正確、回程分別送達 |
| 9 | host 共存 | host 自身 DHCP/ARP/ping/SSH 上游全程正常(`host_ips` 排除、DHCP chaddr 還本機、gateway ARP 收得到) |
| 10 | host↔VM 路由 | direct 零路由通;fwd 鏡像 + /32//128 通(v4+v6 雙向、含 secondary、LL 用 -I) |
| 11 | HOSTMAC 變更即時跟上 | `ip link set up0 address` → 短時間 egress 全 new mac、入向正確、每 entry 廣播(GARP / unsol-NA);guest 表不受影響 |
| 12 | caps:per-mac + global | guest 狂加 IP 超上限 → 封頂、FIFO 擠最舊、其他 guest 不受影響 |
| 13 | **出向零洩漏** | `tcpdump -e up0` 整段:**所有** frame src mac == HOSTMAC,零例外;egress_guard counter 可非 0(定義見 §backend 原語對應) |
| 14 | **學表故障也不洩漏** | 停掉 copy/learn handler 後 guest 發包:連通可中斷,但對端**仍**看不到 foreign src(安全網與學表解耦) |
| 15 | fast-path 不進 userspace | 學表後 iperf3:吞吐高、copy/NFLOG 計數幾乎不增(data 留 kernel) |
| 16 | host→**靜默** VM discovery(僅 fwd) | VM 配 static IP、完全不發包 → host 連 VM:up0-egress discovery dup 把 host 的 ARP/NS clone 到 fwd0 → VM 回應被學、vmroute 建起 → 重試連上(`func-silent-vm.sh`,nft+ebpf) |
| 17 | offload keepalive(僅 offload) | timeout=5、guest 發包後**靜默 15s**:keepalive probe(timeout/2 週期、fwd0 注入)讓 proxied entry 不被踢 → entry 仍在、**gw→guest 仍通**;guest 釋放 IP 後 ~timeout 被踢、gw→guest 轉不通(`func-offload-workaround.sh` Phase C + `func-offload-keepalive.sh`,nft 含 bpf-blocked) |
| 18 | ARP keepalive(`--arp-keepalive`) | 等價場景模擬韌體單 v4 slot:**gw egress 只放行 `tpa==host` 的 ARP request、其餘丟**;host↔gw 先通訊建鄰居表;guest 持 permanent gw neigh(不重 ARP 的窗口)。斷言:off → guest↔gw v4 死、gw entry FAILED;`--arp-keepalive 2` → 恢復(單播 reply 解開 FAILED entry),guest **靜默 10s 後** gw entry 仍 REACHABLE、gw→guest 100% 通(`func-arp-keepalive.sh`,nft bpf-blocked + ebpf) |

額外功能腳本(矩陣外、各自 nft+ebpf):`func-silent-vm.sh`(案例 16)、`func-offload-workaround.sh`(`--offload-workaround` / `fwd-with-offload`:apfsim 模擬 APF,gateway→guest off→fail/on→pass + proxy 機制斷言 + Phase C keepalive 案例 17)、`func-offload-keepalive.sh`(案例 17 位址層 + 釋放→踢除,nft 跑在 bpf()-blocked seccomp 下證明 probe 無需 ebpf)、`func-arp-keepalive.sh`(案例 18,§ARP keepalive)。

### 測試矩陣:env × engine × mode

每個功能案例在每個 config 跑。config = **env × engine × mode(direct / fwd / fwd-with-offload)**。

| env × engine     | 怎麼跑 |
|---|---|
| **x64 nft**      | host netns,**`bpf()` 被擋**(模擬 linux container)。實作:pbridge 在 `noebpf` seccomp wrapper 下跑——`bpf` syscall 回 `EPERM`;nft path 全程 0 bpf,跑得起來即證(ebpf 在同 wrapper 下會在建 map 時 EPERM 失敗,反證 wrapper 有效)|
| **x64 ebpf**     | host netns,**bpf 權限開**(有 bpf 的 linux:dev box / server) |
| **aarch64 ebpf** | **aarch64 GKI 6.6(android15-6.6.102)image 跑在 QEMU**(x64 host、TCG),矩陣 rootfs = **Alpine arm64**(內含 iproute2/tcpdump/bash)—— 真 GKI 上驗 ebpf |
| ~~aarch64 nft~~  | **跳過** —— GKI 無 `NF_TABLES`,且 nft 規則跨架構差異不大,x64 nft 已涵蓋 |

→ mode 現有三種(direct / fwd / fwd-with-offload;後者 = fwd + offload 繞道,topology 同 fwd)。
**實測(linux):engine(nft, ebpf)× mode(direct, fwd, fwd-with-offload)= 6 configs 全綠**,每 config 16 項全過;另 aarch64 ebpf × {direct, fwd} 於真 GKI 6.6 QEMU 通過;redroid15 bionic on GKI:binary 起得來。
harness:tests/finaltest/matrix.sh(`ENV=linux` 跑 nft+ebpf、`ENV=android` 跑 ebpf);aarch64 由 `tests/setup-artifacts.sh`(拉 GKI 6.6 + Alpine + redroid)+ `tests/finaltest/run-android.sh` 在 QEMU 跑(TCG ~20× 慢,計時用 adaptive),redroid 由 `run-redroid-pbridge.sh`。
二進位:`./build.sh`(repo 根)→ `dist/pbridge-{linux-x64,android-arm64}`,皆 **static musl**(可在 glibc/musl/bionic 下跑;aarch64 用內建 rust-lld 連結,免外部 cross toolchain)。
tests/ 結構:**poc/**(能力實驗)、**finaltest/**(功能套件 + android harness)、**artifacts/**(下載/產生的大檔,gitignore);`setup-artifacts.sh` 在 tests/ 根。
**redroid15 arm64(`redroid:15.0.0-latest`)另作 smoke**(矩陣外):pbridge 在真 Android userspace(bionic)起得來(redroid 缺 bpftool/bash/iproute2-tc,故不當矩陣 rootfs)。

tests/ 有一些老 code 的測試腳本可以參考，但不一定對齊我們的測試
