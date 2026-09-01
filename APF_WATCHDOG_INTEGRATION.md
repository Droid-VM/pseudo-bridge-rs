# APF Watchdog Integration into pbridge

## Context

pbridge 的 `fwd-with-offload` 会把 guest `/32` 加到 `wlan0`，使当前 NetworkStack APF 的 ARP request 分支变为无条件 PASS；但小米 vendor APF 程序仍会无条件丢弃 IPv4 ICMP echo request（`DROPPED_ICMP_ECHO`）。已验证的字节码补丁在该 drop 前插入 `ldw r0,[30]` 与每个 guest IPv4 一条 `jeq r0,<guest>,PASS`，同时修正跨插入点的跳转偏移并等量缩小 debugbuf。NetworkStack 在 Doze、RA、地址/LinkProperties、多播、keepalive 等变化时会重装 APF，覆盖手工补丁。

本变更把低延迟覆盖检测与安全重装事务集成进 `pseudo-bridge-rs` 的 eBPF backend。eBPF kprobe 监听 Qualcomm APF 的唯一 vendor-command 入口 `wlan_hdd_cfg80211_apf_offload`，在内核中以 pbridge 的 own TGID 过滤自身的 disable/write/read/enable 命令，避免自激；Rust 控制面接收事件后通过内置的 Qualcomm nl80211 vendor-netlink 客户端读取/生成/验证/写回 APF work memory。该功能显式选择加入，第一版支持最多 8 个固定 IPv4 guest 地址。

## Recommended Implementation

### 1. CLI 与启用边界

在 `pseudo-bridge-rs/src/cli.rs` 增加可重复参数 `--apf-watchdog-guest <IPv4>`：

- 仅接受 IPv4、去重、最多 8 个；空列表即功能关闭。
- 清晰的 parser 错误：IPv6、重复项和第 9 个地址均拒绝。
- 在 `Engine::Nft` 下拒绝启动（或在 parser 后早期返回明确错误）；此功能依赖 BPF kprobe，不能静默退化为轮询。
- 把参数和值加入启动日志；初始化期间在不支持 kprobe/ringbuf 或 Qualcomm 符号不存在时失败退出，禁止进入"看似启用但实际上没有检测"的状态。

### 2. BPF 对象：kprobe 通知与自身过滤

扩展 `pseudo-bridge-rs/bpf/pbridge.bpf.c`，在现有共享 ringbuf 之外添加 watchdog 专用状态和事件：

- 新增 array/hash 配置 map，保存 `watchdog_enabled` 与 pbridge 主进程 `self_tgid`；不要复用 datapath `config`，避免改变其已固定的 Rust `Cfg` ABI。
- 新增一个极小的事件结构，带 event kind 与触发者 TGID；沿用现有 `events` ringbuf，避免多一个 reader、fd 与停止协议。
- 新增 `SEC("kprobe/wlan_hdd_cfg80211_apf_offload")` 程序：当 watchdog 未启用或 `bpf_get_current_pid_tgid() >> 32 == self_tgid` 时直接返回；其余调用向 ringbuf 发 `ApfExternalWrite`。
- 声明 `bpf_get_current_pid_tgid` helper (14)；不读取函数参数、不依赖隐藏符号地址，故对 KASLR/模块符号地址为 0 的 Android 环境安全。
- 不在 probe 中尝试判定 APF 子命令：入口覆盖 legacy SET、APF 3.0 WRITE/READ、enable/disable；userspace 通过 own-TGID 过滤本进程操作，外部调用一律做 debounce 后重打补丁。这也覆盖 NetworkStack 当前走 legacy SET、未来切换 WRITE 的情况。

### 3. Aya 加载与事件分流

修改 `pseudo-bridge-rs/src/backend/ebpf.rs`：

- 使用 Aya 0.13 已有的 `KProbe` API：load 后 `attach("wlan_hdd_cfg80211_apf_offload", 0)`；与 tc program 一同由 `Ebpf` 生命周期管理，backend teardown/drop 自动解绑。
- 取得当前进程 TGID（`std::process::id()`），写入 watchdog config map，再 attach kprobe；启用顺序保证 probe 一旦生效即可过滤自己的事务。
- 扩展 ringbuf parser：保留现有固定 24-byte `Learn`/`ArpRequest` ABI，按 event kind 解析 watchdog 的新事件；用明确的版本/kind 区分，避免把旧 copy event 误当 APF 事件。
- 新增 `CopyEvent::ApfExternalWrite`（或将 enum 改名为更广义的 `KernelEvent`）；为 watchdog 事件设独立有界 Tokio channel，不能共用 copy 学习队列。数据路径 ringbuf 满时可以丢 learn，但 APF 覆盖事件必须保证重试/合并：reader 对该类事件使用非阻塞"已通知"标志或单槽容量通道；满时记录一次待处理，而不是无限丢弃。
- 将 watchdog 初始化从 `EbpfBackend::init()` 显式传入配置；没有 CLI guest 地址时，不创建 watchdog map 内容、不 load/attach KProbe，保持当前 eBPF session 的行为与 BPF 权限需求不变。

### 4. 内置 Qualcomm nl80211 vendor-netlink（不执行 lpc_ctl）

在新模块 `pseudo-bridge-rs/src/apf.rs` 实现 APF work-memory 读写客户机，复用 crate 已有 `netlink-sys` / `netlink-packet-core` 依赖链但不依赖外部 CLI：

- 建立 `NETLINK_GENERIC` socket，向 `GENL_ID_CTRL` 解析 `nl80211` family id；发送 `NL80211_CMD_VENDOR`。
- 将 `NL80211_ATTR_IFINDEX`、QCA vendor id `0x001374`、vendor subcommand `83` 和带 `NLA_F_NESTED` 的 `NL80211_ATTR_VENDOR_DATA` 编码为安全的 `Vec<u8>` TLV；不得使用 shell、`iw`、`bpftool` 或 `/data/local/tmp/lpc_ctl`。
- 实现 QCA APF 子命令：`DISABLE=6`、`WRITE=3`、`READ=4`、`ENABLE=5`；属性为 `SUBCMD=1`、`SIZE=4`、`CURRENT_OFFSET=5`、`PROGRAM=6`、`PROG_LENGTH=7`。
- `read_work_memory(ifindex, length)` 发送 READ 并从 reply 的 nested `APF_PROGRAM` 二进制属性提取完整 payload；`write_work_memory(ifindex, program)` 发送 WRITE，携带完整 `PROG_LENGTH`、offset 0 和程序 bytes。第一版仅支持程序小于驱动 `MAX_APF_MEMORY_LEN=4096` 的单消息写入；APF RAM 是 2048 bytes，满足该条件。
- API 设计为阻塞小操作，由 Core 的 async actor 直接调用；所有 Netlink ACK、NLMSG_ERROR、TLV 长度/对齐、缺属性、截断 reply 都返回带上下文的错误。
- 以 RAII guard/显式 finally 结构保证：只要成功发出 disable，所有成功、错误和 Tokio signal/shutdown 分支都会尽力发 enable。禁止 APF 以 disabled 状态遗留。

### 5. 现场程序来源、补丁器与重装事务

在 `src/apf.rs` 实现不依赖 `dumpsys network_stack` 的固件真相流程：

- 在 disabled 状态使用 READ 读取完整 2048-byte work memory；从头解析 APFv6 指令，定位 `DROPPED_ICMP_ECHO` 模式（IPv4 proto==1、ICMP type==8、紧接的 `drop counter=21`）。
- 不能直接把整块 2048 bytes 当 program length。读到的是 work memory，长度须由 APF 指令 walk + `debugbuf` 保留边界推导，或通过解析有效 program 末尾/计算 `program_len + debugbuf_size` 常量求得；对无效、歧义、多个候选 site 和不符合当前已验证 vendor 模式的程序安全失败，不写任何内容。
- 插入序列：一条 `ldw r0,[30]`，随后按 guest 地址排序的至多 8 条 `jeq r0,<guest>,PASS`。总插入量为 `2 + 9*N` bytes；N=8 时为 74 bytes。保留/复用 `apf_patch.py` 的已验证算法规则：所有满足 `end <= insertion_point <= target` 的正向跳转立即数加 delta；debugbuf 减 delta；任何跳转字段溢出、debugbuf 空间不足、最终 program 超过 APF RAM，均拒绝写入。
- 事务：`disable -> read stock work memory -> parse/patch -> static structural validation -> write -> read same patched length -> byte-for-byte compare -> enable`。
- 事务开始前 debounce 事件（例如 150–250 ms），合并 NetworkStack 一次逻辑更新触发的多次 APF vendor command；事务结束后若期间有新的 external-write 标志，立刻再运行一次，最多有限次数，之后带退避重试。
- APF 不可用、当前程序没有目标 drop、补丁容量不足或 readback 不一致时：记录错误，保持/恢复 APF enable，不将未验证内容投入运行；通过指数退避重试下一次外部写事件或定时恢复检查。

### 6. Core 集成、并发与生命周期

修改 `pseudo-bridge-rs/src/core.rs` 和 `src/backend/mod.rs`：

- 将 APF watcher 事件作为第四类控制面事件接入现有单线程 `tokio::select!` actor；该 actor 已是唯一控制面 writer，避免与 link reconciliation、entry mutation 和 teardown 并发执行。
- `init_session()` 在 eBPF backend 与 up0 ifindex 均就绪后初始化 watchdog；此时才允许 BPF probe events 进入 Core。`teardown_session()` 先停止/禁用 watchdog，再 drop backend，避免 session 销毁时触发一次尾随重装。
- 事件只在 session initialized、engine=ebpf、watchdog guest list 非空时处理；up0 消失、kprobe reader 停止或 session teardown 时取消 pending retry。
- **cold-start discovery**：watchdog guest 是显式 IPv4、但不含 MAC，不能把它们伪造预填到 `ip2mac`。在 backend hooks 已挂载、guest-facing bridge 已 ready 后，立即向每个尚未 learned 的 watchdog guest 注入 RFC 5227 匿名 ARP probe（`spa=0.0.0.0`）；guest 的真实 defense/reply 经普通 OUT path 建立 authoritative `(IP, MAC)` binding。前 5 秒每秒重试，之后仅每 30 秒重试，learn 后自动停止并交给既有 aging probe；绝不扫描非 CLI 指定地址。
- 不从 pbridge 的动态 guest `entries` 推导 APF 放行列表：第一版仅使用显式 CLI IPv4 列表，避免 aging/学习变化反复重建 APF，也确保用户可以明确控制扩大 ICMP 输入面的地址集合。
- 记录清晰的 INFO/DEBUG 日志：外部 APF 写入 TGID、debounce、stock/patch lengths、guest 数、readback hash 或长度、成功/失败/重试原因；绝不打印完整二进制程序。

### 7. 文档与测试

更新 `pseudo-bridge-rs/ARCHITECTURE.md`、`pseudo-bridge-rs/README.md`（如 CLI 表所在处）和 `apf/APF_WATCHDOG_DESIGN.md`：

- 明确 watchdog 仅为 `-e ebpf --apf-watchdog-guest ...` 的显式选项；支持最多 8 个固定 IPv4。
- 更正此前"NetworkStack 的 installPacketFilter 走 WRITE"的不严谨表述：kprobe 实测它触发 `wlan_hdd_cfg80211_apf_offload`，未触发 `wmi_send_apf_write_work_memory_cmd_tlv`，因此当前走 legacy SET；不过 APF 3.0 work-memory READ/WRITE 能读写相同的最终程序内存并可用于验证。
- 说明 own-TGID 过滤、debounce、readback compare 和 APF enable cleanup 的安全模型与限制。

## Verification

### 1. Rust 单元测试

- CLI：空值关闭、重复地址去重/拒绝策略、IPv6 拒绝、8 地址接受、第 9 地址拒绝、nft engine + watchdog 拒绝。
- APF TLV：对齐、nested vendor data、READ reply 解析、NLMSG_ERROR/截断/未知属性拒绝。
- APF walker/patcher：用现有 `apf/programs/apf-current.orig.bin` 与 `apf-guest.bin` 逐字节复现单地址历史补丁；对当前现场 captured program 覆盖 1/8 个地址；验证 `end == insertion point` 的 jump fix-up、PASS/DROP target、debugbuf 缩小、无空间/溢出/多候选安全失败。
- ring event parser：旧 Learn/ArpRequest 兼容、新 ApfExternalWrite、坏长度拒绝；own-TGID 的 BPF 逻辑以纯结构/常量测试补充。

### 2. 构建与对象检查

- `cargo test`、`./build.sh host`、`./build.sh arm64`；确认 BPF object 中同时存在 tc sections 与 kprobe section，Aya 仍可解析 object。
- 确认未新增外部命令执行；grep/审阅不得出现 `Command::new` 用于 CLI 工具。

### 3. 设备正控制与自激排除

在设备 `b784178b`（root / `u:r:ksu:s0`）上：

- 使用 `-e ebpf -m fwd-with-offload --apf-watchdog-guest 192.168.1.204` 启动 pbridge；确认 Aya attach 到 `wlan_hdd_cfg80211_apf_offload`，且 BPF ringbuf reader 工作。
- 用外部 `dumpsys deviceidle force-idle` 触发 NetworkStack legacy SET；确认 pbridge 在 debounce 后一次完成 write/readback compare，Linux -> guest ping 恢复 `5/5`，Linux -> phone 仍 `0/3`。
- 检查 pbridge 自己的 `disable/write/read/enable` 调用不产生重装循环：日志每次外部重装至多对应一次成功事务（除非实测到竞争重装），CPU/日志不持续增长。
- 启动时设定 2–8 个测试 IP（可使用 netns guest 地址），离线比对每个地址的 echo request 被 pass、未列地址和 phone IP 仍由 counter 21 drop；如果 APF 仅剩 debugbuf 不足容纳 8 条，验证 pbridge 拒绝写且保持 APF enabled。
- 在 write/read 中发送 SIGINT/SIGTERM；确认 finally 重新 enable，随后 stock/NetworkStack APF 可继续工作。
- 断开/重连 wlan0 或停止 pbridge；确认 kprobe/TC programs 随 Ebpf drop 自动解绑，没有残留 pbridge BPF object、路由或 disabled APF。

### 4. 回归测试

运行既有 `pseudo-bridge-rs` netns/Android eBPF 矩阵，确保 tc datapath、ringbuf learn、ARP proxy、aging 和 `fwd-with-offload` 不回归。

## Implementation Status

- [x] CLI: `--apf-watchdog-guest` parser and validation
- [x] BPF: kprobe program, watchdog config map, ringbuf event
- [x] Aya: KProbe load/attach, ringbuf parser extension
- [x] APF: nl80211 vendor netlink client (GENL socket, TLV encode/decode)
- [x] APF: READ/WRITE/ENABLE/DISABLE operations
- [x] APF: program walker, ICMP drop site locator
- [x] APF: multi-guest patcher with jump fixup and debugbuf adjust
- [x] APF: transaction with readback compare and enable cleanup
- [x] Core: watchdog event channel and debounce logic
- [x] Core: init/teardown lifecycle integration
- [x] Core: explicit-guest cold-start ARP discovery
- [x] Tests: CLI unit tests
- [x] Tests: APF TLV and patcher unit tests
- [ ] Tests: device validation (正控制 + 自激排除)
- [ ] Tests: regression matrix
- [x] Docs: ARCHITECTURE.md, README.md, APF_WATCHDOG_DESIGN.md updates
