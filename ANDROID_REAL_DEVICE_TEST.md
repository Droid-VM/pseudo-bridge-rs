# pbridge Android 实机测试记录

本文记录方案 2（删除 guest `/32` 的 local route，由 pbridge 代理 ARP，并回填 host
邻居）的 Android 实机验证。测试使用临时 Linux network namespace 模拟一个 guest，
不会修改 guest 系统或 Wi-Fi 固件配置。

## 测试环境

| 项目 | 值 |
| --- | --- |
| 测试日期 | 2026-09-01 |
| adb serial | `b784178b` |
| 设备型号 | `M332BF` / `warsaw` |
| Android | `17`，API `37` |
| 内核 | `6.6.118-android15-8`，`aarch64` |
| adb shell 身份 | root，SELinux domain `u:r:ksu:s0` |
| 上游接口 | `wlan0` |
| 上游地址 | `192.168.1.39/24` |
| 上游 HOSTMAC | `e2:ec:48:c1:e3:79` |
| 网关 | `192.168.1.1`，MAC `20:b8:3d:bf:75:e6` |

## 构建和部署

在主机执行：

```sh
cd pseudo-bridge-rs
./build.sh arm64
adb push dist/pbridge-android-arm64 /data/local/tmp/pbridge
adb shell chmod 755 /data/local/tmp/pbridge
```

产物为 4.0 MiB 的 aarch64 静态 ELF。设备上执行版本和启动检查：

```sh
adb shell /data/local/tmp/pbridge --version
adb shell 'RUST_LOG=debug nohup /data/local/tmp/pbridge \
  -i wlan0 -e ebpf -m fwd --arp-keepalive 10 \
  >/data/local/tmp/pbridge.log 2>&1 </dev/null &'
```

实机日志确认：

```text
pbridge start: if=wlan0 engine=Ebpf mode=Fwd ... arp-keepalive=10s
up0 present -> init session
ebpf backend running
```

这证明设备上的 eBPF 加载、TC hook 和 Rust 控制面均能正常启动。

## 临时测试拓扑

测试过程中创建以下链路：

```text
gateway 192.168.1.1
    |
  wlan0 (192.168.1.39, HOSTMAC=e2:ec:48:c1:e3:79)
    |
  pbridge: wlan0-if <-> wlan0-br
                         |
                       vmbr
                         |
              veth pbv-host <-> pbguest:eth0
                                  192.168.1.200
                                  MAC=62:b7:32:82:ea:7b
```

`wlan0-br` 由 pbridge 创建，`vmbr` 和 `pbguest` 是测试脚本创建的临时对象。由于
本次没有使用 `--bridge`，测试脚本在 hook 启动后手动执行：

```sh
ip link add vmbr type bridge
ip link set vmbr up
ip link set wlan0-br master vmbr
ip netns add pbguest
ip link add pbv-host type veth peer name pbv-guest
ip link set pbv-host master vmbr
ip link set pbv-host up
ip link set pbv-guest netns pbguest
ip -n pbguest link set pbv-guest name eth0
ip -n pbguest link set eth0 up
ip -n pbguest addr add 192.168.1.200/24 dev eth0
ip -n pbguest route add default via 192.168.1.1 dev eth0
```

## 测试结果

### 1. eBPF 初始化

通过。设备日志出现 `ebpf backend running`，没有 `bpf()`、BTF、TCX 或 verifier
错误。

### 2. guest -> 网关

```sh
adb shell 'ip netns exec pbguest ping -c 3 -W 2 192.168.1.1'
```

结果：3/3 成功，0% 丢包。

上游 `wlan0` 抓包显示：

```text
e2:ec:48:c1:e3:79 > ff:ff:ff:ff:ff:ff  ARP Request who-has 192.168.1.1 tell 192.168.1.200
e2:ec:48:c1:e3:79 > 20:b8:3d:bf:75:e6  IPv4 192.168.1.200 > 192.168.1.1 ICMP echo request
20:b8:3d:bf:75:e6 > e2:ec:48:c1:e3:79  IPv4 192.168.1.1 > 192.168.1.200 ICMP echo reply
```

上游看到的源 MAC 始终是手机的 `HOSTMAC`，没有出现 guest MAC
`62:b7:32:82:ea:7b`。

### 3. guest -> 外网

```sh
adb shell 'ip netns exec pbguest ping -c 3 -W 3 1.1.1.1'
```

结果：3/3 成功，0% 丢包，平均延迟约 86 ms。

### 4. pbridge 代理 ARP

网关重新解析 guest 地址时，`wlan0` 抓到 request，pbridge 日志出现：

```text
vmroute add 192.168.1.200 -> 62:b7:32:82:ea:7b [route /32@table200]
arp-proxy: 192.168.1.200 is-at e2:ec:48:c1:e3:79 -> 192.168.1.1 (20:b8:3d:bf:75:e6)
```

抓包同时看到：

```text
20:b8:3d:bf:75:e6 > e2:ec:48:c1:e3:79  ARP Request who-has 192.168.1.200 tell 192.168.1.1
e2:ec:48:c1:e3:79 > 20:b8:3d:bf:75:e6  ARP Reply 192.168.1.200 is-at e2:ec:48:c1:e3:79
```

这验证了删除 local route 后，已安装 guest 的 ARP request 可以由 pbridge 直接代答。

### 5. host -> guest

```sh
adb shell 'ip route get 192.168.1.200; ping -c 3 -W 2 192.168.1.200'
```

结果：

```text
192.168.1.200 dev vmbr table 200 src 192.168.1.39
3 packets transmitted, 3 received, 0% packet loss
```

同时确认 `table local` 中没有 `192.168.1.200`，说明 guest `/32` local route 没有
重新出现，host -> guest 确实走 pbridge 的 `table 200` 路由。

### 6. ARP keepalive

日志每 10 秒出现一次：

```text
arp-keepalive: 1 guest + 1 host v4 x 2 neighbours
```

说明 `--arp-keepalive 10` 已生效。它仍然需要保留，用来规避 APF/firmware 在数据包
到达 `wlan0` 之前丢弃 ARP request 的情况；软件代理无法处理这种前置丢包。

## 关闭 keepalive 的对照测试

同一设备上重新启动 pbridge，明确关闭 keepalive：

```sh
RUST_LOG=debug /data/local/tmp/pbridge -i wlan0 -e ebpf -m fwd \
  --arp-keepalive 0 --timeout 30
```

使用新的 guest 地址 `192.168.1.201` 测试，结果如下：

- guest -> 网关首次 ping：3/3 成功；
- guest -> `1.1.1.1`：首次解析阶段出现 1 个丢包，随后收到 2 个回复；
- 网关重新 ARP `192.168.1.201` 时，pbridge 仍输出 `arp-proxy`，代理回复成功；
- 约 40 秒无 guest 流量后，默认 `--timeout 30` 老化学习项：
  `vmroute del 192.168.1.201 (expired/evicted)`；
- 老化后 host -> guest 的首个 ping 包出现一次 `Destination Host Unreachable`，
  随后的包在 guest 重新发包并触发学习后恢复。

关闭 keepalive 时日志中的启动参数为 `arp-keepalive=0s`，且整个静默窗口没有
`arp-keepalive:` 周期日志。这个对照说明：软件代理可以处理已经到达 `wlan0` 的
ARP request，但不能替代 keepalive 解决 Wi-Fi APF/firmware 在 `wlan0` 之前丢包的
情况；同时 guest 长时间静默时仍受正常的 `--timeout` 学习项老化机制影响。本轮
抓包中的网关 ARP request 都到达了 `wlan0`，因此没有把 APF 的前置丢包当作本轮已
复现；要验证该分支需要在设备省电状态下让真实外部 peer 的邻居项过期后再次解析。

需要注意：`--arp-keepalive` 和 `--timeout` 维护的是两个不同的状态。前者通过
`wlan0` 上的 AF_PACKET 报文刷新上游网关/邻居缓存；普通 `fwd` 模式下这些报文不会
经过 guest-facing 的 `fwd0` ingress，因此不会刷新 pbridge 自身的 guest `seen` 项。
完全静默的 guest 仍会在 `--timeout` 到期后被移除。guest 再发一个 ARP/IP 包可以
重新学习并恢复，但恢复前的第一个 host/peer 包可能已经丢失。

## Doze/APF 前置过滤的决定性对照

为确认 host -> guest 的首包失败是否来自 APF，在同一台设备上执行了直接 adb 对照。
测试前保持 guest `192.168.1.204` 已被 pbridge 学习，关闭 `--arp-keepalive`，并执行：

```sh
adb shell 'dumpsys deviceidle force-idle'
ip neigh del 192.168.1.204 dev eth0
ping -I eth0 -c 5 -W 2 192.168.1.204
```

APF 启用时结果为 `0/5`，主机输出 `Destination Host Unreachable`。此时 APF 计数
`DROPPED_ARP_OTHER_HOST` 从 92 增加到 99，pbridge 日志没有新的 `arp-proxy`，说明
ARP request 在到达 `wlan0`/pbridge 之前已经被 APF/固件丢弃。

随后只执行：

```sh
adb shell '/data/local/tmp/lpc_ctl.apf.final wlan0 apf-disable'
ip neigh del 192.168.1.204 dev eth0
ping -I eth0 -c 5 -W 2 192.168.1.204
```

结果恢复为 `5/5`，pbridge 日志出现：

```text
arp-proxy: 192.168.1.204 is-at e2:ec:48:c1:e3:79 -> 192.168.1.114
```

这次对照确认实际故障点是 APF/固件的 `DROPPED_ARP_OTHER_HOST`，不是
`DROPPED_ICMP_ECHO`。因此只在 `DROPPED_ICMP_ECHO` 前加入放行条件不能修复该首包
问题；要么让 APF 生成器对已安装的 guest `/32` 放行 ARP request，要么保留
`--arp-keepalive 10`，从出向刷新上游邻居，避免设备在 Doze 中收到该 ARP request。

> 注：这段结论只对当时那个 `mIPv4Address` 非 null 的程序成立。改用
> `-m fwd-with-offload` 后 `wlan0` 上出现 guest 的 `/32`，`mIPv4Address` 变成
> null，ARP request 分支变为无条件 pass，此时唯一的丢包点就是
> `DROPPED_ICMP_ECHO`。见下面的“替换 APF 程序复测（2026-09-01 晚）”。

测试结束后执行 `adb shell 'cmd deviceidle unforce'`，并重新启用 APF。

## 清理和恢复

测试结束发送 SIGINT，pbridge 自动撤销 hook、路由和 mirror；然后删除临时对象：

```sh
adb shell 'kill -INT $(pidof pbridge) 2>/dev/null || true; sleep 2
ip netns del pbguest 2>/dev/null || true
ip link del pbv-host 2>/dev/null || true
ip link del vmbr 2>/dev/null || true'
```

清理后确认：

- pbridge 进程不存在；
- `wlan0-if`、`wlan0-br`、`vmbr` 和 `pbguest` 均已删除；
- `ip route show table 200` 为空，pbridge 的 rule 已撤销；
- `wlan0` 仍为 `192.168.1.39/24`，原有 Wi-Fi 连接未改变。

## aging probe 版本的直接 adb 验证

在完成“老化前主动 ARP/NS probe，收到 guest 回复则保留、无回复才删除”后，使用同一台
设备直接运行新构建产物（不运行测试套件），并临时创建一个 veth guest 接入 `vmbr`：

```sh
./build.sh arm64
adb -s b784178b push dist/pbridge-android-arm64 /data/local/tmp/pbridge-new
adb -s b784178b shell chmod 755 /data/local/tmp/pbridge-new
adb -s b784178b shell 'RUST_LOG=debug nohup /data/local/tmp/pbridge-new \
  -i wlan0 -e ebpf -m fwd --timeout 4 --arp-keepalive 0 \
  >/data/local/tmp/pbridge-new.log 2>&1 </dev/null & p=$!; \
  sleep 5; kill -INT "$p"; sleep 2; cat /data/local/tmp/pbridge-new.log'
```

结果：

- `pbridge 0.1.0` 可执行，aarch64 静态 ELF 在设备上正常运行；
- Android `6.6.118-android15-8` 内核完成 BTF/TC eBPF 装载，日志出现
  `ebpf backend running`；
- guest `192.168.1.200` 到真实网关 `192.168.1.1` ping 为 `1/1`，并成功学习为
  `vmroute /32@table200`；
- guest 侧抓包实际看到匿名 probe 和回复：

  ```text
  e2:ec:48:c1:e3:79 > ff:ff:ff:ff:ff:ff  ARP Request who-has 192.168.1.200 tell 0.0.0.0
  be:a1:43:e4:04:d1 > e2:ec:48:c1:e3:79  ARP Reply 192.168.1.200 is-at be:a1:43:e4:04:d1
  e2:ec:48:c1:e3:79 > 33:33:ff:e4:04:d1  :: > ff02::1:ffe4:4d1  Neighbor Solicitation
  be:a1:43:e4:04:d1 > 33:33:00:00:00:01  Neighbor Advertisement
  ```

  IPv4 的 `tell 0.0.0.0` 和 IPv6 的 `src=::` 说明 probe 没有把 host 地址写入 guest
  的邻居缓存；对应 ARP/NA 回复已从 guest 返回到 pbridge OUT 路径。
- `SIGINT` 后正常执行 `teardown`，没有残留 `pbridge-new` 进程或 `wlan0-if`；
- 测试结束已删除临时 `pbguest`、veth 和 `vmbr`，设备 Wi-Fi 接口恢复原状。

## adb 临时 VM 端到端验证

本次没有运行测试套件，直接在 `b784178b` 上创建临时 `pbguest2` network namespace、
`pbv2-host/pbv2-guest` veth 和 `pbvmbr2` bridge，启动：

```sh
/data/local/tmp/pbridge-new -i wlan0 -e ebpf -m fwd -b pbvmbr2 \
  --timeout 6 --arp-keepalive 0
```

guest 使用 `192.168.1.201/24`，MAC 为 `da:bd:4a:ea:74:21`。实测结果：

1. guest -> 真实网关 `192.168.1.1`：`2/2` 成功，pbridge 日志出现
   `vmroute add 192.168.1.201`。
2. guest 侧抓包看到老化探测及回复：

   ```text
   e2:ec:48:c1:e3:79 > ff:ff:ff:ff:ff:ff  ARP Request who-has 192.168.1.201 tell 0.0.0.0
   da:bd:4a:ea:74:21 > e2:ec:48:c1:e3:79  ARP Reply 192.168.1.201 is-at da:bd:4a:ea:74:21
   e2:ec:48:c1:e3:79 > 33:33:ff:e4:04:d1  :: > ff02::1:ffe4:4d1  Neighbor Solicitation
   da:bd:4a:ea:74:21 > 33:33:00:00:00:01  Neighbor Advertisement
   ```

   说明 guest 收到了 IPv4 ACD probe、IPv6 DAD-style NS，并通过 ARP/NA 回复刷新存活
   状态。
3. 删除 guest 的 `192.168.1.201` 地址并保持静默约 8 秒后，日志出现
   `vmroute del 192.168.1.201 (expired/evicted)`，`table 200` 中不再有该路由。
4. 重新加回地址后，guest 再 ping 网关 `2/2` 成功，日志再次出现 `vmroute add`；随后
   Android host 执行 `ip route get 192.168.1.201` 显示走 `pbvmbr2 table 200`，
   host -> guest ping `3/3` 成功。

验证结束已停止 pbridge，并删除 `pbguest2`、veth、`pbvmbr2`；无残留 pbridge 进程、
临时接口或 guest 路由。

## 验证 ARP 代答是否依赖 host -> guest 首包

为排除真实网关邻居缓存影响，另外在同一设备上创建了隔离的模拟上游 `pbgw`（
`10.77.0.1`）和模拟 VM `pbguest3`（`10.77.0.201`），pbridge 的 `up0` 使用临时
`pbup0` veth。流程中没有执行 host -> guest ping：

1. 仅由 guest -> `10.77.0.1` ping `2/2`，学习 `10.77.0.201`，日志出现
   `vmroute add 10.77.0.201`。
2. 删除 guest 的 `10.77.0.201` 地址，使 guest 不可能自己回复 ARP；清空模拟上游的
   邻居项。
3. 直接由 `pbgw` ping `10.77.0.201`。ICMP 没有回复是预期的，因为 guest 地址已删除，
   但 pbridge 日志出现：

   ```text
   arp-proxy: 10.77.0.201 is-at 1e:f6:27:c5:30:40 -> 10.77.0.1 (82:5f:6d:51:f5:03)
   ```

   同时 `pbgw` 邻居表为：

   ```text
   10.77.0.201 lladdr 1e:f6:27:c5:30:40 STALE
   ```

结论：pbridge 代答 ARP 只需要 guest IP 已经存在于 `installed/ip2mac` 学习表，并不
需要先发 host -> guest 首包。guest 尚未被学习时，discovery probe 会先触发学习；
加入 host 邻居回填后，host 首包也可在学习完成后直接送入 guest。

## host 首包实测（先 host ping guest，已加入邻居回填）

为验证 host 首包，创建新的临时 `pbguest-neigh/pbvmbr-neigh`，guest 只配置
`192.168.1.203/24`，不先发送 IPv4 流量。清空 host 两侧邻居项后，pbridge 启动后
直接在 Android host 执行：

```sh
ip neigh del 192.168.1.203 dev wlan0 2>/dev/null || true
ip neigh del 192.168.1.203 dev pbvmbr-neigh 2>/dev/null || true
ping -c 1 -W 3 192.168.1.203
```

结果为 `1 packets transmitted, 1 received, 0% packet loss`。guest 抓包同时显示
pbridge 已克隆匿名 ARP probe，guest 也已经回复：

```text
e2:ec:48:c1:e3:79 > ff:ff:ff:ff:ff:ff  who-has 192.168.1.203 tell 0.0.0.0
02:aa:bb:cc:dd:03 > e2:ec:48:c1:e3:79  192.168.1.203 is-at 02:aa:bb:cc:dd:03
```

此时 pbridge 日志出现 `vmroute add 192.168.1.203`，host 邻居项为：

```text
wlan0        192.168.1.203 lladdr e2:ec:48:c1:e3:79 REACHABLE
pbvmbr-neigh 192.168.1.203 lladdr 02:aa:bb:cc:dd:03 REACHABLE
```

没有出现 `arp-proxy` 日志是正常的，因为该 ARP 是 host 出向请求，不是从 `wlan0`
入向的 ARP。结论是：host 侧邻居回填配合 up0 egress demux 可以让 guest 尚未有
IPv4 流量时的 host 首包直接成功；上游入向 ARP 代答仍用于外部 peer 解析已学习的
guest，`--arp-keepalive 10` 仍用于规避 APF/firmware 前置丢包。验证结束后已清理
临时 guest、veth、bridge、pbridge 进程和路由。

## 开发机 Linux -> 安卓模拟 guest

为验证真实外部 Linux 主机而不是 Android host 自身，使用开发机
`192.168.1.114/24`，安卓 `wlan0=192.168.1.39/24`，并在安卓上创建临时
`pbguest-linux` netns：

```text
guest IPv4 = 192.168.1.204/24
guest MAC  = 02:aa:bb:cc:dd:04
bridge     = pbvmbr-linux
```

pbridge 启动参数为 `-i wlan0 -e ebpf -m fwd -b pbvmbr-linux --timeout 30
--arp-keepalive 0`。先不让 guest 发 IPv4 流量，清空开发机邻居项后直接执行：

```sh
ip neigh del 192.168.1.204 dev eth0 2>/dev/null || true
ping -c 3 -W 3 192.168.1.204
```

结果为 `3/3` 超时并显示 `Destination Host Unreachable`。安卓 `wlan0` 抓包、
`ip monitor neigh` 和 pbridge 日志均没有看到这次 ARP request，说明该 WLAN/APF
在报文到达 `wlan0` ingress 之前就过滤了“尚未学习的 guest 地址”。因此软件 ARP
代答没有机会执行；host 侧邻居回填也只能填充安卓内核的 `wlan0`/bridge 邻居，不能
直接写入远端 Linux 的邻居缓存。

随后让 guest 主动 ping 网关一次：

```sh
adb shell 'ip netns exec pbguest-linux ping -c 1 -W 3 192.168.1.1'
```

pbridge 学习并写入：

```text
vmroute add 192.168.1.204 -> 02:aa:bb:cc:dd:04 [route /32@table200]
wlan0        192.168.1.204 -> e2:ec:48:c1:e3:79 REACHABLE
pbvmbr-linux 192.168.1.204 -> 02:aa:bb:cc:dd:04 REACHABLE
```

此后开发机 Linux 直接执行 `ping -c 3 -W 2 192.168.1.204`，实测一次为
`3/3` 成功，证明已学习后的 host 邻居回填、up0 egress demux、guest-facing
转发和返回路径均可工作。再次删除开发机邻居并重复 ARP 时，因 WLAN 客户端隔离
而可能重新得到 `FAILED`；这不是 pbridge 数据转发失败，而是外部 ARP 没有进入
安卓软件路径。

使用 `--arp-keepalive 10` 的对照运行中，日志每 10 秒出现 keepalive，每 30 秒
出现一次 GARP；它能保持网关等已知邻居，但本次 WLAN 不会把 GARP/ARP 转发给开发机，
所以不能绕过该客户端隔离。对于允许客户端间 ARP 的网络，入向 ARP request 到达
`wlan0` 后，pbridge 的 `arp-proxy` 会以 HOSTMAC 代答；在本机实测的前置过滤场景
下仍应保留 `--arp-keepalive 10`，以避免网关主动重新解析 guest。

本次实机测试确认方案 2 在 Android 17（API 37）userspace、`android15-8` GKI 6.6
arm64 内核上可工作：guest 出网、host -> guest、ARP 代理、guest MAC 隐藏和 10 秒
keepalive 均通过。

## 替换 APF 程序复测（2026-09-01 晚）

按 `apf/README.md` 重跑 “替换 APF 程序 + pbridge，Linux -> 模拟 VM”。设备沿用上一轮
仍在运行的会话，没有重建拓扑：

```text
pbridge  -i wlan0 -e ebpf -m fwd-with-offload -b pbvmbr --arp-keepalive 10 --timeout 60
guest    netns pbtestns，pbg-guest 192.168.1.204/24，MAC 02:aa:bb:cc:dd:04
上游     wlan0 192.168.1.39/24，HOSTMAC e2:ec:48:c1:e3:79
开发机   Linux 192.168.1.114（eth0，同一 L2）
```

复测起点：guest -> 网关 `192.168.1.1` `2/2` 成功，`table 200` 里有
`192.168.1.204 dev pbvmbr`，pbridge 日志有
`vmroute add 192.168.1.204 -> 02:aa:bb:cc:dd:04 [route /32@table200, proxy@up0]`。

### 1. 失败点不是 ARP，而是 ICMP echo

清空开发机邻居后 `ping -c 5 192.168.1.204` 得到 `0/5`，但计数器显示：

```text
DROPPED_ARP_OTHER_HOST: 941 -> 941     # 没有动
PASSED_ARP_REQUEST:    1054 -> 1055    # ARP request 放行了
DROPPED_ICMP_ECHO:        (新出现) 5   # 正好等于 5 个 ping
```

开发机邻居项也正常解析成
`192.168.1.204 lladdr e2:ec:48:c1:e3:79 REACHABLE`。所以 ARP 这一路是通的，
和本文上面 “Doze/APF 前置过滤的决定性对照” 一节的结论不同。原因是
`fwd-with-offload` 给 `wlan0` 加了 guest 的 `/32`，`wlan0` 上有两个 IPv4 地址，
`ApfFilter` 的 `mIPv4Address` 变成 null（`dumpsys` 显示 `IPv4 address: None`），
而 ARP request 丢弃分支只在 `mIPv4Address != null` 时才生成。

两个补充对照：

- 手机自己的 `192.168.1.39` 同样 `0/3`，说明这个 ICMP 丢弃与目的地址无关。
- `cmd deviceidle unforce` 之后 `doze: FALSE`，仍然 ping 不通，说明它不受 Doze
  门控。

同时确认 **Linux -> guest 的 TCP 一直可用**：在 guest netns 里
`toybox nc -L -p 9099 -s 192.168.1.204`，开发机 `/dev/tcp` 连上直接读到
`GUEST_TCP_OK`。pbridge 的转发路径没有问题。

### 2. 补丁后的实测结果

从设备现场抓当前程序，在 `drop counter=21`（`DROPPED_ICMP_ECHO`）之前插入
`ldw r0,[30]` + `jeq r0, 192.168.1.204, PASS`，用
`apf/tools/apf_live_test.sh` 交替安装两轮：

| 安装的程序 | Linux -> guest | Linux -> 手机 | `DROPPED_ICMP_ECHO` |
| --- | --- | --- | --- |
| 原始 996 bytes | `0/5` | `0/3` | +8 |
| 补丁 1007 bytes | `5/5` | `0/3` | +3 |
| 原始 996 bytes | `0/5` | `0/3` | +8 |
| 补丁 1007 bytes | `5/5` | `0/3` | +3 |

用完全相同的 `apf-disable`/`apf-set`/`apf-enable` 流程装未打补丁的程序仍是 `0/5`，
因此恢复连通的是补丁内容，不是 disable/enable 动作。补丁生效期间 guest 的 TCP
仍然正常（`GUEST_TCP_OK`），ping 也稳定在 `3/3`。

### 3. 覆盖寿命

`APF_PROGRAM_ID` 写死在程序里，可用来判断固件跑的是谁的程序：

- 静置 2 分钟以上 ID 停在 50，ping 持续 `2/2`；
- 一次 `dumpsys deviceidle force-idle` 让 NetworkStack 重新生成
  （`Program updates 50 -> 51`），ping 立刻回到 `0/5`；
- 从新的 1001-byte 程序重新打补丁装上（1012 bytes），在 deep `IDLE`、
  `doze: TRUE` 下恢复 `5/5`，手机仍 `0/3`。

### 4. 复测后的状态

`cmd deviceidle unforce`，`apf-disable` + `apf-enable`，并触发一次 NetworkStack
重新生成，恢复到 stock 程序（`Program updates: 54`，996 bytes，
`Filter update status: RUNNING`）。此时 guest 和手机的 ping 都回到 `0/2`，
guest TCP 仍为 `GUEST_TCP_OK`。pbridge 进程、`pbtestns`、`pbvmbr` 和
`table 200` 全部保持复测前的状态，没有拆除。

证据在 `apf/evidence/`：`apf-icmp.*` 和 `apf-doze.*`（现场程序、补丁程序及各自
反汇编）、`ctrs-*-{before,after}.txt`、`ping-*.txt`。

本次使用临时 netns 代替真实 pKVM guest，因此尚未覆盖真实 VM 的 DHCP、IPv6 SLAAC
和多 guest 并发；这些路径已由项目的 netns 自动化测试覆盖。真实设备上若启用
`--offload-workaround v4,v6`，还应额外验证 APF/ND offload 和 proxy 地址的生命周期。
