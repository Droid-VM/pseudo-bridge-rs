# pbridge Android 实机测试记录

本文记录方案 2（删除 guest `/32` 的 local route，由 pbridge 代理 ARP）的 Android
实机验证。测试使用临时 Linux network namespace 模拟一个 guest，不会修改 guest
系统或 Wi-Fi 固件配置。

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

## 结论和限制

本次实机测试确认方案 2 在 Android 17（API 37）userspace、`android15-8` GKI 6.6
arm64 内核上可工作：guest 出网、host -> guest、ARP 代理、guest MAC 隐藏和 10 秒
keepalive 均通过。

本次使用临时 netns 代替真实 pKVM guest，因此尚未覆盖真实 VM 的 DHCP、IPv6 SLAAC
和多 guest 并发；这些路径已由项目的 netns 自动化测试覆盖。真实设备上若启用
`--offload-workaround v4,v6`，还应额外验证 APF/ND offload 和 proxy 地址的生命周期。
