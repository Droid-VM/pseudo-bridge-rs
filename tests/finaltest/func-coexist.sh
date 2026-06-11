#!/usr/bin/env bash
# Functional coexistence tests (PLAN req 2 & 3): bridge rename/re-point, and
# host/VM IP & MAC changes — both non-conflicting and conflicting. On conflict
# the rule is "host connectivity wins": the colliding guest entry is disabled
# (enable=0) and its kernel artifacts (route + nft/ebpf map elem) are withdrawn
# by the reconciler; when the conflict clears the entry recovers.
#
# Topology (vtep) per scenario, rebuilt fresh so state is isolated:
#   ns up (gw/outside 10.0.0.1) ─ u0╌up0 ─┐
#   ns hostns: up0(host 10.0.0.2), br0, mtnat1╌mtnat1p(br0), gbr1(vm1), gbr2(vm2)
#   ns vm1 (10.0.0.5)  ns vm2 (10.0.0.6)   ┘
set -u
BIN="${BIN:-./target/debug/pbridge}"
ENGINES="${ENGINES:-userspace ebpf}"
GW=10.0.0.1; HOST=10.0.0.2; V1=10.0.0.5; V2=10.0.0.6
PBPID=""; PASS=0; TOTAL=0

netns_up() {
  for ns in up hostns vm1 vm2; do ip netns add $ns; done
  ip link add up0 netns hostns type veth peer name u0 netns up
  ip link add gbr1 netns hostns type veth peer name v1eth netns vm1
  ip link add gbr2 netns hostns type veth peer name v2eth netns vm2
  ip -n up addr add $GW/24 dev u0; ip -n up link set u0 up; ip -n up link set lo up
  ip -n hostns link add br0 type bridge
  ip -n hostns link set up0 up; ip -n hostns addr add $HOST/24 dev up0
  ip -n hostns link set gbr1 master br0; ip -n hostns link set gbr2 master br0
  ip -n hostns link set gbr1 up; ip -n hostns link set gbr2 up; ip -n hostns link set br0 up
  ip netns exec hostns sysctl -q net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 2>/dev/null
  ip -n vm1 addr add $V1/24 dev v1eth; ip -n vm1 link set v1eth up; ip -n vm1 link set lo up
  ip -n vm2 addr add $V2/24 dev v2eth; ip -n vm2 link set v2eth up; ip -n vm2 link set lo up
}
netns_down() {
  [ -n "$PBPID" ] && kill "$PBPID" 2>/dev/null; sleep 0.3; PBPID=""
  for ns in up hostns vm1 vm2; do ip netns del $ns 2>/dev/null; done
}
start_pb() {  # $1=engine ; pbridge creates mtnat1/mtnat1p (vtep) and enslaves to br0
  ip netns exec hostns "$BIN" --upstream up0 --fwd-device mtnat1 --bridge br0 \
     --l2nat-backend "$1" --entry-timeout 8 >/tmp/pb-coex.log 2>&1 &
  PBPID=$!
  for _ in $(seq 1 30); do grep -q 'backend running' /tmp/pb-coex.log && return 0; kill -0 "$PBPID" 2>/dev/null || break; sleep 1; done
  echo "    [x] pbridge did not start ($1)"; sed 's/^/      /' /tmp/pb-coex.log; return 1
}
# poll until cmd succeeds within $1s
until_ok(){ local end=$((SECONDS+$1)); shift; while :; do eval "$*" >/dev/null 2>&1 && return 0; [ $SECONDS -ge $end ] && return 1; sleep 1; done; }
# poll until cmd FAILS within $1s (confirms connectivity went down), then confirm it stays down
until_fail(){ local end=$((SECONDS+$1)); shift; while :; do if ! eval "$*" >/dev/null 2>&1; then sleep 1; eval "$*" >/dev/null 2>&1 || return 0; fi; [ $SECONDS -ge $end ] && return 1; sleep 1; done; }
# route in pbridge's dedicated host->VM table (200) for ip $1 via dev-pattern $2
route_has(){ ip -n hostns route show table 200 2>/dev/null | grep -qE "^$1 .*dev ${2:-\S+}"; }
# host->vm with a fresh ARP (clear stale neigh from before a change)
host2vm(){ ip -n hostns neigh flush all 2>/dev/null; ip netns exec hostns ping -c1 -W2 "$1"; }
chk(){ TOTAL=$((TOTAL+1)); if eval "$2"; then PASS=$((PASS+1)); else echo "    [x] $1"; fi; }

prime(){  # learn vm1+vm2 and host->vm routes
  until_ok 12 "ip netns exec vm1 ping -c1 -W2 $GW"
  until_ok 12 "ip netns exec vm2 ping -c1 -W2 $GW"
  until_ok 12 "ip netns exec hostns ping -c1 -W2 $V1"
}

scenario_bridge_rename(){ # req 2
  echo "  -- [$1] bridge rename (delete br0, new br1, rebind up/vtep+vms, ip/mac unchanged)"
  netns_up; start_pb "$1" || { netns_down; return; }; prime
  chk "pre: host->vm1"            "until_ok 6 'ip netns exec hostns ping -c1 -W2 $V1'"
  chk "pre: route .5 dev br0"     "route_has $V1 br0"
  # rename: detach everything from br0, delete it, make br1, re-attach (vm ip/mac unchanged)
  for l in mtnat1p gbr1 gbr2; do ip -n hostns link set $l nomaster; done
  ip -n hostns link del br0
  ip -n hostns link add br1 type bridge; ip -n hostns link set br1 up
  for l in mtnat1p gbr1 gbr2; do ip -n hostns link set $l master br1; ip -n hostns link set $l up; done
  chk "post: vm1->gw"             "until_ok 12 'ip netns exec vm1 ping -c1 -W2 $GW'"
  chk "post: host->vm1"           "until_ok 12 'ip netns exec hostns ping -c1 -W2 $V1'"
  chk "post: route re-pointed br1" "until_ok 12 'route_has $V1 br1'"
  chk "post: old br0 route gone"  "! route_has $V1 br0"
  netns_down
}

# conflict flow helper: normal -> conflict -> recover, centered on "vm reaches gw".
#   $1 label  $2 vm-netns  $3 vm-ip  "$4" make-conflict cmd  "$5" clear-conflict cmd
#   "$6" (optional) host-online cmd to assert host stays up during conflict
conflict_flow(){
  local lbl=$1 vmns=$2 vmip=$3 mk=$4 clr=$5 hostchk=${6:-}
  chk "$lbl: normal vm->gw"      "until_ok 12 'ip netns exec $vmns ping -c1 -W2 $GW'"
  eval "$mk"
  chk "$lbl: conflict -> vm loses external" "until_fail 14 'ip netns exec $vmns ping -c1 -W2 $GW'"
  [ -n "$hostchk" ] && chk "$lbl: host stays online" "until_ok 8 '$hostchk'"
  eval "$clr"
  chk "$lbl: cleared -> vm recovers" "until_ok 14 'ip netns exec $vmns ping -c1 -W2 $GW'"
}

scenario_host_ip(){ # req 3
  echo "  -- [$1] host IP change: non-conflict, then conflict(host takes vm1 IP)->recover"
  netns_up; start_pb "$1" || { netns_down; return; }; prime
  # non-conflict: 10.0.0.2 -> 10.0.0.3 ; vm + host both stay up
  ip -n hostns addr del $HOST/24 dev up0; ip -n hostns addr add 10.0.0.3/24 dev up0
  chk "nonconf: host(.3)->gw"     "until_ok 12 'ip netns exec hostns ping -c1 -W2 $GW'"
  chk "nonconf: vm1 unaffected"   "until_ok 12 'ip netns exec vm1 ping -c1 -W2 $GW'"
  chk "nonconf: host->vm1 ok"     "until_ok 12 'host2vm $V1'"
  # conflict: host ALSO takes vm1's IP (.5) -> vm1 loses external; host keeps it
  conflict_flow "host-ip" vm1 $V1 \
    "ip -n hostns addr add $V1/24 dev up0" \
    "ip -n hostns addr del $V1/24 dev up0" \
    "ip netns exec hostns ping -c1 -W2 $GW"
  netns_down
}

scenario_host_mac(){ # req 3 (HOSTMAC adopts a value colliding with vm1's mac)
  echo "  -- [$1] host MAC change: conflict(HOSTMAC := vm1 mac)->recover"
  netns_up; start_pb "$1" || { netns_down; return; }; prime
  local m1; m1=$(ip netns exec vm1 cat /sys/class/net/v1eth/address)
  conflict_flow "host-mac" vm1 $V1 \
    "ip -n hostns link set up0 address $m1" \
    "ip -n hostns link set up0 address 02:00:00:00:0c:01" \
    "ip netns exec hostns ping -c1 -W2 $GW"
  netns_down
}

scenario_vm_mac(){ # req 3
  echo "  -- [$1] vm1 MAC change (non-conflict): connectivity continues on new mac"
  netns_up; start_pb "$1" || { netns_down; return; }; prime
  ip -n vm1 link set v1eth down; ip -n vm1 link set v1eth address 02:00:00:00:0d:aa; ip -n vm1 link set v1eth up
  chk "vm1(newmac)->gw"           "until_ok 14 'ip netns exec vm1 ping -c1 -W2 $GW'"
  chk "host->vm1(newmac)"         "until_ok 14 'host2vm $V1'"
  # conflict variant: vm1 mac := HOSTMAC -> vm1 indistinguishable -> loses external
  local h0; h0=$(ip netns exec hostns cat /sys/class/net/up0/address)
  conflict_flow "vm-mac" vm1 $V1 \
    "ip -n vm1 link set v1eth down; ip -n vm1 link set v1eth address $h0; ip -n vm1 link set v1eth up" \
    "ip -n vm1 link set v1eth down; ip -n vm1 link set v1eth address 02:00:00:00:0d:bb; ip -n vm1 link set v1eth up"
  netns_down
}

scenario_vm_ip(){ # req 3
  echo "  -- [$1] vm IP change: non-conflict (.5->.7), then conflict(vm2 takes host IP)->recover"
  netns_up; start_pb "$1" || { netns_down; return; }; prime
  # non-conflict: vm1 .5 -> .7
  ip -n vm1 addr del $V1/24 dev v1eth; ip -n vm1 addr add 10.0.0.7/24 dev v1eth
  chk "nonconf: vm1(.7)->gw"      "until_ok 14 'ip netns exec vm1 ping -c1 -W2 $GW'"
  chk "nonconf: host->vm1(.7)"    "until_ok 14 'host2vm 10.0.0.7'"
  # conflict: vm2 takes the host IP (.2) -> vm2 loses external; host keeps .2
  conflict_flow "vm-ip" vm2 "$HOST" \
    "ip -n vm2 addr del $V2/24 dev v2eth; ip -n vm2 addr add $HOST/24 dev v2eth" \
    "ip -n vm2 addr del $HOST/24 dev v2eth; ip -n vm2 addr add 10.0.0.8/24 dev v2eth" \
    "ip netns exec hostns ping -c1 -W2 $GW"
  netns_down
}

trap netns_down EXIT
echo "###### func-coexist (PLAN req 2 & 3)  engines: $ENGINES ######"
for e in $ENGINES; do
  echo "== engine: $e =="
  scenario_bridge_rename "$e"
  scenario_host_ip "$e"
  scenario_host_mac "$e"
  scenario_vm_mac "$e"
  scenario_vm_ip "$e"
done
echo "============================================="
echo "RESULT: $PASS/$TOTAL checks passed"
[ "$PASS" = "$TOTAL" ] && echo "ALL COEXIST CHECKS PASSED" || { echo "SOME COEXIST CHECKS FAILED"; exit 1; }
