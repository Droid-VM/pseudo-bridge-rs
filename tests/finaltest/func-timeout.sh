#!/usr/bin/env bash
# Entry-timeout liveness test (PLAN §4): an *idle* guest entry must time out
# (route + map elem withdrawn); an *actively communicating* guest must NOT be
# evicted, even past entry_timeout. The hard case is the offload backends
# (nft/ebpf): the in-kernel fast path consumes the packets, so liveness must be
# tracked in-kernel (nft set timeout / ebpf last_seen) and fed back to eviction,
# else an active flow is wrongly evicted.
#
#   ns up (gw 10.0.0.1) ─ u0╌up0 ─ hostns(up0, br0, mtnat1; pbridge) ─ vm1 (10.0.0.5)
set -u
BIN="${BIN:-./target/debug/pbridge}"
ENGINES="${ENGINES:-userspace nft ebpf}"
GW=10.0.0.1; V1=10.0.0.5; TMO=6
PBPID=""; PASS=0; TOTAL=0; LOG=/tmp/pb-tmo.log

netns_up(){
  for ns in up hostns vm1; do ip netns add $ns; done
  # this test isolates v4 entry-timeout; silence IPv6 autoconf (RS/MLD) so the
  # netns interfaces don't generate continuous multicast that muddies "idle".
  for ns in up hostns vm1; do ip netns exec $ns sysctl -q net.ipv6.conf.all.disable_ipv6=1 net.ipv6.conf.default.disable_ipv6=1; done
  ip link add up0 netns hostns type veth peer name u0 netns up
  ip link add gbr1 netns hostns type veth peer name v1eth netns vm1
  ip -n up addr add $GW/24 dev u0; ip -n up link set u0 up; ip -n up link set lo up
  ip -n hostns link add br0 type bridge
  ip -n hostns link set up0 up; ip -n hostns addr add 10.0.0.2/24 dev up0
  ip -n hostns link set gbr1 master br0; ip -n hostns link set gbr1 up; ip -n hostns link set br0 up
  ip netns exec hostns sysctl -q net.ipv4.conf.all.rp_filter=0
  ip -n vm1 addr add $V1/24 dev v1eth; ip -n vm1 link set v1eth up; ip -n vm1 link set lo up
}
netns_down(){ [ -n "$PBPID" ] && kill "$PBPID" 2>/dev/null; sleep 0.3; PBPID=""
  for ns in up hostns vm1; do ip netns del $ns 2>/dev/null; done; }
trap netns_down EXIT
until_ok(){ local end=$((SECONDS+$1)); shift; while :; do eval "$*" >/dev/null 2>&1 && return 0; [ $SECONDS -ge $end ] && return 1; sleep 1; done; }
route_has(){ ip -n hostns route show table 200 2>/dev/null | grep -qE "^$V1 "; }
evict_count(){ local n; n=$(grep -c 'evicted [1-9]' "$LOG" 2>/dev/null); echo "${n:-0}"; }
chk(){ TOTAL=$((TOTAL+1)); if eval "$2"; then PASS=$((PASS+1)); else echo "    [x] $1"; fi; }

run_one(){
  local eng=$1
  echo "== engine: $eng (entry-timeout ${TMO}s) =="
  netns_up
  ip netns exec hostns "$BIN" --upstream up0 --fwd-device mtnat1 --bridge br0 \
     --l2nat-backend "$eng" --entry-timeout $TMO >"$LOG" 2>&1 & PBPID=$!
  for _ in $(seq 1 30); do grep -q 'backend running' "$LOG" && break; kill -0 $PBPID 2>/dev/null || break; sleep 1; done

  # learn vm1
  until_ok 12 "ip netns exec vm1 ping -c1 -W2 $GW"
  chk "$eng: learned (route present)" "until_ok 6 route_has"

  # IDLE: no traffic for > timeout -> entry must expire (route withdrawn).
  # Flush neighbor caches so the gateway doesn't NUD-probe .5 (which would count
  # as activity and keep the entry warm); a truly idle guest gets no such probes.
  ip -n up neigh flush all 2>/dev/null; ip -n vm1 neigh flush all 2>/dev/null
  sleep $((TMO + 6))
  chk "$eng: idle entry timed out (route gone)" "! route_has"
  chk "$eng: idle eviction was logged"          "[ $(evict_count) -ge 1 ]"

  # re-learn, then ACTIVE: continuous traffic must keep the entry alive
  until_ok 12 "ip netns exec vm1 ping -c1 -W2 $GW"
  until_ok 6 route_has
  local before; before=$(evict_count)
  ip netns exec vm1 ping -i 0.5 -W2 $GW >/dev/null 2>&1 & local pinger=$!
  sleep $((TMO * 3))    # 3x timeout of continuous traffic
  local route_ok=1; route_has || route_ok=0
  local after; after=$(evict_count)
  kill $pinger 2>/dev/null
  chk "$eng: active entry NOT evicted (route stays)" "[ $route_ok = 1 ]"
  chk "$eng: no eviction during active traffic"      "[ $after = $before ]"
  chk "$eng: active flow still reaches gw"           "until_ok 6 'ip netns exec vm1 ping -c1 -W2 $GW'"
  netns_down
}

echo "###### func-timeout  engines: $ENGINES ######"
for e in $ENGINES; do run_one "$e"; done
echo "============================================="
echo "RESULT: $PASS/$TOTAL checks passed"
[ "$PASS" = "$TOTAL" ] && echo "ALL TIMEOUT CHECKS PASSED" || { echo "SOME TIMEOUT CHECKS FAILED"; exit 1; }
