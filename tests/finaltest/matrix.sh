#!/bin/bash
# pseudo-bridge functional matrix: CASES x (mode x engine).
#   config = mode(direct|fwd) x engine(nft|ebpf)
# Topology per config:
#   ns up (gw 10.0.0.1 / fd00::1, single-MAC enforce) ── up0(hostns: pbridge)
#       hostns has br0; guests g1,g2 on br0.
#   fwd   : pbridge creates mt-if/mt-br (pins only up0); the harness enslaves mt-br into
#           br0 after startup (operator's job); pbridge tracks mt-br.master. up0 keeps IP.
#   direct: up0 enslaved in br0, IP on br0; hooks on up0 egress/ingress.
#
# ENV selects engines + timing:
#   linux   (default): nft + ebpf      (nft run under bpf-blocked seccomp = "no ebpf perm")
#   android (GKI/QEMU): ebpf only       (no NF_TABLES in stock GKI)
set -u
HERE="$(cd "$(dirname "$0")" && pwd)"
BIN="${BIN:-/root/gitrs/pseudo-bridge-rs/target/debug/pbridge}"
NOEBPF="${NOEBPF:-$HERE/noebpf}"
ENV="${ENV:-linux}"
engines_for_env() { case "$ENV" in android) echo "ebpf";; *) echo "nft ebpf";; esac; }
case "$ENV" in android) S=30; R=70;; *) S=12; R=20;; esac   # settle / ready budgets

HMAC=02:00:00:00:00:01
GW4=10.0.0.1; GW6=fd00::1; HOST4=10.0.0.2; HOST6=fd00::2
G1_4=10.0.0.5; G1_6=fd00::5; G2_4=10.0.0.6; G2_6=fd00::6
PB=""
declare -A RESULT

ipx(){ ip netns exec "$@"; }
until_ok(){ local end=$((SECONDS+$1)); shift; while :; do eval "$*" >/dev/null 2>&1 && return 0; [ $SECONDS -ge $end ] && return 1; sleep 1; done; }

set_upstream_filter(){ # $1 = allowed mac. tc flower (no nft dep). Accept frames whose
  # src mac == the single allowed mac (pbridge rewrites every guest frame to it),
  # drop the rest. clsact stays installed across updates (only the prio-1 filter is
  # swapped) to avoid a drop-everything window while reprogramming. The matchall drop
  # is added ONLY if flower loaded — stock GKI lacks CONFIG_NET_CLS_FLOWER, so there
  # enforcement is skipped and correctness rests on the on-wire no-leak capture.
  ipx up tc qdisc add dev u0 clsact 2>/dev/null || true
  ipx up tc filter del dev u0 ingress prio 1 2>/dev/null || true
  if ipx up tc filter add dev u0 ingress prio 1 protocol all flower src_mac "$1" action ok 2>/dev/null; then
    ipx up tc filter replace dev u0 ingress prio 9 protocol all matchall action drop 2>/dev/null || true
  fi
}

topo_up(){ # $1 = mode
  local mode=$1
  for n in up hostns g1 g2; do ip netns add $n; done
  ip link add up0 netns hostns type veth peer name u0 netns up
  ip link add gbr netns hostns type veth peer name g1eth netns g1
  ip link add gbr2 netns hostns type veth peer name g2eth netns g2
  ip -n up addr add $GW4/24 dev u0; ip -n up addr add $GW6/64 dev u0 nodad
  ip -n up link set u0 up; ip -n up link set lo up
  # Model a learning upstream: honor gratuitous ARP / unsolicited NA immediately so
  # a HOSTMAC change re-points the gateway's L2 cache at once (a real switch/AP learns
  # from the source MAC; a Linux gateway otherwise caches until NUD times out).
  ipx up sysctl -q net.ipv4.conf.all.arp_accept=1 net.ipv4.conf.default.arp_accept=1 net.ipv4.conf.u0.arp_accept=1 2>/dev/null
  ip -n hostns link set up0 address $HMAC; ip -n hostns link set up0 up
  # br0 mac == HMAC so direct-mode HOSTMAC (= br0 mac) matches the upstream filter.
  ip -n hostns link add br0 type bridge; ip -n hostns link set br0 address $HMAC; ip -n hostns link set br0 up
  ip -n hostns link set gbr master br0; ip -n hostns link set gbr up
  ip -n hostns link set gbr2 master br0; ip -n hostns link set gbr2 up
  ipx hostns sysctl -q net.ipv4.conf.all.rp_filter=0 net.ipv4.conf.default.rp_filter=0 2>/dev/null
  ipx hostns sysctl -q net.ipv6.conf.all.forwarding=1 net.ipv4.conf.all.forwarding=1 2>/dev/null
  if [ "$mode" != direct ]; then
    ip -n hostns addr add $HOST4/24 dev up0
    ip -n hostns addr add $HOST6/64 dev up0 nodad
  else
    ip -n hostns link set up0 master br0
    ip -n hostns addr add $HOST4/24 dev br0
    ip -n hostns addr add $HOST6/64 dev br0 nodad
  fi
  ip -n g1 addr add $G1_4/24 dev g1eth; ip -n g1 addr add $G1_6/64 dev g1eth nodad
  ip -n g1 link set g1eth up; ip -n g1 link set lo up
  ip -n g2 addr add $G2_4/24 dev g2eth; ip -n g2 addr add $G2_6/64 dev g2eth nodad
  ip -n g2 link set g2eth up; ip -n g2 link set lo up
  set_upstream_filter $HMAC
}
topo_down(){ [ -n "$PB" ] && kill "$PB" 2>/dev/null; PB=""; sleep 0.2; for n in up hostns g1 g2; do ip netns del $n 2>/dev/null; done; }

start_pb(){ # $1 mode $2 engine
  local mode=$1 engine=$2 log=/tmp/pb-$mode-$engine.log
  local args=(-i up0 -e "$engine" -m "$mode" --timeout 6)
  [ "$mode" != direct ] && args+=(--fwd-device-if mt-if --fwd-device-br mt-br)
  local wrap=()
  [ "$engine" = nft ] && wrap=("$NOEBPF")
  ipx hostns "${wrap[@]}" "$BIN" "${args[@]}" >"$log" 2>&1 &
  PB=$!
  local end=$((SECONDS+R))
  while ! grep -q 'backend running' "$log" 2>/dev/null; do
    kill -0 "$PB" 2>/dev/null || { echo "FAILSTART"; return 1; }
    [ $SECONDS -ge $end ] && { echo "FAILSTART"; return 1; }
    sleep 0.5
  done
  # fwd: pbridge made mt-if/mt-br but pins only up0; the operator enslaves fwd1 (mt-br)
  # into the VM bridge whenever — pbridge tracks mt-br.master dynamically. Do it now.
  if [ "$mode" != direct ]; then
    local e=$((SECONDS+10)); while ! ip -n hostns link show mt-br >/dev/null 2>&1; do [ $SECONDS -ge $e ] && break; sleep 0.3; done
    ip -n hostns link set mt-br master br0
    sleep 1   # let pbridge react to the new master (nft rebuild for BRMAC) + bridge warm up
  fi
  return 0
}

run_config(){ # $1 mode $2 engine ; echoes "pass total"
  local mode=$1 engine=$2 pass=0 total=0
  topo_up "$mode"
  if ! start_pb "$mode" "$engine"; then echo "FAILSTART"; topo_down; return; fi
  ck(){ total=$((total+1)); if eval "$2" >/dev/null 2>&1; then pass=$((pass+1)); else echo "    [x] $1" >&2; fi; }
  ckc(){ total=$((total+1)); if until_ok "$S" "$3"; then pass=$((pass+1)); else echo "    [x] $1" >&2; fi; }

  # 3/4: ARP+ND connectivity v4/v6
  ckc "guest v4 -> gw"      x "ipx g1 ping -c1 -W2 $GW4"
  ckc "guest v6 -> gw"      x "ipx g1 ping -c1 -W2 $GW6"
  # 13: zero leak on wire (prime convergence first)
  until_ok "$S" "ipx g1 ping -c1 -W2 $GW4"
  local gmac; gmac=$(ip -n g1 -br link show g1eth | awk '{print $3}')
  ipx up timeout 3 tcpdump -i u0 -e -n 'icmp or arp or icmp6' >/tmp/cap 2>/dev/null & local tp=$!
  sleep 0.3; ipx g1 ping -c2 -W2 $GW4 >/dev/null 2>&1; ipx g1 ping -c2 -W2 $GW6 >/dev/null 2>&1; wait $tp 2>/dev/null
  ck "13 no guest-mac leak"  "! grep -q '$gmac >' /tmp/cap"
  # 9: host coexistence
  ckc "9 host v4 -> gw"     x "ipx hostns ping -c1 -W2 $GW4"
  ckc "9 host v6 -> gw"     x "ipx hostns ping -c1 -W2 $GW6"
  # 10: host -> VM (fwd via /32 route+mirror; direct on-link)
  ckc "10 host -> VM v4"    x "ipx hostns ping -c1 -W2 $G1_4"
  ckc "10 host -> VM v6"    x "ipx hostns ping -c1 -W2 $G1_6"
  # 8: multi-guest + isolation
  ckc "8 guest2 v4 -> gw"   x "ipx g2 ping -c1 -W2 $GW4"
  ckc "8 g1 <-> g2 (bridge)" x "ipx g1 ping -c1 -W2 $G2_4"
  # established g1<->g2 must not traverse u0
  ipx up timeout 3 tcpdump -i u0 -n host $G2_4 >/tmp/cap2 2>/dev/null & tp=$!
  sleep 0.3; ipx g1 ping -c2 -W2 $G2_4 >/dev/null 2>&1; wait $tp 2>/dev/null
  ck "8 g1<->g2 not on u0"  "! grep -q '$G2_4' /tmp/cap2"
  # 6: guest MAC change
  ip -n g1 link set g1eth address 02:00:00:00:0c:01
  ckc "6 guest mac change"  x "ipx g1 ping -c1 -W2 $GW4"
  # 11: HOSTMAC change (fwd: up0 mac; direct: br0 mac). Update upstream to new mac.
  local NEW=02:00:00:00:0a:bb
  if [ "$mode" != direct ]; then ip -n hostns link set up0 address $NEW; else ip -n hostns link set br0 address $NEW; fi
  set_upstream_filter $NEW
  # pbridge broadcasts a gratuitous ARP for each entry (verified on the wire), but a
  # Linux gateway refuses to update a REACHABLE neigh from a gratuitous ARP (anti-spoof)
  # and only re-resolves on NUD timeout. A real switch/AP re-learns from the source MAC
  # instantly; model that by flushing the gateway's stale L2 binding for the guest.
  ipx up ip neigh flush dev u0 2>/dev/null
  ckc "11 HOSTMAC change"   x "ipx g1 ping -c1 -W2 $GW4"
  ipx up timeout 3 tcpdump -i u0 -e -n "icmp" >/tmp/cap11 2>/dev/null & tp=$!
  sleep 0.3; ipx g1 ping -c3 -W2 $GW4 >/dev/null 2>&1; wait $tp 2>/dev/null
  ck "11 wire src=new mac"  "grep -qi '$NEW >' /tmp/cap11"
  # 5: guest IP change
  ip -n g1 addr add 10.0.0.55/24 dev g1eth
  ckc "5 guest new IP works" x "ipx g1 ping -c1 -W2 -I 10.0.0.55 $GW4"
  # 7: timeout — idle entry ages out then re-learns
  ip -n g1 addr del 10.0.0.55/24 dev g1eth 2>/dev/null
  sleep $((S+8))   # > 2*timeout(6) for ebpf second-chance
  ckc "7 reconnect after idle" x "ipx g1 ping -c1 -W2 $GW4"

  # engine isolation assertions
  if [ "$engine" = ebpf ]; then
    ck "ebpf uses 0 nft" "! ipx hostns nft list tables 2>/dev/null | grep -q pbridge"
  else
    ck "nft ran under bpf-block (no ebpf)" "grep -q 'backend running' /tmp/pb-$mode-$engine.log"
  fi

  echo "$pass $total"
  topo_down
}

trap topo_down EXIT
ENGINES=$(engines_for_env)
echo "###### pbridge matrix ENV=$ENV  configs = mode(direct,fwd) x engine($ENGINES) ######"
for mode in direct fwd fwd-with-offload; do for engine in $ENGINES; do
  printf "== config mode=%-6s engine=%-5s ==\n" "$mode" "$engine"
  RESULT["$mode/$engine"]="$(run_config "$mode" "$engine")"
done; done
echo; echo "================ SUMMARY (ENV=$ENV) ================"
allgood=1
for mode in direct fwd fwd-with-offload; do for engine in $ENGINES; do
  r="${RESULT[$mode/$engine]}"
  case "$r" in
    FAILSTART) printf "  %-6s %-5s : FAIL (did not start)\n" "$mode" "$engine"; allgood=0;;
    *) p=${r% *}; t=${r#* }; st=PASS; [ "$p" = "$t" ] || { st=FAIL; allgood=0; }
       printf "  %-6s %-5s : %s (%s/%s)\n" "$mode" "$engine" "$st" "$p" "$t";;
  esac
done; done
echo "==================================================="
[ "$allgood" = 1 ] && echo "ALL CONFIGS PASSED" || { echo "SOME CONFIGS FAILED"; exit 1; }
