#!/usr/bin/env bash
# Functional addressing test (PLAN req 1): 4 nodes — host, neighbor, vm1, vm2 —
# each obtains 3 addresses (DHCPv4, DHCPv6, SLAAC) from a dnsmasq on the upstream
# segment, and all 4 must be pairwise reachable on every family. Then a VM
# releases its lease, gets a new one, and is immediately reachable again.
#
#   ns net: ubr (gw 10.0.0.1 / fd00::1) + dnsmasq(v4+DHCPv6+RA);  u0╌up0, nbp╌nbeth
#   ns nb:  neighbor (on upstream segment, NOT behind pbridge)
#   ns hostns: up0 (host's own client), br0, mtnat1╌mtnat1p, gbr1/gbr2; pbridge
#   ns vm1/vm2: behind br0 (MAC-NAT'd guests)
#
# The host/neighbor are directly on the upstream segment (native addressing);
# vm1/vm2 go through MAC-NAT. veth checksum offload is disabled throughout (a
# test-env artifact: locally generated packets get CHECKSUM_PARTIAL, which a real
# upstream NIC would finalize on TX).
set -u
BIN="${BIN:-./target/debug/pbridge}"
ENGINE="${ENGINE:-userspace}"
PASS=0; TOTAL=0; PB=""
NSES="net nb hostns vm1 vm2"

noff(){ for spec in "$@"; do set -- $spec; ip netns exec $1 ethtool -K $2 tx off rx off >/dev/null 2>&1; done; }
# Emulate a single-MAC upstream (Wi-Fi STA / anti-spoof NIC) by MAC-filtering the
# AP-facing veth end so, like an AP: host->net frames must be sourced from
# HOSTMAC (anti-spoof; leaks dropped+logged), and net->host delivers only to
# HOSTMAC or multicast/broadcast (a unicast to a guest's real mac is dropped —
# which is exactly why DHCPv4 must use the broadcast bit). Dropped frames never
# reach pbridge. $1 ns, $2 AP-facing dev (u0), $3 HOSTMAC.
wifi_filter(){
  ip netns exec "$1" nft -f - <<EOF
table netdev wifiap {
  chain h2n { type filter hook ingress device "$2" priority -500; policy accept;
    ether saddr != $3 counter log prefix "wifiap-spoof " drop
  }
  chain n2h { type filter hook egress device "$2" priority 500; policy accept;
    ether daddr $3 accept
    ether daddr ff:ff:ff:ff:ff:ff accept
    ether daddr 33:33:00:00:00:00/16 accept
    ether daddr 01:00:5e:00:00:00/24 accept
    counter drop
  }
}
EOF
}
# minimal udhcpc (v4) and udhcpc6 (DHCPv6) apply-scripts
cat > /tmp/u4.script <<'EOF'
#!/bin/sh
case "$1" in bound|renew)
  ip -4 addr flush dev "$interface" scope global 2>/dev/null
  ip -4 addr add "$ip/24" dev "$interface"
  [ -n "$router" ] && ip -4 route replace default via "$router" 2>/dev/null ;; esac
exit 0
EOF
cat > /tmp/u6.script <<'EOF'
#!/bin/sh
[ -n "$ipv6" ] && case "$1" in bound|renew)
  ip -6 addr add "$ipv6/128" dev "$interface" 2>/dev/null ;; esac
exit 0
EOF
chmod +x /tmp/u4.script /tmp/u6.script
# acquire all three on ($1 ns,$2 dev): v4 (udhcpc), DHCPv6 (udhcpc6), SLAAC (accept_ra)
acquire(){
  ip netns exec $1 timeout 15 busybox udhcpc  -i $2 -n -q -f -s /tmp/u4.script >/tmp/dh-$1-4.log 2>&1
  ip netns exec $1 timeout 15 busybox udhcpc6 -i $2 -n -q -f -s /tmp/u6.script >/tmp/dh-$1-6.log 2>&1
}
kill_all(){ [ -n "$PB" ] && kill $PB 2>/dev/null; pkill -f 'dnsmasq.*ubr' 2>/dev/null; pkill dhcpcd 2>/dev/null; }
cleanup(){ kill_all; for ns in $NSES; do ip netns del $ns 2>/dev/null; done; }
trap cleanup EXIT
chk(){ TOTAL=$((TOTAL+1)); if eval "$2" >/dev/null 2>&1; then PASS=$((PASS+1)); else echo "    [x] $1"; fi; }
until_ok(){ local end=$((SECONDS+$1)); shift; while :; do eval "$*" >/dev/null 2>&1 && return 0; [ $SECONDS -ge $end ] && return 1; sleep 1; done; }

kill_all; sleep 1
for ns in $NSES; do ip netns del $ns 2>/dev/null; ip netns add $ns; done
ip -n net link add ubr type bridge; ip -n net link set ubr up
ip -n net addr add 10.0.0.1/24 dev ubr; ip -n net addr add fd00::1/64 dev ubr
ip link add u0  netns net type veth peer name up0   netns hostns
ip link add nbp netns net type veth peer name nbeth netns nb
ip -n net link set u0 master ubr;  ip -n net link set u0 up
ip -n net link set nbp master ubr; ip -n net link set nbp up
ip -n hostns link add br0 type bridge; ip -n hostns link set up0 up; ip -n hostns link set br0 up
ip link add gbr1 netns hostns type veth peer name v1eth netns vm1
ip link add gbr2 netns hostns type veth peer name v2eth netns vm2
ip -n hostns link set gbr1 master br0; ip -n hostns link set gbr2 master br0
ip -n hostns link set gbr1 up; ip -n hostns link set gbr2 up
ip netns exec hostns sysctl -q net.ipv4.conf.all.rp_filter=0
for spec in "nb nbeth" "vm1 v1eth" "vm2 v2eth"; do set -- $spec; ip -n $1 link set $2 up; ip -n $1 link set lo up; done
# enable SLAAC (accept RAs) on every client device
for spec in "hostns up0" "nb nbeth" "vm1 v1eth" "vm2 v2eth"; do set -- $spec
  ip netns exec $1 sysctl -q net.ipv6.conf.$2.accept_ra=2 net.ipv6.conf.$2.accept_ra_defrtr=1; done

ip netns exec hostns "$BIN" --upstream up0 --fwd-device mtnat1 --bridge br0 \
   --l2nat-backend "$ENGINE" --entry-timeout 120 >/tmp/pb-dh.log 2>&1 & PB=$!
for _ in $(seq 1 30); do grep -q 'backend running' /tmp/pb-dh.log && break; kill -0 $PB 2>/dev/null || { echo "pbridge died"; sed 's/^/  /' /tmp/pb-dh.log; exit 1; }; sleep 1; done
noff "net ubr" "net u0" "net nbp" "nb nbeth" "hostns up0" "hostns br0" "hostns gbr1" "hostns gbr2" "hostns mtnat1" "vm1 v1eth" "vm2 v2eth"
# apply the single-MAC upstream filter on u0 (HOSTMAC = up0's mac)
HOSTMAC=$(ip netns exec hostns cat /sys/class/net/up0/address)
wifi_filter net u0 "$HOSTMAC"
echo "  (single-MAC upstream filter active on u0; HOSTMAC=$HOSTMAC)"

rm -f /tmp/dnsmasq.log
ip netns exec net dnsmasq --keep-in-foreground --user=root --group=root \
  --interface=ubr --bind-interfaces \
  --dhcp-range=10.0.0.100,10.0.0.200,255.255.255.0,2m \
  --enable-ra --dhcp-range=fd00::100,fd00::1ff,slaac,2m --ra-param=ubr,3,90 \
  --dhcp-authoritative --no-resolv --no-hosts --leasefile-ro --dhcp-leasefile=/dev/null \
  --log-dhcp --log-facility=/tmp/dnsmasq.log >/tmp/dnsmasq.out 2>&1 &
sleep 1
pgrep -f 'dnsmasq.*ubr' >/dev/null || { echo "dnsmasq failed to start:"; sed 's/^/  /' /tmp/dnsmasq.out; exit 1; }

echo "== ENGINE=$ENGINE : 4 nodes acquire DHCPv4 + DHCPv6 + SLAAC =="
sleep 5   # let dnsmasq emit a couple of RAs so SLAAC kicks in
# host's own client on up0; neighbor on nbeth; vms behind pbridge
acquire hostns up0; acquire nb nbeth; acquire vm1 v1eth; acquire vm2 v2eth
sleep 8   # SLAAC autoconf + DAD (proactively learned) + DHCPv6 settle

# --- collect addresses: $1 ns, $2 dev, prints "v4 slaac dhcp6" ---
addrs(){
  local ns=$1 d=$2
  local v4 dh6 sl
  v4=$(ip -n $ns -4 -o addr show dev $d 2>/dev/null | grep -oE '10\.0\.0\.[0-9]+' | head -1)
  # DHCPv6 leases come from fd00::100..1ff ; SLAAC is any other global fd00::
  dh6=$(ip -n $ns -6 -o addr show dev $d scope global 2>/dev/null | grep -oE 'fd00::1[0-9a-f][0-9a-f]?\b' | head -1)
  sl=$(ip -n $ns -6 -o addr show dev $d scope global 2>/dev/null | grep -oE 'fd00::[0-9a-f:]+' | grep -vxF "$dh6" | head -1)
  echo "${v4:-NONE} ${sl:-NONE} ${dh6:-NONE}"
}
read H4 HS H6 <<<"$(addrs hostns up0)"
read N4 NS N6 <<<"$(addrs nb nbeth)"
read A4 AS A6 <<<"$(addrs vm1 v1eth)"
read B4 BS B6 <<<"$(addrs vm2 v2eth)"
printf "  host: v4=%s slaac=%s dhcp6=%s\n" "$H4" "$HS" "$H6"
printf "  nbor: v4=%s slaac=%s dhcp6=%s\n" "$N4" "$NS" "$N6"
printf "  vm1 : v4=%s slaac=%s dhcp6=%s\n" "$A4" "$AS" "$A6"
printf "  vm2 : v4=%s slaac=%s dhcp6=%s\n" "$B4" "$BS" "$B6"

# each node must have all three
for n in "host $H4 $HS $H6" "nbor $N4 $NS $N6" "vm1 $A4 $AS $A6" "vm2 $B4 $BS $B6"; do
  set -- $n; chk "$1 got v4"    "[ '$2' != NONE ]"; chk "$1 got slaac" "[ '$3' != NONE ]"; chk "$1 got dhcp6" "[ '$4' != NONE ]"
done

# --- pairwise reachability per family (ping from $1ns to addr $3) ---
P(){ ip netns exec $1 ping -c1 -W2 ${2:+-I $2} $3; }   # $1 ns, $2 src(opt), $3 dst
pair(){ # label, fromns, dst
  [ "$3" = NONE ] || [ -z "$3" ] && { echo "    [x] $1 (no addr)"; TOTAL=$((TOTAL+1)); return; }
  chk "$1" "until_ok 6 'ip netns exec $2 ping -c1 -W2 $3'"
}
echo "  -- pairwise v4 --"
pair "host->nbor v4" hostns $N4; pair "host->vm1 v4" hostns $A4; pair "host->vm2 v4" hostns $B4
pair "nbor->vm1 v4" nb $A4;      pair "nbor->vm2 v4" nb $B4;     pair "vm1->vm2 v4" vm1 $B4
echo "  -- pairwise slaac --"
pair "host->nbor sl" hostns $NS; pair "host->vm1 sl" hostns $AS; pair "host->vm2 sl" hostns $BS
pair "nbor->vm1 sl" nb $AS;      pair "nbor->vm2 sl" nb $BS;     pair "vm1->vm2 sl" vm1 $BS
echo "  -- pairwise dhcp6 --"
pair "host->nbor d6" hostns $N6; pair "host->vm1 d6" hostns $A6; pair "host->vm2 d6" hostns $B6
pair "nbor->vm1 d6" nb $A6;      pair "nbor->vm2 d6" nb $B6;     pair "vm1->vm2 d6" vm1 $B6

# --- lease renewal: vm1 releases (drops addrs), re-acquires, immediately reachable ---
echo "  -- vm1 lease release + re-acquire --"
ip -n vm1 addr flush dev v1eth scope global 2>/dev/null; sleep 2
acquire vm1 v1eth; sleep 3
read R4 RS R6 <<<"$(addrs vm1 v1eth)"
printf "  vm1(renewed): v4=%s slaac=%s dhcp6=%s\n" "$R4" "$RS" "$R6"
chk "renew: vm1 got v4"        "[ -n '$R4' ]"
chk "renew: host->vm1 v4"      "until_ok 10 'ip netns exec hostns ping -c1 -W2 $R4'"
chk "renew: nbor->vm1 v4"      "until_ok 10 'ip netns exec nb ping -c1 -W2 $R4'"
[ "$R6" != NONE ] && chk "renew: host->vm1 dhcp6" "until_ok 10 'ip netns exec hostns ping -c1 -W2 $R6'"

echo "============================================="
echo "RESULT ($ENGINE): $PASS/$TOTAL checks passed"
[ "$PASS" = "$TOTAL" ] && echo "ALL DHCP/SLAAC CHECKS PASSED" || { echo "SOME DHCP/SLAAC CHECKS FAILED"; exit 1; }
