#!/usr/bin/env bash
# Probe whether nftables can queue inbound packets at netdev ingress when the
# Ethernet destination is the receiving interface's own MAC.
#
# Topology:
#   ns nftq_tx: tx0 198.51.100.1/24  <veth>  rx0 198.51.100.2/24 :nftq_rx
#
# The nft rule lives in nftq_rx and is bound to rx0 ingress only:
#   ether daddr $RX_MAC ip daddr 198.51.100.2 queue num $QUEUE
#
# If libnetfilter_queue development headers are available, the script builds a
# tiny userspace NFQUEUE listener that returns NF_DROP. Otherwise it still tests
# the no-listener queue behavior, which should also keep matching packets out of
# the IP stack unless the rule uses the nft "bypass" flag.
set -Eeuo pipefail

NS_RX="${NS_RX:-nftq_rx}"
NS_TX="${NS_TX:-nftq_tx}"
IF_RX="${IF_RX:-rx0}"
IF_TX="${IF_TX:-tx0}"
IP_RX="${IP_RX:-198.51.100.2}"
IP_TX="${IP_TX:-198.51.100.1}"
PREFIX="${PREFIX:-24}"
TABLE="${TABLE:-test_nft_ingress_queue}"
QUEUE="${QUEUE:-47}"
TMPDIR="${TMPDIR:-/tmp/test_nft_ingress_queue}"

LISTENER_PID=""

die() {
    echo "FAIL: $*" >&2
    exit 1
}

need() {
    command -v "$1" >/dev/null 2>&1 || die "missing command: $1"
}

cleanup() {
    set +e
    if [ -n "$LISTENER_PID" ]; then
        kill "$LISTENER_PID" 2>/dev/null
        wait "$LISTENER_PID" 2>/dev/null
    fi
    ip netns exec "$NS_RX" nft delete table netdev "$TABLE" >/dev/null 2>&1
    ip netns del "$NS_RX" >/dev/null 2>&1
    ip netns del "$NS_TX" >/dev/null 2>&1
    rm -rf "$TMPDIR"
}
trap cleanup EXIT

run_rx() {
    ip netns exec "$NS_RX" "$@"
}

build_listener() {
    mkdir -p "$TMPDIR"
    cat >"$TMPDIR/nfq_drop.c" <<'C_EOF'
#include <errno.h>
#include <linux/netfilter.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

#include <libnetfilter_queue/libnetfilter_queue.h>

static unsigned int seen = 0;

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
              struct nfq_data *nfa, void *data) {
    (void)nfmsg;
    (void)data;

    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    unsigned int id = 0;
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    unsigned char *payload = NULL;
    int len = nfq_get_payload(nfa, &payload);
    seen++;
    printf("NFQUEUE packet %u: id=%u len=%d indev=%u physindev=%u\n",
           seen, id, len, nfq_get_indev(nfa), nfq_get_physindev(nfa));
    fflush(stdout);

    return nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
}

static long now_ms(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

int main(int argc, char **argv) {
    int qnum = argc > 1 ? atoi(argv[1]) : 47;
    int timeout_ms = argc > 2 ? atoi(argv[2]) : 4000;

    struct nfq_handle *h = nfq_open();
    if (!h) {
        perror("nfq_open");
        return 2;
    }

    nfq_unbind_pf(h, AF_INET);
    if (nfq_bind_pf(h, AF_INET) < 0) {
        perror("nfq_bind_pf(AF_INET)");
        nfq_close(h);
        return 2;
    }

    struct nfq_q_handle *qh = nfq_create_queue(h, qnum, &cb, NULL);
    if (!qh) {
        perror("nfq_create_queue");
        nfq_close(h);
        return 2;
    }

    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        perror("nfq_set_mode");
        nfq_destroy_queue(qh);
        nfq_close(h);
        return 2;
    }

    int fd = nfq_fd(h);
    struct timeval tv = { .tv_sec = 0, .tv_usec = 200000 };
    setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));

    char buf[65536] __attribute__((aligned));
    long deadline = now_ms() + timeout_ms;
    while (now_ms() < deadline) {
        int rv = recv(fd, buf, sizeof(buf), 0);
        if (rv >= 0) {
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
            continue;
        }
        perror("recv");
        break;
    }

    printf("NFQUEUE total=%u\n", seen);
    nfq_destroy_queue(qh);
    nfq_close(h);
    return seen == 0 ? 1 : 0;
}
C_EOF

    gcc "$TMPDIR/nfq_drop.c" -o "$TMPDIR/nfq_drop" \
        $(pkg-config --cflags --libs libnetfilter_queue)
}

counter_packets() {
    run_rx nft -a list chain netdev "$TABLE" ingress \
        | sed -n 's/.*counter packets \([0-9][0-9]*\).*/\1/p' \
        | tail -n 1
}

[ "$(id -u)" -eq 0 ] || die "run as root"
need ip
need nft
need ping
if command -v modprobe >/dev/null 2>&1; then
    modprobe nft_queue >/dev/null 2>&1 || true
    modprobe nfnetlink_queue >/dev/null 2>&1 || true
fi
mkdir -p "$TMPDIR"

echo "== setup namespaces =="
ip netns del "$NS_RX" >/dev/null 2>&1 || true
ip netns del "$NS_TX" >/dev/null 2>&1 || true
ip netns add "$NS_RX"
ip netns add "$NS_TX"
ip link add "$IF_RX" netns "$NS_RX" type veth peer name "$IF_TX" netns "$NS_TX"

ip -n "$NS_RX" addr add "$IP_RX/$PREFIX" dev "$IF_RX"
ip -n "$NS_TX" addr add "$IP_TX/$PREFIX" dev "$IF_TX"
ip -n "$NS_RX" link set lo up
ip -n "$NS_TX" link set lo up
ip -n "$NS_RX" link set "$IF_RX" up
ip -n "$NS_TX" link set "$IF_TX" up

RX_MAC="$(run_rx cat "/sys/class/net/$IF_RX/address")"
TX_MAC="$(ip netns exec "$NS_TX" cat "/sys/class/net/$IF_TX/address")"
ip -n "$NS_TX" neigh replace "$IP_RX" lladdr "$RX_MAC" nud permanent dev "$IF_TX"
ip -n "$NS_RX" neigh replace "$IP_TX" lladdr "$TX_MAC" nud permanent dev "$IF_RX"

echo "RX $IF_RX mac=$RX_MAC ip=$IP_RX"
echo "TX $IF_TX mac=$TX_MAC ip=$IP_TX"

echo "== baseline: IP stack receives packets before nft queue =="
ip netns exec "$NS_TX" ping -c 1 -W 1 "$IP_RX" >/dev/null \
    || die "baseline ping failed before installing nft rule"
echo "PASS: baseline ping succeeds"

echo "== install netdev ingress queue rule in $NS_RX =="
run_rx nft delete table netdev "$TABLE" >/dev/null 2>&1 || true
if ! run_rx nft -f - <<EOF
table netdev $TABLE {
  chain ingress {
    type filter hook ingress device "$IF_RX" priority -300; policy accept;
    ether daddr $RX_MAC ip daddr $IP_RX counter queue num $QUEUE
  }
}
EOF
then
    die "nft could not install netdev ingress queue rule; this kernel likely lacks nft netdev queue support"
fi
run_rx nft list table netdev "$TABLE"

LISTENER_MODE="none"
if command -v gcc >/dev/null 2>&1 && command -v pkg-config >/dev/null 2>&1 \
    && pkg-config --exists libnetfilter_queue; then
    echo "== build and start NFQUEUE userspace drop listener =="
    build_listener
    run_rx "$TMPDIR/nfq_drop" "$QUEUE" 4500 >"$TMPDIR/nfq.log" 2>&1 &
    LISTENER_PID=$!
    sleep 0.3
    LISTENER_MODE="libnetfilter_queue"
else
    echo "== NFQUEUE listener skipped =="
    echo "libnetfilter_queue development files are not available; testing no-listener queue drop path"
fi

before="$(counter_packets || echo 0)"
echo "counter before=$before"

echo "== send inbound packet with dst mac == $IF_RX own MAC =="
if ip netns exec "$NS_TX" ping -c 1 -W 1 "$IP_RX" >"$TMPDIR/ping-blocked.log" 2>&1; then
    cat "$TMPDIR/ping-blocked.log"
    die "ping unexpectedly succeeded; queued packet reached the IP stack"
fi
echo "PASS: ping is blocked, so the packet did not continue through the IP stack"

sleep 0.5
after="$(counter_packets || echo 0)"
echo "counter after=$after"
if [ "${after:-0}" -le "${before:-0}" ]; then
    run_rx nft -a list chain netdev "$TABLE" ingress
    die "nft counter did not increase; rule did not match the inbound packet"
fi
echo "PASS: nft ingress rule matched dst-mac=$RX_MAC dst-ip=$IP_RX"

if [ "$LISTENER_MODE" = "libnetfilter_queue" ]; then
    wait "$LISTENER_PID"
    LISTENER_PID=""
    echo "--- nfqueue listener log ---"
    sed 's/^/  /' "$TMPDIR/nfq.log"
    grep -q '^NFQUEUE packet ' "$TMPDIR/nfq.log" \
        || die "listener ran but did not receive queued packets"
    echo "PASS: userspace NFQUEUE listener received the packet and returned NF_DROP"
else
    echo "PASS: without a listener and without nft queue bypass, matching packets are not accepted"
fi

echo "== final nft counter =="
run_rx nft -a list chain netdev "$TABLE" ingress
echo "ALL DONE"
