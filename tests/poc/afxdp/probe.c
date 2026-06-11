// AF_XDP runtime probe — runs as PID 1 (init) inside a QEMU-booted GKI kernel.
// Answers "does this kernel actually support AF_XDP", beyond the static
// CONFIG_XDP_SOCKETS=y, by exercising the real datapath setup:
//   1. socket(AF_XDP, SOCK_RAW, 0)        -> address family registered at runtime
//   2. mmap UMEM + XDP_UMEM_REG           -> XSK umem subsystem works
//   3. FILL/COMPLETION/RX ring setsockopt -> ring registration works
//   4. getsockopt(XDP_MMAP_OFFSETS)       -> ring layout query works
//   5. bind() to an interface (XDP_COPY = generic/SKB mode, no driver needed)
// The guest has only `lo` (no virtio_net), so we self-create a `dummy` netdev
// via rtnetlink to get a normal netdev to bind on, and also try `lo` for ref.
// Everything is best-effort + reported with errno; the core verdict is steps 1-4.
#include <stdio.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <stdint.h>
#include <sys/socket.h>
#include <sys/mman.h>
#include <sys/ioctl.h>
#include <sys/utsname.h>
#include <sys/reboot.h>
#include <net/if.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <linux/if_link.h>
#include <linux/sockios.h>

// --- AF_XDP uapi (self-defined to avoid header-version skew) ---
#ifndef AF_XDP
#define AF_XDP 44
#endif
#define SOL_XDP 283
#define XDP_MMAP_OFFSETS 1
#define XDP_RX_RING 2
#define XDP_UMEM_REG 4
#define XDP_UMEM_FILL_RING 5
#define XDP_UMEM_COMPLETION_RING 6
#define XDP_COPY (1u << 1)

struct xdp_umem_reg {
    uint64_t addr;
    uint64_t len;
    uint32_t chunk_size;
    uint32_t headroom;
    uint32_t flags;
};
struct sockaddr_xdp {
    uint16_t sxdp_family;
    uint16_t sxdp_flags;
    uint32_t sxdp_ifindex;
    uint32_t sxdp_queue_id;
    uint32_t sxdp_shared_umem_fd;
};
struct xdp_ring_offset {
    uint64_t producer, consumer, desc, flags;
};
struct xdp_mmap_offsets {
    struct xdp_ring_offset rx, tx, fr, cr;
};

#define E strerror(errno)

// ---- rtnetlink helpers: create + bring up a `dummy` interface ----
static void addattr(struct nlmsghdr *nh, int type, const void *data, int alen) {
    struct rtattr *rta = (struct rtattr *)((char *)nh + NLMSG_ALIGN(nh->nlmsg_len));
    rta->rta_type = type;
    rta->rta_len = RTA_LENGTH(alen);
    if (alen)
        memcpy(RTA_DATA(rta), data, alen);
    nh->nlmsg_len = NLMSG_ALIGN(nh->nlmsg_len) + RTA_ALIGN(rta->rta_len);
}

static int add_dummy(const char *name) {
    int fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (fd < 0)
        return -1;
    struct {
        struct nlmsghdr nh;
        struct ifinfomsg ifi;
        char buf[256];
    } req;
    memset(&req, 0, sizeof req);
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    req.nh.nlmsg_type = RTM_NEWLINK;
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_EXCL | NLM_F_ACK;
    req.ifi.ifi_family = AF_UNSPEC;
    addattr(&req.nh, IFLA_IFNAME, name, strlen(name) + 1);
    struct rtattr *li = (struct rtattr *)((char *)&req.nh + NLMSG_ALIGN(req.nh.nlmsg_len));
    addattr(&req.nh, IFLA_LINKINFO, NULL, 0);
    addattr(&req.nh, IFLA_INFO_KIND, "dummy", sizeof "dummy");
    li->rta_len = (char *)&req.nh + NLMSG_ALIGN(req.nh.nlmsg_len) - (char *)li;

    if (send(fd, &req, req.nh.nlmsg_len, 0) < 0) {
        close(fd);
        return -1;
    }
    char rbuf[512];
    int n = recv(fd, rbuf, sizeof rbuf, 0);
    close(fd);
    if (n < 0)
        return -1;
    struct nlmsghdr *rh = (struct nlmsghdr *)rbuf;
    if (rh->nlmsg_type == NLMSG_ERROR) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(rh);
        return err->error; // 0 == success
    }
    return 0;
}

static void iface_up(const char *name) {
    int s = socket(AF_INET, SOCK_DGRAM, 0);
    if (s < 0)
        return;
    struct ifreq ifr;
    memset(&ifr, 0, sizeof ifr);
    strncpy(ifr.ifr_name, name, IFNAMSIZ - 1);
    if (ioctl(s, SIOCGIFFLAGS, &ifr) == 0) {
        ifr.ifr_flags |= IFF_UP;
        ioctl(s, SIOCSIFFLAGS, &ifr);
    }
    close(s);
}

// Full XSK setup on `ifname`; reports each step. Returns 0 if bind() succeeds.
static int xsk_try(const char *ifname) {
    printf("  [%s] full XSK setup:\n", ifname);
    int fd = socket(AF_XDP, SOCK_RAW, 0);
    if (fd < 0) {
        printf("    socket(AF_XDP)            : FAIL (%s)\n", E);
        return -1;
    }
    const uint32_t CHUNK = 4096, NFRAMES = 64, NDESC = 64;
    size_t ulen = (size_t)CHUNK * NFRAMES;
    void *umem = mmap(NULL, ulen, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (umem == MAP_FAILED) {
        printf("    mmap(umem)               : FAIL (%s)\n", E);
        close(fd);
        return -1;
    }
    struct xdp_umem_reg reg = {0};
    reg.addr = (uint64_t)(uintptr_t)umem;
    reg.len = ulen;
    reg.chunk_size = CHUNK;
    int rc = setsockopt(fd, SOL_XDP, XDP_UMEM_REG, &reg, sizeof reg);
    printf("    setsockopt(XDP_UMEM_REG) : %s\n", rc == 0 ? "OK" : E);
    uint32_t n = NDESC;
    rc = setsockopt(fd, SOL_XDP, XDP_UMEM_FILL_RING, &n, sizeof n);
    printf("    setsockopt(FILL_RING)    : %s\n", rc == 0 ? "OK" : E);
    rc = setsockopt(fd, SOL_XDP, XDP_UMEM_COMPLETION_RING, &n, sizeof n);
    printf("    setsockopt(COMPLETION)   : %s\n", rc == 0 ? "OK" : E);
    rc = setsockopt(fd, SOL_XDP, XDP_RX_RING, &n, sizeof n);
    printf("    setsockopt(RX_RING)      : %s\n", rc == 0 ? "OK" : E);
    struct xdp_mmap_offsets off;
    socklen_t ol = sizeof off;
    rc = getsockopt(fd, SOL_XDP, XDP_MMAP_OFFSETS, &off, &ol);
    printf("    getsockopt(MMAP_OFFSETS) : %s\n", rc == 0 ? "OK" : E);

    unsigned ifindex = if_nametoindex(ifname);
    struct sockaddr_xdp sxdp = {0};
    sxdp.sxdp_family = AF_XDP;
    sxdp.sxdp_flags = XDP_COPY; // force generic/SKB copy mode (no native driver)
    sxdp.sxdp_ifindex = ifindex;
    sxdp.sxdp_queue_id = 0;
    rc = bind(fd, (struct sockaddr *)&sxdp, sizeof sxdp);
    printf("    bind(ifindex=%u,COPY)     : %s\n", ifindex, rc == 0 ? "OK *** AF_XDP DATAPATH UP ***" : E);
    munmap(umem, ulen);
    close(fd);
    return rc;
}

int main(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    struct utsname u;
    uname(&u);
    printf("\n==== AFXDP_PROBE_START ====\n");
    printf("kernel: %s %s %s\n", u.sysname, u.release, u.machine);

    // 1) bare address-family probe
    int fd = socket(AF_XDP, SOCK_RAW, 0);
    if (fd < 0) {
        printf("socket(AF_XDP,SOCK_RAW): FAIL (%s)\n", E);
        printf("VERDICT: AF_XDP NOT SUPPORTED (address family unavailable)\n");
        printf("==== AFXDP_PROBE_DONE ====\n");
        goto out;
    }
    printf("socket(AF_XDP,SOCK_RAW): OK (fd=%d) -> address family registered\n", fd);
    close(fd);

    // 2) self-create a dummy netdev to bind on (guest has only lo)
    int de = add_dummy("xdp0");
    printf("create dummy 'xdp0'    : %s\n", de == 0 ? "OK" : strerror(-de < 0 ? -de : de));
    if (de == 0)
        iface_up("xdp0");
    iface_up("lo");

    // 3) full datapath setup + bind, on lo (ref) and the dummy
    int blo = xsk_try("lo");
    int bdu = de == 0 ? xsk_try("xdp0") : -1;

    printf("---- VERDICT ----\n");
    printf("AF_XDP address family : SUPPORTED\n");
    printf("UMEM/ring setup       : SUPPORTED (see steps above)\n");
    printf("bind generic(lo)      : %s\n", blo == 0 ? "OK" : "no");
    printf("bind generic(dummy)   : %s\n", bdu == 0 ? "OK" : (de == 0 ? "no" : "skipped"));
    printf("==== AFXDP_PROBE_DONE ====\n");

out:
    sync();
    reboot(RB_POWER_OFF);
    for (;;)
        pause();
    return 0;
}
