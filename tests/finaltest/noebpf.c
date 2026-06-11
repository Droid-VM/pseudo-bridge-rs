// Seccomp wrapper that blocks the bpf() syscall (EPERM), then execs its args.
// Used to run the nft engine "as if in a linux container with no bpf permission",
// proving the nft path makes zero bpf() calls (ARCHITECTURE.md test matrix).
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <linux/seccomp.h>
#include <linux/filter.h>
#include <linux/audit.h>
#include <sys/prctl.h>
#include <sys/syscall.h>

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: noebpf CMD ARGS...\n"); return 2; }
    struct sock_filter filt[] = {
        BPF_STMT(BPF_LD | BPF_W | BPF_ABS, offsetof(struct seccomp_data, nr)),
        BPF_JUMP(BPF_JMP | BPF_JEQ | BPF_K, __NR_bpf, 0, 1),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ERRNO | (EPERM & SECCOMP_RET_DATA)),
        BPF_STMT(BPF_RET | BPF_K, SECCOMP_RET_ALLOW),
    };
    struct sock_fprog prog = { .len = sizeof(filt) / sizeof(filt[0]), .filter = filt };
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) { perror("no_new_privs"); return 1; }
    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, &prog)) { perror("seccomp"); return 1; }
    execvp(argv[1], &argv[1]);
    perror("execvp");
    return 1;
}
