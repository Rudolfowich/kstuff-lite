/*
 * Standalone RPC payload for kstuff.
 *
 * Prerequisite: kstuff loader has already installed UELF (so kekcall syscall
 * is live for ANY userland process on the box). This payload needs no
 * special offsets — only the kekcall numbering has to match UELF.
 *
 * Wire protocol (little-endian, no alignment):
 *   Request:  u32 cmd, u32 arg_len, bytes[arg_len]
 *   Response: i64 status, u32 resp_len, bytes[resp_len]
 *
 * Commands:
 *   0x01 PING      args: ()                        resp: "PONG"
 *   0x02 READ      args: (u64 kaddr, u32 len)      resp: bytes[len]
 *   0x03 WRITE     args: (u64 kaddr, bytes)        resp: ()  -- len % 8 == 0
 *   0x04 WRITE64   args: (u64 kaddr, u64 value)    resp: ()
 *   0x05 KEKCALL   args: (u32 nr, u64 a1,a2,a3)    resp: i64 ret
 *   0x06 KBASE     args: ()                        resp: u64 kbase
 *   0x07 EXIT      args: ()                        resp: ()  -- exits payload
 *   0x08 IOCTL_PATH args: (u32 path_len, u32 flags, u32 cmd, u32 in_len, u32 out_len, bytes[path_len], bytes[in_len])
 *                                                   resp: i32 ret, i32 errno, bytes[out_len]
 *   0x09 GET_PID   args: ()                        resp: u32 pid
 *   0x0a IOCTL_FD  args: (u32 fd, u32 cmd, u32 in_len, u32 out_len, bytes[in_len])
 *                                                   resp: i32 ret, i32 errno, bytes[out_len]
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdint.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <unistd.h>

#include <sys/types.h>
#include <sys/socket.h>
#include <sys/syscall.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>

#include <ps5/klog.h>

/* ---- kekcall ABI (must match ps5-kstuff/uelf/kekcall.c) --------------- */

#define KEKCALL_SWAP_FULL       16
#define KEKCALL_RESTORE_FULL    17
#define KEKCALL_DUMP_MEM        19
#define KEKCALL_GET_KBASE       24
#define KEKCALL_WRITE64         27

static inline __attribute__((noinline)) long
kekcall(uint32_t nr, uint64_t a1, uint64_t a2, uint64_t a3)
{
    register uint64_t rax asm("rax") = ((uint64_t)nr << 32) | SYS_getppid;
    register uint64_t rdi asm("rdi") = a1;
    register uint64_t rsi asm("rsi") = a2;
    register uint64_t rdx asm("rdx") = a3;
    asm volatile("syscall"
                 : "+r"(rax), "+r"(rdi), "+r"(rsi), "+r"(rdx)
                 :
                 : "rcx", "r8", "r9", "r10", "r11", "memory");
    return (long)rax;
}

/* ---- protocol --------------------------------------------------------- */

#define RPC_CMD_PING    0x01
#define RPC_CMD_READ    0x02
#define RPC_CMD_WRITE   0x03
#define RPC_CMD_WRITE64 0x04
#define RPC_CMD_KEKCALL 0x05
#define RPC_CMD_KBASE   0x06
#define RPC_CMD_EXIT    0x07
#define RPC_CMD_IOCTL_PATH 0x08
#define RPC_CMD_GET_PID    0x09
#define RPC_CMD_IOCTL_FD   0x0a

#define RPC_ERR_PROTO   -1000
#define RPC_ERR_RANGE   -1001

#define RPC_PORT 9030

static int read_full(int fd, void *buf, size_t n)
{
    uint8_t *p = buf;
    while (n) {
        ssize_t r = recv(fd, p, n, 0);
        if (r == 0) return -1;
        if (r < 0) { if (errno == EINTR) continue; return -1; }
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int write_full(int fd, const void *buf, size_t n)
{
    const uint8_t *p = buf;
    while (n) {
        ssize_t r = send(fd, p, n, 0);
        if (r <= 0) { if (r < 0 && errno == EINTR) continue; return -1; }
        p += r; n -= (size_t)r;
    }
    return 0;
}

static int send_response(int fd, int64_t status, const void *payload, uint32_t len)
{
    uint8_t hdr[12];
    memcpy(hdr, &status, 8);
    memcpy(hdr + 8, &len, 4);
    if (write_full(fd, hdr, 12) < 0) return -1;
    if (len && write_full(fd, payload, len) < 0) return -1;
    return 0;
}

static int handle_read(int fd, const uint8_t *args, uint32_t alen)
{
    if (alen != 12) return send_response(fd, RPC_ERR_PROTO, NULL, 0);
    uint64_t kaddr; uint32_t len;
    memcpy(&kaddr, args, 8);
    memcpy(&len, args + 8, 4);
    if (len > (1u << 20)) return send_response(fd, RPC_ERR_RANGE, NULL, 0);

    uint8_t hdr[12]; int64_t status = 0;
    memcpy(hdr, &status, 8);
    memcpy(hdr + 8, &len, 4);
    if (write_full(fd, hdr, 12) < 0) return -1;

    uint8_t chunk[4096];
    uint32_t remaining = len; uint64_t cur = kaddr;
    while (remaining) {
        uint32_t n = remaining > sizeof(chunk) ? sizeof(chunk) : remaining;
        memset(chunk, 0, n);
        (void)kekcall(KEKCALL_DUMP_MEM, cur, (uint64_t)chunk, n);
        if (write_full(fd, chunk, n) < 0) return -1;
        cur += n; remaining -= n;
    }
    return 0;
}

static int handle_write(int fd, const uint8_t *args, uint32_t alen)
{
    if (alen < 8 || ((alen - 8) & 7)) return send_response(fd, RPC_ERR_PROTO, NULL, 0);
    uint64_t kaddr; memcpy(&kaddr, args, 8);
    const uint8_t *data = args + 8;
    for (uint32_t off = 0; off < alen - 8; off += 8) {
        uint64_t v; memcpy(&v, data + off, 8);
        long rc = kekcall(KEKCALL_WRITE64, kaddr + off, v, 0);
        if (rc < 0) return send_response(fd, rc, NULL, 0);
    }
    return send_response(fd, 0, NULL, 0);
}

static int handle_write64(int fd, const uint8_t *args, uint32_t alen)
{
    if (alen != 16) return send_response(fd, RPC_ERR_PROTO, NULL, 0);
    uint64_t kaddr, val;
    memcpy(&kaddr, args, 8);
    memcpy(&val, args + 8, 8);
    long rc = kekcall(KEKCALL_WRITE64, kaddr, val, 0);
    return send_response(fd, rc, NULL, 0);
}

static int handle_kekcall(int fd, const uint8_t *args, uint32_t alen)
{
    if (alen != 4 + 8 * 3) return send_response(fd, RPC_ERR_PROTO, NULL, 0);
    uint32_t nr; uint64_t a1, a2, a3;
    memcpy(&nr, args, 4);
    memcpy(&a1, args + 4, 8);
    memcpy(&a2, args + 12, 8);
    memcpy(&a3, args + 20, 8);
    long rc = kekcall(nr, a1, a2, a3);
    int64_t ret64 = rc;
    uint8_t out[8]; memcpy(out, &ret64, 8);
    return send_response(fd, 0, out, 8);
}

static int handle_ioctl_path(int fd, const uint8_t *args, uint32_t alen)
{
    /* args: u32 path_len, u32 flags, u32 cmd, u32 in_len, u32 out_len, path, in */
    if (alen < 20) return send_response(fd, RPC_ERR_PROTO, NULL, 0);
    uint32_t path_len, flags, cmd, in_len, out_len;
    memcpy(&path_len, args + 0,  4);
    memcpy(&flags,    args + 4,  4);
    memcpy(&cmd,      args + 8,  4);
    memcpy(&in_len,   args + 12, 4);
    memcpy(&out_len,  args + 16, 4);
    if (path_len == 0 || path_len > 256) return send_response(fd, RPC_ERR_PROTO, NULL, 0);
    if (in_len > 4096 || out_len > 4096) return send_response(fd, RPC_ERR_RANGE, NULL, 0);
    if (alen != 20 + path_len + in_len) return send_response(fd, RPC_ERR_PROTO, NULL, 0);

    char path[257];
    memcpy(path, args + 20, path_len);
    path[path_len] = 0;

    /* ioctl buffer: must be large enough for the biggest of in_len/out_len */
    uint32_t buflen = in_len > out_len ? in_len : out_len;
    if (buflen < 1) buflen = 1;
    uint8_t *iobuf = calloc(1, buflen);
    if (!iobuf) return send_response(fd, -ENOMEM, NULL, 0);
    if (in_len) memcpy(iobuf, args + 20 + path_len, in_len);

    /* Elevate ucred to root for the device open+ioctl window. */
    uint64_t backup[4] = {0};
    long sr = kekcall(KEKCALL_SWAP_FULL, 1, (uint64_t)backup, 0);

    int ofd = open(path, (int)flags);
    int open_errno = errno;
    int ret, saved_errno;
    if (ofd < 0) {
        /* Encode: ret = -1 means open failed; errno carries open's errno
         * but we flag this via the response's 2nd 32-bit field (saved_errno
         * stays open_errno). Client can tell apart by probing with cmd=0. */
        ret = -1;
        saved_errno = open_errno;
        klog_printf("[rpc_ioctl] open('%s') failed: errno=%d\n", path, open_errno);
    } else {
        errno = 0;
        ret = ioctl(ofd, cmd, iobuf);
        saved_errno = errno;
        klog_printf("[rpc_ioctl] fd=%d cmd=0x%x ret=%d errno=%d\n", ofd, cmd, ret, saved_errno);
        close(ofd);
    }

    if (sr == 0) {
        kekcall(KEKCALL_RESTORE_FULL, 0, (uint64_t)backup, 0);
    }

    /* Response: i32 ret, i32 errno, bytes[out_len] */
    uint8_t *resp = malloc(8 + out_len);
    if (!resp) { free(iobuf); return send_response(fd, -ENOMEM, NULL, 0); }
    memcpy(resp + 0, &ret, 4);
    memcpy(resp + 4, &saved_errno, 4);
    if (out_len) memcpy(resp + 8, iobuf, out_len);
    int rc = send_response(fd, 0, resp, 8 + out_len);
    free(resp);
    free(iobuf);
    return rc;
}

static int handle_get_pid(int fd)
{
    pid_t pid = getpid();
    uint32_t p = (uint32_t)pid;
    uint8_t out[4]; memcpy(out, &p, 4);
    return send_response(fd, 0, out, 4);
}

static int handle_ioctl_fd(int fd, const uint8_t *args, uint32_t alen)
{
    /* args: u32 fd, u32 cmd, u32 in_len, u32 out_len, bytes[in_len] */
    if (alen < 16) return send_response(fd, RPC_ERR_PROTO, NULL, 0);
    uint32_t tfd, cmd, in_len, out_len;
    memcpy(&tfd,     args + 0,  4);
    memcpy(&cmd,     args + 4,  4);
    memcpy(&in_len,  args + 8,  4);
    memcpy(&out_len, args + 12, 4);
    if (in_len > 4096 || out_len > 4096) return send_response(fd, RPC_ERR_RANGE, NULL, 0);
    if (alen != 16 + in_len) return send_response(fd, RPC_ERR_PROTO, NULL, 0);

    uint32_t buflen = in_len > out_len ? in_len : out_len;
    if (buflen < 1) buflen = 1;
    uint8_t *iobuf = calloc(1, buflen);
    if (!iobuf) return send_response(fd, -ENOMEM, NULL, 0);
    if (in_len) memcpy(iobuf, args + 16, in_len);

    errno = 0;
    int ret = ioctl((int)tfd, cmd, iobuf);
    int saved_errno = errno;
    klog_printf("[rpc_ioctl_fd] fd=%d cmd=0x%x ret=%d errno=%d\n", tfd, cmd, ret, saved_errno);

    uint8_t *resp = malloc(8 + out_len);
    if (!resp) { free(iobuf); return send_response(fd, -ENOMEM, NULL, 0); }
    memcpy(resp + 0, &ret, 4);
    memcpy(resp + 4, &saved_errno, 4);
    if (out_len) memcpy(resp + 8, iobuf, out_len);
    int rc = send_response(fd, 0, resp, 8 + out_len);
    free(resp);
    free(iobuf);
    return rc;
}

static int handle_kbase(int fd)
{
    uint64_t kb = (uint64_t)kekcall(KEKCALL_GET_KBASE, 0, 0, 0);
    uint8_t out[8]; memcpy(out, &kb, 8);
    return send_response(fd, 0, out, 8);
}

/* Returns 1 continue, 0 drop client, -1 shutdown server. */
static int serve_one(int fd)
{
    uint8_t hdr[8];
    if (read_full(fd, hdr, 8) < 0) return 0;
    uint32_t cmd, alen;
    memcpy(&cmd, hdr, 4);
    memcpy(&alen, hdr + 4, 4);

    if (alen > (1u << 20)) {
        send_response(fd, RPC_ERR_RANGE, NULL, 0);
        return 0;
    }
    uint8_t *args = NULL;
    if (alen) {
        args = malloc(alen);
        if (!args) { send_response(fd, -ENOMEM, NULL, 0); return 0; }
        if (read_full(fd, args, alen) < 0) { free(args); return 0; }
    }

    int rc = 1;
    switch (cmd) {
    case RPC_CMD_PING:    rc = send_response(fd, 0, "PONG", 4); break;
    case RPC_CMD_READ:    rc = handle_read(fd, args, alen); break;
    case RPC_CMD_WRITE:   rc = handle_write(fd, args, alen); break;
    case RPC_CMD_WRITE64: rc = handle_write64(fd, args, alen); break;
    case RPC_CMD_KEKCALL: rc = handle_kekcall(fd, args, alen); break;
    case RPC_CMD_KBASE:   rc = handle_kbase(fd); break;
    case RPC_CMD_IOCTL_PATH: rc = handle_ioctl_path(fd, args, alen); break;
    case RPC_CMD_GET_PID:    rc = handle_get_pid(fd); break;
    case RPC_CMD_IOCTL_FD:   rc = handle_ioctl_fd(fd, args, alen); break;
    case RPC_CMD_EXIT:    send_response(fd, 0, NULL, 0); free(args); return -1;
    default:              rc = send_response(fd, RPC_ERR_PROTO, NULL, 0); break;
    }
    free(args);
    return rc < 0 ? 0 : 1;
}

int main(void)
{
    klog_printf("[kstuff-rpc] starting on port %d\n", RPC_PORT);

    /* Sanity check: kekcall available? GET_KBASE should return a kernel pointer. */
    uint64_t kb = (uint64_t)kekcall(KEKCALL_GET_KBASE, 0, 0, 0);
    if (kb < 0xffffffff00000000ULL) {
        klog_printf("[kstuff-rpc] kekcall sanity FAILED (kbase=0x%llx) — is kstuff loaded?\n",
                    (unsigned long long)kb);
        return 1;
    }
    klog_printf("[kstuff-rpc] kekcall ok, kbase=0x%llx\n", (unsigned long long)kb);

    int ls = socket(AF_INET, SOCK_STREAM, 0);
    if (ls < 0) { klog_printf("[kstuff-rpc] socket: %s\n", strerror(errno)); return 1; }

    int one = 1;
    setsockopt(ls, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one));

    struct sockaddr_in sa;
    memset(&sa, 0, sizeof(sa));
    sa.sin_family = AF_INET;
    sa.sin_port = htons(RPC_PORT);
    sa.sin_addr.s_addr = htonl(INADDR_ANY);

    if (bind(ls, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        klog_printf("[kstuff-rpc] bind(:%d): %s\n", RPC_PORT, strerror(errno));
        close(ls); return 1;
    }
    if (listen(ls, 1) < 0) {
        klog_printf("[kstuff-rpc] listen: %s\n", strerror(errno));
        close(ls); return 1;
    }

    klog_printf("[kstuff-rpc] listening on 0.0.0.0:%d\n", RPC_PORT);

    for (;;) {
        struct sockaddr_in ca; socklen_t cal = sizeof(ca);
        int cs = accept(ls, (struct sockaddr *)&ca, &cal);
        if (cs < 0) {
            if (errno == EINTR) continue;
            klog_printf("[kstuff-rpc] accept: %s\n", strerror(errno));
            break;
        }
        setsockopt(cs, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        klog_printf("[kstuff-rpc] client %s:%u\n",
                    inet_ntoa(ca.sin_addr), ntohs(ca.sin_port));

        int teardown = 0;
        for (;;) {
            int r = serve_one(cs);
            if (r <= 0) { if (r < 0) teardown = 1; break; }
        }
        close(cs);
        klog_printf("[kstuff-rpc] client gone\n");
        if (teardown) break;
    }

    close(ls);
    klog_printf("[kstuff-rpc] exit\n");
    return 0;
}
