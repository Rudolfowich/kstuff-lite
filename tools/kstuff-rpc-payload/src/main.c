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
#include <sys/event.h>
#include <sys/time.h>
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
#define RPC_CMD_FIND_MP4_CDEV 0x0b
#define RPC_CMD_READ_PHYS     0x0c
#define RPC_CMD_A53_SDBGP_TX  0x0d
#define RPC_CMD_A53_SESSION_RUN 0x0e
#define RPC_CMD_A53_KEKCALL_DUMP 0x0f

#define KEKCALL_DUMP_PHYS       28

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

/* Read physical memory via kekcall(DUMP_PHYS). Args: u64 phys, u32 len. */
static int handle_read_phys(int fd, const uint8_t *args, uint32_t alen)
{
    if (alen != 12) return send_response(fd, RPC_ERR_PROTO, NULL, 0);
    uint64_t phys; uint32_t len;
    memcpy(&phys, args, 8);
    memcpy(&len, args + 8, 4);
    if (len > (1u << 20)) return send_response(fd, RPC_ERR_RANGE, NULL, 0);

    uint8_t hdr[12]; int64_t status = 0;
    memcpy(hdr, &status, 8);
    memcpy(hdr + 8, &len, 4);
    if (write_full(fd, hdr, 12) < 0) return -1;

    uint8_t chunk[4096];
    uint32_t remaining = len; uint64_t cur = phys;
    while (remaining) {
        uint32_t n = remaining > sizeof(chunk) ? sizeof(chunk) : remaining;
        memset(chunk, 0, n);
        (void)kekcall(KEKCALL_DUMP_PHYS, cur, (uint64_t)chunk, n);
        if (write_full(fd, chunk, n) < 0) return -1;
        cur += n; remaining -= n;
    }
    return 0;
}

/* ---- A53 SDBGP transaction with full kqueue flow -------------------- */
/* Writes a 32-bit value to a kernel VA via RMW through KEKCALL_WRITE64. */
static void kwrite32_rmw(uint64_t kaddr, uint32_t val)
{
    uint64_t base = kaddr & ~7ULL;
    uint64_t cur = 0;
    kekcall(KEKCALL_DUMP_MEM, base, (uintptr_t)&cur, 8);
    uint32_t shift = (uint32_t)(kaddr & 7) * 8;
    cur = (cur & ~((uint64_t)0xFFFFFFFF << shift)) | ((uint64_t)val << shift);
    kekcall(KEKCALL_WRITE64, base, cur, 0);
}

static uint32_t kread32_rmw(uint64_t kaddr)
{
    uint64_t base = kaddr & ~7ULL;
    uint64_t cur = 0;
    kekcall(KEKCALL_DUMP_MEM, base, (uintptr_t)&cur, 8);
    uint32_t shift = (uint32_t)(kaddr & 7) * 8;
    return (uint32_t)(cur >> shift);
}

/* Args (84 bytes LE packed):
 *   u64 pa, u32 len, u32 mem_type,
 *   u64 state_addr, u64 flags_addr,
 *   u64 buf_ptr_kva, u64 iommu_ptr_kva, u64 size_ptr_kva,
 *   u64 req_ctr_kva, u64 req_cmd_kva, u64 zcn_bar2,
 *   u32 cmd_type (SDBGP command code, default 0x01040021)
 * Response: 8192 bytes = raw dump of main DMA buffer after transaction.
 */
static int handle_a53_sdbgp_tx(int fd, const uint8_t *args, uint32_t alen)
{
    if (alen != 84) return send_response(fd, RPC_ERR_PROTO, NULL, 0);

    uint64_t pa, state_addr, flags_addr, buf_ptr, iommu_ptr, size_ptr;
    uint64_t req_ctr, req_cmd, bar2;
    uint32_t len, mem_type;
    memcpy(&pa,         args +  0, 8);
    memcpy(&len,        args +  8, 4);
    memcpy(&mem_type,   args + 12, 4);
    memcpy(&state_addr, args + 16, 8);
    memcpy(&flags_addr, args + 24, 8);
    memcpy(&buf_ptr,    args + 32, 8);
    memcpy(&iommu_ptr,  args + 40, 8);
    memcpy(&size_ptr,   args + 48, 8);
    memcpy(&req_ctr,    args + 56, 8);
    memcpy(&req_cmd,    args + 64, 8);
    memcpy(&bar2,       args + 72, 8);
    uint32_t cmd_type;
    memcpy(&cmd_type,   args + 80, 4);
    if (cmd_type == 0) cmd_type = 0x01040021U;

    /* Resolve DMA registry */
    uint64_t buf_kva = 0, iommu = 0;
    uint32_t bufsz = 0;
    kekcall(KEKCALL_DUMP_MEM, buf_ptr,   (uintptr_t)&buf_kva, 8);
    kekcall(KEKCALL_DUMP_MEM, iommu_ptr, (uintptr_t)&iommu,   8);
    uint64_t sz_qw = 0;
    kekcall(KEKCALL_DUMP_MEM, size_ptr,  (uintptr_t)&sz_qw,   8);
    bufsz = (uint32_t)sz_qw;

    klog_printf("[A53_TX] pa=0x%llx len=%u mt=0x%x cmd=0x%x buf=0x%llx iommu=0x%llx sz=0x%x\n",
        (unsigned long long)pa, len, mem_type, cmd_type,
        (unsigned long long)buf_kva, (unsigned long long)iommu, bufsz);

    /* Auto-clear openlock (softc+0x7f0) to recover from stale open from
     * prior failed transactions. mp4sc = buf_ptr - 0x6b8 */
    uint64_t mp4sc = buf_ptr - 0x6b8;
    kwrite32_rmw(mp4sc + 0x7f0, 0);

    /* DAC patch (je→jne) INVERTS d_open ACL: unprivileged users bypass,
     * privileged ones get denied. Do NOT swap_full — stay unprivileged. */
    int64_t status = 0;
    int ofd = open("/dev/mp4/dump", 0 /*O_RDONLY per drakmor*/);
    int open_errno = errno;
    klog_printf("[A53_TX] open ret=%d errno=%d\n", ofd, open_errno);
    if (ofd < 0) {
        return send_response(fd, -open_errno, NULL, 0);
    }

    int kq = kqueue();
    if (kq < 0) {
        klog_printf("[A53_TX] kqueue fail errno=%d\n", errno);
        close(ofd);
        return send_response(fd, -errno, NULL, 0);
    }

    struct kevent ev;
    EV_SET(&ev, ofd, EVFILT_READ, EV_ADD, 0, 0, NULL);

    /* STEP 1: Force state/flags BEFORE kevent register */
    kwrite32_rmw(state_addr, 0xFFFFFFEFU);
    kwrite32_rmw(flags_addr, 0x210U);

    /* STEP 2: Register knote (critical for firmware to emit raw bytes) */
    int kr = kevent(kq, &ev, 1, NULL, 0, NULL);
    klog_printf("[A53_TX] kevent register ret=%d errno=%d\n", kr, errno);

    /* STEP 3: Build SDBGP_READ_MEMORY packet (0x74 bytes) */
    uint8_t pkt[0x80];
    memset(pkt, 0, sizeof(pkt));
    /* deci5s_hdr (0x28) */
    *(uint32_t*)(pkt + 0x00) = 0x73354450U;        /* magic PD5s */
    *(uint32_t*)(pkt + 0x04) = 0x28;               /* self_size */
    *(uint32_t*)(pkt + 0x08) = 0x74;               /* packet_size */
    *(uint32_t*)(pkt + 0x0C) = 0x80FF0180U;        /* src KERNEL */
    *(uint32_t*)(pkt + 0x10) = 0x80FF0201U;        /* dst MP4 */
    *(uint32_t*)(pkt + 0x14) = 0x20000201U;        /* proto SDBGP */
    /* +0x18 attr=0, +0x1c user=0, +0x20 timestamp=0 */
    /* cmd_hdr tail (0x18) */
    *(uint32_t*)(pkt + 0x28) = 0x18;               /* dcmp */
    *(uint32_t*)(pkt + 0x2C) = 0x50;               /* code */
    /* +0x30..+0x37 pad0=0, +0x38..+0x3B unknown0=0 */
    pkt[0x3C] = 1;                                 /* num_commands */
    /* cmd (0x1c): ss, ts, type, 12 bytes pad, na */
    *(uint32_t*)(pkt + 0x40) = 0x1c;               /* self_size */
    *(uint32_t*)(pkt + 0x44) = 0x34;               /* total_size */
    *(uint32_t*)(pkt + 0x48) = cmd_type;           /* SDBGP command */
    *(uint32_t*)(pkt + 0x58) = 1;                  /* num_args */
    /* mem_arg (0x18) */
    *(uint32_t*)(pkt + 0x5C) = 0x18;
    /* access_sz + mem_type packed */
    uint32_t acc_c = ((uint32_t)pa | len) & 0xFFFFFFFF;
    uint32_t acc;
    if (acc_c & 1) acc = 1;
    else if (acc_c & 2) acc = 3;
    else if (acc_c & 4) acc = 4;
    else if (acc_c & 8) acc = 5;
    else acc = 6;
    *(uint32_t*)(pkt + 0x60) = (acc & 0xFF) | ((mem_type & 0xFFFFFF) << 8);
    *(uint64_t*)(pkt + 0x64) = pa;
    *(uint64_t*)(pkt + 0x6C) = len;

    /* STEP 4: Copy packet to DMA buffer */
    for (uint32_t i = 0; i < 0x74; i += 8) {
        uint64_t v;
        memcpy(&v, pkt + i, 8);
        kekcall(KEKCALL_WRITE64, buf_kva + i, v, 0);
    }

    /* STEP 5: MMIO DMA setup */
    kwrite32_rmw(bar2 + 0xf7000, (uint32_t)(iommu >> 32));
    kwrite32_rmw(bar2 + 0xf8000, (uint32_t)(iommu & 0xFFFFFFFF));
    kwrite32_rmw(bar2 + 0xf9000, bufsz);

    uint32_t req_now = kread32_rmw(req_ctr);
    kwrite32_rmw(req_ctr, req_now + 1);
    kwrite32_rmw(req_cmd, 0x20303000U);

    /* STEP 6: Doorbell */
    kwrite32_rmw(bar2 + 0xf6000, 0x20303000U);
    klog_printf("[A53_TX] doorbell fired, req=%u→%u\n", req_now, req_now + 1);

    /* STEP 7: Wait for IRQ (up to 5 sec) */
    struct kevent oev;
    struct timespec to = {5, 0};
    int nev = kevent(kq, NULL, 0, &oev, 1, &to);
    klog_printf("[A53_TX] kevent wait nev=%d errno=%d flags=0x%x data=%lld\n",
        nev, (nev < 0 ? errno : 0),
        (nev > 0 ? oev.flags : 0),
        (nev > 0 ? (long long)oev.data : 0LL));

    /* STEP 8: IOCTL_FINISH */
    uint32_t fin[2] = {8, 0};
    ioctl(ofd, 0x8008410f, fin);

    close(kq);
    close(ofd);

    /* STEP 9: Read reply buffer from DMA (8KB) and return it */
    uint8_t *reply = calloc(1, 0x2000);
    if (!reply) return send_response(fd, -ENOMEM, NULL, 0);
    for (uint32_t off = 0; off < 0x2000; off += 4096) {
        kekcall(KEKCALL_DUMP_MEM, buf_kva + off, (uintptr_t)(reply + off), 4096);
    }

    int rc = send_response(fd, status, reply, 0x2000);
    free(reply);
    return rc;
}

/* ---- A53 session: open fd + kqueue, batch ioctls, close ------------ */
/* Args layout:
 *   u64 state_addr, u64 flags_addr, u64 openlock_addr,
 *   u32 flags_set   (bool: write 0x210 to flags_addr before)
 *   u32 state_zero  (bool: write 0 to state_addr before)
 *   u32 filter      (kevent filter, e.g. 0x1ffff)
 *   u32 n_ops
 *   per op:
 *     u32 op_type   (0=ioctl, 1=kevent_wait_ms, 2=write32_rmw(addr,val),
 *                    3=read_softc_6d0(len), 4=finish_cmd)
 *     u32 arg_a, arg_b, in_len, out_len
 *     bytes[in_len]
 * Response: for each op: i32 ret, i32 err, u32 out_len, bytes[out_len]
 */
static int handle_a53_session_run(int fd, const uint8_t *args, uint32_t alen)
{
    if (alen < 44) return send_response(fd, RPC_ERR_PROTO, NULL, 0);

    uint64_t state_addr, flags_addr, openlock_addr;
    uint32_t flags_set, state_zero, filter, n_ops;
    memcpy(&state_addr,    args +  0, 8);
    memcpy(&flags_addr,    args +  8, 8);
    memcpy(&openlock_addr, args + 16, 8);
    memcpy(&flags_set,     args + 24, 4);
    memcpy(&state_zero,    args + 28, 4);
    memcpy(&filter,        args + 32, 4);
    memcpy(&n_ops,         args + 36, 4);
    uint32_t ops_off = 40;

    klog_printf("[A53_SESS] state=0x%llx flags=0x%llx openlock=0x%llx filter=0x%x n_ops=%u\n",
        (unsigned long long)state_addr, (unsigned long long)flags_addr,
        (unsigned long long)openlock_addr, filter, n_ops);

    /* Pre-setup: clear openlock, optional state zero, optional flags force */
    if (openlock_addr) kwrite32_rmw(openlock_addr, 0);
    if (state_zero) kwrite32_rmw(state_addr, 0);
    if (flags_set) kwrite32_rmw(flags_addr, 0x210);

    /* Open fd (unprivileged — DAC inversion patch) */
    int ofd = open("/dev/mp4/dump", 0);
    int open_errno = errno;
    klog_printf("[A53_SESS] open ret=%d errno=%d\n", ofd, open_errno);
    if (ofd < 0) return send_response(fd, -open_errno, NULL, 0);

    int kq = kqueue();
    if (kq < 0) {
        close(ofd);
        return send_response(fd, -errno, NULL, 0);
    }

    /* Register knote with custom filter */
    struct kevent ev;
    EV_SET(&ev, ofd, (short)filter, EV_ADD, 0, 0, NULL);
    int kr = kevent(kq, &ev, 1, NULL, 0, NULL);
    int kr_errno = errno;
    klog_printf("[A53_SESS] kevent register ret=%d errno=%d\n", kr, kr_errno);

    /* Response buffer: estimate up to 128KB */
    uint32_t resp_cap = 131072;
    uint8_t *resp = calloc(1, resp_cap);
    if (!resp) {
        close(kq); close(ofd);
        return send_response(fd, -ENOMEM, NULL, 0);
    }
    uint32_t resp_off = 0;

    for (uint32_t i = 0; i < n_ops; i++) {
        if (ops_off + 20 > alen) break;
        uint32_t op_type, arg_a, arg_b, in_len, out_len;
        memcpy(&op_type, args + ops_off +  0, 4);
        memcpy(&arg_a,   args + ops_off +  4, 4);
        memcpy(&arg_b,   args + ops_off +  8, 4);
        memcpy(&in_len,  args + ops_off + 12, 4);
        memcpy(&out_len, args + ops_off + 16, 4);
        if (ops_off + 20 + in_len > alen) break;
        if (in_len > 8192 || out_len > 8192) break;

        int32_t ret = 0, saved_err = 0;
        uint8_t io_buf[8192];
        memset(io_buf, 0, sizeof(io_buf));
        if (in_len) memcpy(io_buf, args + ops_off + 20, in_len);

        if (op_type == 0) {
            /* ioctl: arg_a = cmd */
            errno = 0;
            ret = ioctl(ofd, (unsigned long)arg_a, io_buf);
            saved_err = errno;
            klog_printf("[A53_SESS] op%u ioctl cmd=0x%x ret=%d err=%d\n",
                i, arg_a, ret, saved_err);
        } else if (op_type == 1) {
            /* kevent_wait: arg_a = timeout_ms */
            struct kevent oev;
            struct timespec to;
            to.tv_sec = arg_a / 1000;
            to.tv_nsec = (long)(arg_a % 1000) * 1000000L;
            errno = 0;
            int nev = kevent(kq, NULL, 0, &oev, 1, &to);
            saved_err = errno;
            ret = nev;
            if (nev > 0 && out_len >= 8) {
                memcpy(io_buf + 0, &oev.flags, 2);
                memcpy(io_buf + 2, &oev.fflags, 4);
                memcpy(io_buf + 8, &oev.data, 8);
            }
            klog_printf("[A53_SESS] op%u kevent_wait nev=%d err=%d\n", i, nev, saved_err);
        } else if (op_type == 2) {
            /* write32_rmw: arg_a=addr_lo, arg_b=val; (upper 32 bits unknown — need 64-bit addr) */
            /* For 64-bit addr via two u32 args: encode in in_buf as u64 */
            if (in_len >= 8) {
                uint64_t addr; uint32_t val;
                memcpy(&addr, io_buf, 8);
                memcpy(&val, io_buf + 8, 4);
                kwrite32_rmw(addr, val);
                ret = 0; saved_err = 0;
            } else {
                ret = -1; saved_err = EINVAL;
            }
        } else if (op_type == 3) {
            /* read softc region: in_buf starts with u64 addr */
            if (in_len >= 8 && out_len <= sizeof(io_buf)) {
                uint64_t addr;
                memcpy(&addr, io_buf, 8);
                kekcall(KEKCALL_DUMP_MEM, addr, (uintptr_t)io_buf, out_len);
                ret = 0; saved_err = 0;
            } else { ret = -1; saved_err = EINVAL; }
        } else if (op_type == 5) {
            /* plain read() syscall on mp4/dump fd. arg_a = ignored */
            errno = 0;
            ssize_t nr = read(ofd, io_buf, out_len);
            saved_err = errno;
            ret = (int32_t)nr;
            klog_printf("[A53_SESS] op%u read(fd, %u) nr=%zd errno=%d\n",
                i, out_len, nr, saved_err);
        } else {
            ret = -1; saved_err = EINVAL;
        }

        /* Reset openlock between ops in case driver sets it */
        if (openlock_addr) kwrite32_rmw(openlock_addr, 0);

        /* Pack response: i32 ret, i32 err, u32 out_len, bytes[out_len] */
        if (resp_off + 12 + out_len > resp_cap) break;
        memcpy(resp + resp_off + 0, &ret, 4);
        memcpy(resp + resp_off + 4, &saved_err, 4);
        memcpy(resp + resp_off + 8, &out_len, 4);
        if (out_len) memcpy(resp + resp_off + 12, io_buf, out_len);
        resp_off += 12 + out_len;

        ops_off += 20 + in_len;
    }

    /* Finish: send IOCTL_FINISH */
    uint32_t fin[2] = {8, 0};
    ioctl(ofd, 0x8008410f, fin);

    close(kq);
    close(ofd);
    if (openlock_addr) kwrite32_rmw(openlock_addr, 0);

    int rc = send_response(fd, 0, resp, resp_off);
    free(resp);
    return rc;
}

/* Call kekcall(nr, local_buf, nwords, a3) and return the buffer.
 * Args: u32 nr, u32 nwords, u64 a3. Max nwords=256.
 */
static int handle_a53_kekcall_dump(int fd, const uint8_t *args, uint32_t alen)
{
    if (alen != 16) return send_response(fd, RPC_ERR_PROTO, NULL, 0);
    uint32_t nr, nwords;
    uint64_t a3;
    memcpy(&nr,     args + 0, 4);
    memcpy(&nwords, args + 4, 4);
    memcpy(&a3,     args + 8, 8);
    if (nwords > 256) nwords = 256;
    uint64_t buf[256];
    memset(buf, 0, sizeof(buf));
    long rc = kekcall(nr, (uint64_t)buf, nwords, a3);
    klog_printf("[A53_K8] nr=%u nwords=%u rc=%ld\n", nr, nwords, rc);

    uint32_t bytes_out = nwords * 8;
    uint8_t *resp = malloc(8 + bytes_out);
    if (!resp) return send_response(fd, -ENOMEM, NULL, 0);
    memcpy(resp + 0, &rc, 8);
    memcpy(resp + 8, buf, bytes_out);
    int r = send_response(fd, 0, resp, 8 + bytes_out);
    free(resp);
    return r;
}

static int handle_kbase(int fd)
{
    uint64_t kb = (uint64_t)kekcall(KEKCALL_GET_KBASE, 0, 0, 0);
    uint8_t out[8]; memcpy(out, &kb, 8);
    return send_response(fd, 0, out, 8);
}

/* Fixed-length substring search (name buffer may contain embedded NULs
 * from DUMP_MEM's 8-byte-alignment-down behavior). */
static int my_contains_n(const char *hay, int hay_len, const char *needle)
{
    int nlen = 0; while (needle[nlen]) nlen++;
    for (int i = 0; i + nlen <= hay_len; i++) {
        int ok = 1;
        for (int j = 0; j < nlen; j++) {
            if (hay[i+j] != needle[j]) { ok = 0; break; }
        }
        if (ok) return 1;
    }
    return 0;
}

/* Find mp4/dump cdev + softc by scanning kernel memory via kekcall.
 * Takes no args. Returns i64 cdev, i64 softc, i64 cdevsw, i64 dump_buf_va. */
static int handle_find_mp4_cdev(int rpcfd)
{
    uint64_t kb = (uint64_t)kekcall(KEKCALL_GET_KBASE, 0, 0, 0);

    klog_printf("[FIND_MP4] start kb=0x%llx\n", (unsigned long long)kb);
    /* 1. Find mp4_dump_for_syscore cdevsw (D_VERSION 0x17122009 + name match). */
    uint64_t csw = 0;
    uint8_t *page = malloc(4096);
    if (!page) {
        klog_puts("[FIND_MP4] malloc fail\n");
        goto done;
    }
    unsigned pages_scanned = 0;
    unsigned sig_hits = 0;
    unsigned rc_skips = 0;
    uint64_t last_off = 0;
    for (uint64_t off = 0; off < 0x8000000ULL && !csw; off += 4096) {
        last_off = off;
        __builtin_memset(page, 0, 4096);
        long rc = kekcall(KEKCALL_DUMP_MEM, kb + off, (uintptr_t)page, 4096);
        if (rc <= 0) rc_skips++;
        pages_scanned++;
        for (unsigned i = 0; i + 32 <= 4096; i += 8) {
            uint32_t ver;
            __builtin_memcpy(&ver, page + i, 4);
            if (ver != 0x17122009) continue;
            sig_hits++;
            uint64_t name_ptr;
            __builtin_memcpy(&name_ptr, page + i + 8, 8);
            if ((name_ptr & 0xffff000000000000ULL) != 0xffff000000000000ULL) continue;
            /* Check if candidate is at specific known addr */
            if ((kb + off + i) == kb + 0x1f3ddb0ULL) {
                char name[64] = {0};
                __builtin_memset(name, 0, 64);
                kekcall(KEKCALL_DUMP_MEM, name_ptr, (uintptr_t)name, 64);
                klog_printf("[FIND_MP4] TARGET addr=0x%llx name_ptr=0x%llx bytes:\n",
                            (unsigned long long)(kb+off+i),
                            (unsigned long long)name_ptr);
                klog_printf("[FIND_MP4]   %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
                            (uint8_t)name[0],(uint8_t)name[1],(uint8_t)name[2],(uint8_t)name[3],
                            (uint8_t)name[4],(uint8_t)name[5],(uint8_t)name[6],(uint8_t)name[7],
                            (uint8_t)name[8],(uint8_t)name[9],(uint8_t)name[10],(uint8_t)name[11],
                            (uint8_t)name[12],(uint8_t)name[13],(uint8_t)name[14],(uint8_t)name[15]);
                klog_printf("[FIND_MP4]   %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
                            (uint8_t)name[16],(uint8_t)name[17],(uint8_t)name[18],(uint8_t)name[19],
                            (uint8_t)name[20],(uint8_t)name[21],(uint8_t)name[22],(uint8_t)name[23],
                            (uint8_t)name[24],(uint8_t)name[25],(uint8_t)name[26],(uint8_t)name[27],
                            (uint8_t)name[28],(uint8_t)name[29],(uint8_t)name[30],(uint8_t)name[31]);
            }
            char name[32] = {0};
            __builtin_memset(name, 0, 32);
            kekcall(KEKCALL_DUMP_MEM, name_ptr, (uintptr_t)name, 32);
            name[31] = 0;
            if (my_contains_n(name, 32, "mp4_dump_for_syscore")) {
                csw = kb + off + i;
                break;
            }
        }
    }
    free(page);
    klog_printf("[FIND_MP4] pages=%u sig_hits=%u rc_skips=%u last_off=0x%llx csw=0x%llx\n",
                pages_scanned, sig_hits, rc_skips,
                (unsigned long long)last_off, (unsigned long long)csw);
done:;

    /* 2. Scan heap for cdev referencing csw. Try multiple arena bases:
     * discover arenas by walking allproc + looking at proc struct ptrs. */
    uint64_t cdev = 0, softc = 0, dump_va = 0;
    if (csw) {
        /* Collect candidate heap bases from allproc walk */
        uint64_t ap_global = kb + 0x28c9e80;
        uint64_t first_proc = 0;
        kekcall(KEKCALL_DUMP_MEM, ap_global, (uintptr_t)&first_proc, 8);

        /* Enumerate heap arenas: walk procs for proc-arena, plus known
         * typical PS5 cdev heap bases (upper 32 bits vary per boot). */
        uint64_t arenas[32] = {0};
        unsigned narenas = 0;
        /* Try common cdev arena upper-32 patterns seen across boots */
        uint64_t guesses[] = {
            0xffff800000000000, 0xffff900000000000, 0xffffa00000000000,
            0xffffa80000000000, 0xffffb00000000000, 0xffffb80000000000,
            0xffffc00000000000, 0xffffc80000000000, 0xffffd00000000000,
            0xffffd80000000000, 0xffffe00000000000, 0xffffe80000000000,
            0xfffff00000000000, 0xfffff80000000000,
        };
        /* Probe each for mapped page by reading first qword — if it changes
         * when we read twice (not static zero), arena is live. */
        for (unsigned k = 0; k < sizeof(guesses)/sizeof(guesses[0]); k++) {
            uint64_t probe = 0;
            kekcall(KEKCALL_DUMP_MEM, guesses[k], (uintptr_t)&probe, 8);
            /* Also try a random offset within */
            uint64_t probe2 = 0;
            kekcall(KEKCALL_DUMP_MEM, guesses[k] + 0x1000000ULL, (uintptr_t)&probe2, 8);
            if ((probe || probe2) && narenas < 32) {
                arenas[narenas++] = guesses[k];
            }
        }
        /* Also walk proc list */
        uint64_t p = first_proc;
        for (int step = 0; step < 100 && p; step++) {
            uint64_t prefix = p & 0xffffff0000000000ULL;
            int seen = 0;
            for (unsigned k = 0; k < narenas; k++) if (arenas[k] == prefix) { seen = 1; break; }
            if (!seen && narenas < 32) arenas[narenas++] = prefix;
            uint64_t next = 0;
            kekcall(KEKCALL_DUMP_MEM, p, (uintptr_t)&next, 8);
            if (next == p || next == 0) break;
            p = next;
        }
        klog_printf("[FIND_MP4] arenas: %u\n", narenas);
        for (unsigned k = 0; k < narenas; k++) {
            klog_printf("[FIND_MP4]   arena[%u] = 0x%llx\n", k, (unsigned long long)arenas[k]);
        }

        uint8_t *buf = malloc(0x100000);
        if (buf) {
            unsigned hits = 0;
            for (unsigned ai = 0; ai < narenas && !cdev; ai++) {
                uint64_t heap_base = arenas[ai];
                klog_printf("[FIND_MP4] scanning arena 0x%llx..+256MB\n",
                            (unsigned long long)heap_base);
                for (uint64_t off = 0; off < 0x10000000ULL && !cdev; off += 0x100000) {
                    __builtin_memset(buf, 0, 0x100000);
                    for (unsigned coff = 0; coff < 0x100000; coff += 4096) {
                        kekcall(KEKCALL_DUMP_MEM, heap_base + off + coff,
                                (uintptr_t)(buf + coff), 4096);
                    }
                    for (unsigned i = 0; i + 8 <= 0x100000; i += 8) {
                        uint64_t q;
                        __builtin_memcpy(&q, buf + i, 8);
                        if (q != csw) continue;
                        hits++;
                        uint64_t cand = heap_base + off + i - 0xb8;
                        char nm[16] = {0};
                        kekcall(KEKCALL_DUMP_MEM, cand + 0xe0, (uintptr_t)nm, 16);
                        /* name at cand+0xe0 may be unaligned → DUMP aligns to 8 */
                        if (hits <= 10) {
                            klog_printf("[FIND_MP4] cand=0x%llx nm='%.16s'\n",
                                        (unsigned long long)cand, nm);
                        }
                        if (my_contains_n(nm, 16, "mp4/dump") &&
                            !my_contains_n(nm, 16, "decid") &&
                            !my_contains_n(nm, 16, "syscore")) {
                            cdev = cand;
                            kekcall(KEKCALL_DUMP_MEM, cand + 0xa8, (uintptr_t)&softc, 8);
                            if (softc) {
                                kekcall(KEKCALL_DUMP_MEM, softc + 0x6b8, (uintptr_t)&dump_va, 8);
                            }
                            break;
                        }
                    }
                }
            }
            free(buf);
            klog_printf("[FIND_MP4] heap_hits=%u cdev=0x%llx\n", hits, (unsigned long long)cdev);
        }
    }

    uint8_t out[32];
    __builtin_memcpy(out +  0, &cdev,    8);
    __builtin_memcpy(out +  8, &softc,   8);
    __builtin_memcpy(out + 16, &csw,     8);
    __builtin_memcpy(out + 24, &dump_va, 8);
    return send_response(rpcfd, 0, out, 32);
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
    case RPC_CMD_FIND_MP4_CDEV: rc = handle_find_mp4_cdev(fd); break;
    case RPC_CMD_READ_PHYS: rc = handle_read_phys(fd, args, alen); break;
    case RPC_CMD_A53_SDBGP_TX: rc = handle_a53_sdbgp_tx(fd, args, alen); break;
    case RPC_CMD_A53_SESSION_RUN: rc = handle_a53_session_run(fd, args, alen); break;
    case RPC_CMD_A53_KEKCALL_DUMP: rc = handle_a53_kekcall_dump(fd, args, alen); break;
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
