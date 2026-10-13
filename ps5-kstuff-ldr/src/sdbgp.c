/*
 * sdbgp.c — SDBGP transport (corrected model).
 *
 * All ioctl mechanics are SOLID from the 13.60 kernel reverse. The
 * command-word space (what word0/word1 pairs do to the A53) is still TBD.
 */

#include <sys/types.h>
#include <sys/event.h>
#include <sys/ioctl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>

#include <ps5/klog.h>

#include "sdbgp.h"

#define MP4_DEV_PATH "/dev/mp4/dump"

int sdbgp_xport_open(struct sdbgp_xport *xp)
{
    if (!xp) return SDBGP_ERR_OPEN;
    memset(xp, 0, sizeof(*xp));
    xp->fd = -1;
    xp->kq = -1;

    xp->fd = open(MP4_DEV_PATH, O_RDWR);
    if (xp->fd < 0) {
        klog_printf("[sdbgp] open(%s) failed: errno=%d\n", MP4_DEV_PATH, errno);
        return SDBGP_ERR_OPEN;
    }

    xp->kq = kqueue();
    if (xp->kq < 0) {
        klog_printf("[sdbgp] kqueue() failed: errno=%d\n", errno);
        close(xp->fd); xp->fd = -1;
        return SDBGP_ERR_KQUEUE;
    }

    struct kevent kev;
    EV_SET(&kev, SDBGP_KEV_IDENT, EVFILT_READ, EV_ADD, 0, 0, NULL);
    if (kevent(xp->kq, &kev, 1, NULL, 0, NULL) < 0) {
        klog_printf("[sdbgp] kevent(EV_ADD ident=0x%x) failed: errno=%d\n",
                    SDBGP_KEV_IDENT, errno);
        close(xp->kq); xp->kq = -1;
        close(xp->fd); xp->fd = -1;
        return SDBGP_ERR_KQUEUE;
    }

    klog_printf("[sdbgp] transport ready: fd=%d kq=%d\n", xp->fd, xp->kq);
    return SDBGP_OK;
}

void sdbgp_xport_close(struct sdbgp_xport *xp)
{
    if (!xp) return;
    if (xp->kq >= 0) { close(xp->kq); xp->kq = -1; }
    if (xp->fd >= 0) { close(xp->fd); xp->fd = -1; }
}

int sdbgp_ping(struct sdbgp_xport *xp,
               uint32_t word0, uint32_t word1,
               struct sdbgp_readback_buf *out)
{
    if (!xp || xp->fd < 0) return SDBGP_ERR_OPEN;

    struct sdbgp_submit_buf sub = {
        .size = SDBGP_SUBMIT_SIZE_TAG,
        .word1 = word1,
        .word0 = word0,
    };

    xp->txn_ctr++;

    if (ioctl(xp->fd, SDBGP_IOCTL_A_11, &sub) < 0) {
        klog_printf("[sdbgp] A_11 (word0=0x%08x word1=0x%08x) failed: errno=%d\n",
                    word0, word1, errno);
        return SDBGP_ERR_SUBMIT;
    }

    struct sdbgp_readback_buf rb;
    memset(&rb, 0, sizeof(rb));
    if (ioctl(xp->fd, SDBGP_IOCTL_A_21, &rb) < 0) {
        klog_printf("[sdbgp] A_21 after submit failed: errno=%d\n", errno);
        return SDBGP_ERR_READBACK;
    }

    if (rb.size != SDBGP_READBACK_SIZE_TAG) {
        klog_printf("[sdbgp] A_21 size tag mismatch: got 0x%x, want 0x18\n",
                    rb.size);
        return SDBGP_ERR_SIZE_TAG;
    }

    klog_printf("[sdbgp] ping#%llu w0=0x%08x w1=0x%08x -> "
                "echo w0=0x%08x w1=0x%08x flags=0x%08x status=0x%016llx\n",
                (unsigned long long)xp->txn_ctr,
                word0, word1,
                rb.word0_echo, rb.word1_echo,
                rb.flags_const,
                (unsigned long long)rb.status);

    if (out) *out = rb;
    return SDBGP_OK;
}

int sdbgp_check_identity(struct sdbgp_xport *xp)
{
    if (!xp || xp->fd < 0) return SDBGP_ERR_OPEN;

    uint8_t buf[4096];
    ssize_t n = read(xp->fd, buf, sizeof(buf));
    if (n < 4) {
        klog_printf("[sdbgp] read(4096) returned %zd errno=%d\n", n, errno);
        return SDBGP_ERR_IDENTITY;
    }

    uint32_t magic;
    memcpy(&magic, buf, 4);
    klog_printf("[sdbgp] identity: read %zd bytes, first u32 = 0x%08x "
                "(want 0x%08x 'mp40')\n",
                n, magic, SDBGP_IDENTITY_MAGIC);

    return (magic == SDBGP_IDENTITY_MAGIC) ? SDBGP_OK : SDBGP_ERR_IDENTITY;
}
