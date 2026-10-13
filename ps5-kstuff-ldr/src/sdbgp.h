/*
 * sdbgp.h — SDBGP (A53 secure debug ping) transport over /dev/mp4/dump.
 *
 * CORRECTED model (prior drafts had fictional 'PPRP' descriptor at softc+0x740):
 *
 * Protocol is **two ioctls** on /dev/mp4/dump:
 *
 *   A_11 (0x800c410b) — SUBMIT. 12-byte user buffer:
 *     offset 0: u32 size = 0x0c  (kernel validates == 12)
 *     offset 4: u32 word1       (goes to mbox[1])
 *     offset 8: u32 word0       (goes to mbox[0])
 *   Kernel then builds cmd_word = (softc[0x4f0] & 0xFEED0000) | 0x01120212,
 *   writes it to softc+0x4f4, and if softc+0x4ec==0 doorbells the HW mailbox
 *   via memcpy to softc+0x740 (MMIO ptr). Sets softc+0x4e2=1 (write-done).
 *
 *   A_21 (0x40184115) — READBACK. Kernel writes 24 bytes to user:
 *     offset 0x00: u32 size = 0x18
 *     offset 0x04: u32 word1 echo (mbox[1])
 *     offset 0x08: u32 word0 echo (mbox[0])
 *     offset 0x0c: u32 const  = 0x10002
 *     offset 0x10: u64 status with (softc[0x4ec] & 0xffff) in low 16 bits;
 *                  high bits = 0x01000000FFFE0000 on path B (softc[0x4ec]&8),
 *                  else 0.
 *
 * Async completion is signalled via kqueue on the fd (test6 uses
 * EV_ADD, ident=0x1ffff). The kqueue is OPTIONAL for simple pings — A_21
 * will return current softc state regardless.
 *
 * test6's probe_mp4_device_init sends A_11 with {12, 0, 0} — pure handshake.
 * The actual READMEM / WRITE_MEMORY (word0, word1) pairs are TBD (pending
 * reverse of install_ppr_a53 body).
 *
 * NO 'PPRP' magic exists anywhere — kernel never checks for 0x50525050.
 */

#pragma once
#include <sys/types.h>
#include <stdint.h>

/* ---- ioctl command numbers (group 'A', SOLID from kernel) ----------- */
#define SDBGP_IOCTL_A_11  0x800c410bU  /* OUT 12 B — submit (word0,word1) */
#define SDBGP_IOCTL_A_21  0x40184115U  /* IN  24 B — readback status      */
#define SDBGP_IOCTL_A_15  0x8008410fU  /* OUT  8 B — reset path           */
#define SDBGP_IOCTL_A_23  0x40204117U  /* IN  32 B — readback incl. global */
#define SDBGP_IOCTL_A_31  0x4008411fU  /* IN   8 B — read&set softc[0x4e0] */
#define SDBGP_IOCTL_A_32  0x40084120U  /* IN   8 B — read&clear softc[0x4e0] */
#define SDBGP_IOCTL_A_14  0x8014410dU  /* OUT 20 B — region define submit */

/* ---- Byte-exact A_11 submit buffer ---------------------------------- */
struct __attribute__((packed)) sdbgp_submit_buf {
    uint32_t size;    /* must be 12 */
    uint32_t word1;   /* goes to mbox[1] */
    uint32_t word0;   /* goes to mbox[0] */
};
_Static_assert(sizeof(struct sdbgp_submit_buf) == 12, "A_11 is 12 bytes");

#define SDBGP_SUBMIT_SIZE_TAG  0x0c

/* ---- Byte-exact A_21 readback buffer -------------------------------- */
struct __attribute__((packed)) sdbgp_readback_buf {
    uint32_t size;      /* kernel sets to 0x18 */
    uint32_t word1_echo;
    uint32_t word0_echo;
    uint32_t flags_const;  /* always 0x10002 */
    uint64_t status;       /* (softc[0x4ec] & 0xffff) | path_bits */
};
_Static_assert(sizeof(struct sdbgp_readback_buf) == 24, "A_21 is 24 bytes");

#define SDBGP_READBACK_SIZE_TAG    0x18
#define SDBGP_READBACK_FLAGS_CONST 0x10002

/* kqueue identity test6 uses (optional for sync pings). */
#define SDBGP_KEV_IDENT   0x1ffff

/* test6 handshake probe constant (byte-exact from .rodata template). */
static const struct sdbgp_submit_buf SDBGP_HANDSHAKE_PROBE = {
    .size = SDBGP_SUBMIT_SIZE_TAG, .word1 = 0, .word0 = 0,
};

/* read()-check identity: after probe, first 4 bytes of a 4 KiB read()
 * from the fd must be ASCII 'mp40' (0x3034706d LE). */
#define SDBGP_IDENTITY_MAGIC  0x3034706dU  /* 'mp40' LE */

/* ---- Return codes --------------------------------------------------- */
enum sdbgp_result {
    SDBGP_OK = 0,
    SDBGP_ERR_OPEN       = -1,
    SDBGP_ERR_KQUEUE     = -2,
    SDBGP_ERR_SUBMIT     = -3,  /* A_11 ioctl failed */
    SDBGP_ERR_READBACK   = -4,  /* A_21 ioctl failed */
    SDBGP_ERR_IDENTITY   = -5,  /* identity 'mp40' mismatch after probe */
    SDBGP_ERR_SIZE_TAG   = -6,  /* A_21 size tag != 0x18 */
    SDBGP_ERR_NOT_IMPL   = -42,
};

/* Transport handle — one per /dev/mp4/dump session. */
struct sdbgp_xport {
    int fd;
    int kq;
    uint64_t txn_ctr;
};

/* ---- Public API ----------------------------------------------------- */

int  sdbgp_xport_open(struct sdbgp_xport *xp);
void sdbgp_xport_close(struct sdbgp_xport *xp);

/* Submit one A_11 (word0, word1) pair and read back 24-byte A_21 result.
 * SOLID for the ioctl mechanics. The command-word space (what word0/word1
 * pairs mean to the A53) is still TBD. */
int sdbgp_ping(struct sdbgp_xport *xp,
               uint32_t word0, uint32_t word1,
               struct sdbgp_readback_buf *out);

/* Read 4 KiB from the device fd and verify first 4 bytes are 'mp40'. */
int sdbgp_check_identity(struct sdbgp_xport *xp);
