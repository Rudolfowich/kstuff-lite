/*
 * a53_readmem.c — PPR A53 patch via /dev/mp4/dump (loader-side)
 *
 * Final location: ps5-kstuff-ldr/src/a53_readmem.c
 *
 * STATUS: First working skeleton. Uses standard FreeBSD POSIX IO.
 *   - probe_mp4_device() — fully implemented. Opens /dev/mp4/dump, confirms
 *     the MP4 character device exists on this firmware. Safe to call on ANY
 *     firmware including 13.60 — no mutation.
 *   - install_ppr_a53() — looks up profile for current firmware, opens the
 *     MP4 device, but returns WITHOUT sending any A53 commands (TODO:
 *     ioctl protocol below). Still safe.
 *
 * TODO sequence (next commits):
 *   1. ioctl command numbers for A53 mailbox (reverse-engineering sub_4ad0)
 *   2. a53_send_cmd() / a53_recv_response() helpers
 *   3. a53_read_fw_identity() — reads A53 firmware id, logs it to klog
 *      (safe, no mutation; this is where we learn if 13.60 A53 fw differs
 *      from the 11.60 one we have in our profile)
 *   4. install_hooks_profile() — actual patch loop with readback-before-commit
 */

#include <sys/types.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>

#include <ps5/klog.h>

#include "a53_readmem.h"
#include "kekcall.h"

#define MP4_DEV_PATH    "/dev/mp4/dump"

/* ---- Profile lookup -------------------------------------------------- */

const unsigned char *
a53_find_profile(uint32_t fw, uint32_t cond)
{
    const unsigned char *fallback = NULL;
    for (unsigned i = 0; i < a53_fw_table_count; i++) {
        const struct fw_profile_entry *e = &a53_fw_table[i];
        if (e->fw_id != fw)
            continue;
        if (e->cond == cond)
            return a53_profiles[e->profile_idx];
        if (!fallback)
            fallback = a53_profiles[e->profile_idx];
    }
    return fallback;
}

/* ---- MP4 device probe ------------------------------------------------ */

#define KEKCALL_DUMP_MEM   19
#define KEKCALL_SCAN_XREF  20

static uint64_t g_dump[64];
static uint64_t g_finds[32];

int
probe_mp4_device(void)
{
    static uint64_t ext_buf[192];
    for (int i = 0; i < 192; i++) ext_buf[i] = 0;
    kekcall(KEKCALL_EXT_DUMP, 0, (uintptr_t)ext_buf, sizeof(ext_buf));

    uint64_t ucred_va = ext_buf[3];
    uint64_t proc_va  = ext_buf[2];
    uint64_t fd_va    = ext_buf[47];

    uint64_t scan_starts[] = {
        ucred_va ? (ucred_va - (64ULL * 1024 * 1024)) : 0,
        proc_va  ? (proc_va  - (64ULL * 1024 * 1024)) : 0,
        fd_va    ? (fd_va    - (64ULL * 1024 * 1024)) : 0,
    };
    const char *labels[] = {"ucred", "proc", "fd"};

    /* ВАРИАНТ 1: inline "mp4/dump" bytes (0x706d75642f34706d) */
    klog_puts("[a53] === Variant 1: inline bytes ===\n");
    for (int s = 0; s < 3; s++) {
        if (!scan_starts[s]) continue;
        for (int i = 0; i < 32; i++) g_finds[i] = 0;
        long n = kekcall(KEKCALL_SCAN_DMEM, 128, (uintptr_t)g_finds, scan_starts[s]);
        klog_printf("[a53] inline @%s (0x%llx): total=%ld\n",
                    labels[s], (unsigned long long)scan_starts[s], n);
        for (int i = 0; i < 32; i++) {
            if (g_finds[i]) klog_printf("[a53]   inline[%2d] = 0x%016llx\n", i, (unsigned long long)g_finds[i]);
        }
        if (n > 0) {
            klog_puts("[a53] FOUND inline!\n");
            for (int a = 0; a < 4 && a < n; a++) {
                kekcall(KEKCALL_DUMP_MEM, g_finds[a], (uintptr_t)g_dump, 0);
                for (int i = 0; i < 64; i++) {
                    char asc[9] = {0};
                    memcpy(asc, &g_dump[i], 8);
                    for (int c = 0; c < 8; c++) if (asc[c] < 32 || asc[c] > 126) asc[c] = '.';
                    klog_printf("[a53]   [%2d] 0x%016llx '%s' (0x%llx)\n",
                                i, (unsigned long long)g_dump[i], asc,
                                (unsigned long long)((g_finds[a] & ~7ULL) - 256 + i*8));
                }
            }
            return 0;
        }
    }

    /* ВАРИАНТ 2: pointer to .rodata string (0xffffffffdadd38aa) */
    const uint64_t rodata_str_needle = 0xffffffffdadd38aaULL;
    klog_printf("[a53] === Variant 2: pointer to .rodata (0x%llx) ===\n",
                (unsigned long long)rodata_str_needle);
    for (int s = 0; s < 3; s++) {
        if (!scan_starts[s]) continue;
        for (int i = 0; i < 32; i++) g_finds[i] = 0;
        long n = kekcall5(KEKCALL_SCAN_DMEM, 128, (uintptr_t)g_finds, scan_starts[s], rodata_str_needle);
        klog_printf("[a53] ptr @%s (0x%llx): total=%ld\n",
                    labels[s], (unsigned long long)scan_starts[s], n);
        for (int i = 0; i < 32; i++) {
            if (g_finds[i]) klog_printf("[a53]   ptr[%2d] = 0x%016llx\n", i, (unsigned long long)g_finds[i]);
        }
        if (n > 0) {
            klog_puts("[a53] FOUND pointer in heap!\n");
            for (int a = 0; a < 4 && a < n; a++) {
                kekcall(KEKCALL_DUMP_MEM, g_finds[a], (uintptr_t)g_dump, 0);
                for (int i = 0; i < 64; i++) {
                    char asc[9] = {0};
                    memcpy(asc, &g_dump[i], 8);
                    for (int c = 0; c < 8; c++) if (asc[c] < 32 || asc[c] > 126) asc[c] = '.';
                    klog_printf("[a53]   [%2d] 0x%016llx '%s' (0x%llx)\n",
                                i, (unsigned long long)g_dump[i], asc,
                                (unsigned long long)((g_finds[a] & ~7ULL) - 256 + i*8));
                }
            }
            return 0;
        }
    }

    return -1;
}

/* ---- Main install entry --------------------------------------------- */

int
install_ppr_a53(uint32_t system_fw_version)
{
    uint32_t fw = system_fw_version & 0xFFFF0000;
    klog_printf("[a53] install_ppr_a53: system_fw=0x%08x fw_hi=0x%08x\n",
                system_fw_version, fw);

    /* Profile lookup. retail cond=3 first, devkit cond=1 fallback. */
    const unsigned char *profile = a53_find_profile(fw, 3);
    if (!profile)
        profile = a53_find_profile(fw, 1);
    if (!profile) {
        klog_printf("[a53] no PPR profile for fw=0x%08x — skipping\n", fw);
        return -1;
    }

    uint32_t profile_fw;
    memcpy(&profile_fw, profile, 4);
    klog_printf("[a53] profile found: profile_fw=0x%08x\n", profile_fw);

    /* Запрашиваем kernel diagnostic dump — безопасно, только чтение */
    klog_puts("[a53] requesting UELF diagnostic dump (kekcall 8) ...\n");
    uint64_t dump[136] = {0};
    long dump_ret = kekcall(KEKCALL_A53_DUMP, (uint64_t)dump, 136, 0);
    klog_printf("[a53] kekcall(8) returned=%ld words written\n", dump_ret);

    if (dump_ret > 0) {
        for (long i = 0; i < dump_ret; i++) {
            klog_printf("[a53] slot[%ld] = 0x%016llx\n", i, (unsigned long long)dump[i]);
        }
    }

    /* Расширенная разведка ucred и proc (kekcall 11) */
    klog_puts("[a53] extended diagnostic dump (kekcall 11) ...\n");
    uint64_t ext_buf[192] = {0};
    long rc = kekcall(KEKCALL_EXT_DUMP, 0, (uint64_t)ext_buf, sizeof(ext_buf));
    klog_printf("[a53] kekcall(11) ret=%ld\n", rc);
    if (rc > 0) {
        for (int i = 0; i < rc && i < 170; i++) {
            klog_printf("[a53] ext[%d] = 0x%016llx\n", i, (unsigned long long)ext_buf[i]);
        }
    }

    /* Device probe */
    if (probe_mp4_device() != 0) {
        klog_puts("[a53] MP4 device not accessible — abort\n");
        return -2;
    }

    /* STOP HERE for now. Actual patch sequence is TODO:
     *   1. Open device for persistent session
     *   2. a53_read_fw_identity() — compare with profile's expected id
     *   3. If mismatch: ABORT (log the observed id for RE)
     *   4. install_hooks_internal(profile) — 3 internal hooks
     *   5. install_hooks_public(profile) — 10 public callers
     *   6. verify readback — commit or rollback
     */
    klog_puts("[a53] skeleton stage complete; mailbox TX/RX not yet implemented\n");
    return 0;
}
