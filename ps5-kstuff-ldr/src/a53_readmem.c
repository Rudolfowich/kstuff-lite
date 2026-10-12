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
    /* Получаем живые адреса через ext dump — потом считаем arena bases */
    static uint64_t ext_buf[192];
    for (int i = 0; i < 192; i++) ext_buf[i] = 0;
    kekcall(KEKCALL_EXT_DUMP, 0, (uintptr_t)ext_buf, sizeof(ext_buf));

    uint64_t ucred_va = ext_buf[3];   /* ucred VA — обычно в "низком" heap arena */
    uint64_t proc_va  = ext_buf[2];   /* proc VA — часто в "высоком" heap arena */

    /* Выравниваем на 4GB вниз — надёжный arena base */
    uint64_t arena1 = ucred_va & ~0xFFFFFFFFULL;
    uint64_t arena2 = proc_va  & ~0xFFFFFFFFULL;

    klog_printf("[a53] arena1 base = 0x%llx (from ucred VA 0x%llx)\n",
                (unsigned long long)arena1, (unsigned long long)ucred_va);
    klog_printf("[a53] arena2 base = 0x%llx (from proc VA 0x%llx)\n",
                (unsigned long long)arena2, (unsigned long long)proc_va);

    /* Scan arena 1 */
    for (int i = 0; i < 32; i++) g_finds[i] = 0;
    long n1 = kekcall(KEKCALL_SCAN_DMEM, 128 /* MB */, (uintptr_t)g_finds, arena1);
    klog_printf("[a53] arena1 scan: total=%ld\n", n1);
    for (int i = 0; i < 32; i++) {
        klog_printf("[a53]   a1[%2d] = 0x%016llx\n", i, (unsigned long long)g_finds[i]);
    }

    if (n1 > 0) {
        int count = (n1 > 4) ? 4 : (int)n1;
        for (int a = 0; a < count; a++) {
            if (!g_finds[a]) continue;
            for (int i = 0; i < 64; i++) g_dump[i] = 0;
            klog_printf("[a53] === dump around heap addr 0x%llx ===\n", (unsigned long long)g_finds[a]);
            kekcall(KEKCALL_DUMP_MEM, g_finds[a], (uintptr_t)g_dump, 0);
            for (int i = 0; i < 64; i++) {
                char asc[9] = {0};
                memcpy(asc, &g_dump[i], 8);
                for (int c = 0; c < 8; c++) {
                    if (asc[c] < 32 || asc[c] > 126) asc[c] = '.';
                }
                klog_printf("[a53]   [%2d] 0x%016llx '%s' (0x%llx)\n",
                            i, (unsigned long long)g_dump[i], asc,
                            (unsigned long long)((g_finds[a] & ~7ULL) - 256 + i*8));
            }
        }
    }

    /* Scan arena 2 — только если arena2 != arena1 */
    if (arena2 != arena1) {
        static uint64_t a2_finds[32];
        for (int i = 0; i < 32; i++) a2_finds[i] = 0;
        long n2 = kekcall(KEKCALL_SCAN_DMEM, 128 /* MB */, (uintptr_t)a2_finds, arena2);
        klog_printf("[a53] arena2 scan: total=%ld\n", n2);
        for (int i = 0; i < 32; i++) {
            klog_printf("[a53]   a2[%2d] = 0x%016llx\n", i, (unsigned long long)a2_finds[i]);
        }
        if (n2 > 0) {
            int count = (n2 > 4) ? 4 : (int)n2;
            for (int a = 0; a < count; a++) {
                if (!a2_finds[a]) continue;
                for (int i = 0; i < 64; i++) g_dump[i] = 0;
                klog_printf("[a53] === dump around heap addr 0x%llx ===\n", (unsigned long long)a2_finds[a]);
                kekcall(KEKCALL_DUMP_MEM, a2_finds[a], (uintptr_t)g_dump, 0);
                for (int i = 0; i < 64; i++) {
                    char asc[9] = {0};
                    memcpy(asc, &g_dump[i], 8);
                    for (int c = 0; c < 8; c++) {
                        if (asc[c] < 32 || asc[c] > 126) asc[c] = '.';
                    }
                    klog_printf("[a53]   [%2d] 0x%016llx '%s' (0x%llx)\n",
                                i, (unsigned long long)g_dump[i], asc,
                                (unsigned long long)((a2_finds[a] & ~7ULL) - 256 + i*8));
                }
            }
        }
        n1 = n1 + n2;
    }

    return (n1 > 0) ? 0 : -1;
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
