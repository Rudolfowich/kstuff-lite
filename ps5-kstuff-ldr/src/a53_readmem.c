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


int
probe_mp4_device(void)
{
    /* 1. Найти str_addr */
    uint64_t str_addr = 0;
    static uint64_t g_str[32];
    for (int i = 0; i < 32; i++) g_str[i] = 0;
    kekcall(KEKCALL_SCAN_DMEM, 32, (uintptr_t)g_str, 0);
    for (int i = 0; i < 32; i++) {
        if (g_str[i] && (g_str[i] & 0xff) == 0xaa) {
            str_addr = g_str[i];
            break;
        }
    }
    if (!str_addr) {
        klog_puts("[a53] can't find str_addr\n");
        return -1;
    }
    klog_printf("[a53] str_addr = 0x%llx\n", (unsigned long long)str_addr);

    /* ===== APPROACH 1 EXTENDED: ptr scan .data 64 MB вперёд от kdata_base ===== */
    klog_puts("[a53] APPROACH 1 EXTENDED: ptr scan .data forward 64MB\n");
    static uint64_t g_p[32];
    for (int i = 0; i < 32; i++) g_p[i] = 0;
    long np = kekcall(KEKCALL_SCAN_PTR, (uintptr_t)g_p, str_addr, 64);
    klog_printf("[a53] ptr scan 64MB: total=%ld\n", np);
    for (int i = 0; i < 32; i++) {
        if (g_p[i]) klog_printf("[a53]   ptr[%d] = 0x%016llx\n", i, (unsigned long long)g_p[i]);
    }
    if (np > 0) return 0;

    /* ===== APPROACH 5: xref НАЗАД chunks 1MB x 60 — расширили до 60 MB ===== */
    klog_puts("[a53] APPROACH 5 EXTENDED: xref backward chunks 1MB x 60\n");
    for (int chunk = 1; chunk <= 60; chunk++) {
        static uint64_t g_xref[32];
        for (int i = 0; i < 32; i++) g_xref[i] = 0;
        uint64_t cs = str_addr - (uint64_t)chunk * 1024ULL * 1024ULL;
        long n = kekcall(KEKCALL_SCAN_XREF_V2, str_addr, (uintptr_t)g_xref, cs);
        if (n > 0) {
            klog_printf("[a53] FOUND! chunk -%d start=0x%llx total=%ld\n",
                        chunk, (unsigned long long)cs, n);
            for (int i = 0; i < 32; i++) {
                if (g_xref[i]) klog_printf("[a53]   x[%d] = 0x%016llx\n", i, (unsigned long long)g_xref[i]);
            }
            return 0;
        }
        /* Печатаем каждые 10 chunks для прогресса */
        if (chunk % 10 == 0) {
            klog_printf("[a53] scanned -%d MB, still 0 finds\n", chunk);
        }
    }

    /* ===== APPROACH 6: ptr scan .data НАЗАД от kdata_base 32 MB =====
     * На случай если .data размещена ПЕРЕД kdata_base */
    klog_puts("[a53] APPROACH 6: ptr scan .data BACKWARD 32MB\n");
    int64_t offset_back = -(32LL * 1024 * 1024);
    for (int i = 0; i < 32; i++) g_p[i] = 0;
    long np_back = kekcall5(KEKCALL_SCAN_PTR_CUSTOM, (uintptr_t)g_p, str_addr, 32, (uint64_t)offset_back);
    klog_printf("[a53] ptr scan 32MB backward: total=%ld\n", np_back);
    for (int i = 0; i < 32; i++) {
        if (g_p[i]) klog_printf("[a53]   ptr_back[%d] = 0x%016llx\n", i, (unsigned long long)g_p[i]);
    }
    if (np_back > 0) return 0;

    klog_puts("[a53] all approaches: 0 найдено\n");
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
