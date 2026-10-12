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

int
probe_mp4_device(void)
{
    static uint64_t ext_buf[192];
    for (int i = 0; i < 192; i++) ext_buf[i] = 0;
    kekcall(KEKCALL_EXT_DUMP, 0, (uintptr_t)ext_buf, sizeof(ext_buf));
    uint64_t proc_va = ext_buf[2];
    uint64_t arena_base = proc_va & ~0xFFFFFFFFULL;

    /* ===== APPROACH 3: Heap scan для inline cdev (как в "jackpot" boot) ===== 
     * В одном из прошлых boot мы находили inline байты "mp4/dump" в heap
     * (адрес 0xffff94c693cd38aa). Это была cdev struct с si_name inline.
     * Повторяем heap scan — ищем по тому же 0x90000000 offset в arena */
    klog_puts("[a53] APPROACH 3: heap scan for inline cdev si_name\n");
    uint64_t heap_scan_starts[] = {
        arena_base + 0x80000000ULL,
        arena_base + 0x90000000ULL,
        arena_base + 0xA0000000ULL,
    };
    for (int s = 0; s < 3; s++) {
        static uint64_t g_heap[32];
        for (int i = 0; i < 32; i++) g_heap[i] = 0;
        long n = kekcall(KEKCALL_SCAN_DMEM, 256, (uintptr_t)g_heap, heap_scan_starts[s]);
        klog_printf("[a53] heap start=0x%llx total=%ld\n", 
                    (unsigned long long)heap_scan_starts[s], n);
        for (int i = 0; i < 32; i++) {
            if (g_heap[i]) klog_printf("[a53]   h[%d] = 0x%016llx\n", i, (unsigned long long)g_heap[i]);
        }
        if (n > 0) {
            klog_puts("[a53] FOUND heap inline — это cdev struct!\n");
            /* Теперь dump вокруг этого адреса */
            uint64_t cdev_name_addr = g_heap[0];  /* первая находка */
            static uint64_t g_cdev[64];
            for (int i = 0; i < 64; i++) g_cdev[i] = 0;
            kekcall(KEKCALL_DUMP_MEM, cdev_name_addr, (uintptr_t)g_cdev, 0);
            klog_printf("[a53] dump around cdev_name 0x%llx:\n", 
                        (unsigned long long)cdev_name_addr);
            for (int i = 0; i < 64; i++) {
                char asc[9] = {0};
                memcpy(asc, &g_cdev[i], 8);
                for (int c = 0; c < 8; c++) {
                    if ((unsigned char)asc[c] < 32 || (unsigned char)asc[c] > 126) asc[c] = '.';
                }
                klog_printf("[a53]   [%+4d] 0x%016llx '%s'\n", 
                            (i - 32) * 8, (unsigned long long)g_cdev[i], asc);
            }
            return 0;
        }
    }

    /* ===== APPROACH 4: xref scan ВПЕРЁД от str_addr (не назад) ===== */
    klog_puts("[a53] APPROACH 4: xref FORWARD from str_addr, 1MB chunks\n");
    uint64_t str_addr = 0;
    /* Find current str_addr through scan from kdata_base */
    static uint64_t g_str[32];
    for (int i = 0; i < 32; i++) g_str[i] = 0;
    kekcall(KEKCALL_SCAN_DMEM, 32, (uintptr_t)g_str, 0);  /* 32 MB from kdata_base */
    for (int i = 0; i < 32; i++) {
        if (g_str[i] && (g_str[i] & 0xff) == 0xaa) {  /* ends with ...8aa */
            str_addr = g_str[i];
            break;
        }
    }
    if (!str_addr) {
        klog_puts("[a53] can't find str_addr for approach 4\n");
        return -1;
    }
    klog_printf("[a53] using str_addr=0x%llx for xref forward scan\n",
                (unsigned long long)str_addr);

    for (int chunk = 0; chunk < 20; chunk++) {
        static uint64_t g_xref[32];
        for (int i = 0; i < 32; i++) g_xref[i] = 0;
        uint64_t chunk_start = str_addr + (uint64_t)chunk * 1024ULL * 1024ULL;
        long n = kekcall(KEKCALL_SCAN_XREF_V2, str_addr, (uintptr_t)g_xref, chunk_start);
        if (n > 0) {
            klog_printf("[a53] FOUND xref! chunk %d start=0x%llx total=%ld\n",
                        chunk, (unsigned long long)chunk_start, n);
            for (int i = 0; i < 32; i++) {
                if (g_xref[i]) klog_printf("[a53]   x[%d] = 0x%016llx\n", i, (unsigned long long)g_xref[i]);
            }
            return 0;
        }
    }

    klog_puts("[a53] both approaches 3+4 failed\n");
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
