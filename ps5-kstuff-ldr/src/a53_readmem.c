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
step_rodata_hunt(void)
{
    /* [1] РАСШИРИТЬ .rodata вокруг "mp4/dump": ищем "mp4_cdev_open" или "mp4_open" */
    uint64_t str_mp4_dump = 0xffffffff903138aaULL;
    /* dump 4 KB после mp4/dump (вперёд) */
    for (int chunk = 0; chunk < 4; chunk++) {
        uint64_t base = (str_mp4_dump + chunk * 1024) & ~7ULL;
        uint8_t buf[1024];
        for (int i = 0; i < 1024; i++) buf[i] = 0;
        long r = kekcall(KEKCALL_DUMP_MEM, base, (uintptr_t)buf, 1024);
        klog_printf("[RD] chunk %d base=0x%llx ret=%ld\n", chunk, (unsigned long long)base, r);
        /* ищем "mp4" в буфере */
        for (int i = 0; i + 16 < 1024; i++) {
            if (buf[i]=='m' && buf[i+1]=='p' && buf[i+2]=='4' && buf[i+3]=='_') {
                /* нашли mp4_ — печатаем имя */
                klog_printf("[RD] @ 0x%llx: ", (unsigned long long)(base + i));
                int j = 0;
                while (j < 48 && buf[i+j] >= 32 && buf[i+j] < 127) {
                    klog_printf("%c", buf[i+j]);
                    j++;
                }
                klog_printf("\n");
            }
        }
    }
    
    /* [2] Проверить 0x8f сегмент — последний невыясненный кандидат */
    {
        uint64_t addr = 0xffffffff8f2ea920ULL;
        uint8_t buf[128];
        for (int i = 0; i < 128; i++) buf[i] = 0;
        long r = kekcall(KEKCALL_DUMP_MEM, addr, (uintptr_t)buf, 128);
        klog_printf("[8F] 0x%llx ret=%ld\n", (unsigned long long)addr, r);
        for (int i = 0; i < 128; i += 16) {
            klog_printf("[8F] +0x%02x: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x | %c%c%c%c%c%c%c%c%c%c%c%c%c%c%c%c\n",
                i,
                buf[i], buf[i+1], buf[i+2], buf[i+3], buf[i+4], buf[i+5], buf[i+6], buf[i+7],
                buf[i+8], buf[i+9], buf[i+10], buf[i+11], buf[i+12], buf[i+13], buf[i+14], buf[i+15],
                (buf[i]>=32&&buf[i]<127)?buf[i]:'.',
                (buf[i+1]>=32&&buf[i+1]<127)?buf[i+1]:'.',
                (buf[i+2]>=32&&buf[i+2]<127)?buf[i+2]:'.',
                (buf[i+3]>=32&&buf[i+3]<127)?buf[i+3]:'.',
                (buf[i+4]>=32&&buf[i+4]<127)?buf[i+4]:'.',
                (buf[i+5]>=32&&buf[i+5]<127)?buf[i+5]:'.',
                (buf[i+6]>=32&&buf[i+6]<127)?buf[i+6]:'.',
                (buf[i+7]>=32&&buf[i+7]<127)?buf[i+7]:'.',
                (buf[i+8]>=32&&buf[i+8]<127)?buf[i+8]:'.',
                (buf[i+9]>=32&&buf[i+9]<127)?buf[i+9]:'.',
                (buf[i+10]>=32&&buf[i+10]<127)?buf[i+10]:'.',
                (buf[i+11]>=32&&buf[i+11]<127)?buf[i+11]:'.',
                (buf[i+12]>=32&&buf[i+12]<127)?buf[i+12]:'.',
                (buf[i+13]>=32&&buf[i+13]<127)?buf[i+13]:'.',
                (buf[i+14]>=32&&buf[i+14]<127)?buf[i+14]:'.',
                (buf[i+15]>=32&&buf[i+15]<127)?buf[i+15]:'.');
        }
    }
    return 0;
}

int
smart_xref_scan(void)
{
    /* Динамический адрес строки "mp4/dump" для текущей сессии KASLR */
    uint64_t str_mp4 = 0;
    static uint64_t g_str[32];
    for (int i = 0; i < 32; i++) g_str[i] = 0;
    kekcall(KEKCALL_SCAN_DMEM, 32, (uintptr_t)g_str, 0);
    for (int i = 0; i < 32; i++) {
        if (g_str[i] && (g_str[i] & 0xff) == 0xaa) {
            str_mp4 = g_str[i];
            break;
        }
    }
    if (!str_mp4) {
        str_mp4 = 0xffffffff90fe38aaULL;
    }

    uint64_t kbase = (uint64_t)kekcall(KEKCALL_GET_KBASE, 0, 0, 0);

    /* .text основного ядра: от (kbase - 0xA68000 & ~0xFFF) до kbase.
     * Это гарантированно замапленный регион с copyin / doreti_iret. */
    uint64_t text_start = (kbase - 0xA68000ULL) & ~0xFFFULL;
    uint64_t text_end   = kbase;

    klog_printf("[XR] kdata_base = 0x%llx, scan .text 0x%llx..0x%llx for xref to 0x%llx\n",
                (unsigned long long)kbase,
                (unsigned long long)text_start,
                (unsigned long long)text_end,
                (unsigned long long)str_mp4);

    /* Сканируем .text шагами по 64 KB, чтобы ни при каких условиях не триггерить watchdog ядра */
    uint64_t chunk_step = 64ULL * 1024ULL;
    uint32_t total_chunks = (uint32_t)((text_end - text_start) / chunk_step);

    klog_printf("[XR] scanning %u chunks (64 KB each) with safe-probe\n", total_chunks);

    for (uint32_t chunk = 0; chunk < total_chunks; chunk++) {
        uint64_t cs = text_start + (uint64_t)chunk * chunk_step;

        /* SAFE PROBE: проверяем доступность адреса cs перед сканированием */
        uint64_t probe = 0;
        if (kekcall(KEKCALL_SAFE_PEEK, cs, (uintptr_t)&probe, 0) != 0) {
            continue;
        }

        uint64_t finds[16] = {0};
        /* kekcall5(22, target, user_buf, start_abs, chunk_bytes=64KB) */
        long n = kekcall5(KEKCALL_SCAN_XREF_V2, str_mp4, (uintptr_t)finds, cs, chunk_step);

        if (n > 0) {
            klog_printf("[XR] chunk %u @ 0x%llx: %ld xrefs\n",
                        chunk, (unsigned long long)cs, n);
            for (int i = 0; i < 16; i++) {
                if (finds[i]) {
                    uint64_t rip = finds[i];
                    klog_printf("[XR]   xref @ 0x%llx\n", (unsigned long long)rip);

                    /* Dump 128 bytes вокруг xref (-64 .. +64) для проверки пролога и контекста */
                    uint64_t base = (rip - 64) & ~7ULL;
                    uint8_t buf[128];
                    for (int b = 0; b < 128; b++) buf[b] = 0;
                    if (kekcall(KEKCALL_DUMP_MEM, base, (uintptr_t)buf, 128) == 0) {
                        klog_printf("[XR]   code dump @ 0x%llx:\n", (unsigned long long)base);
                        for (int b = 0; b < 128; b += 16) {
                            klog_printf("[XR]     +0x%02x: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                b,
                                buf[b], buf[b+1], buf[b+2], buf[b+3],
                                buf[b+4], buf[b+5], buf[b+6], buf[b+7],
                                buf[b+8], buf[b+9], buf[b+10], buf[b+11],
                                buf[b+12], buf[b+13], buf[b+14], buf[b+15]);
                        }
                    }
                }
            }
        }

        /* Каждые 16 чанков (1 МБ) даем короткую паузу планировщику */
        if ((chunk & 0x0F) == 0) {
            usleep(5000);  /* 5 мс */
        }
    }
    return 0;
}

int
probe_mp4_device(void)
{
    smart_xref_scan();
    return 0;
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

    /* Device probe (runs xref_scan_text) */
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
