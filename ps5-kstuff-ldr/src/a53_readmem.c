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
find_mp4_cdevsw(void)
{
    uint64_t kbase = (uint64_t)kekcall(KEKCALL_GET_KBASE, 0, 0, 0);

    /* krodata = kbase
     * kdata = kbase + 0xD9D000 (~13.6 MB .rodata) */
    uint64_t rodata_start = kbase;
    uint64_t rodata_size  = 14ULL * 1024ULL * 1024ULL;  /* 14 MB .rodata */
    uint64_t data_start   = kbase + 0xD9D000ULL;

    klog_printf("[CDEV] scanning .rodata 0x%llx..0x%llx (14 MB) for 'mp4\\0'\n",
                (unsigned long long)rodata_start,
                (unsigned long long)(rodata_start + rodata_size));

    uint64_t mp4_strings[16] = {0};
    unsigned n_strings = 0;

    /* Всегда включаем подтвержденный адрес строки "mp4/dump" */
    uint64_t str_mp4_dump = kbase + 0x5D38AAULL;
    mp4_strings[n_strings++] = str_mp4_dump;
    klog_printf("[CDEV] candidate #0 (mp4/dump): 0x%llx\n", (unsigned long long)str_mp4_dump);

    for (uint64_t off = 0; off < rodata_size; off += 4096) {
        uint8_t buf[4096];
        for (int i = 0; i < 4096; i++) buf[i] = 0;
        if (kekcall(KEKCALL_DUMP_MEM, rodata_start + off, (uintptr_t)buf, 4096) != 0)
            continue;

        for (int i = 0; i + 4 < 4096; i++) {
            /* Любая "mp4\0" (без жесткого требования к предшествующему нулю) */
            if (buf[i] == 'm' && buf[i+1] == 'p' && buf[i+2] == '4' && buf[i+3] == '\0') {
                uint64_t addr = rodata_start + off + i;
                klog_printf("[CDEV] 'mp4\\0' @ 0x%llx\n", (unsigned long long)addr);
                if (n_strings < 16) mp4_strings[n_strings++] = addr;
            }
            /* Также проверим "a53\0" */
            else if (buf[i] == 'a' && buf[i+1] == '5' && buf[i+2] == '3' && buf[i+3] == '\0') {
                uint64_t addr = rodata_start + off + i;
                klog_printf("[CDEV] 'a53\\0' @ 0x%llx\n", (unsigned long long)addr);
                if (n_strings < 16) mp4_strings[n_strings++] = addr;
            }
        }
    }

    klog_printf("[CDEV] total %u target strings to check in .data\n", n_strings);

    /* Шаг 2: для каждой найденной строки — scan .data */
    for (unsigned k = 0; k < n_strings; k++) {
        klog_printf("[CDEV] scan .data for ptr to 0x%llx\n",
                    (unsigned long long)mp4_strings[k]);

        for (int chunk = 0; chunk < 24; chunk++) {
            uint64_t cs = data_start + chunk * 1024ULL * 1024ULL;
            uint64_t finds[16] = {0};
            long n = kekcall5(KEKCALL_SCAN_PTR_CUSTOM, (uintptr_t)finds, mp4_strings[k], 1, cs);
            if (n > 0) {
                klog_printf("[CDEV] chunk %d: %ld ptrs\n", chunk, n);
                for (int i = 0; i < 16; i++) {
                    if (finds[i]) {
                        /* finds[i] = адрес поля cdevsw.d_name */
                        /* d_name на offset +0x08 от начала cdevsw */
                        uint64_t cdevsw_addr = finds[i] - 0x08;
                        uint64_t d_open_addr = cdevsw_addr + 0x10;
                        klog_printf("[CDEV]   d_name_ptr @ 0x%llx (cdevsw @ 0x%llx, d_open at 0x%llx)\n",
                                    (unsigned long long)finds[i],
                                    (unsigned long long)cdevsw_addr,
                                    (unsigned long long)d_open_addr);

                        /* Dump полной cdevsw для верификации */
                        uint8_t cbuf[128];
                        if (kekcall(KEKCALL_DUMP_MEM, cdevsw_addr, (uintptr_t)cbuf, 128) == 0) {
                            klog_printf("[CDEV]   cdevsw dump:\n");
                            for (int b = 0; b < 128; b += 16) {
                                klog_printf("[CDEV]     +0x%02x: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                    b, cbuf[b], cbuf[b+1], cbuf[b+2], cbuf[b+3],
                                    cbuf[b+4], cbuf[b+5], cbuf[b+6], cbuf[b+7],
                                    cbuf[b+8], cbuf[b+9], cbuf[b+10], cbuf[b+11],
                                    cbuf[b+12], cbuf[b+13], cbuf[b+14], cbuf[b+15]);
                            }
                        }
                    }
                }
            }
            sleep(1);
        }
    }
    return 0;
}

int
test_mp4_open_with_root(void)
{
    uint64_t backup[4] = {0};

    klog_printf("[OPEN] attempting /dev/mp4/dump WITHOUT swap first (baseline)\n");
    int fd1 = open("/dev/mp4/dump", O_RDWR);
    int err1 = errno;
    klog_printf("[OPEN] baseline: fd=%d errno=%d\n", fd1, err1);
    if (fd1 >= 0) close(fd1);

    klog_printf("[OPEN] now with KEKCALL_SWAP_FULL (target_pid=1 root ucred)\n");
    /* args[RDI]=target_pid (1 = init/root), args[RSI]=user_buf (backup) */
    long sr = kekcall(KEKCALL_SWAP_FULL, 1, (uintptr_t)backup, 0);
    klog_printf("[OPEN] swap ret=%ld\n", sr);

    int fd2 = open("/dev/mp4/dump", O_RDWR);
    int err2 = errno;
    klog_printf("[OPEN] with-swap: fd=%d errno=%d\n", fd2, err2);

    /* args[RSI]=user_buf (backup) */
    long rr = kekcall(KEKCALL_RESTORE_FULL, 0, (uintptr_t)backup, 0);
    klog_printf("[OPEN] restored (ret=%ld)\n", rr);

    if (fd2 >= 0) {
        klog_printf("[OPEN] *** SUCCESS! /dev/mp4/dump opened with root ucred (fd=%d) ***\n", fd2);
        klog_printf("[OPEN] *** FPKG unlock = SWAP + open, no patching needed! ***\n");
        close(fd2);
        return 0;
    } else {
        klog_printf("[OPEN] blocked. errno=%d\n", err2);
        if (err2 == EPERM)
            klog_printf("[OPEN]   EPERM(1): check is NOT simply ucred-based or device has specific check\n");
        else if (err2 == EACCES)
            klog_printf("[OPEN]   EACCES(13): permission on device node\n");
        else if (err2 == ENODEV)
            klog_printf("[OPEN]   ENODEV(19): device driver not active\n");
        else if (err2 == EBUSY)
            klog_printf("[OPEN]   EBUSY(16): already open/busy\n");
        return -1;
    }
}

int
probe_mp4_device(void)
{
    test_mp4_open_with_root();
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
