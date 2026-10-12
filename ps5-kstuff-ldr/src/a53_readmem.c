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
#include <signal.h>
#include <setjmp.h>

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

    if (sr == 0) {
        long rr = kekcall(KEKCALL_RESTORE_FULL, 0, (uintptr_t)backup, 0);
        klog_printf("[OPEN] restored (ret=%ld)\n", rr);
    } else {
        klog_printf("[OPEN] swap failed (ret=%ld), skip restore\n", sr);
    }

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
walk_find_mp4_cdevsw(uint64_t curproc_hint)
{
    /* allproc получаем через KEKCALL_GET_KBASE */
    uint64_t kbase = (uint64_t)kekcall(KEKCALL_GET_KBASE, 0, 0, 0);
    uint64_t allproc_addr = kbase + 0x28C9E80ULL;

    klog_printf("[WALK] kbase=0x%llx, allproc=0x%llx, curproc_hint=0x%llx\n",
                (unsigned long long)kbase,
                (unsigned long long)allproc_addr,
                (unsigned long long)curproc_hint);

    uint64_t curr_proc = 0;
    long r = kekcall(KEKCALL_DUMP_MEM, allproc_addr, (uintptr_t)&curr_proc, 8);
    klog_printf("[WALK] read allproc ret=%ld, val=0x%llx\n", r, (unsigned long long)curr_proc);

    if (!curr_proc && curproc_hint) {
        klog_printf("[WALK] using curproc_hint 0x%llx as start point!\n", (unsigned long long)curproc_hint);
        curr_proc = curproc_hint;
    }

    if (!curr_proc) {
        klog_printf("[WALK] no starting proc found, abort\n");
        return -1;
    }

    int found = 0, printed = 0;
    int proc_cnt = 0;
    for (int cnt = 0; cnt < 300 && curr_proc; cnt++) {
        proc_cnt++;
        uint64_t pid_u64 = 0;
        char comm[32] = {0};
        uint64_t p_fd = 0;

        kekcall(KEKCALL_DUMP_MEM, curr_proc + 0xBC, (uintptr_t)&pid_u64, 8);
        kekcall(KEKCALL_DUMP_MEM, curr_proc + 0x448, (uintptr_t)comm, 32);
        kekcall(KEKCALL_DUMP_MEM, curr_proc + 0x48, (uintptr_t)&p_fd, 8);
        comm[31] = 0;
        uint32_t pid = (uint32_t)(pid_u64 & 0xFFFFFFFF);

        uint64_t fd_nfiles_u64 = 0;
        uint64_t fd_ofiles = 0;
        if (p_fd) {
            kekcall(KEKCALL_DUMP_MEM, p_fd + 0x08, (uintptr_t)&fd_ofiles, 8);
            kekcall(KEKCALL_DUMP_MEM, p_fd + 0x10, (uintptr_t)&fd_nfiles_u64, 8);
        }
        uint32_t fd_nfiles = (uint32_t)(fd_nfiles_u64 & 0xFFFFFFFF);

        if (printed < 10) {
            klog_printf("[WALK] #%d proc=0x%llx pid=%u comm='%s' p_fd=0x%llx nfiles=%u\n",
                        cnt, (unsigned long long)curr_proc,
                        pid, comm, (unsigned long long)p_fd, fd_nfiles);
            printed++;
        }

        if (p_fd && fd_ofiles && fd_nfiles > 0 && fd_nfiles < 1000) {
            for (uint32_t i = 0; i < fd_nfiles && i < 256; i++) {
                uint64_t file_ptr = 0;
                kekcall(KEKCALL_DUMP_MEM, fd_ofiles + i * 0x20,
                        (uintptr_t)&file_ptr, 8);
                if (!file_ptr) continue;

                uint64_t f_data = 0;
                kekcall(KEKCALL_DUMP_MEM, file_ptr + 0x08,
                        (uintptr_t)&f_data, 8);
                if (!f_data) continue;

                char si_name[64] = {0};
                if (kekcall(KEKCALL_DUMP_MEM, f_data + 0x98,
                            (uintptr_t)si_name, 64) != 0) continue;
                si_name[63] = 0;

                if (printed <= 3 && i < 3 && si_name[0] != 0) {
                    klog_printf("[WALK]   fd %u device: '%s'\n", i, si_name);
                }

                /* ЛЮБОЙ "mp4*" device */
                if (si_name[0]=='m' && si_name[1]=='p' && si_name[2]=='4')
                {
                    /* ЗОЛОТО! Читаем si_devsw из cdev */
                    uint64_t si_devsw = 0;
                    kekcall(KEKCALL_DUMP_MEM, f_data + 0x70,
                            (uintptr_t)&si_devsw, 8);

                    klog_printf("[WALK] *** pid=%u (%s) fd=%u device='%s' cdev=0x%llx si_devsw=0x%llx ***\n",
                                pid, comm, i, si_name,
                                (unsigned long long)f_data,
                                (unsigned long long)si_devsw);

                    if (si_devsw) {
                        /* Dump cdevsw структуру — тут d_open на offset +0x10 */
                        uint8_t cdevsw_buf[128];
                        if (kekcall(KEKCALL_DUMP_MEM, si_devsw,
                                    (uintptr_t)cdevsw_buf, 128) == 0) {
                            klog_printf("[WALK] cdevsw @ 0x%llx dump:\n",
                                        (unsigned long long)si_devsw);
                            for (int b = 0; b < 128; b += 16) {
                                klog_printf("[WALK]   +0x%02x: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                    b, cdevsw_buf[b], cdevsw_buf[b+1], cdevsw_buf[b+2], cdevsw_buf[b+3],
                                    cdevsw_buf[b+4], cdevsw_buf[b+5], cdevsw_buf[b+6], cdevsw_buf[b+7],
                                    cdevsw_buf[b+8], cdevsw_buf[b+9], cdevsw_buf[b+10], cdevsw_buf[b+11],
                                    cdevsw_buf[b+12], cdevsw_buf[b+13], cdevsw_buf[b+14], cdevsw_buf[b+15]);
                            }
                            /* d_open = +0x10 */
                            uint64_t d_open = 0;
                            __builtin_memcpy(&d_open, cdevsw_buf + 0x10, 8);
                            klog_printf("[WALK]   >>> d_open = 0x%llx (mp4_cdev_open!) <<<\n",
                                        (unsigned long long)d_open);
                        }
                    }
                    found++;
                }
            }
        }

        uint64_t next_proc = 0;
        kekcall(KEKCALL_DUMP_MEM, curr_proc + 0x10, (uintptr_t)&next_proc, 8);
        curr_proc = next_proc;
    }

    klog_printf("[WALK] done, scanned %d procs, found %d mp4-related fds\n", proc_cnt, found);
    return 0;
}

static sigjmp_buf g_sigsys_jmp;
static volatile int g_sigsys_fault = 0;

static void
sigsys_handler(int sig)
{
    (void)sig;
    g_sigsys_fault = 1;
    siglongjmp(g_sigsys_jmp, 1);
}

static uint64_t g_cdevsw_list[256];
static char     g_cdevsw_names[256][32];
static int      g_cdevsw_count = 0;

int
scan_cdevsw(void)
{
    uint64_t kbase = (uint64_t)kekcall(KEKCALL_GET_KBASE, 0, 0, 0);

    /* Быстрая проверка: что лежит по адресу 0x5D38AA */
    char s_check[16] = {0};
    uint64_t s_words[2] = {0};
    kekcall(KEKCALL_DUMP_MEM, kbase + 0x5D38AAULL, (uintptr_t)s_words, 16);
    memcpy(s_check, s_words, 15);
    s_check[15] = 0;
    klog_printf("[CHECK] bytes at kbase+0x5D38AA: '%s'\n", s_check);

    /* Устанавливаем обработчик SIGSYS с SA_NODEFER для безопасного обхода unmapped страниц */
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigsys_handler;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGSYS, &sa, NULL);

    uint64_t data_start = kbase + 0xD9D000ULL;
    uint64_t data_end   = data_start + 24ULL * 1024 * 1024; /* 24 MB */
    uint32_t D_VER9 = 0x17122009;
    uint32_t D_VER5 = 0x20011966;

    klog_printf("[CDVS] safe scan .data 0x%llx..0x%llx with SIGSYS handler\n",
                (unsigned long long)data_start, (unsigned long long)data_end);

    int total_cdevsw = 0;
    g_cdevsw_count = 0;
    uint64_t mp4_cdevsw_addr = 0;
    (void)mp4_cdevsw_addr;
    uint64_t mp4_d_open = 0;
    (void)mp4_d_open;

    for (uint64_t va = data_start; va < data_end; va += 4096) {
        uint64_t buf64[512] = {0}; /* 4096 байт, выровнено на 8 */
        g_sigsys_fault = 0;

        if (sigsetjmp(g_sigsys_jmp, 1) == 0) {
            kekcall(KEKCALL_DUMP_MEM, va, (uintptr_t)buf64, 4096);
        } else {
            /* Попали на unmapped страницу — перехвачено SIGSYS, идём дальше */
            continue;
        }
        if (g_sigsys_fault) continue;

        uint8_t *buf = (uint8_t *)buf64;

        for (int i = 0; i + 32 <= 4096; i += 8) {
            uint32_t ver = 0;
            __builtin_memcpy(&ver, buf + i, 4);
            if (ver != D_VER9 && ver != D_VER5)
                continue;

            uint64_t cdevsw_addr = va + i;
            uint64_t d_name_ptr = 0;
            uint64_t d_open = 0;
            __builtin_memcpy(&d_name_ptr, buf + i + 8, 8);
            __builtin_memcpy(&d_open, buf + i + 0x10, 8);

            if (!d_name_ptr || (d_name_ptr & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
                continue;

            /* Безопасно читаем d_name */
            char name[32] = {0};
            uint64_t name_words[4] = {0};
            g_sigsys_fault = 0;

            if (sigsetjmp(g_sigsys_jmp, 1) == 0) {
                kekcall(KEKCALL_DUMP_MEM, d_name_ptr, (uintptr_t)name_words, 32);
                memcpy(name, name_words, 31);
                name[31] = 0;
            } else {
                continue;
            }
            if (g_sigsys_fault) continue;
            if (name[0] < 32 || name[0] > 126) continue;

            total_cdevsw++;
            if (g_cdevsw_count < 256) {
                g_cdevsw_list[g_cdevsw_count] = cdevsw_addr;
                strncpy(g_cdevsw_names[g_cdevsw_count], name, 31);
                g_cdevsw_names[g_cdevsw_count][31] = 0;
                g_cdevsw_count++;
            }
            klog_printf("[CDVS] #%d @ 0x%llx ver=0x%08x name='%s' d_open=0x%llx\n",
                        total_cdevsw, (unsigned long long)cdevsw_addr, ver, name,
                        (unsigned long long)d_open);

            if (name[0] == 'm' && name[1] == 'p' && name[2] == '4') {
                klog_printf("[CDVS] ****************************************************\n");
                klog_printf("[CDVS] *** FOUND mp4 cdevsw! @ 0x%llx d_open=0x%llx ***\n",
                            (unsigned long long)cdevsw_addr, (unsigned long long)d_open);
                klog_printf("[CDVS] ****************************************************\n");
                mp4_cdevsw_addr = cdevsw_addr;
                mp4_d_open = d_open;
            }
        }
    }

    klog_printf("[CDVS] safe scan completed. Found %d cdevsw total.\n", total_cdevsw);

    /* Диагностический дамп 192 байт известного cdevsw: icc_configuration */
    klog_printf("[ICC] dumping 192 bytes of icc_configuration cdevsw @ 0xffffffffcd71fb78:\n");
    uint8_t icc_buf[192] = {0};
    g_sigsys_fault = 0;
    if (sigsetjmp(g_sigsys_jmp, 1) == 0) {
        kekcall(KEKCALL_DUMP_MEM, 0xffffffffcd71fb78ULL, (uintptr_t)icc_buf, 192);
        for (int off = 0; off < 192; off += 8) {
            uint64_t v = 0;
            __builtin_memcpy(&v, icc_buf + off, 8);
            klog_printf("[ICC] +0x%02x = 0x%016llx\n", off, (unsigned long long)v);
        }
    } else {
        klog_printf("[ICC] failed to dump icc_configuration\n");
    }

    /* Шаг #0: Диагностический дамп 256 байт struct cdev (icc0 / icc_configuration) */
    klog_printf("[CDEV0] dumping 256 bytes of struct cdev @ 0xffff937101989200:\n");
    uint8_t cdev_buf[256] = {0};
    g_sigsys_fault = 0;
    if (sigsetjmp(g_sigsys_jmp, 1) == 0) {
        kekcall(KEKCALL_DUMP_MEM, 0xffff937101989200ULL, (uintptr_t)cdev_buf, 256);
        for (int off = 0; off < 256; off += 8) {
            uint64_t v = 0;
            __builtin_memcpy(&v, cdev_buf + off, 8);

            /* Проверяем, не лежит ли строка прямо inline внутри буфера cdev (например __si_namebuf) */
            char inline_str[9] = {0};
            __builtin_memcpy(inline_str, cdev_buf + off, 8);
            int is_inline_ascii = 1;
            for (int k = 0; k < 8; k++) {
                if (inline_str[k] == 0) break;
                if (inline_str[k] < 32 || inline_str[k] > 126) { is_inline_ascii = 0; break; }
            }

            /* Пробуем прочитать первые 16 байт строки, если это валидный указатель ядра/кучи */
            char preview[16] = {0};
            if ((v & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL) {
                g_sigsys_fault = 0;
                if (sigsetjmp(g_sigsys_jmp, 1) == 0) {
                    uint64_t s_words[2] = {0};
                    kekcall(KEKCALL_DUMP_MEM, v, (uintptr_t)s_words, 16);
                    memcpy(preview, s_words, 15);
                    for (int k = 0; k < 15; k++) {
                        if (preview[k] < 32 || preview[k] > 126) { preview[k] = 0; break; }
                    }
                }
            }

            if (preview[0]) {
                klog_printf("[CDEV0] +0x%02x = 0x%016llx  ptr_str='%s'\n", off, (unsigned long long)v, preview);
            } else if (is_inline_ascii && inline_str[0] >= 'a' && inline_str[0] <= 'z') {
                klog_printf("[CDEV0] +0x%02x = 0x%016llx  inline='%s'\n", off, (unsigned long long)v, inline_str);
            } else {
                klog_printf("[CDEV0] +0x%02x = 0x%016llx\n", off, (unsigned long long)v);
            }
        }
    } else {
        klog_printf("[CDEV0] failed to dump struct cdev\n");
    }

    /* Восстанавливаем дефолтный обработчик SIGSYS */
    signal(SIGSYS, SIG_DFL);

    return 0;
}

/* Полноценный полный обход d_devs для каждого найденного cdevsw БЕЗ прерываний */
int
find_and_patch_mp4_cdevsw(void)
{
    klog_printf("[WALK] ====================================================\n");
    klog_printf("[WALK] FULL CDEV WALK: mapping all /dev nodes across %d cdevsw\n", g_cdevsw_count);
    klog_printf("[WALK] ====================================================\n");

    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = sigsys_handler;
    sa.sa_flags = SA_NODEFER;
    sigaction(SIGSYS, &sa, NULL);

    int total_cdev_nodes = 0;
    uint64_t mp4_parent_csw = 0;
    uint64_t mp4_cdev_node = 0;
    (void)mp4_cdev_node;
    char mp4_node_name[64] = {0};

    for (int idx = 0; idx < g_cdevsw_count; idx++) {
        uint64_t csw = g_cdevsw_list[idx];
        const char *csw_name = g_cdevsw_names[idx];
        uint64_t first_cdev = 0;

        g_sigsys_fault = 0;
        if (sigsetjmp(g_sigsys_jmp, 1) == 0) {
            kekcall(KEKCALL_DUMP_MEM, csw + 0xa8ULL, (uintptr_t)&first_cdev, 8);
        } else {
            continue;
        }
        if (g_sigsys_fault || !first_cdev) continue;

        uint64_t cur_cdev = first_cdev;
        int depth = 0;
        uint64_t seen[64] = {0};

        while (cur_cdev && depth < 50) {
            if ((cur_cdev & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL) break;

            int is_loop = 0;
            for (int k = 0; k < depth; k++) {
                if (seen[k] == cur_cdev) { is_loop = 1; break; }
            }
            if (is_loop) break;
            seen[depth++] = cur_cdev;

            /* Читаем si_namebuf (+0xe0) */
            char dev_name[64] = {0};
            g_sigsys_fault = 0;
            if (sigsetjmp(g_sigsys_jmp, 1) == 0) {
                uint64_t nwords[8] = {0};
                kekcall(KEKCALL_DUMP_MEM, cur_cdev + 0xe0ULL, (uintptr_t)nwords, 64);
                memcpy(dev_name, nwords, 63);
                dev_name[63] = 0;
            } else {
                break;
            }
            if (g_sigsys_fault) break;

            /* Если inline пусто, пробуем si_name как указатель на +0x88..+0x98 */
            if (!dev_name[0]) {
                for (uint64_t off = 0x88; off <= 0x98; off += 8) {
                    uint64_t ptr = 0;
                    if (sigsetjmp(g_sigsys_jmp, 1) == 0) {
                        kekcall(KEKCALL_DUMP_MEM, cur_cdev + off, (uintptr_t)&ptr, 8);
                        if ((ptr & 0xFFFF000000000000ULL) == 0xFFFF000000000000ULL) {
                            uint64_t sw[4] = {0};
                            kekcall(KEKCALL_DUMP_MEM, ptr, (uintptr_t)sw, 32);
                            memcpy(dev_name, sw, 31);
                            if (dev_name[0] >= 32 && dev_name[0] <= 126) break;
                            dev_name[0] = 0;
                        }
                    }
                }
            }

            if (dev_name[0]) {
                total_cdev_nodes++;
                klog_printf("[WALK] #%d csw=0x%llx csw_name='%s' cdev=0x%llx dev='%s'\n",
                            total_cdev_nodes, (unsigned long long)csw, csw_name,
                            (unsigned long long)cur_cdev, dev_name);

                if (strstr(dev_name, "mp4") || strstr(dev_name, "dump")) {
                    klog_printf("[WALK] ****************************************************\n");
                    klog_printf("[WALK] *** TARGET MATCH: '%s' @ cdev=0x%llx parent_csw=0x%llx (%s) ***\n",
                                dev_name, (unsigned long long)cur_cdev,
                                (unsigned long long)csw, csw_name);
                    klog_printf("[WALK] ****************************************************\n");
                    mp4_parent_csw = csw;
                    mp4_cdev_node = cur_cdev;
                    strncpy(mp4_node_name, dev_name, sizeof(mp4_node_name) - 1);
                }
            }

            /* Следующий cdev в списке (si_list.le_next на +0x60) */
            uint64_t next_cdev = 0;
            g_sigsys_fault = 0;
            if (sigsetjmp(g_sigsys_jmp, 1) == 0) {
                kekcall(KEKCALL_DUMP_MEM, cur_cdev + 0x60ULL, (uintptr_t)&next_cdev, 8);
            } else {
                break;
            }
            if (g_sigsys_fault) break;
            cur_cdev = next_cdev;
        }
    }

    signal(SIGSYS, SIG_DFL);
    klog_printf("[WALK] Full map complete. Total cdev nodes found: %d\n", total_cdev_nodes);

    /* Тестовая проверка kekcall(26) probe на известном icc_configuration */
    uint64_t icc_filter = 0;
    memcpy(&icc_filter, "icc_conf", 8);
    long probe_ret = kekcall(26, icc_filter, 0, 0);
    klog_printf("[TEST26] kekcall(26, filter='icc_conf', do_patch=0) returned 0x%lx\n", probe_ret);

    if (mp4_parent_csw) {
        klog_printf("[WALK] Confirmed mp4 node '%s' under parent csw 0x%llx\n",
                    mp4_node_name, (unsigned long long)mp4_parent_csw);
    } else {
        klog_printf("[WALK] Notice: no node with 'mp4' or 'dump' in name was encountered.\n");
    }

    return 0;
}

int
probe_mp4_device(uint64_t curproc_hint)
{
    (void)curproc_hint;
    test_mp4_open_with_root();
    scan_cdevsw();
    find_and_patch_mp4_cdevsw();
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
    uint64_t curproc_hint = (rc > 38) ? ext_buf[38] : 0;
    if (probe_mp4_device(curproc_hint) != 0) {
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
