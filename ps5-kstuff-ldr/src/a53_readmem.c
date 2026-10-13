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
#include <sys/stat.h>
#include <dirent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/ioccom.h>
#include <sys/mman.h>
#include <signal.h>
#include <setjmp.h>

#include <ps5/klog.h>

#include "a53_readmem.h"
#include "kekcall.h"

extern unsigned long kernel_get_proc_cr3(int pid, unsigned long *optional_out_kernel_dmap_base);
extern uint64_t virt2phys(uintptr_t addr, uint64_t *phys_limit, uint64_t dmap, uint64_t pml);

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

static uint32_t g_cand_pids[32];
static uint64_t g_cand_authids[32];
static uint64_t g_cand_ucreds[32];
static char     g_cand_comms[32][32];

static uint64_t g_cdev_deci_mp4_ioc = 0;
static uint64_t g_cdev_deci_mp4_mmc = 0;
static uint64_t g_cdev_deci_coredump = 0;
static uint64_t g_cdev_mp4_dump_for_decid = 0;

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

    /* Завершение сканирования cdevsw */

    /* Восстанавливаем дефолтный обработчик SIGSYS */
    signal(SIGSYS, SIG_DFL);

    return 0;
}

static void
probe_opened_mp4_fd(int fd, const char *name)
{
    klog_printf("[PROBE] === Starting deep probe on %s (fd=%d) ===\n", name, fd);

    /* Специфический глубокий probe для /dev/mp4/dump_for_decid */
    if (strstr(name, "dump_for_decid")) {
        klog_printf("[INIT_PROBE] === Starting comprehensive session init on %s (fd=%d) ===\n", name, fd);

        /* --------------------------------------------------------------------- */
        /* RING 0 FP & CDEVPRIV INJECTION DIRECTLY ON THE LIVE OPENED FD         */
        /* --------------------------------------------------------------------- */
        klog_printf("[LIVE_FP] === Fresh FDT dump after successful open of %s (fd=%d) ===\n", name, fd);

        /* Свежий вызов KEKCALL_GET_FD_INFO: fd_live=fd (8), fd_ref=1 (stdout) */
        uint64_t live_info[40] = {0};
        kekcall(KEKCALL_GET_FD_INFO, (uint64_t)fd, 1ULL, (uintptr_t)live_info);
        uint64_t live_p_fd = live_info[0];
        uint64_t live_fdt  = live_info[1];

        klog_printf("[LIVE_FP] p_fd=0x%llx fdt=0x%llx\n",
                    (unsigned long long)live_p_fd, (unsigned long long)live_fdt);

        /* Печатаем СВЕЖИЙ дамп таблицы FDT прямо сейчас (после open) */
        for (int i = 0; i < 20; i++) {
            klog_printf("[LIVE_FDT+0x%02x] (fd=%d) = 0x%016llx\n",
                        i * 8, (i >= 2 ? i - 2 : -1), (unsigned long long)live_info[5 + i]);
        }

        /* Точный слот для fd: fdt + 0x10 + fd * 8 -> в live_info это индекс 5 + 2 + fd */
        uint64_t fp_live = live_info[5 + 2 + fd];

        /* Если слот fd пуст, пробуем overflow table: *(p_fd + 0x08) -> *(fd_files + 0x08 + fd * 8) */
        if (!fp_live || (fp_live >> 48) != 0xffff) {
            uint64_t fd_files = 0;
            kekcall(KEKCALL_DUMP_MEM, live_p_fd + 0x08ULL, (uintptr_t)&fd_files, 8);
            if ((fd_files >> 48) == 0xffff) {
                kekcall(KEKCALL_DUMP_MEM, fd_files + 0x08ULL + (uint64_t)fd * 8ULL, (uintptr_t)&fp_live, 8);
                klog_printf("[LIVE_FP] overflow lookup: fd_files=0x%llx -> fp_live=0x%llx\n",
                            (unsigned long long)fd_files, (unsigned long long)fp_live);
            }
        }

        /* Открываем свежий /dev/null прямо сейчас для гарантированного live ref */
        int fd_null_live = open("/dev/null", O_RDWR);
        uint64_t fp_ref = 0;
        if (fd_null_live >= 0) {
            uint64_t null_info[40] = {0};
            kekcall(KEKCALL_GET_FD_INFO, (uint64_t)fd_null_live, 1ULL, (uintptr_t)null_info);
            fp_ref = null_info[5 + 2 + fd_null_live];
            klog_printf("[LIVE_FP] live /dev/null opened: fd=%d -> fp_ref=0x%llx\n",
                        fd_null_live, (unsigned long long)fp_ref);
        }
        if (!fp_ref || (fp_ref >> 48) != 0xffff) {
            fp_ref = live_info[5 + 2 + 1]; /* fallback: stdout (fd=1) */
        }

        klog_printf("[LIVE_FP] FINAL PAIR: mp4 fp_live=0x%llx, ref fp_ref=0x%llx\n",
                    (unsigned long long)fp_live, (unsigned long long)fp_ref);

        /* --------------------------------------------------------------------- */
        /* ДАМП 0x100 БАЙТ struct file ДЛЯ АНАЛИЗА ГЛАЗАМИ                      */
        /* --------------------------------------------------------------------- */
        klog_printf("[DUMP_FP] === Full 0x100 byte dump of fp_live=0x%llx ===\n", (unsigned long long)fp_live);
        for (int i = 0; i < 32; i++) {
            uint64_t val = 0;
            kekcall(KEKCALL_DUMP_MEM, fp_live + (uint64_t)i * 8, (uintptr_t)&val, 8);
            klog_printf("[FP_LIVE+0x%02x] = 0x%016llx\n", i * 8, (unsigned long long)val);
        }

        /* --------------------------------------------------------------------- */
        /* 3 ЦЕЛЕВЫХ ГЛУБОКИХ ДАМПА:                                              */
        /* 1) fp+0x40 (cdev_privdata?)                                           */
        /* 2) fp+0x18 (vnode/rdev?)                                              */
        /* 3) fp+0x20 (secondary fdt / list?)                                    */
        /* --------------------------------------------------------------------- */
        uint64_t ptr_40 = 0, ptr_18 = 0, ptr_20 = 0;
        kekcall(KEKCALL_DUMP_MEM, fp_live + 0x40ULL, (uintptr_t)&ptr_40, 8);
        kekcall(KEKCALL_DUMP_MEM, fp_live + 0x18ULL, (uintptr_t)&ptr_18, 8);
        kekcall(KEKCALL_DUMP_MEM, fp_live + 0x20ULL, (uintptr_t)&ptr_20, 8);

        klog_printf("[DEEP_1] === Dump fp+0x40 (ptr=0x%llx, 0x80 bytes) ===\n", (unsigned long long)ptr_40);
        if (ptr_40 && (ptr_40 >> 48) == 0xffff) {
            for (int i = 0; i < 16; i++) {
                uint64_t v = 0;
                kekcall(KEKCALL_DUMP_MEM, ptr_40 + (uint64_t)i * 8, (uintptr_t)&v, 8);
                klog_printf("[PTR40+0x%02x] = 0x%016llx\n", i * 8, (unsigned long long)v);
            }
        }

        klog_printf("[DEEP_2] === Dump fp+0x18 (ptr=0x%llx, 0x80 bytes) ===\n", (unsigned long long)ptr_18);
        if (ptr_18 && (ptr_18 >> 48) == 0xffff) {
            for (int i = 0; i < 16; i++) {
                uint64_t v = 0;
                kekcall(KEKCALL_DUMP_MEM, ptr_18 + (uint64_t)i * 8, (uintptr_t)&v, 8);
                klog_printf("[PTR18+0x%02x] = 0x%016llx\n", i * 8, (unsigned long long)v);
            }
        }

        klog_printf("[DEEP_3] === Dump fp+0x20 (ptr=0x%llx, 0x40 bytes) ===\n", (unsigned long long)ptr_20);
        if (ptr_20 && (ptr_20 >> 48) == 0xffff) {
            for (int i = 0; i < 8; i++) {
                uint64_t v = 0;
                kekcall(KEKCALL_DUMP_MEM, ptr_20 + (uint64_t)i * 8, (uintptr_t)&v, 8);
                klog_printf("[PTR20+0x%02x] = 0x%016llx\n", i * 8, (unsigned long long)v);
            }
        }

        /* --------------------------------------------------------------------- */
        /* ШАГ 1: ВСЕ ОПЕРАЦИИ КРОМЕ WRITE (ioctl, mmap, read) НА fd_mp4 И SIBLING */
        /* --------------------------------------------------------------------- */
        klog_printf("[STEP_1_OPS] === Testing non-write ops on fd_mp4=%d ===\n", fd);

        /* 1a. IOCTL */
        uint8_t iobuf[256] = {0};
        uint32_t ioctl_cmds[] = { 0, 0x40044D01, 0xC0084D02, 0x40044D10 };
        for (int ic = 0; ic < 4; ic++) {
            errno = 0;
            int ir = ioctl(fd, ioctl_cmds[ic], iobuf);
            int ie = errno;
            klog_printf("[STEP_1_IOCTL] cmd=0x%08x -> ret=%d (errno=%d)\n", ioctl_cmds[ic], ir, ie);
        }

        /* 1b. MMAP */
        errno = 0;
        void *map_ptr = mmap(NULL, 0x1000, PROT_READ, MAP_SHARED, fd, 0);
        int me = errno;
        klog_printf("[STEP_1_MMAP] mmap ret=%p (errno=%d)\n", map_ptr, me);
        if (map_ptr != MAP_FAILED) {
            klog_printf("[BREAKTHROUGH!] MMAP SUCCESS on fd=%d! first_u32=0x%08x\n",
                        fd, *(uint32_t*)map_ptr);
            munmap(map_ptr, 0x1000);
        }

        /* 1c. READ */
        uint8_t r_buf[256] = {0};
        errno = 0;
        ssize_t r_bytes = read(fd, r_buf, sizeof(r_buf));
        int re = errno;
        klog_printf("[STEP_1_READ] read ret=%zd (errno=%d)\n", r_bytes, re);

        /* --------------------------------------------------------------------- */
        /* ШАГ B: Открыть эталонные cdev (/dev/dmem1, /dev/dce, /dev/notification0) */
        /* --------------------------------------------------------------------- */
        const char *cand_cdevs[] = {
            "/dev/dmem1", "/dev/dce", "/dev/notification0", "/dev/dmem0", "/dev/da0"
        };
        int fd_priv_cand = -1;
        uint64_t fp_cand_priv = 0;
        const char *found_cand_name = "none";

        for (int c = 0; c < 5; c++) {
            errno = 0;
            int c_fd = open(cand_cdevs[c], O_RDWR);
            if (c_fd < 0) {
                errno = 0;
                c_fd = open(cand_cdevs[c], O_RDONLY);
            }
            int err = errno;
            klog_printf("[REF_TRY] '%s' -> fd=%d (errno=%d)\n", cand_cdevs[c], c_fd, err);

            if (c_fd >= 0) {
                /* Чистим старый слот и берем правильный дескриптор */
                uint64_t c_info[40] = {0};
                kekcall(KEKCALL_GET_FD_INFO, (uint64_t)c_fd, 1ULL, (uintptr_t)c_info);
                uint64_t c_fp = c_info[5 + 2 + c_fd];
                if (c_fp && (c_fp >> 48) == 0xffff) {
                    fd_priv_cand = c_fd;
                    fp_cand_priv = c_fp;
                    found_cand_name = cand_cdevs[c];
                    klog_printf("[STEP_B] SUCCESS: Opened %s (fd=%d) -> fp_cand=0x%llx\n",
                                found_cand_name, fd_priv_cand, (unsigned long long)fp_cand_priv);
                    break;
                }
                close(c_fd);
            }
        }

        /* --------------------------------------------------------------------- */
        /* ШАГ 2: Скопировать fp+0x40 блоб из dmem1 в fp+0x40 нашего mp4        */
        /* --------------------------------------------------------------------- */
        if (fp_cand_priv && ptr_40 && (ptr_40 >> 48) == 0xffff) {
            uint64_t cand_ptr40 = 0;
            kekcall(KEKCALL_DUMP_MEM, fp_cand_priv + 0x40ULL, (uintptr_t)&cand_ptr40, 8);
            klog_printf("[STEP_2] candidate %s fp+0x40 = 0x%llx, our ptr_40 = 0x%llx\n",
                        found_cand_name, (unsigned long long)cand_ptr40, (unsigned long long)ptr_40);

            if (cand_ptr40 && (cand_ptr40 >> 48) == 0xffff) {
                /* Бэкапим наш блоб ptr_40 (0x80 байт) */
                uint64_t bkp_ptr40[16] = {0};
                for (int i = 0; i < 16; i++) {
                    kekcall(KEKCALL_DUMP_MEM, ptr_40 + (uint64_t)i * 8, (uintptr_t)&bkp_ptr40[i], 8);
                }

                /* Клонируем блоб из cand_ptr40 в ptr_40 */
                for (int i = 0; i < 16; i++) {
                    uint64_t cv = 0;
                    kekcall(KEKCALL_DUMP_MEM, cand_ptr40 + (uint64_t)i * 8, (uintptr_t)&cv, 8);
                    kekcall(27 /* WRITE64 */, ptr_40 + (uint64_t)i * 8, cv, 0);
                }

                /* Пробуем write */
                uint8_t w_cmd[8] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
                errno = 0;
                ssize_t nw2 = write(fd, w_cmd, 8);
                int we2 = errno;
                klog_printf("[STEP_2_WRITE] write after cloning %s fp+0x40: nw=%zd (errno=%d)\n",
                            found_cand_name, nw2, we2);

                if (nw2 >= 0 || we2 != 19) {
                    klog_printf("[BREAKTHROUGH!] ENODEV 19 BYPASSED VIA FP+0x40 CLONING! nw=%zd errno=%d\n",
                                nw2, we2);
                }

                /* Восстанавливаем оригинальный блог */
                for (int i = 0; i < 16; i++) {
                    kekcall(27, ptr_40 + (uint64_t)i * 8, bkp_ptr40[i], 0);
                }
            }
        }

        if (fp_cand_priv) {
            klog_printf("[DUMP_CAND] === Full 0x100 byte dump of %s fp=0x%llx ===\n",
                        found_cand_name, (unsigned long long)fp_cand_priv);
            for (int i = 0; i < 32; i++) {
                uint64_t val = 0;
                kekcall(KEKCALL_DUMP_MEM, fp_cand_priv + (uint64_t)i * 8, (uintptr_t)&val, 8);
                klog_printf("[FP_CAND+0x%02x] = 0x%016llx\n", i * 8, (unsigned long long)val);
            }

            /* Дамп его fp+0x40 для прямого сравнения */
            uint64_t cand_ptr40 = 0;
            kekcall(KEKCALL_DUMP_MEM, fp_cand_priv + 0x40ULL, (uintptr_t)&cand_ptr40, 8);
            klog_printf("[DUMP_CAND_40] %s fp+0x40 = 0x%llx\n", found_cand_name, (unsigned long long)cand_ptr40);
            if (cand_ptr40 && (cand_ptr40 >> 48) == 0xffff) {
                for (int i = 0; i < 8; i++) {
                    uint64_t cv = 0;
                    kekcall(KEKCALL_DUMP_MEM, cand_ptr40 + (uint64_t)i * 8, (uintptr_t)&cv, 8);
                    klog_printf("[CAND_PTR40+0x%02x] = 0x%016llx\n", i * 8, (unsigned long long)cv);
                }
            }

            /* Diff против cdevpriv дескриптора */
            uint64_t cand_diff[32] = {0};
            uint32_t diff_priv_off = (uint32_t)kekcall(KEKCALL_DIFF_FP, fp_live, fp_cand_priv, (uintptr_t)cand_diff);
            klog_printf("[STEP_B_DIFF] diff against %s candidate detected offset: +0x%x\n",
                        found_cand_name, diff_priv_off);
        }

        /* --------------------------------------------------------------------- */
        /* ШАГ A: Полный автоматический перебор смещений от +0x38 до +0xD0       */
        /* --------------------------------------------------------------------- */
        klog_printf("[STEP_A_SCAN] === Scanning all offsets from +0x38 to +0xD0 ===\n");
        uint32_t scan_offsets[] = {
            0x38, 0x40, 0x48, 0x50, 0x58, 0x60, 0x68, 0x70,
            0x78, 0x80, 0x88, 0x90, 0x98, 0xA0, 0xA8, 0xB0,
            0xB8, 0xC0, 0xC8, 0xD0
        };
        int num_offsets = sizeof(scan_offsets) / sizeof(scan_offsets[0]);
        uint8_t test_cmd[8] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

        for (int s = 0; s < num_offsets; s++) {
            uint32_t off = scan_offsets[s];

            /* Инжектируем cdev */
            uint64_t bk = (uint64_t)kekcall(KEKCALL_INJECT_CDEVPRIV, fp_live, (uint64_t)off, g_cdev_mp4_dump_for_decid);

            errno = 0;
            ssize_t nw = write(fd, test_cmd, 8);
            int err = errno;

            klog_printf("[SCAN +0x%02x] injected (old=0x%llx) -> nw=%zd errno=%d\n",
                        off, (unsigned long long)bk, nw, err);

            /* Восстанавливаем старое значение */
            kekcall(KEKCALL_INJECT_CDEVPRIV, fp_live, (uint64_t)off, bk);

            if (nw >= 0 || (err != 19 && err != 0)) {
                klog_printf("[BREAKTHROUGH!] ENODEV (19) BYPASSED AT +0x%x! nw=%zd errno=%d\n",
                            off, nw, err);
                break;
            }
        }

        if (fd_priv_cand >= 0) close(fd_priv_cand);
        if (fd_null_live >= 0) close(fd_null_live);

        /* Шаг 1: Сканирование ioctl диапазонов (включая расширенные группы Sony M, D, AF) */
        uint8_t ibuf[256] = {0};
        uint32_t groups[] = {
            0x40044400, 0x80044400, 0xC0184400, 
            0x40044D00, 0x80044D00, 0xC0184D00,
            0x4004AF00, 0x8004AF00, 0xC018AF00
        };
        for (int g = 0; g < 9; g++) {
            for (uint32_t cmd = groups[g]; cmd <= groups[g] + 0x1F; cmd++) {
                int r = ioctl(fd, cmd, ibuf);
                int e = errno;
                if (e != 25 /* ENOTTY */) {
                    klog_printf("[IOCTL_HIT] 0x%08x ret=%d errno=%d *** RECOGNIZED! ***\n", cmd, r, e);
                }
            }
        }

        /* Дополнительное сканирование стандартных команд _IOWR('M'..'V', 0..31) */
        for (int group = 'M'; group <= 'V'; group++) {
            for (int num = 0; num < 32; num++) {
                uint32_t cmd = (0xC0184000 | (group << 8) | num);
                int r = ioctl(fd, cmd, ibuf);
                int e = errno;
                if (e != 25 /* ENOTTY */) {
                    klog_printf("[IOCTL_HIT_SONY] 0x%08x ret=%d errno=%d *** RECOGNIZED! ***\n", cmd, r, e);
                }
            }
        }

        /* Шаг 2: Повторный write после IOCTL probe */
        ssize_t nw = write(fd, "\x01\x00\x00\x00\x00\x00\x00\x00", 8);
        klog_printf("[POST_IOCTL_WRITE] nw=%zd errno=%d\n", nw, errno);

        /* Шаг 3: Handshake-записи с магическими заголовками */
        const uint8_t magics[][8] = {
            {0x44,0x45,0x43,0x49, 0x01,0x00,0x00,0x00},  /* "DECI" + ver 1 */
            {0x4D,0x50,0x34,0x44, 0x01,0x00,0x00,0x00},  /* "MP4D" + ver 1 */
            {0x01,0x00,0x00,0x00, 0x00,0x00,0x00,0x00},  /* init cmd 1 */
            {0x10,0x00,0x00,0x00, 0x00,0x00,0x00,0x00},  /* init cmd 0x10 */
            {0xDE,0xC1,0x4D,0x50, 0x00,0x00,0x00,0x00},  /* 0xDEC14D50 */
            {0x00,0x00,0x00,0x00, 0x00,0x00,0x00,0x00},  /* 8 zeros */
        };

        for (int i = 0; i < 6; i++) {
            errno = 0;
            ssize_t nw_magic = write(fd, magics[i], 8);
            int werr = errno;
            uint8_t resp[256] = {0};
            errno = 0;
            ssize_t nr = read(fd, resp, sizeof(resp));
            int rerr = errno;

            klog_printf("[INIT_%d] nw=%zd (errno=%d) nr=%zd (errno=%d) first_u32=0x%08x\n",
                        i, nw_magic, werr, nr, rerr, *(uint32_t*)resp);

            if (nr > 0) {
                klog_printf("[INIT_HIT] *** BINGO! %s session produced %zd bytes! ***\n", name, nr);
                for (int off = 0; off < nr && off < 64; off += 16) {
                    klog_printf("[INIT_DATA] +0x%02x: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                off, resp[off], resp[off+1], resp[off+2], resp[off+3],
                                resp[off+4], resp[off+5], resp[off+6], resp[off+7]);
                }
            }
        }

        /* Шаг 4: Повторный read после всех попыток инициализации */
        uint8_t final_buf[256] = {0};
        errno = 0;
        ssize_t nr_final = read(fd, final_buf, sizeof(final_buf));
        klog_printf("[INIT_FINAL] post-handshake read nr=%zd errno=%d\n", nr_final, errno);
        return;
    }

    uint8_t dummy[64] = {0};
    ssize_t nr = read(fd, dummy, sizeof(dummy));
    klog_printf("[NODE_CHECK] %s: read nr=%zd status=0x%08x\n", name, nr, *(uint32_t*)dummy);
}

/* Полноценный полный обход d_devs для каждого найденного cdevsw БЕЗ прерываний */
int
find_and_patch_mp4_cdevsw(uint64_t curproc_hint)
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
    uint64_t null_parent_csw = 0;
    uint64_t mp4_parent_csws[8] = {0};
    uint64_t mp4_cdev_nodes[8] = {0};
    char     mp4_names[8][64] = {{0}};
    int      mp4_count = 0;

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

                if (strcmp(dev_name, "null") == 0) {
                    null_parent_csw = csw;
                    klog_printf("[WALK] *** FOUND /dev/null parent_csw=0x%llx ***\n",
                                (unsigned long long)csw);
                }

                if (strcmp(dev_name, "deci_mp4_ioc") == 0) g_cdev_deci_mp4_ioc = cur_cdev;
                if (strcmp(dev_name, "deci_mp4_mmc") == 0) g_cdev_deci_mp4_mmc = cur_cdev;
                if (strcmp(dev_name, "deci_coredump") == 0) g_cdev_deci_coredump = cur_cdev;
                if (strcmp(dev_name, "mp4/dump_for_decid") == 0) g_cdev_mp4_dump_for_decid = cur_cdev;

                if (strncmp(dev_name, "mp4/", 4) == 0 || strstr(dev_name, "mp4")) {
                    klog_printf("[WALK] ****************************************************\n");
                    klog_printf("[WALK] *** TARGET MATCH: '%s' @ cdev=0x%llx parent_csw=0x%llx (%s) ***\n",
                                dev_name, (unsigned long long)cur_cdev,
                                (unsigned long long)csw, csw_name);
                    klog_printf("[WALK] ****************************************************\n");
                    int found_dup = 0;
                    for (int m = 0; m < mp4_count; m++) {
                        if (mp4_parent_csws[m] == csw) found_dup = 1;
                    }
                    if (!found_dup && mp4_count < 8) {
                        mp4_parent_csws[mp4_count] = csw;
                        mp4_cdev_nodes[mp4_count] = cur_cdev;
                        strncpy(mp4_names[mp4_count], dev_name, 63);
                        mp4_count++;
                    }
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

    /* Шаг 1: pre-test на /dev/mp4/dump прямо сейчас (до нового патча) */
    int fd0 = open("/dev/mp4/dump", 0x0002 /* O_RDWR */);
    int err0 = errno;
    klog_printf("[STEP1] /dev/mp4/dump pre-patch: fd=%d errno=%d\n", fd0, err0);
    if (fd0 >= 0) {
        klog_printf("[STEP1] *** VICTORY: /dev/mp4/dump OPENED WITHOUT NEW PATCH! fd=%d ***\n", fd0);
        close(fd0);
        return 0;
    }

    /* Шаг 2: sanity check на /dev/null */
    int nfd = open("/dev/null", 0x0002 /* O_RDWR */);
    int nerr = errno;
    klog_printf("[STEP2] /dev/null sanity: fd=%d errno=%d\n", nfd, nerr);
    if (nfd >= 0) close(nfd);

    if (!null_parent_csw) {
        klog_printf("[STEP3] ERROR: null_csw not found in walk!\n");
        return -1;
    }

    /* Шаг 3: достать null_dopen из null_csw + 0x10 */
    uint64_t null_dopen = 0;
    kekcall(KEKCALL_DUMP_MEM, null_parent_csw + 0x10ULL, (uintptr_t)&null_dopen, 8);
    klog_printf("[STEP3] null_csw=0x%llx -> null_dopen=0x%llx\n",
                (unsigned long long)null_parent_csw, (unsigned long long)null_dopen);
    if (!null_dopen) {
        klog_printf("[STEP3] ERROR: null_dopen is NULL!\n");
        return -1;
    }

    /* Микро-тест чтения памяти через KEKCALL_DUMP_MEM */
    klog_printf("[READ_TEST] === Memory dump sanity check ===\n");
    uint64_t data_v = null_parent_csw;
    char data_bytes[16] = {0};
    long r_data = kekcall(KEKCALL_DUMP_MEM, data_v, (uintptr_t)data_bytes, 16);
    klog_printf("[READ_TEST] (.data @ 0x%llx): ret=%ld, first_u64=0x%lx\n",
                (unsigned long long)data_v, r_data, *(unsigned long*)data_bytes);

    /* Тест чтения .text ядра (null_dopen prologue) */
    klog_printf("[XOM_TEST] === Dumping null_dopen .text prologue @ 0x%llx (0x40 bytes) ===\n",
                (unsigned long long)null_dopen);
    uint8_t code_buf[64] = {0};
    long r_code = kekcall(KEKCALL_DUMP_MEM, null_dopen, (uintptr_t)code_buf, 64);
    klog_printf("[XOM_TEST] dump ret=%ld\n", r_code);
    for (int r = 0; r < 4; r++) {
        klog_printf("[XOM_TEST +0x%02x] %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                    r * 16,
                    code_buf[r*16 + 0], code_buf[r*16 + 1], code_buf[r*16 + 2], code_buf[r*16 + 3],
                    code_buf[r*16 + 4], code_buf[r*16 + 5], code_buf[r*16 + 6], code_buf[r*16 + 7],
                    code_buf[r*16 + 8], code_buf[r*16 + 9], code_buf[r*16 + 10], code_buf[r*16 + 11],
                    code_buf[r*16 + 12], code_buf[r*16 + 13], code_buf[r*16 + 14], code_buf[r*16 + 15]);
    }

    /* Шаг 3: Полная энумерация ВСЕХ процессов через KEKCALL_ENUM_ALLPROC (nr 29) */
    klog_printf("[AUTH_ENUM] === ENUMERATING ALL PROCESSES VIA KERNEL allproc SYMBOL (KEKCALL 29) ===\n");

    /* Буфер для 128 процессов по 48 байт: pid(4), comm(24), ucred(8), authid(8) */
    uint8_t proc_buf[128 * 48] = {0};
    long total_procs = kekcall(KEKCALL_ENUM_ALLPROC, (uintptr_t)proc_buf, 128, 0);
    klog_printf("[AUTH_ENUM] KEKCALL_ENUM_ALLPROC returned %ld processes\n", total_procs);

    /* Сканирование p_comm на структуре процесса pid=1 (init) для поиска смещения имени */
    for (long i = 0; i < total_procs && i < 128; i++) {
        uint8_t *entry = proc_buf + i * 48;
        uint32_t pid = *(uint32_t*)(entry + 0);
        char comm[25] = {0};
        memcpy(comm, entry + 4, 24);
        comm[24] = 0;
        uint64_t ucred = *(uint64_t*)(entry + 28);
        uint64_t authid = *(uint64_t*)(entry + 36);

        klog_printf("[PROC] #%ld pid=%u comm='%s' ucred=0x%llx authid=0x%016llx\n",
                    i, pid, comm, (unsigned long long)ucred, (unsigned long long)authid);
    }

    /* Сессионно-независимый отбор кандидатов по authid (в глобальные статические массивы) */
    memset(g_cand_pids, 0, sizeof(g_cand_pids));
    memset(g_cand_authids, 0, sizeof(g_cand_authids));
    memset(g_cand_ucreds, 0, sizeof(g_cand_ucreds));
    memset(g_cand_comms, 0, sizeof(g_cand_comms));
    int ncand = 0;

    /* ПЕРВЫЙ КАНДИДАТ ВСЕГДА: pid=1 (init baseline) */
    for (long i = 0; i < total_procs && i < 128; i++) {
        uint8_t *entry = proc_buf + i * 48;
        uint32_t pid = *(uint32_t*)(entry + 0);
        if (pid == 1 && ncand < 32) {
            g_cand_pids[ncand] = 1;
            g_cand_authids[ncand] = *(uint64_t*)(entry + 36);
            g_cand_ucreds[ncand] = *(uint64_t*)(entry + 28);
            memcpy(g_cand_comms[ncand], entry + 4, 24);
            ncand++;
            break;
        }
    }

    /* Остальные кандидаты: фильтр по authid (media cluster 0x1000..0x10FF или debug bit 0x10000000 или Sony 0x3800) */
    for (long i = 0; i < total_procs && i < 128; i++) {
        uint8_t *entry = proc_buf + i * 48;
        uint32_t pid = *(uint32_t*)(entry + 0);
        if (pid == 0 || pid == 1) continue;

        uint64_t auth = *(uint64_t*)(entry + 36);
        if (auth == 0) continue;

        uint16_t low = auth & 0xFFFF;
        int is_media = (low >= 0x1000 && low <= 0x10FF);
        int is_debug = ((auth & 0x10000000ULL) != 0);
        int is_sce   = ((auth >> 48) == 0x3800);

        if ((is_media || is_debug || is_sce) && ncand < 32) {
            g_cand_pids[ncand] = pid;
            g_cand_authids[ncand] = auth;
            g_cand_ucreds[ncand] = *(uint64_t*)(entry + 28);
            memcpy(g_cand_comms[ncand], entry + 4, 24);
            ncand++;
        }
    }

    klog_printf("[REAL_OPEN] filtered %d candidates from %ld procs\n", ncand, total_procs);
    for (int c = 0; c < ncand; c++) {
        klog_printf("[CAND #%d] pid=%u authid=0x%016llx ucred=0x%llx\n",
                    c, g_cand_pids[c], (unsigned long long)g_cand_authids[c], (unsigned long long)g_cand_ucreds[c]);
    }

    if (ncand == 0) {
        klog_printf("[FATAL] no candidates matched filter!\n");
        return -1;
    }

    /* Шаг 3.1: Восстановление истинного orig_dopen (null_dopen + 0x468) на mp4 cdevsw */
    uint64_t orig_dopen_calc = null_dopen + 0x468ULL;
    klog_printf("[DBG] null_dopen=0x%llx orig_dopen_calc=0x%llx\n",
                (unsigned long long)null_dopen, (unsigned long long)orig_dopen_calc);

    uint64_t dedicated_mp4_csw = 0;
    uint64_t dedicated_mp4_cdev = 0;

    for (int m = 0; m < mp4_count; m++) {
        uint64_t csw = mp4_parent_csws[m];
        if (!csw) continue;
        if (strstr(mp4_names[m], "dump_for_decid") || strstr(mp4_names[m], "dump")) {
            dedicated_mp4_csw = csw;
            dedicated_mp4_cdev = mp4_cdev_nodes[m];
            long wr = kekcall(27 /* WRITE64 */, csw + 0x10ULL, orig_dopen_calc, 0);
            uint64_t rb = 0;
            kekcall(KEKCALL_DUMP_MEM, csw + 0x10ULL, (uintptr_t)&rb, 8);
            klog_printf("[VERIFY] csw[%d] (node '%s') +0x10 after unpatch: 0x%llx (expected 0x%llx) %s (ret=%ld)\n",
                        m, mp4_names[m], (unsigned long long)rb, (unsigned long long)orig_dopen_calc,
                        (rb == orig_dopen_calc) ? "OK" : "MISMATCH", wr);
        }
    }

    /* Fallback: если не определился csw, берем адрес последнего найденного mp4_csw */
    if (!dedicated_mp4_csw && mp4_count > 0) {
        dedicated_mp4_csw = mp4_parent_csws[mp4_count - 1];
        dedicated_mp4_cdev = mp4_cdev_nodes[mp4_count - 1];
    }

    /* ТЕСТ ПЕРВЫЙ: Сканирование offset'ов td_ucred / p_ucred (KEKCALL 31) */
    klog_printf("[TEST0] === SCAN_TD_UCRED: scanning struct thread/proc for ucred offsets ===\n");
    uint64_t scan_result[8] = {0};
    long scan_ret = kekcall(KEKCALL_SCAN_TD_UCRED, (uintptr_t)scan_result, 0, 0);
    uint32_t empirical_td_off = (uint32_t)(scan_result[0] & 0xFFFFFFFF);
    uint32_t empirical_p_off  = (uint32_t)(scan_result[1] & 0xFFFFFFFF);
    uint64_t scanned_td       = scan_result[2];
    uint64_t scanned_proc     = scan_result[3];
    uint64_t scanned_td_ucred = scan_result[4];
    uint64_t scanned_p_ucred  = scan_result[5];
    uint64_t scanned_td_auth  = scan_result[6];
    uint64_t scanned_p_auth   = scan_result[7];

    klog_printf("[TEST0] SCAN ret=%ld td_off=0x%x p_off=0x%x td=0x%llx proc=0x%llx\n",
                scan_ret, empirical_td_off, empirical_p_off,
                (unsigned long long)scanned_td, (unsigned long long)scanned_proc);
    klog_printf("[TEST0] SCAN vals: td_ucred=0x%llx (auth=0x%llx) p_ucred=0x%llx (auth=0x%llx)\n",
                (unsigned long long)scanned_td_ucred, (unsigned long long)scanned_td_auth,
                (unsigned long long)scanned_p_ucred, (unsigned long long)scanned_p_auth);

    /* ТЕСТ ВТОРОЙ: Верификация работы SWAP_BY_UCRED (KEKCALL 30) */
    klog_printf("[TEST1] === Verifying KEKCALL_SWAP_BY_UCRED (nr 30) direct pointer swap ===\n");
    uint64_t init_target_ucred = g_cand_ucreds[0]; /* pid=1 ucred */
    uint64_t swap_bkp[4] = {0};
    long swap_ret = kekcall(KEKCALL_SWAP_BY_UCRED, init_target_ucred, (uintptr_t)swap_bkp, 0);
    klog_printf("[SWAP_VERIFY] swap_ret=%ld old_td=0x%llx old_p=0x%llx new_td=0x%llx new_p=0x%llx target=0x%llx\n",
                swap_ret,
                (unsigned long long)swap_bkp[0], (unsigned long long)swap_bkp[1],
                (unsigned long long)swap_bkp[2], (unsigned long long)swap_bkp[3],
                (unsigned long long)init_target_ucred);

    if (swap_ret == 0) {
        kekcall(KEKCALL_RESTORE_FULL, 0, (uintptr_t)swap_bkp, 0);
        klog_printf("[SWAP_VERIFY] restore done, %s\n",
                    (swap_bkp[2] == init_target_ucred && init_target_ucred != 0) ? "CONFIRMED_WORKING" : "SWAP_FAILED");
    }


    /* ТЕСТ ВТОРОЙ: Dump cdevsw mp4/dump_for_decid */
    if (dedicated_mp4_csw) {
        klog_printf("[TEST2] === Full cdevsw dump for mp4 @ 0x%llx ===\n",
                    (unsigned long long)dedicated_mp4_csw);
        uint64_t fns[16] = {0};
        kekcall(KEKCALL_DUMP_MEM, dedicated_mp4_csw, (uintptr_t)fns, sizeof(fns));
        for (int i = 0; i < 12; i++) {
            klog_printf("[MP4_CSW+0x%02x] = 0x%016llx\n", i * 8, (unsigned long long)fns[i]);
        }
    }

    /* ТЕСТ ТРЕТИЙ: Dump cdev struct для /dev/mp4/dump_for_decid */
    if (dedicated_mp4_cdev) {
        klog_printf("[TEST3] === Hex dump of struct cdev @ 0x%llx (512 bytes) ===\n",
                    (unsigned long long)dedicated_mp4_cdev);
        uint8_t cdev_buf[512] = {0};
        kekcall(KEKCALL_DUMP_MEM, dedicated_mp4_cdev, (uintptr_t)cdev_buf, 512);
        for (int i = 0; i < 512; i += 16) {
            klog_printf("[CDEV] +0x%03x: %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        i, cdev_buf[i], cdev_buf[i+1], cdev_buf[i+2], cdev_buf[i+3],
                        cdev_buf[i+4], cdev_buf[i+5], cdev_buf[i+6], cdev_buf[i+7],
                        cdev_buf[i+8], cdev_buf[i+9], cdev_buf[i+10], cdev_buf[i+11],
                        cdev_buf[i+12], cdev_buf[i+13], cdev_buf[i+14], cdev_buf[i+15]);
        }

        /* --------------------------------------------------------------------- */
        /* БОНУС: Тест si_cred mp4 cdev (cdev + 0xa8) через KEKCALL 30           */
        /* --------------------------------------------------------------------- */
        /* DISABLED 2026-10-13: KEKCALL_SWAP_BY_UCRED с валидным si_cred вызывает
         * Fatal trap 12 и ребут PS5 — блокирует выполнение последующего
         * NATIVE_OPEN блока. Подтверждено: si_cred ненулевой (0xfffff501018a2000),
         * DAC-гейт через ucred compare. Оставляем только диагностический вывод. */
        uint64_t si_cred = *(uint64_t*)(cdev_buf + 0xa8);
        klog_printf("[SI_CRED_TEST] cdev+0xa8 = 0x%llx (SWAP disabled — see 2026-10-13)\n",
                    (unsigned long long)si_cred);
    }

    /* ========================================================================= */
    /* DOPEN_HEX: DUMP_MEM 0x400 реального d_open для mp4/dump_for_decid         */
    /* ПЕРЕД STEP4. Используем KEKCALL_DUMP_MEM (nr 19) — kpeek64_checked внутри */
    /* умеет большие страницы .text в отличие от SAFE_PEEK (который валит ядро). */
    /* ========================================================================= */
    if (dedicated_mp4_csw) {
        uint64_t orig_dopen = 0;
        kekcall(KEKCALL_DUMP_MEM, dedicated_mp4_csw + 0x10ULL, (uintptr_t)&orig_dopen, 8);
        klog_printf("[DOPEN_HEX] mp4/dump_for_decid csw+0x10 (d_open) = 0x%llx\n",
                    (unsigned long long)orig_dopen);

        uint64_t real_dopen = orig_dopen;
        if (orig_dopen && (orig_dopen >> 48) == 0xffff) {
            uint8_t tramp[16] = {0};
            long tr = kekcall(KEKCALL_DUMP_MEM, orig_dopen, (uintptr_t)tramp, 16);
            klog_printf("[DOPEN_HEX] trampoline ret=%ld bytes: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        tr, tramp[0], tramp[1], tramp[2], tramp[3],
                        tramp[4], tramp[5], tramp[6], tramp[7]);
            if (tr >= 5 && tramp[0] == 0xe9) {
                int32_t rel32 = (int32_t)(tramp[1] | (tramp[2]<<8) | (tramp[3]<<16) | (tramp[4]<<24));
                real_dopen = orig_dopen + 5 + (int64_t)rel32;
                klog_printf("[DOPEN_HEX] decoded jmp rel32=0x%08x → real d_open = 0x%llx\n",
                            (uint32_t)rel32, (unsigned long long)real_dopen);
            } else {
                klog_printf("[DOPEN_HEX] no e9 trampoline — treating orig as real body\n");
            }
        }

        if (real_dopen && (real_dopen >> 48) == 0xffff) {
            uint8_t body[1024] = {0};
            long pr = kekcall(KEKCALL_DUMP_MEM, real_dopen, (uintptr_t)body, sizeof(body));
            klog_printf("[DOPEN_HEX] === real d_open @ 0x%llx (0x400 bytes, dump_ret=%ld) ===\n",
                        (unsigned long long)real_dopen, pr);
            for (int l = 0; l < 64; l++) {
                klog_printf("[DOPEN+0x%03x] %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                            l * 16,
                            body[l*16+0], body[l*16+1], body[l*16+2], body[l*16+3],
                            body[l*16+4], body[l*16+5], body[l*16+6], body[l*16+7],
                            body[l*16+8], body[l*16+9], body[l*16+10], body[l*16+11],
                            body[l*16+12], body[l*16+13], body[l*16+14], body[l*16+15]);
            }
        }
    }

    /* ========================================================================= */
    /* AUTH_MUTATE_TEST: подменяем ucred на 3 целевых кандидата и пробуем        */
    /* open("/dev/mp4/dump_for_decid") без STEP4-патча. Логируем fd+errno для    */
    /* каждого authid, затем RESTORE_FULL. Низ 16 бит authid определяет роль:    */
    /*   0x1005 — SceVideoCore2K, 0x1004 — SceMediaCoreServer, 0x0022 — mini-sc.*/
    /* ========================================================================= */
    {
        klog_printf("[AUTH_MUTATE_TEST] === Trying open as 3 target authids ===\n");
        const struct { uint16_t low16; const char *tag; } targets[] = {
            { 0x1005, "SceVideoCore2K"    },
            { 0x1004, "SceMediaCoreServer" },
            { 0x0022, "mini-syscore"      },
        };
        for (int t = 0; t < 3; t++) {
            uint64_t target_ucred = 0;
            uint32_t target_pid = 0;
            const char *target_comm = NULL;
            for (int c = 0; c < 32; c++) {
                if (!g_cand_authids[c]) continue;
                if ((uint16_t)(g_cand_authids[c] & 0xFFFF) == targets[t].low16) {
                    target_ucred = g_cand_ucreds[c];
                    target_pid   = g_cand_pids[c];
                    target_comm  = g_cand_comms[c];
                    break;
                }
            }
            if (!target_ucred) {
                klog_printf("[MUT_%d] %s (0x%04x) — no candidate found, skip\n",
                            t, targets[t].tag, targets[t].low16);
                continue;
            }

            klog_printf("[MUT_%d] trying %s pid=%u ucred=0x%llx (comm='%s', authid_low=0x%04x)\n",
                        t, targets[t].tag, target_pid,
                        (unsigned long long)target_ucred,
                        target_comm ? target_comm : "?",
                        targets[t].low16);

            uint64_t bkp[4] = {0};
            long sr = kekcall(KEKCALL_SWAP_BY_UCRED, target_ucred, (uintptr_t)bkp, 0);
            klog_printf("[MUT_%d_SWAP] ret=%ld old_td=0x%llx old_p=0x%llx new_td=0x%llx new_p=0x%llx\n",
                        t, sr,
                        (unsigned long long)bkp[0], (unsigned long long)bkp[1],
                        (unsigned long long)bkp[2], (unsigned long long)bkp[3]);
            if (sr != 0) {
                klog_printf("[MUT_%d] swap failed, skip open\n", t);
                continue;
            }

            errno = 0;
            int mfd = open("/dev/mp4/dump_for_decid", O_RDWR);
            int me = errno;
            klog_printf("[MUT_%d_OPEN] %s O_RDWR fd=%d errno=%d\n",
                        t, targets[t].tag, mfd, me);
            if (mfd < 0) {
                errno = 0;
                mfd = open("/dev/mp4/dump_for_decid", O_RDONLY);
                me = errno;
                klog_printf("[MUT_%d_OPEN] %s O_RDONLY fd=%d errno=%d\n",
                            t, targets[t].tag, mfd, me);
            }
            if (mfd >= 0) {
                klog_printf("[MUT_%d_OPEN] *** SUCCESS *** %s unlocked mp4/dump_for_decid!\n",
                            t, targets[t].tag);
                close(mfd);
            }

            kekcall(KEKCALL_RESTORE_FULL, 0, (uintptr_t)bkp, 0);
            klog_printf("[MUT_%d_RESTORE] done\n", t);
        }
        klog_printf("[AUTH_MUTATE_TEST] === END ===\n");
    }

    /* ========================================================================= */
    /* MP4_GATE_TEST: ОТКЛЮЧЕНО (вызывает ребут через ~5s после 2-3 open'ов     */
    /* mp4/dump_for_decid под модифицированным global state — похоже на         */
    /* kernel-side watchdog/race condition).                                     */
    /* ========================================================================= */
    if (0) {
        uint64_t kbase_now = (uint64_t)kekcall(KEKCALL_GET_KBASE, 0, 0, 0);
        if (kbase_now > 0xffffffff00000000ULL) {
            uint64_t global_va = kbase_now + 0xc2446cULL;
            uint64_t string_va = kbase_now + 0x2c5c310ULL;

            klog_printf("[MP4_GATE] kbase=0x%llx global_va=0x%llx string_va=0x%llx\n",
                        (unsigned long long)kbase_now,
                        (unsigned long long)global_va,
                        (unsigned long long)string_va);

            /* Читаем текущее значение глобала и строку рядом */
            uint64_t orig_val = 0;
            kekcall(KEKCALL_DUMP_MEM, global_va, (uintptr_t)&orig_val, 8);
            klog_printf("[MP4_GATE] CURRENT global = 0x%016llx\n",
                        (unsigned long long)orig_val);

            uint8_t strbuf[128] = {0};
            kekcall(KEKCALL_DUMP_MEM, string_va, (uintptr_t)strbuf, sizeof(strbuf));
            /* защищённо печатаем первые 100 символов */
            strbuf[sizeof(strbuf)-1] = 0;
            klog_printf("[MP4_GATE] near-string: '%.*s'\n", 100, (char*)strbuf);

            /* Перебираем значения 0..7. Низшие 32 бита — то что сравнивают
             * check-функции (mov ecx, [rip+..] — 32-битное чтение). */
            for (uint32_t probe = 0; probe < 8; probe++) {
                uint64_t test_val = (orig_val & 0xffffffff00000000ULL) | (uint64_t)probe;
                long wr = kekcall(27 /* KEKCALL_WRITE64 */, global_va, test_val, 0);

                uint64_t readback = 0;
                kekcall(KEKCALL_DUMP_MEM, global_va, (uintptr_t)&readback, 8);
                klog_printf("[GATE_%u] wr_ret=%ld wrote=0x%llx readback=0x%llx\n",
                            probe, wr,
                            (unsigned long long)test_val,
                            (unsigned long long)readback);

                errno = 0;
                int gfd = open("/dev/mp4/dump_for_decid", O_RDWR);
                int ge  = errno;
                klog_printf("[GATE_%u_OPEN] O_RDWR fd=%d errno=%d\n", probe, gfd, ge);
                if (gfd < 0) {
                    errno = 0;
                    gfd = open("/dev/mp4/dump_for_decid", O_RDONLY);
                    ge  = errno;
                    klog_printf("[GATE_%u_OPEN] O_RDONLY fd=%d errno=%d\n", probe, gfd, ge);
                }
                if (gfd >= 0) {
                    klog_printf("[GATE_%u_OPEN] *** SUCCESS *** probe=%u opened mp4/dump_for_decid!\n",
                                probe, probe);
                    close(gfd);
                }
            }

            /* Восстанавливаем исходное значение глобала */
            long rr = kekcall(27 /* KEKCALL_WRITE64 */, global_va, orig_val, 0);
            uint64_t final_readback = 0;
            kekcall(KEKCALL_DUMP_MEM, global_va, (uintptr_t)&final_readback, 8);
            klog_printf("[MP4_GATE] RESTORED orig=0x%llx (wr_ret=%ld, readback=0x%llx) %s\n",
                        (unsigned long long)orig_val, rr,
                        (unsigned long long)final_readback,
                        (final_readback == orig_val) ? "OK" : "MISMATCH");
        } else {
            klog_printf("[MP4_GATE] skipped: kbase invalid (0x%llx)\n", (unsigned long long)kbase_now);
        }
    }

    /* ========================================================================= */
    /* DOPEN_JMP_PATCH: пропускаем auth-chain в real d_open mp4/dump_for_decid.  */
    /* На real_dopen+0x18 стоит `call target1` (5 байт). Заменяем на jmp +0x51   */
    /* чтобы попасть прямо в softc init path @ offset 0x6e. Это должно и open   */
    /* сделать успешным, и softc инициализировать (write/ioctl тогда ОК).       */
    /* Безопасно: читаем 8 байт (патч+3 сохраняемых) → WRITE64 → open → RESTORE.*/
    /* real_dopen вычисляем через csw+0x10 trampoline как в DOPEN_HEX.          */
    /* ========================================================================= */
    if (dedicated_mp4_csw) {
        uint64_t orig_dopen2 = 0;
        kekcall(KEKCALL_DUMP_MEM, dedicated_mp4_csw + 0x10ULL, (uintptr_t)&orig_dopen2, 8);
        uint64_t real_dopen2 = orig_dopen2;
        if (orig_dopen2 && (orig_dopen2 >> 48) == 0xffff) {
            uint8_t tramp2[16] = {0};
            kekcall(KEKCALL_DUMP_MEM, orig_dopen2, (uintptr_t)tramp2, 16);
            if (tramp2[0] == 0xe9) {
                int32_t rel32 = (int32_t)(tramp2[1] | (tramp2[2]<<8) | (tramp2[3]<<16) | (tramp2[4]<<24));
                real_dopen2 = orig_dopen2 + 5 + (int64_t)rel32;
            }
        }
        klog_printf("[DOPEN_JMP] real_dopen=0x%llx, patching +0x18 (call→jmp 0x6e)\n",
                    (unsigned long long)real_dopen2);

        if (real_dopen2 && (real_dopen2 >> 48) == 0xffff) {
            uint64_t patch_addr = real_dopen2 + 0x18ULL;
            uint64_t orig_qword = 0;
            kekcall(KEKCALL_DUMP_MEM, patch_addr, (uintptr_t)&orig_qword, 8);
            klog_printf("[DOPEN_JMP] saved orig 8 bytes at 0x%llx: 0x%016llx\n",
                        (unsigned long long)patch_addr, (unsigned long long)orig_qword);

            /* Новый qword: байты [0..4] = e9 51 00 00 00 (jmp +0x51), байты [5..7] = original */
            uint8_t bytes[8];
            memcpy(bytes, &orig_qword, 8);
            bytes[0] = 0xe9;
            bytes[1] = 0x51;
            bytes[2] = 0x00;
            bytes[3] = 0x00;
            bytes[4] = 0x00;
            uint64_t new_qword = 0;
            memcpy(&new_qword, bytes, 8);

            long wr = kekcall(27 /* KEKCALL_WRITE64 */, patch_addr, new_qword, 0);
            uint64_t rb = 0;
            kekcall(KEKCALL_DUMP_MEM, patch_addr, (uintptr_t)&rb, 8);
            klog_printf("[DOPEN_JMP] wr_ret=%ld wrote=0x%016llx readback=0x%016llx %s\n",
                        wr, (unsigned long long)new_qword, (unsigned long long)rb,
                        (rb == new_qword) ? "PATCHED" : "WRITE-FAILED");

            if (rb == new_qword) {
                errno = 0;
                int jfd = open("/dev/mp4/dump_for_decid", O_RDWR);
                int je_err = errno;
                klog_printf("[DOPEN_JMP_OPEN] O_RDWR fd=%d errno=%d\n", jfd, je_err);
                if (jfd < 0) {
                    errno = 0;
                    jfd = open("/dev/mp4/dump_for_decid", O_RDONLY);
                    je_err = errno;
                    klog_printf("[DOPEN_JMP_OPEN] O_RDONLY fd=%d errno=%d\n", jfd, je_err);
                }
                if (jfd >= 0) {
                    klog_printf("[DOPEN_JMP_OPEN] *** SUCCESS *** opened mp4/dump_for_decid with legitimate init!\n");

                    /* d_write — это заглушка (b8 13 00 00 00 c3 = mov eax, ENODEV; ret),
                     * write в этот device не предусмотрен. Это dump-only identifier
                     * channel. Пробуем read разных размеров и ioctl для trigger'а. */

                    /* 1) RAW READ разных размеров */
                    static uint8_t rbuf[4096];
                    for (unsigned int rsz = 16; rsz <= 4096; rsz <<= 1) {
                        memset(rbuf, 0, sizeof(rbuf));
                        errno = 0;
                        ssize_t nr = read(jfd, rbuf, rsz);
                        int re = errno;
                        klog_printf("[READ_%u] nr=%zd errno=%d first16=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
                                    rsz, nr, re,
                                    rbuf[0],rbuf[1],rbuf[2],rbuf[3], rbuf[4],rbuf[5],rbuf[6],rbuf[7],
                                    rbuf[8],rbuf[9],rbuf[10],rbuf[11], rbuf[12],rbuf[13],rbuf[14],rbuf[15]);
                        if (nr > 0) {
                            klog_printf("[READ_%u] *** GOT DATA *** full hex dump of %zd bytes:\n", rsz, nr);
                            for (ssize_t off = 0; off < nr && off < 256; off += 16) {
                                klog_printf("[DUMP+%03zx] %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                            off,
                                            rbuf[off+0], rbuf[off+1], rbuf[off+2], rbuf[off+3],
                                            rbuf[off+4], rbuf[off+5], rbuf[off+6], rbuf[off+7],
                                            rbuf[off+8], rbuf[off+9], rbuf[off+10], rbuf[off+11],
                                            rbuf[off+12], rbuf[off+13], rbuf[off+14], rbuf[off+15]);
                            }
                            break; /* нашли данные — хватит перебирать размеры */
                        }
                    }

                    /* 2) IOCTL REAL CMDs: разобраны оффлайн из d_ioctl switch
                     *    0x4014421b = _IOW('B',27, 20-byte struct)
                     *    0x4014421c = _IOW('B',28, 20-byte struct)
                     *    0xc014420b = _IOWR('B',11, 20-byte struct)
                     *    0xc0144215 = _IOWR('B',21, 20-byte struct)
                     * Группа 'B' = 0x42, size=0x14=20 байт. */
                    /* B_11 (0xc014420b) и B_21 (0xc0144215) блокируют поток
                     * (waiting на mp4 hw response) → убраны. Сначала пробуем
                     * init cmd'ы B_28/B_31/B_32, смотрим на return. */
                    {
                        /* B_28: _IOW('B',28, 20 bytes) — первый в прошлый ран дал
                         *       ret=0, out[0..3]=14 00 00 00 (=20), out[8..11]=ff ff ff ff */
                        uint8_t a[20] = {0};
                        errno = 0;
                        int ir = ioctl(jfd, 0x4014421c, a);
                        int ie = errno;
                        klog_printf("[IOCTL_IOW_B_28] ret=%d errno=%d out20=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
                                    ir, ie,
                                    a[0],a[1],a[2],a[3], a[4],a[5],a[6],a[7],
                                    a[8],a[9],a[10],a[11], a[12],a[13],a[14],a[15],
                                    a[16],a[17],a[18],a[19]);
                    }
                    {
                        /* B_31: _IOW('B',31, 8 bytes) — маленький, вероятно init */
                        uint8_t a[8] = {0};
                        errno = 0;
                        int ir = ioctl(jfd, 0x4008421f, a);
                        int ie = errno;
                        klog_printf("[IOCTL_IOW_B_31] ret=%d errno=%d out8=%02x%02x%02x%02x %02x%02x%02x%02x\n",
                                    ir, ie, a[0],a[1],a[2],a[3], a[4],a[5],a[6],a[7]);
                    }
                    {
                        /* B_32: _IOW('B',32, 8 bytes) — маленький, вероятно init */
                        uint8_t a[8] = {0};
                        errno = 0;
                        int ir = ioctl(jfd, 0x40084220, a);
                        int ie = errno;
                        klog_printf("[IOCTL_IOW_B_32] ret=%d errno=%d out8=%02x%02x%02x%02x %02x%02x%02x%02x\n",
                                    ir, ie, a[0],a[1],a[2],a[3], a[4],a[5],a[6],a[7]);
                    }
                    /* После init cmd'ов повтор read'а и B_28 — вдруг изменилось */
                    {
                        uint8_t a[20] = {0};
                        errno = 0;
                        int ir = ioctl(jfd, 0x4014421c, a);
                        int ie = errno;
                        klog_printf("[IOCTL_IOW_B_28_AGAIN] ret=%d errno=%d out20=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
                                    ir, ie,
                                    a[0],a[1],a[2],a[3], a[4],a[5],a[6],a[7],
                                    a[8],a[9],a[10],a[11], a[12],a[13],a[14],a[15],
                                    a[16],a[17],a[18],a[19]);
                    }

                    /* 3) После ioctl-попыток — ещё один read 4096 на случай если ioctl разогрел буфер */
                    memset(rbuf, 0, sizeof(rbuf));
                    errno = 0;
                    ssize_t nr_final = read(jfd, rbuf, 4096);
                    int re_final = errno;
                    klog_printf("[READ_AFTER_IOCTL] nr=%zd errno=%d first16=%02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x %02x%02x%02x%02x\n",
                                nr_final, re_final,
                                rbuf[0],rbuf[1],rbuf[2],rbuf[3], rbuf[4],rbuf[5],rbuf[6],rbuf[7],
                                rbuf[8],rbuf[9],rbuf[10],rbuf[11], rbuf[12],rbuf[13],rbuf[14],rbuf[15]);

                    close(jfd);
                }
            }

            /* Восстанавливаем оригинальные 8 байт */
            long rr = kekcall(27 /* KEKCALL_WRITE64 */, patch_addr, orig_qword, 0);
            uint64_t final_rb = 0;
            kekcall(KEKCALL_DUMP_MEM, patch_addr, (uintptr_t)&final_rb, 8);
            klog_printf("[DOPEN_JMP] RESTORED orig=0x%016llx wr_ret=%ld readback=0x%016llx %s\n",
                        (unsigned long long)orig_qword, rr,
                        (unsigned long long)final_rb,
                        (final_rb == orig_qword) ? "OK" : "MISMATCH-DANGER");
        }
    }

    /* ------------------------------------------------------------------------- */
    /* ДЕКОДИРОВАНИЕ TRAMPOLINE И ДАМП РЕАЛЬНОГО .text ДЛЯ d_write, d_ioctl, etc */
    /* ------------------------------------------------------------------------- */
    if (dedicated_mp4_csw) {
        struct {
            const char *name;
            uint32_t csw_off;
            uint32_t dump_size;
        } ops[] = {
            { "d_write", 0x30, 0x600 },
            { "d_ioctl", 0x38, 0x600 },
            { "d_read",  0x28, 0x400 },
            { "d_mmap",  0x48, 0x400 },
            { "d_open",  0x10, 0x400 }
        };

        for (int op = 0; op < 5; op++) {
            uint64_t tramp = 0;
            kekcall(KEKCALL_DUMP_MEM, dedicated_mp4_csw + ops[op].csw_off, (uintptr_t)&tramp, 8);
            klog_printf("[TRAMP] %s @ csw+0x%02x: 0x%llx\n", ops[op].name, ops[op].csw_off, (unsigned long long)tramp);

            if (!tramp || (tramp >> 48) != 0xffff) continue;

            uint8_t tb[16] = {0};
            kekcall(KEKCALL_DUMP_MEM, tramp, (uintptr_t)tb, 16);
            klog_printf("[TRAMP_BYTES] %s: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        ops[op].name, tb[0], tb[1], tb[2], tb[3], tb[4], tb[5], tb[6], tb[7]);

            uint64_t target = tramp;
            if (tb[0] == 0xe9) {
                int32_t rel32 = (int32_t)(tb[1] | (tb[2] << 8) | (tb[3] << 16) | (tb[4] << 24));
                target = tramp + 5 + rel32;
                klog_printf("[TRAMP_RESOLVE] %s: 0x%llx + 5 + (%d) = 0x%llx\n",
                            ops[op].name, (unsigned long long)tramp, (int)rel32, (unsigned long long)target);
            }

            /* Дамп тела функции */
            uint32_t sz = ops[op].dump_size;
            if (sz > 0x600) sz = 0x600;
            uint8_t func_buf[0x600];
            memset(func_buf, 0, sz);
            long r_fn = kekcall(KEKCALL_DUMP_MEM, target, (uintptr_t)func_buf, sz);
            klog_printf("[FUNC_DUMP] === %s @ 0x%llx (size=0x%x, ret=%ld) ===\n",
                        ops[op].name, (unsigned long long)target, sz, r_fn);

            for (uint32_t b = 0; b < sz; b += 16) {
                klog_printf("[%s+0x%03x] %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                            ops[op].name, b,
                            func_buf[b+0], func_buf[b+1], func_buf[b+2], func_buf[b+3],
                            func_buf[b+4], func_buf[b+5], func_buf[b+6], func_buf[b+7],
                            func_buf[b+8], func_buf[b+9], func_buf[b+10], func_buf[b+11],
                            func_buf[b+12], func_buf[b+13], func_buf[b+14], func_buf[b+15]);
            }
        }
    }

    /* ========================================================================= */
    /* ПРИОРИТЕТНЫЙ БЛОК: ТРИ НОВЫХ ТЕСТА (DIFF, PRISON, P_SYSTEM)               */
    /* ========================================================================= */

    uint64_t our_ucred = scanned_td_ucred;
    uint64_t video_ucred = 0;
    uint32_t video_pid = 0;

    /* Ищем ucred процесса SceVideoCore2K или первого media daemon (low authid == 0x1005 / 0x1004) */
    for (int c = 0; c < ncand; c++) {
        uint64_t a = g_cand_authids[c];
        uint16_t low = a & 0xFFFF;
        if (low == 0x1005 || low == 0x1004 || low == 0x1002 || strstr(g_cand_comms[c], "Video") || strstr(g_cand_comms[c], "Media")) {
            video_ucred = g_cand_ucreds[c];
            video_pid = g_cand_pids[c];
            break;
        }
    }
    if (!video_ucred && ncand > 0) {
        /* Fallback на лучшего кандидата */
        video_ucred = g_cand_ucreds[ncand > 7 ? 7 : 0];
        video_pid = g_cand_pids[ncand > 7 ? 7 : 0];
    }

    klog_printf("[SETUP] our_ucred=0x%llx target_video_ucred=0x%llx (pid=%u)\n",
                (unsigned long long)our_ucred, (unsigned long long)video_ucred, video_pid);

    /* ------------------------------------------------------------------------- */
    /* ТЕСТ 1 — UCRED DIFF В ЯДРЕ ЧЕРЕЗ KEKCALL_DIFF_TEST (32)                   */
    /* ------------------------------------------------------------------------- */
    klog_printf("[TEST1_START] === TEST 1: KERNEL UCRED DIFF (KEKCALL 32, flag=0) ===\n");
    static uint64_t diff_buf[128];
    memset(diff_buf, 0, sizeof(diff_buf));

    long diff_ret = kekcall(KEKCALL_DIFF_TEST, video_ucred, (uintptr_t)diff_buf, 0 /* read-only diff */);
    klog_printf("[TEST1] KEKCALL_DIFF_TEST ret=%ld diff_count=%llu prison_off=0x%llx cand_prison=0x%llx\n",
                diff_ret, (unsigned long long)diff_buf[0], (unsigned long long)diff_buf[1], (unsigned long long)diff_buf[3]);

    uint32_t diff_cnt = (uint32_t)diff_buf[0];
    for (uint32_t d = 0; d < diff_cnt && d < 24; d++) {
        uint32_t off = (uint32_t)diff_buf[6 + d * 3 + 0];
        uint64_t our_v = diff_buf[6 + d * 3 + 1];
        uint64_t vid_v = diff_buf[6 + d * 3 + 2];
        klog_printf("[DIFF #%u] +0x%03x our=0x%016llx video=0x%016llx\n",
                    d, off, (unsigned long long)our_v, (unsigned long long)vid_v);
    }

    /* ------------------------------------------------------------------------- */
    /* ГЛАВНЫЙ ТЕСТ: IN-PLACE MUTATION (КЛОНИРОВАНИЕ ПОЛЕЙ БЕЗ ПОДМЕНЫ УКАЗАТЕЛЯ) */
    /* ------------------------------------------------------------------------- */
    klog_printf("[INPLACE_START] === TEST: IN-PLACE UCRED MUTATION (KEKCALL 34) ===\n");
    {
        static uint64_t inplace_bkp[64];
        memset(inplace_bkp, 0, sizeof(inplace_bkp));

        long mut_ret = kekcall(KEKCALL_MUTATE_INPLACE, video_ucred, (uintptr_t)inplace_bkp, 0);
        klog_printf("[INPLACE_SET] KEKCALL_MUTATE_INPLACE ret=%ld\n", mut_ret);

        errno = 0;
        int fd_mut = open("/dev/mp4/dump_for_decid", O_RDWR);
        int em = errno;
        if (fd_mut < 0 && em == 1) {
            fd_mut = open("/dev/mp4/dump_for_decid", O_RDONLY);
            em = errno;
        }
        klog_printf("[INPLACE_OPEN] fd=%d errno=%d\n", fd_mut, em);

        if (fd_mut >= 0) {
            klog_printf("[INPLACE_OPEN] *** BINGO! VICTORY! /dev/mp4/dump_for_decid OPENED WITH IN-PLACE MUTATION! ***\n");
            uint8_t cmd[4] = {0x01, 0x00, 0x00, 0x00};
            errno = 0;
            ssize_t nw = write(fd_mut, cmd, 4);
            int we = errno;
            uint8_t rdata[256] = {0};
            errno = 0;
            ssize_t nr = read(fd_mut, rdata, sizeof(rdata));
            int re = errno;
            klog_printf("[INPLACE_IO] write nw=%zd (errno=%d) read nr=%zd (errno=%d)\n", nw, we, nr, re);
            if (nr > 0) {
                klog_printf("[INPLACE_DATA] first_u32=0x%08x\n", *(uint32_t*)rdata);
            }
            close(fd_mut);
        }

        /* Восстановление */
        long rst_ret = kekcall(KEKCALL_RESTORE_INPLACE, (uintptr_t)inplace_bkp, 0, 0);
        klog_printf("[INPLACE_RESTORE] KEKCALL_RESTORE_INPLACE ret=%ld\n", rst_ret);
    }

    /* ========================================================================= */
    /* ШАГИ A, B, C, D: РАЗВЕДКА И ИНЪЕКЦИЯ SOFTC                                */
    /* ========================================================================= */

    uint64_t mp4_cdev_addr = g_cdev_mp4_dump_for_decid ? g_cdev_mp4_dump_for_decid : dedicated_mp4_cdev;

    /* ------------------------------------------------------------------------- */
    /* ШАГ A — Dump cdev трёх соседей (+0x60..+0x90)                             */
    /* ------------------------------------------------------------------------- */
    klog_printf("[STEP_A] === STEP A: Dump neighbour cdevs for softc discovery ===\n");
    klog_printf("[STEP_A] targets: ioc=0x%llx mmc=0x%llx coredump=0x%llx mp4=0x%llx\n",
                (unsigned long long)g_cdev_deci_mp4_ioc,
                (unsigned long long)g_cdev_deci_mp4_mmc,
                (unsigned long long)g_cdev_deci_coredump,
                (unsigned long long)mp4_cdev_addr);

    uint64_t cdev_list[4] = {
        g_cdev_deci_mp4_ioc,
        g_cdev_deci_mp4_mmc,
        g_cdev_deci_coredump,
        mp4_cdev_addr
    };

    uint64_t discovered_softc = 0;
    uint32_t discovered_softc_off = 0;

    for (int n = 0; n < 4; n++) {
        uint64_t cdev = cdev_list[n];
        if (!cdev) continue;
        uint64_t nwords[8] = {0};
        kekcall(KEKCALL_DUMP_MEM, cdev + 0x60ULL, (uintptr_t)nwords, 64);
        klog_printf("[CDEV_DUMP #%d @ 0x%llx +0x60..0x98]:\n", n, (unsigned long long)cdev);
        for (int i = 0; i < 8; i++) {
            uint32_t off = 0x60 + i * 8;
            uint64_t val = nwords[i];
            klog_printf("  +0x%02x = 0x%016llx\n", off, (unsigned long long)val);

            /* Шаг B: ищем non-NULL softc в диапазоне +0x68..+0x80 у открывающихся соседей */
            if (n < 3 && (off == 0x70 || off == 0x78 || off == 0x80) && val != 0 && (val >> 48) == 0xffff) {
                if (!discovered_softc) {
                    discovered_softc = val;
                    discovered_softc_off = off;
                }
            }
        }
    }


    /* ------------------------------------------------------------------------- */
    /* ШАГ B — Результат определения EXACT offset si_drv1                        */
    /* ------------------------------------------------------------------------- */
    klog_printf("[STEP_B] Discovered softc candidate: ptr=0x%llx at offset +0x%02x\n",
                (unsigned long long)discovered_softc, discovered_softc_off);

    /* ========================================================================= */
    /* ТЕСТ 1: DUMP И DIFF struct file ДЛЯ fd_mp4 И fd_ioc                      */
    /* ========================================================================= */
    /* ТЕСТ 1: DUMP И DIFF struct file ДЛЯ fd_mp4 И fd_ioc                      */
    /* ========================================================================= */
    klog_printf("[FILE_TEST] === TEST 1: Dump and diff struct file for open fds ===\n");

    /* RE-INSTALL SIGSYS handler с SA_NODEFER для защиты от unmapped адресов ядра */
    struct sigaction sa_ft;
    memset(&sa_ft, 0, sizeof(sa_ft));
    sa_ft.sa_handler = sigsys_handler;
    sa_ft.sa_flags = SA_NODEFER;
    sigaction(SIGSYS, &sa_ft, NULL);

    if (sigsetjmp(g_sigsys_jmp, 1) == 0) {
        if (dedicated_mp4_csw) {
            /* Временно ставим null_dopen для получения дескрипторов */
            kekcall(27 /* WRITE64 */, dedicated_mp4_csw + 0x10ULL, null_dopen, 0);

            int fd_mp4 = open("/dev/mp4/dump_for_decid", O_RDWR);
            int fd_null = open("/dev/null", O_RDWR);
            klog_printf("[FILE_TEST] opened fds: fd_mp4=%d fd_null=%d\n", fd_mp4, fd_null);

            /* Если fd_null почему-то не открылся, используем stdin (fd=0) или stdout (fd=1) для diff */
            int fd_ref = (fd_null >= 0) ? fd_null : 1;

            /* Получаем указатели fd_files, fp_mp4, fp_ref через KEKCALL 36 в Ring 0 */
            uint64_t fd_info[40] = {0};
            long r_info = kekcall(KEKCALL_GET_FD_INFO, (uint64_t)fd_mp4, (uint64_t)fd_ref, (uintptr_t)fd_info);
            uint64_t p_fd = fd_info[0];
            uint64_t verified_fd_files = fd_info[1];
            uint64_t fp_mp4 = fd_info[2];
            uint64_t fp_null = fd_info[3];
            int p_fd_off = (int)fd_info[4];

            klog_printf("[RING0_FD_INFO] ret=%ld p_fd=0x%llx (off=0x%x) fdt=0x%llx fp_mp4=0x%llx fp_ref=0x%llx\n",
                        r_info, (unsigned long long)p_fd, p_fd_off, (unsigned long long)verified_fd_files,
                        (unsigned long long)fp_mp4, (unsigned long long)fp_null);

            for (int i = 0; i < 32; i++) {
                klog_printf("[FDT+0x%02x] = 0x%016llx\n", i * 8, (unsigned long long)fd_info[5 + i]);
            }

            /* Если fp_null на fd=10 был 0, берём гарантированно открытый fd=1 (+0x18 в fdt) или fd=0 (+0x10) */
            if (!fp_null || (fp_null >> 48) != 0xffff) {
                fp_null = fd_info[5 + 1]; /* FDT+0x08 для fd=0 или +0x18 для fd=1: слоты 5+2, 5+3 */
                if ((fp_null >> 48) != 0xffff) fp_null = fd_info[5 + 2]; /* fd=0: +0x10 */
                klog_printf("[REF_FALLBACK] using ref fp from fdt: 0x%llx\n", (unsigned long long)fp_null);
            }

            /* Модуль 37: DIFF_FP прямо в Ring 0 */
            uint64_t diff_table[32] = {0};
            uint32_t f_cdevpriv_off = (uint32_t)kekcall(KEKCALL_DIFF_FP, fp_mp4, fp_null, (uintptr_t)diff_table);
            klog_printf("[RING0_DIFF_FP] detected cdevpriv candidate offset: +0x%x\n", f_cdevpriv_off);

            for (int i = 0; i < 16; i++) {
                if (diff_table[i] != 0) {
                    klog_printf("[DIFF_FP +0x%02x] xor=0x%016llx\n", i * 8, (unsigned long long)diff_table[i]);
                }
            }

            /* Тест write до инъекции softc */
            uint8_t payload[4] = {0x01, 0x02, 0x03, 0x04};
            ssize_t nw0 = write(fd_mp4, payload, sizeof(payload));
            klog_printf("[WRITE_BEFORE] nw=%zd errno=%d\n", nw0, errno);

            /* Модуль 38: INJECT_CDEVPRIV по найденному смещению и стандартным смещениям */
            uint32_t target_offs[] = { f_cdevpriv_off, 0x38, 0x40, 0x48 };
            for (int t = 0; t < 4; t++) {
                uint32_t inj_off = target_offs[t];
                if (!inj_off) continue;

                /* Инжектируем softc через KEKCALL 38 */
                uint64_t bk = (uint64_t)kekcall(KEKCALL_INJECT_CDEVPRIV, fp_mp4, (uint64_t)inj_off, dedicated_mp4_cdev);
                klog_printf("[INJECT_CDEVPRIV +0x%x] injected cdev=0x%llx (old_val=0x%llx)\n",
                            inj_off, (unsigned long long)dedicated_mp4_cdev, (unsigned long long)bk);

                /* Тест записи */
                errno = 0;
                ssize_t nw = write(fd_mp4, payload, sizeof(payload));
                int err = errno;
                klog_printf("[TEST_WRITE +0x%x] nw=%zd errno=%d\n", inj_off, nw, err);

                /* Восстанавливаем старое значение через KEKCALL 38 */
                kekcall(KEKCALL_INJECT_CDEVPRIV, fp_mp4, (uint64_t)inj_off, bk);

                if (nw >= 0 || err != 19) {
                    klog_printf("[BREAKTHROUGH!] ENODEV 19 BYPASSED AT +0x%x! nw=%zd errno=%d\n",
                                inj_off, nw, err);
                    break;
                }
            }

            if (fd_mp4 >= 0) close(fd_mp4);
            if (fd_null >= 0) close(fd_null);

            /* Возвращаем оригинальный d_open */
            kekcall(27 /* WRITE64 */, dedicated_mp4_csw + 0x10ULL, orig_dopen_calc, 0);
        }
    } else {
        klog_printf("[FILE_TEST] SIGSYS caught — safe exit\n");
    }

    signal(SIGSYS, SIG_DFL);

    /* ========================================================================= */
    /* NATIVE_OPEN: плоский open БЕЗ патча csw + дамп ucred для EPERM анализа     */
    /* ========================================================================= */
    klog_printf("[NATIVE_OPEN] === Probing /dev/mp4/dump_for_decid without csw patch ===\n");
    errno = 0;
    int nfd_rdwr = open("/dev/mp4/dump_for_decid", 0x0002 /* O_RDWR */);
    int nerr_rdwr = errno;
    klog_printf("[NATIVE_OPEN] O_RDWR: fd=%d errno=%d\n", nfd_rdwr, nerr_rdwr);
    if (nfd_rdwr >= 0) {
        klog_printf("[NATIVE_OPEN] *** UNEXPECTED SUCCESS O_RDWR fd=%d ***\n", nfd_rdwr);
        close(nfd_rdwr);
    }

    errno = 0;
    int nfd_rdonly = open("/dev/mp4/dump_for_decid", 0x0000 /* O_RDONLY */);
    int nerr_rdonly = errno;
    klog_printf("[NATIVE_OPEN] O_RDONLY: fd=%d errno=%d\n", nfd_rdonly, nerr_rdonly);
    if (nfd_rdonly >= 0) {
        klog_printf("[NATIVE_OPEN] *** RDONLY SUCCESS fd=%d (write-check differs) ***\n", nfd_rdonly);
        close(nfd_rdonly);
    }

    /* OUR ucred dump: full 0x200 window + extracted named fields */
    static uint8_t ucred_buf[0x200];
    if (our_ucred) {
        memset(ucred_buf, 0, sizeof(ucred_buf));
        long r_u = kekcall(KEKCALL_DUMP_MEM, our_ucred, (uintptr_t)ucred_buf, sizeof(ucred_buf));
        klog_printf("[OUR_UCRED @ 0x%llx] dump_ret=%ld (size=0x200)\n",
                    (unsigned long long)our_ucred, r_u);
        for (int b = 0; b < (int)sizeof(ucred_buf); b += 16) {
            klog_printf("[OUR_UCRED+0x%03x] %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        b,
                        ucred_buf[b+0], ucred_buf[b+1], ucred_buf[b+2], ucred_buf[b+3],
                        ucred_buf[b+4], ucred_buf[b+5], ucred_buf[b+6], ucred_buf[b+7],
                        ucred_buf[b+8], ucred_buf[b+9], ucred_buf[b+10], ucred_buf[b+11],
                        ucred_buf[b+12], ucred_buf[b+13], ucred_buf[b+14], ucred_buf[b+15]);
        }

        uint32_t cr_uid        = *(uint32_t*)(ucred_buf + 0x04);
        uint32_t cr_ruid       = *(uint32_t*)(ucred_buf + 0x08);
        uint32_t cr_svuid      = *(uint32_t*)(ucred_buf + 0x0c);
        uint64_t cr_prison     = *(uint64_t*)(ucred_buf + 0x30);
        uint64_t cr_sce_authid = *(uint64_t*)(ucred_buf + 0x58);
        uint64_t cr_label      = *(uint64_t*)(ucred_buf + 0x78);
        uint64_t cr_118        = *(uint64_t*)(ucred_buf + 0x118);
        uint64_t cr_120        = *(uint64_t*)(ucred_buf + 0x120);
        uint64_t cr_1f8        = *(uint64_t*)(ucred_buf + 0x1f8);

        klog_printf("[UCRED_FIELDS] cr_uid=%u cr_ruid=%u cr_svuid=%u\n",
                    cr_uid, cr_ruid, cr_svuid);
        klog_printf("[UCRED_FIELDS] cr_prison=0x%llx cr_sce_authid=0x%llx cr_label=0x%llx\n",
                    (unsigned long long)cr_prison,
                    (unsigned long long)cr_sce_authid,
                    (unsigned long long)cr_label);
        klog_printf("[UCRED_FIELDS] +0x118=0x%llx +0x120=0x%llx +0x1f8=0x%llx\n",
                    (unsigned long long)cr_118,
                    (unsigned long long)cr_120,
                    (unsigned long long)cr_1f8);

        if (cr_label) {
            uint8_t lbl_buf[64] = {0};
            long r_l = kekcall(KEKCALL_DUMP_MEM, cr_label, (uintptr_t)lbl_buf, sizeof(lbl_buf));
            klog_printf("[MAC_LABEL] cr_label=0x%llx dump_ret=%ld\n",
                        (unsigned long long)cr_label, r_l);
            for (int b = 0; b < 64; b += 16) {
                klog_printf("[MAC_LABEL+0x%02x] %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                            b,
                            lbl_buf[b+0], lbl_buf[b+1], lbl_buf[b+2], lbl_buf[b+3],
                            lbl_buf[b+4], lbl_buf[b+5], lbl_buf[b+6], lbl_buf[b+7],
                            lbl_buf[b+8], lbl_buf[b+9], lbl_buf[b+10], lbl_buf[b+11],
                            lbl_buf[b+12], lbl_buf[b+13], lbl_buf[b+14], lbl_buf[b+15]);
            }
        } else {
            klog_printf("[MAC_LABEL] cr_label=0 — no MAC policy label attached\n");
        }
    } else {
        klog_printf("[OUR_UCRED] ERROR: our_ucred=0 — skipping dump\n");
    }

    /* SI_CRED dump: per-mp4-cdev. si_cred @ cdev+0xa8 */
    static uint8_t sicred_buf[0x200];
    for (int m = 0; m < mp4_count; m++) {
        uint64_t cdev = mp4_cdev_nodes[m];
        if (!cdev) continue;
        uint64_t si_cred = 0;
        kekcall(KEKCALL_DUMP_MEM, cdev + 0xa8ULL, (uintptr_t)&si_cred, 8);
        klog_printf("[SI_CRED] cdev[%d] '%s' @ 0x%llx -> si_cred=0x%llx\n",
                    m, mp4_names[m], (unsigned long long)cdev, (unsigned long long)si_cred);
        if (!si_cred) {
            klog_printf("[SI_CRED] cdev[%d] NULL — DAC via vnode mode/uid/gid, not ucred compare\n", m);
            continue;
        }
        memset(sicred_buf, 0, sizeof(sicred_buf));
        long r_sc = kekcall(KEKCALL_DUMP_MEM, si_cred, (uintptr_t)sicred_buf, sizeof(sicred_buf));
        klog_printf("[SI_CRED @ 0x%llx cdev='%s'] dump_ret=%ld (size=0x200)\n",
                    (unsigned long long)si_cred, mp4_names[m], r_sc);
        for (int b = 0; b < (int)sizeof(sicred_buf); b += 16) {
            klog_printf("[SI_CRED[%d]+0x%03x] %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        m, b,
                        sicred_buf[b+0], sicred_buf[b+1], sicred_buf[b+2], sicred_buf[b+3],
                        sicred_buf[b+4], sicred_buf[b+5], sicred_buf[b+6], sicred_buf[b+7],
                        sicred_buf[b+8], sicred_buf[b+9], sicred_buf[b+10], sicred_buf[b+11],
                        sicred_buf[b+12], sicred_buf[b+13], sicred_buf[b+14], sicred_buf[b+15]);
        }
        /* NOTE: cdev+0xa8 на PS5 — НЕ struct ucred (FreeBSD si_cred), а Sony-
         * specific device-private context (vtable для cdev[0], mp4_dev_t с
         * guard 0xdeadbeef для cdev[1]). Поля ниже — просто сырые qword'ы
         * на тех же оффсетах, НЕ интерпретировать как ucred. */
        uint64_t q00 = *(uint64_t*)(sicred_buf + 0x00);
        uint64_t q08 = *(uint64_t*)(sicred_buf + 0x08);
        uint64_t q58 = *(uint64_t*)(sicred_buf + 0x58);
        uint64_t q1f8 = *(uint64_t*)(sicred_buf + 0x1f8);
        klog_printf("[DEVCTX cdev[%d]] (NOT ucred) +0x00=0x%llx +0x08=0x%llx +0x58=0x%llx +0x1f8=0x%llx\n",
                    m,
                    (unsigned long long)q00,
                    (unsigned long long)q08,
                    (unsigned long long)q58,
                    (unsigned long long)q1f8);
    }
    klog_printf("[NATIVE_OPEN] === END probe ===\n");




    /* ------------------------------------------------------------------------- */
    /* ПРИНУДИТЕЛЬНО закрываем все лишние дескрипторы процесса (fd 3..64)        */
    /* ------------------------------------------------------------------------- */
    klog_printf("[CLEANUP] Closing extra fds 3..64 for predictable slot mapping...\n");
    for (int i = 3; i < 64; i++) {
        close(i);
    }

    /* Шаг 4: патчим все найденные mp4 cdevsw */
    for (int m = 0; m < mp4_count; m++) {
        uint64_t target_csw = mp4_parent_csws[m];
        if (!target_csw) continue;
        uint64_t orig_dopen = 0;
        kekcall(KEKCALL_DUMP_MEM, target_csw + 0x10ULL, (uintptr_t)&orig_dopen, 8);
        klog_printf("[STEP4] mp4 csw[%d] 0x%llx (node '%s'): orig_dopen=0x%llx\n",
                    m, (unsigned long long)target_csw, mp4_names[m], (unsigned long long)orig_dopen);

        /* --------------------------------------------------------------------- */
        /* ДАМП ВСЕЙ ТАБЛИЦЫ cdevsw (0x80 БАЙТ)                                 */
        /* --------------------------------------------------------------------- */
        klog_printf("[CDEVSW_DUMP] === Full cdevsw table dump for '%s' @ 0x%llx ===\n",
                    mp4_names[m], (unsigned long long)target_csw);
        for (int i = 0; i < 16; i++) {
            uint64_t slot_val = 0;
            kekcall(KEKCALL_DUMP_MEM, target_csw + (uint64_t)i * 8, (uintptr_t)&slot_val, 8);
            const char *slot_name = "field";
            if (i == 0) slot_name = "d_version";
            else if (i == 1) slot_name = "d_name";
            else if (i == 2) slot_name = "d_open";
            else if (i == 3) slot_name = "d_fdopen";
            else if (i == 4) slot_name = "d_close";
            else if (i == 5) slot_name = "d_read";
            else if (i == 6) slot_name = "d_write";
            else if (i == 7) slot_name = "d_ioctl";
            else if (i == 8) slot_name = "d_poll";
            else if (i == 9) slot_name = "d_mmap";
            klog_printf("[CSW+0x%02x] (%s) = 0x%016llx\n", i * 8, slot_name, (unsigned long long)slot_val);
        }

        /* --------------------------------------------------------------------- */
        /* ДАМП И ДЕКОДИРОВАНИЕ TRAMPOLINE d_open -> REAL d_open FUNCTION         */
        /* --------------------------------------------------------------------- */
        if (orig_dopen && (orig_dopen >> 48) == 0xffff) {
            uint8_t tramp[16] = {0};
            kekcall(KEKCALL_DUMP_MEM, orig_dopen, (uintptr_t)tramp, 16);
            klog_printf("[TRAMP] orig_dopen @ 0x%llx: %02x %02x %02x %02x %02x %02x %02x %02x\n",
                        (unsigned long long)orig_dopen,
                        tramp[0], tramp[1], tramp[2], tramp[3], tramp[4], tramp[5], tramp[6], tramp[7]);

            uint64_t real_dopen = 0;
            if (tramp[0] == 0xe9) {
                /* jmp rel32: target = orig_dopen + 5 + (int32_t)rel32 */
                int32_t rel32 = *(int32_t*)(tramp + 1);
                real_dopen = orig_dopen + 5 + (int64_t)rel32;
                klog_printf("[DECODE] rel32=0x%08x -> REAL d_open target = 0x%llx\n",
                            (uint32_t)rel32, (unsigned long long)real_dopen);
            } else {
                real_dopen = orig_dopen;
                klog_printf("[DECODE] direct entry point (no jmp) -> 0x%llx\n",
                            (unsigned long long)real_dopen);
            }

            /* Дамп 0x200 байт тела настоящей d_open функции */
            if (real_dopen && (real_dopen >> 48) == 0xffff) {
                klog_printf("[DUMP_REAL_DOPEN] === Real d_open @ 0x%llx (0x200 bytes) ===\n",
                            (unsigned long long)real_dopen);
                uint8_t body[512] = {0};
                kekcall(KEKCALL_DUMP_MEM, real_dopen, (uintptr_t)body, sizeof(body));
                for (int l = 0; l < 32; l++) {
                    klog_printf("[DOPEN+0x%03x] %02x %02x %02x %02x %02x %02x %02x %02x  %02x %02x %02x %02x %02x %02x %02x %02x\n",
                                l * 16,
                                body[l*16 + 0], body[l*16 + 1], body[l*16 + 2], body[l*16 + 3],
                                body[l*16 + 4], body[l*16 + 5], body[l*16 + 6], body[l*16 + 7],
                                body[l*16 + 8], body[l*16 + 9], body[l*16 + 10], body[l*16 + 11],
                                body[l*16 + 12], body[l*16 + 13], body[l*16 + 14], body[l*16 + 15]);
                }
            }
        }

        klog_printf("[STEP4] patching mp4 csw[%d] 0x%llx (node '%s'): orig=0x%llx -> null_dopen=0x%llx...\n",
                    m, (unsigned long long)target_csw, mp4_names[m],
                    (unsigned long long)orig_dopen, (unsigned long long)null_dopen);

        long wr = kekcall(27, target_csw + 0x10ULL, null_dopen, 0);
        klog_printf("[STEP4] KEKCALL_WRITE64 ret=%ld\n", wr);

        uint64_t rb = 0;
        kekcall(KEKCALL_DUMP_MEM, target_csw + 0x10ULL, (uintptr_t)&rb, 8);
        klog_printf("[STEP4] readback = 0x%llx (expected 0x%llx)\n",
                    (unsigned long long)rb, (unsigned long long)null_dopen);
        if (rb != null_dopen) {
            klog_printf("[STEP4] FAIL: readback mismatch on csw 0x%llx!\n", (unsigned long long)target_csw);
            return -1;
        }
    }

    /* Шаг 5: Проверка целевых каналов (приоритет: mp4/dump_for_decid СРАЗУ ПЕРВЫМ) */
    const char *test_paths[] = {
        "/dev/mp4/dump_for_decid",
        "/dev/mp4/dump",
        "/dev/deci_mp4_mmc",
        "/dev/deci_mp4_ioc",
        "/dev/deci_coredump"
    };

    for (int p = 0; p < (int)(sizeof(test_paths)/sizeof(test_paths[0])); p++) {
        const char *path = test_paths[p];
        errno = 0;
        int fd = open(path, 0x0002 /* O_RDWR */);
        int err = errno;
        klog_printf("[PROBE_NODE] '%s' -> fd=%d (errno=%d)\n", path, fd, err);
        if (fd < 0 && err == 1 /* EPERM */) {
            /* Попробуем O_RDONLY */
            errno = 0;
            fd = open(path, 0x0000 /* O_RDONLY */);
            err = errno;
            klog_printf("[PROBE_NODE] '%s' (RDONLY) -> fd=%d (errno=%d)\n", path, fd, err);
        }

        if (fd >= 0) {
            klog_printf("[PROBE_NODE] *** SUCCESS! Opened '%s' with fd=%d! ***\n", path, fd);
            /* Deci-устройства (deci_mp4_mmc, deci_mp4_ioc, deci_coredump) блокируют
             * ioctl/read, ждут хост-сторону через DECI connection — deep probe по
             * ним висит минутами. Запускаем deep probe ТОЛЬКО для mp4/dump_for_decid. */
            if (strstr(path, "mp4/dump_for_decid")) {
                klog_printf("[PROBE_NODE] deep probe on '%s'...\n", path);
                probe_opened_mp4_fd(fd, path);
            } else {
                klog_printf("[PROBE_NODE] skipping deep probe for deci-blocking device '%s'\n", path);
            }
            close(fd);
        }
    }

    return 0;
}

int
probe_mp4_device(uint64_t curproc_hint)
{
    /* test_mp4_open_with_root(); */
    scan_cdevsw();
    find_and_patch_mp4_cdevsw(curproc_hint);
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

    /* ------------------------------------------------------------------------- */
    /* KDUMP: Сохраняем дамп памяти ядра в /data/kdump.bin через KEKCALL 25     */
    /* ВАЖНО: выполняется ДО probe_mp4_device, потому что deep probe mp4-cdev   */
    /* может висеть минутами на ioctl/write и до KDUMP управление не вернётся.  */
    /* ------------------------------------------------------------------------- */
    klog_printf("[KDUMP] Starting kernel memory dump to /data/kdump.bin via KEKCALL 25...\n");
    uint64_t kbase = (uint64_t)kekcall(KEKCALL_GET_KBASE, 0, 0, 0);
    klog_printf("[KDUMP] kdata_base = 0x%llx\n", (unsigned long long)kbase);

    if (kbase > 0xffffffff00000000ULL) {
        int kdfd = open("/data/kdump.bin", O_WRONLY | O_CREAT | O_TRUNC, 0666);
        if (kdfd < 0) {
            klog_printf("[KDUMP] Failed to open /data/kdump.bin (errno=%d)\n", errno);
        } else {
            /* База ядра .text находится примерно на kbase - 0xD9D000 (или 0x1000000 назад) */
            uint64_t scan_start = (kbase > 0x2000000ULL) ? (kbase - 0x1400000ULL) : kbase;
            scan_start &= ~0xfffULL;
            uint64_t scan_size = 32ULL * 1024ULL * 1024ULL; /* 32 MB с запасом (.text + .rodata + .data) */

            klog_printf("[KDUMP] Dumping 0x%llx..0x%llx (size=%llu MB)...\n",
                        (unsigned long long)scan_start,
                        (unsigned long long)(scan_start + scan_size),
                        (unsigned long long)(scan_size / (1024 * 1024)));

            uint8_t chunk[4096];
            uint64_t bytes_written = 0;
            uint64_t pages_zero = 0;
            uint64_t iter = 0;
            const uint64_t total_iters = scan_size / sizeof(chunk);
            const uint64_t PROGRESS_EVERY = 128;

            for (uint64_t cur = scan_start; cur < scan_start + scan_size; cur += sizeof(chunk)) {
                memset(chunk, 0, sizeof(chunk));
                /* DUMP_MEM вместо SAFE_PEEK: умеет большие страницы .text, падает мягко
                 * (возвращает нули для unmapped qword'ов, а не крашит ядро). */
                (void)kekcall(KEKCALL_DUMP_MEM, cur, (uint64_t)chunk, sizeof(chunk));
                /* Эмпирика: если весь чанк пустой — скорее всего unmapped */
                int all_zero = 1;
                for (int z = 0; z < 64; z++) {
                    if (((uint64_t*)chunk)[z] != 0) { all_zero = 0; break; }
                }
                if (all_zero) pages_zero++;

                ssize_t w = write(kdfd, chunk, sizeof(chunk));
                if (w > 0) bytes_written += w;

                usleep(100);

                iter++;
                if ((iter % PROGRESS_EVERY) == 0 || iter == total_iters) {
                    klog_printf("[KDUMP] progress %llu/%llu (%llu KB, zero_chunks=%llu, at 0x%llx)\n",
                                (unsigned long long)iter,
                                (unsigned long long)total_iters,
                                (unsigned long long)(bytes_written / 1024),
                                (unsigned long long)pages_zero,
                                (unsigned long long)(cur + sizeof(chunk)));
                }
            }
            close(kdfd);
            klog_printf("[KDUMP] Dump complete! Wrote %llu bytes to /data/kdump.bin (zero_chunks=%llu/%llu)\n",
                        (unsigned long long)bytes_written,
                        (unsigned long long)pages_zero,
                        (unsigned long long)total_iters);
        }
    }

    /* Device probe (runs xref_scan_text). Запускается ПОСЛЕ KDUMP, т.к. deep
     * probe может висеть минутами на ioctl/write mp4-cdev и прерывать все
     * последующие шаги. */
    uint64_t curproc_hint = (rc > 38) ? ext_buf[38] : 0;
    if (probe_mp4_device(curproc_hint) != 0) {
        klog_puts("[a53] MP4 device not accessible — abort\n");
        return -2;
    }

    klog_puts("[a53] skeleton stage complete; mailbox TX/RX not yet implemented\n");
    return 0;
}

