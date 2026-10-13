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
        klog_printf("[LIVE_FP] === Resolving struct file* for live fd=%d ===\n", fd);
        int fd_ref = 1; /* stdout гарантированно открыт */
        uint64_t fd_info[40] = {0};
        kekcall(KEKCALL_GET_FD_INFO, (uint64_t)fd, (uint64_t)fd_ref, (uintptr_t)fd_info);
        uint64_t fp_live = fd_info[2];
        uint64_t fp_ref  = fd_info[3];

        /* Если fp_live на точном слоте пуст, берём найденный в fdt живой дескриптор */
        if (!fp_live || (fp_live >> 48) != 0xffff) {
            /* Проверяем слоты fdt: +0x58 (индекс 5+9), +0x50 (5+8), +0x48 (5+7) */
            if ((fd_info[5 + 9] >> 48) == 0xffff && (fd_info[5 + 9] >> 40) != 0xffffff) {
                fp_live = fd_info[5 + 9];
            } else {
                for (int s = 2; s < 16; s++) {
                    uint64_t cand = fd_info[5 + s];
                    if ((cand >> 48) == 0xffff && (cand >> 40) != 0xffffff && cand != fp_ref) {
                        fp_live = cand;
                        break;
                    }
                }
            }
        }

        klog_printf("[LIVE_FP] resolved: fp_live=0x%llx fp_ref=0x%llx\n",
                    (unsigned long long)fp_live, (unsigned long long)fp_ref);

        if (fp_live && (fp_live >> 48) == 0xffff) {
            uint64_t diff_table[32] = {0};
            uint32_t f_cdevpriv_off = (uint32_t)kekcall(KEKCALL_DIFF_FP, fp_live, fp_ref, (uintptr_t)diff_table);
            klog_printf("[LIVE_FP] detected candidate offset: +0x%x\n", f_cdevpriv_off);

            for (int i = 0; i < 16; i++) {
                if (diff_table[i] != 0) {
                    klog_printf("[LIVE_DIFF +0x%02x] xor=0x%016llx\n", i * 8, (unsigned long long)diff_table[i]);
                }
            }

            /* Инъекция cdev / softc в fp_live */
            uint32_t target_offs[] = { f_cdevpriv_off, 0x38, 0x40, 0x48, 0x50 };
            uint8_t test_cmd[8] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

            for (int t = 0; t < 5; t++) {
                uint32_t inj_off = target_offs[t];
                if (!inj_off) continue;

                /* Инжектируем cdev */
                uint64_t bk = (uint64_t)kekcall(KEKCALL_INJECT_CDEVPRIV, fp_live, (uint64_t)inj_off, g_cdev_mp4_dump_for_decid);
                klog_printf("[LIVE_INJECT +0x%x] injected cdev=0x%llx (old_val=0x%llx)\n",
                            inj_off, (unsigned long long)g_cdev_mp4_dump_for_decid, (unsigned long long)bk);

                errno = 0;
                ssize_t nw = write(fd, test_cmd, 8);
                int err = errno;
                klog_printf("[LIVE_TEST +0x%x] nw=%zd errno=%d\n", inj_off, nw, err);

                if (nw >= 0 || err != 19) {
                    klog_printf("[BREAKTHROUGH!] ENODEV 19 BYPASSED ON LIVE FD AT +0x%x! nw=%zd errno=%d\n",
                                inj_off, nw, err);
                } else {
                    /* Восстанавливаем старое значение */
                    kekcall(KEKCALL_INJECT_CDEVPRIV, fp_live, (uint64_t)inj_off, bk);
                }
            }
        }

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






    /* Шаг 4: патчим все найденные mp4 cdevsw */
    for (int m = 0; m < mp4_count; m++) {
        uint64_t target_csw = mp4_parent_csws[m];
        if (!target_csw) continue;
        uint64_t orig_dopen = 0;
        kekcall(KEKCALL_DUMP_MEM, target_csw + 0x10ULL, (uintptr_t)&orig_dopen, 8);
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
        int fd = open(path, 0x0002 /* O_RDWR */);
        int err = errno;
        klog_printf("[PROBE_NODE] '%s' -> fd=%d errno=%d\n", path, fd, err);
        if (fd < 0 && err == 1 /* EPERM */) {
            /* Попробуем O_RDONLY */
            fd = open(path, 0x0000 /* O_RDONLY */);
            err = errno;
            klog_printf("[PROBE_NODE] '%s' (RDONLY) -> fd=%d errno=%d\n", path, fd, err);
        }

        if (fd >= 0) {
            klog_printf("[PROBE_NODE] *** SUCCESS! Opened '%s' with fd=%d! Starting deep probe... ***\n", path, fd);
            probe_opened_mp4_fd(fd, path);
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
