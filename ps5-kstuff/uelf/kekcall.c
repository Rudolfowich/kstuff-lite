#include <errno.h>
#include <sys/sysent.h>
#include <sys/syscall.h>
#include <machine/sysarch.h>
#include <string.h>
#include "kekcall.h"
#include "traps.h"
#include "utils.h"
#include "log.h"
#include "fpkg.h"

extern char syscall_after[];
extern char doreti_iret[];
extern char nop_ret[];
extern char copyout[];
extern char copyin[];
extern char justreturn[];
extern struct sysent sysents[];

int handle_kekcall(uint64_t* regs, uint64_t* args, uint32_t nr)
{
    if(nr == 1)
    {
        uint64_t stack_frame[12] = {
            (uint64_t)doreti_iret,
            (uint64_t)nop_ret, regs[CS], regs[EFLAGS], regs[RSP], regs[SS],
        };
        int have_dbgregs;
        if(read_dbgregs_checked(stack_frame+6))
            return EFAULT;
        if(get_pcb_dbregs_checked(&have_dbgregs))
            return EFAULT;
        if(!have_dbgregs)
        {
            stack_frame[6] = stack_frame[7] = stack_frame[8] = stack_frame[9] = 0;
            stack_frame[10] &= -16;
        }
        if(push_stack_checked(regs, stack_frame, sizeof(stack_frame)))
            return EFAULT;
        if(copy_to_kernel(regs[RDI]+td_retval, &(const uint64_t){0}, sizeof(uint64_t)))
        {
            regs[RSP] += sizeof(stack_frame);
            return EFAULT;
        }
        regs[RDI] = regs[RSP] + 48;
        regs[RSI] = args[RDI];
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyout;
    }
    else if(nr == 2)
    {
        uint64_t stack_frame[14] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 1), [12] = regs[RDI]};
        if(push_stack_checked(regs, stack_frame, sizeof(stack_frame)))
            return EFAULT;
        regs[RDI] = args[RDI];
        regs[RSI] = regs[RSP] + 48;
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyin;
    }
    else if(nr == 3)
    {
        return rdmsr(args[RDI], &args[RAX]) ? 0 : EFAULT;
    }
    //nr 4 reserved for wrmsr
    else if(nr == 5) //remote syscall
    {
        uint64_t stack_frame[16] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 2)};
        stack_frame[6] = args[RDI];
        stack_frame[7] = args[RSI];
        stack_frame[14] = regs[RDI];
        if(push_stack_checked(regs, stack_frame, sizeof(stack_frame)))
            return EFAULT;
        regs[RDI] = args[RDX];
        regs[RSI] = regs[RSP] + 64;
        regs[RDX] = 48;
        regs[RIP] = (uint64_t)copyin;
    }
    else if(nr == 6)
    {
#if KSTUFF_OBS
        int err = copy_shared_area_snapshot(args[RDI], args[RSI]);
        if(!err)
        {
            args[RAX] = 0;
            METRIC_INC(shared_area_snapshots);
        }
        return err;
#else
        return ENOSYS;
#endif
    }
    else if(nr == 7)
    {
        uint64_t result = 0;
        int err = control_ppr_plaintext_request(args[RDI], args[RSI],
                                                args[RDX], 0,
                                                args[R8], args[R9],
                                                &result);
        if(!err)
            args[RAX] = result;
        return err;
    }
    else if(nr == 8)
    {
        /* A53 diagnostic: dump curthread + curproc raw bytes.
         * Заполняем буфер пользователя (args[RDI] - адрес, args[RSI] - макс. слов).
         * args[RDI] - указатель на массив uint64_t в userland.
         * args[RSI] - размер массива в словах (например 136).
         */
        uint64_t td = regs[RDI];
        uint64_t proc = 0;
        uint64_t ubuf = args[RDI];
        uint64_t ucap = args[RSI];

        if(!ubuf || ucap < 136)
            return EINVAL;

        uint64_t dump[136];
        size_t idx = 0;

        /* Маркер начала и curthread */
        dump[idx++] = 0xDEADBEEF00000008ULL;
        dump[idx++] = td;                       /* curthread VA */

        /* Dump 0x200 байт (64 слова) struct thread */
        dump[idx++] = 0x7468726561643030ULL;    /* "thread00" */
        for (uint64_t off = 0; off < 0x200; off += 8) {
            uint64_t val = 0;
            kpeek64_checked(td + off, &val);
            dump[idx++] = val;
        }

        /* Берём td_proc = td+8, логируем pid для sanity */
        kpeek64_checked(td + 8, &proc);
        dump[idx++] = 0x70726f635f707472ULL;    /* "proc_ptr" */
        dump[idx++] = proc;

        uint64_t pid = 0;
        kpeek64_checked(proc + 0xbc, &pid);
        dump[idx++] = 0x7069645f76616c75ULL;    /* "pid_valu" */
        dump[idx++] = pid & 0xFFFFFFFF;

        /* Dump 0x200 байт (64 слова) struct proc */
        dump[idx++] = 0x70726f6330303030ULL;    /* "proc0000" */
        for (uint64_t off = 0; off < 0x200; off += 8) {
            uint64_t val = 0;
            kpeek64_checked(proc + off, &val);
            dump[idx++] = val;
        }

        /* Маркер конца */
        dump[idx++] = 0xDEADBEEF00000080ULL;

        /* Копируем в память юзерленда */
        if(copy_to_kernel(ubuf, dump, idx * sizeof(uint64_t)))
            return EFAULT;

        args[RAX] = (uint64_t)idx;
        return 0;
    }
    else if(nr == 9)
    {
        /* ELEVATE_CREDS: подменяем td_ucred/p_ucred на ucred первого
         * процесса в allproc (обычно root). Backup кладём в user_buf. */
        uint64_t td = regs[RDI];
        uint64_t proc = 0;
        kpeek64_checked(td + 0x08, &proc);

        uint64_t old_td_ucred = 0, old_p_ucred = 0;
        kpeek64_checked(td + 0x140, &old_td_ucred);
        kpeek64_checked(proc + 0x40, &old_p_ucred);

        /* Resolve allproc и берём ucred первого процесса в списке */
        extern char allproc[];        /* extern из offset_list.txt */
        uint64_t first_proc = 0;
        kpeek64_checked((uint64_t)allproc, &first_proc);
        if (!first_proc) return 1;

        uint64_t root_ucred = 0;
        kpeek64_checked(first_proc + 0x40, &root_ucred);
        if (!root_ucred) return 2;

        /* copyout backup в user buffer */
        uint64_t user_buf = args[RSI];
        if (user_buf) {
            uint64_t backup[2] = { old_td_ucred, old_p_ucred };
            if (copy_to_kernel(user_buf, backup, sizeof(backup)))
                return EFAULT;
        }

        /* Swap pointers */
        kpoke64(td + 0x140, root_ucred);
        kpoke64(proc + 0x40, root_ucred);
        args[RAX] = 0;
        return 0;
    }
    else if(nr == 10)
    {
        /* RESTORE_CREDS: восстанавливаем из user_buf */
        uint64_t td = regs[RDI];
        uint64_t proc = 0;
        kpeek64_checked(td + 0x08, &proc);

        uint64_t user_buf = args[RSI];
        if (!user_buf) return 1;

        uint64_t backup[2] = {0, 0};
        if (copy_from_kernel(backup, user_buf, sizeof(backup)))
            return EFAULT;

        kpoke64(td + 0x140, backup[0]);
        kpoke64(proc + 0x40, backup[1]);
        args[RAX] = 0;
        return 0;
    }
    else if(nr == 11)
    {
        /* Расширенная разведка: dump ucred целиком + расширенный dump proc.
         * user_buf должен быть размером >= 0x600 байт (192 u64 слов) */
        uint64_t td = regs[RDI];
        uint64_t proc = 0;
        uint64_t ucred = 0;
        kpeek64_checked(td + 0x08, &proc);
        kpeek64_checked(td + 0x140, &ucred);

        uint64_t user_buf = args[RSI];
        if (!user_buf) return EINVAL;

        uint64_t tmp[192];
        unsigned idx = 0;

        /* Header: VAs */
        tmp[idx++] = 0xDEADBEEF00000011ULL;
        tmp[idx++] = td;
        tmp[idx++] = proc;
        tmp[idx++] = ucred;

        /* ucred dump — 0x100 bytes = 32 u64 */
        tmp[idx++] = 0x7563726564303030ULL;  /* "ucred000" */
        for (unsigned off = 0; off < 0x100; off += 8) {
            uint64_t v = 0;
            kpeek64_checked(ucred + off, &v);
            tmp[idx++] = v;
        }

        /* proc extended dump — 0x400 bytes = 128 u64 */
        tmp[idx++] = 0x70726f635f657874ULL;  /* "proc_ext" */
        for (unsigned off = 0; off < 0x400; off += 8) {
            uint64_t v = 0;
            kpeek64_checked(proc + off, &v);
            tmp[idx++] = v;
        }

        tmp[idx++] = 0xDEADBEEF00000011ULL;

        if (copy_to_kernel(user_buf, tmp, idx * sizeof(uint64_t)))
            return EFAULT;

        args[RAX] = (uint64_t)idx;
        return 0;
    }
    else if(nr == 12)
    {
        /* MAX_CAPS: забить sce_caps единицами, бэкап в user_buf (80 байт) */
        uint64_t td = regs[RDI];
        uint64_t ucred = 0;
        kpeek64_checked(td + 0x140, &ucred);

        uint64_t user_buf = args[RSI];
        if (!user_buf) return 1;

        uint64_t backup[10];
        for (int i = 0; i < 10; i++) {
            kpeek64_checked(ucred + 0x58 + i*8, &backup[i]);
        }
        if (copy_to_kernel(user_buf, backup, sizeof(backup)))
            return EFAULT;

        for (int i = 0; i < 10; i++) {
            kpoke64(ucred + 0x58 + i*8, 0xFFFFFFFFFFFFFFFFULL);
        }
        args[RAX] = 0;
        return 0;
    }
    else if(nr == 13)
    {
        /* RESTORE_CAPS: вернуть sce_caps из user_buf */
        uint64_t td = regs[RDI];
        uint64_t ucred = 0;
        kpeek64_checked(td + 0x140, &ucred);

        uint64_t user_buf = args[RSI];
        if (!user_buf) return 1;

        uint64_t backup[10];
        if (copy_from_kernel(backup, user_buf, sizeof(backup)))
            return EFAULT;

        for (int i = 0; i < 10; i++) {
            kpoke64(ucred + 0x58 + i*8, backup[i]);
        }
        args[RAX] = 0;
        return 0;
    }
    else if(nr == 14)
    {
        /* SWAP_UCRED_FROM_PID: подмена td_ucred на ucred процесса с target_pid.
         * args[RDI] = target_pid (uint32_t)
         * args[RSI] = user_buf (8 байт — бэкап старого td_ucred ptr)
         * regs[RDI] = curthread */
        uint32_t target_pid = (uint32_t)args[RDI];
        uint64_t user_buf   = args[RSI];
        uint64_t td         = regs[RDI];

        extern char allproc[];
        uint64_t p = 0;
        kpeek64_checked((uint64_t)allproc, &p);

        uint64_t target_ucred = 0;
        unsigned safety = 0;
        while (p && safety++ < 500) {
            uint64_t pid_u64 = 0;
            kpeek64_checked(p + 0x2C0, &pid_u64);
            /* p_pid at proc+0x2C0, int32 in low 32 bits */
            uint32_t pid = (uint32_t)(pid_u64 & 0xFFFFFFFF);
            if (pid == target_pid) {
                kpeek64_checked(p + 0x40, &target_ucred);
                break;
            }
            uint64_t next = 0;
            kpeek64_checked(p, &next);
            p = next;
        }
        if (!target_ucred) return 2;  /* pid не найден или ucred == NULL */

        uint64_t old_ucred = 0;
        kpeek64_checked(td + 0x140, &old_ucred);
        if (user_buf) {
            if (copy_to_kernel(user_buf, &old_ucred, sizeof(old_ucred)))
                return EFAULT;
        }

        kpoke64(td + 0x140, target_ucred);
        args[RAX] = 0;
        return 0;
    }
    else if(nr == 15)
    {
        /* RESTORE_UCRED_PTR: вернуть td_ucred из user_buf (8 байт).
         * args[RSI] = user_buf
         * regs[RDI] = curthread */
        uint64_t td       = regs[RDI];
        uint64_t user_buf = args[RSI];
        if (!user_buf) return 1;

        uint64_t old_ucred = 0;
        if (copy_from_kernel(&old_ucred, user_buf, sizeof(old_ucred)))
            return EFAULT;

        kpoke64(td + 0x140, old_ucred);
        args[RAX] = 0;
        return 0;
    }
    else if(nr == 16)
    {
        /* SWAP_FULL_FROM_PID: td_ucred + p_ucred от target_pid (или first_proc если target_pid == 0/1).
         * args[RDI] = target_pid (uint32_t)
         * args[RSI] = user_buf  (32 байта backup: backup[0..1])
         * regs[RDI] = curthread */
        uint32_t target_pid = (uint32_t)args[RDI];
        uint64_t user_buf   = args[RSI];
        uint64_t td         = regs[RDI];
        uint64_t proc       = 0;
        kpeek64_checked(td + 0x08, &proc);

        extern char allproc[];
        uint64_t p = 0;
        kpeek64_checked((uint64_t)allproc, &p);

        uint64_t t_ucred = 0;
        unsigned safety = 0;
        while (p && safety++ < 500) {
            uint64_t pid_u64_bc = 0;
            uint64_t pid_u64_2c0 = 0;
            kpeek64_checked(p + 0xbc, &pid_u64_bc);
            kpeek64_checked(p + 0x2c0, &pid_u64_2c0);
            uint32_t pid_bc = (uint32_t)(pid_u64_bc & 0xFFFFFFFF);
            uint32_t pid_2c0 = (uint32_t)(pid_u64_2c0 & 0xFFFFFFFF);

            if (pid_bc == target_pid || pid_2c0 == target_pid) {
                kpeek64_checked(p + 0x40, &t_ucred);
                if (t_ucred) break;
            }
            uint64_t next = 0;
            kpeek64_checked(p, &next);
            p = next;
        }

        /* Fallback: если по PID не нашли, берём ucred первого процесса в allproc */
        if (!t_ucred) {
            uint64_t first_p = 0;
            kpeek64_checked((uint64_t)allproc, &first_p);
            if (first_p) {
                kpeek64_checked(first_p + 0x40, &t_ucred);
            }
        }

        if (!t_ucred) return 2;

        uint64_t backup[4] = {0};
        kpeek64_checked(td + 0x140,  &backup[0]);   /* old td_ucred */
        kpeek64_checked(proc + 0x40, &backup[1]);   /* old p_ucred */
        backup[2] = 0;
        backup[3] = 0;
        if (user_buf) {
            if (copy_to_kernel(user_buf, backup, sizeof(backup)))
                return EFAULT;
        }

        kpoke64(td + 0x140,  t_ucred);
        kpoke64(proc + 0x40, t_ucred);
        args[RAX] = 0;
        return 0;
    }
    else if(nr == 17)
    {
        /* RESTORE_FULL: восстановить td_ucred + p_ucred из user_buf.
         * args[RSI] = user_buf (32 байта)
         * regs[RDI] = curthread */
        uint64_t td       = regs[RDI];
        uint64_t proc     = 0;
        kpeek64_checked(td + 0x08, &proc);
        uint64_t user_buf = args[RSI];
        if (!user_buf) return 1;

        uint64_t backup[4] = {0};
        if (copy_from_kernel(backup, user_buf, sizeof(backup)))
            return EFAULT;

        /* КРИТИЧЕСКАЯ ЗАЩИТА: НИКОГДА не писать 0/NULL в ucred! */
        if (!backup[0] || !backup[1]) {
            return EINVAL;
        }

        kpoke64(td + 0x140,  backup[0]);
        kpoke64(proc + 0x40, backup[1]);
        args[RAX] = 0;
        return 0;
    }
    else if(nr == 18)
    {
        /* SCAN_DMEM_FOR_STRING: ищем "mp4/dump" в ядре.
         * args[RDI] = scan_mb (размер скана, в МБ; default 32)
         * args[RSI] = user_buf (uint64_t[32] для адресов находок)
         * args[RDX] = start_abs (абсолютный адрес; 0 = kdata_base)
         * return: число находок */
        uint64_t user_buf = args[RSI];
        uint64_t scan_mb = args[RDI];
        uint64_t start_abs = args[RDX];  /* абсолютный адрес; 0 = kdata_base */
        if (!user_buf) return 1;
        if (scan_mb == 0 || scan_mb > 256) scan_mb = 32;

        extern char kdata_base[];
        uint64_t kbase = (start_abs > 0xfffffc0000000000ULL) ? start_abs : ((uint64_t)kdata_base + start_abs);
        uint64_t scan_bytes = scan_mb * 1024ULL * 1024ULL;

        /* Pattern: custom needle from args[R8] or default "mp4/dump" */
        const uint64_t needle = args[R8] ? args[R8] : 0x706d75642f34706dULL;

        uint64_t finds[32] = {0};
        unsigned nfound = 0;
        unsigned total = 0;

        uint8_t buf[128];

        for (uint64_t off = 0; off + 8 < scan_bytes; off += 120) {
            if (copy_from_kernel(buf, kbase + off, 128) != 0) continue;
            for (unsigned i = 0; i + 8 <= 128; i++) {
                uint64_t v;
                __builtin_memcpy(&v, buf + i, 8);
                if (v == needle) {
                    total++;
                    if (nfound < 32) {
                        log_word(0xAA00000000000000ULL | (uint64_t)nfound);
                        log_word(kbase + off + i);
                        finds[nfound++] = kbase + off + i;
                    }
                }
            }
        }

        /* Проверенный путь из kekcall 8/11 — без copyout */
        if (copy_to_kernel(user_buf, finds, sizeof(finds)) != 0)
            return EFAULT;

        args[RAX] = total;
        return 0;
    }
    else if(nr == 19)
    {
        /* DUMP_KERNEL_MEMORY: dump u64s from target address.
         * args[RDI] = target address (uint64_t)
         * args[RSI] = user_buf (uint64_t*)
         * args[RDX] = nbytes (default 512, max 4096) */
        uint64_t target = args[RDI];
        uint64_t user_buf = args[RSI];
        uint64_t nbytes = args[RDX];
        if (!target || !user_buf) return 1;
        if (nbytes == 0 || nbytes > 4096) nbytes = 4096;
        unsigned count = (nbytes + 7) / 8;

        uint64_t base = target & ~7ULL;
        uint64_t test_v = 0;
        if (kpeek64_checked(base, &test_v) != 0) return EFAULT;

        for (unsigned i = 0; i < count; i++) {
            uint64_t word = 0;
            if (kpeek64_checked(base + i*8, &word) != 0) {
                word = 0;
            }
            if (copy_to_kernel(user_buf + i*8, &word, 8) != 0)
                return EFAULT;
        }

        args[RAX] = count * 8;
        return 0;
    }
    else if(nr == 20)
    {
        uint64_t target = args[RDI];
        uint64_t user_buf = args[RSI];
        int64_t scan_mb_signed = (int64_t)args[RDX];  /* <0 = назад, >0 = вперёд */
        if (!target || !user_buf) return 1;

        uint64_t scan_abs = (scan_mb_signed < 0) ? -scan_mb_signed : scan_mb_signed;
        if (scan_abs == 0 || scan_abs > 128) scan_abs = 10;
        uint64_t scan_bytes = scan_abs * 1024ULL * 1024ULL;

        /* Сканируем вокруг САМОЙ строки target в .text/.rodata ядра */
        uint64_t start = (scan_mb_signed < 0)
                         ? (target - scan_bytes)
                         : target;

        uint64_t finds[32] = {0};
        unsigned nfound = 0;
        unsigned total = 0;
        uint8_t buf[128];

        for (uint64_t off = 0; off + 4 < scan_bytes; off += 120) {
            if (copy_from_kernel(buf, start + off, 128) != 0) continue;
            for (unsigned i = 0; i + 4 <= 128; i++) {
                int32_t disp;
                __builtin_memcpy(&disp, buf + i, 4);
                uint64_t rip_after = start + off + i + 4;
                if ((rip_after + (int64_t)disp) == target) {
                    total++;
                    if (nfound < 32) {
                        log_word(0xBB00000000000000ULL | (uint64_t)nfound);
                        log_word(start + off + i);
                        finds[nfound++] = start + off + i;
                    }
                }
            }
        }

        if (copy_to_kernel(user_buf, finds, sizeof(finds)) != 0)
            return EFAULT;
        args[RAX] = total;
        return 0;
    }
    else if(nr == 21)
    {
        /* SCAN_PTR_IN_DATA: scan .data from kdata_base forward for 8-byte pointer value.
         * args[RDI] = user_buf (uint64_t[32])
         * args[RSI] = needle (8-byte pointer value)
         * args[RDX] = scan_mb (default 8) */
        uint64_t user_buf = args[RDI];
        uint64_t needle = args[RSI];
        uint64_t scan_mb = args[RDX];
        if (!user_buf || !needle) return 1;
        if (scan_mb == 0 || scan_mb > 128) scan_mb = 8;

        extern char kdata_base[];
        uint64_t kbase = (uint64_t)kdata_base;
        uint64_t scan_bytes = scan_mb * 1024ULL * 1024ULL;

        uint64_t finds[32] = {0};
        unsigned nfound = 0, total = 0;
        uint8_t buf[128];

        for (uint64_t off = 0; off + 8 < scan_bytes; off += 120) {
            if (copy_from_kernel(buf, kbase + off, 128) != 0) continue;
            for (unsigned i = 0; i + 8 <= 128; i++) {
                uint64_t v;
                __builtin_memcpy(&v, buf + i, 8);
                if (v == needle) {
                    total++;
                    if (nfound < 32) finds[nfound++] = kbase + off + i;
                }
            }
        }

        if (copy_to_kernel(user_buf, finds, sizeof(finds)) != 0)
            return EFAULT;
        args[RAX] = total;
        return 0;
    }
    else if(nr == 22)
    {
        /* SCAN_XREF_V2: xref scan with explicit start_abs and safe chunk_bytes
         * args[RDI] = target
         * args[RSI] = user_buf
         * args[RDX] = start_abs
         * args[R8]  = chunk_bytes (default 64KB, max 256KB) */
        uint64_t target = args[RDI];
        uint64_t user_buf = args[RSI];
        uint64_t start_abs = args[RDX];
        uint64_t chunk_bytes = args[R8] ? args[R8] : (64ULL * 1024ULL);
        if (!target || !user_buf || !start_abs) return 1;
        if (chunk_bytes > 256ULL * 1024ULL) chunk_bytes = 64ULL * 1024ULL;

        /* Предварительная проверка доступности страницы */
        uint64_t test_val = 0;
        if (kpeek64_checked(start_abs, &test_val) != 0) {
            args[RAX] = 0;
            return 0;
        }

        uint64_t scan_bytes = chunk_bytes;
        uint64_t finds[32] = {0};
        unsigned nfound = 0, total = 0;
        uint8_t buf[128];

        for (uint64_t off = 0; off + 4 < scan_bytes; off += 120) {
            if (copy_from_kernel(buf, start_abs + off, 128) != 0) continue;
            for (unsigned i = 0; i + 4 <= 128; i++) {
                int32_t disp;
                __builtin_memcpy(&disp, buf + i, 4);
                uint64_t rip_after = start_abs + off + i + 4;
                if ((rip_after + (int64_t)disp) == target) {
                    total++;
                    if (nfound < 32) finds[nfound++] = start_abs + off + i;
                }
            }
        }

        if (copy_to_kernel(user_buf, finds, sizeof(finds)) != 0)
            return EFAULT;
        args[RAX] = total;
        return 0;
    }
    else if(nr == 23)
    {
        /* SCAN_PTR_CUSTOM: scan memory for 8-byte pointer value.
         * args[RDI] = user_buf (uint64_t[32])
         * args[RSI] = needle (8-byte pointer value)
         * args[RDX] = scan_mb (default 8)
         * args[R8]  = start_or_offset (if > 0xfffffc0000000000ULL: absolute, else: kdata_base + (int64_t)offset) */
        uint64_t user_buf = args[RDI];
        uint64_t needle = args[RSI];
        uint64_t scan_mb = args[RDX];
        uint64_t start_param = args[R8];
        if (!user_buf || !needle) return 1;
        if (scan_mb == 0 || scan_mb > 128) scan_mb = 8;

        extern char kdata_base[];
        uint64_t kbase;
        if (start_param > 0xfffffc0000000000ULL) {
            kbase = start_param;
        } else {
            kbase = (uint64_t)kdata_base + (int64_t)start_param;
        }
        uint64_t scan_bytes = scan_mb * 1024ULL * 1024ULL;

        uint64_t finds[32] = {0};
        unsigned nfound = 0, total = 0;
        uint8_t buf[128];

        for (uint64_t off = 0; off + 8 < scan_bytes; off += 120) {
            if (copy_from_kernel(buf, kbase + off, 128) != 0) continue;
            for (unsigned i = 0; i + 8 <= 128; i++) {
                uint64_t v;
                __builtin_memcpy(&v, buf + i, 8);
                if (v == needle) {
                    total++;
                    if (nfound < 32) finds[nfound++] = kbase + off + i;
                }
            }
        }

        if (copy_to_kernel(user_buf, finds, sizeof(finds)) != 0)
            return EFAULT;
        args[RAX] = total;
        return 0;
    }
    else if(nr == 24)
    {
        /* GET_KBASE: return kdata_base address to caller */
        extern char kdata_base[];
        args[RAX] = (uint64_t)kdata_base;
        return 0;
    }
    else if(nr == 25)
    {
        /* SAFE_PEEK: probe and read kernel memory via page table walk (virt2phys + DMEM).
         * args[RDI] = kaddr (kernel virtual address)
         * args[RSI] = user_dst (destination buffer in userland)
         * args[RDX] = len (length in bytes, default/max 4096)
         * return: 0 on success, EFAULT if any page is unmapped
         */
        uint64_t src = args[RDI];
        uint64_t dst = args[RSI];
        uint64_t len = args[RDX];
        if (!src || !dst) return EINVAL;
        if (len == 0) len = 8;
        if (len > 4096) len = 4096;

        /* Critical: check page mapping for every 4KB page in the range before touching */
        for (uint64_t p = (src & ~0xfffULL); p < src + len; p += 0x1000) {
            uint64_t phys = 0, limit = 0;
            if (!virt2phys(p, &phys, &limit)) {
                return EFAULT; /* Unmapped page — do NOT touch */
            }
        }

        /* All pages are verified mapped: copy directly into user buffer */
        if (copy_from_kernel_raw((void*)dst, src, len) != 0) {
            return EFAULT;
        }

        args[RAX] = 0;
        return 0;
    }
    else if(nr == 26)
    {
        /* SCAN_CDEVSW: scan kernel .data for struct cdevsw with D_VERSION
         * args[RDI] = filter_name (e.g. 0x0034706d = 'mp4', or 0 for any)
         * args[RSI] = do_patch (1 = patch d_open with justreturn immediately, 0 = read-only)
         * args[RDX] = user_out_dopen (optional pointer in userland - ignored, returns in RAX)
         * return in RAX: address of matched cdevsw (or 0 if not found) */
        uint64_t filter = args[RDI];
        uint64_t do_patch = args[RSI];

        extern char kdata_base[];
        uint64_t data_start = (uint64_t)kdata_base;
        uint64_t scan_bytes = 16ULL * 1024ULL * 1024ULL; /* 16 MB .data */

        const uint32_t D_VER_FREEBSD9 = 0x17122009;
        const uint32_t D_VER_FREEBSD5 = 0x20011966;

        uint64_t matched_cdevsw = 0;
        uint64_t orig_d_open = 0;
        uint8_t page[4096];

        for (uint64_t off = 0; off < scan_bytes && !matched_cdevsw; off += 4096) {
            uint64_t cur_page = data_start + off;
            if (copy_from_kernel(page, cur_page, 4096) != 0)
                continue;

            for (unsigned i = 0; i + 32 <= 4096; i += 8) {
                uint32_t ver = 0;
                __builtin_memcpy(&ver, page + i, 4);
                if (ver != D_VER_FREEBSD9 && ver != D_VER_FREEBSD5)
                    continue;

                uint64_t cdevsw_addr = cur_page + i;
                uint64_t d_name_ptr = 0;
                __builtin_memcpy(&d_name_ptr, page + i + 8, 8);
                if (!d_name_ptr || (d_name_ptr & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
                    continue;

                char name[32] = {0};
                if (copy_from_kernel(name, d_name_ptr, 32) != 0)
                    continue;
                name[31] = 0;
                if (name[0] < 32 || name[0] > 126)
                    continue;

                /* Если задан фильтр (например 'm','p','4') */
                if (filter != 0) {
                    const char* fstr = (const char*)&filter;
                    int match = 1;
                    for (int fi = 0; fi < 8 && fstr[fi]; fi++) {
                        if (name[fi] != fstr[fi]) {
                            match = 0;
                            break;
                        }
                    }
                    if (!match) continue;
                }

                __builtin_memcpy(&orig_d_open, page + i + 0x10, 8);
                matched_cdevsw = cdevsw_addr;

                if (do_patch) {
                    /* Патчим d_open (+0x10) на justreturn */
                    kpoke64(cdevsw_addr + 0x10, (uint64_t)justreturn);
                }

                break;
            }
        }

        args[RAX] = matched_cdevsw;
        return 0;
    }
    else if(nr == 27)
    {
        /* WRITE64: atomic write 64-bit value to kernel memory with safety checks
         * args[RDI] = target kernel address
         * args[RSI] = value to write
         * return: 0 on success, EFAULT if address invalid */
        uint64_t target = args[RDI];
        uint64_t val = args[RSI];
        if (!target || (target & 0xFFFF000000000000ULL) != 0xFFFF000000000000ULL)
            return EFAULT;

        uint64_t test_v = 0;
        if (kpeek64_checked(target, &test_v) != 0)
            return EFAULT;

        kpoke64(target, val);
        args[RAX] = 0;
        return 0;
    }
    else if(nr == 28)
    {
        /* DUMP_PHYS: read raw physical memory via DMEM mapping (bypasses XOM).
         * args[RDI] = physical address (uint64_t)
         * args[RSI] = userland buffer (uint64_t)
         * args[RDX] = nbytes (max 4096) */
        uint64_t phys = args[RDI];
        uint64_t user_buf = args[RSI];
        uint64_t nbytes = args[RDX];
        if (!user_buf) return 1;
        if (nbytes == 0 || nbytes > 4096) nbytes = 4096;

        /* Читаем напрямую из физического маппинга DMEM */
        if (copy_to_kernel(user_buf, DMEM + phys, nbytes) != 0)
            return EFAULT;

        args[RAX] = nbytes;
        return 0;
    }
    else if(nr == 29)
    {
        /* ENUM_ALLPROC: walk allproc in kernel space safely and return array of:
         * struct { uint32_t pid; char comm[24]; uint64_t ucred; uint64_t authid; } (48 bytes each)
         * args[RDI] = user_buf
         * args[RSI] = max_entries */
        uint64_t user_buf = args[RDI];
        uint32_t max_entries = (uint32_t)args[RSI];
        if (!user_buf || max_entries == 0) return EINVAL;
        if (max_entries > 256) max_entries = 256;

        extern char allproc[];
        uint64_t p = 0;
        kpeek64_checked((uint64_t)allproc, &p);

        uint32_t count = 0;
        unsigned safety = 0;
        while (p && count < max_entries && safety++ < 600) {
            uint64_t pid_u64_bc = 0, pid_u64_b0 = 0;
            kpeek64_checked(p + 0xBC, &pid_u64_bc);
            kpeek64_checked(p + 0xB0, &pid_u64_b0);
            uint32_t pid = (uint32_t)(pid_u64_bc & 0xFFFFFFFF);
            if (!pid) pid = (uint32_t)(pid_u64_b0 & 0xFFFFFFFF);

            char comm[24] = {0};
            /* Ищем p_comm перебором вероятных смещений FreeBSD/Prospero (0x440..0x460) */
            const uint64_t comm_offsets[] = { 0x450, 0x454, 0x458, 0x44C, 0x448, 0x440, 0x460 };
            for (int co = 0; co < 7; co++) {
                char test_comm[24] = {0};
                copy_from_kernel(test_comm, p + comm_offsets[co], 20);
                test_comm[20] = 0;
                /* Проверяем, что первый символ — печатный ASCII */
                if ((unsigned char)test_comm[0] >= 32 && (unsigned char)test_comm[0] <= 126) {
                    memcpy(comm, test_comm, 20);
                    break;
                }
            }

            uint64_t ucred = 0;
            kpeek64_checked(p + 0x40, &ucred);
            if (!ucred) kpeek64_checked(p + 0x48, &ucred);

            uint64_t authid = 0;
            if (ucred) kpeek64_checked(ucred + 0x58, &authid);

            /* Pack struct: pid(4), comm(24), ucred(8), authid(8) = 44 bytes -> 48 bytes with pad */
            uint8_t entry[48] = {0};
            memcpy(entry + 0, &pid, 4);
            memcpy(entry + 4, comm, 24);
            memcpy(entry + 28, &ucred, 8);
            memcpy(entry + 36, &authid, 8);

            if (copy_to_kernel(user_buf + (uint64_t)count * 48, entry, 48) != 0)
                break;

            count++;

            uint64_t next = 0;
            kpeek64_checked(p, &next);
            if (!next) kpeek64_checked(p + 0x10, &next);
            p = next;
        }

        args[RAX] = count;
        return 0;
    }
    else if(nr == 30)
    {
        /* SWAP_BY_UCRED: подмена td_ucred + p_ucred напрямую по указателю target_ucred.
         * args[RDI] = target_ucred (uint64_t)
         * args[RSI] = user_buf (32 байта backup: old_td_ucred, old_p_ucred, new_td, new_p)
         * regs[RDI] = curthread */
        uint64_t target_ucred = args[RDI];
        uint64_t user_buf     = args[RSI];
        uint64_t td           = regs[RDI];
        uint64_t proc         = 0;
        kpeek64_checked(td + 0x08, &proc);

        if (!target_ucred) return EINVAL;

        uint32_t td_ucred_off = 0x140;  /* default */
        uint32_t p_ucred_off  = 0x40;   /* default */

        /* Ищем корректный td_ucred offset: первый kernel ptr в диапазоне 0x120..0x180
         * у которого по +0x58 лежит ненулевой authid (структура ucred) */
        for (uint32_t toff = 0x120; toff <= 0x180; toff += 8) {
            uint64_t v = 0;
            if (kpeek64_checked(td + toff, &v)) continue;
            if ((v >> 48) != 0xffff) continue;
            uint64_t authid_check = 0;
            if (kpeek64_checked(v + 0x58, &authid_check)) continue;
            if (authid_check != 0) {
                td_ucred_off = toff;
                break;
            }
        }

        /* Ищем корректный p_ucred offset в proc 0x30..0x70 */
        if (proc) {
            for (uint32_t poff = 0x30; poff <= 0x70; poff += 8) {
                uint64_t v = 0;
                if (kpeek64_checked(proc + poff, &v)) continue;
                if ((v >> 48) != 0xffff) continue;
                uint64_t authid_check = 0;
                if (kpeek64_checked(v + 0x58, &authid_check)) continue;
                if (authid_check != 0) {
                    p_ucred_off = poff;
                    break;
                }
            }
        }

        uint64_t backup[4] = {0};
        kpeek64_checked(td + td_ucred_off,  &backup[0]);   /* old td_ucred */
        if (proc) {
            kpeek64_checked(proc + p_ucred_off, &backup[1]);   /* old p_ucred */
        }

        kpoke64(td + td_ucred_off, target_ucred);
        if (proc) {
            kpoke64(proc + p_ucred_off, target_ucred);
        }

        kpeek64_checked(td + td_ucred_off, &backup[2]);   /* new td_ucred */
        if (proc) {
            kpeek64_checked(proc + p_ucred_off, &backup[3]);   /* new p_ucred */
        }

        if (user_buf) {
            if (copy_to_kernel(user_buf, backup, sizeof(backup)))
                return EFAULT;
        }

        args[RAX] = 0;
        return 0;
    }
    else if(nr == 31)
    {
        /* SCAN_TD_UCRED_OFFSET: эмпирически находит offset td_ucred в struct thread
         * и p_ucred в struct proc для текущей сессии.
         * args[RDI] = user_buf (размер 128 байт:
         *   [0] = td_ucred_off
         *   [1] = p_ucred_off
         *   [2] = td (curthread ptr)
         *   [3] = proc (curproc ptr)
         *   [4] = td_ucred_val
         *   [5] = p_ucred_val
         *   [6] = td_authid
         *   [7] = p_authid
         * )
         * regs[RDI] = curthread */
        uint64_t user_buf = args[RDI];
        uint64_t td       = regs[RDI];
        uint64_t proc     = 0;
        kpeek64_checked(td + 0x08, &proc);

        uint32_t td_ucred_off = 0;
        uint32_t p_ucred_off  = 0;
        uint64_t td_ucred_val = 0;
        uint64_t p_ucred_val  = 0;
        uint64_t td_authid    = 0;
        uint64_t p_authid     = 0;

        /* Сканируем td 0x110..0x190 */
        for (uint32_t toff = 0x110; toff <= 0x190; toff += 8) {
            uint64_t v = 0;
            if (kpeek64_checked(td + toff, &v)) continue;
            if ((v >> 48) != 0xffff) continue;
            uint64_t authid = 0;
            if (kpeek64_checked(v + 0x58, &authid)) continue;
            if (authid != 0 && td_ucred_off == 0) {
                td_ucred_off = toff;
                td_ucred_val = v;
                td_authid    = authid;
                break;
            }
        }

        /* Сканируем proc 0x20..0x80 */
        if (proc) {
            for (uint32_t poff = 0x20; poff <= 0x80; poff += 8) {
                uint64_t v = 0;
                if (kpeek64_checked(proc + poff, &v)) continue;
                if ((v >> 48) != 0xffff) continue;
                uint64_t authid = 0;
                if (kpeek64_checked(v + 0x58, &authid)) continue;
                if (authid != 0 && p_ucred_off == 0) {
                    p_ucred_off = poff;
                    p_ucred_val = v;
                    p_authid    = authid;
                    break;
                }
            }
        }

        if (user_buf) {
            uint64_t result[8] = {
                (uint64_t)td_ucred_off,
                (uint64_t)p_ucred_off,
                td,
                proc,
                td_ucred_val,
                p_ucred_val,
                td_authid,
                p_authid
            };
            if (copy_to_kernel(user_buf, result, sizeof(result)))
                return EFAULT;
        }

        args[RAX] = ((uint64_t)p_ucred_off << 32) | td_ucred_off;
        return 0;
    }
    else if(nr == 32)
    {
        /* KEKCALL_DIFF_AND_PRISON_TEST:
         * Выполняет diff между our_ucred и video_ucred (64 qwords),
         * складывает различия в user_buf, патчит cr_prison и p_flag.
         * args[RDI] = video_ucred
         * args[RSI] = user_buf (размер >= 1024 байта)
         * args[RDX] = flags (1 = patch prison, 2 = patch p_flag, 3 = both)
         * regs[RDI] = curthread */
        uint64_t video_ucred = args[RDI];
        uint64_t user_buf    = args[RSI];
        uint64_t flags       = args[RDX];
        uint64_t td          = regs[RDI];
        uint64_t proc        = 0;
        kpeek64_checked(td + 0x08, &proc);

        uint64_t our_ucred = 0;
        kpeek64_checked(td + 0x140, &our_ucred);

        if (!our_ucred || !video_ucred || !user_buf) return EINVAL;

        /* Буфер результатов:
         * [0] = diff_count
         * [1] = prison_offset
         * [2] = old_prison
         * [3] = new_prison
         * [4] = orig_pflag
         * [5] = new_pflag
         * [6..] = пары diff: offset, our_val, video_val (3 qwords на запись) */
        uint64_t out[128] = {0};
        uint32_t diff_cnt = 0;
        uint32_t prison_off = 0;
        uint64_t cand_prison = 0;

        for (uint32_t i = 0; i < 512 && diff_cnt < 32; i += 8) {
            uint64_t o = 0, v = 0;
            kpeek64_checked(our_ucred + i, &o);
            kpeek64_checked(video_ucred + i, &v);
            if (o != v) {
                out[6 + diff_cnt * 3 + 0] = (uint64_t)i;
                out[6 + diff_cnt * 3 + 1] = o;
                out[6 + diff_cnt * 3 + 2] = v;
                diff_cnt++;

                /* Ищем cr_prison: указатель ядра (0xffff...) в диапазоне +0x28..+0x50 */
                if (i >= 0x28 && i <= 0x50 && (v >> 48) == 0xffff && !cand_prison) {
                    cand_prison = v;
                    prison_off = i;
                }
            }
        }
        out[0] = (uint64_t)diff_cnt;
        out[1] = (uint64_t)prison_off;
        out[3] = cand_prison;

        /* Тест 2: Подмена cr_prison */
        if ((flags & 1) && prison_off && cand_prison) {
            uint64_t old_p = 0;
            kpeek64_checked(our_ucred + prison_off, &old_p);
            out[2] = old_p;
            kpoke64(our_ucred + prison_off, cand_prison);
        }

        /* Тест 3: Установка P_SYSTEM (0x200) в proc + 0xb4 */
        if ((flags & 2) && proc) {
            uint64_t cur_pflag = 0;
            kpeek64_checked(proc + 0xB0, &cur_pflag);
            out[4] = cur_pflag;
            uint64_t new_pflag = cur_pflag | 0x200ULL;
            kpoke64(proc + 0xB0, new_pflag);
            out[5] = new_pflag;
        }

        if (copy_to_kernel(user_buf, out, sizeof(out)))
            return EFAULT;

        args[RAX] = 0;
        return 0;
    }
    else if(nr == 33)
    {
        /* KEKCALL_RESTORE_DIFF_TEST:
         * Восстанавливает cr_prison и p_flag из сохранённых значений.
         * args[RDI] = prison_offset
         * args[RSI] = old_prison
         * args[RDX] = orig_pflag */
        uint32_t prison_off = (uint32_t)args[RDI];
        uint64_t old_prison = args[RSI];
        uint64_t orig_pflag = args[RDX];
        uint64_t td         = regs[RDI];
        uint64_t proc       = 0;
        kpeek64_checked(td + 0x08, &proc);

        uint64_t our_ucred = 0;
        kpeek64_checked(td + 0x140, &our_ucred);

        if (our_ucred && prison_off && old_prison) {
            kpoke64(our_ucred + prison_off, old_prison);
        }
        if (proc && orig_pflag) {
            kpoke64(proc + 0xB0, orig_pflag);
        }

        args[RAX] = 0;
        return 0;
    }
    else if(nr == 34)
    {
        /* KEKCALL_MUTATE_INPLACE:
         * In-place мутация our_ucred полями из video_ucred БЕЗ подмены указателя.
         * args[RDI] = video_ucred
         * args[RSI] = user_buf (бэкап старых значений our_ucred, 512 байт)
         * regs[RDI] = curthread */
        uint64_t video_ucred = args[RDI];
        uint64_t user_buf    = args[RSI];
        uint64_t td          = regs[RDI];

        uint64_t our_ucred = 0;
        kpeek64_checked(td + 0x140, &our_ucred);

        if (!our_ucred || !video_ucred) return EINVAL;

        /* 1. Бэкап первых 512 байт our_ucred в user_buf */
        if (user_buf) {
            uint64_t bkp[64] = {0};
            for (int i = 0; i < 64; i++) {
                kpeek64_checked(our_ucred + i * 8, &bkp[i]);
            }
            if (copy_to_kernel(user_buf, bkp, sizeof(bkp)))
                return EFAULT;
        }

        /* 2. Копируем все ключевые поля из video_ucred в our_ucred, НЕ трогая cr_ref (+0x00) */
        /* Поля идентичности: uid/ruid (+0x08), svuid (+0x10), rgid (+0x18) */
        uint64_t v = 0;
        kpeek64_checked(video_ucred + 0x08, &v); kpoke64(our_ucred + 0x08, v);
        kpeek64_checked(video_ucred + 0x10, &v); kpoke64(our_ucred + 0x10, v);
        kpeek64_checked(video_ucred + 0x18, &v); kpoke64(our_ucred + 0x18, v);

        /* authid (+0x58) */
        kpeek64_checked(video_ucred + 0x58, &v); kpoke64(our_ucred + 0x58, v);

        /* sce_caps (0x60..0x98) */
        for (uint32_t off = 0x60; off <= 0x98; off += 8) {
            kpeek64_checked(video_ucred + off, &v);
            kpoke64(our_ucred + off, v);
        }

        /* agroups (+0x120) */
        kpeek64_checked(video_ucred + 0x120, &v); kpoke64(our_ucred + 0x120, v);

        args[RAX] = 0;
        return 0;
    }
    else if(nr == 35)
    {
        /* KEKCALL_RESTORE_INPLACE:
         * Восстановление our_ucred из user_buf (512 байт).
         * args[RDI] = user_buf
         * regs[RDI] = curthread */
        uint64_t user_buf = args[RDI];
        uint64_t td       = regs[RDI];

        uint64_t our_ucred = 0;
        kpeek64_checked(td + 0x140, &our_ucred);

        if (!our_ucred || !user_buf) return EINVAL;

        uint64_t bkp[64] = {0};
        if (copy_from_kernel(bkp, user_buf, sizeof(bkp)))
            return EFAULT;

        /* Восстанавливаем поля с +0x08 по +0x1f8 (пропуская cr_ref на +0x00) */
        for (int i = 1; i < 64; i++) {
            kpoke64(our_ucred + i * 8, bkp[i]);
        }

        args[RAX] = 0;
        return 0;
    }
    else if(nr == 36)
    {
        /* KEKCALL 36: GET_FD_INFO (resolve указателей)
         * args[RDI] = fd_mp4
         * args[RSI] = fd_null
         * args[RDX] = user_buf (64 bytes: [0]=p_fd, [1]=fd_files, [2]=fp_mp4, [3]=fp_null, [4]=p_fd_off, ...)
         */
        int target_fd_mp4 = (int)args[RDI];
        int target_fd_null = (int)args[RSI];
        uint64_t user_buf  = args[RDX];
        uint64_t td        = regs[RDI];
        uint64_t proc      = 0;
        kpeek64_checked(td + 0x08, &proc);

        uint64_t found_p_fd = 0;
        uint64_t found_fd_files = 0;
        uint64_t found_fp_mp4 = 0;
        uint64_t found_fp_null = 0;
        uint32_t found_off = 0;

        if (proc) {
            /* Приоритет 1: точный оффсет proc + 0x60 (FreeBSD / PS5) */
            uint64_t cand_p_fd = 0;
            kpeek64_checked(proc + 0x60ULL, &cand_p_fd);
            if ((cand_p_fd >> 48) == 0xffff && (cand_p_fd >> 40) != 0xffffff) {
                uint64_t f_files = 0;
                kpeek64_checked(cand_p_fd + 0x08ULL, &f_files);
                if ((f_files >> 48) == 0xffff && (f_files >> 40) != 0xffffff) {
                    found_p_fd = cand_p_fd;
                    found_fd_files = f_files;
                    found_off = 0x60;
                }
            }

            /* Запасной вариант: если +0x60 пуст, ищем с +0x40 до +0x200 */
            if (!found_p_fd) {
                for (uint32_t off = 0x40; off < 0x200; off += 8) {
                    uint64_t v = 0;
                    if (kpeek64_checked(proc + off, &v) != 0) continue;
                    if ((v >> 48) != 0xffff || (v >> 40) == 0xffffff) continue;

                    uint64_t f_files = 0;
                    if (kpeek64_checked(v + 0x08ULL, &f_files) != 0) continue;
                    if ((f_files >> 48) != 0xffff || (f_files >> 40) == 0xffffff) continue;

                    found_p_fd = v;
                    found_fd_files = f_files;
                    found_off = off;
                    break;
                }
            }
        }

        if (found_fd_files) {
            /* Проверенная структура PS5 Prospero fdt:
             * header = 0x10, stride = 0x08 (плоский массив struct file*)
             */
            uint64_t cand_m = 0, cand_n = 0;
            kpeek64_checked(found_fd_files + 0x10ULL + (uint64_t)target_fd_mp4 * 8ULL, &cand_m);
            kpeek64_checked(found_fd_files + 0x10ULL + (uint64_t)target_fd_null * 8ULL, &cand_n);

            /* Если целевой слот пуст, ищем ближайший ненулевой указатель кучи в диапазоне fd +/- 2 */
            if ((cand_m >> 48) != 0xffff) {
                int deltas[] = { 1, -1, 2, -2 };
                for (int d = 0; d < 4; d++) {
                    int try_fd = target_fd_mp4 + deltas[d];
                    if (try_fd < 0 || try_fd > 32) continue;
                    uint64_t try_fp = 0;
                    kpeek64_checked(found_fd_files + 0x10ULL + (uint64_t)try_fd * 8ULL, &try_fp);
                    if ((try_fp >> 48) == 0xffff && (try_fp >> 40) != 0xffffff && try_fp != cand_n) {
                        cand_m = try_fp;
                        break;
                    }
                }
            }

            found_fp_mp4 = cand_m;
            found_fp_null = cand_n;
        }

        if (user_buf) {
            /* Возвращаем в userland:
             * [0] = p_fd
             * [1] = fd_files
             * [2] = fp_mp4
             * [3] = fp_null
             * [4] = p_fd_off
             * [5..36] = первые 32 qwords из fdt (256 байт) для полного анализа таблицы в юзерленде
             */
            uint64_t out[37] = {0};
            out[0] = found_p_fd;
            out[1] = found_fd_files;
            out[2] = found_fp_mp4;
            out[3] = found_fp_null;
            out[4] = (uint64_t)found_off;

            if (found_fd_files) {
                for (int i = 0; i < 32; i++) {
                    kpeek64_checked(found_fd_files + (uint64_t)i * 8, &out[5 + i]);
                }
            }

            copy_to_kernel(user_buf, out, sizeof(out));
        }

        args[RAX] = (found_fp_mp4 && found_fp_null && found_fp_mp4 != found_fp_null) ? 0 : 1;
        return 0;
    }
    else if(nr == 37)
    {
        /* KEKCALL 37: DIFF_FP (сравнение двух struct file)
         * args[RDI] = fp_mp4
         * args[RSI] = fp_null
         * args[RDX] = user_buf (out: 64 qwords diff pairs or raw dump)
         * return: detected offset of f_cdevpriv in RAX (where mp4 is 0 and null is heap ptr)
         */
        uint64_t fp_mp4  = args[RDI];
        uint64_t fp_null = args[RSI];
        uint64_t user_buf = args[RDX];
        uint32_t detected_cdevpriv_off = 0;

        /* КРИТИЧЕСКАЯ ЗАЩИТА: проверяем, что оба указателя — валидные адреса ядра в куче! */
        if ((fp_mp4 >> 48) != 0xffff || (fp_null >> 48) != 0xffff ||
            (fp_mp4 >> 40) == 0xffffff || (fp_null >> 40) == 0xffffff ||
            fp_mp4 < 0xffff800000000000ULL || fp_null < 0xffff800000000000ULL) {
            args[RAX] = 0;
            return 0;
        }

        uint64_t diff_out[32] = {0};

        for (int i = 0; i < 24; i++) {
            uint64_t vm = 0, vn = 0;
            if (kpeek64_checked(fp_mp4 + (uint64_t)i * 8, &vm) != 0) break;
            if (kpeek64_checked(fp_null + (uint64_t)i * 8, &vn) != 0) break;

            diff_out[i] = (vm ^ vn);
            if (vm == 0 && (vn >> 48) == 0xffff && (vn >> 40) != 0xffffff && !detected_cdevpriv_off) {
                detected_cdevpriv_off = (uint32_t)(i * 8);
            }
        }

        if (user_buf) {
            copy_to_kernel(user_buf, diff_out, sizeof(diff_out));
        }

        args[RAX] = (uint64_t)detected_cdevpriv_off;
        return 0;
    }
    else if(nr == 38)
    {
        /* KEKCALL 38: INJECT_CDEVPRIV (запись softc/cdevpriv в fp + offset)
         * args[RDI] = fp_mp4
         * args[RSI] = offset (e.g. detected_cdevpriv_off, or 0x38, 0x40, 0x48)
         * args[RDX] = value_to_write (e.g. dedicated_mp4_cdev или softc)
         * return: old value in RAX
         */
        uint64_t fp_mp4 = args[RDI];
        uint64_t offset = args[RSI];
        uint64_t new_val = args[RDX];
        uint64_t old_val = 0;

        /* КРИТИЧЕСКАЯ ЗАЩИТА: проверка адреса */
        if ((fp_mp4 >> 48) != 0xffff || fp_mp4 < 0xffff800000000000ULL || offset > 0x200) {
            args[RAX] = 0;
            return 0;
        }

        if (fp_mp4 && offset) {
            kpeek64_checked(fp_mp4 + offset, &old_val);
            kpoke64(fp_mp4 + offset, new_val);
        }

        args[RAX] = old_val;
        return 0;
    }
    else if(nr == 39)
    {
        /* KEKCALL 39: WRITE_TEST (чтение поля и проверка валидности fp)
         * args[RDI] = fp_mp4
         * args[RSI] = offset
         * return: текущее значение поля fp_mp4 + offset
         */
        uint64_t fp_mp4 = args[RDI];
        uint64_t offset = args[RSI];
        uint64_t cur_val = 0;

        if ((fp_mp4 >> 48) == 0xffff && fp_mp4 >= 0xffff800000000000ULL && offset <= 0x200) {
            kpeek64_checked(fp_mp4 + offset, &cur_val);
        }

        args[RAX] = cur_val;
        return 0;
    }
    else if(nr == 40)
    {
        /* WRITE_PHYS: write to physical memory via DMEM mapping (bypasses WP).
         * args[RDI] = kernel virtual address (KVA, we va2phys inside)
         *             OR direct physical address if top bit NOT set (phys < 1<<48)
         * args[RSI] = value (u64 or u32 depending on width)
         * args[RDX] = width (4 or 8), default 8
         * return 0 on success, EFAULT if VA unmapped, EINVAL if bad width
         */
        uint64_t addr = args[RDI];
        uint64_t val  = args[RSI];
        uint32_t width = (uint32_t)args[RDX];
        if (width == 0) width = 8;
        if (width != 4 && width != 8) return EINVAL;

        /* If addr is a kernel VA (top bits = 0xffff), translate via page walk.
         * Otherwise treat as physical address. */
        uint64_t phys = addr;
        if ((addr >> 48) == 0xffff) {
            uint64_t limit = 0;
            if (!virt2phys(addr, &phys, &limit))
                return EFAULT;
        }

        /* Write via DMEM aperture — bypasses WP bit. */
        if (width == 4) {
            *(volatile uint32_t*)(DMEM + phys) = (uint32_t)val;
        } else {
            *(volatile uint64_t*)(DMEM + phys) = val;
        }

        args[RAX] = 0;
        return 0;
    }
    else if(nr == 0xffffffff)
    {
        args[RAX] = 0;
        return 0;
    }
    return ENOSYS;
}

void handle_kekcall_trap(uint64_t* regs, uint32_t trap)
{
    if(trap == 1)
    {
        enum { FRAME_QWORDS = 14, TAIL_OFFSET_QWORDS = 5 };
        uint64_t tail[FRAME_QWORDS - TAIL_OFFSET_QWORDS];
        struct dbgregs_snapshot snapshot;
        if(pop_stack_tail_checked(regs, tail,
                                  FRAME_QWORDS * sizeof(uint64_t),
                                  TAIL_OFFSET_QWORDS * sizeof(uint64_t),
                                  sizeof(tail)))
            return;
        regs[RIP] = tail[8];
        if((uint32_t)regs[RAX])
            return;
        if(copy_to_kernel(tail[6]+td_retval, &(const uint64_t){0}, sizeof(uint64_t)))
        {
            regs[RAX] = EFAULT;
            return;
        }
        if(snapshot_current_dbgregs_checked(&snapshot))
        {
            regs[RAX] = EFAULT;
            return;
        }
        if(install_dbgregs_checked(tail, &snapshot))
        {
            regs[RAX] = EFAULT;
        }
    }
    else if(trap == 2)
    {
        enum { FRAME_QWORDS = 15, TAIL_OFFSET_QWORDS = 5 };
        uint64_t tail[9];
        if(pop_stack_tail_checked(regs, tail,
                                  FRAME_QWORDS * sizeof(uint64_t),
                                  TAIL_OFFSET_QWORDS * sizeof(uint64_t),
                                  sizeof(tail)))
            return;
        if((uint32_t)regs[RAX])
        {
            if(pop_stack_checked(regs, &regs[RIP], 8))
                return;
            return;
        }
        uint32_t pid = tail[0];
        uint32_t sysc_no = tail[1];
        uint64_t proc_u;
        if(kpeek64_checked(tail[8]+td_proc, &proc_u))
            goto fail_remote_syscall;
        int64_t proc = proc_u;
        while(proc < -0x100000000)
        {
            if(kpeek64_checked(proc+8, &proc_u))
                goto fail_remote_syscall;
            proc = proc_u;
        }
        while(proc)
        {
            uint64_t proc_pid;
            if(kpeek64_checked(proc+p_pid, &proc_pid))
                goto fail_remote_syscall;
            if((uint32_t)proc_pid == pid)
                break;
            if(kpeek64_checked(proc, &proc_u))
                goto fail_remote_syscall;
            proc = proc_u;
        }
        if(!proc)
        {
            regs[RAX] = ESRCH;
            if(pop_stack_checked(regs, &regs[RIP], 8))
                return;
            return;
        }
        if(kpeek64_checked(proc+16, &regs[RDI]))
            goto fail_remote_syscall;
        uint64_t stack_frame_2[14] = {(uint64_t)doreti_iret, MKTRAP(TRAP_KEKCALL, 3), [6] = tail[8], regs[RDI]};
        memcpy(stack_frame_2+8, tail+2, 48);
        uint64_t sysc_target = 0;
        if(sysc_no == SYS_sysarch && (uint32_t)tail[2] == AMD64_GET_FSBASE)
        {
            stack_frame_2[1] = MKTRAP(TRAP_KEKCALL, 4);

            uint64_t thread_pcb;
            if(kpeek64_checked(regs[RDI] + td_pcb, &thread_pcb))
                goto fail_remote_syscall;
            if(kpeek64_checked(get_pcb_field_ptr(thread_pcb, pcb_fsbase), &stack_frame_2[8]))
                goto fail_remote_syscall;
            if(copy_to_kernel(tail[8]+td_retval, &(const uint64_t){0}, sizeof(uint64_t)))
                goto fail_remote_syscall;
        }
        else
        {
            if(kpeek64_checked((uint64_t)&sysents[sysc_no].sy_call, &sysc_target))
                goto fail_remote_syscall;
            if(copy_to_kernel(regs[RDI]+td_retval, &(const uint64_t){0}, sizeof(uint64_t)))
                goto fail_remote_syscall;
        }
        if(push_stack_checked(regs, stack_frame_2, sizeof(stack_frame_2)))
            goto fail_remote_syscall;
        regs[RAX] = (uint64_t)&sysents[sysc_no];
        if(sysc_no == SYS_sysarch && (uint32_t)tail[2] == AMD64_GET_FSBASE)
        {
            regs[RIP] = (uint64_t)copyout;
            regs[RDI] = regs[RSP] + 64;
            regs[RSI] = tail[3];
            regs[RDX] = 8;
        }
        else
        {
            regs[RIP] = sysc_target;
            regs[RSI] = regs[RSP] + 64;
            handle_syscall(regs, 0);
        }
        return;
fail_remote_syscall:
        regs[RAX] = EFAULT;
        if(pop_stack_checked(regs, &regs[RIP], 8))
            return;
        return;
    }
    else if(trap == 3 || trap == 4)
    {
        enum { FRAME_QWORDS = 14, TAIL_OFFSET_QWORDS = 5 };
        uint64_t tail[FRAME_QWORDS - TAIL_OFFSET_QWORDS];
        if(pop_stack_tail_checked(regs, tail,
                                  FRAME_QWORDS * sizeof(uint64_t),
                                  TAIL_OFFSET_QWORDS * sizeof(uint64_t),
                                  sizeof(tail)))
            return;
        if(trap == 3 && !(uint32_t)regs[RAX])
        {
            uint64_t retval;
            if(kpeek64_checked(tail[1]+td_retval, &retval))
                regs[RAX] = EFAULT;
            else
                kpoke64(tail[0]+td_retval, retval);
        }
        regs[RIP] = tail[8];
    }
}
