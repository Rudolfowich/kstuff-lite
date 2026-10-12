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
        /* SWAP_FULL_FROM_PID: td_ucred + p_ucred + p_fd от target_pid.
         * args[RDI] = target_pid (uint32_t)
         * args[RSI] = user_buf  (32 байта backup: backup[0..2])
         * regs[RDI] = curthread */
        uint32_t target_pid = (uint32_t)args[RDI];
        uint64_t user_buf   = args[RSI];
        uint64_t td         = regs[RDI];
        uint64_t proc       = 0;
        kpeek64_checked(td + 0x08, &proc);

        extern char allproc[];
        uint64_t p = 0;
        kpeek64_checked((uint64_t)allproc, &p);

        uint64_t t_ucred = 0, t_fd = 0;
        unsigned safety = 0;
        while (p && safety++ < 500) {
            uint64_t pid_u64 = 0;
            /* p_pid at proc+0x2C0 (ext[128]=0xDF=223=our pid, verified) */
            kpeek64_checked(p + 0x2C0, &pid_u64);
            if ((uint32_t)(pid_u64 & 0xFFFFFFFF) == target_pid) {
                kpeek64_checked(p + 0x40, &t_ucred);
                kpeek64_checked(p + 0x48, &t_fd);
                break;
            }
            uint64_t next = 0;
            kpeek64_checked(p, &next);
            p = next;
        }
        if (!t_ucred || !t_fd) return 2;

        uint64_t backup[4] = {0};
        kpeek64_checked(td + 0x140,  &backup[0]);   /* old td_ucred */
        kpeek64_checked(proc + 0x40, &backup[1]);   /* old p_ucred */
        kpeek64_checked(proc + 0x48, &backup[2]);   /* old p_fd */
        backup[3] = 0;
        if (user_buf) {
            if (copy_to_kernel(user_buf, backup, sizeof(backup)))
                return EFAULT;
        }

        kpoke64(td + 0x140,  t_ucred);
        kpoke64(proc + 0x40, t_ucred);
        kpoke64(proc + 0x48, t_fd);   /* fixed: was 0x60 */
        args[RAX] = 0;
        return 0;
    }
    else if(nr == 17)
    {
        /* RESTORE_FULL: восстановить td_ucred + p_ucred + p_fd из user_buf.
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

        kpoke64(td + 0x140,  backup[0]);
        kpoke64(proc + 0x40, backup[1]);
        kpoke64(proc + 0x48, backup[2]);   /* p_fd */
        args[RAX] = 0;
        return 0;
    }
    else if(nr == 18)
    {
        /* SCAN_DMEM_FOR_STRING: ищем "/dev/mp4" в ядре.
         * args[RDI] = user_buf (uint64_t[32] для адресов находок)
         * args[RSI] = scan_mb (размер скана, в МБ; default 32)
         * return: число находок */
        uint64_t user_buf = args[RDI];
        uint64_t scan_mb = args[RSI];
        if (!user_buf) return 1;
        if (scan_mb == 0 || scan_mb > 256) scan_mb = 32;

        extern char kdata_base[];
        uint64_t kbase = (uint64_t)kdata_base;
        uint64_t scan_bytes = scan_mb * 1024ULL * 1024ULL;

        /* Pattern: "/dev/mp4" little-endian u64 */
        const uint64_t needle = 0x34706d2f7665642fULL;

        uint64_t finds[32] = {0};
        unsigned nfound = 0;

        #define CHUNK 128
        uint8_t buf[CHUNK];

        for (uint64_t off = 0; off + 8 < scan_bytes && nfound < 32; off += (CHUNK - 8)) {
            if (copy_from_kernel(buf, kbase + off, CHUNK) != 0) continue;
            for (unsigned i = 0; i + 8 <= CHUNK; i++) {
                uint64_t v;
                __builtin_memcpy(&v, buf + i, 8);
                if (v == needle) {
                    finds[nfound++] = kbase + off + i;
                    if (nfound >= 32) break;
                }
            }
        }

        if (copy_to_kernel(user_buf, finds, sizeof(finds)))
            return EFAULT;

        args[RAX] = nfound;
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
