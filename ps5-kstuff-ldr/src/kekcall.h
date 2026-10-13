#pragma once
#include <sys/types.h>
#include <sys/syscall.h>

#define KEKCALL_A53_DUMP       8
#define KEKCALL_ELEVATE_CREDS   9
#define KEKCALL_RESTORE_CREDS   10
#define KEKCALL_EXT_DUMP       11
#define KEKCALL_MAX_CAPS       12
#define KEKCALL_RESTORE_CAPS   13
#define KEKCALL_SWAP_UCRED_PID    14
#define KEKCALL_RESTORE_UCRED_PTR 15
#define KEKCALL_SWAP_FULL         16
#define KEKCALL_RESTORE_FULL      17
#define KEKCALL_SCAN_DMEM         18
#define KEKCALL_DUMP_MEM          19
#define KEKCALL_SCAN_XREF         20
#define KEKCALL_SCAN_PTR          21
#define KEKCALL_SCAN_XREF_V2      22
#define KEKCALL_SCAN_PTR_CUSTOM   23
#define KEKCALL_GET_KBASE         24
#define KEKCALL_SAFE_PEEK         25
#define KEKCALL_SCAN_CDEVSW       26
#define KEKCALL_WRITE64           27
#define KEKCALL_DUMP_PHYS         28
#define KEKCALL_ENUM_ALLPROC      29
#define KEKCALL_SWAP_BY_UCRED     30
#define KEKCALL_SCAN_TD_UCRED     31
#define KEKCALL_DIFF_TEST         32
#define KEKCALL_MUTATE_INPLACE    34
#define KEKCALL_RESTORE_INPLACE   35
#define KEKCALL_GET_FD_INFO       36
#define KEKCALL_DIFF_FP           37
#define KEKCALL_INJECT_CDEVPRIV   38
#define KEKCALL_WRITE_TEST        39

static inline __attribute__((noinline)) long
kekcall(uint32_t nr, uint64_t a1, uint64_t a2, uint64_t a3)
{
    register uint64_t rax asm("rax") = ((uint64_t)nr << 32) | SYS_getppid;
    register uint64_t rdi asm("rdi") = a1;
    register uint64_t rsi asm("rsi") = a2;
    register uint64_t rdx asm("rdx") = a3;
    asm volatile("syscall"
                 : "+r"(rax), "+r"(rdi), "+r"(rsi), "+r"(rdx)
                 :
                 : "rcx", "r8", "r9", "r10", "r11", "memory");
    return (long)rax;
}

static inline __attribute__((noinline)) long
kekcall5(uint32_t nr, uint64_t a1, uint64_t a2, uint64_t a3, uint64_t a4)
{
    register uint64_t rax asm("rax") = ((uint64_t)nr << 32) | SYS_getppid;
    register uint64_t rdi asm("rdi") = a1;
    register uint64_t rsi asm("rsi") = a2;
    register uint64_t rdx asm("rdx") = a3;
    register uint64_t r8  asm("r8")  = a4;
    asm volatile("syscall"
                 : "+r"(rax), "+r"(rdi), "+r"(rsi), "+r"(rdx), "+r"(r8)
                 :
                 : "rcx", "r9", "r10", "r11", "memory");
    return (long)rax;
}

