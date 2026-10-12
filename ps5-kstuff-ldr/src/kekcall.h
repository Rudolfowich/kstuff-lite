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

static inline long
kekcall(uint32_t nr, uint64_t a1, uint64_t a2, uint64_t a3)
{
    register uint64_t rax asm("rax") = ((uint64_t)nr << 32) | SYS_getppid;
    register uint64_t rdi asm("rdi") = a1;
    register uint64_t rsi asm("rsi") = a2;
    register uint64_t rdx asm("rdx") = a3;
    asm volatile("syscall"
                 : "+r"(rax)
                 : "r"(rdi), "r"(rsi), "r"(rdx)
                 : "rcx", "r11", "memory");
    return (long)rax;
}
