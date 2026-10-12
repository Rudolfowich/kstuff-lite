#pragma once
#include <sys/types.h>
#include <sys/syscall.h>

#define KEKCALL_A53_DUMP       8
#define KEKCALL_ELEVATE_CREDS   9
#define KEKCALL_RESTORE_CREDS   10

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
