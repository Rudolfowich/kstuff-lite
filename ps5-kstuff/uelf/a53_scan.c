/*
 * A53 scanner v3.1 — 100% safe page-checked scan via virt2phys
 */
#include <sys/types.h>
#include <stddef.h>
#include "log.h"
#include "utils.h"

/* Known __func__ string offsets in .data (from strings scan of dump) */
#define NAME_PPFS_GET_XTS_INDEX        0x6C1F41UL
#define NAME_L2P_READ_DECRYPT_ICV_OUT  0x5C05E4UL
#define NAME_PPFS_WAIT_A53IO_RESULT    0x69AF9FUL

/* Scan window around the known-working anchor */
#define ANCHOR_FN_OFF_NEG   0x12C6E0UL
#define SCAN_HALF_WINDOW    0x100000UL   /* ±1 MB */

#define PROLOGUE_BACK       0x400UL

/* Log markers */
#define MK_BEG_START        0xBABE000000000001ULL
#define MK_BEG_END          0xBABE000000000002ULL
#define MK_BEG_TARGET       0xBABE000000000003ULL
#define MK_PROG_BASE        0xC0DEC0DE00000000ULL
#define MK_HIT_ANCHOR       0xAAAA000000000000ULL
#define MK_HIT_L2P          0xBBBB000000000000ULL
#define MK_HIT_WAIT         0xCCCC000000000000ULL
#define MK_FUN_ANCHOR       0xFACEAAAA00000000ULL
#define MK_FUN_L2P          0xFACEBBBB00000000ULL
#define MK_FUN_WAIT         0xFACECCCC00000000ULL
#define MK_END              0xDEADDEADDEADDEADULL

/* Safely read 1 byte from kernel virtual address via virt2phys */
static inline int safe_read_u8(uint64_t vaddr, uint8_t* out)
{
    uint64_t phys = 0, limit = 0;
    if(!virt2phys(vaddr, &phys, &limit))
        return 0;
    *out = *(uint8_t*)(DMEM + phys);
    return 1;
}

static int
scan_lea_matches_safe(uint64_t start_vaddr, uint64_t end_vaddr,
                      uint64_t target_abs, uint64_t kdata_base,
                      uint64_t hit_marker, uint64_t fn_marker)
{
    int hits = 0;
    uint64_t cur_page = 0;
    uint64_t cur_phys_base = 0;
    uint64_t cur_limit = 0;
    int cur_page_valid = 0;

    for(uint64_t vaddr = start_vaddr; vaddr + 7 < end_vaddr; vaddr++)
    {
        /* Progress ping every 64 KB */
        if(((vaddr - start_vaddr) & 0xFFFF) == 0)
        {
            log_word(MK_PROG_BASE | ((vaddr - start_vaddr) & 0xFFFFFFFFUL));
        }

        /* Check if we crossed a page boundary (4KB) */
        uint64_t page_base = vaddr & ~0xFFFULL;
        if(page_base != cur_page)
        {
            cur_page = page_base;
            cur_page_valid = virt2phys(page_base, &cur_phys_base, &cur_limit);
        }

        if(!cur_page_valid)
        {
            /* Skip unmapped page entirely */
            vaddr = page_base + 0xFFF;
            continue;
        }

        /* Ensure all 7 instruction bytes fall into valid mapped pages */
        uint64_t offset_in_page = vaddr - page_base;
        const uint8_t* insn_ptr;
        uint8_t insn_buf[8];

        if(offset_in_page + 7 <= 0x1000)
        {
            insn_ptr = (const uint8_t*)(DMEM + cur_phys_base + offset_in_page);
        }
        else
        {
            /* Instruction crosses page boundary — check byte by byte */
            int ok = 1;
            for(int b = 0; b < 7; b++)
            {
                if(!safe_read_u8(vaddr + b, &insn_buf[b]))
                {
                    ok = 0;
                    break;
                }
            }
            if(!ok) continue;
            insn_ptr = insn_buf;
        }

        /* REX prefix: 0x48 or 0x4C */
        uint8_t rex = insn_ptr[0];
        if(rex != 0x48 && rex != 0x4C)
            continue;
        if(insn_ptr[1] != 0x8D)
            continue;

        /* modrm & 0xC7 == 0x05 */
        if((insn_ptr[2] & 0xC7) != 0x05)
            continue;

        int32_t disp = (int32_t)(
            ((uint32_t)insn_ptr[3])       |
            ((uint32_t)insn_ptr[4] <<  8) |
            ((uint32_t)insn_ptr[5] << 16) |
            ((uint32_t)insn_ptr[6] << 24)
        );

        uint64_t rip_after = vaddr + 7;
        uint64_t target    = rip_after + (uint64_t)(int64_t)disp;

        if(target != target_abs)
            continue;

        hits++;
        uint64_t neg_off = (uint64_t)(((int64_t)kdata_base) - ((int64_t)vaddr));

        log_word(hit_marker | (uint64_t)hits);
        log_word(vaddr);
        log_word(neg_off);

        /* Walk back for prologue: push rbp; mov rbp, rsp = 55 48 89 e5 */
        uint64_t back_limit = (vaddr > start_vaddr + PROLOGUE_BACK)
                            ? (vaddr - PROLOGUE_BACK) : start_vaddr;

        for(uint64_t b = vaddr; b > back_limit; b--)
        {
            uint8_t p[4];
            if(safe_read_u8(b, &p[0]) &&
               safe_read_u8(b + 1, &p[1]) &&
               safe_read_u8(b + 2, &p[2]) &&
               safe_read_u8(b + 3, &p[3]))
            {
                if(p[0] == 0x55 && p[1] == 0x48 && p[2] == 0x89 && p[3] == 0xE5)
                {
                    uint64_t fn_neg = (uint64_t)(((int64_t)kdata_base) - ((int64_t)b));
                    log_word(fn_marker | (uint64_t)hits);
                    log_word(b);
                    log_word(fn_neg);
                    break;
                }
            }
        }

        if(hits >= 5)
            return hits;
    }

    return hits;
}

void
scan_a53_targets_v3(uint64_t kdata_base)
{
    uint64_t anchor_abs = kdata_base - ANCHOR_FN_OFF_NEG;
    uint64_t start = anchor_abs - SCAN_HALF_WINDOW;
    uint64_t end   = anchor_abs + SCAN_HALF_WINDOW;

    log_word(MK_BEG_START);
    log_word(start);
    log_word(MK_BEG_END);
    log_word(end);
    log_word(MK_BEG_TARGET);
    log_word(kdata_base + NAME_PPFS_GET_XTS_INDEX);

    /* 1. Known anchor */
    scan_lea_matches_safe(start, end,
                          kdata_base + NAME_PPFS_GET_XTS_INDEX, kdata_base,
                          MK_HIT_ANCHOR, MK_FUN_ANCHOR);

    /* 2. l2p_read_decrypt_icv_outer */
    scan_lea_matches_safe(start, end,
                          kdata_base + NAME_L2P_READ_DECRYPT_ICV_OUT, kdata_base,
                          MK_HIT_L2P, MK_FUN_L2P);

    /* 3. ppfs_wait_a53io_result */
    scan_lea_matches_safe(start, end,
                          kdata_base + NAME_PPFS_WAIT_A53IO_RESULT, kdata_base,
                          MK_HIT_WAIT, MK_FUN_WAIT);

    log_word(MK_END);
}
