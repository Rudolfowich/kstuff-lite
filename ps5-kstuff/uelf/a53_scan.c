/*
 * A53 bypass scanner v2 adapted for kstuff uelf environment
 */
#include <sys/types.h>
#include <stddef.h>
#include "log.h"

#define NAME_PPFS_GET_XTS_INDEX        0x6C1F41UL  /* known anchor */
#define NAME_L2P_READ_DECRYPT_ICV_OUT  0x5C05E4UL  /* target 1 */
#define NAME_PPFS_WAIT_A53IO_RESULT    0x69AF9FUL  /* target 2 */

/* SAFE scan range — strictly inside walalache's used .text pages */
#define SCAN_START_OFF  0xA80000UL   /* kdata_base - this */
#define SCAN_END_OFF    0x0B0000UL   /* kdata_base - this */

/* Walk-back limit when locating function prologue */
#define PROLOGUE_BACK   0x400UL

static void a53_scan_one(uint64_t kdata_base, uint64_t target_abs, uint64_t tag_magic)
{
    uint64_t start = kdata_base - SCAN_START_OFF;
    uint64_t end   = kdata_base - SCAN_END_OFF;
    const uint8_t *text = (const uint8_t *)start;
    size_t size = (size_t)(end - start);
    int hits = 0;

    for (size_t i = 0; i + 7 < size; i++) {
        /* REX.W (0x48) or REX.WR (0x4C) prefix + LEA opcode (0x8D) */
        uint8_t rex = text[i];
        if (rex != 0x48 && rex != 0x4C)
            continue;
        if (text[i + 1] != 0x8D)
            continue;

        /* RIP-relative: mod=00, rm=101  → (modrm & 0xC7) == 0x05 */
        uint8_t modrm = text[i + 2];
        if ((modrm & 0xC7) != 0x05)
            continue;

        /* disp32, signed */
        int32_t disp = (int32_t)(
            ((uint32_t)text[i + 3])       |
            ((uint32_t)text[i + 4] <<  8) |
            ((uint32_t)text[i + 5] << 16) |
            ((uint32_t)text[i + 6] << 24)
        );

        uint64_t rip_after = start + i + 7;
        uint64_t target    = rip_after + (uint64_t)(int64_t)disp;

        if (target != target_abs)
            continue;

        hits++;
        int64_t lea_off_from_kdata = (int64_t)(start + i) - (int64_t)kdata_base;
        log_word(0x4135333343414E31ull); /* "A53CAN1" */
        log_word(tag_magic);
        log_word((uint64_t)(start + i));
        log_word((uint64_t)(-lea_off_from_kdata));

        /* Walk back to function prologue: push rbp; mov rbp, rsp
           bytes:                           55       48 89 e5           */
        size_t low = (i > PROLOGUE_BACK) ? (i - PROLOGUE_BACK) : 0;
        for (size_t b = i; b > low; b--) {
            if (text[b] == 0x55 &&
                text[b + 1] == 0x48 &&
                text[b + 2] == 0x89 &&
                text[b + 3] == 0xE5) {
                int64_t fn_off_from_kdata = (int64_t)(start + b) - (int64_t)kdata_base;
                log_word(0x4135333346554E53ull); /* "A53FUNS" */
                log_word(tag_magic);
                log_word((uint64_t)(start + b));
                log_word((uint64_t)(-fn_off_from_kdata));
                break;
            }
        }

        if (hits >= 10)
            return;
    }
}

void scan_a53_targets(uint64_t kdata_base)
{
    log_word(0x4135335354415254ull); /* "A53START" */
    log_word(kdata_base);

    /* 1. Anchor: "ppfs_get_xts_index" */
    a53_scan_one(kdata_base,
                 kdata_base + NAME_PPFS_GET_XTS_INDEX,
                 0x414e43484f525f58ull); /* "ANCHOR_X" */

    /* 2. Target 1: "l2p_read_decrypt_icv_outer" */
    a53_scan_one(kdata_base,
                 kdata_base + NAME_L2P_READ_DECRYPT_ICV_OUT,
                 0x4c32505f52454144ull); /* "L2P_READ" */

    /* 3. Target 2: "ppfs_wait_a53io_result" */
    a53_scan_one(kdata_base,
                 kdata_base + NAME_PPFS_WAIT_A53IO_RESULT,
                 0x574149545f413533ull); /* "WAIT_A53" */

    log_word(0x413533444f4e4521ull); /* "A53DONE!" */
}
