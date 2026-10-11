/*
 * A53 scanner v3 — tight scan around known anchor, no printf, log_word only
 *
 * KEY DIFFERENCE FROM v2:
 *   - Scan range reduced from 10 MB to ~2 MB, centered on ppr_pfs_get_xts_index
 *     (which we KNOW works at kdata_base - 0x12C6E0).
 *   - All ppfs_* functions live in the same kernel module, so they are near
 *     this anchor. ±1 MB window captures them without hanging the handler.
 *   - No printf — only log_word() packed markers. printf format processing in
 *     a trap handler is what caused the hang in v2.
 *   - Progress markers every 64 KB so if it hangs we see where.
 *
 * SAFETY:
 *   Scan: [anchor - 0x100000, anchor + 0x100000] = ~2 MB total.
 *   anchor = kdata_base - 0x12C6E0 (ppr_pfs_get_xts_index)
 *   ~2M iterations × ~3 ns = ~6 ms CPU. Fits watchdog budget.
 *
 * CALL:
 *   Same place as v2 — try_handle_fpkg_trap() with static done flag.
 *
 * LOG MARKERS (all values are valid hex: 0-9 A-F):
 *   0xBABE000000000001 → followed by: scan start address
 *   0xBABE000000000002 → followed by: scan end address
 *   0xBABE000000000003 → followed by: anchor target abs address
 *   0xC0DEC0DE<offset> → progress at this byte offset
 *   0xAAAA00000000000N → anchor lea hit N, then lea_abs, then kdata-lea
 *   0xBBBB00000000000N → l2p_read_decrypt lea hit N, then lea_abs, kdata-lea
 *   0xCCCC00000000000N → wait_a53io lea hit N, then lea_abs, kdata-lea
 *   0xFACEAAAA0000000N → anchor FUNCTION_START N, then fn_abs, kdata-fn
 *   0xFACEBBBB0000000N → l2p FUNCTION_START N, then fn_abs, kdata-fn
 *   0xFACECCCC0000000N → wait FUNCTION_START N, then fn_abs, kdata-fn
 *   0xDEADDEADDEADDEAD → scan complete
 */

#include <sys/types.h>

extern void log_word(uint64_t w);

/* Known __func__ string offsets in .data (from strings scan of dump) */
#define NAME_PPFS_GET_XTS_INDEX        0x6C1F41UL
#define NAME_L2P_READ_DECRYPT_ICV_OUT  0x5C05E4UL
#define NAME_PPFS_WAIT_A53IO_RESULT    0x69AF9FUL

/* Tight scan window around the known-working anchor */
#define ANCHOR_FN_OFF_NEG   0x12C6E0UL
#define SCAN_HALF_WINDOW    0x100000UL   /* ±1 MB */

#define PROLOGUE_BACK       0x400UL

/* Log markers — all strictly hex-valid */
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

static int
scan_lea_matches(const uint8_t *text, size_t size,
                 uint64_t base_addr, uint64_t target_abs,
                 uint64_t kdata_base,
                 uint64_t hit_marker, uint64_t fn_marker)
{
    int hits = 0;

    for (size_t i = 0; i + 7 < size; i++) {
        /* Progress ping every 64 KB so hang location is visible */
        if ((i & 0xFFFF) == 0) {
            log_word(MK_PROG_BASE | (uint64_t)i);
        }

        uint8_t rex = text[i];
        if (rex != 0x48 && rex != 0x4C)
            continue;
        if (text[i + 1] != 0x8D)
            continue;

        uint8_t modrm = text[i + 2];
        if ((modrm & 0xC7) != 0x05)
            continue;

        int32_t disp = (int32_t)(
            ((uint32_t)text[i + 3])       |
            ((uint32_t)text[i + 4] <<  8) |
            ((uint32_t)text[i + 5] << 16) |
            ((uint32_t)text[i + 6] << 24)
        );

        uint64_t rip_after = base_addr + i + 7;
        uint64_t target    = rip_after + (uint64_t)(int64_t)disp;

        if (target != target_abs)
            continue;

        hits++;
        uint64_t lea_abs = base_addr + i;
        uint64_t neg_off = (uint64_t)(((int64_t)kdata_base) - ((int64_t)lea_abs));

        log_word(hit_marker | (uint64_t)hits);
        log_word(lea_abs);
        log_word(neg_off);

        /* Walk back for prologue: push rbp; mov rbp, rsp = 55 48 89 e5 */
        size_t low = (i > PROLOGUE_BACK) ? (i - PROLOGUE_BACK) : 0;
        for (size_t b = i; b > low; b--) {
            if (text[b] == 0x55 &&
                text[b + 1] == 0x48 &&
                text[b + 2] == 0x89 &&
                text[b + 3] == 0xE5) {
                uint64_t fn_abs = base_addr + b;
                uint64_t fn_neg = (uint64_t)(((int64_t)kdata_base) - ((int64_t)fn_abs));
                log_word(fn_marker | (uint64_t)hits);
                log_word(fn_abs);
                log_word(fn_neg);
                break;
            }
        }

        if (hits >= 5)
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
    const uint8_t *text = (const uint8_t *)start;
    size_t size = (size_t)(end - start);

    log_word(MK_BEG_START);
    log_word(start);
    log_word(MK_BEG_END);
    log_word(end);
    log_word(MK_BEG_TARGET);
    log_word(kdata_base + NAME_PPFS_GET_XTS_INDEX);

    /* 1. Known anchor */
    scan_lea_matches(text, size, start,
                     kdata_base + NAME_PPFS_GET_XTS_INDEX, kdata_base,
                     MK_HIT_ANCHOR, MK_FUN_ANCHOR);

    /* 2. l2p_read_decrypt_icv_outer */
    scan_lea_matches(text, size, start,
                     kdata_base + NAME_L2P_READ_DECRYPT_ICV_OUT, kdata_base,
                     MK_HIT_L2P, MK_FUN_L2P);

    /* 3. ppfs_wait_a53io_result */
    scan_lea_matches(text, size, start,
                     kdata_base + NAME_PPFS_WAIT_A53IO_RESULT, kdata_base,
                     MK_HIT_WAIT, MK_FUN_WAIT);

    log_word(MK_END);
}
