/*
 * a53_readmem.h — PPR A53 patch via READMEM mailbox (UELF-side port)
 *
 * Port of drakmor's READMEM A53 patch infrastructure (from test6 binary).
 * Reimplemented as UELF code using virt2phys + DMEM for MMIO access,
 * instead of test6's userland FreeBSD device-tree walk.
 *
 * All data symbols here are marked __attribute__((used)) so the linker's
 * --gc-sections does NOT drop them before the first install call lands
 * in main.c / fpkg.c.
 */

#pragma once
#include <sys/types.h>

#ifndef KSTUFF_USED
#define KSTUFF_USED __attribute__((used))
#endif

/* Firmware → profile_idx table entry. 12 bytes. */
struct fw_profile_entry {
    uint32_t fw_id;         /* e.g. 0x11600000 for 11.60 */
    uint32_t cond;          /* 1=devkit, 2=testkit, 3=retail */
    uint16_t profile_idx;   /* index into a53_profiles[] */
    uint16_t pad;
};

/* Static data (defined in a53_readmem_data.c) */
extern const struct fw_profile_entry a53_fw_table[] KSTUFF_USED;
extern const unsigned a53_fw_table_count KSTUFF_USED;
extern const unsigned char a53_profiles[57][400] KSTUFF_USED;
extern const unsigned a53_profiles_count KSTUFF_USED;

/* Lookup functions */
const unsigned char *a53_find_profile(uint32_t fw, uint32_t cond) KSTUFF_USED;

/* Main entry — call once after kstuff init to apply A53 patch.
 * Returns 0 on success, nonzero on failure (safe, no A53 mutation). */
int install_ppr_a53(void) KSTUFF_USED;

/* Diagnostic — may be called separately to just read A53 firmware id and
 * log it, without mutating anything. Useful first step on 13.60 to compare
 * the A53 fw against what the 11.60 profile expects. */
int diagnose_a53_firmware(void) KSTUFF_USED;
