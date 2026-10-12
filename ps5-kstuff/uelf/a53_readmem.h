/*
 * a53_readmem.h — PPR A53 patch via READMEM mailbox
 *
 * Port of drakmor's READMEM A53 patch infrastructure (from test6 binary).
 * Extended with 13.60 profile support.
 *
 * Interface used by fpkg.c / main.c to install the A53 patch after plaintext
 * PPR interception is armed but before mount is attempted on the first FPKG.
 *
 * install_ppr_a53() reads kernel firmware version, selects matching A53
 * profile from the table, opens READMEM mailbox to the A53 (secure processor),
 * writes patch instructions to the A53's .text, verifies by readback, then
 * commits. On failure it aborts cleanly without modifying A53 state when
 * readback does not match the stock bytes (safety-check from drakmor's design).
 */

#pragma once
#include <sys/types.h>

/* Firmware → profile_idx table entry. 12 bytes. */
struct fw_profile_entry {
    uint32_t fw_id;         /* e.g. 0x11600000 for 11.60 */
    uint32_t cond;          /* 1=devkit, 2=testkit, 3=retail */
    uint16_t profile_idx;   /* index into a53_profiles[] */
    uint16_t pad;
};

/* Static data (defined in a53_readmem_data.c) */
extern const struct fw_profile_entry a53_fw_table[];
extern const unsigned a53_fw_table_count;
extern const unsigned char a53_profiles[57][400];
extern const unsigned a53_profiles_count;

/* Lookup functions */
const unsigned char *a53_find_profile(uint32_t fw, uint32_t cond);

/* Main entry — call once after kstuff init to apply A53 patch.
 * Returns 0 on success, nonzero on failure (safe, no A53 mutation). */
int install_ppr_a53(void);

/* Diagnostic — may be called separately to just read A53 firmware id and
 * log it, without mutating anything. Useful first step on 13.60 to compare
 * the A53 fw against what the 11.60 profile expects. */
int diagnose_a53_firmware(void);
