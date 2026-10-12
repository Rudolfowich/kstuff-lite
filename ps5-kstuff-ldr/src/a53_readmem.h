/*
 * a53_readmem.h — PPR A53 patch via /dev/mp4/dump (loader-side)
 *
 * Final location: ps5-kstuff-ldr/src/a53_readmem.h
 *
 * Port of drakmor's READMEM A53 patch infrastructure (from test6 binary).
 * Runs in userland loader (ps5-kstuff-ldr), uses standard FreeBSD POSIX
 * (open/read/write/ioctl/close) on `/dev/mp4/dump` to talk to the A53
 * secure processor via its character device.
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

/* Profile lookup */
const unsigned char *a53_find_profile(uint32_t fw, uint32_t cond);

/* Main entry — call from main.c after kstuff kernel init but before any
 * FPKG mount. Returns 0 on success, nonzero on failure (safe, no A53 mutation
 * on error paths because drakmor's design does readback before any commit).
 */
int install_ppr_a53(uint32_t system_fw_version);

/* Diagnostic — minimal check that /dev/mp4/dump exists and opens. Does NOT
 * send any A53 commands. Call this first on an unknown firmware to confirm
 * MP4 driver is present. */
int probe_mp4_device(void);
