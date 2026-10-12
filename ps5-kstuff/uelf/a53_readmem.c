/*
 * a53_readmem.c — PPR A53 patch via READMEM mailbox (skeleton)
 *
 * STATUS: WIP — profile data is complete, mailbox/transport is stub.
 *
 * This is the FIRST compile-sanity version. Antigravity: this file should
 * compile cleanly as part of uelf/. It defines the symbols that main.c /
 * fpkg.c can start calling (via `install_ppr_a53()`), but the actual
 * mailbox work is a TODO stubbed out so the binary builds.
 *
 * Follow-ups:
 *   1. Fill in a53_mailbox_init() — reverse-engineered from test6 sub_4ad0
 *   2. Fill in readmem_write_cmd() / readmem_read_cmd() — mailbox protocol
 *   3. Fill in a53_read_fw_identity() — from test6 sub_52e0
 *   4. Fill in install_hooks_internal() / install_hooks_public()
 *   5. Fill in a53_patch_apply_profile() — the actual patching loop
 *
 * As each stage lands, we test on real PS5 to iterate.
 */

#include <sys/types.h>
#include <string.h>
#include "a53_readmem.h"
#include "log.h"
#include "utils.h"

/* Diagnostic markers — exactly 16 hex digits (uint64), 0-9 A-F only */
#define MK_INSTALL_BEGIN       0xA53BE00000000000ULL
#define MK_INSTALL_FW          0xA53FFFF000000000ULL
#define MK_PROFILE_FOUND       0xA53F00DA53F00DA5ULL
#define MK_PROFILE_MISSING     0xA53FA11ED53FA11EULL
#define MK_MBOX_INIT_FAIL      0xA53BAD00A53BAD00ULL
#define MK_FW_IDENT_READ       0xA531DEA531DEA531ULL
#define MK_HOOKS_INSTALLED     0xA53000DA53000DAFULL
#define MK_INSTALL_DONE_OK     0xA53F1E55F1E55F1EULL
#define MK_DIAG_BEGIN          0xA53D1A6D1A6D1A60ULL
#define MK_DIAG_FAIL_MBOX      0xA53D1A6FA11EDBADULL
#define MK_DIAG_FAIL_READ      0xA53D1A6FA11DEADFULL

/*
 * Profile lookup by (fw, cond). Returns pointer to the matching profile
 * blob (400 bytes), or NULL if no match.
 *
 * Mirrors test6 sub_9d20.
 */
const unsigned char *
a53_find_profile(uint32_t fw, uint32_t cond)
{
    const unsigned char *fallback = NULL;
    for (unsigned i = 0; i < a53_fw_table_count; i++) {
        const struct fw_profile_entry *e = &a53_fw_table[i];
        if (e->fw_id != fw)
            continue;
        if (e->cond == cond)
            return a53_profiles[e->profile_idx];
        /* Save first-match-regardless-of-cond as fallback */
        if (!fallback)
            fallback = a53_profiles[e->profile_idx];
    }
    return fallback;
}

/* --------------------------------------------------------------------- */
/* STUB: mailbox init — TODO reverse-engineer sub_4ad0 from test6 */
static int
a53_mailbox_init(void *ctx)
{
    (void)ctx;
    log_word(MK_MBOX_INIT_FAIL);
    return -1;  /* always fail for now so install_ppr_a53() aborts safely */
}

/* --------------------------------------------------------------------- */
/* STUB: read A53 firmware identity — TODO sub_52e0 from test6 */
static int
a53_read_fw_identity(void *buf, size_t size)
{
    (void)buf;
    (void)size;
    log_word(MK_FW_IDENT_READ);
    return -1;
}

/* --------------------------------------------------------------------- */
/* STUB: hooks installation — TODO install_hooks_internal/public from test6 */
static int
install_hooks_profile(const unsigned char *profile)
{
    (void)profile;
    log_word(MK_HOOKS_INSTALLED);
    return -1;
}

/* --------------------------------------------------------------------- */
/* Diagnose A53 without mutating anything.
 * Useful first run on 13.60 to collect info before attempting patch. */
int
diagnose_a53_firmware(void)
{
    unsigned char ident_buf[0xA0];
    memset(ident_buf, 0, sizeof(ident_buf));

    log_word(MK_DIAG_BEGIN);

    if (a53_mailbox_init(NULL) != 0) {
        log_word(MK_DIAG_FAIL_MBOX);
        return -1;
    }

    if (a53_read_fw_identity(ident_buf, sizeof(ident_buf)) != 0) {
        log_word(MK_DIAG_FAIL_READ);
        return -2;
    }

    /* Log first 4 u64's of identity */
    for (int i = 0; i < 4; i++) {
        uint64_t v;
        memcpy(&v, ident_buf + i*8, 8);
        log_word(v);
    }

    return 0;
}

/* --------------------------------------------------------------------- */
/* Main entry point — called from main.c after kstuff init.
 * Mirrors test6 sub_8e40 but trimmed to the plaintext PPR flow we need. */
int
install_ppr_a53(void)
{
    extern char fwver[];
    uint32_t raw_fw = (uint32_t)(uintptr_t)fwver;  /* FWVER from utils.h */
    uint32_t fw = raw_fw & 0xFFFF0000;

    log_word(MK_INSTALL_BEGIN);
    log_word(MK_INSTALL_FW | (uint64_t)fw);

    /* Select profile for current firmware (retail cond=3) */
    const unsigned char *profile = a53_find_profile(fw, 3);
    if (!profile) {
        /* Try cond=1 (devkit) as fallback */
        profile = a53_find_profile(fw, 1);
    }
    if (!profile) {
        log_word(MK_PROFILE_MISSING);
        return -1;
    }
    log_word(MK_PROFILE_FOUND);
    log_word((uint64_t)(uintptr_t)profile);

    /* TODO: full install sequence
     *   1. a53_mailbox_init()  — currently stub, returns -1 → safe exit
     *   2. a53_read_fw_identity() — verify A53 firmware matches profile
     *   3. install_hooks_profile() — apply the actual A53 patch
     */
    if (a53_mailbox_init(NULL) != 0) {
        return -2;  /* safe: no mutation attempted */
    }

    unsigned char ident[0xA0] = {0};
    if (a53_read_fw_identity(ident, sizeof(ident)) != 0) {
        return -3;  /* safe */
    }

    if (install_hooks_profile(profile) != 0) {
        return -4;  /* safe: drakmor's design does readback before commit */
    }

    log_word(MK_INSTALL_DONE_OK);
    return 0;
}
