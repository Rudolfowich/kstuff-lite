/*
 * a53_readmem_patch.c — call anchor to prevent gc-sections dropping
 *
 * The linker's --gc-sections removes `a53_profiles[]`, `a53_fw_table[]`,
 * `install_ppr_a53()` because nothing in fpkg.c / main.c references them yet.
 *
 * This TU creates a single `__attribute__((used, retain))` call anchor that
 * references all the public symbols so the linker keeps them. We DO NOT
 * actually run install_ppr_a53() yet — the anchor is called from a dead-code
 * path guarded by a constant-false runtime check that the optimizer cannot
 * fold out at link time (because it reads a volatile).
 *
 * Antigravity: add this file to uelf/ alongside a53_readmem.c, add to Makefile.
 * No other changes needed. Once we land a real call site in fpkg.c / main.c,
 * this file can be removed.
 */

#include <sys/types.h>
#include "a53_readmem.h"

static volatile uint64_t a53_readmem_anchor_cookie = 0;

__attribute__((used, noinline))
void a53_readmem_link_anchor(void)
{
    /* Reference all public symbols so they survive --gc-sections */
    if (a53_readmem_anchor_cookie != 0xDEADF00DBAADC0DEULL) {
        return;
    }
    /* These calls never execute (cookie never matches), but linker still
     * includes the referenced symbols. */
    (void)a53_fw_table[0].fw_id;
    (void)a53_fw_table_count;
    (void)a53_profiles[0][0];
    (void)a53_profiles_count;
    (void)a53_find_profile(0, 0);
    (void)install_ppr_a53();
    (void)diagnose_a53_firmware();
}
