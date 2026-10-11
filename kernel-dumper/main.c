/* PS5 kernel dumper for retail 13.60 — SAFE version
 * Uses SDK-provided KERNEL_ADDRESS_TEXT_BASE / DATA_BASE or dynamically
 * discovers the kernel ELF header (\x7fELF) starting from known-mapped kernel space.
 * Prevents kernel page faults in unmapped guard pages. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>
#include <ps5/payload.h>

#define DATA_FWD    0x200000   /* 2 MB after data_base — covers allproc/idt */
#define CHUNK       0x10000    /* 64 KB chunk */

#define LOGF(...) do { klog_printf(__VA_ARGS__); printf(__VA_ARGS__); } while(0)

static int dump_range(intptr_t start, size_t size, uint8_t *buf) {
    size_t got = 0;
    for (size_t off = 0; off < size; off += CHUNK) {
        size_t len = CHUNK;
        if (off + len > size) len = size - off;
        if (kernel_copyout(start + off, buf + off, len) < 0) {
            LOGF("[kdump] copyout returned error @ 0x%lx\n", start + off);
            return -1;
        }
        got += len;
        if ((off & 0xFFFFF) == 0)
            LOGF("[kdump] progress: 0x%lx / 0x%lx\n", off, (long)size);
    }
    LOGF("[kdump] got %zu bytes clean\n", got);
    return 0;
}

int main(void) {
    payload_args_t *args = payload_get_args();
    if (!args) {
        LOGF("[kdump] FATAL: no payload args\n");
        return 1;
    }

    intptr_t text_base = KERNEL_ADDRESS_TEXT_BASE;
    intptr_t data_base = KERNEL_ADDRESS_DATA_BASE;

    if (!text_base || !data_base) {
        intptr_t kdata = args->kdata_base_addr;
        if (!kdata) { LOGF("[kdump] FATAL: no kdata_base\n"); return 1; }
        data_base = kdata;

        /* Safely locate the kernel ELF header (\x7fELF) near cpu_switch (-0xA6DEA0) */
        uint32_t magic = 0;
        text_base = 0;
        for (intptr_t p = (kdata - 0xA00000) & ~0xFFFFF; p >= kdata - 0xB00000; p -= 0x100000) {
            if (kernel_copyout(p, &magic, 4) == 0 && magic == 0x464c457f) {
                text_base = p;
                LOGF("[kdump] Found ELF header at 0x%lx (-0x%lx from kdata)\n", text_base, kdata - text_base);
                break;
            }
        }
        if (!text_base) {
            /* Fallback to safe bound right before cpu_switch (-0xA6DEA0) */
            text_base = (kdata - 0xA70000) & ~0xFFF;
            LOGF("[kdump] ELF header not found on 1MB boundary, using safe bound 0x%lx\n", text_base);
        }
    }

    size_t text_size = data_base - text_base;
    size_t total = text_size + DATA_FWD;

    LOGF("[kdump] text_base = 0x%lx\n", text_base);
    LOGF("[kdump] data_base = 0x%lx\n", data_base);
    LOGF("[kdump] text size = 0x%lx (%.2f MB)\n", text_size, text_size / (double)(1024*1024));
    LOGF("[kdump] total dump = %zu bytes\n", total);

    uint8_t *buf = calloc(1, total);
    if (!buf) { LOGF("[kdump] calloc failed\n"); return 2; }

    LOGF("[kdump] === dumping .text/.rodata ===\n");
    if (dump_range(text_base, text_size, buf) < 0) {
        LOGF("[kdump] text dump failed\n");
        free(buf);
        return 3;
    }

    LOGF("[kdump] === dumping .data (2 MB) ===\n");
    if (dump_range(data_base, DATA_FWD, buf + text_size) < 0) {
        LOGF("[kdump] data dump partial\n");
    }

    LOGF("[kdump] writing /data/kernel-13.60-dump.bin\n");
    FILE *f = fopen("/data/kernel-13.60-dump.bin", "wb");
    if (!f) { LOGF("[kdump] fopen failed: %s\n", strerror(errno)); free(buf); return 4; }
    fwrite(buf, 1, total, f);
    fclose(f);

    f = fopen("/data/kernel-13.60-dump.meta", "w");
    if (f) {
        fprintf(f, "kdata_base=0x%lx\n", data_base);
        fprintf(f, "dump_start=0x%lx\n", text_base);
        fprintf(f, "dump_size=0x%zx\n", total);
        fclose(f);
    }

    free(buf);
    LOGF("[kdump] DONE. Pull /data/kernel-13.60-dump.bin via FTP\n");
    return 0;
}
