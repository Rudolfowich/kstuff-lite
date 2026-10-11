/* PS5 kernel dumper for retail 13.60
 * Dumps a window around kdata_base covering .text, .rodata, start of .data. */

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <ps5/kernel.h>
#include <ps5/klog.h>
#include <ps5/payload.h>

#define TEXT_BACK   0xC00000   /* 12 MB перед kdata_base — покрывает все offsets 13_60.h */
#define DATA_FWD    0x400000   /*  4 MB после   kdata_base — allproc/idt/sysents */
#define TOTAL_SIZE  (TEXT_BACK + DATA_FWD)
#define CHUNK       0x10000    /* 64 KB за один copyout */

#define LOGF(...) do { klog_printf(__VA_ARGS__); printf(__VA_ARGS__); } while(0)

int main(void) {
    payload_args_t *args = payload_get_args();
    if (!args || !args->kdata_base_addr) {
        LOGF("[kdump] FATAL: no kdata_base in payload args\n");
        return 1;
    }

    intptr_t kdata = args->kdata_base_addr;
    intptr_t start = kdata - TEXT_BACK;

    LOGF("[kdump] kdata_base = 0x%lx\n", kdata);
    LOGF("[kdump] dump range = 0x%lx .. 0x%lx (%u bytes)\n",
         start, start + TOTAL_SIZE, (unsigned)TOTAL_SIZE);

    uint8_t *buf = malloc(TOTAL_SIZE);
    if (!buf) { LOGF("[kdump] malloc failed\n"); return 2; }

    size_t got = 0;
    for (size_t off = 0; off < TOTAL_SIZE; off += CHUNK) {
        size_t len = CHUNK;
        if (off + len > TOTAL_SIZE) len = TOTAL_SIZE - off;
        if (kernel_copyout(start + off, buf + off, len) < 0) {
            LOGF("[kdump] copyout failed @ 0x%lx\n", start + off);
            memset(buf + off, 0, len);
        } else {
            got += len;
        }
        if ((off & 0xFFFFF) == 0)
            LOGF("[kdump] progress: 0x%lx / 0x%lx\n", off, (long)TOTAL_SIZE);
    }

    LOGF("[kdump] copied %zu bytes, writing /data/kernel-13.60-dump.bin\n", got);

    FILE *f = fopen("/data/kernel-13.60-dump.bin", "wb");
    if (!f) { LOGF("[kdump] fopen failed: %s\n", strerror(errno)); free(buf); return 3; }
    fwrite(buf, 1, TOTAL_SIZE, f);
    fclose(f);

    f = fopen("/data/kernel-13.60-dump.meta", "w");
    if (f) {
        fprintf(f, "kdata_base=0x%lx\n", kdata);
        fprintf(f, "dump_start=0x%lx\n", start);
        fprintf(f, "dump_size=0x%x\n", (unsigned)TOTAL_SIZE);
        fclose(f);
    }

    free(buf);
    LOGF("[kdump] DONE. Pull /data/kernel-13.60-dump.bin via FTP\n");
    return 0;
}
