ifdef PS5_PAYLOAD_SDK
include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
$(error PS5_PAYLOAD_SDK is undefined)
endif

ELF := kernel-dumper.elf
CFLAGS += -Wall -Wextra -g

all: $(ELF)

$(ELF): main.c
	$(CC) $(CFLAGS) -o $@ main.c

clean:
	rm -f $(ELF) *.o

.PHONY: all clean
