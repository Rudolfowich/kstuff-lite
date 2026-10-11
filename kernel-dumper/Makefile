ifndef PS5_PAYLOAD_SDK
    $(error PS5_PAYLOAD_SDK is undefined)
endif

include $(PS5_PAYLOAD_SDK)/make/elf.mk

ELF := kernel-dumper.elf
SRCS := main.c

all: $(ELF)

clean:
	rm -f $(ELF) *.o

.PHONY: all clean
