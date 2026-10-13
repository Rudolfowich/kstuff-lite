PS5_HOST ?= 192.168.2.2
PS5_PORT ?= 9021

ifdef PS5_PAYLOAD_SDK
    include $(PS5_PAYLOAD_SDK)/toolchain/prospero.mk
else
    $(error PS5_PAYLOAD_SDK is undefined)
endif

CFLAGS  += -Wall -Werror -O2

SRC := $(wildcard src/*.c)

all: kstuff-rpc.elf

kstuff-rpc.elf: $(SRC)
	$(CC) $(CPPFLAGS) $(CFLAGS) $(SRC) -o $@ -Wl,-s

clean:
	rm -f *.elf

deploy: kstuff-rpc.elf
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $<
