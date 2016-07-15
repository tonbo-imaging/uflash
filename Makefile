CC = gcc
CFLAGS = -Wall -Wstrict-prototypes -O2 -fomit-frame-pointer -DUSE_HOSTCC
INCLUDE = -I ./include

all: uflash

uflash:	./src/uflash.c ./lib/crc32.c ./lib/errno.c
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $^

clean:
	rm -f uflash

.PHONY: all clean