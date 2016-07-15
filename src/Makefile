include $(TOPDIR)/config.mk

all: $(obj)uflash

HOSTCFLAGS_NOPED += -I $(SRCTREE)/include -DUSE_HOSTCC

$(obj)uflash: $(SRCTREE)/tools/uflash/uflash.c $(SRCTREE)/lib/crc32.c $(SRCTREE)/lib/errno.c
	# echo $(TOPDIR) # /home/anirudh/ti/u-boot-davinci
	# echo $(SRCTREE) # /home/anirudh/ti/u-boot-davinci
	# echo $(HOSTCC) # gcc
	# echo $(HOSTCFLAGS_NOPED) # -Wall -Wstrict-prototypes -O2 -fomit-frame-pointer -I /home/anirudh/ti/u-boot-davinci/include -DUSE_HOSTCC
	# echo $(HOSTLDFLAGS) # <Blank>
	$(HOSTCC) $(HOSTCFLAGS_NOPED) $(HOSTLDFLAGS) -o $@ $^

clean:
	rm -f $(obj)uflash

.PHONY: all clean
