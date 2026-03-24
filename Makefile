obj-m := diamorphine.o
KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
IDIR := $(MDIR)/src/include

all:
	make -C $(KDIR) M=$(MDIR) modules
clean:
	make -C $(KDIR) M=$(MDIR) clean
	
ccflags-y += -I$(srctree)/arch/arm64/mm
