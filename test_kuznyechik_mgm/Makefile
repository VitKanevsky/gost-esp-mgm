KSRC ?= /lib/modules/$(shell uname -r)/build
#KSRC = $(HOME)/linux/

obj-m += test_kuznyechik_mgm.o

ccflags-y := -I $(PWD)

all: modules

modules modules_install clean:
	$(MAKE) -C $(KSRC) M=$(PWD) $@
