obj-m := task1.o 

KDIR  := /lib/modules/$(shell uname -r)/build

PWD   := $(shell pwd)

default:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	rm -rf *.o *.ko *mod.c *.cmd *.markers *.order *.symvers .tmp_versions
