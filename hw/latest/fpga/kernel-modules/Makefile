# Licensed under the Apache-2.0 license

CONFIG_MODULE_SIG=n
KERNEL ?= $(shell uname -r)
obj-m += rom_backdoor_class.o caliptra_rom_backdoor.o mcu_rom_backdoor.o io_module.o
all:
		make -C /lib/modules/$(KERNEL)/build M=$(PWD) modules
clean:
		make -C /lib/modules/$(KERNEL)/build M=$(PWD) clean
