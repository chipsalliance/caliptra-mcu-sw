// Licensed under the Apache-2.0 license

#include <linux/module.h>
#include <linux/cdev.h>
#include <asm/io.h>

#ifndef CLASS_NAME
#define CLASS_NAME "rom-backdoor"
#endif

struct class *rom_backdoor_chardev_class;
EXPORT_SYMBOL(rom_backdoor_chardev_class);

static int mychardev_uevent(struct device *dev, struct kobj_uevent_env *env)
{
    return add_uevent_var(env, "DEVMODE=%#o", 0666);
}

static int __init register_rom_backdoor_class(void)
{
    rom_backdoor_chardev_class = class_create(THIS_MODULE, CLASS_NAME);
    if (IS_ERR(rom_backdoor_chardev_class))
    {
        printk(KERN_ALERT "register_rom_backdoor_class: error %lu in class_create\n", PTR_ERR(rom_backdoor_chardev_class));
        return PTR_ERR(rom_backdoor_chardev_class);
    }

    rom_backdoor_chardev_class->dev_uevent = mychardev_uevent;

    return 0;
}

static void __exit rom_backdoor_backdoor_class_remove(void)
{
    class_unregister(rom_backdoor_chardev_class);
    class_destroy(rom_backdoor_chardev_class);
}

module_init(register_rom_backdoor_class);
module_exit(rom_backdoor_backdoor_class_remove);

MODULE_AUTHOR("Luke Mahowald <jlmahowa@amd.com>");
MODULE_DESCRIPTION("Caliptra FPGA ROM driver");
MODULE_LICENSE("GPL v2");
