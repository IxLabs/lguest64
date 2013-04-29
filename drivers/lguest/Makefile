# Guest requires the device configuration and probing code.
obj-$(CONFIG_LGUEST_GUEST) += lguest_device.o

# Host requires the other files, which can be a module.
obj-$(CONFIG_LGUEST)	+= lg.o
lg-y = core.o lguest_user.o


lg-$(CONFIG_X86_32) += x86_32/switcher.o x86_32/core.o x86_32/hypercalls.o \
                       x86_32/interrupts_and_traps.o x86_32/page_tables.o \
                       x86_32/segments.o x86_32/lguest_user.o

lg-$(CONFIG_X86_64) += x86_64/switcher.o x86_64/core.o x86_64/hypercalls.o			\
                       x86_64/interrupts_and_traps.o x86_64/page_tables.o			\
                       x86_64/segments.o x86_64/lguest_user.o x86_64/lguest_stat.o	\
					   x86_64/lguest_debug.o

Preparation Preparation!: PREFIX=P
Guest: PREFIX=G
Drivers: PREFIX=D
Launcher: PREFIX=L
Host: PREFIX=H
Switcher: PREFIX=S
Mastery: PREFIX=M
Beer:
	@for f in Preparation Guest Drivers Launcher Host Switcher Mastery; do echo "{==- $$f -==}"; make -s $$f; done; echo "{==-==}"
Preparation Preparation! Guest Drivers Launcher Host Switcher Mastery:
	@sh ../../tools/lguest/extract $(PREFIX) `find ../../* -name '*.[chS]' -wholename '*lguest*'`
Puppy:
	@clear
	@printf "      __  \n (___()'\`;\n /,    /\`\n \\\\\\\"--\\\\\\   \n"
	@sleep 2; clear; printf "\n\n   Sit!\n\n"; sleep 1; clear
	@printf "    __    \n   ()'\`;  \n   /\\|\` \n  /  |  \n(/_)_|_   \n"
	@sleep 2; clear; printf "\n\n  Stand!\n\n"; sleep 1; clear
	@printf "    __    \n   ()'\`;  \n   /\\|\` \n  /._.= \n /| /     \n(_\_)_    \n"
	@sleep 2; clear; printf "\n\n  Good puppy!\n\n"; sleep 1; clear

.PHONY clean:
	rm -f lg.ko *.o x86_*/*.o
