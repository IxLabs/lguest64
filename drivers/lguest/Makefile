KDIR=/lib/modules/`uname -r`/build

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

build:
	make -C $(KDIR) M=`pwd`

.PHONY clean:
	rm lg.ko *.o
