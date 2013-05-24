# This creates the demonstration utility "lguest" which runs a Linux guest.
# Missing headers?  Add "-I../../../include -I../../../arch/x86/include"
CFLAGS:= -Wall -Wmissing-declarations -Wmissing-prototypes -O3 -U_FORTIFY_SOURCE

all: lguest

build_image:
	@if [ ! -f "./initrd.img" ]; then\
		echo "Building initrd...";\
		./build_initrd.sh;\
	fi

run: build_image all
	@if [`lsmod | grep lg` -eq ""]; then\
		modprobe lg;\
	fi
	@./lguest 64 /boot/vmlinuz-`uname -r` --tunnet=192.168.19.1 --block=initrd.img root=/dev/vda

clean:
	rm -f lguest
