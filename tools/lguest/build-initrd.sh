#!/bin/bash

lguestdir=`pwd`

# Do a little housekeeping.
rm -f initrd.img

# Set ramdisk image constants.
CNTSIZE=4000
BLKSIZE=1024

# Create an empty ramdisk image.
dd if=/dev/zero of=initrd.img bs=$BLKSIZE count=$CNTSIZE &> /dev/null

# Make it an ext2 mountable file system.
/sbin/mke2fs -F -m 0 -b $BLKSIZE initrd.img $CNTSIZE &> /dev/null

# Mount it, so we can populate it.
mkdir -p /mnt/initrd
mount initrd.img /mnt/initrd -t ext2 -o loop

# Create the basic directories.
cd /mnt/initrd
mkdir -p bin dev etc lib proc sbin sys tmp var

# Grab the device files.
cd /mnt/initrd/dev
cp -a /dev/* .

# Download BusyBox and build it as a static library.
cd /tmp
wget -q http://www.busybox.net/downloads/busybox-1.21.0.tar.bz2
tar -jxf busybox-1.21.0.tar.bz2
cd busybox-1.21.0
make defconfig &> /dev/null
echo "CONFIG_STATIC=y" >> .config
make &> /dev/null

# Grab the newly created binary.
cd /mnt/initrd/bin
cp /tmp/busybox-1.21.0/busybox .
rm -Rf /tmp/busybox*

# Create the 'init' symbolic link.
cd /mnt/initrd/sbin
ln -s ../bin/busybox init

# Create the 'ash' symbolic link.
cd /mnt/initrd/bin
ln -s busybox ash

# Create the essential user commands' symbolic links.
BINARIES=`ls -m1 /bin`
for binary in $BINARIES
do
	ln -s busybox $binary &> /dev/null
done

# Create the root-only commands' symbolic links.
cd /mnt/initrd/sbin
BINARIES=`ls -m1 /sbin`
for binary in $BINARIES
do
	ln -s ../bin/busybox $binary &> /dev/null
done

# Create the 'rcS' file, which will mount all the filesystems.
cd /mnt/initrd/etc
mkdir -p init.d
cd init.d
touch rcS
chmod +x rcS

cat > rcS << EOF
#!/bin/ash

mount -a
EOF

# Create the 'fstab' file, so 'rcS' will know what to do.
cd /mnt/initrd/etc

cat > fstab << EOF
# /etc/fstab: static file system information.
#
# <file system> <mount pt>     <type>	<options>         <dump> <pass>
/dev/root	/              ext2	rw,noauto         0      1
proc		/proc	       proc     defaults	  0	 0
none		/sys           sysfs	defaults	  0	 0
devpts		/dev/pts       devpts   defaults,gid=5,mode=620	  0	 0
tmpfs           /tmp           tmpfs    defaults          0      0
EOF

# Finish up.
cd $lguestdir
umount /mnt/initrd
