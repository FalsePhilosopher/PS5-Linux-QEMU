all: hdd.img

clean:
	rm -f hdd.img vmlinux

hdd.img: bmvm/libfakexen ../fakexen/fakexen.elf build.py main.cpp fakekernel.asm config.txt vmlinux
	cd bmvm; python3 build.py amalgam libfakexen/hdd.img libfakexen/config.txt linux32

bmvm/libfakexen:
	ln -s $(shell pwd) bmvm/libfakexen

../fakexen/fakexen.elf:
	cd ../fakexen; make

vmlinux: ../linux/linux-6.12.8/vmlinux
	objcopy --strip-all ../linux/linux-6.12.8/vmlinux vmlinux

qemu: all
	qemu-system-x86_64 -cpu max,tsc-frequency=12471095 -m 8192 -smp 16 -hda hdd.img -debugcon >(cat) -serial pty -s -no-reboot -no-shutdown

kvm: all
	qemu-system-x86_64 -cpu host -enable-kvm -m 8192 -smp 16 -hda hdd.img -debugcon >(cat) -serial pty -s -no-reboot -no-shutdown

bochs: all
	bochs
