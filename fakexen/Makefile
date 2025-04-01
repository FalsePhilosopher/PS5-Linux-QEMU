all: fakexen.elf

clean:
	rm -f crt.o fakexen.elf

%.o: %.asm
	yasm -f elf64 $< -o $@

fakexen.elf: *.c *.h crt.o hypercalls.o
	gcc -Wl,-Bsymbolic -Wl,-gc-sections -ffunction-sections -fdata-sections -nostdlib -nostdinc -ffreestanding -mgeneral-regs-only -fno-stack-protector -O0 -g -fPIE -fPIC *.c crt.o hypercalls.o -shared -fvisibility=hidden -o fakexen.elf
	if readelf -d fakexen.elf | grep -q JMPREL; then readelf -r fakexen.elf; rm fakexen.elf; false; fi

qemu: fakexen.elf
	cd ../loader; make qemu

kvm: fakexen.elf
	cd ../loader; make kvm

bochs: fakexen.elf
	cd ../loader; make bochs
