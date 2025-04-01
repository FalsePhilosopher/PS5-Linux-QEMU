all: payload.bin

clean:
	rm -f payload.elf payload.bin trampoline.o

../lib/lib-elf-ps5.a:
	cd ../lib; make

../prosper0gdb/prosper0gdb.o:
	cd ../prosper0gdb; make

../ps5-kstuff/structs.inc:
	cd ../ps5-kstuff; make structs.inc

fakexen/fakexen.elf: fakexen/*.c fakexen/*.h fakexen/*.asm
	cd fakexen; make

trampoline.o: trampoline.asm
	yasm -f elf64 $< -o $@

payload.elf: ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o main.c trampoline.o fakexen/fakexen.elf
	gcc -O0 -g -isystem ../freebsd-headers -nostdinc -nostdlib -fno-stack-protector -static ../lib/lib-elf-ps5.a ../prosper0gdb/prosper0gdb.o $(EXTRA_CFLAGS) main.c trampoline.o -DPS5KEK ../prosper0gdb/dbg.c -Wl,-gc-sections -o payload.elf -fPIE -ffreestanding -no-pie -Wl,-z,max-page-size=16384 -Wl,-zcommon-page-size=16384

payloa%.bin: payloa%.elf
	objcopy $< --only-section .text --only-section .data --only-section .bss --only-section .rodata -O binary $@
	python3 ../lib/frankenelf.py $@
