# ps5-fakexen

This should've been the solution for running Linux under the PS5 hypervisor. It was written under the assumption that GMET is active in the PS5 hypervisor, and only pages of authentic kernel code are allowed to execute. Turns out, this was [not the case](https://github.com/buzzer-re/PS5_kldload), and this kind of dirty hacks isn't really necessary to run Linux on the PS5. Thus, I'm now releasing the code "as is" for history (and for the unlikely case that Sony fixes this oversight in later firmwares, which, as far as I know, they can do).

## Building Linux

Place your Linux kernel (in vmlinux format, not bzImage) in `linux/linux-6.12.8/vmlinux`. It should have `CONFIG_XEN_PV` enabled.

## Running on QEMU

To run on QEMU, cd into the fakexen directory and run `make qemu`. This will be slow, unless your host CPU has 16+ cores.

`loader/frankenkernel.elf` contains a fake "BSD kernel" with all the gadgets fakexen requires. Thus, you don't need access to decrypted kernels to test this out.

## Running on real hardware

Run `make` in the top directory to build the `payload.bin` frankenELF. After loading the payload, send the vmlinux file over TCP port 9999. You will want to strip it before sending, it'll save you a lot of space (`loader/Makefile` does this for you).

You'll need to solder to the Titania UART testpads on the PS5 motherboard. I'm not writing up on how to do this here.

If you've done everything correctly, you should see some (hopefully useful) logs on the UART.

## GDB stub

There is a built-in GDB stub for debugging the Linux kernel. To drop into it, send some bytes to the serial during the initial loading messages. Then fire up GDB with the connect-ps5.gdb script, and you're good to go.

The debugger will also be fired (opportunistically) on crashes within fakexen itself, but from there it's postmortem only, trying to reenter fakexen will only break things further.

## Caveats

This is far from polished. It breaks badly if you don't specify "maxcpus=1" in the kernel command line (see `fakexen/linux.c`). It may contain arbitrary bugs that make it exploitable from "guest" userspace. Once again, this is now more of a curiousity and a backup plan in case Sony plugs the hole, rather than production-intended code. Use with caution, don't use in production, you've been warned.
