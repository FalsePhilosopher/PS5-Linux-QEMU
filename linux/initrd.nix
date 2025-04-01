{ pkgs ? import<nixpkgs>{} }:

with pkgs;

let
  init = writeScript "init.sh" ''
    #!${busybox}/bin/sh
    set -x
    exec >/dev/hvc0 2>&1
    export PATH=${busybox}/bin
    mkdir -p /dev /proc /sys
    [[ -e /dev/null ]] || mount -t devtmpfs udev /dev
    exec >/dev/hvc0 2>&1
    [[ -e /proc/version ]] || mount -t proc proc /proc
    [[ -e /sys/class ]] || mount -t sysfs sysfs /sys
    ls /dev
    ls /dev/snd
    ls /proc
    ls /sys
    ls -R -l /sys/firmware
    ${pciutils}/bin/lspci
    ${strace}/bin/strace -f ${usbutils}/bin/lsusb
    ls -l /sys/bus/pci/devices/*/driver
    for i in `seq 1 5`; do sleep 1; done
    uname -a
    cat /proc/cpuinfo
    sleep inf
  '';
in
#   ${pkgsi686Linux.busybox}/bin/uname -a

makeInitrd {
  contents = [
    {
      object = init;
      symlink = "init";
    }
    {
      object = init;
      symlink = "bin/sh";
    }
  ];
}
