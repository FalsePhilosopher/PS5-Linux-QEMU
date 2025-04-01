!touch /dev/ttyUSB0 || sudo chmod 777 /dev/ttyUSB0
set serial baud 230400
#set debug remote 1
target remote /dev/ttyUSB0
source fakexen/defines.gdb
