#!/bin/bash
#

# Normal execution
/home/super_hexagon/qemu-system-aarch64 -nographic -machine hitcon -cpu hitcon -bios /home/super_hexagon/bios.bin -monitor /dev/null 2>/dev/null -serial null

# wait for debugger (64bit debugging)
#/home/super_hexagon/qemu-system-aarch64 -nographic -machine hitcon -cpu hitcon -bios /home/super_hexagon/bios.bin -monitor /dev/null 2>/dev/null -serial null -S -s

# wait for debugger (32bit debugging)
#/home/super_hexagon/qemu-system-debug-aarch64 -nographic -machine hitcon -cpu hitcon -bios /home/super_hexagon/bios.bin -monitor /dev/null 2>/dev/null -S -s
