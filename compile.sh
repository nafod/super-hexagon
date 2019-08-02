#!/bin/bash
set -e
rm -f *.o
aarch64-linux-gnu-gcc -c ./el0.S
aarch64-linux-gnu-objcopy -O binary el0.o el0-raw.o
aarch64-linux-gnu-gcc -c ./el1.S
aarch64-linux-gnu-objcopy -O binary el1.o el1-raw.o
aarch64-linux-gnu-gcc -c ./el2.S
aarch64-linux-gnu-objcopy -O binary el2.o el2-raw.o
aarch64-linux-gnu-gcc -c ./sel0.S
aarch64-linux-gnu-objcopy -O binary sel0.o sel0-raw.o
arm-linux-gnueabi-gcc-7 -mbig-endian -c ./sel0-stager.S
arm-linux-gnueabi-objcopy -O binary sel0-stager.o sel0-stager-raw.o
arm-linux-gnueabi-gcc-7 -c ./sel0-flag.S
arm-linux-gnueabi-objcopy -O binary sel0-flag.o sel0-flag-raw.o
aarch64-linux-gnu-gcc -c ./el2-redux.S
aarch64-linux-gnu-objcopy -O binary el2-redux.o el2-redux-raw.o
arm-linux-gnueabi-gcc-7 -march=armv7-a -c ./sel1-el3.S
arm-linux-gnueabi-objcopy -O binary sel1-el3.o sel1-el3-raw.o
aarch64-linux-gnu-gcc -c ./el3.S
aarch64-linux-gnu-objcopy -O binary el3.o el3-raw.o
echo "compiled all shellcode blobs"
