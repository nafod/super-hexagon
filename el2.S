.section .text
.global _start
_start:

    # We no longer have a print flag function, so we have to retrieve
    # it ourselves via the MSRs + el2_kprintf

    # Grab some scratch space
    ldr x0, =0x40102000
    mrs x1, s3_3_c15_c12_0
    str w1, [x0]
    mrs x1, s3_3_c15_c12_1
    str w1, [x0,#4]
    mrs x1, s3_3_c15_c12_2
    str w1, [x0,#8]
    mrs x1, s3_3_c15_c12_3
    str w1, [x0,#0xC]
    mrs x1, s3_3_c15_c12_4
    str w1, [x0,#0x10]
    mrs x1, s3_3_c15_c12_5
    str w1, [x0,#0x14]
    mrs x1, s3_3_c15_c12_6
    str w1, [x0,#0x18]
    mrs x1, s3_3_c15_c12_7
    str w1, [x0,#0x1c]

    # Print out the flag 
    mov x15, x0

    add x16, x15, #0x20

loop:
    ldr x0, [x15]
    ldr x8, =0x40100690
    blr x8
    add x15, x15, #1
    cmp x15, x16
    bne loop

    nop
    nop
    nop
    nop


    # Prevent ourselves from looping forever
wfi:
    b wfi
