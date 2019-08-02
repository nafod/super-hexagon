.section .text
.global _start
_start:

    # Executing in EL3! print out the S-EL1 flag,
    # since we haven't gotten that yet, and also
    # the EL3 flag
    nop
    nop
    nop

    # Print out the S-EL1 flag
    ldr x0, =0xe002700
    ldr x8, =0x11b4
    blr x8

    # Save out the EL3 flag
    add x0, sp, 0x100
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

    # Print out the EL3 flag
    blr x8

    # Loop forever, nothing else left to do!
wfi:
    b wfi
