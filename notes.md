# super-hexagon notes

order recommended by challenge writers:
```
EL0 - Hard
EL1 - Harder
EL2 - Hardest
S-EL0 - Hardester
S-EL1 - Hardestest
S-EL3 - Hardestestest
```

overall data layout in bios.bin:

- 0x00000 -> EL3
- 0x0C000 -> EL0
- 0x10000 -> EL2
- 0x20000 -> S-EL1
- 0xB0000 -> EL1
- 0xBDF10 -> S-EL0

- top level of the binary is aarch64

- relevant code from init_chip:

```
  el3_bzero(0xE002000ui64, 0x202000i64);
  el3_memcpy((_QWORD *)0xE000000, (char *)&unk_2850, (unsigned __int64)&loc_68);
  el3_memcpy((_QWORD *)0x40100000, (char *)&unk_10000, (unsigned __int64)&unk_10000);
  el3_memcpy((_QWORD *)0xE400000, (char *)&loc_20000, 0x90000ui64);
  el3_memcpy((_QWORD *)0x40000000, (char *)&unk_B0000, (unsigned __int64)&unk_10000);
```

- 0xE003000 may be the offset of the global page tables? i say this because of el3_mmu_setup

vmm runs in el2

- looks like we map several things in that function
- EL3 RAM is printed to us: 0xE000000 -> 0xE204000
-prints out SCTLR_EL3 and SCR_EL3

- vmm mappings at 0 and 0xC000

- kernel generates both HVC (calls to El2) and SMC (calls to EL3)

- el0 mappings probably will be at 0xFFFFFFFFC000C010i64

- our hint that not all mappings are aarch64 are that ida seems to believe some functions are ARM in the mappings setup in el3

- based on the picture HITCON posted, I'd guess el0/el1/el2 are aarch64, with the remaining ones being arm

looks like el0, el1, and el2 are all aarch64

- at 0xbc010 we see an elf header, so let's go ahead and extract it (its near the end of the file)

- it's a valid aarch64 elf, NX but no aslr, mapped at 0x400000
- statically linked and comes with debug info

- EL0:

- defines two commands in a table and then takes user input
- first thing is does is to load a trustlet, presumably solely for the purpose of showing us how to do it
  - this probably ends up allowing us to interface with the trustlet. for now, let's focus on EL0 -> EL1 bugs, rather than EL0 -> S-EL0
- it seems like there is a syscall that will take a el0 mapping, make it shareable with trustlet space, and then init it
- trustlet blob is loaded via a syscall - we'll put this aside until later
- trivial bug in the run() function, cmd can be out of the buffer size range to get control of PC
- the binary claims to have NX, need to check if its actually enforced
	- NX is enforced! furthermore, vmm/EL2 prevents EL1 from creating RWX mappings

- nothing to EL0:
  - notice that the internals of scanf() invoke gets()
  - we can clobber the buffer to write some mostly-alphanumeric shellcode
  - afterwards, use our function gadget to call mprotect() on the buffer to make it execute-only
  - execute the code in the buffer to read our stage2 into the trustlet buffer (allocated earlier as RW)
  - invoke mprotect again to jump to tha trustlet code
  - now we can execute our arbitrary bytes :)
  - key points:
  	- the vmm prevents the mmap syscall from creating RWX mappings. you will get an el2_kprintf and abort
  	- the read() syscall only ever returns 1 byte, so it needs to be called in a loop
  		- we can determine this by reversing out the syscall handler in the main binary. you can find the syscall handler by just 
  		  going through bytes near the already-defined el1 functions and defining them out
  	- EL0 has no ASLR

- EL1:
	- very simple kernel, with only 4 syscalls (mmap, mprotect, getchar, putchar)
		- in addition, there are 4 hypercalls that can go through the syscall interface
		- these are denoted with a syscall number with highest byte 0xFF
	- there is simple page table handling (for mprotect) and support for allocating a few pages
		- simple translations from virtual to physical addresses (add or subtract 0x40000000)
	- kernel is mapped at 0xffffffffc0000000
	- we are looking for bugs in one of the 4 syscalls, since it's the only way we know how to interact with EL1
		- hypercalls, later
	- kernel and user space are separated from each other, but there is no PAN protection, so kernel can directly write to userspace
	- however, none of the handlers actually do `copy_to_user`/`copy_from_user`
	- write syscall doesn't look particularly interesting
	- mmap and mprotect seem to perform extensive checking on argument validity
		- mprotect checks to make sure the page requested is already mapped
		- both also perform further checking on the specific page range in el1_mmap_into_el0, so we can't trivially map certain pages into el0
	- read syscall IS interesting
		- it invokes an function to read a byte, and then directly writes it to the requested address without any validation!
		- passing a kernel address will result in your data being written directly to that address (respecting memory protections)
	- EL1 has no ASLR

- EL0 to EL1:
	- notice the bug in the read syscall
	- because of mmu being enabled, we can't directly write over the kernel text data
	- we could possibly target the kernel stack, but it's not clear how to trivially turn ROP into shellcode execution
	- easiest path is to overwrite page table entries
		- in el1_enable_mmu, the kernel adds its own physical pages to the mmu
		- using that information, we can create an allocation in userspace and then overwrite that allocation's physaddr in the page tables
		- el1 updates the page table in el1_update_page_table, navigating through 3 levels
	- once we have a physical page in both userspace and kernelspace, we can write code to it with a RW mapping
		- from here, we could overwrite the return address on the kernel stack, or simply overwrite code that we can then invoke
	- page table entry at 0xffffffffc0028fe0 corresponds to our shellcode mmap, should point to the page with el1_wfi_spinloop, a call we can hit via syscall
		- we want to turn 0x60000000035443, pte for our mapping, to 0x40000000009483, pte for the page containing el1_wfi_spinloop
	- upon implementation, we find that the EL2 vmm is protecting kernel pages from being overwritten, even if EL1 page table disagrees
		- new plan: convert our mapping to a kernel page after writing our shellcode there, abusing discrepancy with EL1/El2 page tables
		- EL2 doesn't seem to be checking whether the page is in EL0 or EL1, only that the physical page is mapped with the same memory protections
		- we write our shellcode to a userspace page, then target kernel page 0xB0000 in the binary, which is used only for init
		- its pte is at 0xffffffffc001e000
		- we make it point to our page, then we smash a single byte in the stack, so that the syscall handler returns to that page
	- alternative exploit: overwrite saved SP value to get a ropchain (via our saved registers)
		- rop to mmap/mprotect

- EL2:
	- El2 implements a simple vmm, beginning at 0x10000 in the raw data and 0x40100000 in virtual memory
	- we are primarily interested in the setup routine, and the hypercall interface available to us
	- hypercall function is very small, and basically defines a vmm_mmap call, and some secure monitor calls, which we'll not look at yet
	- the mmap call implements its own mmaping with its own page tables, validating intermediate physical addresses (IPAs) coming from EL1
		- these are IPAs, so EL1 thinks they are real physical addresses
		- e.g. it maps EL1 into EL2 page tables, and passes values 0x0000 -> 0xB0000
	- the EL1 kernel would invoke vmm_mmap whenever it updated its own page tables, so they would stay in sync
	- based on the error strings, vmm_mmap validate 3 things
		- you cannot map RWX pages
		- you must map valid physical addresses (must be < 0x3BFF)
		- you can't map writeable pages in "RO area", which is defined as x < 0xBFFF and bit 7 in the TTE
		- bit 7 corresponds to the top bit of the access permissions, which determines whether the page is readonly or read/write in EL2/EL1
		- this information is confirmed to us in the boot printks:

			[VMM] RO_IPA: 00000000-0000c000
			[VMM] RW_IPA: 0000c000-0003c000

		- our best guess here is that the vmm is trying to prevent you from directly overwriting EL2 or EL1 code
	- the page tables themselves are mapped in start at 0x40107000

- EL1 to EL2:
	- there is only one relevant syscall handler (el2_mmap) so it must have a bug
	- it validates x0 as the page to map and x1 as the args, but it doesn't clear the bottom bits of x0
		- this wouldn't matter from EL0, since we couldn't directly make the hypercall
	- this means we can actually leave x1 as zero, and put our permissions into the bottom bits of x0
	- with this, we can map RWX pages as we please
		- note that we couldn't do this from EL0, because we couldn't directly hit this function
	- x1 is barely checked in general, beyond the permission bits, so we can map basically any phys page
	- we can map EL2 pages by putting 0x10000 into x1, and the rest of the page data + permissions into x0
	- we map 0xffffffffc0001000 PTE to point to 0x40101000
	- then we update our own EL1 page tables to mark 0xffffffffc0001000 as r/w
	- we write shellcode to 0xffffffffc0001000
	- then we invoke a hypercall to redirect execution to 0x40101000
	- one small catch: we have to read and output the flag MSRs ourselves, no el2_print_flag

- S-EL0/S-EL1:
	- realm of trusted apps
	- in theory runs at same execution level as normal EL0 but is in secure world, only accessible via security monitor call
	- on a real chip, this would be distributed directly by the manufacturer and meant not to run user code
		- possibly just directly burned into the ROM
	- in super_hexagon, S-EL1 is arm/thumb not aarch64
		- to facilitate this, we'll create a second idb for bios.bin
	- first information we have is the actual functionality of EL0, which loads the trustlet and receives a handle
		- it also loads something called "world shared memory" which it uses for interfacing
	- later, this handle is used for trustlet calls that securely loads+stores keys, which is the primary functionality of the EL0 software
	- let's examine the trustlet blob itself (as loaded by S-EL1)
		- where is the blob? excerpt from the EL0 elf file:

				ADRP            X0, #TA_BIN_SIZE@PAGE
				LDR             W1, [X0,#TA_BIN_SIZE@PAGEOFF] ; size
				ADRP            X0, #TA_BIN@PAGE ; "HITCON"
				ADD             X0, X0, #TA_BIN@PAGEOFF ; "HITCON"
				BL              load_trustlet


		- starts at 0x000bdf10 in bios.bin, size of 0x750
		- begins with magic string HITCON\x00\x00
		- S-EL1 does a hash of the file (sha256) and compares it to a built in constant
		- no known attacks on sha256, so we can't load arbitrary trustlets in directly
		- trustlet format
			- 0x24 byte header
			- 0x8 byte header (HITCON\x00\x00)
			- whole thing is compared to a hardcoded sha256 hash
			- followed by pointers to text, data, bss
				- text section immediately follows our header (loaded at 0x1000, len 0x0684)
				- data section starts at 0x6a8 in file (loaded at 0x2000, len 0xa8)
				- bss (loaded at 0x081070, len 0x10000)
		- see attached idb with the trustlet properly mapped into memory (note! big endian)
		- the trustlet is very small and contains the two handlers we see exposed
		- it's BIG-ENDIAN arm thumb mode; the qemu-system-aarch64 cannot handle debugging this
			- to work around this, we need to compile our own qemu-system-aarch64 with the provided debug patch
			- the patch switches the gdbserver debug routines to return arm information instead
			- we'll continue forward using both qemus to debug, switching between them as needed
		- it is capable of storing up to 10 keys (0 thru 9, inclusive)
			- we can see syscall usage and compare it to S-EL1
		- NX and ASLR both appear to be disabled
		- it will store database entries for each one, and contains a malloc/free
			- free() is triggered when you try to store a key over an existing one
			- malloc and free are simplified dlmalloc with a single freelist, and large-size mmapping

- EL0/EL1 to S-EL0:
		- the tci_handle in EL0 is actually an address in S-EL0 corresponding to the shared memory
			- these are restricted by the S-EL1 map/unmap calls to be within a certain range
			- these addressess are also checked during a smc call, so we can't spoof the handle
		- however, there are not checks in S-EL1 on the size of the S-EL0 mapping to make sure it matches the EL0 mapping
			- this IS checked in EL1, but we control that
			- why not checked? secure world can't check normal world PTEs, so it would need to ask EL3
			- ideally it should pass index'd handles rather than raw addresses, so we can't spoof them as easily
		- S-EL1 also provides an unmap call which isn't used in EL0, but we can invoke from EL1
		- we can abuse the difference in the page tables as follows:
			- make a mapping in S-EL0 of size 0x41000 from EL1
				- we don't need that much in EL1, it doesn't validate that all of that range is mapped
			- use our huge mapping as a tci_buf to create an mmap'd secure key
			- unmap the first chunk of that secure key
			- map a 0x1000 buf into S-EL0, overwriting the first page of our secure key, giving us control over the chunk header
			- abuse unsafe unlink to overwrite the saved PC on the stack and jump to shellcode in our key
		- there is a catch; it wasn't clear to me how to produce output on UART in S-EL0, so we want a more robust shellcoding method
			- we'll overwrite S-EL0 load_key to execute a function pointer on our shellcode page and return, so we can retrieve output
		- furthermore, armv7 doesn't have MSRs, but rather coprocessor registers, so we have to adopt our flag reading code
			- looking at the qemu.patch provided by the organizers (and armv7 manual), we come up with the following instructions

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

S-EL1:
	- we've already done pretty significant reversing on S-EL1 in order to understand S-EL0
	- still no ASLR/NX, and also S-EL1 can read/write S-EL0 mappings, including world-shared-mappings (so, no PAN/PXN)
	- therefore, the main surface we haven't examined yet is the S-EL1 syscall interface, which is accessible to S-EL0
	- only 3 syscalls (!)
		- mmap (used by sel0_malloc)
		- munmap (used by sel0_free)
		- signal handler register, which sets a global in sel1_memory based on the signal (hardcoded to only SIGSEGV)
			- this is used by the S-EL0 loop code to handle segfaults, and also reset to -1 in the segfault handler in S-EL0
	- all 3 seem relatively robust
		- mmap gives us no control besides the size (it ignores the addr)
		- munmap is identical to the other munmap code (for world shared memory)
		- the signal handler call doesn't seem of interest, since it would only give us execution in S-EL0, which we already have
	- the inner workings of S-EL1 mmap is interesting; it stores a bitmap of 32 dwords, where each bit in every dword
	represents whether or not a page is free
	- a similar bitmap exists for S-EL0, based on virtual addresses
	- these may be related to the two-step TTBR0 and TTBR1 setup in the S-EL1 entrypoint

- EL1/EL2/S-EL0 to S-EL1/EL3:
	- in the map shared world handler, the code in S-EL1 attempts to make sure your physical page is above 0x40000000
	- this number is because pages above that number are reserved for normal world, and pages below for secure
	- preventing us from mapping below that prevents us from creating a RW buffer in S-El1 text section
	- however, there is no overflow protection
		- physaddr + size could overlap and become 0, which is actually an EL3 (!) page
	- naively attempting to map 0xFFFFF000 for 0x2000 bytes fails however, because EL2 inserts itself into the securecall handler
		- EL2 will ensure the page you pass is greater than 0 and <= 0x3C000, and then add 0x8000000 to that
	- however, this isn't a security boundary anymore for us; we control EL2 execution
		- we'll therefore continue the exploit from EL2
		- before we go, we'll load some more shellcode into S-EL0, since its easier
	- therefore, we can actually obtain a writeable mapping to EL3 memory in S-EL0, by issuing a smc in EL2
	- we can transition directly from EL2 to S-EL0, then copy out payload to EL3 and jump there
	- EL3 can print out its own flag, then drop to S-EL1 (it's privileged, after all) and get that one too
	- problem:
		- when implementing this solution, a problem arose; S-EL0 for some reason can only read from the mapping, not write to it
		- this may be because the first chunk of physical pages mapped in the challenge are VIRT_FLASH
		- despite this, gdb itself can write to the mappings...?
	- back to the drawing board
	- one thing that is very interesting is the signal handler behavior
		- it is set up to return to normal world with an error code whenever a signal happens
		- this return happens via code executed in S-EL0
	- internally, on a data abort, S-EL1 will check if a sighandler is defined, and then return to that
		- actually, it does not force the SPSR to be userspace; it only reverts it to what it was at the time of the signal
	- in other words, if we set a signal handler and then force a fault in S-EL1, we'll be returned to a controlled address but running in S-EL1!
	- we can trivially trigger a data abort by passing an unmapped trustlet address, in the valid range, to load_trustlet
	- doing so gives us execution in S-EL1 running our shellcode!

EL3 (secure monitor):
	- the final frontier
	- EL3 is actually pretty minimal here; it sets up the MMU and UART, does some basic configuration, and then steps down
	- it defines an smc interface which is responsible for passing execution back and forth between normal and secure worlds
	- it runs directly off of the VIRT_FLASH ROM physical pages, so we can't overwrite it (see above)
		- however, if we could redirect execution to the el1_print_flag routine in memory, it would give us the flag

S-EL1 to EL3:
	- not a real security boundary as implemented in super-hexagon
	- we can overwrite EL3 data pages, such as that which contains the saved stack pointers for the securecall transition
	- we can also map EL3 physical pages into our address space by updating our page table
	- first, shove our shellcode into an EL3 data page somewhere
	- then, overwrite the EL3 saved stack pointer for normal world to point to EL3 stack, such that the smc ret value smashes the EL3 stack
	- then simply returning from secure world allows us to redirect execution to the shellcode we just wrote
	- one caveat; when we write the shellcode in, we should also update the EL3 PTE to mark that page as executable
		- we can do this trivially by mapping in the page table physaddr into our address space and writing over it