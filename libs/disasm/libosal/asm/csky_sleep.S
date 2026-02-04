
disasm/libosal/obj/csky_sleep.o:     file format elf32-csky-little


Disassembly of section .text.os_sleep:

00000000 <os_sleep>:
   0:	14d0      	push      	r15
   2:	33fa      	movi      	r3, 250
   4:	4362      	lsli      	r3, r3, 2
   6:	7c0c      	mult      	r0, r3
   8:	e0000000 	bsr      	0x0	// 0 <csi_kernel_ms2tick>
   c:	e0000000 	bsr      	0x0	// 0 <csi_kernel_delay>
  10:	1490      	pop      	r15

Disassembly of section .text.os_sleep_ms:

00000000 <os_sleep_ms>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <csi_kernel_delay_ms>
   6:	1490      	pop      	r15
