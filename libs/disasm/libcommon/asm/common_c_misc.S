
disasm/libcommon/obj/common_c_misc.o:     file format elf32-csky-little


Disassembly of section .text.do_global_ctors:

00000000 <do_global_ctors>:
   0:	14d2      	push      	r4-r5, r15
   2:	10ac      	lrw      	r5, 0x0	// 30 <do_global_ctors+0x30>
   4:	3300      	movi      	r3, 0
   6:	9580      	ld.w      	r4, (r5, 0x0)
   8:	2b00      	subi      	r3, 1
   a:	64d2      	cmpne      	r4, r3
   c:	0807      	bt      	0x1a	// 1a <do_global_ctors+0x1a>
   e:	3400      	movi      	r4, 0
  10:	5c62      	addi      	r3, r4, 1
  12:	d0650882 	ldr.w      	r2, (r5, r3 << 2)
  16:	e9220005 	bnez      	r2, 0x20	// 20 <do_global_ctors+0x20>
  1a:	e9240005 	bnez      	r4, 0x24	// 24 <do_global_ctors+0x24>
  1e:	1492      	pop      	r4-r5, r15
  20:	6d0f      	mov      	r4, r3
  22:	07f7      	br      	0x10	// 10 <do_global_ctors+0x10>
  24:	d0850883 	ldr.w      	r3, (r5, r4 << 2)
  28:	7bcd      	jsr      	r3
  2a:	2c00      	subi      	r4, 1
  2c:	07f7      	br      	0x1a	// 1a <do_global_ctors+0x1a>
  2e:	0000      	.short	0x0000
  30:	00000000 	.long	0x00000000

Disassembly of section .text.do_global_dtors:

00000000 <do_global_dtors>:
   0:	14d3      	push      	r4-r6, r15
   2:	10ac      	lrw      	r5, 0x0	// 30 <do_global_dtors+0x30>
   4:	3300      	movi      	r3, 0
   6:	9580      	ld.w      	r4, (r5, 0x0)
   8:	2b00      	subi      	r3, 1
   a:	64d2      	cmpne      	r4, r3
   c:	0807      	bt      	0x1a	// 1a <do_global_dtors+0x1a>
   e:	3400      	movi      	r4, 0
  10:	5c62      	addi      	r3, r4, 1
  12:	d0650882 	ldr.w      	r2, (r5, r3 << 2)
  16:	e9220006 	bnez      	r2, 0x22	// 22 <do_global_dtors+0x22>
  1a:	3601      	movi      	r6, 1
  1c:	6590      	cmphs      	r4, r6
  1e:	0804      	bt      	0x26	// 26 <do_global_dtors+0x26>
  20:	1493      	pop      	r4-r6, r15
  22:	6d0f      	mov      	r4, r3
  24:	07f6      	br      	0x10	// 10 <do_global_dtors+0x10>
  26:	d0c50883 	ldr.w      	r3, (r5, r6 << 2)
  2a:	7bcd      	jsr      	r3
  2c:	2600      	addi      	r6, 1
  2e:	07f7      	br      	0x1c	// 1c <do_global_dtors+0x1c>
  30:	00000000 	.long	0x00000000

Disassembly of section .text.module_version_show:

00000000 <module_version_show>:
   0:	14d3      	push      	r4-r6, r15
   2:	1088      	lrw      	r4, 0x0	// 20 <module_version_show+0x20>
   4:	10a8      	lrw      	r5, 0x0	// 24 <module_version_show+0x24>
   6:	10c9      	lrw      	r6, 0x0	// 28 <module_version_show+0x28>
   8:	6550      	cmphs      	r4, r5
   a:	0c05      	bf      	0x14	// 14 <module_version_show+0x14>
   c:	1008      	lrw      	r0, 0x0	// 2c <module_version_show+0x2c>
   e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  12:	1493      	pop      	r4-r6, r15
  14:	9420      	ld.w      	r1, (r4, 0x0)
  16:	6c1b      	mov      	r0, r6
  18:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  1c:	2403      	addi      	r4, 4
  1e:	07f5      	br      	0x8	// 8 <module_version_show+0x8>
	...
