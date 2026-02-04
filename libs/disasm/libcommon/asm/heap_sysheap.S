
disasm/libcommon/obj/heap_sysheap.o:     file format elf32-csky-little


Disassembly of section .text.sysheap_init:

00000000 <sysheap_init>:
   0:	14d5      	push      	r4-r8, r15
   2:	58ce      	addi      	r6, r0, 4
   4:	6d03      	mov      	r4, r0
   6:	6dc7      	mov      	r7, r1
   8:	6e0b      	mov      	r8, r2
   a:	3100      	movi      	r1, 0
   c:	3228      	movi      	r2, 40
   e:	6c1b      	mov      	r0, r6
  10:	6d4f      	mov      	r5, r3
  12:	e0000000 	bsr      	0x0	// 0 <memset>
  16:	3308      	movi      	r3, 8
  18:	a469      	st.b      	r3, (r4, 0x9)
  1a:	e4652002 	andi      	r3, r5, 2
  1e:	3204      	movi      	r2, 4
  20:	b4ab      	st.w      	r5, (r4, 0x2c)
  22:	e903000f 	bez      	r3, 0x40	// 40 <sysheap_init+0x40>
  26:	8c65      	ld.h      	r3, (r4, 0xa)
  28:	c4625c67 	ins      	r3, r2, 10, 7
  2c:	ac65      	st.h      	r3, (r4, 0xa)
  2e:	3108      	movi      	r1, 8
  30:	8469      	ld.b      	r3, (r4, 0x9)
  32:	c4615ca1 	ins      	r3, r1, 6, 1
  36:	a469      	st.b      	r3, (r4, 0x9)
  38:	9462      	ld.w      	r3, (r4, 0x8)
  3a:	c4625c6f 	ins      	r3, r2, 18, 15
  3e:	b462      	st.w      	r3, (r4, 0x8)
  40:	e4652001 	andi      	r3, r5, 1
  44:	e903000d 	bez      	r3, 0x5e	// 5e <sysheap_init+0x5e>
  48:	8469      	ld.b      	r3, (r4, 0x9)
  4a:	c42354c2 	zext      	r2, r3, 6, 1
  4e:	842a      	ld.b      	r1, (r4, 0xa)
  50:	c4225c63 	ins      	r1, r2, 6, 3
  54:	2213      	addi      	r2, 20
  56:	c4625ca1 	ins      	r3, r2, 6, 1
  5a:	a42a      	st.b      	r1, (r4, 0xa)
  5c:	a469      	st.b      	r3, (r4, 0x9)
  5e:	e4a52004 	andi      	r5, r5, 4
  62:	e9050007 	bez      	r5, 0x70	// 70 <sysheap_init+0x70>
  66:	8c64      	ld.h      	r3, (r4, 0x8)
  68:	3210      	movi      	r2, 16
  6a:	c4625c84 	ins      	r3, r2, 8, 4
  6e:	ac64      	st.h      	r3, (r4, 0x8)
  70:	6ca3      	mov      	r2, r8
  72:	6c5f      	mov      	r1, r7
  74:	6c1b      	mov      	r0, r6
  76:	e0000000 	bsr      	0x0	// 0 <mmpool_init>
  7a:	1495      	pop      	r4-r8, r15

Disassembly of section .text.sysheap_alloc:

00000000 <sysheap_alloc>:
   0:	14d0      	push      	r15
   2:	2003      	addi      	r0, 4
   4:	e0000000 	bsr      	0x0	// 0 <mmpool_alloc>
   8:	1490      	pop      	r15

Disassembly of section .text.sysheap_free:

00000000 <sysheap_free>:
   0:	14d0      	push      	r15
   2:	e9010005 	bez      	r1, 0xc	// c <sysheap_free+0xc>
   6:	2003      	addi      	r0, 4
   8:	e0000000 	bsr      	0x0	// 0 <mmpool_free>
   c:	1490      	pop      	r15

Disassembly of section .text.sysheap_add:

00000000 <sysheap_add>:
   0:	14d0      	push      	r15
   2:	2003      	addi      	r0, 4
   4:	e0000000 	bsr      	0x0	// 0 <mmpool_add_region>
   8:	1490      	pop      	r15

Disassembly of section .text.sysheap_collect_init:

00000000 <sysheap_collect_init>:
   0:	14d0      	push      	r15
   2:	6086      	subu      	r2, r1
   4:	e0000000 	bsr      	0x0	// 0 <sysheap_collect_init>
   8:	1490      	pop      	r15

Disassembly of section .text.sysheap_freesize:

00000000 <sysheap_freesize>:
   0:	14d0      	push      	r15
   2:	2003      	addi      	r0, 4
   4:	3100      	movi      	r1, 0
   6:	e0000000 	bsr      	0x0	// 0 <mmpool_free_size>
   a:	1490      	pop      	r15

Disassembly of section .text.sysheap_totalsize:

00000000 <sysheap_totalsize>:
   0:	9001      	ld.w      	r0, (r0, 0x4)
   2:	783c      	jmp      	r15

Disassembly of section .text.sysheap_of_check:

00000000 <sysheap_of_check>:
   0:	14d0      	push      	r15
   2:	2003      	addi      	r0, 4
   4:	e0000000 	bsr      	0x0	// 0 <mmpool_of_check>
   8:	1490      	pop      	r15

Disassembly of section .text.sysheap_valid_addr:

00000000 <sysheap_valid_addr>:
   0:	14d0      	push      	r15
   2:	2003      	addi      	r0, 4
   4:	e0000000 	bsr      	0x0	// 0 <mmpool_valid_addr>
   8:	1490      	pop      	r15

Disassembly of section .text.sysheap_status:

00000000 <sysheap_status>:
   0:	14d8      	push      	r4-r11, r15
   2:	1425      	subi      	r14, r14, 20
   4:	3500      	movi      	r5, 0
   6:	6d83      	mov      	r6, r0
   8:	6e07      	mov      	r8, r1
   a:	6e4b      	mov      	r9, r2
   c:	6e8f      	mov      	r10, r3
   e:	b8a4      	st.w      	r5, (r14, 0x10)
  10:	58ee      	addi      	r7, r0, 4
  12:	e921000f 	bnez      	r1, 0x30	// 30 <sysheap_status+0x30>
  16:	9080      	ld.w      	r4, (r0, 0x0)
  18:	90a1      	ld.w      	r5, (r0, 0x4)
  1a:	6c1f      	mov      	r0, r7
  1c:	e0000000 	bsr      	0x0	// 0 <mmpool_free_size>
  20:	6cc3      	mov      	r3, r0
  22:	6c97      	mov      	r2, r5
  24:	6c53      	mov      	r1, r4
  26:	1203      	lrw      	r0, 0x0	// 130 <sysheap_status+0x130>
  28:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  2c:	1405      	addi      	r14, r14, 20
  2e:	1498      	pop      	r4-r11, r15
  30:	1b04      	addi      	r3, r14, 16
  32:	6c1f      	mov      	r0, r7
  34:	e0000000 	bsr      	0x0	// 0 <mmpool_free_state>
  38:	6ec3      	mov      	r11, r0
  3a:	111f      	lrw      	r0, 0x0	// 134 <sysheap_status+0x134>
  3c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  40:	c7eb4843 	lsri      	r3, r11, 31
  44:	60ec      	addu      	r3, r11
  46:	5361      	asri      	r3, r3, 1
  48:	6c9f      	mov      	r2, r7
  4a:	9620      	ld.w      	r1, (r6, 0x0)
  4c:	6d23      	mov      	r4, r8
  4e:	111b      	lrw      	r0, 0x0	// 138 <sysheap_status+0x138>
  50:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  54:	6f23      	mov      	r12, r8
  56:	ea8d003a 	lrw      	r13, 0x0	// 13c <sysheap_status+0x13c>
  5a:	66d5      	cmplt      	r5, r11
  5c:	0831      	bt      	0xbe	// be <sysheap_status+0xbe>
  5e:	9824      	ld.w      	r1, (r14, 0x10)
  60:	1118      	lrw      	r0, 0x0	// 140 <sysheap_status+0x140>
  62:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  66:	1114      	lrw      	r0, 0x0	// 134 <hgprintf+0x134>
  68:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  6c:	966b      	ld.w      	r3, (r6, 0x2c)
  6e:	e4632001 	andi      	r3, r3, 1
  72:	e9030021 	bez      	r3, 0xb4	// b4 <sysheap_status+0xb4>
  76:	6ca7      	mov      	r2, r9
  78:	6c63      	mov      	r1, r8
  7a:	1b04      	addi      	r3, r14, 16
  7c:	6c1f      	mov      	r0, r7
  7e:	3500      	movi      	r5, 0
  80:	dd4e2000 	st.w      	r10, (r14, 0x0)
  84:	b8a4      	st.w      	r5, (r14, 0x10)
  86:	e0000000 	bsr      	0x0	// 0 <mmpool_used_state>
  8a:	3205      	movi      	r2, 5
  8c:	c4408042 	divs      	r2, r0, r2
  90:	6dc3      	mov      	r7, r0
  92:	9620      	ld.w      	r1, (r6, 0x0)
  94:	110c      	lrw      	r0, 0x0	// 144 <sysheap_status+0x144>
  96:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  9a:	ea88002c 	lrw      	r8, 0x0	// 148 <sysheap_status+0x148>
  9e:	ea89002c 	lrw      	r9, 0x0	// 14c <sysheap_status+0x14c>
  a2:	65d5      	cmplt      	r5, r7
  a4:	082e      	bt      	0x100	// 100 <sysheap_status+0x100>
  a6:	110b      	lrw      	r0, 0x0	// 150 <sysheap_status+0x150>
  a8:	9824      	ld.w      	r1, (r14, 0x10)
  aa:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ae:	1102      	lrw      	r0, 0x0	// 134 <hgprintf+0x134>
  b0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  b4:	9621      	ld.w      	r1, (r6, 0x4)
  b6:	1108      	lrw      	r0, 0x0	// 154 <sysheap_status+0x154>
  b8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  bc:	07b8      	br      	0x2c	// 2c <sysheap_status+0x2c>
  be:	d86c2001 	ld.w      	r3, (r12, 0x4)
  c2:	6c8f      	mov      	r2, r3
  c4:	3000      	movi      	r0, 0
  c6:	4a41      	lsri      	r2, r2, 1
  c8:	e922001a 	bnez      	r2, 0xfc	// fc <sysheap_status+0xfc>
  cc:	4d3f      	lsri      	r1, r5, 31
  ce:	6054      	addu      	r1, r5
  d0:	d84c2000 	ld.w      	r2, (r12, 0x0)
  d4:	5121      	asri      	r1, r1, 1
  d6:	b801      	st.w      	r0, (r14, 0x4)
  d8:	b860      	st.w      	r3, (r14, 0x0)
  da:	6c37      	mov      	r0, r13
  dc:	60c8      	addu      	r3, r2
  de:	2100      	addi      	r1, 1
  e0:	dd8e2003 	st.w      	r12, (r14, 0xc)
  e4:	ddae2002 	st.w      	r13, (r14, 0x8)
  e8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ec:	d98e2003 	ld.w      	r12, (r14, 0xc)
  f0:	2501      	addi      	r5, 2
  f2:	e58c0007 	addi      	r12, r12, 8
  f6:	d9ae2002 	ld.w      	r13, (r14, 0x8)
  fa:	07b0      	br      	0x5a	// 5a <sysheap_status+0x5a>
  fc:	2000      	addi      	r0, 1
  fe:	07e4      	br      	0xc6	// c6 <sysheap_status+0xc6>
 100:	9401      	ld.w      	r0, (r4, 0x4)
 102:	9442      	ld.w      	r2, (r4, 0x8)
 104:	9424      	ld.w      	r1, (r4, 0x10)
 106:	e900000e 	bez      	r0, 0x122	// 122 <sysheap_status+0x122>
 10a:	b821      	st.w      	r1, (r14, 0x4)
 10c:	9463      	ld.w      	r3, (r4, 0xc)
 10e:	b860      	st.w      	r3, (r14, 0x0)
 110:	9420      	ld.w      	r1, (r4, 0x0)
 112:	6ccb      	mov      	r3, r2
 114:	6c83      	mov      	r2, r0
 116:	6c27      	mov      	r0, r9
 118:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 11c:	2504      	addi      	r5, 5
 11e:	2413      	addi      	r4, 20
 120:	07c1      	br      	0xa2	// a2 <sysheap_status+0xa2>
 122:	9463      	ld.w      	r3, (r4, 0xc)
 124:	b820      	st.w      	r1, (r14, 0x0)
 126:	9420      	ld.w      	r1, (r4, 0x0)
 128:	6c23      	mov      	r0, r8
 12a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 12e:	07f7      	br      	0x11c	// 11c <sysheap_status+0x11c>
	...
