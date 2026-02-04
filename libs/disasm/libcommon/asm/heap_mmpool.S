
disasm/libcommon/obj/heap_mmpool.o:     file format elf32-csky-little


Disassembly of section .text.list_del:

00000000 <list_del>:
   0:	9061      	ld.w      	r3, (r0, 0x4)
   2:	9040      	ld.w      	r2, (r0, 0x0)
   4:	e9030006 	bez      	r3, 0x10	// 10 <list_del+0x10>
   8:	e9020004 	bez      	r2, 0x10	// 10 <list_del+0x10>
   c:	b261      	st.w      	r3, (r2, 0x4)
   e:	b340      	st.w      	r2, (r3, 0x0)
  10:	3300      	movi      	r3, 0
  12:	b060      	st.w      	r3, (r0, 0x0)
  14:	b061      	st.w      	r3, (r0, 0x4)
  16:	783c      	jmp      	r15

Disassembly of section .text.mmpool_valid_addr:

00000000 <mmpool_valid_addr>:
   0:	8064      	ld.b      	r3, (r0, 0x4)
   2:	e463200f 	andi      	r3, r3, 15
   6:	2007      	addi      	r0, 8
   8:	3200      	movi      	r2, 0
   a:	64c9      	cmplt      	r2, r3
   c:	0803      	bt      	0x12	// 12 <mmpool_valid_addr+0x12>
   e:	3000      	movi      	r0, 0
  10:	783c      	jmp      	r15
  12:	d9802000 	ld.w      	r12, (r0, 0x0)
  16:	6704      	cmphs      	r1, r12
  18:	0c05      	bf      	0x22	// 22 <mmpool_valid_addr+0x22>
  1a:	d9802001 	ld.w      	r12, (r0, 0x4)
  1e:	6704      	cmphs      	r1, r12
  20:	0c04      	bf      	0x28	// 28 <mmpool_valid_addr+0x28>
  22:	2200      	addi      	r2, 1
  24:	2007      	addi      	r0, 8
  26:	07f2      	br      	0xa	// a <mmpool_valid_addr+0xa>
  28:	3001      	movi      	r0, 1
  2a:	07f3      	br      	0x10	// 10 <mmpool_valid_addr+0x10>

Disassembly of section .text.mmpool_alloc:

00000000 <mmpool_alloc>:
   0:	14d7      	push      	r4-r10, r15
   2:	d9800005 	ld.b      	r12, (r0, 0x5)
   6:	6e4f      	mov      	r9, r3
   8:	9061      	ld.w      	r3, (r0, 0x4)
   a:	c5e35643 	zext      	r3, r3, 18, 15
   e:	c42c54cc 	zext      	r12, r12, 6, 1
  12:	630c      	addu      	r12, r3
  14:	6070      	addu      	r1, r12
  16:	6d43      	mov      	r5, r0
  18:	6e0b      	mov      	r8, r2
  1a:	8802      	ld.h      	r0, (r0, 0x4)
  1c:	392b      	cmplti      	r1, 12
  1e:	320c      	movi      	r2, 12
  20:	c4805500 	zext      	r0, r0, 8, 4
  24:	c4220c40 	inct      	r1, r2, 0
  28:	59c0      	addu      	r6, r1, r0
  2a:	3300      	movi      	r3, 0
  2c:	60c2      	subu      	r3, r0
  2e:	2e00      	subi      	r6, 1
  30:	698c      	and      	r6, r3
  32:	c0006027 	mfcr      	r7, cr<0, 0>
  36:	c0807020 	psrclr      	ie
  3a:	e4e72040 	andi      	r7, r7, 64
  3e:	9586      	ld.w      	r4, (r5, 0x18)
  40:	e4450017 	addi      	r2, r5, 24
  44:	6492      	cmpne      	r4, r2
  46:	080b      	bt      	0x5c	// 5c <mmpool_alloc+0x5c>
  48:	e9070008 	bez      	r7, 0x58	// 58 <mmpool_alloc+0x58>
  4c:	ea0a0000 	movi      	r10, 0
  50:	c0807420 	psrset      	ie
  54:	e92a0059 	bnez      	r10, 0x106	// 106 <mmpool_alloc+0x106>
  58:	3000      	movi      	r0, 0
  5a:	1497      	pop      	r4-r10, r15
  5c:	d9442002 	ld.w      	r10, (r4, 0x8)
  60:	65a8      	cmphs      	r10, r6
  62:	0c5c      	bf      	0x11a	// 11a <mmpool_alloc+0x11a>
  64:	eb2c000b 	cmplti      	r12, 12
  68:	310c      	movi      	r1, 12
  6a:	c42c0c20 	incf      	r1, r12, 0
  6e:	6040      	addu      	r1, r0
  70:	2102      	addi      	r1, 3
  72:	c4ca0082 	subu      	r2, r10, r6
  76:	684c      	and      	r1, r3
  78:	6448      	cmphs      	r2, r1
  7a:	0c4b      	bf      	0x110	// 110 <mmpool_alloc+0x110>
  7c:	5c78      	addu      	r3, r4, r6
  7e:	b342      	st.w      	r2, (r3, 0x8)
  80:	9440      	ld.w      	r2, (r4, 0x0)
  82:	b340      	st.w      	r2, (r3, 0x0)
  84:	9441      	ld.w      	r2, (r4, 0x4)
  86:	b341      	st.w      	r2, (r3, 0x4)
  88:	9441      	ld.w      	r2, (r4, 0x4)
  8a:	b260      	st.w      	r3, (r2, 0x0)
  8c:	9440      	ld.w      	r2, (r4, 0x0)
  8e:	b261      	st.w      	r3, (r2, 0x4)
  90:	b4c0      	st.w      	r6, (r4, 0x0)
  92:	8526      	ld.b      	r1, (r5, 0x6)
  94:	e4612078 	andi      	r3, r1, 120
  98:	6e93      	mov      	r10, r4
  9a:	e9030023 	bez      	r3, 0xe0	// e0 <mmpool_alloc+0xe0>
  9e:	c46154c1 	zext      	r1, r1, 6, 3
  a2:	9568      	ld.w      	r3, (r5, 0x20)
  a4:	6050      	addu      	r1, r4
  a6:	b321      	st.w      	r1, (r3, 0x4)
  a8:	b160      	st.w      	r3, (r1, 0x0)
  aa:	e465001f 	addi      	r3, r5, 32
  ae:	b161      	st.w      	r3, (r1, 0x4)
  b0:	8566      	ld.b      	r3, (r5, 0x6)
  b2:	c46354c3 	zext      	r3, r3, 6, 3
  b6:	60d0      	addu      	r3, r4
  b8:	b528      	st.w      	r1, (r5, 0x20)
  ba:	dd032002 	st.w      	r8, (r3, 0x8)
  be:	8566      	ld.b      	r3, (r5, 0x6)
  c0:	c46354c3 	zext      	r3, r3, 6, 3
  c4:	60d0      	addu      	r3, r4
  c6:	dd232003 	st.w      	r9, (r3, 0xc)
  ca:	d9050006 	ld.b      	r8, (r5, 0x6)
  ce:	c46854c8 	zext      	r8, r8, 6, 3
  d2:	e508000f 	addi      	r8, r8, 16
  d6:	6210      	addu      	r8, r4
  d8:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  dc:	dc082000 	st.w      	r0, (r8, 0x0)
  e0:	8d63      	ld.h      	r3, (r5, 0x6)
  e2:	e4432780 	andi      	r2, r3, 1920
  e6:	e902000e 	bez      	r2, 0x102	// 102 <mmpool_alloc+0x102>
  ea:	c4e35543 	zext      	r3, r3, 10, 7
  ee:	104d      	lrw      	r2, 0x695abeaf	// 120 <mmpool_alloc+0x120>
  f0:	d4640822 	str.w      	r2, (r4, r3 << 0)
  f4:	9561      	ld.w      	r3, (r5, 0x4)
  f6:	c5e35643 	zext      	r3, r3, 18, 15
  fa:	610e      	subu      	r4, r3
  fc:	106a      	lrw      	r3, 0xfaeba596	// 124 <mmpool_alloc+0x124>
  fe:	d4c40823 	str.w      	r3, (r4, r6 << 0)
 102:	e927ffa7 	bnez      	r7, 0x50	// 50 <mmpool_alloc+0x50>
 106:	8505      	ld.b      	r0, (r5, 0x5)
 108:	c42054c0 	zext      	r0, r0, 6, 1
 10c:	6028      	addu      	r0, r10
 10e:	07a6      	br      	0x5a	// 5a <mmpool_alloc+0x5a>
 110:	6c13      	mov      	r0, r4
 112:	e0000000 	bsr      	0x0	// 0 <mmpool_alloc>
 116:	6dab      	mov      	r6, r10
 118:	07bc      	br      	0x90	// 90 <mmpool_alloc+0x90>
 11a:	9480      	ld.w      	r4, (r4, 0x0)
 11c:	0794      	br      	0x44	// 44 <mmpool_alloc+0x44>
 11e:	0000      	.short	0x0000
 120:	695abeaf 	.long	0x695abeaf
 124:	faeba596 	.long	0xfaeba596

Disassembly of section .text.mmpool_free:

00000000 <mmpool_free>:
   0:	14d5      	push      	r4-r8, r15
   2:	6d43      	mov      	r5, r0
   4:	6d07      	mov      	r4, r1
   6:	e0000000 	bsr      	0x0	// 0 <mmpool_free>
   a:	e9200008 	bnez      	r0, 0x1a	// 1a <mmpool_free+0x1a>
   e:	6c93      	mov      	r2, r4
  10:	6c57      	mov      	r1, r5
  12:	111e      	lrw      	r0, 0x0	// 108 <mmpool_free+0x108>
  14:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  18:	1495      	pop      	r4-r8, r15
  1a:	8565      	ld.b      	r3, (r5, 0x5)
  1c:	c42354c3 	zext      	r3, r3, 6, 1
  20:	610e      	subu      	r4, r3
  22:	8d63      	ld.h      	r3, (r5, 0x6)
  24:	e4432780 	andi      	r2, r3, 1920
  28:	94c0      	ld.w      	r6, (r4, 0x0)
  2a:	e902002c 	bez      	r2, 0x82	// 82 <mmpool_free+0x82>
  2e:	c4e35543 	zext      	r3, r3, 10, 7
  32:	d0830822 	ldr.w      	r2, (r3, r4 << 0)
  36:	1176      	lrw      	r3, 0x695abeaf	// 10c <mmpool_free+0x10c>
  38:	64ca      	cmpne      	r2, r3
  3a:	0c06      	bf      	0x46	// 46 <mmpool_free+0x46>
  3c:	1155      	lrw      	r2, 0x0	// 110 <mmpool_free+0x110>
  3e:	316c      	movi      	r1, 108
  40:	1115      	lrw      	r0, 0x0	// 114 <mmpool_free+0x114>
  42:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  46:	9561      	ld.w      	r3, (r5, 0x4)
  48:	c5e35643 	zext      	r3, r3, 18, 15
  4c:	5c6d      	subu      	r3, r4, r3
  4e:	d0c30822 	ldr.w      	r2, (r3, r6 << 0)
  52:	1172      	lrw      	r3, 0xfaeba596	// 118 <mmpool_free+0x118>
  54:	64ca      	cmpne      	r2, r3
  56:	0c06      	bf      	0x62	// 62 <mmpool_free+0x62>
  58:	1151      	lrw      	r2, 0x0	// 11c <mmpool_free+0x11c>
  5a:	316c      	movi      	r1, 108
  5c:	110e      	lrw      	r0, 0x0	// 114 <mmpool_free+0x114>
  5e:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  62:	8d63      	ld.h      	r3, (r5, 0x6)
  64:	e4432780 	andi      	r2, r3, 1920
  68:	e902000d 	bez      	r2, 0x82	// 82 <mmpool_free+0x82>
  6c:	c4e35543 	zext      	r3, r3, 10, 7
  70:	3200      	movi      	r2, 0
  72:	d4830822 	str.w      	r2, (r3, r4 << 0)
  76:	9561      	ld.w      	r3, (r5, 0x4)
  78:	c5e35643 	zext      	r3, r3, 18, 15
  7c:	5c6d      	subu      	r3, r4, r3
  7e:	d4c30822 	str.w      	r2, (r3, r6 << 0)
  82:	c0006027 	mfcr      	r7, cr<0, 0>
  86:	c0807020 	psrclr      	ie
  8a:	8506      	ld.b      	r0, (r5, 0x6)
  8c:	e4602078 	andi      	r3, r0, 120
  90:	e4e72040 	andi      	r7, r7, 64
  94:	e9030007 	bez      	r3, 0xa2	// a2 <mmpool_free+0xa2>
  98:	c46054c0 	zext      	r0, r0, 6, 3
  9c:	6010      	addu      	r0, r4
  9e:	e0000000 	bsr      	0x0	// 0 <mmpool_free>
  a2:	b4c2      	st.w      	r6, (r4, 0x8)
  a4:	9566      	ld.w      	r3, (r5, 0x18)
  a6:	e5050017 	addi      	r8, r5, 24
  aa:	660e      	cmpne      	r3, r8
  ac:	0808      	bt      	0xbc	// bc <mmpool_free+0xbc>
  ae:	9567      	ld.w      	r3, (r5, 0x1c)
  b0:	b587      	st.w      	r4, (r5, 0x1c)
  b2:	dd042000 	st.w      	r8, (r4, 0x0)
  b6:	b461      	st.w      	r3, (r4, 0x4)
  b8:	b380      	st.w      	r4, (r3, 0x0)
  ba:	0408      	br      	0xca	// ca <mmpool_free+0xca>
  bc:	64d0      	cmphs      	r4, r3
  be:	0823      	bt      	0x104	// 104 <mmpool_free+0x104>
  c0:	9341      	ld.w      	r2, (r3, 0x4)
  c2:	b381      	st.w      	r4, (r3, 0x4)
  c4:	b460      	st.w      	r3, (r4, 0x0)
  c6:	b441      	st.w      	r2, (r4, 0x4)
  c8:	b280      	st.w      	r4, (r2, 0x0)
  ca:	9400      	ld.w      	r0, (r4, 0x0)
  cc:	6422      	cmpne      	r8, r0
  ce:	0c09      	bf      	0xe0	// e0 <mmpool_free+0xe0>
  d0:	5c78      	addu      	r3, r4, r6
  d2:	64c2      	cmpne      	r0, r3
  d4:	0806      	bt      	0xe0	// e0 <mmpool_free+0xe0>
  d6:	9062      	ld.w      	r3, (r0, 0x8)
  d8:	618c      	addu      	r6, r3
  da:	b4c2      	st.w      	r6, (r4, 0x8)
  dc:	e0000000 	bsr      	0x0	// 0 <mmpool_free>
  e0:	9461      	ld.w      	r3, (r4, 0x4)
  e2:	64e2      	cmpne      	r8, r3
  e4:	0c0b      	bf      	0xfa	// fa <mmpool_free+0xfa>
  e6:	9322      	ld.w      	r1, (r3, 0x8)
  e8:	5b44      	addu      	r2, r3, r1
  ea:	6492      	cmpne      	r4, r2
  ec:	0807      	bt      	0xfa	// fa <mmpool_free+0xfa>
  ee:	9442      	ld.w      	r2, (r4, 0x8)
  f0:	6084      	addu      	r2, r1
  f2:	b342      	st.w      	r2, (r3, 0x8)
  f4:	6c13      	mov      	r0, r4
  f6:	e0000000 	bsr      	0x0	// 0 <mmpool_free>
  fa:	e907ff8f 	bez      	r7, 0x18	// 18 <mmpool_free+0x18>
  fe:	c0807420 	psrset      	ie
 102:	078b      	br      	0x18	// 18 <mmpool_free+0x18>
 104:	9360      	ld.w      	r3, (r3, 0x0)
 106:	07d2      	br      	0xaa	// aa <mmpool_free+0xaa>
 108:	00000000 	.long	0x00000000
 10c:	695abeaf 	.long	0x695abeaf
	...
 118:	faeba596 	.long	0xfaeba596
 11c:	0000      	.short	0x0000
	...

Disassembly of section .text.mmpool_add_region:

00000000 <mmpool_add_region>:
   0:	14c2      	push      	r4-r5
   2:	8862      	ld.h      	r3, (r0, 0x4)
   4:	c4835504 	zext      	r4, r3, 8, 4
   8:	3300      	movi      	r3, 0
   a:	5bb1      	subu      	r5, r3, r4
   c:	d9800005 	ld.b      	r12, (r0, 0x5)
  10:	9061      	ld.w      	r3, (r0, 0x4)
  12:	c42c54cc 	zext      	r12, r12, 6, 1
  16:	c5e35643 	zext      	r3, r3, 18, 15
  1a:	60f0      	addu      	r3, r12
  1c:	3b2b      	cmplti      	r3, 12
  1e:	ea0c000c 	movi      	r12, 12
  22:	c46c0c40 	inct      	r3, r12, 0
  26:	e5a11000 	subi      	r13, r1, 1
  2a:	60d0      	addu      	r3, r4
  2c:	6350      	addu      	r13, r4
  2e:	2302      	addi      	r3, 3
  30:	6b54      	and      	r13, r5
  32:	6084      	addu      	r2, r1
  34:	68d4      	and      	r3, r5
  36:	c5a20081 	subu      	r1, r2, r13
  3a:	60d0      	addu      	r3, r4
  3c:	64c4      	cmphs      	r1, r3
  3e:	0c2c      	bf      	0x96	// 96 <mmpool_add_region+0x96>
  40:	dc2d2002 	st.w      	r1, (r13, 0x8)
  44:	c000602c 	mfcr      	r12, cr<0, 0>
  48:	c0807020 	psrclr      	ie
  4c:	8064      	ld.b      	r3, (r0, 0x4)
  4e:	e463200f 	andi      	r3, r3, 15
  52:	3b23      	cmplti      	r3, 4
  54:	e58c2040 	andi      	r12, r12, 64
  58:	0c0b      	bf      	0x6e	// 6e <mmpool_add_region+0x6e>
  5a:	5b82      	addi      	r4, r3, 1
  5c:	4363      	lsli      	r3, r3, 3
  5e:	60c0      	addu      	r3, r0
  60:	d480090d 	str.w      	r13, (r0, r4 << 3)
  64:	b343      	st.w      	r2, (r3, 0xc)
  66:	8064      	ld.b      	r3, (r0, 0x4)
  68:	c4645c60 	ins      	r3, r4, 3, 0
  6c:	a064      	st.b      	r3, (r0, 0x4)
  6e:	9060      	ld.w      	r3, (r0, 0x0)
  70:	604c      	addu      	r1, r3
  72:	9066      	ld.w      	r3, (r0, 0x18)
  74:	b020      	st.w      	r1, (r0, 0x0)
  76:	dda32001 	st.w      	r13, (r3, 0x4)
  7a:	dc6d2000 	st.w      	r3, (r13, 0x0)
  7e:	e4600017 	addi      	r3, r0, 24
  82:	dc6d2001 	st.w      	r3, (r13, 0x4)
  86:	dda02006 	st.w      	r13, (r0, 0x18)
  8a:	e90c0009 	bez      	r12, 0x9c	// 9c <mmpool_add_region+0x9c>
  8e:	c0807420 	psrset      	ie
  92:	3000      	movi      	r0, 0
  94:	1482      	pop      	r4-r5
  96:	3000      	movi      	r0, 0
  98:	2800      	subi      	r0, 1
  9a:	07fd      	br      	0x94	// 94 <mmpool_add_region+0x94>
  9c:	6c33      	mov      	r0, r12
  9e:	07fb      	br      	0x94	// 94 <mmpool_add_region+0x94>

Disassembly of section .text.mmpool_init:

00000000 <mmpool_init>:
   0:	14d1      	push      	r4, r15
   2:	8862      	ld.h      	r3, (r0, 0x4)
   4:	e58321f0 	andi      	r12, r3, 496
   8:	e92c0007 	bnez      	r12, 0x16	// 16 <mmpool_init+0x16>
   c:	ea0c0004 	movi      	r12, 4
  10:	c46c5c84 	ins      	r3, r12, 8, 4
  14:	a862      	st.h      	r3, (r0, 0x4)
  16:	d9a01002 	ld.h      	r13, (r0, 0x4)
  1a:	d9800005 	ld.b      	r12, (r0, 0x5)
  1e:	c48d550d 	zext      	r13, r13, 8, 4
  22:	c42c54c4 	zext      	r4, r12, 6, 1
  26:	74f4      	zextb      	r3, r13
  28:	60d0      	addu      	r3, r4
  2a:	3400      	movi      	r4, 0
  2c:	c5a4008d 	subu      	r13, r4, r13
  30:	2b00      	subi      	r3, 1
  32:	68f4      	and      	r3, r13
  34:	c5835ca1 	ins      	r12, r3, 6, 1
  38:	e4600017 	addi      	r3, r0, 24
  3c:	b066      	st.w      	r3, (r0, 0x18)
  3e:	b067      	st.w      	r3, (r0, 0x1c)
  40:	e460001f 	addi      	r3, r0, 32
  44:	dd800005 	st.b      	r12, (r0, 0x5)
  48:	b068      	st.w      	r3, (r0, 0x20)
  4a:	b069      	st.w      	r3, (r0, 0x24)
  4c:	e0000000 	bsr      	0x0	// 0 <mmpool_init>
  50:	1491      	pop      	r4, r15

Disassembly of section .text.mmpool_free_size:

00000000 <mmpool_free_size>:
   0:	14c1      	push      	r4
   2:	c0006023 	mfcr      	r3, cr<0, 0>
   6:	c0807020 	psrclr      	ie
   a:	3200      	movi      	r2, 0
   c:	d9802006 	ld.w      	r12, (r0, 0x18)
  10:	e4632040 	andi      	r3, r3, 64
  14:	2017      	addi      	r0, 24
  16:	6432      	cmpne      	r12, r0
  18:	0807      	bt      	0x26	// 26 <mmpool_free_size+0x26>
  1a:	e9030004 	bez      	r3, 0x22	// 22 <mmpool_free_size+0x22>
  1e:	c0807420 	psrset      	ie
  22:	6c0b      	mov      	r0, r2
  24:	1481      	pop      	r4
  26:	d9ac2002 	ld.w      	r13, (r12, 0x8)
  2a:	c5a20024 	addu      	r4, r2, r13
  2e:	6474      	cmphs      	r13, r1
  30:	c4440c40 	inct      	r2, r4, 0
  34:	d98c2000 	ld.w      	r12, (r12, 0x0)
  38:	07ef      	br      	0x16	// 16 <mmpool_free_size+0x16>

Disassembly of section .text.mmpool_free_state:

00000000 <mmpool_free_state>:
   0:	14c3      	push      	r4-r6
   2:	e901002d 	bez      	r1, 0x5c	// 5c <mmpool_free_state+0x5c>
   6:	3a21      	cmplti      	r2, 2
   8:	082a      	bt      	0x5c	// 5c <mmpool_free_state+0x5c>
   a:	c0006024 	mfcr      	r4, cr<0, 0>
   e:	c0807020 	psrclr      	ie
  12:	ea0c0000 	movi      	r12, 0
  16:	d9a02006 	ld.w      	r13, (r0, 0x18)
  1a:	e4842040 	andi      	r4, r4, 64
  1e:	2017      	addi      	r0, 24
  20:	6436      	cmpne      	r13, r0
  22:	0807      	bt      	0x30	// 30 <mmpool_free_state+0x30>
  24:	e9040004 	bez      	r4, 0x2c	// 2c <mmpool_free_state+0x2c>
  28:	c0807420 	psrset      	ie
  2c:	6c33      	mov      	r0, r12
  2e:	1483      	pop      	r4-r6
  30:	93a0      	ld.w      	r5, (r3, 0x0)
  32:	d8cd2002 	ld.w      	r6, (r13, 0x8)
  36:	6158      	addu      	r5, r6
  38:	b3a0      	st.w      	r5, (r3, 0x0)
  3a:	e4ac0000 	addi      	r5, r12, 1
  3e:	6495      	cmplt      	r5, r2
  40:	0c0b      	bf      	0x56	// 56 <mmpool_free_state+0x56>
  42:	c44c4825 	lsli      	r5, r12, 2
  46:	d581088d 	str.w      	r13, (r1, r12 << 2)
  4a:	6144      	addu      	r5, r1
  4c:	d8cd2002 	ld.w      	r6, (r13, 0x8)
  50:	e58c0001 	addi      	r12, r12, 2
  54:	b5c1      	st.w      	r6, (r5, 0x4)
  56:	d9ad2000 	ld.w      	r13, (r13, 0x0)
  5a:	07e3      	br      	0x20	// 20 <mmpool_free_state+0x20>
  5c:	ea0c0000 	movi      	r12, 0
  60:	07e6      	br      	0x2c	// 2c <mmpool_free_state+0x2c>

Disassembly of section .text.mmpool_of_check:

00000000 <mmpool_of_check>:
   0:	14d4      	push      	r4-r7, r15
   2:	8086      	ld.b      	r4, (r0, 0x6)
   4:	e4642078 	andi      	r3, r4, 120
   8:	6dc3      	mov      	r7, r0
   a:	6d47      	mov      	r5, r1
   c:	6d8b      	mov      	r6, r2
   e:	e9030028 	bez      	r3, 0x5e	// 5e <mmpool_of_check+0x5e>
  12:	e0000000 	bsr      	0x0	// 0 <mmpool_of_check>
  16:	e9000026 	bez      	r0, 0x62	// 62 <mmpool_of_check+0x62>
  1a:	c000602c 	mfcr      	r12, cr<0, 0>
  1e:	c0807020 	psrclr      	ie
  22:	e447001f 	addi      	r2, r7, 32
  26:	9728      	ld.w      	r1, (r7, 0x20)
  28:	644a      	cmpne      	r2, r1
  2a:	e58c2040 	andi      	r12, r12, 64
  2e:	0c16      	bf      	0x5a	// 5a <mmpool_of_check+0x5a>
  30:	c46454c4 	zext      	r4, r4, 6, 3
  34:	5971      	subu      	r3, r1, r4
  36:	654c      	cmphs      	r3, r5
  38:	080e      	bt      	0x54	// 54 <mmpool_of_check+0x54>
  3a:	9300      	ld.w      	r0, (r3, 0x0)
  3c:	60c0      	addu      	r3, r0
  3e:	654c      	cmphs      	r3, r5
  40:	0c0a      	bf      	0x54	// 54 <mmpool_of_check+0x54>
  42:	6158      	addu      	r5, r6
  44:	654c      	cmphs      	r3, r5
  46:	c4000500 	mvc      	r0
  4a:	e90c0004 	bez      	r12, 0x52	// 52 <mmpool_of_check+0x52>
  4e:	c0807420 	psrset      	ie
  52:	1494      	pop      	r4-r7, r15
  54:	9120      	ld.w      	r1, (r1, 0x0)
  56:	644a      	cmpne      	r2, r1
  58:	0bee      	bt      	0x34	// 34 <mmpool_of_check+0x34>
  5a:	3000      	movi      	r0, 0
  5c:	07f7      	br      	0x4a	// 4a <mmpool_of_check+0x4a>
  5e:	3001      	movi      	r0, 1
  60:	07f9      	br      	0x52	// 52 <mmpool_of_check+0x52>
  62:	3000      	movi      	r0, 0
  64:	2800      	subi      	r0, 1
  66:	07f6      	br      	0x52	// 52 <mmpool_of_check+0x52>

Disassembly of section .text.mmpool_used_state:

00000000 <mmpool_used_state>:
   0:	14c6      	push      	r4-r9
   2:	6f43      	mov      	r13, r0
   4:	9806      	ld.w      	r0, (r14, 0x18)
   6:	6e43      	mov      	r9, r0
   8:	e9010054 	bez      	r1, 0xb0	// b0 <mmpool_used_state+0xb0>
   c:	3a24      	cmplti      	r2, 5
   e:	0851      	bt      	0xb0	// b0 <mmpool_used_state+0xb0>
  10:	d80d0006 	ld.b      	r0, (r13, 0x6)
  14:	e4002078 	andi      	r0, r0, 120
  18:	e900004b 	bez      	r0, 0xae	// ae <mmpool_used_state+0xae>
  1c:	c0006025 	mfcr      	r5, cr<0, 0>
  20:	c0807020 	psrclr      	ie
  24:	3000      	movi      	r0, 0
  26:	e4a52040 	andi      	r5, r5, 64
  2a:	e50d001f 	addi      	r8, r13, 32
  2e:	d8cd2008 	ld.w      	r6, (r13, 0x20)
  32:	65a2      	cmpne      	r8, r6
  34:	0c39      	bf      	0xa6	// a6 <mmpool_used_state+0xa6>
  36:	d98d0006 	ld.b      	r12, (r13, 0x6)
  3a:	c46c54cc 	zext      	r12, r12, 6, 3
  3e:	c586008c 	subu      	r12, r6, r12
  42:	9380      	ld.w      	r4, (r3, 0x0)
  44:	d8ec2000 	ld.w      	r7, (r12, 0x0)
  48:	611c      	addu      	r4, r7
  4a:	b380      	st.w      	r4, (r3, 0x0)
  4c:	588e      	addi      	r4, r0, 4
  4e:	6491      	cmplt      	r4, r2
  50:	0c29      	bf      	0xa2	// a2 <mmpool_used_state+0xa2>
  52:	d88c2000 	ld.w      	r4, (r12, 0x0)
  56:	6650      	cmphs      	r4, r9
  58:	6de7      	mov      	r7, r9
  5a:	0c24      	bf      	0xa2	// a2 <mmpool_used_state+0xa2>
  5c:	d8ed0006 	ld.b      	r7, (r13, 0x6)
  60:	c46754c7 	zext      	r7, r7, 6, 3
  64:	61f0      	addu      	r7, r12
  66:	4082      	lsli      	r4, r0, 2
  68:	97e2      	ld.w      	r7, (r7, 0x8)
  6a:	d4010887 	str.w      	r7, (r1, r0 << 2)
  6e:	d8ed0006 	ld.b      	r7, (r13, 0x6)
  72:	c46754c7 	zext      	r7, r7, 6, 3
  76:	61f0      	addu      	r7, r12
  78:	6104      	addu      	r4, r1
  7a:	97e3      	ld.w      	r7, (r7, 0xc)
  7c:	b4e1      	st.w      	r7, (r4, 0x4)
  7e:	d8ec2000 	ld.w      	r7, (r12, 0x0)
  82:	b4e2      	st.w      	r7, (r4, 0x8)
  84:	d8ed0006 	ld.b      	r7, (r13, 0x6)
  88:	c46754c7 	zext      	r7, r7, 6, 3
  8c:	61f0      	addu      	r7, r12
  8e:	2004      	addi      	r0, 5
  90:	97e4      	ld.w      	r7, (r7, 0x10)
  92:	b4e3      	st.w      	r7, (r4, 0xc)
  94:	d8ed0005 	ld.b      	r7, (r13, 0x5)
  98:	c42754c7 	zext      	r7, r7, 6, 1
  9c:	631c      	addu      	r12, r7
  9e:	dd842004 	st.w      	r12, (r4, 0x10)
  a2:	96c0      	ld.w      	r6, (r6, 0x0)
  a4:	07c7      	br      	0x32	// 32 <mmpool_used_state+0x32>
  a6:	e9050004 	bez      	r5, 0xae	// ae <mmpool_used_state+0xae>
  aa:	c0807420 	psrset      	ie
  ae:	1486      	pop      	r4-r9
  b0:	3000      	movi      	r0, 0
  b2:	07fe      	br      	0xae	// ae <mmpool_used_state+0xae>
