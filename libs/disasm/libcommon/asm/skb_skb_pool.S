
disasm/libcommon/obj/skb_skb_pool.o:     file format elf32-csky-little


Disassembly of section .text.skbpool_alloc:

00000000 <skbpool_alloc>:
   0:	14d5      	push      	r4-r8, r15
   2:	10be      	lrw      	r5, 0x0	// 78 <skbpool_alloc+0x78>
   4:	3940      	cmpnei      	r1, 0
   6:	5dce      	addi      	r6, r5, 4
   8:	c4c50c40 	inct      	r6, r5, 0
   c:	6e03      	mov      	r8, r0
   e:	6dc7      	mov      	r7, r1
  10:	9600      	ld.w      	r0, (r6, 0x0)
  12:	9523      	ld.w      	r1, (r5, 0xc)
  14:	6404      	cmphs      	r1, r0
  16:	2d27      	subi      	r5, 40
  18:	0c2e      	bf      	0x74	// 74 <skbpool_alloc+0x74>
  1a:	e4280047 	addi      	r1, r8, 72
  1e:	6c17      	mov      	r0, r5
  20:	e0000000 	bsr      	0x0	// 0 <mmpool_alloc>
  24:	6d03      	mov      	r4, r0
  26:	e9000025 	bez      	r0, 0x70	// 70 <skbpool_alloc+0x70>
  2a:	3248      	movi      	r2, 72
  2c:	3100      	movi      	r1, 0
  2e:	e0000000 	bsr      	0x0	// 0 <memset>
  32:	d864002b 	ld.b      	r3, (r4, 0x2b)
  36:	e4040047 	addi      	r0, r4, 72
  3a:	c4675c02 	ins      	r3, r7, 2, 2
  3e:	b408      	st.w      	r0, (r4, 0x20)
  40:	b407      	st.w      	r0, (r4, 0x1c)
  42:	b406      	st.w      	r0, (r4, 0x18)
  44:	dc64002b 	st.b      	r3, (r4, 0x2b)
  48:	6020      	addu      	r0, r8
  4a:	106d      	lrw      	r3, 0x0	// 7c <skbpool_alloc+0x7c>
  4c:	b470      	st.w      	r3, (r4, 0x40)
  4e:	b409      	st.w      	r0, (r4, 0x24)
  50:	b4b1      	st.w      	r5, (r4, 0x44)
  52:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  56:	3301      	movi      	r3, 1
  58:	b46f      	st.w      	r3, (r4, 0x3c)
  5a:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  5e:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  62:	9469      	ld.w      	r3, (r4, 0x24)
  64:	5b51      	subu      	r2, r3, r4
  66:	9660      	ld.w      	r3, (r6, 0x0)
  68:	60c8      	addu      	r3, r2
  6a:	b660      	st.w      	r3, (r6, 0x0)
  6c:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  70:	6c13      	mov      	r0, r4
  72:	1495      	pop      	r4-r8, r15
  74:	3400      	movi      	r4, 0
  76:	07fd      	br      	0x70	// 70 <skbpool_alloc+0x70>
	...

Disassembly of section .text.skbpool_free:

00000000 <skbpool_free>:
   0:	14d3      	push      	r4-r6, r15
   2:	d861002b 	ld.b      	r3, (r1, 0x2b)
   6:	e4632004 	andi      	r3, r3, 4
   a:	6d83      	mov      	r6, r0
   c:	6d07      	mov      	r4, r1
   e:	e903001a 	bez      	r3, 0x42	// 42 <skbpool_free+0x42>
  12:	e4a00027 	addi      	r5, r0, 40
  16:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  1a:	9469      	ld.w      	r3, (r4, 0x24)
  1c:	9540      	ld.w      	r2, (r5, 0x0)
  1e:	5b31      	subu      	r1, r3, r4
  20:	6484      	cmphs      	r1, r2
  22:	0813      	bt      	0x48	// 48 <skbpool_free+0x48>
  24:	5c6d      	subu      	r3, r4, r3
  26:	60c8      	addu      	r3, r2
  28:	b560      	st.w      	r3, (r5, 0x0)
  2a:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  2e:	6c53      	mov      	r1, r4
  30:	6c1b      	mov      	r0, r6
  32:	e0000000 	bsr      	0x0	// 0 <mmpool_free>
  36:	1066      	lrw      	r3, 0x0	// 4c <skbpool_free+0x4c>
  38:	9360      	ld.w      	r3, (r3, 0x0)
  3a:	e9030003 	bez      	r3, 0x40	// 40 <skbpool_free+0x40>
  3e:	7bcd      	jsr      	r3
  40:	1493      	pop      	r4-r6, r15
  42:	e4a0002b 	addi      	r5, r0, 44
  46:	07e8      	br      	0x16	// 16 <skbpool_free+0x16>
  48:	3300      	movi      	r3, 0
  4a:	07ef      	br      	0x28	// 28 <skbpool_free+0x28>
  4c:	00000000 	.long	0x00000000

Disassembly of section .text.skbpool_init:

00000000 <skbpool_init>:
   0:	14d5      	push      	r4-r8, r15
   2:	1421      	subi      	r14, r14, 4
   4:	1096      	lrw      	r4, 0x0	// 5c <skbpool_init+0x5c>
   6:	6d83      	mov      	r6, r0
   8:	6d47      	mov      	r5, r1
   a:	6dcb      	mov      	r7, r2
   c:	3100      	movi      	r1, 0
   e:	3238      	movi      	r2, 56
  10:	6c13      	mov      	r0, r4
  12:	6e0f      	mov      	r8, r3
  14:	e0000000 	bsr      	0x0	// 0 <memset>
  18:	3308      	movi      	r3, 8
  1a:	6c97      	mov      	r2, r5
  1c:	6c5b      	mov      	r1, r6
  1e:	6c13      	mov      	r0, r4
  20:	a465      	st.b      	r3, (r4, 0x5)
  22:	dd040031 	st.b      	r8, (r4, 0x31)
  26:	e0000000 	bsr      	0x0	// 0 <mmpool_init>
  2a:	e4671031 	subi      	r3, r7, 50
  2e:	eb030032 	cmphsi      	r3, 51
  32:	3350      	movi      	r3, 80
  34:	c4670c20 	incf      	r3, r7, 0
  38:	9440      	ld.w      	r2, (r4, 0x0)
  3a:	dc640030 	st.b      	r3, (r4, 0x30)
  3e:	7cc8      	mult      	r3, r2
  40:	3264      	movi      	r2, 100
  42:	c4438023 	divu      	r3, r3, r2
  46:	b46d      	st.w      	r3, (r4, 0x34)
  48:	b8e0      	st.w      	r7, (r14, 0x0)
  4a:	5e74      	addu      	r3, r6, r5
  4c:	6c9b      	mov      	r2, r6
  4e:	6c57      	mov      	r1, r5
  50:	1004      	lrw      	r0, 0x0	// 60 <skbpool_init+0x60>
  52:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  56:	3000      	movi      	r0, 0
  58:	1401      	addi      	r14, r14, 4
  5a:	1495      	pop      	r4-r8, r15
	...

Disassembly of section .text.skbpool_freesize:

00000000 <skbpool_freesize>:
   0:	14d1      	push      	r4, r15
   2:	106b      	lrw      	r3, 0x0	// 2c <skbpool_freesize+0x2c>
   4:	e9000010 	bez      	r0, 0x24	// 24 <skbpool_freesize+0x24>
   8:	930a      	ld.w      	r0, (r3, 0x28)
   a:	938d      	ld.w      	r4, (r3, 0x34)
   c:	6500      	cmphs      	r0, r4
   e:	080d      	bt      	0x28	// 28 <skbpool_freesize+0x28>
  10:	3180      	movi      	r1, 128
  12:	6102      	subu      	r4, r0
  14:	4124      	lsli      	r1, r1, 4
  16:	1006      	lrw      	r0, 0x0	// 2c <skbpool_freesize+0x2c>
  18:	e0000000 	bsr      	0x0	// 0 <mmpool_free_size>
  1c:	6500      	cmphs      	r0, r4
  1e:	c4040c40 	inct      	r0, r4, 0
  22:	1491      	pop      	r4, r15
  24:	930b      	ld.w      	r0, (r3, 0x2c)
  26:	07f2      	br      	0xa	// a <skbpool_freesize+0xa>
  28:	3000      	movi      	r0, 0
  2a:	07fc      	br      	0x22	// 22 <skbpool_freesize+0x22>
  2c:	0000      	.short	0x0000
	...

Disassembly of section .text.skbpool_collect_init:

00000000 <skbpool_collect_init>:
   0:	14d1      	push      	r4, r15
   2:	1089      	lrw      	r4, 0x0	// 24 <skbpool_collect_init+0x24>
   4:	1029      	lrw      	r1, 0x0	// 28 <skbpool_collect_init+0x28>
   6:	104a      	lrw      	r2, 0x0	// 2c <skbpool_collect_init+0x2c>
   8:	6086      	subu      	r2, r1
   a:	6c13      	mov      	r0, r4
   c:	e0000000 	bsr      	0x0	// 0 <mmpool_add_region>
  10:	9440      	ld.w      	r2, (r4, 0x0)
  12:	d8640030 	ld.b      	r3, (r4, 0x30)
  16:	7cc8      	mult      	r3, r2
  18:	3264      	movi      	r2, 100
  1a:	c4438023 	divu      	r3, r3, r2
  1e:	b46d      	st.w      	r3, (r4, 0x34)
  20:	1491      	pop      	r4, r15
	...

Disassembly of section .text.skbpool_add_region:

00000000 <skbpool_add_region>:
   0:	14d1      	push      	r4, r15
   2:	1088      	lrw      	r4, 0x0	// 20 <skbpool_add_region+0x20>
   4:	6c87      	mov      	r2, r1
   6:	6c43      	mov      	r1, r0
   8:	6c13      	mov      	r0, r4
   a:	e0000000 	bsr      	0x0	// 0 <mmpool_add_region>
   e:	9440      	ld.w      	r2, (r4, 0x0)
  10:	d8640030 	ld.b      	r3, (r4, 0x30)
  14:	7cc8      	mult      	r3, r2
  16:	3264      	movi      	r2, 100
  18:	c4438023 	divu      	r3, r3, r2
  1c:	b46d      	st.w      	r3, (r4, 0x34)
  1e:	1491      	pop      	r4, r15
  20:	0000      	.short	0x0000
	...

Disassembly of section .text.skbpool_max_usage:

00000000 <skbpool_max_usage>:
   0:	e4601031 	subi      	r3, r0, 50
   4:	74cc      	zextb      	r3, r3
   6:	eb030032 	cmphsi      	r3, 51
   a:	3350      	movi      	r3, 80
   c:	c4030c40 	inct      	r0, r3, 0
  10:	1066      	lrw      	r3, 0x0	// 28 <skbpool_max_usage+0x28>
  12:	9340      	ld.w      	r2, (r3, 0x0)
  14:	dc030030 	st.b      	r0, (r3, 0x30)
  18:	7c08      	mult      	r0, r2
  1a:	3264      	movi      	r2, 100
  1c:	c4408020 	divu      	r0, r0, r2
  20:	b30d      	st.w      	r0, (r3, 0x34)
  22:	3000      	movi      	r0, 0
  24:	783c      	jmp      	r15
  26:	0000      	.short	0x0000
  28:	0000      	.short	0x0000
	...

Disassembly of section .text.skbpool_status:

00000000 <skbpool_status>:
   0:	14d8      	push      	r4-r11, r15
   2:	1423      	subi      	r14, r14, 12
   4:	3500      	movi      	r5, 0
   6:	6d83      	mov      	r6, r0
   8:	6dc7      	mov      	r7, r1
   a:	6e0b      	mov      	r8, r2
   c:	b8a2      	st.w      	r5, (r14, 0x8)
   e:	e9000079 	bez      	r0, 0x100	// 100 <skbpool_status+0x100>
  12:	3902      	cmphsi      	r1, 3
  14:	0c76      	bf      	0x100	// 100 <skbpool_status+0x100>
  16:	6c87      	mov      	r2, r1
  18:	1b02      	addi      	r3, r14, 8
  1a:	6c43      	mov      	r1, r0
  1c:	1201      	lrw      	r0, 0x0	// 120 <skbpool_status+0x120>
  1e:	e0000000 	bsr      	0x0	// 0 <mmpool_free_state>
  22:	6e43      	mov      	r9, r0
  24:	1200      	lrw      	r0, 0x0	// 124 <skbpool_status+0x124>
  26:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  2a:	c7e94841 	lsri      	r1, r9, 31
  2e:	6064      	addu      	r1, r9
  30:	5121      	asri      	r1, r1, 1
  32:	111e      	lrw      	r0, 0x0	// 128 <skbpool_status+0x128>
  34:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  38:	6d1b      	mov      	r4, r6
  3a:	6e9b      	mov      	r10, r6
  3c:	ea8b003c 	lrw      	r11, 0x0	// 12c <skbpool_status+0x12c>
  40:	6655      	cmplt      	r5, r9
  42:	082c      	bt      	0x9a	// 9a <skbpool_status+0x9a>
  44:	9822      	ld.w      	r1, (r14, 0x8)
  46:	3500      	movi      	r5, 0
  48:	111a      	lrw      	r0, 0x0	// 130 <skbpool_status+0x130>
  4a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  4e:	1116      	lrw      	r0, 0x0	// 124 <hgprintf+0x124>
  50:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  54:	6c9f      	mov      	r2, r7
  56:	6c5b      	mov      	r1, r6
  58:	dd0e2000 	st.w      	r8, (r14, 0x0)
  5c:	1b02      	addi      	r3, r14, 8
  5e:	1111      	lrw      	r0, 0x0	// 120 <skbpool_status+0x120>
  60:	11f5      	lrw      	r7, 0x0	// 134 <skbpool_status+0x134>
  62:	ea880036 	lrw      	r8, 0x0	// 138 <skbpool_status+0x138>
  66:	b8a2      	st.w      	r5, (r14, 0x8)
  68:	e0000000 	bsr      	0x0	// 0 <mmpool_used_state>
  6c:	3105      	movi      	r1, 5
  6e:	c4208041 	divs      	r1, r0, r1
  72:	6d83      	mov      	r6, r0
  74:	1112      	lrw      	r0, 0x0	// 13c <skbpool_status+0x13c>
  76:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  7a:	6595      	cmplt      	r5, r6
  7c:	082a      	bt      	0xd0	// d0 <skbpool_status+0xd0>
  7e:	9822      	ld.w      	r1, (r14, 0x8)
  80:	1110      	lrw      	r0, 0x0	// 140 <skbpool_status+0x140>
  82:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  86:	1108      	lrw      	r0, 0x0	// 124 <hgprintf+0x124>
  88:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  8c:	1165      	lrw      	r3, 0x0	// 120 <skbpool_status+0x120>
  8e:	110e      	lrw      	r0, 0x0	// 144 <skbpool_status+0x144>
  90:	9320      	ld.w      	r1, (r3, 0x0)
  92:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  96:	1403      	addi      	r14, r14, 12
  98:	1498      	pop      	r4-r11, r15
  9a:	d86a2001 	ld.w      	r3, (r10, 0x4)
  9e:	6c8f      	mov      	r2, r3
  a0:	3000      	movi      	r0, 0
  a2:	4a3f      	lsri      	r1, r2, 31
  a4:	6084      	addu      	r2, r1
  a6:	5241      	asri      	r2, r2, 1
  a8:	e9220012 	bnez      	r2, 0xcc	// cc <skbpool_status+0xcc>
  ac:	4d3f      	lsri      	r1, r5, 31
  ae:	6054      	addu      	r1, r5
  b0:	d84a2000 	ld.w      	r2, (r10, 0x0)
  b4:	5121      	asri      	r1, r1, 1
  b6:	b801      	st.w      	r0, (r14, 0x4)
  b8:	b860      	st.w      	r3, (r14, 0x0)
  ba:	2100      	addi      	r1, 1
  bc:	60c8      	addu      	r3, r2
  be:	6c2f      	mov      	r0, r11
  c0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  c4:	2501      	addi      	r5, 2
  c6:	e54a0007 	addi      	r10, r10, 8
  ca:	07bb      	br      	0x40	// 40 <skbpool_status+0x40>
  cc:	2000      	addi      	r0, 1
  ce:	07ea      	br      	0xa2	// a2 <skbpool_status+0xa2>
  d0:	9401      	ld.w      	r0, (r4, 0x4)
  d2:	9442      	ld.w      	r2, (r4, 0x8)
  d4:	9424      	ld.w      	r1, (r4, 0x10)
  d6:	e900000e 	bez      	r0, 0xf2	// f2 <skbpool_status+0xf2>
  da:	b821      	st.w      	r1, (r14, 0x4)
  dc:	9463      	ld.w      	r3, (r4, 0xc)
  de:	b860      	st.w      	r3, (r14, 0x0)
  e0:	9420      	ld.w      	r1, (r4, 0x0)
  e2:	6ccb      	mov      	r3, r2
  e4:	6c83      	mov      	r2, r0
  e6:	6c23      	mov      	r0, r8
  e8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ec:	2504      	addi      	r5, 5
  ee:	2413      	addi      	r4, 20
  f0:	07c5      	br      	0x7a	// 7a <skbpool_status+0x7a>
  f2:	9463      	ld.w      	r3, (r4, 0xc)
  f4:	b820      	st.w      	r1, (r14, 0x0)
  f6:	9420      	ld.w      	r1, (r4, 0x0)
  f8:	6c1f      	mov      	r0, r7
  fa:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  fe:	07f7      	br      	0xec	// ec <skbpool_status+0xec>
 100:	1088      	lrw      	r4, 0x0	// 120 <skbpool_status+0x120>
 102:	3100      	movi      	r1, 0
 104:	6c13      	mov      	r0, r4
 106:	94a0      	ld.w      	r5, (r4, 0x0)
 108:	e0000000 	bsr      	0x0	// 0 <mmpool_free_size>
 10c:	944b      	ld.w      	r2, (r4, 0x2c)
 10e:	946a      	ld.w      	r3, (r4, 0x28)
 110:	6c57      	mov      	r1, r5
 112:	b840      	st.w      	r2, (r14, 0x0)
 114:	6c83      	mov      	r2, r0
 116:	100d      	lrw      	r0, 0x0	// 148 <skbpool_status+0x148>
 118:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 11c:	07bd      	br      	0x96	// 96 <skbpool_status+0x96>
	...

Disassembly of section .text.kfree_skb:

00000000 <kfree_skb>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	e9000013 	bez      	r0, 0x2a	// 2a <kfree_skb+0x2a>
   8:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
   c:	946f      	ld.w      	r3, (r4, 0x3c)
   e:	e903000f 	bez      	r3, 0x2c	// 2c <kfree_skb+0x2c>
  12:	2b00      	subi      	r3, 1
  14:	3b40      	cmpnei      	r3, 0
  16:	b46f      	st.w      	r3, (r4, 0x3c)
  18:	6543      	mvcv      	r5
  1a:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  1e:	e9050006 	bez      	r5, 0x2a	// 2a <kfree_skb+0x2a>
  22:	9470      	ld.w      	r3, (r4, 0x40)
  24:	6c53      	mov      	r1, r4
  26:	9411      	ld.w      	r0, (r4, 0x44)
  28:	7bcd      	jsr      	r3
  2a:	1492      	pop      	r4-r5, r15
  2c:	3501      	movi      	r5, 1
  2e:	07f6      	br      	0x1a	// 1a <kfree_skb+0x1a>

Disassembly of section .text.free_heapskb:

00000000 <free_heapskb>:
   0:	14d1      	push      	r4, r15
   2:	6d07      	mov      	r4, r1
   4:	9102      	ld.w      	r0, (r1, 0x8)
   6:	e0000000 	bsr      	0x0	// 0 <free_heapskb>
   a:	6c13      	mov      	r0, r4
   c:	e0000000 	bsr      	0x0	// 0 <_os_free>
  10:	1491      	pop      	r4, r15

Disassembly of section .text._alloc_tx_skb:

00000000 <_alloc_tx_skb>:
   0:	14d0      	push      	r15
   2:	6ccb      	mov      	r3, r2
   4:	6c87      	mov      	r2, r1
   6:	3101      	movi      	r1, 1
   8:	e0000000 	bsr      	0x0	// 0 <_alloc_tx_skb>
   c:	1490      	pop      	r15

Disassembly of section .text._alloc_rx_skb:

00000000 <_alloc_rx_skb>:
   0:	14d0      	push      	r15
   2:	6ccb      	mov      	r3, r2
   4:	6c87      	mov      	r2, r1
   6:	3100      	movi      	r1, 0
   8:	e0000000 	bsr      	0x0	// 0 <_alloc_rx_skb>
   c:	1490      	pop      	r15

Disassembly of section .text.alloc_heapskb:

00000000 <alloc_heapskb>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	2047      	addi      	r0, 72
   6:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
   a:	6d03      	mov      	r4, r0
   c:	e9000017 	bez      	r0, 0x3a	// 3a <alloc_heapskb+0x3a>
  10:	3248      	movi      	r2, 72
  12:	3100      	movi      	r1, 0
  14:	e0000000 	bsr      	0x0	// 0 <memset>
  18:	e4040047 	addi      	r0, r4, 72
  1c:	1069      	lrw      	r3, 0x0	// 40 <alloc_heapskb+0x40>
  1e:	b470      	st.w      	r3, (r4, 0x40)
  20:	b408      	st.w      	r0, (r4, 0x20)
  22:	3300      	movi      	r3, 0
  24:	b407      	st.w      	r0, (r4, 0x1c)
  26:	b406      	st.w      	r0, (r4, 0x18)
  28:	6014      	addu      	r0, r5
  2a:	b471      	st.w      	r3, (r4, 0x44)
  2c:	b409      	st.w      	r0, (r4, 0x24)
  2e:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  32:	3301      	movi      	r3, 1
  34:	b46f      	st.w      	r3, (r4, 0x3c)
  36:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  3a:	6c13      	mov      	r0, r4
  3c:	1492      	pop      	r4-r5, r15
  3e:	0000      	.short	0x0000
  40:	00000000 	.long	0x00000000

Disassembly of section .text._alloc_skb:

00000000 <_alloc_skb>:
   0:	14d3      	push      	r4-r6, r15
   2:	106c      	lrw      	r3, 0x0	// 30 <_alloc_skb+0x30>
   4:	6d03      	mov      	r4, r0
   6:	d8630031 	ld.b      	r3, (r3, 0x31)
   a:	e4632001 	andi      	r3, r3, 1
   e:	6d47      	mov      	r5, r1
  10:	6d8b      	mov      	r6, r2
  12:	e9030005 	bez      	r3, 0x1c	// 1c <_alloc_skb+0x1c>
  16:	e0000000 	bsr      	0x0	// 0 <_alloc_skb>
  1a:	1493      	pop      	r4-r6, r15
  1c:	e0000000 	bsr      	0x0	// 0 <_alloc_skb>
  20:	e920fffd 	bnez      	r0, 0x1a	// 1a <_alloc_skb+0x1a>
  24:	6c9b      	mov      	r2, r6
  26:	6c57      	mov      	r1, r5
  28:	6c13      	mov      	r0, r4
  2a:	e0000000 	bsr      	0x0	// 0 <_alloc_skb>
  2e:	07f6      	br      	0x1a	// 1a <_alloc_skb+0x1a>
  30:	00000000 	.long	0x00000000

Disassembly of section .text.alloc_tx_skb:

00000000 <alloc_tx_skb>:
   0:	14d0      	push      	r15
   2:	3200      	movi      	r2, 0
   4:	6c4b      	mov      	r1, r2
   6:	e0000000 	bsr      	0x0	// 0 <alloc_tx_skb>
   a:	1490      	pop      	r15

Disassembly of section .text.alloc_rx_skb:

00000000 <alloc_rx_skb>:
   0:	14d0      	push      	r15
   2:	3200      	movi      	r2, 0
   4:	6c4b      	mov      	r1, r2
   6:	e0000000 	bsr      	0x0	// 0 <alloc_rx_skb>
   a:	1490      	pop      	r15

Disassembly of section .text.alloc_skb:

00000000 <alloc_skb>:
   0:	14d0      	push      	r15
   2:	3200      	movi      	r2, 0
   4:	6c4b      	mov      	r1, r2
   6:	e0000000 	bsr      	0x0	// 0 <alloc_skb>
   a:	1490      	pop      	r15

Disassembly of section .text.skb_put:

00000000 <skb_put>:
   0:	14d3      	push      	r4-r6, r15
   2:	90c6      	ld.w      	r6, (r0, 0x18)
   4:	5e64      	addu      	r3, r6, r1
   6:	9049      	ld.w      	r2, (r0, 0x24)
   8:	64c8      	cmphs      	r2, r3
   a:	6d03      	mov      	r4, r0
   c:	6d47      	mov      	r5, r1
   e:	0807      	bt      	0x1c	// 1c <skb_put+0x1c>
  10:	319e      	movi      	r1, 158
  12:	1047      	lrw      	r2, 0x0	// 2c <skb_put+0x2c>
  14:	4121      	lsli      	r1, r1, 1
  16:	1007      	lrw      	r0, 0x0	// 30 <skb_put+0x30>
  18:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  1c:	9466      	ld.w      	r3, (r4, 0x18)
  1e:	60d4      	addu      	r3, r5
  20:	b466      	st.w      	r3, (r4, 0x18)
  22:	8c74      	ld.h      	r3, (r4, 0x28)
  24:	614c      	addu      	r5, r3
  26:	6c1b      	mov      	r0, r6
  28:	acb4      	st.h      	r5, (r4, 0x28)
  2a:	1493      	pop      	r4-r6, r15
	...

Disassembly of section .text.skb_push:

00000000 <skb_push>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	3000      	movi      	r0, 0
   6:	58c5      	subu      	r6, r0, r1
   8:	9467      	ld.w      	r3, (r4, 0x1c)
   a:	60d8      	addu      	r3, r6
   c:	9448      	ld.w      	r2, (r4, 0x20)
   e:	648c      	cmphs      	r3, r2
  10:	6d47      	mov      	r5, r1
  12:	0807      	bt      	0x20	// 20 <skb_push+0x20>
  14:	1047      	lrw      	r2, 0x0	// 30 <skb_push+0x30>
  16:	ea010147 	movi      	r1, 327
  1a:	1007      	lrw      	r0, 0x0	// 34 <assert_internal+0x34>
  1c:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  20:	9407      	ld.w      	r0, (r4, 0x1c)
  22:	8c74      	ld.h      	r3, (r4, 0x28)
  24:	6018      	addu      	r0, r6
  26:	614c      	addu      	r5, r3
  28:	b407      	st.w      	r0, (r4, 0x1c)
  2a:	acb4      	st.h      	r5, (r4, 0x28)
  2c:	1493      	pop      	r4-r6, r15
	...

Disassembly of section .text.skb_pull:

00000000 <skb_pull>:
   0:	14d2      	push      	r4-r5, r15
   2:	8874      	ld.h      	r3, (r0, 0x28)
   4:	644c      	cmphs      	r3, r1
   6:	6d03      	mov      	r4, r0
   8:	6d47      	mov      	r5, r1
   a:	0c06      	bf      	0x16	// 16 <skb_pull+0x16>
   c:	9067      	ld.w      	r3, (r0, 0x1c)
   e:	60c4      	addu      	r3, r1
  10:	9049      	ld.w      	r2, (r0, 0x24)
  12:	648c      	cmphs      	r3, r2
  14:	0c07      	bf      	0x22	// 22 <skb_pull+0x22>
  16:	31a9      	movi      	r1, 169
  18:	1046      	lrw      	r2, 0x0	// 30 <skb_pull+0x30>
  1a:	4121      	lsli      	r1, r1, 1
  1c:	1006      	lrw      	r0, 0x0	// 34 <skb_pull+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  22:	8c74      	ld.h      	r3, (r4, 0x28)
  24:	9407      	ld.w      	r0, (r4, 0x1c)
  26:	6014      	addu      	r0, r5
  28:	60d6      	subu      	r3, r5
  2a:	ac74      	st.h      	r3, (r4, 0x28)
  2c:	b407      	st.w      	r0, (r4, 0x1c)
  2e:	1492      	pop      	r4-r5, r15
	...

Disassembly of section .text.skb_reserve:

00000000 <skb_reserve>:
   0:	14d2      	push      	r4-r5, r15
   2:	9066      	ld.w      	r3, (r0, 0x18)
   4:	60c4      	addu      	r3, r1
   6:	9049      	ld.w      	r2, (r0, 0x24)
   8:	648c      	cmphs      	r3, r2
   a:	6d03      	mov      	r4, r0
   c:	6d47      	mov      	r5, r1
   e:	0c07      	bf      	0x1c	// 1c <skb_reserve+0x1c>
  10:	31ae      	movi      	r1, 174
  12:	1047      	lrw      	r2, 0x0	// 2c <skb_reserve+0x2c>
  14:	4121      	lsli      	r1, r1, 1
  16:	1007      	lrw      	r0, 0x0	// 30 <skb_reserve+0x30>
  18:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  1c:	9467      	ld.w      	r3, (r4, 0x1c)
  1e:	9426      	ld.w      	r1, (r4, 0x18)
  20:	60d4      	addu      	r3, r5
  22:	6054      	addu      	r1, r5
  24:	b467      	st.w      	r3, (r4, 0x1c)
  26:	b426      	st.w      	r1, (r4, 0x18)
  28:	1492      	pop      	r4-r5, r15
	...

Disassembly of section .text._skb_copy:

00000000 <_skb_copy>:
   0:	14d2      	push      	r4-r5, r15
   2:	d820002b 	ld.b      	r1, (r0, 0x2b)
   6:	d9802009 	ld.w      	r12, (r0, 0x24)
   a:	6d03      	mov      	r4, r0
   c:	9008      	ld.w      	r0, (r0, 0x20)
   e:	c4415441 	zext      	r1, r1, 2, 2
  12:	c40c0080 	subu      	r0, r12, r0
  16:	e0000000 	bsr      	0x0	// 0 <_skb_copy>
  1a:	6d43      	mov      	r5, r0
  1c:	e900002e 	bez      	r0, 0x78	// 78 <_skb_copy+0x78>
  20:	9468      	ld.w      	r3, (r4, 0x20)
  22:	9427      	ld.w      	r1, (r4, 0x1c)
  24:	604e      	subu      	r1, r3
  26:	e0000000 	bsr      	0x0	// 0 <_skb_copy>
  2a:	8c54      	ld.h      	r2, (r4, 0x28)
  2c:	9427      	ld.w      	r1, (r4, 0x1c)
  2e:	9507      	ld.w      	r0, (r5, 0x1c)
  30:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
  34:	320c      	movi      	r2, 12
  36:	5c28      	addu      	r1, r4, r2
  38:	5d08      	addu      	r0, r5, r2
  3a:	e0000000 	bsr      	0x0	// 0 <memcpy>
  3e:	d844002a 	ld.b      	r2, (r4, 0x2a)
  42:	d865002a 	ld.b      	r3, (r5, 0x2a)
  46:	c4625c60 	ins      	r3, r2, 3, 0
  4a:	dc65002a 	st.b      	r3, (r5, 0x2a)
  4e:	8c75      	ld.h      	r3, (r4, 0x2a)
  50:	8d55      	ld.h      	r2, (r5, 0x2a)
  52:	c4e35523 	zext      	r3, r3, 9, 7
  56:	c4435c47 	ins      	r2, r3, 9, 7
  5a:	ad55      	st.h      	r2, (r5, 0x2a)
  5c:	d864002b 	ld.b      	r3, (r4, 0x2b)
  60:	d845002b 	ld.b      	r2, (r5, 0x2b)
  64:	c4435443 	zext      	r3, r3, 2, 2
  68:	c4435c02 	ins      	r2, r3, 2, 2
  6c:	dc45002b 	st.b      	r2, (r5, 0x2b)
  70:	8c34      	ld.h      	r1, (r4, 0x28)
  72:	6c17      	mov      	r0, r5
  74:	e0000000 	bsr      	0x0	// 0 <_skb_copy>
  78:	6c17      	mov      	r0, r5
  7a:	1492      	pop      	r4-r5, r15

Disassembly of section .text.skb_copy:

00000000 <skb_copy>:
   0:	14d0      	push      	r15
   2:	3300      	movi      	r3, 0
   4:	6c8f      	mov      	r2, r3
   6:	e0000000 	bsr      	0x0	// 0 <skb_copy>
   a:	1490      	pop      	r15

Disassembly of section .text._skb_clone:

00000000 <_skb_clone>:
   0:	14d2      	push      	r4-r5, r15
   2:	d820002b 	ld.b      	r1, (r0, 0x2b)
   6:	6d43      	mov      	r5, r0
   8:	3082      	movi      	r0, 130
   a:	c4415441 	zext      	r1, r1, 2, 2
   e:	4001      	lsli      	r0, r0, 1
  10:	e0000000 	bsr      	0x0	// 0 <_skb_clone>
  14:	6d03      	mov      	r4, r0
  16:	e9000027 	bez      	r0, 0x64	// 64 <_skb_clone+0x64>
  1a:	3180      	movi      	r1, 128
  1c:	4121      	lsli      	r1, r1, 1
  1e:	e0000000 	bsr      	0x0	// 0 <_skb_clone>
  22:	9567      	ld.w      	r3, (r5, 0x1c)
  24:	b467      	st.w      	r3, (r4, 0x1c)
  26:	8d74      	ld.h      	r3, (r5, 0x28)
  28:	ac74      	st.h      	r3, (r4, 0x28)
  2a:	9566      	ld.w      	r3, (r5, 0x18)
  2c:	b466      	st.w      	r3, (r4, 0x18)
  2e:	9569      	ld.w      	r3, (r5, 0x24)
  30:	b469      	st.w      	r3, (r4, 0x24)
  32:	d865002b 	ld.b      	r3, (r5, 0x2b)
  36:	d844002b 	ld.b      	r2, (r4, 0x2b)
  3a:	c4435443 	zext      	r3, r3, 2, 2
  3e:	c4435c02 	ins      	r2, r3, 2, 2
  42:	dc44002b 	st.b      	r2, (r4, 0x2b)
  46:	d864002a 	ld.b      	r3, (r4, 0x2a)
  4a:	3201      	movi      	r2, 1
  4c:	c4625c05 	ins      	r3, r2, 5, 5
  50:	dc64002a 	st.b      	r3, (r4, 0x2a)
  54:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  58:	956f      	ld.w      	r3, (r5, 0x3c)
  5a:	2300      	addi      	r3, 1
  5c:	b56f      	st.w      	r3, (r5, 0x3c)
  5e:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  62:	b4a2      	st.w      	r5, (r4, 0x8)
  64:	6c13      	mov      	r0, r4
  66:	1492      	pop      	r4-r5, r15

Disassembly of section .text.skb_clone:

00000000 <skb_clone>:
   0:	14d0      	push      	r15
   2:	3300      	movi      	r3, 0
   4:	6c8f      	mov      	r2, r3
   6:	e0000000 	bsr      	0x0	// 0 <skb_clone>
   a:	1490      	pop      	r15

Disassembly of section .text.skb_put_zero:

00000000 <skb_put_zero>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d47      	mov      	r5, r1
   4:	e0000000 	bsr      	0x0	// 0 <skb_put_zero>
   8:	6d03      	mov      	r4, r0
   a:	e9000006 	bez      	r0, 0x16	// 16 <skb_put_zero+0x16>
   e:	6c97      	mov      	r2, r5
  10:	3100      	movi      	r1, 0
  12:	e0000000 	bsr      	0x0	// 0 <memset>
  16:	6c13      	mov      	r0, r4
  18:	1492      	pop      	r4-r5, r15

Disassembly of section .text.skb_put_data:

00000000 <skb_put_data>:
   0:	14d2      	push      	r4-r5, r15
   2:	1421      	subi      	r14, r14, 4
   4:	6d47      	mov      	r5, r1
   6:	6c4b      	mov      	r1, r2
   8:	b840      	st.w      	r2, (r14, 0x0)
   a:	e0000000 	bsr      	0x0	// 0 <skb_put_data>
   e:	6d03      	mov      	r4, r0
  10:	e9000006 	bez      	r0, 0x1c	// 1c <skb_put_data+0x1c>
  14:	9840      	ld.w      	r2, (r14, 0x0)
  16:	6c57      	mov      	r1, r5
  18:	e0000000 	bsr      	0x0	// 0 <memcpy>
  1c:	6c13      	mov      	r0, r4
  1e:	1401      	addi      	r14, r14, 4
  20:	1492      	pop      	r4-r5, r15
