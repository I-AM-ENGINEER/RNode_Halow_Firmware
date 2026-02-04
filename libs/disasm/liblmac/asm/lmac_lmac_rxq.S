
disasm/liblmac/obj/lmac_lmac_rxq.o:     file format elf32-csky-little


Disassembly of section .text.lmac_rxq_init:

00000000 <lmac_rxq_init>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	6d87      	mov      	r6, r1
   6:	6d4b      	mov      	r5, r2
   8:	3100      	movi      	r1, 0
   a:	3214      	movi      	r2, 20
   c:	e0000000 	bsr      	0x0	// 0 <memset>
  10:	3100      	movi      	r1, 0
  12:	6c13      	mov      	r0, r4
  14:	e0000000 	bsr      	0x0	// 0 <os_sema_init>
  18:	3000      	movi      	r0, 0
  1a:	b4c2      	st.w      	r6, (r4, 0x8)
  1c:	b4a4      	st.w      	r5, (r4, 0x10)
  1e:	1493      	pop      	r4-r6, r15

Disassembly of section .text.lmac_rxq_put:

00000000 <lmac_rxq_put>:
   0:	14d4      	push      	r4-r7, r15
   2:	6d4b      	mov      	r5, r2
   4:	e962003b 	blsz      	r2, 0x7a	// 7a <lmac_rxq_put+0x7a>
   8:	8866      	ld.h      	r3, (r0, 0xc)
   a:	8847      	ld.h      	r2, (r0, 0xe)
   c:	648c      	cmphs      	r3, r2
   e:	d9802004 	ld.w      	r12, (r0, 0x10)
  12:	0c2f      	bf      	0x70	// 70 <lmac_rxq_put+0x70>
  14:	60ca      	subu      	r3, r2
  16:	60d4      	addu      	r3, r5
  18:	670c      	cmphs      	r3, r12
  1a:	082d      	bt      	0x74	// 74 <lmac_rxq_put+0x74>
  1c:	3400      	movi      	r4, 0
  1e:	6d93      	mov      	r6, r4
  20:	d9a01006 	ld.h      	r13, (r0, 0xc)
  24:	e46d0000 	addi      	r3, r13, 1
  28:	670c      	cmphs      	r3, r12
  2a:	6dcf      	mov      	r7, r3
  2c:	c4660c40 	inct      	r3, r6, 0
  30:	648e      	cmpne      	r3, r2
  32:	0c14      	bf      	0x5a	// 5a <lmac_rxq_put+0x5a>
  34:	9062      	ld.w      	r3, (r0, 0x8)
  36:	c46d482d 	lsli      	r13, r13, 3
  3a:	634c      	addu      	r13, r3
  3c:	9160      	ld.w      	r3, (r1, 0x0)
  3e:	dc6d2000 	st.w      	r3, (r13, 0x0)
  42:	9161      	ld.w      	r3, (r1, 0x4)
  44:	dc6d2001 	st.w      	r3, (r13, 0x4)
  48:	671c      	cmphs      	r7, r12
  4a:	74dd      	zexth      	r3, r7
  4c:	2400      	addi      	r4, 1
  4e:	c4660c40 	inct      	r3, r6, 0
  52:	6516      	cmpne      	r5, r4
  54:	a866      	st.h      	r3, (r0, 0xc)
  56:	2107      	addi      	r1, 8
  58:	0be4      	bt      	0x20	// 20 <lmac_rxq_put+0x20>
  5a:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  5e:	6516      	cmpne      	r5, r4
  60:	0c06      	bf      	0x6c	// 6c <lmac_rxq_put+0x6c>
  62:	1048      	lrw      	r2, 0x0	// 80 <lmac_rxq_put+0x80>
  64:	313a      	movi      	r1, 58
  66:	1008      	lrw      	r0, 0x0	// 84 <lmac_rxq_put+0x84>
  68:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  6c:	6c13      	mov      	r0, r4
  6e:	1494      	pop      	r4-r7, r15
  70:	60f0      	addu      	r3, r12
  72:	07d1      	br      	0x14	// 14 <lmac_rxq_put+0x14>
  74:	1005      	lrw      	r0, 0x0	// 88 <lmac_rxq_put+0x88>
  76:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  7a:	3400      	movi      	r4, 0
  7c:	07f8      	br      	0x6c	// 6c <lmac_rxq_put+0x6c>
	...

Disassembly of section .text.lmac_rxq_get:

00000000 <lmac_rxq_get>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d47      	mov      	r5, r1
   4:	6d8b      	mov      	r6, r2
   6:	8826      	ld.h      	r1, (r0, 0xc)
   8:	8847      	ld.h      	r2, (r0, 0xe)
   a:	6486      	cmpne      	r1, r2
   c:	6d03      	mov      	r4, r0
   e:	0804      	bt      	0x16	// 16 <lmac_rxq_get+0x16>
  10:	6c4f      	mov      	r1, r3
  12:	e0000000 	bsr      	0x0	// 0 <os_sema_down>
  16:	3000      	movi      	r0, 0
  18:	8c46      	ld.h      	r2, (r4, 0xc)
  1a:	6c57      	mov      	r1, r5
  1c:	6f43      	mov      	r13, r0
  1e:	8c67      	ld.h      	r3, (r4, 0xe)
  20:	64ca      	cmpne      	r2, r3
  22:	0c03      	bf      	0x28	// 28 <lmac_rxq_get+0x28>
  24:	6581      	cmplt      	r0, r6
  26:	0802      	bt      	0x2a	// 2a <lmac_rxq_get+0x2a>
  28:	1493      	pop      	r4-r6, r15
  2a:	43a3      	lsli      	r5, r3, 3
  2c:	d9842002 	ld.w      	r12, (r4, 0x8)
  30:	6314      	addu      	r12, r5
  32:	2300      	addi      	r3, 1
  34:	d8ac2000 	ld.w      	r5, (r12, 0x0)
  38:	d98c2001 	ld.w      	r12, (r12, 0x4)
  3c:	dd812001 	st.w      	r12, (r1, 0x4)
  40:	b1a0      	st.w      	r5, (r1, 0x0)
  42:	770d      	zexth      	r12, r3
  44:	94a4      	ld.w      	r5, (r4, 0x10)
  46:	654c      	cmphs      	r3, r5
  48:	6cf3      	mov      	r3, r12
  4a:	c46d0c40 	inct      	r3, r13, 0
  4e:	ac67      	st.h      	r3, (r4, 0xe)
  50:	2000      	addi      	r0, 1
  52:	2107      	addi      	r1, 8
  54:	07e5      	br      	0x1e	// 1e <lmac_rxq_get+0x1e>

Disassembly of section .text.lmac_rxq_free:

00000000 <lmac_rxq_free>:
   0:	8867      	ld.h      	r3, (r0, 0xe)
   2:	8846      	ld.h      	r2, (r0, 0xc)
   4:	64c8      	cmphs      	r2, r3
   6:	0804      	bt      	0xe	// e <lmac_rxq_free+0xe>
   8:	5b09      	subu      	r0, r3, r2
   a:	2800      	subi      	r0, 1
   c:	783c      	jmp      	r15
   e:	9004      	ld.w      	r0, (r0, 0x10)
  10:	2800      	subi      	r0, 1
  12:	600c      	addu      	r0, r3
  14:	600a      	subu      	r0, r2
  16:	07fb      	br      	0xc	// c <lmac_rxq_free+0xc>

Disassembly of section .text.lmac_rxq_count:

00000000 <lmac_rxq_count>:
   0:	8846      	ld.h      	r2, (r0, 0xc)
   2:	8867      	ld.h      	r3, (r0, 0xe)
   4:	64c8      	cmphs      	r2, r3
   6:	0c03      	bf      	0xc	// c <lmac_rxq_count+0xc>
   8:	5a0d      	subu      	r0, r2, r3
   a:	783c      	jmp      	r15
   c:	9004      	ld.w      	r0, (r0, 0x10)
   e:	6008      	addu      	r0, r2
  10:	600e      	subu      	r0, r3
  12:	07fc      	br      	0xa	// a <lmac_rxq_count+0xa>
