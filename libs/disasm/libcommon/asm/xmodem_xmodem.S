
disasm/libcommon/obj/xmodem_xmodem.o:     file format elf32-csky-little


Disassembly of section .text.xmodem_receive:

00000000 <xmodem_receive>:
   0:	14d8      	push      	r4-r11, r15
   2:	1424      	subi      	r14, r14, 16
   4:	3941      	cmpnei      	r1, 1
   6:	6d43      	mov      	r5, r0
   8:	6dcb      	mov      	r7, r2
   a:	6e4f      	mov      	r9, r3
   c:	0c1b      	bf      	0x42	// 42 <xmodem_receive+0x42>
   e:	3940      	cmpnei      	r1, 0
  10:	0c15      	bf      	0x3a	// 3a <xmodem_receive+0x3a>
  12:	3942      	cmpnei      	r1, 2
  14:	080a      	bt      	0x28	// 28 <xmodem_receive+0x28>
  16:	3615      	movi      	r6, 21
  18:	ea080020 	movi      	r8, 32
  1c:	ea8a0047 	lrw      	r10, 0x0	// 138 <xmodem_receive+0x138>
  20:	e5081000 	subi      	r8, r8, 1
  24:	e9480076 	bhz      	r8, 0x110	// 110 <xmodem_receive+0x110>
  28:	9560      	ld.w      	r3, (r5, 0x0)
  2a:	3018      	movi      	r0, 24
  2c:	7bcd      	jsr      	r3
  2e:	9560      	ld.w      	r3, (r5, 0x0)
  30:	3018      	movi      	r0, 24
  32:	7bcd      	jsr      	r3
  34:	9560      	ld.w      	r3, (r5, 0x0)
  36:	3018      	movi      	r0, 24
  38:	040d      	br      	0x52	// 52 <xmodem_receive+0x52>
  3a:	3301      	movi      	r3, 1
  3c:	a068      	st.b      	r3, (r0, 0x8)
  3e:	3643      	movi      	r6, 67
  40:	07ec      	br      	0x18	// 18 <xmodem_receive+0x18>
  42:	3606      	movi      	r6, 6
  44:	07ea      	br      	0x18	// 18 <xmodem_receive+0x18>
  46:	3844      	cmpnei      	r0, 4
  48:	9560      	ld.w      	r3, (r5, 0x0)
  4a:	0c44      	bf      	0xd2	// d2 <xmodem_receive+0xd2>
  4c:	3858      	cmpnei      	r0, 24
  4e:	0be9      	bt      	0x20	// 20 <xmodem_receive+0x20>
  50:	3006      	movi      	r0, 6
  52:	3400      	movi      	r4, 0
  54:	7bcd      	jsr      	r3
  56:	2c00      	subi      	r4, 1
  58:	043f      	br      	0xd6	// d6 <xmodem_receive+0xd6>
  5a:	3480      	movi      	r4, 128
  5c:	4483      	lsli      	r4, r4, 3
  5e:	6525      	cmplt      	r9, r4
  60:	0be4      	bt      	0x28	// 28 <xmodem_receive+0x28>
  62:	30fa      	movi      	r0, 250
  64:	9561      	ld.w      	r3, (r5, 0x4)
  66:	1903      	addi      	r1, r14, 12
  68:	4002      	lsli      	r0, r0, 2
  6a:	7bcd      	jsr      	r3
  6c:	9863      	ld.w      	r3, (r14, 0xc)
  6e:	6d83      	mov      	r6, r0
  70:	e9230048 	bnez      	r3, 0x100	// 100 <xmodem_receive+0x100>
  74:	30fa      	movi      	r0, 250
  76:	9561      	ld.w      	r3, (r5, 0x4)
  78:	1903      	addi      	r1, r14, 12
  7a:	4002      	lsli      	r0, r0, 2
  7c:	7bcd      	jsr      	r3
  7e:	9863      	ld.w      	r3, (r14, 0xc)
  80:	6ec3      	mov      	r11, r0
  82:	e923003f 	bnez      	r3, 0x100	// 100 <xmodem_receive+0x100>
  86:	6c9f      	mov      	r2, r7
  88:	6cdf      	mov      	r3, r7
  8a:	e5840000 	addi      	r12, r4, 1
  8e:	5b3d      	subu      	r1, r3, r7
  90:	6471      	cmplt      	r12, r1
  92:	0c25      	bf      	0xdc	// dc <xmodem_receive+0xdc>
  94:	6eee      	nor      	r11, r11
  96:	76ec      	zextb      	r11, r11
  98:	66da      	cmpne      	r6, r11
  9a:	0833      	bt      	0x100	// 100 <xmodem_receive+0x100>
  9c:	5f30      	addu      	r1, r7, r4
  9e:	3300      	movi      	r3, 0
  a0:	4b08      	lsri      	r0, r3, 8
  a2:	d9820000 	ld.b      	r12, (r2, 0x0)
  a6:	6c31      	xor      	r0, r12
  a8:	2200      	addi      	r2, 1
  aa:	4368      	lsli      	r3, r3, 8
  ac:	d00a0440 	ldr.h      	r0, (r10, r0 << 1)
  b0:	6486      	cmpne      	r1, r2
  b2:	6cc1      	xor      	r3, r0
  b4:	74cd      	zexth      	r3, r3
  b6:	0bf5      	bt      	0xa0	// a0 <xmodem_receive+0xa0>
  b8:	8140      	ld.b      	r2, (r1, 0x0)
  ba:	8101      	ld.b      	r0, (r1, 0x1)
  bc:	4248      	lsli      	r2, r2, 8
  be:	6080      	addu      	r2, r0
  c0:	7489      	zexth      	r2, r2
  c2:	64ca      	cmpne      	r2, r3
  c4:	081e      	bt      	0x100	// 100 <xmodem_receive+0x100>
  c6:	8568      	ld.b      	r3, (r5, 0x8)
  c8:	64da      	cmpne      	r6, r3
  ca:	081d      	bt      	0x104	// 104 <xmodem_receive+0x104>
  cc:	2600      	addi      	r6, 1
  ce:	a5c8      	st.b      	r6, (r5, 0x8)
  d0:	0403      	br      	0xd6	// d6 <xmodem_receive+0xd6>
  d2:	3006      	movi      	r0, 6
  d4:	7bcd      	jsr      	r3
  d6:	6c13      	mov      	r0, r4
  d8:	1404      	addi      	r14, r14, 16
  da:	1498      	pop      	r4-r11, r15
  dc:	1903      	addi      	r1, r14, 12
  de:	d9a52001 	ld.w      	r13, (r5, 0x4)
  e2:	3064      	movi      	r0, 100
  e4:	dd8e2002 	st.w      	r12, (r14, 0x8)
  e8:	b841      	st.w      	r2, (r14, 0x4)
  ea:	b860      	st.w      	r3, (r14, 0x0)
  ec:	7bf5      	jsr      	r13
  ee:	9860      	ld.w      	r3, (r14, 0x0)
  f0:	9823      	ld.w      	r1, (r14, 0xc)
  f2:	a300      	st.b      	r0, (r3, 0x0)
  f4:	9841      	ld.w      	r2, (r14, 0x4)
  f6:	2300      	addi      	r3, 1
  f8:	d98e2002 	ld.w      	r12, (r14, 0x8)
  fc:	e901ffc9 	bez      	r1, 0x8e	// 8e <xmodem_receive+0x8e>
 100:	3615      	movi      	r6, 21
 102:	078f      	br      	0x20	// 20 <xmodem_receive+0x20>
 104:	2b00      	subi      	r3, 1
 106:	64da      	cmpne      	r6, r3
 108:	0b90      	bt      	0x28	// 28 <xmodem_receive+0x28>
 10a:	3606      	movi      	r6, 6
 10c:	ea08000f 	movi      	r8, 15
 110:	9560      	ld.w      	r3, (r5, 0x0)
 112:	6c1b      	mov      	r0, r6
 114:	7bcd      	jsr      	r3
 116:	30fa      	movi      	r0, 250
 118:	9561      	ld.w      	r3, (r5, 0x4)
 11a:	1903      	addi      	r1, r14, 12
 11c:	4002      	lsli      	r0, r0, 2
 11e:	7bcd      	jsr      	r3
 120:	9883      	ld.w      	r4, (r14, 0xc)
 122:	e924ff7f 	bnez      	r4, 0x20	// 20 <xmodem_receive+0x20>
 126:	3842      	cmpnei      	r0, 2
 128:	0f99      	bf      	0x5a	// 5a <xmodem_receive+0x5a>
 12a:	3802      	cmphsi      	r0, 3
 12c:	0b8d      	bt      	0x46	// 46 <xmodem_receive+0x46>
 12e:	3841      	cmpnei      	r0, 1
 130:	0b78      	bt      	0x20	// 20 <xmodem_receive+0x20>
 132:	3480      	movi      	r4, 128
 134:	0795      	br      	0x5e	// 5e <xmodem_receive+0x5e>
 136:	0000      	.short	0x0000
 138:	00000000 	.long	0x00000000

Disassembly of section .text.xmodem_stop:

00000000 <xmodem_stop>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	9060      	ld.w      	r3, (r0, 0x0)
   6:	3018      	movi      	r0, 24
   8:	7bcd      	jsr      	r3
   a:	9460      	ld.w      	r3, (r4, 0x0)
   c:	3018      	movi      	r0, 24
   e:	7bcd      	jsr      	r3
  10:	9460      	ld.w      	r3, (r4, 0x0)
  12:	3018      	movi      	r0, 24
  14:	7bcd      	jsr      	r3
  16:	1491      	pop      	r4, r15
