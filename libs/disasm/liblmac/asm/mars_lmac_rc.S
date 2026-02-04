
disasm/liblmac/obj/mars_lmac_rc.o:     file format elf32-csky-little


Disassembly of section .text.grp_invalid_check:

00000000 <grp_invalid_check>:
   0:	104b      	lrw      	r2, 0x0	// 2c <grp_invalid_check+0x2c>
   2:	c4605483 	zext      	r3, r0, 4, 3
   6:	d8220308 	ld.b      	r1, (r2, 0x308)
   a:	d842034a 	ld.b      	r2, (r2, 0x34a)
   e:	e4422001 	andi      	r2, r2, 1
  12:	64c5      	cmplt      	r1, r3
  14:	c4000500 	mvc      	r0
  18:	3b40      	cmpnei      	r3, 0
  1a:	e9020005 	bez      	r2, 0x24	// 24 <grp_invalid_check+0x24>
  1e:	c4000c41 	inct      	r0, r0, 1
  22:	783c      	jmp      	r15
  24:	c4000c21 	incf      	r0, r0, 1
  28:	07fd      	br      	0x22	// 22 <grp_invalid_check+0x22>
  2a:	0000      	.short	0x0000
  2c:	00000000 	.long	0x00000000

Disassembly of section .text.prob_rate_update:

00000000 <prob_rate_update>:
   0:	14d7      	push      	r4-r10, r15
   2:	9083      	ld.w      	r4, (r0, 0xc)
   4:	6e07      	mov      	r8, r1
   6:	e9240006 	bnez      	r4, 0x12	// 12 <prob_rate_update+0x12>
   a:	101f      	lrw      	r0, 0x0	// 84 <hgprintf+0x84>
   c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  10:	1497      	pop      	r4-r10, r15
  12:	10fe      	lrw      	r7, 0x0	// 88 <prob_rate_update+0x88>
  14:	8f5f      	ld.h      	r2, (r7, 0x3e)
  16:	6449      	cmplt      	r2, r1
  18:	0c04      	bf      	0x20	// 20 <prob_rate_update+0x20>
  1a:	101d      	lrw      	r0, 0x0	// 8c <prob_rate_update+0x8c>
  1c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  20:	ea090020 	movi      	r9, 32
  24:	24bb      	addi      	r4, 188
  26:	ea8a001b 	lrw      	r10, 0x0	// 90 <prob_rate_update+0x90>
  2a:	8464      	ld.b      	r3, (r4, 0x4)
  2c:	e443201f 	andi      	r2, r3, 31
  30:	d04a0025 	ldr.b      	r5, (r10, r2 << 0)
  34:	e445201f 	andi      	r2, r5, 31
  38:	2300      	addi      	r3, 1
  3a:	d0470446 	ldr.h      	r6, (r7, r2 << 1)
  3e:	a464      	st.b      	r3, (r4, 0x4)
  40:	6c17      	mov      	r0, r5
  42:	7599      	zexth      	r6, r6
  44:	e0000000 	bsr      	0x0	// 0 <prob_rate_update>
  48:	e920000c 	bnez      	r0, 0x60	// 60 <prob_rate_update+0x60>
  4c:	d864006c 	ld.b      	r3, (r4, 0x6c)
  50:	654e      	cmpne      	r3, r5
  52:	0c07      	bf      	0x60	// 60 <prob_rate_update+0x60>
  54:	d8640070 	ld.b      	r3, (r4, 0x70)
  58:	654e      	cmpne      	r3, r5
  5a:	0c03      	bf      	0x60	// 60 <prob_rate_update+0x60>
  5c:	6619      	cmplt      	r6, r8
  5e:	0c0e      	bf      	0x7a	// 7a <prob_rate_update+0x7a>
  60:	e5291000 	subi      	r9, r9, 1
  64:	e929ffe3 	bnez      	r9, 0x2a	// 2a <prob_rate_update+0x2a>
  68:	d864006c 	ld.b      	r3, (r4, 0x6c)
  6c:	dc640074 	st.b      	r3, (r4, 0x74)
  70:	d8641035 	ld.h      	r3, (r4, 0x6a)
  74:	dc641039 	st.h      	r3, (r4, 0x72)
  78:	07cc      	br      	0x10	// 10 <prob_rate_update+0x10>
  7a:	dca40074 	st.b      	r5, (r4, 0x74)
  7e:	dcc41039 	st.h      	r6, (r4, 0x72)
  82:	07c7      	br      	0x10	// 10 <prob_rate_update+0x10>
	...

Disassembly of section .text.sta_rc_init:

00000000 <sta_rc_init>:
   0:	14d1      	push      	r4, r15
   2:	e900001d 	bez      	r0, 0x3c	// 3c <sta_rc_init+0x3c>
   6:	e48000bb 	addi      	r4, r0, 188
   a:	3278      	movi      	r2, 120
   c:	3100      	movi      	r1, 0
   e:	6c13      	mov      	r0, r4
  10:	e0000000 	bsr      	0x0	// 0 <memset>
  14:	106b      	lrw      	r3, 0x0	// 40 <sta_rc_init+0x40>
  16:	104c      	lrw      	r2, 0x0	// 44 <sta_rc_init+0x44>
  18:	d863034a 	ld.b      	r3, (r3, 0x34a)
  1c:	e4632001 	andi      	r3, r3, 1
  20:	3b40      	cmpnei      	r3, 0
  22:	64c3      	mvcv      	r3
  24:	4363      	lsli      	r3, r3, 3
  26:	d0620442 	ldr.h      	r2, (r2, r3 << 1)
  2a:	7489      	zexth      	r2, r2
  2c:	dc64006c 	st.b      	r3, (r4, 0x6c)
  30:	dc441035 	st.h      	r2, (r4, 0x6a)
  34:	dc640070 	st.b      	r3, (r4, 0x70)
  38:	dc441037 	st.h      	r2, (r4, 0x6e)
  3c:	1491      	pop      	r4, r15
	...

Disassembly of section .text.ah_ant_status:

00000000 <ah_ant_status>:
   0:	14d4      	push      	r4-r7, r15
   2:	1422      	subi      	r14, r14, 8
   4:	1242      	lrw      	r2, 0x0	// 10c <ah_ant_status+0x10c>
   6:	6dc3      	mov      	r7, r0
   8:	8260      	ld.b      	r3, (r2, 0x0)
   a:	2300      	addi      	r3, 1
   c:	74cc      	zextb      	r3, r3
   e:	3b03      	cmphsi      	r3, 4
  10:	6d87      	mov      	r6, r1
  12:	1280      	lrw      	r4, 0x0	// 110 <ah_ant_status+0x110>
  14:	12a0      	lrw      	r5, 0x0	// 114 <ah_ant_status+0x114>
  16:	083a      	bt      	0x8a	// 8a <ah_ant_status+0x8a>
  18:	a260      	st.b      	r3, (r2, 0x0)
  1a:	e9070050 	bez      	r7, 0xba	// ba <ah_ant_status+0xba>
  1e:	a5c1      	st.b      	r6, (r5, 0x1)
  20:	d8640875 	ld.b      	r3, (r4, 0x875)
  24:	e443200c 	andi      	r2, r3, 12
  28:	3a4c      	cmpnei      	r2, 12
  2a:	082e      	bt      	0x86	// 86 <ah_ant_status+0x86>
  2c:	d844202f 	ld.w      	r2, (r4, 0xbc)
  30:	3a41      	cmpnei      	r2, 1
  32:	082a      	bt      	0x86	// 86 <ah_ant_status+0x86>
  34:	d8254000 	ld.bs      	r1, (r5, 0x0)
  38:	d8454001 	ld.bs      	r2, (r5, 0x1)
  3c:	6449      	cmplt      	r2, r1
  3e:	0c40      	bf      	0xbe	// be <ah_ant_status+0xbe>
  40:	1116      	lrw      	r0, 0x0	// 118 <ah_ant_status+0x118>
  42:	6d43      	mov      	r5, r0
  44:	d9800000 	ld.b      	r12, (r0, 0x0)
  48:	e58c0000 	addi      	r12, r12, 1
  4c:	7730      	zextb      	r12, r12
  4e:	eb0c0004 	cmphsi      	r12, 5
  52:	dd800000 	st.b      	r12, (r0, 0x0)
  56:	0c16      	bf      	0x82	// 82 <ah_ant_status+0x82>
  58:	e4632010 	andi      	r3, r3, 16
  5c:	e903000b 	bez      	r3, 0x72	// 72 <ah_ant_status+0x72>
  60:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
  64:	e4632100 	andi      	r3, r3, 256
  68:	e9030005 	bez      	r3, 0x72	// 72 <ah_ant_status+0x72>
  6c:	110c      	lrw      	r0, 0x0	// 11c <hgprintf+0x11c>
  6e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  72:	d8440875 	ld.b      	r2, (r4, 0x875)
  76:	3300      	movi      	r3, 0
  78:	c4435c04 	ins      	r2, r3, 4, 4
  7c:	dc440875 	st.b      	r2, (r4, 0x875)
  80:	a560      	st.b      	r3, (r5, 0x0)
  82:	3300      	movi      	r3, 0
  84:	a561      	st.b      	r3, (r5, 0x1)
  86:	1402      	addi      	r14, r14, 8
  88:	1494      	pop      	r4-r7, r15
  8a:	3300      	movi      	r3, 0
  8c:	a260      	st.b      	r3, (r2, 0x0)
  8e:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
  92:	e4632100 	andi      	r3, r3, 256
  96:	e903ffc2 	bez      	r3, 0x1a	// 1a <ah_ant_status+0x1a>
  9a:	d8454001 	ld.bs      	r2, (r5, 0x1)
  9e:	b841      	st.w      	r2, (r14, 0x4)
  a0:	d8454000 	ld.bs      	r2, (r5, 0x0)
  a4:	d8640875 	ld.b      	r3, (r4, 0x875)
  a8:	b840      	st.w      	r2, (r14, 0x0)
  aa:	c4835483 	zext      	r3, r3, 4, 4
  ae:	6c87      	mov      	r2, r1
  b0:	6c43      	mov      	r1, r0
  b2:	101c      	lrw      	r0, 0x0	// 120 <ah_ant_status+0x120>
  b4:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  b8:	07b1      	br      	0x1a	// 1a <ah_ant_status+0x1a>
  ba:	a5c0      	st.b      	r6, (r5, 0x0)
  bc:	07b2      	br      	0x20	// 20 <ah_ant_status+0x20>
  be:	6485      	cmplt      	r1, r2
  c0:	0fe3      	bf      	0x86	// 86 <ah_ant_status+0x86>
  c2:	1016      	lrw      	r0, 0x0	// 118 <ah_ant_status+0x118>
  c4:	6d43      	mov      	r5, r0
  c6:	d9800001 	ld.b      	r12, (r0, 0x1)
  ca:	e58c0000 	addi      	r12, r12, 1
  ce:	7730      	zextb      	r12, r12
  d0:	eb0c0004 	cmphsi      	r12, 5
  d4:	dd800001 	st.b      	r12, (r0, 0x1)
  d8:	0c17      	bf      	0x106	// 106 <ah_ant_status+0x106>
  da:	e4632010 	andi      	r3, r3, 16
  de:	e923000b 	bnez      	r3, 0xf4	// f4 <ah_ant_status+0xf4>
  e2:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
  e6:	e4632100 	andi      	r3, r3, 256
  ea:	e9030005 	bez      	r3, 0xf4	// f4 <ah_ant_status+0xf4>
  ee:	100e      	lrw      	r0, 0x0	// 124 <hgprintf+0x124>
  f0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  f4:	d8640875 	ld.b      	r3, (r4, 0x875)
  f8:	3201      	movi      	r2, 1
  fa:	c4625c04 	ins      	r3, r2, 4, 4
  fe:	dc640875 	st.b      	r3, (r4, 0x875)
 102:	3300      	movi      	r3, 0
 104:	a561      	st.b      	r3, (r5, 0x1)
 106:	3300      	movi      	r3, 0
 108:	a560      	st.b      	r3, (r5, 0x0)
 10a:	07be      	br      	0x86	// 86 <ah_ant_status+0x86>
	...

Disassembly of section .text.ah_tx_status:

00000000 <ah_tx_status>:
   0:	14d4      	push      	r4-r7, r15
   2:	6d83      	mov      	r6, r0
   4:	d86e0014 	ld.b      	r3, (r14, 0x14)
   8:	d80e0018 	ld.b      	r0, (r14, 0x18)
   c:	2300      	addi      	r3, 1
   e:	e906008a 	bez      	r6, 0x122	// 122 <ah_tx_status+0x122>
  12:	e9010088 	bez      	r1, 0x122	// 122 <ah_tx_status+0x122>
  16:	40e3      	lsli      	r7, r0, 3
  18:	4363      	lsli      	r3, r3, 3
  1a:	e4e72040 	andi      	r7, r7, 64
  1e:	e4632018 	andi      	r3, r3, 24
  22:	6cdc      	or      	r3, r7
  24:	e4e02007 	andi      	r7, r0, 7
  28:	61cc      	addu      	r7, r3
  2a:	e48600bb 	addi      	r4, r6, 188
  2e:	5c7c      	addu      	r3, r4, r7
  30:	ea0c00ff 	movi      	r12, 255
  34:	d8030046 	ld.b      	r0, (r3, 0x46)
  38:	2000      	addi      	r0, 1
  3a:	7400      	zextb      	r0, r0
  3c:	dc030046 	st.b      	r0, (r3, 0x46)
  40:	d866202f 	ld.w      	r3, (r6, 0xbc)
  44:	c52c482c 	lsli      	r12, r12, 9
  48:	68f0      	and      	r3, r12
  4a:	eb431000 	cmpnei      	r3, 4096
  4e:	086d      	bt      	0x128	// 128 <ah_tx_status+0x128>
  50:	8464      	ld.b      	r3, (r4, 0x4)
  52:	2300      	addi      	r3, 1
  54:	74cc      	zextb      	r3, r3
  56:	3b1f      	cmphsi      	r3, 32
  58:	0866      	bt      	0x124	// 124 <ah_tx_status+0x124>
  5a:	a464      	st.b      	r3, (r4, 0x4)
  5c:	8c61      	ld.h      	r3, (r4, 0x2)
  5e:	c423550c 	zext      	r12, r3, 8, 1
  62:	eb0c0013 	cmphsi      	r12, 20
  66:	0c87      	bf      	0x174	// 174 <ah_tx_status+0x174>
  68:	ea0c0000 	movi      	r12, 0
  6c:	c46c5ce1 	ins      	r3, r12, 8, 1
  70:	ac61      	st.h      	r3, (r4, 0x2)
  72:	ea0c00ff 	movi      	r12, 255
  76:	d866202f 	ld.w      	r3, (r6, 0xbc)
  7a:	c52c482c 	lsli      	r12, r12, 9
  7e:	68f0      	and      	r3, r12
  80:	eb434000 	cmpnei      	r3, 16384
  84:	0878      	bt      	0x174	// 174 <ah_tx_status+0x174>
  86:	3500      	movi      	r5, 0
  88:	d866202f 	ld.w      	r3, (r6, 0xbc)
  8c:	3200      	movi      	r2, 0
  8e:	c4625ce9 	ins      	r3, r2, 16, 9
  92:	dc66202f 	st.w      	r3, (r6, 0xbc)
  96:	d804006c 	ld.b      	r0, (r4, 0x6c)
  9a:	641e      	cmpne      	r7, r0
  9c:	0806      	bt      	0xa8	// a8 <ah_tx_status+0xa8>
  9e:	d864006d 	ld.b      	r3, (r4, 0x6d)
  a2:	2300      	addi      	r3, 1
  a4:	dc64006d 	st.b      	r3, (r4, 0x6d)
  a8:	d8640070 	ld.b      	r3, (r4, 0x70)
  ac:	64de      	cmpne      	r7, r3
  ae:	0806      	bt      	0xba	// ba <ah_tx_status+0xba>
  b0:	d8640071 	ld.b      	r3, (r4, 0x71)
  b4:	2300      	addi      	r3, 1
  b6:	dc640071 	st.b      	r3, (r4, 0x71)
  ba:	d866105e 	ld.h      	r3, (r6, 0xbc)
  be:	e46321fe 	andi      	r3, r3, 510
  c2:	3b52      	cmpnei      	r3, 18
  c4:	080e      	bt      	0xe0	// e0 <ah_tx_status+0xe0>
  c6:	641e      	cmpne      	r7, r0
  c8:	080c      	bt      	0xe0	// e0 <ah_tx_status+0xe0>
  ca:	d864006d 	ld.b      	r3, (r4, 0x6d)
  ce:	3b1e      	cmphsi      	r3, 31
  d0:	0c08      	bf      	0xe0	// e0 <ah_tx_status+0xe0>
  d2:	5866      	addi      	r3, r0, 2
  d4:	60cc      	addu      	r3, r3
  d6:	60d0      	addu      	r3, r4
  d8:	8b61      	ld.h      	r3, (r3, 0x2)
  da:	eb0313ff 	cmphsi      	r3, 5120
  de:	0c03      	bf      	0xe4	// e4 <ah_tx_status+0xe4>
  e0:	e9050089 	bez      	r5, 0x1f2	// 1f2 <ah_tx_status+0x1f2>
  e4:	6c1b      	mov      	r0, r6
  e6:	e0000000 	bsr      	0x0	// 0 <ah_tx_status>
  ea:	031d      	lrw      	r0, 0x0	// 2f0 <hgprintf+0x2f0>
  ec:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  f0:	037e      	lrw      	r3, 0x0	// 2f4 <ah_tx_status+0x2f4>
  f2:	d86320ee 	ld.w      	r3, (r3, 0x3b8)
  f6:	e4632002 	andi      	r3, r3, 2
  fa:	e903000d 	bez      	r3, 0x114	// 114 <ah_tx_status+0x114>
  fe:	5f66      	addi      	r3, r7, 2
 100:	60cc      	addu      	r3, r3
 102:	60d0      	addu      	r3, r4
 104:	d844006d 	ld.b      	r2, (r4, 0x6d)
 108:	8b61      	ld.h      	r3, (r3, 0x2)
 10a:	4b68      	lsri      	r3, r3, 8
 10c:	6c5f      	mov      	r1, r7
 10e:	131b      	lrw      	r0, 0x0	// 2f8 <ah_tx_status+0x2f8>
 110:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 114:	8c61      	ld.h      	r3, (r4, 0x2)
 116:	c4235502 	zext      	r2, r3, 8, 1
 11a:	2200      	addi      	r2, 1
 11c:	c4625ce1 	ins      	r3, r2, 8, 1
 120:	ac61      	st.h      	r3, (r4, 0x2)
 122:	1494      	pop      	r4-r7, r15
 124:	3300      	movi      	r3, 0
 126:	079a      	br      	0x5a	// 5a <ah_tx_status+0x5a>
 128:	eb434000 	cmpnei      	r3, 16384
 12c:	0824      	bt      	0x174	// 174 <ah_tx_status+0x174>
 12e:	3801      	cmphsi      	r0, 2
 130:	0c20      	bf      	0x170	// 170 <ah_tx_status+0x170>
 132:	5863      	subi      	r3, r0, 1
 134:	c4e7002d 	addu      	r13, r7, r7
 138:	6358      	addu      	r13, r6
 13a:	ea0c0064 	movi      	r12, 100
 13e:	7f08      	mult      	r12, r2
 140:	d8ad1061 	ld.h      	r5, (r13, 0xc2)
 144:	c50c482c 	lsli      	r12, r12, 8
 148:	7d4c      	mult      	r5, r3
 14a:	c42c802c 	divu      	r12, r12, r1
 14e:	2300      	addi      	r3, 1
 150:	6314      	addu      	r12, r5
 152:	c46c802c 	divu      	r12, r12, r3
 156:	dd8d1061 	st.h      	r12, (r13, 0xc2)
 15a:	d866105e 	ld.h      	r3, (r6, 0xbc)
 15e:	c423550c 	zext      	r12, r3, 8, 1
 162:	e58c0000 	addi      	r12, r12, 1
 166:	c46c5ce1 	ins      	r3, r12, 8, 1
 16a:	dc66105e 	st.h      	r3, (r6, 0xbc)
 16e:	0782      	br      	0x72	// 72 <ah_tx_status+0x72>
 170:	3300      	movi      	r3, 0
 172:	07e1      	br      	0x134	// 134 <ah_tx_status+0x134>
 174:	ea0c0064 	movi      	r12, 100
 178:	c5828423 	mult      	r3, r2, r12
 17c:	c4e7002d 	addu      	r13, r7, r7
 180:	6358      	addu      	r13, r6
 182:	4368      	lsli      	r3, r3, 8
 184:	c4238023 	divu      	r3, r3, r1
 188:	3106      	movi      	r1, 6
 18a:	7cc4      	mult      	r3, r1
 18c:	327a      	movi      	r2, 122
 18e:	d82d1061 	ld.h      	r1, (r13, 0xc2)
 192:	7c48      	mult      	r1, r2
 194:	60c4      	addu      	r3, r1
 196:	d82610e3 	ld.h      	r1, (r6, 0x1c6)
 19a:	3909      	cmphsi      	r1, 10
 19c:	4b67      	lsri      	r3, r3, 7
 19e:	dc6d1061 	st.h      	r3, (r13, 0xc2)
 1a2:	0c26      	bf      	0x1ee	// 1ee <ah_tx_status+0x1ee>
 1a4:	d84610ea 	ld.h      	r2, (r6, 0x1d4)
 1a8:	6448      	cmphs      	r2, r1
 1aa:	0822      	bt      	0x1ee	// 1ee <ah_tx_status+0x1ee>
 1ac:	5969      	subu      	r3, r1, r2
 1ae:	7cf0      	mult      	r3, r12
 1b0:	c4238043 	divs      	r3, r3, r1
 1b4:	74cc      	zextb      	r3, r3
 1b6:	d846105e 	ld.h      	r2, (r6, 0xbc)
 1ba:	e44221fe 	andi      	r2, r2, 510
 1be:	3a52      	cmpnei      	r2, 18
 1c0:	0b63      	bt      	0x86	// 86 <ah_tx_status+0x86>
 1c2:	381e      	cmphsi      	r0, 31
 1c4:	0f61      	bf      	0x86	// 86 <ah_tx_status+0x86>
 1c6:	d84640b4 	ld.bs      	r2, (r6, 0xb4)
 1ca:	3a34      	cmplti      	r2, 21
 1cc:	0b5d      	bt      	0x86	// 86 <ah_tx_status+0x86>
 1ce:	4f43      	lsri      	r2, r7, 3
 1d0:	e4422008 	andi      	r2, r2, 8
 1d4:	e4272007 	andi      	r1, r7, 7
 1d8:	6c84      	or      	r2, r1
 1da:	3a03      	cmphsi      	r2, 4
 1dc:	0b55      	bt      	0x86	// 86 <ah_tx_status+0x86>
 1de:	eb03005a 	cmphsi      	r3, 91
 1e2:	0f52      	bf      	0x86	// 86 <ah_tx_status+0x86>
 1e4:	1206      	lrw      	r0, 0x0	// 2fc <ah_tx_status+0x2fc>
 1e6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1ea:	3501      	movi      	r5, 1
 1ec:	074e      	br      	0x88	// 88 <ah_tx_status+0x88>
 1ee:	3300      	movi      	r3, 0
 1f0:	07e3      	br      	0x1b6	// 1b6 <ah_tx_status+0x1b6>
 1f2:	6c97      	mov      	r2, r5
 1f4:	6cd7      	mov      	r3, r5
 1f6:	ea8d0043 	lrw      	r13, 0x0	// 300 <ah_tx_status+0x300>
 1fa:	5e2c      	addu      	r1, r6, r3
 1fc:	d9810102 	ld.b      	r12, (r1, 0x102)
 200:	e90c0010 	bez      	r12, 0x220	// 220 <ah_tx_status+0x220>
 204:	604c      	addu      	r1, r3
 206:	5bec      	addu      	r7, r3, r3
 208:	d9811061 	ld.h      	r12, (r1, 0xc2)
 20c:	e90c000a 	bez      	r12, 0x220	// 220 <ah_tx_status+0x220>
 210:	d1a70421 	ldr.h      	r1, (r7, r13 << 0)
 214:	7445      	zexth      	r1, r1
 216:	7c70      	mult      	r1, r12
 218:	6449      	cmplt      	r2, r1
 21a:	0c03      	bf      	0x220	// 220 <ah_tx_status+0x220>
 21c:	6c87      	mov      	r2, r1
 21e:	6d4f      	mov      	r5, r3
 220:	2300      	addi      	r3, 1
 222:	eb430020 	cmpnei      	r3, 32
 226:	0bea      	bt      	0x1fa	// 1fa <ah_tx_status+0x1fa>
 228:	e9020020 	bez      	r2, 0x268	// 268 <ah_tx_status+0x268>
 22c:	6542      	cmpne      	r0, r5
 22e:	0c1d      	bf      	0x268	// 268 <ah_tx_status+0x268>
 230:	1171      	lrw      	r3, 0x0	// 2f4 <ah_tx_status+0x2f4>
 232:	d86320ee 	ld.w      	r3, (r3, 0x3b8)
 236:	e4632002 	andi      	r3, r3, 2
 23a:	e903000b 	bez      	r3, 0x250	// 250 <ah_tx_status+0x250>
 23e:	5d66      	addi      	r3, r5, 2
 240:	60cc      	addu      	r3, r3
 242:	60d0      	addu      	r3, r4
 244:	5248      	asri      	r2, r2, 8
 246:	8b61      	ld.h      	r3, (r3, 0x2)
 248:	6c57      	mov      	r1, r5
 24a:	110f      	lrw      	r0, 0x0	// 304 <ah_tx_status+0x304>
 24c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 250:	3300      	movi      	r3, 0
 252:	dc64006d 	st.b      	r3, (r4, 0x6d)
 256:	dca4006c 	st.b      	r5, (r4, 0x6c)
 25a:	e4a5201f 	andi      	r5, r5, 31
 25e:	1169      	lrw      	r3, 0x0	// 300 <ah_tx_status+0x300>
 260:	d0a30443 	ldr.h      	r3, (r3, r5 << 1)
 264:	dc641035 	st.h      	r3, (r4, 0x6a)
 268:	3500      	movi      	r5, 0
 26a:	d984006c 	ld.b      	r12, (r4, 0x6c)
 26e:	6c97      	mov      	r2, r5
 270:	6cd7      	mov      	r3, r5
 272:	ea8d0024 	lrw      	r13, 0x0	// 300 <ah_tx_status+0x300>
 276:	64f2      	cmpne      	r12, r3
 278:	0c15      	bf      	0x2a2	// 2a2 <ah_tx_status+0x2a2>
 27a:	5e2c      	addu      	r1, r6, r3
 27c:	d8010102 	ld.b      	r0, (r1, 0x102)
 280:	e9000011 	bez      	r0, 0x2a2	// 2a2 <ah_tx_status+0x2a2>
 284:	604c      	addu      	r1, r3
 286:	d8011061 	ld.h      	r0, (r1, 0xc2)
 28a:	e900000c 	bez      	r0, 0x2a2	// 2a2 <ah_tx_status+0x2a2>
 28e:	e423201f 	andi      	r1, r3, 31
 292:	d02d0441 	ldr.h      	r1, (r13, r1 << 1)
 296:	7445      	zexth      	r1, r1
 298:	7c40      	mult      	r1, r0
 29a:	6449      	cmplt      	r2, r1
 29c:	0c03      	bf      	0x2a2	// 2a2 <ah_tx_status+0x2a2>
 29e:	6c87      	mov      	r2, r1
 2a0:	6d4f      	mov      	r5, r3
 2a2:	2300      	addi      	r3, 1
 2a4:	eb430020 	cmpnei      	r3, 32
 2a8:	0be7      	bt      	0x276	// 276 <ah_tx_status+0x276>
 2aa:	e902ff35 	bez      	r2, 0x114	// 114 <ah_tx_status+0x114>
 2ae:	d8640070 	ld.b      	r3, (r4, 0x70)
 2b2:	654e      	cmpne      	r3, r5
 2b4:	0f30      	bf      	0x114	// 114 <ah_tx_status+0x114>
 2b6:	1070      	lrw      	r3, 0x0	// 2f4 <ah_tx_status+0x2f4>
 2b8:	d86320ee 	ld.w      	r3, (r3, 0x3b8)
 2bc:	e4632002 	andi      	r3, r3, 2
 2c0:	e903000b 	bez      	r3, 0x2d6	// 2d6 <ah_tx_status+0x2d6>
 2c4:	5d66      	addi      	r3, r5, 2
 2c6:	60cc      	addu      	r3, r3
 2c8:	60d0      	addu      	r3, r4
 2ca:	5248      	asri      	r2, r2, 8
 2cc:	8b61      	ld.h      	r3, (r3, 0x2)
 2ce:	6c57      	mov      	r1, r5
 2d0:	100e      	lrw      	r0, 0x0	// 308 <ah_tx_status+0x308>
 2d2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2d6:	3300      	movi      	r3, 0
 2d8:	dc640071 	st.b      	r3, (r4, 0x71)
 2dc:	dca40070 	st.b      	r5, (r4, 0x70)
 2e0:	e4a5201f 	andi      	r5, r5, 31
 2e4:	1067      	lrw      	r3, 0x0	// 300 <ah_tx_status+0x300>
 2e6:	d0a30443 	ldr.h      	r3, (r3, r5 << 1)
 2ea:	dc641037 	st.h      	r3, (r4, 0x6e)
 2ee:	0713      	br      	0x114	// 114 <ah_tx_status+0x114>
	...

Disassembly of section .text.ah_get_rate:

00000000 <ah_get_rate>:
   0:	14d7      	push      	r4-r10, r15
   2:	1421      	subi      	r14, r14, 4
   4:	90c3      	ld.w      	r6, (r0, 0xc)
   6:	e9060011 	bez      	r6, 0x28	// 28 <ah_get_rate+0x28>
   a:	ea230a00 	movih      	r3, 2560
   e:	3ba9      	bseti      	r3, 9
  10:	9049      	ld.w      	r2, (r0, 0x24)
  12:	688c      	and      	r2, r3
  14:	3380      	movi      	r3, 128
  16:	4372      	lsli      	r3, r3, 18
  18:	64ca      	cmpne      	r2, r3
  1a:	0807      	bt      	0x28	// 28 <ah_get_rate+0x28>
  1c:	d8600024 	ld.b      	r3, (r0, 0x24)
  20:	e4632003 	andi      	r3, r3, 3
  24:	3b41      	cmpnei      	r3, 1
  26:	0836      	bt      	0x92	// 92 <ah_get_rate+0x92>
  28:	0342      	lrw      	r2, 0x0	// 29c <ah_get_rate+0x29c>
  2a:	d8620875 	ld.b      	r3, (r2, 0x875)
  2e:	e4632002 	andi      	r3, r3, 2
  32:	e903002e 	bez      	r3, 0x8e	// 8e <ah_get_rate+0x8e>
  36:	d8620867 	ld.b      	r3, (r2, 0x867)
  3a:	3b43      	cmpnei      	r3, 3
  3c:	c4000503 	mvc      	r3
  40:	74cc      	zextb      	r3, r3
  42:	d8200027 	ld.b      	r1, (r0, 0x27)
  46:	e4212002 	andi      	r1, r1, 2
  4a:	e9010008 	bez      	r1, 0x5a	// 5a <ah_get_rate+0x5a>
  4e:	d980003d 	ld.b      	r12, (r0, 0x3d)
  52:	eb4c00ff 	cmpnei      	r12, 255
  56:	c46c0c40 	inct      	r3, r12, 0
  5a:	d842034a 	ld.b      	r2, (r2, 0x34a)
  5e:	6c8a      	nor      	r2, r2
  60:	e4422001 	andi      	r2, r2, 1
  64:	e901000a 	bez      	r1, 0x78	// 78 <ah_get_rate+0x78>
  68:	d880003c 	ld.b      	r4, (r0, 0x3c)
  6c:	eb4400ff 	cmpnei      	r4, 255
  70:	0c04      	bf      	0x78	// 78 <ah_get_rate+0x78>
  72:	5c42      	addi      	r2, r4, 1
  74:	e4422003 	andi      	r2, r2, 3
  78:	4383      	lsli      	r4, r3, 3
  7a:	e4842040 	andi      	r4, r4, 64
  7e:	4243      	lsli      	r2, r2, 3
  80:	6c90      	or      	r2, r4
  82:	e4632007 	andi      	r3, r3, 7
  86:	5a8c      	addu      	r4, r2, r3
  88:	6c13      	mov      	r0, r4
  8a:	1401      	addi      	r14, r14, 4
  8c:	1497      	pop      	r4-r10, r15
  8e:	3301      	movi      	r3, 1
  90:	07d9      	br      	0x42	// 42 <ah_get_rate+0x42>
  92:	d82600bc 	ld.b      	r1, (r6, 0xbc)
  96:	e4212001 	andi      	r1, r1, 1
  9a:	e4a600bb 	addi      	r5, r6, 188
  9e:	e901000c 	bez      	r1, 0xb6	// b6 <ah_get_rate+0xb6>
  a2:	d8850068 	ld.b      	r4, (r5, 0x68)
  a6:	d866202f 	ld.w      	r3, (r6, 0xbc)
  aa:	3201      	movi      	r2, 1
  ac:	c4625ce9 	ins      	r3, r2, 16, 9
  b0:	dc66202f 	st.w      	r3, (r6, 0xbc)
  b4:	07ea      	br      	0x88	// 88 <ah_get_rate+0x88>
  b6:	d866105e 	ld.h      	r3, (r6, 0xbc)
  ba:	c4235503 	zext      	r3, r3, 8, 1
  be:	3b08      	cmphsi      	r3, 9
  c0:	0849      	bt      	0x152	// 152 <ah_get_rate+0x152>
  c2:	3400      	movi      	r4, 0
  c4:	2c00      	subi      	r4, 1
  c6:	ea890077 	lrw      	r9, 0x0	// 2a0 <ah_get_rate+0x2a0>
  ca:	d9051000 	ld.h      	r8, (r5, 0x0)
  ce:	c4285507 	zext      	r7, r8, 8, 1
  d2:	3f08      	cmphsi      	r7, 9
  d4:	0c32      	bf      	0x138	// 138 <ah_get_rate+0x138>
  d6:	1372      	lrw      	r3, 0x0	// 29c <ah_get_rate+0x29c>
  d8:	d86320ee 	ld.w      	r3, (r3, 0x3b8)
  dc:	e4632002 	andi      	r3, r3, 2
  e0:	e9030027 	bez      	r3, 0x12e	// 12e <ah_get_rate+0x12e>
  e4:	1310      	lrw      	r0, 0x0	// 2a4 <hgprintf+0x2a4>
  e6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ea:	e50600c1 	addi      	r8, r6, 194
  ee:	3700      	movi      	r7, 0
  f0:	ea89006e 	lrw      	r9, 0x0	// 2a8 <ah_get_rate+0x2a8>
  f4:	ea8a006e 	lrw      	r10, 0x0	// 2ac <ah_get_rate+0x2ac>
  f8:	5e7c      	addu      	r3, r6, r7
  fa:	d8430102 	ld.b      	r2, (r3, 0x102)
  fe:	e9220006 	bnez      	r2, 0x10a	// 10a <ah_get_rate+0x10a>
 102:	d8681000 	ld.h      	r3, (r8, 0x0)
 106:	e903000e 	bez      	r3, 0x122	// 122 <ah_get_rate+0x122>
 10a:	d8281000 	ld.h      	r1, (r8, 0x0)
 10e:	d0e90443 	ldr.h      	r3, (r9, r7 << 1)
 112:	4928      	lsri      	r1, r1, 8
 114:	74cd      	zexth      	r3, r3
 116:	b820      	st.w      	r1, (r14, 0x0)
 118:	7cc4      	mult      	r3, r1
 11a:	6c2b      	mov      	r0, r10
 11c:	6c5f      	mov      	r1, r7
 11e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 122:	2700      	addi      	r7, 1
 124:	eb470020 	cmpnei      	r7, 32
 128:	e5080001 	addi      	r8, r8, 2
 12c:	0be6      	bt      	0xf8	// f8 <ah_get_rate+0xf8>
 12e:	d865006c 	ld.b      	r3, (r5, 0x6c)
 132:	dc650074 	st.b      	r3, (r5, 0x74)
 136:	07a9      	br      	0x88	// 88 <ah_get_rate+0x88>
 138:	d0e90024 	ldr.b      	r4, (r9, r7 << 0)
 13c:	6c13      	mov      	r0, r4
 13e:	e0000000 	bsr      	0x0	// 0 <ah_get_rate>
 142:	e9000096 	bez      	r0, 0x26e	// 26e <ah_get_rate+0x26e>
 146:	2700      	addi      	r7, 1
 148:	c5075ce1 	ins      	r8, r7, 8, 1
 14c:	dd051000 	st.h      	r8, (r5, 0x0)
 150:	07bd      	br      	0xca	// ca <ah_get_rate+0xca>
 152:	8d41      	ld.h      	r2, (r5, 0x2)
 154:	c422550c 	zext      	r12, r2, 8, 1
 158:	eb0c0013 	cmphsi      	r12, 20
 15c:	d8600028 	ld.b      	r3, (r0, 0x28)
 160:	087b      	bt      	0x256	// 256 <ah_get_rate+0x256>
 162:	740c      	zextb      	r0, r3
 164:	3802      	cmphsi      	r0, 3
 166:	0c07      	bf      	0x174	// 174 <ah_get_rate+0x174>
 168:	e58c0001 	addi      	r12, r12, 2
 16c:	6ccb      	mov      	r3, r2
 16e:	c46c5ce1 	ins      	r3, r12, 8, 1
 172:	ad61      	st.h      	r3, (r5, 0x2)
 174:	12ca      	lrw      	r6, 0x0	// 29c <ah_get_rate+0x29c>
 176:	d8260311 	ld.b      	r1, (r6, 0x311)
 17a:	3941      	cmpnei      	r1, 1
 17c:	0818      	bt      	0x1ac	// 1ac <ah_get_rate+0x1ac>
 17e:	d8660313 	ld.b      	r3, (r6, 0x313)
 182:	3b03      	cmphsi      	r3, 4
 184:	d885006c 	ld.b      	r4, (r5, 0x6c)
 188:	0c09      	bf      	0x19a	// 19a <ah_get_rate+0x19a>
 18a:	5b43      	subi      	r2, r3, 1
 18c:	6481      	cmplt      	r0, r2
 18e:	0c62      	bf      	0x252	// 252 <ah_get_rate+0x252>
 190:	2b02      	subi      	r3, 3
 192:	64c1      	cmplt      	r0, r3
 194:	0803      	bt      	0x19a	// 19a <ah_get_rate+0x19a>
 196:	d8850070 	ld.b      	r4, (r5, 0x70)
 19a:	d866036e 	ld.b      	r3, (r6, 0x36e)
 19e:	e4632040 	andi      	r3, r3, 64
 1a2:	e903ff73 	bez      	r3, 0x88	// 88 <ah_get_rate+0x88>
 1a6:	d885006c 	ld.b      	r4, (r5, 0x6c)
 1aa:	076f      	br      	0x88	// 88 <ah_get_rate+0x88>
 1ac:	3942      	cmpnei      	r1, 2
 1ae:	081e      	bt      	0x1ea	// 1ea <ah_get_rate+0x1ea>
 1b0:	d885006c 	ld.b      	r4, (r5, 0x6c)
 1b4:	5463      	asri      	r3, r4, 3
 1b6:	e4232003 	andi      	r1, r3, 3
 1ba:	e4842007 	andi      	r4, r4, 7
 1be:	e4632008 	andi      	r3, r3, 8
 1c2:	6cd0      	or      	r3, r4
 1c4:	5843      	subi      	r2, r0, 1
 1c6:	3901      	cmphsi      	r1, 2
 1c8:	7488      	zextb      	r2, r2
 1ca:	085a      	bt      	0x27e	// 27e <ah_get_rate+0x27e>
 1cc:	3b01      	cmphsi      	r3, 2
 1ce:	085f      	bt      	0x28c	// 28c <ah_get_rate+0x28c>
 1d0:	4383      	lsli      	r4, r3, 3
 1d2:	4123      	lsli      	r1, r1, 3
 1d4:	e4842040 	andi      	r4, r4, 64
 1d8:	e4212018 	andi      	r1, r1, 24
 1dc:	6d04      	or      	r4, r1
 1de:	e4632007 	andi      	r3, r3, 7
 1e2:	610c      	addu      	r4, r3
 1e4:	07db      	br      	0x19a	// 19a <ah_get_rate+0x19a>
 1e6:	3301      	movi      	r3, 1
 1e8:	07f4      	br      	0x1d0	// 1d0 <ah_get_rate+0x1d0>
 1ea:	3943      	cmpnei      	r1, 3
 1ec:	082d      	bt      	0x246	// 246 <ah_get_rate+0x246>
 1ee:	d825006c 	ld.b      	r1, (r5, 0x6c)
 1f2:	5143      	asri      	r2, r1, 3
 1f4:	e4622008 	andi      	r3, r2, 8
 1f8:	e4212007 	andi      	r1, r1, 7
 1fc:	e4822003 	andi      	r4, r2, 3
 200:	6cc4      	or      	r3, r1
 202:	e920000c 	bnez      	r0, 0x21a	// 21a <ah_get_rate+0x21a>
 206:	4484      	lsli      	r4, r4, 4
 208:	60d0      	addu      	r3, r4
 20a:	c4635464 	zext      	r4, r3, 3, 3
 20e:	4b41      	lsri      	r2, r3, 1
 210:	4486      	lsli      	r4, r4, 6
 212:	e4422018 	andi      	r2, r2, 24
 216:	6d08      	or      	r4, r2
 218:	07e3      	br      	0x1de	// 1de <ah_get_rate+0x1de>
 21a:	3841      	cmpnei      	r0, 1
 21c:	4362      	lsli      	r3, r3, 2
 21e:	0806      	bt      	0x22a	// 22a <ah_get_rate+0x22a>
 220:	1144      	lrw      	r2, 0x0	// 2b0 <ah_get_rate+0x2b0>
 222:	60c8      	addu      	r3, r2
 224:	d0830023 	ldr.b      	r3, (r3, r4 << 0)
 228:	07f1      	br      	0x20a	// 20a <ah_get_rate+0x20a>
 22a:	3842      	cmpnei      	r0, 2
 22c:	0803      	bt      	0x232	// 232 <ah_get_rate+0x232>
 22e:	1142      	lrw      	r2, 0x0	// 2b4 <ah_get_rate+0x2b4>
 230:	07f9      	br      	0x222	// 222 <ah_get_rate+0x222>
 232:	3843      	cmpnei      	r0, 3
 234:	0803      	bt      	0x23a	// 23a <ah_get_rate+0x23a>
 236:	1141      	lrw      	r2, 0x0	// 2b8 <ah_get_rate+0x2b8>
 238:	07f5      	br      	0x222	// 222 <ah_get_rate+0x222>
 23a:	3844      	cmpnei      	r0, 4
 23c:	0803      	bt      	0x242	// 242 <ah_get_rate+0x242>
 23e:	1140      	lrw      	r2, 0x0	// 2bc <ah_get_rate+0x2bc>
 240:	07f1      	br      	0x222	// 222 <ah_get_rate+0x222>
 242:	1140      	lrw      	r2, 0x0	// 2c0 <ah_get_rate+0x2c0>
 244:	07ef      	br      	0x222	// 222 <ah_get_rate+0x222>
 246:	1100      	lrw      	r0, 0x0	// 2c4 <ah_get_rate+0x2c4>
 248:	3400      	movi      	r4, 0
 24a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 24e:	2c00      	subi      	r4, 1
 250:	07a5      	br      	0x19a	// 19a <ah_get_rate+0x19a>
 252:	3409      	movi      	r4, 9
 254:	07a3      	br      	0x19a	// 19a <ah_get_rate+0x19a>
 256:	e9230004 	bnez      	r3, 0x25e	// 25e <ah_get_rate+0x25e>
 25a:	d8251035 	ld.h      	r1, (r5, 0x6a)
 25e:	e0000000 	bsr      	0x0	// 0 <ah_get_rate>
 262:	d8850074 	ld.b      	r4, (r5, 0x74)
 266:	d866202f 	ld.w      	r3, (r6, 0xbc)
 26a:	3208      	movi      	r2, 8
 26c:	0720      	br      	0xac	// ac <ah_get_rate+0xac>
 26e:	9560      	ld.w      	r3, (r5, 0x0)
 270:	3220      	movi      	r2, 32
 272:	c4625ce9 	ins      	r3, r2, 16, 9
 276:	dc850074 	st.b      	r4, (r5, 0x74)
 27a:	b560      	st.w      	r3, (r5, 0x0)
 27c:	0706      	br      	0x88	// 88 <ah_get_rate+0x88>
 27e:	eb4200ff 	cmpnei      	r2, 255
 282:	0fa7      	bf      	0x1d0	// 1d0 <ah_get_rate+0x1d0>
 284:	2900      	subi      	r1, 1
 286:	7444      	zextb      	r1, r1
 288:	2a00      	subi      	r2, 1
 28a:	079e      	br      	0x1c6	// 1c6 <ah_get_rate+0x1c6>
 28c:	eb4200ff 	cmpnei      	r2, 255
 290:	0fa0      	bf      	0x1d0	// 1d0 <ah_get_rate+0x1d0>
 292:	3b42      	cmpnei      	r3, 2
 294:	0fa9      	bf      	0x1e6	// 1e6 <ah_get_rate+0x1e6>
 296:	2b01      	subi      	r3, 2
 298:	74cc      	zextb      	r3, r3
 29a:	07f7      	br      	0x288	// 288 <ah_get_rate+0x288>
	...

Disassembly of section .text.lmac_rc_init:

00000000 <lmac_rc_init>:
   0:	106d      	lrw      	r3, 0x0	// 34 <lmac_rc_init+0x34>
   2:	3200      	movi      	r2, 0
   4:	dc430870 	st.b      	r2, (r3, 0x870)
   8:	320a      	movi      	r2, 10
   a:	106c      	lrw      	r3, 0x0	// 38 <lmac_rc_init+0x38>
   c:	3000      	movi      	r0, 0
   e:	a340      	st.b      	r2, (r3, 0x0)
  10:	320c      	movi      	r2, 12
  12:	a341      	st.b      	r2, (r3, 0x1)
  14:	320e      	movi      	r2, 14
  16:	a342      	st.b      	r2, (r3, 0x2)
  18:	3212      	movi      	r2, 18
  1a:	a343      	st.b      	r2, (r3, 0x3)
  1c:	3214      	movi      	r2, 20
  1e:	a344      	st.b      	r2, (r3, 0x4)
  20:	3216      	movi      	r2, 22
  22:	a345      	st.b      	r2, (r3, 0x5)
  24:	321a      	movi      	r2, 26
  26:	a346      	st.b      	r2, (r3, 0x6)
  28:	321c      	movi      	r2, 28
  2a:	a347      	st.b      	r2, (r3, 0x7)
  2c:	321e      	movi      	r2, 30
  2e:	a348      	st.b      	r2, (r3, 0x8)
  30:	783c      	jmp      	r15
	...
