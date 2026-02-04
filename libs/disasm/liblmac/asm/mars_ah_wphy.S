
disasm/liblmac/obj/mars_ah_wphy.o:     file format elf32-csky-little


Disassembly of section .text.config_dpd_ram_sel:

00000000 <config_dpd_ram_sel>:
   0:	14c3      	push      	r4-r6
   2:	107f      	lrw      	r3, 0x0	// 7c <config_dpd_ram_sel+0x7c>
   4:	c6e0482d 	lsli      	r13, r0, 23
   8:	9334      	ld.w      	r1, (r3, 0x50)
   a:	ea234002 	movih      	r3, 16386
   e:	3bae      	bseti      	r3, 14
  10:	4002      	lsli      	r0, r0, 2
  12:	93c0      	ld.w      	r6, (r3, 0x0)
  14:	9340      	ld.w      	r2, (r3, 0x0)
  16:	3a8c      	bclri      	r2, 12
  18:	b340      	st.w      	r2, (r3, 0x0)
  1a:	3280      	movi      	r2, 128
  1c:	4250      	lsli      	r2, r2, 16
  1e:	6b48      	and      	r13, r2
  20:	ea0c0000 	movi      	r12, 0
  24:	3480      	movi      	r4, 128
  26:	c6cd284d 	bseti      	r13, r13, 22
  2a:	6004      	addu      	r0, r1
  2c:	6cb3      	mov      	r2, r12
  2e:	448f      	lsli      	r4, r4, 15
  30:	d1800905 	ldr.w      	r5, (r0, r12 << 3)
  34:	c70c4821 	lsli      	r1, r12, 24
  38:	6c74      	or      	r1, r13
  3a:	c4055685 	zext      	r5, r5, 20, 0
  3e:	6c54      	or      	r1, r5
  40:	dc232085 	st.w      	r1, (r3, 0x214)
  44:	d8a32085 	ld.w      	r5, (r3, 0x214)
  48:	6950      	and      	r5, r4
  4a:	e9250009 	bnez      	r5, 0x5c	// 5c <config_dpd_ram_sel+0x5c>
  4e:	e58c0000 	addi      	r12, r12, 1
  52:	eb4c00d8 	cmpnei      	r12, 216
  56:	0bed      	bt      	0x30	// 30 <config_dpd_ram_sel+0x30>
  58:	b3c0      	st.w      	r6, (r3, 0x0)
  5a:	1483      	pop      	r4-r6
  5c:	eb0200ff 	cmphsi      	r2, 256
  60:	0804      	bt      	0x68	// 68 <config_dpd_ram_sel+0x68>
  62:	2200      	addi      	r2, 1
  64:	7489      	zexth      	r2, r2
  66:	07ef      	br      	0x44	// 44 <config_dpd_ram_sel+0x44>
  68:	d8432085 	ld.w      	r2, (r3, 0x214)
  6c:	3a96      	bclri      	r2, 22
  6e:	dc432085 	st.w      	r2, (r3, 0x214)
  72:	dc232085 	st.w      	r1, (r3, 0x214)
  76:	3200      	movi      	r2, 0
  78:	07e6      	br      	0x44	// 44 <config_dpd_ram_sel+0x44>
  7a:	0000      	.short	0x0000
  7c:	0000      	.short	0x0000
	...

Disassembly of section .text.verify_dpd_ram_sel:

00000000 <verify_dpd_ram_sel>:
   0:	14c8      	push      	r4-r11
   2:	1421      	subi      	r14, r14, 4
   4:	ea224002 	movih      	r2, 16386
   8:	3aae      	bseti      	r2, 14
   a:	1168      	lrw      	r3, 0x0	// a8 <verify_dpd_ram_sel+0xa8>
   c:	4097      	lsli      	r4, r0, 23
   e:	d9a32014 	ld.w      	r13, (r3, 0x50)
  12:	9260      	ld.w      	r3, (r2, 0x0)
  14:	b860      	st.w      	r3, (r14, 0x0)
  16:	9260      	ld.w      	r3, (r2, 0x0)
  18:	3b8c      	bclri      	r3, 12
  1a:	b260      	st.w      	r3, (r2, 0x0)
  1c:	3380      	movi      	r3, 128
  1e:	4002      	lsli      	r0, r0, 2
  20:	4370      	lsli      	r3, r3, 16
  22:	3100      	movi      	r1, 0
  24:	3580      	movi      	r5, 128
  26:	3680      	movi      	r6, 128
  28:	3780      	movi      	r7, 128
  2a:	6340      	addu      	r13, r0
  2c:	690c      	and      	r4, r3
  2e:	3001      	movi      	r0, 1
  30:	45af      	lsli      	r5, r5, 15
  32:	46cc      	lsli      	r6, r6, 12
  34:	ea29fff8 	movih      	r9, 65528
  38:	47ed      	lsli      	r7, r7, 13
  3a:	ea2afff0 	movih      	r10, 65520
  3e:	6e07      	mov      	r8, r1
  40:	4178      	lsli      	r3, r1, 24
  42:	6cd0      	or      	r3, r4
  44:	dc622086 	st.w      	r3, (r2, 0x218)
  48:	d8622086 	ld.w      	r3, (r2, 0x218)
  4c:	3bb6      	bseti      	r3, 22
  4e:	dc622086 	st.w      	r3, (r2, 0x218)
  52:	d8622086 	ld.w      	r3, (r2, 0x218)
  56:	68d4      	and      	r3, r5
  58:	e923fffd 	bnez      	r3, 0x52	// 52 <verify_dpd_ram_sel+0x52>
  5c:	eb010023 	cmphsi      	r1, 36
  60:	d9822086 	ld.w      	r12, (r2, 0x218)
  64:	c40c5683 	zext      	r3, r12, 20, 0
  68:	081c      	bt      	0xa0	// a0 <verify_dpd_ram_sel+0xa0>
  6a:	6ecf      	mov      	r11, r3
  6c:	6b1c      	and      	r12, r7
  6e:	6ce8      	or      	r3, r10
  70:	eb4c0000 	cmpnei      	r12, 0
  74:	c46b0c20 	incf      	r3, r11, 0
  78:	d02d090c 	ldr.w      	r12, (r13, r1 << 3)
  7c:	670e      	cmpne      	r3, r12
  7e:	2100      	addi      	r1, 1
  80:	c4080c40 	inct      	r0, r8, 0
  84:	eb4100d8 	cmpnei      	r1, 216
  88:	0bdc      	bt      	0x40	// 40 <verify_dpd_ram_sel+0x40>
  8a:	ea234002 	movih      	r3, 16386
  8e:	3bae      	bseti      	r3, 14
  90:	e4004001 	xori      	r0, r0, 1
  94:	9840      	ld.w      	r2, (r14, 0x0)
  96:	c4005800 	sext      	r0, r0, 0, 0
  9a:	b340      	st.w      	r2, (r3, 0x0)
  9c:	1401      	addi      	r14, r14, 4
  9e:	1488      	pop      	r4-r11
  a0:	6ecf      	mov      	r11, r3
  a2:	6b18      	and      	r12, r6
  a4:	6ce4      	or      	r3, r9
  a6:	07e5      	br      	0x70	// 70 <verify_dpd_ram_sel+0x70>
  a8:	00000000 	.long	0x00000000

Disassembly of section .text.read_dpd_ram_sel:

00000000 <read_dpd_ram_sel>:
   0:	14c6      	push      	r4-r9
   2:	3380      	movi      	r3, 128
   4:	c6e0482d 	lsli      	r13, r0, 23
   8:	4370      	lsli      	r3, r3, 16
   a:	6b4c      	and      	r13, r3
   c:	107d      	lrw      	r3, 0x0	// 80 <read_dpd_ram_sel+0x80>
   e:	4002      	lsli      	r0, r0, 2
  10:	9374      	ld.w      	r3, (r3, 0x50)
  12:	3480      	movi      	r4, 128
  14:	3580      	movi      	r5, 128
  16:	3680      	movi      	r6, 128
  18:	600c      	addu      	r0, r3
  1a:	3100      	movi      	r1, 0
  1c:	ea2c4002 	movih      	r12, 16386
  20:	c5cc284c 	bseti      	r12, r12, 14
  24:	448f      	lsli      	r4, r4, 15
  26:	45ac      	lsli      	r5, r5, 12
  28:	ea27fff8 	movih      	r7, 65528
  2c:	46cd      	lsli      	r6, r6, 13
  2e:	ea28fff0 	movih      	r8, 65520
  32:	4178      	lsli      	r3, r1, 24
  34:	6cf4      	or      	r3, r13
  36:	dc6c2086 	st.w      	r3, (r12, 0x218)
  3a:	d86c2086 	ld.w      	r3, (r12, 0x218)
  3e:	3bb6      	bseti      	r3, 22
  40:	dc6c2086 	st.w      	r3, (r12, 0x218)
  44:	d86c2086 	ld.w      	r3, (r12, 0x218)
  48:	68d0      	and      	r3, r4
  4a:	e923fffd 	bnez      	r3, 0x44	// 44 <read_dpd_ram_sel+0x44>
  4e:	eb010023 	cmphsi      	r1, 36
  52:	d84c2086 	ld.w      	r2, (r12, 0x218)
  56:	c4025683 	zext      	r3, r2, 20, 0
  5a:	080e      	bt      	0x76	// 76 <read_dpd_ram_sel+0x76>
  5c:	6e4f      	mov      	r9, r3
  5e:	6898      	and      	r2, r6
  60:	6ce0      	or      	r3, r8
  62:	3a40      	cmpnei      	r2, 0
  64:	c4690c20 	incf      	r3, r9, 0
  68:	d4200903 	str.w      	r3, (r0, r1 << 3)
  6c:	2100      	addi      	r1, 1
  6e:	eb4100d8 	cmpnei      	r1, 216
  72:	0be0      	bt      	0x32	// 32 <read_dpd_ram_sel+0x32>
  74:	1486      	pop      	r4-r9
  76:	6e4f      	mov      	r9, r3
  78:	6894      	and      	r2, r5
  7a:	6cdc      	or      	r3, r7
  7c:	07f3      	br      	0x62	// 62 <read_dpd_ram_sel+0x62>
  7e:	0000      	.short	0x0000
  80:	00000000 	.long	0x00000000

Disassembly of section .text.config_rx_gain_mode_inner.constprop.1:

00000000 <config_rx_gain_mode_inner.constprop.1>:
   0:	14c4      	push      	r4-r7
   2:	8061      	ld.b      	r3, (r0, 0x1)
   4:	8040      	ld.b      	r2, (r0, 0x0)
   6:	4368      	lsli      	r3, r3, 8
   8:	6cc8      	or      	r3, r2
   a:	8042      	ld.b      	r2, (r0, 0x2)
   c:	4250      	lsli      	r2, r2, 16
   e:	6cc8      	or      	r3, r2
  10:	8043      	ld.b      	r2, (r0, 0x3)
  12:	4258      	lsli      	r2, r2, 24
  14:	6c8c      	or      	r2, r3
  16:	ea234002 	movih      	r3, 16386
  1a:	3bae      	bseti      	r3, 14
  1c:	34ff      	movi      	r4, 255
  1e:	b35d      	st.w      	r2, (r3, 0x74)
  20:	8044      	ld.b      	r2, (r0, 0x4)
  22:	b35e      	st.w      	r2, (r3, 0x78)
  24:	8026      	ld.b      	r1, (r0, 0x6)
  26:	8045      	ld.b      	r2, (r0, 0x5)
  28:	4128      	lsli      	r1, r1, 8
  2a:	6c48      	or      	r1, r2
  2c:	8047      	ld.b      	r2, (r0, 0x7)
  2e:	4250      	lsli      	r2, r2, 16
  30:	6c48      	or      	r1, r2
  32:	8048      	ld.b      	r2, (r0, 0x8)
  34:	4258      	lsli      	r2, r2, 24
  36:	6c84      	or      	r2, r1
  38:	b35f      	st.w      	r2, (r3, 0x7c)
  3a:	8049      	ld.b      	r2, (r0, 0x9)
  3c:	dc432020 	st.w      	r2, (r3, 0x80)
  40:	ea0c0001 	movi      	r12, 1
  44:	e4400009 	addi      	r2, r0, 10
  48:	4490      	lsli      	r4, r4, 16
  4a:	d9a24003 	ld.bs      	r13, (r2, 0x3)
  4e:	8220      	ld.b      	r1, (r2, 0x0)
  50:	c70d482d 	lsli      	r13, r13, 24
  54:	6c74      	or      	r1, r13
  56:	d9a20001 	ld.b      	r13, (r2, 0x1)
  5a:	c50d482d 	lsli      	r13, r13, 8
  5e:	6c74      	or      	r1, r13
  60:	d9a24002 	ld.bs      	r13, (r2, 0x2)
  64:	c60d482d 	lsli      	r13, r13, 16
  68:	6b50      	and      	r13, r4
  6a:	6c74      	or      	r1, r13
  6c:	c46c482d 	lsli      	r13, r12, 3
  70:	634c      	addu      	r13, r3
  72:	dc2d201f 	st.w      	r1, (r13, 0x7c)
  76:	e42c000f 	addi      	r1, r12, 16
  7a:	e58c0000 	addi      	r12, r12, 1
  7e:	eb4c0008 	cmpnei      	r12, 8
  82:	d9a20004 	ld.b      	r13, (r2, 0x4)
  86:	d423090d 	str.w      	r13, (r3, r1 << 3)
  8a:	2204      	addi      	r2, 5
  8c:	0bdf      	bt      	0x4a	// 4a <config_rx_gain_mode_inner.constprop.1+0x4a>
  8e:	35ff      	movi      	r5, 255
  90:	ea0c00f8 	movi      	r12, 248
  94:	34f8      	movi      	r4, 248
  96:	ea0d00f8 	movi      	r13, 248
  9a:	202c      	addi      	r0, 45
  9c:	3100      	movi      	r1, 0
  9e:	45b0      	lsli      	r5, r5, 16
  a0:	ea264002 	movih      	r6, 16386
  a4:	3eae      	bseti      	r6, 14
  a6:	c4ac482c 	lsli      	r12, r12, 5
  aa:	448d      	lsli      	r4, r4, 13
  ac:	c6ad482d 	lsli      	r13, r13, 21
  b0:	d8404003 	ld.bs      	r2, (r0, 0x3)
  b4:	8060      	ld.b      	r3, (r0, 0x0)
  b6:	4258      	lsli      	r2, r2, 24
  b8:	6cc8      	or      	r3, r2
  ba:	8041      	ld.b      	r2, (r0, 0x1)
  bc:	4248      	lsli      	r2, r2, 8
  be:	6cc8      	or      	r3, r2
  c0:	d8404002 	ld.bs      	r2, (r0, 0x2)
  c4:	4250      	lsli      	r2, r2, 16
  c6:	6894      	and      	r2, r5
  c8:	6cc8      	or      	r3, r2
  ca:	4143      	lsli      	r2, r1, 3
  cc:	6098      	addu      	r2, r6
  ce:	2100      	addi      	r1, 1
  d0:	dc62202f 	st.w      	r3, (r2, 0xbc)
  d4:	8065      	ld.b      	r3, (r0, 0x5)
  d6:	80e4      	ld.b      	r7, (r0, 0x4)
  d8:	4368      	lsli      	r3, r3, 8
  da:	6cdc      	or      	r3, r7
  dc:	dc622030 	st.w      	r3, (r2, 0xc0)
  e0:	d8600031 	ld.b      	r3, (r0, 0x31)
  e4:	d8e00032 	ld.b      	r7, (r0, 0x32)
  e8:	4368      	lsli      	r3, r3, 8
  ea:	47f0      	lsli      	r7, r7, 16
  ec:	69d0      	and      	r7, r4
  ee:	68f0      	and      	r3, r12
  f0:	6cdc      	or      	r3, r7
  f2:	d8e00030 	ld.b      	r7, (r0, 0x30)
  f6:	e4e7201f 	andi      	r7, r7, 31
  fa:	6cdc      	or      	r3, r7
  fc:	d8e00033 	ld.b      	r7, (r0, 0x33)
 100:	47f8      	lsli      	r7, r7, 24
 102:	69f4      	and      	r7, r13
 104:	6cdc      	or      	r3, r7
 106:	dc62203f 	st.w      	r3, (r2, 0xfc)
 10a:	d8600035 	ld.b      	r3, (r0, 0x35)
 10e:	d8e00034 	ld.b      	r7, (r0, 0x34)
 112:	4368      	lsli      	r3, r3, 8
 114:	68f0      	and      	r3, r12
 116:	e4e7201f 	andi      	r7, r7, 31
 11a:	3948      	cmpnei      	r1, 8
 11c:	6cdc      	or      	r3, r7
 11e:	dc622040 	st.w      	r3, (r2, 0x100)
 122:	2005      	addi      	r0, 6
 124:	0bc6      	bt      	0xb0	// b0 <config_rx_gain_mode_inner.constprop.1+0xb0>
 126:	1484      	pop      	r4-r7

Disassembly of section .text.config_phy_ah_rx_imb.constprop.2:

00000000 <config_phy_ah_rx_imb.constprop.2>:
   0:	3300      	movi      	r3, 0
   2:	ea224002 	movih      	r2, 16386
   6:	3aae      	bseti      	r2, 14
   8:	d060088c 	ldr.w      	r12, (r0, r3 << 2)
   c:	e4230056 	addi      	r1, r3, 87
  10:	2300      	addi      	r3, 1
  12:	3b46      	cmpnei      	r3, 6
  14:	d422088c 	str.w      	r12, (r2, r1 << 2)
  18:	0bf8      	bt      	0x8	// 8 <config_phy_ah_rx_imb.constprop.2+0x8>
  1a:	783c      	jmp      	r15

Disassembly of section .text.config_phy_ah_rx_dc_offset.constprop.3:

00000000 <config_phy_ah_rx_dc_offset.constprop.3>:
   0:	8041      	ld.b      	r2, (r0, 0x1)
   2:	8060      	ld.b      	r3, (r0, 0x0)
   4:	4248      	lsli      	r2, r2, 8
   6:	6c8c      	or      	r2, r3
   8:	8062      	ld.b      	r3, (r0, 0x2)
   a:	4370      	lsli      	r3, r3, 16
   c:	6c8c      	or      	r2, r3
   e:	8063      	ld.b      	r3, (r0, 0x3)
  10:	ea214002 	movih      	r1, 16386
  14:	39ae      	bseti      	r1, 14
  16:	4378      	lsli      	r3, r3, 24
  18:	6cc8      	or      	r3, r2
  1a:	b16d      	st.w      	r3, (r1, 0x34)
  1c:	8065      	ld.b      	r3, (r0, 0x5)
  1e:	8044      	ld.b      	r2, (r0, 0x4)
  20:	4368      	lsli      	r3, r3, 8
  22:	6cc8      	or      	r3, r2
  24:	b16e      	st.w      	r3, (r1, 0x38)
  26:	8047      	ld.b      	r2, (r0, 0x7)
  28:	8066      	ld.b      	r3, (r0, 0x6)
  2a:	4248      	lsli      	r2, r2, 8
  2c:	6c8c      	or      	r2, r3
  2e:	8068      	ld.b      	r3, (r0, 0x8)
  30:	4370      	lsli      	r3, r3, 16
  32:	6c8c      	or      	r2, r3
  34:	8069      	ld.b      	r3, (r0, 0x9)
  36:	4378      	lsli      	r3, r3, 24
  38:	6cc8      	or      	r3, r2
  3a:	b175      	st.w      	r3, (r1, 0x54)
  3c:	806b      	ld.b      	r3, (r0, 0xb)
  3e:	804a      	ld.b      	r2, (r0, 0xa)
  40:	4368      	lsli      	r3, r3, 8
  42:	6cc8      	or      	r3, r2
  44:	b176      	st.w      	r3, (r1, 0x58)
  46:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_bw_cfg:

00000000 <ah_wphy_bw_cfg>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	31c0      	movi      	r1, 192
   8:	9340      	ld.w      	r2, (r3, 0x0)
   a:	3a90      	bclri      	r2, 16
   c:	3a91      	bclri      	r2, 17
   e:	b340      	st.w      	r2, (r3, 0x0)
  10:	412a      	lsli      	r1, r1, 10
  12:	4010      	lsli      	r0, r0, 16
  14:	9340      	ld.w      	r2, (r3, 0x0)
  16:	6804      	and      	r0, r1
  18:	6c08      	or      	r0, r2
  1a:	b300      	st.w      	r0, (r3, 0x0)
  1c:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_enable:

00000000 <ah_wphy_enable>:
   0:	ea224002 	movih      	r2, 16386
   4:	3aae      	bseti      	r2, 14
   6:	9260      	ld.w      	r3, (r2, 0x0)
   8:	ec630001 	ori      	r3, r3, 1
   c:	b260      	st.w      	r3, (r2, 0x0)
   e:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_disable:

00000000 <ah_wphy_disable>:
   0:	ea224002 	movih      	r2, 16386
   4:	3aae      	bseti      	r2, 14
   6:	9260      	ld.w      	r3, (r2, 0x0)
   8:	3b80      	bclri      	r3, 0
   a:	b260      	st.w      	r3, (r2, 0x0)
   c:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_cont_tx_enable:

00000000 <ah_wphy_cont_tx_enable>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	9341      	ld.w      	r2, (r3, 0x4)
   8:	3a87      	bclri      	r2, 7
   a:	b341      	st.w      	r2, (r3, 0x4)
   c:	9341      	ld.w      	r2, (r3, 0x4)
   e:	ec420080 	ori      	r2, r2, 128
  12:	b341      	st.w      	r2, (r3, 0x4)
  14:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_cont_tx_disable:

00000000 <ah_wphy_cont_tx_disable>:
   0:	ea224002 	movih      	r2, 16386
   4:	3aae      	bseti      	r2, 14
   6:	9261      	ld.w      	r3, (r2, 0x4)
   8:	3b87      	bclri      	r3, 7
   a:	b261      	st.w      	r3, (r2, 0x4)
   c:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_pri_channel_cfg:

00000000 <ah_wphy_pri_channel_cfg>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	3100      	movi      	r1, 0
   8:	9341      	ld.w      	r2, (r3, 0x4)
   a:	291c      	subi      	r1, 29
   c:	6884      	and      	r2, r1
   e:	b341      	st.w      	r2, (r3, 0x4)
  10:	4002      	lsli      	r0, r0, 2
  12:	9341      	ld.w      	r2, (r3, 0x4)
  14:	e400201c 	andi      	r0, r0, 28
  18:	6c08      	or      	r0, r2
  1a:	b301      	st.w      	r0, (r3, 0x4)
  1c:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_tx_crc_get:

00000000 <ah_wphy_tx_crc_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	9302      	ld.w      	r0, (r3, 0x8)
   8:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_tx_sine_mode_cfg:

00000000 <ah_wphy_tx_sine_mode_cfg>:
   0:	107b      	lrw      	r3, 0x0	// 6c <ah_wphy_tx_sine_mode_cfg+0x6c>
   2:	ea0c0000 	movi      	r12, 0
   6:	9373      	ld.w      	r3, (r3, 0x4c)
   8:	e4002003 	andi      	r0, r0, 3
   c:	d84300ed 	ld.b      	r2, (r3, 0xed)
  10:	c44c5c00 	ins      	r2, r12, 0, 0
  14:	dc4300ed 	st.b      	r2, (r3, 0xed)
  18:	d84300e9 	ld.b      	r2, (r3, 0xe9)
  1c:	c4405c23 	ins      	r2, r0, 4, 3
  20:	dc4300e9 	st.b      	r2, (r3, 0xe9)
  24:	e42121ff 	andi      	r1, r1, 511
  28:	d8431075 	ld.h      	r2, (r3, 0xea)
  2c:	c4415d00 	ins      	r2, r1, 8, 0
  30:	dc431075 	st.h      	r2, (r3, 0xea)
  34:	ea234002 	movih      	r3, 16386
  38:	3bae      	bseti      	r3, 14
  3a:	4131      	lsli      	r1, r1, 17
  3c:	9341      	ld.w      	r2, (r3, 0x4)
  3e:	3a80      	bclri      	r2, 0
  40:	3a81      	bclri      	r2, 1
  42:	b341      	st.w      	r2, (r3, 0x4)
  44:	9341      	ld.w      	r2, (r3, 0x4)
  46:	6c08      	or      	r0, r2
  48:	b301      	st.w      	r0, (r3, 0x4)
  4a:	ea20fc02 	movih      	r0, 64514
  4e:	9341      	ld.w      	r2, (r3, 0x4)
  50:	2800      	subi      	r0, 1
  52:	6880      	and      	r2, r0
  54:	b341      	st.w      	r2, (r3, 0x4)
  56:	9341      	ld.w      	r2, (r3, 0x4)
  58:	6c48      	or      	r1, r2
  5a:	b321      	st.w      	r1, (r3, 0x4)
  5c:	9341      	ld.w      	r2, (r3, 0x4)
  5e:	c40257c2 	zext      	r2, r2, 30, 0
  62:	b341      	st.w      	r2, (r3, 0x4)
  64:	9341      	ld.w      	r2, (r3, 0x4)
  66:	b341      	st.w      	r2, (r3, 0x4)
  68:	783c      	jmp      	r15
  6a:	0000      	.short	0x0000
  6c:	00000000 	.long	0x00000000

Disassembly of section .text.ah_wphy_tx_tri_mode_cfg:

00000000 <ah_wphy_tx_tri_mode_cfg>:
   0:	107b      	lrw      	r3, 0x0	// 6c <ah_wphy_tx_tri_mode_cfg+0x6c>
   2:	ea0c0001 	movi      	r12, 1
   6:	9373      	ld.w      	r3, (r3, 0x4c)
   8:	e4002003 	andi      	r0, r0, 3
   c:	d84300ed 	ld.b      	r2, (r3, 0xed)
  10:	c44c5c00 	ins      	r2, r12, 0, 0
  14:	dc4300ed 	st.b      	r2, (r3, 0xed)
  18:	d84300e9 	ld.b      	r2, (r3, 0xe9)
  1c:	c4405c23 	ins      	r2, r0, 4, 3
  20:	dc4300e9 	st.b      	r2, (r3, 0xe9)
  24:	e42121ff 	andi      	r1, r1, 511
  28:	d8431075 	ld.h      	r2, (r3, 0xea)
  2c:	c4415d00 	ins      	r2, r1, 8, 0
  30:	dc431075 	st.h      	r2, (r3, 0xea)
  34:	ea234002 	movih      	r3, 16386
  38:	3bae      	bseti      	r3, 14
  3a:	4131      	lsli      	r1, r1, 17
  3c:	9341      	ld.w      	r2, (r3, 0x4)
  3e:	3a80      	bclri      	r2, 0
  40:	3a81      	bclri      	r2, 1
  42:	b341      	st.w      	r2, (r3, 0x4)
  44:	9341      	ld.w      	r2, (r3, 0x4)
  46:	6c08      	or      	r0, r2
  48:	b301      	st.w      	r0, (r3, 0x4)
  4a:	ea20fc02 	movih      	r0, 64514
  4e:	9341      	ld.w      	r2, (r3, 0x4)
  50:	2800      	subi      	r0, 1
  52:	6880      	and      	r2, r0
  54:	b341      	st.w      	r2, (r3, 0x4)
  56:	9341      	ld.w      	r2, (r3, 0x4)
  58:	6c48      	or      	r1, r2
  5a:	b321      	st.w      	r1, (r3, 0x4)
  5c:	9341      	ld.w      	r2, (r3, 0x4)
  5e:	c40257c2 	zext      	r2, r2, 30, 0
  62:	b341      	st.w      	r2, (r3, 0x4)
  64:	9341      	ld.w      	r2, (r3, 0x4)
  66:	3abf      	bseti      	r2, 31
  68:	b341      	st.w      	r2, (r3, 0x4)
  6a:	783c      	jmp      	r15
  6c:	00000000 	.long	0x00000000

Disassembly of section .text.ah_wphy_tx_norm_mode_cfg:

00000000 <ah_wphy_tx_norm_mode_cfg>:
   0:	106a      	lrw      	r3, 0x0	// 28 <ah_wphy_tx_norm_mode_cfg+0x28>
   2:	3100      	movi      	r1, 0
   4:	9373      	ld.w      	r3, (r3, 0x4c)
   6:	d84300e9 	ld.b      	r2, (r3, 0xe9)
   a:	c4415c23 	ins      	r2, r1, 4, 3
   e:	dc4300e9 	st.b      	r2, (r3, 0xe9)
  12:	ea234002 	movih      	r3, 16386
  16:	3bae      	bseti      	r3, 14
  18:	9341      	ld.w      	r2, (r3, 0x4)
  1a:	3a80      	bclri      	r2, 0
  1c:	3a81      	bclri      	r2, 1
  1e:	b341      	st.w      	r2, (r3, 0x4)
  20:	9341      	ld.w      	r2, (r3, 0x4)
  22:	b341      	st.w      	r2, (r3, 0x4)
  24:	783c      	jmp      	r15
  26:	0000      	.short	0x0000
  28:	0000      	.short	0x0000
	...

Disassembly of section .text.ah_wphy_param_disp:

00000000 <ah_wphy_param_disp>:
   0:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_soft_reset:

00000000 <ah_wphy_soft_reset>:
   0:	ea224002 	movih      	r2, 16386
   4:	3aae      	bseti      	r2, 14
   6:	9260      	ld.w      	r3, (r2, 0x0)
   8:	c40357c3 	zext      	r3, r3, 30, 0
   c:	b260      	st.w      	r3, (r2, 0x0)
   e:	3180      	movi      	r1, 128
  10:	9260      	ld.w      	r3, (r2, 0x0)
  12:	4138      	lsli      	r1, r1, 24
  14:	68c4      	and      	r3, r1
  16:	e923fffc 	bnez      	r3, 0xe	// e <ah_wphy_soft_reset+0xe>
  1a:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_soft_dereset:

00000000 <ah_wphy_soft_dereset>:
   0:	ea224002 	movih      	r2, 16386
   4:	3aae      	bseti      	r2, 14
   6:	9260      	ld.w      	r3, (r2, 0x0)
   8:	3bbf      	bseti      	r3, 31
   a:	b260      	st.w      	r3, (r2, 0x0)
   c:	3180      	movi      	r1, 128
   e:	9260      	ld.w      	r3, (r2, 0x0)
  10:	4138      	lsli      	r1, r1, 24
  12:	68c4      	and      	r3, r1
  14:	e903fffc 	bez      	r3, 0xc	// c <ah_wphy_soft_dereset+0xc>
  18:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_dpd_ram_cfg:

00000000 <ah_wphy_dpd_ram_cfg>:
   0:	14d2      	push      	r4-r5, r15
   2:	ea244002 	movih      	r4, 16386
   6:	3cae      	bseti      	r4, 14
   8:	3000      	movi      	r0, 0
   a:	94a1      	ld.w      	r5, (r4, 0x4)
   c:	9461      	ld.w      	r3, (r4, 0x4)
   e:	3b89      	bclri      	r3, 9
  10:	b461      	st.w      	r3, (r4, 0x4)
  12:	e0000000 	bsr      	0x0	// 0 <ah_wphy_dpd_ram_cfg>
  16:	3001      	movi      	r0, 1
  18:	e0000000 	bsr      	0x0	// 0 <ah_wphy_dpd_ram_cfg>
  1c:	b4a1      	st.w      	r5, (r4, 0x4)
  1e:	1492      	pop      	r4-r5, r15

Disassembly of section .text.ah_wphy_dpd_ram_verify:

00000000 <ah_wphy_dpd_ram_verify>:
   0:	14d3      	push      	r4-r6, r15
   2:	ea244002 	movih      	r4, 16386
   6:	3cae      	bseti      	r4, 14
   8:	3000      	movi      	r0, 0
   a:	94c1      	ld.w      	r6, (r4, 0x4)
   c:	9461      	ld.w      	r3, (r4, 0x4)
   e:	3b89      	bclri      	r3, 9
  10:	b461      	st.w      	r3, (r4, 0x4)
  12:	e0000000 	bsr      	0x0	// 0 <ah_wphy_dpd_ram_verify>
  16:	6d43      	mov      	r5, r0
  18:	3001      	movi      	r0, 1
  1a:	e0000000 	bsr      	0x0	// 0 <ah_wphy_dpd_ram_verify>
  1e:	6c14      	or      	r0, r5
  20:	b4c1      	st.w      	r6, (r4, 0x4)
  22:	1493      	pop      	r4-r6, r15

Disassembly of section .text.ah_wphy_dpd_ram_read:

00000000 <ah_wphy_dpd_ram_read>:
   0:	14d2      	push      	r4-r5, r15
   2:	ea244002 	movih      	r4, 16386
   6:	3cae      	bseti      	r4, 14
   8:	3000      	movi      	r0, 0
   a:	94a1      	ld.w      	r5, (r4, 0x4)
   c:	9461      	ld.w      	r3, (r4, 0x4)
   e:	3b89      	bclri      	r3, 9
  10:	b461      	st.w      	r3, (r4, 0x4)
  12:	e0000000 	bsr      	0x0	// 0 <ah_wphy_dpd_ram_read>
  16:	3001      	movi      	r0, 1
  18:	e0000000 	bsr      	0x0	// 0 <ah_wphy_dpd_ram_read>
  1c:	b4a1      	st.w      	r5, (r4, 0x4)
  1e:	1492      	pop      	r4-r5, r15

Disassembly of section .text.ah_wphy_open:

00000000 <ah_wphy_open>:
   0:	14d5      	push      	r4-r8, r15
   2:	ea830218 	lrw      	r3, 0x0	// 860 <ah_wphy_open+0x860>
   6:	3100      	movi      	r1, 0
   8:	93b3      	ld.w      	r5, (r3, 0x4c)
   a:	ea820217 	lrw      	r2, 0x4002423c	// 864 <ah_wphy_open+0x864>
   e:	ea234002 	movih      	r3, 16386
  12:	3bae      	bseti      	r3, 14
  14:	b320      	st.w      	r1, (r3, 0x0)
  16:	2303      	addi      	r3, 4
  18:	648e      	cmpne      	r3, r2
  1a:	0bfd      	bt      	0x14	// 14 <ah_wphy_open+0x14>
  1c:	ea244002 	movih      	r4, 16386
  20:	3cae      	bseti      	r4, 14
  22:	e0000000 	bsr      	0x0	// 0 <ah_wphy_open>
  26:	e0000000 	bsr      	0x0	// 0 <ah_wphy_open>
  2a:	9460      	ld.w      	r3, (r4, 0x0)
  2c:	3b80      	bclri      	r3, 0
  2e:	b460      	st.w      	r3, (r4, 0x0)
  30:	9460      	ld.w      	r3, (r4, 0x0)
  32:	3b9e      	bclri      	r3, 30
  34:	b460      	st.w      	r3, (r4, 0x0)
  36:	9460      	ld.w      	r3, (r4, 0x0)
  38:	3b9d      	bclri      	r3, 29
  3a:	b460      	st.w      	r3, (r4, 0x0)
  3c:	9460      	ld.w      	r3, (r4, 0x0)
  3e:	3b9c      	bclri      	r3, 28
  40:	b460      	st.w      	r3, (r4, 0x0)
  42:	9460      	ld.w      	r3, (r4, 0x0)
  44:	3b9b      	bclri      	r3, 27
  46:	b460      	st.w      	r3, (r4, 0x0)
  48:	9460      	ld.w      	r3, (r4, 0x0)
  4a:	3b8f      	bclri      	r3, 15
  4c:	b460      	st.w      	r3, (r4, 0x0)
  4e:	d86500f1 	ld.b      	r3, (r5, 0xf1)
  52:	c4c354c3 	zext      	r3, r3, 6, 6
  56:	9440      	ld.w      	r2, (r4, 0x0)
  58:	436f      	lsli      	r3, r3, 15
  5a:	6cc8      	or      	r3, r2
  5c:	b460      	st.w      	r3, (r4, 0x0)
  5e:	9460      	ld.w      	r3, (r4, 0x0)
  60:	3b94      	bclri      	r3, 20
  62:	3b95      	bclri      	r3, 21
  64:	b460      	st.w      	r3, (r4, 0x0)
  66:	d865203c 	ld.w      	r3, (r5, 0xf0)
  6a:	c5e35603 	zext      	r3, r3, 16, 15
  6e:	9440      	ld.w      	r2, (r4, 0x0)
  70:	4374      	lsli      	r3, r3, 20
  72:	6cc8      	or      	r3, r2
  74:	b460      	st.w      	r3, (r4, 0x0)
  76:	9460      	ld.w      	r3, (r4, 0x0)
  78:	3bba      	bseti      	r3, 26
  7a:	b460      	st.w      	r3, (r4, 0x0)
  7c:	9460      	ld.w      	r3, (r4, 0x0)
  7e:	3b9a      	bclri      	r3, 26
  80:	b460      	st.w      	r3, (r4, 0x0)
  82:	9460      	ld.w      	r3, (r4, 0x0)
  84:	3bb9      	bseti      	r3, 25
  86:	b460      	st.w      	r3, (r4, 0x0)
  88:	9460      	ld.w      	r3, (r4, 0x0)
  8a:	3b99      	bclri      	r3, 25
  8c:	b460      	st.w      	r3, (r4, 0x0)
  8e:	9460      	ld.w      	r3, (r4, 0x0)
  90:	3bb8      	bseti      	r3, 24
  92:	b460      	st.w      	r3, (r4, 0x0)
  94:	9460      	ld.w      	r3, (r4, 0x0)
  96:	3b98      	bclri      	r3, 24
  98:	b460      	st.w      	r3, (r4, 0x0)
  9a:	9460      	ld.w      	r3, (r4, 0x0)
  9c:	3b97      	bclri      	r3, 23
  9e:	b460      	st.w      	r3, (r4, 0x0)
  a0:	9460      	ld.w      	r3, (r4, 0x0)
  a2:	3bb7      	bseti      	r3, 23
  a4:	b460      	st.w      	r3, (r4, 0x0)
  a6:	9460      	ld.w      	r3, (r4, 0x0)
  a8:	3b92      	bclri      	r3, 18
  aa:	3b93      	bclri      	r3, 19
  ac:	b460      	st.w      	r3, (r4, 0x0)
  ae:	9460      	ld.w      	r3, (r4, 0x0)
  b0:	3bb3      	bseti      	r3, 19
  b2:	b460      	st.w      	r3, (r4, 0x0)
  b4:	9460      	ld.w      	r3, (r4, 0x0)
  b6:	ec631000 	ori      	r3, r3, 4096
  ba:	b460      	st.w      	r3, (r4, 0x0)
  bc:	9460      	ld.w      	r3, (r4, 0x0)
  be:	ec630800 	ori      	r3, r3, 2048
  c2:	b460      	st.w      	r3, (r4, 0x0)
  c4:	9460      	ld.w      	r3, (r4, 0x0)
  c6:	ec630400 	ori      	r3, r3, 1024
  ca:	b460      	st.w      	r3, (r4, 0x0)
  cc:	9460      	ld.w      	r3, (r4, 0x0)
  ce:	ec630200 	ori      	r3, r3, 512
  d2:	b460      	st.w      	r3, (r4, 0x0)
  d4:	9460      	ld.w      	r3, (r4, 0x0)
  d6:	ec630100 	ori      	r3, r3, 256
  da:	b460      	st.w      	r3, (r4, 0x0)
  dc:	9460      	ld.w      	r3, (r4, 0x0)
  de:	ec630080 	ori      	r3, r3, 128
  e2:	b460      	st.w      	r3, (r4, 0x0)
  e4:	9460      	ld.w      	r3, (r4, 0x0)
  e6:	ec630040 	ori      	r3, r3, 64
  ea:	b460      	st.w      	r3, (r4, 0x0)
  ec:	9460      	ld.w      	r3, (r4, 0x0)
  ee:	ec630020 	ori      	r3, r3, 32
  f2:	b460      	st.w      	r3, (r4, 0x0)
  f4:	9460      	ld.w      	r3, (r4, 0x0)
  f6:	ec630010 	ori      	r3, r3, 16
  fa:	b460      	st.w      	r3, (r4, 0x0)
  fc:	9460      	ld.w      	r3, (r4, 0x0)
  fe:	ec630008 	ori      	r3, r3, 8
 102:	b460      	st.w      	r3, (r4, 0x0)
 104:	9460      	ld.w      	r3, (r4, 0x0)
 106:	ec630004 	ori      	r3, r3, 4
 10a:	b460      	st.w      	r3, (r4, 0x0)
 10c:	9460      	ld.w      	r3, (r4, 0x0)
 10e:	ec630002 	ori      	r3, r3, 2
 112:	b460      	st.w      	r3, (r4, 0x0)
 114:	8500      	ld.b      	r0, (r5, 0x0)
 116:	4806      	lsri      	r0, r0, 6
 118:	e0000000 	bsr      	0x0	// 0 <ah_wphy_open>
 11c:	9460      	ld.w      	r3, (r4, 0x0)
 11e:	3b92      	bclri      	r3, 18
 120:	3b93      	bclri      	r3, 19
 122:	b460      	st.w      	r3, (r4, 0x0)
 124:	31c0      	movi      	r1, 192
 126:	d86500ed 	ld.b      	r3, (r5, 0xed)
 12a:	412c      	lsli      	r1, r1, 12
 12c:	4371      	lsli      	r3, r3, 17
 12e:	9440      	ld.w      	r2, (r4, 0x0)
 130:	68c4      	and      	r3, r1
 132:	6cc8      	or      	r3, r2
 134:	b460      	st.w      	r3, (r4, 0x0)
 136:	9461      	ld.w      	r3, (r4, 0x4)
 138:	3b80      	bclri      	r3, 0
 13a:	3b81      	bclri      	r3, 1
 13c:	b461      	st.w      	r3, (r4, 0x4)
 13e:	d86500e9 	ld.b      	r3, (r5, 0xe9)
 142:	9441      	ld.w      	r2, (r4, 0x4)
 144:	c4635483 	zext      	r3, r3, 4, 3
 148:	6cc8      	or      	r3, r2
 14a:	b461      	st.w      	r3, (r4, 0x4)
 14c:	ea22fc02 	movih      	r2, 64514
 150:	9461      	ld.w      	r3, (r4, 0x4)
 152:	2a00      	subi      	r2, 1
 154:	68c8      	and      	r3, r2
 156:	b461      	st.w      	r3, (r4, 0x4)
 158:	d8651075 	ld.h      	r3, (r5, 0xea)
 15c:	e46321ff 	andi      	r3, r3, 511
 160:	9441      	ld.w      	r2, (r4, 0x4)
 162:	4371      	lsli      	r3, r3, 17
 164:	6cc8      	or      	r3, r2
 166:	b461      	st.w      	r3, (r4, 0x4)
 168:	9461      	ld.w      	r3, (r4, 0x4)
 16a:	c40357c3 	zext      	r3, r3, 30, 0
 16e:	b461      	st.w      	r3, (r4, 0x4)
 170:	d86500ed 	ld.b      	r3, (r5, 0xed)
 174:	9441      	ld.w      	r2, (r4, 0x4)
 176:	437f      	lsli      	r3, r3, 31
 178:	6cc8      	or      	r3, r2
 17a:	b461      	st.w      	r3, (r4, 0x4)
 17c:	9461      	ld.w      	r3, (r4, 0x4)
 17e:	c7205022 	bmaski      	r2, 26
 182:	c6224902 	rotli      	r2, r2, 17
 186:	68c8      	and      	r3, r2
 188:	b461      	st.w      	r3, (r4, 0x4)
 18a:	d8651074 	ld.h      	r3, (r5, 0xe8)
 18e:	c4a35543 	zext      	r3, r3, 10, 5
 192:	9441      	ld.w      	r2, (r4, 0x4)
 194:	436b      	lsli      	r3, r3, 11
 196:	6cc8      	or      	r3, r2
 198:	b461      	st.w      	r3, (r4, 0x4)
 19a:	9461      	ld.w      	r3, (r4, 0x4)
 19c:	3b8a      	bclri      	r3, 10
 19e:	b461      	st.w      	r3, (r4, 0x4)
 1a0:	d86500e4 	ld.b      	r3, (r5, 0xe4)
 1a4:	e4632001 	andi      	r3, r3, 1
 1a8:	9441      	ld.w      	r2, (r4, 0x4)
 1aa:	436a      	lsli      	r3, r3, 10
 1ac:	6cc8      	or      	r3, r2
 1ae:	b461      	st.w      	r3, (r4, 0x4)
 1b0:	9461      	ld.w      	r3, (r4, 0x4)
 1b2:	3b89      	bclri      	r3, 9
 1b4:	b461      	st.w      	r3, (r4, 0x4)
 1b6:	9461      	ld.w      	r3, (r4, 0x4)
 1b8:	3b88      	bclri      	r3, 8
 1ba:	b461      	st.w      	r3, (r4, 0x4)
 1bc:	d86500ba 	ld.b      	r3, (r5, 0xba)
 1c0:	c4c354c3 	zext      	r3, r3, 6, 6
 1c4:	9441      	ld.w      	r2, (r4, 0x4)
 1c6:	4368      	lsli      	r3, r3, 8
 1c8:	6cc8      	or      	r3, r2
 1ca:	b461      	st.w      	r3, (r4, 0x4)
 1cc:	9461      	ld.w      	r3, (r4, 0x4)
 1ce:	3b87      	bclri      	r3, 7
 1d0:	b461      	st.w      	r3, (r4, 0x4)
 1d2:	8560      	ld.b      	r3, (r5, 0x0)
 1d4:	c4835483 	zext      	r3, r3, 4, 4
 1d8:	9441      	ld.w      	r2, (r4, 0x4)
 1da:	4367      	lsli      	r3, r3, 7
 1dc:	6cc8      	or      	r3, r2
 1de:	b461      	st.w      	r3, (r4, 0x4)
 1e0:	9461      	ld.w      	r3, (r4, 0x4)
 1e2:	8540      	ld.b      	r2, (r5, 0x0)
 1e4:	3b86      	bclri      	r3, 6
 1e6:	b461      	st.w      	r3, (r4, 0x4)
 1e8:	c4625462 	zext      	r2, r2, 3, 3
 1ec:	9461      	ld.w      	r3, (r4, 0x4)
 1ee:	4246      	lsli      	r2, r2, 6
 1f0:	6c8c      	or      	r2, r3
 1f2:	b441      	st.w      	r2, (r4, 0x4)
 1f4:	9461      	ld.w      	r3, (r4, 0x4)
 1f6:	3b85      	bclri      	r3, 5
 1f8:	b461      	st.w      	r3, (r4, 0x4)
 1fa:	8560      	ld.b      	r3, (r5, 0x0)
 1fc:	9441      	ld.w      	r2, (r4, 0x4)
 1fe:	e4632020 	andi      	r3, r3, 32
 202:	6cc8      	or      	r3, r2
 204:	b461      	st.w      	r3, (r4, 0x4)
 206:	3200      	movi      	r2, 0
 208:	9461      	ld.w      	r3, (r4, 0x4)
 20a:	2a1c      	subi      	r2, 29
 20c:	68c8      	and      	r3, r2
 20e:	8540      	ld.b      	r2, (r5, 0x0)
 210:	b461      	st.w      	r3, (r4, 0x4)
 212:	e4422007 	andi      	r2, r2, 7
 216:	9461      	ld.w      	r3, (r4, 0x4)
 218:	4242      	lsli      	r2, r2, 2
 21a:	6c8c      	or      	r2, r3
 21c:	b441      	st.w      	r2, (r4, 0x4)
 21e:	32c4      	movi      	r2, 196
 220:	4258      	lsli      	r2, r2, 24
 222:	9461      	ld.w      	r3, (r4, 0x4)
 224:	2a00      	subi      	r2, 1
 226:	68c8      	and      	r3, r2
 228:	d84500e4 	ld.b      	r2, (r5, 0xe4)
 22c:	b461      	st.w      	r3, (r4, 0x4)
 22e:	c4225462 	zext      	r2, r2, 3, 1
 232:	9461      	ld.w      	r3, (r4, 0x4)
 234:	425a      	lsli      	r2, r2, 26
 236:	6c8c      	or      	r2, r3
 238:	b441      	st.w      	r2, (r4, 0x4)
 23a:	9463      	ld.w      	r3, (r4, 0xc)
 23c:	c4035663 	zext      	r3, r3, 19, 0
 240:	b463      	st.w      	r3, (r4, 0xc)
 242:	9443      	ld.w      	r2, (r4, 0xc)
 244:	8d6e      	ld.h      	r3, (r5, 0x1c)
 246:	4374      	lsli      	r3, r3, 20
 248:	6cc8      	or      	r3, r2
 24a:	b463      	st.w      	r3, (r4, 0xc)
 24c:	9463      	ld.w      	r3, (r4, 0xc)
 24e:	3b92      	bclri      	r3, 18
 250:	3b93      	bclri      	r3, 19
 252:	b463      	st.w      	r3, (r4, 0xc)
 254:	8568      	ld.b      	r3, (r5, 0x8)
 256:	4372      	lsli      	r3, r3, 18
 258:	9443      	ld.w      	r2, (r4, 0xc)
 25a:	68c4      	and      	r3, r1
 25c:	6cc8      	or      	r3, r2
 25e:	b463      	st.w      	r3, (r4, 0xc)
 260:	9463      	ld.w      	r3, (r4, 0xc)
 262:	3b90      	bclri      	r3, 16
 264:	3b91      	bclri      	r3, 17
 266:	b463      	st.w      	r3, (r4, 0xc)
 268:	8567      	ld.b      	r3, (r5, 0x7)
 26a:	c4a354c3 	zext      	r3, r3, 6, 5
 26e:	9443      	ld.w      	r2, (r4, 0xc)
 270:	4370      	lsli      	r3, r3, 16
 272:	6cc8      	or      	r3, r2
 274:	b463      	st.w      	r3, (r4, 0xc)
 276:	9463      	ld.w      	r3, (r4, 0xc)
 278:	3b8f      	bclri      	r3, 15
 27a:	b463      	st.w      	r3, (r4, 0xc)
 27c:	d86500ad 	ld.b      	r3, (r5, 0xad)
 280:	c4435443 	zext      	r3, r3, 2, 2
 284:	9443      	ld.w      	r2, (r4, 0xc)
 286:	436f      	lsli      	r3, r3, 15
 288:	6cc8      	or      	r3, r2
 28a:	b463      	st.w      	r3, (r4, 0xc)
 28c:	9463      	ld.w      	r3, (r4, 0xc)
 28e:	3b8e      	bclri      	r3, 14
 290:	b463      	st.w      	r3, (r4, 0xc)
 292:	3280      	movi      	r2, 128
 294:	d86500ad 	ld.b      	r3, (r5, 0xad)
 298:	4247      	lsli      	r2, r2, 7
 29a:	436d      	lsli      	r3, r3, 13
 29c:	9423      	ld.w      	r1, (r4, 0xc)
 29e:	68c8      	and      	r3, r2
 2a0:	6cc4      	or      	r3, r1
 2a2:	b463      	st.w      	r3, (r4, 0xc)
 2a4:	9463      	ld.w      	r3, (r4, 0xc)
 2a6:	3b8d      	bclri      	r3, 13
 2a8:	b463      	st.w      	r3, (r4, 0xc)
 2aa:	d86500ad 	ld.b      	r3, (r5, 0xad)
 2ae:	e4632001 	andi      	r3, r3, 1
 2b2:	9443      	ld.w      	r2, (r4, 0xc)
 2b4:	436d      	lsli      	r3, r3, 13
 2b6:	6cc8      	or      	r3, r2
 2b8:	b463      	st.w      	r3, (r4, 0xc)
 2ba:	9463      	ld.w      	r3, (r4, 0xc)
 2bc:	ea021f00 	movi      	r2, 7936
 2c0:	6c8a      	nor      	r2, r2
 2c2:	68c8      	and      	r3, r2
 2c4:	b463      	st.w      	r3, (r4, 0xc)
 2c6:	8567      	ld.b      	r3, (r5, 0x7)
 2c8:	e463201f 	andi      	r3, r3, 31
 2cc:	9443      	ld.w      	r2, (r4, 0xc)
 2ce:	4368      	lsli      	r3, r3, 8
 2d0:	6cc8      	or      	r3, r2
 2d2:	b463      	st.w      	r3, (r4, 0xc)
 2d4:	9463      	ld.w      	r3, (r4, 0xc)
 2d6:	3b86      	bclri      	r3, 6
 2d8:	3b87      	bclri      	r3, 7
 2da:	b463      	st.w      	r3, (r4, 0xc)
 2dc:	8566      	ld.b      	r3, (r5, 0x6)
 2de:	9443      	ld.w      	r2, (r4, 0xc)
 2e0:	e46320c0 	andi      	r3, r3, 192
 2e4:	6cc8      	or      	r3, r2
 2e6:	b463      	st.w      	r3, (r4, 0xc)
 2e8:	9463      	ld.w      	r3, (r4, 0xc)
 2ea:	3b84      	bclri      	r3, 4
 2ec:	3b85      	bclri      	r3, 5
 2ee:	b463      	st.w      	r3, (r4, 0xc)
 2f0:	8566      	ld.b      	r3, (r5, 0x6)
 2f2:	9443      	ld.w      	r2, (r4, 0xc)
 2f4:	e4632030 	andi      	r3, r3, 48
 2f8:	6cc8      	or      	r3, r2
 2fa:	b463      	st.w      	r3, (r4, 0xc)
 2fc:	3200      	movi      	r2, 0
 2fe:	9463      	ld.w      	r3, (r4, 0xc)
 300:	2a0f      	subi      	r2, 16
 302:	68c8      	and      	r3, r2
 304:	b463      	st.w      	r3, (r4, 0xc)
 306:	8566      	ld.b      	r3, (r5, 0x6)
 308:	9443      	ld.w      	r2, (r4, 0xc)
 30a:	e463200f 	andi      	r3, r3, 15
 30e:	6cc8      	or      	r3, r2
 310:	b463      	st.w      	r3, (r4, 0xc)
 312:	946a      	ld.w      	r3, (r4, 0x28)
 314:	c40356e3 	zext      	r3, r3, 23, 0
 318:	b46a      	st.w      	r3, (r4, 0x28)
 31a:	8565      	ld.b      	r3, (r5, 0x5)
 31c:	944a      	ld.w      	r2, (r4, 0x28)
 31e:	4378      	lsli      	r3, r3, 24
 320:	6cc8      	or      	r3, r2
 322:	b46a      	st.w      	r3, (r4, 0x28)
 324:	ea22ff01 	movih      	r2, 65281
 328:	946a      	ld.w      	r3, (r4, 0x28)
 32a:	2a00      	subi      	r2, 1
 32c:	68c8      	and      	r3, r2
 32e:	b46a      	st.w      	r3, (r4, 0x28)
 330:	8564      	ld.b      	r3, (r5, 0x4)
 332:	944a      	ld.w      	r2, (r4, 0x28)
 334:	4370      	lsli      	r3, r3, 16
 336:	6cc8      	or      	r3, r2
 338:	b46a      	st.w      	r3, (r4, 0x28)
 33a:	946a      	ld.w      	r3, (r4, 0x28)
 33c:	ea02ff00 	movi      	r2, 65280
 340:	6c8a      	nor      	r2, r2
 342:	68c8      	and      	r3, r2
 344:	b46a      	st.w      	r3, (r4, 0x28)
 346:	8563      	ld.b      	r3, (r5, 0x3)
 348:	944a      	ld.w      	r2, (r4, 0x28)
 34a:	4368      	lsli      	r3, r3, 8
 34c:	6cc8      	or      	r3, r2
 34e:	b46a      	st.w      	r3, (r4, 0x28)
 350:	3200      	movi      	r2, 0
 352:	946a      	ld.w      	r3, (r4, 0x28)
 354:	2aff      	subi      	r2, 256
 356:	68c8      	and      	r3, r2
 358:	b46a      	st.w      	r3, (r4, 0x28)
 35a:	944a      	ld.w      	r2, (r4, 0x28)
 35c:	8562      	ld.b      	r3, (r5, 0x2)
 35e:	6cc8      	or      	r3, r2
 360:	3281      	movi      	r2, 129
 362:	b46a      	st.w      	r3, (r4, 0x28)
 364:	4258      	lsli      	r2, r2, 24
 366:	946b      	ld.w      	r3, (r4, 0x2c)
 368:	2a00      	subi      	r2, 1
 36a:	68c8      	and      	r3, r2
 36c:	b46b      	st.w      	r3, (r4, 0x2c)
 36e:	8d64      	ld.h      	r3, (r5, 0x8)
 370:	c4e355a3 	zext      	r3, r3, 13, 7
 374:	944b      	ld.w      	r2, (r4, 0x2c)
 376:	4378      	lsli      	r3, r3, 24
 378:	6cc8      	or      	r3, r2
 37a:	b46b      	st.w      	r3, (r4, 0x2c)
 37c:	ea22ff01 	movih      	r2, 65281
 380:	946b      	ld.w      	r3, (r4, 0x2c)
 382:	2a00      	subi      	r2, 1
 384:	68c8      	and      	r3, r2
 386:	b46b      	st.w      	r3, (r4, 0x2c)
 388:	8561      	ld.b      	r3, (r5, 0x1)
 38a:	944b      	ld.w      	r2, (r4, 0x2c)
 38c:	4370      	lsli      	r3, r3, 16
 38e:	6cc8      	or      	r3, r2
 390:	b46b      	st.w      	r3, (r4, 0x2c)
 392:	946b      	ld.w      	r3, (r4, 0x2c)
 394:	ea02ff00 	movi      	r2, 65280
 398:	6c8a      	nor      	r2, r2
 39a:	68c8      	and      	r3, r2
 39c:	b46b      	st.w      	r3, (r4, 0x2c)
 39e:	856b      	ld.b      	r3, (r5, 0xb)
 3a0:	944b      	ld.w      	r2, (r4, 0x2c)
 3a2:	4368      	lsli      	r3, r3, 8
 3a4:	6cc8      	or      	r3, r2
 3a6:	b46b      	st.w      	r3, (r4, 0x2c)
 3a8:	3200      	movi      	r2, 0
 3aa:	946b      	ld.w      	r3, (r4, 0x2c)
 3ac:	2aff      	subi      	r2, 256
 3ae:	68c8      	and      	r3, r2
 3b0:	b46b      	st.w      	r3, (r4, 0x2c)
 3b2:	944b      	ld.w      	r2, (r4, 0x2c)
 3b4:	856c      	ld.b      	r3, (r5, 0xc)
 3b6:	6cc8      	or      	r3, r2
 3b8:	b46b      	st.w      	r3, (r4, 0x2c)
 3ba:	946c      	ld.w      	r3, (r4, 0x30)
 3bc:	c40356e3 	zext      	r3, r3, 23, 0
 3c0:	b46c      	st.w      	r3, (r4, 0x30)
 3c2:	8d6f      	ld.h      	r3, (r5, 0x1e)
 3c4:	c4835563 	zext      	r3, r3, 11, 4
 3c8:	944c      	ld.w      	r2, (r4, 0x30)
 3ca:	4378      	lsli      	r3, r3, 24
 3cc:	6cc8      	or      	r3, r2
 3ce:	b46c      	st.w      	r3, (r4, 0x30)
 3d0:	ea22ff01 	movih      	r2, 65281
 3d4:	946c      	ld.w      	r3, (r4, 0x30)
 3d6:	2a00      	subi      	r2, 1
 3d8:	68c8      	and      	r3, r2
 3da:	b46c      	st.w      	r3, (r4, 0x30)
 3dc:	36ff      	movi      	r6, 255
 3de:	9567      	ld.w      	r3, (r5, 0x1c)
 3e0:	46d0      	lsli      	r6, r6, 16
 3e2:	4364      	lsli      	r3, r3, 4
 3e4:	944c      	ld.w      	r2, (r4, 0x30)
 3e6:	68d8      	and      	r3, r6
 3e8:	6cc8      	or      	r3, r2
 3ea:	b46c      	st.w      	r3, (r4, 0x30)
 3ec:	946c      	ld.w      	r3, (r4, 0x30)
 3ee:	3b8f      	bclri      	r3, 15
 3f0:	b46c      	st.w      	r3, (r4, 0x30)
 3f2:	946c      	ld.w      	r3, (r4, 0x30)
 3f4:	b46c      	st.w      	r3, (r4, 0x30)
 3f6:	946c      	ld.w      	r3, (r4, 0x30)
 3f8:	3b8e      	bclri      	r3, 14
 3fa:	b46c      	st.w      	r3, (r4, 0x30)
 3fc:	8568      	ld.b      	r3, (r5, 0x8)
 3fe:	c4c354c3 	zext      	r3, r3, 6, 6
 402:	944c      	ld.w      	r2, (r4, 0x30)
 404:	436e      	lsli      	r3, r3, 14
 406:	6cc8      	or      	r3, r2
 408:	b46c      	st.w      	r3, (r4, 0x30)
 40a:	946c      	ld.w      	r3, (r4, 0x30)
 40c:	3b8c      	bclri      	r3, 12
 40e:	3b8d      	bclri      	r3, 13
 410:	b46c      	st.w      	r3, (r4, 0x30)
 412:	d86500ad 	ld.b      	r3, (r5, 0xad)
 416:	c4635483 	zext      	r3, r3, 4, 3
 41a:	944c      	ld.w      	r2, (r4, 0x30)
 41c:	436c      	lsli      	r3, r3, 12
 41e:	6cc8      	or      	r3, r2
 420:	b46c      	st.w      	r3, (r4, 0x30)
 422:	946c      	ld.w      	r3, (r4, 0x30)
 424:	ea020f00 	movi      	r2, 3840
 428:	6c8a      	nor      	r2, r2
 42a:	68c8      	and      	r3, r2
 42c:	b46c      	st.w      	r3, (r4, 0x30)
 42e:	9562      	ld.w      	r3, (r5, 0x8)
 430:	c5c35623 	zext      	r3, r3, 17, 14
 434:	944c      	ld.w      	r2, (r4, 0x30)
 436:	4368      	lsli      	r3, r3, 8
 438:	6cc8      	or      	r3, r2
 43a:	b46c      	st.w      	r3, (r4, 0x30)
 43c:	946c      	ld.w      	r3, (r4, 0x30)
 43e:	3b87      	bclri      	r3, 7
 440:	b46c      	st.w      	r3, (r4, 0x30)
 442:	d86500ad 	ld.b      	r3, (r5, 0xad)
 446:	c4a354a3 	zext      	r3, r3, 5, 5
 44a:	944c      	ld.w      	r2, (r4, 0x30)
 44c:	4367      	lsli      	r3, r3, 7
 44e:	6cc8      	or      	r3, r2
 450:	b46c      	st.w      	r3, (r4, 0x30)
 452:	946c      	ld.w      	r3, (r4, 0x30)
 454:	3b85      	bclri      	r3, 5
 456:	b46c      	st.w      	r3, (r4, 0x30)
 458:	d86500f2 	ld.b      	r3, (r5, 0xf2)
 45c:	c4235423 	zext      	r3, r3, 1, 1
 460:	944c      	ld.w      	r2, (r4, 0x30)
 462:	4365      	lsli      	r3, r3, 5
 464:	6cc8      	or      	r3, r2
 466:	b46c      	st.w      	r3, (r4, 0x30)
 468:	946c      	ld.w      	r3, (r4, 0x30)
 46a:	3b86      	bclri      	r3, 6
 46c:	b46c      	st.w      	r3, (r4, 0x30)
 46e:	944c      	ld.w      	r2, (r4, 0x30)
 470:	857f      	ld.b      	r3, (r5, 0x1f)
 472:	c4835483 	zext      	r3, r3, 4, 4
 476:	4366      	lsli      	r3, r3, 6
 478:	6cc8      	or      	r3, r2
 47a:	b46c      	st.w      	r3, (r4, 0x30)
 47c:	946c      	ld.w      	r3, (r4, 0x30)
 47e:	3b84      	bclri      	r3, 4
 480:	b46c      	st.w      	r3, (r4, 0x30)
 482:	d86500f2 	ld.b      	r3, (r5, 0xf2)
 486:	4b67      	lsri      	r3, r3, 7
 488:	944c      	ld.w      	r2, (r4, 0x30)
 48a:	4364      	lsli      	r3, r3, 4
 48c:	6cc8      	or      	r3, r2
 48e:	b46c      	st.w      	r3, (r4, 0x30)
 490:	946c      	ld.w      	r3, (r4, 0x30)
 492:	3b83      	bclri      	r3, 3
 494:	b46c      	st.w      	r3, (r4, 0x30)
 496:	8568      	ld.b      	r3, (r5, 0x8)
 498:	c4a354a3 	zext      	r3, r3, 5, 5
 49c:	944c      	ld.w      	r2, (r4, 0x30)
 49e:	4363      	lsli      	r3, r3, 3
 4a0:	6cc8      	or      	r3, r2
 4a2:	b46c      	st.w      	r3, (r4, 0x30)
 4a4:	946c      	ld.w      	r3, (r4, 0x30)
 4a6:	3b82      	bclri      	r3, 2
 4a8:	b46c      	st.w      	r3, (r4, 0x30)
 4aa:	8568      	ld.b      	r3, (r5, 0x8)
 4ac:	c4835483 	zext      	r3, r3, 4, 4
 4b0:	944c      	ld.w      	r2, (r4, 0x30)
 4b2:	4362      	lsli      	r3, r3, 2
 4b4:	6cc8      	or      	r3, r2
 4b6:	b46c      	st.w      	r3, (r4, 0x30)
 4b8:	946c      	ld.w      	r3, (r4, 0x30)
 4ba:	3b80      	bclri      	r3, 0
 4bc:	3b81      	bclri      	r3, 1
 4be:	b46c      	st.w      	r3, (r4, 0x30)
 4c0:	8568      	ld.b      	r3, (r5, 0x8)
 4c2:	944c      	ld.w      	r2, (r4, 0x30)
 4c4:	c4435463 	zext      	r3, r3, 3, 2
 4c8:	6cc8      	or      	r3, r2
 4ca:	b46c      	st.w      	r3, (r4, 0x30)
 4cc:	e405000f 	addi      	r0, r5, 16
 4d0:	e0000000 	bsr      	0x0	// 0 <ah_wphy_open>
 4d4:	9568      	ld.w      	r3, (r5, 0x20)
 4d6:	b47d      	st.w      	r3, (r4, 0x74)
 4d8:	d8650024 	ld.b      	r3, (r5, 0x24)
 4dc:	b47e      	st.w      	r3, (r4, 0x78)
 4de:	d8450026 	ld.b      	r2, (r5, 0x26)
 4e2:	d8650025 	ld.b      	r3, (r5, 0x25)
 4e6:	4248      	lsli      	r2, r2, 8
 4e8:	6c8c      	or      	r2, r3
 4ea:	d8650027 	ld.b      	r3, (r5, 0x27)
 4ee:	4370      	lsli      	r3, r3, 16
 4f0:	6c8c      	or      	r2, r3
 4f2:	d8650028 	ld.b      	r3, (r5, 0x28)
 4f6:	4378      	lsli      	r3, r3, 24
 4f8:	6cc8      	or      	r3, r2
 4fa:	b47f      	st.w      	r3, (r4, 0x7c)
 4fc:	d8650029 	ld.b      	r3, (r5, 0x29)
 500:	dc642020 	st.w      	r3, (r4, 0x80)
 504:	3101      	movi      	r1, 1
 506:	e4650029 	addi      	r3, r5, 42
 50a:	d8034003 	ld.bs      	r0, (r3, 0x3)
 50e:	8340      	ld.b      	r2, (r3, 0x0)
 510:	4018      	lsli      	r0, r0, 24
 512:	6c80      	or      	r2, r0
 514:	8301      	ld.b      	r0, (r3, 0x1)
 516:	4008      	lsli      	r0, r0, 8
 518:	6c80      	or      	r2, r0
 51a:	d8034002 	ld.bs      	r0, (r3, 0x2)
 51e:	4010      	lsli      	r0, r0, 16
 520:	6818      	and      	r0, r6
 522:	6c80      	or      	r2, r0
 524:	4103      	lsli      	r0, r1, 3
 526:	6010      	addu      	r0, r4
 528:	b05f      	st.w      	r2, (r0, 0x7c)
 52a:	e441000f 	addi      	r2, r1, 16
 52e:	2100      	addi      	r1, 1
 530:	3948      	cmpnei      	r1, 8
 532:	8304      	ld.b      	r0, (r3, 0x4)
 534:	d4440900 	str.w      	r0, (r4, r2 << 3)
 538:	2304      	addi      	r3, 5
 53a:	0be8      	bt      	0x50a	// 50a <ah_wphy_open+0x50a>
 53c:	ea0c00ff 	movi      	r12, 255
 540:	34f8      	movi      	r4, 248
 542:	37f8      	movi      	r7, 248
 544:	36f8      	movi      	r6, 248
 546:	e445004c 	addi      	r2, r5, 77
 54a:	ea0d0000 	movi      	r13, 0
 54e:	c60c482c 	lsli      	r12, r12, 16
 552:	ea234002 	movih      	r3, 16386
 556:	3bae      	bseti      	r3, 14
 558:	4485      	lsli      	r4, r4, 5
 55a:	47ed      	lsli      	r7, r7, 13
 55c:	46d5      	lsli      	r6, r6, 21
 55e:	d8024003 	ld.bs      	r0, (r2, 0x3)
 562:	8220      	ld.b      	r1, (r2, 0x0)
 564:	4018      	lsli      	r0, r0, 24
 566:	6c40      	or      	r1, r0
 568:	8201      	ld.b      	r0, (r2, 0x1)
 56a:	4008      	lsli      	r0, r0, 8
 56c:	6c40      	or      	r1, r0
 56e:	d8024002 	ld.bs      	r0, (r2, 0x2)
 572:	4010      	lsli      	r0, r0, 16
 574:	6830      	and      	r0, r12
 576:	6c40      	or      	r1, r0
 578:	c46d4820 	lsli      	r0, r13, 3
 57c:	600c      	addu      	r0, r3
 57e:	e5ad0000 	addi      	r13, r13, 1
 582:	dc20202f 	st.w      	r1, (r0, 0xbc)
 586:	8225      	ld.b      	r1, (r2, 0x5)
 588:	d9020004 	ld.b      	r8, (r2, 0x4)
 58c:	4128      	lsli      	r1, r1, 8
 58e:	6c60      	or      	r1, r8
 590:	dc202030 	st.w      	r1, (r0, 0xc0)
 594:	d8220031 	ld.b      	r1, (r2, 0x31)
 598:	d9020032 	ld.b      	r8, (r2, 0x32)
 59c:	4128      	lsli      	r1, r1, 8
 59e:	c6084828 	lsli      	r8, r8, 16
 5a2:	6a1c      	and      	r8, r7
 5a4:	6850      	and      	r1, r4
 5a6:	6c60      	or      	r1, r8
 5a8:	d9020030 	ld.b      	r8, (r2, 0x30)
 5ac:	e508201f 	andi      	r8, r8, 31
 5b0:	6c60      	or      	r1, r8
 5b2:	d9020033 	ld.b      	r8, (r2, 0x33)
 5b6:	c7084828 	lsli      	r8, r8, 24
 5ba:	6a18      	and      	r8, r6
 5bc:	6c60      	or      	r1, r8
 5be:	dc20203f 	st.w      	r1, (r0, 0xfc)
 5c2:	d8220035 	ld.b      	r1, (r2, 0x35)
 5c6:	d9020034 	ld.b      	r8, (r2, 0x34)
 5ca:	4128      	lsli      	r1, r1, 8
 5cc:	6850      	and      	r1, r4
 5ce:	e508201f 	andi      	r8, r8, 31
 5d2:	eb4d0008 	cmpnei      	r13, 8
 5d6:	6c60      	or      	r1, r8
 5d8:	dc202040 	st.w      	r1, (r0, 0x100)
 5dc:	2205      	addi      	r2, 6
 5de:	0bc0      	bt      	0x55e	// 55e <ah_wphy_open+0x55e>
 5e0:	9340      	ld.w      	r2, (r3, 0x0)
 5e2:	ec424000 	ori      	r2, r2, 16384
 5e6:	b340      	st.w      	r2, (r3, 0x0)
 5e8:	d8432051 	ld.w      	r2, (r3, 0x144)
 5ec:	c40256e2 	zext      	r2, r2, 23, 0
 5f0:	dc432051 	st.w      	r2, (r3, 0x144)
 5f4:	d84500b9 	ld.b      	r2, (r5, 0xb9)
 5f8:	d8232051 	ld.w      	r1, (r3, 0x144)
 5fc:	4258      	lsli      	r2, r2, 24
 5fe:	6c84      	or      	r2, r1
 600:	dc432051 	st.w      	r2, (r3, 0x144)
 604:	ea21ff01 	movih      	r1, 65281
 608:	d8432051 	ld.w      	r2, (r3, 0x144)
 60c:	2900      	subi      	r1, 1
 60e:	6884      	and      	r2, r1
 610:	dc432051 	st.w      	r2, (r3, 0x144)
 614:	d84500b8 	ld.b      	r2, (r5, 0xb8)
 618:	d8232051 	ld.w      	r1, (r3, 0x144)
 61c:	4250      	lsli      	r2, r2, 16
 61e:	6c84      	or      	r2, r1
 620:	dc432051 	st.w      	r2, (r3, 0x144)
 624:	d8432051 	ld.w      	r2, (r3, 0x144)
 628:	ea01f800 	movi      	r1, 63488
 62c:	6c46      	nor      	r1, r1
 62e:	6884      	and      	r2, r1
 630:	dc432051 	st.w      	r2, (r3, 0x144)
 634:	d84500ba 	ld.b      	r2, (r5, 0xba)
 638:	e442201f 	andi      	r2, r2, 31
 63c:	d8232051 	ld.w      	r1, (r3, 0x144)
 640:	424b      	lsli      	r2, r2, 11
 642:	6c84      	or      	r2, r1
 644:	dc432051 	st.w      	r2, (r3, 0x144)
 648:	d8432051 	ld.w      	r2, (r3, 0x144)
 64c:	3a8a      	bclri      	r2, 10
 64e:	dc432051 	st.w      	r2, (r3, 0x144)
 652:	d84500e0 	ld.b      	r2, (r5, 0xe0)
 656:	e4422001 	andi      	r2, r2, 1
 65a:	d8232051 	ld.w      	r1, (r3, 0x144)
 65e:	424a      	lsli      	r2, r2, 10
 660:	6c84      	or      	r2, r1
 662:	dc432051 	st.w      	r2, (r3, 0x144)
 666:	d8432051 	ld.w      	r2, (r3, 0x144)
 66a:	3a89      	bclri      	r2, 9
 66c:	dc432051 	st.w      	r2, (r3, 0x144)
 670:	d84500e0 	ld.b      	r2, (r5, 0xe0)
 674:	c4225422 	zext      	r2, r2, 1, 1
 678:	d8232051 	ld.w      	r1, (r3, 0x144)
 67c:	4249      	lsli      	r2, r2, 9
 67e:	6c84      	or      	r2, r1
 680:	dc432051 	st.w      	r2, (r3, 0x144)
 684:	d8432051 	ld.w      	r2, (r3, 0x144)
 688:	3a87      	bclri      	r2, 7
 68a:	3a88      	bclri      	r2, 8
 68c:	dc432051 	st.w      	r2, (r3, 0x144)
 690:	d84500dc 	ld.b      	r2, (r5, 0xdc)
 694:	e4422003 	andi      	r2, r2, 3
 698:	d8232051 	ld.w      	r1, (r3, 0x144)
 69c:	4247      	lsli      	r2, r2, 7
 69e:	6c84      	or      	r2, r1
 6a0:	dc432051 	st.w      	r2, (r3, 0x144)
 6a4:	d8432051 	ld.w      	r2, (r3, 0x144)
 6a8:	3a86      	bclri      	r2, 6
 6aa:	dc432051 	st.w      	r2, (r3, 0x144)
 6ae:	d84500ba 	ld.b      	r2, (r5, 0xba)
 6b2:	c4a254a2 	zext      	r2, r2, 5, 5
 6b6:	d8232051 	ld.w      	r1, (r3, 0x144)
 6ba:	4246      	lsli      	r2, r2, 6
 6bc:	6c84      	or      	r2, r1
 6be:	dc432051 	st.w      	r2, (r3, 0x144)
 6c2:	3100      	movi      	r1, 0
 6c4:	d8432051 	ld.w      	r2, (r3, 0x144)
 6c8:	2938      	subi      	r1, 57
 6ca:	6884      	and      	r2, r1
 6cc:	dc432051 	st.w      	r2, (r3, 0x144)
 6d0:	854a      	ld.b      	r2, (r5, 0xa)
 6d2:	4a45      	lsri      	r2, r2, 5
 6d4:	d8232051 	ld.w      	r1, (r3, 0x144)
 6d8:	4243      	lsli      	r2, r2, 3
 6da:	6c84      	or      	r2, r1
 6dc:	dc432051 	st.w      	r2, (r3, 0x144)
 6e0:	3100      	movi      	r1, 0
 6e2:	d8432051 	ld.w      	r2, (r3, 0x144)
 6e6:	2907      	subi      	r1, 8
 6e8:	6884      	and      	r2, r1
 6ea:	dc432051 	st.w      	r2, (r3, 0x144)
 6ee:	854a      	ld.b      	r2, (r5, 0xa)
 6f0:	d8232051 	ld.w      	r1, (r3, 0x144)
 6f4:	c4425482 	zext      	r2, r2, 4, 2
 6f8:	6c84      	or      	r2, r1
 6fa:	dc432051 	st.w      	r2, (r3, 0x144)
 6fe:	d8251077 	ld.h      	r1, (r5, 0xee)
 702:	d84500af 	ld.b      	r2, (r5, 0xaf)
 706:	412d      	lsli      	r1, r1, 13
 708:	4248      	lsli      	r2, r2, 8
 70a:	6b04      	and      	r12, r1
 70c:	6f08      	or      	r12, r2
 70e:	d84500ae 	ld.b      	r2, (r5, 0xae)
 712:	6f08      	or      	r12, r2
 714:	dd832052 	st.w      	r12, (r3, 0x148)
 718:	d845202c 	ld.w      	r2, (r5, 0xb0)
 71c:	dc432053 	st.w      	r2, (r3, 0x14c)
 720:	d845202d 	ld.w      	r2, (r5, 0xb4)
 724:	dc432054 	st.w      	r2, (r3, 0x150)
 728:	9340      	ld.w      	r2, (r3, 0x0)
 72a:	3a8e      	bclri      	r2, 14
 72c:	b340      	st.w      	r2, (r3, 0x0)
 72e:	9340      	ld.w      	r2, (r3, 0x0)
 730:	3a8d      	bclri      	r2, 13
 732:	b340      	st.w      	r2, (r3, 0x0)
 734:	e42500bb 	addi      	r1, r5, 188
 738:	3200      	movi      	r2, 0
 73a:	ea2c03ff 	movih      	r12, 1023
 73e:	ea244002 	movih      	r4, 16386
 742:	3cae      	bseti      	r4, 14
 744:	d8615006 	ld.hs      	r3, (r1, 0xc)
 748:	8900      	ld.h      	r0, (r1, 0x0)
 74a:	4370      	lsli      	r3, r3, 16
 74c:	e4002fff 	andi      	r0, r0, 4095
 750:	68f0      	and      	r3, r12
 752:	6cc0      	or      	r3, r0
 754:	e4020056 	addi      	r0, r2, 87
 758:	2200      	addi      	r2, 1
 75a:	3a46      	cmpnei      	r2, 6
 75c:	d4040883 	str.w      	r3, (r4, r0 << 2)
 760:	2101      	addi      	r1, 2
 762:	0bf1      	bt      	0x744	// 744 <ah_wphy_open+0x744>
 764:	3307      	movi      	r3, 7
 766:	dc642077 	st.w      	r3, (r4, 0x1dc)
 76a:	ea230059 	movih      	r3, 89
 76e:	2313      	addi      	r3, 20
 770:	dc642079 	st.w      	r3, (r4, 0x1e4)
 774:	d8652035 	ld.w      	r3, (r5, 0xd4)
 778:	dc64207b 	st.w      	r3, (r4, 0x1ec)
 77c:	d84500eb 	ld.b      	r2, (r5, 0xeb)
 780:	d8652036 	ld.w      	r3, (r5, 0xd8)
 784:	c4225482 	zext      	r2, r2, 4, 1
 788:	dc64207c 	st.w      	r3, (r4, 0x1f0)
 78c:	425c      	lsli      	r2, r2, 28
 78e:	d865106f 	ld.h      	r3, (r5, 0xde)
 792:	6c8c      	or      	r2, r3
 794:	33f0      	movi      	r3, 240
 796:	436e      	lsli      	r3, r3, 14
 798:	6c8c      	or      	r2, r3
 79a:	31e0      	movi      	r1, 224
 79c:	d86500e3 	ld.b      	r3, (r5, 0xe3)
 7a0:	4133      	lsli      	r1, r1, 19
 7a2:	4374      	lsli      	r3, r3, 20
 7a4:	68c4      	and      	r3, r1
 7a6:	6c8c      	or      	r2, r3
 7a8:	d86500ec 	ld.b      	r3, (r5, 0xec)
 7ac:	dc44207d 	st.w      	r2, (r4, 0x1f4)
 7b0:	e443200f 	andi      	r2, r3, 15
 7b4:	4b64      	lsri      	r3, r3, 4
 7b6:	437c      	lsli      	r3, r3, 28
 7b8:	424c      	lsli      	r2, r2, 12
 7ba:	6c8c      	or      	r2, r3
 7bc:	d8651071 	ld.h      	r3, (r5, 0xe2)
 7c0:	e4632fff 	andi      	r3, r3, 4095
 7c4:	6c8c      	or      	r2, r3
 7c6:	d8651070 	ld.h      	r3, (r5, 0xe0)
 7ca:	c44355a3 	zext      	r3, r3, 13, 2
 7ce:	4370      	lsli      	r3, r3, 16
 7d0:	6c8c      	or      	r2, r3
 7d2:	dc442082 	st.w      	r2, (r4, 0x208)
 7d6:	d84500e7 	ld.b      	r2, (r5, 0xe7)
 7da:	c42254a3 	zext      	r3, r2, 5, 1
 7de:	437b      	lsli      	r3, r3, 27
 7e0:	4a46      	lsri      	r2, r2, 6
 7e2:	6cc8      	or      	r3, r2
 7e4:	d84500e8 	ld.b      	r2, (r5, 0xe8)
 7e8:	e442201f 	andi      	r2, r2, 31
 7ec:	4242      	lsli      	r2, r2, 2
 7ee:	6cc8      	or      	r3, r2
 7f0:	d8451072 	ld.h      	r2, (r5, 0xe4)
 7f4:	c48255c2 	zext      	r2, r2, 14, 4
 7f8:	4247      	lsli      	r2, r2, 7
 7fa:	6cc8      	or      	r3, r2
 7fc:	d84500e6 	ld.b      	r2, (r5, 0xe6)
 800:	e442203f 	andi      	r2, r2, 63
 804:	4252      	lsli      	r2, r2, 18
 806:	6cc8      	or      	r3, r2
 808:	d8451073 	ld.h      	r2, (r5, 0xe6)
 80c:	4252      	lsli      	r2, r2, 18
 80e:	6848      	and      	r1, r2
 810:	6cc4      	or      	r3, r1
 812:	dc642084 	st.w      	r3, (r4, 0x210)
 816:	d8451078 	ld.h      	r2, (r5, 0xf0)
 81a:	d86500ed 	ld.b      	r3, (r5, 0xed)
 81e:	c4635463 	zext      	r3, r3, 3, 3
 822:	e44221ff 	andi      	r2, r2, 511
 826:	4243      	lsli      	r2, r2, 3
 828:	436c      	lsli      	r3, r3, 12
 82a:	6cc8      	or      	r3, r2
 82c:	d84500f1 	ld.b      	r2, (r5, 0xf1)
 830:	c4225462 	zext      	r2, r2, 3, 1
 834:	6cc8      	or      	r3, r2
 836:	dc642089 	st.w      	r3, (r4, 0x224)
 83a:	9461      	ld.w      	r3, (r4, 0x4)
 83c:	3b9e      	bclri      	r3, 30
 83e:	b461      	st.w      	r3, (r4, 0x4)
 840:	d86500f1 	ld.b      	r3, (r5, 0xf1)
 844:	c4835483 	zext      	r3, r3, 4, 4
 848:	9441      	ld.w      	r2, (r4, 0x4)
 84a:	437e      	lsli      	r3, r3, 30
 84c:	6cc8      	or      	r3, r2
 84e:	b461      	st.w      	r3, (r4, 0x4)
 850:	e0000000 	bsr      	0x0	// 0 <ah_wphy_open>
 854:	e0000000 	bsr      	0x0	// 0 <ah_wphy_open>
 858:	e9000008 	bez      	r0, 0x868	// 868 <ah_wphy_open+0x868>
 85c:	0400      	br      	0x85c	// 85c <ah_wphy_open+0x85c>
 85e:	0000      	.short	0x0000
 860:	00000000 	.long	0x00000000
 864:	4002423c 	.long	0x4002423c
 868:	9461      	ld.w      	r3, (r4, 0x4)
 86a:	3b89      	bclri      	r3, 9
 86c:	b461      	st.w      	r3, (r4, 0x4)
 86e:	d86500e3 	ld.b      	r3, (r5, 0xe3)
 872:	4b67      	lsri      	r3, r3, 7
 874:	9441      	ld.w      	r2, (r4, 0x4)
 876:	4369      	lsli      	r3, r3, 9
 878:	6cc8      	or      	r3, r2
 87a:	b461      	st.w      	r3, (r4, 0x4)
 87c:	1495      	pop      	r4-r8, r15

Disassembly of section .text.ah_wphy_scrambler_init_get:

00000000 <ah_wphy_scrambler_init_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	d8032050 	ld.w      	r0, (r3, 0x140)
   a:	4819      	lsri      	r0, r0, 25
   c:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_avg_power_get:

00000000 <ah_wphy_avg_power_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	3180      	movi      	r1, 128
   8:	9345      	ld.w      	r2, (r3, 0x14)
   a:	4133      	lsli      	r1, r1, 19
   c:	6884      	and      	r2, r1
   e:	e9020006 	bez      	r2, 0x1a	// 1a <ah_wphy_avg_power_get+0x1a>
  12:	d8032056 	ld.w      	r0, (r3, 0x158)
  16:	5018      	asri      	r0, r0, 24
  18:	783c      	jmp      	r15
  1a:	3180      	movi      	r1, 128
  1c:	9345      	ld.w      	r2, (r3, 0x14)
  1e:	4132      	lsli      	r1, r1, 18
  20:	6884      	and      	r2, r1
  22:	d8032056 	ld.w      	r0, (r3, 0x158)
  26:	e9020005 	bez      	r2, 0x30	// 30 <ah_wphy_avg_power_get+0x30>
  2a:	c6005ae0 	sext      	r0, r0, 23, 16
  2e:	07f5      	br      	0x18	// 18 <ah_wphy_avg_power_get+0x18>
  30:	7402      	sextb      	r0, r0
  32:	07f3      	br      	0x18	// 18 <ah_wphy_avg_power_get+0x18>

Disassembly of section .text.ah_wphy_avg_evm_get:

00000000 <ah_wphy_avg_evm_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	d803207a 	ld.w      	r0, (r3, 0x1e8)
   a:	d863204f 	ld.w      	r3, (r3, 0x13c)
   e:	c66356c3 	zext      	r3, r3, 22, 19
  12:	e9030006 	bez      	r3, 0x1e	// 1e <ah_wphy_avg_evm_get+0x1e>
  16:	3b4a      	cmpnei      	r3, 10
  18:	0c03      	bf      	0x1e	// 1e <ah_wphy_avg_evm_get+0x1e>
  1a:	7402      	sextb      	r0, r0
  1c:	783c      	jmp      	r15
  1e:	2002      	addi      	r0, 3
  20:	07fd      	br      	0x1a	// 1a <ah_wphy_avg_evm_get+0x1a>

Disassembly of section .text.ah_wphy_err_code_get:

00000000 <ah_wphy_err_code_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	9304      	ld.w      	r0, (r3, 0x10)
   8:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_agc_info_get:

00000000 <ah_wphy_agc_info_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	d803207a 	ld.w      	r0, (r3, 0x1e8)
   a:	4810      	lsri      	r0, r0, 16
   c:	ea037777 	movi      	r3, 30583
  10:	680c      	and      	r0, r3
  12:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_rx_freq_offset_get:

00000000 <ah_wphy_rx_freq_offset_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	9347      	ld.w      	r2, (r3, 0x1c)
   8:	3280      	movi      	r2, 128
   a:	9309      	ld.w      	r0, (r3, 0x24)
   c:	424a      	lsli      	r2, r2, 10
   e:	6880      	and      	r2, r0
  10:	e9220019 	bnez      	r2, 0x42	// 42 <ah_wphy_rx_freq_offset_get+0x42>
  14:	6c83      	mov      	r2, r0
  16:	9305      	ld.w      	r0, (r3, 0x14)
  18:	e4002100 	andi      	r0, r0, 256
  1c:	e9000011 	bez      	r0, 0x3e	// 3e <ah_wphy_rx_freq_offset_get+0x3e>
  20:	9325      	ld.w      	r1, (r3, 0x14)
  22:	e4212010 	andi      	r1, r1, 16
  26:	e9210012 	bnez      	r1, 0x4a	// 4a <ah_wphy_rx_freq_offset_get+0x4a>
  2a:	d8032080 	ld.w      	r0, (r3, 0x200)
  2e:	3380      	movi      	r3, 128
  30:	436a      	lsli      	r3, r3, 10
  32:	68c0      	and      	r3, r0
  34:	e9030005 	bez      	r3, 0x3e	// 3e <ah_wphy_rx_freq_offset_get+0x3e>
  38:	ea23fffc 	movih      	r3, 65532
  3c:	6c0c      	or      	r0, r3
  3e:	6008      	addu      	r0, r2
  40:	783c      	jmp      	r15
  42:	ea22fffc 	movih      	r2, 65532
  46:	6c80      	or      	r2, r0
  48:	07e7      	br      	0x16	// 16 <ah_wphy_rx_freq_offset_get+0x16>
  4a:	3000      	movi      	r0, 0
  4c:	07f9      	br      	0x3e	// 3e <ah_wphy_rx_freq_offset_get+0x3e>

Disassembly of section .text.ah_wphy_info_get:

00000000 <ah_wphy_info_get>:
   0:	14d2      	push      	r4-r5, r15
   2:	ea234002 	movih      	r3, 16386
   6:	3bae      	bseti      	r3, 14
   8:	118c      	lrw      	r4, 0x0	// b8 <ah_wphy_info_get+0xb8>
   a:	3180      	movi      	r1, 128
   c:	9344      	ld.w      	r2, (r3, 0x10)
   e:	b440      	st.w      	r2, (r4, 0x0)
  10:	9344      	ld.w      	r2, (r3, 0x10)
  12:	b441      	st.w      	r2, (r4, 0x4)
  14:	9346      	ld.w      	r2, (r3, 0x18)
  16:	4a50      	lsri      	r2, r2, 16
  18:	ac44      	st.h      	r2, (r4, 0x8)
  1a:	9346      	ld.w      	r2, (r3, 0x18)
  1c:	ac45      	st.h      	r2, (r4, 0xa)
  1e:	412a      	lsli      	r1, r1, 10
  20:	9347      	ld.w      	r2, (r3, 0x1c)
  22:	6848      	and      	r1, r2
  24:	e921003d 	bnez      	r1, 0x9e	// 9e <ah_wphy_info_get+0x9e>
  28:	b443      	st.w      	r2, (r4, 0xc)
  2a:	3280      	movi      	r2, 128
  2c:	9369      	ld.w      	r3, (r3, 0x24)
  2e:	424a      	lsli      	r2, r2, 10
  30:	688c      	and      	r2, r3
  32:	e922003a 	bnez      	r2, 0xa6	// a6 <ah_wphy_info_get+0xa6>
  36:	b464      	st.w      	r3, (r4, 0x10)
  38:	ea234002 	movih      	r3, 16386
  3c:	3bae      	bseti      	r3, 14
  3e:	3180      	movi      	r1, 128
  40:	9348      	ld.w      	r2, (r3, 0x20)
  42:	b445      	st.w      	r2, (r4, 0x14)
  44:	d843204f 	ld.w      	r2, (r3, 0x13c)
  48:	b446      	st.w      	r2, (r4, 0x18)
  4a:	d8432050 	ld.w      	r2, (r3, 0x140)
  4e:	b447      	st.w      	r2, (r4, 0x1c)
  50:	d8432055 	ld.w      	r2, (r3, 0x154)
  54:	b448      	st.w      	r2, (r4, 0x20)
  56:	d8432056 	ld.w      	r2, (r3, 0x158)
  5a:	b449      	st.w      	r2, (r4, 0x24)
  5c:	d843207a 	ld.w      	r2, (r3, 0x1e8)
  60:	b44a      	st.w      	r2, (r4, 0x28)
  62:	d843207e 	ld.w      	r2, (r3, 0x1f8)
  66:	b44c      	st.w      	r2, (r4, 0x30)
  68:	d8432080 	ld.w      	r2, (r3, 0x200)
  6c:	412a      	lsli      	r1, r1, 10
  6e:	6848      	and      	r1, r2
  70:	6d4f      	mov      	r5, r3
  72:	e921001e 	bnez      	r1, 0xae	// ae <ah_wphy_info_get+0xae>
  76:	b44d      	st.w      	r2, (r4, 0x34)
  78:	d8652083 	ld.w      	r3, (r5, 0x20c)
  7c:	b46e      	st.w      	r3, (r4, 0x38)
  7e:	d8652088 	ld.w      	r3, (r5, 0x220)
  82:	b46f      	st.w      	r3, (r4, 0x3c)
  84:	e0000000 	bsr      	0x0	// 0 <ah_wphy_info_get>
  88:	d865208d 	ld.w      	r3, (r5, 0x234)
  8c:	c4035603 	zext      	r3, r3, 16, 0
  90:	b470      	st.w      	r3, (r4, 0x40)
  92:	d865208e 	ld.w      	r3, (r5, 0x238)
  96:	c4035603 	zext      	r3, r3, 16, 0
  9a:	b471      	st.w      	r3, (r4, 0x44)
  9c:	1492      	pop      	r4-r5, r15
  9e:	ea21fffc 	movih      	r1, 65532
  a2:	6c84      	or      	r2, r1
  a4:	07c2      	br      	0x28	// 28 <ah_wphy_info_get+0x28>
  a6:	ea22fffc 	movih      	r2, 65532
  aa:	6cc8      	or      	r3, r2
  ac:	07c5      	br      	0x36	// 36 <ah_wphy_info_get+0x36>
  ae:	ea23fffc 	movih      	r3, 65532
  b2:	6c8c      	or      	r2, r3
  b4:	07e1      	br      	0x76	// 76 <ah_wphy_info_get+0x76>
  b6:	0000      	.short	0x0000
  b8:	00000000 	.long	0x00000000

Disassembly of section .text.ah_wphy_cali_rx_imb_en:

00000000 <ah_wphy_cali_rx_imb_en>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	c6a05021 	bmaski      	r1, 22
   a:	c6214901 	rotli      	r1, r1, 17
   e:	d8432077 	ld.w      	r2, (r3, 0x1dc)
  12:	3a80      	bclri      	r2, 0
  14:	dc432077 	st.w      	r2, (r3, 0x1dc)
  18:	d8432077 	ld.w      	r2, (r3, 0x1dc)
  1c:	3a81      	bclri      	r2, 1
  1e:	3a82      	bclri      	r2, 2
  20:	dc432077 	st.w      	r2, (r3, 0x1dc)
  24:	d8432077 	ld.w      	r2, (r3, 0x1dc)
  28:	ec420018 	ori      	r2, r2, 24
  2c:	dc432077 	st.w      	r2, (r3, 0x1dc)
  30:	d8432077 	ld.w      	r2, (r3, 0x1dc)
  34:	6884      	and      	r2, r1
  36:	dc432077 	st.w      	r2, (r3, 0x1dc)
  3a:	d8432077 	ld.w      	r2, (r3, 0x1dc)
  3e:	ec422800 	ori      	r2, r2, 10240
  42:	dc432077 	st.w      	r2, (r3, 0x1dc)
  46:	d8432077 	ld.w      	r2, (r3, 0x1dc)
  4a:	3a85      	bclri      	r2, 5
  4c:	3a86      	bclri      	r2, 6
  4e:	dc432077 	st.w      	r2, (r3, 0x1dc)
  52:	d8432077 	ld.w      	r2, (r3, 0x1dc)
  56:	ec420001 	ori      	r2, r2, 1
  5a:	dc432077 	st.w      	r2, (r3, 0x1dc)
  5e:	d8632077 	ld.w      	r3, (r3, 0x1dc)
  62:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_cali_rx_imb_dis:

00000000 <ah_wphy_cali_rx_imb_dis>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	d8432077 	ld.w      	r2, (r3, 0x1dc)
   a:	ec420060 	ori      	r2, r2, 96
   e:	dc432077 	st.w      	r2, (r3, 0x1dc)
  12:	d8432077 	ld.w      	r2, (r3, 0x1dc)
  16:	e4422060 	andi      	r2, r2, 96
  1a:	eb420060 	cmpnei      	r2, 96
  1e:	0bfa      	bt      	0x12	// 12 <ah_wphy_cali_rx_imb_dis+0x12>
  20:	104c      	lrw      	r2, 0x0	// 50 <ah_wphy_cali_rx_imb_dis+0x50>
  22:	d8632078 	ld.w      	r3, (r3, 0x1e0)
  26:	d9a21017 	ld.h      	r13, (r2, 0x2e)
  2a:	c603484c 	lsri      	r12, r3, 16
  2e:	c5ac5d20 	ins      	r13, r12, 9, 0
  32:	e58c23ff 	andi      	r12, r12, 1023
  36:	dda21017 	st.h      	r13, (r2, 0x2e)
  3a:	74cd      	zexth      	r3, r3
  3c:	dd801000 	st.h      	r12, (r0, 0x0)
  40:	8a16      	ld.h      	r0, (r2, 0x2c)
  42:	c4035d60 	ins      	r0, r3, 11, 0
  46:	e4632fff 	andi      	r3, r3, 4095
  4a:	aa16      	st.h      	r0, (r2, 0x2c)
  4c:	a960      	st.h      	r3, (r1, 0x0)
  4e:	783c      	jmp      	r15
  50:	00000000 	.long	0x00000000

Disassembly of section .text.ah_wphy_rx_testmode_enable:

00000000 <ah_wphy_rx_testmode_enable>:
   0:	ea224002 	movih      	r2, 16386
   4:	3aae      	bseti      	r2, 14
   6:	926c      	ld.w      	r3, (r2, 0x30)
   8:	3b84      	bclri      	r3, 4
   a:	b26c      	st.w      	r3, (r2, 0x30)
   c:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_rx_testmode_disable:

00000000 <ah_wphy_rx_testmode_disable>:
   0:	ea224002 	movih      	r2, 16386
   4:	3aae      	bseti      	r2, 14
   6:	926c      	ld.w      	r3, (r2, 0x30)
   8:	ec630010 	ori      	r3, r3, 16
   c:	b26c      	st.w      	r3, (r2, 0x30)
   e:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_special_reg_write:

00000000 <ah_wphy_special_reg_write>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	dc032081 	st.w      	r0, (r3, 0x204)
   a:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_direct_rx_iq:

00000000 <ah_wphy_direct_rx_iq>:
   0:	14d0      	push      	r15
   2:	ea224002 	movih      	r2, 16386
   6:	3aae      	bseti      	r2, 14
   8:	9260      	ld.w      	r3, (r2, 0x0)
   a:	3b9d      	bclri      	r3, 29
   c:	b260      	st.w      	r3, (r2, 0x0)
   e:	1063      	lrw      	r3, 0x0	// 18 <ah_wphy_direct_rx_iq+0x18>
  10:	b315      	st.w      	r0, (r3, 0x54)
  12:	e0000000 	bsr      	0x0	// 0 <ah_wphy_direct_rx_iq>
  16:	1490      	pop      	r15
  18:	0000      	.short	0x0000
	...

Disassembly of section .text.ah_wphy_rx_iq_swap:

00000000 <ah_wphy_rx_iq_swap>:
   0:	14d0      	push      	r15
   2:	ea224002 	movih      	r2, 16386
   6:	3aae      	bseti      	r2, 14
   8:	9260      	ld.w      	r3, (r2, 0x0)
   a:	3bbd      	bseti      	r3, 29
   c:	b260      	st.w      	r3, (r2, 0x0)
   e:	1063      	lrw      	r3, 0x0	// 18 <ah_wphy_rx_iq_swap+0x18>
  10:	b315      	st.w      	r0, (r3, 0x54)
  12:	e0000000 	bsr      	0x0	// 0 <ah_wphy_rx_iq_swap>
  16:	1490      	pop      	r15
  18:	0000      	.short	0x0000
	...

Disassembly of section .text.ah_wphy_para_change:

00000000 <ah_wphy_para_change>:
   0:	14d0      	push      	r15
   2:	1065      	lrw      	r3, 0x0	// 14 <ah_wphy_para_change+0x14>
   4:	3284      	movi      	r2, 132
   6:	6c43      	mov      	r1, r0
   8:	4242      	lsli      	r2, r2, 2
   a:	9313      	ld.w      	r0, (r3, 0x4c)
   c:	e0000000 	bsr      	0x0	// 0 <memcpy>
  10:	1490      	pop      	r15
  12:	0000      	.short	0x0000
  14:	00000000 	.long	0x00000000

Disassembly of section .text.ah_wphy_close:

00000000 <ah_wphy_close>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <ah_wphy_close>
   6:	e0000000 	bsr      	0x0	// 0 <ah_wphy_close>
   a:	1490      	pop      	r15

Disassembly of section .text.ah_wphy_rx_agc_disable:

00000000 <ah_wphy_rx_agc_disable>:
   0:	1069      	lrw      	r3, 0x0	// 24 <ah_wphy_rx_agc_disable+0x24>
   2:	3001      	movi      	r0, 1
   4:	9333      	ld.w      	r1, (r3, 0x4c)
   6:	ea234002 	movih      	r3, 16386
   a:	3bae      	bseti      	r3, 14
   c:	934c      	ld.w      	r2, (r3, 0x30)
   e:	3a86      	bclri      	r2, 6
  10:	b34c      	st.w      	r2, (r3, 0x30)
  12:	815f      	ld.b      	r2, (r1, 0x1f)
  14:	c4405c04 	ins      	r2, r0, 4, 4
  18:	a15f      	st.b      	r2, (r1, 0x1f)
  1a:	934c      	ld.w      	r2, (r3, 0x30)
  1c:	ec420040 	ori      	r2, r2, 64
  20:	b34c      	st.w      	r2, (r3, 0x30)
  22:	783c      	jmp      	r15
  24:	0000      	.short	0x0000
	...

Disassembly of section .text.ah_wphy_rx_agc_enable:

00000000 <ah_wphy_rx_agc_enable>:
   0:	1068      	lrw      	r3, 0x0	// 20 <ah_wphy_rx_agc_enable+0x20>
   2:	3000      	movi      	r0, 0
   4:	9333      	ld.w      	r1, (r3, 0x4c)
   6:	ea234002 	movih      	r3, 16386
   a:	3bae      	bseti      	r3, 14
   c:	934c      	ld.w      	r2, (r3, 0x30)
   e:	3a86      	bclri      	r2, 6
  10:	b34c      	st.w      	r2, (r3, 0x30)
  12:	815f      	ld.b      	r2, (r1, 0x1f)
  14:	c4405c04 	ins      	r2, r0, 4, 4
  18:	a15f      	st.b      	r2, (r1, 0x1f)
  1a:	934c      	ld.w      	r2, (r3, 0x30)
  1c:	b34c      	st.w      	r2, (r3, 0x30)
  1e:	783c      	jmp      	r15
  20:	00000000 	.long	0x00000000

Disassembly of section .text.ah_wphy_rx_imb_tab_cfg:

00000000 <ah_wphy_rx_imb_tab_cfg>:
   0:	14d1      	push      	r4, r15
   2:	1070      	lrw      	r3, 0x0	// 40 <ah_wphy_rx_imb_tab_cfg+0x40>
   4:	ea0d03ff 	movi      	r13, 1023
   8:	6f76      	nor      	r13, r13
   a:	9333      	ld.w      	r1, (r3, 0x4c)
   c:	e44100bb 	addi      	r2, r1, 188
  10:	e58100c7 	addi      	r12, r1, 200
  14:	6c4f      	mov      	r1, r3
  16:	9060      	ld.w      	r3, (r0, 0x0)
  18:	e4832fff 	andi      	r4, r3, 4095
  1c:	c6035723 	zext      	r3, r3, 25, 16
  20:	aa80      	st.h      	r4, (r2, 0x0)
  22:	e4832200 	andi      	r4, r3, 512
  26:	e924000b 	bnez      	r4, 0x3c	// 3c <ah_wphy_rx_imb_tab_cfg+0x3c>
  2a:	aa66      	st.h      	r3, (r2, 0xc)
  2c:	2201      	addi      	r2, 2
  2e:	64b2      	cmpne      	r12, r2
  30:	2003      	addi      	r0, 4
  32:	0bf2      	bt      	0x16	// 16 <ah_wphy_rx_imb_tab_cfg+0x16>
  34:	9115      	ld.w      	r0, (r1, 0x54)
  36:	e0000000 	bsr      	0x0	// 0 <ah_wphy_rx_imb_tab_cfg>
  3a:	1491      	pop      	r4, r15
  3c:	6cf4      	or      	r3, r13
  3e:	07f6      	br      	0x2a	// 2a <ah_wphy_rx_imb_tab_cfg+0x2a>
  40:	00000000 	.long	0x00000000

Disassembly of section .text.ah_wphy_rx_dc_tab_cfg:

00000000 <ah_wphy_rx_dc_tab_cfg>:
   0:	14d0      	push      	r15
   2:	106b      	lrw      	r3, 0x0	// 2c <ah_wphy_rx_dc_tab_cfg+0x2c>
   4:	6c83      	mov      	r2, r0
   6:	9373      	ld.w      	r3, (r3, 0x4c)
   8:	230f      	addi      	r3, 16
   a:	5836      	addi      	r1, r0, 6
   c:	d9820000 	ld.b      	r12, (r2, 0x0)
  10:	dd830000 	st.b      	r12, (r3, 0x0)
  14:	d9820006 	ld.b      	r12, (r2, 0x6)
  18:	2200      	addi      	r2, 1
  1a:	644a      	cmpne      	r2, r1
  1c:	dd830006 	st.b      	r12, (r3, 0x6)
  20:	2300      	addi      	r3, 1
  22:	0bf5      	bt      	0xc	// c <ah_wphy_rx_dc_tab_cfg+0xc>
  24:	e0000000 	bsr      	0x0	// 0 <ah_wphy_rx_dc_tab_cfg>
  28:	1490      	pop      	r15
  2a:	0000      	.short	0x0000
  2c:	0000      	.short	0x0000
	...

Disassembly of section .text.ah_wphy_rx_gain_idx_cfg:

00000000 <ah_wphy_rx_gain_idx_cfg>:
   0:	106c      	lrw      	r3, 0x0	// 30 <ah_wphy_rx_gain_idx_cfg+0x30>
   2:	3206      	movi      	r2, 6
   4:	7c80      	mult      	r2, r0
   6:	9373      	ld.w      	r3, (r3, 0x4c)
   8:	60c8      	addu      	r3, r2
   a:	4003      	lsli      	r0, r0, 3
   c:	dc230082 	st.b      	r1, (r3, 0x82)
  10:	ea234002 	movih      	r3, 16386
  14:	3bae      	bseti      	r3, 14
  16:	600c      	addu      	r0, r3
  18:	ea021f00 	movi      	r2, 7936
  1c:	6c8a      	nor      	r2, r2
  1e:	d8602040 	ld.w      	r3, (r0, 0x100)
  22:	68c8      	and      	r3, r2
  24:	4128      	lsli      	r1, r1, 8
  26:	6c4c      	or      	r1, r3
  28:	dc202040 	st.w      	r1, (r0, 0x100)
  2c:	783c      	jmp      	r15
  2e:	0000      	.short	0x0000
  30:	00000000 	.long	0x00000000

Disassembly of section .text.ah_wphy_rx_gain_tab_cfg:

00000000 <ah_wphy_rx_gain_tab_cfg>:
   0:	1166      	lrw      	r3, 0x0	// 98 <ah_wphy_rx_gain_tab_cfg+0x98>
   2:	3206      	movi      	r2, 6
   4:	9373      	ld.w      	r3, (r3, 0x4c)
   6:	7c80      	mult      	r2, r0
   8:	60c8      	addu      	r3, r2
   a:	8140      	ld.b      	r2, (r1, 0x0)
   c:	dc43004d 	st.b      	r2, (r3, 0x4d)
  10:	8141      	ld.b      	r2, (r1, 0x1)
  12:	dc43004e 	st.b      	r2, (r3, 0x4e)
  16:	8142      	ld.b      	r2, (r1, 0x2)
  18:	dc43004f 	st.b      	r2, (r3, 0x4f)
  1c:	8143      	ld.b      	r2, (r1, 0x3)
  1e:	dc430050 	st.b      	r2, (r3, 0x50)
  22:	8144      	ld.b      	r2, (r1, 0x4)
  24:	dc430051 	st.b      	r2, (r3, 0x51)
  28:	8145      	ld.b      	r2, (r1, 0x5)
  2a:	dc430052 	st.b      	r2, (r3, 0x52)
  2e:	3200      	movi      	r2, 0
  30:	dc43007d 	st.b      	r2, (r3, 0x7d)
  34:	3201      	movi      	r2, 1
  36:	dc43007e 	st.b      	r2, (r3, 0x7e)
  3a:	3202      	movi      	r2, 2
  3c:	dc43007f 	st.b      	r2, (r3, 0x7f)
  40:	3203      	movi      	r2, 3
  42:	dc430080 	st.b      	r2, (r3, 0x80)
  46:	3204      	movi      	r2, 4
  48:	dc430081 	st.b      	r2, (r3, 0x81)
  4c:	3205      	movi      	r2, 5
  4e:	dc430082 	st.b      	r2, (r3, 0x82)
  52:	8141      	ld.b      	r2, (r1, 0x1)
  54:	8160      	ld.b      	r3, (r1, 0x0)
  56:	4248      	lsli      	r2, r2, 8
  58:	6c8c      	or      	r2, r3
  5a:	8162      	ld.b      	r3, (r1, 0x2)
  5c:	4370      	lsli      	r3, r3, 16
  5e:	6c8c      	or      	r2, r3
  60:	8163      	ld.b      	r3, (r1, 0x3)
  62:	4378      	lsli      	r3, r3, 24
  64:	6cc8      	or      	r3, r2
  66:	ea2c4002 	movih      	r12, 16386
  6a:	c5cc284c 	bseti      	r12, r12, 14
  6e:	4043      	lsli      	r2, r0, 3
  70:	60b0      	addu      	r2, r12
  72:	dc62202f 	st.w      	r3, (r2, 0xbc)
  76:	8165      	ld.b      	r3, (r1, 0x5)
  78:	d9810004 	ld.b      	r12, (r1, 0x4)
  7c:	4368      	lsli      	r3, r3, 8
  7e:	6cf0      	or      	r3, r12
  80:	dc622030 	st.w      	r3, (r2, 0xc0)
  84:	ea230302 	movih      	r3, 770
  88:	3ba8      	bseti      	r3, 8
  8a:	dc62203f 	st.w      	r3, (r2, 0xfc)
  8e:	ea030504 	movi      	r3, 1284
  92:	dc622040 	st.w      	r3, (r2, 0x100)
  96:	783c      	jmp      	r15
  98:	00000000 	.long	0x00000000

Disassembly of section .text.ah_wphy_cca_th_cfg:

00000000 <ah_wphy_cca_th_cfg>:
   0:	14c8      	push      	r4-r11
   2:	ea2d4002 	movih      	r13, 16386
   6:	c5cd284d 	bseti      	r13, r13, 14
   a:	1173      	lrw      	r3, 0x0	// d4 <ah_wphy_cca_th_cfg+0xd4>
   c:	d84d2000 	ld.w      	r2, (r13, 0x0)
  10:	ec424000 	ori      	r2, r2, 16384
  14:	9373      	ld.w      	r3, (r3, 0x4c)
  16:	dc4d2000 	st.w      	r2, (r13, 0x0)
  1a:	d9404000 	ld.bs      	r10, (r0, 0x0)
  1e:	dd4300ae 	st.b      	r10, (r3, 0xae)
  22:	d9804001 	ld.bs      	r12, (r0, 0x1)
  26:	dd8300af 	st.b      	r12, (r3, 0xaf)
  2a:	d9204002 	ld.bs      	r9, (r0, 0x2)
  2e:	dd2300b0 	st.b      	r9, (r3, 0xb0)
  32:	d8e04003 	ld.bs      	r7, (r0, 0x3)
  36:	dce300b1 	st.b      	r7, (r3, 0xb1)
  3a:	d9004004 	ld.bs      	r8, (r0, 0x4)
  3e:	dd0300b2 	st.b      	r8, (r3, 0xb2)
  42:	d8204005 	ld.bs      	r1, (r0, 0x5)
  46:	dc2300b3 	st.b      	r1, (r3, 0xb3)
  4a:	d8c04006 	ld.bs      	r6, (r0, 0x6)
  4e:	dcc300b4 	st.b      	r6, (r3, 0xb4)
  52:	d8804007 	ld.bs      	r4, (r0, 0x7)
  56:	dc8300b5 	st.b      	r4, (r3, 0xb5)
  5a:	d8a04008 	ld.bs      	r5, (r0, 0x8)
  5e:	dca300b6 	st.b      	r5, (r3, 0xb6)
  62:	d8404009 	ld.bs      	r2, (r0, 0x9)
  66:	dc4300b7 	st.b      	r2, (r3, 0xb7)
  6a:	800a      	ld.b      	r0, (r0, 0xa)
  6c:	d9631077 	ld.h      	r11, (r3, 0xee)
  70:	c5605ce3 	ins      	r11, r0, 10, 3
  74:	dd631077 	st.h      	r11, (r3, 0xee)
  78:	33ff      	movi      	r3, 255
  7a:	4370      	lsli      	r3, r3, 16
  7c:	e52920ff 	andi      	r9, r9, 255
  80:	e4c620ff 	andi      	r6, r6, 255
  84:	45b0      	lsli      	r5, r5, 16
  86:	c50c482c 	lsli      	r12, r12, 8
  8a:	4138      	lsli      	r1, r1, 24
  8c:	c6084828 	lsli      	r8, r8, 16
  90:	4258      	lsli      	r2, r2, 24
  92:	6a0c      	and      	r8, r3
  94:	e54a20ff 	andi      	r10, r10, 255
  98:	68d4      	and      	r3, r5
  9a:	6c64      	or      	r1, r9
  9c:	6c98      	or      	r2, r6
  9e:	c40c55ec 	zext      	r12, r12, 15, 0
  a2:	47e8      	lsli      	r7, r7, 8
  a4:	4488      	lsli      	r4, r4, 8
  a6:	6f28      	or      	r12, r10
  a8:	4010      	lsli      	r0, r0, 16
  aa:	6c60      	or      	r1, r8
  ac:	c40755e7 	zext      	r7, r7, 15, 0
  b0:	6c8c      	or      	r2, r3
  b2:	c40455e4 	zext      	r4, r4, 15, 0
  b6:	6f00      	or      	r12, r0
  b8:	6c5c      	or      	r1, r7
  ba:	6c90      	or      	r2, r4
  bc:	dd8d2052 	st.w      	r12, (r13, 0x148)
  c0:	dc2d2053 	st.w      	r1, (r13, 0x14c)
  c4:	dc4d2054 	st.w      	r2, (r13, 0x150)
  c8:	d86d2000 	ld.w      	r3, (r13, 0x0)
  cc:	3b8e      	bclri      	r3, 14
  ce:	dc6d2000 	st.w      	r3, (r13, 0x0)
  d2:	1488      	pop      	r4-r11
  d4:	00000000 	.long	0x00000000

Disassembly of section .text.ah_wphy_approved_bw_get:

00000000 <ah_wphy_approved_bw_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	d8032050 	ld.w      	r0, (r3, 0x140)
   a:	c5405560 	zext      	r0, r0, 11, 10
   e:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_obss_sd_det_enable:

00000000 <ah_wphy_obss_sd_det_enable>:
   0:	ea224002 	movih      	r2, 16386
   4:	3aae      	bseti      	r2, 14
   6:	d8622089 	ld.w      	r3, (r2, 0x224)
   a:	ec631000 	ori      	r3, r3, 4096
   e:	dc622089 	st.w      	r3, (r2, 0x224)
  12:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_obss_sd_det_disable:

00000000 <ah_wphy_obss_sd_det_disable>:
   0:	ea224002 	movih      	r2, 16386
   4:	3aae      	bseti      	r2, 14
   6:	d8622089 	ld.w      	r3, (r2, 0x224)
   a:	3b8c      	bclri      	r3, 12
   c:	dc622089 	st.w      	r3, (r2, 0x224)
  10:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_obss_para_cfg:

00000000 <ah_wphy_obss_para_cfg>:
   0:	14c1      	push      	r4
   2:	4123      	lsli      	r1, r1, 3
   4:	ea2c4002 	movih      	r12, 16386
   8:	c5cc284c 	bseti      	r12, r12, 14
   c:	e4002007 	andi      	r0, r0, 7
  10:	e4212ff8 	andi      	r1, r1, 4088
  14:	d9ac2089 	ld.w      	r13, (r12, 0x224)
  18:	ea042fff 	movi      	r4, 12287
  1c:	6d12      	nor      	r4, r4
  1e:	6c40      	or      	r1, r0
  20:	3080      	movi      	r0, 128
  22:	6b50      	and      	r13, r4
  24:	4006      	lsli      	r0, r0, 6
  26:	424d      	lsli      	r2, r2, 13
  28:	ddac2089 	st.w      	r13, (r12, 0x224)
  2c:	6880      	and      	r2, r0
  2e:	d9ac2089 	ld.w      	r13, (r12, 0x224)
  32:	6c48      	or      	r1, r2
  34:	6c74      	or      	r1, r13
  36:	dc2c2089 	st.w      	r1, (r12, 0x224)
  3a:	31ff      	movi      	r1, 255
  3c:	4130      	lsli      	r1, r1, 16
  3e:	4370      	lsli      	r3, r3, 16
  40:	d84c2052 	ld.w      	r2, (r12, 0x148)
  44:	68c4      	and      	r3, r1
  46:	6cc8      	or      	r3, r2
  48:	dc6c2052 	st.w      	r3, (r12, 0x148)
  4c:	1481      	pop      	r4

Disassembly of section .text.ah_wphy_rx_psdu_crc_get:

00000000 <ah_wphy_rx_psdu_crc_get>:
   0:	ea224002 	movih      	r2, 16386
   4:	3aae      	bseti      	r2, 14
   6:	3180      	movi      	r1, 128
   8:	d862204f 	ld.w      	r3, (r2, 0x13c)
   c:	4132      	lsli      	r1, r1, 18
   e:	68c4      	and      	r3, r1
  10:	e9230006 	bnez      	r3, 0x1c	// 1c <ah_wphy_rx_psdu_crc_get+0x1c>
  14:	d802208c 	ld.w      	r0, (r2, 0x230)
  18:	4810      	lsri      	r0, r0, 16
  1a:	783c      	jmp      	r15
  1c:	ea00fffe 	movi      	r0, 65534
  20:	07fd      	br      	0x1a	// 1a <ah_wphy_rx_psdu_crc_get+0x1a>

Disassembly of section .text.ah_wphy_tx_psdu_crc_get:

00000000 <ah_wphy_tx_psdu_crc_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	d803208c 	ld.w      	r0, (r3, 0x230)
   a:	7401      	zexth      	r0, r0
   c:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_dpd_info_get:

00000000 <ah_wphy_dpd_info_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	d8032083 	ld.w      	r0, (r3, 0x20c)
   a:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_rx_sat_info_get:

00000000 <ah_wphy_rx_sat_info_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	d8032088 	ld.w      	r0, (r3, 0x220)
   a:	c6205620 	zext      	r0, r0, 17, 17
   e:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_dpd_rx_sat_info_get:

00000000 <ah_wphy_dpd_rx_sat_info_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	d8032088 	ld.w      	r0, (r3, 0x220)
   a:	c6005600 	zext      	r0, r0, 16, 16
   e:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_tx_crc4_get:

00000000 <ah_wphy_tx_crc4_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	9305      	ld.w      	r0, (r3, 0x14)
   8:	481c      	lsri      	r0, r0, 28
   a:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_rx_crc4_get:

00000000 <ah_wphy_rx_crc4_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	d8032050 	ld.w      	r0, (r3, 0x140)
   a:	c58055e0 	zext      	r0, r0, 15, 12
   e:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_agc_bw_src_cfg:

00000000 <ah_wphy_agc_bw_src_cfg>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	400f      	lsli      	r0, r0, 15
   8:	9340      	ld.w      	r2, (r3, 0x0)
   a:	3a8f      	bclri      	r2, 15
   c:	b340      	st.w      	r2, (r3, 0x0)
   e:	9340      	ld.w      	r2, (r3, 0x0)
  10:	c40055e0 	zext      	r0, r0, 15, 0
  14:	6c08      	or      	r0, r2
  16:	b300      	st.w      	r0, (r3, 0x0)
  18:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_agc_bw_cfg:

00000000 <ah_wphy_agc_bw_cfg>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	31c0      	movi      	r1, 192
   8:	9340      	ld.w      	r2, (r3, 0x0)
   a:	3a94      	bclri      	r2, 20
   c:	3a95      	bclri      	r2, 21
   e:	b340      	st.w      	r2, (r3, 0x0)
  10:	412e      	lsli      	r1, r1, 14
  12:	4014      	lsli      	r0, r0, 20
  14:	9340      	ld.w      	r2, (r3, 0x0)
  16:	6804      	and      	r0, r1
  18:	6c08      	or      	r0, r2
  1a:	b300      	st.w      	r0, (r3, 0x0)
  1c:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_rx_bw_src_cfg:

00000000 <ah_wphy_rx_bw_src_cfg>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	3180      	movi      	r1, 128
   8:	9340      	ld.w      	r2, (r3, 0x0)
   a:	3a8d      	bclri      	r2, 13
   c:	b340      	st.w      	r2, (r3, 0x0)
   e:	4126      	lsli      	r1, r1, 6
  10:	400d      	lsli      	r0, r0, 13
  12:	9340      	ld.w      	r2, (r3, 0x0)
  14:	6804      	and      	r0, r1
  16:	6c08      	or      	r0, r2
  18:	b300      	st.w      	r0, (r3, 0x0)
  1a:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_low_pwr_th_cfg:

00000000 <ah_wphy_low_pwr_th_cfg>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	3100      	movi      	r1, 0
   8:	9343      	ld.w      	r2, (r3, 0xc)
   a:	290f      	subi      	r1, 16
   c:	6884      	and      	r2, r1
   e:	b343      	st.w      	r2, (r3, 0xc)
  10:	9343      	ld.w      	r2, (r3, 0xc)
  12:	e400200f 	andi      	r0, r0, 15
  16:	6c08      	or      	r0, r2
  18:	b303      	st.w      	r0, (r3, 0xc)
  1a:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_auto_sig_err_rst_disable:

00000000 <ah_wphy_auto_sig_err_rst_disable>:
   0:	ea224002 	movih      	r2, 16386
   4:	3aae      	bseti      	r2, 14
   6:	926c      	ld.w      	r3, (r2, 0x30)
   8:	3b85      	bclri      	r3, 5
   a:	b26c      	st.w      	r3, (r2, 0x30)
   c:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_auto_sig_err_rst_enable:

00000000 <ah_wphy_auto_sig_err_rst_enable>:
   0:	ea224002 	movih      	r2, 16386
   4:	3aae      	bseti      	r2, 14
   6:	926c      	ld.w      	r3, (r2, 0x30)
   8:	ec630020 	ori      	r3, r3, 32
   c:	b26c      	st.w      	r3, (r2, 0x30)
   e:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_rx_conv_gain_config:

00000000 <ah_wphy_rx_conv_gain_config>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	4018      	lsli      	r0, r0, 24
   8:	934c      	ld.w      	r2, (r3, 0x30)
   a:	c40256e2 	zext      	r2, r2, 23, 0
   e:	b34c      	st.w      	r2, (r3, 0x30)
  10:	934c      	ld.w      	r2, (r3, 0x30)
  12:	6c08      	or      	r0, r2
  14:	b30c      	st.w      	r0, (r3, 0x30)
  16:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_dpd_cfg:

00000000 <ah_wphy_dpd_cfg>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	4009      	lsli      	r0, r0, 9
   8:	9341      	ld.w      	r2, (r3, 0x4)
   a:	3a89      	bclri      	r2, 9
   c:	3a8a      	bclri      	r2, 10
   e:	b341      	st.w      	r2, (r3, 0x4)
  10:	9341      	ld.w      	r2, (r3, 0x4)
  12:	e4002200 	andi      	r0, r0, 512
  16:	412a      	lsli      	r1, r1, 10
  18:	6c08      	or      	r0, r2
  1a:	e4212400 	andi      	r1, r1, 1024
  1e:	6c04      	or      	r0, r1
  20:	b301      	st.w      	r0, (r3, 0x4)
  22:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_gain_value_adjust:

00000000 <ah_wphy_gain_value_adjust>:
   0:	14d7      	push      	r4-r10, r15
   2:	1068      	lrw      	r3, 0x0	// 20 <ah_wphy_gain_value_adjust+0x20>
   4:	6d07      	mov      	r4, r1
   6:	6d43      	mov      	r5, r0
   8:	93d3      	ld.w      	r6, (r3, 0x4c)
   a:	e0000000 	bsr      	0x0	// 0 <ah_wphy_gain_value_adjust>
   e:	3c04      	cmphsi      	r4, 5
  10:	ea224002 	movih      	r2, 16386
  14:	3aae      	bseti      	r2, 14
  16:	083e      	bt      	0x92	// 92 <ah_wphy_gain_value_adjust+0x92>
  18:	1063      	lrw      	r3, 0x0	// 24 <ah_wphy_gain_value_adjust+0x24>
  1a:	d0830883 	ldr.w      	r3, (r3, r4 << 2)
  1e:	780c      	jmp      	r3
	...
  28:	d862202f 	ld.w      	r3, (r2, 0xbc)
  2c:	74ce      	sextb      	r3, r3
  2e:	040a      	br      	0x42	// 42 <ah_wphy_gain_value_adjust+0x42>
  30:	d862202f 	ld.w      	r3, (r2, 0xbc)
  34:	c50359e3 	sext      	r3, r3, 15, 8
  38:	0405      	br      	0x42	// 42 <ah_wphy_gain_value_adjust+0x42>
  3a:	d862202f 	ld.w      	r3, (r2, 0xbc)
  3e:	c6035ae3 	sext      	r3, r3, 23, 16
  42:	6016      	subu      	r0, r5
  44:	600c      	addu      	r0, r3
  46:	7402      	sextb      	r0, r0
  48:	33ff      	movi      	r3, 255
  4a:	40b0      	lsli      	r5, r0, 16
  4c:	4370      	lsli      	r3, r3, 16
  4e:	c500482c 	lsli      	r12, r0, 8
  52:	5e50      	addu      	r2, r6, r4
  54:	40f8      	lsli      	r7, r0, 24
  56:	694c      	and      	r5, r3
  58:	c40c55ec 	zext      	r12, r12, 15, 0
  5c:	3100      	movi      	r1, 0
  5e:	ea880009 	lrw      	r8, 0x0	// 80 <ah_wphy_gain_value_adjust+0x80>
  62:	e4c020ff 	andi      	r6, r0, 255
  66:	ea2d4002 	movih      	r13, 16386
  6a:	c5cd284d 	bseti      	r13, r13, 14
  6e:	3c04      	cmphsi      	r4, 5
  70:	dc02004d 	st.b      	r0, (r2, 0x4d)
  74:	4163      	lsli      	r3, r1, 3
  76:	085f      	bt      	0x134	// 134 <ah_wphy_gain_value_adjust+0x134>
  78:	d0880889 	ldr.w      	r9, (r8, r4 << 2)
  7c:	7824      	jmp      	r9
  7e:	0000      	.short	0x0000
  80:	00000000 	.long	0x00000000
  84:	d862202f 	ld.w      	r3, (r2, 0xbc)
  88:	5378      	asri      	r3, r3, 24
  8a:	07dc      	br      	0x42	// 42 <ah_wphy_gain_value_adjust+0x42>
  8c:	d8622030 	ld.w      	r3, (r2, 0xc0)
  90:	07ce      	br      	0x2c	// 2c <ah_wphy_gain_value_adjust+0x2c>
  92:	d8622030 	ld.w      	r3, (r2, 0xc0)
  96:	07cf      	br      	0x34	// 34 <ah_wphy_gain_value_adjust+0x34>
  98:	60f4      	addu      	r3, r13
  9a:	ea0a0000 	movi      	r10, 0
  9e:	d923202f 	ld.w      	r9, (r3, 0xbc)
  a2:	e54a10ff 	subi      	r10, r10, 256
  a6:	6a68      	and      	r9, r10
  a8:	dd23202f 	st.w      	r9, (r3, 0xbc)
  ac:	d923202f 	ld.w      	r9, (r3, 0xbc)
  b0:	6e58      	or      	r9, r6
  b2:	dd23202f 	st.w      	r9, (r3, 0xbc)
  b6:	2100      	addi      	r1, 1
  b8:	3948      	cmpnei      	r1, 8
  ba:	2205      	addi      	r2, 6
  bc:	0bd9      	bt      	0x6e	// 6e <ah_wphy_gain_value_adjust+0x6e>
  be:	1497      	pop      	r4-r10, r15
  c0:	60f4      	addu      	r3, r13
  c2:	ea0aff00 	movi      	r10, 65280
  c6:	6eaa      	nor      	r10, r10
  c8:	d923202f 	ld.w      	r9, (r3, 0xbc)
  cc:	6a68      	and      	r9, r10
  ce:	dd23202f 	st.w      	r9, (r3, 0xbc)
  d2:	d923202f 	ld.w      	r9, (r3, 0xbc)
  d6:	6e70      	or      	r9, r12
  d8:	07ed      	br      	0xb2	// b2 <ah_wphy_gain_value_adjust+0xb2>
  da:	60f4      	addu      	r3, r13
  dc:	ea2aff01 	movih      	r10, 65281
  e0:	d923202f 	ld.w      	r9, (r3, 0xbc)
  e4:	e54a1000 	subi      	r10, r10, 1
  e8:	6a68      	and      	r9, r10
  ea:	dd23202f 	st.w      	r9, (r3, 0xbc)
  ee:	d923202f 	ld.w      	r9, (r3, 0xbc)
  f2:	6e54      	or      	r9, r5
  f4:	07df      	br      	0xb2	// b2 <ah_wphy_gain_value_adjust+0xb2>
  f6:	60f4      	addu      	r3, r13
  f8:	d923202f 	ld.w      	r9, (r3, 0xbc)
  fc:	c40956e9 	zext      	r9, r9, 23, 0
 100:	dd23202f 	st.w      	r9, (r3, 0xbc)
 104:	d923202f 	ld.w      	r9, (r3, 0xbc)
 108:	6e5c      	or      	r9, r7
 10a:	07d4      	br      	0xb2	// b2 <ah_wphy_gain_value_adjust+0xb2>
 10c:	ea294002 	movih      	r9, 16386
 110:	c5c92849 	bseti      	r9, r9, 14
 114:	60e4      	addu      	r3, r9
 116:	ea0a0000 	movi      	r10, 0
 11a:	d9232030 	ld.w      	r9, (r3, 0xc0)
 11e:	e54a10ff 	subi      	r10, r10, 256
 122:	6a68      	and      	r9, r10
 124:	dd232030 	st.w      	r9, (r3, 0xc0)
 128:	d9232030 	ld.w      	r9, (r3, 0xc0)
 12c:	6e58      	or      	r9, r6
 12e:	dd232030 	st.w      	r9, (r3, 0xc0)
 132:	07c2      	br      	0xb6	// b6 <ah_wphy_gain_value_adjust+0xb6>
 134:	ea294002 	movih      	r9, 16386
 138:	c5c92849 	bseti      	r9, r9, 14
 13c:	60e4      	addu      	r3, r9
 13e:	ea0aff00 	movi      	r10, 65280
 142:	6eaa      	nor      	r10, r10
 144:	d9232030 	ld.w      	r9, (r3, 0xc0)
 148:	6a68      	and      	r9, r10
 14a:	dd232030 	st.w      	r9, (r3, 0xc0)
 14e:	d9232030 	ld.w      	r9, (r3, 0xc0)
 152:	6e70      	or      	r9, r12
 154:	07ed      	br      	0x12e	// 12e <ah_wphy_gain_value_adjust+0x12e>

Disassembly of section .text.ah_wphy_rx_fix_gain_idx_cfg:

00000000 <ah_wphy_rx_fix_gain_idx_cfg>:
   0:	14c1      	push      	r4
   2:	33f8      	movi      	r3, 248
   4:	c500482c 	lsli      	r12, r0, 8
   8:	4365      	lsli      	r3, r3, 5
   a:	6b0c      	and      	r12, r3
   c:	1077      	lrw      	r3, 0x0	// 68 <ah_wphy_rx_fix_gain_idx_cfg+0x68>
   e:	3100      	movi      	r1, 0
  10:	9373      	ld.w      	r3, (r3, 0x4c)
  12:	600c      	addu      	r0, r3
  14:	4163      	lsli      	r3, r1, 3
  16:	ea2d4002 	movih      	r13, 16386
  1a:	c5cd284d 	bseti      	r13, r13, 14
  1e:	60f4      	addu      	r3, r13
  20:	ea04ff00 	movi      	r4, 65280
  24:	6d12      	nor      	r4, r4
  26:	d9a32030 	ld.w      	r13, (r3, 0xc0)
  2a:	d840404d 	ld.bs      	r2, (r0, 0x4d)
  2e:	6b50      	and      	r13, r4
  30:	dda32030 	st.w      	r13, (r3, 0xc0)
  34:	4248      	lsli      	r2, r2, 8
  36:	d9a32030 	ld.w      	r13, (r3, 0xc0)
  3a:	c40255e2 	zext      	r2, r2, 15, 0
  3e:	6cb4      	or      	r2, r13
  40:	dc432030 	st.w      	r2, (r3, 0xc0)
  44:	d8432040 	ld.w      	r2, (r3, 0x100)
  48:	ea0d1f00 	movi      	r13, 7936
  4c:	6f76      	nor      	r13, r13
  4e:	68b4      	and      	r2, r13
  50:	dc432040 	st.w      	r2, (r3, 0x100)
  54:	2100      	addi      	r1, 1
  56:	d8432040 	ld.w      	r2, (r3, 0x100)
  5a:	3948      	cmpnei      	r1, 8
  5c:	6cb0      	or      	r2, r12
  5e:	dc432040 	st.w      	r2, (r3, 0x100)
  62:	2005      	addi      	r0, 6
  64:	0bd8      	bt      	0x14	// 14 <ah_wphy_rx_fix_gain_idx_cfg+0x14>
  66:	1481      	pop      	r4
  68:	0000      	.short	0x0000
	...

Disassembly of section .text.ah_wphy_rx_gain_para_get:

00000000 <ah_wphy_rx_gain_para_get>:
   0:	ea234002 	movih      	r3, 16386
   4:	3bae      	bseti      	r3, 14
   6:	d843202f 	ld.w      	r2, (r3, 0xbc)
   a:	a040      	st.b      	r2, (r0, 0x0)
   c:	d843202f 	ld.w      	r2, (r3, 0xbc)
  10:	4a48      	lsri      	r2, r2, 8
  12:	a041      	st.b      	r2, (r0, 0x1)
  14:	d843202f 	ld.w      	r2, (r3, 0xbc)
  18:	4a50      	lsri      	r2, r2, 16
  1a:	a042      	st.b      	r2, (r0, 0x2)
  1c:	d843202f 	ld.w      	r2, (r3, 0xbc)
  20:	4a58      	lsri      	r2, r2, 24
  22:	a043      	st.b      	r2, (r0, 0x3)
  24:	d8432030 	ld.w      	r2, (r3, 0xc0)
  28:	a044      	st.b      	r2, (r0, 0x4)
  2a:	d8432030 	ld.w      	r2, (r3, 0xc0)
  2e:	4a48      	lsri      	r2, r2, 8
  30:	a045      	st.b      	r2, (r0, 0x5)
  32:	936c      	ld.w      	r3, (r3, 0x30)
  34:	4b78      	lsri      	r3, r3, 24
  36:	a160      	st.b      	r3, (r1, 0x0)
  38:	783c      	jmp      	r15

Disassembly of section .text.ah_wphy_rx_gain_stage_cfg:

00000000 <ah_wphy_rx_gain_stage_cfg>:
   0:	14d0      	push      	r15
   2:	3844      	cmpnei      	r0, 4
   4:	1066      	lrw      	r3, 0x0	// 1c <ah_wphy_rx_gain_stage_cfg+0x1c>
   6:	9373      	ld.w      	r3, (r3, 0x4c)
   8:	0806      	bt      	0x14	// 14 <ah_wphy_rx_gain_stage_cfg+0x14>
   a:	e40300f2 	addi      	r0, r3, 243
   e:	e0000000 	bsr      	0x0	// 0 <ah_wphy_rx_gain_stage_cfg>
  12:	1490      	pop      	r15
  14:	e403017f 	addi      	r0, r3, 384
  18:	07fb      	br      	0xe	// e <ah_wphy_rx_gain_stage_cfg+0xe>
  1a:	0000      	.short	0x0000
  1c:	00000000 	.long	0x00000000
