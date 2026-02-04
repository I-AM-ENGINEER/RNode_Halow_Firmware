
disasm/libnetutils/obj/utils_udp.o:     file format elf32-csky-little


Disassembly of section .text.net_setup_udpdata:

00000000 <net_setup_udpdata>:
   0:	14d8      	push      	r4-r11, r15
   2:	1422      	subi      	r14, r14, 8
   4:	6d43      	mov      	r5, r0
   6:	6d07      	mov      	r4, r1
   8:	e900008b 	bez      	r0, 0x11e	// 11e <net_setup_udpdata+0x11e>
   c:	e901008b 	bez      	r1, 0x122	// 122 <net_setup_udpdata+0x122>
  10:	90e7      	ld.w      	r7, (r0, 0x1c)
  12:	2729      	addi      	r7, 42
  14:	eb0705dc 	cmphsi      	r7, 1501
  18:	ea0305dc 	movi      	r3, 1500
  1c:	9020      	ld.w      	r1, (r0, 0x0)
  1e:	3206      	movi      	r2, 6
  20:	6c13      	mov      	r0, r4
  22:	c4e30c40 	inct      	r7, r3, 0
  26:	e0000000 	bsr      	0x0	// 0 <memcpy>
  2a:	3206      	movi      	r2, 6
  2c:	9521      	ld.w      	r1, (r5, 0x4)
  2e:	5c08      	addu      	r0, r4, r2
  30:	e0000000 	bsr      	0x0	// 0 <memcpy>
  34:	3308      	movi      	r3, 8
  36:	a46c      	st.b      	r3, (r4, 0xc)
  38:	761d      	zexth      	r8, r7
  3a:	3345      	movi      	r3, 69
  3c:	a46e      	st.b      	r3, (r4, 0xe)
  3e:	e468100d 	subi      	r3, r8, 14
  42:	74cd      	zexth      	r3, r3
  44:	a471      	st.b      	r3, (r4, 0x11)
  46:	4b48      	lsri      	r2, r3, 8
  48:	3340      	movi      	r3, 64
  4a:	3600      	movi      	r6, 0
  4c:	a474      	st.b      	r3, (r4, 0x14)
  4e:	a476      	st.b      	r3, (r4, 0x16)
  50:	3311      	movi      	r3, 17
  52:	a450      	st.b      	r2, (r4, 0x10)
  54:	a4cd      	st.b      	r6, (r4, 0xd)
  56:	a4cf      	st.b      	r6, (r4, 0xf)
  58:	a4d2      	st.b      	r6, (r4, 0x12)
  5a:	a4d3      	st.b      	r6, (r4, 0x13)
  5c:	a4d5      	st.b      	r6, (r4, 0x15)
  5e:	a477      	st.b      	r3, (r4, 0x17)
  60:	a4d8      	st.b      	r6, (r4, 0x18)
  62:	a4d9      	st.b      	r6, (r4, 0x19)
  64:	9564      	ld.w      	r3, (r5, 0x10)
  66:	4b50      	lsri      	r2, r3, 16
  68:	4a28      	lsri      	r1, r2, 8
  6a:	a45b      	st.b      	r2, (r4, 0x1b)
  6c:	c50355e2 	zext      	r2, r3, 15, 8
  70:	a43a      	st.b      	r1, (r4, 0x1a)
  72:	a45c      	st.b      	r2, (r4, 0x1c)
  74:	a47d      	st.b      	r3, (r4, 0x1d)
  76:	9562      	ld.w      	r3, (r5, 0x8)
  78:	4b50      	lsri      	r2, r3, 16
  7a:	4a28      	lsri      	r1, r2, 8
  7c:	a45f      	st.b      	r2, (r4, 0x1f)
  7e:	c50355e2 	zext      	r2, r3, 15, 8
  82:	a43e      	st.b      	r1, (r4, 0x1e)
  84:	dc440020 	st.b      	r2, (r4, 0x20)
  88:	dc640021 	st.b      	r3, (r4, 0x21)
  8c:	3214      	movi      	r2, 20
  8e:	e424000d 	addi      	r1, r4, 14
  92:	3000      	movi      	r0, 0
  94:	e0000000 	bsr      	0x0	// 0 <net_checksum>
  98:	6c02      	nor      	r0, r0
  9a:	7401      	zexth      	r0, r0
  9c:	4868      	lsri      	r3, r0, 8
  9e:	a419      	st.b      	r0, (r4, 0x19)
  a0:	a478      	st.b      	r3, (r4, 0x18)
  a2:	9565      	ld.w      	r3, (r5, 0x14)
  a4:	c50355e2 	zext      	r2, r3, 15, 8
  a8:	dc440022 	st.b      	r2, (r4, 0x22)
  ac:	dc640023 	st.b      	r3, (r4, 0x23)
  b0:	e5281021 	subi      	r9, r8, 34
  b4:	9563      	ld.w      	r3, (r5, 0xc)
  b6:	7665      	zexth      	r9, r9
  b8:	c50355e2 	zext      	r2, r3, 15, 8
  bc:	dc640025 	st.b      	r3, (r4, 0x25)
  c0:	c5094843 	lsri      	r3, r9, 8
  c4:	dc440024 	st.b      	r2, (r4, 0x24)
  c8:	dc640026 	st.b      	r3, (r4, 0x26)
  cc:	dd240027 	st.b      	r9, (r4, 0x27)
  d0:	dcc40028 	st.b      	r6, (r4, 0x28)
  d4:	dcc40029 	st.b      	r6, (r4, 0x29)
  d8:	e4040029 	addi      	r0, r4, 42
  dc:	9526      	ld.w      	r1, (r5, 0x18)
  de:	6442      	cmpne      	r0, r1
  e0:	e5440019 	addi      	r10, r4, 26
  e4:	e564001d 	addi      	r11, r4, 30
  e8:	e5840021 	addi      	r12, r4, 34
  ec:	0c09      	bf      	0xfe	// fe <net_setup_udpdata+0xfe>
  ee:	e4471029 	subi      	r2, r7, 42
  f2:	dd8e2001 	st.w      	r12, (r14, 0x4)
  f6:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
  fa:	d98e2001 	ld.w      	r12, (r14, 0x4)
  fe:	6ceb      	mov      	r3, r10
 100:	dd6e2000 	st.w      	r11, (r14, 0x0)
 104:	6ca7      	mov      	r2, r9
 106:	6c73      	mov      	r1, r12
 108:	3011      	movi      	r0, 17
 10a:	e0000000 	bsr      	0x0	// 0 <net_pseudo_checksum>
 10e:	4868      	lsri      	r3, r0, 8
 110:	dc640028 	st.b      	r3, (r4, 0x28)
 114:	dc040029 	st.b      	r0, (r4, 0x29)
 118:	6c23      	mov      	r0, r8
 11a:	1402      	addi      	r14, r14, 8
 11c:	1498      	pop      	r4-r11, r15
 11e:	6e03      	mov      	r8, r0
 120:	07fc      	br      	0x118	// 118 <net_setup_udpdata+0x118>
 122:	6e07      	mov      	r8, r1
 124:	07fa      	br      	0x118	// 118 <net_setup_udpdata+0x118>

Disassembly of section .text.net_setup_icmp:

00000000 <net_setup_icmp>:
   0:	14d5      	push      	r4-r8, r15
   2:	6d43      	mov      	r5, r0
   4:	6d07      	mov      	r4, r1
   6:	e9000084 	bez      	r0, 0x10e	// 10e <net_setup_icmp+0x10e>
   a:	e9010083 	bez      	r1, 0x110	// 110 <net_setup_icmp+0x110>
   e:	9065      	ld.w      	r3, (r0, 0x14)
  10:	e9230004 	bnez      	r3, 0x18	// 18 <net_setup_icmp+0x18>
  14:	3320      	movi      	r3, 32
  16:	b065      	st.w      	r3, (r0, 0x14)
  18:	9505      	ld.w      	r0, (r5, 0x14)
  1a:	2029      	addi      	r0, 42
  1c:	eb0005dc 	cmphsi      	r0, 1501
  20:	ea0705dc 	movi      	r7, 1500
  24:	c4e00c20 	incf      	r7, r0, 0
  28:	3206      	movi      	r2, 6
  2a:	9520      	ld.w      	r1, (r5, 0x0)
  2c:	6c13      	mov      	r0, r4
  2e:	e0000000 	bsr      	0x0	// 0 <memcpy>
  32:	3206      	movi      	r2, 6
  34:	9521      	ld.w      	r1, (r5, 0x4)
  36:	5c08      	addu      	r0, r4, r2
  38:	e0000000 	bsr      	0x0	// 0 <memcpy>
  3c:	3308      	movi      	r3, 8
  3e:	a46c      	st.b      	r3, (r4, 0xc)
  40:	3345      	movi      	r3, 69
  42:	a46e      	st.b      	r3, (r4, 0xe)
  44:	e467100d 	subi      	r3, r7, 14
  48:	74cd      	zexth      	r3, r3
  4a:	3600      	movi      	r6, 0
  4c:	a471      	st.b      	r3, (r4, 0x11)
  4e:	4b48      	lsri      	r2, r3, 8
  50:	ea080001 	movi      	r8, 1
  54:	3340      	movi      	r3, 64
  56:	a450      	st.b      	r2, (r4, 0x10)
  58:	a4cd      	st.b      	r6, (r4, 0xd)
  5a:	a4cf      	st.b      	r6, (r4, 0xf)
  5c:	a4d2      	st.b      	r6, (r4, 0x12)
  5e:	a4d3      	st.b      	r6, (r4, 0x13)
  60:	a474      	st.b      	r3, (r4, 0x14)
  62:	a4d5      	st.b      	r6, (r4, 0x15)
  64:	a476      	st.b      	r3, (r4, 0x16)
  66:	dd040017 	st.b      	r8, (r4, 0x17)
  6a:	a4d8      	st.b      	r6, (r4, 0x18)
  6c:	a4d9      	st.b      	r6, (r4, 0x19)
  6e:	9563      	ld.w      	r3, (r5, 0xc)
  70:	4b50      	lsri      	r2, r3, 16
  72:	4a28      	lsri      	r1, r2, 8
  74:	a45b      	st.b      	r2, (r4, 0x1b)
  76:	c50355e2 	zext      	r2, r3, 15, 8
  7a:	a43a      	st.b      	r1, (r4, 0x1a)
  7c:	a45c      	st.b      	r2, (r4, 0x1c)
  7e:	a47d      	st.b      	r3, (r4, 0x1d)
  80:	9562      	ld.w      	r3, (r5, 0x8)
  82:	4b50      	lsri      	r2, r3, 16
  84:	4a28      	lsri      	r1, r2, 8
  86:	a45f      	st.b      	r2, (r4, 0x1f)
  88:	c50355e2 	zext      	r2, r3, 15, 8
  8c:	a43e      	st.b      	r1, (r4, 0x1e)
  8e:	dc440020 	st.b      	r2, (r4, 0x20)
  92:	dc640021 	st.b      	r3, (r4, 0x21)
  96:	3214      	movi      	r2, 20
  98:	e424000d 	addi      	r1, r4, 14
  9c:	3000      	movi      	r0, 0
  9e:	e0000000 	bsr      	0x0	// 0 <net_checksum>
  a2:	6c02      	nor      	r0, r0
  a4:	7401      	zexth      	r0, r0
  a6:	4868      	lsri      	r3, r0, 8
  a8:	a419      	st.b      	r0, (r4, 0x19)
  aa:	a478      	st.b      	r3, (r4, 0x18)
  ac:	8578      	ld.b      	r3, (r5, 0x18)
  ae:	dc640022 	st.b      	r3, (r4, 0x22)
  b2:	dcc40023 	st.b      	r6, (r4, 0x23)
  b6:	dcc40024 	st.b      	r6, (r4, 0x24)
  ba:	dcc40025 	st.b      	r6, (r4, 0x25)
  be:	dcc40026 	st.b      	r6, (r4, 0x26)
  c2:	dd040027 	st.b      	r8, (r4, 0x27)
  c6:	8d6d      	ld.h      	r3, (r5, 0x1a)
  c8:	4b48      	lsri      	r2, r3, 8
  ca:	dc440028 	st.b      	r2, (r4, 0x28)
  ce:	dc640029 	st.b      	r3, (r4, 0x29)
  d2:	9524      	ld.w      	r1, (r5, 0x10)
  d4:	9545      	ld.w      	r2, (r5, 0x14)
  d6:	e4040029 	addi      	r0, r4, 42
  da:	e9010016 	bez      	r1, 0x106	// 106 <net_setup_icmp+0x106>
  de:	6406      	cmpne      	r1, r0
  e0:	0c03      	bf      	0xe6	// e6 <net_setup_icmp+0xe6>
  e2:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
  e6:	9545      	ld.w      	r2, (r5, 0x14)
  e8:	2207      	addi      	r2, 8
  ea:	e4240021 	addi      	r1, r4, 34
  ee:	3000      	movi      	r0, 0
  f0:	e0000000 	bsr      	0x0	// 0 <net_checksum>
  f4:	6c02      	nor      	r0, r0
  f6:	7401      	zexth      	r0, r0
  f8:	4868      	lsri      	r3, r0, 8
  fa:	dc040025 	st.b      	r0, (r4, 0x25)
  fe:	dc640024 	st.b      	r3, (r4, 0x24)
 102:	6c1f      	mov      	r0, r7
 104:	1495      	pop      	r4-r8, r15
 106:	6c4b      	mov      	r1, r2
 108:	e0000000 	bsr      	0x0	// 0 <os_random_bytes>
 10c:	07ed      	br      	0xe6	// e6 <net_setup_icmp+0xe6>
 10e:	07fb      	br      	0x104	// 104 <net_setup_icmp+0x104>
 110:	6c07      	mov      	r0, r1
 112:	07f9      	br      	0x104	// 104 <net_setup_icmp+0x104>
