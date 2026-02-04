
disasm/liblmac/obj/mars_lmac_cipher.o:     file format elf32-csky-little


Disassembly of section .text.ah_ce_irq_handler:

00000000 <ah_ce_irq_handler>:
   0:	14d0      	push      	r15
   2:	1069      	lrw      	r3, 0x0	// 24 <ah_ce_irq_handler+0x24>
   4:	9300      	ld.w      	r0, (r3, 0x0)
   6:	9060      	ld.w      	r3, (r0, 0x0)
   8:	935a      	ld.w      	r2, (r3, 0x68)
   a:	e4422001 	andi      	r2, r2, 1
   e:	e9020009 	bez      	r2, 0x20	// 20 <ah_ce_irq_handler+0x20>
  12:	935a      	ld.w      	r2, (r3, 0x68)
  14:	ec420001 	ori      	r2, r2, 1
  18:	b35a      	st.w      	r2, (r3, 0x68)
  1a:	200b      	addi      	r0, 12
  1c:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  20:	1490      	pop      	r15
  22:	0000      	.short	0x0000
  24:	00000000 	.long	0x00000000

Disassembly of section .text.ah_ce_init:

00000000 <ah_ce_init>:
   0:	14d1      	push      	r4, r15
   2:	1072      	lrw      	r3, 0x0	// 48 <ah_ce_init+0x48>
   4:	6d07      	mov      	r4, r1
   6:	590e      	addi      	r0, r1, 4
   8:	b320      	st.w      	r1, (r3, 0x0)
   a:	e0000000 	bsr      	0x0	// 0 <os_mutex_init>
   e:	3100      	movi      	r1, 0
  10:	e404000b 	addi      	r0, r4, 12
  14:	e0000000 	bsr      	0x0	// 0 <os_sema_init>
  18:	6c93      	mov      	r2, r4
  1a:	102d      	lrw      	r1, 0x0	// 4c <ah_ce_init+0x4c>
  1c:	9405      	ld.w      	r0, (r4, 0x14)
  1e:	e0000000 	bsr      	0x0	// 0 <request_irq>
  22:	9465      	ld.w      	r3, (r4, 0x14)
  24:	c4a354c1 	zext      	r1, r3, 6, 5
  28:	3201      	movi      	r2, 1
  2a:	e463201f 	andi      	r3, r3, 31
  2e:	c4624023 	lsl      	r3, r2, r3
  32:	1048      	lrw      	r2, 0xe000e100	// 50 <ah_ce_init+0x50>
  34:	d4220883 	str.w      	r3, (r2, r1 << 2)
  38:	9440      	ld.w      	r2, (r4, 0x0)
  3a:	3000      	movi      	r0, 0
  3c:	9278      	ld.w      	r3, (r2, 0x60)
  3e:	ec630002 	ori      	r3, r3, 2
  42:	b278      	st.w      	r3, (r2, 0x60)
  44:	1491      	pop      	r4, r15
	...
  4e:	0000      	.short	0x0000
  50:	e000e100 	.long	0xe000e100

Disassembly of section .text.ah_ce_start:

00000000 <ah_ce_start>:
   0:	14d5      	push      	r4-r8, r15
   2:	1429      	subi      	r14, r14, 36
   4:	6d47      	mov      	r5, r1
   6:	58ce      	addi      	r6, r0, 4
   8:	3100      	movi      	r1, 0
   a:	6dc3      	mov      	r7, r0
   c:	2900      	subi      	r1, 1
   e:	6c1b      	mov      	r0, r6
  10:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  14:	e900000e 	bez      	r0, 0x30	// 30 <ah_ce_start+0x30>
  18:	0318      	lrw      	r0, 0x0	// 234 <hgprintf+0x234>
  1a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  1e:	0318      	lrw      	r0, 0x0	// 238 <hgprintf+0x238>
  20:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  24:	3400      	movi      	r4, 0
  26:	6c1b      	mov      	r0, r6
  28:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  2c:	2c00      	subi      	r4, 1
  2e:	04df      	br      	0x1ec	// 1ec <ah_ce_start+0x1ec>
  30:	8544      	ld.b      	r2, (r5, 0x4)
  32:	e92200a8 	bnez      	r2, 0x182	// 182 <ah_ce_start+0x182>
  36:	9700      	ld.w      	r0, (r7, 0x0)
  38:	9520      	ld.w      	r1, (r5, 0x0)
  3a:	9079      	ld.w      	r3, (r0, 0x64)
  3c:	3b8c      	bclri      	r3, 12
  3e:	3b8d      	bclri      	r3, 13
  40:	b079      	st.w      	r3, (r0, 0x64)
  42:	8161      	ld.b      	r3, (r1, 0x1)
  44:	d9810000 	ld.b      	r12, (r1, 0x0)
  48:	4368      	lsli      	r3, r3, 8
  4a:	60f0      	addu      	r3, r12
  4c:	d9810002 	ld.b      	r12, (r1, 0x2)
  50:	c60c482c 	lsli      	r12, r12, 16
  54:	60f0      	addu      	r3, r12
  56:	d9810003 	ld.b      	r12, (r1, 0x3)
  5a:	c70c482c 	lsli      	r12, r12, 24
  5e:	60f0      	addu      	r3, r12
  60:	d4400883 	str.w      	r3, (r0, r2 << 2)
  64:	2200      	addi      	r2, 1
  66:	3a44      	cmpnei      	r2, 4
  68:	2103      	addi      	r1, 4
  6a:	0bec      	bt      	0x42	// 42 <ah_ce_start+0x42>
  6c:	8566      	ld.b      	r3, (r5, 0x6)
  6e:	8545      	ld.b      	r2, (r5, 0x5)
  70:	4364      	lsli      	r3, r3, 4
  72:	e442200f 	andi      	r2, r2, 15
  76:	e4632010 	andi      	r3, r3, 16
  7a:	6cc8      	or      	r3, r2
  7c:	8547      	ld.b      	r2, (r5, 0x7)
  7e:	4245      	lsli      	r2, r2, 5
  80:	9780      	ld.w      	r4, (r7, 0x0)
  82:	e4422020 	andi      	r2, r2, 32
  86:	60c8      	addu      	r3, r2
  88:	3200      	movi      	r2, 0
  8a:	9428      	ld.w      	r1, (r4, 0x20)
  8c:	2aff      	subi      	r2, 256
  8e:	6884      	and      	r2, r1
  90:	6cc8      	or      	r3, r2
  92:	b468      	st.w      	r3, (r4, 0x20)
  94:	9468      	ld.w      	r3, (r4, 0x20)
  96:	9542      	ld.w      	r2, (r5, 0x8)
  98:	e46320ff 	andi      	r3, r3, 255
  9c:	b468      	st.w      	r3, (r4, 0x20)
  9e:	8262      	ld.b      	r3, (r2, 0x2)
  a0:	8221      	ld.b      	r1, (r2, 0x1)
  a2:	4130      	lsli      	r1, r1, 16
  a4:	4378      	lsli      	r3, r3, 24
  a6:	60c4      	addu      	r3, r1
  a8:	8220      	ld.b      	r1, (r2, 0x0)
  aa:	4128      	lsli      	r1, r1, 8
  ac:	9408      	ld.w      	r0, (r4, 0x20)
  ae:	60c4      	addu      	r3, r1
  b0:	6cc0      	or      	r3, r0
  b2:	b468      	st.w      	r3, (r4, 0x20)
  b4:	8265      	ld.b      	r3, (r2, 0x5)
  b6:	8224      	ld.b      	r1, (r2, 0x4)
  b8:	4128      	lsli      	r1, r1, 8
  ba:	4370      	lsli      	r3, r3, 16
  bc:	8243      	ld.b      	r2, (r2, 0x3)
  be:	60c4      	addu      	r3, r1
  c0:	60c8      	addu      	r3, r2
  c2:	9543      	ld.w      	r2, (r5, 0xc)
  c4:	b469      	st.w      	r3, (r4, 0x24)
  c6:	8262      	ld.b      	r3, (r2, 0x2)
  c8:	8223      	ld.b      	r1, (r2, 0x3)
  ca:	4130      	lsli      	r1, r1, 16
  cc:	4378      	lsli      	r3, r3, 24
  ce:	60c4      	addu      	r3, r1
  d0:	8224      	ld.b      	r1, (r2, 0x4)
  d2:	4128      	lsli      	r1, r1, 8
  d4:	60c4      	addu      	r3, r1
  d6:	8225      	ld.b      	r1, (r2, 0x5)
  d8:	60c4      	addu      	r3, r1
  da:	b46a      	st.w      	r3, (r4, 0x28)
  dc:	8260      	ld.b      	r3, (r2, 0x0)
  de:	4368      	lsli      	r3, r3, 8
  e0:	8241      	ld.b      	r2, (r2, 0x1)
  e2:	60c8      	addu      	r3, r2
  e4:	e50e0003 	addi      	r8, r14, 4
  e8:	321e      	movi      	r2, 30
  ea:	b46b      	st.w      	r3, (r4, 0x2c)
  ec:	3100      	movi      	r1, 0
  ee:	6c23      	mov      	r0, r8
  f0:	e0000000 	bsr      	0x0	// 0 <memset>
  f4:	8554      	ld.b      	r2, (r5, 0x14)
  f6:	3a1e      	cmphsi      	r2, 31
  f8:	0b93      	bt      	0x1e	// 1e <ah_ce_start+0x1e>
  fa:	9524      	ld.w      	r1, (r5, 0x10)
  fc:	4208      	lsli      	r0, r2, 8
  fe:	8160      	ld.b      	r3, (r1, 0x0)
 100:	4370      	lsli      	r3, r3, 16
 102:	60c0      	addu      	r3, r0
 104:	8101      	ld.b      	r0, (r1, 0x1)
 106:	4018      	lsli      	r0, r0, 24
 108:	60c0      	addu      	r3, r0
 10a:	b46c      	st.w      	r3, (r4, 0x30)
 10c:	3302      	movi      	r3, 2
 10e:	740c      	zextb      	r0, r3
 110:	6480      	cmphs      	r0, r2
 112:	0c5a      	bf      	0x1c6	// 1c6 <ah_ce_start+0x1c6>
 114:	e44e0005 	addi      	r2, r14, 6
 118:	3104      	movi      	r1, 4
 11a:	8261      	ld.b      	r3, (r2, 0x1)
 11c:	d9820000 	ld.b      	r12, (r2, 0x0)
 120:	4368      	lsli      	r3, r3, 8
 122:	60f0      	addu      	r3, r12
 124:	d9820002 	ld.b      	r12, (r2, 0x2)
 128:	c60c482c 	lsli      	r12, r12, 16
 12c:	5102      	asri      	r0, r1, 2
 12e:	60f0      	addu      	r3, r12
 130:	2103      	addi      	r1, 4
 132:	d9820003 	ld.b      	r12, (r2, 0x3)
 136:	c70c482c 	lsli      	r12, r12, 24
 13a:	eb410020 	cmpnei      	r1, 32
 13e:	60f0      	addu      	r3, r12
 140:	200b      	addi      	r0, 12
 142:	d4040883 	str.w      	r3, (r4, r0 << 2)
 146:	2203      	addi      	r2, 4
 148:	0be9      	bt      	0x11a	// 11a <ah_ce_start+0x11a>
 14a:	8d6b      	ld.h      	r3, (r5, 0x16)
 14c:	eb034000 	cmphsi      	r3, 16385
 150:	0b67      	bt      	0x1e	// 1e <ah_ce_start+0x1e>
 152:	b474      	st.w      	r3, (r4, 0x50)
 154:	9566      	ld.w      	r3, (r5, 0x18)
 156:	b475      	st.w      	r3, (r4, 0x54)
 158:	9567      	ld.w      	r3, (r5, 0x1c)
 15a:	b476      	st.w      	r3, (r4, 0x58)
 15c:	8575      	ld.b      	r3, (r5, 0x15)
 15e:	e923003a 	bnez      	r3, 0x1d2	// 1d2 <ah_ce_start+0x1d2>
 162:	9479      	ld.w      	r3, (r4, 0x64)
 164:	3b80      	bclri      	r3, 0
 166:	b479      	st.w      	r3, (r4, 0x64)
 168:	9478      	ld.w      	r3, (r4, 0x60)
 16a:	ec630001 	ori      	r3, r3, 1
 16e:	b478      	st.w      	r3, (r4, 0x60)
 170:	3164      	movi      	r1, 100
 172:	e407000b 	addi      	r0, r7, 12
 176:	e0000000 	bsr      	0x0	// 0 <os_sema_down>
 17a:	e9200032 	bnez      	r0, 0x1de	// 1de <ah_ce_start+0x1de>
 17e:	1110      	lrw      	r0, 0x0	// 23c <ah_ce_start+0x23c>
 180:	074d      	br      	0x1a	// 1a <ah_ce_start+0x1a>
 182:	3a42      	cmpnei      	r2, 2
 184:	0b4d      	bt      	0x1e	// 1e <ah_ce_start+0x1e>
 186:	9720      	ld.w      	r1, (r7, 0x0)
 188:	9540      	ld.w      	r2, (r5, 0x0)
 18a:	9179      	ld.w      	r3, (r1, 0x64)
 18c:	3b8c      	bclri      	r3, 12
 18e:	3b8d      	bclri      	r3, 13
 190:	b179      	st.w      	r3, (r1, 0x64)
 192:	9179      	ld.w      	r3, (r1, 0x64)
 194:	ec632000 	ori      	r3, r3, 8192
 198:	b179      	st.w      	r3, (r1, 0x64)
 19a:	8261      	ld.b      	r3, (r2, 0x1)
 19c:	d9820000 	ld.b      	r12, (r2, 0x0)
 1a0:	4368      	lsli      	r3, r3, 8
 1a2:	60f0      	addu      	r3, r12
 1a4:	d9820002 	ld.b      	r12, (r2, 0x2)
 1a8:	c60c482c 	lsli      	r12, r12, 16
 1ac:	60f0      	addu      	r3, r12
 1ae:	d9820003 	ld.b      	r12, (r2, 0x3)
 1b2:	c70c482c 	lsli      	r12, r12, 24
 1b6:	60f0      	addu      	r3, r12
 1b8:	d4010883 	str.w      	r3, (r1, r0 << 2)
 1bc:	2000      	addi      	r0, 1
 1be:	3848      	cmpnei      	r0, 8
 1c0:	2203      	addi      	r2, 4
 1c2:	0bec      	bt      	0x19a	// 19a <ah_ce_start+0x19a>
 1c4:	0754      	br      	0x6c	// 6c <ah_ce_start+0x6c>
 1c6:	d0610020 	ldr.b      	r0, (r1, r3 << 0)
 1ca:	d4680020 	str.b      	r0, (r8, r3 << 0)
 1ce:	2300      	addi      	r3, 1
 1d0:	079f      	br      	0x10e	// 10e <ah_ce_start+0x10e>
 1d2:	3b41      	cmpnei      	r3, 1
 1d4:	0b25      	bt      	0x1e	// 1e <ah_ce_start+0x1e>
 1d6:	9479      	ld.w      	r3, (r4, 0x64)
 1d8:	ec630001 	ori      	r3, r3, 1
 1dc:	07c5      	br      	0x166	// 166 <ah_ce_start+0x166>
 1de:	8575      	ld.b      	r3, (r5, 0x15)
 1e0:	3b41      	cmpnei      	r3, 1
 1e2:	0c08      	bf      	0x1f2	// 1f2 <ah_ce_start+0x1f2>
 1e4:	3400      	movi      	r4, 0
 1e6:	6c1b      	mov      	r0, r6
 1e8:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
 1ec:	6c13      	mov      	r0, r4
 1ee:	1409      	addi      	r14, r14, 36
 1f0:	1495      	pop      	r4-r8, r15
 1f2:	9700      	ld.w      	r0, (r7, 0x0)
 1f4:	907a      	ld.w      	r3, (r0, 0x68)
 1f6:	e4632002 	andi      	r3, r3, 2
 1fa:	e903000a 	bez      	r3, 0x20e	// 20e <ah_ce_start+0x20e>
 1fe:	903c      	ld.w      	r1, (r0, 0x70)
 200:	905d      	ld.w      	r2, (r0, 0x74)
 202:	907e      	ld.w      	r3, (r0, 0x78)
 204:	901f      	ld.w      	r0, (r0, 0x7c)
 206:	b800      	st.w      	r0, (r14, 0x0)
 208:	100e      	lrw      	r0, 0x0	// 240 <ah_ce_start+0x240>
 20a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 20e:	9760      	ld.w      	r3, (r7, 0x0)
 210:	937a      	ld.w      	r3, (r3, 0x68)
 212:	e4632002 	andi      	r3, r3, 2
 216:	e903ffe7 	bez      	r3, 0x1e4	// 1e4 <ah_ce_start+0x1e4>
 21a:	8524      	ld.b      	r1, (r5, 0x4)
 21c:	100a      	lrw      	r0, 0x0	// 244 <ah_ce_start+0x244>
 21e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 222:	3400      	movi      	r4, 0
 224:	3301      	movi      	r3, 1
 226:	8544      	ld.b      	r2, (r5, 0x4)
 228:	9520      	ld.w      	r1, (r5, 0x0)
 22a:	2c00      	subi      	r4, 1
 22c:	1007      	lrw      	r0, 0x0	// 248 <ah_ce_start+0x248>
 22e:	e0000000 	bsr      	0x0	// 0 <dump_hex>
 232:	07da      	br      	0x1e6	// 1e6 <ah_ce_start+0x1e6>
	...
