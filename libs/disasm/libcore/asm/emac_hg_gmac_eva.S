
disasm/libcore/obj/emac_hg_gmac_eva.o:     file format elf32-csky-little


Disassembly of section .text.csi_vic_disable_irq:

00000000 <csi_vic_disable_irq>:
   0:	c4a054c3 	zext      	r3, r0, 6, 5
   4:	3201      	movi      	r2, 1
   6:	e400201f 	andi      	r0, r0, 31
   a:	c4024020 	lsl      	r0, r2, r0
   e:	231f      	addi      	r3, 32
  10:	1042      	lrw      	r2, 0xe000e100	// 18 <csi_vic_disable_irq+0x18>
  12:	d4620880 	str.w      	r0, (r2, r3 << 2)
  16:	783c      	jmp      	r15
  18:	e000e100 	.long	0xe000e100

Disassembly of section .text.hg_gmac_hw_init:

00000000 <hg_gmac_hw_init>:
   0:	14d2      	push      	r4-r5, r15
   2:	1095      	lrw      	r4, 0x40026000	// 54 <hg_gmac_hw_init+0x54>
   4:	6d43      	mov      	r5, r0
   6:	9466      	ld.w      	r3, (r4, 0x18)
   8:	3bb1      	bseti      	r3, 17
   a:	b466      	st.w      	r3, (r4, 0x18)
   c:	9465      	ld.w      	r3, (r4, 0x14)
   e:	3bbf      	bseti      	r3, 31
  10:	b465      	st.w      	r3, (r4, 0x14)
  12:	947f      	ld.w      	r3, (r4, 0x7c)
  14:	ec632000 	ori      	r3, r3, 8192
  18:	b47f      	st.w      	r3, (r4, 0x7c)
  1a:	9462      	ld.w      	r3, (r4, 0x8)
  1c:	3b9d      	bclri      	r3, 29
  1e:	b462      	st.w      	r3, (r4, 0x8)
  20:	3001      	movi      	r0, 1
  22:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  26:	9462      	ld.w      	r3, (r4, 0x8)
  28:	3bbd      	bseti      	r3, 29
  2a:	b462      	st.w      	r3, (r4, 0x8)
  2c:	3001      	movi      	r0, 1
  2e:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  32:	3380      	movi      	r3, 128
  34:	436b      	lsli      	r3, r3, 11
  36:	b572      	st.w      	r3, (r5, 0x48)
  38:	6c03      	mov      	r0, r0
  3a:	3380      	movi      	r3, 128
  3c:	4365      	lsli      	r3, r3, 5
  3e:	b560      	st.w      	r3, (r5, 0x0)
  40:	6c03      	mov      	r0, r0
  42:	ea034de7 	movi      	r3, 19943
  46:	b56a      	st.w      	r3, (r5, 0x28)
  48:	6c03      	mov      	r0, r0
  4a:	3300      	movi      	r3, 0
  4c:	b56e      	st.w      	r3, (r5, 0x38)
  4e:	6c03      	mov      	r0, r0
  50:	1492      	pop      	r4-r5, r15
  52:	0000      	.short	0x0000
  54:	40026000 	.long	0x40026000

Disassembly of section .text.hg_gmac_descriptor_init:

00000000 <hg_gmac_descriptor_init>:
   0:	14d5      	push      	r4-r8, r15
   2:	6d03      	mov      	r4, r0
   4:	9044      	ld.w      	r2, (r0, 0x10)
   6:	4244      	lsli      	r2, r2, 4
   8:	3100      	movi      	r1, 0
   a:	9005      	ld.w      	r0, (r0, 0x14)
   c:	e0000000 	bsr      	0x0	// 0 <memset>
  10:	9447      	ld.w      	r2, (r4, 0x1c)
  12:	4244      	lsli      	r2, r2, 4
  14:	3100      	movi      	r1, 0
  16:	9408      	ld.w      	r0, (r4, 0x20)
  18:	e0000000 	bsr      	0x0	// 0 <memset>
  1c:	3000      	movi      	r0, 0
  1e:	94a4      	ld.w      	r5, (r4, 0x10)
  20:	6c83      	mov      	r2, r0
  22:	6cc3      	mov      	r3, r0
  24:	3601      	movi      	r6, 1
  26:	6dc3      	mov      	r7, r0
  28:	ea0800ac 	movi      	r8, 172
  2c:	654e      	cmpne      	r3, r5
  2e:	e5a2000f 	addi      	r13, r2, 16
  32:	9425      	ld.w      	r1, (r4, 0x14)
  34:	082a      	bt      	0x88	// 88 <hg_gmac_descriptor_init+0x88>
  36:	c7605022 	bmaski      	r2, 28
  3a:	60c8      	addu      	r3, r2
  3c:	4364      	lsli      	r3, r3, 4
  3e:	60c4      	addu      	r3, r1
  40:	32be      	movi      	r2, 190
  42:	8b02      	ld.h      	r0, (r3, 0x4)
  44:	4243      	lsli      	r2, r2, 3
  46:	c4025d40 	ins      	r0, r2, 10, 0
  4a:	ea0d0001 	movi      	r13, 1
  4e:	8347      	ld.b      	r2, (r3, 0x7)
  50:	c44d5c21 	ins      	r2, r13, 2, 1
  54:	a347      	st.b      	r2, (r3, 0x7)
  56:	ea0c0000 	movi      	r12, 0
  5a:	ab02      	st.h      	r0, (r3, 0x4)
  5c:	b323      	st.w      	r1, (r3, 0xc)
  5e:	94e7      	ld.w      	r7, (r4, 0x1c)
  60:	6cb3      	mov      	r2, r12
  62:	6cf3      	mov      	r3, r12
  64:	6db3      	mov      	r6, r12
  66:	65ce      	cmpne      	r3, r7
  68:	e4a2000f 	addi      	r5, r2, 16
  6c:	9408      	ld.w      	r0, (r4, 0x20)
  6e:	082b      	bt      	0xc4	// c4 <hg_gmac_descriptor_init+0xc4>
  70:	c7605022 	bmaski      	r2, 28
  74:	60c8      	addu      	r3, r2
  76:	4364      	lsli      	r3, r3, 4
  78:	60c0      	addu      	r3, r0
  7a:	3101      	movi      	r1, 1
  7c:	8347      	ld.b      	r2, (r3, 0x7)
  7e:	c4415c01 	ins      	r2, r1, 1, 1
  82:	b303      	st.w      	r0, (r3, 0xc)
  84:	a347      	st.b      	r2, (r3, 0x7)
  86:	1495      	pop      	r4-r8, r15
  88:	6084      	addu      	r2, r1
  8a:	6074      	addu      	r1, r13
  8c:	d9820003 	ld.b      	r12, (r2, 0x3)
  90:	c5865c07 	ins      	r12, r6, 7, 7
  94:	dd820003 	st.b      	r12, (r2, 0x3)
  98:	d9820007 	ld.b      	r12, (r2, 0x7)
  9c:	c5875c00 	ins      	r12, r7, 0, 0
  a0:	dd820007 	st.b      	r12, (r2, 0x7)
  a4:	d9821002 	ld.h      	r12, (r2, 0x4)
  a8:	c5885d40 	ins      	r12, r8, 10, 0
  ac:	dd821002 	st.h      	r12, (r2, 0x4)
  b0:	d9842006 	ld.w      	r12, (r4, 0x18)
  b4:	6300      	addu      	r12, r0
  b6:	dd822002 	st.w      	r12, (r2, 0x8)
  ba:	b223      	st.w      	r1, (r2, 0xc)
  bc:	20ab      	addi      	r0, 172
  be:	2300      	addi      	r3, 1
  c0:	6cb7      	mov      	r2, r13
  c2:	07b5      	br      	0x2c	// 2c <hg_gmac_descriptor_init+0x2c>
  c4:	6080      	addu      	r2, r0
  c6:	6014      	addu      	r0, r5
  c8:	8223      	ld.b      	r1, (r2, 0x3)
  ca:	c4265c07 	ins      	r1, r6, 7, 7
  ce:	a223      	st.b      	r1, (r2, 0x3)
  d0:	8227      	ld.b      	r1, (r2, 0x7)
  d2:	c42d5c05 	ins      	r1, r13, 5, 5
  d6:	c42d5c06 	ins      	r1, r13, 6, 6
  da:	c4265c00 	ins      	r1, r6, 0, 0
  de:	a227      	st.b      	r1, (r2, 0x7)
  e0:	9429      	ld.w      	r1, (r4, 0x24)
  e2:	6070      	addu      	r1, r12
  e4:	b222      	st.w      	r1, (r2, 0x8)
  e6:	b203      	st.w      	r0, (r2, 0xc)
  e8:	e58c05eb 	addi      	r12, r12, 1516
  ec:	2300      	addi      	r3, 1
  ee:	6c97      	mov      	r2, r5
  f0:	07bb      	br      	0x66	// 66 <hg_gmac_descriptor_init+0x66>

Disassembly of section .text.hg_gmac_set_mac_addr:

00000000 <hg_gmac_set_mac_addr>:
   0:	14d3      	push      	r4-r6, r15
   2:	9090      	ld.w      	r4, (r0, 0x40)
   4:	6d43      	mov      	r5, r0
   6:	6d87      	mov      	r6, r1
   8:	e9240008 	bnez      	r4, 0x18	// 18 <hg_gmac_set_mac_addr+0x18>
   c:	3206      	movi      	r2, 6
   e:	206b      	addi      	r0, 108
  10:	e0000000 	bsr      	0x0	// 0 <memcpy>
  14:	6c13      	mov      	r0, r4
  16:	1493      	pop      	r4-r6, r15
  18:	9032      	ld.w      	r1, (r0, 0x48)
  1a:	3380      	movi      	r3, 128
  1c:	9182      	ld.w      	r4, (r1, 0x8)
  1e:	4366      	lsli      	r3, r3, 6
  20:	9140      	ld.w      	r2, (r1, 0x0)
  22:	e982004c 	blz      	r2, 0xba	// ba <hg_gmac_set_mac_addr+0xba>
  26:	3206      	movi      	r2, 6
  28:	6c5b      	mov      	r1, r6
  2a:	e405006b 	addi      	r0, r5, 108
  2e:	e0000000 	bsr      	0x0	// 0 <memcpy>
  32:	8661      	ld.b      	r3, (r6, 0x1)
  34:	8640      	ld.b      	r2, (r6, 0x0)
  36:	4368      	lsli      	r3, r3, 8
  38:	6cc8      	or      	r3, r2
  3a:	b460      	st.w      	r3, (r4, 0x0)
  3c:	8663      	ld.b      	r3, (r6, 0x3)
  3e:	8642      	ld.b      	r2, (r6, 0x2)
  40:	4368      	lsli      	r3, r3, 8
  42:	6cc8      	or      	r3, r2
  44:	b461      	st.w      	r3, (r4, 0x4)
  46:	8665      	ld.b      	r3, (r6, 0x5)
  48:	8644      	ld.b      	r2, (r6, 0x4)
  4a:	4368      	lsli      	r3, r3, 8
  4c:	6cc8      	or      	r3, r2
  4e:	b462      	st.w      	r3, (r4, 0x8)
  50:	e4c400bf 	addi      	r6, r4, 192
  54:	e464000b 	addi      	r3, r4, 12
  58:	6c0f      	mov      	r0, r3
  5a:	320c      	movi      	r2, 12
  5c:	6c53      	mov      	r1, r4
  5e:	e0000000 	bsr      	0x0	// 0 <memcpy>
  62:	6cc3      	mov      	r3, r0
  64:	230b      	addi      	r3, 12
  66:	658e      	cmpne      	r3, r6
  68:	0bf8      	bt      	0x58	// 58 <hg_gmac_set_mac_addr+0x58>
  6a:	9572      	ld.w      	r3, (r5, 0x48)
  6c:	3201      	movi      	r2, 1
  6e:	9321      	ld.w      	r1, (r3, 0x4)
  70:	c4225c1f 	ins      	r1, r2, 31, 31
  74:	b321      	st.w      	r1, (r3, 0x4)
  76:	9321      	ld.w      	r1, (r3, 0x4)
  78:	3000      	movi      	r0, 0
  7a:	c4205c1d 	ins      	r1, r0, 29, 29
  7e:	b321      	st.w      	r1, (r3, 0x4)
  80:	9321      	ld.w      	r1, (r3, 0x4)
  82:	c4205c1e 	ins      	r1, r0, 30, 30
  86:	b321      	st.w      	r1, (r3, 0x4)
  88:	9321      	ld.w      	r1, (r3, 0x4)
  8a:	c4205c1c 	ins      	r1, r0, 28, 28
  8e:	b321      	st.w      	r1, (r3, 0x4)
  90:	9321      	ld.w      	r1, (r3, 0x4)
  92:	c4205c16 	ins      	r1, r0, 22, 22
  96:	b321      	st.w      	r1, (r3, 0x4)
  98:	9321      	ld.w      	r1, (r3, 0x4)
  9a:	c4225c1b 	ins      	r1, r2, 27, 27
  9e:	b321      	st.w      	r1, (r3, 0x4)
  a0:	9321      	ld.w      	r1, (r3, 0x4)
  a2:	ea0c00c0 	movi      	r12, 192
  a6:	c42c5d40 	ins      	r1, r12, 10, 0
  aa:	b321      	st.w      	r1, (r3, 0x4)
  ac:	9320      	ld.w      	r1, (r3, 0x0)
  ae:	c4225c1f 	ins      	r1, r2, 31, 31
  b2:	b320      	st.w      	r1, (r3, 0x0)
  b4:	9363      	ld.w      	r3, (r3, 0xc)
  b6:	b572      	st.w      	r3, (r5, 0x48)
  b8:	07af      	br      	0x16	// 16 <hg_gmac_set_mac_addr+0x16>
  ba:	9548      	ld.w      	r2, (r5, 0x20)
  bc:	924c      	ld.w      	r2, (r2, 0x30)
  be:	6c03      	mov      	r0, r0
  c0:	688c      	and      	r2, r3
  c2:	e922ffaf 	bnez      	r2, 0x20	// 20 <hg_gmac_set_mac_addr+0x20>
  c6:	3000      	movi      	r0, 0
  c8:	2800      	subi      	r0, 1
  ca:	07a6      	br      	0x16	// 16 <hg_gmac_set_mac_addr+0x16>

Disassembly of section .text.hg_gmac_mdio_read:

00000000 <hg_gmac_mdio_read>:
   0:	14d5      	push      	r4-r8, r15
   2:	6e07      	mov      	r8, r1
   4:	e4e000ab 	addi      	r7, r0, 172
   8:	3100      	movi      	r1, 0
   a:	6d03      	mov      	r4, r0
   c:	2900      	subi      	r1, 1
   e:	6c1f      	mov      	r0, r7
  10:	6d8b      	mov      	r6, r2
  12:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  16:	3300      	movi      	r3, 0
  18:	6c8f      	mov      	r2, r3
  1a:	3102      	movi      	r1, 2
  1c:	940e      	ld.w      	r0, (r4, 0x38)
  1e:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  22:	3300      	movi      	r3, 0
  24:	3201      	movi      	r2, 1
  26:	3102      	movi      	r1, 2
  28:	940d      	ld.w      	r0, (r4, 0x34)
  2a:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  2e:	3000      	movi      	r0, 0
  30:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  34:	3520      	movi      	r5, 32
  36:	3300      	movi      	r3, 0
  38:	3201      	movi      	r2, 1
  3a:	3102      	movi      	r1, 2
  3c:	940e      	ld.w      	r0, (r4, 0x38)
  3e:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  42:	3000      	movi      	r0, 0
  44:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  48:	3300      	movi      	r3, 0
  4a:	6c8f      	mov      	r2, r3
  4c:	3102      	movi      	r1, 2
  4e:	940e      	ld.w      	r0, (r4, 0x38)
  50:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  54:	2d00      	subi      	r5, 1
  56:	3000      	movi      	r0, 0
  58:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  5c:	e925ffed 	bnez      	r5, 0x36	// 36 <hg_gmac_mdio_read+0x36>
  60:	6cd7      	mov      	r3, r5
  62:	6c97      	mov      	r2, r5
  64:	3102      	movi      	r1, 2
  66:	940d      	ld.w      	r0, (r4, 0x34)
  68:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  6c:	6c17      	mov      	r0, r5
  6e:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  72:	6cd7      	mov      	r3, r5
  74:	3201      	movi      	r2, 1
  76:	3102      	movi      	r1, 2
  78:	940e      	ld.w      	r0, (r4, 0x38)
  7a:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  7e:	6c17      	mov      	r0, r5
  80:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  84:	6cd7      	mov      	r3, r5
  86:	6c97      	mov      	r2, r5
  88:	3102      	movi      	r1, 2
  8a:	940e      	ld.w      	r0, (r4, 0x38)
  8c:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  90:	6cd7      	mov      	r3, r5
  92:	3201      	movi      	r2, 1
  94:	3102      	movi      	r1, 2
  96:	940d      	ld.w      	r0, (r4, 0x34)
  98:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  9c:	6c17      	mov      	r0, r5
  9e:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  a2:	6cd7      	mov      	r3, r5
  a4:	3201      	movi      	r2, 1
  a6:	3102      	movi      	r1, 2
  a8:	940e      	ld.w      	r0, (r4, 0x38)
  aa:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  ae:	6c17      	mov      	r0, r5
  b0:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  b4:	6cd7      	mov      	r3, r5
  b6:	6c97      	mov      	r2, r5
  b8:	3102      	movi      	r1, 2
  ba:	940e      	ld.w      	r0, (r4, 0x38)
  bc:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  c0:	6cd7      	mov      	r3, r5
  c2:	3201      	movi      	r2, 1
  c4:	3102      	movi      	r1, 2
  c6:	940d      	ld.w      	r0, (r4, 0x34)
  c8:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  cc:	6c17      	mov      	r0, r5
  ce:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  d2:	6cd7      	mov      	r3, r5
  d4:	3201      	movi      	r2, 1
  d6:	3102      	movi      	r1, 2
  d8:	940e      	ld.w      	r0, (r4, 0x38)
  da:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  de:	6c17      	mov      	r0, r5
  e0:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  e4:	6cd7      	mov      	r3, r5
  e6:	6c97      	mov      	r2, r5
  e8:	3102      	movi      	r1, 2
  ea:	940e      	ld.w      	r0, (r4, 0x38)
  ec:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  f0:	6cd7      	mov      	r3, r5
  f2:	6c97      	mov      	r2, r5
  f4:	3102      	movi      	r1, 2
  f6:	940d      	ld.w      	r0, (r4, 0x34)
  f8:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  fc:	6c17      	mov      	r0, r5
  fe:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 102:	6cd7      	mov      	r3, r5
 104:	3201      	movi      	r2, 1
 106:	3102      	movi      	r1, 2
 108:	940e      	ld.w      	r0, (r4, 0x38)
 10a:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 10e:	6c17      	mov      	r0, r5
 110:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 114:	6cd7      	mov      	r3, r5
 116:	6c97      	mov      	r2, r5
 118:	3102      	movi      	r1, 2
 11a:	940e      	ld.w      	r0, (r4, 0x38)
 11c:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 120:	3504      	movi      	r5, 4
 122:	c4a84043 	lsr      	r3, r8, r5
 126:	e4632001 	andi      	r3, r3, 1
 12a:	940d      	ld.w      	r0, (r4, 0x34)
 12c:	e90300a7 	bez      	r3, 0x27a	// 27a <hg_gmac_mdio_read+0x27a>
 130:	3300      	movi      	r3, 0
 132:	3201      	movi      	r2, 1
 134:	3102      	movi      	r1, 2
 136:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 13a:	3000      	movi      	r0, 0
 13c:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 140:	3300      	movi      	r3, 0
 142:	3201      	movi      	r2, 1
 144:	3102      	movi      	r1, 2
 146:	940e      	ld.w      	r0, (r4, 0x38)
 148:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 14c:	3000      	movi      	r0, 0
 14e:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 152:	3300      	movi      	r3, 0
 154:	6c8f      	mov      	r2, r3
 156:	3102      	movi      	r1, 2
 158:	940e      	ld.w      	r0, (r4, 0x38)
 15a:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 15e:	3300      	movi      	r3, 0
 160:	2d00      	subi      	r5, 1
 162:	2b00      	subi      	r3, 1
 164:	64d6      	cmpne      	r5, r3
 166:	0bde      	bt      	0x122	// 122 <hg_gmac_mdio_read+0x122>
 168:	3504      	movi      	r5, 4
 16a:	c4a64043 	lsr      	r3, r6, r5
 16e:	e4632001 	andi      	r3, r3, 1
 172:	940d      	ld.w      	r0, (r4, 0x34)
 174:	e9030085 	bez      	r3, 0x27e	// 27e <hg_gmac_mdio_read+0x27e>
 178:	3300      	movi      	r3, 0
 17a:	3201      	movi      	r2, 1
 17c:	3102      	movi      	r1, 2
 17e:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 182:	3000      	movi      	r0, 0
 184:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 188:	3300      	movi      	r3, 0
 18a:	3201      	movi      	r2, 1
 18c:	3102      	movi      	r1, 2
 18e:	940e      	ld.w      	r0, (r4, 0x38)
 190:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 194:	3000      	movi      	r0, 0
 196:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 19a:	3300      	movi      	r3, 0
 19c:	6c8f      	mov      	r2, r3
 19e:	3102      	movi      	r1, 2
 1a0:	940e      	ld.w      	r0, (r4, 0x38)
 1a2:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 1a6:	3300      	movi      	r3, 0
 1a8:	2d00      	subi      	r5, 1
 1aa:	2b00      	subi      	r3, 1
 1ac:	64d6      	cmpne      	r5, r3
 1ae:	0bde      	bt      	0x16a	// 16a <hg_gmac_mdio_read+0x16a>
 1b0:	3300      	movi      	r3, 0
 1b2:	6c8f      	mov      	r2, r3
 1b4:	3101      	movi      	r1, 1
 1b6:	940d      	ld.w      	r0, (r4, 0x34)
 1b8:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 1bc:	3000      	movi      	r0, 0
 1be:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 1c2:	3300      	movi      	r3, 0
 1c4:	3201      	movi      	r2, 1
 1c6:	3102      	movi      	r1, 2
 1c8:	940e      	ld.w      	r0, (r4, 0x38)
 1ca:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 1ce:	3000      	movi      	r0, 0
 1d0:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 1d4:	3300      	movi      	r3, 0
 1d6:	6c8f      	mov      	r2, r3
 1d8:	3102      	movi      	r1, 2
 1da:	940e      	ld.w      	r0, (r4, 0x38)
 1dc:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 1e0:	3000      	movi      	r0, 0
 1e2:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 1e6:	3300      	movi      	r3, 0
 1e8:	3201      	movi      	r2, 1
 1ea:	3102      	movi      	r1, 2
 1ec:	940e      	ld.w      	r0, (r4, 0x38)
 1ee:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 1f2:	3000      	movi      	r0, 0
 1f4:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 1f8:	360f      	movi      	r6, 15
 1fa:	3500      	movi      	r5, 0
 1fc:	ea080001 	movi      	r8, 1
 200:	3300      	movi      	r3, 0
 202:	6c8f      	mov      	r2, r3
 204:	3102      	movi      	r1, 2
 206:	940e      	ld.w      	r0, (r4, 0x38)
 208:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 20c:	940d      	ld.w      	r0, (r4, 0x34)
 20e:	e0000000 	bsr      	0x0	// 0 <gpio_get_val>
 212:	e9000006 	bez      	r0, 0x21e	// 21e <hg_gmac_mdio_read+0x21e>
 216:	c4c84023 	lsl      	r3, r8, r6
 21a:	6d4c      	or      	r5, r3
 21c:	7555      	zexth      	r5, r5
 21e:	3000      	movi      	r0, 0
 220:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 224:	3300      	movi      	r3, 0
 226:	3201      	movi      	r2, 1
 228:	3102      	movi      	r1, 2
 22a:	940e      	ld.w      	r0, (r4, 0x38)
 22c:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 230:	3000      	movi      	r0, 0
 232:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 236:	3300      	movi      	r3, 0
 238:	2e00      	subi      	r6, 1
 23a:	2b00      	subi      	r3, 1
 23c:	64da      	cmpne      	r6, r3
 23e:	0be1      	bt      	0x200	// 200 <hg_gmac_mdio_read+0x200>
 240:	3300      	movi      	r3, 0
 242:	6c8f      	mov      	r2, r3
 244:	3102      	movi      	r1, 2
 246:	940e      	ld.w      	r0, (r4, 0x38)
 248:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 24c:	3000      	movi      	r0, 0
 24e:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 252:	3201      	movi      	r2, 1
 254:	6c4b      	mov      	r1, r2
 256:	3300      	movi      	r3, 0
 258:	940d      	ld.w      	r0, (r4, 0x34)
 25a:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 25e:	3300      	movi      	r3, 0
 260:	3201      	movi      	r2, 1
 262:	3102      	movi      	r1, 2
 264:	940d      	ld.w      	r0, (r4, 0x34)
 266:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 26a:	3000      	movi      	r0, 0
 26c:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 270:	6c1f      	mov      	r0, r7
 272:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
 276:	6c17      	mov      	r0, r5
 278:	1495      	pop      	r4-r8, r15
 27a:	6c8f      	mov      	r2, r3
 27c:	075c      	br      	0x134	// 134 <hg_gmac_mdio_read+0x134>
 27e:	6c8f      	mov      	r2, r3
 280:	077e      	br      	0x17c	// 17c <hg_gmac_mdio_read+0x17c>

Disassembly of section .text.hg_gmac_mdio_write:

00000000 <hg_gmac_mdio_write>:
   0:	14d6      	push      	r4-r9, r15
   2:	6e47      	mov      	r9, r1
   4:	e4c000ab 	addi      	r6, r0, 172
   8:	3100      	movi      	r1, 0
   a:	6d03      	mov      	r4, r0
   c:	2900      	subi      	r1, 1
   e:	6c1b      	mov      	r0, r6
  10:	6e0b      	mov      	r8, r2
  12:	6dcf      	mov      	r7, r3
  14:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  18:	3300      	movi      	r3, 0
  1a:	6c8f      	mov      	r2, r3
  1c:	3102      	movi      	r1, 2
  1e:	940e      	ld.w      	r0, (r4, 0x38)
  20:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  24:	3300      	movi      	r3, 0
  26:	3201      	movi      	r2, 1
  28:	3102      	movi      	r1, 2
  2a:	940d      	ld.w      	r0, (r4, 0x34)
  2c:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  30:	3000      	movi      	r0, 0
  32:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  36:	3520      	movi      	r5, 32
  38:	3300      	movi      	r3, 0
  3a:	3201      	movi      	r2, 1
  3c:	3102      	movi      	r1, 2
  3e:	940e      	ld.w      	r0, (r4, 0x38)
  40:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  44:	3000      	movi      	r0, 0
  46:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  4a:	3300      	movi      	r3, 0
  4c:	6c8f      	mov      	r2, r3
  4e:	3102      	movi      	r1, 2
  50:	940e      	ld.w      	r0, (r4, 0x38)
  52:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  56:	2d00      	subi      	r5, 1
  58:	3000      	movi      	r0, 0
  5a:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  5e:	e925ffed 	bnez      	r5, 0x38	// 38 <hg_gmac_mdio_write+0x38>
  62:	6cd7      	mov      	r3, r5
  64:	6c97      	mov      	r2, r5
  66:	3102      	movi      	r1, 2
  68:	940d      	ld.w      	r0, (r4, 0x34)
  6a:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  6e:	6c17      	mov      	r0, r5
  70:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  74:	6cd7      	mov      	r3, r5
  76:	3201      	movi      	r2, 1
  78:	3102      	movi      	r1, 2
  7a:	940e      	ld.w      	r0, (r4, 0x38)
  7c:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  80:	6c17      	mov      	r0, r5
  82:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  86:	6cd7      	mov      	r3, r5
  88:	6c97      	mov      	r2, r5
  8a:	3102      	movi      	r1, 2
  8c:	940e      	ld.w      	r0, (r4, 0x38)
  8e:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  92:	6cd7      	mov      	r3, r5
  94:	3201      	movi      	r2, 1
  96:	3102      	movi      	r1, 2
  98:	940d      	ld.w      	r0, (r4, 0x34)
  9a:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  9e:	6c17      	mov      	r0, r5
  a0:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  a4:	6cd7      	mov      	r3, r5
  a6:	3201      	movi      	r2, 1
  a8:	3102      	movi      	r1, 2
  aa:	940e      	ld.w      	r0, (r4, 0x38)
  ac:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  b0:	6c17      	mov      	r0, r5
  b2:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  b6:	6cd7      	mov      	r3, r5
  b8:	6c97      	mov      	r2, r5
  ba:	3102      	movi      	r1, 2
  bc:	940e      	ld.w      	r0, (r4, 0x38)
  be:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  c2:	6cd7      	mov      	r3, r5
  c4:	6c97      	mov      	r2, r5
  c6:	3102      	movi      	r1, 2
  c8:	940d      	ld.w      	r0, (r4, 0x34)
  ca:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  ce:	6c17      	mov      	r0, r5
  d0:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  d4:	6cd7      	mov      	r3, r5
  d6:	3201      	movi      	r2, 1
  d8:	3102      	movi      	r1, 2
  da:	940e      	ld.w      	r0, (r4, 0x38)
  dc:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  e0:	6c17      	mov      	r0, r5
  e2:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  e6:	6cd7      	mov      	r3, r5
  e8:	6c97      	mov      	r2, r5
  ea:	3102      	movi      	r1, 2
  ec:	940e      	ld.w      	r0, (r4, 0x38)
  ee:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  f2:	6cd7      	mov      	r3, r5
  f4:	3201      	movi      	r2, 1
  f6:	3102      	movi      	r1, 2
  f8:	940d      	ld.w      	r0, (r4, 0x34)
  fa:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
  fe:	6c17      	mov      	r0, r5
 100:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 104:	6cd7      	mov      	r3, r5
 106:	3201      	movi      	r2, 1
 108:	3102      	movi      	r1, 2
 10a:	940e      	ld.w      	r0, (r4, 0x38)
 10c:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 110:	6c17      	mov      	r0, r5
 112:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 116:	6cd7      	mov      	r3, r5
 118:	6c97      	mov      	r2, r5
 11a:	3102      	movi      	r1, 2
 11c:	940e      	ld.w      	r0, (r4, 0x38)
 11e:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 122:	3504      	movi      	r5, 4
 124:	c4a94043 	lsr      	r3, r9, r5
 128:	e4632001 	andi      	r3, r3, 1
 12c:	940d      	ld.w      	r0, (r4, 0x34)
 12e:	e90300c2 	bez      	r3, 0x2b2	// 2b2 <hg_gmac_mdio_write+0x2b2>
 132:	3300      	movi      	r3, 0
 134:	3201      	movi      	r2, 1
 136:	3102      	movi      	r1, 2
 138:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 13c:	3000      	movi      	r0, 0
 13e:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 142:	3300      	movi      	r3, 0
 144:	3201      	movi      	r2, 1
 146:	3102      	movi      	r1, 2
 148:	940e      	ld.w      	r0, (r4, 0x38)
 14a:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 14e:	3000      	movi      	r0, 0
 150:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 154:	3300      	movi      	r3, 0
 156:	6c8f      	mov      	r2, r3
 158:	3102      	movi      	r1, 2
 15a:	940e      	ld.w      	r0, (r4, 0x38)
 15c:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 160:	3300      	movi      	r3, 0
 162:	2d00      	subi      	r5, 1
 164:	2b00      	subi      	r3, 1
 166:	64d6      	cmpne      	r5, r3
 168:	0bde      	bt      	0x124	// 124 <hg_gmac_mdio_write+0x124>
 16a:	3504      	movi      	r5, 4
 16c:	c4a84043 	lsr      	r3, r8, r5
 170:	e4632001 	andi      	r3, r3, 1
 174:	940d      	ld.w      	r0, (r4, 0x34)
 176:	e90300a0 	bez      	r3, 0x2b6	// 2b6 <hg_gmac_mdio_write+0x2b6>
 17a:	3300      	movi      	r3, 0
 17c:	3201      	movi      	r2, 1
 17e:	3102      	movi      	r1, 2
 180:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 184:	3000      	movi      	r0, 0
 186:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 18a:	3300      	movi      	r3, 0
 18c:	3201      	movi      	r2, 1
 18e:	3102      	movi      	r1, 2
 190:	940e      	ld.w      	r0, (r4, 0x38)
 192:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 196:	3000      	movi      	r0, 0
 198:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 19c:	3300      	movi      	r3, 0
 19e:	6c8f      	mov      	r2, r3
 1a0:	3102      	movi      	r1, 2
 1a2:	940e      	ld.w      	r0, (r4, 0x38)
 1a4:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 1a8:	3300      	movi      	r3, 0
 1aa:	2d00      	subi      	r5, 1
 1ac:	2b00      	subi      	r3, 1
 1ae:	64d6      	cmpne      	r5, r3
 1b0:	0bde      	bt      	0x16c	// 16c <hg_gmac_mdio_write+0x16c>
 1b2:	3300      	movi      	r3, 0
 1b4:	3201      	movi      	r2, 1
 1b6:	3102      	movi      	r1, 2
 1b8:	940d      	ld.w      	r0, (r4, 0x34)
 1ba:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 1be:	3000      	movi      	r0, 0
 1c0:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 1c4:	3300      	movi      	r3, 0
 1c6:	3201      	movi      	r2, 1
 1c8:	3102      	movi      	r1, 2
 1ca:	940e      	ld.w      	r0, (r4, 0x38)
 1cc:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 1d0:	3000      	movi      	r0, 0
 1d2:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 1d6:	3300      	movi      	r3, 0
 1d8:	6c8f      	mov      	r2, r3
 1da:	3102      	movi      	r1, 2
 1dc:	940e      	ld.w      	r0, (r4, 0x38)
 1de:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 1e2:	3300      	movi      	r3, 0
 1e4:	6c8f      	mov      	r2, r3
 1e6:	3102      	movi      	r1, 2
 1e8:	940d      	ld.w      	r0, (r4, 0x34)
 1ea:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 1ee:	3000      	movi      	r0, 0
 1f0:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 1f4:	3300      	movi      	r3, 0
 1f6:	3201      	movi      	r2, 1
 1f8:	3102      	movi      	r1, 2
 1fa:	940e      	ld.w      	r0, (r4, 0x38)
 1fc:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 200:	3000      	movi      	r0, 0
 202:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 206:	3300      	movi      	r3, 0
 208:	6c8f      	mov      	r2, r3
 20a:	3102      	movi      	r1, 2
 20c:	940e      	ld.w      	r0, (r4, 0x38)
 20e:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 212:	350f      	movi      	r5, 15
 214:	c4a74043 	lsr      	r3, r7, r5
 218:	e4632001 	andi      	r3, r3, 1
 21c:	940d      	ld.w      	r0, (r4, 0x34)
 21e:	e903004e 	bez      	r3, 0x2ba	// 2ba <hg_gmac_mdio_write+0x2ba>
 222:	3300      	movi      	r3, 0
 224:	3201      	movi      	r2, 1
 226:	3102      	movi      	r1, 2
 228:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 22c:	3000      	movi      	r0, 0
 22e:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 232:	3300      	movi      	r3, 0
 234:	3201      	movi      	r2, 1
 236:	3102      	movi      	r1, 2
 238:	940e      	ld.w      	r0, (r4, 0x38)
 23a:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 23e:	3000      	movi      	r0, 0
 240:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 244:	3300      	movi      	r3, 0
 246:	6c8f      	mov      	r2, r3
 248:	3102      	movi      	r1, 2
 24a:	940e      	ld.w      	r0, (r4, 0x38)
 24c:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 250:	3300      	movi      	r3, 0
 252:	2d00      	subi      	r5, 1
 254:	2b00      	subi      	r3, 1
 256:	64d6      	cmpne      	r5, r3
 258:	0bde      	bt      	0x214	// 214 <hg_gmac_mdio_write+0x214>
 25a:	3300      	movi      	r3, 0
 25c:	6c8f      	mov      	r2, r3
 25e:	3102      	movi      	r1, 2
 260:	940e      	ld.w      	r0, (r4, 0x38)
 262:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 266:	3300      	movi      	r3, 0
 268:	3201      	movi      	r2, 1
 26a:	3102      	movi      	r1, 2
 26c:	940d      	ld.w      	r0, (r4, 0x34)
 26e:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 272:	3000      	movi      	r0, 0
 274:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 278:	3520      	movi      	r5, 32
 27a:	3300      	movi      	r3, 0
 27c:	3201      	movi      	r2, 1
 27e:	3102      	movi      	r1, 2
 280:	940e      	ld.w      	r0, (r4, 0x38)
 282:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 286:	3000      	movi      	r0, 0
 288:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 28c:	3300      	movi      	r3, 0
 28e:	6c8f      	mov      	r2, r3
 290:	3102      	movi      	r1, 2
 292:	940e      	ld.w      	r0, (r4, 0x38)
 294:	e0000000 	bsr      	0x0	// 0 <gpio_ioctl>
 298:	2d00      	subi      	r5, 1
 29a:	3000      	movi      	r0, 0
 29c:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 2a0:	e925ffed 	bnez      	r5, 0x27a	// 27a <hg_gmac_mdio_write+0x27a>
 2a4:	3001      	movi      	r0, 1
 2a6:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
 2aa:	6c1b      	mov      	r0, r6
 2ac:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
 2b0:	1496      	pop      	r4-r9, r15
 2b2:	6c8f      	mov      	r2, r3
 2b4:	0741      	br      	0x136	// 136 <hg_gmac_mdio_write+0x136>
 2b6:	6c8f      	mov      	r2, r3
 2b8:	0763      	br      	0x17e	// 17e <hg_gmac_mdio_write+0x17e>
 2ba:	6c8f      	mov      	r2, r3
 2bc:	07b5      	br      	0x226	// 226 <hg_gmac_mdio_write+0x226>

Disassembly of section .text.hg_gmac_send_scatter_data:

00000000 <hg_gmac_send_scatter_data>:
   0:	14d6      	push      	r4-r9, r15
   2:	9072      	ld.w      	r3, (r0, 0x48)
   4:	6d43      	mov      	r5, r0
   6:	d9232002 	ld.w      	r9, (r3, 0x8)
   a:	d8602028 	ld.w      	r3, (r0, 0xa0)
   e:	3b41      	cmpnei      	r3, 1
  10:	6e07      	mov      	r8, r1
  12:	6d0b      	mov      	r4, r2
  14:	084f      	bt      	0xb2	// b2 <hg_gmac_send_scatter_data+0xb2>
  16:	e902006c 	bez      	r2, 0xee	// ee <hg_gmac_send_scatter_data+0xee>
  1a:	e4e000b3 	addi      	r7, r0, 180
  1e:	3100      	movi      	r1, 0
  20:	2900      	subi      	r1, 1
  22:	6c1f      	mov      	r0, r7
  24:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  28:	3180      	movi      	r1, 128
  2a:	9572      	ld.w      	r3, (r5, 0x48)
  2c:	4126      	lsli      	r1, r1, 6
  2e:	9340      	ld.w      	r2, (r3, 0x0)
  30:	4a5f      	lsri      	r2, r2, 31
  32:	e9220037 	bnez      	r2, 0xa0	// a0 <hg_gmac_send_scatter_data+0xa0>
  36:	9321      	ld.w      	r1, (r3, 0x4)
  38:	c7615761 	zext      	r1, r1, 27, 27
  3c:	e9010017 	bez      	r1, 0x6a	// 6a <hg_gmac_send_scatter_data+0x6a>
  40:	9321      	ld.w      	r1, (r3, 0x4)
  42:	c4225c1b 	ins      	r1, r2, 27, 27
  46:	b321      	st.w      	r1, (r3, 0x4)
  48:	9321      	ld.w      	r1, (r3, 0x4)
  4a:	c4225c1c 	ins      	r1, r2, 28, 28
  4e:	b321      	st.w      	r1, (r3, 0x4)
  50:	9321      	ld.w      	r1, (r3, 0x4)
  52:	c4225c16 	ins      	r1, r2, 22, 22
  56:	b321      	st.w      	r1, (r3, 0x4)
  58:	9341      	ld.w      	r2, (r3, 0x4)
  5a:	3101      	movi      	r1, 1
  5c:	c4415c1d 	ins      	r2, r1, 29, 29
  60:	b341      	st.w      	r2, (r3, 0x4)
  62:	9341      	ld.w      	r2, (r3, 0x4)
  64:	c4415c1e 	ins      	r2, r1, 30, 30
  68:	b341      	st.w      	r2, (r3, 0x4)
  6a:	3600      	movi      	r6, 0
  6c:	d8482001 	ld.w      	r2, (r8, 0x4)
  70:	6188      	addu      	r6, r2
  72:	eb0605ea 	cmphsi      	r6, 1515
  76:	2c00      	subi      	r4, 1
  78:	081a      	bt      	0xac	// ac <hg_gmac_send_scatter_data+0xac>
  7a:	d8282000 	ld.w      	r1, (r8, 0x0)
  7e:	6c27      	mov      	r0, r9
  80:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
  84:	d8682001 	ld.w      	r3, (r8, 0x4)
  88:	624c      	addu      	r9, r3
  8a:	e5080007 	addi      	r8, r8, 8
  8e:	e924ffef 	bnez      	r4, 0x6c	// 6c <hg_gmac_send_scatter_data+0x6c>
  92:	e9260013 	bnez      	r6, 0xb8	// b8 <hg_gmac_send_scatter_data+0xb8>
  96:	6c1f      	mov      	r0, r7
  98:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  9c:	6c1b      	mov      	r0, r6
  9e:	1496      	pop      	r4-r9, r15
  a0:	9548      	ld.w      	r2, (r5, 0x20)
  a2:	924c      	ld.w      	r2, (r2, 0x30)
  a4:	6c03      	mov      	r0, r0
  a6:	6884      	and      	r2, r1
  a8:	e922ffc3 	bnez      	r2, 0x2e	// 2e <hg_gmac_send_scatter_data+0x2e>
  ac:	6c1f      	mov      	r0, r7
  ae:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  b2:	3000      	movi      	r0, 0
  b4:	2800      	subi      	r0, 1
  b6:	07f4      	br      	0x9e	// 9e <hg_gmac_send_scatter_data+0x9e>
  b8:	9572      	ld.w      	r3, (r5, 0x48)
  ba:	3101      	movi      	r1, 1
  bc:	9341      	ld.w      	r2, (r3, 0x4)
  be:	c4465d40 	ins      	r2, r6, 10, 0
  c2:	b341      	st.w      	r2, (r3, 0x4)
  c4:	9341      	ld.w      	r2, (r3, 0x4)
  c6:	c4415c1f 	ins      	r2, r1, 31, 31
  ca:	b341      	st.w      	r2, (r3, 0x4)
  cc:	9340      	ld.w      	r2, (r3, 0x0)
  ce:	c4415c1f 	ins      	r2, r1, 31, 31
  d2:	b340      	st.w      	r2, (r3, 0x0)
  d4:	9363      	ld.w      	r3, (r3, 0xc)
  d6:	b572      	st.w      	r3, (r5, 0x48)
  d8:	9568      	ld.w      	r3, (r5, 0x20)
  da:	b382      	st.w      	r4, (r3, 0x8)
  dc:	6c03      	mov      	r0, r0
  de:	d865202f 	ld.w      	r3, (r5, 0xbc)
  e2:	60c4      	addu      	r3, r1
  e4:	dc65202f 	st.w      	r3, (r5, 0xbc)
  e8:	6c1f      	mov      	r0, r7
  ea:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  ee:	6c13      	mov      	r0, r4
  f0:	07d7      	br      	0x9e	// 9e <hg_gmac_send_scatter_data+0x9e>

Disassembly of section .text.hg_gmac_open:

00000000 <hg_gmac_open>:
   0:	14d5      	push      	r4-r8, r15
   2:	1422      	subi      	r14, r14, 8
   4:	6d03      	mov      	r4, r0
   6:	6d87      	mov      	r6, r1
   8:	3206      	movi      	r2, 6
   a:	0330      	lrw      	r1, 0x0	// 244 <hg_gmac_open+0x244>
   c:	6c3b      	mov      	r0, r14
   e:	6dcf      	mov      	r7, r3
  10:	e0000000 	bsr      	0x0	// 0 <memcpy>
  14:	9470      	ld.w      	r3, (r4, 0x40)
  16:	e9230103 	bnez      	r3, 0x21c	// 21c <hg_gmac_open+0x21c>
  1a:	947f      	ld.w      	r3, (r4, 0x7c)
  1c:	eb030602 	cmphsi      	r3, 1539
  20:	0809      	bt      	0x32	// 32 <hg_gmac_open+0x32>
  22:	0355      	lrw      	r2, 0x0	// 248 <hg_gmac_open+0x248>
  24:	ea0104aa 	movi      	r1, 1194
  28:	0316      	lrw      	r0, 0x0	// 24c <assert_internal+0x24c>
  2a:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  2e:	3500      	movi      	r5, 0
  30:	0439      	br      	0xa2	// a2 <hg_gmac_open+0xa2>
  32:	d8642020 	ld.w      	r3, (r4, 0x80)
  36:	eb0306c2 	cmphsi      	r3, 1731
  3a:	0807      	bt      	0x48	// 48 <hg_gmac_open+0x48>
  3c:	3196      	movi      	r1, 150
  3e:	035a      	lrw      	r2, 0x0	// 250 <hg_gmac_open+0x250>
  40:	4123      	lsli      	r1, r1, 3
  42:	031c      	lrw      	r0, 0x0	// 24c <hg_gmac_open+0x24c>
  44:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  48:	941f      	ld.w      	r0, (r4, 0x7c)
  4a:	ea0205fc 	movi      	r2, 1532
  4e:	d8642020 	ld.w      	r3, (r4, 0x80)
  52:	2806      	subi      	r0, 7
  54:	c4408020 	divu      	r0, r0, r2
  58:	e463154a 	subi      	r3, r3, 1355
  5c:	35bc      	movi      	r5, 188
  5e:	b418      	st.w      	r0, (r4, 0x60)
  60:	c4a38023 	divu      	r3, r3, r5
  64:	7c08      	mult      	r0, r2
  66:	b475      	st.w      	r3, (r4, 0x54)
  68:	2006      	addi      	r0, 7
  6a:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  6e:	b414      	st.w      	r0, (r4, 0x50)
  70:	e900ffdf 	bez      	r0, 0x2e	// 2e <hg_gmac_open+0x2e>
  74:	3300      	movi      	r3, 0
  76:	2b07      	subi      	r3, 8
  78:	2006      	addi      	r0, 7
  7a:	680c      	and      	r0, r3
  7c:	9478      	ld.w      	r3, (r4, 0x60)
  7e:	4364      	lsli      	r3, r3, 4
  80:	b419      	st.w      	r0, (r4, 0x64)
  82:	600c      	addu      	r0, r3
  84:	b41a      	st.w      	r0, (r4, 0x68)
  86:	9415      	ld.w      	r0, (r4, 0x54)
  88:	7c14      	mult      	r0, r5
  8a:	e400054a 	addi      	r0, r0, 1355
  8e:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  92:	6d43      	mov      	r5, r0
  94:	b413      	st.w      	r0, (r4, 0x4c)
  96:	e9200008 	bnez      	r0, 0xa6	// a6 <hg_gmac_open+0xa6>
  9a:	9414      	ld.w      	r0, (r4, 0x50)
  9c:	e0000000 	bsr      	0x0	// 0 <_os_free>
  a0:	b4b4      	st.w      	r5, (r4, 0x50)
  a2:	2d00      	subi      	r5, 1
  a4:	041a      	br      	0xd8	// d8 <hg_gmac_open+0xd8>
  a6:	3300      	movi      	r3, 0
  a8:	2b07      	subi      	r3, 8
  aa:	2506      	addi      	r5, 7
  ac:	694c      	and      	r5, r3
  ae:	9475      	ld.w      	r3, (r4, 0x54)
  b0:	4364      	lsli      	r3, r3, 4
  b2:	b4b6      	st.w      	r5, (r4, 0x58)
  b4:	614c      	addu      	r5, r3
  b6:	b4b7      	st.w      	r5, (r4, 0x5c)
  b8:	3101      	movi      	r1, 1
  ba:	9400      	ld.w      	r0, (r4, 0x0)
  bc:	e0000000 	bsr      	0x0	// 0 <pin_func>
  c0:	6d43      	mov      	r5, r0
  c2:	e900000e 	bez      	r0, 0xde	// de <hg_gmac_open+0xde>
  c6:	9414      	ld.w      	r0, (r4, 0x50)
  c8:	3600      	movi      	r6, 0
  ca:	e0000000 	bsr      	0x0	// 0 <_os_free>
  ce:	b4d4      	st.w      	r6, (r4, 0x50)
  d0:	9413      	ld.w      	r0, (r4, 0x4c)
  d2:	e0000000 	bsr      	0x0	// 0 <_os_free>
  d6:	b4d3      	st.w      	r6, (r4, 0x4c)
  d8:	6c17      	mov      	r0, r5
  da:	1402      	addi      	r14, r14, 8
  dc:	1495      	pop      	r4-r8, r15
  de:	9408      	ld.w      	r0, (r4, 0x20)
  e0:	e0000000 	bsr      	0x0	// 0 <hg_gmac_open>
  e4:	e4040043 	addi      	r0, r4, 68
  e8:	e0000000 	bsr      	0x0	// 0 <hg_gmac_open>
  ec:	9448      	ld.w      	r2, (r4, 0x20)
  ee:	9436      	ld.w      	r1, (r4, 0x58)
  f0:	b226      	st.w      	r1, (r2, 0x18)
  f2:	6c03      	mov      	r0, r0
  f4:	9479      	ld.w      	r3, (r4, 0x64)
  f6:	b268      	st.w      	r3, (r2, 0x20)
  f8:	6c03      	mov      	r0, r0
  fa:	b431      	st.w      	r1, (r4, 0x44)
  fc:	3180      	movi      	r1, 128
  fe:	b472      	st.w      	r3, (r4, 0x48)
 100:	b22c      	st.w      	r1, (r2, 0x30)
 102:	6c03      	mov      	r0, r0
 104:	32c0      	movi      	r2, 192
 106:	9302      	ld.w      	r0, (r3, 0x8)
 108:	31ff      	movi      	r1, 255
 10a:	e0000000 	bsr      	0x0	// 0 <memset>
 10e:	9472      	ld.w      	r3, (r4, 0x48)
 110:	3201      	movi      	r2, 1
 112:	9321      	ld.w      	r1, (r3, 0x4)
 114:	c4225c1f 	ins      	r1, r2, 31, 31
 118:	b321      	st.w      	r1, (r3, 0x4)
 11a:	9321      	ld.w      	r1, (r3, 0x4)
 11c:	c4255c1d 	ins      	r1, r5, 29, 29
 120:	b321      	st.w      	r1, (r3, 0x4)
 122:	9321      	ld.w      	r1, (r3, 0x4)
 124:	c4255c1e 	ins      	r1, r5, 30, 30
 128:	b321      	st.w      	r1, (r3, 0x4)
 12a:	9321      	ld.w      	r1, (r3, 0x4)
 12c:	c4225c1c 	ins      	r1, r2, 28, 28
 130:	b321      	st.w      	r1, (r3, 0x4)
 132:	9321      	ld.w      	r1, (r3, 0x4)
 134:	c4255c16 	ins      	r1, r5, 22, 22
 138:	b321      	st.w      	r1, (r3, 0x4)
 13a:	9321      	ld.w      	r1, (r3, 0x4)
 13c:	c4225c1b 	ins      	r1, r2, 27, 27
 140:	b321      	st.w      	r1, (r3, 0x4)
 142:	9321      	ld.w      	r1, (r3, 0x4)
 144:	30c0      	movi      	r0, 192
 146:	c4205d40 	ins      	r1, r0, 10, 0
 14a:	b321      	st.w      	r1, (r3, 0x4)
 14c:	9320      	ld.w      	r1, (r3, 0x0)
 14e:	c4225c1f 	ins      	r1, r2, 31, 31
 152:	b320      	st.w      	r1, (r3, 0x0)
 154:	9363      	ld.w      	r3, (r3, 0xc)
 156:	b472      	st.w      	r3, (r4, 0x48)
 158:	9468      	ld.w      	r3, (r4, 0x20)
 15a:	ea0280c0 	movi      	r2, 32960
 15e:	3ab0      	bseti      	r2, 16
 160:	b34e      	st.w      	r2, (r3, 0x38)
 162:	6c03      	mov      	r0, r0
 164:	9409      	ld.w      	r0, (r4, 0x24)
 166:	e900005f 	bez      	r0, 0x224	// 224 <hg_gmac_open+0x224>
 16a:	e0000000 	bsr      	0x0	// 0 <dev_get>
 16e:	6d43      	mov      	r5, r0
 170:	e9200008 	bnez      	r0, 0x180	// 180 <hg_gmac_open+0x180>
 174:	1158      	lrw      	r2, 0x0	// 254 <hg_gmac_open+0x254>
 176:	ea010503 	movi      	r1, 1283
 17a:	1115      	lrw      	r0, 0x0	// 24c <assert_internal+0x24c>
 17c:	e0000000 	bsr      	0x0	// 0 <assert_internal>
 180:	6c53      	mov      	r1, r4
 182:	6c17      	mov      	r0, r5
 184:	e0000000 	bsr      	0x0	// 0 <eth_mdio_bus_open>
 188:	e9000008 	bez      	r0, 0x198	// 198 <hg_gmac_open+0x198>
 18c:	1153      	lrw      	r2, 0x0	// 258 <hg_gmac_open+0x258>
 18e:	ea010505 	movi      	r1, 1285
 192:	110f      	lrw      	r0, 0x0	// 24c <assert_internal+0x24c>
 194:	e0000000 	bsr      	0x0	// 0 <assert_internal>
 198:	940a      	ld.w      	r0, (r4, 0x28)
 19a:	e900001a 	bez      	r0, 0x1ce	// 1ce <hg_gmac_open+0x1ce>
 19e:	e0000000 	bsr      	0x0	// 0 <dev_get>
 1a2:	6e03      	mov      	r8, r0
 1a4:	e9200008 	bnez      	r0, 0x1b4	// 1b4 <hg_gmac_open+0x1b4>
 1a8:	114d      	lrw      	r2, 0x0	// 25c <hg_gmac_open+0x25c>
 1aa:	ea01050a 	movi      	r1, 1290
 1ae:	1108      	lrw      	r0, 0x0	// 24c <assert_internal+0x24c>
 1b0:	e0000000 	bsr      	0x0	// 0 <assert_internal>
 1b4:	6c93      	mov      	r2, r4
 1b6:	6c57      	mov      	r1, r5
 1b8:	6c23      	mov      	r0, r8
 1ba:	e0000000 	bsr      	0x0	// 0 <eth_phy_open>
 1be:	e9000008 	bez      	r0, 0x1ce	// 1ce <hg_gmac_open+0x1ce>
 1c2:	1146      	lrw      	r2, 0x0	// 258 <hg_gmac_open+0x258>
 1c4:	ea01050c 	movi      	r1, 1292
 1c8:	1101      	lrw      	r0, 0x0	// 24c <assert_internal+0x24c>
 1ca:	e0000000 	bsr      	0x0	// 0 <assert_internal>
 1ce:	940b      	ld.w      	r0, (r4, 0x2c)
 1d0:	e9000005 	bez      	r0, 0x1da	// 1da <hg_gmac_open+0x1da>
 1d4:	e0000000 	bsr      	0x0	// 0 <dev_get>
 1d8:	b40c      	st.w      	r0, (r4, 0x30)
 1da:	6c93      	mov      	r2, r4
 1dc:	1121      	lrw      	r1, 0x0	// 260 <hg_gmac_open+0x260>
 1de:	940f      	ld.w      	r0, (r4, 0x3c)
 1e0:	e0000000 	bsr      	0x0	// 0 <request_irq>
 1e4:	6d43      	mov      	r5, r0
 1e6:	e920ff70 	bnez      	r0, 0xc6	// c6 <hg_gmac_open+0xc6>
 1ea:	946f      	ld.w      	r3, (r4, 0x3c)
 1ec:	c4a354c0 	zext      	r0, r3, 6, 5
 1f0:	3201      	movi      	r2, 1
 1f2:	e463201f 	andi      	r3, r3, 31
 1f6:	c4624023 	lsl      	r3, r2, r3
 1fa:	103b      	lrw      	r1, 0xe000e100	// 264 <hg_gmac_open+0x264>
 1fc:	e4a4006b 	addi      	r5, r4, 108
 200:	d4010883 	str.w      	r3, (r1, r0 << 2)
 204:	b450      	st.w      	r2, (r4, 0x40)
 206:	6c7b      	mov      	r1, r14
 208:	3206      	movi      	r2, 6
 20a:	6c17      	mov      	r0, r5
 20c:	e0000000 	bsr      	0x0	// 0 <memcmp>
 210:	e9000006 	bez      	r0, 0x21c	// 21c <hg_gmac_open+0x21c>
 214:	6c57      	mov      	r1, r5
 216:	6c13      	mov      	r0, r4
 218:	e0000000 	bsr      	0x0	// 0 <hg_gmac_open>
 21c:	e9260006 	bnez      	r6, 0x228	// 228 <hg_gmac_open+0x228>
 220:	3500      	movi      	r5, 0
 222:	075b      	br      	0xd8	// d8 <hg_gmac_open+0xd8>
 224:	6d43      	mov      	r5, r0
 226:	07b9      	br      	0x198	// 198 <hg_gmac_open+0x198>
 228:	c0006023 	mfcr      	r3, cr<0, 0>
 22c:	c0807020 	psrclr      	ie
 230:	e4632040 	andi      	r3, r3, 64
 234:	b4dd      	st.w      	r6, (r4, 0x74)
 236:	b4fe      	st.w      	r7, (r4, 0x78)
 238:	e903fff4 	bez      	r3, 0x220	// 220 <hg_gmac_open+0x220>
 23c:	c0807420 	psrset      	ie
 240:	07f0      	br      	0x220	// 220 <hg_gmac_open+0x220>
	...
 262:	0000      	.short	0x0000
 264:	e000e100 	.long	0xe000e100

Disassembly of section .text.hg_gmac_irq_handler:

00000000 <hg_gmac_irq_handler>:
   0:	14d0      	push      	r15
   2:	9068      	ld.w      	r3, (r0, 0x20)
   4:	934a      	ld.w      	r2, (r3, 0x28)
   6:	6c03      	mov      	r0, r0
   8:	e44220c0 	andi      	r2, r2, 192
   c:	e902000b 	bez      	r2, 0x22	// 22 <hg_gmac_irq_handler+0x22>
  10:	1045      	lrw      	r2, 0xfffe7f3f	// 24 <hg_gmac_irq_handler+0x24>
  12:	b34e      	st.w      	r2, (r3, 0x38)
  14:	6c03      	mov      	r0, r0
  16:	3240      	movi      	r2, 64
  18:	b34a      	st.w      	r2, (r3, 0x28)
  1a:	6c03      	mov      	r0, r0
  1c:	20a3      	addi      	r0, 164
  1e:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  22:	1490      	pop      	r15
  24:	fffe7f3f 	.long	0xfffe7f3f

Disassembly of section .text.hg_gmac_ioctl:

00000000 <hg_gmac_ioctl>:
   0:	14d0      	push      	r15
   2:	3904      	cmphsi      	r1, 5
   4:	6ccb      	mov      	r3, r2
   6:	084f      	bt      	0xa4	// a4 <hg_gmac_ioctl+0xa4>
   8:	1042      	lrw      	r2, 0x0	// 10 <hg_gmac_ioctl+0x10>
   a:	d0220882 	ldr.w      	r2, (r2, r1 << 2)
   e:	7808      	jmp      	r2
  10:	00000000 	.long	0x00000000
  14:	e420006b 	addi      	r1, r0, 108
  18:	3206      	movi      	r2, 6
  1a:	6c0f      	mov      	r0, r3
  1c:	e0000000 	bsr      	0x0	// 0 <memcpy>
  20:	3000      	movi      	r0, 0
  22:	0404      	br      	0x2a	// 2a <hg_gmac_ioctl+0x2a>
  24:	6c4f      	mov      	r1, r3
  26:	e0000000 	bsr      	0x0	// 0 <hg_gmac_ioctl>
  2a:	1490      	pop      	r15
  2c:	d8002026 	ld.w      	r0, (r0, 0x98)
  30:	07fd      	br      	0x2a	// 2a <hg_gmac_ioctl+0x2a>
  32:	d8002028 	ld.w      	r0, (r0, 0xa0)
  36:	07fa      	br      	0x2a	// 2a <hg_gmac_ioctl+0x2a>
  38:	9050      	ld.w      	r2, (r0, 0x40)
  3a:	e9020039 	bez      	r2, 0xac	// ac <hg_gmac_ioctl+0xac>
  3e:	3b4a      	cmpnei      	r3, 10
  40:	0c04      	bf      	0x48	// 48 <hg_gmac_ioctl+0x48>
  42:	eb430064 	cmpnei      	r3, 100
  46:	0833      	bt      	0xac	// ac <hg_gmac_ioctl+0xac>
  48:	9048      	ld.w      	r2, (r0, 0x20)
  4a:	922c      	ld.w      	r1, (r2, 0x30)
  4c:	3981      	bclri      	r1, 1
  4e:	398d      	bclri      	r1, 13
  50:	6c03      	mov      	r0, r0
  52:	b22c      	st.w      	r1, (r2, 0x30)
  54:	6c03      	mov      	r0, r0
  56:	922a      	ld.w      	r1, (r2, 0x28)
  58:	6c03      	mov      	r0, r0
  5a:	c68156cc 	zext      	r12, r1, 22, 20
  5e:	e92cfffc 	bnez      	r12, 0x56	// 56 <hg_gmac_ioctl+0x56>
  62:	c6215661 	zext      	r1, r1, 19, 17
  66:	e921fff8 	bnez      	r1, 0x56	// 56 <hg_gmac_ioctl+0x56>
  6a:	922c      	ld.w      	r1, (r2, 0x30)
  6c:	6c03      	mov      	r0, r0
  6e:	3b4a      	cmpnei      	r3, 10
  70:	0c04      	bf      	0x78	// 78 <hg_gmac_ioctl+0x78>
  72:	eb430064 	cmpnei      	r3, 100
  76:	081b      	bt      	0xac	// ac <hg_gmac_ioctl+0xac>
  78:	922c      	ld.w      	r1, (r2, 0x30)
  7a:	ec212002 	ori      	r1, r1, 8194
  7e:	6c03      	mov      	r0, r0
  80:	b22c      	st.w      	r1, (r2, 0x30)
  82:	6c03      	mov      	r0, r0
  84:	31c1      	movi      	r1, 193
  86:	4121      	lsli      	r1, r1, 1
  88:	b22a      	st.w      	r1, (r2, 0x28)
  8a:	6c03      	mov      	r0, r0
  8c:	3201      	movi      	r2, 1
  8e:	dc602026 	st.w      	r3, (r0, 0x98)
  92:	dc402028 	st.w      	r2, (r0, 0xa0)
  96:	6c4f      	mov      	r1, r3
  98:	ea00ffff 	movi      	r0, 65535
  9c:	2001      	addi      	r0, 2
  9e:	e0000000 	bsr      	0x0	// 0 <sys_event_new>
  a2:	07bf      	br      	0x20	// 20 <hg_gmac_ioctl+0x20>
  a4:	ea00020b 	movi      	r0, 523
  a8:	6c02      	nor      	r0, r0
  aa:	07c0      	br      	0x2a	// 2a <hg_gmac_ioctl+0x2a>
  ac:	3000      	movi      	r0, 0
  ae:	2800      	subi      	r0, 1
  b0:	07bd      	br      	0x2a	// 2a <hg_gmac_ioctl+0x2a>

Disassembly of section .text.hg_gmac_send_data:

00000000 <hg_gmac_send_data>:
   0:	14d4      	push      	r4-r7, r15
   2:	eb0205ea 	cmphsi      	r2, 1515
   6:	6d43      	mov      	r5, r0
   8:	6dc7      	mov      	r7, r1
   a:	6d0b      	mov      	r4, r2
   c:	085b      	bt      	0xc2	// c2 <hg_gmac_send_data+0xc2>
   e:	d8602028 	ld.w      	r3, (r0, 0xa0)
  12:	3b41      	cmpnei      	r3, 1
  14:	0857      	bt      	0xc2	// c2 <hg_gmac_send_data+0xc2>
  16:	e902004b 	bez      	r2, 0xac	// ac <hg_gmac_send_data+0xac>
  1a:	e4c000b3 	addi      	r6, r0, 180
  1e:	3100      	movi      	r1, 0
  20:	2900      	subi      	r1, 1
  22:	6c1b      	mov      	r0, r6
  24:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  28:	3180      	movi      	r1, 128
  2a:	9572      	ld.w      	r3, (r5, 0x48)
  2c:	4126      	lsli      	r1, r1, 6
  2e:	9340      	ld.w      	r2, (r3, 0x0)
  30:	4a5f      	lsri      	r2, r2, 31
  32:	e922003f 	bnez      	r2, 0xb0	// b0 <hg_gmac_send_data+0xb0>
  36:	9321      	ld.w      	r1, (r3, 0x4)
  38:	c7615761 	zext      	r1, r1, 27, 27
  3c:	e9010017 	bez      	r1, 0x6a	// 6a <hg_gmac_send_data+0x6a>
  40:	9321      	ld.w      	r1, (r3, 0x4)
  42:	c4225c1b 	ins      	r1, r2, 27, 27
  46:	b321      	st.w      	r1, (r3, 0x4)
  48:	9321      	ld.w      	r1, (r3, 0x4)
  4a:	c4225c1c 	ins      	r1, r2, 28, 28
  4e:	b321      	st.w      	r1, (r3, 0x4)
  50:	9321      	ld.w      	r1, (r3, 0x4)
  52:	c4225c16 	ins      	r1, r2, 22, 22
  56:	b321      	st.w      	r1, (r3, 0x4)
  58:	9341      	ld.w      	r2, (r3, 0x4)
  5a:	3101      	movi      	r1, 1
  5c:	c4415c1d 	ins      	r2, r1, 29, 29
  60:	b341      	st.w      	r2, (r3, 0x4)
  62:	9341      	ld.w      	r2, (r3, 0x4)
  64:	c4415c1e 	ins      	r2, r1, 30, 30
  68:	b341      	st.w      	r2, (r3, 0x4)
  6a:	9302      	ld.w      	r0, (r3, 0x8)
  6c:	6c93      	mov      	r2, r4
  6e:	6c5f      	mov      	r1, r7
  70:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
  74:	9572      	ld.w      	r3, (r5, 0x48)
  76:	3101      	movi      	r1, 1
  78:	9341      	ld.w      	r2, (r3, 0x4)
  7a:	c4445d40 	ins      	r2, r4, 10, 0
  7e:	b341      	st.w      	r2, (r3, 0x4)
  80:	9341      	ld.w      	r2, (r3, 0x4)
  82:	c4415c1f 	ins      	r2, r1, 31, 31
  86:	b341      	st.w      	r2, (r3, 0x4)
  88:	9340      	ld.w      	r2, (r3, 0x0)
  8a:	c4415c1f 	ins      	r2, r1, 31, 31
  8e:	b340      	st.w      	r2, (r3, 0x0)
  90:	9363      	ld.w      	r3, (r3, 0xc)
  92:	b572      	st.w      	r3, (r5, 0x48)
  94:	9568      	ld.w      	r3, (r5, 0x20)
  96:	3400      	movi      	r4, 0
  98:	b382      	st.w      	r4, (r3, 0x8)
  9a:	6c03      	mov      	r0, r0
  9c:	d865202f 	ld.w      	r3, (r5, 0xbc)
  a0:	60c4      	addu      	r3, r1
  a2:	dc65202f 	st.w      	r3, (r5, 0xbc)
  a6:	6c1b      	mov      	r0, r6
  a8:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  ac:	6c13      	mov      	r0, r4
  ae:	040c      	br      	0xc6	// c6 <hg_gmac_send_data+0xc6>
  b0:	9548      	ld.w      	r2, (r5, 0x20)
  b2:	924c      	ld.w      	r2, (r2, 0x30)
  b4:	6c03      	mov      	r0, r0
  b6:	6884      	and      	r2, r1
  b8:	e922ffbb 	bnez      	r2, 0x2e	// 2e <hg_gmac_send_data+0x2e>
  bc:	6c1b      	mov      	r0, r6
  be:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  c2:	3000      	movi      	r0, 0
  c4:	2800      	subi      	r0, 1
  c6:	1494      	pop      	r4-r7, r15

Disassembly of section .text.hg_gmac_close:

00000000 <hg_gmac_close>:
   0:	14d3      	push      	r4-r6, r15
   2:	9070      	ld.w      	r3, (r0, 0x40)
   4:	6d03      	mov      	r4, r0
   6:	e903005c 	bez      	r3, 0xbe	// be <hg_gmac_close+0xbe>
   a:	900a      	ld.w      	r0, (r0, 0x28)
   c:	e9000010 	bez      	r0, 0x2c	// 2c <hg_gmac_close+0x2c>
  10:	e0000000 	bsr      	0x0	// 0 <dev_get>
  14:	6d43      	mov      	r5, r0
  16:	e9200008 	bnez      	r0, 0x26	// 26 <hg_gmac_close+0x26>
  1a:	114b      	lrw      	r2, 0x0	// c4 <hg_gmac_close+0xc4>
  1c:	ea01053d 	movi      	r1, 1341
  20:	110a      	lrw      	r0, 0x0	// c8 <assert_internal+0xc8>
  22:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  26:	6c17      	mov      	r0, r5
  28:	e0000000 	bsr      	0x0	// 0 <eth_phy_close>
  2c:	9409      	ld.w      	r0, (r4, 0x24)
  2e:	e9000018 	bez      	r0, 0x5e	// 5e <hg_gmac_close+0x5e>
  32:	e0000000 	bsr      	0x0	// 0 <dev_get>
  36:	6d43      	mov      	r5, r0
  38:	e9200008 	bnez      	r0, 0x48	// 48 <hg_gmac_close+0x48>
  3c:	1144      	lrw      	r2, 0x0	// cc <hg_gmac_close+0xcc>
  3e:	ea010544 	movi      	r1, 1348
  42:	1102      	lrw      	r0, 0x0	// c8 <assert_internal+0xc8>
  44:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  48:	6c17      	mov      	r0, r5
  4a:	e0000000 	bsr      	0x0	// 0 <eth_mdio_bus_close>
  4e:	e9000008 	bez      	r0, 0x5e	// 5e <hg_gmac_close+0x5e>
  52:	1140      	lrw      	r2, 0x0	// d0 <hg_gmac_close+0xd0>
  54:	ea010546 	movi      	r1, 1350
  58:	101c      	lrw      	r0, 0x0	// c8 <assert_internal+0xc8>
  5a:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  5e:	940f      	ld.w      	r0, (r4, 0x3c)
  60:	e0000000 	bsr      	0x0	// 0 <hg_gmac_close>
  64:	9468      	ld.w      	r3, (r4, 0x20)
  66:	3200      	movi      	r2, 0
  68:	b34c      	st.w      	r2, (r3, 0x30)
  6a:	6c03      	mov      	r0, r0
  6c:	934a      	ld.w      	r2, (r3, 0x28)
  6e:	c68256c2 	zext      	r2, r2, 22, 20
  72:	e922fffc 	bnez      	r2, 0x6a	// 6a <hg_gmac_close+0x6a>
  76:	6c03      	mov      	r0, r0
  78:	93ac      	ld.w      	r5, (r3, 0x30)
  7a:	c6255665 	zext      	r5, r5, 19, 17
  7e:	e925fffc 	bnez      	r5, 0x76	// 76 <hg_gmac_close+0x76>
  82:	6c03      	mov      	r0, r0
  84:	10d4      	lrw      	r6, 0x40026000	// d4 <hg_gmac_close+0xd4>
  86:	3001      	movi      	r0, 1
  88:	9662      	ld.w      	r3, (r6, 0x8)
  8a:	3b9d      	bclri      	r3, 29
  8c:	b662      	st.w      	r3, (r6, 0x8)
  8e:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  92:	9662      	ld.w      	r3, (r6, 0x8)
  94:	3bbd      	bseti      	r3, 29
  96:	b662      	st.w      	r3, (r6, 0x8)
  98:	3001      	movi      	r0, 1
  9a:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  9e:	9413      	ld.w      	r0, (r4, 0x4c)
  a0:	e0000000 	bsr      	0x0	// 0 <_os_free>
  a4:	9414      	ld.w      	r0, (r4, 0x50)
  a6:	b4b3      	st.w      	r5, (r4, 0x4c)
  a8:	e0000000 	bsr      	0x0	// 0 <_os_free>
  ac:	b4b4      	st.w      	r5, (r4, 0x50)
  ae:	b4b0      	st.w      	r5, (r4, 0x40)
  b0:	6c57      	mov      	r1, r5
  b2:	9400      	ld.w      	r0, (r4, 0x0)
  b4:	e0000000 	bsr      	0x0	// 0 <pin_func>
  b8:	9666      	ld.w      	r3, (r6, 0x18)
  ba:	3b91      	bclri      	r3, 17
  bc:	b666      	st.w      	r3, (r6, 0x18)
  be:	3000      	movi      	r0, 0
  c0:	1493      	pop      	r4-r6, r15
	...
  d2:	0000      	.short	0x0000
  d4:	40026000 	.long	0x40026000

Disassembly of section .text.gmac_csr_dv_disable:

00000000 <gmac_csr_dv_disable>:
   0:	783c      	jmp      	r15

Disassembly of section .text.gmac_csr_dv_enable:

00000000 <gmac_csr_dv_enable>:
   0:	783c      	jmp      	r15

Disassembly of section .text.hg_gmac_ru_handler:

00000000 <hg_gmac_ru_handler>:
   0:	14d1      	push      	r4, r15
   2:	9048      	ld.w      	r2, (r0, 0x20)
   4:	6d03      	mov      	r4, r0
   6:	926a      	ld.w      	r3, (r2, 0x28)
   8:	6c03      	mov      	r0, r0
   a:	e4632080 	andi      	r3, r3, 128
   e:	e9030029 	bez      	r3, 0x60	// 60 <hg_gmac_ru_handler+0x60>
  12:	3380      	movi      	r3, 128
  14:	b26a      	st.w      	r3, (r2, 0x28)
  16:	6c03      	mov      	r0, r0
  18:	d8602031 	ld.w      	r3, (r0, 0xc4)
  1c:	2300      	addi      	r3, 1
  1e:	dc602031 	st.w      	r3, (r0, 0xc4)
  22:	9000      	ld.w      	r0, (r0, 0x0)
  24:	e0000000 	bsr      	0x0	// 0 <hg_gmac_ru_handler>
  28:	9468      	ld.w      	r3, (r4, 0x20)
  2a:	936c      	ld.w      	r3, (r3, 0x30)
  2c:	6c03      	mov      	r0, r0
  2e:	3280      	movi      	r2, 128
  30:	424a      	lsli      	r2, r2, 10
  32:	68c8      	and      	r3, r2
  34:	e9030017 	bez      	r3, 0x62	// 62 <hg_gmac_ru_handler+0x62>
  38:	3005      	movi      	r0, 5
  3a:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  3e:	9468      	ld.w      	r3, (r4, 0x20)
  40:	3200      	movi      	r2, 0
  42:	b344      	st.w      	r2, (r3, 0x10)
  44:	6c03      	mov      	r0, r0
  46:	936c      	ld.w      	r3, (r3, 0x30)
  48:	6c03      	mov      	r0, r0
  4a:	3280      	movi      	r2, 128
  4c:	424a      	lsli      	r2, r2, 10
  4e:	68c8      	and      	r3, r2
  50:	e903000b 	bez      	r3, 0x66	// 66 <hg_gmac_ru_handler+0x66>
  54:	3005      	movi      	r0, 5
  56:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  5a:	9400      	ld.w      	r0, (r4, 0x0)
  5c:	e0000000 	bsr      	0x0	// 0 <hg_gmac_ru_handler>
  60:	1491      	pop      	r4, r15
  62:	3001      	movi      	r0, 1
  64:	07eb      	br      	0x3a	// 3a <hg_gmac_ru_handler+0x3a>
  66:	3001      	movi      	r0, 1
  68:	07f7      	br      	0x56	// 56 <hg_gmac_ru_handler+0x56>

Disassembly of section .text.hg_gmac_has_received_frame:

00000000 <hg_gmac_has_received_frame>:
   0:	9071      	ld.w      	r3, (r0, 0x44)
   2:	d8434003 	ld.bs      	r2, (r3, 0x3)
   6:	e9820009 	blz      	r2, 0x18	// 18 <hg_gmac_has_received_frame+0x18>
   a:	8341      	ld.b      	r2, (r3, 0x1)
   c:	e4422001 	andi      	r2, r2, 1
  10:	e9220007 	bnez      	r2, 0x1e	// 1e <hg_gmac_has_received_frame+0x1e>
  14:	9363      	ld.w      	r3, (r3, 0xc)
  16:	07f6      	br      	0x2	// 2 <hg_gmac_has_received_frame+0x2>
  18:	3000      	movi      	r0, 0
  1a:	2800      	subi      	r0, 1
  1c:	783c      	jmp      	r15
  1e:	3000      	movi      	r0, 0
  20:	07fe      	br      	0x1c	// 1c <hg_gmac_has_received_frame+0x1c>

Disassembly of section .text.hg_gmac_receive_data:

00000000 <hg_gmac_receive_data>:
   0:	14d3      	push      	r4-r6, r15
   2:	d8602030 	ld.w      	r3, (r0, 0xc0)
   6:	90d1      	ld.w      	r6, (r0, 0x44)
   8:	2300      	addi      	r3, 1
   a:	6d03      	mov      	r4, r0
   c:	dc602030 	st.w      	r3, (r0, 0xc0)
  10:	6d5b      	mov      	r5, r6
  12:	3101      	movi      	r1, 1
  14:	8541      	ld.b      	r2, (r5, 0x1)
  16:	e4622001 	andi      	r3, r2, 1
  1a:	e9230008 	bnez      	r3, 0x2a	// 2a <hg_gmac_receive_data+0x2a>
  1e:	95a3      	ld.w      	r5, (r5, 0xc)
  20:	8563      	ld.b      	r3, (r5, 0x3)
  22:	c4615c07 	ins      	r3, r1, 7, 7
  26:	a563      	st.b      	r3, (r5, 0x3)
  28:	07f6      	br      	0x14	// 14 <hg_gmac_receive_data+0x14>
  2a:	c0006023 	mfcr      	r3, cr<0, 0>
  2e:	c0807020 	psrclr      	ie
  32:	e4632040 	andi      	r3, r3, 64
  36:	e9030004 	bez      	r3, 0x3e	// 3e <hg_gmac_receive_data+0x3e>
  3a:	c0807420 	psrset      	ie
  3e:	748a      	sextb      	r2, r2
  40:	e982000f 	blz      	r2, 0x5e	// 5e <hg_gmac_receive_data+0x5e>
  44:	d984201d 	ld.w      	r12, (r4, 0x74)
  48:	e90c000b 	bez      	r12, 0x5e	// 5e <hg_gmac_receive_data+0x5e>
  4c:	ea033fff 	movi      	r3, 16383
  50:	8d41      	ld.h      	r2, (r5, 0x2)
  52:	688c      	and      	r2, r3
  54:	2a03      	subi      	r2, 4
  56:	947e      	ld.w      	r3, (r4, 0x78)
  58:	9622      	ld.w      	r1, (r6, 0x8)
  5a:	6c13      	mov      	r0, r4
  5c:	7bf1      	jsr      	r12
  5e:	8663      	ld.b      	r3, (r6, 0x3)
  60:	3201      	movi      	r2, 1
  62:	c4625c07 	ins      	r3, r2, 7, 7
  66:	a663      	st.b      	r3, (r6, 0x3)
  68:	9563      	ld.w      	r3, (r5, 0xc)
  6a:	6c13      	mov      	r0, r4
  6c:	b471      	st.w      	r3, (r4, 0x44)
  6e:	e0000000 	bsr      	0x0	// 0 <hg_gmac_receive_data>
  72:	3000      	movi      	r0, 0
  74:	1493      	pop      	r4-r6, r15

Disassembly of section .text.hg_gmac_receive_frame_thread:

00000000 <hg_gmac_receive_frame_thread>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	e4c000a3 	addi      	r6, r0, 164
   8:	3540      	movi      	r5, 64
   a:	3100      	movi      	r1, 0
   c:	2900      	subi      	r1, 1
   e:	6c1b      	mov      	r0, r6
  10:	e0000000 	bsr      	0x0	// 0 <os_sema_down>
  14:	6c13      	mov      	r0, r4
  16:	e0000000 	bsr      	0x0	// 0 <hg_gmac_receive_frame_thread>
  1a:	e900000e 	bez      	r0, 0x36	// 36 <hg_gmac_receive_frame_thread+0x36>
  1e:	6c13      	mov      	r0, r4
  20:	e0000000 	bsr      	0x0	// 0 <hg_gmac_receive_frame_thread>
  24:	9468      	ld.w      	r3, (r4, 0x20)
  26:	b3aa      	st.w      	r5, (r3, 0x28)
  28:	6c03      	mov      	r0, r0
  2a:	ea0280c0 	movi      	r2, 32960
  2e:	3ab0      	bseti      	r2, 16
  30:	b34e      	st.w      	r2, (r3, 0x38)
  32:	6c03      	mov      	r0, r0
  34:	07eb      	br      	0xa	// a <hg_gmac_receive_frame_thread+0xa>
  36:	6c13      	mov      	r0, r4
  38:	e0000000 	bsr      	0x0	// 0 <hg_gmac_receive_frame_thread>
  3c:	07ec      	br      	0x14	// 14 <hg_gmac_receive_frame_thread+0x14>

Disassembly of section .text.hg_gmac_reset:

00000000 <hg_gmac_reset>:
   0:	14d4      	push      	r4-r7, r15
   2:	1422      	subi      	r14, r14, 8
   4:	6d03      	mov      	r4, r0
   6:	3206      	movi      	r2, 6
   8:	113d      	lrw      	r1, 0x0	// fc <hg_gmac_reset+0xfc>
   a:	6c3b      	mov      	r0, r14
   c:	e0000000 	bsr      	0x0	// 0 <memcpy>
  10:	9400      	ld.w      	r0, (r4, 0x0)
  12:	e0000000 	bsr      	0x0	// 0 <hg_gmac_reset>
  16:	9468      	ld.w      	r3, (r4, 0x20)
  18:	936c      	ld.w      	r3, (r3, 0x30)
  1a:	6c03      	mov      	r0, r0
  1c:	3280      	movi      	r2, 128
  1e:	424a      	lsli      	r2, r2, 10
  20:	68c8      	and      	r3, r2
  22:	e9030065 	bez      	r3, 0xec	// ec <hg_gmac_reset+0xec>
  26:	3005      	movi      	r0, 5
  28:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  2c:	940f      	ld.w      	r0, (r4, 0x3c)
  2e:	e0000000 	bsr      	0x0	// 0 <hg_gmac_reset>
  32:	9408      	ld.w      	r0, (r4, 0x20)
  34:	e0000000 	bsr      	0x0	// 0 <hg_gmac_reset>
  38:	e4040043 	addi      	r0, r4, 68
  3c:	e0000000 	bsr      	0x0	// 0 <hg_gmac_reset>
  40:	9468      	ld.w      	r3, (r4, 0x20)
  42:	9456      	ld.w      	r2, (r4, 0x58)
  44:	b346      	st.w      	r2, (r3, 0x18)
  46:	6c03      	mov      	r0, r0
  48:	94d9      	ld.w      	r6, (r4, 0x64)
  4a:	b3c8      	st.w      	r6, (r3, 0x20)
  4c:	6c03      	mov      	r0, r0
  4e:	b451      	st.w      	r2, (r4, 0x44)
  50:	3280      	movi      	r2, 128
  52:	b4d2      	st.w      	r6, (r4, 0x48)
  54:	b34c      	st.w      	r2, (r3, 0x30)
  56:	6c03      	mov      	r0, r0
  58:	e4e4006b 	addi      	r7, r4, 108
  5c:	3206      	movi      	r2, 6
  5e:	6c7b      	mov      	r1, r14
  60:	6c1f      	mov      	r0, r7
  62:	e0000000 	bsr      	0x0	// 0 <memcmp>
  66:	6d43      	mov      	r5, r0
  68:	e9200044 	bnez      	r0, 0xf0	// f0 <hg_gmac_reset+0xf0>
  6c:	32c0      	movi      	r2, 192
  6e:	31ff      	movi      	r1, 255
  70:	9602      	ld.w      	r0, (r6, 0x8)
  72:	e0000000 	bsr      	0x0	// 0 <memset>
  76:	9472      	ld.w      	r3, (r4, 0x48)
  78:	3201      	movi      	r2, 1
  7a:	9321      	ld.w      	r1, (r3, 0x4)
  7c:	c4225c1f 	ins      	r1, r2, 31, 31
  80:	b321      	st.w      	r1, (r3, 0x4)
  82:	9321      	ld.w      	r1, (r3, 0x4)
  84:	c4255c1d 	ins      	r1, r5, 29, 29
  88:	b321      	st.w      	r1, (r3, 0x4)
  8a:	9321      	ld.w      	r1, (r3, 0x4)
  8c:	c4255c1e 	ins      	r1, r5, 30, 30
  90:	b321      	st.w      	r1, (r3, 0x4)
  92:	9321      	ld.w      	r1, (r3, 0x4)
  94:	c4225c1c 	ins      	r1, r2, 28, 28
  98:	b321      	st.w      	r1, (r3, 0x4)
  9a:	9321      	ld.w      	r1, (r3, 0x4)
  9c:	c4255c16 	ins      	r1, r5, 22, 22
  a0:	b321      	st.w      	r1, (r3, 0x4)
  a2:	9321      	ld.w      	r1, (r3, 0x4)
  a4:	c4225c1b 	ins      	r1, r2, 27, 27
  a8:	b321      	st.w      	r1, (r3, 0x4)
  aa:	9321      	ld.w      	r1, (r3, 0x4)
  ac:	30c0      	movi      	r0, 192
  ae:	c4205d40 	ins      	r1, r0, 10, 0
  b2:	b321      	st.w      	r1, (r3, 0x4)
  b4:	9320      	ld.w      	r1, (r3, 0x0)
  b6:	c4225c1f 	ins      	r1, r2, 31, 31
  ba:	b320      	st.w      	r1, (r3, 0x0)
  bc:	9363      	ld.w      	r3, (r3, 0xc)
  be:	b472      	st.w      	r3, (r4, 0x48)
  c0:	9468      	ld.w      	r3, (r4, 0x20)
  c2:	ea0280c0 	movi      	r2, 32960
  c6:	3ab0      	bseti      	r2, 16
  c8:	b34e      	st.w      	r2, (r3, 0x38)
  ca:	6c03      	mov      	r0, r0
  cc:	946f      	ld.w      	r3, (r4, 0x3c)
  ce:	c4a354c1 	zext      	r1, r3, 6, 5
  d2:	3201      	movi      	r2, 1
  d4:	e463201f 	andi      	r3, r3, 31
  d8:	c4624023 	lsl      	r3, r2, r3
  dc:	1049      	lrw      	r2, 0xe000e100	// 100 <hg_gmac_reset+0x100>
  de:	d4220883 	str.w      	r3, (r2, r1 << 2)
  e2:	9400      	ld.w      	r0, (r4, 0x0)
  e4:	e0000000 	bsr      	0x0	// 0 <hg_gmac_reset>
  e8:	1402      	addi      	r14, r14, 8
  ea:	1494      	pop      	r4-r7, r15
  ec:	3001      	movi      	r0, 1
  ee:	079d      	br      	0x28	// 28 <hg_gmac_reset+0x28>
  f0:	6c5f      	mov      	r1, r7
  f2:	6c13      	mov      	r0, r4
  f4:	e0000000 	bsr      	0x0	// 0 <hg_gmac_reset>
  f8:	07e4      	br      	0xc0	// c0 <hg_gmac_reset+0xc0>
  fa:	0000      	.short	0x0000
  fc:	00000000 	.long	0x00000000
 100:	e000e100 	.long	0xe000e100

Disassembly of section .text.hg_gmac_phy_event:

00000000 <hg_gmac_phy_event>:
   0:	14d4      	push      	r4-r7, r15
   2:	1421      	subi      	r14, r14, 4
   4:	6d03      	mov      	r4, r0
   6:	e9210087 	bnez      	r1, 0x114	// 114 <hg_gmac_phy_event+0x114>
   a:	d8605016 	ld.hs      	r3, (r0, 0x2c)
   e:	90a6      	ld.w      	r5, (r0, 0x18)
  10:	e9030052 	bez      	r3, 0xb4	// b4 <hg_gmac_phy_event+0xb4>
  14:	9050      	ld.w      	r2, (r0, 0x40)
  16:	9069      	ld.w      	r3, (r0, 0x24)
  18:	64ca      	cmpne      	r2, r3
  1a:	0c4d      	bf      	0xb4	// b4 <hg_gmac_phy_event+0xb4>
  1c:	9548      	ld.w      	r2, (r5, 0x20)
  1e:	3300      	movi      	r3, 0
  20:	2b00      	subi      	r3, 1
  22:	dc601021 	st.h      	r3, (r0, 0x42)
  26:	926c      	ld.w      	r3, (r2, 0x30)
  28:	dc201020 	st.h      	r1, (r0, 0x40)
  2c:	3b81      	bclri      	r3, 1
  2e:	3b8d      	bclri      	r3, 13
  30:	6c03      	mov      	r0, r0
  32:	b26c      	st.w      	r3, (r2, 0x30)
  34:	6c03      	mov      	r0, r0
  36:	922a      	ld.w      	r1, (r2, 0x28)
  38:	6c03      	mov      	r0, r0
  3a:	4974      	lsri      	r3, r1, 20
  3c:	4931      	lsri      	r1, r1, 17
  3e:	6cc4      	or      	r3, r1
  40:	e4632007 	andi      	r3, r3, 7
  44:	e9230068 	bnez      	r3, 0x114	// 114 <hg_gmac_phy_event+0x114>
  48:	926c      	ld.w      	r3, (r2, 0x30)
  4a:	6c03      	mov      	r0, r0
  4c:	d9801013 	ld.h      	r12, (r0, 0x26)
  50:	7433      	sexth      	r0, r12
  52:	1134      	lrw      	r1, 0xfffcfdff	// 120 <hg_gmac_phy_event+0x120>
  54:	68c4      	and      	r3, r1
  56:	e9000004 	bez      	r0, 0x5e	// 5e <hg_gmac_phy_event+0x5e>
  5a:	ec630200 	ori      	r3, r3, 512
  5e:	d9a41012 	ld.h      	r13, (r4, 0x24)
  62:	7477      	sexth      	r1, r13
  64:	394a      	cmpnei      	r1, 10
  66:	0c59      	bf      	0x118	// 118 <hg_gmac_phy_event+0x118>
  68:	eb4103e8 	cmpnei      	r1, 1000
  6c:	0c58      	bf      	0x11c	// 11c <hg_gmac_phy_event+0x11c>
  6e:	b26c      	st.w      	r3, (r2, 0x30)
  70:	6c03      	mov      	r0, r0
  72:	926c      	ld.w      	r3, (r2, 0x30)
  74:	ec632002 	ori      	r3, r3, 8194
  78:	6c03      	mov      	r0, r0
  7a:	b26c      	st.w      	r3, (r2, 0x30)
  7c:	6c03      	mov      	r0, r0
  7e:	33c1      	movi      	r3, 193
  80:	4361      	lsli      	r3, r3, 1
  82:	b26a      	st.w      	r3, (r2, 0x28)
  84:	6c03      	mov      	r0, r0
  86:	3301      	movi      	r3, 1
  88:	dda41020 	st.h      	r13, (r4, 0x40)
  8c:	dd841021 	st.h      	r12, (r4, 0x42)
  90:	dc252026 	st.w      	r1, (r5, 0x98)
  94:	dc052027 	st.w      	r0, (r5, 0x9c)
  98:	dc652028 	st.w      	r3, (r5, 0xa0)
  9c:	ea00ffff 	movi      	r0, 65535
  a0:	2001      	addi      	r0, 2
  a2:	e0000000 	bsr      	0x0	// 0 <sys_event_new>
  a6:	d8445012 	ld.hs      	r2, (r4, 0x24)
  aa:	d8245013 	ld.hs      	r1, (r4, 0x26)
  ae:	101e      	lrw      	r0, 0x0	// 124 <hgprintf+0x124>
  b0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  b4:	8cf6      	ld.h      	r7, (r4, 0x2c)
  b6:	759f      	sexth      	r6, r7
  b8:	d8645022 	ld.hs      	r3, (r4, 0x44)
  bc:	658e      	cmpne      	r3, r6
  be:	0c2b      	bf      	0x114	// 114 <hg_gmac_phy_event+0x114>
  c0:	e9260027 	bnez      	r6, 0x10e	// 10e <hg_gmac_phy_event+0x10e>
  c4:	1019      	lrw      	r0, 0x0	// 128 <hgprintf+0x128>
  c6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ca:	9406      	ld.w      	r0, (r4, 0x18)
  cc:	3300      	movi      	r3, 0
  ce:	2b00      	subi      	r3, 1
  d0:	dc652027 	st.w      	r3, (r5, 0x9c)
  d4:	d820202f 	ld.w      	r1, (r0, 0xbc)
  d8:	dcc52028 	st.w      	r6, (r5, 0xa0)
  dc:	dcc52026 	st.w      	r6, (r5, 0x98)
  e0:	d8402030 	ld.w      	r2, (r0, 0xc0)
  e4:	dc641021 	st.h      	r3, (r4, 0x42)
  e8:	d8602032 	ld.w      	r3, (r0, 0xc8)
  ec:	d8002031 	ld.w      	r0, (r0, 0xc4)
  f0:	b800      	st.w      	r0, (r14, 0x0)
  f2:	dce41020 	st.h      	r7, (r4, 0x40)
  f6:	100e      	lrw      	r0, 0x0	// 12c <hgprintf+0x12c>
  f8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  fc:	9406      	ld.w      	r0, (r4, 0x18)
  fe:	e0000000 	bsr      	0x0	// 0 <hg_gmac_phy_event>
 102:	6c5b      	mov      	r1, r6
 104:	ea00ffff 	movi      	r0, 65535
 108:	2002      	addi      	r0, 3
 10a:	e0000000 	bsr      	0x0	// 0 <sys_event_new>
 10e:	8c76      	ld.h      	r3, (r4, 0x2c)
 110:	dc641022 	st.h      	r3, (r4, 0x44)
 114:	1401      	addi      	r14, r14, 4
 116:	1494      	pop      	r4-r7, r15
 118:	3bb1      	bseti      	r3, 17
 11a:	07aa      	br      	0x6e	// 6e <hg_gmac_phy_event+0x6e>
 11c:	3bb0      	bseti      	r3, 16
 11e:	07a8      	br      	0x6e	// 6e <hg_gmac_phy_event+0x6e>
 120:	fffcfdff 	.long	0xfffcfdff
	...

Disassembly of section .text.hg_gmac_attach:

00000000 <hg_gmac_attach>:
   0:	14d3      	push      	r4-r6, r15
   2:	1168      	lrw      	r3, 0x0	// a0 <hg_gmac_attach+0xa0>
   4:	6d07      	mov      	r4, r1
   6:	b162      	st.w      	r3, (r1, 0x8)
   8:	3300      	movi      	r3, 0
   a:	3500      	movi      	r5, 0
   c:	2b00      	subi      	r3, 1
   e:	dc612027 	st.w      	r3, (r1, 0x9c)
  12:	b1b0      	st.w      	r5, (r1, 0x40)
  14:	b1bd      	st.w      	r5, (r1, 0x74)
  16:	dca12026 	st.w      	r5, (r1, 0x98)
  1a:	dca12028 	st.w      	r5, (r1, 0xa0)
  1e:	3206      	movi      	r2, 6
  20:	31ff      	movi      	r1, 255
  22:	6d83      	mov      	r6, r0
  24:	e404006b 	addi      	r0, r4, 108
  28:	e0000000 	bsr      	0x0	// 0 <memset>
  2c:	3210      	movi      	r2, 16
  2e:	6c57      	mov      	r1, r5
  30:	e40400bb 	addi      	r0, r4, 188
  34:	e0000000 	bsr      	0x0	// 0 <memset>
  38:	6c57      	mov      	r1, r5
  3a:	e40400a3 	addi      	r0, r4, 164
  3e:	e0000000 	bsr      	0x0	// 0 <os_sema_init>
  42:	e40400ab 	addi      	r0, r4, 172
  46:	e0000000 	bsr      	0x0	// 0 <os_mutex_init>
  4a:	e4a40083 	addi      	r5, r4, 132
  4e:	e40400b3 	addi      	r0, r4, 180
  52:	e0000000 	bsr      	0x0	// 0 <os_mutex_init>
  56:	6cd3      	mov      	r3, r4
  58:	1053      	lrw      	r2, 0x0	// a4 <hg_gmac_attach+0xa4>
  5a:	6c57      	mov      	r1, r5
  5c:	1013      	lrw      	r0, 0x0	// a8 <hg_gmac_attach+0xa8>
  5e:	e0000000 	bsr      	0x0	// 0 <os_task_init>
  62:	3180      	movi      	r1, 128
  64:	4122      	lsli      	r1, r1, 2
  66:	6c17      	mov      	r0, r5
  68:	e0000000 	bsr      	0x0	// 0 <os_task_set_stacksize>
  6c:	3157      	movi      	r1, 87
  6e:	6c17      	mov      	r0, r5
  70:	e0000000 	bsr      	0x0	// 0 <_os_task_set_priority>
  74:	6c17      	mov      	r0, r5
  76:	e0000000 	bsr      	0x0	// 0 <os_task_run>
  7a:	940d      	ld.w      	r0, (r4, 0x34)
  7c:	e9000009 	bez      	r0, 0x8e	// 8e <hg_gmac_attach+0x8e>
  80:	3101      	movi      	r1, 1
  82:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  86:	3101      	movi      	r1, 1
  88:	940e      	ld.w      	r0, (r4, 0x38)
  8a:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  8e:	940f      	ld.w      	r0, (r4, 0x3c)
  90:	e0000000 	bsr      	0x0	// 0 <hg_gmac_attach>
  94:	6c53      	mov      	r1, r4
  96:	6c1b      	mov      	r0, r6
  98:	e0000000 	bsr      	0x0	// 0 <dev_register>
  9c:	3000      	movi      	r0, 0
  9e:	1493      	pop      	r4-r6, r15
	...
