
disasm/libcore/obj/slave_hgsdio20_slave.o:     file format elf32-csky-little


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

Disassembly of section .text.hgsdio20_slave_hw_init:

00000000 <hgsdio20_slave_hw_init>:
   0:	9063      	ld.w      	r3, (r0, 0xc)
   2:	e4400033 	addi      	r2, r0, 52
   6:	b342      	st.w      	r2, (r3, 0x8)
   8:	e4400044 	addi      	r2, r0, 69
   c:	b343      	st.w      	r2, (r3, 0xc)
   e:	3200      	movi      	r2, 0
  10:	b34c      	st.w      	r2, (r3, 0x30)
  12:	ea02ff80 	movi      	r2, 65408
  16:	c5024902 	rotli      	r2, r2, 8
  1a:	b34d      	st.w      	r2, (r3, 0x34)
  1c:	d8400032 	ld.b      	r2, (r0, 0x32)
  20:	3a05      	cmphsi      	r2, 6
  22:	102c      	lrw      	r1, 0xa007232	// 50 <hgsdio20_slave_hw_init+0x50>
  24:	104c      	lrw      	r2, 0xe007232	// 54 <hgsdio20_slave_hw_init+0x54>
  26:	c4410c20 	incf      	r2, r1, 0
  2a:	b349      	st.w      	r2, (r3, 0x24)
  2c:	3207      	movi      	r2, 7
  2e:	b34f      	st.w      	r2, (r3, 0x3c)
  30:	3288      	movi      	r2, 136
  32:	4258      	lsli      	r2, r2, 24
  34:	b355      	st.w      	r2, (r3, 0x54)
  36:	ea01049d 	movi      	r1, 1181
  3a:	3208      	movi      	r2, 8
  3c:	2a00      	subi      	r2, 1
  3e:	b32a      	st.w      	r1, (r3, 0x28)
  40:	e922fffe 	bnez      	r2, 0x3c	// 3c <hgsdio20_slave_hw_init+0x3c>
  44:	b357      	st.w      	r2, (r3, 0x5c)
  46:	3280      	movi      	r2, 128
  48:	4258      	lsli      	r2, r2, 24
  4a:	b356      	st.w      	r2, (r3, 0x58)
  4c:	783c      	jmp      	r15
  4e:	0000      	.short	0x0000
  50:	0a007232 	.long	0x0a007232
  54:	0e007232 	.long	0x0e007232

Disassembly of section .text.hgsdio20_slave_read:

00000000 <hgsdio20_slave_read>:
   0:	d9802003 	ld.w      	r12, (r0, 0xc)
   4:	d800002f 	ld.b      	r0, (r0, 0x2f)
   8:	e4002001 	andi      	r0, r0, 1
   c:	e900000d 	bez      	r0, 0x26	// 26 <hgsdio20_slave_read+0x26>
  10:	e923000e 	bnez      	r3, 0x2c	// 2c <hgsdio20_slave_read+0x2c>
  14:	3abf      	bseti      	r2, 31
  16:	dc2c2006 	st.w      	r1, (r12, 0x18)
  1a:	6c0f      	mov      	r0, r3
  1c:	dc6c2017 	st.w      	r3, (r12, 0x5c)
  20:	dc4c2016 	st.w      	r2, (r12, 0x58)
  24:	783c      	jmp      	r15
  26:	3000      	movi      	r0, 0
  28:	2800      	subi      	r0, 1
  2a:	07fd      	br      	0x24	// 24 <hgsdio20_slave_read+0x24>
  2c:	ea00020b 	movi      	r0, 523
  30:	6c02      	nor      	r0, r0
  32:	07f9      	br      	0x24	// 24 <hgsdio20_slave_read+0x24>

Disassembly of section .text.hgsdio20_slave_ioctl:

00000000 <hgsdio20_slave_ioctl>:
   0:	3941      	cmpnei      	r1, 1
   2:	9063      	ld.w      	r3, (r0, 0xc)
   4:	0c0b      	bf      	0x1a	// 1a <hgsdio20_slave_ioctl+0x1a>
   6:	3942      	cmpnei      	r1, 2
   8:	0c0e      	bf      	0x24	// 24 <hgsdio20_slave_ioctl+0x24>
   a:	e9210006 	bnez      	r1, 0x16	// 16 <hgsdio20_slave_ioctl+0x16>
   e:	9332      	ld.w      	r1, (r3, 0x48)
  10:	6486      	cmpne      	r1, r2
  12:	0c02      	bf      	0x16	// 16 <hgsdio20_slave_ioctl+0x16>
  14:	b352      	st.w      	r2, (r3, 0x48)
  16:	3000      	movi      	r0, 0
  18:	783c      	jmp      	r15
  1a:	9333      	ld.w      	r1, (r3, 0x4c)
  1c:	644a      	cmpne      	r2, r1
  1e:	0ffc      	bf      	0x16	// 16 <hgsdio20_slave_ioctl+0x16>
  20:	b353      	st.w      	r2, (r3, 0x4c)
  22:	07fa      	br      	0x16	// 16 <hgsdio20_slave_ioctl+0x16>
  24:	9334      	ld.w      	r1, (r3, 0x50)
  26:	644a      	cmpne      	r2, r1
  28:	0ff7      	bf      	0x16	// 16 <hgsdio20_slave_ioctl+0x16>
  2a:	b354      	st.w      	r2, (r3, 0x50)
  2c:	07f5      	br      	0x16	// 16 <hgsdio20_slave_ioctl+0x16>

Disassembly of section .text.hgsdio20_slave_irq_handler:

00000000 <hgsdio20_slave_irq_handler>:
   0:	14d4      	push      	r4-r7, r15
   2:	90a3      	ld.w      	r5, (r0, 0xc)
   4:	6d03      	mov      	r4, r0
   6:	95cb      	ld.w      	r6, (r5, 0x2c)
   8:	e4662040 	andi      	r3, r6, 64
   c:	e903000e 	bez      	r3, 0x28	// 28 <hgsdio20_slave_irq_handler+0x28>
  10:	d9802004 	ld.w      	r12, (r0, 0x10)
  14:	e90c0007 	bez      	r12, 0x22	// 22 <hgsdio20_slave_irq_handler+0x22>
  18:	3300      	movi      	r3, 0
  1a:	9025      	ld.w      	r1, (r0, 0x14)
  1c:	6c8f      	mov      	r2, r3
  1e:	3002      	movi      	r0, 2
  20:	7bf1      	jsr      	r12
  22:	3300      	movi      	r3, 0
  24:	2b40      	subi      	r3, 65
  26:	b56b      	st.w      	r3, (r5, 0x2c)
  28:	e4e62021 	andi      	r7, r6, 33
  2c:	e9070019 	bez      	r7, 0x5e	// 5e <hgsdio20_slave_irq_handler+0x5e>
  30:	d864002e 	ld.b      	r3, (r4, 0x2e)
  34:	d9842004 	ld.w      	r12, (r4, 0x10)
  38:	ec630001 	ori      	r3, r3, 1
  3c:	dc64002e 	st.b      	r3, (r4, 0x2e)
  40:	e90c000d 	bez      	r12, 0x5a	// 5a <hgsdio20_slave_irq_handler+0x5a>
  44:	d864002f 	ld.b      	r3, (r4, 0x2f)
  48:	e4632001 	andi      	r3, r3, 1
  4c:	e9030007 	bez      	r3, 0x5a	// 5a <hgsdio20_slave_irq_handler+0x5a>
  50:	9546      	ld.w      	r2, (r5, 0x18)
  52:	9425      	ld.w      	r1, (r4, 0x14)
  54:	9577      	ld.w      	r3, (r5, 0x5c)
  56:	3000      	movi      	r0, 0
  58:	7bf1      	jsr      	r12
  5a:	6dde      	nor      	r7, r7
  5c:	b5eb      	st.w      	r7, (r5, 0x2c)
  5e:	e4662002 	andi      	r3, r6, 2
  62:	e9030024 	bez      	r3, 0xaa	// aa <hgsdio20_slave_irq_handler+0xaa>
  66:	d864002e 	ld.b      	r3, (r4, 0x2e)
  6a:	e4632002 	andi      	r3, r3, 2
  6e:	e903001e 	bez      	r3, 0xaa	// aa <hgsdio20_slave_irq_handler+0xaa>
  72:	d9842004 	ld.w      	r12, (r4, 0x10)
  76:	3300      	movi      	r3, 0
  78:	b572      	st.w      	r3, (r5, 0x48)
  7a:	e90c000c 	bez      	r12, 0x92	// 92 <hgsdio20_slave_irq_handler+0x92>
  7e:	d844002f 	ld.b      	r2, (r4, 0x2f)
  82:	e4422001 	andi      	r2, r2, 1
  86:	e9020006 	bez      	r2, 0x92	// 92 <hgsdio20_slave_irq_handler+0x92>
  8a:	6c8f      	mov      	r2, r3
  8c:	9425      	ld.w      	r1, (r4, 0x14)
  8e:	3003      	movi      	r0, 3
  90:	7bf1      	jsr      	r12
  92:	d864002e 	ld.b      	r3, (r4, 0x2e)
  96:	3b81      	bclri      	r3, 1
  98:	dc64002e 	st.b      	r3, (r4, 0x2e)
  9c:	3300      	movi      	r3, 0
  9e:	2b02      	subi      	r3, 3
  a0:	b56b      	st.w      	r3, (r5, 0x2c)
  a2:	e404001f 	addi      	r0, r4, 32
  a6:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  aa:	e4c62004 	andi      	r6, r6, 4
  ae:	e9060020 	bez      	r6, 0xee	// ee <hgsdio20_slave_irq_handler+0xee>
  b2:	d864002e 	ld.b      	r3, (r4, 0x2e)
  b6:	e4632002 	andi      	r3, r3, 2
  ba:	e903001a 	bez      	r3, 0xee	// ee <hgsdio20_slave_irq_handler+0xee>
  be:	d9842004 	ld.w      	r12, (r4, 0x10)
  c2:	e90c000d 	bez      	r12, 0xdc	// dc <hgsdio20_slave_irq_handler+0xdc>
  c6:	d864002f 	ld.b      	r3, (r4, 0x2f)
  ca:	e4632001 	andi      	r3, r3, 1
  ce:	e9030007 	bez      	r3, 0xdc	// dc <hgsdio20_slave_irq_handler+0xdc>
  d2:	3300      	movi      	r3, 0
  d4:	6c8f      	mov      	r2, r3
  d6:	9425      	ld.w      	r1, (r4, 0x14)
  d8:	3004      	movi      	r0, 4
  da:	7bf1      	jsr      	r12
  dc:	d864002e 	ld.b      	r3, (r4, 0x2e)
  e0:	ec630004 	ori      	r3, r3, 4
  e4:	dc64002e 	st.b      	r3, (r4, 0x2e)
  e8:	3300      	movi      	r3, 0
  ea:	2b04      	subi      	r3, 5
  ec:	b56b      	st.w      	r3, (r5, 0x2c)
  ee:	1494      	pop      	r4-r7, r15

Disassembly of section .text.hgsdio20_slave_close:

00000000 <hgsdio20_slave_close>:
   0:	14d3      	push      	r4-r6, r15
   2:	d860002f 	ld.b      	r3, (r0, 0x2f)
   6:	e4632001 	andi      	r3, r3, 1
   a:	6d03      	mov      	r4, r0
   c:	e9030020 	bez      	r3, 0x4c	// 4c <hgsdio20_slave_close+0x4c>
  10:	90a3      	ld.w      	r5, (r0, 0xc)
  12:	d800002c 	ld.b      	r0, (r0, 0x2c)
  16:	e0000000 	bsr      	0x0	// 0 <hgsdio20_slave_close>
  1a:	d804002d 	ld.b      	r0, (r4, 0x2d)
  1e:	e0000000 	bsr      	0x0	// 0 <hgsdio20_slave_close>
  22:	956b      	ld.w      	r3, (r5, 0x2c)
  24:	3b83      	bclri      	r3, 3
  26:	b56b      	st.w      	r3, (r5, 0x2c)
  28:	3600      	movi      	r6, 0
  2a:	3301      	movi      	r3, 1
  2c:	b570      	st.w      	r3, (r5, 0x40)
  2e:	6c5b      	mov      	r1, r6
  30:	b5cc      	st.w      	r6, (r5, 0x30)
  32:	9400      	ld.w      	r0, (r4, 0x0)
  34:	e0000000 	bsr      	0x0	// 0 <pin_func>
  38:	1046      	lrw      	r2, 0x40026000	// 50 <hgsdio20_slave_close+0x50>
  3a:	9265      	ld.w      	r3, (r2, 0x14)
  3c:	3b97      	bclri      	r3, 23
  3e:	b265      	st.w      	r3, (r2, 0x14)
  40:	d864002f 	ld.b      	r3, (r4, 0x2f)
  44:	c4665c00 	ins      	r3, r6, 0, 0
  48:	dc64002f 	st.b      	r3, (r4, 0x2f)
  4c:	3000      	movi      	r0, 0
  4e:	1493      	pop      	r4-r6, r15
  50:	40026000 	.long	0x40026000

Disassembly of section .text.hgsdio20_slave_rst_irq_handler:

00000000 <hgsdio20_slave_rst_irq_handler>:
   0:	14d3      	push      	r4-r6, r15
   2:	90a3      	ld.w      	r5, (r0, 0xc)
   4:	6d03      	mov      	r4, r0
   6:	95cb      	ld.w      	r6, (r5, 0x2c)
   8:	e4662008 	andi      	r3, r6, 8
   c:	e9030034 	bez      	r3, 0x74	// 74 <hgsdio20_slave_rst_irq_handler+0x74>
  10:	110b      	lrw      	r0, 0x0	// bc <hgprintf+0xbc>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	9463      	ld.w      	r3, (r4, 0xc)
  18:	6c13      	mov      	r0, r4
  1a:	934b      	ld.w      	r2, (r3, 0x2c)
  1c:	3a83      	bclri      	r2, 3
  1e:	b34b      	st.w      	r2, (r3, 0x2c)
  20:	3201      	movi      	r2, 1
  22:	b350      	st.w      	r2, (r3, 0x40)
  24:	1167      	lrw      	r3, 0x40026000	// c0 <hgsdio20_slave_rst_irq_handler+0xc0>
  26:	9342      	ld.w      	r2, (r3, 0x8)
  28:	3a92      	bclri      	r2, 18
  2a:	b342      	st.w      	r2, (r3, 0x8)
  2c:	9342      	ld.w      	r2, (r3, 0x8)
  2e:	3ab2      	bseti      	r2, 18
  30:	b342      	st.w      	r2, (r3, 0x8)
  32:	e0000000 	bsr      	0x0	// 0 <hgsdio20_slave_rst_irq_handler>
  36:	956c      	ld.w      	r3, (r5, 0x30)
  38:	d9842004 	ld.w      	r12, (r4, 0x10)
  3c:	ec63001f 	ori      	r3, r3, 31
  40:	b56c      	st.w      	r3, (r5, 0x30)
  42:	e90c0007 	bez      	r12, 0x50	// 50 <hgsdio20_slave_rst_irq_handler+0x50>
  46:	3300      	movi      	r3, 0
  48:	6c8f      	mov      	r2, r3
  4a:	9425      	ld.w      	r1, (r4, 0x14)
  4c:	3005      	movi      	r0, 5
  4e:	7bf1      	jsr      	r12
  50:	3300      	movi      	r3, 0
  52:	2b08      	subi      	r3, 9
  54:	b56b      	st.w      	r3, (r5, 0x2c)
  56:	d864002e 	ld.b      	r3, (r4, 0x2e)
  5a:	e4632002 	andi      	r3, r3, 2
  5e:	e9030006 	bez      	r3, 0x6a	// 6a <hgsdio20_slave_rst_irq_handler+0x6a>
  62:	e404001f 	addi      	r0, r4, 32
  66:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  6a:	3300      	movi      	r3, 0
  6c:	dc64002e 	st.b      	r3, (r4, 0x2e)
  70:	3300      	movi      	r3, 0
  72:	b572      	st.w      	r3, (r5, 0x48)
  74:	e4c62010 	andi      	r6, r6, 16
  78:	e9060021 	bez      	r6, 0xba	// ba <hgsdio20_slave_rst_irq_handler+0xba>
  7c:	1012      	lrw      	r0, 0x0	// c4 <hgprintf+0xc4>
  7e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  82:	d9842004 	ld.w      	r12, (r4, 0x10)
  86:	e90c0007 	bez      	r12, 0x94	// 94 <hgsdio20_slave_rst_irq_handler+0x94>
  8a:	3300      	movi      	r3, 0
  8c:	6c8f      	mov      	r2, r3
  8e:	9425      	ld.w      	r1, (r4, 0x14)
  90:	3005      	movi      	r0, 5
  92:	7bf1      	jsr      	r12
  94:	d864002e 	ld.b      	r3, (r4, 0x2e)
  98:	e4632002 	andi      	r3, r3, 2
  9c:	e9030006 	bez      	r3, 0xa8	// a8 <hgsdio20_slave_rst_irq_handler+0xa8>
  a0:	e404001f 	addi      	r0, r4, 32
  a4:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  a8:	d864002e 	ld.b      	r3, (r4, 0x2e)
  ac:	3b81      	bclri      	r3, 1
  ae:	dc64002e 	st.b      	r3, (r4, 0x2e)
  b2:	3300      	movi      	r3, 0
  b4:	b572      	st.w      	r3, (r5, 0x48)
  b6:	2b10      	subi      	r3, 17
  b8:	b56b      	st.w      	r3, (r5, 0x2c)
  ba:	1493      	pop      	r4-r6, r15
  bc:	00000000 	.long	0x00000000
  c0:	40026000 	.long	0x40026000
  c4:	00000000 	.long	0x00000000

Disassembly of section .text.hgsdio20_slave_open:

00000000 <hgsdio20_slave_open>:
   0:	14d2      	push      	r4-r5, r15
   2:	d860002f 	ld.b      	r3, (r0, 0x2f)
   6:	e4632001 	andi      	r3, r3, 1
   a:	6d03      	mov      	r4, r0
   c:	e923002f 	bnez      	r3, 0x6a	// 6a <hgsdio20_slave_open+0x6a>
  10:	3906      	cmphsi      	r1, 7
  12:	082f      	bt      	0x70	// 70 <hgsdio20_slave_open+0x70>
  14:	1079      	lrw      	r3, 0x0	// 78 <hgsdio20_slave_open+0x78>
  16:	dc200032 	st.b      	r1, (r0, 0x32)
  1a:	d0230023 	ldr.b      	r3, (r3, r1 << 0)
  1e:	dc60003d 	st.b      	r3, (r0, 0x3d)
  22:	3101      	movi      	r1, 1
  24:	9000      	ld.w      	r0, (r0, 0x0)
  26:	e0000000 	bsr      	0x0	// 0 <pin_func>
  2a:	6d43      	mov      	r5, r0
  2c:	e900000a 	bez      	r0, 0x40	// 40 <hgsdio20_slave_open+0x40>
  30:	1053      	lrw      	r2, 0x0	// 7c <hgsdio20_slave_open+0x7c>
  32:	ea010173 	movi      	r1, 371
  36:	1013      	lrw      	r0, 0x0	// 80 <assert_internal+0x80>
  38:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  3c:	6c17      	mov      	r0, r5
  3e:	1492      	pop      	r4-r5, r15
  40:	1071      	lrw      	r3, 0x40026000	// 84 <hgsdio20_slave_open+0x84>
  42:	6c13      	mov      	r0, r4
  44:	9345      	ld.w      	r2, (r3, 0x14)
  46:	3ab7      	bseti      	r2, 23
  48:	b345      	st.w      	r2, (r3, 0x14)
  4a:	9342      	ld.w      	r2, (r3, 0x8)
  4c:	3a92      	bclri      	r2, 18
  4e:	b342      	st.w      	r2, (r3, 0x8)
  50:	9342      	ld.w      	r2, (r3, 0x8)
  52:	3ab2      	bseti      	r2, 18
  54:	b342      	st.w      	r2, (r3, 0x8)
  56:	e0000000 	bsr      	0x0	// 0 <hgsdio20_slave_open>
  5a:	d864002f 	ld.b      	r3, (r4, 0x2f)
  5e:	3201      	movi      	r2, 1
  60:	c4625c00 	ins      	r3, r2, 0, 0
  64:	dc64002f 	st.b      	r3, (r4, 0x2f)
  68:	07ea      	br      	0x3c	// 3c <hgsdio20_slave_open+0x3c>
  6a:	3500      	movi      	r5, 0
  6c:	2d0f      	subi      	r5, 16
  6e:	07e7      	br      	0x3c	// 3c <hgsdio20_slave_open+0x3c>
  70:	ea05020b 	movi      	r5, 523
  74:	6d56      	nor      	r5, r5
  76:	07e3      	br      	0x3c	// 3c <hgsdio20_slave_open+0x3c>
	...
  84:	40026000 	.long	0x40026000

Disassembly of section .text.hgsdio20_slave_request_irq:

00000000 <hgsdio20_slave_request_irq>:
   0:	14d3      	push      	r4-r6, r15
   2:	d860002f 	ld.b      	r3, (r0, 0x2f)
   6:	e4632001 	andi      	r3, r3, 1
   a:	6d03      	mov      	r4, r0
   c:	90a3      	ld.w      	r5, (r0, 0xc)
   e:	e903003c 	bez      	r3, 0x86	// 86 <hgsdio20_slave_request_irq+0x86>
  12:	b024      	st.w      	r1, (r0, 0x10)
  14:	b045      	st.w      	r2, (r0, 0x14)
  16:	6c83      	mov      	r2, r0
  18:	103d      	lrw      	r1, 0x0	// 8c <hgsdio20_slave_request_irq+0x8c>
  1a:	d800002c 	ld.b      	r0, (r0, 0x2c)
  1e:	e0000000 	bsr      	0x0	// 0 <request_irq>
  22:	6d83      	mov      	r6, r0
  24:	e9000008 	bez      	r0, 0x34	// 34 <hgsdio20_slave_request_irq+0x34>
  28:	105a      	lrw      	r2, 0x0	// 90 <hgsdio20_slave_request_irq+0x90>
  2a:	ea010251 	movi      	r1, 593
  2e:	101a      	lrw      	r0, 0x0	// 94 <assert_internal+0x94>
  30:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  34:	6c93      	mov      	r2, r4
  36:	1039      	lrw      	r1, 0x0	// 98 <hgsdio20_slave_request_irq+0x98>
  38:	d804002d 	ld.b      	r0, (r4, 0x2d)
  3c:	e0000000 	bsr      	0x0	// 0 <request_irq>
  40:	e9060008 	bez      	r6, 0x50	// 50 <hgsdio20_slave_request_irq+0x50>
  44:	1053      	lrw      	r2, 0x0	// 90 <hgsdio20_slave_request_irq+0x90>
  46:	ea010253 	movi      	r1, 595
  4a:	1013      	lrw      	r0, 0x0	// 94 <assert_internal+0x94>
  4c:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  50:	d864002c 	ld.b      	r3, (r4, 0x2c)
  54:	c4a354c0 	zext      	r0, r3, 6, 5
  58:	3201      	movi      	r2, 1
  5a:	e463201f 	andi      	r3, r3, 31
  5e:	c4624023 	lsl      	r3, r2, r3
  62:	102f      	lrw      	r1, 0xe000e100	// 9c <hgsdio20_slave_request_irq+0x9c>
  64:	d4010883 	str.w      	r3, (r1, r0 << 2)
  68:	d864002d 	ld.b      	r3, (r4, 0x2d)
  6c:	c4a354c0 	zext      	r0, r3, 6, 5
  70:	e463201f 	andi      	r3, r3, 31
  74:	708c      	lsl      	r2, r3
  76:	d4010882 	str.w      	r2, (r1, r0 << 2)
  7a:	956c      	ld.w      	r3, (r5, 0x30)
  7c:	ec63007f 	ori      	r3, r3, 127
  80:	b56c      	st.w      	r3, (r5, 0x30)
  82:	3000      	movi      	r0, 0
  84:	1493      	pop      	r4-r6, r15
  86:	3000      	movi      	r0, 0
  88:	2800      	subi      	r0, 1
  8a:	07fd      	br      	0x84	// 84 <hgsdio20_slave_request_irq+0x84>
	...
  9c:	e000e100 	.long	0xe000e100

Disassembly of section .text.hgsdio20_slave_write:

00000000 <hgsdio20_slave_write>:
   0:	14d6      	push      	r4-r9, r15
   2:	6e47      	mov      	r9, r1
   4:	d820002f 	ld.b      	r1, (r0, 0x2f)
   8:	e4212001 	andi      	r1, r1, 1
   c:	6d43      	mov      	r5, r0
   e:	e9010017 	bez      	r1, 0x3c	// 3c <hgsdio20_slave_write+0x3c>
  12:	e903008f 	bez      	r3, 0x130	// 130 <hgsdio20_slave_write+0x130>
  16:	c4025664 	zext      	r4, r2, 19, 0
  1a:	e904008f 	bez      	r4, 0x138	// 138 <hgsdio20_slave_write+0x138>
  1e:	e4c00017 	addi      	r6, r0, 24
  22:	31fa      	movi      	r1, 250
  24:	d9002003 	ld.w      	r8, (r0, 0xc)
  28:	4123      	lsli      	r1, r1, 3
  2a:	6c1b      	mov      	r0, r6
  2c:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  30:	6dc3      	mov      	r7, r0
  32:	e9000008 	bez      	r0, 0x42	// 42 <hgsdio20_slave_write+0x42>
  36:	1202      	lrw      	r0, 0x0	// 13c <hgprintf+0x13c>
  38:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  3c:	3000      	movi      	r0, 0
  3e:	2800      	subi      	r0, 1
  40:	046d      	br      	0x11a	// 11a <hgsdio20_slave_write+0x11a>
  42:	d865002e 	ld.b      	r3, (r5, 0x2e)
  46:	e4432001 	andi      	r2, r3, 1
  4a:	e9220009 	bnez      	r2, 0x5c	// 5c <hgsdio20_slave_write+0x5c>
  4e:	111d      	lrw      	r0, 0x0	// 140 <hgprintf+0x140>
  50:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  54:	6c1b      	mov      	r0, r6
  56:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  5a:	07f1      	br      	0x3c	// 3c <hgsdio20_slave_write+0x3c>
  5c:	3b82      	bclri      	r3, 2
  5e:	ec630002 	ori      	r3, r3, 2
  62:	dc65002e 	st.b      	r3, (r5, 0x2e)
  66:	d8482018 	ld.w      	r2, (r8, 0x60)
  6a:	5c03      	subi      	r0, r4, 1
  6c:	d8682018 	ld.w      	r3, (r8, 0x60)
  70:	6008      	addu      	r0, r2
  72:	5f8d      	subu      	r4, r7, r3
  74:	d868200a 	ld.w      	r3, (r8, 0x28)
  78:	6810      	and      	r0, r4
  7a:	3b81      	bclri      	r3, 1
  7c:	dc68200a 	st.w      	r3, (r8, 0x28)
  80:	dd282005 	st.w      	r9, (r8, 0x14)
  84:	dc082007 	st.w      	r0, (r8, 0x1c)
  88:	4008      	lsli      	r0, r0, 8
  8a:	ec000001 	ori      	r0, r0, 1
  8e:	dc082012 	st.w      	r0, (r8, 0x48)
  92:	d868200a 	ld.w      	r3, (r8, 0x28)
  96:	ec630003 	ori      	r3, r3, 3
  9a:	31fa      	movi      	r1, 250
  9c:	dc68200a 	st.w      	r3, (r8, 0x28)
  a0:	4123      	lsli      	r1, r1, 3
  a2:	e405001f 	addi      	r0, r5, 32
  a6:	e0000000 	bsr      	0x0	// 0 <os_sema_down>
  aa:	6e43      	mov      	r9, r0
  ac:	dce82012 	st.w      	r7, (r8, 0x48)
  b0:	e9400036 	bhz      	r0, 0x11c	// 11c <hgsdio20_slave_write+0x11c>
  b4:	1104      	lrw      	r0, 0x0	// 144 <hgprintf+0x144>
  b6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ba:	d865002e 	ld.b      	r3, (r5, 0x2e)
  be:	3b80      	bclri      	r3, 0
  c0:	dc65002e 	st.b      	r3, (r5, 0x2e)
  c4:	1161      	lrw      	r3, 0x40026000	// 148 <hgsdio20_slave_write+0x148>
  c6:	6c17      	mov      	r0, r5
  c8:	9342      	ld.w      	r2, (r3, 0x8)
  ca:	3a92      	bclri      	r2, 18
  cc:	b342      	st.w      	r2, (r3, 0x8)
  ce:	9342      	ld.w      	r2, (r3, 0x8)
  d0:	3ab2      	bseti      	r2, 18
  d2:	b342      	st.w      	r2, (r3, 0x8)
  d4:	e0000000 	bsr      	0x0	// 0 <hgsdio20_slave_write>
  d8:	9524      	ld.w      	r1, (r5, 0x10)
  da:	e9010017 	bez      	r1, 0x108	// 108 <hgsdio20_slave_write+0x108>
  de:	9545      	ld.w      	r2, (r5, 0x14)
  e0:	6c17      	mov      	r0, r5
  e2:	e0000000 	bsr      	0x0	// 0 <hgsdio20_slave_write>
  e6:	c0006024 	mfcr      	r4, cr<0, 0>
  ea:	c0807020 	psrclr      	ie
  ee:	e4842040 	andi      	r4, r4, 64
  f2:	d9852004 	ld.w      	r12, (r5, 0x10)
  f6:	6cdf      	mov      	r3, r7
  f8:	6c9f      	mov      	r2, r7
  fa:	9525      	ld.w      	r1, (r5, 0x14)
  fc:	3005      	movi      	r0, 5
  fe:	7bf1      	jsr      	r12
 100:	e9040004 	bez      	r4, 0x108	// 108 <hgsdio20_slave_write+0x108>
 104:	c0807420 	psrset      	ie
 108:	6c1b      	mov      	r0, r6
 10a:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
 10e:	eb290000 	cmplti      	r9, 1
 112:	c4000502 	mvc      	r2
 116:	3000      	movi      	r0, 0
 118:	600a      	subu      	r0, r2
 11a:	1496      	pop      	r4-r9, r15
 11c:	d845002e 	ld.b      	r2, (r5, 0x2e)
 120:	e4422004 	andi      	r2, r2, 4
 124:	3300      	movi      	r3, 0
 126:	2b00      	subi      	r3, 1
 128:	3a40      	cmpnei      	r2, 0
 12a:	c5230c40 	inct      	r9, r3, 0
 12e:	07ed      	br      	0x108	// 108 <hgsdio20_slave_write+0x108>
 130:	ea00020b 	movi      	r0, 523
 134:	6c02      	nor      	r0, r0
 136:	07f2      	br      	0x11a	// 11a <hgsdio20_slave_write+0x11a>
 138:	6c13      	mov      	r0, r4
 13a:	07f0      	br      	0x11a	// 11a <hgsdio20_slave_write+0x11a>
	...
 148:	40026000 	.long	0x40026000

Disassembly of section .text.hgsdio20_slave_attach:

00000000 <hgsdio20_slave_attach>:
   0:	14d4      	push      	r4-r7, r15
   2:	6d07      	mov      	r4, r1
   4:	1166      	lrw      	r3, 0x0	// 9c <hgsdio20_slave_attach+0x9c>
   6:	e4e10017 	addi      	r7, r1, 24
   a:	b162      	st.w      	r3, (r1, 0x8)
   c:	3208      	movi      	r2, 8
   e:	3100      	movi      	r1, 0
  10:	e4a4001f 	addi      	r5, r4, 32
  14:	6d83      	mov      	r6, r0
  16:	6c1f      	mov      	r0, r7
  18:	e0000000 	bsr      	0x0	// 0 <memset>
  1c:	3208      	movi      	r2, 8
  1e:	3100      	movi      	r1, 0
  20:	6c17      	mov      	r0, r5
  22:	e0000000 	bsr      	0x0	// 0 <memset>
  26:	6c1f      	mov      	r0, r7
  28:	e0000000 	bsr      	0x0	// 0 <os_mutex_init>
  2c:	3100      	movi      	r1, 0
  2e:	6c17      	mov      	r0, r5
  30:	e0000000 	bsr      	0x0	// 0 <os_sema_init>
  34:	3211      	movi      	r2, 17
  36:	103b      	lrw      	r1, 0x0	// a0 <hgsdio20_slave_attach+0xa0>
  38:	e4040033 	addi      	r0, r4, 52
  3c:	e0000000 	bsr      	0x0	// 0 <memcpy>
  40:	3235      	movi      	r2, 53
  42:	1039      	lrw      	r1, 0x0	// a4 <hgsdio20_slave_attach+0xa4>
  44:	e4040044 	addi      	r0, r4, 69
  48:	e0000000 	bsr      	0x0	// 0 <memcpy>
  4c:	d8640042 	ld.b      	r3, (r4, 0x42)
  50:	d8440043 	ld.b      	r2, (r4, 0x43)
  54:	6cc8      	or      	r3, r2
  56:	e9230009 	bnez      	r3, 0x68	// 68 <hgsdio20_slave_attach+0x68>
  5a:	e0000000 	bsr      	0x0	// 0 <sysctrl_get_chip_id>
  5e:	dc040042 	st.b      	r0, (r4, 0x42)
  62:	4808      	lsri      	r0, r0, 8
  64:	dc040043 	st.b      	r0, (r4, 0x43)
  68:	3500      	movi      	r5, 0
  6a:	d864002f 	ld.b      	r3, (r4, 0x2f)
  6e:	c4655c00 	ins      	r3, r5, 0, 0
  72:	dc64002f 	st.b      	r3, (r4, 0x2f)
  76:	d804002c 	ld.b      	r0, (r4, 0x2c)
  7a:	b4a4      	st.w      	r5, (r4, 0x10)
  7c:	b4a5      	st.w      	r5, (r4, 0x14)
  7e:	dca4002e 	st.b      	r5, (r4, 0x2e)
  82:	e0000000 	bsr      	0x0	// 0 <hgsdio20_slave_attach>
  86:	d804002d 	ld.b      	r0, (r4, 0x2d)
  8a:	e0000000 	bsr      	0x0	// 0 <hgsdio20_slave_attach>
  8e:	6c53      	mov      	r1, r4
  90:	6c1b      	mov      	r0, r6
  92:	e0000000 	bsr      	0x0	// 0 <dev_register>
  96:	6c17      	mov      	r0, r5
  98:	1494      	pop      	r4-r7, r15
	...
