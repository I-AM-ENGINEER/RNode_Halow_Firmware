
disasm/libcore/obj/usb11_hgusb11_dev_ep0.o:     file format elf32-csky-little


Disassembly of section .text.hgusb11_dev_exit:

00000000 <hgusb11_dev_exit>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <hgusb11_switch_stable_otg>
   6:	1490      	pop      	r15

Disassembly of section .text.hgusb11_dev_ep0_tx:

00000000 <hgusb11_dev_ep0_tx>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	6d87      	mov      	r6, r1
   6:	3342      	movi      	r3, 66
   8:	e4400154 	addi      	r2, r0, 341
   c:	3100      	movi      	r1, 0
   e:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep_rx_kick>
  12:	9463      	ld.w      	r3, (r4, 0xc)
  14:	3500      	movi      	r5, 0
  16:	3240      	movi      	r2, 64
  18:	a3ae      	st.b      	r5, (r3, 0xe)
  1a:	a351      	st.b      	r2, (r3, 0x11)
  1c:	9463      	ld.w      	r3, (r4, 0xc)
  1e:	e4440112 	addi      	r2, r4, 275
  22:	a3ae      	st.b      	r5, (r3, 0xe)
  24:	3100      	movi      	r1, 0
  26:	6cdb      	mov      	r3, r6
  28:	6c13      	mov      	r0, r4
  2a:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep_tx_kick>
  2e:	9463      	ld.w      	r3, (r4, 0xc)
  30:	320a      	movi      	r2, 10
  32:	a3ae      	st.b      	r5, (r3, 0xe)
  34:	3001      	movi      	r0, 1
  36:	a351      	st.b      	r2, (r3, 0x11)
  38:	3301      	movi      	r3, 1
  3a:	dc6400f4 	st.b      	r3, (r4, 0xf4)
  3e:	1493      	pop      	r4-r6, r15

Disassembly of section .text.hgusb11_dev_clear_stall_flag:

00000000 <hgusb11_dev_clear_stall_flag>:
   0:	3300      	movi      	r3, 0
   2:	dc600101 	st.b      	r3, (r0, 0x101)
   6:	dc600102 	st.b      	r3, (r0, 0x102)
   a:	dc600103 	st.b      	r3, (r0, 0x103)
   e:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep0_clrrx_pkt0:

00000000 <hgusb11_dev_ep0_clrrx_pkt0>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	3342      	movi      	r3, 66
   6:	e4400154 	addi      	r2, r0, 341
   a:	3100      	movi      	r1, 0
   c:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep_rx_kick>
  10:	9463      	ld.w      	r3, (r4, 0xc)
  12:	3200      	movi      	r2, 0
  14:	a34e      	st.b      	r2, (r3, 0xe)
  16:	3248      	movi      	r2, 72
  18:	a351      	st.b      	r2, (r3, 0x11)
  1a:	3001      	movi      	r0, 1
  1c:	3301      	movi      	r3, 1
  1e:	dc6400f4 	st.b      	r3, (r4, 0xf4)
  22:	1491      	pop      	r4, r15

Disassembly of section .text.hgusb11_dev_intr_init_b:

00000000 <hgusb11_dev_intr_init_b>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e0000000 	bsr      	0x0	// 0 <hgusb11_intr_dis>
   8:	9463      	ld.w      	r3, (r4, 0xc)
   a:	320c      	movi      	r2, 12
   c:	a34b      	st.b      	r2, (r3, 0xb)
   e:	3200      	movi      	r2, 0
  10:	a349      	st.b      	r2, (r3, 0x9)
  12:	3201      	movi      	r2, 1
  14:	a347      	st.b      	r2, (r3, 0x7)
  16:	1491      	pop      	r4, r15

Disassembly of section .text.hgusb11_dev_init:

00000000 <hgusb11_dev_init>:
   0:	14d3      	push      	r4-r6, r15
   2:	d860102c 	ld.h      	r3, (r0, 0x58)
   6:	eb0301f7 	cmphsi      	r3, 504
   a:	6d03      	mov      	r4, r0
   c:	3500      	movi      	r5, 0
   e:	086a      	bt      	0xe2	// e2 <hgusb11_dev_init+0xe2>
  10:	1176      	lrw      	r3, 0x40026000	// e8 <hgusb11_dev_init+0xe8>
  12:	9342      	ld.w      	r2, (r3, 0x8)
  14:	3a8c      	bclri      	r2, 12
  16:	b342      	st.w      	r2, (r3, 0x8)
  18:	9342      	ld.w      	r2, (r3, 0x8)
  1a:	ec421000 	ori      	r2, r2, 4096
  1e:	b342      	st.w      	r2, (r3, 0x8)
  20:	e0000000 	bsr      	0x0	// 0 <hgusb11_switch_host>
  24:	3005      	movi      	r0, 5
  26:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
  2a:	9463      	ld.w      	r3, (r4, 0xc)
  2c:	6c13      	mov      	r0, r4
  2e:	dca320c0 	st.w      	r5, (r3, 0x300)
  32:	d84320c2 	ld.w      	r2, (r3, 0x308)
  36:	ec422001 	ori      	r2, r2, 8193
  3a:	dc4320c2 	st.w      	r2, (r3, 0x308)
  3e:	3280      	movi      	r2, 128
  40:	4243      	lsli      	r2, r2, 3
  42:	dc4320c6 	st.w      	r2, (r3, 0x318)
  46:	e0000000 	bsr      	0x0	// 0 <hgusb11_switch_stable_device>
  4a:	3342      	movi      	r3, 66
  4c:	6c57      	mov      	r1, r5
  4e:	e4440154 	addi      	r2, r4, 341
  52:	6c13      	mov      	r0, r4
  54:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep_rx_kick>
  58:	6c57      	mov      	r1, r5
  5a:	3212      	movi      	r2, 18
  5c:	e40400db 	addi      	r0, r4, 220
  60:	e0000000 	bsr      	0x0	// 0 <memset>
  64:	6c57      	mov      	r1, r5
  66:	3212      	movi      	r2, 18
  68:	e40400ef 	addi      	r0, r4, 240
  6c:	e0000000 	bsr      	0x0	// 0 <memset>
  70:	3212      	movi      	r2, 18
  72:	9432      	ld.w      	r1, (r4, 0x48)
  74:	e4040196 	addi      	r0, r4, 407
  78:	e0000000 	bsr      	0x0	// 0 <memcpy>
  7c:	d8641020 	ld.h      	r3, (r4, 0x40)
  80:	dc64019f 	st.b      	r3, (r4, 0x19f)
  84:	4b68      	lsri      	r3, r3, 8
  86:	dc6401a0 	st.b      	r3, (r4, 0x1a0)
  8a:	d8641021 	ld.h      	r3, (r4, 0x42)
  8e:	dc6401a1 	st.b      	r3, (r4, 0x1a1)
  92:	4b68      	lsri      	r3, r3, 8
  94:	dc6401a2 	st.b      	r3, (r4, 0x1a2)
  98:	3209      	movi      	r2, 9
  9a:	9433      	ld.w      	r1, (r4, 0x4c)
  9c:	e40401b2 	addi      	r0, r4, 435
  a0:	e0000000 	bsr      	0x0	// 0 <memcpy>
  a4:	d8a4102c 	ld.h      	r5, (r4, 0x58)
  a8:	6c97      	mov      	r2, r5
  aa:	9435      	ld.w      	r1, (r4, 0x54)
  ac:	e40401bb 	addi      	r0, r4, 444
  b0:	2508      	addi      	r5, 9
  b2:	e0000000 	bsr      	0x0	// 0 <memcpy>
  b6:	7555      	zexth      	r5, r5
  b8:	6c13      	mov      	r0, r4
  ba:	d8c4005a 	ld.b      	r6, (r4, 0x5a)
  be:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_init>
  c2:	74d4      	zextb      	r3, r5
  c4:	dc6401b5 	st.b      	r3, (r4, 0x1b5)
  c8:	3340      	movi      	r3, 64
  ca:	dc6400f5 	st.b      	r3, (r4, 0xf5)
  ce:	9463      	ld.w      	r3, (r4, 0xc)
  d0:	4da8      	lsri      	r5, r5, 8
  d2:	3201      	movi      	r2, 1
  d4:	dca401b6 	st.b      	r5, (r4, 0x1b6)
  d8:	dcc401b7 	st.b      	r6, (r4, 0x1b7)
  dc:	3001      	movi      	r0, 1
  de:	a34e      	st.b      	r2, (r3, 0xe)
  e0:	1493      	pop      	r4-r6, r15
  e2:	6c17      	mov      	r0, r5
  e4:	07fe      	br      	0xe0	// e0 <hgusb11_dev_init+0xe0>
  e6:	0000      	.short	0x0000
  e8:	40026000 	.long	0x40026000

Disassembly of section .text.hgusb11_dev_check_faddr:

00000000 <hgusb11_dev_check_faddr>:
   0:	d86000f1 	ld.b      	r3, (r0, 0xf1)
   4:	e903000d 	bez      	r3, 0x1e	// 1e <hgusb11_dev_check_faddr+0x1e>
   8:	3300      	movi      	r3, 0
   a:	3100      	movi      	r1, 0
   c:	dc6000f1 	st.b      	r3, (r0, 0xf1)
  10:	297f      	subi      	r1, 128
  12:	d86000e6 	ld.b      	r3, (r0, 0xe6)
  16:	9043      	ld.w      	r2, (r0, 0xc)
  18:	6cc4      	or      	r3, r1
  1a:	74cc      	zextb      	r3, r3
  1c:	a260      	st.b      	r3, (r2, 0x0)
  1e:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_reset:

00000000 <hgusb11_dev_reset>:
   0:	14c6      	push      	r4-r9
   2:	9043      	ld.w      	r2, (r0, 0xc)
   4:	3300      	movi      	r3, 0
   6:	dc6220c5 	st.w      	r3, (r2, 0x314)
   a:	e5a3106f 	subi      	r13, r3, 112
   e:	3440      	movi      	r4, 64
  10:	3548      	movi      	r5, 72
  12:	6d8f      	mov      	r6, r3
  14:	d840007a 	ld.b      	r2, (r0, 0x7a)
  18:	648c      	cmphs      	r3, r2
  1a:	0c0a      	bf      	0x2e	// 2e <hgusb11_dev_reset+0x2e>
  1c:	3300      	movi      	r3, 0
  1e:	dc6000f4 	st.b      	r3, (r0, 0xf4)
  22:	dc6000f3 	st.b      	r3, (r0, 0xf3)
  26:	3300      	movi      	r3, 0
  28:	dc60107e 	st.h      	r3, (r0, 0xfc)
  2c:	1486      	pop      	r4-r9
  2e:	4323      	lsli      	r1, r3, 3
  30:	c420002c 	addu      	r12, r0, r1
  34:	90e3      	ld.w      	r7, (r0, 0xc)
  36:	d92c007c 	ld.b      	r9, (r12, 0x7c)
  3a:	dd27000e 	st.b      	r9, (r7, 0xe)
  3e:	d90c007e 	ld.b      	r8, (r12, 0x7e)
  42:	e443000f 	addi      	r2, r3, 16
  46:	dd27000e 	st.b      	r9, (r7, 0xe)
  4a:	e9080021 	bez      	r8, 0x8c	// 8c <hgusb11_dev_reset+0x8c>
  4e:	a7b1      	st.b      	r5, (r7, 0x11)
  50:	d8ec007d 	ld.b      	r7, (r12, 0x7d)
  54:	3f41      	cmpnei      	r7, 1
  56:	d98c007c 	ld.b      	r12, (r12, 0x7c)
  5a:	90e3      	ld.w      	r7, (r0, 0xc)
  5c:	7730      	zextb      	r12, r12
  5e:	dd87000e 	st.b      	r12, (r7, 0xe)
  62:	0813      	bt      	0x88	// 88 <hgusb11_dev_reset+0x88>
  64:	a792      	st.b      	r4, (r7, 0x12)
  66:	6040      	addu      	r1, r0
  68:	d9802003 	ld.w      	r12, (r0, 0xc)
  6c:	4243      	lsli      	r2, r2, 3
  6e:	d821007c 	ld.b      	r1, (r1, 0x7c)
  72:	6080      	addu      	r2, r0
  74:	dc2c000e 	st.b      	r1, (r12, 0xe)
  78:	8a41      	ld.h      	r2, (r2, 0x2)
  7a:	c4625542 	zext      	r2, r2, 10, 3
  7e:	dc4c0010 	st.b      	r2, (r12, 0x10)
  82:	2300      	addi      	r3, 1
  84:	74cc      	zextb      	r3, r3
  86:	07c7      	br      	0x14	// 14 <hgusb11_dev_reset+0x14>
  88:	a7d2      	st.b      	r6, (r7, 0x12)
  8a:	07ee      	br      	0x66	// 66 <hgusb11_dev_reset+0x66>
  8c:	dda70014 	st.b      	r13, (r7, 0x14)
  90:	d8ec007d 	ld.b      	r7, (r12, 0x7d)
  94:	3f41      	cmpnei      	r7, 1
  96:	d98c007c 	ld.b      	r12, (r12, 0x7c)
  9a:	90e3      	ld.w      	r7, (r0, 0xc)
  9c:	7730      	zextb      	r12, r12
  9e:	dd87000e 	st.b      	r12, (r7, 0xe)
  a2:	0811      	bt      	0xc4	// c4 <hgusb11_dev_reset+0xc4>
  a4:	a795      	st.b      	r4, (r7, 0x15)
  a6:	6040      	addu      	r1, r0
  a8:	d9802003 	ld.w      	r12, (r0, 0xc)
  ac:	4243      	lsli      	r2, r2, 3
  ae:	d821007c 	ld.b      	r1, (r1, 0x7c)
  b2:	6080      	addu      	r2, r0
  b4:	dc2c000e 	st.b      	r1, (r12, 0xe)
  b8:	8a41      	ld.h      	r2, (r2, 0x2)
  ba:	c4625542 	zext      	r2, r2, 10, 3
  be:	dc4c0013 	st.b      	r2, (r12, 0x13)
  c2:	07e0      	br      	0x82	// 82 <hgusb11_dev_reset+0x82>
  c4:	dd070015 	st.b      	r8, (r7, 0x15)
  c8:	07ef      	br      	0xa6	// a6 <hgusb11_dev_reset+0xa6>

Disassembly of section .text.hgusb11_dev_ep0_get_request:

00000000 <hgusb11_dev_ep0_get_request>:
   0:	14d0      	push      	r15
   2:	e4200154 	addi      	r1, r0, 341
   6:	3208      	movi      	r2, 8
   8:	20e3      	addi      	r0, 228
   a:	e0000000 	bsr      	0x0	// 0 <memcpy>
   e:	1490      	pop      	r15

Disassembly of section .text.hgusb11_dev_stall_ep:

00000000 <hgusb11_dev_stall_ep>:
   0:	14d3      	push      	r4-r6, r15
   2:	9063      	ld.w      	r3, (r0, 0xc)
   4:	3941      	cmpnei      	r1, 1
   6:	83ce      	ld.b      	r6, (r3, 0xe)
   8:	e441207f 	andi      	r2, r1, 127
   c:	6d43      	mov      	r5, r0
   e:	6d07      	mov      	r4, r1
  10:	7598      	zextb      	r6, r6
  12:	a34e      	st.b      	r2, (r3, 0xe)
  14:	0c13      	bf      	0x3a	// 3a <hgusb11_dev_stall_ep+0x3a>
  16:	3940      	cmpnei      	r1, 0
  18:	0c07      	bf      	0x26	// 26 <hgusb11_dev_stall_ep+0x26>
  1a:	eb410081 	cmpnei      	r1, 129
  1e:	0c14      	bf      	0x46	// 46 <hgusb11_dev_stall_ep+0x46>
  20:	9563      	ld.w      	r3, (r5, 0xc)
  22:	a3ce      	st.b      	r6, (r3, 0xe)
  24:	1493      	pop      	r4-r6, r15
  26:	3342      	movi      	r3, 66
  28:	e4400154 	addi      	r2, r0, 341
  2c:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep_rx_kick>
  30:	9563      	ld.w      	r3, (r5, 0xc)
  32:	3260      	movi      	r2, 96
  34:	a38e      	st.b      	r4, (r3, 0xe)
  36:	a351      	st.b      	r2, (r3, 0x11)
  38:	07f4      	br      	0x20	// 20 <hgusb11_dev_stall_ep+0x20>
  3a:	3220      	movi      	r2, 32
  3c:	dc250102 	st.b      	r1, (r5, 0x102)
  40:	a32e      	st.b      	r1, (r3, 0xe)
  42:	a354      	st.b      	r2, (r3, 0x14)
  44:	07ee      	br      	0x20	// 20 <hgusb11_dev_stall_ep+0x20>
  46:	3201      	movi      	r2, 1
  48:	dc400101 	st.b      	r2, (r0, 0x101)
  4c:	a34e      	st.b      	r2, (r3, 0xe)
  4e:	3210      	movi      	r2, 16
  50:	07f3      	br      	0x36	// 36 <hgusb11_dev_stall_ep+0x36>

Disassembly of section .text.hgusb11_dev_clear_ep:

00000000 <hgusb11_dev_clear_ep>:
   0:	9063      	ld.w      	r3, (r0, 0xc)
   2:	3941      	cmpnei      	r1, 1
   4:	834e      	ld.b      	r2, (r3, 0xe)
   6:	e581207f 	andi      	r12, r1, 127
   a:	7488      	zextb      	r2, r2
   c:	dd83000e 	st.b      	r12, (r3, 0xe)
  10:	0c07      	bf      	0x1e	// 1e <hgusb11_dev_clear_ep+0x1e>
  12:	eb410081 	cmpnei      	r1, 129
  16:	0c0d      	bf      	0x30	// 30 <hgusb11_dev_clear_ep+0x30>
  18:	9063      	ld.w      	r3, (r0, 0xc)
  1a:	a34e      	st.b      	r2, (r3, 0xe)
  1c:	783c      	jmp      	r15
  1e:	ea0c0000 	movi      	r12, 0
  22:	dd800102 	st.b      	r12, (r0, 0x102)
  26:	a32e      	st.b      	r1, (r3, 0xe)
  28:	3100      	movi      	r1, 0
  2a:	297f      	subi      	r1, 128
  2c:	a334      	st.b      	r1, (r3, 0x14)
  2e:	07f5      	br      	0x18	// 18 <hgusb11_dev_clear_ep+0x18>
  30:	3100      	movi      	r1, 0
  32:	dc200101 	st.b      	r1, (r0, 0x101)
  36:	3101      	movi      	r1, 1
  38:	a32e      	st.b      	r1, (r3, 0xe)
  3a:	3140      	movi      	r1, 64
  3c:	a331      	st.b      	r1, (r3, 0x11)
  3e:	07ed      	br      	0x18	// 18 <hgusb11_dev_clear_ep+0x18>

Disassembly of section .text.hgusb11_dev_bot_reset:

00000000 <hgusb11_dev_bot_reset>:
   0:	14c3      	push      	r4-r6
   2:	3300      	movi      	r3, 0
   4:	dc600101 	st.b      	r3, (r0, 0x101)
   8:	dc600102 	st.b      	r3, (r0, 0x102)
   c:	dc600103 	st.b      	r3, (r0, 0x103)
  10:	3300      	movi      	r3, 0
  12:	e583106f 	subi      	r12, r3, 112
  16:	3548      	movi      	r5, 72
  18:	e5a3105f 	subi      	r13, r3, 96
  1c:	d840007a 	ld.b      	r2, (r0, 0x7a)
  20:	648c      	cmphs      	r3, r2
  22:	0c02      	bf      	0x26	// 26 <hgusb11_dev_bot_reset+0x26>
  24:	1483      	pop      	r4-r6
  26:	4343      	lsli      	r2, r3, 3
  28:	6080      	addu      	r2, r0
  2a:	9023      	ld.w      	r1, (r0, 0xc)
  2c:	d882007c 	ld.b      	r4, (r2, 0x7c)
  30:	a18e      	st.b      	r4, (r1, 0xe)
  32:	d8c2007d 	ld.b      	r6, (r2, 0x7d)
  36:	3e42      	cmpnei      	r6, 2
  38:	080d      	bt      	0x52	// 52 <hgusb11_dev_bot_reset+0x52>
  3a:	d8c2007e 	ld.b      	r6, (r2, 0x7e)
  3e:	a18e      	st.b      	r4, (r1, 0xe)
  40:	e906000c 	bez      	r6, 0x58	// 58 <hgusb11_dev_bot_reset+0x58>
  44:	a1b1      	st.b      	r5, (r1, 0x11)
  46:	9023      	ld.w      	r1, (r0, 0xc)
  48:	d842007c 	ld.b      	r2, (r2, 0x7c)
  4c:	a14e      	st.b      	r2, (r1, 0xe)
  4e:	dda10012 	st.b      	r13, (r1, 0x12)
  52:	2300      	addi      	r3, 1
  54:	74cc      	zextb      	r3, r3
  56:	07e3      	br      	0x1c	// 1c <hgusb11_dev_bot_reset+0x1c>
  58:	dd810014 	st.b      	r12, (r1, 0x14)
  5c:	07fb      	br      	0x52	// 52 <hgusb11_dev_bot_reset+0x52>

Disassembly of section .text.hgusb11_dev_ep0_get_status:

00000000 <hgusb11_dev_ep0_get_status>:
   0:	14d0      	push      	r15
   2:	d86000e4 	ld.b      	r3, (r0, 0xe4)
   6:	748e      	sextb      	r2, r3
   8:	e9820004 	blz      	r2, 0x10	// 10 <hgusb11_dev_ep0_get_status+0x10>
   c:	3000      	movi      	r0, 0
   e:	042f      	br      	0x6c	// 6c <hgusb11_dev_ep0_get_status+0x6c>
  10:	d84000f3 	ld.b      	r2, (r0, 0xf3)
  14:	e902fffc 	bez      	r2, 0xc	// c <hgusb11_dev_ep0_get_status+0xc>
  18:	e463201f 	andi      	r3, r3, 31
  1c:	3b41      	cmpnei      	r3, 1
  1e:	3100      	movi      	r1, 0
  20:	dc200113 	st.b      	r1, (r0, 0x113)
  24:	0c1c      	bf      	0x5c	// 5c <hgusb11_dev_ep0_get_status+0x5c>
  26:	3b40      	cmpnei      	r3, 0
  28:	0c1c      	bf      	0x60	// 60 <hgusb11_dev_ep0_get_status+0x60>
  2a:	3b42      	cmpnei      	r3, 2
  2c:	0bf0      	bt      	0xc	// c <hgusb11_dev_ep0_get_status+0xc>
  2e:	3a41      	cmpnei      	r2, 1
  30:	d8601074 	ld.h      	r3, (r0, 0xe8)
  34:	0804      	bt      	0x3c	// 3c <hgusb11_dev_ep0_get_status+0x3c>
  36:	748c      	zextb      	r2, r3
  38:	e922ffea 	bnez      	r2, 0xc	// c <hgusb11_dev_ep0_get_status+0xc>
  3c:	74cd      	zexth      	r3, r3
  3e:	e443207f 	andi      	r2, r3, 127
  42:	3a02      	cmphsi      	r2, 3
  44:	080e      	bt      	0x60	// 60 <hgusb11_dev_ep0_get_status+0x60>
  46:	74ce      	sextb      	r3, r3
  48:	e9a30013 	bhsz      	r3, 0x6e	// 6e <hgusb11_dev_ep0_get_status+0x6e>
  4c:	d8600101 	ld.b      	r3, (r0, 0x101)
  50:	e9030008 	bez      	r3, 0x60	// 60 <hgusb11_dev_ep0_get_status+0x60>
  54:	3301      	movi      	r3, 1
  56:	dc600113 	st.b      	r3, (r0, 0x113)
  5a:	0403      	br      	0x60	// 60 <hgusb11_dev_ep0_get_status+0x60>
  5c:	3a41      	cmpnei      	r2, 1
  5e:	0fd7      	bf      	0xc	// c <hgusb11_dev_ep0_get_status+0xc>
  60:	3300      	movi      	r3, 0
  62:	dc600114 	st.b      	r3, (r0, 0x114)
  66:	3102      	movi      	r1, 2
  68:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_get_status>
  6c:	1490      	pop      	r15
  6e:	d8600102 	ld.b      	r3, (r0, 0x102)
  72:	07ef      	br      	0x50	// 50 <hgusb11_dev_ep0_get_status+0x50>

Disassembly of section .text.hgusb11_dev_ep0_clr_feature:

00000000 <hgusb11_dev_ep0_clr_feature>:
   0:	14d1      	push      	r4, r15
   2:	d86000f3 	ld.b      	r3, (r0, 0xf3)
   6:	6d03      	mov      	r4, r0
   8:	e903001b 	bez      	r3, 0x3e	// 3e <hgusb11_dev_ep0_clr_feature+0x3e>
   c:	d84000e4 	ld.b      	r2, (r0, 0xe4)
  10:	e442201f 	andi      	r2, r2, 31
  14:	3a42      	cmpnei      	r2, 2
  16:	0814      	bt      	0x3e	// 3e <hgusb11_dev_ep0_clr_feature+0x3e>
  18:	d8001073 	ld.h      	r0, (r0, 0xe6)
  1c:	e9200011 	bnez      	r0, 0x3e	// 3e <hgusb11_dev_ep0_clr_feature+0x3e>
  20:	3b41      	cmpnei      	r3, 1
  22:	d8241074 	ld.h      	r1, (r4, 0xe8)
  26:	0804      	bt      	0x2e	// 2e <hgusb11_dev_ep0_clr_feature+0x2e>
  28:	74c4      	zextb      	r3, r1
  2a:	e9230009 	bnez      	r3, 0x3c	// 3c <hgusb11_dev_ep0_clr_feature+0x3c>
  2e:	6c13      	mov      	r0, r4
  30:	7444      	zextb      	r1, r1
  32:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_clr_feature>
  36:	6c13      	mov      	r0, r4
  38:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_clr_feature>
  3c:	1491      	pop      	r4, r15
  3e:	3000      	movi      	r0, 0
  40:	07fe      	br      	0x3c	// 3c <hgusb11_dev_ep0_clr_feature+0x3c>

Disassembly of section .text.hgusb11_dev_ep0_set_feature:

00000000 <hgusb11_dev_ep0_set_feature>:
   0:	14d1      	push      	r4, r15
   2:	d86000e4 	ld.b      	r3, (r0, 0xe4)
   6:	e463201f 	andi      	r3, r3, 31
   a:	3b42      	cmpnei      	r3, 2
   c:	6d03      	mov      	r4, r0
   e:	0816      	bt      	0x3a	// 3a <hgusb11_dev_ep0_set_feature+0x3a>
  10:	d8001073 	ld.h      	r0, (r0, 0xe6)
  14:	e9200013 	bnez      	r0, 0x3a	// 3a <hgusb11_dev_ep0_set_feature+0x3a>
  18:	d86400f3 	ld.b      	r3, (r4, 0xf3)
  1c:	3b41      	cmpnei      	r3, 1
  1e:	d8241074 	ld.h      	r1, (r4, 0xe8)
  22:	0804      	bt      	0x2a	// 2a <hgusb11_dev_ep0_set_feature+0x2a>
  24:	74c4      	zextb      	r3, r1
  26:	e9230009 	bnez      	r3, 0x38	// 38 <hgusb11_dev_ep0_set_feature+0x38>
  2a:	6c13      	mov      	r0, r4
  2c:	7444      	zextb      	r1, r1
  2e:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_set_feature>
  32:	6c13      	mov      	r0, r4
  34:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_set_feature>
  38:	1491      	pop      	r4, r15
  3a:	3000      	movi      	r0, 0
  3c:	07fe      	br      	0x38	// 38 <hgusb11_dev_ep0_set_feature+0x38>

Disassembly of section .text.hgusb11_dev_ep0_set_address:

00000000 <hgusb11_dev_ep0_set_address>:
   0:	14d0      	push      	r15
   2:	d86000f3 	ld.b      	r3, (r0, 0xf3)
   6:	3b41      	cmpnei      	r3, 1
   8:	0c14      	bf      	0x30	// 30 <hgusb11_dev_ep0_set_address+0x30>
   a:	3b40      	cmpnei      	r3, 0
   c:	0c0a      	bf      	0x20	// 20 <hgusb11_dev_ep0_set_address+0x20>
   e:	3b42      	cmpnei      	r3, 2
  10:	0c15      	bf      	0x3a	// 3a <hgusb11_dev_ep0_set_address+0x3a>
  12:	3301      	movi      	r3, 1
  14:	dc6000f1 	st.b      	r3, (r0, 0xf1)
  18:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_set_address>
  1c:	3001      	movi      	r0, 1
  1e:	1490      	pop      	r15
  20:	d8601073 	ld.h      	r3, (r0, 0xe6)
  24:	e903fff7 	bez      	r3, 0x12	// 12 <hgusb11_dev_ep0_set_address+0x12>
  28:	3301      	movi      	r3, 1
  2a:	dc6000f3 	st.b      	r3, (r0, 0xf3)
  2e:	07f2      	br      	0x12	// 12 <hgusb11_dev_ep0_set_address+0x12>
  30:	d8601073 	ld.h      	r3, (r0, 0xe6)
  34:	e923ffef 	bnez      	r3, 0x12	// 12 <hgusb11_dev_ep0_set_address+0x12>
  38:	07f9      	br      	0x2a	// 2a <hgusb11_dev_ep0_set_address+0x2a>
  3a:	3000      	movi      	r0, 0
  3c:	07f1      	br      	0x1e	// 1e <hgusb11_dev_ep0_set_address+0x1e>

Disassembly of section .text.hgusb11_dev_ep0_transfer:

00000000 <hgusb11_dev_ep0_transfer>:
   0:	14d3      	push      	r4-r6, r15
   2:	d8c0107e 	ld.h      	r6, (r0, 0xfc)
   6:	6d03      	mov      	r4, r0
   8:	e5800112 	addi      	r12, r0, 275
   c:	e906002c 	bez      	r6, 0x64	// 64 <hgusb11_dev_ep0_transfer+0x64>
  10:	d8a000f5 	ld.b      	r5, (r0, 0xf5)
  14:	74d8      	zextb      	r3, r6
  16:	6594      	cmphs      	r5, r6
  18:	c4a30c40 	inct      	r5, r3, 0
  1c:	6196      	subu      	r6, r5
  1e:	dcc0107e 	st.h      	r6, (r0, 0xfc)
  22:	d8c0203e 	ld.w      	r6, (r0, 0xf8)
  26:	6c5b      	mov      	r1, r6
  28:	6c97      	mov      	r2, r5
  2a:	6c33      	mov      	r0, r12
  2c:	e0000000 	bsr      	0x0	// 0 <memcpy>
  30:	9463      	ld.w      	r3, (r4, 0xc)
  32:	3200      	movi      	r2, 0
  34:	6194      	addu      	r6, r5
  36:	dcc4203e 	st.w      	r6, (r4, 0xf8)
  3a:	3100      	movi      	r1, 0
  3c:	a34e      	st.b      	r2, (r3, 0xe)
  3e:	6c83      	mov      	r2, r0
  40:	6cd7      	mov      	r3, r5
  42:	6c13      	mov      	r0, r4
  44:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep_tx_kick>
  48:	d86400f5 	ld.b      	r3, (r4, 0xf5)
  4c:	654e      	cmpne      	r3, r5
  4e:	0c12      	bf      	0x72	// 72 <hgusb11_dev_ep0_transfer+0x72>
  50:	3301      	movi      	r3, 1
  52:	dc6400f4 	st.b      	r3, (r4, 0xf4)
  56:	320a      	movi      	r2, 10
  58:	9463      	ld.w      	r3, (r4, 0xc)
  5a:	3100      	movi      	r1, 0
  5c:	3001      	movi      	r0, 1
  5e:	a32e      	st.b      	r1, (r3, 0xe)
  60:	a351      	st.b      	r2, (r3, 0x11)
  62:	1493      	pop      	r4-r6, r15
  64:	6cdb      	mov      	r3, r6
  66:	6cb3      	mov      	r2, r12
  68:	6c5b      	mov      	r1, r6
  6a:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep_tx_kick>
  6e:	6d5b      	mov      	r5, r6
  70:	07ec      	br      	0x48	// 48 <hgusb11_dev_ep0_transfer+0x48>
  72:	3202      	movi      	r2, 2
  74:	07f2      	br      	0x58	// 58 <hgusb11_dev_ep0_transfer+0x58>

Disassembly of section .text.hgusb11_dev_ep0_descriptor:

00000000 <hgusb11_dev_ep0_descriptor>:
   0:	14d1      	push      	r4, r15
   2:	d8601075 	ld.h      	r3, (r0, 0xea)
   6:	6d03      	mov      	r4, r0
   8:	740d      	zexth      	r0, r3
   a:	6408      	cmphs      	r2, r0
   c:	0802      	bt      	0x10	// 10 <hgusb11_dev_ep0_descriptor+0x10>
   e:	6ccb      	mov      	r3, r2
  10:	dc64107e 	st.h      	r3, (r4, 0xfc)
  14:	3302      	movi      	r3, 2
  16:	dc24203e 	st.w      	r1, (r4, 0xf8)
  1a:	dc6400f4 	st.b      	r3, (r4, 0xf4)
  1e:	e4440154 	addi      	r2, r4, 341
  22:	3100      	movi      	r1, 0
  24:	3342      	movi      	r3, 66
  26:	6c13      	mov      	r0, r4
  28:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep_rx_kick>
  2c:	9463      	ld.w      	r3, (r4, 0xc)
  2e:	3200      	movi      	r2, 0
  30:	a34e      	st.b      	r2, (r3, 0xe)
  32:	3240      	movi      	r2, 64
  34:	a351      	st.b      	r2, (r3, 0x11)
  36:	6c13      	mov      	r0, r4
  38:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_descriptor>
  3c:	1491      	pop      	r4, r15

Disassembly of section .text.hgusb11_dev_ep0_get_descriptor:

00000000 <hgusb11_dev_ep0_get_descriptor>:
   0:	14d3      	push      	r4-r6, r15
   2:	d8601073 	ld.h      	r3, (r0, 0xe6)
   6:	4ba8      	lsri      	r5, r3, 8
   8:	3d42      	cmpnei      	r5, 2
   a:	6d03      	mov      	r4, r0
   c:	0c28      	bf      	0x5c	// 5c <hgusb11_dev_ep0_get_descriptor+0x5c>
   e:	3d02      	cmphsi      	r5, 3
  10:	0805      	bt      	0x1a	// 1a <hgusb11_dev_ep0_get_descriptor+0x1a>
  12:	3d41      	cmpnei      	r5, 1
  14:	0c1e      	bf      	0x50	// 50 <hgusb11_dev_ep0_get_descriptor+0x50>
  16:	3000      	movi      	r0, 0
  18:	0421      	br      	0x5a	// 5a <hgusb11_dev_ep0_get_descriptor+0x5a>
  1a:	3d43      	cmpnei      	r5, 3
  1c:	0c29      	bf      	0x6e	// 6e <hgusb11_dev_ep0_get_descriptor+0x6e>
  1e:	3d46      	cmpnei      	r5, 6
  20:	0bfb      	bt      	0x16	// 16 <hgusb11_dev_ep0_get_descriptor+0x16>
  22:	90d2      	ld.w      	r6, (r0, 0x48)
  24:	e46001a8 	addi      	r3, r0, 425
  28:	3208      	movi      	r2, 8
  2a:	6c5b      	mov      	r1, r6
  2c:	6c0f      	mov      	r0, r3
  2e:	e0000000 	bsr      	0x0	// 0 <memcpy>
  32:	320a      	movi      	r2, 10
  34:	dc4401a9 	st.b      	r2, (r4, 0x1a9)
  38:	dca401aa 	st.b      	r5, (r4, 0x1aa)
  3c:	8651      	ld.b      	r2, (r6, 0x11)
  3e:	dc4401b1 	st.b      	r2, (r4, 0x1b1)
  42:	3200      	movi      	r2, 0
  44:	dc4401b2 	st.b      	r2, (r4, 0x1b2)
  48:	6c43      	mov      	r1, r0
  4a:	320a      	movi      	r2, 10
  4c:	6c13      	mov      	r0, r4
  4e:	0404      	br      	0x56	// 56 <hgusb11_dev_ep0_get_descriptor+0x56>
  50:	3212      	movi      	r2, 18
  52:	e4200196 	addi      	r1, r0, 407
  56:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_get_descriptor>
  5a:	1493      	pop      	r4-r6, r15
  5c:	d84001b5 	ld.b      	r2, (r0, 0x1b5)
  60:	d86001b6 	ld.b      	r3, (r0, 0x1b6)
  64:	4368      	lsli      	r3, r3, 8
  66:	6c8c      	or      	r2, r3
  68:	e42001b2 	addi      	r1, r0, 435
  6c:	07f5      	br      	0x56	// 56 <hgusb11_dev_ep0_get_descriptor+0x56>
  6e:	74cc      	zextb      	r3, r3
  70:	3b41      	cmpnei      	r3, 1
  72:	0c0f      	bf      	0x90	// 90 <hgusb11_dev_ep0_get_descriptor+0x90>
  74:	3b40      	cmpnei      	r3, 0
  76:	0c09      	bf      	0x88	// 88 <hgusb11_dev_ep0_get_descriptor+0x88>
  78:	3b42      	cmpnei      	r3, 2
  7a:	0c0f      	bf      	0x98	// 98 <hgusb11_dev_ep0_get_descriptor+0x98>
  7c:	3b43      	cmpnei      	r3, 3
  7e:	0bcc      	bt      	0x16	// 16 <hgusb11_dev_ep0_get_descriptor+0x16>
  80:	d840103c 	ld.h      	r2, (r0, 0x78)
  84:	903d      	ld.w      	r1, (r0, 0x74)
  86:	07e8      	br      	0x56	// 56 <hgusb11_dev_ep0_get_descriptor+0x56>
  88:	d8401030 	ld.h      	r2, (r0, 0x60)
  8c:	9037      	ld.w      	r1, (r0, 0x5c)
  8e:	07e4      	br      	0x56	// 56 <hgusb11_dev_ep0_get_descriptor+0x56>
  90:	d8401034 	ld.h      	r2, (r0, 0x68)
  94:	9039      	ld.w      	r1, (r0, 0x64)
  96:	07e0      	br      	0x56	// 56 <hgusb11_dev_ep0_get_descriptor+0x56>
  98:	d8401038 	ld.h      	r2, (r0, 0x70)
  9c:	903b      	ld.w      	r1, (r0, 0x6c)
  9e:	07dc      	br      	0x56	// 56 <hgusb11_dev_ep0_get_descriptor+0x56>

Disassembly of section .text.hgusb11_dev_ep0_get_configuration:

00000000 <hgusb11_dev_ep0_get_configuration>:
   0:	14d0      	push      	r15
   2:	d86000f3 	ld.b      	r3, (r0, 0xf3)
   6:	e903000a 	bez      	r3, 0x1a	// 1a <hgusb11_dev_ep0_get_configuration+0x1a>
   a:	d86000f2 	ld.b      	r3, (r0, 0xf2)
   e:	dc600113 	st.b      	r3, (r0, 0x113)
  12:	3101      	movi      	r1, 1
  14:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_get_configuration>
  18:	1490      	pop      	r15
  1a:	6c0f      	mov      	r0, r3
  1c:	07fe      	br      	0x18	// 18 <hgusb11_dev_ep0_get_configuration+0x18>

Disassembly of section .text.hgusb11_dev_ep0_set_configuration:

00000000 <hgusb11_dev_ep0_set_configuration>:
   0:	14d1      	push      	r4, r15
   2:	d86000f3 	ld.b      	r3, (r0, 0xf3)
   6:	6d03      	mov      	r4, r0
   8:	e9230004 	bnez      	r3, 0x10	// 10 <hgusb11_dev_ep0_set_configuration+0x10>
   c:	3000      	movi      	r0, 0
   e:	1491      	pop      	r4, r15
  10:	9043      	ld.w      	r2, (r0, 0xc)
  12:	3305      	movi      	r3, 5
  14:	a26b      	st.b      	r3, (r2, 0xb)
  16:	3300      	movi      	r3, 0
  18:	2b7e      	subi      	r3, 127
  1a:	a261      	st.b      	r3, (r2, 0x1)
  1c:	d8601073 	ld.h      	r3, (r0, 0xe6)
  20:	3b01      	cmphsi      	r3, 2
  22:	0bf5      	bt      	0xc	// c <hgusb11_dev_ep0_set_configuration+0xc>
  24:	3b40      	cmpnei      	r3, 0
  26:	dc6000f2 	st.b      	r3, (r0, 0xf2)
  2a:	c4000503 	mvc      	r3
  2e:	2300      	addi      	r3, 1
  30:	dc6000f3 	st.b      	r3, (r0, 0xf3)
  34:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_set_configuration>
  38:	9463      	ld.w      	r3, (r4, 0xc)
  3a:	3200      	movi      	r2, 0
  3c:	a34e      	st.b      	r2, (r3, 0xe)
  3e:	6c13      	mov      	r0, r4
  40:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_set_configuration>
  44:	07e5      	br      	0xe	// e <hgusb11_dev_ep0_set_configuration+0xe>

Disassembly of section .text.hgusb11_dev_ep0_get_interface:

00000000 <hgusb11_dev_ep0_get_interface>:
   0:	14d0      	push      	r15
   2:	d84000f3 	ld.b      	r2, (r0, 0xf3)
   6:	3a42      	cmpnei      	r2, 2
   8:	0809      	bt      	0x1a	// 1a <hgusb11_dev_ep0_get_interface+0x1a>
   a:	d84001bf 	ld.b      	r2, (r0, 0x1bf)
   e:	dc400113 	st.b      	r2, (r0, 0x113)
  12:	3101      	movi      	r1, 1
  14:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_get_interface>
  18:	1490      	pop      	r15
  1a:	3000      	movi      	r0, 0
  1c:	07fe      	br      	0x18	// 18 <hgusb11_dev_ep0_get_interface+0x18>

Disassembly of section .text.hgusb11_dev_ep0_set_interface:

00000000 <hgusb11_dev_ep0_set_interface>:
   0:	14d0      	push      	r15
   2:	d86000f3 	ld.b      	r3, (r0, 0xf3)
   6:	3b42      	cmpnei      	r3, 2
   8:	0804      	bt      	0x10	// 10 <hgusb11_dev_ep0_set_interface+0x10>
   a:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_set_interface>
   e:	1490      	pop      	r15
  10:	3000      	movi      	r0, 0
  12:	07fe      	br      	0xe	// e <hgusb11_dev_ep0_set_interface+0xe>

Disassembly of section .text.hgusb11_dev_ep0_standard:

00000000 <hgusb11_dev_ep0_standard>:
   0:	14d0      	push      	r15
   2:	d86000e5 	ld.b      	r3, (r0, 0xe5)
   6:	3b0b      	cmphsi      	r3, 12
   8:	0827      	bt      	0x56	// 56 <hgusb11_dev_ep0_standard+0x56>
   a:	1043      	lrw      	r2, 0x0	// 14 <hgusb11_dev_ep0_standard+0x14>
   c:	d0620883 	ldr.w      	r3, (r2, r3 << 2)
  10:	780c      	jmp      	r3
  12:	0000      	.short	0x0000
  14:	00000000 	.long	0x00000000
  18:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_standard>
  1c:	1490      	pop      	r15
  1e:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_standard>
  22:	07fd      	br      	0x1c	// 1c <hgusb11_dev_ep0_standard+0x1c>
  24:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_standard>
  28:	07fa      	br      	0x1c	// 1c <hgusb11_dev_ep0_standard+0x1c>
  2a:	106d      	lrw      	r3, 0x0	// 5c <hgusb11_dev_ep0_standard+0x5c>
  2c:	8367      	ld.b      	r3, (r3, 0x7)
  2e:	dc6000f5 	st.b      	r3, (r0, 0xf5)
  32:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_standard>
  36:	07f3      	br      	0x1c	// 1c <hgusb11_dev_ep0_standard+0x1c>
  38:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_standard>
  3c:	07f0      	br      	0x1c	// 1c <hgusb11_dev_ep0_standard+0x1c>
  3e:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_standard>
  42:	07ed      	br      	0x1c	// 1c <hgusb11_dev_ep0_standard+0x1c>
  44:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_standard>
  48:	07ea      	br      	0x1c	// 1c <hgusb11_dev_ep0_standard+0x1c>
  4a:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_standard>
  4e:	07e7      	br      	0x1c	// 1c <hgusb11_dev_ep0_standard+0x1c>
  50:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_standard>
  54:	07e4      	br      	0x1c	// 1c <hgusb11_dev_ep0_standard+0x1c>
  56:	3000      	movi      	r0, 0
  58:	07e2      	br      	0x1c	// 1c <hgusb11_dev_ep0_standard+0x1c>
  5a:	0000      	.short	0x0000
  5c:	00000000 	.long	0x00000000

Disassembly of section .text.hgusb11_dev_ep0_class_reset:

00000000 <hgusb11_dev_ep0_class_reset>:
   0:	14d0      	push      	r15
   2:	d84000f3 	ld.b      	r2, (r0, 0xf3)
   6:	3a42      	cmpnei      	r2, 2
   8:	0809      	bt      	0x1a	// 1a <hgusb11_dev_ep0_class_reset+0x1a>
   a:	9063      	ld.w      	r3, (r0, 0xc)
   c:	3200      	movi      	r2, 0
   e:	dc400103 	st.b      	r2, (r0, 0x103)
  12:	a34e      	st.b      	r2, (r3, 0xe)
  14:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_class_reset>
  18:	1490      	pop      	r15
  1a:	3000      	movi      	r0, 0
  1c:	07fe      	br      	0x18	// 18 <hgusb11_dev_ep0_class_reset+0x18>

Disassembly of section .text.hgusb11_dev_ep0_class_get_lun:

00000000 <hgusb11_dev_ep0_class_get_lun>:
   0:	14d0      	push      	r15
   2:	3300      	movi      	r3, 0
   4:	dc600113 	st.b      	r3, (r0, 0x113)
   8:	3101      	movi      	r1, 1
   a:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_class_get_lun>
   e:	1490      	pop      	r15

Disassembly of section .text.hgusb11_dev_ep0_audio_sample_ctrl:

00000000 <hgusb11_dev_ep0_audio_sample_ctrl>:
   0:	d8401075 	ld.h      	r2, (r0, 0xea)
   4:	3a43      	cmpnei      	r2, 3
   6:	080e      	bt      	0x22	// 22 <hgusb11_dev_ep0_audio_sample_ctrl+0x22>
   8:	d86000e5 	ld.b      	r3, (r0, 0xe5)
   c:	3b41      	cmpnei      	r3, 1
   e:	080a      	bt      	0x22	// 22 <hgusb11_dev_ep0_audio_sample_ctrl+0x22>
  10:	dc4000f4 	st.b      	r2, (r0, 0xf4)
  14:	9043      	ld.w      	r2, (r0, 0xc)
  16:	3100      	movi      	r1, 0
  18:	a22e      	st.b      	r1, (r2, 0xe)
  1a:	3140      	movi      	r1, 64
  1c:	a231      	st.b      	r1, (r2, 0x11)
  1e:	6c0f      	mov      	r0, r3
  20:	783c      	jmp      	r15
  22:	3000      	movi      	r0, 0
  24:	07fe      	br      	0x20	// 20 <hgusb11_dev_ep0_audio_sample_ctrl+0x20>

Disassembly of section .text.hgusb11_dev_ep0_audio_mute_ctrl:

00000000 <hgusb11_dev_ep0_audio_mute_ctrl>:
   0:	14d0      	push      	r15
   2:	d8201075 	ld.h      	r1, (r0, 0xea)
   6:	3941      	cmpnei      	r1, 1
   8:	0819      	bt      	0x3a	// 3a <hgusb11_dev_ep0_audio_mute_ctrl+0x3a>
   a:	d8401072 	ld.h      	r2, (r0, 0xe4)
   e:	eb420121 	cmpnei      	r2, 289
  12:	080b      	bt      	0x28	// 28 <hgusb11_dev_ep0_audio_mute_ctrl+0x28>
  14:	9063      	ld.w      	r3, (r0, 0xc)
  16:	3203      	movi      	r2, 3
  18:	dc4000f4 	st.b      	r2, (r0, 0xf4)
  1c:	3200      	movi      	r2, 0
  1e:	a34e      	st.b      	r2, (r3, 0xe)
  20:	3240      	movi      	r2, 64
  22:	a351      	st.b      	r2, (r3, 0x11)
  24:	6c07      	mov      	r0, r1
  26:	1490      	pop      	r15
  28:	eb4281a1 	cmpnei      	r2, 33185
  2c:	0807      	bt      	0x3a	// 3a <hgusb11_dev_ep0_audio_mute_ctrl+0x3a>
  2e:	3200      	movi      	r2, 0
  30:	dc400113 	st.b      	r2, (r0, 0x113)
  34:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_audio_mute_ctrl>
  38:	07f7      	br      	0x26	// 26 <hgusb11_dev_ep0_audio_mute_ctrl+0x26>
  3a:	3000      	movi      	r0, 0
  3c:	07f5      	br      	0x26	// 26 <hgusb11_dev_ep0_audio_mute_ctrl+0x26>

Disassembly of section .text.hgusb11_dev_ep0_audio_volume_ctrl:

00000000 <hgusb11_dev_ep0_audio_volume_ctrl>:
   0:	14d0      	push      	r15
   2:	d8601075 	ld.h      	r3, (r0, 0xea)
   6:	3b42      	cmpnei      	r3, 2
   8:	0839      	bt      	0x7a	// 7a <hgusb11_dev_ep0_audio_volume_ctrl+0x7a>
   a:	d8601072 	ld.h      	r3, (r0, 0xe4)
   e:	eb430121 	cmpnei      	r3, 289
  12:	080b      	bt      	0x28	// 28 <hgusb11_dev_ep0_audio_volume_ctrl+0x28>
  14:	3303      	movi      	r3, 3
  16:	dc6000f4 	st.b      	r3, (r0, 0xf4)
  1a:	9063      	ld.w      	r3, (r0, 0xc)
  1c:	3200      	movi      	r2, 0
  1e:	a34e      	st.b      	r2, (r3, 0xe)
  20:	3240      	movi      	r2, 64
  22:	a351      	st.b      	r2, (r3, 0x11)
  24:	3001      	movi      	r0, 1
  26:	1490      	pop      	r15
  28:	d86000e4 	ld.b      	r3, (r0, 0xe4)
  2c:	eb4300a1 	cmpnei      	r3, 161
  30:	0825      	bt      	0x7a	// 7a <hgusb11_dev_ep0_audio_volume_ctrl+0x7a>
  32:	d86000e5 	ld.b      	r3, (r0, 0xe5)
  36:	eb430081 	cmpnei      	r3, 129
  3a:	080d      	bt      	0x54	// 54 <hgusb11_dev_ep0_audio_volume_ctrl+0x54>
  3c:	d860010a 	ld.b      	r3, (r0, 0x10a)
  40:	dc600113 	st.b      	r3, (r0, 0x113)
  44:	3300      	movi      	r3, 0
  46:	2b7f      	subi      	r3, 128
  48:	dc600114 	st.b      	r3, (r0, 0x114)
  4c:	3102      	movi      	r1, 2
  4e:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_audio_volume_ctrl>
  52:	07ea      	br      	0x26	// 26 <hgusb11_dev_ep0_audio_volume_ctrl+0x26>
  54:	eb430082 	cmpnei      	r3, 130
  58:	0803      	bt      	0x5e	// 5e <hgusb11_dev_ep0_audio_volume_ctrl+0x5e>
  5a:	3300      	movi      	r3, 0
  5c:	07f2      	br      	0x40	// 40 <hgusb11_dev_ep0_audio_volume_ctrl+0x40>
  5e:	eb430083 	cmpnei      	r3, 131
  62:	0804      	bt      	0x6a	// 6a <hgusb11_dev_ep0_audio_volume_ctrl+0x6a>
  64:	3300      	movi      	r3, 0
  66:	2b0f      	subi      	r3, 16
  68:	07ec      	br      	0x40	// 40 <hgusb11_dev_ep0_audio_volume_ctrl+0x40>
  6a:	eb430084 	cmpnei      	r3, 132
  6e:	0806      	bt      	0x7a	// 7a <hgusb11_dev_ep0_audio_volume_ctrl+0x7a>
  70:	3301      	movi      	r3, 1
  72:	dc600113 	st.b      	r3, (r0, 0x113)
  76:	3300      	movi      	r3, 0
  78:	07e8      	br      	0x48	// 48 <hgusb11_dev_ep0_audio_volume_ctrl+0x48>
  7a:	3000      	movi      	r0, 0
  7c:	07d5      	br      	0x26	// 26 <hgusb11_dev_ep0_audio_volume_ctrl+0x26>

Disassembly of section .text.hgusb11_dev_ep0_class:

00000000 <hgusb11_dev_ep0_class>:
   0:	14d0      	push      	r15
   2:	d84000e4 	ld.b      	r2, (r0, 0xe4)
   6:	eb420022 	cmpnei      	r2, 34
   a:	6cc3      	mov      	r3, r0
   c:	0809      	bt      	0x1e	// 1e <hgusb11_dev_ep0_class+0x1e>
   e:	d8601073 	ld.h      	r3, (r0, 0xe6)
  12:	4b68      	lsri      	r3, r3, 8
  14:	3b41      	cmpnei      	r3, 1
  16:	0834      	bt      	0x7e	// 7e <hgusb11_dev_ep0_class+0x7e>
  18:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_class>
  1c:	1490      	pop      	r15
  1e:	d8401074 	ld.h      	r2, (r0, 0xe8)
  22:	4a28      	lsri      	r1, r2, 8
  24:	3942      	cmpnei      	r1, 2
  26:	0c03      	bf      	0x2c	// 2c <hgusb11_dev_ep0_class+0x2c>
  28:	3945      	cmpnei      	r1, 5
  2a:	0810      	bt      	0x4a	// 4a <hgusb11_dev_ep0_class+0x4a>
  2c:	d8431073 	ld.h      	r2, (r3, 0xe6)
  30:	4a48      	lsri      	r2, r2, 8
  32:	3a41      	cmpnei      	r2, 1
  34:	0805      	bt      	0x3e	// 3e <hgusb11_dev_ep0_class+0x3e>
  36:	6c0f      	mov      	r0, r3
  38:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_class>
  3c:	07f0      	br      	0x1c	// 1c <hgusb11_dev_ep0_class+0x1c>
  3e:	3a42      	cmpnei      	r2, 2
  40:	081f      	bt      	0x7e	// 7e <hgusb11_dev_ep0_class+0x7e>
  42:	6c0f      	mov      	r0, r3
  44:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_class>
  48:	07ea      	br      	0x1c	// 1c <hgusb11_dev_ep0_class+0x1c>
  4a:	d8201072 	ld.h      	r1, (r0, 0xe4)
  4e:	eb410a21 	cmpnei      	r1, 2593
  52:	0804      	bt      	0x5a	// 5a <hgusb11_dev_ep0_class+0x5a>
  54:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_class>
  58:	07e2      	br      	0x1c	// 1c <hgusb11_dev_ep0_class+0x1c>
  5a:	e9220012 	bnez      	r2, 0x7e	// 7e <hgusb11_dev_ep0_class+0x7e>
  5e:	d8601073 	ld.h      	r3, (r0, 0xe6)
  62:	e923000e 	bnez      	r3, 0x7e	// 7e <hgusb11_dev_ep0_class+0x7e>
  66:	eb41ff21 	cmpnei      	r1, 65313
  6a:	0804      	bt      	0x72	// 72 <hgusb11_dev_ep0_class+0x72>
  6c:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_class>
  70:	07d6      	br      	0x1c	// 1c <hgusb11_dev_ep0_class+0x1c>
  72:	eb41fea1 	cmpnei      	r1, 65185
  76:	0806      	bt      	0x82	// 82 <hgusb11_dev_ep0_class+0x82>
  78:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_class>
  7c:	07d0      	br      	0x1c	// 1c <hgusb11_dev_ep0_class+0x1c>
  7e:	3000      	movi      	r0, 0
  80:	07ce      	br      	0x1c	// 1c <hgusb11_dev_ep0_class+0x1c>
  82:	6c0f      	mov      	r0, r3
  84:	07cc      	br      	0x1c	// 1c <hgusb11_dev_ep0_class+0x1c>

Disassembly of section .text.hgusb11_dev_ep0_request:

00000000 <hgusb11_dev_ep0_request>:
   0:	14d0      	push      	r15
   2:	d86000e4 	ld.b      	r3, (r0, 0xe4)
   6:	e4632060 	andi      	r3, r3, 96
   a:	e9230005 	bnez      	r3, 0x14	// 14 <hgusb11_dev_ep0_request+0x14>
   e:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_request>
  12:	1490      	pop      	r15
  14:	eb430020 	cmpnei      	r3, 32
  18:	0804      	bt      	0x20	// 20 <hgusb11_dev_ep0_request+0x20>
  1a:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_request>
  1e:	07fa      	br      	0x12	// 12 <hgusb11_dev_ep0_request+0x12>
  20:	3000      	movi      	r0, 0
  22:	07f8      	br      	0x12	// 12 <hgusb11_dev_ep0_request+0x12>

Disassembly of section .text.hgusb11_dev_ep0_receive:

00000000 <hgusb11_dev_ep0_receive>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_receive>
   6:	1490      	pop      	r15

Disassembly of section .text.hgusb11_dev_ep0_func:

00000000 <hgusb11_dev_ep0_func>:
   0:	14d3      	push      	r4-r6, r15
   2:	9063      	ld.w      	r3, (r0, 0xc)
   4:	6d03      	mov      	r4, r0
   6:	3500      	movi      	r5, 0
   8:	83ce      	ld.b      	r6, (r3, 0xe)
   a:	a3ae      	st.b      	r5, (r3, 0xe)
   c:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_func>
  10:	9443      	ld.w      	r2, (r4, 0xc)
  12:	7598      	zextb      	r6, r6
  14:	a2ae      	st.b      	r5, (r2, 0xe)
  16:	8271      	ld.b      	r3, (r2, 0x11)
  18:	74cc      	zextb      	r3, r3
  1a:	e4232004 	andi      	r1, r3, 4
  1e:	e9010006 	bez      	r1, 0x2a	// 2a <hgusb11_dev_ep0_func+0x2a>
  22:	a2ae      	st.b      	r5, (r2, 0xe)
  24:	a2b1      	st.b      	r5, (r2, 0x11)
  26:	dca400f4 	st.b      	r5, (r4, 0xf4)
  2a:	e4432010 	andi      	r2, r3, 16
  2e:	e902000a 	bez      	r2, 0x42	// 42 <hgusb11_dev_ep0_func+0x42>
  32:	9403      	ld.w      	r0, (r4, 0xc)
  34:	3200      	movi      	r2, 0
  36:	3100      	movi      	r1, 0
  38:	2a7f      	subi      	r2, 128
  3a:	a02e      	st.b      	r1, (r0, 0xe)
  3c:	a051      	st.b      	r2, (r0, 0x11)
  3e:	dc2400f4 	st.b      	r1, (r4, 0xf4)
  42:	d84400f4 	ld.b      	r2, (r4, 0xf4)
  46:	3a41      	cmpnei      	r2, 1
  48:	0804      	bt      	0x50	// 50 <hgusb11_dev_ep0_func+0x50>
  4a:	3200      	movi      	r2, 0
  4c:	dc4400f4 	st.b      	r2, (r4, 0xf4)
  50:	d84400f4 	ld.b      	r2, (r4, 0xf4)
  54:	3a42      	cmpnei      	r2, 2
  56:	0c18      	bf      	0x86	// 86 <hgusb11_dev_ep0_func+0x86>
  58:	3a43      	cmpnei      	r2, 3
  5a:	0c1a      	bf      	0x8e	// 8e <hgusb11_dev_ep0_func+0x8e>
  5c:	e9220012 	bnez      	r2, 0x80	// 80 <hgusb11_dev_ep0_func+0x80>
  60:	e4632001 	andi      	r3, r3, 1
  64:	e903000e 	bez      	r3, 0x80	// 80 <hgusb11_dev_ep0_func+0x80>
  68:	6c13      	mov      	r0, r4
  6a:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_func>
  6e:	6c13      	mov      	r0, r4
  70:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_func>
  74:	6c43      	mov      	r1, r0
  76:	e9200005 	bnez      	r0, 0x80	// 80 <hgusb11_dev_ep0_func+0x80>
  7a:	6c13      	mov      	r0, r4
  7c:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_func>
  80:	9463      	ld.w      	r3, (r4, 0xc)
  82:	a3ce      	st.b      	r6, (r3, 0xe)
  84:	1493      	pop      	r4-r6, r15
  86:	6c13      	mov      	r0, r4
  88:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_func>
  8c:	07fa      	br      	0x80	// 80 <hgusb11_dev_ep0_func+0x80>
  8e:	6c13      	mov      	r0, r4
  90:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_func>
  94:	07f6      	br      	0x80	// 80 <hgusb11_dev_ep0_func+0x80>
