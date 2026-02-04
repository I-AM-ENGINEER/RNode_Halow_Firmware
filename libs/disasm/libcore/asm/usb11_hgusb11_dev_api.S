
disasm/libcore/obj/usb11_hgusb11_dev_api.o:     file format elf32-csky-little


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

Disassembly of section .text.hgusb11_dev_sof_irq_hdl:

00000000 <hgusb11_dev_sof_irq_hdl>:
   0:	14d0      	push      	r15
   2:	d9802005 	ld.w      	r12, (r0, 0x14)
   6:	e90c000a 	bez      	r12, 0x1a	// 1a <hgusb11_dev_sof_irq_hdl+0x1a>
   a:	906e      	ld.w      	r3, (r0, 0x38)
   c:	e9030007 	bez      	r3, 0x1a	// 1a <hgusb11_dev_sof_irq_hdl+0x1a>
  10:	3300      	movi      	r3, 0
  12:	902f      	ld.w      	r1, (r0, 0x3c)
  14:	6c8f      	mov      	r2, r3
  16:	3003      	movi      	r0, 3
  18:	7bf1      	jsr      	r12
  1a:	1490      	pop      	r15

Disassembly of section .text.hgusb11_dev_ep0_task:

00000000 <hgusb11_dev_ep0_task>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	e4a000cf 	addi      	r5, r0, 208
   8:	3100      	movi      	r1, 0
   a:	2900      	subi      	r1, 1
   c:	6c17      	mov      	r0, r5
   e:	e0000000 	bsr      	0x0	// 0 <os_sema_down>
  12:	6c13      	mov      	r0, r4
  14:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep0_func>
  18:	d86400f3 	ld.b      	r3, (r4, 0xf3)
  1c:	3b42      	cmpnei      	r3, 2
  1e:	9464      	ld.w      	r3, (r4, 0x10)
  20:	0809      	bt      	0x32	// 32 <hgusb11_dev_ep0_task+0x32>
  22:	ec630001 	ori      	r3, r3, 1
  26:	b464      	st.w      	r3, (r4, 0x10)
  28:	d8640111 	ld.b      	r3, (r4, 0x111)
  2c:	e903ffee 	bez      	r3, 0x8	// 8 <hgusb11_dev_ep0_task+0x8>
  30:	1492      	pop      	r4-r5, r15
  32:	3b80      	bclri      	r3, 0
  34:	07f9      	br      	0x26	// 26 <hgusb11_dev_ep0_task+0x26>

Disassembly of section .text.hgusb11_dev_ioctl:

00000000 <hgusb11_dev_ioctl>:
   0:	7488      	zextb      	r2, r2
   2:	e9010008 	bez      	r1, 0x12	// 12 <hgusb11_dev_ioctl+0x12>
   6:	3941      	cmpnei      	r1, 1
   8:	0c18      	bf      	0x38	// 38 <hgusb11_dev_ioctl+0x38>
   a:	ea00020b 	movi      	r0, 523
   e:	6c02      	nor      	r0, r0
  10:	040b      	br      	0x26	// 26 <hgusb11_dev_ioctl+0x26>
  12:	3a41      	cmpnei      	r2, 1
  14:	080a      	bt      	0x28	// 28 <hgusb11_dev_ioctl+0x28>
  16:	9043      	ld.w      	r2, (r0, 0xc)
  18:	d86220c6 	ld.w      	r3, (r2, 0x318)
  1c:	ec630100 	ori      	r3, r3, 256
  20:	dc6220c6 	st.w      	r3, (r2, 0x318)
  24:	3000      	movi      	r0, 0
  26:	783c      	jmp      	r15
  28:	3a42      	cmpnei      	r2, 2
  2a:	0bf0      	bt      	0xa	// a <hgusb11_dev_ioctl+0xa>
  2c:	9043      	ld.w      	r2, (r0, 0xc)
  2e:	d86220c6 	ld.w      	r3, (r2, 0x318)
  32:	ec630200 	ori      	r3, r3, 512
  36:	07f5      	br      	0x20	// 20 <hgusb11_dev_ioctl+0x20>
  38:	3a41      	cmpnei      	r2, 1
  3a:	0806      	bt      	0x46	// 46 <hgusb11_dev_ioctl+0x46>
  3c:	9043      	ld.w      	r2, (r0, 0xc)
  3e:	d86220c6 	ld.w      	r3, (r2, 0x318)
  42:	3b88      	bclri      	r3, 8
  44:	07ee      	br      	0x20	// 20 <hgusb11_dev_ioctl+0x20>
  46:	3a42      	cmpnei      	r2, 2
  48:	0be1      	bt      	0xa	// a <hgusb11_dev_ioctl+0xa>
  4a:	9043      	ld.w      	r2, (r0, 0xc)
  4c:	d86220c6 	ld.w      	r3, (r2, 0x318)
  50:	3b89      	bclri      	r3, 9
  52:	07e7      	br      	0x20	// 20 <hgusb11_dev_ioctl+0x20>

Disassembly of section .text.hgusb11_dev_remote_wakeup:

00000000 <hgusb11_dev_remote_wakeup>:
   0:	14d2      	push      	r4-r5, r15
   2:	9063      	ld.w      	r3, (r0, 0xc)
   4:	6d43      	mov      	r5, r0
   6:	8381      	ld.b      	r4, (r3, 0x1)
   8:	7510      	zextb      	r4, r4
   a:	ec440004 	ori      	r2, r4, 4
   e:	a341      	st.b      	r2, (r3, 0x1)
  10:	300a      	movi      	r0, 10
  12:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
  16:	9563      	ld.w      	r3, (r5, 0xc)
  18:	e48420fb 	andi      	r4, r4, 251
  1c:	a381      	st.b      	r4, (r3, 0x1)
  1e:	1492      	pop      	r4-r5, r15

Disassembly of section .text.hgusb11_dev_hw_init:

00000000 <hgusb11_dev_hw_init>:
   0:	14d2      	push      	r4-r5, r15
   2:	1057      	lrw      	r2, 0x40026000	// 5c <hgusb11_dev_hw_init+0x5c>
   4:	6d43      	mov      	r5, r0
   6:	9265      	ld.w      	r3, (r2, 0x14)
   8:	ec631000 	ori      	r3, r3, 4096
   c:	b265      	st.w      	r3, (r2, 0x14)
   e:	9262      	ld.w      	r3, (r2, 0x8)
  10:	3b8c      	bclri      	r3, 12
  12:	b262      	st.w      	r3, (r2, 0x8)
  14:	9262      	ld.w      	r3, (r2, 0x8)
  16:	ec631000 	ori      	r3, r3, 4096
  1a:	b262      	st.w      	r3, (r2, 0x8)
  1c:	e0000000 	bsr      	0x0	// 0 <hgusb11_init_globle>
  20:	6c17      	mov      	r0, r5
  22:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_init>
  26:	e48500bb 	addi      	r4, r5, 188
  2a:	3100      	movi      	r1, 0
  2c:	e40500cf 	addi      	r0, r5, 208
  30:	e0000000 	bsr      	0x0	// 0 <os_sema_init>
  34:	6cd7      	mov      	r3, r5
  36:	104b      	lrw      	r2, 0x0	// 60 <hgusb11_dev_hw_init+0x60>
  38:	6c53      	mov      	r1, r4
  3a:	100b      	lrw      	r0, 0x0	// 64 <hgusb11_dev_hw_init+0x64>
  3c:	e0000000 	bsr      	0x0	// 0 <os_task_init>
  40:	3180      	movi      	r1, 128
  42:	4122      	lsli      	r1, r1, 2
  44:	6c13      	mov      	r0, r4
  46:	e0000000 	bsr      	0x0	// 0 <os_task_set_stacksize>
  4a:	3150      	movi      	r1, 80
  4c:	6c13      	mov      	r0, r4
  4e:	e0000000 	bsr      	0x0	// 0 <_os_task_set_priority>
  52:	6c13      	mov      	r0, r4
  54:	e0000000 	bsr      	0x0	// 0 <os_task_run>
  58:	1492      	pop      	r4-r5, r15
  5a:	0000      	.short	0x0000
  5c:	40026000 	.long	0x40026000
	...

Disassembly of section .text.hgusb11_dev_open:

00000000 <hgusb11_dev_open>:
   0:	14d2      	push      	r4-r5, r15
   2:	904e      	ld.w      	r2, (r0, 0x38)
   4:	6d03      	mov      	r4, r0
   6:	e9220027 	bnez      	r2, 0x54	// 54 <hgusb11_dev_open+0x54>
   a:	8164      	ld.b      	r3, (r1, 0x4)
   c:	3b42      	cmpnei      	r3, 2
   e:	0826      	bt      	0x5a	// 5a <hgusb11_dev_open+0x5a>
  10:	327c      	movi      	r2, 124
  12:	203f      	addi      	r0, 64
  14:	e0000000 	bsr      	0x0	// 0 <memcpy>
  18:	d86411da 	ld.h      	r3, (r4, 0x3b4)
  1c:	dc641020 	st.h      	r3, (r4, 0x40)
  20:	d86411db 	ld.h      	r3, (r4, 0x3b6)
  24:	dc641021 	st.h      	r3, (r4, 0x42)
  28:	3101      	movi      	r1, 1
  2a:	9400      	ld.w      	r0, (r4, 0x0)
  2c:	e0000000 	bsr      	0x0	// 0 <pin_func>
  30:	6d43      	mov      	r5, r0
  32:	e900000a 	bez      	r0, 0x46	// 46 <hgusb11_dev_open+0x46>
  36:	31dc      	movi      	r1, 220
  38:	104b      	lrw      	r2, 0x0	// 64 <hgusb11_dev_open+0x64>
  3a:	4121      	lsli      	r1, r1, 1
  3c:	100b      	lrw      	r0, 0x0	// 68 <hgusb11_dev_open+0x68>
  3e:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  42:	6c17      	mov      	r0, r5
  44:	1492      	pop      	r4-r5, r15
  46:	6c13      	mov      	r0, r4
  48:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_open>
  4c:	3301      	movi      	r3, 1
  4e:	b4ad      	st.w      	r5, (r4, 0x34)
  50:	b46e      	st.w      	r3, (r4, 0x38)
  52:	07f8      	br      	0x42	// 42 <hgusb11_dev_open+0x42>
  54:	3500      	movi      	r5, 0
  56:	2d0f      	subi      	r5, 16
  58:	07f5      	br      	0x42	// 42 <hgusb11_dev_open+0x42>
  5a:	ea05020b 	movi      	r5, 523
  5e:	6d56      	nor      	r5, r5
  60:	07f1      	br      	0x42	// 42 <hgusb11_dev_open+0x42>
	...

Disassembly of section .text.hgusb11_dev_free:

00000000 <hgusb11_dev_free>:
   0:	14d1      	push      	r4, r15
   2:	3301      	movi      	r3, 1
   4:	dc600111 	st.b      	r3, (r0, 0x111)
   8:	6d03      	mov      	r4, r0
   a:	20cf      	addi      	r0, 208
   c:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  10:	6c13      	mov      	r0, r4
  12:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_exit>
  16:	940a      	ld.w      	r0, (r4, 0x28)
  18:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_free>
  1c:	940b      	ld.w      	r0, (r4, 0x2c)
  1e:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_free>
  22:	1491      	pop      	r4, r15

Disassembly of section .text.hgusb11_dev_close:

00000000 <hgusb11_dev_close>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	e4c00017 	addi      	r6, r0, 24
   8:	3100      	movi      	r1, 0
   a:	2900      	subi      	r1, 1
   c:	6c1b      	mov      	r0, r6
   e:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  12:	946e      	ld.w      	r3, (r4, 0x38)
  14:	e9230007 	bnez      	r3, 0x22	// 22 <hgusb11_dev_close+0x22>
  18:	6c1b      	mov      	r0, r6
  1a:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  1e:	3000      	movi      	r0, 0
  20:	1493      	pop      	r4-r6, r15
  22:	940a      	ld.w      	r0, (r4, 0x28)
  24:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_close>
  28:	940b      	ld.w      	r0, (r4, 0x2c)
  2a:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_close>
  2e:	e40400bb 	addi      	r0, r4, 188
  32:	e0000000 	bsr      	0x0	// 0 <os_task_del>
  36:	3100      	movi      	r1, 0
  38:	9400      	ld.w      	r0, (r4, 0x0)
  3a:	e0000000 	bsr      	0x0	// 0 <pin_func>
  3e:	106d      	lrw      	r3, 0x40026000	// 70 <hgusb11_dev_close+0x70>
  40:	3500      	movi      	r5, 0
  42:	9345      	ld.w      	r2, (r3, 0x14)
  44:	3a8c      	bclri      	r2, 12
  46:	b345      	st.w      	r2, (r3, 0x14)
  48:	9342      	ld.w      	r2, (r3, 0x8)
  4a:	3a8c      	bclri      	r2, 12
  4c:	b342      	st.w      	r2, (r3, 0x8)
  4e:	9342      	ld.w      	r2, (r3, 0x8)
  50:	ec421000 	ori      	r2, r2, 4096
  54:	940c      	ld.w      	r0, (r4, 0x30)
  56:	b342      	st.w      	r2, (r3, 0x8)
  58:	e0000000 	bsr      	0x0	// 0 <_os_free>
  5c:	b4ac      	st.w      	r5, (r4, 0x30)
  5e:	b4a5      	st.w      	r5, (r4, 0x14)
  60:	b4af      	st.w      	r5, (r4, 0x3c)
  62:	b4ad      	st.w      	r5, (r4, 0x34)
  64:	b4ae      	st.w      	r5, (r4, 0x38)
  66:	6c13      	mov      	r0, r4
  68:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_close>
  6c:	07d6      	br      	0x18	// 18 <hgusb11_dev_close+0x18>
  6e:	0000      	.short	0x0000
  70:	6000      	.short	0x6000
  72:	4002      	.short	0x4002

Disassembly of section .text.hgusb11_dev_irq_set:

00000000 <hgusb11_dev_irq_set>:
   0:	3906      	cmphsi      	r1, 7
   2:	e903004c 	bez      	r3, 0x9a	// 9a <hgusb11_dev_irq_set+0x9a>
   6:	085e      	bt      	0xc2	// c2 <hgusb11_dev_irq_set+0xc2>
   8:	1062      	lrw      	r3, 0x0	// 10 <hgusb11_dev_irq_set+0x10>
   a:	d0230883 	ldr.w      	r3, (r3, r1 << 2)
   e:	780c      	jmp      	r3
  10:	00000000 	.long	0x00000000
  14:	9043      	ld.w      	r2, (r0, 0xc)
  16:	d86220c1 	ld.w      	r3, (r2, 0x304)
  1a:	3b89      	bclri      	r3, 9
  1c:	dc6220c1 	st.w      	r3, (r2, 0x304)
  20:	0451      	br      	0xc2	// c2 <hgusb11_dev_irq_set+0xc2>
  22:	e9020050 	bez      	r2, 0xc2	// c2 <hgusb11_dev_irq_set+0xc2>
  26:	9003      	ld.w      	r0, (r0, 0xc)
  28:	3301      	movi      	r3, 1
  2a:	5a36      	addi      	r1, r2, 6
  2c:	d98020c1 	ld.w      	r12, (r0, 0x304)
  30:	c4234021 	lsl      	r1, r3, r1
  34:	c42c2041 	andn      	r1, r12, r1
  38:	dc2020c1 	st.w      	r1, (r0, 0x304)
  3c:	708c      	lsl      	r2, r3
  3e:	d82020c6 	ld.w      	r1, (r0, 0x318)
  42:	608c      	addu      	r2, r3
  44:	70c8      	lsl      	r3, r2
  46:	6cc4      	or      	r3, r1
  48:	dc6020c6 	st.w      	r3, (r0, 0x318)
  4c:	043b      	br      	0xc2	// c2 <hgusb11_dev_irq_set+0xc2>
  4e:	e902003a 	bez      	r2, 0xc2	// c2 <hgusb11_dev_irq_set+0xc2>
  52:	9003      	ld.w      	r0, (r0, 0xc)
  54:	e4220008 	addi      	r1, r2, 9
  58:	3301      	movi      	r3, 1
  5a:	d98020c1 	ld.w      	r12, (r0, 0x304)
  5e:	c4234021 	lsl      	r1, r3, r1
  62:	c42c2041 	andn      	r1, r12, r1
  66:	dc2020c1 	st.w      	r1, (r0, 0x304)
  6a:	d82020c6 	ld.w      	r1, (r0, 0x318)
  6e:	6088      	addu      	r2, r2
  70:	07ea      	br      	0x44	// 44 <hgusb11_dev_irq_set+0x44>
  72:	9043      	ld.w      	r2, (r0, 0xc)
  74:	d86220c1 	ld.w      	r3, (r2, 0x304)
  78:	3b8e      	bclri      	r3, 14
  7a:	07d1      	br      	0x1c	// 1c <hgusb11_dev_irq_set+0x1c>
  7c:	9043      	ld.w      	r2, (r0, 0xc)
  7e:	d86220c1 	ld.w      	r3, (r2, 0x304)
  82:	3b8c      	bclri      	r3, 12
  84:	07cc      	br      	0x1c	// 1c <hgusb11_dev_irq_set+0x1c>
  86:	9043      	ld.w      	r2, (r0, 0xc)
  88:	d86220c1 	ld.w      	r3, (r2, 0x304)
  8c:	3b8d      	bclri      	r3, 13
  8e:	07c7      	br      	0x1c	// 1c <hgusb11_dev_irq_set+0x1c>
  90:	9043      	ld.w      	r2, (r0, 0xc)
  92:	d86220c1 	ld.w      	r3, (r2, 0x304)
  96:	3b86      	bclri      	r3, 6
  98:	07c2      	br      	0x1c	// 1c <hgusb11_dev_irq_set+0x1c>
  9a:	0814      	bt      	0xc2	// c2 <hgusb11_dev_irq_set+0xc2>
  9c:	1062      	lrw      	r3, 0x0	// a4 <hgusb11_dev_irq_set+0xa4>
  9e:	d0230883 	ldr.w      	r3, (r3, r1 << 2)
  a2:	780c      	jmp      	r3
  a4:	00000000 	.long	0x00000000
  a8:	9063      	ld.w      	r3, (r0, 0xc)
  aa:	d84320c1 	ld.w      	r2, (r3, 0x304)
  ae:	ec420200 	ori      	r2, r2, 512
  b2:	dc4320c1 	st.w      	r2, (r3, 0x304)
  b6:	d84320c6 	ld.w      	r2, (r3, 0x318)
  ba:	3a80      	bclri      	r2, 0
  bc:	3a81      	bclri      	r2, 1
  be:	dc4320c6 	st.w      	r2, (r3, 0x318)
  c2:	783c      	jmp      	r15
  c4:	e902ffff 	bez      	r2, 0xc2	// c2 <hgusb11_dev_irq_set+0xc2>
  c8:	9003      	ld.w      	r0, (r0, 0xc)
  ca:	3301      	movi      	r3, 1
  cc:	5a36      	addi      	r1, r2, 6
  ce:	d98020c1 	ld.w      	r12, (r0, 0x304)
  d2:	c4234021 	lsl      	r1, r3, r1
  d6:	6c70      	or      	r1, r12
  d8:	708c      	lsl      	r2, r3
  da:	dc2020c1 	st.w      	r1, (r0, 0x304)
  de:	608c      	addu      	r2, r3
  e0:	d82020c6 	ld.w      	r1, (r0, 0x318)
  e4:	70c8      	lsl      	r3, r2
  e6:	c4612043 	andn      	r3, r1, r3
  ea:	07af      	br      	0x48	// 48 <hgusb11_dev_irq_set+0x48>
  ec:	e902ffeb 	bez      	r2, 0xc2	// c2 <hgusb11_dev_irq_set+0xc2>
  f0:	9003      	ld.w      	r0, (r0, 0xc)
  f2:	e4220008 	addi      	r1, r2, 9
  f6:	3301      	movi      	r3, 1
  f8:	d98020c1 	ld.w      	r12, (r0, 0x304)
  fc:	c4234021 	lsl      	r1, r3, r1
 100:	6c70      	or      	r1, r12
 102:	dc2020c1 	st.w      	r1, (r0, 0x304)
 106:	6088      	addu      	r2, r2
 108:	d82020c6 	ld.w      	r1, (r0, 0x318)
 10c:	c4434022 	lsl      	r2, r3, r2
 110:	c4412042 	andn      	r2, r1, r2
 114:	dc4020c6 	st.w      	r2, (r0, 0x318)
 118:	07d5      	br      	0xc2	// c2 <hgusb11_dev_irq_set+0xc2>
 11a:	9043      	ld.w      	r2, (r0, 0xc)
 11c:	d86220c1 	ld.w      	r3, (r2, 0x304)
 120:	ec634000 	ori      	r3, r3, 16384
 124:	077c      	br      	0x1c	// 1c <hgusb11_dev_irq_set+0x1c>
 126:	9043      	ld.w      	r2, (r0, 0xc)
 128:	d86220c1 	ld.w      	r3, (r2, 0x304)
 12c:	ec631000 	ori      	r3, r3, 4096
 130:	0776      	br      	0x1c	// 1c <hgusb11_dev_irq_set+0x1c>
 132:	9043      	ld.w      	r2, (r0, 0xc)
 134:	d86220c1 	ld.w      	r3, (r2, 0x304)
 138:	ec632000 	ori      	r3, r3, 8192
 13c:	0770      	br      	0x1c	// 1c <hgusb11_dev_irq_set+0x1c>
 13e:	9043      	ld.w      	r2, (r0, 0xc)
 140:	d86220c1 	ld.w      	r3, (r2, 0x304)
 144:	ec630040 	ori      	r3, r3, 64
 148:	076a      	br      	0x1c	// 1c <hgusb11_dev_irq_set+0x1c>

Disassembly of section .text.hgusb11_dev_request_irq:

00000000 <hgusb11_dev_request_irq>:
   0:	14d2      	push      	r4-r5, r15
   2:	906e      	ld.w      	r3, (r0, 0x38)
   4:	6d03      	mov      	r4, r0
   6:	e903005b 	bez      	r3, 0xbc	// bc <hgusb11_dev_request_irq+0xbc>
   a:	b04f      	st.w      	r2, (r0, 0x3c)
   c:	b025      	st.w      	r1, (r0, 0x14)
   e:	6c83      	mov      	r2, r0
  10:	112d      	lrw      	r1, 0x0	// c4 <hgusb11_dev_request_irq+0xc4>
  12:	900a      	ld.w      	r0, (r0, 0x28)
  14:	e0000000 	bsr      	0x0	// 0 <request_irq>
  18:	6d43      	mov      	r5, r0
  1a:	e9000008 	bez      	r0, 0x2a	// 2a <hgusb11_dev_request_irq+0x2a>
  1e:	114b      	lrw      	r2, 0x0	// c8 <hgusb11_dev_request_irq+0xc8>
  20:	ea010246 	movi      	r1, 582
  24:	110a      	lrw      	r0, 0x0	// cc <assert_internal+0xcc>
  26:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  2a:	6c93      	mov      	r2, r4
  2c:	1129      	lrw      	r1, 0x0	// d0 <hgusb11_dev_request_irq+0xd0>
  2e:	940b      	ld.w      	r0, (r4, 0x2c)
  30:	e0000000 	bsr      	0x0	// 0 <request_irq>
  34:	e9050008 	bez      	r5, 0x44	// 44 <hgusb11_dev_request_irq+0x44>
  38:	3192      	movi      	r1, 146
  3a:	1144      	lrw      	r2, 0x0	// c8 <hgusb11_dev_request_irq+0xc8>
  3c:	4122      	lsli      	r1, r1, 2
  3e:	1104      	lrw      	r0, 0x0	// cc <hgusb11_dev_request_irq+0xcc>
  40:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  44:	9463      	ld.w      	r3, (r4, 0xc)
  46:	3105      	movi      	r1, 5
  48:	d84320c1 	ld.w      	r2, (r3, 0x304)
  4c:	3a89      	bclri      	r2, 9
  4e:	dc4320c1 	st.w      	r2, (r3, 0x304)
  52:	d84320c1 	ld.w      	r2, (r3, 0x304)
  56:	3a8e      	bclri      	r2, 14
  58:	dc4320c1 	st.w      	r2, (r3, 0x304)
  5c:	d84320c1 	ld.w      	r2, (r3, 0x304)
  60:	3a8c      	bclri      	r2, 12
  62:	dc4320c1 	st.w      	r2, (r3, 0x304)
  66:	d84320c1 	ld.w      	r2, (r3, 0x304)
  6a:	3a8d      	bclri      	r2, 13
  6c:	dc4320c1 	st.w      	r2, (r3, 0x304)
  70:	d84320c1 	ld.w      	r2, (r3, 0x304)
  74:	ec420040 	ori      	r2, r2, 64
  78:	dc4320c1 	st.w      	r2, (r3, 0x304)
  7c:	3301      	movi      	r3, 1
  7e:	6c8f      	mov      	r2, r3
  80:	6c13      	mov      	r0, r4
  82:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_request_irq>
  86:	3301      	movi      	r3, 1
  88:	6c8f      	mov      	r2, r3
  8a:	3106      	movi      	r1, 6
  8c:	6c13      	mov      	r0, r4
  8e:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_request_irq>
  92:	946a      	ld.w      	r3, (r4, 0x28)
  94:	c4a354c0 	zext      	r0, r3, 6, 5
  98:	3201      	movi      	r2, 1
  9a:	e463201f 	andi      	r3, r3, 31
  9e:	c4624023 	lsl      	r3, r2, r3
  a2:	102d      	lrw      	r1, 0xe000e100	// d4 <hgusb11_dev_request_irq+0xd4>
  a4:	d4010883 	str.w      	r3, (r1, r0 << 2)
  a8:	946b      	ld.w      	r3, (r4, 0x2c)
  aa:	c4a354c0 	zext      	r0, r3, 6, 5
  ae:	e463201f 	andi      	r3, r3, 31
  b2:	708c      	lsl      	r2, r3
  b4:	d4010882 	str.w      	r2, (r1, r0 << 2)
  b8:	3000      	movi      	r0, 0
  ba:	1492      	pop      	r4-r5, r15
  bc:	3000      	movi      	r0, 0
  be:	2800      	subi      	r0, 1
  c0:	07fd      	br      	0xba	// ba <hgusb11_dev_request_irq+0xba>
	...
  d2:	0000      	.short	0x0000
  d4:	e000e100 	.long	0xe000e100

Disassembly of section .text.hgusb11_dev_irq:

00000000 <hgusb11_dev_irq>:
   0:	14d4      	push      	r4-r7, r15
   2:	9043      	ld.w      	r2, (r0, 0xc)
   4:	6d03      	mov      	r4, r0
   6:	82ce      	ld.b      	r6, (r2, 0xe)
   8:	8226      	ld.b      	r1, (r2, 0x6)
   a:	7444      	zextb      	r1, r1
   c:	e5a12004 	andi      	r13, r1, 4
  10:	d8a220c4 	ld.w      	r5, (r2, 0x310)
  14:	82e2      	ld.b      	r7, (r2, 0x2)
  16:	7598      	zextb      	r6, r6
  18:	8264      	ld.b      	r3, (r2, 0x4)
  1a:	75dc      	zextb      	r7, r7
  1c:	dca220c4 	st.w      	r5, (r2, 0x310)
  20:	e90d0084 	bez      	r13, 0x128	// 128 <hgusb11_dev_irq+0x128>
  24:	9064      	ld.w      	r3, (r0, 0x10)
  26:	3b80      	bclri      	r3, 0
  28:	b064      	st.w      	r3, (r0, 0x10)
  2a:	3301      	movi      	r3, 1
  2c:	dc6000dc 	st.b      	r3, (r0, 0xdc)
  30:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_reset>
  34:	6c13      	mov      	r0, r4
  36:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_intr_init_b>
  3a:	d9842005 	ld.w      	r12, (r4, 0x14)
  3e:	e90c000a 	bez      	r12, 0x52	// 52 <hgusb11_dev_irq+0x52>
  42:	946e      	ld.w      	r3, (r4, 0x38)
  44:	e9030007 	bez      	r3, 0x52	// 52 <hgusb11_dev_irq+0x52>
  48:	3300      	movi      	r3, 0
  4a:	6c8f      	mov      	r2, r3
  4c:	942f      	ld.w      	r1, (r4, 0x3c)
  4e:	6c0f      	mov      	r0, r3
  50:	7bf1      	jsr      	r12
  52:	e4e72001 	andi      	r7, r7, 1
  56:	e9070006 	bez      	r7, 0x62	// 62 <hgusb11_dev_irq+0x62>
  5a:	e40400cf 	addi      	r0, r4, 208
  5e:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  62:	e4652004 	andi      	r3, r5, 4
  66:	e903001d 	bez      	r3, 0xa0	// a0 <hgusb11_dev_irq+0xa0>
  6a:	d9842005 	ld.w      	r12, (r4, 0x14)
  6e:	e90c0015 	bez      	r12, 0x98	// 98 <hgusb11_dev_irq+0x98>
  72:	946e      	ld.w      	r3, (r4, 0x38)
  74:	e9030012 	bez      	r3, 0x98	// 98 <hgusb11_dev_irq+0x98>
  78:	9443      	ld.w      	r2, (r4, 0xc)
  7a:	942f      	ld.w      	r1, (r4, 0x3c)
  7c:	d80220d6 	ld.w      	r0, (r2, 0x358)
  80:	d86220cc 	ld.w      	r3, (r2, 0x330)
  84:	640c      	cmphs      	r3, r0
  86:	087c      	bt      	0x17e	// 17e <hgusb11_dev_irq+0x17e>
  88:	d86220d6 	ld.w      	r3, (r2, 0x358)
  8c:	d84220cc 	ld.w      	r2, (r2, 0x330)
  90:	60ca      	subu      	r3, r2
  92:	3201      	movi      	r2, 1
  94:	3006      	movi      	r0, 6
  96:	7bf1      	jsr      	r12
  98:	e404001f 	addi      	r0, r4, 32
  9c:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  a0:	e4652008 	andi      	r3, r5, 8
  a4:	e903001f 	bez      	r3, 0xe2	// e2 <hgusb11_dev_irq+0xe2>
  a8:	9464      	ld.w      	r3, (r4, 0x10)
  aa:	d9842005 	ld.w      	r12, (r4, 0x14)
  ae:	ec630001 	ori      	r3, r3, 1
  b2:	b464      	st.w      	r3, (r4, 0x10)
  b4:	e90c0017 	bez      	r12, 0xe2	// e2 <hgusb11_dev_irq+0xe2>
  b8:	946e      	ld.w      	r3, (r4, 0x38)
  ba:	e9030014 	bez      	r3, 0xe2	// e2 <hgusb11_dev_irq+0xe2>
  be:	9463      	ld.w      	r3, (r4, 0xc)
  c0:	942f      	ld.w      	r1, (r4, 0x3c)
  c2:	d9a320d7 	ld.w      	r13, (r3, 0x35c)
  c6:	d80320cd 	ld.w      	r0, (r3, 0x334)
  ca:	6740      	cmphs      	r0, r13
  cc:	e443032f 	addi      	r2, r3, 816
  d0:	0859      	bt      	0x182	// 182 <hgusb11_dev_irq+0x182>
  d2:	d86320d7 	ld.w      	r3, (r3, 0x35c)
  d6:	2b01      	subi      	r3, 2
  d8:	9241      	ld.w      	r2, (r2, 0x4)
  da:	60ca      	subu      	r3, r2
  dc:	3201      	movi      	r2, 1
  de:	3005      	movi      	r0, 5
  e0:	7bf1      	jsr      	r12
  e2:	e4652010 	andi      	r3, r5, 16
  e6:	e903000e 	bez      	r3, 0x102	// 102 <hgusb11_dev_irq+0x102>
  ea:	d9842005 	ld.w      	r12, (r4, 0x14)
  ee:	e90c000a 	bez      	r12, 0x102	// 102 <hgusb11_dev_irq+0x102>
  f2:	946e      	ld.w      	r3, (r4, 0x38)
  f4:	e9030007 	bez      	r3, 0x102	// 102 <hgusb11_dev_irq+0x102>
  f8:	3300      	movi      	r3, 0
  fa:	3202      	movi      	r2, 2
  fc:	942f      	ld.w      	r1, (r4, 0x3c)
  fe:	3006      	movi      	r0, 6
 100:	7bf1      	jsr      	r12
 102:	e4a52020 	andi      	r5, r5, 32
 106:	e905000e 	bez      	r5, 0x122	// 122 <hgusb11_dev_irq+0x122>
 10a:	d9842005 	ld.w      	r12, (r4, 0x14)
 10e:	e90c000a 	bez      	r12, 0x122	// 122 <hgusb11_dev_irq+0x122>
 112:	946e      	ld.w      	r3, (r4, 0x38)
 114:	e9030007 	bez      	r3, 0x122	// 122 <hgusb11_dev_irq+0x122>
 118:	3300      	movi      	r3, 0
 11a:	3202      	movi      	r2, 2
 11c:	942f      	ld.w      	r1, (r4, 0x3c)
 11e:	3005      	movi      	r0, 5
 120:	7bf1      	jsr      	r12
 122:	9463      	ld.w      	r3, (r4, 0xc)
 124:	a3ce      	st.b      	r6, (r3, 0xe)
 126:	1494      	pop      	r4-r7, r15
 128:	e4612001 	andi      	r3, r1, 1
 12c:	e9030014 	bez      	r3, 0x154	// 154 <hgusb11_dev_irq+0x154>
 130:	9044      	ld.w      	r2, (r0, 0x10)
 132:	d9802005 	ld.w      	r12, (r0, 0x14)
 136:	3a80      	bclri      	r2, 0
 138:	3301      	movi      	r3, 1
 13a:	b044      	st.w      	r2, (r0, 0x10)
 13c:	dc6000dc 	st.b      	r3, (r0, 0xdc)
 140:	e90cff89 	bez      	r12, 0x52	// 52 <hgusb11_dev_irq+0x52>
 144:	906e      	ld.w      	r3, (r0, 0x38)
 146:	e903ff86 	bez      	r3, 0x52	// 52 <hgusb11_dev_irq+0x52>
 14a:	902f      	ld.w      	r1, (r0, 0x3c)
 14c:	6cf7      	mov      	r3, r13
 14e:	6cb7      	mov      	r2, r13
 150:	3001      	movi      	r0, 1
 152:	077f      	br      	0x50	// 50 <hgusb11_dev_irq+0x50>
 154:	e4212002 	andi      	r1, r1, 2
 158:	e901ff7d 	bez      	r1, 0x52	// 52 <hgusb11_dev_irq+0x52>
 15c:	9024      	ld.w      	r1, (r0, 0x10)
 15e:	ec210001 	ori      	r1, r1, 1
 162:	b024      	st.w      	r1, (r0, 0x10)
 164:	3104      	movi      	r1, 4
 166:	a22b      	st.b      	r1, (r2, 0xb)
 168:	d9802005 	ld.w      	r12, (r0, 0x14)
 16c:	e90cff73 	bez      	r12, 0x52	// 52 <hgusb11_dev_irq+0x52>
 170:	904e      	ld.w      	r2, (r0, 0x38)
 172:	e902ff70 	bez      	r2, 0x52	// 52 <hgusb11_dev_irq+0x52>
 176:	902f      	ld.w      	r1, (r0, 0x3c)
 178:	6c8f      	mov      	r2, r3
 17a:	3002      	movi      	r0, 2
 17c:	076a      	br      	0x50	// 50 <hgusb11_dev_irq+0x50>
 17e:	3300      	movi      	r3, 0
 180:	0789      	br      	0x92	// 92 <hgusb11_dev_irq+0x92>
 182:	3300      	movi      	r3, 0
 184:	07ac      	br      	0xdc	// dc <hgusb11_dev_irq+0xdc>

Disassembly of section .text.hgusb11_dev_ctrl_irq_hdl:

00000000 <hgusb11_dev_ctrl_irq_hdl>:
   0:	14d0      	push      	r15
   2:	d8600112 	ld.b      	r3, (r0, 0x112)
   6:	e9030004 	bez      	r3, 0xe	// e <hgusb11_dev_ctrl_irq_hdl+0xe>
   a:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ctrl_irq_hdl>
   e:	1490      	pop      	r15

Disassembly of section .text.hgusb11_dev_ep_tx_kick:

00000000 <hgusb11_dev_ep_tx_kick>:
   0:	d9802003 	ld.w      	r12, (r0, 0xc)
   4:	c481482d 	lsli      	r13, r1, 4
   8:	e40c031f 	addi      	r0, r12, 800
   c:	6034      	addu      	r0, r13
   e:	6044      	addu      	r1, r1
  10:	b040      	st.w      	r2, (r0, 0x0)
  12:	b062      	st.w      	r3, (r0, 0x8)
  14:	3001      	movi      	r0, 1
  16:	c4204021 	lsl      	r1, r0, r1
  1a:	dc2c20c5 	st.w      	r1, (r12, 0x314)
  1e:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep_set_rxrdy:

00000000 <hgusb11_dev_ep_set_rxrdy>:
   0:	9063      	ld.w      	r3, (r0, 0xc)
   2:	3210      	movi      	r2, 16
   4:	a32e      	st.b      	r1, (r3, 0xe)
   6:	a354      	st.b      	r2, (r3, 0x14)
   8:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep_rx_kick:

00000000 <hgusb11_dev_ep_rx_kick>:
   0:	14d2      	push      	r4-r5, r15
   2:	3901      	cmphsi      	r1, 2
   4:	0818      	bt      	0x34	// 34 <hgusb11_dev_ep_rx_kick+0x34>
   6:	90a3      	ld.w      	r5, (r0, 0xc)
   8:	7707      	sexth      	r12, r1
   a:	c48c4824 	lsli      	r4, r12, 4
   e:	e5a5031f 	addi      	r13, r5, 800
  12:	6330      	addu      	r12, r12
  14:	6350      	addu      	r13, r4
  16:	e58c0000 	addi      	r12, r12, 1
  1a:	3401      	movi      	r4, 1
  1c:	c584402c 	lsl      	r12, r4, r12
  20:	dc4d2001 	st.w      	r2, (r13, 0x4)
  24:	dc6d2003 	st.w      	r3, (r13, 0xc)
  28:	dd8520c5 	st.w      	r12, (r5, 0x314)
  2c:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_ep_rx_kick>
  30:	6c13      	mov      	r0, r4
  32:	1492      	pop      	r4-r5, r15
  34:	3000      	movi      	r0, 0
  36:	07fe      	br      	0x32	// 32 <hgusb11_dev_ep_rx_kick+0x32>

Disassembly of section .text.hgusb11_dev_read:

00000000 <hgusb11_dev_read>:
   0:	14d1      	push      	r4, r15
   2:	d9a0200e 	ld.w      	r13, (r0, 0x38)
   6:	d88e0008 	ld.b      	r4, (r14, 0x8)
   a:	e90d000d 	bez      	r13, 0x24	// 24 <hgusb11_dev_read+0x24>
   e:	3902      	cmphsi      	r1, 3
  10:	080a      	bt      	0x24	// 24 <hgusb11_dev_read+0x24>
  12:	e924000c 	bnez      	r4, 0x2a	// 2a <hgusb11_dev_read+0x2a>
  16:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_read>
  1a:	e4004001 	xori      	r0, r0, 1
  1e:	7400      	zextb      	r0, r0
  20:	5c01      	subu      	r0, r4, r0
  22:	1491      	pop      	r4, r15
  24:	3000      	movi      	r0, 0
  26:	2800      	subi      	r0, 1
  28:	07fd      	br      	0x22	// 22 <hgusb11_dev_read+0x22>
  2a:	ea00020b 	movi      	r0, 523
  2e:	6c02      	nor      	r0, r0
  30:	07f9      	br      	0x22	// 22 <hgusb11_dev_read+0x22>

Disassembly of section .text.hgusb11_dev_ep_set_txrdy:

00000000 <hgusb11_dev_ep_set_txrdy>:
   0:	9063      	ld.w      	r3, (r0, 0xc)
   2:	3201      	movi      	r2, 1
   4:	a32e      	st.b      	r1, (r3, 0xe)
   6:	a351      	st.b      	r2, (r3, 0x11)
   8:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_write:

00000000 <hgusb11_dev_write>:
   0:	14d4      	push      	r4-r7, r15
   2:	1422      	subi      	r14, r14, 8
   4:	6d43      	mov      	r5, r0
   6:	900e      	ld.w      	r0, (r0, 0x38)
   8:	6d87      	mov      	r6, r1
   a:	d82e001c 	ld.b      	r1, (r14, 0x1c)
   e:	e9200007 	bnez      	r0, 0x1c	// 1c <hgusb11_dev_write+0x1c>
  12:	3400      	movi      	r4, 0
  14:	2c00      	subi      	r4, 1
  16:	6c13      	mov      	r0, r4
  18:	1402      	addi      	r14, r14, 8
  1a:	1494      	pop      	r4-r7, r15
  1c:	3e02      	cmphsi      	r6, 3
  1e:	b861      	st.w      	r3, (r14, 0x4)
  20:	b840      	st.w      	r2, (r14, 0x0)
  22:	0bf8      	bt      	0x12	// 12 <hgusb11_dev_write+0x12>
  24:	e921002f 	bnez      	r1, 0x82	// 82 <hgusb11_dev_write+0x82>
  28:	e4e50017 	addi      	r7, r5, 24
  2c:	31fa      	movi      	r1, 250
  2e:	4123      	lsli      	r1, r1, 3
  30:	6c1f      	mov      	r0, r7
  32:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  36:	6d03      	mov      	r4, r0
  38:	e920ffed 	bnez      	r0, 0x12	// 12 <hgusb11_dev_write+0x12>
  3c:	9524      	ld.w      	r1, (r5, 0x10)
  3e:	e4212001 	andi      	r1, r1, 1
  42:	9840      	ld.w      	r2, (r14, 0x0)
  44:	9861      	ld.w      	r3, (r14, 0x4)
  46:	e9210006 	bnez      	r1, 0x52	// 52 <hgusb11_dev_write+0x52>
  4a:	6c1f      	mov      	r0, r7
  4c:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  50:	07e2      	br      	0x14	// 14 <hgusb11_dev_write+0x14>
  52:	6c5b      	mov      	r1, r6
  54:	6c17      	mov      	r0, r5
  56:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_write>
  5a:	6c5b      	mov      	r1, r6
  5c:	6c17      	mov      	r0, r5
  5e:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_write>
  62:	31fa      	movi      	r1, 250
  64:	4123      	lsli      	r1, r1, 3
  66:	e405001f 	addi      	r0, r5, 32
  6a:	e0000000 	bsr      	0x0	// 0 <os_sema_down>
  6e:	e9400006 	bhz      	r0, 0x7a	// 7a <hgusb11_dev_write+0x7a>
  72:	9563      	ld.w      	r3, (r5, 0xc)
  74:	3248      	movi      	r2, 72
  76:	a3ce      	st.b      	r6, (r3, 0xe)
  78:	a351      	st.b      	r2, (r3, 0x11)
  7a:	6c1f      	mov      	r0, r7
  7c:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  80:	07cb      	br      	0x16	// 16 <hgusb11_dev_write+0x16>
  82:	ea04020b 	movi      	r4, 523
  86:	6d12      	nor      	r4, r4
  88:	07c7      	br      	0x16	// 16 <hgusb11_dev_write+0x16>

Disassembly of section .text.hgusb11_dev_ep_dma_state:

00000000 <hgusb11_dev_ep_dma_state>:
   0:	9063      	ld.w      	r3, (r0, 0xc)
   2:	d80320c4 	ld.w      	r0, (r3, 0x310)
   6:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep_clear_dma_state:

00000000 <hgusb11_dev_ep_clear_dma_state>:
   0:	9063      	ld.w      	r3, (r0, 0xc)
   2:	dc2320c4 	st.w      	r1, (r3, 0x310)
   6:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep_get_dma_rx_pending:

00000000 <hgusb11_dev_ep_get_dma_rx_pending>:
   0:	9063      	ld.w      	r3, (r0, 0xc)
   2:	4121      	lsli      	r1, r1, 1
   4:	d80320c4 	ld.w      	r0, (r3, 0x310)
   8:	2100      	addi      	r1, 1
   a:	7005      	lsr      	r0, r1
   c:	e4002001 	andi      	r0, r0, 1
  10:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep_get_dma_tx_pending:

00000000 <hgusb11_dev_ep_get_dma_tx_pending>:
   0:	9063      	ld.w      	r3, (r0, 0xc)
   2:	4121      	lsli      	r1, r1, 1
   4:	d80320c4 	ld.w      	r0, (r3, 0x310)
   8:	7005      	lsr      	r0, r1
   a:	e4002001 	andi      	r0, r0, 1
   e:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep_get_dma_rx_overflow_pending:

00000000 <hgusb11_dev_ep_get_dma_rx_overflow_pending>:
   0:	9063      	ld.w      	r3, (r0, 0xc)
   2:	2106      	addi      	r1, 7
   4:	d80320c4 	ld.w      	r0, (r3, 0x310)
   8:	7005      	lsr      	r0, r1
   a:	e4002001 	andi      	r0, r0, 1
   e:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep_get_dma_rx_empty_packet_pending:

00000000 <hgusb11_dev_ep_get_dma_rx_empty_packet_pending>:
   0:	9063      	ld.w      	r3, (r0, 0xc)
   2:	2108      	addi      	r1, 9
   4:	d80320c4 	ld.w      	r0, (r3, 0x310)
   8:	7005      	lsr      	r0, r1
   a:	e4002001 	andi      	r0, r0, 1
   e:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep_clear_dma_rx_pending:

00000000 <hgusb11_dev_ep_clear_dma_rx_pending>:
   0:	4121      	lsli      	r1, r1, 1
   2:	5962      	addi      	r3, r1, 1
   4:	9043      	ld.w      	r2, (r0, 0xc)
   6:	3101      	movi      	r1, 1
   8:	704c      	lsl      	r1, r3
   a:	dc2220c4 	st.w      	r1, (r2, 0x310)
   e:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep_clear_dma_tx_pending:

00000000 <hgusb11_dev_ep_clear_dma_tx_pending>:
   0:	9043      	ld.w      	r2, (r0, 0xc)
   2:	3301      	movi      	r3, 1
   4:	4121      	lsli      	r1, r1, 1
   6:	c4234021 	lsl      	r1, r3, r1
   a:	dc2220c4 	st.w      	r1, (r2, 0x310)
   e:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep_clear_dma_rx_overflow_pending:

00000000 <hgusb11_dev_ep_clear_dma_rx_overflow_pending>:
   0:	9043      	ld.w      	r2, (r0, 0xc)
   2:	3301      	movi      	r3, 1
   4:	2106      	addi      	r1, 7
   6:	c4234021 	lsl      	r1, r3, r1
   a:	dc2220c4 	st.w      	r1, (r2, 0x310)
   e:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep_clear_dma_rx_empty_packet_pending:

00000000 <hgusb11_dev_ep_clear_dma_rx_empty_packet_pending>:
   0:	9043      	ld.w      	r2, (r0, 0xc)
   2:	3301      	movi      	r3, 1
   4:	2108      	addi      	r1, 9
   6:	c4234021 	lsl      	r1, r3, r1
   a:	dc2220c4 	st.w      	r1, (r2, 0x310)
   e:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_dev_ep_get_rx_len:

00000000 <hgusb11_dev_ep_get_rx_len>:
   0:	3901      	cmphsi      	r1, 2
   2:	0814      	bt      	0x2a	// 2a <hgusb11_dev_ep_get_rx_len+0x2a>
   4:	9063      	ld.w      	r3, (r0, 0xc)
   6:	7447      	sexth      	r1, r1
   8:	4104      	lsli      	r0, r1, 4
   a:	e443031f 	addi      	r2, r3, 800
   e:	4123      	lsli      	r1, r1, 3
  10:	e463034f 	addi      	r3, r3, 848
  14:	6080      	addu      	r2, r0
  16:	604c      	addu      	r1, r3
  18:	9101      	ld.w      	r0, (r1, 0x4)
  1a:	9261      	ld.w      	r3, (r2, 0x4)
  1c:	640c      	cmphs      	r3, r0
  1e:	0806      	bt      	0x2a	// 2a <hgusb11_dev_ep_get_rx_len+0x2a>
  20:	9101      	ld.w      	r0, (r1, 0x4)
  22:	2801      	subi      	r0, 2
  24:	9261      	ld.w      	r3, (r2, 0x4)
  26:	600e      	subu      	r0, r3
  28:	783c      	jmp      	r15
  2a:	3000      	movi      	r0, 0
  2c:	07fe      	br      	0x28	// 28 <hgusb11_dev_ep_get_rx_len+0x28>

Disassembly of section .text.hgusb11_dev_ep_get_tx_len:

00000000 <hgusb11_dev_ep_get_tx_len>:
   0:	3901      	cmphsi      	r1, 2
   2:	0813      	bt      	0x28	// 28 <hgusb11_dev_ep_get_tx_len+0x28>
   4:	9063      	ld.w      	r3, (r0, 0xc)
   6:	7447      	sexth      	r1, r1
   8:	4104      	lsli      	r0, r1, 4
   a:	e443031f 	addi      	r2, r3, 800
   e:	4123      	lsli      	r1, r1, 3
  10:	e463034f 	addi      	r3, r3, 848
  14:	6080      	addu      	r2, r0
  16:	604c      	addu      	r1, r3
  18:	9100      	ld.w      	r0, (r1, 0x0)
  1a:	9260      	ld.w      	r3, (r2, 0x0)
  1c:	640c      	cmphs      	r3, r0
  1e:	0805      	bt      	0x28	// 28 <hgusb11_dev_ep_get_tx_len+0x28>
  20:	9100      	ld.w      	r0, (r1, 0x0)
  22:	9260      	ld.w      	r3, (r2, 0x0)
  24:	600e      	subu      	r0, r3
  26:	783c      	jmp      	r15
  28:	3000      	movi      	r0, 0
  2a:	07fe      	br      	0x26	// 26 <hgusb11_dev_ep_get_tx_len+0x26>

Disassembly of section .text.hgusb11_dev_attach:

00000000 <hgusb11_dev_attach>:
   0:	14d5      	push      	r4-r8, r15
   2:	6d07      	mov      	r4, r1
   4:	6e03      	mov      	r8, r0
   6:	e0000000 	bsr      	0x0	// 0 <sysctrl_get_chip_id>
   a:	ea035fed 	movi      	r3, 24557
   e:	6cce      	nor      	r3, r3
  10:	dc6411da 	st.h      	r3, (r4, 0x3b4)
  14:	e4c40017 	addi      	r6, r4, 24
  18:	1077      	lrw      	r3, 0x0	// 74 <hgusb11_dev_attach+0x74>
  1a:	3708      	movi      	r7, 8
  1c:	b462      	st.w      	r3, (r4, 0x8)
  1e:	e4a4001f 	addi      	r5, r4, 32
  22:	dc0411db 	st.h      	r0, (r4, 0x3b6)
  26:	6c9f      	mov      	r2, r7
  28:	3100      	movi      	r1, 0
  2a:	6c1b      	mov      	r0, r6
  2c:	e0000000 	bsr      	0x0	// 0 <memset>
  30:	6c9f      	mov      	r2, r7
  32:	3100      	movi      	r1, 0
  34:	6c17      	mov      	r0, r5
  36:	e0000000 	bsr      	0x0	// 0 <memset>
  3a:	6c1b      	mov      	r0, r6
  3c:	e0000000 	bsr      	0x0	// 0 <os_mutex_init>
  40:	3100      	movi      	r1, 0
  42:	6c17      	mov      	r0, r5
  44:	e0000000 	bsr      	0x0	// 0 <os_sema_init>
  48:	3500      	movi      	r5, 0
  4a:	3301      	movi      	r3, 1
  4c:	dc640112 	st.b      	r3, (r4, 0x112)
  50:	940a      	ld.w      	r0, (r4, 0x28)
  52:	b4a5      	st.w      	r5, (r4, 0x14)
  54:	b4af      	st.w      	r5, (r4, 0x3c)
  56:	b4ac      	st.w      	r5, (r4, 0x30)
  58:	b4ad      	st.w      	r5, (r4, 0x34)
  5a:	b4ae      	st.w      	r5, (r4, 0x38)
  5c:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_attach>
  60:	940b      	ld.w      	r0, (r4, 0x2c)
  62:	e0000000 	bsr      	0x0	// 0 <hgusb11_dev_attach>
  66:	6c53      	mov      	r1, r4
  68:	6c23      	mov      	r0, r8
  6a:	e0000000 	bsr      	0x0	// 0 <dev_register>
  6e:	6c17      	mov      	r0, r5
  70:	1495      	pop      	r4-r8, r15
  72:	0000      	.short	0x0000
  74:	00000000 	.long	0x00000000
