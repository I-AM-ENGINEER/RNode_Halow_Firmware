
disasm/libosal/obj/osal_work.o:     file format elf32-csky-little


Disassembly of section .text.list_del:

00000000 <list_del>:
   0:	9061      	ld.w      	r3, (r0, 0x4)
   2:	9040      	ld.w      	r2, (r0, 0x0)
   4:	e9030006 	bez      	r3, 0x10	// 10 <list_del+0x10>
   8:	e9020004 	bez      	r2, 0x10	// 10 <list_del+0x10>
   c:	b261      	st.w      	r3, (r2, 0x4)
   e:	b340      	st.w      	r2, (r3, 0x0)
  10:	3300      	movi      	r3, 0
  12:	b060      	st.w      	r3, (r0, 0x0)
  14:	b061      	st.w      	r3, (r0, 0x4)
  16:	783c      	jmp      	r15

Disassembly of section .text.os_work_func_cb:

00000000 <os_work_func_cb>:
   0:	14d0      	push      	r15
   2:	9068      	ld.w      	r3, (r0, 0x20)
   4:	904b      	ld.w      	r2, (r0, 0x2c)
   6:	902a      	ld.w      	r1, (r0, 0x28)
   8:	9009      	ld.w      	r0, (r0, 0x24)
   a:	7bcd      	jsr      	r3
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15

Disassembly of section .text.mainwkq_mntr_cb:

00000000 <mainwkq_mntr_cb>:
   0:	14d3      	push      	r4-r6, r15
   2:	1421      	subi      	r14, r14, 4
   4:	c0006023 	mfcr      	r3, cr<0, 0>
   8:	c0807020 	psrclr      	ie
   c:	1055      	lrw      	r2, 0x0	// 60 <mainwkq_mntr_cb+0x60>
   e:	e4632040 	andi      	r3, r3, 64
  12:	9294      	ld.w      	r4, (r2, 0x50)
  14:	6d4b      	mov      	r5, r2
  16:	e904001b 	bez      	r4, 0x4c	// 4c <mainwkq_mntr_cb+0x4c>
  1a:	94c7      	ld.w      	r6, (r4, 0x1c)
  1c:	e923001b 	bnez      	r3, 0x52	// 52 <mainwkq_mntr_cb+0x52>
  20:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  24:	d9852015 	ld.w      	r12, (r5, 0x54)
  28:	d9a52016 	ld.w      	r13, (r5, 0x58)
  2c:	6400      	cmphs      	r0, r0
  2e:	6033      	subc      	r0, r12
  30:	6077      	subc      	r1, r13
  32:	e9210005 	bnez      	r1, 0x3c	// 3c <mainwkq_mntr_cb+0x3c>
  36:	eb000064 	cmphsi      	r0, 101
  3a:	0c10      	bf      	0x5a	// 5a <mainwkq_mntr_cb+0x5a>
  3c:	b820      	st.w      	r1, (r14, 0x0)
  3e:	6cc3      	mov      	r3, r0
  40:	6c9b      	mov      	r2, r6
  42:	6c53      	mov      	r1, r4
  44:	1008      	lrw      	r0, 0x0	// 64 <mainwkq_mntr_cb+0x64>
  46:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  4a:	0408      	br      	0x5a	// 5a <mainwkq_mntr_cb+0x5a>
  4c:	e9030007 	bez      	r3, 0x5a	// 5a <mainwkq_mntr_cb+0x5a>
  50:	6d93      	mov      	r6, r4
  52:	c0807420 	psrset      	ie
  56:	e924ffe5 	bnez      	r4, 0x20	// 20 <mainwkq_mntr_cb+0x20>
  5a:	1401      	addi      	r14, r14, 4
  5c:	1493      	pop      	r4-r6, r15
	...

Disassembly of section .text.os_workqueue_add:

00000000 <os_workqueue_add>:
   0:	14d0      	push      	r15
   2:	816c      	ld.b      	r3, (r1, 0xc)
   4:	3200      	movi      	r2, 0
   6:	e46320fe 	andi      	r3, r3, 254
   a:	c4625c02 	ins      	r3, r2, 2, 2
   e:	a16c      	st.b      	r3, (r1, 0xc)
  10:	9163      	ld.w      	r3, (r1, 0xc)
  12:	1056      	lrw      	r2, 0xa763d3	// 68 <os_workqueue_add+0x68>
  14:	c4625ee8 	ins      	r3, r2, 31, 8
  18:	748c      	zextb      	r2, r3
  1a:	b163      	st.w      	r3, (r1, 0xc)
  1c:	e46220f8 	andi      	r3, r2, 248
  20:	b102      	st.w      	r0, (r1, 0x8)
  22:	e5800037 	addi      	r12, r0, 56
  26:	e9030009 	bez      	r3, 0x38	// 38 <os_workqueue_add+0x38>
  2a:	906e      	ld.w      	r3, (r0, 0x38)
  2c:	64f2      	cmpne      	r12, r3
  2e:	0c05      	bf      	0x38	// 38 <os_workqueue_add+0x38>
  30:	c46254e2 	zext      	r2, r2, 7, 3
  34:	64f2      	cmpne      	r12, r3
  36:	0806      	bt      	0x42	// 42 <os_workqueue_add+0x42>
  38:	906f      	ld.w      	r3, (r0, 0x3c)
  3a:	b02f      	st.w      	r1, (r0, 0x3c)
  3c:	dd812000 	st.w      	r12, (r1, 0x0)
  40:	040b      	br      	0x56	// 56 <os_workqueue_add+0x56>
  42:	d9a3000c 	ld.b      	r13, (r3, 0xc)
  46:	c46d484d 	lsri      	r13, r13, 3
  4a:	64b5      	cmplt      	r13, r2
  4c:	0c0b      	bf      	0x62	// 62 <os_workqueue_add+0x62>
  4e:	9361      	ld.w      	r3, (r3, 0x4)
  50:	9340      	ld.w      	r2, (r3, 0x0)
  52:	b221      	st.w      	r1, (r2, 0x4)
  54:	b140      	st.w      	r2, (r1, 0x0)
  56:	b161      	st.w      	r3, (r1, 0x4)
  58:	2047      	addi      	r0, 72
  5a:	b320      	st.w      	r1, (r3, 0x0)
  5c:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  60:	1490      	pop      	r15
  62:	9360      	ld.w      	r3, (r3, 0x0)
  64:	07e8      	br      	0x34	// 34 <os_workqueue_add+0x34>
  66:	0000      	.short	0x0000
  68:	00a763d3 	.long	0x00a763d3

Disassembly of section .text.os_workqueue_task:

00000000 <os_workqueue_task>:
   0:	14d8      	push      	r4-r11, r15
   2:	1422      	subi      	r14, r14, 8
   4:	6dc3      	mov      	r7, r0
   6:	3500      	movi      	r5, 0
   8:	e5400047 	addi      	r10, r0, 72
   c:	ea080000 	movi      	r8, 0
  10:	ea090000 	movi      	r9, 0
  14:	8745      	ld.b      	r2, (r7, 0x5)
  16:	3101      	movi      	r1, 1
  18:	c4415c03 	ins      	r2, r1, 3, 3
  1c:	3100      	movi      	r1, 0
  1e:	a745      	st.b      	r2, (r7, 0x5)
  20:	2900      	subi      	r1, 1
  22:	6c2b      	mov      	r0, r10
  24:	e0000000 	bsr      	0x0	// 0 <os_sema_down>
  28:	3600      	movi      	r6, 0
  2a:	8745      	ld.b      	r2, (r7, 0x5)
  2c:	c4465c03 	ins      	r2, r6, 3, 3
  30:	a745      	st.b      	r2, (r7, 0x5)
  32:	e5670037 	addi      	r11, r7, 56
  36:	c0006022 	mfcr      	r2, cr<0, 0>
  3a:	c0807020 	psrclr      	ie
  3e:	978e      	ld.w      	r4, (r7, 0x38)
  40:	66d2      	cmpne      	r4, r11
  42:	e4422040 	andi      	r2, r2, 64
  46:	0c53      	bf      	0xec	// ec <os_workqueue_task+0xec>
  48:	e9040052 	bez      	r4, 0xec	// ec <os_workqueue_task+0xec>
  4c:	b794      	st.w      	r4, (r7, 0x50)
  4e:	6c13      	mov      	r0, r4
  50:	b841      	st.w      	r2, (r14, 0x4)
  52:	e0000000 	bsr      	0x0	// 0 <os_workqueue_task>
  56:	94a3      	ld.w      	r5, (r4, 0xc)
  58:	1127      	lrw      	r1, 0x3d367a	// f4 <os_workqueue_task+0xf4>
  5a:	c4a15ee8 	ins      	r5, r1, 31, 8
  5e:	b4a3      	st.w      	r5, (r4, 0xc)
  60:	3101      	movi      	r1, 1
  62:	c4a15c00 	ins      	r5, r1, 0, 0
  66:	9841      	ld.w      	r2, (r14, 0x4)
  68:	9424      	ld.w      	r1, (r4, 0x10)
  6a:	2900      	subi      	r1, 1
  6c:	9467      	ld.w      	r3, (r4, 0x1c)
  6e:	a4ac      	st.b      	r5, (r4, 0xc)
  70:	b4c2      	st.w      	r6, (r4, 0x8)
  72:	b424      	st.w      	r1, (r4, 0x10)
  74:	c4255425 	zext      	r5, r5, 1, 1
  78:	b860      	st.w      	r3, (r14, 0x0)
  7a:	e9020006 	bez      	r2, 0x86	// 86 <os_workqueue_task+0x86>
  7e:	c0807420 	psrset      	ie
  82:	e904ffc9 	bez      	r4, 0x14	// 14 <os_workqueue_task+0x14>
  86:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  8a:	b715      	st.w      	r0, (r7, 0x54)
  8c:	b736      	st.w      	r1, (r7, 0x58)
  8e:	9860      	ld.w      	r3, (r14, 0x0)
  90:	6c13      	mov      	r0, r4
  92:	7bcd      	jsr      	r3
  94:	dd072015 	st.w      	r8, (r7, 0x54)
  98:	dd272016 	st.w      	r9, (r7, 0x58)
  9c:	b7d4      	st.w      	r6, (r7, 0x50)
  9e:	e9050006 	bez      	r5, 0xaa	// aa <os_workqueue_task+0xaa>
  a2:	6c13      	mov      	r0, r4
  a4:	e0000000 	bsr      	0x0	// 0 <_os_free>
  a8:	07c7      	br      	0x36	// 36 <os_workqueue_task+0x36>
  aa:	e920ffc6 	bnez      	r0, 0x36	// 36 <os_workqueue_task+0x36>
  ae:	c0006022 	mfcr      	r2, cr<0, 0>
  b2:	c0807020 	psrclr      	ie
  b6:	842c      	ld.b      	r1, (r4, 0xc)
  b8:	c4255c00 	ins      	r1, r5, 0, 0
  bc:	a42c      	st.b      	r1, (r4, 0xc)
  be:	9424      	ld.w      	r1, (r4, 0x10)
  c0:	e4422040 	andi      	r2, r2, 64
  c4:	e901000f 	bez      	r1, 0xe2	// e2 <os_workqueue_task+0xe2>
  c8:	3300      	movi      	r3, 0
  ca:	9423      	ld.w      	r1, (r4, 0xc)
  cc:	2bff      	subi      	r3, 256
  ce:	684c      	and      	r1, r3
  d0:	100a      	lrw      	r0, 0xa763d300	// f8 <os_workqueue_task+0xf8>
  d2:	6406      	cmpne      	r1, r0
  d4:	0c07      	bf      	0xe2	// e2 <os_workqueue_task+0xe2>
  d6:	6c53      	mov      	r1, r4
  d8:	6c1f      	mov      	r0, r7
  da:	b841      	st.w      	r2, (r14, 0x4)
  dc:	e0000000 	bsr      	0x0	// 0 <os_workqueue_task>
  e0:	9841      	ld.w      	r2, (r14, 0x4)
  e2:	e902ffaa 	bez      	r2, 0x36	// 36 <os_workqueue_task+0x36>
  e6:	c0807420 	psrset      	ie
  ea:	07a6      	br      	0x36	// 36 <os_workqueue_task+0x36>
  ec:	e902ff94 	bez      	r2, 0x14	// 14 <os_workqueue_task+0x14>
  f0:	3400      	movi      	r4, 0
  f2:	07c6      	br      	0x7e	// 7e <os_workqueue_task+0x7e>
  f4:	003d367a 	.long	0x003d367a
  f8:	a763d300 	.long	0xa763d300

Disassembly of section .text.os_workqueue_check_expired:

00000000 <os_workqueue_check_expired>:
   0:	14d8      	push      	r4-r11, r15
   2:	1421      	subi      	r14, r14, 4
   4:	6d03      	mov      	r4, r0
   6:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
   a:	6e03      	mov      	r8, r0
   c:	6e47      	mov      	r9, r1
   e:	9430      	ld.w      	r1, (r4, 0x40)
  10:	e544003f 	addi      	r10, r4, 64
  14:	91a0      	ld.w      	r5, (r1, 0x0)
  16:	ea0b0000 	movi      	r11, 0
  1a:	3600      	movi      	r6, 0
  1c:	3700      	movi      	r7, 0
  1e:	6686      	cmpne      	r1, r10
  20:	080a      	bt      	0x34	// 34 <os_workqueue_check_expired+0x34>
  22:	9410      	ld.w      	r0, (r4, 0x40)
  24:	6406      	cmpne      	r1, r0
  26:	0c26      	bf      	0x72	// 72 <os_workqueue_check_expired+0x72>
  28:	e9000004 	bez      	r0, 0x30	// 30 <os_workqueue_check_expired+0x30>
  2c:	9005      	ld.w      	r0, (r0, 0x14)
  2e:	6022      	subu      	r0, r8
  30:	1401      	addi      	r14, r14, 4
  32:	1498      	pop      	r4-r11, r15
  34:	9145      	ld.w      	r2, (r1, 0x14)
  36:	9166      	ld.w      	r3, (r1, 0x18)
  38:	64a2      	cmpne      	r8, r2
  3a:	0803      	bt      	0x40	// 40 <os_workqueue_check_expired+0x40>
  3c:	64e6      	cmpne      	r9, r3
  3e:	0c06      	bf      	0x4a	// 4a <os_workqueue_check_expired+0x4a>
  40:	6488      	cmphs      	r2, r2
  42:	60a3      	subc      	r2, r8
  44:	60e7      	subc      	r3, r9
  46:	e9a30013 	bhsz      	r3, 0x6c	// 6c <os_workqueue_check_expired+0x6c>
  4a:	816c      	ld.b      	r3, (r1, 0xc)
  4c:	c46b5c02 	ins      	r3, r11, 2, 2
  50:	a16c      	st.b      	r3, (r1, 0xc)
  52:	9164      	ld.w      	r3, (r1, 0x10)
  54:	2300      	addi      	r3, 1
  56:	6c07      	mov      	r0, r1
  58:	b1c5      	st.w      	r6, (r1, 0x14)
  5a:	b1e6      	st.w      	r7, (r1, 0x18)
  5c:	b164      	st.w      	r3, (r1, 0x10)
  5e:	b820      	st.w      	r1, (r14, 0x0)
  60:	e0000000 	bsr      	0x0	// 0 <os_workqueue_check_expired>
  64:	9820      	ld.w      	r1, (r14, 0x0)
  66:	6c13      	mov      	r0, r4
  68:	e0000000 	bsr      	0x0	// 0 <os_workqueue_check_expired>
  6c:	6c57      	mov      	r1, r5
  6e:	95a0      	ld.w      	r5, (r5, 0x0)
  70:	07d7      	br      	0x1e	// 1e <os_workqueue_check_expired+0x1e>
  72:	3000      	movi      	r0, 0
  74:	07de      	br      	0x30	// 30 <os_workqueue_check_expired+0x30>

Disassembly of section .text.os_workqueue_timer_cb:

00000000 <os_workqueue_timer_cb>:
   0:	14d3      	push      	r4-r6, r15
   2:	58be      	addi      	r5, r0, 8
   4:	6d83      	mov      	r6, r0
   6:	6c17      	mov      	r0, r5
   8:	e0000000 	bsr      	0x0	// 0 <os_timer_stop>
   c:	c0006024 	mfcr      	r4, cr<0, 0>
  10:	c0807020 	psrclr      	ie
  14:	6c1b      	mov      	r0, r6
  16:	e4842040 	andi      	r4, r4, 64
  1a:	e0000000 	bsr      	0x0	// 0 <os_workqueue_timer_cb>
  1e:	6c43      	mov      	r1, r0
  20:	e9040004 	bez      	r4, 0x28	// 28 <os_workqueue_timer_cb+0x28>
  24:	c0807420 	psrset      	ie
  28:	e9010005 	bez      	r1, 0x32	// 32 <os_workqueue_timer_cb+0x32>
  2c:	6c17      	mov      	r0, r5
  2e:	e0000000 	bsr      	0x0	// 0 <os_timer_start>
  32:	1493      	pop      	r4-r6, r15

Disassembly of section .text.mainwkq_monitor_init:

00000000 <mainwkq_monitor_init>:
   0:	14d1      	push      	r4, r15
   2:	1088      	lrw      	r4, 0x0	// 20 <mainwkq_monitor_init+0x20>
   4:	3300      	movi      	r3, 0
   6:	3201      	movi      	r2, 1
   8:	1027      	lrw      	r1, 0x0	// 24 <mainwkq_monitor_init+0x24>
   a:	6c13      	mov      	r0, r4
   c:	e0000000 	bsr      	0x0	// 0 <os_timer_init>
  10:	ea011388 	movi      	r1, 5000
  14:	6c13      	mov      	r0, r4
  16:	e0000000 	bsr      	0x0	// 0 <os_timer_start>
  1a:	3000      	movi      	r0, 0
  1c:	1491      	pop      	r4, r15
	...

Disassembly of section .text.os_workqueue_init:

00000000 <os_workqueue_init>:
   0:	14d2      	push      	r4-r5, r15
   2:	b020      	st.w      	r1, (r0, 0x0)
   4:	a863      	st.h      	r3, (r0, 0x6)
   6:	8822      	ld.h      	r1, (r0, 0x4)
   8:	e4600037 	addi      	r3, r0, 56
   c:	c4225d20 	ins      	r1, r2, 9, 0
  10:	b06e      	st.w      	r3, (r0, 0x38)
  12:	b06f      	st.w      	r3, (r0, 0x3c)
  14:	e460003f 	addi      	r3, r0, 64
  18:	6d03      	mov      	r4, r0
  1a:	a822      	st.h      	r1, (r0, 0x4)
  1c:	b070      	st.w      	r3, (r0, 0x40)
  1e:	b071      	st.w      	r3, (r0, 0x44)
  20:	3100      	movi      	r1, 0
  22:	2047      	addi      	r0, 72
  24:	e0000000 	bsr      	0x0	// 0 <os_sema_init>
  28:	e4a40023 	addi      	r5, r4, 36
  2c:	6cd3      	mov      	r3, r4
  2e:	3200      	movi      	r2, 0
  30:	102e      	lrw      	r1, 0x0	// 68 <os_workqueue_init+0x68>
  32:	5c1e      	addi      	r0, r4, 8
  34:	e0000000 	bsr      	0x0	// 0 <os_timer_init>
  38:	6cd3      	mov      	r3, r4
  3a:	104d      	lrw      	r2, 0x0	// 6c <os_workqueue_init+0x6c>
  3c:	6c57      	mov      	r1, r5
  3e:	9400      	ld.w      	r0, (r4, 0x0)
  40:	e0000000 	bsr      	0x0	// 0 <os_task_init>
  44:	8c23      	ld.h      	r1, (r4, 0x6)
  46:	6c17      	mov      	r0, r5
  48:	e0000000 	bsr      	0x0	// 0 <os_task_set_stacksize>
  4c:	8424      	ld.b      	r1, (r4, 0x4)
  4e:	6c17      	mov      	r0, r5
  50:	e0000000 	bsr      	0x0	// 0 <os_task_set_priority>
  54:	6c17      	mov      	r0, r5
  56:	e0000000 	bsr      	0x0	// 0 <os_task_run>
  5a:	8465      	ld.b      	r3, (r4, 0x5)
  5c:	3201      	movi      	r2, 1
  5e:	c4625c02 	ins      	r3, r2, 2, 2
  62:	3000      	movi      	r0, 0
  64:	a465      	st.b      	r3, (r4, 0x5)
  66:	1492      	pop      	r4-r5, r15
	...

Disassembly of section .text.os_work_schedule:

00000000 <os_work_schedule>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d83      	mov      	r6, r0
   4:	6d07      	mov      	r4, r1
   6:	c0006025 	mfcr      	r5, cr<0, 0>
   a:	c0807020 	psrclr      	ie
   e:	3200      	movi      	r2, 0
  10:	2aff      	subi      	r2, 256
  12:	9163      	ld.w      	r3, (r1, 0xc)
  14:	c4432021 	and      	r1, r3, r2
  18:	104f      	lrw      	r2, 0xa763d300	// 54 <os_work_schedule+0x54>
  1a:	6486      	cmpne      	r1, r2
  1c:	e4a52040 	andi      	r5, r5, 64
  20:	080d      	bt      	0x3a	// 3a <os_work_schedule+0x3a>
  22:	3200      	movi      	r2, 0
  24:	2afb      	subi      	r2, 252
  26:	68c8      	and      	r3, r2
  28:	104c      	lrw      	r2, 0xa763d304	// 58 <os_work_schedule+0x58>
  2a:	648e      	cmpne      	r3, r2
  2c:	080b      	bt      	0x42	// 42 <os_work_schedule+0x42>
  2e:	9460      	ld.w      	r3, (r4, 0x0)
  30:	e9030005 	bez      	r3, 0x3a	// 3a <os_work_schedule+0x3a>
  34:	6c13      	mov      	r0, r4
  36:	e0000000 	bsr      	0x0	// 0 <os_work_schedule>
  3a:	6c53      	mov      	r1, r4
  3c:	6c1b      	mov      	r0, r6
  3e:	e0000000 	bsr      	0x0	// 0 <os_work_schedule>
  42:	9464      	ld.w      	r3, (r4, 0x10)
  44:	2300      	addi      	r3, 1
  46:	b464      	st.w      	r3, (r4, 0x10)
  48:	e9050004 	bez      	r5, 0x50	// 50 <os_work_schedule+0x50>
  4c:	c0807420 	psrset      	ie
  50:	1493      	pop      	r4-r6, r15
  52:	0000      	.short	0x0000
  54:	a763d300 	.long	0xa763d300
  58:	a763d304 	.long	0xa763d304

Disassembly of section .text.os_work_schedule_delay:

00000000 <os_work_schedule_delay>:
   0:	14d5      	push      	r4-r8, r15
   2:	58de      	addi      	r6, r0, 8
   4:	6dc3      	mov      	r7, r0
   6:	6c1b      	mov      	r0, r6
   8:	6d07      	mov      	r4, r1
   a:	6e0b      	mov      	r8, r2
   c:	e0000000 	bsr      	0x0	// 0 <os_timer_stop>
  10:	c0006025 	mfcr      	r5, cr<0, 0>
  14:	c0807020 	psrclr      	ie
  18:	3200      	movi      	r2, 0
  1a:	2aff      	subi      	r2, 256
  1c:	9463      	ld.w      	r3, (r4, 0xc)
  1e:	68c8      	and      	r3, r2
  20:	1146      	lrw      	r2, 0xa763d300	// b8 <os_work_schedule_delay+0xb8>
  22:	648e      	cmpne      	r3, r2
  24:	e4a52040 	andi      	r5, r5, 64
  28:	0807      	bt      	0x36	// 36 <os_work_schedule_delay+0x36>
  2a:	9460      	ld.w      	r3, (r4, 0x0)
  2c:	e9030005 	bez      	r3, 0x36	// 36 <os_work_schedule_delay+0x36>
  30:	6c13      	mov      	r0, r4
  32:	e0000000 	bsr      	0x0	// 0 <os_work_schedule_delay>
  36:	846c      	ld.b      	r3, (r4, 0xc)
  38:	3201      	movi      	r2, 1
  3a:	e46320fe 	andi      	r3, r3, 254
  3e:	c4625c02 	ins      	r3, r2, 2, 2
  42:	a46c      	st.b      	r3, (r4, 0xc)
  44:	9463      	ld.w      	r3, (r4, 0xc)
  46:	105e      	lrw      	r2, 0xa763d3	// bc <os_work_schedule_delay+0xbc>
  48:	c4625ee8 	ins      	r3, r2, 31, 8
  4c:	b463      	st.w      	r3, (r4, 0xc)
  4e:	b4e2      	st.w      	r7, (r4, 0x8)
  50:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  54:	6ca3      	mov      	r2, r8
  56:	3300      	movi      	r3, 0
  58:	6401      	cmplt      	r0, r0
  5a:	6009      	addc      	r0, r2
  5c:	604d      	addc      	r1, r3
  5e:	e447003f 	addi      	r2, r7, 64
  62:	9770      	ld.w      	r3, (r7, 0x40)
  64:	64ca      	cmpne      	r2, r3
  66:	b405      	st.w      	r0, (r4, 0x14)
  68:	b426      	st.w      	r1, (r4, 0x18)
  6a:	0c03      	bf      	0x70	// 70 <os_work_schedule_delay+0x70>
  6c:	64ca      	cmpne      	r2, r3
  6e:	0804      	bt      	0x76	// 76 <os_work_schedule_delay+0x76>
  70:	9771      	ld.w      	r3, (r7, 0x44)
  72:	b791      	st.w      	r4, (r7, 0x44)
  74:	040f      	br      	0x92	// 92 <os_work_schedule_delay+0x92>
  76:	d9832005 	ld.w      	r12, (r3, 0x14)
  7a:	d9a32006 	ld.w      	r13, (r3, 0x18)
  7e:	6730      	cmphs      	r12, r12
  80:	c580010c 	subc      	r12, r0, r12
  84:	c5a1010d 	subc      	r13, r1, r13
  88:	e9ad0016 	bhsz      	r13, 0xb4	// b4 <os_work_schedule_delay+0xb4>
  8c:	9361      	ld.w      	r3, (r3, 0x4)
  8e:	9340      	ld.w      	r2, (r3, 0x0)
  90:	b281      	st.w      	r4, (r2, 0x4)
  92:	b440      	st.w      	r2, (r4, 0x0)
  94:	b461      	st.w      	r3, (r4, 0x4)
  96:	6c1f      	mov      	r0, r7
  98:	b380      	st.w      	r4, (r3, 0x0)
  9a:	e0000000 	bsr      	0x0	// 0 <os_work_schedule_delay>
  9e:	6c43      	mov      	r1, r0
  a0:	e9050004 	bez      	r5, 0xa8	// a8 <os_work_schedule_delay+0xa8>
  a4:	c0807420 	psrset      	ie
  a8:	e9010005 	bez      	r1, 0xb2	// b2 <os_work_schedule_delay+0xb2>
  ac:	6c1b      	mov      	r0, r6
  ae:	e0000000 	bsr      	0x0	// 0 <os_timer_start>
  b2:	1495      	pop      	r4-r8, r15
  b4:	9360      	ld.w      	r3, (r3, 0x0)
  b6:	07db      	br      	0x6c	// 6c <os_work_schedule_delay+0x6c>
  b8:	a763d300 	.long	0xa763d300
  bc:	00a763d3 	.long	0x00a763d3

Disassembly of section .text.os_work_cancle:

00000000 <os_work_cancle>:
   0:	14d3      	push      	r4-r6, r15
   2:	9062      	ld.w      	r3, (r0, 0x8)
   4:	6d43      	mov      	r5, r0
   6:	6d87      	mov      	r6, r1
   8:	e903001f 	bez      	r3, 0x46	// 46 <os_work_cancle+0x46>
   c:	c0006024 	mfcr      	r4, cr<0, 0>
  10:	c0807020 	psrclr      	ie
  14:	3200      	movi      	r2, 0
  16:	2aff      	subi      	r2, 256
  18:	9063      	ld.w      	r3, (r0, 0xc)
  1a:	68c8      	and      	r3, r2
  1c:	1050      	lrw      	r2, 0xa763d300	// 5c <os_work_cancle+0x5c>
  1e:	648e      	cmpne      	r3, r2
  20:	e4842040 	andi      	r4, r4, 64
  24:	0812      	bt      	0x48	// 48 <os_work_cancle+0x48>
  26:	9060      	ld.w      	r3, (r0, 0x0)
  28:	e9030004 	bez      	r3, 0x30	// 30 <os_work_cancle+0x30>
  2c:	e0000000 	bsr      	0x0	// 0 <os_work_cancle>
  30:	e9040004 	bez      	r4, 0x38	// 38 <os_work_cancle+0x38>
  34:	c0807420 	psrset      	ie
  38:	e9060007 	bez      	r6, 0x46	// 46 <os_work_cancle+0x46>
  3c:	856c      	ld.b      	r3, (r5, 0xc)
  3e:	e4632001 	andi      	r3, r3, 1
  42:	e9230009 	bnez      	r3, 0x54	// 54 <os_work_cancle+0x54>
  46:	1493      	pop      	r4-r6, r15
  48:	1046      	lrw      	r2, 0x3d367a00	// 60 <os_work_cancle+0x60>
  4a:	648e      	cmpne      	r3, r2
  4c:	3300      	movi      	r3, 0
  4e:	c4c30c40 	inct      	r6, r3, 0
  52:	07ef      	br      	0x30	// 30 <os_work_cancle+0x30>
  54:	3001      	movi      	r0, 1
  56:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
  5a:	07ef      	br      	0x38	// 38 <os_work_cancle+0x38>
  5c:	d300      	.short	0xd300
  5e:	a763      	.short	0xa763
  60:	3d367a00 	.long	0x3d367a00

Disassembly of section .text.os_run_func:

00000000 <os_run_func>:
   0:	14d5      	push      	r4-r8, r15
   2:	1096      	lrw      	r4, 0x0	// 58 <os_run_func+0x58>
   4:	6d43      	mov      	r5, r0
   6:	8405      	ld.b      	r0, (r4, 0x5)
   8:	e4002004 	andi      	r0, r0, 4
   c:	6e07      	mov      	r8, r1
   e:	6dcb      	mov      	r7, r2
  10:	6d8f      	mov      	r6, r3
  12:	e900001d 	bez      	r0, 0x4c	// 4c <os_run_func+0x4c>
  16:	e905001b 	bez      	r5, 0x4c	// 4c <os_run_func+0x4c>
  1a:	3030      	movi      	r0, 48
  1c:	e0000000 	bsr      	0x0	// 0 <_os_zalloc>
  20:	e9000019 	bez      	r0, 0x52	// 52 <os_run_func+0x52>
  24:	106e      	lrw      	r3, 0x0	// 5c <os_run_func+0x5c>
  26:	d980000c 	ld.b      	r12, (r0, 0xc)
  2a:	b067      	st.w      	r3, (r0, 0x1c)
  2c:	3301      	movi      	r3, 1
  2e:	c5835c01 	ins      	r12, r3, 1, 1
  32:	dd80000c 	st.b      	r12, (r0, 0xc)
  36:	b0a8      	st.w      	r5, (r0, 0x20)
  38:	dd002009 	st.w      	r8, (r0, 0x24)
  3c:	b0ea      	st.w      	r7, (r0, 0x28)
  3e:	b0cb      	st.w      	r6, (r0, 0x2c)
  40:	6c43      	mov      	r1, r0
  42:	6c13      	mov      	r0, r4
  44:	e0000000 	bsr      	0x0	// 0 <os_run_func>
  48:	3000      	movi      	r0, 0
  4a:	1495      	pop      	r4-r8, r15
  4c:	3000      	movi      	r0, 0
  4e:	2815      	subi      	r0, 22
  50:	07fd      	br      	0x4a	// 4a <os_run_func+0x4a>
  52:	3000      	movi      	r0, 0
  54:	280b      	subi      	r0, 12
  56:	07fa      	br      	0x4a	// 4a <os_run_func+0x4a>
	...

Disassembly of section .text.os_run_func_delay:

00000000 <os_run_func_delay>:
   0:	14d5      	push      	r4-r8, r15
   2:	1098      	lrw      	r4, 0x0	// 60 <os_run_func_delay+0x60>
   4:	6d83      	mov      	r6, r0
   6:	d9840005 	ld.b      	r12, (r4, 0x5)
   a:	e58c2004 	andi      	r12, r12, 4
   e:	6e07      	mov      	r8, r1
  10:	6dcb      	mov      	r7, r2
  12:	6d4f      	mov      	r5, r3
  14:	e90c0020 	bez      	r12, 0x54	// 54 <os_run_func_delay+0x54>
  18:	e900001e 	bez      	r0, 0x54	// 54 <os_run_func_delay+0x54>
  1c:	e9230005 	bnez      	r3, 0x26	// 26 <os_run_func_delay+0x26>
  20:	e0000000 	bsr      	0x0	// 0 <os_run_func_delay>
  24:	1495      	pop      	r4-r8, r15
  26:	3030      	movi      	r0, 48
  28:	e0000000 	bsr      	0x0	// 0 <_os_zalloc>
  2c:	6c43      	mov      	r1, r0
  2e:	e9000016 	bez      	r0, 0x5a	// 5a <os_run_func_delay+0x5a>
  32:	106d      	lrw      	r3, 0x0	// 64 <os_run_func_delay+0x64>
  34:	3201      	movi      	r2, 1
  36:	b067      	st.w      	r3, (r0, 0x1c)
  38:	806c      	ld.b      	r3, (r0, 0xc)
  3a:	c4625c01 	ins      	r3, r2, 1, 1
  3e:	a06c      	st.b      	r3, (r0, 0xc)
  40:	b0c8      	st.w      	r6, (r0, 0x20)
  42:	dd002009 	st.w      	r8, (r0, 0x24)
  46:	b0ea      	st.w      	r7, (r0, 0x28)
  48:	6c97      	mov      	r2, r5
  4a:	6c13      	mov      	r0, r4
  4c:	e0000000 	bsr      	0x0	// 0 <os_run_func_delay>
  50:	3000      	movi      	r0, 0
  52:	07e9      	br      	0x24	// 24 <os_run_func_delay+0x24>
  54:	3000      	movi      	r0, 0
  56:	2815      	subi      	r0, 22
  58:	07e6      	br      	0x24	// 24 <os_run_func_delay+0x24>
  5a:	3000      	movi      	r0, 0
  5c:	280b      	subi      	r0, 12
  5e:	07e3      	br      	0x24	// 24 <os_run_func_delay+0x24>
	...

Disassembly of section .text.os_run_work:

00000000 <os_run_work>:
   0:	14d0      	push      	r15
   2:	6c43      	mov      	r1, r0
   4:	1009      	lrw      	r0, 0x0	// 28 <os_run_work+0x28>
   6:	8065      	ld.b      	r3, (r0, 0x5)
   8:	e4632004 	andi      	r3, r3, 4
   c:	e903000b 	bez      	r3, 0x22	// 22 <os_run_work+0x22>
  10:	e9010009 	bez      	r1, 0x22	// 22 <os_run_work+0x22>
  14:	9167      	ld.w      	r3, (r1, 0x1c)
  16:	e9030006 	bez      	r3, 0x22	// 22 <os_run_work+0x22>
  1a:	e0000000 	bsr      	0x0	// 0 <os_run_work>
  1e:	3000      	movi      	r0, 0
  20:	1490      	pop      	r15
  22:	3000      	movi      	r0, 0
  24:	2815      	subi      	r0, 22
  26:	07fd      	br      	0x20	// 20 <os_run_work+0x20>
  28:	00000000 	.long	0x00000000

Disassembly of section .text.os_run_work_delay:

00000000 <os_run_work_delay>:
   0:	14d1      	push      	r4, r15
   2:	6cc3      	mov      	r3, r0
   4:	100d      	lrw      	r0, 0x0	// 38 <os_run_work_delay+0x38>
   6:	8045      	ld.b      	r2, (r0, 0x5)
   8:	e4422004 	andi      	r2, r2, 4
   c:	e9020013 	bez      	r2, 0x32	// 32 <os_run_work_delay+0x32>
  10:	e9030011 	bez      	r3, 0x32	// 32 <os_run_work_delay+0x32>
  14:	9347      	ld.w      	r2, (r3, 0x1c)
  16:	e902000e 	bez      	r2, 0x32	// 32 <os_run_work_delay+0x32>
  1a:	e9210007 	bnez      	r1, 0x28	// 28 <os_run_work_delay+0x28>
  1e:	6c4f      	mov      	r1, r3
  20:	e0000000 	bsr      	0x0	// 0 <os_run_work_delay>
  24:	3000      	movi      	r0, 0
  26:	1491      	pop      	r4, r15
  28:	6c87      	mov      	r2, r1
  2a:	6c4f      	mov      	r1, r3
  2c:	e0000000 	bsr      	0x0	// 0 <os_run_work_delay>
  30:	07fa      	br      	0x24	// 24 <os_run_work_delay+0x24>
  32:	3000      	movi      	r0, 0
  34:	2815      	subi      	r0, 22
  36:	07f8      	br      	0x26	// 26 <os_run_work_delay+0x26>
  38:	00000000 	.long	0x00000000
