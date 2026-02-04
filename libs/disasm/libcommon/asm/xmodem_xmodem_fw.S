
disasm/libcommon/obj/xmodem_xmodem_fw.o:     file format elf32-csky-little


Disassembly of section .text.xmodem_fwupgrade_task:

00000000 <xmodem_fwupgrade_task>:
   0:	14d5      	push      	r4-r8, r15
   2:	1424      	subi      	r14, r14, 16
   4:	6d03      	mov      	r4, r0
   6:	3100      	movi      	r1, 0
   8:	320c      	movi      	r2, 12
   a:	1801      	addi      	r0, r14, 4
   c:	b820      	st.w      	r1, (r14, 0x0)
   e:	e0000000 	bsr      	0x0	// 0 <memset>
  12:	1269      	lrw      	r3, 0x0	// 134 <xmodem_fwupgrade_task+0x134>
  14:	3096      	movi      	r0, 150
  16:	b861      	st.w      	r3, (r14, 0x4)
  18:	4003      	lsli      	r0, r0, 3
  1a:	1268      	lrw      	r3, 0x0	// 138 <xmodem_fwupgrade_task+0x138>
  1c:	b862      	st.w      	r3, (r14, 0x8)
  1e:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  22:	6d43      	mov      	r5, r0
  24:	e9000083 	bez      	r0, 0x12a	// 12a <xmodem_fwupgrade_task+0x12a>
  28:	1205      	lrw      	r0, 0x0	// 13c <atcmd_printf+0x13c>
  2a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  2e:	3c41      	cmpnei      	r4, 1
  30:	0805      	bt      	0x3a	// 3a <xmodem_fwupgrade_task+0x3a>
  32:	c0006023 	mfcr      	r3, cr<0, 0>
  36:	c0807020 	psrclr      	ie
  3a:	3000      	movi      	r0, 0
  3c:	e0000000 	bsr      	0x0	// 0 <mcu_watchdog_timeout>
  40:	3001      	movi      	r0, 1
  42:	e0000000 	bsr      	0x0	// 0 <disable_print>
  46:	117f      	lrw      	r3, 0x0	// 140 <xmodem_fwupgrade_task+0x140>
  48:	3101      	movi      	r1, 1
  4a:	8341      	ld.b      	r2, (r3, 0x1)
  4c:	c4415c03 	ins      	r2, r1, 3, 3
  50:	3700      	movi      	r7, 0
  52:	a341      	st.b      	r2, (r3, 0x1)
  54:	61c6      	subu      	r7, r1
  56:	3400      	movi      	r4, 0
  58:	3c40      	cmpnei      	r4, 0
  5a:	ea03044c 	movi      	r3, 1100
  5e:	5d50      	addu      	r2, r5, r4
  60:	c4000501 	mvc      	r1
  64:	1801      	addi      	r0, r14, 4
  66:	e0000000 	bsr      	0x0	// 0 <xmodem_receive>
  6a:	e9600035 	blsz      	r0, 0xd4	// d4 <xmodem_fwupgrade_task+0xd4>
  6e:	6100      	addu      	r4, r0
  70:	eb2403ff 	cmplti      	r4, 1024
  74:	0bf2      	bt      	0x58	// 58 <xmodem_fwupgrade_task+0x58>
  76:	6c7b      	mov      	r1, r14
  78:	6c17      	mov      	r0, r5
  7a:	e0000000 	bsr      	0x0	// 0 <fwinfo_get_fw_chipid>
  7e:	6d83      	mov      	r6, r0
  80:	e0000000 	bsr      	0x0	// 0 <sysctrl_get_chip_id>
  84:	641a      	cmpne      	r6, r0
  86:	0827      	bt      	0xd4	// d4 <xmodem_fwupgrade_task+0xd4>
  88:	3100      	movi      	r1, 0
  8a:	6c07      	mov      	r0, r1
  8c:	74d1      	zexth      	r3, r4
  8e:	6c97      	mov      	r2, r5
  90:	2800      	subi      	r0, 1
  92:	e0000000 	bsr      	0x0	// 0 <libota_write_fw_ah>
  96:	b800      	st.w      	r0, (r14, 0x0)
  98:	e920001e 	bnez      	r0, 0xd4	// d4 <xmodem_fwupgrade_task+0xd4>
  9c:	ea03044c 	movi      	r3, 1100
  a0:	6c97      	mov      	r2, r5
  a2:	3101      	movi      	r1, 1
  a4:	1801      	addi      	r0, r14, 4
  a6:	e0000000 	bsr      	0x0	// 0 <xmodem_receive>
  aa:	6d83      	mov      	r6, r0
  ac:	e9600026 	blsz      	r0, 0xf8	// f8 <xmodem_fwupgrade_task+0xf8>
  b0:	c4040028 	addu      	r8, r4, r0
  b4:	65e2      	cmpne      	r8, r7
  b6:	0817      	bt      	0xe4	// e4 <xmodem_fwupgrade_task+0xe4>
  b8:	c4842483 	nor      	r3, r4, r4
  bc:	74cd      	zexth      	r3, r3
  be:	6c97      	mov      	r2, r5
  c0:	6c53      	mov      	r1, r4
  c2:	6c1f      	mov      	r0, r7
  c4:	e0000000 	bsr      	0x0	// 0 <libota_write_fw_ah>
  c8:	b800      	st.w      	r0, (r14, 0x0)
  ca:	9860      	ld.w      	r3, (r14, 0x0)
  cc:	c4c80024 	addu      	r4, r8, r6
  d0:	e903002a 	bez      	r3, 0x124	// 124 <xmodem_fwupgrade_task+0x124>
  d4:	ea03044c 	movi      	r3, 1100
  d8:	6c97      	mov      	r2, r5
  da:	3103      	movi      	r1, 3
  dc:	1801      	addi      	r0, r14, 4
  de:	e0000000 	bsr      	0x0	// 0 <xmodem_receive>
  e2:	07ba      	br      	0x56	// 56 <xmodem_fwupgrade_task+0x56>
  e4:	74c1      	zexth      	r3, r0
  e6:	3000      	movi      	r0, 0
  e8:	6c97      	mov      	r2, r5
  ea:	6c53      	mov      	r1, r4
  ec:	2800      	subi      	r0, 1
  ee:	e0000000 	bsr      	0x0	// 0 <libota_write_fw_ah>
  f2:	b800      	st.w      	r0, (r14, 0x0)
  f4:	6e13      	mov      	r8, r4
  f6:	07ea      	br      	0xca	// ca <xmodem_fwupgrade_task+0xca>
  f8:	e920ffee 	bnez      	r0, 0xd4	// d4 <xmodem_fwupgrade_task+0xd4>
  fc:	6cc3      	mov      	r3, r0
  fe:	6c97      	mov      	r2, r5
 100:	6c53      	mov      	r1, r4
 102:	6c13      	mov      	r0, r4
 104:	e0000000 	bsr      	0x0	// 0 <libota_write_fw_ah>
 108:	1801      	addi      	r0, r14, 4
 10a:	e0000000 	bsr      	0x0	// 0 <xmodem_stop>
 10e:	6c17      	mov      	r0, r5
 110:	e0000000 	bsr      	0x0	// 0 <_os_free>
 114:	3000      	movi      	r0, 0
 116:	e0000000 	bsr      	0x0	// 0 <disable_print>
 11a:	e0000000 	bsr      	0x0	// 0 <mcu_reset>
 11e:	3000      	movi      	r0, 0
 120:	1404      	addi      	r14, r14, 16
 122:	1495      	pop      	r4-r8, r15
 124:	65d2      	cmpne      	r4, r7
 126:	0bbb      	bt      	0x9c	// 9c <xmodem_fwupgrade_task+0x9c>
 128:	07f0      	br      	0x108	// 108 <xmodem_fwupgrade_task+0x108>
 12a:	1007      	lrw      	r0, 0x0	// 144 <xmodem_fwupgrade_task+0x144>
 12c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
 130:	07f7      	br      	0x11e	// 11e <xmodem_fwupgrade_task+0x11e>
	...

Disassembly of section .text.xmodem_in:

00000000 <xmodem_in>:
   0:	14d2      	push      	r4-r5, r15
   2:	3300      	movi      	r3, 0
   4:	2b00      	subi      	r3, 1
   6:	b160      	st.w      	r3, (r1, 0x0)
   8:	6d47      	mov      	r5, r1
   a:	1073      	lrw      	r3, 0x0	// 54 <xmodem_in+0x54>
   c:	6d0f      	mov      	r4, r3
   e:	9340      	ld.w      	r2, (r3, 0x0)
  10:	d982180f 	ld.h      	r12, (r2, 0x101e)
  14:	d822180e 	ld.h      	r1, (r2, 0x101c)
  18:	6472      	cmpne      	r12, r1
  1a:	0805      	bt      	0x24	// 24 <xmodem_in+0x24>
  1c:	6c43      	mov      	r1, r0
  1e:	6c0b      	mov      	r0, r2
  20:	e0000000 	bsr      	0x0	// 0 <os_sema_down>
  24:	9440      	ld.w      	r2, (r4, 0x0)
  26:	d862180f 	ld.h      	r3, (r2, 0x101e)
  2a:	d822180e 	ld.h      	r1, (r2, 0x101c)
  2e:	64c6      	cmpne      	r1, r3
  30:	0c0f      	bf      	0x4e	// 4e <xmodem_in+0x4e>
  32:	5a2c      	addu      	r1, r2, r3
  34:	2300      	addi      	r3, 1
  36:	74cd      	zexth      	r3, r3
  38:	eb030fff 	cmphsi      	r3, 4096
  3c:	811c      	ld.b      	r0, (r1, 0x1c)
  3e:	0806      	bt      	0x4a	// 4a <xmodem_in+0x4a>
  40:	dc62180f 	st.h      	r3, (r2, 0x101e)
  44:	3300      	movi      	r3, 0
  46:	b560      	st.w      	r3, (r5, 0x0)
  48:	1492      	pop      	r4-r5, r15
  4a:	3300      	movi      	r3, 0
  4c:	07fa      	br      	0x40	// 40 <xmodem_in+0x40>
  4e:	3000      	movi      	r0, 0
  50:	07fc      	br      	0x48	// 48 <xmodem_in+0x48>
  52:	0000      	.short	0x0000
  54:	00000000 	.long	0x00000000

Disassembly of section .text.xmodem_out:

00000000 <xmodem_out>:
   0:	14d0      	push      	r15
   2:	1421      	subi      	r14, r14, 4
   4:	dc0e0003 	st.b      	r0, (r14, 0x3)
   8:	3101      	movi      	r1, 1
   a:	e40e0002 	addi      	r0, r14, 3
   e:	e0000000 	bsr      	0x0	// 0 <atcmd_output>
  12:	1401      	addi      	r14, r14, 4
  14:	1490      	pop      	r15

Disassembly of section .text.xmodem_fwupgrade_hdl:

00000000 <xmodem_fwupgrade_hdl>:
   0:	14d4      	push      	r4-r7, r15
   2:	1195      	lrw      	r4, 0x0	// d4 <xmodem_fwupgrade_hdl+0xd4>
   4:	6dc7      	mov      	r7, r1
   6:	9460      	ld.w      	r3, (r4, 0x0)
   8:	6d4b      	mov      	r5, r2
   a:	e9230033 	bnez      	r3, 0x70	// 70 <xmodem_fwupgrade_hdl+0x70>
   e:	3081      	movi      	r0, 129
  10:	4005      	lsli      	r0, r0, 5
  12:	e0000000 	bsr      	0x0	// 0 <_os_zalloc>
  16:	b400      	st.w      	r0, (r4, 0x0)
  18:	e9000028 	bez      	r0, 0x68	// 68 <xmodem_fwupgrade_hdl+0x68>
  1c:	e9050008 	bez      	r5, 0x2c	// 2c <xmodem_fwupgrade_hdl+0x2c>
  20:	9760      	ld.w      	r3, (r7, 0x0)
  22:	8360      	ld.b      	r3, (r3, 0x0)
  24:	eb430031 	cmpnei      	r3, 49
  28:	6543      	mvcv      	r5
  2a:	7554      	zextb      	r5, r5
  2c:	3100      	movi      	r1, 0
  2e:	e0000000 	bsr      	0x0	// 0 <os_sema_init>
  32:	9420      	ld.w      	r1, (r4, 0x0)
  34:	6cd7      	mov      	r3, r5
  36:	1149      	lrw      	r2, 0x0	// d8 <xmodem_fwupgrade_hdl+0xd8>
  38:	2107      	addi      	r1, 8
  3a:	1109      	lrw      	r0, 0x0	// dc <xmodem_fwupgrade_hdl+0xdc>
  3c:	e0000000 	bsr      	0x0	// 0 <os_task_init>
  40:	9400      	ld.w      	r0, (r4, 0x0)
  42:	3180      	movi      	r1, 128
  44:	4124      	lsli      	r1, r1, 4
  46:	2007      	addi      	r0, 8
  48:	e0000000 	bsr      	0x0	// 0 <os_task_set_stacksize>
  4c:	9400      	ld.w      	r0, (r4, 0x0)
  4e:	3140      	movi      	r1, 64
  50:	2007      	addi      	r0, 8
  52:	e0000000 	bsr      	0x0	// 0 <os_task_set_priority>
  56:	9400      	ld.w      	r0, (r4, 0x0)
  58:	2007      	addi      	r0, 8
  5a:	e0000000 	bsr      	0x0	// 0 <os_task_run>
  5e:	9460      	ld.w      	r3, (r4, 0x0)
  60:	3b40      	cmpnei      	r3, 0
  62:	c4000500 	mvc      	r0
  66:	1494      	pop      	r4-r7, r15
  68:	101e      	lrw      	r0, 0x0	// e0 <xmodem_fwupgrade_hdl+0xe0>
  6a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  6e:	07f8      	br      	0x5e	// 5e <xmodem_fwupgrade_hdl+0x5e>
  70:	d803180e 	ld.h      	r0, (r3, 0x101c)
  74:	5a20      	addu      	r1, r2, r0
  76:	eb011000 	cmphsi      	r1, 4097
  7a:	231b      	addi      	r3, 28
  7c:	0818      	bt      	0xac	// ac <xmodem_fwupgrade_hdl+0xac>
  7e:	600c      	addu      	r0, r3
  80:	9720      	ld.w      	r1, (r7, 0x0)
  82:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
  86:	9440      	ld.w      	r2, (r4, 0x0)
  88:	d862180e 	ld.h      	r3, (r2, 0x101c)
  8c:	614c      	addu      	r5, r3
  8e:	dca2180e 	st.h      	r5, (r2, 0x101c)
  92:	9400      	ld.w      	r0, (r4, 0x0)
  94:	d860180e 	ld.h      	r3, (r0, 0x101c)
  98:	eb030fff 	cmphsi      	r3, 4096
  9c:	0c04      	bf      	0xa4	// a4 <xmodem_fwupgrade_hdl+0xa4>
  9e:	3300      	movi      	r3, 0
  a0:	dc60180e 	st.h      	r3, (r0, 0x101c)
  a4:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  a8:	3001      	movi      	r0, 1
  aa:	07de      	br      	0x66	// 66 <xmodem_fwupgrade_hdl+0x66>
  ac:	3680      	movi      	r6, 128
  ae:	46c5      	lsli      	r6, r6, 5
  b0:	6182      	subu      	r6, r0
  b2:	6c9b      	mov      	r2, r6
  b4:	600c      	addu      	r0, r3
  b6:	9720      	ld.w      	r1, (r7, 0x0)
  b8:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
  bc:	615a      	subu      	r5, r6
  be:	9720      	ld.w      	r1, (r7, 0x0)
  c0:	9400      	ld.w      	r0, (r4, 0x0)
  c2:	6c97      	mov      	r2, r5
  c4:	6058      	addu      	r1, r6
  c6:	201b      	addi      	r0, 28
  c8:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
  cc:	9460      	ld.w      	r3, (r4, 0x0)
  ce:	dca3180e 	st.h      	r5, (r3, 0x101c)
  d2:	07e0      	br      	0x92	// 92 <xmodem_fwupgrade_hdl+0x92>
	...
