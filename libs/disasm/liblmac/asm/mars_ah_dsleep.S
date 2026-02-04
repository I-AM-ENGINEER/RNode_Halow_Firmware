
disasm/liblmac/obj/mars_ah_dsleep.o:     file format elf32-csky-little


Disassembly of section .text.csi_system_reset:

00000000 <csi_system_reset>:
   0:	c01f6023 	mfcr      	r3, cr<31, 0>
   4:	ea025432 	movi      	r2, 21554
   8:	6c8a      	nor      	r2, r2
   a:	c4625df0 	ins      	r3, r2, 31, 16
   e:	c0000420 	sync
  12:	c003643f 	mtcr      	r3, cr<31, 0>
  16:	c0000420 	sync
  1a:	6c03      	mov      	r0, r0
  1c:	07ff      	br      	0x1a	// 1a <csi_system_reset+0x1a>

Disassembly of section .text.core_sec_opt_func:

00000000 <core_sec_opt_func>:
   0:	ea038003 	movi      	r3, 32771
   4:	c5e34903 	rotli      	r3, r3, 15
   8:	1048      	lrw      	r2, 0xc053781b	// 28 <core_sec_opt_func+0x28>
   a:	dc03202e 	st.w      	r0, (r3, 0xb8)
   e:	dc23202d 	st.w      	r1, (r3, 0xb4)
  12:	dc43202f 	st.w      	r2, (r3, 0xbc)
  16:	6c03      	mov      	r0, r0
  18:	6c03      	mov      	r0, r0
  1a:	6c03      	mov      	r0, r0
  1c:	6c03      	mov      	r0, r0
  1e:	6c03      	mov      	r0, r0
  20:	6c03      	mov      	r0, r0
  22:	6c03      	mov      	r0, r0
  24:	6c03      	mov      	r0, r0
  26:	783c      	jmp      	r15
  28:	c053781b 	.long	0xc053781b

Disassembly of section .text.system_sleep_config:

00000000 <system_sleep_config>:
   0:	3807      	cmphsi      	r0, 8
   2:	080b      	bt      	0x18	// 18 <system_sleep_config+0x18>
   4:	1062      	lrw      	r3, 0x0	// c <system_sleep_config+0xc>
   6:	d0030883 	ldr.w      	r3, (r3, r0 << 2)
   a:	780c      	jmp      	r3
   c:	00000000 	.long	0x00000000
  10:	1162      	lrw      	r3, 0x0	// 98 <system_sleep_config+0x98>
  12:	9362      	ld.w      	r3, (r3, 0x8)
  14:	dc2320ad 	st.w      	r1, (r3, 0x2b4)
  18:	783c      	jmp      	r15
  1a:	1160      	lrw      	r3, 0x0	// 98 <system_sleep_config+0x98>
  1c:	3940      	cmpnei      	r1, 0
  1e:	9362      	ld.w      	r3, (r3, 0x8)
  20:	d843025b 	ld.b      	r2, (r3, 0x25b)
  24:	dc2320ae 	st.w      	r1, (r3, 0x2b8)
  28:	c4000501 	mvc      	r1
  2c:	c4415c03 	ins      	r2, r1, 3, 3
  30:	dc43025b 	st.b      	r2, (r3, 0x25b)
  34:	07f2      	br      	0x18	// 18 <system_sleep_config+0x18>
  36:	1079      	lrw      	r3, 0x0	// 98 <system_sleep_config+0x98>
  38:	9362      	ld.w      	r3, (r3, 0x8)
  3a:	dc2320af 	st.w      	r1, (r3, 0x2bc)
  3e:	07ed      	br      	0x18	// 18 <system_sleep_config+0x18>
  40:	1076      	lrw      	r3, 0x0	// 98 <system_sleep_config+0x98>
  42:	9362      	ld.w      	r3, (r3, 0x8)
  44:	d84302c0 	ld.b      	r2, (r3, 0x2c0)
  48:	c4415c60 	ins      	r2, r1, 3, 0
  4c:	dc4302c0 	st.b      	r2, (r3, 0x2c0)
  50:	07e4      	br      	0x18	// 18 <system_sleep_config+0x18>
  52:	1072      	lrw      	r3, 0x0	// 98 <system_sleep_config+0x98>
  54:	9362      	ld.w      	r3, (r3, 0x8)
  56:	d84302c0 	ld.b      	r2, (r3, 0x2c0)
  5a:	c4415c04 	ins      	r2, r1, 4, 4
  5e:	dc4302c0 	st.b      	r2, (r3, 0x2c0)
  62:	07db      	br      	0x18	// 18 <system_sleep_config+0x18>
  64:	106d      	lrw      	r3, 0x0	// 98 <system_sleep_config+0x98>
  66:	3a40      	cmpnei      	r2, 0
  68:	9302      	ld.w      	r0, (r3, 0x8)
  6a:	c4000502 	mvc      	r2
  6e:	d8600259 	ld.b      	r3, (r0, 0x259)
  72:	c4615cc0 	ins      	r3, r1, 6, 0
  76:	c4625c07 	ins      	r3, r2, 7, 7
  7a:	dc600259 	st.b      	r3, (r0, 0x259)
  7e:	07cd      	br      	0x18	// 18 <system_sleep_config+0x18>
  80:	1066      	lrw      	r3, 0x0	// 98 <system_sleep_config+0x98>
  82:	3940      	cmpnei      	r1, 0
  84:	9362      	ld.w      	r3, (r3, 0x8)
  86:	c4000501 	mvc      	r1
  8a:	d843025b 	ld.b      	r2, (r3, 0x25b)
  8e:	c4415c05 	ins      	r2, r1, 5, 5
  92:	dc43025b 	st.b      	r2, (r3, 0x25b)
  96:	07c1      	br      	0x18	// 18 <system_sleep_config+0x18>
  98:	00000000 	.long	0x00000000

Disassembly of section .text.system_sleep:

00000000 <system_sleep>:
   0:	14d0      	push      	r15
   2:	6cc3      	mov      	r3, r0
   4:	e901000b 	bez      	r1, 0x1a	// 1a <system_sleep+0x1a>
   8:	32fa      	movi      	r2, 250
   a:	9120      	ld.w      	r1, (r1, 0x0)
   c:	4242      	lsli      	r2, r2, 2
   e:	7c84      	mult      	r2, r1
  10:	3000      	movi      	r0, 0
  12:	3101      	movi      	r1, 1
  14:	e0000000 	bsr      	0x0	// 0 <lmac_psm_enter>
  18:	1490      	pop      	r15
  1a:	1066      	lrw      	r3, 0x0	// 30 <system_sleep+0x30>
  1c:	9342      	ld.w      	r2, (r3, 0x8)
  1e:	6cc7      	mov      	r3, r1
  20:	d84220af 	ld.w      	r2, (r2, 0x2bc)
  24:	3101      	movi      	r1, 1
  26:	6c0f      	mov      	r0, r3
  28:	e0000000 	bsr      	0x0	// 0 <lmac_psm_enter>
  2c:	07f6      	br      	0x18	// 18 <system_sleep+0x18>
  2e:	0000      	.short	0x0000
  30:	00000000 	.long	0x00000000

Disassembly of section .text.system_resume:

00000000 <system_resume>:
   0:	14d0      	push      	r15
   2:	3300      	movi      	r3, 0
   4:	6c8f      	mov      	r2, r3
   6:	6c4f      	mov      	r1, r3
   8:	6c0f      	mov      	r0, r3
   a:	e0000000 	bsr      	0x0	// 0 <lmac_psm_enter>
   e:	1490      	pop      	r15

Disassembly of section .text.system_sleep_reset:

00000000 <system_sleep_reset>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <system_sleep_reset>

Disassembly of section .text.sys_wakeup_reason:

00000000 <sys_wakeup_reason>:
   0:	1063      	lrw      	r3, 0x0	// c <sys_wakeup_reason+0xc>
   2:	9362      	ld.w      	r3, (r3, 0x8)
   4:	d8030257 	ld.b      	r0, (r3, 0x257)
   8:	783c      	jmp      	r15
   a:	0000      	.short	0x0000
   c:	00000000 	.long	0x00000000

Disassembly of section .text.dsleep_lhw_abort_fsm:

00000000 <dsleep_lhw_abort_fsm>:
   0:	106a      	lrw      	r3, 0x0	// 28 <dsleep_lhw_abort_fsm+0x28>
   2:	32a0      	movi      	r2, 160
   4:	9360      	ld.w      	r3, (r3, 0x0)
   6:	4245      	lsli      	r2, r2, 5
   8:	b352      	st.w      	r2, (r3, 0x48)
   a:	934c      	ld.w      	r2, (r3, 0x30)
   c:	ec420002 	ori      	r2, r2, 2
  10:	b34c      	st.w      	r2, (r3, 0x30)
  12:	3214      	movi      	r2, 20
  14:	6c03      	mov      	r0, r0
  16:	2a00      	subi      	r2, 1
  18:	e922fffe 	bnez      	r2, 0x14	// 14 <dsleep_lhw_abort_fsm+0x14>
  1c:	934c      	ld.w      	r2, (r3, 0x30)
  1e:	ec420002 	ori      	r2, r2, 2
  22:	b34c      	st.w      	r2, (r3, 0x30)
  24:	783c      	jmp      	r15
  26:	0000      	.short	0x0000
  28:	00000000 	.long	0x00000000

Disassembly of section .text.dsleep_memcpy_word:

00000000 <dsleep_memcpy_word>:
   0:	e900000e 	bez      	r0, 0x1c	// 1c <dsleep_memcpy_word+0x1c>
   4:	e901000d 	bez      	r1, 0x1e	// 1e <dsleep_memcpy_word+0x1e>
   8:	e902000d 	bez      	r2, 0x22	// 22 <dsleep_memcpy_word+0x22>
   c:	3300      	movi      	r3, 0
   e:	d061088c 	ldr.w      	r12, (r1, r3 << 2)
  12:	d460088c 	str.w      	r12, (r0, r3 << 2)
  16:	2300      	addi      	r3, 1
  18:	648e      	cmpne      	r3, r2
  1a:	0bfa      	bt      	0xe	// e <dsleep_memcpy_word+0xe>
  1c:	783c      	jmp      	r15
  1e:	6c07      	mov      	r0, r1
  20:	07fe      	br      	0x1c	// 1c <dsleep_memcpy_word+0x1c>
  22:	6c0b      	mov      	r0, r2
  24:	07fc      	br      	0x1c	// 1c <dsleep_memcpy_word+0x1c>

Disassembly of section .text.dsleep_gpio_set_val:

00000000 <dsleep_gpio_set_val>:
   0:	381f      	cmphsi      	r0, 32
   2:	0c0b      	bf      	0x18	// 18 <dsleep_gpio_set_val+0x18>
   4:	eb000032 	cmphsi      	r0, 51
   8:	3300      	movi      	r3, 0
   a:	104d      	lrw      	r2, 0x40025000	// 3c <dsleep_gpio_set_val+0x3c>
   c:	c4430c40 	inct      	r2, r3, 0
  10:	281f      	subi      	r0, 32
  12:	e9220006 	bnez      	r2, 0x1e	// 1e <dsleep_gpio_set_val+0x1e>
  16:	783c      	jmp      	r15
  18:	ea224002 	movih      	r2, 16386
  1c:	3aad      	bseti      	r2, 13
  1e:	3301      	movi      	r3, 1
  20:	e9010007 	bez      	r1, 0x2e	// 2e <dsleep_gpio_set_val+0x2e>
  24:	9226      	ld.w      	r1, (r2, 0x18)
  26:	70c0      	lsl      	r3, r0
  28:	6cc4      	or      	r3, r1
  2a:	b266      	st.w      	r3, (r2, 0x18)
  2c:	07f5      	br      	0x16	// 16 <dsleep_gpio_set_val+0x16>
  2e:	9226      	ld.w      	r1, (r2, 0x18)
  30:	70c0      	lsl      	r3, r0
  32:	c4612043 	andn      	r3, r1, r3
  36:	b266      	st.w      	r3, (r2, 0x18)
  38:	07ef      	br      	0x16	// 16 <dsleep_gpio_set_val+0x16>
  3a:	0000      	.short	0x0000
  3c:	5000      	.short	0x5000
  3e:	4002      	.short	0x4002

Disassembly of section .text.dsleep_gpio_get_val:

00000000 <dsleep_gpio_get_val>:
   0:	381f      	cmphsi      	r0, 32
   2:	0c07      	bf      	0x10	// 10 <dsleep_gpio_get_val+0x10>
   4:	eb000032 	cmphsi      	r0, 51
   8:	0c10      	bf      	0x28	// 28 <dsleep_gpio_get_val+0x28>
   a:	3000      	movi      	r0, 0
   c:	2800      	subi      	r0, 1
   e:	783c      	jmp      	r15
  10:	ea234002 	movih      	r3, 16386
  14:	3bad      	bseti      	r3, 13
  16:	9346      	ld.w      	r2, (r3, 0x18)
  18:	3301      	movi      	r3, 1
  1a:	c4034020 	lsl      	r0, r3, r0
  1e:	6808      	and      	r0, r2
  20:	3840      	cmpnei      	r0, 0
  22:	c4000500 	mvc      	r0
  26:	07f4      	br      	0xe	// e <dsleep_gpio_get_val+0xe>
  28:	281f      	subi      	r0, 32
  2a:	1062      	lrw      	r3, 0x40025000	// 30 <dsleep_gpio_get_val+0x30>
  2c:	07f5      	br      	0x16	// 16 <dsleep_gpio_get_val+0x16>
  2e:	0000      	.short	0x0000
  30:	40025000 	.long	0x40025000

Disassembly of section .text.dsleep_gpio_set_dir:

00000000 <dsleep_gpio_set_dir>:
   0:	381f      	cmphsi      	r0, 32
   2:	0c0b      	bf      	0x18	// 18 <dsleep_gpio_set_dir+0x18>
   4:	eb000032 	cmphsi      	r0, 51
   8:	3300      	movi      	r3, 0
   a:	105f      	lrw      	r2, 0x40025000	// 84 <dsleep_gpio_set_dir+0x84>
   c:	c4430c40 	inct      	r2, r3, 0
  10:	281f      	subi      	r0, 32
  12:	e9220006 	bnez      	r2, 0x1e	// 1e <dsleep_gpio_set_dir+0x1e>
  16:	783c      	jmp      	r15
  18:	ea224002 	movih      	r2, 16386
  1c:	3aad      	bseti      	r2, 13
  1e:	3941      	cmpnei      	r1, 1
  20:	081b      	bt      	0x56	// 56 <dsleep_gpio_set_dir+0x56>
  22:	380f      	cmphsi      	r0, 16
  24:	3303      	movi      	r3, 3
  26:	080c      	bt      	0x3e	// 3e <dsleep_gpio_set_dir+0x3e>
  28:	6000      	addu      	r0, r0
  2a:	d9822000 	ld.w      	r12, (r2, 0x0)
  2e:	70c0      	lsl      	r3, r0
  30:	c46c2043 	andn      	r3, r12, r3
  34:	c4014020 	lsl      	r0, r1, r0
  38:	6c0c      	or      	r0, r3
  3a:	b200      	st.w      	r0, (r2, 0x0)
  3c:	07ed      	br      	0x16	// 16 <dsleep_gpio_set_dir+0x16>
  3e:	280f      	subi      	r0, 16
  40:	6000      	addu      	r0, r0
  42:	d9822001 	ld.w      	r12, (r2, 0x4)
  46:	70c0      	lsl      	r3, r0
  48:	c46c2043 	andn      	r3, r12, r3
  4c:	c4014020 	lsl      	r0, r1, r0
  50:	6c0c      	or      	r0, r3
  52:	b201      	st.w      	r0, (r2, 0x4)
  54:	07e1      	br      	0x16	// 16 <dsleep_gpio_set_dir+0x16>
  56:	e921ffe0 	bnez      	r1, 0x16	// 16 <dsleep_gpio_set_dir+0x16>
  5a:	380f      	cmphsi      	r0, 16
  5c:	3303      	movi      	r3, 3
  5e:	0809      	bt      	0x70	// 70 <dsleep_gpio_set_dir+0x70>
  60:	6000      	addu      	r0, r0
  62:	9220      	ld.w      	r1, (r2, 0x0)
  64:	c4034020 	lsl      	r0, r3, r0
  68:	c4012040 	andn      	r0, r1, r0
  6c:	b200      	st.w      	r0, (r2, 0x0)
  6e:	07d4      	br      	0x16	// 16 <dsleep_gpio_set_dir+0x16>
  70:	280f      	subi      	r0, 16
  72:	6000      	addu      	r0, r0
  74:	9221      	ld.w      	r1, (r2, 0x4)
  76:	c4034020 	lsl      	r0, r3, r0
  7a:	c4012040 	andn      	r0, r1, r0
  7e:	b201      	st.w      	r0, (r2, 0x4)
  80:	07cb      	br      	0x16	// 16 <dsleep_gpio_set_dir+0x16>
  82:	0000      	.short	0x0000
  84:	40025000 	.long	0x40025000

Disassembly of section .text.dsleep_gpio_afio:

00000000 <dsleep_gpio_afio>:
   0:	381f      	cmphsi      	r0, 32
   2:	0c0b      	bf      	0x18	// 18 <dsleep_gpio_afio+0x18>
   4:	eb000032 	cmphsi      	r0, 51
   8:	3300      	movi      	r3, 0
   a:	1154      	lrw      	r2, 0x40025000	// d8 <dsleep_gpio_afio+0xd8>
   c:	c4620c20 	incf      	r3, r2, 0
  10:	281f      	subi      	r0, 32
  12:	e9230006 	bnez      	r3, 0x1e	// 1e <dsleep_gpio_afio+0x1e>
  16:	783c      	jmp      	r15
  18:	ea234002 	movih      	r3, 16386
  1c:	3bad      	bseti      	r3, 13
  1e:	380f      	cmphsi      	r0, 16
  20:	082d      	bt      	0x7a	// 7a <dsleep_gpio_afio+0x7a>
  22:	3807      	cmphsi      	r0, 8
  24:	320f      	movi      	r2, 15
  26:	081b      	bt      	0x5c	// 5c <dsleep_gpio_afio+0x5c>
  28:	c440482c 	lsli      	r12, r0, 2
  2c:	d9a32002 	ld.w      	r13, (r3, 0x8)
  30:	70b0      	lsl      	r2, r12
  32:	c44d2042 	andn      	r2, r13, r2
  36:	b342      	st.w      	r2, (r3, 0x8)
  38:	9342      	ld.w      	r2, (r3, 0x8)
  3a:	7070      	lsl      	r1, r12
  3c:	6c48      	or      	r1, r2
  3e:	b322      	st.w      	r1, (r3, 0x8)
  40:	6000      	addu      	r0, r0
  42:	3203      	movi      	r2, 3
  44:	9320      	ld.w      	r1, (r3, 0x0)
  46:	7080      	lsl      	r2, r0
  48:	c4412042 	andn      	r2, r1, r2
  4c:	b340      	st.w      	r2, (r3, 0x0)
  4e:	3202      	movi      	r2, 2
  50:	9320      	ld.w      	r1, (r3, 0x0)
  52:	c4024020 	lsl      	r0, r2, r0
  56:	6c04      	or      	r0, r1
  58:	b300      	st.w      	r0, (r3, 0x0)
  5a:	07de      	br      	0x16	// 16 <dsleep_gpio_afio+0x16>
  5c:	e5801007 	subi      	r12, r0, 8
  60:	c44c482c 	lsli      	r12, r12, 2
  64:	d9a32003 	ld.w      	r13, (r3, 0xc)
  68:	70b0      	lsl      	r2, r12
  6a:	c44d2042 	andn      	r2, r13, r2
  6e:	b343      	st.w      	r2, (r3, 0xc)
  70:	9343      	ld.w      	r2, (r3, 0xc)
  72:	7070      	lsl      	r1, r12
  74:	6c48      	or      	r1, r2
  76:	b323      	st.w      	r1, (r3, 0xc)
  78:	07e4      	br      	0x40	// 40 <dsleep_gpio_afio+0x40>
  7a:	e580100f 	subi      	r12, r0, 16
  7e:	eb0c0007 	cmphsi      	r12, 8
  82:	320f      	movi      	r2, 15
  84:	081c      	bt      	0xbc	// bc <dsleep_gpio_afio+0xbc>
  86:	c44c4820 	lsli      	r0, r12, 2
  8a:	d9a32004 	ld.w      	r13, (r3, 0x10)
  8e:	7080      	lsl      	r2, r0
  90:	c44d2042 	andn      	r2, r13, r2
  94:	b344      	st.w      	r2, (r3, 0x10)
  96:	9344      	ld.w      	r2, (r3, 0x10)
  98:	7040      	lsl      	r1, r0
  9a:	6c48      	or      	r1, r2
  9c:	b324      	st.w      	r1, (r3, 0x10)
  9e:	6330      	addu      	r12, r12
  a0:	3203      	movi      	r2, 3
  a2:	9321      	ld.w      	r1, (r3, 0x4)
  a4:	70b0      	lsl      	r2, r12
  a6:	c4412042 	andn      	r2, r1, r2
  aa:	b341      	st.w      	r2, (r3, 0x4)
  ac:	3202      	movi      	r2, 2
  ae:	9321      	ld.w      	r1, (r3, 0x4)
  b0:	c582402c 	lsl      	r12, r2, r12
  b4:	6f04      	or      	r12, r1
  b6:	dd832001 	st.w      	r12, (r3, 0x4)
  ba:	07ae      	br      	0x16	// 16 <dsleep_gpio_afio+0x16>
  bc:	2817      	subi      	r0, 24
  be:	4002      	lsli      	r0, r0, 2
  c0:	d9a32005 	ld.w      	r13, (r3, 0x14)
  c4:	7080      	lsl      	r2, r0
  c6:	c44d2042 	andn      	r2, r13, r2
  ca:	b345      	st.w      	r2, (r3, 0x14)
  cc:	9345      	ld.w      	r2, (r3, 0x14)
  ce:	c4014020 	lsl      	r0, r1, r0
  d2:	6c08      	or      	r0, r2
  d4:	b305      	st.w      	r0, (r3, 0x14)
  d6:	07e4      	br      	0x9e	// 9e <dsleep_gpio_afio+0x9e>
  d8:	40025000 	.long	0x40025000

Disassembly of section .text.dsleep_gpio_mode:

00000000 <dsleep_gpio_mode>:
   0:	14c1      	push      	r4
   2:	381f      	cmphsi      	r0, 32
   4:	0c0f      	bf      	0x22	// 22 <dsleep_gpio_mode+0x22>
   6:	3300      	movi      	r3, 0
   8:	eb000032 	cmphsi      	r0, 51
   c:	ea8c0092 	lrw      	r12, 0x40025000	// 254 <dsleep_gpio_mode+0x254>
  10:	c5830c40 	inct      	r12, r3, 0
  14:	e460101f 	subi      	r3, r0, 32
  18:	e92c000a 	bnez      	r12, 0x2c	// 2c <dsleep_gpio_mode+0x2c>
  1c:	3000      	movi      	r0, 0
  1e:	2800      	subi      	r0, 1
  20:	040a      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
  22:	6cc3      	mov      	r3, r0
  24:	ea2c4002 	movih      	r12, 16386
  28:	c5ac284c 	bseti      	r12, r12, 13
  2c:	3906      	cmphsi      	r1, 7
  2e:	0c04      	bf      	0x36	// 36 <dsleep_gpio_mode+0x36>
  30:	3000      	movi      	r0, 0
  32:	2815      	subi      	r0, 22
  34:	1481      	pop      	r4
  36:	ea0d0001 	movi      	r13, 1
  3a:	c42d4021 	lsl      	r1, r13, r1
  3e:	e5a12058 	andi      	r13, r1, 88
  42:	e92d003d 	bnez      	r13, 0xbc	// bc <dsleep_gpio_mode+0xbc>
  46:	e5a12007 	andi      	r13, r1, 7
  4a:	e90dfff3 	bez      	r13, 0x30	// 30 <dsleep_gpio_mode+0x30>
  4e:	d9ac2016 	ld.w      	r13, (r12, 0x58)
  52:	6b4d      	andn      	r13, r3
  54:	ddac2016 	st.w      	r13, (r12, 0x58)
  58:	381f      	cmphsi      	r0, 32
  5a:	0c0d      	bf      	0x74	// 74 <dsleep_gpio_mode+0x74>
  5c:	eb000032 	cmphsi      	r0, 51
  60:	3400      	movi      	r4, 0
  62:	ea8d007d 	lrw      	r13, 0x40025000	// 254 <dsleep_gpio_mode+0x254>
  66:	c5a40c40 	inct      	r13, r4, 0
  6a:	281f      	subi      	r0, 32
  6c:	e90dffd8 	bez      	r13, 0x1c	// 1c <dsleep_gpio_mode+0x1c>
  70:	381f      	cmphsi      	r0, 32
  72:	0bdf      	bt      	0x30	// 30 <dsleep_gpio_mode+0x30>
  74:	e4012044 	andi      	r0, r1, 68
  78:	e92000a6 	bnez      	r0, 0x1c4	// 1c4 <dsleep_gpio_mode+0x1c4>
  7c:	e5a12012 	andi      	r13, r1, 18
  80:	e92d0060 	bnez      	r13, 0x140	// 140 <dsleep_gpio_mode+0x140>
  84:	e4212009 	andi      	r1, r1, 9
  88:	e901ffd4 	bez      	r1, 0x30	// 30 <dsleep_gpio_mode+0x30>
  8c:	4b43      	lsri      	r2, r3, 3
  8e:	3a42      	cmpnei      	r2, 2
  90:	0c30      	bf      	0xf0	// f0 <dsleep_gpio_mode+0xf0>
  92:	3a43      	cmpnei      	r2, 3
  94:	0c42      	bf      	0x118	// 118 <dsleep_gpio_mode+0x118>
  96:	3a41      	cmpnei      	r2, 1
  98:	310f      	movi      	r1, 15
  9a:	0c17      	bf      	0xc8	// c8 <dsleep_gpio_mode+0xc8>
  9c:	4362      	lsli      	r3, r3, 2
  9e:	704c      	lsl      	r1, r3
  a0:	d80c200d 	ld.w      	r0, (r12, 0x34)
  a4:	6c46      	nor      	r1, r1
  a6:	c4202023 	and      	r3, r0, r1
  aa:	dc6c200d 	st.w      	r3, (r12, 0x34)
  ae:	d86c2009 	ld.w      	r3, (r12, 0x24)
  b2:	684c      	and      	r1, r3
  b4:	dc2c2009 	st.w      	r1, (r12, 0x24)
  b8:	6c37      	mov      	r0, r13
  ba:	07bd      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
  bc:	d9ac2016 	ld.w      	r13, (r12, 0x58)
  c0:	6f4c      	or      	r13, r3
  c2:	ddac2016 	st.w      	r13, (r12, 0x58)
  c6:	07c9      	br      	0x58	// 58 <dsleep_gpio_mode+0x58>
  c8:	c7a05020 	bmaski      	r0, 30
  cc:	2806      	subi      	r0, 7
  ce:	60c0      	addu      	r3, r0
  d0:	4362      	lsli      	r3, r3, 2
  d2:	c4614023 	lsl      	r3, r1, r3
  d6:	d84c200e 	ld.w      	r2, (r12, 0x38)
  da:	6cce      	nor      	r3, r3
  dc:	688c      	and      	r2, r3
  de:	dc4c200e 	st.w      	r2, (r12, 0x38)
  e2:	d84c200a 	ld.w      	r2, (r12, 0x28)
  e6:	68c8      	and      	r3, r2
  e8:	dc6c200a 	st.w      	r3, (r12, 0x28)
  ec:	6c37      	mov      	r0, r13
  ee:	07a3      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
  f0:	c7a05021 	bmaski      	r1, 30
  f4:	290e      	subi      	r1, 15
  f6:	60c4      	addu      	r3, r1
  f8:	4322      	lsli      	r1, r3, 2
  fa:	330f      	movi      	r3, 15
  fc:	70c4      	lsl      	r3, r1
  fe:	d84c200f 	ld.w      	r2, (r12, 0x3c)
 102:	6cce      	nor      	r3, r3
 104:	688c      	and      	r2, r3
 106:	dc4c200f 	st.w      	r2, (r12, 0x3c)
 10a:	d84c200b 	ld.w      	r2, (r12, 0x2c)
 10e:	68c8      	and      	r3, r2
 110:	dc6c200b 	st.w      	r3, (r12, 0x2c)
 114:	6c37      	mov      	r0, r13
 116:	078f      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
 118:	c7a05021 	bmaski      	r1, 30
 11c:	2916      	subi      	r1, 23
 11e:	60c4      	addu      	r3, r1
 120:	4322      	lsli      	r1, r3, 2
 122:	330f      	movi      	r3, 15
 124:	70c4      	lsl      	r3, r1
 126:	d84c2010 	ld.w      	r2, (r12, 0x40)
 12a:	6cce      	nor      	r3, r3
 12c:	688c      	and      	r2, r3
 12e:	dc4c2010 	st.w      	r2, (r12, 0x40)
 132:	d84c200c 	ld.w      	r2, (r12, 0x30)
 136:	68c8      	and      	r3, r2
 138:	dc6c200c 	st.w      	r3, (r12, 0x30)
 13c:	6c37      	mov      	r0, r13
 13e:	077b      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
 140:	4b23      	lsri      	r1, r3, 3
 142:	3942      	cmpnei      	r1, 2
 144:	0c20      	bf      	0x184	// 184 <dsleep_gpio_mode+0x184>
 146:	3943      	cmpnei      	r1, 3
 148:	0c2e      	bf      	0x1a4	// 1a4 <dsleep_gpio_mode+0x1a4>
 14a:	3941      	cmpnei      	r1, 1
 14c:	310f      	movi      	r1, 15
 14e:	0c0c      	bf      	0x166	// 166 <dsleep_gpio_mode+0x166>
 150:	4362      	lsli      	r3, r3, 2
 152:	d9ac2009 	ld.w      	r13, (r12, 0x24)
 156:	704c      	lsl      	r1, r3
 158:	c42d2041 	andn      	r1, r13, r1
 15c:	708c      	lsl      	r2, r3
 15e:	6c84      	or      	r2, r1
 160:	dc4c2009 	st.w      	r2, (r12, 0x24)
 164:	0768      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
 166:	c7a05024 	bmaski      	r4, 30
 16a:	2c06      	subi      	r4, 7
 16c:	60d0      	addu      	r3, r4
 16e:	4362      	lsli      	r3, r3, 2
 170:	d9ac200a 	ld.w      	r13, (r12, 0x28)
 174:	704c      	lsl      	r1, r3
 176:	c42d2041 	andn      	r1, r13, r1
 17a:	708c      	lsl      	r2, r3
 17c:	6c84      	or      	r2, r1
 17e:	dc4c200a 	st.w      	r2, (r12, 0x28)
 182:	0759      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
 184:	c7a05021 	bmaski      	r1, 30
 188:	290e      	subi      	r1, 15
 18a:	60c4      	addu      	r3, r1
 18c:	4362      	lsli      	r3, r3, 2
 18e:	310f      	movi      	r1, 15
 190:	d9ac200b 	ld.w      	r13, (r12, 0x2c)
 194:	704c      	lsl      	r1, r3
 196:	c42d2041 	andn      	r1, r13, r1
 19a:	708c      	lsl      	r2, r3
 19c:	6c84      	or      	r2, r1
 19e:	dc4c200b 	st.w      	r2, (r12, 0x2c)
 1a2:	0749      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
 1a4:	c7a05021 	bmaski      	r1, 30
 1a8:	2916      	subi      	r1, 23
 1aa:	60c4      	addu      	r3, r1
 1ac:	4362      	lsli      	r3, r3, 2
 1ae:	310f      	movi      	r1, 15
 1b0:	d9ac200c 	ld.w      	r13, (r12, 0x30)
 1b4:	704c      	lsl      	r1, r3
 1b6:	c42d2041 	andn      	r1, r13, r1
 1ba:	708c      	lsl      	r2, r3
 1bc:	6c84      	or      	r2, r1
 1be:	dc4c200c 	st.w      	r2, (r12, 0x30)
 1c2:	0739      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
 1c4:	4b23      	lsri      	r1, r3, 3
 1c6:	3942      	cmpnei      	r1, 2
 1c8:	0c23      	bf      	0x20e	// 20e <dsleep_gpio_mode+0x20e>
 1ca:	3943      	cmpnei      	r1, 3
 1cc:	0c32      	bf      	0x230	// 230 <dsleep_gpio_mode+0x230>
 1ce:	3941      	cmpnei      	r1, 1
 1d0:	310f      	movi      	r1, 15
 1d2:	0c0d      	bf      	0x1ec	// 1ec <dsleep_gpio_mode+0x1ec>
 1d4:	4362      	lsli      	r3, r3, 2
 1d6:	d80c200d 	ld.w      	r0, (r12, 0x34)
 1da:	704c      	lsl      	r1, r3
 1dc:	c4202041 	andn      	r1, r0, r1
 1e0:	708c      	lsl      	r2, r3
 1e2:	6c84      	or      	r2, r1
 1e4:	dc4c200d 	st.w      	r2, (r12, 0x34)
 1e8:	3000      	movi      	r0, 0
 1ea:	0725      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
 1ec:	c7a0502d 	bmaski      	r13, 30
 1f0:	e5ad1006 	subi      	r13, r13, 7
 1f4:	60f4      	addu      	r3, r13
 1f6:	4362      	lsli      	r3, r3, 2
 1f8:	d80c200e 	ld.w      	r0, (r12, 0x38)
 1fc:	704c      	lsl      	r1, r3
 1fe:	c4202041 	andn      	r1, r0, r1
 202:	708c      	lsl      	r2, r3
 204:	6c84      	or      	r2, r1
 206:	dc4c200e 	st.w      	r2, (r12, 0x38)
 20a:	3000      	movi      	r0, 0
 20c:	0714      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
 20e:	c7a05021 	bmaski      	r1, 30
 212:	290e      	subi      	r1, 15
 214:	60c4      	addu      	r3, r1
 216:	4362      	lsli      	r3, r3, 2
 218:	310f      	movi      	r1, 15
 21a:	d80c200f 	ld.w      	r0, (r12, 0x3c)
 21e:	704c      	lsl      	r1, r3
 220:	c4202041 	andn      	r1, r0, r1
 224:	708c      	lsl      	r2, r3
 226:	6c84      	or      	r2, r1
 228:	dc4c200f 	st.w      	r2, (r12, 0x3c)
 22c:	3000      	movi      	r0, 0
 22e:	0703      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
 230:	c7a05021 	bmaski      	r1, 30
 234:	2916      	subi      	r1, 23
 236:	60c4      	addu      	r3, r1
 238:	4362      	lsli      	r3, r3, 2
 23a:	310f      	movi      	r1, 15
 23c:	d80c2010 	ld.w      	r0, (r12, 0x40)
 240:	704c      	lsl      	r1, r3
 242:	c4202041 	andn      	r1, r0, r1
 246:	708c      	lsl      	r2, r3
 248:	6c84      	or      	r2, r1
 24a:	dc4c2010 	st.w      	r2, (r12, 0x40)
 24e:	3000      	movi      	r0, 0
 250:	06f2      	br      	0x34	// 34 <dsleep_gpio_mode+0x34>
 252:	0000      	.short	0x0000
 254:	40025000 	.long	0x40025000

Disassembly of section .text.dsleep_uart0_open:

00000000 <dsleep_uart0_open>:
   0:	14d2      	push      	r4-r5, r15
   2:	1072      	lrw      	r3, 0x0	// 48 <dsleep_uart0_open+0x48>
   4:	6d03      	mov      	r4, r0
   6:	9362      	ld.w      	r3, (r3, 0x8)
   8:	d8630a4e 	ld.b      	r3, (r3, 0xa4e)
   c:	e4632030 	andi      	r3, r3, 48
  10:	3b50      	cmpnei      	r3, 16
  12:	080e      	bt      	0x2e	// 2e <dsleep_uart0_open+0x2e>
  14:	3104      	movi      	r1, 4
  16:	300b      	movi      	r0, 11
  18:	e0000000 	bsr      	0x0	// 0 <dsleep_uart0_open>
  1c:	3500      	movi      	r5, 0
  1e:	b4a4      	st.w      	r5, (r4, 0x10)
  20:	6c13      	mov      	r0, r4
  22:	e0000000 	bsr      	0x0	// 0 <dsleep_uart0_open>
  26:	3303      	movi      	r3, 3
  28:	b463      	st.w      	r3, (r4, 0xc)
  2a:	b4a2      	st.w      	r5, (r4, 0x8)
  2c:	1492      	pop      	r4-r5, r15
  2e:	eb430020 	cmpnei      	r3, 32
  32:	0806      	bt      	0x3e	// 3e <dsleep_uart0_open+0x3e>
  34:	3109      	movi      	r1, 9
  36:	301f      	movi      	r0, 31
  38:	e0000000 	bsr      	0x0	// 0 <dsleep_uart0_open>
  3c:	07f0      	br      	0x1c	// 1c <dsleep_uart0_open+0x1c>
  3e:	3100      	movi      	r1, 0
  40:	300d      	movi      	r0, 13
  42:	e0000000 	bsr      	0x0	// 0 <dsleep_uart0_open>
  46:	07eb      	br      	0x1c	// 1c <dsleep_uart0_open+0x1c>
  48:	00000000 	.long	0x00000000

Disassembly of section .text.dsleep_uart_putc:

00000000 <dsleep_uart_putc>:
   0:	b020      	st.w      	r1, (r0, 0x0)
   2:	9065      	ld.w      	r3, (r0, 0x14)
   4:	e4632020 	andi      	r3, r3, 32
   8:	e903fffd 	bez      	r3, 0x2	// 2 <dsleep_uart_putc+0x2>
   c:	3000      	movi      	r0, 0
   e:	783c      	jmp      	r15

Disassembly of section .text.dsleep_print:

00000000 <dsleep_print>:
   0:	14d3      	push      	r4-r6, r15
   2:	1090      	lrw      	r4, 0x0	// 40 <dsleep_print+0x40>
   4:	6d43      	mov      	r5, r0
   6:	310a      	movi      	r1, 10
   8:	940c      	ld.w      	r0, (r4, 0x30)
   a:	e0000000 	bsr      	0x0	// 0 <dsleep_print>
   e:	310d      	movi      	r1, 13
  10:	940c      	ld.w      	r0, (r4, 0x30)
  12:	e0000000 	bsr      	0x0	// 0 <dsleep_print>
  16:	e4c5003f 	addi      	r6, r5, 64
  1a:	8520      	ld.b      	r1, (r5, 0x0)
  1c:	e9010008 	bez      	r1, 0x2c	// 2c <dsleep_print+0x2c>
  20:	940c      	ld.w      	r0, (r4, 0x30)
  22:	2500      	addi      	r5, 1
  24:	e0000000 	bsr      	0x0	// 0 <dsleep_print>
  28:	6596      	cmpne      	r5, r6
  2a:	0bf8      	bt      	0x1a	// 1a <dsleep_print+0x1a>
  2c:	310a      	movi      	r1, 10
  2e:	940c      	ld.w      	r0, (r4, 0x30)
  30:	e0000000 	bsr      	0x0	// 0 <dsleep_print>
  34:	310d      	movi      	r1, 13
  36:	940c      	ld.w      	r0, (r4, 0x30)
  38:	e0000000 	bsr      	0x0	// 0 <dsleep_print>
  3c:	1493      	pop      	r4-r6, r15
  3e:	0000      	.short	0x0000
  40:	00000000 	.long	0x00000000

Disassembly of section .text.dsleep_itoa:

00000000 <dsleep_itoa>:
   0:	14d3      	push      	r4-r6, r15
   2:	1424      	subi      	r14, r14, 16
   4:	c4000202 	abs      	r2, r0
   8:	3100      	movi      	r1, 0
   a:	ea0d000a 	movi      	r13, 10
   e:	c5a2804c 	divs      	r12, r2, r13
  12:	c5ac8424 	mult      	r4, r12, r13
  16:	6092      	subu      	r2, r4
  18:	222f      	addi      	r2, 48
  1a:	d42e0022 	str.b      	r2, (r14, r1 << 0)
  1e:	5962      	addi      	r3, r1, 1
  20:	6cb3      	mov      	r2, r12
  22:	e94c0026 	bhz      	r12, 0x6e	// 6e <dsleep_itoa+0x6e>
  26:	e9a00006 	bhsz      	r0, 0x32	// 32 <dsleep_itoa+0x32>
  2a:	322d      	movi      	r2, 45
  2c:	d46e0022 	str.b      	r2, (r14, r3 << 0)
  30:	5966      	addi      	r3, r1, 2
  32:	3200      	movi      	r2, 0
  34:	3600      	movi      	r6, 0
  36:	d46e0022 	str.b      	r2, (r14, r3 << 0)
  3a:	5b83      	subi      	r4, r3, 1
  3c:	10ae      	lrw      	r5, 0x0	// 74 <dsleep_itoa+0x74>
  3e:	2e01      	subi      	r6, 2
  40:	c48e0023 	addu      	r3, r14, r4
  44:	950c      	ld.w      	r0, (r5, 0x30)
  46:	8321      	ld.b      	r1, (r3, 0x1)
  48:	2c00      	subi      	r4, 1
  4a:	e0000000 	bsr      	0x0	// 0 <dsleep_itoa>
  4e:	6592      	cmpne      	r4, r6
  50:	0bf8      	bt      	0x40	// 40 <dsleep_itoa+0x40>
  52:	3100      	movi      	r1, 0
  54:	950c      	ld.w      	r0, (r5, 0x30)
  56:	e0000000 	bsr      	0x0	// 0 <dsleep_itoa>
  5a:	310a      	movi      	r1, 10
  5c:	950c      	ld.w      	r0, (r5, 0x30)
  5e:	e0000000 	bsr      	0x0	// 0 <dsleep_itoa>
  62:	310d      	movi      	r1, 13
  64:	950c      	ld.w      	r0, (r5, 0x30)
  66:	e0000000 	bsr      	0x0	// 0 <dsleep_itoa>
  6a:	1404      	addi      	r14, r14, 16
  6c:	1493      	pop      	r4-r6, r15
  6e:	6c4f      	mov      	r1, r3
  70:	07cf      	br      	0xe	// e <dsleep_itoa+0xe>
  72:	0000      	.short	0x0000
  74:	00000000 	.long	0x00000000

Disassembly of section .text.dsleep_rfspi_read:

00000000 <dsleep_rfspi_read>:
   0:	9061      	ld.w      	r3, (r0, 0x4)
   2:	3b83      	bclri      	r3, 3
   4:	b061      	st.w      	r3, (r0, 0x4)
   6:	9061      	ld.w      	r3, (r0, 0x4)
   8:	ec630003 	ori      	r3, r3, 3
   c:	b061      	st.w      	r3, (r0, 0x4)
   e:	3301      	movi      	r3, 1
  10:	b068      	st.w      	r3, (r0, 0x20)
  12:	3300      	movi      	r3, 0
  14:	b069      	st.w      	r3, (r0, 0x24)
  16:	4130      	lsli      	r1, r1, 16
  18:	ea237fff 	movih      	r3, 32767
  1c:	684c      	and      	r1, r3
  1e:	b024      	st.w      	r1, (r0, 0x10)
  20:	9063      	ld.w      	r3, (r0, 0xc)
  22:	e4632400 	andi      	r3, r3, 1024
  26:	e903fffd 	bez      	r3, 0x20	// 20 <dsleep_rfspi_read+0x20>
  2a:	9063      	ld.w      	r3, (r0, 0xc)
  2c:	ec630400 	ori      	r3, r3, 1024
  30:	b063      	st.w      	r3, (r0, 0xc)
  32:	9061      	ld.w      	r3, (r0, 0x4)
  34:	ec630008 	ori      	r3, r3, 8
  38:	b061      	st.w      	r3, (r0, 0x4)
  3a:	9005      	ld.w      	r0, (r0, 0x14)
  3c:	7401      	zexth      	r0, r0
  3e:	783c      	jmp      	r15

Disassembly of section .text.dsleep_rfspi_write:

00000000 <dsleep_rfspi_write>:
   0:	9061      	ld.w      	r3, (r0, 0x4)
   2:	3b83      	bclri      	r3, 3
   4:	b061      	st.w      	r3, (r0, 0x4)
   6:	9061      	ld.w      	r3, (r0, 0x4)
   8:	3b80      	bclri      	r3, 0
   a:	3b81      	bclri      	r3, 1
   c:	b061      	st.w      	r3, (r0, 0x4)
   e:	9061      	ld.w      	r3, (r0, 0x4)
  10:	ec630002 	ori      	r3, r3, 2
  14:	b061      	st.w      	r3, (r0, 0x4)
  16:	3301      	movi      	r3, 1
  18:	b068      	st.w      	r3, (r0, 0x20)
  1a:	3300      	movi      	r3, 0
  1c:	b069      	st.w      	r3, (r0, 0x24)
  1e:	4130      	lsli      	r1, r1, 16
  20:	ea237fff 	movih      	r3, 32767
  24:	684c      	and      	r1, r3
  26:	3abf      	bseti      	r2, 31
  28:	6c48      	or      	r1, r2
  2a:	b024      	st.w      	r1, (r0, 0x10)
  2c:	9063      	ld.w      	r3, (r0, 0xc)
  2e:	e4632400 	andi      	r3, r3, 1024
  32:	e903fffd 	bez      	r3, 0x2c	// 2c <dsleep_rfspi_write+0x2c>
  36:	9063      	ld.w      	r3, (r0, 0xc)
  38:	ec630400 	ori      	r3, r3, 1024
  3c:	b063      	st.w      	r3, (r0, 0xc)
  3e:	9061      	ld.w      	r3, (r0, 0x4)
  40:	ec630008 	ori      	r3, r3, 8
  44:	b061      	st.w      	r3, (r0, 0x4)
  46:	3000      	movi      	r0, 0
  48:	783c      	jmp      	r15

Disassembly of section .text.dsleep_hgspi_dw_wait_tx_done:

00000000 <dsleep_hgspi_dw_wait_tx_done>:
   0:	14d1      	push      	r4, r15
   2:	1073      	lrw      	r3, 0x0	// 4c <dsleep_hgspi_dw_wait_tx_done+0x4c>
   4:	ea02ffff 	movi      	r2, 65535
   8:	2201      	addi      	r2, 2
   a:	938e      	ld.w      	r4, (r3, 0x38)
   c:	946a      	ld.w      	r3, (r4, 0x28)
   e:	e4632004 	andi      	r3, r3, 4
  12:	e9030004 	bez      	r3, 0x1a	// 1a <dsleep_hgspi_dw_wait_tx_done+0x1a>
  16:	3000      	movi      	r0, 0
  18:	0409      	br      	0x2a	// 2a <dsleep_hgspi_dw_wait_tx_done+0x2a>
  1a:	2a00      	subi      	r2, 1
  1c:	e922fff8 	bnez      	r2, 0xc	// c <dsleep_hgspi_dw_wait_tx_done+0xc>
  20:	100c      	lrw      	r0, 0x0	// 50 <dsleep_hgspi_dw_wait_tx_done+0x50>
  22:	e0000000 	bsr      	0x0	// 0 <dsleep_hgspi_dw_wait_tx_done>
  26:	3000      	movi      	r0, 0
  28:	2800      	subi      	r0, 1
  2a:	ea02ffff 	movi      	r2, 65535
  2e:	2201      	addi      	r2, 2
  30:	946a      	ld.w      	r3, (r4, 0x28)
  32:	e4632001 	andi      	r3, r3, 1
  36:	e903000a 	bez      	r3, 0x4a	// 4a <dsleep_hgspi_dw_wait_tx_done+0x4a>
  3a:	2a00      	subi      	r2, 1
  3c:	e922fffa 	bnez      	r2, 0x30	// 30 <dsleep_hgspi_dw_wait_tx_done+0x30>
  40:	1005      	lrw      	r0, 0x0	// 54 <dsleep_hgspi_dw_wait_tx_done+0x54>
  42:	e0000000 	bsr      	0x0	// 0 <dsleep_hgspi_dw_wait_tx_done>
  46:	3000      	movi      	r0, 0
  48:	2800      	subi      	r0, 1
  4a:	1491      	pop      	r4, r15
	...

Disassembly of section .text.dsleep_spi_nor_qpi_read_jedec_id:

00000000 <dsleep_spi_nor_qpi_read_jedec_id>:
   0:	14d3      	push      	r4-r6, r15
   2:	3100      	movi      	r1, 0
   4:	11c3      	lrw      	r6, 0x0	// 90 <dsleep_spi_nor_qpi_read_jedec_id+0x90>
   6:	6d43      	mov      	r5, r0
   8:	6c07      	mov      	r0, r1
   a:	e0000000 	bsr      	0x0	// 0 <dsleep_spi_nor_qpi_read_jedec_id>
   e:	968e      	ld.w      	r4, (r6, 0x38)
  10:	ea03ffff 	movi      	r3, 65535
  14:	2301      	addi      	r3, 2
  16:	944a      	ld.w      	r2, (r4, 0x28)
  18:	e4422002 	andi      	r2, r2, 2
  1c:	e9220008 	bnez      	r2, 0x2c	// 2c <dsleep_spi_nor_qpi_read_jedec_id+0x2c>
  20:	2b00      	subi      	r3, 1
  22:	e923fffa 	bnez      	r3, 0x16	// 16 <dsleep_spi_nor_qpi_read_jedec_id+0x16>
  26:	101c      	lrw      	r0, 0x0	// 94 <dsleep_spi_nor_qpi_read_jedec_id+0x94>
  28:	e0000000 	bsr      	0x0	// 0 <dsleep_spi_nor_qpi_read_jedec_id>
  2c:	339f      	movi      	r3, 159
  2e:	b478      	st.w      	r3, (r4, 0x60)
  30:	e0000000 	bsr      	0x0	// 0 <dsleep_spi_nor_qpi_read_jedec_id>
  34:	968e      	ld.w      	r4, (r6, 0x38)
  36:	e0000000 	bsr      	0x0	// 0 <dsleep_spi_nor_qpi_read_jedec_id>
  3a:	3300      	movi      	r3, 0
  3c:	b462      	st.w      	r3, (r4, 0x8)
  3e:	9460      	ld.w      	r3, (r4, 0x0)
  40:	3b88      	bclri      	r3, 8
  42:	3b89      	bclri      	r3, 9
  44:	ec630200 	ori      	r3, r3, 512
  48:	b460      	st.w      	r3, (r4, 0x0)
  4a:	3301      	movi      	r3, 1
  4c:	b462      	st.w      	r3, (r4, 0x8)
  4e:	6c17      	mov      	r0, r5
  50:	5d2a      	addi      	r1, r5, 3
  52:	ea0c00ff 	movi      	r12, 255
  56:	6442      	cmpne      	r0, r1
  58:	0810      	bt      	0x78	// 78 <dsleep_spi_nor_qpi_read_jedec_id+0x78>
  5a:	e0000000 	bsr      	0x0	// 0 <dsleep_spi_nor_qpi_read_jedec_id>
  5e:	3000      	movi      	r0, 0
  60:	b402      	st.w      	r0, (r4, 0x8)
  62:	9460      	ld.w      	r3, (r4, 0x0)
  64:	3b88      	bclri      	r3, 8
  66:	3b89      	bclri      	r3, 9
  68:	ec630100 	ori      	r3, r3, 256
  6c:	3101      	movi      	r1, 1
  6e:	b460      	st.w      	r3, (r4, 0x0)
  70:	b422      	st.w      	r1, (r4, 0x8)
  72:	e0000000 	bsr      	0x0	// 0 <dsleep_spi_nor_qpi_read_jedec_id>
  76:	1493      	pop      	r4-r6, r15
  78:	dd842018 	st.w      	r12, (r4, 0x60)
  7c:	964e      	ld.w      	r2, (r6, 0x38)
  7e:	926a      	ld.w      	r3, (r2, 0x28)
  80:	e4632008 	andi      	r3, r3, 8
  84:	e903fffd 	bez      	r3, 0x7e	// 7e <dsleep_spi_nor_qpi_read_jedec_id+0x7e>
  88:	9278      	ld.w      	r3, (r2, 0x60)
  8a:	a060      	st.b      	r3, (r0, 0x0)
  8c:	2000      	addi      	r0, 1
  8e:	07e4      	br      	0x56	// 56 <dsleep_spi_nor_qpi_read_jedec_id+0x56>
	...

Disassembly of section .text.dsleep_spi_nor_standard_release_power_down:

00000000 <dsleep_spi_nor_standard_release_power_down>:
   0:	783c      	jmp      	r15

Disassembly of section .text.dsleep_hgspi_dw_open:

00000000 <dsleep_hgspi_dw_open>:
   0:	14d3      	push      	r4-r6, r15
   2:	1165      	lrw      	r3, 0x0	// 94 <dsleep_hgspi_dw_open+0x94>
   4:	3500      	movi      	r5, 0
   6:	938e      	ld.w      	r4, (r3, 0x38)
   8:	93cf      	ld.w      	r6, (r3, 0x3c)
   a:	1164      	lrw      	r3, 0x40026000	// 98 <dsleep_hgspi_dw_open+0x98>
   c:	3101      	movi      	r1, 1
   e:	9345      	ld.w      	r2, (r3, 0x14)
  10:	ec420100 	ori      	r2, r2, 256
  14:	b345      	st.w      	r2, (r3, 0x14)
  16:	9342      	ld.w      	r2, (r3, 0x8)
  18:	3a88      	bclri      	r2, 8
  1a:	b342      	st.w      	r2, (r3, 0x8)
  1c:	9342      	ld.w      	r2, (r3, 0x8)
  1e:	ec420100 	ori      	r2, r2, 256
  22:	b342      	st.w      	r2, (r3, 0x8)
  24:	6c17      	mov      	r0, r5
  26:	e0000000 	bsr      	0x0	// 0 <dsleep_hgspi_dw_open>
  2a:	3101      	movi      	r1, 1
  2c:	6c17      	mov      	r0, r5
  2e:	e0000000 	bsr      	0x0	// 0 <dsleep_hgspi_dw_open>
  32:	6c57      	mov      	r1, r5
  34:	3001      	movi      	r0, 1
  36:	e0000000 	bsr      	0x0	// 0 <dsleep_hgspi_dw_open>
  3a:	6c57      	mov      	r1, r5
  3c:	3002      	movi      	r0, 2
  3e:	e0000000 	bsr      	0x0	// 0 <dsleep_hgspi_dw_open>
  42:	6c57      	mov      	r1, r5
  44:	3003      	movi      	r0, 3
  46:	e0000000 	bsr      	0x0	// 0 <dsleep_hgspi_dw_open>
  4a:	b4a2      	st.w      	r5, (r4, 0x8)
  4c:	9472      	ld.w      	r3, (r4, 0x48)
  4e:	3307      	movi      	r3, 7
  50:	b4ab      	st.w      	r5, (r4, 0x2c)
  52:	b460      	st.w      	r3, (r4, 0x0)
  54:	b4a1      	st.w      	r5, (r4, 0x4)
  56:	b4b4      	st.w      	r5, (r4, 0x50)
  58:	b4b5      	st.w      	r5, (r4, 0x54)
  5a:	b4b3      	st.w      	r5, (r4, 0x4c)
  5c:	e0000000 	bsr      	0x0	// 0 <sys_get_apbclk>
  60:	c4c08026 	divu      	r6, r0, r6
  64:	5e67      	subi      	r3, r6, 2
  66:	eb03fffc 	cmphsi      	r3, 65533
  6a:	0c07      	bf      	0x78	// 78 <dsleep_hgspi_dw_open+0x78>
  6c:	104c      	lrw      	r2, 0x0	// 9c <dsleep_hgspi_dw_open+0x9c>
  6e:	ea0103cd 	movi      	r1, 973
  72:	100c      	lrw      	r0, 0x0	// a0 <assert_internal+0xa0>
  74:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  78:	3380      	movi      	r3, 128
  7a:	4362      	lsli      	r3, r3, 2
  7c:	b4c5      	st.w      	r6, (r4, 0x14)
  7e:	3000      	movi      	r0, 0
  80:	dc64203d 	st.w      	r3, (r4, 0xf4)
  84:	3301      	movi      	r3, 1
  86:	dc04203c 	st.w      	r0, (r4, 0xf0)
  8a:	b406      	st.w      	r0, (r4, 0x18)
  8c:	b407      	st.w      	r0, (r4, 0x1c)
  8e:	b464      	st.w      	r3, (r4, 0x10)
  90:	b462      	st.w      	r3, (r4, 0x8)
  92:	1493      	pop      	r4-r6, r15
  94:	00000000 	.long	0x00000000
  98:	40026000 	.long	0x40026000
	...

Disassembly of section .text.dsleep_rf_open:

00000000 <dsleep_rf_open>:
   0:	14d8      	push      	r4-r11, r15
   2:	1421      	subi      	r14, r14, 4
   4:	0182      	lrw      	r4, 0x40026000	// 378 <dsleep_rf_open+0x378>
   6:	01e1      	lrw      	r7, 0x3fac87e4	// 37c <dsleep_rf_open+0x37c>
   8:	b4eb      	st.w      	r7, (r4, 0x2c)
   a:	9460      	ld.w      	r3, (r4, 0x0)
   c:	3b90      	bclri      	r3, 16
   e:	b460      	st.w      	r3, (r4, 0x0)
  10:	9460      	ld.w      	r3, (r4, 0x0)
  12:	3b8f      	bclri      	r3, 15
  14:	3b9f      	bclri      	r3, 31
  16:	b460      	st.w      	r3, (r4, 0x0)
  18:	9460      	ld.w      	r3, (r4, 0x0)
  1a:	3bb9      	bseti      	r3, 25
  1c:	b460      	st.w      	r3, (r4, 0x0)
  1e:	9473      	ld.w      	r3, (r4, 0x4c)
  20:	3bba      	bseti      	r3, 26
  22:	b473      	st.w      	r3, (r4, 0x4c)
  24:	9473      	ld.w      	r3, (r4, 0x4c)
  26:	3b97      	bclri      	r3, 23
  28:	b473      	st.w      	r3, (r4, 0x4c)
  2a:	9473      	ld.w      	r3, (r4, 0x4c)
  2c:	3bb7      	bseti      	r3, 23
  2e:	b473      	st.w      	r3, (r4, 0x4c)
  30:	e0000000 	bsr      	0x0	// 0 <lmac_rf_sw_ctrl>
  34:	3000      	movi      	r0, 0
  36:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
  3a:	3000      	movi      	r0, 0
  3c:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  40:	3000      	movi      	r0, 0
  42:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rx_en>
  46:	ea038003 	movi      	r3, 32771
  4a:	c5e34903 	rotli      	r3, r3, 15
  4e:	3020      	movi      	r0, 32
  50:	9328      	ld.w      	r1, (r3, 0x20)
  52:	39ba      	bseti      	r1, 26
  54:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
  58:	300a      	movi      	r0, 10
  5a:	e0000000 	bsr      	0x0	// 0 <delay_us>
  5e:	9475      	ld.w      	r3, (r4, 0x54)
  60:	3b9e      	bclri      	r3, 30
  62:	b475      	st.w      	r3, (r4, 0x54)
  64:	9475      	ld.w      	r3, (r4, 0x54)
  66:	c40357c3 	zext      	r3, r3, 30, 0
  6a:	b475      	st.w      	r3, (r4, 0x54)
  6c:	9465      	ld.w      	r3, (r4, 0x14)
  6e:	ec638000 	ori      	r3, r3, 32768
  72:	01db      	lrw      	r6, 0x0	// 380 <dsleep_rf_open+0x380>
  74:	96a3      	ld.w      	r5, (r6, 0xc)
  76:	b465      	st.w      	r3, (r4, 0x14)
  78:	9462      	ld.w      	r3, (r4, 0x8)
  7a:	3b99      	bclri      	r3, 25
  7c:	b462      	st.w      	r3, (r4, 0x8)
  7e:	9462      	ld.w      	r3, (r4, 0x8)
  80:	3bb9      	bseti      	r3, 25
  82:	b462      	st.w      	r3, (r4, 0x8)
  84:	017f      	lrw      	r3, 0x40f03cc	// 384 <dsleep_rf_open+0x384>
  86:	b560      	st.w      	r3, (r5, 0x0)
  88:	9561      	ld.w      	r3, (r5, 0x4)
  8a:	ec630004 	ori      	r3, r3, 4
  8e:	b561      	st.w      	r3, (r5, 0x4)
  90:	b4eb      	st.w      	r7, (r4, 0x2c)
  92:	9460      	ld.w      	r3, (r4, 0x0)
  94:	3b95      	bclri      	r3, 21
  96:	b460      	st.w      	r3, (r4, 0x0)
  98:	9460      	ld.w      	r3, (r4, 0x0)
  9a:	3b96      	bclri      	r3, 22
  9c:	b460      	st.w      	r3, (r4, 0x0)
  9e:	e0000000 	bsr      	0x0	// 0 <sys_get_apbclk>
  a2:	ea22ff01 	movih      	r2, 65281
  a6:	9560      	ld.w      	r3, (r5, 0x0)
  a8:	2a00      	subi      	r2, 1
  aa:	68c8      	and      	r3, r2
  ac:	b560      	st.w      	r3, (r5, 0x0)
  ae:	ea03b71b 	movi      	r3, 46875
  b2:	c5634903 	rotli      	r3, r3, 11
  b6:	c4608043 	divs      	r3, r0, r3
  ba:	e46320ff 	andi      	r3, r3, 255
  be:	2b00      	subi      	r3, 1
  c0:	9540      	ld.w      	r2, (r5, 0x0)
  c2:	4370      	lsli      	r3, r3, 16
  c4:	6cc8      	or      	r3, r2
  c6:	b560      	st.w      	r3, (r5, 0x0)
  c8:	e0000000 	bsr      	0x0	// 0 <sys_get_apbclk>
  cc:	487f      	lsri      	r3, r0, 31
  ce:	600c      	addu      	r0, r3
  d0:	32f9      	movi      	r2, 249
  d2:	ea03b71b 	movi      	r3, 46875
  d6:	c5434903 	rotli      	r3, r3, 10
  da:	5001      	asri      	r0, r0, 1
  dc:	4258      	lsli      	r2, r2, 24
  de:	64c2      	cmpne      	r0, r3
  e0:	2a00      	subi      	r2, 1
  e2:	9560      	ld.w      	r3, (r5, 0x0)
  e4:	68c8      	and      	r3, r2
  e6:	b560      	st.w      	r3, (r5, 0x0)
  e8:	6d1b      	mov      	r4, r6
  ea:	9560      	ld.w      	r3, (r5, 0x0)
  ec:	091d      	bt      	0x326	// 326 <dsleep_rf_open+0x326>
  ee:	3bb8      	bseti      	r3, 24
  f0:	b560      	st.w      	r3, (r5, 0x0)
  f2:	94c3      	ld.w      	r6, (r4, 0xc)
  f4:	3500      	movi      	r5, 0
  f6:	5d74      	addu      	r3, r5, r5
  f8:	025b      	lrw      	r2, 0x0	// 388 <dsleep_rf_open+0x388>
  fa:	60c8      	addu      	r3, r2
  fc:	7455      	zexth      	r1, r5
  fe:	d8431022 	ld.h      	r2, (r3, 0x44)
 102:	6c1b      	mov      	r0, r6
 104:	2500      	addi      	r5, 1
 106:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 10a:	eb450022 	cmpnei      	r5, 34
 10e:	0bf4      	bt      	0xf6	// f6 <dsleep_rf_open+0xf6>
 110:	3001      	movi      	r0, 1
 112:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
 116:	300a      	movi      	r0, 10
 118:	e0000000 	bsr      	0x0	// 0 <delay_us>
 11c:	3000      	movi      	r0, 0
 11e:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
 122:	ea038003 	movi      	r3, 32771
 126:	c5e34903 	rotli      	r3, r3, 15
 12a:	302c      	movi      	r0, 44
 12c:	932b      	ld.w      	r1, (r3, 0x2c)
 12e:	ec210001 	ori      	r1, r1, 1
 132:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 136:	3004      	movi      	r0, 4
 138:	e0000000 	bsr      	0x0	// 0 <pmu_vccmipi_vol_set_sec>
 13c:	3100      	movi      	r1, 0
 13e:	302a      	movi      	r0, 42
 140:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 144:	3103      	movi      	r1, 3
 146:	302b      	movi      	r0, 43
 148:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 14c:	e0000000 	bsr      	0x0	// 0 <adc_calib_res_restore>
 150:	0375      	lrw      	r3, 0x40026000	// 378 <dsleep_rf_open+0x378>
 152:	0354      	lrw      	r2, 0x3fac87e4	// 37c <dsleep_rf_open+0x37c>
 154:	9422      	ld.w      	r1, (r4, 0x8)
 156:	b34b      	st.w      	r2, (r3, 0x2c)
 158:	e42103df 	addi      	r1, r1, 992
 15c:	3259      	movi      	r2, 89
 15e:	9406      	ld.w      	r0, (r4, 0x18)
 160:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 164:	3700      	movi      	r7, 0
 166:	94a3      	ld.w      	r5, (r4, 0xc)
 168:	3640      	movi      	r6, 64
 16a:	2743      	addi      	r7, 68
 16c:	0378      	lrw      	r3, 0x0	// 388 <dsleep_rf_open+0x388>
 16e:	6e1b      	mov      	r8, r6
 170:	ea090000 	movi      	r9, 0
 174:	c467002a 	addu      	r10, r7, r3
 178:	d12a0442 	ldr.h      	r2, (r10, r9 << 1)
 17c:	6c63      	mov      	r1, r8
 17e:	7489      	zexth      	r2, r2
 180:	6c17      	mov      	r0, r5
 182:	e5290000 	addi      	r9, r9, 1
 186:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 18a:	eb490022 	cmpnei      	r9, 34
 18e:	e5080000 	addi      	r8, r8, 1
 192:	7621      	zexth      	r8, r8
 194:	0bf2      	bt      	0x178	// 178 <dsleep_rf_open+0x178>
 196:	263f      	addi      	r6, 64
 198:	7599      	zexth      	r6, r6
 19a:	eb460100 	cmpnei      	r6, 256
 19e:	0be6      	bt      	0x16a	// 16a <dsleep_rf_open+0x16a>
 1a0:	3680      	movi      	r6, 128
 1a2:	ea090000 	movi      	r9, 0
 1a6:	46c2      	lsli      	r6, r6, 2
 1a8:	1379      	lrw      	r3, 0x0	// 38c <dsleep_rf_open+0x38c>
 1aa:	6ddb      	mov      	r7, r6
 1ac:	ea080000 	movi      	r8, 0
 1b0:	c469002a 	addu      	r10, r9, r3
 1b4:	d10a0442 	ldr.h      	r2, (r10, r8 << 1)
 1b8:	6c5f      	mov      	r1, r7
 1ba:	7489      	zexth      	r2, r2
 1bc:	6c17      	mov      	r0, r5
 1be:	e5080000 	addi      	r8, r8, 1
 1c2:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 1c6:	eb480009 	cmpnei      	r8, 9
 1ca:	2700      	addi      	r7, 1
 1cc:	75dd      	zexth      	r7, r7
 1ce:	0bf3      	bt      	0x1b4	// 1b4 <dsleep_rf_open+0x1b4>
 1d0:	260f      	addi      	r6, 16
 1d2:	7599      	zexth      	r6, r6
 1d4:	eb460300 	cmpnei      	r6, 768
 1d8:	e5290011 	addi      	r9, r9, 18
 1dc:	0be6      	bt      	0x1a8	// 1a8 <dsleep_rf_open+0x1a8>
 1de:	3680      	movi      	r6, 128
 1e0:	ea090000 	movi      	r9, 0
 1e4:	46c3      	lsli      	r6, r6, 3
 1e6:	136b      	lrw      	r3, 0x0	// 390 <dsleep_rf_open+0x390>
 1e8:	6ddb      	mov      	r7, r6
 1ea:	ea080000 	movi      	r8, 0
 1ee:	c469002a 	addu      	r10, r9, r3
 1f2:	d10a0442 	ldr.h      	r2, (r10, r8 << 1)
 1f6:	6c5f      	mov      	r1, r7
 1f8:	7489      	zexth      	r2, r2
 1fa:	6c17      	mov      	r0, r5
 1fc:	e5080000 	addi      	r8, r8, 1
 200:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 204:	eb480003 	cmpnei      	r8, 3
 208:	2700      	addi      	r7, 1
 20a:	75dd      	zexth      	r7, r7
 20c:	0bf3      	bt      	0x1f2	// 1f2 <dsleep_rf_open+0x1f2>
 20e:	2607      	addi      	r6, 8
 210:	7599      	zexth      	r6, r6
 212:	eb460440 	cmpnei      	r6, 1088
 216:	e5290005 	addi      	r9, r9, 6
 21a:	0be6      	bt      	0x1e6	// 1e6 <dsleep_rf_open+0x1e6>
 21c:	36e0      	movi      	r6, 224
 21e:	46c3      	lsli      	r6, r6, 3
 220:	3700      	movi      	r7, 0
 222:	ea8a005d 	lrw      	r10, 0x0	// 394 <dsleep_rf_open+0x394>
 226:	ea88005d 	lrw      	r8, 0x0	// 398 <dsleep_rf_open+0x398>
 22a:	ea090006 	movi      	r9, 6
 22e:	d0ea0482 	ldr.h      	r2, (r10, r7 << 2)
 232:	4762      	lsli      	r3, r7, 2
 234:	6c5b      	mov      	r1, r6
 236:	7489      	zexth      	r2, r2
 238:	6c17      	mov      	r0, r5
 23a:	b860      	st.w      	r3, (r14, 0x0)
 23c:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 240:	1255      	lrw      	r2, 0x0	// 394 <dsleep_rf_open+0x394>
 242:	76dc      	zextb      	r11, r7
 244:	9860      	ld.w      	r3, (r14, 0x0)
 246:	60c8      	addu      	r3, r2
 248:	5e22      	addi      	r1, r6, 1
 24a:	8b41      	ld.h      	r2, (r3, 0x2)
 24c:	ea030fff 	movi      	r3, 4095
 250:	6cce      	nor      	r3, r3
 252:	688c      	and      	r2, r3
 254:	c46b4843 	lsri      	r3, r11, 3
 258:	7ce4      	mult      	r3, r9
 25a:	e56b2007 	andi      	r11, r11, 7
 25e:	60ec      	addu      	r3, r11
 260:	d0680443 	ldr.h      	r3, (r8, r3 << 1)
 264:	6c8c      	or      	r2, r3
 266:	7489      	zexth      	r2, r2
 268:	7445      	zexth      	r1, r1
 26a:	6c17      	mov      	r0, r5
 26c:	2700      	addi      	r7, 1
 26e:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 272:	eb470040 	cmpnei      	r7, 64
 276:	2601      	addi      	r6, 2
 278:	7599      	zexth      	r6, r6
 27a:	0bda      	bt      	0x22e	// 22e <dsleep_rf_open+0x22e>
 27c:	31a0      	movi      	r1, 160
 27e:	3200      	movi      	r2, 0
 280:	4121      	lsli      	r1, r1, 1
 282:	6c17      	mov      	r0, r5
 284:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 288:	3200      	movi      	r2, 0
 28a:	ea010141 	movi      	r1, 321
 28e:	6c17      	mov      	r0, r5
 290:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 294:	31a1      	movi      	r1, 161
 296:	3200      	movi      	r2, 0
 298:	4121      	lsli      	r1, r1, 1
 29a:	6c17      	mov      	r0, r5
 29c:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 2a0:	31c4      	movi      	r1, 196
 2a2:	3200      	movi      	r2, 0
 2a4:	4122      	lsli      	r1, r1, 2
 2a6:	6c17      	mov      	r0, r5
 2a8:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 2ac:	3189      	movi      	r1, 137
 2ae:	3200      	movi      	r2, 0
 2b0:	4123      	lsli      	r1, r1, 3
 2b2:	6c17      	mov      	r0, r5
 2b4:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 2b8:	3200      	movi      	r2, 0
 2ba:	ea010782 	movi      	r1, 1922
 2be:	6c17      	mov      	r0, r5
 2c0:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 2c4:	9462      	ld.w      	r3, (r4, 0x8)
 2c6:	94e3      	ld.w      	r7, (r4, 0xc)
 2c8:	d8630a4e 	ld.b      	r3, (r3, 0xa4e)
 2cc:	e4632001 	andi      	r3, r3, 1
 2d0:	e923002d 	bnez      	r3, 0x32a	// 32a <dsleep_rf_open+0x32a>
 2d4:	9462      	ld.w      	r3, (r4, 0x8)
 2d6:	d8630a4e 	ld.b      	r3, (r3, 0xa4e)
 2da:	e4632002 	andi      	r3, r3, 2
 2de:	e9230039 	bnez      	r3, 0x350	// 350 <dsleep_rf_open+0x350>
 2e2:	3001      	movi      	r0, 1
 2e4:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
 2e8:	9445      	ld.w      	r2, (r4, 0x14)
 2ea:	3100      	movi      	r1, 0
 2ec:	9260      	ld.w      	r3, (r2, 0x0)
 2ee:	2907      	subi      	r1, 8
 2f0:	68c4      	and      	r3, r1
 2f2:	b260      	st.w      	r3, (r2, 0x0)
 2f4:	e0000000 	bsr      	0x0	// 0 <lmac_rf_hw_ctrl>
 2f8:	1160      	lrw      	r3, 0x40026000	// 378 <dsleep_rf_open+0x378>
 2fa:	3100      	movi      	r1, 0
 2fc:	9347      	ld.w      	r2, (r3, 0x1c)
 2fe:	3ab3      	bseti      	r2, 19
 300:	b347      	st.w      	r2, (r3, 0x1c)
 302:	9355      	ld.w      	r2, (r3, 0x54)
 304:	3a89      	bclri      	r2, 9
 306:	b355      	st.w      	r2, (r3, 0x54)
 308:	9446      	ld.w      	r2, (r4, 0x18)
 30a:	302a      	movi      	r0, 42
 30c:	9278      	ld.w      	r3, (r2, 0x60)
 30e:	ec630010 	ori      	r3, r3, 16
 312:	b278      	st.w      	r3, (r2, 0x60)
 314:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 318:	3103      	movi      	r1, 3
 31a:	302b      	movi      	r0, 43
 31c:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 320:	3000      	movi      	r0, 0
 322:	1401      	addi      	r14, r14, 4
 324:	1498      	pop      	r4-r11, r15
 326:	b560      	st.w      	r3, (r5, 0x0)
 328:	06e5      	br      	0xf2	// f2 <dsleep_rf_open+0xf2>
 32a:	35a0      	movi      	r5, 160
 32c:	45a3      	lsli      	r5, r5, 3
 32e:	3600      	movi      	r6, 0
 330:	9462      	ld.w      	r3, (r4, 0x8)
 332:	e4460457 	addi      	r2, r6, 1112
 336:	d0430442 	ldr.h      	r2, (r3, r2 << 1)
 33a:	6c57      	mov      	r1, r5
 33c:	7489      	zexth      	r2, r2
 33e:	6c1f      	mov      	r0, r7
 340:	2600      	addi      	r6, 1
 342:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 346:	3e44      	cmpnei      	r6, 4
 348:	2500      	addi      	r5, 1
 34a:	7555      	zexth      	r5, r5
 34c:	0bf2      	bt      	0x330	// 330 <dsleep_rf_open+0x330>
 34e:	07c3      	br      	0x2d4	// 2d4 <dsleep_rf_open+0x2d4>
 350:	35a2      	movi      	r5, 162
 352:	45a3      	lsli      	r5, r5, 3
 354:	3600      	movi      	r6, 0
 356:	9462      	ld.w      	r3, (r4, 0x8)
 358:	e446045b 	addi      	r2, r6, 1116
 35c:	d0430442 	ldr.h      	r2, (r3, r2 << 1)
 360:	6c57      	mov      	r1, r5
 362:	7489      	zexth      	r2, r2
 364:	6c1f      	mov      	r0, r7
 366:	2600      	addi      	r6, 1
 368:	e0000000 	bsr      	0x0	// 0 <dsleep_rf_open>
 36c:	3e44      	cmpnei      	r6, 4
 36e:	2500      	addi      	r5, 1
 370:	7555      	zexth      	r5, r5
 372:	0bf2      	bt      	0x356	// 356 <dsleep_rf_open+0x356>
 374:	07b7      	br      	0x2e2	// 2e2 <dsleep_rf_open+0x2e2>
 376:	0000      	.short	0x0000
 378:	40026000 	.long	0x40026000
 37c:	3fac87e4 	.long	0x3fac87e4
 380:	00000000 	.long	0x00000000
 384:	040f03cc 	.long	0x040f03cc
	...

Disassembly of section .text.dsleep_io_set:

00000000 <dsleep_io_set>:
   0:	14d4      	push      	r4-r7, r15
   2:	1377      	lrw      	r3, 0x40026000	// 1dc <dsleep_io_set+0x1dc>
   4:	1397      	lrw      	r4, 0x0	// 1e0 <dsleep_io_set+0x1e0>
   6:	1358      	lrw      	r2, 0x3fac87e4	// 1e4 <dsleep_io_set+0x1e4>
   8:	b34b      	st.w      	r2, (r3, 0x2c)
   a:	9462      	ld.w      	r3, (r4, 0x8)
   c:	3200      	movi      	r2, 0
   e:	d9a320ad 	ld.w      	r13, (r3, 0x2b4)
  12:	3501      	movi      	r5, 1
  14:	9469      	ld.w      	r3, (r4, 0x24)
  16:	ea0c0003 	movi      	r12, 3
  1a:	c4454020 	lsl      	r0, r5, r2
  1e:	c40d2021 	and      	r1, r13, r0
  22:	e921000d 	bnez      	r1, 0x3c	// 3c <dsleep_io_set+0x3c>
  26:	3a0f      	cmphsi      	r2, 16
  28:	08be      	bt      	0x1a4	// 1a4 <dsleep_io_set+0x1a4>
  2a:	5a28      	addu      	r1, r2, r2
  2c:	93c0      	ld.w      	r6, (r3, 0x0)
  2e:	c42c4021 	lsl      	r1, r12, r1
  32:	6c58      	or      	r1, r6
  34:	b320      	st.w      	r1, (r3, 0x0)
  36:	9338      	ld.w      	r1, (r3, 0x60)
  38:	6c04      	or      	r0, r1
  3a:	b318      	st.w      	r0, (r3, 0x60)
  3c:	2200      	addi      	r2, 1
  3e:	eb420020 	cmpnei      	r2, 32
  42:	0bec      	bt      	0x1a	// 1a <dsleep_io_set+0x1a>
  44:	9340      	ld.w      	r2, (r3, 0x0)
  46:	3a80      	bclri      	r2, 0
  48:	3a81      	bclri      	r2, 1
  4a:	b340      	st.w      	r2, (r3, 0x0)
  4c:	9358      	ld.w      	r2, (r3, 0x60)
  4e:	3a80      	bclri      	r2, 0
  50:	b358      	st.w      	r2, (r3, 0x60)
  52:	3100      	movi      	r1, 0
  54:	9349      	ld.w      	r2, (r3, 0x24)
  56:	290f      	subi      	r1, 16
  58:	6884      	and      	r2, r1
  5a:	b349      	st.w      	r2, (r3, 0x24)
  5c:	9349      	ld.w      	r2, (r3, 0x24)
  5e:	ec420001 	ori      	r2, r2, 1
  62:	b349      	st.w      	r2, (r3, 0x24)
  64:	9340      	ld.w      	r2, (r3, 0x0)
  66:	3a82      	bclri      	r2, 2
  68:	3a83      	bclri      	r2, 3
  6a:	b340      	st.w      	r2, (r3, 0x0)
  6c:	9358      	ld.w      	r2, (r3, 0x60)
  6e:	3a81      	bclri      	r2, 1
  70:	b358      	st.w      	r2, (r3, 0x60)
  72:	3100      	movi      	r1, 0
  74:	9349      	ld.w      	r2, (r3, 0x24)
  76:	29f0      	subi      	r1, 241
  78:	6884      	and      	r2, r1
  7a:	b349      	st.w      	r2, (r3, 0x24)
  7c:	9349      	ld.w      	r2, (r3, 0x24)
  7e:	ec420010 	ori      	r2, r2, 16
  82:	b349      	st.w      	r2, (r3, 0x24)
  84:	9340      	ld.w      	r2, (r3, 0x0)
  86:	3a84      	bclri      	r2, 4
  88:	3a85      	bclri      	r2, 5
  8a:	b340      	st.w      	r2, (r3, 0x0)
  8c:	9358      	ld.w      	r2, (r3, 0x60)
  8e:	3a82      	bclri      	r2, 2
  90:	b358      	st.w      	r2, (r3, 0x60)
  92:	9349      	ld.w      	r2, (r3, 0x24)
  94:	ea010f00 	movi      	r1, 3840
  98:	6c46      	nor      	r1, r1
  9a:	6884      	and      	r2, r1
  9c:	b349      	st.w      	r2, (r3, 0x24)
  9e:	9349      	ld.w      	r2, (r3, 0x24)
  a0:	ec420100 	ori      	r2, r2, 256
  a4:	b349      	st.w      	r2, (r3, 0x24)
  a6:	9340      	ld.w      	r2, (r3, 0x0)
  a8:	3a86      	bclri      	r2, 6
  aa:	3a87      	bclri      	r2, 7
  ac:	b340      	st.w      	r2, (r3, 0x0)
  ae:	9358      	ld.w      	r2, (r3, 0x60)
  b0:	3a83      	bclri      	r2, 3
  b2:	b358      	st.w      	r2, (r3, 0x60)
  b4:	3100      	movi      	r1, 0
  b6:	301f      	movi      	r0, 31
  b8:	e0000000 	bsr      	0x0	// 0 <dsleep_io_set>
  bc:	3201      	movi      	r2, 1
  be:	6c4b      	mov      	r1, r2
  c0:	301f      	movi      	r0, 31
  c2:	e0000000 	bsr      	0x0	// 0 <dsleep_io_set>
  c6:	9469      	ld.w      	r3, (r4, 0x24)
  c8:	ea01f000 	movi      	r1, 61440
  cc:	6c46      	nor      	r1, r1
  ce:	934d      	ld.w      	r2, (r3, 0x34)
  d0:	6884      	and      	r2, r1
  d2:	b34d      	st.w      	r2, (r3, 0x34)
  d4:	934d      	ld.w      	r2, (r3, 0x34)
  d6:	d9842002 	ld.w      	r12, (r4, 0x8)
  da:	ec421000 	ori      	r2, r2, 4096
  de:	b34d      	st.w      	r2, (r3, 0x34)
  e0:	d8ac20ae 	ld.w      	r5, (r12, 0x2b8)
  e4:	942a      	ld.w      	r1, (r4, 0x28)
  e6:	3300      	movi      	r3, 0
  e8:	3601      	movi      	r6, 1
  ea:	ea0d0003 	movi      	r13, 3
  ee:	c4664020 	lsl      	r0, r6, r3
  f2:	c4052022 	and      	r2, r5, r0
  f6:	e922000d 	bnez      	r2, 0x110	// 110 <dsleep_io_set+0x110>
  fa:	3b0f      	cmphsi      	r3, 16
  fc:	085f      	bt      	0x1ba	// 1ba <dsleep_io_set+0x1ba>
  fe:	5b4c      	addu      	r2, r3, r3
 100:	91e0      	ld.w      	r7, (r1, 0x0)
 102:	c44d4022 	lsl      	r2, r13, r2
 106:	6c9c      	or      	r2, r7
 108:	b140      	st.w      	r2, (r1, 0x0)
 10a:	9158      	ld.w      	r2, (r1, 0x60)
 10c:	6c08      	or      	r0, r2
 10e:	b118      	st.w      	r0, (r1, 0x60)
 110:	2300      	addi      	r3, 1
 112:	3b53      	cmpnei      	r3, 19
 114:	0bed      	bt      	0xee	// ee <dsleep_io_set+0xee>
 116:	d80c025a 	ld.b      	r0, (r12, 0x25a)
 11a:	e4602001 	andi      	r3, r0, 1
 11e:	e903000d 	bez      	r3, 0x138	// 138 <dsleep_io_set+0x138>
 122:	3101      	movi      	r1, 1
 124:	7005      	lsr      	r0, r1
 126:	e0000000 	bsr      	0x0	// 0 <dsleep_io_set>
 12a:	9462      	ld.w      	r3, (r4, 0x8)
 12c:	3101      	movi      	r1, 1
 12e:	d803025a 	ld.b      	r0, (r3, 0x25a)
 132:	7005      	lsr      	r0, r1
 134:	e0000000 	bsr      	0x0	// 0 <dsleep_io_set>
 138:	9462      	ld.w      	r3, (r4, 0x8)
 13a:	d8030258 	ld.b      	r0, (r3, 0x258)
 13e:	e400207f 	andi      	r0, r0, 127
 142:	e460007e 	addi      	r3, r0, 127
 146:	e463207f 	andi      	r3, r3, 127
 14a:	eb030031 	cmphsi      	r3, 50
 14e:	081a      	bt      	0x182	// 182 <dsleep_io_set+0x182>
 150:	3100      	movi      	r1, 0
 152:	e0000000 	bsr      	0x0	// 0 <dsleep_io_set>
 156:	9462      	ld.w      	r3, (r4, 0x8)
 158:	3201      	movi      	r2, 1
 15a:	d8030258 	ld.b      	r0, (r3, 0x258)
 15e:	74c2      	sextb      	r3, r0
 160:	e9a30038 	bhsz      	r3, 0x1d0	// 1d0 <dsleep_io_set+0x1d0>
 164:	6c4b      	mov      	r1, r2
 166:	e400207f 	andi      	r0, r0, 127
 16a:	e0000000 	bsr      	0x0	// 0 <dsleep_io_set>
 16e:	ea038003 	movi      	r3, 32771
 172:	c5e34903 	rotli      	r3, r3, 15
 176:	30a0      	movi      	r0, 160
 178:	d8232028 	ld.w      	r1, (r3, 0xa0)
 17c:	39b0      	bseti      	r1, 16
 17e:	e0000000 	bsr      	0x0	// 0 <dsleep_io_set>
 182:	9402      	ld.w      	r0, (r4, 0x8)
 184:	321a      	movi      	r2, 26
 186:	ea214002 	movih      	r1, 16386
 18a:	39ad      	bseti      	r1, 13
 18c:	e40002e7 	addi      	r0, r0, 744
 190:	e0000000 	bsr      	0x0	// 0 <dsleep_io_set>
 194:	9402      	ld.w      	r0, (r4, 0x8)
 196:	321a      	movi      	r2, 26
 198:	1034      	lrw      	r1, 0x40025000	// 1e8 <dsleep_io_set+0x1e8>
 19a:	e400034f 	addi      	r0, r0, 848
 19e:	e0000000 	bsr      	0x0	// 0 <dsleep_io_set>
 1a2:	1494      	pop      	r4-r7, r15
 1a4:	c7c05021 	bmaski      	r1, 31
 1a8:	290e      	subi      	r1, 15
 1aa:	6048      	addu      	r1, r2
 1ac:	6044      	addu      	r1, r1
 1ae:	93c1      	ld.w      	r6, (r3, 0x4)
 1b0:	c42c4021 	lsl      	r1, r12, r1
 1b4:	6c58      	or      	r1, r6
 1b6:	b321      	st.w      	r1, (r3, 0x4)
 1b8:	073f      	br      	0x36	// 36 <dsleep_io_set+0x36>
 1ba:	c7c05022 	bmaski      	r2, 31
 1be:	2a0e      	subi      	r2, 15
 1c0:	608c      	addu      	r2, r3
 1c2:	6088      	addu      	r2, r2
 1c4:	91e1      	ld.w      	r7, (r1, 0x4)
 1c6:	c44d4022 	lsl      	r2, r13, r2
 1ca:	6c9c      	or      	r2, r7
 1cc:	b141      	st.w      	r2, (r1, 0x4)
 1ce:	079e      	br      	0x10a	// 10a <dsleep_io_set+0x10a>
 1d0:	3102      	movi      	r1, 2
 1d2:	e400207f 	andi      	r0, r0, 127
 1d6:	e0000000 	bsr      	0x0	// 0 <dsleep_io_set>
 1da:	07ca      	br      	0x16e	// 16e <dsleep_io_set+0x16e>
 1dc:	40026000 	.long	0x40026000
 1e0:	00000000 	.long	0x00000000
 1e4:	3fac87e4 	.long	0x3fac87e4
 1e8:	40025000 	.long	0x40025000

Disassembly of section .text.AlwaysOn_SRAM0_PowerDown:

00000000 <AlwaysOn_SRAM0_PowerDown>:
   0:	4241      	lsli      	r2, r2, 1
   2:	ea8c0016 	lrw      	r12, 0x40026000	// 58 <AlwaysOn_SRAM0_PowerDown+0x58>
   6:	ea8d0016 	lrw      	r13, 0x3fac87e4	// 5c <AlwaysOn_SRAM0_PowerDown+0x5c>
   a:	e4212001 	andi      	r1, r1, 1
   e:	e44227fe 	andi      	r2, r2, 2046
  12:	ddac200b 	st.w      	r13, (r12, 0x2c)
  16:	6c84      	or      	r2, r1
  18:	ea0d0000 	movi      	r13, 0
  1c:	436b      	lsli      	r3, r3, 11
  1e:	ea210020 	movih      	r1, 32
  22:	e42117ff 	subi      	r1, r1, 2048
  26:	ddac200a 	st.w      	r13, (r12, 0x28)
  2a:	68c4      	and      	r3, r1
  2c:	d9ac200a 	ld.w      	r13, (r12, 0x28)
  30:	6c8c      	or      	r2, r3
  32:	6cb4      	or      	r2, r13
  34:	dc4c200a 	st.w      	r2, (r12, 0x28)
  38:	e9200008 	bnez      	r0, 0x48	// 48 <AlwaysOn_SRAM0_PowerDown+0x48>
  3c:	d86c2019 	ld.w      	r3, (r12, 0x64)
  40:	3b92      	bclri      	r3, 18
  42:	dc6c2019 	st.w      	r3, (r12, 0x64)
  46:	783c      	jmp      	r15
  48:	3841      	cmpnei      	r0, 1
  4a:	0bfe      	bt      	0x46	// 46 <AlwaysOn_SRAM0_PowerDown+0x46>
  4c:	d86c2019 	ld.w      	r3, (r12, 0x64)
  50:	3bb2      	bseti      	r3, 18
  52:	dc6c2019 	st.w      	r3, (r12, 0x64)
  56:	07f8      	br      	0x46	// 46 <AlwaysOn_SRAM0_PowerDown+0x46>
  58:	40026000 	.long	0x40026000
  5c:	87e4      	.short	0x87e4
  5e:	3fac      	.short	0x3fac

Disassembly of section .text.dsleep_mode_set:

00000000 <dsleep_mode_set>:
   0:	1422      	subi      	r14, r14, 8
   2:	dd0e2000 	st.w      	r8, (r14, 0x0)
   6:	ddee2001 	st.w      	r15, (r14, 0x4)
   a:	6e3b      	mov      	r8, r14
   c:	1421      	subi      	r14, r14, 4
   e:	026a      	lrw      	r3, 0x40026000	// 2e0 <dsleep_mode_set+0x2e0>
  10:	024a      	lrw      	r2, 0x3fac87e4	// 2e4 <dsleep_mode_set+0x2e4>
  12:	b34b      	st.w      	r2, (r3, 0x2c)
  14:	3101      	movi      	r1, 1
  16:	30b0      	movi      	r0, 176
  18:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
  1c:	026c      	lrw      	r3, 0x0	// 2e8 <dsleep_mode_set+0x2e8>
  1e:	936b      	ld.w      	r3, (r3, 0x2c)
  20:	3200      	movi      	r2, 0
  22:	dc4320c0 	st.w      	r2, (r3, 0x300)
  26:	026e      	lrw      	r3, 0x0	// 2e8 <dsleep_mode_set+0x2e8>
  28:	936b      	ld.w      	r3, (r3, 0x2c)
  2a:	3200      	movi      	r2, 0
  2c:	dc4320c1 	st.w      	r2, (r3, 0x304)
  30:	0271      	lrw      	r3, 0x0	// 2e8 <dsleep_mode_set+0x2e8>
  32:	936b      	ld.w      	r3, (r3, 0x2c)
  34:	3200      	movi      	r2, 0
  36:	dc4320c2 	st.w      	r2, (r3, 0x308)
  3a:	0273      	lrw      	r3, 0x0	// 2e8 <dsleep_mode_set+0x2e8>
  3c:	936b      	ld.w      	r3, (r3, 0x2c)
  3e:	3200      	movi      	r2, 0
  40:	dc4320c3 	st.w      	r2, (r3, 0x30c)
  44:	0278      	lrw      	r3, 0x40026000	// 2e0 <dsleep_mode_set+0x2e0>
  46:	ea02cca4 	movi      	r2, 52388
  4a:	3ab6      	bseti      	r2, 22
  4c:	b353      	st.w      	r2, (r3, 0x4c)
  4e:	0277      	lrw      	r3, 0x4001a000	// 2ec <dsleep_mode_set+0x2ec>
  50:	3200      	movi      	r2, 0
  52:	b340      	st.w      	r2, (r3, 0x0)
  54:	027c      	lrw      	r3, 0x40026000	// 2e0 <dsleep_mode_set+0x2e0>
  56:	0258      	lrw      	r2, 0x7e000a00	// 2f0 <dsleep_mode_set+0x2f0>
  58:	b341      	st.w      	r2, (r3, 0x4)
  5a:	027d      	lrw      	r3, 0x40026000	// 2e0 <dsleep_mode_set+0x2e0>
  5c:	ea02840a 	movi      	r2, 33802
  60:	c6624902 	rotli      	r2, r2, 19
  64:	b347      	st.w      	r2, (r3, 0x1c)
  66:	0360      	lrw      	r3, 0x40026000	// 2e0 <dsleep_mode_set+0x2e0>
  68:	3200      	movi      	r2, 0
  6a:	b34e      	st.w      	r2, (r3, 0x38)
  6c:	ea038003 	movi      	r3, 32771
  70:	c5e34903 	rotli      	r3, r3, 15
  74:	936a      	ld.w      	r3, (r3, 0x28)
  76:	e46331e0 	andni      	r3, r3, 480
  7a:	6c4f      	mov      	r1, r3
  7c:	3028      	movi      	r0, 40
  7e:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
  82:	ea038003 	movi      	r3, 32771
  86:	c5e34903 	rotli      	r3, r3, 15
  8a:	936b      	ld.w      	r3, (r3, 0x2c)
  8c:	e4633001 	andni      	r3, r3, 1
  90:	6c4f      	mov      	r1, r3
  92:	302c      	movi      	r0, 44
  94:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
  98:	ea038003 	movi      	r3, 32771
  9c:	c5e34903 	rotli      	r3, r3, 15
  a0:	9360      	ld.w      	r3, (r3, 0x0)
  a2:	e4633001 	andni      	r3, r3, 1
  a6:	6c4f      	mov      	r1, r3
  a8:	3000      	movi      	r0, 0
  aa:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
  ae:	ea038003 	movi      	r3, 32771
  b2:	c5e34903 	rotli      	r3, r3, 15
  b6:	9360      	ld.w      	r3, (r3, 0x0)
  b8:	e4633002 	andni      	r3, r3, 2
  bc:	6c4f      	mov      	r1, r3
  be:	3000      	movi      	r0, 0
  c0:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
  c4:	ea038003 	movi      	r3, 32771
  c8:	c5e34903 	rotli      	r3, r3, 15
  cc:	9360      	ld.w      	r3, (r3, 0x0)
  ce:	e4633004 	andni      	r3, r3, 4
  d2:	6c4f      	mov      	r1, r3
  d4:	3000      	movi      	r0, 0
  d6:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
  da:	ea038003 	movi      	r3, 32771
  de:	c5e34903 	rotli      	r3, r3, 15
  e2:	9360      	ld.w      	r3, (r3, 0x0)
  e4:	e4633008 	andni      	r3, r3, 8
  e8:	6c4f      	mov      	r1, r3
  ea:	3000      	movi      	r0, 0
  ec:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
  f0:	ea038003 	movi      	r3, 32771
  f4:	c5e34903 	rotli      	r3, r3, 15
  f8:	9360      	ld.w      	r3, (r3, 0x0)
  fa:	e4633010 	andni      	r3, r3, 16
  fe:	6c4f      	mov      	r1, r3
 100:	3000      	movi      	r0, 0
 102:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 106:	ea038003 	movi      	r3, 32771
 10a:	c5e34903 	rotli      	r3, r3, 15
 10e:	9348      	ld.w      	r2, (r3, 0x20)
 110:	e4681003 	subi      	r3, r8, 4
 114:	1338      	lrw      	r1, 0xbf807f7	// 2f4 <dsleep_mode_set+0x2f4>
 116:	6885      	andn      	r2, r1
 118:	b340      	st.w      	r2, (r3, 0x0)
 11a:	1374      	lrw      	r3, 0x0	// 2e8 <dsleep_mode_set+0x2e8>
 11c:	9362      	ld.w      	r3, (r3, 0x8)
 11e:	d863025b 	ld.b      	r3, (r3, 0x25b)
 122:	74cc      	zextb      	r3, r3
 124:	e4632003 	andi      	r3, r3, 3
 128:	74cc      	zextb      	r3, r3
 12a:	e9030011 	bez      	r3, 0x14c	// 14c <dsleep_mode_set+0x14c>
 12e:	e4681003 	subi      	r3, r8, 4
 132:	e4481003 	subi      	r2, r8, 4
 136:	9240      	ld.w      	r2, (r2, 0x0)
 138:	ec420680 	ori      	r2, r2, 1664
 13c:	b340      	st.w      	r2, (r3, 0x0)
 13e:	e4681003 	subi      	r3, r8, 4
 142:	9320      	ld.w      	r1, (r3, 0x0)
 144:	3020      	movi      	r0, 32
 146:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 14a:	0409      	br      	0x15c	// 15c <dsleep_mode_set+0x15c>
 14c:	e4681003 	subi      	r3, r8, 4
 150:	e4481003 	subi      	r2, r8, 4
 154:	9220      	ld.w      	r1, (r2, 0x0)
 156:	1349      	lrw      	r2, 0x3200680	// 2f8 <dsleep_mode_set+0x2f8>
 158:	6c84      	or      	r2, r1
 15a:	b340      	st.w      	r2, (r3, 0x0)
 15c:	1363      	lrw      	r3, 0x0	// 2e8 <dsleep_mode_set+0x2e8>
 15e:	9362      	ld.w      	r3, (r3, 0x8)
 160:	d863025b 	ld.b      	r3, (r3, 0x25b)
 164:	74cc      	zextb      	r3, r3
 166:	e4632008 	andi      	r3, r3, 8
 16a:	74cc      	zextb      	r3, r3
 16c:	e903000a 	bez      	r3, 0x180	// 180 <dsleep_mode_set+0x180>
 170:	e4681003 	subi      	r3, r8, 4
 174:	e4481003 	subi      	r2, r8, 4
 178:	9240      	ld.w      	r2, (r2, 0x0)
 17a:	3aba      	bseti      	r2, 26
 17c:	3abb      	bseti      	r2, 27
 17e:	b340      	st.w      	r2, (r3, 0x0)
 180:	e4681003 	subi      	r3, r8, 4
 184:	9320      	ld.w      	r1, (r3, 0x0)
 186:	3020      	movi      	r0, 32
 188:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 18c:	ea038003 	movi      	r3, 32771
 190:	c5e34903 	rotli      	r3, r3, 15
 194:	9369      	ld.w      	r3, (r3, 0x24)
 196:	ec630007 	ori      	r3, r3, 7
 19a:	6c4f      	mov      	r1, r3
 19c:	3024      	movi      	r0, 36
 19e:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 1a2:	e4681003 	subi      	r3, r8, 4
 1a6:	1256      	lrw      	r2, 0x9ccf0a0b	// 2fc <dsleep_mode_set+0x2fc>
 1a8:	b340      	st.w      	r2, (r3, 0x0)
 1aa:	e4681003 	subi      	r3, r8, 4
 1ae:	9320      	ld.w      	r1, (r3, 0x0)
 1b0:	3030      	movi      	r0, 48
 1b2:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 1b6:	ea210100 	movih      	r1, 256
 1ba:	3034      	movi      	r0, 52
 1bc:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 1c0:	ea038003 	movi      	r3, 32771
 1c4:	c5e34903 	rotli      	r3, r3, 15
 1c8:	934e      	ld.w      	r2, (r3, 0x38)
 1ca:	e4681003 	subi      	r3, r8, 4
 1ce:	ea011ff0 	movi      	r1, 8176
 1d2:	6885      	andn      	r2, r1
 1d4:	b340      	st.w      	r2, (r3, 0x0)
 1d6:	e4681003 	subi      	r3, r8, 4
 1da:	e4481003 	subi      	r2, r8, 4
 1de:	9240      	ld.w      	r2, (r2, 0x0)
 1e0:	ec4204b0 	ori      	r2, r2, 1200
 1e4:	b340      	st.w      	r2, (r3, 0x0)
 1e6:	e4681003 	subi      	r3, r8, 4
 1ea:	9320      	ld.w      	r1, (r3, 0x0)
 1ec:	3038      	movi      	r0, 56
 1ee:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 1f2:	3300      	movi      	r3, 0
 1f4:	3201      	movi      	r2, 1
 1f6:	3101      	movi      	r1, 1
 1f8:	3000      	movi      	r0, 0
 1fa:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 1fe:	e4681003 	subi      	r3, r8, 4
 202:	1240      	lrw      	r2, 0x1f58350f	// 300 <dsleep_mode_set+0x300>
 204:	b340      	st.w      	r2, (r3, 0x0)
 206:	e4681003 	subi      	r3, r8, 4
 20a:	9320      	ld.w      	r1, (r3, 0x0)
 20c:	3010      	movi      	r0, 16
 20e:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 212:	e4681003 	subi      	r3, r8, 4
 216:	115c      	lrw      	r2, 0x5ff0707	// 304 <dsleep_mode_set+0x304>
 218:	b340      	st.w      	r2, (r3, 0x0)
 21a:	e4681003 	subi      	r3, r8, 4
 21e:	9320      	ld.w      	r1, (r3, 0x0)
 220:	3014      	movi      	r0, 20
 222:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 226:	e4681003 	subi      	r3, r8, 4
 22a:	1158      	lrw      	r2, 0xc71c71f	// 308 <dsleep_mode_set+0x308>
 22c:	b340      	st.w      	r2, (r3, 0x0)
 22e:	e4681003 	subi      	r3, r8, 4
 232:	9320      	ld.w      	r1, (r3, 0x0)
 234:	3018      	movi      	r0, 24
 236:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 23a:	ea210003 	movih      	r1, 3
 23e:	301c      	movi      	r0, 28
 240:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 244:	ea038003 	movi      	r3, 32771
 248:	c5e34903 	rotli      	r3, r3, 15
 24c:	d8632028 	ld.w      	r3, (r3, 0xa0)
 250:	3bb1      	bseti      	r3, 17
 252:	6c4f      	mov      	r1, r3
 254:	30a0      	movi      	r0, 160
 256:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 25a:	ea038003 	movi      	r3, 32771
 25e:	c5e34903 	rotli      	r3, r3, 15
 262:	d8632028 	ld.w      	r3, (r3, 0xa0)
 266:	ec630400 	ori      	r3, r3, 1024
 26a:	6c4f      	mov      	r1, r3
 26c:	30a0      	movi      	r0, 160
 26e:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 272:	ea038003 	movi      	r3, 32771
 276:	c5e34903 	rotli      	r3, r3, 15
 27a:	d8632028 	ld.w      	r3, (r3, 0xa0)
 27e:	3bb2      	bseti      	r3, 18
 280:	6c4f      	mov      	r1, r3
 282:	30a0      	movi      	r0, 160
 284:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 288:	ea038003 	movi      	r3, 32771
 28c:	c5e34903 	rotli      	r3, r3, 15
 290:	d8632028 	ld.w      	r3, (r3, 0xa0)
 294:	ec630800 	ori      	r3, r3, 2048
 298:	6c4f      	mov      	r1, r3
 29a:	30a0      	movi      	r0, 160
 29c:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 2a0:	ea038003 	movi      	r3, 32771
 2a4:	c5e34903 	rotli      	r3, r3, 15
 2a8:	d8632028 	ld.w      	r3, (r3, 0xa0)
 2ac:	3bb3      	bseti      	r3, 19
 2ae:	6c4f      	mov      	r1, r3
 2b0:	30a0      	movi      	r0, 160
 2b2:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 2b6:	ea038003 	movi      	r3, 32771
 2ba:	c5e34903 	rotli      	r3, r3, 15
 2be:	d8632028 	ld.w      	r3, (r3, 0xa0)
 2c2:	ec631000 	ori      	r3, r3, 4096
 2c6:	6c4f      	mov      	r1, r3
 2c8:	30a0      	movi      	r0, 160
 2ca:	e0000000 	bsr      	0x0	// 0 <dsleep_mode_set>
 2ce:	6c00      	or      	r0, r0
 2d0:	6fa3      	mov      	r14, r8
 2d2:	d9ee2001 	ld.w      	r15, (r14, 0x4)
 2d6:	d90e2000 	ld.w      	r8, (r14, 0x0)
 2da:	1402      	addi      	r14, r14, 8
 2dc:	783c      	jmp      	r15
 2de:	0000      	.short	0x0000
 2e0:	40026000 	.long	0x40026000
 2e4:	3fac87e4 	.long	0x3fac87e4
 2e8:	00000000 	.long	0x00000000
 2ec:	4001a000 	.long	0x4001a000
 2f0:	7e000a00 	.long	0x7e000a00
 2f4:	0bf807f7 	.long	0x0bf807f7
 2f8:	03200680 	.long	0x03200680
 2fc:	9ccf0a0b 	.long	0x9ccf0a0b
 300:	1f58350f 	.long	0x1f58350f
 304:	05ff0707 	.long	0x05ff0707
 308:	0c71c71f 	.long	0x0c71c71f

Disassembly of section .text.wakeup_by_mclr:

00000000 <wakeup_by_mclr>:
   0:	1422      	subi      	r14, r14, 8
   2:	dd0e2000 	st.w      	r8, (r14, 0x0)
   6:	ddee2001 	st.w      	r15, (r14, 0x4)
   a:	6e3b      	mov      	r8, r14
   c:	1422      	subi      	r14, r14, 8
   e:	ea038003 	movi      	r3, 32771
  12:	c5e34903 	rotli      	r3, r3, 15
  16:	9367      	ld.w      	r3, (r3, 0x1c)
  18:	e4632080 	andi      	r3, r3, 128
  1c:	e9030004 	bez      	r3, 0x24	// 24 <wakeup_by_mclr+0x24>
  20:	e0000000 	bsr      	0x0	// 0 <pmu_pd_clear_core_pd_pnd_sec>
  24:	ea038003 	movi      	r3, 32771
  28:	c5e34903 	rotli      	r3, r3, 15
  2c:	9347      	ld.w      	r2, (r3, 0x1c)
  2e:	ea038000 	movi      	r3, 32768
  32:	68c8      	and      	r3, r2
  34:	e9030004 	bez      	r3, 0x3c	// 3c <wakeup_by_mclr+0x3c>
  38:	e0000000 	bsr      	0x0	// 0 <pmu_pd_clear_rf_pd_pnd_sec>
  3c:	ea038003 	movi      	r3, 32771
  40:	c5e34903 	rotli      	r3, r3, 15
  44:	d8632028 	ld.w      	r3, (r3, 0xa0)
  48:	e4633002 	andni      	r3, r3, 2
  4c:	6c4f      	mov      	r1, r3
  4e:	30a0      	movi      	r0, 160
  50:	e0000000 	bsr      	0x0	// 0 <wakeup_by_mclr>
  54:	1170      	lrw      	r3, 0x0	// 114 <wakeup_by_mclr+0x114>
  56:	9362      	ld.w      	r3, (r3, 0x8)
  58:	d8630258 	ld.b      	r3, (r3, 0x258)
  5c:	74cc      	zextb      	r3, r3
  5e:	e463307f 	andni      	r3, r3, 127
  62:	74cc      	zextb      	r3, r3
  64:	e903000e 	bez      	r3, 0x80	// 80 <wakeup_by_mclr+0x80>
  68:	ea038003 	movi      	r3, 32771
  6c:	c5e34903 	rotli      	r3, r3, 15
  70:	d8632028 	ld.w      	r3, (r3, 0xa0)
  74:	ec630002 	ori      	r3, r3, 2
  78:	6c4f      	mov      	r1, r3
  7a:	30a0      	movi      	r0, 160
  7c:	e0000000 	bsr      	0x0	// 0 <wakeup_by_mclr>
  80:	1165      	lrw      	r3, 0x0	// 114 <wakeup_by_mclr+0x114>
  82:	9362      	ld.w      	r3, (r3, 0x8)
  84:	d8630258 	ld.b      	r3, (r3, 0x258)
  88:	74cc      	zextb      	r3, r3
  8a:	e463207f 	andi      	r3, r3, 127
  8e:	74cc      	zextb      	r3, r3
  90:	e903000b 	bez      	r3, 0xa6	// a6 <wakeup_by_mclr+0xa6>
  94:	1160      	lrw      	r3, 0x0	// 114 <wakeup_by_mclr+0x114>
  96:	9362      	ld.w      	r3, (r3, 0x8)
  98:	d8630258 	ld.b      	r3, (r3, 0x258)
  9c:	c40354c3 	zext      	r3, r3, 6, 0
  a0:	74cc      	zextb      	r3, r3
  a2:	6c8f      	mov      	r2, r3
  a4:	0402      	br      	0xa8	// a8 <wakeup_by_mclr+0xa8>
  a6:	3233      	movi      	r2, 51
  a8:	e4681000 	subi      	r3, r8, 1
  ac:	a340      	st.b      	r2, (r3, 0x0)
  ae:	ea038003 	movi      	r3, 32771
  b2:	c5e34903 	rotli      	r3, r3, 15
  b6:	d8432028 	ld.w      	r2, (r3, 0xa0)
  ba:	e4681007 	subi      	r3, r8, 8
  be:	e44230fc 	andni      	r2, r2, 252
  c2:	b340      	st.w      	r2, (r3, 0x0)
  c4:	e4681000 	subi      	r3, r8, 1
  c8:	8360      	ld.b      	r3, (r3, 0x0)
  ca:	74cc      	zextb      	r3, r3
  cc:	4362      	lsli      	r3, r3, 2
  ce:	e42320ff 	andi      	r1, r3, 255
  d2:	e4681007 	subi      	r3, r8, 8
  d6:	e4481007 	subi      	r2, r8, 8
  da:	9240      	ld.w      	r2, (r2, 0x0)
  dc:	6c84      	or      	r2, r1
  de:	b340      	st.w      	r2, (r3, 0x0)
  e0:	e4681007 	subi      	r3, r8, 8
  e4:	9320      	ld.w      	r1, (r3, 0x0)
  e6:	30a0      	movi      	r0, 160
  e8:	e0000000 	bsr      	0x0	// 0 <wakeup_by_mclr>
  ec:	ea038003 	movi      	r3, 32771
  f0:	c5e34903 	rotli      	r3, r3, 15
  f4:	d8632028 	ld.w      	r3, (r3, 0xa0)
  f8:	ec630001 	ori      	r3, r3, 1
  fc:	6c4f      	mov      	r1, r3
  fe:	30a0      	movi      	r0, 160
 100:	e0000000 	bsr      	0x0	// 0 <wakeup_by_mclr>
 104:	6c00      	or      	r0, r0
 106:	6fa3      	mov      	r14, r8
 108:	d9ee2001 	ld.w      	r15, (r14, 0x4)
 10c:	d90e2000 	ld.w      	r8, (r14, 0x0)
 110:	1402      	addi      	r14, r14, 8
 112:	783c      	jmp      	r15
 114:	00000000 	.long	0x00000000

Disassembly of section .text.mars_power_down:

00000000 <mars_power_down>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <mars_power_down>
   6:	e0000000 	bsr      	0x0	// 0 <mars_power_down>
   a:	1067      	lrw      	r3, 0x40026000	// 24 <mars_power_down+0x24>
   c:	9346      	ld.w      	r2, (r3, 0x18)
   e:	3ab5      	bseti      	r2, 21
  10:	3ab6      	bseti      	r2, 22
  12:	b346      	st.w      	r2, (r3, 0x18)
  14:	9346      	ld.w      	r2, (r3, 0x18)
  16:	3ab7      	bseti      	r2, 23
  18:	b346      	st.w      	r2, (r3, 0x18)
  1a:	c6005022 	bmaski      	r2, 17
  1e:	2a01      	subi      	r2, 2
  20:	b359      	st.w      	r2, (r3, 0x64)
  22:	1490      	pop      	r15
  24:	6000      	.short	0x6000
  26:	4002      	.short	0x4002

Disassembly of section .text.dsleep_lo_set:

00000000 <dsleep_lo_set>:
   0:	14d3      	push      	r4-r6, r15
   2:	1284      	lrw      	r4, 0x0	// 110 <dsleep_lo_set+0x110>
   4:	31c2      	movi      	r1, 194
   6:	94a3      	ld.w      	r5, (r4, 0xc)
   8:	6d83      	mov      	r6, r0
   a:	4123      	lsli      	r1, r1, 3
   c:	6c17      	mov      	r0, r5
   e:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  12:	ec4000ff 	ori      	r2, r0, 255
  16:	31c2      	movi      	r1, 194
  18:	7489      	zexth      	r2, r2
  1a:	4123      	lsli      	r1, r1, 3
  1c:	6c17      	mov      	r0, r5
  1e:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  22:	117d      	lrw      	r3, 0xfff4dc70	// 114 <dsleep_lo_set+0x114>
  24:	5e4c      	addu      	r2, r6, r3
  26:	ea03c350 	movi      	r3, 50000
  2a:	c4434903 	rotli      	r3, r3, 2
  2e:	648c      	cmphs      	r3, r2
  30:	0809      	bt      	0x42	// 42 <dsleep_lo_set+0x42>
  32:	111a      	lrw      	r0, 0x0	// 118 <dsleep_lo_set+0x118>
  34:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  38:	1199      	lrw      	r4, 0x0	// 11c <dsleep_lo_set+0x11c>
  3a:	6c13      	mov      	r0, r4
  3c:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  40:	07fd      	br      	0x3a	// 3a <dsleep_lo_set+0x3a>
  42:	3364      	movi      	r3, 100
  44:	3250      	movi      	r2, 80
  46:	c4668023 	divu      	r3, r6, r3
  4a:	c4438025 	divu      	r5, r3, r2
  4e:	7d48      	mult      	r5, r2
  50:	5bb5      	subu      	r5, r3, r5
  52:	c6a05023 	bmaski      	r3, 22
  56:	9483      	ld.w      	r4, (r4, 0xc)
  58:	2b01      	subi      	r3, 2
  5a:	31c2      	movi      	r1, 194
  5c:	7d4c      	mult      	r5, r3
  5e:	4123      	lsli      	r1, r1, 3
  60:	6c13      	mov      	r0, r4
  62:	c4458025 	divu      	r5, r5, r2
  66:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  6a:	ec4000ff 	ori      	r2, r0, 255
  6e:	31c2      	movi      	r1, 194
  70:	7489      	zexth      	r2, r2
  72:	4123      	lsli      	r1, r1, 3
  74:	6c13      	mov      	r0, r4
  76:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  7a:	32fa      	movi      	r2, 250
  7c:	4245      	lsli      	r2, r2, 5
  7e:	c4468022 	divu      	r2, r6, r2
  82:	31c0      	movi      	r1, 192
  84:	7489      	zexth      	r2, r2
  86:	4123      	lsli      	r1, r1, 3
  88:	6c13      	mov      	r0, r4
  8a:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  8e:	7495      	zexth      	r2, r5
  90:	ea010601 	movi      	r1, 1537
  94:	6c13      	mov      	r0, r4
  96:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  9a:	4d50      	lsri      	r2, r5, 16
  9c:	ea010602 	movi      	r1, 1538
  a0:	6c13      	mov      	r0, r4
  a2:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  a6:	3181      	movi      	r1, 129
  a8:	3230      	movi      	r2, 48
  aa:	4124      	lsli      	r1, r1, 4
  ac:	6c13      	mov      	r0, r4
  ae:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  b2:	3181      	movi      	r1, 129
  b4:	3231      	movi      	r2, 49
  b6:	4124      	lsli      	r1, r1, 4
  b8:	6c13      	mov      	r0, r4
  ba:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  be:	ea010811 	movi      	r1, 2065
  c2:	6c13      	mov      	r0, r4
  c4:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  c8:	e4002400 	andi      	r0, r0, 1024
  cc:	e900fff9 	bez      	r0, 0xbe	// be <dsleep_lo_set+0xbe>
  d0:	30c8      	movi      	r0, 200
  d2:	e0000000 	bsr      	0x0	// 0 <delay_us>
  d6:	ea010811 	movi      	r1, 2065
  da:	6c13      	mov      	r0, r4
  dc:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  e0:	e44021ff 	andi      	r2, r0, 511
  e4:	ea010603 	movi      	r1, 1539
  e8:	6c13      	mov      	r0, r4
  ea:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  ee:	ea010603 	movi      	r1, 1539
  f2:	6c13      	mov      	r0, r4
  f4:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
  f8:	ea010811 	movi      	r1, 2065
  fc:	6c13      	mov      	r0, r4
  fe:	e0000000 	bsr      	0x0	// 0 <dsleep_lo_set>
 102:	e4002400 	andi      	r0, r0, 1024
 106:	e900ff99 	bez      	r0, 0x38	// 38 <dsleep_lo_set+0x38>
 10a:	3000      	movi      	r0, 0
 10c:	1493      	pop      	r4-r6, r15
 10e:	0000      	.short	0x0000
 110:	00000000 	.long	0x00000000
 114:	fff4dc70 	.long	0xfff4dc70
	...

Disassembly of section .text.dsleep_params_save:

00000000 <dsleep_params_save>:
   0:	14d1      	push      	r4, r15
   2:	1096      	lrw      	r4, 0x0	// 58 <dsleep_params_save+0x58>
   4:	320b      	movi      	r2, 11
   6:	9402      	ld.w      	r0, (r4, 0x8)
   8:	1035      	lrw      	r1, 0x40016000	// 5c <dsleep_params_save+0x5c>
   a:	e4000543 	addi      	r0, r0, 1348
   e:	e0000000 	bsr      	0x0	// 0 <dsleep_params_save>
  12:	9402      	ld.w      	r0, (r4, 0x8)
  14:	3259      	movi      	r2, 89
  16:	1033      	lrw      	r1, 0x4001d000	// 60 <dsleep_params_save+0x60>
  18:	e40003df 	addi      	r0, r0, 992
  1c:	e0000000 	bsr      	0x0	// 0 <dsleep_params_save>
  20:	9402      	ld.w      	r0, (r4, 0x8)
  22:	320a      	movi      	r2, 10
  24:	ea015000 	movi      	r1, 20480
  28:	39be      	bseti      	r1, 30
  2a:	e40003b7 	addi      	r0, r0, 952
  2e:	e0000000 	bsr      	0x0	// 0 <dsleep_params_save>
  32:	9402      	ld.w      	r0, (r4, 0x8)
  34:	328f      	movi      	r2, 143
  36:	ea214002 	movih      	r1, 16386
  3a:	39ae      	bseti      	r1, 14
  3c:	e400056f 	addi      	r0, r0, 1392
  40:	e0000000 	bsr      	0x0	// 0 <dsleep_params_save>
  44:	9402      	ld.w      	r0, (r4, 0x8)
  46:	3241      	movi      	r2, 65
  48:	ea018000 	movi      	r1, 32768
  4c:	39be      	bseti      	r1, 30
  4e:	e40007ab 	addi      	r0, r0, 1964
  52:	e0000000 	bsr      	0x0	// 0 <dsleep_params_save>
  56:	1491      	pop      	r4, r15
  58:	00000000 	.long	0x00000000
  5c:	6000      	.short	0x6000
  5e:	4001      	.short	0x4001
  60:	4001d000 	.long	0x4001d000

Disassembly of section .text.dsleep_pd_tmr_start_sec:

00000000 <dsleep_pd_tmr_start_sec>:
   0:	14d5      	push      	r4-r8, r15
   2:	117b      	lrw      	r3, 0x6b49d200	// ec <dsleep_pd_tmr_start_sec+0xec>
   4:	640c      	cmphs      	r3, r0
   6:	6d83      	mov      	r6, r0
   8:	11fa      	lrw      	r7, 0x0	// f0 <dsleep_pd_tmr_start_sec+0xf0>
   a:	0865      	bt      	0xd4	// d4 <dsleep_pd_tmr_start_sec+0xd4>
   c:	111a      	lrw      	r0, 0x0	// f4 <dsleep_pd_tmr_start_sec+0xf4>
   e:	e0000000 	bsr      	0x0	// 0 <dsleep_pd_tmr_start_sec>
  12:	6c1b      	mov      	r0, r6
  14:	e0000000 	bsr      	0x0	// 0 <dsleep_pd_tmr_start_sec>
  18:	ea06f424 	movi      	r6, 62500
  1c:	c4864906 	rotli      	r6, r6, 4
  20:	3500      	movi      	r5, 0
  22:	6d1b      	mov      	r4, r6
  24:	6c93      	mov      	r2, r4
  26:	6cd7      	mov      	r3, r5
  28:	d8072043 	ld.w      	r0, (r7, 0x10c)
  2c:	6c57      	mov      	r1, r5
  2e:	e0000000 	bsr      	0x0	// 0 <__muldi3>
  32:	ea068003 	movi      	r6, 32771
  36:	c5e64906 	rotli      	r6, r6, 15
  3a:	412b      	lsli      	r1, r1, 11
  3c:	4815      	lsri      	r0, r0, 21
  3e:	6c04      	or      	r0, r1
  40:	32e0      	movi      	r2, 224
  42:	4258      	lsli      	r2, r2, 24
  44:	d8662022 	ld.w      	r3, (r6, 0x88)
  48:	2800      	subi      	r0, 1
  4a:	68c8      	and      	r3, r2
  4c:	c4005780 	zext      	r0, r0, 28, 0
  50:	c4602421 	or      	r1, r0, r3
  54:	3088      	movi      	r0, 136
  56:	e0000000 	bsr      	0x0	// 0 <dsleep_pd_tmr_start_sec>
  5a:	d8262020 	ld.w      	r1, (r6, 0x80)
  5e:	ec210001 	ori      	r1, r1, 1
  62:	3080      	movi      	r0, 128
  64:	e0000000 	bsr      	0x0	// 0 <dsleep_pd_tmr_start_sec>
  68:	1164      	lrw      	r3, 0x0	// f8 <dsleep_pd_tmr_start_sec+0xf8>
  6a:	6c97      	mov      	r2, r5
  6c:	9320      	ld.w      	r1, (r3, 0x0)
  6e:	d9072002 	ld.w      	r8, (r7, 0x8)
  72:	9105      	ld.w      	r0, (r1, 0x14)
  74:	d9812004 	ld.w      	r12, (r1, 0x10)
  78:	6cc3      	mov      	r3, r0
  7a:	6c57      	mov      	r1, r5
  7c:	6c33      	mov      	r0, r12
  7e:	6401      	cmplt      	r0, r0
  80:	6009      	addc      	r0, r2
  82:	604d      	addc      	r1, r3
  84:	d98820b4 	ld.w      	r12, (r8, 0x2d0)
  88:	d9a820b5 	ld.w      	r13, (r8, 0x2d4)
  8c:	6474      	cmphs      	r13, r1
  8e:	0c05      	bf      	0x98	// 98 <dsleep_pd_tmr_start_sec+0x98>
  90:	6746      	cmpne      	r1, r13
  92:	081a      	bt      	0xc6	// c6 <dsleep_pd_tmr_start_sec+0xc6>
  94:	6430      	cmphs      	r12, r0
  96:	0818      	bt      	0xc6	// c6 <dsleep_pd_tmr_start_sec+0xc6>
  98:	36fa      	movi      	r6, 250
  9a:	d84820b2 	ld.w      	r2, (r8, 0x2c8)
  9e:	d86820b3 	ld.w      	r3, (r8, 0x2cc)
  a2:	46c3      	lsli      	r6, r6, 3
  a4:	3700      	movi      	r7, 0
  a6:	6489      	cmplt      	r2, r2
  a8:	6099      	addc      	r2, r6
  aa:	60dd      	addc      	r3, r7
  ac:	6488      	cmphs      	r2, r2
  ae:	60b3      	subc      	r2, r12
  b0:	60f7      	subc      	r3, r13
  b2:	6489      	cmplt      	r2, r2
  b4:	6081      	addc      	r2, r0
  b6:	60c5      	addc      	r3, r1
  b8:	6489      	cmplt      	r2, r2
  ba:	6091      	addc      	r2, r4
  bc:	60d5      	addc      	r3, r5
  be:	dc4820b2 	st.w      	r2, (r8, 0x2c8)
  c2:	dc6820b3 	st.w      	r3, (r8, 0x2cc)
  c6:	3300      	movi      	r3, 0
  c8:	3400      	movi      	r4, 0
  ca:	dc6820b4 	st.w      	r3, (r8, 0x2d0)
  ce:	dc8820b5 	st.w      	r4, (r8, 0x2d4)
  d2:	1495      	pop      	r4-r8, r15
  d4:	9742      	ld.w      	r2, (r7, 0x8)
  d6:	d86209c6 	ld.b      	r3, (r2, 0x9c6)
  da:	d842227f 	ld.w      	r2, (r2, 0x9fc)
  de:	7cc8      	mult      	r3, r2
  e0:	4b44      	lsri      	r2, r3, 4
  e2:	6480      	cmphs      	r0, r2
  e4:	60c0      	addu      	r3, r0
  e6:	c4c30c20 	incf      	r6, r3, 0
  ea:	079b      	br      	0x20	// 20 <dsleep_pd_tmr_start_sec+0x20>
  ec:	6b49d200 	.long	0x6b49d200
	...

Disassembly of section .text.dsleep_norflash_reboot:

00000000 <dsleep_norflash_reboot>:
   0:	14d1      	push      	r4, r15
   2:	107a      	lrw      	r3, 0x0	// 68 <dsleep_norflash_reboot+0x68>
   4:	3100      	movi      	r1, 0
   6:	8346      	ld.b      	r2, (r3, 0x6)
   8:	c4415c02 	ins      	r2, r1, 2, 2
   c:	ea048003 	movi      	r4, 32771
  10:	c5e44904 	rotli      	r4, r4, 15
  14:	3180      	movi      	r1, 128
  16:	a346      	st.b      	r2, (r3, 0x6)
  18:	4131      	lsli      	r1, r1, 17
  1a:	3034      	movi      	r0, 52
  1c:	e0000000 	bsr      	0x0	// 0 <dsleep_norflash_reboot>
  20:	d8242020 	ld.w      	r1, (r4, 0x80)
  24:	3980      	bclri      	r1, 0
  26:	3080      	movi      	r0, 128
  28:	e0000000 	bsr      	0x0	// 0 <dsleep_norflash_reboot>
  2c:	d8242028 	ld.w      	r1, (r4, 0xa0)
  30:	3980      	bclri      	r1, 0
  32:	30a0      	movi      	r0, 160
  34:	e0000000 	bsr      	0x0	// 0 <dsleep_norflash_reboot>
  38:	9427      	ld.w      	r1, (r4, 0x1c)
  3a:	3987      	bclri      	r1, 7
  3c:	398f      	bclri      	r1, 15
  3e:	301c      	movi      	r0, 28
  40:	e0000000 	bsr      	0x0	// 0 <dsleep_norflash_reboot>
  44:	d8242020 	ld.w      	r1, (r4, 0x80)
  48:	3982      	bclri      	r1, 2
  4a:	3983      	bclri      	r1, 3
  4c:	3080      	movi      	r0, 128
  4e:	e0000000 	bsr      	0x0	// 0 <dsleep_norflash_reboot>
  52:	d8242028 	ld.w      	r1, (r4, 0xa0)
  56:	39b0      	bseti      	r1, 16
  58:	30a0      	movi      	r0, 160
  5a:	e0000000 	bsr      	0x0	// 0 <dsleep_norflash_reboot>
  5e:	1004      	lrw      	r0, 0x0	// 6c <dsleep_norflash_reboot+0x6c>
  60:	e0000000 	bsr      	0x0	// 0 <dsleep_norflash_reboot>
  64:	e0000000 	bsr      	0x0	// 0 <dsleep_norflash_reboot>
	...

Disassembly of section .text.dsleep_back_to_dsleep:

00000000 <dsleep_back_to_dsleep>:
   0:	14d4      	push      	r4-r7, r15
   2:	02a1      	lrw      	r5, 0x0	// 2f8 <dsleep_back_to_dsleep+0x2f8>
   4:	6d03      	mov      	r4, r0
   6:	8564      	ld.b      	r3, (r5, 0x4)
   8:	e4432001 	andi      	r2, r3, 1
   c:	e902015d 	bez      	r2, 0x2c6	// 2c6 <dsleep_back_to_dsleep+0x2c6>
  10:	8546      	ld.b      	r2, (r5, 0x6)
  12:	c4435443 	zext      	r3, r3, 2, 2
  16:	c4435c02 	ins      	r2, r3, 2, 2
  1a:	a546      	st.b      	r2, (r5, 0x6)
  1c:	d8454128 	ld.bs      	r2, (r5, 0x128)
  20:	e9820041 	blz      	r2, 0xa2	// a2 <dsleep_back_to_dsleep+0xa2>
  24:	9562      	ld.w      	r3, (r5, 0x8)
  26:	d82309c6 	ld.b      	r1, (r3, 0x9c6)
  2a:	6449      	cmplt      	r2, r1
  2c:	0c3b      	bf      	0xa2	// a2 <dsleep_back_to_dsleep+0xa2>
  2e:	32fa      	movi      	r2, 250
  30:	d8250129 	ld.b      	r1, (r5, 0x129)
  34:	4242      	lsli      	r2, r2, 2
  36:	7c84      	mult      	r2, r1
  38:	ea01aae6 	movi      	r1, 43750
  3c:	c4814901 	rotli      	r1, r1, 4
  40:	6048      	addu      	r1, r2
  42:	dc232281 	st.w      	r1, (r3, 0xa04)
  46:	dc232280 	st.w      	r1, (r3, 0xa00)
  4a:	d82309c7 	ld.b      	r1, (r3, 0x9c7)
  4e:	3941      	cmpnei      	r1, 1
  50:	0c7b      	bf      	0x146	// 146 <dsleep_back_to_dsleep+0x146>
  52:	3940      	cmpnei      	r1, 0
  54:	0c8e      	bf      	0x170	// 170 <dsleep_back_to_dsleep+0x170>
  56:	3942      	cmpnei      	r1, 2
  58:	0c67      	bf      	0x126	// 126 <dsleep_back_to_dsleep+0x126>
  5a:	3943      	cmpnei      	r1, 3
  5c:	0810      	bt      	0x7c	// 7c <dsleep_back_to_dsleep+0x7c>
  5e:	d82309c3 	ld.b      	r1, (r3, 0x9c3)
  62:	e4212007 	andi      	r1, r1, 7
  66:	30fa      	movi      	r0, 250
  68:	4003      	lsli      	r0, r0, 3
  6a:	dc2309c3 	st.b      	r1, (r3, 0x9c3)
  6e:	4921      	lsri      	r1, r1, 1
  70:	7c40      	mult      	r1, r0
  72:	021c      	lrw      	r0, 0xaa2a8	// 2fc <dsleep_back_to_dsleep+0x2fc>
  74:	6080      	addu      	r2, r0
  76:	6084      	addu      	r2, r1
  78:	dc432280 	st.w      	r2, (r3, 0xa00)
  7c:	3200      	movi      	r2, 0
  7e:	2a00      	subi      	r2, 1
  80:	dc450128 	st.b      	r2, (r5, 0x128)
  84:	3100      	movi      	r1, 0
  86:	d8430a4e 	ld.b      	r2, (r3, 0xa4e)
  8a:	c4415c00 	ins      	r2, r1, 0, 0
  8e:	dc430a4e 	st.b      	r2, (r3, 0xa4e)
  92:	0303      	lrw      	r0, 0x0	// 300 <dsleep_back_to_dsleep+0x300>
  94:	e0000000 	bsr      	0x0	// 0 <dsleep_back_to_dsleep>
  98:	9562      	ld.w      	r3, (r5, 0x8)
  9a:	d8032281 	ld.w      	r0, (r3, 0xa04)
  9e:	e0000000 	bsr      	0x0	// 0 <dsleep_back_to_dsleep>
  a2:	9502      	ld.w      	r0, (r5, 0x8)
  a4:	8524      	ld.b      	r1, (r5, 0x4)
  a6:	e4212004 	andi      	r1, r1, 4
  aa:	d9a009c6 	ld.b      	r13, (r0, 0x9c6)
  ae:	d840227f 	ld.w      	r2, (r0, 0x9fc)
  b2:	c44d8426 	mult      	r6, r13, r2
  b6:	ea8c0094 	lrw      	r12, 0x0	// 304 <dsleep_back_to_dsleep+0x304>
  ba:	e9010085 	bez      	r1, 0x1c4	// 1c4 <dsleep_back_to_dsleep+0x1c4>
  be:	d8652044 	ld.w      	r3, (r5, 0x110)
  c2:	d885203f 	ld.w      	r4, (r5, 0xfc)
  c6:	5b91      	subu      	r4, r3, r4
  c8:	d86c2000 	ld.w      	r3, (r12, 0x0)
  cc:	9324      	ld.w      	r1, (r3, 0x10)
  ce:	6504      	cmphs      	r1, r4
  d0:	0c53      	bf      	0x176	// 176 <dsleep_back_to_dsleep+0x176>
  d2:	9364      	ld.w      	r3, (r3, 0x10)
  d4:	60d2      	subu      	r3, r4
  d6:	e9060055 	bez      	r6, 0x180	// 180 <dsleep_back_to_dsleep+0x180>
  da:	d8852045 	ld.w      	r4, (r5, 0x114)
  de:	3100      	movi      	r1, 0
  e0:	650c      	cmphs      	r3, r4
  e2:	084c      	bt      	0x17a	// 17a <dsleep_back_to_dsleep+0x17a>
  e4:	e9010004 	bez      	r1, 0xec	// ec <dsleep_back_to_dsleep+0xec>
  e8:	dc852045 	st.w      	r4, (r5, 0x114)
  ec:	5c6d      	subu      	r3, r4, r3
  ee:	4a41      	lsri      	r2, r2, 1
  f0:	5e8c      	addu      	r4, r6, r3
  f2:	648c      	cmphs      	r3, r2
  f4:	c4830c40 	inct      	r4, r3, 0
  f8:	9542      	ld.w      	r2, (r5, 0x8)
  fa:	d865203e 	ld.w      	r3, (r5, 0xf8)
  fe:	d8220a4e 	ld.b      	r1, (r2, 0xa4e)
 102:	e4212040 	andi      	r1, r1, 64
 106:	e46317cf 	subi      	r3, r3, 2000
 10a:	dc65203e 	st.w      	r3, (r5, 0xf8)
 10e:	e9010049 	bez      	r1, 0x1a0	// 1a0 <dsleep_back_to_dsleep+0x1a0>
 112:	eb032edf 	cmphsi      	r3, 12000
 116:	083d      	bt      	0x190	// 190 <dsleep_back_to_dsleep+0x190>
 118:	ea032ee0 	movi      	r3, 12000
 11c:	dc65203e 	st.w      	r3, (r5, 0xf8)
 120:	e9a400bc 	bhsz      	r4, 0x298	// 298 <dsleep_back_to_dsleep+0x298>
 124:	04af      	br      	0x282	// 282 <dsleep_back_to_dsleep+0x282>
 126:	d82309c3 	ld.b      	r1, (r3, 0x9c3)
 12a:	e4212003 	andi      	r1, r1, 3
 12e:	30fa      	movi      	r0, 250
 130:	4003      	lsli      	r0, r0, 3
 132:	dc2309c3 	st.b      	r1, (r3, 0x9c3)
 136:	4921      	lsri      	r1, r1, 1
 138:	7c40      	mult      	r1, r0
 13a:	1314      	lrw      	r0, 0xaaa78	// 308 <dsleep_back_to_dsleep+0x308>
 13c:	6080      	addu      	r2, r0
 13e:	6084      	addu      	r2, r1
 140:	dc432280 	st.w      	r2, (r3, 0xa00)
 144:	079c      	br      	0x7c	// 7c <dsleep_back_to_dsleep+0x7c>
 146:	d8230a4e 	ld.b      	r1, (r3, 0xa4e)
 14a:	e4212040 	andi      	r1, r1, 64
 14e:	e901000a 	bez      	r1, 0x162	// 162 <dsleep_back_to_dsleep+0x162>
 152:	3100      	movi      	r1, 0
 154:	dc2309c3 	st.b      	r1, (r3, 0x9c3)
 158:	132d      	lrw      	r1, 0xab054	// 30c <dsleep_back_to_dsleep+0x30c>
 15a:	6084      	addu      	r2, r1
 15c:	dc432280 	st.w      	r2, (r3, 0xa00)
 160:	078e      	br      	0x7c	// 7c <dsleep_back_to_dsleep+0x7c>
 162:	d84309c3 	ld.b      	r2, (r3, 0x9c3)
 166:	e4422001 	andi      	r2, r2, 1
 16a:	dc4309c3 	st.b      	r2, (r3, 0x9c3)
 16e:	0787      	br      	0x7c	// 7c <dsleep_back_to_dsleep+0x7c>
 170:	dc2309c3 	st.b      	r1, (r3, 0x9c3)
 174:	0784      	br      	0x7c	// 7c <dsleep_back_to_dsleep+0x7c>
 176:	3300      	movi      	r3, 0
 178:	07af      	br      	0xd6	// d6 <dsleep_back_to_dsleep+0xd6>
 17a:	6118      	addu      	r4, r6
 17c:	3101      	movi      	r1, 1
 17e:	07b1      	br      	0xe0	// e0 <dsleep_back_to_dsleep+0xe0>
 180:	1304      	lrw      	r0, 0x0	// 310 <dsleep_back_to_dsleep+0x310>
 182:	e0000000 	bsr      	0x0	// 0 <dsleep_back_to_dsleep>
 186:	ea049c40 	movi      	r4, 40000
 18a:	c5044904 	rotli      	r4, r4, 8
 18e:	07b5      	br      	0xf8	// f8 <dsleep_back_to_dsleep+0xf8>
 190:	eb033a98 	cmphsi      	r3, 15001
 194:	0fc6      	bf      	0x120	// 120 <dsleep_back_to_dsleep+0x120>
 196:	ea033a98 	movi      	r3, 15000
 19a:	dc65203e 	st.w      	r3, (r5, 0xf8)
 19e:	07c1      	br      	0x120	// 120 <dsleep_back_to_dsleep+0x120>
 1a0:	eb030bb7 	cmphsi      	r3, 3000
 1a4:	0808      	bt      	0x1b4	// 1b4 <dsleep_back_to_dsleep+0x1b4>
 1a6:	ea030bb8 	movi      	r3, 3000
 1aa:	dc65203e 	st.w      	r3, (r5, 0xf8)
 1ae:	e9a40077 	bhsz      	r4, 0x29c	// 29c <dsleep_back_to_dsleep+0x29c>
 1b2:	0468      	br      	0x282	// 282 <dsleep_back_to_dsleep+0x282>
 1b4:	eb037530 	cmphsi      	r3, 30001
 1b8:	0ffb      	bf      	0x1ae	// 1ae <dsleep_back_to_dsleep+0x1ae>
 1ba:	ea037530 	movi      	r3, 30000
 1be:	dc65203e 	st.w      	r3, (r5, 0xf8)
 1c2:	07f6      	br      	0x1ae	// 1ae <dsleep_back_to_dsleep+0x1ae>
 1c4:	d86c2000 	ld.w      	r3, (r12, 0x0)
 1c8:	d985203c 	ld.w      	r12, (r5, 0xf0)
 1cc:	9384      	ld.w      	r4, (r3, 0x10)
 1ce:	d8600a4e 	ld.b      	r3, (r0, 0xa4e)
 1d2:	e46320fe 	andi      	r3, r3, 254
 1d6:	c4615c01 	ins      	r3, r1, 1, 1
 1da:	5ef1      	subu      	r7, r6, r4
 1dc:	dc600a4e 	st.b      	r3, (r0, 0xa4e)
 1e0:	e90c00a4 	bez      	r12, 0x328	// 328 <dsleep_back_to_dsleep+0x328>
 1e4:	3415      	movi      	r4, 21
 1e6:	e42c1000 	subi      	r1, r12, 1
 1ea:	c4818023 	divu      	r3, r1, r4
 1ee:	7cd0      	mult      	r3, r4
 1f0:	604e      	subu      	r1, r3
 1f2:	2100      	addi      	r1, 1
 1f4:	e4612001 	andi      	r3, r1, 1
 1f8:	3400      	movi      	r4, 0
 1fa:	3b40      	cmpnei      	r3, 0
 1fc:	2c00      	subi      	r4, 1
 1fe:	3301      	movi      	r3, 1
 200:	c4640c40 	inct      	r3, r4, 0
 204:	3955      	cmpnei      	r1, 21
 206:	0c8d      	bf      	0x320	// 320 <dsleep_back_to_dsleep+0x320>
 208:	412a      	lsli      	r1, r1, 10
 20a:	7cc4      	mult      	r3, r1
 20c:	3403      	movi      	r4, 3
 20e:	7d0c      	mult      	r4, r3
 210:	31fa      	movi      	r1, 250
 212:	4a6a      	lsri      	r3, r2, 10
 214:	7f4c      	mult      	r13, r3
 216:	e58c0000 	addi      	r12, r12, 1
 21a:	8867      	ld.h      	r3, (r0, 0xe)
 21c:	4122      	lsli      	r1, r1, 2
 21e:	7f34      	mult      	r12, r13
 220:	7cc4      	mult      	r3, r1
 222:	64f0      	cmphs      	r12, r3
 224:	611c      	addu      	r4, r7
 226:	0c83      	bf      	0x32c	// 32c <dsleep_back_to_dsleep+0x32c>
 228:	ea032710 	movi      	r3, 10000
 22c:	608c      	addu      	r2, r3
 22e:	6088      	addu      	r2, r2
 230:	ea078003 	movi      	r7, 32771
 234:	c5e74907 	rotli      	r7, r7, 15
 238:	dc45203e 	st.w      	r2, (r5, 0xf8)
 23c:	d8272023 	ld.w      	r1, (r7, 0x8c)
 240:	ea03ffc0 	movi      	r3, 65472
 244:	c6234903 	rotli      	r3, r3, 17
 248:	684c      	and      	r1, r3
 24a:	c6a05023 	bmaski      	r3, 22
 24e:	2b00      	subi      	r3, 1
 250:	6c4c      	or      	r1, r3
 252:	308c      	movi      	r0, 140
 254:	e0000000 	bsr      	0x0	// 0 <dsleep_back_to_dsleep>
 258:	d8272023 	ld.w      	r1, (r7, 0x8c)
 25c:	ec210001 	ori      	r1, r1, 1
 260:	308c      	movi      	r0, 140
 262:	e0000000 	bsr      	0x0	// 0 <dsleep_back_to_dsleep>
 266:	d8672023 	ld.w      	r3, (r7, 0x8c)
 26a:	e4632001 	andi      	r3, r3, 1
 26e:	e923fffc 	bnez      	r3, 0x266	// 266 <dsleep_back_to_dsleep+0x266>
 272:	d8672021 	ld.w      	r3, (r7, 0x84)
 276:	dc652043 	st.w      	r3, (r5, 0x10c)
 27a:	1167      	lrw      	r3, 0xfffe7960	// 314 <dsleep_back_to_dsleep+0x314>
 27c:	610c      	addu      	r4, r3
 27e:	e9a40006 	bhsz      	r4, 0x28a	// 28a <dsleep_back_to_dsleep+0x28a>
 282:	1106      	lrw      	r0, 0x0	// 318 <dsleep_back_to_dsleep+0x318>
 284:	e0000000 	bsr      	0x0	// 0 <dsleep_back_to_dsleep>
 288:	6d1b      	mov      	r4, r6
 28a:	9542      	ld.w      	r2, (r5, 0x8)
 28c:	d8620a4e 	ld.b      	r3, (r2, 0xa4e)
 290:	e4632040 	andi      	r3, r3, 64
 294:	e9030004 	bez      	r3, 0x29c	// 29c <dsleep_back_to_dsleep+0x29c>
 298:	e48413e7 	subi      	r4, r4, 1000
 29c:	d862231b 	ld.w      	r3, (r2, 0xc6c)
 2a0:	e9030013 	bez      	r3, 0x2c6	// 2c6 <dsleep_back_to_dsleep+0x2c6>
 2a4:	60d2      	subu      	r3, r4
 2a6:	dc62231b 	st.w      	r3, (r2, 0xc6c)
 2aa:	e943000e 	bhz      	r3, 0x2c6	// 2c6 <dsleep_back_to_dsleep+0x2c6>
 2ae:	3301      	movi      	r3, 1
 2b0:	8524      	ld.b      	r1, (r5, 0x4)
 2b2:	c4235c01 	ins      	r1, r3, 1, 1
 2b6:	dc620257 	st.b      	r3, (r2, 0x257)
 2ba:	1019      	lrw      	r0, 0x0	// 31c <dsleep_back_to_dsleep+0x31c>
 2bc:	a524      	st.b      	r1, (r5, 0x4)
 2be:	e0000000 	bsr      	0x0	// 0 <dsleep_back_to_dsleep>
 2c2:	e0000000 	bsr      	0x0	// 0 <dsleep_back_to_dsleep>
 2c6:	8566      	ld.b      	r3, (r5, 0x6)
 2c8:	e4632008 	andi      	r3, r3, 8
 2cc:	e9030005 	bez      	r3, 0x2d6	// 2d6 <dsleep_back_to_dsleep+0x2d6>
 2d0:	9562      	ld.w      	r3, (r5, 0x8)
 2d2:	d88320af 	ld.w      	r4, (r3, 0x2bc)
 2d6:	6c13      	mov      	r0, r4
 2d8:	e0000000 	bsr      	0x0	// 0 <dsleep_back_to_dsleep>
 2dc:	ea038003 	movi      	r3, 32771
 2e0:	c5e34903 	rotli      	r3, r3, 15
 2e4:	30a0      	movi      	r0, 160
 2e6:	d8232028 	ld.w      	r1, (r3, 0xa0)
 2ea:	ec210001 	ori      	r1, r1, 1
 2ee:	e0000000 	bsr      	0x0	// 0 <dsleep_back_to_dsleep>
 2f2:	e0000000 	bsr      	0x0	// 0 <dsleep_back_to_dsleep>
 2f6:	1494      	pop      	r4-r7, r15
 2f8:	00000000 	.long	0x00000000
 2fc:	000aa2a8 	.long	0x000aa2a8
	...
 308:	000aaa78 	.long	0x000aaa78
 30c:	000ab054 	.long	0x000ab054
 310:	00000000 	.long	0x00000000
 314:	fffe7960 	.long	0xfffe7960
	...
 320:	34a8      	movi      	r4, 168
 322:	4486      	lsli      	r4, r4, 6
 324:	7cd0      	mult      	r3, r4
 326:	0773      	br      	0x20c	// 20c <dsleep_back_to_dsleep+0x20c>
 328:	6cf3      	mov      	r3, r12
 32a:	0771      	br      	0x20c	// 20c <dsleep_back_to_dsleep+0x20c>
 32c:	d8600a4e 	ld.b      	r3, (r0, 0xa4e)
 330:	e4632040 	andi      	r3, r3, 64
 334:	3b40      	cmpnei      	r3, 0
 336:	ea023a98 	movi      	r2, 15000
 33a:	ea037530 	movi      	r3, 30000
 33e:	c4620c40 	inct      	r3, r2, 0
 342:	dc65203e 	st.w      	r3, (r5, 0xf8)
 346:	079c      	br      	0x27e	// 27e <dsleep_back_to_dsleep+0x27e>

Disassembly of section .text.dsleep_wakeup_exit:

00000000 <dsleep_wakeup_exit>:
   0:	14d2      	push      	r4-r5, r15
   2:	118a      	lrw      	r4, 0x0	// a8 <dsleep_wakeup_exit+0xa8>
   4:	8445      	ld.b      	r2, (r4, 0x5)
   6:	e4622010 	andi      	r3, r2, 16
   a:	e9230016 	bnez      	r3, 0x36	// 36 <dsleep_wakeup_exit+0x36>
   e:	9422      	ld.w      	r1, (r4, 0x8)
  10:	d861227f 	ld.w      	r3, (r1, 0x9fc)
  14:	d80109c6 	ld.b      	r0, (r1, 0x9c6)
  18:	4b6a      	lsri      	r3, r3, 10
  1a:	7cc0      	mult      	r3, r0
  1c:	d804203c 	ld.w      	r0, (r4, 0xf0)
  20:	7cc0      	mult      	r3, r0
  22:	30fa      	movi      	r0, 250
  24:	8927      	ld.h      	r1, (r1, 0xe)
  26:	4002      	lsli      	r0, r0, 2
  28:	7c40      	mult      	r1, r0
  2a:	644c      	cmphs      	r3, r1
  2c:	0805      	bt      	0x36	// 36 <dsleep_wakeup_exit+0x36>
  2e:	d864203a 	ld.w      	r3, (r4, 0xe8)
  32:	3b06      	cmphsi      	r3, 7
  34:	0c06      	bf      	0x40	// 40 <dsleep_wakeup_exit+0x40>
  36:	8466      	ld.b      	r3, (r4, 0x6)
  38:	3100      	movi      	r1, 0
  3a:	c4615c01 	ins      	r3, r1, 1, 1
  3e:	a466      	st.b      	r3, (r4, 0x6)
  40:	8464      	ld.b      	r3, (r4, 0x4)
  42:	e4632002 	andi      	r3, r3, 2
  46:	e923000c 	bnez      	r3, 0x5e	// 5e <dsleep_wakeup_exit+0x5e>
  4a:	ea038003 	movi      	r3, 32771
  4e:	c5e34903 	rotli      	r3, r3, 15
  52:	d8032028 	ld.w      	r0, (r3, 0xa0)
  56:	e4002100 	andi      	r0, r0, 256
  5a:	e9000020 	bez      	r0, 0x9a	// 9a <dsleep_wakeup_exit+0x9a>
  5e:	ea058003 	movi      	r5, 32771
  62:	c5e54905 	rotli      	r5, r5, 15
  66:	d8652028 	ld.w      	r3, (r5, 0xa0)
  6a:	e4632100 	andi      	r3, r3, 256
  6e:	e903000f 	bez      	r3, 0x8c	// 8c <dsleep_wakeup_exit+0x8c>
  72:	100f      	lrw      	r0, 0x0	// ac <dsleep_wakeup_exit+0xac>
  74:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup_exit>
  78:	d8252028 	ld.w      	r1, (r5, 0xa0)
  7c:	39b0      	bseti      	r1, 16
  7e:	30a0      	movi      	r0, 160
  80:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup_exit>
  84:	9462      	ld.w      	r3, (r4, 0x8)
  86:	3204      	movi      	r2, 4
  88:	dc430257 	st.b      	r2, (r3, 0x257)
  8c:	8464      	ld.b      	r3, (r4, 0x4)
  8e:	3200      	movi      	r2, 0
  90:	c4625c01 	ins      	r3, r2, 1, 1
  94:	a464      	st.b      	r3, (r4, 0x4)
  96:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup_exit>
  9a:	e4422004 	andi      	r2, r2, 4
  9e:	e9020004 	bez      	r2, 0xa6	// a6 <dsleep_wakeup_exit+0xa6>
  a2:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup_exit>
  a6:	1492      	pop      	r4-r5, r15
	...

Disassembly of section .text.dsleep_sys_pll_close:

00000000 <dsleep_sys_pll_close>:
   0:	106e      	lrw      	r3, 0x40026000	// 38 <dsleep_sys_pll_close+0x38>
   2:	104f      	lrw      	r2, 0x3fac87e4	// 3c <dsleep_sys_pll_close+0x3c>
   4:	b34b      	st.w      	r2, (r3, 0x2c)
   6:	31ff      	movi      	r1, 255
   8:	9344      	ld.w      	r2, (r3, 0x10)
   a:	4138      	lsli      	r1, r1, 24
   c:	6884      	and      	r2, r1
   e:	b344      	st.w      	r2, (r3, 0x10)
  10:	9350      	ld.w      	r2, (r3, 0x40)
  12:	3a9a      	bclri      	r2, 26
  14:	b350      	st.w      	r2, (r3, 0x40)
  16:	3100      	movi      	r1, 0
  18:	9343      	ld.w      	r2, (r3, 0xc)
  1a:	29c3      	subi      	r1, 196
  1c:	6884      	and      	r2, r1
  1e:	ec420001 	ori      	r2, r2, 1
  22:	b343      	st.w      	r2, (r3, 0xc)
  24:	9354      	ld.w      	r2, (r3, 0x50)
  26:	3a80      	bclri      	r2, 0
  28:	b354      	st.w      	r2, (r3, 0x50)
  2a:	ea02f424 	movi      	r2, 62500
  2e:	c5224902 	rotli      	r2, r2, 9
  32:	1064      	lrw      	r3, 0x0	// 40 <dsleep_sys_pll_close+0x40>
  34:	b340      	st.w      	r2, (r3, 0x0)
  36:	783c      	jmp      	r15
  38:	6000      	.short	0x6000
  3a:	4002      	.short	0x4002
  3c:	87e4      	.short	0x87e4
  3e:	3fac      	.short	0x3fac
  40:	00000000 	.long	0x00000000

Disassembly of section .text.dsleep_cfg_txvec_part2:

00000000 <dsleep_cfg_txvec_part2>:
   0:	1046      	lrw      	r2, 0x0	// 18 <dsleep_cfg_txvec_part2+0x18>
   2:	1067      	lrw      	r3, 0x0	// 1c <dsleep_cfg_txvec_part2+0x1c>
   4:	9255      	ld.w      	r2, (r2, 0x54)
   6:	9360      	ld.w      	r3, (r3, 0x0)
   8:	9221      	ld.w      	r1, (r2, 0x4)
   a:	b33a      	st.w      	r1, (r3, 0x68)
   c:	9222      	ld.w      	r1, (r2, 0x8)
   e:	b33b      	st.w      	r1, (r3, 0x6c)
  10:	9243      	ld.w      	r2, (r2, 0xc)
  12:	b35c      	st.w      	r2, (r3, 0x70)
  14:	783c      	jmp      	r15
	...

Disassembly of section .text.dsleep_cca_start:

00000000 <dsleep_cca_start>:
   0:	14d3      	push      	r4-r6, r15
   2:	114e      	lrw      	r2, 0x40026000	// b8 <dsleep_cca_start+0xb8>
   4:	118e      	lrw      	r4, 0x0	// bc <dsleep_cca_start+0xbc>
   6:	9265      	ld.w      	r3, (r2, 0x14)
   8:	3bbc      	bseti      	r3, 28
   a:	b265      	st.w      	r3, (r2, 0x14)
   c:	e0000000 	bsr      	0x0	// 0 <sysctrl_dac_init>
  10:	e0000000 	bsr      	0x0	// 0 <dsleep_cca_start>
  14:	3000      	movi      	r0, 0
  16:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
  1a:	116a      	lrw      	r3, 0x0	// c0 <dsleep_cca_start+0xc0>
  1c:	9440      	ld.w      	r2, (r4, 0x0)
  1e:	9335      	ld.w      	r1, (r3, 0x54)
  20:	9307      	ld.w      	r0, (r3, 0x1c)
  22:	9120      	ld.w      	r1, (r1, 0x0)
  24:	b239      	st.w      	r1, (r2, 0x64)
  26:	9322      	ld.w      	r1, (r3, 0x8)
  28:	d9802004 	ld.w      	r12, (r0, 0x10)
  2c:	d82114e2 	ld.h      	r1, (r1, 0x9c4)
  30:	8366      	ld.b      	r3, (r3, 0x6)
  32:	6070      	addu      	r1, r12
  34:	e4632008 	andi      	r3, r3, 8
  38:	b02f      	st.w      	r1, (r0, 0x3c)
  3a:	922f      	ld.w      	r1, (r2, 0x3c)
  3c:	e9030021 	bez      	r3, 0x7e	// 7e <dsleep_cca_start+0x7e>
  40:	e421201f 	andi      	r1, r1, 31
  44:	2101      	addi      	r1, 2
  46:	7445      	zexth      	r1, r1
  48:	3002      	movi      	r0, 2
  4a:	3680      	movi      	r6, 128
  4c:	e0000000 	bsr      	0x0	// 0 <lhw_start_cca>
  50:	46c3      	lsli      	r6, r6, 3
  52:	9460      	ld.w      	r3, (r4, 0x0)
  54:	930d      	ld.w      	r0, (r3, 0x34)
  56:	c5005540 	zext      	r0, r0, 10, 8
  5a:	e9200019 	bnez      	r0, 0x8c	// 8c <dsleep_cca_start+0x8c>
  5e:	934d      	ld.w      	r2, (r3, 0x34)
  60:	c7025742 	zext      	r2, r2, 26, 24
  64:	3a41      	cmpnei      	r2, 1
  66:	0813      	bt      	0x8c	// 8c <dsleep_cca_start+0x8c>
  68:	e0000000 	bsr      	0x0	// 0 <lhw_start_tx>
  6c:	9460      	ld.w      	r3, (r4, 0x0)
  6e:	93b2      	ld.w      	r5, (r3, 0x48)
  70:	e4a52020 	andi      	r5, r5, 32
  74:	e905001c 	bez      	r5, 0xac	// ac <dsleep_cca_start+0xac>
  78:	3220      	movi      	r2, 32
  7a:	b352      	st.w      	r2, (r3, 0x48)
  7c:	1493      	pop      	r4-r6, r15
  7e:	323f      	movi      	r2, 63
  80:	c4418023 	divu      	r3, r1, r2
  84:	7cc8      	mult      	r3, r2
  86:	604e      	subu      	r1, r3
  88:	2101      	addi      	r1, 2
  8a:	07de      	br      	0x46	// 46 <dsleep_cca_start+0x46>
  8c:	9352      	ld.w      	r2, (r3, 0x48)
  8e:	e4422400 	andi      	r2, r2, 1024
  92:	e902ffe0 	bez      	r2, 0x52	// 52 <dsleep_cca_start+0x52>
  96:	b3d2      	st.w      	r6, (r3, 0x48)
  98:	e0000000 	bsr      	0x0	// 0 <dsleep_cca_start>
  9c:	3096      	movi      	r0, 150
  9e:	4002      	lsli      	r0, r0, 2
  a0:	e0000000 	bsr      	0x0	// 0 <delay_us>
  a4:	3000      	movi      	r0, 0
  a6:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
  aa:	07d4      	br      	0x52	// 52 <dsleep_cca_start+0x52>
  ac:	9352      	ld.w      	r2, (r3, 0x48)
  ae:	e4422400 	andi      	r2, r2, 1024
  b2:	e902ffde 	bez      	r2, 0x6e	// 6e <dsleep_cca_start+0x6e>
  b6:	07f0      	br      	0x96	// 96 <dsleep_cca_start+0x96>
  b8:	40026000 	.long	0x40026000
	...

Disassembly of section .text.dsleep_bo_fns:

00000000 <dsleep_bo_fns>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d07      	mov      	r4, r1
   4:	6d43      	mov      	r5, r0
   6:	3001      	movi      	r0, 1
   8:	e0000000 	bsr      	0x0	// 0 <lhw_cfg_dma_list_cnt>
   c:	6c93      	mov      	r2, r4
   e:	6c57      	mov      	r1, r5
  10:	3000      	movi      	r0, 0
  12:	e0000000 	bsr      	0x0	// 0 <lhw_cfg_tx_sub_frm>
  16:	1067      	lrw      	r3, 0x0	// 30 <dsleep_bo_fns+0x30>
  18:	2403      	addi      	r4, 4
  1a:	9360      	ld.w      	r3, (r3, 0x0)
  1c:	b39f      	st.w      	r4, (r3, 0x7c)
  1e:	9356      	ld.w      	r2, (r3, 0x58)
  20:	3a80      	bclri      	r2, 0
  22:	b356      	st.w      	r2, (r3, 0x58)
  24:	9356      	ld.w      	r2, (r3, 0x58)
  26:	b356      	st.w      	r2, (r3, 0x58)
  28:	e0000000 	bsr      	0x0	// 0 <dsleep_bo_fns>
  2c:	1492      	pop      	r4-r5, r15
  2e:	0000      	.short	0x0000
  30:	00000000 	.long	0x00000000

Disassembly of section .text.dsleep_tx_end:

00000000 <dsleep_tx_end>:
   0:	14d1      	push      	r4, r15
   2:	1098      	lrw      	r4, 0x0	// 60 <dsleep_tx_end+0x60>
   4:	9440      	ld.w      	r2, (r4, 0x0)
   6:	9272      	ld.w      	r3, (r2, 0x48)
   8:	e4632004 	andi      	r3, r3, 4
   c:	e903fffd 	bez      	r3, 0x6	// 6 <dsleep_tx_end+0x6>
  10:	3304      	movi      	r3, 4
  12:	b272      	st.w      	r3, (r2, 0x48)
  14:	e0000000 	bsr      	0x0	// 0 <dsleep_tx_end>
  18:	9460      	ld.w      	r3, (r4, 0x0)
  1a:	937d      	ld.w      	r3, (r3, 0x74)
  1c:	e4632003 	andi      	r3, r3, 3
  20:	e903001e 	bez      	r3, 0x5c	// 5c <dsleep_tx_end+0x5c>
  24:	1010      	lrw      	r0, 0x0	// 64 <dsleep_tx_end+0x64>
  26:	e0000000 	bsr      	0x0	// 0 <dsleep_tx_end>
  2a:	1070      	lrw      	r3, 0x0	// 68 <dsleep_tx_end+0x68>
  2c:	9368      	ld.w      	r3, (r3, 0x20)
  2e:	9304      	ld.w      	r0, (r3, 0x10)
  30:	e0000000 	bsr      	0x0	// 0 <dsleep_tx_end>
  34:	9460      	ld.w      	r3, (r4, 0x0)
  36:	931d      	ld.w      	r0, (r3, 0x74)
  38:	e0000000 	bsr      	0x0	// 0 <dsleep_tx_end>
  3c:	9460      	ld.w      	r3, (r4, 0x0)
  3e:	9319      	ld.w      	r0, (r3, 0x64)
  40:	e0000000 	bsr      	0x0	// 0 <dsleep_tx_end>
  44:	9460      	ld.w      	r3, (r4, 0x0)
  46:	931a      	ld.w      	r0, (r3, 0x68)
  48:	e0000000 	bsr      	0x0	// 0 <dsleep_tx_end>
  4c:	9460      	ld.w      	r3, (r4, 0x0)
  4e:	931b      	ld.w      	r0, (r3, 0x6c)
  50:	e0000000 	bsr      	0x0	// 0 <dsleep_tx_end>
  54:	9460      	ld.w      	r3, (r4, 0x0)
  56:	931c      	ld.w      	r0, (r3, 0x70)
  58:	e0000000 	bsr      	0x0	// 0 <dsleep_tx_end>
  5c:	1491      	pop      	r4, r15
	...

Disassembly of section .text.dsleep_wait_ack:

00000000 <dsleep_wait_ack>:
   0:	14d2      	push      	r4-r5, r15
   2:	1194      	lrw      	r4, 0x0	// d0 <dsleep_wait_ack+0xd0>
   4:	e0000000 	bsr      	0x0	// 0 <dsleep_wait_ack>
   8:	9462      	ld.w      	r3, (r4, 0x8)
   a:	31a0      	movi      	r1, 160
   c:	d8030a4e 	ld.b      	r0, (r3, 0xa4e)
  10:	11b1      	lrw      	r5, 0x0	// d4 <dsleep_wait_ack+0xd4>
  12:	e4002040 	andi      	r0, r0, 64
  16:	33fa      	movi      	r3, 250
  18:	9540      	ld.w      	r2, (r5, 0x0)
  1a:	3840      	cmpnei      	r0, 0
  1c:	4122      	lsli      	r1, r1, 2
  1e:	4363      	lsli      	r3, r3, 3
  20:	c4610c20 	incf      	r3, r1, 0
  24:	dc622031 	st.w      	r3, (r2, 0xc4)
  28:	d8622033 	ld.w      	r3, (r2, 0xcc)
  2c:	ec630004 	ori      	r3, r3, 4
  30:	dc622033 	st.w      	r3, (r2, 0xcc)
  34:	3380      	movi      	r3, 128
  36:	4363      	lsli      	r3, r3, 3
  38:	b272      	st.w      	r3, (r2, 0x48)
  3a:	3000      	movi      	r0, 0
  3c:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
  40:	9540      	ld.w      	r2, (r5, 0x0)
  42:	d8622031 	ld.w      	r3, (r2, 0xc4)
  46:	e9230008 	bnez      	r3, 0x56	// 56 <dsleep_wait_ack+0x56>
  4a:	1104      	lrw      	r0, 0x0	// d8 <dsleep_wait_ack+0xd8>
  4c:	3400      	movi      	r4, 0
  4e:	e0000000 	bsr      	0x0	// 0 <dsleep_wait_ack>
  52:	2c00      	subi      	r4, 1
  54:	0436      	br      	0xc0	// c0 <dsleep_wait_ack+0xc0>
  56:	9272      	ld.w      	r3, (r2, 0x48)
  58:	e4632400 	andi      	r3, r3, 1024
  5c:	e903fff3 	bez      	r3, 0x42	// 42 <dsleep_wait_ack+0x42>
  60:	3380      	movi      	r3, 128
  62:	4363      	lsli      	r3, r3, 3
  64:	b272      	st.w      	r3, (r2, 0x48)
  66:	3180      	movi      	r1, 128
  68:	d8622108 	ld.w      	r3, (r2, 0x420)
  6c:	4127      	lsli      	r1, r1, 7
  6e:	d8422109 	ld.w      	r2, (r2, 0x424)
  72:	6884      	and      	r2, r1
  74:	e922ffeb 	bnez      	r2, 0x4a	// 4a <dsleep_wait_ack+0x4a>
  78:	9442      	ld.w      	r2, (r4, 0x8)
  7a:	8304      	ld.b      	r0, (r3, 0x4)
  7c:	d82209f6 	ld.b      	r1, (r2, 0x9f6)
  80:	6442      	cmpne      	r0, r1
  82:	0be4      	bt      	0x4a	// 4a <dsleep_wait_ack+0x4a>
  84:	8305      	ld.b      	r0, (r3, 0x5)
  86:	d82209f7 	ld.b      	r1, (r2, 0x9f7)
  8a:	6442      	cmpne      	r0, r1
  8c:	0bdf      	bt      	0x4a	// 4a <dsleep_wait_ack+0x4a>
  8e:	8306      	ld.b      	r0, (r3, 0x6)
  90:	d82209f8 	ld.b      	r1, (r2, 0x9f8)
  94:	6442      	cmpne      	r0, r1
  96:	0bda      	bt      	0x4a	// 4a <dsleep_wait_ack+0x4a>
  98:	8307      	ld.b      	r0, (r3, 0x7)
  9a:	d82209f9 	ld.b      	r1, (r2, 0x9f9)
  9e:	6442      	cmpne      	r0, r1
  a0:	0bd5      	bt      	0x4a	// 4a <dsleep_wait_ack+0x4a>
  a2:	8308      	ld.b      	r0, (r3, 0x8)
  a4:	d82209fa 	ld.b      	r1, (r2, 0x9fa)
  a8:	6442      	cmpne      	r0, r1
  aa:	0bd0      	bt      	0x4a	// 4a <dsleep_wait_ack+0x4a>
  ac:	8329      	ld.b      	r1, (r3, 0x9)
  ae:	d84209fb 	ld.b      	r2, (r2, 0x9fb)
  b2:	6486      	cmpne      	r1, r2
  b4:	0bcb      	bt      	0x4a	// 4a <dsleep_wait_ack+0x4a>
  b6:	836a      	ld.b      	r3, (r3, 0xa)
  b8:	eb4300d4 	cmpnei      	r3, 212
  bc:	0bc7      	bt      	0x4a	// 4a <dsleep_wait_ack+0x4a>
  be:	3400      	movi      	r4, 0
  c0:	e0000000 	bsr      	0x0	// 0 <dsleep_wait_ack>
  c4:	3000      	movi      	r0, 0
  c6:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
  ca:	6c13      	mov      	r0, r4
  cc:	1492      	pop      	r4-r5, r15
	...

Disassembly of section .text.dsleep_vs_element_rx:

00000000 <dsleep_vs_element_rx>:
   0:	14d1      	push      	r4, r15
   2:	8062      	ld.b      	r3, (r0, 0x2)
   4:	e9230066 	bnez      	r3, 0xd0	// d0 <dsleep_vs_element_rx+0xd0>
   8:	8063      	ld.b      	r3, (r0, 0x3)
   a:	eb430040 	cmpnei      	r3, 64
   e:	0861      	bt      	0xd0	// d0 <dsleep_vs_element_rx+0xd0>
  10:	8064      	ld.b      	r3, (r0, 0x4)
  12:	3b41      	cmpnei      	r3, 1
  14:	085e      	bt      	0xd0	// d0 <dsleep_vs_element_rx+0xd0>
  16:	8067      	ld.b      	r3, (r0, 0x7)
  18:	3b44      	cmpnei      	r3, 4
  1a:	085b      	bt      	0xd0	// d0 <dsleep_vs_element_rx+0xd0>
  1c:	1174      	lrw      	r3, 0x0	// ec <dsleep_vs_element_rx+0xec>
  1e:	583e      	addi      	r1, r0, 8
  20:	d9832045 	ld.w      	r12, (r3, 0x114)
  24:	d9a10004 	ld.b      	r13, (r1, 0x4)
  28:	6334      	addu      	r12, r13
  2a:	dd832045 	st.w      	r12, (r3, 0x114)
  2e:	d9830006 	ld.b      	r12, (r3, 0x6)
  32:	e58c2005 	andi      	r12, r12, 5
  36:	9342      	ld.w      	r2, (r3, 0x8)
  38:	eb4c0004 	cmpnei      	r12, 4
  3c:	d84214e2 	ld.h      	r2, (r2, 0x9c4)
  40:	0822      	bt      	0x84	// 84 <dsleep_vs_element_rx+0x84>
  42:	d983203f 	ld.w      	r12, (r3, 0xfc)
  46:	d8832044 	ld.w      	r4, (r3, 0x110)
  4a:	d9a00009 	ld.b      	r13, (r0, 0x9)
  4e:	6132      	subu      	r4, r12
  50:	c50d482d 	lsli      	r13, r13, 8
  54:	d9800008 	ld.b      	r12, (r0, 0x8)
  58:	6f34      	or      	r12, r13
  5a:	d9a0000a 	ld.b      	r13, (r0, 0xa)
  5e:	c60d482d 	lsli      	r13, r13, 16
  62:	6f70      	or      	r13, r12
  64:	d980000b 	ld.b      	r12, (r0, 0xb)
  68:	c70c482c 	lsli      	r12, r12, 24
  6c:	6f34      	or      	r12, r13
  6e:	c584008c 	subu      	r12, r4, r12
  72:	eb2c01f4 	cmplti      	r12, 501
  76:	082e      	bt      	0xd2	// d2 <dsleep_vs_element_rx+0xd2>
  78:	d9832043 	ld.w      	r12, (r3, 0x10c)
  7c:	e58c0000 	addi      	r12, r12, 1
  80:	dd832043 	st.w      	r12, (r3, 0x10c)
  84:	8001      	ld.b      	r0, (r0, 0x1)
  86:	380e      	cmphsi      	r0, 15
  88:	0c24      	bf      	0xd0	// d0 <dsleep_vs_element_rx+0xd0>
  8a:	ea003fff 	movi      	r0, 16383
  8e:	8186      	ld.b      	r4, (r1, 0x6)
  90:	6808      	and      	r0, r2
  92:	4488      	lsli      	r4, r4, 8
  94:	8145      	ld.b      	r2, (r1, 0x5)
  96:	6108      	addu      	r4, r2
  98:	8147      	ld.b      	r2, (r1, 0x7)
  9a:	4250      	lsli      	r2, r2, 16
  9c:	6108      	addu      	r4, r2
  9e:	381f      	cmphsi      	r0, 32
  a0:	8148      	ld.b      	r2, (r1, 0x8)
  a2:	4258      	lsli      	r2, r2, 24
  a4:	6108      	addu      	r4, r2
  a6:	080a      	bt      	0xba	// ba <dsleep_vs_element_rx+0xba>
  a8:	3201      	movi      	r2, 1
  aa:	7080      	lsl      	r2, r0
  ac:	6890      	and      	r2, r4
  ae:	e9220006 	bnez      	r2, 0xba	// ba <dsleep_vs_element_rx+0xba>
  b2:	8326      	ld.b      	r1, (r3, 0x6)
  b4:	c4225c01 	ins      	r1, r2, 1, 1
  b8:	a326      	st.b      	r1, (r3, 0x6)
  ba:	8364      	ld.b      	r3, (r3, 0x4)
  bc:	e4632002 	andi      	r3, r3, 2
  c0:	e9030008 	bez      	r3, 0xd0	// d0 <dsleep_vs_element_rx+0xd0>
  c4:	100b      	lrw      	r0, 0x0	// f0 <dsleep_vs_element_rx+0xf0>
  c6:	e0000000 	bsr      	0x0	// 0 <dsleep_vs_element_rx>
  ca:	6c13      	mov      	r0, r4
  cc:	e0000000 	bsr      	0x0	// 0 <dsleep_vs_element_rx>
  d0:	1491      	pop      	r4, r15
  d2:	ea0d01f3 	movi      	r13, 499
  d6:	6f76      	nor      	r13, r13
  d8:	6771      	cmplt      	r12, r13
  da:	0fd5      	bf      	0x84	// 84 <dsleep_vs_element_rx+0x84>
  dc:	d9832043 	ld.w      	r12, (r3, 0x10c)
  e0:	e58c1000 	subi      	r12, r12, 1
  e4:	dd832043 	st.w      	r12, (r3, 0x10c)
  e8:	07ce      	br      	0x84	// 84 <dsleep_vs_element_rx+0x84>
	...

Disassembly of section .text.dsleep_wakeup:

00000000 <dsleep_wakeup>:
       0:	14d8      	push      	r4-r11, r15
       2:	1429      	subi      	r14, r14, 36
       4:	ea048003 	movi      	r4, 32771
       8:	c5e44904 	rotli      	r4, r4, 15
       c:	9467      	ld.w      	r3, (r4, 0x1c)
       e:	e4632080 	andi      	r3, r3, 128
      12:	e9030bdc 	bez      	r3, 0x17ca	// 17ca <dsleep_wakeup+0x17ca>
      16:	ea87013b 	lrw      	r7, 0x0	// 500 <dsleep_wakeup+0x500>
      1a:	33fa      	movi      	r3, 250
      1c:	436a      	lsli      	r3, r3, 10
      1e:	b760      	st.w      	r3, (r7, 0x0)
      20:	ea830139 	lrw      	r3, 0x40026000	// 504 <dsleep_wakeup+0x504>
      24:	ea820139 	lrw      	r2, 0x3fac87e4	// 508 <dsleep_wakeup+0x508>
      28:	b34b      	st.w      	r2, (r3, 0x2c)
      2a:	3101      	movi      	r1, 1
      2c:	30b0      	movi      	r0, 176
      2e:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
      32:	d8242028 	ld.w      	r1, (r4, 0xa0)
      36:	ec210001 	ori      	r1, r1, 1
      3a:	30a0      	movi      	r0, 160
      3c:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
      40:	946d      	ld.w      	r3, (r4, 0x34)
      42:	e4632001 	andi      	r3, r3, 1
      46:	e9030007 	bez      	r3, 0x54	// 54 <dsleep_wakeup+0x54>
      4a:	3180      	movi      	r1, 128
      4c:	4131      	lsli      	r1, r1, 17
      4e:	3034      	movi      	r0, 52
      50:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
      54:	ea058003 	movi      	r5, 32771
      58:	c5e54905 	rotli      	r5, r5, 15
      5c:	301c      	movi      	r0, 28
      5e:	9527      	ld.w      	r1, (r5, 0x1c)
      60:	3987      	bclri      	r1, 7
      62:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
      66:	33e0      	movi      	r3, 224
      68:	95c7      	ld.w      	r6, (r5, 0x1c)
      6a:	4378      	lsli      	r3, r3, 24
      6c:	698c      	and      	r6, r3
      6e:	e926fffc 	bnez      	r6, 0x66	// 66 <dsleep_wakeup+0x66>
      72:	ea840125 	lrw      	r4, 0x40026000	// 504 <dsleep_wakeup+0x504>
      76:	32ff      	movi      	r2, 255
      78:	9464      	ld.w      	r3, (r4, 0x10)
      7a:	4258      	lsli      	r2, r2, 24
      7c:	68c8      	and      	r3, r2
      7e:	b464      	st.w      	r3, (r4, 0x10)
      80:	9470      	ld.w      	r3, (r4, 0x40)
      82:	3b9a      	bclri      	r3, 26
      84:	b470      	st.w      	r3, (r4, 0x40)
      86:	3200      	movi      	r2, 0
      88:	9463      	ld.w      	r3, (r4, 0xc)
      8a:	2ac3      	subi      	r2, 196
      8c:	68c8      	and      	r3, r2
      8e:	ec630001 	ori      	r3, r3, 1
      92:	b463      	st.w      	r3, (r4, 0xc)
      94:	3300      	movi      	r3, 0
      96:	9528      	ld.w      	r1, (r5, 0x20)
      98:	2be0      	subi      	r3, 225
      9a:	684c      	and      	r1, r3
      9c:	ec210020 	ori      	r1, r1, 32
      a0:	3020      	movi      	r0, 32
      a2:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
      a6:	ea03f424 	movi      	r3, 62500
      aa:	c5234903 	rotli      	r3, r3, 9
      ae:	b760      	st.w      	r3, (r7, 0x0)
      b0:	c0006023 	mfcr      	r3, cr<0, 0>
      b4:	c0807020 	psrclr      	ie
      b8:	e0000000 	bsr      	0x0	// 0 <sysctrl_err_resp_disable>
      bc:	6c5b      	mov      	r1, r6
      be:	30b0      	movi      	r0, 176
      c0:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
      c4:	9568      	ld.w      	r3, (r5, 0x20)
      c6:	ec630001 	ori      	r3, r3, 1
      ca:	b568      	st.w      	r3, (r5, 0x20)
      cc:	3101      	movi      	r1, 1
      ce:	30b0      	movi      	r0, 176
      d0:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
      d4:	3007      	movi      	r0, 7
      d6:	e0000000 	bsr      	0x0	// 0 <pmu_vdd_vol_set_sec>
      da:	9460      	ld.w      	r3, (r4, 0x0)
      dc:	3b90      	bclri      	r3, 16
      de:	3b96      	bclri      	r3, 22
      e0:	b460      	st.w      	r3, (r4, 0x0)
      e2:	ea83010b 	lrw      	r3, 0x6e3d8b2c	// 50c <dsleep_wakeup+0x50c>
      e6:	b465      	st.w      	r3, (r4, 0x14)
      e8:	6c9b      	mov      	r2, r6
      ea:	3308      	movi      	r3, 8
      ec:	6c5b      	mov      	r1, r6
      ee:	3001      	movi      	r0, 1
      f0:	e0000000 	bsr      	0x0	// 0 <sysctrl_adcpll_set>
      f4:	ea00b71b 	movi      	r0, 46875
      f8:	c5604900 	rotli      	r0, r0, 11
      fc:	e0000000 	bsr      	0x0	// 0 <sys_set_sysclk>
     100:	3300      	movi      	r3, 0
     102:	2b00      	subi      	r3, 1
     104:	64c2      	cmpne      	r0, r3
     106:	ea840103 	lrw      	r4, 0x0	// 510 <dsleep_wakeup+0x510>
     10a:	0806      	bt      	0x116	// 116 <dsleep_wakeup+0x116>
     10c:	8465      	ld.b      	r3, (r4, 0x5)
     10e:	3201      	movi      	r2, 1
     110:	c4625c03 	ins      	r3, r2, 3, 3
     114:	a465      	st.b      	r3, (r4, 0x5)
     116:	0063      	lrw      	r3, 0x40026000	// 504 <dsleep_wakeup+0x504>
     118:	ea8100ff 	lrw      	r1, 0xe8effddf	// 514 <dsleep_wakeup+0x514>
     11c:	9342      	ld.w      	r2, (r3, 0x8)
     11e:	6884      	and      	r2, r1
     120:	b342      	st.w      	r2, (r3, 0x8)
     122:	3200      	movi      	r2, 0
     124:	2a00      	subi      	r2, 1
     126:	b342      	st.w      	r2, (r3, 0x8)
     128:	9346      	ld.w      	r2, (r3, 0x18)
     12a:	ec420001 	ori      	r2, r2, 1
     12e:	b346      	st.w      	r2, (r3, 0x18)
     130:	9359      	ld.w      	r2, (r3, 0x64)
     132:	3ab3      	bseti      	r2, 19
     134:	b359      	st.w      	r2, (r3, 0x64)
     136:	9359      	ld.w      	r2, (r3, 0x64)
     138:	3ab4      	bseti      	r2, 20
     13a:	b359      	st.w      	r2, (r3, 0x64)
     13c:	9359      	ld.w      	r2, (r3, 0x64)
     13e:	3ab5      	bseti      	r2, 21
     140:	9422      	ld.w      	r1, (r4, 0x8)
     142:	b359      	st.w      	r2, (r3, 0x64)
     144:	e42102e7 	addi      	r1, r1, 744
     148:	321a      	movi      	r2, 26
     14a:	ea204002 	movih      	r0, 16386
     14e:	38ad      	bseti      	r0, 13
     150:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     154:	9422      	ld.w      	r1, (r4, 0x8)
     156:	321a      	movi      	r2, 26
     158:	e421034f 	addi      	r1, r1, 848
     15c:	0010      	lrw      	r0, 0x40025000	// 518 <dsleep_wakeup+0x518>
     15e:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     162:	3000      	movi      	r0, 0
     164:	e0000000 	bsr      	0x0	// 0 <jtag_map_set>
     168:	3101      	movi      	r1, 1
     16a:	3000      	movi      	r0, 0
     16c:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     170:	3101      	movi      	r1, 1
     172:	3000      	movi      	r0, 0
     174:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     178:	3101      	movi      	r1, 1
     17a:	3016      	movi      	r0, 22
     17c:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     180:	3016      	movi      	r0, 22
     182:	3101      	movi      	r1, 1
     184:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     188:	9462      	ld.w      	r3, (r4, 0x8)
     18a:	d803025a 	ld.b      	r0, (r3, 0x25a)
     18e:	e4602001 	andi      	r3, r0, 1
     192:	e903000d 	bez      	r3, 0x1ac	// 1ac <dsleep_wakeup+0x1ac>
     196:	3101      	movi      	r1, 1
     198:	7005      	lsr      	r0, r1
     19a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     19e:	9462      	ld.w      	r3, (r4, 0x8)
     1a0:	3101      	movi      	r1, 1
     1a2:	d803025a 	ld.b      	r0, (r3, 0x25a)
     1a6:	7005      	lsr      	r0, r1
     1a8:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     1ac:	9462      	ld.w      	r3, (r4, 0x8)
     1ae:	d8230a4e 	ld.b      	r1, (r3, 0xa4e)
     1b2:	e4412004 	andi      	r2, r1, 4
     1b6:	e902002d 	bez      	r2, 0x210	// 210 <dsleep_wakeup+0x210>
     1ba:	d8030a4f 	ld.b      	r0, (r3, 0xa4f)
     1be:	74c2      	sextb      	r3, r0
     1c0:	e9a30010 	bhsz      	r3, 0x1e0	// 1e0 <dsleep_wakeup+0x1e0>
     1c4:	c4615461 	zext      	r1, r1, 3, 3
     1c8:	e400207f 	andi      	r0, r0, 127
     1cc:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     1d0:	9462      	ld.w      	r3, (r4, 0x8)
     1d2:	3101      	movi      	r1, 1
     1d4:	d8030a4f 	ld.b      	r0, (r3, 0xa4f)
     1d8:	e400207f 	andi      	r0, r0, 127
     1dc:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     1e0:	9462      	ld.w      	r3, (r4, 0x8)
     1e2:	d8030a50 	ld.b      	r0, (r3, 0xa50)
     1e6:	7482      	sextb      	r2, r0
     1e8:	e9a20014 	bhsz      	r2, 0x210	// 210 <dsleep_wakeup+0x210>
     1ec:	d8230a4e 	ld.b      	r1, (r3, 0xa4e)
     1f0:	e4214008 	xori      	r1, r1, 8
     1f4:	c4615461 	zext      	r1, r1, 3, 3
     1f8:	e400207f 	andi      	r0, r0, 127
     1fc:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     200:	9462      	ld.w      	r3, (r4, 0x8)
     202:	3101      	movi      	r1, 1
     204:	d8030a50 	ld.b      	r0, (r3, 0xa50)
     208:	e400207f 	andi      	r0, r0, 127
     20c:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     210:	3100      	movi      	r1, 0
     212:	3020      	movi      	r0, 32
     214:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     218:	3020      	movi      	r0, 32
     21a:	3101      	movi      	r1, 1
     21c:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     220:	9462      	ld.w      	r3, (r4, 0x8)
     222:	d8030259 	ld.b      	r0, (r3, 0x259)
     226:	e460207f 	andi      	r3, r0, 127
     22a:	e9030012 	bez      	r3, 0x24e	// 24e <dsleep_wakeup+0x24e>
     22e:	6c0f      	mov      	r0, r3
     230:	3100      	movi      	r1, 0
     232:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     236:	9462      	ld.w      	r3, (r4, 0x8)
     238:	3201      	movi      	r2, 1
     23a:	d8030259 	ld.b      	r0, (r3, 0x259)
     23e:	74c2      	sextb      	r3, r0
     240:	e9a3015a 	bhsz      	r3, 0x4f4	// 4f4 <dsleep_wakeup+0x4f4>
     244:	3102      	movi      	r1, 2
     246:	e400207f 	andi      	r0, r0, 127
     24a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     24e:	0271      	lrw      	r3, 0x40026000	// 504 <dsleep_wakeup+0x504>
     250:	940c      	ld.w      	r0, (r4, 0x30)
     252:	9345      	ld.w      	r2, (r3, 0x14)
     254:	ec420800 	ori      	r2, r2, 2048
     258:	b345      	st.w      	r2, (r3, 0x14)
     25a:	9342      	ld.w      	r2, (r3, 0x8)
     25c:	3a8b      	bclri      	r2, 11
     25e:	b342      	st.w      	r2, (r3, 0x8)
     260:	9342      	ld.w      	r2, (r3, 0x8)
     262:	ec420800 	ori      	r2, r2, 2048
     266:	b342      	st.w      	r2, (r3, 0x8)
     268:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     26c:	ea058003 	movi      	r5, 32771
     270:	c5e54905 	rotli      	r5, r5, 15
     274:	310a      	movi      	r1, 10
     276:	940c      	ld.w      	r0, (r4, 0x30)
     278:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     27c:	310d      	movi      	r1, 13
     27e:	940c      	ld.w      	r0, (r4, 0x30)
     280:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     284:	9528      	ld.w      	r1, (r5, 0x20)
     286:	39ba      	bseti      	r1, 26
     288:	3020      	movi      	r0, 32
     28a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     28e:	9528      	ld.w      	r1, (r5, 0x20)
     290:	39bb      	bseti      	r1, 27
     292:	3020      	movi      	r0, 32
     294:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     298:	9524      	ld.w      	r1, (r5, 0x10)
     29a:	39b4      	bseti      	r1, 20
     29c:	3010      	movi      	r0, 16
     29e:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     2a2:	d8642041 	ld.w      	r3, (r4, 0x104)
     2a6:	2300      	addi      	r3, 1
     2a8:	dc642041 	st.w      	r3, (r4, 0x104)
     2ac:	8465      	ld.b      	r3, (r4, 0x5)
     2ae:	e4632008 	andi      	r3, r3, 8
     2b2:	e9030005 	bez      	r3, 0x2bc	// 2bc <dsleep_wakeup+0x2bc>
     2b6:	0305      	lrw      	r0, 0x0	// 51c <dsleep_wakeup+0x51c>
     2b8:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     2bc:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     2c0:	ea058003 	movi      	r5, 32771
     2c4:	c5e54905 	rotli      	r5, r5, 15
     2c8:	3101      	movi      	r1, 1
     2ca:	3002      	movi      	r0, 2
     2cc:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     2d0:	3100      	movi      	r1, 0
     2d2:	3002      	movi      	r0, 2
     2d4:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     2d8:	956d      	ld.w      	r3, (r5, 0x34)
     2da:	e4632001 	andi      	r3, r3, 1
     2de:	e9030007 	bez      	r3, 0x2ec	// 2ec <dsleep_wakeup+0x2ec>
     2e2:	31c0      	movi      	r1, 192
     2e4:	4131      	lsli      	r1, r1, 17
     2e6:	3034      	movi      	r0, 52
     2e8:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     2ec:	9567      	ld.w      	r3, (r5, 0x1c)
     2ee:	e4632080 	andi      	r3, r3, 128
     2f2:	e9030015 	bez      	r3, 0x31c	// 31c <dsleep_wakeup+0x31c>
     2f6:	0314      	lrw      	r0, 0x0	// 520 <dsleep_wakeup+0x520>
     2f8:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     2fc:	9527      	ld.w      	r1, (r5, 0x1c)
     2fe:	3987      	bclri      	r1, 7
     300:	301c      	movi      	r0, 28
     302:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     306:	9567      	ld.w      	r3, (r5, 0x1c)
     308:	e4632080 	andi      	r3, r3, 128
     30c:	e9030008 	bez      	r3, 0x31c	// 31c <dsleep_wakeup+0x31c>
     310:	031a      	lrw      	r0, 0x0	// 524 <dsleep_wakeup+0x524>
     312:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     316:	9507      	ld.w      	r0, (r5, 0x1c)
     318:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     31c:	ea058003 	movi      	r5, 32771
     320:	c5e54905 	rotli      	r5, r5, 15
     324:	3680      	movi      	r6, 128
     326:	9567      	ld.w      	r3, (r5, 0x1c)
     328:	46c8      	lsli      	r6, r6, 8
     32a:	68d8      	and      	r3, r6
     32c:	e903010c 	bez      	r3, 0x544	// 544 <dsleep_wakeup+0x544>
     330:	9527      	ld.w      	r1, (r5, 0x1c)
     332:	398f      	bclri      	r1, 15
     334:	301c      	movi      	r0, 28
     336:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     33a:	9567      	ld.w      	r3, (r5, 0x1c)
     33c:	698c      	and      	r6, r3
     33e:	e9060008 	bez      	r6, 0x34e	// 34e <dsleep_wakeup+0x34e>
     342:	131a      	lrw      	r0, 0x0	// 528 <dsleep_wakeup+0x528>
     344:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     348:	9507      	ld.w      	r0, (r5, 0x1c)
     34a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     34e:	ea068003 	movi      	r6, 32771
     352:	c5e64906 	rotli      	r6, r6, 15
     356:	d8a62028 	ld.w      	r5, (r6, 0xa0)
     35a:	e4a52100 	andi      	r5, r5, 256
     35e:	e9050038 	bez      	r5, 0x3ce	// 3ce <dsleep_wakeup+0x3ce>
     362:	1313      	lrw      	r0, 0x0	// 52c <dsleep_wakeup+0x52c>
     364:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     368:	d8262028 	ld.w      	r1, (r6, 0xa0)
     36c:	39b0      	bseti      	r1, 16
     36e:	30a0      	movi      	r0, 160
     370:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     374:	d8662028 	ld.w      	r3, (r6, 0xa0)
     378:	e4632100 	andi      	r3, r3, 256
     37c:	e9030009 	bez      	r3, 0x38e	// 38e <dsleep_wakeup+0x38e>
     380:	130c      	lrw      	r0, 0x0	// 530 <dsleep_wakeup+0x530>
     382:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     386:	d8062028 	ld.w      	r0, (r6, 0xa0)
     38a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     38e:	9462      	ld.w      	r3, (r4, 0x8)
     390:	3100      	movi      	r1, 0
     392:	8355      	ld.b      	r2, (r3, 0x15)
     394:	c4415c03 	ins      	r2, r1, 3, 3
     398:	d8030259 	ld.b      	r0, (r3, 0x259)
     39c:	a355      	st.b      	r2, (r3, 0x15)
     39e:	e440207f 	andi      	r2, r0, 127
     3a2:	e90200da 	bez      	r2, 0x556	// 556 <dsleep_wakeup+0x556>
     3a6:	6c0b      	mov      	r0, r2
     3a8:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     3ac:	9462      	ld.w      	r3, (r4, 0x8)
     3ae:	d9830259 	ld.b      	r12, (r3, 0x259)
     3b2:	c4ec4842 	lsri      	r2, r12, 7
     3b6:	6482      	cmpne      	r0, r2
     3b8:	08cb      	bt      	0x54e	// 54e <dsleep_wakeup+0x54e>
     3ba:	3204      	movi      	r2, 4
     3bc:	dc430257 	st.b      	r2, (r3, 0x257)
     3c0:	3200      	movi      	r2, 0
     3c2:	6c4b      	mov      	r1, r2
     3c4:	e40c207f 	andi      	r0, r12, 127
     3c8:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     3cc:	3501      	movi      	r5, 1
     3ce:	ea068003 	movi      	r6, 32771
     3d2:	c5e64906 	rotli      	r6, r6, 15
     3d6:	3280      	movi      	r2, 128
     3d8:	d8662028 	ld.w      	r3, (r6, 0xa0)
     3dc:	4246      	lsli      	r2, r2, 6
     3de:	68c8      	and      	r3, r2
     3e0:	e9030015 	bez      	r3, 0x40a	// 40a <dsleep_wakeup+0x40a>
     3e4:	1214      	lrw      	r0, 0x0	// 534 <dsleep_wakeup+0x534>
     3e6:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     3ea:	d8262028 	ld.w      	r1, (r6, 0xa0)
     3ee:	39b1      	bseti      	r1, 17
     3f0:	30a0      	movi      	r0, 160
     3f2:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     3f6:	9462      	ld.w      	r3, (r4, 0x8)
     3f8:	3100      	movi      	r1, 0
     3fa:	8355      	ld.b      	r2, (r3, 0x15)
     3fc:	c4415c03 	ins      	r2, r1, 3, 3
     400:	a355      	st.b      	r2, (r3, 0x15)
     402:	3209      	movi      	r2, 9
     404:	dc430257 	st.b      	r2, (r3, 0x257)
     408:	3501      	movi      	r5, 1
     40a:	ea068003 	movi      	r6, 32771
     40e:	c5e64906 	rotli      	r6, r6, 15
     412:	3280      	movi      	r2, 128
     414:	d8662028 	ld.w      	r3, (r6, 0xa0)
     418:	4247      	lsli      	r2, r2, 7
     41a:	68c8      	and      	r3, r2
     41c:	e9030015 	bez      	r3, 0x446	// 446 <dsleep_wakeup+0x446>
     420:	1206      	lrw      	r0, 0x0	// 538 <dsleep_wakeup+0x538>
     422:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     426:	d8262028 	ld.w      	r1, (r6, 0xa0)
     42a:	39b2      	bseti      	r1, 18
     42c:	30a0      	movi      	r0, 160
     42e:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     432:	9462      	ld.w      	r3, (r4, 0x8)
     434:	3100      	movi      	r1, 0
     436:	8355      	ld.b      	r2, (r3, 0x15)
     438:	c4415c03 	ins      	r2, r1, 3, 3
     43c:	a355      	st.b      	r2, (r3, 0x15)
     43e:	320a      	movi      	r2, 10
     440:	dc430257 	st.b      	r2, (r3, 0x257)
     444:	3501      	movi      	r5, 1
     446:	ea068003 	movi      	r6, 32771
     44a:	c5e64906 	rotli      	r6, r6, 15
     44e:	3280      	movi      	r2, 128
     450:	d8662028 	ld.w      	r3, (r6, 0xa0)
     454:	4248      	lsli      	r2, r2, 8
     456:	68c8      	and      	r3, r2
     458:	e9030015 	bez      	r3, 0x482	// 482 <dsleep_wakeup+0x482>
     45c:	1118      	lrw      	r0, 0x0	// 53c <dsleep_wakeup+0x53c>
     45e:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     462:	d8262028 	ld.w      	r1, (r6, 0xa0)
     466:	39b3      	bseti      	r1, 19
     468:	30a0      	movi      	r0, 160
     46a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     46e:	9462      	ld.w      	r3, (r4, 0x8)
     470:	3100      	movi      	r1, 0
     472:	8355      	ld.b      	r2, (r3, 0x15)
     474:	c4415c03 	ins      	r2, r1, 3, 3
     478:	a355      	st.b      	r2, (r3, 0x15)
     47a:	320a      	movi      	r2, 10
     47c:	dc430257 	st.b      	r2, (r3, 0x257)
     480:	3501      	movi      	r5, 1
     482:	ea068003 	movi      	r6, 32771
     486:	c5e64906 	rotli      	r6, r6, 15
     48a:	d8662020 	ld.w      	r3, (r6, 0x80)
     48e:	e4632004 	andi      	r3, r3, 4
     492:	e903001e 	bez      	r3, 0x4ce	// 4ce <dsleep_wakeup+0x4ce>
     496:	d8262020 	ld.w      	r1, (r6, 0x80)
     49a:	3982      	bclri      	r1, 2
     49c:	3983      	bclri      	r1, 3
     49e:	3080      	movi      	r0, 128
     4a0:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     4a4:	d8662020 	ld.w      	r3, (r6, 0x80)
     4a8:	e463200c 	andi      	r3, r3, 12
     4ac:	e9030009 	bez      	r3, 0x4be	// 4be <dsleep_wakeup+0x4be>
     4b0:	1104      	lrw      	r0, 0x0	// 540 <dsleep_wakeup+0x540>
     4b2:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     4b6:	d8062020 	ld.w      	r0, (r6, 0x80)
     4ba:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     4be:	9442      	ld.w      	r2, (r4, 0x8)
     4c0:	8275      	ld.b      	r3, (r2, 0x15)
     4c2:	e4632008 	andi      	r3, r3, 8
     4c6:	e9230004 	bnez      	r3, 0x4ce	// 4ce <dsleep_wakeup+0x4ce>
     4ca:	dc620257 	st.b      	r3, (r2, 0x257)
     4ce:	e0000000 	bsr      	0x0	// 0 <system_sleep_wakeup_hook>
     4d2:	32a0      	movi      	r2, 160
     4d4:	4249      	lsli      	r2, r2, 9
     4d6:	9461      	ld.w      	r3, (r4, 0x4)
     4d8:	c4432021 	and      	r1, r3, r2
     4dc:	6486      	cmpne      	r1, r2
     4de:	0c03      	bf      	0x4e4	// 4e4 <dsleep_wakeup+0x4e4>
     4e0:	e9250008 	bnez      	r5, 0x4f0	// 4f0 <dsleep_wakeup+0x4f0>
     4e4:	c6405022 	bmaski      	r2, 19
     4e8:	2201      	addi      	r2, 2
     4ea:	68c8      	and      	r3, r2
     4ec:	e923003a 	bnez      	r3, 0x560	// 560 <dsleep_wakeup+0x560>
     4f0:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     4f4:	6c4b      	mov      	r1, r2
     4f6:	e400207f 	andi      	r0, r0, 127
     4fa:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     4fe:	06a8      	br      	0x24e	// 24e <sys_clk+0x24e>
     500:	00000000 	.long	0x00000000
     504:	40026000 	.long	0x40026000
     508:	3fac87e4 	.long	0x3fac87e4
     50c:	6e3d8b2c 	.long	0x6e3d8b2c
     510:	00000000 	.long	0x00000000
     514:	e8effddf 	.long	0xe8effddf
     518:	40025000 	.long	0x40025000
	...
     544:	ea80013e 	lrw      	r0, 0x0	// a3c <dsleep_wakeup+0xa3c>
     548:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     54c:	0701      	br      	0x34e	// 34e <dsleep_wakeup+0x34e>
     54e:	320b      	movi      	r2, 11
     550:	dc430257 	st.b      	r2, (r3, 0x257)
     554:	0736      	br      	0x3c0	// 3c0 <dsleep_wakeup+0x3c0>
     556:	3204      	movi      	r2, 4
     558:	dc430257 	st.b      	r2, (r3, 0x257)
     55c:	3501      	movi      	r5, 1
     55e:	0738      	br      	0x3ce	// 3ce <dsleep_wakeup+0x3ce>
     560:	8465      	ld.b      	r3, (r4, 0x5)
     562:	e4632040 	andi      	r3, r3, 64
     566:	e9030006 	bez      	r3, 0x572	// 572 <dsleep_wakeup+0x572>
     56a:	3d40      	cmpnei      	r5, 0
     56c:	c4000503 	mvc      	r3
     570:	74cc      	zextb      	r3, r3
     572:	8445      	ld.b      	r2, (r4, 0x5)
     574:	c4435c07 	ins      	r2, r3, 7, 7
     578:	9422      	ld.w      	r1, (r4, 0x8)
     57a:	a445      	st.b      	r2, (r4, 0x5)
     57c:	e42107ab 	addi      	r1, r1, 1964
     580:	3241      	movi      	r2, 65
     582:	ea008000 	movi      	r0, 32768
     586:	38be      	bseti      	r0, 30
     588:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     58c:	9422      	ld.w      	r1, (r4, 0x8)
     58e:	328f      	movi      	r2, 143
     590:	e421056f 	addi      	r1, r1, 1392
     594:	ea204002 	movih      	r0, 16386
     598:	38ae      	bseti      	r0, 14
     59a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     59e:	9422      	ld.w      	r1, (r4, 0x8)
     5a0:	320b      	movi      	r2, 11
     5a2:	e4210543 	addi      	r1, r1, 1348
     5a6:	ea800127 	lrw      	r0, 0x40016000	// a40 <dsleep_wakeup+0xa40>
     5aa:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     5ae:	9422      	ld.w      	r1, (r4, 0x8)
     5b0:	320a      	movi      	r2, 10
     5b2:	e42103b7 	addi      	r1, r1, 952
     5b6:	ea005000 	movi      	r0, 20480
     5ba:	38be      	bseti      	r0, 30
     5bc:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     5c0:	9422      	ld.w      	r1, (r4, 0x8)
     5c2:	3259      	movi      	r2, 89
     5c4:	e42103df 	addi      	r1, r1, 992
     5c8:	ea80011f 	lrw      	r0, 0x4001d000	// a44 <dsleep_wakeup+0xa44>
     5cc:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     5d0:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     5d4:	9442      	ld.w      	r2, (r4, 0x8)
     5d6:	d8620a4e 	ld.b      	r3, (r2, 0xa4e)
     5da:	e4632001 	andi      	r3, r3, 1
     5de:	e9030245 	bez      	r3, 0xa68	// a68 <dsleep_wakeup+0xa68>
     5e2:	94a3      	ld.w      	r5, (r4, 0xc)
     5e4:	31c2      	movi      	r1, 194
     5e6:	4123      	lsli      	r1, r1, 3
     5e8:	6c17      	mov      	r0, r5
     5ea:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     5ee:	33ff      	movi      	r3, 255
     5f0:	4368      	lsli      	r3, r3, 8
     5f2:	31c2      	movi      	r1, 194
     5f4:	c4602022 	and      	r2, r0, r3
     5f8:	4123      	lsli      	r1, r1, 3
     5fa:	6c17      	mov      	r0, r5
     5fc:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     600:	3000      	movi      	r0, 0
     602:	e0000000 	bsr      	0x0	// 0 <sysctrl_internal_rf_sel_lo_freq>
     606:	3181      	movi      	r1, 129
     608:	3238      	movi      	r2, 56
     60a:	4124      	lsli      	r1, r1, 4
     60c:	9403      	ld.w      	r0, (r4, 0xc)
     60e:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     612:	ea80010e 	lrw      	r0, 0x0	// a48 <dsleep_wakeup+0xa48>
     616:	ea0c0000 	movi      	r12, 0
     61a:	9020      	ld.w      	r1, (r0, 0x0)
     61c:	e58c1007 	subi      	r12, r12, 8
     620:	9170      	ld.w      	r3, (r1, 0x40)
     622:	3b84      	bclri      	r3, 4
     624:	3b85      	bclri      	r3, 5
     626:	b170      	st.w      	r3, (r1, 0x40)
     628:	9170      	ld.w      	r3, (r1, 0x40)
     62a:	ec630010 	ori      	r3, r3, 16
     62e:	b170      	st.w      	r3, (r1, 0x40)
     630:	9468      	ld.w      	r3, (r4, 0x20)
     632:	6e83      	mov      	r10, r0
     634:	9340      	ld.w      	r2, (r3, 0x0)
     636:	3a90      	bclri      	r2, 16
     638:	3a91      	bclri      	r2, 17
     63a:	b340      	st.w      	r2, (r3, 0x0)
     63c:	9340      	ld.w      	r2, (r3, 0x0)
     63e:	3ab0      	bseti      	r2, 16
     640:	b340      	st.w      	r2, (r3, 0x0)
     642:	9466      	ld.w      	r3, (r4, 0x18)
     644:	9358      	ld.w      	r2, (r3, 0x60)
     646:	3a88      	bclri      	r2, 8
     648:	3a89      	bclri      	r2, 9
     64a:	ec420100 	ori      	r2, r2, 256
     64e:	b358      	st.w      	r2, (r3, 0x60)
     650:	9358      	ld.w      	r2, (r3, 0x60)
     652:	68b0      	and      	r2, r12
     654:	b358      	st.w      	r2, (r3, 0x60)
     656:	9358      	ld.w      	r2, (r3, 0x60)
     658:	ec420005 	ori      	r2, r2, 5
     65c:	b358      	st.w      	r2, (r3, 0x60)
     65e:	ea0c0000 	movi      	r12, 0
     662:	9358      	ld.w      	r2, (r3, 0x60)
     664:	e58c10e0 	subi      	r12, r12, 225
     668:	68b0      	and      	r2, r12
     66a:	b358      	st.w      	r2, (r3, 0x60)
     66c:	9358      	ld.w      	r2, (r3, 0x60)
     66e:	ec4200a0 	ori      	r2, r2, 160
     672:	b358      	st.w      	r2, (r3, 0x60)
     674:	9358      	ld.w      	r2, (r3, 0x60)
     676:	ec420008 	ori      	r2, r2, 8
     67a:	b358      	st.w      	r2, (r3, 0x60)
     67c:	9358      	ld.w      	r2, (r3, 0x60)
     67e:	e4422008 	andi      	r2, r2, 8
     682:	e922fffd 	bnez      	r2, 0x67c	// 67c <dsleep_wakeup+0x67c>
     686:	9442      	ld.w      	r2, (r4, 0x8)
     688:	ea0c0000 	movi      	r12, 0
     68c:	d8420a51 	ld.b      	r2, (r2, 0xa51)
     690:	e4022007 	andi      	r0, r2, 7
     694:	934b      	ld.w      	r2, (r3, 0x2c)
     696:	3a8f      	bclri      	r2, 15
     698:	b34b      	st.w      	r2, (r3, 0x2c)
     69a:	934b      	ld.w      	r2, (r3, 0x2c)
     69c:	e58c1007 	subi      	r12, r12, 8
     6a0:	68b0      	and      	r2, r12
     6a2:	6c80      	or      	r2, r0
     6a4:	b34b      	st.w      	r2, (r3, 0x2c)
     6a6:	934b      	ld.w      	r2, (r3, 0x2c)
     6a8:	ec420008 	ori      	r2, r2, 8
     6ac:	b34b      	st.w      	r2, (r3, 0x2c)
     6ae:	93ab      	ld.w      	r5, (r3, 0x2c)
     6b0:	e4a52008 	andi      	r5, r5, 8
     6b4:	e925fffd 	bnez      	r5, 0x6ae	// 6ae <dsleep_wakeup+0x6ae>
     6b8:	9171      	ld.w      	r3, (r1, 0x44)
     6ba:	3bbf      	bseti      	r3, 31
     6bc:	b171      	st.w      	r3, (r1, 0x44)
     6be:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     6c2:	d86a2000 	ld.w      	r3, (r10, 0x0)
     6c6:	9422      	ld.w      	r1, (r4, 0x8)
     6c8:	934c      	ld.w      	r2, (r3, 0x30)
     6ca:	ec420200 	ori      	r2, r2, 512
     6ce:	b34c      	st.w      	r2, (r3, 0x30)
     6d0:	934c      	ld.w      	r2, (r3, 0x30)
     6d2:	ec420400 	ori      	r2, r2, 1024
     6d6:	b34c      	st.w      	r2, (r3, 0x30)
     6d8:	e44108bf 	addi      	r2, r1, 2240
     6dc:	dc432101 	st.w      	r2, (r3, 0x404)
     6e0:	e44109bf 	addi      	r2, r1, 2496
     6e4:	dc432102 	st.w      	r2, (r3, 0x408)
     6e8:	dca32100 	st.w      	r5, (r3, 0x400)
     6ec:	d8432100 	ld.w      	r2, (r3, 0x400)
     6f0:	3a82      	bclri      	r2, 2
     6f2:	3a83      	bclri      	r2, 3
     6f4:	dc432100 	st.w      	r2, (r3, 0x400)
     6f8:	d8432100 	ld.w      	r2, (r3, 0x400)
     6fc:	dc432100 	st.w      	r2, (r3, 0x400)
     700:	3280      	movi      	r2, 128
     702:	4243      	lsli      	r2, r2, 3
     704:	b352      	st.w      	r2, (r3, 0x48)
     706:	d84114fc 	ld.h      	r2, (r1, 0x9f8)
     70a:	d80114fb 	ld.h      	r0, (r1, 0x9f6)
     70e:	4250      	lsli      	r2, r2, 16
     710:	6c80      	or      	r2, r0
     712:	b34f      	st.w      	r2, (r3, 0x3c)
     714:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     718:	940c      	ld.w      	r0, (r4, 0x30)
     71a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     71e:	8464      	ld.b      	r3, (r4, 0x4)
     720:	e4632093 	andi      	r3, r3, 147
     724:	c4655c04 	ins      	r3, r5, 4, 4
     728:	a464      	st.b      	r3, (r4, 0x4)
     72a:	8465      	ld.b      	r3, (r4, 0x5)
     72c:	8446      	ld.b      	r2, (r4, 0x6)
     72e:	3101      	movi      	r1, 1
     730:	e46320ea 	andi      	r3, r3, 234
     734:	c4415c01 	ins      	r2, r1, 1, 1
     738:	c4655c01 	ins      	r3, r5, 1, 1
     73c:	9422      	ld.w      	r1, (r4, 0x8)
     73e:	a446      	st.b      	r2, (r4, 0x6)
     740:	a465      	st.b      	r3, (r4, 0x5)
     742:	8905      	ld.h      	r0, (r1, 0xa)
     744:	dca42042 	st.w      	r5, (r4, 0x108)
     748:	e9000013 	bez      	r0, 0x76e	// 76e <dsleep_wakeup+0x76e>
     74c:	8175      	ld.b      	r3, (r1, 0x15)
     74e:	e4632007 	andi      	r3, r3, 7
     752:	3b41      	cmpnei      	r3, 1
     754:	080d      	bt      	0x76e	// 76e <dsleep_wakeup+0x76e>
     756:	d8442041 	ld.w      	r2, (r4, 0x104)
     75a:	c402802c 	divu      	r12, r2, r0
     75e:	7f00      	mult      	r12, r0
     760:	60b2      	subu      	r2, r12
     762:	e9220006 	bnez      	r2, 0x76e	// 76e <dsleep_wakeup+0x76e>
     766:	8445      	ld.b      	r2, (r4, 0x5)
     768:	c4435c01 	ins      	r2, r3, 1, 1
     76c:	a445      	st.b      	r2, (r4, 0x5)
     76e:	d8442040 	ld.w      	r2, (r4, 0x100)
     772:	e9020014 	bez      	r2, 0x79a	// 79a <dsleep_wakeup+0x79a>
     776:	d8642041 	ld.w      	r3, (r4, 0x104)
     77a:	c443802c 	divu      	r12, r3, r2
     77e:	7f08      	mult      	r12, r2
     780:	60f2      	subu      	r3, r12
     782:	e923000c 	bnez      	r3, 0x79a	// 79a <dsleep_wakeup+0x79a>
     786:	8465      	ld.b      	r3, (r4, 0x5)
     788:	e5832002 	andi      	r12, r3, 2
     78c:	e92c0007 	bnez      	r12, 0x79a	// 79a <dsleep_wakeup+0x79a>
     790:	ea0c0001 	movi      	r12, 1
     794:	c46c5c00 	ins      	r3, r12, 0, 0
     798:	a465      	st.b      	r3, (r4, 0x5)
     79a:	e900000e 	bez      	r0, 0x7b6	// 7b6 <dsleep_wakeup+0x7b6>
     79e:	8175      	ld.b      	r3, (r1, 0x15)
     7a0:	e4632007 	andi      	r3, r3, 7
     7a4:	3b41      	cmpnei      	r3, 1
     7a6:	0808      	bt      	0x7b6	// 7b6 <dsleep_wakeup+0x7b6>
     7a8:	6408      	cmphs      	r2, r0
     7aa:	0c06      	bf      	0x7b6	// 7b6 <dsleep_wakeup+0x7b6>
     7ac:	8465      	ld.b      	r3, (r4, 0x5)
     7ae:	3200      	movi      	r2, 0
     7b0:	c4625c00 	ins      	r3, r2, 0, 0
     7b4:	a465      	st.b      	r3, (r4, 0x5)
     7b6:	d8640125 	ld.b      	r3, (r4, 0x125)
     7ba:	e9030011 	bez      	r3, 0x7dc	// 7dc <dsleep_wakeup+0x7dc>
     7be:	8465      	ld.b      	r3, (r4, 0x5)
     7c0:	3201      	movi      	r2, 1
     7c2:	c4625c00 	ins      	r3, r2, 0, 0
     7c6:	a465      	st.b      	r3, (r4, 0x5)
     7c8:	3300      	movi      	r3, 0
     7ca:	dc640125 	st.b      	r3, (r4, 0x125)
     7ce:	3200      	movi      	r2, 0
     7d0:	d8610a4e 	ld.b      	r3, (r1, 0xa4e)
     7d4:	c4625c00 	ins      	r3, r2, 0, 0
     7d8:	dc610a4e 	st.b      	r3, (r1, 0xa4e)
     7dc:	8466      	ld.b      	r3, (r4, 0x6)
     7de:	e4432008 	andi      	r2, r3, 8
     7e2:	e9020006 	bez      	r2, 0x7ee	// 7ee <dsleep_wakeup+0x7ee>
     7e6:	3201      	movi      	r2, 1
     7e8:	c4625c04 	ins      	r3, r2, 4, 4
     7ec:	a466      	st.b      	r3, (r4, 0x6)
     7ee:	d801025a 	ld.b      	r0, (r1, 0x25a)
     7f2:	e4602001 	andi      	r3, r0, 1
     7f6:	e9030006 	bez      	r3, 0x802	// 802 <dsleep_wakeup+0x802>
     7fa:	3100      	movi      	r1, 0
     7fc:	4801      	lsri      	r0, r0, 1
     7fe:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     802:	9442      	ld.w      	r2, (r4, 0x8)
     804:	d8644128 	ld.bs      	r3, (r4, 0x128)
     808:	d84209c6 	ld.b      	r2, (r2, 0x9c6)
     80c:	648d      	cmplt      	r3, r2
     80e:	0804      	bt      	0x816	// 816 <dsleep_wakeup+0x816>
     810:	60ca      	subu      	r3, r2
     812:	dc640128 	st.b      	r3, (r4, 0x128)
     816:	3000      	movi      	r0, 0
     818:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
     81c:	d86a2000 	ld.w      	r3, (r10, 0x0)
     820:	3200      	movi      	r2, 0
     822:	0394      	lrw      	r4, 0x0	// a4c <dsleep_wakeup+0xa4c>
     824:	b344      	st.w      	r2, (r3, 0x10)
     826:	b345      	st.w      	r2, (r3, 0x14)
     828:	e4640083 	addi      	r3, r4, 132
     82c:	b867      	st.w      	r3, (r14, 0x1c)
     82e:	e4640073 	addi      	r3, r4, 116
     832:	b868      	st.w      	r3, (r14, 0x20)
     834:	d86a2000 	ld.w      	r3, (r10, 0x0)
     838:	9352      	ld.w      	r2, (r3, 0x48)
     83a:	e4422400 	andi      	r2, r2, 1024
     83e:	e90206c6 	bez      	r2, 0x15ca	// 15ca <dsleep_wakeup+0x15ca>
     842:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     846:	d86a2000 	ld.w      	r3, (r10, 0x0)
     84a:	3280      	movi      	r2, 128
     84c:	4243      	lsli      	r2, r2, 3
     84e:	b352      	st.w      	r2, (r3, 0x48)
     850:	d843202d 	ld.w      	r2, (r3, 0xb4)
     854:	e4422004 	andi      	r2, r2, 4
     858:	e9220015 	bnez      	r2, 0x882	// 882 <dsleep_wakeup+0x882>
     85c:	3180      	movi      	r1, 128
     85e:	d843202d 	ld.w      	r2, (r3, 0xb4)
     862:	4128      	lsli      	r1, r1, 8
     864:	6884      	and      	r2, r1
     866:	e922000e 	bnez      	r2, 0x882	// 882 <dsleep_wakeup+0x882>
     86a:	d843202d 	ld.w      	r2, (r3, 0xb4)
     86e:	e4422008 	andi      	r2, r2, 8
     872:	e9220008 	bnez      	r2, 0x882	// 882 <dsleep_wakeup+0x882>
     876:	d843202d 	ld.w      	r2, (r3, 0xb4)
     87a:	e4422020 	andi      	r2, r2, 32
     87e:	e9020123 	bez      	r2, 0xac4	// ac4 <dsleep_wakeup+0xac4>
     882:	3200      	movi      	r2, 0
     884:	2a00      	subi      	r2, 1
     886:	dc43202d 	st.w      	r2, (r3, 0xb4)
     88a:	3000      	movi      	r0, 0
     88c:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
     890:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     894:	8464      	ld.b      	r3, (r4, 0x4)
     896:	e4432008 	andi      	r2, r3, 8
     89a:	e902001e 	bez      	r2, 0x8d6	// 8d6 <dsleep_wakeup+0x8d6>
     89e:	e4632010 	andi      	r3, r3, 16
     8a2:	e923001a 	bnez      	r3, 0x8d6	// 8d6 <dsleep_wakeup+0x8d6>
     8a6:	130b      	lrw      	r0, 0x0	// a50 <dsleep_wakeup+0xa50>
     8a8:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     8ac:	9867      	ld.w      	r3, (r14, 0x1c)
     8ae:	b475      	st.w      	r3, (r4, 0x54)
     8b0:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     8b4:	3110      	movi      	r1, 16
     8b6:	9808      	ld.w      	r0, (r14, 0x20)
     8b8:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     8bc:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     8c0:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     8c4:	e9200009 	bnez      	r0, 0x8d6	// 8d6 <dsleep_wakeup+0x8d6>
     8c8:	8464      	ld.b      	r3, (r4, 0x4)
     8ca:	3201      	movi      	r2, 1
     8cc:	c4625c04 	ins      	r3, r2, 4, 4
     8d0:	a464      	st.b      	r3, (r4, 0x4)
     8d2:	dc04203d 	st.w      	r0, (r4, 0xf4)
     8d6:	d8644004 	ld.bs      	r3, (r4, 0x4)
     8da:	e9a30048 	bhsz      	r3, 0x96a	// 96a <dsleep_wakeup+0x96a>
     8de:	9462      	ld.w      	r3, (r4, 0x8)
     8e0:	8352      	ld.b      	r2, (r3, 0x12)
     8e2:	e9020703 	bez      	r2, 0x16e8	// 16e8 <dsleep_wakeup+0x16e8>
     8e6:	83b5      	ld.b      	r5, (r3, 0x15)
     8e8:	e4a52007 	andi      	r5, r5, 7
     8ec:	3d41      	cmpnei      	r5, 1
     8ee:	e86006fd 	bt      	0x16e8	// 16e8 <dsleep_wakeup+0x16e8>
     8f2:	1219      	lrw      	r0, 0x0	// a54 <dsleep_wakeup+0xa54>
     8f4:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     8f8:	9442      	ld.w      	r2, (r4, 0x8)
     8fa:	8278      	ld.b      	r3, (r2, 0x18)
     8fc:	8237      	ld.b      	r1, (r2, 0x17)
     8fe:	4368      	lsli      	r3, r3, 8
     900:	6cc4      	or      	r3, r1
     902:	ec631000 	ori      	r3, r3, 4096
     906:	74cd      	zexth      	r3, r3
     908:	a277      	st.b      	r3, (r2, 0x17)
     90a:	4b68      	lsri      	r3, r3, 8
     90c:	a278      	st.b      	r3, (r2, 0x18)
     90e:	d862002e 	ld.b      	r3, (r2, 0x2e)
     912:	d822002d 	ld.b      	r1, (r2, 0x2d)
     916:	4368      	lsli      	r3, r3, 8
     918:	6cc4      	or      	r3, r1
     91a:	ea01fff0 	movi      	r1, 65520
     91e:	68c4      	and      	r3, r1
     920:	230f      	addi      	r3, 16
     922:	74cd      	zexth      	r3, r3
     924:	dc62002d 	st.b      	r3, (r2, 0x2d)
     928:	4b68      	lsri      	r3, r3, 8
     92a:	dc62002e 	st.b      	r3, (r2, 0x2e)
     92e:	126b      	lrw      	r3, 0x0	// a58 <dsleep_wakeup+0xa58>
     930:	b475      	st.w      	r3, (r4, 0x54)
     932:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     936:	9402      	ld.w      	r0, (r4, 0x8)
     938:	8032      	ld.b      	r1, (r0, 0x12)
     93a:	2016      	addi      	r0, 23
     93c:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     940:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     944:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     948:	e9200011 	bnez      	r0, 0x96a	// 96a <dsleep_wakeup+0x96a>
     94c:	d864203a 	ld.w      	r3, (r4, 0xe8)
     950:	2300      	addi      	r3, 1
     952:	dc64203a 	st.w      	r3, (r4, 0xe8)
     956:	8464      	ld.b      	r3, (r4, 0x4)
     958:	c4605c07 	ins      	r3, r0, 7, 7
     95c:	a464      	st.b      	r3, (r4, 0x4)
     95e:	8465      	ld.b      	r3, (r4, 0x5)
     960:	c4655c02 	ins      	r3, r5, 2, 2
     964:	a465      	st.b      	r3, (r4, 0x5)
     966:	dc04203d 	st.w      	r0, (r4, 0xf4)
     96a:	8466      	ld.b      	r3, (r4, 0x6)
     96c:	e4632008 	andi      	r3, r3, 8
     970:	e923070a 	bnez      	r3, 0x1784	// 1784 <dsleep_wakeup+0x1784>
     974:	8465      	ld.b      	r3, (r4, 0x5)
     976:	e44320a0 	andi      	r2, r3, 160
     97a:	eb420020 	cmpnei      	r2, 32
     97e:	0c08      	bf      	0x98e	// 98e <dsleep_wakeup+0x98e>
     980:	8c42      	ld.h      	r2, (r4, 0x4)
     982:	ea018004 	movi      	r1, 32772
     986:	6884      	and      	r2, r1
     988:	eb428004 	cmpnei      	r2, 32772
     98c:	0812      	bt      	0x9b0	// 9b0 <dsleep_wakeup+0x9b0>
     98e:	8444      	ld.b      	r2, (r4, 0x4)
     990:	e4422004 	andi      	r2, r2, 4
     994:	e9220009 	bnez      	r2, 0x9a6	// 9a6 <dsleep_wakeup+0x9a6>
     998:	d84a2000 	ld.w      	r2, (r10, 0x0)
     99c:	9224      	ld.w      	r1, (r2, 0x10)
     99e:	d844203e 	ld.w      	r2, (r4, 0xf8)
     9a2:	6484      	cmphs      	r1, r2
     9a4:	0c06      	bf      	0x9b0	// 9b0 <dsleep_wakeup+0x9b0>
     9a6:	8444      	ld.b      	r2, (r4, 0x4)
     9a8:	3101      	movi      	r1, 1
     9aa:	c4415c06 	ins      	r2, r1, 6, 6
     9ae:	a444      	st.b      	r2, (r4, 0x4)
     9b0:	8444      	ld.b      	r2, (r4, 0x4)
     9b2:	e4422040 	andi      	r2, r2, 64
     9b6:	e90206e7 	bez      	r2, 0x1784	// 1784 <dsleep_wakeup+0x1784>
     9ba:	748e      	sextb      	r2, r3
     9bc:	e9a2069f 	bhsz      	r2, 0x16fa	// 16fa <dsleep_wakeup+0x16fa>
     9c0:	1107      	lrw      	r0, 0x0	// a5c <dsleep_wakeup+0xa5c>
     9c2:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     9c6:	1167      	lrw      	r3, 0x0	// a60 <dsleep_wakeup+0xa60>
     9c8:	b475      	st.w      	r3, (r4, 0x54)
     9ca:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     9ce:	d8444005 	ld.bs      	r2, (r4, 0x5)
     9d2:	d864104a 	ld.h      	r3, (r4, 0x94)
     9d6:	e9a206a0 	bhsz      	r2, 0x1716	// 1716 <dsleep_wakeup+0x1716>
     9da:	3b8c      	bclri      	r3, 12
     9dc:	dc64104a 	st.h      	r3, (r4, 0x94)
     9e0:	d8641055 	ld.h      	r3, (r4, 0xaa)
     9e4:	230f      	addi      	r3, 16
     9e6:	dc641055 	st.h      	r3, (r4, 0xaa)
     9ea:	311a      	movi      	r1, 26
     9ec:	101e      	lrw      	r0, 0x0	// a64 <dsleep_wakeup+0xa64>
     9ee:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     9f2:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     9f6:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     9fa:	e9200694 	bnez      	r0, 0x1722	// 1722 <dsleep_wakeup+0x1722>
     9fe:	8465      	ld.b      	r3, (r4, 0x5)
     a00:	c4605c05 	ins      	r3, r0, 5, 5
     a04:	dc040125 	st.b      	r0, (r4, 0x125)
     a08:	dc040126 	st.b      	r0, (r4, 0x126)
     a0c:	a465      	st.b      	r3, (r4, 0x5)
     a0e:	d804412a 	ld.bs      	r0, (r4, 0x12a)
     a12:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     a16:	8464      	ld.b      	r3, (r4, 0x4)
     a18:	3200      	movi      	r2, 0
     a1a:	c4625c06 	ins      	r3, r2, 6, 6
     a1e:	a464      	st.b      	r3, (r4, 0x4)
     a20:	8465      	ld.b      	r3, (r4, 0x5)
     a22:	744e      	sextb      	r1, r3
     a24:	3201      	movi      	r2, 1
     a26:	e9a106cd 	bhsz      	r1, 0x17c0	// 17c0 <dsleep_wakeup+0x17c0>
     a2a:	8464      	ld.b      	r3, (r4, 0x4)
     a2c:	c4625c01 	ins      	r3, r2, 1, 1
     a30:	a464      	st.b      	r3, (r4, 0x4)
     a32:	3300      	movi      	r3, 0
     a34:	dc64203d 	st.w      	r3, (r4, 0xf4)
     a38:	e800068d 	br      	0x1752	// 1752 <dsleep_wakeup+0x1752>
     a3c:	00000000 	.long	0x00000000
     a40:	40016000 	.long	0x40016000
     a44:	4001d000 	.long	0x4001d000
	...
     a68:	d8022280 	ld.w      	r0, (r2, 0xa00)
     a6c:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     a70:	94a2      	ld.w      	r5, (r4, 0x8)
     a72:	ea01092e 	movi      	r1, 2350
     a76:	9403      	ld.w      	r0, (r4, 0xc)
     a78:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     a7c:	dc051458 	st.h      	r0, (r5, 0x8b0)
     a80:	ea01092f 	movi      	r1, 2351
     a84:	94a2      	ld.w      	r5, (r4, 0x8)
     a86:	9403      	ld.w      	r0, (r4, 0xc)
     a88:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     a8c:	3193      	movi      	r1, 147
     a8e:	dc051459 	st.h      	r0, (r5, 0x8b2)
     a92:	4124      	lsli      	r1, r1, 4
     a94:	94a2      	ld.w      	r5, (r4, 0x8)
     a96:	9403      	ld.w      	r0, (r4, 0xc)
     a98:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     a9c:	dc05145a 	st.h      	r0, (r5, 0x8b4)
     aa0:	ea010931 	movi      	r1, 2353
     aa4:	94a2      	ld.w      	r5, (r4, 0x8)
     aa6:	9403      	ld.w      	r0, (r4, 0xc)
     aa8:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     aac:	9462      	ld.w      	r3, (r4, 0x8)
     aae:	dc05145b 	st.h      	r0, (r5, 0x8b6)
     ab2:	d8430a4e 	ld.b      	r2, (r3, 0xa4e)
     ab6:	3101      	movi      	r1, 1
     ab8:	c4415c00 	ins      	r2, r1, 0, 0
     abc:	dc430a4e 	st.b      	r2, (r3, 0xa4e)
     ac0:	e800fda9 	br      	0x612	// 612 <dsleep_wakeup+0x612>
     ac4:	d8232105 	ld.w      	r1, (r3, 0x414)
     ac8:	e421207f 	andi      	r1, r1, 127
     acc:	e901fedf 	bez      	r1, 0x88a	// 88a <dsleep_wakeup+0x88a>
     ad0:	3080      	movi      	r0, 128
     ad2:	d8232109 	ld.w      	r1, (r3, 0x424)
     ad6:	4007      	lsli      	r0, r0, 7
     ad8:	6840      	and      	r1, r0
     ada:	e9010004 	bez      	r1, 0xae2	// ae2 <dsleep_wakeup+0xae2>
     ade:	b450      	st.w      	r2, (r4, 0x40)
     ae0:	06d5      	br      	0x88a	// 88a <dsleep_wakeup+0x88a>
     ae2:	94a2      	ld.w      	r5, (r4, 0x8)
     ae4:	d8432109 	ld.w      	r2, (r3, 0x424)
     ae8:	c40255a2 	zext      	r2, r2, 13, 0
     aec:	d82508c0 	ld.b      	r1, (r5, 0x8c0)
     af0:	b450      	st.w      	r2, (r4, 0x40)
     af2:	e441208f 	andi      	r2, r1, 143
     af6:	eb420088 	cmpnei      	r2, 136
     afa:	09d4      	bt      	0xea2	// ea2 <dsleep_wakeup+0xea2>
     afc:	d84548c1 	ld.bs      	r2, (r5, 0x8c1)
     b00:	3adf      	btsti      	r2, 31
     b02:	301c      	movi      	r0, 28
     b04:	321a      	movi      	r2, 26
     b06:	c4400c40 	inct      	r2, r0, 0
     b0a:	dc440124 	st.b      	r2, (r4, 0x124)
     b0e:	d8432029 	ld.w      	r2, (r3, 0xa4)
     b12:	b451      	st.w      	r2, (r4, 0x44)
     b14:	d843202a 	ld.w      	r2, (r3, 0xa8)
     b18:	b452      	st.w      	r2, (r4, 0x48)
     b1a:	395c      	cmpnei      	r1, 28
     b1c:	d843202b 	ld.w      	r2, (r3, 0xac)
     b20:	b453      	st.w      	r2, (r4, 0x4c)
     b22:	d843202c 	ld.w      	r2, (r3, 0xb0)
     b26:	b454      	st.w      	r2, (r4, 0x50)
     b28:	0c8d      	bf      	0xc42	// c42 <dsleep_wakeup+0xc42>
     b2a:	e421200f 	andi      	r1, r1, 15
     b2e:	3944      	cmpnei      	r1, 4
     b30:	0c89      	bf      	0xc42	// c42 <dsleep_wakeup+0xc42>
     b32:	d82509f6 	ld.b      	r1, (r5, 0x9f6)
     b36:	d84508c4 	ld.b      	r2, (r5, 0x8c4)
     b3a:	6486      	cmpne      	r1, r2
     b3c:	0883      	bt      	0xc42	// c42 <dsleep_wakeup+0xc42>
     b3e:	d82509f7 	ld.b      	r1, (r5, 0x9f7)
     b42:	d84508c5 	ld.b      	r2, (r5, 0x8c5)
     b46:	6486      	cmpne      	r1, r2
     b48:	087d      	bt      	0xc42	// c42 <dsleep_wakeup+0xc42>
     b4a:	d82509f8 	ld.b      	r1, (r5, 0x9f8)
     b4e:	d84508c6 	ld.b      	r2, (r5, 0x8c6)
     b52:	6486      	cmpne      	r1, r2
     b54:	0877      	bt      	0xc42	// c42 <dsleep_wakeup+0xc42>
     b56:	d82509f9 	ld.b      	r1, (r5, 0x9f9)
     b5a:	d84508c7 	ld.b      	r2, (r5, 0x8c7)
     b5e:	6486      	cmpne      	r1, r2
     b60:	0871      	bt      	0xc42	// c42 <dsleep_wakeup+0xc42>
     b62:	d82509fa 	ld.b      	r1, (r5, 0x9fa)
     b66:	d84508c8 	ld.b      	r2, (r5, 0x8c8)
     b6a:	6486      	cmpne      	r1, r2
     b6c:	086b      	bt      	0xc42	// c42 <dsleep_wakeup+0xc42>
     b6e:	d82509fb 	ld.b      	r1, (r5, 0x9fb)
     b72:	d84508c9 	ld.b      	r2, (r5, 0x8c9)
     b76:	6486      	cmpne      	r1, r2
     b78:	0865      	bt      	0xc42	// c42 <dsleep_wakeup+0xc42>
     b7a:	32d4      	movi      	r2, 212
     b7c:	dc44102c 	st.h      	r2, (r4, 0x58)
     b80:	3200      	movi      	r2, 0
     b82:	dc44102d 	st.h      	r2, (r4, 0x5a)
     b86:	e40508c9 	addi      	r0, r5, 2250
     b8a:	3200      	movi      	r2, 0
     b8c:	5c28      	addu      	r1, r4, r2
     b8e:	d040002c 	ldr.b      	r12, (r0, r2 << 0)
     b92:	2200      	addi      	r2, 1
     b94:	3a46      	cmpnei      	r2, 6
     b96:	dd81005c 	st.b      	r12, (r1, 0x5c)
     b9a:	0bf9      	bt      	0xb8c	// b8c <dsleep_wakeup+0xb8c>
     b9c:	0157      	lrw      	r2, 0x0	// ebc <dsleep_wakeup+0xebc>
     b9e:	9304      	ld.w      	r0, (r3, 0x10)
     ba0:	b455      	st.w      	r2, (r4, 0x54)
     ba2:	934e      	ld.w      	r2, (r3, 0x38)
     ba4:	6480      	cmphs      	r0, r2
     ba6:	93ee      	ld.w      	r7, (r3, 0x38)
     ba8:	0d9a      	bf      	0xedc	// edc <dsleep_wakeup+0xedc>
     baa:	01d9      	lrw      	r6, 0x0	// ec0 <dsleep_wakeup+0xec0>
     bac:	58fd      	subu      	r7, r0, r7
     bae:	3100      	movi      	r1, 0
     bb0:	3002      	movi      	r0, 2
     bb2:	e0000000 	bsr      	0x0	// 0 <lhw_start_cca>
     bb6:	9660      	ld.w      	r3, (r6, 0x0)
     bb8:	3000      	movi      	r0, 0
     bba:	934c      	ld.w      	r2, (r3, 0x30)
     bbc:	3a89      	bclri      	r2, 9
     bbe:	b34c      	st.w      	r2, (r3, 0x30)
     bc0:	934c      	ld.w      	r2, (r3, 0x30)
     bc2:	2852      	subi      	r0, 83
     bc4:	ec420400 	ori      	r2, r2, 1024
     bc8:	601e      	subu      	r0, r7
     bca:	b34c      	st.w      	r2, (r3, 0x30)
     bcc:	7400      	zextb      	r0, r0
     bce:	e0000000 	bsr      	0x0	// 0 <lhw_start_tx>
     bd2:	9640      	ld.w      	r2, (r6, 0x0)
     bd4:	9272      	ld.w      	r3, (r2, 0x48)
     bd6:	e4632020 	andi      	r3, r3, 32
     bda:	e903fffd 	bez      	r3, 0xbd4	// bd4 <dsleep_wakeup+0xbd4>
     bde:	3320      	movi      	r3, 32
     be0:	b272      	st.w      	r3, (r2, 0x48)
     be2:	310a      	movi      	r1, 10
     be4:	0207      	lrw      	r0, 0x0	// ec4 <dsleep_wakeup+0xec4>
     be6:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     bea:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     bee:	d86508c1 	ld.b      	r3, (r5, 0x8c1)
     bf2:	e4632020 	andi      	r3, r3, 32
     bf6:	e9230179 	bnez      	r3, 0xee8	// ee8 <dsleep_wakeup+0xee8>
     bfa:	8464      	ld.b      	r3, (r4, 0x4)
     bfc:	e4432020 	andi      	r2, r3, 32
     c00:	e902000b 	bez      	r2, 0xc16	// c16 <dsleep_wakeup+0xc16>
     c04:	8445      	ld.b      	r2, (r4, 0x5)
     c06:	e4422002 	andi      	r2, r2, 2
     c0a:	3101      	movi      	r1, 1
     c0c:	e902016a 	bez      	r2, 0xee0	// ee0 <dsleep_wakeup+0xee0>
     c10:	c4615c07 	ins      	r3, r1, 7, 7
     c14:	a464      	st.b      	r3, (r4, 0x4)
     c16:	8464      	ld.b      	r3, (r4, 0x4)
     c18:	3200      	movi      	r2, 0
     c1a:	c4625c05 	ins      	r3, r2, 5, 5
     c1e:	a464      	st.b      	r3, (r4, 0x4)
     c20:	9640      	ld.w      	r2, (r6, 0x0)
     c22:	3180      	movi      	r1, 128
     c24:	d8622109 	ld.w      	r3, (r2, 0x424)
     c28:	4127      	lsli      	r1, r1, 7
     c2a:	68c4      	and      	r3, r1
     c2c:	e903000b 	bez      	r3, 0xc42	// c42 <dsleep_wakeup+0xc42>
     c30:	d8222109 	ld.w      	r1, (r2, 0x424)
     c34:	ea033fff 	movi      	r3, 16383
     c38:	684c      	and      	r1, r3
     c3a:	e40508bf 	addi      	r0, r5, 2240
     c3e:	e0000000 	bsr      	0x0	// 0 <system_sleep_rxdata_hook>
     c42:	94c2      	ld.w      	r6, (r4, 0x8)
     c44:	d86608c0 	ld.b      	r3, (r6, 0x8c0)
     c48:	3b5c      	cmpnei      	r3, 28
     c4a:	0836      	bt      	0xcb6	// cb6 <dsleep_wakeup+0xcb6>
     c4c:	8466      	ld.b      	r3, (r4, 0x6)
     c4e:	e4632008 	andi      	r3, r3, 8
     c52:	e4e608bf 	addi      	r7, r6, 2240
     c56:	e903014f 	bez      	r3, 0xef4	// ef4 <dsleep_wakeup+0xef4>
     c5a:	8675      	ld.b      	r3, (r6, 0x15)
     c5c:	e4632020 	andi      	r3, r3, 32
     c60:	e903014a 	bez      	r3, 0xef4	// ef4 <dsleep_wakeup+0xef4>
     c64:	8744      	ld.b      	r2, (r7, 0x4)
     c66:	d866029c 	ld.b      	r3, (r6, 0x29c)
     c6a:	64ca      	cmpne      	r2, r3
     c6c:	0944      	bt      	0xef4	// ef4 <dsleep_wakeup+0xef4>
     c6e:	8745      	ld.b      	r2, (r7, 0x5)
     c70:	d866029d 	ld.b      	r3, (r6, 0x29d)
     c74:	64ca      	cmpne      	r2, r3
     c76:	093f      	bt      	0xef4	// ef4 <dsleep_wakeup+0xef4>
     c78:	8746      	ld.b      	r2, (r7, 0x6)
     c7a:	d866029e 	ld.b      	r3, (r6, 0x29e)
     c7e:	64ca      	cmpne      	r2, r3
     c80:	093a      	bt      	0xef4	// ef4 <dsleep_wakeup+0xef4>
     c82:	8747      	ld.b      	r2, (r7, 0x7)
     c84:	d866029f 	ld.b      	r3, (r6, 0x29f)
     c88:	64ca      	cmpne      	r2, r3
     c8a:	0935      	bt      	0xef4	// ef4 <dsleep_wakeup+0xef4>
     c8c:	8748      	ld.b      	r2, (r7, 0x8)
     c8e:	d86602a0 	ld.b      	r3, (r6, 0x2a0)
     c92:	64ca      	cmpne      	r2, r3
     c94:	0930      	bt      	0xef4	// ef4 <dsleep_wakeup+0xef4>
     c96:	8749      	ld.b      	r2, (r7, 0x9)
     c98:	d86602a1 	ld.b      	r3, (r6, 0x2a1)
     c9c:	64ca      	cmpne      	r2, r3
     c9e:	092b      	bt      	0xef4	// ef4 <dsleep_wakeup+0xef4>
     ca0:	8464      	ld.b      	r3, (r4, 0x4)
     ca2:	3201      	movi      	r2, 1
     ca4:	c4625c01 	ins      	r3, r2, 1, 1
     ca8:	a464      	st.b      	r3, (r4, 0x4)
     caa:	330e      	movi      	r3, 14
     cac:	dc660257 	st.b      	r3, (r6, 0x257)
     cb0:	0319      	lrw      	r0, 0x0	// ec8 <dsleep_wakeup+0xec8>
     cb2:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     cb6:	8464      	ld.b      	r3, (r4, 0x4)
     cb8:	e4632008 	andi      	r3, r3, 8
     cbc:	e9030054 	bez      	r3, 0xd64	// d64 <dsleep_wakeup+0xd64>
     cc0:	9462      	ld.w      	r3, (r4, 0x8)
     cc2:	8355      	ld.b      	r2, (r3, 0x15)
     cc4:	e4422007 	andi      	r2, r2, 7
     cc8:	3a41      	cmpnei      	r2, 1
     cca:	084d      	bt      	0xd64	// d64 <dsleep_wakeup+0xd64>
     ccc:	8313      	ld.b      	r0, (r3, 0x13)
     cce:	d8440124 	ld.b      	r2, (r4, 0x124)
     cd2:	5a20      	addu      	r1, r2, r0
     cd4:	d9842010 	ld.w      	r12, (r4, 0x40)
     cd8:	6470      	cmphs      	r12, r1
     cda:	0c45      	bf      	0xd64	// d64 <dsleep_wakeup+0xd64>
     cdc:	e9000044 	bez      	r0, 0xd64	// d64 <dsleep_wakeup+0xd64>
     ce0:	d98309f6 	ld.b      	r12, (r3, 0x9f6)
     ce4:	d82308c4 	ld.b      	r1, (r3, 0x8c4)
     ce8:	6472      	cmpne      	r12, r1
     cea:	083d      	bt      	0xd64	// d64 <dsleep_wakeup+0xd64>
     cec:	d98309f7 	ld.b      	r12, (r3, 0x9f7)
     cf0:	d82308c5 	ld.b      	r1, (r3, 0x8c5)
     cf4:	6472      	cmpne      	r12, r1
     cf6:	0837      	bt      	0xd64	// d64 <dsleep_wakeup+0xd64>
     cf8:	d98309f8 	ld.b      	r12, (r3, 0x9f8)
     cfc:	d82308c6 	ld.b      	r1, (r3, 0x8c6)
     d00:	6472      	cmpne      	r12, r1
     d02:	0831      	bt      	0xd64	// d64 <dsleep_wakeup+0xd64>
     d04:	d98309f9 	ld.b      	r12, (r3, 0x9f9)
     d08:	d82308c7 	ld.b      	r1, (r3, 0x8c7)
     d0c:	6472      	cmpne      	r12, r1
     d0e:	082b      	bt      	0xd64	// d64 <dsleep_wakeup+0xd64>
     d10:	d98309fa 	ld.b      	r12, (r3, 0x9fa)
     d14:	d82308c8 	ld.b      	r1, (r3, 0x8c8)
     d18:	6472      	cmpne      	r12, r1
     d1a:	0825      	bt      	0xd64	// d64 <dsleep_wakeup+0xd64>
     d1c:	d98309fb 	ld.b      	r12, (r3, 0x9fb)
     d20:	d82308c9 	ld.b      	r1, (r3, 0x8c9)
     d24:	6472      	cmpne      	r12, r1
     d26:	081f      	bt      	0xd64	// d64 <dsleep_wakeup+0xd64>
     d28:	e42308bf 	addi      	r1, r3, 2240
     d2c:	6048      	addu      	r1, r2
     d2e:	ea0c0014 	movi      	r12, 20
     d32:	8151      	ld.b      	r2, (r1, 0x11)
     d34:	3a51      	cmpnei      	r2, 17
     d36:	3204      	movi      	r2, 4
     d38:	c5820c20 	incf      	r12, r2, 0
     d3c:	3200      	movi      	r2, 0
     d3e:	c44c002d 	addu      	r13, r12, r2
     d42:	5ba8      	addu      	r5, r3, r2
     d44:	6344      	addu      	r13, r1
     d46:	d8a50119 	ld.b      	r5, (r5, 0x119)
     d4a:	d9ad0020 	ld.b      	r13, (r13, 0x20)
     d4e:	6756      	cmpne      	r5, r13
     d50:	080a      	bt      	0xd64	// d64 <dsleep_wakeup+0xd64>
     d52:	2200      	addi      	r2, 1
     d54:	6409      	cmplt      	r2, r0
     d56:	0bf4      	bt      	0xd3e	// d3e <dsleep_wakeup+0xd3e>
     d58:	121d      	lrw      	r0, 0x0	// ecc <dsleep_wakeup+0xecc>
     d5a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     d5e:	3300      	movi      	r3, 0
     d60:	dc64203a 	st.w      	r3, (r4, 0xe8)
     d64:	8464      	ld.b      	r3, (r4, 0x4)
     d66:	e4632008 	andi      	r3, r3, 8
     d6a:	e903005a 	bez      	r3, 0xe1e	// e1e <dsleep_wakeup+0xe1e>
     d6e:	9462      	ld.w      	r3, (r4, 0x8)
     d70:	8355      	ld.b      	r2, (r3, 0x15)
     d72:	e4422007 	andi      	r2, r2, 7
     d76:	3a41      	cmpnei      	r2, 1
     d78:	0853      	bt      	0xe1e	// e1e <dsleep_wakeup+0xe1e>
     d7a:	8314      	ld.b      	r0, (r3, 0x14)
     d7c:	d8440124 	ld.b      	r2, (r4, 0x124)
     d80:	5a20      	addu      	r1, r2, r0
     d82:	d9842010 	ld.w      	r12, (r4, 0x40)
     d86:	6470      	cmphs      	r12, r1
     d88:	0c4b      	bf      	0xe1e	// e1e <dsleep_wakeup+0xe1e>
     d8a:	e900004a 	bez      	r0, 0xe1e	// e1e <dsleep_wakeup+0xe1e>
     d8e:	d98309f6 	ld.b      	r12, (r3, 0x9f6)
     d92:	d82308c4 	ld.b      	r1, (r3, 0x8c4)
     d96:	6472      	cmpne      	r12, r1
     d98:	0843      	bt      	0xe1e	// e1e <dsleep_wakeup+0xe1e>
     d9a:	d98309f7 	ld.b      	r12, (r3, 0x9f7)
     d9e:	d82308c5 	ld.b      	r1, (r3, 0x8c5)
     da2:	6472      	cmpne      	r12, r1
     da4:	083d      	bt      	0xe1e	// e1e <dsleep_wakeup+0xe1e>
     da6:	d98309f8 	ld.b      	r12, (r3, 0x9f8)
     daa:	d82308c6 	ld.b      	r1, (r3, 0x8c6)
     dae:	6472      	cmpne      	r12, r1
     db0:	0837      	bt      	0xe1e	// e1e <dsleep_wakeup+0xe1e>
     db2:	d98309f9 	ld.b      	r12, (r3, 0x9f9)
     db6:	d82308c7 	ld.b      	r1, (r3, 0x8c7)
     dba:	6472      	cmpne      	r12, r1
     dbc:	0831      	bt      	0xe1e	// e1e <dsleep_wakeup+0xe1e>
     dbe:	d98309fa 	ld.b      	r12, (r3, 0x9fa)
     dc2:	d82308c8 	ld.b      	r1, (r3, 0x8c8)
     dc6:	6472      	cmpne      	r12, r1
     dc8:	082b      	bt      	0xe1e	// e1e <dsleep_wakeup+0xe1e>
     dca:	d98309fb 	ld.b      	r12, (r3, 0x9fb)
     dce:	d82308c9 	ld.b      	r1, (r3, 0x8c9)
     dd2:	6472      	cmpne      	r12, r1
     dd4:	0825      	bt      	0xe1e	// e1e <dsleep_wakeup+0xe1e>
     dd6:	e42308bf 	addi      	r1, r3, 2240
     dda:	6048      	addu      	r1, r2
     ddc:	ea0c0014 	movi      	r12, 20
     de0:	8151      	ld.b      	r2, (r1, 0x11)
     de2:	3a51      	cmpnei      	r2, 17
     de4:	3204      	movi      	r2, 4
     de6:	c5820c20 	incf      	r12, r2, 0
     dea:	3200      	movi      	r2, 0
     dec:	c44c002d 	addu      	r13, r12, r2
     df0:	5ba8      	addu      	r5, r3, r2
     df2:	6344      	addu      	r13, r1
     df4:	d8a50199 	ld.b      	r5, (r5, 0x199)
     df8:	d9ad0020 	ld.b      	r13, (r13, 0x20)
     dfc:	6756      	cmpne      	r5, r13
     dfe:	0810      	bt      	0xe1e	// e1e <dsleep_wakeup+0xe1e>
     e00:	2200      	addi      	r2, 1
     e02:	6409      	cmplt      	r2, r0
     e04:	0bf4      	bt      	0xdec	// dec <dsleep_wakeup+0xdec>
     e06:	1113      	lrw      	r0, 0x0	// ed0 <dsleep_wakeup+0xed0>
     e08:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     e0c:	8464      	ld.b      	r3, (r4, 0x4)
     e0e:	3201      	movi      	r2, 1
     e10:	c4625c01 	ins      	r3, r2, 1, 1
     e14:	a464      	st.b      	r3, (r4, 0x4)
     e16:	9462      	ld.w      	r3, (r4, 0x8)
     e18:	3208      	movi      	r2, 8
     e1a:	dc430257 	st.b      	r2, (r3, 0x257)
     e1e:	8466      	ld.b      	r3, (r4, 0x6)
     e20:	e4632008 	andi      	r3, r3, 8
     e24:	e903fd33 	bez      	r3, 0x88a	// 88a <dsleep_wakeup+0x88a>
     e28:	9462      	ld.w      	r3, (r4, 0x8)
     e2a:	8355      	ld.b      	r2, (r3, 0x15)
     e2c:	e4422020 	andi      	r2, r2, 32
     e30:	e902038d 	bez      	r2, 0x154a	// 154a <dsleep_wakeup+0x154a>
     e34:	d823029c 	ld.b      	r1, (r3, 0x29c)
     e38:	d84308ca 	ld.b      	r2, (r3, 0x8ca)
     e3c:	6486      	cmpne      	r1, r2
     e3e:	e860fd26 	bt      	0x88a	// 88a <dsleep_wakeup+0x88a>
     e42:	d823029d 	ld.b      	r1, (r3, 0x29d)
     e46:	d84308cb 	ld.b      	r2, (r3, 0x8cb)
     e4a:	6486      	cmpne      	r1, r2
     e4c:	e860fd1f 	bt      	0x88a	// 88a <dsleep_wakeup+0x88a>
     e50:	d823029e 	ld.b      	r1, (r3, 0x29e)
     e54:	d84308cc 	ld.b      	r2, (r3, 0x8cc)
     e58:	6486      	cmpne      	r1, r2
     e5a:	e860fd18 	bt      	0x88a	// 88a <dsleep_wakeup+0x88a>
     e5e:	d823029f 	ld.b      	r1, (r3, 0x29f)
     e62:	d84308cd 	ld.b      	r2, (r3, 0x8cd)
     e66:	6486      	cmpne      	r1, r2
     e68:	e860fd11 	bt      	0x88a	// 88a <dsleep_wakeup+0x88a>
     e6c:	d82302a0 	ld.b      	r1, (r3, 0x2a0)
     e70:	d84308ce 	ld.b      	r2, (r3, 0x8ce)
     e74:	6486      	cmpne      	r1, r2
     e76:	e860fd0a 	bt      	0x88a	// 88a <dsleep_wakeup+0x88a>
     e7a:	d82302a1 	ld.b      	r1, (r3, 0x2a1)
     e7e:	d84308cf 	ld.b      	r2, (r3, 0x8cf)
     e82:	6486      	cmpne      	r1, r2
     e84:	e860fd03 	bt      	0x88a	// 88a <dsleep_wakeup+0x88a>
     e88:	8444      	ld.b      	r2, (r4, 0x4)
     e8a:	3101      	movi      	r1, 1
     e8c:	c4415c01 	ins      	r2, r1, 1, 1
     e90:	a444      	st.b      	r2, (r4, 0x4)
     e92:	320e      	movi      	r2, 14
     e94:	dc430257 	st.b      	r2, (r3, 0x257)
     e98:	100f      	lrw      	r0, 0x0	// ed4 <dsleep_wakeup+0xed4>
     e9a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
     e9e:	e800fcf6 	br      	0x88a	// 88a <dsleep_wakeup+0x88a>
     ea2:	e441200f 	andi      	r2, r1, 15
     ea6:	e9220019 	bnez      	r2, 0xed8	// ed8 <dsleep_wakeup+0xed8>
     eaa:	d84548c1 	ld.bs      	r2, (r5, 0x8c1)
     eae:	3adf      	btsti      	r2, 31
     eb0:	301a      	movi      	r0, 26
     eb2:	3218      	movi      	r2, 24
     eb4:	c4400c40 	inct      	r2, r0, 0
     eb8:	0629      	br      	0xb0a	// b0a <dsleep_wakeup+0xb0a>
	...
     ed6:	0000      	.short	0x0000
     ed8:	3218      	movi      	r2, 24
     eda:	0618      	br      	0xb0a	// b0a <dsleep_wakeup+0xb0a>
     edc:	2800      	subi      	r0, 1
     ede:	0666      	br      	0xbaa	// baa <dsleep_wakeup+0xbaa>
     ee0:	c4615c06 	ins      	r3, r1, 6, 6
     ee4:	a464      	st.b      	r3, (r4, 0x4)
     ee6:	0698      	br      	0xc16	// c16 <dsleep_wakeup+0xc16>
     ee8:	8464      	ld.b      	r3, (r4, 0x4)
     eea:	3201      	movi      	r2, 1
     eec:	c4625c05 	ins      	r3, r2, 5, 5
     ef0:	a464      	st.b      	r3, (r4, 0x4)
     ef2:	0697      	br      	0xc20	// c20 <dsleep_wakeup+0xc20>
     ef4:	8744      	ld.b      	r2, (r7, 0x4)
     ef6:	d86609f0 	ld.b      	r3, (r6, 0x9f0)
     efa:	64ca      	cmpne      	r2, r3
     efc:	0add      	bt      	0xcb6	// cb6 <dsleep_wakeup+0xcb6>
     efe:	8745      	ld.b      	r2, (r7, 0x5)
     f00:	d86609f1 	ld.b      	r3, (r6, 0x9f1)
     f04:	64ca      	cmpne      	r2, r3
     f06:	0ad8      	bt      	0xcb6	// cb6 <dsleep_wakeup+0xcb6>
     f08:	8746      	ld.b      	r2, (r7, 0x6)
     f0a:	d86609f2 	ld.b      	r3, (r6, 0x9f2)
     f0e:	64ca      	cmpne      	r2, r3
     f10:	0ad3      	bt      	0xcb6	// cb6 <dsleep_wakeup+0xcb6>
     f12:	8747      	ld.b      	r2, (r7, 0x7)
     f14:	d86609f3 	ld.b      	r3, (r6, 0x9f3)
     f18:	64ca      	cmpne      	r2, r3
     f1a:	0ace      	bt      	0xcb6	// cb6 <dsleep_wakeup+0xcb6>
     f1c:	8748      	ld.b      	r2, (r7, 0x8)
     f1e:	d86609f4 	ld.b      	r3, (r6, 0x9f4)
     f22:	64ca      	cmpne      	r2, r3
     f24:	0ac9      	bt      	0xcb6	// cb6 <dsleep_wakeup+0xcb6>
     f26:	8749      	ld.b      	r2, (r7, 0x9)
     f28:	d86609f5 	ld.b      	r3, (r6, 0x9f5)
     f2c:	64ca      	cmpne      	r2, r3
     f2e:	0ac4      	bt      	0xcb6	// cb6 <dsleep_wakeup+0xcb6>
     f30:	9468      	ld.w      	r3, (r4, 0x20)
     f32:	3201      	movi      	r2, 1
     f34:	d8632056 	ld.w      	r3, (r3, 0x158)
     f38:	dc64012a 	st.b      	r3, (r4, 0x12a)
     f3c:	8464      	ld.b      	r3, (r4, 0x4)
     f3e:	c4625c02 	ins      	r3, r2, 2, 2
     f42:	d82a2000 	ld.w      	r1, (r10, 0x0)
     f46:	a464      	st.b      	r3, (r4, 0x4)
     f48:	3300      	movi      	r3, 0
     f4a:	dc64203c 	st.w      	r3, (r4, 0xf0)
     f4e:	d864203b 	ld.w      	r3, (r4, 0xec)
     f52:	60c8      	addu      	r3, r2
     f54:	914e      	ld.w      	r2, (r1, 0x38)
     f56:	d801202d 	ld.w      	r0, (r1, 0xb4)
     f5a:	e4002100 	andi      	r0, r0, 256
     f5e:	dc64203b 	st.w      	r3, (r4, 0xec)
     f62:	dc442044 	st.w      	r2, (r4, 0x110)
     f66:	d864004c 	ld.b      	r3, (r4, 0x4c)
     f6a:	e90000a5 	bez      	r0, 0x10b4	// 10b4 <dsleep_wakeup+0x10b4>
     f6e:	d821202d 	ld.w      	r1, (r1, 0xb4)
     f72:	e4212200 	andi      	r1, r1, 512
     f76:	e4632003 	andi      	r3, r3, 3
     f7a:	4368      	lsli      	r3, r3, 8
     f7c:	e9010095 	bez      	r1, 0x10a6	// 10a6 <dsleep_wakeup+0x10a6>
     f80:	d824004b 	ld.b      	r1, (r4, 0x4b)
     f84:	2307      	addi      	r3, 8
     f86:	60c4      	addu      	r3, r1
     f88:	3128      	movi      	r1, 40
     f8a:	7cc4      	mult      	r3, r1
     f8c:	2327      	addi      	r3, 40
     f8e:	64c8      	cmphs      	r2, r3
     f90:	dc64203f 	st.w      	r3, (r4, 0xfc)
     f94:	0803      	bt      	0xf9a	// f9a <dsleep_wakeup+0xf9a>
     f96:	dc642044 	st.w      	r3, (r4, 0x110)
     f9a:	9470      	ld.w      	r3, (r4, 0x40)
     f9c:	60dc      	addu      	r3, r7
     f9e:	b862      	st.w      	r3, (r14, 0x8)
     fa0:	d86608cb 	ld.b      	r3, (r6, 0x8cb)
     fa4:	4368      	lsli      	r3, r3, 8
     fa6:	d82608ca 	ld.b      	r1, (r6, 0x8ca)
     faa:	6c4c      	or      	r1, r3
     fac:	d86608cc 	ld.b      	r3, (r6, 0x8cc)
     fb0:	4370      	lsli      	r3, r3, 16
     fb2:	d84608cd 	ld.b      	r2, (r6, 0x8cd)
     fb6:	6cc4      	or      	r3, r1
     fb8:	4258      	lsli      	r2, r2, 24
     fba:	6cc8      	or      	r3, r2
     fbc:	b861      	st.w      	r3, (r14, 0x4)
     fbe:	8761      	ld.b      	r3, (r7, 0x1)
     fc0:	e4632001 	andi      	r3, r3, 1
     fc4:	e9030082 	bez      	r3, 0x10c8	// 10c8 <dsleep_wakeup+0x10c8>
     fc8:	d86608cf 	ld.b      	r3, (r6, 0x8cf)
     fcc:	d84608d0 	ld.b      	r2, (r6, 0x8d0)
     fd0:	4250      	lsli      	r2, r2, 16
     fd2:	4368      	lsli      	r3, r3, 8
     fd4:	60c8      	addu      	r3, r2
     fd6:	d84608d1 	ld.b      	r2, (r6, 0x8d1)
     fda:	4258      	lsli      	r2, r2, 24
     fdc:	60c8      	addu      	r3, r2
     fde:	e4a608d1 	addi      	r5, r6, 2258
     fe2:	dc642045 	st.w      	r3, (r4, 0x114)
     fe6:	8761      	ld.b      	r3, (r7, 0x1)
     fe8:	e4432002 	andi      	r2, r3, 2
     fec:	3a40      	cmpnei      	r2, 0
     fee:	e4632004 	andi      	r3, r3, 4
     ff2:	c4a50c44 	inct      	r5, r5, 4
     ff6:	3b40      	cmpnei      	r3, 0
     ff8:	3300      	movi      	r3, 0
     ffa:	b860      	st.w      	r3, (r14, 0x0)
     ffc:	c4a50c41 	inct      	r5, r5, 1
    1000:	127b      	lrw      	r3, 0x0	// 116c <dsleep_wakeup+0x116c>
    1002:	b865      	st.w      	r3, (r14, 0x14)
    1004:	127b      	lrw      	r3, 0x0	// 1170 <dsleep_wakeup+0x1170>
    1006:	b866      	st.w      	r3, (r14, 0x18)
    1008:	9862      	ld.w      	r3, (r14, 0x8)
    100a:	64d4      	cmphs      	r5, r3
    100c:	0c66      	bf      	0x10d8	// 10d8 <dsleep_wakeup+0x10d8>
    100e:	9402      	ld.w      	r0, (r4, 0x8)
    1010:	d8442046 	ld.w      	r2, (r4, 0x118)
    1014:	d860227f 	ld.w      	r3, (r0, 0x9fc)
    1018:	d8a009c6 	ld.b      	r5, (r0, 0x9c6)
    101c:	d98e2001 	ld.w      	r12, (r14, 0x4)
    1020:	7d4c      	mult      	r5, r3
    1022:	6708      	cmphs      	r2, r12
    1024:	d8642048 	ld.w      	r3, (r4, 0x120)
    1028:	60c8      	addu      	r3, r2
    102a:	5d34      	addu      	r1, r5, r5
    102c:	604c      	addu      	r1, r3
    102e:	0806      	bt      	0x103a	// 103a <dsleep_wakeup+0x103a>
    1030:	3200      	movi      	r2, 0
    1032:	2a00      	subi      	r2, 1
    1034:	64c4      	cmphs      	r1, r3
    1036:	c4220c20 	incf      	r1, r2, 0
    103a:	d8442047 	ld.w      	r2, (r4, 0x11c)
    103e:	d98e2000 	ld.w      	r12, (r14, 0x0)
    1042:	64b0      	cmphs      	r12, r2
    1044:	0c09      	bf      	0x1056	// 1056 <dsleep_wakeup+0x1056>
    1046:	670a      	cmpne      	r2, r12
    1048:	081a      	bt      	0x107c	// 107c <dsleep_wakeup+0x107c>
    104a:	60d6      	subu      	r3, r5
    104c:	9841      	ld.w      	r2, (r14, 0x4)
    104e:	64c8      	cmphs      	r2, r3
    1050:	0c03      	bf      	0x1056	// 1056 <dsleep_wakeup+0x1056>
    1052:	6484      	cmphs      	r1, r2
    1054:	0814      	bt      	0x107c	// 107c <dsleep_wakeup+0x107c>
    1056:	8445      	ld.b      	r2, (r4, 0x5)
    1058:	3301      	movi      	r3, 1
    105a:	c4435c04 	ins      	r2, r3, 4, 4
    105e:	a445      	st.b      	r2, (r4, 0x5)
    1060:	8444      	ld.b      	r2, (r4, 0x4)
    1062:	c4435c01 	ins      	r2, r3, 1, 1
    1066:	a444      	st.b      	r2, (r4, 0x4)
    1068:	8055      	ld.b      	r2, (r0, 0x15)
    106a:	c4435c03 	ins      	r2, r3, 3, 3
    106e:	3306      	movi      	r3, 6
    1070:	a055      	st.b      	r2, (r0, 0x15)
    1072:	dc600257 	st.b      	r3, (r0, 0x257)
    1076:	1200      	lrw      	r0, 0x0	// 1174 <dsleep_wakeup+0x1174>
    1078:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    107c:	9860      	ld.w      	r3, (r14, 0x0)
    107e:	d84648c1 	ld.bs      	r2, (r6, 0x8c1)
    1082:	dc642047 	st.w      	r3, (r4, 0x11c)
    1086:	9861      	ld.w      	r3, (r14, 0x4)
    1088:	dc642046 	st.w      	r3, (r4, 0x118)
    108c:	dca42048 	st.w      	r5, (r4, 0x120)
    1090:	8466      	ld.b      	r3, (r4, 0x6)
    1092:	e9a20253 	bhsz      	r2, 0x1538	// 1538 <dsleep_wakeup+0x1538>
    1096:	3201      	movi      	r2, 1
    1098:	c4625c00 	ins      	r3, r2, 0, 0
    109c:	a466      	st.b      	r3, (r4, 0x6)
    109e:	1117      	lrw      	r0, 0x0	// 1178 <dsleep_wakeup+0x1178>
    10a0:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    10a4:	0609      	br      	0xcb6	// cb6 <dsleep_wakeup+0xcb6>
    10a6:	d824004b 	ld.b      	r1, (r4, 0x4b)
    10aa:	2305      	addi      	r3, 6
    10ac:	60c4      	addu      	r3, r1
    10ae:	3128      	movi      	r1, 40
    10b0:	7cc4      	mult      	r3, r1
    10b2:	076d      	br      	0xf8c	// f8c <dsleep_wakeup+0xf8c>
    10b4:	e4632003 	andi      	r3, r3, 3
    10b8:	4368      	lsli      	r3, r3, 8
    10ba:	d824004b 	ld.b      	r1, (r4, 0x4b)
    10be:	230d      	addi      	r3, 14
    10c0:	60c4      	addu      	r3, r1
    10c2:	3128      	movi      	r1, 40
    10c4:	7cc4      	mult      	r3, r1
    10c6:	0763      	br      	0xf8c	// f8c <dsleep_wakeup+0xf8c>
    10c8:	110d      	lrw      	r0, 0x0	// 117c <dsleep_wakeup+0x117c>
    10ca:	e4a608ce 	addi      	r5, r6, 2255
    10ce:	dc642045 	st.w      	r3, (r4, 0x114)
    10d2:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    10d6:	0788      	br      	0xfe6	// fe6 <dsleep_wakeup+0xfe6>
    10d8:	8560      	ld.b      	r3, (r5, 0x0)
    10da:	eb4300d5 	cmpnei      	r3, 213
    10de:	0c18      	bf      	0x110e	// 110e <dsleep_wakeup+0x110e>
    10e0:	eb0300d5 	cmphsi      	r3, 214
    10e4:	080b      	bt      	0x10fa	// 10fa <dsleep_wakeup+0x10fa>
    10e6:	3b45      	cmpnei      	r3, 5
    10e8:	0c20      	bf      	0x1128	// 1128 <dsleep_wakeup+0x1128>
    10ea:	eb430025 	cmpnei      	r3, 37
    10ee:	e8400203 	bf      	0x14f4	// 14f4 <dsleep_wakeup+0x14f4>
    10f2:	8561      	ld.b      	r3, (r5, 0x1)
    10f4:	2301      	addi      	r3, 2
    10f6:	614c      	addu      	r5, r3
    10f8:	0788      	br      	0x1008	// 1008 <dsleep_wakeup+0x1008>
    10fa:	eb4300d6 	cmpnei      	r3, 214
    10fe:	0df2      	bf      	0x14e2	// 14e2 <dsleep_wakeup+0x14e2>
    1100:	eb4300dd 	cmpnei      	r3, 221
    1104:	0bf7      	bt      	0x10f2	// 10f2 <dsleep_wakeup+0x10f2>
    1106:	6c17      	mov      	r0, r5
    1108:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    110c:	07f3      	br      	0x10f2	// 10f2 <dsleep_wakeup+0x10f2>
    110e:	8567      	ld.b      	r3, (r5, 0x7)
    1110:	4368      	lsli      	r3, r3, 8
    1112:	8506      	ld.b      	r0, (r5, 0x6)
    1114:	c4032421 	or      	r1, r3, r0
    1118:	8568      	ld.b      	r3, (r5, 0x8)
    111a:	4370      	lsli      	r3, r3, 16
    111c:	8549      	ld.b      	r2, (r5, 0x9)
    111e:	6cc4      	or      	r3, r1
    1120:	4258      	lsli      	r2, r2, 24
    1122:	6cc8      	or      	r3, r2
    1124:	b860      	st.w      	r3, (r14, 0x0)
    1126:	07e6      	br      	0x10f2	// 10f2 <dsleep_wakeup+0x10f2>
    1128:	8562      	ld.b      	r3, (r5, 0x2)
    112a:	5d26      	addi      	r1, r5, 2
    112c:	dc640127 	st.b      	r3, (r4, 0x127)
    1130:	9442      	ld.w      	r2, (r4, 0x8)
    1132:	8161      	ld.b      	r3, (r1, 0x1)
    1134:	dc6209c6 	st.b      	r3, (r2, 0x9c6)
    1138:	8102      	ld.b      	r0, (r1, 0x2)
    113a:	e460203e 	andi      	r3, r0, 62
    113e:	eb43003e 	cmpnei      	r3, 62
    1142:	8561      	ld.b      	r3, (r5, 0x1)
    1144:	099a      	bt      	0x1478	// 1478 <dsleep_wakeup+0x1478>
    1146:	74cc      	zextb      	r3, r3
    1148:	3b03      	cmphsi      	r3, 4
    114a:	0d84      	bf      	0x1452	// 1452 <dsleep_wakeup+0x1452>
    114c:	d86214e2 	ld.h      	r3, (r2, 0x9c4)
    1150:	ea023fff 	movi      	r2, 16383
    1154:	c443202b 	and      	r11, r3, r2
    1158:	8163      	ld.b      	r3, (r1, 0x3)
    115a:	e4632007 	andi      	r3, r3, 7
    115e:	3b06      	cmphsi      	r3, 7
    1160:	0976      	bt      	0x144c	// 144c <dsleep_wakeup+0x144c>
    1162:	1048      	lrw      	r2, 0x0	// 1180 <dsleep_wakeup+0x1180>
    1164:	d0620883 	ldr.w      	r3, (r2, r3 << 2)
    1168:	780c      	jmp      	r3
	...
    1182:	0000      	.short	0x0000
    1184:	8142      	ld.b      	r2, (r1, 0x2)
    1186:	33c0      	movi      	r3, 192
    1188:	4365      	lsli      	r3, r3, 5
    118a:	4245      	lsli      	r2, r2, 5
    118c:	688c      	and      	r2, r3
    118e:	8163      	ld.b      	r3, (r1, 0x3)
    1190:	4b63      	lsri      	r3, r3, 3
    1192:	4366      	lsli      	r3, r3, 6
    1194:	608c      	addu      	r2, r3
    1196:	8164      	ld.b      	r3, (r1, 0x4)
    1198:	b863      	st.w      	r3, (r14, 0xc)
    119a:	3101      	movi      	r1, 1
    119c:	3300      	movi      	r3, 0
    119e:	7489      	zexth      	r2, r2
    11a0:	6c0f      	mov      	r0, r3
    11a2:	e5050001 	addi      	r8, r5, 2
    11a6:	6e47      	mov      	r9, r1
    11a8:	d98e2003 	ld.w      	r12, (r14, 0xc)
    11ac:	7301      	lsr      	r12, r0
    11ae:	e58c2001 	andi      	r12, r12, 1
    11b2:	e90c001b 	bez      	r12, 0x11e8	// 11e8 <dsleep_wakeup+0x11e8>
    11b6:	59e2      	addi      	r7, r1, 1
    11b8:	6060      	addu      	r1, r8
    11ba:	ea0c0000 	movi      	r12, 0
    11be:	8124      	ld.b      	r1, (r1, 0x4)
    11c0:	b824      	st.w      	r1, (r14, 0x10)
    11c2:	6c4b      	mov      	r1, r2
    11c4:	d9ae2004 	ld.w      	r13, (r14, 0x10)
    11c8:	7371      	lsr      	r13, r12
    11ca:	e5ad2001 	andi      	r13, r13, 1
    11ce:	e90d0005 	bez      	r13, 0x11d8	// 11d8 <dsleep_wakeup+0x11d8>
    11d2:	66c6      	cmpne      	r1, r11
    11d4:	c4690c20 	incf      	r3, r9, 0
    11d8:	e58c0000 	addi      	r12, r12, 1
    11dc:	eb4c0008 	cmpnei      	r12, 8
    11e0:	2100      	addi      	r1, 1
    11e2:	7445      	zexth      	r1, r1
    11e4:	0bf0      	bt      	0x11c4	// 11c4 <dsleep_wakeup+0x11c4>
    11e6:	6c5f      	mov      	r1, r7
    11e8:	2000      	addi      	r0, 1
    11ea:	3848      	cmpnei      	r0, 8
    11ec:	2207      	addi      	r2, 8
    11ee:	7489      	zexth      	r2, r2
    11f0:	0bdc      	bt      	0x11a8	// 11a8 <dsleep_wakeup+0x11a8>
    11f2:	e9230013 	bnez      	r3, 0x1218	// 1218 <dsleep_wakeup+0x1218>
    11f6:	052e      	br      	0x1452	// 1452 <dsleep_wakeup+0x1452>
    11f8:	8142      	ld.b      	r2, (r1, 0x2)
    11fa:	33c0      	movi      	r3, 192
    11fc:	4365      	lsli      	r3, r3, 5
    11fe:	4245      	lsli      	r2, r2, 5
    1200:	688c      	and      	r2, r3
    1202:	8163      	ld.b      	r3, (r1, 0x3)
    1204:	4b63      	lsri      	r3, r3, 3
    1206:	4366      	lsli      	r3, r3, 6
    1208:	60c8      	addu      	r3, r2
    120a:	8144      	ld.b      	r2, (r1, 0x4)
    120c:	e442203f 	andi      	r2, r2, 63
    1210:	60c8      	addu      	r3, r2
    1212:	74cd      	zexth      	r3, r3
    1214:	64ee      	cmpne      	r11, r3
    1216:	091e      	bt      	0x1452	// 1452 <dsleep_wakeup+0x1452>
    1218:	9806      	ld.w      	r0, (r14, 0x18)
    121a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    121e:	3701      	movi      	r7, 1
    1220:	8464      	ld.b      	r3, (r4, 0x4)
    1222:	c4675c03 	ins      	r3, r7, 3, 3
    1226:	c4675c05 	ins      	r3, r7, 5, 5
    122a:	a464      	st.b      	r3, (r4, 0x4)
    122c:	9462      	ld.w      	r3, (r4, 0x8)
    122e:	8375      	ld.b      	r3, (r3, 0x15)
    1230:	e4632007 	andi      	r3, r3, 7
    1234:	3b41      	cmpnei      	r3, 1
    1236:	0d3e      	bf      	0x14b2	// 14b2 <dsleep_wakeup+0x14b2>
    1238:	0106      	lrw      	r0, 0x0	// 159c <dsleep_wakeup+0x159c>
    123a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    123e:	8464      	ld.b      	r3, (r4, 0x4)
    1240:	c4675c01 	ins      	r3, r7, 1, 1
    1244:	a464      	st.b      	r3, (r4, 0x4)
    1246:	9462      	ld.w      	r3, (r4, 0x8)
    1248:	3202      	movi      	r2, 2
    124a:	dc430257 	st.b      	r2, (r3, 0x257)
    124e:	3100      	movi      	r1, 0
    1250:	8355      	ld.b      	r2, (r3, 0x15)
    1252:	c4415c03 	ins      	r2, r1, 3, 3
    1256:	a355      	st.b      	r2, (r3, 0x15)
    1258:	8464      	ld.b      	r3, (r4, 0x4)
    125a:	e4632008 	andi      	r3, r3, 8
    125e:	e903ff4a 	bez      	r3, 0x10f2	// 10f2 <dsleep_wakeup+0x10f2>
    1262:	9462      	ld.w      	r3, (r4, 0x8)
    1264:	d8032281 	ld.w      	r0, (r3, 0xa04)
    1268:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    126c:	9865      	ld.w      	r3, (r14, 0x14)
    126e:	9402      	ld.w      	r0, (r4, 0x8)
    1270:	9320      	ld.w      	r1, (r3, 0x0)
    1272:	9170      	ld.w      	r3, (r1, 0x40)
    1274:	3b84      	bclri      	r3, 4
    1276:	3b85      	bclri      	r3, 5
    1278:	b170      	st.w      	r3, (r1, 0x40)
    127a:	d86009c7 	ld.b      	r3, (r0, 0x9c7)
    127e:	4344      	lsli      	r2, r3, 4
    1280:	d9812010 	ld.w      	r12, (r1, 0x40)
    1284:	e4422030 	andi      	r2, r2, 48
    1288:	6cb0      	or      	r2, r12
    128a:	b150      	st.w      	r2, (r1, 0x40)
    128c:	9448      	ld.w      	r2, (r4, 0x20)
    128e:	9220      	ld.w      	r1, (r2, 0x0)
    1290:	3990      	bclri      	r1, 16
    1292:	3991      	bclri      	r1, 17
    1294:	b220      	st.w      	r1, (r2, 0x0)
    1296:	d9822000 	ld.w      	r12, (r2, 0x0)
    129a:	4330      	lsli      	r1, r3, 16
    129c:	6c70      	or      	r1, r12
    129e:	b220      	st.w      	r1, (r2, 0x0)
    12a0:	9446      	ld.w      	r2, (r4, 0x18)
    12a2:	4368      	lsli      	r3, r3, 8
    12a4:	9238      	ld.w      	r1, (r2, 0x60)
    12a6:	3988      	bclri      	r1, 8
    12a8:	3989      	bclri      	r1, 9
    12aa:	6cc4      	or      	r3, r1
    12ac:	b278      	st.w      	r3, (r2, 0x60)
    12ae:	3100      	movi      	r1, 0
    12b0:	9278      	ld.w      	r3, (r2, 0x60)
    12b2:	2907      	subi      	r1, 8
    12b4:	68c4      	and      	r3, r1
    12b6:	b278      	st.w      	r3, (r2, 0x60)
    12b8:	9278      	ld.w      	r3, (r2, 0x60)
    12ba:	ec630005 	ori      	r3, r3, 5
    12be:	b278      	st.w      	r3, (r2, 0x60)
    12c0:	3100      	movi      	r1, 0
    12c2:	9278      	ld.w      	r3, (r2, 0x60)
    12c4:	29e0      	subi      	r1, 225
    12c6:	68c4      	and      	r3, r1
    12c8:	b278      	st.w      	r3, (r2, 0x60)
    12ca:	9278      	ld.w      	r3, (r2, 0x60)
    12cc:	ec6300a0 	ori      	r3, r3, 160
    12d0:	b278      	st.w      	r3, (r2, 0x60)
    12d2:	9278      	ld.w      	r3, (r2, 0x60)
    12d4:	ec630008 	ori      	r3, r3, 8
    12d8:	b278      	st.w      	r3, (r2, 0x60)
    12da:	9278      	ld.w      	r3, (r2, 0x60)
    12dc:	e4632008 	andi      	r3, r3, 8
    12e0:	e923fffd 	bnez      	r3, 0x12da	// 12da <dsleep_wakeup+0x12da>
    12e4:	d8600a51 	ld.b      	r3, (r0, 0xa51)
    12e8:	e4232007 	andi      	r1, r3, 7
    12ec:	926b      	ld.w      	r3, (r2, 0x2c)
    12ee:	3b8f      	bclri      	r3, 15
    12f0:	b26b      	st.w      	r3, (r2, 0x2c)
    12f2:	3000      	movi      	r0, 0
    12f4:	926b      	ld.w      	r3, (r2, 0x2c)
    12f6:	2807      	subi      	r0, 8
    12f8:	68c0      	and      	r3, r0
    12fa:	6cc4      	or      	r3, r1
    12fc:	b26b      	st.w      	r3, (r2, 0x2c)
    12fe:	926b      	ld.w      	r3, (r2, 0x2c)
    1300:	ec630008 	ori      	r3, r3, 8
    1304:	b26b      	st.w      	r3, (r2, 0x2c)
    1306:	926b      	ld.w      	r3, (r2, 0x2c)
    1308:	e4632008 	andi      	r3, r3, 8
    130c:	e923fffd 	bnez      	r3, 0x1306	// 1306 <dsleep_wakeup+0x1306>
    1310:	06f1      	br      	0x10f2	// 10f2 <dsleep_wakeup+0x10f2>
    1312:	8142      	ld.b      	r2, (r1, 0x2)
    1314:	33c0      	movi      	r3, 192
    1316:	4365      	lsli      	r3, r3, 5
    1318:	4245      	lsli      	r2, r2, 5
    131a:	688c      	and      	r2, r3
    131c:	8163      	ld.b      	r3, (r1, 0x3)
    131e:	4b63      	lsri      	r3, r3, 3
    1320:	4366      	lsli      	r3, r3, 6
    1322:	608c      	addu      	r2, r3
    1324:	3300      	movi      	r3, 0
    1326:	7489      	zexth      	r2, r2
    1328:	81e4      	ld.b      	r7, (r1, 0x4)
    132a:	6c0f      	mov      	r0, r3
    132c:	ea080001 	movi      	r8, 1
    1330:	65c1      	cmplt      	r0, r7
    1332:	0f60      	bf      	0x11f2	// 11f2 <dsleep_wakeup+0x11f2>
    1334:	2000      	addi      	r0, 1
    1336:	5d20      	addu      	r1, r5, r0
    1338:	ea0c0000 	movi      	r12, 0
    133c:	d9210006 	ld.b      	r9, (r1, 0x6)
    1340:	6c4b      	mov      	r1, r2
    1342:	c589404d 	lsr      	r13, r9, r12
    1346:	e5ad2001 	andi      	r13, r13, 1
    134a:	e90d0005 	bez      	r13, 0x1354	// 1354 <dsleep_wakeup+0x1354>
    134e:	66c6      	cmpne      	r1, r11
    1350:	c4680c20 	incf      	r3, r8, 0
    1354:	e58c0000 	addi      	r12, r12, 1
    1358:	eb4c0008 	cmpnei      	r12, 8
    135c:	2100      	addi      	r1, 1
    135e:	7445      	zexth      	r1, r1
    1360:	0bf1      	bt      	0x1342	// 1342 <dsleep_wakeup+0x1342>
    1362:	2207      	addi      	r2, 8
    1364:	7489      	zexth      	r2, r2
    1366:	07e5      	br      	0x1330	// 1330 <dsleep_wakeup+0x1330>
    1368:	8142      	ld.b      	r2, (r1, 0x2)
    136a:	33c0      	movi      	r3, 192
    136c:	4365      	lsli      	r3, r3, 5
    136e:	4245      	lsli      	r2, r2, 5
    1370:	688c      	and      	r2, r3
    1372:	8163      	ld.b      	r3, (r1, 0x3)
    1374:	4b63      	lsri      	r3, r3, 3
    1376:	4366      	lsli      	r3, r3, 6
    1378:	608c      	addu      	r2, r3
    137a:	7489      	zexth      	r2, r2
    137c:	64ad      	cmplt      	r11, r2
    137e:	0833      	bt      	0x13e4	// 13e4 <dsleep_wakeup+0x13e4>
    1380:	e462003e 	addi      	r3, r2, 63
    1384:	66cd      	cmplt      	r3, r11
    1386:	64c3      	mvcv      	r3
    1388:	74cc      	zextb      	r3, r3
    138a:	8124      	ld.b      	r1, (r1, 0x4)
    138c:	b823      	st.w      	r1, (r14, 0xc)
    138e:	3100      	movi      	r1, 0
    1390:	3001      	movi      	r0, 1
    1392:	e5050001 	addi      	r8, r5, 2
    1396:	6e47      	mov      	r9, r1
    1398:	d98e2003 	ld.w      	r12, (r14, 0xc)
    139c:	7305      	lsr      	r12, r1
    139e:	e58c2001 	andi      	r12, r12, 1
    13a2:	e90c001b 	bez      	r12, 0x13d8	// 13d8 <dsleep_wakeup+0x13d8>
    13a6:	58e2      	addi      	r7, r0, 1
    13a8:	6020      	addu      	r0, r8
    13aa:	ea0c0000 	movi      	r12, 0
    13ae:	8004      	ld.b      	r0, (r0, 0x4)
    13b0:	b804      	st.w      	r0, (r14, 0x10)
    13b2:	6c0b      	mov      	r0, r2
    13b4:	d9ae2004 	ld.w      	r13, (r14, 0x10)
    13b8:	7371      	lsr      	r13, r12
    13ba:	e5ad2001 	andi      	r13, r13, 1
    13be:	e90d0005 	bez      	r13, 0x13c8	// 13c8 <dsleep_wakeup+0x13c8>
    13c2:	66c2      	cmpne      	r0, r11
    13c4:	c4690c20 	incf      	r3, r9, 0
    13c8:	e58c0000 	addi      	r12, r12, 1
    13cc:	eb4c0008 	cmpnei      	r12, 8
    13d0:	2000      	addi      	r0, 1
    13d2:	7401      	zexth      	r0, r0
    13d4:	0bf0      	bt      	0x13b4	// 13b4 <dsleep_wakeup+0x13b4>
    13d6:	6c1f      	mov      	r0, r7
    13d8:	2100      	addi      	r1, 1
    13da:	3948      	cmpnei      	r1, 8
    13dc:	2207      	addi      	r2, 8
    13de:	7489      	zexth      	r2, r2
    13e0:	0bdc      	bt      	0x1398	// 1398 <dsleep_wakeup+0x1398>
    13e2:	0708      	br      	0x11f2	// 11f2 <dsleep_wakeup+0x11f2>
    13e4:	3300      	movi      	r3, 0
    13e6:	07d2      	br      	0x138a	// 138a <dsleep_wakeup+0x138a>
    13e8:	8142      	ld.b      	r2, (r1, 0x2)
    13ea:	33c0      	movi      	r3, 192
    13ec:	4365      	lsli      	r3, r3, 5
    13ee:	4245      	lsli      	r2, r2, 5
    13f0:	688c      	and      	r2, r3
    13f2:	8163      	ld.b      	r3, (r1, 0x3)
    13f4:	4b63      	lsri      	r3, r3, 3
    13f6:	4366      	lsli      	r3, r3, 6
    13f8:	608c      	addu      	r2, r3
    13fa:	7489      	zexth      	r2, r2
    13fc:	64ad      	cmplt      	r11, r2
    13fe:	0825      	bt      	0x1448	// 1448 <dsleep_wakeup+0x1448>
    1400:	e462007e 	addi      	r3, r2, 127
    1404:	66cd      	cmplt      	r3, r11
    1406:	64c3      	mvcv      	r3
    1408:	74cc      	zextb      	r3, r3
    140a:	81e4      	ld.b      	r7, (r1, 0x4)
    140c:	3100      	movi      	r1, 0
    140e:	6e07      	mov      	r8, r1
    1410:	65c5      	cmplt      	r1, r7
    1412:	0ef0      	bf      	0x11f2	// 11f2 <dsleep_wakeup+0x11f2>
    1414:	2100      	addi      	r1, 1
    1416:	5d04      	addu      	r0, r5, r1
    1418:	ea0c0000 	movi      	r12, 0
    141c:	d9200006 	ld.b      	r9, (r0, 0x6)
    1420:	6c0b      	mov      	r0, r2
    1422:	c589404d 	lsr      	r13, r9, r12
    1426:	e5ad2001 	andi      	r13, r13, 1
    142a:	e90d0005 	bez      	r13, 0x1434	// 1434 <dsleep_wakeup+0x1434>
    142e:	642e      	cmpne      	r11, r0
    1430:	c4680c20 	incf      	r3, r8, 0
    1434:	e58c0000 	addi      	r12, r12, 1
    1438:	eb4c0008 	cmpnei      	r12, 8
    143c:	2000      	addi      	r0, 1
    143e:	7401      	zexth      	r0, r0
    1440:	0bf1      	bt      	0x1422	// 1422 <dsleep_wakeup+0x1422>
    1442:	2207      	addi      	r2, 8
    1444:	7489      	zexth      	r2, r2
    1446:	07e5      	br      	0x1410	// 1410 <dsleep_wakeup+0x1410>
    1448:	3300      	movi      	r3, 0
    144a:	07e0      	br      	0x140a	// 140a <dsleep_wakeup+0x140a>
    144c:	1215      	lrw      	r0, 0x0	// 15a0 <dsleep_wakeup+0x15a0>
    144e:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    1452:	8465      	ld.b      	r3, (r4, 0x5)
    1454:	748c      	zextb      	r2, r3
    1456:	e4222002 	andi      	r1, r2, 2
    145a:	e9010030 	bez      	r1, 0x14ba	// 14ba <dsleep_wakeup+0x14ba>
    145e:	8464      	ld.b      	r3, (r4, 0x4)
    1460:	3201      	movi      	r2, 1
    1462:	c4625c07 	ins      	r3, r2, 7, 7
    1466:	a464      	st.b      	r3, (r4, 0x4)
    1468:	8464      	ld.b      	r3, (r4, 0x4)
    146a:	e46320f7 	andi      	r3, r3, 247
    146e:	3200      	movi      	r2, 0
    1470:	c4625c05 	ins      	r3, r2, 5, 5
    1474:	a464      	st.b      	r3, (r4, 0x4)
    1476:	06f1      	br      	0x1258	// 1258 <dsleep_wakeup+0x1258>
    1478:	d98214e2 	ld.h      	r12, (r2, 0x9c4)
    147c:	e40020fe 	andi      	r0, r0, 254
    1480:	c46c5542 	zext      	r2, r12, 10, 3
    1484:	2b03      	subi      	r3, 4
    1486:	6408      	cmphs      	r2, r0
    1488:	60c0      	addu      	r3, r0
    148a:	74cc      	zextb      	r3, r3
    148c:	0fe3      	bf      	0x1452	// 1452 <dsleep_wakeup+0x1452>
    148e:	648c      	cmphs      	r3, r2
    1490:	0fe1      	bf      	0x1452	// 1452 <dsleep_wakeup+0x1452>
    1492:	6082      	subu      	r2, r0
    1494:	7488      	zextb      	r2, r2
    1496:	6048      	addu      	r1, r2
    1498:	3301      	movi      	r3, 1
    149a:	e58c2007 	andi      	r12, r12, 7
    149e:	c583402c 	lsl      	r12, r3, r12
    14a2:	8163      	ld.b      	r3, (r1, 0x3)
    14a4:	6b0c      	and      	r12, r3
    14a6:	eb4c0000 	cmpnei      	r12, 0
    14aa:	c4000503 	mvc      	r3
    14ae:	74cc      	zextb      	r3, r3
    14b0:	06a1      	br      	0x11f2	// 11f2 <dsleep_wakeup+0x11f2>
    14b2:	111d      	lrw      	r0, 0x0	// 15a4 <dsleep_wakeup+0x15a4>
    14b4:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    14b8:	06d0      	br      	0x1258	// 1258 <dsleep_wakeup+0x1258>
    14ba:	8c22      	ld.h      	r1, (r4, 0x4)
    14bc:	e4212108 	andi      	r1, r1, 264
    14c0:	e9010008 	bez      	r1, 0x14d0	// 14d0 <dsleep_wakeup+0x14d0>
    14c4:	8464      	ld.b      	r3, (r4, 0x4)
    14c6:	3201      	movi      	r2, 1
    14c8:	c4625c06 	ins      	r3, r2, 6, 6
    14cc:	a464      	st.b      	r3, (r4, 0x4)
    14ce:	07cd      	br      	0x1468	// 1468 <dsleep_wakeup+0x1468>
    14d0:	e44220a0 	andi      	r2, r2, 160
    14d4:	e922ffca 	bnez      	r2, 0x1468	// 1468 <dsleep_wakeup+0x1468>
    14d8:	3201      	movi      	r2, 1
    14da:	c4625c02 	ins      	r3, r2, 2, 2
    14de:	a465      	st.b      	r3, (r4, 0x5)
    14e0:	07c4      	br      	0x1468	// 1468 <dsleep_wakeup+0x1468>
    14e2:	8563      	ld.b      	r3, (r5, 0x3)
    14e4:	8522      	ld.b      	r1, (r5, 0x2)
    14e6:	4368      	lsli      	r3, r3, 8
    14e8:	9442      	ld.w      	r2, (r4, 0x8)
    14ea:	60c4      	addu      	r3, r1
    14ec:	436a      	lsli      	r3, r3, 10
    14ee:	dc62227f 	st.w      	r3, (r2, 0x9fc)
    14f2:	0600      	br      	0x10f2	// 10f2 <dsleep_wakeup+0x10f2>
    14f4:	8561      	ld.b      	r3, (r5, 0x1)
    14f6:	3b43      	cmpnei      	r3, 3
    14f8:	d9050003 	ld.b      	r8, (r5, 0x3)
    14fc:	e860fdfb 	bt      	0x10f2	// 10f2 <dsleep_wakeup+0x10f2>
    1500:	33fa      	movi      	r3, 250
    1502:	4362      	lsli      	r3, r3, 2
    1504:	ea02aae6 	movi      	r2, 43750
    1508:	c4824902 	rotli      	r2, r2, 4
    150c:	7ce0      	mult      	r3, r8
    150e:	60c8      	addu      	r3, r2
    1510:	9442      	ld.w      	r2, (r4, 0x8)
    1512:	d8422281 	ld.w      	r2, (r2, 0xa04)
    1516:	648e      	cmpne      	r3, r2
    1518:	e840fded 	bf      	0x10f2	// 10f2 <dsleep_wakeup+0x10f2>
    151c:	d8e54004 	ld.bs      	r7, (r5, 0x4)
    1520:	1102      	lrw      	r0, 0x0	// 15a8 <dsleep_wakeup+0x15a8>
    1522:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    1526:	6c1f      	mov      	r0, r7
    1528:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    152c:	dce40128 	st.b      	r7, (r4, 0x128)
    1530:	dd040129 	st.b      	r8, (r4, 0x129)
    1534:	e800fddf 	br      	0x10f2	// 10f2 <dsleep_wakeup+0x10f2>
    1538:	3200      	movi      	r2, 0
    153a:	c4625c00 	ins      	r3, r2, 0, 0
    153e:	a466      	st.b      	r3, (r4, 0x6)
    1540:	101b      	lrw      	r0, 0x0	// 15ac <dsleep_wakeup+0x15ac>
    1542:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    1546:	e800fbb8 	br      	0xcb6	// cb6 <dsleep_wakeup+0xcb6>
    154a:	d84308c0 	ld.b      	r2, (r3, 0x8c0)
    154e:	eb420050 	cmpnei      	r2, 80
    1552:	e860f99c 	bt      	0x88a	// 88a <dsleep_wakeup+0x88a>
    1556:	94b0      	ld.w      	r5, (r4, 0x40)
    1558:	e4c308e3 	addi      	r6, r3, 2276
    155c:	e46308bf 	addi      	r3, r3, 2240
    1560:	614c      	addu      	r5, r3
    1562:	3701      	movi      	r7, 1
    1564:	ea880013 	lrw      	r8, 0x0	// 15b0 <dsleep_wakeup+0x15b0>
    1568:	6558      	cmphs      	r6, r5
    156a:	e860f990 	bt      	0x88a	// 88a <dsleep_wakeup+0x88a>
    156e:	8660      	ld.b      	r3, (r6, 0x0)
    1570:	e9230011 	bnez      	r3, 0x1592	// 1592 <dsleep_wakeup+0x1592>
    1574:	8601      	ld.b      	r0, (r6, 0x1)
    1576:	9442      	ld.w      	r2, (r4, 0x8)
    1578:	744c      	zextb      	r1, r3
    157a:	6404      	cmphs      	r1, r0
    157c:	0c1c      	bf      	0x15b4	// 15b4 <dsleep_wakeup+0x15b4>
    157e:	8464      	ld.b      	r3, (r4, 0x4)
    1580:	c4675c01 	ins      	r3, r7, 1, 1
    1584:	a464      	st.b      	r3, (r4, 0x4)
    1586:	330e      	movi      	r3, 14
    1588:	dc620257 	st.b      	r3, (r2, 0x257)
    158c:	6c23      	mov      	r0, r8
    158e:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    1592:	8661      	ld.b      	r3, (r6, 0x1)
    1594:	2301      	addi      	r3, 2
    1596:	618c      	addu      	r6, r3
    1598:	07e8      	br      	0x1568	// 1568 <dsleep_wakeup+0x1568>
	...
    15b2:	0000      	.short	0x0000
    15b4:	5e2c      	addu      	r1, r6, r3
    15b6:	2300      	addi      	r3, 1
    15b8:	c462002c 	addu      	r12, r2, r3
    15bc:	8122      	ld.b      	r1, (r1, 0x2)
    15be:	d98c025b 	ld.b      	r12, (r12, 0x25b)
    15c2:	6472      	cmpne      	r12, r1
    15c4:	0fda      	bf      	0x1578	// 1578 <dsleep_wakeup+0x1578>
    15c6:	e800f962 	br      	0x88a	// 88a <dsleep_wakeup+0x88a>
    15ca:	8444      	ld.b      	r2, (r4, 0x4)
    15cc:	e4422044 	andi      	r2, r2, 68
    15d0:	e922f960 	bnez      	r2, 0x890	// 890 <dsleep_wakeup+0x890>
    15d4:	d8444005 	ld.bs      	r2, (r4, 0x5)
    15d8:	e9a2001d 	bhsz      	r2, 0x1612	// 1612 <dsleep_wakeup+0x1612>
    15dc:	9442      	ld.w      	r2, (r4, 0x8)
    15de:	9324      	ld.w      	r1, (r3, 0x10)
    15e0:	3003      	movi      	r0, 3
    15e2:	d862227f 	ld.w      	r3, (r2, 0x9fc)
    15e6:	7cc0      	mult      	r3, r0
    15e8:	d84209c6 	ld.b      	r2, (r2, 0x9c6)
    15ec:	7cc8      	mult      	r3, r2
    15ee:	64c4      	cmphs      	r1, r3
    15f0:	e840f950 	bf      	0x890	// 890 <dsleep_wakeup+0x890>
    15f4:	1317      	lrw      	r0, 0x0	// 17d0 <dsleep_wakeup+0x17d0>
    15f6:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    15fa:	8464      	ld.b      	r3, (r4, 0x4)
    15fc:	3101      	movi      	r1, 1
    15fe:	c4615c01 	ins      	r3, r1, 1, 1
    1602:	a464      	st.b      	r3, (r4, 0x4)
    1604:	9462      	ld.w      	r3, (r4, 0x8)
    1606:	8355      	ld.b      	r2, (r3, 0x15)
    1608:	c4415c03 	ins      	r2, r1, 3, 3
    160c:	a355      	st.b      	r2, (r3, 0x15)
    160e:	e800f941 	br      	0x890	// 890 <dsleep_wakeup+0x890>
    1612:	9344      	ld.w      	r2, (r3, 0x10)
    1614:	d864203e 	ld.w      	r3, (r4, 0xf8)
    1618:	64c8      	cmphs      	r2, r3
    161a:	e840f93b 	bf      	0x890	// 890 <dsleep_wakeup+0x890>
    161e:	8466      	ld.b      	r3, (r4, 0x6)
    1620:	e4632008 	andi      	r3, r3, 8
    1624:	e903000c 	bez      	r3, 0x163c	// 163c <dsleep_wakeup+0x163c>
    1628:	130b      	lrw      	r0, 0x0	// 17d4 <dsleep_wakeup+0x17d4>
    162a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    162e:	8465      	ld.b      	r3, (r4, 0x5)
    1630:	3201      	movi      	r2, 1
    1632:	c4625c02 	ins      	r3, r2, 2, 2
    1636:	a465      	st.b      	r3, (r4, 0x5)
    1638:	e800f92c 	br      	0x890	// 890 <dsleep_wakeup+0x890>
    163c:	d864203c 	ld.w      	r3, (r4, 0xf0)
    1640:	9442      	ld.w      	r2, (r4, 0x8)
    1642:	2300      	addi      	r3, 1
    1644:	dc64203c 	st.w      	r3, (r4, 0xf0)
    1648:	d86209c6 	ld.b      	r3, (r2, 0x9c6)
    164c:	d842227f 	ld.w      	r2, (r2, 0x9fc)
    1650:	7cc8      	mult      	r3, r2
    1652:	d8442048 	ld.w      	r2, (r4, 0x120)
    1656:	60c8      	addu      	r3, r2
    1658:	1300      	lrw      	r0, 0x0	// 17d8 <dsleep_wakeup+0x17d8>
    165a:	dc642048 	st.w      	r3, (r4, 0x120)
    165e:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    1662:	d804412a 	ld.bs      	r0, (r4, 0x12a)
    1666:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    166a:	9442      	ld.w      	r2, (r4, 0x8)
    166c:	d862227f 	ld.w      	r3, (r2, 0x9fc)
    1670:	d82209c6 	ld.b      	r1, (r2, 0x9c6)
    1674:	4b6a      	lsri      	r3, r3, 10
    1676:	7cc4      	mult      	r3, r1
    1678:	d824203c 	ld.w      	r1, (r4, 0xf0)
    167c:	7cc4      	mult      	r3, r1
    167e:	31fa      	movi      	r1, 250
    1680:	8a47      	ld.h      	r2, (r2, 0xe)
    1682:	4122      	lsli      	r1, r1, 2
    1684:	7c84      	mult      	r2, r1
    1686:	648c      	cmphs      	r3, r2
    1688:	0c13      	bf      	0x16ae	// 16ae <dsleep_wakeup+0x16ae>
    168a:	1215      	lrw      	r0, 0x0	// 17dc <dsleep_wakeup+0x17dc>
    168c:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    1690:	8464      	ld.b      	r3, (r4, 0x4)
    1692:	3101      	movi      	r1, 1
    1694:	c4615c01 	ins      	r3, r1, 1, 1
    1698:	a464      	st.b      	r3, (r4, 0x4)
    169a:	9462      	ld.w      	r3, (r4, 0x8)
    169c:	8355      	ld.b      	r2, (r3, 0x15)
    169e:	c4415c03 	ins      	r2, r1, 3, 3
    16a2:	a355      	st.b      	r2, (r3, 0x15)
    16a4:	3205      	movi      	r2, 5
    16a6:	dc430257 	st.b      	r2, (r3, 0x257)
    16aa:	e800f8f3 	br      	0x890	// 890 <dsleep_wakeup+0x890>
    16ae:	8465      	ld.b      	r3, (r4, 0x5)
    16b0:	748c      	zextb      	r2, r3
    16b2:	e4222002 	andi      	r1, r2, 2
    16b6:	e9010009 	bez      	r1, 0x16c8	// 16c8 <dsleep_wakeup+0x16c8>
    16ba:	8464      	ld.b      	r3, (r4, 0x4)
    16bc:	3201      	movi      	r2, 1
    16be:	c4625c07 	ins      	r3, r2, 7, 7
    16c2:	a464      	st.b      	r3, (r4, 0x4)
    16c4:	e800f8e6 	br      	0x890	// 890 <dsleep_wakeup+0x890>
    16c8:	e4422001 	andi      	r2, r2, 1
    16cc:	3101      	movi      	r1, 1
    16ce:	e9020008 	bez      	r2, 0x16de	// 16de <dsleep_wakeup+0x16de>
    16d2:	8464      	ld.b      	r3, (r4, 0x4)
    16d4:	c4615c06 	ins      	r3, r1, 6, 6
    16d8:	a464      	st.b      	r3, (r4, 0x4)
    16da:	e800f8db 	br      	0x890	// 890 <dsleep_wakeup+0x890>
    16de:	c4615c02 	ins      	r3, r1, 2, 2
    16e2:	a465      	st.b      	r3, (r4, 0x5)
    16e4:	e800f8d6 	br      	0x890	// 890 <dsleep_wakeup+0x890>
    16e8:	8464      	ld.b      	r3, (r4, 0x4)
    16ea:	e463207f 	andi      	r3, r3, 127
    16ee:	3201      	movi      	r2, 1
    16f0:	c4625c06 	ins      	r3, r2, 6, 6
    16f4:	a464      	st.b      	r3, (r4, 0x4)
    16f6:	e800f93a 	br      	0x96a	// 96a <dsleep_wakeup+0x96a>
    16fa:	e4632020 	andi      	r3, r3, 32
    16fe:	e9030007 	bez      	r3, 0x170c	// 170c <dsleep_wakeup+0x170c>
    1702:	1118      	lrw      	r0, 0x0	// 17e0 <dsleep_wakeup+0x17e0>
    1704:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    1708:	e800f95f 	br      	0x9c6	// 9c6 <dsleep_wakeup+0x9c6>
    170c:	1116      	lrw      	r0, 0x0	// 17e4 <dsleep_wakeup+0x17e4>
    170e:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    1712:	e800f95a 	br      	0x9c6	// 9c6 <dsleep_wakeup+0x9c6>
    1716:	ec631000 	ori      	r3, r3, 4096
    171a:	dc64104a 	st.h      	r3, (r4, 0x94)
    171e:	e800f961 	br      	0x9e0	// 9e0 <dsleep_wakeup+0x9e0>
    1722:	d8640125 	ld.b      	r3, (r4, 0x125)
    1726:	2300      	addi      	r3, 1
    1728:	dc640125 	st.b      	r3, (r4, 0x125)
    172c:	d8640126 	ld.b      	r3, (r4, 0x126)
    1730:	2300      	addi      	r3, 1
    1732:	dc640126 	st.b      	r3, (r4, 0x126)
    1736:	d86a2000 	ld.w      	r3, (r10, 0x0)
    173a:	930f      	ld.w      	r0, (r3, 0x3c)
    173c:	e40021ff 	andi      	r0, r0, 511
    1740:	e40001ff 	addi      	r0, r0, 512
    1744:	e0000000 	bsr      	0x0	// 0 <delay_us>
    1748:	d8640125 	ld.b      	r3, (r4, 0x125)
    174c:	3b09      	cmphsi      	r3, 10
    174e:	e860f960 	bt      	0xa0e	// a0e <dsleep_wakeup+0xa0e>
    1752:	d8640126 	ld.b      	r3, (r4, 0x126)
    1756:	eb030031 	cmphsi      	r3, 50
    175a:	0c15      	bf      	0x1784	// 1784 <dsleep_wakeup+0x1784>
    175c:	8465      	ld.b      	r3, (r4, 0x5)
    175e:	3201      	movi      	r2, 1
    1760:	c4625c04 	ins      	r3, r2, 4, 4
    1764:	a465      	st.b      	r3, (r4, 0x5)
    1766:	8464      	ld.b      	r3, (r4, 0x4)
    1768:	c4625c01 	ins      	r3, r2, 1, 1
    176c:	a464      	st.b      	r3, (r4, 0x4)
    176e:	9462      	ld.w      	r3, (r4, 0x8)
    1770:	101e      	lrw      	r0, 0x0	// 17e8 <dsleep_wakeup+0x17e8>
    1772:	8335      	ld.b      	r1, (r3, 0x15)
    1774:	c4225c03 	ins      	r1, r2, 3, 3
    1778:	3206      	movi      	r2, 6
    177a:	a335      	st.b      	r1, (r3, 0x15)
    177c:	dc430257 	st.b      	r2, (r3, 0x257)
    1780:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    1784:	8466      	ld.b      	r3, (r4, 0x6)
    1786:	e4632010 	andi      	r3, r3, 16
    178a:	e903f855 	bez      	r3, 0x834	// 834 <dsleep_wakeup+0x834>
    178e:	1078      	lrw      	r3, 0x0	// 17ec <dsleep_wakeup+0x17ec>
    1790:	b475      	st.w      	r3, (r4, 0x54)
    1792:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    1796:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    179a:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    179e:	d86a2000 	ld.w      	r3, (r10, 0x0)
    17a2:	9364      	ld.w      	r3, (r3, 0x10)
    17a4:	dc642042 	st.w      	r3, (r4, 0x108)
    17a8:	e0000000 	bsr      	0x0	// 0 <dsleep_wakeup>
    17ac:	3000      	movi      	r0, 0
    17ae:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
    17b2:	8466      	ld.b      	r3, (r4, 0x6)
    17b4:	3200      	movi      	r2, 0
    17b6:	c4625c04 	ins      	r3, r2, 4, 4
    17ba:	a466      	st.b      	r3, (r4, 0x6)
    17bc:	e800f83c 	br      	0x834	// 834 <dsleep_wakeup+0x834>
    17c0:	c4625c02 	ins      	r3, r2, 2, 2
    17c4:	a465      	st.b      	r3, (r4, 0x5)
    17c6:	e800f936 	br      	0xa32	// a32 <dsleep_wakeup+0xa32>
    17ca:	1409      	addi      	r14, r14, 36
    17cc:	1498      	pop      	r4-r11, r15
	...

Disassembly of section .text.dsleep_cfg_get:

00000000 <dsleep_cfg_get>:
   0:	1062      	lrw      	r3, 0x0	// 8 <dsleep_cfg_get+0x8>
   2:	9302      	ld.w      	r0, (r3, 0x8)
   4:	783c      	jmp      	r15
   6:	0000      	.short	0x0000
   8:	0000      	.short	0x0000
	...

Disassembly of section .text.dsleep_enter:

00000000 <dsleep_enter>:
   0:	14d7      	push      	r4-r10, r15
   2:	ea880133 	lrw      	r8, 0x0	// 4cc <dsleep_enter+0x4cc>
   6:	6d43      	mov      	r5, r0
   8:	d8682000 	ld.w      	r3, (r8, 0x0)
   c:	93c4      	ld.w      	r6, (r3, 0x10)
   e:	c0006023 	mfcr      	r3, cr<0, 0>
  12:	c0807020 	psrclr      	ie
  16:	ea84012f 	lrw      	r4, 0x0	// 4d0 <dsleep_enter+0x4d0>
  1a:	e4634040 	xori      	r3, r3, 64
  1e:	c4c354c3 	zext      	r3, r3, 6, 6
  22:	c4415442 	zext      	r2, r1, 2, 2
  26:	b460      	st.w      	r3, (r4, 0x0)
  28:	8465      	ld.b      	r3, (r4, 0x5)
  2a:	c4625c06 	ins      	r3, r2, 6, 6
  2e:	c4215422 	zext      	r2, r1, 1, 1
  32:	c4625c05 	ins      	r3, r2, 5, 5
  36:	a465      	st.b      	r3, (r4, 0x5)
  38:	8466      	ld.b      	r3, (r4, 0x6)
  3a:	e4e12008 	andi      	r7, r1, 8
  3e:	c4625c00 	ins      	r3, r2, 0, 0
  42:	8444      	ld.b      	r2, (r4, 0x4)
  44:	c4415c00 	ins      	r2, r1, 0, 0
  48:	3f40      	cmpnei      	r7, 0
  4a:	a444      	st.b      	r2, (r4, 0x4)
  4c:	c4000502 	mvc      	r2
  50:	c4625c03 	ins      	r3, r2, 3, 3
  54:	3840      	cmpnei      	r0, 0
  56:	a466      	st.b      	r3, (r4, 0x6)
  58:	ea83011f 	lrw      	r3, 0x3938700	// 4d4 <dsleep_enter+0x4d4>
  5c:	c4a30c20 	incf      	r5, r3, 0
  60:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
  64:	3000      	movi      	r0, 0
  66:	284f      	subi      	r0, 80
  68:	e0000000 	bsr      	0x0	// 0 <lmac_adjust_cca_threshold>
  6c:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
  70:	940c      	ld.w      	r0, (r4, 0x30)
  72:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
  76:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
  7a:	9462      	ld.w      	r3, (r4, 0x8)
  7c:	3f40      	cmpnei      	r7, 0
  7e:	ea00c350 	movi      	r0, 50000
  82:	ea011388 	movi      	r1, 5000
  86:	d84314e2 	ld.h      	r2, (r3, 0x9c4)
  8a:	c4200c20 	incf      	r1, r0, 0
  8e:	dc442041 	st.w      	r2, (r4, 0x104)
  92:	dc24203e 	st.w      	r1, (r4, 0xf8)
  96:	3200      	movi      	r2, 0
  98:	8426      	ld.b      	r1, (r4, 0x6)
  9a:	c4225c02 	ins      	r1, r2, 2, 2
  9e:	a426      	st.b      	r1, (r4, 0x6)
  a0:	3100      	movi      	r1, 0
  a2:	2900      	subi      	r1, 1
  a4:	dc240128 	st.b      	r1, (r4, 0x128)
  a8:	3196      	movi      	r1, 150
  aa:	4121      	lsli      	r1, r1, 1
  ac:	dc44203d 	st.w      	r2, (r4, 0xf4)
  b0:	dc440126 	st.b      	r2, (r4, 0x126)
  b4:	dc242040 	st.w      	r1, (r4, 0x100)
  b8:	e9070006 	bez      	r7, 0xc4	// c4 <dsleep_enter+0xc4>
  bc:	dc4309c6 	st.b      	r2, (r3, 0x9c6)
  c0:	dc43227f 	st.w      	r2, (r3, 0x9fc)
  c4:	d8e309c6 	ld.b      	r7, (r3, 0x9c6)
  c8:	d843227f 	ld.w      	r2, (r3, 0x9fc)
  cc:	7dc8      	mult      	r7, r2
  ce:	e9070016 	bez      	r7, 0xfa	// fa <dsleep_enter+0xfa>
  d2:	32fa      	movi      	r2, 250
  d4:	4242      	lsli      	r2, r2, 2
  d6:	d8631504 	ld.h      	r3, (r3, 0xa08)
  da:	7cc8      	mult      	r3, r2
  dc:	4f4a      	lsri      	r2, r7, 10
  de:	c4438023 	divu      	r3, r3, r2
  e2:	dc642040 	st.w      	r3, (r4, 0x100)
  e6:	d8682000 	ld.w      	r3, (r8, 0x0)
  ea:	9345      	ld.w      	r2, (r3, 0x14)
  ec:	9364      	ld.w      	r3, (r3, 0x10)
  ee:	dc442047 	st.w      	r2, (r4, 0x11c)
  f2:	dc642046 	st.w      	r3, (r4, 0x118)
  f6:	dce42048 	st.w      	r7, (r4, 0x120)
  fa:	d8642040 	ld.w      	r3, (r4, 0x100)
  fe:	3b0a      	cmphsi      	r3, 11
 100:	0c1a      	bf      	0x134	// 134 <dsleep_enter+0x134>
 102:	3203      	movi      	r2, 3
 104:	7cc8      	mult      	r3, r2
 106:	4b62      	lsri      	r3, r3, 2
 108:	dc642040 	st.w      	r3, (r4, 0x100)
 10c:	ea8900f3 	lrw      	r9, 0x40026000	// 4d8 <dsleep_enter+0x4d8>
 110:	ea8a00f3 	lrw      	r10, 0x3fac87e4	// 4dc <dsleep_enter+0x4dc>
 114:	dd49200b 	st.w      	r10, (r9, 0x2c)
 118:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 11c:	9462      	ld.w      	r3, (r4, 0x8)
 11e:	8375      	ld.b      	r3, (r3, 0x15)
 120:	e4632007 	andi      	r3, r3, 7
 124:	3b46      	cmpnei      	r3, 6
 126:	e86003b5 	bt      	0x890	// 890 <dsleep_enter+0x890>
 12a:	0011      	lrw      	r0, 0x0	// 4e0 <dsleep_enter+0x4e0>
 12c:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 130:	e800040f 	br      	0x94e	// 94e <dsleep_enter+0x94e>
 134:	3b01      	cmphsi      	r3, 2
 136:	0feb      	bf      	0x10c	// 10c <dsleep_enter+0x10c>
 138:	4b61      	lsri      	r3, r3, 1
 13a:	dc642040 	st.w      	r3, (r4, 0x100)
 13e:	07e7      	br      	0x10c	// 10c <dsleep_enter+0x10c>
 140:	2800      	subi      	r0, 1
 142:	e80003f1 	br      	0x924	// 924 <dsleep_enter+0x924>
 146:	0017      	lrw      	r0, 0x0	// 4e4 <dsleep_enter+0x4e4>
 148:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 14c:	001d      	lrw      	r0, 0x3938700	// 4d4 <dsleep_enter+0x4d4>
 14e:	e80003f7 	br      	0x93c	// 93c <dsleep_enter+0x93c>
 152:	001e      	lrw      	r0, 0x3938700	// 4d4 <dsleep_enter+0x4d4>
 154:	e80003f4 	br      	0x93c	// 93c <dsleep_enter+0x93c>
 158:	6c17      	mov      	r0, r5
 15a:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 15e:	e80003f5 	br      	0x948	// 948 <dsleep_enter+0x948>
 162:	d8640085 	ld.b      	r3, (r4, 0x85)
 166:	3201      	movi      	r2, 1
 168:	c4625c20 	ins      	r3, r2, 1, 0
 16c:	c4625c22 	ins      	r3, r2, 3, 2
 170:	dc640085 	st.b      	r3, (r4, 0x85)
 174:	3304      	movi      	r3, 4
 176:	e8000439 	br      	0x9e8	// 9e8 <dsleep_enter+0x9e8>
 17a:	d844008c 	ld.b      	r2, (r4, 0x8c)
 17e:	3001      	movi      	r0, 1
 180:	c4435c02 	ins      	r2, r3, 2, 2
 184:	c4405c04 	ins      	r2, r0, 4, 4
 188:	c4405c06 	ins      	r2, r0, 6, 6
 18c:	dc44008c 	st.b      	r2, (r4, 0x8c)
 190:	d8441046 	ld.h      	r2, (r4, 0x8c)
 194:	c48154e1 	zext      	r1, r1, 7, 4
 198:	c4415c67 	ins      	r2, r1, 10, 7
 19c:	dc441046 	st.h      	r2, (r4, 0x8c)
 1a0:	d844008d 	ld.b      	r2, (r4, 0x8d)
 1a4:	c4435c03 	ins      	r2, r3, 3, 3
 1a8:	dc44008d 	st.b      	r2, (r4, 0x8d)
 1ac:	d8442023 	ld.w      	r2, (r4, 0x8c)
 1b0:	3114      	movi      	r1, 20
 1b2:	c4415d0c 	ins      	r2, r1, 20, 12
 1b6:	dc442023 	st.w      	r2, (r4, 0x8c)
 1ba:	d844008e 	ld.b      	r2, (r4, 0x8e)
 1be:	3102      	movi      	r1, 2
 1c0:	c4415c25 	ins      	r2, r1, 6, 5
 1c4:	dc44008e 	st.b      	r2, (r4, 0x8e)
 1c8:	d844008f 	ld.b      	r2, (r4, 0x8f)
 1cc:	c4435c00 	ins      	r2, r3, 0, 0
 1d0:	c4435c01 	ins      	r2, r3, 1, 1
 1d4:	dc44008f 	st.b      	r2, (r4, 0x8f)
 1d8:	ea0311c8 	movi      	r3, 4552
 1dc:	9422      	ld.w      	r1, (r4, 0x8)
 1de:	dc64104a 	st.h      	r3, (r4, 0x94)
 1e2:	015d      	lrw      	r2, 0x0	// 4e8 <dsleep_enter+0x4e8>
 1e4:	e46109ef 	addi      	r3, r1, 2544
 1e8:	e58109f5 	addi      	r12, r1, 2550
 1ec:	8300      	ld.b      	r0, (r3, 0x0)
 1ee:	a200      	st.b      	r0, (r2, 0x0)
 1f0:	d9a30006 	ld.b      	r13, (r3, 0x6)
 1f4:	2300      	addi      	r3, 1
 1f6:	64f2      	cmpne      	r12, r3
 1f8:	dda20006 	st.b      	r13, (r2, 0x6)
 1fc:	a20c      	st.b      	r0, (r2, 0xc)
 1fe:	2200      	addi      	r2, 1
 200:	0bf6      	bt      	0x1ec	// 1ec <dsleep_enter+0x1ec>
 202:	3300      	movi      	r3, 0
 204:	dc641055 	st.h      	r3, (r4, 0xaa)
 208:	3300      	movi      	r3, 0
 20a:	dc64202c 	st.w      	r3, (r4, 0xb0)
 20e:	3200      	movi      	r2, 0
 210:	dc64202d 	st.w      	r3, (r4, 0xb4)
 214:	3300      	movi      	r3, 0
 216:	dc44202e 	st.w      	r2, (r4, 0xb8)
 21a:	dc64202f 	st.w      	r3, (r4, 0xbc)
 21e:	330c      	movi      	r3, 12
 220:	dc6400b2 	st.b      	r3, (r4, 0xb2)
 224:	d8610a4e 	ld.b      	r3, (r1, 0xa4e)
 228:	e4632040 	andi      	r3, r3, 64
 22c:	3b40      	cmpnei      	r3, 0
 22e:	6483      	mvcv      	r2
 230:	7488      	zextb      	r2, r2
 232:	3000      	movi      	r0, 0
 234:	c4025c64 	ins      	r0, r2, 7, 4
 238:	dc0400b1 	st.b      	r0, (r4, 0xb1)
 23c:	d82109c7 	ld.b      	r1, (r1, 0x9c7)
 240:	02b4      	lrw      	r5, 0x0	// 4ec <dsleep_enter+0x4ec>
 242:	e9010004 	bez      	r1, 0x24a	// 24a <dsleep_enter+0x24a>
 246:	e9030058 	bez      	r3, 0x2f6	// 2f6 <dsleep_enter+0x2f6>
 24a:	3b40      	cmpnei      	r3, 0
 24c:	c4000501 	mvc      	r1
 250:	d86400b1 	ld.b      	r3, (r4, 0xb1)
 254:	c4615c20 	ins      	r3, r1, 1, 0
 258:	3100      	movi      	r1, 0
 25a:	c4615c22 	ins      	r3, r1, 3, 2
 25e:	dc6400b1 	st.b      	r3, (r4, 0xb1)
 262:	d0450501 	ldr.h      	r1, (r5, r2 << 3)
 266:	3387      	movi      	r3, 135
 268:	7405      	zexth      	r0, r1
 26a:	4361      	lsli      	r3, r3, 1
 26c:	c4038021 	divu      	r1, r3, r0
 270:	7485      	zexth      	r2, r1
 272:	7c40      	mult      	r1, r0
 274:	60c6      	subu      	r3, r1
 276:	e9030004 	bez      	r3, 0x27e	// 27e <dsleep_enter+0x27e>
 27a:	2200      	addi      	r2, 1
 27c:	7489      	zexth      	r2, r2
 27e:	dc44202d 	st.w      	r2, (r4, 0xb4)
 282:	d82400b1 	ld.b      	r1, (r4, 0xb1)
 286:	c4415463 	zext      	r3, r1, 3, 2
 28a:	e9030043 	bez      	r3, 0x310	// 310 <dsleep_enter+0x310>
 28e:	3b41      	cmpnei      	r3, 1
 290:	0d36      	bf      	0x4fc	// 4fc <dsleep_enter+0x4fc>
 292:	31ef      	movi      	r1, 239
 294:	0348      	lrw      	r2, 0x0	// 4f0 <dsleep_enter+0x4f0>
 296:	4124      	lsli      	r1, r1, 4
 298:	0308      	lrw      	r0, 0x0	// 4f4 <dsleep_enter+0x4f4>
 29a:	e0000000 	bsr      	0x0	// 0 <assert_internal>
 29e:	0468      	br      	0x36e	// 36e <dsleep_enter+0x36e>
 2a0:	d844008c 	ld.b      	r2, (r4, 0x8c)
 2a4:	d8040084 	ld.b      	r0, (r4, 0x84)
 2a8:	c4435c00 	ins      	r2, r3, 0, 0
 2ac:	c4c054e0 	zext      	r0, r0, 7, 6
 2b0:	c4405c23 	ins      	r2, r0, 4, 3
 2b4:	dc44008c 	st.b      	r2, (r4, 0x8c)
 2b8:	d844008e 	ld.b      	r2, (r4, 0x8e)
 2bc:	e44220fe 	andi      	r2, r2, 254
 2c0:	c4435c02 	ins      	r2, r3, 2, 2
 2c4:	6ccb      	mov      	r3, r2
 2c6:	c48154e1 	zext      	r1, r1, 7, 4
 2ca:	c4615c63 	ins      	r3, r1, 6, 3
 2ce:	dc64008e 	st.b      	r3, (r4, 0x8e)
 2d2:	3328      	movi      	r3, 40
 2d4:	dc64008f 	st.b      	r3, (r4, 0x8f)
 2d8:	d8640090 	ld.b      	r3, (r4, 0x90)
 2dc:	3202      	movi      	r2, 2
 2de:	e46320fc 	andi      	r3, r3, 252
 2e2:	c4625c22 	ins      	r3, r2, 3, 2
 2e6:	e46320ec 	andi      	r3, r3, 236
 2ea:	3200      	movi      	r2, 0
 2ec:	c4625c05 	ins      	r3, r2, 5, 5
 2f0:	dc640090 	st.b      	r3, (r4, 0x90)
 2f4:	0772      	br      	0x1d8	// 1d8 <dsleep_enter+0x1d8>
 2f6:	d86400b1 	ld.b      	r3, (r4, 0xb1)
 2fa:	3201      	movi      	r2, 1
 2fc:	c4625c20 	ins      	r3, r2, 1, 0
 300:	c4625c22 	ins      	r3, r2, 3, 2
 304:	dc6400b1 	st.b      	r3, (r4, 0xb1)
 308:	3306      	movi      	r3, 6
 30a:	dc64202d 	st.w      	r3, (r4, 0xb4)
 30e:	07ba      	br      	0x282	// 282 <dsleep_enter+0x282>
 310:	d84400b8 	ld.b      	r2, (r4, 0xb8)
 314:	3001      	movi      	r0, 1
 316:	c4435c02 	ins      	r2, r3, 2, 2
 31a:	c4405c04 	ins      	r2, r0, 4, 4
 31e:	c4405c06 	ins      	r2, r0, 6, 6
 322:	dc4400b8 	st.b      	r2, (r4, 0xb8)
 326:	d844105c 	ld.h      	r2, (r4, 0xb8)
 32a:	c48154e1 	zext      	r1, r1, 7, 4
 32e:	c4415c67 	ins      	r2, r1, 10, 7
 332:	dc44105c 	st.h      	r2, (r4, 0xb8)
 336:	d84400b9 	ld.b      	r2, (r4, 0xb9)
 33a:	c4435c03 	ins      	r2, r3, 3, 3
 33e:	dc4400b9 	st.b      	r2, (r4, 0xb9)
 342:	d844202e 	ld.w      	r2, (r4, 0xb8)
 346:	3120      	movi      	r1, 32
 348:	c4415d0c 	ins      	r2, r1, 20, 12
 34c:	dc44202e 	st.w      	r2, (r4, 0xb8)
 350:	d84400ba 	ld.b      	r2, (r4, 0xba)
 354:	3102      	movi      	r1, 2
 356:	c4415c25 	ins      	r2, r1, 6, 5
 35a:	dc4400ba 	st.b      	r2, (r4, 0xba)
 35e:	d84400bb 	ld.b      	r2, (r4, 0xbb)
 362:	c4435c00 	ins      	r2, r3, 0, 0
 366:	c4435c01 	ins      	r2, r3, 1, 1
 36a:	dc4400bb 	st.b      	r2, (r4, 0xbb)
 36e:	d84400c0 	ld.b      	r2, (r4, 0xc0)
 372:	3307      	movi      	r3, 7
 374:	9402      	ld.w      	r0, (r4, 0x8)
 376:	c4435c40 	ins      	r2, r3, 2, 0
 37a:	3300      	movi      	r3, 0
 37c:	c4435c03 	ins      	r2, r3, 3, 3
 380:	dc4400c0 	st.b      	r2, (r4, 0xc0)
 384:	d8402272 	ld.w      	r2, (r0, 0x9c8)
 388:	4224      	lsli      	r1, r2, 4
 38a:	d8442030 	ld.w      	r2, (r4, 0xc0)
 38e:	e442200f 	andi      	r2, r2, 15
 392:	6c84      	or      	r2, r1
 394:	dc442030 	st.w      	r2, (r4, 0xc0)
 398:	d84009cb 	ld.b      	r2, (r0, 0x9cb)
 39c:	ea0c0000 	movi      	r12, 0
 3a0:	4a24      	lsri      	r1, r2, 4
 3a2:	e58c100f 	subi      	r12, r12, 16
 3a6:	d84400c4 	ld.b      	r2, (r4, 0xc4)
 3aa:	68b0      	and      	r2, r12
 3ac:	6c84      	or      	r2, r1
 3ae:	3101      	movi      	r1, 1
 3b0:	c4415c04 	ins      	r2, r1, 4, 4
 3b4:	dc4400c4 	st.b      	r2, (r4, 0xc4)
 3b8:	d8442031 	ld.w      	r2, (r4, 0xc4)
 3bc:	c4435f45 	ins      	r2, r3, 31, 5
 3c0:	dc442031 	st.w      	r2, (r4, 0xc4)
 3c4:	320f      	movi      	r2, 15
 3c6:	dc642032 	st.w      	r3, (r4, 0xc8)
 3ca:	dc4400ca 	st.b      	r2, (r4, 0xca)
 3ce:	d9800a4e 	ld.b      	r12, (r0, 0xa4e)
 3d2:	e58c2040 	andi      	r12, r12, 64
 3d6:	eb4c0000 	cmpnei      	r12, 0
 3da:	c400050d 	mvc      	r13
 3de:	e5ad2003 	andi      	r13, r13, 3
 3e2:	6cb7      	mov      	r2, r13
 3e4:	c4415c22 	ins      	r2, r1, 3, 2
 3e8:	dc4400c9 	st.b      	r2, (r4, 0xc9)
 3ec:	d84400ca 	ld.b      	r2, (r4, 0xca)
 3f0:	c4435c07 	ins      	r2, r3, 7, 7
 3f4:	d8c42030 	ld.w      	r6, (r4, 0xc0)
 3f8:	d8e42031 	ld.w      	r7, (r4, 0xc4)
 3fc:	dc4400ca 	st.b      	r2, (r4, 0xca)
 400:	4145      	lsli      	r2, r1, 5
 402:	dcc42034 	st.w      	r6, (r4, 0xd0)
 406:	dce42035 	st.w      	r7, (r4, 0xd4)
 40a:	c4435c80 	ins      	r2, r3, 4, 0
 40e:	dc4400c8 	st.b      	r2, (r4, 0xc8)
 412:	d84400d4 	ld.b      	r2, (r4, 0xd4)
 416:	c4415c05 	ins      	r2, r1, 5, 5
 41a:	dc642033 	st.w      	r3, (r4, 0xcc)
 41e:	dc4400d4 	st.b      	r2, (r4, 0xd4)
 422:	8052      	ld.b      	r2, (r0, 0x12)
 424:	dc642036 	st.w      	r3, (r4, 0xd8)
 428:	dc642037 	st.w      	r3, (r4, 0xdc)
 42c:	e4622003 	andi      	r3, r2, 3
 430:	3600      	movi      	r6, 0
 432:	3700      	movi      	r7, 0
 434:	dcc42038 	st.w      	r6, (r4, 0xe0)
 438:	dce42039 	st.w      	r7, (r4, 0xe4)
 43c:	2203      	addi      	r2, 4
 43e:	e9030005 	bez      	r3, 0x448	// 448 <dsleep_enter+0x448>
 442:	3a80      	bclri      	r2, 0
 444:	3a81      	bclri      	r2, 1
 446:	2203      	addi      	r2, 4
 448:	d86400da 	ld.b      	r3, (r4, 0xda)
 44c:	310a      	movi      	r1, 10
 44e:	eb4c0000 	cmpnei      	r12, 0
 452:	c4615cc0 	ins      	r3, r1, 6, 0
 456:	6443      	mvcv      	r1
 458:	dc6400da 	st.b      	r3, (r4, 0xda)
 45c:	7444      	zextb      	r1, r1
 45e:	d86400d9 	ld.b      	r3, (r4, 0xd9)
 462:	c4615c64 	ins      	r3, r1, 7, 4
 466:	dc6400d9 	st.b      	r3, (r4, 0xd9)
 46a:	d80009c7 	ld.b      	r0, (r0, 0x9c7)
 46e:	5a62      	addi      	r3, r2, 1
 470:	e9000004 	bez      	r0, 0x478	// 478 <dsleep_enter+0x478>
 474:	e90c006f 	bez      	r12, 0x552	// 552 <dsleep_enter+0x552>
 478:	d80400d9 	ld.b      	r0, (r4, 0xd9)
 47c:	ea0c0000 	movi      	r12, 0
 480:	c40d5c20 	ins      	r0, r13, 1, 0
 484:	c40c5c22 	ins      	r0, r12, 3, 2
 488:	dc0400d9 	st.b      	r0, (r4, 0xd9)
 48c:	4363      	lsli      	r3, r3, 3
 48e:	d0250500 	ldr.h      	r0, (r5, r1 << 3)
 492:	2305      	addi      	r3, 6
 494:	7701      	zexth      	r12, r0
 496:	c5838020 	divu      	r0, r3, r12
 49a:	7441      	zexth      	r1, r0
 49c:	7c30      	mult      	r0, r12
 49e:	60c2      	subu      	r3, r0
 4a0:	e9030004 	bez      	r3, 0x4a8	// 4a8 <dsleep_enter+0x4a8>
 4a4:	2100      	addi      	r1, 1
 4a6:	7445      	zexth      	r1, r1
 4a8:	d80400d9 	ld.b      	r0, (r4, 0xd9)
 4ac:	c4405463 	zext      	r3, r0, 3, 2
 4b0:	dc242037 	st.w      	r1, (r4, 0xdc)
 4b4:	e9030060 	bez      	r3, 0x574	// 574 <dsleep_enter+0x574>
 4b8:	3b41      	cmpnei      	r3, 1
 4ba:	0cd2      	bf      	0x65e	// 65e <dsleep_enter+0x65e>
 4bc:	104d      	lrw      	r2, 0x0	// 4f0 <dsleep_enter+0x4f0>
 4be:	ea010f3d 	movi      	r1, 3901
 4c2:	100e      	lrw      	r0, 0x0	// 4f8 <assert_internal+0x4f8>
 4c4:	e0000000 	bsr      	0x0	// 0 <assert_internal>
 4c8:	0485      	br      	0x5d2	// 5d2 <dsleep_enter+0x5d2>
	...
 4d2:	0000      	.short	0x0000
 4d4:	03938700 	.long	0x03938700
 4d8:	40026000 	.long	0x40026000
 4dc:	3fac87e4 	.long	0x3fac87e4
	...
 4fc:	d84400b8 	ld.b      	r2, (r4, 0xb8)
 500:	d80400b0 	ld.b      	r0, (r4, 0xb0)
 504:	c4435c00 	ins      	r2, r3, 0, 0
 508:	c4c054e0 	zext      	r0, r0, 7, 6
 50c:	c4405c23 	ins      	r2, r0, 4, 3
 510:	dc4400b8 	st.b      	r2, (r4, 0xb8)
 514:	d84400ba 	ld.b      	r2, (r4, 0xba)
 518:	e44220fe 	andi      	r2, r2, 254
 51c:	c4435c02 	ins      	r2, r3, 2, 2
 520:	6ccb      	mov      	r3, r2
 522:	c48154e1 	zext      	r1, r1, 7, 4
 526:	c4615c63 	ins      	r3, r1, 6, 3
 52a:	dc6400ba 	st.b      	r3, (r4, 0xba)
 52e:	3340      	movi      	r3, 64
 530:	dc6400bb 	st.b      	r3, (r4, 0xbb)
 534:	d86400bc 	ld.b      	r3, (r4, 0xbc)
 538:	3202      	movi      	r2, 2
 53a:	e46320fc 	andi      	r3, r3, 252
 53e:	c4625c22 	ins      	r3, r2, 3, 2
 542:	e46320ec 	andi      	r3, r3, 236
 546:	3200      	movi      	r2, 0
 548:	c4625c05 	ins      	r3, r2, 5, 5
 54c:	dc6400bc 	st.b      	r3, (r4, 0xbc)
 550:	070f      	br      	0x36e	// 36e <dsleep_enter+0x36e>
 552:	ea0c0001 	movi      	r12, 1
 556:	d80400d9 	ld.b      	r0, (r4, 0xd9)
 55a:	4123      	lsli      	r1, r1, 3
 55c:	c40c5c20 	ins      	r0, r12, 1, 0
 560:	6054      	addu      	r1, r5
 562:	c40c5c22 	ins      	r0, r12, 3, 2
 566:	4363      	lsli      	r3, r3, 3
 568:	dc0400d9 	st.b      	r0, (r4, 0xd9)
 56c:	2305      	addi      	r3, 6
 56e:	d9811001 	ld.h      	r12, (r1, 0x2)
 572:	0792      	br      	0x496	// 496 <dsleep_enter+0x496>
 574:	d82400e0 	ld.b      	r1, (r4, 0xe0)
 578:	ea0c0001 	movi      	r12, 1
 57c:	c4235c02 	ins      	r1, r3, 2, 2
 580:	c42c5c04 	ins      	r1, r12, 4, 4
 584:	c42c5c06 	ins      	r1, r12, 6, 6
 588:	dc2400e0 	st.b      	r1, (r4, 0xe0)
 58c:	d8241070 	ld.h      	r1, (r4, 0xe0)
 590:	c48054e0 	zext      	r0, r0, 7, 4
 594:	c4205c67 	ins      	r1, r0, 10, 7
 598:	dc241070 	st.h      	r1, (r4, 0xe0)
 59c:	d82400e1 	ld.b      	r1, (r4, 0xe1)
 5a0:	c4235c03 	ins      	r1, r3, 3, 3
 5a4:	dc2400e1 	st.b      	r1, (r4, 0xe1)
 5a8:	d8242038 	ld.w      	r1, (r4, 0xe0)
 5ac:	c4225d0c 	ins      	r1, r2, 20, 12
 5b0:	dc242038 	st.w      	r1, (r4, 0xe0)
 5b4:	d84400e2 	ld.b      	r2, (r4, 0xe2)
 5b8:	3102      	movi      	r1, 2
 5ba:	c4415c25 	ins      	r2, r1, 6, 5
 5be:	dc4400e2 	st.b      	r2, (r4, 0xe2)
 5c2:	d84400e3 	ld.b      	r2, (r4, 0xe3)
 5c6:	c4435c00 	ins      	r2, r3, 0, 0
 5ca:	c4435c01 	ins      	r2, r3, 1, 1
 5ce:	dc4400e3 	st.b      	r2, (r4, 0xe3)
 5d2:	3300      	movi      	r3, 0
 5d4:	b479      	st.w      	r3, (r4, 0x64)
 5d6:	3200      	movi      	r2, 0
 5d8:	b47a      	st.w      	r3, (r4, 0x68)
 5da:	3300      	movi      	r3, 0
 5dc:	b45b      	st.w      	r2, (r4, 0x6c)
 5de:	b47c      	st.w      	r3, (r4, 0x70)
 5e0:	9422      	ld.w      	r1, (r4, 0x8)
 5e2:	330d      	movi      	r3, 13
 5e4:	dc640066 	st.b      	r3, (r4, 0x66)
 5e8:	d8610a4e 	ld.b      	r3, (r1, 0xa4e)
 5ec:	e4632040 	andi      	r3, r3, 64
 5f0:	3b40      	cmpnei      	r3, 0
 5f2:	6483      	mvcv      	r2
 5f4:	7488      	zextb      	r2, r2
 5f6:	3000      	movi      	r0, 0
 5f8:	c4025c64 	ins      	r0, r2, 7, 4
 5fc:	dc040065 	st.b      	r0, (r4, 0x65)
 600:	d82109c7 	ld.b      	r1, (r1, 0x9c7)
 604:	e9010004 	bez      	r1, 0x60c	// 60c <dsleep_enter+0x60c>
 608:	e9030059 	bez      	r3, 0x6ba	// 6ba <dsleep_enter+0x6ba>
 60c:	3b40      	cmpnei      	r3, 0
 60e:	c4000501 	mvc      	r1
 612:	d8640065 	ld.b      	r3, (r4, 0x65)
 616:	c4615c20 	ins      	r3, r1, 1, 0
 61a:	3100      	movi      	r1, 0
 61c:	c4615c22 	ins      	r3, r1, 3, 2
 620:	d0450501 	ldr.h      	r1, (r5, r2 << 3)
 624:	7405      	zexth      	r0, r1
 626:	328e      	movi      	r2, 142
 628:	c4028021 	divu      	r1, r2, r0
 62c:	dc640065 	st.b      	r3, (r4, 0x65)
 630:	74c5      	zexth      	r3, r1
 632:	7c40      	mult      	r1, r0
 634:	6086      	subu      	r2, r1
 636:	e9020004 	bez      	r2, 0x63e	// 63e <dsleep_enter+0x63e>
 63a:	2300      	addi      	r3, 1
 63c:	74cd      	zexth      	r3, r3
 63e:	d8240065 	ld.b      	r1, (r4, 0x65)
 642:	b47a      	st.w      	r3, (r4, 0x68)
 644:	c4415463 	zext      	r3, r1, 3, 2
 648:	e9030044 	bez      	r3, 0x6d0	// 6d0 <dsleep_enter+0x6d0>
 64c:	3b41      	cmpnei      	r3, 1
 64e:	0cfb      	bf      	0x844	// 844 <dsleep_enter+0x844>
 650:	004f      	lrw      	r2, 0x0	// a10 <dsleep_enter+0xa10>
 652:	ea010f72 	movi      	r1, 3954
 656:	000f      	lrw      	r0, 0x0	// a14 <assert_internal+0xa14>
 658:	e0000000 	bsr      	0x0	// 0 <assert_internal>
 65c:	0466      	br      	0x728	// 728 <dsleep_enter+0x728>
 65e:	d82400e0 	ld.b      	r1, (r4, 0xe0)
 662:	d98400d8 	ld.b      	r12, (r4, 0xd8)
 666:	c4235c00 	ins      	r1, r3, 0, 0
 66a:	c4cc54ec 	zext      	r12, r12, 7, 6
 66e:	c42c5c23 	ins      	r1, r12, 4, 3
 672:	dc2400e0 	st.b      	r1, (r4, 0xe0)
 676:	d82400e2 	ld.b      	r1, (r4, 0xe2)
 67a:	e42120fe 	andi      	r1, r1, 254
 67e:	c4235c02 	ins      	r1, r3, 2, 2
 682:	c48054e0 	zext      	r0, r0, 7, 4
 686:	6cc7      	mov      	r3, r1
 688:	c4605c63 	ins      	r3, r0, 6, 3
 68c:	dc6400e2 	st.b      	r3, (r4, 0xe2)
 690:	4261      	lsli      	r3, r2, 1
 692:	dc6400e3 	st.b      	r3, (r4, 0xe3)
 696:	c4e25503 	zext      	r3, r2, 8, 7
 69a:	d84400e4 	ld.b      	r2, (r4, 0xe4)
 69e:	3a80      	bclri      	r2, 0
 6a0:	3a81      	bclri      	r2, 1
 6a2:	6c8c      	or      	r2, r3
 6a4:	3302      	movi      	r3, 2
 6a6:	c4435c22 	ins      	r2, r3, 3, 2
 6aa:	e44220ef 	andi      	r2, r2, 239
 6ae:	3300      	movi      	r3, 0
 6b0:	c4435c05 	ins      	r2, r3, 5, 5
 6b4:	dc4400e4 	st.b      	r2, (r4, 0xe4)
 6b8:	078d      	br      	0x5d2	// 5d2 <dsleep_enter+0x5d2>
 6ba:	d8640065 	ld.b      	r3, (r4, 0x65)
 6be:	3201      	movi      	r2, 1
 6c0:	c4625c20 	ins      	r3, r2, 1, 0
 6c4:	c4625c22 	ins      	r3, r2, 3, 2
 6c8:	dc640065 	st.b      	r3, (r4, 0x65)
 6cc:	3303      	movi      	r3, 3
 6ce:	07b8      	br      	0x63e	// 63e <dsleep_enter+0x63e>
 6d0:	d844006c 	ld.b      	r2, (r4, 0x6c)
 6d4:	3001      	movi      	r0, 1
 6d6:	c4435c02 	ins      	r2, r3, 2, 2
 6da:	c4405c04 	ins      	r2, r0, 4, 4
 6de:	c4405c06 	ins      	r2, r0, 6, 6
 6e2:	dc44006c 	st.b      	r2, (r4, 0x6c)
 6e6:	d8441036 	ld.h      	r2, (r4, 0x6c)
 6ea:	c48154e1 	zext      	r1, r1, 7, 4
 6ee:	c4415c67 	ins      	r2, r1, 10, 7
 6f2:	dc441036 	st.h      	r2, (r4, 0x6c)
 6f6:	d844006d 	ld.b      	r2, (r4, 0x6d)
 6fa:	c4435c03 	ins      	r2, r3, 3, 3
 6fe:	dc44006d 	st.b      	r2, (r4, 0x6d)
 702:	945b      	ld.w      	r2, (r4, 0x6c)
 704:	3110      	movi      	r1, 16
 706:	c4415d0c 	ins      	r2, r1, 20, 12
 70a:	b45b      	st.w      	r2, (r4, 0x6c)
 70c:	d844006e 	ld.b      	r2, (r4, 0x6e)
 710:	c4435c25 	ins      	r2, r3, 6, 5
 714:	dc44006e 	st.b      	r2, (r4, 0x6e)
 718:	d844006f 	ld.b      	r2, (r4, 0x6f)
 71c:	c4435c00 	ins      	r2, r3, 0, 0
 720:	c4435c01 	ins      	r2, r3, 1, 1
 724:	dc44006f 	st.b      	r2, (r4, 0x6f)
 728:	ea028003 	movi      	r2, 32771
 72c:	c5e24902 	rotli      	r2, r2, 15
 730:	9267      	ld.w      	r3, (r2, 0x1c)
 732:	e4632080 	andi      	r3, r3, 128
 736:	e903000a 	bez      	r3, 0x74a	// 74a <dsleep_enter+0x74a>
 73a:	9227      	ld.w      	r1, (r2, 0x1c)
 73c:	301c      	movi      	r0, 28
 73e:	3987      	bclri      	r1, 7
 740:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 744:	020a      	lrw      	r0, 0x0	// a18 <dsleep_enter+0xa18>
 746:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 74a:	ea028003 	movi      	r2, 32771
 74e:	c5e24902 	rotli      	r2, r2, 15
 752:	3180      	movi      	r1, 128
 754:	9267      	ld.w      	r3, (r2, 0x1c)
 756:	4128      	lsli      	r1, r1, 8
 758:	68c4      	and      	r3, r1
 75a:	e903000a 	bez      	r3, 0x76e	// 76e <dsleep_enter+0x76e>
 75e:	9227      	ld.w      	r1, (r2, 0x1c)
 760:	301c      	movi      	r0, 28
 762:	398f      	bclri      	r1, 15
 764:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 768:	0212      	lrw      	r0, 0x0	// a1c <dsleep_enter+0xa1c>
 76a:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 76e:	ea048003 	movi      	r4, 32771
 772:	c5e44904 	rotli      	r4, r4, 15
 776:	d8642028 	ld.w      	r3, (r4, 0xa0)
 77a:	e4632100 	andi      	r3, r3, 256
 77e:	e903000b 	bez      	r3, 0x794	// 794 <dsleep_enter+0x794>
 782:	0217      	lrw      	r0, 0x0	// a20 <dsleep_enter+0xa20>
 784:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 788:	d8242028 	ld.w      	r1, (r4, 0xa0)
 78c:	39b0      	bseti      	r1, 16
 78e:	30a0      	movi      	r0, 160
 790:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 794:	ea048003 	movi      	r4, 32771
 798:	c5e44904 	rotli      	r4, r4, 15
 79c:	3280      	movi      	r2, 128
 79e:	d8642028 	ld.w      	r3, (r4, 0xa0)
 7a2:	4246      	lsli      	r2, r2, 6
 7a4:	68c8      	and      	r3, r2
 7a6:	e903000b 	bez      	r3, 0x7bc	// 7bc <dsleep_enter+0x7bc>
 7aa:	0300      	lrw      	r0, 0x0	// a24 <dsleep_enter+0xa24>
 7ac:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 7b0:	d8242028 	ld.w      	r1, (r4, 0xa0)
 7b4:	39b1      	bseti      	r1, 17
 7b6:	30a0      	movi      	r0, 160
 7b8:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 7bc:	ea048003 	movi      	r4, 32771
 7c0:	c5e44904 	rotli      	r4, r4, 15
 7c4:	3280      	movi      	r2, 128
 7c6:	d8642028 	ld.w      	r3, (r4, 0xa0)
 7ca:	4247      	lsli      	r2, r2, 7
 7cc:	68c8      	and      	r3, r2
 7ce:	e903000b 	bez      	r3, 0x7e4	// 7e4 <dsleep_enter+0x7e4>
 7d2:	0309      	lrw      	r0, 0x0	// a28 <dsleep_enter+0xa28>
 7d4:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 7d8:	d8242028 	ld.w      	r1, (r4, 0xa0)
 7dc:	39b2      	bseti      	r1, 18
 7de:	30a0      	movi      	r0, 160
 7e0:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 7e4:	ea048003 	movi      	r4, 32771
 7e8:	c5e44904 	rotli      	r4, r4, 15
 7ec:	3280      	movi      	r2, 128
 7ee:	d8642028 	ld.w      	r3, (r4, 0xa0)
 7f2:	4248      	lsli      	r2, r2, 8
 7f4:	68c8      	and      	r3, r2
 7f6:	e903000b 	bez      	r3, 0x80c	// 80c <dsleep_enter+0x80c>
 7fa:	0312      	lrw      	r0, 0x0	// a2c <dsleep_enter+0xa2c>
 7fc:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 800:	d8242028 	ld.w      	r1, (r4, 0xa0)
 804:	39b3      	bseti      	r1, 19
 806:	30a0      	movi      	r0, 160
 808:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 80c:	ea048003 	movi      	r4, 32771
 810:	c5e44904 	rotli      	r4, r4, 15
 814:	d8642020 	ld.w      	r3, (r4, 0x80)
 818:	e4632004 	andi      	r3, r3, 4
 81c:	e903000c 	bez      	r3, 0x834	// 834 <dsleep_enter+0x834>
 820:	031b      	lrw      	r0, 0x0	// a30 <dsleep_enter+0xa30>
 822:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 826:	d8242020 	ld.w      	r1, (r4, 0x80)
 82a:	3982      	bclri      	r1, 2
 82c:	3983      	bclri      	r1, 3
 82e:	3080      	movi      	r0, 128
 830:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 834:	e0000000 	bsr      	0x0	// 0 <system_sleep_enter_hook>
 838:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 83c:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 840:	3000      	movi      	r0, 0
 842:	1497      	pop      	r4-r10, r15
 844:	d844006c 	ld.b      	r2, (r4, 0x6c)
 848:	d8040064 	ld.b      	r0, (r4, 0x64)
 84c:	c4435c00 	ins      	r2, r3, 0, 0
 850:	c4c054e0 	zext      	r0, r0, 7, 6
 854:	c4405c23 	ins      	r2, r0, 4, 3
 858:	dc44006c 	st.b      	r2, (r4, 0x6c)
 85c:	d844006e 	ld.b      	r2, (r4, 0x6e)
 860:	e44220fe 	andi      	r2, r2, 254
 864:	c4435c02 	ins      	r2, r3, 2, 2
 868:	6ccb      	mov      	r3, r2
 86a:	c48154e1 	zext      	r1, r1, 7, 4
 86e:	c4615c63 	ins      	r3, r1, 6, 3
 872:	dc64006e 	st.b      	r3, (r4, 0x6e)
 876:	3320      	movi      	r3, 32
 878:	dc64006f 	st.b      	r3, (r4, 0x6f)
 87c:	d8640070 	ld.b      	r3, (r4, 0x70)
 880:	e46320e0 	andi      	r3, r3, 224
 884:	3200      	movi      	r2, 0
 886:	c4625c05 	ins      	r3, r2, 5, 5
 88a:	dc640070 	st.b      	r3, (r4, 0x70)
 88e:	074d      	br      	0x728	// 728 <pmu_pd_timer_clear_pnd_sec+0x728>
 890:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_clear_pnd_sec>
 894:	dd49200b 	st.w      	r10, (r9, 0x2c)
 898:	ea098003 	movi      	r9, 32771
 89c:	c5e94909 	rotli      	r9, r9, 15
 8a0:	3101      	movi      	r1, 1
 8a2:	30b0      	movi      	r0, 176
 8a4:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 8a8:	d8292023 	ld.w      	r1, (r9, 0x8c)
 8ac:	ea03ffc0 	movi      	r3, 65472
 8b0:	c6234903 	rotli      	r3, r3, 17
 8b4:	684c      	and      	r1, r3
 8b6:	c6a05023 	bmaski      	r3, 22
 8ba:	2b00      	subi      	r3, 1
 8bc:	6c4c      	or      	r1, r3
 8be:	308c      	movi      	r0, 140
 8c0:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 8c4:	d8292023 	ld.w      	r1, (r9, 0x8c)
 8c8:	ec210001 	ori      	r1, r1, 1
 8cc:	308c      	movi      	r0, 140
 8ce:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 8d2:	d8692023 	ld.w      	r3, (r9, 0x8c)
 8d6:	e4632001 	andi      	r3, r3, 1
 8da:	e923fffc 	bnez      	r3, 0x8d2	// 8d2 <dsleep_enter+0x8d2>
 8de:	d8692021 	ld.w      	r3, (r9, 0x84)
 8e2:	311f      	movi      	r1, 31
 8e4:	3084      	movi      	r0, 132
 8e6:	dc642043 	st.w      	r3, (r4, 0x10c)
 8ea:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 8ee:	33e0      	movi      	r3, 224
 8f0:	4378      	lsli      	r3, r3, 24
 8f2:	d8292022 	ld.w      	r1, (r9, 0x88)
 8f6:	6c4c      	or      	r1, r3
 8f8:	3088      	movi      	r0, 136
 8fa:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 8fe:	d8292020 	ld.w      	r1, (r9, 0x80)
 902:	3984      	bclri      	r1, 4
 904:	3080      	movi      	r0, 128
 906:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 90a:	8464      	ld.b      	r3, (r4, 0x4)
 90c:	e4632001 	andi      	r3, r3, 1
 910:	e903fc24 	bez      	r3, 0x158	// 158 <dsleep_enter+0x158>
 914:	e907fc1f 	bez      	r7, 0x152	// 152 <dsleep_enter+0x152>
 918:	d8682000 	ld.w      	r3, (r8, 0x0)
 91c:	9304      	ld.w      	r0, (r3, 0x10)
 91e:	6418      	cmphs      	r6, r0
 920:	e860fc10 	bt      	0x140	// 140 <dsleep_enter+0x140>
 924:	601a      	subu      	r0, r6
 926:	6540      	cmphs      	r0, r5
 928:	e860fc0f 	bt      	0x146	// 146 <dsleep_enter+0x146>
 92c:	5d01      	subu      	r0, r5, r0
 92e:	ea03869f 	movi      	r3, 34463
 932:	3bb0      	bseti      	r3, 16
 934:	61c0      	addu      	r7, r0
 936:	640c      	cmphs      	r3, r0
 938:	c4070c40 	inct      	r0, r7, 0
 93c:	ea034e1f 	movi      	r3, 19999
 940:	6cce      	nor      	r3, r3
 942:	600c      	addu      	r0, r3
 944:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 948:	111b      	lrw      	r0, 0x0	// a34 <dsleep_enter+0xa34>
 94a:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 94e:	ea0310a4 	movi      	r3, 4260
 952:	dc64103a 	st.h      	r3, (r4, 0x74)
 956:	9422      	ld.w      	r1, (r4, 0x8)
 958:	3300      	movi      	r3, 0
 95a:	590c      	addu      	r0, r1, r3
 95c:	5c4c      	addu      	r2, r4, r3
 95e:	d98009f0 	ld.b      	r12, (r0, 0x9f0)
 962:	2300      	addi      	r3, 1
 964:	dd820078 	st.b      	r12, (r2, 0x78)
 968:	3b46      	cmpnei      	r3, 6
 96a:	d80009f6 	ld.b      	r0, (r0, 0x9f6)
 96e:	dc02007e 	st.b      	r0, (r2, 0x7e)
 972:	0bf4      	bt      	0x95a	// 95a <dsleep_enter+0x95a>
 974:	3300      	movi      	r3, 0
 976:	dc642021 	st.w      	r3, (r4, 0x84)
 97a:	3200      	movi      	r2, 0
 97c:	dc642022 	st.w      	r3, (r4, 0x88)
 980:	3300      	movi      	r3, 0
 982:	dc442023 	st.w      	r2, (r4, 0x8c)
 986:	dc642024 	st.w      	r3, (r4, 0x90)
 98a:	330a      	movi      	r3, 10
 98c:	dc640086 	st.b      	r3, (r4, 0x86)
 990:	d8610a4e 	ld.b      	r3, (r1, 0xa4e)
 994:	e4632040 	andi      	r3, r3, 64
 998:	3b40      	cmpnei      	r3, 0
 99a:	6483      	mvcv      	r2
 99c:	7488      	zextb      	r2, r2
 99e:	3000      	movi      	r0, 0
 9a0:	c4025c64 	ins      	r0, r2, 7, 4
 9a4:	dc040085 	st.b      	r0, (r4, 0x85)
 9a8:	d82109c7 	ld.b      	r1, (r1, 0x9c7)
 9ac:	e9010004 	bez      	r1, 0x9b4	// 9b4 <dsleep_enter+0x9b4>
 9b0:	e903fbd9 	bez      	r3, 0x162	// 162 <dsleep_enter+0x162>
 9b4:	3b40      	cmpnei      	r3, 0
 9b6:	c4000501 	mvc      	r1
 9ba:	d8640085 	ld.b      	r3, (r4, 0x85)
 9be:	c4615c20 	ins      	r3, r1, 1, 0
 9c2:	3100      	movi      	r1, 0
 9c4:	c4615c22 	ins      	r3, r1, 3, 2
 9c8:	dc640085 	st.b      	r3, (r4, 0x85)
 9cc:	107b      	lrw      	r3, 0x0	// a38 <dsleep_enter+0xa38>
 9ce:	d0430501 	ldr.h      	r1, (r3, r2 << 3)
 9d2:	7405      	zexth      	r0, r1
 9d4:	32ae      	movi      	r2, 174
 9d6:	c4028021 	divu      	r1, r2, r0
 9da:	74c5      	zexth      	r3, r1
 9dc:	7c40      	mult      	r1, r0
 9de:	6086      	subu      	r2, r1
 9e0:	e9020004 	bez      	r2, 0x9e8	// 9e8 <dsleep_enter+0x9e8>
 9e4:	2300      	addi      	r3, 1
 9e6:	74cd      	zexth      	r3, r3
 9e8:	d8240085 	ld.b      	r1, (r4, 0x85)
 9ec:	dc642022 	st.w      	r3, (r4, 0x88)
 9f0:	c4415463 	zext      	r3, r1, 3, 2
 9f4:	e903fbc3 	bez      	r3, 0x17a	// 17a <dsleep_enter+0x17a>
 9f8:	3b41      	cmpnei      	r3, 1
 9fa:	e840fc53 	bf      	0x2a0	// 2a0 <dsleep_enter+0x2a0>
 9fe:	31eb      	movi      	r1, 235
 a00:	1044      	lrw      	r2, 0x0	// a10 <dsleep_enter+0xa10>
 a02:	4124      	lsli      	r1, r1, 4
 a04:	100e      	lrw      	r0, 0x0	// a3c <dsleep_enter+0xa3c>
 a06:	e0000000 	bsr      	0x0	// 0 <assert_internal>
 a0a:	e800fbe7 	br      	0x1d8	// 1d8 <dsleep_enter+0x1d8>
	...

Disassembly of section .text.lmac_dsleep_init:

00000000 <lmac_dsleep_init>:
   0:	14d0      	push      	r15
   2:	31c7      	movi      	r1, 199
   4:	4124      	lsli      	r1, r1, 4
   6:	3000      	movi      	r0, 0
   8:	e0000000 	bsr      	0x0	// 0 <sys_sleepdata_request>
   c:	1066      	lrw      	r3, 0x0	// 24 <lmac_dsleep_init+0x24>
   e:	b302      	st.w      	r0, (r3, 0x8)
  10:	e9200008 	bnez      	r0, 0x20	// 20 <lmac_dsleep_init+0x20>
  14:	1045      	lrw      	r2, 0x0	// 28 <lmac_dsleep_init+0x28>
  16:	ea011016 	movi      	r1, 4118
  1a:	1005      	lrw      	r0, 0x0	// 2c <assert_internal+0x2c>
  1c:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  20:	1490      	pop      	r15
	...

Disassembly of section .text.dsleep_uart0_set_baudrate.constprop.7:

00000000 <dsleep_uart0_set_baudrate.constprop.7>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e0000000 	bsr      	0x0	// 0 <sys_get_apbclk>
   8:	33e1      	movi      	r3, 225
   a:	4369      	lsli      	r3, r3, 9
   c:	c4608040 	divs      	r0, r0, r3
  10:	9463      	ld.w      	r3, (r4, 0xc)
  12:	ec630080 	ori      	r3, r3, 128
  16:	b463      	st.w      	r3, (r4, 0xc)
  18:	c4805563 	zext      	r3, r0, 11, 4
  1c:	b460      	st.w      	r3, (r4, 0x0)
  1e:	c5805663 	zext      	r3, r0, 19, 12
  22:	e400200f 	andi      	r0, r0, 15
  26:	b461      	st.w      	r3, (r4, 0x4)
  28:	dc042030 	st.w      	r0, (r4, 0xc0)
  2c:	9463      	ld.w      	r3, (r4, 0xc)
  2e:	3b87      	bclri      	r3, 7
  30:	b463      	st.w      	r3, (r4, 0xc)
  32:	1491      	pop      	r4, r15
