
disasm/liblmac/obj/mars_lmac_util.o:     file format elf32-csky-little


Disassembly of section .text.lmac_psm_info_update:

00000000 <lmac_psm_info_update>:
   0:	14c2      	push      	r4-r5
   2:	1073      	lrw      	r3, 0x0	// 4c <lmac_psm_info_update+0x4c>
   4:	3200      	movi      	r2, 0
   6:	d983227e 	ld.w      	r12, (r3, 0x9f8)
   a:	6c4b      	mov      	r1, r2
   c:	6c0b      	mov      	r0, r2
   e:	e48309f7 	addi      	r4, r3, 2552
  12:	6532      	cmpne      	r12, r4
  14:	0808      	bt      	0x24	// 24 <lmac_psm_info_update+0x24>
  16:	dc031504 	st.h      	r0, (r3, 0xa08)
  1a:	dc231505 	st.h      	r1, (r3, 0xa0a)
  1e:	dc431506 	st.h      	r2, (r3, 0xa0c)
  22:	1482      	pop      	r4-r5
  24:	d9ac006b 	ld.b      	r13, (r12, 0x6b)
  28:	e4ad2002 	andi      	r5, r13, 2
  2c:	2000      	addi      	r0, 1
  2e:	7401      	zexth      	r0, r0
  30:	e9050004 	bez      	r5, 0x38	// 38 <lmac_psm_info_update+0x38>
  34:	2100      	addi      	r1, 1
  36:	7445      	zexth      	r1, r1
  38:	e5ad2008 	andi      	r13, r13, 8
  3c:	e90d0004 	bez      	r13, 0x44	// 44 <lmac_psm_info_update+0x44>
  40:	2200      	addi      	r2, 1
  42:	7489      	zexth      	r2, r2
  44:	d98c2000 	ld.w      	r12, (r12, 0x0)
  48:	07e5      	br      	0x12	// 12 <lmac_psm_info_update+0x12>
  4a:	0000      	.short	0x0000
  4c:	00000000 	.long	0x00000000

Disassembly of section .text.__lmac_delay_asm:

00000000 <__lmac_delay_asm>:
   0:	c4201020 	decgt      	r0, r0, 1
   4:	e860fffe 	bt      	0x0	// 0 <__lmac_delay_asm>
   8:	783c      	jmp      	r15

Disassembly of section .text.lmac_delay_us:

00000000 <lmac_delay_us>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e0000000 	bsr      	0x0	// 0 <sys_get_sysclk>
   8:	106e      	lrw      	r3, 0xf423f	// 40 <lmac_delay_us+0x40>
   a:	640d      	cmplt      	r3, r0
   c:	ea04f424 	movi      	r4, 62500
  10:	c4844904 	rotli      	r4, r4, 4
  14:	0810      	bt      	0x34	// 34 <sys_get_sysclk+0x34>
  16:	e0000000 	bsr      	0x0	// 0 <sys_get_sysclk>
  1a:	7c14      	mult      	r0, r5
  1c:	c4808020 	divu      	r0, r0, r4
  20:	eb00002f 	cmphsi      	r0, 48
  24:	0c07      	bf      	0x32	// 32 <lmac_delay_us+0x32>
  26:	282e      	subi      	r0, 47
  28:	3303      	movi      	r3, 3
  2a:	c4608020 	divu      	r0, r0, r3
  2e:	e0000000 	bsr      	0x0	// 0 <lmac_delay_us>
  32:	1492      	pop      	r4-r5, r15
  34:	e0000000 	bsr      	0x0	// 0 <sys_get_sysclk>
  38:	c4808040 	divs      	r0, r0, r4
  3c:	7c14      	mult      	r0, r5
  3e:	07f1      	br      	0x20	// 20 <lmac_delay_us+0x20>
  40:	423f      	.short	0x423f
  42:	000f      	.short	0x000f

Disassembly of section .text.hgics_print_hex:

00000000 <hgics_print_hex>:
   0:	14d6      	push      	r4-r9, r15
   2:	6d83      	mov      	r6, r0
   4:	6d47      	mov      	r5, r1
   6:	3400      	movi      	r4, 0
   8:	10f1      	lrw      	r7, 0x0	// 4c <hgics_print_hex+0x4c>
   a:	ea880012 	lrw      	r8, 0x0	// 50 <hgics_print_hex+0x50>
   e:	ea890012 	lrw      	r9, 0x0	// 54 <hgics_print_hex+0x54>
  12:	6551      	cmplt      	r4, r5
  14:	0805      	bt      	0x1e	// 1e <hgics_print_hex+0x1e>
  16:	1011      	lrw      	r0, 0x0	// 58 <hgics_print_hex+0x58>
  18:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  1c:	1496      	pop      	r4-r9, r15
  1e:	e9640009 	blsz      	r4, 0x30	// 30 <hgics_print_hex+0x30>
  22:	e464200f 	andi      	r3, r4, 15
  26:	e923000c 	bnez      	r3, 0x3e	// 3e <hgics_print_hex+0x3e>
  2a:	6c23      	mov      	r0, r8
  2c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  30:	d0860021 	ldr.b      	r1, (r6, r4 << 0)
  34:	6c27      	mov      	r0, r9
  36:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  3a:	2400      	addi      	r4, 1
  3c:	07eb      	br      	0x12	// 12 <hgics_print_hex+0x12>
  3e:	e4642007 	andi      	r3, r4, 7
  42:	e923fff7 	bnez      	r3, 0x30	// 30 <hgics_print_hex+0x30>
  46:	6c1f      	mov      	r0, r7
  48:	07f2      	br      	0x2c	// 2c <hgics_print_hex+0x2c>
	...

Disassembly of section .text.hgics_print_char:

00000000 <hgics_print_char>:
   0:	14d5      	push      	r4-r8, r15
   2:	6d83      	mov      	r6, r0
   4:	6d47      	mov      	r5, r1
   6:	3400      	movi      	r4, 0
   8:	10ed      	lrw      	r7, 0x0	// 3c <hgics_print_char+0x3c>
   a:	ea88000e 	lrw      	r8, 0x0	// 40 <hgics_print_char+0x40>
   e:	6551      	cmplt      	r4, r5
  10:	0805      	bt      	0x1a	// 1a <hgics_print_char+0x1a>
  12:	100d      	lrw      	r0, 0x0	// 44 <hgics_print_char+0x44>
  14:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  18:	1495      	pop      	r4-r8, r15
  1a:	e9640009 	blsz      	r4, 0x2c	// 2c <hgics_print_char+0x2c>
  1e:	e464201f 	andi      	r3, r4, 31
  22:	e9230005 	bnez      	r3, 0x2c	// 2c <hgics_print_char+0x2c>
  26:	6c1f      	mov      	r0, r7
  28:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  2c:	d0860021 	ldr.b      	r1, (r6, r4 << 0)
  30:	6c23      	mov      	r0, r8
  32:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  36:	2400      	addi      	r4, 1
  38:	07eb      	br      	0xe	// e <hgics_print_char+0xe>
	...

Disassembly of section .text.lmac_hw_init:

00000000 <lmac_hw_init>:
   0:	14d4      	push      	r4-r7, r15
   2:	12ca      	lrw      	r6, 0x0	// 128 <lmac_hw_init+0x128>
   4:	6dc7      	mov      	r7, r1
   6:	6d03      	mov      	r4, r0
   8:	e0000000 	bsr      	0x0	// 0 <lhw_irq_init>
   c:	9660      	ld.w      	r3, (r6, 0x0)
   e:	3500      	movi      	r5, 0
  10:	b3b3      	st.w      	r5, (r3, 0x4c)
  12:	9344      	ld.w      	r2, (r3, 0x10)
  14:	b34f      	st.w      	r2, (r3, 0x3c)
  16:	9350      	ld.w      	r2, (r3, 0x40)
  18:	3a84      	bclri      	r2, 4
  1a:	3a85      	bclri      	r2, 5
  1c:	b350      	st.w      	r2, (r3, 0x40)
  1e:	4484      	lsli      	r4, r4, 4
  20:	9310      	ld.w      	r0, (r3, 0x40)
  22:	e4842030 	andi      	r4, r4, 48
  26:	6d00      	or      	r4, r0
  28:	b390      	st.w      	r4, (r3, 0x40)
  2a:	3100      	movi      	r1, 0
  2c:	d843203f 	ld.w      	r2, (r3, 0xfc)
  30:	2907      	subi      	r1, 8
  32:	6884      	and      	r2, r1
  34:	dc43203f 	st.w      	r2, (r3, 0xfc)
  38:	d843203f 	ld.w      	r2, (r3, 0xfc)
  3c:	e4272007 	andi      	r1, r7, 7
  40:	6c48      	or      	r1, r2
  42:	dc23203f 	st.w      	r1, (r3, 0xfc)
  46:	6c17      	mov      	r0, r5
  48:	3315      	movi      	r3, 21
  4a:	3210      	movi      	r2, 16
  4c:	310b      	movi      	r1, 11
  4e:	e0000000 	bsr      	0x0	// 0 <lhw_cfg_tx_delay_before>
  52:	3329      	movi      	r3, 41
  54:	6c8f      	mov      	r2, r3
  56:	6c4f      	mov      	r1, r3
  58:	6c0f      	mov      	r0, r3
  5a:	e0000000 	bsr      	0x0	// 0 <lhw_cfg_tx_delay_after>
  5e:	6c57      	mov      	r1, r5
  60:	320a      	movi      	r2, 10
  62:	3082      	movi      	r0, 130
  64:	e0000000 	bsr      	0x0	// 0 <lhw_cfg_sifs>
  68:	3202      	movi      	r2, 2
  6a:	3101      	movi      	r1, 1
  6c:	6c17      	mov      	r0, r5
  6e:	e0000000 	bsr      	0x0	// 0 <lhw_cfg_tx_dalay_dac_rf>
  72:	3012      	movi      	r0, 18
  74:	e0000000 	bsr      	0x0	// 0 <lhw_cfg_tx_delay_pa>
  78:	9660      	ld.w      	r3, (r6, 0x0)
  7a:	3100      	movi      	r1, 0
  7c:	9350      	ld.w      	r2, (r3, 0x40)
  7e:	ec421000 	ori      	r2, r2, 4096
  82:	b350      	st.w      	r2, (r3, 0x40)
  84:	9350      	ld.w      	r2, (r3, 0x40)
  86:	3a8d      	bclri      	r2, 13
  88:	b350      	st.w      	r2, (r3, 0x40)
  8a:	9350      	ld.w      	r2, (r3, 0x40)
  8c:	3a8e      	bclri      	r2, 14
  8e:	b350      	st.w      	r2, (r3, 0x40)
  90:	9350      	ld.w      	r2, (r3, 0x40)
  92:	3a8f      	bclri      	r2, 15
  94:	b350      	st.w      	r2, (r3, 0x40)
  96:	9350      	ld.w      	r2, (r3, 0x40)
  98:	3a80      	bclri      	r2, 0
  9a:	b350      	st.w      	r2, (r3, 0x40)
  9c:	9350      	ld.w      	r2, (r3, 0x40)
  9e:	3a80      	bclri      	r2, 0
  a0:	b350      	st.w      	r2, (r3, 0x40)
  a2:	9350      	ld.w      	r2, (r3, 0x40)
  a4:	3ab2      	bseti      	r2, 18
  a6:	b350      	st.w      	r2, (r3, 0x40)
  a8:	934c      	ld.w      	r2, (r3, 0x30)
  aa:	3a8d      	bclri      	r2, 13
  ac:	b34c      	st.w      	r2, (r3, 0x30)
  ae:	935e      	ld.w      	r2, (r3, 0x78)
  b0:	c40256e2 	zext      	r2, r2, 23, 0
  b4:	b35e      	st.w      	r2, (r3, 0x78)
  b6:	935e      	ld.w      	r2, (r3, 0x78)
  b8:	3ab8      	bseti      	r2, 24
  ba:	3ab9      	bseti      	r2, 25
  bc:	b35e      	st.w      	r2, (r3, 0x78)
  be:	d843203e 	ld.w      	r2, (r3, 0xf8)
  c2:	3a80      	bclri      	r2, 0
  c4:	dc43203e 	st.w      	r2, (r3, 0xf8)
  c8:	9356      	ld.w      	r2, (r3, 0x58)
  ca:	29f0      	subi      	r1, 241
  cc:	6884      	and      	r2, r1
  ce:	b356      	st.w      	r2, (r3, 0x58)
  d0:	9356      	ld.w      	r2, (r3, 0x58)
  d2:	b356      	st.w      	r2, (r3, 0x58)
  d4:	ea224e79 	movih      	r2, 20089
  d8:	3aa0      	bseti      	r2, 0
  da:	dc432020 	st.w      	r2, (r3, 0x80)
  de:	d8432028 	ld.w      	r2, (r3, 0xa0)
  e2:	3a80      	bclri      	r2, 0
  e4:	3a81      	bclri      	r2, 1
  e6:	dc432028 	st.w      	r2, (r3, 0xa0)
  ea:	300b      	movi      	r0, 11
  ec:	e0000000 	bsr      	0x0	// 0 <lhw_cfg_phy_rx_delay>
  f0:	9660      	ld.w      	r3, (r6, 0x0)
  f2:	3107      	movi      	r1, 7
  f4:	d8432100 	ld.w      	r2, (r3, 0x400)
  f8:	3a82      	bclri      	r2, 2
  fa:	3a83      	bclri      	r2, 3
  fc:	dc432100 	st.w      	r2, (r3, 0x400)
 100:	d8432100 	ld.w      	r2, (r3, 0x400)
 104:	ec42000c 	ori      	r2, r2, 12
 108:	dc432100 	st.w      	r2, (r3, 0x400)
 10c:	302f      	movi      	r0, 47
 10e:	b3a8      	st.w      	r5, (r3, 0x20)
 110:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
 114:	3107      	movi      	r1, 7
 116:	3030      	movi      	r0, 48
 118:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
 11c:	3107      	movi      	r1, 7
 11e:	3031      	movi      	r0, 49
 120:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
 124:	6c17      	mov      	r0, r5
 126:	1494      	pop      	r4-r7, r15
 128:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_wait_bgscan:

00000000 <lmac_wait_bgscan>:
   0:	e9000017 	bez      	r0, 0x2e	// 2e <lmac_wait_bgscan+0x2e>
   4:	106b      	lrw      	r3, 0x0	// 30 <lmac_wait_bgscan+0x30>
   6:	9360      	ld.w      	r3, (r3, 0x0)
   8:	9351      	ld.w      	r2, (r3, 0x44)
   a:	3a87      	bclri      	r2, 7
   c:	b351      	st.w      	r2, (r3, 0x44)
   e:	3280      	movi      	r2, 128
  10:	b352      	st.w      	r2, (r3, 0x48)
  12:	9351      	ld.w      	r2, (r3, 0x44)
  14:	3a8a      	bclri      	r2, 10
  16:	b351      	st.w      	r2, (r3, 0x44)
  18:	3280      	movi      	r2, 128
  1a:	4243      	lsli      	r2, r2, 3
  1c:	b352      	st.w      	r2, (r3, 0x48)
  1e:	dc032031 	st.w      	r0, (r3, 0xc4)
  22:	d8432033 	ld.w      	r2, (r3, 0xcc)
  26:	ec420004 	ori      	r2, r2, 4
  2a:	dc432033 	st.w      	r2, (r3, 0xcc)
  2e:	783c      	jmp      	r15
  30:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_wait_sync:

00000000 <lmac_wait_sync>:
   0:	1075      	lrw      	r3, 0x0	// 54 <lmac_wait_sync+0x54>
   2:	d843034a 	ld.b      	r2, (r3, 0x34a)
   6:	e4422001 	andi      	r2, r2, 1
   a:	e9020004 	bez      	r2, 0x12	// 12 <lmac_wait_sync+0x12>
   e:	e400013f 	addi      	r0, r0, 320
  12:	d84311ee 	ld.h      	r2, (r3, 0x3dc)
  16:	6008      	addu      	r0, r2
  18:	e900001c 	bez      	r0, 0x50	// 50 <lmac_wait_sync+0x50>
  1c:	d84309dc 	ld.b      	r2, (r3, 0x9dc)
  20:	3101      	movi      	r1, 1
  22:	c4415c07 	ins      	r2, r1, 7, 7
  26:	dc4309dc 	st.b      	r2, (r3, 0x9dc)
  2a:	106c      	lrw      	r3, 0x0	// 58 <lmac_wait_sync+0x58>
  2c:	9360      	ld.w      	r3, (r3, 0x0)
  2e:	9351      	ld.w      	r2, (r3, 0x44)
  30:	ec420100 	ori      	r2, r2, 256
  34:	b351      	st.w      	r2, (r3, 0x44)
  36:	9351      	ld.w      	r2, (r3, 0x44)
  38:	3a87      	bclri      	r2, 7
  3a:	b351      	st.w      	r2, (r3, 0x44)
  3c:	3280      	movi      	r2, 128
  3e:	b352      	st.w      	r2, (r3, 0x48)
  40:	dc032031 	st.w      	r0, (r3, 0xc4)
  44:	d8432033 	ld.w      	r2, (r3, 0xcc)
  48:	ec420004 	ori      	r2, r2, 4
  4c:	dc432033 	st.w      	r2, (r3, 0xcc)
  50:	306c      	movi      	r0, 108
  52:	783c      	jmp      	r15
	...

Disassembly of section .text.lmac_cancle_tx_tmo:

00000000 <lmac_cancle_tx_tmo>:
   0:	1069      	lrw      	r3, 0x0	// 24 <lmac_cancle_tx_tmo+0x24>
   2:	9360      	ld.w      	r3, (r3, 0x0)
   4:	d8432033 	ld.w      	r2, (r3, 0xcc)
   8:	ec420008 	ori      	r2, r2, 8
   c:	dc432033 	st.w      	r2, (r3, 0xcc)
  10:	3280      	movi      	r2, 128
  12:	4247      	lsli      	r2, r2, 7
  14:	b352      	st.w      	r2, (r3, 0x48)
  16:	9351      	ld.w      	r2, (r3, 0x44)
  18:	3a88      	bclri      	r2, 8
  1a:	b351      	st.w      	r2, (r3, 0x44)
  1c:	3280      	movi      	r2, 128
  1e:	4241      	lsli      	r2, r2, 1
  20:	b352      	st.w      	r2, (r3, 0x48)
  22:	783c      	jmp      	r15
  24:	0000      	.short	0x0000
	...

Disassembly of section .text.calc_max_agg_bytes:

00000000 <calc_max_agg_bytes>:
   0:	2000      	addi      	r0, 1
   2:	e4002003 	andi      	r0, r0, 3
   6:	4122      	lsli      	r1, r1, 2
   8:	6040      	addu      	r1, r0
   a:	1063      	lrw      	r3, 0x0	// 14 <calc_max_agg_bytes+0x14>
   c:	d0230880 	ldr.w      	r0, (r3, r1 << 2)
  10:	2803      	subi      	r0, 4
  12:	783c      	jmp      	r15
  14:	00000000 	.long	0x00000000

Disassembly of section .text.calc_symbol_len:

00000000 <calc_symbol_len>:
   0:	14d2      	push      	r4-r5, r15
   2:	1422      	subi      	r14, r14, 8
   4:	3943      	cmpnei      	r1, 3
   6:	6d43      	mov      	r5, r0
   8:	6d07      	mov      	r4, r1
   a:	6ccb      	mov      	r3, r2
   c:	0c09      	bf      	0x1e	// 1e <calc_symbol_len+0x1e>
   e:	3a07      	cmphsi      	r2, 8
  10:	0c07      	bf      	0x1e	// 1e <calc_symbol_len+0x1e>
  12:	1123      	lrw      	r1, 0x0	// 9c <calc_symbol_len+0x9c>
  14:	1103      	lrw      	r0, 0x0	// a0 <calc_symbol_len+0xa0>
  16:	b841      	st.w      	r2, (r14, 0x4)
  18:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  1c:	9861      	ld.w      	r3, (r14, 0x4)
  1e:	5c22      	addi      	r1, r4, 1
  20:	e4212003 	andi      	r1, r1, 3
  24:	4342      	lsli      	r2, r3, 2
  26:	6084      	addu      	r2, r1
  28:	101f      	lrw      	r0, 0x0	// a4 <calc_symbol_len+0xa4>
  2a:	d0400444 	ldr.h      	r4, (r0, r2 << 1)
  2e:	7511      	zexth      	r4, r4
  30:	e924000c 	bnez      	r4, 0x48	// 48 <calc_symbol_len+0x48>
  34:	6c8f      	mov      	r2, r3
  36:	3301      	movi      	r3, 1
  38:	c4234021 	lsl      	r1, r3, r1
  3c:	101b      	lrw      	r0, 0x0	// a8 <hgprintf+0xa8>
  3e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  42:	6c13      	mov      	r0, r4
  44:	1402      	addi      	r14, r14, 8
  46:	1492      	pop      	r4-r5, r15
  48:	4543      	lsli      	r2, r5, 3
  4a:	220d      	addi      	r2, 14
  4c:	c4828020 	divu      	r0, r2, r4
  50:	6f13      	mov      	r12, r4
  52:	7501      	zexth      	r4, r0
  54:	7c30      	mult      	r0, r12
  56:	6082      	subu      	r2, r0
  58:	e9020004 	bez      	r2, 0x60	// 60 <calc_symbol_len+0x60>
  5c:	2400      	addi      	r4, 1
  5e:	7511      	zexth      	r4, r4
  60:	3b07      	cmphsi      	r3, 8
  62:	080c      	bt      	0x7a	// 7a <calc_symbol_len+0x7a>
  64:	eb0401ff 	cmphsi      	r4, 512
  68:	0fed      	bf      	0x42	// 42 <calc_symbol_len+0x42>
  6a:	3201      	movi      	r2, 1
  6c:	7084      	lsl      	r2, r1
  6e:	b880      	st.w      	r4, (r14, 0x0)
  70:	6c57      	mov      	r1, r5
  72:	100f      	lrw      	r0, 0x0	// ac <calc_symbol_len+0xac>
  74:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  78:	07e5      	br      	0x42	// 42 <calc_symbol_len+0x42>
  7a:	3b4a      	cmpnei      	r3, 10
  7c:	080a      	bt      	0x90	// 90 <calc_symbol_len+0x90>
  7e:	eb0402ac 	cmphsi      	r4, 685
  82:	0fe0      	bf      	0x42	// 42 <calc_symbol_len+0x42>
  84:	3201      	movi      	r2, 1
  86:	7084      	lsl      	r2, r1
  88:	b880      	st.w      	r4, (r14, 0x0)
  8a:	6c57      	mov      	r1, r5
  8c:	1009      	lrw      	r0, 0x0	// b0 <calc_symbol_len+0xb0>
  8e:	07f3      	br      	0x74	// 74 <calc_symbol_len+0x74>
  90:	6c4f      	mov      	r1, r3
  92:	1009      	lrw      	r0, 0x0	// b4 <calc_symbol_len+0xb4>
  94:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  98:	07d5      	br      	0x42	// 42 <calc_symbol_len+0x42>
	...

Disassembly of section .text.lmac_get_seq_num:

00000000 <lmac_get_seq_num>:
   0:	14d0      	push      	r15
   2:	8061      	ld.b      	r3, (r0, 0x1)
   4:	8040      	ld.b      	r2, (r0, 0x0)
   6:	4368      	lsli      	r3, r3, 8
   8:	6cc8      	or      	r3, r2
   a:	e4432003 	andi      	r2, r3, 3
   e:	e9220017 	bnez      	r2, 0x3c	// 3c <lmac_get_seq_num+0x3c>
  12:	c4435462 	zext      	r2, r3, 3, 2
  16:	3a42      	cmpnei      	r2, 2
  18:	0c05      	bf      	0x22	// 22 <lmac_get_seq_num+0x22>
  1a:	3a43      	cmpnei      	r2, 3
  1c:	0c09      	bf      	0x2e	// 2e <lmac_get_seq_num+0x2e>
  1e:	e922000c 	bnez      	r2, 0x36	// 36 <lmac_get_seq_num+0x36>
  22:	8076      	ld.b      	r3, (r0, 0x16)
  24:	8017      	ld.b      	r0, (r0, 0x17)
  26:	4008      	lsli      	r0, r0, 8
  28:	6c0c      	or      	r0, r3
  2a:	4804      	lsri      	r0, r0, 4
  2c:	1490      	pop      	r15
  2e:	c48354e3 	zext      	r3, r3, 7, 4
  32:	3b4f      	cmpnei      	r3, 15
  34:	0ff7      	bf      	0x22	// 22 <lmac_get_seq_num+0x22>
  36:	ea00ffff 	movi      	r0, 65535
  3a:	07f9      	br      	0x2c	// 2c <lmac_get_seq_num+0x2c>
  3c:	3a41      	cmpnei      	r2, 1
  3e:	0bfc      	bt      	0x36	// 36 <lmac_get_seq_num+0x36>
  40:	c4435482 	zext      	r2, r3, 4, 2
  44:	3a41      	cmpnei      	r2, 1
  46:	0c0b      	bf      	0x5c	// 5c <lmac_get_seq_num+0x5c>
  48:	3a40      	cmpnei      	r2, 0
  4a:	0c0d      	bf      	0x64	// 64 <lmac_get_seq_num+0x64>
  4c:	3a42      	cmpnei      	r2, 2
  4e:	0ff4      	bf      	0x36	// 36 <lmac_get_seq_num+0x36>
  50:	3a43      	cmpnei      	r2, 3
  52:	0c0b      	bf      	0x68	// 68 <lmac_get_seq_num+0x68>
  54:	1006      	lrw      	r0, 0x0	// 6c <lmac_get_seq_num+0x6c>
  56:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  5a:	07ee      	br      	0x36	// 36 <lmac_get_seq_num+0x36>
  5c:	c4a354e3 	zext      	r3, r3, 7, 5
  60:	3b01      	cmphsi      	r3, 2
  62:	0bea      	bt      	0x36	// 36 <lmac_get_seq_num+0x36>
  64:	8805      	ld.h      	r0, (r0, 0xa)
  66:	07e3      	br      	0x2c	// 2c <lmac_get_seq_num+0x2c>
  68:	8807      	ld.h      	r0, (r0, 0xe)
  6a:	07e1      	br      	0x2c	// 2c <lmac_get_seq_num+0x2c>
  6c:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_quick_sort_sid:

00000000 <lmac_quick_sort_sid>:
   0:	14d8      	push      	r4-r11, r15
   2:	1423      	subi      	r14, r14, 12
   4:	ea880044 	lrw      	r8, 0x0	// 114 <lmac_quick_sort_sid+0x114>
   8:	12e4      	lrw      	r7, 0x0	// 118 <lmac_quick_sort_sid+0x118>
   a:	3300      	movi      	r3, 0
   c:	6ec3      	mov      	r11, r0
   e:	dc681000 	st.h      	r3, (r8, 0x0)
  12:	af20      	st.h      	r1, (r7, 0x0)
  14:	3500      	movi      	r5, 0
  16:	d0a70449 	ldr.h      	r9, (r7, r5 << 1)
  1a:	7665      	zexth      	r9, r9
  1c:	e4c91000 	subi      	r6, r9, 1
  20:	d0a81444 	ldr.hs      	r4, (r8, r5 << 1)
  24:	759b      	sexth      	r6, r6
  26:	6591      	cmplt      	r4, r6
  28:	b8a0      	st.w      	r5, (r14, 0x0)
  2a:	0c72      	bf      	0x10e	// 10e <lmac_quick_sort_sid+0x10e>
  2c:	d08b050c 	ldr.h      	r12, (r11, r4 << 3)
  30:	ea031fff 	movi      	r3, 8191
  34:	c46c202a 	and      	r10, r12, r3
  38:	4663      	lsli      	r3, r6, 3
  3a:	60ec      	addu      	r3, r11
  3c:	0403      	br      	0x42	// 42 <lmac_quick_sort_sid+0x42>
  3e:	2e00      	subi      	r6, 1
  40:	759b      	sexth      	r6, r6
  42:	8b40      	ld.h      	r2, (r3, 0x0)
  44:	ea011fff 	movi      	r1, 8191
  48:	6884      	and      	r2, r1
  4a:	6689      	cmplt      	r2, r10
  4c:	6f4f      	mov      	r13, r3
  4e:	083d      	bt      	0xc8	// c8 <lmac_quick_sort_sid+0xc8>
  50:	6591      	cmplt      	r4, r6
  52:	2b07      	subi      	r3, 8
  54:	0bf5      	bt      	0x3e	// 3e <lmac_quick_sort_sid+0x3e>
  56:	4443      	lsli      	r2, r4, 3
  58:	60ac      	addu      	r2, r11
  5a:	8a20      	ld.h      	r1, (r2, 0x0)
  5c:	ea001fff 	movi      	r0, 8191
  60:	6840      	and      	r1, r0
  62:	6469      	cmplt      	r10, r1
  64:	6ccb      	mov      	r3, r2
  66:	0846      	bt      	0xf2	// f2 <lmac_quick_sort_sid+0xf2>
  68:	6591      	cmplt      	r4, r6
  6a:	2207      	addi      	r2, 8
  6c:	0840      	bt      	0xec	// ec <lmac_quick_sort_sid+0xec>
  6e:	8b40      	ld.h      	r2, (r3, 0x0)
  70:	7511      	zexth      	r4, r4
  72:	c44a5d80 	ins      	r2, r10, 12, 0
  76:	ab40      	st.h      	r2, (r3, 0x0)
  78:	2500      	addi      	r5, 1
  7a:	5c62      	addi      	r3, r4, 1
  7c:	d4a80443 	str.h      	r3, (r8, r5 << 1)
  80:	d4a70449 	str.h      	r9, (r7, r5 << 1)
  84:	9860      	ld.w      	r3, (r14, 0x0)
  86:	7557      	sexth      	r5, r5
  88:	d4670444 	str.h      	r4, (r7, r3 << 1)
  8c:	5d63      	subi      	r3, r5, 1
  8e:	d0a70442 	ldr.h      	r2, (r7, r5 << 1)
  92:	d0a80440 	ldr.h      	r0, (r8, r5 << 1)
  96:	d0670441 	ldr.h      	r1, (r7, r3 << 1)
  9a:	d068044c 	ldr.h      	r12, (r8, r3 << 1)
  9e:	7489      	zexth      	r2, r2
  a0:	7401      	zexth      	r0, r0
  a2:	7445      	zexth      	r1, r1
  a4:	7731      	zexth      	r12, r12
  a6:	5a81      	subu      	r4, r2, r0
  a8:	c581008d 	subu      	r13, r1, r12
  ac:	6535      	cmplt      	r13, r4
  ae:	0c09      	bf      	0xc0	// c0 <lmac_quick_sort_sid+0xc0>
  b0:	d4a8044c 	str.h      	r12, (r8, r5 << 1)
  b4:	d4a70441 	str.h      	r1, (r7, r5 << 1)
  b8:	d4680440 	str.h      	r0, (r8, r3 << 1)
  bc:	d4670442 	str.h      	r2, (r7, r3 << 1)
  c0:	e9a5ffab 	bhsz      	r5, 0x16	// 16 <lmac_quick_sort_sid+0x16>
  c4:	1403      	addi      	r14, r14, 12
  c6:	1498      	pop      	r4-r11, r15
  c8:	6591      	cmplt      	r4, r6
  ca:	0fc6      	bf      	0x56	// 56 <lmac_quick_sort_sid+0x56>
  cc:	5c62      	addi      	r3, r4, 1
  ce:	4403      	lsli      	r0, r4, 3
  d0:	74cf      	sexth      	r3, r3
  d2:	6c77      	mov      	r1, r13
  d4:	3208      	movi      	r2, 8
  d6:	602c      	addu      	r0, r11
  d8:	b862      	st.w      	r3, (r14, 0x8)
  da:	ddae2001 	st.w      	r13, (r14, 0x4)
  de:	e0000000 	bsr      	0x0	// 0 <memcpy>
  e2:	9862      	ld.w      	r3, (r14, 0x8)
  e4:	6d0f      	mov      	r4, r3
  e6:	d9ae2001 	ld.w      	r13, (r14, 0x4)
  ea:	07b6      	br      	0x56	// 56 <lmac_quick_sort_sid+0x56>
  ec:	2400      	addi      	r4, 1
  ee:	7513      	sexth      	r4, r4
  f0:	07b5      	br      	0x5a	// 5a <lmac_quick_sort_sid+0x5a>
  f2:	6591      	cmplt      	r4, r6
  f4:	0fbd      	bf      	0x6e	// 6e <lmac_quick_sort_sid+0x6e>
  f6:	2e00      	subi      	r6, 1
  f8:	6c4f      	mov      	r1, r3
  fa:	759b      	sexth      	r6, r6
  fc:	3208      	movi      	r2, 8
  fe:	6c37      	mov      	r0, r13
 100:	b861      	st.w      	r3, (r14, 0x4)
 102:	e0000000 	bsr      	0x0	// 0 <memcpy>
 106:	6591      	cmplt      	r4, r6
 108:	9861      	ld.w      	r3, (r14, 0x4)
 10a:	0b97      	bt      	0x38	// 38 <lmac_quick_sort_sid+0x38>
 10c:	07b1      	br      	0x6e	// 6e <lmac_quick_sort_sid+0x6e>
 10e:	2d00      	subi      	r5, 1
 110:	7557      	sexth      	r5, r5
 112:	07d7      	br      	0xc0	// c0 <lmac_quick_sort_sid+0xc0>
	...

Disassembly of section .text.lmac_convert_sid2mac:

00000000 <lmac_convert_sid2mac>:
   0:	3000      	movi      	r0, 0
   2:	783c      	jmp      	r15

Disassembly of section .text.sid_mac_map_init:

00000000 <sid_mac_map_init>:
   0:	14c4      	push      	r4-r7
   2:	3100      	movi      	r1, 0
   4:	ea0c0000 	movi      	r12, 0
   8:	3320      	movi      	r3, 32
   a:	ea0d0052 	movi      	r13, 82
   e:	3430      	movi      	r4, 48
  10:	290e      	subi      	r1, 15
  12:	e58c107b 	subi      	r12, r12, 124
  16:	3544      	movi      	r5, 68
  18:	3608      	movi      	r6, 8
  1a:	8840      	ld.h      	r2, (r0, 0x0)
  1c:	c4435d80 	ins      	r2, r3, 12, 0
  20:	ea071fff 	movi      	r7, 8191
  24:	a840      	st.h      	r2, (r0, 0x0)
  26:	689c      	and      	r2, r7
  28:	3a47      	cmpnei      	r2, 7
  2a:	0811      	bt      	0x4c	// 4c <sid_mac_map_init+0x4c>
  2c:	dda00002 	st.b      	r13, (r0, 0x2)
  30:	a083      	st.b      	r4, (r0, 0x3)
  32:	a024      	st.b      	r1, (r0, 0x4)
  34:	dd800005 	st.b      	r12, (r0, 0x5)
  38:	a0a6      	st.b      	r5, (r0, 0x6)
  3a:	a0c7      	st.b      	r6, (r0, 0x7)
  3c:	ea021fff 	movi      	r2, 8191
  40:	60c8      	addu      	r3, r2
  42:	68c8      	and      	r3, r2
  44:	2007      	addi      	r0, 8
  46:	e923ffea 	bnez      	r3, 0x1a	// 1a <sid_mac_map_init+0x1a>
  4a:	1484      	pop      	r4-r7
  4c:	748c      	zextb      	r2, r3
  4e:	a042      	st.b      	r2, (r0, 0x2)
  50:	a043      	st.b      	r2, (r0, 0x3)
  52:	a044      	st.b      	r2, (r0, 0x4)
  54:	a045      	st.b      	r2, (r0, 0x5)
  56:	a046      	st.b      	r2, (r0, 0x6)
  58:	a047      	st.b      	r2, (r0, 0x7)
  5a:	07f1      	br      	0x3c	// 3c <sid_mac_map_init+0x3c>

Disassembly of section .text.ieee80211_is_data:

00000000 <ieee80211_is_data>:
   0:	e4602003 	andi      	r3, r0, 3
   4:	e9230008 	bnez      	r3, 0x14	// 14 <ieee80211_is_data+0x14>
   8:	c4405460 	zext      	r0, r0, 3, 2
   c:	3842      	cmpnei      	r0, 2
   e:	6403      	mvcv      	r0
  10:	7400      	zextb      	r0, r0
  12:	783c      	jmp      	r15
  14:	3b41      	cmpnei      	r3, 1
  16:	0809      	bt      	0x28	// 28 <ieee80211_is_data+0x28>
  18:	c4405480 	zext      	r0, r0, 4, 2
  1c:	e9000004 	bez      	r0, 0x24	// 24 <ieee80211_is_data+0x24>
  20:	3843      	cmpnei      	r0, 3
  22:	07f6      	br      	0xe	// e <ieee80211_is_data+0xe>
  24:	6c0f      	mov      	r0, r3
  26:	07f6      	br      	0x12	// 12 <ieee80211_is_data+0x12>
  28:	3000      	movi      	r0, 0
  2a:	07f4      	br      	0x12	// 12 <ieee80211_is_data+0x12>

Disassembly of section .text.ieee80211_is_data_qos:

00000000 <ieee80211_is_data_qos>:
   0:	e4602003 	andi      	r3, r0, 3
   4:	e923000c 	bnez      	r3, 0x1c	// 1c <ieee80211_is_data_qos+0x1c>
   8:	c4405462 	zext      	r2, r0, 3, 2
   c:	3a42      	cmpnei      	r2, 2
   e:	080f      	bt      	0x2c	// 2c <ieee80211_is_data_qos+0x2c>
  10:	c48054e0 	zext      	r0, r0, 7, 4
  14:	3848      	cmpnei      	r0, 8
  16:	6403      	mvcv      	r0
  18:	7400      	zextb      	r0, r0
  1a:	783c      	jmp      	r15
  1c:	3b41      	cmpnei      	r3, 1
  1e:	0809      	bt      	0x30	// 30 <ieee80211_is_data_qos+0x30>
  20:	c4405480 	zext      	r0, r0, 4, 2
  24:	e9000004 	bez      	r0, 0x2c	// 2c <ieee80211_is_data_qos+0x2c>
  28:	3843      	cmpnei      	r0, 3
  2a:	07f6      	br      	0x16	// 16 <ieee80211_is_data_qos+0x16>
  2c:	6c0f      	mov      	r0, r3
  2e:	07f6      	br      	0x1a	// 1a <ieee80211_is_data_qos+0x1a>
  30:	3000      	movi      	r0, 0
  32:	07f4      	br      	0x1a	// 1a <ieee80211_is_data_qos+0x1a>

Disassembly of section .text.ieee80211_get_qos_ctl:

00000000 <ieee80211_get_qos_ctl>:
   0:	8860      	ld.h      	r3, (r0, 0x0)
   2:	e4432003 	andi      	r2, r3, 3
   6:	e922000b 	bnez      	r2, 0x1c	// 1c <ieee80211_get_qos_ctl+0x1c>
   a:	8061      	ld.b      	r3, (r0, 0x1)
   c:	e4632003 	andi      	r3, r3, 3
  10:	3b43      	cmpnei      	r3, 3
  12:	0803      	bt      	0x18	// 18 <ieee80211_get_qos_ctl+0x18>
  14:	880f      	ld.h      	r0, (r0, 0x1e)
  16:	783c      	jmp      	r15
  18:	880c      	ld.h      	r0, (r0, 0x18)
  1a:	07fe      	br      	0x16	// 16 <ieee80211_get_qos_ctl+0x16>
  1c:	3a41      	cmpnei      	r2, 1
  1e:	0821      	bt      	0x60	// 60 <ieee80211_get_qos_ctl+0x60>
  20:	c4435483 	zext      	r3, r3, 4, 2
  24:	e923001a 	bnez      	r3, 0x58	// 58 <ieee80211_get_qos_ctl+0x58>
  28:	8061      	ld.b      	r3, (r0, 0x1)
  2a:	e4632001 	andi      	r3, r3, 1
  2e:	e9030013 	bez      	r3, 0x54	// 54 <ieee80211_get_qos_ctl+0x54>
  32:	8043      	ld.b      	r2, (r0, 0x3)
  34:	e4622020 	andi      	r3, r2, 32
  38:	3b40      	cmpnei      	r3, 0
  3a:	3112      	movi      	r1, 18
  3c:	330c      	movi      	r3, 12
  3e:	e4422040 	andi      	r2, r2, 64
  42:	c4610c40 	inct      	r3, r1, 0
  46:	3a40      	cmpnei      	r2, 0
  48:	c4630c46 	inct      	r3, r3, 6
  4c:	d0600420 	ldr.h      	r0, (r0, r3 << 0)
  50:	7401      	zexth      	r0, r0
  52:	07e2      	br      	0x16	// 16 <ieee80211_get_qos_ctl+0x16>
  54:	8049      	ld.b      	r2, (r0, 0x9)
  56:	07ef      	br      	0x34	// 34 <ieee80211_get_qos_ctl+0x34>
  58:	3b43      	cmpnei      	r3, 3
  5a:	0803      	bt      	0x60	// 60 <ieee80211_get_qos_ctl+0x60>
  5c:	880e      	ld.h      	r0, (r0, 0x1c)
  5e:	07dc      	br      	0x16	// 16 <ieee80211_get_qos_ctl+0x16>
  60:	3000      	movi      	r0, 0
  62:	07da      	br      	0x16	// 16 <ieee80211_get_qos_ctl+0x16>

Disassembly of section .text.lmac_get_tid:

00000000 <lmac_get_tid>:
   0:	14d3      	push      	r4-r6, r15
   2:	88a0      	ld.h      	r5, (r0, 0x0)
   4:	6d83      	mov      	r6, r0
   6:	6c17      	mov      	r0, r5
   8:	e0000000 	bsr      	0x0	// 0 <lmac_get_tid>
   c:	e9000019 	bez      	r0, 0x3e	// 3e <lmac_get_tid+0x3e>
  10:	6c17      	mov      	r0, r5
  12:	e0000000 	bsr      	0x0	// 0 <lmac_get_tid>
  16:	6d03      	mov      	r4, r0
  18:	e900000b 	bez      	r0, 0x2e	// 2e <lmac_get_tid+0x2e>
  1c:	e4652003 	andi      	r3, r5, 3
  20:	3b41      	cmpnei      	r3, 1
  22:	0808      	bt      	0x32	// 32 <lmac_get_tid+0x32>
  24:	1008      	lrw      	r0, 0x0	// 44 <lmac_get_tid+0x44>
  26:	c4a554e4 	zext      	r4, r5, 7, 5
  2a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  2e:	6c13      	mov      	r0, r4
  30:	1493      	pop      	r4-r6, r15
  32:	6c1b      	mov      	r0, r6
  34:	e0000000 	bsr      	0x0	// 0 <lmac_get_tid>
  38:	e480200f 	andi      	r4, r0, 15
  3c:	07f9      	br      	0x2e	// 2e <lmac_get_tid+0x2e>
  3e:	3407      	movi      	r4, 7
  40:	07f7      	br      	0x2e	// 2e <lmac_get_tid+0x2e>
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_get_hdr_len_pv1:

00000000 <lmac_get_hdr_len_pv1>:
   0:	8840      	ld.h      	r2, (r0, 0x0)
   2:	c4425461 	zext      	r1, r2, 3, 2
   6:	3942      	cmpnei      	r1, 2
   8:	0c4e      	bf      	0xa4	// a4 <lmac_get_hdr_len_pv1+0xa4>
   a:	3943      	cmpnei      	r1, 3
   c:	0c1e      	bf      	0x48	// 48 <lmac_get_hdr_len_pv1+0x48>
   e:	3941      	cmpnei      	r1, 1
  10:	8061      	ld.b      	r3, (r0, 0x1)
  12:	0823      	bt      	0x58	// 58 <lmac_get_hdr_len_pv1+0x58>
  14:	c48254e2 	zext      	r2, r2, 7, 4
  18:	3a42      	cmpnei      	r2, 2
  1a:	081f      	bt      	0x58	// 58 <lmac_get_hdr_len_pv1+0x58>
  1c:	74cc      	zextb      	r3, r3
  1e:	e4432001 	andi      	r2, r3, 1
  22:	3a40      	cmpnei      	r2, 0
  24:	3016      	movi      	r0, 22
  26:	3213      	movi      	r2, 19
  28:	c4020c20 	incf      	r0, r2, 0
  2c:	e4432002 	andi      	r2, r3, 2
  30:	e4632004 	andi      	r3, r3, 4
  34:	3a40      	cmpnei      	r2, 0
  36:	c4000c24 	incf      	r0, r0, 4
  3a:	e9230044 	bnez      	r3, 0xc2	// c2 <lmac_get_hdr_len_pv1+0xc2>
  3e:	2000      	addi      	r0, 1
  40:	7400      	zextb      	r0, r0
  42:	6c8f      	mov      	r2, r3
  44:	6f4f      	mov      	r13, r3
  46:	0405      	br      	0x50	// 50 <lmac_get_hdr_len_pv1+0x50>
  48:	3002      	movi      	r0, 2
  4a:	3300      	movi      	r3, 0
  4c:	6c8f      	mov      	r2, r3
  4e:	6f43      	mov      	r13, r0
  50:	ea0c0006 	movi      	r12, 6
  54:	6c73      	mov      	r1, r12
  56:	042c      	br      	0xae	// ae <lmac_get_hdr_len_pv1+0xae>
  58:	e4432001 	andi      	r2, r3, 1
  5c:	e9020014 	bez      	r2, 0x84	// 84 <lmac_get_hdr_len_pv1+0x84>
  60:	8063      	ld.b      	r3, (r0, 0x3)
  62:	e4432020 	andi      	r2, r3, 32
  66:	e4632040 	andi      	r3, r3, 64
  6a:	3a40      	cmpnei      	r2, 0
  6c:	3106      	movi      	r1, 6
  6e:	3200      	movi      	r2, 0
  70:	c4410c40 	inct      	r2, r1, 0
  74:	3002      	movi      	r0, 2
  76:	e9030023 	bez      	r3, 0xbc	// bc <lmac_get_hdr_len_pv1+0xbc>
  7a:	6cc7      	mov      	r3, r1
  7c:	6f43      	mov      	r13, r0
  7e:	6f07      	mov      	r12, r1
  80:	6c43      	mov      	r1, r0
  82:	0416      	br      	0xae	// ae <lmac_get_hdr_len_pv1+0xae>
  84:	8069      	ld.b      	r3, (r0, 0x9)
  86:	e4032020 	andi      	r0, r3, 32
  8a:	e4632040 	andi      	r3, r3, 64
  8e:	3840      	cmpnei      	r0, 0
  90:	3106      	movi      	r1, 6
  92:	c4410c40 	inct      	r2, r1, 0
  96:	3002      	movi      	r0, 2
  98:	e9030003 	bez      	r3, 0x9e	// 9e <lmac_get_hdr_len_pv1+0x9e>
  9c:	6cc7      	mov      	r3, r1
  9e:	6f43      	mov      	r13, r0
  a0:	6f03      	mov      	r12, r0
  a2:	0406      	br      	0xae	// ae <lmac_get_hdr_len_pv1+0xae>
  a4:	3300      	movi      	r3, 0
  a6:	6c07      	mov      	r0, r1
  a8:	6c8f      	mov      	r2, r3
  aa:	6f4f      	mov      	r13, r3
  ac:	6f0f      	mov      	r12, r3
  ae:	6070      	addu      	r1, r12
  b0:	6074      	addu      	r1, r13
  b2:	6048      	addu      	r1, r2
  b4:	60c4      	addu      	r3, r1
  b6:	600c      	addu      	r0, r3
  b8:	7400      	zextb      	r0, r0
  ba:	783c      	jmp      	r15
  bc:	6f43      	mov      	r13, r0
  be:	6f07      	mov      	r12, r1
  c0:	07e0      	br      	0x80	// 80 <lmac_get_hdr_len_pv1+0x80>
  c2:	3300      	movi      	r3, 0
  c4:	07bf      	br      	0x42	// 42 <lmac_get_hdr_len_pv1+0x42>

Disassembly of section .text.lmac_get_hdr_len_pv0:

00000000 <lmac_get_hdr_len_pv0>:
   0:	14d5      	push      	r4-r8, r15
   2:	6cc3      	mov      	r3, r0
   4:	8800      	ld.h      	r0, (r0, 0x0)
   6:	c4405466 	zext      	r6, r0, 3, 2
   a:	3e42      	cmpnei      	r6, 2
   c:	c48054e1 	zext      	r1, r0, 7, 4
  10:	0c46      	bf      	0x9c	// 9c <lmac_get_hdr_len_pv0+0x9c>
  12:	3e43      	cmpnei      	r6, 3
  14:	0c5a      	bf      	0xc8	// c8 <lmac_get_hdr_len_pv0+0xc8>
  16:	3e41      	cmpnei      	r6, 1
  18:	0c0b      	bf      	0x2e	// 2e <lmac_get_hdr_len_pv0+0x2e>
  1a:	d8634001 	ld.bs      	r3, (r3, 0x1)
  1e:	320a      	movi      	r2, 10
  20:	e9a30077 	bhsz      	r3, 0x10e	// 10e <lmac_get_hdr_len_pv0+0x10e>
  24:	3000      	movi      	r0, 0
  26:	3304      	movi      	r3, 4
  28:	6dc3      	mov      	r7, r0
  2a:	3602      	movi      	r6, 2
  2c:	042a      	br      	0x80	// 80 <lmac_get_hdr_len_pv0+0x80>
  2e:	594b      	subi      	r2, r1, 3
  30:	7488      	zextb      	r2, r2
  32:	3a0c      	cmphsi      	r2, 13
  34:	0829      	bt      	0x86	// 86 <lmac_get_hdr_len_pv0+0x86>
  36:	1003      	lrw      	r0, 0x0	// 40 <lmac_get_hdr_len_pv0+0x40>
  38:	d0400882 	ldr.w      	r2, (r0, r2 << 2)
  3c:	7808      	jmp      	r2
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000
  42:	0000      	.short	0x0000
  44:	3300      	movi      	r3, 0
  46:	320a      	movi      	r2, 10
  48:	6c0f      	mov      	r0, r3
  4a:	6dcf      	mov      	r7, r3
  4c:	6d8f      	mov      	r6, r3
  4e:	6c4f      	mov      	r1, r3
  50:	ea0c0006 	movi      	r12, 6
  54:	6070      	addu      	r1, r12
  56:	6184      	addu      	r6, r1
  58:	619c      	addu      	r6, r7
  5a:	6018      	addu      	r0, r6
  5c:	60c0      	addu      	r3, r0
  5e:	60c8      	addu      	r3, r2
  60:	740c      	zextb      	r0, r3
  62:	1495      	pop      	r4-r8, r15
  64:	d8634001 	ld.bs      	r3, (r3, 0x1)
  68:	e9a3004c 	bhsz      	r3, 0x100	// 100 <lmac_get_hdr_len_pv0+0x100>
  6c:	3215      	movi      	r2, 21
  6e:	3300      	movi      	r3, 0
  70:	6c0f      	mov      	r0, r3
  72:	6dcf      	mov      	r7, r3
  74:	07ed      	br      	0x4e	// 4e <lmac_get_hdr_len_pv0+0x4e>
  76:	3300      	movi      	r3, 0
  78:	320a      	movi      	r2, 10
  7a:	6c0f      	mov      	r0, r3
  7c:	6dcf      	mov      	r7, r3
  7e:	6d8f      	mov      	r6, r3
  80:	3106      	movi      	r1, 6
  82:	6f07      	mov      	r12, r1
  84:	07e8      	br      	0x54	// 54 <lmac_get_hdr_len_pv0+0x54>
  86:	1105      	lrw      	r0, 0x0	// 118 <lmac_get_hdr_len_pv0+0x118>
  88:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  8c:	3300      	movi      	r3, 0
  8e:	320a      	movi      	r2, 10
  90:	6c0f      	mov      	r0, r3
  92:	6dcf      	mov      	r7, r3
  94:	6d8f      	mov      	r6, r3
  96:	6c4f      	mov      	r1, r3
  98:	6f0f      	mov      	r12, r3
  9a:	07dd      	br      	0x54	// 54 <lmac_get_hdr_len_pv0+0x54>
  9c:	d9030001 	ld.b      	r8, (r3, 0x1)
  a0:	c4285423 	zext      	r3, r8, 1, 1
  a4:	68e0      	and      	r3, r8
  a6:	3506      	movi      	r5, 6
  a8:	3b40      	cmpnei      	r3, 0
  aa:	3400      	movi      	r4, 0
  ac:	6dd7      	mov      	r7, r5
  ae:	c4e40c20 	incf      	r7, r4, 0
  b2:	7622      	sextb      	r8, r8
  b4:	e0000000 	bsr      	0x0	// 0 <lmac_get_hdr_len_pv0>
  b8:	3840      	cmpnei      	r0, 0
  ba:	c4060c40 	inct      	r0, r6, 0
  be:	320a      	movi      	r2, 10
  c0:	e9880022 	blz      	r8, 0x104	// 104 <lmac_get_hdr_len_pv0+0x104>
  c4:	6cd3      	mov      	r3, r4
  c6:	07dd      	br      	0x80	// 80 <lmac_get_hdr_len_pv0+0x80>
  c8:	3941      	cmpnei      	r1, 1
  ca:	0817      	bt      	0xf8	// f8 <lmac_get_hdr_len_pv0+0xf8>
  cc:	8321      	ld.b      	r1, (r3, 0x1)
  ce:	e4612001 	andi      	r3, r1, 1
  d2:	3b40      	cmpnei      	r3, 0
  d4:	3011      	movi      	r0, 17
  d6:	320e      	movi      	r2, 14
  d8:	e4212002 	andi      	r1, r1, 2
  dc:	c4400c40 	inct      	r2, r0, 0
  e0:	3940      	cmpnei      	r1, 0
  e2:	c4420c44 	inct      	r2, r2, 4
  e6:	e9030011 	bez      	r3, 0x108	// 108 <lmac_get_hdr_len_pv0+0x108>
  ea:	2200      	addi      	r2, 1
  ec:	7488      	zextb      	r2, r2
  ee:	3601      	movi      	r6, 1
  f0:	3300      	movi      	r3, 0
  f2:	6c0f      	mov      	r0, r3
  f4:	6dcf      	mov      	r7, r3
  f6:	07d0      	br      	0x96	// 96 <lmac_get_hdr_len_pv0+0x96>
  f8:	394f      	cmpnei      	r1, 15
  fa:	0c09      	bf      	0x10c	// 10c <lmac_get_hdr_len_pv0+0x10c>
  fc:	1008      	lrw      	r0, 0x0	// 11c <lmac_get_hdr_len_pv0+0x11c>
  fe:	07c5      	br      	0x88	// 88 <lmac_get_hdr_len_pv0+0x88>
 100:	320f      	movi      	r2, 15
 102:	07b6      	br      	0x6e	// 6e <lmac_get_hdr_len_pv0+0x6e>
 104:	3304      	movi      	r3, 4
 106:	07bd      	br      	0x80	// 80 <lmac_get_hdr_len_pv0+0x80>
 108:	3601      	movi      	r6, 1
 10a:	07f4      	br      	0xf2	// f2 <lmac_get_hdr_len_pv0+0xf2>
 10c:	320a      	movi      	r2, 10
 10e:	3300      	movi      	r3, 0
 110:	6c0f      	mov      	r0, r3
 112:	6dcf      	mov      	r7, r3
 114:	078b      	br      	0x2a	// 2a <lmac_get_hdr_len_pv0+0x2a>
	...

Disassembly of section .text.lmac_get_tx_addr:

00000000 <lmac_get_tx_addr>:
   0:	14d1      	push      	r4, r15
   2:	8141      	ld.b      	r2, (r1, 0x1)
   4:	6d07      	mov      	r4, r1
   6:	4268      	lsli      	r3, r2, 8
   8:	8120      	ld.b      	r1, (r1, 0x0)
   a:	6cc4      	or      	r3, r1
   c:	e4232003 	andi      	r1, r3, 3
  10:	6f03      	mov      	r12, r0
  12:	e921001b 	bnez      	r1, 0x48	// 48 <lmac_get_tx_addr+0x48>
  16:	c4435462 	zext      	r2, r3, 3, 2
  1a:	3a41      	cmpnei      	r2, 1
  1c:	0c03      	bf      	0x22	// 22 <lmac_get_tx_addr+0x22>
  1e:	3a43      	cmpnei      	r2, 3
  20:	0c05      	bf      	0x2a	// 2a <lmac_get_tx_addr+0x2a>
  22:	3206      	movi      	r2, 6
  24:	e4240009 	addi      	r1, r4, 10
  28:	0408      	br      	0x38	// 38 <lmac_get_tx_addr+0x38>
  2a:	c48354e3 	zext      	r3, r3, 7, 4
  2e:	3b41      	cmpnei      	r3, 1
  30:	0807      	bt      	0x3e	// 3e <lmac_get_tx_addr+0x3e>
  32:	3206      	movi      	r2, 6
  34:	5c2e      	addi      	r1, r4, 4
  36:	6c33      	mov      	r0, r12
  38:	e0000000 	bsr      	0x0	// 0 <memcpy>
  3c:	0405      	br      	0x46	// 46 <lmac_get_tx_addr+0x46>
  3e:	3b4f      	cmpnei      	r3, 15
  40:	0ff1      	bf      	0x22	// 22 <lmac_get_tx_addr+0x22>
  42:	3301      	movi      	r3, 1
  44:	a060      	st.b      	r3, (r0, 0x0)
  46:	1491      	pop      	r4, r15
  48:	3941      	cmpnei      	r1, 1
  4a:	0815      	bt      	0x74	// 74 <lmac_get_tx_addr+0x74>
  4c:	c4435483 	zext      	r3, r3, 4, 2
  50:	3b41      	cmpnei      	r3, 1
  52:	0c0e      	bf      	0x6e	// 6e <lmac_get_tx_addr+0x6e>
  54:	3b43      	cmpnei      	r3, 3
  56:	0c0c      	bf      	0x6e	// 6e <lmac_get_tx_addr+0x6e>
  58:	e923fff7 	bnez      	r3, 0x46	// 46 <lmac_get_tx_addr+0x46>
  5c:	e4422001 	andi      	r2, r2, 1
  60:	e922ffe9 	bnez      	r2, 0x32	// 32 <lmac_get_tx_addr+0x32>
  64:	8468      	ld.b      	r3, (r4, 0x8)
  66:	a060      	st.b      	r3, (r0, 0x0)
  68:	8469      	ld.b      	r3, (r4, 0x9)
  6a:	a061      	st.b      	r3, (r0, 0x1)
  6c:	07ed      	br      	0x46	// 46 <lmac_get_tx_addr+0x46>
  6e:	3206      	movi      	r2, 6
  70:	5c3e      	addi      	r1, r4, 8
  72:	07e3      	br      	0x38	// 38 <lmac_get_tx_addr+0x38>
  74:	1004      	lrw      	r0, 0x0	// 84 <lmac_get_tx_addr+0x84>
  76:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  7a:	3110      	movi      	r1, 16
  7c:	6c13      	mov      	r0, r4
  7e:	e0000000 	bsr      	0x0	// 0 <lmac_get_tx_addr>
  82:	07e2      	br      	0x46	// 46 <lmac_get_tx_addr+0x46>
  84:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_get_rx_addr:

00000000 <lmac_get_rx_addr>:
   0:	14d1      	push      	r4, r15
   2:	8141      	ld.b      	r2, (r1, 0x1)
   4:	6d07      	mov      	r4, r1
   6:	4268      	lsli      	r3, r2, 8
   8:	8120      	ld.b      	r1, (r1, 0x0)
   a:	6cc4      	or      	r3, r1
   c:	e4232003 	andi      	r1, r3, 3
  10:	e9210014 	bnez      	r1, 0x38	// 38 <lmac_get_rx_addr+0x38>
  14:	c4435462 	zext      	r2, r3, 3, 2
  18:	3a43      	cmpnei      	r2, 3
  1a:	0c06      	bf      	0x26	// 26 <lmac_get_rx_addr+0x26>
  1c:	3206      	movi      	r2, 6
  1e:	5c2e      	addi      	r1, r4, 4
  20:	e0000000 	bsr      	0x0	// 0 <memcpy>
  24:	0409      	br      	0x36	// 36 <lmac_get_rx_addr+0x36>
  26:	c48354e3 	zext      	r3, r3, 7, 4
  2a:	3b4f      	cmpnei      	r3, 15
  2c:	3206      	movi      	r2, 6
  2e:	0ff8      	bf      	0x1e	// 1e <lmac_get_rx_addr+0x1e>
  30:	31ff      	movi      	r1, 255
  32:	e0000000 	bsr      	0x0	// 0 <memset>
  36:	1491      	pop      	r4, r15
  38:	3941      	cmpnei      	r1, 1
  3a:	0818      	bt      	0x6a	// 6a <lmac_get_rx_addr+0x6a>
  3c:	c4435483 	zext      	r3, r3, 4, 2
  40:	3b41      	cmpnei      	r3, 1
  42:	0c11      	bf      	0x64	// 64 <lmac_get_rx_addr+0x64>
  44:	3b43      	cmpnei      	r3, 3
  46:	0c0f      	bf      	0x64	// 64 <lmac_get_rx_addr+0x64>
  48:	e923fff7 	bnez      	r3, 0x36	// 36 <lmac_get_rx_addr+0x36>
  4c:	e4422001 	andi      	r2, r2, 1
  50:	5c26      	addi      	r1, r4, 2
  52:	e9020007 	bez      	r2, 0x60	// 60 <lmac_get_rx_addr+0x60>
  56:	8462      	ld.b      	r3, (r4, 0x2)
  58:	a060      	st.b      	r3, (r0, 0x0)
  5a:	8161      	ld.b      	r3, (r1, 0x1)
  5c:	a061      	st.b      	r3, (r0, 0x1)
  5e:	07ec      	br      	0x36	// 36 <lmac_get_rx_addr+0x36>
  60:	3206      	movi      	r2, 6
  62:	07df      	br      	0x20	// 20 <lmac_get_rx_addr+0x20>
  64:	3206      	movi      	r2, 6
  66:	5c26      	addi      	r1, r4, 2
  68:	07dc      	br      	0x20	// 20 <lmac_get_rx_addr+0x20>
  6a:	1068      	lrw      	r3, 0x0	// 88 <lmac_get_rx_addr+0x88>
  6c:	d86309e2 	ld.b      	r3, (r3, 0x9e2)
  70:	e4632002 	andi      	r3, r3, 2
  74:	e923ffe1 	bnez      	r3, 0x36	// 36 <lmac_get_rx_addr+0x36>
  78:	1005      	lrw      	r0, 0x0	// 8c <hgprintf+0x8c>
  7a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  7e:	3110      	movi      	r1, 16
  80:	6c13      	mov      	r0, r4
  82:	e0000000 	bsr      	0x0	// 0 <lmac_get_rx_addr>
  86:	07d8      	br      	0x36	// 36 <ah_lmac+0x36>
	...

Disassembly of section .text.lmac_set_basic_nav:

00000000 <lmac_set_basic_nav>:
   0:	1052      	lrw      	r2, 0x0	// 48 <lmac_set_basic_nav+0x48>
   2:	d86209e2 	ld.b      	r3, (r2, 0x9e2)
   6:	e4632002 	andi      	r3, r3, 2
   a:	e9230006 	bnez      	r3, 0x16	// 16 <lmac_set_basic_nav+0x16>
   e:	d862202f 	ld.w      	r3, (r2, 0xbc)
  12:	e9030019 	bez      	r3, 0x44	// 44 <lmac_set_basic_nav+0x44>
  16:	106e      	lrw      	r3, 0x0	// 4c <lmac_set_basic_nav+0x4c>
  18:	9360      	ld.w      	r3, (r3, 0x0)
  1a:	d8432034 	ld.w      	r2, (r3, 0xd0)
  1e:	6408      	cmphs      	r2, r0
  20:	d8232033 	ld.w      	r1, (r3, 0xcc)
  24:	c4020c40 	inct      	r0, r2, 0
  28:	ec210080 	ori      	r1, r1, 128
  2c:	dc232033 	st.w      	r1, (r3, 0xcc)
  30:	e900000a 	bez      	r0, 0x44	// 44 <lmac_set_basic_nav+0x44>
  34:	dc032034 	st.w      	r0, (r3, 0xd0)
  38:	d8432033 	ld.w      	r2, (r3, 0xcc)
  3c:	ec420040 	ori      	r2, r2, 64
  40:	dc432033 	st.w      	r2, (r3, 0xcc)
  44:	783c      	jmp      	r15
	...

Disassembly of section .text.lmac_clr_basic_nav:

00000000 <lmac_clr_basic_nav>:
   0:	1068      	lrw      	r3, 0x0	// 20 <lmac_clr_basic_nav+0x20>
   2:	9360      	ld.w      	r3, (r3, 0x0)
   4:	d8432033 	ld.w      	r2, (r3, 0xcc)
   8:	ec420080 	ori      	r2, r2, 128
   c:	dc432033 	st.w      	r2, (r3, 0xcc)
  10:	3280      	movi      	r2, 128
  12:	4249      	lsli      	r2, r2, 9
  14:	b352      	st.w      	r2, (r3, 0x48)
  16:	3200      	movi      	r2, 0
  18:	dc432034 	st.w      	r2, (r3, 0xd0)
  1c:	783c      	jmp      	r15
  1e:	0000      	.short	0x0000
  20:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_set_obss_nav:

00000000 <lmac_set_obss_nav>:
   0:	106f      	lrw      	r3, 0x0	// 3c <lmac_set_obss_nav+0x3c>
   2:	d863202f 	ld.w      	r3, (r3, 0xbc)
   6:	3b81      	bclri      	r3, 1
   8:	e9030019 	bez      	r3, 0x3a	// 3a <lmac_set_obss_nav+0x3a>
   c:	106d      	lrw      	r3, 0x0	// 40 <lmac_set_obss_nav+0x40>
   e:	9360      	ld.w      	r3, (r3, 0x0)
  10:	d8432035 	ld.w      	r2, (r3, 0xd4)
  14:	6408      	cmphs      	r2, r0
  16:	d8232033 	ld.w      	r1, (r3, 0xcc)
  1a:	c4020c40 	inct      	r0, r2, 0
  1e:	ec210200 	ori      	r1, r1, 512
  22:	dc232033 	st.w      	r1, (r3, 0xcc)
  26:	e900000a 	bez      	r0, 0x3a	// 3a <lmac_set_obss_nav+0x3a>
  2a:	dc032035 	st.w      	r0, (r3, 0xd4)
  2e:	d8432033 	ld.w      	r2, (r3, 0xcc)
  32:	ec420100 	ori      	r2, r2, 256
  36:	dc432033 	st.w      	r2, (r3, 0xcc)
  3a:	783c      	jmp      	r15
	...

Disassembly of section .text.lmac_clr_obss_nav:

00000000 <lmac_clr_obss_nav>:
   0:	1068      	lrw      	r3, 0x0	// 20 <lmac_clr_obss_nav+0x20>
   2:	9360      	ld.w      	r3, (r3, 0x0)
   4:	d8432033 	ld.w      	r2, (r3, 0xcc)
   8:	ec420200 	ori      	r2, r2, 512
   c:	dc432033 	st.w      	r2, (r3, 0xcc)
  10:	3280      	movi      	r2, 128
  12:	424a      	lsli      	r2, r2, 10
  14:	b352      	st.w      	r2, (r3, 0x48)
  16:	3200      	movi      	r2, 0
  18:	dc432035 	st.w      	r2, (r3, 0xd4)
  1c:	783c      	jmp      	r15
  1e:	0000      	.short	0x0000
  20:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_select_mcs_by_evm:

00000000 <lmac_select_mcs_by_evm>:
   0:	1422      	subi      	r14, r14, 8
   2:	3300      	movi      	r3, 0
   4:	2b07      	subi      	r3, 8
   6:	dc6e0000 	st.b      	r3, (r14, 0x0)
   a:	3300      	movi      	r3, 0
   c:	2b08      	subi      	r3, 9
   e:	dc6e0001 	st.b      	r3, (r14, 0x1)
  12:	3300      	movi      	r3, 0
  14:	2b0c      	subi      	r3, 13
  16:	dc6e0002 	st.b      	r3, (r14, 0x2)
  1a:	3300      	movi      	r3, 0
  1c:	2b0e      	subi      	r3, 15
  1e:	dc6e0003 	st.b      	r3, (r14, 0x3)
  22:	3300      	movi      	r3, 0
  24:	2b11      	subi      	r3, 18
  26:	dc6e0004 	st.b      	r3, (r14, 0x4)
  2a:	3300      	movi      	r3, 0
  2c:	2b13      	subi      	r3, 20
  2e:	dc6e0005 	st.b      	r3, (r14, 0x5)
  32:	3300      	movi      	r3, 0
  34:	2b15      	subi      	r3, 22
  36:	dc6e0006 	st.b      	r3, (r14, 0x6)
  3a:	3300      	movi      	r3, 0
  3c:	2b17      	subi      	r3, 24
  3e:	dc6e0007 	st.b      	r3, (r14, 0x7)
  42:	3200      	movi      	r2, 0
  44:	3307      	movi      	r3, 7
  46:	c44e002c 	addu      	r12, r14, r2
  4a:	d98c4007 	ld.bs      	r12, (r12, 0x7)
  4e:	6306      	subu      	r12, r1
  50:	6701      	cmplt      	r0, r12
  52:	0806      	bt      	0x5e	// 5e <lmac_select_mcs_by_evm+0x5e>
  54:	2b00      	subi      	r3, 1
  56:	74cc      	zextb      	r3, r3
  58:	2a00      	subi      	r2, 1
  5a:	e923fff6 	bnez      	r3, 0x46	// 46 <lmac_select_mcs_by_evm+0x46>
  5e:	6c0f      	mov      	r0, r3
  60:	1402      	addi      	r14, r14, 8
  62:	783c      	jmp      	r15

Disassembly of section .text.lmac_std_calc:

00000000 <lmac_std_calc>:
   0:	14d7      	push      	r4-r10, r15
   2:	3400      	movi      	r4, 0
   4:	6d83      	mov      	r6, r0
   6:	6d47      	mov      	r5, r1
   8:	6dc3      	mov      	r7, r0
   a:	6e13      	mov      	r8, r4
   c:	5f79      	subu      	r3, r7, r6
   e:	654d      	cmplt      	r3, r5
  10:	0826      	bt      	0x5c	// 5c <lmac_std_calc+0x5c>
  12:	6c17      	mov      	r0, r5
  14:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
  18:	6c83      	mov      	r2, r0
  1a:	6cc7      	mov      	r3, r1
  1c:	6c13      	mov      	r0, r4
  1e:	6c63      	mov      	r1, r8
  20:	e0000000 	bsr      	0x0	// 0 <__divdf3>
  24:	3400      	movi      	r4, 0
  26:	6e43      	mov      	r9, r0
  28:	6e87      	mov      	r10, r1
  2a:	6ddb      	mov      	r7, r6
  2c:	6e13      	mov      	r8, r4
  2e:	5f79      	subu      	r3, r7, r6
  30:	654d      	cmplt      	r3, r5
  32:	0823      	bt      	0x78	// 78 <lmac_std_calc+0x78>
  34:	5d03      	subi      	r0, r5, 1
  36:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
  3a:	6c83      	mov      	r2, r0
  3c:	6cc7      	mov      	r3, r1
  3e:	6c13      	mov      	r0, r4
  40:	6c63      	mov      	r1, r8
  42:	e0000000 	bsr      	0x0	// 0 <__divdf3>
  46:	e0000000 	bsr      	0x0	// 0 <sqrt>
  4a:	3200      	movi      	r2, 0
  4c:	ea233fe0 	movih      	r3, 16352
  50:	e0000000 	bsr      	0x0	// 0 <__adddf3>
  54:	e0000000 	bsr      	0x0	// 0 <__fixdfsi>
  58:	7402      	sextb      	r0, r0
  5a:	1497      	pop      	r4-r10, r15
  5c:	d8074000 	ld.bs      	r0, (r7, 0x0)
  60:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
  64:	6c83      	mov      	r2, r0
  66:	6cc7      	mov      	r3, r1
  68:	6c13      	mov      	r0, r4
  6a:	6c63      	mov      	r1, r8
  6c:	e0000000 	bsr      	0x0	// 0 <__adddf3>
  70:	6d03      	mov      	r4, r0
  72:	6e07      	mov      	r8, r1
  74:	2700      	addi      	r7, 1
  76:	07cb      	br      	0xc	// c <lmac_std_calc+0xc>
  78:	d8074000 	ld.bs      	r0, (r7, 0x0)
  7c:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
  80:	6ca7      	mov      	r2, r9
  82:	6ceb      	mov      	r3, r10
  84:	e0000000 	bsr      	0x0	// 0 <__subdf3>
  88:	6c83      	mov      	r2, r0
  8a:	6cc7      	mov      	r3, r1
  8c:	e0000000 	bsr      	0x0	// 0 <__muldf3>
  90:	6c83      	mov      	r2, r0
  92:	6cc7      	mov      	r3, r1
  94:	6c13      	mov      	r0, r4
  96:	6c63      	mov      	r1, r8
  98:	e0000000 	bsr      	0x0	// 0 <__adddf3>
  9c:	6d03      	mov      	r4, r0
  9e:	6e07      	mov      	r8, r1
  a0:	2700      	addi      	r7, 1
  a2:	07c6      	br      	0x2e	// 2e <lmac_std_calc+0x2e>

Disassembly of section .text.lmac_ewma_update:

00000000 <lmac_ewma_update>:
   0:	14d5      	push      	r4-r8, r15
   2:	3305      	movi      	r3, 5
   4:	c4628023 	divu      	r3, r2, r3
   8:	2b00      	subi      	r3, 1
   a:	74cc      	zextb      	r3, r3
   c:	1055      	lrw      	r2, 0x0	// 60 <lmac_ewma_update+0x60>
   e:	4363      	lsli      	r3, r3, 3
  10:	60c8      	addu      	r3, r2
  12:	6dc3      	mov      	r7, r0
  14:	4110      	lsli      	r0, r1, 16
  16:	93a0      	ld.w      	r5, (r3, 0x0)
  18:	9381      	ld.w      	r4, (r3, 0x4)
  1a:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
  1e:	6e03      	mov      	r8, r0
  20:	6d87      	mov      	r6, r1
  22:	6c97      	mov      	r2, r5
  24:	6cd3      	mov      	r3, r4
  26:	3000      	movi      	r0, 0
  28:	ea213ff0 	movih      	r1, 16368
  2c:	e0000000 	bsr      	0x0	// 0 <__subdf3>
  30:	6c83      	mov      	r2, r0
  32:	6cc7      	mov      	r3, r1
  34:	6c23      	mov      	r0, r8
  36:	6c5b      	mov      	r1, r6
  38:	e0000000 	bsr      	0x0	// 0 <__muldf3>
  3c:	6e03      	mov      	r8, r0
  3e:	6c1f      	mov      	r0, r7
  40:	6d87      	mov      	r6, r1
  42:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
  46:	6c97      	mov      	r2, r5
  48:	6cd3      	mov      	r3, r4
  4a:	e0000000 	bsr      	0x0	// 0 <__muldf3>
  4e:	6c83      	mov      	r2, r0
  50:	6cc7      	mov      	r3, r1
  52:	6c23      	mov      	r0, r8
  54:	6c5b      	mov      	r1, r6
  56:	e0000000 	bsr      	0x0	// 0 <__adddf3>
  5a:	e0000000 	bsr      	0x0	// 0 <__fixdfsi>
  5e:	1495      	pop      	r4-r8, r15
  60:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_auto_rate_ctrl:

00000000 <lmac_auto_rate_ctrl>:
   0:	14d7      	push      	r4-r10, r15
   2:	1421      	subi      	r14, r14, 4
   4:	9060      	ld.w      	r3, (r0, 0x0)
   6:	64c2      	cmpne      	r0, r3
   8:	6d03      	mov      	r4, r0
   a:	0c75      	bf      	0xf4	// f4 <lmac_auto_rate_ctrl+0xf4>
   c:	3100      	movi      	r1, 0
   e:	2900      	subi      	r1, 1
  10:	111a      	lrw      	r0, 0x0	// f8 <lmac_auto_rate_ctrl+0xf8>
  12:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  16:	11ba      	lrw      	r5, 0x0	// fc <lmac_auto_rate_ctrl+0xfc>
  18:	11da      	lrw      	r6, 0x0	// 100 <lmac_auto_rate_ctrl+0x100>
  1a:	94e0      	ld.w      	r7, (r4, 0x0)
  1c:	65d2      	cmpne      	r4, r7
  1e:	0807      	bt      	0x2c	// 2c <lmac_auto_rate_ctrl+0x2c>
  20:	1116      	lrw      	r0, 0x0	// f8 <lmac_auto_rate_ctrl+0xf8>
  22:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  26:	6c13      	mov      	r0, r4
  28:	1401      	addi      	r14, r14, 4
  2a:	1497      	pop      	r4-r10, r15
  2c:	d9050317 	ld.b      	r8, (r5, 0x317)
  30:	d86700a0 	ld.b      	r3, (r7, 0xa0)
  34:	660c      	cmphs      	r3, r8
  36:	0c44      	bf      	0xbe	// be <lmac_auto_rate_ctrl+0xbe>
  38:	d86740a2 	ld.bs      	r3, (r7, 0xa2)
  3c:	d9272027 	ld.w      	r9, (r7, 0x9c)
  40:	e9230046 	bnez      	r3, 0xcc	// cc <lmac_auto_rate_ctrl+0xcc>
  44:	6c0f      	mov      	r0, r3
  46:	660d      	cmplt      	r3, r8
  48:	083d      	bt      	0xc2	// c2 <lmac_auto_rate_ctrl+0xc2>
  4a:	c5008040 	divs      	r0, r0, r8
  4e:	4010      	lsli      	r0, r0, 16
  50:	3380      	movi      	r3, 128
  52:	4368      	lsli      	r3, r3, 8
  54:	60c0      	addu      	r3, r0
  56:	5370      	asri      	r3, r3, 16
  58:	dc6700a2 	st.b      	r3, (r7, 0xa2)
  5c:	6c63      	mov      	r1, r8
  5e:	6c27      	mov      	r0, r9
  60:	e0000000 	bsr      	0x0	// 0 <lmac_auto_rate_ctrl>
  64:	3823      	cmplti      	r0, 4
  66:	dc0700a3 	st.b      	r0, (r7, 0xa3)
  6a:	d86700a2 	ld.b      	r3, (r7, 0xa2)
  6e:	0c3c      	bf      	0xe6	// e6 <lmac_auto_rate_ctrl+0xe6>
  70:	600c      	addu      	r0, r3
  72:	d8254870 	ld.bs      	r1, (r5, 0x870)
  76:	7402      	sextb      	r0, r0
  78:	e0000000 	bsr      	0x0	// 0 <lmac_auto_rate_ctrl>
  7c:	d86700ad 	ld.b      	r3, (r7, 0xad)
  80:	e443200f 	andi      	r2, r3, 15
  84:	6481      	cmplt      	r0, r2
  86:	0c32      	bf      	0xea	// ea <lmac_auto_rate_ctrl+0xea>
  88:	220e      	addi      	r2, 15
  8a:	c4625c60 	ins      	r3, r2, 3, 0
  8e:	dc6700ad 	st.b      	r3, (r7, 0xad)
  92:	3300      	movi      	r3, 0
  94:	dc6700a0 	st.b      	r3, (r7, 0xa0)
  98:	d86520ee 	ld.w      	r3, (r5, 0x3b8)
  9c:	e4632004 	andi      	r3, r3, 4
  a0:	e903000f 	bez      	r3, 0xbe	// be <lmac_auto_rate_ctrl+0xbe>
  a4:	d86700ad 	ld.b      	r3, (r7, 0xad)
  a8:	4b04      	lsri      	r0, r3, 4
  aa:	d84740a3 	ld.bs      	r2, (r7, 0xa3)
  ae:	d82740a2 	ld.bs      	r1, (r7, 0xa2)
  b2:	e463200f 	andi      	r3, r3, 15
  b6:	b800      	st.w      	r0, (r14, 0x0)
  b8:	6c1b      	mov      	r0, r6
  ba:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  be:	97e0      	ld.w      	r7, (r7, 0x0)
  c0:	07ae      	br      	0x1c	// 1c <lmac_auto_rate_ctrl+0x1c>
  c2:	d0691022 	ldr.bs      	r2, (r9, r3 << 0)
  c6:	6008      	addu      	r0, r2
  c8:	2300      	addi      	r3, 1
  ca:	07be      	br      	0x46	// 46 <lmac_auto_rate_ctrl+0x46>
  cc:	4310      	lsli      	r0, r3, 16
  ce:	ea0a0000 	movi      	r10, 0
  d2:	6629      	cmplt      	r10, r8
  d4:	0fbe      	bf      	0x50	// 50 <lmac_auto_rate_ctrl+0x50>
  d6:	d1491021 	ldr.bs      	r1, (r9, r10 << 0)
  da:	6ca3      	mov      	r2, r8
  dc:	e0000000 	bsr      	0x0	// 0 <lmac_auto_rate_ctrl>
  e0:	e54a0000 	addi      	r10, r10, 1
  e4:	07f7      	br      	0xd2	// d2 <lmac_auto_rate_ctrl+0xd2>
  e6:	5b0a      	addi      	r0, r3, 3
  e8:	07c5      	br      	0x72	// 72 <lmac_auto_rate_ctrl+0x72>
  ea:	6409      	cmplt      	r2, r0
  ec:	0fd3      	bf      	0x92	// 92 <lmac_auto_rate_ctrl+0x92>
  ee:	c4605c60 	ins      	r3, r0, 3, 0
  f2:	07ce      	br      	0x8e	// 8e <lmac_auto_rate_ctrl+0x8e>
  f4:	3000      	movi      	r0, 0
  f6:	0799      	br      	0x28	// 28 <lmac_auto_rate_ctrl+0x28>
	...

Disassembly of section .text.lmac_bss_bw:

00000000 <lmac_bss_bw>:
   0:	104f      	lrw      	r2, 0x0	// 3c <lmac_bss_bw+0x3c>
   2:	d8620308 	ld.b      	r3, (r2, 0x308)
   6:	3b42      	cmpnei      	r3, 2
   8:	0c11      	bf      	0x2a	// 2a <lmac_bss_bw+0x2a>
   a:	3b43      	cmpnei      	r3, 3
   c:	0c12      	bf      	0x30	// 30 <lmac_bss_bw+0x30>
   e:	3b41      	cmpnei      	r3, 1
  10:	0813      	bt      	0x36	// 36 <lmac_bss_bw+0x36>
  12:	d842034a 	ld.b      	r2, (r2, 0x34a)
  16:	e4422001 	andi      	r2, r2, 1
  1a:	30fa      	movi      	r0, 250
  1c:	33fa      	movi      	r3, 250
  1e:	4002      	lsli      	r0, r0, 2
  20:	4363      	lsli      	r3, r3, 3
  22:	3a40      	cmpnei      	r2, 0
  24:	c4030c20 	incf      	r0, r3, 0
  28:	0403      	br      	0x2e	// 2e <lmac_bss_bw+0x2e>
  2a:	30fa      	movi      	r0, 250
  2c:	4004      	lsli      	r0, r0, 4
  2e:	783c      	jmp      	r15
  30:	30fa      	movi      	r0, 250
  32:	4005      	lsli      	r0, r0, 5
  34:	07fd      	br      	0x2e	// 2e <lmac_bss_bw+0x2e>
  36:	30fa      	movi      	r0, 250
  38:	4002      	lsli      	r0, r0, 2
  3a:	07fa      	br      	0x2e	// 2e <lmac_bss_bw+0x2e>
  3c:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_alloc_sta:

00000000 <lmac_alloc_sta>:
   0:	14d1      	push      	r4, r15
   2:	30fa      	movi      	r0, 250
   4:	4001      	lsli      	r0, r0, 1
   6:	e0000000 	bsr      	0x0	// 0 <_os_zalloc>
   a:	6d03      	mov      	r4, r0
   c:	e9000008 	bez      	r0, 0x1c	// 1c <lmac_alloc_sta+0x1c>
  10:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  14:	3301      	movi      	r3, 1
  16:	b465      	st.w      	r3, (r4, 0x14)
  18:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  1c:	6c13      	mov      	r0, r4
  1e:	1491      	pop      	r4, r15

Disassembly of section .text.lmac_sta_get:

00000000 <lmac_sta_get>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d47      	mov      	r5, r1
   4:	3100      	movi      	r1, 0
   6:	6d83      	mov      	r6, r0
   8:	2900      	subi      	r1, 1
   a:	1105      	lrw      	r0, 0x0	// 9c <lmac_sta_get+0x9c>
   c:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  10:	1164      	lrw      	r3, 0x0	// a0 <lmac_sta_get+0xa0>
  12:	e44309f7 	addi      	r2, r3, 2552
  16:	d883227e 	ld.w      	r4, (r3, 0x9f8)
  1a:	6492      	cmpne      	r4, r2
  1c:	0803      	bt      	0x22	// 22 <lmac_sta_get+0x22>
  1e:	3400      	movi      	r4, 0
  20:	0415      	br      	0x4a	// 4a <lmac_sta_get+0x4a>
  22:	eb46ffff 	cmpnei      	r6, 65535
  26:	0c19      	bf      	0x58	// 58 <lmac_sta_get+0x58>
  28:	d8641034 	ld.h      	r3, (r4, 0x68)
  2c:	658e      	cmpne      	r3, r6
  2e:	0815      	bt      	0x58	// 58 <lmac_sta_get+0x58>
  30:	d864006b 	ld.b      	r3, (r4, 0x6b)
  34:	e4632020 	andi      	r3, r3, 32
  38:	e9230010 	bnez      	r3, 0x58	// 58 <lmac_sta_get+0x58>
  3c:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  40:	9465      	ld.w      	r3, (r4, 0x14)
  42:	2300      	addi      	r3, 1
  44:	b465      	st.w      	r3, (r4, 0x14)
  46:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  4a:	e0000000 	bsr      	0x0	// 0 <lmac_sta_get>
  4e:	1014      	lrw      	r0, 0x0	// 9c <os_mutex_unlock+0x9c>
  50:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  54:	6c13      	mov      	r0, r4
  56:	1493      	pop      	r4-r6, r15
  58:	e9050020 	bez      	r5, 0x98	// 98 <lmac_sta_get+0x98>
  5c:	d824006f 	ld.b      	r1, (r4, 0x6f)
  60:	8560      	ld.b      	r3, (r5, 0x0)
  62:	64c6      	cmpne      	r1, r3
  64:	081a      	bt      	0x98	// 98 <lmac_sta_get+0x98>
  66:	d8240070 	ld.b      	r1, (r4, 0x70)
  6a:	8561      	ld.b      	r3, (r5, 0x1)
  6c:	64c6      	cmpne      	r1, r3
  6e:	0815      	bt      	0x98	// 98 <lmac_sta_get+0x98>
  70:	d8240071 	ld.b      	r1, (r4, 0x71)
  74:	8562      	ld.b      	r3, (r5, 0x2)
  76:	64c6      	cmpne      	r1, r3
  78:	0810      	bt      	0x98	// 98 <lmac_sta_get+0x98>
  7a:	d8240072 	ld.b      	r1, (r4, 0x72)
  7e:	8563      	ld.b      	r3, (r5, 0x3)
  80:	64c6      	cmpne      	r1, r3
  82:	080b      	bt      	0x98	// 98 <lmac_sta_get+0x98>
  84:	d8240073 	ld.b      	r1, (r4, 0x73)
  88:	8564      	ld.b      	r3, (r5, 0x4)
  8a:	64c6      	cmpne      	r1, r3
  8c:	0806      	bt      	0x98	// 98 <lmac_sta_get+0x98>
  8e:	d8240074 	ld.b      	r1, (r4, 0x74)
  92:	8565      	ld.b      	r3, (r5, 0x5)
  94:	64c6      	cmpne      	r1, r3
  96:	0fd3      	bf      	0x3c	// 3c <lmac_sta_get+0x3c>
  98:	9480      	ld.w      	r4, (r4, 0x0)
  9a:	07c0      	br      	0x1a	// 1a <lmac_sta_get+0x1a>
	...

Disassembly of section .text.lmac_sta_search:

00000000 <lmac_sta_search>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d47      	mov      	r5, r1
   4:	3100      	movi      	r1, 0
   6:	6d83      	mov      	r6, r0
   8:	2900      	subi      	r1, 1
   a:	101e      	lrw      	r0, 0x0	// 80 <lmac_sta_search+0x80>
   c:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  10:	107d      	lrw      	r3, 0x0	// 84 <lmac_sta_search+0x84>
  12:	e46309f7 	addi      	r3, r3, 2552
  16:	9380      	ld.w      	r4, (r3, 0x0)
  18:	64d2      	cmpne      	r4, r3
  1a:	0809      	bt      	0x2c	// 2c <lmac_sta_search+0x2c>
  1c:	3400      	movi      	r4, 0
  1e:	e0000000 	bsr      	0x0	// 0 <lmac_sta_search>
  22:	1018      	lrw      	r0, 0x0	// 80 <os_mutex_unlock+0x80>
  24:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  28:	6c13      	mov      	r0, r4
  2a:	1493      	pop      	r4-r6, r15
  2c:	eb46ffff 	cmpnei      	r6, 65535
  30:	0c05      	bf      	0x3a	// 3a <lmac_sta_search+0x3a>
  32:	d8441034 	ld.h      	r2, (r4, 0x68)
  36:	658a      	cmpne      	r2, r6
  38:	0ff3      	bf      	0x1e	// 1e <lmac_sta_search+0x1e>
  3a:	e9050020 	bez      	r5, 0x7a	// 7a <lmac_sta_search+0x7a>
  3e:	d824006f 	ld.b      	r1, (r4, 0x6f)
  42:	8540      	ld.b      	r2, (r5, 0x0)
  44:	6486      	cmpne      	r1, r2
  46:	081a      	bt      	0x7a	// 7a <lmac_sta_search+0x7a>
  48:	d8240070 	ld.b      	r1, (r4, 0x70)
  4c:	8541      	ld.b      	r2, (r5, 0x1)
  4e:	6486      	cmpne      	r1, r2
  50:	0815      	bt      	0x7a	// 7a <lmac_sta_search+0x7a>
  52:	d8240071 	ld.b      	r1, (r4, 0x71)
  56:	8542      	ld.b      	r2, (r5, 0x2)
  58:	6486      	cmpne      	r1, r2
  5a:	0810      	bt      	0x7a	// 7a <lmac_sta_search+0x7a>
  5c:	d8240072 	ld.b      	r1, (r4, 0x72)
  60:	8543      	ld.b      	r2, (r5, 0x3)
  62:	6486      	cmpne      	r1, r2
  64:	080b      	bt      	0x7a	// 7a <lmac_sta_search+0x7a>
  66:	d8240073 	ld.b      	r1, (r4, 0x73)
  6a:	8544      	ld.b      	r2, (r5, 0x4)
  6c:	6486      	cmpne      	r1, r2
  6e:	0806      	bt      	0x7a	// 7a <lmac_sta_search+0x7a>
  70:	d8240074 	ld.b      	r1, (r4, 0x74)
  74:	8545      	ld.b      	r2, (r5, 0x5)
  76:	6486      	cmpne      	r1, r2
  78:	0fd3      	bf      	0x1e	// 1e <lmac_sta_search+0x1e>
  7a:	9480      	ld.w      	r4, (r4, 0x0)
  7c:	07ce      	br      	0x18	// 18 <lmac_sta_search+0x18>
	...

Disassembly of section .text.lmac_sta_put:

00000000 <lmac_sta_put>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	3100      	movi      	r1, 0
   6:	2900      	subi      	r1, 1
   8:	101c      	lrw      	r0, 0x0	// 78 <lmac_sta_put+0x78>
   a:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
   e:	e904002c 	bez      	r4, 0x66	// 66 <lmac_sta_put+0x66>
  12:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  16:	9465      	ld.w      	r3, (r4, 0x14)
  18:	e903002d 	bez      	r3, 0x72	// 72 <lmac_sta_put+0x72>
  1c:	2b00      	subi      	r3, 1
  1e:	3b40      	cmpnei      	r3, 0
  20:	b465      	st.w      	r3, (r4, 0x14)
  22:	6543      	mvcv      	r5
  24:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  28:	e905001f 	bez      	r5, 0x66	// 66 <lmac_sta_put+0x66>
  2c:	1074      	lrw      	r3, 0x0	// 7c <lmac_sta_put+0x7c>
  2e:	d8241034 	ld.h      	r1, (r4, 0x68)
  32:	d8431504 	ld.h      	r2, (r3, 0xa08)
  36:	2a00      	subi      	r2, 1
  38:	1012      	lrw      	r0, 0x0	// 80 <lmac_sta_put+0x80>
  3a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  3e:	9461      	ld.w      	r3, (r4, 0x4)
  40:	9440      	ld.w      	r2, (r4, 0x0)
  42:	e9030006 	bez      	r3, 0x4e	// 4e <lmac_sta_put+0x4e>
  46:	e9020004 	bez      	r2, 0x4e	// 4e <lmac_sta_put+0x4e>
  4a:	b261      	st.w      	r3, (r2, 0x4)
  4c:	b340      	st.w      	r2, (r3, 0x0)
  4e:	3500      	movi      	r5, 0
  50:	d8042027 	ld.w      	r0, (r4, 0x9c)
  54:	b4a0      	st.w      	r5, (r4, 0x0)
  56:	b4a1      	st.w      	r5, (r4, 0x4)
  58:	e0000000 	bsr      	0x0	// 0 <_os_free>
  5c:	dca42027 	st.w      	r5, (r4, 0x9c)
  60:	6c13      	mov      	r0, r4
  62:	e0000000 	bsr      	0x0	// 0 <_os_free>
  66:	e0000000 	bsr      	0x0	// 0 <lmac_sta_put>
  6a:	1004      	lrw      	r0, 0x0	// 78 <os_mutex_unlock+0x78>
  6c:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  70:	1492      	pop      	r4-r5, r15
  72:	3501      	movi      	r5, 1
  74:	07d8      	br      	0x24	// 24 <lmac_sta_put+0x24>
	...

Disassembly of section .text.lmac_sta_del:

00000000 <lmac_sta_del>:
   0:	14d6      	push      	r4-r9, r15
   2:	6d87      	mov      	r6, r1
   4:	12b7      	lrw      	r5, 0x0	// 160 <lmac_sta_del+0x160>
   6:	3100      	movi      	r1, 0
   8:	6e43      	mov      	r9, r0
   a:	2900      	subi      	r1, 1
   c:	1216      	lrw      	r0, 0x0	// 164 <lmac_sta_del+0x164>
   e:	6e3f      	mov      	r8, r15
  10:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  14:	d885227e 	ld.w      	r4, (r5, 0x9f8)
  18:	e44509f7 	addi      	r2, r5, 2552
  1c:	9460      	ld.w      	r3, (r4, 0x0)
  1e:	6dcb      	mov      	r7, r2
  20:	6492      	cmpne      	r4, r2
  22:	0c40      	bf      	0xa2	// a2 <lmac_sta_del+0xa2>
  24:	eb49ffff 	cmpnei      	r9, 65535
  28:	0c58      	bf      	0xd8	// d8 <lmac_sta_del+0xd8>
  2a:	d8241034 	ld.h      	r1, (r4, 0x68)
  2e:	6646      	cmpne      	r1, r9
  30:	0854      	bt      	0xd8	// d8 <lmac_sta_del+0xd8>
  32:	d8641034 	ld.h      	r3, (r4, 0x68)
  36:	e9030074 	bez      	r3, 0x11e	// 11e <lmac_sta_del+0x11e>
  3a:	d864006b 	ld.b      	r3, (r4, 0x6b)
  3e:	e4432020 	andi      	r2, r3, 32
  42:	e9220078 	bnez      	r2, 0x132	// 132 <lmac_sta_del+0x132>
  46:	3601      	movi      	r6, 1
  48:	c4665c05 	ins      	r3, r6, 5, 5
  4c:	dc64006b 	st.b      	r3, (r4, 0x6b)
  50:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_save>
  54:	9465      	ld.w      	r3, (r4, 0x14)
  56:	e9030006 	bez      	r3, 0x62	// 62 <lmac_sta_del+0x62>
  5a:	2b00      	subi      	r3, 1
  5c:	3b40      	cmpnei      	r3, 0
  5e:	b465      	st.w      	r3, (r4, 0x14)
  60:	6583      	mvcv      	r6
  62:	e0000000 	bsr      	0x0	// 0 <cpu_intrpt_restore>
  66:	d8241034 	ld.h      	r1, (r4, 0x68)
  6a:	e906005d 	bez      	r6, 0x124	// 124 <lmac_sta_del+0x124>
  6e:	d8451504 	ld.h      	r2, (r5, 0xa08)
  72:	7445      	zexth      	r1, r1
  74:	111d      	lrw      	r0, 0x0	// 168 <lmac_sta_del+0x168>
  76:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  7a:	9461      	ld.w      	r3, (r4, 0x4)
  7c:	9440      	ld.w      	r2, (r4, 0x0)
  7e:	e9030006 	bez      	r3, 0x8a	// 8a <lmac_sta_del+0x8a>
  82:	e9020004 	bez      	r2, 0x8a	// 8a <lmac_sta_del+0x8a>
  86:	b261      	st.w      	r3, (r2, 0x4)
  88:	b340      	st.w      	r2, (r3, 0x0)
  8a:	3600      	movi      	r6, 0
  8c:	d8042027 	ld.w      	r0, (r4, 0x9c)
  90:	b4c0      	st.w      	r6, (r4, 0x0)
  92:	b4c1      	st.w      	r6, (r4, 0x4)
  94:	e0000000 	bsr      	0x0	// 0 <_os_free>
  98:	dcc42027 	st.w      	r6, (r4, 0x9c)
  9c:	6c13      	mov      	r0, r4
  9e:	e0000000 	bsr      	0x0	// 0 <_os_free>
  a2:	3000      	movi      	r0, 0
  a4:	d865227e 	ld.w      	r3, (r5, 0x9f8)
  a8:	6c43      	mov      	r1, r0
  aa:	ea0d0001 	movi      	r13, 1
  ae:	65ce      	cmpne      	r3, r7
  b0:	0845      	bt      	0x13a	// 13a <lmac_sta_del+0x13a>
  b2:	dc05229d 	st.w      	r0, (r5, 0xa74)
  b6:	dc25229c 	st.w      	r1, (r5, 0xa70)
  ba:	110d      	lrw      	r0, 0x0	// 16c <hgprintf+0x16c>
  bc:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  c0:	d825229d 	ld.w      	r1, (r5, 0xa74)
  c4:	110b      	lrw      	r0, 0x0	// 170 <hgprintf+0x170>
  c6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ca:	e0000000 	bsr      	0x0	// 0 <lmac_sta_del>
  ce:	1106      	lrw      	r0, 0x0	// 164 <os_mutex_unlock+0x164>
  d0:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  d4:	3000      	movi      	r0, 0
  d6:	1496      	pop      	r4-r9, r15
  d8:	e9060020 	bez      	r6, 0x118	// 118 <lmac_sta_del+0x118>
  dc:	d804006f 	ld.b      	r0, (r4, 0x6f)
  e0:	8620      	ld.b      	r1, (r6, 0x0)
  e2:	6442      	cmpne      	r0, r1
  e4:	081a      	bt      	0x118	// 118 <lmac_sta_del+0x118>
  e6:	d8040070 	ld.b      	r0, (r4, 0x70)
  ea:	8621      	ld.b      	r1, (r6, 0x1)
  ec:	6442      	cmpne      	r0, r1
  ee:	0815      	bt      	0x118	// 118 <lmac_sta_del+0x118>
  f0:	d8040071 	ld.b      	r0, (r4, 0x71)
  f4:	8622      	ld.b      	r1, (r6, 0x2)
  f6:	6442      	cmpne      	r0, r1
  f8:	0810      	bt      	0x118	// 118 <lmac_sta_del+0x118>
  fa:	d8040072 	ld.b      	r0, (r4, 0x72)
  fe:	8623      	ld.b      	r1, (r6, 0x3)
 100:	6442      	cmpne      	r0, r1
 102:	080b      	bt      	0x118	// 118 <lmac_sta_del+0x118>
 104:	d8040073 	ld.b      	r0, (r4, 0x73)
 108:	8624      	ld.b      	r1, (r6, 0x4)
 10a:	6442      	cmpne      	r0, r1
 10c:	0806      	bt      	0x118	// 118 <lmac_sta_del+0x118>
 10e:	d8040074 	ld.b      	r0, (r4, 0x74)
 112:	8625      	ld.b      	r1, (r6, 0x5)
 114:	6442      	cmpne      	r0, r1
 116:	0f8e      	bf      	0x32	// 32 <lmac_sta_del+0x32>
 118:	6d0f      	mov      	r4, r3
 11a:	9360      	ld.w      	r3, (r3, 0x0)
 11c:	0782      	br      	0x20	// 20 <lmac_sta_del+0x20>
 11e:	dc65202f 	st.w      	r3, (r5, 0xbc)
 122:	078c      	br      	0x3a	// 3a <lmac_sta_del+0x3a>
 124:	7485      	zexth      	r2, r1
 126:	6ce3      	mov      	r3, r8
 128:	9425      	ld.w      	r1, (r4, 0x14)
 12a:	1013      	lrw      	r0, 0x0	// 174 <lmac_sta_del+0x174>
 12c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 130:	07b9      	br      	0xa2	// a2 <lmac_sta_del+0xa2>
 132:	1012      	lrw      	r0, 0x0	// 178 <lmac_sta_del+0x178>
 134:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 138:	07b5      	br      	0xa2	// a2 <lmac_sta_del+0xa2>
 13a:	d8431034 	ld.h      	r2, (r3, 0x68)
 13e:	3a1f      	cmphsi      	r2, 32
 140:	0804      	bt      	0x148	// 148 <lmac_sta_del+0x148>
 142:	c44d402c 	lsl      	r12, r13, r2
 146:	6c70      	or      	r1, r12
 148:	d983006b 	ld.b      	r12, (r3, 0x6b)
 14c:	e58c2002 	andi      	r12, r12, 2
 150:	e90c0005 	bez      	r12, 0x15a	// 15a <lmac_sta_del+0x15a>
 154:	c44d4022 	lsl      	r2, r13, r2
 158:	6c08      	or      	r0, r2
 15a:	9360      	ld.w      	r3, (r3, 0x0)
 15c:	07a9      	br      	0xae	// ae <lmac_sta_del+0xae>
	...

Disassembly of section .text.get_icmp_seq_num:

00000000 <get_icmp_seq_num>:
   0:	d8600029 	ld.b      	r3, (r0, 0x29)
   4:	3b41      	cmpnei      	r3, 1
   6:	0808      	bt      	0x16	// 16 <get_icmp_seq_num+0x16>
   8:	d860003a 	ld.b      	r3, (r0, 0x3a)
   c:	4368      	lsli      	r3, r3, 8
   e:	d800003b 	ld.b      	r0, (r0, 0x3b)
  12:	600c      	addu      	r0, r3
  14:	783c      	jmp      	r15
  16:	3000      	movi      	r0, 0
  18:	2800      	subi      	r0, 1
  1a:	07fd      	br      	0x14	// 14 <get_icmp_seq_num+0x14>

Disassembly of section .text.partial_bssid_calc:

00000000 <partial_bssid_calc>:
   0:	8065      	ld.b      	r3, (r0, 0x5)
   2:	4368      	lsli      	r3, r3, 8
   4:	8004      	ld.b      	r0, (r0, 0x4)
   6:	600c      	addu      	r0, r3
   8:	ea0201ff 	movi      	r2, 511
   c:	c4e056c0 	zext      	r0, r0, 22, 7
  10:	c4408023 	divu      	r3, r0, r2
  14:	7cc8      	mult      	r3, r2
  16:	600e      	subu      	r0, r3
  18:	2000      	addi      	r0, 1
  1a:	7401      	zexth      	r0, r0
  1c:	783c      	jmp      	r15

Disassembly of section .text.partial_aid_ndp_calc:

00000000 <partial_aid_ndp_calc>:
   0:	8165      	ld.b      	r3, (r1, 0x5)
   2:	4b44      	lsri      	r2, r3, 4
   4:	6cc9      	xor      	r3, r2
   6:	4365      	lsli      	r3, r3, 5
   8:	600c      	addu      	r0, r3
   a:	e40021ff 	andi      	r0, r0, 511
   e:	783c      	jmp      	r15

Disassembly of section .text.partial_aid_calc:

00000000 <partial_aid_calc>:
   0:	8165      	ld.b      	r3, (r1, 0x5)
   2:	4b44      	lsri      	r2, r3, 4
   4:	6cc9      	xor      	r3, r2
   6:	4365      	lsli      	r3, r3, 5
   8:	600c      	addu      	r0, r3
   a:	e400203f 	andi      	r0, r0, 63
   e:	783c      	jmp      	r15

Disassembly of section .text.element_short_beacon_interval_hdl:

00000000 <element_short_beacon_interval_hdl>:
   0:	8061      	ld.b      	r3, (r0, 0x1)
   2:	3b42      	cmpnei      	r3, 2
   4:	0812      	bt      	0x28	// 28 <element_short_beacon_interval_hdl+0x28>
   6:	8063      	ld.b      	r3, (r0, 0x3)
   8:	8042      	ld.b      	r2, (r0, 0x2)
   a:	4368      	lsli      	r3, r3, 8
   c:	6cc8      	or      	r3, r2
   e:	1048      	lrw      	r2, 0x0	// 2c <element_short_beacon_interval_hdl+0x2c>
  10:	74cf      	sexth      	r3, r3
  12:	dc620656 	st.b      	r3, (r2, 0x656)
  16:	c50355e3 	zext      	r3, r3, 15, 8
  1a:	dc620657 	st.b      	r3, (r2, 0x657)
  1e:	d862132b 	ld.h      	r3, (r2, 0x656)
  22:	436a      	lsli      	r3, r3, 10
  24:	dc622196 	st.w      	r3, (r2, 0x658)
  28:	783c      	jmp      	r15
  2a:	0000      	.short	0x0000
  2c:	0000      	.short	0x0000
	...

Disassembly of section .text.calc_bitmap_offset:

00000000 <calc_bitmap_offset>:
   0:	6441      	cmplt      	r0, r1
   2:	5825      	subu      	r1, r0, r1
   4:	0809      	bt      	0x16	// 16 <calc_bitmap_offset+0x16>
   6:	7447      	sexth      	r1, r1
   8:	3000      	movi      	r0, 0
   a:	eb21003f 	cmplti      	r1, 64
   e:	2800      	subi      	r0, 1
  10:	c4010c40 	inct      	r0, r1, 0
  14:	783c      	jmp      	r15
  16:	e4210fff 	addi      	r1, r1, 4096
  1a:	07f6      	br      	0x6	// 6 <calc_bitmap_offset+0x6>

Disassembly of section .text.lmac_update_pv0_cfend_addr:

00000000 <lmac_update_pv0_cfend_addr>:
   0:	14d0      	push      	r15
   2:	100b      	lrw      	r0, 0x0	// 2c <lmac_update_pv0_cfend_addr+0x2c>
   4:	3206      	movi      	r2, 6
   6:	d860202f 	ld.w      	r3, (r0, 0xbc)
   a:	3b42      	cmpnei      	r3, 2
   c:	080d      	bt      	0x26	// 26 <lmac_update_pv0_cfend_addr+0x26>
   e:	1029      	lrw      	r1, 0x0	// 30 <lmac_update_pv0_cfend_addr+0x30>
  10:	e400095b 	addi      	r0, r0, 2396
  14:	e0000000 	bsr      	0x0	// 0 <memcpy>
  18:	1027      	lrw      	r1, 0x0	// 34 <lmac_update_pv0_cfend_addr+0x34>
  1a:	3206      	movi      	r2, 6
  1c:	e401065f 	addi      	r0, r1, 1632
  20:	e0000000 	bsr      	0x0	// 0 <memcpy>
  24:	1490      	pop      	r15
  26:	e4200525 	addi      	r1, r0, 1318
  2a:	07f3      	br      	0x10	// 10 <ah_lmac+0x10>
	...

Disassembly of section .text.lmac_amp_atten_calc:

00000000 <lmac_amp_atten_calc>:
   0:	14d3      	push      	r4-r6, r15
   2:	6f0b      	mov      	r12, r2
   4:	6d83      	mov      	r6, r0
   6:	3200      	movi      	r2, 0
   8:	ea234034 	movih      	r3, 16436
   c:	6c07      	mov      	r0, r1
   e:	6c73      	mov      	r1, r12
  10:	e0000000 	bsr      	0x0	// 0 <__divdf3>
  14:	6c83      	mov      	r2, r0
  16:	6cc7      	mov      	r3, r1
  18:	3000      	movi      	r0, 0
  1a:	ea214024 	movih      	r1, 16420
  1e:	e0000000 	bsr      	0x0	// 0 <pow>
  22:	6d43      	mov      	r5, r0
  24:	6d07      	mov      	r4, r1
  26:	6c1b      	mov      	r0, r6
  28:	e0000000 	bsr      	0x0	// 0 <__floatunsidf>
  2c:	6cd3      	mov      	r3, r4
  2e:	6c97      	mov      	r2, r5
  30:	e0000000 	bsr      	0x0	// 0 <__divdf3>
  34:	e0000000 	bsr      	0x0	// 0 <__fixunsdfsi>
  38:	6cc3      	mov      	r3, r0
  3a:	7401      	zexth      	r0, r0
  3c:	eb0007ff 	cmphsi      	r0, 2048
  40:	0c03      	bf      	0x46	// 46 <lmac_amp_atten_calc+0x46>
  42:	ea0307ff 	movi      	r3, 2047
  46:	740d      	zexth      	r0, r3
  48:	1493      	pop      	r4-r6, r15

Disassembly of section .text.lmac_next_dtim_calc:

00000000 <lmac_next_dtim_calc>:
   0:	14d1      	push      	r4, r15
   2:	1070      	lrw      	r3, 0x0	// 40 <lmac_next_dtim_calc+0x40>
   4:	9360      	ld.w      	r3, (r3, 0x0)
   6:	d9832005 	ld.w      	r12, (r3, 0x14)
   a:	9344      	ld.w      	r2, (r3, 0x10)
   c:	106e      	lrw      	r3, 0x0	// 44 <lmac_next_dtim_calc+0x44>
   e:	d8032196 	ld.w      	r0, (r3, 0x658)
  12:	e9000013 	bez      	r0, 0x38	// 38 <lmac_next_dtim_calc+0x38>
  16:	d8830556 	ld.b      	r4, (r3, 0x556)
  1a:	e9040010 	bez      	r4, 0x3a	// 3a <lmac_next_dtim_calc+0x3a>
  1e:	7d00      	mult      	r4, r0
  20:	3000      	movi      	r0, 0
  22:	6c73      	mov      	r1, r12
  24:	6f43      	mov      	r13, r0
  26:	6f0b      	mov      	r12, r2
  28:	6cc3      	mov      	r3, r0
  2a:	6c93      	mov      	r2, r4
  2c:	6401      	cmplt      	r0, r0
  2e:	6031      	addc      	r0, r12
  30:	6075      	addc      	r1, r13
  32:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
  36:	5c01      	subu      	r0, r4, r0
  38:	1491      	pop      	r4, r15
  3a:	6c13      	mov      	r0, r4
  3c:	07fe      	br      	0x38	// 38 <lmac_next_dtim_calc+0x38>
	...

Disassembly of section .text.lmac_bkn_dly_calc:

00000000 <lmac_bkn_dly_calc>:
   0:	14d1      	push      	r4, r15
   2:	106f      	lrw      	r3, 0x0	// 3c <lmac_bkn_dly_calc+0x3c>
   4:	102f      	lrw      	r1, 0x0	// 40 <lmac_bkn_dly_calc+0x40>
   6:	9360      	ld.w      	r3, (r3, 0x0)
   8:	d8812196 	ld.w      	r4, (r1, 0x658)
   c:	9345      	ld.w      	r2, (r3, 0x14)
   e:	9364      	ld.w      	r3, (r3, 0x10)
  10:	e9040013 	bez      	r4, 0x36	// 36 <lmac_bkn_dly_calc+0x36>
  14:	3000      	movi      	r0, 0
  16:	6f0f      	mov      	r12, r3
  18:	6c4b      	mov      	r1, r2
  1a:	6f43      	mov      	r13, r0
  1c:	6cc3      	mov      	r3, r0
  1e:	6c93      	mov      	r2, r4
  20:	6401      	cmplt      	r0, r0
  22:	6031      	addc      	r0, r12
  24:	6075      	addc      	r1, r13
  26:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
  2a:	4c61      	lsri      	r3, r4, 1
  2c:	640c      	cmphs      	r3, r0
  2e:	5891      	subu      	r4, r0, r4
  30:	c4040c20 	incf      	r0, r4, 0
  34:	1491      	pop      	r4, r15
  36:	6c13      	mov      	r0, r4
  38:	07fe      	br      	0x34	// 34 <lmac_bkn_dly_calc+0x34>
	...

Disassembly of section .text.lmac_beacon_timer_start:

00000000 <lmac_beacon_timer_start>:
   0:	106a      	lrw      	r3, 0x0	// 28 <lmac_beacon_timer_start+0x28>
   2:	9360      	ld.w      	r3, (r3, 0x0)
   4:	d8432033 	ld.w      	r2, (r3, 0xcc)
   8:	ec420002 	ori      	r2, r2, 2
   c:	dc432033 	st.w      	r2, (r3, 0xcc)
  10:	3280      	movi      	r2, 128
  12:	4246      	lsli      	r2, r2, 6
  14:	b352      	st.w      	r2, (r3, 0x48)
  16:	dc032030 	st.w      	r0, (r3, 0xc0)
  1a:	d8432033 	ld.w      	r2, (r3, 0xcc)
  1e:	ec420001 	ori      	r2, r2, 1
  22:	dc432033 	st.w      	r2, (r3, 0xcc)
  26:	783c      	jmp      	r15
  28:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_beacon_timer_abort:

00000000 <lmac_beacon_timer_abort>:
   0:	1066      	lrw      	r3, 0x0	// 18 <lmac_beacon_timer_abort+0x18>
   2:	9360      	ld.w      	r3, (r3, 0x0)
   4:	d8432033 	ld.w      	r2, (r3, 0xcc)
   8:	ec420002 	ori      	r2, r2, 2
   c:	dc432033 	st.w      	r2, (r3, 0xcc)
  10:	3280      	movi      	r2, 128
  12:	4246      	lsli      	r2, r2, 6
  14:	b352      	st.w      	r2, (r3, 0x48)
  16:	783c      	jmp      	r15
  18:	00000000 	.long	0x00000000

Disassembly of section .text.lf_timer_start:

00000000 <lf_timer_start>:
   0:	106a      	lrw      	r3, 0x0	// 28 <lf_timer_start+0x28>
   2:	4805      	lsri      	r0, r0, 5
   4:	9360      	ld.w      	r3, (r3, 0x0)
   6:	d8432032 	ld.w      	r2, (r3, 0xc8)
   a:	dc432032 	st.w      	r2, (r3, 0xc8)
   e:	d8432032 	ld.w      	r2, (r3, 0xc8)
  12:	6c08      	or      	r0, r2
  14:	dc032032 	st.w      	r0, (r3, 0xc8)
  18:	d8432033 	ld.w      	r2, (r3, 0xcc)
  1c:	ec420010 	ori      	r2, r2, 16
  20:	dc432033 	st.w      	r2, (r3, 0xcc)
  24:	783c      	jmp      	r15
  26:	0000      	.short	0x0000
  28:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_qa_results_valid_check:

00000000 <lmac_qa_results_valid_check>:
   0:	1269      	lrw      	r3, 0x0	// 124 <lmac_qa_results_valid_check+0x124>
   2:	d84308c0 	ld.b      	r2, (r3, 0x8c0)
   6:	d98308ac 	ld.b      	r12, (r3, 0x8ac)
   a:	d823089c 	ld.b      	r1, (r3, 0x89c)
   e:	e4022001 	andi      	r0, r2, 1
  12:	7732      	sextb      	r12, r12
  14:	7446      	sextb      	r1, r1
  16:	6471      	cmplt      	r12, r1
  18:	e9000056 	bez      	r0, 0xc4	// c4 <lmac_qa_results_valid_check+0xc4>
  1c:	c4000500 	mvc      	r0
  20:	3100      	movi      	r1, 0
  22:	5901      	subu      	r0, r1, r0
  24:	e4222002 	andi      	r1, r2, 2
  28:	d9a348ad 	ld.bs      	r13, (r3, 0x8ad)
  2c:	d983489d 	ld.bs      	r12, (r3, 0x89d)
  30:	e901004d 	bez      	r1, 0xca	// ca <lmac_qa_results_valid_check+0xca>
  34:	3100      	movi      	r1, 0
  36:	2900      	subi      	r1, 1
  38:	6771      	cmplt      	r12, r13
  3a:	c4010c40 	inct      	r0, r1, 0
  3e:	e4422004 	andi      	r2, r2, 4
  42:	d98348ae 	ld.bs      	r12, (r3, 0x8ae)
  46:	e9020048 	bez      	r2, 0xd6	// d6 <lmac_qa_results_valid_check+0xd6>
  4a:	d843489e 	ld.bs      	r2, (r3, 0x89e)
  4e:	6709      	cmplt      	r2, r12
  50:	084e      	bt      	0xec	// ec <lmac_qa_results_valid_check+0xec>
  52:	3100      	movi      	r1, 0
  54:	604a      	subu      	r1, r2
  56:	3200      	movi      	r2, 0
  58:	2a00      	subi      	r2, 1
  5a:	6471      	cmplt      	r12, r1
  5c:	c4020c40 	inct      	r0, r2, 0
  60:	d84308c1 	ld.b      	r2, (r3, 0x8c1)
  64:	e5a22001 	andi      	r13, r2, 1
  68:	d98308b6 	ld.b      	r12, (r3, 0x8b6)
  6c:	d82308a4 	ld.b      	r1, (r3, 0x8a4)
  70:	7732      	sextb      	r12, r12
  72:	7446      	sextb      	r1, r1
  74:	e90d003f 	bez      	r13, 0xf2	// f2 <lmac_qa_results_valid_check+0xf2>
  78:	ea0d0000 	movi      	r13, 0
  7c:	e5ad1000 	subi      	r13, r13, 1
  80:	6471      	cmplt      	r12, r1
  82:	c40d0c40 	inct      	r0, r13, 0
  86:	e4222002 	andi      	r1, r2, 2
  8a:	d9a348b7 	ld.bs      	r13, (r3, 0x8b7)
  8e:	d98348a5 	ld.bs      	r12, (r3, 0x8a5)
  92:	e9010038 	bez      	r1, 0x102	// 102 <lmac_qa_results_valid_check+0x102>
  96:	3100      	movi      	r1, 0
  98:	2900      	subi      	r1, 1
  9a:	6771      	cmplt      	r12, r13
  9c:	c4010c40 	inct      	r0, r1, 0
  a0:	e4422004 	andi      	r2, r2, 4
  a4:	d82348b8 	ld.bs      	r1, (r3, 0x8b8)
  a8:	d86348a6 	ld.bs      	r3, (r3, 0x8a6)
  ac:	644d      	cmplt      	r3, r1
  ae:	e9020030 	bez      	r2, 0x10e	// 10e <lmac_qa_results_valid_check+0x10e>
  b2:	0836      	bt      	0x11e	// 11e <lmac_qa_results_valid_check+0x11e>
  b4:	3200      	movi      	r2, 0
  b6:	608e      	subu      	r2, r3
  b8:	3300      	movi      	r3, 0
  ba:	2b00      	subi      	r3, 1
  bc:	6485      	cmplt      	r1, r2
  be:	c4030c40 	inct      	r0, r3, 0
  c2:	783c      	jmp      	r15
  c4:	6443      	mvcv      	r1
  c6:	6006      	subu      	r0, r1
  c8:	07ae      	br      	0x24	// 24 <lmac_qa_results_valid_check+0x24>
  ca:	3100      	movi      	r1, 0
  cc:	2900      	subi      	r1, 1
  ce:	6771      	cmplt      	r12, r13
  d0:	c4010c20 	incf      	r0, r1, 0
  d4:	07b5      	br      	0x3e	// 3e <lmac_qa_results_valid_check+0x3e>
  d6:	d823489e 	ld.bs      	r1, (r3, 0x89e)
  da:	6705      	cmplt      	r1, r12
  dc:	0bc2      	bt      	0x60	// 60 <lmac_qa_results_valid_check+0x60>
  de:	6086      	subu      	r2, r1
  e0:	3100      	movi      	r1, 0
  e2:	2900      	subi      	r1, 1
  e4:	64b1      	cmplt      	r12, r2
  e6:	c4010c20 	incf      	r0, r1, 0
  ea:	07bb      	br      	0x60	// 60 <lmac_qa_results_valid_check+0x60>
  ec:	3000      	movi      	r0, 0
  ee:	2800      	subi      	r0, 1
  f0:	07b8      	br      	0x60	// 60 <lmac_qa_results_valid_check+0x60>
  f2:	ea0d0000 	movi      	r13, 0
  f6:	e5ad1000 	subi      	r13, r13, 1
  fa:	6471      	cmplt      	r12, r1
  fc:	c40d0c20 	incf      	r0, r13, 0
 100:	07c3      	br      	0x86	// 86 <lmac_qa_results_valid_check+0x86>
 102:	3100      	movi      	r1, 0
 104:	2900      	subi      	r1, 1
 106:	6771      	cmplt      	r12, r13
 108:	c4010c20 	incf      	r0, r1, 0
 10c:	07ca      	br      	0xa0	// a0 <lmac_qa_results_valid_check+0xa0>
 10e:	0bda      	bt      	0xc2	// c2 <lmac_qa_results_valid_check+0xc2>
 110:	608e      	subu      	r2, r3
 112:	3300      	movi      	r3, 0
 114:	2b00      	subi      	r3, 1
 116:	6485      	cmplt      	r1, r2
 118:	c4030c20 	incf      	r0, r3, 0
 11c:	07d3      	br      	0xc2	// c2 <lmac_qa_results_valid_check+0xc2>
 11e:	3000      	movi      	r0, 0
 120:	2800      	subi      	r0, 1
 122:	07d0      	br      	0xc2	// c2 <lmac_qa_results_valid_check+0xc2>
 124:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_rx_dbg_info:

00000000 <lmac_rx_dbg_info>:
   0:	14d3      	push      	r4-r6, r15
   2:	1100      	lrw      	r0, 0x0	// 80 <lmac_rx_dbg_info+0x80>
   4:	e0000000 	bsr      	0x0	// 0 <hgprintf>
   8:	3400      	movi      	r4, 0
   a:	10bf      	lrw      	r5, 0x0	// 84 <lmac_rx_dbg_info+0x84>
   c:	ea038000 	movi      	r3, 32768
  10:	3bbe      	bseti      	r3, 30
  12:	60d0      	addu      	r3, r4
  14:	6c53      	mov      	r1, r4
  16:	9340      	ld.w      	r2, (r3, 0x0)
  18:	6c17      	mov      	r0, r5
  1a:	2403      	addi      	r4, 4
  1c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  20:	eb440630 	cmpnei      	r4, 1584
  24:	0bf4      	bt      	0xc	// c <lmac_rx_dbg_info+0xc>
  26:	1019      	lrw      	r0, 0x0	// 88 <lmac_rx_dbg_info+0x88>
  28:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  2c:	3400      	movi      	r4, 0
  2e:	10b8      	lrw      	r5, 0x0	// 8c <lmac_rx_dbg_info+0x8c>
  30:	ea234002 	movih      	r3, 16386
  34:	3bae      	bseti      	r3, 14
  36:	60d0      	addu      	r3, r4
  38:	6c53      	mov      	r1, r4
  3a:	9340      	ld.w      	r2, (r3, 0x0)
  3c:	6c17      	mov      	r0, r5
  3e:	2403      	addi      	r4, 4
  40:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  44:	eb44023c 	cmpnei      	r4, 572
  48:	0bf4      	bt      	0x30	// 30 <lmac_rx_dbg_info+0x30>
  4a:	3400      	movi      	r4, 0
  4c:	10b1      	lrw      	r5, 0x0	// 90 <lmac_rx_dbg_info+0x90>
  4e:	10d2      	lrw      	r6, 0x0	// 94 <lmac_rx_dbg_info+0x94>
  50:	9560      	ld.w      	r3, (r5, 0x0)
  52:	d8632105 	ld.w      	r3, (r3, 0x414)
  56:	e463207f 	andi      	r3, r3, 127
  5a:	64d0      	cmphs      	r4, r3
  5c:	0c03      	bf      	0x62	// 62 <lmac_rx_dbg_info+0x62>
  5e:	3000      	movi      	r0, 0
  60:	1493      	pop      	r4-r6, r15
  62:	6c53      	mov      	r1, r4
  64:	6c1b      	mov      	r0, r6
  66:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  6a:	e4440083 	addi      	r2, r4, 132
  6e:	9560      	ld.w      	r3, (r5, 0x0)
  70:	d0430900 	ldr.w      	r0, (r3, r2 << 3)
  74:	3160      	movi      	r1, 96
  76:	e0000000 	bsr      	0x0	// 0 <lmac_rx_dbg_info>
  7a:	2400      	addi      	r4, 1
  7c:	07ea      	br      	0x50	// 50 <lmac_rx_dbg_info+0x50>
	...

Disassembly of section .text.lmac_adc_dump:

00000000 <lmac_adc_dump>:
   0:	14d4      	push      	r4-r7, r15
   2:	1182      	lrw      	r4, 0x0	// 88 <lmac_adc_dump+0x88>
   4:	6dc7      	mov      	r7, r1
   6:	d8640333 	ld.b      	r3, (r4, 0x333)
   a:	e4632001 	andi      	r3, r3, 1
   e:	6d8b      	mov      	r6, r2
  10:	e903003a 	bez      	r3, 0x84	// 84 <lmac_adc_dump+0x84>
  14:	d8640332 	ld.b      	r3, (r4, 0x332)
  18:	640e      	cmpne      	r3, r0
  1a:	0835      	bt      	0x84	// 84 <lmac_adc_dump+0x84>
  1c:	c0006025 	mfcr      	r5, cr<0, 0>
  20:	c0807020 	psrclr      	ie
  24:	3000      	movi      	r0, 0
  26:	e0000000 	bsr      	0x0	// 0 <mcu_watchdog_timeout>
  2a:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
  2e:	e4632002 	andi      	r3, r3, 2
  32:	e4a52040 	andi      	r5, r5, 64
  36:	e9030005 	bez      	r3, 0x40	// 40 <lmac_adc_dump+0x40>
  3a:	3000      	movi      	r0, 0
  3c:	e0000000 	bsr      	0x0	// 0 <disable_print>
  40:	e0000000 	bsr      	0x0	// 0 <lmac_adc_dump>
  44:	1012      	lrw      	r0, 0x0	// 8c <hgprintf+0x8c>
  46:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  4a:	6c5b      	mov      	r1, r6
  4c:	6c1f      	mov      	r0, r7
  4e:	e0000000 	bsr      	0x0	// 0 <lmac_adc_dump>
  52:	6c9b      	mov      	r2, r6
  54:	d8240332 	ld.b      	r1, (r4, 0x332)
  58:	100e      	lrw      	r0, 0x0	// 90 <hgprintf+0x90>
  5a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  5e:	3300      	movi      	r3, 0
  60:	dc640332 	st.b      	r3, (r4, 0x332)
  64:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
  68:	e4632002 	andi      	r3, r3, 2
  6c:	e9030005 	bez      	r3, 0x76	// 76 <lmac_adc_dump+0x76>
  70:	3001      	movi      	r0, 1
  72:	e0000000 	bsr      	0x0	// 0 <disable_print>
  76:	3005      	movi      	r0, 5
  78:	e0000000 	bsr      	0x0	// 0 <mcu_watchdog_timeout>
  7c:	e9050004 	bez      	r5, 0x84	// 84 <lmac_adc_dump+0x84>
  80:	c0807420 	psrset      	ie
  84:	3000      	movi      	r0, 0
  86:	1494      	pop      	r4-r7, r15
	...

Disassembly of section .text.lmac_tdma_start:

00000000 <lmac_tdma_start>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
   6:	e0000000 	bsr      	0x0	// 0 <ah_tdma_start>
   a:	1490      	pop      	r15

Disassembly of section .text.lmac_is_icmp_ping:

00000000 <lmac_is_icmp_ping>:
   0:	14d1      	push      	r4, r15
   2:	8066      	ld.b      	r3, (r0, 0x6)
   4:	4368      	lsli      	r3, r3, 8
   6:	8047      	ld.b      	r2, (r0, 0x7)
   8:	6cc8      	or      	r3, r2
   a:	74cf      	sexth      	r3, r3
   c:	eb430800 	cmpnei      	r3, 2048
  10:	0813      	bt      	0x36	// 36 <lmac_is_icmp_ping+0x36>
  12:	8068      	ld.b      	r3, (r0, 0x8)
  14:	eb430045 	cmpnei      	r3, 69
  18:	080f      	bt      	0x36	// 36 <lmac_is_icmp_ping+0x36>
  1a:	8091      	ld.b      	r4, (r0, 0x11)
  1c:	3c41      	cmpnei      	r4, 1
  1e:	080c      	bt      	0x36	// 36 <lmac_is_icmp_ping+0x36>
  20:	d8600022 	ld.b      	r3, (r0, 0x22)
  24:	d8200023 	ld.b      	r1, (r0, 0x23)
  28:	4368      	lsli      	r3, r3, 8
  2a:	1005      	lrw      	r0, 0x0	// 3c <lmac_is_icmp_ping+0x3c>
  2c:	6c4c      	or      	r1, r3
  2e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  32:	6c13      	mov      	r0, r4
  34:	1491      	pop      	r4, r15
  36:	3000      	movi      	r0, 0
  38:	07fe      	br      	0x34	// 34 <lmac_is_icmp_ping+0x34>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000
	...

Disassembly of section .text.dsleep_dur_calc:

00000000 <dsleep_dur_calc>:
   0:	14c5      	push      	r4-r8
   2:	1073      	lrw      	r3, 0x0	// 4c <dsleep_dur_calc+0x4c>
   4:	1053      	lrw      	r2, 0x0	// 50 <dsleep_dur_calc+0x50>
   6:	9360      	ld.w      	r3, (r3, 0x0)
   8:	d9832005 	ld.w      	r12, (r3, 0x14)
   c:	d9032004 	ld.w      	r8, (r3, 0x10)
  10:	d8620556 	ld.b      	r3, (r2, 0x556)
  14:	d8422196 	ld.w      	r2, (r2, 0x658)
  18:	7cc8      	mult      	r3, r2
  1a:	e9030011 	bez      	r3, 0x3c	// 3c <dsleep_dur_calc+0x3c>
  1e:	3600      	movi      	r6, 0
  20:	6df3      	mov      	r7, r12
  22:	6f5b      	mov      	r13, r6
  24:	6f23      	mov      	r12, r8
  26:	6731      	cmplt      	r12, r12
  28:	6319      	addc      	r12, r6
  2a:	635d      	addc      	r13, r7
  2c:	6474      	cmphs      	r13, r1
  2e:	0c05      	bf      	0x38	// 38 <dsleep_dur_calc+0x38>
  30:	6746      	cmpne      	r1, r13
  32:	0807      	bt      	0x40	// 40 <dsleep_dur_calc+0x40>
  34:	6430      	cmphs      	r12, r0
  36:	0805      	bt      	0x40	// 40 <dsleep_dur_calc+0x40>
  38:	60f2      	subu      	r3, r12
  3a:	60c0      	addu      	r3, r0
  3c:	6c0f      	mov      	r0, r3
  3e:	1485      	pop      	r4-r8
  40:	6d0f      	mov      	r4, r3
  42:	3500      	movi      	r5, 0
  44:	6401      	cmplt      	r0, r0
  46:	6011      	addc      	r0, r4
  48:	6055      	addc      	r1, r5
  4a:	07f1      	br      	0x2c	// 2c <dsleep_dur_calc+0x2c>
	...

Disassembly of section .text.lmac_rx_gain_cfg:

00000000 <lmac_rx_gain_cfg>:
   0:	14d2      	push      	r4-r5, r15
   2:	586f      	subi      	r3, r0, 4
   4:	74cc      	zextb      	r3, r3
   6:	3b01      	cmphsi      	r3, 2
   8:	6d03      	mov      	r4, r0
   a:	0c06      	bf      	0x16	// 16 <lmac_rx_gain_cfg+0x16>
   c:	6c43      	mov      	r1, r0
   e:	100a      	lrw      	r0, 0x0	// 34 <lmac_rx_gain_cfg+0x34>
  10:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  14:	1492      	pop      	r4-r5, r15
  16:	10a9      	lrw      	r5, 0x0	// 38 <lmac_rx_gain_cfg+0x38>
  18:	d8250308 	ld.b      	r1, (r5, 0x308)
  1c:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_gain>
  20:	6c13      	mov      	r0, r4
  22:	e0000000 	bsr      	0x0	// 0 <ah_wphy_rx_gain_stage_cfg>
  26:	d86511b1 	ld.h      	r3, (r5, 0x362)
  2a:	c4645ce4 	ins      	r3, r4, 11, 4
  2e:	dc6511b1 	st.h      	r3, (r5, 0x362)
  32:	07f1      	br      	0x14	// 14 <lmac_rx_gain_cfg+0x14>
	...

Disassembly of section .text.lmac_get_avg_power:

00000000 <lmac_get_avg_power>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <ah_wphy_avg_power_get>
   6:	e9200009 	bnez      	r0, 0x18	// 18 <lmac_get_avg_power+0x18>
   a:	104a      	lrw      	r2, 0x0	// 30 <lmac_get_avg_power+0x30>
   c:	d8621402 	ld.h      	r3, (r2, 0x804)
  10:	2300      	addi      	r3, 1
  12:	dc621402 	st.h      	r3, (r2, 0x804)
  16:	1490      	pop      	r15
  18:	3300      	movi      	r3, 0
  1a:	2b7f      	subi      	r3, 128
  1c:	64c2      	cmpne      	r0, r3
  1e:	0bfc      	bt      	0x16	// 16 <lmac_get_avg_power+0x16>
  20:	1044      	lrw      	r2, 0x0	// 30 <lmac_get_avg_power+0x30>
  22:	d8621403 	ld.h      	r3, (r2, 0x806)
  26:	2300      	addi      	r3, 1
  28:	dc621403 	st.h      	r3, (r2, 0x806)
  2c:	07f5      	br      	0x16	// 16 <lmac_get_avg_power+0x16>
  2e:	0000      	.short	0x0000
  30:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_arp_data_det:

00000000 <lmac_arp_data_det>:
   0:	d8604000 	ld.bs      	r3, (r0, 0x0)
   4:	3bdf      	btsti      	r3, 31
   6:	321a      	movi      	r2, 26
   8:	3318      	movi      	r3, 24
   a:	c4620c40 	inct      	r3, r2, 0
   e:	600c      	addu      	r0, r3
  10:	8066      	ld.b      	r3, (r0, 0x6)
  12:	8047      	ld.b      	r2, (r0, 0x7)
  14:	4368      	lsli      	r3, r3, 8
  16:	6cc8      	or      	r3, r2
  18:	74cf      	sexth      	r3, r3
  1a:	eb430806 	cmpnei      	r3, 2054
  1e:	6403      	mvcv      	r0
  20:	783c      	jmp      	r15

Disassembly of section .text.data_scrambler:

00000000 <data_scrambler>:
   0:	14c3      	push      	r4-r6
   2:	3300      	movi      	r3, 0
   4:	c4605cc0 	ins      	r3, r0, 6, 0
   8:	c423542c 	zext      	r12, r3, 1, 1
   c:	e5a32001 	andi      	r13, r3, 1
  10:	c4835486 	zext      	r6, r3, 4, 4
  14:	c58d2442 	xor      	r2, r13, r12
  18:	c4435441 	zext      	r1, r3, 2, 2
  1c:	6c99      	xor      	r2, r6
  1e:	3000      	movi      	r0, 0
  20:	c4a354a5 	zext      	r5, r3, 5, 5
  24:	c4025c00 	ins      	r0, r2, 0, 0
  28:	c42c2442 	xor      	r2, r12, r1
  2c:	6c95      	xor      	r2, r5
  2e:	c4025c01 	ins      	r0, r2, 1, 1
  32:	c4635462 	zext      	r2, r3, 3, 3
  36:	c4412444 	xor      	r4, r1, r2
  3a:	c4c354c3 	zext      	r3, r3, 6, 6
  3e:	6d0d      	xor      	r4, r3
  40:	c4045c02 	ins      	r0, r4, 2, 2
  44:	6f49      	xor      	r13, r2
  46:	c40d5c03 	ins      	r0, r13, 3, 3
  4a:	6f19      	xor      	r12, r6
  4c:	c40c5c04 	ins      	r0, r12, 4, 4
  50:	6c55      	xor      	r1, r5
  52:	c4015c05 	ins      	r0, r1, 5, 5
  56:	6cc9      	xor      	r3, r2
  58:	c4035c06 	ins      	r0, r3, 6, 6
  5c:	e400207f 	andi      	r0, r0, 127
  60:	1483      	pop      	r4-r6

Disassembly of section .text.lmac_get_beacon_retry_limit:

00000000 <lmac_get_beacon_retry_limit>:
   0:	104b      	lrw      	r2, 0x0	// 2c <lmac_get_beacon_retry_limit+0x2c>
   2:	301f      	movi      	r0, 31
   4:	d8222196 	ld.w      	r1, (r2, 0x658)
   8:	d8620556 	ld.b      	r3, (r2, 0x556)
   c:	7cc4      	mult      	r3, r1
   e:	d842034a 	ld.b      	r2, (r2, 0x34a)
  12:	1028      	lrw      	r1, 0x4e1fff	// 30 <lmac_get_beacon_retry_limit+0x30>
  14:	64c4      	cmphs      	r1, r3
  16:	e4422001 	andi      	r2, r2, 1
  1a:	3307      	movi      	r3, 7
  1c:	c4600c20 	incf      	r3, r0, 0
  20:	3a40      	cmpnei      	r2, 0
  22:	3003      	movi      	r0, 3
  24:	c4030c20 	incf      	r0, r3, 0
  28:	783c      	jmp      	r15
  2a:	0000      	.short	0x0000
  2c:	0000      	.short	0x0000
  2e:	0000      	.short	0x0000
  30:	004e1fff 	.long	0x004e1fff

Disassembly of section .text.lmac_next_beacon_calc:

00000000 <lmac_next_beacon_calc>:
   0:	14d4      	push      	r4-r7, r15
   2:	e0000000 	bsr      	0x0	// 0 <lmac_next_beacon_calc>
   6:	11e2      	lrw      	r7, 0x0	// 8c <lmac_next_beacon_calc+0x8c>
   8:	1162      	lrw      	r3, 0x0	// 90 <lmac_next_beacon_calc+0x90>
   a:	6d43      	mov      	r5, r0
   c:	9360      	ld.w      	r3, (r3, 0x0)
   e:	d8c72196 	ld.w      	r6, (r7, 0x658)
  12:	9345      	ld.w      	r2, (r3, 0x14)
  14:	9364      	ld.w      	r3, (r3, 0x10)
  16:	e9060030 	bez      	r6, 0x76	// 76 <lmac_next_beacon_calc+0x76>
  1a:	3000      	movi      	r0, 0
  1c:	6f0f      	mov      	r12, r3
  1e:	6c4b      	mov      	r1, r2
  20:	6f43      	mov      	r13, r0
  22:	6cc3      	mov      	r3, r0
  24:	6c9b      	mov      	r2, r6
  26:	6401      	cmplt      	r0, r0
  28:	6031      	addc      	r0, r12
  2a:	6075      	addc      	r1, r13
  2c:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
  30:	5e81      	subu      	r4, r6, r0
  32:	4e61      	lsri      	r3, r6, 1
  34:	64d0      	cmphs      	r4, r3
  36:	6190      	addu      	r6, r4
  38:	c4860c20 	incf      	r4, r6, 0
  3c:	d8670555 	ld.b      	r3, (r7, 0x555)
  40:	3b41      	cmpnei      	r3, 1
  42:	0818      	bt      	0x72	// 72 <lmac_next_beacon_calc+0x72>
  44:	d8671505 	ld.h      	r3, (r7, 0xa0a)
  48:	e9030015 	bez      	r3, 0x72	// 72 <lmac_next_beacon_calc+0x72>
  4c:	877f      	ld.b      	r3, (r7, 0x1f)
  4e:	5b2c      	addu      	r1, r3, r3
  50:	604c      	addu      	r1, r3
  52:	4144      	lsli      	r2, r1, 4
  54:	6084      	addu      	r2, r1
  56:	60c8      	addu      	r3, r2
  58:	e443009f 	addi      	r2, r3, 160
  5c:	d827133a 	ld.h      	r1, (r7, 0x674)
  60:	6084      	addu      	r2, r1
  62:	2d00      	subi      	r5, 1
  64:	7c94      	mult      	r2, r5
  66:	4a41      	lsri      	r2, r2, 1
  68:	608e      	subu      	r2, r3
  6a:	2a9f      	subi      	r2, 160
  6c:	6508      	cmphs      	r2, r4
  6e:	0809      	bt      	0x80	// 80 <lmac_next_beacon_calc+0x80>
  70:	610a      	subu      	r4, r2
  72:	6c13      	mov      	r0, r4
  74:	1494      	pop      	r4-r7, r15
  76:	1008      	lrw      	r0, 0x0	// 94 <lmac_next_beacon_calc+0x94>
  78:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  7c:	6d1b      	mov      	r4, r6
  7e:	07df      	br      	0x3c	// 3c <lmac_next_beacon_calc+0x3c>
  80:	6c53      	mov      	r1, r4
  82:	1006      	lrw      	r0, 0x0	// 98 <lmac_next_beacon_calc+0x98>
  84:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  88:	07f5      	br      	0x72	// 72 <lmac_next_beacon_calc+0x72>
	...

Disassembly of section .text.lmac_report_sleep_exit:

00000000 <lmac_report_sleep_exit>:
   0:	14d0      	push      	r15
   2:	1421      	subi      	r14, r14, 4
   4:	106a      	lrw      	r3, 0x0	// 2c <lmac_report_sleep_exit+0x2c>
   6:	dc0e0003 	st.b      	r0, (r14, 0x3)
   a:	9360      	ld.w      	r3, (r3, 0x0)
   c:	d9832009 	ld.w      	r12, (r3, 0x24)
  10:	e90c000b 	bez      	r12, 0x26	// 26 <lmac_report_sleep_exit+0x26>
  14:	1007      	lrw      	r0, 0x0	// 30 <lmac_report_sleep_exit+0x30>
  16:	3300      	movi      	r3, 0
  18:	e44e0002 	addi      	r2, r14, 3
  1c:	3114      	movi      	r1, 20
  1e:	9000      	ld.w      	r0, (r0, 0x0)
  20:	7bf1      	jsr      	r12
  22:	1401      	addi      	r14, r14, 4
  24:	1490      	pop      	r15
  26:	3000      	movi      	r0, 0
  28:	2800      	subi      	r0, 1
  2a:	07fc      	br      	0x22	// 22 <lmac_report_sleep_exit+0x22>
	...
