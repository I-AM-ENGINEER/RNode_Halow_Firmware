
disasm/liblmac/obj/mars_lmac_hw.o:     file format elf32-csky-little


Disassembly of section .text.lhw_enable_irq_ac:

00000000 <lhw_enable_irq_ac>:
   0:	1064      	lrw      	r3, 0x0	// 10 <lhw_enable_irq_ac+0x10>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	9271      	ld.w      	r3, (r2, 0x44)
   6:	ec630080 	ori      	r3, r3, 128
   a:	b271      	st.w      	r3, (r2, 0x44)
   c:	783c      	jmp      	r15
   e:	0000      	.short	0x0000
  10:	00000000 	.long	0x00000000

Disassembly of section .text.lhw_start_rx:

00000000 <lhw_start_rx>:
   0:	1071      	lrw      	r3, 0x0	// 44 <lhw_start_rx+0x44>
   2:	1032      	lrw      	r1, 0xf000f0	// 48 <lhw_start_rx+0x48>
   4:	9360      	ld.w      	r3, (r3, 0x0)
   6:	934d      	ld.w      	r2, (r3, 0x34)
   8:	6884      	and      	r2, r1
   a:	e922001c 	bnez      	r2, 0x42	// 42 <lhw_start_rx+0x42>
   e:	9347      	ld.w      	r2, (r3, 0x1c)
  10:	ea01ffff 	movi      	r1, 65535
  14:	c7014901 	rotli      	r1, r1, 24
  18:	6884      	and      	r2, r1
  1a:	b347      	st.w      	r2, (r3, 0x1c)
  1c:	9347      	ld.w      	r2, (r3, 0x1c)
  1e:	4008      	lsli      	r0, r0, 8
  20:	6c08      	or      	r0, r2
  22:	b307      	st.w      	r0, (r3, 0x1c)
  24:	934c      	ld.w      	r2, (r3, 0x30)
  26:	3a84      	bclri      	r2, 4
  28:	3a85      	bclri      	r2, 5
  2a:	b34c      	st.w      	r2, (r3, 0x30)
  2c:	934c      	ld.w      	r2, (r3, 0x30)
  2e:	ec420020 	ori      	r2, r2, 32
  32:	b34c      	st.w      	r2, (r3, 0x30)
  34:	934c      	ld.w      	r2, (r3, 0x30)
  36:	ec420001 	ori      	r2, r2, 1
  3a:	b34c      	st.w      	r2, (r3, 0x30)
  3c:	934c      	ld.w      	r2, (r3, 0x30)
  3e:	3a8d      	bclri      	r2, 13
  40:	b34c      	st.w      	r2, (r3, 0x30)
  42:	783c      	jmp      	r15
  44:	00000000 	.long	0x00000000
  48:	00f0      	.short	0x00f0
  4a:	00f0      	.short	0x00f0

Disassembly of section .text.lhw_abort_fsm:

00000000 <lhw_abort_fsm>:
   0:	14d1      	push      	r4, r15
   2:	1053      	lrw      	r2, 0x0	// 4c <lhw_abort_fsm+0x4c>
   4:	31a0      	movi      	r1, 160
   6:	9260      	ld.w      	r3, (r2, 0x0)
   8:	4125      	lsli      	r1, r1, 5
   a:	b332      	st.w      	r1, (r3, 0x48)
   c:	9311      	ld.w      	r0, (r3, 0x44)
   e:	388a      	bclri      	r0, 10
  10:	388c      	bclri      	r0, 12
  12:	b311      	st.w      	r0, (r3, 0x44)
  14:	b332      	st.w      	r1, (r3, 0x48)
  16:	932c      	ld.w      	r1, (r3, 0x30)
  18:	ec210002 	ori      	r1, r1, 2
  1c:	b32c      	st.w      	r1, (r3, 0x30)
  1e:	6d0b      	mov      	r4, r2
  20:	3314      	movi      	r3, 20
  22:	6c03      	mov      	r0, r0
  24:	2b00      	subi      	r3, 1
  26:	e923fffe 	bnez      	r3, 0x22	// 22 <lhw_abort_fsm+0x22>
  2a:	e0000000 	bsr      	0x0	// 0 <lmac_rx_cleanup_info>
  2e:	9460      	ld.w      	r3, (r4, 0x0)
  30:	934c      	ld.w      	r2, (r3, 0x30)
  32:	ec420002 	ori      	r2, r2, 2
  36:	b34c      	st.w      	r2, (r3, 0x30)
  38:	9351      	ld.w      	r2, (r3, 0x44)
  3a:	ec420400 	ori      	r2, r2, 1024
  3e:	b351      	st.w      	r2, (r3, 0x44)
  40:	9351      	ld.w      	r2, (r3, 0x44)
  42:	ec421000 	ori      	r2, r2, 4096
  46:	b351      	st.w      	r2, (r3, 0x44)
  48:	1491      	pop      	r4, r15
  4a:	0000      	.short	0x0000
  4c:	00000000 	.long	0x00000000

Disassembly of section .text.lhw_get_cca_remain:

00000000 <lhw_get_cca_remain>:
   0:	1063      	lrw      	r3, 0x0	// c <lhw_get_cca_remain+0xc>
   2:	9360      	ld.w      	r3, (r3, 0x0)
   4:	9308      	ld.w      	r0, (r3, 0x20)
   6:	e40027ff 	andi      	r0, r0, 2047
   a:	783c      	jmp      	r15
   c:	0000      	.short	0x0000
	...

Disassembly of section .text.lhw_start_cca:

00000000 <lhw_start_cca>:
   0:	380f      	cmphsi      	r0, 16
   2:	106b      	lrw      	r3, 0x0	// 2c <lhw_start_cca+0x2c>
   4:	d9832000 	ld.w      	r12, (r3, 0x0)
   8:	6cc3      	mov      	r3, r0
   a:	0c02      	bf      	0xe	// e <lhw_start_cca+0xe>
   c:	330f      	movi      	r3, 15
   e:	eb0107ff 	cmphsi      	r1, 2048
  12:	74cc      	zextb      	r3, r3
  14:	436c      	lsli      	r3, r3, 12
  16:	6c87      	mov      	r2, r1
  18:	0c03      	bf      	0x1e	// 1e <lhw_start_cca+0x1e>
  1a:	ea0207ff 	movi      	r2, 2047
  1e:	7489      	zexth      	r2, r2
  20:	60c8      	addu      	r3, r2
  22:	e46307ff 	addi      	r3, r3, 2048
  26:	dc6c2008 	st.w      	r3, (r12, 0x20)
  2a:	783c      	jmp      	r15
  2c:	0000      	.short	0x0000
	...

Disassembly of section .text.lhw_start_tx:

00000000 <lhw_start_tx>:
   0:	106c      	lrw      	r3, 0x0	// 30 <lhw_start_tx+0x30>
   2:	3100      	movi      	r1, 0
   4:	9360      	ld.w      	r3, (r3, 0x0)
   6:	29ff      	subi      	r1, 256
   8:	9347      	ld.w      	r2, (r3, 0x1c)
   a:	6884      	and      	r2, r1
   c:	b347      	st.w      	r2, (r3, 0x1c)
   e:	9347      	ld.w      	r2, (r3, 0x1c)
  10:	6c08      	or      	r0, r2
  12:	b307      	st.w      	r0, (r3, 0x1c)
  14:	934c      	ld.w      	r2, (r3, 0x30)
  16:	3a84      	bclri      	r2, 4
  18:	3a85      	bclri      	r2, 5
  1a:	b34c      	st.w      	r2, (r3, 0x30)
  1c:	934c      	ld.w      	r2, (r3, 0x30)
  1e:	ec420010 	ori      	r2, r2, 16
  22:	b34c      	st.w      	r2, (r3, 0x30)
  24:	934c      	ld.w      	r2, (r3, 0x30)
  26:	ec420001 	ori      	r2, r2, 1
  2a:	b34c      	st.w      	r2, (r3, 0x30)
  2c:	783c      	jmp      	r15
  2e:	0000      	.short	0x0000
  30:	0000      	.short	0x0000
	...

Disassembly of section .text.lhw_irq_init:

00000000 <lhw_irq_init>:
   0:	1078      	lrw      	r3, 0x0	// 60 <lhw_irq_init+0x60>
   2:	3200      	movi      	r2, 0
   4:	9360      	ld.w      	r3, (r3, 0x0)
   6:	b351      	st.w      	r2, (r3, 0x44)
   8:	2a00      	subi      	r2, 1
   a:	b352      	st.w      	r2, (r3, 0x48)
   c:	9351      	ld.w      	r2, (r3, 0x44)
   e:	ec420080 	ori      	r2, r2, 128
  12:	b351      	st.w      	r2, (r3, 0x44)
  14:	9351      	ld.w      	r2, (r3, 0x44)
  16:	ec420020 	ori      	r2, r2, 32
  1a:	b351      	st.w      	r2, (r3, 0x44)
  1c:	9351      	ld.w      	r2, (r3, 0x44)
  1e:	ec420004 	ori      	r2, r2, 4
  22:	b351      	st.w      	r2, (r3, 0x44)
  24:	9351      	ld.w      	r2, (r3, 0x44)
  26:	ec420400 	ori      	r2, r2, 1024
  2a:	b351      	st.w      	r2, (r3, 0x44)
  2c:	9351      	ld.w      	r2, (r3, 0x44)
  2e:	ec428000 	ori      	r2, r2, 32768
  32:	b351      	st.w      	r2, (r3, 0x44)
  34:	9351      	ld.w      	r2, (r3, 0x44)
  36:	ec422000 	ori      	r2, r2, 8192
  3a:	b351      	st.w      	r2, (r3, 0x44)
  3c:	9351      	ld.w      	r2, (r3, 0x44)
  3e:	ec424000 	ori      	r2, r2, 16384
  42:	b351      	st.w      	r2, (r3, 0x44)
  44:	9351      	ld.w      	r2, (r3, 0x44)
  46:	3ab2      	bseti      	r2, 18
  48:	b351      	st.w      	r2, (r3, 0x44)
  4a:	ea0261a8 	movi      	r2, 25000
  4e:	b357      	st.w      	r2, (r3, 0x5c)
  50:	9351      	ld.w      	r2, (r3, 0x44)
  52:	3ab4      	bseti      	r2, 20
  54:	b351      	st.w      	r2, (r3, 0x44)
  56:	9351      	ld.w      	r2, (r3, 0x44)
  58:	ec421000 	ori      	r2, r2, 4096
  5c:	b351      	st.w      	r2, (r3, 0x44)
  5e:	783c      	jmp      	r15
  60:	00000000 	.long	0x00000000

Disassembly of section .text.lhw_cfg_sifs:

00000000 <lhw_cfg_sifs>:
   0:	1069      	lrw      	r3, 0x0	// 24 <lhw_cfg_sifs+0x24>
   2:	4128      	lsli      	r1, r1, 8
   4:	9360      	ld.w      	r3, (r3, 0x0)
   6:	6c40      	or      	r1, r0
   8:	d9832007 	ld.w      	r12, (r3, 0x1c)
   c:	ea0c0000 	movi      	r12, 0
  10:	dd832007 	st.w      	r12, (r3, 0x1c)
  14:	4258      	lsli      	r2, r2, 24
  16:	d9832007 	ld.w      	r12, (r3, 0x1c)
  1a:	6c48      	or      	r1, r2
  1c:	6c70      	or      	r1, r12
  1e:	b327      	st.w      	r1, (r3, 0x1c)
  20:	783c      	jmp      	r15
  22:	0000      	.short	0x0000
  24:	00000000 	.long	0x00000000

Disassembly of section .text.lhw_cfg_tx_delay_before:

00000000 <lhw_cfg_tx_delay_before>:
   0:	100d      	lrw      	r0, 0x0	// 34 <lhw_cfg_tx_delay_before+0x34>
   2:	ea0d7fff 	movi      	r13, 32767
   6:	6f76      	nor      	r13, r13
   8:	9000      	ld.w      	r0, (r0, 0x0)
   a:	e442201f 	andi      	r2, r2, 31
   e:	d980201e 	ld.w      	r12, (r0, 0x78)
  12:	6b34      	and      	r12, r13
  14:	e463201f 	andi      	r3, r3, 31
  18:	4245      	lsli      	r2, r2, 5
  1a:	e421201f 	andi      	r1, r1, 31
  1e:	dd80201e 	st.w      	r12, (r0, 0x78)
  22:	6c8c      	or      	r2, r3
  24:	412a      	lsli      	r1, r1, 10
  26:	d980201e 	ld.w      	r12, (r0, 0x78)
  2a:	6c84      	or      	r2, r1
  2c:	6cb0      	or      	r2, r12
  2e:	b05e      	st.w      	r2, (r0, 0x78)
  30:	783c      	jmp      	r15
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000

Disassembly of section .text.lhw_cfg_tx_delay_after:

00000000 <lhw_cfg_tx_delay_after>:
   0:	14c1      	push      	r4
   2:	ea8c0010 	lrw      	r12, 0x0	// 40 <lhw_cfg_tx_delay_after+0x40>
   6:	e442203f 	andi      	r2, r2, 63
   a:	d98c2000 	ld.w      	r12, (r12, 0x0)
   e:	108e      	lrw      	r4, 0xc0c0c0c0	// 44 <lhw_cfg_tx_delay_after+0x44>
  10:	d9ac2021 	ld.w      	r13, (r12, 0x84)
  14:	e463203f 	andi      	r3, r3, 63
  18:	4248      	lsli      	r2, r2, 8
  1a:	e421203f 	andi      	r1, r1, 63
  1e:	6b50      	and      	r13, r4
  20:	6c8c      	or      	r2, r3
  22:	4130      	lsli      	r1, r1, 16
  24:	e400203f 	andi      	r0, r0, 63
  28:	ddac2021 	st.w      	r13, (r12, 0x84)
  2c:	6c84      	or      	r2, r1
  2e:	4018      	lsli      	r0, r0, 24
  30:	d9ac2021 	ld.w      	r13, (r12, 0x84)
  34:	6c80      	or      	r2, r0
  36:	6cb4      	or      	r2, r13
  38:	dc4c2021 	st.w      	r2, (r12, 0x84)
  3c:	1481      	pop      	r4
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000
  42:	0000      	.short	0x0000
  44:	c0c0c0c0 	.long	0xc0c0c0c0

Disassembly of section .text.lhw_cfg_tx_dalay_dac_rf:

00000000 <lhw_cfg_tx_dalay_dac_rf>:
   0:	106d      	lrw      	r3, 0x0	// 34 <lhw_cfg_tx_dalay_dac_rf+0x34>
   2:	ea0d0f3f 	movi      	r13, 3903
   6:	6f76      	nor      	r13, r13
   8:	9360      	ld.w      	r3, (r3, 0x0)
   a:	e4422003 	andi      	r2, r2, 3
   e:	d9832023 	ld.w      	r12, (r3, 0x8c)
  12:	6b34      	and      	r12, r13
  14:	e421200f 	andi      	r1, r1, 15
  18:	4244      	lsli      	r2, r2, 4
  1a:	e400200f 	andi      	r0, r0, 15
  1e:	dd832023 	st.w      	r12, (r3, 0x8c)
  22:	6c84      	or      	r2, r1
  24:	4008      	lsli      	r0, r0, 8
  26:	d9832023 	ld.w      	r12, (r3, 0x8c)
  2a:	6c80      	or      	r2, r0
  2c:	6cb0      	or      	r2, r12
  2e:	dc432023 	st.w      	r2, (r3, 0x8c)
  32:	783c      	jmp      	r15
  34:	00000000 	.long	0x00000000

Disassembly of section .text.lhw_cfg_phy_rx_delay:

00000000 <lhw_cfg_phy_rx_delay>:
   0:	1068      	lrw      	r3, 0x0	// 20 <lhw_cfg_phy_rx_delay+0x20>
   2:	401c      	lsli      	r0, r0, 28
   4:	9360      	ld.w      	r3, (r3, 0x0)
   6:	d8432028 	ld.w      	r2, (r3, 0xa0)
   a:	c4025762 	zext      	r2, r2, 27, 0
   e:	dc432028 	st.w      	r2, (r3, 0xa0)
  12:	d8432028 	ld.w      	r2, (r3, 0xa0)
  16:	6c08      	or      	r0, r2
  18:	dc032028 	st.w      	r0, (r3, 0xa0)
  1c:	783c      	jmp      	r15
  1e:	0000      	.short	0x0000
  20:	0000      	.short	0x0000
	...

Disassembly of section .text.lhw_cfg_dma_list_cnt:

00000000 <lhw_cfg_dma_list_cnt>:
   0:	1069      	lrw      	r3, 0x0	// 24 <lhw_cfg_dma_list_cnt+0x24>
   2:	3100      	movi      	r1, 0
   4:	9360      	ld.w      	r3, (r3, 0x0)
   6:	297f      	subi      	r1, 128
   8:	d8432040 	ld.w      	r2, (r3, 0x100)
   c:	6884      	and      	r2, r1
   e:	dc432040 	st.w      	r2, (r3, 0x100)
  12:	d8432040 	ld.w      	r2, (r3, 0x100)
  16:	e400207f 	andi      	r0, r0, 127
  1a:	6c08      	or      	r0, r2
  1c:	dc032040 	st.w      	r0, (r3, 0x100)
  20:	783c      	jmp      	r15
  22:	0000      	.short	0x0000
  24:	00000000 	.long	0x00000000

Disassembly of section .text.lhw_cfg_tx_sub_frm:

00000000 <lhw_cfg_tx_sub_frm>:
   0:	1066      	lrw      	r3, 0x0	// 18 <lhw_cfg_tx_sub_frm+0x18>
   2:	e5800023 	addi      	r12, r0, 36
   6:	9360      	ld.w      	r3, (r3, 0x0)
   8:	4003      	lsli      	r0, r0, 3
   a:	d5830901 	str.w      	r1, (r3, r12 << 3)
   e:	60c0      	addu      	r3, r0
  10:	dc432049 	st.w      	r2, (r3, 0x124)
  14:	783c      	jmp      	r15
  16:	0000      	.short	0x0000
  18:	0000      	.short	0x0000
	...

Disassembly of section .text.lhw_cfg_tx_delay_pa:

00000000 <lhw_cfg_tx_delay_pa>:
   0:	106a      	lrw      	r3, 0x0	// 28 <lhw_cfg_tx_delay_pa+0x28>
   2:	c7405021 	bmaski      	r1, 27
   6:	c6214901 	rotli      	r1, r1, 17
   a:	9360      	ld.w      	r3, (r3, 0x0)
   c:	e400201f 	andi      	r0, r0, 31
  10:	d8432023 	ld.w      	r2, (r3, 0x8c)
  14:	6884      	and      	r2, r1
  16:	dc432023 	st.w      	r2, (r3, 0x8c)
  1a:	d8432023 	ld.w      	r2, (r3, 0x8c)
  1e:	400c      	lsli      	r0, r0, 12
  20:	6c08      	or      	r0, r2
  22:	dc032023 	st.w      	r0, (r3, 0x8c)
  26:	783c      	jmp      	r15
  28:	0000      	.short	0x0000
	...

Disassembly of section .text.lhw_get_rx_frm_type:

00000000 <lhw_get_rx_frm_type>:
   0:	1069      	lrw      	r3, 0x0	// 24 <lhw_get_rx_frm_type+0x24>
   2:	9360      	ld.w      	r3, (r3, 0x0)
   4:	d803202d 	ld.w      	r0, (r3, 0xb4)
   8:	e4002100 	andi      	r0, r0, 256
   c:	e900000a 	bez      	r0, 0x20	// 20 <lhw_get_rx_frm_type+0x20>
  10:	d863202d 	ld.w      	r3, (r3, 0xb4)
  14:	e4632200 	andi      	r3, r3, 512
  18:	3b40      	cmpnei      	r3, 0
  1a:	c4000500 	mvc      	r0
  1e:	2000      	addi      	r0, 1
  20:	783c      	jmp      	r15
  22:	0000      	.short	0x0000
  24:	00000000 	.long	0x00000000

Disassembly of section .text.lhw_get_rx_ndp_ind:

00000000 <lhw_get_rx_ndp_ind>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <lhw_get_rx_ndp_ind>
   6:	3842      	cmpnei      	r0, 2
   8:	0c0f      	bf      	0x26	// 26 <lhw_get_rx_ndp_ind+0x26>
   a:	1069      	lrw      	r3, 0x0	// 2c <lhw_get_rx_ndp_ind+0x2c>
   c:	9360      	ld.w      	r3, (r3, 0x0)
   e:	e9200007 	bnez      	r0, 0x1c	// 1c <lhw_get_rx_ndp_ind+0x1c>
  12:	d8032029 	ld.w      	r0, (r3, 0xa4)
  16:	c7205720 	zext      	r0, r0, 25, 25
  1a:	1490      	pop      	r15
  1c:	d803202a 	ld.w      	r0, (r3, 0xa8)
  20:	c4a054a0 	zext      	r0, r0, 5, 5
  24:	07fb      	br      	0x1a	// 1a <lhw_get_rx_ndp_ind+0x1a>
  26:	3000      	movi      	r0, 0
  28:	07f9      	br      	0x1a	// 1a <lhw_get_rx_ndp_ind+0x1a>
  2a:	0000      	.short	0x0000
  2c:	0000      	.short	0x0000
	...

Disassembly of section .text.lhw_get_ndp2m:

00000000 <lhw_get_ndp2m>:
   0:	1067      	lrw      	r3, 0x0	// 1c <lhw_get_ndp2m+0x1c>
   2:	3200      	movi      	r2, 0
   4:	9360      	ld.w      	r3, (r3, 0x0)
   6:	d823202a 	ld.w      	r1, (r3, 0xa8)
   a:	d9832029 	ld.w      	r12, (r3, 0xa4)
   e:	6c33      	mov      	r0, r12
  10:	6cc7      	mov      	r3, r1
  12:	6c4b      	mov      	r1, r2
  14:	6c08      	or      	r0, r2
  16:	6c4c      	or      	r1, r3
  18:	783c      	jmp      	r15
  1a:	0000      	.short	0x0000
  1c:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_rf_sw_ctrl:

00000000 <lmac_rf_sw_ctrl>:
   0:	1064      	lrw      	r3, 0x0	// 10 <lmac_rf_sw_ctrl+0x10>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	9270      	ld.w      	r3, (r2, 0x40)
   6:	ec630200 	ori      	r3, r3, 512
   a:	b270      	st.w      	r3, (r2, 0x40)
   c:	783c      	jmp      	r15
   e:	0000      	.short	0x0000
  10:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_rf_hw_ctrl:

00000000 <lmac_rf_hw_ctrl>:
   0:	1063      	lrw      	r3, 0x0	// c <lmac_rf_hw_ctrl+0xc>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	9270      	ld.w      	r3, (r2, 0x40)
   6:	3b89      	bclri      	r3, 9
   8:	b270      	st.w      	r3, (r2, 0x40)
   a:	783c      	jmp      	r15
   c:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_cfg_rf_en:

00000000 <lmac_cfg_rf_en>:
   0:	1066      	lrw      	r3, 0x0	// 18 <lmac_cfg_rf_en+0x18>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	9270      	ld.w      	r3, (r2, 0x40)
   6:	e9000006 	bez      	r0, 0x12	// 12 <lmac_cfg_rf_en+0x12>
   a:	ec630100 	ori      	r3, r3, 256
   e:	b270      	st.w      	r3, (r2, 0x40)
  10:	783c      	jmp      	r15
  12:	3b88      	bclri      	r3, 8
  14:	07fd      	br      	0xe	// e <lmac_cfg_rf_en+0xe>
  16:	0000      	.short	0x0000
  18:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_cfg_tx_en:

00000000 <lmac_cfg_tx_en>:
   0:	1066      	lrw      	r3, 0x0	// 18 <lmac_cfg_tx_en+0x18>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	9270      	ld.w      	r3, (r2, 0x40)
   6:	e9000006 	bez      	r0, 0x12	// 12 <lmac_cfg_tx_en+0x12>
   a:	ec630400 	ori      	r3, r3, 1024
   e:	b270      	st.w      	r3, (r2, 0x40)
  10:	783c      	jmp      	r15
  12:	3b8a      	bclri      	r3, 10
  14:	07fd      	br      	0xe	// e <lmac_cfg_tx_en+0xe>
  16:	0000      	.short	0x0000
  18:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_cfg_rx_en:

00000000 <lmac_cfg_rx_en>:
   0:	1066      	lrw      	r3, 0x0	// 18 <lmac_cfg_rx_en+0x18>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	9270      	ld.w      	r3, (r2, 0x40)
   6:	e9000006 	bez      	r0, 0x12	// 12 <lmac_cfg_rx_en+0x12>
   a:	ec630800 	ori      	r3, r3, 2048
   e:	b270      	st.w      	r3, (r2, 0x40)
  10:	783c      	jmp      	r15
  12:	3b8b      	bclri      	r3, 11
  14:	07fd      	br      	0xe	// e <lmac_cfg_rx_en+0xe>
  16:	0000      	.short	0x0000
  18:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_cfg_pa_en:

00000000 <lmac_cfg_pa_en>:
   0:	1065      	lrw      	r3, 0x0	// 14 <lmac_cfg_pa_en+0x14>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	9270      	ld.w      	r3, (r2, 0x40)
   6:	e9000005 	bez      	r0, 0x10	// 10 <lmac_cfg_pa_en+0x10>
   a:	3bb0      	bseti      	r3, 16
   c:	b270      	st.w      	r3, (r2, 0x40)
   e:	783c      	jmp      	r15
  10:	3b90      	bclri      	r3, 16
  12:	07fd      	br      	0xc	// c <lmac_cfg_pa_en+0xc>
  14:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_cfg_dac_en:

00000000 <lmac_cfg_dac_en>:
   0:	1065      	lrw      	r3, 0x0	// 14 <lmac_cfg_dac_en+0x14>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	9270      	ld.w      	r3, (r2, 0x40)
   6:	e9000005 	bez      	r0, 0x10	// 10 <lmac_cfg_dac_en+0x10>
   a:	3bb1      	bseti      	r3, 17
   c:	b270      	st.w      	r3, (r2, 0x40)
   e:	783c      	jmp      	r15
  10:	3b91      	bclri      	r3, 17
  12:	07fd      	br      	0xc	// c <lmac_cfg_dac_en+0xc>
  14:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_cfg_end_to_limit:

00000000 <lmac_cfg_end_to_limit>:
   0:	1062      	lrw      	r3, 0x0	// 8 <lmac_cfg_end_to_limit+0x8>
   2:	9360      	ld.w      	r3, (r3, 0x0)
   4:	b317      	st.w      	r0, (r3, 0x5c)
   6:	783c      	jmp      	r15
   8:	0000      	.short	0x0000
	...

Disassembly of section .text.lhw_set_bo_bypass:

00000000 <lhw_set_bo_bypass>:
   0:	1066      	lrw      	r3, 0x0	// 18 <lhw_set_bo_bypass+0x18>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	926c      	ld.w      	r3, (r2, 0x30)
   6:	e9000006 	bez      	r0, 0x12	// 12 <lhw_set_bo_bypass+0x12>
   a:	ec630100 	ori      	r3, r3, 256
   e:	b26c      	st.w      	r3, (r2, 0x30)
  10:	783c      	jmp      	r15
  12:	3b88      	bclri      	r3, 8
  14:	07fd      	br      	0xe	// e <lhw_set_bo_bypass+0xe>
  16:	0000      	.short	0x0000
  18:	0000      	.short	0x0000
	...

Disassembly of section .text.lhw_set_tsf:

00000000 <lhw_set_tsf>:
   0:	1063      	lrw      	r3, 0x0	// c <lhw_set_tsf+0xc>
   2:	9360      	ld.w      	r3, (r3, 0x0)
   4:	b304      	st.w      	r0, (r3, 0x10)
   6:	b325      	st.w      	r1, (r3, 0x14)
   8:	783c      	jmp      	r15
   a:	0000      	.short	0x0000
   c:	0000      	.short	0x0000
	...

Disassembly of section .text.lhw_start_cca_observ:

00000000 <lhw_start_cca_observ>:
   0:	1067      	lrw      	r3, 0x0	// 1c <lhw_start_cca_observ+0x1c>
   2:	4001      	lsli      	r0, r0, 1
   4:	9360      	ld.w      	r3, (r3, 0x0)
   6:	e400200e 	andi      	r0, r0, 14
   a:	dc03218c 	st.w      	r0, (r3, 0x630)
   e:	d843218c 	ld.w      	r2, (r3, 0x630)
  12:	ec420001 	ori      	r2, r2, 1
  16:	dc43218c 	st.w      	r2, (r3, 0x630)
  1a:	783c      	jmp      	r15
  1c:	0000      	.short	0x0000
	...

Disassembly of section .text.lhw_get_cca_observ:

00000000 <lhw_get_cca_observ>:
   0:	1071      	lrw      	r3, 0x0	// 44 <lhw_get_cca_observ+0x44>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	d862218c 	ld.w      	r3, (r2, 0x630)
   8:	e4632010 	andi      	r3, r3, 16
   c:	e9030013 	bez      	r3, 0x32	// 32 <lhw_get_cca_observ+0x32>
  10:	d862218d 	ld.w      	r3, (r2, 0x634)
  14:	b060      	st.w      	r3, (r0, 0x0)
  16:	d862218e 	ld.w      	r3, (r2, 0x638)
  1a:	b061      	st.w      	r3, (r0, 0x4)
  1c:	d862218f 	ld.w      	r3, (r2, 0x63c)
  20:	b062      	st.w      	r3, (r0, 0x8)
  22:	d8622190 	ld.w      	r3, (r2, 0x640)
  26:	b063      	st.w      	r3, (r0, 0xc)
  28:	d8622191 	ld.w      	r3, (r2, 0x644)
  2c:	b064      	st.w      	r3, (r0, 0x10)
  2e:	3000      	movi      	r0, 0
  30:	783c      	jmp      	r15
  32:	b060      	st.w      	r3, (r0, 0x0)
  34:	b061      	st.w      	r3, (r0, 0x4)
  36:	b062      	st.w      	r3, (r0, 0x8)
  38:	b063      	st.w      	r3, (r0, 0xc)
  3a:	b064      	st.w      	r3, (r0, 0x10)
  3c:	3000      	movi      	r0, 0
  3e:	2800      	subi      	r0, 1
  40:	07f8      	br      	0x30	// 30 <lhw_get_cca_observ+0x30>
  42:	0000      	.short	0x0000
  44:	00000000 	.long	0x00000000
