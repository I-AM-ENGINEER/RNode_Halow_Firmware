
disasm/liblmac/obj/mars_lmac_rx.o:     file format elf32-csky-little


Disassembly of section .text.__get_unaligned_le32:

00000000 <__get_unaligned_le32>:
   0:	8061      	ld.b      	r3, (r0, 0x1)
   2:	8040      	ld.b      	r2, (r0, 0x0)
   4:	4368      	lsli      	r3, r3, 8
   6:	6c8c      	or      	r2, r3
   8:	8062      	ld.b      	r3, (r0, 0x2)
   a:	4370      	lsli      	r3, r3, 16
   c:	8003      	ld.b      	r0, (r0, 0x3)
   e:	6cc8      	or      	r3, r2
  10:	4018      	lsli      	r0, r0, 24
  12:	6c0c      	or      	r0, r3
  14:	783c      	jmp      	r15

Disassembly of section .text.ndp_paging_rx_hdl:

00000000 <ndp_paging_rx_hdl>:
   0:	1063      	lrw      	r3, 0x0	// c <ndp_paging_rx_hdl+0xc>
   2:	3000      	movi      	r0, 0
   4:	dc032265 	st.w      	r0, (r3, 0x994)
   8:	783c      	jmp      	r15
   a:	0000      	.short	0x0000
   c:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_rx_pv0_ctrl:

00000000 <lmac_rx_pv0_ctrl>:
   0:	14d0      	push      	r15
   2:	8061      	ld.b      	r3, (r0, 0x1)
   4:	8040      	ld.b      	r2, (r0, 0x0)
   6:	4368      	lsli      	r3, r3, 8
   8:	6cc8      	or      	r3, r2
   a:	104f      	lrw      	r2, 0x0	// 44 <lmac_rx_pv0_ctrl+0x44>
   c:	c4835563 	zext      	r3, r3, 11, 4
  10:	d842009b 	ld.b      	r2, (r2, 0x9b)
  14:	e442207f 	andi      	r2, r2, 127
  18:	3a41      	cmpnei      	r2, 1
  1a:	e583200f 	andi      	r12, r3, 15
  1e:	080f      	bt      	0x3c	// 3c <lmac_rx_pv0_ctrl+0x3c>
  20:	e463200b 	andi      	r3, r3, 11
  24:	3b43      	cmpnei      	r3, 3
  26:	0c06      	bf      	0x32	// 32 <lmac_rx_pv0_ctrl+0x32>
  28:	e46c1008 	subi      	r3, r12, 9
  2c:	74cc      	zextb      	r3, r3
  2e:	3b06      	cmphsi      	r3, 7
  30:	0806      	bt      	0x3c	// 3c <lmac_rx_pv0_ctrl+0x3c>
  32:	1066      	lrw      	r3, 0x0	// 48 <lmac_rx_pv0_ctrl+0x48>
  34:	d1830883 	ldr.w      	r3, (r3, r12 << 2)
  38:	7bcd      	jsr      	r3
  3a:	1490      	pop      	r15
  3c:	3000      	movi      	r0, 0
  3e:	2800      	subi      	r0, 1
  40:	07fd      	br      	0x3a	// 3a <lmac_rx_pv0_ctrl+0x3a>
	...

Disassembly of section .text.lmac_rx_pv1_data2:

00000000 <lmac_rx_pv1_data2>:
   0:	3000      	movi      	r0, 0
   2:	2800      	subi      	r0, 1
   4:	783c      	jmp      	r15

Disassembly of section .text.ndp_prob_req_rx_hdl:

00000000 <ndp_prob_req_rx_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	e4602008 	andi      	r3, r0, 8
   6:	e922004e 	bnez      	r2, 0xa2	// a2 <ndp_prob_req_rx_hdl+0xa2>
   a:	e923004a 	bnez      	r3, 0x9e	// 9e <ndp_prob_req_rx_hdl+0x9e>
   e:	c4805663 	zext      	r3, r0, 19, 4
  12:	c6805681 	zext      	r1, r0, 20, 20
  16:	3941      	cmpnei      	r1, 1
  18:	11ad      	lrw      	r5, 0x0	// cc <ndp_prob_req_rx_hdl+0xcc>
  1a:	084e      	bt      	0xb6	// b6 <ndp_prob_req_rx_hdl+0xb6>
  1c:	d8452154 	ld.w      	r2, (r5, 0x550)
  20:	648e      	cmpne      	r3, r2
  22:	084a      	bt      	0xb6	// b6 <ndp_prob_req_rx_hdl+0xb6>
  24:	d805202f 	ld.w      	r0, (r5, 0xbc)
  28:	3842      	cmpnei      	r0, 2
  2a:	0846      	bt      	0xb6	// b6 <ndp_prob_req_rx_hdl+0xb6>
  2c:	1189      	lrw      	r4, 0x0	// d0 <ndp_prob_req_rx_hdl+0xd0>
  2e:	3303      	movi      	r3, 3
  30:	d8440147 	ld.b      	r2, (r4, 0x147)
  34:	dc640146 	st.b      	r3, (r4, 0x146)
  38:	d86400c0 	ld.b      	r3, (r4, 0xc0)
  3c:	c4435c60 	ins      	r2, r3, 3, 0
  40:	dc440147 	st.b      	r2, (r4, 0x147)
  44:	e4432030 	andi      	r2, r3, 48
  48:	eb420030 	cmpnei      	r2, 48
  4c:	0c05      	bf      	0x56	// 56 <ndp_prob_req_rx_hdl+0x56>
  4e:	c48354a1 	zext      	r1, r3, 5, 4
  52:	c4204021 	lsl      	r1, r0, r1
  56:	d8640147 	ld.b      	r3, (r4, 0x147)
  5a:	c4615c64 	ins      	r3, r1, 7, 4
  5e:	dc640147 	st.b      	r3, (r4, 0x147)
  62:	e0000000 	bsr      	0x0	// 0 <ah_wphy_avg_evm_get>
  66:	dc040148 	st.b      	r0, (r4, 0x148)
  6a:	e0000000 	bsr      	0x0	// 0 <lmac_get_avg_power>
  6e:	d86503e0 	ld.b      	r3, (r5, 0x3e0)
  72:	600c      	addu      	r0, r3
  74:	d86520cf 	ld.w      	r3, (r5, 0x33c)
  78:	3264      	movi      	r2, 100
  7a:	c50357e3 	zext      	r3, r3, 31, 8
  7e:	c4438043 	divs      	r3, r3, r2
  82:	dc040149 	st.b      	r0, (r4, 0x149)
  86:	dc6410a5 	st.h      	r3, (r4, 0x14a)
  8a:	e0000000 	bsr      	0x0	// 0 <ah_wphy_rx_freq_offset_get>
  8e:	dc0410a6 	st.h      	r0, (r4, 0x14c)
  92:	e0000000 	bsr      	0x0	// 0 <lmac_send_probe_resp>
  96:	3000      	movi      	r0, 0
  98:	dc052265 	st.w      	r0, (r5, 0x994)
  9c:	1492      	pop      	r4-r5, r15
  9e:	6ccb      	mov      	r3, r2
  a0:	07b9      	br      	0x12	// 12 <ndp_prob_req_rx_hdl+0x12>
  a2:	e9230008 	bnez      	r3, 0xb2	// b2 <ndp_prob_req_rx_hdl+0xb2>
  a6:	4804      	lsri      	r0, r0, 4
  a8:	417c      	lsli      	r3, r1, 28
  aa:	6cc0      	or      	r3, r0
  ac:	c4815481 	zext      	r1, r1, 4, 4
  b0:	07b3      	br      	0x16	// 16 <ndp_prob_req_rx_hdl+0x16>
  b2:	3300      	movi      	r3, 0
  b4:	07fc      	br      	0xac	// ac <ndp_prob_req_rx_hdl+0xac>
  b6:	d845202f 	ld.w      	r2, (r5, 0xbc)
  ba:	3a42      	cmpnei      	r2, 2
  bc:	0bed      	bt      	0x96	// 96 <ndp_prob_req_rx_hdl+0x96>
  be:	d8452154 	ld.w      	r2, (r5, 0x550)
  c2:	6c4f      	mov      	r1, r3
  c4:	1004      	lrw      	r0, 0x0	// d4 <ndp_prob_req_rx_hdl+0xd4>
  c6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ca:	07e6      	br      	0x96	// 96 <ah_lmac+0x96>
	...

Disassembly of section .text.ndp_cts_rx_hdl:

00000000 <ndp_cts_rx_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	1421      	subi      	r14, r14, 4
   4:	3303      	movi      	r3, 3
   6:	dc6e0000 	st.b      	r3, (r14, 0x0)
   a:	3300      	movi      	r3, 0
   c:	dc6e0001 	st.b      	r3, (r14, 0x1)
  10:	3a41      	cmpnei      	r2, 1
  12:	3301      	movi      	r3, 1
  14:	dc6e0002 	st.b      	r3, (r14, 0x2)
  18:	3302      	movi      	r3, 2
  1a:	dc6e0003 	st.b      	r3, (r14, 0x3)
  1e:	0854      	bt      	0xc6	// c6 <ndp_cts_rx_hdl+0xc6>
  20:	e4a12001 	andi      	r5, r1, 1
  24:	c5c05783 	zext      	r3, r0, 28, 14
  28:	c4805482 	zext      	r2, r0, 4, 4
  2c:	c4a055ac 	zext      	r12, r0, 13, 5
  30:	45a2      	lsli      	r5, r5, 2
  32:	481e      	lsri      	r0, r0, 30
  34:	6d40      	or      	r5, r0
  36:	1133      	lrw      	r1, 0x0	// 100 <ndp_cts_rx_hdl+0x100>
  38:	1193      	lrw      	r4, 0x0	// 104 <ndp_cts_rx_hdl+0x104>
  3a:	dc611049 	st.h      	r3, (r1, 0x92)
  3e:	d864202f 	ld.w      	r3, (r4, 0xbc)
  42:	3b42      	cmpnei      	r3, 2
  44:	084b      	bt      	0xda	// da <ndp_cts_rx_hdl+0xda>
  46:	d8641334 	ld.h      	r3, (r4, 0x668)
  4a:	c4635563 	zext      	r3, r3, 11, 3
  4e:	e9220055 	bnez      	r2, 0xf8	// f8 <ndp_cts_rx_hdl+0xf8>
  52:	670e      	cmpne      	r3, r12
  54:	0852      	bt      	0xf8	// f8 <ndp_cts_rx_hdl+0xf8>
  56:	d8642266 	ld.w      	r3, (r4, 0x998)
  5a:	3b42      	cmpnei      	r3, 2
  5c:	084e      	bt      	0xf8	// f8 <ndp_cts_rx_hdl+0xf8>
  5e:	d8640380 	ld.b      	r3, (r4, 0x380)
  62:	d0ae0021 	ldr.b      	r1, (r14, r5 << 0)
  66:	c4615c20 	ins      	r3, r1, 1, 0
  6a:	d8242294 	ld.w      	r1, (r4, 0xa50)
  6e:	dc640380 	st.b      	r3, (r4, 0x380)
  72:	74cc      	zextb      	r3, r3
  74:	e901003a 	bez      	r1, 0xe8	// e8 <ndp_cts_rx_hdl+0xe8>
  78:	d84100ad 	ld.b      	r2, (r1, 0xad)
  7c:	c48254e2 	zext      	r2, r2, 7, 4
  80:	c4625c62 	ins      	r3, r2, 5, 2
  84:	dc640380 	st.b      	r3, (r4, 0x380)
  88:	e0000000 	bsr      	0x0	// 0 <lmac_update_frm_tx_vec>
  8c:	3301      	movi      	r3, 1
  8e:	d8440380 	ld.b      	r2, (r4, 0x380)
  92:	c4a34025 	lsl      	r5, r3, r5
  96:	dc642265 	st.w      	r3, (r4, 0x994)
  9a:	d86421f6 	ld.w      	r3, (r4, 0x7d8)
  9e:	c44254a1 	zext      	r1, r2, 5, 2
  a2:	614c      	addu      	r5, r3
  a4:	d84421f5 	ld.w      	r2, (r4, 0x7d4)
  a8:	d86421f7 	ld.w      	r3, (r4, 0x7dc)
  ac:	6084      	addu      	r2, r1
  ae:	2300      	addi      	r3, 1
  b0:	dc4421f5 	st.w      	r2, (r4, 0x7d4)
  b4:	dca421f6 	st.w      	r5, (r4, 0x7d8)
  b8:	dc6421f7 	st.w      	r3, (r4, 0x7dc)
  bc:	3000      	movi      	r0, 0
  be:	dc042266 	st.w      	r0, (r4, 0x998)
  c2:	1401      	addi      	r14, r14, 4
  c4:	1492      	pop      	r4-r5, r15
  c6:	3228      	movi      	r2, 40
  c8:	c5c056e3 	zext      	r3, r0, 23, 14
  cc:	7cc8      	mult      	r3, r2
  ce:	c4a055ac 	zext      	r12, r0, 13, 5
  d2:	c4805482 	zext      	r2, r0, 4, 4
  d6:	3500      	movi      	r5, 0
  d8:	07af      	br      	0x36	// 36 <ndp_cts_rx_hdl+0x36>
  da:	3b41      	cmpnei      	r3, 1
  dc:	080e      	bt      	0xf8	// f8 <ndp_cts_rx_hdl+0xf8>
  de:	d864119b 	ld.h      	r3, (r4, 0x336)
  e2:	c4e355e3 	zext      	r3, r3, 15, 7
  e6:	07b4      	br      	0x4e	// 4e <ndp_cts_rx_hdl+0x4e>
  e8:	c4625c62 	ins      	r3, r2, 5, 2
  ec:	1007      	lrw      	r0, 0x0	// 108 <ndp_cts_rx_hdl+0x108>
  ee:	dc640380 	st.b      	r3, (r4, 0x380)
  f2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  f6:	07c9      	br      	0x88	// 88 <ndp_cts_rx_hdl+0x88>
  f8:	3300      	movi      	r3, 0
  fa:	dc642265 	st.w      	r3, (r4, 0x994)
  fe:	07df      	br      	0xbc	// bc <ndp_cts_rx_hdl+0xbc>
	...

Disassembly of section .text.lmac_rx_pv0_ctrl_cfend:

00000000 <lmac_rx_pv0_ctrl_cfend>:
   0:	14d2      	push      	r4-r5, r15
   2:	1196      	lrw      	r4, 0x0	// d8 <lmac_rx_pv0_ctrl_cfend+0xd8>
   4:	11b6      	lrw      	r5, 0x0	// dc <lmac_rx_pv0_ctrl_cfend+0xdc>
   6:	d86400c0 	ld.b      	r3, (r4, 0xc0)
   a:	e4632040 	andi      	r3, r3, 64
   e:	e9030040 	bez      	r3, 0x8e	// 8e <lmac_rx_pv0_ctrl_cfend+0x8e>
  12:	8842      	ld.h      	r2, (r0, 0x4)
  14:	d8651293 	ld.h      	r3, (r5, 0x526)
  18:	64ca      	cmpne      	r2, r3
  1a:	0846      	bt      	0xa6	// a6 <lmac_rx_pv0_ctrl_cfend+0xa6>
  1c:	8843      	ld.h      	r2, (r0, 0x6)
  1e:	d8651294 	ld.h      	r3, (r5, 0x528)
  22:	64ca      	cmpne      	r2, r3
  24:	0841      	bt      	0xa6	// a6 <lmac_rx_pv0_ctrl_cfend+0xa6>
  26:	8844      	ld.h      	r2, (r0, 0x8)
  28:	d8651295 	ld.h      	r3, (r5, 0x52a)
  2c:	64ca      	cmpne      	r2, r3
  2e:	c4000503 	mvc      	r3
  32:	d84400c0 	ld.b      	r2, (r4, 0xc0)
  36:	c4435c07 	ins      	r2, r3, 7, 7
  3a:	dc4400c0 	st.b      	r2, (r4, 0xc0)
  3e:	8044      	ld.b      	r2, (r0, 0x4)
  40:	d86400b0 	ld.b      	r3, (r4, 0xb0)
  44:	c4625c01 	ins      	r3, r2, 1, 1
  48:	dc6400b0 	st.b      	r3, (r4, 0xb0)
  4c:	8842      	ld.h      	r2, (r0, 0x4)
  4e:	d8651181 	ld.h      	r3, (r5, 0x302)
  52:	64ca      	cmpne      	r2, r3
  54:	082b      	bt      	0xaa	// aa <lmac_rx_pv0_ctrl_cfend+0xaa>
  56:	8843      	ld.h      	r2, (r0, 0x6)
  58:	d8651182 	ld.h      	r3, (r5, 0x304)
  5c:	64ca      	cmpne      	r2, r3
  5e:	0826      	bt      	0xaa	// aa <lmac_rx_pv0_ctrl_cfend+0xaa>
  60:	d8651183 	ld.h      	r3, (r5, 0x306)
  64:	8844      	ld.h      	r2, (r0, 0x8)
  66:	64ca      	cmpne      	r2, r3
  68:	64c3      	mvcv      	r3
  6a:	d84400b0 	ld.b      	r2, (r4, 0xb0)
  6e:	c4435c00 	ins      	r2, r3, 0, 0
  72:	3300      	movi      	r3, 0
  74:	dc641049 	st.h      	r3, (r4, 0x92)
  78:	d86440c0 	ld.bs      	r3, (r4, 0xc0)
  7c:	dc4400b0 	st.b      	r2, (r4, 0xb0)
  80:	e9a30017 	bhsz      	r3, 0xae	// ae <lmac_rx_pv0_ctrl_cfend+0xae>
  84:	e0000000 	bsr      	0x0	// 0 <lmac_clr_obss_nav>
  88:	3000      	movi      	r0, 0
  8a:	2800      	subi      	r0, 1
  8c:	1492      	pop      	r4-r5, r15
  8e:	8845      	ld.h      	r2, (r0, 0xa)
  90:	d8651293 	ld.h      	r3, (r5, 0x526)
  94:	64ca      	cmpne      	r2, r3
  96:	0808      	bt      	0xa6	// a6 <lmac_rx_pv0_ctrl_cfend+0xa6>
  98:	8846      	ld.h      	r2, (r0, 0xc)
  9a:	d8651294 	ld.h      	r3, (r5, 0x528)
  9e:	64ca      	cmpne      	r2, r3
  a0:	0803      	bt      	0xa6	// a6 <lmac_rx_pv0_ctrl_cfend+0xa6>
  a2:	8847      	ld.h      	r2, (r0, 0xe)
  a4:	07c2      	br      	0x28	// 28 <lmac_rx_pv0_ctrl_cfend+0x28>
  a6:	3301      	movi      	r3, 1
  a8:	07c5      	br      	0x32	// 32 <lmac_rx_pv0_ctrl_cfend+0x32>
  aa:	3300      	movi      	r3, 0
  ac:	07df      	br      	0x6a	// 6a <lmac_rx_pv0_ctrl_cfend+0x6a>
  ae:	e0000000 	bsr      	0x0	// 0 <lmac_clr_basic_nav>
  b2:	d86400b0 	ld.b      	r3, (r4, 0xb0)
  b6:	e4632001 	andi      	r3, r3, 1
  ba:	e903ffe7 	bez      	r3, 0x88	// 88 <lmac_rx_pv0_ctrl_cfend+0x88>
  be:	d865202f 	ld.w      	r3, (r5, 0xbc)
  c2:	3b42      	cmpnei      	r3, 2
  c4:	0be2      	bt      	0x88	// 88 <lmac_rx_pv0_ctrl_cfend+0x88>
  c6:	e0000000 	bsr      	0x0	// 0 <lmac_update_pv0_cfend_addr>
  ca:	e0000000 	bsr      	0x0	// 0 <lmac_update_pv0_cfend_tx_vec>
  ce:	3307      	movi      	r3, 7
  d0:	dc652265 	st.w      	r3, (r5, 0x994)
  d4:	07da      	br      	0x88	// 88 <lmac_rx_pv0_ctrl_cfend+0x88>
	...

Disassembly of section .text.lmac_rx_pv0_ctrl_ack:

00000000 <lmac_rx_pv0_ctrl_ack>:
   0:	14d1      	push      	r4, r15
   2:	135d      	lrw      	r2, 0x0	// 1f4 <lmac_rx_pv0_ctrl_ack+0x1f4>
   4:	6cc3      	mov      	r3, r0
   6:	d80200c0 	ld.b      	r0, (r2, 0xc0)
   a:	e4202040 	andi      	r1, r0, 64
   e:	139b      	lrw      	r4, 0x0	// 1f8 <lmac_rx_pv0_ctrl_ack+0x1f8>
  10:	e901007d 	bez      	r1, 0x10a	// 10a <lmac_rx_pv0_ctrl_ack+0x10a>
  14:	8304      	ld.b      	r0, (r3, 0x4)
  16:	d8240526 	ld.b      	r1, (r4, 0x526)
  1a:	6442      	cmpne      	r0, r1
  1c:	0875      	bt      	0x106	// 106 <lmac_rx_pv0_ctrl_ack+0x106>
  1e:	8305      	ld.b      	r0, (r3, 0x5)
  20:	d8240527 	ld.b      	r1, (r4, 0x527)
  24:	6442      	cmpne      	r0, r1
  26:	0870      	bt      	0x106	// 106 <lmac_rx_pv0_ctrl_ack+0x106>
  28:	8306      	ld.b      	r0, (r3, 0x6)
  2a:	d8240528 	ld.b      	r1, (r4, 0x528)
  2e:	6442      	cmpne      	r0, r1
  30:	086b      	bt      	0x106	// 106 <lmac_rx_pv0_ctrl_ack+0x106>
  32:	8307      	ld.b      	r0, (r3, 0x7)
  34:	d8240529 	ld.b      	r1, (r4, 0x529)
  38:	6442      	cmpne      	r0, r1
  3a:	0866      	bt      	0x106	// 106 <lmac_rx_pv0_ctrl_ack+0x106>
  3c:	8308      	ld.b      	r0, (r3, 0x8)
  3e:	d824052a 	ld.b      	r1, (r4, 0x52a)
  42:	6442      	cmpne      	r0, r1
  44:	0861      	bt      	0x106	// 106 <lmac_rx_pv0_ctrl_ack+0x106>
  46:	d824052b 	ld.b      	r1, (r4, 0x52b)
  4a:	8309      	ld.b      	r0, (r3, 0x9)
  4c:	6442      	cmpne      	r0, r1
  4e:	c4000501 	mvc      	r1
  52:	d80200c0 	ld.b      	r0, (r2, 0xc0)
  56:	c4015c07 	ins      	r0, r1, 7, 7
  5a:	dc0200c0 	st.b      	r0, (r2, 0xc0)
  5e:	8324      	ld.b      	r1, (r3, 0x4)
  60:	d80200b0 	ld.b      	r0, (r2, 0xb0)
  64:	c4015c01 	ins      	r0, r1, 1, 1
  68:	dc0200b0 	st.b      	r0, (r2, 0xb0)
  6c:	d8040302 	ld.b      	r0, (r4, 0x302)
  70:	6442      	cmpne      	r0, r1
  72:	0865      	bt      	0x13c	// 13c <lmac_rx_pv0_ctrl_ack+0x13c>
  74:	8305      	ld.b      	r0, (r3, 0x5)
  76:	d8240303 	ld.b      	r1, (r4, 0x303)
  7a:	6442      	cmpne      	r0, r1
  7c:	0860      	bt      	0x13c	// 13c <lmac_rx_pv0_ctrl_ack+0x13c>
  7e:	8306      	ld.b      	r0, (r3, 0x6)
  80:	d8240304 	ld.b      	r1, (r4, 0x304)
  84:	6442      	cmpne      	r0, r1
  86:	085b      	bt      	0x13c	// 13c <lmac_rx_pv0_ctrl_ack+0x13c>
  88:	8307      	ld.b      	r0, (r3, 0x7)
  8a:	d8240305 	ld.b      	r1, (r4, 0x305)
  8e:	6442      	cmpne      	r0, r1
  90:	0856      	bt      	0x13c	// 13c <lmac_rx_pv0_ctrl_ack+0x13c>
  92:	8308      	ld.b      	r0, (r3, 0x8)
  94:	d8240306 	ld.b      	r1, (r4, 0x306)
  98:	6442      	cmpne      	r0, r1
  9a:	0851      	bt      	0x13c	// 13c <lmac_rx_pv0_ctrl_ack+0x13c>
  9c:	d8240307 	ld.b      	r1, (r4, 0x307)
  a0:	8309      	ld.b      	r0, (r3, 0x9)
  a2:	6442      	cmpne      	r0, r1
  a4:	6443      	mvcv      	r1
  a6:	d80200b0 	ld.b      	r0, (r2, 0xb0)
  aa:	c4015c00 	ins      	r0, r1, 0, 0
  ae:	dc0200b0 	st.b      	r0, (r2, 0xb0)
  b2:	e4002001 	andi      	r0, r0, 1
  b6:	e9200045 	bnez      	r0, 0x140	// 140 <lmac_rx_pv0_ctrl_ack+0x140>
  ba:	8323      	ld.b      	r1, (r3, 0x3)
  bc:	d9830002 	ld.b      	r12, (r3, 0x2)
  c0:	4128      	lsli      	r1, r1, 8
  c2:	6c70      	or      	r1, r12
  c4:	dc221049 	st.h      	r1, (r2, 0x92)
  c8:	d8442266 	ld.w      	r2, (r4, 0x998)
  cc:	3a41      	cmpnei      	r2, 1
  ce:	083e      	bt      	0x14a	// 14a <lmac_rx_pv0_ctrl_ack+0x14a>
  d0:	e900003a 	bez      	r0, 0x144	// 144 <lmac_rx_pv0_ctrl_ack+0x144>
  d4:	d8642294 	ld.w      	r3, (r4, 0xa50)
  d8:	e903000e 	bez      	r3, 0xf4	// f4 <lmac_rx_pv0_ctrl_ack+0xf4>
  dc:	e0000000 	bsr      	0x0	// 0 <lmac_get_avg_power>
  e0:	e460007e 	addi      	r3, r0, 127
  e4:	74cc      	zextb      	r3, r3
  e6:	eb03007e 	cmphsi      	r3, 127
  ea:	0805      	bt      	0xf4	// f4 <lmac_rx_pv0_ctrl_ack+0xf4>
  ec:	d8642294 	ld.w      	r3, (r4, 0xa50)
  f0:	dc0300b8 	st.b      	r0, (r3, 0xb8)
  f4:	3001      	movi      	r0, 1
  f6:	e0000000 	bsr      	0x0	// 0 <lmac_update_tx_state_ack>
  fa:	3300      	movi      	r3, 0
  fc:	dc642266 	st.w      	r3, (r4, 0x998)
 100:	3000      	movi      	r0, 0
 102:	2800      	subi      	r0, 1
 104:	1491      	pop      	r4, r15
 106:	3101      	movi      	r1, 1
 108:	07a5      	br      	0x52	// 52 <lmac_rx_pv0_ctrl_ack+0x52>
 10a:	d82200be 	ld.b      	r1, (r2, 0xbe)
 10e:	e4212003 	andi      	r1, r1, 3
 112:	2900      	subi      	r1, 1
 114:	7444      	zextb      	r1, r1
 116:	3901      	cmphsi      	r1, 2
 118:	0ba3      	bt      	0x5e	// 5e <lmac_rx_pv0_ctrl_ack+0x5e>
 11a:	d8240668 	ld.b      	r1, (r4, 0x668)
 11e:	d9821058 	ld.h      	r12, (r2, 0xb0)
 122:	c46c556c 	zext      	r12, r12, 11, 3
 126:	e4212007 	andi      	r1, r1, 7
 12a:	6472      	cmpne      	r12, r1
 12c:	c400050c 	mvc      	r12
 130:	6c43      	mov      	r1, r0
 132:	c42c5c07 	ins      	r1, r12, 7, 7
 136:	dc2200c0 	st.b      	r1, (r2, 0xc0)
 13a:	0792      	br      	0x5e	// 5e <lmac_rx_pv0_ctrl_ack+0x5e>
 13c:	3100      	movi      	r1, 0
 13e:	07b4      	br      	0xa6	// a6 <lmac_rx_pv0_ctrl_ack+0xa6>
 140:	3100      	movi      	r1, 0
 142:	07c1      	br      	0xc4	// c4 <lmac_rx_pv0_ctrl_ack+0xc4>
 144:	e0000000 	bsr      	0x0	// 0 <lmac_update_tx_state_ack>
 148:	07dc      	br      	0x100	// 100 <lmac_rx_pv0_ctrl_ack+0x100>
 14a:	3a45      	cmpnei      	r2, 5
 14c:	082c      	bt      	0x1a4	// 1a4 <lmac_rx_pv0_ctrl_ack+0x1a4>
 14e:	e900ffd9 	bez      	r0, 0x100	// 100 <lmac_rx_pv0_ctrl_ack+0x100>
 152:	d864202f 	ld.w      	r3, (r4, 0xbc)
 156:	3b42      	cmpnei      	r3, 2
 158:	081b      	bt      	0x18e	// 18e <lmac_rx_pv0_ctrl_ack+0x18e>
 15a:	d8442294 	ld.w      	r2, (r4, 0xa50)
 15e:	e9020012 	bez      	r2, 0x182	// 182 <lmac_rx_pv0_ctrl_ack+0x182>
 162:	d862006b 	ld.b      	r3, (r2, 0x6b)
 166:	e4232008 	andi      	r1, r3, 8
 16a:	e921000c 	bnez      	r1, 0x182	// 182 <lmac_rx_pv0_ctrl_ack+0x182>
 16e:	3101      	movi      	r1, 1
 170:	c4615c03 	ins      	r3, r1, 3, 3
 174:	dc62006b 	st.b      	r3, (r2, 0x6b)
 178:	d8641506 	ld.h      	r3, (r4, 0xa0c)
 17c:	60c4      	addu      	r3, r1
 17e:	dc641506 	st.h      	r3, (r4, 0xa0c)
 182:	d8441506 	ld.h      	r2, (r4, 0xa0c)
 186:	d8641504 	ld.h      	r3, (r4, 0xa08)
 18a:	64c8      	cmphs      	r2, r3
 18c:	0fba      	bf      	0x100	// 100 <lmac_rx_pv0_ctrl_ack+0x100>
 18e:	3300      	movi      	r3, 0
 190:	dc640318 	st.b      	r3, (r4, 0x318)
 194:	3201      	movi      	r2, 1
 196:	d8640319 	ld.b      	r3, (r4, 0x319)
 19a:	c4625c01 	ins      	r3, r2, 1, 1
 19e:	dc640319 	st.b      	r3, (r4, 0x319)
 1a2:	07af      	br      	0x100	// 100 <lmac_rx_pv0_ctrl_ack+0x100>
 1a4:	3a46      	cmpnei      	r2, 6
 1a6:	0bad      	bt      	0x100	// 100 <lmac_rx_pv0_ctrl_ack+0x100>
 1a8:	e900ffac 	bez      	r0, 0x100	// 100 <lmac_rx_pv0_ctrl_ack+0x100>
 1ac:	d8240319 	ld.b      	r1, (r4, 0x319)
 1b0:	3200      	movi      	r2, 0
 1b2:	c4225c00 	ins      	r1, r2, 0, 0
 1b6:	dc240319 	st.b      	r1, (r4, 0x319)
 1ba:	d824202f 	ld.w      	r1, (r4, 0xbc)
 1be:	3942      	cmpnei      	r1, 2
 1c0:	0814      	bt      	0x1e8	// 1e8 <lmac_rx_pv0_ctrl_ack+0x1e8>
 1c2:	d8242294 	ld.w      	r1, (r4, 0xa50)
 1c6:	dc41006e 	st.b      	r2, (r1, 0x6e)
 1ca:	8361      	ld.b      	r3, (r3, 0x1)
 1cc:	c4a354a3 	zext      	r3, r3, 5, 5
 1d0:	e903ff98 	bez      	r3, 0x100	// 100 <lmac_rx_pv0_ctrl_ack+0x100>
 1d4:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
 1d8:	dc0420f0 	st.w      	r0, (r4, 0x3c0)
 1dc:	dc2420f1 	st.w      	r1, (r4, 0x3c4)
 1e0:	1007      	lrw      	r0, 0x0	// 1fc <hgprintf+0x1fc>
 1e2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1e6:	078d      	br      	0x100	// 100 <lmac_rx_pv0_ctrl_ack+0x100>
 1e8:	3941      	cmpnei      	r1, 1
 1ea:	0b8b      	bt      	0x100	// 100 <lmac_rx_pv0_ctrl_ack+0x100>
 1ec:	d8640319 	ld.b      	r3, (r4, 0x319)
 1f0:	07d5      	br      	0x19a	// 19a <lmac_rx_pv0_ctrl_ack+0x19a>
	...

Disassembly of section .text.lmac_vht_info_set:

00000000 <lmac_vht_info_set>:
   0:	14d2      	push      	r4-r5, r15
   2:	1422      	subi      	r14, r14, 8
   4:	b820      	st.w      	r1, (r14, 0x0)
   6:	6d03      	mov      	r4, r0
   8:	3501      	movi      	r5, 1
   a:	e0000000 	bsr      	0x0	// 0 <lmac_vht_info_set>
   e:	b801      	st.w      	r0, (r14, 0x4)
  10:	3300      	movi      	r3, 0
  12:	c4055c00 	ins      	r0, r5, 0, 0
  16:	c4035c01 	ins      	r0, r3, 1, 1
  1a:	dc0e0004 	st.b      	r0, (r14, 0x4)
  1e:	9820      	ld.w      	r1, (r14, 0x0)
  20:	ea00ffff 	movi      	r0, 65535
  24:	e0000000 	bsr      	0x0	// 0 <lmac_sta_search>
  28:	d86e0005 	ld.b      	r3, (r14, 0x5)
  2c:	e9000016 	bez      	r0, 0x58	// 58 <lmac_vht_info_set+0x58>
  30:	d84000ad 	ld.b      	r2, (r0, 0xad)
  34:	c4625c63 	ins      	r3, r2, 6, 3
  38:	dc6e0005 	st.b      	r3, (r14, 0x5)
  3c:	d86000ae 	ld.b      	r3, (r0, 0xae)
  40:	9841      	ld.w      	r2, (r14, 0x4)
  42:	c48354e3 	zext      	r3, r3, 7, 4
  46:	c4435c4f 	ins      	r2, r3, 17, 15
  4a:	b841      	st.w      	r2, (r14, 0x4)
  4c:	e0000000 	bsr      	0x0	// 0 <lmac_get_avg_power>
  50:	e9200016 	bnez      	r0, 0x7c	// 7c <lmac_vht_info_set+0x7c>
  54:	3300      	movi      	r3, 0
  56:	043b      	br      	0xcc	// cc <lmac_vht_info_set+0xcc>
  58:	c4655c63 	ins      	r3, r5, 6, 3
  5c:	dc6e0005 	st.b      	r3, (r14, 0x5)
  60:	1164      	lrw      	r3, 0x0	// f0 <lmac_vht_info_set+0xf0>
  62:	d863034a 	ld.b      	r3, (r3, 0x34a)
  66:	e4632001 	andi      	r3, r3, 1
  6a:	3b40      	cmpnei      	r3, 0
  6c:	3303      	movi      	r3, 3
  6e:	c4030c40 	inct      	r0, r3, 0
  72:	9861      	ld.w      	r3, (r14, 0x4)
  74:	c4605c4f 	ins      	r3, r0, 17, 15
  78:	b861      	st.w      	r3, (r14, 0x4)
  7a:	07e9      	br      	0x4c	// 4c <lmac_vht_info_set+0x4c>
  7c:	103d      	lrw      	r1, 0x0	// f0 <lmac_vht_info_set+0xf0>
  7e:	3300      	movi      	r3, 0
  80:	d841431e 	ld.bs      	r2, (r1, 0x31e)
  84:	2b54      	subi      	r3, 85
  86:	64c9      	cmplt      	r2, r3
  88:	0809      	bt      	0x9a	// 9a <lmac_vht_info_set+0x9a>
  8a:	487f      	lsri      	r3, r0, 31
  8c:	600c      	addu      	r0, r3
  8e:	4a7f      	lsri      	r3, r2, 31
  90:	608c      	addu      	r2, r3
  92:	5001      	asri      	r0, r0, 1
  94:	5241      	asri      	r2, r2, 1
  96:	600a      	subu      	r0, r2
  98:	040b      	br      	0xae	// ae <lmac_vht_info_set+0xae>
  9a:	d861431d 	ld.bs      	r3, (r1, 0x31d)
  9e:	e4231054 	subi      	r1, r3, 85
  a2:	6441      	cmplt      	r0, r1
  a4:	080b      	bt      	0xba	// ba <lmac_vht_info_set+0xba>
  a6:	487f      	lsri      	r3, r0, 31
  a8:	600c      	addu      	r0, r3
  aa:	5001      	asri      	r0, r0, 1
  ac:	2029      	addi      	r0, 42
  ae:	7402      	sextb      	r0, r0
  b0:	eb20003f 	cmplti      	r0, 64
  b4:	0809      	bt      	0xc6	// c6 <lmac_vht_info_set+0xc6>
  b6:	333f      	movi      	r3, 63
  b8:	040b      	br      	0xce	// ce <lmac_vht_info_set+0xce>
  ba:	5a2c      	addu      	r1, r2, r3
  bc:	6441      	cmplt      	r0, r1
  be:	0be6      	bt      	0x8a	// 8a <lmac_vht_info_set+0x8a>
  c0:	4b1f      	lsri      	r0, r3, 31
  c2:	600c      	addu      	r0, r3
  c4:	5001      	asri      	r0, r0, 1
  c6:	6cc3      	mov      	r3, r0
  c8:	e980ffc6 	blz      	r0, 0x54	// 54 <lmac_vht_info_set+0x54>
  cc:	74ce      	sextb      	r3, r3
  ce:	d84e0006 	ld.b      	r2, (r14, 0x6)
  d2:	c4435ca2 	ins      	r2, r3, 7, 2
  d6:	dc4e0006 	st.b      	r2, (r14, 0x6)
  da:	9861      	ld.w      	r3, (r14, 0x4)
  dc:	4b50      	lsri      	r2, r3, 16
  de:	a442      	st.b      	r2, (r4, 0x2)
  e0:	a460      	st.b      	r3, (r4, 0x0)
  e2:	4a48      	lsri      	r2, r2, 8
  e4:	c50355e3 	zext      	r3, r3, 15, 8
  e8:	a443      	st.b      	r2, (r4, 0x3)
  ea:	a461      	st.b      	r3, (r4, 0x1)
  ec:	1402      	addi      	r14, r14, 8
  ee:	1492      	pop      	r4-r5, r15
  f0:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_rx_pv0_ctrl_rts:

00000000 <lmac_rx_pv0_ctrl_rts>:
   0:	14d6      	push      	r4-r9, r15
   2:	02d7      	lrw      	r6, 0x0	// 2a0 <lmac_rx_pv0_ctrl_rts+0x2a0>
   4:	6d43      	mov      	r5, r0
   6:	d86600c0 	ld.b      	r3, (r6, 0xc0)
   a:	e4632040 	andi      	r3, r3, 64
   e:	6e07      	mov      	r8, r1
  10:	029a      	lrw      	r4, 0x0	// 2a4 <lmac_rx_pv0_ctrl_rts+0x2a4>
  12:	e90300ab 	bez      	r3, 0x168	// 168 <lmac_rx_pv0_ctrl_rts+0x168>
  16:	8842      	ld.h      	r2, (r0, 0x4)
  18:	d8641293 	ld.h      	r3, (r4, 0x526)
  1c:	64ca      	cmpne      	r2, r3
  1e:	08b1      	bt      	0x180	// 180 <lmac_rx_pv0_ctrl_rts+0x180>
  20:	8843      	ld.h      	r2, (r0, 0x6)
  22:	d8641294 	ld.h      	r3, (r4, 0x528)
  26:	64ca      	cmpne      	r2, r3
  28:	08ac      	bt      	0x180	// 180 <lmac_rx_pv0_ctrl_rts+0x180>
  2a:	8844      	ld.h      	r2, (r0, 0x8)
  2c:	d8641295 	ld.h      	r3, (r4, 0x52a)
  30:	64ca      	cmpne      	r2, r3
  32:	c4000503 	mvc      	r3
  36:	d84600c0 	ld.b      	r2, (r6, 0xc0)
  3a:	c4435c07 	ins      	r2, r3, 7, 7
  3e:	dc4600c0 	st.b      	r2, (r6, 0xc0)
  42:	8d61      	ld.h      	r3, (r5, 0x2)
  44:	dc661049 	st.h      	r3, (r6, 0x92)
  48:	8544      	ld.b      	r2, (r5, 0x4)
  4a:	d86600b0 	ld.b      	r3, (r6, 0xb0)
  4e:	c4625c01 	ins      	r3, r2, 1, 1
  52:	dc6600b0 	st.b      	r3, (r6, 0xb0)
  56:	8d42      	ld.h      	r2, (r5, 0x4)
  58:	d8641181 	ld.h      	r3, (r4, 0x302)
  5c:	64ca      	cmpne      	r2, r3
  5e:	0893      	bt      	0x184	// 184 <lmac_rx_pv0_ctrl_rts+0x184>
  60:	8d43      	ld.h      	r2, (r5, 0x6)
  62:	d8641182 	ld.h      	r3, (r4, 0x304)
  66:	64ca      	cmpne      	r2, r3
  68:	088e      	bt      	0x184	// 184 <lmac_rx_pv0_ctrl_rts+0x184>
  6a:	8d44      	ld.h      	r2, (r5, 0x8)
  6c:	d8641183 	ld.h      	r3, (r4, 0x306)
  70:	64ca      	cmpne      	r2, r3
  72:	6483      	mvcv      	r2
  74:	d86600b0 	ld.b      	r3, (r6, 0xb0)
  78:	c4625c00 	ins      	r3, r2, 0, 0
  7c:	dc6600b0 	st.b      	r3, (r6, 0xb0)
  80:	e4632001 	andi      	r3, r3, 1
  84:	e903006f 	bez      	r3, 0x162	// 162 <lmac_rx_pv0_ctrl_rts+0x162>
  88:	e4e50009 	addi      	r7, r5, 10
  8c:	6c5f      	mov      	r1, r7
  8e:	ea00ffff 	movi      	r0, 65535
  92:	e0000000 	bsr      	0x0	// 0 <lmac_sta_search>
  96:	6e43      	mov      	r9, r0
  98:	e9000065 	bez      	r0, 0x162	// 162 <lmac_rx_pv0_ctrl_rts+0x162>
  9c:	d8441338 	ld.h      	r2, (r4, 0x670)
  a0:	d8641336 	ld.h      	r3, (r4, 0x66c)
  a4:	60c8      	addu      	r3, r2
  a6:	e46301f8 	addi      	r3, r3, 505
  aa:	8d41      	ld.h      	r2, (r5, 0x2)
  ac:	648d      	cmplt      	r3, r2
  ae:	0818      	bt      	0xde	// de <lmac_rx_pv0_ctrl_rts+0xde>
  b0:	3300      	movi      	r3, 0
  b2:	ad61      	st.h      	r3, (r5, 0x2)
  b4:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
  b8:	e4632100 	andi      	r3, r3, 256
  bc:	e9030011 	bez      	r3, 0xde	// de <lmac_rx_pv0_ctrl_rts+0xde>
  c0:	d8441336 	ld.h      	r2, (r4, 0x66c)
  c4:	d8641338 	ld.h      	r3, (r4, 0x670)
  c8:	608c      	addu      	r2, r3
  ca:	3100      	movi      	r1, 0
  cc:	1317      	lrw      	r0, 0x0	// 2a8 <lmac_rx_pv0_ctrl_rts+0x2a8>
  ce:	e44201f9 	addi      	r2, r2, 506
  d2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  d6:	6c63      	mov      	r1, r8
  d8:	6c17      	mov      	r0, r5
  da:	e0000000 	bsr      	0x0	// 0 <hgics_print_hex>
  de:	d86600bf 	ld.b      	r3, (r6, 0xbf)
  e2:	c4435463 	zext      	r3, r3, 3, 2
  e6:	3b42      	cmpnei      	r3, 2
  e8:	0c8c      	bf      	0x200	// 200 <lmac_rx_pv0_ctrl_rts+0x200>
  ea:	3b02      	cmphsi      	r3, 3
  ec:	08d3      	bt      	0x292	// 292 <lmac_rx_pv0_ctrl_rts+0x292>
  ee:	3b41      	cmpnei      	r3, 1
  f0:	0839      	bt      	0x162	// 162 <lmac_rx_pv0_ctrl_rts+0x162>
  f2:	d864202f 	ld.w      	r3, (r4, 0xbc)
  f6:	3b41      	cmpnei      	r3, 1
  f8:	0848      	bt      	0x188	// 188 <lmac_rx_pv0_ctrl_rts+0x188>
  fa:	d9241334 	ld.h      	r9, (r4, 0x668)
  fe:	c4695569 	zext      	r9, r9, 11, 3
 102:	8dc1      	ld.h      	r6, (r5, 0x2)
 104:	e906002f 	bez      	r6, 0x162	// 162 <lmac_rx_pv0_ctrl_rts+0x162>
 108:	d864219a 	ld.w      	r3, (r4, 0x668)
 10c:	c5835763 	zext      	r3, r3, 27, 12
 110:	618e      	subu      	r6, r3
 112:	e0000000 	bsr      	0x0	// 0 <ah_wphy_approved_bw_get>
 116:	d864034a 	ld.b      	r3, (r4, 0x34a)
 11a:	e4632001 	andi      	r3, r3, 1
 11e:	3500      	movi      	r5, 0
 120:	2e9f      	subi      	r6, 160
 122:	6e17      	mov      	r8, r5
 124:	7599      	zexth      	r6, r6
 126:	6dc3      	mov      	r7, r0
 128:	c4a55c03 	ins      	r5, r5, 3, 3
 12c:	e9030035 	bez      	r3, 0x196	// 196 <lmac_rx_pv0_ctrl_rts+0x196>
 130:	c4a85c04 	ins      	r5, r8, 4, 4
 134:	3328      	movi      	r3, 40
 136:	c4a95d05 	ins      	r5, r9, 13, 5
 13a:	c4668026 	divu      	r6, r6, r3
 13e:	c4a65d2e 	ins      	r5, r6, 23, 14
 142:	c4a85c18 	ins      	r5, r8, 24, 24
 146:	6c17      	mov      	r0, r5
 148:	6c63      	mov      	r1, r8
 14a:	e0000000 	bsr      	0x0	// 0 <lmac_update_ndp_cts_tx_vec>
 14e:	d86409dc 	ld.b      	r3, (r4, 0x9dc)
 152:	3201      	movi      	r2, 1
 154:	c4625c04 	ins      	r3, r2, 4, 4
 158:	dc6409dc 	st.b      	r3, (r4, 0x9dc)
 15c:	3305      	movi      	r3, 5
 15e:	dc642265 	st.w      	r3, (r4, 0x994)
 162:	3000      	movi      	r0, 0
 164:	2800      	subi      	r0, 1
 166:	1496      	pop      	r4-r9, r15
 168:	8845      	ld.h      	r2, (r0, 0xa)
 16a:	d8641293 	ld.h      	r3, (r4, 0x526)
 16e:	64ca      	cmpne      	r2, r3
 170:	0808      	bt      	0x180	// 180 <lmac_rx_pv0_ctrl_rts+0x180>
 172:	8846      	ld.h      	r2, (r0, 0xc)
 174:	d8641294 	ld.h      	r3, (r4, 0x528)
 178:	64ca      	cmpne      	r2, r3
 17a:	0803      	bt      	0x180	// 180 <lmac_rx_pv0_ctrl_rts+0x180>
 17c:	8847      	ld.h      	r2, (r0, 0xe)
 17e:	0757      	br      	0x2c	// 2c <lmac_rx_pv0_ctrl_rts+0x2c>
 180:	3301      	movi      	r3, 1
 182:	075a      	br      	0x36	// 36 <lmac_rx_pv0_ctrl_rts+0x36>
 184:	3200      	movi      	r2, 0
 186:	0777      	br      	0x74	// 74 <lmac_rx_pv0_ctrl_rts+0x74>
 188:	d8091034 	ld.h      	r0, (r9, 0x68)
 18c:	1228      	lrw      	r1, 0x0	// 2ac <partial_aid_ndp_calc+0x2ac>
 18e:	e0000000 	bsr      	0x0	// 0 <partial_aid_ndp_calc>
 192:	6e43      	mov      	r9, r0
 194:	07b7      	br      	0x102	// 102 <lmac_rx_pv0_ctrl_rts+0x102>
 196:	c4a35c04 	ins      	r5, r3, 4, 4
 19a:	c4a95d05 	ins      	r5, r9, 13, 5
 19e:	c4a65dce 	ins      	r5, r6, 28, 14
 1a2:	c4a35c1d 	ins      	r5, r3, 29, 29
 1a6:	1263      	lrw      	r3, 0x0	// 2b0 <lmac_rx_pv0_ctrl_rts+0x2b0>
 1a8:	9360      	ld.w      	r3, (r3, 0x0)
 1aa:	d863202d 	ld.w      	r3, (r3, 0xb4)
 1ae:	c5a355c3 	zext      	r3, r3, 14, 13
 1b2:	3b41      	cmpnei      	r3, 1
 1b4:	0c0a      	bf      	0x1c8	// 1c8 <lmac_rx_pv0_ctrl_rts+0x1c8>
 1b6:	3b40      	cmpnei      	r3, 0
 1b8:	0c22      	bf      	0x1fc	// 1fc <lmac_rx_pv0_ctrl_rts+0x1fc>
 1ba:	3b42      	cmpnei      	r3, 2
 1bc:	0c1e      	bf      	0x1f8	// 1f8 <lmac_rx_pv0_ctrl_rts+0x1f8>
 1be:	111e      	lrw      	r0, 0x0	// 2b4 <lmac_rx_pv0_ctrl_rts+0x2b4>
 1c0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1c4:	3104      	movi      	r1, 4
 1c6:	0402      	br      	0x1ca	// 1ca <lmac_rx_pv0_ctrl_rts+0x1ca>
 1c8:	3102      	movi      	r1, 2
 1ca:	65c4      	cmphs      	r1, r7
 1cc:	c4270c40 	inct      	r1, r7, 0
 1d0:	7444      	zextb      	r1, r1
 1d2:	c4a15c3e 	ins      	r5, r1, 31, 30
 1d6:	c4415448 	zext      	r8, r1, 2, 2
 1da:	e0000000 	bsr      	0x0	// 0 <ah_wphy_avg_evm_get>
 1de:	487f      	lsri      	r3, r0, 31
 1e0:	60c0      	addu      	r3, r0
 1e2:	5361      	asri      	r3, r3, 1
 1e4:	3000      	movi      	r0, 0
 1e6:	600e      	subu      	r0, r3
 1e8:	7402      	sextb      	r0, r0
 1ea:	382f      	cmplti      	r0, 16
 1ec:	6cc3      	mov      	r3, r0
 1ee:	0802      	bt      	0x1f2	// 1f2 <lmac_rx_pv0_ctrl_rts+0x1f2>
 1f0:	330f      	movi      	r3, 15
 1f2:	c5035c61 	ins      	r8, r3, 4, 1
 1f6:	07a8      	br      	0x146	// 146 <lmac_rx_pv0_ctrl_rts+0x146>
 1f8:	3103      	movi      	r1, 3
 1fa:	07e8      	br      	0x1ca	// 1ca <lmac_rx_pv0_ctrl_rts+0x1ca>
 1fc:	3101      	movi      	r1, 1
 1fe:	07e6      	br      	0x1ca	// 1ca <lmac_rx_pv0_ctrl_rts+0x1ca>
 200:	8da1      	ld.h      	r5, (r5, 0x2)
 202:	e905ffb0 	bez      	r5, 0x162	// 162 <lmac_rx_pv0_ctrl_rts+0x162>
 206:	3206      	movi      	r2, 6
 208:	6c5f      	mov      	r1, r7
 20a:	110c      	lrw      	r0, 0x0	// 2b8 <lmac_rx_pv0_ctrl_rts+0x2b8>
 20c:	e0000000 	bsr      	0x0	// 0 <memcpy>
 210:	d8641337 	ld.h      	r3, (r4, 0x66e)
 214:	614e      	subu      	r5, r3
 216:	1129      	lrw      	r1, 0x0	// 2b8 <lmac_rx_pv0_ctrl_rts+0x2b8>
 218:	2d9f      	subi      	r5, 160
 21a:	591e      	addi      	r0, r1, 8
 21c:	dca4147b 	st.h      	r5, (r4, 0x8f6)
 220:	e0000000 	bsr      	0x0	// 0 <lmac_rx_pv0_ctrl_rts>
 224:	e0000000 	bsr      	0x0	// 0 <lmac_update_pv0_wpcts_tx_vec>
 228:	1162      	lrw      	r3, 0x0	// 2b0 <lmac_rx_pv0_ctrl_rts+0x2b0>
 22a:	9360      	ld.w      	r3, (r3, 0x0)
 22c:	d8a3202d 	ld.w      	r5, (r3, 0xb4)
 230:	c5a555c5 	zext      	r5, r5, 14, 13
 234:	3d43      	cmpnei      	r5, 3
 236:	0807      	bt      	0x244	// 244 <lmac_rx_pv0_ctrl_rts+0x244>
 238:	d864226d 	ld.w      	r3, (r4, 0x9b4)
 23c:	ec630040 	ori      	r3, r3, 64
 240:	dc64226d 	st.w      	r3, (r4, 0x9b4)
 244:	d864034a 	ld.b      	r3, (r4, 0x34a)
 248:	e4632001 	andi      	r3, r3, 1
 24c:	e9230021 	bnez      	r3, 0x28e	// 28e <lmac_rx_pv0_ctrl_rts+0x28e>
 250:	2500      	addi      	r5, 1
 252:	e0000000 	bsr      	0x0	// 0 <ah_wphy_avg_evm_get>
 256:	d86421f2 	ld.w      	r3, (r4, 0x7c8)
 25a:	600c      	addu      	r0, r3
 25c:	3301      	movi      	r3, 1
 25e:	70d4      	lsl      	r3, r5
 260:	d8a421f3 	ld.w      	r5, (r4, 0x7cc)
 264:	614c      	addu      	r5, r3
 266:	d86421f4 	ld.w      	r3, (r4, 0x7d0)
 26a:	2300      	addi      	r3, 1
 26c:	dc6421f4 	st.w      	r3, (r4, 0x7d0)
 270:	3305      	movi      	r3, 5
 272:	dc642265 	st.w      	r3, (r4, 0x994)
 276:	3200      	movi      	r2, 0
 278:	d86409dc 	ld.b      	r3, (r4, 0x9dc)
 27c:	c4625c04 	ins      	r3, r2, 4, 4
 280:	dc0421f2 	st.w      	r0, (r4, 0x7c8)
 284:	dca421f3 	st.w      	r5, (r4, 0x7cc)
 288:	dc6409dc 	st.b      	r3, (r4, 0x9dc)
 28c:	076b      	br      	0x162	// 162 <lmac_rx_pv0_ctrl_rts+0x162>
 28e:	3500      	movi      	r5, 0
 290:	07e1      	br      	0x252	// 252 <lmac_rx_pv0_ctrl_rts+0x252>
 292:	d864226d 	ld.w      	r3, (r4, 0x9b4)
 296:	ec630080 	ori      	r3, r3, 128
 29a:	dc64226d 	st.w      	r3, (r4, 0x9b4)
 29e:	0762      	br      	0x162	// 162 <lmac_rx_pv0_ctrl_rts+0x162>
	...

Disassembly of section .text.lmac_rx_pv0_ctrl_ba:

00000000 <lmac_rx_pv0_ctrl_ba>:
   0:	14d4      	push      	r4-r7, r15
   2:	80d3      	ld.b      	r6, (r0, 0x13)
   4:	0196      	lrw      	r4, 0x0	// 328 <lmac_rx_pv0_ctrl_ba+0x328>
   6:	e4c6200f 	andi      	r6, r6, 15
   a:	8072      	ld.b      	r3, (r0, 0x12)
   c:	46c8      	lsli      	r6, r6, 8
   e:	6d8c      	or      	r6, r3
  10:	6d43      	mov      	r5, r0
  12:	d864227e 	ld.w      	r3, (r4, 0x9f8)
  16:	e44409f7 	addi      	r2, r4, 2552
  1a:	648e      	cmpne      	r3, r2
  1c:	098c      	bt      	0x334	// 334 <lmac_rx_pv0_ctrl_ba+0x334>
  1e:	01fb      	lrw      	r7, 0x0	// 32c <lmac_rx_pv0_ctrl_ba+0x32c>
  20:	d86700c0 	ld.b      	r3, (r7, 0xc0)
  24:	e4632040 	andi      	r3, r3, 64
  28:	e90301a6 	bez      	r3, 0x374	// 374 <lmac_rx_pv0_ctrl_ba+0x374>
  2c:	8544      	ld.b      	r2, (r5, 0x4)
  2e:	d8640526 	ld.b      	r3, (r4, 0x526)
  32:	64ca      	cmpne      	r2, r3
  34:	09bb      	bt      	0x3aa	// 3aa <lmac_rx_pv0_ctrl_ba+0x3aa>
  36:	8545      	ld.b      	r2, (r5, 0x5)
  38:	d8640527 	ld.b      	r3, (r4, 0x527)
  3c:	64ca      	cmpne      	r2, r3
  3e:	09b6      	bt      	0x3aa	// 3aa <lmac_rx_pv0_ctrl_ba+0x3aa>
  40:	8546      	ld.b      	r2, (r5, 0x6)
  42:	d8640528 	ld.b      	r3, (r4, 0x528)
  46:	64ca      	cmpne      	r2, r3
  48:	09b1      	bt      	0x3aa	// 3aa <lmac_rx_pv0_ctrl_ba+0x3aa>
  4a:	8547      	ld.b      	r2, (r5, 0x7)
  4c:	d8640529 	ld.b      	r3, (r4, 0x529)
  50:	64ca      	cmpne      	r2, r3
  52:	09ac      	bt      	0x3aa	// 3aa <lmac_rx_pv0_ctrl_ba+0x3aa>
  54:	8548      	ld.b      	r2, (r5, 0x8)
  56:	d864052a 	ld.b      	r3, (r4, 0x52a)
  5a:	64ca      	cmpne      	r2, r3
  5c:	09a7      	bt      	0x3aa	// 3aa <lmac_rx_pv0_ctrl_ba+0x3aa>
  5e:	8549      	ld.b      	r2, (r5, 0x9)
  60:	d864052b 	ld.b      	r3, (r4, 0x52b)
  64:	64ca      	cmpne      	r2, r3
  66:	c4000503 	mvc      	r3
  6a:	d84700c0 	ld.b      	r2, (r7, 0xc0)
  6e:	c4435c07 	ins      	r2, r3, 7, 7
  72:	dc4700c0 	st.b      	r2, (r7, 0xc0)
  76:	8544      	ld.b      	r2, (r5, 0x4)
  78:	d8240302 	ld.b      	r1, (r4, 0x302)
  7c:	d86700b0 	ld.b      	r3, (r7, 0xb0)
  80:	644a      	cmpne      	r2, r1
  82:	c4625c01 	ins      	r3, r2, 1, 1
  86:	dc6700b0 	st.b      	r3, (r7, 0xb0)
  8a:	0992      	bt      	0x3ae	// 3ae <lmac_rx_pv0_ctrl_ba+0x3ae>
  8c:	8505      	ld.b      	r0, (r5, 0x5)
  8e:	d8640303 	ld.b      	r3, (r4, 0x303)
  92:	64c2      	cmpne      	r0, r3
  94:	098d      	bt      	0x3ae	// 3ae <lmac_rx_pv0_ctrl_ba+0x3ae>
  96:	8506      	ld.b      	r0, (r5, 0x6)
  98:	d8640304 	ld.b      	r3, (r4, 0x304)
  9c:	64c2      	cmpne      	r0, r3
  9e:	0988      	bt      	0x3ae	// 3ae <lmac_rx_pv0_ctrl_ba+0x3ae>
  a0:	8507      	ld.b      	r0, (r5, 0x7)
  a2:	d8640305 	ld.b      	r3, (r4, 0x305)
  a6:	64c2      	cmpne      	r0, r3
  a8:	0983      	bt      	0x3ae	// 3ae <lmac_rx_pv0_ctrl_ba+0x3ae>
  aa:	8508      	ld.b      	r0, (r5, 0x8)
  ac:	d8640306 	ld.b      	r3, (r4, 0x306)
  b0:	64c2      	cmpne      	r0, r3
  b2:	097e      	bt      	0x3ae	// 3ae <lmac_rx_pv0_ctrl_ba+0x3ae>
  b4:	d8640307 	ld.b      	r3, (r4, 0x307)
  b8:	8509      	ld.b      	r0, (r5, 0x9)
  ba:	64c2      	cmpne      	r0, r3
  bc:	64c3      	mvcv      	r3
  be:	d80700b0 	ld.b      	r0, (r7, 0xb0)
  c2:	c4035c00 	ins      	r0, r3, 0, 0
  c6:	dc0700b0 	st.b      	r0, (r7, 0xb0)
  ca:	e4002001 	andi      	r0, r0, 1
  ce:	e9200172 	bnez      	r0, 0x3b2	// 3b2 <lmac_rx_pv0_ctrl_ba+0x3b2>
  d2:	8563      	ld.b      	r3, (r5, 0x3)
  d4:	d9850002 	ld.b      	r12, (r5, 0x2)
  d8:	4368      	lsli      	r3, r3, 8
  da:	6cf0      	or      	r3, r12
  dc:	dc671049 	st.h      	r3, (r7, 0x92)
  e0:	d8642266 	ld.w      	r3, (r4, 0x998)
  e4:	3b41      	cmpnei      	r3, 1
  e6:	099d      	bt      	0x420	// 420 <lmac_rx_pv0_ctrl_ba+0x420>
  e8:	e9000197 	bez      	r0, 0x416	// 416 <lmac_rx_pv0_ctrl_ba+0x416>
  ec:	8570      	ld.b      	r3, (r5, 0x10)
  ee:	4b04      	lsri      	r0, r3, 4
  f0:	8571      	ld.b      	r3, (r5, 0x11)
  f2:	e463200f 	andi      	r3, r3, 15
  f6:	4364      	lsli      	r3, r3, 4
  f8:	6cc0      	or      	r3, r0
  fa:	eb430055 	cmpnei      	r3, 85
  fe:	0961      	bt      	0x3c0	// 3c0 <lmac_rx_pv0_ctrl_ba+0x3c0>
 100:	644a      	cmpne      	r2, r1
 102:	0907      	bt      	0x310	// 310 <lmac_rx_pv0_ctrl_ba+0x310>
 104:	8545      	ld.b      	r2, (r5, 0x5)
 106:	d8640303 	ld.b      	r3, (r4, 0x303)
 10a:	64ca      	cmpne      	r2, r3
 10c:	0902      	bt      	0x310	// 310 <lmac_rx_pv0_ctrl_ba+0x310>
 10e:	8546      	ld.b      	r2, (r5, 0x6)
 110:	d8640304 	ld.b      	r3, (r4, 0x304)
 114:	64ca      	cmpne      	r2, r3
 116:	08fd      	bt      	0x310	// 310 <lmac_rx_pv0_ctrl_ba+0x310>
 118:	8547      	ld.b      	r2, (r5, 0x7)
 11a:	d8640305 	ld.b      	r3, (r4, 0x305)
 11e:	64ca      	cmpne      	r2, r3
 120:	08f8      	bt      	0x310	// 310 <lmac_rx_pv0_ctrl_ba+0x310>
 122:	8548      	ld.b      	r2, (r5, 0x8)
 124:	d8640306 	ld.b      	r3, (r4, 0x306)
 128:	64ca      	cmpne      	r2, r3
 12a:	08f3      	bt      	0x310	// 310 <lmac_rx_pv0_ctrl_ba+0x310>
 12c:	8549      	ld.b      	r2, (r5, 0x9)
 12e:	d8640307 	ld.b      	r3, (r4, 0x307)
 132:	64ca      	cmpne      	r2, r3
 134:	08ee      	bt      	0x310	// 310 <lmac_rx_pv0_ctrl_ba+0x310>
 136:	854a      	ld.b      	r2, (r5, 0xa)
 138:	d86408c2 	ld.b      	r3, (r4, 0x8c2)
 13c:	64ca      	cmpne      	r2, r3
 13e:	081a      	bt      	0x172	// 172 <lmac_rx_pv0_ctrl_ba+0x172>
 140:	854b      	ld.b      	r2, (r5, 0xb)
 142:	d86408c3 	ld.b      	r3, (r4, 0x8c3)
 146:	64ca      	cmpne      	r2, r3
 148:	0815      	bt      	0x172	// 172 <lmac_rx_pv0_ctrl_ba+0x172>
 14a:	854c      	ld.b      	r2, (r5, 0xc)
 14c:	d86408c4 	ld.b      	r3, (r4, 0x8c4)
 150:	64ca      	cmpne      	r2, r3
 152:	0810      	bt      	0x172	// 172 <lmac_rx_pv0_ctrl_ba+0x172>
 154:	854d      	ld.b      	r2, (r5, 0xd)
 156:	d86408c5 	ld.b      	r3, (r4, 0x8c5)
 15a:	64ca      	cmpne      	r2, r3
 15c:	080b      	bt      	0x172	// 172 <lmac_rx_pv0_ctrl_ba+0x172>
 15e:	854e      	ld.b      	r2, (r5, 0xe)
 160:	d86408c6 	ld.b      	r3, (r4, 0x8c6)
 164:	64ca      	cmpne      	r2, r3
 166:	0806      	bt      	0x172	// 172 <lmac_rx_pv0_ctrl_ba+0x172>
 168:	854f      	ld.b      	r2, (r5, 0xf)
 16a:	d86408c7 	ld.b      	r3, (r4, 0x8c7)
 16e:	64ca      	cmpne      	r2, r3
 170:	0c0a      	bf      	0x184	// 184 <lmac_rx_pv0_ctrl_ba+0x184>
 172:	3206      	movi      	r2, 6
 174:	e4250009 	addi      	r1, r5, 10
 178:	130e      	lrw      	r0, 0x0	// 330 <memcpy+0x330>
 17a:	e0000000 	bsr      	0x0	// 0 <memcpy>
 17e:	3300      	movi      	r3, 0
 180:	dc640891 	st.b      	r3, (r4, 0x891)
 184:	8574      	ld.b      	r3, (r5, 0x14)
 186:	dc6408ac 	st.b      	r3, (r4, 0x8ac)
 18a:	8575      	ld.b      	r3, (r5, 0x15)
 18c:	dc6408ad 	st.b      	r3, (r4, 0x8ad)
 190:	8576      	ld.b      	r3, (r5, 0x16)
 192:	dc6408ae 	st.b      	r3, (r4, 0x8ae)
 196:	8577      	ld.b      	r3, (r5, 0x17)
 198:	dc6408af 	st.b      	r3, (r4, 0x8af)
 19c:	d8454018 	ld.bs      	r2, (r5, 0x18)
 1a0:	dc4408b0 	st.b      	r2, (r4, 0x8b0)
 1a4:	857a      	ld.b      	r3, (r5, 0x1a)
 1a6:	8539      	ld.b      	r1, (r5, 0x19)
 1a8:	4368      	lsli      	r3, r3, 8
 1aa:	6cc4      	or      	r3, r1
 1ac:	74cf      	sexth      	r3, r3
 1ae:	744d      	zexth      	r1, r3
 1b0:	dc6408b2 	st.b      	r3, (r4, 0x8b2)
 1b4:	4968      	lsri      	r3, r1, 8
 1b6:	dc6408b3 	st.b      	r3, (r4, 0x8b3)
 1ba:	857b      	ld.b      	r3, (r5, 0x1b)
 1bc:	e4632001 	andi      	r3, r3, 1
 1c0:	e9030009 	bez      	r3, 0x1d2	// 1d2 <lmac_rx_pv0_ctrl_ba+0x1d2>
 1c4:	d8640892 	ld.b      	r3, (r4, 0x892)
 1c8:	3001      	movi      	r0, 1
 1ca:	c4605c02 	ins      	r3, r0, 2, 2
 1ce:	dc640892 	st.b      	r3, (r4, 0x892)
 1d2:	3300      	movi      	r3, 0
 1d4:	2b58      	subi      	r3, 89
 1d6:	64c9      	cmplt      	r2, r3
 1d8:	08ef      	bt      	0x3b6	// 3b6 <lmac_rx_pv0_ctrl_ba+0x3b6>
 1da:	dc44031e 	st.b      	r2, (r4, 0x31e)
 1de:	eb01376d 	cmphsi      	r1, 14190
 1e2:	0c0b      	bf      	0x1f8	// 1f8 <lmac_rx_pv0_ctrl_ba+0x1f8>
 1e4:	8562      	ld.b      	r3, (r5, 0x2)
 1e6:	dc6408c9 	st.b      	r3, (r4, 0x8c9)
 1ea:	8543      	ld.b      	r2, (r5, 0x3)
 1ec:	d86408c8 	ld.b      	r3, (r4, 0x8c8)
 1f0:	c4625ca0 	ins      	r3, r2, 5, 0
 1f4:	dc6408c8 	st.b      	r3, (r4, 0x8c8)
 1f8:	e0000000 	bsr      	0x0	// 0 <ah_wphy_avg_evm_get>
 1fc:	dc0408b7 	st.b      	r0, (r4, 0x8b7)
 200:	e0000000 	bsr      	0x0	// 0 <lmac_get_avg_power>
 204:	dc0408b6 	st.b      	r0, (r4, 0x8b6)
 208:	e0000000 	bsr      	0x0	// 0 <ah_wphy_rx_freq_offset_get>
 20c:	33fa      	movi      	r3, 250
 20e:	4362      	lsli      	r3, r3, 2
 210:	c4608040 	divs      	r0, r0, r3
 214:	3300      	movi      	r3, 0
 216:	2b7f      	subi      	r3, 128
 218:	64c1      	cmplt      	r0, r3
 21a:	c4030c40 	inct      	r0, r3, 0
 21e:	eb20007f 	cmplti      	r0, 128
 222:	337f      	movi      	r3, 127
 224:	c4030c20 	incf      	r0, r3, 0
 228:	dc0408b8 	st.b      	r0, (r4, 0x8b8)
 22c:	e0000000 	bsr      	0x0	// 0 <ah_wphy_agc_info_get>
 230:	3300      	movi      	r3, 0
 232:	2b00      	subi      	r3, 1
 234:	dc6408c0 	st.b      	r3, (r4, 0x8c0)
 238:	dc6408c1 	st.b      	r3, (r4, 0x8c1)
 23c:	d84448ac 	ld.bs      	r2, (r4, 0x8ac)
 240:	d864489c 	ld.bs      	r3, (r4, 0x89c)
 244:	64c9      	cmplt      	r2, r3
 246:	e400200f 	andi      	r0, r0, 15
 24a:	dc0408b9 	st.b      	r0, (r4, 0x8b9)
 24e:	0c05      	bf      	0x258	// 258 <lmac_rx_pv0_ctrl_ba+0x258>
 250:	3300      	movi      	r3, 0
 252:	2b01      	subi      	r3, 2
 254:	dc6408c0 	st.b      	r3, (r4, 0x8c0)
 258:	d84448ad 	ld.bs      	r2, (r4, 0x8ad)
 25c:	d864489d 	ld.bs      	r3, (r4, 0x89d)
 260:	648d      	cmplt      	r3, r2
 262:	0c06      	bf      	0x26e	// 26e <lmac_rx_pv0_ctrl_ba+0x26e>
 264:	d86408c0 	ld.b      	r3, (r4, 0x8c0)
 268:	3b81      	bclri      	r3, 1
 26a:	dc6408c0 	st.b      	r3, (r4, 0x8c0)
 26e:	d84448ae 	ld.bs      	r2, (r4, 0x8ae)
 272:	d824489e 	ld.bs      	r1, (r4, 0x89e)
 276:	6485      	cmplt      	r1, r2
 278:	0805      	bt      	0x282	// 282 <lmac_rx_pv0_ctrl_ba+0x282>
 27a:	3300      	movi      	r3, 0
 27c:	60c6      	subu      	r3, r1
 27e:	64c9      	cmplt      	r2, r3
 280:	0c06      	bf      	0x28c	// 28c <lmac_rx_pv0_ctrl_ba+0x28c>
 282:	d86408c0 	ld.b      	r3, (r4, 0x8c0)
 286:	3b82      	bclri      	r3, 2
 288:	dc6408c0 	st.b      	r3, (r4, 0x8c0)
 28c:	3300      	movi      	r3, 0
 28e:	d84448b0 	ld.bs      	r2, (r4, 0x8b0)
 292:	2b58      	subi      	r3, 89
 294:	64c9      	cmplt      	r2, r3
 296:	0806      	bt      	0x2a2	// 2a2 <lmac_rx_pv0_ctrl_ba+0x2a2>
 298:	d86408c0 	ld.b      	r3, (r4, 0x8c0)
 29c:	3b84      	bclri      	r3, 4
 29e:	dc6408c0 	st.b      	r3, (r4, 0x8c0)
 2a2:	d84448b6 	ld.bs      	r2, (r4, 0x8b6)
 2a6:	d86448a4 	ld.bs      	r3, (r4, 0x8a4)
 2aa:	64c9      	cmplt      	r2, r3
 2ac:	0c05      	bf      	0x2b6	// 2b6 <lmac_rx_pv0_ctrl_ba+0x2b6>
 2ae:	3300      	movi      	r3, 0
 2b0:	2b01      	subi      	r3, 2
 2b2:	dc6408c1 	st.b      	r3, (r4, 0x8c1)
 2b6:	d84448b7 	ld.bs      	r2, (r4, 0x8b7)
 2ba:	d86448a5 	ld.bs      	r3, (r4, 0x8a5)
 2be:	648d      	cmplt      	r3, r2
 2c0:	0c06      	bf      	0x2cc	// 2cc <lmac_rx_pv0_ctrl_ba+0x2cc>
 2c2:	d86408c1 	ld.b      	r3, (r4, 0x8c1)
 2c6:	3b81      	bclri      	r3, 1
 2c8:	dc6408c1 	st.b      	r3, (r4, 0x8c1)
 2cc:	d84448b8 	ld.bs      	r2, (r4, 0x8b8)
 2d0:	d82448a6 	ld.bs      	r1, (r4, 0x8a6)
 2d4:	6485      	cmplt      	r1, r2
 2d6:	0805      	bt      	0x2e0	// 2e0 <lmac_rx_pv0_ctrl_ba+0x2e0>
 2d8:	3300      	movi      	r3, 0
 2da:	60c6      	subu      	r3, r1
 2dc:	64c9      	cmplt      	r2, r3
 2de:	0c06      	bf      	0x2ea	// 2ea <lmac_rx_pv0_ctrl_ba+0x2ea>
 2e0:	d86408c1 	ld.b      	r3, (r4, 0x8c1)
 2e4:	3b82      	bclri      	r3, 2
 2e6:	dc6408c1 	st.b      	r3, (r4, 0x8c1)
 2ea:	d86408c0 	ld.b      	r3, (r4, 0x8c0)
 2ee:	e4632007 	andi      	r3, r3, 7
 2f2:	3b47      	cmpnei      	r3, 7
 2f4:	080c      	bt      	0x30c	// 30c <lmac_rx_pv0_ctrl_ba+0x30c>
 2f6:	d86408c1 	ld.b      	r3, (r4, 0x8c1)
 2fa:	e4632007 	andi      	r3, r3, 7
 2fe:	3b47      	cmpnei      	r3, 7
 300:	0806      	bt      	0x30c	// 30c <lmac_rx_pv0_ctrl_ba+0x30c>
 302:	d8640891 	ld.b      	r3, (r4, 0x891)
 306:	2300      	addi      	r3, 1
 308:	dc640891 	st.b      	r3, (r4, 0x891)
 30c:	e0000000 	bsr      	0x0	// 0 <lmac_qa_results_valid_check>
 310:	3101      	movi      	r1, 1
 312:	3200      	movi      	r2, 0
 314:	6c1b      	mov      	r0, r6
 316:	e0000000 	bsr      	0x0	// 0 <lmac_update_tx_state_ba>
 31a:	3300      	movi      	r3, 0
 31c:	dc671049 	st.h      	r3, (r7, 0x92)
 320:	3000      	movi      	r0, 0
 322:	2800      	subi      	r0, 1
 324:	1494      	pop      	r4-r7, r15
	...
 332:	0000      	.short	0x0000
 334:	d803006f 	ld.b      	r0, (r3, 0x6f)
 338:	852a      	ld.b      	r1, (r5, 0xa)
 33a:	6442      	cmpne      	r0, r1
 33c:	081a      	bt      	0x370	// 370 <lmac_rx_pv0_ctrl_ba+0x370>
 33e:	d8030070 	ld.b      	r0, (r3, 0x70)
 342:	852b      	ld.b      	r1, (r5, 0xb)
 344:	6442      	cmpne      	r0, r1
 346:	0815      	bt      	0x370	// 370 <lmac_rx_pv0_ctrl_ba+0x370>
 348:	d8030071 	ld.b      	r0, (r3, 0x71)
 34c:	852c      	ld.b      	r1, (r5, 0xc)
 34e:	6442      	cmpne      	r0, r1
 350:	0810      	bt      	0x370	// 370 <lmac_rx_pv0_ctrl_ba+0x370>
 352:	d8030072 	ld.b      	r0, (r3, 0x72)
 356:	852d      	ld.b      	r1, (r5, 0xd)
 358:	6442      	cmpne      	r0, r1
 35a:	080b      	bt      	0x370	// 370 <lmac_rx_pv0_ctrl_ba+0x370>
 35c:	d8030073 	ld.b      	r0, (r3, 0x73)
 360:	852e      	ld.b      	r1, (r5, 0xe)
 362:	6442      	cmpne      	r0, r1
 364:	0806      	bt      	0x370	// 370 <lmac_rx_pv0_ctrl_ba+0x370>
 366:	d8030074 	ld.b      	r0, (r3, 0x74)
 36a:	852f      	ld.b      	r1, (r5, 0xf)
 36c:	6442      	cmpne      	r0, r1
 36e:	0ca3      	bf      	0x4b4	// 4b4 <lmac_rx_pv0_ctrl_ba+0x4b4>
 370:	9360      	ld.w      	r3, (r3, 0x0)
 372:	0654      	br      	0x1a	// 1a <lmac_rx_pv0_ctrl_ba+0x1a>
 374:	854a      	ld.b      	r2, (r5, 0xa)
 376:	d8640526 	ld.b      	r3, (r4, 0x526)
 37a:	64ca      	cmpne      	r2, r3
 37c:	0817      	bt      	0x3aa	// 3aa <lmac_rx_pv0_ctrl_ba+0x3aa>
 37e:	854b      	ld.b      	r2, (r5, 0xb)
 380:	d8640527 	ld.b      	r3, (r4, 0x527)
 384:	64ca      	cmpne      	r2, r3
 386:	0812      	bt      	0x3aa	// 3aa <lmac_rx_pv0_ctrl_ba+0x3aa>
 388:	854c      	ld.b      	r2, (r5, 0xc)
 38a:	d8640528 	ld.b      	r3, (r4, 0x528)
 38e:	64ca      	cmpne      	r2, r3
 390:	080d      	bt      	0x3aa	// 3aa <lmac_rx_pv0_ctrl_ba+0x3aa>
 392:	854d      	ld.b      	r2, (r5, 0xd)
 394:	d8640529 	ld.b      	r3, (r4, 0x529)
 398:	64ca      	cmpne      	r2, r3
 39a:	0808      	bt      	0x3aa	// 3aa <lmac_rx_pv0_ctrl_ba+0x3aa>
 39c:	854e      	ld.b      	r2, (r5, 0xe)
 39e:	d864052a 	ld.b      	r3, (r4, 0x52a)
 3a2:	64ca      	cmpne      	r2, r3
 3a4:	0803      	bt      	0x3aa	// 3aa <lmac_rx_pv0_ctrl_ba+0x3aa>
 3a6:	854f      	ld.b      	r2, (r5, 0xf)
 3a8:	065c      	br      	0x60	// 60 <lmac_rx_pv0_ctrl_ba+0x60>
 3aa:	3301      	movi      	r3, 1
 3ac:	065f      	br      	0x6a	// 6a <lmac_rx_pv0_ctrl_ba+0x6a>
 3ae:	3300      	movi      	r3, 0
 3b0:	0687      	br      	0xbe	// be <lmac_rx_pv0_ctrl_ba+0xbe>
 3b2:	3300      	movi      	r3, 0
 3b4:	0694      	br      	0xdc	// dc <lmac_rx_pv0_ctrl_ba+0xdc>
 3b6:	3300      	movi      	r3, 0
 3b8:	2b59      	subi      	r3, 90
 3ba:	dc64031e 	st.b      	r3, (r4, 0x31e)
 3be:	0710      	br      	0x1de	// 1de <lmac_rx_pv0_ctrl_ba+0x1de>
 3c0:	d8642294 	ld.w      	r3, (r4, 0xa50)
 3c4:	e903000e 	bez      	r3, 0x3e0	// 3e0 <lmac_rx_pv0_ctrl_ba+0x3e0>
 3c8:	e0000000 	bsr      	0x0	// 0 <lmac_get_avg_power>
 3cc:	e460007e 	addi      	r3, r0, 127
 3d0:	74cc      	zextb      	r3, r3
 3d2:	eb03007e 	cmphsi      	r3, 127
 3d6:	0805      	bt      	0x3e0	// 3e0 <lmac_rx_pv0_ctrl_ba+0x3e0>
 3d8:	d8642294 	ld.w      	r3, (r4, 0xa50)
 3dc:	dc0300b8 	st.b      	r0, (r3, 0xb8)
 3e0:	8535      	ld.b      	r1, (r5, 0x15)
 3e2:	8559      	ld.b      	r2, (r5, 0x19)
 3e4:	8514      	ld.b      	r0, (r5, 0x14)
 3e6:	8578      	ld.b      	r3, (r5, 0x18)
 3e8:	4128      	lsli      	r1, r1, 8
 3ea:	4248      	lsli      	r2, r2, 8
 3ec:	6c40      	or      	r1, r0
 3ee:	6c8c      	or      	r2, r3
 3f0:	8516      	ld.b      	r0, (r5, 0x16)
 3f2:	857a      	ld.b      	r3, (r5, 0x1a)
 3f4:	4010      	lsli      	r0, r0, 16
 3f6:	4370      	lsli      	r3, r3, 16
 3f8:	6cc8      	or      	r3, r2
 3fa:	6c04      	or      	r0, r1
 3fc:	855b      	ld.b      	r2, (r5, 0x1b)
 3fe:	8537      	ld.b      	r1, (r5, 0x17)
 400:	4138      	lsli      	r1, r1, 24
 402:	4258      	lsli      	r2, r2, 24
 404:	6c40      	or      	r1, r0
 406:	6c8c      	or      	r2, r3
 408:	6c1b      	mov      	r0, r6
 40a:	e0000000 	bsr      	0x0	// 0 <lmac_update_tx_state_ba>
 40e:	3300      	movi      	r3, 0
 410:	dc642266 	st.w      	r3, (r4, 0x998)
 414:	0786      	br      	0x320	// 320 <lmac_rx_pv0_ctrl_ba+0x320>
 416:	3100      	movi      	r1, 0
 418:	3200      	movi      	r2, 0
 41a:	e0000000 	bsr      	0x0	// 0 <lmac_update_tx_state_ba>
 41e:	0781      	br      	0x320	// 320 <lmac_rx_pv0_ctrl_ba+0x320>
 420:	3b45      	cmpnei      	r3, 5
 422:	082c      	bt      	0x47a	// 47a <lmac_rx_pv0_ctrl_ba+0x47a>
 424:	e900ff7e 	bez      	r0, 0x320	// 320 <lmac_rx_pv0_ctrl_ba+0x320>
 428:	d864202f 	ld.w      	r3, (r4, 0xbc)
 42c:	3b42      	cmpnei      	r3, 2
 42e:	081b      	bt      	0x464	// 464 <lmac_rx_pv0_ctrl_ba+0x464>
 430:	d8442294 	ld.w      	r2, (r4, 0xa50)
 434:	e9020012 	bez      	r2, 0x458	// 458 <lmac_rx_pv0_ctrl_ba+0x458>
 438:	d862006b 	ld.b      	r3, (r2, 0x6b)
 43c:	e4232008 	andi      	r1, r3, 8
 440:	e921000c 	bnez      	r1, 0x458	// 458 <lmac_rx_pv0_ctrl_ba+0x458>
 444:	3101      	movi      	r1, 1
 446:	c4615c03 	ins      	r3, r1, 3, 3
 44a:	dc62006b 	st.b      	r3, (r2, 0x6b)
 44e:	d8641506 	ld.h      	r3, (r4, 0xa0c)
 452:	60c4      	addu      	r3, r1
 454:	dc641506 	st.h      	r3, (r4, 0xa0c)
 458:	d8441506 	ld.h      	r2, (r4, 0xa0c)
 45c:	d8641504 	ld.h      	r3, (r4, 0xa08)
 460:	64c8      	cmphs      	r2, r3
 462:	0f5f      	bf      	0x320	// 320 <lmac_rx_pv0_ctrl_ba+0x320>
 464:	3300      	movi      	r3, 0
 466:	dc640318 	st.b      	r3, (r4, 0x318)
 46a:	3201      	movi      	r2, 1
 46c:	d8640319 	ld.b      	r3, (r4, 0x319)
 470:	c4625c01 	ins      	r3, r2, 1, 1
 474:	dc640319 	st.b      	r3, (r4, 0x319)
 478:	0754      	br      	0x320	// 320 <lmac_rx_pv0_ctrl_ba+0x320>
 47a:	3b46      	cmpnei      	r3, 6
 47c:	0b52      	bt      	0x320	// 320 <lmac_rx_pv0_ctrl_ba+0x320>
 47e:	e900ff51 	bez      	r0, 0x320	// 320 <lmac_rx_pv0_ctrl_ba+0x320>
 482:	d8640319 	ld.b      	r3, (r4, 0x319)
 486:	3200      	movi      	r2, 0
 488:	c4625c00 	ins      	r3, r2, 0, 0
 48c:	dc640319 	st.b      	r3, (r4, 0x319)
 490:	d864202f 	ld.w      	r3, (r4, 0xbc)
 494:	3b42      	cmpnei      	r3, 2
 496:	080a      	bt      	0x4aa	// 4aa <lmac_rx_pv0_ctrl_ba+0x4aa>
 498:	8561      	ld.b      	r3, (r5, 0x1)
 49a:	c4a354a3 	zext      	r3, r3, 5, 5
 49e:	e903ff41 	bez      	r3, 0x320	// 320 <lmac_rx_pv0_ctrl_ba+0x320>
 4a2:	100c      	lrw      	r0, 0x0	// 4d0 <hgprintf+0x4d0>
 4a4:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 4a8:	073c      	br      	0x320	// 320 <lmac_rx_pv0_ctrl_ba+0x320>
 4aa:	3b41      	cmpnei      	r3, 1
 4ac:	0b3a      	bt      	0x320	// 320 <lmac_rx_pv0_ctrl_ba+0x320>
 4ae:	d8640319 	ld.b      	r3, (r4, 0x319)
 4b2:	07df      	br      	0x470	// 470 <lmac_rx_pv0_ctrl_ba+0x470>
 4b4:	d86300b9 	ld.b      	r3, (r3, 0xb9)
 4b8:	e4632001 	andi      	r3, r3, 1
 4bc:	e903fdb1 	bez      	r3, 0x1e	// 1e <lmac_rx_pv0_ctrl_ba+0x1e>
 4c0:	85d3      	ld.b      	r6, (r5, 0x13)
 4c2:	8572      	ld.b      	r3, (r5, 0x12)
 4c4:	46c8      	lsli      	r6, r6, 8
 4c6:	6d8c      	or      	r6, r3
 4c8:	759b      	sexth      	r6, r6
 4ca:	e800fdaa 	br      	0x1e	// 1e <lmac_rx_pv0_ctrl_ba+0x1e>
 4ce:	0000      	.short	0x0000
 4d0:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_rx_pv0_ctrl_wrapper:

00000000 <lmac_rx_pv0_ctrl_wrapper>:
   0:	14d8      	push      	r4-r11, r15
   2:	1423      	subi      	r14, r14, 12
   4:	b821      	st.w      	r1, (r14, 0x4)
   6:	8069      	ld.b      	r3, (r0, 0x9)
   8:	8042      	ld.b      	r2, (r0, 0x2)
   a:	8083      	ld.b      	r4, (r0, 0x3)
   c:	b860      	st.w      	r3, (r14, 0x0)
   e:	80ab      	ld.b      	r5, (r0, 0xb)
  10:	4488      	lsli      	r4, r4, 8
  12:	6d08      	or      	r4, r2
  14:	45a8      	lsli      	r5, r5, 8
  16:	804a      	ld.b      	r2, (r0, 0xa)
  18:	6d48      	or      	r5, r2
  1a:	114e      	lrw      	r2, 0x0	// d0 <lmac_rx_pv0_ctrl_wrapper+0xd0>
  1c:	6d83      	mov      	r6, r0
  1e:	d8220a4f 	ld.b      	r1, (r2, 0xa4f)
  22:	d9600004 	ld.b      	r11, (r0, 0x4)
  26:	d9400005 	ld.b      	r10, (r0, 0x5)
  2a:	d9200006 	ld.b      	r9, (r0, 0x6)
  2e:	d9000007 	ld.b      	r8, (r0, 0x7)
  32:	80e8      	ld.b      	r7, (r0, 0x8)
  34:	3001      	movi      	r0, 1
  36:	c4205c02 	ins      	r1, r0, 2, 2
  3a:	e406000b 	addi      	r0, r6, 12
  3e:	dc220a4f 	st.b      	r1, (r2, 0xa4f)
  42:	b842      	st.w      	r2, (r14, 0x8)
  44:	e0000000 	bsr      	0x0	// 0 <lmac_rx_pv0_ctrl_wrapper>
  48:	9842      	ld.w      	r2, (r14, 0x8)
  4a:	dc022292 	st.w      	r0, (r2, 0xa48)
  4e:	d9860004 	ld.b      	r12, (r6, 0x4)
  52:	d8220302 	ld.b      	r1, (r2, 0x302)
  56:	6472      	cmpne      	r12, r1
  58:	0820      	bt      	0x98	// 98 <lmac_rx_pv0_ctrl_wrapper+0x98>
  5a:	d9860005 	ld.b      	r12, (r6, 0x5)
  5e:	d8220303 	ld.b      	r1, (r2, 0x303)
  62:	6472      	cmpne      	r12, r1
  64:	081a      	bt      	0x98	// 98 <lmac_rx_pv0_ctrl_wrapper+0x98>
  66:	d9860006 	ld.b      	r12, (r6, 0x6)
  6a:	d8220304 	ld.b      	r1, (r2, 0x304)
  6e:	6472      	cmpne      	r12, r1
  70:	0814      	bt      	0x98	// 98 <lmac_rx_pv0_ctrl_wrapper+0x98>
  72:	d9860007 	ld.b      	r12, (r6, 0x7)
  76:	d8220305 	ld.b      	r1, (r2, 0x305)
  7a:	6472      	cmpne      	r12, r1
  7c:	080e      	bt      	0x98	// 98 <lmac_rx_pv0_ctrl_wrapper+0x98>
  7e:	d9860008 	ld.b      	r12, (r6, 0x8)
  82:	d8220306 	ld.b      	r1, (r2, 0x306)
  86:	6472      	cmpne      	r12, r1
  88:	0808      	bt      	0x98	// 98 <lmac_rx_pv0_ctrl_wrapper+0x98>
  8a:	8629      	ld.b      	r1, (r6, 0x9)
  8c:	d8420307 	ld.b      	r2, (r2, 0x307)
  90:	6486      	cmpne      	r1, r2
  92:	0803      	bt      	0x98	// 98 <lmac_rx_pv0_ctrl_wrapper+0x98>
  94:	e0000000 	bsr      	0x0	// 0 <lmac_vht_info_get>
  98:	a6a6      	st.b      	r5, (r6, 0x6)
  9a:	a688      	st.b      	r4, (r6, 0x8)
  9c:	d86e0000 	ld.b      	r3, (r14, 0x0)
  a0:	9821      	ld.w      	r1, (r14, 0x4)
  a2:	4da8      	lsri      	r5, r5, 8
  a4:	4c88      	lsri      	r4, r4, 8
  a6:	a6a7      	st.b      	r5, (r6, 0x7)
  a8:	a689      	st.b      	r4, (r6, 0x9)
  aa:	dd66000a 	st.b      	r11, (r6, 0xa)
  ae:	dd46000b 	st.b      	r10, (r6, 0xb)
  b2:	dd26000c 	st.b      	r9, (r6, 0xc)
  b6:	dd06000d 	st.b      	r8, (r6, 0xd)
  ba:	a6ee      	st.b      	r7, (r6, 0xe)
  bc:	a66f      	st.b      	r3, (r6, 0xf)
  be:	2905      	subi      	r1, 6
  c0:	5e16      	addi      	r0, r6, 6
  c2:	e0000000 	bsr      	0x0	// 0 <lmac_rx_pv0_ctrl_wrapper>
  c6:	3000      	movi      	r0, 0
  c8:	2800      	subi      	r0, 1
  ca:	1403      	addi      	r14, r14, 12
  cc:	1498      	pop      	r4-r11, r15
  ce:	0000      	.short	0x0000
  d0:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_iface_task:

00000000 <lmac_iface_task>:
   0:	14d5      	push      	r4-r8, r15
   2:	11a9      	lrw      	r5, 0x0	// a4 <lmac_iface_task+0xa4>
   4:	3400      	movi      	r4, 0
   6:	e4e5057f 	addi      	r7, r5, 1408
   a:	11c8      	lrw      	r6, 0x0	// a8 <lmac_iface_task+0xa8>
   c:	3100      	movi      	r1, 0
   e:	2900      	subi      	r1, 1
  10:	6c1f      	mov      	r0, r7
  12:	e0000000 	bsr      	0x0	// 0 <os_sema_down>
  16:	d86520da 	ld.w      	r3, (r5, 0x368)
  1a:	d84520db 	ld.w      	r2, (r5, 0x36c)
  1e:	64ca      	cmpne      	r2, r3
  20:	0c0e      	bf      	0x3c	// 3c <lmac_iface_task+0x3c>
  22:	e44300dc 	addi      	r2, r3, 221
  26:	d0450884 	ldr.w      	r4, (r5, r2 << 2)
  2a:	2300      	addi      	r3, 1
  2c:	d84520dc 	ld.w      	r2, (r5, 0x370)
  30:	5b29      	subu      	r1, r3, r2
  32:	648d      	cmplt      	r3, r2
  34:	c4610c20 	incf      	r3, r1, 0
  38:	dc6520da 	st.w      	r3, (r5, 0x368)
  3c:	9460      	ld.w      	r3, (r4, 0x0)
  3e:	e463200a 	andi      	r3, r3, 10
  42:	e923001e 	bnez      	r3, 0x7e	// 7e <lmac_iface_task+0x7e>
  46:	9668      	ld.w      	r3, (r6, 0x20)
  48:	e903001b 	bez      	r3, 0x7e	// 7e <lmac_iface_task+0x7e>
  4c:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  50:	6e03      	mov      	r8, r0
  52:	9446      	ld.w      	r2, (r4, 0x18)
  54:	d9862008 	ld.w      	r12, (r6, 0x20)
  58:	9467      	ld.w      	r3, (r4, 0x1c)
  5a:	e4240067 	addi      	r1, r4, 104
  5e:	6c1b      	mov      	r0, r6
  60:	7bf1      	jsr      	r12
  62:	9460      	ld.w      	r3, (r4, 0x0)
  64:	ec630002 	ori      	r3, r3, 2
  68:	b460      	st.w      	r3, (r4, 0x0)
  6a:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  6e:	1070      	lrw      	r3, 0x0	// ac <lmac_iface_task+0xac>
  70:	6022      	subu      	r0, r8
  72:	d84321e7 	ld.w      	r2, (r3, 0x79c)
  76:	6409      	cmplt      	r2, r0
  78:	0c03      	bf      	0x7e	// 7e <lmac_iface_task+0x7e>
  7a:	dc0321e7 	st.w      	r0, (r3, 0x79c)
  7e:	9405      	ld.w      	r0, (r4, 0x14)
  80:	e0000000 	bsr      	0x0	// 0 <lmac_sta_put>
  84:	9460      	ld.w      	r3, (r4, 0x0)
  86:	e4632040 	andi      	r3, r3, 64
  8a:	e9230008 	bnez      	r3, 0x9a	// 9a <lmac_iface_task+0x9a>
  8e:	9447      	ld.w      	r2, (r4, 0x1c)
  90:	9466      	ld.w      	r3, (r4, 0x18)
  92:	60c8      	addu      	r3, r2
  94:	955a      	ld.w      	r2, (r5, 0x68)
  96:	60ca      	subu      	r3, r2
  98:	b57b      	st.w      	r3, (r5, 0x6c)
  9a:	6c13      	mov      	r0, r4
  9c:	e0000000 	bsr      	0x0	// 0 <_os_free>
  a0:	07b6      	br      	0xc	// c <lmac_iface_task+0xc>
	...

Disassembly of section .text.lmac_mcast_data_dup_filter.isra.4:

00000000 <lmac_mcast_data_dup_filter.isra.4>:
   0:	14d5      	push      	r4-r8, r15
   2:	8064      	ld.b      	r3, (r0, 0x4)
   4:	e4632001 	andi      	r3, r3, 1
   8:	e9230004 	bnez      	r3, 0x10	// 10 <lmac_mcast_data_dup_filter.isra.4+0x10>
   c:	3000      	movi      	r0, 0
   e:	1495      	pop      	r4-r8, r15
  10:	1394      	lrw      	r4, 0x0	// 1e0 <lmac_mcast_data_dup_filter.isra.4+0x1e0>
  12:	804a      	ld.b      	r2, (r0, 0xa)
  14:	d8640526 	ld.b      	r3, (r4, 0x526)
  18:	64ca      	cmpne      	r2, r3
  1a:	0bf9      	bt      	0xc	// c <lmac_mcast_data_dup_filter.isra.4+0xc>
  1c:	804b      	ld.b      	r2, (r0, 0xb)
  1e:	d8640527 	ld.b      	r3, (r4, 0x527)
  22:	64ca      	cmpne      	r2, r3
  24:	0bf4      	bt      	0xc	// c <lmac_mcast_data_dup_filter.isra.4+0xc>
  26:	804c      	ld.b      	r2, (r0, 0xc)
  28:	d8640528 	ld.b      	r3, (r4, 0x528)
  2c:	64ca      	cmpne      	r2, r3
  2e:	0bef      	bt      	0xc	// c <lmac_mcast_data_dup_filter.isra.4+0xc>
  30:	804d      	ld.b      	r2, (r0, 0xd)
  32:	d8640529 	ld.b      	r3, (r4, 0x529)
  36:	64ca      	cmpne      	r2, r3
  38:	0bea      	bt      	0xc	// c <lmac_mcast_data_dup_filter.isra.4+0xc>
  3a:	804e      	ld.b      	r2, (r0, 0xe)
  3c:	d864052a 	ld.b      	r3, (r4, 0x52a)
  40:	64ca      	cmpne      	r2, r3
  42:	0be5      	bt      	0xc	// c <lmac_mcast_data_dup_filter.isra.4+0xc>
  44:	804f      	ld.b      	r2, (r0, 0xf)
  46:	d864052b 	ld.b      	r3, (r4, 0x52b)
  4a:	64ca      	cmpne      	r2, r3
  4c:	0be0      	bt      	0xc	// c <lmac_mcast_data_dup_filter.isra.4+0xc>
  4e:	80f7      	ld.b      	r7, (r0, 0x17)
  50:	8076      	ld.b      	r3, (r0, 0x16)
  52:	47e8      	lsli      	r7, r7, 8
  54:	d8a40a63 	ld.b      	r5, (r4, 0xa63)
  58:	6dcc      	or      	r7, r3
  5a:	74d6      	sextb      	r3, r5
  5c:	4fe4      	lsri      	r7, r7, 4
  5e:	759d      	zexth      	r6, r7
  60:	e9a30092 	bhsz      	r3, 0x184	// 184 <lmac_mcast_data_dup_filter.isra.4+0x184>
  64:	d8441530 	ld.h      	r2, (r4, 0xa60)
  68:	e4422fff 	andi      	r2, r2, 4095
  6c:	649d      	cmplt      	r7, r2
  6e:	5e49      	subu      	r2, r6, r2
  70:	0837      	bt      	0xde	// de <lmac_mcast_data_dup_filter.isra.4+0xde>
  72:	d8a40a63 	ld.b      	r5, (r4, 0xa63)
  76:	7489      	zexth      	r2, r2
  78:	e4a5207f 	andi      	r5, r5, 127
  7c:	6549      	cmplt      	r2, r5
  7e:	0c33      	bf      	0xe4	// e4 <lmac_mcast_data_dup_filter.isra.4+0xe4>
  80:	3001      	movi      	r0, 1
  82:	3100      	movi      	r1, 0
  84:	e0000000 	bsr      	0x0	// 0 <__ashldi3>
  88:	d9842296 	ld.w      	r12, (r4, 0xa58)
  8c:	d9a42297 	ld.w      	r13, (r4, 0xa5c)
  90:	c5802022 	and      	r2, r0, r12
  94:	c5a12023 	and      	r3, r1, r13
  98:	6c8c      	or      	r2, r3
  9a:	e922009f 	bnez      	r2, 0x1d8	// 1d8 <lmac_mcast_data_dup_filter.isra.4+0x1d8>
  9e:	6c30      	or      	r0, r12
  a0:	6c74      	or      	r1, r13
  a2:	1271      	lrw      	r3, 0x0	// 1e4 <lmac_mcast_data_dup_filter.isra.4+0x1e4>
  a4:	dc042296 	st.w      	r0, (r4, 0xa58)
  a8:	dc242297 	st.w      	r1, (r4, 0xa5c)
  ac:	8b60      	ld.h      	r3, (r3, 0x0)
  ae:	2300      	addi      	r3, 1
  b0:	e4632fff 	andi      	r3, r3, 4095
  b4:	64da      	cmpne      	r6, r3
  b6:	085b      	bt      	0x16c	// 16c <lmac_mcast_data_dup_filter.isra.4+0x16c>
  b8:	128c      	lrw      	r4, 0x0	// 1e8 <lmac_mcast_data_dup_filter.isra.4+0x1e8>
  ba:	126b      	lrw      	r3, 0x0	// 1e4 <lmac_mcast_data_dup_filter.isra.4+0x1e4>
  bc:	8c40      	ld.h      	r2, (r4, 0x0)
  be:	2200      	addi      	r2, 1
  c0:	7489      	zexth      	r2, r2
  c2:	eb02270f 	cmphsi      	r2, 10000
  c6:	abc0      	st.h      	r6, (r3, 0x0)
  c8:	ac40      	st.h      	r2, (r4, 0x0)
  ca:	0fa1      	bf      	0xc	// c <lmac_mcast_data_dup_filter.isra.4+0xc>
  cc:	12a8      	lrw      	r5, 0x0	// 1ec <lmac_mcast_data_dup_filter.isra.4+0x1ec>
  ce:	1209      	lrw      	r0, 0x0	// 1f0 <lmac_mcast_data_dup_filter.isra.4+0x1f0>
  d0:	8d20      	ld.h      	r1, (r5, 0x0)
  d2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  d6:	3300      	movi      	r3, 0
  d8:	ad60      	st.h      	r3, (r5, 0x0)
  da:	ac60      	st.h      	r3, (r4, 0x0)
  dc:	0798      	br      	0xc	// c <lmac_mcast_data_dup_filter.isra.4+0xc>
  de:	e4420fff 	addi      	r2, r2, 4096
  e2:	07c8      	br      	0x72	// 72 <lmac_mcast_data_dup_filter.isra.4+0x72>
  e4:	eb0207ff 	cmphsi      	r2, 2048
  e8:	0878      	bt      	0x1d8	// 1d8 <lmac_mcast_data_dup_filter.isra.4+0x1d8>
  ea:	d8442298 	ld.w      	r2, (r4, 0xa60)
  ee:	c58256e2 	zext      	r2, r2, 23, 12
  f2:	649d      	cmplt      	r7, r2
  f4:	5e49      	subu      	r2, r6, r2
  f6:	0829      	bt      	0x148	// 148 <lmac_mcast_data_dup_filter.isra.4+0x148>
  f8:	7489      	zexth      	r2, r2
  fa:	6549      	cmplt      	r2, r5
  fc:	0829      	bt      	0x14e	// 14e <lmac_mcast_data_dup_filter.isra.4+0x14e>
  fe:	3200      	movi      	r2, 0
 100:	3300      	movi      	r3, 0
 102:	dc442296 	st.w      	r2, (r4, 0xa58)
 106:	dc642297 	st.w      	r3, (r4, 0xa5c)
 10a:	5f62      	addi      	r3, r7, 1
 10c:	654d      	cmplt      	r3, r5
 10e:	5e75      	subu      	r3, r6, r5
 110:	082a      	bt      	0x164	// 164 <lmac_mcast_data_dup_filter.isra.4+0x164>
 112:	2300      	addi      	r3, 1
 114:	d8441530 	ld.h      	r2, (r4, 0xa60)
 118:	e4632fff 	andi      	r3, r3, 4095
 11c:	c4435d60 	ins      	r2, r3, 11, 0
 120:	dc441530 	st.h      	r2, (r4, 0xa60)
 124:	d8642298 	ld.w      	r3, (r4, 0xa60)
 128:	c4675d6c 	ins      	r3, r7, 23, 12
 12c:	dc642298 	st.w      	r3, (r4, 0xa60)
 130:	5d43      	subi      	r2, r5, 1
 132:	3001      	movi      	r0, 1
 134:	3100      	movi      	r1, 0
 136:	e0000000 	bsr      	0x0	// 0 <__ashldi3>
 13a:	d8442296 	ld.w      	r2, (r4, 0xa58)
 13e:	d8642297 	ld.w      	r3, (r4, 0xa5c)
 142:	6c08      	or      	r0, r2
 144:	6c4c      	or      	r1, r3
 146:	07ae      	br      	0xa2	// a2 <lmac_mcast_data_dup_filter.isra.4+0xa2>
 148:	e4420fff 	addi      	r2, r2, 4096
 14c:	07d6      	br      	0xf8	// f8 <lmac_mcast_data_dup_filter.isra.4+0xf8>
 14e:	d8042296 	ld.w      	r0, (r4, 0xa58)
 152:	d8242297 	ld.w      	r1, (r4, 0xa5c)
 156:	e0000000 	bsr      	0x0	// 0 <__lshrdi3>
 15a:	dc042296 	st.w      	r0, (r4, 0xa58)
 15e:	dc242297 	st.w      	r1, (r4, 0xa5c)
 162:	07d4      	br      	0x10a	// 10a <lmac_mcast_data_dup_filter.isra.4+0x10a>
 164:	ea021001 	movi      	r2, 4097
 168:	60c8      	addu      	r3, r2
 16a:	07d5      	br      	0x114	// 114 <lmac_mcast_data_dup_filter.isra.4+0x114>
 16c:	64d8      	cmphs      	r6, r3
 16e:	5e6d      	subu      	r3, r6, r3
 170:	0c07      	bf      	0x17e	// 17e <lmac_mcast_data_dup_filter.isra.4+0x17e>
 172:	105f      	lrw      	r2, 0x0	// 1ec <lmac_mcast_data_dup_filter.isra.4+0x1ec>
 174:	74cd      	zexth      	r3, r3
 176:	8a20      	ld.h      	r1, (r2, 0x0)
 178:	60c4      	addu      	r3, r1
 17a:	aa60      	st.h      	r3, (r2, 0x0)
 17c:	079e      	br      	0xb8	// b8 <lmac_mcast_data_dup_filter.isra.4+0xb8>
 17e:	e4630fff 	addi      	r3, r3, 4096
 182:	07f8      	br      	0x172	// 172 <lmac_mcast_data_dup_filter.isra.4+0x172>
 184:	ea080001 	movi      	r8, 1
 188:	c4a85c07 	ins      	r5, r8, 7, 7
 18c:	dca40a63 	st.b      	r5, (r4, 0xa63)
 190:	e4a5207f 	andi      	r5, r5, 127
 194:	5d43      	subi      	r2, r5, 1
 196:	3001      	movi      	r0, 1
 198:	3100      	movi      	r1, 0
 19a:	e0000000 	bsr      	0x0	// 0 <__ashldi3>
 19e:	d8642298 	ld.w      	r3, (r4, 0xa60)
 1a2:	655d      	cmplt      	r7, r5
 1a4:	c4675d6c 	ins      	r3, r7, 23, 12
 1a8:	dc042296 	st.w      	r0, (r4, 0xa58)
 1ac:	dc242297 	st.w      	r1, (r4, 0xa5c)
 1b0:	dc642298 	st.w      	r3, (r4, 0xa60)
 1b4:	080d      	bt      	0x1ce	// 1ce <lmac_mcast_data_dup_filter.isra.4+0x1ce>
 1b6:	c4a80085 	subu      	r5, r8, r5
 1ba:	6158      	addu      	r5, r6
 1bc:	d8641530 	ld.h      	r3, (r4, 0xa60)
 1c0:	e4a52fff 	andi      	r5, r5, 4095
 1c4:	c4655d60 	ins      	r3, r5, 11, 0
 1c8:	dc641530 	st.h      	r3, (r4, 0xa60)
 1cc:	0776      	br      	0xb8	// b8 <lmac_mcast_data_dup_filter.isra.4+0xb8>
 1ce:	5eb5      	subu      	r5, r6, r5
 1d0:	ea031001 	movi      	r3, 4097
 1d4:	614c      	addu      	r5, r3
 1d6:	07f3      	br      	0x1bc	// 1bc <lmac_mcast_data_dup_filter.isra.4+0x1bc>
 1d8:	3000      	movi      	r0, 0
 1da:	2800      	subi      	r0, 1
 1dc:	0719      	br      	0xe	// e <lmac_mcast_data_dup_filter.isra.4+0xe>
	...

Disassembly of section .text.lmac_ops_rx:

00000000 <lmac_ops_rx>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
   8:	6d43      	mov      	r5, r0
   a:	9406      	ld.w      	r0, (r4, 0x18)
   c:	e0000000 	bsr      	0x0	// 0 <lmac_ops_rx>
  10:	9460      	ld.w      	r3, (r4, 0x0)
  12:	e4632008 	andi      	r3, r3, 8
  16:	e9030011 	bez      	r3, 0x38	// 38 <lmac_ops_rx+0x38>
  1a:	1073      	lrw      	r3, 0x0	// 64 <lmac_ops_rx+0x64>
  1c:	d86320ee 	ld.w      	r3, (r3, 0x3b8)
  20:	e4632020 	andi      	r3, r3, 32
  24:	e9030005 	bez      	r3, 0x2e	// 2e <lmac_ops_rx+0x2e>
  28:	1010      	lrw      	r0, 0x0	// 68 <hgprintf+0x68>
  2a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  2e:	9460      	ld.w      	r3, (r4, 0x0)
  30:	ec630002 	ori      	r3, r3, 2
  34:	b460      	st.w      	r3, (r4, 0x0)
  36:	1492      	pop      	r4-r5, r15
  38:	100d      	lrw      	r0, 0x0	// 6c <lmac_ops_rx+0x6c>
  3a:	d9802008 	ld.w      	r12, (r0, 0x20)
  3e:	e90cfff8 	bez      	r12, 0x2e	// 2e <lmac_ops_rx+0x2e>
  42:	9467      	ld.w      	r3, (r4, 0x1c)
  44:	9446      	ld.w      	r2, (r4, 0x18)
  46:	e4240067 	addi      	r1, r4, 104
  4a:	7bf1      	jsr      	r12
  4c:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  50:	1065      	lrw      	r3, 0x0	// 64 <lmac_ops_rx+0x64>
  52:	6016      	subu      	r0, r5
  54:	d84321e7 	ld.w      	r2, (r3, 0x79c)
  58:	6408      	cmphs      	r2, r0
  5a:	0bea      	bt      	0x2e	// 2e <lmac_ops_rx+0x2e>
  5c:	dc0321e7 	st.w      	r0, (r3, 0x79c)
  60:	07e7      	br      	0x2e	// 2e <lmac_ops_rx+0x2e>
	...

Disassembly of section .text.lmac_rx_pv0_ctrl_pspoll:

00000000 <lmac_rx_pv0_ctrl_pspoll>:
   0:	14d2      	push      	r4-r5, r15
   2:	1194      	lrw      	r4, 0x0	// d0 <lmac_rx_pv0_ctrl_pspoll+0xd0>
   4:	8044      	ld.b      	r2, (r0, 0x4)
   6:	d8640302 	ld.b      	r3, (r4, 0x302)
   a:	64ca      	cmpne      	r2, r3
   c:	085f      	bt      	0xca	// ca <lmac_rx_pv0_ctrl_pspoll+0xca>
   e:	8045      	ld.b      	r2, (r0, 0x5)
  10:	d8640303 	ld.b      	r3, (r4, 0x303)
  14:	64ca      	cmpne      	r2, r3
  16:	085a      	bt      	0xca	// ca <lmac_rx_pv0_ctrl_pspoll+0xca>
  18:	8046      	ld.b      	r2, (r0, 0x6)
  1a:	d8640304 	ld.b      	r3, (r4, 0x304)
  1e:	64ca      	cmpne      	r2, r3
  20:	0855      	bt      	0xca	// ca <lmac_rx_pv0_ctrl_pspoll+0xca>
  22:	8047      	ld.b      	r2, (r0, 0x7)
  24:	d8640305 	ld.b      	r3, (r4, 0x305)
  28:	64ca      	cmpne      	r2, r3
  2a:	0850      	bt      	0xca	// ca <lmac_rx_pv0_ctrl_pspoll+0xca>
  2c:	8048      	ld.b      	r2, (r0, 0x8)
  2e:	d8640306 	ld.b      	r3, (r4, 0x306)
  32:	64ca      	cmpne      	r2, r3
  34:	084b      	bt      	0xca	// ca <lmac_rx_pv0_ctrl_pspoll+0xca>
  36:	8049      	ld.b      	r2, (r0, 0x9)
  38:	d8640307 	ld.b      	r3, (r4, 0x307)
  3c:	64ca      	cmpne      	r2, r3
  3e:	0846      	bt      	0xca	// ca <lmac_rx_pv0_ctrl_pspoll+0xca>
  40:	e4200009 	addi      	r1, r0, 10
  44:	3206      	movi      	r2, 6
  46:	e4040907 	addi      	r0, r4, 2312
  4a:	e0000000 	bsr      	0x0	// 0 <memcpy>
  4e:	d8640910 	ld.b      	r3, (r4, 0x910)
  52:	3201      	movi      	r2, 1
  54:	3500      	movi      	r5, 0
  56:	c4625c00 	ins      	r3, r2, 0, 0
  5a:	c4655c01 	ins      	r3, r5, 1, 1
  5e:	dc640910 	st.b      	r3, (r4, 0x910)
  62:	d8640912 	ld.b      	r3, (r4, 0x912)
  66:	c4655ca2 	ins      	r3, r5, 7, 2
  6a:	dc640912 	st.b      	r3, (r4, 0x912)
  6e:	d8640911 	ld.b      	r3, (r4, 0x911)
  72:	c4655c63 	ins      	r3, r5, 6, 3
  76:	dc640911 	st.b      	r3, (r4, 0x911)
  7a:	d864034a 	ld.b      	r3, (r4, 0x34a)
  7e:	68c8      	and      	r3, r2
  80:	3b40      	cmpnei      	r3, 0
  82:	3303      	movi      	r3, 3
  84:	c4650c20 	incf      	r3, r5, 0
  88:	d8442244 	ld.w      	r2, (r4, 0x910)
  8c:	c4435c4f 	ins      	r2, r3, 17, 15
  90:	dc442244 	st.w      	r2, (r4, 0x910)
  94:	e0000000 	bsr      	0x0	// 0 <lmac_update_pv0_wpack_tx_vec>
  98:	d86409dc 	ld.b      	r3, (r4, 0x9dc)
  9c:	c4655c06 	ins      	r3, r5, 6, 6
  a0:	dc6409dc 	st.b      	r3, (r4, 0x9dc)
  a4:	3302      	movi      	r3, 2
  a6:	dc642265 	st.w      	r3, (r4, 0x994)
  aa:	d84420f1 	ld.w      	r2, (r4, 0x3c4)
  ae:	d86420f0 	ld.w      	r3, (r4, 0x3c0)
  b2:	6cc8      	or      	r3, r2
  b4:	e903000b 	bez      	r3, 0xca	// ca <lmac_rx_pv0_ctrl_pspoll+0xca>
  b8:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  bc:	3332      	movi      	r3, 50
  be:	dc0420f0 	st.w      	r0, (r4, 0x3c0)
  c2:	dc2420f1 	st.w      	r1, (r4, 0x3c4)
  c6:	dc6411e4 	st.h      	r3, (r4, 0x3c8)
  ca:	3000      	movi      	r0, 0
  cc:	2800      	subi      	r0, 1
  ce:	1492      	pop      	r4-r5, r15
  d0:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_rx_pv1_mgmt:

00000000 <lmac_rx_pv1_mgmt>:
   0:	3000      	movi      	r0, 0
   2:	2800      	subi      	r0, 1
   4:	783c      	jmp      	r15

Disassembly of section .text.ndp_brp_rx_hdl:

00000000 <ndp_brp_rx_hdl>:
   0:	1063      	lrw      	r3, 0x0	// c <ndp_brp_rx_hdl+0xc>
   2:	3000      	movi      	r0, 0
   4:	dc032265 	st.w      	r0, (r3, 0x994)
   8:	783c      	jmp      	r15
   a:	0000      	.short	0x0000
   c:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_cfg_rx_ce_para.constprop.18:

00000000 <lmac_cfg_rx_ce_para.constprop.18>:
   0:	14d3      	push      	r4-r6, r15
   2:	9065      	ld.w      	r3, (r0, 0x14)
   4:	6d43      	mov      	r5, r0
   6:	e9230005 	bnez      	r3, 0x10	// 10 <lmac_cfg_rx_ce_para.constprop.18+0x10>
   a:	1205      	lrw      	r0, 0x0	// 11c <hgprintf+0x11c>
   c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  10:	d865403a 	ld.bs      	r3, (r5, 0x3a)
  14:	e9a30011 	bhsz      	r3, 0x36	// 36 <lmac_cfg_rx_ce_para.constprop.18+0x36>
  18:	12c2      	lrw      	r6, 0x0	// 120 <lmac_cfg_rx_ce_para.constprop.18+0x120>
  1a:	d82606b5 	ld.b      	r1, (r6, 0x6b5)
  1e:	e4c606b5 	addi      	r6, r6, 1718
  22:	3950      	cmpnei      	r1, 16
  24:	1280      	lrw      	r4, 0x0	// 124 <lmac_cfg_rx_ce_para.constprop.18+0x124>
  26:	0c0d      	bf      	0x40	// 40 <lmac_cfg_rx_ce_para.constprop.18+0x40>
  28:	eb410020 	cmpnei      	r1, 32
  2c:	0c50      	bf      	0xcc	// cc <lmac_cfg_rx_ce_para.constprop.18+0xcc>
  2e:	111f      	lrw      	r0, 0x0	// 128 <lmac_cfg_rx_ce_para.constprop.18+0x128>
  30:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  34:	0409      	br      	0x46	// 46 <lmac_cfg_rx_ce_para.constprop.18+0x46>
  36:	95c5      	ld.w      	r6, (r5, 0x14)
  38:	d8260076 	ld.b      	r1, (r6, 0x76)
  3c:	2676      	addi      	r6, 119
  3e:	07f2      	br      	0x22	// 22 <lmac_cfg_rx_ce_para.constprop.18+0x22>
  40:	3300      	movi      	r3, 0
  42:	dc640128 	st.b      	r3, (r4, 0x128)
  46:	d8640116 	ld.b      	r3, (r4, 0x116)
  4a:	c4035463 	zext      	r3, r3, 3, 0
  4e:	dc640129 	st.b      	r3, (r4, 0x129)
  52:	d8640116 	ld.b      	r3, (r4, 0x116)
  56:	c4835483 	zext      	r3, r3, 4, 4
  5a:	dc64012a 	st.b      	r3, (r4, 0x12a)
  5e:	d8640116 	ld.b      	r3, (r4, 0x116)
  62:	c4a354a3 	zext      	r3, r3, 5, 5
  66:	dc64012b 	st.b      	r3, (r4, 0x12b)
  6a:	1171      	lrw      	r3, 0x0	// 12c <lmac_cfg_rx_ce_para.constprop.18+0x12c>
  6c:	dc64204b 	st.w      	r3, (r4, 0x12c)
  70:	2305      	addi      	r3, 6
  72:	dc64204c 	st.w      	r3, (r4, 0x130)
  76:	d8640144 	ld.b      	r3, (r4, 0x144)
  7a:	dc640138 	st.b      	r3, (r4, 0x138)
  7e:	d8650038 	ld.b      	r3, (r5, 0x38)
  82:	e4632003 	andi      	r3, r3, 3
  86:	dcc42049 	st.w      	r6, (r4, 0x124)
  8a:	e9030023 	bez      	r3, 0xd0	// d0 <lmac_cfg_rx_ce_para.constprop.18+0xd0>
  8e:	1109      	lrw      	r0, 0x0	// 130 <hgprintf+0x130>
  90:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  94:	9545      	ld.w      	r2, (r5, 0x14)
  96:	9567      	ld.w      	r3, (r5, 0x1c)
  98:	d9850020 	ld.b      	r12, (r5, 0x20)
  9c:	d8420076 	ld.b      	r2, (r2, 0x76)
  a0:	1125      	lrw      	r1, 0x0	// 134 <lmac_cfg_rx_ce_para.constprop.18+0x134>
  a2:	4a41      	lsri      	r2, r2, 1
  a4:	c5830080 	subu      	r0, r3, r12
  a8:	dc24204d 	st.w      	r1, (r4, 0x134)
  ac:	9526      	ld.w      	r1, (r5, 0x18)
  ae:	6070      	addu      	r1, r12
  b0:	600a      	subu      	r0, r2
  b2:	60ca      	subu      	r3, r2
  b4:	dc04109d 	st.h      	r0, (r4, 0x13a)
  b8:	dc24204f 	st.w      	r1, (r4, 0x13c)
  bc:	dc242050 	st.w      	r1, (r4, 0x140)
  c0:	b567      	st.w      	r3, (r5, 0x1c)
  c2:	3301      	movi      	r3, 1
  c4:	dc640139 	st.b      	r3, (r4, 0x139)
  c8:	3000      	movi      	r0, 0
  ca:	0415      	br      	0xf4	// f4 <lmac_cfg_rx_ce_para.constprop.18+0xf4>
  cc:	3302      	movi      	r3, 2
  ce:	07ba      	br      	0x42	// 42 <lmac_cfg_rx_ce_para.constprop.18+0x42>
  d0:	9565      	ld.w      	r3, (r5, 0x14)
  d2:	d8450020 	ld.b      	r2, (r5, 0x20)
  d6:	d8630076 	ld.b      	r3, (r3, 0x76)
  da:	c423484c 	lsri      	r12, r3, 1
  de:	5a1e      	addi      	r0, r2, 8
  e0:	9527      	ld.w      	r1, (r5, 0x1c)
  e2:	c580002d 	addu      	r13, r0, r12
  e6:	6474      	cmphs      	r13, r1
  e8:	0c07      	bf      	0xf6	// f6 <lmac_cfg_rx_ce_para.constprop.18+0xf6>
  ea:	1014      	lrw      	r0, 0x0	// 138 <lmac_cfg_rx_ce_para.constprop.18+0x138>
  ec:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  f0:	3000      	movi      	r0, 0
  f2:	2800      	subi      	r0, 1
  f4:	1493      	pop      	r4-r6, r15
  f6:	2907      	subi      	r1, 8
  f8:	5969      	subu      	r3, r1, r2
  fa:	60f2      	subu      	r3, r12
  fc:	dc64109d 	st.h      	r3, (r4, 0x13a)
 100:	106f      	lrw      	r3, 0x0	// 13c <lmac_cfg_rx_ce_para.constprop.18+0x13c>
 102:	dc64204d 	st.w      	r3, (r4, 0x134)
 106:	9566      	ld.w      	r3, (r5, 0x18)
 108:	600c      	addu      	r0, r3
 10a:	6072      	subu      	r1, r12
 10c:	60c8      	addu      	r3, r2
 10e:	dc04204f 	st.w      	r0, (r4, 0x13c)
 112:	dc642050 	st.w      	r3, (r4, 0x140)
 116:	b527      	st.w      	r1, (r5, 0x1c)
 118:	07d5      	br      	0xc2	// c2 <lmac_cfg_rx_ce_para.constprop.18+0xc2>
	...

Disassembly of section .text.lmac_decrypt_data_pv0:

00000000 <lmac_decrypt_data_pv0>:
   0:	14d5      	push      	r4-r8, r15
   2:	6d43      	mov      	r5, r0
   4:	d8600020 	ld.b      	r3, (r0, 0x20)
   8:	128a      	lrw      	r4, 0x0	// 130 <lmac_decrypt_data_pv0+0x130>
   a:	3208      	movi      	r2, 8
   c:	9026      	ld.w      	r1, (r0, 0x18)
   e:	604c      	addu      	r1, r3
  10:	e40400d3 	addi      	r0, r4, 212
  14:	e0000000 	bsr      	0x0	// 0 <memcpy>
  18:	95c6      	ld.w      	r6, (r5, 0x18)
  1a:	5e2e      	addi      	r1, r6, 4
  1c:	86e1      	ld.b      	r7, (r6, 0x1)
  1e:	8660      	ld.b      	r3, (r6, 0x0)
  20:	47e8      	lsli      	r7, r7, 8
  22:	6dcc      	or      	r7, r3
  24:	8677      	ld.b      	r3, (r6, 0x17)
  26:	8656      	ld.b      	r2, (r6, 0x16)
  28:	4368      	lsli      	r3, r3, 8
  2a:	6cc8      	or      	r3, r2
  2c:	ad72      	st.h      	r3, (r5, 0x24)
  2e:	ea033870 	movi      	r3, 14448
  32:	6cce      	nor      	r3, r3
  34:	68dc      	and      	r3, r7
  36:	ec634000 	ori      	r3, r3, 16384
  3a:	3212      	movi      	r2, 18
  3c:	e40400dd 	addi      	r0, r4, 222
  40:	dc64106e 	st.h      	r3, (r4, 0xdc)
  44:	e0000000 	bsr      	0x0	// 0 <memcpy>
  48:	9565      	ld.w      	r3, (r5, 0x14)
  4a:	e5060017 	addi      	r8, r6, 24
  4e:	d86300b9 	ld.b      	r3, (r3, 0xb9)
  52:	e4632001 	andi      	r3, r3, 1
  56:	e9030067 	bez      	r3, 0x124	// 124 <lmac_decrypt_data_pv0+0x124>
  5a:	9568      	ld.w      	r3, (r5, 0x20)
  5c:	c5035563 	zext      	r3, r3, 11, 8
  60:	dc641078 	st.h      	r3, (r4, 0xf0)
  64:	3316      	movi      	r3, 22
  66:	dc640144 	st.b      	r3, (r4, 0x144)
  6a:	d8450039 	ld.b      	r2, (r5, 0x39)
  6e:	e4422006 	andi      	r2, r2, 6
  72:	3a46      	cmpnei      	r2, 6
  74:	085c      	bt      	0x12c	// 12c <lmac_decrypt_data_pv0+0x12c>
  76:	6c63      	mov      	r1, r8
  78:	110f      	lrw      	r0, 0x0	// 134 <lmac_decrypt_data_pv0+0x134>
  7a:	e0000000 	bsr      	0x0	// 0 <memcpy>
  7e:	331c      	movi      	r3, 28
  80:	e506001d 	addi      	r8, r6, 30
  84:	dc640144 	st.b      	r3, (r4, 0x144)
  88:	11cc      	lrw      	r6, 0x0	// 138 <lmac_decrypt_data_pv0+0x138>
  8a:	6c1f      	mov      	r0, r7
  8c:	e0000000 	bsr      	0x0	// 0 <ieee80211_is_data_qos>
  90:	e9000013 	bez      	r0, 0xb6	// b6 <lmac_decrypt_data_pv0+0xb6>
  94:	d864106e 	ld.h      	r3, (r4, 0xdc)
  98:	c40355c3 	zext      	r3, r3, 14, 0
  9c:	dc64106e 	st.h      	r3, (r4, 0xdc)
  a0:	d8680000 	ld.b      	r3, (r8, 0x0)
  a4:	a660      	st.b      	r3, (r6, 0x0)
  a6:	d8680001 	ld.b      	r3, (r8, 0x1)
  aa:	a661      	st.b      	r3, (r6, 0x1)
  ac:	d8640144 	ld.b      	r3, (r4, 0x144)
  b0:	2301      	addi      	r3, 2
  b2:	dc640144 	st.b      	r3, (r4, 0x144)
  b6:	d845003a 	ld.b      	r2, (r5, 0x3a)
  ba:	d8640116 	ld.b      	r3, (r4, 0x116)
  be:	c4225482 	zext      	r2, r2, 4, 1
  c2:	c4625c60 	ins      	r3, r2, 3, 0
  c6:	9526      	ld.w      	r1, (r5, 0x18)
  c8:	3200      	movi      	r2, 0
  ca:	e46320cf 	andi      	r3, r3, 207
  ce:	c4625c26 	ins      	r3, r2, 7, 6
  d2:	2109      	addi      	r1, 10
  d4:	3206      	movi      	r2, 6
  d6:	101a      	lrw      	r0, 0x0	// 13c <lmac_decrypt_data_pv0+0x13c>
  d8:	dc640116 	st.b      	r3, (r4, 0x116)
  dc:	e0000000 	bsr      	0x0	// 0 <memcpy>
  e0:	d86400d4 	ld.b      	r3, (r4, 0xd4)
  e4:	dc64011d 	st.b      	r3, (r4, 0x11d)
  e8:	d86400d5 	ld.b      	r3, (r4, 0xd5)
  ec:	dc64011e 	st.b      	r3, (r4, 0x11e)
  f0:	d86400d8 	ld.b      	r3, (r4, 0xd8)
  f4:	dc64011f 	st.b      	r3, (r4, 0x11f)
  f8:	d86400d9 	ld.b      	r3, (r4, 0xd9)
  fc:	dc640120 	st.b      	r3, (r4, 0x120)
 100:	d86400da 	ld.b      	r3, (r4, 0xda)
 104:	dc640121 	st.b      	r3, (r4, 0x121)
 108:	6c17      	mov      	r0, r5
 10a:	d86400db 	ld.b      	r3, (r4, 0xdb)
 10e:	dc640122 	st.b      	r3, (r4, 0x122)
 112:	e0000000 	bsr      	0x0	// 0 <lmac_decrypt_data_pv0>
 116:	e9200006 	bnez      	r0, 0x122	// 122 <lmac_decrypt_data_pv0+0x122>
 11a:	102a      	lrw      	r1, 0x0	// 140 <lmac_decrypt_data_pv0+0x140>
 11c:	100a      	lrw      	r0, 0x0	// 144 <lmac_decrypt_data_pv0+0x144>
 11e:	e0000000 	bsr      	0x0	// 0 <ah_ce_start>
 122:	1495      	pop      	r4-r8, r15
 124:	8d72      	ld.h      	r3, (r5, 0x24)
 126:	e463200f 	andi      	r3, r3, 15
 12a:	079b      	br      	0x60	// 60 <lmac_decrypt_data_pv0+0x60>
 12c:	10c2      	lrw      	r6, 0x0	// 134 <lmac_decrypt_data_pv0+0x134>
 12e:	07ae      	br      	0x8a	// 8a <lmac_decrypt_data_pv0+0x8a>
	...

Disassembly of section .text.lmac_rx_pv1_ctrl:

00000000 <lmac_rx_pv1_ctrl>:
   0:	3000      	movi      	r0, 0
   2:	2800      	subi      	r0, 1
   4:	783c      	jmp      	r15

Disassembly of section .text.ndp_pspoll_rx_hdl:

00000000 <ndp_pspoll_rx_hdl>:
   0:	1063      	lrw      	r3, 0x0	// c <ndp_pspoll_rx_hdl+0xc>
   2:	3000      	movi      	r0, 0
   4:	dc032265 	st.w      	r0, (r3, 0x994)
   8:	783c      	jmp      	r15
   a:	0000      	.short	0x0000
   c:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_rx_pv0_ctrl_s1g_tack:

00000000 <lmac_rx_pv0_ctrl_s1g_tack>:
   0:	3000      	movi      	r0, 0
   2:	2800      	subi      	r0, 1
   4:	783c      	jmp      	r15

Disassembly of section .text.lmac_rx_pv0_ctrl_cfendack:

00000000 <lmac_rx_pv0_ctrl_cfendack>:
   0:	3000      	movi      	r0, 0
   2:	2800      	subi      	r0, 1
   4:	783c      	jmp      	r15

Disassembly of section .text.lmac_rx_pv1_data1:

00000000 <lmac_rx_pv1_data1>:
   0:	3000      	movi      	r0, 0
   2:	2800      	subi      	r0, 1
   4:	783c      	jmp      	r15

Disassembly of section .text.lmac_cache_task:

00000000 <lmac_cache_task>:
   0:	14d8      	push      	r4-r11, r15
   2:	142f      	subi      	r14, r14, 60
   4:	00b8      	lrw      	r5, 0x0	// 3a0 <lmac_cache_task+0x3a0>
   6:	e465000b 	addi      	r3, r5, 12
   a:	6d17      	mov      	r4, r5
   c:	b869      	st.w      	r3, (r14, 0x24)
   e:	8560      	ld.b      	r3, (r5, 0x0)
  10:	e4632002 	andi      	r3, r3, 2
  14:	e9030004 	bez      	r3, 0x1c	// 1c <lmac_cache_task+0x1c>
  18:	140f      	addi      	r14, r14, 60
  1a:	1498      	pop      	r4-r11, r15
  1c:	3101      	movi      	r1, 1
  1e:	001d      	lrw      	r0, 0x0	// 3a4 <lmac_cache_task+0x3a4>
  20:	e0000000 	bsr      	0x0	// 0 <os_sema_down>
  24:	d8652056 	ld.w      	r3, (r5, 0x158)
  28:	d8452057 	ld.w      	r2, (r5, 0x15c)
  2c:	64ca      	cmpne      	r2, r3
  2e:	0c2b      	bf      	0x84	// 84 <lmac_cache_task+0x84>
  30:	e4430058 	addi      	r2, r3, 89
  34:	d0450886 	ldr.w      	r6, (r5, r2 << 2)
  38:	2300      	addi      	r3, 1
  3a:	d8452058 	ld.w      	r2, (r5, 0x160)
  3e:	5b29      	subu      	r1, r3, r2
  40:	648d      	cmplt      	r3, r2
  42:	c4610c20 	incf      	r3, r1, 0
  46:	dc642056 	st.w      	r3, (r4, 0x158)
  4a:	e906001d 	bez      	r6, 0x84	// 84 <lmac_cache_task+0x84>
  4e:	d86410a9 	ld.h      	r3, (r4, 0x152)
  52:	5b42      	addi      	r2, r3, 1
  54:	dc4410a9 	st.h      	r2, (r4, 0x152)
  58:	b675      	st.w      	r3, (r6, 0x54)
  5a:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  5e:	9464      	ld.w      	r3, (r4, 0x10)
  60:	b616      	st.w      	r0, (r6, 0x58)
  62:	b637      	st.w      	r1, (r6, 0x5c)
  64:	e446000b 	addi      	r2, r6, 12
  68:	9829      	ld.w      	r1, (r14, 0x24)
  6a:	b444      	st.w      	r2, (r4, 0x10)
  6c:	b664      	st.w      	r3, (r6, 0x10)
  6e:	b623      	st.w      	r1, (r6, 0xc)
  70:	b340      	st.w      	r2, (r3, 0x0)
  72:	6c1b      	mov      	r0, r6
  74:	0152      	lrw      	r2, 0x0	// 3a8 <lmac_cache_task+0x3a8>
  76:	d862153f 	ld.h      	r3, (r2, 0xa7e)
  7a:	2300      	addi      	r3, 1
  7c:	dc62153f 	st.h      	r3, (r2, 0xa7e)
  80:	e0000000 	bsr      	0x0	// 0 <lmac_cache_task>
  84:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  88:	ea8900c9 	lrw      	r9, 0x0	// 3ac <lmac_cache_task+0x3ac>
  8c:	b80a      	st.w      	r0, (r14, 0x28)
  8e:	b82b      	st.w      	r1, (r14, 0x2c)
  90:	9462      	ld.w      	r3, (r4, 0x8)
  92:	dd2e2008 	st.w      	r9, (r14, 0x20)
  96:	ea8b00c5 	lrw      	r11, 0x0	// 3a8 <lmac_cache_task+0x3a8>
  9a:	664e      	cmpne      	r3, r9
  9c:	0855      	bt      	0x146	// 146 <lmac_cache_task+0x146>
  9e:	94c1      	ld.w      	r6, (r4, 0x4)
  a0:	ea090fff 	movi      	r9, 4095
  a4:	6e66      	nor      	r9, r9
  a6:	ea8800c3 	lrw      	r8, 0x0	// 3b0 <lmac_cache_task+0x3b0>
  aa:	9868      	ld.w      	r3, (r14, 0x20)
  ac:	64da      	cmpne      	r6, r3
  ae:	08b3      	bt      	0x214	// 214 <lmac_cache_task+0x214>
  b0:	017e      	lrw      	r3, 0x0	// 3b4 <lmac_cache_task+0x3b4>
  b2:	ea8b00be 	lrw      	r11, 0x0	// 3a8 <lmac_cache_task+0x3a8>
  b6:	ea8900c1 	lrw      	r9, 0x0	// 3b8 <lmac_cache_task+0x3b8>
  ba:	6dcf      	mov      	r7, r3
  bc:	94c1      	ld.w      	r6, (r4, 0x4)
  be:	9868      	ld.w      	r3, (r14, 0x20)
  c0:	64da      	cmpne      	r6, r3
  c2:	091d      	bt      	0x2fc	// 2fc <lmac_cache_task+0x2fc>
  c4:	0261      	lrw      	r3, 0x0	// 3bc <lmac_cache_task+0x3bc>
  c6:	ea0b0000 	movi      	r11, 0
  ca:	94e3      	ld.w      	r7, (r4, 0xc)
  cc:	b868      	st.w      	r3, (r14, 0x20)
  ce:	ea8900b7 	lrw      	r9, 0x0	// 3a8 <lmac_cache_task+0x3a8>
  d2:	9869      	ld.w      	r3, (r14, 0x24)
  d4:	64de      	cmpne      	r7, r3
  d6:	0f9c      	bf      	0xe	// e <lmac_cache_task+0xe>
  d8:	e4c7100b 	subi      	r6, r7, 12
  dc:	d9472000 	ld.w      	r10, (r7, 0x0)
  e0:	9660      	ld.w      	r3, (r6, 0x0)
  e2:	e4432002 	andi      	r2, r3, 2
  e6:	e902016f 	bez      	r2, 0x3c4	// 3c4 <lmac_cache_task+0x3c4>
  ea:	9647      	ld.w      	r2, (r6, 0x1c)
  ec:	d9062006 	ld.w      	r8, (r6, 0x18)
  f0:	6208      	addu      	r8, r2
  f2:	d849153f 	ld.h      	r2, (r9, 0xa7e)
  f6:	eb020064 	cmphsi      	r2, 101
  fa:	0c08      	bf      	0x10a	// 10a <lmac_cache_task+0x10a>
  fc:	b860      	st.w      	r3, (r14, 0x0)
  fe:	6c6f      	mov      	r1, r11
 100:	6ccb      	mov      	r3, r2
 102:	9808      	ld.w      	r0, (r14, 0x20)
 104:	6ca3      	mov      	r2, r8
 106:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 10a:	9761      	ld.w      	r3, (r7, 0x4)
 10c:	9740      	ld.w      	r2, (r7, 0x0)
 10e:	e9030006 	bez      	r3, 0x11a	// 11a <lmac_cache_task+0x11a>
 112:	e9020004 	bez      	r2, 0x11a	// 11a <lmac_cache_task+0x11a>
 116:	b261      	st.w      	r3, (r2, 0x4)
 118:	b340      	st.w      	r2, (r3, 0x0)
 11a:	3300      	movi      	r3, 0
 11c:	b760      	st.w      	r3, (r7, 0x0)
 11e:	b761      	st.w      	r3, (r7, 0x4)
 120:	9605      	ld.w      	r0, (r6, 0x14)
 122:	e0000000 	bsr      	0x0	// 0 <lmac_sta_put>
 126:	6c1b      	mov      	r0, r6
 128:	e0000000 	bsr      	0x0	// 0 <_os_free>
 12c:	947a      	ld.w      	r3, (r4, 0x68)
 12e:	620e      	subu      	r8, r3
 130:	d869153f 	ld.h      	r3, (r9, 0xa7e)
 134:	2b00      	subi      	r3, 1
 136:	dd04201b 	st.w      	r8, (r4, 0x6c)
 13a:	dc69153f 	st.h      	r3, (r9, 0xa7e)
 13e:	e56b0000 	addi      	r11, r11, 1
 142:	6deb      	mov      	r7, r10
 144:	07c7      	br      	0xd2	// d2 <lmac_cache_task+0xd2>
 146:	5b2f      	subi      	r1, r3, 4
 148:	9361      	ld.w      	r3, (r3, 0x4)
 14a:	9100      	ld.w      	r0, (r1, 0x0)
 14c:	e5802020 	andi      	r12, r0, 32
 150:	b86c      	st.w      	r3, (r14, 0x30)
 152:	e90c0004 	bez      	r12, 0x15a	// 15a <lmac_cache_task+0x15a>
 156:	986c      	ld.w      	r3, (r14, 0x30)
 158:	07a1      	br      	0x9a	// 9a <lmac_cache_task+0x9a>
 15a:	9156      	ld.w      	r2, (r1, 0x58)
 15c:	9177      	ld.w      	r3, (r1, 0x5c)
 15e:	98ca      	ld.w      	r6, (r14, 0x28)
 160:	98eb      	ld.w      	r7, (r14, 0x2c)
 162:	6598      	cmphs      	r6, r6
 164:	618b      	subc      	r6, r2
 166:	61cf      	subc      	r7, r3
 168:	d901003a 	ld.b      	r8, (r1, 0x3a)
 16c:	c4285488 	zext      	r8, r8, 4, 1
 170:	6c9b      	mov      	r2, r6
 172:	6cdf      	mov      	r3, r7
 174:	d9412005 	ld.w      	r10, (r1, 0x14)
 178:	e5a80014 	addi      	r13, r8, 21
 17c:	64f0      	cmphs      	r12, r3
 17e:	c48d482d 	lsli      	r13, r13, 4
 182:	d1aa002d 	ldr.b      	r13, (r10, r13 << 0)
 186:	0c05      	bf      	0x190	// 190 <lmac_cache_task+0x190>
 188:	670e      	cmpne      	r3, r12
 18a:	0be6      	bt      	0x156	// 156 <lmac_cache_task+0x156>
 18c:	65b4      	cmphs      	r13, r6
 18e:	0be4      	bt      	0x156	// 156 <lmac_cache_task+0x156>
 190:	91c8      	ld.w      	r6, (r1, 0x20)
 192:	ec000020 	ori      	r0, r0, 32
 196:	c50656e6 	zext      	r6, r6, 23, 8
 19a:	b100      	st.w      	r0, (r1, 0x0)
 19c:	d9842002 	ld.w      	r12, (r4, 0x8)
 1a0:	ea8d0088 	lrw      	r13, 0x0	// 3c0 <lmac_cache_task+0x3c0>
 1a4:	9868      	ld.w      	r3, (r14, 0x20)
 1a6:	64f2      	cmpne      	r12, r3
 1a8:	0fd7      	bf      	0x156	// 156 <lmac_cache_task+0x156>
 1aa:	e42c1003 	subi      	r1, r12, 4
 1ae:	9165      	ld.w      	r3, (r1, 0x14)
 1b0:	64ea      	cmpne      	r10, r3
 1b2:	082a      	bt      	0x206	// 206 <lmac_cache_task+0x206>
 1b4:	d861003a 	ld.b      	r3, (r1, 0x3a)
 1b8:	c4235483 	zext      	r3, r3, 4, 1
 1bc:	660e      	cmpne      	r3, r8
 1be:	0824      	bt      	0x206	// 206 <lmac_cache_task+0x206>
 1c0:	9148      	ld.w      	r2, (r1, 0x20)
 1c2:	c50256e2 	zext      	r2, r2, 23, 8
 1c6:	6588      	cmphs      	r2, r6
 1c8:	0c22      	bf      	0x20c	// 20c <lmac_cache_task+0x20c>
 1ca:	5a79      	subu      	r3, r2, r6
 1cc:	eb2307ff 	cmplti      	r3, 2048
 1d0:	64c3      	mvcv      	r3
 1d2:	74cc      	zextb      	r3, r3
 1d4:	e9030019 	bez      	r3, 0x206	// 206 <lmac_cache_task+0x206>
 1d8:	9160      	ld.w      	r3, (r1, 0x0)
 1da:	ec630020 	ori      	r3, r3, 32
 1de:	b160      	st.w      	r3, (r1, 0x0)
 1e0:	d86b20ee 	ld.w      	r3, (r11, 0x3b8)
 1e4:	e4632020 	andi      	r3, r3, 32
 1e8:	e903000f 	bez      	r3, 0x206	// 206 <lmac_cache_task+0x206>
 1ec:	6c37      	mov      	r0, r13
 1ee:	6cdb      	mov      	r3, r6
 1f0:	6c63      	mov      	r1, r8
 1f2:	dd8e200e 	st.w      	r12, (r14, 0x38)
 1f6:	ddae200d 	st.w      	r13, (r14, 0x34)
 1fa:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1fe:	d98e200e 	ld.w      	r12, (r14, 0x38)
 202:	d9ae200d 	ld.w      	r13, (r14, 0x34)
 206:	d98c2001 	ld.w      	r12, (r12, 0x4)
 20a:	07cd      	br      	0x1a4	// 1a4 <lmac_cache_task+0x1a4>
 20c:	e4620fff 	addi      	r3, r2, 4096
 210:	60da      	subu      	r3, r6
 212:	07dd      	br      	0x1cc	// 1cc <lmac_cache_task+0x1cc>
 214:	e5461003 	subi      	r10, r6, 4
 218:	d80a003a 	ld.b      	r0, (r10, 0x3a)
 21c:	c4205480 	zext      	r0, r0, 4, 1
 220:	d9aa2005 	ld.w      	r13, (r10, 0x14)
 224:	4004      	lsli      	r0, r0, 4
 226:	c40d0023 	addu      	r3, r13, r0
 22a:	d82a2008 	ld.w      	r1, (r10, 0x20)
 22e:	d86310a6 	ld.h      	r3, (r3, 0x14c)
 232:	e4632fff 	andi      	r3, r3, 4095
 236:	c50156e1 	zext      	r1, r1, 23, 8
 23a:	64c5      	cmplt      	r1, r3
 23c:	96c0      	ld.w      	r6, (r6, 0x0)
 23e:	084b      	bt      	0x2d4	// 2d4 <lmac_cache_task+0x2d4>
 240:	594d      	subu      	r2, r1, r3
 242:	c40d002b 	addu      	r11, r13, r0
 246:	7489      	zexth      	r2, r2
 248:	d98b014f 	ld.b      	r12, (r11, 0x14f)
 24c:	e58c207f 	andi      	r12, r12, 127
 250:	6709      	cmplt      	r2, r12
 252:	d98a2000 	ld.w      	r12, (r10, 0x0)
 256:	0c43      	bf      	0x2dc	// 2dc <lmac_cache_task+0x2dc>
 258:	d82b2051 	ld.w      	r1, (r11, 0x144)
 25c:	e4212001 	andi      	r1, r1, 1
 260:	e9210006 	bnez      	r1, 0x26c	// 26c <lmac_cache_task+0x26c>
 264:	e42c2020 	andi      	r1, r12, 32
 268:	e901ff21 	bez      	r1, 0xaa	// aa <lmac_cache_task+0xaa>
 26c:	c40d0021 	addu      	r1, r13, r0
 270:	ed8c0010 	ori      	r12, r12, 16
 274:	60c8      	addu      	r3, r2
 276:	dd8a2000 	st.w      	r12, (r10, 0x0)
 27a:	2300      	addi      	r3, 1
 27c:	d98110a6 	ld.h      	r12, (r1, 0x14c)
 280:	c5835d60 	ins      	r12, r3, 11, 0
 284:	dd8110a6 	st.h      	r12, (r1, 0x14c)
 288:	d981014f 	ld.b      	r12, (r1, 0x14f)
 28c:	e58c207f 	andi      	r12, r12, 127
 290:	e4632fff 	andi      	r3, r3, 4095
 294:	60f0      	addu      	r3, r12
 296:	2b00      	subi      	r3, 1
 298:	ea2c8000 	movih      	r12, 32768
 29c:	e58c0ffe 	addi      	r12, r12, 4095
 2a0:	68f0      	and      	r3, r12
 2a2:	e9a30005 	bhsz      	r3, 0x2ac	// 2ac <lmac_cache_task+0x2ac>
 2a6:	2b00      	subi      	r3, 1
 2a8:	6ce4      	or      	r3, r9
 2aa:	2300      	addi      	r3, 1
 2ac:	d9812053 	ld.w      	r12, (r1, 0x14c)
 2b0:	c40d002a 	addu      	r10, r13, r0
 2b4:	c5835d6c 	ins      	r12, r3, 23, 12
 2b8:	dd812053 	st.w      	r12, (r1, 0x14c)
 2bc:	d80a2051 	ld.w      	r0, (r10, 0x144)
 2c0:	d82a2052 	ld.w      	r1, (r10, 0x148)
 2c4:	2200      	addi      	r2, 1
 2c6:	e0000000 	bsr      	0x0	// 0 <__lshrdi3>
 2ca:	dc0a2051 	st.w      	r0, (r10, 0x144)
 2ce:	dc2a2052 	st.w      	r1, (r10, 0x148)
 2d2:	06ec      	br      	0xaa	// aa <lmac_cache_task+0xaa>
 2d4:	e4410fff 	addi      	r2, r1, 4096
 2d8:	608e      	subu      	r2, r3
 2da:	07b4      	br      	0x242	// 242 <lmac_cache_task+0x242>
 2dc:	eb0207ff 	cmphsi      	r2, 2048
 2e0:	ed8c0010 	ori      	r12, r12, 16
 2e4:	dd8a2000 	st.w      	r12, (r10, 0x0)
 2e8:	0ae1      	bt      	0xaa	// aa <lmac_cache_task+0xaa>
 2ea:	d80b2053 	ld.w      	r0, (r11, 0x14c)
 2ee:	c58056e0 	zext      	r0, r0, 23, 12
 2f2:	b800      	st.w      	r0, (r14, 0x0)
 2f4:	6c23      	mov      	r0, r8
 2f6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2fa:	06d8      	br      	0xaa	// aa <lmac_cache_task+0xaa>
 2fc:	e5061003 	subi      	r8, r6, 4
 300:	d9462000 	ld.w      	r10, (r6, 0x0)
 304:	d8682000 	ld.w      	r3, (r8, 0x0)
 308:	e4632018 	andi      	r3, r3, 24
 30c:	e9030031 	bez      	r3, 0x36e	// 36e <lmac_cache_task+0x36e>
 310:	6c23      	mov      	r0, r8
 312:	e0000000 	bsr      	0x0	// 0 <lmac_cache_task>
 316:	d86b20ee 	ld.w      	r3, (r11, 0x3b8)
 31a:	e4632020 	andi      	r3, r3, 32
 31e:	e9030028 	bez      	r3, 0x36e	// 36e <lmac_cache_task+0x36e>
 322:	d8682008 	ld.w      	r3, (r8, 0x20)
 326:	c50356e3 	zext      	r3, r3, 23, 8
 32a:	eb030fff 	cmphsi      	r3, 4096
 32e:	0820      	bt      	0x36e	// 36e <lmac_cache_task+0x36e>
 330:	d8482000 	ld.w      	r2, (r8, 0x0)
 334:	e4422008 	andi      	r2, r2, 8
 338:	e9020011 	bez      	r2, 0x35a	// 35a <lmac_cache_task+0x35a>
 33c:	d828003a 	ld.b      	r1, (r8, 0x3a)
 340:	c4215481 	zext      	r1, r1, 4, 1
 344:	d0290442 	ldr.h      	r2, (r9, r1 << 1)
 348:	7489      	zexth      	r2, r2
 34a:	5a02      	addi      	r0, r2, 1
 34c:	e4002fff 	andi      	r0, r0, 4095
 350:	640e      	cmpne      	r3, r0
 352:	0c04      	bf      	0x35a	// 35a <lmac_cache_task+0x35a>
 354:	6c1f      	mov      	r0, r7
 356:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 35a:	d868003a 	ld.b      	r3, (r8, 0x3a)
 35e:	d8482008 	ld.w      	r2, (r8, 0x20)
 362:	c4235483 	zext      	r3, r3, 4, 1
 366:	c50256e2 	zext      	r2, r2, 23, 8
 36a:	d4690442 	str.h      	r2, (r9, r3 << 1)
 36e:	d8682000 	ld.w      	r3, (r8, 0x0)
 372:	e4632002 	andi      	r3, r3, 2
 376:	e9030012 	bez      	r3, 0x39a	// 39a <lmac_cache_task+0x39a>
 37a:	9661      	ld.w      	r3, (r6, 0x4)
 37c:	9640      	ld.w      	r2, (r6, 0x0)
 37e:	e9030006 	bez      	r3, 0x38a	// 38a <lmac_cache_task+0x38a>
 382:	e9020004 	bez      	r2, 0x38a	// 38a <lmac_cache_task+0x38a>
 386:	b261      	st.w      	r3, (r2, 0x4)
 388:	b340      	st.w      	r2, (r3, 0x0)
 38a:	3300      	movi      	r3, 0
 38c:	b660      	st.w      	r3, (r6, 0x0)
 38e:	b661      	st.w      	r3, (r6, 0x4)
 390:	d86b153e 	ld.h      	r3, (r11, 0xa7c)
 394:	2b00      	subi      	r3, 1
 396:	dc6b153e 	st.h      	r3, (r11, 0xa7c)
 39a:	6dab      	mov      	r6, r10
 39c:	0691      	br      	0xbe	// be <lmac_cache_task+0xbe>
	...
 3c2:	0000      	.short	0x0000
 3c4:	d849153f 	ld.h      	r2, (r9, 0xa7e)
 3c8:	eb020064 	cmphsi      	r2, 101
 3cc:	0e21      	bf      	0xe	// e <lmac_cache_task+0xe>
 3ce:	6c6f      	mov      	r1, r11
 3d0:	101d      	lrw      	r0, 0x0	// 444 <lmac_cache_task+0x444>
 3d2:	d906003a 	ld.b      	r8, (r6, 0x3a)
 3d6:	96e5      	ld.w      	r7, (r6, 0x14)
 3d8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 3dc:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
 3e0:	c4285488 	zext      	r8, r8, 4, 1
 3e4:	6e43      	mov      	r9, r0
 3e6:	6e87      	mov      	r10, r1
 3e8:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
 3ec:	c4884822 	lsli      	r2, r8, 4
 3f0:	609c      	addu      	r2, r7
 3f2:	d9862016 	ld.w      	r12, (r6, 0x58)
 3f6:	d9a62017 	ld.w      	r13, (r6, 0x5c)
 3fa:	d8e22051 	ld.w      	r7, (r2, 0x144)
 3fe:	d9022052 	ld.w      	r8, (r2, 0x148)
 402:	b8e6      	st.w      	r7, (r14, 0x18)
 404:	dd0e2007 	st.w      	r8, (r14, 0x1c)
 408:	d8622053 	ld.w      	r3, (r2, 0x14c)
 40c:	c58356e3 	zext      	r3, r3, 23, 12
 410:	b865      	st.w      	r3, (r14, 0x14)
 412:	d86210a6 	ld.h      	r3, (r2, 0x14c)
 416:	e4632fff 	andi      	r3, r3, 4095
 41a:	b864      	st.w      	r3, (r14, 0x10)
 41c:	9648      	ld.w      	r2, (r6, 0x20)
 41e:	6400      	cmphs      	r0, r0
 420:	6033      	subc      	r0, r12
 422:	6077      	subc      	r1, r13
 424:	c50256e2 	zext      	r2, r2, 23, 8
 428:	b801      	st.w      	r0, (r14, 0x4)
 42a:	b822      	st.w      	r1, (r14, 0x8)
 42c:	b843      	st.w      	r2, (r14, 0xc)
 42e:	dd4e2000 	st.w      	r10, (r14, 0x0)
 432:	6ce7      	mov      	r3, r9
 434:	6c73      	mov      	r1, r12
 436:	6cb7      	mov      	r2, r13
 438:	1004      	lrw      	r0, 0x0	// 448 <lmac_cache_task+0x448>
 43a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 43e:	e800fde8 	br      	0xe	// e <lmac_cache_task+0xe>
	...

Disassembly of section .text.lmac_rx_data_queue_put:

00000000 <lmac_rx_data_queue_put>:
   0:	14d0      	push      	r15
   2:	6c87      	mov      	r2, r1
   4:	6c43      	mov      	r1, r0
   6:	1003      	lrw      	r0, 0x0	// 10 <lmac_rx_data_queue_put+0x10>
   8:	e0000000 	bsr      	0x0	// 0 <lmac_rxq_put>
   c:	1490      	pop      	r15
   e:	0000      	.short	0x0000
  10:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_rx_data_queue_count:

00000000 <lmac_rx_data_queue_count>:
   0:	14d0      	push      	r15
   2:	1003      	lrw      	r0, 0x0	// c <lmac_rx_data_queue_count+0xc>
   4:	e0000000 	bsr      	0x0	// 0 <lmac_rxq_count>
   8:	1490      	pop      	r15
   a:	0000      	.short	0x0000
   c:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_rx_iface_queue_count:

00000000 <lmac_rx_iface_queue_count>:
   0:	1067      	lrw      	r3, 0x0	// 1c <lmac_rx_iface_queue_count+0x1c>
   2:	d80320db 	ld.w      	r0, (r3, 0x36c)
   6:	d84320da 	ld.w      	r2, (r3, 0x368)
   a:	6481      	cmplt      	r0, r2
   c:	0803      	bt      	0x12	// 12 <lmac_rx_iface_queue_count+0x12>
   e:	600a      	subu      	r0, r2
  10:	783c      	jmp      	r15
  12:	d86320dc 	ld.w      	r3, (r3, 0x370)
  16:	60ca      	subu      	r3, r2
  18:	600c      	addu      	r0, r3
  1a:	07fb      	br      	0x10	// 10 <lmac_rx_iface_queue_count+0x10>
  1c:	00000000 	.long	0x00000000

Disassembly of section .text.get_rx_time_delay:

00000000 <get_rx_time_delay>:
   0:	1066      	lrw      	r3, 0x0	// 18 <get_rx_time_delay+0x18>
   2:	9360      	ld.w      	r3, (r3, 0x0)
   4:	9304      	ld.w      	r0, (r3, 0x10)
   6:	934e      	ld.w      	r2, (r3, 0x38)
   8:	6480      	cmphs      	r0, r2
   a:	936e      	ld.w      	r3, (r3, 0x38)
   c:	0c03      	bf      	0x12	// 12 <get_rx_time_delay+0x12>
   e:	600e      	subu      	r0, r3
  10:	783c      	jmp      	r15
  12:	2800      	subi      	r0, 1
  14:	07fd      	br      	0xe	// e <get_rx_time_delay+0xe>
  16:	0000      	.short	0x0000
  18:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_rx_pv0_ctrl_cts:

00000000 <lmac_rx_pv0_ctrl_cts>:
   0:	14d2      	push      	r4-r5, r15
   2:	127d      	lrw      	r3, 0x0	// 174 <lmac_rx_pv0_ctrl_cts+0x174>
   4:	6d43      	mov      	r5, r0
   6:	d82300c0 	ld.b      	r1, (r3, 0xc0)
   a:	e4412040 	andi      	r2, r1, 64
   e:	129b      	lrw      	r4, 0x0	// 178 <lmac_rx_pv0_ctrl_cts+0x178>
  10:	e902008a 	bez      	r2, 0x124	// 124 <lmac_rx_pv0_ctrl_cts+0x124>
  14:	8024      	ld.b      	r1, (r0, 0x4)
  16:	d8440526 	ld.b      	r2, (r4, 0x526)
  1a:	6486      	cmpne      	r1, r2
  1c:	0882      	bt      	0x120	// 120 <lmac_rx_pv0_ctrl_cts+0x120>
  1e:	8025      	ld.b      	r1, (r0, 0x5)
  20:	d8440527 	ld.b      	r2, (r4, 0x527)
  24:	6486      	cmpne      	r1, r2
  26:	087d      	bt      	0x120	// 120 <lmac_rx_pv0_ctrl_cts+0x120>
  28:	8026      	ld.b      	r1, (r0, 0x6)
  2a:	d8440528 	ld.b      	r2, (r4, 0x528)
  2e:	6486      	cmpne      	r1, r2
  30:	0878      	bt      	0x120	// 120 <lmac_rx_pv0_ctrl_cts+0x120>
  32:	8027      	ld.b      	r1, (r0, 0x7)
  34:	d8440529 	ld.b      	r2, (r4, 0x529)
  38:	6486      	cmpne      	r1, r2
  3a:	0873      	bt      	0x120	// 120 <lmac_rx_pv0_ctrl_cts+0x120>
  3c:	8028      	ld.b      	r1, (r0, 0x8)
  3e:	d844052a 	ld.b      	r2, (r4, 0x52a)
  42:	6486      	cmpne      	r1, r2
  44:	086e      	bt      	0x120	// 120 <lmac_rx_pv0_ctrl_cts+0x120>
  46:	d844052b 	ld.b      	r2, (r4, 0x52b)
  4a:	8029      	ld.b      	r1, (r0, 0x9)
  4c:	6486      	cmpne      	r1, r2
  4e:	c4000502 	mvc      	r2
  52:	d82300c0 	ld.b      	r1, (r3, 0xc0)
  56:	c4225c07 	ins      	r1, r2, 7, 7
  5a:	dc2300c0 	st.b      	r1, (r3, 0xc0)
  5e:	8544      	ld.b      	r2, (r5, 0x4)
  60:	d82300b0 	ld.b      	r1, (r3, 0xb0)
  64:	c4225c01 	ins      	r1, r2, 1, 1
  68:	dc2300b0 	st.b      	r1, (r3, 0xb0)
  6c:	d8240302 	ld.b      	r1, (r4, 0x302)
  70:	6486      	cmpne      	r1, r2
  72:	0872      	bt      	0x156	// 156 <lmac_rx_pv0_ctrl_cts+0x156>
  74:	8525      	ld.b      	r1, (r5, 0x5)
  76:	d8440303 	ld.b      	r2, (r4, 0x303)
  7a:	6486      	cmpne      	r1, r2
  7c:	086d      	bt      	0x156	// 156 <lmac_rx_pv0_ctrl_cts+0x156>
  7e:	8526      	ld.b      	r1, (r5, 0x6)
  80:	d8440304 	ld.b      	r2, (r4, 0x304)
  84:	6486      	cmpne      	r1, r2
  86:	0868      	bt      	0x156	// 156 <lmac_rx_pv0_ctrl_cts+0x156>
  88:	8527      	ld.b      	r1, (r5, 0x7)
  8a:	d8440305 	ld.b      	r2, (r4, 0x305)
  8e:	6486      	cmpne      	r1, r2
  90:	0863      	bt      	0x156	// 156 <lmac_rx_pv0_ctrl_cts+0x156>
  92:	8528      	ld.b      	r1, (r5, 0x8)
  94:	d8440306 	ld.b      	r2, (r4, 0x306)
  98:	6486      	cmpne      	r1, r2
  9a:	085e      	bt      	0x156	// 156 <lmac_rx_pv0_ctrl_cts+0x156>
  9c:	8529      	ld.b      	r1, (r5, 0x9)
  9e:	d8440307 	ld.b      	r2, (r4, 0x307)
  a2:	6486      	cmpne      	r1, r2
  a4:	6443      	mvcv      	r1
  a6:	d84300b0 	ld.b      	r2, (r3, 0xb0)
  aa:	c4415c00 	ins      	r2, r1, 0, 0
  ae:	dc4300b0 	st.b      	r2, (r3, 0xb0)
  b2:	e4422001 	andi      	r2, r2, 1
  b6:	e9220052 	bnez      	r2, 0x15a	// 15a <lmac_rx_pv0_ctrl_cts+0x15a>
  ba:	8523      	ld.b      	r1, (r5, 0x3)
  bc:	8502      	ld.b      	r0, (r5, 0x2)
  be:	4128      	lsli      	r1, r1, 8
  c0:	6c40      	or      	r1, r0
  c2:	dc231049 	st.h      	r1, (r3, 0x92)
  c6:	e9020027 	bez      	r2, 0x114	// 114 <lmac_rx_pv0_ctrl_cts+0x114>
  ca:	d8642266 	ld.w      	r3, (r4, 0x998)
  ce:	3b42      	cmpnei      	r3, 2
  d0:	0847      	bt      	0x15e	// 15e <lmac_rx_pv0_ctrl_cts+0x15e>
  d2:	e0000000 	bsr      	0x0	// 0 <lmac_rx_pv0_ctrl_cts>
  d6:	8563      	ld.b      	r3, (r5, 0x3)
  d8:	8542      	ld.b      	r2, (r5, 0x2)
  da:	4368      	lsli      	r3, r3, 8
  dc:	6cc8      	or      	r3, r2
  de:	64c0      	cmphs      	r0, r3
  e0:	0815      	bt      	0x10a	// 10a <lmac_rx_pv0_ctrl_cts+0x10a>
  e2:	1147      	lrw      	r2, 0x0	// 17c <lmac_rx_pv0_ctrl_cts+0x17c>
  e4:	60c2      	subu      	r3, r0
  e6:	9240      	ld.w      	r2, (r2, 0x0)
  e8:	d8222033 	ld.w      	r1, (r2, 0xcc)
  ec:	ec212000 	ori      	r1, r1, 8192
  f0:	dc222033 	st.w      	r1, (r2, 0xcc)
  f4:	3180      	movi      	r1, 128
  f6:	412c      	lsli      	r1, r1, 12
  f8:	b232      	st.w      	r1, (r2, 0x48)
  fa:	dc622037 	st.w      	r3, (r2, 0xdc)
  fe:	d8622033 	ld.w      	r3, (r2, 0xcc)
 102:	ec631000 	ori      	r3, r3, 4096
 106:	dc622033 	st.w      	r3, (r2, 0xcc)
 10a:	e0000000 	bsr      	0x0	// 0 <lmac_update_frm_tx_vec>
 10e:	3301      	movi      	r3, 1
 110:	dc642265 	st.w      	r3, (r4, 0x994)
 114:	3300      	movi      	r3, 0
 116:	6c0f      	mov      	r0, r3
 118:	2800      	subi      	r0, 1
 11a:	dc642266 	st.w      	r3, (r4, 0x998)
 11e:	1492      	pop      	r4-r5, r15
 120:	3201      	movi      	r2, 1
 122:	0798      	br      	0x52	// 52 <lmac_rx_pv0_ctrl_cts+0x52>
 124:	d84300be 	ld.b      	r2, (r3, 0xbe)
 128:	e4422003 	andi      	r2, r2, 3
 12c:	2a00      	subi      	r2, 1
 12e:	7488      	zextb      	r2, r2
 130:	3a01      	cmphsi      	r2, 2
 132:	0b96      	bt      	0x5e	// 5e <lmac_rx_pv0_ctrl_cts+0x5e>
 134:	d8440668 	ld.b      	r2, (r4, 0x668)
 138:	d8031058 	ld.h      	r0, (r3, 0xb0)
 13c:	c4605560 	zext      	r0, r0, 11, 3
 140:	e4422007 	andi      	r2, r2, 7
 144:	6482      	cmpne      	r0, r2
 146:	c4000500 	mvc      	r0
 14a:	6c87      	mov      	r2, r1
 14c:	c4405c07 	ins      	r2, r0, 7, 7
 150:	dc4300c0 	st.b      	r2, (r3, 0xc0)
 154:	0785      	br      	0x5e	// 5e <lmac_rx_pv0_ctrl_cts+0x5e>
 156:	3100      	movi      	r1, 0
 158:	07a7      	br      	0xa6	// a6 <lmac_rx_pv0_ctrl_cts+0xa6>
 15a:	3100      	movi      	r1, 0
 15c:	07b3      	br      	0xc2	// c2 <lmac_rx_pv0_ctrl_cts+0xc2>
 15e:	e0000000 	bsr      	0x0	// 0 <lmac_get_avg_power>
 162:	6c43      	mov      	r1, r0
 164:	1007      	lrw      	r0, 0x0	// 180 <lmac_rx_pv0_ctrl_cts+0x180>
 166:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 16a:	e0000000 	bsr      	0x0	// 0 <lmac_get_avg_power>
 16e:	e0000000 	bsr      	0x0	// 0 <lmac_update_tx_state_cts>
 172:	07d1      	br      	0x114	// 114 <lmac_rx_pv0_ctrl_cts+0x114>
	...

Disassembly of section .text.update_rx_buff_addr:

00000000 <update_rx_buff_addr>:
   0:	14d7      	push      	r4-r10, r15
   2:	1387      	lrw      	r4, 0x0	// 19c <update_rx_buff_addr+0x19c>
   4:	13a7      	lrw      	r5, 0x0	// 1a0 <update_rx_buff_addr+0x1a0>
   6:	d86409f4 	ld.b      	r3, (r4, 0x9f4)
   a:	e4632001 	andi      	r3, r3, 1
   e:	e903008c 	bez      	r3, 0x126	// 126 <update_rx_buff_addr+0x126>
  12:	d8e40332 	ld.b      	r7, (r4, 0x332)
  16:	e9270088 	bnez      	r7, 0x126	// 126 <update_rx_buff_addr+0x126>
  1a:	d8640333 	ld.b      	r3, (r4, 0x333)
  1e:	c4675c00 	ins      	r3, r7, 0, 0
  22:	dc640333 	st.b      	r3, (r4, 0x333)
  26:	d8642236 	ld.w      	r3, (r4, 0x8d8)
  2a:	dc642279 	st.w      	r3, (r4, 0x9e4)
  2e:	d8642237 	ld.w      	r3, (r4, 0x8dc)
  32:	b5fd      	st.w      	r7, (r5, 0x74)
  34:	dc64227a 	st.w      	r3, (r4, 0x9e8)
  38:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
  3c:	d824227a 	ld.w      	r1, (r4, 0x9e8)
  40:	d8042279 	ld.w      	r0, (r4, 0x9e4)
  44:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_buff>
  48:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
  4c:	e4632002 	andi      	r3, r3, 2
  50:	e9030006 	bez      	r3, 0x5c	// 5c <update_rx_buff_addr+0x5c>
  54:	3304      	movi      	r3, 4
  56:	b57c      	st.w      	r3, (r5, 0x70)
  58:	3300      	movi      	r3, 0
  5a:	b57b      	st.w      	r3, (r5, 0x6c)
  5c:	955d      	ld.w      	r2, (r5, 0x74)
  5e:	957e      	ld.w      	r3, (r5, 0x78)
  60:	60ca      	subu      	r3, r2
  62:	955c      	ld.w      	r2, (r5, 0x70)
  64:	648c      	cmphs      	r3, r2
  66:	0c04      	bf      	0x6e	// 6e <update_rx_buff_addr+0x6e>
  68:	955b      	ld.w      	r2, (r5, 0x6c)
  6a:	648c      	cmphs      	r3, r2
  6c:	0804      	bt      	0x74	// 74 <update_rx_buff_addr+0x74>
  6e:	120e      	lrw      	r0, 0x0	// 1a4 <update_rx_buff_addr+0x1a4>
  70:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  74:	955c      	ld.w      	r2, (r5, 0x70)
  76:	2202      	addi      	r2, 3
  78:	d985201e 	ld.w      	r12, (r5, 0x78)
  7c:	957d      	ld.w      	r3, (r5, 0x74)
  7e:	3a80      	bclri      	r2, 0
  80:	3a81      	bclri      	r2, 1
  82:	c46c0083 	subu      	r3, r12, r3
  86:	648c      	cmphs      	r3, r2
  88:	b55c      	st.w      	r2, (r5, 0x70)
  8a:	0802      	bt      	0x8e	// 8e <update_rx_buff_addr+0x8e>
  8c:	b57c      	st.w      	r3, (r5, 0x70)
  8e:	955c      	ld.w      	r2, (r5, 0x70)
  90:	953b      	ld.w      	r1, (r5, 0x6c)
  92:	6484      	cmphs      	r1, r2
  94:	ea890045 	lrw      	r9, 0x0	// 1a8 <update_rx_buff_addr+0x1a8>
  98:	0858      	bt      	0x148	// 148 <update_rx_buff_addr+0x148>
  9a:	5bc9      	subu      	r6, r3, r2
  9c:	d86409f4 	ld.b      	r3, (r4, 0x9f4)
  a0:	e4632001 	andi      	r3, r3, 1
  a4:	6e07      	mov      	r8, r1
  a6:	e9030046 	bez      	r3, 0x132	// 132 <update_rx_buff_addr+0x132>
  aa:	d8040333 	ld.b      	r0, (r4, 0x333)
  ae:	e5402001 	andi      	r10, r0, 1
  b2:	e92a0040 	bnez      	r10, 0x132	// 132 <update_rx_buff_addr+0x132>
  b6:	d8640332 	ld.b      	r3, (r4, 0x332)
  ba:	e903003c 	bez      	r3, 0x132	// 132 <update_rx_buff_addr+0x132>
  be:	659d      	cmplt      	r7, r6
  c0:	0c39      	bf      	0x132	// 132 <update_rx_buff_addr+0x132>
  c2:	6c43      	mov      	r1, r0
  c4:	3301      	movi      	r3, 1
  c6:	c4235c00 	ins      	r1, r3, 0, 0
  ca:	631e      	subu      	r12, r7
  cc:	957a      	ld.w      	r3, (r5, 0x68)
  ce:	630c      	addu      	r12, r3
  d0:	dd842279 	st.w      	r12, (r4, 0x9e4)
  d4:	dc240333 	st.b      	r1, (r4, 0x333)
  d8:	b5fd      	st.w      	r7, (r5, 0x74)
  da:	dce4227a 	st.w      	r7, (r4, 0x9e8)
  de:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
  e2:	d824227a 	ld.w      	r1, (r4, 0x9e8)
  e6:	d8042279 	ld.w      	r0, (r4, 0x9e4)
  ea:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_buff>
  ee:	5727      	asri      	r1, r7, 7
  f0:	110f      	lrw      	r0, 0x0	// 1ac <update_rx_buff_addr+0x1ac>
  f2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  f6:	6ce3      	mov      	r3, r8
  f8:	6cab      	mov      	r2, r10
  fa:	eb2341bb 	cmplti      	r3, 16828
  fe:	0c33      	bf      	0x164	// 164 <update_rx_buff_addr+0x164>
 100:	d8092000 	ld.w      	r0, (r9, 0x0)
 104:	3100      	movi      	r1, 0
 106:	dc202101 	st.w      	r1, (r0, 0x404)
 10a:	eb2318bc 	cmplti      	r3, 6333
 10e:	dc202102 	st.w      	r1, (r0, 0x408)
 112:	d80421e6 	ld.w      	r0, (r4, 0x798)
 116:	2000      	addi      	r0, 1
 118:	dc0421e6 	st.w      	r0, (r4, 0x798)
 11c:	0832      	bt      	0x180	// 180 <update_rx_buff_addr+0x180>
 11e:	d865009b 	ld.b      	r3, (r5, 0x9b)
 122:	3100      	movi      	r1, 0
 124:	0430      	br      	0x184	// 184 <update_rx_buff_addr+0x184>
 126:	95fe      	ld.w      	r7, (r5, 0x78)
 128:	47e2      	lsli      	r7, r7, 2
 12a:	3305      	movi      	r3, 5
 12c:	c4678027 	divu      	r7, r7, r3
 130:	078c      	br      	0x48	// 48 <update_rx_buff_addr+0x48>
 132:	ea0390bb 	movi      	r3, 37051
 136:	3bb0      	bseti      	r3, 16
 138:	658d      	cmplt      	r3, r6
 13a:	3200      	movi      	r2, 0
 13c:	0813      	bt      	0x162	// 162 <update_rx_buff_addr+0x162>
 13e:	6459      	cmplt      	r6, r1
 140:	0c0f      	bf      	0x15e	// 15e <update_rx_buff_addr+0x15e>
 142:	b55c      	st.w      	r2, (r5, 0x70)
 144:	6cc7      	mov      	r3, r1
 146:	07da      	br      	0xfa	// fa <update_rx_buff_addr+0xfa>
 148:	6448      	cmphs      	r2, r1
 14a:	3600      	movi      	r6, 0
 14c:	0805      	bt      	0x156	// 156 <update_rx_buff_addr+0x156>
 14e:	5949      	subu      	r2, r1, r2
 150:	6ccb      	mov      	r3, r2
 152:	6e1b      	mov      	r8, r6
 154:	07d3      	br      	0xfa	// fa <update_rx_buff_addr+0xfa>
 156:	b5dc      	st.w      	r6, (r5, 0x70)
 158:	b5db      	st.w      	r6, (r5, 0x6c)
 15a:	6c9b      	mov      	r2, r6
 15c:	07fb      	br      	0x152	// 152 <update_rx_buff_addr+0x152>
 15e:	6cdb      	mov      	r3, r6
 160:	07cd      	br      	0xfa	// fa <update_rx_buff_addr+0xfa>
 162:	6cdb      	mov      	r3, r6
 164:	953c      	ld.w      	r1, (r5, 0x70)
 166:	e40100bb 	addi      	r0, r1, 188
 16a:	953a      	ld.w      	r1, (r5, 0x68)
 16c:	6040      	addu      	r1, r0
 16e:	60c4      	addu      	r3, r1
 170:	d8092000 	ld.w      	r0, (r9, 0x0)
 174:	2bbf      	subi      	r3, 192
 176:	dc202101 	st.w      	r1, (r0, 0x404)
 17a:	dc602102 	st.w      	r3, (r0, 0x408)
 17e:	07d0      	br      	0x11e	// 11e <update_rx_buff_addr+0x11e>
 180:	d865009b 	ld.b      	r3, (r5, 0x9b)
 184:	c4615c07 	ins      	r3, r1, 7, 7
 188:	dc65009b 	st.b      	r3, (r5, 0x9b)
 18c:	dd04220b 	st.w      	r8, (r4, 0x82c)
 190:	dc44220c 	st.w      	r2, (r4, 0x830)
 194:	dcc4220d 	st.w      	r6, (r4, 0x834)
 198:	1497      	pop      	r4-r10, r15
	...

Disassembly of section .text.lmac_rx_info_gen:

00000000 <lmac_rx_info_gen>:
   0:	14d5      	push      	r4-r8, r15
   2:	1421      	subi      	r14, r14, 4
   4:	90a6      	ld.w      	r5, (r0, 0x18)
   6:	90c0      	ld.w      	r6, (r0, 0x0)
   8:	8520      	ld.b      	r1, (r5, 0x0)
   a:	d8600038 	ld.b      	r3, (r0, 0x38)
   e:	e4212003 	andi      	r1, r1, 3
  12:	e4c62002 	andi      	r6, r6, 2
  16:	c4615c20 	ins      	r3, r1, 1, 0
  1a:	6d03      	mov      	r4, r0
  1c:	dc600038 	st.b      	r3, (r0, 0x38)
  20:	e9060006 	bez      	r6, 0x2c	// 2c <lmac_rx_info_gen+0x2c>
  24:	3000      	movi      	r0, 0
  26:	2800      	subi      	r0, 1
  28:	1401      	addi      	r14, r14, 4
  2a:	1495      	pop      	r4-r8, r15
  2c:	d8600038 	ld.b      	r3, (r0, 0x38)
  30:	e4e32003 	andi      	r7, r3, 3
  34:	e9270059 	bnez      	r7, 0xe6	// e6 <lmac_rx_info_gen+0xe6>
  38:	8d20      	ld.h      	r1, (r5, 0x0)
  3a:	c4415462 	zext      	r2, r1, 3, 2
  3e:	c4625c42 	ins      	r3, r2, 4, 2
  42:	dc600038 	st.b      	r3, (r0, 0x38)
  46:	8c7c      	ld.h      	r3, (r4, 0x38)
  48:	5104      	asri      	r0, r1, 4
  4a:	c4605c65 	ins      	r3, r0, 8, 5
  4e:	ac7c      	st.h      	r3, (r4, 0x38)
  50:	8561      	ld.b      	r3, (r5, 0x1)
  52:	d9840039 	ld.b      	r12, (r4, 0x39)
  56:	c4235423 	zext      	r3, r3, 1, 1
  5a:	c5835c01 	ins      	r12, r3, 1, 1
  5e:	dd840039 	st.b      	r12, (r4, 0x39)
  62:	d9850001 	ld.b      	r12, (r5, 0x1)
  66:	d8640039 	ld.b      	r3, (r4, 0x39)
  6a:	c46c5c02 	ins      	r3, r12, 2, 2
  6e:	3a43      	cmpnei      	r2, 3
  70:	dc640039 	st.b      	r3, (r4, 0x39)
  74:	8541      	ld.b      	r2, (r5, 0x1)
  76:	d8640039 	ld.b      	r3, (r4, 0x39)
  7a:	e8600279 	bt      	0x56c	// 56c <lmac_rx_info_gen+0x56c>
  7e:	e400200f 	andi      	r0, r0, 15
  82:	3841      	cmpnei      	r0, 1
  84:	e8600274 	bt      	0x56c	// 56c <lmac_rx_info_gen+0x56c>
  88:	e4212003 	andi      	r1, r1, 3
  8c:	e9210270 	bnez      	r1, 0x56c	// 56c <lmac_rx_info_gen+0x56c>
  90:	c4e254e2 	zext      	r2, r2, 7, 7
  94:	c4625c03 	ins      	r3, r2, 3, 3
  98:	dc640039 	st.b      	r3, (r4, 0x39)
  9c:	8561      	ld.b      	r3, (r5, 0x1)
  9e:	c4a354a3 	zext      	r3, r3, 5, 5
  a2:	d8440039 	ld.b      	r2, (r4, 0x39)
  a6:	c4435c04 	ins      	r2, r3, 4, 4
  aa:	dc440039 	st.b      	r2, (r4, 0x39)
  ae:	6c17      	mov      	r0, r5
  b0:	e0000000 	bsr      	0x0	// 0 <lmac_get_hdr_len_pv0>
  b4:	d8240038 	ld.b      	r1, (r4, 0x38)
  b8:	e461201c 	andi      	r3, r1, 28
  bc:	3b48      	cmpnei      	r3, 8
  be:	dc040020 	st.b      	r0, (r4, 0x20)
  c2:	d864003a 	ld.b      	r3, (r4, 0x3a)
  c6:	080e      	bt      	0xe2	// e2 <lmac_rx_info_gen+0xe2>
  c8:	8541      	ld.b      	r2, (r5, 0x1)
  ca:	c4c254c2 	zext      	r2, r2, 6, 6
  ce:	c4415481 	zext      	r1, r1, 4, 2
  d2:	3924      	cmplti      	r1, 5
  d4:	c4625c05 	ins      	r3, r2, 5, 5
  d8:	dc64003a 	st.b      	r3, (r4, 0x3a)
  dc:	0848      	bt      	0x16c	// 16c <lmac_rx_info_gen+0x16c>
  de:	010e      	lrw      	r0, 0x0	// 420 <lmac_rx_info_gen+0x420>
  e0:	0443      	br      	0x166	// 166 <lmac_rx_info_gen+0x166>
  e2:	3200      	movi      	r2, 0
  e4:	07f5      	br      	0xce	// ce <lmac_rx_info_gen+0xce>
  e6:	3f41      	cmpnei      	r7, 1
  e8:	083e      	bt      	0x164	// 164 <lmac_rx_info_gen+0x164>
  ea:	8d40      	ld.h      	r2, (r5, 0x0)
  ec:	5222      	asri      	r1, r2, 2
  ee:	c4615c42 	ins      	r3, r1, 4, 2
  f2:	dc600038 	st.b      	r3, (r0, 0x38)
  f6:	887c      	ld.h      	r3, (r0, 0x38)
  f8:	c4a254e2 	zext      	r2, r2, 7, 5
  fc:	c4625c65 	ins      	r3, r2, 8, 5
 100:	a87c      	st.h      	r3, (r0, 0x38)
 102:	8561      	ld.b      	r3, (r5, 0x1)
 104:	d840003a 	ld.b      	r2, (r0, 0x3a)
 108:	c4835483 	zext      	r3, r3, 4, 4
 10c:	c4435c05 	ins      	r2, r3, 5, 5
 110:	dc40003a 	st.b      	r2, (r0, 0x3a)
 114:	8541      	ld.b      	r2, (r5, 0x1)
 116:	d8600039 	ld.b      	r3, (r0, 0x39)
 11a:	c4625c01 	ins      	r3, r2, 1, 1
 11e:	dc600039 	st.b      	r3, (r0, 0x39)
 122:	8561      	ld.b      	r3, (r5, 0x1)
 124:	d8400039 	ld.b      	r2, (r0, 0x39)
 128:	c4435443 	zext      	r3, r3, 2, 2
 12c:	c4435c03 	ins      	r2, r3, 3, 3
 130:	dc400039 	st.b      	r2, (r0, 0x39)
 134:	8561      	ld.b      	r3, (r5, 0x1)
 136:	d8400039 	ld.b      	r2, (r0, 0x39)
 13a:	c4635463 	zext      	r3, r3, 3, 3
 13e:	c4435c04 	ins      	r2, r3, 4, 4
 142:	dc400039 	st.b      	r2, (r0, 0x39)
 146:	6c17      	mov      	r0, r5
 148:	e0000000 	bsr      	0x0	// 0 <lmac_get_hdr_len_pv1>
 14c:	d864003a 	ld.b      	r3, (r4, 0x3a)
 150:	c4675c06 	ins      	r3, r7, 6, 6
 154:	dc040020 	st.b      	r0, (r4, 0x20)
 158:	dc64003a 	st.b      	r3, (r4, 0x3a)
 15c:	020d      	lrw      	r0, 0x0	// 424 <hgprintf+0x424>
 15e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 162:	0761      	br      	0x24	// 24 <lmac_rx_info_gen+0x24>
 164:	020e      	lrw      	r0, 0x0	// 428 <lmac_rx_info_gen+0x428>
 166:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 16a:	075d      	br      	0x24	// 24 <lmac_rx_info_gen+0x24>
 16c:	9406      	ld.w      	r0, (r4, 0x18)
 16e:	e0000000 	bsr      	0x0	// 0 <lmac_get_tid>
 172:	d864003a 	ld.b      	r3, (r4, 0x3a)
 176:	c4605c61 	ins      	r3, r0, 4, 1
 17a:	dc64003a 	st.b      	r3, (r4, 0x3a)
 17e:	9406      	ld.w      	r0, (r4, 0x18)
 180:	e0000000 	bsr      	0x0	// 0 <lmac_get_seq_num>
 184:	9468      	ld.w      	r3, (r4, 0x20)
 186:	c4605de8 	ins      	r3, r0, 23, 8
 18a:	b468      	st.w      	r3, (r4, 0x20)
 18c:	9426      	ld.w      	r1, (r4, 0x18)
 18e:	e4040025 	addi      	r0, r4, 38
 192:	e4e4002b 	addi      	r7, r4, 44
 196:	e0000000 	bsr      	0x0	// 0 <lmac_get_rx_addr>
 19a:	9426      	ld.w      	r1, (r4, 0x18)
 19c:	6c1f      	mov      	r0, r7
 19e:	e0000000 	bsr      	0x0	// 0 <lmac_get_tx_addr>
 1a2:	d864003a 	ld.b      	r3, (r4, 0x3a)
 1a6:	d8440026 	ld.b      	r2, (r4, 0x26)
 1aa:	c4625c07 	ins      	r3, r2, 7, 7
 1ae:	02bf      	lrw      	r5, 0x0	// 42c <lmac_rx_info_gen+0x42c>
 1b0:	8c53      	ld.h      	r2, (r4, 0x26)
 1b2:	dc64003a 	st.b      	r3, (r4, 0x3a)
 1b6:	d8651181 	ld.h      	r3, (r5, 0x302)
 1ba:	64ca      	cmpne      	r2, r3
 1bc:	0820      	bt      	0x1fc	// 1fc <lmac_rx_info_gen+0x1fc>
 1be:	944a      	ld.w      	r2, (r4, 0x28)
 1c0:	d86520c1 	ld.w      	r3, (r5, 0x304)
 1c4:	64ca      	cmpne      	r2, r3
 1c6:	081b      	bt      	0x1fc	// 1fc <lmac_rx_info_gen+0x1fc>
 1c8:	d86520f0 	ld.w      	r3, (r5, 0x3c0)
 1cc:	d84520f1 	ld.w      	r2, (r5, 0x3c4)
 1d0:	6cc8      	or      	r3, r2
 1d2:	e9030008 	bez      	r3, 0x1e2	// 1e2 <lmac_rx_info_gen+0x1e2>
 1d6:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
 1da:	dc0520f0 	st.w      	r0, (r5, 0x3c0)
 1de:	dc2520f1 	st.w      	r1, (r5, 0x3c4)
 1e2:	d86520f3 	ld.w      	r3, (r5, 0x3cc)
 1e6:	d84520f4 	ld.w      	r2, (r5, 0x3d0)
 1ea:	6cc8      	or      	r3, r2
 1ec:	e9030008 	bez      	r3, 0x1fc	// 1fc <lmac_rx_info_gen+0x1fc>
 1f0:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
 1f4:	dc0520f3 	st.w      	r0, (r5, 0x3cc)
 1f8:	dc2520f4 	st.w      	r1, (r5, 0x3d0)
 1fc:	d86520ce 	ld.w      	r3, (r5, 0x338)
 200:	c4835763 	zext      	r3, r3, 27, 4
 204:	9452      	ld.w      	r2, (r4, 0x48)
 206:	64ca      	cmpne      	r2, r3
 208:	0808      	bt      	0x218	// 218 <lmac_rx_info_gen+0x218>
 20a:	d8650a4f 	ld.b      	r3, (r5, 0xa4f)
 20e:	3200      	movi      	r2, 0
 210:	c4625c01 	ins      	r3, r2, 1, 1
 214:	dc650a4f 	st.b      	r3, (r5, 0xa4f)
 218:	6c5f      	mov      	r1, r7
 21a:	ea00ffff 	movi      	r0, 65535
 21e:	e0000000 	bsr      	0x0	// 0 <lmac_sta_get>
 222:	b405      	st.w      	r0, (r4, 0x14)
 224:	e9000027 	bez      	r0, 0x272	// 272 <lmac_rx_info_gen+0x272>
 228:	d8440039 	ld.b      	r2, (r4, 0x39)
 22c:	d860006b 	ld.b      	r3, (r0, 0x6b)
 230:	c4625462 	zext      	r2, r2, 3, 3
 234:	c4235421 	zext      	r1, r3, 1, 1
 238:	6486      	cmpne      	r1, r2
 23a:	0c11      	bf      	0x25c	// 25c <lmac_rx_info_gen+0x25c>
 23c:	c4625c01 	ins      	r3, r2, 1, 1
 240:	dc60006b 	st.b      	r3, (r0, 0x6b)
 244:	d865227e 	ld.w      	r3, (r5, 0x9f8)
 248:	133a      	lrw      	r1, 0x0	// 430 <lmac_rx_info_gen+0x430>
 24a:	3001      	movi      	r0, 1
 24c:	644e      	cmpne      	r3, r1
 24e:	0851      	bt      	0x2f0	// 2f0 <lmac_rx_info_gen+0x2f0>
 250:	6c5b      	mov      	r1, r6
 252:	1319      	lrw      	r0, 0x0	// 434 <lmac_rx_info_gen+0x434>
 254:	dcc5229d 	st.w      	r6, (r5, 0xa74)
 258:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 25c:	9445      	ld.w      	r2, (r4, 0x14)
 25e:	d8640039 	ld.b      	r3, (r4, 0x39)
 262:	d822006b 	ld.b      	r1, (r2, 0x6b)
 266:	c4835483 	zext      	r3, r3, 4, 4
 26a:	c4235c02 	ins      	r1, r3, 2, 2
 26e:	dc22006b 	st.b      	r1, (r2, 0x6b)
 272:	d844003a 	ld.b      	r2, (r4, 0x3a)
 276:	e4222020 	andi      	r1, r2, 32
 27a:	9465      	ld.w      	r3, (r4, 0x14)
 27c:	e9010056 	bez      	r1, 0x328	// 328 <lmac_rx_info_gen+0x328>
 280:	748a      	sextb      	r2, r2
 282:	e9030047 	bez      	r3, 0x310	// 310 <lmac_rx_info_gen+0x310>
 286:	e9a20042 	bhsz      	r2, 0x30a	// 30a <lmac_rx_info_gen+0x30a>
 28a:	d845202f 	ld.w      	r2, (r5, 0xbc)
 28e:	3a42      	cmpnei      	r2, 2
 290:	0eca      	bf      	0x24	// 24 <lmac_rx_info_gen+0x24>
 292:	d84506b5 	ld.b      	r2, (r5, 0x6b5)
 296:	3a50      	cmpnei      	r2, 16
 298:	0c48      	bf      	0x328	// 328 <lmac_rx_info_gen+0x328>
 29a:	eb420020 	cmpnei      	r2, 32
 29e:	0c45      	bf      	0x328	// 328 <lmac_rx_info_gen+0x328>
 2a0:	d865220a 	ld.w      	r3, (r5, 0x828)
 2a4:	2300      	addi      	r3, 1
 2a6:	dc65220a 	st.w      	r3, (r5, 0x828)
 2aa:	9425      	ld.w      	r1, (r4, 0x14)
 2ac:	e901febc 	bez      	r1, 0x24	// 24 <lmac_rx_info_gen+0x24>
 2b0:	d864403a 	ld.bs      	r3, (r4, 0x3a)
 2b4:	e9a30008 	bhsz      	r3, 0x2c4	// 2c4 <lmac_rx_info_gen+0x2c4>
 2b8:	d86100b9 	ld.b      	r3, (r1, 0xb9)
 2bc:	e4632001 	andi      	r3, r3, 1
 2c0:	e923feb2 	bnez      	r3, 0x24	// 24 <lmac_rx_info_gen+0x24>
 2c4:	d84506b5 	ld.b      	r2, (r5, 0x6b5)
 2c8:	d8610076 	ld.b      	r3, (r1, 0x76)
 2cc:	121b      	lrw      	r0, 0x0	// 438 <lmac_rx_info_gen+0x438>
 2ce:	b840      	st.w      	r2, (r14, 0x0)
 2d0:	9447      	ld.w      	r2, (r4, 0x1c)
 2d2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2d6:	9425      	ld.w      	r1, (r4, 0x14)
 2d8:	3301      	movi      	r3, 1
 2da:	d8410076 	ld.b      	r2, (r1, 0x76)
 2de:	1218      	lrw      	r0, 0x0	// 43c <lmac_rx_info_gen+0x43c>
 2e0:	2176      	addi      	r1, 119
 2e2:	e0000000 	bsr      	0x0	// 0 <dump_hex>
 2e6:	3110      	movi      	r1, 16
 2e8:	9406      	ld.w      	r0, (r4, 0x18)
 2ea:	e0000000 	bsr      	0x0	// 0 <hgics_print_hex>
 2ee:	069b      	br      	0x24	// 24 <lmac_rx_info_gen+0x24>
 2f0:	d843006b 	ld.b      	r2, (r3, 0x6b)
 2f4:	e4422002 	andi      	r2, r2, 2
 2f8:	e9020007 	bez      	r2, 0x306	// 306 <lmac_rx_info_gen+0x306>
 2fc:	d8431034 	ld.h      	r2, (r3, 0x68)
 300:	c4404022 	lsl      	r2, r0, r2
 304:	6d88      	or      	r6, r2
 306:	9360      	ld.w      	r3, (r3, 0x0)
 308:	07a2      	br      	0x24c	// 24c <lmac_rx_info_gen+0x24c>
 30a:	d8430076 	ld.b      	r2, (r3, 0x76)
 30e:	07c4      	br      	0x296	// 296 <lmac_rx_info_gen+0x296>
 310:	e982ffcd 	blz      	r2, 0x2aa	// 2aa <lmac_rx_info_gen+0x2aa>
 314:	9500      	ld.w      	r0, (r5, 0x0)
 316:	d9802009 	ld.w      	r12, (r0, 0x24)
 31a:	e90cffc8 	bez      	r12, 0x2aa	// 2aa <lmac_rx_info_gen+0x2aa>
 31e:	3306      	movi      	r3, 6
 320:	6c9f      	mov      	r2, r7
 322:	3122      	movi      	r1, 34
 324:	7bf1      	jsr      	r12
 326:	07c2      	br      	0x2aa	// 2aa <lmac_rx_info_gen+0x2aa>
 328:	9440      	ld.w      	r2, (r4, 0x0)
 32a:	e4422005 	andi      	r2, r2, 5
 32e:	3a45      	cmpnei      	r2, 5
 330:	0868      	bt      	0x400	// 400 <lmac_rx_info_gen+0x400>
 332:	e9030067 	bez      	r3, 0x400	// 400 <lmac_rx_info_gen+0x400>
 336:	d8440026 	ld.b      	r2, (r4, 0x26)
 33a:	e4422001 	andi      	r2, r2, 1
 33e:	e9220061 	bnez      	r2, 0x400	// 400 <lmac_rx_info_gen+0x400>
 342:	d8440038 	ld.b      	r2, (r4, 0x38)
 346:	e442201f 	andi      	r2, r2, 31
 34a:	3a48      	cmpnei      	r2, 8
 34c:	085a      	bt      	0x400	// 400 <lmac_rx_info_gen+0x400>
 34e:	8c5e      	ld.h      	r2, (r4, 0x3c)
 350:	dc431036 	st.h      	r2, (r3, 0x6c)
 354:	d8044051 	ld.bs      	r0, (r4, 0x51)
 358:	dc0300b6 	st.b      	r0, (r3, 0xb6)
 35c:	d824003e 	ld.b      	r1, (r4, 0x3e)
 360:	d84300b7 	ld.b      	r2, (r3, 0xb7)
 364:	c4415c60 	ins      	r2, r1, 3, 0
 368:	4924      	lsri      	r1, r1, 4
 36a:	c4415c64 	ins      	r2, r1, 7, 4
 36e:	dc4300b7 	st.b      	r2, (r3, 0xb7)
 372:	d8450308 	ld.b      	r2, (r5, 0x308)
 376:	11d3      	lrw      	r6, 0x0	// 440 <lmac_rx_info_gen+0x440>
 378:	d0460022 	ldr.b      	r2, (r6, r2 << 0)
 37c:	6486      	cmpne      	r1, r2
 37e:	d844003e 	ld.b      	r2, (r4, 0x3e)
 382:	0c06      	bf      	0x38e	// 38e <lmac_rx_info_gen+0x38e>
 384:	e44220f0 	andi      	r2, r2, 240
 388:	eb420030 	cmpnei      	r2, 48
 38c:	0836      	bt      	0x3f8	// 3f8 <lmac_rx_info_gen+0x3f8>
 38e:	d84300a0 	ld.b      	r2, (r3, 0xa0)
 392:	d8250317 	ld.b      	r1, (r5, 0x317)
 396:	6448      	cmphs      	r2, r1
 398:	0827      	bt      	0x3e6	// 3e6 <lmac_rx_info_gen+0x3e6>
 39a:	d8232027 	ld.w      	r1, (r3, 0x9c)
 39e:	e5820000 	addi      	r12, r2, 1
 3a2:	dd8300a0 	st.b      	r12, (r3, 0xa0)
 3a6:	d4410020 	str.b      	r0, (r1, r2 << 0)
 3aa:	9465      	ld.w      	r3, (r4, 0x14)
 3ac:	d84300a0 	ld.b      	r2, (r3, 0xa0)
 3b0:	d8650317 	ld.b      	r3, (r5, 0x317)
 3b4:	64c8      	cmphs      	r2, r3
 3b6:	0c18      	bf      	0x3e6	// 3e6 <lmac_rx_info_gen+0x3e6>
 3b8:	d84522a1 	ld.w      	r2, (r5, 0xa84)
 3bc:	5a62      	addi      	r3, r2, 1
 3be:	d82522a2 	ld.w      	r1, (r5, 0xa88)
 3c2:	644d      	cmplt      	r3, r1
 3c4:	5b05      	subu      	r0, r3, r1
 3c6:	c4600c20 	incf      	r3, r0, 0
 3ca:	d82522a0 	ld.w      	r1, (r5, 0xa80)
 3ce:	64c6      	cmpne      	r1, r3
 3d0:	0c08      	bf      	0x3e0	// 3e0 <lmac_rx_info_gen+0x3e0>
 3d2:	e44202a2 	addi      	r2, r2, 675
 3d6:	3102      	movi      	r1, 2
 3d8:	d4450881 	str.w      	r1, (r5, r2 << 2)
 3dc:	dc6522a1 	st.w      	r3, (r5, 0xa84)
 3e0:	1019      	lrw      	r0, 0x0	// 444 <os_sema_up+0x444>
 3e2:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
 3e6:	d8250308 	ld.b      	r1, (r5, 0x308)
 3ea:	d864003e 	ld.b      	r3, (r4, 0x3e)
 3ee:	4b64      	lsri      	r3, r3, 4
 3f0:	d0260022 	ldr.b      	r2, (r6, r1 << 0)
 3f4:	648e      	cmpne      	r3, r2
 3f6:	0c29      	bf      	0x448	// 448 <lmac_rx_info_gen+0x448>
 3f8:	d8644050 	ld.bs      	r3, (r4, 0x50)
 3fc:	e9230090 	bnez      	r3, 0x51c	// 51c <lmac_rx_info_gen+0x51c>
 400:	d86521dc 	ld.w      	r3, (r5, 0x770)
 404:	2300      	addi      	r3, 1
 406:	9407      	ld.w      	r0, (r4, 0x1c)
 408:	dc6521dc 	st.w      	r3, (r5, 0x770)
 40c:	d86521dd 	ld.w      	r3, (r5, 0x774)
 410:	60c0      	addu      	r3, r0
 412:	dc6521dd 	st.w      	r3, (r5, 0x774)
 416:	9465      	ld.w      	r3, (r4, 0x14)
 418:	e9230086 	bnez      	r3, 0x524	// 524 <lmac_rx_info_gen+0x524>
 41c:	3000      	movi      	r0, 0
 41e:	0605      	br      	0x28	// 28 <lmac_rx_info_gen+0x28>
	...
 448:	d864003f 	ld.b      	r3, (r4, 0x3f)
 44c:	9405      	ld.w      	r0, (r4, 0x14)
 44e:	e4632003 	andi      	r3, r3, 3
 452:	60c0      	addu      	r3, r0
 454:	d84300a5 	ld.b      	r2, (r3, 0xa5)
 458:	2200      	addi      	r2, 1
 45a:	dc4300a5 	st.b      	r2, (r3, 0xa5)
 45e:	d86000a4 	ld.b      	r3, (r0, 0xa4)
 462:	2300      	addi      	r3, 1
 464:	74cc      	zextb      	r3, r3
 466:	dc6000a4 	st.b      	r3, (r0, 0xa4)
 46a:	d84511df 	ld.h      	r2, (r5, 0x3be)
 46e:	648c      	cmphs      	r3, r2
 470:	0fc4      	bf      	0x3f8	// 3f8 <lmac_rx_info_gen+0x3f8>
 472:	d8e5034a 	ld.b      	r7, (r5, 0x34a)
 476:	e4e72001 	andi      	r7, r7, 1
 47a:	d86000ae 	ld.b      	r3, (r0, 0xae)
 47e:	e9070030 	bez      	r7, 0x4de	// 4de <lmac_rx_info_gen+0x4de>
 482:	3203      	movi      	r2, 3
 484:	c4625c64 	ins      	r3, r2, 7, 4
 488:	dc6000ae 	st.b      	r3, (r0, 0xae)
 48c:	d86000ae 	ld.b      	r3, (r0, 0xae)
 490:	ea8c0039 	lrw      	r12, 0x0	// 574 <lmac_rx_info_gen+0x574>
 494:	4b44      	lsri      	r2, r3, 4
 496:	d04c0022 	ldr.b      	r2, (r12, r2 << 0)
 49a:	6484      	cmphs      	r1, r2
 49c:	0813      	bt      	0x4c2	// 4c2 <lmac_rx_info_gen+0x4c2>
 49e:	d0260022 	ldr.b      	r2, (r6, r1 << 0)
 4a2:	c4625c64 	ins      	r3, r2, 7, 4
 4a6:	dc6000ae 	st.b      	r3, (r0, 0xae)
 4aa:	d84000a6 	ld.b      	r2, (r0, 0xa6)
 4ae:	d86000a7 	ld.b      	r3, (r0, 0xa7)
 4b2:	d82000a5 	ld.b      	r1, (r0, 0xa5)
 4b6:	d80000a8 	ld.b      	r0, (r0, 0xa8)
 4ba:	b800      	st.w      	r0, (r14, 0x0)
 4bc:	110f      	lrw      	r0, 0x0	// 578 <lmac_rx_info_gen+0x578>
 4be:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 4c2:	9445      	ld.w      	r2, (r4, 0x14)
 4c4:	3100      	movi      	r1, 0
 4c6:	dc2200a4 	st.b      	r1, (r2, 0xa4)
 4ca:	e46200a4 	addi      	r3, r2, 165
 4ce:	22a8      	addi      	r2, 169
 4d0:	8300      	ld.b      	r0, (r3, 0x0)
 4d2:	a304      	st.b      	r0, (r3, 0x4)
 4d4:	a320      	st.b      	r1, (r3, 0x0)
 4d6:	2300      	addi      	r3, 1
 4d8:	64ca      	cmpne      	r2, r3
 4da:	0bfb      	bt      	0x4d0	// 4d0 <lmac_rx_info_gen+0x4d0>
 4dc:	078e      	br      	0x3f8	// 3f8 <lmac_rx_info_gen+0x3f8>
 4de:	d90000a7 	ld.b      	r8, (r0, 0xa7)
 4e2:	d84000a6 	ld.b      	r2, (r0, 0xa6)
 4e6:	d9a000a8 	ld.b      	r13, (r0, 0xa8)
 4ea:	60a0      	addu      	r2, r8
 4ec:	c5a8002c 	addu      	r12, r8, r13
 4f0:	60b4      	addu      	r2, r13
 4f2:	c44c482c 	lsli      	r12, r12, 2
 4f6:	6088      	addu      	r2, r2
 4f8:	6708      	cmphs      	r2, r12
 4fa:	0c0d      	bf      	0x514	// 514 <lmac_rx_info_gen+0x514>
 4fc:	c4675c64 	ins      	r3, r7, 7, 4
 500:	dc6000ae 	st.b      	r3, (r0, 0xae)
 504:	c46d4823 	lsli      	r3, r13, 3
 508:	64f0      	cmphs      	r12, r3
 50a:	0bc1      	bt      	0x48c	// 48c <lmac_rx_info_gen+0x48c>
 50c:	d86000ae 	ld.b      	r3, (r0, 0xae)
 510:	3202      	movi      	r2, 2
 512:	07b9      	br      	0x484	// 484 <lmac_rx_info_gen+0x484>
 514:	3201      	movi      	r2, 1
 516:	c4625c64 	ins      	r3, r2, 7, 4
 51a:	07f3      	br      	0x500	// 500 <lmac_rx_info_gen+0x500>
 51c:	9445      	ld.w      	r2, (r4, 0x14)
 51e:	dc6200b5 	st.b      	r3, (r2, 0xb5)
 522:	076f      	br      	0x400	// 400 <lmac_rx_info_gen+0x400>
 524:	d8432079 	ld.w      	r2, (r3, 0x1e4)
 528:	6080      	addu      	r2, r0
 52a:	dc432079 	st.w      	r2, (r3, 0x1e4)
 52e:	9440      	ld.w      	r2, (r4, 0x0)
 530:	d82310f1 	ld.h      	r1, (r3, 0x1e2)
 534:	e4422001 	andi      	r2, r2, 1
 538:	2100      	addi      	r1, 1
 53a:	dc2310f1 	st.h      	r1, (r3, 0x1e2)
 53e:	e902ff6f 	bez      	r2, 0x41c	// 41c <lmac_rx_info_gen+0x41c>
 542:	d84310f0 	ld.h      	r2, (r3, 0x1e0)
 546:	2200      	addi      	r2, 1
 548:	9431      	ld.w      	r1, (r4, 0x44)
 54a:	dc4310f0 	st.h      	r2, (r3, 0x1e0)
 54e:	d843207a 	ld.w      	r2, (r3, 0x1e8)
 552:	6084      	addu      	r2, r1
 554:	dc43207a 	st.w      	r2, (r3, 0x1e8)
 558:	9430      	ld.w      	r1, (r4, 0x40)
 55a:	d843207c 	ld.w      	r2, (r3, 0x1f0)
 55e:	6084      	addu      	r2, r1
 560:	dc43207c 	st.w      	r2, (r3, 0x1f0)
 564:	9453      	ld.w      	r2, (r4, 0x4c)
 566:	dc43207b 	st.w      	r2, (r3, 0x1ec)
 56a:	0759      	br      	0x41c	// 41c <lmac_rx_info_gen+0x41c>
 56c:	c4825482 	zext      	r2, r2, 4, 4
 570:	e800fd92 	br      	0x94	// 94 <lmac_rx_info_gen+0x94>
	...

Disassembly of section .text.lmac_rx_radio_info_check:

00000000 <lmac_rx_radio_info_check>:
   0:	14d2      	push      	r4-r5, r15
   2:	118a      	lrw      	r4, 0x0	// a8 <lmac_rx_radio_info_check+0xa8>
   4:	3200      	movi      	r2, 0
   6:	d8640378 	ld.b      	r3, (r4, 0x378)
   a:	6c4b      	mov      	r1, r2
   c:	64c5      	cmplt      	r1, r3
   e:	0818      	bt      	0x3e	// 3e <lmac_rx_radio_info_check+0x3e>
  10:	e9030023 	bez      	r3, 0x56	// 56 <lmac_rx_radio_info_check+0x56>
  14:	d84409e2 	ld.b      	r2, (r4, 0x9e2)
  18:	e4422002 	andi      	r2, r2, 2
  1c:	e922001d 	bnez      	r2, 0x56	// 56 <lmac_rx_radio_info_check+0x56>
  20:	3218      	movi      	r2, 24
  22:	2b00      	subi      	r3, 1
  24:	7cc8      	mult      	r3, r2
  26:	60d0      	addu      	r3, r4
  28:	9032      	ld.w      	r1, (r0, 0x48)
  2a:	d8632030 	ld.w      	r3, (r3, 0xc0)
  2e:	d8442030 	ld.w      	r2, (r4, 0xc0)
  32:	101f      	lrw      	r0, 0x0	// ac <hgprintf+0xac>
  34:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  38:	3000      	movi      	r0, 0
  3a:	2800      	subi      	r0, 1
  3c:	1492      	pop      	r4-r5, r15
  3e:	2217      	addi      	r2, 24
  40:	ea8c001a 	lrw      	r12, 0x0	// a8 <lmac_rx_radio_info_check+0xa8>
  44:	6308      	addu      	r12, r2
  46:	d9a02012 	ld.w      	r13, (r0, 0x48)
  4a:	d98c202a 	ld.w      	r12, (r12, 0xa8)
  4e:	6736      	cmpne      	r13, r12
  50:	0c03      	bf      	0x56	// 56 <lmac_rx_radio_info_check+0x56>
  52:	2100      	addi      	r1, 1
  54:	07dc      	br      	0xc	// c <lmac_rx_radio_info_check+0xc>
  56:	d860003e 	ld.b      	r3, (r0, 0x3e)
  5a:	e423200f 	andi      	r1, r3, 15
  5e:	3927      	cmplti      	r1, 8
  60:	0807      	bt      	0x6e	// 6e <lmac_rx_radio_info_check+0x6e>
  62:	394a      	cmpnei      	r1, 10
  64:	0c05      	bf      	0x6e	// 6e <lmac_rx_radio_info_check+0x6e>
  66:	1013      	lrw      	r0, 0x0	// b0 <lmac_rx_radio_info_check+0xb0>
  68:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  6c:	07e6      	br      	0x38	// 38 <lmac_rx_radio_info_check+0x38>
  6e:	d8604051 	ld.bs      	r3, (r0, 0x51)
  72:	e9630005 	blsz      	r3, 0x7c	// 7c <lmac_rx_radio_info_check+0x7c>
  76:	3300      	movi      	r3, 0
  78:	dc600051 	st.b      	r3, (r0, 0x51)
  7c:	104e      	lrw      	r2, 0x0	// b4 <lmac_rx_radio_info_check+0xb4>
  7e:	3364      	movi      	r3, 100
  80:	9012      	ld.w      	r0, (r0, 0x48)
  82:	c4608023 	divu      	r3, r0, r3
  86:	d84210a5 	ld.h      	r2, (r2, 0x14a)
  8a:	648e      	cmpne      	r3, r2
  8c:	0c0c      	bf      	0xa4	// a4 <lmac_rx_radio_info_check+0xa4>
  8e:	10ab      	lrw      	r5, 0x0	// b8 <lmac_rx_radio_info_check+0xb8>
  90:	d84414ed 	ld.h      	r2, (r4, 0x9da)
  94:	8d60      	ld.h      	r3, (r5, 0x0)
  96:	64ca      	cmpne      	r2, r3
  98:	0c06      	bf      	0xa4	// a4 <lmac_rx_radio_info_check+0xa4>
  9a:	e0000000 	bsr      	0x0	// 0 <lmac_notify_channel_switch>
  9e:	d86414ed 	ld.h      	r3, (r4, 0x9da)
  a2:	ad60      	st.h      	r3, (r5, 0x0)
  a4:	3000      	movi      	r0, 0
  a6:	07cb      	br      	0x3c	// 3c <lmac_rx_radio_info_check+0x3c>
	...

Disassembly of section .text.hgic_hdr_update:

00000000 <hgic_hdr_update>:
   0:	14d3      	push      	r4-r6, r15
   2:	90c0      	ld.w      	r6, (r0, 0x0)
   4:	e4c62001 	andi      	r6, r6, 1
   8:	6d03      	mov      	r4, r0
   a:	e9060064 	bez      	r6, 0xd2	// d2 <hgic_hdr_update+0xd2>
   e:	e0000000 	bsr      	0x0	// 0 <hgic_hdr_update>
  12:	6d83      	mov      	r6, r0
  14:	11b4      	lrw      	r5, 0x0	// e4 <hgic_hdr_update+0xe4>
  16:	e9200044 	bnez      	r0, 0x9e	// 9e <hgic_hdr_update+0x9e>
  1a:	320c      	movi      	r2, 12
  1c:	6c43      	mov      	r1, r0
  1e:	e4050145 	addi      	r0, r5, 326
  22:	e0000000 	bsr      	0x0	// 0 <memset>
  26:	3303      	movi      	r3, 3
  28:	dc650146 	st.b      	r3, (r5, 0x146)
  2c:	d844003e 	ld.b      	r2, (r4, 0x3e)
  30:	d8650147 	ld.b      	r3, (r5, 0x147)
  34:	c4625c60 	ins      	r3, r2, 3, 0
  38:	dc650147 	st.b      	r3, (r5, 0x147)
  3c:	d864003e 	ld.b      	r3, (r4, 0x3e)
  40:	e44320f0 	andi      	r2, r3, 240
  44:	eb420030 	cmpnei      	r2, 48
  48:	0c29      	bf      	0x9a	// 9a <hgic_hdr_update+0x9a>
  4a:	4b44      	lsri      	r2, r3, 4
  4c:	3302      	movi      	r3, 2
  4e:	70c8      	lsl      	r3, r2
  50:	d8450147 	ld.b      	r2, (r5, 0x147)
  54:	c4435c64 	ins      	r2, r3, 7, 4
  58:	dc450147 	st.b      	r2, (r5, 0x147)
  5c:	d8640051 	ld.b      	r3, (r4, 0x51)
  60:	dc650148 	st.b      	r3, (r5, 0x148)
  64:	9445      	ld.w      	r2, (r4, 0x14)
  66:	e9020024 	bez      	r2, 0xae	// ae <hgic_hdr_update+0xae>
  6a:	d8640038 	ld.b      	r3, (r4, 0x38)
  6e:	e463201c 	andi      	r3, r3, 28
  72:	e9030004 	bez      	r3, 0x7a	// 7a <hgic_hdr_update+0x7a>
  76:	3b4c      	cmpnei      	r3, 12
  78:	080e      	bt      	0x94	// 94 <hgic_hdr_update+0x94>
  7a:	3300      	movi      	r3, 0
  7c:	d8244050 	ld.bs      	r1, (r4, 0x50)
  80:	2b7f      	subi      	r3, 128
  82:	64c6      	cmpne      	r1, r3
  84:	0c08      	bf      	0x94	// 94 <hgic_hdr_update+0x94>
  86:	9460      	ld.w      	r3, (r4, 0x0)
  88:	e4632004 	andi      	r3, r3, 4
  8c:	e9030004 	bez      	r3, 0x94	// 94 <hgic_hdr_update+0x94>
  90:	dc2200b8 	st.b      	r1, (r2, 0xb8)
  94:	d86200b8 	ld.b      	r3, (r2, 0xb8)
  98:	040d      	br      	0xb2	// b2 <hgic_hdr_update+0xb2>
  9a:	3301      	movi      	r3, 1
  9c:	07da      	br      	0x50	// 50 <hgic_hdr_update+0x50>
  9e:	3300      	movi      	r3, 0
  a0:	dc650146 	st.b      	r3, (r5, 0x146)
  a4:	3300      	movi      	r3, 0
  a6:	2b7f      	subi      	r3, 128
  a8:	dc650149 	st.b      	r3, (r5, 0x149)
  ac:	0413      	br      	0xd2	// d2 <hgic_hdr_update+0xd2>
  ae:	d8640050 	ld.b      	r3, (r4, 0x50)
  b2:	104e      	lrw      	r2, 0x0	// e8 <hgic_hdr_update+0xe8>
  b4:	d84203e0 	ld.b      	r2, (r2, 0x3e0)
  b8:	60c8      	addu      	r3, r2
  ba:	dc650149 	st.b      	r3, (r5, 0x149)
  be:	9472      	ld.w      	r3, (r4, 0x48)
  c0:	3264      	movi      	r2, 100
  c2:	c4438023 	divu      	r3, r3, r2
  c6:	dc6510a5 	st.h      	r3, (r5, 0x14a)
  ca:	d8641026 	ld.h      	r3, (r4, 0x4c)
  ce:	dc6510a6 	st.h      	r3, (r5, 0x14c)
  d2:	320c      	movi      	r2, 12
  d4:	1026      	lrw      	r1, 0x0	// ec <hgic_hdr_update+0xec>
  d6:	e4040067 	addi      	r0, r4, 104
  da:	e0000000 	bsr      	0x0	// 0 <memcpy>
  de:	6c1b      	mov      	r0, r6
  e0:	1493      	pop      	r4-r6, r15
	...

Disassembly of section .text.lmac_decrypt_hdl:

00000000 <lmac_decrypt_hdl>:
   0:	14d5      	push      	r4-r8, r15
   2:	d880003a 	ld.b      	r4, (r0, 0x3a)
   6:	e4842020 	andi      	r4, r4, 32
   a:	6d83      	mov      	r6, r0
   c:	e9040019 	bez      	r4, 0x3e	// 3e <lmac_decrypt_hdl+0x3e>
  10:	d8200038 	ld.b      	r1, (r0, 0x38)
  14:	e4e12003 	andi      	r7, r1, 3
  18:	90a6      	ld.w      	r5, (r0, 0x18)
  1a:	e9270014 	bnez      	r7, 0x42	// 42 <lmac_decrypt_hdl+0x42>
  1e:	e0000000 	bsr      	0x0	// 0 <lmac_decrypt_hdl>
  22:	9666      	ld.w      	r3, (r6, 0x18)
  24:	64d6      	cmpne      	r5, r3
  26:	6d03      	mov      	r4, r0
  28:	0806      	bt      	0x34	// 34 <lmac_decrypt_hdl+0x34>
  2a:	8561      	ld.b      	r3, (r5, 0x1)
  2c:	c4675c06 	ins      	r3, r7, 6, 6
  30:	a561      	st.b      	r3, (r5, 0x1)
  32:	0406      	br      	0x3e	// 3e <lmac_decrypt_hdl+0x3e>
  34:	0312      	lrw      	r0, 0x0	// 268 <lmac_decrypt_hdl+0x268>
  36:	3400      	movi      	r4, 0
  38:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  3c:	2c00      	subi      	r4, 1
  3e:	6c13      	mov      	r0, r4
  40:	1495      	pop      	r4-r8, r15
  42:	3f41      	cmpnei      	r7, 1
  44:	090a      	bt      	0x258	// 258 <lmac_decrypt_hdl+0x258>
  46:	0395      	lrw      	r4, 0x0	// 26c <lmac_decrypt_hdl+0x26c>
  48:	3310      	movi      	r3, 16
  4a:	dc640144 	st.b      	r3, (r4, 0x144)
  4e:	d8600038 	ld.b      	r3, (r0, 0x38)
  52:	c4435483 	zext      	r3, r3, 4, 2
  56:	3b02      	cmphsi      	r3, 3
  58:	0807      	bt      	0x66	// 66 <lmac_decrypt_hdl+0x66>
  5a:	3b40      	cmpnei      	r3, 0
  5c:	0c09      	bf      	0x6e	// 6e <lmac_decrypt_hdl+0x6e>
  5e:	031a      	lrw      	r0, 0x0	// 270 <lmac_decrypt_hdl+0x270>
  60:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  64:	0449      	br      	0xf6	// f6 <lmac_decrypt_hdl+0xf6>
  66:	3b43      	cmpnei      	r3, 3
  68:	0cce      	bf      	0x204	// 204 <lmac_decrypt_hdl+0x204>
  6a:	031c      	lrw      	r0, 0x0	// 274 <lmac_decrypt_hdl+0x274>
  6c:	07fa      	br      	0x60	// 60 <lmac_decrypt_hdl+0x60>
  6e:	856b      	ld.b      	r3, (r5, 0xb)
  70:	854a      	ld.b      	r2, (r5, 0xa)
  72:	4368      	lsli      	r3, r3, 8
  74:	6cc8      	or      	r3, r2
  76:	a872      	st.h      	r3, (r0, 0x24)
  78:	d8600039 	ld.b      	r3, (r0, 0x39)
  7c:	e4632002 	andi      	r3, r3, 2
  80:	3206      	movi      	r2, 6
  82:	e903007f 	bez      	r3, 0x180	// 180 <lmac_decrypt_hdl+0x180>
  86:	133d      	lrw      	r1, 0x0	// 278 <lmac_decrypt_hdl+0x278>
  88:	e40400fb 	addi      	r0, r4, 252
  8c:	e0000000 	bsr      	0x0	// 0 <memcpy>
  90:	3206      	movi      	r2, 6
  92:	e4260025 	addi      	r1, r6, 38
  96:	e4040101 	addi      	r0, r4, 258
  9a:	e0000000 	bsr      	0x0	// 0 <memcpy>
  9e:	8563      	ld.b      	r3, (r5, 0x3)
  a0:	e4632020 	andi      	r3, r3, 32
  a4:	e903006b 	bez      	r3, 0x17a	// 17a <lmac_decrypt_hdl+0x17a>
  a8:	3206      	movi      	r2, 6
  aa:	e425000b 	addi      	r1, r5, 12
  ae:	e4040109 	addi      	r0, r4, 266
  b2:	e0000000 	bsr      	0x0	// 0 <memcpy>
  b6:	3316      	movi      	r3, 22
  b8:	dc640144 	st.b      	r3, (r4, 0x144)
  bc:	e404010f 	addi      	r0, r4, 272
  c0:	8563      	ld.b      	r3, (r5, 0x3)
  c2:	e4632040 	andi      	r3, r3, 64
  c6:	e903000c 	bez      	r3, 0xde	// de <lmac_decrypt_hdl+0xde>
  ca:	3206      	movi      	r2, 6
  cc:	e4250011 	addi      	r1, r5, 18
  d0:	e0000000 	bsr      	0x0	// 0 <memcpy>
  d4:	d8640144 	ld.b      	r3, (r4, 0x144)
  d8:	2305      	addi      	r3, 6
  da:	dc640144 	st.b      	r3, (r4, 0x144)
  de:	8d60      	ld.h      	r3, (r5, 0x0)
  e0:	e46323ff 	andi      	r3, r3, 1023
  e4:	ec631000 	ori      	r3, r3, 4096
  e8:	dc64107d 	st.h      	r3, (r4, 0xfa)
  ec:	8e72      	ld.h      	r3, (r6, 0x24)
  ee:	e463200f 	andi      	r3, r3, 15
  f2:	dc641084 	st.h      	r3, (r4, 0x108)
  f6:	d8440116 	ld.b      	r2, (r4, 0x116)
  fa:	e44220e0 	andi      	r2, r2, 224
  fe:	ea080001 	movi      	r8, 1
 102:	3700      	movi      	r7, 0
 104:	c4485c05 	ins      	r2, r8, 5, 5
 108:	123d      	lrw      	r1, 0x0	// 27c <lmac_decrypt_hdl+0x27c>
 10a:	c4475c26 	ins      	r2, r7, 7, 6
 10e:	dc440116 	st.b      	r2, (r4, 0x116)
 112:	e4010014 	addi      	r0, r1, 21
 116:	3206      	movi      	r2, 6
 118:	e0000000 	bsr      	0x0	// 0 <memcpy>
 11c:	337b      	movi      	r3, 123
 11e:	dce40122 	st.b      	r7, (r4, 0x122)
 122:	dce40121 	st.b      	r7, (r4, 0x121)
 126:	dce40120 	st.b      	r7, (r4, 0x120)
 12a:	dc64011f 	st.b      	r3, (r4, 0x11f)
 12e:	8e72      	ld.h      	r3, (r6, 0x24)
 130:	4b48      	lsri      	r2, r3, 8
 132:	6c1b      	mov      	r0, r6
 134:	dc44011e 	st.b      	r2, (r4, 0x11e)
 138:	dc64011d 	st.b      	r3, (r4, 0x11d)
 13c:	e0000000 	bsr      	0x0	// 0 <lmac_decrypt_hdl>
 140:	6d03      	mov      	r4, r0
 142:	e9200017 	bnez      	r0, 0x170	// 170 <lmac_decrypt_hdl+0x170>
 146:	122f      	lrw      	r1, 0x0	// 280 <lmac_decrypt_hdl+0x280>
 148:	120f      	lrw      	r0, 0x0	// 284 <lmac_decrypt_hdl+0x284>
 14a:	e0000000 	bsr      	0x0	// 0 <ah_ce_start>
 14e:	6cdf      	mov      	r3, r7
 150:	60e2      	subu      	r3, r8
 152:	64c2      	cmpne      	r0, r3
 154:	6d03      	mov      	r4, r0
 156:	080d      	bt      	0x170	// 170 <lmac_decrypt_hdl+0x170>
 158:	126c      	lrw      	r3, 0x0	// 288 <lmac_decrypt_hdl+0x288>
 15a:	120d      	lrw      	r0, 0x0	// 28c <lmac_decrypt_hdl+0x28c>
 15c:	d8432209 	ld.w      	r2, (r3, 0x824)
 160:	60a0      	addu      	r2, r8
 162:	dc432209 	st.w      	r2, (r3, 0x824)
 166:	9626      	ld.w      	r1, (r6, 0x18)
 168:	6ce3      	mov      	r3, r8
 16a:	9647      	ld.w      	r2, (r6, 0x1c)
 16c:	e0000000 	bsr      	0x0	// 0 <dump_hex>
 170:	8561      	ld.b      	r3, (r5, 0x1)
 172:	3200      	movi      	r2, 0
 174:	c4625c04 	ins      	r3, r2, 4, 4
 178:	075c      	br      	0x30	// 30 <lmac_decrypt_hdl+0x30>
 17a:	e4040109 	addi      	r0, r4, 266
 17e:	07a1      	br      	0xc0	// c0 <lmac_decrypt_hdl+0xc0>
 180:	5d26      	addi      	r1, r5, 2
 182:	e40400fb 	addi      	r0, r4, 252
 186:	e0000000 	bsr      	0x0	// 0 <memcpy>
 18a:	8d04      	ld.h      	r0, (r5, 0x8)
 18c:	e0000000 	bsr      	0x0	// 0 <lmac_convert_sid2mac>
 190:	6c43      	mov      	r1, r0
 192:	3206      	movi      	r2, 6
 194:	e4040101 	addi      	r0, r4, 258
 198:	e0000000 	bsr      	0x0	// 0 <memcpy>
 19c:	8569      	ld.b      	r3, (r5, 0x9)
 19e:	e4632020 	andi      	r3, r3, 32
 1a2:	e9030012 	bez      	r3, 0x1c6	// 1c6 <lmac_decrypt_hdl+0x1c6>
 1a6:	3206      	movi      	r2, 6
 1a8:	e425000b 	addi      	r1, r5, 12
 1ac:	e4040109 	addi      	r0, r4, 266
 1b0:	e0000000 	bsr      	0x0	// 0 <memcpy>
 1b4:	d8640144 	ld.b      	r3, (r4, 0x144)
 1b8:	2305      	addi      	r3, 6
 1ba:	dc640144 	st.b      	r3, (r4, 0x144)
 1be:	e404010f 	addi      	r0, r4, 272
 1c2:	8569      	ld.b      	r3, (r5, 0x9)
 1c4:	077f      	br      	0xc2	// c2 <lmac_decrypt_hdl+0xc2>
 1c6:	d866003a 	ld.b      	r3, (r6, 0x3a)
 1ca:	e4632040 	andi      	r3, r3, 64
 1ce:	e9030018 	bez      	r3, 0x1fe	// 1fe <lmac_decrypt_hdl+0x1fe>
 1d2:	3302      	movi      	r3, 2
 1d4:	dc64010a 	st.b      	r3, (r4, 0x10a)
 1d8:	3300      	movi      	r3, 0
 1da:	2b2d      	subi      	r3, 46
 1dc:	dc64010b 	st.b      	r3, (r4, 0x10b)
 1e0:	3300      	movi      	r3, 0
 1e2:	2b1e      	subi      	r3, 31
 1e4:	dc64010c 	st.b      	r3, (r4, 0x10c)
 1e8:	3328      	movi      	r3, 40
 1ea:	dc64010d 	st.b      	r3, (r4, 0x10d)
 1ee:	3300      	movi      	r3, 0
 1f0:	2b5a      	subi      	r3, 91
 1f2:	dc64010e 	st.b      	r3, (r4, 0x10e)
 1f6:	337c      	movi      	r3, 124
 1f8:	dc64010f 	st.b      	r3, (r4, 0x10f)
 1fc:	07dc      	br      	0x1b4	// 1b4 <lmac_decrypt_hdl+0x1b4>
 1fe:	e4040109 	addi      	r0, r4, 266
 202:	07e0      	br      	0x1c2	// 1c2 <lmac_decrypt_hdl+0x1c2>
 204:	856f      	ld.b      	r3, (r5, 0xf)
 206:	854e      	ld.b      	r2, (r5, 0xe)
 208:	4368      	lsli      	r3, r3, 8
 20a:	6cc8      	or      	r3, r2
 20c:	a872      	st.h      	r3, (r0, 0x24)
 20e:	1101      	lrw      	r0, 0x0	// 290 <lmac_decrypt_hdl+0x290>
 210:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 214:	3206      	movi      	r2, 6
 216:	5d26      	addi      	r1, r5, 2
 218:	e40400fb 	addi      	r0, r4, 252
 21c:	e0000000 	bsr      	0x0	// 0 <memcpy>
 220:	3206      	movi      	r2, 6
 222:	5d3e      	addi      	r1, r5, 8
 224:	e4040101 	addi      	r0, r4, 258
 228:	e0000000 	bsr      	0x0	// 0 <memcpy>
 22c:	3302      	movi      	r3, 2
 22e:	dc64010a 	st.b      	r3, (r4, 0x10a)
 232:	3300      	movi      	r3, 0
 234:	2b2d      	subi      	r3, 46
 236:	dc64010b 	st.b      	r3, (r4, 0x10b)
 23a:	3300      	movi      	r3, 0
 23c:	2b1e      	subi      	r3, 31
 23e:	dc64010c 	st.b      	r3, (r4, 0x10c)
 242:	3328      	movi      	r3, 40
 244:	dc64010d 	st.b      	r3, (r4, 0x10d)
 248:	3300      	movi      	r3, 0
 24a:	2b5a      	subi      	r3, 91
 24c:	dc64010e 	st.b      	r3, (r4, 0x10e)
 250:	337c      	movi      	r3, 124
 252:	dc64010f 	st.b      	r3, (r4, 0x10f)
 256:	073f      	br      	0xd4	// d4 <lmac_decrypt_hdl+0xd4>
 258:	e4212003 	andi      	r1, r1, 3
 25c:	100e      	lrw      	r0, 0x0	// 294 <hgprintf+0x294>
 25e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 262:	3400      	movi      	r4, 0
 264:	06ed      	br      	0x3e	// 3e <lmac_decrypt_hdl+0x3e>
	...

Disassembly of section .text.lmac_test_dup_filter:

00000000 <lmac_test_dup_filter>:
   0:	14d2      	push      	r4-r5, r15
   2:	3400      	movi      	r4, 0
   4:	10a8      	lrw      	r5, 0x0	// 24 <lmac_test_dup_filter+0x24>
   6:	e4642003 	andi      	r3, r4, 3
   a:	e9230004 	bnez      	r3, 0x12	// 12 <lmac_test_dup_filter+0x12>
   e:	9560      	ld.w      	r3, (r5, 0x0)
  10:	936f      	ld.w      	r3, (r3, 0x3c)
  12:	3000      	movi      	r0, 0
  14:	2400      	addi      	r4, 1
  16:	e0000000 	bsr      	0x0	// 0 <lmac_test_dup_filter>
  1a:	eb440064 	cmpnei      	r4, 100
  1e:	0bf4      	bt      	0x6	// 6 <lmac_test_dup_filter+0x6>
  20:	1492      	pop      	r4-r5, r15
  22:	0000      	.short	0x0000
  24:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_rx_check:

00000000 <lmac_rx_check>:
   0:	14d3      	push      	r4-r6, r15
   2:	016f      	lrw      	r3, 0x0	// 340 <lmac_rx_check+0x340>
   4:	6d4f      	mov      	r5, r3
   6:	d803033c 	ld.b      	r0, (r3, 0x33c)
   a:	d8430340 	ld.b      	r2, (r3, 0x340)
   e:	640a      	cmpne      	r2, r0
  10:	01d2      	lrw      	r6, 0x0	// 344 <lmac_rx_check+0x344>
  12:	0c18      	bf      	0x42	// 42 <lmac_rx_check+0x42>
  14:	d8430a4f 	ld.b      	r2, (r3, 0xa4f)
  18:	e4422008 	andi      	r2, r2, 8
  1c:	e9220013 	bnez      	r2, 0x42	// 42 <lmac_rx_check+0x42>
  20:	d8630892 	ld.b      	r3, (r3, 0x892)
  24:	e4632002 	andi      	r3, r3, 2
  28:	e923000d 	bnez      	r3, 0x42	// 42 <lmac_rx_check+0x42>
  2c:	e0000000 	bsr      	0x0	// 0 <lmac_lo_table_kick>
  30:	3034      	movi      	r0, 52
  32:	e0000000 	bsr      	0x0	// 0 <lmac_delay_us>
  36:	9660      	ld.w      	r3, (r6, 0x0)
  38:	3000      	movi      	r0, 0
  3a:	2800      	subi      	r0, 1
  3c:	dc03202d 	st.w      	r0, (r3, 0xb4)
  40:	04f7      	br      	0x22e	// 22e <lmac_rx_check+0x22e>
  42:	d86509e0 	ld.b      	r3, (r5, 0x9e0)
  46:	e4632001 	andi      	r3, r3, 1
  4a:	e9030013 	bez      	r3, 0x70	// 70 <lmac_rx_check+0x70>
  4e:	c6005022 	bmaski      	r2, 17
  52:	2a00      	subi      	r2, 1
  54:	d8652278 	ld.w      	r3, (r5, 0x9e0)
  58:	c4432021 	and      	r1, r3, r2
  5c:	6486      	cmpne      	r1, r2
  5e:	0fec      	bf      	0x36	// 36 <lmac_rx_check+0x36>
  60:	c4235602 	zext      	r2, r3, 16, 1
  64:	2200      	addi      	r2, 1
  66:	c4625de1 	ins      	r3, r2, 16, 1
  6a:	dc652278 	st.w      	r3, (r5, 0x9e0)
  6e:	07e4      	br      	0x36	// 36 <lmac_rx_check+0x36>
  70:	9660      	ld.w      	r3, (r6, 0x0)
  72:	d843202d 	ld.w      	r2, (r3, 0xb4)
  76:	e4422004 	andi      	r2, r2, 4
  7a:	e9020013 	bez      	r2, 0xa0	// a0 <lmac_rx_check+0xa0>
  7e:	e0000000 	bsr      	0x0	// 0 <ah_wphy_err_code_get>
  82:	d86521e2 	ld.w      	r3, (r5, 0x788)
  86:	2300      	addi      	r3, 1
  88:	dc0521e3 	st.w      	r0, (r5, 0x78c)
  8c:	dc6521e2 	st.w      	r3, (r5, 0x788)
  90:	d845227a 	ld.w      	r2, (r5, 0x9e8)
  94:	d8252279 	ld.w      	r1, (r5, 0x9e4)
  98:	3009      	movi      	r0, 9
  9a:	e0000000 	bsr      	0x0	// 0 <lmac_adc_dump>
  9e:	07cc      	br      	0x36	// 36 <lmac_rx_check+0x36>
  a0:	3280      	movi      	r2, 128
  a2:	d823202d 	ld.w      	r1, (r3, 0xb4)
  a6:	4248      	lsli      	r2, r2, 8
  a8:	6848      	and      	r1, r2
  aa:	e901000a 	bez      	r1, 0xbe	// be <lmac_rx_check+0xbe>
  ae:	d82509e2 	ld.b      	r1, (r5, 0x9e2)
  b2:	e4212002 	andi      	r1, r1, 2
  b6:	e9010016 	bez      	r1, 0xe2	// e2 <lmac_rx_check+0xe2>
  ba:	dc43202d 	st.w      	r2, (r3, 0xb4)
  be:	d843202d 	ld.w      	r2, (r3, 0xb4)
  c2:	e4422008 	andi      	r2, r2, 8
  c6:	e9020014 	bez      	r2, 0xee	// ee <lmac_rx_check+0xee>
  ca:	d865226d 	ld.w      	r3, (r5, 0x9b4)
  ce:	ec630400 	ori      	r3, r3, 1024
  d2:	dc65226d 	st.w      	r3, (r5, 0x9b4)
  d6:	d845227a 	ld.w      	r2, (r5, 0x9e8)
  da:	d8252279 	ld.w      	r1, (r5, 0x9e4)
  de:	300b      	movi      	r0, 11
  e0:	07dd      	br      	0x9a	// 9a <lmac_rx_check+0x9a>
  e2:	d845227a 	ld.w      	r2, (r5, 0x9e8)
  e6:	d8252279 	ld.w      	r1, (r5, 0x9e4)
  ea:	300a      	movi      	r0, 10
  ec:	07d7      	br      	0x9a	// 9a <lmac_rx_check+0x9a>
  ee:	d863202d 	ld.w      	r3, (r3, 0xb4)
  f2:	e4632020 	andi      	r3, r3, 32
  f6:	e9030008 	bez      	r3, 0x106	// 106 <lmac_rx_check+0x106>
  fa:	d86521e5 	ld.w      	r3, (r5, 0x794)
  fe:	2300      	addi      	r3, 1
 100:	dc6521e5 	st.w      	r3, (r5, 0x794)
 104:	0799      	br      	0x36	// 36 <lmac_rx_check+0x36>
 106:	038e      	lrw      	r4, 0x0	// 348 <lmac_rx_check+0x348>
 108:	e0000000 	bsr      	0x0	// 0 <lhw_get_rx_ndp_ind>
 10c:	d86400be 	ld.b      	r3, (r4, 0xbe)
 110:	9640      	ld.w      	r2, (r6, 0x0)
 112:	c4605c02 	ins      	r3, r0, 2, 2
 116:	dc6400be 	st.b      	r3, (r4, 0xbe)
 11a:	d8622105 	ld.w      	r3, (r2, 0x414)
 11e:	d824009b 	ld.b      	r1, (r4, 0x9b)
 122:	74cc      	zextb      	r3, r3
 124:	c4235cc0 	ins      	r1, r3, 6, 0
 128:	d80400be 	ld.b      	r0, (r4, 0xbe)
 12c:	dc24009b 	st.b      	r1, (r4, 0x9b)
 130:	e4002004 	andi      	r0, r0, 4
 134:	d8222108 	ld.w      	r1, (r2, 0x420)
 138:	dc242025 	st.w      	r1, (r4, 0x94)
 13c:	e9200038 	bnez      	r0, 0x1ac	// 1ac <lmac_rx_check+0x1ac>
 140:	d804009b 	ld.b      	r0, (r4, 0x9b)
 144:	e400207f 	andi      	r0, r0, 127
 148:	e9000032 	bez      	r0, 0x1ac	// 1ac <lmac_rx_check+0x1ac>
 14c:	d8022101 	ld.w      	r0, (r2, 0x404)
 150:	6404      	cmphs      	r1, r0
 152:	0c05      	bf      	0x15c	// 15c <lmac_rx_check+0x15c>
 154:	d8022102 	ld.w      	r0, (r2, 0x408)
 158:	6404      	cmphs      	r1, r0
 15a:	0c08      	bf      	0x16a	// 16a <lmac_rx_check+0x16a>
 15c:	d865226d 	ld.w      	r3, (r5, 0x9b4)
 160:	ec630800 	ori      	r3, r3, 2048
 164:	dc65226d 	st.w      	r3, (r5, 0x9b4)
 168:	0767      	br      	0x36	// 36 <lmac_rx_check+0x36>
 16a:	941a      	ld.w      	r0, (r4, 0x68)
 16c:	6404      	cmphs      	r1, r0
 16e:	0f64      	bf      	0x36	// 36 <lmac_rx_check+0x36>
 170:	d984201e 	ld.w      	r12, (r4, 0x78)
 174:	d9a4201d 	ld.w      	r13, (r4, 0x74)
 178:	6336      	subu      	r12, r13
 17a:	6030      	addu      	r0, r12
 17c:	6404      	cmphs      	r1, r0
 17e:	0b5c      	bt      	0x36	// 36 <lmac_rx_check+0x36>
 180:	e463207f 	andi      	r3, r3, 127
 184:	2b00      	subi      	r3, 1
 186:	74cc      	zextb      	r3, r3
 188:	e4230083 	addi      	r1, r3, 132
 18c:	4363      	lsli      	r3, r3, 3
 18e:	60c8      	addu      	r3, r2
 190:	d0220901 	ldr.w      	r1, (r2, r1 << 3)
 194:	d8632109 	ld.w      	r3, (r3, 0x424)
 198:	c40355a3 	zext      	r3, r3, 13, 0
 19c:	d8422102 	ld.w      	r2, (r2, 0x408)
 1a0:	60c4      	addu      	r3, r1
 1a2:	64c8      	cmphs      	r2, r3
 1a4:	0804      	bt      	0x1ac	// 1ac <lmac_rx_check+0x1ac>
 1a6:	130a      	lrw      	r0, 0x0	// 34c <lmac_rx_check+0x34c>
 1a8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1ac:	9660      	ld.w      	r3, (r6, 0x0)
 1ae:	d84400be 	ld.b      	r2, (r4, 0xbe)
 1b2:	d8232029 	ld.w      	r1, (r3, 0xa4)
 1b6:	c4415c43 	ins      	r2, r1, 5, 3
 1ba:	dc4400be 	st.b      	r2, (r4, 0xbe)
 1be:	d843202d 	ld.w      	r2, (r3, 0xb4)
 1c2:	d82400be 	ld.b      	r1, (r4, 0xbe)
 1c6:	4a48      	lsri      	r2, r2, 8
 1c8:	c4225c07 	ins      	r1, r2, 7, 7
 1cc:	d843202d 	ld.w      	r2, (r3, 0xb4)
 1d0:	4a4d      	lsri      	r2, r2, 13
 1d2:	dc2400be 	st.b      	r1, (r4, 0xbe)
 1d6:	d82400bf 	ld.b      	r1, (r4, 0xbf)
 1da:	c4225c20 	ins      	r1, r2, 1, 0
 1de:	dc2400bf 	st.b      	r1, (r4, 0xbf)
 1e2:	9375      	ld.w      	r3, (r3, 0x54)
 1e4:	dc642028 	st.w      	r3, (r4, 0xa0)
 1e8:	e0000000 	bsr      	0x0	// 0 <ah_wphy_scrambler_init_get>
 1ec:	9660      	ld.w      	r3, (r6, 0x0)
 1ee:	dc04009a 	st.b      	r0, (r4, 0x9a)
 1f2:	d8432029 	ld.w      	r2, (r3, 0xa4)
 1f6:	b45f      	st.w      	r2, (r4, 0x7c)
 1f8:	d843202a 	ld.w      	r2, (r3, 0xa8)
 1fc:	dc442020 	st.w      	r2, (r4, 0x80)
 200:	d843202b 	ld.w      	r2, (r3, 0xac)
 204:	d863202c 	ld.w      	r3, (r3, 0xb0)
 208:	dc642022 	st.w      	r3, (r4, 0x88)
 20c:	dc442021 	st.w      	r2, (r4, 0x84)
 210:	e0000000 	bsr      	0x0	// 0 <lhw_get_rx_frm_type>
 214:	e4002003 	andi      	r0, r0, 3
 218:	d86400be 	ld.b      	r3, (r4, 0xbe)
 21c:	c4605c20 	ins      	r3, r0, 1, 0
 220:	dc6400be 	st.b      	r3, (r4, 0xbe)
 224:	e4632004 	andi      	r3, r3, 4
 228:	e9030004 	bez      	r3, 0x230	// 230 <lmac_rx_check+0x230>
 22c:	3000      	movi      	r0, 0
 22e:	1493      	pop      	r4-r6, r15
 230:	3841      	cmpnei      	r0, 1
 232:	0c4a      	bf      	0x2c6	// 2c6 <lmac_rx_check+0x2c6>
 234:	3840      	cmpnei      	r0, 0
 236:	0c0a      	bf      	0x24a	// 24a <lmac_rx_check+0x24a>
 238:	3842      	cmpnei      	r0, 2
 23a:	0c46      	bf      	0x2c6	// 2c6 <lmac_rx_check+0x2c6>
 23c:	d865226d 	ld.w      	r3, (r5, 0x9b4)
 240:	ec630010 	ori      	r3, r3, 16
 244:	dc65226d 	st.w      	r3, (r5, 0x9b4)
 248:	0431      	br      	0x2aa	// 2aa <lmac_rx_check+0x2aa>
 24a:	d844007e 	ld.b      	r2, (r4, 0x7e)
 24e:	c4a254c2 	zext      	r2, r2, 6, 5
 252:	d86400bf 	ld.b      	r3, (r4, 0xbf)
 256:	c4625c22 	ins      	r3, r2, 3, 2
 25a:	d844007d 	ld.b      	r2, (r4, 0x7d)
 25e:	c4625462 	zext      	r2, r2, 3, 3
 262:	d82400be 	ld.b      	r1, (r4, 0xbe)
 266:	c4225c06 	ins      	r1, r2, 6, 6
 26a:	d844007f 	ld.b      	r2, (r4, 0x7f)
 26e:	c44254a2 	zext      	r2, r2, 5, 2
 272:	c4625c64 	ins      	r3, r2, 7, 4
 276:	d844103e 	ld.h      	r2, (r4, 0x7c)
 27a:	c4e25542 	zext      	r2, r2, 10, 7
 27e:	dc6400bf 	st.b      	r3, (r4, 0xbf)
 282:	d86400c0 	ld.b      	r3, (r4, 0xc0)
 286:	c4625c60 	ins      	r3, r2, 3, 0
 28a:	3203      	movi      	r2, 3
 28c:	c4625c24 	ins      	r3, r2, 5, 4
 290:	dc6400c0 	st.b      	r3, (r4, 0xc0)
 294:	d8640084 	ld.b      	r3, (r4, 0x84)
 298:	dc2400be 	st.b      	r1, (r4, 0xbe)
 29c:	68c8      	and      	r3, r2
 29e:	4368      	lsli      	r3, r3, 8
 2a0:	d8440083 	ld.b      	r2, (r4, 0x83)
 2a4:	60c8      	addu      	r3, r2
 2a6:	dc642031 	st.w      	r3, (r4, 0xc4)
 2aa:	d86509e2 	ld.b      	r3, (r5, 0x9e2)
 2ae:	e4632002 	andi      	r3, r3, 2
 2b2:	e903ffbd 	bez      	r3, 0x22c	// 22c <lmac_rx_check+0x22c>
 2b6:	d86400bf 	ld.b      	r3, (r4, 0xbf)
 2ba:	3202      	movi      	r2, 2
 2bc:	c4625c22 	ins      	r3, r2, 3, 2
 2c0:	dc6400bf 	st.b      	r3, (r4, 0xbf)
 2c4:	07b4      	br      	0x22c	// 22c <lmac_rx_check+0x22c>
 2c6:	d844007c 	ld.b      	r2, (r4, 0x7c)
 2ca:	c4425442 	zext      	r2, r2, 2, 2
 2ce:	d86400c0 	ld.b      	r3, (r4, 0xc0)
 2d2:	c4625c06 	ins      	r3, r2, 6, 6
 2d6:	d844103e 	ld.h      	r2, (r4, 0x7c)
 2da:	c4e255e2 	zext      	r2, r2, 15, 7
 2de:	d8241058 	ld.h      	r1, (r4, 0xb0)
 2e2:	c4225d03 	ins      	r1, r2, 11, 3
 2e6:	dc241058 	st.h      	r1, (r4, 0xb0)
 2ea:	d8240080 	ld.b      	r1, (r4, 0x80)
 2ee:	c4415461 	zext      	r1, r1, 3, 2
 2f2:	d84400bf 	ld.b      	r2, (r4, 0xbf)
 2f6:	c4415c22 	ins      	r2, r1, 3, 2
 2fa:	d804007f 	ld.b      	r0, (r4, 0x7f)
 2fe:	d82400be 	ld.b      	r1, (r4, 0xbe)
 302:	c4205c06 	ins      	r1, r0, 6, 6
 306:	dc2400be 	st.b      	r1, (r4, 0xbe)
 30a:	d8241040 	ld.h      	r1, (r4, 0x80)
 30e:	c4c15521 	zext      	r1, r1, 9, 6
 312:	c4415c64 	ins      	r2, r1, 7, 4
 316:	dc4400bf 	st.b      	r2, (r4, 0xbf)
 31a:	d844007e 	ld.b      	r2, (r4, 0x7e)
 31e:	c46254c2 	zext      	r2, r2, 6, 3
 322:	c4625c60 	ins      	r3, r2, 3, 0
 326:	d844007c 	ld.b      	r2, (r4, 0x7c)
 32a:	c4625482 	zext      	r2, r2, 4, 3
 32e:	c4625c24 	ins      	r3, r2, 5, 4
 332:	dc6400c0 	st.b      	r3, (r4, 0xc0)
 336:	d8640084 	ld.b      	r3, (r4, 0x84)
 33a:	e4632003 	andi      	r3, r3, 3
 33e:	07b0      	br      	0x29e	// 29e <ah_lmac+0x29e>
	...

Disassembly of section .text.lmac_gen_ndp_ba:

00000000 <lmac_gen_ndp_ba>:
   0:	14d4      	push      	r4-r7, r15
   2:	11c1      	lrw      	r6, 0x0	// 84 <lmac_gen_ndp_ba+0x84>
   4:	11a1      	lrw      	r5, 0x0	// 88 <lmac_gen_ndp_ba+0x88>
   6:	d86603e2 	ld.b      	r3, (r6, 0x3e2)
   a:	e4632001 	andi      	r3, r3, 1
   e:	3400      	movi      	r4, 0
  10:	6dd3      	mov      	r7, r4
  12:	d805009a 	ld.b      	r0, (r5, 0x9a)
  16:	e9030004 	bez      	r3, 0x1e	// 1e <lmac_gen_ndp_ba+0x1e>
  1a:	e0000000 	bsr      	0x0	// 0 <data_scrambler>
  1e:	3304      	movi      	r3, 4
  20:	c4835c40 	ins      	r4, r3, 2, 0
  24:	d866034a 	ld.b      	r3, (r6, 0x34a)
  28:	e4632001 	andi      	r3, r3, 1
  2c:	e903001d 	bez      	r3, 0x66	// 66 <lmac_gen_ndp_ba+0x66>
  30:	d8651052 	ld.h      	r3, (r5, 0xa4)
  34:	c4805c23 	ins      	r4, r0, 4, 3
  38:	c4835d65 	ins      	r4, r3, 16, 5
  3c:	d86500a8 	ld.b      	r3, (r5, 0xa8)
  40:	c4835cf1 	ins      	r4, r3, 24, 17
  44:	6c13      	mov      	r0, r4
  46:	6c5f      	mov      	r1, r7
  48:	e0000000 	bsr      	0x0	// 0 <lmac_update_ndp_ba_tx_vec>
  4c:	d86609dc 	ld.b      	r3, (r6, 0x9dc)
  50:	3201      	movi      	r2, 1
  52:	c4625c05 	ins      	r3, r2, 5, 5
  56:	dc6609dc 	st.b      	r3, (r6, 0x9dc)
  5a:	6c13      	mov      	r0, r4
  5c:	3303      	movi      	r3, 3
  5e:	6c5f      	mov      	r1, r7
  60:	dc662265 	st.w      	r3, (r6, 0x994)
  64:	1494      	pop      	r4-r7, r15
  66:	d8651052 	ld.h      	r3, (r5, 0xa4)
  6a:	c4805ca3 	ins      	r4, r0, 8, 3
  6e:	c4835d69 	ins      	r4, r3, 20, 9
  72:	d8e500a9 	ld.b      	r7, (r5, 0xa9)
  76:	d8651054 	ld.h      	r3, (r5, 0xa8)
  7a:	c4835d55 	ins      	r4, r3, 31, 21
  7e:	4fe3      	lsri      	r7, r7, 3
  80:	07e2      	br      	0x44	// 44 <lmac_gen_ndp_ba+0x44>
	...

Disassembly of section .text.pv0_cfpoll_rx_hdl:

00000000 <pv0_cfpoll_rx_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	1161      	lrw      	r3, 0x0	// 84 <pv0_cfpoll_rx_hdl+0x84>
   4:	8841      	ld.h      	r2, (r0, 0x2)
   6:	1181      	lrw      	r4, 0x0	// 88 <pv0_cfpoll_rx_hdl+0x88>
   8:	dc431049 	st.h      	r2, (r3, 0x92)
   c:	8825      	ld.h      	r1, (r0, 0xa)
   e:	d8441293 	ld.h      	r2, (r4, 0x526)
  12:	6486      	cmpne      	r1, r2
  14:	0834      	bt      	0x7c	// 7c <pv0_cfpoll_rx_hdl+0x7c>
  16:	9023      	ld.w      	r1, (r0, 0xc)
  18:	d844214a 	ld.w      	r2, (r4, 0x528)
  1c:	6486      	cmpne      	r1, r2
  1e:	c400050c 	mvc      	r12
  22:	7730      	zextb      	r12, r12
  24:	d84300c0 	ld.b      	r2, (r3, 0xc0)
  28:	c44c5c07 	ins      	r2, r12, 7, 7
  2c:	dc4300c0 	st.b      	r2, (r3, 0xc0)
  30:	748a      	sextb      	r2, r2
  32:	e9820024 	blz      	r2, 0x7a	// 7a <pv0_cfpoll_rx_hdl+0x7a>
  36:	d8a4202f 	ld.w      	r5, (r4, 0xbc)
  3a:	3d41      	cmpnei      	r5, 1
  3c:	081f      	bt      	0x7a	// 7a <pv0_cfpoll_rx_hdl+0x7a>
  3e:	8822      	ld.h      	r1, (r0, 0x4)
  40:	d8441181 	ld.h      	r2, (r4, 0x302)
  44:	6486      	cmpne      	r1, r2
  46:	081a      	bt      	0x7a	// 7a <pv0_cfpoll_rx_hdl+0x7a>
  48:	8823      	ld.h      	r1, (r0, 0x6)
  4a:	d8441182 	ld.h      	r2, (r4, 0x304)
  4e:	6486      	cmpne      	r1, r2
  50:	0815      	bt      	0x7a	// 7a <pv0_cfpoll_rx_hdl+0x7a>
  52:	8824      	ld.h      	r1, (r0, 0x8)
  54:	d8441183 	ld.h      	r2, (r4, 0x306)
  58:	6486      	cmpne      	r1, r2
  5a:	0810      	bt      	0x7a	// 7a <pv0_cfpoll_rx_hdl+0x7a>
  5c:	3200      	movi      	r2, 0
  5e:	dc431049 	st.h      	r2, (r3, 0x92)
  62:	e4200009 	addi      	r1, r0, 10
  66:	3206      	movi      	r2, 6
  68:	1009      	lrw      	r0, 0x0	// 8c <pv0_cfpoll_rx_hdl+0x8c>
  6a:	e0000000 	bsr      	0x0	// 0 <memcpy>
  6e:	e0000000 	bsr      	0x0	// 0 <lmac_tx_date_prepared>
  72:	e9200004 	bnez      	r0, 0x7a	// 7a <pv0_cfpoll_rx_hdl+0x7a>
  76:	dca42265 	st.w      	r5, (r4, 0x994)
  7a:	1492      	pop      	r4-r5, r15
  7c:	ea0c0001 	movi      	r12, 1
  80:	07d2      	br      	0x24	// 24 <pv0_cfpoll_rx_hdl+0x24>
	...

Disassembly of section .text.lmac_rx_obss_check:

00000000 <lmac_rx_obss_check>:
   0:	8020      	ld.b      	r1, (r0, 0x0)
   2:	6cc3      	mov      	r3, r0
   4:	e4012003 	andi      	r0, r1, 3
   8:	e9200064 	bnez      	r0, 0xd0	// d0 <lmac_rx_obss_check+0xd0>
   c:	8341      	ld.b      	r2, (r3, 0x1)
   e:	4248      	lsli      	r2, r2, 8
  10:	6c84      	or      	r2, r1
  12:	c4425521 	zext      	r1, r2, 9, 2
  16:	e5812001 	andi      	r12, r1, 1
  1a:	e92c0025 	bnez      	r12, 0x64	// 64 <lmac_rx_obss_check+0x64>
  1e:	114e      	lrw      	r2, 0x0	// d4 <lmac_rx_obss_check+0xd4>
  20:	d82200c0 	ld.b      	r1, (r2, 0xc0)
  24:	e4212040 	andi      	r1, r1, 64
  28:	114c      	lrw      	r2, 0x0	// d8 <lmac_rx_obss_check+0xd8>
  2a:	e901002c 	bez      	r1, 0x82	// 82 <lmac_rx_obss_check+0x82>
  2e:	8304      	ld.b      	r0, (r3, 0x4)
  30:	d8220526 	ld.b      	r1, (r2, 0x526)
  34:	6442      	cmpne      	r0, r1
  36:	084b      	bt      	0xcc	// cc <lmac_rx_obss_check+0xcc>
  38:	8305      	ld.b      	r0, (r3, 0x5)
  3a:	d8220527 	ld.b      	r1, (r2, 0x527)
  3e:	6442      	cmpne      	r0, r1
  40:	0846      	bt      	0xcc	// cc <lmac_rx_obss_check+0xcc>
  42:	8306      	ld.b      	r0, (r3, 0x6)
  44:	d8220528 	ld.b      	r1, (r2, 0x528)
  48:	6442      	cmpne      	r0, r1
  4a:	0841      	bt      	0xcc	// cc <lmac_rx_obss_check+0xcc>
  4c:	8307      	ld.b      	r0, (r3, 0x7)
  4e:	d8220529 	ld.b      	r1, (r2, 0x529)
  52:	6442      	cmpne      	r0, r1
  54:	083c      	bt      	0xcc	// cc <lmac_rx_obss_check+0xcc>
  56:	8308      	ld.b      	r0, (r3, 0x8)
  58:	d822052a 	ld.b      	r1, (r2, 0x52a)
  5c:	6442      	cmpne      	r0, r1
  5e:	0837      	bt      	0xcc	// cc <lmac_rx_obss_check+0xcc>
  60:	8329      	ld.b      	r1, (r3, 0x9)
  62:	042a      	br      	0xb6	// b6 <lmac_rx_obss_check+0xb6>
  64:	e4212003 	andi      	r1, r1, 3
  68:	3941      	cmpnei      	r1, 1
  6a:	082d      	bt      	0xc4	// c4 <lmac_rx_obss_check+0xc4>
  6c:	c4825562 	zext      	r2, r2, 11, 4
  70:	e422200f 	andi      	r1, r2, 15
  74:	394e      	cmpnei      	r1, 14
  76:	0fd4      	bf      	0x1e	// 1e <lmac_rx_obss_check+0x1e>
  78:	e442200d 	andi      	r2, r2, 13
  7c:	3a49      	cmpnei      	r2, 9
  7e:	0fd0      	bf      	0x1e	// 1e <lmac_rx_obss_check+0x1e>
  80:	783c      	jmp      	r15
  82:	830a      	ld.b      	r0, (r3, 0xa)
  84:	d8220526 	ld.b      	r1, (r2, 0x526)
  88:	6442      	cmpne      	r0, r1
  8a:	0821      	bt      	0xcc	// cc <lmac_rx_obss_check+0xcc>
  8c:	830b      	ld.b      	r0, (r3, 0xb)
  8e:	d8220527 	ld.b      	r1, (r2, 0x527)
  92:	6442      	cmpne      	r0, r1
  94:	081c      	bt      	0xcc	// cc <lmac_rx_obss_check+0xcc>
  96:	830c      	ld.b      	r0, (r3, 0xc)
  98:	d8220528 	ld.b      	r1, (r2, 0x528)
  9c:	6442      	cmpne      	r0, r1
  9e:	0817      	bt      	0xcc	// cc <lmac_rx_obss_check+0xcc>
  a0:	830d      	ld.b      	r0, (r3, 0xd)
  a2:	d8220529 	ld.b      	r1, (r2, 0x529)
  a6:	6442      	cmpne      	r0, r1
  a8:	0812      	bt      	0xcc	// cc <lmac_rx_obss_check+0xcc>
  aa:	830e      	ld.b      	r0, (r3, 0xe)
  ac:	d822052a 	ld.b      	r1, (r2, 0x52a)
  b0:	6442      	cmpne      	r0, r1
  b2:	080d      	bt      	0xcc	// cc <lmac_rx_obss_check+0xcc>
  b4:	832f      	ld.b      	r1, (r3, 0xf)
  b6:	d862052b 	ld.b      	r3, (r2, 0x52b)
  ba:	64c6      	cmpne      	r1, r3
  bc:	c4000500 	mvc      	r0
  c0:	7400      	zextb      	r0, r0
  c2:	07df      	br      	0x80	// 80 <lmac_rx_obss_check+0x80>
  c4:	3943      	cmpnei      	r1, 3
  c6:	0bdd      	bt      	0x80	// 80 <lmac_rx_obss_check+0x80>
  c8:	1044      	lrw      	r2, 0x0	// d8 <lmac_rx_obss_check+0xd8>
  ca:	07b2      	br      	0x2e	// 2e <lmac_rx_obss_check+0x2e>
  cc:	3001      	movi      	r0, 1
  ce:	07f9      	br      	0xc0	// c0 <lmac_rx_obss_check+0xc0>
  d0:	3000      	movi      	r0, 0
  d2:	07d7      	br      	0x80	// 80 <lmac_rx_obss_check+0x80>
	...

Disassembly of section .text.wpcts_rx_check:

00000000 <wpcts_rx_check>:
   0:	8060      	ld.b      	r3, (r0, 0x0)
   2:	eb430074 	cmpnei      	r3, 116
   6:	0809      	bt      	0x18	// 18 <wpcts_rx_check+0x18>
   8:	806a      	ld.b      	r3, (r0, 0xa)
   a:	e46320f0 	andi      	r3, r3, 240
   e:	eb4300c0 	cmpnei      	r3, 192
  12:	6403      	mvcv      	r0
  14:	4004      	lsli      	r0, r0, 4
  16:	783c      	jmp      	r15
  18:	3000      	movi      	r0, 0
  1a:	07fe      	br      	0x16	// 16 <wpcts_rx_check+0x16>

Disassembly of section .text.non_ndp_rx_hdl:

00000000 <non_ndp_rx_hdl>:
       0:	14d8      	push      	r4-r11, r15
       2:	143c      	subi      	r14, r14, 112
       4:	ea8800fa 	lrw      	r8, 0x0	// 3ec <non_ndp_rx_hdl+0x3ec>
       8:	0085      	lrw      	r4, 0x0	// 3f0 <non_ndp_rx_hdl+0x3f0>
       a:	d868009c 	ld.b      	r3, (r8, 0x9c)
       e:	b867      	st.w      	r3, (r14, 0x1c)
      10:	3300      	movi      	r3, 0
      12:	b865      	st.w      	r3, (r14, 0x14)
      14:	0067      	lrw      	r3, 0x0	// 3f4 <non_ndp_rx_hdl+0x3f4>
      16:	b866      	st.w      	r3, (r14, 0x18)
      18:	d868009b 	ld.b      	r3, (r8, 0x9b)
      1c:	e463207f 	andi      	r3, r3, 127
      20:	9847      	ld.w      	r2, (r14, 0x1c)
      22:	64c9      	cmplt      	r2, r3
      24:	0c32      	bf      	0x88	// 88 <non_ndp_rx_hdl+0x88>
      26:	d868009c 	ld.b      	r3, (r8, 0x9c)
      2a:	2300      	addi      	r3, 1
      2c:	dc68009c 	st.b      	r3, (r8, 0x9c)
      30:	9866      	ld.w      	r3, (r14, 0x18)
      32:	9847      	ld.w      	r2, (r14, 0x1c)
      34:	42a3      	lsli      	r5, r2, 3
      36:	9360      	ld.w      	r3, (r3, 0x0)
      38:	60d4      	addu      	r3, r5
      3a:	3180      	movi      	r1, 128
      3c:	d8432109 	ld.w      	r2, (r3, 0x424)
      40:	4127      	lsli      	r1, r1, 7
      42:	6884      	and      	r2, r1
      44:	e90200e7 	bez      	r2, 0x212	// 212 <non_ndp_rx_hdl+0x212>
      48:	d8482032 	ld.w      	r2, (r8, 0xc8)
      4c:	2200      	addi      	r2, 1
      4e:	3101      	movi      	r1, 1
      50:	dc482032 	st.w      	r2, (r8, 0xc8)
      54:	d8440bb4 	ld.b      	r2, (r4, 0xbb4)
      58:	c4415c00 	ins      	r2, r1, 0, 0
      5c:	dc440bb4 	st.b      	r2, (r4, 0xbb4)
      60:	d8632109 	ld.w      	r3, (r3, 0x424)
      64:	d86421e4 	ld.w      	r3, (r4, 0x790)
      68:	60c4      	addu      	r3, r1
      6a:	d844227a 	ld.w      	r2, (r4, 0x9e8)
      6e:	d8242279 	ld.w      	r1, (r4, 0x9e4)
      72:	3002      	movi      	r0, 2
      74:	dc6421e4 	st.w      	r3, (r4, 0x790)
      78:	e0000000 	bsr      	0x0	// 0 <lmac_adc_dump>
      7c:	d8640310 	ld.b      	r3, (r4, 0x310)
      80:	e4632008 	andi      	r3, r3, 8
      84:	e90305ad 	bez      	r3, 0xbde	// bde <non_ndp_rx_hdl+0xbde>
      88:	d8640319 	ld.b      	r3, (r4, 0x319)
      8c:	e4632002 	andi      	r3, r3, 2
      90:	e92306b4 	bnez      	r3, 0xdf8	// df8 <non_ndp_rx_hdl+0xdf8>
      94:	9865      	ld.w      	r3, (r14, 0x14)
      96:	e90306b4 	bez      	r3, 0xdfe	// dfe <non_ndp_rx_hdl+0xdfe>
      9a:	d8680098 	ld.b      	r3, (r8, 0x98)
      9e:	2b00      	subi      	r3, 1
      a0:	01e9      	lrw      	r7, 0x0	// 3f8 <non_ndp_rx_hdl+0x3f8>
      a2:	0108      	lrw      	r0, 0x0	// 3fc <non_ndp_rx_hdl+0x3fc>
      a4:	d0670905 	ldr.w      	r5, (r7, r3 << 3)
      a8:	6c57      	mov      	r1, r5
      aa:	e0000000 	bsr      	0x0	// 0 <lmac_get_rx_addr>
      ae:	6c57      	mov      	r1, r5
      b0:	010b      	lrw      	r0, 0x0	// 400 <non_ndp_rx_hdl+0x400>
      b2:	e0000000 	bsr      	0x0	// 0 <lmac_get_tx_addr>
      b6:	6c17      	mov      	r0, r5
      b8:	e0000000 	bsr      	0x0	// 0 <non_ndp_rx_hdl>
      bc:	d86800c0 	ld.b      	r3, (r8, 0xc0)
      c0:	c4605c07 	ins      	r3, r0, 7, 7
      c4:	dc6800c0 	st.b      	r3, (r8, 0xc0)
      c8:	d84800b2 	ld.b      	r2, (r8, 0xb2)
      cc:	d86800b0 	ld.b      	r3, (r8, 0xb0)
      d0:	c4625c01 	ins      	r3, r2, 1, 1
      d4:	dc6800b0 	st.b      	r3, (r8, 0xb0)
      d8:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
      dc:	e4632002 	andi      	r3, r3, 2
      e0:	e9230691 	bnez      	r3, 0xe02	// e02 <non_ndp_rx_hdl+0xe02>
      e4:	d8440303 	ld.b      	r2, (r4, 0x303)
      e8:	d8640302 	ld.b      	r3, (r4, 0x302)
      ec:	6cc8      	or      	r3, r2
      ee:	d8440304 	ld.b      	r2, (r4, 0x304)
      f2:	6cc8      	or      	r3, r2
      f4:	d8440305 	ld.b      	r2, (r4, 0x305)
      f8:	6cc8      	or      	r3, r2
      fa:	d8440306 	ld.b      	r2, (r4, 0x306)
      fe:	6cc8      	or      	r3, r2
     100:	d8440307 	ld.b      	r2, (r4, 0x307)
     104:	6cc8      	or      	r3, r2
     106:	e923067e 	bnez      	r3, 0xe02	// e02 <non_ndp_rx_hdl+0xe02>
     10a:	d84800b0 	ld.b      	r2, (r8, 0xb0)
     10e:	c4435c00 	ins      	r2, r3, 0, 0
     112:	dc4800b0 	st.b      	r2, (r8, 0xb0)
     116:	8561      	ld.b      	r3, (r5, 0x1)
     118:	8540      	ld.b      	r2, (r5, 0x0)
     11a:	4368      	lsli      	r3, r3, 8
     11c:	6cc8      	or      	r3, r2
     11e:	dc681048 	st.h      	r3, (r8, 0x90)
     122:	8563      	ld.b      	r3, (r5, 0x3)
     124:	8542      	ld.b      	r2, (r5, 0x2)
     126:	4368      	lsli      	r3, r3, 8
     128:	6cc8      	or      	r3, r2
     12a:	dc681049 	st.h      	r3, (r8, 0x92)
     12e:	d86800b0 	ld.b      	r3, (r8, 0xb0)
     132:	e4632003 	andi      	r3, r3, 3
     136:	e9030664 	bez      	r3, 0xdfe	// dfe <non_ndp_rx_hdl+0xdfe>
     13a:	9865      	ld.w      	r3, (r14, 0x14)
     13c:	d8280098 	ld.b      	r1, (r8, 0x98)
     140:	604e      	subu      	r1, r3
     142:	4123      	lsli      	r1, r1, 3
     144:	6c8f      	mov      	r2, r3
     146:	605c      	addu      	r1, r7
     148:	0210      	lrw      	r0, 0x0	// 404 <non_ndp_rx_hdl+0x404>
     14a:	e0000000 	bsr      	0x0	// 0 <lmac_rxq_put>
     14e:	e9000658 	bez      	r0, 0xdfe	// dfe <non_ndp_rx_hdl+0xdfe>
     152:	d86800b0 	ld.b      	r3, (r8, 0xb0)
     156:	e4632001 	andi      	r3, r3, 1
     15a:	e903004b 	bez      	r3, 0x1f0	// 1f0 <non_ndp_rx_hdl+0x1f0>
     15e:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
     162:	e4632002 	andi      	r3, r3, 2
     166:	e9230678 	bnez      	r3, 0xe56	// e56 <non_ndp_rx_hdl+0xe56>
     16a:	d848202e 	ld.w      	r2, (r8, 0xb8)
     16e:	d80800b8 	ld.b      	r0, (r8, 0xb8)
     172:	c50256e2 	zext      	r2, r2, 23, 8
     176:	d98800bb 	ld.b      	r12, (r8, 0xbb)
     17a:	d9a800bc 	ld.b      	r13, (r8, 0xbc)
     17e:	d8a800bd 	ld.b      	r5, (r8, 0xbd)
     182:	d864227e 	ld.w      	r3, (r4, 0x9f8)
     186:	023e      	lrw      	r1, 0x0	// 408 <non_ndp_rx_hdl+0x408>
     188:	644e      	cmpne      	r3, r1
     18a:	e860064e 	bt      	0xe26	// e26 <non_ndp_rx_hdl+0xe26>
     18e:	d8481048 	ld.h      	r2, (r8, 0x90)
     192:	c4425462 	zext      	r2, r2, 3, 2
     196:	3a42      	cmpnei      	r2, 2
     198:	0808      	bt      	0x1a8	// 1a8 <non_ndp_rx_hdl+0x1a8>
     19a:	d84800bf 	ld.b      	r2, (r8, 0xbf)
     19e:	3300      	movi      	r3, 0
     1a0:	c4435c22 	ins      	r2, r3, 3, 2
     1a4:	dc4800bf 	st.b      	r2, (r8, 0xbf)
     1a8:	d84800bf 	ld.b      	r2, (r8, 0xbf)
     1ac:	c4425462 	zext      	r2, r2, 3, 2
     1b0:	3a41      	cmpnei      	r2, 1
     1b2:	e8400655 	bf      	0xe5c	// e5c <non_ndp_rx_hdl+0xe5c>
     1b6:	3a42      	cmpnei      	r2, 2
     1b8:	e84006b4 	bf      	0xf20	// f20 <non_ndp_rx_hdl+0xf20>
     1bc:	d86420f0 	ld.w      	r3, (r4, 0x3c0)
     1c0:	d84420f1 	ld.w      	r2, (r4, 0x3c4)
     1c4:	6cc8      	or      	r3, r2
     1c6:	e9030008 	bez      	r3, 0x1d6	// 1d6 <non_ndp_rx_hdl+0x1d6>
     1ca:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
     1ce:	dc0420f0 	st.w      	r0, (r4, 0x3c0)
     1d2:	dc2420f1 	st.w      	r1, (r4, 0x3c4)
     1d6:	d86420f3 	ld.w      	r3, (r4, 0x3cc)
     1da:	d84420f4 	ld.w      	r2, (r4, 0x3d0)
     1de:	6cc8      	or      	r3, r2
     1e0:	e9030008 	bez      	r3, 0x1f0	// 1f0 <non_ndp_rx_hdl+0x1f0>
     1e4:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
     1e8:	dc0420f3 	st.w      	r0, (r4, 0x3cc)
     1ec:	dc2420f4 	st.w      	r1, (r4, 0x3d0)
     1f0:	d8680098 	ld.b      	r3, (r8, 0x98)
     1f4:	2b00      	subi      	r3, 1
     1f6:	4343      	lsli      	r2, r3, 3
     1f8:	609c      	addu      	r2, r7
     1fa:	d0670903 	ldr.w      	r3, (r7, r3 << 3)
     1fe:	9241      	ld.w      	r2, (r2, 0x4)
     200:	60c8      	addu      	r3, r2
     202:	d848201a 	ld.w      	r2, (r8, 0x68)
     206:	60ca      	subu      	r3, r2
     208:	2303      	addi      	r3, 4
     20a:	dc68201c 	st.w      	r3, (r8, 0x70)
     20e:	e80005f8 	br      	0xdfe	// dfe <non_ndp_rx_hdl+0xdfe>
     212:	d844227a 	ld.w      	r2, (r4, 0x9e8)
     216:	d8242279 	ld.w      	r1, (r4, 0x9e4)
     21a:	3001      	movi      	r0, 1
     21c:	e0000000 	bsr      	0x0	// 0 <lmac_adc_dump>
     220:	9866      	ld.w      	r3, (r14, 0x18)
     222:	9847      	ld.w      	r2, (r14, 0x1c)
     224:	9360      	ld.w      	r3, (r3, 0x0)
     226:	614c      	addu      	r5, r3
     228:	2283      	addi      	r2, 132
     22a:	d9252109 	ld.w      	r9, (r5, 0x424)
     22e:	d0430905 	ldr.w      	r5, (r3, r2 << 3)
     232:	d868201a 	ld.w      	r3, (r8, 0x68)
     236:	64d4      	cmphs      	r5, r3
     238:	e84004d3 	bf      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     23c:	d848201e 	ld.w      	r2, (r8, 0x78)
     240:	60c8      	addu      	r3, r2
     242:	654c      	cmphs      	r3, r5
     244:	e84004cd 	bf      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     248:	ea033fff 	movi      	r3, 16383
     24c:	6a4c      	and      	r9, r3
     24e:	e4691009 	subi      	r3, r9, 10
     252:	74cd      	zexth      	r3, r3
     254:	eb030f2d 	cmphsi      	r3, 3886
     258:	0c0c      	bf      	0x270	// 270 <non_ndp_rx_hdl+0x270>
     25a:	d86421fe 	ld.w      	r3, (r4, 0x7f8)
     25e:	2300      	addi      	r3, 1
     260:	dc6421fe 	st.w      	r3, (r4, 0x7f8)
     264:	e92904bd 	bnez      	r9, 0xbde	// bde <non_ndp_rx_hdl+0xbde>
     268:	6c17      	mov      	r0, r5
     26a:	e0000000 	bsr      	0x0	// 0 <non_ndp_rx_hdl>
     26e:	6e43      	mov      	r9, r0
     270:	e465107f 	subi      	r3, r5, 128
     274:	3200      	movi      	r2, 0
     276:	a340      	st.b      	r2, (r3, 0x0)
     278:	e465107e 	subi      	r3, r5, 127
     27c:	a340      	st.b      	r2, (r3, 0x0)
     27e:	85c0      	ld.b      	r6, (r5, 0x0)
     280:	e4e6200f 	andi      	r7, r6, 15
     284:	3f44      	cmpnei      	r7, 4
     286:	0c35      	bf      	0x2f0	// 2f0 <non_ndp_rx_hdl+0x2f0>
     288:	3f04      	cmphsi      	r7, 5
     28a:	080e      	bt      	0x2a6	// 2a6 <non_ndp_rx_hdl+0x2a6>
     28c:	e9070508 	bez      	r7, 0xc9c	// c9c <non_ndp_rx_hdl+0xc9c>
     290:	d864226d 	ld.w      	r3, (r4, 0x9b4)
     294:	3bb0      	bseti      	r3, 16
     296:	dc64226d 	st.w      	r3, (r4, 0x9b4)
     29a:	d844227a 	ld.w      	r2, (r4, 0x9e8)
     29e:	d8242279 	ld.w      	r1, (r4, 0x9e4)
     2a2:	3003      	movi      	r0, 3
     2a4:	0422      	br      	0x2e8	// 2e8 <non_ndp_rx_hdl+0x2e8>
     2a6:	3f48      	cmpnei      	r7, 8
     2a8:	e8400501 	bf      	0xcaa	// caa <non_ndp_rx_hdl+0xcaa>
     2ac:	3f4c      	cmpnei      	r7, 12
     2ae:	0bf1      	bt      	0x290	// 290 <non_ndp_rx_hdl+0x290>
     2b0:	d844227a 	ld.w      	r2, (r4, 0x9e8)
     2b4:	d8242279 	ld.w      	r1, (r4, 0x9e4)
     2b8:	3008      	movi      	r0, 8
     2ba:	e0000000 	bsr      	0x0	// 0 <lmac_adc_dump>
     2be:	e4691009 	subi      	r3, r9, 10
     2c2:	74cd      	zexth      	r3, r3
     2c4:	eb030f2d 	cmphsi      	r3, 3886
     2c8:	0c33      	bf      	0x32e	// 32e <non_ndp_rx_hdl+0x32e>
     2ca:	d86421fe 	ld.w      	r3, (r4, 0x7f8)
     2ce:	2300      	addi      	r3, 1
     2d0:	dc6421fe 	st.w      	r3, (r4, 0x7f8)
     2d4:	d864226d 	ld.w      	r3, (r4, 0x9b4)
     2d8:	3bb1      	bseti      	r3, 17
     2da:	dc64226d 	st.w      	r3, (r4, 0x9b4)
     2de:	d844227a 	ld.w      	r2, (r4, 0x9e8)
     2e2:	d8242279 	ld.w      	r1, (r4, 0x9e4)
     2e6:	300c      	movi      	r0, 12
     2e8:	e0000000 	bsr      	0x0	// 0 <lmac_adc_dump>
     2ec:	e8000479 	br      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     2f0:	d8242279 	ld.w      	r1, (r4, 0x9e4)
     2f4:	d844227a 	ld.w      	r2, (r4, 0x9e8)
     2f8:	3006      	movi      	r0, 6
     2fa:	e0000000 	bsr      	0x0	// 0 <lmac_adc_dump>
     2fe:	6c67      	mov      	r1, r9
     300:	6c17      	mov      	r0, r5
     302:	e0000000 	bsr      	0x0	// 0 <non_ndp_rx_hdl>
     306:	e920046c 	bnez      	r0, 0xbde	// bde <non_ndp_rx_hdl+0xbde>
     30a:	d8680098 	ld.b      	r3, (r8, 0x98)
     30e:	115b      	lrw      	r2, 0x0	// 3f8 <non_ndp_rx_hdl+0x3f8>
     310:	4323      	lsli      	r1, r3, 3
     312:	d4620905 	str.w      	r5, (r2, r3 << 3)
     316:	6084      	addu      	r2, r1
     318:	2300      	addi      	r3, 1
     31a:	dd222001 	st.w      	r9, (r2, 0x4)
     31e:	dc680098 	st.b      	r3, (r8, 0x98)
     322:	9865      	ld.w      	r3, (r14, 0x14)
     324:	2300      	addi      	r3, 1
     326:	74cc      	zextb      	r3, r3
     328:	b865      	st.w      	r3, (r14, 0x14)
     32a:	e800045a 	br      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     32e:	8560      	ld.b      	r3, (r5, 0x0)
     330:	4b64      	lsri      	r3, r3, 4
     332:	3b41      	cmpnei      	r3, 1
     334:	e86002ed 	bt      	0x90e	// 90e <non_ndp_rx_hdl+0x90e>
     338:	3206      	movi      	r2, 6
     33a:	5d2e      	addi      	r1, r5, 4
     33c:	1111      	lrw      	r0, 0x0	// 400 <non_ndp_rx_hdl+0x400>
     33e:	e0000000 	bsr      	0x0	// 0 <memcpy>
     342:	8561      	ld.b      	r3, (r5, 0x1)
     344:	e4432001 	andi      	r2, r3, 1
     348:	e9220066 	bnez      	r2, 0x414	// 414 <non_ndp_rx_hdl+0x414>
     34c:	e565000e 	addi      	r11, r5, 15
     350:	b84f      	st.w      	r2, (r14, 0x3c)
     352:	e4432002 	andi      	r2, r3, 2
     356:	3a40      	cmpnei      	r2, 0
     358:	e4432004 	andi      	r2, r3, 4
     35c:	74ce      	sextb      	r3, r3
     35e:	c56b0c44 	inct      	r11, r11, 4
     362:	3a40      	cmpnei      	r2, 0
     364:	c56b0c41 	inct      	r11, r11, 1
     368:	e9a30061 	bhsz      	r3, 0x42a	// 42a <non_ndp_rx_hdl+0x42a>
     36c:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
     370:	e4632080 	andi      	r3, r3, 128
     374:	e9030005 	bez      	r3, 0x37e	// 37e <non_ndp_rx_hdl+0x37e>
     378:	1105      	lrw      	r0, 0x0	// 40c <hgprintf+0x40c>
     37a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
     37e:	8544      	ld.b      	r2, (r5, 0x4)
     380:	d8640526 	ld.b      	r3, (r4, 0x526)
     384:	64ca      	cmpne      	r2, r3
     386:	081a      	bt      	0x3ba	// 3ba <non_ndp_rx_hdl+0x3ba>
     388:	8545      	ld.b      	r2, (r5, 0x5)
     38a:	d8640527 	ld.b      	r3, (r4, 0x527)
     38e:	64ca      	cmpne      	r2, r3
     390:	0815      	bt      	0x3ba	// 3ba <non_ndp_rx_hdl+0x3ba>
     392:	8546      	ld.b      	r2, (r5, 0x6)
     394:	d8640528 	ld.b      	r3, (r4, 0x528)
     398:	64ca      	cmpne      	r2, r3
     39a:	0810      	bt      	0x3ba	// 3ba <non_ndp_rx_hdl+0x3ba>
     39c:	8547      	ld.b      	r2, (r5, 0x7)
     39e:	d8640529 	ld.b      	r3, (r4, 0x529)
     3a2:	64ca      	cmpne      	r2, r3
     3a4:	080b      	bt      	0x3ba	// 3ba <non_ndp_rx_hdl+0x3ba>
     3a6:	8548      	ld.b      	r2, (r5, 0x8)
     3a8:	d864052a 	ld.b      	r3, (r4, 0x52a)
     3ac:	64ca      	cmpne      	r2, r3
     3ae:	0806      	bt      	0x3ba	// 3ba <non_ndp_rx_hdl+0x3ba>
     3b0:	8549      	ld.b      	r2, (r5, 0x9)
     3b2:	d864052b 	ld.b      	r3, (r4, 0x52b)
     3b6:	64ca      	cmpne      	r2, r3
     3b8:	0c05      	bf      	0x3c2	// 3c2 <non_ndp_rx_hdl+0x3c2>
     3ba:	d864202f 	ld.w      	r3, (r4, 0xbc)
     3be:	e923ffa6 	bnez      	r3, 0x30a	// 30a <non_ndp_rx_hdl+0x30a>
     3c2:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
     3c6:	d86411e5 	ld.h      	r3, (r4, 0x3ca)
     3ca:	dc6411e4 	st.h      	r3, (r4, 0x3c8)
     3ce:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
     3d2:	e4632080 	andi      	r3, r3, 128
     3d6:	dc0420f3 	st.w      	r0, (r4, 0x3cc)
     3da:	dc2420f4 	st.w      	r1, (r4, 0x3d0)
     3de:	e903ff96 	bez      	r3, 0x30a	// 30a <non_ndp_rx_hdl+0x30a>
     3e2:	100c      	lrw      	r0, 0x0	// 410 <hgprintf+0x410>
     3e4:	e0000000 	bsr      	0x0	// 0 <hgprintf>
     3e8:	0791      	br      	0x30a	// 30a <non_ndp_rx_hdl+0x30a>
	...
     412:	0000      	.short	0x0000
     414:	854f      	ld.b      	r2, (r5, 0xf)
     416:	4228      	lsli      	r1, r2, 8
     418:	8550      	ld.b      	r2, (r5, 0x10)
     41a:	4250      	lsli      	r2, r2, 16
     41c:	6084      	addu      	r2, r1
     41e:	8531      	ld.b      	r1, (r5, 0x11)
     420:	4138      	lsli      	r1, r1, 24
     422:	e5650011 	addi      	r11, r5, 18
     426:	6084      	addu      	r2, r1
     428:	0794      	br      	0x350	// 350 <non_ndp_rx_hdl+0x350>
     42a:	d864202f 	ld.w      	r3, (r4, 0xbc)
     42e:	3b41      	cmpnei      	r3, 1
     430:	0b6d      	bt      	0x30a	// 30a <non_ndp_rx_hdl+0x30a>
     432:	8544      	ld.b      	r2, (r5, 0x4)
     434:	d8640526 	ld.b      	r3, (r4, 0x526)
     438:	64ca      	cmpne      	r2, r3
     43a:	0b68      	bt      	0x30a	// 30a <non_ndp_rx_hdl+0x30a>
     43c:	8545      	ld.b      	r2, (r5, 0x5)
     43e:	d8640527 	ld.b      	r3, (r4, 0x527)
     442:	64ca      	cmpne      	r2, r3
     444:	0b63      	bt      	0x30a	// 30a <non_ndp_rx_hdl+0x30a>
     446:	8546      	ld.b      	r2, (r5, 0x6)
     448:	d8640528 	ld.b      	r3, (r4, 0x528)
     44c:	64ca      	cmpne      	r2, r3
     44e:	0b5e      	bt      	0x30a	// 30a <non_ndp_rx_hdl+0x30a>
     450:	8547      	ld.b      	r2, (r5, 0x7)
     452:	d8640529 	ld.b      	r3, (r4, 0x529)
     456:	64ca      	cmpne      	r2, r3
     458:	0b59      	bt      	0x30a	// 30a <non_ndp_rx_hdl+0x30a>
     45a:	8548      	ld.b      	r2, (r5, 0x8)
     45c:	d864052a 	ld.b      	r3, (r4, 0x52a)
     460:	64ca      	cmpne      	r2, r3
     462:	0b54      	bt      	0x30a	// 30a <non_ndp_rx_hdl+0x30a>
     464:	8549      	ld.b      	r2, (r5, 0x9)
     466:	d864052b 	ld.b      	r3, (r4, 0x52b)
     46a:	64ca      	cmpne      	r2, r3
     46c:	0b4f      	bt      	0x30a	// 30a <non_ndp_rx_hdl+0x30a>
     46e:	d8642267 	ld.w      	r3, (r4, 0x99c)
     472:	3b41      	cmpnei      	r3, 1
     474:	0803      	bt      	0x47a	// 47a <non_ndp_rx_hdl+0x47a>
     476:	dc640318 	st.b      	r3, (r4, 0x318)
     47a:	9866      	ld.w      	r3, (r14, 0x18)
     47c:	ea8a00cd 	lrw      	r10, 0x0	// 7b0 <non_ndp_rx_hdl+0x7b0>
     480:	9360      	ld.w      	r3, (r3, 0x0)
     482:	9365      	ld.w      	r3, (r3, 0x14)
     484:	dc642199 	st.w      	r3, (r4, 0x664)
     488:	3300      	movi      	r3, 0
     48a:	b86c      	st.w      	r3, (r14, 0x30)
     48c:	0175      	lrw      	r3, 0x0	// 7b4 <non_ndp_rx_hdl+0x7b4>
     48e:	b86d      	st.w      	r3, (r14, 0x34)
     490:	c5250023 	addu      	r3, r5, r9
     494:	64ec      	cmphs      	r11, r3
     496:	0cc2      	bf      	0x61a	// 61a <non_ndp_rx_hdl+0x61a>
     498:	d86800be 	ld.b      	r3, (r8, 0xbe)
     49c:	e4632003 	andi      	r3, r3, 3
     4a0:	3b41      	cmpnei      	r3, 1
     4a2:	0df6      	bf      	0x88e	// 88e <non_ndp_rx_hdl+0x88e>
     4a4:	e90301f7 	bez      	r3, 0x892	// 892 <non_ndp_rx_hdl+0x892>
     4a8:	3b42      	cmpnei      	r3, 2
     4aa:	6583      	mvcv      	r6
     4ac:	46c3      	lsli      	r6, r6, 3
     4ae:	9866      	ld.w      	r3, (r14, 0x18)
     4b0:	e4050009 	addi      	r0, r5, 10
     4b4:	9360      	ld.w      	r3, (r3, 0x0)
     4b6:	9345      	ld.w      	r2, (r3, 0x14)
     4b8:	b849      	st.w      	r2, (r14, 0x24)
     4ba:	9364      	ld.w      	r3, (r3, 0x10)
     4bc:	3200      	movi      	r2, 0
     4be:	b848      	st.w      	r2, (r14, 0x20)
     4c0:	b872      	st.w      	r3, (r14, 0x48)
     4c2:	b853      	st.w      	r2, (r14, 0x4c)
     4c4:	d98e2012 	ld.w      	r12, (r14, 0x48)
     4c8:	d9ae2013 	ld.w      	r13, (r14, 0x4c)
     4cc:	9848      	ld.w      	r2, (r14, 0x20)
     4ce:	9869      	ld.w      	r3, (r14, 0x24)
     4d0:	6731      	cmplt      	r12, r12
     4d2:	6309      	addc      	r12, r2
     4d4:	634d      	addc      	r13, r3
     4d6:	d8682031 	ld.w      	r3, (r8, 0xc4)
     4da:	618c      	addu      	r6, r3
     4dc:	3328      	movi      	r3, 40
     4de:	7d8c      	mult      	r6, r3
     4e0:	d8642199 	ld.w      	r3, (r4, 0x664)
     4e4:	7599      	zexth      	r6, r6
     4e6:	b871      	st.w      	r3, (r14, 0x44)
     4e8:	9868      	ld.w      	r3, (r14, 0x20)
     4ea:	b870      	st.w      	r3, (r14, 0x40)
     4ec:	dd8e200d 	st.w      	r12, (r14, 0x34)
     4f0:	ddae200e 	st.w      	r13, (r14, 0x38)
     4f4:	dcc4133a 	st.h      	r6, (r4, 0x674)
     4f8:	e0000000 	bsr      	0x0	// 0 <non_ndp_rx_hdl>
     4fc:	6dc3      	mov      	r7, r0
     4fe:	e0000000 	bsr      	0x0	// 0 <non_ndp_rx_hdl>
     502:	601c      	addu      	r0, r7
     504:	2018      	addi      	r0, 25
     506:	5878      	addu      	r3, r0, r6
     508:	b874      	st.w      	r3, (r14, 0x50)
     50a:	9868      	ld.w      	r3, (r14, 0x20)
     50c:	b875      	st.w      	r3, (r14, 0x54)
     50e:	d94e2014 	ld.w      	r10, (r14, 0x50)
     512:	d96e2015 	ld.w      	r11, (r14, 0x54)
     516:	9850      	ld.w      	r2, (r14, 0x40)
     518:	9871      	ld.w      	r3, (r14, 0x44)
     51a:	66a9      	cmplt      	r10, r10
     51c:	6289      	addc      	r10, r2
     51e:	62cd      	addc      	r11, r3
     520:	9866      	ld.w      	r3, (r14, 0x18)
     522:	d8c42233 	ld.w      	r6, (r4, 0x8cc)
     526:	93e0      	ld.w      	r7, (r3, 0x0)
     528:	dd472004 	st.w      	r10, (r7, 0x10)
     52c:	dd672005 	st.w      	r11, (r7, 0x14)
     530:	e9060035 	bez      	r6, 0x59a	// 59a <non_ndp_rx_hdl+0x59a>
     534:	d84620b8 	ld.w      	r2, (r6, 0x2e0)
     538:	d86620b9 	ld.w      	r3, (r6, 0x2e4)
     53c:	c4622421 	or      	r1, r2, r3
     540:	e90101ab 	bez      	r1, 0x896	// 896 <non_ndp_rx_hdl+0x896>
     544:	66cc      	cmphs      	r3, r11
     546:	0c05      	bf      	0x550	// 550 <non_ndp_rx_hdl+0x550>
     548:	64ee      	cmpne      	r11, r3
     54a:	09a6      	bt      	0x896	// 896 <non_ndp_rx_hdl+0x896>
     54c:	6688      	cmphs      	r2, r10
     54e:	09a4      	bt      	0x896	// 896 <non_ndp_rx_hdl+0x896>
     550:	d80620b6 	ld.w      	r0, (r6, 0x2d8)
     554:	d82620b7 	ld.w      	r1, (r6, 0x2dc)
     558:	6730      	cmphs      	r12, r12
     55a:	c440010c 	subc      	r12, r0, r2
     55e:	c461010d 	subc      	r13, r1, r3
     562:	6401      	cmplt      	r0, r0
     564:	c54c0040 	addc      	r0, r12, r10
     568:	c56d0041 	addc      	r1, r13, r11
     56c:	ea02eebb 	movi      	r2, 61115
     570:	c5a24902 	rotli      	r2, r2, 13
     574:	3314      	movi      	r3, 20
     576:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
     57a:	dc0620b6 	st.w      	r0, (r6, 0x2d8)
     57e:	dc2620b7 	st.w      	r1, (r6, 0x2dc)
     582:	dd4620b8 	st.w      	r10, (r6, 0x2e0)
     586:	dd6620b9 	st.w      	r11, (r6, 0x2e4)
     58a:	dc0620b2 	st.w      	r0, (r6, 0x2c8)
     58e:	dc2620b3 	st.w      	r1, (r6, 0x2cc)
     592:	dd4620b4 	st.w      	r10, (r6, 0x2d0)
     596:	dd6620b5 	st.w      	r11, (r6, 0x2d4)
     59a:	d86409df 	ld.b      	r3, (r4, 0x9df)
     59e:	3201      	movi      	r2, 1
     5a0:	c4625c06 	ins      	r3, r2, 6, 6
     5a4:	dc6409df 	st.b      	r3, (r4, 0x9df)
     5a8:	9725      	ld.w      	r1, (r7, 0x14)
     5aa:	9764      	ld.w      	r3, (r7, 0x10)
     5ac:	b86a      	st.w      	r3, (r14, 0x28)
     5ae:	3300      	movi      	r3, 0
     5b0:	b86b      	st.w      	r3, (r14, 0x2c)
     5b2:	d864133a 	ld.h      	r3, (r4, 0x674)
     5b6:	b876      	st.w      	r3, (r14, 0x58)
     5b8:	986b      	ld.w      	r3, (r14, 0x2c)
     5ba:	b877      	st.w      	r3, (r14, 0x5c)
     5bc:	b839      	st.w      	r1, (r14, 0x64)
     5be:	982b      	ld.w      	r1, (r14, 0x2c)
     5c0:	984a      	ld.w      	r2, (r14, 0x28)
     5c2:	986b      	ld.w      	r3, (r14, 0x2c)
     5c4:	d98e2016 	ld.w      	r12, (r14, 0x58)
     5c8:	d9ae2017 	ld.w      	r13, (r14, 0x5c)
     5cc:	b838      	st.w      	r1, (r14, 0x60)
     5ce:	6488      	cmphs      	r2, r2
     5d0:	60b3      	subc      	r2, r12
     5d2:	60f7      	subc      	r3, r13
     5d4:	9818      	ld.w      	r0, (r14, 0x60)
     5d6:	9839      	ld.w      	r1, (r14, 0x64)
     5d8:	6401      	cmplt      	r0, r0
     5da:	6009      	addc      	r0, r2
     5dc:	604d      	addc      	r1, r3
     5de:	6c83      	mov      	r2, r0
     5e0:	6cc7      	mov      	r3, r1
     5e2:	982f      	ld.w      	r1, (r14, 0x3c)
     5e4:	b83a      	st.w      	r1, (r14, 0x68)
     5e6:	982b      	ld.w      	r1, (r14, 0x2c)
     5e8:	b83b      	st.w      	r1, (r14, 0x6c)
     5ea:	981a      	ld.w      	r0, (r14, 0x68)
     5ec:	983b      	ld.w      	r1, (r14, 0x6c)
     5ee:	6401      	cmplt      	r0, r0
     5f0:	6009      	addc      	r0, r2
     5f2:	604d      	addc      	r1, r3
     5f4:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
     5f8:	e4632080 	andi      	r3, r3, 128
     5fc:	dc0420fa 	st.w      	r0, (r4, 0x3e8)
     600:	dc2420fb 	st.w      	r1, (r4, 0x3ec)
     604:	e9030006 	bez      	r3, 0x610	// 610 <non_ndp_rx_hdl+0x610>
     608:	982c      	ld.w      	r1, (r14, 0x30)
     60a:	130c      	lrw      	r0, 0x0	// 7b8 <non_ndp_rx_hdl+0x7b8>
     60c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
     610:	986c      	ld.w      	r3, (r14, 0x30)
     612:	e903fe7c 	bez      	r3, 0x30a	// 30a <non_ndp_rx_hdl+0x30a>
     616:	e80002e4 	br      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     61a:	d86b0000 	ld.b      	r3, (r11, 0x0)
     61e:	eb430025 	cmpnei      	r3, 37
     622:	d82b0001 	ld.b      	r1, (r11, 0x1)
     626:	0cd9      	bf      	0x7d8	// 7d8 <non_ndp_rx_hdl+0x7d8>
     628:	eb030025 	cmphsi      	r3, 38
     62c:	0814      	bt      	0x654	// 654 <non_ndp_rx_hdl+0x654>
     62e:	3b44      	cmpnei      	r3, 4
     630:	0d0a      	bf      	0x844	// 844 <non_ndp_rx_hdl+0x844>
     632:	3b45      	cmpnei      	r3, 5
     634:	0c2c      	bf      	0x68c	// 68c <non_ndp_rx_hdl+0x68c>
     636:	e923000a 	bnez      	r3, 0x64a	// 64a <non_ndp_rx_hdl+0x64a>
     63a:	eb010020 	cmphsi      	r1, 33
     63e:	0823      	bt      	0x684	// 684 <non_ndp_rx_hdl+0x684>
     640:	5946      	addi      	r2, r1, 2
     642:	121f      	lrw      	r0, 0x0	// 7bc <non_ndp_rx_hdl+0x7bc>
     644:	6c6f      	mov      	r1, r11
     646:	e0000000 	bsr      	0x0	// 0 <memcpy>
     64a:	d86b0001 	ld.b      	r3, (r11, 0x1)
     64e:	2301      	addi      	r3, 2
     650:	62cc      	addu      	r11, r3
     652:	071f      	br      	0x490	// 490 <non_ndp_rx_hdl+0x490>
     654:	eb4300d6 	cmpnei      	r3, 214
     658:	0ca8      	bf      	0x7a8	// 7a8 <non_ndp_rx_hdl+0x7a8>
     65a:	eb4300d9 	cmpnei      	r3, 217
     65e:	0c8f      	bf      	0x77c	// 77c <non_ndp_rx_hdl+0x77c>
     660:	eb4300d5 	cmpnei      	r3, 213
     664:	0bf3      	bt      	0x64a	// 64a <non_ndp_rx_hdl+0x64a>
     666:	d86b0003 	ld.b      	r3, (r11, 0x3)
     66a:	d84b0002 	ld.b      	r2, (r11, 0x2)
     66e:	4368      	lsli      	r3, r3, 8
     670:	6cc8      	or      	r3, r2
     672:	e40b0005 	addi      	r0, r11, 6
     676:	dc64132a 	st.h      	r3, (r4, 0x654)
     67a:	e0000000 	bsr      	0x0	// 0 <non_ndp_rx_hdl>
     67e:	dc042199 	st.w      	r0, (r4, 0x664)
     682:	07e4      	br      	0x64a	// 64a <non_ndp_rx_hdl+0x64a>
     684:	120f      	lrw      	r0, 0x0	// 7c0 <non_ndp_rx_hdl+0x7c0>
     686:	e0000000 	bsr      	0x0	// 0 <hgprintf>
     68a:	07e0      	br      	0x64a	// 64a <non_ndp_rx_hdl+0x64a>
     68c:	d86b0002 	ld.b      	r3, (r11, 0x2)
     690:	dc640555 	st.b      	r3, (r4, 0x555)
     694:	d86b0003 	ld.b      	r3, (r11, 0x3)
     698:	dc640556 	st.b      	r3, (r4, 0x556)
     69c:	d80b0004 	ld.b      	r0, (r11, 0x4)
     6a0:	e5a02001 	andi      	r13, r0, 1
     6a4:	e58b0001 	addi      	r12, r11, 2
     6a8:	e92d001e 	bnez      	r13, 0x6e4	// 6e4 <non_ndp_rx_hdl+0x6e4>
     6ac:	d8641198 	ld.h      	r3, (r4, 0x330)
     6b0:	c4635542 	zext      	r2, r3, 10, 3
     6b4:	3101      	movi      	r1, 1
     6b6:	e4632007 	andi      	r3, r3, 7
     6ba:	c4614023 	lsl      	r3, r1, r3
     6be:	e40020fe 	andi      	r0, r0, 254
     6c2:	d82b0001 	ld.b      	r1, (r11, 0x1)
     6c6:	2903      	subi      	r1, 4
     6c8:	6408      	cmphs      	r2, r0
     6ca:	6040      	addu      	r1, r0
     6cc:	74cc      	zextb      	r3, r3
     6ce:	7444      	zextb      	r1, r1
     6d0:	0c26      	bf      	0x71c	// 71c <non_ndp_rx_hdl+0x71c>
     6d2:	6484      	cmphs      	r1, r2
     6d4:	0c24      	bf      	0x71c	// 71c <non_ndp_rx_hdl+0x71c>
     6d6:	6082      	subu      	r2, r0
     6d8:	7488      	zextb      	r2, r2
     6da:	60b0      	addu      	r2, r12
     6dc:	8243      	ld.b      	r2, (r2, 0x3)
     6de:	68c8      	and      	r3, r2
     6e0:	e903001e 	bez      	r3, 0x71c	// 71c <non_ndp_rx_hdl+0x71c>
     6e4:	d8640319 	ld.b      	r3, (r4, 0x319)
     6e8:	e4432002 	andi      	r2, r3, 2
     6ec:	e9020018 	bez      	r2, 0x71c	// 71c <non_ndp_rx_hdl+0x71c>
     6f0:	3201      	movi      	r2, 1
     6f2:	e46320fd 	andi      	r3, r3, 253
     6f6:	c4625c00 	ins      	r3, r2, 0, 0
     6fa:	dc640319 	st.b      	r3, (r4, 0x319)
     6fe:	eb4d0000 	cmpnei      	r13, 0
     702:	986d      	ld.w      	r3, (r14, 0x34)
     704:	1130      	lrw      	r1, 0x0	// 7c4 <non_ndp_rx_hdl+0x7c4>
     706:	c4230c40 	inct      	r1, r3, 0
     70a:	1110      	lrw      	r0, 0x0	// 7c8 <hgprintf+0x7c8>
     70c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
     710:	d82b0001 	ld.b      	r1, (r11, 0x1)
     714:	2101      	addi      	r1, 2
     716:	6c2f      	mov      	r0, r11
     718:	e0000000 	bsr      	0x0	// 0 <hgics_print_hex>
     71c:	d8640555 	ld.b      	r3, (r4, 0x555)
     720:	e9230007 	bnez      	r3, 0x72e	// 72e <non_ndp_rx_hdl+0x72e>
     724:	d86a2000 	ld.w      	r3, (r10, 0x0)
     728:	2300      	addi      	r3, 1
     72a:	dc6a2000 	st.w      	r3, (r10, 0x0)
     72e:	d8440319 	ld.b      	r2, (r4, 0x319)
     732:	e4622002 	andi      	r3, r2, 2
     736:	e903001f 	bez      	r3, 0x774	// 774 <non_ndp_rx_hdl+0x774>
     73a:	d824132b 	ld.h      	r1, (r4, 0x656)
     73e:	d8640556 	ld.b      	r3, (r4, 0x556)
     742:	7cc4      	mult      	r3, r1
     744:	d82a2000 	ld.w      	r1, (r10, 0x0)
     748:	7cc4      	mult      	r3, r1
     74a:	d824133b 	ld.h      	r1, (r4, 0x676)
     74e:	4921      	lsri      	r1, r1, 1
     750:	64c4      	cmphs      	r1, r3
     752:	080f      	bt      	0x770	// 770 <non_ndp_rx_hdl+0x770>
     754:	6ccb      	mov      	r3, r2
     756:	3600      	movi      	r6, 0
     758:	c4665c01 	ins      	r3, r6, 1, 1
     75c:	dc640319 	st.b      	r3, (r4, 0x319)
     760:	3301      	movi      	r3, 1
     762:	101b      	lrw      	r0, 0x0	// 7cc <non_ndp_rx_hdl+0x7cc>
     764:	dc640318 	st.b      	r3, (r4, 0x318)
     768:	e0000000 	bsr      	0x0	// 0 <hgprintf>
     76c:	dcca2000 	st.w      	r6, (r10, 0x0)
     770:	3300      	movi      	r3, 0
     772:	2b00      	subi      	r3, 1
     774:	984c      	ld.w      	r2, (r14, 0x30)
     776:	6c8c      	or      	r2, r3
     778:	b84c      	st.w      	r2, (r14, 0x30)
     77a:	0768      	br      	0x64a	// 64a <non_ndp_rx_hdl+0x64a>
     77c:	394f      	cmpnei      	r1, 15
     77e:	0813      	bt      	0x7a4	// 7a4 <non_ndp_rx_hdl+0x7a4>
     780:	e4cb0001 	addi      	r6, r11, 2
     784:	6c87      	mov      	r2, r1
     786:	1013      	lrw      	r0, 0x0	// 7d0 <non_ndp_rx_hdl+0x7d0>
     788:	6c5b      	mov      	r1, r6
     78a:	e0000000 	bsr      	0x0	// 0 <memcpy>
     78e:	d86b000a 	ld.b      	r3, (r11, 0xa)
     792:	d8440668 	ld.b      	r2, (r4, 0x668)
     796:	c4435483 	zext      	r3, r3, 4, 2
     79a:	c4435c40 	ins      	r2, r3, 2, 0
     79e:	dc440668 	st.b      	r2, (r4, 0x668)
     7a2:	0754      	br      	0x64a	// 64a <non_ndp_rx_hdl+0x64a>
     7a4:	100c      	lrw      	r0, 0x0	// 7d4 <non_ndp_rx_hdl+0x7d4>
     7a6:	0770      	br      	0x686	// 686 <non_ndp_rx_hdl+0x686>
     7a8:	6c2f      	mov      	r0, r11
     7aa:	e0000000 	bsr      	0x0	// 0 <element_short_beacon_interval_hdl>
     7ae:	074e      	br      	0x64a	// 64a <non_ndp_rx_hdl+0x64a>
	...
     7d8:	3943      	cmpnei      	r1, 3
     7da:	0833      	bt      	0x840	// 840 <non_ndp_rx_hdl+0x840>
     7dc:	d8642196 	ld.w      	r3, (r4, 0x658)
     7e0:	d8cb0004 	ld.b      	r6, (r11, 0x4)
     7e4:	7d8c      	mult      	r6, r3
     7e6:	d86b0002 	ld.b      	r3, (r11, 0x2)
     7ea:	264f      	addi      	r6, 80
     7ec:	e9030005 	bez      	r3, 0x7f6	// 7f6 <non_ndp_rx_hdl+0x7f6>
     7f0:	6c1b      	mov      	r0, r6
     7f2:	e0000000 	bsr      	0x0	// 0 <lmac_set_basic_nav>
     7f6:	32fa      	movi      	r2, 250
     7f8:	d86b0003 	ld.b      	r3, (r11, 0x3)
     7fc:	4242      	lsli      	r2, r2, 2
     7fe:	7cc8      	mult      	r3, r2
     800:	ea02aae6 	movi      	r2, 43750
     804:	c4824902 	rotli      	r2, r2, 4
     808:	60c8      	addu      	r3, r2
     80a:	d84420ce 	ld.w      	r2, (r4, 0x338)
     80e:	c4825762 	zext      	r2, r2, 27, 4
     812:	648e      	cmpne      	r3, r2
     814:	dc6420d1 	st.w      	r3, (r4, 0x344)
     818:	0f19      	bf      	0x64a	// 64a <non_ndp_rx_hdl+0x64a>
     81a:	e906ff18 	bez      	r6, 0x64a	// 64a <non_ndp_rx_hdl+0x64a>
     81e:	9866      	ld.w      	r3, (r14, 0x18)
     820:	9360      	ld.w      	r3, (r3, 0x0)
     822:	d8432033 	ld.w      	r2, (r3, 0xcc)
     826:	ec420800 	ori      	r2, r2, 2048
     82a:	dc432033 	st.w      	r2, (r3, 0xcc)
     82e:	dcc32036 	st.w      	r6, (r3, 0xd8)
     832:	d8432033 	ld.w      	r2, (r3, 0xcc)
     836:	ec420400 	ori      	r2, r2, 1024
     83a:	dc432033 	st.w      	r2, (r3, 0xcc)
     83e:	0706      	br      	0x64a	// 64a <non_ndp_rx_hdl+0x64a>
     840:	0015      	lrw      	r0, 0x0	// be8 <non_ndp_rx_hdl+0xbe8>
     842:	0722      	br      	0x686	// 686 <non_ndp_rx_hdl+0x686>
     844:	3946      	cmpnei      	r1, 6
     846:	0821      	bt      	0x888	// 888 <non_ndp_rx_hdl+0x888>
     848:	d8eb0005 	ld.b      	r7, (r11, 0x5)
     84c:	d86b0004 	ld.b      	r3, (r11, 0x4)
     850:	47e8      	lsli      	r7, r7, 8
     852:	d8cb0007 	ld.b      	r6, (r11, 0x7)
     856:	61cc      	addu      	r7, r3
     858:	46c8      	lsli      	r6, r6, 8
     85a:	d86b0006 	ld.b      	r3, (r11, 0x6)
     85e:	618c      	addu      	r6, r3
     860:	d86b0002 	ld.b      	r3, (r11, 0x2)
     864:	75dd      	zexth      	r7, r7
     866:	7599      	zexth      	r6, r6
     868:	e923000e 	bnez      	r3, 0x884	// 884 <non_ndp_rx_hdl+0x884>
     86c:	470a      	lsli      	r0, r7, 10
     86e:	e0000000 	bsr      	0x0	// 0 <lmac_set_basic_nav>
     872:	d864202f 	ld.w      	r3, (r4, 0xbc)
     876:	3b41      	cmpnei      	r3, 1
     878:	0ae9      	bt      	0x64a	// 64a <non_ndp_rx_hdl+0x64a>
     87a:	dce4143e 	st.h      	r7, (r4, 0x87c)
     87e:	dcc4143f 	st.h      	r6, (r4, 0x87e)
     882:	06e4      	br      	0x64a	// 64a <non_ndp_rx_hdl+0x64a>
     884:	460a      	lsli      	r0, r6, 10
     886:	07f4      	br      	0x86e	// 86e <non_ndp_rx_hdl+0x86e>
     888:	0126      	lrw      	r1, 0x0	// bec <non_ndp_rx_hdl+0xbec>
     88a:	0105      	lrw      	r0, 0x0	// bf0 <non_ndp_rx_hdl+0xbf0>
     88c:	06fd      	br      	0x686	// 686 <non_ndp_rx_hdl+0x686>
     88e:	3606      	movi      	r6, 6
     890:	060f      	br      	0x4ae	// 4ae <non_ndp_rx_hdl+0x4ae>
     892:	360e      	movi      	r6, 14
     894:	060d      	br      	0x4ae	// 4ae <non_ndp_rx_hdl+0x4ae>
     896:	d84620b4 	ld.w      	r2, (r6, 0x2d0)
     89a:	d86620b5 	ld.w      	r3, (r6, 0x2d4)
     89e:	c4622421 	or      	r1, r2, r3
     8a2:	e901fe7c 	bez      	r1, 0x59a	// 59a <non_ndp_rx_hdl+0x59a>
     8a6:	982e      	ld.w      	r1, (r14, 0x38)
     8a8:	644c      	cmphs      	r3, r1
     8aa:	0c06      	bf      	0x8b6	// 8b6 <non_ndp_rx_hdl+0x8b6>
     8ac:	64c6      	cmpne      	r1, r3
     8ae:	0a76      	bt      	0x59a	// 59a <non_ndp_rx_hdl+0x59a>
     8b0:	982d      	ld.w      	r1, (r14, 0x34)
     8b2:	6448      	cmphs      	r2, r1
     8b4:	0a73      	bt      	0x59a	// 59a <non_ndp_rx_hdl+0x59a>
     8b6:	d80620b2 	ld.w      	r0, (r6, 0x2c8)
     8ba:	d82620b3 	ld.w      	r1, (r6, 0x2cc)
     8be:	6730      	cmphs      	r12, r12
     8c0:	c440010c 	subc      	r12, r0, r2
     8c4:	c461010d 	subc      	r13, r1, r3
     8c8:	6c33      	mov      	r0, r12
     8ca:	6c77      	mov      	r1, r13
     8cc:	d98e200d 	ld.w      	r12, (r14, 0x34)
     8d0:	d9ae200e 	ld.w      	r13, (r14, 0x38)
     8d4:	6731      	cmplt      	r12, r12
     8d6:	6301      	addc      	r12, r0
     8d8:	6345      	addc      	r13, r1
     8da:	ea02eebb 	movi      	r2, 61115
     8de:	c5a24902 	rotli      	r2, r2, 13
     8e2:	3314      	movi      	r3, 20
     8e4:	6c33      	mov      	r0, r12
     8e6:	6c77      	mov      	r1, r13
     8e8:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
     8ec:	dc0620b2 	st.w      	r0, (r6, 0x2c8)
     8f0:	dc2620b3 	st.w      	r1, (r6, 0x2cc)
     8f4:	dd4620b4 	st.w      	r10, (r6, 0x2d0)
     8f8:	dd6620b5 	st.w      	r11, (r6, 0x2d4)
     8fc:	dc0620b6 	st.w      	r0, (r6, 0x2d8)
     900:	dc2620b7 	st.w      	r1, (r6, 0x2dc)
     904:	dd4620b8 	st.w      	r10, (r6, 0x2e0)
     908:	dd6620b9 	st.w      	r11, (r6, 0x2e4)
     90c:	0647      	br      	0x59a	// 59a <non_ndp_rx_hdl+0x59a>
     90e:	3b4f      	cmpnei      	r3, 15
     910:	0967      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     912:	8564      	ld.b      	r3, (r5, 0x4)
     914:	e9230015 	bnez      	r3, 0x93e	// 93e <non_ndp_rx_hdl+0x93e>
     918:	8545      	ld.b      	r2, (r5, 0x5)
     91a:	3a50      	cmpnei      	r2, 16
     91c:	0811      	bt      	0x93e	// 93e <non_ndp_rx_hdl+0x93e>
     91e:	8546      	ld.b      	r2, (r5, 0x6)
     920:	eb420020 	cmpnei      	r2, 32
     924:	080d      	bt      	0x93e	// 93e <non_ndp_rx_hdl+0x93e>
     926:	8547      	ld.b      	r2, (r5, 0x7)
     928:	eb420030 	cmpnei      	r2, 48
     92c:	0809      	bt      	0x93e	// 93e <non_ndp_rx_hdl+0x93e>
     92e:	8548      	ld.b      	r2, (r5, 0x8)
     930:	eb420040 	cmpnei      	r2, 64
     934:	0805      	bt      	0x93e	// 93e <non_ndp_rx_hdl+0x93e>
     936:	8549      	ld.b      	r2, (r5, 0x9)
     938:	eb420050 	cmpnei      	r2, 80
     93c:	0c1e      	bf      	0x978	// 978 <non_ndp_rx_hdl+0x978>
     93e:	d8440302 	ld.b      	r2, (r4, 0x302)
     942:	64ca      	cmpne      	r2, r3
     944:	094d      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     946:	8545      	ld.b      	r2, (r5, 0x5)
     948:	d8640303 	ld.b      	r3, (r4, 0x303)
     94c:	64ca      	cmpne      	r2, r3
     94e:	0948      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     950:	8546      	ld.b      	r2, (r5, 0x6)
     952:	d8640304 	ld.b      	r3, (r4, 0x304)
     956:	64ca      	cmpne      	r2, r3
     958:	0943      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     95a:	8547      	ld.b      	r2, (r5, 0x7)
     95c:	d8640305 	ld.b      	r3, (r4, 0x305)
     960:	64ca      	cmpne      	r2, r3
     962:	093e      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     964:	8548      	ld.b      	r2, (r5, 0x8)
     966:	d8640306 	ld.b      	r3, (r4, 0x306)
     96a:	64ca      	cmpne      	r2, r3
     96c:	0939      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     96e:	8549      	ld.b      	r2, (r5, 0x9)
     970:	d8640307 	ld.b      	r3, (r4, 0x307)
     974:	64ca      	cmpne      	r2, r3
     976:	0934      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     978:	d8640892 	ld.b      	r3, (r4, 0x892)
     97c:	e4632001 	andi      	r3, r3, 1
     980:	e923012f 	bnez      	r3, 0xbde	// bde <non_ndp_rx_hdl+0xbde>
     984:	d9250017 	ld.b      	r9, (r5, 0x17)
     988:	8576      	ld.b      	r3, (r5, 0x16)
     98a:	c5094829 	lsli      	r9, r9, 8
     98e:	6e4c      	or      	r9, r3
     990:	c4894849 	lsri      	r9, r9, 4
     994:	e0000000 	bsr      	0x0	// 0 <lmac_get_avg_power>
     998:	75e6      	sextb      	r7, r9
     99a:	65c1      	cmplt      	r0, r7
     99c:	6d83      	mov      	r6, r0
     99e:	0920      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     9a0:	8578      	ld.b      	r3, (r5, 0x18)
     9a2:	eb4300dd 	cmpnei      	r3, 221
     9a6:	0814      	bt      	0x9ce	// 9ce <non_ndp_rx_hdl+0x9ce>
     9a8:	8579      	ld.b      	r3, (r5, 0x19)
     9aa:	3b49      	cmpnei      	r3, 9
     9ac:	0811      	bt      	0x9ce	// 9ce <non_ndp_rx_hdl+0x9ce>
     9ae:	857a      	ld.b      	r3, (r5, 0x1a)
     9b0:	eb430080 	cmpnei      	r3, 128
     9b4:	080d      	bt      	0x9ce	// 9ce <non_ndp_rx_hdl+0x9ce>
     9b6:	857f      	ld.b      	r3, (r5, 0x1f)
     9b8:	e4632001 	andi      	r3, r3, 1
     9bc:	e9030009 	bez      	r3, 0x9ce	// 9ce <non_ndp_rx_hdl+0x9ce>
     9c0:	d8640892 	ld.b      	r3, (r4, 0x892)
     9c4:	3201      	movi      	r2, 1
     9c6:	c4625c02 	ins      	r3, r2, 2, 2
     9ca:	dc640892 	st.b      	r3, (r4, 0x892)
     9ce:	d8641496 	ld.h      	r3, (r4, 0x92c)
     9d2:	c4695d60 	ins      	r3, r9, 11, 0
     9d6:	3206      	movi      	r2, 6
     9d8:	e4250009 	addi      	r1, r5, 10
     9dc:	0319      	lrw      	r0, 0x0	// bf4 <non_ndp_rx_hdl+0xbf4>
     9de:	dc641496 	st.h      	r3, (r4, 0x92c)
     9e2:	e0000000 	bsr      	0x0	// 0 <memcpy>
     9e6:	033a      	lrw      	r1, 0x0	// bf8 <non_ndp_rx_hdl+0xbf8>
     9e8:	e4010621 	addi      	r0, r1, 1570
     9ec:	3206      	movi      	r2, 6
     9ee:	e0000000 	bsr      	0x0	// 0 <memcpy>
     9f2:	3255      	movi      	r2, 85
     9f4:	d8641495 	ld.h      	r3, (r4, 0x92a)
     9f8:	c4625ce4 	ins      	r3, r2, 11, 4
     9fc:	dc641495 	st.h      	r3, (r4, 0x92a)
     a00:	dcc4092e 	st.b      	r6, (r4, 0x92e)
     a04:	e0000000 	bsr      	0x0	// 0 <ah_wphy_avg_evm_get>
     a08:	dc04092f 	st.b      	r0, (r4, 0x92f)
     a0c:	e0000000 	bsr      	0x0	// 0 <ah_wphy_rx_freq_offset_get>
     a10:	33fa      	movi      	r3, 250
     a12:	4362      	lsli      	r3, r3, 2
     a14:	c4608040 	divs      	r0, r0, r3
     a18:	3300      	movi      	r3, 0
     a1a:	2b7f      	subi      	r3, 128
     a1c:	64c1      	cmplt      	r0, r3
     a1e:	c4030c40 	inct      	r0, r3, 0
     a22:	eb20007f 	cmplti      	r0, 128
     a26:	337f      	movi      	r3, 127
     a28:	c4030c20 	incf      	r0, r3, 0
     a2c:	dc040930 	st.b      	r0, (r4, 0x930)
     a30:	e0000000 	bsr      	0x0	// 0 <ah_wphy_agc_info_get>
     a34:	e400200f 	andi      	r0, r0, 15
     a38:	d864031e 	ld.b      	r3, (r4, 0x31e)
     a3c:	dc640932 	st.b      	r3, (r4, 0x932)
     a40:	dc040931 	st.b      	r0, (r4, 0x931)
     a44:	ea214120 	movih      	r1, 16672
     a48:	d804219f 	ld.w      	r0, (r4, 0x67c)
     a4c:	e0000000 	bsr      	0x0	// 0 <__mulsf3>
     a50:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
     a54:	ea233fe0 	movih      	r3, 16352
     a58:	3200      	movi      	r2, 0
     a5a:	e0000000 	bsr      	0x0	// 0 <__adddf3>
     a5e:	e0000000 	bsr      	0x0	// 0 <__fixdfsi>
     a62:	38df      	btsti      	r0, 31
     a64:	3300      	movi      	r3, 0
     a66:	c4030c40 	inct      	r0, r3, 0
     a6a:	eb20003f 	cmplti      	r0, 64
     a6e:	333f      	movi      	r3, 63
     a70:	c4030c20 	incf      	r0, r3, 0
     a74:	d8640917 	ld.b      	r3, (r4, 0x917)
     a78:	c4605ca0 	ins      	r3, r0, 5, 0
     a7c:	dc640917 	st.b      	r3, (r4, 0x917)
     a80:	d8640678 	ld.b      	r3, (r4, 0x678)
     a84:	dc640916 	st.b      	r3, (r4, 0x916)
     a88:	3367      	movi      	r3, 103
     a8a:	dc640933 	st.b      	r3, (r4, 0x933)
     a8e:	3300      	movi      	r3, 0
     a90:	2b6a      	subi      	r3, 107
     a92:	dc640934 	st.b      	r3, (r4, 0x934)
     a96:	d8640892 	ld.b      	r3, (r4, 0x892)
     a9a:	e4632004 	andi      	r3, r3, 4
     a9e:	e903000e 	bez      	r3, 0xaba	// aba <non_ndp_rx_hdl+0xaba>
     aa2:	d8640935 	ld.b      	r3, (r4, 0x935)
     aa6:	3201      	movi      	r2, 1
     aa8:	c4625c00 	ins      	r3, r2, 0, 0
     aac:	3104      	movi      	r1, 4
     aae:	c4615c61 	ins      	r3, r1, 4, 1
     ab2:	c4625c45 	ins      	r3, r2, 7, 5
     ab6:	dc640935 	st.b      	r3, (r4, 0x935)
     aba:	e0000000 	bsr      	0x0	// 0 <lmac_update_pv0_wpba_tx_vec>
     abe:	d86409dc 	ld.b      	r3, (r4, 0x9dc)
     ac2:	3200      	movi      	r2, 0
     ac4:	c4625c05 	ins      	r3, r2, 5, 5
     ac8:	dc6409dc 	st.b      	r3, (r4, 0x9dc)
     acc:	3303      	movi      	r3, 3
     ace:	dc642265 	st.w      	r3, (r4, 0x994)
     ad2:	d8640892 	ld.b      	r3, (r4, 0x892)
     ad6:	e4632004 	andi      	r3, r3, 4
     ada:	e9030020 	bez      	r3, 0xb1a	// b1a <non_ndp_rx_hdl+0xb1a>
     ade:	8544      	ld.b      	r2, (r5, 0x4)
     ae0:	d8640302 	ld.b      	r3, (r4, 0x302)
     ae4:	64ca      	cmpne      	r2, r3
     ae6:	087c      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     ae8:	8545      	ld.b      	r2, (r5, 0x5)
     aea:	d8640303 	ld.b      	r3, (r4, 0x303)
     aee:	64ca      	cmpne      	r2, r3
     af0:	0877      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     af2:	8546      	ld.b      	r2, (r5, 0x6)
     af4:	d8640304 	ld.b      	r3, (r4, 0x304)
     af8:	64ca      	cmpne      	r2, r3
     afa:	0872      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     afc:	8547      	ld.b      	r2, (r5, 0x7)
     afe:	d8640305 	ld.b      	r3, (r4, 0x305)
     b02:	64ca      	cmpne      	r2, r3
     b04:	086d      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     b06:	8548      	ld.b      	r2, (r5, 0x8)
     b08:	d8640306 	ld.b      	r3, (r4, 0x306)
     b0c:	64ca      	cmpne      	r2, r3
     b0e:	0868      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     b10:	8549      	ld.b      	r2, (r5, 0x9)
     b12:	d8640307 	ld.b      	r3, (r4, 0x307)
     b16:	64ca      	cmpne      	r2, r3
     b18:	0863      	bt      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     b1a:	8578      	ld.b      	r3, (r5, 0x18)
     b1c:	eb4300dd 	cmpnei      	r3, 221
     b20:	0821      	bt      	0xb62	// b62 <non_ndp_rx_hdl+0xb62>
     b22:	8579      	ld.b      	r3, (r5, 0x19)
     b24:	3b49      	cmpnei      	r3, 9
     b26:	081e      	bt      	0xb62	// b62 <non_ndp_rx_hdl+0xb62>
     b28:	857a      	ld.b      	r3, (r5, 0x1a)
     b2a:	eb430080 	cmpnei      	r3, 128
     b2e:	081a      	bt      	0xb62	// b62 <non_ndp_rx_hdl+0xb62>
     b30:	d925001b 	ld.b      	r9, (r5, 0x1b)
     b34:	e4692001 	andi      	r3, r9, 1
     b38:	e445001a 	addi      	r2, r5, 27
     b3c:	e923006a 	bnez      	r3, 0xc10	// c10 <non_ndp_rx_hdl+0xc10>
     b40:	c4295489 	zext      	r9, r9, 4, 1
     b44:	e5290000 	addi      	r9, r9, 1
     b48:	eb490002 	cmpnei      	r9, 2
     b4c:	0c64      	bf      	0xc14	// c14 <non_ndp_rx_hdl+0xc14>
     b4e:	eb490004 	cmpnei      	r9, 4
     b52:	0c61      	bf      	0xc14	// c14 <non_ndp_rx_hdl+0xc14>
     b54:	eb490008 	cmpnei      	r9, 8
     b58:	0c5e      	bf      	0xc14	// c14 <non_ndp_rx_hdl+0xc14>
     b5a:	6c67      	mov      	r1, r9
     b5c:	1108      	lrw      	r0, 0x0	// bfc <non_ndp_rx_hdl+0xbfc>
     b5e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
     b62:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
     b66:	e4632002 	andi      	r3, r3, 2
     b6a:	e9230020 	bnez      	r3, 0xbaa	// baa <non_ndp_rx_hdl+0xbaa>
     b6e:	e0000000 	bsr      	0x0	// 0 <lmac_get_avg_power>
     b72:	854f      	ld.b      	r2, (r5, 0xf)
     b74:	856a      	ld.b      	r3, (r5, 0xa)
     b76:	b844      	st.w      	r2, (r14, 0x10)
     b78:	854e      	ld.b      	r2, (r5, 0xe)
     b7a:	b843      	st.w      	r2, (r14, 0xc)
     b7c:	854d      	ld.b      	r2, (r5, 0xd)
     b7e:	b842      	st.w      	r2, (r14, 0x8)
     b80:	854c      	ld.b      	r2, (r5, 0xc)
     b82:	b841      	st.w      	r2, (r14, 0x4)
     b84:	854b      	ld.b      	r2, (r5, 0xb)
     b86:	6c43      	mov      	r1, r0
     b88:	b840      	st.w      	r2, (r14, 0x0)
     b8a:	6c9f      	mov      	r2, r7
     b8c:	101d      	lrw      	r0, 0x0	// c00 <non_ndp_rx_hdl+0xc00>
     b8e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
     b92:	d8640892 	ld.b      	r3, (r4, 0x892)
     b96:	e4632004 	andi      	r3, r3, 4
     b9a:	3b40      	cmpnei      	r3, 0
     b9c:	103a      	lrw      	r1, 0x0	// c04 <non_ndp_rx_hdl+0xc04>
     b9e:	107b      	lrw      	r3, 0x0	// c08 <non_ndp_rx_hdl+0xc08>
     ba0:	c4230c20 	incf      	r1, r3, 0
     ba4:	101a      	lrw      	r0, 0x0	// c0c <hgprintf+0xc0c>
     ba6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
     baa:	d8640892 	ld.b      	r3, (r4, 0x892)
     bae:	320a      	movi      	r2, 10
     bb0:	c4625c83 	ins      	r3, r2, 7, 3
     bb4:	dc640892 	st.b      	r3, (r4, 0x892)
     bb8:	3201      	movi      	r2, 1
     bba:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
     bbe:	c4625c01 	ins      	r3, r2, 1, 1
     bc2:	dc6409e2 	st.b      	r3, (r4, 0x9e2)
     bc6:	9460      	ld.w      	r3, (r4, 0x0)
     bc8:	3200      	movi      	r2, 0
     bca:	832a      	ld.b      	r1, (r3, 0xa)
     bcc:	c4225c00 	ins      	r1, r2, 0, 0
     bd0:	a32a      	st.b      	r1, (r3, 0xa)
     bd2:	d864036d 	ld.b      	r3, (r4, 0x36d)
     bd6:	c4625c22 	ins      	r3, r2, 3, 2
     bda:	dc64036d 	st.b      	r3, (r4, 0x36d)
     bde:	9867      	ld.w      	r3, (r14, 0x1c)
     be0:	2300      	addi      	r3, 1
     be2:	b867      	st.w      	r3, (r14, 0x1c)
     be4:	e800fa1a 	br      	0x18	// 18 <non_ndp_rx_hdl+0x18>
	...
     c10:	ea090001 	movi      	r9, 1
     c14:	33fa      	movi      	r3, 250
     c16:	82c3      	ld.b      	r6, (r2, 0x3)
     c18:	4362      	lsli      	r3, r3, 2
     c1a:	7d8c      	mult      	r6, r3
     c1c:	ea03aae6 	movi      	r3, 43750
     c20:	c4834903 	rotli      	r3, r3, 4
     c24:	60d8      	addu      	r3, r6
     c26:	82c4      	ld.b      	r6, (r2, 0x4)
     c28:	d9420002 	ld.b      	r10, (r2, 0x2)
     c2c:	c4265486 	zext      	r6, r6, 4, 1
     c30:	3264      	movi      	r2, 100
     c32:	7d88      	mult      	r6, r2
     c34:	618c      	addu      	r6, r3
     c36:	d8640309 	ld.b      	r3, (r4, 0x309)
     c3a:	668e      	cmpne      	r3, r10
     c3c:	0c0a      	bf      	0xc50	// c50 <non_ndp_rx_hdl+0xc50>
     c3e:	0019      	lrw      	r0, 0x0	// fd4 <non_ndp_rx_hdl+0xfd4>
     c40:	6c6b      	mov      	r1, r10
     c42:	e0000000 	bsr      	0x0	// 0 <hgprintf>
     c46:	6c2b      	mov      	r0, r10
     c48:	dd440309 	st.b      	r10, (r4, 0x309)
     c4c:	e0000000 	bsr      	0x0	// 0 <ah_wphy_pri_channel_cfg>
     c50:	eb490001 	cmpnei      	r9, 1
     c54:	0810      	bt      	0xc74	// c74 <non_ndp_rx_hdl+0xc74>
     c56:	d864034a 	ld.b      	r3, (r4, 0x34a)
     c5a:	e4632001 	andi      	r3, r3, 1
     c5e:	e9230011 	bnez      	r3, 0xc80	// c80 <non_ndp_rx_hdl+0xc80>
     c62:	6c67      	mov      	r1, r9
     c64:	0102      	lrw      	r0, 0x0	// fd8 <non_ndp_rx_hdl+0xfd8>
     c66:	e0000000 	bsr      	0x0	// 0 <hgprintf>
     c6a:	6c67      	mov      	r1, r9
     c6c:	9400      	ld.w      	r0, (r4, 0x0)
     c6e:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_set_bss_bw>
     c72:	0407      	br      	0xc80	// c80 <non_ndp_rx_hdl+0xc80>
     c74:	d8440308 	ld.b      	r2, (r4, 0x308)
     c78:	3301      	movi      	r3, 1
     c7a:	70c8      	lsl      	r3, r2
     c7c:	664e      	cmpne      	r3, r9
     c7e:	0bf2      	bt      	0xc62	// c62 <non_ndp_rx_hdl+0xc62>
     c80:	d86420ce 	ld.w      	r3, (r4, 0x338)
     c84:	c4835763 	zext      	r3, r3, 27, 4
     c88:	64da      	cmpne      	r6, r3
     c8a:	0f6c      	bf      	0xb62	// b62 <non_ndp_rx_hdl+0xb62>
     c8c:	6c5b      	mov      	r1, r6
     c8e:	010b      	lrw      	r0, 0x0	// fdc <non_ndp_rx_hdl+0xfdc>
     c90:	e0000000 	bsr      	0x0	// 0 <hgprintf>
     c94:	6c1b      	mov      	r0, r6
     c96:	e0000000 	bsr      	0x0	// 0 <lmac_lo_freq_set>
     c9a:	0764      	br      	0xb62	// b62 <non_ndp_rx_hdl+0xb62>
     c9c:	d844227a 	ld.w      	r2, (r4, 0x9e8)
     ca0:	d8242279 	ld.w      	r1, (r4, 0x9e4)
     ca4:	3005      	movi      	r0, 5
     ca6:	e0000000 	bsr      	0x0	// 0 <lmac_adc_dump>
     caa:	d844227a 	ld.w      	r2, (r4, 0x9e8)
     cae:	d8242279 	ld.w      	r1, (r4, 0x9e4)
     cb2:	3007      	movi      	r0, 7
     cb4:	e0000000 	bsr      	0x0	// 0 <lmac_adc_dump>
     cb8:	e4691009 	subi      	r3, r9, 10
     cbc:	74cd      	zexth      	r3, r3
     cbe:	eb030f2d 	cmphsi      	r3, 3886
     cc2:	e860fb04 	bt      	0x2ca	// 2ca <non_ndp_rx_hdl+0x2ca>
     cc6:	eb4600a8 	cmpnei      	r6, 168
     cca:	0805      	bt      	0xcd4	// cd4 <non_ndp_rx_hdl+0xcd4>
     ccc:	6c17      	mov      	r0, r5
     cce:	e0000000 	bsr      	0x0	// 0 <non_ndp_rx_hdl>
     cd2:	0786      	br      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     cd4:	8557      	ld.b      	r2, (r5, 0x17)
     cd6:	8576      	ld.b      	r3, (r5, 0x16)
     cd8:	4248      	lsli      	r2, r2, 8
     cda:	6c8c      	or      	r2, r3
     cdc:	d86800b0 	ld.b      	r3, (r8, 0xb0)
     ce0:	e4232004 	andi      	r1, r3, 4
     ce4:	4a44      	lsri      	r2, r2, 4
     ce6:	e921000e 	bnez      	r1, 0xd02	// d02 <non_ndp_rx_hdl+0xd02>
     cea:	8524      	ld.b      	r1, (r5, 0x4)
     cec:	e4012001 	andi      	r0, r1, 1
     cf0:	e900004f 	bez      	r0, 0xd8e	// d8e <non_ndp_rx_hdl+0xd8e>
     cf4:	3101      	movi      	r1, 1
     cf6:	c4615c02 	ins      	r3, r1, 2, 2
     cfa:	c4615c01 	ins      	r3, r1, 1, 1
     cfe:	dc6800b0 	st.b      	r3, (r8, 0xb0)
     d02:	d86800b0 	ld.b      	r3, (r8, 0xb0)
     d06:	e4232004 	andi      	r1, r3, 4
     d0a:	e901ff6a 	bez      	r1, 0xbde	// bde <non_ndp_rx_hdl+0xbde>
     d0e:	e4632002 	andi      	r3, r3, 2
     d12:	8524      	ld.b      	r1, (r5, 0x4)
     d14:	e9030006 	bez      	r3, 0xd20	// d20 <non_ndp_rx_hdl+0xd20>
     d18:	e4612001 	andi      	r3, r1, 1
     d1c:	e923faf7 	bnez      	r3, 0x30a	// 30a <non_ndp_rx_hdl+0x30a>
     d20:	d8640302 	ld.b      	r3, (r4, 0x302)
     d24:	64c6      	cmpne      	r1, r3
     d26:	0862      	bt      	0xdea	// dea <non_ndp_rx_hdl+0xdea>
     d28:	8525      	ld.b      	r1, (r5, 0x5)
     d2a:	d8640303 	ld.b      	r3, (r4, 0x303)
     d2e:	64c6      	cmpne      	r1, r3
     d30:	085d      	bt      	0xdea	// dea <non_ndp_rx_hdl+0xdea>
     d32:	8526      	ld.b      	r1, (r5, 0x6)
     d34:	d8640304 	ld.b      	r3, (r4, 0x304)
     d38:	64c6      	cmpne      	r1, r3
     d3a:	0858      	bt      	0xdea	// dea <non_ndp_rx_hdl+0xdea>
     d3c:	8527      	ld.b      	r1, (r5, 0x7)
     d3e:	d8640305 	ld.b      	r3, (r4, 0x305)
     d42:	64c6      	cmpne      	r1, r3
     d44:	0853      	bt      	0xdea	// dea <non_ndp_rx_hdl+0xdea>
     d46:	8528      	ld.b      	r1, (r5, 0x8)
     d48:	d8640306 	ld.b      	r3, (r4, 0x306)
     d4c:	64c6      	cmpne      	r1, r3
     d4e:	084e      	bt      	0xdea	// dea <non_ndp_rx_hdl+0xdea>
     d50:	8529      	ld.b      	r1, (r5, 0x9)
     d52:	d8640307 	ld.b      	r3, (r4, 0x307)
     d56:	64c6      	cmpne      	r1, r3
     d58:	0849      	bt      	0xdea	// dea <non_ndp_rx_hdl+0xdea>
     d5a:	d8681052 	ld.h      	r3, (r8, 0xa4)
     d5e:	64c8      	cmphs      	r2, r3
     d60:	0f3f      	bf      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     d62:	608e      	subu      	r2, r3
     d64:	eb22003f 	cmplti      	r2, 64
     d68:	0f3b      	bf      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     d6a:	3001      	movi      	r0, 1
     d6c:	3100      	movi      	r1, 0
     d6e:	e0000000 	bsr      	0x0	// 0 <__ashldi3>
     d72:	d848202a 	ld.w      	r2, (r8, 0xa8)
     d76:	d868202b 	ld.w      	r3, (r8, 0xac)
     d7a:	c440242c 	or      	r12, r0, r2
     d7e:	c461242d 	or      	r13, r1, r3
     d82:	dd88202a 	st.w      	r12, (r8, 0xa8)
     d86:	dda8202b 	st.w      	r13, (r8, 0xac)
     d8a:	e800fac0 	br      	0x30a	// 30a <non_ndp_rx_hdl+0x30a>
     d8e:	d8640302 	ld.b      	r3, (r4, 0x302)
     d92:	644e      	cmpne      	r3, r1
     d94:	0824      	bt      	0xddc	// ddc <non_ndp_rx_hdl+0xddc>
     d96:	8525      	ld.b      	r1, (r5, 0x5)
     d98:	d8640303 	ld.b      	r3, (r4, 0x303)
     d9c:	64c6      	cmpne      	r1, r3
     d9e:	081f      	bt      	0xddc	// ddc <non_ndp_rx_hdl+0xddc>
     da0:	8526      	ld.b      	r1, (r5, 0x6)
     da2:	d8640304 	ld.b      	r3, (r4, 0x304)
     da6:	64c6      	cmpne      	r1, r3
     da8:	081a      	bt      	0xddc	// ddc <non_ndp_rx_hdl+0xddc>
     daa:	8527      	ld.b      	r1, (r5, 0x7)
     dac:	d8640305 	ld.b      	r3, (r4, 0x305)
     db0:	64c6      	cmpne      	r1, r3
     db2:	0815      	bt      	0xddc	// ddc <non_ndp_rx_hdl+0xddc>
     db4:	8528      	ld.b      	r1, (r5, 0x8)
     db6:	d8640306 	ld.b      	r3, (r4, 0x306)
     dba:	64c6      	cmpne      	r1, r3
     dbc:	0810      	bt      	0xddc	// ddc <non_ndp_rx_hdl+0xddc>
     dbe:	8529      	ld.b      	r1, (r5, 0x9)
     dc0:	d8640307 	ld.b      	r3, (r4, 0x307)
     dc4:	64c6      	cmpne      	r1, r3
     dc6:	080b      	bt      	0xddc	// ddc <non_ndp_rx_hdl+0xddc>
     dc8:	d86800b0 	ld.b      	r3, (r8, 0xb0)
     dcc:	3101      	movi      	r1, 1
     dce:	c4615c02 	ins      	r3, r1, 2, 2
     dd2:	dc6800b0 	st.b      	r3, (r8, 0xb0)
     dd6:	dc481052 	st.h      	r2, (r8, 0xa4)
     dda:	0794      	br      	0xd02	// d02 <non_ndp_rx_hdl+0xd02>
     ddc:	8563      	ld.b      	r3, (r5, 0x3)
     dde:	8522      	ld.b      	r1, (r5, 0x2)
     de0:	4368      	lsli      	r3, r3, 8
     de2:	6cc4      	or      	r3, r1
     de4:	dc681049 	st.h      	r3, (r8, 0x92)
     de8:	078d      	br      	0xd02	// d02 <non_ndp_rx_hdl+0xd02>
     dea:	8563      	ld.b      	r3, (r5, 0x3)
     dec:	8542      	ld.b      	r2, (r5, 0x2)
     dee:	4368      	lsli      	r3, r3, 8
     df0:	6cc8      	or      	r3, r2
     df2:	dc681049 	st.h      	r3, (r8, 0x92)
     df6:	06f4      	br      	0xbde	// bde <non_ndp_rx_hdl+0xbde>
     df8:	3300      	movi      	r3, 0
     dfa:	dc680098 	st.b      	r3, (r8, 0x98)
     dfe:	141c      	addi      	r14, r14, 112
     e00:	1498      	pop      	r4-r11, r15
     e02:	d8481059 	ld.h      	r2, (r8, 0xb2)
     e06:	d8641181 	ld.h      	r3, (r4, 0x302)
     e0a:	64ca      	cmpne      	r2, r3
     e0c:	080a      	bt      	0xe20	// e20 <non_ndp_rx_hdl+0xe20>
     e0e:	d86420c1 	ld.w      	r3, (r4, 0x304)
     e12:	d848202d 	ld.w      	r2, (r8, 0xb4)
     e16:	64ca      	cmpne      	r2, r3
     e18:	64c3      	mvcv      	r3
     e1a:	74cc      	zextb      	r3, r3
     e1c:	e800f977 	br      	0x10a	// 10a <non_ndp_rx_hdl+0x10a>
     e20:	3300      	movi      	r3, 0
     e22:	e800f974 	br      	0x10a	// 10a <non_ndp_rx_hdl+0x10a>
     e26:	d8c3006f 	ld.b      	r6, (r3, 0x6f)
     e2a:	641a      	cmpne      	r6, r0
     e2c:	0812      	bt      	0xe50	// e50 <non_ndp_rx_hdl+0xe50>
     e2e:	d8c31038 	ld.h      	r6, (r3, 0x70)
     e32:	649a      	cmpne      	r6, r2
     e34:	080e      	bt      	0xe50	// e50 <non_ndp_rx_hdl+0xe50>
     e36:	d8c30072 	ld.b      	r6, (r3, 0x72)
     e3a:	671a      	cmpne      	r6, r12
     e3c:	080a      	bt      	0xe50	// e50 <non_ndp_rx_hdl+0xe50>
     e3e:	d8c30073 	ld.b      	r6, (r3, 0x73)
     e42:	675a      	cmpne      	r6, r13
     e44:	0806      	bt      	0xe50	// e50 <non_ndp_rx_hdl+0xe50>
     e46:	d8c30074 	ld.b      	r6, (r3, 0x74)
     e4a:	655a      	cmpne      	r6, r5
     e4c:	e840f9ae 	bf      	0x1a8	// 1a8 <non_ndp_rx_hdl+0x1a8>
     e50:	9360      	ld.w      	r3, (r3, 0x0)
     e52:	e800f99b 	br      	0x188	// 188 <non_ndp_rx_hdl+0x188>
     e56:	3300      	movi      	r3, 0
     e58:	e800f9a8 	br      	0x1a8	// 1a8 <non_ndp_rx_hdl+0x1a8>
     e5c:	d8a800be 	ld.b      	r5, (r8, 0xbe)
     e60:	e4a52040 	andi      	r5, r5, 64
     e64:	e9050006 	bez      	r5, 0xe70	// e70 <non_ndp_rx_hdl+0xe70>
     e68:	e0000000 	bsr      	0x0	// 0 <non_ndp_rx_hdl>
     e6c:	e800f9a8 	br      	0x1bc	// 1bc <non_ndp_rx_hdl+0x1bc>
     e70:	d86403e2 	ld.b      	r3, (r4, 0x3e2)
     e74:	e4632001 	andi      	r3, r3, 1
     e78:	6e57      	mov      	r9, r5
     e7a:	d8c82028 	ld.w      	r6, (r8, 0xa0)
     e7e:	d808009a 	ld.b      	r0, (r8, 0x9a)
     e82:	e9030004 	bez      	r3, 0xe8a	// e8a <non_ndp_rx_hdl+0xe8a>
     e86:	e0000000 	bsr      	0x0	// 0 <data_scrambler>
     e8a:	3302      	movi      	r3, 2
     e8c:	c4a35c40 	ins      	r5, r3, 2, 0
     e90:	d864034a 	ld.b      	r3, (r4, 0x34a)
     e94:	e4632001 	andi      	r3, r3, 1
     e98:	e440207f 	andi      	r2, r0, 127
     e9c:	e9030028 	bez      	r3, 0xeec	// eec <non_ndp_rx_hdl+0xeec>
     ea0:	4e17      	lsri      	r0, r6, 23
     ea2:	e4002180 	andi      	r0, r0, 384
     ea6:	6c08      	or      	r0, r2
     ea8:	d848409b 	ld.bs      	r2, (r8, 0x9b)
     eac:	c4a05d03 	ins      	r5, r0, 11, 3
     eb0:	3300      	movi      	r3, 0
     eb2:	c4a35c0c 	ins      	r5, r3, 12, 12
     eb6:	e9a20018 	bhsz      	r2, 0xee6	// ee6 <non_ndp_rx_hdl+0xee6>
     eba:	3201      	movi      	r2, 1
     ebc:	c4a25c0d 	ins      	r5, r2, 13, 13
     ec0:	c4a35d2e 	ins      	r5, r3, 23, 14
     ec4:	c4a35c18 	ins      	r5, r3, 24, 24
     ec8:	c4a35cd9 	ins      	r5, r3, 31, 25
     ecc:	6c17      	mov      	r0, r5
     ece:	6c67      	mov      	r1, r9
     ed0:	e0000000 	bsr      	0x0	// 0 <lmac_update_ndp_ack_tx_vec>
     ed4:	d86409dc 	ld.b      	r3, (r4, 0x9dc)
     ed8:	3201      	movi      	r2, 1
     eda:	c4625c06 	ins      	r3, r2, 6, 6
     ede:	dc6409dc 	st.b      	r3, (r4, 0x9dc)
     ee2:	3302      	movi      	r3, 2
     ee4:	0474      	br      	0xfcc	// fcc <non_ndp_rx_hdl+0xfcc>
     ee6:	c4a35c0d 	ins      	r5, r3, 13, 13
     eea:	07eb      	br      	0xec0	// ec0 <non_ndp_rx_hdl+0xec0>
     eec:	3100      	movi      	r1, 0
     eee:	4e10      	lsri      	r0, r6, 16
     ef0:	297f      	subi      	r1, 128
     ef2:	6804      	and      	r0, r1
     ef4:	6c08      	or      	r0, r2
     ef6:	d848409b 	ld.bs      	r2, (r8, 0x9b)
     efa:	c4a05de3 	ins      	r5, r0, 18, 3
     efe:	c4a35c13 	ins      	r5, r3, 19, 19
     f02:	e9a2000c 	bhsz      	r2, 0xf1a	// f1a <non_ndp_rx_hdl+0xf1a>
     f06:	3201      	movi      	r2, 1
     f08:	c4a25d74 	ins      	r5, r2, 31, 20
     f0c:	6e4f      	mov      	r9, r3
     f0e:	3300      	movi      	r3, 0
     f10:	c5235c03 	ins      	r9, r3, 3, 3
     f14:	c5235f45 	ins      	r9, r3, 31, 5
     f18:	07da      	br      	0xecc	// ecc <non_ndp_rx_hdl+0xecc>
     f1a:	c4a35d74 	ins      	r5, r3, 31, 20
     f1e:	07f7      	br      	0xf0c	// f0c <non_ndp_rx_hdl+0xf0c>
     f20:	d84800be 	ld.b      	r2, (r8, 0xbe)
     f24:	e4422040 	andi      	r2, r2, 64
     f28:	112e      	lrw      	r1, 0x0	// fe0 <non_ndp_rx_hdl+0xfe0>
     f2a:	e902006b 	bez      	r2, 0x1000	// 1000 <non_ndp_rx_hdl+0x1000>
     f2e:	e903005f 	bez      	r3, 0xfec	// fec <non_ndp_rx_hdl+0xfec>
     f32:	d86300b9 	ld.b      	r3, (r3, 0xb9)
     f36:	e4632001 	andi      	r3, r3, 1
     f3a:	e9030059 	bez      	r3, 0xfec	// fec <non_ndp_rx_hdl+0xfec>
     f3e:	d8681052 	ld.h      	r3, (r8, 0xa4)
     f42:	dc641496 	st.h      	r3, (r4, 0x92c)
     f46:	1108      	lrw      	r0, 0x0	// fe4 <non_ndp_rx_hdl+0xfe4>
     f48:	d8681054 	ld.h      	r3, (r8, 0xa8)
     f4c:	dc641497 	st.h      	r3, (r4, 0x92e)
     f50:	d8681055 	ld.h      	r3, (r8, 0xaa)
     f54:	a861      	st.h      	r3, (r0, 0x2)
     f56:	d8681056 	ld.h      	r3, (r8, 0xac)
     f5a:	a862      	st.h      	r3, (r0, 0x4)
     f5c:	d8681057 	ld.h      	r3, (r8, 0xae)
     f60:	a863      	st.h      	r3, (r0, 0x6)
     f62:	d8641495 	ld.h      	r3, (r4, 0x92a)
     f66:	3500      	movi      	r5, 0
     f68:	d8440bb4 	ld.b      	r2, (r4, 0xbb4)
     f6c:	c4655ce4 	ins      	r3, r5, 11, 4
     f70:	dc641495 	st.h      	r3, (r4, 0x92a)
     f74:	c4625c03 	ins      	r3, r2, 3, 3
     f78:	dc64092a 	st.b      	r3, (r4, 0x92a)
     f7c:	d848202e 	ld.w      	r2, (r8, 0xb8)
     f80:	e4601015 	subi      	r3, r0, 22
     f84:	dc442246 	st.w      	r2, (r4, 0x918)
     f88:	8942      	ld.h      	r2, (r1, 0x4)
     f8a:	ab42      	st.h      	r2, (r3, 0x4)
     f8c:	e420162b 	subi      	r1, r0, 1580
     f90:	3206      	movi      	r2, 6
     f92:	2809      	subi      	r0, 10
     f94:	e0000000 	bsr      	0x0	// 0 <memcpy>
     f98:	d8441338 	ld.h      	r2, (r4, 0x670)
     f9c:	d8681049 	ld.h      	r3, (r8, 0x92)
     fa0:	e42200ac 	addi      	r1, r2, 173
     fa4:	64c5      	cmplt      	r1, r3
     fa6:	0c2a      	bf      	0xffa	// ffa <non_ndp_rx_hdl+0xffa>
     fa8:	2bac      	subi      	r3, 173
     faa:	60ca      	subu      	r3, r2
     fac:	dc64148b 	st.h      	r3, (r4, 0x916)
     fb0:	102e      	lrw      	r1, 0x0	// fe8 <non_ndp_rx_hdl+0xfe8>
     fb2:	591e      	addi      	r0, r1, 8
     fb4:	e0000000 	bsr      	0x0	// 0 <non_ndp_rx_hdl>
     fb8:	e0000000 	bsr      	0x0	// 0 <lmac_update_pv0_wpba_tx_vec>
     fbc:	d86409dc 	ld.b      	r3, (r4, 0x9dc)
     fc0:	3200      	movi      	r2, 0
     fc2:	c4625c05 	ins      	r3, r2, 5, 5
     fc6:	dc6409dc 	st.b      	r3, (r4, 0x9dc)
     fca:	3303      	movi      	r3, 3
     fcc:	dc642265 	st.w      	r3, (r4, 0x994)
     fd0:	e800f8f6 	br      	0x1bc	// 1bc <non_ndp_rx_hdl+0x1bc>
	...
     fec:	d8641496 	ld.h      	r3, (r4, 0x92c)
     ff0:	d8481052 	ld.h      	r2, (r8, 0xa4)
     ff4:	c4625d60 	ins      	r3, r2, 11, 0
     ff8:	07a5      	br      	0xf42	// f42 <non_ndp_rx_hdl+0xf42>
     ffa:	dca4148b 	st.h      	r5, (r4, 0x916)
     ffe:	07d9      	br      	0xfb0	// fb0 <non_ndp_rx_hdl+0xfb0>
    1000:	d868202e 	ld.w      	r3, (r8, 0xb8)
    1004:	dc642242 	st.w      	r3, (r4, 0x908)
    1008:	106e      	lrw      	r3, 0x0	// 1040 <non_ndp_rx_hdl+0x1040>
    100a:	8922      	ld.h      	r1, (r1, 0x4)
    100c:	ab22      	st.h      	r1, (r3, 0x4)
    100e:	d8241337 	ld.h      	r1, (r4, 0x66e)
    1012:	d8681049 	ld.h      	r3, (r8, 0x92)
    1016:	e40100ac 	addi      	r0, r1, 173
    101a:	64c1      	cmplt      	r0, r3
    101c:	0c0f      	bf      	0x103a	// 103a <non_ndp_rx_hdl+0x103a>
    101e:	2bac      	subi      	r3, 173
    1020:	60c6      	subu      	r3, r1
    1022:	dc641483 	st.h      	r3, (r4, 0x906)
    1026:	1027      	lrw      	r1, 0x0	// 1040 <non_ndp_rx_hdl+0x1040>
    1028:	591e      	addi      	r0, r1, 8
    102a:	e0000000 	bsr      	0x0	// 0 <non_ndp_rx_hdl>
    102e:	e0000000 	bsr      	0x0	// 0 <lmac_update_pv0_wpack_tx_vec>
    1032:	d86409dc 	ld.b      	r3, (r4, 0x9dc)
    1036:	3200      	movi      	r2, 0
    1038:	0751      	br      	0xeda	// eda <non_ndp_rx_hdl+0xeda>
    103a:	dc441483 	st.h      	r2, (r4, 0x906)
    103e:	07f4      	br      	0x1026	// 1026 <ah_lmac+0x1026>
    1040:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_start_tx_after_sifs:

00000000 <lmac_start_tx_after_sifs>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	3100      	movi      	r1, 0
   6:	3002      	movi      	r0, 2
   8:	e0000000 	bsr      	0x0	// 0 <lhw_start_cca>
   c:	1067      	lrw      	r3, 0x0	// 28 <lmac_start_tx_after_sifs+0x28>
   e:	6c13      	mov      	r0, r4
  10:	9360      	ld.w      	r3, (r3, 0x0)
  12:	934c      	ld.w      	r2, (r3, 0x30)
  14:	3a89      	bclri      	r2, 9
  16:	b34c      	st.w      	r2, (r3, 0x30)
  18:	934c      	ld.w      	r2, (r3, 0x30)
  1a:	ec420400 	ori      	r2, r2, 1024
  1e:	b34c      	st.w      	r2, (r3, 0x30)
  20:	e0000000 	bsr      	0x0	// 0 <lhw_start_tx>
  24:	1491      	pop      	r4, r15
  26:	0000      	.short	0x0000
  28:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_rx_dur_info:

00000000 <lmac_rx_dur_info>:
   0:	14d2      	push      	r4-r5, r15
   2:	1098      	lrw      	r4, 0x0	// 60 <lmac_rx_dur_info+0x60>
   4:	e0000000 	bsr      	0x0	// 0 <lmac_rx_dur_info>
   8:	d8641049 	ld.h      	r3, (r4, 0x92)
   c:	64c0      	cmphs      	r0, r3
   e:	0822      	bt      	0x52	// 52 <lmac_rx_dur_info+0x52>
  10:	60c2      	subu      	r3, r0
  12:	10b5      	lrw      	r5, 0x0	// 64 <lmac_rx_dur_info+0x64>
  14:	dc641049 	st.h      	r3, (r4, 0x92)
  18:	d865037d 	ld.b      	r3, (r5, 0x37d)
  1c:	e4632010 	andi      	r3, r3, 16
  20:	e903001b 	bez      	r3, 0x56	// 56 <lmac_rx_dur_info+0x56>
  24:	d86440c0 	ld.bs      	r3, (r4, 0xc0)
  28:	e9a30017 	bhsz      	r3, 0x56	// 56 <lmac_rx_dur_info+0x56>
  2c:	e0000000 	bsr      	0x0	// 0 <lmac_get_avg_power>
  30:	d865431e 	ld.bs      	r3, (r5, 0x31e)
  34:	d84520df 	ld.w      	r2, (r5, 0x37c)
  38:	600e      	subu      	r0, r3
  3a:	c5a25642 	zext      	r2, r2, 18, 13
  3e:	d8654a4e 	ld.bs      	r3, (r5, 0xa4e)
  42:	60c8      	addu      	r3, r2
  44:	640d      	cmplt      	r3, r0
  46:	0c05      	bf      	0x50	// 50 <lmac_rx_dur_info+0x50>
  48:	d8041049 	ld.h      	r0, (r4, 0x92)
  4c:	e0000000 	bsr      	0x0	// 0 <lmac_set_obss_nav>
  50:	1492      	pop      	r4-r5, r15
  52:	3300      	movi      	r3, 0
  54:	07df      	br      	0x12	// 12 <lmac_rx_dur_info+0x12>
  56:	d8041049 	ld.h      	r0, (r4, 0x92)
  5a:	e0000000 	bsr      	0x0	// 0 <lmac_set_basic_nav>
  5e:	07f9      	br      	0x50	// 50 <lmac_rx_dur_info+0x50>
	...

Disassembly of section .text.lmac_rx_radio_info:

00000000 <lmac_rx_radio_info>:
   0:	14d2      	push      	r4-r5, r15
   2:	1363      	lrw      	r3, 0x0	// 18c <lmac_rx_radio_info+0x18c>
   4:	1383      	lrw      	r4, 0x0	// 190 <lmac_rx_radio_info+0x190>
   6:	d8430098 	ld.b      	r2, (r3, 0x98)
   a:	e902009c 	bez      	r2, 0x142	// 142 <lmac_rx_radio_info+0x142>
   e:	1342      	lrw      	r2, 0x0	// 194 <lmac_rx_radio_info+0x194>
  10:	92a0      	ld.w      	r5, (r2, 0x0)
  12:	2d7f      	subi      	r5, 128
  14:	9540      	ld.w      	r2, (r5, 0x0)
  16:	e42220ff 	andi      	r1, r2, 255
  1a:	e9010012 	bez      	r1, 0x3e	// 3e <lmac_rx_radio_info+0x3e>
  1e:	d864226d 	ld.w      	r3, (r4, 0x9b4)
  22:	ec638000 	ori      	r3, r3, 32768
  26:	d844227a 	ld.w      	r2, (r4, 0x9e8)
  2a:	d8242279 	ld.w      	r1, (r4, 0x9e4)
  2e:	3004      	movi      	r0, 4
  30:	dc64226d 	st.w      	r3, (r4, 0x9b4)
  34:	e0000000 	bsr      	0x0	// 0 <lmac_adc_dump>
  38:	3000      	movi      	r0, 0
  3a:	2800      	subi      	r0, 1
  3c:	0478      	br      	0x12c	// 12c <lmac_rx_radio_info+0x12c>
  3e:	d80300bf 	ld.b      	r0, (r3, 0xbf)
  42:	e4002003 	andi      	r0, r0, 3
  46:	3840      	cmpnei      	r0, 0
  48:	3004      	movi      	r0, 4
  4a:	c4200c20 	incf      	r1, r0, 0
  4e:	ec420001 	ori      	r2, r2, 1
  52:	6c84      	or      	r2, r1
  54:	b540      	st.w      	r2, (r5, 0x0)
  56:	d82300c0 	ld.b      	r1, (r3, 0xc0)
  5a:	d845003e 	ld.b      	r2, (r5, 0x3e)
  5e:	c4415c60 	ins      	r2, r1, 3, 0
  62:	dc45003e 	st.b      	r2, (r5, 0x3e)
  66:	d84300c0 	ld.b      	r2, (r3, 0xc0)
  6a:	d825003e 	ld.b      	r1, (r5, 0x3e)
  6e:	c48254a2 	zext      	r2, r2, 5, 4
  72:	c4225c64 	ins      	r1, r2, 7, 4
  76:	dc25003e 	st.b      	r1, (r5, 0x3e)
  7a:	d84420cf 	ld.w      	r2, (r4, 0x33c)
  7e:	c50257e2 	zext      	r2, r2, 31, 8
  82:	b552      	st.w      	r2, (r5, 0x48)
  84:	d8432031 	ld.w      	r2, (r3, 0xc4)
  88:	d8632032 	ld.w      	r3, (r3, 0xc8)
  8c:	b551      	st.w      	r2, (r5, 0x44)
  8e:	b570      	st.w      	r3, (r5, 0x40)
  90:	e0000000 	bsr      	0x0	// 0 <lmac_get_avg_power>
  94:	dc050050 	st.b      	r0, (r5, 0x50)
  98:	e0000000 	bsr      	0x0	// 0 <ah_wphy_avg_evm_get>
  9c:	dc050051 	st.b      	r0, (r5, 0x51)
  a0:	e0000000 	bsr      	0x0	// 0 <ah_wphy_rx_freq_offset_get>
  a4:	b513      	st.w      	r0, (r5, 0x4c)
  a6:	e0000000 	bsr      	0x0	// 0 <ah_wphy_agc_info_get>
  aa:	ad1e      	st.h      	r0, (r5, 0x3c)
  ac:	e0000000 	bsr      	0x0	// 0 <ah_wphy_approved_bw_get>
  b0:	d865003f 	ld.b      	r3, (r5, 0x3f)
  b4:	c4605c20 	ins      	r3, r0, 1, 0
  b8:	dc65003f 	st.b      	r3, (r5, 0x3f)
  bc:	e4632003 	andi      	r3, r3, 3
  c0:	d844227a 	ld.w      	r2, (r4, 0x9e8)
  c4:	d8242279 	ld.w      	r1, (r4, 0x9e4)
  c8:	e9230033 	bnez      	r3, 0x12e	// 12e <lmac_rx_radio_info+0x12e>
  cc:	300d      	movi      	r0, 13
  ce:	e0000000 	bsr      	0x0	// 0 <lmac_adc_dump>
  d2:	8d7e      	ld.h      	r3, (r5, 0x3c)
  d4:	dc6421e1 	st.w      	r3, (r4, 0x784)
  d8:	dc6421c1 	st.w      	r3, (r4, 0x704)
  dc:	3200      	movi      	r2, 0
  de:	d8654050 	ld.bs      	r3, (r5, 0x50)
  e2:	2a7f      	subi      	r2, 128
  e4:	648e      	cmpne      	r3, r2
  e6:	dc6421df 	st.w      	r3, (r4, 0x77c)
  ea:	0c03      	bf      	0xf0	// f0 <lmac_rx_radio_info+0xf0>
  ec:	dc6421be 	st.w      	r3, (r4, 0x6f8)
  f0:	d8454051 	ld.bs      	r2, (r5, 0x51)
  f4:	dc4421e0 	st.w      	r2, (r4, 0x780)
  f8:	dc4421bf 	st.w      	r2, (r4, 0x6fc)
  fc:	9553      	ld.w      	r2, (r5, 0x4c)
  fe:	9531      	ld.w      	r1, (r5, 0x44)
 100:	dc4421da 	st.w      	r2, (r4, 0x768)
 104:	dc4421c0 	st.w      	r2, (r4, 0x700)
 108:	d84421de 	ld.w      	r2, (r4, 0x778)
 10c:	6084      	addu      	r2, r1
 10e:	dc4421de 	st.w      	r2, (r4, 0x778)
 112:	e9230003 	bnez      	r3, 0x118	// 118 <lmac_rx_radio_info+0x118>
 116:	b560      	st.w      	r3, (r5, 0x0)
 118:	d865003e 	ld.b      	r3, (r5, 0x3e)
 11c:	e443200f 	andi      	r2, r3, 15
 120:	3a27      	cmplti      	r2, 8
 122:	0833      	bt      	0x188	// 188 <lmac_rx_radio_info+0x188>
 124:	3a4a      	cmpnei      	r2, 10
 126:	3000      	movi      	r0, 0
 128:	0c02      	bf      	0x12c	// 12c <lmac_rx_radio_info+0x12c>
 12a:	b500      	st.w      	r0, (r5, 0x0)
 12c:	1492      	pop      	r4-r5, r15
 12e:	3b41      	cmpnei      	r3, 1
 130:	0803      	bt      	0x136	// 136 <lmac_rx_radio_info+0x136>
 132:	300e      	movi      	r0, 14
 134:	07cd      	br      	0xce	// ce <lmac_rx_radio_info+0xce>
 136:	3b42      	cmpnei      	r3, 2
 138:	0803      	bt      	0x13e	// 13e <lmac_rx_radio_info+0x13e>
 13a:	300f      	movi      	r0, 15
 13c:	07c9      	br      	0xce	// ce <lmac_rx_radio_info+0xce>
 13e:	3010      	movi      	r0, 16
 140:	07c7      	br      	0xce	// ce <lmac_rx_radio_info+0xce>
 142:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
 146:	e4632002 	andi      	r3, r3, 2
 14a:	e903ff77 	bez      	r3, 0x38	// 38 <lmac_rx_radio_info+0x38>
 14e:	e0000000 	bsr      	0x0	// 0 <ah_wphy_agc_info_get>
 152:	dc0421e1 	st.w      	r0, (r4, 0x784)
 156:	dc0421c1 	st.w      	r0, (r4, 0x704)
 15a:	e0000000 	bsr      	0x0	// 0 <lmac_get_avg_power>
 15e:	3300      	movi      	r3, 0
 160:	2b7f      	subi      	r3, 128
 162:	64c2      	cmpne      	r0, r3
 164:	dc0421df 	st.w      	r0, (r4, 0x77c)
 168:	0c03      	bf      	0x16e	// 16e <lmac_rx_radio_info+0x16e>
 16a:	dc0421be 	st.w      	r0, (r4, 0x6f8)
 16e:	e0000000 	bsr      	0x0	// 0 <ah_wphy_avg_evm_get>
 172:	dc0421e0 	st.w      	r0, (r4, 0x780)
 176:	dc0421bf 	st.w      	r0, (r4, 0x6fc)
 17a:	e0000000 	bsr      	0x0	// 0 <ah_wphy_rx_freq_offset_get>
 17e:	dc0421da 	st.w      	r0, (r4, 0x768)
 182:	dc0421c0 	st.w      	r0, (r4, 0x700)
 186:	0759      	br      	0x38	// 38 <lmac_rx_radio_info+0x38>
 188:	3000      	movi      	r0, 0
 18a:	07d1      	br      	0x12c	// 12c <lmac_rx_radio_info+0x12c>
	...

Disassembly of section .text.lmac_rx_cleanup_info:

00000000 <lmac_rx_cleanup_info>:
   0:	1161      	lrw      	r3, 0x0	// 84 <lmac_rx_cleanup_info+0x84>
   2:	3200      	movi      	r2, 0
   4:	8320      	ld.b      	r1, (r3, 0x0)
   6:	c4225c02 	ins      	r1, r2, 2, 2
   a:	a320      	st.b      	r1, (r3, 0x0)
   c:	d82300b0 	ld.b      	r1, (r3, 0xb0)
  10:	e42120fa 	andi      	r1, r1, 250
  14:	3000      	movi      	r0, 0
  16:	c4225c01 	ins      	r1, r2, 1, 1
  1a:	dc2300b0 	st.b      	r1, (r3, 0xb0)
  1e:	dc03009c 	st.b      	r0, (r3, 0x9c)
  22:	dc030099 	st.b      	r0, (r3, 0x99)
  26:	3100      	movi      	r1, 0
  28:	3000      	movi      	r0, 0
  2a:	dc03202a 	st.w      	r0, (r3, 0xa8)
  2e:	dc23202b 	st.w      	r1, (r3, 0xac)
  32:	d823009b 	ld.b      	r1, (r3, 0x9b)
  36:	c4225c07 	ins      	r1, r2, 7, 7
  3a:	dc23009b 	st.b      	r1, (r3, 0x9b)
  3e:	d82300c0 	ld.b      	r1, (r3, 0xc0)
  42:	c4225c07 	ins      	r1, r2, 7, 7
  46:	dc2300c0 	st.b      	r1, (r3, 0xc0)
  4a:	3180      	movi      	r1, 128
  4c:	d8031058 	ld.h      	r0, (r3, 0xb0)
  50:	4121      	lsli      	r1, r1, 1
  52:	c4015d03 	ins      	r0, r1, 11, 3
  56:	dc431049 	st.h      	r2, (r3, 0x92)
  5a:	dc432032 	st.w      	r2, (r3, 0xc8)
  5e:	dc430098 	st.b      	r2, (r3, 0x98)
  62:	dc031058 	st.h      	r0, (r3, 0xb0)
  66:	1069      	lrw      	r3, 0x0	// 88 <lmac_rx_cleanup_info+0x88>
  68:	d8230a4f 	ld.b      	r1, (r3, 0xa4f)
  6c:	c4225c02 	ins      	r1, r2, 2, 2
  70:	dc230a4f 	st.b      	r1, (r3, 0xa4f)
  74:	d8230bb4 	ld.b      	r1, (r3, 0xbb4)
  78:	c4225c00 	ins      	r1, r2, 0, 0
  7c:	dc230bb4 	st.b      	r1, (r3, 0xbb4)
  80:	783c      	jmp      	r15
	...

Disassembly of section .text.lmac_irq_rx_subframe:

00000000 <lmac_irq_rx_subframe>:
   0:	14d1      	push      	r4, r15
   2:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_subframe>
   6:	e9200021 	bnez      	r0, 0x48	// 48 <lmac_irq_rx_subframe+0x48>
   a:	1092      	lrw      	r4, 0x0	// 50 <lmac_irq_rx_subframe+0x50>
   c:	d84400be 	ld.b      	r2, (r4, 0xbe)
  10:	e4622004 	andi      	r3, r2, 4
  14:	e903001b 	bez      	r3, 0x4a	// 4a <lmac_irq_rx_subframe+0x4a>
  18:	c46254a1 	zext      	r1, r2, 5, 3
  1c:	106e      	lrw      	r3, 0x0	// 54 <lmac_irq_rx_subframe+0x54>
  1e:	4a47      	lsri      	r2, r2, 7
  20:	d0230883 	ldr.w      	r3, (r3, r1 << 2)
  24:	941f      	ld.w      	r0, (r4, 0x7c)
  26:	d8242020 	ld.w      	r1, (r4, 0x80)
  2a:	7bcd      	jsr      	r3
  2c:	8460      	ld.b      	r3, (r4, 0x0)
  2e:	e4632004 	andi      	r3, r3, 4
  32:	e923000b 	bnez      	r3, 0x48	// 48 <lmac_irq_rx_subframe+0x48>
  36:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_subframe>
  3a:	e9200007 	bnez      	r0, 0x48	// 48 <lmac_irq_rx_subframe+0x48>
  3e:	8460      	ld.b      	r3, (r4, 0x0)
  40:	3201      	movi      	r2, 1
  42:	c4625c02 	ins      	r3, r2, 2, 2
  46:	a460      	st.b      	r3, (r4, 0x0)
  48:	1491      	pop      	r4, r15
  4a:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_subframe>
  4e:	07ef      	br      	0x2c	// 2c <lmac_irq_rx_subframe+0x2c>
	...

Disassembly of section .text.lmac_irq_rx_end:

00000000 <lmac_irq_rx_end>:
   0:	14d2      	push      	r4-r5, r15
   2:	1194      	lrw      	r4, 0x0	// d0 <lmac_irq_rx_end+0xd0>
   4:	9460      	ld.w      	r3, (r4, 0x0)
   6:	934c      	ld.w      	r2, (r3, 0x30)
   8:	ec420002 	ori      	r2, r2, 2
   c:	b34c      	st.w      	r2, (r3, 0x30)
   e:	3280      	movi      	r2, 128
  10:	4243      	lsli      	r2, r2, 3
  12:	b352      	st.w      	r2, (r3, 0x48)
  14:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
  18:	9460      	ld.w      	r3, (r4, 0x0)
  1a:	118f      	lrw      	r4, 0x0	// d4 <lmac_irq_rx_end+0xd4>
  1c:	9351      	ld.w      	r2, (r3, 0x44)
  1e:	3a88      	bclri      	r2, 8
  20:	b351      	st.w      	r2, (r3, 0x44)
  22:	3280      	movi      	r2, 128
  24:	4241      	lsli      	r2, r2, 1
  26:	b352      	st.w      	r2, (r3, 0x48)
  28:	d84409dc 	ld.b      	r2, (r4, 0x9dc)
  2c:	3300      	movi      	r3, 0
  2e:	c4435c07 	ins      	r2, r3, 7, 7
  32:	dc4409dc 	st.b      	r2, (r4, 0x9dc)
  36:	dc642265 	st.w      	r3, (r4, 0x994)
  3a:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_end>
  3e:	6d43      	mov      	r5, r0
  40:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_end>
  44:	e9200037 	bnez      	r0, 0xb2	// b2 <lmac_irq_rx_end+0xb2>
  48:	d86421e8 	ld.w      	r3, (r4, 0x7a0)
  4c:	654c      	cmphs      	r3, r5
  4e:	0803      	bt      	0x54	// 54 <lmac_irq_rx_end+0x54>
  50:	dca421e8 	st.w      	r5, (r4, 0x7a0)
  54:	11a1      	lrw      	r5, 0x0	// d8 <lmac_irq_rx_end+0xd8>
  56:	d84500be 	ld.b      	r2, (r5, 0xbe)
  5a:	e4622004 	andi      	r3, r2, 4
  5e:	e9030043 	bez      	r3, 0xe4	// e4 <lmac_irq_rx_end+0xe4>
  62:	c46254a1 	zext      	r1, r2, 5, 3
  66:	107e      	lrw      	r3, 0x0	// dc <lmac_irq_rx_end+0xdc>
  68:	4a47      	lsri      	r2, r2, 7
  6a:	d0230883 	ldr.w      	r3, (r3, r1 << 2)
  6e:	951f      	ld.w      	r0, (r5, 0x7c)
  70:	d8252020 	ld.w      	r1, (r5, 0x80)
  74:	7bcd      	jsr      	r3
  76:	8560      	ld.b      	r3, (r5, 0x0)
  78:	e4632004 	andi      	r3, r3, 4
  7c:	e923000b 	bnez      	r3, 0x92	// 92 <lmac_irq_rx_end+0x92>
  80:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_end>
  84:	e9200007 	bnez      	r0, 0x92	// 92 <lmac_irq_rx_end+0x92>
  88:	8560      	ld.b      	r3, (r5, 0x0)
  8a:	3201      	movi      	r2, 1
  8c:	c4625c02 	ins      	r3, r2, 2, 2
  90:	a560      	st.b      	r3, (r5, 0x0)
  92:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_end>
  96:	d865009b 	ld.b      	r3, (r5, 0x9b)
  9a:	e443207f 	andi      	r2, r3, 127
  9e:	d86421db 	ld.w      	r3, (r4, 0x76c)
  a2:	60c8      	addu      	r3, r2
  a4:	dc6421db 	st.w      	r3, (r4, 0x76c)
  a8:	d86421cf 	ld.w      	r3, (r4, 0x73c)
  ac:	2300      	addi      	r3, 1
  ae:	dc6421cf 	st.w      	r3, (r4, 0x73c)
  b2:	3300      	movi      	r3, 0
  b4:	dc642266 	st.w      	r3, (r4, 0x998)
  b8:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_end>
  bc:	d8642265 	ld.w      	r3, (r4, 0x994)
  c0:	3b07      	cmphsi      	r3, 8
  c2:	6d43      	mov      	r5, r0
  c4:	0888      	bt      	0x1d4	// 1d4 <lmac_irq_rx_end+0x1d4>
  c6:	1047      	lrw      	r2, 0x0	// e0 <lmac_irq_rx_end+0xe0>
  c8:	d0620883 	ldr.w      	r3, (r2, r3 << 2)
  cc:	780c      	jmp      	r3
	...
  e2:	0000      	.short	0x0000
  e4:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_end>
  e8:	07c7      	br      	0x76	// 76 <lmac_irq_rx_end+0x76>
  ea:	eb0000ad 	cmphsi      	r0, 174
  ee:	083d      	bt      	0x168	// 168 <lmac_irq_rx_end+0x168>
  f0:	3000      	movi      	r0, 0
  f2:	2852      	subi      	r0, 83
  f4:	6016      	subu      	r0, r5
  f6:	7400      	zextb      	r0, r0
  f8:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_end>
  fc:	d86421e9 	ld.w      	r3, (r4, 0x7a4)
 100:	654c      	cmphs      	r3, r5
 102:	0803      	bt      	0x108	// 108 <lmac_irq_rx_end+0x108>
 104:	dca421e9 	st.w      	r5, (r4, 0x7a4)
 108:	d8a42265 	ld.w      	r5, (r4, 0x994)
 10c:	e925002b 	bnez      	r5, 0x162	// 162 <lmac_irq_rx_end+0x162>
 110:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_end>
 114:	d8640319 	ld.b      	r3, (r4, 0x319)
 118:	e4632002 	andi      	r3, r3, 2
 11c:	e903008b 	bez      	r3, 0x232	// 232 <lmac_irq_rx_end+0x232>
 120:	d864202f 	ld.w      	r3, (r4, 0xbc)
 124:	3b42      	cmpnei      	r3, 2
 126:	0861      	bt      	0x1e8	// 1e8 <lmac_irq_rx_end+0x1e8>
 128:	e0000000 	bsr      	0x0	// 0 <ap_sleep_enter>
 12c:	d86411b1 	ld.h      	r3, (r4, 0x362)
 130:	e4632ff0 	andi      	r3, r3, 4080
 134:	eb430050 	cmpnei      	r3, 80
 138:	0815      	bt      	0x162	// 162 <lmac_irq_rx_end+0x162>
 13a:	d8640bb4 	ld.b      	r3, (r4, 0xbb4)
 13e:	e4632001 	andi      	r3, r3, 1
 142:	e9230010 	bnez      	r3, 0x162	// 162 <lmac_irq_rx_end+0x162>
 146:	d86421e1 	ld.w      	r3, (r4, 0x784)
 14a:	e463200f 	andi      	r3, r3, 15
 14e:	3b47      	cmpnei      	r3, 7
 150:	0809      	bt      	0x162	// 162 <lmac_irq_rx_end+0x162>
 152:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_dcoci_get>
 156:	dc041389 	st.h      	r0, (r4, 0x712)
 15a:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_dcocq_get>
 15e:	dc04138a 	st.h      	r0, (r4, 0x714)
 162:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_end>
 166:	1492      	pop      	r4-r5, r15
 168:	d86421ee 	ld.w      	r3, (r4, 0x7b8)
 16c:	2300      	addi      	r3, 1
 16e:	dc6421ee 	st.w      	r3, (r4, 0x7b8)
 172:	3300      	movi      	r3, 0
 174:	dc642265 	st.w      	r3, (r4, 0x994)
 178:	07c2      	br      	0xfc	// fc <lmac_irq_rx_end+0xfc>
 17a:	eb0000ad 	cmphsi      	r0, 174
 17e:	080e      	bt      	0x19a	// 19a <lmac_irq_rx_end+0x19a>
 180:	3000      	movi      	r0, 0
 182:	2852      	subi      	r0, 83
 184:	6016      	subu      	r0, r5
 186:	7400      	zextb      	r0, r0
 188:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_end>
 18c:	d86421ea 	ld.w      	r3, (r4, 0x7a8)
 190:	654c      	cmphs      	r3, r5
 192:	0bbb      	bt      	0x108	// 108 <lmac_irq_rx_end+0x108>
 194:	dca421ea 	st.w      	r5, (r4, 0x7a8)
 198:	07b8      	br      	0x108	// 108 <lmac_irq_rx_end+0x108>
 19a:	1171      	lrw      	r3, 0x0	// 25c <lmac_irq_rx_end+0x25c>
 19c:	d8430098 	ld.b      	r2, (r3, 0x98)
 1a0:	d86421f0 	ld.w      	r3, (r4, 0x7c0)
 1a4:	60c8      	addu      	r3, r2
 1a6:	dc6421f0 	st.w      	r3, (r4, 0x7c0)
 1aa:	d86421ef 	ld.w      	r3, (r4, 0x7bc)
 1ae:	2300      	addi      	r3, 1
 1b0:	dc6421ef 	st.w      	r3, (r4, 0x7bc)
 1b4:	3300      	movi      	r3, 0
 1b6:	dc642265 	st.w      	r3, (r4, 0x994)
 1ba:	07e9      	br      	0x18c	// 18c <lmac_irq_rx_end+0x18c>
 1bc:	eb0000ad 	cmphsi      	r0, 174
 1c0:	0808      	bt      	0x1d0	// 1d0 <lmac_irq_rx_end+0x1d0>
 1c2:	3000      	movi      	r0, 0
 1c4:	2852      	subi      	r0, 83
 1c6:	6016      	subu      	r0, r5
 1c8:	7400      	zextb      	r0, r0
 1ca:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_end>
 1ce:	079d      	br      	0x108	// 108 <lmac_irq_rx_end+0x108>
 1d0:	3034      	movi      	r0, 52
 1d2:	07fc      	br      	0x1ca	// 1ca <lmac_irq_rx_end+0x1ca>
 1d4:	d864226d 	ld.w      	r3, (r4, 0x9b4)
 1d8:	ec631000 	ori      	r3, r3, 4096
 1dc:	dc64226d 	st.w      	r3, (r4, 0x9b4)
 1e0:	3300      	movi      	r3, 0
 1e2:	dc642265 	st.w      	r3, (r4, 0x994)
 1e6:	0791      	br      	0x108	// 108 <lmac_irq_rx_end+0x108>
 1e8:	d8042233 	ld.w      	r0, (r4, 0x8cc)
 1ec:	e0000000 	bsr      	0x0	// 0 <dsleep_cfg_init>
 1f0:	e920000f 	bnez      	r0, 0x20e	// 20e <lmac_irq_rx_end+0x20e>
 1f4:	3303      	movi      	r3, 3
 1f6:	d80420fa 	ld.w      	r0, (r4, 0x3e8)
 1fa:	d82420fb 	ld.w      	r1, (r4, 0x3ec)
 1fe:	dc642267 	st.w      	r3, (r4, 0x99c)
 202:	e0000000 	bsr      	0x0	// 0 <dsleep_dur_calc>
 206:	3105      	movi      	r1, 5
 208:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 20c:	0790      	br      	0x12c	// 12c <lmac_irq_rx_end+0x12c>
 20e:	9460      	ld.w      	r3, (r4, 0x0)
 210:	3101      	movi      	r1, 1
 212:	834a      	ld.b      	r2, (r3, 0xa)
 214:	c4415c00 	ins      	r2, r1, 0, 0
 218:	a34a      	st.b      	r2, (r3, 0xa)
 21a:	d8640319 	ld.b      	r3, (r4, 0x319)
 21e:	c4655c01 	ins      	r3, r5, 1, 1
 222:	1010      	lrw      	r0, 0x0	// 260 <lmac_irq_rx_end+0x260>
 224:	dc640319 	st.b      	r3, (r4, 0x319)
 228:	dca42267 	st.w      	r5, (r4, 0x99c)
 22c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 230:	077e      	br      	0x12c	// 12c <lmac_irq_rx_end+0x12c>
 232:	d86409e0 	ld.b      	r3, (r4, 0x9e0)
 236:	e4632001 	andi      	r3, r3, 1
 23a:	e9230004 	bnez      	r3, 0x242	// 242 <lmac_irq_rx_end+0x242>
 23e:	e0000000 	bsr      	0x0	// 0 <lhw_enable_irq_ac>
 242:	d80411b1 	ld.h      	r0, (r4, 0x362)
 246:	c4805560 	zext      	r0, r0, 11, 4
 24a:	e0000000 	bsr      	0x0	// 0 <lmac_rx_gain_cfg>
 24e:	3000      	movi      	r0, 0
 250:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
 254:	e0000000 	bsr      	0x0	// 0 <lmac_tdma_start>
 258:	076a      	br      	0x12c	// 12c <lmac_irq_rx_end+0x12c>
	...

Disassembly of section .text.lmac_rx_frm_hdl:

00000000 <lmac_rx_frm_hdl>:
   0:	14d8      	push      	r4-r11, r15
   2:	142f      	subi      	r14, r14, 60
   4:	d8600038 	ld.b      	r3, (r0, 0x38)
   8:	e4c32003 	andi      	r6, r3, 3
   c:	6d43      	mov      	r5, r0
   e:	e9260219 	bnez      	r6, 0x440	// 440 <lmac_rx_frm_hdl+0x440>
  12:	c4435482 	zext      	r2, r3, 4, 2
  16:	e9020034 	bez      	r2, 0x7e	// 7e <lmac_rx_frm_hdl+0x7e>
  1a:	3a42      	cmpnei      	r2, 2
  1c:	0dc9      	bf      	0x3ae	// 3ae <lmac_rx_frm_hdl+0x3ae>
  1e:	018e      	lrw      	r4, 0x0	// 360 <lmac_rx_frm_hdl+0x360>
  20:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
  24:	e4632008 	andi      	r3, r3, 8
  28:	e9030012 	bez      	r3, 0x4c	// 4c <lmac_rx_frm_hdl+0x4c>
  2c:	d8640a4f 	ld.b      	r3, (r4, 0xa4f)
  30:	e4632008 	andi      	r3, r3, 8
  34:	e903000c 	bez      	r3, 0x4c	// 4c <lmac_rx_frm_hdl+0x4c>
  38:	0174      	lrw      	r3, 0x0	// 364 <lmac_rx_frm_hdl+0x364>
  3a:	0113      	lrw      	r0, 0x0	// 368 <lmac_rx_frm_hdl+0x368>
  3c:	d82310a5 	ld.h      	r1, (r3, 0x14a)
  40:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  44:	9527      	ld.w      	r1, (r5, 0x1c)
  46:	9506      	ld.w      	r0, (r5, 0x18)
  48:	e0000000 	bsr      	0x0	// 0 <hgics_print_hex>
  4c:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
  50:	e4632008 	andi      	r3, r3, 8
  54:	e9030012 	bez      	r3, 0x78	// 78 <lmac_rx_frm_hdl+0x78>
  58:	d8640a4f 	ld.b      	r3, (r4, 0xa4f)
  5c:	e4632008 	andi      	r3, r3, 8
  60:	e903000c 	bez      	r3, 0x78	// 78 <lmac_rx_frm_hdl+0x78>
  64:	017f      	lrw      	r3, 0x0	// 364 <lmac_rx_frm_hdl+0x364>
  66:	011e      	lrw      	r0, 0x0	// 368 <lmac_rx_frm_hdl+0x368>
  68:	d82310a5 	ld.h      	r1, (r3, 0x14a)
  6c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  70:	9527      	ld.w      	r1, (r5, 0x1c)
  72:	9506      	ld.w      	r0, (r5, 0x18)
  74:	e0000000 	bsr      	0x0	// 0 <hgics_print_hex>
  78:	6c1b      	mov      	r0, r6
  7a:	140f      	addi      	r14, r14, 60
  7c:	1498      	pop      	r4-r11, r15
  7e:	9086      	ld.w      	r4, (r0, 0x18)
  80:	8461      	ld.b      	r3, (r4, 0x1)
  82:	8420      	ld.b      	r1, (r4, 0x0)
  84:	4368      	lsli      	r3, r3, 8
  86:	6cc4      	or      	r3, r1
  88:	c48354e1 	zext      	r1, r3, 7, 4
  8c:	3945      	cmpnei      	r1, 5
  8e:	0c3f      	bf      	0x10c	// 10c <lmac_rx_frm_hdl+0x10c>
  90:	394d      	cmpnei      	r1, 13
  92:	0c4d      	bf      	0x12c	// 12c <lmac_rx_frm_hdl+0x12c>
  94:	3941      	cmpnei      	r1, 1
  96:	098a      	bt      	0x3aa	// 3aa <lmac_rx_frm_hdl+0x3aa>
  98:	c50359e3 	sext      	r3, r3, 15, 8
  9c:	90c7      	ld.w      	r6, (r0, 0x1c)
  9e:	6190      	addu      	r6, r4
  a0:	e9830022 	blz      	r3, 0xe4	// e4 <lmac_rx_frm_hdl+0xe4>
  a4:	2417      	addi      	r4, 24
  a6:	2403      	addi      	r4, 4
  a8:	02ee      	lrw      	r7, 0x0	// 36c <lmac_rx_frm_hdl+0x36c>
  aa:	ea8800ae 	lrw      	r8, 0x0	// 360 <lmac_rx_frm_hdl+0x360>
  ae:	ea8900b1 	lrw      	r9, 0x0	// 370 <lmac_rx_frm_hdl+0x370>
  b2:	6590      	cmphs      	r4, r6
  b4:	0c1a      	bf      	0xe8	// e8 <lmac_rx_frm_hdl+0xe8>
  b6:	3600      	movi      	r6, 0
  b8:	0275      	lrw      	r3, 0x0	// 360 <lmac_rx_frm_hdl+0x360>
  ba:	8d33      	ld.h      	r1, (r5, 0x26)
  bc:	d8431181 	ld.h      	r2, (r3, 0x302)
  c0:	6486      	cmpne      	r1, r2
  c2:	0bae      	bt      	0x1e	// 1e <lmac_rx_frm_hdl+0x1e>
  c4:	952a      	ld.w      	r1, (r5, 0x28)
  c6:	d84320c1 	ld.w      	r2, (r3, 0x304)
  ca:	6486      	cmpne      	r1, r2
  cc:	0ba9      	bt      	0x1e	// 1e <lmac_rx_frm_hdl+0x1e>
  ce:	d84320f0 	ld.w      	r2, (r3, 0x3c0)
  d2:	d82320f1 	ld.w      	r1, (r3, 0x3c4)
  d6:	6c84      	or      	r2, r1
  d8:	e902ffa3 	bez      	r2, 0x1e	// 1e <lmac_rx_frm_hdl+0x1e>
  dc:	3296      	movi      	r2, 150
  de:	dc4311e4 	st.h      	r2, (r3, 0x3c8)
  e2:	079e      	br      	0x1e	// 1e <lmac_rx_frm_hdl+0x1e>
  e4:	241b      	addi      	r4, 28
  e6:	07e0      	br      	0xa6	// a6 <lmac_rx_frm_hdl+0xa6>
  e8:	8460      	ld.b      	r3, (r4, 0x0)
  ea:	eb43005a 	cmpnei      	r3, 90
  ee:	0809      	bt      	0x100	// 100 <lmac_rx_frm_hdl+0x100>
  f0:	8421      	ld.b      	r1, (r4, 0x1)
  f2:	3943      	cmpnei      	r1, 3
  f4:	080a      	bt      	0x108	// 108 <lmac_rx_frm_hdl+0x108>
  f6:	d828133b 	ld.h      	r1, (r8, 0x676)
  fa:	6c27      	mov      	r0, r9
  fc:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 100:	8461      	ld.b      	r3, (r4, 0x1)
 102:	2301      	addi      	r3, 2
 104:	610c      	addu      	r4, r3
 106:	07d6      	br      	0xb2	// b2 <lmac_rx_frm_hdl+0xb2>
 108:	6c1f      	mov      	r0, r7
 10a:	07f9      	br      	0xfc	// fc <lmac_rx_frm_hdl+0xfc>
 10c:	c50359e3 	sext      	r3, r3, 15, 8
 110:	9047      	ld.w      	r2, (r0, 0x1c)
 112:	6090      	addu      	r2, r4
 114:	e983000a 	blz      	r3, 0x128	// 128 <lmac_rx_frm_hdl+0x128>
 118:	2417      	addi      	r4, 24
 11a:	2409      	addi      	r4, 10
 11c:	6490      	cmphs      	r4, r2
 11e:	0bcc      	bt      	0xb6	// b6 <lmac_rx_frm_hdl+0xb6>
 120:	8461      	ld.b      	r3, (r4, 0x1)
 122:	2301      	addi      	r3, 2
 124:	610c      	addu      	r4, r3
 126:	07fb      	br      	0x11c	// 11c <lmac_rx_frm_hdl+0x11c>
 128:	241b      	addi      	r4, 28
 12a:	07f8      	br      	0x11a	// 11a <lmac_rx_frm_hdl+0x11a>
 12c:	9067      	ld.w      	r3, (r0, 0x1c)
 12e:	60d0      	addu      	r3, r4
 130:	b86b      	st.w      	r3, (r14, 0x2c)
 132:	3600      	movi      	r6, 0
 134:	036f      	lrw      	r3, 0x0	// 374 <lmac_rx_frm_hdl+0x374>
 136:	2417      	addi      	r4, 24
 138:	2e00      	subi      	r6, 1
 13a:	03f5      	lrw      	r7, 0x0	// 360 <lmac_rx_frm_hdl+0x360>
 13c:	b86d      	st.w      	r3, (r14, 0x34)
 13e:	986b      	ld.w      	r3, (r14, 0x2c)
 140:	64d0      	cmphs      	r4, r3
 142:	0bbb      	bt      	0xb8	// b8 <lmac_rx_frm_hdl+0xb8>
 144:	8460      	ld.b      	r3, (r4, 0x0)
 146:	eb430026 	cmpnei      	r3, 38
 14a:	0c1d      	bf      	0x184	// 184 <lmac_rx_frm_hdl+0x184>
 14c:	eb030026 	cmphsi      	r3, 39
 150:	0806      	bt      	0x15c	// 15c <lmac_rx_frm_hdl+0x15c>
 152:	eb430025 	cmpnei      	r3, 37
 156:	0c2e      	bf      	0x1b2	// 1b2 <lmac_rx_frm_hdl+0x1b2>
 158:	3600      	movi      	r6, 0
 15a:	042c      	br      	0x1b2	// 1b2 <lmac_rx_frm_hdl+0x1b2>
 15c:	eb430027 	cmpnei      	r3, 39
 160:	0c2d      	bf      	0x1ba	// 1ba <lmac_rx_frm_hdl+0x1ba>
 162:	eb4300dd 	cmpnei      	r3, 221
 166:	0bf9      	bt      	0x158	// 158 <lmac_rx_frm_hdl+0x158>
 168:	8462      	ld.b      	r3, (r4, 0x2)
 16a:	e9230009 	bnez      	r3, 0x17c	// 17c <lmac_rx_frm_hdl+0x17c>
 16e:	8463      	ld.b      	r3, (r4, 0x3)
 170:	eb430040 	cmpnei      	r3, 64
 174:	0804      	bt      	0x17c	// 17c <lmac_rx_frm_hdl+0x17c>
 176:	8464      	ld.b      	r3, (r4, 0x4)
 178:	3b41      	cmpnei      	r3, 1
 17a:	0c4e      	bf      	0x216	// 216 <lmac_rx_frm_hdl+0x216>
 17c:	980d      	ld.w      	r0, (r14, 0x34)
 17e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 182:	07eb      	br      	0x158	// 158 <lmac_rx_frm_hdl+0x158>
 184:	8464      	ld.b      	r3, (r4, 0x4)
 186:	3b44      	cmpnei      	r3, 4
 188:	0815      	bt      	0x1b2	// 1b2 <lmac_rx_frm_hdl+0x1b2>
 18a:	846a      	ld.b      	r3, (r4, 0xa)
 18c:	8449      	ld.b      	r2, (r4, 0x9)
 18e:	4368      	lsli      	r3, r3, 8
 190:	6cc8      	or      	r3, r2
 192:	32fa      	movi      	r2, 250
 194:	436a      	lsli      	r3, r3, 10
 196:	4242      	lsli      	r2, r2, 2
 198:	c4438043 	divs      	r3, r3, r2
 19c:	dc6720e4 	st.w      	r3, (r7, 0x390)
 1a0:	e9030009 	bez      	r3, 0x1b2	// 1b2 <lmac_rx_frm_hdl+0x1b2>
 1a4:	d867037d 	ld.b      	r3, (r7, 0x37d)
 1a8:	3201      	movi      	r2, 1
 1aa:	c4625c02 	ins      	r3, r2, 2, 2
 1ae:	dc67037d 	st.b      	r3, (r7, 0x37d)
 1b2:	8461      	ld.b      	r3, (r4, 0x1)
 1b4:	2301      	addi      	r3, 2
 1b6:	610c      	addu      	r4, r3
 1b8:	07c3      	br      	0x13e	// 13e <lmac_rx_frm_hdl+0x13e>
 1ba:	8464      	ld.b      	r3, (r4, 0x4)
 1bc:	3b44      	cmpnei      	r3, 4
 1be:	0bfa      	bt      	0x1b2	// 1b2 <lmac_rx_frm_hdl+0x1b2>
 1c0:	d9452005 	ld.w      	r10, (r5, 0x14)
 1c4:	e5640025 	addi      	r11, r4, 38
 1c8:	e90afff5 	bez      	r10, 0x1b2	// 1b2 <lmac_rx_frm_hdl+0x1b2>
 1cc:	d924001f 	ld.b      	r9, (r4, 0x1f)
 1d0:	e5291005 	subi      	r9, r9, 6
 1d4:	3305      	movi      	r3, 5
 1d6:	c4698029 	divu      	r9, r9, r3
 1da:	ea080000 	movi      	r8, 0
 1de:	6661      	cmplt      	r8, r9
 1e0:	0809      	bt      	0x1f2	// 1f2 <lmac_rx_frm_hdl+0x1f2>
 1e2:	d86a006b 	ld.b      	r3, (r10, 0x6b)
 1e6:	3201      	movi      	r2, 1
 1e8:	c4625c06 	ins      	r3, r2, 6, 6
 1ec:	dc6a006b 	st.b      	r3, (r10, 0x6b)
 1f0:	07e1      	br      	0x1b2	// 1b2 <lmac_rx_frm_hdl+0x1b2>
 1f2:	6c2f      	mov      	r0, r11
 1f4:	e0000000 	bsr      	0x0	// 0 <lmac_rx_frm_hdl>
 1f8:	c4484823 	lsli      	r3, r8, 2
 1fc:	60e8      	addu      	r3, r10
 1fe:	b306      	st.w      	r0, (r3, 0x18)
 200:	c50a0023 	addu      	r3, r10, r8
 204:	d84b0004 	ld.b      	r2, (r11, 0x4)
 208:	dc430058 	st.b      	r2, (r3, 0x58)
 20c:	e56b0004 	addi      	r11, r11, 5
 210:	e5080000 	addi      	r8, r8, 1
 214:	07e5      	br      	0x1de	// 1de <lmac_rx_frm_hdl+0x1de>
 216:	8427      	ld.b      	r1, (r4, 0x7)
 218:	3942      	cmpnei      	r1, 2
 21a:	0c07      	bf      	0x228	// 228 <lmac_rx_frm_hdl+0x228>
 21c:	3943      	cmpnei      	r1, 3
 21e:	0cb3      	bf      	0x384	// 384 <lmac_rx_frm_hdl+0x384>
 220:	1216      	lrw      	r0, 0x0	// 378 <lmac_rx_frm_hdl+0x378>
 222:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 226:	04bf      	br      	0x3a4	// 3a4 <lmac_rx_frm_hdl+0x3a4>
 228:	9560      	ld.w      	r3, (r5, 0x0)
 22a:	e4632001 	andi      	r3, r3, 1
 22e:	e903ff95 	bez      	r3, 0x158	// 158 <lmac_rx_frm_hdl+0x158>
 232:	5c7e      	addi      	r3, r4, 8
 234:	6c0f      	mov      	r0, r3
 236:	b86c      	st.w      	r3, (r14, 0x30)
 238:	95c6      	ld.w      	r6, (r5, 0x18)
 23a:	e0000000 	bsr      	0x0	// 0 <lmac_rx_frm_hdl>
 23e:	986c      	ld.w      	r3, (r14, 0x30)
 240:	862a      	ld.b      	r1, (r6, 0xa)
 242:	d8434004 	ld.bs      	r2, (r3, 0x4)
 246:	d9434005 	ld.bs      	r10, (r3, 0x5)
 24a:	d9634006 	ld.bs      	r11, (r3, 0x6)
 24e:	d9834007 	ld.bs      	r12, (r3, 0x7)
 252:	d8670526 	ld.b      	r3, (r7, 0x526)
 256:	64c6      	cmpne      	r1, r3
 258:	d9054050 	ld.bs      	r8, (r5, 0x50)
 25c:	6e43      	mov      	r9, r0
 25e:	b84c      	st.w      	r2, (r14, 0x30)
 260:	081a      	bt      	0x294	// 294 <lmac_rx_frm_hdl+0x294>
 262:	860b      	ld.b      	r0, (r6, 0xb)
 264:	d8470527 	ld.b      	r2, (r7, 0x527)
 268:	6482      	cmpne      	r0, r2
 26a:	0815      	bt      	0x294	// 294 <lmac_rx_frm_hdl+0x294>
 26c:	860c      	ld.b      	r0, (r6, 0xc)
 26e:	d8470528 	ld.b      	r2, (r7, 0x528)
 272:	6482      	cmpne      	r0, r2
 274:	0810      	bt      	0x294	// 294 <lmac_rx_frm_hdl+0x294>
 276:	860d      	ld.b      	r0, (r6, 0xd)
 278:	d8470529 	ld.b      	r2, (r7, 0x529)
 27c:	6482      	cmpne      	r0, r2
 27e:	080b      	bt      	0x294	// 294 <lmac_rx_frm_hdl+0x294>
 280:	860e      	ld.b      	r0, (r6, 0xe)
 282:	d847052a 	ld.b      	r2, (r7, 0x52a)
 286:	6482      	cmpne      	r0, r2
 288:	0806      	bt      	0x294	// 294 <lmac_rx_frm_hdl+0x294>
 28a:	860f      	ld.b      	r0, (r6, 0xf)
 28c:	d847052b 	ld.b      	r2, (r7, 0x52b)
 290:	6482      	cmpne      	r0, r2
 292:	0f63      	bf      	0x158	// 158 <lmac_rx_frm_hdl+0x158>
 294:	8610      	ld.b      	r0, (r6, 0x10)
 296:	640e      	cmpne      	r3, r0
 298:	081a      	bt      	0x2cc	// 2cc <lmac_rx_frm_hdl+0x2cc>
 29a:	8651      	ld.b      	r2, (r6, 0x11)
 29c:	d8670527 	ld.b      	r3, (r7, 0x527)
 2a0:	64ca      	cmpne      	r2, r3
 2a2:	0815      	bt      	0x2cc	// 2cc <lmac_rx_frm_hdl+0x2cc>
 2a4:	8652      	ld.b      	r2, (r6, 0x12)
 2a6:	d8670528 	ld.b      	r3, (r7, 0x528)
 2aa:	64ca      	cmpne      	r2, r3
 2ac:	0810      	bt      	0x2cc	// 2cc <lmac_rx_frm_hdl+0x2cc>
 2ae:	8653      	ld.b      	r2, (r6, 0x13)
 2b0:	d8670529 	ld.b      	r3, (r7, 0x529)
 2b4:	64ca      	cmpne      	r2, r3
 2b6:	080b      	bt      	0x2cc	// 2cc <lmac_rx_frm_hdl+0x2cc>
 2b8:	8654      	ld.b      	r2, (r6, 0x14)
 2ba:	d867052a 	ld.b      	r3, (r7, 0x52a)
 2be:	64ca      	cmpne      	r2, r3
 2c0:	0806      	bt      	0x2cc	// 2cc <lmac_rx_frm_hdl+0x2cc>
 2c2:	8655      	ld.b      	r2, (r6, 0x15)
 2c4:	d867052b 	ld.b      	r3, (r7, 0x52b)
 2c8:	64ca      	cmpne      	r2, r3
 2ca:	0f47      	bf      	0x158	// 158 <lmac_rx_frm_hdl+0x158>
 2cc:	d86720ee 	ld.w      	r3, (r7, 0x3b8)
 2d0:	e4632001 	andi      	r3, r3, 1
 2d4:	e903002a 	bez      	r3, 0x328	// 328 <lmac_rx_frm_hdl+0x328>
 2d8:	866c      	ld.b      	r3, (r6, 0xc)
 2da:	864b      	ld.b      	r2, (r6, 0xb)
 2dc:	dd0e200a 	st.w      	r8, (r14, 0x28)
 2e0:	dd2e2009 	st.w      	r9, (r14, 0x24)
 2e4:	d9a60015 	ld.b      	r13, (r6, 0x15)
 2e8:	ddae2008 	st.w      	r13, (r14, 0x20)
 2ec:	d9a60014 	ld.b      	r13, (r6, 0x14)
 2f0:	ddae2007 	st.w      	r13, (r14, 0x1c)
 2f4:	d9a60013 	ld.b      	r13, (r6, 0x13)
 2f8:	ddae2006 	st.w      	r13, (r14, 0x18)
 2fc:	d9a60012 	ld.b      	r13, (r6, 0x12)
 300:	ddae2005 	st.w      	r13, (r14, 0x14)
 304:	d9a60011 	ld.b      	r13, (r6, 0x11)
 308:	ddae2004 	st.w      	r13, (r14, 0x10)
 30c:	b803      	st.w      	r0, (r14, 0xc)
 30e:	860f      	ld.b      	r0, (r6, 0xf)
 310:	b802      	st.w      	r0, (r14, 0x8)
 312:	860e      	ld.b      	r0, (r6, 0xe)
 314:	b801      	st.w      	r0, (r14, 0x4)
 316:	860d      	ld.b      	r0, (r6, 0xd)
 318:	b800      	st.w      	r0, (r14, 0x0)
 31a:	dd8e200e 	st.w      	r12, (r14, 0x38)
 31e:	1018      	lrw      	r0, 0x0	// 37c <hgprintf+0x37c>
 320:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 324:	d98e200e 	ld.w      	r12, (r14, 0x38)
 328:	1076      	lrw      	r3, 0x0	// 380 <lmac_rx_frm_hdl+0x380>
 32a:	3210      	movi      	r2, 16
 32c:	e9090014 	bez      	r9, 0x354	// 354 <lmac_rx_frm_hdl+0x354>
 330:	9320      	ld.w      	r1, (r3, 0x0)
 332:	6466      	cmpne      	r9, r1
 334:	0810      	bt      	0x354	// 354 <lmac_rx_frm_hdl+0x354>
 336:	d8234007 	ld.bs      	r1, (r3, 0x7)
 33a:	6605      	cmplt      	r1, r8
 33c:	0c0c      	bf      	0x354	// 354 <lmac_rx_frm_hdl+0x354>
 33e:	d82e0030 	ld.b      	r1, (r14, 0x30)
 342:	dd030007 	st.b      	r8, (r3, 0x7)
 346:	dd430005 	st.b      	r10, (r3, 0x5)
 34a:	a324      	st.b      	r1, (r3, 0x4)
 34c:	dd630006 	st.b      	r11, (r3, 0x6)
 350:	dd830008 	st.b      	r12, (r3, 0x8)
 354:	2a00      	subi      	r2, 1
 356:	230b      	addi      	r3, 12
 358:	e922ffea 	bnez      	r2, 0x32c	// 32c <lmac_rx_frm_hdl+0x32c>
 35c:	06fe      	br      	0x158	// 158 <lmac_rx_frm_hdl+0x158>
	...
 382:	0000      	.short	0x0000
 384:	3300      	movi      	r3, 0
 386:	5c4c      	addu      	r2, r4, r3
 388:	d822400f 	ld.bs      	r1, (r2, 0xf)
 38c:	1152      	lrw      	r2, 0x0	// 454 <lmac_rx_frm_hdl+0x454>
 38e:	608c      	addu      	r2, r3
 390:	d8024247 	ld.bs      	r0, (r2, 0x247)
 394:	6441      	cmplt      	r0, r1
 396:	0c03      	bf      	0x39c	// 39c <lmac_rx_frm_hdl+0x39c>
 398:	dc220247 	st.b      	r1, (r2, 0x247)
 39c:	230b      	addi      	r3, 12
 39e:	eb4300c0 	cmpnei      	r3, 192
 3a2:	0bf2      	bt      	0x386	// 386 <lmac_rx_frm_hdl+0x386>
 3a4:	3600      	movi      	r6, 0
 3a6:	2e00      	subi      	r6, 1
 3a8:	0705      	br      	0x1b2	// 1b2 <lmac_rx_frm_hdl+0x1b2>
 3aa:	6d8b      	mov      	r6, r2
 3ac:	0686      	br      	0xb8	// b8 <lmac_rx_frm_hdl+0xb8>
 3ae:	90e6      	ld.w      	r7, (r0, 0x18)
 3b0:	d9002007 	ld.w      	r8, (r0, 0x1c)
 3b4:	8781      	ld.b      	r4, (r7, 0x1)
 3b6:	8760      	ld.b      	r3, (r7, 0x0)
 3b8:	4488      	lsli      	r4, r4, 8
 3ba:	6d0c      	or      	r4, r3
 3bc:	c4845564 	zext      	r4, r4, 11, 4
 3c0:	e464200f 	andi      	r3, r4, 15
 3c4:	3b4a      	cmpnei      	r3, 10
 3c6:	0806      	bt      	0x3d2	// 3d2 <lmac_rx_frm_hdl+0x3d2>
 3c8:	1104      	lrw      	r0, 0x0	// 458 <lmac_rx_frm_hdl+0x458>
 3ca:	3600      	movi      	r6, 0
 3cc:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 3d0:	2e00      	subi      	r6, 1
 3d2:	9565      	ld.w      	r3, (r5, 0x14)
 3d4:	ea890020 	lrw      	r9, 0x0	// 454 <lmac_rx_frm_hdl+0x454>
 3d8:	e9230013 	bnez      	r3, 0x3fe	// 3fe <lmac_rx_frm_hdl+0x3fe>
 3dc:	d865403a 	ld.bs      	r3, (r5, 0x3a)
 3e0:	e983000f 	blz      	r3, 0x3fe	// 3fe <lmac_rx_frm_hdl+0x3fe>
 3e4:	d8092000 	ld.w      	r0, (r9, 0x0)
 3e8:	d9802009 	ld.w      	r12, (r0, 0x24)
 3ec:	e90c0007 	bez      	r12, 0x3fa	// 3fa <lmac_rx_frm_hdl+0x3fa>
 3f0:	3306      	movi      	r3, 6
 3f2:	e445002b 	addi      	r2, r5, 44
 3f6:	3122      	movi      	r1, 34
 3f8:	7bf1      	jsr      	r12
 3fa:	3600      	movi      	r6, 0
 3fc:	2e00      	subi      	r6, 1
 3fe:	e4842007 	andi      	r4, r4, 7
 402:	3c44      	cmpnei      	r4, 4
 404:	080c      	bt      	0x41c	// 41c <lmac_rx_frm_hdl+0x41c>
 406:	1076      	lrw      	r3, 0x0	// 45c <lmac_rx_frm_hdl+0x45c>
 408:	6c63      	mov      	r1, r8
 40a:	1016      	lrw      	r0, 0x0	// 460 <lmac_rx_frm_hdl+0x460>
 40c:	d8434149 	ld.bs      	r2, (r3, 0x149)
 410:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 414:	3110      	movi      	r1, 16
 416:	6c1f      	mov      	r0, r7
 418:	e0000000 	bsr      	0x0	// 0 <hgics_print_hex>
 41c:	d8690314 	ld.b      	r3, (r9, 0x314)
 420:	e463201f 	andi      	r3, r3, 31
 424:	e903fdfd 	bez      	r3, 0x1e	// 1e <lmac_rx_frm_hdl+0x1e>
 428:	d8690310 	ld.b      	r3, (r9, 0x310)
 42c:	e4632020 	andi      	r3, r3, 32
 430:	e923fdf7 	bnez      	r3, 0x1e	// 1e <lmac_rx_frm_hdl+0x1e>
 434:	6c1f      	mov      	r0, r7
 436:	e0000000 	bsr      	0x0	// 0 <lmac_rx_frm_hdl>
 43a:	6d83      	mov      	r6, r0
 43c:	e800fdf1 	br      	0x1e	// 1e <lmac_rx_frm_hdl+0x1e>
 440:	1049      	lrw      	r2, 0x0	// 464 <lmac_rx_frm_hdl+0x464>
 442:	c4435483 	zext      	r3, r3, 4, 2
 446:	9027      	ld.w      	r1, (r0, 0x1c)
 448:	d0620883 	ldr.w      	r3, (r2, r3 << 2)
 44c:	9006      	ld.w      	r0, (r0, 0x18)
 44e:	7bcd      	jsr      	r3
 450:	07f5      	br      	0x43a	// 43a <lmac_rx_frm_hdl+0x43a>
	...

Disassembly of section .text.lmac_rx_task:

00000000 <lmac_rx_task>:
   0:	14d5      	push      	r4-r8, r15
   2:	1422      	subi      	r14, r14, 8
   4:	12f6      	lrw      	r7, 0x0	// 15c <lmac_rx_task+0x15c>
   6:	12b7      	lrw      	r5, 0x0	// 160 <lmac_rx_task+0x160>
   8:	6d97      	mov      	r6, r5
   a:	8560      	ld.b      	r3, (r5, 0x0)
   c:	e4632001 	andi      	r3, r3, 1
  10:	e9030004 	bez      	r3, 0x18	// 18 <lmac_rx_task+0x18>
  14:	1402      	addi      	r14, r14, 8
  16:	1495      	pop      	r4-r8, r15
  18:	3300      	movi      	r3, 0
  1a:	2b00      	subi      	r3, 1
  1c:	3201      	movi      	r2, 1
  1e:	6c7b      	mov      	r1, r14
  20:	e406004f 	addi      	r0, r6, 80
  24:	e0000000 	bsr      	0x0	// 0 <lmac_rxq_get>
  28:	e900ffef 	bez      	r0, 0x6	// 6 <lmac_rx_task+0x6>
  2c:	d8670319 	ld.b      	r3, (r7, 0x319)
  30:	e4632002 	andi      	r3, r3, 2
  34:	e923001f 	bnez      	r3, 0x72	// 72 <lmac_rx_task+0x72>
  38:	d90709e2 	ld.b      	r8, (r7, 0x9e2)
  3c:	c4285428 	zext      	r8, r8, 1, 1
  40:	9820      	ld.w      	r1, (r14, 0x0)
  42:	957a      	ld.w      	r3, (r5, 0x68)
  44:	64c4      	cmphs      	r1, r3
  46:	0c0c      	bf      	0x5e	// 5e <lmac_rx_task+0x5e>
  48:	955e      	ld.w      	r2, (r5, 0x78)
  4a:	951d      	ld.w      	r0, (r5, 0x74)
  4c:	6082      	subu      	r2, r0
  4e:	60c8      	addu      	r3, r2
  50:	644c      	cmphs      	r3, r1
  52:	0c06      	bf      	0x5e	// 5e <lmac_rx_task+0x5e>
  54:	9861      	ld.w      	r3, (r14, 0x4)
  56:	2b09      	subi      	r3, 10
  58:	eb030f2d 	cmphsi      	r3, 3886
  5c:	0c11      	bf      	0x7e	// 7e <lmac_rx_task+0x7e>
  5e:	9841      	ld.w      	r2, (r14, 0x4)
  60:	1201      	lrw      	r0, 0x0	// 164 <lmac_rx_task+0x164>
  62:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  66:	d8672200 	ld.w      	r3, (r7, 0x800)
  6a:	2300      	addi      	r3, 1
  6c:	dc672200 	st.w      	r3, (r7, 0x800)
  70:	07cb      	br      	0x6	// 6 <lmac_rx_task+0x6>
  72:	ea080001 	movi      	r8, 1
  76:	07e5      	br      	0x40	// 40 <lmac_rx_task+0x40>
  78:	3005      	movi      	r0, 5
  7a:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
  7e:	3074      	movi      	r0, 116
  80:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  84:	6d03      	mov      	r4, r0
  86:	e900fff9 	bez      	r0, 0x78	// 78 <lmac_rx_task+0x78>
  8a:	9820      	ld.w      	r1, (r14, 0x0)
  8c:	3274      	movi      	r2, 116
  8e:	297f      	subi      	r1, 128
  90:	e0000000 	bsr      	0x0	// 0 <memcpy>
  94:	9860      	ld.w      	r3, (r14, 0x0)
  96:	b466      	st.w      	r3, (r4, 0x18)
  98:	9861      	ld.w      	r3, (r14, 0x4)
  9a:	b467      	st.w      	r3, (r4, 0x1c)
  9c:	3300      	movi      	r3, 0
  9e:	b465      	st.w      	r3, (r4, 0x14)
  a0:	e9080025 	bez      	r8, 0xea	// ea <lmac_rx_task+0xea>
  a4:	3301      	movi      	r3, 1
  a6:	d8470310 	ld.b      	r2, (r7, 0x310)
  aa:	e4422020 	andi      	r2, r2, 32
  ae:	e9020038 	bez      	r2, 0x11e	// 11e <lmac_rx_task+0x11e>
  b2:	e9030006 	bez      	r3, 0xbe	// be <lmac_rx_task+0xbe>
  b6:	9460      	ld.w      	r3, (r4, 0x0)
  b8:	ec630008 	ori      	r3, r3, 8
  bc:	b460      	st.w      	r3, (r4, 0x0)
  be:	d8462057 	ld.w      	r2, (r6, 0x15c)
  c2:	5a62      	addi      	r3, r2, 1
  c4:	d8262058 	ld.w      	r1, (r6, 0x160)
  c8:	644d      	cmplt      	r3, r1
  ca:	5b05      	subu      	r0, r3, r1
  cc:	c4600c20 	incf      	r3, r0, 0
  d0:	d8262056 	ld.w      	r1, (r6, 0x158)
  d4:	644e      	cmpne      	r3, r1
  d6:	0c20      	bf      	0x116	// 116 <lmac_rx_task+0x116>
  d8:	2258      	addi      	r2, 89
  da:	d4450884 	str.w      	r4, (r5, r2 << 2)
  de:	dc652057 	st.w      	r3, (r5, 0x15c)
  e2:	1102      	lrw      	r0, 0x0	// 168 <os_sema_up+0x168>
  e4:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  e8:	078f      	br      	0x6	// 6 <lmac_rx_task+0x6>
  ea:	6c13      	mov      	r0, r4
  ec:	e0000000 	bsr      	0x0	// 0 <lmac_rx_task>
  f0:	e920ffda 	bnez      	r0, 0xa4	// a4 <lmac_rx_task+0xa4>
  f4:	6c13      	mov      	r0, r4
  f6:	e0000000 	bsr      	0x0	// 0 <lmac_rx_task>
  fa:	e920ffd5 	bnez      	r0, 0xa4	// a4 <lmac_rx_task+0xa4>
  fe:	6c13      	mov      	r0, r4
 100:	e0000000 	bsr      	0x0	// 0 <lmac_rx_task>
 104:	e920ffd0 	bnez      	r0, 0xa4	// a4 <lmac_rx_task+0xa4>
 108:	6c13      	mov      	r0, r4
 10a:	e0000000 	bsr      	0x0	// 0 <lmac_rx_task>
 10e:	3840      	cmpnei      	r0, 0
 110:	c4000503 	mvc      	r3
 114:	07c9      	br      	0xa6	// a6 <lmac_rx_task+0xa6>
 116:	3005      	movi      	r0, 5
 118:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
 11c:	07d1      	br      	0xbe	// be <lmac_rx_task+0xbe>
 11e:	e9030006 	bez      	r3, 0x12a	// 12a <lmac_rx_task+0x12a>
 122:	9460      	ld.w      	r3, (r4, 0x0)
 124:	ec630008 	ori      	r3, r3, 8
 128:	b460      	st.w      	r3, (r4, 0x0)
 12a:	d84620db 	ld.w      	r2, (r6, 0x36c)
 12e:	5a62      	addi      	r3, r2, 1
 130:	d82620dc 	ld.w      	r1, (r6, 0x370)
 134:	644d      	cmplt      	r3, r1
 136:	5b05      	subu      	r0, r3, r1
 138:	c4600c20 	incf      	r3, r0, 0
 13c:	d82620da 	ld.w      	r1, (r6, 0x368)
 140:	644e      	cmpne      	r3, r1
 142:	0c08      	bf      	0x152	// 152 <lmac_rx_task+0x152>
 144:	22dc      	addi      	r2, 221
 146:	d4450884 	str.w      	r4, (r5, r2 << 2)
 14a:	dc6520db 	st.w      	r3, (r5, 0x36c)
 14e:	1008      	lrw      	r0, 0x0	// 16c <lmac_rx_task+0x16c>
 150:	07ca      	br      	0xe4	// e4 <lmac_rx_task+0xe4>
 152:	3005      	movi      	r0, 5
 154:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
 158:	07e9      	br      	0x12a	// 12a <lmac_rx_task+0x12a>
	...

Disassembly of section .text.rx_ccmp_test:

00000000 <rx_ccmp_test>:
   0:	14d4      	push      	r4-r7, r15
   2:	173d      	subi      	r14, r14, 500
   4:	11a1      	lrw      	r5, 0x0	// 88 <rx_ccmp_test+0x88>
   6:	364c      	movi      	r6, 76
   8:	6c9b      	mov      	r2, r6
   a:	1121      	lrw      	r1, 0x0	// 8c <rx_ccmp_test+0x8c>
   c:	6c17      	mov      	r0, r5
   e:	e0000000 	bsr      	0x0	// 0 <memcpy>
  12:	3074      	movi      	r0, 116
  14:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  18:	6d03      	mov      	r4, r0
  1a:	b0a6      	st.w      	r5, (r0, 0x18)
  1c:	b0c7      	st.w      	r6, (r0, 0x1c)
  1e:	6c17      	mov      	r0, r5
  20:	e0000000 	bsr      	0x0	// 0 <lmac_get_hdr_len_pv0>
  24:	3701      	movi      	r7, 1
  26:	d864003b 	ld.b      	r3, (r4, 0x3b)
  2a:	c4675c00 	ins      	r3, r7, 0, 0
  2e:	dc64003b 	st.b      	r3, (r4, 0x3b)
  32:	3300      	movi      	r3, 0
  34:	dc040020 	st.b      	r0, (r4, 0x20)
  38:	3210      	movi      	r2, 16
  3a:	dc6e0075 	st.b      	r3, (r14, 0x75)
  3e:	e40e0076 	addi      	r0, r14, 119
  42:	3310      	movi      	r3, 16
  44:	1033      	lrw      	r1, 0x0	// 90 <rx_ccmp_test+0x90>
  46:	dc6e0076 	st.b      	r3, (r14, 0x76)
  4a:	e0000000 	bsr      	0x0	// 0 <memcpy>
  4e:	6c5b      	mov      	r1, r6
  50:	1011      	lrw      	r0, 0x0	// 94 <rx_ccmp_test+0x94>
  52:	ddc42005 	st.w      	r14, (r4, 0x14)
  56:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  5a:	1010      	lrw      	r0, 0x0	// 98 <rx_ccmp_test+0x98>
  5c:	6cdf      	mov      	r3, r7
  5e:	6c9b      	mov      	r2, r6
  60:	6c57      	mov      	r1, r5
  62:	e0000000 	bsr      	0x0	// 0 <dump_hex>
  66:	6c13      	mov      	r0, r4
  68:	e0000000 	bsr      	0x0	// 0 <rx_ccmp_test>
  6c:	e9200008 	bnez      	r0, 0x7c	// 7c <rx_ccmp_test+0x7c>
  70:	6cdf      	mov      	r3, r7
  72:	9447      	ld.w      	r2, (r4, 0x1c)
  74:	9426      	ld.w      	r1, (r4, 0x18)
  76:	100a      	lrw      	r0, 0x0	// 9c <rx_ccmp_test+0x9c>
  78:	e0000000 	bsr      	0x0	// 0 <dump_hex>
  7c:	6c13      	mov      	r0, r4
  7e:	e0000000 	bsr      	0x0	// 0 <_os_free>
  82:	171d      	addi      	r14, r14, 500
  84:	1494      	pop      	r4-r7, r15
	...

Disassembly of section .text.lmac_cache_check:

00000000 <lmac_cache_check>:
   0:	3000      	movi      	r0, 0
   2:	2800      	subi      	r0, 1
   4:	783c      	jmp      	r15

Disassembly of section .text.lmac_cache_win_update:

00000000 <lmac_cache_win_update>:
   0:	14d5      	push      	r4-r8, r15
   2:	1427      	subi      	r14, r14, 28
   4:	d980003a 	ld.b      	r12, (r0, 0x3a)
   8:	c42c548c 	zext      	r12, r12, 4, 1
   c:	90c5      	ld.w      	r6, (r0, 0x14)
   e:	c48c4825 	lsli      	r5, r12, 4
  12:	5e74      	addu      	r3, r6, r5
  14:	6d03      	mov      	r4, r0
  16:	d843414f 	ld.bs      	r2, (r3, 0x14f)
  1a:	e9a2003d 	bhsz      	r2, 0x94	// 94 <lmac_cache_win_update+0x94>
  1e:	90e8      	ld.w      	r7, (r0, 0x20)
  20:	d80310a6 	ld.h      	r0, (r3, 0x14c)
  24:	c50756e7 	zext      	r7, r7, 23, 8
  28:	e4002fff 	andi      	r0, r0, 4095
  2c:	641d      	cmplt      	r7, r0
  2e:	0829      	bt      	0x80	// 80 <lmac_cache_win_update+0x80>
  30:	5f41      	subu      	r2, r7, r0
  32:	c4a60028 	addu      	r8, r6, r5
  36:	7489      	zexth      	r2, r2
  38:	d868014f 	ld.b      	r3, (r8, 0x14f)
  3c:	e463207f 	andi      	r3, r3, 127
  40:	64c9      	cmplt      	r2, r3
  42:	0c54      	bf      	0xea	// ea <lmac_cache_win_update+0xea>
  44:	3001      	movi      	r0, 1
  46:	3100      	movi      	r1, 0
  48:	e0000000 	bsr      	0x0	// 0 <__ashldi3>
  4c:	d9882051 	ld.w      	r12, (r8, 0x144)
  50:	d9a82052 	ld.w      	r13, (r8, 0x148)
  54:	c5802022 	and      	r2, r0, r12
  58:	c5a12023 	and      	r3, r1, r13
  5c:	6c8c      	or      	r2, r3
  5e:	e9020015 	bez      	r2, 0x88	// 88 <lmac_cache_win_update+0x88>
  62:	127f      	lrw      	r3, 0x0	// 1dc <lmac_cache_win_update+0x1dc>
  64:	d86320ee 	ld.w      	r3, (r3, 0x3b8)
  68:	e4632020 	andi      	r3, r3, 32
  6c:	e9030005 	bez      	r3, 0x76	// 76 <lmac_cache_win_update+0x76>
  70:	121c      	lrw      	r0, 0x0	// 1e0 <hgprintf+0x1e0>
  72:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  76:	9460      	ld.w      	r3, (r4, 0x0)
  78:	ec630008 	ori      	r3, r3, 8
  7c:	b460      	st.w      	r3, (r4, 0x0)
  7e:	040b      	br      	0x94	// 94 <lmac_cache_win_update+0x94>
  80:	e4470fff 	addi      	r2, r7, 4096
  84:	6082      	subu      	r2, r0
  86:	07d6      	br      	0x32	// 32 <lmac_cache_win_update+0x32>
  88:	6c30      	or      	r0, r12
  8a:	6c74      	or      	r1, r13
  8c:	dc082051 	st.w      	r0, (r8, 0x144)
  90:	dc282052 	st.w      	r1, (r8, 0x148)
  94:	5e74      	addu      	r3, r6, r5
  96:	d9832051 	ld.w      	r12, (r3, 0x144)
  9a:	eb4c0001 	cmpnei      	r12, 1
  9e:	d8032052 	ld.w      	r0, (r3, 0x148)
  a2:	0803      	bt      	0xa8	// a8 <lmac_cache_win_update+0xa8>
  a4:	e900005c 	bez      	r0, 0x15c	// 15c <lmac_cache_win_update+0x15c>
  a8:	126d      	lrw      	r3, 0x0	// 1dc <lmac_cache_win_update+0x1dc>
  aa:	d86320ee 	ld.w      	r3, (r3, 0x3b8)
  ae:	e4632020 	andi      	r3, r3, 32
  b2:	e9030055 	bez      	r3, 0x15c	// 15c <lmac_cache_win_update+0x15c>
  b6:	6158      	addu      	r5, r6
  b8:	dd8e2002 	st.w      	r12, (r14, 0x8)
  bc:	b803      	st.w      	r0, (r14, 0xc)
  be:	d8052053 	ld.w      	r0, (r5, 0x14c)
  c2:	c58056e0 	zext      	r0, r0, 23, 12
  c6:	b801      	st.w      	r0, (r14, 0x4)
  c8:	d80510a6 	ld.h      	r0, (r5, 0x14c)
  cc:	9468      	ld.w      	r3, (r4, 0x20)
  ce:	d844003a 	ld.b      	r2, (r4, 0x3a)
  d2:	e4002fff 	andi      	r0, r0, 4095
  d6:	b800      	st.w      	r0, (r14, 0x0)
  d8:	9425      	ld.w      	r1, (r4, 0x14)
  da:	c50356e3 	zext      	r3, r3, 23, 8
  de:	c4225482 	zext      	r2, r2, 4, 1
  e2:	1201      	lrw      	r0, 0x0	// 1e4 <hgprintf+0x1e4>
  e4:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  e8:	043a      	br      	0x15c	// 15c <lmac_cache_win_update+0x15c>
  ea:	117d      	lrw      	r3, 0x0	// 1dc <lmac_cache_win_update+0x1dc>
  ec:	eb0207ff 	cmphsi      	r2, 2048
  f0:	d86320ee 	ld.w      	r3, (r3, 0x3b8)
  f4:	e4632020 	andi      	r3, r3, 32
  f8:	0857      	bt      	0x1a6	// 1a6 <lmac_cache_win_update+0x1a6>
  fa:	e9030005 	bez      	r3, 0x104	// 104 <lmac_cache_win_update+0x104>
  fe:	111b      	lrw      	r0, 0x0	// 1e8 <hgprintf+0x1e8>
 100:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 104:	5e54      	addu      	r2, r6, r5
 106:	ea218000 	movih      	r1, 32768
 10a:	e4210ffe 	addi      	r1, r1, 4095
 10e:	d86210a6 	ld.h      	r3, (r2, 0x14c)
 112:	c4675d60 	ins      	r3, r7, 11, 0
 116:	dc6210a6 	st.h      	r3, (r2, 0x14c)
 11a:	d862014f 	ld.b      	r3, (r2, 0x14f)
 11e:	e463207f 	andi      	r3, r3, 127
 122:	60dc      	addu      	r3, r7
 124:	2b00      	subi      	r3, 1
 126:	68c4      	and      	r3, r1
 128:	e9a30008 	bhsz      	r3, 0x138	// 138 <lmac_cache_win_update+0x138>
 12c:	2b00      	subi      	r3, 1
 12e:	ea010fff 	movi      	r1, 4095
 132:	6c46      	nor      	r1, r1
 134:	6cc4      	or      	r3, r1
 136:	2300      	addi      	r3, 1
 138:	d8222053 	ld.w      	r1, (r2, 0x14c)
 13c:	c4235d6c 	ins      	r1, r3, 23, 12
 140:	6158      	addu      	r5, r6
 142:	dc222053 	st.w      	r1, (r2, 0x14c)
 146:	3300      	movi      	r3, 0
 148:	3201      	movi      	r2, 1
 14a:	dc452051 	st.w      	r2, (r5, 0x144)
 14e:	dc652052 	st.w      	r3, (r5, 0x148)
 152:	1147      	lrw      	r2, 0x0	// 1ec <lmac_cache_win_update+0x1ec>
 154:	2203      	addi      	r2, 4
 156:	9220      	ld.w      	r1, (r2, 0x0)
 158:	6486      	cmpne      	r1, r2
 15a:	0803      	bt      	0x160	// 160 <lmac_cache_win_update+0x160>
 15c:	1407      	addi      	r14, r14, 28
 15e:	1495      	pop      	r4-r8, r15
 160:	d9812004 	ld.w      	r12, (r1, 0x10)
 164:	9465      	ld.w      	r3, (r4, 0x14)
 166:	64f2      	cmpne      	r12, r3
 168:	081a      	bt      	0x19c	// 19c <lmac_cache_win_update+0x19c>
 16a:	d8610036 	ld.b      	r3, (r1, 0x36)
 16e:	d984003a 	ld.b      	r12, (r4, 0x3a)
 172:	6cf1      	xor      	r3, r12
 174:	e463201e 	andi      	r3, r3, 30
 178:	e9230012 	bnez      	r3, 0x19c	// 19c <lmac_cache_win_update+0x19c>
 17c:	9167      	ld.w      	r3, (r1, 0x1c)
 17e:	c50356e3 	zext      	r3, r3, 23, 8
 182:	65cc      	cmphs      	r3, r7
 184:	0c0e      	bf      	0x1a0	// 1a0 <lmac_cache_win_update+0x1a0>
 186:	60de      	subu      	r3, r7
 188:	eb2307ff 	cmplti      	r3, 2048
 18c:	64c3      	mvcv      	r3
 18e:	74cc      	zextb      	r3, r3
 190:	e9030006 	bez      	r3, 0x19c	// 19c <lmac_cache_win_update+0x19c>
 194:	9460      	ld.w      	r3, (r4, 0x0)
 196:	ec630010 	ori      	r3, r3, 16
 19a:	b460      	st.w      	r3, (r4, 0x0)
 19c:	9120      	ld.w      	r1, (r1, 0x0)
 19e:	07dd      	br      	0x158	// 158 <lmac_cache_win_update+0x158>
 1a0:	e4630fff 	addi      	r3, r3, 4096
 1a4:	07f1      	br      	0x186	// 186 <lmac_cache_win_update+0x186>
 1a6:	e903ff68 	bez      	r3, 0x76	// 76 <lmac_cache_win_update+0x76>
 1aa:	b806      	st.w      	r0, (r14, 0x18)
 1ac:	d8040031 	ld.b      	r0, (r4, 0x31)
 1b0:	b802      	st.w      	r0, (r14, 0x8)
 1b2:	d8040030 	ld.b      	r0, (r4, 0x30)
 1b6:	b801      	st.w      	r0, (r14, 0x4)
 1b8:	d804002f 	ld.b      	r0, (r4, 0x2f)
 1bc:	b800      	st.w      	r0, (r14, 0x0)
 1be:	d864002e 	ld.b      	r3, (r4, 0x2e)
 1c2:	d844002d 	ld.b      	r2, (r4, 0x2d)
 1c6:	d824002c 	ld.b      	r1, (r4, 0x2c)
 1ca:	b8e5      	st.w      	r7, (r14, 0x14)
 1cc:	dd8e2004 	st.w      	r12, (r14, 0x10)
 1d0:	b8c3      	st.w      	r6, (r14, 0xc)
 1d2:	1008      	lrw      	r0, 0x0	// 1f0 <lmac_cache_win_update+0x1f0>
 1d4:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1d8:	074f      	br      	0x76	// 76 <lmac_cache_win_update+0x76>
	...

Disassembly of section .text.lmac_rx_init:

00000000 <lmac_rx_init>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	1281      	lrw      	r4, 0x0	// 108 <lmac_rx_init+0x108>
   6:	32b1      	movi      	r2, 177
   8:	4243      	lsli      	r2, r2, 3
   a:	3100      	movi      	r1, 0
   c:	6c13      	mov      	r0, r4
   e:	e0000000 	bsr      	0x0	// 0 <memset>
  12:	9501      	ld.w      	r0, (r5, 0x4)
  14:	9560      	ld.w      	r3, (r5, 0x0)
  16:	b41e      	st.w      	r0, (r4, 0x78)
  18:	4808      	lsri      	r0, r0, 8
  1a:	4003      	lsli      	r0, r0, 3
  1c:	b47a      	st.w      	r3, (r4, 0x68)
  1e:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  22:	b419      	st.w      	r0, (r4, 0x64)
  24:	e9200008 	bnez      	r0, 0x34	// 34 <lmac_rx_init+0x34>
  28:	1159      	lrw      	r2, 0x0	// 10c <lmac_rx_init+0x10c>
  2a:	ea0111eb 	movi      	r1, 4587
  2e:	1119      	lrw      	r0, 0x0	// 110 <assert_internal+0x110>
  30:	e0000000 	bsr      	0x0	// 0 <assert_internal>
  34:	945e      	ld.w      	r2, (r4, 0x78)
  36:	4a48      	lsri      	r2, r2, 8
  38:	9439      	ld.w      	r1, (r4, 0x64)
  3a:	1117      	lrw      	r0, 0x0	// 114 <lmac_rx_init+0x114>
  3c:	e0000000 	bsr      	0x0	// 0 <lmac_rxq_init>
  40:	e0000000 	bsr      	0x0	// 0 <lmac_rx_init>
  44:	e0000000 	bsr      	0x0	// 0 <lmac_rx_init>
  48:	3100      	movi      	r1, 0
  4a:	1114      	lrw      	r0, 0x0	// 118 <lmac_rx_init+0x118>
  4c:	e0000000 	bsr      	0x0	// 0 <os_sema_init>
  50:	3100      	movi      	r1, 0
  52:	1113      	lrw      	r0, 0x0	// 11c <lmac_rx_init+0x11c>
  54:	e0000000 	bsr      	0x0	// 0 <os_sema_init>
  58:	11b2      	lrw      	r5, 0x0	// 120 <lmac_rx_init+0x120>
  5a:	3300      	movi      	r3, 0
  5c:	dc642056 	st.w      	r3, (r4, 0x158)
  60:	dc642057 	st.w      	r3, (r4, 0x15c)
  64:	dc6420da 	st.w      	r3, (r4, 0x368)
  68:	dc6420db 	st.w      	r3, (r4, 0x36c)
  6c:	5d7e      	addi      	r3, r5, 8
  6e:	3280      	movi      	r2, 128
  70:	b463      	st.w      	r3, (r4, 0xc)
  72:	b464      	st.w      	r3, (r4, 0x10)
  74:	5d6f      	subi      	r3, r5, 4
  76:	e4230013 	addi      	r1, r3, 20
  7a:	dc442058 	st.w      	r2, (r4, 0x160)
  7e:	dc4420dc 	st.w      	r2, (r4, 0x370)
  82:	b4a1      	st.w      	r5, (r4, 0x4)
  84:	b4a2      	st.w      	r5, (r4, 0x8)
  86:	1108      	lrw      	r0, 0x0	// 124 <lmac_rx_init+0x124>
  88:	1148      	lrw      	r2, 0x0	// 128 <lmac_rx_init+0x128>
  8a:	e0000000 	bsr      	0x0	// 0 <os_task_init>
  8e:	3180      	movi      	r1, 128
  90:	4123      	lsli      	r1, r1, 3
  92:	e405000f 	addi      	r0, r5, 16
  96:	e0000000 	bsr      	0x0	// 0 <os_task_set_stacksize>
  9a:	3157      	movi      	r1, 87
  9c:	e405000f 	addi      	r0, r5, 16
  a0:	e0000000 	bsr      	0x0	// 0 <_os_task_set_priority>
  a4:	e405000f 	addi      	r0, r5, 16
  a8:	e0000000 	bsr      	0x0	// 0 <os_task_run>
  ac:	5d6f      	subi      	r3, r5, 4
  ae:	e4230027 	addi      	r1, r3, 40
  b2:	105f      	lrw      	r2, 0x0	// 12c <lmac_rx_init+0x12c>
  b4:	101f      	lrw      	r0, 0x0	// 130 <lmac_rx_init+0x130>
  b6:	e0000000 	bsr      	0x0	// 0 <os_task_init>
  ba:	3180      	movi      	r1, 128
  bc:	4123      	lsli      	r1, r1, 3
  be:	e4050023 	addi      	r0, r5, 36
  c2:	e0000000 	bsr      	0x0	// 0 <os_task_set_stacksize>
  c6:	3156      	movi      	r1, 86
  c8:	e4050023 	addi      	r0, r5, 36
  cc:	e0000000 	bsr      	0x0	// 0 <_os_task_set_priority>
  d0:	e4050023 	addi      	r0, r5, 36
  d4:	e0000000 	bsr      	0x0	// 0 <os_task_run>
  d8:	5d6f      	subi      	r3, r5, 4
  da:	e423003b 	addi      	r1, r3, 60
  de:	1056      	lrw      	r2, 0x0	// 134 <lmac_rx_init+0x134>
  e0:	1016      	lrw      	r0, 0x0	// 138 <lmac_rx_init+0x138>
  e2:	e0000000 	bsr      	0x0	// 0 <os_task_init>
  e6:	3180      	movi      	r1, 128
  e8:	4123      	lsli      	r1, r1, 3
  ea:	e4050037 	addi      	r0, r5, 56
  ee:	e0000000 	bsr      	0x0	// 0 <os_task_set_stacksize>
  f2:	3150      	movi      	r1, 80
  f4:	e4050037 	addi      	r0, r5, 56
  f8:	e0000000 	bsr      	0x0	// 0 <_os_task_set_priority>
  fc:	e4050037 	addi      	r0, r5, 56
 100:	e0000000 	bsr      	0x0	// 0 <os_task_run>
 104:	1492      	pop      	r4-r5, r15
	...
