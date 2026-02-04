
disasm/liblmac/obj/mars_rfdigicali.o:     file format elf32-csky-little


Disassembly of section .text.ah_rfdigicali_stop_tx_cali:

00000000 <ah_rfdigicali_stop_tx_cali>:
   0:	1067      	lrw      	r3, 0x4001d000	// 1c <ah_rfdigicali_stop_tx_cali+0x1c>
   2:	9340      	ld.w      	r2, (r3, 0x0)
   4:	3a80      	bclri      	r2, 0
   6:	3a81      	bclri      	r2, 1
   8:	b340      	st.w      	r2, (r3, 0x0)
   a:	9340      	ld.w      	r2, (r3, 0x0)
   c:	3a86      	bclri      	r2, 6
   e:	b340      	st.w      	r2, (r3, 0x0)
  10:	9340      	ld.w      	r2, (r3, 0x0)
  12:	ec420008 	ori      	r2, r2, 8
  16:	b340      	st.w      	r2, (r3, 0x0)
  18:	783c      	jmp      	r15
  1a:	0000      	.short	0x0000
  1c:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_power_calc_kick_start:

00000000 <ah_rfdigicali_power_calc_kick_start>:
   0:	106d      	lrw      	r3, 0x4001d000	// 34 <ah_rfdigicali_power_calc_kick_start+0x34>
   2:	3180      	movi      	r1, 128
   4:	9345      	ld.w      	r2, (r3, 0x14)
   6:	ec422000 	ori      	r2, r2, 8192
   a:	b345      	st.w      	r2, (r3, 0x14)
   c:	9345      	ld.w      	r2, (r3, 0x14)
   e:	ec420001 	ori      	r2, r2, 1
  12:	b345      	st.w      	r2, (r3, 0x14)
  14:	4126      	lsli      	r1, r1, 6
  16:	9345      	ld.w      	r2, (r3, 0x14)
  18:	6884      	and      	r2, r1
  1a:	e902fffe 	bez      	r2, 0x16	// 16 <ah_rfdigicali_power_calc_kick_start+0x16>
  1e:	9345      	ld.w      	r2, (r3, 0x14)
  20:	ec422000 	ori      	r2, r2, 8192
  24:	b345      	st.w      	r2, (r3, 0x14)
  26:	9306      	ld.w      	r0, (r3, 0x18)
  28:	9345      	ld.w      	r2, (r3, 0x14)
  2a:	3a80      	bclri      	r2, 0
  2c:	4808      	lsri      	r0, r0, 8
  2e:	b345      	st.w      	r2, (r3, 0x14)
  30:	783c      	jmp      	r15
  32:	0000      	.short	0x0000
  34:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_dcoc_est_en:

00000000 <ah_rfdigicali_dcoc_est_en>:
   0:	1066      	lrw      	r3, 0x4001d000	// 18 <ah_rfdigicali_dcoc_est_en+0x18>
   2:	ea02d058 	movi      	r2, 53336
   6:	c4824902 	rotli      	r2, r2, 4
   a:	b340      	st.w      	r2, (r3, 0x0)
   c:	ea021e02 	movi      	r2, 7682
  10:	b341      	st.w      	r2, (r3, 0x4)
  12:	3202      	movi      	r2, 2
  14:	b342      	st.w      	r2, (r3, 0x8)
  16:	783c      	jmp      	r15
  18:	d000      	.short	0xd000
  1a:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_rx_dcoc_hw_trig_en:

00000000 <ah_rfdigicali_rx_dcoc_hw_trig_en>:
   0:	1043      	lrw      	r2, 0x4001d000	// c <ah_rfdigicali_rx_dcoc_hw_trig_en+0xc>
   2:	9260      	ld.w      	r3, (r2, 0x0)
   4:	3bb9      	bseti      	r3, 25
   6:	b260      	st.w      	r3, (r2, 0x0)
   8:	783c      	jmp      	r15
   a:	0000      	.short	0x0000
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_rx_dcoc_hw_trig_dis:

00000000 <ah_rfdigicali_rx_dcoc_hw_trig_dis>:
   0:	1043      	lrw      	r2, 0x4001d000	// c <ah_rfdigicali_rx_dcoc_hw_trig_dis+0xc>
   2:	9260      	ld.w      	r3, (r2, 0x0)
   4:	3b99      	bclri      	r3, 25
   6:	b260      	st.w      	r3, (r2, 0x0)
   8:	783c      	jmp      	r15
   a:	0000      	.short	0x0000
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_dcoc_est_kick_start:

00000000 <ah_rfdigicali_dcoc_est_kick_start>:
   0:	14d2      	push      	r4-r5, r15
   2:	1093      	lrw      	r4, 0x4001d000	// 4c <ah_rfdigicali_dcoc_est_kick_start+0x4c>
   4:	6d43      	mov      	r5, r0
   6:	9460      	ld.w      	r3, (r4, 0x0)
   8:	ec630003 	ori      	r3, r3, 3
   c:	b460      	st.w      	r3, (r4, 0x0)
   e:	3002      	movi      	r0, 2
  10:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
  14:	9460      	ld.w      	r3, (r4, 0x0)
  16:	ec630040 	ori      	r3, r3, 64
  1a:	b460      	st.w      	r3, (r4, 0x0)
  1c:	3002      	movi      	r0, 2
  1e:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  22:	9463      	ld.w      	r3, (r4, 0xc)
  24:	c4035963 	sext      	r3, r3, 11, 0
  28:	b560      	st.w      	r3, (r5, 0x0)
  2a:	9463      	ld.w      	r3, (r4, 0xc)
  2c:	c5835ae3 	sext      	r3, r3, 23, 12
  30:	b561      	st.w      	r3, (r5, 0x4)
  32:	9460      	ld.w      	r3, (r4, 0x0)
  34:	3b80      	bclri      	r3, 0
  36:	3b81      	bclri      	r3, 1
  38:	b460      	st.w      	r3, (r4, 0x0)
  3a:	9460      	ld.w      	r3, (r4, 0x0)
  3c:	3b86      	bclri      	r3, 6
  3e:	b460      	st.w      	r3, (r4, 0x0)
  40:	9460      	ld.w      	r3, (r4, 0x0)
  42:	ec630008 	ori      	r3, r3, 8
  46:	b460      	st.w      	r3, (r4, 0x0)
  48:	1492      	pop      	r4-r5, r15
  4a:	0000      	.short	0x0000
  4c:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_dcoc_imb_est_kick_start:

00000000 <ah_rfdigicali_dcoc_imb_est_kick_start>:
   0:	1066      	lrw      	r3, 0x4001d000	// 18 <ah_rfdigicali_dcoc_imb_est_kick_start+0x18>
   2:	3280      	movi      	r2, 128
   4:	4252      	lsli      	r2, r2, 18
   6:	b344      	st.w      	r2, (r3, 0x10)
   8:	3228      	movi      	r2, 40
   a:	b345      	st.w      	r2, (r3, 0x14)
   c:	9340      	ld.w      	r2, (r3, 0x0)
   e:	ec420003 	ori      	r2, r2, 3
  12:	b340      	st.w      	r2, (r3, 0x0)
  14:	783c      	jmp      	r15
  16:	0000      	.short	0x0000
  18:	d000      	.short	0xd000
  1a:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_config_hw_rx_dcoc:

00000000 <ah_rfdigicali_config_hw_rx_dcoc>:
   0:	1078      	lrw      	r3, 0x4001d000	// 60 <ah_rfdigicali_config_hw_rx_dcoc+0x60>
   2:	ea8d0019 	lrw      	r13, 0xfc001e00	// 64 <ah_rfdigicali_config_hw_rx_dcoc+0x64>
   6:	d9832000 	ld.w      	r12, (r3, 0x0)
   a:	6b34      	and      	r12, r13
   c:	dd832000 	st.w      	r12, (r3, 0x0)
  10:	d9a32000 	ld.w      	r13, (r3, 0x0)
  14:	c461484c 	lsri      	r12, r1, 3
  18:	edada704 	ori      	r13, r13, 42756
  1c:	c62c482c 	lsli      	r12, r12, 17
  20:	6f34      	or      	r12, r13
  22:	dd832000 	st.w      	r12, (r3, 0x0)
  26:	ea0d00ff 	movi      	r13, 255
  2a:	d9832001 	ld.w      	r12, (r3, 0x4)
  2e:	c70d482d 	lsli      	r13, r13, 24
  32:	6b34      	and      	r12, r13
  34:	dd832001 	st.w      	r12, (r3, 0x4)
  38:	6048      	addu      	r1, r2
  3a:	d9832001 	ld.w      	r12, (r3, 0x4)
  3e:	ea220100 	movih      	r2, 256
  42:	2aff      	subi      	r2, 256
  44:	4125      	lsli      	r1, r1, 5
  46:	6848      	and      	r1, r2
  48:	6c30      	or      	r0, r12
  4a:	6c40      	or      	r1, r0
  4c:	b321      	st.w      	r1, (r3, 0x4)
  4e:	3200      	movi      	r2, 0
  50:	31f2      	movi      	r1, 242
  52:	b342      	st.w      	r2, (r3, 0x8)
  54:	4138      	lsli      	r1, r1, 24
  56:	9344      	ld.w      	r2, (r3, 0x10)
  58:	2900      	subi      	r1, 1
  5a:	6884      	and      	r2, r1
  5c:	b344      	st.w      	r2, (r3, 0x10)
  5e:	783c      	jmp      	r15
  60:	4001d000 	.long	0x4001d000
  64:	fc001e00 	.long	0xfc001e00

Disassembly of section .text.ah_rfdigicali_config_hw_bknoise:

00000000 <ah_rfdigicali_config_hw_bknoise>:
   0:	104d      	lrw      	r2, 0x4001d000	// 34 <ah_rfdigicali_config_hw_bknoise+0x34>
   2:	33c0      	movi      	r3, 192
   4:	4367      	lsli      	r3, r3, 7
   6:	b265      	st.w      	r3, (r2, 0x14)
   8:	d9822005 	ld.w      	r12, (r2, 0x14)
   c:	4167      	lsli      	r3, r1, 7
   e:	ea2d0001 	movih      	r13, 1
  12:	e5ad085f 	addi      	r13, r13, 2144
  16:	6f34      	or      	r12, r13
  18:	e4632780 	andi      	r3, r3, 1920
  1c:	6044      	addu      	r1, r1
  1e:	6cf0      	or      	r3, r12
  20:	e421201e 	andi      	r1, r1, 30
  24:	6c4c      	or      	r1, r3
  26:	4011      	lsli      	r0, r0, 17
  28:	ea233ffe 	movih      	r3, 16382
  2c:	680c      	and      	r0, r3
  2e:	6c40      	or      	r1, r0
  30:	b225      	st.w      	r1, (r2, 0x14)
  32:	783c      	jmp      	r15
  34:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_bknoise_hw_trig_en:

00000000 <ah_rfdigicali_bknoise_hw_trig_en>:
   0:	1043      	lrw      	r2, 0x4001d000	// c <ah_rfdigicali_bknoise_hw_trig_en+0xc>
   2:	9265      	ld.w      	r3, (r2, 0x14)
   4:	ec638000 	ori      	r3, r3, 32768
   8:	b265      	st.w      	r3, (r2, 0x14)
   a:	783c      	jmp      	r15
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_bknoise_hw_trig_dis:

00000000 <ah_rfdigicali_bknoise_hw_trig_dis>:
   0:	1043      	lrw      	r2, 0x4001d000	// c <ah_rfdigicali_bknoise_hw_trig_dis+0xc>
   2:	9265      	ld.w      	r3, (r2, 0x14)
   4:	3b8f      	bclri      	r3, 15
   6:	b265      	st.w      	r3, (r2, 0x14)
   8:	783c      	jmp      	r15
   a:	0000      	.short	0x0000
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_bknoise_calc_en:

00000000 <ah_rfdigicali_bknoise_calc_en>:
   0:	1043      	lrw      	r2, 0x4001d000	// c <ah_rfdigicali_bknoise_calc_en+0xc>
   2:	9265      	ld.w      	r3, (r2, 0x14)
   4:	ec630001 	ori      	r3, r3, 1
   8:	b265      	st.w      	r3, (r2, 0x14)
   a:	783c      	jmp      	r15
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_bknoise_calc_dis:

00000000 <ah_rfdigicali_bknoise_calc_dis>:
   0:	1044      	lrw      	r2, 0x4001d000	// 10 <ah_rfdigicali_bknoise_calc_dis+0x10>
   2:	ea016001 	movi      	r1, 24577
   6:	6c46      	nor      	r1, r1
   8:	9265      	ld.w      	r3, (r2, 0x14)
   a:	68c4      	and      	r3, r1
   c:	b265      	st.w      	r3, (r2, 0x14)
   e:	783c      	jmp      	r15
  10:	d000      	.short	0xd000
  12:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_bknoise_valid_pd_get:

00000000 <ah_rfdigicali_bknoise_valid_pd_get>:
   0:	1063      	lrw      	r3, 0x4001d000	// c <ah_rfdigicali_bknoise_valid_pd_get+0xc>
   2:	9305      	ld.w      	r0, (r3, 0x14)
   4:	3380      	movi      	r3, 128
   6:	4366      	lsli      	r3, r3, 6
   8:	680c      	and      	r0, r3
   a:	783c      	jmp      	r15
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_bknoise_valid_pd_clr:

00000000 <ah_rfdigicali_bknoise_valid_pd_clr>:
   0:	1043      	lrw      	r2, 0x4001d000	// c <ah_rfdigicali_bknoise_valid_pd_clr+0xc>
   2:	9265      	ld.w      	r3, (r2, 0x14)
   4:	ec636000 	ori      	r3, r3, 24576
   8:	b265      	st.w      	r3, (r2, 0x14)
   a:	783c      	jmp      	r15
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_dcoci_get:

00000000 <ah_rfdigicali_dcoci_get>:
   0:	1049      	lrw      	r2, 0x4001d000	// 24 <ah_rfdigicali_dcoci_get+0x24>
   2:	9260      	ld.w      	r3, (r2, 0x0)
   4:	e4632001 	andi      	r3, r3, 1
   8:	e923000b 	bnez      	r3, 0x1e	// 1e <ah_rfdigicali_dcoci_get+0x1e>
   c:	9203      	ld.w      	r0, (r2, 0xc)
   e:	e4002fff 	andi      	r0, r0, 4095
  12:	eb2007ff 	cmplti      	r0, 2048
  16:	0803      	bt      	0x1c	// 1c <ah_rfdigicali_dcoci_get+0x1c>
  18:	e4001fff 	subi      	r0, r0, 4096
  1c:	783c      	jmp      	r15
  1e:	ea007fff 	movi      	r0, 32767
  22:	07fd      	br      	0x1c	// 1c <ah_rfdigicali_dcoci_get+0x1c>
  24:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_dcocq_get:

00000000 <ah_rfdigicali_dcocq_get>:
   0:	1049      	lrw      	r2, 0x4001d000	// 24 <ah_rfdigicali_dcocq_get+0x24>
   2:	9260      	ld.w      	r3, (r2, 0x0)
   4:	e4632002 	andi      	r3, r3, 2
   8:	e923000b 	bnez      	r3, 0x1e	// 1e <ah_rfdigicali_dcocq_get+0x1e>
   c:	9203      	ld.w      	r0, (r2, 0xc)
   e:	c58056e0 	zext      	r0, r0, 23, 12
  12:	eb2007ff 	cmplti      	r0, 2048
  16:	0803      	bt      	0x1c	// 1c <ah_rfdigicali_dcocq_get+0x1c>
  18:	e4001fff 	subi      	r0, r0, 4096
  1c:	783c      	jmp      	r15
  1e:	ea007fff 	movi      	r0, 32767
  22:	07fd      	br      	0x1c	// 1c <ah_rfdigicali_dcocq_get+0x1c>
  24:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_bknoise_get:

00000000 <ah_rfdigicali_bknoise_get>:
   0:	1069      	lrw      	r3, 0x4001d000	// 24 <ah_rfdigicali_bknoise_get+0x24>
   2:	3180      	movi      	r1, 128
   4:	9345      	ld.w      	r2, (r3, 0x14)
   6:	4126      	lsli      	r1, r1, 6
   8:	6884      	and      	r2, r1
   a:	e9020009 	bez      	r2, 0x1c	// 1c <ah_rfdigicali_bknoise_get+0x1c>
   e:	9306      	ld.w      	r0, (r3, 0x18)
  10:	7402      	sextb      	r0, r0
  12:	9345      	ld.w      	r2, (r3, 0x14)
  14:	ec422000 	ori      	r2, r2, 8192
  18:	b345      	st.w      	r2, (r3, 0x14)
  1a:	783c      	jmp      	r15
  1c:	3000      	movi      	r0, 0
  1e:	2800      	subi      	r0, 1
  20:	07f9      	br      	0x12	// 12 <ah_rfdigicali_bknoise_get+0x12>
  22:	0000      	.short	0x0000
  24:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_tx_pwr:

00000000 <ah_rfdigicali_tx_pwr>:
   0:	106a      	lrw      	r3, 0x4001d000	// 28 <ah_rfdigicali_tx_pwr+0x28>
   2:	3100      	movi      	r1, 0
   4:	934b      	ld.w      	r2, (r3, 0x2c)
   6:	3a8f      	bclri      	r2, 15
   8:	b34b      	st.w      	r2, (r3, 0x2c)
   a:	934b      	ld.w      	r2, (r3, 0x2c)
   c:	2907      	subi      	r1, 8
   e:	6884      	and      	r2, r1
  10:	6c08      	or      	r0, r2
  12:	b30b      	st.w      	r0, (r3, 0x2c)
  14:	934b      	ld.w      	r2, (r3, 0x2c)
  16:	ec420008 	ori      	r2, r2, 8
  1a:	b34b      	st.w      	r2, (r3, 0x2c)
  1c:	934b      	ld.w      	r2, (r3, 0x2c)
  1e:	e4422008 	andi      	r2, r2, 8
  22:	e922fffd 	bnez      	r2, 0x1c	// 1c <ah_rfdigicali_tx_pwr+0x1c>
  26:	783c      	jmp      	r15
  28:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_tx_dcoc:

00000000 <ah_rfdigicali_tx_dcoc>:
   0:	4122      	lsli      	r1, r1, 2
   2:	1071      	lrw      	r3, 0x4001d000	// 44 <ah_rfdigicali_tx_dcoc+0x44>
   4:	604c      	addu      	r1, r3
   6:	ea22fff0 	movih      	r2, 65520
   a:	916c      	ld.w      	r3, (r1, 0x30)
   c:	68c8      	and      	r3, r2
   e:	b16c      	st.w      	r3, (r1, 0x30)
  10:	d8605001 	ld.hs      	r3, (r0, 0x2)
  14:	436a      	lsli      	r3, r3, 10
  16:	ea2c0010 	movih      	r12, 16
  1a:	e58c13ff 	subi      	r12, r12, 1024
  1e:	914c      	ld.w      	r2, (r1, 0x30)
  20:	68f0      	and      	r3, r12
  22:	6cc8      	or      	r3, r2
  24:	8840      	ld.h      	r2, (r0, 0x0)
  26:	e44223ff 	andi      	r2, r2, 1023
  2a:	6cc8      	or      	r3, r2
  2c:	b16c      	st.w      	r3, (r1, 0x30)
  2e:	1066      	lrw      	r3, 0x4001d000	// 44 <ah_rfdigicali_tx_dcoc+0x44>
  30:	934b      	ld.w      	r2, (r3, 0x2c)
  32:	ec420008 	ori      	r2, r2, 8
  36:	b34b      	st.w      	r2, (r3, 0x2c)
  38:	934b      	ld.w      	r2, (r3, 0x2c)
  3a:	e4422008 	andi      	r2, r2, 8
  3e:	e922fffd 	bnez      	r2, 0x38	// 38 <ah_rfdigicali_tx_dcoc+0x38>
  42:	783c      	jmp      	r15
  44:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_tx_imb:

00000000 <ah_rfdigicali_config_tx_imb>:
   0:	4242      	lsli      	r2, r2, 2
   2:	107c      	lrw      	r3, 0x4001d000	// 70 <ah_rfdigicali_config_tx_imb+0x70>
   4:	608c      	addu      	r2, r3
   6:	ea2ce010 	movih      	r12, 57360
   a:	926c      	ld.w      	r3, (r2, 0x30)
   c:	e58c1000 	subi      	r12, r12, 1
  10:	68f0      	and      	r3, r12
  12:	b26c      	st.w      	r3, (r2, 0x30)
  14:	4014      	lsli      	r0, r0, 20
  16:	ea2c1ff0 	movih      	r12, 8176
  1a:	926c      	ld.w      	r3, (r2, 0x30)
  1c:	6830      	and      	r0, r12
  1e:	6c0c      	or      	r0, r3
  20:	b20c      	st.w      	r0, (r2, 0x30)
  22:	30ff      	movi      	r0, 255
  24:	9272      	ld.w      	r3, (r2, 0x48)
  26:	4018      	lsli      	r0, r0, 24
  28:	eb010400 	cmphsi      	r1, 1025
  2c:	68c0      	and      	r3, r0
  2e:	b272      	st.w      	r3, (r2, 0x48)
  30:	0c1c      	bf      	0x68	// 68 <ah_rfdigicali_config_tx_imb+0x68>
  32:	3380      	movi      	r3, 128
  34:	436f      	lsli      	r3, r3, 15
  36:	c4238043 	divs      	r3, r3, r1
  3a:	9212      	ld.w      	r0, (r2, 0x48)
  3c:	e4212fff 	andi      	r1, r1, 4095
  40:	6c40      	or      	r1, r0
  42:	436c      	lsli      	r3, r3, 12
  44:	ea00fff0 	movi      	r0, 65520
  48:	c5004900 	rotli      	r0, r0, 8
  4c:	68c0      	and      	r3, r0
  4e:	6cc4      	or      	r3, r1
  50:	b272      	st.w      	r3, (r2, 0x48)
  52:	1068      	lrw      	r3, 0x4001d000	// 70 <ah_rfdigicali_config_tx_imb+0x70>
  54:	934b      	ld.w      	r2, (r3, 0x2c)
  56:	ec420008 	ori      	r2, r2, 8
  5a:	b34b      	st.w      	r2, (r3, 0x2c)
  5c:	934b      	ld.w      	r2, (r3, 0x2c)
  5e:	e4422008 	andi      	r2, r2, 8
  62:	e922fffd 	bnez      	r2, 0x5c	// 5c <ah_rfdigicali_config_tx_imb+0x5c>
  66:	783c      	jmp      	r15
  68:	ea030fff 	movi      	r3, 4095
  6c:	07e7      	br      	0x3a	// 3a <ah_rfdigicali_config_tx_imb+0x3a>
  6e:	0000      	.short	0x0000
  70:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_tx_digi_gain:

00000000 <ah_rfdigicali_config_tx_digi_gain>:
   0:	eb0007ff 	cmphsi      	r0, 2048
   4:	6cc3      	mov      	r3, r0
   6:	0c03      	bf      	0xc	// c <ah_rfdigicali_config_tx_digi_gain+0xc>
   8:	ea0307ff 	movi      	r3, 2047
   c:	3904      	cmphsi      	r1, 5
   e:	74cd      	zexth      	r3, r3
  10:	1043      	lrw      	r2, 0x4001d000	// 1c <ah_rfdigicali_config_tx_digi_gain+0x1c>
  12:	085b      	bt      	0xc8	// c8 <ah_rfdigicali_config_tx_digi_gain+0xc8>
  14:	1003      	lrw      	r0, 0x0	// 20 <ah_rfdigicali_config_tx_digi_gain+0x20>
  16:	d0200881 	ldr.w      	r1, (r0, r1 << 2)
  1a:	7804      	jmp      	r1
  1c:	4001d000 	.long	0x4001d000
  20:	0000      	.short	0x0000
  22:	0000      	.short	0x0000
  24:	d8222056 	ld.w      	r1, (r2, 0x158)
  28:	ea0007ff 	movi      	r0, 2047
  2c:	6c02      	nor      	r0, r0
  2e:	6840      	and      	r1, r0
  30:	dc222056 	st.w      	r1, (r2, 0x158)
  34:	d8222056 	ld.w      	r1, (r2, 0x158)
  38:	6cc4      	or      	r3, r1
  3a:	dc622056 	st.w      	r3, (r2, 0x158)
  3e:	116b      	lrw      	r3, 0x4001d000	// e8 <ah_rfdigicali_config_tx_digi_gain+0xe8>
  40:	934b      	ld.w      	r2, (r3, 0x2c)
  42:	ec420008 	ori      	r2, r2, 8
  46:	b34b      	st.w      	r2, (r3, 0x2c)
  48:	934b      	ld.w      	r2, (r3, 0x2c)
  4a:	e4422008 	andi      	r2, r2, 8
  4e:	e922fffd 	bnez      	r2, 0x48	// 48 <ah_rfdigicali_config_tx_digi_gain+0x48>
  52:	783c      	jmp      	r15
  54:	ea20f801 	movih      	r0, 63489
  58:	d8222056 	ld.w      	r1, (r2, 0x158)
  5c:	2800      	subi      	r0, 1
  5e:	6840      	and      	r1, r0
  60:	dc222056 	st.w      	r1, (r2, 0x158)
  64:	4370      	lsli      	r3, r3, 16
  66:	ea2007ff 	movih      	r0, 2047
  6a:	d8222056 	ld.w      	r1, (r2, 0x158)
  6e:	68c0      	and      	r3, r0
  70:	07e4      	br      	0x38	// 38 <ah_rfdigicali_config_tx_digi_gain+0x38>
  72:	d8222057 	ld.w      	r1, (r2, 0x15c)
  76:	ea0007ff 	movi      	r0, 2047
  7a:	6c02      	nor      	r0, r0
  7c:	6840      	and      	r1, r0
  7e:	dc222057 	st.w      	r1, (r2, 0x15c)
  82:	d8222057 	ld.w      	r1, (r2, 0x15c)
  86:	6cc4      	or      	r3, r1
  88:	dc622057 	st.w      	r3, (r2, 0x15c)
  8c:	07d9      	br      	0x3e	// 3e <ah_rfdigicali_config_tx_digi_gain+0x3e>
  8e:	ea20f801 	movih      	r0, 63489
  92:	d8222057 	ld.w      	r1, (r2, 0x15c)
  96:	2800      	subi      	r0, 1
  98:	6840      	and      	r1, r0
  9a:	dc222057 	st.w      	r1, (r2, 0x15c)
  9e:	4370      	lsli      	r3, r3, 16
  a0:	ea2007ff 	movih      	r0, 2047
  a4:	d8222057 	ld.w      	r1, (r2, 0x15c)
  a8:	68c0      	and      	r3, r0
  aa:	07ee      	br      	0x86	// 86 <ah_rfdigicali_config_tx_digi_gain+0x86>
  ac:	d8222058 	ld.w      	r1, (r2, 0x160)
  b0:	ea0007ff 	movi      	r0, 2047
  b4:	6c02      	nor      	r0, r0
  b6:	6840      	and      	r1, r0
  b8:	dc222058 	st.w      	r1, (r2, 0x160)
  bc:	d8222058 	ld.w      	r1, (r2, 0x160)
  c0:	6cc4      	or      	r3, r1
  c2:	dc622058 	st.w      	r3, (r2, 0x160)
  c6:	07bc      	br      	0x3e	// 3e <ah_rfdigicali_config_tx_digi_gain+0x3e>
  c8:	ea20f801 	movih      	r0, 63489
  cc:	d8222058 	ld.w      	r1, (r2, 0x160)
  d0:	2800      	subi      	r0, 1
  d2:	6840      	and      	r1, r0
  d4:	dc222058 	st.w      	r1, (r2, 0x160)
  d8:	4370      	lsli      	r3, r3, 16
  da:	ea2007ff 	movih      	r0, 2047
  de:	d8222058 	ld.w      	r1, (r2, 0x160)
  e2:	68c0      	and      	r3, r0
  e4:	07ee      	br      	0xc0	// c0 <ah_rfdigicali_config_tx_digi_gain+0xc0>
  e6:	0000      	.short	0x0000
  e8:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_rx_gain:

00000000 <ah_rfdigicali_config_rx_gain>:
   0:	1071      	lrw      	r3, 0x4001d000	// 44 <ah_rfdigicali_config_rx_gain+0x44>
   2:	4128      	lsli      	r1, r1, 8
   4:	9358      	ld.w      	r2, (r3, 0x60)
   6:	3a88      	bclri      	r2, 8
   8:	3a89      	bclri      	r2, 9
   a:	6c84      	or      	r2, r1
   c:	b358      	st.w      	r2, (r3, 0x60)
   e:	3100      	movi      	r1, 0
  10:	9358      	ld.w      	r2, (r3, 0x60)
  12:	2907      	subi      	r1, 8
  14:	6884      	and      	r2, r1
  16:	b358      	st.w      	r2, (r3, 0x60)
  18:	9358      	ld.w      	r2, (r3, 0x60)
  1a:	6c80      	or      	r2, r0
  1c:	b358      	st.w      	r2, (r3, 0x60)
  1e:	3100      	movi      	r1, 0
  20:	9358      	ld.w      	r2, (r3, 0x60)
  22:	29e0      	subi      	r1, 225
  24:	6884      	and      	r2, r1
  26:	b358      	st.w      	r2, (r3, 0x60)
  28:	9358      	ld.w      	r2, (r3, 0x60)
  2a:	4005      	lsli      	r0, r0, 5
  2c:	6c08      	or      	r0, r2
  2e:	b318      	st.w      	r0, (r3, 0x60)
  30:	9358      	ld.w      	r2, (r3, 0x60)
  32:	ec420008 	ori      	r2, r2, 8
  36:	b358      	st.w      	r2, (r3, 0x60)
  38:	9358      	ld.w      	r2, (r3, 0x60)
  3a:	e4422008 	andi      	r2, r2, 8
  3e:	e922fffd 	bnez      	r2, 0x38	// 38 <ah_rfdigicali_config_rx_gain+0x38>
  42:	783c      	jmp      	r15
  44:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_rx_dcoc:

00000000 <ah_rfdigicali_config_rx_dcoc>:
   0:	3a03      	cmphsi      	r2, 4
   2:	8861      	ld.h      	r3, (r0, 0x2)
   4:	8800      	ld.h      	r0, (r0, 0x0)
   6:	0826      	bt      	0x52	// 52 <ah_rfdigicali_config_rx_dcoc+0x52>
   8:	770b      	sexth      	r12, r2
   a:	c58c0022 	addu      	r2, r12, r12
   e:	60b0      	addu      	r2, r12
  10:	4242      	lsli      	r2, r2, 2
  12:	6048      	addu      	r1, r2
  14:	4122      	lsli      	r1, r1, 2
  16:	105c      	lrw      	r2, 0x4001d000	// 84 <ah_rfdigicali_config_rx_dcoc+0x84>
  18:	6048      	addu      	r1, r2
  1a:	ea2cfff0 	movih      	r12, 65520
  1e:	9159      	ld.w      	r2, (r1, 0x64)
  20:	68b0      	and      	r2, r12
  22:	436a      	lsli      	r3, r3, 10
  24:	ea2c0010 	movih      	r12, 16
  28:	e58c13ff 	subi      	r12, r12, 1024
  2c:	b159      	st.w      	r2, (r1, 0x64)
  2e:	68f0      	and      	r3, r12
  30:	e40023ff 	andi      	r0, r0, 1023
  34:	9159      	ld.w      	r2, (r1, 0x64)
  36:	6cc0      	or      	r3, r0
  38:	6cc8      	or      	r3, r2
  3a:	b179      	st.w      	r3, (r1, 0x64)
  3c:	1072      	lrw      	r3, 0x4001d000	// 84 <ah_rfdigicali_config_rx_dcoc+0x84>
  3e:	9358      	ld.w      	r2, (r3, 0x60)
  40:	ec420008 	ori      	r2, r2, 8
  44:	b358      	st.w      	r2, (r3, 0x60)
  46:	9358      	ld.w      	r2, (r3, 0x60)
  48:	e4422008 	andi      	r2, r2, 8
  4c:	e922fffd 	bnez      	r2, 0x46	// 46 <ah_rfdigicali_config_rx_dcoc+0x46>
  50:	783c      	jmp      	r15
  52:	104d      	lrw      	r2, 0x4001d000	// 84 <ah_rfdigicali_config_rx_dcoc+0x84>
  54:	4122      	lsli      	r1, r1, 2
  56:	6048      	addu      	r1, r2
  58:	ea2cfff0 	movih      	r12, 65520
  5c:	d8412049 	ld.w      	r2, (r1, 0x124)
  60:	68b0      	and      	r2, r12
  62:	dc412049 	st.w      	r2, (r1, 0x124)
  66:	436a      	lsli      	r3, r3, 10
  68:	ea2c0010 	movih      	r12, 16
  6c:	e58c13ff 	subi      	r12, r12, 1024
  70:	d8412049 	ld.w      	r2, (r1, 0x124)
  74:	68f0      	and      	r3, r12
  76:	6cc8      	or      	r3, r2
  78:	e40023ff 	andi      	r0, r0, 1023
  7c:	6cc0      	or      	r3, r0
  7e:	dc612049 	st.w      	r3, (r1, 0x124)
  82:	07dd      	br      	0x3c	// 3c <ah_rfdigicali_config_rx_dcoc+0x3c>
  84:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_rx_imb:

00000000 <ah_rfdigicali_config_rx_imb>:
   0:	eb010400 	cmphsi      	r1, 1025
   4:	0c3d      	bf      	0x7e	// 7e <ah_rfdigicali_config_rx_imb+0x7e>
   6:	ea0c0080 	movi      	r12, 128
   a:	c5ec482c 	lsli      	r12, r12, 15
   e:	c42c804c 	divs      	r12, r12, r1
  12:	3b03      	cmphsi      	r3, 4
  14:	4014      	lsli      	r0, r0, 20
  16:	c58c482d 	lsli      	r13, r12, 12
  1a:	e4212fff 	andi      	r1, r1, 4095
  1e:	0833      	bt      	0x84	// 84 <ah_rfdigicali_config_rx_imb+0x84>
  20:	770f      	sexth      	r12, r3
  22:	c58c0023 	addu      	r3, r12, r12
  26:	60f0      	addu      	r3, r12
  28:	4362      	lsli      	r3, r3, 2
  2a:	608c      	addu      	r2, r3
  2c:	4242      	lsli      	r2, r2, 2
  2e:	116a      	lrw      	r3, 0x4001d000	// d4 <ah_rfdigicali_config_rx_imb+0xd4>
  30:	608c      	addu      	r2, r3
  32:	ea2cc010 	movih      	r12, 49168
  36:	9279      	ld.w      	r3, (r2, 0x64)
  38:	e58c1000 	subi      	r12, r12, 1
  3c:	68f0      	and      	r3, r12
  3e:	b279      	st.w      	r3, (r2, 0x64)
  40:	ea2c3ff0 	movih      	r12, 16368
  44:	9279      	ld.w      	r3, (r2, 0x64)
  46:	6830      	and      	r0, r12
  48:	6c0c      	or      	r0, r3
  4a:	b219      	st.w      	r0, (r2, 0x64)
  4c:	30ff      	movi      	r0, 255
  4e:	927f      	ld.w      	r3, (r2, 0x7c)
  50:	4018      	lsli      	r0, r0, 24
  52:	68c0      	and      	r3, r0
  54:	b27f      	st.w      	r3, (r2, 0x7c)
  56:	927f      	ld.w      	r3, (r2, 0x7c)
  58:	ea00fff0 	movi      	r0, 65520
  5c:	c5004900 	rotli      	r0, r0, 8
  60:	6b40      	and      	r13, r0
  62:	6c4c      	or      	r1, r3
  64:	6c74      	or      	r1, r13
  66:	b23f      	st.w      	r1, (r2, 0x7c)
  68:	107b      	lrw      	r3, 0x4001d000	// d4 <ah_rfdigicali_config_rx_imb+0xd4>
  6a:	9358      	ld.w      	r2, (r3, 0x60)
  6c:	ec420008 	ori      	r2, r2, 8
  70:	b358      	st.w      	r2, (r3, 0x60)
  72:	9358      	ld.w      	r2, (r3, 0x60)
  74:	e4422008 	andi      	r2, r2, 8
  78:	e922fffd 	bnez      	r2, 0x72	// 72 <ah_rfdigicali_config_rx_imb+0x72>
  7c:	783c      	jmp      	r15
  7e:	ea0c0fff 	movi      	r12, 4095
  82:	07c8      	br      	0x12	// 12 <ah_rfdigicali_config_rx_imb+0x12>
  84:	1074      	lrw      	r3, 0x4001d000	// d4 <ah_rfdigicali_config_rx_imb+0xd4>
  86:	4242      	lsli      	r2, r2, 2
  88:	608c      	addu      	r2, r3
  8a:	ea2cc010 	movih      	r12, 49168
  8e:	d8622049 	ld.w      	r3, (r2, 0x124)
  92:	e58c1000 	subi      	r12, r12, 1
  96:	68f0      	and      	r3, r12
  98:	dc622049 	st.w      	r3, (r2, 0x124)
  9c:	ea2c3ff0 	movih      	r12, 16368
  a0:	d8622049 	ld.w      	r3, (r2, 0x124)
  a4:	6830      	and      	r0, r12
  a6:	6c0c      	or      	r0, r3
  a8:	dc022049 	st.w      	r0, (r2, 0x124)
  ac:	30ff      	movi      	r0, 255
  ae:	d862204f 	ld.w      	r3, (r2, 0x13c)
  b2:	4018      	lsli      	r0, r0, 24
  b4:	68c0      	and      	r3, r0
  b6:	dc62204f 	st.w      	r3, (r2, 0x13c)
  ba:	d862204f 	ld.w      	r3, (r2, 0x13c)
  be:	6c4c      	or      	r1, r3
  c0:	ea03fff0 	movi      	r3, 65520
  c4:	c5034903 	rotli      	r3, r3, 8
  c8:	6b4c      	and      	r13, r3
  ca:	6c74      	or      	r1, r13
  cc:	dc22204f 	st.w      	r1, (r2, 0x13c)
  d0:	07cc      	br      	0x68	// 68 <ah_rfdigicali_config_rx_imb+0x68>
  d2:	0000      	.short	0x0000
  d4:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_tx_gain_idx_src:

00000000 <ah_rfdigicali_config_tx_gain_idx_src>:
   0:	1066      	lrw      	r3, 0x4001d000	// 18 <ah_rfdigicali_config_tx_gain_idx_src+0x18>
   2:	400f      	lsli      	r0, r0, 15
   4:	934b      	ld.w      	r2, (r3, 0x2c)
   6:	3a8f      	bclri      	r2, 15
   8:	b34b      	st.w      	r2, (r3, 0x2c)
   a:	934b      	ld.w      	r2, (r3, 0x2c)
   c:	c40055e0 	zext      	r0, r0, 15, 0
  10:	6c08      	or      	r0, r2
  12:	b30b      	st.w      	r0, (r3, 0x2c)
  14:	783c      	jmp      	r15
  16:	0000      	.short	0x0000
  18:	d000      	.short	0xd000
  1a:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_config_rx_gain_idx_src:

00000000 <ah_rfdigicali_config_rx_gain_idx_src>:
   0:	1066      	lrw      	r3, 0x4001d000	// 18 <ah_rfdigicali_config_rx_gain_idx_src+0x18>
   2:	4004      	lsli      	r0, r0, 4
   4:	9358      	ld.w      	r2, (r3, 0x60)
   6:	3a84      	bclri      	r2, 4
   8:	b358      	st.w      	r2, (r3, 0x60)
   a:	9358      	ld.w      	r2, (r3, 0x60)
   c:	e4002010 	andi      	r0, r0, 16
  10:	6c08      	or      	r0, r2
  12:	b318      	st.w      	r0, (r3, 0x60)
  14:	783c      	jmp      	r15
  16:	0000      	.short	0x0000
  18:	d000      	.short	0xd000
  1a:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_config_rx_filter:

00000000 <ah_rfdigicali_config_rx_filter>:
   0:	4001      	lsli      	r0, r0, 1
   2:	1047      	lrw      	r2, 0x4001d000	// 1c <ah_rfdigicali_config_rx_filter+0x1c>
   4:	3300      	movi      	r3, 0
   6:	e4002006 	andi      	r0, r0, 6
   a:	2b1f      	subi      	r3, 32
   c:	ec000011 	ori      	r0, r0, 17
  10:	dc622055 	st.w      	r3, (r2, 0x154)
  14:	dc022055 	st.w      	r0, (r2, 0x154)
  18:	783c      	jmp      	r15
  1a:	0000      	.short	0x0000
  1c:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_rx_filter_auto:

00000000 <ah_rfdigicali_config_rx_filter_auto>:
   0:	1045      	lrw      	r2, 0x4001d000	// 14 <ah_rfdigicali_config_rx_filter_auto+0x14>
   2:	3300      	movi      	r3, 0
   4:	2b19      	subi      	r3, 26
   6:	dc622055 	st.w      	r3, (r2, 0x154)
   a:	3319      	movi      	r3, 25
   c:	dc622055 	st.w      	r3, (r2, 0x154)
  10:	783c      	jmp      	r15
  12:	0000      	.short	0x0000
  14:	d000      	.short	0xd000
  16:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_get_rx_dcoc:

00000000 <ah_rfdigicali_get_rx_dcoc>:
   0:	3a03      	cmphsi      	r2, 4
   2:	0812      	bt      	0x26	// 26 <ah_rfdigicali_get_rx_dcoc+0x26>
   4:	74cb      	sexth      	r3, r2
   6:	5b4c      	addu      	r2, r3, r3
   8:	608c      	addu      	r2, r3
   a:	4242      	lsli      	r2, r2, 2
   c:	6048      	addu      	r1, r2
   e:	106c      	lrw      	r3, 0x4001d000	// 3c <ah_rfdigicali_get_rx_dcoc+0x3c>
  10:	4122      	lsli      	r1, r1, 2
  12:	604c      	addu      	r1, r3
  14:	9179      	ld.w      	r3, (r1, 0x64)
  16:	e46323ff 	andi      	r3, r3, 1023
  1a:	a860      	st.h      	r3, (r0, 0x0)
  1c:	9179      	ld.w      	r3, (r1, 0x64)
  1e:	c5435663 	zext      	r3, r3, 19, 10
  22:	a861      	st.h      	r3, (r0, 0x2)
  24:	783c      	jmp      	r15
  26:	1066      	lrw      	r3, 0x4001d000	// 3c <ah_rfdigicali_get_rx_dcoc+0x3c>
  28:	4122      	lsli      	r1, r1, 2
  2a:	604c      	addu      	r1, r3
  2c:	d8612049 	ld.w      	r3, (r1, 0x124)
  30:	e46323ff 	andi      	r3, r3, 1023
  34:	a860      	st.h      	r3, (r0, 0x0)
  36:	d8612049 	ld.w      	r3, (r1, 0x124)
  3a:	07f2      	br      	0x1e	// 1e <ah_rfdigicali_get_rx_dcoc+0x1e>
  3c:	d000      	.short	0xd000
  3e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_get_rx_imb:

00000000 <ah_rfdigicali_get_rx_imb>:
   0:	3b03      	cmphsi      	r3, 4
   2:	0813      	bt      	0x28	// 28 <ah_rfdigicali_get_rx_imb+0x28>
   4:	770f      	sexth      	r12, r3
   6:	c58c0023 	addu      	r3, r12, r12
   a:	60f0      	addu      	r3, r12
   c:	4362      	lsli      	r3, r3, 2
   e:	608c      	addu      	r2, r3
  10:	4242      	lsli      	r2, r2, 2
  12:	106c      	lrw      	r3, 0x4001d000	// 40 <ah_rfdigicali_get_rx_imb+0x40>
  14:	608c      	addu      	r2, r3
  16:	9279      	ld.w      	r3, (r2, 0x64)
  18:	c68357a3 	zext      	r3, r3, 29, 20
  1c:	a860      	st.h      	r3, (r0, 0x0)
  1e:	927f      	ld.w      	r3, (r2, 0x7c)
  20:	e4632fff 	andi      	r3, r3, 4095
  24:	a960      	st.h      	r3, (r1, 0x0)
  26:	783c      	jmp      	r15
  28:	1066      	lrw      	r3, 0x4001d000	// 40 <ah_rfdigicali_get_rx_imb+0x40>
  2a:	4242      	lsli      	r2, r2, 2
  2c:	608c      	addu      	r2, r3
  2e:	d8622049 	ld.w      	r3, (r2, 0x124)
  32:	c68357a3 	zext      	r3, r3, 29, 20
  36:	a860      	st.h      	r3, (r0, 0x0)
  38:	d862204f 	ld.w      	r3, (r2, 0x13c)
  3c:	07f2      	br      	0x20	// 20 <ah_rfdigicali_get_rx_imb+0x20>
  3e:	0000      	.short	0x0000
  40:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_get_tx_digi_gain:

00000000 <ah_rfdigicali_get_tx_digi_gain>:
   0:	3804      	cmphsi      	r0, 5
   2:	1064      	lrw      	r3, 0x4001d000	// 10 <ah_rfdigicali_get_tx_digi_gain+0x10>
   4:	081d      	bt      	0x3e	// 3e <ah_rfdigicali_get_tx_digi_gain+0x3e>
   6:	1044      	lrw      	r2, 0x0	// 14 <ah_rfdigicali_get_tx_digi_gain+0x14>
   8:	d0020882 	ldr.w      	r2, (r2, r0 << 2)
   c:	7808      	jmp      	r2
   e:	0000      	.short	0x0000
  10:	d000      	.short	0xd000
  12:	4001      	.short	0x4001
  14:	0000      	.short	0x0000
  16:	0000      	.short	0x0000
  18:	d8032056 	ld.w      	r0, (r3, 0x158)
  1c:	e40027ff 	andi      	r0, r0, 2047
  20:	783c      	jmp      	r15
  22:	d8032056 	ld.w      	r0, (r3, 0x158)
  26:	c6005740 	zext      	r0, r0, 26, 16
  2a:	07fb      	br      	0x20	// 20 <ah_rfdigicali_get_tx_digi_gain+0x20>
  2c:	d8032057 	ld.w      	r0, (r3, 0x15c)
  30:	07f6      	br      	0x1c	// 1c <ah_rfdigicali_get_tx_digi_gain+0x1c>
  32:	d8032057 	ld.w      	r0, (r3, 0x15c)
  36:	07f8      	br      	0x26	// 26 <ah_rfdigicali_get_tx_digi_gain+0x26>
  38:	d8032058 	ld.w      	r0, (r3, 0x160)
  3c:	07f0      	br      	0x1c	// 1c <ah_rfdigicali_get_tx_digi_gain+0x1c>
  3e:	d8032058 	ld.w      	r0, (r3, 0x160)
  42:	07f2      	br      	0x26	// 26 <ah_rfdigicali_get_tx_digi_gain+0x26>

Disassembly of section .text.ah_rfdigicali_cfg_fb_comp:

00000000 <ah_rfdigicali_cfg_fb_comp>:
   0:	106f      	lrw      	r3, 0x4001d000	// 3c <ah_rfdigicali_cfg_fb_comp+0x3c>
   2:	9344      	ld.w      	r2, (r3, 0x10)
   4:	3a99      	bclri      	r2, 25
   6:	b344      	st.w      	r2, (r3, 0x10)
   8:	9358      	ld.w      	r2, (r3, 0x60)
   a:	e9200011 	bnez      	r0, 0x2c	// 2c <ah_rfdigicali_cfg_fb_comp+0x2c>
   e:	3a8a      	bclri      	r2, 10
  10:	b358      	st.w      	r2, (r3, 0x60)
  12:	d8432055 	ld.w      	r2, (r3, 0x154)
  16:	3a80      	bclri      	r2, 0
  18:	dc432055 	st.w      	r2, (r3, 0x154)
  1c:	1048      	lrw      	r2, 0x4001d000	// 3c <ah_rfdigicali_cfg_fb_comp+0x3c>
  1e:	d8622055 	ld.w      	r3, (r2, 0x154)
  22:	ec630010 	ori      	r3, r3, 16
  26:	dc622055 	st.w      	r3, (r2, 0x154)
  2a:	783c      	jmp      	r15
  2c:	ec420400 	ori      	r2, r2, 1024
  30:	b358      	st.w      	r2, (r3, 0x60)
  32:	d8432055 	ld.w      	r2, (r3, 0x154)
  36:	ec420001 	ori      	r2, r2, 1
  3a:	07ef      	br      	0x18	// 18 <ah_rfdigicali_cfg_fb_comp+0x18>
  3c:	d000      	.short	0xd000
  3e:	4001      	.short	0x4001
