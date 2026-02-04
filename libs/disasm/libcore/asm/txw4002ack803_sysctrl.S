
disasm/libcore/obj/txw4002ack803_sysctrl.o:     file format elf32-csky-little


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

Disassembly of section .text.__sysctrl_delay_asm:

00000000 <__sysctrl_delay_asm>:
   0:	c4201020 	decgt      	r0, r0, 1
   4:	e860fffe 	bt      	0x0	// 0 <__sysctrl_delay_asm>
   8:	783c      	jmp      	r15

Disassembly of section .text.pmu_pd_lvd_vcc_vol_set_sec:

00000000 <pmu_pd_lvd_vcc_vol_set_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	ea023800 	movi      	r2, 14336
   e:	6c8a      	nor      	r2, r2
  10:	9360      	ld.w      	r3, (r3, 0x0)
  12:	68c8      	and      	r3, r2
  14:	402b      	lsli      	r1, r0, 11
  16:	6c4c      	or      	r1, r3
  18:	3000      	movi      	r0, 0
  1a:	e0000000 	bsr      	0x0	// 0 <pmu_pd_lvd_vcc_vol_set_sec>
  1e:	1490      	pop      	r15

Disassembly of section .text.pmu_vdd13a_lpwr_det_vol_set:

00000000 <pmu_vdd13a_lpwr_det_vol_set>:
   0:	ea028003 	movi      	r2, 32771
   4:	c5e24902 	rotli      	r2, r2, 15
   8:	4005      	lsli      	r0, r0, 5
   a:	9260      	ld.w      	r3, (r2, 0x0)
   c:	3b85      	bclri      	r3, 5
   e:	3b86      	bclri      	r3, 6
  10:	e4002060 	andi      	r0, r0, 96
  14:	6c0c      	or      	r0, r3
  16:	b200      	st.w      	r0, (r2, 0x0)
  18:	783c      	jmp      	r15

Disassembly of section .text.pmu_vdd13d_lpwr_det_vol_set:

00000000 <pmu_vdd13d_lpwr_det_vol_set>:
   0:	ea028003 	movi      	r2, 32771
   4:	c5e24902 	rotli      	r2, r2, 15
   8:	4007      	lsli      	r0, r0, 7
   a:	9260      	ld.w      	r3, (r2, 0x0)
   c:	3b87      	bclri      	r3, 7
   e:	3b88      	bclri      	r3, 8
  10:	e4002180 	andi      	r0, r0, 384
  14:	6c0c      	or      	r0, r3
  16:	b200      	st.w      	r0, (r2, 0x0)
  18:	783c      	jmp      	r15

Disassembly of section .text.pmu_vdd_lpwr_det_vol_set:

00000000 <pmu_vdd_lpwr_det_vol_set>:
   0:	ea028003 	movi      	r2, 32771
   4:	c5e24902 	rotli      	r2, r2, 15
   8:	4009      	lsli      	r0, r0, 9
   a:	9260      	ld.w      	r3, (r2, 0x0)
   c:	3b89      	bclri      	r3, 9
   e:	3b8a      	bclri      	r3, 10
  10:	e4002600 	andi      	r0, r0, 1536
  14:	6c0c      	or      	r0, r3
  16:	b200      	st.w      	r0, (r2, 0x0)
  18:	783c      	jmp      	r15

Disassembly of section .text.pmu_vcca_lpwr_det_vol_set:

00000000 <pmu_vcca_lpwr_det_vol_set>:
   0:	ea028003 	movi      	r2, 32771
   4:	c5e24902 	rotli      	r2, r2, 15
   8:	ea013800 	movi      	r1, 14336
   c:	6c46      	nor      	r1, r1
   e:	9260      	ld.w      	r3, (r2, 0x0)
  10:	68c4      	and      	r3, r1
  12:	31e0      	movi      	r1, 224
  14:	4126      	lsli      	r1, r1, 6
  16:	400b      	lsli      	r0, r0, 11
  18:	6804      	and      	r0, r1
  1a:	6c0c      	or      	r0, r3
  1c:	b200      	st.w      	r0, (r2, 0x0)
  1e:	783c      	jmp      	r15

Disassembly of section .text.pmu_vdd_oc_det_cur_set:

00000000 <pmu_vdd_oc_det_cur_set>:
   0:	ea028003 	movi      	r2, 32771
   4:	c5e24902 	rotli      	r2, r2, 15
   8:	400e      	lsli      	r0, r0, 14
   a:	9260      	ld.w      	r3, (r2, 0x0)
   c:	3b8e      	bclri      	r3, 14
   e:	3b8f      	bclri      	r3, 15
  10:	c40055e0 	zext      	r0, r0, 15, 0
  14:	6c0c      	or      	r0, r3
  16:	b200      	st.w      	r0, (r2, 0x0)
  18:	783c      	jmp      	r15

Disassembly of section .text.pmu_vdd_vol_set_sec:

00000000 <pmu_vdd_vol_set_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	ea020700 	movi      	r2, 1792
   e:	6c8a      	nor      	r2, r2
  10:	9368      	ld.w      	r3, (r3, 0x20)
  12:	68c8      	and      	r3, r2
  14:	4028      	lsli      	r1, r0, 8
  16:	6c4c      	or      	r1, r3
  18:	3020      	movi      	r0, 32
  1a:	e0000000 	bsr      	0x0	// 0 <pmu_vdd_vol_set_sec>
  1e:	1490      	pop      	r15

Disassembly of section .text.pmu_vdd13b_vol_set_sec:

00000000 <pmu_vdd13b_vol_set_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	ea22ffc8 	movih      	r2, 65480
   e:	2a00      	subi      	r2, 1
  10:	9368      	ld.w      	r3, (r3, 0x20)
  12:	68c8      	and      	r3, r2
  14:	4033      	lsli      	r1, r0, 19
  16:	6c4c      	or      	r1, r3
  18:	3020      	movi      	r0, 32
  1a:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13b_vol_set_sec>
  1e:	1490      	pop      	r15

Disassembly of section .text.pmu_vdd13c_vol_set_sec:

00000000 <pmu_vdd13c_vol_set_sec>:
   0:	14d1      	push      	r4, r15
   2:	ea048003 	movi      	r4, 32771
   6:	c5e44904 	rotli      	r4, r4, 15
   a:	ea22fe40 	movih      	r2, 65088
   e:	2a00      	subi      	r2, 1
  10:	9468      	ld.w      	r3, (r4, 0x20)
  12:	68c8      	and      	r3, r2
  14:	4036      	lsli      	r1, r0, 22
  16:	6c4c      	or      	r1, r3
  18:	3020      	movi      	r0, 32
  1a:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13c_vol_set_sec>
  1e:	9428      	ld.w      	r1, (r4, 0x20)
  20:	39b9      	bseti      	r1, 25
  22:	3020      	movi      	r0, 32
  24:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13c_vol_set_sec>
  28:	1491      	pop      	r4, r15

Disassembly of section .text.pmu_vdd_ldo_bias_cur_set:

00000000 <pmu_vdd_ldo_bias_cur_set>:
   0:	ea028003 	movi      	r2, 32771
   4:	c5e24902 	rotli      	r2, r2, 15
   8:	3100      	movi      	r1, 0
   a:	9268      	ld.w      	r3, (r2, 0x20)
   c:	29e0      	subi      	r1, 225
   e:	4005      	lsli      	r0, r0, 5
  10:	68c4      	and      	r3, r1
  12:	e40020ff 	andi      	r0, r0, 255
  16:	6c0c      	or      	r0, r3
  18:	b208      	st.w      	r0, (r2, 0x20)
  1a:	783c      	jmp      	r15

Disassembly of section .text.pmu_tsensor_chan_sel_sec:

00000000 <pmu_tsensor_chan_sel_sec>:
   0:	14d0      	push      	r15
   2:	3803      	cmphsi      	r0, 4
   4:	080d      	bt      	0x1e	// 1e <pmu_tsensor_chan_sel_sec+0x1e>
   6:	ea038003 	movi      	r3, 32771
   a:	c5e34903 	rotli      	r3, r3, 15
   e:	400b      	lsli      	r0, r0, 11
  10:	9328      	ld.w      	r1, (r3, 0x20)
  12:	398b      	bclri      	r1, 11
  14:	398c      	bclri      	r1, 12
  16:	6c40      	or      	r1, r0
  18:	3020      	movi      	r0, 32
  1a:	e0000000 	bsr      	0x0	// 0 <pmu_tsensor_chan_sel_sec>
  1e:	1490      	pop      	r15

Disassembly of section .text.pmu_vref_vol_set_sec:

00000000 <pmu_vref_vol_set_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	ea02e000 	movi      	r2, 57344
   e:	6c8a      	nor      	r2, r2
  10:	9368      	ld.w      	r3, (r3, 0x20)
  12:	68c8      	and      	r3, r2
  14:	402d      	lsli      	r1, r0, 13
  16:	6c4c      	or      	r1, r3
  18:	3020      	movi      	r0, 32
  1a:	e0000000 	bsr      	0x0	// 0 <pmu_vref_vol_set_sec>
  1e:	1490      	pop      	r15

Disassembly of section .text.pmu_vccmipi_vol_set_sec:

00000000 <pmu_vccmipi_vol_set_sec>:
   0:	14d0      	push      	r15
   2:	3803      	cmphsi      	r0, 4
   4:	ea038003 	movi      	r3, 32771
   8:	c5e34903 	rotli      	r3, r3, 15
   c:	9328      	ld.w      	r1, (r3, 0x20)
   e:	080b      	bt      	0x24	// 24 <pmu_vccmipi_vol_set_sec+0x24>
  10:	ea23fbf9 	movih      	r3, 64505
  14:	2b00      	subi      	r3, 1
  16:	684c      	and      	r1, r3
  18:	4010      	lsli      	r0, r0, 16
  1a:	6c40      	or      	r1, r0
  1c:	3020      	movi      	r0, 32
  1e:	e0000000 	bsr      	0x0	// 0 <pmu_vccmipi_vol_set_sec>
  22:	1490      	pop      	r15
  24:	39ba      	bseti      	r1, 26
  26:	07fb      	br      	0x1c	// 1c <pmu_vccmipi_vol_set_sec+0x1c>

Disassembly of section .text.pmu_vdd13_ldo_dis_sec:

00000000 <pmu_vdd13_ldo_dis_sec>:
   0:	14d1      	push      	r4, r15
   2:	ea048003 	movi      	r4, 32771
   6:	c5e44904 	rotli      	r4, r4, 15
   a:	ea23fe40 	movih      	r3, 65088
   e:	9428      	ld.w      	r1, (r4, 0x20)
  10:	2b00      	subi      	r3, 1
  12:	684c      	and      	r1, r3
  14:	3020      	movi      	r0, 32
  16:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13_ldo_dis_sec>
  1a:	ea23ffc8 	movih      	r3, 65480
  1e:	2b00      	subi      	r3, 1
  20:	9428      	ld.w      	r1, (r4, 0x20)
  22:	684c      	and      	r1, r3
  24:	3020      	movi      	r0, 32
  26:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13_ldo_dis_sec>
  2a:	9428      	ld.w      	r1, (r4, 0x20)
  2c:	3999      	bclri      	r1, 25
  2e:	3020      	movi      	r0, 32
  30:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13_ldo_dis_sec>
  34:	1491      	pop      	r4, r15

Disassembly of section .text.pmu_xo_vbg_set_sec:

00000000 <pmu_xo_vbg_set_sec>:
   0:	14d0      	push      	r15
   2:	3807      	cmphsi      	r0, 8
   4:	080e      	bt      	0x20	// 20 <pmu_xo_vbg_set_sec+0x20>
   6:	ea038003 	movi      	r3, 32771
   a:	c5e34903 	rotli      	r3, r3, 15
   e:	4004      	lsli      	r0, r0, 4
  10:	932b      	ld.w      	r1, (r3, 0x2c)
  12:	3300      	movi      	r3, 0
  14:	2b70      	subi      	r3, 113
  16:	684c      	and      	r1, r3
  18:	6c40      	or      	r1, r0
  1a:	302c      	movi      	r0, 44
  1c:	e0000000 	bsr      	0x0	// 0 <pmu_xo_vbg_set_sec>
  20:	1490      	pop      	r15

Disassembly of section .text.pmu_test_chan_sel:

00000000 <pmu_test_chan_sel>:
   0:	ea028003 	movi      	r2, 32771
   4:	c5e24902 	rotli      	r2, r2, 15
   8:	401c      	lsli      	r0, r0, 28
   a:	9268      	ld.w      	r3, (r2, 0x20)
   c:	c4035763 	zext      	r3, r3, 27, 0
  10:	6c0c      	or      	r0, r3
  12:	b208      	st.w      	r0, (r2, 0x20)
  14:	783c      	jmp      	r15

Disassembly of section .text.pmu_pd_alwayson_clk_cfg_sel:

00000000 <pmu_pd_alwayson_clk_cfg_sel>:
   0:	ea028003 	movi      	r2, 32771
   4:	c5e24902 	rotli      	r2, r2, 15
   8:	4006      	lsli      	r0, r0, 6
   a:	9264      	ld.w      	r3, (r2, 0x10)
   c:	3b86      	bclri      	r3, 6
   e:	3b87      	bclri      	r3, 7
  10:	e40020ff 	andi      	r0, r0, 255
  14:	6c0c      	or      	r0, r3
  16:	b204      	st.w      	r0, (r2, 0x10)
  18:	783c      	jmp      	r15

Disassembly of section .text.pmu_pd_alwayson_clk_cfg_sel_sec:

00000000 <pmu_pd_alwayson_clk_cfg_sel_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	4026      	lsli      	r1, r0, 6
   c:	9364      	ld.w      	r3, (r3, 0x10)
   e:	3b86      	bclri      	r3, 6
  10:	3b87      	bclri      	r3, 7
  12:	6c4c      	or      	r1, r3
  14:	3010      	movi      	r0, 16
  16:	e0000000 	bsr      	0x0	// 0 <pmu_pd_alwayson_clk_cfg_sel_sec>
  1a:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_timer_trim_time_unit_set:

00000000 <pmu_pd_timer_trim_time_unit_set>:
   0:	33fa      	movi      	r3, 250
   2:	4367      	lsli      	r3, r3, 7
   4:	7c0c      	mult      	r0, r3
   6:	ea018003 	movi      	r1, 32771
   a:	c5e14901 	rotli      	r1, r1, 15
   e:	2800      	subi      	r0, 1
  10:	c6c05023 	bmaski      	r3, 23
  14:	2b00      	subi      	r3, 1
  16:	6000      	addu      	r0, r0
  18:	d8412023 	ld.w      	r2, (r1, 0x8c)
  1c:	680c      	and      	r0, r3
  1e:	ea03ffc0 	movi      	r3, 65472
  22:	c6234903 	rotli      	r3, r3, 17
  26:	688c      	and      	r2, r3
  28:	6c08      	or      	r0, r2
  2a:	dc012023 	st.w      	r0, (r1, 0x8c)
  2e:	783c      	jmp      	r15

Disassembly of section .text.pmu_pd_timer_trim_time_unit_set_sec:

00000000 <pmu_pd_timer_trim_time_unit_set_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	d8232023 	ld.w      	r1, (r3, 0x8c)
   e:	ea03ffc0 	movi      	r3, 65472
  12:	c6234903 	rotli      	r3, r3, 17
  16:	684c      	and      	r1, r3
  18:	33fa      	movi      	r3, 250
  1a:	4367      	lsli      	r3, r3, 7
  1c:	7c0c      	mult      	r0, r3
  1e:	2800      	subi      	r0, 1
  20:	c6c05023 	bmaski      	r3, 23
  24:	2b00      	subi      	r3, 1
  26:	6000      	addu      	r0, r0
  28:	680c      	and      	r0, r3
  2a:	6c40      	or      	r1, r0
  2c:	308c      	movi      	r0, 140
  2e:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_trim_time_unit_set_sec>
  32:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_rc256k_sw_trim_en_sec:

00000000 <pmu_pd_rc256k_sw_trim_en_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	308c      	movi      	r0, 140
   c:	d8232023 	ld.w      	r1, (r3, 0x8c)
  10:	ec210001 	ori      	r1, r1, 1
  14:	e0000000 	bsr      	0x0	// 0 <pmu_pd_rc256k_sw_trim_en_sec>
  18:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_rc256k_hw_trim_en_sec:

00000000 <pmu_pd_rc256k_hw_trim_en_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3010      	movi      	r0, 16
   c:	9324      	ld.w      	r1, (r3, 0x10)
   e:	39b1      	bseti      	r1, 17
  10:	e0000000 	bsr      	0x0	// 0 <pmu_pd_rc256k_hw_trim_en_sec>
  14:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_timer_clk_sel_256k_sec:

00000000 <pmu_pd_timer_clk_sel_256k_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3010      	movi      	r0, 16
   c:	9324      	ld.w      	r1, (r3, 0x10)
   e:	398f      	bclri      	r1, 15
  10:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_clk_sel_256k_sec>
  14:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_pwr_down_osc_en_sec:

00000000 <pmu_pd_pwr_down_osc_en_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3010      	movi      	r0, 16
   c:	9324      	ld.w      	r1, (r3, 0x10)
   e:	39b2      	bseti      	r1, 18
  10:	e0000000 	bsr      	0x0	// 0 <pmu_pd_pwr_down_osc_en_sec>
  14:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_timer_timeout_set:

00000000 <pmu_pd_timer_timeout_set>:
   0:	ea028003 	movi      	r2, 32771
   4:	c5e24902 	rotli      	r2, r2, 15
   8:	d8622023 	ld.w      	r3, (r2, 0x8c)
   c:	d8222021 	ld.w      	r1, (r2, 0x84)
  10:	c40155e1 	zext      	r1, r1, 15, 0
  14:	d9822021 	ld.w      	r12, (r2, 0x84)
  18:	6c70      	or      	r1, r12
  1a:	c42356c3 	zext      	r3, r3, 22, 1
  1e:	ea0c00fa 	movi      	r12, 250
  22:	c4ec482c 	lsli      	r12, r12, 7
  26:	2300      	addi      	r3, 1
  28:	c5838023 	divu      	r3, r3, r12
  2c:	dc222021 	st.w      	r1, (r2, 0x84)
  30:	c4608023 	divu      	r3, r0, r3
  34:	30e0      	movi      	r0, 224
  36:	d8222022 	ld.w      	r1, (r2, 0x88)
  3a:	4018      	lsli      	r0, r0, 24
  3c:	2b00      	subi      	r3, 1
  3e:	6840      	and      	r1, r0
  40:	c4035783 	zext      	r3, r3, 28, 0
  44:	6cc4      	or      	r3, r1
  46:	dc622022 	st.w      	r3, (r2, 0x88)
  4a:	783c      	jmp      	r15

Disassembly of section .text.pmu_pd_timer_timeout_set_sec:

00000000 <pmu_pd_timer_timeout_set_sec>:
   0:	14d3      	push      	r4-r6, r15
   2:	ea068003 	movi      	r6, 32771
   6:	c5e64906 	rotli      	r6, r6, 15
   a:	6d03      	mov      	r4, r0
   c:	d8a62023 	ld.w      	r5, (r6, 0x8c)
  10:	3084      	movi      	r0, 132
  12:	d8262021 	ld.w      	r1, (r6, 0x84)
  16:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_timeout_set_sec>
  1a:	33e0      	movi      	r3, 224
  1c:	d8262022 	ld.w      	r1, (r6, 0x88)
  20:	4378      	lsli      	r3, r3, 24
  22:	684c      	and      	r1, r3
  24:	c42556c5 	zext      	r5, r5, 22, 1
  28:	33fa      	movi      	r3, 250
  2a:	4367      	lsli      	r3, r3, 7
  2c:	2500      	addi      	r5, 1
  2e:	c4658025 	divu      	r5, r5, r3
  32:	c4a48024 	divu      	r4, r4, r5
  36:	2c00      	subi      	r4, 1
  38:	c4045784 	zext      	r4, r4, 28, 0
  3c:	6c50      	or      	r1, r4
  3e:	3088      	movi      	r0, 136
  40:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_timeout_set_sec>
  44:	1493      	pop      	r4-r6, r15

Disassembly of section .text.pmu_pd_xosc_pre_coarse_set:

00000000 <pmu_pd_xosc_pre_coarse_set>:
   0:	ea028003 	movi      	r2, 32771
   4:	c5e24902 	rotli      	r2, r2, 15
   8:	401d      	lsli      	r0, r0, 29
   a:	d8622022 	ld.w      	r3, (r2, 0x88)
   e:	c4035783 	zext      	r3, r3, 28, 0
  12:	6cc0      	or      	r3, r0
  14:	dc622022 	st.w      	r3, (r2, 0x88)
  18:	783c      	jmp      	r15

Disassembly of section .text.pmu_pd_xosc_pre_coarse_set_sec:

00000000 <pmu_pd_xosc_pre_coarse_set_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	403d      	lsli      	r1, r0, 29
   c:	d8632022 	ld.w      	r3, (r3, 0x88)
  10:	c4035783 	zext      	r3, r3, 28, 0
  14:	6c4c      	or      	r1, r3
  16:	3088      	movi      	r0, 136
  18:	e0000000 	bsr      	0x0	// 0 <pmu_pd_xosc_pre_coarse_set_sec>
  1c:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_xosc_pre_fine_set:

00000000 <pmu_pd_xosc_pre_fine_set>:
   0:	ea028003 	movi      	r2, 32771
   4:	c5e24902 	rotli      	r2, r2, 15
   8:	4016      	lsli      	r0, r0, 22
   a:	9264      	ld.w      	r3, (r2, 0x10)
   c:	c40356a3 	zext      	r3, r3, 21, 0
  10:	6cc0      	or      	r3, r0
  12:	b264      	st.w      	r3, (r2, 0x10)
  14:	783c      	jmp      	r15

Disassembly of section .text.pmu_pd_xosc_pre_fine_set_sec:

00000000 <pmu_pd_xosc_pre_fine_set_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	4036      	lsli      	r1, r0, 22
   c:	9364      	ld.w      	r3, (r3, 0x10)
   e:	c40356a3 	zext      	r3, r3, 21, 0
  12:	6c4c      	or      	r1, r3
  14:	3010      	movi      	r0, 16
  16:	e0000000 	bsr      	0x0	// 0 <pmu_pd_xosc_pre_fine_set_sec>
  1a:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_timer_irq_en_sec:

00000000 <pmu_pd_timer_irq_en_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3080      	movi      	r0, 128
   c:	d8232020 	ld.w      	r1, (r3, 0x80)
  10:	ec210010 	ori      	r1, r1, 16
  14:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_irq_en_sec>
  18:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_timer_en_sec:

00000000 <pmu_pd_timer_en_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3080      	movi      	r0, 128
   c:	d8232020 	ld.w      	r1, (r3, 0x80)
  10:	ec210001 	ori      	r1, r1, 1
  14:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_en_sec>
  18:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_io_wkup_sel_pin:

00000000 <pmu_pd_io_wkup_sel_pin>:
   0:	eb000031 	cmphsi      	r0, 50
   4:	0810      	bt      	0x24	// 24 <pmu_pd_io_wkup_sel_pin+0x24>
   6:	ea028003 	movi      	r2, 32771
   a:	c5e24902 	rotli      	r2, r2, 15
   e:	3100      	movi      	r1, 0
  10:	d8622028 	ld.w      	r3, (r2, 0xa0)
  14:	29fc      	subi      	r1, 253
  16:	68c4      	and      	r3, r1
  18:	4002      	lsli      	r0, r0, 2
  1a:	6c0c      	or      	r0, r3
  1c:	dc022028 	st.w      	r0, (r2, 0xa0)
  20:	3000      	movi      	r0, 0
  22:	783c      	jmp      	r15
  24:	3000      	movi      	r0, 0
  26:	2815      	subi      	r0, 22
  28:	07fd      	br      	0x22	// 22 <pmu_pd_io_wkup_sel_pin+0x22>

Disassembly of section .text.pmu_pd_io_wkup_sel_pin_sec:

00000000 <pmu_pd_io_wkup_sel_pin_sec>:
   0:	14d0      	push      	r15
   2:	eb000033 	cmphsi      	r0, 52
   6:	0811      	bt      	0x28	// 28 <pmu_pd_io_wkup_sel_pin_sec+0x28>
   8:	ea038003 	movi      	r3, 32771
   c:	c5e34903 	rotli      	r3, r3, 15
  10:	4002      	lsli      	r0, r0, 2
  12:	d8232028 	ld.w      	r1, (r3, 0xa0)
  16:	3300      	movi      	r3, 0
  18:	2bfc      	subi      	r3, 253
  1a:	684c      	and      	r1, r3
  1c:	6c40      	or      	r1, r0
  1e:	30a0      	movi      	r0, 160
  20:	e0000000 	bsr      	0x0	// 0 <pmu_pd_io_wkup_sel_pin_sec>
  24:	3000      	movi      	r0, 0
  26:	1490      	pop      	r15
  28:	3000      	movi      	r0, 0
  2a:	2815      	subi      	r0, 22
  2c:	07fd      	br      	0x26	// 26 <pmu_pd_io_wkup_sel_pin_sec+0x26>

Disassembly of section .text.jtag_map_set:

00000000 <jtag_map_set>:
   0:	14d1      	push      	r4, r15
   2:	3808      	cmphsi      	r0, 9
   4:	0817      	bt      	0x32	// 32 <jtag_map_set+0x32>
   6:	ea040117 	movi      	r4, 279
   a:	7101      	lsr      	r4, r0
   c:	6d12      	nor      	r4, r4
   e:	e4842001 	andi      	r4, r4, 1
  12:	e9240010 	bnez      	r4, 0x32	// 32 <jtag_map_set+0x32>
  16:	ea038003 	movi      	r3, 32771
  1a:	c5e34903 	rotli      	r3, r3, 15
  1e:	932e      	ld.w      	r1, (r3, 0x38)
  20:	3300      	movi      	r3, 0
  22:	2b0f      	subi      	r3, 16
  24:	684c      	and      	r1, r3
  26:	6c40      	or      	r1, r0
  28:	3038      	movi      	r0, 56
  2a:	e0000000 	bsr      	0x0	// 0 <jtag_map_set>
  2e:	6c13      	mov      	r0, r4
  30:	1491      	pop      	r4, r15
  32:	3000      	movi      	r0, 0
  34:	2815      	subi      	r0, 22
  36:	07fd      	br      	0x30	// 30 <jtag_map_set+0x30>

Disassembly of section .text.pmu_vdd13a_stable_delay:

00000000 <pmu_vdd13a_stable_delay>:
   0:	eb0001ff 	cmphsi      	r0, 512
   4:	0812      	bt      	0x28	// 28 <pmu_vdd13a_stable_delay+0x28>
   6:	ea028003 	movi      	r2, 32771
   a:	c5e24902 	rotli      	r2, r2, 15
   e:	ea011ff0 	movi      	r1, 8176
  12:	4004      	lsli      	r0, r0, 4
  14:	926e      	ld.w      	r3, (r2, 0x38)
  16:	6804      	and      	r0, r1
  18:	ea011ff0 	movi      	r1, 8176
  1c:	6c46      	nor      	r1, r1
  1e:	68c4      	and      	r3, r1
  20:	6c0c      	or      	r0, r3
  22:	b20e      	st.w      	r0, (r2, 0x38)
  24:	3000      	movi      	r0, 0
  26:	783c      	jmp      	r15
  28:	3000      	movi      	r0, 0
  2a:	2815      	subi      	r0, 22
  2c:	07fd      	br      	0x26	// 26 <pmu_vdd13a_stable_delay+0x26>

Disassembly of section .text.pmu_vdd13a_stable_delay_sec:

00000000 <pmu_vdd13a_stable_delay_sec>:
   0:	14d0      	push      	r15
   2:	eb0001ff 	cmphsi      	r0, 512
   6:	0811      	bt      	0x28	// 28 <pmu_vdd13a_stable_delay_sec+0x28>
   8:	ea038003 	movi      	r3, 32771
   c:	c5e34903 	rotli      	r3, r3, 15
  10:	4004      	lsli      	r0, r0, 4
  12:	932e      	ld.w      	r1, (r3, 0x38)
  14:	ea031ff0 	movi      	r3, 8176
  18:	6cce      	nor      	r3, r3
  1a:	684c      	and      	r1, r3
  1c:	6c40      	or      	r1, r0
  1e:	3038      	movi      	r0, 56
  20:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13a_stable_delay_sec>
  24:	3000      	movi      	r0, 0
  26:	1490      	pop      	r15
  28:	3000      	movi      	r0, 0
  2a:	2815      	subi      	r0, 22
  2c:	07fd      	br      	0x26	// 26 <pmu_vdd13a_stable_delay_sec+0x26>

Disassembly of section .text.pmu_pd_timer_clear_pnd_sec:

00000000 <pmu_pd_timer_clear_pnd_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3080      	movi      	r0, 128
   c:	d8232020 	ld.w      	r1, (r3, 0x80)
  10:	3982      	bclri      	r1, 2
  12:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_clear_pnd_sec>
  16:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_timer_clear_pnd1_sec:

00000000 <pmu_pd_timer_clear_pnd1_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3080      	movi      	r0, 128
   c:	d8232020 	ld.w      	r1, (r3, 0x80)
  10:	3983      	bclri      	r1, 3
  12:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_clear_pnd1_sec>
  16:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_clear_core_pd_pnd_sec:

00000000 <pmu_pd_clear_core_pd_pnd_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	301c      	movi      	r0, 28
   c:	9327      	ld.w      	r1, (r3, 0x1c)
   e:	3987      	bclri      	r1, 7
  10:	e0000000 	bsr      	0x0	// 0 <pmu_pd_clear_core_pd_pnd_sec>
  14:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_clear_pd_pnd_sec:

00000000 <pmu_pd_clear_pd_pnd_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	301c      	movi      	r0, 28
   c:	9327      	ld.w      	r1, (r3, 0x1c)
   e:	398f      	bclri      	r1, 15
  10:	e0000000 	bsr      	0x0	// 0 <pmu_pd_clear_pd_pnd_sec>
  14:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_clear_rf_pd_pnd_sec:

00000000 <pmu_pd_clear_rf_pd_pnd_sec>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <pmu_pd_clear_rf_pd_pnd_sec>
   6:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_rf_latch_cpu_by_hw_sec:

00000000 <pmu_pd_rf_latch_cpu_by_hw_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	301c      	movi      	r0, 28
   c:	9327      	ld.w      	r1, (r3, 0x1c)
   e:	39b0      	bseti      	r1, 16
  10:	e0000000 	bsr      	0x0	// 0 <pmu_pd_rf_latch_cpu_by_hw_sec>
  14:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_io_latch_cpu_by_hw_sec:

00000000 <pmu_pd_io_latch_cpu_by_hw_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	301c      	movi      	r0, 28
   c:	9327      	ld.w      	r1, (r3, 0x1c)
   e:	39b1      	bseti      	r1, 17
  10:	e0000000 	bsr      	0x0	// 0 <pmu_pd_io_latch_cpu_by_hw_sec>
  14:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_core_en_sec:

00000000 <pmu_pd_core_en_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3010      	movi      	r0, 16
   c:	9324      	ld.w      	r1, (r3, 0x10)
   e:	ec210001 	ori      	r1, r1, 1
  12:	e0000000 	bsr      	0x0	// 0 <pmu_pd_core_en_sec>
  16:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_rf_en_sec:

00000000 <pmu_pd_rf_en_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3010      	movi      	r0, 16
   c:	9324      	ld.w      	r1, (r3, 0x10)
   e:	ec210002 	ori      	r1, r1, 2
  12:	e0000000 	bsr      	0x0	// 0 <pmu_pd_rf_en_sec>
  16:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_lvd_dbs_sel_256k_sec:

00000000 <pmu_pd_lvd_dbs_sel_256k_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3010      	movi      	r0, 16
   c:	9324      	ld.w      	r1, (r3, 0x10)
   e:	ec210004 	ori      	r1, r1, 4
  12:	e0000000 	bsr      	0x0	// 0 <pmu_pd_lvd_dbs_sel_256k_sec>
  16:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_io_wkup_clear_pnd_sec:

00000000 <pmu_pd_io_wkup_clear_pnd_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	30a0      	movi      	r0, 160
   c:	d8232028 	ld.w      	r1, (r3, 0xa0)
  10:	39b0      	bseti      	r1, 16
  12:	e0000000 	bsr      	0x0	// 0 <pmu_pd_io_wkup_clear_pnd_sec>
  16:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_boot_clk_sel_256k_sec:

00000000 <pmu_pd_boot_clk_sel_256k_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3010      	movi      	r0, 16
   c:	9324      	ld.w      	r1, (r3, 0x10)
   e:	3985      	bclri      	r1, 5
  10:	e0000000 	bsr      	0x0	// 0 <pmu_pd_boot_clk_sel_256k_sec>
  14:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_boot_clk_sel_xosc_sec:

00000000 <pmu_pd_boot_clk_sel_xosc_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3010      	movi      	r0, 16
   c:	9324      	ld.w      	r1, (r3, 0x10)
   e:	ec210020 	ori      	r1, r1, 32
  12:	e0000000 	bsr      	0x0	// 0 <pmu_pd_boot_clk_sel_xosc_sec>
  16:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_io_wkup_en_sec:

00000000 <pmu_pd_io_wkup_en_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	30a0      	movi      	r0, 160
   c:	d8232028 	ld.w      	r1, (r3, 0xa0)
  10:	ec210001 	ori      	r1, r1, 1
  14:	e0000000 	bsr      	0x0	// 0 <pmu_pd_io_wkup_en_sec>
  18:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_io_wkup_sel_rs_edge_sec:

00000000 <pmu_pd_io_wkup_sel_rs_edge_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	30a0      	movi      	r0, 160
   c:	d8232028 	ld.w      	r1, (r3, 0xa0)
  10:	3981      	bclri      	r1, 1
  12:	e0000000 	bsr      	0x0	// 0 <pmu_pd_io_wkup_sel_rs_edge_sec>
  16:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_io_wkup_sel_fl_edge_sec:

00000000 <pmu_pd_io_wkup_sel_fl_edge_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	30a0      	movi      	r0, 160
   c:	d8232028 	ld.w      	r1, (r3, 0xa0)
  10:	ec210002 	ori      	r1, r1, 2
  14:	e0000000 	bsr      	0x0	// 0 <pmu_pd_io_wkup_sel_fl_edge_sec>
  18:	1490      	pop      	r15

Disassembly of section .text.xo_set_cs_sec:

00000000 <xo_set_cs_sec>:
   0:	14d0      	push      	r15
   2:	381f      	cmphsi      	r0, 32
   4:	080f      	bt      	0x22	// 22 <xo_set_cs_sec+0x22>
   6:	ea038003 	movi      	r3, 32771
   a:	c5e34903 	rotli      	r3, r3, 15
   e:	4013      	lsli      	r0, r0, 19
  10:	932a      	ld.w      	r1, (r3, 0x28)
  12:	ea23ff08 	movih      	r3, 65288
  16:	2b00      	subi      	r3, 1
  18:	684c      	and      	r1, r3
  1a:	6c40      	or      	r1, r0
  1c:	3028      	movi      	r0, 40
  1e:	e0000000 	bsr      	0x0	// 0 <xo_set_cs_sec>
  22:	1490      	pop      	r15

Disassembly of section .text.xo_set_ct_sec:

00000000 <xo_set_ct_sec>:
   0:	14d2      	push      	r4-r5, r15
   2:	381f      	cmphsi      	r0, 32
   4:	6d03      	mov      	r4, r0
   6:	081a      	bt      	0x3a	// 3a <xo_set_ct_sec+0x3a>
   8:	ea058003 	movi      	r5, 32771
   c:	c5e54905 	rotli      	r5, r5, 15
  10:	c7405022 	bmaski      	r2, 27
  14:	c6624902 	rotli      	r2, r2, 19
  18:	956a      	ld.w      	r3, (r5, 0x28)
  1a:	68c8      	and      	r3, r2
  1c:	402e      	lsli      	r1, r0, 14
  1e:	6c4c      	or      	r1, r3
  20:	3028      	movi      	r0, 40
  22:	e0000000 	bsr      	0x0	// 0 <xo_set_ct_sec>
  26:	952a      	ld.w      	r1, (r5, 0x28)
  28:	ea033e00 	movi      	r3, 15872
  2c:	6cce      	nor      	r3, r3
  2e:	684c      	and      	r1, r3
  30:	4489      	lsli      	r4, r4, 9
  32:	6c50      	or      	r1, r4
  34:	3028      	movi      	r0, 40
  36:	e0000000 	bsr      	0x0	// 0 <xo_set_ct_sec>
  3a:	1492      	pop      	r4-r5, r15

Disassembly of section .text.xo_set_dr_sec:

00000000 <xo_set_dr_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	4038      	lsli      	r1, r0, 24
   c:	936a      	ld.w      	r3, (r3, 0x28)
   e:	c40356e3 	zext      	r3, r3, 23, 0
  12:	6c4c      	or      	r1, r3
  14:	3028      	movi      	r0, 40
  16:	e0000000 	bsr      	0x0	// 0 <xo_set_dr_sec>
  1a:	1490      	pop      	r15

Disassembly of section .text.pd_hxosc_en_sec:

00000000 <pd_hxosc_en_sec>:
   0:	14d0      	push      	r15
   2:	3841      	cmpnei      	r0, 1
   4:	ea038003 	movi      	r3, 32771
   8:	c5e34903 	rotli      	r3, r3, 15
   c:	932a      	ld.w      	r1, (r3, 0x28)
   e:	0807      	bt      	0x1c	// 1c <pd_hxosc_en_sec+0x1c>
  10:	ec210001 	ori      	r1, r1, 1
  14:	3028      	movi      	r0, 40
  16:	e0000000 	bsr      	0x0	// 0 <pd_hxosc_en_sec>
  1a:	1490      	pop      	r15
  1c:	3980      	bclri      	r1, 0
  1e:	07fb      	br      	0x14	// 14 <pd_hxosc_en_sec+0x14>

Disassembly of section .text.pmu_pd_set_anatop_en_sec:

00000000 <pmu_pd_set_anatop_en_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	302c      	movi      	r0, 44
   c:	932b      	ld.w      	r1, (r3, 0x2c)
   e:	ec210001 	ori      	r1, r1, 1
  12:	e0000000 	bsr      	0x0	// 0 <pmu_pd_set_anatop_en_sec>
  16:	1490      	pop      	r15

Disassembly of section .text.pmu_pd_set_anatop_dis_sec:

00000000 <pmu_pd_set_anatop_dis_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	302c      	movi      	r0, 44
   c:	932b      	ld.w      	r1, (r3, 0x2c)
   e:	3980      	bclri      	r1, 0
  10:	e0000000 	bsr      	0x0	// 0 <pmu_pd_set_anatop_dis_sec>
  14:	1490      	pop      	r15

Disassembly of section .text.sysctrl_external_xosc_en:

00000000 <sysctrl_external_xosc_en>:
   0:	14d0      	push      	r15
   2:	e921000a 	bnez      	r1, 0x16	// 16 <sysctrl_external_xosc_en+0x16>
   6:	1070      	lrw      	r3, 0x40026000	// 44 <sysctrl_external_xosc_en+0x44>
   8:	9345      	ld.w      	r2, (r3, 0x14)
   a:	3a91      	bclri      	r2, 17
   c:	b345      	st.w      	r2, (r3, 0x14)
   e:	9350      	ld.w      	r2, (r3, 0x40)
  10:	3a80      	bclri      	r2, 0
  12:	b350      	st.w      	r2, (r3, 0x40)
  14:	1490      	pop      	r15
  16:	3941      	cmpnei      	r1, 1
  18:	0bfe      	bt      	0x14	// 14 <sysctrl_external_xosc_en+0x14>
  1a:	385c      	cmpnei      	r0, 28
  1c:	0805      	bt      	0x26	// 26 <sysctrl_external_xosc_en+0x26>
  1e:	106a      	lrw      	r3, 0x40026000	// 44 <sysctrl_external_xosc_en+0x44>
  20:	9345      	ld.w      	r2, (r3, 0x14)
  22:	3ab1      	bseti      	r2, 17
  24:	07f4      	br      	0xc	// c <sysctrl_external_xosc_en+0xc>
  26:	eb400029 	cmpnei      	r0, 41
  2a:	0bf5      	bt      	0x14	// 14 <sysctrl_external_xosc_en+0x14>
  2c:	1066      	lrw      	r3, 0x40026000	// 44 <sysctrl_external_xosc_en+0x44>
  2e:	3100      	movi      	r1, 0
  30:	9345      	ld.w      	r2, (r3, 0x14)
  32:	3a91      	bclri      	r2, 17
  34:	b345      	st.w      	r2, (r3, 0x14)
  36:	9350      	ld.w      	r2, (r3, 0x40)
  38:	ec420001 	ori      	r2, r2, 1
  3c:	b350      	st.w      	r2, (r3, 0x40)
  3e:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  42:	07e9      	br      	0x14	// 14 <sysctrl_external_xosc_en+0x14>
  44:	40026000 	.long	0x40026000

Disassembly of section .text.sysctrl_syspll_adc_calib:

00000000 <sysctrl_syspll_adc_calib>:
   0:	1044      	lrw      	r2, 0x40026000	// 10 <sysctrl_syspll_adc_calib+0x10>
   2:	3100      	movi      	r1, 0
   4:	9274      	ld.w      	r3, (r2, 0x50)
   6:	293e      	subi      	r1, 63
   8:	68c4      	and      	r3, r1
   a:	b274      	st.w      	r3, (r2, 0x50)
   c:	783c      	jmp      	r15
   e:	0000      	.short	0x0000
  10:	40026000 	.long	0x40026000

Disassembly of section .text.sysctrl_adcpll_adc_calib:

00000000 <sysctrl_adcpll_adc_calib>:
   0:	1044      	lrw      	r2, 0x40026000	// 10 <sysctrl_adcpll_adc_calib+0x10>
   2:	3100      	movi      	r1, 0
   4:	9273      	ld.w      	r3, (r2, 0x4c)
   6:	293e      	subi      	r1, 63
   8:	68c4      	and      	r3, r1
   a:	b273      	st.w      	r3, (r2, 0x4c)
   c:	783c      	jmp      	r15
   e:	0000      	.short	0x0000
  10:	40026000 	.long	0x40026000

Disassembly of section .text.sysctrl_syspll_set:

00000000 <sysctrl_syspll_set>:
   0:	ea8c001a 	lrw      	r12, 0x40026000	// 68 <sysctrl_syspll_set+0x68>
   4:	e9200008 	bnez      	r0, 0x14	// 14 <sysctrl_syspll_set+0x14>
   8:	d86c2014 	ld.w      	r3, (r12, 0x50)
   c:	3b80      	bclri      	r3, 0
   e:	dc6c2014 	st.w      	r3, (r12, 0x50)
  12:	783c      	jmp      	r15
  14:	d80c2010 	ld.w      	r0, (r12, 0x40)
  18:	ea0d0f00 	movi      	r13, 3840
  1c:	6f76      	nor      	r13, r13
  1e:	6834      	and      	r0, r13
  20:	dc0c2010 	st.w      	r0, (r12, 0x40)
  24:	4128      	lsli      	r1, r1, 8
  26:	d80c2010 	ld.w      	r0, (r12, 0x40)
  2a:	e4212f00 	andi      	r1, r1, 3840
  2e:	6c40      	or      	r1, r0
  30:	3a41      	cmpnei      	r2, 1
  32:	dc2c2010 	st.w      	r1, (r12, 0x40)
  36:	d84c2010 	ld.w      	r2, (r12, 0x40)
  3a:	0815      	bt      	0x64	// 64 <sysctrl_syspll_set+0x64>
  3c:	3a97      	bclri      	r2, 23
  3e:	dc4c2010 	st.w      	r2, (r12, 0x40)
  42:	104a      	lrw      	r2, 0x40026000	// 68 <sysctrl_syspll_set+0x68>
  44:	3000      	movi      	r0, 0
  46:	9230      	ld.w      	r1, (r2, 0x40)
  48:	28fe      	subi      	r0, 255
  4a:	6840      	and      	r1, r0
  4c:	b230      	st.w      	r1, (r2, 0x40)
  4e:	60cc      	addu      	r3, r3
  50:	9230      	ld.w      	r1, (r2, 0x40)
  52:	e46320ff 	andi      	r3, r3, 255
  56:	6cc4      	or      	r3, r1
  58:	b270      	st.w      	r3, (r2, 0x40)
  5a:	9274      	ld.w      	r3, (r2, 0x50)
  5c:	ec630001 	ori      	r3, r3, 1
  60:	b274      	st.w      	r3, (r2, 0x50)
  62:	07d8      	br      	0x12	// 12 <sysctrl_syspll_set+0x12>
  64:	3ab7      	bseti      	r2, 23
  66:	07ec      	br      	0x3e	// 3e <sysctrl_syspll_set+0x3e>
  68:	40026000 	.long	0x40026000

Disassembly of section .text.sysctrl_adcpll_set:

00000000 <sysctrl_adcpll_set>:
   0:	ea8c0020 	lrw      	r12, 0x40026000	// 80 <sysctrl_adcpll_set+0x80>
   4:	e9200008 	bnez      	r0, 0x14	// 14 <sysctrl_adcpll_set+0x14>
   8:	d86c2013 	ld.w      	r3, (r12, 0x4c)
   c:	3b80      	bclri      	r3, 0
   e:	dc6c2013 	st.w      	r3, (r12, 0x4c)
  12:	783c      	jmp      	r15
  14:	d80c2010 	ld.w      	r0, (r12, 0x40)
  18:	ea0df000 	movi      	r13, 61440
  1c:	6f76      	nor      	r13, r13
  1e:	6834      	and      	r0, r13
  20:	dc0c2010 	st.w      	r0, (r12, 0x40)
  24:	412c      	lsli      	r1, r1, 12
  26:	d80c2010 	ld.w      	r0, (r12, 0x40)
  2a:	c40155e1 	zext      	r1, r1, 15, 0
  2e:	6c40      	or      	r1, r0
  30:	dc2c2010 	st.w      	r1, (r12, 0x40)
  34:	d82c2010 	ld.w      	r1, (r12, 0x40)
  38:	3998      	bclri      	r1, 24
  3a:	3999      	bclri      	r1, 25
  3c:	30c0      	movi      	r0, 192
  3e:	dc2c2010 	st.w      	r1, (r12, 0x40)
  42:	4258      	lsli      	r2, r2, 24
  44:	4012      	lsli      	r0, r0, 18
  46:	d82c2010 	ld.w      	r1, (r12, 0x40)
  4a:	6880      	and      	r2, r0
  4c:	6c84      	or      	r2, r1
  4e:	dc4c2010 	st.w      	r2, (r12, 0x40)
  52:	ea21ff81 	movih      	r1, 65409
  56:	d84c2010 	ld.w      	r2, (r12, 0x40)
  5a:	2900      	subi      	r1, 1
  5c:	6884      	and      	r2, r1
  5e:	31fe      	movi      	r1, 254
  60:	dc4c2010 	st.w      	r2, (r12, 0x40)
  64:	4370      	lsli      	r3, r3, 16
  66:	412f      	lsli      	r1, r1, 15
  68:	d84c2010 	ld.w      	r2, (r12, 0x40)
  6c:	68c4      	and      	r3, r1
  6e:	6cc8      	or      	r3, r2
  70:	dc6c2010 	st.w      	r3, (r12, 0x40)
  74:	d86c2013 	ld.w      	r3, (r12, 0x4c)
  78:	ec630001 	ori      	r3, r3, 1
  7c:	07c9      	br      	0xe	// e <sysctrl_adcpll_set+0xe>
  7e:	0000      	.short	0x0000
  80:	40026000 	.long	0x40026000

Disassembly of section .text.sysctrl_sysclk_cfg:

00000000 <sysctrl_sysclk_cfg>:
   0:	106f      	lrw      	r3, 0x40026000	// 3c <sysctrl_sysclk_cfg+0x3c>
   2:	e9200018 	bnez      	r0, 0x32	// 32 <sysctrl_sysclk_cfg+0x32>
   6:	9310      	ld.w      	r0, (r3, 0x40)
   8:	389a      	bclri      	r0, 26
   a:	b310      	st.w      	r0, (r3, 0x40)
   c:	106c      	lrw      	r3, 0x40026000	// 3c <sysctrl_sysclk_cfg+0x3c>
   e:	e4212003 	andi      	r1, r1, 3
  12:	9303      	ld.w      	r0, (r3, 0xc)
  14:	3880      	bclri      	r0, 0
  16:	3881      	bclri      	r0, 1
  18:	6c40      	or      	r1, r0
  1a:	b323      	st.w      	r1, (r3, 0xc)
  1c:	9323      	ld.w      	r1, (r3, 0xc)
  1e:	3986      	bclri      	r1, 6
  20:	3987      	bclri      	r1, 7
  22:	b323      	st.w      	r1, (r3, 0xc)
  24:	3000      	movi      	r0, 0
  26:	9324      	ld.w      	r1, (r3, 0x10)
  28:	28ff      	subi      	r0, 256
  2a:	6840      	and      	r1, r0
  2c:	6c84      	or      	r2, r1
  2e:	b344      	st.w      	r2, (r3, 0x10)
  30:	783c      	jmp      	r15
  32:	3841      	cmpnei      	r0, 1
  34:	0bec      	bt      	0xc	// c <sysctrl_sysclk_cfg+0xc>
  36:	9310      	ld.w      	r0, (r3, 0x40)
  38:	38ba      	bseti      	r0, 26
  3a:	07e8      	br      	0xa	// a <sysctrl_sysclk_cfg+0xa>
  3c:	40026000 	.long	0x40026000

Disassembly of section .text.sysctrl_apbclk_cfg:

00000000 <sysctrl_apbclk_cfg>:
   0:	1049      	lrw      	r2, 0x40026000	// 24 <sysctrl_apbclk_cfg+0x24>
   2:	ea0cff00 	movi      	r12, 65280
   6:	6f32      	nor      	r12, r12
   8:	9264      	ld.w      	r3, (r2, 0x10)
   a:	68f0      	and      	r3, r12
   c:	4008      	lsli      	r0, r0, 8
   e:	6cc0      	or      	r3, r0
  10:	b264      	st.w      	r3, (r2, 0x10)
  12:	ea20ff01 	movih      	r0, 65281
  16:	9264      	ld.w      	r3, (r2, 0x10)
  18:	2800      	subi      	r0, 1
  1a:	68c0      	and      	r3, r0
  1c:	4130      	lsli      	r1, r1, 16
  1e:	6c4c      	or      	r1, r3
  20:	b224      	st.w      	r1, (r2, 0x10)
  22:	783c      	jmp      	r15
  24:	40026000 	.long	0x40026000

Disassembly of section .text.sysctrl_crcdma_clk_cfg:

00000000 <sysctrl_crcdma_clk_cfg>:
   0:	1045      	lrw      	r2, 0x40026000	// 14 <sysctrl_crcdma_clk_cfg+0x14>
   2:	4006      	lsli      	r0, r0, 6
   4:	9263      	ld.w      	r3, (r2, 0xc)
   6:	3b86      	bclri      	r3, 6
   8:	3b87      	bclri      	r3, 7
   a:	e40020ff 	andi      	r0, r0, 255
   e:	6c0c      	or      	r0, r3
  10:	b203      	st.w      	r0, (r2, 0xc)
  12:	783c      	jmp      	r15
  14:	6000      	.short	0x6000
  16:	4002      	.short	0x4002

Disassembly of section .text.sysctrl_lf_clk_cfg:

00000000 <sysctrl_lf_clk_cfg>:
   0:	1046      	lrw      	r2, 0x40026000	// 18 <sysctrl_lf_clk_cfg+0x18>
   2:	9263      	ld.w      	r3, (r2, 0xc)
   4:	ec630100 	ori      	r3, r3, 256
   8:	b263      	st.w      	r3, (r2, 0xc)
   a:	9263      	ld.w      	r3, (r2, 0xc)
   c:	3b82      	bclri      	r3, 2
   e:	3b83      	bclri      	r3, 3
  10:	ec630004 	ori      	r3, r3, 4
  14:	b263      	st.w      	r3, (r2, 0xc)
  16:	783c      	jmp      	r15
  18:	6000      	.short	0x6000
  1a:	4002      	.short	0x4002

Disassembly of section .text.sysctrl_rfspi_clk_div_cfg:

00000000 <sysctrl_rfspi_clk_div_cfg>:
   0:	1044      	lrw      	r2, 0x40026000	// 10 <sysctrl_rfspi_clk_div_cfg+0x10>
   2:	4018      	lsli      	r0, r0, 24
   4:	9264      	ld.w      	r3, (r2, 0x10)
   6:	c40356e3 	zext      	r3, r3, 23, 0
   a:	6cc0      	or      	r3, r0
   c:	b264      	st.w      	r3, (r2, 0x10)
   e:	783c      	jmp      	r15
  10:	40026000 	.long	0x40026000

Disassembly of section .text.sysctrl_clk_output_to_pa29_cfg:

00000000 <sysctrl_clk_output_to_pa29_cfg>:
   0:	14d0      	push      	r15
   2:	104c      	lrw      	r2, 0x40026000	// 30 <sysctrl_clk_output_to_pa29_cfg+0x30>
   4:	ea8c000c 	lrw      	r12, 0xc0ffffcf	// 34 <sysctrl_clk_output_to_pa29_cfg+0x34>
   8:	9263      	ld.w      	r3, (r2, 0xc)
   a:	4004      	lsli      	r0, r0, 4
   c:	68f0      	and      	r3, r12
   e:	e4002030 	andi      	r0, r0, 48
  12:	6cc0      	or      	r3, r0
  14:	30fc      	movi      	r0, 252
  16:	4016      	lsli      	r0, r0, 22
  18:	4138      	lsli      	r1, r1, 24
  1a:	6840      	and      	r1, r0
  1c:	6c4c      	or      	r1, r3
  1e:	b223      	st.w      	r1, (r2, 0xc)
  20:	9260      	ld.w      	r3, (r2, 0x0)
  22:	3bb8      	bseti      	r3, 24
  24:	b260      	st.w      	r3, (r2, 0x0)
  26:	3101      	movi      	r1, 1
  28:	301d      	movi      	r0, 29
  2a:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  2e:	1490      	pop      	r15
  30:	6000      	.short	0x6000
  32:	4002      	.short	0x4002
  34:	c0ffffcf 	.long	0xc0ffffcf

Disassembly of section .text.sysctrl_dac_init:

00000000 <sysctrl_dac_init>:
   0:	1071      	lrw      	r3, 0x40026000	// 44 <sysctrl_dac_init+0x44>
   2:	ea01f000 	movi      	r1, 61440
   6:	6c46      	nor      	r1, r1
   8:	9341      	ld.w      	r2, (r3, 0x4)
   a:	6884      	and      	r2, r1
   c:	ea01f00f 	movi      	r1, 61455
  10:	c7014901 	rotli      	r1, r1, 24
  14:	6c84      	or      	r2, r1
  16:	b341      	st.w      	r2, (r3, 0x4)
  18:	934c      	ld.w      	r2, (r3, 0x30)
  1a:	ea01c300 	movi      	r1, 49920
  1e:	c6c14901 	rotli      	r1, r1, 22
  22:	6884      	and      	r2, r1
  24:	1029      	lrw      	r1, 0x20820830	// 48 <sysctrl_dac_init+0x48>
  26:	6c84      	or      	r2, r1
  28:	b34c      	st.w      	r2, (r3, 0x30)
  2a:	9355      	ld.w      	r2, (r3, 0x54)
  2c:	3a88      	bclri      	r2, 8
  2e:	b355      	st.w      	r2, (r3, 0x54)
  30:	9355      	ld.w      	r2, (r3, 0x54)
  32:	ec420200 	ori      	r2, r2, 512
  36:	b355      	st.w      	r2, (r3, 0x54)
  38:	9341      	ld.w      	r2, (r3, 0x4)
  3a:	ec420001 	ori      	r2, r2, 1
  3e:	b341      	st.w      	r2, (r3, 0x4)
  40:	783c      	jmp      	r15
  42:	0000      	.short	0x0000
  44:	40026000 	.long	0x40026000
  48:	0830      	.short	0x0830
  4a:	2082      	.short	0x2082

Disassembly of section .text.sysctrl_set_dac_default_state:

00000000 <sysctrl_set_dac_default_state>:
   0:	3803      	cmphsi      	r0, 4
   2:	080e      	bt      	0x1e	// 1e <sysctrl_set_dac_default_state+0x1e>
   4:	1068      	lrw      	r3, 0x40026000	// 24 <sysctrl_set_dac_default_state+0x24>
   6:	400a      	lsli      	r0, r0, 10
   8:	9355      	ld.w      	r2, (r3, 0x54)
   a:	3a8a      	bclri      	r2, 10
   c:	3a8b      	bclri      	r2, 11
   e:	b355      	st.w      	r2, (r3, 0x54)
  10:	9355      	ld.w      	r2, (r3, 0x54)
  12:	e4002c00 	andi      	r0, r0, 3072
  16:	6c08      	or      	r0, r2
  18:	b315      	st.w      	r0, (r3, 0x54)
  1a:	3000      	movi      	r0, 0
  1c:	783c      	jmp      	r15
  1e:	3000      	movi      	r0, 0
  20:	2815      	subi      	r0, 22
  22:	07fd      	br      	0x1c	// 1c <sysctrl_set_dac_default_state+0x1c>
  24:	40026000 	.long	0x40026000

Disassembly of section .text.adc_cfg_reg_wr:

00000000 <adc_cfg_reg_wr>:
   0:	ea224001 	movih      	r2, 16385
   4:	3aae      	bseti      	r2, 14
   6:	9260      	ld.w      	r3, (r2, 0x0)
   8:	e4632001 	andi      	r3, r3, 1
   c:	e923fffd 	bnez      	r3, 0x6	// 6 <adc_cfg_reg_wr+0x6>
  10:	ea232000 	movih      	r3, 8192
  14:	2b7f      	subi      	r3, 128
  16:	4127      	lsli      	r1, r1, 7
  18:	684c      	and      	r1, r3
  1a:	4002      	lsli      	r0, r0, 2
  1c:	ec210003 	ori      	r1, r1, 3
  20:	e400207c 	andi      	r0, r0, 124
  24:	6c04      	or      	r0, r1
  26:	b200      	st.w      	r0, (r2, 0x0)
  28:	783c      	jmp      	r15

Disassembly of section .text.adc_cfg_reg_rd:

00000000 <adc_cfg_reg_rd>:
   0:	ea234001 	movih      	r3, 16385
   4:	3bae      	bseti      	r3, 14
   6:	9340      	ld.w      	r2, (r3, 0x0)
   8:	e4422001 	andi      	r2, r2, 1
   c:	e922fffd 	bnez      	r2, 0x6	// 6 <adc_cfg_reg_rd+0x6>
  10:	4002      	lsli      	r0, r0, 2
  12:	e400207c 	andi      	r0, r0, 124
  16:	ec000001 	ori      	r0, r0, 1
  1a:	b300      	st.w      	r0, (r3, 0x0)
  1c:	9300      	ld.w      	r0, (r3, 0x0)
  1e:	4807      	lsri      	r0, r0, 7
  20:	783c      	jmp      	r15

Disassembly of section NON_DSLEEP:

00000000 <memory_read>:
   0:	14d4      	push      	r4-r7, r15
   2:	6d43      	mov      	r5, r0
   4:	3037      	movi      	r0, 55
   6:	6d87      	mov      	r6, r1
   8:	6dcb      	mov      	r7, r2
   a:	e0000000 	bsr      	0x0	// 0 <dev_get>
   e:	6d03      	mov      	r4, r0
  10:	e9000011 	bez      	r0, 0x32	// 32 <memory_read+0x32>
  14:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
  18:	e425006f 	addi      	r1, r5, 112
  1c:	4762      	lsli      	r3, r7, 2
  1e:	6c9b      	mov      	r2, r6
  20:	412c      	lsli      	r1, r1, 12
  22:	6c13      	mov      	r0, r4
  24:	e0000000 	bsr      	0x0	// 0 <spi_nor_read>
  28:	6c13      	mov      	r0, r4
  2a:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
  2e:	3000      	movi      	r0, 0
  30:	1494      	pop      	r4-r7, r15
  32:	3000      	movi      	r0, 0
  34:	2800      	subi      	r0, 1
  36:	07fd      	br      	0x30	// 30 <memory_read+0x30>

00000038 <memory_write>:
  38:	14d4      	push      	r4-r7, r15
  3a:	1421      	subi      	r14, r14, 4
  3c:	6d03      	mov      	r4, r0
  3e:	3037      	movi      	r0, 55
  40:	6dc7      	mov      	r7, r1
  42:	6d8b      	mov      	r6, r2
  44:	e0000000 	bsr      	0x0	// 0 <dev_get>
  48:	3355      	movi      	r3, 85
  4a:	6d43      	mov      	r5, r0
  4c:	b860      	st.w      	r3, (r14, 0x0)
  4e:	e900001d 	bez      	r0, 0x88	// 88 <memory_write+0x50>
  52:	246f      	addi      	r4, 112
  54:	448c      	lsli      	r4, r4, 12
  56:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
  5a:	46c2      	lsli      	r6, r6, 2
  5c:	6c53      	mov      	r1, r4
  5e:	6c17      	mov      	r0, r5
  60:	e0000000 	bsr      	0x0	// 0 <spi_nor_sector_erase>
  64:	6cdb      	mov      	r3, r6
  66:	6c9f      	mov      	r2, r7
  68:	6c53      	mov      	r1, r4
  6a:	6c17      	mov      	r0, r5
  6c:	e0000000 	bsr      	0x0	// 0 <spi_nor_write>
  70:	3304      	movi      	r3, 4
  72:	6cbb      	mov      	r2, r14
  74:	5c38      	addu      	r1, r4, r6
  76:	6c17      	mov      	r0, r5
  78:	e0000000 	bsr      	0x0	// 0 <spi_nor_write>
  7c:	6c17      	mov      	r0, r5
  7e:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
  82:	3000      	movi      	r0, 0
  84:	1401      	addi      	r14, r14, 4
  86:	1494      	pop      	r4-r7, r15
  88:	3000      	movi      	r0, 0
  8a:	2800      	subi      	r0, 1
  8c:	07fc      	br      	0x84	// 84 <memory_write+0x4c>
	...

00000090 <sysctrl_efuse_config_and_read>:
  90:	14c5      	push      	r4-r8
  92:	c000602c 	mfcr      	r12, cr<0, 0>
  96:	c0807020 	psrclr      	ie
  9a:	119c      	lrw      	r4, 0x40026000	// 188 <sysctrl_efuse_config_and_read+0xf8>
  9c:	117c      	lrw      	r3, 0x4c5de9b3	// 18c <sysctrl_efuse_config_and_read+0xfc>
  9e:	b46b      	st.w      	r3, (r4, 0x2c)
  a0:	ea03a000 	movi      	r3, 40960
  a4:	3bbe      	bseti      	r3, 30
  a6:	ea0d0000 	movi      	r13, 0
  aa:	dda32002 	st.w      	r13, (r3, 0x8)
  ae:	dda32004 	st.w      	r13, (r3, 0x10)
  b2:	dda32000 	st.w      	r13, (r3, 0x0)
  b6:	dda32003 	st.w      	r13, (r3, 0xc)
  ba:	ea0d2922 	movi      	r13, 10530
  be:	dda32001 	st.w      	r13, (r3, 0x4)
  c2:	ea0d0003 	movi      	r13, 3
  c6:	dda32000 	st.w      	r13, (r3, 0x0)
  ca:	1172      	lrw      	r3, 0x3fac87e4	// 190 <sysctrl_efuse_config_and_read+0x100>
  cc:	b46b      	st.w      	r3, (r4, 0x2c)
  ce:	e46c2040 	andi      	r3, r12, 64
  d2:	e9230029 	bnez      	r3, 0x124	// 124 <sysctrl_efuse_config_and_read+0x94>
  d6:	ea03a000 	movi      	r3, 40960
  da:	3bbe      	bseti      	r3, 30
  dc:	6006      	subu      	r0, r1
  de:	3500      	movi      	r5, 0
  e0:	118a      	lrw      	r4, 0x40026000	// 188 <sysctrl_efuse_config_and_read+0xf8>
  e2:	11cb      	lrw      	r6, 0x4c5de9b3	// 18c <sysctrl_efuse_config_and_read+0xfc>
  e4:	11eb      	lrw      	r7, 0x3fac87e4	// 190 <sysctrl_efuse_config_and_read+0x100>
  e6:	6e0f      	mov      	r8, r3
  e8:	c420002d 	addu      	r13, r0, r1
  ec:	e922001f 	bnez      	r2, 0x12a	// 12a <sysctrl_efuse_config_and_read+0x9a>
  f0:	c0006023 	mfcr      	r3, cr<0, 0>
  f4:	c0807020 	psrclr      	ie
  f8:	1104      	lrw      	r0, 0x40026000	// 188 <sysctrl_efuse_config_and_read+0xf8>
  fa:	1125      	lrw      	r1, 0x4c5de9b3	// 18c <sysctrl_efuse_config_and_read+0xfc>
  fc:	ea0ca000 	movi      	r12, 40960
 100:	c7cc284c 	bseti      	r12, r12, 30
 104:	b02b      	st.w      	r1, (r0, 0x2c)
 106:	d82c2000 	ld.w      	r1, (r12, 0x0)
 10a:	3980      	bclri      	r1, 0
 10c:	e4632040 	andi      	r3, r3, 64
 110:	dc2c2000 	st.w      	r1, (r12, 0x0)
 114:	103f      	lrw      	r1, 0x3fac87e4	// 190 <sysctrl_efuse_config_and_read+0x100>
 116:	b02b      	st.w      	r1, (r0, 0x2c)
 118:	e9030004 	bez      	r3, 0x120	// 120 <sysctrl_efuse_config_and_read+0x90>
 11c:	c0807420 	psrset      	ie
 120:	6c0b      	mov      	r0, r2
 122:	1485      	pop      	r4-r8
 124:	c0807420 	psrset      	ie
 128:	07d7      	br      	0xd6	// d6 <sysctrl_efuse_config_and_read+0x46>
 12a:	c000602c 	mfcr      	r12, cr<0, 0>
 12e:	c0807020 	psrclr      	ie
 132:	e5ad2fff 	andi      	r13, r13, 4095
 136:	c60d284d 	bseti      	r13, r13, 16
 13a:	b4cb      	st.w      	r6, (r4, 0x2c)
 13c:	dda32004 	st.w      	r13, (r3, 0x10)
 140:	b3a3      	st.w      	r5, (r3, 0xc)
 142:	d9a32000 	ld.w      	r13, (r3, 0x0)
 146:	e58c2040 	andi      	r12, r12, 64
 14a:	edad0020 	ori      	r13, r13, 32
 14e:	dda32000 	st.w      	r13, (r3, 0x0)
 152:	b4eb      	st.w      	r7, (r4, 0x2c)
 154:	e90c0004 	bez      	r12, 0x15c	// 15c <sysctrl_efuse_config_and_read+0xcc>
 158:	c0807420 	psrset      	ie
 15c:	ea0c0064 	movi      	r12, 100
 160:	d9a32003 	ld.w      	r13, (r3, 0xc)
 164:	eb4d0002 	cmpnei      	r13, 2
 168:	0c03      	bf      	0x16e	// 16e <sysctrl_efuse_config_and_read+0xde>
 16a:	e92c000c 	bnez      	r12, 0x182	// 182 <sysctrl_efuse_config_and_read+0xf2>
 16e:	d9a82005 	ld.w      	r13, (r8, 0x14)
 172:	dda10000 	st.b      	r13, (r1, 0x0)
 176:	2100      	addi      	r1, 1
 178:	e90cffbc 	bez      	r12, 0xf0	// f0 <sysctrl_efuse_config_and_read+0x60>
 17c:	2a00      	subi      	r2, 1
 17e:	7489      	zexth      	r2, r2
 180:	07b4      	br      	0xe8	// e8 <sysctrl_efuse_config_and_read+0x58>
 182:	e58c1000 	subi      	r12, r12, 1
 186:	07ed      	br      	0x160	// 160 <sysctrl_efuse_config_and_read+0xd0>
 188:	40026000 	.long	0x40026000
 18c:	4c5de9b3 	.long	0x4c5de9b3
 190:	3fac87e4 	.long	0x3fac87e4

00000194 <is_adc_calibed>:
 194:	14d0      	push      	r15
 196:	1439      	subi      	r14, r14, 100
 198:	127a      	lrw      	r3, 0x0	// 300 <rfadc_calib_mode_soft_test+0x9c>
 19a:	d8434003 	ld.bs      	r2, (r3, 0x3)
 19e:	e9220009 	bnez      	r2, 0x1b0	// 1b0 <is_adc_calibed+0x1c>
 1a2:	d8634002 	ld.bs      	r3, (r3, 0x2)
 1a6:	e9230005 	bnez      	r3, 0x1b0	// 1b0 <is_adc_calibed+0x1c>
 1aa:	3000      	movi      	r0, 0
 1ac:	1419      	addi      	r14, r14, 100
 1ae:	1490      	pop      	r15
 1b0:	3219      	movi      	r2, 25
 1b2:	6c7b      	mov      	r1, r14
 1b4:	3000      	movi      	r0, 0
 1b6:	e0000000 	bsr      	0x0	// 0 <memory_read>
 1ba:	e920000f 	bnez      	r0, 0x1d8	// 1d8 <is_adc_calibed+0x44>
 1be:	9878      	ld.w      	r3, (r14, 0x60)
 1c0:	eb430055 	cmpnei      	r3, 85
 1c4:	080a      	bt      	0x1d8	// 1d8 <is_adc_calibed+0x44>
 1c6:	1270      	lrw      	r3, 0x0	// 304 <rfadc_calib_mode_soft_test+0xa0>
 1c8:	d00e0882 	ldr.w      	r2, (r14, r0 << 2)
 1cc:	d4030882 	str.w      	r2, (r3, r0 << 2)
 1d0:	2000      	addi      	r0, 1
 1d2:	3858      	cmpnei      	r0, 24
 1d4:	0bfa      	bt      	0x1c8	// 1c8 <is_adc_calibed+0x34>
 1d6:	07ea      	br      	0x1aa	// 1aa <is_adc_calibed+0x16>
 1d8:	3000      	movi      	r0, 0
 1da:	2800      	subi      	r0, 1
 1dc:	07e8      	br      	0x1ac	// 1ac <is_adc_calibed+0x18>
	...

000001e0 <adc_init>:
 1e0:	14d3      	push      	r4-r6, r15
 1e2:	3402      	movi      	r4, 2
 1e4:	3500      	movi      	r5, 0
 1e6:	12c9      	lrw      	r6, 0x0	// 308 <rfadc_calib_mode_soft_test+0xa4>
 1e8:	d0a60881 	ldr.w      	r1, (r6, r5 << 2)
 1ec:	6c13      	mov      	r0, r4
 1ee:	2500      	addi      	r5, 1
 1f0:	e0000000 	bsr      	0x0	// 0 <memory_read>
 1f4:	3d58      	cmpnei      	r5, 24
 1f6:	2400      	addi      	r4, 1
 1f8:	7510      	zextb      	r4, r4
 1fa:	0bf7      	bt      	0x1e8	// 1e8 <adc_init+0x8>
 1fc:	1284      	lrw      	r4, 0x40026000	// 30c <rfadc_calib_mode_soft_test+0xa8>
 1fe:	310f      	movi      	r1, 15
 200:	9467      	ld.w      	r3, (r4, 0x1c)
 202:	3bb4      	bseti      	r3, 20
 204:	b467      	st.w      	r3, (r4, 0x1c)
 206:	9467      	ld.w      	r3, (r4, 0x1c)
 208:	ec630200 	ori      	r3, r3, 512
 20c:	b467      	st.w      	r3, (r4, 0x1c)
 20e:	9467      	ld.w      	r3, (r4, 0x1c)
 210:	3bb3      	bseti      	r3, 19
 212:	b467      	st.w      	r3, (r4, 0x1c)
 214:	9467      	ld.w      	r3, (r4, 0x1c)
 216:	3bb2      	bseti      	r3, 18
 218:	b467      	st.w      	r3, (r4, 0x1c)
 21a:	3000      	movi      	r0, 0
 21c:	e0000000 	bsr      	0x0	// 0 <memory_read>
 220:	3000      	movi      	r0, 0
 222:	e0000000 	bsr      	0x0	// 0 <memory_read>
 226:	ea228020 	movih      	r2, 32800
 22a:	9467      	ld.w      	r3, (r4, 0x1c)
 22c:	2a00      	subi      	r2, 1
 22e:	68c8      	and      	r3, r2
 230:	b467      	st.w      	r3, (r4, 0x1c)
 232:	9467      	ld.w      	r3, (r4, 0x1c)
 234:	3bb5      	bseti      	r3, 21
 236:	3bba      	bseti      	r3, 26
 238:	b467      	st.w      	r3, (r4, 0x1c)
 23a:	1493      	pop      	r4-r6, r15

0000023c <adc_calib_res_store>:
 23c:	14d3      	push      	r4-r6, r15
 23e:	3502      	movi      	r5, 2
 240:	3400      	movi      	r4, 0
 242:	11d1      	lrw      	r6, 0x0	// 304 <rfadc_calib_mode_soft_test+0xa0>
 244:	6c17      	mov      	r0, r5
 246:	e0000000 	bsr      	0x0	// 0 <memory_read>
 24a:	d4860880 	str.w      	r0, (r6, r4 << 2)
 24e:	2400      	addi      	r4, 1
 250:	3c58      	cmpnei      	r4, 24
 252:	2500      	addi      	r5, 1
 254:	7554      	zextb      	r5, r5
 256:	0bf7      	bt      	0x244	// 244 <adc_calib_res_store+0x8>
 258:	6c93      	mov      	r2, r4
 25a:	112b      	lrw      	r1, 0x0	// 304 <rfadc_calib_mode_soft_test+0xa0>
 25c:	3000      	movi      	r0, 0
 25e:	e0000000 	bsr      	0x0	// 38 <memory_write>
 262:	1493      	pop      	r4-r6, r15

00000264 <rfadc_calib_mode_soft_test>:
 264:	14d3      	push      	r4-r6, r15
 266:	3000      	movi      	r0, 0
 268:	e0000000 	bsr      	0x0	// 0 <memory_read>
 26c:	3300      	movi      	r3, 0
 26e:	2b0f      	subi      	r3, 16
 270:	c4602021 	and      	r1, r0, r3
 274:	3000      	movi      	r0, 0
 276:	e0000000 	bsr      	0x0	// 0 <memory_read>
 27a:	1145      	lrw      	r2, 0x40026000	// 30c <rfadc_calib_mode_soft_test+0xa8>
 27c:	3402      	movi      	r4, 2
 27e:	9267      	ld.w      	r3, (r2, 0x1c)
 280:	3b92      	bclri      	r3, 18
 282:	b267      	st.w      	r3, (r2, 0x1c)
 284:	3500      	movi      	r5, 0
 286:	11c1      	lrw      	r6, 0x0	// 308 <rfadc_calib_mode_soft_test+0xa4>
 288:	d0a60881 	ldr.w      	r1, (r6, r5 << 2)
 28c:	6c13      	mov      	r0, r4
 28e:	2500      	addi      	r5, 1
 290:	e0000000 	bsr      	0x0	// 0 <memory_read>
 294:	3d58      	cmpnei      	r5, 24
 296:	2400      	addi      	r4, 1
 298:	7510      	zextb      	r4, r4
 29a:	0bf7      	bt      	0x288	// 288 <rfadc_calib_mode_soft_test+0x24>
 29c:	107c      	lrw      	r3, 0x40026000	// 30c <rfadc_calib_mode_soft_test+0xa8>
 29e:	ea011010 	movi      	r1, 4112
 2a2:	39b0      	bseti      	r1, 16
 2a4:	9347      	ld.w      	r2, (r3, 0x1c)
 2a6:	3a94      	bclri      	r2, 20
 2a8:	b347      	st.w      	r2, (r3, 0x1c)
 2aa:	9347      	ld.w      	r2, (r3, 0x1c)
 2ac:	3ab2      	bseti      	r2, 18
 2ae:	3001      	movi      	r0, 1
 2b0:	b347      	st.w      	r2, (r3, 0x1c)
 2b2:	e0000000 	bsr      	0x0	// 0 <memory_read>
 2b6:	ea0143f7 	movi      	r1, 17399
 2ba:	3000      	movi      	r0, 0
 2bc:	e0000000 	bsr      	0x0	// 0 <memory_read>
 2c0:	3000      	movi      	r0, 0
 2c2:	e0000000 	bsr      	0x0	// 0 <memory_read>
 2c6:	e4a02001 	andi      	r5, r0, 1
 2ca:	e925fffb 	bnez      	r5, 0x2c0	// 2c0 <rfadc_calib_mode_soft_test+0x5c>
 2ce:	1090      	lrw      	r4, 0x40026000	// 30c <rfadc_calib_mode_soft_test+0xa8>
 2d0:	ea0143fe 	movi      	r1, 17406
 2d4:	9467      	ld.w      	r3, (r4, 0x1c)
 2d6:	3b92      	bclri      	r3, 18
 2d8:	b467      	st.w      	r3, (r4, 0x1c)
 2da:	6c17      	mov      	r0, r5
 2dc:	e0000000 	bsr      	0x0	// 0 <memory_read>
 2e0:	9467      	ld.w      	r3, (r4, 0x1c)
 2e2:	3bb4      	bseti      	r3, 20
 2e4:	b467      	st.w      	r3, (r4, 0x1c)
 2e6:	9467      	ld.w      	r3, (r4, 0x1c)
 2e8:	3bb2      	bseti      	r3, 18
 2ea:	b467      	st.w      	r3, (r4, 0x1c)
 2ec:	6c17      	mov      	r0, r5
 2ee:	e0000000 	bsr      	0x0	// 0 <memory_read>
 2f2:	ec20000f 	ori      	r1, r0, 15
 2f6:	6c17      	mov      	r0, r5
 2f8:	e0000000 	bsr      	0x0	// 0 <memory_read>
 2fc:	1493      	pop      	r4-r6, r15
	...
 30a:	0000      	.short	0x0000
 30c:	40026000 	.long	0x40026000

00000310 <tsensor_open>:
 310:	14d0      	push      	r15
 312:	ea038003 	movi      	r3, 32771
 316:	c5e34903 	rotli      	r3, r3, 15
 31a:	3020      	movi      	r0, 32
 31c:	9328      	ld.w      	r1, (r3, 0x20)
 31e:	ec210002 	ori      	r1, r1, 2
 322:	e0000000 	bsr      	0x0	// 0 <memory_read>
 326:	1490      	pop      	r15

00000328 <tsensor_close>:
 328:	14d0      	push      	r15
 32a:	ea038003 	movi      	r3, 32771
 32e:	c5e34903 	rotli      	r3, r3, 15
 332:	3020      	movi      	r0, 32
 334:	9328      	ld.w      	r1, (r3, 0x20)
 336:	3981      	bclri      	r1, 1
 338:	e0000000 	bsr      	0x0	// 0 <memory_read>
 33c:	1490      	pop      	r15
	...

00000340 <sys_monitor_chan_config>:
 340:	1166      	lrw      	r3, 0x40029000	// 3d8 <tsensor_ref_get_from_efuse+0x48>
 342:	3101      	movi      	r1, 1
 344:	9340      	ld.w      	r2, (r3, 0x0)
 346:	3ab5      	bseti      	r2, 21
 348:	b340      	st.w      	r2, (r3, 0x0)
 34a:	9040      	ld.w      	r2, (r0, 0x0)
 34c:	d9832000 	ld.w      	r12, (r3, 0x0)
 350:	7048      	lsl      	r1, r2
 352:	6c70      	or      	r1, r12
 354:	b320      	st.w      	r1, (r3, 0x0)
 356:	5a2e      	addi      	r1, r2, 4
 358:	4124      	lsli      	r1, r1, 4
 35a:	d9802001 	ld.w      	r12, (r0, 0x4)
 35e:	4244      	lsli      	r2, r2, 4
 360:	d461082c 	str.w      	r12, (r1, r3 << 0)
 364:	60c8      	addu      	r3, r2
 366:	9022      	ld.w      	r1, (r0, 0x8)
 368:	b331      	st.w      	r1, (r3, 0x44)
 36a:	783c      	jmp      	r15

0000036c <sys_monitor_reset>:
 36c:	105b      	lrw      	r2, 0x40029000	// 3d8 <tsensor_ref_get_from_efuse+0x48>
 36e:	3300      	movi      	r3, 0
 370:	b260      	st.w      	r3, (r2, 0x0)
 372:	6c0f      	mov      	r0, r3
 374:	b262      	st.w      	r3, (r2, 0x8)
 376:	5b2e      	addi      	r1, r3, 4
 378:	4124      	lsli      	r1, r1, 4
 37a:	d4410820 	str.w      	r0, (r1, r2 << 0)
 37e:	4324      	lsli      	r1, r3, 4
 380:	2300      	addi      	r3, 1
 382:	6048      	addu      	r1, r2
 384:	3b55      	cmpnei      	r3, 21
 386:	b111      	st.w      	r0, (r1, 0x44)
 388:	b112      	st.w      	r0, (r1, 0x48)
 38a:	0bf6      	bt      	0x376	// 376 <sys_monitor_reset+0xa>
 38c:	783c      	jmp      	r15
	...

00000390 <tsensor_ref_get_from_efuse>:
 390:	14d0      	push      	r15
 392:	1421      	subi      	r14, r14, 4
 394:	3300      	movi      	r3, 0
 396:	dc6e1000 	st.h      	r3, (r14, 0x0)
 39a:	e0000000 	bsr      	0x0	// 310 <tsensor_open>
 39e:	3202      	movi      	r2, 2
 3a0:	6c7b      	mov      	r1, r14
 3a2:	303a      	movi      	r0, 58
 3a4:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 3a8:	d86e0001 	ld.b      	r3, (r14, 0x1)
 3ac:	4368      	lsli      	r3, r3, 8
 3ae:	d84e0000 	ld.b      	r2, (r14, 0x0)
 3b2:	e4632300 	andi      	r3, r3, 768
 3b6:	6cc8      	or      	r3, r2
 3b8:	1049      	lrw      	r2, 0x0	// 3dc <tsensor_ref_get_from_efuse+0x4c>
 3ba:	dc621036 	st.h      	r3, (r2, 0x6c)
 3be:	e9030006 	bez      	r3, 0x3ca	// 3ca <tsensor_ref_get_from_efuse+0x3a>
 3c2:	d8624002 	ld.bs      	r3, (r2, 0x2)
 3c6:	e9030006 	bez      	r3, 0x3d2	// 3d2 <tsensor_ref_get_from_efuse+0x42>
 3ca:	ea030281 	movi      	r3, 641
 3ce:	dc621036 	st.h      	r3, (r2, 0x6c)
 3d2:	1401      	addi      	r14, r14, 4
 3d4:	1490      	pop      	r15
 3d6:	0000      	.short	0x0000
 3d8:	40029000 	.long	0x40029000
 3dc:	00000000 	.long	0x00000000

000003e0 <tsensor_meas>:
 3e0:	14d0      	push      	r15
 3e2:	e0000000 	bsr      	0x0	// 0 <memory_read>
 3e6:	3003      	movi      	r0, 3
 3e8:	e0000000 	bsr      	0x0	// 0 <memory_read>
 3ec:	127e      	lrw      	r3, 0x0	// 564 <io_input_meas+0x28>
 3ee:	d8631036 	ld.h      	r3, (r3, 0x6c)
 3f2:	600e      	subu      	r0, r3
 3f4:	330a      	movi      	r3, 10
 3f6:	7c0c      	mult      	r0, r3
 3f8:	3315      	movi      	r3, 21
 3fa:	c4608040 	divs      	r0, r0, r3
 3fe:	2018      	addi      	r0, 25
 400:	1490      	pop      	r15
	...

00000404 <vcc_meas>:
 404:	14d1      	push      	r4, r15
 406:	1299      	lrw      	r4, 0x4001a000	// 568 <io_input_meas+0x2c>
 408:	3000      	movi      	r0, 0
 40a:	9460      	ld.w      	r3, (r4, 0x0)
 40c:	ec630800 	ori      	r3, r3, 2048
 410:	b460      	st.w      	r3, (r4, 0x0)
 412:	e0000000 	bsr      	0x0	// 0 <memory_read>
 416:	9460      	ld.w      	r3, (r4, 0x0)
 418:	3b8b      	bclri      	r3, 11
 41a:	b460      	st.w      	r3, (r4, 0x0)
 41c:	e0000000 	bsr      	0x0	// 0 <__floatunsisf>
 420:	ea2140a0 	movih      	r1, 16544
 424:	e0000000 	bsr      	0x0	// 0 <__mulsf3>
 428:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 42c:	1250      	lrw      	r2, 0x9999999a	// 56c <io_input_meas+0x30>
 42e:	1271      	lrw      	r3, 0x3ff19999	// 570 <io_input_meas+0x34>
 430:	e0000000 	bsr      	0x0	// 0 <__muldf3>
 434:	3200      	movi      	r2, 0
 436:	ea233f50 	movih      	r3, 16208
 43a:	e0000000 	bsr      	0x0	// 0 <__muldf3>
 43e:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
 442:	1491      	pop      	r4, r15

00000444 <vdd13b_meas>:
 444:	14d2      	push      	r4-r5, r15
 446:	ea048003 	movi      	r4, 32771
 44a:	c5e44904 	rotli      	r4, r4, 15
 44e:	ea0301f8 	movi      	r3, 504
 452:	6cce      	nor      	r3, r3
 454:	9429      	ld.w      	r1, (r4, 0x24)
 456:	684c      	and      	r1, r3
 458:	ec210040 	ori      	r1, r1, 64
 45c:	3024      	movi      	r0, 36
 45e:	e0000000 	bsr      	0x0	// 0 <memory_read>
 462:	9428      	ld.w      	r1, (r4, 0x20)
 464:	c4015761 	zext      	r1, r1, 27, 0
 468:	39bc      	bseti      	r1, 28
 46a:	3020      	movi      	r0, 32
 46c:	e0000000 	bsr      	0x0	// 0 <memory_read>
 470:	300b      	movi      	r0, 11
 472:	e0000000 	bsr      	0x0	// 0 <memory_read>
 476:	9429      	ld.w      	r1, (r4, 0x24)
 478:	ea0301f8 	movi      	r3, 504
 47c:	6cce      	nor      	r3, r3
 47e:	6d43      	mov      	r5, r0
 480:	684c      	and      	r1, r3
 482:	3024      	movi      	r0, 36
 484:	e0000000 	bsr      	0x0	// 0 <memory_read>
 488:	c7605023 	bmaski      	r3, 28
 48c:	9428      	ld.w      	r1, (r4, 0x20)
 48e:	684c      	and      	r1, r3
 490:	3020      	movi      	r0, 32
 492:	e0000000 	bsr      	0x0	// 0 <memory_read>
 496:	6c17      	mov      	r0, r5
 498:	e0000000 	bsr      	0x0	// 0 <__floatunsisf>
 49c:	ea2140a0 	movih      	r1, 16544
 4a0:	e0000000 	bsr      	0x0	// 0 <__mulsf3>
 4a4:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 4a8:	1151      	lrw      	r2, 0x9999999a	// 56c <io_input_meas+0x30>
 4aa:	1172      	lrw      	r3, 0x3ff19999	// 570 <io_input_meas+0x34>
 4ac:	e0000000 	bsr      	0x0	// 0 <__muldf3>
 4b0:	3200      	movi      	r2, 0
 4b2:	ea233f50 	movih      	r3, 16208
 4b6:	e0000000 	bsr      	0x0	// 0 <__muldf3>
 4ba:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
 4be:	1492      	pop      	r4-r5, r15

000004c0 <vdd13c_meas>:
 4c0:	14d2      	push      	r4-r5, r15
 4c2:	ea048003 	movi      	r4, 32771
 4c6:	c5e44904 	rotli      	r4, r4, 15
 4ca:	ea0301f8 	movi      	r3, 504
 4ce:	6cce      	nor      	r3, r3
 4d0:	9429      	ld.w      	r1, (r4, 0x24)
 4d2:	684c      	and      	r1, r3
 4d4:	ec210080 	ori      	r1, r1, 128
 4d8:	3024      	movi      	r0, 36
 4da:	e0000000 	bsr      	0x0	// 0 <memory_read>
 4de:	9428      	ld.w      	r1, (r4, 0x20)
 4e0:	c4015761 	zext      	r1, r1, 27, 0
 4e4:	39bd      	bseti      	r1, 29
 4e6:	3020      	movi      	r0, 32
 4e8:	e0000000 	bsr      	0x0	// 0 <memory_read>
 4ec:	300b      	movi      	r0, 11
 4ee:	e0000000 	bsr      	0x0	// 0 <memory_read>
 4f2:	9429      	ld.w      	r1, (r4, 0x24)
 4f4:	ea0301f8 	movi      	r3, 504
 4f8:	6cce      	nor      	r3, r3
 4fa:	6d43      	mov      	r5, r0
 4fc:	684c      	and      	r1, r3
 4fe:	3024      	movi      	r0, 36
 500:	e0000000 	bsr      	0x0	// 0 <memory_read>
 504:	c7605023 	bmaski      	r3, 28
 508:	9428      	ld.w      	r1, (r4, 0x20)
 50a:	684c      	and      	r1, r3
 50c:	3020      	movi      	r0, 32
 50e:	e0000000 	bsr      	0x0	// 0 <memory_read>
 512:	6c17      	mov      	r0, r5
 514:	e0000000 	bsr      	0x0	// 0 <__floatunsisf>
 518:	ea2140a0 	movih      	r1, 16544
 51c:	e0000000 	bsr      	0x0	// 0 <__mulsf3>
 520:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 524:	1052      	lrw      	r2, 0x9999999a	// 56c <io_input_meas+0x30>
 526:	1073      	lrw      	r3, 0x3ff19999	// 570 <io_input_meas+0x34>
 528:	e0000000 	bsr      	0x0	// 0 <__muldf3>
 52c:	3200      	movi      	r2, 0
 52e:	ea233f50 	movih      	r3, 16208
 532:	e0000000 	bsr      	0x0	// 0 <__muldf3>
 536:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
 53a:	1492      	pop      	r4-r5, r15

0000053c <io_input_meas>:
 53c:	14d0      	push      	r15
 53e:	301f      	movi      	r0, 31
 540:	e0000000 	bsr      	0x0	// 0 <memory_read>
 544:	e0000000 	bsr      	0x0	// 0 <__floatunsisf>
 548:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 54c:	1048      	lrw      	r2, 0x9999999a	// 56c <io_input_meas+0x30>
 54e:	1069      	lrw      	r3, 0x3ff19999	// 570 <io_input_meas+0x34>
 550:	e0000000 	bsr      	0x0	// 0 <__muldf3>
 554:	3200      	movi      	r2, 0
 556:	ea233f50 	movih      	r3, 16208
 55a:	e0000000 	bsr      	0x0	// 0 <__muldf3>
 55e:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
 562:	1490      	pop      	r15
 564:	00000000 	.long	0x00000000
 568:	4001a000 	.long	0x4001a000
 56c:	9999999a 	.long	0x9999999a
 570:	3ff19999 	.long	0x3ff19999

00000574 <sysctrl_efuse_mac_addr_calc>:
 574:	14d2      	push      	r4-r5, r15
 576:	1422      	subi      	r14, r14, 8
 578:	6c7b      	mov      	r1, r14
 57a:	3206      	movi      	r2, 6
 57c:	6d03      	mov      	r4, r0
 57e:	ea0001cf 	movi      	r0, 463
 582:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 586:	d84e0000 	ld.b      	r2, (r14, 0x0)
 58a:	d82e0001 	ld.b      	r1, (r14, 0x1)
 58e:	d80e0002 	ld.b      	r0, (r14, 0x2)
 592:	c4222423 	or      	r3, r2, r1
 596:	d98e0003 	ld.b      	r12, (r14, 0x3)
 59a:	6cc0      	or      	r3, r0
 59c:	d9ae0004 	ld.b      	r13, (r14, 0x4)
 5a0:	6cf0      	or      	r3, r12
 5a2:	d8ae0005 	ld.b      	r5, (r14, 0x5)
 5a6:	6cf4      	or      	r3, r13
 5a8:	6cd4      	or      	r3, r5
 5aa:	e9230023 	bnez      	r3, 0x5f0	// 5f0 <sysctrl_efuse_mac_addr_calc+0x7c>
 5ae:	0119      	lrw      	r0, 0x0	// 8c4 <hgprintf+0x8c4>
 5b0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 5b4:	3207      	movi      	r2, 7
 5b6:	6c7b      	mov      	r1, r14
 5b8:	302a      	movi      	r0, 42
 5ba:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 5be:	d86e0000 	ld.b      	r3, (r14, 0x0)
 5c2:	3b80      	bclri      	r3, 0
 5c4:	3b81      	bclri      	r3, 1
 5c6:	ec630002 	ori      	r3, r3, 2
 5ca:	a460      	st.b      	r3, (r4, 0x0)
 5cc:	d86e0001 	ld.b      	r3, (r14, 0x1)
 5d0:	a461      	st.b      	r3, (r4, 0x1)
 5d2:	d86e0002 	ld.b      	r3, (r14, 0x2)
 5d6:	a462      	st.b      	r3, (r4, 0x2)
 5d8:	d86e0005 	ld.b      	r3, (r14, 0x5)
 5dc:	a463      	st.b      	r3, (r4, 0x3)
 5de:	d86e0006 	ld.b      	r3, (r14, 0x6)
 5e2:	a464      	st.b      	r3, (r4, 0x4)
 5e4:	d86e0004 	ld.b      	r3, (r14, 0x4)
 5e8:	4363      	lsli      	r3, r3, 3
 5ea:	a465      	st.b      	r3, (r4, 0x5)
 5ec:	1402      	addi      	r14, r14, 8
 5ee:	1492      	pop      	r4-r5, r15
 5f0:	a4a0      	st.b      	r5, (r4, 0x0)
 5f2:	dda40001 	st.b      	r13, (r4, 0x1)
 5f6:	dd840002 	st.b      	r12, (r4, 0x2)
 5fa:	a403      	st.b      	r0, (r4, 0x3)
 5fc:	a424      	st.b      	r1, (r4, 0x4)
 5fe:	a445      	st.b      	r2, (r4, 0x5)
 600:	07f6      	br      	0x5ec	// 5ec <sysctrl_efuse_mac_addr_calc+0x78>
	...

00000604 <sysctrl_efuse_get_customer_id>:
 604:	14d0      	push      	r15
 606:	1421      	subi      	r14, r14, 4
 608:	6c7b      	mov      	r1, r14
 60a:	3300      	movi      	r3, 0
 60c:	3202      	movi      	r2, 2
 60e:	3028      	movi      	r0, 40
 610:	dc6e0000 	st.b      	r3, (r14, 0x0)
 614:	dc6e0001 	st.b      	r3, (r14, 0x1)
 618:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 61c:	d86e0000 	ld.b      	r3, (r14, 0x0)
 620:	4368      	lsli      	r3, r3, 8
 622:	d80e0001 	ld.b      	r0, (r14, 0x1)
 626:	6c0c      	or      	r0, r3
 628:	1401      	addi      	r14, r14, 4
 62a:	1490      	pop      	r15

0000062c <sysctrl_efuse_get_vref>:
 62c:	14d0      	push      	r15
 62e:	1421      	subi      	r14, r14, 4
 630:	e42e0002 	addi      	r1, r14, 3
 634:	3300      	movi      	r3, 0
 636:	3201      	movi      	r2, 1
 638:	3031      	movi      	r0, 49
 63a:	dc6e0003 	st.b      	r3, (r14, 0x3)
 63e:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 642:	d80e0003 	ld.b      	r0, (r14, 0x3)
 646:	e9000006 	bez      	r0, 0x652	// 652 <sysctrl_efuse_get_vref+0x26>
 64a:	e4002007 	andi      	r0, r0, 7
 64e:	1401      	addi      	r14, r14, 4
 650:	1490      	pop      	r15
 652:	3004      	movi      	r0, 4
 654:	07fd      	br      	0x64e	// 64e <sysctrl_efuse_get_vref+0x22>
	...

00000658 <sysctrl_efuse_get_xo_vbg>:
 658:	14d0      	push      	r15
 65a:	1421      	subi      	r14, r14, 4
 65c:	e42e0002 	addi      	r1, r14, 3
 660:	3300      	movi      	r3, 0
 662:	3201      	movi      	r2, 1
 664:	3035      	movi      	r0, 53
 666:	dc6e0003 	st.b      	r3, (r14, 0x3)
 66a:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 66e:	d80e0003 	ld.b      	r0, (r14, 0x3)
 672:	e9000006 	bez      	r0, 0x67e	// 67e <sysctrl_efuse_get_xo_vbg+0x26>
 676:	c48054c0 	zext      	r0, r0, 6, 4
 67a:	1401      	addi      	r14, r14, 4
 67c:	1490      	pop      	r15
 67e:	3003      	movi      	r0, 3
 680:	07fd      	br      	0x67a	// 67a <sysctrl_efuse_get_xo_vbg+0x22>
	...

00000684 <sysctrl_efuse_get_xtal_id>:
 684:	14d0      	push      	r15
 686:	1421      	subi      	r14, r14, 4
 688:	3201      	movi      	r2, 1
 68a:	3080      	movi      	r0, 128
 68c:	e42e0002 	addi      	r1, r14, 3
 690:	7008      	lsl      	r0, r2
 692:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 696:	d80e0003 	ld.b      	r0, (r14, 0x3)
 69a:	1401      	addi      	r14, r14, 4
 69c:	1490      	pop      	r15
	...

000006a0 <sysctrl_efuse_get_bios_id>:
 6a0:	14d0      	push      	r15
 6a2:	1421      	subi      	r14, r14, 4
 6a4:	e42e0002 	addi      	r1, r14, 3
 6a8:	3201      	movi      	r2, 1
 6aa:	30ff      	movi      	r0, 255
 6ac:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 6b0:	d80e0003 	ld.b      	r0, (r14, 0x3)
 6b4:	1401      	addi      	r14, r14, 4
 6b6:	1490      	pop      	r15

000006b8 <sysctrl_efuse_get_xo_cs>:
 6b8:	14d0      	push      	r15
 6ba:	1421      	subi      	r14, r14, 4
 6bc:	e42e0002 	addi      	r1, r14, 3
 6c0:	3201      	movi      	r2, 1
 6c2:	30b2      	movi      	r0, 178
 6c4:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 6c8:	d80e0003 	ld.b      	r0, (r14, 0x3)
 6cc:	e400201f 	andi      	r0, r0, 31
 6d0:	1401      	addi      	r14, r14, 4
 6d2:	1490      	pop      	r15

000006d4 <is_xo_cs_calibed>:
 6d4:	14d1      	push      	r4, r15
 6d6:	1422      	subi      	r14, r14, 8
 6d8:	139c      	lrw      	r4, 0x0	// 8c8 <sysctrl_efuse_get_saw_info+0x20>
 6da:	d8644002 	ld.bs      	r3, (r4, 0x2)
 6de:	e9230010 	bnez      	r3, 0x6fe	// 6fe <is_xo_cs_calibed+0x2a>
 6e2:	e0000000 	bsr      	0x0	// 6b8 <sysctrl_efuse_get_xo_cs>
 6e6:	e900000c 	bez      	r0, 0x6fe	// 6fe <is_xo_cs_calibed+0x2a>
 6ea:	8460      	ld.b      	r3, (r4, 0x0)
 6ec:	e9230005 	bnez      	r3, 0x6f6	// 6f6 <is_xo_cs_calibed+0x22>
 6f0:	2000      	addi      	r0, 1
 6f2:	1402      	addi      	r14, r14, 8
 6f4:	1491      	pop      	r4, r15
 6f6:	3b41      	cmpnei      	r3, 1
 6f8:	c4000c82 	decf      	r0, r0, 2
 6fc:	07fb      	br      	0x6f2	// 6f2 <is_xo_cs_calibed+0x1e>
 6fe:	3202      	movi      	r2, 2
 700:	6c7b      	mov      	r1, r14
 702:	3007      	movi      	r0, 7
 704:	e0000000 	bsr      	0x0	// 0 <memory_read>
 708:	e9200008 	bnez      	r0, 0x718	// 718 <is_xo_cs_calibed+0x44>
 70c:	9861      	ld.w      	r3, (r14, 0x4)
 70e:	eb430055 	cmpnei      	r3, 85
 712:	0803      	bt      	0x718	// 718 <is_xo_cs_calibed+0x44>
 714:	9800      	ld.w      	r0, (r14, 0x0)
 716:	07ee      	br      	0x6f2	// 6f2 <is_xo_cs_calibed+0x1e>
 718:	3000      	movi      	r0, 0
 71a:	2800      	subi      	r0, 1
 71c:	07eb      	br      	0x6f2	// 6f2 <is_xo_cs_calibed+0x1e>
	...

00000720 <sysctrl_efuse_get_xo_ct>:
 720:	14d0      	push      	r15
 722:	1421      	subi      	r14, r14, 4
 724:	e42e0002 	addi      	r1, r14, 3
 728:	3201      	movi      	r2, 1
 72a:	30b2      	movi      	r0, 178
 72c:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 730:	d80e0003 	ld.b      	r0, (r14, 0x3)
 734:	5003      	asri      	r0, r0, 3
 736:	e400201c 	andi      	r0, r0, 28
 73a:	1401      	addi      	r14, r14, 4
 73c:	1490      	pop      	r15
	...

00000740 <sysctrl_efuse_get_tx_analog_gain_mcs7>:
 740:	14d0      	push      	r15
 742:	1421      	subi      	r14, r14, 4
 744:	e42e0002 	addi      	r1, r14, 3
 748:	3201      	movi      	r2, 1
 74a:	30d2      	movi      	r0, 210
 74c:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 750:	d80e0003 	ld.b      	r0, (r14, 0x3)
 754:	1401      	addi      	r14, r14, 4
 756:	1490      	pop      	r15

00000758 <sysctrl_efuse_get_tx_analog_gain_mcs3>:
 758:	14d0      	push      	r15
 75a:	1421      	subi      	r14, r14, 4
 75c:	e42e0002 	addi      	r1, r14, 3
 760:	3201      	movi      	r2, 1
 762:	30d3      	movi      	r0, 211
 764:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 768:	d80e0003 	ld.b      	r0, (r14, 0x3)
 76c:	1401      	addi      	r14, r14, 4
 76e:	1490      	pop      	r15

00000770 <sysctrl_efuse_get_tx_analog_gain_mcs0>:
 770:	14d0      	push      	r15
 772:	1421      	subi      	r14, r14, 4
 774:	e42e0002 	addi      	r1, r14, 3
 778:	3201      	movi      	r2, 1
 77a:	30d4      	movi      	r0, 212
 77c:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 780:	d80e0003 	ld.b      	r0, (r14, 0x3)
 784:	1401      	addi      	r14, r14, 4
 786:	1490      	pop      	r15

00000788 <sysctrl_efuse_get_test_temp>:
 788:	14d0      	push      	r15
 78a:	1421      	subi      	r14, r14, 4
 78c:	e42e0002 	addi      	r1, r14, 3
 790:	3201      	movi      	r2, 1
 792:	ea000101 	movi      	r0, 257
 796:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 79a:	d80e4003 	ld.bs      	r0, (r14, 0x3)
 79e:	1401      	addi      	r14, r14, 4
 7a0:	1490      	pop      	r15
	...

000007a4 <sysctrl_efuse_get_module_type>:
 7a4:	14d0      	push      	r15
 7a6:	1421      	subi      	r14, r14, 4
 7a8:	3201      	movi      	r2, 1
 7aa:	3081      	movi      	r0, 129
 7ac:	e42e0002 	addi      	r1, r14, 3
 7b0:	7008      	lsl      	r0, r2
 7b2:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 7b6:	d80e0003 	ld.b      	r0, (r14, 0x3)
 7ba:	e400200f 	andi      	r0, r0, 15
 7be:	1401      	addi      	r14, r14, 4
 7c0:	1490      	pop      	r15
	...

000007c4 <sysctrl_efuse_get_sip_ind>:
 7c4:	14d0      	push      	r15
 7c6:	1421      	subi      	r14, r14, 4
 7c8:	3201      	movi      	r2, 1
 7ca:	3081      	movi      	r0, 129
 7cc:	e42e0002 	addi      	r1, r14, 3
 7d0:	7008      	lsl      	r0, r2
 7d2:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 7d6:	d80e0003 	ld.b      	r0, (r14, 0x3)
 7da:	e4002040 	andi      	r0, r0, 64
 7de:	1401      	addi      	r14, r14, 4
 7e0:	1490      	pop      	r15
	...

000007e4 <sysctrl_efuse_get_dcn>:
 7e4:	14d0      	push      	r15
 7e6:	1421      	subi      	r14, r14, 4
 7e8:	e42e0002 	addi      	r1, r14, 3
 7ec:	3201      	movi      	r2, 1
 7ee:	3040      	movi      	r0, 64
 7f0:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 7f4:	d80e0003 	ld.b      	r0, (r14, 0x3)
 7f8:	1401      	addi      	r14, r14, 4
 7fa:	1490      	pop      	r15

000007fc <sysctrl_efuse_get_vdd13_trim_valid>:
 7fc:	14d0      	push      	r15
 7fe:	1421      	subi      	r14, r14, 4
 800:	e42e0002 	addi      	r1, r14, 3
 804:	3201      	movi      	r2, 1
 806:	3039      	movi      	r0, 57
 808:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 80c:	d80e0003 	ld.b      	r0, (r14, 0x3)
 810:	c4405440 	zext      	r0, r0, 2, 2
 814:	1401      	addi      	r14, r14, 4
 816:	1490      	pop      	r15

00000818 <sysctrl_efuse_get_vdd13b_trim>:
 818:	14d0      	push      	r15
 81a:	1421      	subi      	r14, r14, 4
 81c:	e42e0002 	addi      	r1, r14, 3
 820:	3201      	movi      	r2, 1
 822:	3037      	movi      	r0, 55
 824:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 828:	d80e0003 	ld.b      	r0, (r14, 0x3)
 82c:	c4405480 	zext      	r0, r0, 4, 2
 830:	1401      	addi      	r14, r14, 4
 832:	1490      	pop      	r15

00000834 <sysctrl_efuse_get_vdd13c_trim>:
 834:	14d0      	push      	r15
 836:	1421      	subi      	r14, r14, 4
 838:	e42e0002 	addi      	r1, r14, 3
 83c:	3201      	movi      	r2, 1
 83e:	3037      	movi      	r0, 55
 840:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 844:	d80e0003 	ld.b      	r0, (r14, 0x3)
 848:	4805      	lsri      	r0, r0, 5
 84a:	1401      	addi      	r14, r14, 4
 84c:	1490      	pop      	r15
	...

00000850 <sysctrl_efuse_get_module_crc>:
 850:	14d0      	push      	r15
 852:	1421      	subi      	r14, r14, 4
 854:	3201      	movi      	r2, 1
 856:	30ff      	movi      	r0, 255
 858:	e42e0002 	addi      	r1, r14, 3
 85c:	7008      	lsl      	r0, r2
 85e:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 862:	d80e0003 	ld.b      	r0, (r14, 0x3)
 866:	1401      	addi      	r14, r14, 4
 868:	1490      	pop      	r15
	...

0000086c <sysctrl_efuse_get_smt_dat>:
 86c:	14d0      	push      	r15
 86e:	1421      	subi      	r14, r14, 4
 870:	6c7b      	mov      	r1, r14
 872:	3204      	movi      	r2, 4
 874:	ea0001d5 	movi      	r0, 469
 878:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 87c:	9800      	ld.w      	r0, (r14, 0x0)
 87e:	1401      	addi      	r14, r14, 4
 880:	1490      	pop      	r15
	...

00000884 <sysctrl_efuse_get_rx_conv_gain>:
 884:	14d1      	push      	r4, r15
 886:	1421      	subi      	r14, r14, 4
 888:	6d03      	mov      	r4, r0
 88a:	3203      	movi      	r2, 3
 88c:	6c7b      	mov      	r1, r14
 88e:	ea00011d 	movi      	r0, 285
 892:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 896:	3c02      	cmphsi      	r4, 3
 898:	0805      	bt      	0x8a2	// 8a2 <sysctrl_efuse_get_rx_conv_gain+0x1e>
 89a:	d08e0020 	ldr.b      	r0, (r14, r4 << 0)
 89e:	1401      	addi      	r14, r14, 4
 8a0:	1491      	pop      	r4, r15
 8a2:	3000      	movi      	r0, 0
 8a4:	07fd      	br      	0x89e	// 89e <sysctrl_efuse_get_rx_conv_gain+0x1a>
	...

000008a8 <sysctrl_efuse_get_saw_info>:
 8a8:	14d0      	push      	r15
 8aa:	1421      	subi      	r14, r14, 4
 8ac:	e42e0002 	addi      	r1, r14, 3
 8b0:	3201      	movi      	r2, 1
 8b2:	ea0001d9 	movi      	r0, 473
 8b6:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 8ba:	d80e0003 	ld.b      	r0, (r14, 0x3)
 8be:	1401      	addi      	r14, r14, 4
 8c0:	1490      	pop      	r15
	...

000008cc <sysctrl_efuse_crc_check>:
 8cc:	14d3      	push      	r4-r6, r15
 8ce:	172c      	subi      	r14, r14, 432
 8d0:	33ff      	movi      	r3, 255
 8d2:	303b      	movi      	r0, 59
 8d4:	b860      	st.w      	r3, (r14, 0x0)
 8d6:	e0000000 	bsr      	0x0	// 0 <dev_get>
 8da:	1078      	lrw      	r3, 0x0	// 938 <sysctrl_efuse_crc_check+0x6c>
 8dc:	6d03      	mov      	r4, r0
 8de:	8360      	ld.b      	r3, (r3, 0x0)
 8e0:	3b01      	cmphsi      	r3, 2
 8e2:	0c25      	bf      	0x92c	// 92c <sysctrl_efuse_crc_check+0x60>
 8e4:	ea03019d 	movi      	r3, 413
 8e8:	b863      	st.w      	r3, (r14, 0xc)
 8ea:	1d04      	addi      	r5, r14, 16
 8ec:	d84e1006 	ld.h      	r2, (r14, 0xc)
 8f0:	6c57      	mov      	r1, r5
 8f2:	3031      	movi      	r0, 49
 8f4:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
 8f8:	e0000000 	bsr      	0x0	// 850 <sysctrl_efuse_get_module_crc>
 8fc:	3303      	movi      	r3, 3
 8fe:	dc6e1002 	st.h      	r3, (r14, 0x4)
 902:	9462      	ld.w      	r3, (r4, 0x8)
 904:	6d83      	mov      	r6, r0
 906:	d9832001 	ld.w      	r12, (r3, 0x4)
 90a:	b8a2      	st.w      	r5, (r14, 0x8)
 90c:	e90c0007 	bez      	r12, 0x91a	// 91a <sysctrl_efuse_crc_check+0x4e>
 910:	3300      	movi      	r3, 0
 912:	6cbb      	mov      	r2, r14
 914:	1901      	addi      	r1, r14, 4
 916:	6c13      	mov      	r0, r4
 918:	7bf1      	jsr      	r12
 91a:	9860      	ld.w      	r3, (r14, 0x0)
 91c:	658e      	cmpne      	r3, r6
 91e:	c4000503 	mvc      	r3
 922:	3000      	movi      	r0, 0
 924:	600e      	subu      	r0, r3
 926:	7402      	sextb      	r0, r0
 928:	170c      	addi      	r14, r14, 432
 92a:	1493      	pop      	r4-r6, r15
 92c:	3b41      	cmpnei      	r3, 1
 92e:	0803      	bt      	0x934	// 934 <sysctrl_efuse_crc_check+0x68>
 930:	33cf      	movi      	r3, 207
 932:	07db      	br      	0x8e8	// 8e8 <sysctrl_efuse_crc_check+0x1c>
 934:	3000      	movi      	r0, 0
 936:	07f9      	br      	0x928	// 928 <sysctrl_efuse_crc_check+0x5c>
 938:	00000000 	.long	0x00000000

0000093c <system_enter_sleep>:
 93c:	14d2      	push      	r4-r5, r15
 93e:	1289      	lrw      	r4, 0x40026000	// a60 <system_exit_sleep+0xa4>
 940:	e0000000 	bsr      	0x0	// 0 <lhw_abort_fsm>
 944:	3000      	movi      	r0, 0
 946:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
 94a:	9467      	ld.w      	r3, (r4, 0x1c)
 94c:	3b92      	bclri      	r3, 18
 94e:	b467      	st.w      	r3, (r4, 0x1c)
 950:	9465      	ld.w      	r3, (r4, 0x14)
 952:	3b9c      	bclri      	r3, 28
 954:	b465      	st.w      	r3, (r4, 0x14)
 956:	9465      	ld.w      	r3, (r4, 0x14)
 958:	3b9b      	bclri      	r3, 27
 95a:	b465      	st.w      	r3, (r4, 0x14)
 95c:	9465      	ld.w      	r3, (r4, 0x14)
 95e:	3b9a      	bclri      	r3, 26
 960:	b465      	st.w      	r3, (r4, 0x14)
 962:	9465      	ld.w      	r3, (r4, 0x14)
 964:	3b9d      	bclri      	r3, 29
 966:	b465      	st.w      	r3, (r4, 0x14)
 968:	9465      	ld.w      	r3, (r4, 0x14)
 96a:	3b93      	bclri      	r3, 19
 96c:	b465      	st.w      	r3, (r4, 0x14)
 96e:	9465      	ld.w      	r3, (r4, 0x14)
 970:	3b8f      	bclri      	r3, 15
 972:	b465      	st.w      	r3, (r4, 0x14)
 974:	9465      	ld.w      	r3, (r4, 0x14)
 976:	3b8b      	bclri      	r3, 11
 978:	b465      	st.w      	r3, (r4, 0x14)
 97a:	9465      	ld.w      	r3, (r4, 0x14)
 97c:	3b89      	bclri      	r3, 9
 97e:	b465      	st.w      	r3, (r4, 0x14)
 980:	9465      	ld.w      	r3, (r4, 0x14)
 982:	3b88      	bclri      	r3, 8
 984:	b465      	st.w      	r3, (r4, 0x14)
 986:	9465      	ld.w      	r3, (r4, 0x14)
 988:	3b85      	bclri      	r3, 5
 98a:	b465      	st.w      	r3, (r4, 0x14)
 98c:	9465      	ld.w      	r3, (r4, 0x14)
 98e:	3b84      	bclri      	r3, 4
 990:	b465      	st.w      	r3, (r4, 0x14)
 992:	9465      	ld.w      	r3, (r4, 0x14)
 994:	3b80      	bclri      	r3, 0
 996:	3500      	movi      	r5, 0
 998:	b465      	st.w      	r3, (r4, 0x14)
 99a:	e0000000 	bsr      	0x0	// 328 <tsensor_close>
 99e:	6c97      	mov      	r2, r5
 9a0:	6c57      	mov      	r1, r5
 9a2:	6c17      	mov      	r0, r5
 9a4:	e0000000 	bsr      	0x0	// 0 <memory_read>
 9a8:	9474      	ld.w      	r3, (r4, 0x50)
 9aa:	3b80      	bclri      	r3, 0
 9ac:	b474      	st.w      	r3, (r4, 0x50)
 9ae:	9473      	ld.w      	r3, (r4, 0x4c)
 9b0:	3b80      	bclri      	r3, 0
 9b2:	b473      	st.w      	r3, (r4, 0x4c)
 9b4:	6c17      	mov      	r0, r5
 9b6:	e0000000 	bsr      	0x0	// 0 <memory_read>
 9ba:	1492      	pop      	r4-r5, r15

000009bc <system_exit_sleep>:
 9bc:	14d0      	push      	r15
 9be:	ea038003 	movi      	r3, 32771
 9c2:	c5e34903 	rotli      	r3, r3, 15
 9c6:	3028      	movi      	r0, 40
 9c8:	932a      	ld.w      	r1, (r3, 0x28)
 9ca:	ec210001 	ori      	r1, r1, 1
 9ce:	e0000000 	bsr      	0x0	// 0 <memory_read>
 9d2:	3200      	movi      	r2, 0
 9d4:	3308      	movi      	r3, 8
 9d6:	6c4b      	mov      	r1, r2
 9d8:	3001      	movi      	r0, 1
 9da:	e0000000 	bsr      	0x0	// 0 <memory_read>
 9de:	ea00b71b 	movi      	r0, 46875
 9e2:	c5604900 	rotli      	r0, r0, 11
 9e6:	e0000000 	bsr      	0x0	// 0 <memory_read>
 9ea:	3300      	movi      	r3, 0
 9ec:	2b00      	subi      	r3, 1
 9ee:	64c2      	cmpne      	r0, r3
 9f0:	0802      	bt      	0x9f4	// 9f4 <system_exit_sleep+0x38>
 9f2:	0400      	br      	0x9f2	// 9f2 <system_exit_sleep+0x36>
 9f4:	e0000000 	bsr      	0x0	// 310 <tsensor_open>
 9f8:	107a      	lrw      	r3, 0x40026000	// a60 <system_exit_sleep+0xa4>
 9fa:	3001      	movi      	r0, 1
 9fc:	9345      	ld.w      	r2, (r3, 0x14)
 9fe:	3abc      	bseti      	r2, 28
 a00:	b345      	st.w      	r2, (r3, 0x14)
 a02:	9345      	ld.w      	r2, (r3, 0x14)
 a04:	3abb      	bseti      	r2, 27
 a06:	b345      	st.w      	r2, (r3, 0x14)
 a08:	9345      	ld.w      	r2, (r3, 0x14)
 a0a:	3aba      	bseti      	r2, 26
 a0c:	b345      	st.w      	r2, (r3, 0x14)
 a0e:	9345      	ld.w      	r2, (r3, 0x14)
 a10:	3abd      	bseti      	r2, 29
 a12:	b345      	st.w      	r2, (r3, 0x14)
 a14:	9345      	ld.w      	r2, (r3, 0x14)
 a16:	3ab3      	bseti      	r2, 19
 a18:	b345      	st.w      	r2, (r3, 0x14)
 a1a:	9345      	ld.w      	r2, (r3, 0x14)
 a1c:	ec428000 	ori      	r2, r2, 32768
 a20:	b345      	st.w      	r2, (r3, 0x14)
 a22:	9345      	ld.w      	r2, (r3, 0x14)
 a24:	ec420800 	ori      	r2, r2, 2048
 a28:	b345      	st.w      	r2, (r3, 0x14)
 a2a:	9345      	ld.w      	r2, (r3, 0x14)
 a2c:	ec420200 	ori      	r2, r2, 512
 a30:	b345      	st.w      	r2, (r3, 0x14)
 a32:	9345      	ld.w      	r2, (r3, 0x14)
 a34:	ec420100 	ori      	r2, r2, 256
 a38:	b345      	st.w      	r2, (r3, 0x14)
 a3a:	9345      	ld.w      	r2, (r3, 0x14)
 a3c:	ec420020 	ori      	r2, r2, 32
 a40:	b345      	st.w      	r2, (r3, 0x14)
 a42:	9345      	ld.w      	r2, (r3, 0x14)
 a44:	ec420010 	ori      	r2, r2, 16
 a48:	b345      	st.w      	r2, (r3, 0x14)
 a4a:	9345      	ld.w      	r2, (r3, 0x14)
 a4c:	ec420001 	ori      	r2, r2, 1
 a50:	b345      	st.w      	r2, (r3, 0x14)
 a52:	9347      	ld.w      	r2, (r3, 0x1c)
 a54:	3ab2      	bseti      	r2, 18
 a56:	b347      	st.w      	r2, (r3, 0x1c)
 a58:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
 a5c:	1490      	pop      	r15
 a5e:	0000      	.short	0x0000
 a60:	40026000 	.long	0x40026000

Disassembly of section .text.rf_para_efuse_check_valid:

00000000 <rf_para_efuse_check_valid>:
   0:	14d0      	push      	r15
   2:	1421      	subi      	r14, r14, 4
   4:	e42e0002 	addi      	r1, r14, 3
   8:	3201      	movi      	r2, 1
   a:	30b3      	movi      	r0, 179
   c:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
  10:	d86e0003 	ld.b      	r3, (r14, 0x3)
  14:	eb430055 	cmpnei      	r3, 85
  18:	64c3      	mvcv      	r3
  1a:	1043      	lrw      	r2, 0x0	// 24 <rf_para_efuse_check_valid+0x24>
  1c:	2b00      	subi      	r3, 1
  1e:	a263      	st.b      	r3, (r2, 0x3)
  20:	1401      	addi      	r14, r14, 4
  22:	1490      	pop      	r15
  24:	00000000 	.long	0x00000000

Disassembly of section .text.xo_cs_store:

00000000 <xo_cs_store>:
   0:	14d0      	push      	r15
   2:	1421      	subi      	r14, r14, 4
   4:	b800      	st.w      	r0, (r14, 0x0)
   6:	3201      	movi      	r2, 1
   8:	6c7b      	mov      	r1, r14
   a:	3007      	movi      	r0, 7
   c:	e0000000 	bsr      	0x0	// 38 <memory_write>
  10:	1401      	addi      	r14, r14, 4
  12:	1490      	pop      	r15

Disassembly of section .text.sysctrl_get_xo_drcs:

00000000 <sysctrl_get_xo_drcs>:
   0:	ea038003 	movi      	r3, 32771
   4:	c5e34903 	rotli      	r3, r3, 15
   8:	930a      	ld.w      	r0, (r3, 0x28)
   a:	936a      	ld.w      	r3, (r3, 0x28)
   c:	4b78      	lsri      	r3, r3, 24
   e:	4365      	lsli      	r3, r3, 5
  10:	c66056e0 	zext      	r0, r0, 23, 19
  14:	6c0c      	or      	r0, r3
  16:	783c      	jmp      	r15

Disassembly of section .text.sysctrl_set_xo_drcs:

00000000 <sysctrl_set_xo_drcs>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	c5005580 	zext      	r0, r0, 12, 8
   8:	e0000000 	bsr      	0x0	// 0 <sysctrl_set_xo_drcs>
   c:	7410      	zextb      	r0, r4
   e:	e0000000 	bsr      	0x0	// 0 <sysctrl_set_xo_drcs>
  12:	3000      	movi      	r0, 0
  14:	1491      	pop      	r4, r15

Disassembly of section .text.sysctrl_set_xo_fx2:

00000000 <sysctrl_set_xo_fx2>:
   0:	14d1      	push      	r4, r15
   2:	3841      	cmpnei      	r0, 1
   4:	080d      	bt      	0x1e	// 1e <sysctrl_set_xo_fx2+0x1e>
   6:	ea038003 	movi      	r3, 32771
   a:	c5e34903 	rotli      	r3, r3, 15
   e:	932a      	ld.w      	r1, (r3, 0x28)
  10:	ec210080 	ori      	r1, r1, 128
  14:	3028      	movi      	r0, 40
  16:	e0000000 	bsr      	0x0	// 0 <sysctrl_set_xo_fx2>
  1a:	3000      	movi      	r0, 0
  1c:	1491      	pop      	r4, r15
  1e:	e9200009 	bnez      	r0, 0x30	// 30 <sysctrl_set_xo_fx2+0x30>
  22:	ea038003 	movi      	r3, 32771
  26:	c5e34903 	rotli      	r3, r3, 15
  2a:	932a      	ld.w      	r1, (r3, 0x28)
  2c:	3987      	bclri      	r1, 7
  2e:	07f3      	br      	0x14	// 14 <sysctrl_set_xo_fx2+0x14>
  30:	3000      	movi      	r0, 0
  32:	2800      	subi      	r0, 1
  34:	07f4      	br      	0x1c	// 1c <sysctrl_set_xo_fx2+0x1c>

Disassembly of section .text.adc_calib_res_restore:

00000000 <adc_calib_res_restore>:
   0:	14d3      	push      	r4-r6, r15
   2:	3402      	movi      	r4, 2
   4:	3500      	movi      	r5, 0
   6:	10d6      	lrw      	r6, 0x0	// 5c <adc_calib_res_restore+0x5c>
   8:	d0a60881 	ldr.w      	r1, (r6, r5 << 2)
   c:	6c13      	mov      	r0, r4
   e:	2500      	addi      	r5, 1
  10:	e0000000 	bsr      	0x0	// 0 <adc_calib_res_restore>
  14:	3d58      	cmpnei      	r5, 24
  16:	2400      	addi      	r4, 1
  18:	7510      	zextb      	r4, r4
  1a:	0bf7      	bt      	0x8	// 8 <adc_calib_res_restore+0x8>
  1c:	1091      	lrw      	r4, 0x40026000	// 60 <adc_calib_res_restore+0x60>
  1e:	310f      	movi      	r1, 15
  20:	9467      	ld.w      	r3, (r4, 0x1c)
  22:	3bb4      	bseti      	r3, 20
  24:	b467      	st.w      	r3, (r4, 0x1c)
  26:	9467      	ld.w      	r3, (r4, 0x1c)
  28:	ec630200 	ori      	r3, r3, 512
  2c:	b467      	st.w      	r3, (r4, 0x1c)
  2e:	9467      	ld.w      	r3, (r4, 0x1c)
  30:	3bb3      	bseti      	r3, 19
  32:	b467      	st.w      	r3, (r4, 0x1c)
  34:	9467      	ld.w      	r3, (r4, 0x1c)
  36:	3bb2      	bseti      	r3, 18
  38:	b467      	st.w      	r3, (r4, 0x1c)
  3a:	3000      	movi      	r0, 0
  3c:	e0000000 	bsr      	0x0	// 0 <adc_calib_res_restore>
  40:	3000      	movi      	r0, 0
  42:	e0000000 	bsr      	0x0	// 0 <adc_calib_res_restore>
  46:	ea228020 	movih      	r2, 32800
  4a:	9467      	ld.w      	r3, (r4, 0x1c)
  4c:	2a00      	subi      	r2, 1
  4e:	68c8      	and      	r3, r2
  50:	b467      	st.w      	r3, (r4, 0x1c)
  52:	9467      	ld.w      	r3, (r4, 0x1c)
  54:	3bb5      	bseti      	r3, 21
  56:	3bba      	bseti      	r3, 26
  58:	b467      	st.w      	r3, (r4, 0x1c)
  5a:	1493      	pop      	r4-r6, r15
  5c:	00000000 	.long	0x00000000
  60:	40026000 	.long	0x40026000

Disassembly of section .text.tx_digi_gain_store:

00000000 <tx_digi_gain_store>:
   0:	14d0      	push      	r15
   2:	1421      	subi      	r14, r14, 4
   4:	b800      	st.w      	r0, (r14, 0x0)
   6:	3201      	movi      	r2, 1
   8:	6c7b      	mov      	r1, r14
   a:	3008      	movi      	r0, 8
   c:	e0000000 	bsr      	0x0	// 38 <memory_write>
  10:	1401      	addi      	r14, r14, 4
  12:	1490      	pop      	r15

Disassembly of section .text.sysctrl_internal_rf_sel_lo_freq:

00000000 <sysctrl_internal_rf_sel_lo_freq>:
   0:	380f      	cmphsi      	r0, 16
   2:	081d      	bt      	0x3c	// 3c <sysctrl_internal_rf_sel_lo_freq+0x3c>
   4:	1070      	lrw      	r3, 0x40026000	// 44 <sysctrl_internal_rf_sel_lo_freq+0x44>
   6:	31f0      	movi      	r1, 240
   8:	9341      	ld.w      	r2, (r3, 0x4)
   a:	4138      	lsli      	r1, r1, 24
   c:	6c84      	or      	r2, r1
   e:	b341      	st.w      	r2, (r3, 0x4)
  10:	6c03      	mov      	r0, r0
  12:	6c03      	mov      	r0, r0
  14:	6c03      	mov      	r0, r0
  16:	6c03      	mov      	r0, r0
  18:	6c03      	mov      	r0, r0
  1a:	6c03      	mov      	r0, r0
  1c:	9341      	ld.w      	r2, (r3, 0x4)
  1e:	c4025762 	zext      	r2, r2, 27, 0
  22:	b341      	st.w      	r2, (r3, 0x4)
  24:	6c03      	mov      	r0, r0
  26:	6c03      	mov      	r0, r0
  28:	6c03      	mov      	r0, r0
  2a:	6c03      	mov      	r0, r0
  2c:	6c03      	mov      	r0, r0
  2e:	6c03      	mov      	r0, r0
  30:	9341      	ld.w      	r2, (r3, 0x4)
  32:	401c      	lsli      	r0, r0, 28
  34:	6c08      	or      	r0, r2
  36:	b301      	st.w      	r0, (r3, 0x4)
  38:	3000      	movi      	r0, 0
  3a:	783c      	jmp      	r15
  3c:	3000      	movi      	r0, 0
  3e:	2815      	subi      	r0, 22
  40:	07fd      	br      	0x3a	// 3a <sysctrl_internal_rf_sel_lo_freq+0x3a>
  42:	0000      	.short	0x0000
  44:	40026000 	.long	0x40026000

Disassembly of section .text.sysctrl_err_resp_usb_bus:

00000000 <sysctrl_err_resp_usb_bus>:
   0:	1066      	lrw      	r3, 0x40026000	// 18 <sysctrl_err_resp_usb_bus+0x18>
   2:	9352      	ld.w      	r2, (r3, 0x48)
   4:	e9000006 	bez      	r0, 0x10	// 10 <sysctrl_err_resp_usb_bus+0x10>
   8:	3abf      	bseti      	r2, 31
   a:	3000      	movi      	r0, 0
   c:	b352      	st.w      	r2, (r3, 0x48)
   e:	783c      	jmp      	r15
  10:	c40257c2 	zext      	r2, r2, 30, 0
  14:	07fb      	br      	0xa	// a <sysctrl_err_resp_usb_bus+0xa>
  16:	0000      	.short	0x0000
  18:	6000      	.short	0x6000
  1a:	4002      	.short	0x4002

Disassembly of section .text.sysctrl_err_resp_icode_bus:

00000000 <sysctrl_err_resp_icode_bus>:
   0:	1065      	lrw      	r3, 0x40026000	// 14 <sysctrl_err_resp_icode_bus+0x14>
   2:	9352      	ld.w      	r2, (r3, 0x48)
   4:	e9000006 	bez      	r0, 0x10	// 10 <sysctrl_err_resp_icode_bus+0x10>
   8:	3abb      	bseti      	r2, 27
   a:	3000      	movi      	r0, 0
   c:	b352      	st.w      	r2, (r3, 0x48)
   e:	783c      	jmp      	r15
  10:	3a9b      	bclri      	r2, 27
  12:	07fc      	br      	0xa	// a <sysctrl_err_resp_icode_bus+0xa>
  14:	6000      	.short	0x6000
  16:	4002      	.short	0x4002

Disassembly of section .text.sysctrl_err_resp_dcode_bus:

00000000 <sysctrl_err_resp_dcode_bus>:
   0:	1065      	lrw      	r3, 0x40026000	// 14 <sysctrl_err_resp_dcode_bus+0x14>
   2:	9352      	ld.w      	r2, (r3, 0x48)
   4:	e9000006 	bez      	r0, 0x10	// 10 <sysctrl_err_resp_dcode_bus+0x10>
   8:	3abc      	bseti      	r2, 28
   a:	3000      	movi      	r0, 0
   c:	b352      	st.w      	r2, (r3, 0x48)
   e:	783c      	jmp      	r15
  10:	3a9c      	bclri      	r2, 28
  12:	07fc      	br      	0xa	// a <sysctrl_err_resp_dcode_bus+0xa>
  14:	6000      	.short	0x6000
  16:	4002      	.short	0x4002

Disassembly of section .text.sysctrl_err_resp_ahb2dma_bus:

00000000 <sysctrl_err_resp_ahb2dma_bus>:
   0:	1065      	lrw      	r3, 0x40026000	// 14 <sysctrl_err_resp_ahb2dma_bus+0x14>
   2:	9352      	ld.w      	r2, (r3, 0x48)
   4:	e9000006 	bez      	r0, 0x10	// 10 <sysctrl_err_resp_ahb2dma_bus+0x10>
   8:	3abd      	bseti      	r2, 29
   a:	3000      	movi      	r0, 0
   c:	b352      	st.w      	r2, (r3, 0x48)
   e:	783c      	jmp      	r15
  10:	3a9d      	bclri      	r2, 29
  12:	07fc      	br      	0xa	// a <sysctrl_err_resp_ahb2dma_bus+0xa>
  14:	6000      	.short	0x6000
  16:	4002      	.short	0x4002

Disassembly of section .text.sysctrl_err_resp_sdiodevice_bus:

00000000 <sysctrl_err_resp_sdiodevice_bus>:
   0:	1065      	lrw      	r3, 0x40026000	// 14 <sysctrl_err_resp_sdiodevice_bus+0x14>
   2:	9352      	ld.w      	r2, (r3, 0x48)
   4:	e9000006 	bez      	r0, 0x10	// 10 <sysctrl_err_resp_sdiodevice_bus+0x10>
   8:	3abe      	bseti      	r2, 30
   a:	3000      	movi      	r0, 0
   c:	b352      	st.w      	r2, (r3, 0x48)
   e:	783c      	jmp      	r15
  10:	3a9e      	bclri      	r2, 30
  12:	07fc      	br      	0xa	// a <sysctrl_err_resp_sdiodevice_bus+0xa>
  14:	6000      	.short	0x6000
  16:	4002      	.short	0x4002

Disassembly of section .text.sysctrl_err_resp_disable:

00000000 <sysctrl_err_resp_disable>:
   0:	1044      	lrw      	r2, 0x40026000	// 10 <sysctrl_err_resp_disable+0x10>
   2:	3000      	movi      	r0, 0
   4:	9272      	ld.w      	r3, (r2, 0x48)
   6:	c4035743 	zext      	r3, r3, 26, 0
   a:	b272      	st.w      	r3, (r2, 0x48)
   c:	783c      	jmp      	r15
   e:	0000      	.short	0x0000
  10:	40026000 	.long	0x40026000

Disassembly of section .text.adkey_set_period:

00000000 <adkey_set_period>:
   0:	1066      	lrw      	r3, 0x4001a000	// 18 <adkey_set_period+0x18>
   2:	4010      	lsli      	r0, r0, 16
   4:	9340      	ld.w      	r2, (r3, 0x0)
   6:	c40255e2 	zext      	r2, r2, 15, 0
   a:	b340      	st.w      	r2, (r3, 0x0)
   c:	9340      	ld.w      	r2, (r3, 0x0)
   e:	c4005760 	zext      	r0, r0, 27, 0
  12:	6c08      	or      	r0, r2
  14:	b300      	st.w      	r0, (r3, 0x0)
  16:	783c      	jmp      	r15
  18:	a000      	.short	0xa000
  1a:	4001      	.short	0x4001

Disassembly of section .text.adkey_set_baud:

00000000 <adkey_set_baud>:
   0:	1067      	lrw      	r3, 0x4001a000	// 1c <adkey_set_baud+0x1c>
   2:	31f0      	movi      	r1, 240
   4:	9341      	ld.w      	r2, (r3, 0x4)
   6:	4138      	lsli      	r1, r1, 24
   8:	6884      	and      	r2, r1
   a:	b341      	st.w      	r2, (r3, 0x4)
   c:	c7605021 	bmaski      	r1, 28
  10:	9341      	ld.w      	r2, (r3, 0x4)
  12:	6804      	and      	r0, r1
  14:	6c08      	or      	r0, r2
  16:	b301      	st.w      	r0, (r3, 0x4)
  18:	783c      	jmp      	r15
  1a:	0000      	.short	0x0000
  1c:	4001a000 	.long	0x4001a000

Disassembly of section .text.pmu_iref_en_sec:

00000000 <pmu_iref_en_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3020      	movi      	r0, 32
   c:	9328      	ld.w      	r1, (r3, 0x20)
   e:	ec210010 	ori      	r1, r1, 16
  12:	e0000000 	bsr      	0x0	// 0 <pmu_iref_en_sec>
  16:	1490      	pop      	r15

Disassembly of section .text.pmu_iref_dis_sec:

00000000 <pmu_iref_dis_sec>:
   0:	14d0      	push      	r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	3020      	movi      	r0, 32
   c:	9328      	ld.w      	r1, (r3, 0x20)
   e:	3984      	bclri      	r1, 4
  10:	e0000000 	bsr      	0x0	// 0 <pmu_iref_dis_sec>
  14:	1490      	pop      	r15

Disassembly of section .text.adkey_select_channel:

00000000 <adkey_select_channel>:
   0:	104c      	lrw      	r2, 0x4001a000	// 30 <adkey_select_channel+0x30>
   2:	3100      	movi      	r1, 0
   4:	9260      	ld.w      	r3, (r2, 0x0)
   6:	293f      	subi      	r1, 64
   8:	385f      	cmpnei      	r0, 31
   a:	68c4      	and      	r3, r1
   c:	b260      	st.w      	r3, (r2, 0x0)
   e:	0c05      	bf      	0x18	// 18 <adkey_select_channel+0x18>
  10:	381f      	cmphsi      	r0, 32
  12:	0809      	bt      	0x24	// 24 <adkey_select_channel+0x24>
  14:	380b      	cmphsi      	r0, 12
  16:	080a      	bt      	0x2a	// 2a <adkey_select_channel+0x2a>
  18:	1066      	lrw      	r3, 0x4001a000	// 30 <adkey_select_channel+0x30>
  1a:	9340      	ld.w      	r2, (r3, 0x0)
  1c:	6c08      	or      	r0, r2
  1e:	b300      	st.w      	r0, (r3, 0x0)
  20:	3000      	movi      	r0, 0
  22:	783c      	jmp      	r15
  24:	eb40002f 	cmpnei      	r0, 47
  28:	07f7      	br      	0x16	// 16 <adkey_select_channel+0x16>
  2a:	3000      	movi      	r0, 0
  2c:	2815      	subi      	r0, 22
  2e:	07fa      	br      	0x22	// 22 <adkey_select_channel+0x22>
  30:	a000      	.short	0xa000
  32:	4001      	.short	0x4001

Disassembly of section .text.gpio_enable:

00000000 <gpio_enable>:
   0:	3000      	movi      	r0, 0
   2:	783c      	jmp      	r15

Disassembly of section .text.sys_get_apbclk:

00000000 <sys_get_apbclk>:
   0:	1062      	lrw      	r3, 0x0	// 8 <sys_get_apbclk+0x8>
   2:	9300      	ld.w      	r0, (r3, 0x0)
   4:	783c      	jmp      	r15
   6:	0000      	.short	0x0000
   8:	0000      	.short	0x0000
	...

Disassembly of section .text.sys_get_sysclk:

00000000 <sys_get_sysclk>:
   0:	1062      	lrw      	r3, 0x0	// 8 <sys_get_sysclk+0x8>
   2:	9300      	ld.w      	r0, (r3, 0x0)
   4:	783c      	jmp      	r15
   6:	0000      	.short	0x0000
   8:	0000      	.short	0x0000
	...

Disassembly of section .text.sys_set_sysclk:

00000000 <sys_set_sysclk>:
   0:	14d1      	push      	r4, r15
   2:	3100      	movi      	r1, 0
   4:	6d03      	mov      	r4, r0
   6:	6c07      	mov      	r0, r1
   8:	e0000000 	bsr      	0x0	// 0 <sys_set_sysclk>
   c:	ea03b71b 	movi      	r3, 46875
  10:	c5434903 	rotli      	r3, r3, 10
  14:	64d2      	cmpne      	r4, r3
  16:	080a      	bt      	0x2a	// 2a <sys_set_sysclk+0x2a>
  18:	3202      	movi      	r2, 2
  1a:	3103      	movi      	r1, 3
  1c:	3000      	movi      	r0, 0
  1e:	e0000000 	bsr      	0x0	// 0 <sys_set_sysclk>
  22:	1167      	lrw      	r3, 0x0	// bc <sys_set_sysclk+0xbc>
  24:	b380      	st.w      	r4, (r3, 0x0)
  26:	3000      	movi      	r0, 0
  28:	1491      	pop      	r4, r15
  2a:	1166      	lrw      	r3, 0x44aa200	// c0 <sys_set_sysclk+0xc0>
  2c:	64d2      	cmpne      	r4, r3
  2e:	0803      	bt      	0x34	// 34 <sys_set_sysclk+0x34>
  30:	3201      	movi      	r2, 1
  32:	07f4      	br      	0x1a	// 1a <sys_set_sysclk+0x1a>
  34:	1164      	lrw      	r3, 0x8954400	// c4 <sys_set_sysclk+0xc4>
  36:	64d2      	cmpne      	r4, r3
  38:	0805      	bt      	0x42	// 42 <sys_set_sysclk+0x42>
  3a:	3200      	movi      	r2, 0
  3c:	3103      	movi      	r1, 3
  3e:	6c0b      	mov      	r0, r2
  40:	07ef      	br      	0x1e	// 1e <sys_set_sysclk+0x1e>
  42:	1162      	lrw      	r3, 0xfc2f7000	// c8 <sys_set_sysclk+0xc8>
  44:	5c4c      	addu      	r2, r4, r3
  46:	1162      	lrw      	r3, 0x1e847ff	// cc <sys_set_sysclk+0xcc>
  48:	648c      	cmphs      	r3, r2
  4a:	0c14      	bf      	0x72	// 72 <sys_set_sysclk+0x72>
  4c:	3303      	movi      	r3, 3
  4e:	ea02f424 	movi      	r2, 62500
  52:	c5224902 	rotli      	r2, r2, 9
  56:	7cd0      	mult      	r3, r4
  58:	c4438023 	divu      	r3, r3, r2
  5c:	2b00      	subi      	r3, 1
  5e:	3200      	movi      	r2, 0
  60:	6c4b      	mov      	r1, r2
  62:	3001      	movi      	r0, 1
  64:	74cc      	zextb      	r3, r3
  66:	e0000000 	bsr      	0x0	// 0 <sys_set_sysclk>
  6a:	3200      	movi      	r2, 0
  6c:	3102      	movi      	r1, 2
  6e:	3001      	movi      	r0, 1
  70:	07d7      	br      	0x1e	// 1e <sys_set_sysclk+0x1e>
  72:	1078      	lrw      	r3, 0xfa472800	// d0 <sys_set_sysclk+0xd0>
  74:	5c4c      	addu      	r2, r4, r3
  76:	ea03b71b 	movi      	r3, 46875
  7a:	c5634903 	rotli      	r3, r3, 11
  7e:	648c      	cmphs      	r3, r2
  80:	ea02f424 	movi      	r2, 62500
  84:	c5224902 	rotli      	r2, r2, 9
  88:	0c0e      	bf      	0xa4	// a4 <sys_set_sysclk+0xa4>
  8a:	5c70      	addu      	r3, r4, r4
  8c:	c4438023 	divu      	r3, r3, r2
  90:	2b00      	subi      	r3, 1
  92:	3200      	movi      	r2, 0
  94:	6c4b      	mov      	r1, r2
  96:	74cc      	zextb      	r3, r3
  98:	3001      	movi      	r0, 1
  9a:	e0000000 	bsr      	0x0	// 0 <sys_set_sysclk>
  9e:	3200      	movi      	r2, 0
  a0:	3102      	movi      	r1, 2
  a2:	07ce      	br      	0x3e	// 3e <sys_set_sysclk+0x3e>
  a4:	6492      	cmpne      	r4, r2
  a6:	0807      	bt      	0xb4	// b4 <sys_set_sysclk+0xb4>
  a8:	3200      	movi      	r2, 0
  aa:	3101      	movi      	r1, 1
  ac:	6c0b      	mov      	r0, r2
  ae:	e0000000 	bsr      	0x0	// 0 <sys_set_sysclk>
  b2:	07ba      	br      	0x26	// 26 <sys_set_sysclk+0x26>
  b4:	3000      	movi      	r0, 0
  b6:	2800      	subi      	r0, 1
  b8:	07b8      	br      	0x28	// 28 <sys_set_sysclk+0x28>
  ba:	0000      	.short	0x0000
  bc:	00000000 	.long	0x00000000
  c0:	044aa200 	.long	0x044aa200
  c4:	08954400 	.long	0x08954400
  c8:	fc2f7000 	.long	0xfc2f7000
  cc:	01e847ff 	.long	0x01e847ff
  d0:	fa472800 	.long	0xfa472800

Disassembly of section .text.adkey_init:

00000000 <adkey_init>:
   0:	14d1      	push      	r4, r15
   2:	109c      	lrw      	r4, 0x4001a000	// 70 <adkey_init+0x70>
   4:	301e      	movi      	r0, 30
   6:	9460      	ld.w      	r3, (r4, 0x0)
   8:	ec630040 	ori      	r3, r3, 64
   c:	b460      	st.w      	r3, (r4, 0x0)
   e:	e0000000 	bsr      	0x0	// 0 <delay_us>
  12:	9461      	ld.w      	r3, (r4, 0x4)
  14:	3bbe      	bseti      	r3, 30
  16:	b461      	st.w      	r3, (r4, 0x4)
  18:	9461      	ld.w      	r3, (r4, 0x4)
  1a:	3bbc      	bseti      	r3, 28
  1c:	b461      	st.w      	r3, (r4, 0x4)
  1e:	301e      	movi      	r0, 30
  20:	e0000000 	bsr      	0x0	// 0 <delay_us>
  24:	9461      	ld.w      	r3, (r4, 0x4)
  26:	3bbd      	bseti      	r3, 29
  28:	b461      	st.w      	r3, (r4, 0x4)
  2a:	9460      	ld.w      	r3, (r4, 0x0)
  2c:	ec630080 	ori      	r3, r3, 128
  30:	b460      	st.w      	r3, (r4, 0x0)
  32:	301e      	movi      	r0, 30
  34:	e0000000 	bsr      	0x0	// 0 <delay_us>
  38:	9460      	ld.w      	r3, (r4, 0x0)
  3a:	3b89      	bclri      	r3, 9
  3c:	b460      	st.w      	r3, (r4, 0x0)
  3e:	9460      	ld.w      	r3, (r4, 0x0)
  40:	3b8a      	bclri      	r3, 10
  42:	b460      	st.w      	r3, (r4, 0x0)
  44:	9460      	ld.w      	r3, (r4, 0x0)
  46:	3b8d      	bclri      	r3, 13
  48:	b460      	st.w      	r3, (r4, 0x0)
  4a:	ea03c350 	movi      	r3, 50000
  4e:	c4634903 	rotli      	r3, r3, 3
  52:	1089      	lrw      	r4, 0x0	// 74 <adkey_init+0x74>
  54:	9400      	ld.w      	r0, (r4, 0x0)
  56:	c4608040 	divs      	r0, r0, r3
  5a:	7401      	zexth      	r0, r0
  5c:	e0000000 	bsr      	0x0	// 0 <adkey_init>
  60:	9400      	ld.w      	r0, (r4, 0x0)
  62:	ea034e20 	movi      	r3, 20000
  66:	c4608040 	divs      	r0, r0, r3
  6a:	e0000000 	bsr      	0x0	// 0 <adkey_init>
  6e:	1491      	pop      	r4, r15
  70:	4001a000 	.long	0x4001a000
  74:	00000000 	.long	0x00000000

Disassembly of section .text.adkey_meas_kick:

00000000 <adkey_meas_kick>:
   0:	14d2      	push      	r4-r5, r15
   2:	1093      	lrw      	r4, 0x4001a000	// 4c <adkey_meas_kick+0x4c>
   4:	6d43      	mov      	r5, r0
   6:	9460      	ld.w      	r3, (r4, 0x0)
   8:	ec630100 	ori      	r3, r3, 256
   c:	b460      	st.w      	r3, (r4, 0x0)
   e:	301e      	movi      	r0, 30
  10:	e0000000 	bsr      	0x0	// 0 <delay_us>
  14:	6c17      	mov      	r0, r5
  16:	e0000000 	bsr      	0x0	// 0 <adkey_meas_kick>
  1a:	3032      	movi      	r0, 50
  1c:	e0000000 	bsr      	0x0	// 0 <delay_us>
  20:	9460      	ld.w      	r3, (r4, 0x0)
  22:	ec631000 	ori      	r3, r3, 4096
  26:	b460      	st.w      	r3, (r4, 0x0)
  28:	3064      	movi      	r0, 100
  2a:	e0000000 	bsr      	0x0	// 0 <delay_us>
  2e:	9460      	ld.w      	r3, (r4, 0x0)
  30:	9402      	ld.w      	r0, (r4, 0x8)
  32:	9460      	ld.w      	r3, (r4, 0x0)
  34:	3b8e      	bclri      	r3, 14
  36:	b460      	st.w      	r3, (r4, 0x0)
  38:	9460      	ld.w      	r3, (r4, 0x0)
  3a:	3b8c      	bclri      	r3, 12
  3c:	b460      	st.w      	r3, (r4, 0x0)
  3e:	9460      	ld.w      	r3, (r4, 0x0)
  40:	3b88      	bclri      	r3, 8
  42:	e40023ff 	andi      	r0, r0, 1023
  46:	b460      	st.w      	r3, (r4, 0x0)
  48:	1492      	pop      	r4-r5, r15
  4a:	0000      	.short	0x0000
  4c:	a000      	.short	0xa000
  4e:	4001      	.short	0x4001

Disassembly of section .text.io_input_meas_mv:

00000000 <io_input_meas_mv>:
   0:	14d0      	push      	r15
   2:	301f      	movi      	r0, 31
   4:	e0000000 	bsr      	0x0	// 0 <io_input_meas_mv>
   8:	ea03c8e0 	movi      	r3, 51424
   c:	3bb4      	bseti      	r3, 20
   e:	7c0c      	mult      	r0, r3
  10:	32fa      	movi      	r2, 250
  12:	486a      	lsri      	r3, r0, 10
  14:	4242      	lsli      	r2, r2, 2
  16:	c4438021 	divu      	r1, r3, r2
  1a:	7c84      	mult      	r2, r1
  1c:	60ca      	subu      	r3, r2
  1e:	eb0301f4 	cmphsi      	r3, 501
  22:	33fa      	movi      	r3, 250
  24:	436c      	lsli      	r3, r3, 12
  26:	c4608020 	divu      	r0, r0, r3
  2a:	0c02      	bf      	0x2e	// 2e <io_input_meas_mv+0x2e>
  2c:	2000      	addi      	r0, 1
  2e:	1490      	pop      	r15

Disassembly of section .text.mcu_reset:

00000000 <mcu_reset>:
   0:	c01f6023 	mfcr      	r3, cr<31, 0>
   4:	ea025432 	movi      	r2, 21554
   8:	6c8a      	nor      	r2, r2
   a:	c4625df0 	ins      	r3, r2, 31, 16
   e:	c0000420 	sync
  12:	c003643f 	mtcr      	r3, cr<31, 0>
  16:	c0000420 	sync
  1a:	6c03      	mov      	r0, r0
  1c:	07ff      	br      	0x1a	// 1a <mcu_reset+0x1a>

Disassembly of section .text.mcu_watchdog_timeout:

00000000 <mcu_watchdog_timeout>:
   0:	e9000014 	bez      	r0, 0x28	// 28 <mcu_watchdog_timeout+0x28>
   4:	3206      	movi      	r2, 6
   6:	4801      	lsri      	r0, r0, 1
   8:	2200      	addi      	r2, 1
   a:	e920fffe 	bnez      	r0, 0x6	// 6 <mcu_watchdog_timeout+0x6>
   e:	102a      	lrw      	r1, 0x40013000	// 34 <mcu_watchdog_timeout+0x34>
  10:	3000      	movi      	r0, 0
  12:	9160      	ld.w      	r3, (r1, 0x0)
  14:	280f      	subi      	r0, 16
  16:	68c0      	and      	r3, r0
  18:	e442200f 	andi      	r2, r2, 15
  1c:	6cc8      	or      	r3, r2
  1e:	b160      	st.w      	r3, (r1, 0x0)
  20:	ea03cccc 	movi      	r3, 52428
  24:	b161      	st.w      	r3, (r1, 0x4)
  26:	783c      	jmp      	r15
  28:	1063      	lrw      	r3, 0x40013000	// 34 <mcu_watchdog_timeout+0x34>
  2a:	ea02dddd 	movi      	r2, 56797
  2e:	b341      	st.w      	r2, (r3, 0x4)
  30:	07fb      	br      	0x26	// 26 <mcu_watchdog_timeout+0x26>
  32:	0000      	.short	0x0000
  34:	40013000 	.long	0x40013000

Disassembly of section .text.mcu_watchdog_feed:

00000000 <mcu_watchdog_feed>:
   0:	1063      	lrw      	r3, 0x40013000	// c <mcu_watchdog_feed+0xc>
   2:	ea02aaaa 	movi      	r2, 43690
   6:	b341      	st.w      	r2, (r3, 0x4)
   8:	783c      	jmp      	r15
   a:	0000      	.short	0x0000
   c:	3000      	.short	0x3000
   e:	4001      	.short	0x4001

Disassembly of section .text.lvd_irq_handler:

00000000 <lvd_irq_handler>:
   0:	14d1      	push      	r4, r15
   2:	ea038003 	movi      	r3, 32771
   6:	c5e34903 	rotli      	r3, r3, 15
   a:	9380      	ld.w      	r4, (r3, 0x0)
   c:	33ff      	movi      	r3, 255
   e:	4378      	lsli      	r3, r3, 24
  10:	68d0      	and      	r3, r4
  12:	e9230006 	bnez      	r3, 0x1e	// 1e <lvd_irq_handler+0x1e>
  16:	100f      	lrw      	r0, 0x0	// 50 <hgprintf+0x50>
  18:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  1c:	1491      	pop      	r4, r15
  1e:	3380      	movi      	r3, 128
  20:	4377      	lsli      	r3, r3, 23
  22:	68d0      	and      	r3, r4
  24:	e9030005 	bez      	r3, 0x2e	// 2e <lvd_irq_handler+0x2e>
  28:	100b      	lrw      	r0, 0x0	// 54 <hgprintf+0x54>
  2a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  2e:	3380      	movi      	r3, 128
  30:	4376      	lsli      	r3, r3, 22
  32:	68d0      	and      	r3, r4
  34:	e9030005 	bez      	r3, 0x3e	// 3e <lvd_irq_handler+0x3e>
  38:	1008      	lrw      	r0, 0x0	// 58 <hgprintf+0x58>
  3a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  3e:	c6e05023 	bmaski      	r3, 24
  42:	c4642021 	and      	r1, r4, r3
  46:	3000      	movi      	r0, 0
  48:	e0000000 	bsr      	0x0	// 0 <lvd_irq_handler>
  4c:	07e8      	br      	0x1c	// 1c <lvd_irq_handler+0x1c>
	...

Disassembly of section .text.pd_timer_init:

00000000 <pd_timer_init>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <pd_timer_init>
   6:	3004      	movi      	r0, 4
   8:	e0000000 	bsr      	0x0	// 0 <pd_timer_init>
   c:	e0000000 	bsr      	0x0	// 0 <pd_timer_init>
  10:	ea028003 	movi      	r2, 32771
  14:	c5e24902 	rotli      	r2, r2, 15
  18:	d8622023 	ld.w      	r3, (r2, 0x8c)
  1c:	e4632001 	andi      	r3, r3, 1
  20:	e923fffc 	bnez      	r3, 0x18	// 18 <pd_timer_init+0x18>
  24:	e0000000 	bsr      	0x0	// 0 <pd_timer_init>
  28:	1490      	pop      	r15

Disassembly of section .text.pd_timer_start:

00000000 <pd_timer_start>:
   0:	14d0      	push      	r15
   2:	1421      	subi      	r14, r14, 4
   4:	b800      	st.w      	r0, (r14, 0x0)
   6:	e0000000 	bsr      	0x0	// 0 <pd_timer_start>
   a:	9800      	ld.w      	r0, (r14, 0x0)
   c:	e0000000 	bsr      	0x0	// 0 <pd_timer_start>
  10:	e0000000 	bsr      	0x0	// 0 <pd_timer_start>
  14:	1401      	addi      	r14, r14, 4
  16:	1490      	pop      	r15

Disassembly of section .text.lf_timer_init:

00000000 <lf_timer_init>:
   0:	1046      	lrw      	r2, 0x40026000	// 18 <lf_timer_init+0x18>
   2:	9263      	ld.w      	r3, (r2, 0xc)
   4:	3b82      	bclri      	r3, 2
   6:	3b83      	bclri      	r3, 3
   8:	ec630004 	ori      	r3, r3, 4
   c:	b263      	st.w      	r3, (r2, 0xc)
   e:	9263      	ld.w      	r3, (r2, 0xc)
  10:	c40357a3 	zext      	r3, r3, 29, 0
  14:	b263      	st.w      	r3, (r2, 0xc)
  16:	783c      	jmp      	r15
  18:	6000      	.short	0x6000
  1a:	4002      	.short	0x4002

Disassembly of section .text.sysctrl_get_chip_id:

00000000 <sysctrl_get_chip_id>:
   0:	1062      	lrw      	r3, 0x40026000	// 8 <sysctrl_get_chip_id+0x8>
   2:	931c      	ld.w      	r0, (r3, 0x70)
   4:	7401      	zexth      	r0, r0
   6:	783c      	jmp      	r15
   8:	6000      	.short	0x6000
   a:	4002      	.short	0x4002

Disassembly of section .text.sysctrl_efuse_get_chip_uuid:

00000000 <sysctrl_efuse_get_chip_uuid>:
   0:	14d0      	push      	r15
   2:	6cc3      	mov      	r3, r0
   4:	3906      	cmphsi      	r1, 7
   6:	3006      	movi      	r0, 6
   8:	c4010c20 	incf      	r0, r1, 0
   c:	e9000008 	bez      	r0, 0x1c	// 1c <sysctrl_efuse_get_chip_uuid+0x1c>
  10:	7481      	zexth      	r2, r0
  12:	6c4f      	mov      	r1, r3
  14:	ea0001cf 	movi      	r0, 463
  18:	e0000000 	bsr      	0x0	// 90 <sysctrl_efuse_config_and_read>
  1c:	1490      	pop      	r15
