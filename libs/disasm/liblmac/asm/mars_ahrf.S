
disasm/liblmac/obj/mars_ahrf.o:     file format elf32-csky-little


Disassembly of section .text.rx_dcoc_ana_calib:

00000000 <rx_dcoc_ana_calib>:
   0:	14d6      	push      	r4-r9, r15
   2:	1422      	subi      	r14, r14, 8
   4:	6d83      	mov      	r6, r0
   6:	ea000781 	movi      	r0, 1921
   a:	6dcb      	mov      	r7, r2
   c:	6d47      	mov      	r5, r1
   e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  12:	33e0      	movi      	r3, 224
  14:	4367      	lsli      	r3, r3, 7
  16:	c4602021 	and      	r1, r0, r3
  1a:	ea000781 	movi      	r0, 1921
  1e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  22:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_dcoc_est_en>
  26:	6c3b      	mov      	r0, r14
  28:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_dcoc_est_kick_start>
  2c:	9800      	ld.w      	r0, (r14, 0x0)
  2e:	c4000202 	abs      	r2, r0
  32:	eb220117 	cmplti      	r2, 280
  36:	9821      	ld.w      	r1, (r14, 0x4)
  38:	c4010203 	abs      	r3, r1
  3c:	0c41      	bf      	0xbe	// be <rx_dcoc_ana_calib+0xbe>
  3e:	eb230117 	cmplti      	r3, 280
  42:	0848      	bt      	0xd2	// d2 <rx_dcoc_ana_calib+0xd2>
  44:	eb230179 	cmplti      	r3, 378
  48:	0849      	bt      	0xda	// da <rx_dcoc_ana_calib+0xda>
  4a:	eb23022f 	cmplti      	r3, 560
  4e:	ea0c0028 	movi      	r12, 40
  52:	3450      	movi      	r4, 80
  54:	c48c0c40 	inct      	r4, r12, 0
  58:	ea090003 	movi      	r9, 3
  5c:	eb23022f 	cmplti      	r3, 560
  60:	ea0c0002 	movi      	r12, 2
  64:	c52c0c40 	inct      	r9, r12, 0
  68:	c4828022 	divu      	r2, r2, r4
  6c:	c4838023 	divu      	r3, r3, r4
  70:	7608      	zextb      	r8, r2
  72:	750c      	zextb      	r4, r3
  74:	e9800005 	blz      	r0, 0x7e	// 7e <rx_dcoc_ana_calib+0x7e>
  78:	e508000f 	addi      	r8, r8, 16
  7c:	7620      	zextb      	r8, r8
  7e:	e9810004 	blz      	r1, 0x86	// 86 <rx_dcoc_ana_calib+0x86>
  82:	240f      	addi      	r4, 16
  84:	7510      	zextb      	r4, r4
  86:	ea000781 	movi      	r0, 1921
  8a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  8e:	c5202421 	or      	r1, r0, r9
  92:	c4484828 	lsli      	r8, r8, 2
  96:	4487      	lsli      	r4, r4, 7
  98:	6c60      	or      	r1, r8
  9a:	6c50      	or      	r1, r4
  9c:	7445      	zexth      	r1, r1
  9e:	ea000781 	movi      	r0, 1921
  a2:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  a6:	3f41      	cmpnei      	r7, 1
  a8:	0809      	bt      	0xba	// ba <rx_dcoc_ana_calib+0xba>
  aa:	3306      	movi      	r3, 6
  ac:	7d4c      	mult      	r5, r3
  ae:	6e24      	or      	r8, r9
  b0:	6194      	addu      	r6, r5
  b2:	6d20      	or      	r4, r8
  b4:	106c      	lrw      	r3, 0x0	// e4 <rx_dcoc_ana_calib+0xe4>
  b6:	d4c30444 	str.h      	r4, (r3, r6 << 1)
  ba:	1402      	addi      	r14, r14, 8
  bc:	1496      	pop      	r4-r9, r15
  be:	eb220179 	cmplti      	r2, 378
  c2:	0bc1      	bt      	0x44	// 44 <rx_dcoc_ana_calib+0x44>
  c4:	eb22022f 	cmplti      	r2, 560
  c8:	0bc1      	bt      	0x4a	// 4a <rx_dcoc_ana_calib+0x4a>
  ca:	3450      	movi      	r4, 80
  cc:	ea090003 	movi      	r9, 3
  d0:	07cc      	br      	0x68	// 68 <rx_dcoc_ana_calib+0x68>
  d2:	3414      	movi      	r4, 20
  d4:	ea090000 	movi      	r9, 0
  d8:	07c8      	br      	0x68	// 68 <rx_dcoc_ana_calib+0x68>
  da:	341b      	movi      	r4, 27
  dc:	ea090001 	movi      	r9, 1
  e0:	07c4      	br      	0x68	// 68 <rx_dcoc_ana_calib+0x68>
  e2:	0000      	.short	0x0000
  e4:	00000000 	.long	0x00000000

Disassembly of section .text.tx_ram2rf_adc_cal:

00000000 <tx_ram2rf_adc_cal>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
   6:	3001      	movi      	r0, 1
   8:	e0000000 	bsr      	0x0	// 0 <ah_set_dbgpath_device_path_mode>
   c:	3101      	movi      	r1, 1
   e:	3000      	movi      	r0, 0
  10:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_mode>
  14:	31fc      	movi      	r1, 252
  16:	1005      	lrw      	r0, 0x0	// 28 <tx_ram2rf_adc_cal+0x28>
  18:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_buff>
  1c:	e0000000 	bsr      	0x0	// 0 <ah_tdma_start>
  20:	e0000000 	bsr      	0x0	// 0 <ah_trig_dbgpath_device_dma>
  24:	1490      	pop      	r15
  26:	0000      	.short	0x0000
  28:	00000000 	.long	0x00000000

Disassembly of section .text.rx_imb_comp_inner:

00000000 <rx_imb_comp_inner>:
   0:	14d1      	push      	r4, r15
   2:	1421      	subi      	r14, r14, 4
   4:	b820      	st.w      	r1, (r14, 0x0)
   6:	6d03      	mov      	r4, r0
   8:	e0000000 	bsr      	0x0	// 0 <ah_wphy_cali_rx_imb_en>
   c:	3001      	movi      	r0, 1
   e:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rx_en>
  12:	3000      	movi      	r0, 0
  14:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  18:	3000      	movi      	r0, 0
  1a:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
  1e:	3032      	movi      	r0, 50
  20:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
  24:	9820      	ld.w      	r1, (r14, 0x0)
  26:	6c13      	mov      	r0, r4
  28:	e0000000 	bsr      	0x0	// 0 <ah_wphy_cali_rx_imb_dis>
  2c:	1066      	lrw      	r3, 0x0	// 44 <rx_imb_comp_inner+0x44>
  2e:	3000      	movi      	r0, 0
  30:	9340      	ld.w      	r2, (r3, 0x0)
  32:	926c      	ld.w      	r3, (r2, 0x30)
  34:	ec630002 	ori      	r3, r3, 2
  38:	b26c      	st.w      	r3, (r2, 0x30)
  3a:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rx_en>
  3e:	1401      	addi      	r14, r14, 4
  40:	1491      	pop      	r4, r15
  42:	0000      	.short	0x0000
  44:	00000000 	.long	0x00000000

Disassembly of section .text.override_rf_adc_cal:

00000000 <override_rf_adc_cal>:
   0:	14d3      	push      	r4-r6, r15
   2:	1179      	lrw      	r3, 0x40026000	// e4 <override_rf_adc_cal+0xe4>
   4:	3480      	movi      	r4, 128
   6:	9353      	ld.w      	r2, (r3, 0x4c)
   8:	3a97      	bclri      	r2, 23
   a:	b353      	st.w      	r2, (r3, 0x4c)
   c:	9353      	ld.w      	r2, (r3, 0x4c)
   e:	3ab7      	bseti      	r2, 23
  10:	b353      	st.w      	r2, (r3, 0x4c)
  12:	4481      	lsli      	r4, r4, 1
  14:	3500      	movi      	r5, 0
  16:	11d5      	lrw      	r6, 0x0	// e8 <override_rf_adc_cal+0xe8>
  18:	d0a60441 	ldr.h      	r1, (r6, r5 << 1)
  1c:	6c13      	mov      	r0, r4
  1e:	7445      	zexth      	r1, r1
  20:	2500      	addi      	r5, 1
  22:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  26:	eb450022 	cmpnei      	r5, 34
  2a:	2400      	addi      	r4, 1
  2c:	7511      	zexth      	r4, r4
  2e:	0bf5      	bt      	0x18	// 18 <override_rf_adc_cal+0x18>
  30:	34c0      	movi      	r4, 192
  32:	3500      	movi      	r5, 0
  34:	4482      	lsli      	r4, r4, 2
  36:	116e      	lrw      	r3, 0x0	// ec <override_rf_adc_cal+0xec>
  38:	60d4      	addu      	r3, r5
  3a:	6c13      	mov      	r0, r4
  3c:	2400      	addi      	r4, 1
  3e:	d8231087 	ld.h      	r1, (r3, 0x10e)
  42:	7511      	zexth      	r4, r4
  44:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  48:	eb440309 	cmpnei      	r4, 777
  4c:	2501      	addi      	r5, 2
  4e:	0bf4      	bt      	0x36	// 36 <override_rf_adc_cal+0x36>
  50:	1188      	lrw      	r4, 0x0	// f0 <override_rf_adc_cal+0xf0>
  52:	3088      	movi      	r0, 136
  54:	8c35      	ld.h      	r1, (r4, 0x2a)
  56:	4003      	lsli      	r0, r0, 3
  58:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  5c:	8c36      	ld.h      	r1, (r4, 0x2c)
  5e:	ea000441 	movi      	r0, 1089
  62:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  66:	8c37      	ld.h      	r1, (r4, 0x2e)
  68:	ea000442 	movi      	r0, 1090
  6c:	1182      	lrw      	r4, 0x0	// f4 <ah_rfspi_write+0xf4>
  6e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  72:	30f0      	movi      	r0, 240
  74:	d8241070 	ld.h      	r1, (r4, 0xe0)
  78:	4003      	lsli      	r0, r0, 3
  7a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  7e:	d8241071 	ld.h      	r1, (r4, 0xe2)
  82:	ea000781 	movi      	r0, 1921
  86:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  8a:	30a0      	movi      	r0, 160
  8c:	ea01ffff 	movi      	r1, 65535
  90:	4001      	lsli      	r0, r0, 1
  92:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  96:	ea01ffff 	movi      	r1, 65535
  9a:	ea000141 	movi      	r0, 321
  9e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  a2:	30a1      	movi      	r0, 161
  a4:	ea01ffff 	movi      	r1, 65535
  a8:	4001      	lsli      	r0, r0, 1
  aa:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  ae:	30c4      	movi      	r0, 196
  b0:	ea01ffff 	movi      	r1, 65535
  b4:	4002      	lsli      	r0, r0, 2
  b6:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  ba:	3089      	movi      	r0, 137
  bc:	ea01ffff 	movi      	r1, 65535
  c0:	4003      	lsli      	r0, r0, 3
  c2:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  c6:	ea01ffff 	movi      	r1, 65535
  ca:	ea000782 	movi      	r0, 1922
  ce:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  d2:	3101      	movi      	r1, 1
  d4:	302a      	movi      	r0, 42
  d6:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  da:	3100      	movi      	r1, 0
  dc:	302a      	movi      	r0, 42
  de:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  e2:	1493      	pop      	r4-r6, r15
  e4:	40026000 	.long	0x40026000
	...

Disassembly of section .text.adc_calib:

00000000 <adc_calib>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <adc_calib>
   6:	e0000000 	bsr      	0x0	// 0 <lmac_rf_sw_ctrl>
   a:	3000      	movi      	r0, 0
   c:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rx_en>
  10:	3001      	movi      	r0, 1
  12:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  16:	3000      	movi      	r0, 0
  18:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_pa_en>
  1c:	e0000000 	bsr      	0x0	// 0 <adc_calib>
  20:	ea01a0cf 	movi      	r1, 41167
  24:	ea000303 	movi      	r0, 771
  28:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  2c:	30c1      	movi      	r0, 193
  2e:	ea018b60 	movi      	r1, 35680
  32:	4002      	lsli      	r0, r0, 2
  34:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  38:	ea01620e 	movi      	r1, 25102
  3c:	ea000305 	movi      	r0, 773
  40:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  44:	ea01cc99 	movi      	r1, 52377
  48:	ea000306 	movi      	r0, 774
  4c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  50:	ea01baff 	movi      	r1, 47871
  54:	ea000307 	movi      	r0, 775
  58:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  5c:	30c2      	movi      	r0, 194
  5e:	ea0127ff 	movi      	r1, 10239
  62:	4002      	lsli      	r0, r0, 2
  64:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  68:	e0000000 	bsr      	0x0	// 0 <rfadc_calib_mode_soft_test>
  6c:	1017      	lrw      	r0, 0x0	// c8 <hgprintf+0xc8>
  6e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  72:	ea0180cf 	movi      	r1, 32975
  76:	ea000303 	movi      	r0, 771
  7a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  7e:	30c1      	movi      	r0, 193
  80:	ea018b72 	movi      	r1, 35698
  84:	4002      	lsli      	r0, r0, 2
  86:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  8a:	ea01620f 	movi      	r1, 25103
  8e:	ea000305 	movi      	r0, 773
  92:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  96:	ea01ec99 	movi      	r1, 60569
  9a:	ea000306 	movi      	r0, 774
  9e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  a2:	ea01b2ff 	movi      	r1, 45823
  a6:	ea000307 	movi      	r0, 775
  aa:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  ae:	30c2      	movi      	r0, 194
  b0:	ea01277f 	movi      	r1, 10111
  b4:	4002      	lsli      	r0, r0, 2
  b6:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  ba:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
  be:	3000      	movi      	r0, 0
  c0:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  c4:	1490      	pop      	r15
  c6:	0000      	.short	0x0000
  c8:	00000000 	.long	0x00000000

Disassembly of section .text.rfdigcal_rx_dcoc_calib:

00000000 <rfdigcal_rx_dcoc_calib>:
   0:	14d1      	push      	r4, r15
   2:	1422      	subi      	r14, r14, 8
   4:	6d03      	mov      	r4, r0
   6:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_dcoc_est_en>
   a:	6c3b      	mov      	r0, r14
   c:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_dcoc_est_kick_start>
  10:	9840      	ld.w      	r2, (r14, 0x0)
  12:	eb2201ff 	cmplti      	r2, 512
  16:	0c17      	bf      	0x44	// 44 <rfdigcal_rx_dcoc_calib+0x44>
  18:	ea0101ff 	movi      	r1, 511
  1c:	6c46      	nor      	r1, r1
  1e:	74cb      	sexth      	r3, r2
  20:	6449      	cmplt      	r2, r1
  22:	c4610c40 	inct      	r3, r1, 0
  26:	9841      	ld.w      	r2, (r14, 0x4)
  28:	eb2201ff 	cmplti      	r2, 512
  2c:	ac60      	st.h      	r3, (r4, 0x0)
  2e:	0c0e      	bf      	0x4a	// 4a <rfdigcal_rx_dcoc_calib+0x4a>
  30:	ea0101ff 	movi      	r1, 511
  34:	6c46      	nor      	r1, r1
  36:	74cb      	sexth      	r3, r2
  38:	6449      	cmplt      	r2, r1
  3a:	c4610c40 	inct      	r3, r1, 0
  3e:	ac61      	st.h      	r3, (r4, 0x2)
  40:	1402      	addi      	r14, r14, 8
  42:	1491      	pop      	r4, r15
  44:	ea0301ff 	movi      	r3, 511
  48:	07ef      	br      	0x26	// 26 <rfdigcal_rx_dcoc_calib+0x26>
  4a:	ea0301ff 	movi      	r3, 511
  4e:	07f8      	br      	0x3e	// 3e <rfdigcal_rx_dcoc_calib+0x3e>

Disassembly of section .text.tx_dcoc_rx_path_dcoc_cal.constprop.0:

00000000 <tx_dcoc_rx_path_dcoc_cal.constprop.0>:
   0:	14d0      	push      	r15
   2:	1421      	subi      	r14, r14, 4
   4:	3000      	movi      	r0, 0
   6:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_gain_idx_src>
   a:	3105      	movi      	r1, 5
   c:	3000      	movi      	r0, 0
   e:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
  12:	3180      	movi      	r1, 128
  14:	3205      	movi      	r2, 5
  16:	4124      	lsli      	r1, r1, 4
  18:	3000      	movi      	r0, 0
  1a:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_imb>
  1e:	3300      	movi      	r3, 0
  20:	3204      	movi      	r2, 4
  22:	3105      	movi      	r1, 5
  24:	6c3b      	mov      	r0, r14
  26:	dc6e1000 	st.h      	r3, (r14, 0x0)
  2a:	dc6e1001 	st.h      	r3, (r14, 0x2)
  2e:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_dcoc>
  32:	3005      	movi      	r0, 5
  34:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_tx_pwr>
  38:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
  3c:	3001      	movi      	r0, 1
  3e:	e0000000 	bsr      	0x0	// 0 <ah_set_dbgpath_device_path_mode>
  42:	3101      	movi      	r1, 1
  44:	3000      	movi      	r0, 0
  46:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_mode>
  4a:	3180      	movi      	r1, 128
  4c:	100b      	lrw      	r0, 0x0	// 78 <tx_dcoc_rx_path_dcoc_cal.constprop.0+0x78>
  4e:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_buff>
  52:	e0000000 	bsr      	0x0	// 0 <ah_tdma_start>
  56:	e0000000 	bsr      	0x0	// 0 <ah_trig_dbgpath_device_dma>
  5a:	3200      	movi      	r2, 0
  5c:	3104      	movi      	r1, 4
  5e:	3005      	movi      	r0, 5
  60:	e0000000 	bsr      	0x0	// 0 <tx_dcoc_rx_path_dcoc_cal.constprop.0>
  64:	6c3b      	mov      	r0, r14
  66:	e0000000 	bsr      	0x0	// 0 <tx_dcoc_rx_path_dcoc_cal.constprop.0>
  6a:	3204      	movi      	r2, 4
  6c:	3105      	movi      	r1, 5
  6e:	6c3b      	mov      	r0, r14
  70:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_dcoc>
  74:	1401      	addi      	r14, r14, 4
  76:	1490      	pop      	r15
  78:	00000000 	.long	0x00000000

Disassembly of section .text.dft_pwr_fixed_out_one:

00000000 <dft_pwr_fixed_out_one>:
   0:	14d8      	push      	r4-r11, r15
   2:	1422      	subi      	r14, r14, 8
   4:	4246      	lsli      	r2, r2, 6
   6:	1173      	lrw      	r3, 0x0	// d0 <dft_pwr_fixed_out_one+0xd0>
   8:	c462002c 	addu      	r12, r2, r3
   c:	3600      	movi      	r6, 0
   e:	1172      	lrw      	r3, 0x0	// d4 <dft_pwr_fixed_out_one+0xd4>
  10:	3700      	movi      	r7, 0
  12:	6d43      	mov      	r5, r0
  14:	c462002a 	addu      	r10, r2, r3
  18:	6e1b      	mov      	r8, r6
  1a:	6e5f      	mov      	r9, r7
  1c:	ea0b0000 	movi      	r11, 0
  20:	d8655020 	ld.hs      	r3, (r5, 0x40)
  24:	d8855000 	ld.hs      	r4, (r5, 0x0)
  28:	610c      	addu      	r4, r3
  2a:	d8655040 	ld.hs      	r3, (r5, 0x80)
  2e:	610c      	addu      	r4, r3
  30:	d8655060 	ld.hs      	r3, (r5, 0xc0)
  34:	610c      	addu      	r4, r3
  36:	d8655080 	ld.hs      	r3, (r5, 0x100)
  3a:	610c      	addu      	r4, r3
  3c:	d86550a0 	ld.hs      	r3, (r5, 0x140)
  40:	610c      	addu      	r4, r3
  42:	d86550c0 	ld.hs      	r3, (r5, 0x180)
  46:	610c      	addu      	r4, r3
  48:	d86550e0 	ld.hs      	r3, (r5, 0x1c0)
  4c:	610c      	addu      	r4, r3
  4e:	d16c0880 	ldr.w      	r0, (r12, r11 << 2)
  52:	c7e4488d 	asri      	r13, r4, 31
  56:	6cf7      	mov      	r3, r13
  58:	6c93      	mov      	r2, r4
  5a:	503f      	asri      	r1, r0, 31
  5c:	dd8e2000 	st.w      	r12, (r14, 0x0)
  60:	ddae2001 	st.w      	r13, (r14, 0x4)
  64:	e0000000 	bsr      	0x0	// 0 <__muldi3>
  68:	6621      	cmplt      	r8, r8
  6a:	6201      	addc      	r8, r0
  6c:	6245      	addc      	r9, r1
  6e:	d9ae2001 	ld.w      	r13, (r14, 0x4)
  72:	d16a0880 	ldr.w      	r0, (r10, r11 << 2)
  76:	6c93      	mov      	r2, r4
  78:	6cf7      	mov      	r3, r13
  7a:	503f      	asri      	r1, r0, 31
  7c:	e0000000 	bsr      	0x0	// 0 <__muldi3>
  80:	e56b0000 	addi      	r11, r11, 1
  84:	6599      	cmplt      	r6, r6
  86:	6181      	addc      	r6, r0
  88:	61c5      	addc      	r7, r1
  8a:	eb4b0010 	cmpnei      	r11, 16
  8e:	2503      	addi      	r5, 4
  90:	d98e2000 	ld.w      	r12, (r14, 0x0)
  94:	0bc6      	bt      	0x20	// 20 <dft_pwr_fixed_out_one+0x20>
  96:	c5c94823 	lsli      	r3, r9, 14
  9a:	c6484842 	lsri      	r2, r8, 18
  9e:	6c8c      	or      	r2, r3
  a0:	472e      	lsli      	r1, r7, 14
  a2:	c6494883 	asri      	r3, r9, 18
  a6:	4e92      	lsri      	r4, r6, 18
  a8:	6d04      	or      	r4, r1
  aa:	6c0b      	mov      	r0, r2
  ac:	6c4f      	mov      	r1, r3
  ae:	e0000000 	bsr      	0x0	// 0 <__muldi3>
  b2:	57b2      	asri      	r5, r7, 18
  b4:	6c93      	mov      	r2, r4
  b6:	6d83      	mov      	r6, r0
  b8:	6dc7      	mov      	r7, r1
  ba:	6cd7      	mov      	r3, r5
  bc:	6c13      	mov      	r0, r4
  be:	6c57      	mov      	r1, r5
  c0:	e0000000 	bsr      	0x0	// 0 <__muldi3>
  c4:	6401      	cmplt      	r0, r0
  c6:	6019      	addc      	r0, r6
  c8:	605d      	addc      	r1, r7
  ca:	1402      	addi      	r14, r14, 8
  cc:	1498      	pop      	r4-r11, r15
	...

Disassembly of section .text.snr_calc_128_dft_fixed_point:

00000000 <snr_calc_128_dft_fixed_point>:
   0:	14d4      	push      	r4-r7, r15
   2:	3400      	movi      	r4, 0
   4:	6c83      	mov      	r2, r0
   6:	e5a001ff 	addi      	r13, r0, 512
   a:	6d93      	mov      	r6, r4
   c:	6d53      	mov      	r5, r4
   e:	d8625000 	ld.hs      	r3, (r2, 0x0)
  12:	d8225002 	ld.hs      	r1, (r2, 0x4)
  16:	c463842c 	mult      	r12, r3, r3
  1a:	c4218427 	mult      	r7, r1, r1
  1e:	2207      	addi      	r2, 8
  20:	631c      	addu      	r12, r7
  22:	64b6      	cmpne      	r13, r2
  24:	6170      	addu      	r5, r12
  26:	c423002c 	addu      	r12, r3, r1
  2a:	60c6      	subu      	r3, r1
  2c:	6130      	addu      	r4, r12
  2e:	618c      	addu      	r6, r3
  30:	0bef      	bt      	0xe	// e <snr_calc_128_dft_fixed_point+0xe>
  32:	3200      	movi      	r2, 0
  34:	7d98      	mult      	r6, r6
  36:	3108      	movi      	r1, 8
  38:	7d10      	mult      	r4, r4
  3a:	e0000000 	bsr      	0x0	// 0 <snr_calc_128_dft_fixed_point>
  3e:	6118      	addu      	r4, r6
  40:	4128      	lsli      	r1, r1, 8
  42:	4818      	lsri      	r0, r0, 24
  44:	5487      	asri      	r4, r4, 7
  46:	6c04      	or      	r0, r1
  48:	5d91      	subu      	r4, r5, r4
  4a:	6102      	subu      	r4, r0
  4c:	c4808020 	divu      	r0, r0, r4
  50:	1494      	pop      	r4-r7, r15

Disassembly of section .text.check_adc_perf:

00000000 <check_adc_perf>:
   0:	14d3      	push      	r4-r6, r15
   2:	3080      	movi      	r0, 128
   4:	4003      	lsli      	r0, r0, 3
   6:	e0000000 	bsr      	0x0	// 0 <_os_zalloc>
   a:	6d03      	mov      	r4, r0
   c:	e9200004 	bnez      	r0, 0x14	// 14 <check_adc_perf+0x14>
  10:	3000      	movi      	r0, 0
  12:	1493      	pop      	r4-r6, r15
  14:	e0000000 	bsr      	0x0	// 0 <check_adc_perf>
  18:	e0000000 	bsr      	0x0	// 0 <lmac_rf_sw_ctrl>
  1c:	3000      	movi      	r0, 0
  1e:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rx_en>
  22:	3001      	movi      	r0, 1
  24:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  28:	3000      	movi      	r0, 0
  2a:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_pa_en>
  2e:	3100      	movi      	r1, 0
  30:	3001      	movi      	r0, 1
  32:	e0000000 	bsr      	0x0	// 0 <ah_tdma2_set_mode>
  36:	3180      	movi      	r1, 128
  38:	4123      	lsli      	r1, r1, 3
  3a:	6c13      	mov      	r0, r4
  3c:	e0000000 	bsr      	0x0	// 0 <ah_tdma2_set_buff>
  40:	e0000000 	bsr      	0x0	// 0 <ah_tdma2_enable_irq>
  44:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
  48:	3001      	movi      	r0, 1
  4a:	e0000000 	bsr      	0x0	// 0 <ah_set_dbgpath_device_path_mode>
  4e:	3101      	movi      	r1, 1
  50:	3000      	movi      	r0, 0
  52:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_mode>
  56:	3140      	movi      	r1, 64
  58:	110d      	lrw      	r0, 0x0	// 10c <check_adc_perf+0x10c>
  5a:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_buff>
  5e:	e0000000 	bsr      	0x0	// 0 <ah_tdma_start>
  62:	e0000000 	bsr      	0x0	// 0 <ah_trig_dbgpath_device_dma>
  66:	30fa      	movi      	r0, 250
  68:	4002      	lsli      	r0, r0, 2
  6a:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
  6e:	ea0180cf 	movi      	r1, 32975
  72:	ea000303 	movi      	r0, 771
  76:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  7a:	30c1      	movi      	r0, 193
  7c:	ea018b72 	movi      	r1, 35698
  80:	4002      	lsli      	r0, r0, 2
  82:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  86:	ea01620f 	movi      	r1, 25103
  8a:	ea000305 	movi      	r0, 773
  8e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  92:	ea01ec99 	movi      	r1, 60569
  96:	ea000306 	movi      	r0, 774
  9a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  9e:	ea01b2ff 	movi      	r1, 45823
  a2:	ea000307 	movi      	r0, 775
  a6:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  aa:	30c2      	movi      	r0, 194
  ac:	ea01277f 	movi      	r1, 10111
  b0:	4002      	lsli      	r0, r0, 2
  b2:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  b6:	e0000000 	bsr      	0x0	// 0 <ah_tdma2_start>
  ba:	e0000000 	bsr      	0x0	// 0 <ah_tdma2_get_pd>
  be:	e900fffe 	bez      	r0, 0xba	// ba <check_adc_perf+0xba>
  c2:	e0000000 	bsr      	0x0	// 0 <ah_tdma2_clear_pd>
  c6:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
  ca:	3000      	movi      	r0, 0
  cc:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  d0:	e40400ff 	addi      	r0, r4, 256
  d4:	e0000000 	bsr      	0x0	// 0 <check_adc_perf>
  d8:	6d43      	mov      	r5, r0
  da:	e4040101 	addi      	r0, r4, 258
  de:	e0000000 	bsr      	0x0	// 0 <check_adc_perf>
  e2:	6d83      	mov      	r6, r0
  e4:	6c13      	mov      	r0, r4
  e6:	e0000000 	bsr      	0x0	// 0 <_os_free>
  ea:	eb059c40 	cmphsi      	r5, 40001
  ee:	0c04      	bf      	0xf6	// f6 <check_adc_perf+0xf6>
  f0:	eb069c40 	cmphsi      	r6, 40001
  f4:	0b8e      	bt      	0x10	// 10 <check_adc_perf+0x10>
  f6:	1007      	lrw      	r0, 0x0	// 110 <check_adc_perf+0x110>
  f8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  fc:	1006      	lrw      	r0, 0x0	// 114 <check_adc_perf+0x114>
  fe:	6c9b      	mov      	r2, r6
 100:	6c57      	mov      	r1, r5
 102:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 106:	3000      	movi      	r0, 0
 108:	2800      	subi      	r0, 1
 10a:	0784      	br      	0x12	// 12 <check_adc_perf+0x12>
	...

Disassembly of section .text.rf_para_efuse_read:

00000000 <rf_para_efuse_read>:
   0:	14d8      	push      	r4-r11, r15
   2:	1436      	subi      	r14, r14, 88
   4:	1804      	addi      	r0, r14, 16
   6:	3248      	movi      	r2, 72
   8:	3100      	movi      	r1, 0
   a:	e0000000 	bsr      	0x0	// 0 <memset>
   e:	3400      	movi      	r4, 0
  10:	1904      	addi      	r1, r14, 16
  12:	3248      	movi      	r2, 72
  14:	3042      	movi      	r0, 66
  16:	b880      	st.w      	r4, (r14, 0x0)
  18:	dc8e1002 	st.h      	r4, (r14, 0x4)
  1c:	6dbb      	mov      	r6, r14
  1e:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_config_and_read>
  22:	1904      	addi      	r1, r14, 16
  24:	6cd3      	mov      	r3, r4
  26:	ea8c010a 	lrw      	r12, 0x0	// 44c <rf_para_efuse_read+0x44c>
  2a:	8142      	ld.b      	r2, (r1, 0x2)
  2c:	8101      	ld.b      	r0, (r1, 0x1)
  2e:	4008      	lsli      	r0, r0, 8
  30:	4250      	lsli      	r2, r2, 16
  32:	6c80      	or      	r2, r0
  34:	8100      	ld.b      	r0, (r1, 0x0)
  36:	6c80      	or      	r2, r0
  38:	d46c0882 	str.w      	r2, (r12, r3 << 2)
  3c:	2300      	addi      	r3, 1
  3e:	3b58      	cmpnei      	r3, 24
  40:	2102      	addi      	r1, 3
  42:	0bf4      	bt      	0x2a	// 2a <rf_para_efuse_read+0x2a>
  44:	3203      	movi      	r2, 3
  46:	1904      	addi      	r1, r14, 16
  48:	30a9      	movi      	r0, 169
  4a:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_config_and_read>
  4e:	d82e0011 	ld.b      	r1, (r14, 0x11)
  52:	4148      	lsli      	r2, r1, 8
  54:	d86e0010 	ld.b      	r3, (r14, 0x10)
  58:	e4422300 	andi      	r2, r2, 768
  5c:	6c8c      	or      	r2, r3
  5e:	d86e0012 	ld.b      	r3, (r14, 0x12)
  62:	4364      	lsli      	r3, r3, 4
  64:	0004      	lrw      	r0, 0x0	// 450 <rf_para_efuse_read+0x450>
  66:	4924      	lsri      	r1, r1, 4
  68:	e46323f0 	andi      	r3, r3, 1008
  6c:	6cc4      	or      	r3, r1
  6e:	a861      	st.h      	r3, (r0, 0x2)
  70:	a840      	st.h      	r2, (r0, 0x0)
  72:	00a6      	lrw      	r5, 0x0	// 454 <rf_para_efuse_read+0x454>
  74:	0006      	lrw      	r0, 0x0	// 458 <rf_para_efuse_read+0x458>
  76:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  7a:	3203      	movi      	r2, 3
  7c:	1904      	addi      	r1, r14, 16
  7e:	30a0      	movi      	r0, 160
  80:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_config_and_read>
  84:	d82e0011 	ld.b      	r1, (r14, 0x11)
  88:	4148      	lsli      	r2, r1, 8
  8a:	d86e0010 	ld.b      	r3, (r14, 0x10)
  8e:	e4422f00 	andi      	r2, r2, 3840
  92:	6c8c      	or      	r2, r3
  94:	006d      	lrw      	r3, 0x0	// 45c <rf_para_efuse_read+0x45c>
  96:	4924      	lsri      	r1, r1, 4
  98:	ab40      	st.h      	r2, (r3, 0x0)
  9a:	d86e0012 	ld.b      	r3, (r14, 0x12)
  9e:	4364      	lsli      	r3, r3, 4
  a0:	004f      	lrw      	r2, 0x0	// 460 <rf_para_efuse_read+0x460>
  a2:	e46323f0 	andi      	r3, r3, 1008
  a6:	6cc4      	or      	r3, r1
  a8:	aa60      	st.h      	r3, (r2, 0x0)
  aa:	1904      	addi      	r1, r14, 16
  ac:	3203      	movi      	r2, 3
  ae:	30a6      	movi      	r0, 166
  b0:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_config_and_read>
  b4:	d82e0011 	ld.b      	r1, (r14, 0x11)
  b8:	4148      	lsli      	r2, r1, 8
  ba:	d86e0010 	ld.b      	r3, (r14, 0x10)
  be:	e4422f00 	andi      	r2, r2, 3840
  c2:	6c8c      	or      	r2, r3
  c4:	0077      	lrw      	r3, 0x0	// 464 <rf_para_efuse_read+0x464>
  c6:	4924      	lsri      	r1, r1, 4
  c8:	ab40      	st.h      	r2, (r3, 0x0)
  ca:	d86e0012 	ld.b      	r3, (r14, 0x12)
  ce:	4364      	lsli      	r3, r3, 4
  d0:	e46321f0 	andi      	r3, r3, 496
  d4:	005a      	lrw      	r2, 0x0	// 468 <rf_para_efuse_read+0x468>
  d6:	6cc4      	or      	r3, r1
  d8:	aa60      	st.h      	r3, (r2, 0x0)
  da:	8565      	ld.b      	r3, (r5, 0x5)
  dc:	e9030009 	bez      	r3, 0xee	// ee <rf_para_efuse_read+0xee>
  e0:	ea02453f 	movi      	r2, 17727
  e4:	6c8a      	nor      	r2, r2
  e6:	6cc8      	or      	r3, r2
  e8:	005e      	lrw      	r2, 0x0	// 46c <rf_para_efuse_read+0x46c>
  ea:	dc62107c 	st.h      	r3, (r2, 0xf8)
  ee:	8560      	ld.b      	r3, (r5, 0x0)
  f0:	2b06      	subi      	r3, 7
  f2:	74cc      	zextb      	r3, r3
  f4:	3b18      	cmphsi      	r3, 25
  f6:	081f      	bt      	0x134	// 134 <rf_para_efuse_read+0x134>
  f8:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_tx_analog_gain_mcs3>
  fc:	0183      	lrw      	r4, 0x0	// 46c <rf_para_efuse_read+0x46c>
  fe:	ea07453f 	movi      	r7, 17727
 102:	6dde      	nor      	r7, r7
 104:	6c1c      	or      	r0, r7
 106:	dc041058 	st.h      	r0, (r4, 0xb0)
 10a:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_tx_analog_gain_mcs0>
 10e:	6c1c      	or      	r0, r7
 110:	dc04104f 	st.h      	r0, (r4, 0x9e)
 114:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_module_type>
 118:	3850      	cmpnei      	r0, 16
 11a:	09ad      	bt      	0x474	// 474 <rf_para_efuse_read+0x474>
 11c:	ea036202 	movi      	r3, 25090
 120:	dc64107a 	st.h      	r3, (r4, 0xf4)
 124:	ea036202 	movi      	r3, 25090
 128:	dc641056 	st.h      	r3, (r4, 0xac)
 12c:	ea036203 	movi      	r3, 25091
 130:	dc64104d 	st.h      	r3, (r4, 0x9a)
 134:	8560      	ld.b      	r3, (r5, 0x0)
 136:	2b00      	subi      	r3, 1
 138:	74cc      	zextb      	r3, r3
 13a:	3b07      	cmphsi      	r3, 8
 13c:	0877      	bt      	0x22a	// 22a <rf_para_efuse_read+0x22a>
 13e:	1b02      	addi      	r3, r14, 8
 140:	320c      	movi      	r2, 12
 142:	a340      	st.b      	r2, (r3, 0x0)
 144:	3208      	movi      	r2, 8
 146:	0195      	lrw      	r4, 0x0	// 46c <rf_para_efuse_read+0x46c>
 148:	3100      	movi      	r1, 0
 14a:	a341      	st.b      	r2, (r3, 0x1)
 14c:	3206      	movi      	r2, 6
 14e:	a342      	st.b      	r2, (r3, 0x2)
 150:	3204      	movi      	r2, 4
 152:	d804009e 	ld.b      	r0, (r4, 0x9e)
 156:	a343      	st.b      	r2, (r3, 0x3)
 158:	a344      	st.b      	r2, (r3, 0x4)
 15a:	3202      	movi      	r2, 2
 15c:	a345      	st.b      	r2, (r3, 0x5)
 15e:	e400203f 	andi      	r0, r0, 63
 162:	6c87      	mov      	r2, r1
 164:	ea0d0020 	movi      	r13, 32
 168:	c42d408c 	asr      	r12, r13, r1
 16c:	6b00      	and      	r12, r0
 16e:	e90c0006 	bez      	r12, 0x17a	// 17a <rf_para_efuse_read+0x17a>
 172:	d023002c 	ldr.b      	r12, (r3, r1 << 0)
 176:	60b0      	addu      	r2, r12
 178:	7488      	zextb      	r2, r2
 17a:	2100      	addi      	r1, 1
 17c:	3946      	cmpnei      	r1, 6
 17e:	0bf5      	bt      	0x168	// 168 <rf_para_efuse_read+0x168>
 180:	a322      	st.b      	r1, (r3, 0x2)
 182:	3104      	movi      	r1, 4
 184:	2a01      	subi      	r2, 2
 186:	a323      	st.b      	r1, (r3, 0x3)
 188:	a324      	st.b      	r1, (r3, 0x4)
 18a:	3102      	movi      	r1, 2
 18c:	a325      	st.b      	r1, (r3, 0x5)
 18e:	6c4b      	mov      	r1, r2
 190:	7488      	zextb      	r2, r2
 192:	300c      	movi      	r0, 12
 194:	eb020024 	cmphsi      	r2, 37
 198:	a300      	st.b      	r0, (r3, 0x0)
 19a:	3008      	movi      	r0, 8
 19c:	a301      	st.b      	r0, (r3, 0x1)
 19e:	0c02      	bf      	0x1a2	// 1a2 <rf_para_efuse_read+0x1a2>
 1a0:	3124      	movi      	r1, 36
 1a2:	3200      	movi      	r2, 0
 1a4:	7444      	zextb      	r1, r1
 1a6:	6f0b      	mov      	r12, r2
 1a8:	ea0d0001 	movi      	r13, 1
 1ac:	d0430020 	ldr.b      	r0, (r3, r2 << 0)
 1b0:	5901      	subu      	r0, r1, r0
 1b2:	e9800168 	blz      	r0, 0x482	// 482 <rf_para_efuse_read+0x482>
 1b6:	d446002d 	str.b      	r13, (r6, r2 << 0)
 1ba:	7440      	zextb      	r1, r0
 1bc:	2200      	addi      	r2, 1
 1be:	3a46      	cmpnei      	r2, 6
 1c0:	0bf6      	bt      	0x1ac	// 1ac <rf_para_efuse_read+0x1ac>
 1c2:	3700      	movi      	r7, 0
 1c4:	ea080005 	movi      	r8, 5
 1c8:	e5271000 	subi      	r9, r7, 1
 1cc:	c5060083 	subu      	r3, r6, r8
 1d0:	8305      	ld.b      	r0, (r3, 0x5)
 1d2:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
 1d6:	6ec3      	mov      	r11, r0
 1d8:	6c23      	mov      	r0, r8
 1da:	6e87      	mov      	r10, r1
 1dc:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
 1e0:	6cc7      	mov      	r3, r1
 1e2:	3180      	movi      	r1, 128
 1e4:	6c83      	mov      	r2, r0
 1e6:	4137      	lsli      	r1, r1, 23
 1e8:	3000      	movi      	r0, 0
 1ea:	e0000000 	bsr      	0x0	// 0 <pow>
 1ee:	6c83      	mov      	r2, r0
 1f0:	6cc7      	mov      	r3, r1
 1f2:	6c2f      	mov      	r0, r11
 1f4:	6c6b      	mov      	r1, r10
 1f6:	e0000000 	bsr      	0x0	// 0 <__muldf3>
 1fa:	6ec3      	mov      	r11, r0
 1fc:	6c1f      	mov      	r0, r7
 1fe:	6e87      	mov      	r10, r1
 200:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
 204:	6c83      	mov      	r2, r0
 206:	6cc7      	mov      	r3, r1
 208:	6c2f      	mov      	r0, r11
 20a:	6c6b      	mov      	r1, r10
 20c:	e0000000 	bsr      	0x0	// 0 <__adddf3>
 210:	e5081000 	subi      	r8, r8, 1
 214:	e0000000 	bsr      	0x0	// 0 <__fixunsdfsi>
 218:	6662      	cmpne      	r8, r9
 21a:	75c0      	zextb      	r7, r0
 21c:	0bd8      	bt      	0x1cc	// 1cc <rf_para_efuse_read+0x1cc>
 21e:	ea03453f 	movi      	r3, 17727
 222:	6cce      	nor      	r3, r3
 224:	6dcc      	or      	r7, r3
 226:	dce4104f 	st.h      	r7, (r4, 0x9e)
 22a:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_module_type>
 22e:	3850      	cmpnei      	r0, 16
 230:	092c      	bt      	0x488	// 488 <rf_para_efuse_read+0x488>
 232:	0370      	lrw      	r3, 0x0	// 46c <rf_para_efuse_read+0x46c>
 234:	ea02451d 	movi      	r2, 17693
 238:	6c8a      	nor      	r2, r2
 23a:	dc43107c 	st.h      	r2, (r3, 0xf8)
 23e:	ea02450f 	movi      	r2, 17679
 242:	6c8a      	nor      	r2, r2
 244:	dc431058 	st.h      	r2, (r3, 0xb0)
 248:	ea024517 	movi      	r2, 17687
 24c:	6c8a      	nor      	r2, r2
 24e:	dc43104f 	st.h      	r2, (r3, 0x9e)
 252:	d8654002 	ld.bs      	r3, (r5, 0x2)
 256:	e92300f8 	bnez      	r3, 0x446	// 446 <rf_para_efuse_read+0x446>
 25a:	3205      	movi      	r2, 5
 25c:	1904      	addi      	r1, r14, 16
 25e:	3031      	movi      	r0, 49
 260:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_config_and_read>
 264:	d86e0010 	ld.b      	r3, (r14, 0x10)
 268:	e9230006 	bnez      	r3, 0x274	// 274 <rf_para_efuse_read+0x274>
 26c:	d84e0011 	ld.b      	r2, (r14, 0x11)
 270:	e90200eb 	bez      	r2, 0x446	// 446 <rf_para_efuse_read+0x446>
 274:	139f      	lrw      	r4, 0x0	// 470 <rf_para_efuse_read+0x470>
 276:	4365      	lsli      	r3, r3, 5
 278:	d84e0011 	ld.b      	r2, (r14, 0x11)
 27c:	e4632700 	andi      	r3, r3, 1792
 280:	6cc8      	or      	r3, r2
 282:	ea010fff 	movi      	r1, 4095
 286:	6c46      	nor      	r1, r1
 288:	8c5f      	ld.h      	r2, (r4, 0x3e)
 28a:	6884      	and      	r2, r1
 28c:	6c8c      	or      	r2, r3
 28e:	ac5f      	st.h      	r2, (r4, 0x3e)
 290:	d8441041 	ld.h      	r2, (r4, 0x82)
 294:	6884      	and      	r2, r1
 296:	6c8c      	or      	r2, r3
 298:	dc441041 	st.h      	r2, (r4, 0x82)
 29c:	d8441063 	ld.h      	r2, (r4, 0xc6)
 2a0:	6884      	and      	r2, r1
 2a2:	6c8c      	or      	r2, r3
 2a4:	dc441063 	st.h      	r2, (r4, 0xc6)
 2a8:	d8441085 	ld.h      	r2, (r4, 0x10a)
 2ac:	6884      	and      	r2, r1
 2ae:	6cc8      	or      	r3, r2
 2b0:	dc641085 	st.h      	r3, (r4, 0x10a)
 2b4:	d86e0012 	ld.b      	r3, (r14, 0x12)
 2b8:	8c32      	ld.h      	r1, (r4, 0x24)
 2ba:	434c      	lsli      	r2, r3, 12
 2bc:	748b      	sexth      	r2, r2
 2be:	e4212fff 	andi      	r1, r1, 4095
 2c2:	6c48      	or      	r1, r2
 2c4:	ac32      	st.h      	r1, (r4, 0x24)
 2c6:	d8241034 	ld.h      	r1, (r4, 0x68)
 2ca:	e4212fff 	andi      	r1, r1, 4095
 2ce:	6c48      	or      	r1, r2
 2d0:	dc241034 	st.h      	r1, (r4, 0x68)
 2d4:	d8241056 	ld.h      	r1, (r4, 0xac)
 2d8:	e4212fff 	andi      	r1, r1, 4095
 2dc:	6c48      	or      	r1, r2
 2de:	dc241056 	st.h      	r1, (r4, 0xac)
 2e2:	d8241078 	ld.h      	r1, (r4, 0xf0)
 2e6:	e4212fff 	andi      	r1, r1, 4095
 2ea:	6c84      	or      	r2, r1
 2ec:	3100      	movi      	r1, 0
 2ee:	29f0      	subi      	r1, 241
 2f0:	dc441078 	st.h      	r2, (r4, 0xf0)
 2f4:	8c53      	ld.h      	r2, (r4, 0x26)
 2f6:	e46320f0 	andi      	r3, r3, 240
 2fa:	6884      	and      	r2, r1
 2fc:	6c8c      	or      	r2, r3
 2fe:	ac53      	st.h      	r2, (r4, 0x26)
 300:	d8441035 	ld.h      	r2, (r4, 0x6a)
 304:	6884      	and      	r2, r1
 306:	6c8c      	or      	r2, r3
 308:	dc441035 	st.h      	r2, (r4, 0x6a)
 30c:	d8441057 	ld.h      	r2, (r4, 0xae)
 310:	6884      	and      	r2, r1
 312:	6c8c      	or      	r2, r3
 314:	dc441057 	st.h      	r2, (r4, 0xae)
 318:	d8441079 	ld.h      	r2, (r4, 0xf2)
 31c:	6884      	and      	r2, r1
 31e:	d8ae0013 	ld.b      	r5, (r14, 0x13)
 322:	6cc8      	or      	r3, r2
 324:	ea060f00 	movi      	r6, 3840
 328:	6d9a      	nor      	r6, r6
 32a:	dc641079 	st.h      	r3, (r4, 0xf2)
 32e:	450c      	lsli      	r0, r5, 12
 330:	4564      	lsli      	r3, r5, 4
 332:	8cbb      	ld.h      	r5, (r4, 0x36)
 334:	e4632f00 	andi      	r3, r3, 3840
 338:	6958      	and      	r5, r6
 33a:	6d4c      	or      	r5, r3
 33c:	d9a4101d 	ld.h      	r13, (r4, 0x3a)
 340:	d824103f 	ld.h      	r1, (r4, 0x7e)
 344:	d8441061 	ld.h      	r2, (r4, 0xc2)
 348:	d9841083 	ld.h      	r12, (r4, 0x106)
 34c:	acbb      	st.h      	r5, (r4, 0x36)
 34e:	d8a4103d 	ld.h      	r5, (r4, 0x7a)
 352:	6958      	and      	r5, r6
 354:	6d4c      	or      	r5, r3
 356:	dca4103d 	st.h      	r5, (r4, 0x7a)
 35a:	d8a4105f 	ld.h      	r5, (r4, 0xbe)
 35e:	6958      	and      	r5, r6
 360:	6d4c      	or      	r5, r3
 362:	dca4105f 	st.h      	r5, (r4, 0xbe)
 366:	d8a41081 	ld.h      	r5, (r4, 0x102)
 36a:	6958      	and      	r5, r6
 36c:	6cd4      	or      	r3, r5
 36e:	dc641081 	st.h      	r3, (r4, 0x102)
 372:	d86e0014 	ld.b      	r3, (r14, 0x14)
 376:	7403      	sexth      	r0, r0
 378:	e4212e1f 	andi      	r1, r1, 3615
 37c:	e4422e1f 	andi      	r2, r2, 3615
 380:	4365      	lsli      	r3, r3, 5
 382:	e46321e0 	andi      	r3, r3, 480
 386:	e58c2e1f 	andi      	r12, r12, 3615
 38a:	6c40      	or      	r1, r0
 38c:	6c80      	or      	r2, r0
 38e:	e5ad2e1f 	andi      	r13, r13, 3615
 392:	6c4c      	or      	r1, r3
 394:	6c8c      	or      	r2, r3
 396:	6f40      	or      	r13, r0
 398:	6c30      	or      	r0, r12
 39a:	6f4c      	or      	r13, r3
 39c:	dc24103f 	st.h      	r1, (r4, 0x7e)
 3a0:	6cc0      	or      	r3, r0
 3a2:	dc441061 	st.h      	r2, (r4, 0xc2)
 3a6:	1904      	addi      	r1, r14, 16
 3a8:	3202      	movi      	r2, 2
 3aa:	303e      	movi      	r0, 62
 3ac:	dc641083 	st.h      	r3, (r4, 0x106)
 3b0:	dda4101d 	st.h      	r13, (r4, 0x3a)
 3b4:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_config_and_read>
 3b8:	d84e0011 	ld.b      	r2, (r14, 0x11)
 3bc:	e462200f 	andi      	r3, r2, 15
 3c0:	3b0b      	cmphsi      	r3, 12
 3c2:	0868      	bt      	0x492	// 492 <rf_para_efuse_read+0x492>
 3c4:	4364      	lsli      	r3, r3, 4
 3c6:	e423003f 	addi      	r1, r3, 64
 3ca:	d80e0010 	ld.b      	r0, (r14, 0x10)
 3ce:	4068      	lsli      	r3, r0, 8
 3d0:	e4632f00 	andi      	r3, r3, 3840
 3d4:	6cc4      	or      	r3, r1
 3d6:	4804      	lsri      	r0, r0, 4
 3d8:	6cc0      	or      	r3, r0
 3da:	8c27      	ld.h      	r1, (r4, 0xe)
 3dc:	ea000fff 	movi      	r0, 4095
 3e0:	6c02      	nor      	r0, r0
 3e2:	74cf      	sexth      	r3, r3
 3e4:	6840      	and      	r1, r0
 3e6:	6c4c      	or      	r1, r3
 3e8:	ac27      	st.h      	r1, (r4, 0xe)
 3ea:	d8241029 	ld.h      	r1, (r4, 0x52)
 3ee:	6840      	and      	r1, r0
 3f0:	6c4c      	or      	r1, r3
 3f2:	dc241029 	st.h      	r1, (r4, 0x52)
 3f6:	d824104b 	ld.h      	r1, (r4, 0x96)
 3fa:	6840      	and      	r1, r0
 3fc:	6c4c      	or      	r1, r3
 3fe:	dc24104b 	st.h      	r1, (r4, 0x96)
 402:	d824106d 	ld.h      	r1, (r4, 0xda)
 406:	6840      	and      	r1, r0
 408:	6cc4      	or      	r3, r1
 40a:	dc64106d 	st.h      	r3, (r4, 0xda)
 40e:	ea010f00 	movi      	r1, 3840
 412:	6c46      	nor      	r1, r1
 414:	4264      	lsli      	r3, r2, 4
 416:	8c4f      	ld.h      	r2, (r4, 0x1e)
 418:	e4632f00 	andi      	r3, r3, 3840
 41c:	6884      	and      	r2, r1
 41e:	6c8c      	or      	r2, r3
 420:	ac4f      	st.h      	r2, (r4, 0x1e)
 422:	d8441031 	ld.h      	r2, (r4, 0x62)
 426:	6884      	and      	r2, r1
 428:	6c8c      	or      	r2, r3
 42a:	dc441031 	st.h      	r2, (r4, 0x62)
 42e:	d8441053 	ld.h      	r2, (r4, 0xa6)
 432:	6884      	and      	r2, r1
 434:	6c8c      	or      	r2, r3
 436:	dc441053 	st.h      	r2, (r4, 0xa6)
 43a:	d8441075 	ld.h      	r2, (r4, 0xea)
 43e:	6884      	and      	r2, r1
 440:	6cc8      	or      	r3, r2
 442:	dc641075 	st.h      	r3, (r4, 0xea)
 446:	3000      	movi      	r0, 0
 448:	1416      	addi      	r14, r14, 88
 44a:	1498      	pop      	r4-r11, r15
	...
 474:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_module_type>
 478:	3843      	cmpnei      	r0, 3
 47a:	0e51      	bf      	0x11c	// 11c <rf_para_efuse_read+0x11c>
 47c:	ea036201 	movi      	r3, 25089
 480:	0650      	br      	0x120	// 120 <rf_para_efuse_read+0x120>
 482:	d446002c 	str.b      	r12, (r6, r2 << 0)
 486:	069b      	br      	0x1bc	// 1bc <sysctrl_efuse_get_module_type+0x1bc>
 488:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_module_type>
 48c:	3843      	cmpnei      	r0, 3
 48e:	0ae2      	bt      	0x252	// 252 <rf_para_efuse_read+0x252>
 490:	06d1      	br      	0x232	// 232 <rf_para_efuse_read+0x232>
 492:	31f0      	movi      	r1, 240
 494:	079b      	br      	0x3ca	// 3ca <rf_para_efuse_read+0x3ca>

Disassembly of section .text.ah_rf_regs_read:

00000000 <ah_rf_regs_read>:
   0:	14d3      	push      	r4-r6, r15
   2:	3490      	movi      	r4, 144
   4:	4484      	lsli      	r4, r4, 4
   6:	3500      	movi      	r5, 0
   8:	10c7      	lrw      	r6, 0x0	// 24 <ah_rf_regs_read+0x24>
   a:	6c13      	mov      	r0, r4
   c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  10:	d4a60440 	str.h      	r0, (r6, r5 << 1)
  14:	2500      	addi      	r5, 1
  16:	eb450038 	cmpnei      	r5, 56
  1a:	2400      	addi      	r4, 1
  1c:	7511      	zexth      	r4, r4
  1e:	0bf6      	bt      	0xa	// a <ah_rf_regs_read+0xa>
  20:	3000      	movi      	r0, 0
  22:	1493      	pop      	r4-r6, r15
  24:	0000      	.short	0x0000
	...

Disassembly of section .text.ah_rf_reg_read:

00000000 <ah_rf_reg_read>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
   6:	1490      	pop      	r15

Disassembly of section .text.ah_rf_reg_write:

00000000 <ah_rf_reg_write>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
   6:	1490      	pop      	r15

Disassembly of section .text.ah_rf_soft_reset:

00000000 <ah_rf_soft_reset>:
   0:	14d0      	push      	r15
   2:	3101      	movi      	r1, 1
   4:	ea000fff 	movi      	r0, 4095
   8:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
   c:	3100      	movi      	r1, 0
   e:	ea000fff 	movi      	r0, 4095
  12:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  16:	3000      	movi      	r0, 0
  18:	1490      	pop      	r15

Disassembly of section .text.ah_rf_rx_bb_ana_out:

00000000 <ah_rf_rx_bb_ana_out>:
   0:	14d0      	push      	r15
   2:	ea011c84 	movi      	r1, 7300
   6:	3097      	movi      	r0, 151
   8:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15

Disassembly of section .text.ah_rf_tx_bb_ana_out:

00000000 <ah_rf_tx_bb_ana_out>:
   0:	14d0      	push      	r15
   2:	ea01188d 	movi      	r1, 6285
   6:	30d8      	movi      	r0, 216
   8:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15

Disassembly of section .text.ah_rf_check_lo_lock:

00000000 <ah_rf_check_lo_lock>:
   0:	14d0      	push      	r15
   2:	ea000811 	movi      	r0, 2065
   6:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
   a:	e4004400 	xori      	r0, r0, 1024
   e:	c5405940 	sext      	r0, r0, 10, 10
  12:	1490      	pop      	r15

Disassembly of section .text.ah_rf_lo_freq_set:

00000000 <ah_rf_lo_freq_set>:
   0:	14d3      	push      	r4-r6, r15
   2:	1270      	lrw      	r3, 0xfff4dc70	// 140 <ah_rf_lo_freq_set+0x140>
   4:	584c      	addu      	r2, r0, r3
   6:	ea03c350 	movi      	r3, 50000
   a:	c4434903 	rotli      	r3, r3, 2
   e:	648c      	cmphs      	r3, r2
  10:	0c95      	bf      	0x13a	// 13a <ah_rf_lo_freq_set+0x13a>
  12:	e0000000 	bsr      	0x0	// 0 <__floatunsisf>
  16:	31fc      	movi      	r1, 252
  18:	4136      	lsli      	r1, r1, 22
  1a:	e0000000 	bsr      	0x0	// 0 <__mulsf3>
  1e:	ea21447a 	movih      	r1, 17530
  22:	e0000000 	bsr      	0x0	// 0 <__divsf3>
  26:	31f8      	movi      	r1, 248
  28:	4136      	lsli      	r1, r1, 22
  2a:	e0000000 	bsr      	0x0	// 0 <__mulsf3>
  2e:	6d03      	mov      	r4, r0
  30:	e0000000 	bsr      	0x0	// 0 <__fixunssfsi>
  34:	7541      	zexth      	r5, r0
  36:	6c17      	mov      	r0, r5
  38:	e0000000 	bsr      	0x0	// 0 <__floatunsisf>
  3c:	6c43      	mov      	r1, r0
  3e:	6c13      	mov      	r0, r4
  40:	e0000000 	bsr      	0x0	// 0 <__subsf3>
  44:	3195      	movi      	r1, 149
  46:	4137      	lsli      	r1, r1, 23
  48:	6d83      	mov      	r6, r0
  4a:	e0000000 	bsr      	0x0	// 0 <__mulsf3>
  4e:	6d03      	mov      	r4, r0
  50:	ea214040 	movih      	r1, 16448
  54:	6c1b      	mov      	r0, r6
  56:	e0000000 	bsr      	0x0	// 0 <__mulsf3>
  5a:	6c43      	mov      	r1, r0
  5c:	6c13      	mov      	r0, r4
  5e:	e0000000 	bsr      	0x0	// 0 <__subsf3>
  62:	e0000000 	bsr      	0x0	// 0 <__fixunssfsi>
  66:	6d03      	mov      	r4, r0
  68:	30c2      	movi      	r0, 194
  6a:	4003      	lsli      	r0, r0, 3
  6c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  70:	ec2000ff 	ori      	r1, r0, 255
  74:	30c2      	movi      	r0, 194
  76:	7445      	zexth      	r1, r1
  78:	4003      	lsli      	r0, r0, 3
  7a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  7e:	30c0      	movi      	r0, 192
  80:	6c57      	mov      	r1, r5
  82:	4003      	lsli      	r0, r0, 3
  84:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  88:	7451      	zexth      	r1, r4
  8a:	ea000601 	movi      	r0, 1537
  8e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  92:	4c30      	lsri      	r1, r4, 16
  94:	ea000602 	movi      	r0, 1538
  98:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  9c:	3405      	movi      	r4, 5
  9e:	3081      	movi      	r0, 129
  a0:	3130      	movi      	r1, 48
  a2:	4004      	lsli      	r0, r0, 4
  a4:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  a8:	2c00      	subi      	r4, 1
  aa:	3081      	movi      	r0, 129
  ac:	3131      	movi      	r1, 49
  ae:	4004      	lsli      	r0, r0, 4
  b0:	7510      	zextb      	r4, r4
  b2:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  b6:	30c8      	movi      	r0, 200
  b8:	e0000000 	bsr      	0x0	// 0 <delay_us>
  bc:	e9240024 	bnez      	r4, 0x104	// 104 <ah_rf_lo_freq_set+0x104>
  c0:	1161      	lrw      	r3, 0x0	// 144 <ah_rf_lo_freq_set+0x144>
  c2:	8368      	ld.b      	r3, (r3, 0x8)
  c4:	e923001a 	bnez      	r3, 0xf8	// f8 <ah_rf_lo_freq_set+0xf8>
  c8:	30c8      	movi      	r0, 200
  ca:	4002      	lsli      	r0, r0, 2
  cc:	e0000000 	bsr      	0x0	// 0 <delay_us>
  d0:	ea000811 	movi      	r0, 2065
  d4:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  d8:	e4002400 	andi      	r0, r0, 1024
  dc:	e900001d 	bez      	r0, 0x116	// 116 <ah_rf_lo_freq_set+0x116>
  e0:	ea000811 	movi      	r0, 2065
  e4:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  e8:	e42021ff 	andi      	r1, r0, 511
  ec:	ea000603 	movi      	r0, 1539
  f0:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write_and_read>
  f4:	3000      	movi      	r0, 0
  f6:	0406      	br      	0x102	// 102 <ah_rf_lo_freq_set+0x102>
  f8:	1014      	lrw      	r0, 0x0	// 148 <ah_rf_lo_freq_set+0x148>
  fa:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  fe:	3000      	movi      	r0, 0
 100:	2800      	subi      	r0, 1
 102:	1493      	pop      	r4-r6, r15
 104:	ea000811 	movi      	r0, 2065
 108:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
 10c:	e4002200 	andi      	r0, r0, 512
 110:	e900ffc7 	bez      	r0, 0x9e	// 9e <ah_rf_lo_freq_set+0x9e>
 114:	07da      	br      	0xc8	// c8 <ah_rf_lo_freq_set+0xc8>
 116:	30fa      	movi      	r0, 250
 118:	4003      	lsli      	r0, r0, 3
 11a:	e0000000 	bsr      	0x0	// 0 <delay_us>
 11e:	ea000811 	movi      	r0, 2065
 122:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
 126:	e4002400 	andi      	r0, r0, 1024
 12a:	e920ffdb 	bnez      	r0, 0xe0	// e0 <ah_rf_lo_freq_set+0xe0>
 12e:	1066      	lrw      	r3, 0x0	// 144 <ah_rf_lo_freq_set+0x144>
 130:	8368      	ld.b      	r3, (r3, 0x8)
 132:	e903ffd7 	bez      	r3, 0xe0	// e0 <ah_rf_lo_freq_set+0xe0>
 136:	1006      	lrw      	r0, 0x0	// 14c <ah_rf_lo_freq_set+0x14c>
 138:	07e1      	br      	0xfa	// fa <ah_rf_lo_freq_set+0xfa>
 13a:	3000      	movi      	r0, 0
 13c:	2815      	subi      	r0, 22
 13e:	07e2      	br      	0x102	// 102 <ah_rf_lo_freq_set+0x102>
 140:	fff4dc70 	.long	0xfff4dc70
	...

Disassembly of section .text.ah_rf_lo_table_ctrl:

00000000 <ah_rf_lo_table_ctrl>:
   0:	14d0      	push      	r15
   2:	3841      	cmpnei      	r0, 1
   4:	30c2      	movi      	r0, 194
   6:	4003      	lsli      	r0, r0, 3
   8:	080d      	bt      	0x22	// 22 <ah_rf_lo_table_ctrl+0x22>
   a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
   e:	3300      	movi      	r3, 0
  10:	2bff      	subi      	r3, 256
  12:	680c      	and      	r0, r3
  14:	7441      	zexth      	r1, r0
  16:	30c2      	movi      	r0, 194
  18:	4003      	lsli      	r0, r0, 3
  1a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  1e:	3000      	movi      	r0, 0
  20:	1490      	pop      	r15
  22:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  26:	ec0000ff 	ori      	r0, r0, 255
  2a:	7401      	zexth      	r0, r0
  2c:	07f4      	br      	0x14	// 14 <ah_rf_lo_table_ctrl+0x14>

Disassembly of section .text.ah_rf_lo_table_cfg:

00000000 <ah_rf_lo_table_cfg>:
   0:	14d6      	push      	r4-r9, r15
   2:	3910      	cmphsi      	r1, 17
   4:	6dc3      	mov      	r7, r0
   6:	6d87      	mov      	r6, r1
   8:	0827      	bt      	0x56	// 56 <ah_rf_lo_table_cfg+0x56>
   a:	3500      	movi      	r5, 0
   c:	6594      	cmphs      	r5, r6
   e:	0c03      	bf      	0x14	// 14 <ah_rf_lo_table_cfg+0x14>
  10:	3000      	movi      	r0, 0
  12:	1496      	pop      	r4-r9, r15
  14:	d0a70880 	ldr.w      	r0, (r7, r5 << 2)
  18:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_table_cfg>
  1c:	e920fffb 	bnez      	r0, 0x12	// 12 <ah_rf_lo_table_cfg+0x12>
  20:	4584      	lsli      	r4, r5, 4
  22:	e48404ff 	addi      	r4, r4, 1280
  26:	ea08092e 	movi      	r8, 2350
  2a:	6c23      	mov      	r0, r8
  2c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  30:	6e43      	mov      	r9, r0
  32:	e5080000 	addi      	r8, r8, 1
  36:	6c13      	mov      	r0, r4
  38:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  3c:	7621      	zexth      	r8, r8
  3e:	6c13      	mov      	r0, r4
  40:	6c67      	mov      	r1, r9
  42:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  46:	eb480932 	cmpnei      	r8, 2354
  4a:	2400      	addi      	r4, 1
  4c:	7511      	zexth      	r4, r4
  4e:	0bee      	bt      	0x2a	// 2a <ah_rf_lo_table_cfg+0x2a>
  50:	2500      	addi      	r5, 1
  52:	7554      	zextb      	r5, r5
  54:	07dc      	br      	0xc	// c <ah_rf_lo_table_cfg+0xc>
  56:	3000      	movi      	r0, 0
  58:	2800      	subi      	r0, 1
  5a:	07dc      	br      	0x12	// 12 <ah_rf_lo_table_cfg+0x12>

Disassembly of section .text.ah_rf_lo_table_kick:

00000000 <ah_rf_lo_table_kick>:
   0:	14d0      	push      	r15
   2:	3081      	movi      	r0, 129
   4:	3138      	movi      	r1, 56
   6:	4004      	lsli      	r0, r0, 4
   8:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15

Disassembly of section .text.override_rf_dpd_cal_iPA:

00000000 <override_rf_dpd_cal_iPA>:
   0:	14d3      	push      	r4-r6, r15
   2:	3480      	movi      	r4, 128
   4:	4481      	lsli      	r4, r4, 1
   6:	3500      	movi      	r5, 0
   8:	10d6      	lrw      	r6, 0x0	// 60 <override_rf_dpd_cal_iPA+0x60>
   a:	d0a60441 	ldr.h      	r1, (r6, r5 << 1)
   e:	6c13      	mov      	r0, r4
  10:	7445      	zexth      	r1, r1
  12:	2500      	addi      	r5, 1
  14:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  18:	eb450022 	cmpnei      	r5, 34
  1c:	2400      	addi      	r4, 1
  1e:	7511      	zexth      	r4, r4
  20:	0bf5      	bt      	0xa	// a <override_rf_dpd_cal_iPA+0xa>
  22:	1091      	lrw      	r4, 0x0	// 64 <override_rf_dpd_cal_iPA+0x64>
  24:	3088      	movi      	r0, 136
  26:	8c35      	ld.h      	r1, (r4, 0x2a)
  28:	4003      	lsli      	r0, r0, 3
  2a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  2e:	8c36      	ld.h      	r1, (r4, 0x2c)
  30:	ea000441 	movi      	r0, 1089
  34:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  38:	8c37      	ld.h      	r1, (r4, 0x2e)
  3a:	ea000442 	movi      	r0, 1090
  3e:	108b      	lrw      	r4, 0x0	// 68 <ah_rfspi_write+0x68>
  40:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  44:	30f0      	movi      	r0, 240
  46:	d8241070 	ld.h      	r1, (r4, 0xe0)
  4a:	4003      	lsli      	r0, r0, 3
  4c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  50:	d8241071 	ld.h      	r1, (r4, 0xe2)
  54:	ea000781 	movi      	r0, 1921
  58:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  5c:	1493      	pop      	r4-r6, r15
	...

Disassembly of section .text.override_rf_dpd_cal_ePA:

00000000 <override_rf_dpd_cal_ePA>:
   0:	14d3      	push      	r4-r6, r15
   2:	3480      	movi      	r4, 128
   4:	4481      	lsli      	r4, r4, 1
   6:	3500      	movi      	r5, 0
   8:	10d6      	lrw      	r6, 0x0	// 60 <override_rf_dpd_cal_ePA+0x60>
   a:	d0a60441 	ldr.h      	r1, (r6, r5 << 1)
   e:	6c13      	mov      	r0, r4
  10:	7445      	zexth      	r1, r1
  12:	2500      	addi      	r5, 1
  14:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  18:	eb450022 	cmpnei      	r5, 34
  1c:	2400      	addi      	r4, 1
  1e:	7511      	zexth      	r4, r4
  20:	0bf5      	bt      	0xa	// a <override_rf_dpd_cal_ePA+0xa>
  22:	1091      	lrw      	r4, 0x0	// 64 <override_rf_dpd_cal_ePA+0x64>
  24:	3088      	movi      	r0, 136
  26:	8c35      	ld.h      	r1, (r4, 0x2a)
  28:	4003      	lsli      	r0, r0, 3
  2a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  2e:	8c36      	ld.h      	r1, (r4, 0x2c)
  30:	ea000441 	movi      	r0, 1089
  34:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  38:	8c37      	ld.h      	r1, (r4, 0x2e)
  3a:	ea000442 	movi      	r0, 1090
  3e:	108b      	lrw      	r4, 0x0	// 68 <ah_rfspi_write+0x68>
  40:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  44:	30f0      	movi      	r0, 240
  46:	d8241070 	ld.h      	r1, (r4, 0xe0)
  4a:	4003      	lsli      	r0, r0, 3
  4c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  50:	d8241071 	ld.h      	r1, (r4, 0xe2)
  54:	ea000781 	movi      	r0, 1921
  58:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  5c:	1493      	pop      	r4-r6, r15
	...

Disassembly of section .text.override_rf_dpd_dcoc_imb_cfg_iPA:

00000000 <override_rf_dpd_dcoc_imb_cfg_iPA>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <override_rf_dpd_dcoc_imb_cfg_iPA>
   6:	3000      	movi      	r0, 0
   8:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_pa_en>
   c:	30c0      	movi      	r0, 192
   e:	ea0104e1 	movi      	r1, 1249
  12:	4002      	lsli      	r0, r0, 2
  14:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  18:	3100      	movi      	r1, 0
  1a:	ea000301 	movi      	r0, 769
  1e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  22:	31c6      	movi      	r1, 198
  24:	4127      	lsli      	r1, r1, 7
  26:	ea000302 	movi      	r0, 770
  2a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  2e:	ea0180c1 	movi      	r1, 32961
  32:	ea000303 	movi      	r0, 771
  36:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  3a:	30c1      	movi      	r0, 193
  3c:	ea013760 	movi      	r1, 14176
  40:	4002      	lsli      	r0, r0, 2
  42:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  46:	ea01620f 	movi      	r1, 25103
  4a:	ea000305 	movi      	r0, 773
  4e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  52:	ea018c99 	movi      	r1, 35993
  56:	ea000306 	movi      	r0, 774
  5a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  5e:	ea0192ff 	movi      	r1, 37631
  62:	ea000307 	movi      	r0, 775
  66:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  6a:	30c2      	movi      	r0, 194
  6c:	ea0127ff 	movi      	r1, 10239
  70:	4002      	lsli      	r0, r0, 2
  72:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  76:	ea0140f0 	movi      	r1, 16624
  7a:	ea000303 	movi      	r0, 771
  7e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  82:	3088      	movi      	r0, 136
  84:	ea0101cd 	movi      	r1, 461
  88:	4003      	lsli      	r0, r0, 3
  8a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  8e:	31c8      	movi      	r1, 200
  90:	ea000442 	movi      	r0, 1090
  94:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  98:	31a0      	movi      	r1, 160
  9a:	30f0      	movi      	r0, 240
  9c:	4122      	lsli      	r1, r1, 2
  9e:	4003      	lsli      	r0, r0, 3
  a0:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  a4:	3180      	movi      	r1, 128
  a6:	4127      	lsli      	r1, r1, 7
  a8:	ea000781 	movi      	r0, 1921
  ac:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  b0:	1490      	pop      	r15

Disassembly of section .text.override_rf_dpd_dcoc_imb_cfg_ePA:

00000000 <override_rf_dpd_dcoc_imb_cfg_ePA>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <override_rf_dpd_dcoc_imb_cfg_ePA>
   6:	3001      	movi      	r0, 1
   8:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_pa_en>
   c:	30c0      	movi      	r0, 192
   e:	ea0104e1 	movi      	r1, 1249
  12:	4002      	lsli      	r0, r0, 2
  14:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  18:	3100      	movi      	r1, 0
  1a:	ea000301 	movi      	r0, 769
  1e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  22:	31c6      	movi      	r1, 198
  24:	4127      	lsli      	r1, r1, 7
  26:	ea000302 	movi      	r0, 770
  2a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  2e:	ea0180f0 	movi      	r1, 33008
  32:	ea000303 	movi      	r0, 771
  36:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  3a:	30c1      	movi      	r0, 193
  3c:	ea014b60 	movi      	r1, 19296
  40:	4002      	lsli      	r0, r0, 2
  42:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  46:	ea016201 	movi      	r1, 25089
  4a:	ea000305 	movi      	r0, 773
  4e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  52:	ea018c99 	movi      	r1, 35993
  56:	ea000306 	movi      	r0, 774
  5a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  5e:	ea01baed 	movi      	r1, 47853
  62:	ea000307 	movi      	r0, 775
  66:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  6a:	30c2      	movi      	r0, 194
  6c:	ea0127ff 	movi      	r1, 10239
  70:	4002      	lsli      	r0, r0, 2
  72:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  76:	3088      	movi      	r0, 136
  78:	ea0101cd 	movi      	r1, 461
  7c:	4003      	lsli      	r0, r0, 3
  7e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  82:	31c8      	movi      	r1, 200
  84:	ea000442 	movi      	r0, 1090
  88:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  8c:	31a0      	movi      	r1, 160
  8e:	30f0      	movi      	r0, 240
  90:	4122      	lsli      	r1, r1, 2
  92:	4003      	lsli      	r0, r0, 3
  94:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  98:	3180      	movi      	r1, 128
  9a:	4127      	lsli      	r1, r1, 7
  9c:	ea000781 	movi      	r0, 1921
  a0:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  a4:	1490      	pop      	r15

Disassembly of section .text.override_rf_tx_dcoc_cal_inner_path:

00000000 <override_rf_tx_dcoc_cal_inner_path>:
   0:	14d3      	push      	r4-r6, r15
   2:	3480      	movi      	r4, 128
   4:	4481      	lsli      	r4, r4, 1
   6:	3500      	movi      	r5, 0
   8:	10d6      	lrw      	r6, 0x0	// 60 <override_rf_tx_dcoc_cal_inner_path+0x60>
   a:	d0a60441 	ldr.h      	r1, (r6, r5 << 1)
   e:	6c13      	mov      	r0, r4
  10:	7445      	zexth      	r1, r1
  12:	2500      	addi      	r5, 1
  14:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  18:	eb450022 	cmpnei      	r5, 34
  1c:	2400      	addi      	r4, 1
  1e:	7511      	zexth      	r4, r4
  20:	0bf5      	bt      	0xa	// a <override_rf_tx_dcoc_cal_inner_path+0xa>
  22:	1091      	lrw      	r4, 0x0	// 64 <override_rf_tx_dcoc_cal_inner_path+0x64>
  24:	3088      	movi      	r0, 136
  26:	8c35      	ld.h      	r1, (r4, 0x2a)
  28:	4003      	lsli      	r0, r0, 3
  2a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  2e:	8c36      	ld.h      	r1, (r4, 0x2c)
  30:	ea000441 	movi      	r0, 1089
  34:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  38:	8c37      	ld.h      	r1, (r4, 0x2e)
  3a:	ea000442 	movi      	r0, 1090
  3e:	108b      	lrw      	r4, 0x0	// 68 <ah_rfspi_write+0x68>
  40:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  44:	30f0      	movi      	r0, 240
  46:	d8241070 	ld.h      	r1, (r4, 0xe0)
  4a:	4003      	lsli      	r0, r0, 3
  4c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  50:	d8241071 	ld.h      	r1, (r4, 0xe2)
  54:	ea000781 	movi      	r0, 1921
  58:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  5c:	1493      	pop      	r4-r6, r15
	...

Disassembly of section .text.ah_rf_rx_dcoc_calib:

00000000 <ah_rf_rx_dcoc_calib>:
   0:	14d8      	push      	r4-r11, r15
   2:	1425      	subi      	r14, r14, 20
   4:	e0000000 	bsr      	0x0	// 0 <lmac_rf_sw_ctrl>
   8:	3480      	movi      	r4, 128
   a:	3000      	movi      	r0, 0
   c:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_pa_en>
  10:	4481      	lsli      	r4, r4, 1
  12:	3500      	movi      	r5, 0
  14:	12d4      	lrw      	r6, 0x0	// 164 <ah_rf_rx_dcoc_calib+0x164>
  16:	d0a60441 	ldr.h      	r1, (r6, r5 << 1)
  1a:	6c13      	mov      	r0, r4
  1c:	7445      	zexth      	r1, r1
  1e:	2500      	addi      	r5, 1
  20:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  24:	eb450022 	cmpnei      	r5, 34
  28:	2400      	addi      	r4, 1
  2a:	7511      	zexth      	r4, r4
  2c:	0bf5      	bt      	0x16	// 16 <ah_rf_rx_dcoc_calib+0x16>
  2e:	3001      	movi      	r0, 1
  30:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rx_en>
  34:	3000      	movi      	r0, 0
  36:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  3a:	12ac      	lrw      	r5, 0x0	// 168 <ah_rf_rx_dcoc_calib+0x168>
  3c:	ea89004c 	lrw      	r9, 0x0	// 16c <ah_rf_rx_dcoc_calib+0x16c>
  40:	ea0a0000 	movi      	r10, 0
  44:	3603      	movi      	r6, 3
  46:	3088      	movi      	r0, 136
  48:	8d20      	ld.h      	r1, (r5, 0x0)
  4a:	4003      	lsli      	r0, r0, 3
  4c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  50:	8d21      	ld.h      	r1, (r5, 0x2)
  52:	ea000441 	movi      	r0, 1089
  56:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  5a:	8d22      	ld.h      	r1, (r5, 0x4)
  5c:	ea000442 	movi      	r0, 1090
  60:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  64:	1263      	lrw      	r3, 0x0	// 170 <ah_rf_rx_dcoc_calib+0x170>
  66:	c46a0028 	addu      	r8, r10, r3
  6a:	6de7      	mov      	r7, r9
  6c:	ea0b0005 	movi      	r11, 5
  70:	7518      	zextb      	r4, r6
  72:	045c      	br      	0x12a	// 12a <ah_rf_rx_dcoc_calib+0x12a>
  74:	8a20      	ld.h      	r1, (r2, 0x0)
  76:	6c0f      	mov      	r0, r3
  78:	b842      	st.w      	r2, (r14, 0x8)
  7a:	b861      	st.w      	r3, (r14, 0x4)
  7c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  80:	9861      	ld.w      	r3, (r14, 0x4)
  82:	2300      	addi      	r3, 1
  84:	74cd      	zexth      	r3, r3
  86:	eb430304 	cmpnei      	r3, 772
  8a:	9842      	ld.w      	r2, (r14, 0x8)
  8c:	2201      	addi      	r2, 2
  8e:	0bf3      	bt      	0x74	// 74 <ah_rf_rx_dcoc_calib+0x74>
  90:	e4681001 	subi      	r3, r8, 2
  94:	30f0      	movi      	r0, 240
  96:	8b20      	ld.h      	r1, (r3, 0x0)
  98:	4003      	lsli      	r0, r0, 3
  9a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  9e:	d8281000 	ld.h      	r1, (r8, 0x0)
  a2:	ea000781 	movi      	r0, 1921
  a6:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  aa:	3000      	movi      	r0, 0
  ac:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_gain_idx_src>
  b0:	776c      	zextb      	r13, r11
  b2:	6c37      	mov      	r0, r13
  b4:	6c53      	mov      	r1, r4
  b6:	ddae2001 	st.w      	r13, (r14, 0x4)
  ba:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_gain>
  be:	6c13      	mov      	r0, r4
  c0:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_filter>
  c4:	3201      	movi      	r2, 1
  c6:	6c5b      	mov      	r1, r6
  c8:	9800      	ld.w      	r0, (r14, 0x0)
  ca:	e0000000 	bsr      	0x0	// 0 <ah_rf_rx_dcoc_calib>
  ce:	1803      	addi      	r0, r14, 12
  d0:	e0000000 	bsr      	0x0	// 0 <ah_rf_rx_dcoc_calib>
  d4:	d9ae2001 	ld.w      	r13, (r14, 0x4)
  d8:	6c77      	mov      	r1, r13
  da:	6c93      	mov      	r2, r4
  dc:	1804      	addi      	r0, r14, 16
  de:	ddae2000 	st.w      	r13, (r14, 0x0)
  e2:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_get_rx_dcoc>
  e6:	d86e1006 	ld.h      	r3, (r14, 0xc)
  ea:	d84e1008 	ld.h      	r2, (r14, 0x10)
  ee:	d82e1007 	ld.h      	r1, (r14, 0xe)
  f2:	608c      	addu      	r2, r3
  f4:	d86e1009 	ld.h      	r3, (r14, 0x12)
  f8:	60c4      	addu      	r3, r1
  fa:	74cf      	sexth      	r3, r3
  fc:	748b      	sexth      	r2, r2
  fe:	d9ae2000 	ld.w      	r13, (r14, 0x0)
 102:	af40      	st.h      	r2, (r7, 0x0)
 104:	af61      	st.h      	r3, (r7, 0x2)
 106:	dc4e1006 	st.h      	r2, (r14, 0xc)
 10a:	6c77      	mov      	r1, r13
 10c:	6c93      	mov      	r2, r4
 10e:	1803      	addi      	r0, r14, 12
 110:	dc6e1007 	st.h      	r3, (r14, 0xe)
 114:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_dcoc>
 118:	3300      	movi      	r3, 0
 11a:	e56b1000 	subi      	r11, r11, 1
 11e:	2b00      	subi      	r3, 1
 120:	64ee      	cmpne      	r11, r3
 122:	2f03      	subi      	r7, 4
 124:	e5081003 	subi      	r8, r8, 4
 128:	0c0a      	bf      	0x13c	// 13c <ah_rf_rx_dcoc_calib+0x13c>
 12a:	74ee      	sextb      	r3, r11
 12c:	3212      	movi      	r2, 18
 12e:	b860      	st.w      	r3, (r14, 0x0)
 130:	7cac      	mult      	r2, r11
 132:	1071      	lrw      	r3, 0x0	// 174 <ah_rf_rx_dcoc_calib+0x174>
 134:	608c      	addu      	r2, r3
 136:	33c0      	movi      	r3, 192
 138:	4362      	lsli      	r3, r3, 2
 13a:	079d      	br      	0x74	// 74 <ah_rf_rx_dcoc_calib+0x74>
 13c:	2c00      	subi      	r4, 1
 13e:	7592      	sextb      	r6, r4
 140:	66da      	cmpne      	r6, r11
 142:	2d05      	subi      	r5, 6
 144:	e5291017 	subi      	r9, r9, 24
 148:	e54a101f 	subi      	r10, r10, 32
 14c:	0b7d      	bt      	0x46	// 46 <ah_rf_rx_dcoc_calib+0x46>
 14e:	3103      	movi      	r1, 3
 150:	3005      	movi      	r0, 5
 152:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_gain>
 156:	3000      	movi      	r0, 0
 158:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rx_en>
 15c:	3000      	movi      	r0, 0
 15e:	1405      	addi      	r14, r14, 20
 160:	1498      	pop      	r4-r11, r15
	...

Disassembly of section .text.ah_rf_tx_imb_calib:

00000000 <ah_rf_tx_imb_calib>:
   0:	14d8      	push      	r4-r11, r15
   2:	1422      	subi      	r14, r14, 8
   4:	3480      	movi      	r4, 128
   6:	4481      	lsli      	r4, r4, 1
   8:	3500      	movi      	r5, 0
   a:	13d4      	lrw      	r6, 0x0	// 1d8 <ah_rf_tx_imb_calib+0x1d8>
   c:	d0a60441 	ldr.h      	r1, (r6, r5 << 1)
  10:	6c13      	mov      	r0, r4
  12:	7445      	zexth      	r1, r1
  14:	2500      	addi      	r5, 1
  16:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  1a:	eb450022 	cmpnei      	r5, 34
  1e:	2400      	addi      	r4, 1
  20:	7511      	zexth      	r4, r4
  22:	0bf5      	bt      	0xc	// c <ah_rf_tx_imb_calib+0xc>
  24:	138e      	lrw      	r4, 0x0	// 1dc <ah_rf_tx_imb_calib+0x1dc>
  26:	3088      	movi      	r0, 136
  28:	8c35      	ld.h      	r1, (r4, 0x2a)
  2a:	4003      	lsli      	r0, r0, 3
  2c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  30:	8c36      	ld.h      	r1, (r4, 0x2c)
  32:	ea000441 	movi      	r0, 1089
  36:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  3a:	8c37      	ld.h      	r1, (r4, 0x2e)
  3c:	ea000442 	movi      	r0, 1090
  40:	1388      	lrw      	r4, 0x0	// 1e0 <ah_rfspi_write+0x1e0>
  42:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  46:	30f0      	movi      	r0, 240
  48:	d8241070 	ld.h      	r1, (r4, 0xe0)
  4c:	4003      	lsli      	r0, r0, 3
  4e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  52:	d8241071 	ld.h      	r1, (r4, 0xe2)
  56:	ea000781 	movi      	r0, 1921
  5a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  5e:	e0000000 	bsr      	0x0	// 0 <lmac_rf_sw_ctrl>
  62:	3001      	movi      	r0, 1
  64:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  68:	3000      	movi      	r0, 0
  6a:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rx_en>
  6e:	3000      	movi      	r0, 0
  70:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_pa_en>
  74:	319c      	movi      	r1, 156
  76:	30c0      	movi      	r0, 192
  78:	4123      	lsli      	r1, r1, 3
  7a:	4002      	lsli      	r0, r0, 2
  7c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  80:	3100      	movi      	r1, 0
  82:	ea000301 	movi      	r0, 769
  86:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  8a:	ea014338 	movi      	r1, 17208
  8e:	ea000302 	movi      	r0, 770
  92:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  96:	ea01d8cf 	movi      	r1, 55503
  9a:	ea000303 	movi      	r0, 771
  9e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  a2:	30c1      	movi      	r0, 193
  a4:	ea014b60 	movi      	r1, 19296
  a8:	4002      	lsli      	r0, r0, 2
  aa:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  ae:	ea016201 	movi      	r1, 25089
  b2:	ea000305 	movi      	r0, 773
  b6:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  ba:	ea018c99 	movi      	r1, 35993
  be:	ea000306 	movi      	r0, 774
  c2:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  c6:	ea01baed 	movi      	r1, 47853
  ca:	ea000307 	movi      	r0, 775
  ce:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  d2:	30c2      	movi      	r0, 194
  d4:	ea0127ff 	movi      	r1, 10239
  d8:	4002      	lsli      	r0, r0, 2
  da:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  de:	e0000000 	bsr      	0x0	// 0 <ah_rf_tx_imb_calib>
  e2:	30a0      	movi      	r0, 160
  e4:	3105      	movi      	r1, 5
  e6:	4003      	lsli      	r0, r0, 3
  e8:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
  ec:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_dcoc_est_en>
  f0:	35e0      	movi      	r5, 224
  f2:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_dcoc_imb_est_kick_start>
  f6:	3600      	movi      	r6, 0
  f8:	3002      	movi      	r0, 2
  fa:	45a3      	lsli      	r5, r5, 3
  fc:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
 100:	c7c05028 	bmaski      	r8, 31
 104:	2e77      	subi      	r6, 120
 106:	6e57      	mov      	r9, r5
 108:	3400      	movi      	r4, 0
 10a:	2c77      	subi      	r4, 120
 10c:	75e5      	zexth      	r7, r9
 10e:	3205      	movi      	r2, 5
 110:	6c5f      	mov      	r1, r7
 112:	6c13      	mov      	r0, r4
 114:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_imb>
 118:	300a      	movi      	r0, 10
 11a:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 11e:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_power_calc_kick_start>
 122:	6e83      	mov      	r10, r0
 124:	300a      	movi      	r0, 10
 126:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 12a:	6629      	cmplt      	r10, r8
 12c:	0c04      	bf      	0x134	// 134 <ah_rf_tx_imb_calib+0x134>
 12e:	6d93      	mov      	r6, r4
 130:	6d67      	mov      	r5, r9
 132:	6e2b      	mov      	r8, r10
 134:	240f      	addi      	r4, 16
 136:	7513      	sexth      	r4, r4
 138:	eb440088 	cmpnei      	r4, 136
 13c:	0be9      	bt      	0x10e	// 10e <ah_rf_tx_imb_calib+0x10e>
 13e:	270f      	addi      	r7, 16
 140:	75dd      	zexth      	r7, r7
 142:	eb470910 	cmpnei      	r7, 2320
 146:	765f      	sexth      	r9, r7
 148:	0be0      	bt      	0x108	// 108 <ah_rf_tx_imb_calib+0x108>
 14a:	74d5      	zexth      	r3, r5
 14c:	e483100f 	subi      	r4, r3, 16
 150:	230f      	addi      	r3, 16
 152:	768f      	sexth      	r10, r3
 154:	74d9      	zexth      	r3, r6
 156:	e563100f 	subi      	r11, r3, 16
 15a:	230f      	addi      	r3, 16
 15c:	7513      	sexth      	r4, r4
 15e:	76ef      	sexth      	r11, r11
 160:	764f      	sexth      	r9, r3
 162:	6529      	cmplt      	r10, r4
 164:	0823      	bt      	0x1aa	// 1aa <ah_rf_tx_imb_calib+0x1aa>
 166:	6def      	mov      	r7, r11
 168:	7711      	zexth      	r12, r4
 16a:	041b      	br      	0x1a0	// 1a0 <ah_rf_tx_imb_calib+0x1a0>
 16c:	6c73      	mov      	r1, r12
 16e:	3205      	movi      	r2, 5
 170:	6c1f      	mov      	r0, r7
 172:	dd8e2001 	st.w      	r12, (r14, 0x4)
 176:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_imb>
 17a:	300a      	movi      	r0, 10
 17c:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 180:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_power_calc_kick_start>
 184:	b800      	st.w      	r0, (r14, 0x0)
 186:	300a      	movi      	r0, 10
 188:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
 18c:	9860      	ld.w      	r3, (r14, 0x0)
 18e:	660d      	cmplt      	r3, r8
 190:	d98e2001 	ld.w      	r12, (r14, 0x4)
 194:	0c04      	bf      	0x19c	// 19c <ah_rf_tx_imb_calib+0x19c>
 196:	6d9f      	mov      	r6, r7
 198:	6d53      	mov      	r5, r4
 19a:	6e0f      	mov      	r8, r3
 19c:	2700      	addi      	r7, 1
 19e:	75df      	sexth      	r7, r7
 1a0:	65e5      	cmplt      	r9, r7
 1a2:	0fe5      	bf      	0x16c	// 16c <ah_rf_tx_imb_calib+0x16c>
 1a4:	2400      	addi      	r4, 1
 1a6:	7513      	sexth      	r4, r4
 1a8:	07dd      	br      	0x162	// 162 <ah_rf_tx_imb_calib+0x162>
 1aa:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_stop_tx_cali>
 1ae:	106e      	lrw      	r3, 0x0	// 1e4 <ah_rf_tx_imb_calib+0x1e4>
 1b0:	3205      	movi      	r2, 5
 1b2:	aba0      	st.h      	r5, (r3, 0x0)
 1b4:	7455      	zexth      	r1, r5
 1b6:	106d      	lrw      	r3, 0x0	// 1e8 <ah_rf_tx_imb_calib+0x1e8>
 1b8:	6c1b      	mov      	r0, r6
 1ba:	abc0      	st.h      	r6, (r3, 0x0)
 1bc:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_imb>
 1c0:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
 1c4:	3000      	movi      	r0, 0
 1c6:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
 1ca:	3000      	movi      	r0, 0
 1cc:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_pa_en>
 1d0:	3000      	movi      	r0, 0
 1d2:	1402      	addi      	r14, r14, 8
 1d4:	1498      	pop      	r4-r11, r15
	...

Disassembly of section .text.ah_rf_tx_dcoc_calib:

00000000 <ah_rf_tx_dcoc_calib>:
   0:	14d5      	push      	r4-r8, r15
   2:	1423      	subi      	r14, r14, 12
   4:	1343      	lrw      	r2, 0x40026000	// 190 <ah_rf_tx_dcoc_calib+0x190>
   6:	3400      	movi      	r4, 0
   8:	9275      	ld.w      	r3, (r2, 0x54)
   a:	ec630200 	ori      	r3, r3, 512
   e:	b275      	st.w      	r3, (r2, 0x54)
  10:	e0000000 	bsr      	0x0	// 0 <lmac_rf_sw_ctrl>
  14:	3000      	movi      	r0, 0
  16:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rx_en>
  1a:	3001      	movi      	r0, 1
  1c:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  20:	e0000000 	bsr      	0x0	// 0 <ah_rf_tx_dcoc_calib>
  24:	319c      	movi      	r1, 156
  26:	30c0      	movi      	r0, 192
  28:	4123      	lsli      	r1, r1, 3
  2a:	4002      	lsli      	r0, r0, 2
  2c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  30:	3100      	movi      	r1, 0
  32:	ea000301 	movi      	r0, 769
  36:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  3a:	ea016338 	movi      	r1, 25400
  3e:	ea000302 	movi      	r0, 770
  42:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  46:	ea01d8cf 	movi      	r1, 55503
  4a:	ea000303 	movi      	r0, 771
  4e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  52:	30c1      	movi      	r0, 193
  54:	ea013760 	movi      	r1, 14176
  58:	4002      	lsli      	r0, r0, 2
  5a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  5e:	ea01620f 	movi      	r1, 25103
  62:	ea000305 	movi      	r0, 773
  66:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  6a:	ea018c99 	movi      	r1, 35993
  6e:	ea000306 	movi      	r0, 774
  72:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  76:	ea0192ff 	movi      	r1, 37631
  7a:	ea000307 	movi      	r0, 775
  7e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  82:	30c2      	movi      	r0, 194
  84:	ea0127ff 	movi      	r1, 10239
  88:	4002      	lsli      	r0, r0, 2
  8a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  8e:	ea000119 	movi      	r0, 281
  92:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  96:	ea03b7ff 	movi      	r3, 47103
  9a:	c4602021 	and      	r1, r0, r3
  9e:	ea000119 	movi      	r0, 281
  a2:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  a6:	3000      	movi      	r0, 0
  a8:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_pa_en>
  ac:	e0000000 	bsr      	0x0	// 0 <ah_rf_tx_dcoc_calib>
  b0:	ea000119 	movi      	r0, 281
  b4:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  b8:	ec204800 	ori      	r1, r0, 18432
  bc:	2c13      	subi      	r4, 20
  be:	7445      	zexth      	r1, r1
  c0:	ea000119 	movi      	r0, 281
  c4:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  c8:	6d93      	mov      	r6, r4
  ca:	6dd3      	mov      	r7, r4
  cc:	c7c05028 	bmaski      	r8, 31
  d0:	3500      	movi      	r5, 0
  d2:	2d13      	subi      	r5, 20
  d4:	3105      	movi      	r1, 5
  d6:	6c3b      	mov      	r0, r14
  d8:	dc8e1000 	st.h      	r4, (r14, 0x0)
  dc:	dcae1001 	st.h      	r5, (r14, 0x2)
  e0:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_tx_dcoc>
  e4:	3002      	movi      	r0, 2
  e6:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
  ea:	1801      	addi      	r0, r14, 4
  ec:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_dcoc_est_kick_start>
  f0:	9861      	ld.w      	r3, (r14, 0x4)
  f2:	9842      	ld.w      	r2, (r14, 0x8)
  f4:	60ca      	subu      	r3, r2
  f6:	c4030203 	abs      	r3, r3
  fa:	660d      	cmplt      	r3, r8
  fc:	0c04      	bf      	0x104	// 104 <ah_rf_tx_dcoc_calib+0x104>
  fe:	6d97      	mov      	r6, r5
 100:	6dd3      	mov      	r7, r4
 102:	6e0f      	mov      	r8, r3
 104:	2504      	addi      	r5, 5
 106:	3d59      	cmpnei      	r5, 25
 108:	0be6      	bt      	0xd4	// d4 <ah_rf_tx_dcoc_calib+0xd4>
 10a:	2404      	addi      	r4, 5
 10c:	3c59      	cmpnei      	r4, 25
 10e:	0be1      	bt      	0xd0	// d0 <ah_rf_tx_dcoc_calib+0xd0>
 110:	5f93      	subi      	r4, r7, 5
 112:	5f72      	addi      	r3, r7, 5
 114:	650d      	cmplt      	r3, r4
 116:	0c1c      	bf      	0x14e	// 14e <ah_rf_tx_dcoc_calib+0x14e>
 118:	10bf      	lrw      	r5, 0x0	// 194 <ah_rf_tx_dcoc_calib+0x194>
 11a:	3105      	movi      	r1, 5
 11c:	6c17      	mov      	r0, r5
 11e:	ade0      	st.h      	r7, (r5, 0x0)
 120:	adc1      	st.h      	r6, (r5, 0x2)
 122:	3400      	movi      	r4, 0
 124:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_tx_dcoc>
 128:	6c53      	mov      	r1, r4
 12a:	2400      	addi      	r4, 1
 12c:	6c17      	mov      	r0, r5
 12e:	7510      	zextb      	r4, r4
 130:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_tx_dcoc>
 134:	3c45      	cmpnei      	r4, 5
 136:	0bf9      	bt      	0x128	// 128 <ah_rf_tx_dcoc_calib+0x128>
 138:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
 13c:	3000      	movi      	r0, 0
 13e:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
 142:	3000      	movi      	r0, 0
 144:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_pa_en>
 148:	3000      	movi      	r0, 0
 14a:	1403      	addi      	r14, r14, 12
 14c:	1495      	pop      	r4-r8, r15
 14e:	5eb3      	subi      	r5, r6, 5
 150:	5e72      	addi      	r3, r6, 5
 152:	654d      	cmplt      	r3, r5
 154:	0c03      	bf      	0x15a	// 15a <ah_rf_tx_dcoc_calib+0x15a>
 156:	2400      	addi      	r4, 1
 158:	07dd      	br      	0x112	// 112 <ah_rf_tx_dcoc_calib+0x112>
 15a:	3105      	movi      	r1, 5
 15c:	6c3b      	mov      	r0, r14
 15e:	dc8e1000 	st.h      	r4, (r14, 0x0)
 162:	dcae1001 	st.h      	r5, (r14, 0x2)
 166:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_tx_dcoc>
 16a:	3002      	movi      	r0, 2
 16c:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
 170:	1801      	addi      	r0, r14, 4
 172:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_dcoc_est_kick_start>
 176:	9861      	ld.w      	r3, (r14, 0x4)
 178:	9842      	ld.w      	r2, (r14, 0x8)
 17a:	60ca      	subu      	r3, r2
 17c:	c4030203 	abs      	r3, r3
 180:	660d      	cmplt      	r3, r8
 182:	0c04      	bf      	0x18a	// 18a <ah_rf_tx_dcoc_calib+0x18a>
 184:	6d97      	mov      	r6, r5
 186:	6dd3      	mov      	r7, r4
 188:	6e0f      	mov      	r8, r3
 18a:	2500      	addi      	r5, 1
 18c:	07e2      	br      	0x150	// 150 <ah_rf_tx_dcoc_calib+0x150>
 18e:	0000      	.short	0x0000
 190:	40026000 	.long	0x40026000
 194:	00000000 	.long	0x00000000

Disassembly of section .text.ah_rf_dpd_dcoc_calib:

00000000 <ah_rf_dpd_dcoc_calib>:
   0:	14d0      	push      	r15
   2:	1422      	subi      	r14, r14, 8
   4:	e0000000 	bsr      	0x0	// 0 <lmac_rf_sw_ctrl>
   8:	3000      	movi      	r0, 0
   a:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rx_en>
   e:	3001      	movi      	r0, 1
  10:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  14:	3000      	movi      	r0, 0
  16:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_gain_idx_src>
  1a:	3105      	movi      	r1, 5
  1c:	3000      	movi      	r0, 0
  1e:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
  22:	3005      	movi      	r0, 5
  24:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_tx_pwr>
  28:	e0000000 	bsr      	0x0	// 0 <ah_rf_dpd_dcoc_calib>
  2c:	107a      	lrw      	r3, 0x0	// 94 <ah_rf_dpd_dcoc_calib+0x94>
  2e:	3205      	movi      	r2, 5
  30:	8b20      	ld.h      	r1, (r3, 0x0)
  32:	107a      	lrw      	r3, 0x0	// 98 <ah_rf_dpd_dcoc_calib+0x98>
  34:	d8035000 	ld.hs      	r0, (r3, 0x0)
  38:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_imb>
  3c:	e0000000 	bsr      	0x0	// 0 <ah_rf_dpd_dcoc_calib>
  40:	6c3b      	mov      	r0, r14
  42:	e0000000 	bsr      	0x0	// 0 <ah_rf_dpd_dcoc_calib>
  46:	3204      	movi      	r2, 4
  48:	c44e0020 	addu      	r0, r14, r2
  4c:	3105      	movi      	r1, 5
  4e:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_get_rx_dcoc>
  52:	1013      	lrw      	r0, 0x0	// 9c <ah_rf_dpd_dcoc_calib+0x9c>
  54:	d84e1000 	ld.h      	r2, (r14, 0x0)
  58:	d86e1002 	ld.h      	r3, (r14, 0x4)
  5c:	60c8      	addu      	r3, r2
  5e:	a860      	st.h      	r3, (r0, 0x0)
  60:	d84e1001 	ld.h      	r2, (r14, 0x2)
  64:	d86e1003 	ld.h      	r3, (r14, 0x6)
  68:	60c8      	addu      	r3, r2
  6a:	3105      	movi      	r1, 5
  6c:	3204      	movi      	r2, 4
  6e:	a861      	st.h      	r3, (r0, 0x2)
  70:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_dcoc>
  74:	3080      	movi      	r0, 128
  76:	3105      	movi      	r1, 5
  78:	4003      	lsli      	r0, r0, 3
  7a:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
  7e:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
  82:	3000      	movi      	r0, 0
  84:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rx_en>
  88:	3000      	movi      	r0, 0
  8a:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  8e:	3000      	movi      	r0, 0
  90:	1402      	addi      	r14, r14, 8
  92:	1490      	pop      	r15
	...

Disassembly of section .text.ah_rf_rx_imb_calib:

00000000 <ah_rf_rx_imb_calib>:
   0:	14d2      	push      	r4-r5, r15
   2:	1421      	subi      	r14, r14, 4
   4:	6d07      	mov      	r4, r1
   6:	6d43      	mov      	r5, r0
   8:	3000      	movi      	r0, 0
   a:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_gain_idx_src>
   e:	6c57      	mov      	r1, r5
  10:	6c13      	mov      	r0, r4
  12:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_gain>
  16:	3380      	movi      	r3, 128
  18:	4364      	lsli      	r3, r3, 4
  1a:	dc6e1001 	st.h      	r3, (r14, 0x2)
  1e:	3180      	movi      	r1, 128
  20:	3300      	movi      	r3, 0
  22:	dc6e1000 	st.h      	r3, (r14, 0x0)
  26:	6c93      	mov      	r2, r4
  28:	6cd7      	mov      	r3, r5
  2a:	4124      	lsli      	r1, r1, 4
  2c:	3000      	movi      	r0, 0
  2e:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_imb>
  32:	e42e0001 	addi      	r1, r14, 2
  36:	6c3b      	mov      	r0, r14
  38:	e0000000 	bsr      	0x0	// 0 <ah_rf_rx_imb_calib>
  3c:	d86e5000 	ld.hs      	r3, (r14, 0x0)
  40:	eb2301ff 	cmplti      	r3, 512
  44:	0807      	bt      	0x52	// 52 <ah_rf_rx_imb_calib+0x52>
  46:	ea0203ff 	movi      	r2, 1023
  4a:	6c8a      	nor      	r2, r2
  4c:	6cc8      	or      	r3, r2
  4e:	dc6e1000 	st.h      	r3, (r14, 0x0)
  52:	6cd7      	mov      	r3, r5
  54:	6c93      	mov      	r2, r4
  56:	d82e1001 	ld.h      	r1, (r14, 0x2)
  5a:	d80e5000 	ld.hs      	r0, (r14, 0x0)
  5e:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_imb>
  62:	1069      	lrw      	r3, 0x0	// 84 <ah_rf_rx_imb_calib+0x84>
  64:	d84e1000 	ld.h      	r2, (r14, 0x0)
  68:	ab40      	st.h      	r2, (r3, 0x0)
  6a:	6c3b      	mov      	r0, r14
  6c:	1067      	lrw      	r3, 0x0	// 88 <ah_rf_rx_imb_calib+0x88>
  6e:	d84e1001 	ld.h      	r2, (r14, 0x2)
  72:	e42e0001 	addi      	r1, r14, 2
  76:	ab40      	st.h      	r2, (r3, 0x0)
  78:	e0000000 	bsr      	0x0	// 0 <ah_rf_rx_imb_calib>
  7c:	3000      	movi      	r0, 0
  7e:	1401      	addi      	r14, r14, 4
  80:	1492      	pop      	r4-r5, r15
	...

Disassembly of section .text.ah_rf_dpd_imb_calib:

00000000 <ah_rf_dpd_imb_calib>:
   0:	14d0      	push      	r15
   2:	1421      	subi      	r14, r14, 4
   4:	3300      	movi      	r3, 0
   6:	dc6e1000 	st.h      	r3, (r14, 0x0)
   a:	dc6e1001 	st.h      	r3, (r14, 0x2)
   e:	e0000000 	bsr      	0x0	// 0 <lmac_rf_sw_ctrl>
  12:	3001      	movi      	r0, 1
  14:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rx_en>
  18:	3000      	movi      	r0, 0
  1a:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  1e:	3303      	movi      	r3, 3
  20:	3205      	movi      	r2, 5
  22:	e42e0001 	addi      	r1, r14, 2
  26:	6c3b      	mov      	r0, r14
  28:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_get_rx_imb>
  2c:	3000      	movi      	r0, 0
  2e:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_gain_idx_src>
  32:	3103      	movi      	r1, 3
  34:	3005      	movi      	r0, 5
  36:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_gain>
  3a:	e0000000 	bsr      	0x0	// 0 <ah_rf_dpd_imb_calib>
  3e:	3203      	movi      	r2, 3
  40:	3105      	movi      	r1, 5
  42:	1100      	lrw      	r0, 0x0	// c0 <ah_rf_dpd_imb_calib+0xc0>
  44:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_dcoc>
  48:	107f      	lrw      	r3, 0x0	// c4 <ah_rf_dpd_imb_calib+0xc4>
  4a:	3205      	movi      	r2, 5
  4c:	8b20      	ld.h      	r1, (r3, 0x0)
  4e:	107f      	lrw      	r3, 0x0	// c8 <ah_rf_dpd_imb_calib+0xc8>
  50:	d8035000 	ld.hs      	r0, (r3, 0x0)
  54:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_imb>
  58:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
  5c:	3001      	movi      	r0, 1
  5e:	e0000000 	bsr      	0x0	// 0 <ah_set_dbgpath_device_path_mode>
  62:	3101      	movi      	r1, 1
  64:	3000      	movi      	r0, 0
  66:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_mode>
  6a:	3140      	movi      	r1, 64
  6c:	1018      	lrw      	r0, 0x0	// cc <ah_rf_dpd_imb_calib+0xcc>
  6e:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_buff>
  72:	e0000000 	bsr      	0x0	// 0 <ah_tdma_start>
  76:	e0000000 	bsr      	0x0	// 0 <ah_trig_dbgpath_device_dma>
  7a:	3105      	movi      	r1, 5
  7c:	3003      	movi      	r0, 3
  7e:	e0000000 	bsr      	0x0	// 0 <ah_rf_dpd_imb_calib>
  82:	1034      	lrw      	r1, 0x0	// d0 <ah_rf_dpd_imb_calib+0xd0>
  84:	1014      	lrw      	r0, 0x0	// d4 <ah_rf_dpd_imb_calib+0xd4>
  86:	3304      	movi      	r3, 4
  88:	3205      	movi      	r2, 5
  8a:	8920      	ld.h      	r1, (r1, 0x0)
  8c:	d8005000 	ld.hs      	r0, (r0, 0x0)
  90:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_imb>
  94:	3203      	movi      	r2, 3
  96:	3105      	movi      	r1, 5
  98:	1010      	lrw      	r0, 0x0	// d8 <ah_rf_dpd_imb_calib+0xd8>
  9a:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_dcoc>
  9e:	3303      	movi      	r3, 3
  a0:	3205      	movi      	r2, 5
  a2:	d82e1001 	ld.h      	r1, (r14, 0x2)
  a6:	d80e5000 	ld.hs      	r0, (r14, 0x0)
  aa:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_imb>
  ae:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
  b2:	3000      	movi      	r0, 0
  b4:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_tx_en>
  b8:	3000      	movi      	r0, 0
  ba:	1401      	addi      	r14, r14, 4
  bc:	1490      	pop      	r15
	...

Disassembly of section .text.rx_imb_res_store:

00000000 <rx_imb_res_store>:
   0:	14d0      	push      	r15
   2:	1423      	subi      	r14, r14, 12
   4:	8863      	ld.h      	r3, (r0, 0x6)
   6:	dc6e1000 	st.h      	r3, (r14, 0x0)
   a:	8963      	ld.h      	r3, (r1, 0x6)
   c:	dc6e1001 	st.h      	r3, (r14, 0x2)
  10:	8864      	ld.h      	r3, (r0, 0x8)
  12:	dc6e1002 	st.h      	r3, (r14, 0x4)
  16:	8964      	ld.h      	r3, (r1, 0x8)
  18:	dc6e1003 	st.h      	r3, (r14, 0x6)
  1c:	8865      	ld.h      	r3, (r0, 0xa)
  1e:	dc6e1004 	st.h      	r3, (r14, 0x8)
  22:	3203      	movi      	r2, 3
  24:	8965      	ld.h      	r3, (r1, 0xa)
  26:	3004      	movi      	r0, 4
  28:	6c7b      	mov      	r1, r14
  2a:	dc6e1005 	st.h      	r3, (r14, 0xa)
  2e:	e0000000 	bsr      	0x0	// 0 <memory_write>
  32:	1403      	addi      	r14, r14, 12
  34:	1490      	pop      	r15

Disassembly of section .text.ah_rf_open:

00000000 <ah_rf_open>:
   0:	14d8      	push      	r4-r11, r15
   2:	1437      	subi      	r14, r14, 92
   4:	008f      	lrw      	r4, 0x40026000	// 3c4 <ah_rf_open+0x3c4>
   6:	3004      	movi      	r0, 4
   8:	e0000000 	bsr      	0x0	// 0 <pmu_vccmipi_vol_set_sec>
   c:	9475      	ld.w      	r3, (r4, 0x54)
   e:	3b9e      	bclri      	r3, 30
  10:	b475      	st.w      	r3, (r4, 0x54)
  12:	9475      	ld.w      	r3, (r4, 0x54)
  14:	c40357c3 	zext      	r3, r3, 30, 0
  18:	3202      	movi      	r2, 2
  1a:	b475      	st.w      	r3, (r4, 0x54)
  1c:	3120      	movi      	r1, 32
  1e:	3001      	movi      	r0, 1
  20:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_open>
  24:	3500      	movi      	r5, 0
  26:	e0000000 	bsr      	0x0	// 0 <pmu_pd_set_anatop_en_sec>
  2a:	6c17      	mov      	r0, r5
  2c:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
  30:	3001      	movi      	r0, 1
  32:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
  36:	9460      	ld.w      	r3, (r4, 0x0)
  38:	3b90      	bclri      	r3, 16
  3a:	b460      	st.w      	r3, (r4, 0x0)
  3c:	9460      	ld.w      	r3, (r4, 0x0)
  3e:	3b8f      	bclri      	r3, 15
  40:	3b9f      	bclri      	r3, 31
  42:	b460      	st.w      	r3, (r4, 0x0)
  44:	9460      	ld.w      	r3, (r4, 0x0)
  46:	3bb9      	bseti      	r3, 25
  48:	b460      	st.w      	r3, (r4, 0x0)
  4a:	9473      	ld.w      	r3, (r4, 0x4c)
  4c:	3bba      	bseti      	r3, 26
  4e:	b473      	st.w      	r3, (r4, 0x4c)
  50:	3004      	movi      	r0, 4
  52:	e0000000 	bsr      	0x0	// 0 <pmu_vccmipi_vol_set_sec>
  56:	6c57      	mov      	r1, r5
  58:	302a      	movi      	r0, 42
  5a:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  5e:	3103      	movi      	r1, 3
  60:	302b      	movi      	r0, 43
  62:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  66:	3101      	movi      	r1, 1
  68:	3016      	movi      	r0, 22
  6a:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  6e:	3101      	movi      	r1, 1
  70:	3016      	movi      	r0, 22
  72:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  76:	018a      	lrw      	r4, 0x0	// 3c8 <ah_rf_open+0x3c8>
  78:	3105      	movi      	r1, 5
  7a:	3017      	movi      	r0, 23
  7c:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  80:	3105      	movi      	r1, 5
  82:	3018      	movi      	r0, 24
  84:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  88:	d8644002 	ld.bs      	r3, (r4, 0x2)
  8c:	a4a5      	st.b      	r5, (r4, 0x5)
  8e:	e923001a 	bnez      	r3, 0xc2	// c2 <ah_rf_open+0xc2>
  92:	e0000000 	bsr      	0x0	// 0 <rf_para_efuse_check_valid>
  96:	d8644003 	ld.bs      	r3, (r4, 0x3)
  9a:	e9230010 	bnez      	r3, 0xba	// ba <ah_rf_open+0xba>
  9e:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_tx_analog_gain_mcs7>
  a2:	a405      	st.b      	r0, (r4, 0x5)
  a4:	84a0      	ld.b      	r5, (r4, 0x0)
  a6:	3d02      	cmphsi      	r5, 3
  a8:	0c0f      	bf      	0xc6	// c6 <ah_rf_open+0xc6>
  aa:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_module_type>
  ae:	3844      	cmpnei      	r0, 4
  b0:	a407      	st.b      	r0, (r4, 0x7)
  b2:	0815      	bt      	0xdc	// dc <ah_rf_open+0xdc>
  b4:	3301      	movi      	r3, 1
  b6:	a467      	st.b      	r3, (r4, 0x7)
  b8:	0412      	br      	0xdc	// dc <ah_rf_open+0xdc>
  ba:	011a      	lrw      	r0, 0x0	// 3cc <ah_rf_open+0x3cc>
  bc:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  c0:	07f2      	br      	0xa4	// a4 <ah_rf_open+0xa4>
  c2:	011b      	lrw      	r0, 0x0	// 3d0 <ah_rf_open+0x3d0>
  c4:	07fc      	br      	0xbc	// bc <ah_rf_open+0xbc>
  c6:	3d42      	cmpnei      	r5, 2
  c8:	0847      	bt      	0x156	// 156 <ah_rf_open+0x156>
  ca:	8425      	ld.b      	r1, (r4, 0x5)
  cc:	011d      	lrw      	r0, 0x0	// 3d4 <ah_rf_open+0x3d4>
  ce:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  d2:	8465      	ld.b      	r3, (r4, 0x5)
  d4:	eb030032 	cmphsi      	r3, 51
  d8:	0fee      	bf      	0xb4	// b4 <ah_rf_open+0xb4>
  da:	a4a7      	st.b      	r5, (r4, 0x7)
  dc:	8467      	ld.b      	r3, (r4, 0x7)
  de:	e44320fb 	andi      	r2, r3, 251
  e2:	3a41      	cmpnei      	r2, 1
  e4:	083e      	bt      	0x160	// 160 <ah_rf_open+0x160>
  e6:	0242      	lrw      	r2, 0x0	// 3d8 <ah_rf_open+0x3d8>
  e8:	0262      	lrw      	r3, 0x0	// 3dc <ah_rf_open+0x3dc>
  ea:	3100      	movi      	r1, 0
  ec:	8a00      	ld.h      	r0, (r2, 0x0)
  ee:	2100      	addi      	r1, 1
  f0:	ab00      	st.h      	r0, (r3, 0x0)
  f2:	7444      	zextb      	r1, r1
  f4:	8a01      	ld.h      	r0, (r2, 0x2)
  f6:	ab01      	st.h      	r0, (r3, 0x2)
  f8:	3946      	cmpnei      	r1, 6
  fa:	8a02      	ld.h      	r0, (r2, 0x4)
  fc:	ab02      	st.h      	r0, (r3, 0x4)
  fe:	8a03      	ld.h      	r0, (r2, 0x6)
 100:	ab03      	st.h      	r0, (r3, 0x6)
 102:	2207      	addi      	r2, 8
 104:	2311      	addi      	r3, 18
 106:	0bf3      	bt      	0xec	// ec <ah_rf_open+0xec>
 108:	3100      	movi      	r1, 0
 10a:	6c87      	mov      	r2, r1
 10c:	3300      	movi      	r3, 0
 10e:	e4a1008f 	addi      	r5, r1, 144
 112:	e5a2004f 	addi      	r13, r2, 80
 116:	5d0c      	addu      	r0, r5, r3
 118:	ea8c00b1 	lrw      	r12, 0x0	// 3dc <ah_rf_open+0x3dc>
 11c:	6030      	addu      	r0, r12
 11e:	02ce      	lrw      	r6, 0x0	// 3e0 <ah_rf_open+0x3e0>
 120:	c46d002c 	addu      	r12, r13, r3
 124:	6318      	addu      	r12, r6
 126:	2301      	addi      	r3, 2
 128:	3b4a      	cmpnei      	r3, 10
 12a:	d98c1000 	ld.h      	r12, (r12, 0x0)
 12e:	dd801004 	st.h      	r12, (r0, 0x8)
 132:	0bf2      	bt      	0x116	// 116 <ah_rf_open+0x116>
 134:	2209      	addi      	r2, 10
 136:	eb42003c 	cmpnei      	r2, 60
 13a:	2111      	addi      	r1, 18
 13c:	0be8      	bt      	0x10c	// 10c <ah_rf_open+0x10c>
 13e:	3300      	movi      	r3, 0
 140:	0256      	lrw      	r2, 0x0	// 3e4 <ah_rf_open+0x3e4>
 142:	0235      	lrw      	r1, 0x0	// 3e8 <ah_rf_open+0x3e8>
 144:	d0610440 	ldr.h      	r0, (r1, r3 << 1)
 148:	d4620480 	str.h      	r0, (r2, r3 << 2)
 14c:	2300      	addi      	r3, 1
 14e:	eb430020 	cmpnei      	r3, 32
 152:	0bf9      	bt      	0x144	// 144 <ah_rf_open+0x144>
 154:	0430      	br      	0x1b4	// 1b4 <ah_rf_open+0x1b4>
 156:	0219      	lrw      	r0, 0x0	// 3ec <ah_rf_open+0x3ec>
 158:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 15c:	3302      	movi      	r3, 2
 15e:	07ac      	br      	0xb6	// b6 <ah_rf_open+0xb6>
 160:	3b50      	cmpnei      	r3, 16
 162:	081c      	bt      	0x19a	// 19a <ah_rf_open+0x19a>
 164:	027c      	lrw      	r3, 0x0	// 3f0 <ah_rf_open+0x3f0>
 166:	3200      	movi      	r2, 0
 168:	8b20      	ld.h      	r1, (r3, 0x0)
 16a:	2200      	addi      	r2, 1
 16c:	ec211000 	ori      	r1, r1, 4096
 170:	7488      	zextb      	r2, r2
 172:	ab20      	st.h      	r1, (r3, 0x0)
 174:	3a46      	cmpnei      	r2, 6
 176:	8b21      	ld.h      	r1, (r3, 0x2)
 178:	ec211000 	ori      	r1, r1, 4096
 17c:	ab21      	st.h      	r1, (r3, 0x2)
 17e:	2311      	addi      	r3, 18
 180:	0bf4      	bt      	0x168	// 168 <ah_rf_open+0x168>
 182:	3300      	movi      	r3, 0
 184:	0347      	lrw      	r2, 0x0	// 3e4 <ah_rf_open+0x3e4>
 186:	0323      	lrw      	r1, 0x0	// 3f4 <ah_rf_open+0x3f4>
 188:	d0610440 	ldr.h      	r0, (r1, r3 << 1)
 18c:	d4620480 	str.h      	r0, (r2, r3 << 2)
 190:	2300      	addi      	r3, 1
 192:	eb430020 	cmpnei      	r3, 32
 196:	0bf9      	bt      	0x188	// 188 <ah_rf_open+0x188>
 198:	040e      	br      	0x1b4	// 1b4 <ah_rf_open+0x1b4>
 19a:	3b43      	cmpnei      	r3, 3
 19c:	080c      	bt      	0x1b4	// 1b4 <ah_rf_open+0x1b4>
 19e:	3300      	movi      	r3, 0
 1a0:	0350      	lrw      	r2, 0x0	// 3dc <ah_rf_open+0x3dc>
 1a2:	5b28      	addu      	r1, r3, r2
 1a4:	2311      	addi      	r3, 18
 1a6:	8943      	ld.h      	r2, (r1, 0x6)
 1a8:	eb43006c 	cmpnei      	r3, 108
 1ac:	ec421000 	ori      	r2, r2, 4096
 1b0:	a943      	st.h      	r2, (r1, 0x6)
 1b2:	0bf7      	bt      	0x1a0	// 1a0 <ah_rf_open+0x1a0>
 1b4:	d8644002 	ld.bs      	r3, (r4, 0x2)
 1b8:	e9230008 	bnez      	r3, 0x1c8	// 1c8 <ah_rf_open+0x1c8>
 1bc:	d8644003 	ld.bs      	r3, (r4, 0x3)
 1c0:	e9230004 	bnez      	r3, 0x1c8	// 1c8 <ah_rf_open+0x1c8>
 1c4:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 1c8:	e0000000 	bsr      	0x0	// 0 <sysctrl_dac_init>
 1cc:	e0000000 	bsr      	0x0	// 0 <is_adc_calibed>
 1d0:	e9000018 	bez      	r0, 0x200	// 200 <ah_rf_open+0x200>
 1d4:	e0000000 	bsr      	0x0	// 0 <adc_init>
 1d8:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 1dc:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 1e0:	e9000043 	bez      	r0, 0x266	// 266 <ah_rf_open+0x266>
 1e4:	3003      	movi      	r0, 3
 1e6:	e0000000 	bsr      	0x0	// 0 <pmu_vdd_vol_set_sec>
 1ea:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 1ee:	3006      	movi      	r0, 6
 1f0:	e0000000 	bsr      	0x0	// 0 <pmu_vdd_vol_set_sec>
 1f4:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 1f8:	e9200044 	bnez      	r0, 0x280	// 280 <ah_rf_open+0x280>
 1fc:	131f      	lrw      	r0, 0x0	// 3f8 <ah_rf_open+0x3f8>
 1fe:	0435      	br      	0x268	// 268 <ah_rf_open+0x268>
 200:	e0000000 	bsr      	0x0	// 0 <adc_calib_res_restore>
 204:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 208:	e920ffe6 	bnez      	r0, 0x1d4	// 1d4 <ah_rf_open+0x1d4>
 20c:	30fa      	movi      	r0, 250
 20e:	4002      	lsli      	r0, r0, 2
 210:	e0000000 	bsr      	0x0	// 0 <delay_us>
 214:	8467      	ld.b      	r3, (r4, 0x7)
 216:	e44320fb 	andi      	r2, r3, 251
 21a:	3a41      	cmpnei      	r2, 1
 21c:	0840      	bt      	0x29c	// 29c <ah_rf_open+0x29c>
 21e:	1318      	lrw      	r0, 0x0	// 3fc <ah_rf_open+0x3fc>
 220:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 224:	ea00c5c1 	movi      	r0, 50625
 228:	c4804900 	rotli      	r0, r0, 4
 22c:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 230:	e9200024 	bnez      	r0, 0x278	// 278 <ah_rf_open+0x278>
 234:	d8644003 	ld.bs      	r3, (r4, 0x3)
 238:	e903004b 	bez      	r3, 0x2ce	// 2ce <ah_rf_open+0x2ce>
 23c:	3202      	movi      	r2, 2
 23e:	1904      	addi      	r1, r14, 16
 240:	3001      	movi      	r0, 1
 242:	e0000000 	bsr      	0x0	// 0 <memory_read>
 246:	e92003b2 	bnez      	r0, 0x9aa	// 9aa <ah_rf_open+0x9aa>
 24a:	d86e500a 	ld.hs      	r3, (r14, 0x14)
 24e:	eb430055 	cmpnei      	r3, 85
 252:	e86003ac 	bt      	0x9aa	// 9aa <ah_rf_open+0x9aa>
 256:	136b      	lrw      	r3, 0x0	// 400 <ah_rf_open+0x400>
 258:	d84e1008 	ld.h      	r2, (r14, 0x10)
 25c:	ab40      	st.h      	r2, (r3, 0x0)
 25e:	d84e1009 	ld.h      	r2, (r14, 0x12)
 262:	ab41      	st.h      	r2, (r3, 0x2)
 264:	0439      	br      	0x2d6	// 2d6 <ah_rf_open+0x2d6>
 266:	1308      	lrw      	r0, 0x0	// 404 <ah_rf_open+0x404>
 268:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 26c:	e0000000 	bsr      	0x0	// 0 <adc_calib_res_store>
 270:	3300      	movi      	r3, 0
 272:	2b00      	subi      	r3, 1
 274:	64c2      	cmpne      	r0, r3
 276:	0bcb      	bt      	0x20c	// 20c <ah_rf_open+0x20c>
 278:	3000      	movi      	r0, 0
 27a:	2800      	subi      	r0, 1
 27c:	1417      	addi      	r14, r14, 92
 27e:	1498      	pop      	r4-r11, r15
 280:	3007      	movi      	r0, 7
 282:	e0000000 	bsr      	0x0	// 0 <pmu_vdd_vol_set_sec>
 286:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 28a:	3006      	movi      	r0, 6
 28c:	e0000000 	bsr      	0x0	// 0 <pmu_vdd_vol_set_sec>
 290:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 294:	e920ffec 	bnez      	r0, 0x26c	// 26c <ah_rf_open+0x26c>
 298:	121c      	lrw      	r0, 0x0	// 408 <ah_rf_open+0x408>
 29a:	07e7      	br      	0x268	// 268 <ah_rf_open+0x268>
 29c:	3b50      	cmpnei      	r3, 16
 29e:	0809      	bt      	0x2b0	// 2b0 <ah_rf_open+0x2b0>
 2a0:	121b      	lrw      	r0, 0x0	// 40c <ah_rf_open+0x40c>
 2a2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2a6:	ea00cf85 	movi      	r0, 53125
 2aa:	c4804900 	rotli      	r0, r0, 4
 2ae:	07bf      	br      	0x22c	// 22c <ah_rf_open+0x22c>
 2b0:	3b43      	cmpnei      	r3, 3
 2b2:	0809      	bt      	0x2c4	// 2c4 <ah_rf_open+0x2c4>
 2b4:	1217      	lrw      	r0, 0x0	// 410 <ah_rf_open+0x410>
 2b6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2ba:	ea00d36d 	movi      	r0, 54125
 2be:	c4804900 	rotli      	r0, r0, 4
 2c2:	07b5      	br      	0x22c	// 22c <ah_rf_open+0x22c>
 2c4:	1214      	lrw      	r0, 0x0	// 414 <ah_rf_open+0x414>
 2c6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2ca:	1214      	lrw      	r0, 0xdf638	// 418 <ah_rf_open+0x418>
 2cc:	07b0      	br      	0x22c	// 22c <ah_rf_open+0x22c>
 2ce:	d8644002 	ld.bs      	r3, (r4, 0x2)
 2d2:	e923ffb5 	bnez      	r3, 0x23c	// 23c <ah_rf_open+0x23c>
 2d6:	3500      	movi      	r5, 0
 2d8:	12ca      	lrw      	r6, 0x0	// 400 <ah_rf_open+0x400>
 2da:	6c57      	mov      	r1, r5
 2dc:	2500      	addi      	r5, 1
 2de:	6c1b      	mov      	r0, r6
 2e0:	7554      	zextb      	r5, r5
 2e2:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_tx_dcoc>
 2e6:	3d46      	cmpnei      	r5, 6
 2e8:	0bf9      	bt      	0x2da	// 2da <ah_rf_open+0x2da>
 2ea:	8460      	ld.b      	r3, (r4, 0x0)
 2ec:	e90300b0 	bez      	r3, 0x44c	// 44c <ah_rf_open+0x44c>
 2f0:	d8644003 	ld.bs      	r3, (r4, 0x3)
 2f4:	e92300ac 	bnez      	r3, 0x44c	// 44c <ah_rf_open+0x44c>
 2f8:	d8644002 	ld.bs      	r3, (r4, 0x2)
 2fc:	e92300a8 	bnez      	r3, 0x44c	// 44c <ah_rf_open+0x44c>
 300:	320f      	movi      	r2, 15
 302:	6c7b      	mov      	r1, r14
 304:	308a      	movi      	r0, 138
 306:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_config_and_read>
 30a:	d86e0000 	ld.b      	r3, (r14, 0x0)
 30e:	e903008b 	bez      	r3, 0x424	// 424 <ah_rf_open+0x424>
 312:	6d7b      	mov      	r5, r14
 314:	6cbb      	mov      	r2, r14
 316:	3000      	movi      	r0, 0
 318:	d9820001 	ld.b      	r12, (r2, 0x1)
 31c:	1260      	lrw      	r3, 0x0	// 41c <ah_rf_open+0x41c>
 31e:	c50c4821 	lsli      	r1, r12, 8
 322:	c460002d 	addu      	r13, r0, r3
 326:	e4212300 	andi      	r1, r1, 768
 32a:	8260      	ld.b      	r3, (r2, 0x0)
 32c:	6c4c      	or      	r1, r3
 32e:	8262      	ld.b      	r3, (r2, 0x2)
 330:	4364      	lsli      	r3, r3, 4
 332:	2003      	addi      	r0, 4
 334:	e46323f0 	andi      	r3, r3, 1008
 338:	c48c484c 	lsri      	r12, r12, 4
 33c:	384c      	cmpnei      	r0, 12
 33e:	6cf0      	or      	r3, r12
 340:	dc2d102a 	st.h      	r1, (r13, 0x54)
 344:	dc6d102b 	st.h      	r3, (r13, 0x56)
 348:	2202      	addi      	r2, 3
 34a:	0be7      	bt      	0x318	// 318 <ah_rf_open+0x318>
 34c:	d86e000a 	ld.b      	r3, (r14, 0xa)
 350:	4368      	lsli      	r3, r3, 8
 352:	11d4      	lrw      	r6, 0x0	// 420 <ah_rf_open+0x420>
 354:	d84e0009 	ld.b      	r2, (r14, 0x9)
 358:	e4632f00 	andi      	r3, r3, 3840
 35c:	6cc8      	or      	r3, r2
 35e:	ae75      	st.h      	r3, (r6, 0x2a)
 360:	d86e000c 	ld.b      	r3, (r14, 0xc)
 364:	4368      	lsli      	r3, r3, 8
 366:	d84e000b 	ld.b      	r2, (r14, 0xb)
 36a:	e4632f00 	andi      	r3, r3, 3840
 36e:	6cc8      	or      	r3, r2
 370:	ae76      	st.h      	r3, (r6, 0x2c)
 372:	d86e000e 	ld.b      	r3, (r14, 0xe)
 376:	4368      	lsli      	r3, r3, 8
 378:	d84e000d 	ld.b      	r2, (r14, 0xd)
 37c:	e4632f00 	andi      	r3, r3, 3840
 380:	6cc8      	or      	r3, r2
 382:	6c7b      	mov      	r1, r14
 384:	320f      	movi      	r2, 15
 386:	30f0      	movi      	r0, 240
 388:	ae77      	st.h      	r3, (r6, 0x2e)
 38a:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_config_and_read>
 38e:	d82e0000 	ld.b      	r1, (r14, 0x0)
 392:	6c9b      	mov      	r2, r6
 394:	e921006e 	bnez      	r1, 0x470	// 470 <ah_rf_open+0x470>
 398:	d86e0001 	ld.b      	r3, (r14, 0x1)
 39c:	e923006a 	bnez      	r3, 0x470	// 470 <ah_rf_open+0x470>
 3a0:	d82e0003 	ld.b      	r1, (r14, 0x3)
 3a4:	e9210067 	bnez      	r1, 0x472	// 472 <ah_rf_open+0x472>
 3a8:	d86e0004 	ld.b      	r3, (r14, 0x4)
 3ac:	e923000a 	bnez      	r3, 0x3c0	// 3c0 <ah_rf_open+0x3c0>
 3b0:	d82e0006 	ld.b      	r1, (r14, 0x6)
 3b4:	e921005f 	bnez      	r1, 0x472	// 472 <ah_rf_open+0x472>
 3b8:	d86e0007 	ld.b      	r3, (r14, 0x7)
 3bc:	e90300b5 	bez      	r3, 0x526	// 526 <ah_rf_open+0x526>
 3c0:	6cc7      	mov      	r3, r1
 3c2:	0458      	br      	0x472	// 472 <ah_rf_open+0x472>
 3c4:	40026000 	.long	0x40026000
	...
 418:	000df638 	.long	0x000df638
	...
 424:	d86e0001 	ld.b      	r3, (r14, 0x1)
 428:	e923ff75 	bnez      	r3, 0x312	// 312 <ah_rf_open+0x312>
 42c:	d86e0003 	ld.b      	r3, (r14, 0x3)
 430:	e923ff71 	bnez      	r3, 0x312	// 312 <ah_rf_open+0x312>
 434:	d86e0004 	ld.b      	r3, (r14, 0x4)
 438:	e923ff6d 	bnez      	r3, 0x312	// 312 <ah_rf_open+0x312>
 43c:	d86e0006 	ld.b      	r3, (r14, 0x6)
 440:	e923ff69 	bnez      	r3, 0x312	// 312 <ah_rf_open+0x312>
 444:	d86e0007 	ld.b      	r3, (r14, 0x7)
 448:	e923ff65 	bnez      	r3, 0x312	// 312 <ah_rf_open+0x312>
 44c:	1d04      	addi      	r5, r14, 16
 44e:	3213      	movi      	r2, 19
 450:	6c57      	mov      	r1, r5
 452:	3003      	movi      	r0, 3
 454:	e0000000 	bsr      	0x0	// 0 <memory_read>
 458:	e9200007 	bnez      	r0, 0x466	// 466 <ah_rf_open+0x466>
 45c:	d8655024 	ld.hs      	r3, (r5, 0x48)
 460:	eb430055 	cmpnei      	r3, 85
 464:	0c73      	bf      	0x54a	// 54a <ah_rf_open+0x54a>
 466:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 46a:	3200      	movi      	r2, 0
 46c:	6ccb      	mov      	r3, r2
 46e:	04c1      	br      	0x5f0	// 5f0 <ah_rf_open+0x5f0>
 470:	3300      	movi      	r3, 0
 472:	d9850001 	ld.b      	r12, (r5, 0x1)
 476:	ea81011c 	lrw      	r1, 0x0	// 8e4 <ah_rf_open+0x8e4>
 47a:	c50c4820 	lsli      	r0, r12, 8
 47e:	c423002d 	addu      	r13, r3, r1
 482:	e4002300 	andi      	r0, r0, 768
 486:	8520      	ld.b      	r1, (r5, 0x0)
 488:	6c04      	or      	r0, r1
 48a:	8522      	ld.b      	r1, (r5, 0x2)
 48c:	4124      	lsli      	r1, r1, 4
 48e:	2303      	addi      	r3, 4
 490:	e42123f0 	andi      	r1, r1, 1008
 494:	c48c484c 	lsri      	r12, r12, 4
 498:	3b4c      	cmpnei      	r3, 12
 49a:	6c70      	or      	r1, r12
 49c:	dc0d1024 	st.h      	r0, (r13, 0x48)
 4a0:	dc2d1025 	st.h      	r1, (r13, 0x4a)
 4a4:	2502      	addi      	r5, 3
 4a6:	0be6      	bt      	0x472	// 472 <ah_rf_open+0x472>
 4a8:	d86e000a 	ld.b      	r3, (r14, 0xa)
 4ac:	4368      	lsli      	r3, r3, 8
 4ae:	d82e0009 	ld.b      	r1, (r14, 0x9)
 4b2:	e4632f00 	andi      	r3, r3, 3840
 4b6:	6cc4      	or      	r3, r1
 4b8:	aa72      	st.h      	r3, (r2, 0x24)
 4ba:	d86e000c 	ld.b      	r3, (r14, 0xc)
 4be:	4368      	lsli      	r3, r3, 8
 4c0:	d82e000b 	ld.b      	r1, (r14, 0xb)
 4c4:	e4632f00 	andi      	r3, r3, 3840
 4c8:	6cc4      	or      	r3, r1
 4ca:	aa73      	st.h      	r3, (r2, 0x26)
 4cc:	d86e000e 	ld.b      	r3, (r14, 0xe)
 4d0:	4368      	lsli      	r3, r3, 8
 4d2:	e4632f00 	andi      	r3, r3, 3840
 4d6:	d82e000d 	ld.b      	r1, (r14, 0xd)
 4da:	6cc4      	or      	r3, r1
 4dc:	aa74      	st.h      	r3, (r2, 0x28)
 4de:	3300      	movi      	r3, 0
 4e0:	6f0f      	mov      	r12, r3
 4e2:	ea860101 	lrw      	r6, 0x0	// 8e4 <ah_rf_open+0x8e4>
 4e6:	c5860080 	subu      	r0, r6, r12
 4ea:	3100      	movi      	r1, 0
 4ec:	5aac      	addu      	r5, r2, r3
 4ee:	c580002d 	addu      	r13, r0, r12
 4f2:	d8ed1024 	ld.h      	r7, (r13, 0x48)
 4f6:	a8e0      	st.h      	r7, (r0, 0x0)
 4f8:	d9ad1025 	ld.h      	r13, (r13, 0x4a)
 4fc:	dda01001 	st.h      	r13, (r0, 0x2)
 500:	c422002d 	addu      	r13, r2, r1
 504:	2003      	addi      	r0, 4
 506:	d9ad1012 	ld.h      	r13, (r13, 0x24)
 50a:	d425042d 	str.h      	r13, (r5, r1 << 0)
 50e:	2101      	addi      	r1, 2
 510:	394c      	cmpnei      	r1, 12
 512:	0bee      	bt      	0x4ee	// 4ee <ah_rf_open+0x4ee>
 514:	230b      	addi      	r3, 12
 516:	eb430024 	cmpnei      	r3, 36
 51a:	e58c1017 	subi      	r12, r12, 24
 51e:	0be4      	bt      	0x4e6	// 4e6 <ah_rf_open+0x4e6>
 520:	3700      	movi      	r7, 0
 522:	6d5f      	mov      	r5, r7
 524:	04e9      	br      	0x6f6	// 6f6 <ah_rf_open+0x6f6>
 526:	000f      	lrw      	r0, 0x0	// 8e4 <ah_rf_open+0x8e4>
 528:	0030      	lrw      	r1, 0x0	// 8e4 <ah_rf_open+0x8e4>
 52a:	604c      	addu      	r1, r3
 52c:	d980102a 	ld.h      	r12, (r0, 0x54)
 530:	2303      	addi      	r3, 4
 532:	dd811024 	st.h      	r12, (r1, 0x48)
 536:	3b4c      	cmpnei      	r3, 12
 538:	d980102b 	ld.h      	r12, (r0, 0x56)
 53c:	dd811025 	st.h      	r12, (r1, 0x4a)
 540:	0bf4      	bt      	0x528	// 528 <ah_rf_open+0x528>
 542:	8a75      	ld.h      	r3, (r2, 0x2a)
 544:	aa72      	st.h      	r3, (r2, 0x24)
 546:	aa73      	st.h      	r3, (r2, 0x26)
 548:	07ca      	br      	0x4dc	// 4dc <ah_rf_open+0x4dc>
 54a:	6cc3      	mov      	r3, r0
 54c:	0058      	lrw      	r2, 0x0	// 8e8 <ah_rf_open+0x8e8>
 54e:	5828      	addu      	r1, r0, r2
 550:	5b56      	addi      	r2, r3, 6
 552:	7488      	zextb      	r2, r2
 554:	e5830000 	addi      	r12, r3, 1
 558:	d065044d 	ldr.h      	r13, (r5, r3 << 1)
 55c:	2301      	addi      	r3, 2
 55e:	74cc      	zextb      	r3, r3
 560:	7730      	zextb      	r12, r12
 562:	64ca      	cmpne      	r2, r3
 564:	d185044c 	ldr.h      	r12, (r5, r12 << 1)
 568:	dda11000 	st.h      	r13, (r1, 0x0)
 56c:	dd811001 	st.h      	r12, (r1, 0x2)
 570:	2103      	addi      	r1, 4
 572:	0bf1      	bt      	0x554	// 554 <ah_rf_open+0x554>
 574:	3a58      	cmpnei      	r2, 24
 576:	2017      	addi      	r0, 24
 578:	0bea      	bt      	0x54c	// 54c <ah_rf_open+0x54c>
 57a:	0162      	lrw      	r3, 0x0	// 8ec <ah_rf_open+0x8ec>
 57c:	3200      	movi      	r2, 0
 57e:	5d28      	addu      	r1, r5, r2
 580:	2205      	addi      	r2, 6
 582:	8918      	ld.h      	r0, (r1, 0x30)
 584:	3a58      	cmpnei      	r2, 24
 586:	ab00      	st.h      	r0, (r3, 0x0)
 588:	8919      	ld.h      	r0, (r1, 0x32)
 58a:	893a      	ld.h      	r1, (r1, 0x34)
 58c:	ab01      	st.h      	r0, (r3, 0x2)
 58e:	ab22      	st.h      	r1, (r3, 0x4)
 590:	230b      	addi      	r3, 12
 592:	0bf6      	bt      	0x57e	// 57e <ah_rf_open+0x57e>
 594:	016b      	lrw      	r3, 0x0	// 8e4 <ah_rf_open+0x8e4>
 596:	3200      	movi      	r2, 0
 598:	ea8d00d6 	lrw      	r13, 0x0	// 8f0 <ah_rf_open+0x8f0>
 59c:	0412      	br      	0x5c0	// 5c0 <ah_rf_open+0x5c0>
 59e:	8ba6      	ld.h      	r5, (r3, 0xc)
 5a0:	a8a0      	st.h      	r5, (r0, 0x0)
 5a2:	8ba7      	ld.h      	r5, (r3, 0xe)
 5a4:	a8a1      	st.h      	r5, (r0, 0x2)
 5a6:	d8ac1003 	ld.h      	r5, (r12, 0x6)
 5aa:	d42c0445 	str.h      	r5, (r12, r1 << 1)
 5ae:	2100      	addi      	r1, 1
 5b0:	3943      	cmpnei      	r1, 3
 5b2:	2003      	addi      	r0, 4
 5b4:	0bf5      	bt      	0x59e	// 59e <ah_rf_open+0x59e>
 5b6:	220b      	addi      	r2, 12
 5b8:	eb420030 	cmpnei      	r2, 48
 5bc:	2317      	addi      	r3, 24
 5be:	0fb1      	bf      	0x520	// 520 <ah_rf_open+0x520>
 5c0:	6c0f      	mov      	r0, r3
 5c2:	3100      	movi      	r1, 0
 5c4:	c44d002c 	addu      	r12, r13, r2
 5c8:	07eb      	br      	0x59e	// 59e <ah_rf_open+0x59e>
 5ca:	d9a01000 	ld.h      	r13, (r0, 0x0)
 5ce:	d465044d 	str.h      	r13, (r5, r3 << 1)
 5d2:	e5830000 	addi      	r12, r3, 1
 5d6:	2301      	addi      	r3, 2
 5d8:	74cc      	zextb      	r3, r3
 5da:	64c6      	cmpne      	r1, r3
 5dc:	d9a01001 	ld.h      	r13, (r0, 0x2)
 5e0:	7730      	zextb      	r12, r12
 5e2:	d585044d 	str.h      	r13, (r5, r12 << 1)
 5e6:	2003      	addi      	r0, 4
 5e8:	0bf1      	bt      	0x5ca	// 5ca <ah_rf_open+0x5ca>
 5ea:	3958      	cmpnei      	r1, 24
 5ec:	2217      	addi      	r2, 24
 5ee:	0c06      	bf      	0x5fa	// 5fa <ah_rf_open+0x5fa>
 5f0:	0221      	lrw      	r1, 0x0	// 8e8 <ah_rf_open+0x8e8>
 5f2:	5a04      	addu      	r0, r2, r1
 5f4:	5b36      	addi      	r1, r3, 6
 5f6:	7444      	zextb      	r1, r1
 5f8:	07e9      	br      	0x5ca	// 5ca <ah_rf_open+0x5ca>
 5fa:	0262      	lrw      	r3, 0x0	// 8ec <ah_rf_open+0x8ec>
 5fc:	3200      	movi      	r2, 0
 5fe:	5d28      	addu      	r1, r5, r2
 600:	8b00      	ld.h      	r0, (r3, 0x0)
 602:	2205      	addi      	r2, 6
 604:	a918      	st.h      	r0, (r1, 0x30)
 606:	3a58      	cmpnei      	r2, 24
 608:	8b01      	ld.h      	r0, (r3, 0x2)
 60a:	a919      	st.h      	r0, (r1, 0x32)
 60c:	8b02      	ld.h      	r0, (r3, 0x4)
 60e:	a91a      	st.h      	r0, (r1, 0x34)
 610:	230b      	addi      	r3, 12
 612:	0bf6      	bt      	0x5fe	// 5fe <ah_rf_open+0x5fe>
 614:	3212      	movi      	r2, 18
 616:	6c57      	mov      	r1, r5
 618:	3003      	movi      	r0, 3
 61a:	e0000000 	bsr      	0x0	// 0 <memory_write>
 61e:	3300      	movi      	r3, 0
 620:	2b00      	subi      	r3, 1
 622:	64c2      	cmpne      	r0, r3
 624:	0e2a      	bf      	0x278	// 278 <ah_rf_open+0x278>
 626:	d8644003 	ld.bs      	r3, (r4, 0x3)
 62a:	02ec      	lrw      	r7, 0x0	// 8f4 <ah_rf_open+0x8f4>
 62c:	02cc      	lrw      	r6, 0x0	// 8f8 <ah_rf_open+0x8f8>
 62e:	e9230006 	bnez      	r3, 0x63a	// 63a <ah_rf_open+0x63a>
 632:	d8644002 	ld.bs      	r3, (r4, 0x2)
 636:	e9030014 	bez      	r3, 0x65e	// 65e <ah_rf_open+0x65e>
 63a:	3203      	movi      	r2, 3
 63c:	1904      	addi      	r1, r14, 16
 63e:	3002      	movi      	r0, 2
 640:	e0000000 	bsr      	0x0	// 0 <memory_read>
 644:	e92001c1 	bnez      	r0, 0x9c6	// 9c6 <ah_rf_open+0x9c6>
 648:	d86e500c 	ld.hs      	r3, (r14, 0x18)
 64c:	eb430055 	cmpnei      	r3, 85
 650:	09bb      	bt      	0x9c6	// 9c6 <ah_rf_open+0x9c6>
 652:	d86e100a 	ld.h      	r3, (r14, 0x14)
 656:	af60      	st.h      	r3, (r7, 0x0)
 658:	d86e100b 	ld.h      	r3, (r14, 0x16)
 65c:	ae60      	st.h      	r3, (r6, 0x0)
 65e:	3500      	movi      	r5, 0
 660:	6c97      	mov      	r2, r5
 662:	2500      	addi      	r5, 1
 664:	8e20      	ld.h      	r1, (r6, 0x0)
 666:	d8075000 	ld.hs      	r0, (r7, 0x0)
 66a:	7554      	zextb      	r5, r5
 66c:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_imb>
 670:	3d46      	cmpnei      	r5, 6
 672:	0bf7      	bt      	0x660	// 660 <ah_rf_open+0x660>
 674:	d8644003 	ld.bs      	r3, (r4, 0x3)
 678:	e9230150 	bnez      	r3, 0x918	// 918 <ah_rf_open+0x918>
 67c:	d8644002 	ld.bs      	r3, (r4, 0x2)
 680:	e923014c 	bnez      	r3, 0x918	// 918 <ah_rf_open+0x918>
 684:	320f      	movi      	r2, 15
 686:	1904      	addi      	r1, r14, 16
 688:	ea00010d 	movi      	r0, 269
 68c:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_config_and_read>
 690:	d86e0010 	ld.b      	r3, (r14, 0x10)
 694:	e9030033 	bez      	r3, 0x6fa	// 6fa <ah_rf_open+0x6fa>
 698:	e58e000f 	addi      	r12, r14, 16
 69c:	3000      	movi      	r0, 0
 69e:	d82c0001 	ld.b      	r1, (r12, 0x1)
 6a2:	4148      	lsli      	r2, r1, 8
 6a4:	0369      	lrw      	r3, 0x0	// 8fc <ah_rf_open+0x8fc>
 6a6:	60c0      	addu      	r3, r0
 6a8:	d9ac0000 	ld.b      	r13, (r12, 0x0)
 6ac:	e4422f00 	andi      	r2, r2, 3840
 6b0:	6cb4      	or      	r2, r13
 6b2:	ab41      	st.h      	r2, (r3, 0x2)
 6b4:	4924      	lsri      	r1, r1, 4
 6b6:	036c      	lrw      	r3, 0x0	// 900 <ah_rf_open+0x900>
 6b8:	584c      	addu      	r2, r0, r3
 6ba:	d86c0002 	ld.b      	r3, (r12, 0x2)
 6be:	4364      	lsli      	r3, r3, 4
 6c0:	2001      	addi      	r0, 2
 6c2:	e46323f0 	andi      	r3, r3, 1008
 6c6:	384a      	cmpnei      	r0, 10
 6c8:	6cc4      	or      	r3, r1
 6ca:	aa61      	st.h      	r3, (r2, 0x2)
 6cc:	e58c0002 	addi      	r12, r12, 3
 6d0:	0be7      	bt      	0x69e	// 69e <ah_rf_open+0x69e>
 6d2:	3500      	movi      	r5, 0
 6d4:	0557      	br      	0x982	// 982 <ah_rf_open+0x982>
 6d6:	5f18      	addu      	r0, r7, r6
 6d8:	037c      	lrw      	r3, 0x0	// 8e4 <ah_rf_open+0x8e4>
 6da:	4002      	lsli      	r0, r0, 2
 6dc:	7458      	zextb      	r1, r6
 6de:	6c97      	mov      	r2, r5
 6e0:	600c      	addu      	r0, r3
 6e2:	2600      	addi      	r6, 1
 6e4:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_dcoc>
 6e8:	3e46      	cmpnei      	r6, 6
 6ea:	0bf6      	bt      	0x6d6	// 6d6 <ah_rf_open+0x6d6>
 6ec:	2500      	addi      	r5, 1
 6ee:	7554      	zextb      	r5, r5
 6f0:	3d44      	cmpnei      	r5, 4
 6f2:	2705      	addi      	r7, 6
 6f4:	0f99      	bf      	0x626	// 626 <ah_rf_open+0x626>
 6f6:	3600      	movi      	r6, 0
 6f8:	07ef      	br      	0x6d6	// 6d6 <ah_rf_open+0x6d6>
 6fa:	d86e0011 	ld.b      	r3, (r14, 0x11)
 6fe:	e923ffcd 	bnez      	r3, 0x698	// 698 <ah_rf_open+0x698>
 702:	d86e0012 	ld.b      	r3, (r14, 0x12)
 706:	e923ffc9 	bnez      	r3, 0x698	// 698 <ah_rf_open+0x698>
 70a:	d86e0013 	ld.b      	r3, (r14, 0x13)
 70e:	e923ffc5 	bnez      	r3, 0x698	// 698 <ah_rf_open+0x698>
 712:	d86e0014 	ld.b      	r3, (r14, 0x14)
 716:	e923ffc1 	bnez      	r3, 0x698	// 698 <ah_rf_open+0x698>
 71a:	d86e0015 	ld.b      	r3, (r14, 0x15)
 71e:	e923ffbd 	bnez      	r3, 0x698	// 698 <ah_rf_open+0x698>
 722:	1379      	lrw      	r3, 0x40026000	// 904 <ah_rf_open+0x904>
 724:	3700      	movi      	r7, 0
 726:	9353      	ld.w      	r2, (r3, 0x4c)
 728:	3a97      	bclri      	r2, 23
 72a:	b353      	st.w      	r2, (r3, 0x4c)
 72c:	9353      	ld.w      	r2, (r3, 0x4c)
 72e:	3ab7      	bseti      	r2, 23
 730:	b353      	st.w      	r2, (r3, 0x4c)
 732:	6d5f      	mov      	r5, r7
 734:	1375      	lrw      	r3, 0x0	// 908 <ah_rf_open+0x908>
 736:	6d97      	mov      	r6, r5
 738:	ea080000 	movi      	r8, 0
 73c:	c4670029 	addu      	r9, r7, r3
 740:	d1090441 	ldr.h      	r1, (r9, r8 << 1)
 744:	6c1b      	mov      	r0, r6
 746:	7445      	zexth      	r1, r1
 748:	e5080000 	addi      	r8, r8, 1
 74c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
 750:	eb480022 	cmpnei      	r8, 34
 754:	2600      	addi      	r6, 1
 756:	7599      	zexth      	r6, r6
 758:	0bf4      	bt      	0x740	// 740 <ah_rf_open+0x740>
 75a:	253f      	addi      	r5, 64
 75c:	7555      	zexth      	r5, r5
 75e:	eb450100 	cmpnei      	r5, 256
 762:	2743      	addi      	r7, 68
 764:	0be8      	bt      	0x734	// 734 <ah_rf_open+0x734>
 766:	3580      	movi      	r5, 128
 768:	ea080000 	movi      	r8, 0
 76c:	45a2      	lsli      	r5, r5, 2
 76e:	1368      	lrw      	r3, 0x0	// 90c <ah_rf_open+0x90c>
 770:	6d97      	mov      	r6, r5
 772:	3700      	movi      	r7, 0
 774:	c4680029 	addu      	r9, r8, r3
 778:	d0e90441 	ldr.h      	r1, (r9, r7 << 1)
 77c:	6c1b      	mov      	r0, r6
 77e:	7445      	zexth      	r1, r1
 780:	2700      	addi      	r7, 1
 782:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
 786:	3f49      	cmpnei      	r7, 9
 788:	2600      	addi      	r6, 1
 78a:	7599      	zexth      	r6, r6
 78c:	0bf6      	bt      	0x778	// 778 <ah_rf_open+0x778>
 78e:	250f      	addi      	r5, 16
 790:	7555      	zexth      	r5, r5
 792:	eb450300 	cmpnei      	r5, 768
 796:	e5080011 	addi      	r8, r8, 18
 79a:	0bea      	bt      	0x76e	// 76e <ah_rf_open+0x76e>
 79c:	3580      	movi      	r5, 128
 79e:	ea080000 	movi      	r8, 0
 7a2:	45a3      	lsli      	r5, r5, 3
 7a4:	127b      	lrw      	r3, 0x0	// 910 <ah_rf_open+0x910>
 7a6:	6d97      	mov      	r6, r5
 7a8:	3700      	movi      	r7, 0
 7aa:	c4680029 	addu      	r9, r8, r3
 7ae:	d0e90441 	ldr.h      	r1, (r9, r7 << 1)
 7b2:	6c1b      	mov      	r0, r6
 7b4:	7445      	zexth      	r1, r1
 7b6:	2700      	addi      	r7, 1
 7b8:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
 7bc:	3f43      	cmpnei      	r7, 3
 7be:	2600      	addi      	r6, 1
 7c0:	7599      	zexth      	r6, r6
 7c2:	0bf6      	bt      	0x7ae	// 7ae <ah_rf_open+0x7ae>
 7c4:	2507      	addi      	r5, 8
 7c6:	7555      	zexth      	r5, r5
 7c8:	eb450440 	cmpnei      	r5, 1088
 7cc:	e5080005 	addi      	r8, r8, 6
 7d0:	0bea      	bt      	0x7a4	// 7a4 <ah_rf_open+0x7a4>
 7d2:	35e0      	movi      	r5, 224
 7d4:	45a3      	lsli      	r5, r5, 3
 7d6:	3600      	movi      	r6, 0
 7d8:	ea89004f 	lrw      	r9, 0x0	// 914 <ah_rf_open+0x914>
 7dc:	12e5      	lrw      	r7, 0x0	// 8f0 <ah_rf_open+0x8f0>
 7de:	ea080006 	movi      	r8, 6
 7e2:	d0c90481 	ldr.h      	r1, (r9, r6 << 2)
 7e6:	7445      	zexth      	r1, r1
 7e8:	6c17      	mov      	r0, r5
 7ea:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
 7ee:	c446482a 	lsli      	r10, r6, 2
 7f2:	1269      	lrw      	r3, 0x0	// 914 <ah_rf_open+0x914>
 7f4:	628c      	addu      	r10, r3
 7f6:	76d8      	zextb      	r11, r6
 7f8:	d82a1001 	ld.h      	r1, (r10, 0x2)
 7fc:	ea030fff 	movi      	r3, 4095
 800:	6cce      	nor      	r3, r3
 802:	684c      	and      	r1, r3
 804:	c46b4843 	lsri      	r3, r11, 3
 808:	e44b2007 	andi      	r2, r11, 7
 80c:	7ce0      	mult      	r3, r8
 80e:	60c8      	addu      	r3, r2
 810:	d0670443 	ldr.h      	r3, (r7, r3 << 1)
 814:	6c4c      	or      	r1, r3
 816:	5d02      	addi      	r0, r5, 1
 818:	7445      	zexth      	r1, r1
 81a:	7401      	zexth      	r0, r0
 81c:	2600      	addi      	r6, 1
 81e:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
 822:	eb460040 	cmpnei      	r6, 64
 826:	2501      	addi      	r5, 2
 828:	7555      	zexth      	r5, r5
 82a:	0bdc      	bt      	0x7e2	// 7e2 <ah_rf_open+0x7e2>
 82c:	30a0      	movi      	r0, 160
 82e:	3100      	movi      	r1, 0
 830:	4001      	lsli      	r0, r0, 1
 832:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
 836:	3100      	movi      	r1, 0
 838:	ea000141 	movi      	r0, 321
 83c:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
 840:	30a1      	movi      	r0, 161
 842:	3100      	movi      	r1, 0
 844:	4001      	lsli      	r0, r0, 1
 846:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
 84a:	30c4      	movi      	r0, 196
 84c:	3100      	movi      	r1, 0
 84e:	4002      	lsli      	r0, r0, 2
 850:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
 854:	3089      	movi      	r0, 137
 856:	3100      	movi      	r1, 0
 858:	4003      	lsli      	r0, r0, 3
 85a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
 85e:	3100      	movi      	r1, 0
 860:	ea000782 	movi      	r0, 1922
 864:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
 868:	e0000000 	bsr      	0x0	// 0 <is_xo_cs_calibed>
 86c:	3300      	movi      	r3, 0
 86e:	2b00      	subi      	r3, 1
 870:	64c2      	cmpne      	r0, r3
 872:	0c8f      	bf      	0x990	// 990 <ah_rf_open+0x990>
 874:	7400      	zextb      	r0, r0
 876:	e0000000 	bsr      	0x0	// 0 <xo_set_cs_sec>
 87a:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_xo_ct>
 87e:	e0000000 	bsr      	0x0	// 0 <xo_set_ct_sec>
 882:	3000      	movi      	r0, 0
 884:	e0000000 	bsr      	0x0	// 0 <ah_set_dbgpath_device_path_mode>
 888:	3000      	movi      	r0, 0
 88a:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
 88e:	3001      	movi      	r0, 1
 890:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
 894:	e0000000 	bsr      	0x0	// 0 <lmac_rf_hw_ctrl>
 898:	107b      	lrw      	r3, 0x40026000	// 904 <ah_rf_open+0x904>
 89a:	3001      	movi      	r0, 1
 89c:	9347      	ld.w      	r2, (r3, 0x1c)
 89e:	3ab3      	bseti      	r2, 19
 8a0:	b347      	st.w      	r2, (r3, 0x1c)
 8a2:	9355      	ld.w      	r2, (r3, 0x54)
 8a4:	3a89      	bclri      	r2, 9
 8a6:	b355      	st.w      	r2, (r3, 0x54)
 8a8:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_gain_idx_src>
 8ac:	3202      	movi      	r2, 2
 8ae:	1904      	addi      	r1, r14, 16
 8b0:	3008      	movi      	r0, 8
 8b2:	e0000000 	bsr      	0x0	// 0 <memory_read>
 8b6:	e920009d 	bnez      	r0, 0x9f0	// 9f0 <ah_rf_open+0x9f0>
 8ba:	9865      	ld.w      	r3, (r14, 0x14)
 8bc:	eb430055 	cmpnei      	r3, 85
 8c0:	0898      	bt      	0x9f0	// 9f0 <ah_rf_open+0x9f0>
 8c2:	d80e1008 	ld.h      	r0, (r14, 0x10)
 8c6:	3105      	movi      	r1, 5
 8c8:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
 8cc:	3100      	movi      	r1, 0
 8ce:	302a      	movi      	r0, 42
 8d0:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
 8d4:	3103      	movi      	r1, 3
 8d6:	302b      	movi      	r0, 43
 8d8:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
 8dc:	3000      	movi      	r0, 0
 8de:	e800fccf 	br      	0x27c	// 27c <ah_rf_open+0x27c>
	...
 902:	0000      	.short	0x0000
 904:	40026000 	.long	0x40026000
	...
 918:	3204      	movi      	r2, 4
 91a:	1904      	addi      	r1, r14, 16
 91c:	6c0b      	mov      	r0, r2
 91e:	e0000000 	bsr      	0x0	// 0 <memory_read>
 922:	e920ff00 	bnez      	r0, 0x722	// 722 <ah_rf_open+0x722>
 926:	d86e500e 	ld.hs      	r3, (r14, 0x1c)
 92a:	eb430055 	cmpnei      	r3, 85
 92e:	0afa      	bt      	0x722	// 722 <ah_rf_open+0x722>
 930:	1153      	lrw      	r2, 0x0	// 9fc <ah_rf_open+0x9fc>
 932:	d86e1008 	ld.h      	r3, (r14, 0x10)
 936:	aa63      	st.h      	r3, (r2, 0x6)
 938:	d82e1009 	ld.h      	r1, (r14, 0x12)
 93c:	1171      	lrw      	r3, 0x0	// a00 <ah_rf_open+0xa00>
 93e:	ab23      	st.h      	r1, (r3, 0x6)
 940:	d82e100a 	ld.h      	r1, (r14, 0x14)
 944:	aa24      	st.h      	r1, (r2, 0x8)
 946:	d82e100b 	ld.h      	r1, (r14, 0x16)
 94a:	ab24      	st.h      	r1, (r3, 0x8)
 94c:	d82e100c 	ld.h      	r1, (r14, 0x18)
 950:	aa25      	st.h      	r1, (r2, 0xa)
 952:	d84e100d 	ld.h      	r2, (r14, 0x1a)
 956:	ab45      	st.h      	r2, (r3, 0xa)
 958:	06bd      	br      	0x6d2	// 6d2 <ah_rf_open+0x6d2>
 95a:	116a      	lrw      	r3, 0x0	// a00 <ah_rf_open+0xa00>
 95c:	5f2c      	addu      	r1, r7, r3
 95e:	1168      	lrw      	r3, 0x0	// 9fc <ah_rf_open+0x9fc>
 960:	5f0c      	addu      	r0, r7, r3
 962:	6c9b      	mov      	r2, r6
 964:	2600      	addi      	r6, 1
 966:	6cd7      	mov      	r3, r5
 968:	8921      	ld.h      	r1, (r1, 0x2)
 96a:	d8005001 	ld.hs      	r0, (r0, 0x2)
 96e:	7598      	zextb      	r6, r6
 970:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_imb>
 974:	3e46      	cmpnei      	r6, 6
 976:	2701      	addi      	r7, 2
 978:	0bf1      	bt      	0x95a	// 95a <ah_rf_open+0x95a>
 97a:	2500      	addi      	r5, 1
 97c:	7554      	zextb      	r5, r5
 97e:	3d44      	cmpnei      	r5, 4
 980:	0c04      	bf      	0x988	// 988 <ah_rf_open+0x988>
 982:	3700      	movi      	r7, 0
 984:	3601      	movi      	r6, 1
 986:	07ea      	br      	0x95a	// 95a <ah_rf_open+0x95a>
 988:	101f      	lrw      	r0, 0x0	// a04 <ah_rf_open+0xa04>
 98a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 98e:	06ca      	br      	0x722	// 722 <ah_rf_open+0x722>
 990:	300a      	movi      	r0, 10
 992:	e0000000 	bsr      	0x0	// 0 <xo_set_cs_sec>
 996:	0776      	br      	0x882	// 882 <ah_rf_open+0x882>
 998:	8445      	ld.b      	r2, (r4, 0x5)
 99a:	3080      	movi      	r0, 128
 99c:	33b5      	movi      	r3, 181
 99e:	4003      	lsli      	r0, r0, 3
 9a0:	4362      	lsli      	r3, r3, 2
 9a2:	3a40      	cmpnei      	r2, 0
 9a4:	c4030c40 	inct      	r0, r3, 0
 9a8:	078f      	br      	0x8c6	// 8c6 <ah_rf_open+0x8c6>
 9aa:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 9ae:	3201      	movi      	r2, 1
 9b0:	1036      	lrw      	r1, 0x0	// a08 <ah_rf_open+0xa08>
 9b2:	6c0b      	mov      	r0, r2
 9b4:	e0000000 	bsr      	0x0	// 0 <memory_write>
 9b8:	3300      	movi      	r3, 0
 9ba:	2b00      	subi      	r3, 1
 9bc:	64c2      	cmpne      	r0, r3
 9be:	e860fc96 	bt      	0x2ea	// 2ea <ah_rf_open+0x2ea>
 9c2:	e800fc5b 	br      	0x278	// 278 <ah_rf_open+0x278>
 9c6:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 9ca:	3300      	movi      	r3, 0
 9cc:	b864      	st.w      	r3, (r14, 0x10)
 9ce:	3202      	movi      	r2, 2
 9d0:	8f60      	ld.h      	r3, (r7, 0x0)
 9d2:	dc6e100a 	st.h      	r3, (r14, 0x14)
 9d6:	1904      	addi      	r1, r14, 16
 9d8:	8e60      	ld.h      	r3, (r6, 0x0)
 9da:	6c0b      	mov      	r0, r2
 9dc:	dc6e100b 	st.h      	r3, (r14, 0x16)
 9e0:	e0000000 	bsr      	0x0	// 0 <memory_write>
 9e4:	3300      	movi      	r3, 0
 9e6:	2b00      	subi      	r3, 1
 9e8:	64c2      	cmpne      	r0, r3
 9ea:	0a45      	bt      	0x674	// 674 <ah_rf_open+0x674>
 9ec:	e800fc46 	br      	0x278	// 278 <ah_rf_open+0x278>
 9f0:	8460      	ld.b      	r3, (r4, 0x0)
 9f2:	e903ffd3 	bez      	r3, 0x998	// 998 <ah_rf_open+0x998>
 9f6:	3080      	movi      	r0, 128
 9f8:	4003      	lsli      	r0, r0, 3
 9fa:	0766      	br      	0x8c6	// 8c6 <ah_rf_open+0x8c6>
	...

Disassembly of section .text.ah_rf_close:

00000000 <ah_rf_close>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_close>
   6:	1067      	lrw      	r3, 0x40026000	// 20 <ah_rf_close+0x20>
   8:	3000      	movi      	r0, 0
   a:	9340      	ld.w      	r2, (r3, 0x0)
   c:	3a90      	bclri      	r2, 16
   e:	b340      	st.w      	r2, (r3, 0x0)
  10:	9340      	ld.w      	r2, (r3, 0x0)
  12:	3a8f      	bclri      	r2, 15
  14:	b340      	st.w      	r2, (r3, 0x0)
  16:	9340      	ld.w      	r2, (r3, 0x0)
  18:	c40257c2 	zext      	r2, r2, 30, 0
  1c:	b340      	st.w      	r2, (r3, 0x0)
  1e:	1490      	pop      	r15
  20:	40026000 	.long	0x40026000
