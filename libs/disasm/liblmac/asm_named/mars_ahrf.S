
libs\obj\liblmac\mars_ahrf.o:     file format elf32-csky-little


Disassembly of section .text.rx_dcoc_ana_calib:

00000000 <rx_dcoc_ana_calib>: // arg_bytes: 12
   0:	14d6      	push	r4-r9, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   6:	ea000781 	movi	r0, 1921	// regs: r0=0x781
   a:	6dcb      	mov	r7, r2	// regs: r7=<arg2>
   c:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   e:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0xe>, r1=<clobbered>
  12:	33e0      	movi	r3, 224	// regs: r3=0xe0
  14:	4367      	lsli	r3, r3, 7	// regs: r3=0x7000
  16:	c4602021 	and	r1, r0, r3	// regs: r1=(<ret ah_rfspi_read@0xe> & 0x7000)
  1a:	ea000781 	movi	r0, 1921	// regs: r0=0x781
  1e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x1e>, r1=<clobbered>
  22:	e0000000 	bsr	0x0	// <ah_rfdigicali_dcoc_est_en>; regs: r0=<ret ah_rfdigicali_dcoc_est_en@0x22>, r1=<clobbered>
  26:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0x8)
  28:	e0000000 	bsr	0x0	// <ah_rfdigicali_dcoc_est_kick_start>; regs: r0=<ret ah_rfdigicali_dcoc_est_kick_start@0x28>, r1=<clobbered>
  2c:	9800      	ld.w	r0, (r14, 0x0)	// regs: r0=local_8
  2e:	c4000202 	abs	r2, r0
  32:	eb220117 	cmplti	r2, 280
  36:	9821      	ld.w	r1, (r14, 0x4)	// regs: r1=local_4
  38:	c4010203 	abs	r3, r1
  3c:	0c41      	bf	0xbe	// if (r2 >= 0x118) goto loc_be;
  3e:	eb230117 	cmplti	r3, 280
  42:	0848      	bt	0xd2	// if (r3 < 0x118) goto loc_d2;
loc_44:
  44:	eb230179 	cmplti	r3, 378
  48:	0849      	bt	0xda	// if (r3 < 0x17a) goto loc_da;
loc_4a:
  4a:	eb23022f 	cmplti	r3, 560
  4e:	ea0c0028 	movi	r12, 40	// regs: r12=0x28
  52:	3450      	movi	r4, 80	// regs: r4=0x50
  54:	c48c0c40 	inct	r4, r12, 0
  58:	ea090003 	movi	r9, 3	// regs: r9=0x3
  5c:	eb23022f 	cmplti	r3, 560
  60:	ea0c0002 	movi	r12, 2	// regs: r12=0x2
  64:	c52c0c40 	inct	r9, r12, 0
loc_68:
  68:	c4828022 	divu	r2, r2, r4	// regs: r2=(<clobbered> / r4)
  6c:	c4838023 	divu	r3, r3, r4	// regs: r3=(<clobbered> / r4)
  70:	7608      	zextb	r8, r2	// regs: r8=zext8((<clobbered> / r4))
  72:	750c      	zextb	r4, r3	// regs: r4=zext8((<clobbered> / r4))
  74:	e9800005 	blz	r0, 0x7e	// if (r0 < 0x0) goto loc_7e;
  78:	e508000f 	addi	r8, r8, 16	// regs: r8=(zext8((<clobbered> / r4)) + 0x10)
  7c:	7620      	zextb	r8, r8	// regs: r8=zext8((zext8((<clobbered> / r4)) + 0x10))
loc_7e:
  7e:	e9810004 	blz	r1, 0x86	// if (r1 < 0x0) goto loc_86;
  82:	240f      	addi	r4, 16	// regs: r4=(zext8((<clobbered> / r4)) + 0x10)
  84:	7510      	zextb	r4, r4	// regs: r4=zext8((zext8((<clobbered> / r4)) + 0x10))
loc_86:
  86:	ea000781 	movi	r0, 1921	// regs: r0=0x781
  8a:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0x8a>, r1=<clobbered>
  8e:	c5202421 	or	r1, r0, r9	// regs: r1=(<ret ah_rfspi_read@0x8a> | r9)
  92:	c4484828 	lsli	r8, r8, 2	// regs: r8=(r8 << 0x2)
  96:	4487      	lsli	r4, r4, 7	// regs: r4=(r4 << 0x7)
  98:	6c60      	or	r1, r8	// regs: r1=((<ret ah_rfspi_read@0x8a> | r9) | (r8 << 0x2))
  9a:	6c50      	or	r1, r4	// regs: r1=(((<ret ah_rfspi_read@0x8a> | r9) | (r8 << 0x2)) | (r4 << 0x7))
  9c:	7445      	zexth	r1, r1	// regs: r1=zext16((((<ret ah_rfspi_read@0x8a> | r9) | (r8 << 0x2)) | (r4 << 0x7)))
  9e:	ea000781 	movi	r0, 1921	// regs: r0=0x781
  a2:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xa2>, r1=<clobbered>
  a6:	3f41      	cmpnei	r7, 1
  a8:	0809      	bt	0xba	// if (r7 != 0x1) goto loc_ba;
  aa:	3306      	movi	r3, 6	// regs: r3=0x6
  ac:	7d4c      	mult	r5, r3	// regs: r5=(<arg1> * 0x6)
  ae:	6e24      	or	r8, r9	// regs: r8=((r8 << 0x2) | r9)
  b0:	6194      	addu	r6, r5	// regs: r6=(<arg0> + (<arg1> * 0x6))
  b2:	6d20      	or	r4, r8	// regs: r4=((r4 << 0x7) | ((r8 << 0x2) | r9))
  b4:	106c      	lrw	r3, 0x0	// regs: r3=0x0
  b6:	d4c30444 	str.h	r4, (r3, r6 << 1)
loc_ba:
  ba:	1402      	addi	r14, r14, 8	// regs: r14=((sp - 0x8) + 0x8)
  bc:	1496      	pop	r4-r9, r15
loc_be:
  be:	eb220179 	cmplti	r2, 378
  c2:	0bc1      	bt	0x44	// if (r2 < 0x17a) goto loc_44;
  c4:	eb22022f 	cmplti	r2, 560
  c8:	0bc1      	bt	0x4a	// if (r2 < 0x230) goto loc_4a;
  ca:	3450      	movi	r4, 80	// regs: r4=0x50
  cc:	ea090003 	movi	r9, 3	// regs: r9=0x3
  d0:	07cc      	br	0x68	// goto loc_68;
loc_d2:
  d2:	3414      	movi	r4, 20	// regs: r4=0x14
  d4:	ea090000 	movi	r9, 0	// regs: r9=0x0
  d8:	07c8      	br	0x68	// goto loc_68;
loc_da:
  da:	341b      	movi	r4, 27	// regs: r4=0x1b
  dc:	ea090001 	movi	r9, 1	// regs: r9=0x1
  e0:	07c4      	br	0x68	// goto loc_68;
  e2:	0000      	.short	0x0000
  e4:	00000000 	.long	0x00000000	// <DSLEEP_PARAM>

Disassembly of section .text.tx_ram2rf_adc_cal:

00000000 <tx_ram2rf_adc_cal>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x2>, r1=<clobbered>
   6:	3001      	movi	r0, 1	// regs: r0=0x1
   8:	e0000000 	bsr	0x0	// <ah_set_dbgpath_device_path_mode>; regs: r0=<ret ah_set_dbgpath_device_path_mode@0x8>, r1=<clobbered>
   c:	3101      	movi	r1, 1	// regs: r1=0x1
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	e0000000 	bsr	0x0	// <ah_tdma_set_mode>; regs: r0=<ret ah_tdma_set_mode@0x10>, r1=<clobbered>
  14:	31fc      	movi	r1, 252	// regs: r1=0xfc
  16:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  18:	e0000000 	bsr	0x0	// <ah_tdma_set_buff>; regs: r0=<ret ah_tdma_set_buff@0x18>, r1=<clobbered>
  1c:	e0000000 	bsr	0x0	// <ah_tdma_start>; regs: r0=<ret ah_tdma_start@0x1c>, r1=<clobbered>
  20:	e0000000 	bsr	0x0	// <ah_trig_dbgpath_device_dma>; regs: r0=<ret ah_trig_dbgpath_device_dma@0x20>, r1=<clobbered>
  24:	1490      	pop	r15
  26:	0000      	.short	0x0000
  28:	00000000 	.long	0x00000000	// <iq_curve_for_adc_cal>

Disassembly of section .text.rx_imb_comp_inner:

00000000 <rx_imb_comp_inner>: // arg_bytes: 8
   0:	14d1      	push	r4, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	b820      	st.w	r1, (r14, 0x0)	// local_4 = <arg1>
   6:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   8:	e0000000 	bsr	0x0	// <ah_wphy_cali_rx_imb_en>; regs: r0=<ret ah_wphy_cali_rx_imb_en@0x8>, r1=<clobbered>
   c:	3001      	movi	r0, 1	// regs: r0=0x1
   e:	e0000000 	bsr	0x0	// <lmac_cfg_rx_en>; regs: r0=<ret lmac_cfg_rx_en@0xe>, r1=<clobbered>
  12:	3000      	movi	r0, 0	// regs: r0=0x0
  14:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0x14>, r1=<clobbered>
  18:	3000      	movi	r0, 0	// regs: r0=0x0
  1a:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x1a>, r1=<clobbered>
  1e:	3032      	movi	r0, 50	// regs: r0=0x32
  20:	e0000000 	bsr	0x0	// <os_sleep_ms>; regs: r0=<ret os_sleep_ms@0x20>, r1=<clobbered>
  24:	9820      	ld.w	r1, (r14, 0x0)	// regs: r1=local_4
  26:	6c13      	mov	r0, r4	// regs: r0=<arg0>
  28:	e0000000 	bsr	0x0	// <ah_wphy_cali_rx_imb_dis>; regs: r0=<ret ah_wphy_cali_rx_imb_dis@0x28>, r1=<clobbered>
  2c:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  2e:	3000      	movi	r0, 0	// regs: r0=0x0
  30:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
  32:	926c      	ld.w	r3, (r2, 0x30)	// regs: r3=*((*(0x0) + 0x30))
  34:	ec630002 	ori	r3, r3, 2	// regs: r3=(*((*(0x0) + 0x30)) | 0x2)
  38:	b26c      	st.w	r3, (r2, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) | 0x2)
  3a:	e0000000 	bsr	0x0	// <lmac_cfg_rx_en>; regs: r0=<ret lmac_cfg_rx_en@0x3a>, r1=<clobbered>
  3e:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  40:	1491      	pop	r4, r15
  42:	0000      	.short	0x0000
  44:	00000000 	.long	0x00000000	// <LMAC>

Disassembly of section .text.override_rf_adc_cal:

00000000 <override_rf_adc_cal>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	1179      	lrw	r3, 0x40026000	// regs: r3=0x40026000
   4:	3480      	movi	r4, 128	// regs: r4=0x80
   6:	9353      	ld.w	r2, (r3, 0x4c)	// regs: r2=*(0x4002604c)
   8:	3a97      	bclri	r2, 23	// regs: r2=(*(0x4002604c) & ~(0x1 << 0x17))
   a:	b353      	st.w	r2, (r3, 0x4c)	// *(0x4002604c) = (*(0x4002604c) & ~(0x1 << 0x17))
   c:	9353      	ld.w	r2, (r3, 0x4c)	// regs: r2=*(0x4002604c)
   e:	3ab7      	bseti	r2, 23	// regs: r2=(*(0x4002604c) | (0x1 << 0x17))
  10:	b353      	st.w	r2, (r3, 0x4c)	// *(0x4002604c) = (*(0x4002604c) | (0x1 << 0x17))
  12:	4481      	lsli	r4, r4, 1	// regs: r4=0x100
  14:	3500      	movi	r5, 0	// regs: r5=0x0
  16:	11d5      	lrw	r6, 0x0	// regs: r6=0x0
loc_18:
  18:	d0a60441 	ldr.h	r1, (r6, r5 << 1)	// regs: r1=*(0x0 + (r5 << 1))
  1c:	6c13      	mov	r0, r4	// regs: r0=r4
  1e:	7445      	zexth	r1, r1	// regs: r1=zext16(*(0x0 + (r5 << 1)))
  20:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  22:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x22>, r1=<clobbered>
  26:	eb450022 	cmpnei	r5, 34
  2a:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  2c:	7511      	zexth	r4, r4	// regs: r4=zext16((r4 + 0x1))
  2e:	0bf5      	bt	0x18	// if (r5 != 0x22) goto loc_18;
  30:	34c0      	movi	r4, 192	// regs: r4=0xc0
  32:	3500      	movi	r5, 0	// regs: r5=0x0
  34:	4482      	lsli	r4, r4, 2	// regs: r4=0x300
loc_36:
  36:	116e      	lrw	r3, 0x0	// regs: r3=0x0
  38:	60d4      	addu	r3, r5	// regs: r3=(0x0 + r5)
  3a:	6c13      	mov	r0, r4	// regs: r0=r4
  3c:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  3e:	d8231087 	ld.h	r1, (r3, 0x10e)	// regs: r1=*(((0x0 + r5) + 0x10e))
  42:	7511      	zexth	r4, r4	// regs: r4=zext16((r4 + 0x1))
  44:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x44>, r1=<clobbered>
  48:	eb440309 	cmpnei	r4, 777
  4c:	2501      	addi	r5, 2	// regs: r5=(r5 + 0x2)
  4e:	0bf4      	bt	0x36	// if (r4 != 0x309) goto loc_36;
  50:	1188      	lrw	r4, 0x0	// regs: r4=0x0
  52:	3088      	movi	r0, 136	// regs: r0=0x88
  54:	8c35      	ld.h	r1, (r4, 0x2a)	// regs: r1=*(0x2a)
  56:	4003      	lsli	r0, r0, 3	// regs: r0=0x440
  58:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x58>, r1=<clobbered>
  5c:	8c36      	ld.h	r1, (r4, 0x2c)	// regs: r1=*(0x2c)
  5e:	ea000441 	movi	r0, 1089	// regs: r0=0x441
  62:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x62>, r1=<clobbered>
  66:	8c37      	ld.h	r1, (r4, 0x2e)	// regs: r1=*(0x2e)
  68:	ea000442 	movi	r0, 1090	// regs: r0=0x442
  6c:	1182      	lrw	r4, 0x0	// regs: r4=0x0
  6e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x6e>, r1=<clobbered>
  72:	30f0      	movi	r0, 240	// regs: r0=0xf0
  74:	d8241070 	ld.h	r1, (r4, 0xe0)	// regs: r1=*(0xe0)
  78:	4003      	lsli	r0, r0, 3	// regs: r0=0x780
  7a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x7a>, r1=<clobbered>
  7e:	d8241071 	ld.h	r1, (r4, 0xe2)	// regs: r1=*(0xe2)
  82:	ea000781 	movi	r0, 1921	// regs: r0=0x781
  86:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x86>, r1=<clobbered>
  8a:	30a0      	movi	r0, 160	// regs: r0=0xa0
  8c:	ea01ffff 	movi	r1, 65535	// regs: r1=0xffff
  90:	4001      	lsli	r0, r0, 1	// regs: r0=0x140
  92:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x92>, r1=<clobbered>
  96:	ea01ffff 	movi	r1, 65535	// regs: r1=0xffff
  9a:	ea000141 	movi	r0, 321	// regs: r0=0x141
  9e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x9e>, r1=<clobbered>
  a2:	30a1      	movi	r0, 161	// regs: r0=0xa1
  a4:	ea01ffff 	movi	r1, 65535	// regs: r1=0xffff
  a8:	4001      	lsli	r0, r0, 1	// regs: r0=0x142
  aa:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xaa>, r1=<clobbered>
  ae:	30c4      	movi	r0, 196	// regs: r0=0xc4
  b0:	ea01ffff 	movi	r1, 65535	// regs: r1=0xffff
  b4:	4002      	lsli	r0, r0, 2	// regs: r0=0x310
  b6:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xb6>, r1=<clobbered>
  ba:	3089      	movi	r0, 137	// regs: r0=0x89
  bc:	ea01ffff 	movi	r1, 65535	// regs: r1=0xffff
  c0:	4003      	lsli	r0, r0, 3	// regs: r0=0x448
  c2:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xc2>, r1=<clobbered>
  c6:	ea01ffff 	movi	r1, 65535	// regs: r1=0xffff
  ca:	ea000782 	movi	r0, 1922	// regs: r0=0x782
  ce:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xce>, r1=<clobbered>
  d2:	3101      	movi	r1, 1	// regs: r1=0x1
  d4:	302a      	movi	r0, 42	// regs: r0=0x2a
  d6:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0xd6>, r1=<clobbered>
  da:	3100      	movi	r1, 0	// regs: r1=0x0
  dc:	302a      	movi	r0, 42	// regs: r0=0x2a
  de:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0xde>, r1=<clobbered>
  e2:	1493      	pop	r4-r6, r15
  e4:	40026000 	.long	0x40026000
  e8:	00000000 	.long	0x00000000	// <rf_reg_ovrd_val_adc_cal>
  ec:	00000000 	.long	0x00000000	// <rf_agc_reg_hw_val>
  f0:	00000000 	.long	0x00000000	// <rf_bw_reg_hw_val>
  f4:	00000000 	.long	0x00000000	// <rf_agcbw_reg_hw_val>

Disassembly of section .text.adc_calib:

00000000 <adc_calib>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <override_rf_adc_cal> // arg_bytes: 0; regs: r0=<ret override_rf_adc_cal@0x2>, r1=<clobbered>
   6:	e0000000 	bsr	0x0	// <lmac_rf_sw_ctrl>; regs: r0=<ret lmac_rf_sw_ctrl@0x6>, r1=<clobbered>
   a:	3000      	movi	r0, 0	// regs: r0=0x0
   c:	e0000000 	bsr	0x0	// <lmac_cfg_rx_en>; regs: r0=<ret lmac_cfg_rx_en@0xc>, r1=<clobbered>
  10:	3001      	movi	r0, 1	// regs: r0=0x1
  12:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0x12>, r1=<clobbered>
  16:	3000      	movi	r0, 0	// regs: r0=0x0
  18:	e0000000 	bsr	0x0	// <lmac_cfg_pa_en>; regs: r0=<ret lmac_cfg_pa_en@0x18>, r1=<clobbered>
  1c:	e0000000 	bsr	0x0	// <tx_ram2rf_adc_cal> // arg_bytes: 0; regs: r0=<ret tx_ram2rf_adc_cal@0x1c>, r1=<clobbered>
  20:	ea01a0cf 	movi	r1, 41167	// regs: r1=0xa0cf
  24:	ea000303 	movi	r0, 771	// regs: r0=0x303
  28:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x28>, r1=<clobbered>
  2c:	30c1      	movi	r0, 193	// regs: r0=0xc1
  2e:	ea018b60 	movi	r1, 35680	// regs: r1=0x8b60
  32:	4002      	lsli	r0, r0, 2	// regs: r0=0x304
  34:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x34>, r1=<clobbered>
  38:	ea01620e 	movi	r1, 25102	// regs: r1=0x620e
  3c:	ea000305 	movi	r0, 773	// regs: r0=0x305
  40:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x40>, r1=<clobbered>
  44:	ea01cc99 	movi	r1, 52377	// regs: r1=0xcc99
  48:	ea000306 	movi	r0, 774	// regs: r0=0x306
  4c:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x4c>, r1=<clobbered>
  50:	ea01baff 	movi	r1, 47871	// regs: r1=0xbaff
  54:	ea000307 	movi	r0, 775	// regs: r0=0x307
  58:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x58>, r1=<clobbered>
  5c:	30c2      	movi	r0, 194	// regs: r0=0xc2
  5e:	ea0127ff 	movi	r1, 10239	// regs: r1=0x27ff
  62:	4002      	lsli	r0, r0, 2	// regs: r0=0x308
  64:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x64>, r1=<clobbered>
  68:	e0000000 	bsr	0x0	// <rfadc_calib_mode_soft_test>; regs: r0=<ret rfadc_calib_mode_soft_test@0x68>, r1=<clobbered>
  6c:	1017      	lrw	r0, 0x0	// regs: r0=0x0
  6e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x6e>, r1=<clobbered>
  72:	ea0180cf 	movi	r1, 32975	// regs: r1=0x80cf
  76:	ea000303 	movi	r0, 771	// regs: r0=0x303
  7a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x7a>, r1=<clobbered>
  7e:	30c1      	movi	r0, 193	// regs: r0=0xc1
  80:	ea018b72 	movi	r1, 35698	// regs: r1=0x8b72
  84:	4002      	lsli	r0, r0, 2	// regs: r0=0x304
  86:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x86>, r1=<clobbered>
  8a:	ea01620f 	movi	r1, 25103	// regs: r1=0x620f
  8e:	ea000305 	movi	r0, 773	// regs: r0=0x305
  92:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x92>, r1=<clobbered>
  96:	ea01ec99 	movi	r1, 60569	// regs: r1=0xec99
  9a:	ea000306 	movi	r0, 774	// regs: r0=0x306
  9e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x9e>, r1=<clobbered>
  a2:	ea01b2ff 	movi	r1, 45823	// regs: r1=0xb2ff
  a6:	ea000307 	movi	r0, 775	// regs: r0=0x307
  aa:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xaa>, r1=<clobbered>
  ae:	30c2      	movi	r0, 194	// regs: r0=0xc2
  b0:	ea01277f 	movi	r1, 10111	// regs: r1=0x277f
  b4:	4002      	lsli	r0, r0, 2	// regs: r0=0x308
  b6:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xb6>, r1=<clobbered>
  ba:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0xba>, r1=<clobbered>
  be:	3000      	movi	r0, 0	// regs: r0=0x0
  c0:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0xc0>, r1=<clobbered>
  c4:	1490      	pop	r15
  c6:	0000      	.short	0x0000
  c8:	00000000 	.long	0x00000000	// <.rodata.adc_calib.str1.1>

Disassembly of section .text.rfdigcal_rx_dcoc_calib:

00000000 <rfdigcal_rx_dcoc_calib>: // arg_bytes: 4
   0:	14d1      	push	r4, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   6:	e0000000 	bsr	0x0	// <ah_rfdigicali_dcoc_est_en>; regs: r0=<ret ah_rfdigicali_dcoc_est_en@0x6>, r1=<clobbered>
   a:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0x8)
   c:	e0000000 	bsr	0x0	// <ah_rfdigicali_dcoc_est_kick_start>; regs: r0=<ret ah_rfdigicali_dcoc_est_kick_start@0xc>, r1=<clobbered>
  10:	9840      	ld.w	r2, (r14, 0x0)	// regs: r2=local_8
  12:	eb2201ff 	cmplti	r2, 512
  16:	0c17      	bf	0x44	// if (r2 >= 0x200) goto loc_44;
  18:	ea0101ff 	movi	r1, 511	// regs: r1=0x1ff
  1c:	6c46      	nor	r1, r1	// regs: r1=(~0x1ff)
  1e:	74cb      	sexth	r3, r2	// regs: r3=sext16(local_8)
  20:	6449      	cmplt	r2, r1
  22:	c4610c40 	inct	r3, r1, 0
loc_26:
  26:	9841      	ld.w	r2, (r14, 0x4)	// regs: r2=local_4
  28:	eb2201ff 	cmplti	r2, 512
  2c:	ac60      	st.h	r3, (r4, 0x0)	// *(<arg0>) = r3
  2e:	0c0e      	bf	0x4a	// if (r2 >= 0x200) goto loc_4a;
  30:	ea0101ff 	movi	r1, 511	// regs: r1=0x1ff
  34:	6c46      	nor	r1, r1	// regs: r1=(~0x1ff)
  36:	74cb      	sexth	r3, r2	// regs: r3=sext16(local_4)
  38:	6449      	cmplt	r2, r1
  3a:	c4610c40 	inct	r3, r1, 0
loc_3e:
  3e:	ac61      	st.h	r3, (r4, 0x2)	// *(<arg0> + 0x2) = r3
  40:	1402      	addi	r14, r14, 8	// regs: r14=((sp - 0x8) + 0x8)
  42:	1491      	pop	r4, r15
loc_44:
  44:	ea0301ff 	movi	r3, 511	// regs: r3=0x1ff
  48:	07ef      	br	0x26	// goto loc_26;
loc_4a:
  4a:	ea0301ff 	movi	r3, 511	// regs: r3=0x1ff
  4e:	07f8      	br	0x3e	// goto loc_3e;

Disassembly of section .text.tx_dcoc_rx_path_dcoc_cal.constprop.0:

00000000 <tx_dcoc_rx_path_dcoc_cal.constprop.0>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	3000      	movi	r0, 0	// regs: r0=0x0
   6:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_gain_idx_src>; regs: r0=<ret ah_rfdigicali_config_tx_gain_idx_src@0x6>, r1=<clobbered>
   a:	3105      	movi	r1, 5	// regs: r1=0x5
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0xe>, r1=<clobbered>
  12:	3180      	movi	r1, 128	// regs: r1=0x80
  14:	3205      	movi	r2, 5	// regs: r2=0x5
  16:	4124      	lsli	r1, r1, 4	// regs: r1=0x800
  18:	3000      	movi	r0, 0	// regs: r0=0x0
  1a:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_imb>; regs: r0=<ret ah_rfdigicali_config_tx_imb@0x1a>, r1=<clobbered>
  1e:	3300      	movi	r3, 0	// regs: r3=0x0
  20:	3204      	movi	r2, 4	// regs: r2=0x4
  22:	3105      	movi	r1, 5	// regs: r1=0x5
  24:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0x4)
  26:	dc6e1000 	st.h	r3, (r14, 0x0)	// local_4 = 0x0
  2a:	dc6e1001 	st.h	r3, (r14, 0x2)	// local_2 = 0x0
  2e:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_dcoc>; regs: r0=<ret ah_rfdigicali_config_rx_dcoc@0x2e>, r1=<clobbered>
  32:	3005      	movi	r0, 5	// regs: r0=0x5
  34:	e0000000 	bsr	0x0	// <ah_rfdigicali_tx_pwr>; regs: r0=<ret ah_rfdigicali_tx_pwr@0x34>, r1=<clobbered>
  38:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x38>, r1=<clobbered>
  3c:	3001      	movi	r0, 1	// regs: r0=0x1
  3e:	e0000000 	bsr	0x0	// <ah_set_dbgpath_device_path_mode>; regs: r0=<ret ah_set_dbgpath_device_path_mode@0x3e>, r1=<clobbered>
  42:	3101      	movi	r1, 1	// regs: r1=0x1
  44:	3000      	movi	r0, 0	// regs: r0=0x0
  46:	e0000000 	bsr	0x0	// <ah_tdma_set_mode>; regs: r0=<ret ah_tdma_set_mode@0x46>, r1=<clobbered>
  4a:	3180      	movi	r1, 128	// regs: r1=0x80
  4c:	100b      	lrw	r0, 0x0	// regs: r0=0x0
  4e:	e0000000 	bsr	0x0	// <ah_tdma_set_buff>; regs: r0=<ret ah_tdma_set_buff@0x4e>, r1=<clobbered>
  52:	e0000000 	bsr	0x0	// <ah_tdma_start>; regs: r0=<ret ah_tdma_start@0x52>, r1=<clobbered>
  56:	e0000000 	bsr	0x0	// <ah_trig_dbgpath_device_dma>; regs: r0=<ret ah_trig_dbgpath_device_dma@0x56>, r1=<clobbered>
  5a:	3200      	movi	r2, 0	// regs: r2=0x0
  5c:	3104      	movi	r1, 4	// regs: r1=0x4
  5e:	3005      	movi	r0, 5	// regs: r0=0x5
  60:	e0000000 	bsr	0x0	// <rx_dcoc_ana_calib> // arg_bytes: 12; regs: r0=<ret rx_dcoc_ana_calib@0x60>, r1=<clobbered>
  64:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0x4)
  66:	e0000000 	bsr	0x0	// <rfdigcal_rx_dcoc_calib> // arg_bytes: 4; regs: r0=<ret rfdigcal_rx_dcoc_calib@0x66>, r1=<clobbered>
  6a:	3204      	movi	r2, 4	// regs: r2=0x4
  6c:	3105      	movi	r1, 5	// regs: r1=0x5
  6e:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0x4)
  70:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_dcoc>; regs: r0=<ret ah_rfdigicali_config_rx_dcoc@0x70>, r1=<clobbered>
  74:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  76:	1490      	pop	r15
  78:	00000000 	.long	0x00000000	// <iq_curve_for_dac_p1MHz>

Disassembly of section .text.dft_pwr_fixed_out_one:

00000000 <dft_pwr_fixed_out_one>: // arg_bytes: 12
   0:	14d8      	push	r4-r11, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	4246      	lsli	r2, r2, 6	// regs: r2=(<arg2> << 0x6)
   6:	1173      	lrw	r3, 0x0	// regs: r3=0x0
   8:	c462002c 	addu	r12, r2, r3	// regs: r12=((<arg2> << 0x6) )
   c:	3600      	movi	r6, 0	// regs: r6=0x0
   e:	1172      	lrw	r3, 0x0	// regs: r3=0x0
  10:	3700      	movi	r7, 0	// regs: r7=0x0
  12:	6d43      	mov	r5, r0	// regs: r5=<arg0>
  14:	c462002a 	addu	r10, r2, r3	// regs: r10=((<arg2> << 0x6) )
  18:	6e1b      	mov	r8, r6	// regs: r8=0x0
  1a:	6e5f      	mov	r9, r7	// regs: r9=0x0
  1c:	ea0b0000 	movi	r11, 0	// regs: r11=0x0
loc_20:
  20:	d8655020 	ld.hs	r3, (r5, 0x40)	// regs: r3=*(r5 + 0x40)
  24:	d8855000 	ld.hs	r4, (r5, 0x0)	// regs: r4=*(r5)
  28:	610c      	addu	r4, r3	// regs: r4=(*(r5) + *(r5 + 0x40))
  2a:	d8655040 	ld.hs	r3, (r5, 0x80)	// regs: r3=*(r5 + 0x80)
  2e:	610c      	addu	r4, r3	// regs: r4=((*(r5) + *(r5 + 0x40)) + *(r5 + 0x80))
  30:	d8655060 	ld.hs	r3, (r5, 0xc0)	// regs: r3=*(r5 + 0xc0)
  34:	610c      	addu	r4, r3	// regs: r4=(((*(r5) + *(r5 + 0x40)) + *(r5 + 0x80)) + *(r5 + 0xc0))
  36:	d8655080 	ld.hs	r3, (r5, 0x100)	// regs: r3=*(r5 + 0x100)
  3a:	610c      	addu	r4, r3	// regs: r4=((((*(r5) + *(r5 + 0x40)) + *(r5 + 0x80)) + *(r5 + 0xc0)) + *(r5 + 0x100))
  3c:	d86550a0 	ld.hs	r3, (r5, 0x140)	// regs: r3=*(r5 + 0x140)
  40:	610c      	addu	r4, r3	// regs: r4=(((((*(r5) + *(r5 + 0x40)) + *(r5 + 0x80)) + *(r5 + 0xc0)) + *(r5 + 0x100)) + *(r5 + 0x140))
  42:	d86550c0 	ld.hs	r3, (r5, 0x180)	// regs: r3=*(r5 + 0x180)
  46:	610c      	addu	r4, r3	// regs: r4=((((((*(r5) + *(r5 + 0x40)) + *(r5 + 0x80)) + *(r5 + 0xc0)) + *(r5 + 0x100)) + *(r5 + 0x140)) + *(r5 + 0x180))
  48:	d86550e0 	ld.hs	r3, (r5, 0x1c0)	// regs: r3=*(r5 + 0x1c0)
  4c:	610c      	addu	r4, r3	// regs: r4=(((((((*(r5) + *(r5 + 0x40)) + *(r5 + 0x80)) + *(r5 + 0xc0)) + *(r5 + 0x100)) + *(r5 + 0x140)) + *(r5 + 0x180)) + *(r5 + 0x1c0))
  4e:	d16c0880 	ldr.w	r0, (r12, r11 << 2)	// regs: r0=*(r12 + (r11 << 2))
  52:	c7e4488d 	asri	r13, r4, 31	// regs: r13=((((((((*(r5) + *(r5 + 0x40)) + *(r5 + 0x80)) + *(r5 + 0xc0)) + *(r5 + 0x100)) + *(r5 + 0x140)) + *(r5 + 0x180)) + *(r5 + 0x1c0)) >> 0x1f)
  56:	6cf7      	mov	r3, r13	// regs: r3=((((((((*(r5) + *(r5 + 0x40)) + *(r5 + 0x80)) + *(r5 + 0xc0)) + *(r5 + 0x100)) + *(r5 + 0x140)) + *(r5 + 0x180)) + *(r5 + 0x1c0)) >> 0x1f)
  58:	6c93      	mov	r2, r4	// regs: r2=(((((((*(r5) + *(r5 + 0x40)) + *(r5 + 0x80)) + *(r5 + 0xc0)) + *(r5 + 0x100)) + *(r5 + 0x140)) + *(r5 + 0x180)) + *(r5 + 0x1c0))
  5a:	503f      	asri	r1, r0, 31	// regs: r1=(*(r12 + (r11 << 2)) >> 0x1f)
  5c:	dd8e2000 	st.w	r12, (r14, 0x0)	// local_8 = r12
  60:	ddae2001 	st.w	r13, (r14, 0x4)	// local_4 = ((((((((*(r5) + *(r5 + 0x40)) + *(r5 + 0x80)) + *(r5 + 0xc0)) + *(r5 + 0x100)) + *(r5 + 0x140)) + *(r5 + 0x180)) + *(r5 + 0x1c0)) >> 0x1f)
  64:	e0000000 	bsr	0x0	// <__muldi3>; regs: r0=<ret __muldi3@0x64>, r1=<clobbered>
  68:	6621      	cmplt	r8, r8
  6a:	6201      	addc	r8, r0
  6c:	6245      	addc	r9, r1
  6e:	d9ae2001 	ld.w	r13, (r14, 0x4)	// regs: r13=local_4
  72:	d16a0880 	ldr.w	r0, (r10, r11 << 2)	// regs: r0=*(((<arg2> << 0x6) ) + (r11 << 2))
  76:	6c93      	mov	r2, r4	// regs: r2=(((((((*(r5) + *(r5 + 0x40)) + *(r5 + 0x80)) + *(r5 + 0xc0)) + *(r5 + 0x100)) + *(r5 + 0x140)) + *(r5 + 0x180)) + *(r5 + 0x1c0))
  78:	6cf7      	mov	r3, r13	// regs: r3=local_4
  7a:	503f      	asri	r1, r0, 31	// regs: r1=(*(((<arg2> << 0x6) ) + (r11 << 2)) >> 0x1f)
  7c:	e0000000 	bsr	0x0	// <__muldi3>; regs: r0=<ret __muldi3@0x7c>, r1=<clobbered>
  80:	e56b0000 	addi	r11, r11, 1	// regs: r11=(r11 + 0x1)
  84:	6599      	cmplt	r6, r6
  86:	6181      	addc	r6, r0
  88:	61c5      	addc	r7, r1
  8a:	eb4b0010 	cmpnei	r11, 16
  8e:	2503      	addi	r5, 4	// regs: r5=(r5 + 0x4)
  90:	d98e2000 	ld.w	r12, (r14, 0x0)	// regs: r12=local_8
  94:	0bc6      	bt	0x20	// if (r11 != 0x10) goto loc_20;
  96:	c5c94823 	lsli	r3, r9, 14	// regs: r3=0x0
  9a:	c6484842 	lsri	r2, r8, 18	// regs: r2=0x0
  9e:	6c8c      	or	r2, r3	// regs: r2=(0x0 | 0x0)
  a0:	472e      	lsli	r1, r7, 14	// regs: r1=0x0
  a2:	c6494883 	asri	r3, r9, 18	// regs: r3=0x0
  a6:	4e92      	lsri	r4, r6, 18	// regs: r4=0x0
  a8:	6d04      	or	r4, r1	// regs: r4=(0x0 | 0x0)
  aa:	6c0b      	mov	r0, r2	// regs: r0=(0x0 | 0x0)
  ac:	6c4f      	mov	r1, r3	// regs: r1=0x0
  ae:	e0000000 	bsr	0x0	// <__muldi3>; regs: r0=<ret __muldi3@0xae>, r1=<clobbered>
  b2:	57b2      	asri	r5, r7, 18	// regs: r5=0x0
  b4:	6c93      	mov	r2, r4	// regs: r2=(0x0 | 0x0)
  b6:	6d83      	mov	r6, r0	// regs: r6=<ret __muldi3@0xae>
  b8:	6dc7      	mov	r7, r1	// regs: r7=<clobbered>
  ba:	6cd7      	mov	r3, r5	// regs: r3=0x0
  bc:	6c13      	mov	r0, r4	// regs: r0=(0x0 | 0x0)
  be:	6c57      	mov	r1, r5	// regs: r1=0x0
  c0:	e0000000 	bsr	0x0	// <__muldi3>; regs: r0=<ret __muldi3@0xc0>, r1=<clobbered>
  c4:	6401      	cmplt	r0, r0
  c6:	6019      	addc	r0, r6
  c8:	605d      	addc	r1, r7
  ca:	1402      	addi	r14, r14, 8	// regs: r14=((sp - 0x8) + 0x8)
  cc:	1498      	pop	r4-r11, r15
  ce:	0000      	.short	0x0000
  d0:	00000000 	.long	0x00000000	// <.rodata.fft_cos>
  d4:	00000000 	.long	0x00000000	// <.rodata.fft_sin>

Disassembly of section .text.snr_calc_128_dft_fixed_point:

00000000 <snr_calc_128_dft_fixed_point>: // arg_bytes: 4
   0:	14d4      	push	r4-r7, r15
   2:	3400      	movi	r4, 0	// regs: r4=0x0
   4:	6c83      	mov	r2, r0	// regs: r2=<arg0>
   6:	e5a001ff 	addi	r13, r0, 512	// regs: r13=(<arg0> + 0x200)
   a:	6d93      	mov	r6, r4	// regs: r6=0x0
   c:	6d53      	mov	r5, r4	// regs: r5=0x0
loc_e:
   e:	d8625000 	ld.hs	r3, (r2, 0x0)	// regs: r3=*(r2)
  12:	d8225002 	ld.hs	r1, (r2, 0x4)	// regs: r1=*(r2 + 0x4)
  16:	c463842c 	mult	r12, r3, r3	// regs: r12=(*(r2) * *(r2))
  1a:	c4218427 	mult	r7, r1, r1	// regs: r7=(*(r2 + 0x4) * *(r2 + 0x4))
  1e:	2207      	addi	r2, 8	// regs: r2=(r2 + 0x8)
  20:	631c      	addu	r12, r7	// regs: r12=((*(r2) * *(r2)) + (*(r2 + 0x4) * *(r2 + 0x4)))
  22:	64b6      	cmpne	r13, r2
  24:	6170      	addu	r5, r12	// regs: r5=(r5 + ((*(r2) * *(r2)) + (*(r2 + 0x4) * *(r2 + 0x4))))
  26:	c423002c 	addu	r12, r3, r1	// regs: r12=(*(r2) + *(r2 + 0x4))
  2a:	60c6      	subu	r3, r1	// regs: r3=(*(r2) - *(r2 + 0x4))
  2c:	6130      	addu	r4, r12	// regs: r4=(r4 + (*(r2) + *(r2 + 0x4)))
  2e:	618c      	addu	r6, r3	// regs: r6=(r6 + (*(r2) - *(r2 + 0x4)))
  30:	0bef      	bt	0xe	// if (T) goto loc_e;
  32:	3200      	movi	r2, 0	// regs: r2=0x0
  34:	7d98      	mult	r6, r6	// regs: r6=((r6 + (*(r2) - *(r2 + 0x4))) * (r6 + (*(r2) - *(r2 + 0x4))))
  36:	3108      	movi	r1, 8	// regs: r1=0x8
  38:	7d10      	mult	r4, r4	// regs: r4=((r4 + (*(r2) + *(r2 + 0x4))) * (r4 + (*(r2) + *(r2 + 0x4))))
  3a:	e0000000 	bsr	0x0	// <dft_pwr_fixed_out_one> // arg_bytes: 12; regs: r0=<ret dft_pwr_fixed_out_one@0x3a>, r1=<clobbered>
  3e:	6118      	addu	r4, r6	// regs: r4=(((r4 + (*(r2) + *(r2 + 0x4))) * (r4 + (*(r2) + *(r2 + 0x4)))) + ((r6 + (*(r2) - *(r2 + 0x4))) * (r6 + (*(r2) - *(r2 + 0x4)))))
  40:	4128      	lsli	r1, r1, 8	// regs: r1=(<clobbered> << 0x8)
  42:	4818      	lsri	r0, r0, 24	// regs: r0=(<ret dft_pwr_fixed_out_one@0x3a> >> 0x18)
  44:	5487      	asri	r4, r4, 7	// regs: r4=((((r4 + (*(r2) + *(r2 + 0x4))) * (r4 + (*(r2) + *(r2 + 0x4)))) + ((r6 + (*(r2) - *(r2 + 0x4))) * (r6 + (*(r2) - *(r2 + 0x4))))) >> 0x7)
  46:	6c04      	or	r0, r1	// regs: r0=((<ret dft_pwr_fixed_out_one@0x3a> >> 0x18) | (<clobbered> << 0x8))
  48:	5d91      	subu	r4, r5, r4	// regs: r4=((r5 + ((*(r2) * *(r2)) + (*(r2 + 0x4) * *(r2 + 0x4)))) - ((((r4 + (*(r2) + *(r2 + 0x4))) * (r4 + (*(r2) + *(r2 + 0x4)))) + ((r6 + (*(r2) - *(r2 + 0x4))) * (r6 + (*(r2) - *(r2 + 0x4))))) >> 0x7))
  4a:	6102      	subu	r4, r0	// regs: r4=(((r5 + ((*(r2) * *(r2)) + (*(r2 + 0x4) * *(r2 + 0x4)))) - ((((r4 + (*(r2) + *(r2 + 0x4))) * (r4 + (*(r2) + *(r2 + 0x4)))) + ((r6 + (*(r2) - *(r2 + 0x4))) * (r6 + (*(r2) - *(r2 + 0x4))))) >> 0x7)) - ((<ret dft_pwr_fixed_out_one@0x3a> >> 0x18) | (<clobbered> << 0x8)))
  4c:	c4808020 	divu	r0, r0, r4	// regs: r0=(((<ret dft_pwr_fixed_out_one@0x3a> >> 0x18) | (<clobbered> << 0x8)) / (((r5 + ((*(r2) * *(r2)) + (*(r2 + 0x4) * *(r2 + 0x4)))) - ((((r4 + (*(r2) + *(r2 + 0x4))) * (r4 + (*(r2) + *(r2 + 0x4)))) + ((r6 + (*(r2) - *(r2 + 0x4))) * (r6 + (*(r2) - *(r2 + 0x4))))) >> 0x7)) - ((<ret dft_pwr_fixed_out_one@0x3a> >> 0x18) | (<clobbered> << 0x8))))
  50:	1494      	pop	r4-r7, r15

Disassembly of section .text.check_adc_perf:

00000000 <check_adc_perf>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	3080      	movi	r0, 128	// regs: r0=0x80
   4:	4003      	lsli	r0, r0, 3	// regs: r0=0x400
   6:	e0000000 	bsr	0x0	// <_os_zalloc>; regs: r0=<ret _os_zalloc@0x6>, r1=<clobbered>
   a:	6d03      	mov	r4, r0	// regs: r4=<ret _os_zalloc@0x6>
   c:	e9200004 	bnez	r0, 0x14	// if (r0 != 0x0) goto loc_14;
loc_10:
  10:	3000      	movi	r0, 0	// regs: r0=0x0
loc_12:
  12:	1493      	pop	r4-r6, r15
loc_14:
  14:	e0000000 	bsr	0x0	// <override_rf_adc_cal> // arg_bytes: 0; regs: r0=<ret override_rf_adc_cal@0x14>, r1=<clobbered>
  18:	e0000000 	bsr	0x0	// <lmac_rf_sw_ctrl>; regs: r0=<ret lmac_rf_sw_ctrl@0x18>, r1=<clobbered>
  1c:	3000      	movi	r0, 0	// regs: r0=0x0
  1e:	e0000000 	bsr	0x0	// <lmac_cfg_rx_en>; regs: r0=<ret lmac_cfg_rx_en@0x1e>, r1=<clobbered>
  22:	3001      	movi	r0, 1	// regs: r0=0x1
  24:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0x24>, r1=<clobbered>
  28:	3000      	movi	r0, 0	// regs: r0=0x0
  2a:	e0000000 	bsr	0x0	// <lmac_cfg_pa_en>; regs: r0=<ret lmac_cfg_pa_en@0x2a>, r1=<clobbered>
  2e:	3100      	movi	r1, 0	// regs: r1=0x0
  30:	3001      	movi	r0, 1	// regs: r0=0x1
  32:	e0000000 	bsr	0x0	// <ah_tdma2_set_mode>; regs: r0=<ret ah_tdma2_set_mode@0x32>, r1=<clobbered>
  36:	3180      	movi	r1, 128	// regs: r1=0x80
  38:	4123      	lsli	r1, r1, 3	// regs: r1=0x400
  3a:	6c13      	mov	r0, r4	// regs: r0=<ret _os_zalloc@0x6>
  3c:	e0000000 	bsr	0x0	// <ah_tdma2_set_buff>; regs: r0=<ret ah_tdma2_set_buff@0x3c>, r1=<clobbered>
  40:	e0000000 	bsr	0x0	// <ah_tdma2_enable_irq>; regs: r0=<ret ah_tdma2_enable_irq@0x40>, r1=<clobbered>
  44:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x44>, r1=<clobbered>
  48:	3001      	movi	r0, 1	// regs: r0=0x1
  4a:	e0000000 	bsr	0x0	// <ah_set_dbgpath_device_path_mode>; regs: r0=<ret ah_set_dbgpath_device_path_mode@0x4a>, r1=<clobbered>
  4e:	3101      	movi	r1, 1	// regs: r1=0x1
  50:	3000      	movi	r0, 0	// regs: r0=0x0
  52:	e0000000 	bsr	0x0	// <ah_tdma_set_mode>; regs: r0=<ret ah_tdma_set_mode@0x52>, r1=<clobbered>
  56:	3140      	movi	r1, 64	// regs: r1=0x40
  58:	110d      	lrw	r0, 0x0	// regs: r0=0x0
  5a:	e0000000 	bsr	0x0	// <ah_tdma_set_buff>; regs: r0=<ret ah_tdma_set_buff@0x5a>, r1=<clobbered>
  5e:	e0000000 	bsr	0x0	// <ah_tdma_start>; regs: r0=<ret ah_tdma_start@0x5e>, r1=<clobbered>
  62:	e0000000 	bsr	0x0	// <ah_trig_dbgpath_device_dma>; regs: r0=<ret ah_trig_dbgpath_device_dma@0x62>, r1=<clobbered>
  66:	30fa      	movi	r0, 250	// regs: r0=0xfa
  68:	4002      	lsli	r0, r0, 2	// regs: r0=0x3e8
  6a:	e0000000 	bsr	0x0	// <os_sleep_us>; regs: r0=<ret os_sleep_us@0x6a>, r1=<clobbered>
  6e:	ea0180cf 	movi	r1, 32975	// regs: r1=0x80cf
  72:	ea000303 	movi	r0, 771	// regs: r0=0x303
  76:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x76>, r1=<clobbered>
  7a:	30c1      	movi	r0, 193	// regs: r0=0xc1
  7c:	ea018b72 	movi	r1, 35698	// regs: r1=0x8b72
  80:	4002      	lsli	r0, r0, 2	// regs: r0=0x304
  82:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x82>, r1=<clobbered>
  86:	ea01620f 	movi	r1, 25103	// regs: r1=0x620f
  8a:	ea000305 	movi	r0, 773	// regs: r0=0x305
  8e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x8e>, r1=<clobbered>
  92:	ea01ec99 	movi	r1, 60569	// regs: r1=0xec99
  96:	ea000306 	movi	r0, 774	// regs: r0=0x306
  9a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x9a>, r1=<clobbered>
  9e:	ea01b2ff 	movi	r1, 45823	// regs: r1=0xb2ff
  a2:	ea000307 	movi	r0, 775	// regs: r0=0x307
  a6:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xa6>, r1=<clobbered>
  aa:	30c2      	movi	r0, 194	// regs: r0=0xc2
  ac:	ea01277f 	movi	r1, 10111	// regs: r1=0x277f
  b0:	4002      	lsli	r0, r0, 2	// regs: r0=0x308
  b2:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xb2>, r1=<clobbered>
  b6:	e0000000 	bsr	0x0	// <ah_tdma2_start>; regs: r0=<ret ah_tdma2_start@0xb6>, r1=<clobbered>
loc_ba:
  ba:	e0000000 	bsr	0x0	// <ah_tdma2_get_pd>; regs: r0=<ret ah_tdma2_get_pd@0xba>, r1=<clobbered>
  be:	e900fffe 	bez	r0, 0xba	// if (r0 == 0x0) goto loc_ba;
  c2:	e0000000 	bsr	0x0	// <ah_tdma2_clear_pd>; regs: r0=<ret ah_tdma2_clear_pd@0xc2>, r1=<clobbered>
  c6:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0xc6>, r1=<clobbered>
  ca:	3000      	movi	r0, 0	// regs: r0=0x0
  cc:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0xcc>, r1=<clobbered>
  d0:	e40400ff 	addi	r0, r4, 256	// regs: r0=(<ret _os_zalloc@0x6> + 0x100)
  d4:	e0000000 	bsr	0x0	// <snr_calc_128_dft_fixed_point> // arg_bytes: 4; regs: r0=<ret snr_calc_128_dft_fixed_point@0xd4>, r1=<clobbered>
  d8:	6d43      	mov	r5, r0	// regs: r5=<ret snr_calc_128_dft_fixed_point@0xd4>
  da:	e4040101 	addi	r0, r4, 258	// regs: r0=(<ret _os_zalloc@0x6> + 0x102)
  de:	e0000000 	bsr	0x0	// <snr_calc_128_dft_fixed_point> // arg_bytes: 4; regs: r0=<ret snr_calc_128_dft_fixed_point@0xde>, r1=<clobbered>
  e2:	6d83      	mov	r6, r0	// regs: r6=<ret snr_calc_128_dft_fixed_point@0xde>
  e4:	6c13      	mov	r0, r4	// regs: r0=<ret _os_zalloc@0x6>
  e6:	e0000000 	bsr	0x0	// <_os_free>; regs: r0=<ret _os_free@0xe6>, r1=<clobbered>
  ea:	eb059c40 	cmphsi	r5, 40001
  ee:	0c04      	bf	0xf6	// if (r5 < 0x9c41) goto loc_f6;
  f0:	eb069c40 	cmphsi	r6, 40001
  f4:	0b8e      	bt	0x10	// if (r6 >= 0x9c41) goto loc_10;
loc_f6:
  f6:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  f8:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xf8>, r1=<clobbered>
  fc:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  fe:	6c9b      	mov	r2, r6	// regs: r2=<ret snr_calc_128_dft_fixed_point@0xde>
 100:	6c57      	mov	r1, r5	// regs: r1=<ret snr_calc_128_dft_fixed_point@0xd4>
 102:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x102>, r1=<clobbered>
 106:	3000      	movi	r0, 0	// regs: r0=0x0
 108:	2800      	subi	r0, 1	// regs: r0=0xffffffff
 10a:	0784      	br	0x12	// goto loc_12;
 10c:	00000000 	.long	0x00000000	// <iq_curve_for_dac_p2MHz>
 110:	00000000 	.long	0x00000000	// <.rodata.check_adc_perf.str1.1>
 114:	00000000 	.long	0x00000000	// <.rodata.check_adc_perf.str1.1+0x19>

Disassembly of section .text.rf_para_efuse_read:

00000000 <rf_para_efuse_read>: // arg_bytes: 4
   0:	14d8      	push	r4-r11, r15
   2:	1436      	subi	r14, r14, 88	// regs: r14=(sp - 0x58)
   4:	1804      	addi	r0, r14, 16	// regs: r0=((sp - 0x58) + 0x10)
   6:	3248      	movi	r2, 72	// regs: r2=0x48
   8:	3100      	movi	r1, 0	// regs: r1=0x0
   a:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0xa>, r1=<clobbered>
   e:	3400      	movi	r4, 0	// regs: r4=0x0
  10:	1904      	addi	r1, r14, 16	// regs: r1=((sp - 0x58) + 0x10)
  12:	3248      	movi	r2, 72	// regs: r2=0x48
  14:	3042      	movi	r0, 66	// regs: r0=0x42
  16:	b880      	st.w	r4, (r14, 0x0)	// local_58 = 0x0
  18:	dc8e1002 	st.h	r4, (r14, 0x4)	// local_54 = 0x0
  1c:	6dbb      	mov	r6, r14	// regs: r6=(sp - 0x58)
  1e:	e0000000 	bsr	0x0	// <sysctrl_efuse_config_and_read>; regs: r0=<ret sysctrl_efuse_config_and_read@0x1e>, r1=<clobbered>
  22:	1904      	addi	r1, r14, 16	// regs: r1=((sp - 0x58) + 0x10)
  24:	6cd3      	mov	r3, r4	// regs: r3=0x0
  26:	ea8c010a 	lrw	r12, 0x0	// regs: r12=0x0
loc_2a:
  2a:	8142      	ld.b	r2, (r1, 0x2)	// regs: r2=*(r1 + 0x2)
  2c:	8101      	ld.b	r0, (r1, 0x1)	// regs: r0=*(r1 + 0x1)
  2e:	4008      	lsli	r0, r0, 8	// regs: r0=(*(r1 + 0x1) << 0x8)
  30:	4250      	lsli	r2, r2, 16	// regs: r2=(*(r1 + 0x2) << 0x10)
  32:	6c80      	or	r2, r0	// regs: r2=((*(r1 + 0x2) << 0x10) | (*(r1 + 0x1) << 0x8))
  34:	8100      	ld.b	r0, (r1, 0x0)	// regs: r0=*(r1)
  36:	6c80      	or	r2, r0	// regs: r2=(((*(r1 + 0x2) << 0x10) | (*(r1 + 0x1) << 0x8)) | *(r1))
  38:	d46c0882 	str.w	r2, (r12, r3 << 2)
  3c:	2300      	addi	r3, 1	// regs: r3=(r3 + 0x1)
  3e:	3b58      	cmpnei	r3, 24
  40:	2102      	addi	r1, 3	// regs: r1=(r1 + 0x3)
  42:	0bf4      	bt	0x2a	// if (r3 != 0x18) goto loc_2a;
  44:	3203      	movi	r2, 3	// regs: r2=0x3
  46:	1904      	addi	r1, r14, 16	// regs: r1=((sp - 0x58) + 0x10)
  48:	30a9      	movi	r0, 169	// regs: r0=0xa9
  4a:	e0000000 	bsr	0x0	// <sysctrl_efuse_config_and_read>; regs: r0=<ret sysctrl_efuse_config_and_read@0x4a>, r1=<clobbered>
  4e:	d82e0011 	ld.b	r1, (r14, 0x11)	// regs: r1=local_47
  52:	4148      	lsli	r2, r1, 8	// regs: r2=(local_47 << 0x8)
  54:	d86e0010 	ld.b	r3, (r14, 0x10)	// regs: r3=local_48
  58:	e4422300 	andi	r2, r2, 768	// regs: r2=((local_47 << 0x8) & 0x300)
  5c:	6c8c      	or	r2, r3	// regs: r2=(((local_47 << 0x8) & 0x300) | local_48)
  5e:	d86e0012 	ld.b	r3, (r14, 0x12)	// regs: r3=local_46
  62:	4364      	lsli	r3, r3, 4	// regs: r3=(local_46 << 0x4)
  64:	0004      	lrw	r0, 0x0	// regs: r0=0x0
  66:	4924      	lsri	r1, r1, 4	// regs: r1=(local_47 >> 0x4)
  68:	e46323f0 	andi	r3, r3, 1008	// regs: r3=((local_46 << 0x4) & 0x3f0)
  6c:	6cc4      	or	r3, r1	// regs: r3=(((local_46 << 0x4) & 0x3f0) | (local_47 >> 0x4))
  6e:	a861      	st.h	r3, (r0, 0x2)	// *(0x2) = (((local_46 << 0x4) & 0x3f0) | (local_47 >> 0x4))
  70:	a840      	st.h	r2, (r0, 0x0)	// *(0x0) = (((local_47 << 0x8) & 0x300) | local_48)
  72:	00a6      	lrw	r5, 0x0	// regs: r5=0x0
  74:	0006      	lrw	r0, 0x0	// regs: r0=0x0
  76:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x76>, r1=<clobbered>
  7a:	3203      	movi	r2, 3	// regs: r2=0x3
  7c:	1904      	addi	r1, r14, 16	// regs: r1=((sp - 0x58) + 0x10)
  7e:	30a0      	movi	r0, 160	// regs: r0=0xa0
  80:	e0000000 	bsr	0x0	// <sysctrl_efuse_config_and_read>; regs: r0=<ret sysctrl_efuse_config_and_read@0x80>, r1=<clobbered>
  84:	d82e0011 	ld.b	r1, (r14, 0x11)	// regs: r1=local_47
  88:	4148      	lsli	r2, r1, 8	// regs: r2=(local_47 << 0x8)
  8a:	d86e0010 	ld.b	r3, (r14, 0x10)	// regs: r3=local_48
  8e:	e4422f00 	andi	r2, r2, 3840	// regs: r2=((local_47 << 0x8) & 0xf00)
  92:	6c8c      	or	r2, r3	// regs: r2=(((local_47 << 0x8) & 0xf00) | local_48)
  94:	006d      	lrw	r3, 0x0	// regs: r3=0x0
  96:	4924      	lsri	r1, r1, 4	// regs: r1=(local_47 >> 0x4)
  98:	ab40      	st.h	r2, (r3, 0x0)	// *(0x0) = (((local_47 << 0x8) & 0xf00) | local_48)
  9a:	d86e0012 	ld.b	r3, (r14, 0x12)	// regs: r3=local_46
  9e:	4364      	lsli	r3, r3, 4	// regs: r3=(local_46 << 0x4)
  a0:	004f      	lrw	r2, 0x0	// regs: r2=0x0
  a2:	e46323f0 	andi	r3, r3, 1008	// regs: r3=((local_46 << 0x4) & 0x3f0)
  a6:	6cc4      	or	r3, r1	// regs: r3=(((local_46 << 0x4) & 0x3f0) | (local_47 >> 0x4))
  a8:	aa60      	st.h	r3, (r2, 0x0)	// *(0x0) = (((local_46 << 0x4) & 0x3f0) | (local_47 >> 0x4))
  aa:	1904      	addi	r1, r14, 16	// regs: r1=((sp - 0x58) + 0x10)
  ac:	3203      	movi	r2, 3	// regs: r2=0x3
  ae:	30a6      	movi	r0, 166	// regs: r0=0xa6
  b0:	e0000000 	bsr	0x0	// <sysctrl_efuse_config_and_read>; regs: r0=<ret sysctrl_efuse_config_and_read@0xb0>, r1=<clobbered>
  b4:	d82e0011 	ld.b	r1, (r14, 0x11)	// regs: r1=local_47
  b8:	4148      	lsli	r2, r1, 8	// regs: r2=(local_47 << 0x8)
  ba:	d86e0010 	ld.b	r3, (r14, 0x10)	// regs: r3=local_48
  be:	e4422f00 	andi	r2, r2, 3840	// regs: r2=((local_47 << 0x8) & 0xf00)
  c2:	6c8c      	or	r2, r3	// regs: r2=(((local_47 << 0x8) & 0xf00) | local_48)
  c4:	0077      	lrw	r3, 0x0	// regs: r3=0x0
  c6:	4924      	lsri	r1, r1, 4	// regs: r1=(local_47 >> 0x4)
  c8:	ab40      	st.h	r2, (r3, 0x0)	// *(0x0) = (((local_47 << 0x8) & 0xf00) | local_48)
  ca:	d86e0012 	ld.b	r3, (r14, 0x12)	// regs: r3=local_46
  ce:	4364      	lsli	r3, r3, 4	// regs: r3=(local_46 << 0x4)
  d0:	e46321f0 	andi	r3, r3, 496	// regs: r3=((local_46 << 0x4) & 0x1f0)
  d4:	005a      	lrw	r2, 0x0	// regs: r2=0x0
  d6:	6cc4      	or	r3, r1	// regs: r3=(((local_46 << 0x4) & 0x1f0) | (local_47 >> 0x4))
  d8:	aa60      	st.h	r3, (r2, 0x0)	// *(0x0) = (((local_46 << 0x4) & 0x1f0) | (local_47 >> 0x4))
  da:	8565      	ld.b	r3, (r5, 0x5)	// regs: r3=*(0x5)
  dc:	e9030009 	bez	r3, 0xee	// if (r3 == 0x0) goto loc_ee;
  e0:	ea02453f 	movi	r2, 17727	// regs: r2=0x453f
  e4:	6c8a      	nor	r2, r2	// regs: r2=(~0x453f)
  e6:	6cc8      	or	r3, r2	// regs: r3=(*(0x5) | (~0x453f))
  e8:	005e      	lrw	r2, 0x0	// regs: r2=0x0
  ea:	dc62107c 	st.h	r3, (r2, 0xf8)	// *(0xf8) = (*(0x5) | (~0x453f))
loc_ee:
  ee:	8560      	ld.b	r3, (r5, 0x0)	// regs: r3=*(0x0)
  f0:	2b06      	subi	r3, 7	// regs: r3=(*(0x0) - 0x7)
  f2:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(0x0) - 0x7))
  f4:	3b18      	cmphsi	r3, 25
  f6:	081f      	bt	0x134	// if (r3 >= 0x19) goto loc_134;
  f8:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_tx_analog_gain_mcs3>; regs: r0=<ret sysctrl_efuse_get_tx_analog_gain_mcs3@0xf8>, r1=<clobbered>
  fc:	0183      	lrw	r4, 0x0	// regs: r4=0x0
  fe:	ea07453f 	movi	r7, 17727	// regs: r7=0x453f
 102:	6dde      	nor	r7, r7	// regs: r7=(~0x453f)
 104:	6c1c      	or	r0, r7	// regs: r0=(<ret sysctrl_efuse_get_tx_analog_gain_mcs3@0xf8> | (~0x453f))
 106:	dc041058 	st.h	r0, (r4, 0xb0)	// *(0xb0) = (<ret sysctrl_efuse_get_tx_analog_gain_mcs3@0xf8> | (~0x453f))
 10a:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_tx_analog_gain_mcs0>; regs: r0=<ret sysctrl_efuse_get_tx_analog_gain_mcs0@0x10a>, r1=<clobbered>
 10e:	6c1c      	or	r0, r7	// regs: r0=(<ret sysctrl_efuse_get_tx_analog_gain_mcs0@0x10a> | (~0x453f))
 110:	dc04104f 	st.h	r0, (r4, 0x9e)	// *(0x9e) = (<ret sysctrl_efuse_get_tx_analog_gain_mcs0@0x10a> | (~0x453f))
 114:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_module_type>; regs: r0=<ret sysctrl_efuse_get_module_type@0x114>, r1=<clobbered>
 118:	3850      	cmpnei	r0, 16
 11a:	09ad      	bt	0x474	// if (r0 != 0x10) goto loc_474;
loc_11c:
 11c:	ea036202 	movi	r3, 25090	// regs: r3=0x6202
loc_120:
 120:	dc64107a 	st.h	r3, (r4, 0xf4)	// *(r4 + 0xf4) = r3
 124:	ea036202 	movi	r3, 25090	// regs: r3=0x6202
 128:	dc641056 	st.h	r3, (r4, 0xac)	// *(r4 + 0xac) = 0x6202
 12c:	ea036203 	movi	r3, 25091	// regs: r3=0x6203
 130:	dc64104d 	st.h	r3, (r4, 0x9a)	// *(r4 + 0x9a) = 0x6203
loc_134:
 134:	8560      	ld.b	r3, (r5, 0x0)	// regs: r3=*(r5)
 136:	2b00      	subi	r3, 1	// regs: r3=(*(r5) - 0x1)
 138:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(r5) - 0x1))
 13a:	3b07      	cmphsi	r3, 8
 13c:	0877      	bt	0x22a	// if (r3 >= 0x8) goto loc_22a;
 13e:	1b02      	addi	r3, r14, 8	// regs: r3=(sp + 0x8)
 140:	320c      	movi	r2, 12	// regs: r2=0xc
 142:	a340      	st.b	r2, (r3, 0x0)	// stack_p8 = 0xc
 144:	3208      	movi	r2, 8	// regs: r2=0x8
 146:	0195      	lrw	r4, 0x0	// regs: r4=0x0
 148:	3100      	movi	r1, 0	// regs: r1=0x0
 14a:	a341      	st.b	r2, (r3, 0x1)	// stack_p9 = 0x8
 14c:	3206      	movi	r2, 6	// regs: r2=0x6
 14e:	a342      	st.b	r2, (r3, 0x2)	// stack_pa = 0x6
 150:	3204      	movi	r2, 4	// regs: r2=0x4
 152:	d804009e 	ld.b	r0, (r4, 0x9e)	// regs: r0=*(0x9e)
 156:	a343      	st.b	r2, (r3, 0x3)	// stack_pb = 0x4
 158:	a344      	st.b	r2, (r3, 0x4)	// stack_pc = 0x4
 15a:	3202      	movi	r2, 2	// regs: r2=0x2
 15c:	a345      	st.b	r2, (r3, 0x5)	// stack_pd = 0x2
 15e:	e400203f 	andi	r0, r0, 63	// regs: r0=(*(0x9e) & 0x3f)
 162:	6c87      	mov	r2, r1	// regs: r2=0x0
 164:	ea0d0020 	movi	r13, 32	// regs: r13=0x20
loc_168:
 168:	c42d408c 	asr	r12, r13, r1
 16c:	6b00      	and	r12, r0	// regs: r12=(r12 & (*(0x9e) & 0x3f))
 16e:	e90c0006 	bez	r12, 0x17a	// if (r12 == 0x0) goto loc_17a;
 172:	d023002c 	ldr.b	r12, (r3, r1 << 0)	// regs: r12=*(r3 + (r1 << 0))
 176:	60b0      	addu	r2, r12	// regs: r2=(r2 + *(r3 + (r1 << 0)))
 178:	7488      	zextb	r2, r2	// regs: r2=zext8((r2 + *(r3 + (r1 << 0))))
loc_17a:
 17a:	2100      	addi	r1, 1	// regs: r1=(r1 + 0x1)
 17c:	3946      	cmpnei	r1, 6
 17e:	0bf5      	bt	0x168	// if (r1 != 0x6) goto loc_168;
 180:	a322      	st.b	r1, (r3, 0x2)	// *(r3 + 0x2) = (r1 + 0x1)
 182:	3104      	movi	r1, 4	// regs: r1=0x4
 184:	2a01      	subi	r2, 2	// regs: r2=(r2 - 0x2)
 186:	a323      	st.b	r1, (r3, 0x3)	// *(r3 + 0x3) = 0x4
 188:	a324      	st.b	r1, (r3, 0x4)	// *(r3 + 0x4) = 0x4
 18a:	3102      	movi	r1, 2	// regs: r1=0x2
 18c:	a325      	st.b	r1, (r3, 0x5)	// *(r3 + 0x5) = 0x2
 18e:	6c4b      	mov	r1, r2	// regs: r1=(r2 - 0x2)
 190:	7488      	zextb	r2, r2	// regs: r2=zext8((r2 - 0x2))
 192:	300c      	movi	r0, 12	// regs: r0=0xc
 194:	eb020024 	cmphsi	r2, 37
 198:	a300      	st.b	r0, (r3, 0x0)	// *(r3) = 0xc
 19a:	3008      	movi	r0, 8	// regs: r0=0x8
 19c:	a301      	st.b	r0, (r3, 0x1)	// *(r3 + 0x1) = 0x8
 19e:	0c02      	bf	0x1a2	// if (r2 < 0x25) goto loc_1a2;
 1a0:	3124      	movi	r1, 36	// regs: r1=0x24
loc_1a2:
 1a2:	3200      	movi	r2, 0	// regs: r2=0x0
 1a4:	7444      	zextb	r1, r1	// regs: r1=zext8(r1)
 1a6:	6f0b      	mov	r12, r2	// regs: r12=0x0
 1a8:	ea0d0001 	movi	r13, 1	// regs: r13=0x1
loc_1ac:
 1ac:	d0430020 	ldr.b	r0, (r3, r2 << 0)	// regs: r0=*(r3 + (r2 << 0))
 1b0:	5901      	subu	r0, r1, r0	// regs: r0=(r1 - *(r3 + (r2 << 0)))
 1b2:	e9800168 	blz	r0, 0x482	// if (r0 < 0x0) goto loc_482;
 1b6:	d446002d 	str.b	r13, (r6, r2 << 0)
 1ba:	7440      	zextb	r1, r0	// regs: r1=zext8((r1 - *(r3 + (r2 << 0))))
loc_1bc:
 1bc:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
 1be:	3a46      	cmpnei	r2, 6
 1c0:	0bf6      	bt	0x1ac	// if (r2 != 0x6) goto loc_1ac;
 1c2:	3700      	movi	r7, 0	// regs: r7=0x0
 1c4:	ea080005 	movi	r8, 5	// regs: r8=0x5
 1c8:	e5271000 	subi	r9, r7, 1	// regs: r9=0xffffffff
loc_1cc:
 1cc:	c5060083 	subu	r3, r6, r8	// regs: r3=(r6 - r8)
 1d0:	8305      	ld.b	r0, (r3, 0x5)	// regs: r0=*(((r6 - r8) + 0x5))
 1d2:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0x1d2>, r1=<clobbered>
 1d6:	6ec3      	mov	r11, r0	// regs: r11=<ret __floatsidf@0x1d2>
 1d8:	6c23      	mov	r0, r8	// regs: r0=r8
 1da:	6e87      	mov	r10, r1	// regs: r10=<clobbered>
 1dc:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0x1dc>, r1=<clobbered>
 1e0:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
 1e2:	3180      	movi	r1, 128	// regs: r1=0x80
 1e4:	6c83      	mov	r2, r0	// regs: r2=<ret __floatsidf@0x1dc>
 1e6:	4137      	lsli	r1, r1, 23	// regs: r1=0x40000000
 1e8:	3000      	movi	r0, 0	// regs: r0=0x0
 1ea:	e0000000 	bsr	0x0	// <pow>; regs: r0=<ret pow@0x1ea>, r1=<clobbered>
 1ee:	6c83      	mov	r2, r0	// regs: r2=<ret pow@0x1ea>
 1f0:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
 1f2:	6c2f      	mov	r0, r11	// regs: r0=<ret __floatsidf@0x1d2>
 1f4:	6c6b      	mov	r1, r10	// regs: r1=<clobbered>
 1f6:	e0000000 	bsr	0x0	// <__muldf3>; regs: r0=<ret __muldf3@0x1f6>, r1=<clobbered>
 1fa:	6ec3      	mov	r11, r0	// regs: r11=<ret __muldf3@0x1f6>
 1fc:	6c1f      	mov	r0, r7	// regs: r0=r7
 1fe:	6e87      	mov	r10, r1	// regs: r10=<clobbered>
 200:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0x200>, r1=<clobbered>
 204:	6c83      	mov	r2, r0	// regs: r2=<ret __floatsidf@0x200>
 206:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
 208:	6c2f      	mov	r0, r11	// regs: r0=<ret __muldf3@0x1f6>
 20a:	6c6b      	mov	r1, r10	// regs: r1=<clobbered>
 20c:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x20c>, r1=<clobbered>
 210:	e5081000 	subi	r8, r8, 1	// regs: r8=(r8 - 0x1)
 214:	e0000000 	bsr	0x0	// <__fixunsdfsi>; regs: r0=<ret __fixunsdfsi@0x214>, r1=<clobbered>
 218:	6662      	cmpne	r8, r9
 21a:	75c0      	zextb	r7, r0	// regs: r7=zext8(<ret __fixunsdfsi@0x214>)
 21c:	0bd8      	bt	0x1cc	// if (T) goto loc_1cc;
 21e:	ea03453f 	movi	r3, 17727	// regs: r3=0x453f
 222:	6cce      	nor	r3, r3	// regs: r3=(~0x453f)
 224:	6dcc      	or	r7, r3	// regs: r7=(zext8(<ret __fixunsdfsi@0x214>) | (~0x453f))
 226:	dce4104f 	st.h	r7, (r4, 0x9e)	// *(0x9e) = (zext8(<ret __fixunsdfsi@0x214>) | (~0x453f))
loc_22a:
 22a:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_module_type>; regs: r0=<ret sysctrl_efuse_get_module_type@0x22a>, r1=<clobbered>
 22e:	3850      	cmpnei	r0, 16
 230:	092c      	bt	0x488	// if (r0 != 0x10) goto loc_488;
loc_232:
 232:	0370      	lrw	r3, 0x0	// regs: r3=0x0
 234:	ea02451d 	movi	r2, 17693	// regs: r2=0x451d
 238:	6c8a      	nor	r2, r2	// regs: r2=(~0x451d)
 23a:	dc43107c 	st.h	r2, (r3, 0xf8)	// *(0xf8) = (~0x451d)
 23e:	ea02450f 	movi	r2, 17679	// regs: r2=0x450f
 242:	6c8a      	nor	r2, r2	// regs: r2=(~0x450f)
 244:	dc431058 	st.h	r2, (r3, 0xb0)	// *(0xb0) = (~0x450f)
 248:	ea024517 	movi	r2, 17687	// regs: r2=0x4517
 24c:	6c8a      	nor	r2, r2	// regs: r2=(~0x4517)
 24e:	dc43104f 	st.h	r2, (r3, 0x9e)	// *(0x9e) = (~0x4517)
loc_252:
 252:	d8654002 	ld.bs	r3, (r5, 0x2)	// regs: r3=*(r5 + 0x2)
 256:	e92300f8 	bnez	r3, 0x446	// if (r3 != 0x0) goto loc_446;
 25a:	3205      	movi	r2, 5	// regs: r2=0x5
 25c:	1904      	addi	r1, r14, 16	// regs: r1=(sp + 0x10)
 25e:	3031      	movi	r0, 49	// regs: r0=0x31
 260:	e0000000 	bsr	0x0	// <sysctrl_efuse_config_and_read>; regs: r0=<ret sysctrl_efuse_config_and_read@0x260>, r1=<clobbered>
 264:	d86e0010 	ld.b	r3, (r14, 0x10)	// regs: r3=stack_p10
 268:	e9230006 	bnez	r3, 0x274	// if (r3 != 0x0) goto loc_274;
 26c:	d84e0011 	ld.b	r2, (r14, 0x11)	// regs: r2=stack_p11
 270:	e90200eb 	bez	r2, 0x446	// if (r2 == 0x0) goto loc_446;
loc_274:
 274:	139f      	lrw	r4, 0x0	// regs: r4=0x0
 276:	4365      	lsli	r3, r3, 5	// regs: r3=(stack_p10 << 0x5)
 278:	d84e0011 	ld.b	r2, (r14, 0x11)	// regs: r2=stack_p11
 27c:	e4632700 	andi	r3, r3, 1792	// regs: r3=((stack_p10 << 0x5) & 0x700)
 280:	6cc8      	or	r3, r2	// regs: r3=(((stack_p10 << 0x5) & 0x700) | stack_p11)
 282:	ea010fff 	movi	r1, 4095	// regs: r1=0xfff
 286:	6c46      	nor	r1, r1	// regs: r1=(~0xfff)
 288:	8c5f      	ld.h	r2, (r4, 0x3e)	// regs: r2=*(0x3e)
 28a:	6884      	and	r2, r1	// regs: r2=(*(0x3e) & (~0xfff))
 28c:	6c8c      	or	r2, r3	// regs: r2=((*(0x3e) & (~0xfff)) | (((stack_p10 << 0x5) & 0x700) | stack_p11))
 28e:	ac5f      	st.h	r2, (r4, 0x3e)	// *(0x3e) = ((*(0x3e) & (~0xfff)) | (((stack_p10 << 0x5) & 0x700) | stack_p11))
 290:	d8441041 	ld.h	r2, (r4, 0x82)	// regs: r2=*(0x82)
 294:	6884      	and	r2, r1	// regs: r2=(*(0x82) & (~0xfff))
 296:	6c8c      	or	r2, r3	// regs: r2=((*(0x82) & (~0xfff)) | (((stack_p10 << 0x5) & 0x700) | stack_p11))
 298:	dc441041 	st.h	r2, (r4, 0x82)	// *(0x82) = ((*(0x82) & (~0xfff)) | (((stack_p10 << 0x5) & 0x700) | stack_p11))
 29c:	d8441063 	ld.h	r2, (r4, 0xc6)	// regs: r2=*(0xc6)
 2a0:	6884      	and	r2, r1	// regs: r2=(*(0xc6) & (~0xfff))
 2a2:	6c8c      	or	r2, r3	// regs: r2=((*(0xc6) & (~0xfff)) | (((stack_p10 << 0x5) & 0x700) | stack_p11))
 2a4:	dc441063 	st.h	r2, (r4, 0xc6)	// *(0xc6) = ((*(0xc6) & (~0xfff)) | (((stack_p10 << 0x5) & 0x700) | stack_p11))
 2a8:	d8441085 	ld.h	r2, (r4, 0x10a)	// regs: r2=*(0x10a)
 2ac:	6884      	and	r2, r1	// regs: r2=(*(0x10a) & (~0xfff))
 2ae:	6cc8      	or	r3, r2	// regs: r3=((((stack_p10 << 0x5) & 0x700) | stack_p11) | (*(0x10a) & (~0xfff)))
 2b0:	dc641085 	st.h	r3, (r4, 0x10a)	// *(0x10a) = ((((stack_p10 << 0x5) & 0x700) | stack_p11) | (*(0x10a) & (~0xfff)))
 2b4:	d86e0012 	ld.b	r3, (r14, 0x12)	// regs: r3=stack_p12
 2b8:	8c32      	ld.h	r1, (r4, 0x24)	// regs: r1=*(0x24)
 2ba:	434c      	lsli	r2, r3, 12	// regs: r2=(stack_p12 << 0xc)
 2bc:	748b      	sexth	r2, r2	// regs: r2=sext16((stack_p12 << 0xc))
 2be:	e4212fff 	andi	r1, r1, 4095	// regs: r1=(*(0x24) & 0xfff)
 2c2:	6c48      	or	r1, r2	// regs: r1=((*(0x24) & 0xfff) | sext16((stack_p12 << 0xc)))
 2c4:	ac32      	st.h	r1, (r4, 0x24)	// *(0x24) = ((*(0x24) & 0xfff) | sext16((stack_p12 << 0xc)))
 2c6:	d8241034 	ld.h	r1, (r4, 0x68)	// regs: r1=*(0x68)
 2ca:	e4212fff 	andi	r1, r1, 4095	// regs: r1=(*(0x68) & 0xfff)
 2ce:	6c48      	or	r1, r2	// regs: r1=((*(0x68) & 0xfff) | sext16((stack_p12 << 0xc)))
 2d0:	dc241034 	st.h	r1, (r4, 0x68)	// *(0x68) = ((*(0x68) & 0xfff) | sext16((stack_p12 << 0xc)))
 2d4:	d8241056 	ld.h	r1, (r4, 0xac)	// regs: r1=*(0xac)
 2d8:	e4212fff 	andi	r1, r1, 4095	// regs: r1=(*(0xac) & 0xfff)
 2dc:	6c48      	or	r1, r2	// regs: r1=((*(0xac) & 0xfff) | sext16((stack_p12 << 0xc)))
 2de:	dc241056 	st.h	r1, (r4, 0xac)	// *(0xac) = ((*(0xac) & 0xfff) | sext16((stack_p12 << 0xc)))
 2e2:	d8241078 	ld.h	r1, (r4, 0xf0)	// regs: r1=*(0xf0)
 2e6:	e4212fff 	andi	r1, r1, 4095	// regs: r1=(*(0xf0) & 0xfff)
 2ea:	6c84      	or	r2, r1	// regs: r2=(sext16((stack_p12 << 0xc)) | (*(0xf0) & 0xfff))
 2ec:	3100      	movi	r1, 0	// regs: r1=0x0
 2ee:	29f0      	subi	r1, 241	// regs: r1=0xffffff0f
 2f0:	dc441078 	st.h	r2, (r4, 0xf0)	// *(0xf0) = (sext16((stack_p12 << 0xc)) | (*(0xf0) & 0xfff))
 2f4:	8c53      	ld.h	r2, (r4, 0x26)	// regs: r2=*(0x26)
 2f6:	e46320f0 	andi	r3, r3, 240	// regs: r3=(stack_p12 & 0xf0)
 2fa:	6884      	and	r2, r1	// regs: r2=(*(0x26) & 0xffffff0f)
 2fc:	6c8c      	or	r2, r3	// regs: r2=((*(0x26) & 0xffffff0f) | (stack_p12 & 0xf0))
 2fe:	ac53      	st.h	r2, (r4, 0x26)	// *(0x26) = ((*(0x26) & 0xffffff0f) | (stack_p12 & 0xf0))
 300:	d8441035 	ld.h	r2, (r4, 0x6a)	// regs: r2=*(0x6a)
 304:	6884      	and	r2, r1	// regs: r2=(*(0x6a) & 0xffffff0f)
 306:	6c8c      	or	r2, r3	// regs: r2=((*(0x6a) & 0xffffff0f) | (stack_p12 & 0xf0))
 308:	dc441035 	st.h	r2, (r4, 0x6a)	// *(0x6a) = ((*(0x6a) & 0xffffff0f) | (stack_p12 & 0xf0))
 30c:	d8441057 	ld.h	r2, (r4, 0xae)	// regs: r2=*(0xae)
 310:	6884      	and	r2, r1	// regs: r2=(*(0xae) & 0xffffff0f)
 312:	6c8c      	or	r2, r3	// regs: r2=((*(0xae) & 0xffffff0f) | (stack_p12 & 0xf0))
 314:	dc441057 	st.h	r2, (r4, 0xae)	// *(0xae) = ((*(0xae) & 0xffffff0f) | (stack_p12 & 0xf0))
 318:	d8441079 	ld.h	r2, (r4, 0xf2)	// regs: r2=*(0xf2)
 31c:	6884      	and	r2, r1	// regs: r2=(*(0xf2) & 0xffffff0f)
 31e:	d8ae0013 	ld.b	r5, (r14, 0x13)	// regs: r5=stack_p13
 322:	6cc8      	or	r3, r2	// regs: r3=((stack_p12 & 0xf0) | (*(0xf2) & 0xffffff0f))
 324:	ea060f00 	movi	r6, 3840	// regs: r6=0xf00
 328:	6d9a      	nor	r6, r6	// regs: r6=(~0xf00)
 32a:	dc641079 	st.h	r3, (r4, 0xf2)	// *(0xf2) = ((stack_p12 & 0xf0) | (*(0xf2) & 0xffffff0f))
 32e:	450c      	lsli	r0, r5, 12	// regs: r0=(stack_p13 << 0xc)
 330:	4564      	lsli	r3, r5, 4	// regs: r3=(stack_p13 << 0x4)
 332:	8cbb      	ld.h	r5, (r4, 0x36)	// regs: r5=*(0x36)
 334:	e4632f00 	andi	r3, r3, 3840	// regs: r3=((stack_p13 << 0x4) & 0xf00)
 338:	6958      	and	r5, r6	// regs: r5=(*(0x36) & (~0xf00))
 33a:	6d4c      	or	r5, r3	// regs: r5=((*(0x36) & (~0xf00)) | ((stack_p13 << 0x4) & 0xf00))
 33c:	d9a4101d 	ld.h	r13, (r4, 0x3a)	// regs: r13=*(0x3a)
 340:	d824103f 	ld.h	r1, (r4, 0x7e)	// regs: r1=*(0x7e)
 344:	d8441061 	ld.h	r2, (r4, 0xc2)	// regs: r2=*(0xc2)
 348:	d9841083 	ld.h	r12, (r4, 0x106)	// regs: r12=*(0x106)
 34c:	acbb      	st.h	r5, (r4, 0x36)	// *(0x36) = ((*(0x36) & (~0xf00)) | ((stack_p13 << 0x4) & 0xf00))
 34e:	d8a4103d 	ld.h	r5, (r4, 0x7a)	// regs: r5=*(0x7a)
 352:	6958      	and	r5, r6	// regs: r5=(*(0x7a) & (~0xf00))
 354:	6d4c      	or	r5, r3	// regs: r5=((*(0x7a) & (~0xf00)) | ((stack_p13 << 0x4) & 0xf00))
 356:	dca4103d 	st.h	r5, (r4, 0x7a)	// *(0x7a) = ((*(0x7a) & (~0xf00)) | ((stack_p13 << 0x4) & 0xf00))
 35a:	d8a4105f 	ld.h	r5, (r4, 0xbe)	// regs: r5=*(0xbe)
 35e:	6958      	and	r5, r6	// regs: r5=(*(0xbe) & (~0xf00))
 360:	6d4c      	or	r5, r3	// regs: r5=((*(0xbe) & (~0xf00)) | ((stack_p13 << 0x4) & 0xf00))
 362:	dca4105f 	st.h	r5, (r4, 0xbe)	// *(0xbe) = ((*(0xbe) & (~0xf00)) | ((stack_p13 << 0x4) & 0xf00))
 366:	d8a41081 	ld.h	r5, (r4, 0x102)	// regs: r5=*(0x102)
 36a:	6958      	and	r5, r6	// regs: r5=(*(0x102) & (~0xf00))
 36c:	6cd4      	or	r3, r5	// regs: r3=(((stack_p13 << 0x4) & 0xf00) | (*(0x102) & (~0xf00)))
 36e:	dc641081 	st.h	r3, (r4, 0x102)	// *(0x102) = (((stack_p13 << 0x4) & 0xf00) | (*(0x102) & (~0xf00)))
 372:	d86e0014 	ld.b	r3, (r14, 0x14)	// regs: r3=stack_p14
 376:	7403      	sexth	r0, r0	// regs: r0=sext16((stack_p13 << 0xc))
 378:	e4212e1f 	andi	r1, r1, 3615	// regs: r1=(*(0x7e) & 0xe1f)
 37c:	e4422e1f 	andi	r2, r2, 3615	// regs: r2=(*(0xc2) & 0xe1f)
 380:	4365      	lsli	r3, r3, 5	// regs: r3=(stack_p14 << 0x5)
 382:	e46321e0 	andi	r3, r3, 480	// regs: r3=((stack_p14 << 0x5) & 0x1e0)
 386:	e58c2e1f 	andi	r12, r12, 3615	// regs: r12=(*(0x106) & 0xe1f)
 38a:	6c40      	or	r1, r0	// regs: r1=((*(0x7e) & 0xe1f) | sext16((stack_p13 << 0xc)))
 38c:	6c80      	or	r2, r0	// regs: r2=((*(0xc2) & 0xe1f) | sext16((stack_p13 << 0xc)))
 38e:	e5ad2e1f 	andi	r13, r13, 3615	// regs: r13=(*(0x3a) & 0xe1f)
 392:	6c4c      	or	r1, r3	// regs: r1=(((*(0x7e) & 0xe1f) | sext16((stack_p13 << 0xc))) | ((stack_p14 << 0x5) & 0x1e0))
 394:	6c8c      	or	r2, r3	// regs: r2=(((*(0xc2) & 0xe1f) | sext16((stack_p13 << 0xc))) | ((stack_p14 << 0x5) & 0x1e0))
 396:	6f40      	or	r13, r0	// regs: r13=((*(0x3a) & 0xe1f) | sext16((stack_p13 << 0xc)))
 398:	6c30      	or	r0, r12	// regs: r0=(sext16((stack_p13 << 0xc)) | (*(0x106) & 0xe1f))
 39a:	6f4c      	or	r13, r3	// regs: r13=(((*(0x3a) & 0xe1f) | sext16((stack_p13 << 0xc))) | ((stack_p14 << 0x5) & 0x1e0))
 39c:	dc24103f 	st.h	r1, (r4, 0x7e)	// *(0x7e) = (((*(0x7e) & 0xe1f) | sext16((stack_p13 << 0xc))) | ((stack_p14 << 0x5) & 0x1e0))
 3a0:	6cc0      	or	r3, r0	// regs: r3=(((stack_p14 << 0x5) & 0x1e0) | (sext16((stack_p13 << 0xc)) | (*(0x106) & 0xe1f)))
 3a2:	dc441061 	st.h	r2, (r4, 0xc2)	// *(0xc2) = (((*(0xc2) & 0xe1f) | sext16((stack_p13 << 0xc))) | ((stack_p14 << 0x5) & 0x1e0))
 3a6:	1904      	addi	r1, r14, 16	// regs: r1=(sp + 0x10)
 3a8:	3202      	movi	r2, 2	// regs: r2=0x2
 3aa:	303e      	movi	r0, 62	// regs: r0=0x3e
 3ac:	dc641083 	st.h	r3, (r4, 0x106)	// *(0x106) = (((stack_p14 << 0x5) & 0x1e0) | (sext16((stack_p13 << 0xc)) | (*(0x106) & 0xe1f)))
 3b0:	dda4101d 	st.h	r13, (r4, 0x3a)	// *(0x3a) = (((*(0x3a) & 0xe1f) | sext16((stack_p13 << 0xc))) | ((stack_p14 << 0x5) & 0x1e0))
 3b4:	e0000000 	bsr	0x0	// <sysctrl_efuse_config_and_read>; regs: r0=<ret sysctrl_efuse_config_and_read@0x3b4>, r1=<clobbered>
 3b8:	d84e0011 	ld.b	r2, (r14, 0x11)	// regs: r2=stack_p11
 3bc:	e462200f 	andi	r3, r2, 15	// regs: r3=(stack_p11 & 0xf)
 3c0:	3b0b      	cmphsi	r3, 12
 3c2:	0868      	bt	0x492	// if (r3 >= 0xc) goto loc_492;
 3c4:	4364      	lsli	r3, r3, 4	// regs: r3=((stack_p11 & 0xf) << 0x4)
 3c6:	e423003f 	addi	r1, r3, 64	// regs: r1=(((stack_p11 & 0xf) << 0x4) + 0x40)
loc_3ca:
 3ca:	d80e0010 	ld.b	r0, (r14, 0x10)	// regs: r0=stack_p10
 3ce:	4068      	lsli	r3, r0, 8	// regs: r3=(stack_p10 << 0x8)
 3d0:	e4632f00 	andi	r3, r3, 3840	// regs: r3=((stack_p10 << 0x8) & 0xf00)
 3d4:	6cc4      	or	r3, r1	// regs: r3=(((stack_p10 << 0x8) & 0xf00) | r1)
 3d6:	4804      	lsri	r0, r0, 4	// regs: r0=(stack_p10 >> 0x4)
 3d8:	6cc0      	or	r3, r0	// regs: r3=((((stack_p10 << 0x8) & 0xf00) | r1) | (stack_p10 >> 0x4))
 3da:	8c27      	ld.h	r1, (r4, 0xe)	// regs: r1=*(0xe)
 3dc:	ea000fff 	movi	r0, 4095	// regs: r0=0xfff
 3e0:	6c02      	nor	r0, r0	// regs: r0=(~0xfff)
 3e2:	74cf      	sexth	r3, r3	// regs: r3=sext16(((((stack_p10 << 0x8) & 0xf00) | r1) | (stack_p10 >> 0x4)))
 3e4:	6840      	and	r1, r0	// regs: r1=(*(0xe) & (~0xfff))
 3e6:	6c4c      	or	r1, r3	// regs: r1=((*(0xe) & (~0xfff)) | sext16(((((stack_p10 << 0x8) & 0xf00) | r1) | (stack_p10 >> 0x4))))
 3e8:	ac27      	st.h	r1, (r4, 0xe)	// *(0xe) = ((*(0xe) & (~0xfff)) | sext16(((((stack_p10 << 0x8) & 0xf00) | r1) | (stack_p10 >> 0x4))))
 3ea:	d8241029 	ld.h	r1, (r4, 0x52)	// regs: r1=*(0x52)
 3ee:	6840      	and	r1, r0	// regs: r1=(*(0x52) & (~0xfff))
 3f0:	6c4c      	or	r1, r3	// regs: r1=((*(0x52) & (~0xfff)) | sext16(((((stack_p10 << 0x8) & 0xf00) | r1) | (stack_p10 >> 0x4))))
 3f2:	dc241029 	st.h	r1, (r4, 0x52)	// *(0x52) = ((*(0x52) & (~0xfff)) | sext16(((((stack_p10 << 0x8) & 0xf00) | r1) | (stack_p10 >> 0x4))))
 3f6:	d824104b 	ld.h	r1, (r4, 0x96)	// regs: r1=*(0x96)
 3fa:	6840      	and	r1, r0	// regs: r1=(*(0x96) & (~0xfff))
 3fc:	6c4c      	or	r1, r3	// regs: r1=((*(0x96) & (~0xfff)) | sext16(((((stack_p10 << 0x8) & 0xf00) | r1) | (stack_p10 >> 0x4))))
 3fe:	dc24104b 	st.h	r1, (r4, 0x96)	// *(0x96) = ((*(0x96) & (~0xfff)) | sext16(((((stack_p10 << 0x8) & 0xf00) | r1) | (stack_p10 >> 0x4))))
 402:	d824106d 	ld.h	r1, (r4, 0xda)	// regs: r1=*(0xda)
 406:	6840      	and	r1, r0	// regs: r1=(*(0xda) & (~0xfff))
 408:	6cc4      	or	r3, r1	// regs: r3=(sext16(((((stack_p10 << 0x8) & 0xf00) | r1) | (stack_p10 >> 0x4))) | (*(0xda) & (~0xfff)))
 40a:	dc64106d 	st.h	r3, (r4, 0xda)	// *(0xda) = (sext16(((((stack_p10 << 0x8) & 0xf00) | r1) | (stack_p10 >> 0x4))) | (*(0xda) & (~0xfff)))
 40e:	ea010f00 	movi	r1, 3840	// regs: r1=0xf00
 412:	6c46      	nor	r1, r1	// regs: r1=(~0xf00)
 414:	4264      	lsli	r3, r2, 4	// regs: r3=(stack_p11 << 0x4)
 416:	8c4f      	ld.h	r2, (r4, 0x1e)	// regs: r2=*(0x1e)
 418:	e4632f00 	andi	r3, r3, 3840	// regs: r3=((stack_p11 << 0x4) & 0xf00)
 41c:	6884      	and	r2, r1	// regs: r2=(*(0x1e) & (~0xf00))
 41e:	6c8c      	or	r2, r3	// regs: r2=((*(0x1e) & (~0xf00)) | ((stack_p11 << 0x4) & 0xf00))
 420:	ac4f      	st.h	r2, (r4, 0x1e)	// *(0x1e) = ((*(0x1e) & (~0xf00)) | ((stack_p11 << 0x4) & 0xf00))
 422:	d8441031 	ld.h	r2, (r4, 0x62)	// regs: r2=*(0x62)
 426:	6884      	and	r2, r1	// regs: r2=(*(0x62) & (~0xf00))
 428:	6c8c      	or	r2, r3	// regs: r2=((*(0x62) & (~0xf00)) | ((stack_p11 << 0x4) & 0xf00))
 42a:	dc441031 	st.h	r2, (r4, 0x62)	// *(0x62) = ((*(0x62) & (~0xf00)) | ((stack_p11 << 0x4) & 0xf00))
 42e:	d8441053 	ld.h	r2, (r4, 0xa6)	// regs: r2=*(0xa6)
 432:	6884      	and	r2, r1	// regs: r2=(*(0xa6) & (~0xf00))
 434:	6c8c      	or	r2, r3	// regs: r2=((*(0xa6) & (~0xf00)) | ((stack_p11 << 0x4) & 0xf00))
 436:	dc441053 	st.h	r2, (r4, 0xa6)	// *(0xa6) = ((*(0xa6) & (~0xf00)) | ((stack_p11 << 0x4) & 0xf00))
 43a:	d8441075 	ld.h	r2, (r4, 0xea)	// regs: r2=*(0xea)
 43e:	6884      	and	r2, r1	// regs: r2=(*(0xea) & (~0xf00))
 440:	6cc8      	or	r3, r2	// regs: r3=(((stack_p11 << 0x4) & 0xf00) | (*(0xea) & (~0xf00)))
 442:	dc641075 	st.h	r3, (r4, 0xea)	// *(0xea) = (((stack_p11 << 0x4) & 0xf00) | (*(0xea) & (~0xf00)))
loc_446:
 446:	3000      	movi	r0, 0	// regs: r0=0x0
 448:	1416      	addi	r14, r14, 88	// regs: r14=(sp + 0x58)
 44a:	1498      	pop	r4-r11, r15
 44c:	00000000 	.long	0x00000000	// <adc_cal_cfg_val_buf>
 450:	00000000 	.long	0x00000000	// <tx_dcoc_res>
 454:	00000000 	.long	0x00000000	// <module_efuse_info>
 458:	00000000 	.long	0x00000000	// <.rodata.rf_para_efuse_read.str1.1>
 45c:	00000000 	.long	0x00000000	// <dpd_epa_gain_comp>
 460:	00000000 	.long	0x00000000	// <dpd_epa_phase_comp>
 464:	00000000 	.long	0x00000000	// <tx_epa_imb_res_gm>
 468:	00000000 	.long	0x00000000	// <tx_epa_imb_res_pm>
 46c:	00000000 	.long	0x00000000	// <rf_agc_reg_hw_val>
 470:	00000000 	.long	0x00000000	// <rf_reg_hw_val>
loc_474:
 474:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_module_type>; regs: r0=<ret sysctrl_efuse_get_module_type@0x474>, r1=<clobbered>
 478:	3843      	cmpnei	r0, 3
 47a:	0e51      	bf	0x11c	// if (r0 == 0x3) goto loc_11c;
 47c:	ea036201 	movi	r3, 25089	// regs: r3=0x6201
 480:	0650      	br	0x120	// goto loc_120;
loc_482:
 482:	d446002c 	str.b	r12, (r6, r2 << 0)
 486:	069b      	br	0x1bc	// goto loc_1bc;
loc_488:
 488:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_module_type>; regs: r0=<ret sysctrl_efuse_get_module_type@0x488>, r1=<clobbered>
 48c:	3843      	cmpnei	r0, 3
 48e:	0ae2      	bt	0x252	// if (r0 != 0x3) goto loc_252;
 490:	06d1      	br	0x232	// goto loc_232;
loc_492:
 492:	31f0      	movi	r1, 240	// regs: r1=0xf0
 494:	079b      	br	0x3ca	// goto loc_3ca;

Disassembly of section .text.ah_rf_regs_read:

00000000 <ah_rf_regs_read>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	3490      	movi	r4, 144	// regs: r4=0x90
   4:	4484      	lsli	r4, r4, 4	// regs: r4=0x900
   6:	3500      	movi	r5, 0	// regs: r5=0x0
   8:	10c7      	lrw	r6, 0x0	// regs: r6=0x0
loc_a:
   a:	6c13      	mov	r0, r4	// regs: r0=r4
   c:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0xc>, r1=<clobbered>
  10:	d4a60440 	str.h	r0, (r6, r5 << 1)
  14:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  16:	eb450038 	cmpnei	r5, 56
  1a:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  1c:	7511      	zexth	r4, r4	// regs: r4=zext16((r4 + 0x1))
  1e:	0bf6      	bt	0xa	// if (r5 != 0x38) goto loc_a;
  20:	3000      	movi	r0, 0	// regs: r0=0x0
  22:	1493      	pop	r4-r6, r15
  24:	0000      	.short	0x0000	// <rf_regs>
  26:	0000      	.short	0x0000

Disassembly of section .text.ah_rf_reg_read:

00000000 <ah_rf_reg_read>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0x2>, r1=<clobbered>
   6:	1490      	pop	r15

Disassembly of section .text.ah_rf_reg_write:

00000000 <ah_rf_reg_write>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x2>, r1=<clobbered>
   6:	1490      	pop	r15

Disassembly of section .text.ah_rf_soft_reset:

00000000 <ah_rf_soft_reset>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	3101      	movi	r1, 1	// regs: r1=0x1
   4:	ea000fff 	movi	r0, 4095	// regs: r0=0xfff
   8:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x8>, r1=<clobbered>
   c:	3100      	movi	r1, 0	// regs: r1=0x0
   e:	ea000fff 	movi	r0, 4095	// regs: r0=0xfff
  12:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x12>, r1=<clobbered>
  16:	3000      	movi	r0, 0	// regs: r0=0x0
  18:	1490      	pop	r15

Disassembly of section .text.ah_rf_rx_bb_ana_out:

00000000 <ah_rf_rx_bb_ana_out>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	ea011c84 	movi	r1, 7300	// regs: r1=0x1c84
   6:	3097      	movi	r0, 151	// regs: r0=0x97
   8:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x8>, r1=<clobbered>
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15

Disassembly of section .text.ah_rf_tx_bb_ana_out:

00000000 <ah_rf_tx_bb_ana_out>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	ea01188d 	movi	r1, 6285	// regs: r1=0x188d
   6:	30d8      	movi	r0, 216	// regs: r0=0xd8
   8:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x8>, r1=<clobbered>
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15

Disassembly of section .text.ah_rf_check_lo_lock:

00000000 <ah_rf_check_lo_lock>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	ea000811 	movi	r0, 2065	// regs: r0=0x811
   6:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0x6>, r1=<clobbered>
   a:	e4004400 	xori	r0, r0, 1024	// regs: r0=(<ret ah_rfspi_read@0x6> ^ 0x400)
   e:	c5405940 	sext	r0, r0, 10, 10	// regs: r0=sext((<ret ah_rfspi_read@0x6> ^ 0x400))
  12:	1490      	pop	r15

Disassembly of section .text.ah_rf_lo_freq_set:

00000000 <ah_rf_lo_freq_set>: // arg_bytes: 4
   0:	14d3      	push	r4-r6, r15
   2:	1270      	lrw	r3, 0xfff4dc70	// regs: r3=0xfff4dc70
   4:	584c      	addu	r2, r0, r3	// regs: r2=(<arg0> + 0xfff4dc70)
   6:	ea03c350 	movi	r3, 50000	// regs: r3=0xc350
   a:	c4434903 	rotli	r3, r3, 2	// regs: r3=rotl(0xc350, 0x2)
   e:	648c      	cmphs	r3, r2
  10:	0c95      	bf	0x13a	// if (!T) goto loc_13a;
  12:	e0000000 	bsr	0x0	// <__floatunsisf>; regs: r0=<ret __floatunsisf@0x12>, r1=<clobbered>
  16:	31fc      	movi	r1, 252	// regs: r1=0xfc
  18:	4136      	lsli	r1, r1, 22	// regs: r1=0x3f000000
  1a:	e0000000 	bsr	0x0	// <__mulsf3>; regs: r0=<ret __mulsf3@0x1a>, r1=<clobbered>
  1e:	ea21447a 	movih	r1, 17530	// regs: r1=(0x447a << 0x10)
  22:	e0000000 	bsr	0x0	// <__divsf3>; regs: r0=<ret __divsf3@0x22>, r1=<clobbered>
  26:	31f8      	movi	r1, 248	// regs: r1=0xf8
  28:	4136      	lsli	r1, r1, 22	// regs: r1=0x3e000000
  2a:	e0000000 	bsr	0x0	// <__mulsf3>; regs: r0=<ret __mulsf3@0x2a>, r1=<clobbered>
  2e:	6d03      	mov	r4, r0	// regs: r4=<ret __mulsf3@0x2a>
  30:	e0000000 	bsr	0x0	// <__fixunssfsi>; regs: r0=<ret __fixunssfsi@0x30>, r1=<clobbered>
  34:	7541      	zexth	r5, r0	// regs: r5=zext16(<ret __fixunssfsi@0x30>)
  36:	6c17      	mov	r0, r5	// regs: r0=zext16(<ret __fixunssfsi@0x30>)
  38:	e0000000 	bsr	0x0	// <__floatunsisf>; regs: r0=<ret __floatunsisf@0x38>, r1=<clobbered>
  3c:	6c43      	mov	r1, r0	// regs: r1=<ret __floatunsisf@0x38>
  3e:	6c13      	mov	r0, r4	// regs: r0=<ret __mulsf3@0x2a>
  40:	e0000000 	bsr	0x0	// <__subsf3>; regs: r0=<ret __subsf3@0x40>, r1=<clobbered>
  44:	3195      	movi	r1, 149	// regs: r1=0x95
  46:	4137      	lsli	r1, r1, 23	// regs: r1=0x4a800000
  48:	6d83      	mov	r6, r0	// regs: r6=<ret __subsf3@0x40>
  4a:	e0000000 	bsr	0x0	// <__mulsf3>; regs: r0=<ret __mulsf3@0x4a>, r1=<clobbered>
  4e:	6d03      	mov	r4, r0	// regs: r4=<ret __mulsf3@0x4a>
  50:	ea214040 	movih	r1, 16448	// regs: r1=(0x4040 << 0x10)
  54:	6c1b      	mov	r0, r6	// regs: r0=<ret __subsf3@0x40>
  56:	e0000000 	bsr	0x0	// <__mulsf3>; regs: r0=<ret __mulsf3@0x56>, r1=<clobbered>
  5a:	6c43      	mov	r1, r0	// regs: r1=<ret __mulsf3@0x56>
  5c:	6c13      	mov	r0, r4	// regs: r0=<ret __mulsf3@0x4a>
  5e:	e0000000 	bsr	0x0	// <__subsf3>; regs: r0=<ret __subsf3@0x5e>, r1=<clobbered>
  62:	e0000000 	bsr	0x0	// <__fixunssfsi>; regs: r0=<ret __fixunssfsi@0x62>, r1=<clobbered>
  66:	6d03      	mov	r4, r0	// regs: r4=<ret __fixunssfsi@0x62>
  68:	30c2      	movi	r0, 194	// regs: r0=0xc2
  6a:	4003      	lsli	r0, r0, 3	// regs: r0=0x610
  6c:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0x6c>, r1=<clobbered>
  70:	ec2000ff 	ori	r1, r0, 255	// regs: r1=(<ret ah_rfspi_read@0x6c> | 0xff)
  74:	30c2      	movi	r0, 194	// regs: r0=0xc2
  76:	7445      	zexth	r1, r1	// regs: r1=zext16((<ret ah_rfspi_read@0x6c> | 0xff))
  78:	4003      	lsli	r0, r0, 3	// regs: r0=0x610
  7a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x7a>, r1=<clobbered>
  7e:	30c0      	movi	r0, 192	// regs: r0=0xc0
  80:	6c57      	mov	r1, r5	// regs: r1=zext16(<ret __fixunssfsi@0x30>)
  82:	4003      	lsli	r0, r0, 3	// regs: r0=0x600
  84:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x84>, r1=<clobbered>
  88:	7451      	zexth	r1, r4	// regs: r1=zext16(<ret __fixunssfsi@0x62>)
  8a:	ea000601 	movi	r0, 1537	// regs: r0=0x601
  8e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x8e>, r1=<clobbered>
  92:	4c30      	lsri	r1, r4, 16	// regs: r1=(<ret __fixunssfsi@0x62> >> 0x10)
  94:	ea000602 	movi	r0, 1538	// regs: r0=0x602
  98:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x98>, r1=<clobbered>
  9c:	3405      	movi	r4, 5	// regs: r4=0x5
loc_9e:
  9e:	3081      	movi	r0, 129	// regs: r0=0x81
  a0:	3130      	movi	r1, 48	// regs: r1=0x30
  a2:	4004      	lsli	r0, r0, 4	// regs: r0=0x810
  a4:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xa4>, r1=<clobbered>
  a8:	2c00      	subi	r4, 1	// regs: r4=(r4 - 0x1)
  aa:	3081      	movi	r0, 129	// regs: r0=0x81
  ac:	3131      	movi	r1, 49	// regs: r1=0x31
  ae:	4004      	lsli	r0, r0, 4	// regs: r0=0x810
  b0:	7510      	zextb	r4, r4	// regs: r4=zext8((r4 - 0x1))
  b2:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xb2>, r1=<clobbered>
  b6:	30c8      	movi	r0, 200	// regs: r0=0xc8
  b8:	e0000000 	bsr	0x0	// <delay_us>; regs: r0=<ret delay_us@0xb8>, r1=<clobbered>
  bc:	e9240024 	bnez	r4, 0x104	// if (r4 != 0x0) goto loc_104;
  c0:	1161      	lrw	r3, 0x0	// regs: r3=0x0
  c2:	8368      	ld.b	r3, (r3, 0x8)	// regs: r3=*(0x8)
  c4:	e923001a 	bnez	r3, 0xf8	// if (r3 != 0x0) goto loc_f8;
loc_c8:
  c8:	30c8      	movi	r0, 200	// regs: r0=0xc8
  ca:	4002      	lsli	r0, r0, 2	// regs: r0=0x320
  cc:	e0000000 	bsr	0x0	// <delay_us>; regs: r0=<ret delay_us@0xcc>, r1=<clobbered>
  d0:	ea000811 	movi	r0, 2065	// regs: r0=0x811
  d4:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0xd4>, r1=<clobbered>
  d8:	e4002400 	andi	r0, r0, 1024	// regs: r0=(<ret ah_rfspi_read@0xd4> & 0x400)
  dc:	e900001d 	bez	r0, 0x116	// if (r0 == 0x0) goto loc_116;
loc_e0:
  e0:	ea000811 	movi	r0, 2065	// regs: r0=0x811
  e4:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0xe4>, r1=<clobbered>
  e8:	e42021ff 	andi	r1, r0, 511	// regs: r1=(<ret ah_rfspi_read@0xe4> & 0x1ff)
  ec:	ea000603 	movi	r0, 1539	// regs: r0=0x603
  f0:	e0000000 	bsr	0x0	// <ah_rfspi_write_and_read>; regs: r0=<ret ah_rfspi_write_and_read@0xf0>, r1=<clobbered>
  f4:	3000      	movi	r0, 0	// regs: r0=0x0
  f6:	0406      	br	0x102	// goto loc_102;
loc_f8:
  f8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
loc_fa:
  fa:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xfa>, r1=<clobbered>
  fe:	3000      	movi	r0, 0	// regs: r0=0x0
 100:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_102:
 102:	1493      	pop	r4-r6, r15
loc_104:
 104:	ea000811 	movi	r0, 2065	// regs: r0=0x811
 108:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0x108>, r1=<clobbered>
 10c:	e4002200 	andi	r0, r0, 512	// regs: r0=(<ret ah_rfspi_read@0x108> & 0x200)
 110:	e900ffc7 	bez	r0, 0x9e	// if (r0 == 0x0) goto loc_9e;
 114:	07da      	br	0xc8	// goto loc_c8;
loc_116:
 116:	30fa      	movi	r0, 250	// regs: r0=0xfa
 118:	4003      	lsli	r0, r0, 3	// regs: r0=0x7d0
 11a:	e0000000 	bsr	0x0	// <delay_us>; regs: r0=<ret delay_us@0x11a>, r1=<clobbered>
 11e:	ea000811 	movi	r0, 2065	// regs: r0=0x811
 122:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0x122>, r1=<clobbered>
 126:	e4002400 	andi	r0, r0, 1024	// regs: r0=(<ret ah_rfspi_read@0x122> & 0x400)
 12a:	e920ffdb 	bnez	r0, 0xe0	// if (r0 != 0x0) goto loc_e0;
 12e:	1066      	lrw	r3, 0x0	// regs: r3=0x0
 130:	8368      	ld.b	r3, (r3, 0x8)	// regs: r3=*(0x8)
 132:	e903ffd7 	bez	r3, 0xe0	// if (r3 == 0x0) goto loc_e0;
 136:	1006      	lrw	r0, 0x0	// regs: r0=0x0
 138:	07e1      	br	0xfa	// goto loc_fa;
loc_13a:
 13a:	3000      	movi	r0, 0	// regs: r0=0x0
 13c:	2815      	subi	r0, 22	// regs: r0=0xffffffea
 13e:	07e2      	br	0x102	// goto loc_102;
 140:	fff4dc70 	.long	0xfff4dc70
 144:	00000000 	.long	0x00000000	// <module_efuse_info>
 148:	00000000 	.long	0x00000000	// <.rodata.ah_rf_lo_freq_set.str1.1>
 14c:	00000000 	.long	0x00000000	// <.rodata.ah_rf_lo_freq_set.str1.1+0x22>

Disassembly of section .text.ah_rf_lo_table_ctrl:

00000000 <ah_rf_lo_table_ctrl>: // arg_bytes: 8
   0:	14d0      	push	r15
   2:	3841      	cmpnei	r0, 1
   4:	30c2      	movi	r0, 194	// regs: r0=0xc2
   6:	4003      	lsli	r0, r0, 3	// regs: r0=0x610
   8:	080d      	bt	0x22	// if (r0 != 0x1) goto loc_22;
   a:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0xa>, r1=<clobbered>
   e:	3300      	movi	r3, 0	// regs: r3=0x0
  10:	2bff      	subi	r3, 256	// regs: r3=0xffffff00
  12:	680c      	and	r0, r3	// regs: r0=(<ret ah_rfspi_read@0xa> & 0xffffff00)
loc_14:
  14:	7441      	zexth	r1, r0	// regs: r1=zext16(r0)
  16:	30c2      	movi	r0, 194	// regs: r0=0xc2
  18:	4003      	lsli	r0, r0, 3	// regs: r0=0x610
  1a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x1a>, r1=<clobbered>
  1e:	3000      	movi	r0, 0	// regs: r0=0x0
  20:	1490      	pop	r15
loc_22:
  22:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0x22>, r1=<clobbered>
  26:	ec0000ff 	ori	r0, r0, 255	// regs: r0=(<ret ah_rfspi_read@0x22> | 0xff)
  2a:	7401      	zexth	r0, r0	// regs: r0=zext16((<ret ah_rfspi_read@0x22> | 0xff))
  2c:	07f4      	br	0x14	// goto loc_14;

Disassembly of section .text.ah_rf_lo_table_cfg:

00000000 <ah_rf_lo_table_cfg>: // arg_bytes: 8
   0:	14d6      	push	r4-r9, r15
   2:	3910      	cmphsi	r1, 17
   4:	6dc3      	mov	r7, r0	// regs: r7=<arg0>
   6:	6d87      	mov	r6, r1	// regs: r6=<arg1>
   8:	0827      	bt	0x56	// if (r1 >= 0x11) goto loc_56;
   a:	3500      	movi	r5, 0	// regs: r5=0x0
loc_c:
   c:	6594      	cmphs	r5, r6
   e:	0c03      	bf	0x14	// if (!T) goto loc_14;
  10:	3000      	movi	r0, 0	// regs: r0=0x0
loc_12:
  12:	1496      	pop	r4-r9, r15
loc_14:
  14:	d0a70880 	ldr.w	r0, (r7, r5 << 2)	// regs: r0=*(<arg0> + (r5 << 2))
  18:	e0000000 	bsr	0x0	// <ah_rf_lo_freq_set> // arg_bytes: 4; regs: r0=<ret ah_rf_lo_freq_set@0x18>, r1=<clobbered>
  1c:	e920fffb 	bnez	r0, 0x12	// if (r0 != 0x0) goto loc_12;
  20:	4584      	lsli	r4, r5, 4	// regs: r4=(r5 << 0x4)
  22:	e48404ff 	addi	r4, r4, 1280	// regs: r4=((r5 << 0x4) + 0x500)
  26:	ea08092e 	movi	r8, 2350	// regs: r8=0x92e
loc_2a:
  2a:	6c23      	mov	r0, r8	// regs: r0=r8
  2c:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0x2c>, r1=<clobbered>
  30:	6e43      	mov	r9, r0	// regs: r9=<ret ah_rfspi_read@0x2c>
  32:	e5080000 	addi	r8, r8, 1	// regs: r8=(r8 + 0x1)
  36:	6c13      	mov	r0, r4	// regs: r0=r4
  38:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0x38>, r1=<clobbered>
  3c:	7621      	zexth	r8, r8	// regs: r8=zext16((r8 + 0x1))
  3e:	6c13      	mov	r0, r4	// regs: r0=r4
  40:	6c67      	mov	r1, r9	// regs: r1=<ret ah_rfspi_read@0x2c>
  42:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x42>, r1=<clobbered>
  46:	eb480932 	cmpnei	r8, 2354
  4a:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  4c:	7511      	zexth	r4, r4	// regs: r4=zext16((r4 + 0x1))
  4e:	0bee      	bt	0x2a	// if (r8 != 0x932) goto loc_2a;
  50:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  52:	7554      	zextb	r5, r5	// regs: r5=zext8((r5 + 0x1))
  54:	07dc      	br	0xc	// goto loc_c;
loc_56:
  56:	3000      	movi	r0, 0	// regs: r0=0x0
  58:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  5a:	07dc      	br	0x12	// goto loc_12;

Disassembly of section .text.ah_rf_lo_table_kick:

00000000 <ah_rf_lo_table_kick>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	3081      	movi	r0, 129	// regs: r0=0x81
   4:	3138      	movi	r1, 56	// regs: r1=0x38
   6:	4004      	lsli	r0, r0, 4	// regs: r0=0x810
   8:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x8>, r1=<clobbered>
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15

Disassembly of section .text.override_rf_dpd_cal_iPA:

00000000 <override_rf_dpd_cal_iPA>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	3480      	movi	r4, 128	// regs: r4=0x80
   4:	4481      	lsli	r4, r4, 1	// regs: r4=0x100
   6:	3500      	movi	r5, 0	// regs: r5=0x0
   8:	10d6      	lrw	r6, 0x0	// regs: r6=0x0
loc_a:
   a:	d0a60441 	ldr.h	r1, (r6, r5 << 1)	// regs: r1=*(0x0 + (r5 << 1))
   e:	6c13      	mov	r0, r4	// regs: r0=r4
  10:	7445      	zexth	r1, r1	// regs: r1=zext16(*(0x0 + (r5 << 1)))
  12:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  14:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x14>, r1=<clobbered>
  18:	eb450022 	cmpnei	r5, 34
  1c:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  1e:	7511      	zexth	r4, r4	// regs: r4=zext16((r4 + 0x1))
  20:	0bf5      	bt	0xa	// if (r5 != 0x22) goto loc_a;
  22:	1091      	lrw	r4, 0x0	// regs: r4=0x0
  24:	3088      	movi	r0, 136	// regs: r0=0x88
  26:	8c35      	ld.h	r1, (r4, 0x2a)	// regs: r1=*(0x2a)
  28:	4003      	lsli	r0, r0, 3	// regs: r0=0x440
  2a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x2a>, r1=<clobbered>
  2e:	8c36      	ld.h	r1, (r4, 0x2c)	// regs: r1=*(0x2c)
  30:	ea000441 	movi	r0, 1089	// regs: r0=0x441
  34:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x34>, r1=<clobbered>
  38:	8c37      	ld.h	r1, (r4, 0x2e)	// regs: r1=*(0x2e)
  3a:	ea000442 	movi	r0, 1090	// regs: r0=0x442
  3e:	108b      	lrw	r4, 0x0	// regs: r4=0x0
  40:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x40>, r1=<clobbered>
  44:	30f0      	movi	r0, 240	// regs: r0=0xf0
  46:	d8241070 	ld.h	r1, (r4, 0xe0)	// regs: r1=*(0xe0)
  4a:	4003      	lsli	r0, r0, 3	// regs: r0=0x780
  4c:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x4c>, r1=<clobbered>
  50:	d8241071 	ld.h	r1, (r4, 0xe2)	// regs: r1=*(0xe2)
  54:	ea000781 	movi	r0, 1921	// regs: r0=0x781
  58:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x58>, r1=<clobbered>
  5c:	1493      	pop	r4-r6, r15
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <rf_reg_ovrd_val_dpd_switch_leakage_iPA>
  64:	00000000 	.long	0x00000000	// <rf_bw_reg_hw_val>
  68:	00000000 	.long	0x00000000	// <rf_agcbw_reg_hw_val>

Disassembly of section .text.override_rf_dpd_cal_ePA:

00000000 <override_rf_dpd_cal_ePA>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	3480      	movi	r4, 128	// regs: r4=0x80
   4:	4481      	lsli	r4, r4, 1	// regs: r4=0x100
   6:	3500      	movi	r5, 0	// regs: r5=0x0
   8:	10d6      	lrw	r6, 0x0	// regs: r6=0x0
loc_a:
   a:	d0a60441 	ldr.h	r1, (r6, r5 << 1)	// regs: r1=*(0x0 + (r5 << 1))
   e:	6c13      	mov	r0, r4	// regs: r0=r4
  10:	7445      	zexth	r1, r1	// regs: r1=zext16(*(0x0 + (r5 << 1)))
  12:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  14:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x14>, r1=<clobbered>
  18:	eb450022 	cmpnei	r5, 34
  1c:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  1e:	7511      	zexth	r4, r4	// regs: r4=zext16((r4 + 0x1))
  20:	0bf5      	bt	0xa	// if (r5 != 0x22) goto loc_a;
  22:	1091      	lrw	r4, 0x0	// regs: r4=0x0
  24:	3088      	movi	r0, 136	// regs: r0=0x88
  26:	8c35      	ld.h	r1, (r4, 0x2a)	// regs: r1=*(0x2a)
  28:	4003      	lsli	r0, r0, 3	// regs: r0=0x440
  2a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x2a>, r1=<clobbered>
  2e:	8c36      	ld.h	r1, (r4, 0x2c)	// regs: r1=*(0x2c)
  30:	ea000441 	movi	r0, 1089	// regs: r0=0x441
  34:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x34>, r1=<clobbered>
  38:	8c37      	ld.h	r1, (r4, 0x2e)	// regs: r1=*(0x2e)
  3a:	ea000442 	movi	r0, 1090	// regs: r0=0x442
  3e:	108b      	lrw	r4, 0x0	// regs: r4=0x0
  40:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x40>, r1=<clobbered>
  44:	30f0      	movi	r0, 240	// regs: r0=0xf0
  46:	d8241070 	ld.h	r1, (r4, 0xe0)	// regs: r1=*(0xe0)
  4a:	4003      	lsli	r0, r0, 3	// regs: r0=0x780
  4c:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x4c>, r1=<clobbered>
  50:	d8241071 	ld.h	r1, (r4, 0xe2)	// regs: r1=*(0xe2)
  54:	ea000781 	movi	r0, 1921	// regs: r0=0x781
  58:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x58>, r1=<clobbered>
  5c:	1493      	pop	r4-r6, r15
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <rf_reg_ovrd_val_dpd_switch_leakage_ePA>
  64:	00000000 	.long	0x00000000	// <rf_bw_reg_hw_val>
  68:	00000000 	.long	0x00000000	// <rf_agcbw_reg_hw_val>

Disassembly of section .text.override_rf_dpd_dcoc_imb_cfg_iPA:

00000000 <override_rf_dpd_dcoc_imb_cfg_iPA>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <override_rf_dpd_cal_iPA> // arg_bytes: 0; regs: r0=<ret override_rf_dpd_cal_iPA@0x2>, r1=<clobbered>
   6:	3000      	movi	r0, 0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <lmac_cfg_pa_en>; regs: r0=<ret lmac_cfg_pa_en@0x8>, r1=<clobbered>
   c:	30c0      	movi	r0, 192	// regs: r0=0xc0
   e:	ea0104e1 	movi	r1, 1249	// regs: r1=0x4e1
  12:	4002      	lsli	r0, r0, 2	// regs: r0=0x300
  14:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x14>, r1=<clobbered>
  18:	3100      	movi	r1, 0	// regs: r1=0x0
  1a:	ea000301 	movi	r0, 769	// regs: r0=0x301
  1e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x1e>, r1=<clobbered>
  22:	31c6      	movi	r1, 198	// regs: r1=0xc6
  24:	4127      	lsli	r1, r1, 7	// regs: r1=0x6300
  26:	ea000302 	movi	r0, 770	// regs: r0=0x302
  2a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x2a>, r1=<clobbered>
  2e:	ea0180c1 	movi	r1, 32961	// regs: r1=0x80c1
  32:	ea000303 	movi	r0, 771	// regs: r0=0x303
  36:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x36>, r1=<clobbered>
  3a:	30c1      	movi	r0, 193	// regs: r0=0xc1
  3c:	ea013760 	movi	r1, 14176	// regs: r1=0x3760
  40:	4002      	lsli	r0, r0, 2	// regs: r0=0x304
  42:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x42>, r1=<clobbered>
  46:	ea01620f 	movi	r1, 25103	// regs: r1=0x620f
  4a:	ea000305 	movi	r0, 773	// regs: r0=0x305
  4e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x4e>, r1=<clobbered>
  52:	ea018c99 	movi	r1, 35993	// regs: r1=0x8c99
  56:	ea000306 	movi	r0, 774	// regs: r0=0x306
  5a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x5a>, r1=<clobbered>
  5e:	ea0192ff 	movi	r1, 37631	// regs: r1=0x92ff
  62:	ea000307 	movi	r0, 775	// regs: r0=0x307
  66:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x66>, r1=<clobbered>
  6a:	30c2      	movi	r0, 194	// regs: r0=0xc2
  6c:	ea0127ff 	movi	r1, 10239	// regs: r1=0x27ff
  70:	4002      	lsli	r0, r0, 2	// regs: r0=0x308
  72:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x72>, r1=<clobbered>
  76:	ea0140f0 	movi	r1, 16624	// regs: r1=0x40f0
  7a:	ea000303 	movi	r0, 771	// regs: r0=0x303
  7e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x7e>, r1=<clobbered>
  82:	3088      	movi	r0, 136	// regs: r0=0x88
  84:	ea0101cd 	movi	r1, 461	// regs: r1=0x1cd
  88:	4003      	lsli	r0, r0, 3	// regs: r0=0x440
  8a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x8a>, r1=<clobbered>
  8e:	31c8      	movi	r1, 200	// regs: r1=0xc8
  90:	ea000442 	movi	r0, 1090	// regs: r0=0x442
  94:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x94>, r1=<clobbered>
  98:	31a0      	movi	r1, 160	// regs: r1=0xa0
  9a:	30f0      	movi	r0, 240	// regs: r0=0xf0
  9c:	4122      	lsli	r1, r1, 2	// regs: r1=0x280
  9e:	4003      	lsli	r0, r0, 3	// regs: r0=0x780
  a0:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xa0>, r1=<clobbered>
  a4:	3180      	movi	r1, 128	// regs: r1=0x80
  a6:	4127      	lsli	r1, r1, 7	// regs: r1=0x4000
  a8:	ea000781 	movi	r0, 1921	// regs: r0=0x781
  ac:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xac>, r1=<clobbered>
  b0:	1490      	pop	r15

Disassembly of section .text.override_rf_dpd_dcoc_imb_cfg_ePA:

00000000 <override_rf_dpd_dcoc_imb_cfg_ePA>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <override_rf_dpd_cal_ePA> // arg_bytes: 0; regs: r0=<ret override_rf_dpd_cal_ePA@0x2>, r1=<clobbered>
   6:	3001      	movi	r0, 1	// regs: r0=0x1
   8:	e0000000 	bsr	0x0	// <lmac_cfg_pa_en>; regs: r0=<ret lmac_cfg_pa_en@0x8>, r1=<clobbered>
   c:	30c0      	movi	r0, 192	// regs: r0=0xc0
   e:	ea0104e1 	movi	r1, 1249	// regs: r1=0x4e1
  12:	4002      	lsli	r0, r0, 2	// regs: r0=0x300
  14:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x14>, r1=<clobbered>
  18:	3100      	movi	r1, 0	// regs: r1=0x0
  1a:	ea000301 	movi	r0, 769	// regs: r0=0x301
  1e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x1e>, r1=<clobbered>
  22:	31c6      	movi	r1, 198	// regs: r1=0xc6
  24:	4127      	lsli	r1, r1, 7	// regs: r1=0x6300
  26:	ea000302 	movi	r0, 770	// regs: r0=0x302
  2a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x2a>, r1=<clobbered>
  2e:	ea0180f0 	movi	r1, 33008	// regs: r1=0x80f0
  32:	ea000303 	movi	r0, 771	// regs: r0=0x303
  36:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x36>, r1=<clobbered>
  3a:	30c1      	movi	r0, 193	// regs: r0=0xc1
  3c:	ea014b60 	movi	r1, 19296	// regs: r1=0x4b60
  40:	4002      	lsli	r0, r0, 2	// regs: r0=0x304
  42:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x42>, r1=<clobbered>
  46:	ea016201 	movi	r1, 25089	// regs: r1=0x6201
  4a:	ea000305 	movi	r0, 773	// regs: r0=0x305
  4e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x4e>, r1=<clobbered>
  52:	ea018c99 	movi	r1, 35993	// regs: r1=0x8c99
  56:	ea000306 	movi	r0, 774	// regs: r0=0x306
  5a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x5a>, r1=<clobbered>
  5e:	ea01baed 	movi	r1, 47853	// regs: r1=0xbaed
  62:	ea000307 	movi	r0, 775	// regs: r0=0x307
  66:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x66>, r1=<clobbered>
  6a:	30c2      	movi	r0, 194	// regs: r0=0xc2
  6c:	ea0127ff 	movi	r1, 10239	// regs: r1=0x27ff
  70:	4002      	lsli	r0, r0, 2	// regs: r0=0x308
  72:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x72>, r1=<clobbered>
  76:	3088      	movi	r0, 136	// regs: r0=0x88
  78:	ea0101cd 	movi	r1, 461	// regs: r1=0x1cd
  7c:	4003      	lsli	r0, r0, 3	// regs: r0=0x440
  7e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x7e>, r1=<clobbered>
  82:	31c8      	movi	r1, 200	// regs: r1=0xc8
  84:	ea000442 	movi	r0, 1090	// regs: r0=0x442
  88:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x88>, r1=<clobbered>
  8c:	31a0      	movi	r1, 160	// regs: r1=0xa0
  8e:	30f0      	movi	r0, 240	// regs: r0=0xf0
  90:	4122      	lsli	r1, r1, 2	// regs: r1=0x280
  92:	4003      	lsli	r0, r0, 3	// regs: r0=0x780
  94:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x94>, r1=<clobbered>
  98:	3180      	movi	r1, 128	// regs: r1=0x80
  9a:	4127      	lsli	r1, r1, 7	// regs: r1=0x4000
  9c:	ea000781 	movi	r0, 1921	// regs: r0=0x781
  a0:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xa0>, r1=<clobbered>
  a4:	1490      	pop	r15

Disassembly of section .text.override_rf_tx_dcoc_cal_inner_path:

00000000 <override_rf_tx_dcoc_cal_inner_path>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	3480      	movi	r4, 128	// regs: r4=0x80
   4:	4481      	lsli	r4, r4, 1	// regs: r4=0x100
   6:	3500      	movi	r5, 0	// regs: r5=0x0
   8:	10d6      	lrw	r6, 0x0	// regs: r6=0x0
loc_a:
   a:	d0a60441 	ldr.h	r1, (r6, r5 << 1)	// regs: r1=*(0x0 + (r5 << 1))
   e:	6c13      	mov	r0, r4	// regs: r0=r4
  10:	7445      	zexth	r1, r1	// regs: r1=zext16(*(0x0 + (r5 << 1)))
  12:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  14:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x14>, r1=<clobbered>
  18:	eb450022 	cmpnei	r5, 34
  1c:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  1e:	7511      	zexth	r4, r4	// regs: r4=zext16((r4 + 0x1))
  20:	0bf5      	bt	0xa	// if (r5 != 0x22) goto loc_a;
  22:	1091      	lrw	r4, 0x0	// regs: r4=0x0
  24:	3088      	movi	r0, 136	// regs: r0=0x88
  26:	8c35      	ld.h	r1, (r4, 0x2a)	// regs: r1=*(0x2a)
  28:	4003      	lsli	r0, r0, 3	// regs: r0=0x440
  2a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x2a>, r1=<clobbered>
  2e:	8c36      	ld.h	r1, (r4, 0x2c)	// regs: r1=*(0x2c)
  30:	ea000441 	movi	r0, 1089	// regs: r0=0x441
  34:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x34>, r1=<clobbered>
  38:	8c37      	ld.h	r1, (r4, 0x2e)	// regs: r1=*(0x2e)
  3a:	ea000442 	movi	r0, 1090	// regs: r0=0x442
  3e:	108b      	lrw	r4, 0x0	// regs: r4=0x0
  40:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x40>, r1=<clobbered>
  44:	30f0      	movi	r0, 240	// regs: r0=0xf0
  46:	d8241070 	ld.h	r1, (r4, 0xe0)	// regs: r1=*(0xe0)
  4a:	4003      	lsli	r0, r0, 3	// regs: r0=0x780
  4c:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x4c>, r1=<clobbered>
  50:	d8241071 	ld.h	r1, (r4, 0xe2)	// regs: r1=*(0xe2)
  54:	ea000781 	movi	r0, 1921	// regs: r0=0x781
  58:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x58>, r1=<clobbered>
  5c:	1493      	pop	r4-r6, r15
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <rf_reg_ovrd_val_tx_dcoc>
  64:	00000000 	.long	0x00000000	// <rf_bw_reg_hw_val>
  68:	00000000 	.long	0x00000000	// <rf_agcbw_reg_hw_val>

Disassembly of section .text.ah_rf_rx_dcoc_calib:

00000000 <ah_rf_rx_dcoc_calib>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	1425      	subi	r14, r14, 20	// regs: r14=(sp - 0x14)
   4:	e0000000 	bsr	0x0	// <lmac_rf_sw_ctrl>; regs: r0=<ret lmac_rf_sw_ctrl@0x4>, r1=<clobbered>
   8:	3480      	movi	r4, 128	// regs: r4=0x80
   a:	3000      	movi	r0, 0	// regs: r0=0x0
   c:	e0000000 	bsr	0x0	// <lmac_cfg_pa_en>; regs: r0=<ret lmac_cfg_pa_en@0xc>, r1=<clobbered>
  10:	4481      	lsli	r4, r4, 1	// regs: r4=0x100
  12:	3500      	movi	r5, 0	// regs: r5=0x0
  14:	12d4      	lrw	r6, 0x0	// regs: r6=0x0
loc_16:
  16:	d0a60441 	ldr.h	r1, (r6, r5 << 1)	// regs: r1=*(0x0 + (r5 << 1))
  1a:	6c13      	mov	r0, r4	// regs: r0=r4
  1c:	7445      	zexth	r1, r1	// regs: r1=zext16(*(0x0 + (r5 << 1)))
  1e:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  20:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x20>, r1=<clobbered>
  24:	eb450022 	cmpnei	r5, 34
  28:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  2a:	7511      	zexth	r4, r4	// regs: r4=zext16((r4 + 0x1))
  2c:	0bf5      	bt	0x16	// if (r5 != 0x22) goto loc_16;
  2e:	3001      	movi	r0, 1	// regs: r0=0x1
  30:	e0000000 	bsr	0x0	// <lmac_cfg_rx_en>; regs: r0=<ret lmac_cfg_rx_en@0x30>, r1=<clobbered>
  34:	3000      	movi	r0, 0	// regs: r0=0x0
  36:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0x36>, r1=<clobbered>
  3a:	12ac      	lrw	r5, 0x0	// regs: r5=0x0
  3c:	ea89004c 	lrw	r9, 0x0	// regs: r9=0x0
  40:	ea0a0000 	movi	r10, 0	// regs: r10=0x0
  44:	3603      	movi	r6, 3	// regs: r6=0x3
loc_46:
  46:	3088      	movi	r0, 136	// regs: r0=0x88
  48:	8d20      	ld.h	r1, (r5, 0x0)	// regs: r1=*(r5)
  4a:	4003      	lsli	r0, r0, 3	// regs: r0=0x440
  4c:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x4c>, r1=<clobbered>
  50:	8d21      	ld.h	r1, (r5, 0x2)	// regs: r1=*(r5 + 0x2)
  52:	ea000441 	movi	r0, 1089	// regs: r0=0x441
  56:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x56>, r1=<clobbered>
  5a:	8d22      	ld.h	r1, (r5, 0x4)	// regs: r1=*(r5 + 0x4)
  5c:	ea000442 	movi	r0, 1090	// regs: r0=0x442
  60:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x60>, r1=<clobbered>
  64:	1263      	lrw	r3, 0x0	// regs: r3=0x0
  66:	c46a0028 	addu	r8, r10, r3	// regs: r8=(r10 )
  6a:	6de7      	mov	r7, r9	// regs: r7=r9
  6c:	ea0b0005 	movi	r11, 5	// regs: r11=0x5
  70:	7518      	zextb	r4, r6	// regs: r4=zext8(r6)
  72:	045c      	br	0x12a	// goto loc_12a;
loc_74:
  74:	8a20      	ld.h	r1, (r2, 0x0)	// regs: r1=*(r2)
  76:	6c0f      	mov	r0, r3	// regs: r0=r3
  78:	b842      	st.w	r2, (r14, 0x8)	// stack_p8 = r2
  7a:	b861      	st.w	r3, (r14, 0x4)	// stack_p4 = r3
  7c:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x7c>, r1=<clobbered>
  80:	9861      	ld.w	r3, (r14, 0x4)	// regs: r3=stack_p4
  82:	2300      	addi	r3, 1	// regs: r3=(stack_p4 + 0x1)
  84:	74cd      	zexth	r3, r3	// regs: r3=zext16((stack_p4 + 0x1))
  86:	eb430304 	cmpnei	r3, 772
  8a:	9842      	ld.w	r2, (r14, 0x8)	// regs: r2=stack_p8
  8c:	2201      	addi	r2, 2	// regs: r2=(stack_p8 + 0x2)
  8e:	0bf3      	bt	0x74	// if (r3 != 0x304) goto loc_74;
  90:	e4681001 	subi	r3, r8, 2	// regs: r3=(r8 - 0x2)
  94:	30f0      	movi	r0, 240	// regs: r0=0xf0
  96:	8b20      	ld.h	r1, (r3, 0x0)	// regs: r1=*(r8 - 0x2)
  98:	4003      	lsli	r0, r0, 3	// regs: r0=0x780
  9a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x9a>, r1=<clobbered>
  9e:	d8281000 	ld.h	r1, (r8, 0x0)	// regs: r1=*(r8)
  a2:	ea000781 	movi	r0, 1921	// regs: r0=0x781
  a6:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xa6>, r1=<clobbered>
  aa:	3000      	movi	r0, 0	// regs: r0=0x0
  ac:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_gain_idx_src>; regs: r0=<ret ah_rfdigicali_config_rx_gain_idx_src@0xac>, r1=<clobbered>
  b0:	776c      	zextb	r13, r11	// regs: r13=zext8(r11)
  b2:	6c37      	mov	r0, r13	// regs: r0=zext8(r11)
  b4:	6c53      	mov	r1, r4	// regs: r1=r4
  b6:	ddae2001 	st.w	r13, (r14, 0x4)	// stack_p4 = zext8(r11)
  ba:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_gain>; regs: r0=<ret ah_rfdigicali_config_rx_gain@0xba>, r1=<clobbered>
  be:	6c13      	mov	r0, r4	// regs: r0=r4
  c0:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_filter>; regs: r0=<ret ah_rfdigicali_config_rx_filter@0xc0>, r1=<clobbered>
  c4:	3201      	movi	r2, 1	// regs: r2=0x1
  c6:	6c5b      	mov	r1, r6	// regs: r1=r6
  c8:	9800      	ld.w	r0, (r14, 0x0)	// regs: r0=stack_0
  ca:	e0000000 	bsr	0x0	// <rx_dcoc_ana_calib> // arg_bytes: 12; regs: r0=<ret rx_dcoc_ana_calib@0xca>, r1=<clobbered>
  ce:	1803      	addi	r0, r14, 12	// regs: r0=(sp + 0xc)
  d0:	e0000000 	bsr	0x0	// <rfdigcal_rx_dcoc_calib> // arg_bytes: 4; regs: r0=<ret rfdigcal_rx_dcoc_calib@0xd0>, r1=<clobbered>
  d4:	d9ae2001 	ld.w	r13, (r14, 0x4)	// regs: r13=stack_p4
  d8:	6c77      	mov	r1, r13	// regs: r1=stack_p4
  da:	6c93      	mov	r2, r4	// regs: r2=r4
  dc:	1804      	addi	r0, r14, 16	// regs: r0=(sp + 0x10)
  de:	ddae2000 	st.w	r13, (r14, 0x0)	// stack_0 = stack_p4
  e2:	e0000000 	bsr	0x0	// <ah_rfdigicali_get_rx_dcoc>; regs: r0=<ret ah_rfdigicali_get_rx_dcoc@0xe2>, r1=<clobbered>
  e6:	d86e1006 	ld.h	r3, (r14, 0xc)	// regs: r3=stack_pc
  ea:	d84e1008 	ld.h	r2, (r14, 0x10)	// regs: r2=stack_p10
  ee:	d82e1007 	ld.h	r1, (r14, 0xe)	// regs: r1=stack_pe
  f2:	608c      	addu	r2, r3	// regs: r2=(stack_p10 + stack_pc)
  f4:	d86e1009 	ld.h	r3, (r14, 0x12)	// regs: r3=stack_p12
  f8:	60c4      	addu	r3, r1	// regs: r3=(stack_p12 + stack_pe)
  fa:	74cf      	sexth	r3, r3	// regs: r3=sext16((stack_p12 + stack_pe))
  fc:	748b      	sexth	r2, r2	// regs: r2=sext16((stack_p10 + stack_pc))
  fe:	d9ae2000 	ld.w	r13, (r14, 0x0)	// regs: r13=stack_0
 102:	af40      	st.h	r2, (r7, 0x0)	// *(r7) = sext16((stack_p10 + stack_pc))
 104:	af61      	st.h	r3, (r7, 0x2)	// *(r7 + 0x2) = sext16((stack_p12 + stack_pe))
 106:	dc4e1006 	st.h	r2, (r14, 0xc)	// stack_pc = sext16((stack_p10 + stack_pc))
 10a:	6c77      	mov	r1, r13	// regs: r1=stack_0
 10c:	6c93      	mov	r2, r4	// regs: r2=r4
 10e:	1803      	addi	r0, r14, 12	// regs: r0=(sp + 0xc)
 110:	dc6e1007 	st.h	r3, (r14, 0xe)	// stack_pe = sext16((stack_p12 + stack_pe))
 114:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_dcoc>; regs: r0=<ret ah_rfdigicali_config_rx_dcoc@0x114>, r1=<clobbered>
 118:	3300      	movi	r3, 0	// regs: r3=0x0
 11a:	e56b1000 	subi	r11, r11, 1	// regs: r11=(r11 - 0x1)
 11e:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 120:	64ee      	cmpne	r11, r3
 122:	2f03      	subi	r7, 4	// regs: r7=(r7 - 0x4)
 124:	e5081003 	subi	r8, r8, 4	// regs: r8=(r8 - 0x4)
 128:	0c0a      	bf	0x13c	// if (!T) goto loc_13c;
loc_12a:
 12a:	74ee      	sextb	r3, r11	// regs: r3=sext8(r11)
 12c:	3212      	movi	r2, 18	// regs: r2=0x12
 12e:	b860      	st.w	r3, (r14, 0x0)	// stack_0 = sext8(r11)
 130:	7cac      	mult	r2, r11	// regs: r2=(0x12 * r11)
 132:	1071      	lrw	r3, 0x0	// regs: r3=0x0
 134:	608c      	addu	r2, r3	// regs: r2=((0x12 * r11) )
 136:	33c0      	movi	r3, 192	// regs: r3=0xc0
 138:	4362      	lsli	r3, r3, 2	// regs: r3=0x300
 13a:	079d      	br	0x74	// goto loc_74;
loc_13c:
 13c:	2c00      	subi	r4, 1	// regs: r4=(r4 - 0x1)
 13e:	7592      	sextb	r6, r4	// regs: r6=sext8((r4 - 0x1))
 140:	66da      	cmpne	r6, r11
 142:	2d05      	subi	r5, 6	// regs: r5=(r5 - 0x6)
 144:	e5291017 	subi	r9, r9, 24	// regs: r9=(r9 - 0x18)
 148:	e54a101f 	subi	r10, r10, 32	// regs: r10=(r10 - 0x20)
 14c:	0b7d      	bt	0x46	// if (T) goto loc_46;
 14e:	3103      	movi	r1, 3	// regs: r1=0x3
 150:	3005      	movi	r0, 5	// regs: r0=0x5
 152:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_gain>; regs: r0=<ret ah_rfdigicali_config_rx_gain@0x152>, r1=<clobbered>
 156:	3000      	movi	r0, 0	// regs: r0=0x0
 158:	e0000000 	bsr	0x0	// <lmac_cfg_rx_en>; regs: r0=<ret lmac_cfg_rx_en@0x158>, r1=<clobbered>
 15c:	3000      	movi	r0, 0	// regs: r0=0x0
 15e:	1405      	addi	r14, r14, 20	// regs: r14=(sp + 0x14)
 160:	1498      	pop	r4-r11, r15
 162:	0000      	.short	0x0000
 164:	00000000 	.long	0x00000000	// <rf_reg_ovrd_val_rx_dcoc>
 168:	00000000 	.long	0x00000000	// <rf_bw_reg_hw_val+0x12>
 16c:	00000000 	.long	0x00000000	// <rx_dcoc_res+0x5c>
 170:	00000000 	.long	0x00000000	// <rf_agcbw_reg_hw_val+0x76>
 174:	00000000 	.long	0x00000000	// <rf_agc_reg_hw_val>

Disassembly of section .text.ah_rf_tx_imb_calib:

00000000 <ah_rf_tx_imb_calib>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	3480      	movi	r4, 128	// regs: r4=0x80
   6:	4481      	lsli	r4, r4, 1	// regs: r4=0x100
   8:	3500      	movi	r5, 0	// regs: r5=0x0
   a:	13d4      	lrw	r6, 0x0	// regs: r6=0x0
loc_c:
   c:	d0a60441 	ldr.h	r1, (r6, r5 << 1)	// regs: r1=*(0x0 + (r5 << 1))
  10:	6c13      	mov	r0, r4	// regs: r0=r4
  12:	7445      	zexth	r1, r1	// regs: r1=zext16(*(0x0 + (r5 << 1)))
  14:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  16:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x16>, r1=<clobbered>
  1a:	eb450022 	cmpnei	r5, 34
  1e:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  20:	7511      	zexth	r4, r4	// regs: r4=zext16((r4 + 0x1))
  22:	0bf5      	bt	0xc	// if (r5 != 0x22) goto loc_c;
  24:	138e      	lrw	r4, 0x0	// regs: r4=0x0
  26:	3088      	movi	r0, 136	// regs: r0=0x88
  28:	8c35      	ld.h	r1, (r4, 0x2a)	// regs: r1=*(0x2a)
  2a:	4003      	lsli	r0, r0, 3	// regs: r0=0x440
  2c:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x2c>, r1=<clobbered>
  30:	8c36      	ld.h	r1, (r4, 0x2c)	// regs: r1=*(0x2c)
  32:	ea000441 	movi	r0, 1089	// regs: r0=0x441
  36:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x36>, r1=<clobbered>
  3a:	8c37      	ld.h	r1, (r4, 0x2e)	// regs: r1=*(0x2e)
  3c:	ea000442 	movi	r0, 1090	// regs: r0=0x442
  40:	1388      	lrw	r4, 0x0	// regs: r4=0x0
  42:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x42>, r1=<clobbered>
  46:	30f0      	movi	r0, 240	// regs: r0=0xf0
  48:	d8241070 	ld.h	r1, (r4, 0xe0)	// regs: r1=*(0xe0)
  4c:	4003      	lsli	r0, r0, 3	// regs: r0=0x780
  4e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x4e>, r1=<clobbered>
  52:	d8241071 	ld.h	r1, (r4, 0xe2)	// regs: r1=*(0xe2)
  56:	ea000781 	movi	r0, 1921	// regs: r0=0x781
  5a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x5a>, r1=<clobbered>
  5e:	e0000000 	bsr	0x0	// <lmac_rf_sw_ctrl>; regs: r0=<ret lmac_rf_sw_ctrl@0x5e>, r1=<clobbered>
  62:	3001      	movi	r0, 1	// regs: r0=0x1
  64:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0x64>, r1=<clobbered>
  68:	3000      	movi	r0, 0	// regs: r0=0x0
  6a:	e0000000 	bsr	0x0	// <lmac_cfg_rx_en>; regs: r0=<ret lmac_cfg_rx_en@0x6a>, r1=<clobbered>
  6e:	3000      	movi	r0, 0	// regs: r0=0x0
  70:	e0000000 	bsr	0x0	// <lmac_cfg_pa_en>; regs: r0=<ret lmac_cfg_pa_en@0x70>, r1=<clobbered>
  74:	319c      	movi	r1, 156	// regs: r1=0x9c
  76:	30c0      	movi	r0, 192	// regs: r0=0xc0
  78:	4123      	lsli	r1, r1, 3	// regs: r1=0x4e0
  7a:	4002      	lsli	r0, r0, 2	// regs: r0=0x300
  7c:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x7c>, r1=<clobbered>
  80:	3100      	movi	r1, 0	// regs: r1=0x0
  82:	ea000301 	movi	r0, 769	// regs: r0=0x301
  86:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x86>, r1=<clobbered>
  8a:	ea014338 	movi	r1, 17208	// regs: r1=0x4338
  8e:	ea000302 	movi	r0, 770	// regs: r0=0x302
  92:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x92>, r1=<clobbered>
  96:	ea01d8cf 	movi	r1, 55503	// regs: r1=0xd8cf
  9a:	ea000303 	movi	r0, 771	// regs: r0=0x303
  9e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x9e>, r1=<clobbered>
  a2:	30c1      	movi	r0, 193	// regs: r0=0xc1
  a4:	ea014b60 	movi	r1, 19296	// regs: r1=0x4b60
  a8:	4002      	lsli	r0, r0, 2	// regs: r0=0x304
  aa:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xaa>, r1=<clobbered>
  ae:	ea016201 	movi	r1, 25089	// regs: r1=0x6201
  b2:	ea000305 	movi	r0, 773	// regs: r0=0x305
  b6:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xb6>, r1=<clobbered>
  ba:	ea018c99 	movi	r1, 35993	// regs: r1=0x8c99
  be:	ea000306 	movi	r0, 774	// regs: r0=0x306
  c2:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xc2>, r1=<clobbered>
  c6:	ea01baed 	movi	r1, 47853	// regs: r1=0xbaed
  ca:	ea000307 	movi	r0, 775	// regs: r0=0x307
  ce:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xce>, r1=<clobbered>
  d2:	30c2      	movi	r0, 194	// regs: r0=0xc2
  d4:	ea0127ff 	movi	r1, 10239	// regs: r1=0x27ff
  d8:	4002      	lsli	r0, r0, 2	// regs: r0=0x308
  da:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xda>, r1=<clobbered>
  de:	e0000000 	bsr	0x0	// <tx_dcoc_rx_path_dcoc_cal.constprop.0> // arg_bytes: 0; regs: r0=<ret tx_dcoc_rx_path_dcoc_cal.constprop.0@0xde>, r1=<clobbered>
  e2:	30a0      	movi	r0, 160	// regs: r0=0xa0
  e4:	3105      	movi	r1, 5	// regs: r1=0x5
  e6:	4003      	lsli	r0, r0, 3	// regs: r0=0x500
  e8:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0xe8>, r1=<clobbered>
  ec:	e0000000 	bsr	0x0	// <ah_rfdigicali_dcoc_est_en>; regs: r0=<ret ah_rfdigicali_dcoc_est_en@0xec>, r1=<clobbered>
  f0:	35e0      	movi	r5, 224	// regs: r5=0xe0
  f2:	e0000000 	bsr	0x0	// <ah_rfdigicali_dcoc_imb_est_kick_start>; regs: r0=<ret ah_rfdigicali_dcoc_imb_est_kick_start@0xf2>, r1=<clobbered>
  f6:	3600      	movi	r6, 0	// regs: r6=0x0
  f8:	3002      	movi	r0, 2	// regs: r0=0x2
  fa:	45a3      	lsli	r5, r5, 3	// regs: r5=0x700
  fc:	e0000000 	bsr	0x0	// <os_sleep_ms>; regs: r0=<ret os_sleep_ms@0xfc>, r1=<clobbered>
 100:	c7c05028 	bmaski	r8, 31
 104:	2e77      	subi	r6, 120	// regs: r6=0xffffff88
 106:	6e57      	mov	r9, r5	// regs: r9=0x700
loc_108:
 108:	3400      	movi	r4, 0	// regs: r4=0x0
 10a:	2c77      	subi	r4, 120	// regs: r4=0xffffff88
 10c:	75e5      	zexth	r7, r9	// regs: r7=zext16(r9)
loc_10e:
 10e:	3205      	movi	r2, 5	// regs: r2=0x5
 110:	6c5f      	mov	r1, r7	// regs: r1=r7
 112:	6c13      	mov	r0, r4	// regs: r0=r4
 114:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_imb>; regs: r0=<ret ah_rfdigicali_config_tx_imb@0x114>, r1=<clobbered>
 118:	300a      	movi	r0, 10	// regs: r0=0xa
 11a:	e0000000 	bsr	0x0	// <os_sleep_us>; regs: r0=<ret os_sleep_us@0x11a>, r1=<clobbered>
 11e:	e0000000 	bsr	0x0	// <ah_rfdigicali_power_calc_kick_start>; regs: r0=<ret ah_rfdigicali_power_calc_kick_start@0x11e>, r1=<clobbered>
 122:	6e83      	mov	r10, r0	// regs: r10=<ret ah_rfdigicali_power_calc_kick_start@0x11e>
 124:	300a      	movi	r0, 10	// regs: r0=0xa
 126:	e0000000 	bsr	0x0	// <os_sleep_us>; regs: r0=<ret os_sleep_us@0x126>, r1=<clobbered>
 12a:	6629      	cmplt	r10, r8
 12c:	0c04      	bf	0x134	// if (!T) goto loc_134;
 12e:	6d93      	mov	r6, r4	// regs: r6=r4
 130:	6d67      	mov	r5, r9	// regs: r5=r9
 132:	6e2b      	mov	r8, r10	// regs: r8=<ret ah_rfdigicali_power_calc_kick_start@0x11e>
loc_134:
 134:	240f      	addi	r4, 16	// regs: r4=(r4 + 0x10)
 136:	7513      	sexth	r4, r4	// regs: r4=sext16((r4 + 0x10))
 138:	eb440088 	cmpnei	r4, 136
 13c:	0be9      	bt	0x10e	// if (r4 != 0x88) goto loc_10e;
 13e:	270f      	addi	r7, 16	// regs: r7=(r7 + 0x10)
 140:	75dd      	zexth	r7, r7	// regs: r7=zext16((r7 + 0x10))
 142:	eb470910 	cmpnei	r7, 2320
 146:	765f      	sexth	r9, r7	// regs: r9=sext16(zext16((r7 + 0x10)))
 148:	0be0      	bt	0x108	// if (r7 != 0x910) goto loc_108;
 14a:	74d5      	zexth	r3, r5	// regs: r3=zext16(r5)
 14c:	e483100f 	subi	r4, r3, 16	// regs: r4=(zext16(r5) - 0x10)
 150:	230f      	addi	r3, 16	// regs: r3=(zext16(r5) + 0x10)
 152:	768f      	sexth	r10, r3	// regs: r10=sext16((zext16(r5) + 0x10))
 154:	74d9      	zexth	r3, r6	// regs: r3=zext16(r6)
 156:	e563100f 	subi	r11, r3, 16	// regs: r11=(zext16(r6) - 0x10)
 15a:	230f      	addi	r3, 16	// regs: r3=(zext16(r6) + 0x10)
 15c:	7513      	sexth	r4, r4	// regs: r4=sext16((zext16(r5) - 0x10))
 15e:	76ef      	sexth	r11, r11	// regs: r11=sext16((zext16(r6) - 0x10))
 160:	764f      	sexth	r9, r3	// regs: r9=sext16((zext16(r6) + 0x10))
loc_162:
 162:	6529      	cmplt	r10, r4
 164:	0823      	bt	0x1aa	// if (T) goto loc_1aa;
 166:	6def      	mov	r7, r11	// regs: r7=r11
 168:	7711      	zexth	r12, r4	// regs: r12=zext16(r4)
 16a:	041b      	br	0x1a0	// goto loc_1a0;
loc_16c:
 16c:	6c73      	mov	r1, r12	// regs: r1=r12
 16e:	3205      	movi	r2, 5	// regs: r2=0x5
 170:	6c1f      	mov	r0, r7	// regs: r0=r7
 172:	dd8e2001 	st.w	r12, (r14, 0x4)	// stack_p4 = r12
 176:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_imb>; regs: r0=<ret ah_rfdigicali_config_tx_imb@0x176>, r1=<clobbered>
 17a:	300a      	movi	r0, 10	// regs: r0=0xa
 17c:	e0000000 	bsr	0x0	// <os_sleep_us>; regs: r0=<ret os_sleep_us@0x17c>, r1=<clobbered>
 180:	e0000000 	bsr	0x0	// <ah_rfdigicali_power_calc_kick_start>; regs: r0=<ret ah_rfdigicali_power_calc_kick_start@0x180>, r1=<clobbered>
 184:	b800      	st.w	r0, (r14, 0x0)	// stack_0 = <ret ah_rfdigicali_power_calc_kick_start@0x180>
 186:	300a      	movi	r0, 10	// regs: r0=0xa
 188:	e0000000 	bsr	0x0	// <os_sleep_us>; regs: r0=<ret os_sleep_us@0x188>, r1=<clobbered>
 18c:	9860      	ld.w	r3, (r14, 0x0)	// regs: r3=stack_0
 18e:	660d      	cmplt	r3, r8
 190:	d98e2001 	ld.w	r12, (r14, 0x4)	// regs: r12=stack_p4
 194:	0c04      	bf	0x19c	// if (!T) goto loc_19c;
 196:	6d9f      	mov	r6, r7	// regs: r6=r7
 198:	6d53      	mov	r5, r4	// regs: r5=r4
 19a:	6e0f      	mov	r8, r3	// regs: r8=stack_0
loc_19c:
 19c:	2700      	addi	r7, 1	// regs: r7=(r7 + 0x1)
 19e:	75df      	sexth	r7, r7	// regs: r7=sext16((r7 + 0x1))
loc_1a0:
 1a0:	65e5      	cmplt	r9, r7
 1a2:	0fe5      	bf	0x16c	// if (!T) goto loc_16c;
 1a4:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
 1a6:	7513      	sexth	r4, r4	// regs: r4=sext16((r4 + 0x1))
 1a8:	07dd      	br	0x162	// goto loc_162;
loc_1aa:
 1aa:	e0000000 	bsr	0x0	// <ah_rfdigicali_stop_tx_cali>; regs: r0=<ret ah_rfdigicali_stop_tx_cali@0x1aa>, r1=<clobbered>
 1ae:	106e      	lrw	r3, 0x0	// regs: r3=0x0
 1b0:	3205      	movi	r2, 5	// regs: r2=0x5
 1b2:	aba0      	st.h	r5, (r3, 0x0)	// *(0x0) = r5
 1b4:	7455      	zexth	r1, r5	// regs: r1=zext16(r5)
 1b6:	106d      	lrw	r3, 0x0	// regs: r3=0x0
 1b8:	6c1b      	mov	r0, r6	// regs: r0=r6
 1ba:	abc0      	st.h	r6, (r3, 0x0)	// *(0x0) = r6
 1bc:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_imb>; regs: r0=<ret ah_rfdigicali_config_tx_imb@0x1bc>, r1=<clobbered>
 1c0:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x1c0>, r1=<clobbered>
 1c4:	3000      	movi	r0, 0	// regs: r0=0x0
 1c6:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0x1c6>, r1=<clobbered>
 1ca:	3000      	movi	r0, 0	// regs: r0=0x0
 1cc:	e0000000 	bsr	0x0	// <lmac_cfg_pa_en>; regs: r0=<ret lmac_cfg_pa_en@0x1cc>, r1=<clobbered>
 1d0:	3000      	movi	r0, 0	// regs: r0=0x0
 1d2:	1402      	addi	r14, r14, 8	// regs: r14=(sp + 0x8)
 1d4:	1498      	pop	r4-r11, r15
 1d6:	0000      	.short	0x0000
 1d8:	00000000 	.long	0x00000000	// <rf_reg_ovrd_val_tx_imb>
 1dc:	00000000 	.long	0x00000000	// <rf_bw_reg_hw_val>
 1e0:	00000000 	.long	0x00000000	// <rf_agcbw_reg_hw_val>
 1e4:	00000000 	.long	0x00000000	// <tx_epa_imb_res_gm>
 1e8:	00000000 	.long	0x00000000	// <tx_epa_imb_res_pm>

Disassembly of section .text.ah_rf_tx_dcoc_calib:

00000000 <ah_rf_tx_dcoc_calib>: // arg_bytes: 0
   0:	14d5      	push	r4-r8, r15
   2:	1423      	subi	r14, r14, 12	// regs: r14=(sp - 0xc)
   4:	1343      	lrw	r2, 0x40026000	// regs: r2=0x40026000
   6:	3400      	movi	r4, 0	// regs: r4=0x0
   8:	9275      	ld.w	r3, (r2, 0x54)	// regs: r3=*(0x40026054)
   a:	ec630200 	ori	r3, r3, 512	// regs: r3=(*(0x40026054) | 0x200)
   e:	b275      	st.w	r3, (r2, 0x54)	// *(0x40026054) = (*(0x40026054) | 0x200)
  10:	e0000000 	bsr	0x0	// <lmac_rf_sw_ctrl>; regs: r0=<ret lmac_rf_sw_ctrl@0x10>, r1=<clobbered>
  14:	3000      	movi	r0, 0	// regs: r0=0x0
  16:	e0000000 	bsr	0x0	// <lmac_cfg_rx_en>; regs: r0=<ret lmac_cfg_rx_en@0x16>, r1=<clobbered>
  1a:	3001      	movi	r0, 1	// regs: r0=0x1
  1c:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0x1c>, r1=<clobbered>
  20:	e0000000 	bsr	0x0	// <override_rf_tx_dcoc_cal_inner_path> // arg_bytes: 0; regs: r0=<ret override_rf_tx_dcoc_cal_inner_path@0x20>, r1=<clobbered>
  24:	319c      	movi	r1, 156	// regs: r1=0x9c
  26:	30c0      	movi	r0, 192	// regs: r0=0xc0
  28:	4123      	lsli	r1, r1, 3	// regs: r1=0x4e0
  2a:	4002      	lsli	r0, r0, 2	// regs: r0=0x300
  2c:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x2c>, r1=<clobbered>
  30:	3100      	movi	r1, 0	// regs: r1=0x0
  32:	ea000301 	movi	r0, 769	// regs: r0=0x301
  36:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x36>, r1=<clobbered>
  3a:	ea016338 	movi	r1, 25400	// regs: r1=0x6338
  3e:	ea000302 	movi	r0, 770	// regs: r0=0x302
  42:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x42>, r1=<clobbered>
  46:	ea01d8cf 	movi	r1, 55503	// regs: r1=0xd8cf
  4a:	ea000303 	movi	r0, 771	// regs: r0=0x303
  4e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x4e>, r1=<clobbered>
  52:	30c1      	movi	r0, 193	// regs: r0=0xc1
  54:	ea013760 	movi	r1, 14176	// regs: r1=0x3760
  58:	4002      	lsli	r0, r0, 2	// regs: r0=0x304
  5a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x5a>, r1=<clobbered>
  5e:	ea01620f 	movi	r1, 25103	// regs: r1=0x620f
  62:	ea000305 	movi	r0, 773	// regs: r0=0x305
  66:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x66>, r1=<clobbered>
  6a:	ea018c99 	movi	r1, 35993	// regs: r1=0x8c99
  6e:	ea000306 	movi	r0, 774	// regs: r0=0x306
  72:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x72>, r1=<clobbered>
  76:	ea0192ff 	movi	r1, 37631	// regs: r1=0x92ff
  7a:	ea000307 	movi	r0, 775	// regs: r0=0x307
  7e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x7e>, r1=<clobbered>
  82:	30c2      	movi	r0, 194	// regs: r0=0xc2
  84:	ea0127ff 	movi	r1, 10239	// regs: r1=0x27ff
  88:	4002      	lsli	r0, r0, 2	// regs: r0=0x308
  8a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x8a>, r1=<clobbered>
  8e:	ea000119 	movi	r0, 281	// regs: r0=0x119
  92:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0x92>, r1=<clobbered>
  96:	ea03b7ff 	movi	r3, 47103	// regs: r3=0xb7ff
  9a:	c4602021 	and	r1, r0, r3	// regs: r1=(<ret ah_rfspi_read@0x92> & 0xb7ff)
  9e:	ea000119 	movi	r0, 281	// regs: r0=0x119
  a2:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xa2>, r1=<clobbered>
  a6:	3000      	movi	r0, 0	// regs: r0=0x0
  a8:	e0000000 	bsr	0x0	// <lmac_cfg_pa_en>; regs: r0=<ret lmac_cfg_pa_en@0xa8>, r1=<clobbered>
  ac:	e0000000 	bsr	0x0	// <tx_dcoc_rx_path_dcoc_cal.constprop.0> // arg_bytes: 0; regs: r0=<ret tx_dcoc_rx_path_dcoc_cal.constprop.0@0xac>, r1=<clobbered>
  b0:	ea000119 	movi	r0, 281	// regs: r0=0x119
  b4:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0xb4>, r1=<clobbered>
  b8:	ec204800 	ori	r1, r0, 18432	// regs: r1=(<ret ah_rfspi_read@0xb4> | 0x4800)
  bc:	2c13      	subi	r4, 20	// regs: r4=0xffffffec
  be:	7445      	zexth	r1, r1	// regs: r1=zext16((<ret ah_rfspi_read@0xb4> | 0x4800))
  c0:	ea000119 	movi	r0, 281	// regs: r0=0x119
  c4:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0xc4>, r1=<clobbered>
  c8:	6d93      	mov	r6, r4	// regs: r6=0xffffffec
  ca:	6dd3      	mov	r7, r4	// regs: r7=0xffffffec
  cc:	c7c05028 	bmaski	r8, 31
loc_d0:
  d0:	3500      	movi	r5, 0	// regs: r5=0x0
  d2:	2d13      	subi	r5, 20	// regs: r5=0xffffffec
loc_d4:
  d4:	3105      	movi	r1, 5	// regs: r1=0x5
  d6:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0xc)
  d8:	dc8e1000 	st.h	r4, (r14, 0x0)	// local_c = r4
  dc:	dcae1001 	st.h	r5, (r14, 0x2)	// local_a = r5
  e0:	e0000000 	bsr	0x0	// <ah_rfdigicali_tx_dcoc>; regs: r0=<ret ah_rfdigicali_tx_dcoc@0xe0>, r1=<clobbered>
  e4:	3002      	movi	r0, 2	// regs: r0=0x2
  e6:	e0000000 	bsr	0x0	// <os_sleep_ms>; regs: r0=<ret os_sleep_ms@0xe6>, r1=<clobbered>
  ea:	1801      	addi	r0, r14, 4	// regs: r0=((sp - 0xc) + 0x4)
  ec:	e0000000 	bsr	0x0	// <ah_rfdigicali_dcoc_est_kick_start>; regs: r0=<ret ah_rfdigicali_dcoc_est_kick_start@0xec>, r1=<clobbered>
  f0:	9861      	ld.w	r3, (r14, 0x4)	// regs: r3=local_8
  f2:	9842      	ld.w	r2, (r14, 0x8)	// regs: r2=local_4
  f4:	60ca      	subu	r3, r2	// regs: r3=(local_8 - local_4)
  f6:	c4030203 	abs	r3, r3
  fa:	660d      	cmplt	r3, r8
  fc:	0c04      	bf	0x104	// if (!T) goto loc_104;
  fe:	6d97      	mov	r6, r5	// regs: r6=r5
 100:	6dd3      	mov	r7, r4	// regs: r7=r4
 102:	6e0f      	mov	r8, r3	// regs: r8=(local_8 - local_4)
loc_104:
 104:	2504      	addi	r5, 5	// regs: r5=(r5 + 0x5)
 106:	3d59      	cmpnei	r5, 25
 108:	0be6      	bt	0xd4	// if (r5 != 0x19) goto loc_d4;
 10a:	2404      	addi	r4, 5	// regs: r4=(r4 + 0x5)
 10c:	3c59      	cmpnei	r4, 25
 10e:	0be1      	bt	0xd0	// if (r4 != 0x19) goto loc_d0;
 110:	5f93      	subi	r4, r7, 5	// regs: r4=(r7 - 0x5)
loc_112:
 112:	5f72      	addi	r3, r7, 5	// regs: r3=(r7 + 0x5)
 114:	650d      	cmplt	r3, r4
 116:	0c1c      	bf	0x14e	// if (!T) goto loc_14e;
 118:	10bf      	lrw	r5, 0x0	// regs: r5=0x0
 11a:	3105      	movi	r1, 5	// regs: r1=0x5
 11c:	6c17      	mov	r0, r5	// regs: r0=0x0
 11e:	ade0      	st.h	r7, (r5, 0x0)	// *(0x0) = r7
 120:	adc1      	st.h	r6, (r5, 0x2)	// *(0x2) = r6
 122:	3400      	movi	r4, 0	// regs: r4=0x0
 124:	e0000000 	bsr	0x0	// <ah_rfdigicali_tx_dcoc>; regs: r0=<ret ah_rfdigicali_tx_dcoc@0x124>, r1=<clobbered>
loc_128:
 128:	6c53      	mov	r1, r4	// regs: r1=r4
 12a:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
 12c:	6c17      	mov	r0, r5	// regs: r0=0x0
 12e:	7510      	zextb	r4, r4	// regs: r4=zext8((r4 + 0x1))
 130:	e0000000 	bsr	0x0	// <ah_rfdigicali_tx_dcoc>; regs: r0=<ret ah_rfdigicali_tx_dcoc@0x130>, r1=<clobbered>
 134:	3c45      	cmpnei	r4, 5
 136:	0bf9      	bt	0x128	// if (r4 != 0x5) goto loc_128;
 138:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x138>, r1=<clobbered>
 13c:	3000      	movi	r0, 0	// regs: r0=0x0
 13e:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0x13e>, r1=<clobbered>
 142:	3000      	movi	r0, 0	// regs: r0=0x0
 144:	e0000000 	bsr	0x0	// <lmac_cfg_pa_en>; regs: r0=<ret lmac_cfg_pa_en@0x144>, r1=<clobbered>
 148:	3000      	movi	r0, 0	// regs: r0=0x0
 14a:	1403      	addi	r14, r14, 12	// regs: r14=((sp - 0xc) + 0xc)
 14c:	1495      	pop	r4-r8, r15
loc_14e:
 14e:	5eb3      	subi	r5, r6, 5	// regs: r5=(r6 - 0x5)
loc_150:
 150:	5e72      	addi	r3, r6, 5	// regs: r3=(r6 + 0x5)
 152:	654d      	cmplt	r3, r5
 154:	0c03      	bf	0x15a	// if (!T) goto loc_15a;
 156:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
 158:	07dd      	br	0x112	// goto loc_112;
loc_15a:
 15a:	3105      	movi	r1, 5	// regs: r1=0x5
 15c:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0xc)
 15e:	dc8e1000 	st.h	r4, (r14, 0x0)	// local_c = r4
 162:	dcae1001 	st.h	r5, (r14, 0x2)	// local_a = r5
 166:	e0000000 	bsr	0x0	// <ah_rfdigicali_tx_dcoc>; regs: r0=<ret ah_rfdigicali_tx_dcoc@0x166>, r1=<clobbered>
 16a:	3002      	movi	r0, 2	// regs: r0=0x2
 16c:	e0000000 	bsr	0x0	// <os_sleep_ms>; regs: r0=<ret os_sleep_ms@0x16c>, r1=<clobbered>
 170:	1801      	addi	r0, r14, 4	// regs: r0=((sp - 0xc) + 0x4)
 172:	e0000000 	bsr	0x0	// <ah_rfdigicali_dcoc_est_kick_start>; regs: r0=<ret ah_rfdigicali_dcoc_est_kick_start@0x172>, r1=<clobbered>
 176:	9861      	ld.w	r3, (r14, 0x4)	// regs: r3=local_8
 178:	9842      	ld.w	r2, (r14, 0x8)	// regs: r2=local_4
 17a:	60ca      	subu	r3, r2	// regs: r3=(local_8 - local_4)
 17c:	c4030203 	abs	r3, r3
 180:	660d      	cmplt	r3, r8
 182:	0c04      	bf	0x18a	// if (!T) goto loc_18a;
 184:	6d97      	mov	r6, r5	// regs: r6=r5
 186:	6dd3      	mov	r7, r4	// regs: r7=r4
 188:	6e0f      	mov	r8, r3	// regs: r8=(local_8 - local_4)
loc_18a:
 18a:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
 18c:	07e2      	br	0x150	// goto loc_150;
 18e:	0000      	.short	0x0000
 190:	40026000 	.long	0x40026000
 194:	00000000 	.long	0x00000000	// <tx_dcoc_res>

Disassembly of section .text.ah_rf_dpd_dcoc_calib:

00000000 <ah_rf_dpd_dcoc_calib>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	e0000000 	bsr	0x0	// <lmac_rf_sw_ctrl>; regs: r0=<ret lmac_rf_sw_ctrl@0x4>, r1=<clobbered>
   8:	3000      	movi	r0, 0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <lmac_cfg_rx_en>; regs: r0=<ret lmac_cfg_rx_en@0xa>, r1=<clobbered>
   e:	3001      	movi	r0, 1	// regs: r0=0x1
  10:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0x10>, r1=<clobbered>
  14:	3000      	movi	r0, 0	// regs: r0=0x0
  16:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_gain_idx_src>; regs: r0=<ret ah_rfdigicali_config_tx_gain_idx_src@0x16>, r1=<clobbered>
  1a:	3105      	movi	r1, 5	// regs: r1=0x5
  1c:	3000      	movi	r0, 0	// regs: r0=0x0
  1e:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0x1e>, r1=<clobbered>
  22:	3005      	movi	r0, 5	// regs: r0=0x5
  24:	e0000000 	bsr	0x0	// <ah_rfdigicali_tx_pwr>; regs: r0=<ret ah_rfdigicali_tx_pwr@0x24>, r1=<clobbered>
  28:	e0000000 	bsr	0x0	// <override_rf_dpd_dcoc_imb_cfg_ePA> // arg_bytes: 0; regs: r0=<ret override_rf_dpd_dcoc_imb_cfg_ePA@0x28>, r1=<clobbered>
  2c:	107a      	lrw	r3, 0x0	// regs: r3=0x0
  2e:	3205      	movi	r2, 5	// regs: r2=0x5
  30:	8b20      	ld.h	r1, (r3, 0x0)	// regs: r1=*(0x0)
  32:	107a      	lrw	r3, 0x0	// regs: r3=0x0
  34:	d8035000 	ld.hs	r0, (r3, 0x0)	// regs: r0=*(0x0)
  38:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_imb>; regs: r0=<ret ah_rfdigicali_config_tx_imb@0x38>, r1=<clobbered>
  3c:	e0000000 	bsr	0x0	// <tx_ram2rf_adc_cal> // arg_bytes: 0; regs: r0=<ret tx_ram2rf_adc_cal@0x3c>, r1=<clobbered>
  40:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0x8)
  42:	e0000000 	bsr	0x0	// <rfdigcal_rx_dcoc_calib> // arg_bytes: 4; regs: r0=<ret rfdigcal_rx_dcoc_calib@0x42>, r1=<clobbered>
  46:	3204      	movi	r2, 4	// regs: r2=0x4
  48:	c44e0020 	addu	r0, r14, r2	// regs: r0=((sp - 0x8) + 0x4)
  4c:	3105      	movi	r1, 5	// regs: r1=0x5
  4e:	e0000000 	bsr	0x0	// <ah_rfdigicali_get_rx_dcoc>; regs: r0=<ret ah_rfdigicali_get_rx_dcoc@0x4e>, r1=<clobbered>
  52:	1013      	lrw	r0, 0x0	// regs: r0=0x0
  54:	d84e1000 	ld.h	r2, (r14, 0x0)	// regs: r2=local_8
  58:	d86e1002 	ld.h	r3, (r14, 0x4)	// regs: r3=local_4
  5c:	60c8      	addu	r3, r2	// regs: r3=(local_4 + local_8)
  5e:	a860      	st.h	r3, (r0, 0x0)	// *(0x0) = (local_4 + local_8)
  60:	d84e1001 	ld.h	r2, (r14, 0x2)	// regs: r2=local_6
  64:	d86e1003 	ld.h	r3, (r14, 0x6)	// regs: r3=local_2
  68:	60c8      	addu	r3, r2	// regs: r3=(local_2 + local_6)
  6a:	3105      	movi	r1, 5	// regs: r1=0x5
  6c:	3204      	movi	r2, 4	// regs: r2=0x4
  6e:	a861      	st.h	r3, (r0, 0x2)	// *(0x2) = (local_2 + local_6)
  70:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_dcoc>; regs: r0=<ret ah_rfdigicali_config_rx_dcoc@0x70>, r1=<clobbered>
  74:	3080      	movi	r0, 128	// regs: r0=0x80
  76:	3105      	movi	r1, 5	// regs: r1=0x5
  78:	4003      	lsli	r0, r0, 3	// regs: r0=0x400
  7a:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0x7a>, r1=<clobbered>
  7e:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x7e>, r1=<clobbered>
  82:	3000      	movi	r0, 0	// regs: r0=0x0
  84:	e0000000 	bsr	0x0	// <lmac_cfg_rx_en>; regs: r0=<ret lmac_cfg_rx_en@0x84>, r1=<clobbered>
  88:	3000      	movi	r0, 0	// regs: r0=0x0
  8a:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0x8a>, r1=<clobbered>
  8e:	3000      	movi	r0, 0	// regs: r0=0x0
  90:	1402      	addi	r14, r14, 8	// regs: r14=((sp - 0x8) + 0x8)
  92:	1490      	pop	r15
  94:	00000000 	.long	0x00000000	// <tx_epa_imb_res_gm>
  98:	00000000 	.long	0x00000000	// <tx_epa_imb_res_pm>
  9c:	00000000 	.long	0x00000000	// <dpd_epa_trx_dcoc_res>

Disassembly of section .text.ah_rf_rx_imb_calib:

00000000 <ah_rf_rx_imb_calib>: // arg_bytes: 8
   0:	14d2      	push	r4-r5, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   6:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   8:	3000      	movi	r0, 0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_gain_idx_src>; regs: r0=<ret ah_rfdigicali_config_rx_gain_idx_src@0xa>, r1=<clobbered>
   e:	6c57      	mov	r1, r5	// regs: r1=<arg0>
  10:	6c13      	mov	r0, r4	// regs: r0=<arg1>
  12:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_gain>; regs: r0=<ret ah_rfdigicali_config_rx_gain@0x12>, r1=<clobbered>
  16:	3380      	movi	r3, 128	// regs: r3=0x80
  18:	4364      	lsli	r3, r3, 4	// regs: r3=0x800
  1a:	dc6e1001 	st.h	r3, (r14, 0x2)	// local_2 = 0x800
  1e:	3180      	movi	r1, 128	// regs: r1=0x80
  20:	3300      	movi	r3, 0	// regs: r3=0x0
  22:	dc6e1000 	st.h	r3, (r14, 0x0)	// local_4 = 0x0
  26:	6c93      	mov	r2, r4	// regs: r2=<arg1>
  28:	6cd7      	mov	r3, r5	// regs: r3=<arg0>
  2a:	4124      	lsli	r1, r1, 4	// regs: r1=0x800
  2c:	3000      	movi	r0, 0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_imb>; regs: r0=<ret ah_rfdigicali_config_rx_imb@0x2e>, r1=<clobbered>
  32:	e42e0001 	addi	r1, r14, 2	// regs: r1=((sp - 0x4) + 0x2)
  36:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0x4)
  38:	e0000000 	bsr	0x0	// <rx_imb_comp_inner> // arg_bytes: 8; regs: r0=<ret rx_imb_comp_inner@0x38>, r1=<clobbered>
  3c:	d86e5000 	ld.hs	r3, (r14, 0x0)	// regs: r3=local_4
  40:	eb2301ff 	cmplti	r3, 512
  44:	0807      	bt	0x52	// if (r3 < 0x200) goto loc_52;
  46:	ea0203ff 	movi	r2, 1023	// regs: r2=0x3ff
  4a:	6c8a      	nor	r2, r2	// regs: r2=(~0x3ff)
  4c:	6cc8      	or	r3, r2	// regs: r3=(local_4 | (~0x3ff))
  4e:	dc6e1000 	st.h	r3, (r14, 0x0)	// local_4 = (local_4 | (~0x3ff))
loc_52:
  52:	6cd7      	mov	r3, r5	// regs: r3=<arg0>
  54:	6c93      	mov	r2, r4	// regs: r2=<arg1>
  56:	d82e1001 	ld.h	r1, (r14, 0x2)	// regs: r1=local_2
  5a:	d80e5000 	ld.hs	r0, (r14, 0x0)	// regs: r0=local_4
  5e:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_imb>; regs: r0=<ret ah_rfdigicali_config_rx_imb@0x5e>, r1=<clobbered>
  62:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  64:	d84e1000 	ld.h	r2, (r14, 0x0)	// regs: r2=local_4
  68:	ab40      	st.h	r2, (r3, 0x0)	// *(0x0) = local_4
  6a:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0x4)
  6c:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  6e:	d84e1001 	ld.h	r2, (r14, 0x2)	// regs: r2=local_2
  72:	e42e0001 	addi	r1, r14, 2	// regs: r1=((sp - 0x4) + 0x2)
  76:	ab40      	st.h	r2, (r3, 0x0)	// *(0x0) = local_2
  78:	e0000000 	bsr	0x0	// <rx_imb_comp_inner> // arg_bytes: 8; regs: r0=<ret rx_imb_comp_inner@0x78>, r1=<clobbered>
  7c:	3000      	movi	r0, 0	// regs: r0=0x0
  7e:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  80:	1492      	pop	r4-r5, r15
  82:	0000      	.short	0x0000
  84:	00000000 	.long	0x00000000	// <dpd_epa_phase_comp>
  88:	00000000 	.long	0x00000000	// <dpd_epa_gain_comp>

Disassembly of section .text.ah_rf_dpd_imb_calib:

00000000 <ah_rf_dpd_imb_calib>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	3300      	movi	r3, 0	// regs: r3=0x0
   6:	dc6e1000 	st.h	r3, (r14, 0x0)	// local_4 = 0x0
   a:	dc6e1001 	st.h	r3, (r14, 0x2)	// local_2 = 0x0
   e:	e0000000 	bsr	0x0	// <lmac_rf_sw_ctrl>; regs: r0=<ret lmac_rf_sw_ctrl@0xe>, r1=<clobbered>
  12:	3001      	movi	r0, 1	// regs: r0=0x1
  14:	e0000000 	bsr	0x0	// <lmac_cfg_rx_en>; regs: r0=<ret lmac_cfg_rx_en@0x14>, r1=<clobbered>
  18:	3000      	movi	r0, 0	// regs: r0=0x0
  1a:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0x1a>, r1=<clobbered>
  1e:	3303      	movi	r3, 3	// regs: r3=0x3
  20:	3205      	movi	r2, 5	// regs: r2=0x5
  22:	e42e0001 	addi	r1, r14, 2	// regs: r1=((sp - 0x4) + 0x2)
  26:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0x4)
  28:	e0000000 	bsr	0x0	// <ah_rfdigicali_get_rx_imb>; regs: r0=<ret ah_rfdigicali_get_rx_imb@0x28>, r1=<clobbered>
  2c:	3000      	movi	r0, 0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_gain_idx_src>; regs: r0=<ret ah_rfdigicali_config_rx_gain_idx_src@0x2e>, r1=<clobbered>
  32:	3103      	movi	r1, 3	// regs: r1=0x3
  34:	3005      	movi	r0, 5	// regs: r0=0x5
  36:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_gain>; regs: r0=<ret ah_rfdigicali_config_rx_gain@0x36>, r1=<clobbered>
  3a:	e0000000 	bsr	0x0	// <override_rf_dpd_dcoc_imb_cfg_ePA> // arg_bytes: 0; regs: r0=<ret override_rf_dpd_dcoc_imb_cfg_ePA@0x3a>, r1=<clobbered>
  3e:	3203      	movi	r2, 3	// regs: r2=0x3
  40:	3105      	movi	r1, 5	// regs: r1=0x5
  42:	1100      	lrw	r0, 0x0	// regs: r0=0x0
  44:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_dcoc>; regs: r0=<ret ah_rfdigicali_config_rx_dcoc@0x44>, r1=<clobbered>
  48:	107f      	lrw	r3, 0x0	// regs: r3=0x0
  4a:	3205      	movi	r2, 5	// regs: r2=0x5
  4c:	8b20      	ld.h	r1, (r3, 0x0)	// regs: r1=*(0x0)
  4e:	107f      	lrw	r3, 0x0	// regs: r3=0x0
  50:	d8035000 	ld.hs	r0, (r3, 0x0)	// regs: r0=*(0x0)
  54:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_imb>; regs: r0=<ret ah_rfdigicali_config_tx_imb@0x54>, r1=<clobbered>
  58:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x58>, r1=<clobbered>
  5c:	3001      	movi	r0, 1	// regs: r0=0x1
  5e:	e0000000 	bsr	0x0	// <ah_set_dbgpath_device_path_mode>; regs: r0=<ret ah_set_dbgpath_device_path_mode@0x5e>, r1=<clobbered>
  62:	3101      	movi	r1, 1	// regs: r1=0x1
  64:	3000      	movi	r0, 0	// regs: r0=0x0
  66:	e0000000 	bsr	0x0	// <ah_tdma_set_mode>; regs: r0=<ret ah_tdma_set_mode@0x66>, r1=<clobbered>
  6a:	3140      	movi	r1, 64	// regs: r1=0x40
  6c:	1018      	lrw	r0, 0x0	// regs: r0=0x0
  6e:	e0000000 	bsr	0x0	// <ah_tdma_set_buff>; regs: r0=<ret ah_tdma_set_buff@0x6e>, r1=<clobbered>
  72:	e0000000 	bsr	0x0	// <ah_tdma_start>; regs: r0=<ret ah_tdma_start@0x72>, r1=<clobbered>
  76:	e0000000 	bsr	0x0	// <ah_trig_dbgpath_device_dma>; regs: r0=<ret ah_trig_dbgpath_device_dma@0x76>, r1=<clobbered>
  7a:	3105      	movi	r1, 5	// regs: r1=0x5
  7c:	3003      	movi	r0, 3	// regs: r0=0x3
  7e:	e0000000 	bsr	0x0	// <ah_rf_rx_imb_calib> // arg_bytes: 8; regs: r0=<ret ah_rf_rx_imb_calib@0x7e>, r1=<clobbered>
  82:	1034      	lrw	r1, 0x0	// regs: r1=0x0
  84:	1014      	lrw	r0, 0x0	// regs: r0=0x0
  86:	3304      	movi	r3, 4	// regs: r3=0x4
  88:	3205      	movi	r2, 5	// regs: r2=0x5
  8a:	8920      	ld.h	r1, (r1, 0x0)	// regs: r1=*(0x0)
  8c:	d8005000 	ld.hs	r0, (r0, 0x0)	// regs: r0=*(0x0)
  90:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_imb>; regs: r0=<ret ah_rfdigicali_config_rx_imb@0x90>, r1=<clobbered>
  94:	3203      	movi	r2, 3	// regs: r2=0x3
  96:	3105      	movi	r1, 5	// regs: r1=0x5
  98:	1010      	lrw	r0, 0x0	// regs: r0=0x0
  9a:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_dcoc>; regs: r0=<ret ah_rfdigicali_config_rx_dcoc@0x9a>, r1=<clobbered>
  9e:	3303      	movi	r3, 3	// regs: r3=0x3
  a0:	3205      	movi	r2, 5	// regs: r2=0x5
  a2:	d82e1001 	ld.h	r1, (r14, 0x2)	// regs: r1=local_2
  a6:	d80e5000 	ld.hs	r0, (r14, 0x0)	// regs: r0=local_4
  aa:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_imb>; regs: r0=<ret ah_rfdigicali_config_rx_imb@0xaa>, r1=<clobbered>
  ae:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0xae>, r1=<clobbered>
  b2:	3000      	movi	r0, 0	// regs: r0=0x0
  b4:	e0000000 	bsr	0x0	// <lmac_cfg_tx_en>; regs: r0=<ret lmac_cfg_tx_en@0xb4>, r1=<clobbered>
  b8:	3000      	movi	r0, 0	// regs: r0=0x0
  ba:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  bc:	1490      	pop	r15
  be:	0000      	.short	0x0000
  c0:	00000000 	.long	0x00000000	// <dpd_epa_trx_dcoc_res>
  c4:	0000      	.short	0x0000	// <tx_epa_imb_res_gm>
  c6:	0000      	.short	0x0000
  c8:	00000000 	.long	0x00000000	// <tx_epa_imb_res_pm>
  cc:	0000      	.short	0x0000	// <iq_curve_for_dac_p2mhz_for_iPA_dpd_imb>
  ce:	0000      	.short	0x0000
  d0:	00000000 	.long	0x00000000	// <dpd_epa_gain_comp>
  d4:	00000000 	.long	0x00000000	// <dpd_epa_phase_comp>
  d8:	00000000 	.long	0x00000000	// <rx_dcoc_res+0x5c>

Disassembly of section .text.rx_imb_res_store:

00000000 <rx_imb_res_store>: // arg_bytes: 8
   0:	14d0      	push	r15
   2:	1423      	subi	r14, r14, 12	// regs: r14=(sp - 0xc)
   4:	8863      	ld.h	r3, (r0, 0x6)	// regs: r3=*(<arg0> + 0x6)
   6:	dc6e1000 	st.h	r3, (r14, 0x0)	// local_c = *(<arg0> + 0x6)
   a:	8963      	ld.h	r3, (r1, 0x6)	// regs: r3=*(<arg1> + 0x6)
   c:	dc6e1001 	st.h	r3, (r14, 0x2)	// local_a = *(<arg1> + 0x6)
  10:	8864      	ld.h	r3, (r0, 0x8)	// regs: r3=*(<arg0> + 0x8)
  12:	dc6e1002 	st.h	r3, (r14, 0x4)	// local_8 = *(<arg0> + 0x8)
  16:	8964      	ld.h	r3, (r1, 0x8)	// regs: r3=*(<arg1> + 0x8)
  18:	dc6e1003 	st.h	r3, (r14, 0x6)	// local_6 = *(<arg1> + 0x8)
  1c:	8865      	ld.h	r3, (r0, 0xa)	// regs: r3=*(<arg0> + 0xa)
  1e:	dc6e1004 	st.h	r3, (r14, 0x8)	// local_4 = *(<arg0> + 0xa)
  22:	3203      	movi	r2, 3	// regs: r2=0x3
  24:	8965      	ld.h	r3, (r1, 0xa)	// regs: r3=*(<arg1> + 0xa)
  26:	3004      	movi	r0, 4	// regs: r0=0x4
  28:	6c7b      	mov	r1, r14	// regs: r1=(sp - 0xc)
  2a:	dc6e1005 	st.h	r3, (r14, 0xa)	// local_2 = *(<arg1> + 0xa)
  2e:	e0000000 	bsr	0x0	// <memory_write>; regs: r0=<ret memory_write@0x2e>, r1=<clobbered>
  32:	1403      	addi	r14, r14, 12	// regs: r14=((sp - 0xc) + 0xc)
  34:	1490      	pop	r15

Disassembly of section .text.ah_rf_open:

00000000 <ah_rf_open>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	1437      	subi	r14, r14, 92	// regs: r14=(sp - 0x5c)
   4:	008f      	lrw	r4, 0x40026000	// regs: r4=0x40026000
   6:	3004      	movi	r0, 4	// regs: r0=0x4
   8:	e0000000 	bsr	0x0	// <pmu_vccmipi_vol_set_sec>; regs: r0=<ret pmu_vccmipi_vol_set_sec@0x8>, r1=<clobbered>
   c:	9475      	ld.w	r3, (r4, 0x54)	// regs: r3=*(0x40026054)
   e:	3b9e      	bclri	r3, 30	// regs: r3=(*(0x40026054) & ~(0x1 << 0x1e))
  10:	b475      	st.w	r3, (r4, 0x54)	// *(0x40026054) = (*(0x40026054) & ~(0x1 << 0x1e))
  12:	9475      	ld.w	r3, (r4, 0x54)	// regs: r3=*(0x40026054)
  14:	c40357c3 	zext	r3, r3, 30, 0	// regs: r3=zext(*(0x40026054))
  18:	3202      	movi	r2, 2	// regs: r2=0x2
  1a:	b475      	st.w	r3, (r4, 0x54)	// *(0x40026054) = zext(*(0x40026054))
  1c:	3120      	movi	r1, 32	// regs: r1=0x20
  1e:	3001      	movi	r0, 1	// regs: r0=0x1
  20:	e0000000 	bsr	0x0	// <ah_rfspi_open>; regs: r0=<ret ah_rfspi_open@0x20>, r1=<clobbered>
  24:	3500      	movi	r5, 0	// regs: r5=0x0
  26:	e0000000 	bsr	0x0	// <pmu_pd_set_anatop_en_sec>; regs: r0=<ret pmu_pd_set_anatop_en_sec@0x26>, r1=<clobbered>
  2a:	6c17      	mov	r0, r5	// regs: r0=0x0
  2c:	e0000000 	bsr	0x0	// <lmac_cfg_rf_en>; regs: r0=<ret lmac_cfg_rf_en@0x2c>, r1=<clobbered>
  30:	3001      	movi	r0, 1	// regs: r0=0x1
  32:	e0000000 	bsr	0x0	// <lmac_cfg_rf_en>; regs: r0=<ret lmac_cfg_rf_en@0x32>, r1=<clobbered>
  36:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x40026000)
  38:	3b90      	bclri	r3, 16	// regs: r3=(*(0x40026000) & ~(0x1 << 0x10))
  3a:	b460      	st.w	r3, (r4, 0x0)	// *(0x40026000) = (*(0x40026000) & ~(0x1 << 0x10))
  3c:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x40026000)
  3e:	3b8f      	bclri	r3, 15	// regs: r3=(*(0x40026000) & ~(0x1 << 0xf))
  40:	3b9f      	bclri	r3, 31	// regs: r3=((*(0x40026000) & ~(0x1 << 0xf)) & ~(0x1 << 0x1f))
  42:	b460      	st.w	r3, (r4, 0x0)	// *(0x40026000) = ((*(0x40026000) & ~(0x1 << 0xf)) & ~(0x1 << 0x1f))
  44:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x40026000)
  46:	3bb9      	bseti	r3, 25	// regs: r3=(*(0x40026000) | (0x1 << 0x19))
  48:	b460      	st.w	r3, (r4, 0x0)	// *(0x40026000) = (*(0x40026000) | (0x1 << 0x19))
  4a:	9473      	ld.w	r3, (r4, 0x4c)	// regs: r3=*(0x4002604c)
  4c:	3bba      	bseti	r3, 26	// regs: r3=(*(0x4002604c) | (0x1 << 0x1a))
  4e:	b473      	st.w	r3, (r4, 0x4c)	// *(0x4002604c) = (*(0x4002604c) | (0x1 << 0x1a))
  50:	3004      	movi	r0, 4	// regs: r0=0x4
  52:	e0000000 	bsr	0x0	// <pmu_vccmipi_vol_set_sec>; regs: r0=<ret pmu_vccmipi_vol_set_sec@0x52>, r1=<clobbered>
  56:	6c57      	mov	r1, r5	// regs: r1=0x0
  58:	302a      	movi	r0, 42	// regs: r0=0x2a
  5a:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x5a>, r1=<clobbered>
  5e:	3103      	movi	r1, 3	// regs: r1=0x3
  60:	302b      	movi	r0, 43	// regs: r0=0x2b
  62:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x62>, r1=<clobbered>
  66:	3101      	movi	r1, 1	// regs: r1=0x1
  68:	3016      	movi	r0, 22	// regs: r0=0x16
  6a:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x6a>, r1=<clobbered>
  6e:	3101      	movi	r1, 1	// regs: r1=0x1
  70:	3016      	movi	r0, 22	// regs: r0=0x16
  72:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x72>, r1=<clobbered>
  76:	018a      	lrw	r4, 0x0	// regs: r4=0x0
  78:	3105      	movi	r1, 5	// regs: r1=0x5
  7a:	3017      	movi	r0, 23	// regs: r0=0x17
  7c:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x7c>, r1=<clobbered>
  80:	3105      	movi	r1, 5	// regs: r1=0x5
  82:	3018      	movi	r0, 24	// regs: r0=0x18
  84:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x84>, r1=<clobbered>
  88:	d8644002 	ld.bs	r3, (r4, 0x2)	// regs: r3=*(0x2)
  8c:	a4a5      	st.b	r5, (r4, 0x5)	// *(0x5) = 0x0
  8e:	e923001a 	bnez	r3, 0xc2	// if (r3 != 0x0) goto loc_c2;
  92:	e0000000 	bsr	0x0	// <rf_para_efuse_check_valid>; regs: r0=<ret rf_para_efuse_check_valid@0x92>, r1=<clobbered>
  96:	d8644003 	ld.bs	r3, (r4, 0x3)	// regs: r3=*(0x3)
  9a:	e9230010 	bnez	r3, 0xba	// if (r3 != 0x0) goto loc_ba;
  9e:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_tx_analog_gain_mcs7>; regs: r0=<ret sysctrl_efuse_get_tx_analog_gain_mcs7@0x9e>, r1=<clobbered>
  a2:	a405      	st.b	r0, (r4, 0x5)	// *(0x5) = <ret sysctrl_efuse_get_tx_analog_gain_mcs7@0x9e>
loc_a4:
  a4:	84a0      	ld.b	r5, (r4, 0x0)	// regs: r5=*(0x0)
  a6:	3d02      	cmphsi	r5, 3
  a8:	0c0f      	bf	0xc6	// if (r5 < 0x3) goto loc_c6;
  aa:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_module_type>; regs: r0=<ret sysctrl_efuse_get_module_type@0xaa>, r1=<clobbered>
  ae:	3844      	cmpnei	r0, 4
  b0:	a407      	st.b	r0, (r4, 0x7)	// *(0x7) = <ret sysctrl_efuse_get_module_type@0xaa>
  b2:	0815      	bt	0xdc	// if (r0 != 0x4) goto loc_dc;
loc_b4:
  b4:	3301      	movi	r3, 1	// regs: r3=0x1
loc_b6:
  b6:	a467      	st.b	r3, (r4, 0x7)	// *(0x7) = r3
  b8:	0412      	br	0xdc	// goto loc_dc;
loc_ba:
  ba:	011a      	lrw	r0, 0x0	// regs: r0=0x0
loc_bc:
  bc:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xbc>, r1=<clobbered>
  c0:	07f2      	br	0xa4	// goto loc_a4;
loc_c2:
  c2:	011b      	lrw	r0, 0x0	// regs: r0=0x0
  c4:	07fc      	br	0xbc	// goto loc_bc;
loc_c6:
  c6:	3d42      	cmpnei	r5, 2
  c8:	0847      	bt	0x156	// if (r5 != 0x2) goto loc_156;
  ca:	8425      	ld.b	r1, (r4, 0x5)	// regs: r1=*(0x5)
  cc:	011d      	lrw	r0, 0x0	// regs: r0=0x0
  ce:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xce>, r1=<clobbered>
  d2:	8465      	ld.b	r3, (r4, 0x5)	// regs: r3=*(0x5)
  d4:	eb030032 	cmphsi	r3, 51
  d8:	0fee      	bf	0xb4	// if (r3 < 0x33) goto loc_b4;
  da:	a4a7      	st.b	r5, (r4, 0x7)	// *(0x7) = *(0x0)
loc_dc:
  dc:	8467      	ld.b	r3, (r4, 0x7)	// regs: r3=*(0x7)
  de:	e44320fb 	andi	r2, r3, 251	// regs: r2=(*(0x7) & 0xfb)
  e2:	3a41      	cmpnei	r2, 1
  e4:	083e      	bt	0x160	// if (r2 != 0x1) goto loc_160;
  e6:	0242      	lrw	r2, 0x0	// regs: r2=0x0
  e8:	0262      	lrw	r3, 0x0	// regs: r3=0x0
  ea:	3100      	movi	r1, 0	// regs: r1=0x0
loc_ec:
  ec:	8a00      	ld.h	r0, (r2, 0x0)	// regs: r0=*(r2)
  ee:	2100      	addi	r1, 1	// regs: r1=(r1 + 0x1)
  f0:	ab00      	st.h	r0, (r3, 0x0)	// *(r3) = *(r2)
  f2:	7444      	zextb	r1, r1	// regs: r1=zext8((r1 + 0x1))
  f4:	8a01      	ld.h	r0, (r2, 0x2)	// regs: r0=*(r2 + 0x2)
  f6:	ab01      	st.h	r0, (r3, 0x2)	// *(r3 + 0x2) = *(r2 + 0x2)
  f8:	3946      	cmpnei	r1, 6
  fa:	8a02      	ld.h	r0, (r2, 0x4)	// regs: r0=*(r2 + 0x4)
  fc:	ab02      	st.h	r0, (r3, 0x4)	// *(r3 + 0x4) = *(r2 + 0x4)
  fe:	8a03      	ld.h	r0, (r2, 0x6)	// regs: r0=*(r2 + 0x6)
 100:	ab03      	st.h	r0, (r3, 0x6)	// *(r3 + 0x6) = *(r2 + 0x6)
 102:	2207      	addi	r2, 8	// regs: r2=(r2 + 0x8)
 104:	2311      	addi	r3, 18	// regs: r3=(r3 + 0x12)
 106:	0bf3      	bt	0xec	// if (r1 != 0x6) goto loc_ec;
 108:	3100      	movi	r1, 0	// regs: r1=0x0
 10a:	6c87      	mov	r2, r1	// regs: r2=0x0
loc_10c:
 10c:	3300      	movi	r3, 0	// regs: r3=0x0
 10e:	e4a1008f 	addi	r5, r1, 144	// regs: r5=(r1 + 0x90)
 112:	e5a2004f 	addi	r13, r2, 80	// regs: r13=(r2 + 0x50)
loc_116:
 116:	5d0c      	addu	r0, r5, r3	// regs: r0=(r5 + r3)
 118:	ea8c00b1 	lrw	r12, 0x0	// regs: r12=0x0
 11c:	6030      	addu	r0, r12	// regs: r0=((r5 + r3) )
 11e:	02ce      	lrw	r6, 0x0	// regs: r6=0x0
 120:	c46d002c 	addu	r12, r13, r3	// regs: r12=(r13 + r3)
 124:	6318      	addu	r12, r6	// regs: r12=((r13 + r3) )
 126:	2301      	addi	r3, 2	// regs: r3=(r3 + 0x2)
 128:	3b4a      	cmpnei	r3, 10
 12a:	d98c1000 	ld.h	r12, (r12, 0x0)	// regs: r12=*(((r13 + r3) ))
 12e:	dd801004 	st.h	r12, (r0, 0x8)	// *((((r5 + r3) ) + 0x8)) = *(((r13 + r3) ))
 132:	0bf2      	bt	0x116	// if (r3 != 0xa) goto loc_116;
 134:	2209      	addi	r2, 10	// regs: r2=(r2 + 0xa)
 136:	eb42003c 	cmpnei	r2, 60
 13a:	2111      	addi	r1, 18	// regs: r1=(r1 + 0x12)
 13c:	0be8      	bt	0x10c	// if (r2 != 0x3c) goto loc_10c;
 13e:	3300      	movi	r3, 0	// regs: r3=0x0
 140:	0256      	lrw	r2, 0x0	// regs: r2=0x0
 142:	0235      	lrw	r1, 0x0	// regs: r1=0x0
loc_144:
 144:	d0610440 	ldr.h	r0, (r1, r3 << 1)	// regs: r0=*(0x0 + (r3 << 1))
 148:	d4620480 	str.h	r0, (r2, r3 << 2)
 14c:	2300      	addi	r3, 1	// regs: r3=(r3 + 0x1)
 14e:	eb430020 	cmpnei	r3, 32
 152:	0bf9      	bt	0x144	// if (r3 != 0x20) goto loc_144;
 154:	0430      	br	0x1b4	// goto loc_1b4;
loc_156:
 156:	0219      	lrw	r0, 0x0	// regs: r0=0x0
 158:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x158>, r1=<clobbered>
 15c:	3302      	movi	r3, 2	// regs: r3=0x2
 15e:	07ac      	br	0xb6	// goto loc_b6;
loc_160:
 160:	3b50      	cmpnei	r3, 16
 162:	081c      	bt	0x19a	// if (r3 != 0x10) goto loc_19a;
 164:	027c      	lrw	r3, 0x0	// regs: r3=0x0
 166:	3200      	movi	r2, 0	// regs: r2=0x0
loc_168:
 168:	8b20      	ld.h	r1, (r3, 0x0)	// regs: r1=*(r3)
 16a:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
 16c:	ec211000 	ori	r1, r1, 4096	// regs: r1=(*(r3) | 0x1000)
 170:	7488      	zextb	r2, r2	// regs: r2=zext8((r2 + 0x1))
 172:	ab20      	st.h	r1, (r3, 0x0)	// *(r3) = (*(r3) | 0x1000)
 174:	3a46      	cmpnei	r2, 6
 176:	8b21      	ld.h	r1, (r3, 0x2)	// regs: r1=*(r3 + 0x2)
 178:	ec211000 	ori	r1, r1, 4096	// regs: r1=(*(r3 + 0x2) | 0x1000)
 17c:	ab21      	st.h	r1, (r3, 0x2)	// *(r3 + 0x2) = (*(r3 + 0x2) | 0x1000)
 17e:	2311      	addi	r3, 18	// regs: r3=(r3 + 0x12)
 180:	0bf4      	bt	0x168	// if (r2 != 0x6) goto loc_168;
 182:	3300      	movi	r3, 0	// regs: r3=0x0
 184:	0347      	lrw	r2, 0x0	// regs: r2=0x0
 186:	0323      	lrw	r1, 0x0	// regs: r1=0x0
loc_188:
 188:	d0610440 	ldr.h	r0, (r1, r3 << 1)	// regs: r0=*(0x0 + (r3 << 1))
 18c:	d4620480 	str.h	r0, (r2, r3 << 2)
 190:	2300      	addi	r3, 1	// regs: r3=(r3 + 0x1)
 192:	eb430020 	cmpnei	r3, 32
 196:	0bf9      	bt	0x188	// if (r3 != 0x20) goto loc_188;
 198:	040e      	br	0x1b4	// goto loc_1b4;
loc_19a:
 19a:	3b43      	cmpnei	r3, 3
 19c:	080c      	bt	0x1b4	// if (r3 != 0x3) goto loc_1b4;
 19e:	3300      	movi	r3, 0	// regs: r3=0x0
loc_1a0:
 1a0:	0350      	lrw	r2, 0x0	// regs: r2=0x0
 1a2:	5b28      	addu	r1, r3, r2	// regs: r1=(r3 )
 1a4:	2311      	addi	r3, 18	// regs: r3=(r3 + 0x12)
 1a6:	8943      	ld.h	r2, (r1, 0x6)	// regs: r2=*(((r3 ) + 0x6))
 1a8:	eb43006c 	cmpnei	r3, 108
 1ac:	ec421000 	ori	r2, r2, 4096	// regs: r2=(*(((r3 ) + 0x6)) | 0x1000)
 1b0:	a943      	st.h	r2, (r1, 0x6)	// *(((r3 ) + 0x6)) = (*(((r3 ) + 0x6)) | 0x1000)
 1b2:	0bf7      	bt	0x1a0	// if (r3 != 0x6c) goto loc_1a0;
loc_1b4:
 1b4:	d8644002 	ld.bs	r3, (r4, 0x2)	// regs: r3=*(0x2)
 1b8:	e9230008 	bnez	r3, 0x1c8	// if (r3 != 0x0) goto loc_1c8;
 1bc:	d8644003 	ld.bs	r3, (r4, 0x3)	// regs: r3=*(0x3)
 1c0:	e9230004 	bnez	r3, 0x1c8	// if (r3 != 0x0) goto loc_1c8;
 1c4:	e0000000 	bsr	0x0	// <rf_para_efuse_read> // arg_bytes: 4; regs: r0=<ret rf_para_efuse_read@0x1c4>, r1=<clobbered>
loc_1c8:
 1c8:	e0000000 	bsr	0x0	// <sysctrl_dac_init>; regs: r0=<ret sysctrl_dac_init@0x1c8>, r1=<clobbered>
 1cc:	e0000000 	bsr	0x0	// <is_adc_calibed>; regs: r0=<ret is_adc_calibed@0x1cc>, r1=<clobbered>
 1d0:	e9000018 	bez	r0, 0x200	// if (r0 == 0x0) goto loc_200;
loc_1d4:
 1d4:	e0000000 	bsr	0x0	// <adc_init>; regs: r0=<ret adc_init@0x1d4>, r1=<clobbered>
 1d8:	e0000000 	bsr	0x0	// <adc_calib> // arg_bytes: 0; regs: r0=<ret adc_calib@0x1d8>, r1=<clobbered>
 1dc:	e0000000 	bsr	0x0	// <check_adc_perf> // arg_bytes: 0; regs: r0=<ret check_adc_perf@0x1dc>, r1=<clobbered>
 1e0:	e9000043 	bez	r0, 0x266	// if (r0 == 0x0) goto loc_266;
 1e4:	3003      	movi	r0, 3	// regs: r0=0x3
 1e6:	e0000000 	bsr	0x0	// <pmu_vdd_vol_set_sec>; regs: r0=<ret pmu_vdd_vol_set_sec@0x1e6>, r1=<clobbered>
 1ea:	e0000000 	bsr	0x0	// <adc_calib> // arg_bytes: 0; regs: r0=<ret adc_calib@0x1ea>, r1=<clobbered>
 1ee:	3006      	movi	r0, 6	// regs: r0=0x6
 1f0:	e0000000 	bsr	0x0	// <pmu_vdd_vol_set_sec>; regs: r0=<ret pmu_vdd_vol_set_sec@0x1f0>, r1=<clobbered>
 1f4:	e0000000 	bsr	0x0	// <check_adc_perf> // arg_bytes: 0; regs: r0=<ret check_adc_perf@0x1f4>, r1=<clobbered>
 1f8:	e9200044 	bnez	r0, 0x280	// if (r0 != 0x0) goto loc_280;
 1fc:	131f      	lrw	r0, 0x0	// regs: r0=0x0
 1fe:	0435      	br	0x268	// goto loc_268;
loc_200:
 200:	e0000000 	bsr	0x0	// <adc_calib_res_restore>; regs: r0=<ret adc_calib_res_restore@0x200>, r1=<clobbered>
 204:	e0000000 	bsr	0x0	// <check_adc_perf> // arg_bytes: 0; regs: r0=<ret check_adc_perf@0x204>, r1=<clobbered>
 208:	e920ffe6 	bnez	r0, 0x1d4	// if (r0 != 0x0) goto loc_1d4;
loc_20c:
 20c:	30fa      	movi	r0, 250	// regs: r0=0xfa
 20e:	4002      	lsli	r0, r0, 2	// regs: r0=0x3e8
 210:	e0000000 	bsr	0x0	// <delay_us>; regs: r0=<ret delay_us@0x210>, r1=<clobbered>
 214:	8467      	ld.b	r3, (r4, 0x7)	// regs: r3=*(0x7)
 216:	e44320fb 	andi	r2, r3, 251	// regs: r2=(*(0x7) & 0xfb)
 21a:	3a41      	cmpnei	r2, 1
 21c:	0840      	bt	0x29c	// if (r2 != 0x1) goto loc_29c;
 21e:	1318      	lrw	r0, 0x0	// regs: r0=0x0
 220:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x220>, r1=<clobbered>
 224:	ea00c5c1 	movi	r0, 50625	// regs: r0=0xc5c1
 228:	c4804900 	rotli	r0, r0, 4	// regs: r0=rotl(0xc5c1, 0x4)
loc_22c:
 22c:	e0000000 	bsr	0x0	// <ah_rf_lo_freq_set> // arg_bytes: 4; regs: r0=<ret ah_rf_lo_freq_set@0x22c>, r1=<clobbered>
 230:	e9200024 	bnez	r0, 0x278	// if (r0 != 0x0) goto loc_278;
 234:	d8644003 	ld.bs	r3, (r4, 0x3)	// regs: r3=*(0x3)
 238:	e903004b 	bez	r3, 0x2ce	// if (r3 == 0x0) goto loc_2ce;
loc_23c:
 23c:	3202      	movi	r2, 2	// regs: r2=0x2
 23e:	1904      	addi	r1, r14, 16	// regs: r1=((sp - 0x5c) + 0x10)
 240:	3001      	movi	r0, 1	// regs: r0=0x1
 242:	e0000000 	bsr	0x0	// <memory_read>; regs: r0=<ret memory_read@0x242>, r1=<clobbered>
 246:	e92003b2 	bnez	r0, 0x9aa	// if (r0 != 0x0) goto loc_9aa;
 24a:	d86e500a 	ld.hs	r3, (r14, 0x14)	// regs: r3=local_48
 24e:	eb430055 	cmpnei	r3, 85
 252:	e86003ac 	bt	0x9aa	// if (r3 != 0x55) goto loc_9aa;
 256:	136b      	lrw	r3, 0x0	// regs: r3=0x0
 258:	d84e1008 	ld.h	r2, (r14, 0x10)	// regs: r2=local_4c
 25c:	ab40      	st.h	r2, (r3, 0x0)	// *(0x0) = local_4c
 25e:	d84e1009 	ld.h	r2, (r14, 0x12)	// regs: r2=local_4a
 262:	ab41      	st.h	r2, (r3, 0x2)	// *(0x2) = local_4a
 264:	0439      	br	0x2d6	// goto loc_2d6;
loc_266:
 266:	1308      	lrw	r0, 0x0	// regs: r0=0x0
loc_268:
 268:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x268>, r1=<clobbered>
loc_26c:
 26c:	e0000000 	bsr	0x0	// <adc_calib_res_store>; regs: r0=<ret adc_calib_res_store@0x26c>, r1=<clobbered>
 270:	3300      	movi	r3, 0	// regs: r3=0x0
 272:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 274:	64c2      	cmpne	r0, r3
 276:	0bcb      	bt	0x20c	// if (T) goto loc_20c;
loc_278:
 278:	3000      	movi	r0, 0	// regs: r0=0x0
 27a:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_27c:
 27c:	1417      	addi	r14, r14, 92	// regs: r14=(sp + 0x5c)
 27e:	1498      	pop	r4-r11, r15
loc_280:
 280:	3007      	movi	r0, 7	// regs: r0=0x7
 282:	e0000000 	bsr	0x0	// <pmu_vdd_vol_set_sec>; regs: r0=<ret pmu_vdd_vol_set_sec@0x282>, r1=<clobbered>
 286:	e0000000 	bsr	0x0	// <adc_calib> // arg_bytes: 0; regs: r0=<ret adc_calib@0x286>, r1=<clobbered>
 28a:	3006      	movi	r0, 6	// regs: r0=0x6
 28c:	e0000000 	bsr	0x0	// <pmu_vdd_vol_set_sec>; regs: r0=<ret pmu_vdd_vol_set_sec@0x28c>, r1=<clobbered>
 290:	e0000000 	bsr	0x0	// <check_adc_perf> // arg_bytes: 0; regs: r0=<ret check_adc_perf@0x290>, r1=<clobbered>
 294:	e920ffec 	bnez	r0, 0x26c	// if (r0 != 0x0) goto loc_26c;
 298:	121c      	lrw	r0, 0x0	// regs: r0=0x0
 29a:	07e7      	br	0x268	// goto loc_268;
loc_29c:
 29c:	3b50      	cmpnei	r3, 16
 29e:	0809      	bt	0x2b0	// if (r3 != 0x10) goto loc_2b0;
 2a0:	121b      	lrw	r0, 0x0	// regs: r0=0x0
 2a2:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2a2>, r1=<clobbered>
 2a6:	ea00cf85 	movi	r0, 53125	// regs: r0=0xcf85
 2aa:	c4804900 	rotli	r0, r0, 4	// regs: r0=rotl(0xcf85, 0x4)
 2ae:	07bf      	br	0x22c	// goto loc_22c;
loc_2b0:
 2b0:	3b43      	cmpnei	r3, 3
 2b2:	0809      	bt	0x2c4	// if (r3 != 0x3) goto loc_2c4;
 2b4:	1217      	lrw	r0, 0x0	// regs: r0=0x0
 2b6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2b6>, r1=<clobbered>
 2ba:	ea00d36d 	movi	r0, 54125	// regs: r0=0xd36d
 2be:	c4804900 	rotli	r0, r0, 4	// regs: r0=rotl(0xd36d, 0x4)
 2c2:	07b5      	br	0x22c	// goto loc_22c;
loc_2c4:
 2c4:	1214      	lrw	r0, 0x0	// regs: r0=0x0
 2c6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2c6>, r1=<clobbered>
 2ca:	1214      	lrw	r0, 0xdf638	// regs: r0=0xdf638
 2cc:	07b0      	br	0x22c	// goto loc_22c;
loc_2ce:
 2ce:	d8644002 	ld.bs	r3, (r4, 0x2)	// regs: r3=*(0x2)
 2d2:	e923ffb5 	bnez	r3, 0x23c	// if (r3 != 0x0) goto loc_23c;
loc_2d6:
 2d6:	3500      	movi	r5, 0	// regs: r5=0x0
 2d8:	12ca      	lrw	r6, 0x0	// regs: r6=0x0
loc_2da:
 2da:	6c57      	mov	r1, r5	// regs: r1=r5
 2dc:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
 2de:	6c1b      	mov	r0, r6	// regs: r0=0x0
 2e0:	7554      	zextb	r5, r5	// regs: r5=zext8((r5 + 0x1))
 2e2:	e0000000 	bsr	0x0	// <ah_rfdigicali_tx_dcoc>; regs: r0=<ret ah_rfdigicali_tx_dcoc@0x2e2>, r1=<clobbered>
 2e6:	3d46      	cmpnei	r5, 6
 2e8:	0bf9      	bt	0x2da	// if (r5 != 0x6) goto loc_2da;
loc_2ea:
 2ea:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(0x0)
 2ec:	e90300b0 	bez	r3, 0x44c	// if (r3 == 0x0) goto loc_44c;
 2f0:	d8644003 	ld.bs	r3, (r4, 0x3)	// regs: r3=*(0x3)
 2f4:	e92300ac 	bnez	r3, 0x44c	// if (r3 != 0x0) goto loc_44c;
 2f8:	d8644002 	ld.bs	r3, (r4, 0x2)	// regs: r3=*(0x2)
 2fc:	e92300a8 	bnez	r3, 0x44c	// if (r3 != 0x0) goto loc_44c;
 300:	320f      	movi	r2, 15	// regs: r2=0xf
 302:	6c7b      	mov	r1, r14	// regs: r1=(sp - 0x5c)
 304:	308a      	movi	r0, 138	// regs: r0=0x8a
 306:	e0000000 	bsr	0x0	// <sysctrl_efuse_config_and_read>; regs: r0=<ret sysctrl_efuse_config_and_read@0x306>, r1=<clobbered>
 30a:	d86e0000 	ld.b	r3, (r14, 0x0)	// regs: r3=local_5c
 30e:	e903008b 	bez	r3, 0x424	// if (r3 == 0x0) goto loc_424;
loc_312:
 312:	6d7b      	mov	r5, r14	// regs: r5=sp
 314:	6cbb      	mov	r2, r14	// regs: r2=sp
 316:	3000      	movi	r0, 0	// regs: r0=0x0
loc_318:
 318:	d9820001 	ld.b	r12, (r2, 0x1)	// regs: r12=*(r2 + 0x1)
 31c:	1260      	lrw	r3, 0x0	// regs: r3=0x0
 31e:	c50c4821 	lsli	r1, r12, 8	// regs: r1=(*(r2 + 0x1) << 0x8)
 322:	c460002d 	addu	r13, r0, r3	// regs: r13=(r0 )
 326:	e4212300 	andi	r1, r1, 768	// regs: r1=((*(r2 + 0x1) << 0x8) & 0x300)
 32a:	8260      	ld.b	r3, (r2, 0x0)	// regs: r3=*(r2)
 32c:	6c4c      	or	r1, r3	// regs: r1=(((*(r2 + 0x1) << 0x8) & 0x300) | *(r2))
 32e:	8262      	ld.b	r3, (r2, 0x2)	// regs: r3=*(r2 + 0x2)
 330:	4364      	lsli	r3, r3, 4	// regs: r3=(*(r2 + 0x2) << 0x4)
 332:	2003      	addi	r0, 4	// regs: r0=(r0 + 0x4)
 334:	e46323f0 	andi	r3, r3, 1008	// regs: r3=((*(r2 + 0x2) << 0x4) & 0x3f0)
 338:	c48c484c 	lsri	r12, r12, 4	// regs: r12=(*(r2 + 0x1) >> 0x4)
 33c:	384c      	cmpnei	r0, 12
 33e:	6cf0      	or	r3, r12	// regs: r3=(((*(r2 + 0x2) << 0x4) & 0x3f0) | (*(r2 + 0x1) >> 0x4))
 340:	dc2d102a 	st.h	r1, (r13, 0x54)	// *(((r0 ) + 0x54)) = (((*(r2 + 0x1) << 0x8) & 0x300) | *(r2))
 344:	dc6d102b 	st.h	r3, (r13, 0x56)	// *(((r0 ) + 0x56)) = (((*(r2 + 0x2) << 0x4) & 0x3f0) | (*(r2 + 0x1) >> 0x4))
 348:	2202      	addi	r2, 3	// regs: r2=(r2 + 0x3)
 34a:	0be7      	bt	0x318	// if (r0 != 0xc) goto loc_318;
 34c:	d86e000a 	ld.b	r3, (r14, 0xa)	// regs: r3=stack_pa
 350:	4368      	lsli	r3, r3, 8	// regs: r3=(stack_pa << 0x8)
 352:	11d4      	lrw	r6, 0x0	// regs: r6=0x0
 354:	d84e0009 	ld.b	r2, (r14, 0x9)	// regs: r2=stack_p9
 358:	e4632f00 	andi	r3, r3, 3840	// regs: r3=((stack_pa << 0x8) & 0xf00)
 35c:	6cc8      	or	r3, r2	// regs: r3=(((stack_pa << 0x8) & 0xf00) | stack_p9)
 35e:	ae75      	st.h	r3, (r6, 0x2a)	// *(0x2a) = (((stack_pa << 0x8) & 0xf00) | stack_p9)
 360:	d86e000c 	ld.b	r3, (r14, 0xc)	// regs: r3=stack_pc
 364:	4368      	lsli	r3, r3, 8	// regs: r3=(stack_pc << 0x8)
 366:	d84e000b 	ld.b	r2, (r14, 0xb)	// regs: r2=stack_pb
 36a:	e4632f00 	andi	r3, r3, 3840	// regs: r3=((stack_pc << 0x8) & 0xf00)
 36e:	6cc8      	or	r3, r2	// regs: r3=(((stack_pc << 0x8) & 0xf00) | stack_pb)
 370:	ae76      	st.h	r3, (r6, 0x2c)	// *(0x2c) = (((stack_pc << 0x8) & 0xf00) | stack_pb)
 372:	d86e000e 	ld.b	r3, (r14, 0xe)	// regs: r3=stack_pe
 376:	4368      	lsli	r3, r3, 8	// regs: r3=(stack_pe << 0x8)
 378:	d84e000d 	ld.b	r2, (r14, 0xd)	// regs: r2=stack_pd
 37c:	e4632f00 	andi	r3, r3, 3840	// regs: r3=((stack_pe << 0x8) & 0xf00)
 380:	6cc8      	or	r3, r2	// regs: r3=(((stack_pe << 0x8) & 0xf00) | stack_pd)
 382:	6c7b      	mov	r1, r14	// regs: r1=sp
 384:	320f      	movi	r2, 15	// regs: r2=0xf
 386:	30f0      	movi	r0, 240	// regs: r0=0xf0
 388:	ae77      	st.h	r3, (r6, 0x2e)	// *(0x2e) = (((stack_pe << 0x8) & 0xf00) | stack_pd)
 38a:	e0000000 	bsr	0x0	// <sysctrl_efuse_config_and_read>; regs: r0=<ret sysctrl_efuse_config_and_read@0x38a>, r1=<clobbered>
 38e:	d82e0000 	ld.b	r1, (r14, 0x0)	// regs: r1=stack_0
 392:	6c9b      	mov	r2, r6	// regs: r2=0x0
 394:	e921006e 	bnez	r1, 0x470	// if (r1 != 0x0) goto loc_470;
 398:	d86e0001 	ld.b	r3, (r14, 0x1)	// regs: r3=stack_p1
 39c:	e923006a 	bnez	r3, 0x470	// if (r3 != 0x0) goto loc_470;
 3a0:	d82e0003 	ld.b	r1, (r14, 0x3)	// regs: r1=stack_p3
 3a4:	e9210067 	bnez	r1, 0x472	// if (r1 != 0x0) goto loc_472;
 3a8:	d86e0004 	ld.b	r3, (r14, 0x4)	// regs: r3=stack_p4
 3ac:	e923000a 	bnez	r3, 0x3c0	// if (r3 != 0x0) goto loc_3c0;
 3b0:	d82e0006 	ld.b	r1, (r14, 0x6)	// regs: r1=stack_p6
 3b4:	e921005f 	bnez	r1, 0x472	// if (r1 != 0x0) goto loc_472;
 3b8:	d86e0007 	ld.b	r3, (r14, 0x7)	// regs: r3=stack_p7
 3bc:	e90300b5 	bez	r3, 0x526	// if (r3 == 0x0) goto loc_526;
loc_3c0:
 3c0:	6cc7      	mov	r3, r1	// regs: r3=r1
 3c2:	0458      	br	0x472	// goto loc_472;
 3c4:	40026000 	.long	0x40026000
 3c8:	00000000 	.long	0x00000000	// <module_efuse_info>
 3cc:	00000000 	.long	0x00000000	// <.rodata.ah_rf_open.str1.1>
 3d0:	00000000 	.long	0x00000000	// <.rodata.ah_rf_open.str1.1+0x29>
 3d4:	00000000 	.long	0x00000000	// <.rodata.ah_rf_open.str1.1+0x54>
 3d8:	00000000 	.long	0x00000000	// <rf_agc_reg_hw_val_rx_810M>
 3dc:	00000000 	.long	0x00000000	// <rf_agc_reg_hw_val>
 3e0:	00000000 	.long	0x00000000	// <rf_agc_reg_hw_val_tx_790M-0x50>
 3e4:	00000000 	.long	0x00000000	// <rf_agcbw_reg_hw_val>
 3e8:	00000000 	.long	0x00000000	// <rf_agcbw_reg_hw_val_rx_750M>
 3ec:	00000000 	.long	0x00000000	// <.rodata.ah_rf_open.str1.1+0x66>
 3f0:	00000000 	.long	0x00000000	// <rf_agc_reg_hw_val+0x4>
 3f4:	00000000 	.long	0x00000000	// <rf_agcbw_reg_hw_val_rx_850M>
 3f8:	00000000 	.long	0x00000000	// <.rodata.ah_rf_open.str1.1+0x8e>
 3fc:	00000000 	.long	0x00000000	// <.rodata.ah_rf_open.str1.1+0xd1>
 400:	00000000 	.long	0x00000000	// <tx_dcoc_res>
 404:	00000000 	.long	0x00000000	// <.rodata.ah_rf_open.str1.1+0x77>
 408:	00000000 	.long	0x00000000	// <.rodata.ah_rf_open.str1.1+0xaf>
 40c:	00000000 	.long	0x00000000	// <.rodata.ah_rf_open.str1.1+0xe4>
 410:	00000000 	.long	0x00000000	// <.rodata.ah_rf_open.str1.1+0xf7>
 414:	00000000 	.long	0x00000000	// <.rodata.ah_rf_open.str1.1+0x10a>
 418:	000df638 	.long	0x000df638
 41c:	00000000 	.long	0x00000000	// <rx_dcoc_res>
 420:	00000000 	.long	0x00000000	// <DSLEEP_PARAM>
loc_424:
 424:	d86e0001 	ld.b	r3, (r14, 0x1)	// regs: r3=stack_p1
 428:	e923ff75 	bnez	r3, 0x312	// if (r3 != 0x0) goto loc_312;
 42c:	d86e0003 	ld.b	r3, (r14, 0x3)	// regs: r3=stack_p3
 430:	e923ff71 	bnez	r3, 0x312	// if (r3 != 0x0) goto loc_312;
 434:	d86e0004 	ld.b	r3, (r14, 0x4)	// regs: r3=stack_p4
 438:	e923ff6d 	bnez	r3, 0x312	// if (r3 != 0x0) goto loc_312;
 43c:	d86e0006 	ld.b	r3, (r14, 0x6)	// regs: r3=stack_p6
 440:	e923ff69 	bnez	r3, 0x312	// if (r3 != 0x0) goto loc_312;
 444:	d86e0007 	ld.b	r3, (r14, 0x7)	// regs: r3=stack_p7
 448:	e923ff65 	bnez	r3, 0x312	// if (r3 != 0x0) goto loc_312;
loc_44c:
 44c:	1d04      	addi	r5, r14, 16	// regs: r5=(sp + 0x10)
 44e:	3213      	movi	r2, 19	// regs: r2=0x13
 450:	6c57      	mov	r1, r5	// regs: r1=(sp + 0x10)
 452:	3003      	movi	r0, 3	// regs: r0=0x3
 454:	e0000000 	bsr	0x0	// <memory_read>; regs: r0=<ret memory_read@0x454>, r1=<clobbered>
 458:	e9200007 	bnez	r0, 0x466	// if (r0 != 0x0) goto loc_466;
 45c:	d8655024 	ld.hs	r3, (r5, 0x48)	// regs: r3=stack_p58
 460:	eb430055 	cmpnei	r3, 85
 464:	0c73      	bf	0x54a	// if (r3 == 0x55) goto loc_54a;
loc_466:
 466:	e0000000 	bsr	0x0	// <ah_rf_rx_dcoc_calib> // arg_bytes: 0; regs: r0=<ret ah_rf_rx_dcoc_calib@0x466>, r1=<clobbered>
 46a:	3200      	movi	r2, 0	// regs: r2=0x0
 46c:	6ccb      	mov	r3, r2	// regs: r3=0x0
 46e:	04c1      	br	0x5f0	// goto loc_5f0;
loc_470:
 470:	3300      	movi	r3, 0	// regs: r3=0x0
loc_472:
 472:	d9850001 	ld.b	r12, (r5, 0x1)	// regs: r12=*(r5 + 0x1)
 476:	ea81011c 	lrw	r1, 0x0	// regs: r1=0x0
 47a:	c50c4820 	lsli	r0, r12, 8	// regs: r0=(*(r5 + 0x1) << 0x8)
 47e:	c423002d 	addu	r13, r3, r1	// regs: r13=(r3 )
 482:	e4002300 	andi	r0, r0, 768	// regs: r0=((*(r5 + 0x1) << 0x8) & 0x300)
 486:	8520      	ld.b	r1, (r5, 0x0)	// regs: r1=*(r5)
 488:	6c04      	or	r0, r1	// regs: r0=(((*(r5 + 0x1) << 0x8) & 0x300) | *(r5))
 48a:	8522      	ld.b	r1, (r5, 0x2)	// regs: r1=*(r5 + 0x2)
 48c:	4124      	lsli	r1, r1, 4	// regs: r1=(*(r5 + 0x2) << 0x4)
 48e:	2303      	addi	r3, 4	// regs: r3=(r3 + 0x4)
 490:	e42123f0 	andi	r1, r1, 1008	// regs: r1=((*(r5 + 0x2) << 0x4) & 0x3f0)
 494:	c48c484c 	lsri	r12, r12, 4	// regs: r12=(*(r5 + 0x1) >> 0x4)
 498:	3b4c      	cmpnei	r3, 12
 49a:	6c70      	or	r1, r12	// regs: r1=(((*(r5 + 0x2) << 0x4) & 0x3f0) | (*(r5 + 0x1) >> 0x4))
 49c:	dc0d1024 	st.h	r0, (r13, 0x48)	// *(((r3 ) + 0x48)) = (((*(r5 + 0x1) << 0x8) & 0x300) | *(r5))
 4a0:	dc2d1025 	st.h	r1, (r13, 0x4a)	// *(((r3 ) + 0x4a)) = (((*(r5 + 0x2) << 0x4) & 0x3f0) | (*(r5 + 0x1) >> 0x4))
 4a4:	2502      	addi	r5, 3	// regs: r5=(r5 + 0x3)
 4a6:	0be6      	bt	0x472	// if (r3 != 0xc) goto loc_472;
 4a8:	d86e000a 	ld.b	r3, (r14, 0xa)	// regs: r3=stack_pa
 4ac:	4368      	lsli	r3, r3, 8	// regs: r3=(stack_pa << 0x8)
 4ae:	d82e0009 	ld.b	r1, (r14, 0x9)	// regs: r1=stack_p9
 4b2:	e4632f00 	andi	r3, r3, 3840	// regs: r3=((stack_pa << 0x8) & 0xf00)
 4b6:	6cc4      	or	r3, r1	// regs: r3=(((stack_pa << 0x8) & 0xf00) | stack_p9)
 4b8:	aa72      	st.h	r3, (r2, 0x24)	// *(0x24) = (((stack_pa << 0x8) & 0xf00) | stack_p9)
 4ba:	d86e000c 	ld.b	r3, (r14, 0xc)	// regs: r3=stack_pc
 4be:	4368      	lsli	r3, r3, 8	// regs: r3=(stack_pc << 0x8)
 4c0:	d82e000b 	ld.b	r1, (r14, 0xb)	// regs: r1=stack_pb
 4c4:	e4632f00 	andi	r3, r3, 3840	// regs: r3=((stack_pc << 0x8) & 0xf00)
 4c8:	6cc4      	or	r3, r1	// regs: r3=(((stack_pc << 0x8) & 0xf00) | stack_pb)
 4ca:	aa73      	st.h	r3, (r2, 0x26)	// *(0x26) = (((stack_pc << 0x8) & 0xf00) | stack_pb)
 4cc:	d86e000e 	ld.b	r3, (r14, 0xe)	// regs: r3=stack_pe
 4d0:	4368      	lsli	r3, r3, 8	// regs: r3=(stack_pe << 0x8)
 4d2:	e4632f00 	andi	r3, r3, 3840	// regs: r3=((stack_pe << 0x8) & 0xf00)
 4d6:	d82e000d 	ld.b	r1, (r14, 0xd)	// regs: r1=stack_pd
 4da:	6cc4      	or	r3, r1	// regs: r3=(((stack_pe << 0x8) & 0xf00) | stack_pd)
loc_4dc:
 4dc:	aa74      	st.h	r3, (r2, 0x28)	// *(0x28) = r3
 4de:	3300      	movi	r3, 0	// regs: r3=0x0
 4e0:	6f0f      	mov	r12, r3	// regs: r12=0x0
 4e2:	ea860101 	lrw	r6, 0x0	// regs: r6=0x0
loc_4e6:
 4e6:	c5860080 	subu	r0, r6, r12	// regs: r0=(0x0 - r12)
 4ea:	3100      	movi	r1, 0	// regs: r1=0x0
 4ec:	5aac      	addu	r5, r2, r3	// regs: r5=(0x0 + r3)
loc_4ee:
 4ee:	c580002d 	addu	r13, r0, r12	// regs: r13=(r0 + r12)
 4f2:	d8ed1024 	ld.h	r7, (r13, 0x48)	// regs: r7=*(((r0 + r12) + 0x48))
 4f6:	a8e0      	st.h	r7, (r0, 0x0)	// *(r0) = *(((r0 + r12) + 0x48))
 4f8:	d9ad1025 	ld.h	r13, (r13, 0x4a)	// regs: r13=*(((r0 + r12) + 0x4a))
 4fc:	dda01001 	st.h	r13, (r0, 0x2)	// *(r0 + 0x2) = *(((r0 + r12) + 0x4a))
 500:	c422002d 	addu	r13, r2, r1	// regs: r13=(0x0 + r1)
 504:	2003      	addi	r0, 4	// regs: r0=(r0 + 0x4)
 506:	d9ad1012 	ld.h	r13, (r13, 0x24)	// regs: r13=*(((0x0 + r1) + 0x24))
 50a:	d425042d 	str.h	r13, (r5, r1 << 0)
 50e:	2101      	addi	r1, 2	// regs: r1=(r1 + 0x2)
 510:	394c      	cmpnei	r1, 12
 512:	0bee      	bt	0x4ee	// if (r1 != 0xc) goto loc_4ee;
 514:	230b      	addi	r3, 12	// regs: r3=(r3 + 0xc)
 516:	eb430024 	cmpnei	r3, 36
 51a:	e58c1017 	subi	r12, r12, 24	// regs: r12=(r12 - 0x18)
 51e:	0be4      	bt	0x4e6	// if (r3 != 0x24) goto loc_4e6;
loc_520:
 520:	3700      	movi	r7, 0	// regs: r7=0x0
 522:	6d5f      	mov	r5, r7	// regs: r5=0x0
 524:	04e9      	br	0x6f6	// goto loc_6f6;
loc_526:
 526:	000f      	lrw	r0, 0x0	// regs: r0=0x0
loc_528:
 528:	0030      	lrw	r1, 0x0	// regs: r1=0x0
 52a:	604c      	addu	r1, r3	// regs: r1=(0x0 + r3)
 52c:	d980102a 	ld.h	r12, (r0, 0x54)	// regs: r12=*(0x54)
 530:	2303      	addi	r3, 4	// regs: r3=(r3 + 0x4)
 532:	dd811024 	st.h	r12, (r1, 0x48)	// *(((0x0 + r3) + 0x48)) = *(0x54)
 536:	3b4c      	cmpnei	r3, 12
 538:	d980102b 	ld.h	r12, (r0, 0x56)	// regs: r12=*(0x56)
 53c:	dd811025 	st.h	r12, (r1, 0x4a)	// *(((0x0 + r3) + 0x4a)) = *(0x56)
 540:	0bf4      	bt	0x528	// if (r3 != 0xc) goto loc_528;
 542:	8a75      	ld.h	r3, (r2, 0x2a)	// regs: r3=*(0x2a)
 544:	aa72      	st.h	r3, (r2, 0x24)	// *(0x24) = *(0x2a)
 546:	aa73      	st.h	r3, (r2, 0x26)	// *(0x26) = *(0x2a)
 548:	07ca      	br	0x4dc	// goto loc_4dc;
loc_54a:
 54a:	6cc3      	mov	r3, r0	// regs: r3=<ret memory_read@0x454>
loc_54c:
 54c:	0058      	lrw	r2, 0x0	// regs: r2=0x0
 54e:	5828      	addu	r1, r0, r2	// regs: r1=(r0 )
 550:	5b56      	addi	r2, r3, 6	// regs: r2=(r3 + 0x6)
 552:	7488      	zextb	r2, r2	// regs: r2=zext8((r3 + 0x6))
loc_554:
 554:	e5830000 	addi	r12, r3, 1	// regs: r12=(r3 + 0x1)
 558:	d065044d 	ldr.h	r13, (r5, r3 << 1)	// regs: r13=*((sp + 0x10) + (r3 << 1))
 55c:	2301      	addi	r3, 2	// regs: r3=(r3 + 0x2)
 55e:	74cc      	zextb	r3, r3	// regs: r3=zext8((r3 + 0x2))
 560:	7730      	zextb	r12, r12	// regs: r12=zext8((r3 + 0x1))
 562:	64ca      	cmpne	r2, r3
 564:	d185044c 	ldr.h	r12, (r5, r12 << 1)	// regs: r12=*((sp + 0x10) + (zext8((r3 + 0x1)) << 1))
 568:	dda11000 	st.h	r13, (r1, 0x0)	// *(r1) = *((sp + 0x10) + (r3 << 1))
 56c:	dd811001 	st.h	r12, (r1, 0x2)	// *(r1 + 0x2) = *((sp + 0x10) + (zext8((r3 + 0x1)) << 1))
 570:	2103      	addi	r1, 4	// regs: r1=(r1 + 0x4)
 572:	0bf1      	bt	0x554	// if (T) goto loc_554;
 574:	3a58      	cmpnei	r2, 24
 576:	2017      	addi	r0, 24	// regs: r0=(r0 + 0x18)
 578:	0bea      	bt	0x54c	// if (r2 != 0x18) goto loc_54c;
 57a:	0162      	lrw	r3, 0x0	// regs: r3=0x0
 57c:	3200      	movi	r2, 0	// regs: r2=0x0
loc_57e:
 57e:	5d28      	addu	r1, r5, r2	// regs: r1=((sp + 0x10) + r2)
 580:	2205      	addi	r2, 6	// regs: r2=(r2 + 0x6)
 582:	8918      	ld.h	r0, (r1, 0x30)	// regs: r0=*((((sp + 0x10) + r2) + 0x30))
 584:	3a58      	cmpnei	r2, 24
 586:	ab00      	st.h	r0, (r3, 0x0)	// *(r3) = *((((sp + 0x10) + r2) + 0x30))
 588:	8919      	ld.h	r0, (r1, 0x32)	// regs: r0=*((((sp + 0x10) + r2) + 0x32))
 58a:	893a      	ld.h	r1, (r1, 0x34)	// regs: r1=*((((sp + 0x10) + r2) + 0x34))
 58c:	ab01      	st.h	r0, (r3, 0x2)	// *(r3 + 0x2) = *((((sp + 0x10) + r2) + 0x32))
 58e:	ab22      	st.h	r1, (r3, 0x4)	// *(r3 + 0x4) = *((((sp + 0x10) + r2) + 0x34))
 590:	230b      	addi	r3, 12	// regs: r3=(r3 + 0xc)
 592:	0bf6      	bt	0x57e	// if (r2 != 0x18) goto loc_57e;
 594:	016b      	lrw	r3, 0x0	// regs: r3=0x0
 596:	3200      	movi	r2, 0	// regs: r2=0x0
 598:	ea8d00d6 	lrw	r13, 0x0	// regs: r13=0x0
 59c:	0412      	br	0x5c0	// goto loc_5c0;
loc_59e:
 59e:	8ba6      	ld.h	r5, (r3, 0xc)	// regs: r5=*(r3 + 0xc)
 5a0:	a8a0      	st.h	r5, (r0, 0x0)	// *(r0) = *(r3 + 0xc)
 5a2:	8ba7      	ld.h	r5, (r3, 0xe)	// regs: r5=*(r3 + 0xe)
 5a4:	a8a1      	st.h	r5, (r0, 0x2)	// *(r0 + 0x2) = *(r3 + 0xe)
 5a6:	d8ac1003 	ld.h	r5, (r12, 0x6)	// regs: r5=*(r12 + 0x6)
 5aa:	d42c0445 	str.h	r5, (r12, r1 << 1)
 5ae:	2100      	addi	r1, 1	// regs: r1=(r1 + 0x1)
 5b0:	3943      	cmpnei	r1, 3
 5b2:	2003      	addi	r0, 4	// regs: r0=(r0 + 0x4)
 5b4:	0bf5      	bt	0x59e	// if (r1 != 0x3) goto loc_59e;
 5b6:	220b      	addi	r2, 12	// regs: r2=(r2 + 0xc)
 5b8:	eb420030 	cmpnei	r2, 48
 5bc:	2317      	addi	r3, 24	// regs: r3=(r3 + 0x18)
 5be:	0fb1      	bf	0x520	// if (r2 == 0x30) goto loc_520;
loc_5c0:
 5c0:	6c0f      	mov	r0, r3	// regs: r0=r3
 5c2:	3100      	movi	r1, 0	// regs: r1=0x0
 5c4:	c44d002c 	addu	r12, r13, r2	// regs: r12=(r13 + r2)
 5c8:	07eb      	br	0x59e	// goto loc_59e;
loc_5ca:
 5ca:	d9a01000 	ld.h	r13, (r0, 0x0)	// regs: r13=*(r0)
 5ce:	d465044d 	str.h	r13, (r5, r3 << 1)
 5d2:	e5830000 	addi	r12, r3, 1	// regs: r12=(r3 + 0x1)
 5d6:	2301      	addi	r3, 2	// regs: r3=(r3 + 0x2)
 5d8:	74cc      	zextb	r3, r3	// regs: r3=zext8((r3 + 0x2))
 5da:	64c6      	cmpne	r1, r3
 5dc:	d9a01001 	ld.h	r13, (r0, 0x2)	// regs: r13=*(r0 + 0x2)
 5e0:	7730      	zextb	r12, r12	// regs: r12=zext8((r3 + 0x1))
 5e2:	d585044d 	str.h	r13, (r5, r12 << 1)
 5e6:	2003      	addi	r0, 4	// regs: r0=(r0 + 0x4)
 5e8:	0bf1      	bt	0x5ca	// if (T) goto loc_5ca;
 5ea:	3958      	cmpnei	r1, 24
 5ec:	2217      	addi	r2, 24	// regs: r2=(r2 + 0x18)
 5ee:	0c06      	bf	0x5fa	// if (r1 == 0x18) goto loc_5fa;
loc_5f0:
 5f0:	0221      	lrw	r1, 0x0	// regs: r1=0x0
 5f2:	5a04      	addu	r0, r2, r1	// regs: r0=(r2 )
 5f4:	5b36      	addi	r1, r3, 6	// regs: r1=(r3 + 0x6)
 5f6:	7444      	zextb	r1, r1	// regs: r1=zext8((r3 + 0x6))
 5f8:	07e9      	br	0x5ca	// goto loc_5ca;
loc_5fa:
 5fa:	0262      	lrw	r3, 0x0	// regs: r3=0x0
 5fc:	3200      	movi	r2, 0	// regs: r2=0x0
loc_5fe:
 5fe:	5d28      	addu	r1, r5, r2	// regs: r1=(r5 + r2)
 600:	8b00      	ld.h	r0, (r3, 0x0)	// regs: r0=*(r3)
 602:	2205      	addi	r2, 6	// regs: r2=(r2 + 0x6)
 604:	a918      	st.h	r0, (r1, 0x30)	// *(((r5 + r2) + 0x30)) = *(r3)
 606:	3a58      	cmpnei	r2, 24
 608:	8b01      	ld.h	r0, (r3, 0x2)	// regs: r0=*(r3 + 0x2)
 60a:	a919      	st.h	r0, (r1, 0x32)	// *(((r5 + r2) + 0x32)) = *(r3 + 0x2)
 60c:	8b02      	ld.h	r0, (r3, 0x4)	// regs: r0=*(r3 + 0x4)
 60e:	a91a      	st.h	r0, (r1, 0x34)	// *(((r5 + r2) + 0x34)) = *(r3 + 0x4)
 610:	230b      	addi	r3, 12	// regs: r3=(r3 + 0xc)
 612:	0bf6      	bt	0x5fe	// if (r2 != 0x18) goto loc_5fe;
 614:	3212      	movi	r2, 18	// regs: r2=0x12
 616:	6c57      	mov	r1, r5	// regs: r1=r5
 618:	3003      	movi	r0, 3	// regs: r0=0x3
 61a:	e0000000 	bsr	0x0	// <memory_write>; regs: r0=<ret memory_write@0x61a>, r1=<clobbered>
 61e:	3300      	movi	r3, 0	// regs: r3=0x0
 620:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 622:	64c2      	cmpne	r0, r3
 624:	0e2a      	bf	0x278	// if (!T) goto loc_278;
loc_626:
 626:	d8644003 	ld.bs	r3, (r4, 0x3)	// regs: r3=*(r4 + 0x3)
 62a:	02ec      	lrw	r7, 0x0	// regs: r7=0x0
 62c:	02cc      	lrw	r6, 0x0	// regs: r6=0x0
 62e:	e9230006 	bnez	r3, 0x63a	// if (r3 != 0x0) goto loc_63a;
 632:	d8644002 	ld.bs	r3, (r4, 0x2)	// regs: r3=*(r4 + 0x2)
 636:	e9030014 	bez	r3, 0x65e	// if (r3 == 0x0) goto loc_65e;
loc_63a:
 63a:	3203      	movi	r2, 3	// regs: r2=0x3
 63c:	1904      	addi	r1, r14, 16	// regs: r1=(sp + 0x10)
 63e:	3002      	movi	r0, 2	// regs: r0=0x2
 640:	e0000000 	bsr	0x0	// <memory_read>; regs: r0=<ret memory_read@0x640>, r1=<clobbered>
 644:	e92001c1 	bnez	r0, 0x9c6	// if (r0 != 0x0) goto loc_9c6;
 648:	d86e500c 	ld.hs	r3, (r14, 0x18)	// regs: r3=stack_p18
 64c:	eb430055 	cmpnei	r3, 85
 650:	09bb      	bt	0x9c6	// if (r3 != 0x55) goto loc_9c6;
 652:	d86e100a 	ld.h	r3, (r14, 0x14)	// regs: r3=stack_p14
 656:	af60      	st.h	r3, (r7, 0x0)	// *(0x0) = stack_p14
 658:	d86e100b 	ld.h	r3, (r14, 0x16)	// regs: r3=stack_p16
 65c:	ae60      	st.h	r3, (r6, 0x0)	// *(0x0) = stack_p16
loc_65e:
 65e:	3500      	movi	r5, 0	// regs: r5=0x0
loc_660:
 660:	6c97      	mov	r2, r5	// regs: r2=r5
 662:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
 664:	8e20      	ld.h	r1, (r6, 0x0)	// regs: r1=*(0x0)
 666:	d8075000 	ld.hs	r0, (r7, 0x0)	// regs: r0=*(0x0)
 66a:	7554      	zextb	r5, r5	// regs: r5=zext8((r5 + 0x1))
 66c:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_imb>; regs: r0=<ret ah_rfdigicali_config_tx_imb@0x66c>, r1=<clobbered>
 670:	3d46      	cmpnei	r5, 6
 672:	0bf7      	bt	0x660	// if (r5 != 0x6) goto loc_660;
loc_674:
 674:	d8644003 	ld.bs	r3, (r4, 0x3)	// regs: r3=*(r4 + 0x3)
 678:	e9230150 	bnez	r3, 0x918	// if (r3 != 0x0) goto loc_918;
 67c:	d8644002 	ld.bs	r3, (r4, 0x2)	// regs: r3=*(r4 + 0x2)
 680:	e923014c 	bnez	r3, 0x918	// if (r3 != 0x0) goto loc_918;
 684:	320f      	movi	r2, 15	// regs: r2=0xf
 686:	1904      	addi	r1, r14, 16	// regs: r1=(sp + 0x10)
 688:	ea00010d 	movi	r0, 269	// regs: r0=0x10d
 68c:	e0000000 	bsr	0x0	// <sysctrl_efuse_config_and_read>; regs: r0=<ret sysctrl_efuse_config_and_read@0x68c>, r1=<clobbered>
 690:	d86e0010 	ld.b	r3, (r14, 0x10)	// regs: r3=stack_p10
 694:	e9030033 	bez	r3, 0x6fa	// if (r3 == 0x0) goto loc_6fa;
loc_698:
 698:	e58e000f 	addi	r12, r14, 16	// regs: r12=(sp + 0x10)
 69c:	3000      	movi	r0, 0	// regs: r0=0x0
loc_69e:
 69e:	d82c0001 	ld.b	r1, (r12, 0x1)	// regs: r1=*(r12 + 0x1)
 6a2:	4148      	lsli	r2, r1, 8	// regs: r2=(*(r12 + 0x1) << 0x8)
 6a4:	0369      	lrw	r3, 0x0	// regs: r3=0x0
 6a6:	60c0      	addu	r3, r0	// regs: r3=(0x0 + r0)
 6a8:	d9ac0000 	ld.b	r13, (r12, 0x0)	// regs: r13=*(r12)
 6ac:	e4422f00 	andi	r2, r2, 3840	// regs: r2=((*(r12 + 0x1) << 0x8) & 0xf00)
 6b0:	6cb4      	or	r2, r13	// regs: r2=(((*(r12 + 0x1) << 0x8) & 0xf00) | *(r12))
 6b2:	ab41      	st.h	r2, (r3, 0x2)	// *(((0x0 + r0) + 0x2)) = (((*(r12 + 0x1) << 0x8) & 0xf00) | *(r12))
 6b4:	4924      	lsri	r1, r1, 4	// regs: r1=(*(r12 + 0x1) >> 0x4)
 6b6:	036c      	lrw	r3, 0x0	// regs: r3=0x0
 6b8:	584c      	addu	r2, r0, r3	// regs: r2=(r0 )
 6ba:	d86c0002 	ld.b	r3, (r12, 0x2)	// regs: r3=*(r12 + 0x2)
 6be:	4364      	lsli	r3, r3, 4	// regs: r3=(*(r12 + 0x2) << 0x4)
 6c0:	2001      	addi	r0, 2	// regs: r0=(r0 + 0x2)
 6c2:	e46323f0 	andi	r3, r3, 1008	// regs: r3=((*(r12 + 0x2) << 0x4) & 0x3f0)
 6c6:	384a      	cmpnei	r0, 10
 6c8:	6cc4      	or	r3, r1	// regs: r3=(((*(r12 + 0x2) << 0x4) & 0x3f0) | (*(r12 + 0x1) >> 0x4))
 6ca:	aa61      	st.h	r3, (r2, 0x2)	// *(((r0 ) + 0x2)) = (((*(r12 + 0x2) << 0x4) & 0x3f0) | (*(r12 + 0x1) >> 0x4))
 6cc:	e58c0002 	addi	r12, r12, 3	// regs: r12=(r12 + 0x3)
 6d0:	0be7      	bt	0x69e	// if (r0 != 0xa) goto loc_69e;
loc_6d2:
 6d2:	3500      	movi	r5, 0	// regs: r5=0x0
 6d4:	0557      	br	0x982	// goto loc_982;
loc_6d6:
 6d6:	5f18      	addu	r0, r7, r6	// regs: r0=(r7 + r6)
 6d8:	037c      	lrw	r3, 0x0	// regs: r3=0x0
 6da:	4002      	lsli	r0, r0, 2	// regs: r0=((r7 + r6) << 0x2)
 6dc:	7458      	zextb	r1, r6	// regs: r1=zext8(r6)
 6de:	6c97      	mov	r2, r5	// regs: r2=r5
 6e0:	600c      	addu	r0, r3	// regs: r0=(((r7 + r6) << 0x2) )
 6e2:	2600      	addi	r6, 1	// regs: r6=(r6 + 0x1)
 6e4:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_dcoc>; regs: r0=<ret ah_rfdigicali_config_rx_dcoc@0x6e4>, r1=<clobbered>
 6e8:	3e46      	cmpnei	r6, 6
 6ea:	0bf6      	bt	0x6d6	// if (r6 != 0x6) goto loc_6d6;
 6ec:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
 6ee:	7554      	zextb	r5, r5	// regs: r5=zext8((r5 + 0x1))
 6f0:	3d44      	cmpnei	r5, 4
 6f2:	2705      	addi	r7, 6	// regs: r7=(r7 + 0x6)
 6f4:	0f99      	bf	0x626	// if (r5 == 0x4) goto loc_626;
loc_6f6:
 6f6:	3600      	movi	r6, 0	// regs: r6=0x0
 6f8:	07ef      	br	0x6d6	// goto loc_6d6;
loc_6fa:
 6fa:	d86e0011 	ld.b	r3, (r14, 0x11)	// regs: r3=stack_p11
 6fe:	e923ffcd 	bnez	r3, 0x698	// if (r3 != 0x0) goto loc_698;
 702:	d86e0012 	ld.b	r3, (r14, 0x12)	// regs: r3=stack_p12
 706:	e923ffc9 	bnez	r3, 0x698	// if (r3 != 0x0) goto loc_698;
 70a:	d86e0013 	ld.b	r3, (r14, 0x13)	// regs: r3=stack_p13
 70e:	e923ffc5 	bnez	r3, 0x698	// if (r3 != 0x0) goto loc_698;
 712:	d86e0014 	ld.b	r3, (r14, 0x14)	// regs: r3=stack_p14
 716:	e923ffc1 	bnez	r3, 0x698	// if (r3 != 0x0) goto loc_698;
 71a:	d86e0015 	ld.b	r3, (r14, 0x15)	// regs: r3=stack_p15
 71e:	e923ffbd 	bnez	r3, 0x698	// if (r3 != 0x0) goto loc_698;
loc_722:
 722:	1379      	lrw	r3, 0x40026000	// regs: r3=0x40026000
 724:	3700      	movi	r7, 0	// regs: r7=0x0
 726:	9353      	ld.w	r2, (r3, 0x4c)	// regs: r2=*(0x4002604c)
 728:	3a97      	bclri	r2, 23	// regs: r2=(*(0x4002604c) & ~(0x1 << 0x17))
 72a:	b353      	st.w	r2, (r3, 0x4c)	// *(0x4002604c) = (*(0x4002604c) & ~(0x1 << 0x17))
 72c:	9353      	ld.w	r2, (r3, 0x4c)	// regs: r2=*(0x4002604c)
 72e:	3ab7      	bseti	r2, 23	// regs: r2=(*(0x4002604c) | (0x1 << 0x17))
 730:	b353      	st.w	r2, (r3, 0x4c)	// *(0x4002604c) = (*(0x4002604c) | (0x1 << 0x17))
 732:	6d5f      	mov	r5, r7	// regs: r5=0x0
loc_734:
 734:	1375      	lrw	r3, 0x0	// regs: r3=0x0
 736:	6d97      	mov	r6, r5	// regs: r6=r5
 738:	ea080000 	movi	r8, 0	// regs: r8=0x0
 73c:	c4670029 	addu	r9, r7, r3	// regs: r9=(r7 )
loc_740:
 740:	d1090441 	ldr.h	r1, (r9, r8 << 1)	// regs: r1=*(r9 + (r8 << 1))
 744:	6c1b      	mov	r0, r6	// regs: r0=r6
 746:	7445      	zexth	r1, r1	// regs: r1=zext16(*(r9 + (r8 << 1)))
 748:	e5080000 	addi	r8, r8, 1	// regs: r8=(r8 + 0x1)
 74c:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x74c>, r1=<clobbered>
 750:	eb480022 	cmpnei	r8, 34
 754:	2600      	addi	r6, 1	// regs: r6=(r6 + 0x1)
 756:	7599      	zexth	r6, r6	// regs: r6=zext16((r6 + 0x1))
 758:	0bf4      	bt	0x740	// if (r8 != 0x22) goto loc_740;
 75a:	253f      	addi	r5, 64	// regs: r5=(r5 + 0x40)
 75c:	7555      	zexth	r5, r5	// regs: r5=zext16((r5 + 0x40))
 75e:	eb450100 	cmpnei	r5, 256
 762:	2743      	addi	r7, 68	// regs: r7=(r7 + 0x44)
 764:	0be8      	bt	0x734	// if (r5 != 0x100) goto loc_734;
 766:	3580      	movi	r5, 128	// regs: r5=0x80
 768:	ea080000 	movi	r8, 0	// regs: r8=0x0
 76c:	45a2      	lsli	r5, r5, 2	// regs: r5=0x200
loc_76e:
 76e:	1368      	lrw	r3, 0x0	// regs: r3=0x0
 770:	6d97      	mov	r6, r5	// regs: r6=r5
 772:	3700      	movi	r7, 0	// regs: r7=0x0
 774:	c4680029 	addu	r9, r8, r3	// regs: r9=(r8 )
loc_778:
 778:	d0e90441 	ldr.h	r1, (r9, r7 << 1)	// regs: r1=*(r9 + (r7 << 1))
 77c:	6c1b      	mov	r0, r6	// regs: r0=r6
 77e:	7445      	zexth	r1, r1	// regs: r1=zext16(*(r9 + (r7 << 1)))
 780:	2700      	addi	r7, 1	// regs: r7=(r7 + 0x1)
 782:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x782>, r1=<clobbered>
 786:	3f49      	cmpnei	r7, 9
 788:	2600      	addi	r6, 1	// regs: r6=(r6 + 0x1)
 78a:	7599      	zexth	r6, r6	// regs: r6=zext16((r6 + 0x1))
 78c:	0bf6      	bt	0x778	// if (r7 != 0x9) goto loc_778;
 78e:	250f      	addi	r5, 16	// regs: r5=(r5 + 0x10)
 790:	7555      	zexth	r5, r5	// regs: r5=zext16((r5 + 0x10))
 792:	eb450300 	cmpnei	r5, 768
 796:	e5080011 	addi	r8, r8, 18	// regs: r8=(r8 + 0x12)
 79a:	0bea      	bt	0x76e	// if (r5 != 0x300) goto loc_76e;
 79c:	3580      	movi	r5, 128	// regs: r5=0x80
 79e:	ea080000 	movi	r8, 0	// regs: r8=0x0
 7a2:	45a3      	lsli	r5, r5, 3	// regs: r5=0x400
loc_7a4:
 7a4:	127b      	lrw	r3, 0x0	// regs: r3=0x0
 7a6:	6d97      	mov	r6, r5	// regs: r6=r5
 7a8:	3700      	movi	r7, 0	// regs: r7=0x0
 7aa:	c4680029 	addu	r9, r8, r3	// regs: r9=(r8 )
loc_7ae:
 7ae:	d0e90441 	ldr.h	r1, (r9, r7 << 1)	// regs: r1=*(r9 + (r7 << 1))
 7b2:	6c1b      	mov	r0, r6	// regs: r0=r6
 7b4:	7445      	zexth	r1, r1	// regs: r1=zext16(*(r9 + (r7 << 1)))
 7b6:	2700      	addi	r7, 1	// regs: r7=(r7 + 0x1)
 7b8:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x7b8>, r1=<clobbered>
 7bc:	3f43      	cmpnei	r7, 3
 7be:	2600      	addi	r6, 1	// regs: r6=(r6 + 0x1)
 7c0:	7599      	zexth	r6, r6	// regs: r6=zext16((r6 + 0x1))
 7c2:	0bf6      	bt	0x7ae	// if (r7 != 0x3) goto loc_7ae;
 7c4:	2507      	addi	r5, 8	// regs: r5=(r5 + 0x8)
 7c6:	7555      	zexth	r5, r5	// regs: r5=zext16((r5 + 0x8))
 7c8:	eb450440 	cmpnei	r5, 1088
 7cc:	e5080005 	addi	r8, r8, 6	// regs: r8=(r8 + 0x6)
 7d0:	0bea      	bt	0x7a4	// if (r5 != 0x440) goto loc_7a4;
 7d2:	35e0      	movi	r5, 224	// regs: r5=0xe0
 7d4:	45a3      	lsli	r5, r5, 3	// regs: r5=0x700
 7d6:	3600      	movi	r6, 0	// regs: r6=0x0
 7d8:	ea89004f 	lrw	r9, 0x0	// regs: r9=0x0
 7dc:	12e5      	lrw	r7, 0x0	// regs: r7=0x0
 7de:	ea080006 	movi	r8, 6	// regs: r8=0x6
loc_7e2:
 7e2:	d0c90481 	ldr.h	r1, (r9, r6 << 2)	// regs: r1=*(0x0 + (r6 << 2))
 7e6:	7445      	zexth	r1, r1	// regs: r1=zext16(*(0x0 + (r6 << 2)))
 7e8:	6c17      	mov	r0, r5	// regs: r0=r5
 7ea:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x7ea>, r1=<clobbered>
 7ee:	c446482a 	lsli	r10, r6, 2	// regs: r10=(r6 << 0x2)
 7f2:	1269      	lrw	r3, 0x0	// regs: r3=0x0
 7f4:	628c      	addu	r10, r3	// regs: r10=((r6 << 0x2) )
 7f6:	76d8      	zextb	r11, r6	// regs: r11=zext8(r6)
 7f8:	d82a1001 	ld.h	r1, (r10, 0x2)	// regs: r1=*((((r6 << 0x2) ) + 0x2))
 7fc:	ea030fff 	movi	r3, 4095	// regs: r3=0xfff
 800:	6cce      	nor	r3, r3	// regs: r3=(~0xfff)
 802:	684c      	and	r1, r3	// regs: r1=(*((((r6 << 0x2) ) + 0x2)) & (~0xfff))
 804:	c46b4843 	lsri	r3, r11, 3	// regs: r3=(zext8(r6) >> 0x3)
 808:	e44b2007 	andi	r2, r11, 7	// regs: r2=(zext8(r6) & 0x7)
 80c:	7ce0      	mult	r3, r8	// regs: r3=((zext8(r6) >> 0x3) * 0x6)
 80e:	60c8      	addu	r3, r2	// regs: r3=(((zext8(r6) >> 0x3) * 0x6) + (zext8(r6) & 0x7))
 810:	d0670443 	ldr.h	r3, (r7, r3 << 1)	// regs: r3=*(0x0 + ((((zext8(r6) >> 0x3) * 0x6) + (zext8(r6) & 0x7)) << 1))
 814:	6c4c      	or	r1, r3	// regs: r1=((*((((r6 << 0x2) ) + 0x2)) & (~0xfff)) | *(0x0 + ((((zext8(r6) >> 0x3) * 0x6) + (zext8(r6) & 0x7)) << 1)))
 816:	5d02      	addi	r0, r5, 1	// regs: r0=(r5 + 0x1)
 818:	7445      	zexth	r1, r1	// regs: r1=zext16(((*((((r6 << 0x2) ) + 0x2)) & (~0xfff)) | *(0x0 + ((((zext8(r6) >> 0x3) * 0x6) + (zext8(r6) & 0x7)) << 1))))
 81a:	7401      	zexth	r0, r0	// regs: r0=zext16((r5 + 0x1))
 81c:	2600      	addi	r6, 1	// regs: r6=(r6 + 0x1)
 81e:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x81e>, r1=<clobbered>
 822:	eb460040 	cmpnei	r6, 64
 826:	2501      	addi	r5, 2	// regs: r5=(r5 + 0x2)
 828:	7555      	zexth	r5, r5	// regs: r5=zext16((r5 + 0x2))
 82a:	0bdc      	bt	0x7e2	// if (r6 != 0x40) goto loc_7e2;
 82c:	30a0      	movi	r0, 160	// regs: r0=0xa0
 82e:	3100      	movi	r1, 0	// regs: r1=0x0
 830:	4001      	lsli	r0, r0, 1	// regs: r0=0x140
 832:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x832>, r1=<clobbered>
 836:	3100      	movi	r1, 0	// regs: r1=0x0
 838:	ea000141 	movi	r0, 321	// regs: r0=0x141
 83c:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x83c>, r1=<clobbered>
 840:	30a1      	movi	r0, 161	// regs: r0=0xa1
 842:	3100      	movi	r1, 0	// regs: r1=0x0
 844:	4001      	lsli	r0, r0, 1	// regs: r0=0x142
 846:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x846>, r1=<clobbered>
 84a:	30c4      	movi	r0, 196	// regs: r0=0xc4
 84c:	3100      	movi	r1, 0	// regs: r1=0x0
 84e:	4002      	lsli	r0, r0, 2	// regs: r0=0x310
 850:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x850>, r1=<clobbered>
 854:	3089      	movi	r0, 137	// regs: r0=0x89
 856:	3100      	movi	r1, 0	// regs: r1=0x0
 858:	4003      	lsli	r0, r0, 3	// regs: r0=0x448
 85a:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x85a>, r1=<clobbered>
 85e:	3100      	movi	r1, 0	// regs: r1=0x0
 860:	ea000782 	movi	r0, 1922	// regs: r0=0x782
 864:	e0000000 	bsr	0x0	// <ah_rfspi_write>; regs: r0=<ret ah_rfspi_write@0x864>, r1=<clobbered>
 868:	e0000000 	bsr	0x0	// <is_xo_cs_calibed>; regs: r0=<ret is_xo_cs_calibed@0x868>, r1=<clobbered>
 86c:	3300      	movi	r3, 0	// regs: r3=0x0
 86e:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 870:	64c2      	cmpne	r0, r3
 872:	0c8f      	bf	0x990	// if (!T) goto loc_990;
 874:	7400      	zextb	r0, r0	// regs: r0=zext8(<ret is_xo_cs_calibed@0x868>)
 876:	e0000000 	bsr	0x0	// <xo_set_cs_sec>; regs: r0=<ret xo_set_cs_sec@0x876>, r1=<clobbered>
 87a:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_xo_ct>; regs: r0=<ret sysctrl_efuse_get_xo_ct@0x87a>, r1=<clobbered>
 87e:	e0000000 	bsr	0x0	// <xo_set_ct_sec>; regs: r0=<ret xo_set_ct_sec@0x87e>, r1=<clobbered>
loc_882:
 882:	3000      	movi	r0, 0	// regs: r0=0x0
 884:	e0000000 	bsr	0x0	// <ah_set_dbgpath_device_path_mode>; regs: r0=<ret ah_set_dbgpath_device_path_mode@0x884>, r1=<clobbered>
 888:	3000      	movi	r0, 0	// regs: r0=0x0
 88a:	e0000000 	bsr	0x0	// <lmac_cfg_rf_en>; regs: r0=<ret lmac_cfg_rf_en@0x88a>, r1=<clobbered>
 88e:	3001      	movi	r0, 1	// regs: r0=0x1
 890:	e0000000 	bsr	0x0	// <lmac_cfg_rf_en>; regs: r0=<ret lmac_cfg_rf_en@0x890>, r1=<clobbered>
 894:	e0000000 	bsr	0x0	// <lmac_rf_hw_ctrl>; regs: r0=<ret lmac_rf_hw_ctrl@0x894>, r1=<clobbered>
 898:	107b      	lrw	r3, 0x40026000	// regs: r3=0x40026000
 89a:	3001      	movi	r0, 1	// regs: r0=0x1
 89c:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*(0x4002601c)
 89e:	3ab3      	bseti	r2, 19	// regs: r2=(*(0x4002601c) | (0x1 << 0x13))
 8a0:	b347      	st.w	r2, (r3, 0x1c)	// *(0x4002601c) = (*(0x4002601c) | (0x1 << 0x13))
 8a2:	9355      	ld.w	r2, (r3, 0x54)	// regs: r2=*(0x40026054)
 8a4:	3a89      	bclri	r2, 9	// regs: r2=(*(0x40026054) & ~(0x1 << 0x9))
 8a6:	b355      	st.w	r2, (r3, 0x54)	// *(0x40026054) = (*(0x40026054) & ~(0x1 << 0x9))
 8a8:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_gain_idx_src>; regs: r0=<ret ah_rfdigicali_config_rx_gain_idx_src@0x8a8>, r1=<clobbered>
 8ac:	3202      	movi	r2, 2	// regs: r2=0x2
 8ae:	1904      	addi	r1, r14, 16	// regs: r1=(sp + 0x10)
 8b0:	3008      	movi	r0, 8	// regs: r0=0x8
 8b2:	e0000000 	bsr	0x0	// <memory_read>; regs: r0=<ret memory_read@0x8b2>, r1=<clobbered>
 8b6:	e920009d 	bnez	r0, 0x9f0	// if (r0 != 0x0) goto loc_9f0;
 8ba:	9865      	ld.w	r3, (r14, 0x14)	// regs: r3=stack_p14
 8bc:	eb430055 	cmpnei	r3, 85
 8c0:	0898      	bt	0x9f0	// if (r3 != 0x55) goto loc_9f0;
 8c2:	d80e1008 	ld.h	r0, (r14, 0x10)	// regs: r0=stack_p10
loc_8c6:
 8c6:	3105      	movi	r1, 5	// regs: r1=0x5
 8c8:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0x8c8>, r1=<clobbered>
 8cc:	3100      	movi	r1, 0	// regs: r1=0x0
 8ce:	302a      	movi	r0, 42	// regs: r0=0x2a
 8d0:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x8d0>, r1=<clobbered>
 8d4:	3103      	movi	r1, 3	// regs: r1=0x3
 8d6:	302b      	movi	r0, 43	// regs: r0=0x2b
 8d8:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x8d8>, r1=<clobbered>
 8dc:	3000      	movi	r0, 0	// regs: r0=0x0
 8de:	e800fccf 	br	0x27c	// goto loc_27c;
 8e2:	0000      	.short	0x0000
 8e4:	00000000 	.long	0x00000000	// <rx_dcoc_res>
 8e8:	00000000 	.long	0x00000000	// <rx_dcoc_res+0xc>
 8ec:	00000000 	.long	0x00000000	// <DSLEEP_PARAM+0x6>
 8f0:	00000000 	.long	0x00000000	// <DSLEEP_PARAM>
 8f4:	00000000 	.long	0x00000000	// <tx_epa_imb_res_pm>
 8f8:	00000000 	.long	0x00000000	// <tx_epa_imb_res_gm>
 8fc:	00000000 	.long	0x00000000	// <rx_imb_gain_comp>
 900:	00000000 	.long	0x00000000	// <rx_imb_phase_comp>
 904:	40026000 	.long	0x40026000
 908:	00000000 	.long	0x00000000	// <rf_reg_hw_val>
 90c:	00000000 	.long	0x00000000	// <rf_agc_reg_hw_val>
 910:	00000000 	.long	0x00000000	// <rf_bw_reg_hw_val>
 914:	00000000 	.long	0x00000000	// <rf_agcbw_reg_hw_val>
loc_918:
 918:	3204      	movi	r2, 4	// regs: r2=0x4
 91a:	1904      	addi	r1, r14, 16	// regs: r1=(sp + 0x10)
 91c:	6c0b      	mov	r0, r2	// regs: r0=0x4
 91e:	e0000000 	bsr	0x0	// <memory_read>; regs: r0=<ret memory_read@0x91e>, r1=<clobbered>
 922:	e920ff00 	bnez	r0, 0x722	// if (r0 != 0x0) goto loc_722;
 926:	d86e500e 	ld.hs	r3, (r14, 0x1c)	// regs: r3=stack_p1c
 92a:	eb430055 	cmpnei	r3, 85
 92e:	0afa      	bt	0x722	// if (r3 != 0x55) goto loc_722;
 930:	1153      	lrw	r2, 0x0	// regs: r2=0x0
 932:	d86e1008 	ld.h	r3, (r14, 0x10)	// regs: r3=stack_p10
 936:	aa63      	st.h	r3, (r2, 0x6)	// *(0x6) = stack_p10
 938:	d82e1009 	ld.h	r1, (r14, 0x12)	// regs: r1=stack_p12
 93c:	1171      	lrw	r3, 0x0	// regs: r3=0x0
 93e:	ab23      	st.h	r1, (r3, 0x6)	// *(0x6) = stack_p12
 940:	d82e100a 	ld.h	r1, (r14, 0x14)	// regs: r1=stack_p14
 944:	aa24      	st.h	r1, (r2, 0x8)	// *(0x8) = stack_p14
 946:	d82e100b 	ld.h	r1, (r14, 0x16)	// regs: r1=stack_p16
 94a:	ab24      	st.h	r1, (r3, 0x8)	// *(0x8) = stack_p16
 94c:	d82e100c 	ld.h	r1, (r14, 0x18)	// regs: r1=stack_p18
 950:	aa25      	st.h	r1, (r2, 0xa)	// *(0xa) = stack_p18
 952:	d84e100d 	ld.h	r2, (r14, 0x1a)	// regs: r2=stack_p1a
 956:	ab45      	st.h	r2, (r3, 0xa)	// *(0xa) = stack_p1a
 958:	06bd      	br	0x6d2	// goto loc_6d2;
loc_95a:
 95a:	116a      	lrw	r3, 0x0	// regs: r3=0x0
 95c:	5f2c      	addu	r1, r7, r3	// regs: r1=(r7 )
 95e:	1168      	lrw	r3, 0x0	// regs: r3=0x0
 960:	5f0c      	addu	r0, r7, r3	// regs: r0=(r7 )
 962:	6c9b      	mov	r2, r6	// regs: r2=r6
 964:	2600      	addi	r6, 1	// regs: r6=(r6 + 0x1)
 966:	6cd7      	mov	r3, r5	// regs: r3=r5
 968:	8921      	ld.h	r1, (r1, 0x2)	// regs: r1=*(((r7 ) + 0x2))
 96a:	d8005001 	ld.hs	r0, (r0, 0x2)	// regs: r0=*(((r7 ) + 0x2))
 96e:	7598      	zextb	r6, r6	// regs: r6=zext8((r6 + 0x1))
 970:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_imb>; regs: r0=<ret ah_rfdigicali_config_rx_imb@0x970>, r1=<clobbered>
 974:	3e46      	cmpnei	r6, 6
 976:	2701      	addi	r7, 2	// regs: r7=(r7 + 0x2)
 978:	0bf1      	bt	0x95a	// if (r6 != 0x6) goto loc_95a;
 97a:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
 97c:	7554      	zextb	r5, r5	// regs: r5=zext8((r5 + 0x1))
 97e:	3d44      	cmpnei	r5, 4
 980:	0c04      	bf	0x988	// if (r5 == 0x4) goto loc_988;
loc_982:
 982:	3700      	movi	r7, 0	// regs: r7=0x0
 984:	3601      	movi	r6, 1	// regs: r6=0x1
 986:	07ea      	br	0x95a	// goto loc_95a;
loc_988:
 988:	101f      	lrw	r0, 0x0	// regs: r0=0x0
 98a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x98a>, r1=<clobbered>
 98e:	06ca      	br	0x722	// goto loc_722;
loc_990:
 990:	300a      	movi	r0, 10	// regs: r0=0xa
 992:	e0000000 	bsr	0x0	// <xo_set_cs_sec>; regs: r0=<ret xo_set_cs_sec@0x992>, r1=<clobbered>
 996:	0776      	br	0x882	// goto loc_882;
loc_998:
 998:	8445      	ld.b	r2, (r4, 0x5)	// regs: r2=*(r4 + 0x5)
 99a:	3080      	movi	r0, 128	// regs: r0=0x80
 99c:	33b5      	movi	r3, 181	// regs: r3=0xb5
 99e:	4003      	lsli	r0, r0, 3	// regs: r0=0x400
 9a0:	4362      	lsli	r3, r3, 2	// regs: r3=0x2d4
 9a2:	3a40      	cmpnei	r2, 0
 9a4:	c4030c40 	inct	r0, r3, 0
 9a8:	078f      	br	0x8c6	// goto loc_8c6;
loc_9aa:
 9aa:	e0000000 	bsr	0x0	// <ah_rf_tx_dcoc_calib> // arg_bytes: 0; regs: r0=<ret ah_rf_tx_dcoc_calib@0x9aa>, r1=<clobbered>
 9ae:	3201      	movi	r2, 1	// regs: r2=0x1
 9b0:	1036      	lrw	r1, 0x0	// regs: r1=0x0
 9b2:	6c0b      	mov	r0, r2	// regs: r0=0x1
 9b4:	e0000000 	bsr	0x0	// <memory_write>; regs: r0=<ret memory_write@0x9b4>, r1=<clobbered>
 9b8:	3300      	movi	r3, 0	// regs: r3=0x0
 9ba:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 9bc:	64c2      	cmpne	r0, r3
 9be:	e860fc96 	bt	0x2ea	// if (T) goto loc_2ea;
 9c2:	e800fc5b 	br	0x278	// goto loc_278;
loc_9c6:
 9c6:	e0000000 	bsr	0x0	// <ah_rf_tx_imb_calib> // arg_bytes: 0; regs: r0=<ret ah_rf_tx_imb_calib@0x9c6>, r1=<clobbered>
 9ca:	3300      	movi	r3, 0	// regs: r3=0x0
 9cc:	b864      	st.w	r3, (r14, 0x10)	// stack_p10 = 0x0
 9ce:	3202      	movi	r2, 2	// regs: r2=0x2
 9d0:	8f60      	ld.h	r3, (r7, 0x0)	// regs: r3=*(0x0)
 9d2:	dc6e100a 	st.h	r3, (r14, 0x14)	// stack_p14 = *(0x0)
 9d6:	1904      	addi	r1, r14, 16	// regs: r1=(sp + 0x10)
 9d8:	8e60      	ld.h	r3, (r6, 0x0)	// regs: r3=*(0x0)
 9da:	6c0b      	mov	r0, r2	// regs: r0=0x2
 9dc:	dc6e100b 	st.h	r3, (r14, 0x16)	// stack_p16 = *(0x0)
 9e0:	e0000000 	bsr	0x0	// <memory_write>; regs: r0=<ret memory_write@0x9e0>, r1=<clobbered>
 9e4:	3300      	movi	r3, 0	// regs: r3=0x0
 9e6:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 9e8:	64c2      	cmpne	r0, r3
 9ea:	0a45      	bt	0x674	// if (T) goto loc_674;
 9ec:	e800fc46 	br	0x278	// goto loc_278;
loc_9f0:
 9f0:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(r4)
 9f2:	e903ffd3 	bez	r3, 0x998	// if (r3 == 0x0) goto loc_998;
 9f6:	3080      	movi	r0, 128	// regs: r0=0x80
 9f8:	4003      	lsli	r0, r0, 3	// regs: r0=0x400
 9fa:	0766      	br	0x8c6	// goto loc_8c6;
 9fc:	00000000 	.long	0x00000000	// <rx_imb_phase_comp>
 a00:	00000000 	.long	0x00000000	// <rx_imb_gain_comp>
 a04:	00000000 	.long	0x00000000	// <.rodata.ah_rf_open.str1.1+0x11d>
 a08:	00000000 	.long	0x00000000	// <tx_dcoc_res>

Disassembly of section .text.ah_rf_close:

00000000 <ah_rf_close>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <ah_rfspi_close>; regs: r0=<ret ah_rfspi_close@0x2>, r1=<clobbered>
   6:	1067      	lrw	r3, 0x40026000	// regs: r3=0x40026000
   8:	3000      	movi	r0, 0	// regs: r0=0x0
   a:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x40026000)
   c:	3a90      	bclri	r2, 16	// regs: r2=(*(0x40026000) & ~(0x1 << 0x10))
   e:	b340      	st.w	r2, (r3, 0x0)	// *(0x40026000) = (*(0x40026000) & ~(0x1 << 0x10))
  10:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x40026000)
  12:	3a8f      	bclri	r2, 15	// regs: r2=(*(0x40026000) & ~(0x1 << 0xf))
  14:	b340      	st.w	r2, (r3, 0x0)	// *(0x40026000) = (*(0x40026000) & ~(0x1 << 0xf))
  16:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x40026000)
  18:	c40257c2 	zext	r2, r2, 30, 0	// regs: r2=zext(*(0x40026000))
  1c:	b340      	st.w	r2, (r3, 0x0)	// *(0x40026000) = zext(*(0x40026000))
  1e:	1490      	pop	r15
  20:	40026000 	.long	0x40026000
