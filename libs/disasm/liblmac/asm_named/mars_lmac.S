
libs\obj\liblmac\mars_lmac.o:     file format elf32-csky-little


Disassembly of section .text.core_sec_opt_func:

00000000 <core_sec_opt_func>: // arg_bytes: 8
   0:	ea038003 	movi	r3, 32771	// regs: r3=0x8003
   4:	c5e34903 	rotli	r3, r3, 15	// regs: r3=rotl(0x8003, 0xf)
   8:	1048      	lrw	r2, 0xc053781b	// regs: r2=0xc053781b
   a:	dc03202e 	st.w	r0, (r3, 0xb8)	// *((rotl(0x8003, 0xf) + 0xb8)) = <arg0>
   e:	dc23202d 	st.w	r1, (r3, 0xb4)	// *((rotl(0x8003, 0xf) + 0xb4)) = <arg1>
  12:	dc43202f 	st.w	r2, (r3, 0xbc)	// *((rotl(0x8003, 0xf) + 0xbc)) = 0xc053781b
  16:	6c03      	mov	r0, r0	// regs: r0=<arg0>
  18:	6c03      	mov	r0, r0	// regs: r0=<arg0>
  1a:	6c03      	mov	r0, r0	// regs: r0=<arg0>
  1c:	6c03      	mov	r0, r0	// regs: r0=<arg0>
  1e:	6c03      	mov	r0, r0	// regs: r0=<arg0>
  20:	6c03      	mov	r0, r0	// regs: r0=<arg0>
  22:	6c03      	mov	r0, r0	// regs: r0=<arg0>
  24:	6c03      	mov	r0, r0	// regs: r0=<arg0>
  26:	783c      	jmp	r15	// return;
  28:	c053781b 	.long	0xc053781b

Disassembly of section .text.lmac_scan_probe_cb:

00000000 <lmac_scan_probe_cb>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0x2>, r1=<clobbered>
   6:	1069      	lrw	r3, 0x0	// regs: r3=0x0
   8:	3100      	movi	r1, 0	// regs: r1=0x0
   a:	d8430a4f 	ld.b	r2, (r3, 0xa4f)	// regs: r2=*(0xa4f)
   e:	c4415c03 	ins	r2, r1, 3, 3
  12:	d803033c 	ld.b	r0, (r3, 0x33c)	// regs: r0=*(0x33c)
  16:	dc430a4f 	st.b	r2, (r3, 0xa4f)	// *(0xa4f) = *(0xa4f)
  1a:	e0000000 	bsr	0x0	// <lmac_lo_table_kick>; regs: r0=<ret lmac_lo_table_kick@0x1a>, r1=<clobbered>
  1e:	3034      	movi	r0, 52	// regs: r0=0x34
  20:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x20>, r1=<clobbered>
  24:	1490      	pop	r15
  26:	0000      	.short	0x0000
  28:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.pd_timer_ap_wkup:

00000000 <pd_timer_ap_wkup>: // arg_bytes: 0
   0:	14d4      	push	r4-r7, r15
   2:	ea078003 	movi	r7, 32771	// regs: r7=0x8003
   6:	c5e74907 	rotli	r7, r7, 15	// regs: r7=rotl(0x8003, 0xf)
   a:	3080      	movi	r0, 128	// regs: r0=0x80
   c:	d8272020 	ld.w	r1, (r7, 0x80)	// regs: r1=*((rotl(0x8003, 0xf) + 0x80))
  10:	3980      	bclri	r1, 0	// regs: r1=(*((rotl(0x8003, 0xf) + 0x80)) & ~(0x1 << 0x0))
  12:	0387      	lrw	r4, 0x0	// regs: r4=0x0
  14:	e0000000 	bsr	0x0	// <core_sec_opt_func> // arg_bytes: 8; regs: r0=<ret core_sec_opt_func@0x14>, r1=<clobbered>
  18:	e0000000 	bsr	0x0	// <pmu_pd_timer_clear_pnd_sec>; regs: r0=<ret pmu_pd_timer_clear_pnd_sec@0x18>, r1=<clobbered>
  1c:	d8442267 	ld.w	r2, (r4, 0x99c)	// regs: r2=*(0x99c)
  20:	3a43      	cmpnei	r2, 3
  22:	0c07      	bf	0x30	// if (r2 == 0x3) goto loc_30;
  24:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
  28:	e4a32002 	andi	r5, r3, 2	// regs: r5=(*(0x319) & 0x2)
  2c:	e90500f0 	bez	r5, 0x20c	// if (r5 == 0x0) goto loc_20c;
loc_30:
  30:	3001      	movi	r0, 1	// regs: r0=0x1
  32:	e0000000 	bsr	0x0	// <pd_hxosc_en_sec>; regs: r0=<ret pd_hxosc_en_sec@0x32>, r1=<clobbered>
  36:	3200      	movi	r2, 0	// regs: r2=0x0
  38:	6c4b      	mov	r1, r2	// regs: r1=0x0
  3a:	3308      	movi	r3, 8	// regs: r3=0x8
  3c:	3001      	movi	r0, 1	// regs: r0=0x1
  3e:	e0000000 	bsr	0x0	// <sysctrl_adcpll_set>; regs: r0=<ret sysctrl_adcpll_set@0x3e>, r1=<clobbered>
  42:	3005      	movi	r0, 5	// regs: r0=0x5
  44:	e0000000 	bsr	0x0	// <mcu_watchdog_timeout>; regs: r0=<ret mcu_watchdog_timeout@0x44>, r1=<clobbered>
  48:	e0000000 	bsr	0x0	// <mcu_watchdog_feed>; regs: r0=<ret mcu_watchdog_feed@0x48>, r1=<clobbered>
  4c:	ea00f424 	movi	r0, 62500	// regs: r0=0xf424
  50:	c5404900 	rotli	r0, r0, 10	// regs: r0=rotl(0xf424, 0xa)
  54:	e0000000 	bsr	0x0	// <sys_set_sysclk>; regs: r0=<ret sys_set_sysclk@0x54>, r1=<clobbered>
  58:	6d43      	mov	r5, r0	// regs: r5=<ret sys_set_sysclk@0x54>
  5a:	e0000000 	bsr	0x0	// <tsensor_open>; regs: r0=<ret tsensor_open@0x5a>, r1=<clobbered>
  5e:	0379      	lrw	r3, 0x40026000	// regs: r3=0x40026000
  60:	3001      	movi	r0, 1	// regs: r0=0x1
  62:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  64:	3abc      	bseti	r2, 28	// regs: r2=(*(0x40026014) | (0x1 << 0x1c))
  66:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | (0x1 << 0x1c))
  68:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  6a:	3abb      	bseti	r2, 27	// regs: r2=(*(0x40026014) | (0x1 << 0x1b))
  6c:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | (0x1 << 0x1b))
  6e:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  70:	3aba      	bseti	r2, 26	// regs: r2=(*(0x40026014) | (0x1 << 0x1a))
  72:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | (0x1 << 0x1a))
  74:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  76:	3abd      	bseti	r2, 29	// regs: r2=(*(0x40026014) | (0x1 << 0x1d))
  78:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | (0x1 << 0x1d))
  7a:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  7c:	3ab3      	bseti	r2, 19	// regs: r2=(*(0x40026014) | (0x1 << 0x13))
  7e:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | (0x1 << 0x13))
  80:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  82:	ec428000 	ori	r2, r2, 32768	// regs: r2=(*(0x40026014) | 0x8000)
  86:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x8000)
  88:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  8a:	ec420800 	ori	r2, r2, 2048	// regs: r2=(*(0x40026014) | 0x800)
  8e:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x800)
  90:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  92:	ec420200 	ori	r2, r2, 512	// regs: r2=(*(0x40026014) | 0x200)
  96:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x200)
  98:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  9a:	ec420100 	ori	r2, r2, 256	// regs: r2=(*(0x40026014) | 0x100)
  9e:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x100)
  a0:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  a2:	ec420020 	ori	r2, r2, 32	// regs: r2=(*(0x40026014) | 0x20)
  a6:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x20)
  a8:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  aa:	ec420010 	ori	r2, r2, 16	// regs: r2=(*(0x40026014) | 0x10)
  ae:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x10)
  b0:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*(0x4002601c)
  b2:	3ab2      	bseti	r2, 18	// regs: r2=(*(0x4002601c) | (0x1 << 0x12))
  b4:	b347      	st.w	r2, (r3, 0x1c)	// *(0x4002601c) = (*(0x4002601c) | (0x1 << 0x12))
  b6:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  b8:	3ab7      	bseti	r2, 23	// regs: r2=(*(0x40026014) | (0x1 << 0x17))
  ba:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | (0x1 << 0x17))
  bc:	9342      	ld.w	r2, (r3, 0x8)	// regs: r2=*(0x40026008)
  be:	3a92      	bclri	r2, 18	// regs: r2=(*(0x40026008) & ~(0x1 << 0x12))
  c0:	b342      	st.w	r2, (r3, 0x8)	// *(0x40026008) = (*(0x40026008) & ~(0x1 << 0x12))
  c2:	9342      	ld.w	r2, (r3, 0x8)	// regs: r2=*(0x40026008)
  c4:	3ab2      	bseti	r2, 18	// regs: r2=(*(0x40026008) | (0x1 << 0x12))
  c6:	b342      	st.w	r2, (r3, 0x8)	// *(0x40026008) = (*(0x40026008) | (0x1 << 0x12))
  c8:	e0000000 	bsr	0x0	// <lmac_cfg_rf_en>; regs: r0=<ret lmac_cfg_rf_en@0xc8>, r1=<clobbered>
  cc:	d80420ce 	ld.w	r0, (r4, 0x338)	// regs: r0=*(0x338)
  d0:	c4805760 	zext	r0, r0, 27, 4	// regs: r0=zext(*(0x338))
  d4:	e0000000 	bsr	0x0	// <lmac_lo_freq_set>; regs: r0=<ret lmac_lo_freq_set@0xd4>, r1=<clobbered>
  d8:	1368      	lrw	r3, 0x0	// regs: r3=0x0
  da:	d82422e7 	ld.w	r1, (r4, 0xb9c)	// regs: r1=*(0xb9c)
  de:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  e0:	d84422e8 	ld.w	r2, (r4, 0xba0)	// regs: r2=*(0xba0)
  e4:	b324      	st.w	r1, (r3, 0x10)	// *((*(0x0) + 0x10)) = *(0xb9c)
  e6:	b345      	st.w	r2, (r3, 0x14)	// *((*(0x0) + 0x14)) = *(0xba0)
  e8:	d8642267 	ld.w	r3, (r4, 0x99c)	// regs: r3=*(0x99c)
  ec:	e923000b 	bnez	r3, 0x102	// if (r3 != 0x0) goto loc_102;
  f0:	d86414ef 	ld.h	r3, (r4, 0x9de)	// regs: r3=*(0x9de)
  f4:	c4c35502 	zext	r2, r3, 8, 6	// regs: r2=zext(*(0x9de))
  f8:	2206      	addi	r2, 7	// regs: r2=(zext(*(0x9de)) + 0x7)
  fa:	c4625c46 	ins	r3, r2, 8, 6
  fe:	dc6414ef 	st.h	r3, (r4, 0x9de)	// *(0x9de) = *(0x9de)
loc_102:
 102:	d8240556 	ld.b	r1, (r4, 0x556)	// regs: r1=*(0x556)
 106:	3901      	cmphsi	r1, 2
 108:	3300      	movi	r3, 0	// regs: r3=0x0
 10a:	dc640555 	st.b	r3, (r4, 0x555)	// *(0x555) = 0x0
 10e:	d8642197 	ld.w	r3, (r4, 0x65c)	// regs: r3=*(0x65c)
 112:	0c7b      	bf	0x208	// if (r1 < 0x2) goto loc_208;
 114:	c4238022 	divu	r2, r3, r1	// regs: r2=(*(0x65c) / *(0x556))
 118:	7cc8      	mult	r3, r2	// regs: r3=(*(0x65c) * (*(0x65c) / *(0x556)))
 11a:	2900      	subi	r1, 1	// regs: r1=(*(0x556) - 0x1)
 11c:	60c4      	addu	r3, r1	// regs: r3=((*(0x65c) * (*(0x65c) / *(0x556))) + (*(0x556) - 0x1))
loc_11e:
 11e:	dc642197 	st.w	r3, (r4, 0x65c)	// *(0x65c) = r3
 122:	e0000000 	bsr	0x0	// <lmac_next_beacon_calc>; regs: r0=<ret lmac_next_beacon_calc@0x122>, r1=<clobbered>
 126:	e0000000 	bsr	0x0	// <lmac_beacon_timer_start>; regs: r0=<ret lmac_beacon_timer_start@0x126>, r1=<clobbered>
 12a:	3702      	movi	r7, 2	// regs: r7=0x2
 12c:	d86409dd 	ld.b	r3, (r4, 0x9dd)	// regs: r3=*(0x9dd)
 130:	c4675c60 	ins	r3, r7, 3, 0
 134:	dc6409dd 	st.b	r3, (r4, 0x9dd)	// *(0x9dd) = *(0x9dd)
 138:	3601      	movi	r6, 1	// regs: r6=0x1
 13a:	d86409df 	ld.b	r3, (r4, 0x9df)	// regs: r3=*(0x9df)
 13e:	c4665c61 	ins	r3, r6, 4, 1
 142:	120f      	lrw	r0, 0x0	// regs: r0=0x0
 144:	dc6409df 	st.b	r3, (r4, 0x9df)	// *(0x9df) = *(0x9df)
 148:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x148>, r1=<clobbered>
 14c:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
 150:	3200      	movi	r2, 0	// regs: r2=0x0
 152:	c4625c01 	ins	r3, r2, 1, 1
 156:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = *(0x319)
 15a:	3200      	movi	r2, 0	// regs: r2=0x0
 15c:	3300      	movi	r3, 0	// regs: r3=0x0
 15e:	dc4420f0 	st.w	r2, (r4, 0x3c0)	// *(0x3c0) = 0x0
 162:	dc6420f1 	st.w	r3, (r4, 0x3c4)	// *(0x3c4) = 0x0
 166:	dce42267 	st.w	r7, (r4, 0x99c)	// *(0x99c) = 0x2
 16a:	1266      	lrw	r3, 0x0	// regs: r3=0x0
 16c:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*(0xa)
 16e:	c4465c00 	ins	r2, r6, 0, 0
 172:	a34a      	st.b	r2, (r3, 0xa)	// *(0xa) = *(0xa)
 174:	e9050006 	bez	r5, 0x180	// if (r5 == 0x0) goto loc_180;
 178:	6c5b      	mov	r1, r6	// regs: r1=0x1
 17a:	1203      	lrw	r0, 0x0	// regs: r0=0x0
 17c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x17c>, r1=<clobbered>
loc_180:
 180:	e0000000 	bsr	0x0	// <system_ap_sleep_wakeup_hook>; regs: r0=<ret system_ap_sleep_wakeup_hook@0x180>, r1=<clobbered>
 184:	d8644319 	ld.bs	r3, (r4, 0x319)	// regs: r3=*(0x319)
 188:	e9a30034 	bhsz	r3, 0x1f0	// if (r3 >= 0x0) goto loc_1f0;
 18c:	e0000000 	bsr	0x0	// <system_ap_sleep_io_wakeup_hook>; regs: r0=<ret system_ap_sleep_io_wakeup_hook@0x18c>, r1=<clobbered>
 190:	6d43      	mov	r5, r0	// regs: r5=<ret system_ap_sleep_io_wakeup_hook@0x18c>
 192:	e900002f 	bez	r0, 0x1f0	// if (r0 == 0x0) goto loc_1f0;
 196:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
 19a:	3200      	movi	r2, 0	// regs: r2=0x0
 19c:	c4625c07 	ins	r3, r2, 7, 7
 1a0:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = *(0x319)
 1a4:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
 1a6:	3001      	movi	r0, 1	// regs: r0=0x1
 1a8:	832a      	ld.b	r1, (r3, 0xa)	// regs: r1=*((*(0x0) + 0xa))
 1aa:	c4205c00 	ins	r1, r0, 0, 0
 1ae:	a32a      	st.b	r1, (r3, 0xa)	// *((*(0x0) + 0xa)) = *((*(0x0) + 0xa))
 1b0:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
 1b4:	e46320fe 	andi	r3, r3, 254	// regs: r3=(*(0x319) & 0xfe)
 1b8:	c4625c01 	ins	r3, r2, 1, 1
 1bc:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = (*(0x319) & 0xfe)
 1c0:	ea038003 	movi	r3, 32771	// regs: r3=0x8003
 1c4:	c5e34903 	rotli	r3, r3, 15	// regs: r3=rotl(0x8003, 0xf)
 1c8:	dc442267 	st.w	r2, (r4, 0x99c)	// *(0x99c) = 0x0
 1cc:	d8632028 	ld.w	r3, (r3, 0xa0)	// regs: r3=*((rotl(0x8003, 0xf) + 0xa0))
 1d0:	e4632100 	andi	r3, r3, 256	// regs: r3=(*((rotl(0x8003, 0xf) + 0xa0)) & 0x100)
 1d4:	e9030005 	bez	r3, 0x1de	// if (r3 == 0x0) goto loc_1de;
 1d8:	110c      	lrw	r0, 0x0	// regs: r0=0x0
 1da:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1da>, r1=<clobbered>
loc_1de:
 1de:	d824031a 	ld.b	r1, (r4, 0x31a)	// regs: r1=*(0x31a)
 1e2:	110b      	lrw	r0, 0x0	// regs: r0=0x0
 1e4:	4921      	lsri	r1, r1, 1	// regs: r1=(*(0x31a) >> 0x1)
 1e6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1e6>, r1=<clobbered>
 1ea:	7414      	zextb	r0, r5	// regs: r0=zext8(<ret system_ap_sleep_io_wakeup_hook@0x18c>)
loc_1ec:
 1ec:	e0000000 	bsr	0x0	// <lmac_report_sleep_exit>; regs: r0=<ret lmac_report_sleep_exit@0x1ec>, r1=<clobbered>
loc_1f0:
 1f0:	1148      	lrw	r2, 0xe000e100	// regs: r2=0xe000e100
 1f2:	3380      	movi	r3, 128	// regs: r3=0x80
 1f4:	436e      	lsli	r3, r3, 14	// regs: r3=0x200000
 1f6:	b260      	st.w	r3, (r2, 0x0)	// *(0xe000e100) = 0x200000
 1f8:	e0000000 	bsr	0x0	// <lhw_enable_irq_ac>; regs: r0=<ret lhw_enable_irq_ac@0x1f8>, r1=<clobbered>
 1fc:	3000      	movi	r0, 0	// regs: r0=0x0
 1fe:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x1fe>, r1=<clobbered>
 202:	e0000000 	bsr	0x0	// <lmac_tdma_start>; regs: r0=<ret lmac_tdma_start@0x202>, r1=<clobbered>
loc_206:
 206:	1494      	pop	r4-r7, r15
loc_208:
 208:	2300      	addi	r3, 1	// regs: r3=(*(0x65c) + 0x1)
 20a:	078a      	br	0x11e	// goto loc_11e;
loc_20c:
 20c:	3a42      	cmpnei	r2, 2
 20e:	0bfc      	bt	0x206	// if (r2 != 0x2) goto loc_206;
 210:	74ce      	sextb	r3, r3	// regs: r3=sext8(*(0x319))
 212:	e9a3ffef 	bhsz	r3, 0x1f0	// if (r3 >= 0x0) goto loc_1f0;
 216:	e0000000 	bsr	0x0	// <system_ap_sleep_io_wakeup_hook>; regs: r0=<ret system_ap_sleep_io_wakeup_hook@0x216>, r1=<clobbered>
 21a:	6d83      	mov	r6, r0	// regs: r6=<ret system_ap_sleep_io_wakeup_hook@0x216>
 21c:	e900ffea 	bez	r0, 0x1f0	// if (r0 == 0x0) goto loc_1f0;
 220:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
 224:	c4655c07 	ins	r3, r5, 7, 7
 228:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = *(0x319)
 22c:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
 22e:	3101      	movi	r1, 1	// regs: r1=0x1
 230:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*((*(0x0) + 0xa))
 232:	c4415c00 	ins	r2, r1, 0, 0
 236:	a34a      	st.b	r2, (r3, 0xa)	// *((*(0x0) + 0xa)) = *((*(0x0) + 0xa))
 238:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
 23c:	e46320fe 	andi	r3, r3, 254	// regs: r3=(*(0x319) & 0xfe)
 240:	c4655c01 	ins	r3, r5, 1, 1
 244:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = (*(0x319) & 0xfe)
 248:	d8672028 	ld.w	r3, (r7, 0xa0)	// regs: r3=*((rotl(0x8003, 0xf) + 0xa0))
 24c:	e4632100 	andi	r3, r3, 256	// regs: r3=(*((rotl(0x8003, 0xf) + 0xa0)) & 0x100)
 250:	dca42267 	st.w	r5, (r4, 0x99c)	// *(0x99c) = (*(0x319) & 0x2)
 254:	e9030005 	bez	r3, 0x25e	// if (r3 == 0x0) goto loc_25e;
 258:	100c      	lrw	r0, 0x0	// regs: r0=0x0
 25a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x25a>, r1=<clobbered>
loc_25e:
 25e:	d824031a 	ld.b	r1, (r4, 0x31a)	// regs: r1=*(0x31a)
 262:	100d      	lrw	r0, 0x0	// regs: r0=0x0
 264:	4921      	lsri	r1, r1, 1	// regs: r1=(*(0x31a) >> 0x1)
 266:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x266>, r1=<clobbered>
 26a:	7418      	zextb	r0, r6	// regs: r0=zext8(<ret system_ap_sleep_io_wakeup_hook@0x216>)
 26c:	07c0      	br	0x1ec	// goto loc_1ec;
 26e:	0000      	.short	0x0000
 270:	00000000 	.long	0x00000000	// <ah_lmac>
 274:	40026000 	.long	0x40026000
 278:	00000000 	.long	0x00000000	// <LMAC>
 27c:	00000000 	.long	0x00000000	// <.rodata.pd_timer_ap_wkup.str1.1>
 280:	00000000 	.long	0x00000000	// <ah_ops>
 284:	00000000 	.long	0x00000000	// <.rodata.pd_timer_ap_wkup.str1.1+0x6>
 288:	00000000 	.long	0x00000000	// <.rodata.pd_timer_ap_wkup.str1.1+0x19>
 28c:	00000000 	.long	0x00000000	// <.rodata.pd_timer_ap_wkup.str1.1+0x31>
 290:	e100      	.short	0xe100
 292:	e000      	.short	0xe000
 294:	00000000 	.long	0x00000000	// <.rodata.pd_timer_ap_wkup.str1.1+0x4e>

Disassembly of section .text.lmac_print_task:

00000000 <lmac_print_task>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	1094      	lrw	r4, 0x0	// regs: r4=0x0
   4:	6d53      	mov	r5, r4	// regs: r5=0x0
   6:	10d4      	lrw	r6, 0x0	// regs: r6=0x0
loc_8:
   8:	d86449df 	ld.bs	r3, (r4, 0x9df)	// regs: r3=*(0x9df)
   c:	e9a30003 	bhsz	r3, 0x12	// if (r3 >= 0x0) goto loc_12;
  10:	1493      	pop	r4-r6, r15
loc_12:
  12:	3100      	movi	r1, 0	// regs: r1=0x0
  14:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  16:	1011      	lrw	r0, 0x0	// regs: r0=0x0
  18:	e0000000 	bsr	0x0	// <os_sema_down>; regs: r0=<ret os_sema_down@0x18>, r1=<clobbered>
  1c:	e960fff6 	blsz	r0, 0x8
  20:	d864226e 	ld.w	r3, (r4, 0x9b8)	// regs: r3=*(0x9b8)
  24:	e903fff2 	bez	r3, 0x8	// if (r3 == 0x0) goto loc_8;
  28:	8660      	ld.b	r3, (r6, 0x0)	// regs: r3=*(0x0)
  2a:	3b01      	cmphsi	r3, 2
  2c:	0804      	bt	0x34	// if (r3 >= 0x2) goto loc_34;
  2e:	100c      	lrw	r0, 0x0	// regs: r0=0x0
  30:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x30>, r1=<clobbered>
loc_34:
  34:	d825226e 	ld.w	r1, (r5, 0x9b8)	// regs: r1=*(0x9b8)
  38:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  3a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x3a>, r1=<clobbered>
  3e:	d805226e 	ld.w	r0, (r5, 0x9b8)	// regs: r0=*(0x9b8)
  42:	e0000000 	bsr	0x0	// <_os_free>; regs: r0=<ret _os_free@0x42>, r1=<clobbered>
  46:	3300      	movi	r3, 0	// regs: r3=0x0
  48:	dc65226e 	st.w	r3, (r5, 0x9b8)	// *(0x9b8) = 0x0
  4c:	07de      	br	0x8	// goto loc_8;
  4e:	0000      	.short	0x0000
  50:	00000000 	.long	0x00000000	// <ah_lmac>
  54:	00000000 	.long	0x00000000	// <module_efuse_info>
  58:	0000      	.short	0x0000	// <ah_lmac+0x9bc>
  5a:	0000      	.short	0x0000
  5c:	00000000 	.long	0x00000000	// <.rodata.lmac_print_task.str1.1>
  60:	00000000 	.long	0x00000000	// <.rodata.lmac_print_task.str1.1+0x2c>

Disassembly of section .text.wakeup_irq_handler:

00000000 <wakeup_irq_handler>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	ea028003 	movi	r2, 32771	// regs: r2=0x8003
   6:	c5e24902 	rotli	r2, r2, 15	// regs: r2=rotl(0x8003, 0xf)
   a:	d8622028 	ld.w	r3, (r2, 0xa0)	// regs: r3=*((rotl(0x8003, 0xf) + 0xa0))
   e:	e4632100 	andi	r3, r3, 256	// regs: r3=(*((rotl(0x8003, 0xf) + 0xa0)) & 0x100)
  12:	e9030019 	bez	r3, 0x44	// if (r3 == 0x0) goto loc_44;
  16:	d8222028 	ld.w	r1, (r2, 0xa0)	// regs: r1=*((rotl(0x8003, 0xf) + 0xa0))
  1a:	c40155e1 	zext	r1, r1, 15, 0	// regs: r1=zext(*((rotl(0x8003, 0xf) + 0xa0)))
  1e:	39b0      	bseti	r1, 16	// regs: r1=(zext(*((rotl(0x8003, 0xf) + 0xa0))) | (0x1 << 0x10))
  20:	30a0      	movi	r0, 160	// regs: r0=0xa0
  22:	e0000000 	bsr	0x0	// <core_sec_opt_func> // arg_bytes: 8; regs: r0=<ret core_sec_opt_func@0x22>, r1=<clobbered>
  26:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  28:	d8432267 	ld.w	r2, (r3, 0x99c)	// regs: r2=*(0x99c)
  2c:	3a43      	cmpnei	r2, 3
  2e:	080b      	bt	0x44	// if (r2 != 0x3) goto loc_44;
  30:	d8430319 	ld.b	r2, (r3, 0x319)	// regs: r2=*(0x319)
  34:	3101      	movi	r1, 1	// regs: r1=0x1
  36:	c4415c07 	ins	r2, r1, 7, 7
  3a:	3000      	movi	r0, 0	// regs: r0=0x0
  3c:	dc430319 	st.b	r2, (r3, 0x319)	// *(0x319) = *(0x319)
  40:	e0000000 	bsr	0x0	// <pd_timer_ap_wkup> // arg_bytes: 0; regs: r0=<ret pd_timer_ap_wkup@0x40>, r1=<clobbered>
loc_44:
  44:	1490      	pop	r15
  46:	0000      	.short	0x0000
  48:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_phy_reset:

00000000 <lmac_phy_reset>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <ah_wphy_soft_reset>; regs: r0=<ret ah_wphy_soft_reset@0x2>, r1=<clobbered>
   6:	6c03      	mov	r0, r0	// regs: r0=<ret ah_wphy_soft_reset@0x2>
   8:	6c03      	mov	r0, r0	// regs: r0=<ret ah_wphy_soft_reset@0x2>
   a:	6c03      	mov	r0, r0	// regs: r0=<ret ah_wphy_soft_reset@0x2>
   c:	6c03      	mov	r0, r0	// regs: r0=<ret ah_wphy_soft_reset@0x2>
   e:	6c03      	mov	r0, r0	// regs: r0=<ret ah_wphy_soft_reset@0x2>
  10:	e0000000 	bsr	0x0	// <ah_wphy_soft_dereset>; regs: r0=<ret ah_wphy_soft_dereset@0x10>, r1=<clobbered>
  14:	1490      	pop	r15

Disassembly of section .text.lmac_phy_soft_reset:

00000000 <lmac_phy_soft_reset>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	109b      	lrw	r4, 0x0	// regs: r4=0x0
   4:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0x4>, r1=<clobbered>
   8:	d804033c 	ld.b	r0, (r4, 0x33c)	// regs: r0=*(0x33c)
   c:	e0000000 	bsr	0x0	// <lmac_lo_table_kick>; regs: r0=<ret lmac_lo_table_kick@0xc>, r1=<clobbered>
  10:	e0000000 	bsr	0x0	// <ah_wphy_soft_reset>; regs: r0=<ret ah_wphy_soft_reset@0x10>, r1=<clobbered>
  14:	e0000000 	bsr	0x0	// <ah_wphy_soft_dereset>; regs: r0=<ret ah_wphy_soft_dereset@0x14>, r1=<clobbered>
  18:	d8640a4f 	ld.b	r3, (r4, 0xa4f)	// regs: r3=*(0xa4f)
  1c:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0xa4f) & 0x1)
  20:	e903001d 	bez	r3, 0x5a	// if (r3 == 0x0) goto loc_5a;
  24:	3001      	movi	r0, 1	// regs: r0=0x1
  26:	e0000000 	bsr	0x0	// <skbpool_freesize>; regs: r0=<ret skbpool_freesize@0x26>, r1=<clobbered>
  2a:	d86422ec 	ld.w	r3, (r4, 0xbb0)	// regs: r3=*(0xbb0)
  2e:	480b      	lsri	r0, r0, 11	// regs: r0=(<ret skbpool_freesize@0x26> >> 0xb)
  30:	4b61      	lsri	r3, r3, 1	// regs: r3=(*(0xbb0) >> 0x1)
  32:	64c0      	cmphs	r0, r3
  34:	0813      	bt	0x5a	// if (T) goto loc_5a;
  36:	3200      	movi	r2, 0	// regs: r2=0x0
  38:	d864431e 	ld.bs	r3, (r4, 0x31e)	// regs: r3=*(0x31e)
  3c:	2a3b      	subi	r2, 60	// regs: r2=0xffffffc4
  3e:	648d      	cmplt	r3, r2
  40:	0c04      	bf	0x48	// if (!T) goto loc_48;
  42:	2301      	addi	r3, 2	// regs: r3=(*(0x31e) + 0x2)
  44:	dc64031e 	st.b	r3, (r4, 0x31e)	// *(0x31e) = (*(0x31e) + 0x2)
loc_48:
  48:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	d824431e 	ld.bs	r1, (r4, 0x31e)	// regs: r1=*(0x31e)
  4e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x4e>, r1=<clobbered>
  52:	d804431e 	ld.bs	r0, (r4, 0x31e)	// regs: r0=*(0x31e)
  56:	e0000000 	bsr	0x0	// <lmac_adjust_cca_threshold>; regs: r0=<ret lmac_adjust_cca_threshold@0x56>, r1=<clobbered>
loc_5a:
  5a:	3000      	movi	r0, 0	// regs: r0=0x0
  5c:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x5c>, r1=<clobbered>
  60:	d86421f1 	ld.w	r3, (r4, 0x7c4)	// regs: r3=*(0x7c4)
  64:	2300      	addi	r3, 1	// regs: r3=(*(0x7c4) + 0x1)
  66:	dc6421f1 	st.w	r3, (r4, 0x7c4)	// *(0x7c4) = (*(0x7c4) + 0x1)
  6a:	1491      	pop	r4, r15
  6c:	00000000 	.long	0x00000000	// <ah_lmac>
  70:	00000000 	.long	0x00000000	// <.rodata.lmac_phy_soft_reset.str1.1>

Disassembly of section .text.lmac_tick_cb:

00000000 <lmac_tick_cb>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	142d      	subi	r14, r14, 52	// regs: r14=(sp - 0x34)
   4:	ea840165 	lrw	r4, 0x0	// regs: r4=0x0
   8:	ea850165 	lrw	r5, 0x0	// regs: r5=0x0
   c:	d9842233 	ld.w	r12, (r4, 0x8cc)	// regs: r12=*(0x8cc)
  10:	d86420e3 	ld.w	r3, (r4, 0x38c)	// regs: r3=*(0x38c)
  14:	b860      	st.w	r3, (r14, 0x0)	// local_34 = *(0x38c)
  16:	d86420e2 	ld.w	r3, (r4, 0x388)	// regs: r3=*(0x388)
  1a:	b861      	st.w	r3, (r14, 0x4)	// local_30 = *(0x388)
  1c:	d86420e4 	ld.w	r3, (r4, 0x390)	// regs: r3=*(0x390)
  20:	b862      	st.w	r3, (r14, 0x8)	// local_2c = *(0x390)
  22:	d86420e7 	ld.w	r3, (r4, 0x39c)	// regs: r3=*(0x39c)
  26:	b863      	st.w	r3, (r14, 0xc)	// local_28 = *(0x39c)
  28:	d86420e8 	ld.w	r3, (r4, 0x3a0)	// regs: r3=*(0x3a0)
  2c:	b864      	st.w	r3, (r14, 0x10)	// local_24 = *(0x3a0)
  2e:	d86420e9 	ld.w	r3, (r4, 0x3a4)	// regs: r3=*(0x3a4)
  32:	b865      	st.w	r3, (r14, 0x14)	// local_20 = *(0x3a4)
  34:	d86420eb 	ld.w	r3, (r4, 0x3ac)	// regs: r3=*(0x3ac)
  38:	b866      	st.w	r3, (r14, 0x18)	// local_1c = *(0x3ac)
  3a:	d86420ec 	ld.w	r3, (r4, 0x3b0)	// regs: r3=*(0x3b0)
  3e:	b867      	st.w	r3, (r14, 0x1c)	// local_18 = *(0x3b0)
  40:	d86420ed 	ld.w	r3, (r4, 0x3b4)	// regs: r3=*(0x3b4)
  44:	b868      	st.w	r3, (r14, 0x20)	// local_14 = *(0x3b4)
  46:	9540      	ld.w	r2, (r5, 0x0)	// regs: r2=*(0x0)
  48:	9561      	ld.w	r3, (r5, 0x4)	// regs: r3=*(0x4)
  4a:	2200      	addi	r2, 1	// regs: r2=(*(0x0) + 0x1)
  4c:	3a40      	cmpnei	r2, 0
  4e:	c4630c21 	incf	r3, r3, 1
  52:	d90420e6 	ld.w	r8, (r4, 0x398)	// regs: r8=*(0x398)
  56:	d8c420e5 	ld.w	r6, (r4, 0x394)	// regs: r6=*(0x394)
  5a:	b540      	st.w	r2, (r5, 0x0)	// *(0x0) = (*(0x0) + 0x1)
  5c:	b561      	st.w	r3, (r5, 0x4)	// *(0x4) = *(0x4)
  5e:	e90c0049 	bez	r12, 0xf0	// if (r12 == 0x0) goto loc_f0;
  62:	ea830150 	lrw	r3, 0x0	// regs: r3=0x0
  66:	ea0a0000 	movi	r10, 0	// regs: r10=0x0
  6a:	9320      	ld.w	r1, (r3, 0x0)	// regs: r1=*(0x0)
  6c:	ea87014e 	lrw	r7, 0x0	// regs: r7=0x0
  70:	9105      	ld.w	r0, (r1, 0x14)	// regs: r0=*((*(0x0) + 0x14))
  72:	d9a12004 	ld.w	r13, (r1, 0x10)	// regs: r13=*((*(0x0) + 0x10))
  76:	6ec3      	mov	r11, r0	// regs: r11=*((*(0x0) + 0x14))
  78:	6c6b      	mov	r1, r10	// regs: r1=0x0
  7a:	6c37      	mov	r0, r13	// regs: r0=*((*(0x0) + 0x10))
  7c:	66a9      	cmplt	r10, r10
  7e:	6281      	addc	r10, r0
  80:	62c5      	addc	r11, r1
  82:	d80c20b4 	ld.w	r0, (r12, 0x2d0)	// regs: r0=*((*(0x8cc) + 0x2d0))
  86:	d82c20b5 	ld.w	r1, (r12, 0x2d4)	// regs: r1=*((*(0x8cc) + 0x2d4))
  8a:	c4202423 	or	r3, r0, r1	// regs: r3=(*((*(0x8cc) + 0x2d0)) | *((*(0x8cc) + 0x2d4)))
  8e:	e9030295 	bez	r3, 0x5b8	// if (r3 == 0x0) goto loc_5b8;
  92:	66c4      	cmphs	r1, r11
  94:	0c07      	bf	0xa2	// if (!T) goto loc_a2;
  96:	646e      	cmpne	r11, r1
  98:	e8600290 	bt	0x5b8	// if (T) goto loc_5b8;
  9c:	6680      	cmphs	r0, r10
  9e:	e860028d 	bt	0x5b8	// if (T) goto loc_5b8;
loc_a2:
  a2:	d84c20b2 	ld.w	r2, (r12, 0x2c8)	// regs: r2=*((*(0x8cc) + 0x2c8))
  a6:	d86c20b3 	ld.w	r3, (r12, 0x2cc)	// regs: r3=*((*(0x8cc) + 0x2cc))
  aa:	6488      	cmphs	r2, r2
  ac:	6083      	subc	r2, r0
  ae:	60c7      	subc	r3, r1
  b0:	6489      	cmplt	r2, r2
  b2:	60a9      	addc	r2, r10
  b4:	60ed      	addc	r3, r11
  b6:	dc4c20b2 	st.w	r2, (r12, 0x2c8)	// *((*(0x8cc) + 0x2c8)) = *((*(0x8cc) + 0x2c8))
  ba:	dc6c20b3 	st.w	r3, (r12, 0x2cc)	// *((*(0x8cc) + 0x2cc)) = *((*(0x8cc) + 0x2cc))
loc_be:
  be:	d9242233 	ld.w	r9, (r4, 0x8cc)	// regs: r9=*(r4 + 0x8cc)
  c2:	ea02eebb 	movi	r2, 61115	// regs: r2=0xeebb
  c6:	c5a24902 	rotli	r2, r2, 13	// regs: r2=rotl(0xeebb, 0xd)
  ca:	d80920b2 	ld.w	r0, (r9, 0x2c8)	// regs: r0=*((*(r4 + 0x8cc) + 0x2c8))
  ce:	d82920b3 	ld.w	r1, (r9, 0x2cc)	// regs: r1=*((*(r4 + 0x8cc) + 0x2cc))
  d2:	3314      	movi	r3, 20	// regs: r3=0x14
  d4:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0xd4>, r1=<clobbered>
  d8:	dc0920b2 	st.w	r0, (r9, 0x2c8)	// *((*(r4 + 0x8cc) + 0x2c8)) = <ret __umoddi3@0xd4>
  dc:	dc2920b3 	st.w	r1, (r9, 0x2cc)	// *((*(r4 + 0x8cc) + 0x2cc)) = <clobbered>
  e0:	dd4920b4 	st.w	r10, (r9, 0x2d0)	// *((*(r4 + 0x8cc) + 0x2d0)) = r10
  e4:	dd6920b5 	st.w	r11, (r9, 0x2d4)	// *((*(r4 + 0x8cc) + 0x2d4)) = r11
  e8:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0xe8>, r1=<clobbered>
  ec:	b700      	st.w	r0, (r7, 0x0)	// *(r7) = <ret os_jiffies@0xe8>
  ee:	b721      	st.w	r1, (r7, 0x4)	// *(r7 + 0x4) = <clobbered>
loc_f0:
  f0:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(r4 + 0x319)
  f4:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(r4 + 0x319) & 0x2)
  f8:	e923024d 	bnez	r3, 0x592	// if (r3 != 0x0) goto loc_592;
  fc:	d8642267 	ld.w	r3, (r4, 0x99c)	// regs: r3=*(r4 + 0x99c)
 100:	e9230249 	bnez	r3, 0x592	// if (r3 != 0x0) goto loc_592;
 104:	c4c88022 	divu	r2, r8, r6	// regs: r2=(r8 / r6)
 108:	e9020039 	bez	r2, 0x17a	// if (r2 == 0x0) goto loc_17a;
 10c:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(r5)
 10e:	9521      	ld.w	r1, (r5, 0x4)	// regs: r1=*(r5 + 0x4)
 110:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x110>, r1=<clobbered>
 114:	6c40      	or	r1, r0	// regs: r1=(<clobbered> | <ret __umoddi3@0x110>)
 116:	e9210032 	bnez	r1, 0x17a	// if (r1 != 0x0) goto loc_17a;
 11a:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(r4 + 0xa84)
 11e:	5a62      	addi	r3, r2, 1	// regs: r3=(*(r4 + 0xa84) + 0x1)
 120:	d82422a2 	ld.w	r1, (r4, 0xa88)	// regs: r1=*(r4 + 0xa88)
 124:	644d      	cmplt	r3, r1
 126:	5b05      	subu	r0, r3, r1	// regs: r0=((*(r4 + 0xa84) + 0x1) - *(r4 + 0xa88))
 128:	c4600c20 	incf	r3, r0, 0
 12c:	d82422a0 	ld.w	r1, (r4, 0xa80)	// regs: r1=*(r4 + 0xa80)
 130:	644e      	cmpne	r3, r1
 132:	0c08      	bf	0x142	// if (!T) goto loc_142;
 134:	e44202a2 	addi	r2, r2, 675	// regs: r2=(*(r4 + 0xa84) + 0x2a3)
 138:	3107      	movi	r1, 7	// regs: r1=0x7
 13a:	d4440881 	str.w	r1, (r4, r2 << 2)
 13e:	dc6422a1 	st.w	r3, (r4, 0xa84)	// *(r4 + 0xa84) = (*(r4 + 0xa84) + 0x1)
loc_142:
 142:	ea80011a 	lrw	r0, 0x0	// regs: r0=0x0
 146:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x146>, r1=<clobbered>
 14a:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(r4 + 0xa84)
 14e:	5a62      	addi	r3, r2, 1	// regs: r3=(*(r4 + 0xa84) + 0x1)
 150:	d82422a2 	ld.w	r1, (r4, 0xa88)	// regs: r1=*(r4 + 0xa88)
 154:	644d      	cmplt	r3, r1
 156:	5b05      	subu	r0, r3, r1	// regs: r0=((*(r4 + 0xa84) + 0x1) - *(r4 + 0xa88))
 158:	c4600c20 	incf	r3, r0, 0
 15c:	d82422a0 	ld.w	r1, (r4, 0xa80)	// regs: r1=*(r4 + 0xa80)
 160:	644e      	cmpne	r3, r1
 162:	0c08      	bf	0x172	// if (!T) goto loc_172;
 164:	e44202a2 	addi	r2, r2, 675	// regs: r2=(*(r4 + 0xa84) + 0x2a3)
 168:	3103      	movi	r1, 3	// regs: r1=0x3
 16a:	d4440881 	str.w	r1, (r4, r2 << 2)
 16e:	dc6422a1 	st.w	r3, (r4, 0xa84)	// *(r4 + 0xa84) = (*(r4 + 0xa84) + 0x1)
loc_172:
 172:	ea80010e 	lrw	r0, 0x0	// regs: r0=0x0
 176:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x176>, r1=<clobbered>
loc_17a:
 17a:	9860      	ld.w	r3, (r14, 0x0)	// regs: r3=stack_0
 17c:	c4c38022 	divu	r2, r3, r6	// regs: r2=(stack_0 / r6)
 180:	e9020021 	bez	r2, 0x1c2	// if (r2 == 0x0) goto loc_1c2;
 184:	3300      	movi	r3, 0	// regs: r3=0x0
 186:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(r5)
 188:	9521      	ld.w	r1, (r5, 0x4)	// regs: r1=*(r5 + 0x4)
 18a:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x18a>, r1=<clobbered>
 18e:	6c40      	or	r1, r0	// regs: r1=(<clobbered> | <ret __umoddi3@0x18a>)
 190:	e9210019 	bnez	r1, 0x1c2	// if (r1 != 0x0) goto loc_1c2;
 194:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(r4 + 0xa84)
 198:	5a62      	addi	r3, r2, 1	// regs: r3=(*(r4 + 0xa84) + 0x1)
 19a:	d82422a2 	ld.w	r1, (r4, 0xa88)	// regs: r1=*(r4 + 0xa88)
 19e:	644d      	cmplt	r3, r1
 1a0:	5b05      	subu	r0, r3, r1	// regs: r0=((*(r4 + 0xa84) + 0x1) - *(r4 + 0xa88))
 1a2:	c4600c20 	incf	r3, r0, 0
 1a6:	d82422a0 	ld.w	r1, (r4, 0xa80)	// regs: r1=*(r4 + 0xa80)
 1aa:	644e      	cmpne	r3, r1
 1ac:	0c08      	bf	0x1bc	// if (!T) goto loc_1bc;
 1ae:	e44202a2 	addi	r2, r2, 675	// regs: r2=(*(r4 + 0xa84) + 0x2a3)
 1b2:	3106      	movi	r1, 6	// regs: r1=0x6
 1b4:	d4440881 	str.w	r1, (r4, r2 << 2)
 1b8:	dc6422a1 	st.w	r3, (r4, 0xa84)	// *(r4 + 0xa84) = (*(r4 + 0xa84) + 0x1)
loc_1bc:
 1bc:	0004      	lrw	r0, 0x0	// regs: r0=0x0
 1be:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x1be>, r1=<clobbered>
loc_1c2:
 1c2:	d8642278 	ld.w	r3, (r4, 0x9e0)	// regs: r3=*(r4 + 0x9e0)
 1c6:	c6005022 	bmaski	r2, 17
 1ca:	2201      	addi	r2, 2	// regs: r2=(r2 + 0x2)
 1cc:	68c8      	and	r3, r2	// regs: r3=(*(r4 + 0x9e0) & (r2 + 0x2))
 1ce:	e9230148 	bnez	r3, 0x45e	// if (r3 != 0x0) goto loc_45e;
 1d2:	9841      	ld.w	r2, (r14, 0x4)	// regs: r2=stack_p4
 1d4:	c4c28022 	divu	r2, r2, r6	// regs: r2=(stack_p4 / r6)
 1d8:	e9020051 	bez	r2, 0x27a	// if (r2 == 0x0) goto loc_27a;
 1dc:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(r5)
 1de:	9521      	ld.w	r1, (r5, 0x4)	// regs: r1=*(r5 + 0x4)
 1e0:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x1e0>, r1=<clobbered>
 1e4:	6c40      	or	r1, r0	// regs: r1=(<clobbered> | <ret __umoddi3@0x1e0>)
 1e6:	e921004a 	bnez	r1, 0x27a	// if (r1 != 0x0) goto loc_27a;
 1ea:	d8640a4f 	ld.b	r3, (r4, 0xa4f)	// regs: r3=*(r4 + 0xa4f)
 1ee:	e4632003 	andi	r3, r3, 3	// regs: r3=(*(r4 + 0xa4f) & 0x3)
 1f2:	3b43      	cmpnei	r3, 3
 1f4:	0c0b      	bf	0x20a	// if (r3 == 0x3) goto loc_20a;
 1f6:	d864483d 	ld.bs	r3, (r4, 0x83d)	// regs: r3=*(r4 + 0x83d)
 1fa:	eb230032 	cmplti	r3, 51
 1fe:	0c06      	bf	0x20a	// if (r3 >= 0x33) goto loc_20a;
 200:	d86421e2 	ld.w	r3, (r4, 0x788)	// regs: r3=*(r4 + 0x788)
 204:	eb230064 	cmplti	r3, 101
 208:	080a      	bt	0x21c	// if (r3 < 0x65) goto loc_21c;
loc_20a:
 20a:	e0000000 	bsr	0x0	// <lmac_phy_soft_reset> // arg_bytes: 0; regs: r0=<ret lmac_phy_soft_reset@0x20a>, r1=<clobbered>
 20e:	d864037d 	ld.b	r3, (r4, 0x37d)	// regs: r3=*(r4 + 0x37d)
 212:	3201      	movi	r2, 1	// regs: r2=0x1
 214:	c4625c03 	ins	r3, r2, 3, 3
 218:	dc64037d 	st.b	r3, (r4, 0x37d)	// *(r4 + 0x37d) = *(r4 + 0x37d)
loc_21c:
 21c:	3201      	movi	r2, 1	// regs: r2=0x1
 21e:	d8640a4f 	ld.b	r3, (r4, 0xa4f)	// regs: r3=*(r4 + 0xa4f)
 222:	c4625c00 	ins	r3, r2, 0, 0
 226:	c4625c01 	ins	r3, r2, 1, 1
 22a:	dc640a4f 	st.b	r3, (r4, 0xa4f)	// *(r4 + 0xa4f) = *(r4 + 0xa4f)
 22e:	d8640875 	ld.b	r3, (r4, 0x875)	// regs: r3=*(r4 + 0x875)
 232:	740c      	zextb	r0, r3	// regs: r0=zext8(*(r4 + 0x875))
 234:	e4402004 	andi	r2, r0, 4	// regs: r2=(zext8(*(r4 + 0x875)) & 0x4)
 238:	e9020021 	bez	r2, 0x27a	// if (r2 == 0x0) goto loc_27a;
 23c:	d8441504 	ld.h	r2, (r4, 0xa08)	// regs: r2=*(r4 + 0xa08)
 240:	e922001d 	bnez	r2, 0x27a	// if (r2 != 0x0) goto loc_27a;
 244:	e4402008 	andi	r2, r0, 8	// regs: r2=(zext8(*(r4 + 0x875)) & 0x8)
 248:	e9020019 	bez	r2, 0x27a	// if (r2 == 0x0) goto loc_27a;
 24c:	e4004010 	xori	r0, r0, 16	// regs: r0=(zext8(*(r4 + 0x875)) ^ 0x10)
 250:	c4805480 	zext	r0, r0, 4, 4	// regs: r0=zext((zext8(*(r4 + 0x875)) ^ 0x10))
 254:	c4605c04 	ins	r3, r0, 4, 4
 258:	dc640875 	st.b	r3, (r4, 0x875)	// *(r4 + 0x875) = *(r4 + 0x875)
 25c:	e0000000 	bsr	0x0	// <lmac_ant_sel>; regs: r0=<ret lmac_ant_sel@0x25c>, r1=<clobbered>
 260:	d86420ee 	ld.w	r3, (r4, 0x3b8)	// regs: r3=*(r4 + 0x3b8)
 264:	e4632100 	andi	r3, r3, 256	// regs: r3=(*(r4 + 0x3b8) & 0x100)
 268:	e9030009 	bez	r3, 0x27a	// if (r3 == 0x0) goto loc_27a;
 26c:	d8240875 	ld.b	r1, (r4, 0x875)	// regs: r1=*(r4 + 0x875)
 270:	c4815481 	zext	r1, r1, 4, 4	// regs: r1=zext(*(r4 + 0x875))
 274:	0111      	lrw	r0, 0x0	// regs: r0=0x0
 276:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x276>, r1=<clobbered>
loc_27a:
 27a:	9862      	ld.w	r3, (r14, 0x8)	// regs: r3=stack_p8
 27c:	c4c38022 	divu	r2, r3, r6	// regs: r2=(stack_p8 / r6)
 280:	e9020050 	bez	r2, 0x320	// if (r2 == 0x0) goto loc_320;
 284:	3300      	movi	r3, 0	// regs: r3=0x0
 286:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(r5)
 288:	9521      	ld.w	r1, (r5, 0x4)	// regs: r1=*(r5 + 0x4)
 28a:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x28a>, r1=<clobbered>
 28e:	6c40      	or	r1, r0	// regs: r1=(<clobbered> | <ret __umoddi3@0x28a>)
 290:	e9210048 	bnez	r1, 0x320	// if (r1 != 0x0) goto loc_320;
 294:	d864202f 	ld.w	r3, (r4, 0xbc)	// regs: r3=*(r4 + 0xbc)
 298:	3b42      	cmpnei	r3, 2
 29a:	0818      	bt	0x2ca	// if (r3 != 0x2) goto loc_2ca;
 29c:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(r4 + 0xa84)
 2a0:	5a62      	addi	r3, r2, 1	// regs: r3=(*(r4 + 0xa84) + 0x1)
 2a2:	d82422a2 	ld.w	r1, (r4, 0xa88)	// regs: r1=*(r4 + 0xa88)
 2a6:	644d      	cmplt	r3, r1
 2a8:	5b05      	subu	r0, r3, r1	// regs: r0=((*(r4 + 0xa84) + 0x1) - *(r4 + 0xa88))
 2aa:	c4600c20 	incf	r3, r0, 0
 2ae:	d82422a0 	ld.w	r1, (r4, 0xa80)	// regs: r1=*(r4 + 0xa80)
 2b2:	644e      	cmpne	r3, r1
 2b4:	0c08      	bf	0x2c4	// if (!T) goto loc_2c4;
 2b6:	e44202a2 	addi	r2, r2, 675	// regs: r2=(*(r4 + 0xa84) + 0x2a3)
 2ba:	3105      	movi	r1, 5	// regs: r1=0x5
 2bc:	d4440881 	str.w	r1, (r4, r2 << 2)
 2c0:	dc6422a1 	st.w	r3, (r4, 0xa84)	// *(r4 + 0xa84) = (*(r4 + 0xa84) + 0x1)
loc_2c4:
 2c4:	0206      	lrw	r0, 0x0	// regs: r0=0x0
 2c6:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x2c6>, r1=<clobbered>
loc_2ca:
 2ca:	d864202f 	ld.w	r3, (r4, 0xbc)	// regs: r3=*(r4 + 0xbc)
 2ce:	3b41      	cmpnei	r3, 1
 2d0:	0828      	bt	0x320	// if (r3 != 0x1) goto loc_320;
 2d2:	d8641505 	ld.h	r3, (r4, 0xa0a)	// regs: r3=*(r4 + 0xa0a)
 2d6:	e9230025 	bnez	r3, 0x320	// if (r3 != 0x0) goto loc_320;
 2da:	d864037d 	ld.b	r3, (r4, 0x37d)	// regs: r3=*(r4 + 0x37d)
 2de:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(r4 + 0x37d) & 0x4)
 2e2:	e903001f 	bez	r3, 0x320	// if (r3 == 0x0) goto loc_320;
 2e6:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(r4)
 2e8:	836a      	ld.b	r3, (r3, 0xa)	// regs: r3=*((*(r4) + 0xa))
 2ea:	e4632001 	andi	r3, r3, 1	// regs: r3=(*((*(r4) + 0xa)) & 0x1)
 2ee:	e9030019 	bez	r3, 0x320	// if (r3 == 0x0) goto loc_320;
 2f2:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(r4 + 0xa84)
 2f6:	5a62      	addi	r3, r2, 1	// regs: r3=(*(r4 + 0xa84) + 0x1)
 2f8:	d82422a2 	ld.w	r1, (r4, 0xa88)	// regs: r1=*(r4 + 0xa88)
 2fc:	644d      	cmplt	r3, r1
 2fe:	5b05      	subu	r0, r3, r1	// regs: r0=((*(r4 + 0xa84) + 0x1) - *(r4 + 0xa88))
 300:	c4600c20 	incf	r3, r0, 0
 304:	d82422a0 	ld.w	r1, (r4, 0xa80)	// regs: r1=*(r4 + 0xa80)
 308:	644e      	cmpne	r3, r1
 30a:	0c08      	bf	0x31a	// if (!T) goto loc_31a;
 30c:	e44202a2 	addi	r2, r2, 675	// regs: r2=(*(r4 + 0xa84) + 0x2a3)
 310:	3104      	movi	r1, 4	// regs: r1=0x4
 312:	d4440881 	str.w	r1, (r4, r2 << 2)
 316:	dc6422a1 	st.w	r3, (r4, 0xa84)	// *(r4 + 0xa84) = (*(r4 + 0xa84) + 0x1)
loc_31a:
 31a:	021b      	lrw	r0, 0x0	// regs: r0=0x0
 31c:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x31c>, r1=<clobbered>
loc_320:
 320:	9863      	ld.w	r3, (r14, 0xc)	// regs: r3=stack_pc
 322:	c4c38022 	divu	r2, r3, r6	// regs: r2=(stack_pc / r6)
 326:	e902003b 	bez	r2, 0x39c	// if (r2 == 0x0) goto loc_39c;
 32a:	3300      	movi	r3, 0	// regs: r3=0x0
 32c:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(r5)
 32e:	9521      	ld.w	r1, (r5, 0x4)	// regs: r1=*(r5 + 0x4)
 330:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x330>, r1=<clobbered>
 334:	6c40      	or	r1, r0	// regs: r1=(<clobbered> | <ret __umoddi3@0x330>)
 336:	e9210033 	bnez	r1, 0x39c	// if (r1 != 0x0) goto loc_39c;
 33a:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(r4 + 0x310)
 33e:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(r4 + 0x310) & 0x2)
 342:	e903002d 	bez	r3, 0x39c	// if (r3 == 0x0) goto loc_39c;
 346:	d8640378 	ld.b	r3, (r4, 0x378)	// regs: r3=*(r4 + 0x378)
 34a:	e9030029 	bez	r3, 0x39c	// if (r3 == 0x0) goto loc_39c;
 34e:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(r4)
 350:	836a      	ld.b	r3, (r3, 0xa)	// regs: r3=*((*(r4) + 0xa))
 352:	e4632001 	andi	r3, r3, 1	// regs: r3=(*((*(r4) + 0xa)) & 0x1)
 356:	e9030023 	bez	r3, 0x39c	// if (r3 == 0x0) goto loc_39c;
 35a:	d864432a 	ld.bs	r3, (r4, 0x32a)	// regs: r3=*(r4 + 0x32a)
 35e:	e9a3001f 	bhsz	r3, 0x39c	// if (r3 >= 0x0) goto loc_39c;
 362:	036f      	lrw	r3, 0x0	// regs: r3=0x0
 364:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
 366:	d8632036 	ld.w	r3, (r3, 0xd8)	// regs: r3=*((*(0x0) + 0xd8))
 36a:	e9230019 	bnez	r3, 0x39c	// if (r3 != 0x0) goto loc_39c;
 36e:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(r4 + 0xa84)
 372:	5a62      	addi	r3, r2, 1	// regs: r3=(*(r4 + 0xa84) + 0x1)
 374:	d82422a2 	ld.w	r1, (r4, 0xa88)	// regs: r1=*(r4 + 0xa88)
 378:	644d      	cmplt	r3, r1
 37a:	5b05      	subu	r0, r3, r1	// regs: r0=((*(r4 + 0xa84) + 0x1) - *(r4 + 0xa88))
 37c:	c4600c20 	incf	r3, r0, 0
 380:	d82422a0 	ld.w	r1, (r4, 0xa80)	// regs: r1=*(r4 + 0xa80)
 384:	644e      	cmpne	r3, r1
 386:	0c08      	bf	0x396	// if (!T) goto loc_396;
 388:	e44202a2 	addi	r2, r2, 675	// regs: r2=(*(r4 + 0xa84) + 0x2a3)
 38c:	3109      	movi	r1, 9	// regs: r1=0x9
 38e:	d4440881 	str.w	r1, (r4, r2 << 2)
 392:	dc6422a1 	st.w	r3, (r4, 0xa84)	// *(r4 + 0xa84) = (*(r4 + 0xa84) + 0x1)
loc_396:
 396:	031a      	lrw	r0, 0x0	// regs: r0=0x0
 398:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x398>, r1=<clobbered>
loc_39c:
 39c:	9864      	ld.w	r3, (r14, 0x10)	// regs: r3=stack_p10
 39e:	c4c38022 	divu	r2, r3, r6	// regs: r2=(stack_p10 / r6)
 3a2:	e902002f 	bez	r2, 0x400	// if (r2 == 0x0) goto loc_400;
 3a6:	3300      	movi	r3, 0	// regs: r3=0x0
 3a8:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(r5)
 3aa:	9521      	ld.w	r1, (r5, 0x4)	// regs: r1=*(r5 + 0x4)
 3ac:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x3ac>, r1=<clobbered>
 3b0:	6c40      	or	r1, r0	// regs: r1=(<clobbered> | <ret __umoddi3@0x3ac>)
 3b2:	e9210027 	bnez	r1, 0x400	// if (r1 != 0x0) goto loc_400;
 3b6:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(r4 + 0x310)
 3ba:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(r4 + 0x310) & 0x2)
 3be:	e9030021 	bez	r3, 0x400	// if (r3 == 0x0) goto loc_400;
 3c2:	d864202f 	ld.w	r3, (r4, 0xbc)	// regs: r3=*(r4 + 0xbc)
 3c6:	3b42      	cmpnei	r3, 2
 3c8:	081c      	bt	0x400	// if (r3 != 0x2) goto loc_400;
 3ca:	d8641504 	ld.h	r3, (r4, 0xa08)	// regs: r3=*(r4 + 0xa08)
 3ce:	e9030019 	bez	r3, 0x400	// if (r3 == 0x0) goto loc_400;
 3d2:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(r4 + 0xa84)
 3d6:	5a62      	addi	r3, r2, 1	// regs: r3=(*(r4 + 0xa84) + 0x1)
 3d8:	d82422a2 	ld.w	r1, (r4, 0xa88)	// regs: r1=*(r4 + 0xa88)
 3dc:	644d      	cmplt	r3, r1
 3de:	5b05      	subu	r0, r3, r1	// regs: r0=((*(r4 + 0xa84) + 0x1) - *(r4 + 0xa88))
 3e0:	c4600c20 	incf	r3, r0, 0
 3e4:	d82422a0 	ld.w	r1, (r4, 0xa80)	// regs: r1=*(r4 + 0xa80)
 3e8:	644e      	cmpne	r3, r1
 3ea:	0c08      	bf	0x3fa	// if (!T) goto loc_3fa;
 3ec:	e44202a2 	addi	r2, r2, 675	// regs: r2=(*(r4 + 0xa84) + 0x2a3)
 3f0:	310a      	movi	r1, 10	// regs: r1=0xa
 3f2:	d4440881 	str.w	r1, (r4, r2 << 2)
 3f6:	dc6422a1 	st.w	r3, (r4, 0xa84)	// *(r4 + 0xa84) = (*(r4 + 0xa84) + 0x1)
loc_3fa:
 3fa:	130c      	lrw	r0, 0x0	// regs: r0=0x0
 3fc:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x3fc>, r1=<clobbered>
loc_400:
 400:	9865      	ld.w	r3, (r14, 0x14)	// regs: r3=stack_p14
 402:	c4c38022 	divu	r2, r3, r6	// regs: r2=(stack_p14 / r6)
 406:	e902002c 	bez	r2, 0x45e	// if (r2 == 0x0) goto loc_45e;
 40a:	3300      	movi	r3, 0	// regs: r3=0x0
 40c:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(r5)
 40e:	9521      	ld.w	r1, (r5, 0x4)	// regs: r1=*(r5 + 0x4)
 410:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x410>, r1=<clobbered>
 414:	6c40      	or	r1, r0	// regs: r1=(<clobbered> | <ret __umoddi3@0x410>)
 416:	e9210024 	bnez	r1, 0x45e	// if (r1 != 0x0) goto loc_45e;
 41a:	d8640a4f 	ld.b	r3, (r4, 0xa4f)	// regs: r3=*(r4 + 0xa4f)
 41e:	e4432010 	andi	r2, r3, 16	// regs: r2=(*(r4 + 0xa4f) & 0x10)
 422:	e92200e8 	bnez	r2, 0x5f2	// if (r2 != 0x0) goto loc_5f2;
 426:	3201      	movi	r2, 1	// regs: r2=0x1
 428:	c4625c04 	ins	r3, r2, 4, 4
 42c:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(r4 + 0xa84)
 430:	d82422a2 	ld.w	r1, (r4, 0xa88)	// regs: r1=*(r4 + 0xa88)
 434:	dc640a4f 	st.b	r3, (r4, 0xa4f)	// *(r4 + 0xa4f) = *(r4 + 0xa4f)
 438:	5a62      	addi	r3, r2, 1	// regs: r3=(*(r4 + 0xa84) + 0x1)
 43a:	644d      	cmplt	r3, r1
 43c:	5b05      	subu	r0, r3, r1	// regs: r0=((*(r4 + 0xa84) + 0x1) - *(r4 + 0xa88))
 43e:	c4600c20 	incf	r3, r0, 0
 442:	d82422a0 	ld.w	r1, (r4, 0xa80)	// regs: r1=*(r4 + 0xa80)
 446:	644e      	cmpne	r3, r1
 448:	0c08      	bf	0x458	// if (!T) goto loc_458;
 44a:	e44202a2 	addi	r2, r2, 675	// regs: r2=(*(r4 + 0xa84) + 0x2a3)
 44e:	310b      	movi	r1, 11	// regs: r1=0xb
 450:	d4440881 	str.w	r1, (r4, r2 << 2)
 454:	dc6422a1 	st.w	r3, (r4, 0xa84)	// *(r4 + 0xa84) = (*(r4 + 0xa84) + 0x1)
loc_458:
 458:	1214      	lrw	r0, 0x0	// regs: r0=0x0
 45a:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x45a>, r1=<clobbered>
loc_45e:
 45e:	9866      	ld.w	r3, (r14, 0x18)	// regs: r3=stack_p18
 460:	c4c38022 	divu	r2, r3, r6	// regs: r2=(stack_p18 / r6)
 464:	e9020011 	bez	r2, 0x486	// if (r2 == 0x0) goto loc_486;
 468:	3300      	movi	r3, 0	// regs: r3=0x0
 46a:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(r5)
 46c:	9521      	ld.w	r1, (r5, 0x4)	// regs: r1=*(r5 + 0x4)
 46e:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x46e>, r1=<clobbered>
 472:	6c40      	or	r1, r0	// regs: r1=(<clobbered> | <ret __umoddi3@0x46e>)
 474:	e9210009 	bnez	r1, 0x486	// if (r1 != 0x0) goto loc_486;
 478:	d864037d 	ld.b	r3, (r4, 0x37d)	// regs: r3=*(r4 + 0x37d)
 47c:	3201      	movi	r2, 1	// regs: r2=0x1
 47e:	c4625c03 	ins	r3, r2, 3, 3
 482:	dc64037d 	st.b	r3, (r4, 0x37d)	// *(r4 + 0x37d) = *(r4 + 0x37d)
loc_486:
 486:	d864037d 	ld.b	r3, (r4, 0x37d)	// regs: r3=*(r4 + 0x37d)
 48a:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(r4 + 0x37d) & 0x8)
 48e:	e9030019 	bez	r3, 0x4c0	// if (r3 == 0x0) goto loc_4c0;
 492:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(r4 + 0xa84)
 496:	5a62      	addi	r3, r2, 1	// regs: r3=(*(r4 + 0xa84) + 0x1)
 498:	d82422a2 	ld.w	r1, (r4, 0xa88)	// regs: r1=*(r4 + 0xa88)
 49c:	644d      	cmplt	r3, r1
 49e:	5b05      	subu	r0, r3, r1	// regs: r0=((*(r4 + 0xa84) + 0x1) - *(r4 + 0xa88))
 4a0:	c4600c20 	incf	r3, r0, 0
 4a4:	d82422a0 	ld.w	r1, (r4, 0xa80)	// regs: r1=*(r4 + 0xa80)
 4a8:	644e      	cmpne	r3, r1
 4aa:	0c08      	bf	0x4ba	// if (!T) goto loc_4ba;
 4ac:	e44202a2 	addi	r2, r2, 675	// regs: r2=(*(r4 + 0xa84) + 0x2a3)
 4b0:	310d      	movi	r1, 13	// regs: r1=0xd
 4b2:	d4440881 	str.w	r1, (r4, r2 << 2)
 4b6:	dc6422a1 	st.w	r3, (r4, 0xa84)	// *(r4 + 0xa84) = (*(r4 + 0xa84) + 0x1)
loc_4ba:
 4ba:	111c      	lrw	r0, 0x0	// regs: r0=0x0
 4bc:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x4bc>, r1=<clobbered>
loc_4c0:
 4c0:	9867      	ld.w	r3, (r14, 0x1c)	// regs: r3=stack_p1c
 4c2:	c4c38022 	divu	r2, r3, r6	// regs: r2=(stack_p1c / r6)
 4c6:	e9020021 	bez	r2, 0x508	// if (r2 == 0x0) goto loc_508;
 4ca:	3300      	movi	r3, 0	// regs: r3=0x0
 4cc:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(r5)
 4ce:	9521      	ld.w	r1, (r5, 0x4)	// regs: r1=*(r5 + 0x4)
 4d0:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x4d0>, r1=<clobbered>
 4d4:	6c40      	or	r1, r0	// regs: r1=(<clobbered> | <ret __umoddi3@0x4d0>)
 4d6:	e9210019 	bnez	r1, 0x508	// if (r1 != 0x0) goto loc_508;
 4da:	d8040892 	ld.b	r0, (r4, 0x892)	// regs: r0=*(r4 + 0x892)
 4de:	e46020f8 	andi	r3, r0, 248	// regs: r3=(*(r4 + 0x892) & 0xf8)
 4e2:	e9030013 	bez	r3, 0x508	// if (r3 == 0x0) goto loc_508;
 4e6:	20f7      	addi	r0, 248	// regs: r0=(*(r4 + 0x892) + 0xf8)
 4e8:	dc040892 	st.b	r0, (r4, 0x892)	// *(r4 + 0x892) = (*(r4 + 0x892) + 0xf8)
 4ec:	e40020f8 	andi	r0, r0, 248	// regs: r0=((*(r4 + 0x892) + 0xf8) & 0xf8)
 4f0:	e920000c 	bnez	r0, 0x508	// if (r0 != 0x0) goto loc_508;
 4f4:	e0000000 	bsr	0x0	// <disable_print>; regs: r0=<ret disable_print@0x4f4>, r1=<clobbered>
 4f8:	110e      	lrw	r0, 0x0	// regs: r0=0x0
 4fa:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x4fa>, r1=<clobbered>
 4fe:	300a      	movi	r0, 10	// regs: r0=0xa
 500:	e0000000 	bsr	0x0	// <os_sleep_ms>; regs: r0=<ret os_sleep_ms@0x500>, r1=<clobbered>
 504:	e0000000 	bsr	0x0	// <mcu_reset>; regs: r0=<ret mcu_reset@0x504>, r1=<clobbered>
loc_508:
 508:	9868      	ld.w	r3, (r14, 0x20)	// regs: r3=stack_p20
 50a:	c4c38022 	divu	r2, r3, r6	// regs: r2=(stack_p20 / r6)
 50e:	e902002b 	bez	r2, 0x564	// if (r2 == 0x0) goto loc_564;
 512:	3300      	movi	r3, 0	// regs: r3=0x0
 514:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(r5)
 516:	9521      	ld.w	r1, (r5, 0x4)	// regs: r1=*(r5 + 0x4)
 518:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x518>, r1=<clobbered>
 51c:	6c40      	or	r1, r0	// regs: r1=(<clobbered> | <ret __umoddi3@0x518>)
 51e:	e9210023 	bnez	r1, 0x564	// if (r1 != 0x0) goto loc_564;
 522:	d8240875 	ld.b	r1, (r4, 0x875)	// regs: r1=*(r4 + 0x875)
 526:	e421200c 	andi	r1, r1, 12	// regs: r1=(*(r4 + 0x875) & 0xc)
 52a:	394c      	cmpnei	r1, 12
 52c:	081c      	bt	0x564	// if (r1 != 0xc) goto loc_564;
 52e:	d864202f 	ld.w	r3, (r4, 0xbc)	// regs: r3=*(r4 + 0xbc)
 532:	3b41      	cmpnei	r3, 1
 534:	0818      	bt	0x564	// if (r3 != 0x1) goto loc_564;
 536:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(r4 + 0xa84)
 53a:	5a62      	addi	r3, r2, 1	// regs: r3=(*(r4 + 0xa84) + 0x1)
 53c:	d80422a2 	ld.w	r0, (r4, 0xa88)	// regs: r0=*(r4 + 0xa88)
 540:	640d      	cmplt	r3, r0
 542:	c403008c 	subu	r12, r3, r0	// regs: r12=((*(r4 + 0xa84) + 0x1) - *(r4 + 0xa88))
 546:	c46c0c20 	incf	r3, r12, 0
 54a:	d80422a0 	ld.w	r0, (r4, 0xa80)	// regs: r0=*(r4 + 0xa80)
 54e:	640e      	cmpne	r3, r0
 550:	0c07      	bf	0x55e	// if (!T) goto loc_55e;
 552:	e44202a2 	addi	r2, r2, 675	// regs: r2=(*(r4 + 0xa84) + 0x2a3)
 556:	d4440881 	str.w	r1, (r4, r2 << 2)
 55a:	dc6422a1 	st.w	r3, (r4, 0xa84)	// *(r4 + 0xa84) = (*(r4 + 0xa84) + 0x1)
loc_55e:
 55e:	1013      	lrw	r0, 0x0	// regs: r0=0x0
 560:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x560>, r1=<clobbered>
loc_564:
 564:	d82422a0 	ld.w	r1, (r4, 0xa80)	// regs: r1=*(r4 + 0xa80)
 568:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(r4 + 0xa84)
 56c:	6449      	cmplt	r2, r1
 56e:	084c      	bt	0x606	// if (T) goto loc_606;
 570:	5a65      	subu	r3, r2, r1	// regs: r3=(*(r4 + 0xa84) - *(r4 + 0xa80))
loc_572:
 572:	eb23003e 	cmplti	r3, 63
 576:	64c3      	mvcv	r3	// regs: r3=<cond>
 578:	74cc      	zextb	r3, r3	// regs: r3=zext8(<cond>)
 57a:	e903000c 	bez	r3, 0x592	// if (r3 == 0x0) goto loc_592;
 57e:	3304      	movi	r3, 4	// regs: r3=0x4
 580:	b869      	st.w	r3, (r14, 0x24)	// stack_p24 = 0x4
 582:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(r4)
 584:	1a09      	addi	r2, r14, 36	// regs: r2=(sp + 0x24)
 586:	d9832009 	ld.w	r12, (r3, 0x24)	// regs: r12=*((*(r4) + 0x24))
 58a:	311b      	movi	r1, 27	// regs: r1=0x1b
 58c:	3310      	movi	r3, 16	// regs: r3=0x10
 58e:	100a      	lrw	r0, 0x0	// regs: r0=0x0
 590:	7bf1      	jsr	r12
loc_592:
 592:	140d      	addi	r14, r14, 52	// regs: r14=(sp + 0x34)
 594:	1498      	pop	r4-r11, r15
 596:	0000      	.short	0x0000
 598:	00000000 	.long	0x00000000	// <ah_lmac>
 59c:	00000000 	.long	0x00000000	// <.bss.lmac_tick_cnt.13350>
 5a0:	00000000 	.long	0x00000000	// <LMAC>
 5a4:	00000000 	.long	0x00000000	// <.bss.rtc_tick.13351>
 5a8:	00000000 	.long	0x00000000	// <ah_lmac+0xb90>
 5ac:	00000000 	.long	0x00000000	// <.rodata.lmac_tick_cb.str1.1>
 5b0:	00000000 	.long	0x00000000	// <.rodata.lmac_tick_cb.str1.1+0x22>
 5b4:	00000000 	.long	0x00000000	// <ah_ops>
loc_5b8:
 5b8:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x5b8>, r1=<clobbered>
 5bc:	d9872000 	ld.w	r12, (r7, 0x0)	// regs: r12=*(r7)
 5c0:	d9a72001 	ld.w	r13, (r7, 0x4)	// regs: r13=*(r7 + 0x4)
 5c4:	d9242233 	ld.w	r9, (r4, 0x8cc)	// regs: r9=*(r4 + 0x8cc)
 5c8:	32fa      	movi	r2, 250	// regs: r2=0xfa
 5ca:	6400      	cmphs	r0, r0
 5cc:	6033      	subc	r0, r12
 5ce:	6077      	subc	r1, r13
 5d0:	4242      	lsli	r2, r2, 2	// regs: r2=0x3e8
 5d2:	3300      	movi	r3, 0	// regs: r3=0x0
 5d4:	e0000000 	bsr	0x0	// <__muldi3>; regs: r0=<ret __muldi3@0x5d4>, r1=<clobbered>
 5d8:	d98920b2 	ld.w	r12, (r9, 0x2c8)	// regs: r12=*((*(r4 + 0x8cc) + 0x2c8))
 5dc:	d9a920b3 	ld.w	r13, (r9, 0x2cc)	// regs: r13=*((*(r4 + 0x8cc) + 0x2cc))
 5e0:	6401      	cmplt	r0, r0
 5e2:	6031      	addc	r0, r12
 5e4:	6075      	addc	r1, r13
 5e6:	dc0920b2 	st.w	r0, (r9, 0x2c8)	// *((*(r4 + 0x8cc) + 0x2c8)) = <ret __muldi3@0x5d4>
 5ea:	dc2920b3 	st.w	r1, (r9, 0x2cc)	// *((*(r4 + 0x8cc) + 0x2cc)) = <clobbered>
 5ee:	e800fd68 	br	0xbe	// goto loc_be;
loc_5f2:
 5f2:	d86420ee 	ld.w	r3, (r4, 0x3b8)	// regs: r3=*(r4 + 0x3b8)
 5f6:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(r4 + 0x3b8) & 0x8)
 5fa:	e903ff32 	bez	r3, 0x45e	// if (r3 == 0x0) goto loc_45e;
 5fe:	1005      	lrw	r0, 0x0	// regs: r0=0x0
 600:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x600>, r1=<clobbered>
 604:	072d      	br	0x45e	// goto loc_45e;
loc_606:
 606:	d86422a2 	ld.w	r3, (r4, 0xa88)	// regs: r3=*(r4 + 0xa88)
 60a:	60c6      	subu	r3, r1	// regs: r3=(*(r4 + 0xa88) - *(r4 + 0xa80))
 60c:	60c8      	addu	r3, r2	// regs: r3=((*(r4 + 0xa88) - *(r4 + 0xa80)) + *(r4 + 0xa84))
 60e:	07b2      	br	0x572	// goto loc_572;
 610:	00000000 	.long	0x00000000	// <.rodata.lmac_tick_cb.str1.1+0xf>

Disassembly of section .text.pd_timer_irq_handler:

00000000 <pd_timer_irq_handler>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	119a      	lrw	r4, 0x0	// regs: r4=0x0
   4:	d8642267 	ld.w	r3, (r4, 0x99c)	// regs: r3=*(0x99c)
   8:	3b43      	cmpnei	r3, 3
   a:	0c07      	bf	0x18	// if (r3 == 0x3) goto loc_18;
   c:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
  10:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x319) & 0x2)
  14:	e9030069 	bez	r3, 0xe6	// if (r3 == 0x0) goto loc_e6;
loc_18:
  18:	3302      	movi	r3, 2	// regs: r3=0x2
  1a:	dc642267 	st.w	r3, (r4, 0x99c)	// *(0x99c) = 0x2
  1e:	3200      	movi	r2, 0	// regs: r2=0x0
  20:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
  24:	c4625c01 	ins	r3, r2, 1, 1
  28:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = *(0x319)
  2c:	3200      	movi	r2, 0	// regs: r2=0x0
  2e:	3300      	movi	r3, 0	// regs: r3=0x0
  30:	dc4420f0 	st.w	r2, (r4, 0x3c0)	// *(0x3c0) = 0x0
  34:	dc6420f1 	st.w	r3, (r4, 0x3c4)	// *(0x3c4) = 0x0
  38:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
  3a:	3501      	movi	r5, 1	// regs: r5=0x1
  3c:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*((*(0x0) + 0xa))
  3e:	c4455c00 	ins	r2, r5, 0, 0
  42:	a34a      	st.b	r2, (r3, 0xa)	// *((*(0x0) + 0xa)) = *((*(0x0) + 0xa))
  44:	e0000000 	bsr	0x0	// <tsensor_open>; regs: r0=<ret tsensor_open@0x44>, r1=<clobbered>
  48:	1169      	lrw	r3, 0x40026000	// regs: r3=0x40026000
  4a:	6c17      	mov	r0, r5	// regs: r0=0x1
  4c:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  4e:	3abc      	bseti	r2, 28	// regs: r2=(*(0x40026014) | (0x1 << 0x1c))
  50:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | (0x1 << 0x1c))
  52:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  54:	3abb      	bseti	r2, 27	// regs: r2=(*(0x40026014) | (0x1 << 0x1b))
  56:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | (0x1 << 0x1b))
  58:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  5a:	3aba      	bseti	r2, 26	// regs: r2=(*(0x40026014) | (0x1 << 0x1a))
  5c:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | (0x1 << 0x1a))
  5e:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  60:	3ab3      	bseti	r2, 19	// regs: r2=(*(0x40026014) | (0x1 << 0x13))
  62:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | (0x1 << 0x13))
  64:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  66:	ec428000 	ori	r2, r2, 32768	// regs: r2=(*(0x40026014) | 0x8000)
  6a:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x8000)
  6c:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  6e:	ec420800 	ori	r2, r2, 2048	// regs: r2=(*(0x40026014) | 0x800)
  72:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x800)
  74:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  76:	ec420200 	ori	r2, r2, 512	// regs: r2=(*(0x40026014) | 0x200)
  7a:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x200)
  7c:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  7e:	ec420100 	ori	r2, r2, 256	// regs: r2=(*(0x40026014) | 0x100)
  82:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x100)
  84:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  86:	ec420020 	ori	r2, r2, 32	// regs: r2=(*(0x40026014) | 0x20)
  8a:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x20)
  8c:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  8e:	ec420010 	ori	r2, r2, 16	// regs: r2=(*(0x40026014) | 0x10)
  92:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x10)
  94:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*(0x4002601c)
  96:	3ab2      	bseti	r2, 18	// regs: r2=(*(0x4002601c) | (0x1 << 0x12))
  98:	b347      	st.w	r2, (r3, 0x1c)	// *(0x4002601c) = (*(0x4002601c) | (0x1 << 0x12))
  9a:	e0000000 	bsr	0x0	// <lmac_cfg_rf_en>; regs: r0=<ret lmac_cfg_rf_en@0x9a>, r1=<clobbered>
  9e:	30fa      	movi	r0, 250	// regs: r0=0xfa
  a0:	4002      	lsli	r0, r0, 2	// regs: r0=0x3e8
  a2:	e0000000 	bsr	0x0	// <delay_us>; regs: r0=<ret delay_us@0xa2>, r1=<clobbered>
  a6:	d80420ce 	ld.w	r0, (r4, 0x338)	// regs: r0=*(0x338)
  aa:	c4805760 	zext	r0, r0, 27, 4	// regs: r0=zext(*(0x338))
  ae:	e0000000 	bsr	0x0	// <lmac_lo_freq_set>; regs: r0=<ret lmac_lo_freq_set@0xae>, r1=<clobbered>
  b2:	ea038003 	movi	r3, 32771	// regs: r3=0x8003
  b6:	c5e34903 	rotli	r3, r3, 15	// regs: r3=rotl(0x8003, 0xf)
  ba:	d8632020 	ld.w	r3, (r3, 0x80)	// regs: r3=*((rotl(0x8003, 0xf) + 0x80))
  be:	e4632004 	andi	r3, r3, 4	// regs: r3=(*((rotl(0x8003, 0xf) + 0x80)) & 0x4)
  c2:	e9030007 	bez	r3, 0xd0	// if (r3 == 0x0) goto loc_d0;
  c6:	e0000000 	bsr	0x0	// <pmu_pd_timer_clear_pnd_sec>; regs: r0=<ret pmu_pd_timer_clear_pnd_sec@0xc6>, r1=<clobbered>
  ca:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  cc:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xcc>, r1=<clobbered>
loc_d0:
  d0:	e0000000 	bsr	0x0	// <mcu_watchdog_feed>; regs: r0=<ret mcu_watchdog_feed@0xd0>, r1=<clobbered>
  d4:	e0000000 	bsr	0x0	// <system_ap_sleep_wakeup_hook>; regs: r0=<ret system_ap_sleep_wakeup_hook@0xd4>, r1=<clobbered>
  d8:	e0000000 	bsr	0x0	// <lhw_enable_irq_ac>; regs: r0=<ret lhw_enable_irq_ac@0xd8>, r1=<clobbered>
  dc:	3000      	movi	r0, 0	// regs: r0=0x0
  de:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0xde>, r1=<clobbered>
  e2:	e0000000 	bsr	0x0	// <lmac_tdma_start>; regs: r0=<ret lmac_tdma_start@0xe2>, r1=<clobbered>
loc_e6:
  e6:	1492      	pop	r4-r5, r15
  e8:	00000000 	.long	0x00000000	// <ah_lmac>
  ec:	40026000 	.long	0x40026000
  f0:	00000000 	.long	0x00000000	// <.rodata.pd_timer_irq_handler.str1.1>

Disassembly of section .text.lmac_psm_enter:

00000000 <lmac_psm_enter>: // arg_bytes: 0
   0:	14d5      	push	r4-r8, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	03b2      	lrw	r5, 0x0	// regs: r5=0x0
   6:	6dcf      	mov	r7, r3	// regs: r7=<arg3>
   8:	d8652233 	ld.w	r3, (r5, 0x8cc)	// regs: r3=*(0x8cc)
   c:	6e0b      	mov	r8, r2	// regs: r8=<arg2>
   e:	d843025b 	ld.b	r2, (r3, 0x25b)	// regs: r2=*((*(0x8cc) + 0x25b))
  12:	e44220c0 	andi	r2, r2, 192	// regs: r2=(*((*(0x8cc) + 0x25b)) & 0xc0)
  16:	eb420040 	cmpnei	r2, 64
  1a:	6d07      	mov	r4, r1	// regs: r4=<arg1>
  1c:	0822      	bt	0x60	// if (r2 != 0x40) goto loc_60;
  1e:	d845202f 	ld.w	r2, (r5, 0xbc)	// regs: r2=*(0xbc)
  22:	e922001f 	bnez	r2, 0x60	// if (r2 != 0x0) goto loc_60;
  26:	d8c320af 	ld.w	r6, (r3, 0x2bc)	// regs: r6=*((*(0x8cc) + 0x2bc))
loc_2a:
  2a:	d865202f 	ld.w	r3, (r5, 0xbc)	// regs: r3=*(0xbc)
  2e:	b860      	st.w	r3, (r14, 0x0)	// local_4 = *(0xbc)
  30:	6c9b      	mov	r2, r6	// regs: r2=r6
  32:	6cdf      	mov	r3, r7	// regs: r3=<arg3>
  34:	6c53      	mov	r1, r4	// regs: r1=<arg1>
  36:	031d      	lrw	r0, 0x0	// regs: r0=0x0
  38:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x38>, r1=<clobbered>
  3c:	e9240033 	bnez	r4, 0xa2	// if (r4 != 0x0) goto loc_a2;
  40:	d865202f 	ld.w	r3, (r5, 0xbc)	// regs: r3=*(0xbc)
  44:	3b42      	cmpnei	r3, 2
  46:	0820      	bt	0x86	// if (r3 != 0x2) goto loc_86;
  48:	d8650319 	ld.b	r3, (r5, 0x319)	// regs: r3=*(0x319)
  4c:	e4632040 	andi	r3, r3, 64	// regs: r3=(*(0x319) & 0x40)
  50:	e9030010 	bez	r3, 0x70	// if (r3 == 0x0) goto loc_70;
  54:	131b      	lrw	r0, 0x0	// regs: r0=0x0
  56:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x56>, r1=<clobbered>
loc_5a:
  5a:	6c13      	mov	r0, r4	// regs: r0=r4
  5c:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  5e:	1495      	pop	r4-r8, r15
loc_60:
  60:	8375      	ld.b	r3, (r3, 0x15)	// regs: r3=*((*(0x8cc) + 0x15))
  62:	e4632007 	andi	r3, r3, 7	// regs: r3=(*((*(0x8cc) + 0x15)) & 0x7)
  66:	3b46      	cmpnei	r3, 6
  68:	3600      	movi	r6, 0	// regs: r6=0x0
  6a:	c4c80c40 	inct	r6, r8, 0
  6e:	07de      	br	0x2a	// goto loc_2a;
loc_70:
  70:	1375      	lrw	r3, 0x0	// regs: r3=0x0
  72:	6c13      	mov	r0, r4	// regs: r0=<arg1>
  74:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
  76:	d8622033 	ld.w	r3, (r2, 0xcc)	// regs: r3=*((*(0x0) + 0xcc))
  7a:	ec630020 	ori	r3, r3, 32	// regs: r3=(*((*(0x0) + 0xcc)) | 0x20)
  7e:	dc622033 	st.w	r3, (r2, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x20)
  82:	e0000000 	bsr	0x0	// <pd_timer_irq_handler> // arg_bytes: 0; regs: r0=<ret pd_timer_irq_handler@0x82>, r1=<clobbered>
loc_86:
  86:	3300      	movi	r3, 0	// regs: r3=0x0
  88:	dc650318 	st.b	r3, (r5, 0x318)	// *(0x318) = 0x0
  8c:	9560      	ld.w	r3, (r5, 0x0)	// regs: r3=*(0x0)
  8e:	3101      	movi	r1, 1	// regs: r1=0x1
  90:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*((*(0x0) + 0xa))
  92:	3000      	movi	r0, 0	// regs: r0=0x0
  94:	c4415c00 	ins	r2, r1, 0, 0
  98:	dc052267 	st.w	r0, (r5, 0x99c)	// *(0x99c) = 0x0
  9c:	a34a      	st.b	r2, (r3, 0xa)	// *((*(0x0) + 0xa)) = *((*(0x0) + 0xa))
loc_9e:
  9e:	3400      	movi	r4, 0	// regs: r4=0x0
  a0:	07dd      	br	0x5a	// goto loc_5a;
loc_a2:
  a2:	d8652267 	ld.w	r3, (r5, 0x99c)	// regs: r3=*(0x99c)
  a6:	3b43      	cmpnei	r3, 3
  a8:	3100      	movi	r1, 0	// regs: r1=0x0
  aa:	0cc5      	bf	0x234	// if (r3 == 0x3) goto loc_234;
  ac:	9560      	ld.w	r3, (r5, 0x0)	// regs: r3=*(0x0)
  ae:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*((*(0x0) + 0xa))
  b0:	c4415c00 	ins	r2, r1, 0, 0
  b4:	a34a      	st.b	r2, (r3, 0xa)	// *((*(0x0) + 0xa)) = *((*(0x0) + 0xa))
  b6:	d8652233 	ld.w	r3, (r5, 0x8cc)	// regs: r3=*(0x8cc)
  ba:	8375      	ld.b	r3, (r3, 0x15)	// regs: r3=*((*(0x8cc) + 0x15))
  bc:	e4632007 	andi	r3, r3, 7	// regs: r3=(*((*(0x8cc) + 0x15)) & 0x7)
  c0:	3b46      	cmpnei	r3, 6
  c2:	0807      	bt	0xd0	// if (r3 != 0x6) goto loc_d0;
  c4:	3303      	movi	r3, 3	// regs: r3=0x3
  c6:	6c07      	mov	r0, r1	// regs: r0=0x0
  c8:	dc652267 	st.w	r3, (r5, 0x99c)	// *(0x99c) = 0x3
  cc:	e0000000 	bsr	0x0	// <dsleep_enter>; regs: r0=<ret dsleep_enter@0xcc>, r1=<clobbered>
loc_d0:
  d0:	d8652233 	ld.w	r3, (r5, 0x8cc)	// regs: r3=*(0x8cc)
  d4:	8375      	ld.b	r3, (r3, 0x15)	// regs: r3=*((*(0x8cc) + 0x15))
  d6:	e4632007 	andi	r3, r3, 7	// regs: r3=(*((*(0x8cc) + 0x15)) & 0x7)
  da:	3b45      	cmpnei	r3, 5
  dc:	0808      	bt	0xec	// if (r3 != 0x5) goto loc_ec;
  de:	3303      	movi	r3, 3	// regs: r3=0x3
  e0:	3100      	movi	r1, 0	// regs: r1=0x0
  e2:	6c23      	mov	r0, r8	// regs: r0=<arg2>
  e4:	dc652267 	st.w	r3, (r5, 0x99c)	// *(0x99c) = 0x3
  e8:	e0000000 	bsr	0x0	// <dsleep_enter>; regs: r0=<ret dsleep_enter@0xe8>, r1=<clobbered>
loc_ec:
  ec:	e907007d 	bez	r7, 0x1e6	// if (r7 == 0x0) goto loc_1e6;
  f0:	d885202f 	ld.w	r4, (r5, 0xbc)	// regs: r4=*(0xbc)
  f4:	3c41      	cmpnei	r4, 1
  f6:	0817      	bt	0x124	// if (r4 != 0x1) goto loc_124;
  f8:	d8651505 	ld.h	r3, (r5, 0xa0a)	// regs: r3=*(0xa0a)
  fc:	e923000a 	bnez	r3, 0x110	// if (r3 != 0x0) goto loc_110;
 100:	d8650556 	ld.b	r3, (r5, 0x556)	// regs: r3=*(0x556)
 104:	e9030006 	bez	r3, 0x110	// if (r3 == 0x0) goto loc_110;
 108:	d8652196 	ld.w	r3, (r5, 0x658)	// regs: r3=*(0x658)
 10c:	e9230009 	bnez	r3, 0x11e	// if (r3 != 0x0) goto loc_11e;
loc_110:
 110:	3300      	movi	r3, 0	// regs: r3=0x0
 112:	dc650318 	st.b	r3, (r5, 0x318)	// *(0x318) = 0x0
loc_116:
 116:	3301      	movi	r3, 1	// regs: r3=0x1
 118:	dc652267 	st.w	r3, (r5, 0x99c)	// *(0x99c) = 0x1
 11c:	07c1      	br	0x9e	// goto loc_9e;
loc_11e:
 11e:	dc850318 	st.b	r4, (r5, 0x318)	// *(0x318) = *(0xbc)
 122:	07fa      	br	0x116	// goto loc_116;
loc_124:
 124:	e9240029 	bnez	r4, 0x176	// if (r4 != 0x0) goto loc_176;
 128:	d8652233 	ld.w	r3, (r5, 0x8cc)	// regs: r3=*(0x8cc)
 12c:	3201      	movi	r2, 1	// regs: r2=0x1
 12e:	8335      	ld.b	r1, (r3, 0x15)	// regs: r1=*((*(0x8cc) + 0x15))
 130:	c4225c03 	ins	r1, r2, 3, 3
 134:	dc430257 	st.b	r2, (r3, 0x257)	// *((*(0x8cc) + 0x257)) = 0x1
 138:	3203      	movi	r2, 3	// regs: r2=0x3
 13a:	a335      	st.b	r1, (r3, 0x15)	// *((*(0x8cc) + 0x15)) = *((*(0x8cc) + 0x15))
 13c:	dc452267 	st.w	r2, (r5, 0x99c)	// *(0x99c) = 0x3
 140:	d843025b 	ld.b	r2, (r3, 0x25b)	// regs: r2=*((*(0x8cc) + 0x25b))
 144:	e44220c0 	andi	r2, r2, 192	// regs: r2=(*((*(0x8cc) + 0x25b)) & 0xc0)
 148:	eb420040 	cmpnei	r2, 64
 14c:	0813      	bt	0x172	// if (r2 != 0x40) goto loc_172;
 14e:	3218      	movi	r2, 24	// regs: r2=0x18
 150:	d8630a4d 	ld.b	r3, (r3, 0xa4d)	// regs: r3=*((*(0x8cc) + 0xa4d))
 154:	7cc8      	mult	r3, r2	// regs: r3=(*((*(0x8cc) + 0xa4d)) * 0x18)
 156:	60d4      	addu	r3, r5	// regs: r3=((*((*(0x8cc) + 0xa4d)) * 0x18) )
 158:	d8032030 	ld.w	r0, (r3, 0xc0)	// regs: r0=*((((*((*(0x8cc) + 0xa4d)) * 0x18) ) + 0xc0))
 15c:	e0000000 	bsr	0x0	// <lmac_lo_freq_set>; regs: r0=<ret lmac_lo_freq_set@0x15c>, r1=<clobbered>
 160:	d8052233 	ld.w	r0, (r5, 0x8cc)	// regs: r0=*(0x8cc)
 164:	e0000000 	bsr	0x0	// <dsleep_cfg_init>; regs: r0=<ret dsleep_cfg_init@0x164>, r1=<clobbered>
 168:	3108      	movi	r1, 8	// regs: r1=0x8
loc_16a:
 16a:	6c1b      	mov	r0, r6	// regs: r0=r6
 16c:	e0000000 	bsr	0x0	// <dsleep_enter>; regs: r0=<ret dsleep_enter@0x16c>, r1=<clobbered>
 170:	0775      	br	0x5a	// goto loc_5a;
loc_172:
 172:	6c53      	mov	r1, r4	// regs: r1=*(0xbc)
 174:	07fb      	br	0x16a	// goto loc_16a;
loc_176:
 176:	3c42      	cmpnei	r4, 2
 178:	082b      	bt	0x1ce	// if (r4 != 0x2) goto loc_1ce;
 17a:	1154      	lrw	r2, 0xe000e100	// regs: r2=0xe000e100
 17c:	3380      	movi	r3, 128	// regs: r3=0x80
 17e:	4368      	lsli	r3, r3, 8	// regs: r3=0x8000
 180:	dc622020 	st.w	r3, (r2, 0x80)	// *(0xe000e180) = 0x8000
 184:	e0000000 	bsr	0x0	// <pmu_pd_timer_clk_sel_256k_sec>; regs: r0=<ret pmu_pd_timer_clk_sel_256k_sec@0x184>, r1=<clobbered>
 188:	3001      	movi	r0, 1	// regs: r0=0x1
 18a:	e0000000 	bsr	0x0	// <pmu_pd_timer_trim_time_unit_set_sec>; regs: r0=<ret pmu_pd_timer_trim_time_unit_set_sec@0x18a>, r1=<clobbered>
 18e:	e0000000 	bsr	0x0	// <pmu_pd_rc256k_sw_trim_en_sec>; regs: r0=<ret pmu_pd_rc256k_sw_trim_en_sec@0x18e>, r1=<clobbered>
 192:	ea038003 	movi	r3, 32771	// regs: r3=0x8003
 196:	c5e34903 	rotli	r3, r3, 15	// regs: r3=rotl(0x8003, 0xf)
loc_19a:
 19a:	d8032023 	ld.w	r0, (r3, 0x8c)	// regs: r0=*((rotl(0x8003, 0xf) + 0x8c))
 19e:	e4802001 	andi	r4, r0, 1	// regs: r4=(*((rotl(0x8003, 0xf) + 0x8c)) & 0x1)
 1a2:	e924fffc 	bnez	r4, 0x19a	// if (r4 != 0x0) goto loc_19a;
 1a6:	e0000000 	bsr	0x0	// <pmu_pd_rc256k_hw_trim_en_sec>; regs: r0=<ret pmu_pd_rc256k_hw_trim_en_sec@0x1a6>, r1=<clobbered>
 1aa:	e0000000 	bsr	0x0	// <pmu_pd_timer_irq_en_sec>; regs: r0=<ret pmu_pd_timer_irq_en_sec@0x1aa>, r1=<clobbered>
 1ae:	1143      	lrw	r2, 0x0	// regs: r2=0x0
 1b0:	1127      	lrw	r1, 0x0	// regs: r1=0x0
 1b2:	300f      	movi	r0, 15	// regs: r0=0xf
 1b4:	e0000000 	bsr	0x0	// <request_irq>; regs: r0=<ret request_irq@0x1b4>, r1=<clobbered>
 1b8:	3380      	movi	r3, 128	// regs: r3=0x80
 1ba:	1144      	lrw	r2, 0xe000e100	// regs: r2=0xe000e100
 1bc:	4368      	lsli	r3, r3, 8	// regs: r3=0x8000
 1be:	b260      	st.w	r3, (r2, 0x0)	// *(0xe000e100) = 0x8000
 1c0:	3301      	movi	r3, 1	// regs: r3=0x1
 1c2:	dc650318 	st.b	r3, (r5, 0x318)	// *(0x318) = 0x1
 1c6:	3302      	movi	r3, 2	// regs: r3=0x2
 1c8:	dc652267 	st.w	r3, (r5, 0x99c)	// *(0x99c) = 0x2
 1cc:	0747      	br	0x5a	// goto loc_5a;
loc_1ce:
 1ce:	9560      	ld.w	r3, (r5, 0x0)	// regs: r3=*(0x0)
 1d0:	3101      	movi	r1, 1	// regs: r1=0x1
 1d2:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*((*(0x0) + 0xa))
 1d4:	c4415c00 	ins	r2, r1, 0, 0
 1d8:	a34a      	st.b	r2, (r3, 0xa)	// *((*(0x0) + 0xa)) = *((*(0x0) + 0xa))
 1da:	3400      	movi	r4, 0	// regs: r4=0x0
 1dc:	101d      	lrw	r0, 0x0	// regs: r0=0x0
 1de:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1de>, r1=<clobbered>
 1e2:	2c00      	subi	r4, 1	// regs: r4=0xffffffff
 1e4:	073b      	br	0x5a	// goto loc_5a;
loc_1e6:
 1e6:	d8652233 	ld.w	r3, (r5, 0x8cc)	// regs: r3=*(0x8cc)
 1ea:	3201      	movi	r2, 1	// regs: r2=0x1
 1ec:	8335      	ld.b	r1, (r3, 0x15)	// regs: r1=*((*(0x8cc) + 0x15))
 1ee:	c4225c03 	ins	r1, r2, 3, 3
 1f2:	dc430257 	st.b	r2, (r3, 0x257)	// *((*(0x8cc) + 0x257)) = 0x1
 1f6:	3203      	movi	r2, 3	// regs: r2=0x3
 1f8:	a335      	st.b	r1, (r3, 0x15)	// *((*(0x8cc) + 0x15)) = *((*(0x8cc) + 0x15))
 1fa:	dc452267 	st.w	r2, (r5, 0x99c)	// *(0x99c) = 0x3
 1fe:	d843025b 	ld.b	r2, (r3, 0x25b)	// regs: r2=*((*(0x8cc) + 0x25b))
 202:	e44220c0 	andi	r2, r2, 192	// regs: r2=(*((*(0x8cc) + 0x25b)) & 0xc0)
 206:	eb420040 	cmpnei	r2, 64
 20a:	0813      	bt	0x230	// if (r2 != 0x40) goto loc_230;
 20c:	3218      	movi	r2, 24	// regs: r2=0x18
 20e:	d8630a4d 	ld.b	r3, (r3, 0xa4d)	// regs: r3=*((*(0x8cc) + 0xa4d))
 212:	7cc8      	mult	r3, r2	// regs: r3=(*((*(0x8cc) + 0xa4d)) * 0x18)
 214:	60d4      	addu	r3, r5	// regs: r3=((*((*(0x8cc) + 0xa4d)) * 0x18) )
 216:	d8032030 	ld.w	r0, (r3, 0xc0)	// regs: r0=*((((*((*(0x8cc) + 0xa4d)) * 0x18) ) + 0xc0))
 21a:	e0000000 	bsr	0x0	// <lmac_lo_freq_set>; regs: r0=<ret lmac_lo_freq_set@0x21a>, r1=<clobbered>
 21e:	d8052233 	ld.w	r0, (r5, 0x8cc)	// regs: r0=*(0x8cc)
 222:	e0000000 	bsr	0x0	// <dsleep_cfg_init>; regs: r0=<ret dsleep_cfg_init@0x222>, r1=<clobbered>
 226:	3108      	movi	r1, 8	// regs: r1=0x8
loc_228:
 228:	6c1b      	mov	r0, r6	// regs: r0=r6
 22a:	e0000000 	bsr	0x0	// <dsleep_enter>; regs: r0=<ret dsleep_enter@0x22a>, r1=<clobbered>
 22e:	0738      	br	0x9e	// goto loc_9e;
loc_230:
 230:	6c5f      	mov	r1, r7	// regs: r1=<arg3>
 232:	07fb      	br	0x228	// goto loc_228;
loc_234:
 234:	6d07      	mov	r4, r1	// regs: r4=0x0
 236:	0712      	br	0x5a	// goto loc_5a;
 238:	00000000 	.long	0x00000000	// <ah_lmac>
 23c:	00000000 	.long	0x00000000	// <.rodata.lmac_psm_enter.str1.1>
 240:	00000000 	.long	0x00000000	// <.rodata.lmac_psm_enter.str1.1+0x26>
 244:	00000000 	.long	0x00000000	// <LMAC>
 248:	e000e100 	.long	0xe000e100
 24c:	00000000 	.long	0x00000000	// <pd_timer_ap_wkup>
 250:	00000000 	.long	0x00000000	// <.rodata.lmac_psm_enter.str1.1+0x2b>

Disassembly of section .text.lmac_obss_eval:

00000000 <lmac_obss_eval>: // arg_bytes: 4
   0:	14d8      	push	r4-r11, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	1296      	lrw	r4, 0x0	// regs: r4=0x0
   6:	d864432a 	ld.bs	r3, (r4, 0x32a)	// regs: r3=*(0x32a)
   a:	e9a300a3 	bhsz	r3, 0x150	// if (r3 >= 0x0) goto loc_150;
   e:	d8e40310 	ld.b	r7, (r4, 0x310)	// regs: r7=*(0x310)
  12:	e4672002 	andi	r3, r7, 2	// regs: r3=(*(0x310) & 0x2)
  16:	e903009d 	bez	r3, 0x150	// if (r3 == 0x0) goto loc_150;
  1a:	ea080000 	movi	r8, 0	// regs: r8=0x0
  1e:	3600      	movi	r6, 0	// regs: r6=0x0
  20:	e4a4023f 	addi	r5, r4, 576	// regs: r5=0x240
  24:	e508107f 	subi	r8, r8, 128	// regs: r8=0xffffff80
  28:	6e9b      	mov	r10, r6	// regs: r10=0x0
  2a:	ea8c004e 	lrw	r12, 0x0	// regs: r12=0x0
  2e:	e4e72004 	andi	r7, r7, 4	// regs: r7=(*(0x310) & 0x4)
loc_32:
  32:	d9252000 	ld.w	r9, (r5, 0x0)	// regs: r9=*(r5)
  36:	e9090034 	bez	r9, 0x9e	// if (r9 == 0x0) goto loc_9e;
  3a:	d86c2000 	ld.w	r3, (r12, 0x0)	// regs: r3=*(r12)
  3e:	64e6      	cmpne	r9, r3
  40:	0c07      	bf	0x4e	// if (!T) goto loc_4e;
  42:	d86420ce 	ld.w	r3, (r4, 0x338)	// regs: r3=*(0x338)
  46:	c4835763 	zext	r3, r3, 27, 4	// regs: r3=zext(*(0x338))
  4a:	64e6      	cmpne	r9, r3
  4c:	0804      	bt	0x54	// if (T) goto loc_54;
loc_4e:
  4e:	8567      	ld.b	r3, (r5, 0x7)	// regs: r3=*(r5 + 0x7)
  50:	2305      	addi	r3, 6	// regs: r3=(*(r5 + 0x7) + 0x6)
  52:	a567      	st.b	r3, (r5, 0x7)	// *(r5 + 0x7) = (*(r5 + 0x7) + 0x6)
loc_54:
  54:	d9654007 	ld.bs	r11, (r5, 0x7)	// regs: r11=*(r5 + 0x7)
  58:	d8644a4d 	ld.bs	r3, (r4, 0xa4d)	// regs: r3=*(0xa4d)
  5c:	60ee      	subu	r3, r11	// regs: r3=(*(0xa4d) - *(r5 + 0x7))
  5e:	d8444300 	ld.bs	r2, (r4, 0x300)	// regs: r2=*(0x300)
  62:	648d      	cmplt	r3, r2
  64:	0c1a      	bf	0x98	// if (!T) goto loc_98;
  66:	d844483d 	ld.bs	r2, (r4, 0x83d)	// regs: r2=*(0x83d)
  6a:	d86403e1 	ld.b	r3, (r4, 0x3e1)	// regs: r3=*(0x3e1)
  6e:	648d      	cmplt	r3, r2
  70:	0c14      	bf	0x98	// if (!T) goto loc_98;
  72:	3305      	movi	r3, 5	// regs: r3=0x5
  74:	dc640301 	st.b	r3, (r4, 0x301)	// *(0x301) = 0x5
  78:	e907000c 	bez	r7, 0x90	// if (r7 == 0x0) goto loc_90;
  7c:	113a      	lrw	r1, 0x0	// regs: r1=0x0
  7e:	3234      	movi	r2, 52	// regs: r2=0x34
  80:	e4011067 	subi	r0, r1, 104	// regs: r0=0xffffff98
  84:	dd8e2001 	st.w	r12, (r14, 0x4)	// local_4 = r12
  88:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x88>, r1=<clobbered>
  8c:	d98e2001 	ld.w	r12, (r14, 0x4)	// regs: r12=local_4
loc_90:
  90:	66e1      	cmplt	r8, r11
  92:	0c03      	bf	0x98	// if (!T) goto loc_98;
  94:	6e2f      	mov	r8, r11	// regs: r8=*(r5 + 0x7)
  96:	6da7      	mov	r6, r9	// regs: r6=*(r5)
loc_98:
  98:	3300      	movi	r3, 0	// regs: r3=0x0
  9a:	2b7f      	subi	r3, 128	// regs: r3=0xffffff80
  9c:	a567      	st.b	r3, (r5, 0x7)	// *(r5 + 0x7) = 0xffffff80
loc_9e:
  9e:	e54a0000 	addi	r10, r10, 1	// regs: r10=(r10 + 0x1)
  a2:	eb4a0010 	cmpnei	r10, 16
  a6:	250b      	addi	r5, 12	// regs: r5=(r5 + 0xc)
  a8:	0bc5      	bt	0x32	// if (r10 != 0x10) goto loc_32;
  aa:	d8244301 	ld.bs	r1, (r4, 0x301)	// regs: r1=*(0x301)
  ae:	e961001f 	blsz	r1, 0xec
  b2:	d86420ee 	ld.w	r3, (r4, 0x3b8)	// regs: r3=*(0x3b8)
  b6:	2900      	subi	r1, 1	// regs: r1=(*(0x301) - 0x1)
  b8:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x3b8) & 0x1)
  bc:	7444      	zextb	r1, r1	// regs: r1=zext8((*(0x301) - 0x1))
  be:	dc240301 	st.b	r1, (r4, 0x301)	// *(0x301) = zext8((*(0x301) - 0x1))
  c2:	e9030005 	bez	r3, 0xcc	// if (r3 == 0x0) goto loc_cc;
  c6:	1109      	lrw	r0, 0x0	// regs: r0=0x0
  c8:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xc8>, r1=<clobbered>
loc_cc:
  cc:	d8644301 	ld.bs	r3, (r4, 0x301)	// regs: r3=*(0x301)
  d0:	e923000e 	bnez	r3, 0xec	// if (r3 != 0x0) goto loc_ec;
  d4:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  d8:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(0x310) & 0x4)
  dc:	e9030008 	bez	r3, 0xec	// if (r3 == 0x0) goto loc_ec;
  e0:	1123      	lrw	r1, 0x0	// regs: r1=0x0
  e2:	3234      	movi	r2, 52	// regs: r2=0x34
  e4:	e4011033 	subi	r0, r1, 52	// regs: r0=0xffffffcc
  e8:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xe8>, r1=<clobbered>
loc_ec:
  ec:	e9660032 	blsz	r6, 0x150
  f0:	d86420ce 	ld.w	r3, (r4, 0x338)	// regs: r3=*(0x338)
  f4:	c4835763 	zext	r3, r3, 27, 4	// regs: r3=zext(*(0x338))
  f8:	64da      	cmpne	r6, r3
  fa:	0c2b      	bf	0x150	// if (!T) goto loc_150;
  fc:	10b9      	lrw	r5, 0x0	// regs: r5=0x0
  fe:	10fd      	lrw	r7, 0x0	// regs: r7=0x0
 100:	9540      	ld.w	r2, (r5, 0x0)	// regs: r2=*(0x0)
 102:	649a      	cmpne	r6, r2
 104:	0c28      	bf	0x154	// if (!T) goto loc_154;
 106:	b5c0      	st.w	r6, (r5, 0x0)	// *(0x0) = r6
 108:	3200      	movi	r2, 0	// regs: r2=0x0
loc_10a:
 10a:	658d      	cmplt	r3, r6
 10c:	3304      	movi	r3, 4	// regs: r3=0x4
 10e:	3602      	movi	r6, 2	// regs: r6=0x2
 110:	a740      	st.b	r2, (r7, 0x0)	// *(0x0) = r2
 112:	c4c30c40 	inct	r6, r3, 0
 116:	8760      	ld.b	r3, (r7, 0x0)	// regs: r3=*(0x0)
 118:	b8c0      	st.w	r6, (r14, 0x0)	// local_8 = 0x2
 11a:	9540      	ld.w	r2, (r5, 0x0)	// regs: r2=*(0x0)
 11c:	6c63      	mov	r1, r8	// regs: r1=r8
 11e:	1016      	lrw	r0, 0x0	// regs: r0=0x0
 120:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x120>, r1=<clobbered>
 124:	8760      	ld.b	r3, (r7, 0x0)	// regs: r3=*(0x0)
 126:	658c      	cmphs	r3, r6
 128:	0c14      	bf	0x150	// if (!T) goto loc_150;
 12a:	9520      	ld.w	r1, (r5, 0x0)	// regs: r1=*(0x0)
 12c:	1073      	lrw	r3, 0xfff551a0	// regs: r3=0xfff551a0
 12e:	32fa      	movi	r2, 250	// regs: r2=0xfa
 130:	60c4      	addu	r3, r1	// regs: r3=(0xfff551a0 + *(0x0))
 132:	4242      	lsli	r2, r2, 2	// regs: r2=0x3e8
 134:	c4438043 	divs	r3, r3, r2	// regs: r3=((0xfff551a0 + *(0x0)) / 0x3e8)
 138:	dc640348 	st.b	r3, (r4, 0x348)	// *(0x348) = ((0xfff551a0 + *(0x0)) / 0x3e8)
 13c:	330a      	movi	r3, 10	// regs: r3=0xa
 13e:	1010      	lrw	r0, 0x0	// regs: r0=0x0
 140:	dc64032a 	st.b	r3, (r4, 0x32a)	// *(0x32a) = 0xa
 144:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x144>, r1=<clobbered>
 148:	3300      	movi	r3, 0	// regs: r3=0x0
 14a:	a760      	st.b	r3, (r7, 0x0)	// *(0x0) = 0x0
 14c:	3300      	movi	r3, 0	// regs: r3=0x0
 14e:	b560      	st.w	r3, (r5, 0x0)	// *(0x0) = 0x0
loc_150:
 150:	1402      	addi	r14, r14, 8	// regs: r14=((sp - 0x8) + 0x8)
 152:	1498      	pop	r4-r11, r15
loc_154:
 154:	8740      	ld.b	r2, (r7, 0x0)	// regs: r2=*(0x0)
 156:	2200      	addi	r2, 1	// regs: r2=(*(0x0) + 0x1)
 158:	07d9      	br	0x10a	// goto loc_10a;
 15a:	0000      	.short	0x0000
 15c:	00000000 	.long	0x00000000	// <ah_lmac>
 160:	00000000 	.long	0x00000000	// <.bss.hop_freq.13208>
 164:	00000000 	.long	0x00000000	// <ah_lmac+0x84>
 168:	00000000 	.long	0x00000000	// <.rodata.lmac_obss_eval.str1.1>
 16c:	00000000 	.long	0x00000000	// <ah_lmac+0x50>
 170:	00000000 	.long	0x00000000	// <.bss.hop_cnt.13207>
 174:	00000000 	.long	0x00000000	// <.rodata.lmac_obss_eval.str1.1+0x10>
 178:	fff551a0 	.long	0xfff551a0
 17c:	00000000 	.long	0x00000000	// <.rodata.lmac_obss_eval.str1.1+0x37>

Disassembly of section .text.lmac_chan_list_eval:

00000000 <lmac_chan_list_eval>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	1626      	subi	r14, r14, 280	// regs: r14=(sp - 0x118)
   4:	0194      	lrw	r4, 0x0	// regs: r4=0x0
   6:	d8a44301 	ld.bs	r5, (r4, 0x301)	// regs: r5=*(0x301)
   a:	e9250008 	bnez	r5, 0x1a	// if (r5 != 0x0) goto loc_1a;
   e:	d864037c 	ld.b	r3, (r4, 0x37c)	// regs: r3=*(0x37c)
  12:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x37c) & 0x2)
  16:	e9230009 	bnez	r3, 0x28	// if (r3 != 0x0) goto loc_28;
loc_1a:
  1a:	0158      	lrw	r2, 0x0	// regs: r2=0x0
  1c:	3300      	movi	r3, 0	// regs: r3=0x0
  1e:	b260      	st.w	r3, (r2, 0x0)	// *(0x0) = 0x0
  20:	0159      	lrw	r2, 0x0	// regs: r2=0x0
  22:	a260      	st.b	r3, (r2, 0x0)	// *(0x0) = 0x0
loc_24:
  24:	1606      	addi	r14, r14, 280	// regs: r14=(sp + 0x118)
  26:	1498      	pop	r4-r11, r15
loc_28:
  28:	ea8a00c5 	lrw	r10, 0x0	// regs: r10=0x0
  2c:	e52400bf 	addi	r9, r4, 192	// regs: r9=0xc0
  30:	e50e0017 	addi	r8, r14, 24	// regs: r8=((sp - 0x118) + 0x18)
  34:	dd4e2003 	st.w	r10, (r14, 0xc)	// local_10c = 0x0
loc_38:
  38:	d8640378 	ld.b	r3, (r4, 0x378)	// regs: r3=*(0x378)
  3c:	64d5      	cmplt	r5, r3
  3e:	1f16      	addi	r7, r14, 88	// regs: r7=((sp - 0x118) + 0x58)
  40:	1e26      	addi	r6, r14, 152	// regs: r6=((sp - 0x118) + 0x98)
  42:	0c7a      	bf	0x136	// if (!T) goto loc_136;
  44:	d86420ce 	ld.w	r3, (r4, 0x338)	// regs: r3=*(0x338)
  48:	d8292000 	ld.w	r1, (r9, 0x0)	// regs: r1=*(r9)
  4c:	c4835763 	zext	r3, r3, 27, 4	// regs: r3=zext(*(0x338))
  50:	64c6      	cmpne	r1, r3
  52:	086e      	bt	0x12e	// if (T) goto loc_12e;
  54:	d8444a4e 	ld.bs	r2, (r4, 0xa4e)	// regs: r2=*(0xa4e)
  58:	d864431d 	ld.bs	r3, (r4, 0x31d)	// regs: r3=*(0x31d)
  5c:	64c9      	cmplt	r2, r3
  5e:	0868      	bt	0x12e	// if (T) goto loc_12e;
  60:	d864483d 	ld.bs	r3, (r4, 0x83d)	// regs: r3=*(0x83d)
  64:	3205      	movi	r2, 5	// regs: r2=0x5
  66:	c4438043 	divs	r3, r3, r2	// regs: r3=(*(0x83d) / 0x5)
  6a:	3b33      	cmplti	r3, 20
  6c:	0c63      	bf	0x132	// if (r3 >= 0x14) goto loc_132;
  6e:	3b22      	cmplti	r3, 3
  70:	3200      	movi	r2, 0	// regs: r2=0x0
  72:	c4620c40 	inct	r3, r2, 0
loc_76:
  76:	d8490007 	ld.b	r2, (r9, 0x7)	// regs: r2=*(r9 + 0x7)
  7a:	60c8      	addu	r3, r2	// regs: r3=(r3 + *(r9 + 0x7))
  7c:	74ce      	sextb	r3, r3	// regs: r3=sext8((r3 + *(r9 + 0x7)))
  7e:	1a36      	addi	r2, r14, 216	// regs: r2=((sp - 0x118) + 0xd8)
  80:	d4a20883 	str.w	r3, (r2, r5 << 2)
  84:	d8440690 	ld.b	r2, (r4, 0x690)	// regs: r2=*(0x690)
  88:	7c8d      	mulsh	r2, r3
  8a:	d4a80881 	str.w	r1, (r8, r5 << 2)
  8e:	3164      	movi	r1, 100	// regs: r1=0x64
  90:	c4228042 	divs	r2, r2, r1	// regs: r2=(*(0x690) / 0x64)
  94:	d4a70882 	str.w	r2, (r7, r5 << 2)
  98:	d8440691 	ld.b	r2, (r4, 0x691)	// regs: r2=*(0x691)
  9c:	7cc9      	mulsh	r3, r2
  9e:	c4238043 	divs	r3, r3, r1	// regs: r3=(sext8((r3 + *(r9 + 0x7))) / 0x64)
loc_a2:
  a2:	d4a60883 	str.w	r3, (r6, r5 << 2)
  a6:	d86a0000 	ld.b	r3, (r10, 0x0)	// regs: r3=*(0x0)
  aa:	e9030012 	bez	r3, 0xce	// if (r3 == 0x0) goto loc_ce;
  ae:	1b36      	addi	r3, r14, 216	// regs: r3=((sp - 0x118) + 0xd8)
  b0:	d0a30883 	ldr.w	r3, (r3, r5 << 2)	// regs: r3=*(((sp - 0x118) + 0xd8) + (r5 << 2))
  b4:	b862      	st.w	r3, (r14, 0x8)	// local_110 = *(((sp - 0x118) + 0xd8) + (r5 << 2))
  b6:	b8a1      	st.w	r5, (r14, 0x4)	// local_114 = r5
  b8:	d0a80883 	ldr.w	r3, (r8, r5 << 2)	// regs: r3=*(((sp - 0x118) + 0x18) + (r5 << 2))
  bc:	b860      	st.w	r3, (r14, 0x0)	// local_118 = *(((sp - 0x118) + 0x18) + (r5 << 2))
  be:	d8440378 	ld.b	r2, (r4, 0x378)	// regs: r2=*(0x378)
  c2:	6cd7      	mov	r3, r5	// regs: r3=r5
  c4:	ea0101c7 	movi	r1, 455	// regs: r1=0x1c7
  c8:	0301      	lrw	r0, 0x0	// regs: r0=0x0
  ca:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xca>, r1=<clobbered>
loc_ce:
  ce:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  d0:	3d50      	cmpnei	r5, 16
  d2:	e5290017 	addi	r9, r9, 24	// regs: r9=(r9 + 0x18)
  d6:	0bb1      	bt	0x38	// if (r5 != 0x10) goto loc_38;
  d8:	d8641504 	ld.h	r3, (r4, 0xa08)	// regs: r3=*(0xa08)
  dc:	e9230033 	bnez	r3, 0x142	// if (r3 != 0x0) goto loc_142;
loc_e0:
  e0:	3500      	movi	r5, 0	// regs: r5=0x0
  e2:	ea08007f 	movi	r8, 127	// regs: r8=0x7f
  e6:	6d97      	mov	r6, r5	// regs: r6=0x0
  e8:	6de3      	mov	r7, r8	// regs: r7=0x7f
  ea:	e54e0017 	addi	r10, r14, 24	// regs: r10=((sp - 0x118) + 0x18)
  ee:	e52e00d7 	addi	r9, r14, 216	// regs: r9=((sp - 0x118) + 0xd8)
  f2:	ea8b0095 	lrw	r11, 0x0	// regs: r11=0x0
loc_f6:
  f6:	d8640378 	ld.b	r3, (r4, 0x378)	// regs: r3=*(0x378)
  fa:	64d5      	cmplt	r5, r3
  fc:	08c3      	bt	0x282	// if (T) goto loc_282;
  fe:	eb47007f 	cmpnei	r7, 127
 102:	0c06      	bf	0x10e	// if (r7 == 0x7f) goto loc_10e;
 104:	eb48007f 	cmpnei	r8, 127
 108:	0c03      	bf	0x10e	// if (r8 == 0x7f) goto loc_10e;
 10a:	e92600e7 	bnez	r6, 0x2d8	// if (r6 != 0x0) goto loc_2d8;
loc_10e:
 10e:	0310      	lrw	r0, 0x0	// regs: r0=0x0
 110:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x110>, r1=<clobbered>
 114:	3500      	movi	r5, 0	// regs: r5=0x0
 116:	1e36      	addi	r6, r14, 216	// regs: r6=((sp - 0x118) + 0xd8)
 118:	1f06      	addi	r7, r14, 24	// regs: r7=((sp - 0x118) + 0x18)
 11a:	ea88008d 	lrw	r8, 0x0	// regs: r8=0x0
loc_11e:
 11e:	d8640378 	ld.b	r3, (r4, 0x378)	// regs: r3=*(0x378)
 122:	64d5      	cmplt	r5, r3
 124:	08d1      	bt	0x2c6	// if (T) goto loc_2c6;
 126:	9863      	ld.w	r3, (r14, 0xc)	// regs: r3=local_10c
 128:	3201      	movi	r2, 1	// regs: r2=0x1
 12a:	a340      	st.b	r2, (r3, 0x0)	// *(local_10c) = 0x1
 12c:	077c      	br	0x24	// goto loc_24;
loc_12e:
 12e:	3300      	movi	r3, 0	// regs: r3=0x0
 130:	07a3      	br	0x76	// goto loc_76;
loc_132:
 132:	3314      	movi	r3, 20	// regs: r3=0x14
 134:	07a1      	br	0x76	// goto loc_76;
loc_136:
 136:	3300      	movi	r3, 0	// regs: r3=0x0
 138:	d4a80883 	str.w	r3, (r8, r5 << 2)
 13c:	d4a70883 	str.w	r3, (r7, r5 << 2)
 140:	07b1      	br	0xa2	// goto loc_a2;
loc_142:
 142:	3100      	movi	r1, 0	// regs: r1=0x0
 144:	2900      	subi	r1, 1	// regs: r1=0xffffffff
 146:	031c      	lrw	r0, 0x0	// regs: r0=0x0
 148:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0x148>, r1=<clobbered>
 14c:	03bd      	lrw	r5, 0x0	// regs: r5=0x0
 14e:	d9a40378 	ld.b	r13, (r4, 0x378)	// regs: r13=*(0x378)
 152:	d824227e 	ld.w	r1, (r4, 0x9f8)	// regs: r1=*(0x9f8)
 156:	3000      	movi	r0, 0	// regs: r0=0x0
 158:	ea0c0064 	movi	r12, 100	// regs: r12=0x64
loc_15c:
 15c:	6546      	cmpne	r1, r5
 15e:	0853      	bt	0x204	// if (T) goto loc_204;
 160:	131c      	lrw	r0, 0x0	// regs: r0=0x0
 162:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0x162>, r1=<clobbered>
 166:	d9a40378 	ld.b	r13, (r4, 0x378)	// regs: r13=*(0x378)
 16a:	e46d1000 	subi	r3, r13, 1	// regs: r3=(*(0x378) - 0x1)
 16e:	3000      	movi	r0, 0	// regs: r0=0x0
 170:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(0x378) - 0x1))
 172:	6d43      	mov	r5, r0	// regs: r5=0x0
 174:	b864      	st.w	r3, (r14, 0x10)	// local_108 = zext8((*(0x378) - 0x1))
 176:	ea0c00ff 	movi	r12, 255	// regs: r12=0xff
 17a:	2d00      	subi	r5, 1	// regs: r5=0xffffffff
 17c:	1e26      	addi	r6, r14, 152	// regs: r6=((sp - 0x118) + 0x98)
 17e:	3721      	movi	r7, 33	// regs: r7=0x21
 180:	e50e0057 	addi	r8, r14, 88	// regs: r8=((sp - 0x118) + 0x58)
 184:	ea090043 	movi	r9, 67	// regs: r9=0x43
 188:	ea0a0064 	movi	r10, 100	// regs: r10=0x64
loc_18c:
 18c:	6741      	cmplt	r0, r13
 18e:	0fa9      	bf	0xe0	// if (!T) goto loc_e0;
 190:	74f2      	sextb	r3, r12	// regs: r3=sext8(r12)
 192:	e42c0001 	addi	r1, r12, 2	// regs: r1=(r12 + 0x2)
 196:	654e      	cmpne	r3, r5
 198:	3200      	movi	r2, 0	// regs: r2=0x0
 19a:	e5600000 	addi	r11, r0, 1	// regs: r11=(r0 + 0x1)
 19e:	c4620c20 	incf	r3, r2, 0
 1a2:	7444      	zextb	r1, r1	// regs: r1=zext8((r12 + 0x2))
 1a4:	9844      	ld.w	r2, (r14, 0x10)	// regs: r2=local_108
 1a6:	676d      	cmplt	r11, r13
 1a8:	c4220c20 	incf	r1, r2, 0
 1ac:	d0660882 	ldr.w	r2, (r6, r3 << 2)	// regs: r2=*(((sp - 0x118) + 0x98) + (sext8(r12) << 2))
 1b0:	d0680883 	ldr.w	r3, (r8, r3 << 2)	// regs: r3=*(((sp - 0x118) + 0x58) + (sext8(r12) << 2))
 1b4:	7ce4      	mult	r3, r9	// regs: r3=(*(((sp - 0x118) + 0x58) + (sext8(r12) << 2)) * 0x43)
 1b6:	7c9c      	mult	r2, r7	// regs: r2=(*(((sp - 0x118) + 0x98) + (sext8(r12) << 2)) * 0x21)
 1b8:	608c      	addu	r2, r3	// regs: r2=((*(((sp - 0x118) + 0x98) + (sext8(r12) << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (sext8(r12) << 2)) * 0x43))
 1ba:	c5428042 	divs	r2, r2, r10	// regs: r2=(((*(((sp - 0x118) + 0x98) + (sext8(r12) << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (sext8(r12) << 2)) * 0x43)) / 0x64)
 1be:	5262      	asri	r3, r2, 2	// regs: r3=((((*(((sp - 0x118) + 0x98) + (sext8(r12) << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (sext8(r12) << 2)) * 0x43)) / 0x64) >> 0x2)
 1c0:	b865      	st.w	r3, (r14, 0x14)	// local_104 = ((((*(((sp - 0x118) + 0x98) + (sext8(r12) << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (sext8(r12) << 2)) * 0x43)) / 0x64) >> 0x2)
 1c2:	d0060883 	ldr.w	r3, (r6, r0 << 2)	// regs: r3=*(((sp - 0x118) + 0x98) + (r0 << 2))
 1c6:	7cdc      	mult	r3, r7	// regs: r3=(*(((sp - 0x118) + 0x98) + (r0 << 2)) * 0x21)
 1c8:	6c8f      	mov	r2, r3	// regs: r2=(*(((sp - 0x118) + 0x98) + (r0 << 2)) * 0x21)
 1ca:	d0080883 	ldr.w	r3, (r8, r0 << 2)	// regs: r3=*(((sp - 0x118) + 0x58) + (r0 << 2))
 1ce:	7ce4      	mult	r3, r9	// regs: r3=(*(((sp - 0x118) + 0x58) + (r0 << 2)) * 0x43)
 1d0:	608c      	addu	r2, r3	// regs: r2=((*(((sp - 0x118) + 0x98) + (r0 << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (r0 << 2)) * 0x43))
 1d2:	c5428043 	divs	r3, r2, r10	// regs: r3=(((*(((sp - 0x118) + 0x98) + (r0 << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (r0 << 2)) * 0x43)) / 0x64)
 1d6:	7446      	sextb	r1, r1	// regs: r1=sext8(zext8((r12 + 0x2)))
 1d8:	5361      	asri	r3, r3, 1	// regs: r3=((((*(((sp - 0x118) + 0x98) + (r0 << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (r0 << 2)) * 0x43)) / 0x64) >> 0x1)
 1da:	9845      	ld.w	r2, (r14, 0x14)	// regs: r2=local_104
 1dc:	608c      	addu	r2, r3	// regs: r2=(local_104 + ((((*(((sp - 0x118) + 0x98) + (r0 << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (r0 << 2)) * 0x43)) / 0x64) >> 0x1))
 1de:	d0260883 	ldr.w	r3, (r6, r1 << 2)	// regs: r3=*(((sp - 0x118) + 0x98) + (sext8(zext8((r12 + 0x2))) << 2))
 1e2:	d0280881 	ldr.w	r1, (r8, r1 << 2)	// regs: r1=*(((sp - 0x118) + 0x58) + (sext8(zext8((r12 + 0x2))) << 2))
 1e6:	7cdc      	mult	r3, r7	// regs: r3=(*(((sp - 0x118) + 0x98) + (sext8(zext8((r12 + 0x2))) << 2)) * 0x21)
 1e8:	7c64      	mult	r1, r9	// regs: r1=(*(((sp - 0x118) + 0x58) + (sext8(zext8((r12 + 0x2))) << 2)) * 0x43)
 1ea:	60c4      	addu	r3, r1	// regs: r3=((*(((sp - 0x118) + 0x98) + (sext8(zext8((r12 + 0x2))) << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (sext8(zext8((r12 + 0x2))) << 2)) * 0x43))
 1ec:	c5438043 	divs	r3, r3, r10	// regs: r3=(((*(((sp - 0x118) + 0x98) + (sext8(zext8((r12 + 0x2))) << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (sext8(zext8((r12 + 0x2))) << 2)) * 0x43)) / 0x64)
 1f0:	5362      	asri	r3, r3, 2	// regs: r3=((((*(((sp - 0x118) + 0x98) + (sext8(zext8((r12 + 0x2))) << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (sext8(zext8((r12 + 0x2))) << 2)) * 0x43)) / 0x64) >> 0x2)
 1f2:	608c      	addu	r2, r3	// regs: r2=((local_104 + ((((*(((sp - 0x118) + 0x98) + (r0 << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (r0 << 2)) * 0x43)) / 0x64) >> 0x1)) + ((((*(((sp - 0x118) + 0x98) + (sext8(zext8((r12 + 0x2))) << 2)) * 0x21) + (*(((sp - 0x118) + 0x58) + (sext8(zext8((r12 + 0x2))) << 2)) * 0x43)) / 0x64) >> 0x2))
 1f4:	e58c0000 	addi	r12, r12, 1	// regs: r12=(r12 + 0x1)
 1f8:	1b36      	addi	r3, r14, 216	// regs: r3=((sp - 0x118) + 0xd8)
 1fa:	d4030882 	str.w	r2, (r3, r0 << 2)
 1fe:	7730      	zextb	r12, r12	// regs: r12=zext8((r12 + 0x1))
 200:	6c2f      	mov	r0, r11	// regs: r0=(r0 + 0x1)
 202:	07c5      	br	0x18c	// goto loc_18c;
loc_204:
 204:	d861006b 	ld.b	r3, (r1, 0x6b)	// regs: r3=*(r1 + 0x6b)
 208:	e4432040 	andi	r2, r3, 64	// regs: r2=(*(r1 + 0x6b) & 0x40)
 20c:	e9220004 	bnez	r2, 0x214	// if (r2 != 0x0) goto loc_214;
loc_210:
 210:	9120      	ld.w	r1, (r1, 0x0)	// regs: r1=*(r1)
 212:	07a5      	br	0x15c	// goto loc_15c;
loc_214:
 214:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(r1 + 0x6b) & 0x2)
 218:	e923fffc 	bnez	r3, 0x210	// if (r3 != 0x0) goto loc_210;
loc_21c:
 21c:	674d      	cmplt	r3, r13
 21e:	0ff9      	bf	0x210	// if (!T) goto loc_210;
 220:	d068088a 	ldr.w	r10, (r8, r3 << 2)	// regs: r10=*(((sp - 0x118) + 0x18) + (r3 << 2))
 224:	e90a0023 	bez	r10, 0x26a	// if (r10 == 0x0) goto loc_26a;
 228:	3200      	movi	r2, 0	// regs: r2=0x0
loc_22a:
 22a:	c4424829 	lsli	r9, r2, 2	// regs: r9=(r2 << 0x2)
 22e:	6244      	addu	r9, r1	// regs: r9=((r2 << 0x2) + r1)
 230:	d9292006 	ld.w	r9, (r9, 0x18)	// regs: r9=*((((r2 << 0x2) + r1) + 0x18))
 234:	666a      	cmpne	r10, r9
 236:	081c      	bt	0x26e	// if (T) goto loc_26e;
 238:	6084      	addu	r2, r1	// regs: r2=(r2 + r1)
 23a:	d92100b2 	ld.b	r9, (r1, 0xb2)	// regs: r9=*(r1 + 0xb2)
 23e:	d9424058 	ld.bs	r10, (r2, 0x58)	// regs: r10=*(((r2 + r1) + 0x58))
 242:	7e69      	mulsh	r9, r10
 244:	c5898049 	divs	r9, r9, r12	// regs: r9=(*(r1 + 0xb2) / 0x64)
 248:	d0670882 	ldr.w	r2, (r7, r3 << 2)	// regs: r2=*(((sp - 0x118) + 0x58) + (r3 << 2))
 24c:	7666      	sextb	r9, r9	// regs: r9=sext8((*(r1 + 0xb2) / 0x64))
 24e:	6248      	addu	r9, r2	// regs: r9=(sext8((*(r1 + 0xb2) / 0x64)) + *(((sp - 0x118) + 0x58) + (r3 << 2)))
 250:	d84100b3 	ld.b	r2, (r1, 0xb3)	// regs: r2=*(r1 + 0xb3)
 254:	7ca9      	mulsh	r2, r10
 256:	c5828042 	divs	r2, r2, r12	// regs: r2=(*(r1 + 0xb3) / 0x64)
 25a:	d4670889 	str.w	r9, (r7, r3 << 2)
 25e:	748a      	sextb	r2, r2	// regs: r2=sext8((*(r1 + 0xb3) / 0x64))
 260:	d0660889 	ldr.w	r9, (r6, r3 << 2)	// regs: r9=*(((sp - 0x118) + 0x98) + (r3 << 2))
 264:	60a4      	addu	r2, r9	// regs: r2=(sext8((*(r1 + 0xb3) / 0x64)) + *(((sp - 0x118) + 0x98) + (r3 << 2)))
 266:	d4660882 	str.w	r2, (r6, r3 << 2)
loc_26a:
 26a:	2300      	addi	r3, 1	// regs: r3=(r3 + 0x1)
 26c:	07d8      	br	0x21c	// goto loc_21c;
loc_26e:
 26e:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
 270:	3a50      	cmpnei	r2, 16
 272:	0bdc      	bt	0x22a	// if (r2 != 0x10) goto loc_22a;
 274:	d4680880 	str.w	r0, (r8, r3 << 2)
 278:	d4670880 	str.w	r0, (r7, r3 << 2)
 27c:	d4660880 	str.w	r0, (r6, r3 << 2)
 280:	07f5      	br	0x26a	// goto loc_26a;
loc_282:
 282:	d0aa0883 	ldr.w	r3, (r10, r5 << 2)	// regs: r3=*(((sp - 0x118) + 0x18) + (r5 << 2))
 286:	e9030010 	bez	r3, 0x2a6	// if (r3 == 0x0) goto loc_2a6;
 28a:	d84420ce 	ld.w	r2, (r4, 0x338)	// regs: r2=*(0x338)
 28e:	c4825762 	zext	r2, r2, 27, 4	// regs: r2=zext(*(0x338))
 292:	648e      	cmpne	r3, r2
 294:	0803      	bt	0x29a	// if (T) goto loc_29a;
 296:	d0a91087 	ldr.bs	r7, (r9, r5 << 2)	// regs: r7=*(((sp - 0x118) + 0xd8) + (r5 << 2))
loc_29a:
 29a:	d0a90882 	ldr.w	r2, (r9, r5 << 2)	// regs: r2=*(((sp - 0x118) + 0xd8) + (r5 << 2))
 29e:	6609      	cmplt	r2, r8
 2a0:	0c03      	bf	0x2a6	// if (!T) goto loc_2a6;
 2a2:	760a      	sextb	r8, r2	// regs: r8=sext8(*(((sp - 0x118) + 0xd8) + (r5 << 2)))
 2a4:	6d8f      	mov	r6, r3	// regs: r6=*(((sp - 0x118) + 0x18) + (r5 << 2))
loc_2a6:
 2a6:	9843      	ld.w	r2, (r14, 0xc)	// regs: r2=local_10c
 2a8:	8240      	ld.b	r2, (r2, 0x0)	// regs: r2=*(local_10c)
 2aa:	e902000c 	bez	r2, 0x2c2	// if (r2 == 0x0) goto loc_2c2;
 2ae:	d0a90882 	ldr.w	r2, (r9, r5 << 2)	// regs: r2=*(((sp - 0x118) + 0xd8) + (r5 << 2))
 2b2:	3180      	movi	r1, 128	// regs: r1=0x80
 2b4:	b841      	st.w	r2, (r14, 0x4)	// local_114 = *(((sp - 0x118) + 0xd8) + (r5 << 2))
 2b6:	b8a0      	st.w	r5, (r14, 0x0)	// local_118 = r5
 2b8:	6c97      	mov	r2, r5	// regs: r2=r5
 2ba:	4122      	lsli	r1, r1, 2	// regs: r1=0x200
 2bc:	6c2f      	mov	r0, r11	// regs: r0=0x0
 2be:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2be>, r1=<clobbered>
loc_2c2:
 2c2:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
 2c4:	0719      	br	0xf6	// goto loc_f6;
loc_2c6:
 2c6:	d0a60882 	ldr.w	r2, (r6, r5 << 2)	// regs: r2=*(((sp - 0x118) + 0xd8) + (r5 << 2))
 2ca:	d0a70881 	ldr.w	r1, (r7, r5 << 2)	// regs: r1=*(((sp - 0x118) + 0x18) + (r5 << 2))
 2ce:	6c23      	mov	r0, r8	// regs: r0=0x0
 2d0:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2d0>, r1=<clobbered>
 2d4:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
 2d6:	0724      	br	0x11e	// goto loc_11e;
loc_2d8:
 2d8:	9863      	ld.w	r3, (r14, 0xc)	// regs: r3=local_10c
 2da:	3200      	movi	r2, 0	// regs: r2=0x0
 2dc:	a340      	st.b	r2, (r3, 0x0)	// *(local_10c) = 0x0
 2de:	d864432a 	ld.bs	r3, (r4, 0x32a)	// regs: r3=*(0x32a)
 2e2:	10b6      	lrw	r5, 0x0	// regs: r5=0x0
 2e4:	e9a30041 	bhsz	r3, 0x366	// if (r3 >= 0x0) goto loc_366;
 2e8:	d86411be 	ld.h	r3, (r4, 0x37c)	// regs: r3=*(0x37c)
 2ec:	c4435523 	zext	r3, r3, 9, 2	// regs: r3=zext(*(0x37c))
 2f0:	61ce      	subu	r7, r3	// regs: r7=(r7 - zext(*(0x37c)))
 2f2:	65e1      	cmplt	r8, r7
 2f4:	0c39      	bf	0x366	// if (!T) goto loc_366;
 2f6:	10f0      	lrw	r7, 0x0	// regs: r7=0x0
 2f8:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(0x0)
 2fa:	64da      	cmpne	r6, r3
 2fc:	0832      	bt	0x360	// if (T) goto loc_360;
 2fe:	8560      	ld.b	r3, (r5, 0x0)	// regs: r3=*(0x0)
 300:	2300      	addi	r3, 1	// regs: r3=(*(0x0) + 0x1)
 302:	74ce      	sextb	r3, r3	// regs: r3=sext8((*(0x0) + 0x1))
 304:	3b24      	cmplti	r3, 5
 306:	a560      	st.b	r3, (r5, 0x0)	// *(0x0) = sext8((*(0x0) + 0x1))
 308:	0a8e      	bt	0x24	// if (r3 < 0x5) goto loc_24;
 30a:	1074      	lrw	r3, 0xfff551a0	// regs: r3=0xfff551a0
 30c:	32fa      	movi	r2, 250	// regs: r2=0xfa
 30e:	4242      	lsli	r2, r2, 2	// regs: r2=0x3e8
 310:	60d8      	addu	r3, r6	// regs: r3=(0xfff551a0 + r6)
 312:	c4438023 	divu	r3, r3, r2	// regs: r3=((0xfff551a0 + r6) / 0x3e8)
 316:	dc640348 	st.b	r3, (r4, 0x348)	// *(0x348) = ((0xfff551a0 + r6) / 0x3e8)
 31a:	6c5b      	mov	r1, r6	// regs: r1=r6
 31c:	330a      	movi	r3, 10	// regs: r3=0xa
 31e:	1010      	lrw	r0, 0x0	// regs: r0=0x0
 320:	dc64032a 	st.b	r3, (r4, 0x32a)	// *(0x32a) = 0xa
 324:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x324>, r1=<clobbered>
 328:	3300      	movi	r3, 0	// regs: r3=0x0
 32a:	b760      	st.w	r3, (r7, 0x0)	// *(0x0) = 0x0
loc_32c:
 32c:	a560      	st.b	r3, (r5, 0x0)	// *(r5) = r3
 32e:	067b      	br	0x24	// goto loc_24;
 330:	00000000 	.long	0x00000000	// <ah_lmac>
 334:	00000000 	.long	0x00000000	// <.bss.hop_freq.13230>
 338:	00000000 	.long	0x00000000	// <.bss.hop_cnt.13231>
 33c:	00000000 	.long	0x00000000	// <.bss.flag_err.13241>
 340:	00000000 	.long	0x00000000	// <.rodata.lmac_chan_list_eval.str1.1>
 344:	00000000 	.long	0x00000000	// <.rodata.lmac_chan_list_eval.str1.1+0x40>
 348:	00000000 	.long	0x00000000	// <.rodata.lmac_chan_list_eval.str1.1+0x71>
 34c:	00000000 	.long	0x00000000	// <.rodata.lmac_chan_list_eval.str1.1+0x91>
 350:	00000000 	.long	0x00000000	// <ah_lmac+0xa00>
 354:	00000000 	.long	0x00000000	// <ah_lmac+0x9f8>
 358:	fff551a0 	.long	0xfff551a0
 35c:	00000000 	.long	0x00000000	// <.rodata.lmac_chan_list_eval.str1.1+0x9a>
loc_360:
 360:	b7c0      	st.w	r6, (r7, 0x0)	// *(r7) = r6
 362:	3301      	movi	r3, 1	// regs: r3=0x1
 364:	07e4      	br	0x32c	// goto loc_32c;
loc_366:
 366:	d8654000 	ld.bs	r3, (r5, 0x0)	// regs: r3=*(0x0)
 36a:	e9630004 	blsz	r3, 0x372
 36e:	2b00      	subi	r3, 1	// regs: r3=(*(0x0) - 0x1)
 370:	07de      	br	0x32c	// goto loc_32c;
 372:	1063      	lrw	r3, 0x0	// regs: r3=0x0
 374:	3200      	movi	r2, 0	// regs: r2=0x0
 376:	b340      	st.w	r2, (r3, 0x0)	// *(0x0) = 0x0
 378:	0656      	br	0x24	// goto loc_24;
 37a:	0000      	.short	0x0000
 37c:	00000000 	.long	0x00000000	// <.bss.hop_freq.13230>

Disassembly of section .text.lmac_doze_enter:

00000000 <lmac_doze_enter>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	3400      	movi	r4, 0	// regs: r4=0x0
   4:	10ad      	lrw	r5, 0x0	// regs: r5=0x0
   6:	2c00      	subi	r4, 1	// regs: r4=0xffffffff
loc_8:
   8:	9540      	ld.w	r2, (r5, 0x0)	// regs: r2=*(0x0)
   a:	9270      	ld.w	r3, (r2, 0x40)	// regs: r3=*((*(0x0) + 0x40))
   c:	3b87      	bclri	r3, 7	// regs: r3=(*((*(0x0) + 0x40)) & ~(0x1 << 0x7))
   e:	b270      	st.w	r3, (r2, 0x40)	// *((*(0x0) + 0x40)) = (*((*(0x0) + 0x40)) & ~(0x1 << 0x7))
  10:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0x10>, r1=<clobbered>
  14:	9560      	ld.w	r3, (r5, 0x0)	// regs: r3=*(0x0)
  16:	9350      	ld.w	r2, (r3, 0x40)	// regs: r2=*((*(0x0) + 0x40))
  18:	ec420080 	ori	r2, r2, 128	// regs: r2=(*((*(0x0) + 0x40)) | 0x80)
  1c:	b350      	st.w	r2, (r3, 0x40)	// *((*(0x0) + 0x40)) = (*((*(0x0) + 0x40)) | 0x80)
  1e:	b392      	st.w	r4, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0xffffffff
  20:	936d      	ld.w	r3, (r3, 0x34)	// regs: r3=*((*(0x0) + 0x34))
  22:	e923fff3 	bnez	r3, 0x8	// if (r3 != 0x0) goto loc_8;
  26:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  28:	3101      	movi	r1, 1	// regs: r1=0x1
  2a:	d8430680 	ld.b	r2, (r3, 0x680)	// regs: r2=*(0x680)
  2e:	c4415c00 	ins	r2, r1, 0, 0
  32:	dc430680 	st.b	r2, (r3, 0x680)	// *(0x680) = *(0x680)
  36:	1492      	pop	r4-r5, r15
  38:	00000000 	.long	0x00000000	// <LMAC>
  3c:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_doze_exit:

00000000 <lmac_doze_exit>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	1069      	lrw	r3, 0x0	// regs: r3=0x0
   4:	3000      	movi	r0, 0	// regs: r0=0x0
   6:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   8:	9270      	ld.w	r3, (r2, 0x40)	// regs: r3=*((*(0x0) + 0x40))
   a:	3b87      	bclri	r3, 7	// regs: r3=(*((*(0x0) + 0x40)) & ~(0x1 << 0x7))
   c:	b270      	st.w	r3, (r2, 0x40)	// *((*(0x0) + 0x40)) = (*((*(0x0) + 0x40)) & ~(0x1 << 0x7))
   e:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0xe>, r1=<clobbered>
  12:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  14:	3100      	movi	r1, 0	// regs: r1=0x0
  16:	d8430680 	ld.b	r2, (r3, 0x680)	// regs: r2=*(0x680)
  1a:	c4415c00 	ins	r2, r1, 0, 0
  1e:	dc430680 	st.b	r2, (r3, 0x680)	// *(0x680) = *(0x680)
  22:	1490      	pop	r15
  24:	0000      	.short	0x0000	// <LMAC>
  26:	0000      	.short	0x0000
  28:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_rf_reset:

00000000 <lmac_rf_reset>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <lmac_doze_enter> // arg_bytes: 0; regs: r0=<ret lmac_doze_enter@0x2>, r1=<clobbered>
   6:	e0000000 	bsr	0x0	// <ah_rf_close>; regs: r0=<ret ah_rf_close@0x6>, r1=<clobbered>
   a:	e0000000 	bsr	0x0	// <ah_rf_open>; regs: r0=<ret ah_rf_open@0xa>, r1=<clobbered>
   e:	e0000000 	bsr	0x0	// <lmac_doze_exit> // arg_bytes: 0; regs: r0=<ret lmac_doze_exit@0xe>, r1=<clobbered>
  12:	1490      	pop	r15

Disassembly of section .text.lmac_chip_monitor:

00000000 <lmac_chip_monitor>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	1425      	subi	r14, r14, 20	// regs: r14=(sp - 0x14)
   4:	3002      	movi	r0, 2	// regs: r0=0x2
   6:	e0000000 	bsr	0x0	// <tsensor_meas>; regs: r0=<ret tsensor_meas@0x6>, r1=<clobbered>
   a:	7443      	sexth	r1, r0	// regs: r1=sext16(<ret tsensor_meas@0x6>)
   c:	eb210095 	cmplti	r1, 150
  10:	018d      	lrw	r4, 0x0	// regs: r4=0x0
  12:	0cce      	bf	0x1ae	// if (r1 >= 0x96) goto loc_1ae;
  14:	dc24219e 	st.w	r1, (r4, 0x678)	// *(0x678) = sext16(<ret tsensor_meas@0x6>)
loc_18:
  18:	e0000000 	bsr	0x0	// <vcc_meas>; regs: r0=<ret vcc_meas@0x18>, r1=<clobbered>
  1c:	ea8900d0 	lrw	r9, 0x0	// regs: r9=0x0
  20:	dc04219f 	st.w	r0, (r4, 0x67c)	// *(0x67c) = <ret vcc_meas@0x18>
  24:	e0000000 	bsr	0x0	// <vdd13b_meas>; regs: r0=<ret vdd13b_meas@0x24>, r1=<clobbered>
  28:	dc0421b6 	st.w	r0, (r4, 0x6d8)	// *(0x6d8) = <ret vdd13b_meas@0x24>
  2c:	e0000000 	bsr	0x0	// <vdd13c_meas>; regs: r0=<ret vdd13c_meas@0x2c>, r1=<clobbered>
  30:	dc0421b7 	st.w	r0, (r4, 0x6dc)	// *(0x6dc) = <ret vdd13c_meas@0x2c>
  34:	d8694009 	ld.bs	r3, (r9, 0x9)	// regs: r3=*(0x9)
  38:	3023      	movi	r0, 35	// regs: r0=0x23
  3a:	d844219e 	ld.w	r2, (r4, 0x678)	// regs: r2=*(0x678)
  3e:	586d      	subu	r3, r0, r3	// regs: r3=(0x23 - *(0x9))
  40:	60c8      	addu	r3, r2	// regs: r3=((0x23 - *(0x9)) + *(0x678))
  42:	dc64219e 	st.w	r3, (r4, 0x678)	// *(0x678) = ((0x23 - *(0x9)) + *(0x678))
  46:	600e      	subu	r0, r3	// regs: r0=(0x23 - ((0x23 - *(0x9)) + *(0x678)))
  48:	e0000000 	bsr	0x0	// <__floatsisf>; regs: r0=<ret __floatsisf@0x48>, r1=<clobbered>
  4c:	ea214120 	movih	r1, 16672	// regs: r1=(0x4120 << 0x10)
  50:	e0000000 	bsr	0x0	// <__divsf3>; regs: r0=<ret __divsf3@0x50>, r1=<clobbered>
  54:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x54>, r1=<clobbered>
  58:	015d      	lrw	r2, 0xcccccccd	// regs: r2=0xcccccccd
  5a:	017c      	lrw	r3, 0x3fe4cccc	// regs: r3=0x3fe4cccc
  5c:	e0000000 	bsr	0x0	// <__muldf3>; regs: r0=<ret __muldf3@0x5c>, r1=<clobbered>
  60:	3200      	movi	r2, 0	// regs: r2=0x0
  62:	ea233fe0 	movih	r3, 16352	// regs: r3=(0x3fe0 << 0x10)
  66:	6e83      	mov	r10, r0	// regs: r10=<ret __muldf3@0x5c>
  68:	6e07      	mov	r8, r1	// regs: r8=<clobbered>
  6a:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x6a>, r1=<clobbered>
  6e:	e0000000 	bsr	0x0	// <__truncdfsf2>; regs: r0=<ret __truncdfsf2@0x6e>, r1=<clobbered>
  72:	6ec3      	mov	r11, r0	// regs: r11=<ret __truncdfsf2@0x6e>
  74:	0262      	lrw	r3, 0x3fc99999	// regs: r3=0x3fc99999
  76:	0241      	lrw	r2, 0x9999999a	// regs: r2=0x9999999a
  78:	6c63      	mov	r1, r8	// regs: r1=<clobbered>
  7a:	6d43      	mov	r5, r0	// regs: r5=<ret __truncdfsf2@0x6e>
  7c:	6c2b      	mov	r0, r10	// regs: r0=<ret __muldf3@0x5c>
  7e:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x7e>, r1=<clobbered>
  82:	e0000000 	bsr	0x0	// <__truncdfsf2>; regs: r0=<ret __truncdfsf2@0x82>, r1=<clobbered>
  86:	6dc3      	mov	r7, r0	// regs: r7=<ret __truncdfsf2@0x82>
  88:	6c63      	mov	r1, r8	// regs: r1=<clobbered>
  8a:	6d83      	mov	r6, r0	// regs: r6=<ret __truncdfsf2@0x82>
  8c:	6c2b      	mov	r0, r10	// regs: r0=<ret __muldf3@0x5c>
  8e:	e0000000 	bsr	0x0	// <__truncdfsf2>; regs: r0=<ret __truncdfsf2@0x8e>, r1=<clobbered>
  92:	d8690007 	ld.b	r3, (r9, 0x7)	// regs: r3=*(0x7)
  96:	3b42      	cmpnei	r3, 2
  98:	6e83      	mov	r10, r0	// regs: r10=<ret __truncdfsf2@0x8e>
  9a:	6e03      	mov	r8, r0	// regs: r8=<ret __truncdfsf2@0x8e>
  9c:	09a3      	bt	0x3e2	// if (r3 != 0x2) goto loc_3e2;
  9e:	d86420ce 	ld.w	r3, (r4, 0x338)	// regs: r3=*(0x338)
  a2:	c4835763 	zext	r3, r3, 27, 4	// regs: r3=zext(*(0x338))
  a6:	024c      	lrw	r2, 0xd6d7f	// regs: r2=0xd6d7f
  a8:	64c9      	cmplt	r2, r3
  aa:	0886      	bt	0x1b6	// if (T) goto loc_1b6;
  ac:	6c2f      	mov	r0, r11	// regs: r0=<ret __truncdfsf2@0x6e>
  ae:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0xae>, r1=<clobbered>
  b2:	0250      	lrw	r2, 0x9999999a	// regs: r2=0x9999999a
  b4:	026f      	lrw	r3, 0x3fd99999	// regs: r3=0x3fd99999
  b6:	e0000000 	bsr	0x0	// <__subdf3>; regs: r0=<ret __subdf3@0xb6>, r1=<clobbered>
  ba:	e0000000 	bsr	0x0	// <__truncdfsf2>; regs: r0=<ret __truncdfsf2@0xba>, r1=<clobbered>
  be:	6d43      	mov	r5, r0	// regs: r5=<ret __truncdfsf2@0xba>
  c0:	6c1f      	mov	r0, r7	// regs: r0=<ret __truncdfsf2@0x82>
  c2:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0xc2>, r1=<clobbered>
  c6:	0255      	lrw	r2, 0x9999999a	// regs: r2=0x9999999a
  c8:	0274      	lrw	r3, 0x3fd99999	// regs: r3=0x3fd99999
  ca:	e0000000 	bsr	0x0	// <__subdf3>; regs: r0=<ret __subdf3@0xca>, r1=<clobbered>
  ce:	e0000000 	bsr	0x0	// <__truncdfsf2>; regs: r0=<ret __truncdfsf2@0xce>, r1=<clobbered>
  d2:	6d83      	mov	r6, r0	// regs: r6=<ret __truncdfsf2@0xce>
  d4:	6c2b      	mov	r0, r10	// regs: r0=<ret __truncdfsf2@0x8e>
  d6:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0xd6>, r1=<clobbered>
  da:	025a      	lrw	r2, 0x9999999a	// regs: r2=0x9999999a
  dc:	0279      	lrw	r3, 0x3fd99999	// regs: r3=0x3fd99999
  de:	e0000000 	bsr	0x0	// <__subdf3>; regs: r0=<ret __subdf3@0xde>, r1=<clobbered>
loc_e2:
  e2:	e0000000 	bsr	0x0	// <__truncdfsf2>; regs: r0=<ret __truncdfsf2@0xe2>, r1=<clobbered>
  e6:	6e03      	mov	r8, r0	// regs: r8=<ret __truncdfsf2@0xe2>
loc_e8:
  e8:	ea21c0c0 	movih	r1, 49344	// regs: r1=(0xc0c0 << 0x10)
  ec:	6c17      	mov	r0, r5	// regs: r0=r5
  ee:	e0000000 	bsr	0x0	// <__ltsf2>; regs: r0=<ret __ltsf2@0xee>, r1=<clobbered>
  f2:	ea27c0c0 	movih	r7, 49344	// regs: r7=(0xc0c0 << 0x10)
  f6:	38df      	btsti	r0, 31
  f8:	6c5f      	mov	r1, r7	// regs: r1=(0xc0c0 << 0x10)
  fa:	6c1b      	mov	r0, r6	// regs: r0=r6
  fc:	c4a70c40 	inct	r5, r7, 0
 100:	e0000000 	bsr	0x0	// <__ltsf2>; regs: r0=<ret __ltsf2@0x100>, r1=<clobbered>
 104:	38df      	btsti	r0, 31
 106:	6c5f      	mov	r1, r7	// regs: r1=(0xc0c0 << 0x10)
 108:	6c23      	mov	r0, r8	// regs: r0=r8
 10a:	c4c70c40 	inct	r6, r7, 0
 10e:	e0000000 	bsr	0x0	// <__ltsf2>; regs: r0=<ret __ltsf2@0x10e>, r1=<clobbered>
 112:	38df      	btsti	r0, 31
 114:	c4e80c20 	incf	r7, r8, 0
 118:	d90403df 	ld.b	r8, (r4, 0x3df)	// regs: r8=*(0x3df)
 11c:	e5082004 	andi	r8, r8, 4	// regs: r8=(*(0x3df) & 0x4)
 120:	e9280026 	bnez	r8, 0x16c	// if (r8 != 0x0) goto loc_16c;
 124:	6c17      	mov	r0, r5	// regs: r0=r5
 126:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x126>, r1=<clobbered>
 12a:	6c87      	mov	r2, r1	// regs: r2=<clobbered>
 12c:	6c43      	mov	r1, r0	// regs: r1=<ret __extendsfdf2@0x126>
 12e:	d8041346 	ld.h	r0, (r4, 0x68c)	// regs: r0=*(0x68c)
 132:	e0000000 	bsr	0x0	// <lmac_amp_atten_calc>; regs: r0=<ret lmac_amp_atten_calc@0x132>, r1=<clobbered>
 136:	3105      	movi	r1, 5	// regs: r1=0x5
 138:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0x138>, r1=<clobbered>
 13c:	6c1b      	mov	r0, r6	// regs: r0=r6
 13e:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x13e>, r1=<clobbered>
 142:	6c87      	mov	r2, r1	// regs: r2=<clobbered>
 144:	6c43      	mov	r1, r0	// regs: r1=<ret __extendsfdf2@0x13e>
 146:	d8041342 	ld.h	r0, (r4, 0x684)	// regs: r0=*(0x684)
 14a:	e0000000 	bsr	0x0	// <lmac_amp_atten_calc>; regs: r0=<ret lmac_amp_atten_calc@0x14a>, r1=<clobbered>
 14e:	3101      	movi	r1, 1	// regs: r1=0x1
 150:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0x150>, r1=<clobbered>
 154:	6c1f      	mov	r0, r7	// regs: r0=(0xc0c0 << 0x10)
 156:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x156>, r1=<clobbered>
 15a:	6c87      	mov	r2, r1	// regs: r2=<clobbered>
 15c:	6c43      	mov	r1, r0	// regs: r1=<ret __extendsfdf2@0x156>
 15e:	d8041341 	ld.h	r0, (r4, 0x682)	// regs: r0=*(0x682)
 162:	e0000000 	bsr	0x0	// <lmac_amp_atten_calc>; regs: r0=<ret lmac_amp_atten_calc@0x162>, r1=<clobbered>
 166:	6c63      	mov	r1, r8	// regs: r1=(*(0x3df) & 0x4)
 168:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0x168>, r1=<clobbered>
loc_16c:
 16c:	d8690008 	ld.b	r3, (r9, 0x8)	// regs: r3=*(0x8)
 170:	e9230067 	bnez	r3, 0x23e	// if (r3 != 0x0) goto loc_23e;
 174:	d844219e 	ld.w	r2, (r4, 0x678)	// regs: r2=*(0x678)
 178:	d8640680 	ld.b	r3, (r4, 0x680)	// regs: r3=*(0x680)
 17c:	e942005b 	bhz	r2, 0x232
 180:	e4432070 	andi	r2, r3, 112	// regs: r2=(*(0x680) & 0x70)
 184:	eb420070 	cmpnei	r2, 112
 188:	0c5b      	bf	0x23e	// if (r2 == 0x70) goto loc_23e;
 18a:	c4235460 	zext	r0, r3, 3, 1	// regs: r0=zext(*(0x680))
 18e:	3825      	cmplti	r0, 6
 190:	0c4f      	bf	0x22e	// if (r0 >= 0x6) goto loc_22e;
 192:	c48354c2 	zext	r2, r3, 6, 4	// regs: r2=zext(*(0x680))
 196:	2001      	addi	r0, 2	// regs: r0=(zext(*(0x680)) + 0x2)
 198:	640a      	cmpne	r2, r0
 19a:	0c52      	bf	0x23e	// if (!T) goto loc_23e;
 19c:	e4002007 	andi	r0, r0, 7	// regs: r0=((zext(*(0x680)) + 0x2) & 0x7)
loc_1a0:
 1a0:	c4605c44 	ins	r3, r0, 6, 4
 1a4:	dc640680 	st.b	r3, (r4, 0x680)	// *(r4 + 0x680) = r3
 1a8:	e0000000 	bsr	0x0	// <pmu_vref_vol_set_sec>; regs: r0=<ret pmu_vref_vol_set_sec@0x1a8>, r1=<clobbered>
 1ac:	0449      	br	0x23e	// goto loc_23e;
loc_1ae:
 1ae:	1313      	lrw	r0, 0x0	// regs: r0=0x0
 1b0:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1b0>, r1=<clobbered>
 1b4:	0732      	br	0x18	// goto loc_18;
loc_1b6:
 1b6:	d8640308 	ld.b	r3, (r4, 0x308)	// regs: r3=*(0x308)
 1ba:	3b01      	cmphsi	r3, 2
 1bc:	081d      	bt	0x1f6	// if (r3 >= 0x2) goto loc_1f6;
 1be:	6c2f      	mov	r0, r11	// regs: r0=<ret __truncdfsf2@0x6e>
 1c0:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x1c0>, r1=<clobbered>
 1c4:	1347      	lrw	r2, 0xcccccccd	// regs: r2=0xcccccccd
 1c6:	136e      	lrw	r3, 0x3feccccc	// regs: r3=0x3feccccc
 1c8:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x1c8>, r1=<clobbered>
 1cc:	e0000000 	bsr	0x0	// <__truncdfsf2>; regs: r0=<ret __truncdfsf2@0x1cc>, r1=<clobbered>
 1d0:	6d43      	mov	r5, r0	// regs: r5=<ret __truncdfsf2@0x1cc>
 1d2:	6c1f      	mov	r0, r7	// regs: r0=<ret __truncdfsf2@0x82>
 1d4:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x1d4>, r1=<clobbered>
 1d8:	1342      	lrw	r2, 0xcccccccd	// regs: r2=0xcccccccd
 1da:	1369      	lrw	r3, 0x3feccccc	// regs: r3=0x3feccccc
 1dc:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x1dc>, r1=<clobbered>
 1e0:	e0000000 	bsr	0x0	// <__truncdfsf2>; regs: r0=<ret __truncdfsf2@0x1e0>, r1=<clobbered>
 1e4:	6d83      	mov	r6, r0	// regs: r6=<ret __truncdfsf2@0x1e0>
 1e6:	6c2b      	mov	r0, r10	// regs: r0=<ret __truncdfsf2@0x8e>
 1e8:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x1e8>, r1=<clobbered>
 1ec:	125d      	lrw	r2, 0xcccccccd	// regs: r2=0xcccccccd
 1ee:	1364      	lrw	r3, 0x3feccccc	// regs: r3=0x3feccccc
loc_1f0:
 1f0:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x1f0>, r1=<clobbered>
 1f4:	0777      	br	0xe2	// goto loc_e2;
loc_1f6:
 1f6:	3b42      	cmpnei	r3, 2
 1f8:	0b78      	bt	0xe8	// if (r3 != 0x2) goto loc_e8;
 1fa:	6c2f      	mov	r0, r11	// regs: r0=<ret __truncdfsf2@0x6e>
 1fc:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x1fc>, r1=<clobbered>
 200:	1340      	lrw	r2, 0x66666666	// regs: r2=0x66666666
 202:	1361      	lrw	r3, 0x3fe66666	// regs: r3=0x3fe66666
 204:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x204>, r1=<clobbered>
 208:	e0000000 	bsr	0x0	// <__truncdfsf2>; regs: r0=<ret __truncdfsf2@0x208>, r1=<clobbered>
 20c:	6d43      	mov	r5, r0	// regs: r5=<ret __truncdfsf2@0x208>
 20e:	6c1f      	mov	r0, r7	// regs: r0=<ret __truncdfsf2@0x82>
 210:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x210>, r1=<clobbered>
 214:	125d      	lrw	r2, 0x33333333	// regs: r2=0x33333333
 216:	127e      	lrw	r3, 0x3fe33333	// regs: r3=0x3fe33333
 218:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x218>, r1=<clobbered>
 21c:	e0000000 	bsr	0x0	// <__truncdfsf2>; regs: r0=<ret __truncdfsf2@0x21c>, r1=<clobbered>
 220:	6d83      	mov	r6, r0	// regs: r6=<ret __truncdfsf2@0x21c>
 222:	6c2b      	mov	r0, r10	// regs: r0=<ret __truncdfsf2@0x8e>
 224:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x224>, r1=<clobbered>
 228:	1258      	lrw	r2, 0x33333333	// regs: r2=0x33333333
 22a:	1279      	lrw	r3, 0x3fe33333	// regs: r3=0x3fe33333
 22c:	07e2      	br	0x1f0	// goto loc_1f0;
loc_22e:
 22e:	3007      	movi	r0, 7	// regs: r0=0x7
 230:	07b8      	br	0x1a0	// goto loc_1a0;
 232:	c4235460 	zext	r0, r3, 3, 1	// regs: r0=zext(<arg3>)
 236:	c48354c2 	zext	r2, r3, 6, 4	// regs: r2=zext(<arg3>)
 23a:	640a      	cmpne	r2, r0
 23c:	0bb2      	bt	0x1a0	// if (T) goto loc_1a0;
loc_23e:
 23e:	d864219e 	ld.w	r3, (r4, 0x678)	// regs: r3=*(r4 + 0x678)
 242:	eb230054 	cmplti	r3, 85
 246:	080d      	bt	0x260	// if (r3 < 0x55) goto loc_260;
 248:	1212      	lrw	r0, 0x0	// regs: r0=0x0
 24a:	3207      	movi	r2, 7	// regs: r2=0x7
 24c:	d9802009 	ld.w	r12, (r0, 0x24)	// regs: r12=*(0x24)
 250:	b841      	st.w	r2, (r14, 0x4)	// stack_p4 = 0x7
 252:	b862      	st.w	r3, (r14, 0x8)	// stack_p8 = *(r4 + 0x678)
 254:	e90c0006 	bez	r12, 0x260	// if (r12 == 0x0) goto loc_260;
 258:	3310      	movi	r3, 16	// regs: r3=0x10
 25a:	1a01      	addi	r2, r14, 4	// regs: r2=(sp + 0x4)
 25c:	311b      	movi	r1, 27	// regs: r1=0x1b
 25e:	7bf1      	jsr	r12
loc_260:
 260:	d844219e 	ld.w	r2, (r4, 0x678)	// regs: r2=*(r4 + 0x678)
 264:	eb220059 	cmplti	r2, 90
 268:	d864036d 	ld.b	r3, (r4, 0x36d)	// regs: r3=*(r4 + 0x36d)
 26c:	c48354a1 	zext	r1, r3, 5, 4	// regs: r1=zext(*(r4 + 0x36d))
 270:	0c98      	bf	0x3a0	// if (r2 >= 0x5a) goto loc_3a0;
 272:	c4435462 	zext	r2, r3, 3, 2	// regs: r2=zext(*(r4 + 0x36d))
 276:	644a      	cmpne	r2, r1
 278:	0c0e      	bf	0x294	// if (!T) goto loc_294;
 27a:	d84409e2 	ld.b	r2, (r4, 0x9e2)	// regs: r2=*(r4 + 0x9e2)
 27e:	e4422002 	andi	r2, r2, 2	// regs: r2=(*(r4 + 0x9e2) & 0x2)
 282:	e9220009 	bnez	r2, 0x294	// if (r2 != 0x0) goto loc_294;
 286:	c4615c22 	ins	r3, r1, 3, 2
 28a:	dc64036d 	st.b	r3, (r4, 0x36d)	// *(r4 + 0x36d) = *(r4 + 0x36d)
 28e:	1202      	lrw	r0, 0x0	// regs: r0=0x0
loc_290:
 290:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x290>, r1=<clobbered>
loc_294:
 294:	d864219e 	ld.w	r3, (r4, 0x678)	// regs: r3=*(r4 + 0x678)
 298:	eb230069 	cmplti	r3, 106
 29c:	0c8e      	bf	0x3b8	// if (r3 >= 0x6a) goto loc_3b8;
 29e:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(r4)
 2a0:	836a      	ld.b	r3, (r3, 0xa)	// regs: r3=*((*(r4) + 0xa))
 2a2:	e4632001 	andi	r3, r3, 1	// regs: r3=(*((*(r4) + 0xa)) & 0x1)
 2a6:	e9030014 	bez	r3, 0x2ce	// if (r3 == 0x0) goto loc_2ce;
 2aa:	d8640680 	ld.b	r3, (r4, 0x680)	// regs: r3=*(r4 + 0x680)
 2ae:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r4 + 0x680) & 0x1)
 2b2:	e903000e 	bez	r3, 0x2ce	// if (r3 == 0x0) goto loc_2ce;
 2b6:	e0000000 	bsr	0x0	// <lmac_doze_exit> // arg_bytes: 0; regs: r0=<ret lmac_doze_exit@0x2b6>, r1=<clobbered>
 2ba:	d8640680 	ld.b	r3, (r4, 0x680)	// regs: r3=*(r4 + 0x680)
 2be:	3200      	movi	r2, 0	// regs: r2=0x0
 2c0:	c4625c00 	ins	r3, r2, 0, 0
 2c4:	dc640680 	st.b	r3, (r4, 0x680)	// *(r4 + 0x680) = *(r4 + 0x680)
 2c8:	1114      	lrw	r0, 0x0	// regs: r0=0x0
loc_2ca:
 2ca:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2ca>, r1=<clobbered>
loc_2ce:
 2ce:	3300      	movi	r3, 0	// regs: r3=0x0
 2d0:	d844219e 	ld.w	r2, (r4, 0x678)	// regs: r2=*(r4 + 0x678)
 2d4:	2b22      	subi	r3, 35	// regs: r3=0xffffffdd
 2d6:	64c9      	cmplt	r2, r3
 2d8:	0882      	bt	0x3dc	// if (T) goto loc_3dc;
 2da:	74cb      	sexth	r3, r2	// regs: r3=sext16(*(r4 + 0x678))
 2dc:	eb220055 	cmplti	r2, 86
 2e0:	325a      	movi	r2, 90	// regs: r2=0x5a
 2e2:	c4620c20 	incf	r3, r2, 0
loc_2e6:
 2e6:	320a      	movi	r2, 10	// regs: r2=0xa
 2e8:	232c      	addi	r3, 45	// regs: r3=(r3 + 0x2d)
 2ea:	c4438043 	divs	r3, r3, r2	// regs: r3=((r3 + 0x2d) / 0xa)
 2ee:	114c      	lrw	r2, 0x0	// regs: r2=0x0
 2f0:	d0620023 	ldr.b	r3, (r2, r3 << 0)	// regs: r3=*(0x0 + (((r3 + 0x2d) / 0xa) << 0))
 2f4:	d844068f 	ld.b	r2, (r4, 0x68f)	// regs: r2=*(r4 + 0x68f)
 2f8:	60c8      	addu	r3, r2	// regs: r3=(*(0x0 + (((r3 + 0x2d) / 0xa) << 0)) + *(r4 + 0x68f))
 2fa:	6c0f      	mov	r0, r3	// regs: r0=(*(0x0 + (((r3 + 0x2d) / 0xa) << 0)) + *(r4 + 0x68f))
 2fc:	74ce      	sextb	r3, r3	// regs: r3=sext8((*(0x0 + (((r3 + 0x2d) / 0xa) << 0)) + *(r4 + 0x68f)))
 2fe:	3b3f      	cmplti	r3, 32
 300:	0802      	bt	0x304	// if (r3 < 0x20) goto loc_304;
 302:	301f      	movi	r0, 31	// regs: r0=0x1f
loc_304:
 304:	74c2      	sextb	r3, r0	// regs: r3=sext8(r0)
 306:	e9a30003 	bhsz	r3, 0x30c	// if (r3 >= 0x0) goto loc_30c;
 30a:	3000      	movi	r0, 0	// regs: r0=0x0
loc_30c:
 30c:	7400      	zextb	r0, r0	// regs: r0=zext8(r0)
 30e:	e0000000 	bsr	0x0	// <xo_set_cs_sec>; regs: r0=<ret xo_set_cs_sec@0x30e>, r1=<clobbered>
 312:	3500      	movi	r5, 0	// regs: r5=0x0
loc_314:
 314:	6c97      	mov	r2, r5	// regs: r2=r5
 316:	3105      	movi	r1, 5	// regs: r1=0x5
 318:	6c3b      	mov	r0, r14	// regs: r0=sp
 31a:	e0000000 	bsr	0x0	// <ah_rfdigicali_get_rx_dcoc>; regs: r0=<ret ah_rfdigicali_get_rx_dcoc@0x31a>, r1=<clobbered>
 31e:	d86e1000 	ld.h	r3, (r14, 0x0)	// regs: r3=stack_0
 322:	d8441389 	ld.h	r2, (r4, 0x712)	// regs: r2=*(r4 + 0x712)
 326:	608c      	addu	r2, r3	// regs: r2=(*(r4 + 0x712) + stack_0)
 328:	d82e1001 	ld.h	r1, (r14, 0x2)	// regs: r1=stack_p2
 32c:	dc64141c 	st.h	r3, (r4, 0x838)	// *(r4 + 0x838) = stack_0
 330:	dc4e1000 	st.h	r2, (r14, 0x0)	// stack_0 = (*(r4 + 0x712) + stack_0)
 334:	d864138a 	ld.h	r3, (r4, 0x714)	// regs: r3=*(r4 + 0x714)
 338:	6c97      	mov	r2, r5	// regs: r2=r5
 33a:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
 33c:	60c4      	addu	r3, r1	// regs: r3=(*(r4 + 0x714) + stack_p2)
 33e:	dc24141d 	st.h	r1, (r4, 0x83a)	// *(r4 + 0x83a) = stack_p2
 342:	6c3b      	mov	r0, r14	// regs: r0=sp
 344:	3105      	movi	r1, 5	// regs: r1=0x5
 346:	7554      	zextb	r5, r5	// regs: r5=zext8((r5 + 0x1))
 348:	dc6e1001 	st.h	r3, (r14, 0x2)	// stack_p2 = (*(r4 + 0x714) + stack_p2)
 34c:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_dcoc>; regs: r0=<ret ah_rfdigicali_config_rx_dcoc@0x34c>, r1=<clobbered>
 350:	3d44      	cmpnei	r5, 4
 352:	0be1      	bt	0x314	// if (r5 != 0x4) goto loc_314;
 354:	1405      	addi	r14, r14, 20	// regs: r14=(sp + 0x14)
 356:	1498      	pop	r4-r11, r15
 358:	00000000 	.long	0x00000000	// <ah_lmac>
 35c:	00000000 	.long	0x00000000	// <module_efuse_info>
 360:	cccccccd 	.long	0xcccccccd
 364:	3fe4cccc 	.long	0x3fe4cccc
 368:	3fc99999 	.long	0x3fc99999
 36c:	9999999a 	.long	0x9999999a
 370:	000d6d7f 	.long	0x000d6d7f
 374:	3fd99999 	.long	0x3fd99999
 378:	0000      	.short	0x0000	// <.rodata.lmac_chip_monitor.str1.1>
 37a:	0000      	.short	0x0000
 37c:	3feccccc 	.long	0x3feccccc
 380:	66666666 	.long	0x66666666
 384:	3fe66666 	.long	0x3fe66666
 388:	3333      	.short	0x3333
 38a:	3333      	.short	0x3333
 38c:	3fe33333 	.long	0x3fe33333
 390:	00000000 	.long	0x00000000	// <ah_ops>
 394:	00000000 	.long	0x00000000	// <.rodata.lmac_chip_monitor.str1.1+0x23>
 398:	00000000 	.long	0x00000000	// <.rodata.lmac_chip_monitor.str1.1+0x60>
 39c:	00000000 	.long	0x00000000	// <.data.xo_cs_comp_1>
loc_3a0:
 3a0:	e901ff7a 	bez	r1, 0x294	// if (r1 == 0x0) goto loc_294;
 3a4:	3100      	movi	r1, 0	// regs: r1=0x0
 3a6:	eb22006d 	cmplti	r2, 110
 3aa:	c4615c22 	ins	r3, r1, 3, 2
 3ae:	dc64036d 	st.b	r3, (r4, 0x36d)	// *(r4 + 0x36d) = r3
 3b2:	0f71      	bf	0x294	// if (r2 >= 0x6e) goto loc_294;
 3b4:	1012      	lrw	r0, 0x0	// regs: r0=0x0
 3b6:	076d      	br	0x290	// goto loc_290;
loc_3b8:
 3b8:	eb23006d 	cmplti	r3, 110
 3bc:	0b89      	bt	0x2ce	// if (r3 < 0x6e) goto loc_2ce;
 3be:	d8640680 	ld.b	r3, (r4, 0x680)	// regs: r3=*(r4 + 0x680)
 3c2:	e4432001 	andi	r2, r3, 1	// regs: r2=(*(r4 + 0x680) & 0x1)
 3c6:	e9220009 	bnez	r2, 0x3d8	// if (r2 != 0x0) goto loc_3d8;
 3ca:	3201      	movi	r2, 1	// regs: r2=0x1
 3cc:	c4625c00 	ins	r3, r2, 0, 0
 3d0:	dc640680 	st.b	r3, (r4, 0x680)	// *(r4 + 0x680) = *(r4 + 0x680)
 3d4:	e0000000 	bsr	0x0	// <lmac_doze_enter> // arg_bytes: 0; regs: r0=<ret lmac_doze_enter@0x3d4>, r1=<clobbered>
loc_3d8:
 3d8:	100a      	lrw	r0, 0x0	// regs: r0=0x0
 3da:	0778      	br	0x2ca	// goto loc_2ca;
loc_3dc:
 3dc:	3300      	movi	r3, 0	// regs: r3=0x0
 3de:	2b27      	subi	r3, 40	// regs: r3=0xffffffd8
 3e0:	0783      	br	0x2e6	// goto loc_2e6;
loc_3e2:
 3e2:	3b43      	cmpnei	r3, 3
 3e4:	0ae9      	bt	0x1b6	// if (r3 != 0x3) goto loc_1b6;
 3e6:	d8640308 	ld.b	r3, (r4, 0x308)	// regs: r3=*(0x308)
 3ea:	3b01      	cmphsi	r3, 2
 3ec:	0a7e      	bt	0xe8	// if (r3 >= 0x2) goto loc_e8;
 3ee:	31fc      	movi	r1, 252	// regs: r1=0xfc
 3f0:	4136      	lsli	r1, r1, 22	// regs: r1=0x3f000000
 3f2:	6c2f      	mov	r0, r11	// regs: r0=<ret __truncdfsf2@0x6e>
 3f4:	e0000000 	bsr	0x0	// <__addsf3>; regs: r0=<ret __addsf3@0x3f4>, r1=<clobbered>
 3f8:	6d43      	mov	r5, r0	// regs: r5=<ret __addsf3@0x3f4>
 3fa:	0677      	br	0xe8	// goto loc_e8;
 3fc:	00000000 	.long	0x00000000	// <.rodata.lmac_chip_monitor.str1.1+0x41>
 400:	00000000 	.long	0x00000000	// <.rodata.lmac_chip_monitor.str1.1+0x79>

Disassembly of section .text.lmac_main_task:

00000000 <lmac_main_task>: // arg_bytes: 4
   0:	14d4      	push	r4-r7, r15
   2:	1430      	subi	r14, r14, 64	// regs: r14=(sp - 0x40)
   4:	10fe      	lrw	r7, 0x0	// regs: r7=0x0
loc_6:
   6:	10bf      	lrw	r5, 0x0	// regs: r5=0x0
   8:	6d17      	mov	r4, r5	// regs: r4=0x0
   a:	d86549df 	ld.bs	r3, (r5, 0x9df)	// regs: r3=*(0x9df)
   e:	e9a30004 	bhsz	r3, 0x16	// if (r3 >= 0x0) goto loc_16;
  12:	1410      	addi	r14, r14, 64	// regs: r14=(sp + 0x40)
  14:	1494      	pop	r4-r7, r15
loc_16:
  16:	3100      	movi	r1, 0	// regs: r1=0x0
  18:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  1a:	e4040b8f 	addi	r0, r4, 2960	// regs: r0=0xb90
  1e:	e0000000 	bsr	0x0	// <os_sema_down>; regs: r0=<ret os_sema_down@0x1e>, r1=<clobbered>
  22:	d8650319 	ld.b	r3, (r5, 0x319)	// regs: r3=*(0x319)
  26:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x319) & 0x2)
  2a:	e923ffee 	bnez	r3, 0x6	// if (r3 != 0x0) goto loc_6;
  2e:	d8652267 	ld.w	r3, (r5, 0x99c)	// regs: r3=*(0x99c)
  32:	e923ffea 	bnez	r3, 0x6	// if (r3 != 0x0) goto loc_6;
  36:	10d4      	lrw	r6, 0x0	// regs: r6=0x0
loc_38:
  38:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(r4 + 0xa84)
  3c:	d98422a2 	ld.w	r12, (r4, 0xa88)	// regs: r12=*(r4 + 0xa88)
  40:	d86422a0 	ld.w	r3, (r4, 0xa80)	// regs: r3=*(r4 + 0xa80)
  44:	3000      	movi	r0, 0	// regs: r0=0x0
  46:	64ca      	cmpne	r2, r3
  48:	0806      	bt	0x54	// if (T) goto loc_54;
  4a:	e900ffde 	bez	r0, 0x6	// if (r0 == 0x0) goto loc_6;
  4e:	dc4522a0 	st.w	r2, (r5, 0xa80)	// *(r5 + 0xa80) = *(r4 + 0xa84)
  52:	07da      	br	0x6	// goto loc_6;
loc_54:
  54:	e42302a2 	addi	r1, r3, 675	// regs: r1=(*(r4 + 0xa80) + 0x2a3)
  58:	d0240881 	ldr.w	r1, (r4, r1 << 2)	// regs: r1=*(r4 + ((*(r4 + 0xa80) + 0x2a3) << 2))
  5c:	2300      	addi	r3, 1	// regs: r3=(*(r4 + 0xa80) + 0x1)
  5e:	c5830080 	subu	r0, r3, r12	// regs: r0=((*(r4 + 0xa80) + 0x1) - *(r4 + 0xa88))
  62:	670d      	cmplt	r3, r12
  64:	e5a11000 	subi	r13, r1, 1	// regs: r13=(*(r4 + ((*(r4 + 0xa80) + 0x2a3) << 2)) - 0x1)
  68:	c4600c20 	incf	r3, r0, 0
  6c:	eb0d000c 	cmphsi	r13, 13
  70:	3001      	movi	r0, 1	// regs: r0=0x1
  72:	08a7      	bt	0x1c0	// if (r13 >= 0xd) goto loc_1c0;
  74:	d1a7088d 	ldr.w	r13, (r7, r13 << 2)	// regs: r13=*(r7 + ((*(r4 + ((*(r4 + 0xa80) + 0x2a3) << 2)) - 0x1) << 2))
  78:	7834      	jmp	r13	// goto *r13;
  7a:	0000      	.short	0x0000
  7c:	00000000 	.long	0x00000000	// <.rodata.lmac_main_task>
  80:	00000000 	.long	0x00000000	// <ah_lmac>
  84:	00000000 	.long	0x00000000	// <ah_ops>
  88:	3100      	movi	r1, 0	// regs: r1=0x0
  8a:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  8c:	1210      	lrw	r0, 0x0	// regs: r0=0x0
  8e:	dc6422a0 	st.w	r3, (r4, 0xa80)	// *(r4 + 0xa80) = <arg3>
  92:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0x92>, r1=<clobbered>
  96:	e0000000 	bsr	0x0	// <lmac_auto_channel_select>; regs: r0=<ret lmac_auto_channel_select@0x96>, r1=<clobbered>
loc_9a:
  9a:	120d      	lrw	r0, 0x0	// regs: r0=0x0
  9c:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0x9c>, r1=<clobbered>
  a0:	07cc      	br	0x38	// goto loc_38;
  a2:	120c      	lrw	r0, 0x0	// regs: r0=0x0
  a4:	dc6422a0 	st.w	r3, (r4, 0xa80)	// *(r4 + 0xa80) = <arg3>
  a8:	e0000000 	bsr	0x0	// <lmac_auto_rate_ctrl>; regs: r0=<ret lmac_auto_rate_ctrl@0xa8>, r1=<clobbered>
  ac:	07c6      	br	0x38	// goto loc_38;
  ae:	dc6422a0 	st.w	r3, (r4, 0xa80)	// *(r4 + 0xa80) = <arg3>
  b2:	d86420dc 	ld.w	r3, (r4, 0x370)	// regs: r3=*(r4 + 0x370)
  b6:	4b41      	lsri	r2, r3, 1	// regs: r2=(*(r4 + 0x370) >> 0x1)
  b8:	d9862009 	ld.w	r12, (r6, 0x24)	// regs: r12=*(r6 + 0x24)
  bc:	4b71      	lsri	r3, r3, 17	// regs: r3=(*(r4 + 0x370) >> 0x11)
  be:	dc6e0002 	st.b	r3, (r14, 0x2)	// stack_p2 = (*(r4 + 0x370) >> 0x11)
  c2:	dc4e0000 	st.b	r2, (r14, 0x0)	// stack_0 = (*(r4 + 0x370) >> 0x1)
  c6:	4b68      	lsri	r3, r3, 8	// regs: r3=((*(r4 + 0x370) >> 0x11) >> 0x8)
  c8:	c50255e2 	zext	r2, r2, 15, 8	// regs: r2=zext((*(r4 + 0x370) >> 0x1))
  cc:	dc6e0003 	st.b	r3, (r14, 0x3)	// stack_p3 = ((*(r4 + 0x370) >> 0x11) >> 0x8)
  d0:	dc4e0001 	st.b	r2, (r14, 0x1)	// stack_p1 = zext((*(r4 + 0x370) >> 0x1))
  d4:	e90cffb2 	bez	r12, 0x38	// if (r12 == 0x0) goto loc_38;
  d8:	3304      	movi	r3, 4	// regs: r3=0x4
  da:	6cbb      	mov	r2, r14	// regs: r2=sp
  dc:	3107      	movi	r1, 7	// regs: r1=0x7
  de:	6c1b      	mov	r0, r6	// regs: r0=r6
  e0:	7bf1      	jsr	r12
  e2:	07ab      	br	0x38	// goto loc_38;
  e4:	dc6422a0 	st.w	r3, (r4, 0xa80)	// *(r4 + 0xa80) = <arg3>
  e8:	e0000000 	bsr	0x0	// <lmac_send_scan_probe>; regs: r0=<ret lmac_send_scan_probe@0xe8>, r1=<clobbered>
  ec:	07a6      	br	0x38	// goto loc_38;
  ee:	dc6422a0 	st.w	r3, (r4, 0xa80)	// *(r4 + 0xa80) = <arg3>
  f2:	e0000000 	bsr	0x0	// <lmac_send_mgmt_meas_report>; regs: r0=<ret lmac_send_mgmt_meas_report@0xf2>, r1=<clobbered>
  f6:	07a1      	br	0x38	// goto loc_38;
  f8:	dc6422a0 	st.w	r3, (r4, 0xa80)	// *(r4 + 0xa80) = <arg3>
  fc:	e0000000 	bsr	0x0	// <lmac_send_bss_announcement>; regs: r0=<ret lmac_send_bss_announcement@0xfc>, r1=<clobbered>
 100:	079c      	br	0x38	// goto loc_38;
 102:	dc6422a0 	st.w	r3, (r4, 0xa80)	// *(r4 + 0xa80) = <arg3>
 106:	e0000000 	bsr	0x0	// <lmac_obss_eval> // arg_bytes: 4; regs: r0=<ret lmac_obss_eval@0x106>, r1=<clobbered>
 10a:	0797      	br	0x38	// goto loc_38;
 10c:	dc6422a0 	st.w	r3, (r4, 0xa80)	// *(r4 + 0xa80) = <arg3>
 110:	e0000000 	bsr	0x0	// <lmac_chan_list_eval> // arg_bytes: 0; regs: r0=<ret lmac_chan_list_eval@0x110>, r1=<clobbered>
 114:	0792      	br	0x38	// goto loc_38;
 116:	dc6422a0 	st.w	r3, (r4, 0xa80)	// *(r4 + 0xa80) = <arg3>
 11a:	e0000000 	bsr	0x0	// <lmac_chip_monitor> // arg_bytes: 0; regs: r0=<ret lmac_chip_monitor@0x11a>, r1=<clobbered>
 11e:	078d      	br	0x38	// goto loc_38;
 120:	dc6422a0 	st.w	r3, (r4, 0xa80)	// *(r4 + 0xa80) = <arg3>
 124:	e0000000 	bsr	0x0	// <lmac_send_ant_pkt>; regs: r0=<ret lmac_send_ant_pkt@0x124>, r1=<clobbered>
 128:	0788      	br	0x38	// goto loc_38;
 12a:	3100      	movi	r1, 0	// regs: r1=0x0
 12c:	2900      	subi	r1, 1	// regs: r1=0xffffffff
 12e:	1108      	lrw	r0, 0x0	// regs: r0=0x0
 130:	dc6422a0 	st.w	r3, (r4, 0xa80)	// *(r4 + 0xa80) = <arg3>
 134:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0x134>, r1=<clobbered>
 138:	d9a40378 	ld.b	r13, (r4, 0x378)	// regs: r13=*(r4 + 0x378)
 13c:	e46d1000 	subi	r3, r13, 1	// regs: r3=(*(r4 + 0x378) - 0x1)
 140:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(r4 + 0x378) - 0x1))
 142:	3b0f      	cmphsi	r3, 16
 144:	0b7a      	bt	0x38	// if (r3 >= 0x10) goto loc_38;
 146:	d804034a 	ld.b	r0, (r4, 0x34a)	// regs: r0=*(r4 + 0x34a)
 14a:	d98411a5 	ld.h	r12, (r4, 0x34a)	// regs: r12=*(r4 + 0x34a)
 14e:	3200      	movi	r2, 0	// regs: r2=0x0
 150:	e4002001 	andi	r0, r0, 1	// regs: r0=(*(r4 + 0x34a) & 0x1)
 154:	c42c55ec 	zext	r12, r12, 15, 1	// regs: r12=zext(*(r4 + 0x34a))
 158:	6ccb      	mov	r3, r2	// regs: r3=0x0
loc_15a:
 15a:	674d      	cmplt	r3, r13
 15c:	0824      	bt	0x1a4	// if (T) goto loc_1a4;
 15e:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0x15e>, r1=<clobbered>
 162:	3000      	movi	r0, 0	// regs: r0=0x0
 164:	e0000000 	bsr	0x0	// <ah_rf_lo_table_ctrl>; regs: r0=<ret ah_rf_lo_table_ctrl@0x164>, r1=<clobbered>
 168:	d8240378 	ld.b	r1, (r4, 0x378)	// regs: r1=*(r4 + 0x378)
 16c:	6c3b      	mov	r0, r14	// regs: r0=sp
 16e:	e0000000 	bsr	0x0	// <ah_rf_lo_table_cfg>; regs: r0=<ret ah_rf_lo_table_cfg@0x16e>, r1=<clobbered>
 172:	3300      	movi	r3, 0	// regs: r3=0x0
 174:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 176:	64c2      	cmpne	r0, r3
 178:	0804      	bt	0x180	// if (T) goto loc_180;
 17a:	1017      	lrw	r0, 0x0	// regs: r0=0x0
 17c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x17c>, r1=<clobbered>
loc_180:
 180:	3001      	movi	r0, 1	// regs: r0=0x1
 182:	e0000000 	bsr	0x0	// <ah_rf_lo_table_ctrl>; regs: r0=<ret ah_rf_lo_table_ctrl@0x182>, r1=<clobbered>
 186:	d804033c 	ld.b	r0, (r4, 0x33c)	// regs: r0=*(r4 + 0x33c)
 18a:	e0000000 	bsr	0x0	// <lmac_lo_table_kick>; regs: r0=<ret lmac_lo_table_kick@0x18a>, r1=<clobbered>
 18e:	3000      	movi	r0, 0	// regs: r0=0x0
 190:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x190>, r1=<clobbered>
 194:	d864037d 	ld.b	r3, (r4, 0x37d)	// regs: r3=*(r4 + 0x37d)
 198:	3200      	movi	r2, 0	// regs: r2=0x0
 19a:	c4625c03 	ins	r3, r2, 3, 3
 19e:	dc64037d 	st.b	r3, (r4, 0x37d)	// *(r4 + 0x37d) = *(r4 + 0x37d)
 1a2:	077c      	br	0x9a	// goto loc_9a;
loc_1a4:
 1a4:	102d      	lrw	r1, 0x0	// regs: r1=0x0
 1a6:	6048      	addu	r1, r2	// regs: r1=(0x0 + r2)
 1a8:	d8212030 	ld.w	r1, (r1, 0xc0)	// regs: r1=*(((0x0 + r2) + 0xc0))
 1ac:	d46e0881 	str.w	r1, (r14, r3 << 2)
 1b0:	e9000005 	bez	r0, 0x1ba	// if (r0 == 0x0) goto loc_1ba;
 1b4:	6070      	addu	r1, r12	// regs: r1=(*(((0x0 + r2) + 0xc0)) + zext(*(r4 + 0x34a)))
 1b6:	d46e0881 	str.w	r1, (r14, r3 << 2)
loc_1ba:
 1ba:	2300      	addi	r3, 1	// regs: r3=(r3 + 0x1)
 1bc:	2217      	addi	r2, 24	// regs: r2=(r2 + 0x18)
 1be:	07ce      	br	0x15a	// goto loc_15a;
loc_1c0:
 1c0:	1007      	lrw	r0, 0x0	// regs: r0=0x0
 1c2:	dc6422a0 	st.w	r3, (r4, 0xa80)	// *(r4 + 0xa80) = (*(r4 + 0xa80) + 0x1)
 1c6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1c6>, r1=<clobbered>
 1ca:	0737      	br	0x38	// goto loc_38;
 1cc:	00000000 	.long	0x00000000	// <ah_lmac+0xbb8>
 1d0:	00000000 	.long	0x00000000	// <ah_lmac+0x9f8>
 1d4:	00000000 	.long	0x00000000	// <.rodata.lmac_main_task.str1.1>
 1d8:	00000000 	.long	0x00000000	// <ah_lmac>
 1dc:	00000000 	.long	0x00000000	// <.rodata.lmac_main_task.str1.1+0x20>

Disassembly of section .text.ap_sleep_enter:

00000000 <ap_sleep_enter>: // arg_bytes: 4
   0:	14d7      	push	r4-r10, r15
   2:	029a      	lrw	r4, 0x0	// regs: r4=0x0
   4:	e0000000 	bsr	0x0	// <lmac_next_dtim_calc>; regs: r0=<ret lmac_next_dtim_calc@0x4>, r1=<clobbered>
   8:	d8642267 	ld.w	r3, (r4, 0x99c)	// regs: r3=*(0x99c)
   c:	e903012e 	bez	r3, 0x268	// if (r3 == 0x0) goto loc_268;
  10:	35fa      	movi	r5, 250	// regs: r5=0xfa
  12:	45a2      	lsli	r5, r5, 2	// regs: r5=0x3e8
  14:	c4a08025 	divu	r5, r0, r5	// regs: r5=(<ret lmac_next_dtim_calc@0x4> / 0x3e8)
  18:	3d08      	cmphsi	r5, 9
  1a:	0d27      	bf	0x268	// if (r5 < 0x9) goto loc_268;
  1c:	0360      	lrw	r3, 0x0	// regs: r3=0x0
  1e:	3600      	movi	r6, 0	// regs: r6=0x0
  20:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*(0xa)
  22:	c4465c00 	ins	r2, r6, 0, 0
  26:	a34a      	st.b	r2, (r3, 0xa)	// *(0xa) = *(0xa)
  28:	3701      	movi	r7, 1	// regs: r7=0x1
  2a:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
  2e:	c4675c01 	ins	r3, r7, 1, 1
  32:	e5032040 	andi	r8, r3, 64	// regs: r8=(*(0x319) & 0x40)
  36:	3203      	movi	r2, 3	// regs: r2=0x3
  38:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = *(0x319)
  3c:	dc442267 	st.w	r2, (r4, 0x99c)	// *(0x99c) = 0x3
  40:	e90800e3 	bez	r8, 0x206	// if (r8 == 0x0) goto loc_206;
  44:	0369      	lrw	r3, 0x0	// regs: r3=0x0
  46:	6c9b      	mov	r2, r6	// regs: r2=0x0
  48:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  4a:	6f5b      	mov	r13, r6	// regs: r13=0x0
  4c:	d9832005 	ld.w	r12, (r3, 0x14)	// regs: r12=*((*(0x0) + 0x14))
  50:	9324      	ld.w	r1, (r3, 0x10)	// regs: r1=*((*(0x0) + 0x10))
  52:	6cf3      	mov	r3, r12	// regs: r3=*((*(0x0) + 0x14))
  54:	6f07      	mov	r12, r1	// regs: r12=*((*(0x0) + 0x10))
  56:	6731      	cmplt	r12, r12
  58:	6309      	addc	r12, r2
  5a:	634d      	addc	r13, r3
  5c:	6c83      	mov	r2, r0	// regs: r2=<ret lmac_next_dtim_calc@0x4>
  5e:	6cdb      	mov	r3, r6	// regs: r3=0x0
  60:	6731      	cmplt	r12, r12
  62:	6309      	addc	r12, r2
  64:	634d      	addc	r13, r3
  66:	dd8422e7 	st.w	r12, (r4, 0xb9c)	// *(0xb9c) = *((*(0x0) + 0x10))
  6a:	dda422e8 	st.w	r13, (r4, 0xba0)	// *(0xba0) = 0x0
  6e:	ea8a008d 	lrw	r10, 0xe000e100	// regs: r10=0xe000e100
  72:	e0000000 	bsr	0x0	// <lmac_beacon_timer_abort>; regs: r0=<ret lmac_beacon_timer_abort@0x72>, r1=<clobbered>
  76:	3380      	movi	r3, 128	// regs: r3=0x80
  78:	436e      	lsli	r3, r3, 14	// regs: r3=0x200000
  7a:	ea098003 	movi	r9, 32771	// regs: r9=0x8003
  7e:	c5e94909 	rotli	r9, r9, 15	// regs: r9=rotl(0x8003, 0xf)
  82:	dc6a2020 	st.w	r3, (r10, 0x80)	// *(0xe000e180) = 0x200000
  86:	d8292028 	ld.w	r1, (r9, 0xa0)	// regs: r1=*((rotl(0x8003, 0xf) + 0xa0))
  8a:	39b0      	bseti	r1, 16	// regs: r1=(*((rotl(0x8003, 0xf) + 0xa0)) | (0x1 << 0x10))
  8c:	39b1      	bseti	r1, 17	// regs: r1=((*((rotl(0x8003, 0xf) + 0xa0)) | (0x1 << 0x10)) | (0x1 << 0x11))
  8e:	30a0      	movi	r0, 160	// regs: r0=0xa0
  90:	e0000000 	bsr	0x0	// <core_sec_opt_func> // arg_bytes: 8; regs: r0=<ret core_sec_opt_func@0x90>, r1=<clobbered>
  94:	e0000000 	bsr	0x0	// <pmu_pd_timer_clear_pnd_sec>; regs: r0=<ret pmu_pd_timer_clear_pnd_sec@0x94>, r1=<clobbered>
  98:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
  9c:	c4665c07 	ins	r3, r6, 7, 7
  a0:	2d06      	subi	r5, 7	// regs: r5=((<ret lmac_next_dtim_calc@0x4> / 0x3e8) - 0x7)
  a2:	6c1b      	mov	r0, r6	// regs: r0=0x0
  a4:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = *(0x319)
  a8:	e0000000 	bsr	0x0	// <mcu_watchdog_timeout>; regs: r0=<ret mcu_watchdog_timeout@0xa8>, r1=<clobbered>
  ac:	6c17      	mov	r0, r5	// regs: r0=((<ret lmac_next_dtim_calc@0x4> / 0x3e8) - 0x7)
  ae:	e0000000 	bsr	0x0	// <csi_kernel_update_tick>; regs: r0=<ret csi_kernel_update_tick@0xae>, r1=<clobbered>
  b2:	6c17      	mov	r0, r5	// regs: r0=((<ret lmac_next_dtim_calc@0x4> / 0x3e8) - 0x7)
  b4:	e0000000 	bsr	0x0	// <pd_timer_start>; regs: r0=<ret pd_timer_start@0xb4>, r1=<clobbered>
  b8:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0xb8>, r1=<clobbered>
  bc:	6c1b      	mov	r0, r6	// regs: r0=0x0
  be:	e0000000 	bsr	0x0	// <lmac_cfg_rf_en>; regs: r0=<ret lmac_cfg_rf_en@0xbe>, r1=<clobbered>
  c2:	1379      	lrw	r3, 0x40026000	// regs: r3=0x40026000
  c4:	30a0      	movi	r0, 160	// regs: r0=0xa0
  c6:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*(0x4002601c)
  c8:	3a92      	bclri	r2, 18	// regs: r2=(*(0x4002601c) & ~(0x1 << 0x12))
  ca:	b347      	st.w	r2, (r3, 0x1c)	// *(0x4002601c) = (*(0x4002601c) & ~(0x1 << 0x12))
  cc:	9342      	ld.w	r2, (r3, 0x8)	// regs: r2=*(0x40026008)
  ce:	3a92      	bclri	r2, 18	// regs: r2=(*(0x40026008) & ~(0x1 << 0x12))
  d0:	b342      	st.w	r2, (r3, 0x8)	// *(0x40026008) = (*(0x40026008) & ~(0x1 << 0x12))
  d2:	9342      	ld.w	r2, (r3, 0x8)	// regs: r2=*(0x40026008)
  d4:	3ab2      	bseti	r2, 18	// regs: r2=(*(0x40026008) | (0x1 << 0x12))
  d6:	b342      	st.w	r2, (r3, 0x8)	// *(0x40026008) = (*(0x40026008) | (0x1 << 0x12))
  d8:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  da:	3a97      	bclri	r2, 23	// regs: r2=(*(0x40026014) & ~(0x1 << 0x17))
  dc:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x17))
  de:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  e0:	3a9c      	bclri	r2, 28	// regs: r2=(*(0x40026014) & ~(0x1 << 0x1c))
  e2:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x1c))
  e4:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  e6:	3a9b      	bclri	r2, 27	// regs: r2=(*(0x40026014) & ~(0x1 << 0x1b))
  e8:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x1b))
  ea:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  ec:	3a9a      	bclri	r2, 26	// regs: r2=(*(0x40026014) & ~(0x1 << 0x1a))
  ee:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x1a))
  f0:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  f2:	3a9d      	bclri	r2, 29	// regs: r2=(*(0x40026014) & ~(0x1 << 0x1d))
  f4:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x1d))
  f6:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  f8:	3a93      	bclri	r2, 19	// regs: r2=(*(0x40026014) & ~(0x1 << 0x13))
  fa:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x13))
  fc:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
  fe:	3a8f      	bclri	r2, 15	// regs: r2=(*(0x40026014) & ~(0x1 << 0xf))
 100:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0xf))
 102:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 104:	3a8b      	bclri	r2, 11	// regs: r2=(*(0x40026014) & ~(0x1 << 0xb))
 106:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0xb))
 108:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 10a:	3a89      	bclri	r2, 9	// regs: r2=(*(0x40026014) & ~(0x1 << 0x9))
 10c:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x9))
 10e:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 110:	3a88      	bclri	r2, 8	// regs: r2=(*(0x40026014) & ~(0x1 << 0x8))
 112:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x8))
 114:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 116:	3a85      	bclri	r2, 5	// regs: r2=(*(0x40026014) & ~(0x1 << 0x5))
 118:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x5))
 11a:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 11c:	3a84      	bclri	r2, 4	// regs: r2=(*(0x40026014) & ~(0x1 << 0x4))
 11e:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x4))
 120:	3380      	movi	r3, 128	// regs: r3=0x80
 122:	4372      	lsli	r3, r3, 18	// regs: r3=0x2000000
 124:	d8a4031a 	ld.b	r5, (r4, 0x31a)	// regs: r5=*(0x31a)
 128:	d904031b 	ld.b	r8, (r4, 0x31b)	// regs: r8=*(0x31b)
 12c:	dc6a2020 	st.w	r3, (r10, 0x80)	// *(0xe000e180) = 0x2000000
 130:	d8292028 	ld.w	r1, (r9, 0xa0)	// regs: r1=*((rotl(0x8003, 0xf) + 0xa0))
 134:	c40155e1 	zext	r1, r1, 15, 0	// regs: r1=zext(*((rotl(0x8003, 0xf) + 0xa0)))
 138:	715d      	lsr	r5, r7
 13a:	39b0      	bseti	r1, 16	// regs: r1=(zext(*((rotl(0x8003, 0xf) + 0xa0))) | (0x1 << 0x10))
 13c:	e0000000 	bsr	0x0	// <core_sec_opt_func> // arg_bytes: 8; regs: r0=<ret core_sec_opt_func@0x13c>, r1=<clobbered>
 140:	eb050032 	cmphsi	r5, 51
 144:	6a1c      	and	r8, r7	// regs: r8=(*(0x31b) & 0x1)
 146:	085e      	bt	0x202	// if (r5 >= 0x33) goto loc_202;
 148:	6c5b      	mov	r1, r6	// regs: r1=0x0
 14a:	6c17      	mov	r0, r5	// regs: r0=*(0x31a)
 14c:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x14c>, r1=<clobbered>
 150:	6c9f      	mov	r2, r7	// regs: r2=0x1
 152:	6c5f      	mov	r1, r7	// regs: r1=0x1
 154:	6c17      	mov	r0, r5	// regs: r0=*(0x31a)
 156:	e0000000 	bsr	0x0	// <gpio_set_mode>; regs: r0=<ret gpio_set_mode@0x156>, r1=<clobbered>
loc_15a:
 15a:	ea068003 	movi	r6, 32771	// regs: r6=0x8003
 15e:	c5e64906 	rotli	r6, r6, 15	// regs: r6=rotl(0x8003, 0xf)
 162:	3300      	movi	r3, 0	// regs: r3=0x0
 164:	d8262028 	ld.w	r1, (r6, 0xa0)	// regs: r1=*((rotl(0x8003, 0xf) + 0xa0))
 168:	2bfc      	subi	r3, 253	// regs: r3=0xffffff03
 16a:	684c      	and	r1, r3	// regs: r1=(*((rotl(0x8003, 0xf) + 0xa0)) & 0xffffff03)
 16c:	45a2      	lsli	r5, r5, 2	// regs: r5=(r5 << 0x2)
 16e:	6c54      	or	r1, r5	// regs: r1=((*((rotl(0x8003, 0xf) + 0xa0)) & 0xffffff03) | (r5 << 0x2))
 170:	30a0      	movi	r0, 160	// regs: r0=0xa0
 172:	e0000000 	bsr	0x0	// <core_sec_opt_func> // arg_bytes: 8; regs: r0=<ret core_sec_opt_func@0x172>, r1=<clobbered>
 176:	d8262028 	ld.w	r1, (r6, 0xa0)	// regs: r1=*((rotl(0x8003, 0xf) + 0xa0))
 17a:	3981      	bclri	r1, 1	// regs: r1=(*((rotl(0x8003, 0xf) + 0xa0)) & ~(0x1 << 0x1))
 17c:	30a0      	movi	r0, 160	// regs: r0=0xa0
 17e:	e0000000 	bsr	0x0	// <core_sec_opt_func> // arg_bytes: 8; regs: r0=<ret core_sec_opt_func@0x17e>, r1=<clobbered>
 182:	e9080009 	bez	r8, 0x194	// if (r8 == 0x0) goto loc_194;
 186:	d8262028 	ld.w	r1, (r6, 0xa0)	// regs: r1=*((rotl(0x8003, 0xf) + 0xa0))
 18a:	ec210002 	ori	r1, r1, 2	// regs: r1=(*((rotl(0x8003, 0xf) + 0xa0)) | 0x2)
 18e:	30a0      	movi	r0, 160	// regs: r0=0xa0
 190:	e0000000 	bsr	0x0	// <core_sec_opt_func> // arg_bytes: 8; regs: r0=<ret core_sec_opt_func@0x190>, r1=<clobbered>
loc_194:
 194:	ea058003 	movi	r5, 32771	// regs: r5=0x8003
 198:	c5e54905 	rotli	r5, r5, 15	// regs: r5=rotl(0x8003, 0xf)
 19c:	30a0      	movi	r0, 160	// regs: r0=0xa0
 19e:	d8252028 	ld.w	r1, (r5, 0xa0)	// regs: r1=*((rotl(0x8003, 0xf) + 0xa0))
 1a2:	ec210200 	ori	r1, r1, 512	// regs: r1=(*((rotl(0x8003, 0xf) + 0xa0)) | 0x200)
 1a6:	e0000000 	bsr	0x0	// <core_sec_opt_func> // arg_bytes: 8; regs: r0=<ret core_sec_opt_func@0x1a6>, r1=<clobbered>
 1aa:	d8252028 	ld.w	r1, (r5, 0xa0)	// regs: r1=*((rotl(0x8003, 0xf) + 0xa0))
 1ae:	ec210001 	ori	r1, r1, 1	// regs: r1=(*((rotl(0x8003, 0xf) + 0xa0)) | 0x1)
 1b2:	30a0      	movi	r0, 160	// regs: r0=0xa0
 1b4:	e0000000 	bsr	0x0	// <core_sec_opt_func> // arg_bytes: 8; regs: r0=<ret core_sec_opt_func@0x1b4>, r1=<clobbered>
 1b8:	113c      	lrw	r1, 0x0	// regs: r1=0x0
 1ba:	1157      	lrw	r2, 0x0	// regs: r2=0x0
 1bc:	3019      	movi	r0, 25	// regs: r0=0x19
 1be:	e0000000 	bsr	0x0	// <request_irq>; regs: r0=<ret request_irq@0x1be>, r1=<clobbered>
 1c2:	1158      	lrw	r2, 0xe000e100	// regs: r2=0xe000e100
 1c4:	3380      	movi	r3, 128	// regs: r3=0x80
 1c6:	4372      	lsli	r3, r3, 18	// regs: r3=0x2000000
 1c8:	b260      	st.w	r3, (r2, 0x0)	// *(0xe000e100) = 0x2000000
 1ca:	e0000000 	bsr	0x0	// <tsensor_close>; regs: r0=<ret tsensor_close@0x1ca>, r1=<clobbered>
 1ce:	3200      	movi	r2, 0	// regs: r2=0x0
 1d0:	6c4b      	mov	r1, r2	// regs: r1=0x0
 1d2:	6c0b      	mov	r0, r2	// regs: r0=0x0
 1d4:	e0000000 	bsr	0x0	// <sysctrl_sysclk_cfg>; regs: r0=<ret sysctrl_sysclk_cfg@0x1d4>, r1=<clobbered>
 1d8:	3300      	movi	r3, 0	// regs: r3=0x0
 1da:	6c8f      	mov	r2, r3	// regs: r2=0x0
 1dc:	6c4f      	mov	r1, r3	// regs: r1=0x0
 1de:	6c0f      	mov	r0, r3	// regs: r0=0x0
 1e0:	e0000000 	bsr	0x0	// <sysctrl_syspll_set>; regs: r0=<ret sysctrl_syspll_set@0x1e0>, r1=<clobbered>
 1e4:	3300      	movi	r3, 0	// regs: r3=0x0
 1e6:	6c0f      	mov	r0, r3	// regs: r0=0x0
 1e8:	6c8f      	mov	r2, r3	// regs: r2=0x0
 1ea:	6c4f      	mov	r1, r3	// regs: r1=0x0
 1ec:	e0000000 	bsr	0x0	// <sysctrl_adcpll_set>; regs: r0=<ret sysctrl_adcpll_set@0x1ec>, r1=<clobbered>
 1f0:	3000      	movi	r0, 0	// regs: r0=0x0
 1f2:	e0000000 	bsr	0x0	// <pd_hxosc_en_sec>; regs: r0=<ret pd_hxosc_en_sec@0x1f2>, r1=<clobbered>
loc_1f6:
 1f6:	d86411e5 	ld.h	r3, (r4, 0x3ca)	// regs: r3=*(0x3ca)
 1fa:	3000      	movi	r0, 0	// regs: r0=0x0
 1fc:	dc6411e4 	st.h	r3, (r4, 0x3c8)	// *(0x3c8) = *(0x3ca)
 200:	1497      	pop	r4-r10, r15
loc_202:
 202:	3533      	movi	r5, 51	// regs: r5=0x33
 204:	07ab      	br	0x15a	// goto loc_15a;
loc_206:
 206:	e4001fff 	subi	r0, r0, 4096	// regs: r0=(<ret lmac_next_dtim_calc@0x4> - 0x1000)
 20a:	e0000000 	bsr	0x0	// <lf_timer_start>; regs: r0=<ret lf_timer_start@0x20a>, r1=<clobbered>
 20e:	1108      	lrw	r0, 0x0	// regs: r0=0x0
 210:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x210>, r1=<clobbered>
 214:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0x214>, r1=<clobbered>
 218:	6c23      	mov	r0, r8	// regs: r0=(*(0x319) & 0x40)
 21a:	e0000000 	bsr	0x0	// <lmac_cfg_rf_en>; regs: r0=<ret lmac_cfg_rf_en@0x21a>, r1=<clobbered>
 21e:	1162      	lrw	r3, 0x40026000	// regs: r3=0x40026000
 220:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*(0x4002601c)
 222:	3a92      	bclri	r2, 18	// regs: r2=(*(0x4002601c) & ~(0x1 << 0x12))
 224:	b347      	st.w	r2, (r3, 0x1c)	// *(0x4002601c) = (*(0x4002601c) & ~(0x1 << 0x12))
 226:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 228:	3a9c      	bclri	r2, 28	// regs: r2=(*(0x40026014) & ~(0x1 << 0x1c))
 22a:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x1c))
 22c:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 22e:	3a9b      	bclri	r2, 27	// regs: r2=(*(0x40026014) & ~(0x1 << 0x1b))
 230:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x1b))
 232:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 234:	3a9a      	bclri	r2, 26	// regs: r2=(*(0x40026014) & ~(0x1 << 0x1a))
 236:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x1a))
 238:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 23a:	3a93      	bclri	r2, 19	// regs: r2=(*(0x40026014) & ~(0x1 << 0x13))
 23c:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x13))
 23e:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 240:	3a8f      	bclri	r2, 15	// regs: r2=(*(0x40026014) & ~(0x1 << 0xf))
 242:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0xf))
 244:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 246:	3a8b      	bclri	r2, 11	// regs: r2=(*(0x40026014) & ~(0x1 << 0xb))
 248:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0xb))
 24a:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 24c:	3a89      	bclri	r2, 9	// regs: r2=(*(0x40026014) & ~(0x1 << 0x9))
 24e:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x9))
 250:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 252:	3a88      	bclri	r2, 8	// regs: r2=(*(0x40026014) & ~(0x1 << 0x8))
 254:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x8))
 256:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 258:	3a85      	bclri	r2, 5	// regs: r2=(*(0x40026014) & ~(0x1 << 0x5))
 25a:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x5))
 25c:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x40026014)
 25e:	3a84      	bclri	r2, 4	// regs: r2=(*(0x40026014) & ~(0x1 << 0x4))
 260:	b345      	st.w	r2, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) & ~(0x1 << 0x4))
 262:	e0000000 	bsr	0x0	// <tsensor_close>; regs: r0=<ret tsensor_close@0x262>, r1=<clobbered>
 266:	07c8      	br	0x1f6	// goto loc_1f6;
loc_268:
 268:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
 26a:	3101      	movi	r1, 1	// regs: r1=0x1
 26c:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*((*(0x0) + 0xa))
 26e:	c4415c00 	ins	r2, r1, 0, 0
 272:	a34a      	st.b	r2, (r3, 0xa)	// *((*(0x0) + 0xa)) = *((*(0x0) + 0xa))
 274:	3500      	movi	r5, 0	// regs: r5=0x0
 276:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
 27a:	c4655c01 	ins	r3, r5, 1, 1
 27e:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = *(0x319)
 282:	e0000000 	bsr	0x0	// <lhw_enable_irq_ac>; regs: r0=<ret lhw_enable_irq_ac@0x282>, r1=<clobbered>
 286:	6c17      	mov	r0, r5	// regs: r0=0x0
 288:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x288>, r1=<clobbered>
 28c:	e0000000 	bsr	0x0	// <lmac_tdma_start>; regs: r0=<ret lmac_tdma_start@0x28c>, r1=<clobbered>
 290:	07b3      	br	0x1f6	// goto loc_1f6;
 292:	0000      	.short	0x0000
 294:	00000000 	.long	0x00000000	// <ah_lmac>
 298:	00000000 	.long	0x00000000	// <ah_ops>
 29c:	00000000 	.long	0x00000000	// <LMAC>
 2a0:	e000e100 	.long	0xe000e100
 2a4:	40026000 	.long	0x40026000
 2a8:	00000000 	.long	0x00000000	// <.text.wakeup_irq_handler>
 2ac:	00000000 	.long	0x00000000	// <.rodata.ap_sleep_enter.str1.1>

Disassembly of section .text.lmac_dsleep_psdata:

00000000 <lmac_dsleep_psdata>: // arg_bytes: 0
   0:	1064      	lrw	r3, 0x0	// regs: r3=0x0
   2:	d8032233 	ld.w	r0, (r3, 0x8cc)	// regs: r0=*(0x8cc)
   6:	3840      	cmpnei	r0, 0
   8:	c4000c44 	inct	r0, r0, 4
   c:	783c      	jmp	r15	// return;
   e:	0000      	.short	0x0000
  10:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_snprint:

00000000 <lmac_snprint>: // arg_bytes: 16
   0:	1423      	subi	r14, r14, 12	// regs: r14=(sp - 0xc)
   2:	b862      	st.w	r3, (r14, 0x8)	// local_4 = <arg3>
   4:	b841      	st.w	r2, (r14, 0x4)	// local_8 = <arg2>
   6:	b820      	st.w	r1, (r14, 0x0)	// local_c = <arg1>
   8:	14d3      	push	r4-r6, r15
   a:	1421      	subi	r14, r14, 4	// regs: r14=((sp - 0xc) - 0x4)
   c:	9089      	ld.w	r4, (r0, 0x24)	// regs: r4=*(<arg0> + 0x24)
   e:	6d83      	mov	r6, r0	// regs: r6=<arg0>
  10:	9006      	ld.w	r0, (r0, 0x18)	// regs: r0=*(<arg0> + 0x18)
  12:	6102      	subu	r4, r0	// regs: r4=(*(<arg0> + 0x24) - *(<arg0> + 0x18))
  14:	2c00      	subi	r4, 1	// regs: r4=((*(<arg0> + 0x24) - *(<arg0> + 0x18)) - 0x1)
  16:	3c21      	cmplti	r4, 2
  18:	9865      	ld.w	r3, (r14, 0x14)	// regs: r3=stack_p4
  1a:	b860      	st.w	r3, (r14, 0x0)	// local_10 = stack_p4
  1c:	081d      	bt	0x56	// if (r4 < 0x2) goto loc_56;
  1e:	1b06      	addi	r3, r14, 24	// regs: r3=(((sp - 0xc) - 0x4) + 0x18)
  20:	9840      	ld.w	r2, (r14, 0x0)	// regs: r2=local_10
  22:	6c53      	mov	r1, r4	// regs: r1=((*(<arg0> + 0x24) - *(<arg0> + 0x18)) - 0x1)
  24:	e0000000 	bsr	0x0	// <vsnprintf>; regs: r0=<ret vsnprintf@0x24>, r1=<clobbered>
  28:	6d43      	mov	r5, r0	// regs: r5=<ret vsnprintf@0x24>
  2a:	e9600012 	blsz	r0, 0x4e
  2e:	6501      	cmplt	r0, r4
  30:	6c53      	mov	r1, r4	// regs: r1=((*(<arg0> + 0x24) - *(<arg0> + 0x18)) - 0x1)
  32:	c4200c40 	inct	r1, r0, 0
  36:	6c1b      	mov	r0, r6	// regs: r0=<arg0>
  38:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x38>, r1=<clobbered>
loc_3c:
  3c:	6c17      	mov	r0, r5	// regs: r0=r5
  3e:	1401      	addi	r14, r14, 4	// regs: r14=(sp + 0x4)
  40:	d9ee2003 	ld.w	r15, (r14, 0xc)	// regs: r15=stack_p10
  44:	98c2      	ld.w	r6, (r14, 0x8)	// regs: r6=stack_pc
  46:	98a1      	ld.w	r5, (r14, 0x4)	// regs: r5=stack_p8
  48:	9880      	ld.w	r4, (r14, 0x0)	// regs: r4=stack_p4
  4a:	1407      	addi	r14, r14, 28	// regs: r14=((sp + 0x4) + 0x1c)
  4c:	783c      	jmp	r15	// return;
  4e:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  50:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x50>, r1=<clobbered>
  54:	07f4      	br	0x3c	// goto loc_3c;
loc_56:
  56:	3500      	movi	r5, 0	// regs: r5=0x0
  58:	07f2      	br	0x3c	// goto loc_3c;
  5a:	0000      	.short	0x0000
  5c:	00000000 	.long	0x00000000	// <.rodata.lmac_snprint.str1.1>

Disassembly of section .text.lmac_sta_info_statics_print:

00000000 <lmac_sta_info_statics_print>: // arg_bytes: 8
   0:	14d7      	push	r4-r10, r15
   2:	1428      	subi	r14, r14, 32	// regs: r14=(sp - 0x20)
   4:	02a9      	lrw	r5, 0x0	// regs: r5=0x0
   6:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   8:	6d87      	mov	r6, r1	// regs: r6=<arg1>
   a:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0xa>, r1=<clobbered>
   e:	d8e52207 	ld.w	r7, (r5, 0x81c)	// regs: r7=*(0x81c)
  12:	58fd      	subu	r7, r0, r7	// regs: r7=(<ret os_jiffies@0xa> - *(0x81c))
  14:	d80520ee 	ld.w	r0, (r5, 0x3b8)	// regs: r0=*(0x3b8)
  18:	e4002004 	andi	r0, r0, 4	// regs: r0=(*(0x3b8) & 0x4)
  1c:	d8640070 	ld.b	r3, (r4, 0x70)	// regs: r3=*(<arg0> + 0x70)
  20:	d844006f 	ld.b	r2, (r4, 0x6f)	// regs: r2=*(<arg0> + 0x6f)
  24:	d8241034 	ld.h	r1, (r4, 0x68)	// regs: r1=*(<arg0> + 0x68)
  28:	d9240074 	ld.b	r9, (r4, 0x74)	// regs: r9=*(<arg0> + 0x74)
  2c:	d9040073 	ld.b	r8, (r4, 0x73)	// regs: r8=*(<arg0> + 0x73)
  30:	d9a40072 	ld.b	r13, (r4, 0x72)	// regs: r13=*(<arg0> + 0x72)
  34:	d9840071 	ld.b	r12, (r4, 0x71)	// regs: r12=*(<arg0> + 0x71)
  38:	e9000131 	bez	r0, 0x29a	// if (r0 == 0x0) goto loc_29a;
  3c:	d80400ae 	ld.b	r0, (r4, 0xae)	// regs: r0=*(<arg0> + 0xae)
  40:	4804      	lsri	r0, r0, 4	// regs: r0=(*(<arg0> + 0xae) >> 0x4)
  42:	b807      	st.w	r0, (r14, 0x1c)	// local_4 = (*(<arg0> + 0xae) >> 0x4)
  44:	d80400ad 	ld.b	r0, (r4, 0xad)	// regs: r0=*(<arg0> + 0xad)
  48:	e540200f 	andi	r10, r0, 15	// regs: r10=(*(<arg0> + 0xad) & 0xf)
  4c:	dd4e2006 	st.w	r10, (r14, 0x18)	// local_8 = (*(<arg0> + 0xad) & 0xf)
  50:	d94400af 	ld.b	r10, (r4, 0xaf)	// regs: r10=*(<arg0> + 0xaf)
  54:	4804      	lsri	r0, r0, 4	// regs: r0=(*(<arg0> + 0xad) >> 0x4)
  56:	e54a200f 	andi	r10, r10, 15	// regs: r10=(*(<arg0> + 0xaf) & 0xf)
  5a:	b804      	st.w	r0, (r14, 0x10)	// local_10 = (*(<arg0> + 0xad) >> 0x4)
  5c:	dd4e2005 	st.w	r10, (r14, 0x14)	// local_c = (*(<arg0> + 0xaf) & 0xf)
  60:	dd2e2003 	st.w	r9, (r14, 0xc)	// local_14 = *(<arg0> + 0x74)
  64:	dd0e2002 	st.w	r8, (r14, 0x8)	// local_18 = *(<arg0> + 0x73)
  68:	ddae2001 	st.w	r13, (r14, 0x4)	// local_1c = *(<arg0> + 0x72)
  6c:	dd8e2000 	st.w	r12, (r14, 0x0)	// local_20 = *(<arg0> + 0x71)
  70:	7445      	zexth	r1, r1	// regs: r1=zext16(*(<arg0> + 0x68))
  72:	0303      	lrw	r0, 0x0	// regs: r0=0x0
  74:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x74>, r1=<clobbered>
loc_78:
  78:	d80410e3 	ld.h	r0, (r4, 0x1c6)	// regs: r0=*(<arg0> + 0x1c6)
  7c:	d86410ea 	ld.h	r3, (r4, 0x1d4)	// regs: r3=*(<arg0> + 0x1d4)
  80:	640c      	cmphs	r3, r0
  82:	0924      	bt	0x2ca	// if (T) goto loc_2ca;
  84:	e9000008 	bez	r0, 0x94	// if (r0 == 0x0) goto loc_94;
  88:	586d      	subu	r3, r0, r3	// regs: r3=(*(<arg0> + 0x1c6) - *(<arg0> + 0x1d4))
  8a:	3264      	movi	r2, 100	// regs: r2=0x64
  8c:	7cc8      	mult	r3, r2	// regs: r3=((*(<arg0> + 0x1c6) - *(<arg0> + 0x1d4)) * 0x64)
  8e:	c4038040 	divs	r0, r3, r0	// regs: r0=(((*(<arg0> + 0x1c6) - *(<arg0> + 0x1d4)) * 0x64) / *(<arg0> + 0x1c6))
  92:	7400      	zextb	r0, r0	// regs: r0=zext8((((*(<arg0> + 0x1c6) - *(<arg0> + 0x1d4)) * 0x64) / *(<arg0> + 0x1c6)))
loc_94:
  94:	d865483d 	ld.bs	r3, (r5, 0x83d)	// regs: r3=*(0x83d)
  98:	640d      	cmplt	r3, r0
  9a:	0c03      	bf	0xa0	// if (!T) goto loc_a0;
  9c:	dc05083d 	st.b	r0, (r5, 0x83d)	// *(0x83d) = r0
loc_a0:
  a0:	d8650866 	ld.b	r3, (r5, 0x866)	// regs: r3=*(0x866)
  a4:	3b07      	cmphsi	r3, 8
  a6:	d8241034 	ld.h	r1, (r4, 0x68)	// regs: r1=*(<arg0> + 0x68)
  aa:	0d12      	bf	0x2ce	// if (r3 < 0x8) goto loc_2ce;
  ac:	3b4a      	cmpnei	r3, 10
  ae:	0351      	lrw	r2, 0x0	// regs: r2=0x0
  b0:	0371      	lrw	r3, 0x0	// regs: r3=0x0
  b2:	c4430c20 	incf	r2, r3, 0
loc_b6:
  b6:	d86400ae 	ld.b	r3, (r4, 0xae)	// regs: r3=*(<arg0> + 0xae)
  ba:	d9842072 	ld.w	r12, (r4, 0x1c8)	// regs: r12=*(<arg0> + 0x1c8)
  be:	e463200f 	andi	r3, r3, 15	// regs: r3=(*(<arg0> + 0xae) & 0xf)
  c2:	d9a440b4 	ld.bs	r13, (r4, 0xb4)	// regs: r13=*(<arg0> + 0xb4)
  c6:	c54c4888 	asri	r8, r12, 10	// regs: r8=(*(<arg0> + 0x1c8) >> 0xa)
  ca:	e9070104 	bez	r7, 0x2d2	// if (r7 == 0x0) goto loc_2d2;
  ce:	ea090064 	movi	r9, 100	// regs: r9=0x64
  d2:	6242      	subu	r9, r0	// regs: r9=(0x64 - r0)
  d4:	c4ec488c 	asri	r12, r12, 7	// regs: r12=(*(<arg0> + 0x1c8) >> 0x7)
  d8:	7f24      	mult	r12, r9	// regs: r12=((*(<arg0> + 0x1c8) >> 0x7) * (0x64 - r0))
  da:	ea09000a 	movi	r9, 10	// regs: r9=0xa
  de:	7f24      	mult	r12, r9	// regs: r12=(((*(<arg0> + 0x1c8) >> 0x7) * (0x64 - r0)) * 0xa)
  e0:	c4ec802c 	divu	r12, r12, r7	// regs: r12=((((*(<arg0> + 0x1c8) >> 0x7) * (0x64 - r0)) * 0xa) / (<ret os_jiffies@0xa> - *(0x81c)))
loc_e4:
  e4:	b803      	st.w	r0, (r14, 0xc)	// local_14 = r0
  e6:	dd8e2002 	st.w	r12, (r14, 0x8)	// local_18 = r12
  ea:	dd0e2001 	st.w	r8, (r14, 0x4)	// local_1c = (*(<arg0> + 0x1c8) >> 0xa)
  ee:	ddae2000 	st.w	r13, (r14, 0x0)	// local_20 = *(<arg0> + 0xb4)
  f2:	131f      	lrw	r0, 0x0	// regs: r0=0x0
  f4:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xf4>, r1=<clobbered>
  f8:	3e41      	cmpnei	r6, 1
  fa:	0835      	bt	0x164	// if (r6 != 0x1) goto loc_164;
  fc:	d82400af 	ld.b	r1, (r4, 0xaf)	// regs: r1=*(<arg0> + 0xaf)
 100:	e46120f0 	andi	r3, r1, 240	// regs: r3=(*(<arg0> + 0xaf) & 0xf0)
 104:	eb430030 	cmpnei	r3, 48
 108:	0ce7      	bf	0x2d6	// if (r3 == 0x30) goto loc_2d6;
 10a:	4924      	lsri	r1, r1, 4	// regs: r1=(*(<arg0> + 0xaf) >> 0x4)
 10c:	3302      	movi	r3, 2	// regs: r3=0x2
 10e:	c4234021 	lsl	r1, r3, r1
loc_112:
 112:	d86410e2 	ld.h	r3, (r4, 0x1c4)	// regs: r3=*(<arg0> + 0x1c4)
 116:	6c8f      	mov	r2, r3	// regs: r2=*(<arg0> + 0x1c4)
 118:	e9030006 	bez	r3, 0x124	// if (r3 == 0x0) goto loc_124;
 11c:	d80410e3 	ld.h	r0, (r4, 0x1c6)	// regs: r0=*(<arg0> + 0x1c6)
 120:	c4608023 	divu	r3, r0, r3	// regs: r3=(*(<arg0> + 0x1c6) / *(<arg0> + 0x1c4))
loc_124:
 124:	d80410eb 	ld.h	r0, (r4, 0x1d6)	// regs: r0=*(<arg0> + 0x1d6)
 128:	b807      	st.w	r0, (r14, 0x1c)	// local_4 = *(<arg0> + 0x1d6)
 12a:	d8042077 	ld.w	r0, (r4, 0x1dc)	// regs: r0=*(<arg0> + 0x1dc)
 12e:	500a      	asri	r0, r0, 10	// regs: r0=(*(<arg0> + 0x1dc) >> 0xa)
 130:	b806      	st.w	r0, (r14, 0x18)	// local_8 = (*(<arg0> + 0x1dc) >> 0xa)
 132:	d80410ea 	ld.h	r0, (r4, 0x1d4)	// regs: r0=*(<arg0> + 0x1d4)
 136:	b805      	st.w	r0, (r14, 0x14)	// local_c = *(<arg0> + 0x1d4)
 138:	d8042076 	ld.w	r0, (r4, 0x1d8)	// regs: r0=*(<arg0> + 0x1d8)
 13c:	500a      	asri	r0, r0, 10	// regs: r0=(*(<arg0> + 0x1d8) >> 0xa)
 13e:	b804      	st.w	r0, (r14, 0x10)	// local_10 = (*(<arg0> + 0x1d8) >> 0xa)
 140:	d8042074 	ld.w	r0, (r4, 0x1d0)	// regs: r0=*(<arg0> + 0x1d0)
 144:	b803      	st.w	r0, (r14, 0xc)	// local_14 = *(<arg0> + 0x1d0)
 146:	9404      	ld.w	r0, (r4, 0x10)	// regs: r0=*(<arg0> + 0x10)
 148:	b802      	st.w	r0, (r14, 0x8)	// local_18 = *(<arg0> + 0x10)
 14a:	d80400b2 	ld.b	r0, (r4, 0xb2)	// regs: r0=*(<arg0> + 0xb2)
 14e:	b801      	st.w	r0, (r14, 0x4)	// local_1c = *(<arg0> + 0xb2)
 150:	ea0c0019 	movi	r12, 25	// regs: r12=0x19
 154:	d8042073 	ld.w	r0, (r4, 0x1cc)	// regs: r0=*(<arg0> + 0x1cc)
 158:	c5808040 	divs	r0, r0, r12	// regs: r0=(*(<arg0> + 0x1cc) / 0x19)
 15c:	b800      	st.w	r0, (r14, 0x0)	// local_20 = (*(<arg0> + 0x1cc) / 0x19)
 15e:	1305      	lrw	r0, 0x0	// regs: r0=0x0
 160:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x160>, r1=<clobbered>
loc_164:
 164:	d80543e0 	ld.bs	r0, (r5, 0x3e0)	// regs: r0=*(0x3e0)
 168:	d98440b8 	ld.bs	r12, (r4, 0xb8)	// regs: r12=*(<arg0> + 0xb8)
 16c:	d84400b7 	ld.b	r2, (r4, 0xb7)	// regs: r2=*(<arg0> + 0xb7)
 170:	6300      	addu	r12, r0	// regs: r12=(*(<arg0> + 0xb8) + *(0x3e0))
 172:	d8042079 	ld.w	r0, (r4, 0x1e4)	// regs: r0=*(<arg0> + 0x1e4)
 176:	d8241034 	ld.h	r1, (r4, 0x68)	// regs: r1=*(<arg0> + 0x68)
 17a:	e442200f 	andi	r2, r2, 15	// regs: r2=(*(<arg0> + 0xb7) & 0xf)
 17e:	d86440b6 	ld.bs	r3, (r4, 0xb6)	// regs: r3=*(<arg0> + 0xb6)
 182:	d90440a3 	ld.bs	r8, (r4, 0xa3)	// regs: r8=*(<arg0> + 0xa3)
 186:	c5404849 	lsri	r9, r0, 10	// regs: r9=(*(<arg0> + 0x1e4) >> 0xa)
 18a:	e907000a 	bez	r7, 0x19e	// if (r7 == 0x0) goto loc_19e;
 18e:	ea0d00fa 	movi	r13, 250	// regs: r13=0xfa
 192:	4807      	lsri	r0, r0, 7	// regs: r0=(*(<arg0> + 0x1e4) >> 0x7)
 194:	c44d482d 	lsli	r13, r13, 2	// regs: r13=0x3e8
 198:	7c34      	mult	r0, r13	// regs: r0=((*(<arg0> + 0x1e4) >> 0x7) * 0x3e8)
 19a:	c4e08027 	divu	r7, r0, r7	// regs: r7=(((*(<arg0> + 0x1e4) >> 0x7) * 0x3e8) / (<ret os_jiffies@0xa> - *(0x81c)))
loc_19e:
 19e:	d80400ac 	ld.b	r0, (r4, 0xac)	// regs: r0=*(<arg0> + 0xac)
 1a2:	b807      	st.w	r0, (r14, 0x1c)	// local_4 = *(<arg0> + 0xac)
 1a4:	d80400ab 	ld.b	r0, (r4, 0xab)	// regs: r0=*(<arg0> + 0xab)
 1a8:	b806      	st.w	r0, (r14, 0x18)	// local_8 = *(<arg0> + 0xab)
 1aa:	d80400aa 	ld.b	r0, (r4, 0xaa)	// regs: r0=*(<arg0> + 0xaa)
 1ae:	b805      	st.w	r0, (r14, 0x14)	// local_c = *(<arg0> + 0xaa)
 1b0:	d80400a9 	ld.b	r0, (r4, 0xa9)	// regs: r0=*(<arg0> + 0xa9)
 1b4:	b804      	st.w	r0, (r14, 0x10)	// local_10 = *(<arg0> + 0xa9)
 1b6:	b8e3      	st.w	r7, (r14, 0xc)	// local_14 = r7
 1b8:	dd2e2002 	st.w	r9, (r14, 0x8)	// local_18 = (*(<arg0> + 0x1e4) >> 0xa)
 1bc:	dd8e2001 	st.w	r12, (r14, 0x4)	// local_1c = (*(<arg0> + 0xb8) + *(0x3e0))
 1c0:	dd0e2000 	st.w	r8, (r14, 0x0)	// local_20 = *(<arg0> + 0xa3)
 1c4:	120c      	lrw	r0, 0x0	// regs: r0=0x0
 1c6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1c6>, r1=<clobbered>
 1ca:	3e41      	cmpnei	r6, 1
 1cc:	0824      	bt	0x214	// if (r6 != 0x1) goto loc_214;
 1ce:	d86410f0 	ld.h	r3, (r4, 0x1e0)	// regs: r3=*(<arg0> + 0x1e0)
 1d2:	d8241036 	ld.h	r1, (r4, 0x6c)	// regs: r1=*(<arg0> + 0x6c)
 1d6:	6c8f      	mov	r2, r3	// regs: r2=*(<arg0> + 0x1e0)
 1d8:	e9030006 	bez	r3, 0x1e4	// if (r3 == 0x0) goto loc_1e4;
 1dc:	d80410f1 	ld.h	r0, (r4, 0x1e2)	// regs: r0=*(<arg0> + 0x1e2)
 1e0:	c4608023 	divu	r3, r0, r3	// regs: r3=(*(<arg0> + 0x1e2) / *(<arg0> + 0x1e0))
loc_1e4:
 1e4:	d804207b 	ld.w	r0, (r4, 0x1ec)	// regs: r0=*(<arg0> + 0x1ec)
 1e8:	b803      	st.w	r0, (r14, 0xc)	// local_14 = *(<arg0> + 0x1ec)
 1ea:	d804207c 	ld.w	r0, (r4, 0x1f0)	// regs: r0=*(<arg0> + 0x1f0)
 1ee:	b802      	st.w	r0, (r14, 0x8)	// local_18 = *(<arg0> + 0x1f0)
 1f0:	d80400b3 	ld.b	r0, (r4, 0xb3)	// regs: r0=*(<arg0> + 0xb3)
 1f4:	ea0c0028 	movi	r12, 40	// regs: r12=0x28
 1f8:	b801      	st.w	r0, (r14, 0x4)	// local_1c = *(<arg0> + 0xb3)
 1fa:	d804207a 	ld.w	r0, (r4, 0x1e8)	// regs: r0=*(<arg0> + 0x1e8)
 1fe:	7c30      	mult	r0, r12	// regs: r0=(*(<arg0> + 0x1e8) * 0x28)
 200:	ea0c00fa 	movi	r12, 250	// regs: r12=0xfa
 204:	c44c482c 	lsli	r12, r12, 2	// regs: r12=0x3e8
 208:	c5808020 	divu	r0, r0, r12	// regs: r0=((*(<arg0> + 0x1e8) * 0x28) / 0x3e8)
 20c:	b800      	st.w	r0, (r14, 0x0)	// local_20 = ((*(<arg0> + 0x1e8) * 0x28) / 0x3e8)
 20e:	111b      	lrw	r0, 0x0	// regs: r0=0x0
 210:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x210>, r1=<clobbered>
loc_214:
 214:	111a      	lrw	r0, 0x0	// regs: r0=0x0
 216:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x216>, r1=<clobbered>
 21a:	d86520ee 	ld.w	r3, (r5, 0x3b8)	// regs: r3=*(0x3b8)
 21e:	e4632006 	andi	r3, r3, 6	// regs: r3=(*(0x3b8) & 0x6)
 222:	e9030010 	bez	r3, 0x242	// if (r3 == 0x0) goto loc_242;
 226:	d804105f 	ld.h	r0, (r4, 0xbe)	// regs: r0=*(<arg0> + 0xbe)
 22a:	c4205500 	zext	r0, r0, 8, 1	// regs: r0=zext(*(<arg0> + 0xbe))
 22e:	b800      	st.w	r0, (r14, 0x0)	// local_20 = zext(*(<arg0> + 0xbe))
 230:	d864012c 	ld.b	r3, (r4, 0x12c)	// regs: r3=*(<arg0> + 0x12c)
 234:	d8440128 	ld.b	r2, (r4, 0x128)	// regs: r2=*(<arg0> + 0x128)
 238:	d8241034 	ld.h	r1, (r4, 0x68)	// regs: r1=*(<arg0> + 0x68)
 23c:	1111      	lrw	r0, 0x0	// regs: r0=0x0
 23e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x23e>, r1=<clobbered>
loc_242:
 242:	d8650338 	ld.b	r3, (r5, 0x338)	// regs: r3=*(0x338)
 246:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x338) & 0x8)
 24a:	e9030026 	bez	r3, 0x296	// if (r3 == 0x0) goto loc_296;
 24e:	d86520ee 	ld.w	r3, (r5, 0x3b8)	// regs: r3=*(0x3b8)
 252:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x3b8) & 0x2)
 256:	e9030020 	bez	r3, 0x296	// if (r3 == 0x0) goto loc_296;
 25a:	e4c400c1 	addi	r6, r4, 194	// regs: r6=(<arg0> + 0xc2)
 25e:	3500      	movi	r5, 0	// regs: r5=0x0
 260:	11e9      	lrw	r7, 0x0	// regs: r7=0x0
 262:	ea88002a 	lrw	r8, 0x0	// regs: r8=0x0
loc_266:
 266:	5c74      	addu	r3, r4, r5	// regs: r3=(<arg0> + r5)
 268:	d8430102 	ld.b	r2, (r3, 0x102)	// regs: r2=*(((<arg0> + r5) + 0x102))
 26c:	e9220005 	bnez	r2, 0x276	// if (r2 != 0x0) goto loc_276;
 270:	8e60      	ld.h	r3, (r6, 0x0)	// regs: r3=*(r6)
 272:	e903000d 	bez	r3, 0x28c	// if (r3 == 0x0) goto loc_28c;
loc_276:
 276:	8e20      	ld.h	r1, (r6, 0x0)	// regs: r1=*(r6)
 278:	d0a70443 	ldr.h	r3, (r7, r5 << 1)	// regs: r3=*(0x0 + (r5 << 1))
 27c:	4928      	lsri	r1, r1, 8	// regs: r1=(*(r6) >> 0x8)
 27e:	74cd      	zexth	r3, r3	// regs: r3=zext16(*(0x0 + (r5 << 1)))
 280:	b820      	st.w	r1, (r14, 0x0)	// local_20 = (*(r6) >> 0x8)
 282:	7cc4      	mult	r3, r1	// regs: r3=(zext16(*(0x0 + (r5 << 1))) * (*(r6) >> 0x8))
 284:	6c23      	mov	r0, r8	// regs: r0=0x0
 286:	6c57      	mov	r1, r5	// regs: r1=r5
 288:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x288>, r1=<clobbered>
loc_28c:
 28c:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
 28e:	eb450020 	cmpnei	r5, 32
 292:	2601      	addi	r6, 2	// regs: r6=(r6 + 0x2)
 294:	0be9      	bt	0x266	// if (r5 != 0x20) goto loc_266;
loc_296:
 296:	1408      	addi	r14, r14, 32	// regs: r14=((sp - 0x20) + 0x20)
 298:	1497      	pop	r4-r10, r15
loc_29a:
 29a:	d80400b9 	ld.b	r0, (r4, 0xb9)	// regs: r0=*(<arg0> + 0xb9)
 29e:	e4002001 	andi	r0, r0, 1	// regs: r0=(*(<arg0> + 0xb9) & 0x1)
 2a2:	3840      	cmpnei	r0, 0
 2a4:	ea8a001a 	lrw	r10, 0x0	// regs: r10=0x0
 2a8:	101a      	lrw	r0, 0x0	// regs: r0=0x0
 2aa:	c40a0c20 	incf	r0, r10, 0
 2ae:	b804      	st.w	r0, (r14, 0x10)	// local_10 = 0x0
 2b0:	dd2e2003 	st.w	r9, (r14, 0xc)	// local_14 = *(<arg0> + 0x74)
 2b4:	dd0e2002 	st.w	r8, (r14, 0x8)	// local_18 = *(<arg0> + 0x73)
 2b8:	ddae2001 	st.w	r13, (r14, 0x4)	// local_1c = *(<arg0> + 0x72)
 2bc:	dd8e2000 	st.w	r12, (r14, 0x0)	// local_20 = *(<arg0> + 0x71)
 2c0:	7445      	zexth	r1, r1	// regs: r1=zext16(*(<arg0> + 0x68))
 2c2:	1015      	lrw	r0, 0x0	// regs: r0=0x0
 2c4:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2c4>, r1=<clobbered>
 2c8:	06d8      	br	0x78	// goto loc_78;
loc_2ca:
 2ca:	3000      	movi	r0, 0	// regs: r0=0x0
 2cc:	06e4      	br	0x94	// goto loc_94;
loc_2ce:
 2ce:	1047      	lrw	r2, 0x0	// regs: r2=0x0
 2d0:	06f3      	br	0xb6	// goto loc_b6;
loc_2d2:
 2d2:	6f1f      	mov	r12, r7	// regs: r12=(<ret os_jiffies@0xa> - *(0x81c))
 2d4:	0708      	br	0xe4	// goto loc_e4;
loc_2d6:
 2d6:	6c5b      	mov	r1, r6	// regs: r1=<arg1>
 2d8:	071d      	br	0x112	// goto loc_112;
 2da:	0000      	.short	0x0000
 2dc:	00000000 	.long	0x00000000	// <ah_lmac>
 2e0:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0x13>
 2e4:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0xd>
 2e8:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0x8>
 2ec:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0x75>
 2f0:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0xa5>
 2f4:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0xfe>
 2f8:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0x14d>
 2fc:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0x193>
 300:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0x196>
 304:	00000000 	.long	0x00000000	// <rate_tbl>
 308:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0x1b6>
 30c:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0x4>
 310:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1>
 314:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0x48>

Disassembly of section .text.lmac_channel_utilization_calc:

00000000 <lmac_channel_utilization_calc>: // arg_bytes: 4
   0:	14d8      	push	r4-r11, r15
   2:	1423      	subi	r14, r14, 12	// regs: r14=(sp - 0xc)
   4:	6e03      	mov	r8, r0	// regs: r8=<arg0>
   6:	e90000bd 	bez	r0, 0x180	// if (r0 == 0x0) goto loc_180;
   a:	12df      	lrw	r6, 0x0	// regs: r6=0x0
   c:	d86621d3 	ld.w	r3, (r6, 0x74c)	// regs: r3=*(0x74c)
  10:	d84621de 	ld.w	r2, (r6, 0x778)	// regs: r2=*(0x778)
  14:	608c      	addu	r2, r3	// regs: r2=(*(0x778) + *(0x74c))
  16:	3328      	movi	r3, 40	// regs: r3=0x28
  18:	7c8c      	mult	r2, r3	// regs: r2=((*(0x778) + *(0x74c)) * 0x28)
  1a:	33fa      	movi	r3, 250	// regs: r3=0xfa
  1c:	4362      	lsli	r3, r3, 2	// regs: r3=0x3e8
  1e:	c4628022 	divu	r2, r2, r3	// regs: r2=(((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)
  22:	6408      	cmphs	r2, r0
  24:	0c09      	bf	0x36	// if (!T) goto loc_36;
  26:	6c43      	mov	r1, r0	// regs: r1=<arg0>
  28:	1218      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2a>, r1=<clobbered>
  2e:	3400      	movi	r4, 0	// regs: r4=0x0
loc_30:
  30:	6c13      	mov	r0, r4	// regs: r0=r4
  32:	1403      	addi	r14, r14, 12	// regs: r14=((sp - 0xc) + 0xc)
  34:	1498      	pop	r4-r11, r15
loc_36:
  36:	d86620ee 	ld.w	r3, (r6, 0x3b8)	// regs: r3=*(0x3b8)
  3a:	e4632040 	andi	r3, r3, 64	// regs: r3=(*(0x3b8) & 0x40)
  3e:	58a9      	subu	r5, r0, r2	// regs: r5=(<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8))
  40:	e9030007 	bez	r3, 0x4e	// if (r3 == 0x0) goto loc_4e;
  44:	6c43      	mov	r1, r0	// regs: r1=<arg0>
  46:	6cd7      	mov	r3, r5	// regs: r3=(<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8))
  48:	1211      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x4a>, r1=<clobbered>
loc_4e:
  4e:	3100      	movi	r1, 0	// regs: r1=0x0
  50:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  52:	1210      	lrw	r0, 0x0	// regs: r0=0x0
  54:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0x54>, r1=<clobbered>
  58:	d8e6227e 	ld.w	r7, (r6, 0x9f8)	// regs: r7=*(0x9f8)
  5c:	126e      	lrw	r3, 0x0	// regs: r3=0x0
loc_5e:
  5e:	64de      	cmpne	r7, r3
  60:	0882      	bt	0x164	// if (T) goto loc_164;
  62:	ea0b0000 	movi	r11, 0	// regs: r11=0x0
loc_66:
  66:	120b      	lrw	r0, 0x0	// regs: r0=0x0
  68:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0x68>, r1=<clobbered>
  6c:	d8660308 	ld.b	r3, (r6, 0x308)	// regs: r3=*(0x308)
  70:	4363      	lsli	r3, r3, 3	// regs: r3=(*(0x308) << 0x3)
  72:	e4632018 	andi	r3, r3, 24	// regs: r3=((*(0x308) << 0x3) & 0x18)
  76:	ea8a0049 	lrw	r10, 0x0	// regs: r10=0x0
  7a:	2306      	addi	r3, 7	// regs: r3=(((*(0x308) << 0x3) & 0x18) + 0x7)
  7c:	d06a0449 	ldr.h	r9, (r10, r3 << 1)	// regs: r9=*(0x0 + ((((*(0x308) << 0x3) & 0x18) + 0x7) << 1))
  80:	7665      	zexth	r9, r9	// regs: r9=zext16(*(0x0 + ((((*(0x308) << 0x3) & 0x18) + 0x7) << 1)))
  82:	4da1      	lsri	r5, r5, 1	// regs: r5=((<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)) >> 0x1)
  84:	e90b007c 	bez	r11, 0x17c	// if (r11 == 0x0) goto loc_17c;
  88:	d84710e3 	ld.h	r2, (r7, 0x1c6)	// regs: r2=*(r7 + 0x1c6)
  8c:	e9020074 	bez	r2, 0x174	// if (r2 == 0x0) goto loc_174;
  90:	d86710ea 	ld.h	r3, (r7, 0x1d4)	// regs: r3=*(r7 + 0x1d4)
  94:	4367      	lsli	r3, r3, 7	// regs: r3=(*(r7 + 0x1d4) << 0x7)
  96:	c4438043 	divs	r3, r3, r2	// regs: r3=((*(r7 + 0x1d4) << 0x7) / *(r7 + 0x1c6))
loc_9a:
  9a:	e46320ff 	andi	r3, r3, 255	// regs: r3=(r3 & 0xff)
  9e:	d82b0128 	ld.b	r1, (r11, 0x128)	// regs: r1=*(r11 + 0x128)
  a2:	c4a38424 	mult	r4, r3, r5	// regs: r4=((r3 & 0xff) * ((<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)) >> 0x1))
  a6:	d02a0441 	ldr.h	r1, (r10, r1 << 1)	// regs: r1=*(0x0 + (*(r11 + 0x128) << 1))
  aa:	7445      	zexth	r1, r1	// regs: r1=zext16(*(0x0 + (*(r11 + 0x128) << 1)))
  ac:	4c87      	lsri	r4, r4, 7	// regs: r4=(((r3 & 0xff) * ((<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)) >> 0x1)) >> 0x7)
  ae:	c4290020 	addu	r0, r9, r1	// regs: r0=(zext16(*(0x0 + ((((*(0x308) << 0x3) & 0x18) + 0x7) << 1))) + zext16(*(0x0 + (*(r11 + 0x128) << 1))))
  b2:	7d04      	mult	r4, r1	// regs: r4=((((r3 & 0xff) * ((<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)) >> 0x1)) >> 0x7) * zext16(*(0x0 + (*(r11 + 0x128) << 1))))
  b4:	c4048024 	divu	r4, r4, r0	// regs: r4=(((((r3 & 0xff) * ((<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)) >> 0x1)) >> 0x7) * zext16(*(0x0 + (*(r11 + 0x128) << 1)))) / (zext16(*(0x0 + ((((*(0x308) << 0x3) & 0x18) + 0x7) << 1))) + zext16(*(0x0 + (*(r11 + 0x128) << 1)))))
  b8:	d80620ee 	ld.w	r0, (r6, 0x3b8)	// regs: r0=*(0x3b8)
  bc:	e4002040 	andi	r0, r0, 64	// regs: r0=(*(0x3b8) & 0x40)
  c0:	e900000b 	bez	r0, 0xd6	// if (r0 == 0x0) goto loc_d6;
  c4:	b882      	st.w	r4, (r14, 0x8)	// local_4 = (((((r3 & 0xff) * ((<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)) >> 0x1)) >> 0x7) * zext16(*(0x0 + (*(r11 + 0x128) << 1)))) / (zext16(*(0x0 + ((((*(0x308) << 0x3) & 0x18) + 0x7) << 1))) + zext16(*(0x0 + (*(r11 + 0x128) << 1)))))
  c6:	b841      	st.w	r2, (r14, 0x4)	// local_8 = *(r7 + 0x1c6)
  c8:	d84710ea 	ld.h	r2, (r7, 0x1d4)	// regs: r2=*(r7 + 0x1d4)
  cc:	b840      	st.w	r2, (r14, 0x0)	// local_c = *(r7 + 0x1d4)
  ce:	6ca7      	mov	r2, r9	// regs: r2=zext16(*(0x0 + ((((*(0x308) << 0x3) & 0x18) + 0x7) << 1)))
  d0:	1113      	lrw	r0, 0x0	// regs: r0=0x0
  d2:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xd2>, r1=<clobbered>
loc_d6:
  d6:	d80710f1 	ld.h	r0, (r7, 0x1e2)	// regs: r0=*(r7 + 0x1e2)
  da:	d987207c 	ld.w	r12, (r7, 0x1f0)	// regs: r12=*(r7 + 0x1f0)
  de:	6300      	addu	r12, r0	// regs: r12=(*(r7 + 0x1f0) + *(r7 + 0x1e2))
  e0:	e90c004c 	bez	r12, 0x178	// if (r12 == 0x0) goto loc_178;
  e4:	4067      	lsli	r3, r0, 7	// regs: r3=(*(r7 + 0x1e2) << 0x7)
  e6:	c5838023 	divu	r3, r3, r12	// regs: r3=((*(r7 + 0x1e2) << 0x7) / (*(r7 + 0x1f0) + *(r7 + 0x1e2)))
loc_ea:
  ea:	d82b00b7 	ld.b	r1, (r11, 0xb7)	// regs: r1=*(r11 + 0xb7)
  ee:	4944      	lsri	r2, r1, 4	// regs: r2=(*(r11 + 0xb7) >> 0x4)
  f0:	2200      	addi	r2, 1	// regs: r2=((*(r11 + 0xb7) >> 0x4) + 0x1)
  f2:	4243      	lsli	r2, r2, 3	// regs: r2=(((*(r11 + 0xb7) >> 0x4) + 0x1) << 0x3)
  f4:	e4212007 	andi	r1, r1, 7	// regs: r1=(*(r11 + 0xb7) & 0x7)
  f8:	e4422018 	andi	r2, r2, 24	// regs: r2=((((*(r11 + 0xb7) >> 0x4) + 0x1) << 0x3) & 0x18)
  fc:	6c84      	or	r2, r1	// regs: r2=(((((*(r11 + 0xb7) >> 0x4) + 0x1) << 0x3) & 0x18) | (*(r11 + 0xb7) & 0x7))
  fe:	e46320ff 	andi	r3, r3, 255	// regs: r3=(r3 & 0xff)
 102:	d04a0441 	ldr.h	r1, (r10, r2 << 1)	// regs: r1=*(0x0 + ((((((*(r11 + 0xb7) >> 0x4) + 0x1) << 0x3) & 0x18) | (*(r11 + 0xb7) & 0x7)) << 1))
 106:	7d4c      	mult	r5, r3	// regs: r5=(((<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)) >> 0x1) * (r3 & 0xff))
 108:	7445      	zexth	r1, r1	// regs: r1=zext16(*(0x0 + ((((((*(r11 + 0xb7) >> 0x4) + 0x1) << 0x3) & 0x18) | (*(r11 + 0xb7) & 0x7)) << 1)))
 10a:	4da7      	lsri	r5, r5, 7	// regs: r5=((((<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)) >> 0x1) * (r3 & 0xff)) >> 0x7)
 10c:	c4290022 	addu	r2, r9, r1	// regs: r2=(zext16(*(0x0 + ((((*(0x308) << 0x3) & 0x18) + 0x7) << 1))) + zext16(*(0x0 + ((((((*(r11 + 0xb7) >> 0x4) + 0x1) << 0x3) & 0x18) | (*(r11 + 0xb7) & 0x7)) << 1))))
 110:	7d44      	mult	r5, r1	// regs: r5=(((((<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)) >> 0x1) * (r3 & 0xff)) >> 0x7) * zext16(*(0x0 + ((((((*(r11 + 0xb7) >> 0x4) + 0x1) << 0x3) & 0x18) | (*(r11 + 0xb7) & 0x7)) << 1))))
 112:	c4458025 	divu	r5, r5, r2	// regs: r5=((((((<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)) >> 0x1) * (r3 & 0xff)) >> 0x7) * zext16(*(0x0 + ((((((*(r11 + 0xb7) >> 0x4) + 0x1) << 0x3) & 0x18) | (*(r11 + 0xb7) & 0x7)) << 1)))) / (zext16(*(0x0 + ((((*(0x308) << 0x3) & 0x18) + 0x7) << 1))) + zext16(*(0x0 + ((((((*(r11 + 0xb7) >> 0x4) + 0x1) << 0x3) & 0x18) | (*(r11 + 0xb7) & 0x7)) << 1)))))
 116:	d84620ee 	ld.w	r2, (r6, 0x3b8)	// regs: r2=*(0x3b8)
 11a:	e4422040 	andi	r2, r2, 64	// regs: r2=(*(0x3b8) & 0x40)
 11e:	e902000a 	bez	r2, 0x132	// if (r2 == 0x0) goto loc_132;
 122:	b800      	st.w	r0, (r14, 0x0)	// local_c = *(r7 + 0x1e2)
 124:	b8a2      	st.w	r5, (r14, 0x8)	// local_4 = ((((((<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)) >> 0x1) * (r3 & 0xff)) >> 0x7) * zext16(*(0x0 + ((((((*(r11 + 0xb7) >> 0x4) + 0x1) << 0x3) & 0x18) | (*(r11 + 0xb7) & 0x7)) << 1)))) / (zext16(*(0x0 + ((((*(0x308) << 0x3) & 0x18) + 0x7) << 1))) + zext16(*(0x0 + ((((((*(r11 + 0xb7) >> 0x4) + 0x1) << 0x3) & 0x18) | (*(r11 + 0xb7) & 0x7)) << 1)))))
 126:	dd8e2001 	st.w	r12, (r14, 0x4)	// local_8 = (*(r7 + 0x1f0) + *(r7 + 0x1e2))
 12a:	6ca7      	mov	r2, r9	// regs: r2=zext16(*(0x0 + ((((*(0x308) << 0x3) & 0x18) + 0x7) << 1)))
 12c:	101d      	lrw	r0, 0x0	// regs: r0=0x0
 12e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x12e>, r1=<clobbered>
loc_132:
 132:	5c34      	addu	r1, r4, r5	// regs: r1=(r4 + r5)
 134:	c4280081 	subu	r1, r8, r1	// regs: r1=(<arg0> - (r4 + r5))
 138:	34ff      	movi	r4, 255	// regs: r4=0xff
 13a:	d86620ee 	ld.w	r3, (r6, 0x3b8)	// regs: r3=*(0x3b8)
 13e:	7c50      	mult	r1, r4	// regs: r1=((<arg0> - (r4 + r5)) * 0xff)
 140:	e4632040 	andi	r3, r3, 64	// regs: r3=(*(0x3b8) & 0x40)
 144:	c5018021 	divu	r1, r1, r8	// regs: r1=(((<arg0> - (r4 + r5)) * 0xff) / <arg0>)
 148:	7504      	zextb	r4, r1	// regs: r4=zext8((((<arg0> - (r4 + r5)) * 0xff) / <arg0>))
 14a:	e903ff73 	bez	r3, 0x30	// if (r3 == 0x0) goto loc_30;
 14e:	d84621de 	ld.w	r2, (r6, 0x778)	// regs: r2=*(0x778)
 152:	d86621d3 	ld.w	r3, (r6, 0x74c)	// regs: r3=*(0x74c)
 156:	60c8      	addu	r3, r2	// regs: r3=(*(0x74c) + *(0x778))
 158:	6c53      	mov	r1, r4	// regs: r1=zext8((((<arg0> - (r4 + r5)) * 0xff) / <arg0>))
 15a:	6ca3      	mov	r2, r8	// regs: r2=<arg0>
 15c:	1012      	lrw	r0, 0x0	// regs: r0=0x0
 15e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x15e>, r1=<clobbered>
 162:	0767      	br	0x30	// goto loc_30;
loc_164:
 164:	d8471034 	ld.h	r2, (r7, 0x68)	// regs: r2=*(r7 + 0x68)
 168:	e9020004 	bez	r2, 0x170	// if (r2 == 0x0) goto loc_170;
 16c:	97e0      	ld.w	r7, (r7, 0x0)	// regs: r7=*(r7)
 16e:	0778      	br	0x5e	// goto loc_5e;
loc_170:
 170:	6edf      	mov	r11, r7	// regs: r11=r7
 172:	077a      	br	0x66	// goto loc_66;
loc_174:
 174:	3380      	movi	r3, 128	// regs: r3=0x80
 176:	0792      	br	0x9a	// goto loc_9a;
loc_178:
 178:	3380      	movi	r3, 128	// regs: r3=0x80
 17a:	07b8      	br	0xea	// goto loc_ea;
loc_17c:
 17c:	6d17      	mov	r4, r5	// regs: r4=((<arg0> - (((*(0x778) + *(0x74c)) * 0x28) / 0x3e8)) >> 0x1)
 17e:	07da      	br	0x132	// goto loc_132;
loc_180:
 180:	6d03      	mov	r4, r0	// regs: r4=<arg0>
 182:	0757      	br	0x30	// goto loc_30;
 184:	00000000 	.long	0x00000000	// <ah_lmac>
 188:	00000000 	.long	0x00000000	// <.rodata.lmac_channel_utilization_calc.str1.1>
 18c:	00000000 	.long	0x00000000	// <.rodata.lmac_channel_utilization_calc.str1.1+0x28>
 190:	00000000 	.long	0x00000000	// <ah_lmac+0xa00>
 194:	00000000 	.long	0x00000000	// <ah_lmac+0x9f8>
 198:	00000000 	.long	0x00000000	// <rate_tbl>
 19c:	00000000 	.long	0x00000000	// <.rodata.lmac_channel_utilization_calc.str1.1+0x48>
 1a0:	00000000 	.long	0x00000000	// <.rodata.lmac_channel_utilization_calc.str1.1+0x7f>
 1a4:	00000000 	.long	0x00000000	// <.rodata.lmac_channel_utilization_calc.str1.1+0xb6>

Disassembly of section .text.lmac_transceive_statics:

00000000 <lmac_transceive_statics>: // arg_bytes: 4
   0:	14d8      	push	r4-r11, r15
   2:	1436      	subi	r14, r14, 88	// regs: r14=(sp - 0x58)
   4:	0096      	lrw	r4, 0x0	// regs: r4=0x0
   6:	6dc3      	mov	r7, r0	// regs: r7=<arg0>
   8:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x8>, r1=<clobbered>
   c:	d8c42207 	ld.w	r6, (r4, 0x81c)	// regs: r6=*(0x81c)
  10:	58d9      	subu	r6, r0, r6	// regs: r6=(<ret os_jiffies@0x8> - *(0x81c))
  12:	6c1b      	mov	r0, r6	// regs: r0=(<ret os_jiffies@0x8> - *(0x81c))
  14:	e0000000 	bsr	0x0	// <lmac_channel_utilization_calc> // arg_bytes: 4; regs: r0=<ret lmac_channel_utilization_calc@0x14>, r1=<clobbered>
  18:	d8a421d0 	ld.w	r5, (r4, 0x740)	// regs: r5=*(0x740)
  1c:	dc040a6a 	st.b	r0, (r4, 0xa6a)	// *(0xa6a) = <ret lmac_channel_utilization_calc@0x14>
  20:	e9050051 	bez	r5, 0xc2	// if (r5 == 0x0) goto loc_c2;
  24:	c7e54889 	asri	r9, r5, 31	// regs: r9=(*(0x740) >> 0x1f)
  28:	6c97      	mov	r2, r5	// regs: r2=*(0x740)
  2a:	6ce7      	mov	r3, r9	// regs: r3=(*(0x740) >> 0x1f)
  2c:	d8042202 	ld.w	r0, (r4, 0x808)	// regs: r0=*(0x808)
  30:	d8242203 	ld.w	r1, (r4, 0x80c)	// regs: r1=*(0x80c)
  34:	e0000000 	bsr	0x0	// <__divdi3>; regs: r0=<ret __divdi3@0x34>, r1=<clobbered>
  38:	6e03      	mov	r8, r0	// regs: r8=<ret __divdi3@0x34>
  3a:	6c97      	mov	r2, r5	// regs: r2=*(0x740)
  3c:	6ce7      	mov	r3, r9	// regs: r3=(*(0x740) >> 0x1f)
  3e:	d8042204 	ld.w	r0, (r4, 0x810)	// regs: r0=*(0x810)
  42:	d8242205 	ld.w	r1, (r4, 0x814)	// regs: r1=*(0x814)
  46:	e0000000 	bsr	0x0	// <__divdi3>; regs: r0=<ret __divdi3@0x46>, r1=<clobbered>
  4a:	3d29      	cmplti	r5, 10
  4c:	083b      	bt	0xc2	// if (r5 < 0xa) goto loc_c2;
  4e:	3314      	movi	r3, 20	// regs: r3=0x14
  50:	7c0c      	mult	r0, r3	// regs: r0=(<ret __divdi3@0x46> * 0x14)
  52:	620c      	addu	r8, r3	// regs: r8=(<ret __divdi3@0x34> + 0x14)
  54:	c5008020 	divu	r0, r0, r8	// regs: r0=((<ret __divdi3@0x46> * 0x14) / (<ret __divdi3@0x34> + 0x14))
loc_58:
  58:	d86409e0 	ld.b	r3, (r4, 0x9e0)	// regs: r3=*(0x9e0)
  5c:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x9e0) & 0x1)
  60:	dc0420dc 	st.w	r0, (r4, 0x370)	// *(0x370) = r0
  64:	e9230032 	bnez	r3, 0xc8	// if (r3 != 0x0) goto loc_c8;
  68:	d8440319 	ld.b	r2, (r4, 0x319)	// regs: r2=*(0x319)
  6c:	e4422002 	andi	r2, r2, 2	// regs: r2=(*(0x319) & 0x2)
  70:	e9220006 	bnez	r2, 0x7c	// if (r2 != 0x0) goto loc_7c;
  74:	3f40      	cmpnei	r7, 0
  76:	c4000503 	mvc	r3	// regs: r3=<cond>
  7a:	74cc      	zextb	r3, r3	// regs: r3=zext8(<cond>)
loc_7c:
  7c:	d8442267 	ld.w	r2, (r4, 0x99c)	// regs: r2=*(0x99c)
  80:	2a01      	subi	r2, 2	// regs: r2=(*(0x99c) - 0x2)
  82:	3a01      	cmphsi	r2, 2
  84:	0c03      	bf	0x8a	// if (r2 < 0x2) goto loc_8a;
  86:	e9230031 	bnez	r3, 0xe8	// if (r3 != 0x0) goto loc_e8;
loc_8a:
  8a:	3100      	movi	r1, 0	// regs: r1=0x0
  8c:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  8e:	0117      	lrw	r0, 0x0	// regs: r0=0x0
  90:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0x90>, r1=<clobbered>
  94:	01d8      	lrw	r6, 0x0	// regs: r6=0x0
  96:	d8a4227e 	ld.w	r5, (r4, 0x9f8)	// regs: r5=*(0x9f8)
loc_9a:
  9a:	6596      	cmpne	r5, r6
  9c:	0818      	bt	0xcc	// if (T) goto loc_cc;
  9e:	5d1e      	addi	r0, r5, 8	// regs: r0=(r5 + 0x8)
  a0:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0xa0>, r1=<clobbered>
  a4:	3286      	movi	r2, 134	// regs: r2=0x86
  a6:	4241      	lsli	r2, r2, 1	// regs: r2=0x10c
  a8:	3100      	movi	r1, 0	// regs: r1=0x0
  aa:	e40512eb 	subi	r0, r5, 748	// regs: r0=(r5 - 0x2ec)
  ae:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0xae>, r1=<clobbered>
loc_b2:
  b2:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0xb2>, r1=<clobbered>
  b6:	dc042207 	st.w	r0, (r4, 0x81c)	// *(r4 + 0x81c) = <ret os_jiffies@0xb2>
  ba:	dc242208 	st.w	r1, (r4, 0x820)	// *(r4 + 0x820) = <clobbered>
  be:	1416      	addi	r14, r14, 88	// regs: r14=(sp + 0x58)
  c0:	1498      	pop	r4-r11, r15
loc_c2:
  c2:	d80420dc 	ld.w	r0, (r4, 0x370)	// regs: r0=*(0x370)
  c6:	07c9      	br	0x58	// goto loc_58;
loc_c8:
  c8:	3300      	movi	r3, 0	// regs: r3=0x0
  ca:	07d9      	br	0x7c	// goto loc_7c;
loc_cc:
  cc:	321c      	movi	r2, 28	// regs: r2=0x1c
  ce:	3100      	movi	r1, 0	// regs: r1=0x0
  d0:	e40501c3 	addi	r0, r5, 452	// regs: r0=(r5 + 0x1c4)
  d4:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0xd4>, r1=<clobbered>
  d8:	e40501df 	addi	r0, r5, 480	// regs: r0=(r5 + 0x1e0)
  dc:	3214      	movi	r2, 20	// regs: r2=0x14
  de:	3100      	movi	r1, 0	// regs: r1=0x0
  e0:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0xe0>, r1=<clobbered>
  e4:	95a0      	ld.w	r5, (r5, 0x0)	// regs: r5=*(r5)
  e6:	07da      	br	0x9a	// goto loc_9a;
loc_e8:
  e8:	3f02      	cmphsi	r7, 3
  ea:	6d5f      	mov	r5, r7	// regs: r5=<arg0>
  ec:	0c02      	bf	0xf0	// if (r7 < 0x3) goto loc_f0;
  ee:	3502      	movi	r5, 2	// regs: r5=0x2
loc_f0:
  f0:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  f4:	e4432002 	andi	r2, r3, 2	// regs: r2=(*(0x9e2) & 0x2)
  f8:	7554      	zextb	r5, r5	// regs: r5=zext8(r5)
  fa:	e90200d7 	bez	r2, 0x2a8	// if (r2 == 0x0) goto loc_2a8;
  fe:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x9e2) & 0x8)
 102:	e9230004 	bnez	r3, 0x10a	// if (r3 != 0x0) goto loc_10a;
 106:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0x106>, r1=<clobbered>
loc_10a:
 10a:	d80409e2 	ld.b	r0, (r4, 0x9e2)	// regs: r0=*(0x9e2)
 10e:	e4002004 	andi	r0, r0, 4	// regs: r0=(*(0x9e2) & 0x4)
 112:	e9200004 	bnez	r0, 0x11a	// if (r0 != 0x0) goto loc_11a;
 116:	e0000000 	bsr	0x0	// <disable_print>; regs: r0=<ret disable_print@0x116>, r1=<clobbered>
loc_11a:
 11a:	d86421d1 	ld.w	r3, (r4, 0x744)	// regs: r3=*(0x744)
 11e:	dc6421b8 	st.w	r3, (r4, 0x6e0)	// *(0x6e0) = *(0x744)
 122:	d86421d6 	ld.w	r3, (r4, 0x758)	// regs: r3=*(0x758)
 126:	dc6421b9 	st.w	r3, (r4, 0x6e4)	// *(0x6e4) = *(0x758)
 12a:	d86421db 	ld.w	r3, (r4, 0x76c)	// regs: r3=*(0x76c)
 12e:	d84421e4 	ld.w	r2, (r4, 0x790)	// regs: r2=*(0x790)
 132:	dc6421bc 	st.w	r3, (r4, 0x6f0)	// *(0x6f0) = *(0x76c)
 136:	d86421e2 	ld.w	r3, (r4, 0x788)	// regs: r3=*(0x788)
 13a:	60c8      	addu	r3, r2	// regs: r3=(*(0x788) + *(0x790))
 13c:	0301      	lrw	r0, 0x0	// regs: r0=0x0
 13e:	03e0      	lrw	r7, 0x0	// regs: r7=0x0
 140:	dc6421bd 	st.w	r3, (r4, 0x6f4)	// *(0x6f4) = (*(0x788) + *(0x790))
 144:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x144>, r1=<clobbered>
 148:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
 14c:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x9e2) & 0x8)
 150:	3b40      	cmpnei	r3, 0
 152:	d804219f 	ld.w	r0, (r4, 0x67c)	// regs: r0=*(0x67c)
 156:	d90420ce 	ld.w	r8, (r4, 0x338)	// regs: r8=*(0x338)
 15a:	c4885768 	zext	r8, r8, 27, 4	// regs: r8=zext(*(0x338))
 15e:	0367      	lrw	r3, 0x0	// regs: r3=0x0
 160:	c4e30c20 	incf	r7, r3, 0
 164:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x164>, r1=<clobbered>
 168:	d9a421b8 	ld.w	r13, (r4, 0x6e0)	// regs: r13=*(0x6e0)
 16c:	d92421c0 	ld.w	r9, (r4, 0x700)	// regs: r9=*(0x700)
 170:	d944219e 	ld.w	r10, (r4, 0x678)	// regs: r10=*(0x678)
 174:	d84421b9 	ld.w	r2, (r4, 0x6e4)	// regs: r2=*(0x6e4)
 178:	e90d0142 	bez	r13, 0x3fc	// if (r13 == 0x0) goto loc_3fc;
 17c:	ea0c0064 	movi	r12, 100	// regs: r12=0x64
 180:	7f08      	mult	r12, r2	// regs: r12=(0x64 * *(0x6e4))
 182:	c5ac804c 	divs	r12, r12, r13	// regs: r12=((0x64 * *(0x6e4)) / *(0x6e0))
loc_186:
 186:	d86421ba 	ld.w	r3, (r4, 0x6e8)	// regs: r3=*(r4 + 0x6e8)
 18a:	b866      	st.w	r3, (r14, 0x18)	// stack_p18 = *(r4 + 0x6e8)
 18c:	dd8e2005 	st.w	r12, (r14, 0x14)	// stack_p14 = r12
 190:	b844      	st.w	r2, (r14, 0x10)	// stack_p10 = r2
 192:	ddae2003 	st.w	r13, (r14, 0xc)	// stack_pc = r13
 196:	b801      	st.w	r0, (r14, 0x4)	// stack_p4 = r0
 198:	b822      	st.w	r1, (r14, 0x8)	// stack_p8 = r1
 19a:	6ce7      	mov	r3, r9	// regs: r3=r9
 19c:	6ca3      	mov	r2, r8	// regs: r2=r8
 19e:	6c5f      	mov	r1, r7	// regs: r1=r7
 1a0:	0317      	lrw	r0, 0x0	// regs: r0=0x0
 1a2:	dd4e2000 	st.w	r10, (r14, 0x0)	// stack_0 = r10
 1a6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1a6>, r1=<clobbered>
 1aa:	d86421bf 	ld.w	r3, (r4, 0x6fc)	// regs: r3=*(r4 + 0x6fc)
 1ae:	b862      	st.w	r3, (r14, 0x8)	// stack_p8 = *(r4 + 0x6fc)
 1b0:	d86421c1 	ld.w	r3, (r4, 0x704)	// regs: r3=*(r4 + 0x704)
 1b4:	d82421bc 	ld.w	r1, (r4, 0x6f0)	// regs: r1=*(r4 + 0x6f0)
 1b8:	d84421e4 	ld.w	r2, (r4, 0x790)	// regs: r2=*(r4 + 0x790)
 1bc:	b861      	st.w	r3, (r14, 0x4)	// stack_p4 = *(r4 + 0x704)
 1be:	d86421be 	ld.w	r3, (r4, 0x6f8)	// regs: r3=*(r4 + 0x6f8)
 1c2:	b860      	st.w	r3, (r14, 0x0)	// stack_0 = *(r4 + 0x6f8)
 1c4:	5949      	subu	r2, r1, r2	// regs: r2=(*(r4 + 0x6f0) - *(r4 + 0x790))
 1c6:	d86421bd 	ld.w	r3, (r4, 0x6f4)	// regs: r3=*(r4 + 0x6f4)
 1ca:	131f      	lrw	r0, 0x0	// regs: r0=0x0
 1cc:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1cc>, r1=<clobbered>
 1d0:	d8640892 	ld.b	r3, (r4, 0x892)	// regs: r3=*(r4 + 0x892)
 1d4:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r4 + 0x892) & 0x1)
 1d8:	e9030059 	bez	r3, 0x28a	// if (r3 == 0x0) goto loc_28a;
 1dc:	d80408c4 	ld.b	r0, (r4, 0x8c4)	// regs: r0=*(r4 + 0x8c4)
 1e0:	b800      	st.w	r0, (r14, 0x0)	// stack_0 = *(r4 + 0x8c4)
 1e2:	d80408c5 	ld.b	r0, (r4, 0x8c5)	// regs: r0=*(r4 + 0x8c5)
 1e6:	d9a448be 	ld.bs	r13, (r4, 0x8be)	// regs: r13=*(r4 + 0x8be)
 1ea:	d8e4489a 	ld.bs	r7, (r4, 0x89a)	// regs: r7=*(r4 + 0x89a)
 1ee:	b801      	st.w	r0, (r14, 0x4)	// stack_p4 = *(r4 + 0x8c5)
 1f0:	d80408c6 	ld.b	r0, (r4, 0x8c6)	// regs: r0=*(r4 + 0x8c6)
 1f4:	675d      	cmplt	r7, r13
 1f6:	b802      	st.w	r0, (r14, 0x8)	// stack_p8 = *(r4 + 0x8c6)
 1f8:	d80408c8 	ld.b	r0, (r4, 0x8c8)	// regs: r0=*(r4 + 0x8c8)
 1fc:	ea8b0073 	lrw	r11, 0x0	// regs: r11=0x0
 200:	ea8c0073 	lrw	r12, 0x0	// regs: r12=0x0
 204:	c58b0c40 	inct	r12, r11, 0
 208:	d90408c7 	ld.b	r8, (r4, 0x8c7)	// regs: r8=*(r4 + 0x8c7)
 20c:	d9241459 	ld.h	r9, (r4, 0x8b2)	// regs: r9=*(r4 + 0x8b2)
 210:	d94448c9 	ld.bs	r10, (r4, 0x8c9)	// regs: r10=*(r4 + 0x8c9)
 214:	e400203f 	andi	r0, r0, 63	// regs: r0=(*(r4 + 0x8c8) & 0x3f)
 218:	d824489b 	ld.bs	r1, (r4, 0x89b)	// regs: r1=*(r4 + 0x89b)
 21c:	d84408c2 	ld.b	r2, (r4, 0x8c2)	// regs: r2=*(r4 + 0x8c2)
 220:	d86408c3 	ld.b	r3, (r4, 0x8c3)	// regs: r3=*(r4 + 0x8c3)
 224:	dd8e2009 	st.w	r12, (r14, 0x24)	// stack_p24 = 0x0
 228:	ddae2007 	st.w	r13, (r14, 0x1c)	// stack_p1c = *(r4 + 0x8be)
 22c:	b806      	st.w	r0, (r14, 0x18)	// stack_p18 = (*(r4 + 0x8c8) & 0x3f)
 22e:	b8e8      	st.w	r7, (r14, 0x20)	// stack_p20 = *(r4 + 0x89a)
 230:	dd4e2005 	st.w	r10, (r14, 0x14)	// stack_p14 = *(r4 + 0x8c9)
 234:	dd2e2004 	st.w	r9, (r14, 0x10)	// stack_p10 = *(r4 + 0x8b2)
 238:	dd0e2003 	st.w	r8, (r14, 0xc)	// stack_pc = *(r4 + 0x8c7)
 23c:	1305      	lrw	r0, 0x0	// regs: r0=0x0
 23e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x23e>, r1=<clobbered>
 242:	d80448b8 	ld.bs	r0, (r4, 0x8b8)	// regs: r0=*(r4 + 0x8b8)
 246:	b802      	st.w	r0, (r14, 0x8)	// stack_p8 = *(r4 + 0x8b8)
 248:	d80448ae 	ld.bs	r0, (r4, 0x8ae)	// regs: r0=*(r4 + 0x8ae)
 24c:	b801      	st.w	r0, (r14, 0x4)	// stack_p4 = *(r4 + 0x8ae)
 24e:	d80448b7 	ld.bs	r0, (r4, 0x8b7)	// regs: r0=*(r4 + 0x8b7)
 252:	d86448ad 	ld.bs	r3, (r4, 0x8ad)	// regs: r3=*(r4 + 0x8ad)
 256:	d84448b6 	ld.bs	r2, (r4, 0x8b6)	// regs: r2=*(r4 + 0x8b6)
 25a:	d82448ac 	ld.bs	r1, (r4, 0x8ac)	// regs: r1=*(r4 + 0x8ac)
 25e:	b800      	st.w	r0, (r14, 0x0)	// stack_0 = *(r4 + 0x8b7)
 260:	121d      	lrw	r0, 0x0	// regs: r0=0x0
 262:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x262>, r1=<clobbered>
 266:	d80448a6 	ld.bs	r0, (r4, 0x8a6)	// regs: r0=*(r4 + 0x8a6)
 26a:	b802      	st.w	r0, (r14, 0x8)	// stack_p8 = *(r4 + 0x8a6)
 26c:	d804489e 	ld.bs	r0, (r4, 0x89e)	// regs: r0=*(r4 + 0x89e)
 270:	b801      	st.w	r0, (r14, 0x4)	// stack_p4 = *(r4 + 0x89e)
 272:	d80448a5 	ld.bs	r0, (r4, 0x8a5)	// regs: r0=*(r4 + 0x8a5)
 276:	b800      	st.w	r0, (r14, 0x0)	// stack_0 = *(r4 + 0x8a5)
 278:	d864489d 	ld.bs	r3, (r4, 0x89d)	// regs: r3=*(r4 + 0x89d)
 27c:	d84448a4 	ld.bs	r2, (r4, 0x8a4)	// regs: r2=*(r4 + 0x8a4)
 280:	d824489c 	ld.bs	r1, (r4, 0x89c)	// regs: r1=*(r4 + 0x89c)
 284:	1215      	lrw	r0, 0x0	// regs: r0=0x0
 286:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x286>, r1=<clobbered>
loc_28a:
 28a:	3001      	movi	r0, 1	// regs: r0=0x1
 28c:	e0000000 	bsr	0x0	// <disable_print>; regs: r0=<ret disable_print@0x28c>, r1=<clobbered>
 290:	d8e409e2 	ld.b	r7, (r4, 0x9e2)	// regs: r7=*(r4 + 0x9e2)
 294:	e4e72008 	andi	r7, r7, 8	// regs: r7=(*(r4 + 0x9e2) & 0x8)
 298:	e9270008 	bnez	r7, 0x2a8	// if (r7 != 0x0) goto loc_2a8;
 29c:	300a      	movi	r0, 10	// regs: r0=0xa
 29e:	e0000000 	bsr	0x0	// <os_sleep_ms>; regs: r0=<ret os_sleep_ms@0x29e>, r1=<clobbered>
 2a2:	6c1f      	mov	r0, r7	// regs: r0=(*(r4 + 0x9e2) & 0x8)
 2a4:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x2a4>, r1=<clobbered>
loc_2a8:
 2a8:	120d      	lrw	r0, 0x0	// regs: r0=0x0
 2aa:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2aa>, r1=<clobbered>
 2ae:	1202      	lrw	r0, 0x0	// regs: r0=0x0
 2b0:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2b0>, r1=<clobbered>
 2b4:	d804202f 	ld.w	r0, (r4, 0xbc)	// regs: r0=*(r4 + 0xbc)
 2b8:	b804      	st.w	r0, (r14, 0x10)	// stack_p10 = *(r4 + 0xbc)
 2ba:	d8041198 	ld.h	r0, (r4, 0x330)	// regs: r0=*(r4 + 0x330)
 2be:	b803      	st.w	r0, (r14, 0xc)	// stack_pc = *(r4 + 0x330)
 2c0:	d8040307 	ld.b	r0, (r4, 0x307)	// regs: r0=*(r4 + 0x307)
 2c4:	b802      	st.w	r0, (r14, 0x8)	// stack_p8 = *(r4 + 0x307)
 2c6:	d8040306 	ld.b	r0, (r4, 0x306)	// regs: r0=*(r4 + 0x306)
 2ca:	b801      	st.w	r0, (r14, 0x4)	// stack_p4 = *(r4 + 0x306)
 2cc:	d8040305 	ld.b	r0, (r4, 0x305)	// regs: r0=*(r4 + 0x305)
 2d0:	d8640304 	ld.b	r3, (r4, 0x304)	// regs: r3=*(r4 + 0x304)
 2d4:	b800      	st.w	r0, (r14, 0x0)	// stack_0 = *(r4 + 0x305)
 2d6:	d8440303 	ld.b	r2, (r4, 0x303)	// regs: r2=*(r4 + 0x303)
 2da:	d8240302 	ld.b	r1, (r4, 0x302)	// regs: r1=*(r4 + 0x302)
 2de:	1201      	lrw	r0, 0x0	// regs: r0=0x0
 2e0:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2e0>, r1=<clobbered>
 2e4:	d86420ee 	ld.w	r3, (r4, 0x3b8)	// regs: r3=*(r4 + 0x3b8)
 2e8:	e4632080 	andi	r3, r3, 128	// regs: r3=(*(r4 + 0x3b8) & 0x80)
 2ec:	e903001d 	bez	r3, 0x326	// if (r3 == 0x0) goto loc_326;
 2f0:	d8041506 	ld.h	r0, (r4, 0xa0c)	// regs: r0=*(r4 + 0xa0c)
 2f4:	b805      	st.w	r0, (r14, 0x14)	// stack_p14 = *(r4 + 0xa0c)
 2f6:	d8041505 	ld.h	r0, (r4, 0xa0a)	// regs: r0=*(r4 + 0xa0a)
 2fa:	b804      	st.w	r0, (r14, 0x10)	// stack_p10 = *(r4 + 0xa0a)
 2fc:	d80422e9 	ld.w	r0, (r4, 0xba4)	// regs: r0=*(r4 + 0xba4)
 300:	b803      	st.w	r0, (r14, 0xc)	// stack_pc = *(r4 + 0xba4)
 302:	d804052b 	ld.b	r0, (r4, 0x52b)	// regs: r0=*(r4 + 0x52b)
 306:	b802      	st.w	r0, (r14, 0x8)	// stack_p8 = *(r4 + 0x52b)
 308:	d804052a 	ld.b	r0, (r4, 0x52a)	// regs: r0=*(r4 + 0x52a)
 30c:	b801      	st.w	r0, (r14, 0x4)	// stack_p4 = *(r4 + 0x52a)
 30e:	d8040529 	ld.b	r0, (r4, 0x529)	// regs: r0=*(r4 + 0x529)
 312:	b800      	st.w	r0, (r14, 0x0)	// stack_0 = *(r4 + 0x529)
 314:	d8640528 	ld.b	r3, (r4, 0x528)	// regs: r3=*(r4 + 0x528)
 318:	d8440527 	ld.b	r2, (r4, 0x527)	// regs: r2=*(r4 + 0x527)
 31c:	d8240526 	ld.b	r1, (r4, 0x526)	// regs: r1=*(r4 + 0x526)
 320:	1111      	lrw	r0, 0x0	// regs: r0=0x0
 322:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x322>, r1=<clobbered>
loc_326:
 326:	d84420ce 	ld.w	r2, (r4, 0x338)	// regs: r2=*(r4 + 0x338)
 32a:	33fa      	movi	r3, 250	// regs: r3=0xfa
 32c:	c4825762 	zext	r2, r2, 27, 4	// regs: r2=zext(*(r4 + 0x338))
 330:	4362      	lsli	r3, r3, 2	// regs: r3=0x3e8
 332:	c4628041 	divs	r1, r2, r3	// regs: r1=(zext(*(r4 + 0x338)) / 0x3e8)
 336:	d804034a 	ld.b	r0, (r4, 0x34a)	// regs: r0=*(r4 + 0x34a)
 33a:	7cc4      	mult	r3, r1	// regs: r3=(0x3e8 * (zext(*(r4 + 0x338)) / 0x3e8))
 33c:	e4002001 	andi	r0, r0, 1	// regs: r0=(*(r4 + 0x34a) & 0x1)
 340:	608e      	subu	r2, r3	// regs: r2=(zext(*(r4 + 0x338)) - (0x3e8 * (zext(*(r4 + 0x338)) / 0x3e8)))
 342:	3364      	movi	r3, 100	// regs: r3=0x64
 344:	c4628042 	divs	r2, r2, r3	// regs: r2=((zext(*(r4 + 0x338)) - (0x3e8 * (zext(*(r4 + 0x338)) / 0x3e8))) / 0x64)
 348:	3301      	movi	r3, 1	// regs: r3=0x1
 34a:	e9200005 	bnez	r0, 0x354	// if (r0 != 0x0) goto loc_354;
 34e:	d8040308 	ld.b	r0, (r4, 0x308)	// regs: r0=*(r4 + 0x308)
 352:	70c0      	lsl	r3, r0
loc_354:
 354:	d80443e0 	ld.bs	r0, (r4, 0x3e0)	// regs: r0=*(r4 + 0x3e0)
 358:	d984431e 	ld.bs	r12, (r4, 0x31e)	// regs: r12=*(r4 + 0x31e)
 35c:	6300      	addu	r12, r0	// regs: r12=(*(r4 + 0x31e) + *(r4 + 0x3e0))
 35e:	d80453f4 	ld.hs	r0, (r4, 0x7e8)	// regs: r0=*(r4 + 0x7e8)
 362:	e9000007 	bez	r0, 0x370	// if (r0 == 0x0) goto loc_370;
 366:	4006      	lsli	r0, r0, 6	// regs: r0=(*(r4 + 0x7e8) << 0x6)
 368:	d9a421f8 	ld.w	r13, (r4, 0x7e0)	// regs: r13=*(r4 + 0x7e0)
 36c:	c40d8040 	divs	r0, r13, r0	// regs: r0=(*(r4 + 0x7e0) / (*(r4 + 0x7e8) << 0x6))
loc_370:
 370:	b801      	st.w	r0, (r14, 0x4)	// stack_p4 = r0
 372:	dd8e2000 	st.w	r12, (r14, 0x0)	// stack_0 = (*(r4 + 0x31e) + *(r4 + 0x3e0))
 376:	101d      	lrw	r0, 0x0	// regs: r0=0x0
 378:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x378>, r1=<clobbered>
 37c:	105c      	lrw	r2, 0x0	// regs: r2=0x0
 37e:	300c      	movi	r0, 12	// regs: r0=0xc
 380:	8260      	ld.b	r3, (r2, 0x0)	// regs: r3=*(0x0)
 382:	c4038021 	divu	r1, r3, r0	// regs: r1=(*(0x0) / 0xc)
 386:	7c40      	mult	r1, r0	// regs: r1=((*(0x0) / 0xc) * 0xc)
 388:	60c6      	subu	r3, r1	// regs: r3=(*(0x0) - ((*(0x0) / 0xc) * 0xc))
 38a:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(0x0) - ((*(0x0) / 0xc) * 0xc)))
 38c:	ea8c0019 	lrw	r12, 0x0	// regs: r12=0x0
 390:	1019      	lrw	r0, 0x0	// regs: r0=0x0
 392:	103a      	lrw	r1, 0x0	// regs: r1=0x0
 394:	e9230036 	bnez	r3, 0x400	// if (r3 != 0x0) goto loc_400;
 398:	a260      	st.b	r3, (r2, 0x0)	// *(0x0) = zext8((*(0x0) - ((*(0x0) / 0xc) * 0xc)))
 39a:	d864431e 	ld.bs	r3, (r4, 0x31e)	// regs: r3=*(r4 + 0x31e)
 39e:	dc6c2000 	st.w	r3, (r12, 0x0)	// *(0x0) = *(r4 + 0x31e)
 3a2:	b060      	st.w	r3, (r0, 0x0)	// *(0x0) = *(r4 + 0x31e)
loc_3a4:
 3a4:	b160      	st.w	r3, (r1, 0x0)	// *(0x0) = *(r4 + 0x31e)
 3a6:	043c      	br	0x41e	// goto loc_41e;
 3a8:	00000000 	.long	0x00000000	// <ah_lmac>
 3ac:	00000000 	.long	0x00000000	// <ah_lmac+0xa00>
 3b0:	00000000 	.long	0x00000000	// <ah_lmac+0x9f8>
 3b4:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x46>
 3b8:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1>
 3bc:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x3>
 3c0:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x56>
 3c4:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0xf4>
 3c8:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0xb>
 3cc:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x6>
 3d0:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x17c>
 3d4:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x1e0>
 3d8:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x20d>
 3dc:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x23a>
 3e0:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x252>
 3e4:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x298>
 3e8:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x2ef>
 3ec:	00000000 	.long	0x00000000	// <.bss.statics_cnt.13476>
 3f0:	00000000 	.long	0x00000000	// <.bss.bgr_acc.13479>
 3f4:	00000000 	.long	0x00000000	// <.bss.bgr_max.13478>
 3f8:	00000000 	.long	0x00000000	// <.bss.bgr_min.13477>
loc_3fc:
 3fc:	6f37      	mov	r12, r13	// regs: r12=r13
 3fe:	06c4      	br	0x186	// goto loc_186;
loc_400:
 400:	d9ac2000 	ld.w	r13, (r12, 0x0)	// regs: r13=*(0x0)
 404:	d864431e 	ld.bs	r3, (r4, 0x31e)	// regs: r3=*(r4 + 0x31e)
 408:	634c      	addu	r13, r3	// regs: r13=(*(0x0) + *(r4 + 0x31e))
 40a:	ddac2000 	st.w	r13, (r12, 0x0)	// *(0x0) = (*(0x0) + *(r4 + 0x31e))
 40e:	d9802000 	ld.w	r12, (r0, 0x0)	// regs: r12=*(0x0)
 412:	64f1      	cmplt	r12, r3
 414:	0c02      	bf	0x418	// if (!T) goto loc_418;
 416:	b060      	st.w	r3, (r0, 0x0)	// *(0x0) = *(r4 + 0x31e)
loc_418:
 418:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(0x0)
 41a:	640d      	cmplt	r3, r0
 41c:	0bc4      	bt	0x3a4	// if (T) goto loc_3a4;
loc_41e:
 41e:	8260      	ld.b	r3, (r2, 0x0)	// regs: r3=*(0x0)
 420:	2300      	addi	r3, 1	// regs: r3=(*(0x0) + 0x1)
 422:	a260      	st.b	r3, (r2, 0x0)	// *(0x0) = (*(0x0) + 0x1)
 424:	d8640378 	ld.b	r3, (r4, 0x378)	// regs: r3=*(r4 + 0x378)
 428:	2b00      	subi	r3, 1	// regs: r3=(*(r4 + 0x378) - 0x1)
 42a:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(r4 + 0x378) - 0x1))
 42c:	3b0f      	cmphsi	r3, 16
 42e:	082b      	bt	0x484	// if (r3 >= 0x10) goto loc_484;
 430:	ea80016f 	lrw	r0, 0x0	// regs: r0=0x0
 434:	3700      	movi	r7, 0	// regs: r7=0x0
 436:	ea0800fa 	movi	r8, 250	// regs: r8=0xfa
 43a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x43a>, r1=<clobbered>
 43e:	6e5f      	mov	r9, r7	// regs: r9=0x0
 440:	c4484828 	lsli	r8, r8, 2	// regs: r8=0x3e8
 444:	ea0a0064 	movi	r10, 100	// regs: r10=0x64
 448:	ea8b016a 	lrw	r11, 0x0	// regs: r11=0x0
loc_44c:
 44c:	d8640378 	ld.b	r3, (r4, 0x378)	// regs: r3=*(r4 + 0x378)
 450:	64e5      	cmplt	r9, r3
 452:	2717      	addi	r7, 24	// regs: r7=(r7 + 0x18)
 454:	e860030e 	bt	0xa70	// if (T) goto loc_a70;
 458:	ea800167 	lrw	r0, 0x0	// regs: r0=0x0
 45c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x45c>, r1=<clobbered>
 460:	3700      	movi	r7, 0	// regs: r7=0x0
 462:	ea800166 	lrw	r0, 0x0	// regs: r0=0x0
 466:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x466>, r1=<clobbered>
 46a:	6e1f      	mov	r8, r7	// regs: r8=0x0
 46c:	ea890164 	lrw	r9, 0x0	// regs: r9=0x0
loc_470:
 470:	d8640378 	ld.b	r3, (r4, 0x378)	// regs: r3=*(r4 + 0x378)
 474:	64e1      	cmplt	r8, r3
 476:	2717      	addi	r7, 24	// regs: r7=(r7 + 0x18)
 478:	e860030e 	bt	0xa94	// if (T) goto loc_a94;
 47c:	ea80015e 	lrw	r0, 0x0	// regs: r0=0x0
 480:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x480>, r1=<clobbered>
loc_484:
 484:	3d41      	cmpnei	r5, 1
 486:	0853      	bt	0x52c	// if (r5 != 0x1) goto loc_52c;
 488:	d86453f4 	ld.hs	r3, (r4, 0x7e8)	// regs: r3=*(r4 + 0x7e8)
 48c:	e9030312 	bez	r3, 0xab0	// if (r3 == 0x0) goto loc_ab0;
 490:	4326      	lsli	r1, r3, 6	// regs: r1=(*(r4 + 0x7e8) << 0x6)
 492:	d84421f8 	ld.w	r2, (r4, 0x7e0)	// regs: r2=*(r4 + 0x7e0)
 496:	c4228041 	divs	r1, r2, r1	// regs: r1=(*(r4 + 0x7e0) / (*(r4 + 0x7e8) << 0x6))
loc_49a:
 49a:	d8445196 	ld.hs	r2, (r4, 0x32c)	// regs: r2=*(r4 + 0x32c)
 49e:	e963030c 	blsz	r3, 0xab6
 4a2:	d80453f3 	ld.hs	r0, (r4, 0x7e6)	// regs: r0=*(r4 + 0x7e6)
 4a6:	c4608043 	divs	r3, r0, r3	// regs: r3=(*(r4 + 0x7e6) / *(r4 + 0x7e8))
loc_4aa:
 4aa:	d8040338 	ld.b	r0, (r4, 0x338)	// regs: r0=*(r4 + 0x338)
 4ae:	e4002001 	andi	r0, r0, 1	// regs: r0=(*(r4 + 0x338) & 0x1)
 4b2:	3840      	cmpnei	r0, 0
 4b4:	ea8c0153 	lrw	r12, 0x0	// regs: r12=0x0
 4b8:	ea800153 	lrw	r0, 0x0	// regs: r0=0x0
 4bc:	c40c0c20 	incf	r0, r12, 0
 4c0:	d98421f0 	ld.w	r12, (r4, 0x7c0)	// regs: r12=*(r4 + 0x7c0)
 4c4:	dd8e200c 	st.w	r12, (r14, 0x30)	// stack_p30 = *(r4 + 0x7c0)
 4c8:	d98421ef 	ld.w	r12, (r4, 0x7bc)	// regs: r12=*(r4 + 0x7bc)
 4cc:	dd8e200b 	st.w	r12, (r14, 0x2c)	// stack_p2c = *(r4 + 0x7bc)
 4d0:	d98421ee 	ld.w	r12, (r4, 0x7b8)	// regs: r12=*(r4 + 0x7b8)
 4d4:	dd8e200a 	st.w	r12, (r14, 0x28)	// stack_p28 = *(r4 + 0x7b8)
 4d8:	d98421ea 	ld.w	r12, (r4, 0x7a8)	// regs: r12=*(r4 + 0x7a8)
 4dc:	dd8e2009 	st.w	r12, (r14, 0x24)	// stack_p24 = *(r4 + 0x7a8)
 4e0:	d98421e9 	ld.w	r12, (r4, 0x7a4)	// regs: r12=*(r4 + 0x7a4)
 4e4:	dd8e2008 	st.w	r12, (r14, 0x20)	// stack_p20 = *(r4 + 0x7a4)
 4e8:	d98421e8 	ld.w	r12, (r4, 0x7a0)	// regs: r12=*(r4 + 0x7a0)
 4ec:	d9a453f2 	ld.hs	r13, (r4, 0x7e4)	// regs: r13=*(r4 + 0x7e4)
 4f0:	d8e45389 	ld.hs	r7, (r4, 0x712)	// regs: r7=*(r4 + 0x712)
 4f4:	d904538a 	ld.hs	r8, (r4, 0x714)	// regs: r8=*(r4 + 0x714)
 4f8:	d924541c 	ld.hs	r9, (r4, 0x838)	// regs: r9=*(r4 + 0x838)
 4fc:	d944541d 	ld.hs	r10, (r4, 0x83a)	// regs: r10=*(r4 + 0x83a)
 500:	dd8e2007 	st.w	r12, (r14, 0x1c)	// stack_p1c = *(r4 + 0x7a0)
 504:	d984036c 	ld.b	r12, (r4, 0x36c)	// regs: r12=*(r4 + 0x36c)
 508:	e58c201f 	andi	r12, r12, 31	// regs: r12=(*(r4 + 0x36c) & 0x1f)
 50c:	b805      	st.w	r0, (r14, 0x14)	// stack_p14 = 0x0
 50e:	dd4e2004 	st.w	r10, (r14, 0x10)	// stack_p10 = *(r4 + 0x83a)
 512:	dd2e2003 	st.w	r9, (r14, 0xc)	// stack_pc = *(r4 + 0x838)
 516:	dd0e2002 	st.w	r8, (r14, 0x8)	// stack_p8 = *(r4 + 0x714)
 51a:	b8e1      	st.w	r7, (r14, 0x4)	// stack_p4 = *(r4 + 0x712)
 51c:	ddae2000 	st.w	r13, (r14, 0x0)	// stack_0 = *(r4 + 0x7e4)
 520:	dd8e2006 	st.w	r12, (r14, 0x18)	// stack_p18 = (*(r4 + 0x36c) & 0x1f)
 524:	ea800139 	lrw	r0, 0x0	// regs: r0=0x0
 528:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x528>, r1=<clobbered>
loc_52c:
 52c:	3001      	movi	r0, 1	// regs: r0=0x1
 52e:	e0000000 	bsr	0x0	// <skbpool_freesize>; regs: r0=<ret skbpool_freesize@0x52e>, r1=<clobbered>
 532:	6dc3      	mov	r7, r0	// regs: r7=<ret skbpool_freesize@0x52e>
 534:	e0000000 	bsr	0x0	// <lmac_txq_count>; regs: r0=<ret lmac_txq_count@0x534>, r1=<clobbered>
 538:	6e03      	mov	r8, r0	// regs: r8=<ret lmac_txq_count@0x534>
 53a:	e0000000 	bsr	0x0	// <lmac_txsq_count>; regs: r0=<ret lmac_txsq_count@0x53a>, r1=<clobbered>
 53e:	6cc3      	mov	r3, r0	// regs: r3=<ret lmac_txsq_count@0x53a>
 540:	6ca3      	mov	r2, r8	// regs: r2=<ret lmac_txq_count@0x534>
 542:	4f2b      	lsri	r1, r7, 11	// regs: r1=(<ret skbpool_freesize@0x52e> >> 0xb)
 544:	ea800132 	lrw	r0, 0x0	// regs: r0=0x0
 548:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x548>, r1=<clobbered>
 54c:	3d41      	cmpnei	r5, 1
 54e:	084b      	bt	0x5e4	// if (r5 != 0x1) goto loc_5e4;
 550:	3000      	movi	r0, 0	// regs: r0=0x0
 552:	e0000000 	bsr	0x0	// <lmac_acq_count>; regs: r0=<ret lmac_acq_count@0x552>, r1=<clobbered>
 556:	6dc3      	mov	r7, r0	// regs: r7=<ret lmac_acq_count@0x552>
 558:	6c17      	mov	r0, r5	// regs: r0=r5
 55a:	e0000000 	bsr	0x0	// <lmac_acq_count>; regs: r0=<ret lmac_acq_count@0x55a>, r1=<clobbered>
 55e:	6e03      	mov	r8, r0	// regs: r8=<ret lmac_acq_count@0x55a>
 560:	3002      	movi	r0, 2	// regs: r0=0x2
 562:	e0000000 	bsr	0x0	// <lmac_acq_count>; regs: r0=<ret lmac_acq_count@0x562>, r1=<clobbered>
 566:	6e43      	mov	r9, r0	// regs: r9=<ret lmac_acq_count@0x562>
 568:	3003      	movi	r0, 3	// regs: r0=0x3
 56a:	e0000000 	bsr	0x0	// <lmac_acq_count>; regs: r0=<ret lmac_acq_count@0x56a>, r1=<clobbered>
 56e:	6e83      	mov	r10, r0	// regs: r10=<ret lmac_acq_count@0x56a>
 570:	3000      	movi	r0, 0	// regs: r0=0x0
 572:	e0000000 	bsr	0x0	// <lmac_txagg_count>; regs: r0=<ret lmac_txagg_count@0x572>, r1=<clobbered>
 576:	6ec3      	mov	r11, r0	// regs: r11=<ret lmac_txagg_count@0x572>
 578:	6c17      	mov	r0, r5	// regs: r0=r5
 57a:	e0000000 	bsr	0x0	// <lmac_txagg_count>; regs: r0=<ret lmac_txagg_count@0x57a>, r1=<clobbered>
 57e:	b811      	st.w	r0, (r14, 0x44)	// stack_p44 = <ret lmac_txagg_count@0x57a>
 580:	3002      	movi	r0, 2	// regs: r0=0x2
 582:	e0000000 	bsr	0x0	// <lmac_txagg_count>; regs: r0=<ret lmac_txagg_count@0x582>, r1=<clobbered>
 586:	b810      	st.w	r0, (r14, 0x40)	// stack_p40 = <ret lmac_txagg_count@0x582>
 588:	3003      	movi	r0, 3	// regs: r0=0x3
 58a:	e0000000 	bsr	0x0	// <lmac_txagg_count>; regs: r0=<ret lmac_txagg_count@0x58a>, r1=<clobbered>
 58e:	b80f      	st.w	r0, (r14, 0x3c)	// stack_p3c = <ret lmac_txagg_count@0x58a>
 590:	e0000000 	bsr	0x0	// <lmac_statq_count>; regs: r0=<ret lmac_statq_count@0x590>, r1=<clobbered>
 594:	b80e      	st.w	r0, (r14, 0x38)	// stack_p38 = <ret lmac_statq_count@0x590>
 596:	e0000000 	bsr	0x0	// <lmac_rx_data_queue_count>; regs: r0=<ret lmac_rx_data_queue_count@0x596>, r1=<clobbered>
 59a:	b80d      	st.w	r0, (r14, 0x34)	// stack_p34 = <ret lmac_rx_data_queue_count@0x596>
 59c:	e0000000 	bsr	0x0	// <lmac_rx_iface_queue_count>; regs: r0=<ret lmac_rx_iface_queue_count@0x59c>, r1=<clobbered>
 5a0:	982f      	ld.w	r1, (r14, 0x3c)	// regs: r1=stack_p3c
 5a2:	9850      	ld.w	r2, (r14, 0x40)	// regs: r2=stack_p40
 5a4:	9871      	ld.w	r3, (r14, 0x44)	// regs: r3=stack_p44
 5a6:	d9ae200d 	ld.w	r13, (r14, 0x34)	// regs: r13=stack_p34
 5aa:	d98e200e 	ld.w	r12, (r14, 0x38)	// regs: r12=stack_p38
 5ae:	b807      	st.w	r0, (r14, 0x1c)	// stack_p1c = <ret lmac_rx_iface_queue_count@0x59c>
 5b0:	b824      	st.w	r1, (r14, 0x10)	// stack_p10 = stack_p3c
 5b2:	b843      	st.w	r2, (r14, 0xc)	// stack_pc = stack_p40
 5b4:	b862      	st.w	r3, (r14, 0x8)	// stack_p8 = stack_p44
 5b6:	6ca3      	mov	r2, r8	// regs: r2=<ret lmac_acq_count@0x55a>
 5b8:	6c5f      	mov	r1, r7	// regs: r1=<ret lmac_acq_count@0x552>
 5ba:	ea800116 	lrw	r0, 0x0	// regs: r0=0x0
 5be:	6ce7      	mov	r3, r9	// regs: r3=<ret lmac_acq_count@0x562>
 5c0:	ddae2006 	st.w	r13, (r14, 0x18)	// stack_p18 = stack_p34
 5c4:	dd8e2005 	st.w	r12, (r14, 0x14)	// stack_p14 = stack_p38
 5c8:	dd6e2001 	st.w	r11, (r14, 0x4)	// stack_p4 = <ret lmac_txagg_count@0x572>
 5cc:	dd4e2000 	st.w	r10, (r14, 0x0)	// stack_0 = <ret lmac_acq_count@0x56a>
 5d0:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x5d0>, r1=<clobbered>
 5d4:	d844553d 	ld.hs	r2, (r4, 0xa7a)	// regs: r2=*(r4 + 0xa7a)
 5d8:	d824553c 	ld.hs	r1, (r4, 0xa78)	// regs: r1=*(r4 + 0xa78)
 5dc:	ea80010e 	lrw	r0, 0x0	// regs: r0=0x0
 5e0:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x5e0>, r1=<clobbered>
loc_5e4:
 5e4:	d86421cf 	ld.w	r3, (r4, 0x73c)	// regs: r3=*(r4 + 0x73c)
 5e8:	b866      	st.w	r3, (r14, 0x18)	// stack_p18 = *(r4 + 0x73c)
 5ea:	d86421cd 	ld.w	r3, (r4, 0x734)	// regs: r3=*(r4 + 0x734)
 5ee:	b865      	st.w	r3, (r14, 0x14)	// stack_p14 = *(r4 + 0x734)
 5f0:	d86421ce 	ld.w	r3, (r4, 0x738)	// regs: r3=*(r4 + 0x738)
 5f4:	b864      	st.w	r3, (r14, 0x10)	// stack_p10 = *(r4 + 0x738)
 5f6:	d86421ca 	ld.w	r3, (r4, 0x728)	// regs: r3=*(r4 + 0x728)
 5fa:	b863      	st.w	r3, (r14, 0xc)	// stack_pc = *(r4 + 0x728)
 5fc:	d86421c9 	ld.w	r3, (r4, 0x724)	// regs: r3=*(r4 + 0x724)
 600:	b862      	st.w	r3, (r14, 0x8)	// stack_p8 = *(r4 + 0x724)
 602:	d86421c8 	ld.w	r3, (r4, 0x720)	// regs: r3=*(r4 + 0x720)
 606:	b861      	st.w	r3, (r14, 0x4)	// stack_p4 = *(r4 + 0x720)
 608:	d86421c7 	ld.w	r3, (r4, 0x71c)	// regs: r3=*(r4 + 0x71c)
 60c:	b860      	st.w	r3, (r14, 0x0)	// stack_0 = *(r4 + 0x71c)
 60e:	d82421c6 	ld.w	r1, (r4, 0x718)	// regs: r1=*(r4 + 0x718)
 612:	d86421cb 	ld.w	r3, (r4, 0x72c)	// regs: r3=*(r4 + 0x72c)
 616:	d84421cc 	ld.w	r2, (r4, 0x730)	// regs: r2=*(r4 + 0x730)
 61a:	ea800100 	lrw	r0, 0x0	// regs: r0=0x0
 61e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x61e>, r1=<clobbered>
 622:	d82421d1 	ld.w	r1, (r4, 0x744)	// regs: r1=*(r4 + 0x744)
 626:	e901024c 	bez	r1, 0xabe	// if (r1 == 0x0) goto loc_abe;
 62a:	3264      	movi	r2, 100	// regs: r2=0x64
 62c:	d86421d6 	ld.w	r3, (r4, 0x758)	// regs: r3=*(r4 + 0x758)
 630:	7cc8      	mult	r3, r2	// regs: r3=(*(r4 + 0x758) * 0x64)
 632:	c4238043 	divs	r3, r3, r1	// regs: r3=((*(r4 + 0x758) * 0x64) / *(r4 + 0x744))
 636:	d84421d9 	ld.w	r2, (r4, 0x764)	// regs: r2=*(r4 + 0x764)
 63a:	75cc      	zextb	r7, r3	// regs: r7=zext8(((*(r4 + 0x758) * 0x64) / *(r4 + 0x744)))
 63c:	dc64083d 	st.b	r3, (r4, 0x83d)	// *(r4 + 0x83d) = ((*(r4 + 0x758) * 0x64) / *(r4 + 0x744))
 640:	c4228042 	divs	r2, r2, r1	// regs: r2=(*(r4 + 0x764) / *(r4 + 0x744))
loc_644:
 644:	d8040338 	ld.b	r0, (r4, 0x338)	// regs: r0=*(r4 + 0x338)
 648:	e4002001 	andi	r0, r0, 1	// regs: r0=(*(r4 + 0x338) & 0x1)
 64c:	d86421d8 	ld.w	r3, (r4, 0x760)	// regs: r3=*(r4 + 0x760)
 650:	d98420dc 	ld.w	r12, (r4, 0x370)	// regs: r12=*(r4 + 0x370)
 654:	e9000239 	bez	r0, 0xac6	// if (r0 == 0x0) goto loc_ac6;
 658:	d8040840 	ld.b	r0, (r4, 0x840)	// regs: r0=*(r4 + 0x840)
loc_65c:
 65c:	d9a421d7 	ld.w	r13, (r4, 0x75c)	// regs: r13=*(r4 + 0x75c)
 660:	ddae2003 	st.w	r13, (r14, 0xc)	// stack_pc = *(r4 + 0x75c)
 664:	d9a421d6 	ld.w	r13, (r4, 0x758)	// regs: r13=*(r4 + 0x758)
 668:	b801      	st.w	r0, (r14, 0x4)	// stack_p4 = r0
 66a:	ddae2002 	st.w	r13, (r14, 0x8)	// stack_p8 = *(r4 + 0x758)
 66e:	dd8e2000 	st.w	r12, (r14, 0x0)	// stack_0 = *(r4 + 0x370)
 672:	0014      	lrw	r0, 0x0	// regs: r0=0x0
 674:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x674>, r1=<clobbered>
 678:	3d41      	cmpnei	r5, 1
 67a:	0841      	bt	0x6fc	// if (r5 != 0x1) goto loc_6fc;
 67c:	d864070f 	ld.b	r3, (r4, 0x70f)	// regs: r3=*(r4 + 0x70f)
 680:	5b42      	addi	r2, r3, 1	// regs: r2=(*(r4 + 0x70f) + 0x1)
 682:	d98421d0 	ld.w	r12, (r4, 0x740)	// regs: r12=*(r4 + 0x740)
 686:	e4422003 	andi	r2, r2, 3	// regs: r2=((*(r4 + 0x70f) + 0x1) & 0x3)
 68a:	d824483d 	ld.bs	r1, (r4, 0x83d)	// regs: r1=*(r4 + 0x83d)
 68e:	c4454022 	lsl	r2, r5, r2
 692:	4b64      	lsri	r3, r3, 4	// regs: r3=(*(r4 + 0x70f) >> 0x4)
 694:	e90c0006 	bez	r12, 0x6a0	// if (r12 == 0x0) goto loc_6a0;
 698:	d80421d1 	ld.w	r0, (r4, 0x744)	// regs: r0=*(r4 + 0x744)
 69c:	c580804c 	divs	r12, r0, r12	// regs: r12=(*(r4 + 0x744) / *(r4 + 0x740))
loc_6a0:
 6a0:	d80421d2 	ld.w	r0, (r4, 0x748)	// regs: r0=*(r4 + 0x748)
 6a4:	d9a421eb 	ld.w	r13, (r4, 0x7ac)	// regs: r13=*(r4 + 0x7ac)
 6a8:	d90421ec 	ld.w	r8, (r4, 0x7b0)	// regs: r8=*(r4 + 0x7b0)
 6ac:	d92421ed 	ld.w	r9, (r4, 0x7b4)	// regs: r9=*(r4 + 0x7b4)
 6b0:	c540488a 	asri	r10, r0, 10	// regs: r10=(*(r4 + 0x748) >> 0xa)
 6b4:	e906020f 	bez	r6, 0xad2	// if (r6 == 0x0) goto loc_ad2;
 6b8:	ea0b0064 	movi	r11, 100	// regs: r11=0x64
 6bc:	c4eb0087 	subu	r7, r11, r7	// regs: r7=(0x64 - r7)
 6c0:	5007      	asri	r0, r0, 7	// regs: r0=(*(r4 + 0x748) >> 0x7)
 6c2:	7c1c      	mult	r0, r7	// regs: r0=((*(r4 + 0x748) >> 0x7) * (0x64 - r7))
 6c4:	370a      	movi	r7, 10	// regs: r7=0xa
 6c6:	7c1c      	mult	r0, r7	// regs: r0=(((*(r4 + 0x748) >> 0x7) * (0x64 - r7)) * 0xa)
 6c8:	c4c08020 	divu	r0, r0, r6	// regs: r0=((((*(r4 + 0x748) >> 0x7) * (0x64 - r7)) * 0xa) / r6)
loc_6cc:
 6cc:	d8e421d4 	ld.w	r7, (r4, 0x750)	// regs: r7=*(r4 + 0x750)
 6d0:	b8e7      	st.w	r7, (r14, 0x1c)	// stack_p1c = *(r4 + 0x750)
 6d2:	ea0b0019 	movi	r11, 25	// regs: r11=0x19
 6d6:	d8e421d3 	ld.w	r7, (r4, 0x74c)	// regs: r7=*(r4 + 0x74c)
 6da:	c5678047 	divs	r7, r7, r11	// regs: r7=(*(r4 + 0x74c) / 0x19)
 6de:	b805      	st.w	r0, (r14, 0x14)	// stack_p14 = r0
 6e0:	b8e6      	st.w	r7, (r14, 0x18)	// stack_p18 = (*(r4 + 0x74c) / 0x19)
 6e2:	dd4e2004 	st.w	r10, (r14, 0x10)	// stack_p10 = (*(r4 + 0x748) >> 0xa)
 6e6:	dd2e2003 	st.w	r9, (r14, 0xc)	// stack_pc = *(r4 + 0x7b4)
 6ea:	dd0e2002 	st.w	r8, (r14, 0x8)	// stack_p8 = *(r4 + 0x7b0)
 6ee:	ddae2001 	st.w	r13, (r14, 0x4)	// stack_p4 = *(r4 + 0x7ac)
 6f2:	dd8e2000 	st.w	r12, (r14, 0x0)	// stack_0 = r12
 6f6:	0114      	lrw	r0, 0x0	// regs: r0=0x0
 6f8:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x6f8>, r1=<clobbered>
loc_6fc:
 6fc:	d84421d1 	ld.w	r2, (r4, 0x744)	// regs: r2=*(r4 + 0x744)
 700:	e902001a 	bez	r2, 0x734	// if (r2 == 0x0) goto loc_734;
 704:	d86421d9 	ld.w	r3, (r4, 0x764)	// regs: r3=*(r4 + 0x764)
 708:	c4438043 	divs	r3, r3, r2	// regs: r3=(*(r4 + 0x764) / *(r4 + 0x744))
 70c:	eb2301f3 	cmplti	r3, 500
 710:	0812      	bt	0x734	// if (r3 < 0x1f4) goto loc_734;
 712:	b874      	st.w	r3, (r14, 0x50)	// stack_p50 = (*(r4 + 0x764) / *(r4 + 0x744))
 714:	3300      	movi	r3, 0	// regs: r3=0x0
 716:	3205      	movi	r2, 5	// regs: r2=0x5
 718:	b875      	st.w	r3, (r14, 0x54)	// stack_p54 = 0x0
 71a:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(r4)
 71c:	b852      	st.w	r2, (r14, 0x48)	// stack_p48 = 0x5
 71e:	d84421d8 	ld.w	r2, (r4, 0x760)	// regs: r2=*(r4 + 0x760)
 722:	b853      	st.w	r2, (r14, 0x4c)	// stack_p4c = *(r4 + 0x760)
 724:	d9832009 	ld.w	r12, (r3, 0x24)	// regs: r12=*((*(r4) + 0x24))
 728:	1a12      	addi	r2, r14, 72	// regs: r2=(sp + 0x48)
 72a:	0200      	lrw	r0, 0x0	// regs: r0=0x0
 72c:	3310      	movi	r3, 16	// regs: r3=0x10
 72e:	311b      	movi	r1, 27	// regs: r1=0x1b
 730:	9000      	ld.w	r0, (r0, 0x0)	// regs: r0=*(0x0)
 732:	7bf1      	jsr	r12
loc_734:
 734:	d84421e7 	ld.w	r2, (r4, 0x79c)	// regs: r2=*(r4 + 0x79c)
 738:	d82421db 	ld.w	r1, (r4, 0x76c)	// regs: r1=*(r4 + 0x76c)
 73c:	0204      	lrw	r0, 0x0	// regs: r0=0x0
 73e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x73e>, r1=<clobbered>
 742:	3d41      	cmpnei	r5, 1
 744:	08a6      	bt	0x890	// if (r5 != 0x1) goto loc_890;
 746:	d84421f7 	ld.w	r2, (r4, 0x7dc)	// regs: r2=*(r4 + 0x7dc)
 74a:	e90201c7 	bez	r2, 0xad8	// if (r2 == 0x0) goto loc_ad8;
 74e:	d82421f6 	ld.w	r1, (r4, 0x7d8)	// regs: r1=*(r4 + 0x7d8)
 752:	d86421f5 	ld.w	r3, (r4, 0x7d4)	// regs: r3=*(r4 + 0x7d4)
 756:	c4418041 	divs	r1, r1, r2	// regs: r1=(*(r4 + 0x7d8) / *(r4 + 0x7dc))
 75a:	c4438042 	divs	r2, r3, r2	// regs: r2=(*(r4 + 0x7d4) / *(r4 + 0x7dc))
loc_75e:
 75e:	d80421dd 	ld.w	r0, (r4, 0x774)	// regs: r0=*(r4 + 0x774)
 762:	d86421dc 	ld.w	r3, (r4, 0x770)	// regs: r3=*(r4 + 0x770)
 766:	c540488d 	asri	r13, r0, 10	// regs: r13=(*(r4 + 0x774) >> 0xa)
 76a:	e906000a 	bez	r6, 0x77e	// if (r6 == 0x0) goto loc_77e;
 76e:	ea0c00fa 	movi	r12, 250	// regs: r12=0xfa
 772:	5007      	asri	r0, r0, 7	// regs: r0=(*(r4 + 0x774) >> 0x7)
 774:	c44c482c 	lsli	r12, r12, 2	// regs: r12=0x3e8
 778:	7c30      	mult	r0, r12	// regs: r0=((*(r4 + 0x774) >> 0x7) * 0x3e8)
 77a:	c4c08026 	divu	r6, r0, r6	// regs: r6=(((*(r4 + 0x774) >> 0x7) * 0x3e8) / r6)
loc_77e:
 77e:	d8041403 	ld.h	r0, (r4, 0x806)	// regs: r0=*(r4 + 0x806)
 782:	b807      	st.w	r0, (r14, 0x1c)	// stack_p1c = *(r4 + 0x806)
 784:	d8041402 	ld.h	r0, (r4, 0x804)	// regs: r0=*(r4 + 0x804)
 788:	b806      	st.w	r0, (r14, 0x18)	// stack_p18 = *(r4 + 0x804)
 78a:	d80421e3 	ld.w	r0, (r4, 0x78c)	// regs: r0=*(r4 + 0x78c)
 78e:	b805      	st.w	r0, (r14, 0x14)	// stack_p14 = *(r4 + 0x78c)
 790:	d80421e4 	ld.w	r0, (r4, 0x790)	// regs: r0=*(r4 + 0x790)
 794:	b804      	st.w	r0, (r14, 0x10)	// stack_p10 = *(r4 + 0x790)
 796:	d80421e2 	ld.w	r0, (r4, 0x788)	// regs: r0=*(r4 + 0x788)
 79a:	ea0c0019 	movi	r12, 25	// regs: r12=0x19
 79e:	b803      	st.w	r0, (r14, 0xc)	// stack_pc = *(r4 + 0x788)
 7a0:	d80421de 	ld.w	r0, (r4, 0x778)	// regs: r0=*(r4 + 0x778)
 7a4:	c5808040 	divs	r0, r0, r12	// regs: r0=(*(r4 + 0x778) / 0x19)
 7a8:	ddae2000 	st.w	r13, (r14, 0x0)	// stack_0 = (*(r4 + 0x774) >> 0xa)
 7ac:	b802      	st.w	r0, (r14, 0x8)	// stack_p8 = (*(r4 + 0x778) / 0x19)
 7ae:	b8c1      	st.w	r6, (r14, 0x4)	// stack_p4 = r6
 7b0:	0300      	lrw	r0, 0x0	// regs: r0=0x0
 7b2:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x7b2>, r1=<clobbered>
 7b6:	d844153f 	ld.h	r2, (r4, 0xa7e)	// regs: r2=*(r4 + 0xa7e)
 7ba:	d824153e 	ld.h	r1, (r4, 0xa7c)	// regs: r1=*(r4 + 0xa7c)
 7be:	0302      	lrw	r0, 0x0	// regs: r0=0x0
 7c0:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x7c0>, r1=<clobbered>
 7c4:	d86414ed 	ld.h	r3, (r4, 0x9da)	// regs: r3=*(r4 + 0x9da)
 7c8:	b868      	st.w	r3, (r14, 0x20)	// stack_p20 = *(r4 + 0x9da)
 7ca:	d86414ec 	ld.h	r3, (r4, 0x9d8)	// regs: r3=*(r4 + 0x9d8)
 7ce:	b867      	st.w	r3, (r14, 0x1c)	// stack_p1c = *(r4 + 0x9d8)
 7d0:	d86421fe 	ld.w	r3, (r4, 0x7f8)	// regs: r3=*(r4 + 0x7f8)
 7d4:	b866      	st.w	r3, (r14, 0x18)	// stack_p18 = *(r4 + 0x7f8)
 7d6:	d8642209 	ld.w	r3, (r4, 0x824)	// regs: r3=*(r4 + 0x824)
 7da:	b865      	st.w	r3, (r14, 0x14)	// stack_p14 = *(r4 + 0x824)
 7dc:	d864220a 	ld.w	r3, (r4, 0x828)	// regs: r3=*(r4 + 0x828)
 7e0:	b864      	st.w	r3, (r14, 0x10)	// stack_p10 = *(r4 + 0x828)
 7e2:	d8642200 	ld.w	r3, (r4, 0x800)	// regs: r3=*(r4 + 0x800)
 7e6:	b863      	st.w	r3, (r14, 0xc)	// stack_pc = *(r4 + 0x800)
 7e8:	d864226d 	ld.w	r3, (r4, 0x9b4)	// regs: r3=*(r4 + 0x9b4)
 7ec:	b862      	st.w	r3, (r14, 0x8)	// stack_p8 = *(r4 + 0x9b4)
 7ee:	d864229d 	ld.w	r3, (r4, 0xa74)	// regs: r3=*(r4 + 0xa74)
 7f2:	b861      	st.w	r3, (r14, 0x4)	// stack_p4 = *(r4 + 0xa74)
 7f4:	d864229c 	ld.w	r3, (r4, 0xa70)	// regs: r3=*(r4 + 0xa70)
 7f8:	b860      	st.w	r3, (r14, 0x0)	// stack_0 = *(r4 + 0xa70)
 7fa:	d84421fc 	ld.w	r2, (r4, 0x7f0)	// regs: r2=*(r4 + 0x7f0)
 7fe:	d86421fd 	ld.w	r3, (r4, 0x7f4)	// regs: r3=*(r4 + 0x7f4)
 802:	d82421fb 	ld.w	r1, (r4, 0x7ec)	// regs: r1=*(r4 + 0x7ec)
 806:	ea88008c 	lrw	r8, 0x0	// regs: r8=0x0
 80a:	0313      	lrw	r0, 0x0	// regs: r0=0x0
 80c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x80c>, r1=<clobbered>
 810:	d8640361 	ld.b	r3, (r4, 0x361)	// regs: r3=*(r4 + 0x361)
 814:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(r4 + 0x361) & 0x8)
 818:	3b40      	cmpnei	r3, 0
 81a:	d8240680 	ld.b	r1, (r4, 0x680)	// regs: r1=*(r4 + 0x680)
 81e:	d864219e 	ld.w	r3, (r4, 0x678)	// regs: r3=*(r4 + 0x678)
 822:	e4212001 	andi	r1, r1, 1	// regs: r1=(*(r4 + 0x680) & 0x1)
 826:	0319      	lrw	r0, 0x0	// regs: r0=0x0
 828:	c4080c20 	incf	r0, r8, 0
 82c:	eb230055 	cmplti	r3, 86
 830:	037b      	lrw	r3, 0x0	// regs: r3=0x0
 832:	c4680c40 	inct	r3, r8, 0
 836:	d8e411b1 	ld.h	r7, (r4, 0x362)	// regs: r7=*(r4 + 0x362)
 83a:	3940      	cmpnei	r1, 0
 83c:	035d      	lrw	r2, 0x0	// regs: r2=0x0
 83e:	c4480c20 	incf	r2, r8, 0
 842:	d9844a4e 	ld.bs	r12, (r4, 0xa4e)	// regs: r12=*(r4 + 0xa4e)
 846:	d9a44a4d 	ld.bs	r13, (r4, 0xa4d)	// regs: r13=*(r4 + 0xa4d)
 84a:	d8c40690 	ld.b	r6, (r4, 0x690)	// regs: r6=*(r4 + 0x690)
 84e:	c4875567 	zext	r7, r7, 11, 4	// regs: r7=zext(*(r4 + 0x362))
 852:	b846      	st.w	r2, (r14, 0x18)	// stack_p18 = 0x0
 854:	b865      	st.w	r3, (r14, 0x14)	// stack_p14 = 0x0
 856:	b803      	st.w	r0, (r14, 0xc)	// stack_pc = 0x0
 858:	d82421f1 	ld.w	r1, (r4, 0x7c4)	// regs: r1=*(r4 + 0x7c4)
 85c:	b8e4      	st.w	r7, (r14, 0x10)	// stack_p10 = zext(*(r4 + 0x362))
 85e:	b8c2      	st.w	r6, (r14, 0x8)	// stack_p8 = *(r4 + 0x690)
 860:	ddae2001 	st.w	r13, (r14, 0x4)	// stack_p4 = *(r4 + 0xa4d)
 864:	dd8e2000 	st.w	r12, (r14, 0x0)	// stack_0 = *(r4 + 0xa4e)
 868:	d86421e6 	ld.w	r3, (r4, 0x798)	// regs: r3=*(r4 + 0x798)
 86c:	d84421e5 	ld.w	r2, (r4, 0x794)	// regs: r2=*(r4 + 0x794)
 870:	1316      	lrw	r0, 0x0	// regs: r0=0x0
 872:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x872>, r1=<clobbered>
 876:	d82422ea 	ld.w	r1, (r4, 0xba8)	// regs: r1=*(r4 + 0xba8)
 87a:	e9210006 	bnez	r1, 0x886	// if (r1 != 0x0) goto loc_886;
 87e:	d86422eb 	ld.w	r3, (r4, 0xbac)	// regs: r3=*(r4 + 0xbac)
 882:	e9030007 	bez	r3, 0x890	// if (r3 == 0x0) goto loc_890;
loc_886:
 886:	d84422eb 	ld.w	r2, (r4, 0xbac)	// regs: r2=*(r4 + 0xbac)
 88a:	1311      	lrw	r0, 0x0	// regs: r0=0x0
 88c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x88c>, r1=<clobbered>
loc_890:
 890:	1310      	lrw	r0, 0x0	// regs: r0=0x0
 892:	e0000000 	bsr	0x0	// <lhw_get_cca_observ>; regs: r0=<ret lhw_get_cca_observ@0x892>, r1=<clobbered>
 896:	e9200123 	bnez	r0, 0xadc	// if (r0 != 0x0) goto loc_adc;
 89a:	d804142a 	ld.h	r0, (r4, 0x854)	// regs: r0=*(r4 + 0x854)
 89e:	b800      	st.w	r0, (r14, 0x0)	// stack_0 = *(r4 + 0x854)
 8a0:	d864142b 	ld.h	r3, (r4, 0x856)	// regs: r3=*(r4 + 0x856)
 8a4:	d8441428 	ld.h	r2, (r4, 0x850)	// regs: r2=*(r4 + 0x850)
 8a8:	d8241429 	ld.h	r1, (r4, 0x852)	// regs: r1=*(r4 + 0x852)
 8ac:	130a      	lrw	r0, 0x0	// regs: r0=0x0
 8ae:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x8ae>, r1=<clobbered>
 8b2:	3d41      	cmpnei	r5, 1
 8b4:	0829      	bt	0x906	// if (r5 != 0x1) goto loc_906;
 8b6:	d824142e 	ld.h	r1, (r4, 0x85c)	// regs: r1=*(r4 + 0x85c)
 8ba:	b824      	st.w	r1, (r14, 0x10)	// stack_p10 = *(r4 + 0x85c)
 8bc:	d824142f 	ld.h	r1, (r4, 0x85e)	// regs: r1=*(r4 + 0x85e)
 8c0:	b823      	st.w	r1, (r14, 0xc)	// stack_pc = *(r4 + 0x85e)
 8c2:	d824142c 	ld.h	r1, (r4, 0x858)	// regs: r1=*(r4 + 0x858)
 8c6:	d8640361 	ld.b	r3, (r4, 0x361)	// regs: r3=*(r4 + 0x361)
 8ca:	b822      	st.w	r1, (r14, 0x8)	// stack_p8 = *(r4 + 0x858)
 8cc:	d824142d 	ld.h	r1, (r4, 0x85a)	// regs: r1=*(r4 + 0x85a)
 8d0:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(r4 + 0x361) & 0x4)
 8d4:	d8440860 	ld.b	r2, (r4, 0x860)	// regs: r2=*(r4 + 0x860)
 8d8:	b821      	st.w	r1, (r14, 0x4)	// stack_p4 = *(r4 + 0x85a)
 8da:	d8241426 	ld.h	r1, (r4, 0x84c)	// regs: r1=*(r4 + 0x84c)
 8de:	3b40      	cmpnei	r3, 0
 8e0:	b820      	st.w	r1, (r14, 0x0)	// stack_0 = *(r4 + 0x84c)
 8e2:	e4422007 	andi	r2, r2, 7	// regs: r2=(*(r4 + 0x860) & 0x7)
 8e6:	1216      	lrw	r0, 0x0	// regs: r0=0x0
 8e8:	1233      	lrw	r1, 0x0	// regs: r1=0x0
 8ea:	c4200c40 	inct	r1, r0, 0
 8ee:	d8641427 	ld.h	r3, (r4, 0x84e)	// regs: r3=*(r4 + 0x84e)
 8f2:	121a      	lrw	r0, 0x0	// regs: r0=0x0
 8f4:	c4454022 	lsl	r2, r5, r2
 8f8:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x8f8>, r1=<clobbered>
 8fc:	d8240a6a 	ld.b	r1, (r4, 0xa6a)	// regs: r1=*(r4 + 0xa6a)
 900:	1217      	lrw	r0, 0x0	// regs: r0=0x0
loc_902:
 902:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x902>, r1=<clobbered>
loc_906:
 906:	d8040860 	ld.b	r0, (r4, 0x860)	// regs: r0=*(r4 + 0x860)
 90a:	e4002007 	andi	r0, r0, 7	// regs: r0=(*(r4 + 0x860) & 0x7)
 90e:	e0000000 	bsr	0x0	// <lhw_start_cca_observ>; regs: r0=<ret lhw_start_cca_observ@0x90e>, r1=<clobbered>
 912:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(r4 + 0x9e2)
 916:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(r4 + 0x9e2) & 0x2)
 91a:	e923001e 	bnez	r3, 0x956	// if (r3 != 0x0) goto loc_956;
 91e:	e905001c 	bez	r5, 0x956	// if (r5 == 0x0) goto loc_956;
 922:	d804219f 	ld.w	r0, (r4, 0x67c)	// regs: r0=*(r4 + 0x67c)
 926:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x926>, r1=<clobbered>
 92a:	6e03      	mov	r8, r0	// regs: r8=<ret __extendsfdf2@0x926>
 92c:	d80421b7 	ld.w	r0, (r4, 0x6dc)	// regs: r0=*(r4 + 0x6dc)
 930:	6dc7      	mov	r7, r1	// regs: r7=<clobbered>
 932:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x932>, r1=<clobbered>
 936:	b802      	st.w	r0, (r14, 0x8)	// stack_p8 = <ret __extendsfdf2@0x932>
 938:	d80421b6 	ld.w	r0, (r4, 0x6d8)	// regs: r0=*(r4 + 0x6d8)
 93c:	d8c4219e 	ld.w	r6, (r4, 0x678)	// regs: r6=*(r4 + 0x678)
 940:	b823      	st.w	r1, (r14, 0xc)	// stack_pc = <clobbered>
 942:	e0000000 	bsr	0x0	// <__extendsfdf2>; regs: r0=<ret __extendsfdf2@0x942>, r1=<clobbered>
 946:	b800      	st.w	r0, (r14, 0x0)	// stack_0 = <ret __extendsfdf2@0x942>
 948:	b821      	st.w	r1, (r14, 0x4)	// stack_p4 = <clobbered>
 94a:	6ca3      	mov	r2, r8	// regs: r2=<ret __extendsfdf2@0x926>
 94c:	6cdf      	mov	r3, r7	// regs: r3=<clobbered>
 94e:	6c5b      	mov	r1, r6	// regs: r1=*(r4 + 0x678)
 950:	1204      	lrw	r0, 0x0	// regs: r0=0x0
 952:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x952>, r1=<clobbered>
loc_956:
 956:	3286      	movi	r2, 134	// regs: r2=0x86
 958:	4241      	lsli	r2, r2, 1	// regs: r2=0x10c
 95a:	3100      	movi	r1, 0	// regs: r1=0x0
 95c:	1202      	lrw	r0, 0x0	// regs: r0=0x0
 95e:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x95e>, r1=<clobbered>
 962:	d9241504 	ld.h	r9, (r4, 0xa08)	// regs: r9=*(r4 + 0xa08)
 966:	e4691000 	subi	r3, r9, 1	// regs: r3=(*(r4 + 0xa08) - 0x1)
 96a:	3b07      	cmphsi	r3, 8
 96c:	ea080000 	movi	r8, 0	// regs: r8=0x0
 970:	dd04226d 	st.w	r8, (r4, 0x9b4)	// *(r4 + 0x9b4) = 0x0
 974:	0807      	bt	0x982	// if (r3 >= 0x8) goto loc_982;
 976:	30fa      	movi	r0, 250	// regs: r0=0xfa
 978:	4001      	lsli	r0, r0, 1	// regs: r0=0x1f4
 97a:	7c24      	mult	r0, r9	// regs: r0=(0x1f4 * *(r4 + 0xa08))
 97c:	e0000000 	bsr	0x0	// <_os_malloc>; regs: r0=<ret _os_malloc@0x97c>, r1=<clobbered>
 980:	6e03      	mov	r8, r0	// regs: r8=<ret _os_malloc@0x97c>
loc_982:
 982:	3100      	movi	r1, 0	// regs: r1=0x0
 984:	2900      	subi	r1, 1	// regs: r1=0xffffffff
 986:	1119      	lrw	r0, 0x0	// regs: r0=0x0
 988:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0x988>, r1=<clobbered>
 98c:	ea0b0000 	movi	r11, 0	// regs: r11=0x0
 990:	d8e4227e 	ld.w	r7, (r4, 0x9f8)	// regs: r7=*(r4 + 0x9f8)
 994:	1136      	lrw	r1, 0x0	// regs: r1=0x0
 996:	6c9f      	mov	r2, r7	// regs: r2=*(r4 + 0x9f8)
 998:	6daf      	mov	r6, r11	// regs: r6=0x0
 99a:	b82d      	st.w	r1, (r14, 0x34)	// stack_p34 = 0x0
loc_99c:
 99c:	644a      	cmpne	r2, r1
 99e:	08a5      	bt	0xae8	// if (T) goto loc_ae8;
 9a0:	ea0a0000 	movi	r10, 0	// regs: r10=0x0
 9a4:	61ac      	addu	r6, r11	// regs: r6=(r6 + r11)
loc_9a6:
 9a6:	986d      	ld.w	r3, (r14, 0x34)	// regs: r3=stack_p34
 9a8:	64de      	cmpne	r7, r3
 9aa:	08a7      	bt	0xaf8	// if (T) goto loc_af8;
 9ac:	5f1e      	addi	r0, r7, 8	// regs: r0=(r7 + 0x8)
 9ae:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0x9ae>, r1=<clobbered>
 9b2:	eb480000 	cmpnei	r8, 0
 9b6:	c52a0c40 	inct	r9, r10, 0
 9ba:	e9060007 	bez	r6, 0x9c8	// if (r6 == 0x0) goto loc_9c8;
 9be:	3264      	movi	r2, 100	// regs: r2=0x64
 9c0:	c44b8423 	mult	r3, r11, r2	// regs: r3=(r11 * 0x64)
 9c4:	c4c38046 	divs	r6, r3, r6	// regs: r6=((r11 * 0x64) / r6)
loc_9c8:
 9c8:	7598      	zextb	r6, r6	// regs: r6=zext8(r6)
 9ca:	3364      	movi	r3, 100	// regs: r3=0x64
 9cc:	dcc40690 	st.b	r6, (r4, 0x690)	// *(r4 + 0x690) = zext8(r6)
 9d0:	5bd9      	subu	r6, r3, r6	// regs: r6=(0x64 - zext8(r6))
 9d2:	dcc40691 	st.b	r6, (r4, 0x691)	// *(r4 + 0x691) = (0x64 - zext8(r6))
 9d6:	e90800c5 	bez	r8, 0xb60	// if (r8 == 0x0) goto loc_b60;
 9da:	6c23      	mov	r0, r8	// regs: r0=r8
 9dc:	3600      	movi	r6, 0	// regs: r6=0x0
loc_9de:
 9de:	665a      	cmpne	r6, r9
 9e0:	08d4      	bt	0xb88	// if (T) goto loc_b88;
 9e2:	6c23      	mov	r0, r8	// regs: r0=r8
 9e4:	e0000000 	bsr	0x0	// <_os_free>; regs: r0=<ret _os_free@0x9e4>, r1=<clobbered>
 9e8:	e800fb65 	br	0xb2	// goto loc_b2;
 9ec:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x30b>
 9f0:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x311>
 9f4:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_info_statics_print.str1.1+0x193>
 9f8:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x319>
 9fc:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x31f>
 a00:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x15>
 a04:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x10>
 a08:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x324>
 a0c:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x36e>
 a10:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x38a>
 a14:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x3c2>
 a18:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x3ce>
 a1c:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x415>
 a20:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x457>
 a24:	00000000 	.long	0x00000000	// <ah_ops>
 a28:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x4ae>
 a2c:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x4c5>
 a30:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x525>
 a34:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x1f>
 a38:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x539>
 a3c:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x1d>
 a40:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x20>
 a44:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x3c>
 a48:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x59f>
 a4c:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x5e2>
 a50:	00000000 	.long	0x00000000	// <ah_lmac+0x84c>
 a54:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x5fe>
 a58:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x61a>
 a5c:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x646>
 a60:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x663>
 a64:	00000000 	.long	0x00000000	// <ah_lmac+0x70c>
 a68:	00000000 	.long	0x00000000	// <ah_lmac+0xa00>
 a6c:	00000000 	.long	0x00000000	// <ah_lmac+0x9f8>
loc_a70:
 a70:	126a      	lrw	r3, 0x0	// regs: r3=0x0
 a72:	60dc      	addu	r3, r7	// regs: r3=(0x0 + r7)
 a74:	6c2f      	mov	r0, r11	// regs: r0=r11
 a76:	d843202a 	ld.w	r2, (r3, 0xa8)	// regs: r2=*(((0x0 + r7) + 0xa8))
 a7a:	c5028021 	divu	r1, r2, r8	// regs: r1=(*(((0x0 + r7) + 0xa8)) / r8)
 a7e:	c5018423 	mult	r3, r1, r8	// regs: r3=((*(((0x0 + r7) + 0xa8)) / r8) * r8)
 a82:	608e      	subu	r2, r3	// regs: r2=(*(((0x0 + r7) + 0xa8)) - ((*(((0x0 + r7) + 0xa8)) / r8) * r8))
 a84:	c5428022 	divu	r2, r2, r10	// regs: r2=((*(((0x0 + r7) + 0xa8)) - ((*(((0x0 + r7) + 0xa8)) / r8) * r8)) / r10)
 a88:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xa88>, r1=<clobbered>
 a8c:	e5290000 	addi	r9, r9, 1	// regs: r9=(r9 + 0x1)
 a90:	e800fcde 	br	0x44c	// goto loc_44c;
loc_a94:
 a94:	1261      	lrw	r3, 0x0	// regs: r3=0x0
 a96:	60dc      	addu	r3, r7	// regs: r3=(0x0 + (r7 + 0x18))
 a98:	6c27      	mov	r0, r9	// regs: r0=0x0
 a9a:	d82340af 	ld.bs	r1, (r3, 0xaf)	// regs: r1=*(((0x0 + (r7 + 0x18)) + 0xaf))
 a9e:	d86443e0 	ld.bs	r3, (r4, 0x3e0)	// regs: r3=*(r4 + 0x3e0)
 aa2:	604c      	addu	r1, r3	// regs: r1=(*(((0x0 + (r7 + 0x18)) + 0xaf)) + *(r4 + 0x3e0))
 aa4:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xaa4>, r1=<clobbered>
 aa8:	e5080000 	addi	r8, r8, 1	// regs: r8=(r8 + 0x1)
 aac:	e800fce2 	br	0x470	// goto loc_470;
loc_ab0:
 ab0:	6c4f      	mov	r1, r3	// regs: r1=*(r4 + 0x7e8)
 ab2:	e800fcf4 	br	0x49a	// goto loc_49a;
 ab6:	3300      	movi	r3, 0	// regs: r3=0x0
 ab8:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 aba:	e800fcf8 	br	0x4aa	// goto loc_4aa;
loc_abe:
 abe:	6dc7      	mov	r7, r1	// regs: r7=*(r4 + 0x744)
 ac0:	6c87      	mov	r2, r1	// regs: r2=*(r4 + 0x744)
 ac2:	e800fdc1 	br	0x644	// goto loc_644;
loc_ac6:
 ac6:	d80411b6 	ld.h	r0, (r4, 0x36c)	// regs: r0=*(r4 + 0x36c)
 aca:	c4a05520 	zext	r0, r0, 9, 5	// regs: r0=zext(*(r4 + 0x36c))
 ace:	e800fdc7 	br	0x65c	// goto loc_65c;
loc_ad2:
 ad2:	6c1b      	mov	r0, r6	// regs: r0=r6
 ad4:	e800fdfc 	br	0x6cc	// goto loc_6cc;
loc_ad8:
 ad8:	6c4b      	mov	r1, r2	// regs: r1=*(r4 + 0x7dc)
 ada:	0642      	br	0x75e	// goto loc_75e;
loc_adc:
 adc:	3d41      	cmpnei	r5, 1
 ade:	0b14      	bt	0x906	// if (r5 != 0x1) goto loc_906;
 ae0:	d8240a6a 	ld.b	r1, (r4, 0xa6a)	// regs: r1=*(r4 + 0xa6a)
 ae4:	110e      	lrw	r0, 0x0	// regs: r0=0x0
 ae6:	070e      	br	0x902	// goto loc_902;
loc_ae8:
 ae8:	d8022073 	ld.w	r0, (r2, 0x1cc)	// regs: r0=*(r2 + 0x1cc)
 aec:	6180      	addu	r6, r0	// regs: r6=(r6 + *(r2 + 0x1cc))
 aee:	d802207a 	ld.w	r0, (r2, 0x1e8)	// regs: r0=*(r2 + 0x1e8)
 af2:	62c0      	addu	r11, r0	// regs: r11=(r11 + *(r2 + 0x1e8))
 af4:	9240      	ld.w	r2, (r2, 0x0)	// regs: r2=*(r2)
 af6:	0753      	br	0x99c	// goto loc_99c;
loc_af8:
 af8:	e9060030 	bez	r6, 0xb58	// if (r6 == 0x0) goto loc_b58;
 afc:	d8472073 	ld.w	r2, (r7, 0x1cc)	// regs: r2=*(r7 + 0x1cc)
 b00:	3364      	movi	r3, 100	// regs: r3=0x64
 b02:	7c8c      	mult	r2, r3	// regs: r2=(*(r7 + 0x1cc) * 0x64)
 b04:	c4c28042 	divs	r2, r2, r6	// regs: r2=((*(r7 + 0x1cc) * 0x64) / r6)
loc_b08:
 b08:	dc4700b2 	st.b	r2, (r7, 0xb2)	// *(r7 + 0xb2) = r2
 b0c:	e9060028 	bez	r6, 0xb5c	// if (r6 == 0x0) goto loc_b5c;
 b10:	d847207a 	ld.w	r2, (r7, 0x1e8)	// regs: r2=*(r7 + 0x1e8)
 b14:	3364      	movi	r3, 100	// regs: r3=0x64
 b16:	7c8c      	mult	r2, r3	// regs: r2=(*(r7 + 0x1e8) * 0x64)
 b18:	c4c28022 	divu	r2, r2, r6	// regs: r2=((*(r7 + 0x1e8) * 0x64) / r6)
loc_b1c:
 b1c:	dc4700b3 	st.b	r2, (r7, 0xb3)	// *(r7 + 0xb3) = r2
 b20:	e908000e 	bez	r8, 0xb3c	// if (r8 == 0x0) goto loc_b3c;
 b24:	6668      	cmphs	r10, r9
 b26:	080b      	bt	0xb3c	// if (T) goto loc_b3c;
 b28:	32fa      	movi	r2, 250	// regs: r2=0xfa
 b2a:	4241      	lsli	r2, r2, 1	// regs: r2=0x1f4
 b2c:	c44a8420 	mult	r0, r10, r2	// regs: r0=(r10 * 0x1f4)
 b30:	6c5f      	mov	r1, r7	// regs: r1=r7
 b32:	6020      	addu	r0, r8	// regs: r0=((r10 * 0x1f4) + r8)
 b34:	e0000000 	bsr	0x0	// <hw_memcpy>; regs: r0=<ret hw_memcpy@0xb34>, r1=<clobbered>
 b38:	e54a0000 	addi	r10, r10, 1	// regs: r10=(r10 + 0x1)
loc_b3c:
 b3c:	321c      	movi	r2, 28	// regs: r2=0x1c
 b3e:	3100      	movi	r1, 0	// regs: r1=0x0
 b40:	e40701c3 	addi	r0, r7, 452	// regs: r0=(r7 + 0x1c4)
 b44:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0xb44>, r1=<clobbered>
 b48:	e40701df 	addi	r0, r7, 480	// regs: r0=(r7 + 0x1e0)
 b4c:	3214      	movi	r2, 20	// regs: r2=0x14
 b4e:	3100      	movi	r1, 0	// regs: r1=0x0
 b50:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0xb50>, r1=<clobbered>
 b54:	97e0      	ld.w	r7, (r7, 0x0)	// regs: r7=*(r7)
 b56:	0728      	br	0x9a6	// goto loc_9a6;
loc_b58:
 b58:	6c9b      	mov	r2, r6	// regs: r2=r6
 b5a:	07d7      	br	0xb08	// goto loc_b08;
loc_b5c:
 b5c:	6c9b      	mov	r2, r6	// regs: r2=r6
 b5e:	07df      	br	0xb1c	// goto loc_b1c;
loc_b60:
 b60:	e4691000 	subi	r3, r9, 1	// regs: r3=(r9 - 0x1)
 b64:	3b07      	cmphsi	r3, 8
 b66:	0807      	bt	0xb74	// if (r3 >= 0x8) goto loc_b74;
 b68:	6c67      	mov	r1, r9	// regs: r1=r9
 b6a:	100e      	lrw	r0, 0x0	// regs: r0=0x0
loc_b6c:
 b6c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xb6c>, r1=<clobbered>
 b70:	e800faa1 	br	0xb2	// goto loc_b2;
loc_b74:
 b74:	e9290007 	bnez	r9, 0xb82	// if (r9 != 0x0) goto loc_b82;
 b78:	100b      	lrw	r0, 0x0	// regs: r0=0x0
 b7a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xb7a>, r1=<clobbered>
 b7e:	e800fa9a 	br	0xb2	// goto loc_b2;
loc_b82:
 b82:	6c67      	mov	r1, r9	// regs: r1=r9
 b84:	1009      	lrw	r0, 0x0	// regs: r0=0x0
 b86:	07f3      	br	0xb6c	// goto loc_b6c;
loc_b88:
 b88:	e4e001f3 	addi	r7, r0, 500	// regs: r7=(r0 + 0x1f4)
 b8c:	6c57      	mov	r1, r5	// regs: r1=r5
 b8e:	e0000000 	bsr	0x0	// <lmac_sta_info_statics_print> // arg_bytes: 8; regs: r0=<ret lmac_sta_info_statics_print@0xb8e>, r1=<clobbered>
 b92:	2600      	addi	r6, 1	// regs: r6=(r6 + 0x1)
 b94:	6c1f      	mov	r0, r7	// regs: r0=(r0 + 0x1f4)
 b96:	0724      	br	0x9de	// goto loc_9de;
 b98:	00000000 	.long	0x00000000	// <ah_lmac>
 b9c:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x653>
 ba0:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x69d>
 ba4:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x6bb>
 ba8:	00000000 	.long	0x00000000	// <.rodata.lmac_transceive_statics.str1.1+0x6d0>

Disassembly of section .text.lmac_notify_channel_switch:

00000000 <lmac_notify_channel_switch>: // arg_bytes: 4
   0:	14d1      	push	r4, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   6:	6c43      	mov	r1, r0	// regs: r1=<arg0>
   8:	100f      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xa>, r1=<clobbered>
   e:	3064      	movi	r0, 100	// regs: r0=0x64
  10:	c4048020 	divu	r0, r4, r0	// regs: r0=(<arg0> / 0x64)
  14:	4870      	lsri	r3, r0, 16	// regs: r3=((<arg0> / 0x64) >> 0x10)
  16:	dc0e0000 	st.b	r0, (r14, 0x0)	// local_4 = (<arg0> / 0x64)
  1a:	c50055e0 	zext	r0, r0, 15, 8	// regs: r0=zext((<arg0> / 0x64))
  1e:	dc0e0001 	st.b	r0, (r14, 0x1)	// local_3 = zext((<arg0> / 0x64))
  22:	dc6e0002 	st.b	r3, (r14, 0x2)	// local_2 = ((<arg0> / 0x64) >> 0x10)
  26:	4b68      	lsri	r3, r3, 8	// regs: r3=(((<arg0> / 0x64) >> 0x10) >> 0x8)
  28:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	dc6e0003 	st.b	r3, (r14, 0x3)	// local_1 = (((<arg0> / 0x64) >> 0x10) >> 0x8)
  2e:	d9802009 	ld.w	r12, (r0, 0x24)	// regs: r12=*(0x24)
  32:	e90c0006 	bez	r12, 0x3e	// if (r12 == 0x0) goto loc_3e;
  36:	3304      	movi	r3, 4	// regs: r3=0x4
  38:	6cbb      	mov	r2, r14	// regs: r2=(sp - 0x4)
  3a:	3102      	movi	r1, 2	// regs: r1=0x2
  3c:	7bf1      	jsr	r12
loc_3e:
  3e:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  40:	1491      	pop	r4, r15
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <.rodata.lmac_notify_channel_switch.str1.1>
  46:	0000      	.short	0x0000
  48:	00000000 	.long	0x00000000	// <ah_ops>

Disassembly of section .text.lmac_irq_handler:

00000000 <lmac_irq_handler>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	0398      	lrw	r4, 0x0	// regs: r4=0x0
   4:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
   6:	9372      	ld.w	r3, (r3, 0x48)	// regs: r3=*((*(0x0) + 0x48))
   8:	e4632080 	andi	r3, r3, 128	// regs: r3=(*((*(0x0) + 0x48)) & 0x80)
   c:	e9030004 	bez	r3, 0x14	// if (r3 == 0x0) goto loc_14;
  10:	e0000000 	bsr	0x0	// <lmac_irq_ac_pd>; regs: r0=<ret lmac_irq_ac_pd@0x10>, r1=<clobbered>
loc_14:
  14:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
  16:	9372      	ld.w	r3, (r3, 0x48)	// regs: r3=*((*(0x0) + 0x48))
  18:	e4632020 	andi	r3, r3, 32	// regs: r3=(*((*(0x0) + 0x48)) & 0x20)
  1c:	e9030004 	bez	r3, 0x24	// if (r3 == 0x0) goto loc_24;
  20:	e0000000 	bsr	0x0	// <lmac_irq_bo_fns>; regs: r0=<ret lmac_irq_bo_fns@0x20>, r1=<clobbered>
loc_24:
  24:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
  26:	9372      	ld.w	r3, (r3, 0x48)	// regs: r3=*((*(0x0) + 0x48))
  28:	e4632004 	andi	r3, r3, 4	// regs: r3=(*((*(0x0) + 0x48)) & 0x4)
  2c:	e9030004 	bez	r3, 0x34	// if (r3 == 0x0) goto loc_34;
  30:	e0000000 	bsr	0x0	// <lmac_irq_tx_end>; regs: r0=<ret lmac_irq_tx_end@0x30>, r1=<clobbered>
loc_34:
  34:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
  36:	9352      	ld.w	r2, (r3, 0x48)	// regs: r2=*((*(0x0) + 0x48))
  38:	e4422100 	andi	r2, r2, 256	// regs: r2=(*((*(0x0) + 0x48)) & 0x100)
  3c:	e9020010 	bez	r2, 0x5c	// if (r2 == 0x0) goto loc_5c;
  40:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  42:	3a88      	bclri	r2, 8	// regs: r2=(*((*(0x0) + 0x44)) & ~(0x1 << 0x8))
  44:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) & ~(0x1 << 0x8))
  46:	3280      	movi	r2, 128	// regs: r2=0x80
  48:	4241      	lsli	r2, r2, 1	// regs: r2=0x100
  4a:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x100
  4c:	3000      	movi	r0, 0	// regs: r0=0x0
  4e:	1355      	lrw	r2, 0x0	// regs: r2=0x0
  50:	d82209dc 	ld.b	r1, (r2, 0x9dc)	// regs: r1=*(0x9dc)
  54:	c4205c07 	ins	r1, r0, 7, 7
  58:	dc2209dc 	st.b	r1, (r2, 0x9dc)	// *(0x9dc) = *(0x9dc)
loc_5c:
  5c:	3280      	movi	r2, 128	// regs: r2=0x80
  5e:	9332      	ld.w	r1, (r3, 0x48)	// regs: r1=*((*(0x0) + 0x48))
  60:	4246      	lsli	r2, r2, 6	// regs: r2=0x2000
  62:	6848      	and	r1, r2	// regs: r1=(*((*(0x0) + 0x48)) & 0x2000)
  64:	e9010052 	bez	r1, 0x108	// if (r1 == 0x0) goto loc_108;
  68:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x2000
  6a:	e0000000 	bsr	0x0	// <lmac_next_beacon_calc>; regs: r0=<ret lmac_next_beacon_calc@0x6a>, r1=<clobbered>
  6e:	e0000000 	bsr	0x0	// <lmac_beacon_timer_start>; regs: r0=<ret lmac_beacon_timer_start@0x6e>, r1=<clobbered>
  72:	136c      	lrw	r3, 0x0	// regs: r3=0x0
  74:	d84303e2 	ld.b	r2, (r3, 0x3e2)	// regs: r2=*(0x3e2)
  78:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0x3e2) & 0x8)
  7c:	e9020046 	bez	r2, 0x108	// if (r2 == 0x0) goto loc_108;
  80:	d8432267 	ld.w	r2, (r3, 0x99c)	// regs: r2=*(0x99c)
  84:	e922000b 	bnez	r2, 0x9a	// if (r2 != 0x0) goto loc_9a;
  88:	d84314ef 	ld.h	r2, (r3, 0x9de)	// regs: r2=*(0x9de)
  8c:	c4c25501 	zext	r1, r2, 8, 6	// regs: r1=zext(*(0x9de))
  90:	2106      	addi	r1, 7	// regs: r1=(zext(*(0x9de)) + 0x7)
  92:	c4415c46 	ins	r2, r1, 8, 6
  96:	dc4314ef 	st.h	r2, (r3, 0x9de)	// *(0x9de) = *(0x9de)
loc_9a:
  9a:	3100      	movi	r1, 0	// regs: r1=0x0
  9c:	dc230555 	st.b	r1, (r3, 0x555)	// *(0x555) = 0x0
  a0:	d8230556 	ld.b	r1, (r3, 0x556)	// regs: r1=*(0x556)
  a4:	d8432197 	ld.w	r2, (r3, 0x65c)	// regs: r2=*(0x65c)
  a8:	3901      	cmphsi	r1, 2
  aa:	2200      	addi	r2, 1	// regs: r2=(*(0x65c) + 0x1)
  ac:	dc432197 	st.w	r2, (r3, 0x65c)	// *(0x65c) = (*(0x65c) + 0x1)
  b0:	0c09      	bf	0xc2	// if (r1 < 0x2) goto loc_c2;
  b2:	c422802c 	divu	r12, r2, r1	// regs: r12=((*(0x65c) + 0x1) / *(0x556))
  b6:	5903      	subi	r0, r1, 1	// regs: r0=(*(0x556) - 0x1)
  b8:	7c70      	mult	r1, r12	// regs: r1=(*(0x556) * ((*(0x65c) + 0x1) / *(0x556)))
  ba:	6086      	subu	r2, r1	// regs: r2=((*(0x65c) + 0x1) - (*(0x556) * ((*(0x65c) + 0x1) / *(0x556))))
  bc:	5849      	subu	r2, r0, r2	// regs: r2=((*(0x556) - 0x1) - ((*(0x65c) + 0x1) - (*(0x556) * ((*(0x65c) + 0x1) / *(0x556)))))
  be:	dc430555 	st.b	r2, (r3, 0x555)	// *(0x555) = ((*(0x556) - 0x1) - ((*(0x65c) + 0x1) - (*(0x556) * ((*(0x65c) + 0x1) / *(0x556)))))
loc_c2:
  c2:	d84309e0 	ld.b	r2, (r3, 0x9e0)	// regs: r2=*(0x9e0)
  c6:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(0x9e0) & 0x1)
  ca:	e922001f 	bnez	r2, 0x108	// if (r2 != 0x0) goto loc_108;
  ce:	d84309dd 	ld.b	r2, (r3, 0x9dd)	// regs: r2=*(0x9dd)
  d2:	3101      	movi	r1, 1	// regs: r1=0x1
  d4:	c4415c60 	ins	r2, r1, 3, 0
  d8:	dc4309dd 	st.b	r2, (r3, 0x9dd)	// *(0x9dd) = *(0x9dd)
  dc:	d843031a 	ld.b	r2, (r3, 0x31a)	// regs: r2=*(0x31a)
  e0:	6884      	and	r2, r1	// regs: r2=(*(0x31a) & 0x1)
  e2:	e9020013 	bez	r2, 0x108	// if (r2 == 0x0) goto loc_108;
  e6:	d843033c 	ld.b	r2, (r3, 0x33c)	// regs: r2=*(0x33c)
  ea:	e902000f 	bez	r2, 0x108	// if (r2 == 0x0) goto loc_108;
  ee:	d84309df 	ld.b	r2, (r3, 0x9df)	// regs: r2=*(0x9df)
  f2:	c4415c61 	ins	r2, r1, 4, 1
  f6:	dc4309df 	st.b	r2, (r3, 0x9df)	// *(0x9df) = *(0x9df)
  fa:	3102      	movi	r1, 2	// regs: r1=0x2
  fc:	d84309dd 	ld.b	r2, (r3, 0x9dd)	// regs: r2=*(0x9dd)
 100:	c4415c60 	ins	r2, r1, 3, 0
 104:	dc4309dd 	st.b	r2, (r3, 0x9dd)	// *(0x9dd) = *(0x9dd)
loc_108:
 108:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
 10a:	3280      	movi	r2, 128	// regs: r2=0x80
 10c:	9372      	ld.w	r3, (r3, 0x48)	// regs: r3=*((*(0x0) + 0x48))
 10e:	4247      	lsli	r2, r2, 7	// regs: r2=0x4000
 110:	68c8      	and	r3, r2	// regs: r3=(*((*(0x0) + 0x48)) & 0x4000)
 112:	e9030004 	bez	r3, 0x11a	// if (r3 == 0x0) goto loc_11a;
 116:	e0000000 	bsr	0x0	// <lmac_irq_tx_tmo>; regs: r0=<ret lmac_irq_tx_tmo@0x116>, r1=<clobbered>
loc_11a:
 11a:	9420      	ld.w	r1, (r4, 0x0)	// regs: r1=*(0x0)
 11c:	3380      	movi	r3, 128	// regs: r3=0x80
 11e:	9152      	ld.w	r2, (r1, 0x48)	// regs: r2=*((*(0x0) + 0x48))
 120:	4365      	lsli	r3, r3, 5	// regs: r3=0x1000
 122:	688c      	and	r2, r3	// regs: r2=(*((*(0x0) + 0x48)) & 0x1000)
 124:	e9020009 	bez	r2, 0x136	// if (r2 == 0x0) goto loc_136;
 128:	115f      	lrw	r2, 0x0	// regs: r2=0x0
 12a:	b172      	st.w	r3, (r1, 0x48)	// *((*(0x0) + 0x48)) = 0x1000
 12c:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*(0x0)
 12e:	2300      	addi	r3, 1	// regs: r3=(*(0x0) + 0x1)
 130:	3b04      	cmphsi	r3, 5
 132:	082a      	bt	0x186	// if (r3 >= 0x5) goto loc_186;
 134:	b260      	st.w	r3, (r2, 0x0)	// *(0x0) = (*(0x0) + 0x1)
loc_136:
 136:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
 138:	9372      	ld.w	r3, (r3, 0x48)	// regs: r3=*((*(0x0) + 0x48))
 13a:	e4632400 	andi	r3, r3, 1024	// regs: r3=(*((*(0x0) + 0x48)) & 0x400)
 13e:	e9030004 	bez	r3, 0x146	// if (r3 == 0x0) goto loc_146;
 142:	e0000000 	bsr	0x0	// <lmac_irq_rx_end>; regs: r0=<ret lmac_irq_rx_end@0x142>, r1=<clobbered>
loc_146:
 146:	9420      	ld.w	r1, (r4, 0x0)	// regs: r1=*(0x0)
 148:	3380      	movi	r3, 128	// regs: r3=0x80
 14a:	9152      	ld.w	r2, (r1, 0x48)	// regs: r2=*((*(0x0) + 0x48))
 14c:	436b      	lsli	r3, r3, 11	// regs: r3=0x40000
 14e:	688c      	and	r2, r3	// regs: r2=(*((*(0x0) + 0x48)) & 0x40000)
 150:	e9020050 	bez	r2, 0x1f0	// if (r2 == 0x0) goto loc_1f0;
 154:	11b3      	lrw	r5, 0x0	// regs: r5=0x0
 156:	b172      	st.w	r3, (r1, 0x48)	// *((*(0x0) + 0x48)) = 0x40000
 158:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0x158>, r1=<clobbered>
 15c:	d84520ce 	ld.w	r2, (r5, 0x338)	// regs: r2=*(0x338)
 160:	d86520d1 	ld.w	r3, (r5, 0x344)	// regs: r3=*(0x344)
 164:	c4825762 	zext	r2, r2, 27, 4	// regs: r2=zext(*(0x338))
 168:	648e      	cmpne	r3, r2
 16a:	0c40      	bf	0x1ea	// if (!T) goto loc_1ea;
 16c:	3200      	movi	r2, 0	// regs: r2=0x0
 16e:	d8250378 	ld.b	r1, (r5, 0x378)	// regs: r1=*(0x378)
 172:	6c0b      	mov	r0, r2	// regs: r0=0x0
loc_174:
 174:	6441      	cmplt	r0, r1
 176:	080d      	bt	0x190	// if (T) goto loc_190;
 178:	d865226d 	ld.w	r3, (r5, 0x9b4)	// regs: r3=*(0x9b4)
 17c:	ec630008 	ori	r3, r3, 8	// regs: r3=(*(0x9b4) | 0x8)
 180:	dc65226d 	st.w	r3, (r5, 0x9b4)	// *(0x9b4) = (*(0x9b4) | 0x8)
 184:	0433      	br	0x1ea	// goto loc_1ea;
loc_186:
 186:	3300      	movi	r3, 0	// regs: r3=0x0
 188:	b260      	st.w	r3, (r2, 0x0)	// *(0x0) = 0x0
 18a:	e0000000 	bsr	0x0	// <lmac_irq_rx_subframe>; regs: r0=<ret lmac_irq_rx_subframe@0x18a>, r1=<clobbered>
 18e:	07d4      	br	0x136	// goto loc_136;
loc_190:
 190:	2217      	addi	r2, 24	// regs: r2=(r2 + 0x18)
 192:	ea8c0024 	lrw	r12, 0x0	// regs: r12=0x0
 196:	6308      	addu	r12, r2	// regs: r12=(0x0 + (r2 + 0x18))
 198:	d98c202a 	ld.w	r12, (r12, 0xa8)	// regs: r12=*(((0x0 + (r2 + 0x18)) + 0xa8))
 19c:	670e      	cmpne	r3, r12
 19e:	0c03      	bf	0x1a4	// if (!T) goto loc_1a4;
 1a0:	2000      	addi	r0, 1	// regs: r0=(r0 + 0x1)
 1a2:	07e9      	br	0x174	// goto loc_174;
loc_1a4:
 1a4:	1121      	lrw	r1, 0x0	// regs: r1=0x0
 1a6:	dc05033c 	st.b	r0, (r5, 0x33c)	// *(0x33c) = r0
 1aa:	e4432fff 	andi	r2, r3, 4095	// regs: r2=(*(0x344) & 0xfff)
 1ae:	c482482c 	lsli	r12, r2, 4	// regs: r12=((*(0x344) & 0xfff) << 0x4)
 1b2:	8943      	ld.h	r2, (r1, 0x6)	// regs: r2=*(0x6)
 1b4:	e442200f 	andi	r2, r2, 15	// regs: r2=(*(0x6) & 0xf)
 1b8:	6cb0      	or	r2, r12	// regs: r2=((*(0x6) & 0xf) | ((*(0x344) & 0xfff) << 0x4))
 1ba:	a943      	st.h	r2, (r1, 0x6)	// *(0x6) = ((*(0x6) & 0xf) | ((*(0x344) & 0xfff) << 0x4))
 1bc:	ea0c0fff 	movi	r12, 4095	// regs: r12=0xfff
 1c0:	6f32      	nor	r12, r12	// regs: r12=(~0xfff)
 1c2:	8944      	ld.h	r2, (r1, 0x8)	// regs: r2=*(0x8)
 1c4:	68b0      	and	r2, r12	// regs: r2=(*(0x8) & (~0xfff))
 1c6:	c58356e3 	zext	r3, r3, 23, 12	// regs: r3=zext(*(0x344))
 1ca:	6cc8      	or	r3, r2	// regs: r3=(zext(*(0x344)) | (*(0x8) & (~0xfff)))
 1cc:	a964      	st.h	r3, (r1, 0x8)	// *(0x8) = (zext(*(0x344)) | (*(0x8) & (~0xfff)))
 1ce:	7401      	zexth	r0, r0	// regs: r0=zext16(r0)
 1d0:	e0000000 	bsr	0x0	// <lmac_lo_table_kick>; regs: r0=<ret lmac_lo_table_kick@0x1d0>, r1=<clobbered>
 1d4:	d80520ce 	ld.w	r0, (r5, 0x338)	// regs: r0=*(0x338)
 1d8:	c4805760 	zext	r0, r0, 27, 4	// regs: r0=zext(*(0x338))
 1dc:	e0000000 	bsr	0x0	// <lmac_notify_channel_switch> // arg_bytes: 4; regs: r0=<ret lmac_notify_channel_switch@0x1dc>, r1=<clobbered>
 1e0:	d86514ed 	ld.h	r3, (r5, 0x9da)	// regs: r3=*(0x9da)
 1e4:	2300      	addi	r3, 1	// regs: r3=(*(0x9da) + 0x1)
 1e6:	dc6514ed 	st.h	r3, (r5, 0x9da)	// *(0x9da) = (*(0x9da) + 0x1)
loc_1ea:
 1ea:	3034      	movi	r0, 52	// regs: r0=0x34
 1ec:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x1ec>, r1=<clobbered>
loc_1f0:
 1f0:	9420      	ld.w	r1, (r4, 0x0)	// regs: r1=*(0x0)
 1f2:	3380      	movi	r3, 128	// regs: r3=0x80
 1f4:	9152      	ld.w	r2, (r1, 0x48)	// regs: r2=*((*(0x0) + 0x48))
 1f6:	4368      	lsli	r3, r3, 8	// regs: r3=0x8000
 1f8:	688c      	and	r2, r3	// regs: r2=(*((*(0x0) + 0x48)) & 0x8000)
 1fa:	e9020006 	bez	r2, 0x206	// if (r2 == 0x0) goto loc_206;
 1fe:	b172      	st.w	r3, (r1, 0x48)	// *((*(0x0) + 0x48)) = 0x8000
 200:	3000      	movi	r0, 0	// regs: r0=0x0
 202:	e0000000 	bsr	0x0	// <pd_timer_irq_handler> // arg_bytes: 0; regs: r0=<ret pd_timer_irq_handler@0x202>, r1=<clobbered>
loc_206:
 206:	9420      	ld.w	r1, (r4, 0x0)	// regs: r1=*(0x0)
 208:	3380      	movi	r3, 128	// regs: r3=0x80
 20a:	9152      	ld.w	r2, (r1, 0x48)	// regs: r2=*((*(0x0) + 0x48))
 20c:	436d      	lsli	r3, r3, 13	// regs: r3=0x100000
 20e:	688c      	and	r2, r3	// regs: r2=(*((*(0x0) + 0x48)) & 0x100000)
 210:	e9020005 	bez	r2, 0x21a	// if (r2 == 0x0) goto loc_21a;
 214:	b172      	st.w	r3, (r1, 0x48)	// *((*(0x0) + 0x48)) = 0x100000
 216:	e0000000 	bsr	0x0	// <lmac_phy_soft_reset> // arg_bytes: 0; regs: r0=<ret lmac_phy_soft_reset@0x216>, r1=<clobbered>
loc_21a:
 21a:	1492      	pop	r4-r5, r15
 21c:	00000000 	.long	0x00000000	// <LMAC>
 220:	00000000 	.long	0x00000000	// <ah_lmac>
 224:	00000000 	.long	0x00000000	// <.bss.rx_subframe_cnt.13196>
 228:	00000000 	.long	0x00000000	// <ah_lmac+0x332>

Disassembly of section .text.lmac_notify_testmode_state:

00000000 <lmac_notify_testmode_state>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	dc0e0003 	st.b	r0, (r14, 0x3)	// local_1 = <arg0>
   8:	1006      	lrw	r0, 0x0	// regs: r0=0x0
   a:	d9802009 	ld.w	r12, (r0, 0x24)	// regs: r12=*(0x24)
   e:	e90c0007 	bez	r12, 0x1c	// if (r12 == 0x0) goto loc_1c;
  12:	3300      	movi	r3, 0	// regs: r3=0x0
  14:	e44e0002 	addi	r2, r14, 3	// regs: r2=((sp - 0x4) + 0x3)
  18:	3111      	movi	r1, 17	// regs: r1=0x11
  1a:	7bf1      	jsr	r12
loc_1c:
  1c:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  1e:	1490      	pop	r15
  20:	00000000 	.long	0x00000000	// <ah_ops>

Disassembly of section .text.lmac_ioctl:

00000000 <lmac_ioctl>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	d9802012 	ld.w	r12, (r0, 0x48)	// regs: r12=*(<arg0> + 0x48)
   6:	e90c0004 	bez	r12, 0xe	// if (r12 == 0x0) goto loc_e;
   a:	7bf1      	jsr	r12
loc_c:
   c:	1490      	pop	r15
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  12:	07fd      	br	0xc	// goto loc_c;

Disassembly of section .text.lmac_ah_init:

00000000 <lmac_ah_init>: // arg_bytes: 4
   0:	14d5      	push	r4-r8, r15
   2:	007c      	lrw	r3, 0x40026000	// regs: r3=0x40026000
   4:	009c      	lrw	r4, 0xe000e100	// regs: r4=0xe000e100
   6:	9342      	ld.w	r2, (r3, 0x8)	// regs: r2=*(0x40026008)
   8:	3a94      	bclri	r2, 20	// regs: r2=(*(0x40026008) & ~(0x1 << 0x14))
   a:	b342      	st.w	r2, (r3, 0x8)	// *(0x40026008) = (*(0x40026008) & ~(0x1 << 0x14))
   c:	9342      	ld.w	r2, (r3, 0x8)	// regs: r2=*(0x40026008)
   e:	3ab4      	bseti	r2, 20	// regs: r2=(*(0x40026008) | (0x1 << 0x14))
  10:	b342      	st.w	r2, (r3, 0x8)	// *(0x40026008) = (*(0x40026008) | (0x1 << 0x14))
  12:	3380      	movi	r3, 128	// regs: r3=0x80
  14:	4370      	lsli	r3, r3, 16	// regs: r3=0x800000
  16:	dc642020 	st.w	r3, (r4, 0x80)	// *(0xe000e180) = 0x800000
  1a:	3380      	movi	r3, 128	// regs: r3=0x80
  1c:	4372      	lsli	r3, r3, 18	// regs: r3=0x2000000
  1e:	dc642020 	st.w	r3, (r4, 0x80)	// *(0xe000e180) = 0x2000000
  22:	6e03      	mov	r8, r0	// regs: r8=<arg0>
  24:	0163      	lrw	r3, 0x0	// regs: r3=0x0
  26:	01c2      	lrw	r6, 0x0	// regs: r6=0x0
  28:	01a2      	lrw	r5, 0x0	// regs: r5=0x0
  2a:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
  2c:	3300      	movi	r3, 0	// regs: r3=0x0
  2e:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  30:	b272      	st.w	r3, (r2, 0x48)	// *((*(0x0) + 0x48)) = 0xffffffff
  32:	e0000000 	bsr	0x0	// <lf_timer_init>; regs: r0=<ret lf_timer_init@0x32>, r1=<clobbered>
  36:	3380      	movi	r3, 128	// regs: r3=0x80
  38:	4368      	lsli	r3, r3, 8	// regs: r3=0x8000
  3a:	3250      	movi	r2, 80	// regs: r2=0x50
  3c:	3100      	movi	r1, 0	// regs: r1=0x0
  3e:	dc642020 	st.w	r3, (r4, 0x80)	// *(0xe000e180) = 0x8000
  42:	6c1b      	mov	r0, r6	// regs: r0=0x0
  44:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x44>, r1=<clobbered>
  48:	3348      	movi	r3, 72	// regs: r3=0x48
  4a:	a668      	st.b	r3, (r6, 0x8)	// *(0x8) = 0x48
  4c:	3320      	movi	r3, 32	// regs: r3=0x20
  4e:	a669      	st.b	r3, (r6, 0x9)	// *(0x9) = 0x20
  50:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  52:	b663      	st.w	r3, (r6, 0xc)	// *(0xc) = 0x0
  54:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  56:	b664      	st.w	r3, (r6, 0x10)	// *(0x10) = 0x0
  58:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  5a:	b665      	st.w	r3, (r6, 0x14)	// *(0x14) = 0x0
  5c:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  5e:	b666      	st.w	r3, (r6, 0x18)	// *(0x18) = 0x0
  60:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  62:	b66b      	st.w	r3, (r6, 0x2c)	// *(0x2c) = 0x0
  64:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  66:	b66c      	st.w	r3, (r6, 0x30)	// *(0x30) = 0x0
  68:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  6a:	b66d      	st.w	r3, (r6, 0x34)	// *(0x34) = 0x0
  6c:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  6e:	b66e      	st.w	r3, (r6, 0x38)	// *(0x38) = 0x0
  70:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  72:	b66f      	st.w	r3, (r6, 0x3c)	// *(0x3c) = 0x0
  74:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  76:	b670      	st.w	r3, (r6, 0x40)	// *(0x40) = 0x0
  78:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  7a:	b66a      	st.w	r3, (r6, 0x28)	// *(0x28) = 0x0
  7c:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  7e:	b671      	st.w	r3, (r6, 0x44)	// *(0x44) = 0x0
  80:	016b      	lrw	r3, 0x0	// regs: r3=0x0
  82:	b672      	st.w	r3, (r6, 0x48)	// *(0x48) = 0x0
  84:	3301      	movi	r3, 1	// regs: r3=0x1
  86:	a66a      	st.b	r3, (r6, 0xa)	// *(0xa) = 0x1
  88:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_bios_id>; regs: r0=<ret sysctrl_efuse_get_bios_id@0x88>, r1=<clobbered>
  8c:	a500      	st.b	r0, (r5, 0x0)	// *(0x0) = <ret sysctrl_efuse_get_bios_id@0x88>
  8e:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_xtal_id>; regs: r0=<ret sysctrl_efuse_get_xtal_id@0x8e>, r1=<clobbered>
  92:	a501      	st.b	r0, (r5, 0x1)	// *(0x1) = <ret sysctrl_efuse_get_xtal_id@0x8e>
  94:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_dcn>; regs: r0=<ret sysctrl_efuse_get_dcn@0x94>, r1=<clobbered>
  98:	a508      	st.b	r0, (r5, 0x8)	// *(0x8) = <ret sysctrl_efuse_get_dcn@0x94>
  9a:	e0000000 	bsr	0x0	// <sysctrl_efuse_crc_check>; regs: r0=<ret sysctrl_efuse_crc_check@0x9a>, r1=<clobbered>
  9e:	a502      	st.b	r0, (r5, 0x2)	// *(0x2) = <ret sysctrl_efuse_crc_check@0x9a>
  a0:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_module_crc>; regs: r0=<ret sysctrl_efuse_get_module_crc@0xa0>, r1=<clobbered>
  a4:	e90001c6 	bez	r0, 0x430	// if (r0 == 0x0) goto loc_430;
  a8:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_test_temp>; regs: r0=<ret sysctrl_efuse_get_test_temp@0xa8>, r1=<clobbered>
  ac:	6c43      	mov	r1, r0	// regs: r1=<ret sysctrl_efuse_get_test_temp@0xa8>
  ae:	a509      	st.b	r0, (r5, 0x9)	// *(0x9) = <ret sysctrl_efuse_get_test_temp@0xa8>
  b0:	0116      	lrw	r0, 0x0	// regs: r0=0x0
  b2:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xb2>, r1=<clobbered>
loc_b6:
  b6:	d8654002 	ld.bs	r3, (r5, 0x2)	// regs: r3=*(r5 + 0x2)
  ba:	e92301c1 	bnez	r3, 0x43c	// if (r3 != 0x0) goto loc_43c;
  be:	8560      	ld.b	r3, (r5, 0x0)	// regs: r3=*(r5)
  c0:	3b02      	cmphsi	r3, 3
  c2:	0dbd      	bf	0x43c	// if (r3 < 0x3) goto loc_43c;
  c4:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_vref>; regs: r0=<ret sysctrl_efuse_get_vref@0xc4>, r1=<clobbered>
  c8:	a504      	st.b	r0, (r5, 0x4)	// *(r5 + 0x4) = <ret sysctrl_efuse_get_vref@0xc4>
  ca:	e0000000 	bsr	0x0	// <pmu_vref_vol_set_sec>; regs: r0=<ret pmu_vref_vol_set_sec@0xca>, r1=<clobbered>
  ce:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_xo_vbg>; regs: r0=<ret sysctrl_efuse_get_xo_vbg@0xce>, r1=<clobbered>
  d2:	e0000000 	bsr	0x0	// <pmu_xo_vbg_set_sec>; regs: r0=<ret pmu_xo_vbg_set_sec@0xd2>, r1=<clobbered>
loc_d6:
  d6:	8568      	ld.b	r3, (r5, 0x8)	// regs: r3=*(r5 + 0x8)
  d8:	e92301b5 	bnez	r3, 0x442	// if (r3 != 0x0) goto loc_442;
  dc:	3007      	movi	r0, 7	// regs: r0=0x7
  de:	e0000000 	bsr	0x0	// <pmu_vdd_vol_set_sec>; regs: r0=<ret pmu_vdd_vol_set_sec@0xde>, r1=<clobbered>
loc_e2:
  e2:	3314      	movi	r3, 20	// regs: r3=0x14
  e4:	3214      	movi	r2, 20	// regs: r2=0x14
  e6:	6c63      	mov	r1, r8	// regs: r1=r8
  e8:	0203      	lrw	r0, 0x0	// regs: r0=0x0
  ea:	a566      	st.b	r3, (r5, 0x6)	// *(r5 + 0x6) = 0x14
  ec:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xec>, r1=<clobbered>
  f0:	e0000000 	bsr	0x0	// <lmac_cfg_init>; regs: r0=<ret lmac_cfg_init@0xf0>, r1=<clobbered>
  f4:	e0000000 	bsr	0x0	// <lmac_rc_init>; regs: r0=<ret lmac_rc_init@0xf4>, r1=<clobbered>
  f8:	e0000000 	bsr	0x0	// <ah_wphy_open>; regs: r0=<ret ah_wphy_open@0xf8>, r1=<clobbered>
  fc:	e0000000 	bsr	0x0	// <ah_wphy_enable>; regs: r0=<ret ah_wphy_enable@0xfc>, r1=<clobbered>
 100:	e0000000 	bsr	0x0	// <ah_wphy_auto_sig_err_rst_enable>; regs: r0=<ret ah_wphy_auto_sig_err_rst_enable@0x100>, r1=<clobbered>
 104:	e0000000 	bsr	0x0	// <ah_init_dbgpath_device>; regs: r0=<ret ah_init_dbgpath_device@0x104>, r1=<clobbered>
 108:	e0000000 	bsr	0x0	// <ah_rf_open>; regs: r0=<ret ah_rf_open@0x108>, r1=<clobbered>
 10c:	8567      	ld.b	r3, (r5, 0x7)	// regs: r3=*(r5 + 0x7)
 10e:	3b41      	cmpnei	r3, 1
 110:	09a6      	bt	0x45c	// if (r3 != 0x1) goto loc_45c;
 112:	3308      	movi	r3, 8	// regs: r3=0x8
 114:	ea021e96 	movi	r2, 7830	// regs: r2=0x1e96
 118:	ea011da6 	movi	r1, 7590	// regs: r1=0x1da6
loc_11c:
 11c:	0300      	lrw	r0, 0x0	// regs: r0=0x0
 11e:	e0000000 	bsr	0x0	// <lmac_cfg_set_freq_range>; regs: r0=<ret lmac_cfg_set_freq_range@0x11e>, r1=<clobbered>
 122:	3001      	movi	r0, 1	// regs: r0=0x1
 124:	e0000000 	bsr	0x0	// <ah_rf_lo_table_ctrl>; regs: r0=<ret ah_rf_lo_table_ctrl@0x124>, r1=<clobbered>
 128:	d8682002 	ld.w	r3, (r8, 0x8)	// regs: r3=*(r8 + 0x8)
 12c:	0293      	lrw	r4, 0x0	// regs: r4=0x0
 12e:	e903002e 	bez	r3, 0x18a	// if (r3 == 0x0) goto loc_18a;
 132:	d8682003 	ld.w	r3, (r8, 0xc)	// regs: r3=*(r8 + 0xc)
 136:	e903002a 	bez	r3, 0x18a	// if (r3 == 0x0) goto loc_18a;
 13a:	d8642236 	ld.w	r3, (r4, 0x8d8)	// regs: r3=*(0x8d8)
 13e:	dc642279 	st.w	r3, (r4, 0x9e4)	// *(0x9e4) = *(0x8d8)
 142:	d8642237 	ld.w	r3, (r4, 0x8dc)	// regs: r3=*(0x8dc)
 146:	dc64227a 	st.w	r3, (r4, 0x9e8)	// *(0x9e8) = *(0x8dc)
 14a:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x14a>, r1=<clobbered>
 14e:	d824227a 	ld.w	r1, (r4, 0x9e8)	// regs: r1=*(0x9e8)
 152:	d8042279 	ld.w	r0, (r4, 0x9e4)	// regs: r0=*(0x9e4)
 156:	e0000000 	bsr	0x0	// <ah_tdma_set_buff>; regs: r0=<ret ah_tdma_set_buff@0x156>, r1=<clobbered>
 15a:	3101      	movi	r1, 1	// regs: r1=0x1
 15c:	6c07      	mov	r0, r1	// regs: r0=0x1
 15e:	e0000000 	bsr	0x0	// <ah_tdma_set_mode>; regs: r0=<ret ah_tdma_set_mode@0x15e>, r1=<clobbered>
 162:	3004      	movi	r0, 4	// regs: r0=0x4
 164:	e0000000 	bsr	0x0	// <ah_set_dbgpath_device_path_mode>; regs: r0=<ret ah_set_dbgpath_device_path_mode@0x164>, r1=<clobbered>
 168:	3000      	movi	r0, 0	// regs: r0=0x0
 16a:	e0000000 	bsr	0x0	// <ah_config_dbgpath_device_dmaend_cond>; regs: r0=<ret ah_config_dbgpath_device_dmaend_cond@0x16a>, r1=<clobbered>
 16e:	d864227a 	ld.w	r3, (r4, 0x9e8)	// regs: r3=*(0x9e8)
 172:	4b1f      	lsri	r0, r3, 31	// regs: r0=(*(0x9e8) >> 0x1f)
 174:	600c      	addu	r0, r3	// regs: r0=((*(0x9e8) >> 0x1f) + *(0x9e8))
 176:	5001      	asri	r0, r0, 1	// regs: r0=(((*(0x9e8) >> 0x1f) + *(0x9e8)) >> 0x1)
 178:	e0000000 	bsr	0x0	// <ah_tdma_set_trig_len>; regs: r0=<ret ah_tdma_set_trig_len@0x178>, r1=<clobbered>
 17c:	d86409f4 	ld.b	r3, (r4, 0x9f4)	// regs: r3=*(0x9f4)
 180:	3201      	movi	r2, 1	// regs: r2=0x1
 182:	c4625c00 	ins	r3, r2, 0, 0
 186:	dc6409f4 	st.b	r3, (r4, 0x9f4)	// *(0x9f4) = *(0x9f4)
loc_18a:
 18a:	d80411b6 	ld.h	r0, (r4, 0x36c)	// regs: r0=*(0x36c)
 18e:	c4a05520 	zext	r0, r0, 9, 5	// regs: r0=zext(*(0x36c))
 192:	e0000000 	bsr	0x0	// <ah_rfdigicali_tx_pwr>; regs: r0=<ret ah_rfdigicali_tx_pwr@0x192>, r1=<clobbered>
 196:	3001      	movi	r0, 1	// regs: r0=0x1
 198:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_gain_idx_src>; regs: r0=<ret ah_rfdigicali_config_rx_gain_idx_src@0x198>, r1=<clobbered>
 19c:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_filter_auto>; regs: r0=<ret ah_rfdigicali_config_rx_filter_auto@0x19c>, r1=<clobbered>
 1a0:	3108      	movi	r1, 8	// regs: r1=0x8
 1a2:	6c07      	mov	r0, r1	// regs: r0=0x8
 1a4:	3210      	movi	r2, 16	// regs: r2=0x10
 1a6:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_hw_rx_dcoc>; regs: r0=<ret ah_rfdigicali_config_hw_rx_dcoc@0x1a6>, r1=<clobbered>
 1aa:	e0000000 	bsr	0x0	// <ah_rfdigicali_rx_dcoc_hw_trig_en>; regs: r0=<ret ah_rfdigicali_rx_dcoc_hw_trig_en@0x1aa>, r1=<clobbered>
 1ae:	3303      	movi	r3, 3	// regs: r3=0x3
 1b0:	3003      	movi	r0, 3	// regs: r0=0x3
 1b2:	dc640309 	st.b	r3, (r4, 0x309)	// *(0x309) = 0x3
 1b6:	e0000000 	bsr	0x0	// <ah_wphy_pri_channel_cfg>; regs: r0=<ret ah_wphy_pri_channel_cfg@0x1b6>, r1=<clobbered>
 1ba:	d8040308 	ld.b	r0, (r4, 0x308)	// regs: r0=*(0x308)
 1be:	e0000000 	bsr	0x0	// <ah_wphy_bw_cfg>; regs: r0=<ret ah_wphy_bw_cfg@0x1be>, r1=<clobbered>
 1c2:	8567      	ld.b	r3, (r5, 0x7)	// regs: r3=*(r5 + 0x7)
 1c4:	3b41      	cmpnei	r3, 1
 1c6:	0969      	bt	0x498	// if (r3 != 0x1) goto loc_498;
 1c8:	3000      	movi	r0, 0	// regs: r0=0x0
loc_1ca:
 1ca:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_rx_conv_gain>; regs: r0=<ret sysctrl_efuse_get_rx_conv_gain@0x1ca>, r1=<clobbered>
 1ce:	6dc3      	mov	r7, r0	// regs: r7=<ret sysctrl_efuse_get_rx_conv_gain@0x1ca>
 1d0:	e9000008 	bez	r0, 0x1e0	// if (r0 == 0x0) goto loc_1e0;
 1d4:	e0000000 	bsr	0x0	// <ah_wphy_rx_conv_gain_config>; regs: r0=<ret ah_wphy_rx_conv_gain_config@0x1d4>, r1=<clobbered>
 1d8:	6c5f      	mov	r1, r7	// regs: r1=<ret sysctrl_efuse_get_rx_conv_gain@0x1ca>
 1da:	031d      	lrw	r0, 0x0	// regs: r0=0x0
 1dc:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1dc>, r1=<clobbered>
loc_1e0:
 1e0:	3700      	movi	r7, 0	// regs: r7=0x0
loc_1e2:
 1e2:	741c      	zextb	r0, r7	// regs: r0=zext8(r7)
 1e4:	e0000000 	bsr	0x0	// <ah_rfdigicali_get_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_get_tx_digi_gain@0x1e4>, r1=<clobbered>
 1e8:	5f7c      	addu	r3, r7, r7	// regs: r3=(r7 + r7)
 1ea:	135d      	lrw	r2, 0x0	// regs: r2=0x0
 1ec:	2700      	addi	r7, 1	// regs: r7=(r7 + 0x1)
 1ee:	60c8      	addu	r3, r2	// regs: r3=((r7 + r7) )
 1f0:	3f46      	cmpnei	r7, 6
 1f2:	dc031341 	st.h	r0, (r3, 0x682)	// *((((r7 + r7) ) + 0x682)) = <ret ah_rfdigicali_get_tx_digi_gain@0x1e4>
 1f6:	0bf6      	bt	0x1e2	// if (r7 != 0x6) goto loc_1e2;
 1f8:	ea038003 	movi	r3, 32771	// regs: r3=0x8003
 1fc:	c5e34903 	rotli	r3, r3, 15	// regs: r3=rotl(0x8003, 0xf)
 200:	3700      	movi	r7, 0	// regs: r7=0x0
 202:	936a      	ld.w	r3, (r3, 0x28)	// regs: r3=*((rotl(0x8003, 0xf) + 0x28))
 204:	c66356e3 	zext	r3, r3, 23, 19	// regs: r3=zext(*((rotl(0x8003, 0xf) + 0x28)))
 208:	6c5f      	mov	r1, r7	// regs: r1=0x0
 20a:	1304      	lrw	r0, 0x0	// regs: r0=0x0
 20c:	dc64068f 	st.b	r3, (r4, 0x68f)	// *(0x68f) = zext(*((rotl(0x8003, 0xf) + 0x28)))
 210:	e0000000 	bsr	0x0	// <lmac_set_bgrssi>; regs: r0=<ret lmac_set_bgrssi@0x210>, r1=<clobbered>
 214:	1334      	lrw	r1, 0x0	// regs: r1=0x0
 216:	5917      	subi	r0, r1, 6	// regs: r0=0xfffffffa
 218:	e0000000 	bsr	0x0	// <ah_wphy_rx_gain_para_get>; regs: r0=<ret ah_wphy_rx_gain_para_get@0x218>, r1=<clobbered>
 21c:	1333      	lrw	r1, 0x0	// regs: r1=0x0
 21e:	6c1f      	mov	r0, r7	// regs: r0=0x0
 220:	e0000000 	bsr	0x0	// <ah_ce_init>; regs: r0=<ret ah_ce_init@0x220>, r1=<clobbered>
 224:	d8240316 	ld.b	r1, (r4, 0x316)	// regs: r1=*(0x316)
 228:	d8040308 	ld.b	r0, (r4, 0x308)	// regs: r0=*(0x308)
 22c:	e0000000 	bsr	0x0	// <lmac_hw_init>; regs: r0=<ret lmac_hw_init@0x22c>, r1=<clobbered>
 230:	e0000000 	bsr	0x0	// <lmac_tx_init>; regs: r0=<ret lmac_tx_init@0x230>, r1=<clobbered>
 234:	6c23      	mov	r0, r8	// regs: r0=r8
 236:	e0000000 	bsr	0x0	// <lmac_rx_init>; regs: r0=<ret lmac_rx_init@0x236>, r1=<clobbered>
 23a:	e0000000 	bsr	0x0	// <lmac_test_init>; regs: r0=<ret lmac_test_init@0x23a>, r1=<clobbered>
 23e:	e0000000 	bsr	0x0	// <lmac_dsleep_init>; regs: r0=<ret lmac_dsleep_init@0x23e>, r1=<clobbered>
 242:	132b      	lrw	r1, 0x0	// regs: r1=0x0
 244:	1346      	lrw	r2, 0x0	// regs: r2=0x0
 246:	3017      	movi	r0, 23	// regs: r0=0x17
 248:	e0000000 	bsr	0x0	// <request_irq>; regs: r0=<ret request_irq@0x248>, r1=<clobbered>
 24c:	1251      	lrw	r2, 0xe000e100	// regs: r2=0xe000e100
 24e:	3380      	movi	r3, 128	// regs: r3=0x80
 250:	4370      	lsli	r3, r3, 16	// regs: r3=0x800000
 252:	b260      	st.w	r3, (r2, 0x0)	// *(0xe000e100) = 0x800000
 254:	e0000000 	bsr	0x0	// <lmac_chip_monitor> // arg_bytes: 0; regs: r0=<ret lmac_chip_monitor@0x254>, r1=<clobbered>
 258:	6c5f      	mov	r1, r7	// regs: r1=0x0
 25a:	1306      	lrw	r0, 0x0	// regs: r0=0x0
 25c:	e0000000 	bsr	0x0	// <os_sema_init>; regs: r0=<ret os_sema_init@0x25c>, r1=<clobbered>
 260:	3340      	movi	r3, 64	// regs: r3=0x40
 262:	dc6422a2 	st.w	r3, (r4, 0xa88)	// *(0xa88) = 0x40
 266:	dce422a0 	st.w	r7, (r4, 0xa80)	// *(0xa80) = 0x0
 26a:	dce422a1 	st.w	r7, (r4, 0xa84)	// *(0xa84) = 0x0
 26e:	1342      	lrw	r2, 0x0	// regs: r2=0x0
 270:	127b      	lrw	r3, 0x0	// regs: r3=0x0
 272:	e423099f 	addi	r1, r3, 2464	// regs: r1=0x9a0
 276:	1301      	lrw	r0, 0x0	// regs: r0=0x0
 278:	e0000000 	bsr	0x0	// <os_task_init>; regs: r0=<ret os_task_init@0x278>, r1=<clobbered>
 27c:	3180      	movi	r1, 128	// regs: r1=0x80
 27e:	4123      	lsli	r1, r1, 3	// regs: r1=0x400
 280:	121f      	lrw	r0, 0x0	// regs: r0=0x0
 282:	e0000000 	bsr	0x0	// <os_task_set_stacksize>; regs: r0=<ret os_task_set_stacksize@0x282>, r1=<clobbered>
 286:	3130      	movi	r1, 48	// regs: r1=0x30
 288:	121d      	lrw	r0, 0x0	// regs: r0=0x0
 28a:	e0000000 	bsr	0x0	// <os_task_set_priority>; regs: r0=<ret os_task_set_priority@0x28a>, r1=<clobbered>
 28e:	121c      	lrw	r0, 0x0	// regs: r0=0x0
 290:	e0000000 	bsr	0x0	// <os_task_run>; regs: r0=<ret os_task_run@0x290>, r1=<clobbered>
 294:	6c5f      	mov	r1, r7	// regs: r1=0x0
 296:	121b      	lrw	r0, 0x0	// regs: r0=0x0
 298:	e0000000 	bsr	0x0	// <os_sema_init>; regs: r0=<ret os_sema_init@0x298>, r1=<clobbered>
 29c:	1270      	lrw	r3, 0x0	// regs: r3=0x0
 29e:	e42309c3 	addi	r1, r3, 2500	// regs: r1=0x9c4
 2a2:	1259      	lrw	r2, 0x0	// regs: r2=0x0
 2a4:	1219      	lrw	r0, 0x0	// regs: r0=0x0
 2a6:	e0000000 	bsr	0x0	// <os_task_init>; regs: r0=<ret os_task_init@0x2a6>, r1=<clobbered>
 2aa:	3180      	movi	r1, 128	// regs: r1=0x80
 2ac:	4122      	lsli	r1, r1, 2	// regs: r1=0x200
 2ae:	1218      	lrw	r0, 0x0	// regs: r0=0x0
 2b0:	e0000000 	bsr	0x0	// <os_task_set_stacksize>; regs: r0=<ret os_task_set_stacksize@0x2b0>, r1=<clobbered>
 2b4:	3110      	movi	r1, 16	// regs: r1=0x10
 2b6:	1216      	lrw	r0, 0x0	// regs: r0=0x0
 2b8:	e0000000 	bsr	0x0	// <os_task_set_priority>; regs: r0=<ret os_task_set_priority@0x2b8>, r1=<clobbered>
 2bc:	1214      	lrw	r0, 0x0	// regs: r0=0x0
 2be:	e0000000 	bsr	0x0	// <os_task_run>; regs: r0=<ret os_task_run@0x2be>, r1=<clobbered>
 2c2:	1274      	lrw	r3, 0x0	// regs: r3=0x0
 2c4:	3201      	movi	r2, 1	// regs: r2=0x1
 2c6:	e403106f 	subi	r0, r3, 112	// regs: r0=0xffffff90
 2ca:	1233      	lrw	r1, 0x0	// regs: r1=0x0
 2cc:	e0000000 	bsr	0x0	// <os_timer_init>; regs: r0=<ret os_timer_init@0x2cc>, r1=<clobbered>
 2d0:	d82420e5 	ld.w	r1, (r4, 0x394)	// regs: r1=*(0x394)
 2d4:	1211      	lrw	r0, 0x0	// regs: r0=0x0
 2d6:	e0000000 	bsr	0x0	// <os_timer_start>; regs: r0=<ret os_timer_start@0x2d6>, r1=<clobbered>
 2da:	126e      	lrw	r3, 0x0	// regs: r3=0x0
 2dc:	6c9f      	mov	r2, r7	// regs: r2=0x0
 2de:	e4031053 	subi	r0, r3, 84	// regs: r0=0xffffffac
 2e2:	122f      	lrw	r1, 0x0	// regs: r1=0x0
 2e4:	e0000000 	bsr	0x0	// <os_timer_init>; regs: r0=<ret os_timer_init@0x2e4>, r1=<clobbered>
 2e8:	8520      	ld.b	r1, (r5, 0x0)	// regs: r1=*(r5)
 2ea:	120e      	lrw	r0, 0x0	// regs: r0=0x0
 2ec:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2ec>, r1=<clobbered>
 2f0:	8521      	ld.b	r1, (r5, 0x1)	// regs: r1=*(r5 + 0x1)
 2f2:	120d      	lrw	r0, 0x0	// regs: r0=0x0
 2f4:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2f4>, r1=<clobbered>
 2f8:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_smt_dat>; regs: r0=<ret sysctrl_efuse_get_smt_dat@0x2f8>, r1=<clobbered>
 2fc:	6c43      	mov	r1, r0	// regs: r1=<ret sysctrl_efuse_get_smt_dat@0x2f8>
 2fe:	e92000d5 	bnez	r0, 0x4a8	// if (r0 != 0x0) goto loc_4a8;
 302:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_sip_ind>; regs: r0=<ret sysctrl_efuse_get_sip_ind@0x302>, r1=<clobbered>
 306:	e92000cf 	bnez	r0, 0x4a4	// if (r0 != 0x0) goto loc_4a4;
 30a:	1208      	lrw	r0, 0x0	// regs: r0=0x0
loc_30c:
 30c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x30c>, r1=<clobbered>
loc_310:
 310:	e0000000 	bsr	0x0	// <dsleep_cfg_get>; regs: r0=<ret dsleep_cfg_get@0x310>, r1=<clobbered>
 314:	dc042233 	st.w	r0, (r4, 0x8cc)	// *(0x8cc) = <ret dsleep_cfg_get@0x310>
 318:	e9000016 	bez	r0, 0x344	// if (r0 == 0x0) goto loc_344;
 31c:	d860025b 	ld.b	r3, (r0, 0x25b)	// regs: r3=*(<ret dsleep_cfg_get@0x310> + 0x25b)
 320:	e4632003 	andi	r3, r3, 3	// regs: r3=(*(<ret dsleep_cfg_get@0x310> + 0x25b) & 0x3)
 324:	3b42      	cmpnei	r3, 2
 326:	0807      	bt	0x334	// if (r3 != 0x2) goto loc_334;
 328:	3005      	movi	r0, 5	// regs: r0=0x5
 32a:	e0000000 	bsr	0x0	// <pmu_vdd13c_vol_set_sec>; regs: r0=<ret pmu_vdd13c_vol_set_sec@0x32a>, r1=<clobbered>
 32e:	3005      	movi	r0, 5	// regs: r0=0x5
 330:	e0000000 	bsr	0x0	// <pmu_vdd13b_vol_set_sec>; regs: r0=<ret pmu_vdd13b_vol_set_sec@0x330>, r1=<clobbered>
loc_334:
 334:	d8642233 	ld.w	r3, (r4, 0x8cc)	// regs: r3=*(0x8cc)
 338:	d8634a52 	ld.bs	r3, (r3, 0xa52)	// regs: r3=*((*(0x8cc) + 0xa52))
 33c:	e9030004 	bez	r3, 0x344	// if (r3 == 0x0) goto loc_344;
 340:	dc64031e 	st.b	r3, (r4, 0x31e)	// *(0x31e) = *((*(0x8cc) + 0xa52))
loc_344:
 344:	3101      	movi	r1, 1	// regs: r1=0x1
 346:	3020      	movi	r0, 32	// regs: r0=0x20
 348:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x348>, r1=<clobbered>
 34c:	3100      	movi	r1, 0	// regs: r1=0x0
 34e:	3020      	movi	r0, 32	// regs: r0=0x20
 350:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x350>, r1=<clobbered>
 354:	3000      	movi	r0, 0	// regs: r0=0x0
 356:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x356>, r1=<clobbered>
 35a:	d8640875 	ld.b	r3, (r4, 0x875)	// regs: r3=*(0x875)
 35e:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(0x875) & 0x4)
 362:	b4c0      	st.w	r6, (r4, 0x0)	// *(0x0) = r6
 364:	e903000b 	bez	r3, 0x37a	// if (r3 == 0x0) goto loc_37a;
 368:	1111      	lrw	r0, 0x0	// regs: r0=0x0
 36a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x36a>, r1=<clobbered>
 36e:	3300      	movi	r3, 0	// regs: r3=0x0
 370:	321f      	movi	r2, 31	// regs: r2=0x1f
 372:	312a      	movi	r1, 42	// regs: r1=0x2a
 374:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(0x0)
 376:	e0000000 	bsr	0x0	// <lmac_ioctl> // arg_bytes: 4; regs: r0=<ret lmac_ioctl@0x376>, r1=<clobbered>
loc_37a:
 37a:	3001      	movi	r0, 1	// regs: r0=0x1
 37c:	e0000000 	bsr	0x0	// <skbpool_freesize>; regs: r0=<ret skbpool_freesize@0x37c>, r1=<clobbered>
 380:	480b      	lsri	r0, r0, 11	// regs: r0=(<ret skbpool_freesize@0x37c> >> 0xb)
 382:	dc0422ec 	st.w	r0, (r4, 0xbb0)	// *(0xbb0) = (<ret skbpool_freesize@0x37c> >> 0xb)
 386:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(0x0)
 388:	1495      	pop	r4-r8, r15
 38a:	0000      	.short	0x0000
 38c:	40026000 	.long	0x40026000
 390:	e000e100 	.long	0xe000e100
 394:	00000000 	.long	0x00000000	// <LMAC>
 398:	00000000 	.long	0x00000000	// <ah_ops>
 39c:	00000000 	.long	0x00000000	// <module_efuse_info>
 3a0:	00000000 	.long	0x00000000	// <lmac_ah_open>
 3a4:	00000000 	.long	0x00000000	// <lmac_ah_close>
 3a8:	00000000 	.long	0x00000000	// <lmac_ah_tx>
 3ac:	00000000 	.long	0x00000000	// <lmac_ah_test_tx>
 3b0:	00000000 	.long	0x00000000	// <lmac_cfg_set_freq_range>
 3b4:	00000000 	.long	0x00000000	// <lmac_cfg_set_freq>
 3b8:	00000000 	.long	0x00000000	// <lmac_ah_start_acs>
 3bc:	00000000 	.long	0x00000000	// <lmac_ah_add_sta>
 3c0:	00000000 	.long	0x00000000	// <lmac_ah_del_sta>
 3c4:	00000000 	.long	0x00000000	// <lmac_ah_set_key>
 3c8:	00000000 	.long	0x00000000	// <lmac_cfg_set_chanlist>
 3cc:	00000000 	.long	0x00000000	// <lmac_psm_enter>
 3d0:	00000000 	.long	0x00000000	// <lmac_ah_ioctl>
 3d4:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_init.str1.1>
 3d8:	00000000 	.long	0x00000000	// <ah_lmac+0x8d0>
 3dc:	00000000 	.long	0x00000000	// <ah_lmac>
 3e0:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_init.str1.1+0x2f>
 3e4:	00000000 	.long	0x00000000	// <ah_lmac+0x327>
 3e8:	00000000 	.long	0x00000000	// <ah_lmac+0x4>
 3ec:	00000000 	.long	0x00000000	// <lmac_irq_handler>
 3f0:	00000000 	.long	0x00000000	// <ah_lmac+0xb90>
 3f4:	00000000 	.long	0x00000000	// <.text.lmac_main_task>
 3f8:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_init.str1.1+0x45>
 3fc:	00000000 	.long	0x00000000	// <ah_lmac+0x9a0>
 400:	00000000 	.long	0x00000000	// <ah_lmac+0x9bc>
 404:	00000000 	.long	0x00000000	// <.text.lmac_print_task>
 408:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_init.str1.1+0x4f>
 40c:	00000000 	.long	0x00000000	// <ah_lmac+0x9c4>
 410:	00000000 	.long	0x00000000	// <ah_lmac+0xa80>
 414:	00000000 	.long	0x00000000	// <.text.lmac_tick_cb>
 418:	00000000 	.long	0x00000000	// <ah_lmac+0xa10>
 41c:	00000000 	.long	0x00000000	// <.text.lmac_scan_probe_cb>
 420:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_init.str1.1+0x5a>
 424:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_init.str1.1+0x6a>
 428:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_init.str1.1+0x78>
 42c:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_init.str1.1+0xbb>
loc_430:
 430:	331e      	movi	r3, 30	// regs: r3=0x1e
 432:	1103      	lrw	r0, 0x0	// regs: r0=0x0
 434:	a569      	st.b	r3, (r5, 0x9)	// *(r5 + 0x9) = 0x1e
 436:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x436>, r1=<clobbered>
 43a:	063e      	br	0xb6	// goto loc_b6;
loc_43c:
 43c:	3304      	movi	r3, 4	// regs: r3=0x4
 43e:	a564      	st.b	r3, (r5, 0x4)	// *(r5 + 0x4) = 0x4
 440:	064b      	br	0xd6	// goto loc_d6;
loc_442:
 442:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_vdd13_trim_valid>; regs: r0=<ret sysctrl_efuse_get_vdd13_trim_valid@0x442>, r1=<clobbered>
 446:	3841      	cmpnei	r0, 1
 448:	0a4d      	bt	0xe2	// if (r0 != 0x1) goto loc_e2;
 44a:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_vdd13b_trim>; regs: r0=<ret sysctrl_efuse_get_vdd13b_trim@0x44a>, r1=<clobbered>
 44e:	e0000000 	bsr	0x0	// <pmu_vdd13b_vol_set_sec>; regs: r0=<ret pmu_vdd13b_vol_set_sec@0x44e>, r1=<clobbered>
 452:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_vdd13c_trim>; regs: r0=<ret sysctrl_efuse_get_vdd13c_trim@0x452>, r1=<clobbered>
 456:	e0000000 	bsr	0x0	// <pmu_vdd13c_vol_set_sec>; regs: r0=<ret pmu_vdd13c_vol_set_sec@0x456>, r1=<clobbered>
 45a:	0644      	br	0xe2	// goto loc_e2;
loc_45c:
 45c:	3b45      	cmpnei	r3, 5
 45e:	0807      	bt	0x46c	// if (r3 != 0x5) goto loc_46c;
 460:	3308      	movi	r3, 8	// regs: r3=0x8
 462:	ea021fcc 	movi	r2, 8140	// regs: r2=0x1fcc
 466:	ea011f7c 	movi	r1, 8060	// regs: r1=0x1f7c
 46a:	0659      	br	0x11c	// goto loc_11c;
loc_46c:
 46c:	3b50      	cmpnei	r3, 16
 46e:	0807      	bt	0x47c	// if (r3 != 0x10) goto loc_47c;
 470:	3302      	movi	r3, 2	// regs: r3=0x2
 472:	ea022166 	movi	r2, 8550	// regs: r2=0x2166
 476:	ea012102 	movi	r1, 8450	// regs: r1=0x2102
 47a:	0651      	br	0x11c	// goto loc_11c;
loc_47c:
 47c:	3b43      	cmpnei	r3, 3
 47e:	0807      	bt	0x48c	// if (r3 != 0x3) goto loc_48c;
 480:	3302      	movi	r3, 2	// regs: r3=0x2
 482:	ea0221de 	movi	r2, 8670	// regs: r2=0x21de
 486:	ea0121d4 	movi	r1, 8660	// regs: r1=0x21d4
 48a:	0649      	br	0x11c	// goto loc_11c;
loc_48c:
 48c:	3308      	movi	r3, 8	// regs: r3=0x8
 48e:	ea022418 	movi	r2, 9240	// regs: r2=0x2418
 492:	ea012378 	movi	r1, 9080	// regs: r1=0x2378
 496:	0643      	br	0x11c	// goto loc_11c;
loc_498:
 498:	3b43      	cmpnei	r3, 3
 49a:	0803      	bt	0x4a0	// if (r3 != 0x3) goto loc_4a0;
 49c:	3001      	movi	r0, 1	// regs: r0=0x1
 49e:	0696      	br	0x1ca	// goto loc_1ca;
loc_4a0:
 4a0:	3002      	movi	r0, 2	// regs: r0=0x2
 4a2:	0694      	br	0x1ca	// goto loc_1ca;
loc_4a4:
 4a4:	1007      	lrw	r0, 0x0	// regs: r0=0x0
 4a6:	0733      	br	0x30c	// goto loc_30c;
loc_4a8:
 4a8:	1067      	lrw	r3, 0x5b8d7f	// regs: r3=0x5b8d7f
 4aa:	640c      	cmphs	r3, r0
 4ac:	0c05      	bf	0x4b6	// if (!T) goto loc_4b6;
 4ae:	1007      	lrw	r0, 0x0	// regs: r0=0x0
loc_4b0:
 4b0:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x4b0>, r1=<clobbered>
 4b4:	072e      	br	0x310	// goto loc_310;
loc_4b6:
 4b6:	1006      	lrw	r0, 0x0	// regs: r0=0x0
 4b8:	07fc      	br	0x4b0	// goto loc_4b0;
 4ba:	0000      	.short	0x0000
 4bc:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_init.str1.1+0x17>
 4c0:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_init.str1.1+0x92>
 4c4:	005b8d7f 	.long	0x005b8d7f
 4c8:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_init.str1.1+0x9d>
 4cc:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_init.str1.1+0xac>

Disassembly of section .text.lmac_set_chan_list:

00000000 <lmac_set_chan_list>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	906a      	ld.w	r3, (r0, 0x28)	// regs: r3=*(<arg0> + 0x28)
   4:	e9030004 	bez	r3, 0xc	// if (r3 == 0x0) goto loc_c;
   8:	7bcd      	jsr	r3
loc_a:
   a:	1490      	pop	r15
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  10:	07fd      	br	0xa	// goto loc_a;

Disassembly of section .text.lmac_start_acs:

00000000 <lmac_start_acs>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	906d      	ld.w	r3, (r0, 0x34)	// regs: r3=*(<arg0> + 0x34)
   4:	e9030004 	bez	r3, 0xc	// if (r3 == 0x0) goto loc_c;
   8:	7bcd      	jsr	r3
loc_a:
   a:	1490      	pop	r15
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  10:	07fd      	br	0xa	// goto loc_a;
