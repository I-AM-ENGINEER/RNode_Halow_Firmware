
disasm/liblmac/obj/mars_lmac.o:     file format elf32-csky-little


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

Disassembly of section .text.lmac_scan_probe_cb:

00000000 <lmac_scan_probe_cb>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <lhw_abort_fsm>
   6:	1069      	lrw      	r3, 0x0	// 28 <lmac_scan_probe_cb+0x28>
   8:	3100      	movi      	r1, 0
   a:	d8430a4f 	ld.b      	r2, (r3, 0xa4f)
   e:	c4415c03 	ins      	r2, r1, 3, 3
  12:	d803033c 	ld.b      	r0, (r3, 0x33c)
  16:	dc430a4f 	st.b      	r2, (r3, 0xa4f)
  1a:	e0000000 	bsr      	0x0	// 0 <lmac_lo_table_kick>
  1e:	3034      	movi      	r0, 52
  20:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
  24:	1490      	pop      	r15
  26:	0000      	.short	0x0000
  28:	00000000 	.long	0x00000000

Disassembly of section .text.pd_timer_ap_wkup:

00000000 <pd_timer_ap_wkup>:
   0:	14d4      	push      	r4-r7, r15
   2:	ea078003 	movi      	r7, 32771
   6:	c5e74907 	rotli      	r7, r7, 15
   a:	3080      	movi      	r0, 128
   c:	d8272020 	ld.w      	r1, (r7, 0x80)
  10:	3980      	bclri      	r1, 0
  12:	0387      	lrw      	r4, 0x0	// 270 <pd_timer_ap_wkup+0x270>
  14:	e0000000 	bsr      	0x0	// 0 <pd_timer_ap_wkup>
  18:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_clear_pnd_sec>
  1c:	d8442267 	ld.w      	r2, (r4, 0x99c)
  20:	3a43      	cmpnei      	r2, 3
  22:	0c07      	bf      	0x30	// 30 <pd_timer_ap_wkup+0x30>
  24:	d8640319 	ld.b      	r3, (r4, 0x319)
  28:	e4a32002 	andi      	r5, r3, 2
  2c:	e90500f0 	bez      	r5, 0x20c	// 20c <pd_timer_ap_wkup+0x20c>
  30:	3001      	movi      	r0, 1
  32:	e0000000 	bsr      	0x0	// 0 <pd_hxosc_en_sec>
  36:	3200      	movi      	r2, 0
  38:	6c4b      	mov      	r1, r2
  3a:	3308      	movi      	r3, 8
  3c:	3001      	movi      	r0, 1
  3e:	e0000000 	bsr      	0x0	// 0 <sysctrl_adcpll_set>
  42:	3005      	movi      	r0, 5
  44:	e0000000 	bsr      	0x0	// 0 <mcu_watchdog_timeout>
  48:	e0000000 	bsr      	0x0	// 0 <mcu_watchdog_feed>
  4c:	ea00f424 	movi      	r0, 62500
  50:	c5404900 	rotli      	r0, r0, 10
  54:	e0000000 	bsr      	0x0	// 0 <sys_set_sysclk>
  58:	6d43      	mov      	r5, r0
  5a:	e0000000 	bsr      	0x0	// 0 <tsensor_open>
  5e:	0379      	lrw      	r3, 0x40026000	// 274 <pd_timer_ap_wkup+0x274>
  60:	3001      	movi      	r0, 1
  62:	9345      	ld.w      	r2, (r3, 0x14)
  64:	3abc      	bseti      	r2, 28
  66:	b345      	st.w      	r2, (r3, 0x14)
  68:	9345      	ld.w      	r2, (r3, 0x14)
  6a:	3abb      	bseti      	r2, 27
  6c:	b345      	st.w      	r2, (r3, 0x14)
  6e:	9345      	ld.w      	r2, (r3, 0x14)
  70:	3aba      	bseti      	r2, 26
  72:	b345      	st.w      	r2, (r3, 0x14)
  74:	9345      	ld.w      	r2, (r3, 0x14)
  76:	3abd      	bseti      	r2, 29
  78:	b345      	st.w      	r2, (r3, 0x14)
  7a:	9345      	ld.w      	r2, (r3, 0x14)
  7c:	3ab3      	bseti      	r2, 19
  7e:	b345      	st.w      	r2, (r3, 0x14)
  80:	9345      	ld.w      	r2, (r3, 0x14)
  82:	ec428000 	ori      	r2, r2, 32768
  86:	b345      	st.w      	r2, (r3, 0x14)
  88:	9345      	ld.w      	r2, (r3, 0x14)
  8a:	ec420800 	ori      	r2, r2, 2048
  8e:	b345      	st.w      	r2, (r3, 0x14)
  90:	9345      	ld.w      	r2, (r3, 0x14)
  92:	ec420200 	ori      	r2, r2, 512
  96:	b345      	st.w      	r2, (r3, 0x14)
  98:	9345      	ld.w      	r2, (r3, 0x14)
  9a:	ec420100 	ori      	r2, r2, 256
  9e:	b345      	st.w      	r2, (r3, 0x14)
  a0:	9345      	ld.w      	r2, (r3, 0x14)
  a2:	ec420020 	ori      	r2, r2, 32
  a6:	b345      	st.w      	r2, (r3, 0x14)
  a8:	9345      	ld.w      	r2, (r3, 0x14)
  aa:	ec420010 	ori      	r2, r2, 16
  ae:	b345      	st.w      	r2, (r3, 0x14)
  b0:	9347      	ld.w      	r2, (r3, 0x1c)
  b2:	3ab2      	bseti      	r2, 18
  b4:	b347      	st.w      	r2, (r3, 0x1c)
  b6:	9345      	ld.w      	r2, (r3, 0x14)
  b8:	3ab7      	bseti      	r2, 23
  ba:	b345      	st.w      	r2, (r3, 0x14)
  bc:	9342      	ld.w      	r2, (r3, 0x8)
  be:	3a92      	bclri      	r2, 18
  c0:	b342      	st.w      	r2, (r3, 0x8)
  c2:	9342      	ld.w      	r2, (r3, 0x8)
  c4:	3ab2      	bseti      	r2, 18
  c6:	b342      	st.w      	r2, (r3, 0x8)
  c8:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
  cc:	d80420ce 	ld.w      	r0, (r4, 0x338)
  d0:	c4805760 	zext      	r0, r0, 27, 4
  d4:	e0000000 	bsr      	0x0	// 0 <lmac_lo_freq_set>
  d8:	1368      	lrw      	r3, 0x0	// 278 <pd_timer_ap_wkup+0x278>
  da:	d82422e7 	ld.w      	r1, (r4, 0xb9c)
  de:	9360      	ld.w      	r3, (r3, 0x0)
  e0:	d84422e8 	ld.w      	r2, (r4, 0xba0)
  e4:	b324      	st.w      	r1, (r3, 0x10)
  e6:	b345      	st.w      	r2, (r3, 0x14)
  e8:	d8642267 	ld.w      	r3, (r4, 0x99c)
  ec:	e923000b 	bnez      	r3, 0x102	// 102 <pd_timer_ap_wkup+0x102>
  f0:	d86414ef 	ld.h      	r3, (r4, 0x9de)
  f4:	c4c35502 	zext      	r2, r3, 8, 6
  f8:	2206      	addi      	r2, 7
  fa:	c4625c46 	ins      	r3, r2, 8, 6
  fe:	dc6414ef 	st.h      	r3, (r4, 0x9de)
 102:	d8240556 	ld.b      	r1, (r4, 0x556)
 106:	3901      	cmphsi      	r1, 2
 108:	3300      	movi      	r3, 0
 10a:	dc640555 	st.b      	r3, (r4, 0x555)
 10e:	d8642197 	ld.w      	r3, (r4, 0x65c)
 112:	0c7b      	bf      	0x208	// 208 <pd_timer_ap_wkup+0x208>
 114:	c4238022 	divu      	r2, r3, r1
 118:	7cc8      	mult      	r3, r2
 11a:	2900      	subi      	r1, 1
 11c:	60c4      	addu      	r3, r1
 11e:	dc642197 	st.w      	r3, (r4, 0x65c)
 122:	e0000000 	bsr      	0x0	// 0 <lmac_next_beacon_calc>
 126:	e0000000 	bsr      	0x0	// 0 <lmac_beacon_timer_start>
 12a:	3702      	movi      	r7, 2
 12c:	d86409dd 	ld.b      	r3, (r4, 0x9dd)
 130:	c4675c60 	ins      	r3, r7, 3, 0
 134:	dc6409dd 	st.b      	r3, (r4, 0x9dd)
 138:	3601      	movi      	r6, 1
 13a:	d86409df 	ld.b      	r3, (r4, 0x9df)
 13e:	c4665c61 	ins      	r3, r6, 4, 1
 142:	120f      	lrw      	r0, 0x0	// 27c <pd_timer_ap_wkup+0x27c>
 144:	dc6409df 	st.b      	r3, (r4, 0x9df)
 148:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 14c:	d8640319 	ld.b      	r3, (r4, 0x319)
 150:	3200      	movi      	r2, 0
 152:	c4625c01 	ins      	r3, r2, 1, 1
 156:	dc640319 	st.b      	r3, (r4, 0x319)
 15a:	3200      	movi      	r2, 0
 15c:	3300      	movi      	r3, 0
 15e:	dc4420f0 	st.w      	r2, (r4, 0x3c0)
 162:	dc6420f1 	st.w      	r3, (r4, 0x3c4)
 166:	dce42267 	st.w      	r7, (r4, 0x99c)
 16a:	1266      	lrw      	r3, 0x0	// 280 <pd_timer_ap_wkup+0x280>
 16c:	834a      	ld.b      	r2, (r3, 0xa)
 16e:	c4465c00 	ins      	r2, r6, 0, 0
 172:	a34a      	st.b      	r2, (r3, 0xa)
 174:	e9050006 	bez      	r5, 0x180	// 180 <pd_timer_ap_wkup+0x180>
 178:	6c5b      	mov      	r1, r6
 17a:	1203      	lrw      	r0, 0x0	// 284 <pd_timer_ap_wkup+0x284>
 17c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 180:	e0000000 	bsr      	0x0	// 0 <system_ap_sleep_wakeup_hook>
 184:	d8644319 	ld.bs      	r3, (r4, 0x319)
 188:	e9a30034 	bhsz      	r3, 0x1f0	// 1f0 <pd_timer_ap_wkup+0x1f0>
 18c:	e0000000 	bsr      	0x0	// 0 <system_ap_sleep_io_wakeup_hook>
 190:	6d43      	mov      	r5, r0
 192:	e900002f 	bez      	r0, 0x1f0	// 1f0 <pd_timer_ap_wkup+0x1f0>
 196:	d8640319 	ld.b      	r3, (r4, 0x319)
 19a:	3200      	movi      	r2, 0
 19c:	c4625c07 	ins      	r3, r2, 7, 7
 1a0:	dc640319 	st.b      	r3, (r4, 0x319)
 1a4:	9460      	ld.w      	r3, (r4, 0x0)
 1a6:	3001      	movi      	r0, 1
 1a8:	832a      	ld.b      	r1, (r3, 0xa)
 1aa:	c4205c00 	ins      	r1, r0, 0, 0
 1ae:	a32a      	st.b      	r1, (r3, 0xa)
 1b0:	d8640319 	ld.b      	r3, (r4, 0x319)
 1b4:	e46320fe 	andi      	r3, r3, 254
 1b8:	c4625c01 	ins      	r3, r2, 1, 1
 1bc:	dc640319 	st.b      	r3, (r4, 0x319)
 1c0:	ea038003 	movi      	r3, 32771
 1c4:	c5e34903 	rotli      	r3, r3, 15
 1c8:	dc442267 	st.w      	r2, (r4, 0x99c)
 1cc:	d8632028 	ld.w      	r3, (r3, 0xa0)
 1d0:	e4632100 	andi      	r3, r3, 256
 1d4:	e9030005 	bez      	r3, 0x1de	// 1de <pd_timer_ap_wkup+0x1de>
 1d8:	110c      	lrw      	r0, 0x0	// 288 <hgprintf+0x288>
 1da:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1de:	d824031a 	ld.b      	r1, (r4, 0x31a)
 1e2:	110b      	lrw      	r0, 0x0	// 28c <pd_timer_ap_wkup+0x28c>
 1e4:	4921      	lsri      	r1, r1, 1
 1e6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1ea:	7414      	zextb      	r0, r5
 1ec:	e0000000 	bsr      	0x0	// 0 <lmac_report_sleep_exit>
 1f0:	1148      	lrw      	r2, 0xe000e100	// 290 <pd_timer_ap_wkup+0x290>
 1f2:	3380      	movi      	r3, 128
 1f4:	436e      	lsli      	r3, r3, 14
 1f6:	b260      	st.w      	r3, (r2, 0x0)
 1f8:	e0000000 	bsr      	0x0	// 0 <lhw_enable_irq_ac>
 1fc:	3000      	movi      	r0, 0
 1fe:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
 202:	e0000000 	bsr      	0x0	// 0 <lmac_tdma_start>
 206:	1494      	pop      	r4-r7, r15
 208:	2300      	addi      	r3, 1
 20a:	078a      	br      	0x11e	// 11e <pd_timer_ap_wkup+0x11e>
 20c:	3a42      	cmpnei      	r2, 2
 20e:	0bfc      	bt      	0x206	// 206 <pd_timer_ap_wkup+0x206>
 210:	74ce      	sextb      	r3, r3
 212:	e9a3ffef 	bhsz      	r3, 0x1f0	// 1f0 <pd_timer_ap_wkup+0x1f0>
 216:	e0000000 	bsr      	0x0	// 0 <system_ap_sleep_io_wakeup_hook>
 21a:	6d83      	mov      	r6, r0
 21c:	e900ffea 	bez      	r0, 0x1f0	// 1f0 <pd_timer_ap_wkup+0x1f0>
 220:	d8640319 	ld.b      	r3, (r4, 0x319)
 224:	c4655c07 	ins      	r3, r5, 7, 7
 228:	dc640319 	st.b      	r3, (r4, 0x319)
 22c:	9460      	ld.w      	r3, (r4, 0x0)
 22e:	3101      	movi      	r1, 1
 230:	834a      	ld.b      	r2, (r3, 0xa)
 232:	c4415c00 	ins      	r2, r1, 0, 0
 236:	a34a      	st.b      	r2, (r3, 0xa)
 238:	d8640319 	ld.b      	r3, (r4, 0x319)
 23c:	e46320fe 	andi      	r3, r3, 254
 240:	c4655c01 	ins      	r3, r5, 1, 1
 244:	dc640319 	st.b      	r3, (r4, 0x319)
 248:	d8672028 	ld.w      	r3, (r7, 0xa0)
 24c:	e4632100 	andi      	r3, r3, 256
 250:	dca42267 	st.w      	r5, (r4, 0x99c)
 254:	e9030005 	bez      	r3, 0x25e	// 25e <pd_timer_ap_wkup+0x25e>
 258:	100c      	lrw      	r0, 0x0	// 288 <hgprintf+0x288>
 25a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 25e:	d824031a 	ld.b      	r1, (r4, 0x31a)
 262:	100d      	lrw      	r0, 0x0	// 294 <pd_timer_ap_wkup+0x294>
 264:	4921      	lsri      	r1, r1, 1
 266:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 26a:	7418      	zextb      	r0, r6
 26c:	07c0      	br      	0x1ec	// 1ec <pd_timer_ap_wkup+0x1ec>
 26e:	0000      	.short	0x0000
 270:	00000000 	.long	0x00000000
 274:	40026000 	.long	0x40026000
	...
 290:	e100      	.short	0xe100
 292:	e000      	.short	0xe000
 294:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_print_task:

00000000 <lmac_print_task>:
   0:	14d3      	push      	r4-r6, r15
   2:	1094      	lrw      	r4, 0x0	// 50 <lmac_print_task+0x50>
   4:	6d53      	mov      	r5, r4
   6:	10d4      	lrw      	r6, 0x0	// 54 <lmac_print_task+0x54>
   8:	d86449df 	ld.bs      	r3, (r4, 0x9df)
   c:	e9a30003 	bhsz      	r3, 0x12	// 12 <lmac_print_task+0x12>
  10:	1493      	pop      	r4-r6, r15
  12:	3100      	movi      	r1, 0
  14:	2900      	subi      	r1, 1
  16:	1011      	lrw      	r0, 0x0	// 58 <lmac_print_task+0x58>
  18:	e0000000 	bsr      	0x0	// 0 <os_sema_down>
  1c:	e960fff6 	blsz      	r0, 0x8	// 8 <lmac_print_task+0x8>
  20:	d864226e 	ld.w      	r3, (r4, 0x9b8)
  24:	e903fff2 	bez      	r3, 0x8	// 8 <lmac_print_task+0x8>
  28:	8660      	ld.b      	r3, (r6, 0x0)
  2a:	3b01      	cmphsi      	r3, 2
  2c:	0804      	bt      	0x34	// 34 <lmac_print_task+0x34>
  2e:	100c      	lrw      	r0, 0x0	// 5c <lmac_print_task+0x5c>
  30:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  34:	d825226e 	ld.w      	r1, (r5, 0x9b8)
  38:	100a      	lrw      	r0, 0x0	// 60 <hgprintf+0x60>
  3a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  3e:	d805226e 	ld.w      	r0, (r5, 0x9b8)
  42:	e0000000 	bsr      	0x0	// 0 <_os_free>
  46:	3300      	movi      	r3, 0
  48:	dc65226e 	st.w      	r3, (r5, 0x9b8)
  4c:	07de      	br      	0x8	// 8 <lmac_print_task+0x8>
	...

Disassembly of section .text.wakeup_irq_handler:

00000000 <wakeup_irq_handler>:
   0:	14d0      	push      	r15
   2:	ea028003 	movi      	r2, 32771
   6:	c5e24902 	rotli      	r2, r2, 15
   a:	d8622028 	ld.w      	r3, (r2, 0xa0)
   e:	e4632100 	andi      	r3, r3, 256
  12:	e9030019 	bez      	r3, 0x44	// 44 <wakeup_irq_handler+0x44>
  16:	d8222028 	ld.w      	r1, (r2, 0xa0)
  1a:	c40155e1 	zext      	r1, r1, 15, 0
  1e:	39b0      	bseti      	r1, 16
  20:	30a0      	movi      	r0, 160
  22:	e0000000 	bsr      	0x0	// 0 <wakeup_irq_handler>
  26:	1069      	lrw      	r3, 0x0	// 48 <wakeup_irq_handler+0x48>
  28:	d8432267 	ld.w      	r2, (r3, 0x99c)
  2c:	3a43      	cmpnei      	r2, 3
  2e:	080b      	bt      	0x44	// 44 <wakeup_irq_handler+0x44>
  30:	d8430319 	ld.b      	r2, (r3, 0x319)
  34:	3101      	movi      	r1, 1
  36:	c4415c07 	ins      	r2, r1, 7, 7
  3a:	3000      	movi      	r0, 0
  3c:	dc430319 	st.b      	r2, (r3, 0x319)
  40:	e0000000 	bsr      	0x0	// 0 <wakeup_irq_handler>
  44:	1490      	pop      	r15
  46:	0000      	.short	0x0000
  48:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_phy_reset:

00000000 <lmac_phy_reset>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <ah_wphy_soft_reset>
   6:	6c03      	mov      	r0, r0
   8:	6c03      	mov      	r0, r0
   a:	6c03      	mov      	r0, r0
   c:	6c03      	mov      	r0, r0
   e:	6c03      	mov      	r0, r0
  10:	e0000000 	bsr      	0x0	// 0 <ah_wphy_soft_dereset>
  14:	1490      	pop      	r15

Disassembly of section .text.lmac_phy_soft_reset:

00000000 <lmac_phy_soft_reset>:
   0:	14d1      	push      	r4, r15
   2:	109b      	lrw      	r4, 0x0	// 6c <lmac_phy_soft_reset+0x6c>
   4:	e0000000 	bsr      	0x0	// 0 <lhw_abort_fsm>
   8:	d804033c 	ld.b      	r0, (r4, 0x33c)
   c:	e0000000 	bsr      	0x0	// 0 <lmac_lo_table_kick>
  10:	e0000000 	bsr      	0x0	// 0 <ah_wphy_soft_reset>
  14:	e0000000 	bsr      	0x0	// 0 <ah_wphy_soft_dereset>
  18:	d8640a4f 	ld.b      	r3, (r4, 0xa4f)
  1c:	e4632001 	andi      	r3, r3, 1
  20:	e903001d 	bez      	r3, 0x5a	// 5a <lmac_phy_soft_reset+0x5a>
  24:	3001      	movi      	r0, 1
  26:	e0000000 	bsr      	0x0	// 0 <skbpool_freesize>
  2a:	d86422ec 	ld.w      	r3, (r4, 0xbb0)
  2e:	480b      	lsri      	r0, r0, 11
  30:	4b61      	lsri      	r3, r3, 1
  32:	64c0      	cmphs      	r0, r3
  34:	0813      	bt      	0x5a	// 5a <lmac_phy_soft_reset+0x5a>
  36:	3200      	movi      	r2, 0
  38:	d864431e 	ld.bs      	r3, (r4, 0x31e)
  3c:	2a3b      	subi      	r2, 60
  3e:	648d      	cmplt      	r3, r2
  40:	0c04      	bf      	0x48	// 48 <lmac_phy_soft_reset+0x48>
  42:	2301      	addi      	r3, 2
  44:	dc64031e 	st.b      	r3, (r4, 0x31e)
  48:	100a      	lrw      	r0, 0x0	// 70 <lmac_phy_soft_reset+0x70>
  4a:	d824431e 	ld.bs      	r1, (r4, 0x31e)
  4e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  52:	d804431e 	ld.bs      	r0, (r4, 0x31e)
  56:	e0000000 	bsr      	0x0	// 0 <lmac_adjust_cca_threshold>
  5a:	3000      	movi      	r0, 0
  5c:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
  60:	d86421f1 	ld.w      	r3, (r4, 0x7c4)
  64:	2300      	addi      	r3, 1
  66:	dc6421f1 	st.w      	r3, (r4, 0x7c4)
  6a:	1491      	pop      	r4, r15
	...

Disassembly of section .text.lmac_tick_cb:

00000000 <lmac_tick_cb>:
   0:	14d8      	push      	r4-r11, r15
   2:	142d      	subi      	r14, r14, 52
   4:	ea840165 	lrw      	r4, 0x0	// 598 <lmac_tick_cb+0x598>
   8:	ea850165 	lrw      	r5, 0x0	// 59c <lmac_tick_cb+0x59c>
   c:	d9842233 	ld.w      	r12, (r4, 0x8cc)
  10:	d86420e3 	ld.w      	r3, (r4, 0x38c)
  14:	b860      	st.w      	r3, (r14, 0x0)
  16:	d86420e2 	ld.w      	r3, (r4, 0x388)
  1a:	b861      	st.w      	r3, (r14, 0x4)
  1c:	d86420e4 	ld.w      	r3, (r4, 0x390)
  20:	b862      	st.w      	r3, (r14, 0x8)
  22:	d86420e7 	ld.w      	r3, (r4, 0x39c)
  26:	b863      	st.w      	r3, (r14, 0xc)
  28:	d86420e8 	ld.w      	r3, (r4, 0x3a0)
  2c:	b864      	st.w      	r3, (r14, 0x10)
  2e:	d86420e9 	ld.w      	r3, (r4, 0x3a4)
  32:	b865      	st.w      	r3, (r14, 0x14)
  34:	d86420eb 	ld.w      	r3, (r4, 0x3ac)
  38:	b866      	st.w      	r3, (r14, 0x18)
  3a:	d86420ec 	ld.w      	r3, (r4, 0x3b0)
  3e:	b867      	st.w      	r3, (r14, 0x1c)
  40:	d86420ed 	ld.w      	r3, (r4, 0x3b4)
  44:	b868      	st.w      	r3, (r14, 0x20)
  46:	9540      	ld.w      	r2, (r5, 0x0)
  48:	9561      	ld.w      	r3, (r5, 0x4)
  4a:	2200      	addi      	r2, 1
  4c:	3a40      	cmpnei      	r2, 0
  4e:	c4630c21 	incf      	r3, r3, 1
  52:	d90420e6 	ld.w      	r8, (r4, 0x398)
  56:	d8c420e5 	ld.w      	r6, (r4, 0x394)
  5a:	b540      	st.w      	r2, (r5, 0x0)
  5c:	b561      	st.w      	r3, (r5, 0x4)
  5e:	e90c0049 	bez      	r12, 0xf0	// f0 <lmac_tick_cb+0xf0>
  62:	ea830150 	lrw      	r3, 0x0	// 5a0 <lmac_tick_cb+0x5a0>
  66:	ea0a0000 	movi      	r10, 0
  6a:	9320      	ld.w      	r1, (r3, 0x0)
  6c:	ea87014e 	lrw      	r7, 0x0	// 5a4 <lmac_tick_cb+0x5a4>
  70:	9105      	ld.w      	r0, (r1, 0x14)
  72:	d9a12004 	ld.w      	r13, (r1, 0x10)
  76:	6ec3      	mov      	r11, r0
  78:	6c6b      	mov      	r1, r10
  7a:	6c37      	mov      	r0, r13
  7c:	66a9      	cmplt      	r10, r10
  7e:	6281      	addc      	r10, r0
  80:	62c5      	addc      	r11, r1
  82:	d80c20b4 	ld.w      	r0, (r12, 0x2d0)
  86:	d82c20b5 	ld.w      	r1, (r12, 0x2d4)
  8a:	c4202423 	or      	r3, r0, r1
  8e:	e9030295 	bez      	r3, 0x5b8	// 5b8 <lmac_tick_cb+0x5b8>
  92:	66c4      	cmphs      	r1, r11
  94:	0c07      	bf      	0xa2	// a2 <lmac_tick_cb+0xa2>
  96:	646e      	cmpne      	r11, r1
  98:	e8600290 	bt      	0x5b8	// 5b8 <lmac_tick_cb+0x5b8>
  9c:	6680      	cmphs      	r0, r10
  9e:	e860028d 	bt      	0x5b8	// 5b8 <lmac_tick_cb+0x5b8>
  a2:	d84c20b2 	ld.w      	r2, (r12, 0x2c8)
  a6:	d86c20b3 	ld.w      	r3, (r12, 0x2cc)
  aa:	6488      	cmphs      	r2, r2
  ac:	6083      	subc      	r2, r0
  ae:	60c7      	subc      	r3, r1
  b0:	6489      	cmplt      	r2, r2
  b2:	60a9      	addc      	r2, r10
  b4:	60ed      	addc      	r3, r11
  b6:	dc4c20b2 	st.w      	r2, (r12, 0x2c8)
  ba:	dc6c20b3 	st.w      	r3, (r12, 0x2cc)
  be:	d9242233 	ld.w      	r9, (r4, 0x8cc)
  c2:	ea02eebb 	movi      	r2, 61115
  c6:	c5a24902 	rotli      	r2, r2, 13
  ca:	d80920b2 	ld.w      	r0, (r9, 0x2c8)
  ce:	d82920b3 	ld.w      	r1, (r9, 0x2cc)
  d2:	3314      	movi      	r3, 20
  d4:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
  d8:	dc0920b2 	st.w      	r0, (r9, 0x2c8)
  dc:	dc2920b3 	st.w      	r1, (r9, 0x2cc)
  e0:	dd4920b4 	st.w      	r10, (r9, 0x2d0)
  e4:	dd6920b5 	st.w      	r11, (r9, 0x2d4)
  e8:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  ec:	b700      	st.w      	r0, (r7, 0x0)
  ee:	b721      	st.w      	r1, (r7, 0x4)
  f0:	d8640319 	ld.b      	r3, (r4, 0x319)
  f4:	e4632002 	andi      	r3, r3, 2
  f8:	e923024d 	bnez      	r3, 0x592	// 592 <lmac_tick_cb+0x592>
  fc:	d8642267 	ld.w      	r3, (r4, 0x99c)
 100:	e9230249 	bnez      	r3, 0x592	// 592 <lmac_tick_cb+0x592>
 104:	c4c88022 	divu      	r2, r8, r6
 108:	e9020039 	bez      	r2, 0x17a	// 17a <lmac_tick_cb+0x17a>
 10c:	9500      	ld.w      	r0, (r5, 0x0)
 10e:	9521      	ld.w      	r1, (r5, 0x4)
 110:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 114:	6c40      	or      	r1, r0
 116:	e9210032 	bnez      	r1, 0x17a	// 17a <lmac_tick_cb+0x17a>
 11a:	d84422a1 	ld.w      	r2, (r4, 0xa84)
 11e:	5a62      	addi      	r3, r2, 1
 120:	d82422a2 	ld.w      	r1, (r4, 0xa88)
 124:	644d      	cmplt      	r3, r1
 126:	5b05      	subu      	r0, r3, r1
 128:	c4600c20 	incf      	r3, r0, 0
 12c:	d82422a0 	ld.w      	r1, (r4, 0xa80)
 130:	644e      	cmpne      	r3, r1
 132:	0c08      	bf      	0x142	// 142 <lmac_tick_cb+0x142>
 134:	e44202a2 	addi      	r2, r2, 675
 138:	3107      	movi      	r1, 7
 13a:	d4440881 	str.w      	r1, (r4, r2 << 2)
 13e:	dc6422a1 	st.w      	r3, (r4, 0xa84)
 142:	ea80011a 	lrw      	r0, 0x0	// 5a8 <lmac_tick_cb+0x5a8>
 146:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
 14a:	d84422a1 	ld.w      	r2, (r4, 0xa84)
 14e:	5a62      	addi      	r3, r2, 1
 150:	d82422a2 	ld.w      	r1, (r4, 0xa88)
 154:	644d      	cmplt      	r3, r1
 156:	5b05      	subu      	r0, r3, r1
 158:	c4600c20 	incf      	r3, r0, 0
 15c:	d82422a0 	ld.w      	r1, (r4, 0xa80)
 160:	644e      	cmpne      	r3, r1
 162:	0c08      	bf      	0x172	// 172 <lmac_tick_cb+0x172>
 164:	e44202a2 	addi      	r2, r2, 675
 168:	3103      	movi      	r1, 3
 16a:	d4440881 	str.w      	r1, (r4, r2 << 2)
 16e:	dc6422a1 	st.w      	r3, (r4, 0xa84)
 172:	ea80010e 	lrw      	r0, 0x0	// 5a8 <lmac_tick_cb+0x5a8>
 176:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
 17a:	9860      	ld.w      	r3, (r14, 0x0)
 17c:	c4c38022 	divu      	r2, r3, r6
 180:	e9020021 	bez      	r2, 0x1c2	// 1c2 <lmac_tick_cb+0x1c2>
 184:	3300      	movi      	r3, 0
 186:	9500      	ld.w      	r0, (r5, 0x0)
 188:	9521      	ld.w      	r1, (r5, 0x4)
 18a:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 18e:	6c40      	or      	r1, r0
 190:	e9210019 	bnez      	r1, 0x1c2	// 1c2 <lmac_tick_cb+0x1c2>
 194:	d84422a1 	ld.w      	r2, (r4, 0xa84)
 198:	5a62      	addi      	r3, r2, 1
 19a:	d82422a2 	ld.w      	r1, (r4, 0xa88)
 19e:	644d      	cmplt      	r3, r1
 1a0:	5b05      	subu      	r0, r3, r1
 1a2:	c4600c20 	incf      	r3, r0, 0
 1a6:	d82422a0 	ld.w      	r1, (r4, 0xa80)
 1aa:	644e      	cmpne      	r3, r1
 1ac:	0c08      	bf      	0x1bc	// 1bc <lmac_tick_cb+0x1bc>
 1ae:	e44202a2 	addi      	r2, r2, 675
 1b2:	3106      	movi      	r1, 6
 1b4:	d4440881 	str.w      	r1, (r4, r2 << 2)
 1b8:	dc6422a1 	st.w      	r3, (r4, 0xa84)
 1bc:	0004      	lrw      	r0, 0x0	// 5a8 <os_sema_up+0x5a8>
 1be:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
 1c2:	d8642278 	ld.w      	r3, (r4, 0x9e0)
 1c6:	c6005022 	bmaski      	r2, 17
 1ca:	2201      	addi      	r2, 2
 1cc:	68c8      	and      	r3, r2
 1ce:	e9230148 	bnez      	r3, 0x45e	// 45e <lmac_tick_cb+0x45e>
 1d2:	9841      	ld.w      	r2, (r14, 0x4)
 1d4:	c4c28022 	divu      	r2, r2, r6
 1d8:	e9020051 	bez      	r2, 0x27a	// 27a <lmac_tick_cb+0x27a>
 1dc:	9500      	ld.w      	r0, (r5, 0x0)
 1de:	9521      	ld.w      	r1, (r5, 0x4)
 1e0:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 1e4:	6c40      	or      	r1, r0
 1e6:	e921004a 	bnez      	r1, 0x27a	// 27a <lmac_tick_cb+0x27a>
 1ea:	d8640a4f 	ld.b      	r3, (r4, 0xa4f)
 1ee:	e4632003 	andi      	r3, r3, 3
 1f2:	3b43      	cmpnei      	r3, 3
 1f4:	0c0b      	bf      	0x20a	// 20a <lmac_tick_cb+0x20a>
 1f6:	d864483d 	ld.bs      	r3, (r4, 0x83d)
 1fa:	eb230032 	cmplti      	r3, 51
 1fe:	0c06      	bf      	0x20a	// 20a <lmac_tick_cb+0x20a>
 200:	d86421e2 	ld.w      	r3, (r4, 0x788)
 204:	eb230064 	cmplti      	r3, 101
 208:	080a      	bt      	0x21c	// 21c <lmac_tick_cb+0x21c>
 20a:	e0000000 	bsr      	0x0	// 0 <lmac_tick_cb>
 20e:	d864037d 	ld.b      	r3, (r4, 0x37d)
 212:	3201      	movi      	r2, 1
 214:	c4625c03 	ins      	r3, r2, 3, 3
 218:	dc64037d 	st.b      	r3, (r4, 0x37d)
 21c:	3201      	movi      	r2, 1
 21e:	d8640a4f 	ld.b      	r3, (r4, 0xa4f)
 222:	c4625c00 	ins      	r3, r2, 0, 0
 226:	c4625c01 	ins      	r3, r2, 1, 1
 22a:	dc640a4f 	st.b      	r3, (r4, 0xa4f)
 22e:	d8640875 	ld.b      	r3, (r4, 0x875)
 232:	740c      	zextb      	r0, r3
 234:	e4402004 	andi      	r2, r0, 4
 238:	e9020021 	bez      	r2, 0x27a	// 27a <lmac_tick_cb+0x27a>
 23c:	d8441504 	ld.h      	r2, (r4, 0xa08)
 240:	e922001d 	bnez      	r2, 0x27a	// 27a <lmac_tick_cb+0x27a>
 244:	e4402008 	andi      	r2, r0, 8
 248:	e9020019 	bez      	r2, 0x27a	// 27a <lmac_tick_cb+0x27a>
 24c:	e4004010 	xori      	r0, r0, 16
 250:	c4805480 	zext      	r0, r0, 4, 4
 254:	c4605c04 	ins      	r3, r0, 4, 4
 258:	dc640875 	st.b      	r3, (r4, 0x875)
 25c:	e0000000 	bsr      	0x0	// 0 <lmac_ant_sel>
 260:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
 264:	e4632100 	andi      	r3, r3, 256
 268:	e9030009 	bez      	r3, 0x27a	// 27a <lmac_tick_cb+0x27a>
 26c:	d8240875 	ld.b      	r1, (r4, 0x875)
 270:	c4815481 	zext      	r1, r1, 4, 4
 274:	0111      	lrw      	r0, 0x0	// 5ac <hgprintf+0x5ac>
 276:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 27a:	9862      	ld.w      	r3, (r14, 0x8)
 27c:	c4c38022 	divu      	r2, r3, r6
 280:	e9020050 	bez      	r2, 0x320	// 320 <lmac_tick_cb+0x320>
 284:	3300      	movi      	r3, 0
 286:	9500      	ld.w      	r0, (r5, 0x0)
 288:	9521      	ld.w      	r1, (r5, 0x4)
 28a:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 28e:	6c40      	or      	r1, r0
 290:	e9210048 	bnez      	r1, 0x320	// 320 <lmac_tick_cb+0x320>
 294:	d864202f 	ld.w      	r3, (r4, 0xbc)
 298:	3b42      	cmpnei      	r3, 2
 29a:	0818      	bt      	0x2ca	// 2ca <lmac_tick_cb+0x2ca>
 29c:	d84422a1 	ld.w      	r2, (r4, 0xa84)
 2a0:	5a62      	addi      	r3, r2, 1
 2a2:	d82422a2 	ld.w      	r1, (r4, 0xa88)
 2a6:	644d      	cmplt      	r3, r1
 2a8:	5b05      	subu      	r0, r3, r1
 2aa:	c4600c20 	incf      	r3, r0, 0
 2ae:	d82422a0 	ld.w      	r1, (r4, 0xa80)
 2b2:	644e      	cmpne      	r3, r1
 2b4:	0c08      	bf      	0x2c4	// 2c4 <lmac_tick_cb+0x2c4>
 2b6:	e44202a2 	addi      	r2, r2, 675
 2ba:	3105      	movi      	r1, 5
 2bc:	d4440881 	str.w      	r1, (r4, r2 << 2)
 2c0:	dc6422a1 	st.w      	r3, (r4, 0xa84)
 2c4:	0206      	lrw      	r0, 0x0	// 5a8 <os_sema_up+0x5a8>
 2c6:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
 2ca:	d864202f 	ld.w      	r3, (r4, 0xbc)
 2ce:	3b41      	cmpnei      	r3, 1
 2d0:	0828      	bt      	0x320	// 320 <lmac_tick_cb+0x320>
 2d2:	d8641505 	ld.h      	r3, (r4, 0xa0a)
 2d6:	e9230025 	bnez      	r3, 0x320	// 320 <lmac_tick_cb+0x320>
 2da:	d864037d 	ld.b      	r3, (r4, 0x37d)
 2de:	e4632004 	andi      	r3, r3, 4
 2e2:	e903001f 	bez      	r3, 0x320	// 320 <lmac_tick_cb+0x320>
 2e6:	9460      	ld.w      	r3, (r4, 0x0)
 2e8:	836a      	ld.b      	r3, (r3, 0xa)
 2ea:	e4632001 	andi      	r3, r3, 1
 2ee:	e9030019 	bez      	r3, 0x320	// 320 <lmac_tick_cb+0x320>
 2f2:	d84422a1 	ld.w      	r2, (r4, 0xa84)
 2f6:	5a62      	addi      	r3, r2, 1
 2f8:	d82422a2 	ld.w      	r1, (r4, 0xa88)
 2fc:	644d      	cmplt      	r3, r1
 2fe:	5b05      	subu      	r0, r3, r1
 300:	c4600c20 	incf      	r3, r0, 0
 304:	d82422a0 	ld.w      	r1, (r4, 0xa80)
 308:	644e      	cmpne      	r3, r1
 30a:	0c08      	bf      	0x31a	// 31a <lmac_tick_cb+0x31a>
 30c:	e44202a2 	addi      	r2, r2, 675
 310:	3104      	movi      	r1, 4
 312:	d4440881 	str.w      	r1, (r4, r2 << 2)
 316:	dc6422a1 	st.w      	r3, (r4, 0xa84)
 31a:	021b      	lrw      	r0, 0x0	// 5a8 <os_sema_up+0x5a8>
 31c:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
 320:	9863      	ld.w      	r3, (r14, 0xc)
 322:	c4c38022 	divu      	r2, r3, r6
 326:	e902003b 	bez      	r2, 0x39c	// 39c <lmac_tick_cb+0x39c>
 32a:	3300      	movi      	r3, 0
 32c:	9500      	ld.w      	r0, (r5, 0x0)
 32e:	9521      	ld.w      	r1, (r5, 0x4)
 330:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 334:	6c40      	or      	r1, r0
 336:	e9210033 	bnez      	r1, 0x39c	// 39c <lmac_tick_cb+0x39c>
 33a:	d8640310 	ld.b      	r3, (r4, 0x310)
 33e:	e4632002 	andi      	r3, r3, 2
 342:	e903002d 	bez      	r3, 0x39c	// 39c <lmac_tick_cb+0x39c>
 346:	d8640378 	ld.b      	r3, (r4, 0x378)
 34a:	e9030029 	bez      	r3, 0x39c	// 39c <lmac_tick_cb+0x39c>
 34e:	9460      	ld.w      	r3, (r4, 0x0)
 350:	836a      	ld.b      	r3, (r3, 0xa)
 352:	e4632001 	andi      	r3, r3, 1
 356:	e9030023 	bez      	r3, 0x39c	// 39c <lmac_tick_cb+0x39c>
 35a:	d864432a 	ld.bs      	r3, (r4, 0x32a)
 35e:	e9a3001f 	bhsz      	r3, 0x39c	// 39c <lmac_tick_cb+0x39c>
 362:	036f      	lrw      	r3, 0x0	// 5a0 <lmac_tick_cb+0x5a0>
 364:	9360      	ld.w      	r3, (r3, 0x0)
 366:	d8632036 	ld.w      	r3, (r3, 0xd8)
 36a:	e9230019 	bnez      	r3, 0x39c	// 39c <lmac_tick_cb+0x39c>
 36e:	d84422a1 	ld.w      	r2, (r4, 0xa84)
 372:	5a62      	addi      	r3, r2, 1
 374:	d82422a2 	ld.w      	r1, (r4, 0xa88)
 378:	644d      	cmplt      	r3, r1
 37a:	5b05      	subu      	r0, r3, r1
 37c:	c4600c20 	incf      	r3, r0, 0
 380:	d82422a0 	ld.w      	r1, (r4, 0xa80)
 384:	644e      	cmpne      	r3, r1
 386:	0c08      	bf      	0x396	// 396 <lmac_tick_cb+0x396>
 388:	e44202a2 	addi      	r2, r2, 675
 38c:	3109      	movi      	r1, 9
 38e:	d4440881 	str.w      	r1, (r4, r2 << 2)
 392:	dc6422a1 	st.w      	r3, (r4, 0xa84)
 396:	031a      	lrw      	r0, 0x0	// 5a8 <os_sema_up+0x5a8>
 398:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
 39c:	9864      	ld.w      	r3, (r14, 0x10)
 39e:	c4c38022 	divu      	r2, r3, r6
 3a2:	e902002f 	bez      	r2, 0x400	// 400 <lmac_tick_cb+0x400>
 3a6:	3300      	movi      	r3, 0
 3a8:	9500      	ld.w      	r0, (r5, 0x0)
 3aa:	9521      	ld.w      	r1, (r5, 0x4)
 3ac:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 3b0:	6c40      	or      	r1, r0
 3b2:	e9210027 	bnez      	r1, 0x400	// 400 <lmac_tick_cb+0x400>
 3b6:	d8640310 	ld.b      	r3, (r4, 0x310)
 3ba:	e4632002 	andi      	r3, r3, 2
 3be:	e9030021 	bez      	r3, 0x400	// 400 <lmac_tick_cb+0x400>
 3c2:	d864202f 	ld.w      	r3, (r4, 0xbc)
 3c6:	3b42      	cmpnei      	r3, 2
 3c8:	081c      	bt      	0x400	// 400 <lmac_tick_cb+0x400>
 3ca:	d8641504 	ld.h      	r3, (r4, 0xa08)
 3ce:	e9030019 	bez      	r3, 0x400	// 400 <lmac_tick_cb+0x400>
 3d2:	d84422a1 	ld.w      	r2, (r4, 0xa84)
 3d6:	5a62      	addi      	r3, r2, 1
 3d8:	d82422a2 	ld.w      	r1, (r4, 0xa88)
 3dc:	644d      	cmplt      	r3, r1
 3de:	5b05      	subu      	r0, r3, r1
 3e0:	c4600c20 	incf      	r3, r0, 0
 3e4:	d82422a0 	ld.w      	r1, (r4, 0xa80)
 3e8:	644e      	cmpne      	r3, r1
 3ea:	0c08      	bf      	0x3fa	// 3fa <lmac_tick_cb+0x3fa>
 3ec:	e44202a2 	addi      	r2, r2, 675
 3f0:	310a      	movi      	r1, 10
 3f2:	d4440881 	str.w      	r1, (r4, r2 << 2)
 3f6:	dc6422a1 	st.w      	r3, (r4, 0xa84)
 3fa:	130c      	lrw      	r0, 0x0	// 5a8 <os_sema_up+0x5a8>
 3fc:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
 400:	9865      	ld.w      	r3, (r14, 0x14)
 402:	c4c38022 	divu      	r2, r3, r6
 406:	e902002c 	bez      	r2, 0x45e	// 45e <lmac_tick_cb+0x45e>
 40a:	3300      	movi      	r3, 0
 40c:	9500      	ld.w      	r0, (r5, 0x0)
 40e:	9521      	ld.w      	r1, (r5, 0x4)
 410:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 414:	6c40      	or      	r1, r0
 416:	e9210024 	bnez      	r1, 0x45e	// 45e <lmac_tick_cb+0x45e>
 41a:	d8640a4f 	ld.b      	r3, (r4, 0xa4f)
 41e:	e4432010 	andi      	r2, r3, 16
 422:	e92200e8 	bnez      	r2, 0x5f2	// 5f2 <lmac_tick_cb+0x5f2>
 426:	3201      	movi      	r2, 1
 428:	c4625c04 	ins      	r3, r2, 4, 4
 42c:	d84422a1 	ld.w      	r2, (r4, 0xa84)
 430:	d82422a2 	ld.w      	r1, (r4, 0xa88)
 434:	dc640a4f 	st.b      	r3, (r4, 0xa4f)
 438:	5a62      	addi      	r3, r2, 1
 43a:	644d      	cmplt      	r3, r1
 43c:	5b05      	subu      	r0, r3, r1
 43e:	c4600c20 	incf      	r3, r0, 0
 442:	d82422a0 	ld.w      	r1, (r4, 0xa80)
 446:	644e      	cmpne      	r3, r1
 448:	0c08      	bf      	0x458	// 458 <lmac_tick_cb+0x458>
 44a:	e44202a2 	addi      	r2, r2, 675
 44e:	310b      	movi      	r1, 11
 450:	d4440881 	str.w      	r1, (r4, r2 << 2)
 454:	dc6422a1 	st.w      	r3, (r4, 0xa84)
 458:	1214      	lrw      	r0, 0x0	// 5a8 <os_sema_up+0x5a8>
 45a:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
 45e:	9866      	ld.w      	r3, (r14, 0x18)
 460:	c4c38022 	divu      	r2, r3, r6
 464:	e9020011 	bez      	r2, 0x486	// 486 <lmac_tick_cb+0x486>
 468:	3300      	movi      	r3, 0
 46a:	9500      	ld.w      	r0, (r5, 0x0)
 46c:	9521      	ld.w      	r1, (r5, 0x4)
 46e:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 472:	6c40      	or      	r1, r0
 474:	e9210009 	bnez      	r1, 0x486	// 486 <lmac_tick_cb+0x486>
 478:	d864037d 	ld.b      	r3, (r4, 0x37d)
 47c:	3201      	movi      	r2, 1
 47e:	c4625c03 	ins      	r3, r2, 3, 3
 482:	dc64037d 	st.b      	r3, (r4, 0x37d)
 486:	d864037d 	ld.b      	r3, (r4, 0x37d)
 48a:	e4632008 	andi      	r3, r3, 8
 48e:	e9030019 	bez      	r3, 0x4c0	// 4c0 <lmac_tick_cb+0x4c0>
 492:	d84422a1 	ld.w      	r2, (r4, 0xa84)
 496:	5a62      	addi      	r3, r2, 1
 498:	d82422a2 	ld.w      	r1, (r4, 0xa88)
 49c:	644d      	cmplt      	r3, r1
 49e:	5b05      	subu      	r0, r3, r1
 4a0:	c4600c20 	incf      	r3, r0, 0
 4a4:	d82422a0 	ld.w      	r1, (r4, 0xa80)
 4a8:	644e      	cmpne      	r3, r1
 4aa:	0c08      	bf      	0x4ba	// 4ba <lmac_tick_cb+0x4ba>
 4ac:	e44202a2 	addi      	r2, r2, 675
 4b0:	310d      	movi      	r1, 13
 4b2:	d4440881 	str.w      	r1, (r4, r2 << 2)
 4b6:	dc6422a1 	st.w      	r3, (r4, 0xa84)
 4ba:	111c      	lrw      	r0, 0x0	// 5a8 <os_sema_up+0x5a8>
 4bc:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
 4c0:	9867      	ld.w      	r3, (r14, 0x1c)
 4c2:	c4c38022 	divu      	r2, r3, r6
 4c6:	e9020021 	bez      	r2, 0x508	// 508 <lmac_tick_cb+0x508>
 4ca:	3300      	movi      	r3, 0
 4cc:	9500      	ld.w      	r0, (r5, 0x0)
 4ce:	9521      	ld.w      	r1, (r5, 0x4)
 4d0:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 4d4:	6c40      	or      	r1, r0
 4d6:	e9210019 	bnez      	r1, 0x508	// 508 <lmac_tick_cb+0x508>
 4da:	d8040892 	ld.b      	r0, (r4, 0x892)
 4de:	e46020f8 	andi      	r3, r0, 248
 4e2:	e9030013 	bez      	r3, 0x508	// 508 <lmac_tick_cb+0x508>
 4e6:	20f7      	addi      	r0, 248
 4e8:	dc040892 	st.b      	r0, (r4, 0x892)
 4ec:	e40020f8 	andi      	r0, r0, 248
 4f0:	e920000c 	bnez      	r0, 0x508	// 508 <lmac_tick_cb+0x508>
 4f4:	e0000000 	bsr      	0x0	// 0 <disable_print>
 4f8:	110e      	lrw      	r0, 0x0	// 5b0 <hgprintf+0x5b0>
 4fa:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 4fe:	300a      	movi      	r0, 10
 500:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
 504:	e0000000 	bsr      	0x0	// 0 <mcu_reset>
 508:	9868      	ld.w      	r3, (r14, 0x20)
 50a:	c4c38022 	divu      	r2, r3, r6
 50e:	e902002b 	bez      	r2, 0x564	// 564 <lmac_tick_cb+0x564>
 512:	3300      	movi      	r3, 0
 514:	9500      	ld.w      	r0, (r5, 0x0)
 516:	9521      	ld.w      	r1, (r5, 0x4)
 518:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 51c:	6c40      	or      	r1, r0
 51e:	e9210023 	bnez      	r1, 0x564	// 564 <lmac_tick_cb+0x564>
 522:	d8240875 	ld.b      	r1, (r4, 0x875)
 526:	e421200c 	andi      	r1, r1, 12
 52a:	394c      	cmpnei      	r1, 12
 52c:	081c      	bt      	0x564	// 564 <lmac_tick_cb+0x564>
 52e:	d864202f 	ld.w      	r3, (r4, 0xbc)
 532:	3b41      	cmpnei      	r3, 1
 534:	0818      	bt      	0x564	// 564 <lmac_tick_cb+0x564>
 536:	d84422a1 	ld.w      	r2, (r4, 0xa84)
 53a:	5a62      	addi      	r3, r2, 1
 53c:	d80422a2 	ld.w      	r0, (r4, 0xa88)
 540:	640d      	cmplt      	r3, r0
 542:	c403008c 	subu      	r12, r3, r0
 546:	c46c0c20 	incf      	r3, r12, 0
 54a:	d80422a0 	ld.w      	r0, (r4, 0xa80)
 54e:	640e      	cmpne      	r3, r0
 550:	0c07      	bf      	0x55e	// 55e <lmac_tick_cb+0x55e>
 552:	e44202a2 	addi      	r2, r2, 675
 556:	d4440881 	str.w      	r1, (r4, r2 << 2)
 55a:	dc6422a1 	st.w      	r3, (r4, 0xa84)
 55e:	1013      	lrw      	r0, 0x0	// 5a8 <os_sema_up+0x5a8>
 560:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
 564:	d82422a0 	ld.w      	r1, (r4, 0xa80)
 568:	d84422a1 	ld.w      	r2, (r4, 0xa84)
 56c:	6449      	cmplt      	r2, r1
 56e:	084c      	bt      	0x606	// 606 <lmac_tick_cb+0x606>
 570:	5a65      	subu      	r3, r2, r1
 572:	eb23003e 	cmplti      	r3, 63
 576:	64c3      	mvcv      	r3
 578:	74cc      	zextb      	r3, r3
 57a:	e903000c 	bez      	r3, 0x592	// 592 <lmac_tick_cb+0x592>
 57e:	3304      	movi      	r3, 4
 580:	b869      	st.w      	r3, (r14, 0x24)
 582:	9460      	ld.w      	r3, (r4, 0x0)
 584:	1a09      	addi      	r2, r14, 36
 586:	d9832009 	ld.w      	r12, (r3, 0x24)
 58a:	311b      	movi      	r1, 27
 58c:	3310      	movi      	r3, 16
 58e:	100a      	lrw      	r0, 0x0	// 5b4 <lmac_tick_cb+0x5b4>
 590:	7bf1      	jsr      	r12
 592:	140d      	addi      	r14, r14, 52
 594:	1498      	pop      	r4-r11, r15
	...
 5b6:	0000      	.short	0x0000
 5b8:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
 5bc:	d9872000 	ld.w      	r12, (r7, 0x0)
 5c0:	d9a72001 	ld.w      	r13, (r7, 0x4)
 5c4:	d9242233 	ld.w      	r9, (r4, 0x8cc)
 5c8:	32fa      	movi      	r2, 250
 5ca:	6400      	cmphs      	r0, r0
 5cc:	6033      	subc      	r0, r12
 5ce:	6077      	subc      	r1, r13
 5d0:	4242      	lsli      	r2, r2, 2
 5d2:	3300      	movi      	r3, 0
 5d4:	e0000000 	bsr      	0x0	// 0 <__muldi3>
 5d8:	d98920b2 	ld.w      	r12, (r9, 0x2c8)
 5dc:	d9a920b3 	ld.w      	r13, (r9, 0x2cc)
 5e0:	6401      	cmplt      	r0, r0
 5e2:	6031      	addc      	r0, r12
 5e4:	6075      	addc      	r1, r13
 5e6:	dc0920b2 	st.w      	r0, (r9, 0x2c8)
 5ea:	dc2920b3 	st.w      	r1, (r9, 0x2cc)
 5ee:	e800fd68 	br      	0xbe	// be <lmac_tick_cb+0xbe>
 5f2:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
 5f6:	e4632008 	andi      	r3, r3, 8
 5fa:	e903ff32 	bez      	r3, 0x45e	// 45e <lmac_tick_cb+0x45e>
 5fe:	1005      	lrw      	r0, 0x0	// 610 <hgprintf+0x610>
 600:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 604:	072d      	br      	0x45e	// 45e <lmac_tick_cb+0x45e>
 606:	d86422a2 	ld.w      	r3, (r4, 0xa88)
 60a:	60c6      	subu      	r3, r1
 60c:	60c8      	addu      	r3, r2
 60e:	07b2      	br      	0x572	// 572 <lmac_tick_cb+0x572>
 610:	00000000 	.long	0x00000000

Disassembly of section .text.pd_timer_irq_handler:

00000000 <pd_timer_irq_handler>:
   0:	14d2      	push      	r4-r5, r15
   2:	119a      	lrw      	r4, 0x0	// e8 <pd_timer_irq_handler+0xe8>
   4:	d8642267 	ld.w      	r3, (r4, 0x99c)
   8:	3b43      	cmpnei      	r3, 3
   a:	0c07      	bf      	0x18	// 18 <pd_timer_irq_handler+0x18>
   c:	d8640319 	ld.b      	r3, (r4, 0x319)
  10:	e4632002 	andi      	r3, r3, 2
  14:	e9030069 	bez      	r3, 0xe6	// e6 <pd_timer_irq_handler+0xe6>
  18:	3302      	movi      	r3, 2
  1a:	dc642267 	st.w      	r3, (r4, 0x99c)
  1e:	3200      	movi      	r2, 0
  20:	d8640319 	ld.b      	r3, (r4, 0x319)
  24:	c4625c01 	ins      	r3, r2, 1, 1
  28:	dc640319 	st.b      	r3, (r4, 0x319)
  2c:	3200      	movi      	r2, 0
  2e:	3300      	movi      	r3, 0
  30:	dc4420f0 	st.w      	r2, (r4, 0x3c0)
  34:	dc6420f1 	st.w      	r3, (r4, 0x3c4)
  38:	9460      	ld.w      	r3, (r4, 0x0)
  3a:	3501      	movi      	r5, 1
  3c:	834a      	ld.b      	r2, (r3, 0xa)
  3e:	c4455c00 	ins      	r2, r5, 0, 0
  42:	a34a      	st.b      	r2, (r3, 0xa)
  44:	e0000000 	bsr      	0x0	// 0 <tsensor_open>
  48:	1169      	lrw      	r3, 0x40026000	// ec <pd_timer_irq_handler+0xec>
  4a:	6c17      	mov      	r0, r5
  4c:	9345      	ld.w      	r2, (r3, 0x14)
  4e:	3abc      	bseti      	r2, 28
  50:	b345      	st.w      	r2, (r3, 0x14)
  52:	9345      	ld.w      	r2, (r3, 0x14)
  54:	3abb      	bseti      	r2, 27
  56:	b345      	st.w      	r2, (r3, 0x14)
  58:	9345      	ld.w      	r2, (r3, 0x14)
  5a:	3aba      	bseti      	r2, 26
  5c:	b345      	st.w      	r2, (r3, 0x14)
  5e:	9345      	ld.w      	r2, (r3, 0x14)
  60:	3ab3      	bseti      	r2, 19
  62:	b345      	st.w      	r2, (r3, 0x14)
  64:	9345      	ld.w      	r2, (r3, 0x14)
  66:	ec428000 	ori      	r2, r2, 32768
  6a:	b345      	st.w      	r2, (r3, 0x14)
  6c:	9345      	ld.w      	r2, (r3, 0x14)
  6e:	ec420800 	ori      	r2, r2, 2048
  72:	b345      	st.w      	r2, (r3, 0x14)
  74:	9345      	ld.w      	r2, (r3, 0x14)
  76:	ec420200 	ori      	r2, r2, 512
  7a:	b345      	st.w      	r2, (r3, 0x14)
  7c:	9345      	ld.w      	r2, (r3, 0x14)
  7e:	ec420100 	ori      	r2, r2, 256
  82:	b345      	st.w      	r2, (r3, 0x14)
  84:	9345      	ld.w      	r2, (r3, 0x14)
  86:	ec420020 	ori      	r2, r2, 32
  8a:	b345      	st.w      	r2, (r3, 0x14)
  8c:	9345      	ld.w      	r2, (r3, 0x14)
  8e:	ec420010 	ori      	r2, r2, 16
  92:	b345      	st.w      	r2, (r3, 0x14)
  94:	9347      	ld.w      	r2, (r3, 0x1c)
  96:	3ab2      	bseti      	r2, 18
  98:	b347      	st.w      	r2, (r3, 0x1c)
  9a:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
  9e:	30fa      	movi      	r0, 250
  a0:	4002      	lsli      	r0, r0, 2
  a2:	e0000000 	bsr      	0x0	// 0 <delay_us>
  a6:	d80420ce 	ld.w      	r0, (r4, 0x338)
  aa:	c4805760 	zext      	r0, r0, 27, 4
  ae:	e0000000 	bsr      	0x0	// 0 <lmac_lo_freq_set>
  b2:	ea038003 	movi      	r3, 32771
  b6:	c5e34903 	rotli      	r3, r3, 15
  ba:	d8632020 	ld.w      	r3, (r3, 0x80)
  be:	e4632004 	andi      	r3, r3, 4
  c2:	e9030007 	bez      	r3, 0xd0	// d0 <pd_timer_irq_handler+0xd0>
  c6:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_clear_pnd_sec>
  ca:	100a      	lrw      	r0, 0x0	// f0 <hgprintf+0xf0>
  cc:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  d0:	e0000000 	bsr      	0x0	// 0 <mcu_watchdog_feed>
  d4:	e0000000 	bsr      	0x0	// 0 <system_ap_sleep_wakeup_hook>
  d8:	e0000000 	bsr      	0x0	// 0 <lhw_enable_irq_ac>
  dc:	3000      	movi      	r0, 0
  de:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
  e2:	e0000000 	bsr      	0x0	// 0 <lmac_tdma_start>
  e6:	1492      	pop      	r4-r5, r15
  e8:	00000000 	.long	0x00000000
  ec:	40026000 	.long	0x40026000
  f0:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_psm_enter:

00000000 <lmac_psm_enter>:
   0:	14d5      	push      	r4-r8, r15
   2:	1421      	subi      	r14, r14, 4
   4:	03b2      	lrw      	r5, 0x0	// 238 <lmac_psm_enter+0x238>
   6:	6dcf      	mov      	r7, r3
   8:	d8652233 	ld.w      	r3, (r5, 0x8cc)
   c:	6e0b      	mov      	r8, r2
   e:	d843025b 	ld.b      	r2, (r3, 0x25b)
  12:	e44220c0 	andi      	r2, r2, 192
  16:	eb420040 	cmpnei      	r2, 64
  1a:	6d07      	mov      	r4, r1
  1c:	0822      	bt      	0x60	// 60 <lmac_psm_enter+0x60>
  1e:	d845202f 	ld.w      	r2, (r5, 0xbc)
  22:	e922001f 	bnez      	r2, 0x60	// 60 <lmac_psm_enter+0x60>
  26:	d8c320af 	ld.w      	r6, (r3, 0x2bc)
  2a:	d865202f 	ld.w      	r3, (r5, 0xbc)
  2e:	b860      	st.w      	r3, (r14, 0x0)
  30:	6c9b      	mov      	r2, r6
  32:	6cdf      	mov      	r3, r7
  34:	6c53      	mov      	r1, r4
  36:	031d      	lrw      	r0, 0x0	// 23c <lmac_psm_enter+0x23c>
  38:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  3c:	e9240033 	bnez      	r4, 0xa2	// a2 <lmac_psm_enter+0xa2>
  40:	d865202f 	ld.w      	r3, (r5, 0xbc)
  44:	3b42      	cmpnei      	r3, 2
  46:	0820      	bt      	0x86	// 86 <lmac_psm_enter+0x86>
  48:	d8650319 	ld.b      	r3, (r5, 0x319)
  4c:	e4632040 	andi      	r3, r3, 64
  50:	e9030010 	bez      	r3, 0x70	// 70 <lmac_psm_enter+0x70>
  54:	131b      	lrw      	r0, 0x0	// 240 <hgprintf+0x240>
  56:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  5a:	6c13      	mov      	r0, r4
  5c:	1401      	addi      	r14, r14, 4
  5e:	1495      	pop      	r4-r8, r15
  60:	8375      	ld.b      	r3, (r3, 0x15)
  62:	e4632007 	andi      	r3, r3, 7
  66:	3b46      	cmpnei      	r3, 6
  68:	3600      	movi      	r6, 0
  6a:	c4c80c40 	inct      	r6, r8, 0
  6e:	07de      	br      	0x2a	// 2a <lmac_psm_enter+0x2a>
  70:	1375      	lrw      	r3, 0x0	// 244 <lmac_psm_enter+0x244>
  72:	6c13      	mov      	r0, r4
  74:	9340      	ld.w      	r2, (r3, 0x0)
  76:	d8622033 	ld.w      	r3, (r2, 0xcc)
  7a:	ec630020 	ori      	r3, r3, 32
  7e:	dc622033 	st.w      	r3, (r2, 0xcc)
  82:	e0000000 	bsr      	0x0	// 0 <lmac_psm_enter>
  86:	3300      	movi      	r3, 0
  88:	dc650318 	st.b      	r3, (r5, 0x318)
  8c:	9560      	ld.w      	r3, (r5, 0x0)
  8e:	3101      	movi      	r1, 1
  90:	834a      	ld.b      	r2, (r3, 0xa)
  92:	3000      	movi      	r0, 0
  94:	c4415c00 	ins      	r2, r1, 0, 0
  98:	dc052267 	st.w      	r0, (r5, 0x99c)
  9c:	a34a      	st.b      	r2, (r3, 0xa)
  9e:	3400      	movi      	r4, 0
  a0:	07dd      	br      	0x5a	// 5a <lmac_psm_enter+0x5a>
  a2:	d8652267 	ld.w      	r3, (r5, 0x99c)
  a6:	3b43      	cmpnei      	r3, 3
  a8:	3100      	movi      	r1, 0
  aa:	0cc5      	bf      	0x234	// 234 <lmac_psm_enter+0x234>
  ac:	9560      	ld.w      	r3, (r5, 0x0)
  ae:	834a      	ld.b      	r2, (r3, 0xa)
  b0:	c4415c00 	ins      	r2, r1, 0, 0
  b4:	a34a      	st.b      	r2, (r3, 0xa)
  b6:	d8652233 	ld.w      	r3, (r5, 0x8cc)
  ba:	8375      	ld.b      	r3, (r3, 0x15)
  bc:	e4632007 	andi      	r3, r3, 7
  c0:	3b46      	cmpnei      	r3, 6
  c2:	0807      	bt      	0xd0	// d0 <lmac_psm_enter+0xd0>
  c4:	3303      	movi      	r3, 3
  c6:	6c07      	mov      	r0, r1
  c8:	dc652267 	st.w      	r3, (r5, 0x99c)
  cc:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
  d0:	d8652233 	ld.w      	r3, (r5, 0x8cc)
  d4:	8375      	ld.b      	r3, (r3, 0x15)
  d6:	e4632007 	andi      	r3, r3, 7
  da:	3b45      	cmpnei      	r3, 5
  dc:	0808      	bt      	0xec	// ec <lmac_psm_enter+0xec>
  de:	3303      	movi      	r3, 3
  e0:	3100      	movi      	r1, 0
  e2:	6c23      	mov      	r0, r8
  e4:	dc652267 	st.w      	r3, (r5, 0x99c)
  e8:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
  ec:	e907007d 	bez      	r7, 0x1e6	// 1e6 <lmac_psm_enter+0x1e6>
  f0:	d885202f 	ld.w      	r4, (r5, 0xbc)
  f4:	3c41      	cmpnei      	r4, 1
  f6:	0817      	bt      	0x124	// 124 <lmac_psm_enter+0x124>
  f8:	d8651505 	ld.h      	r3, (r5, 0xa0a)
  fc:	e923000a 	bnez      	r3, 0x110	// 110 <lmac_psm_enter+0x110>
 100:	d8650556 	ld.b      	r3, (r5, 0x556)
 104:	e9030006 	bez      	r3, 0x110	// 110 <lmac_psm_enter+0x110>
 108:	d8652196 	ld.w      	r3, (r5, 0x658)
 10c:	e9230009 	bnez      	r3, 0x11e	// 11e <lmac_psm_enter+0x11e>
 110:	3300      	movi      	r3, 0
 112:	dc650318 	st.b      	r3, (r5, 0x318)
 116:	3301      	movi      	r3, 1
 118:	dc652267 	st.w      	r3, (r5, 0x99c)
 11c:	07c1      	br      	0x9e	// 9e <lmac_psm_enter+0x9e>
 11e:	dc850318 	st.b      	r4, (r5, 0x318)
 122:	07fa      	br      	0x116	// 116 <lmac_psm_enter+0x116>
 124:	e9240029 	bnez      	r4, 0x176	// 176 <lmac_psm_enter+0x176>
 128:	d8652233 	ld.w      	r3, (r5, 0x8cc)
 12c:	3201      	movi      	r2, 1
 12e:	8335      	ld.b      	r1, (r3, 0x15)
 130:	c4225c03 	ins      	r1, r2, 3, 3
 134:	dc430257 	st.b      	r2, (r3, 0x257)
 138:	3203      	movi      	r2, 3
 13a:	a335      	st.b      	r1, (r3, 0x15)
 13c:	dc452267 	st.w      	r2, (r5, 0x99c)
 140:	d843025b 	ld.b      	r2, (r3, 0x25b)
 144:	e44220c0 	andi      	r2, r2, 192
 148:	eb420040 	cmpnei      	r2, 64
 14c:	0813      	bt      	0x172	// 172 <lmac_psm_enter+0x172>
 14e:	3218      	movi      	r2, 24
 150:	d8630a4d 	ld.b      	r3, (r3, 0xa4d)
 154:	7cc8      	mult      	r3, r2
 156:	60d4      	addu      	r3, r5
 158:	d8032030 	ld.w      	r0, (r3, 0xc0)
 15c:	e0000000 	bsr      	0x0	// 0 <lmac_lo_freq_set>
 160:	d8052233 	ld.w      	r0, (r5, 0x8cc)
 164:	e0000000 	bsr      	0x0	// 0 <dsleep_cfg_init>
 168:	3108      	movi      	r1, 8
 16a:	6c1b      	mov      	r0, r6
 16c:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 170:	0775      	br      	0x5a	// 5a <lmac_psm_enter+0x5a>
 172:	6c53      	mov      	r1, r4
 174:	07fb      	br      	0x16a	// 16a <lmac_psm_enter+0x16a>
 176:	3c42      	cmpnei      	r4, 2
 178:	082b      	bt      	0x1ce	// 1ce <lmac_psm_enter+0x1ce>
 17a:	1154      	lrw      	r2, 0xe000e100	// 248 <lmac_psm_enter+0x248>
 17c:	3380      	movi      	r3, 128
 17e:	4368      	lsli      	r3, r3, 8
 180:	dc622020 	st.w      	r3, (r2, 0x80)
 184:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_clk_sel_256k_sec>
 188:	3001      	movi      	r0, 1
 18a:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_trim_time_unit_set_sec>
 18e:	e0000000 	bsr      	0x0	// 0 <pmu_pd_rc256k_sw_trim_en_sec>
 192:	ea038003 	movi      	r3, 32771
 196:	c5e34903 	rotli      	r3, r3, 15
 19a:	d8032023 	ld.w      	r0, (r3, 0x8c)
 19e:	e4802001 	andi      	r4, r0, 1
 1a2:	e924fffc 	bnez      	r4, 0x19a	// 19a <lmac_psm_enter+0x19a>
 1a6:	e0000000 	bsr      	0x0	// 0 <pmu_pd_rc256k_hw_trim_en_sec>
 1aa:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_irq_en_sec>
 1ae:	1143      	lrw      	r2, 0x0	// 238 <lmac_psm_enter+0x238>
 1b0:	1127      	lrw      	r1, 0x0	// 24c <lmac_psm_enter+0x24c>
 1b2:	300f      	movi      	r0, 15
 1b4:	e0000000 	bsr      	0x0	// 0 <request_irq>
 1b8:	3380      	movi      	r3, 128
 1ba:	1144      	lrw      	r2, 0xe000e100	// 248 <lmac_psm_enter+0x248>
 1bc:	4368      	lsli      	r3, r3, 8
 1be:	b260      	st.w      	r3, (r2, 0x0)
 1c0:	3301      	movi      	r3, 1
 1c2:	dc650318 	st.b      	r3, (r5, 0x318)
 1c6:	3302      	movi      	r3, 2
 1c8:	dc652267 	st.w      	r3, (r5, 0x99c)
 1cc:	0747      	br      	0x5a	// 5a <lmac_psm_enter+0x5a>
 1ce:	9560      	ld.w      	r3, (r5, 0x0)
 1d0:	3101      	movi      	r1, 1
 1d2:	834a      	ld.b      	r2, (r3, 0xa)
 1d4:	c4415c00 	ins      	r2, r1, 0, 0
 1d8:	a34a      	st.b      	r2, (r3, 0xa)
 1da:	3400      	movi      	r4, 0
 1dc:	101d      	lrw      	r0, 0x0	// 250 <lmac_psm_enter+0x250>
 1de:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1e2:	2c00      	subi      	r4, 1
 1e4:	073b      	br      	0x5a	// 5a <lmac_psm_enter+0x5a>
 1e6:	d8652233 	ld.w      	r3, (r5, 0x8cc)
 1ea:	3201      	movi      	r2, 1
 1ec:	8335      	ld.b      	r1, (r3, 0x15)
 1ee:	c4225c03 	ins      	r1, r2, 3, 3
 1f2:	dc430257 	st.b      	r2, (r3, 0x257)
 1f6:	3203      	movi      	r2, 3
 1f8:	a335      	st.b      	r1, (r3, 0x15)
 1fa:	dc452267 	st.w      	r2, (r5, 0x99c)
 1fe:	d843025b 	ld.b      	r2, (r3, 0x25b)
 202:	e44220c0 	andi      	r2, r2, 192
 206:	eb420040 	cmpnei      	r2, 64
 20a:	0813      	bt      	0x230	// 230 <lmac_psm_enter+0x230>
 20c:	3218      	movi      	r2, 24
 20e:	d8630a4d 	ld.b      	r3, (r3, 0xa4d)
 212:	7cc8      	mult      	r3, r2
 214:	60d4      	addu      	r3, r5
 216:	d8032030 	ld.w      	r0, (r3, 0xc0)
 21a:	e0000000 	bsr      	0x0	// 0 <lmac_lo_freq_set>
 21e:	d8052233 	ld.w      	r0, (r5, 0x8cc)
 222:	e0000000 	bsr      	0x0	// 0 <dsleep_cfg_init>
 226:	3108      	movi      	r1, 8
 228:	6c1b      	mov      	r0, r6
 22a:	e0000000 	bsr      	0x0	// 0 <dsleep_enter>
 22e:	0738      	br      	0x9e	// 9e <lmac_psm_enter+0x9e>
 230:	6c5f      	mov      	r1, r7
 232:	07fb      	br      	0x228	// 228 <lmac_psm_enter+0x228>
 234:	6d07      	mov      	r4, r1
 236:	0712      	br      	0x5a	// 5a <lmac_psm_enter+0x5a>
	...
 248:	e000e100 	.long	0xe000e100
	...

Disassembly of section .text.lmac_obss_eval:

00000000 <lmac_obss_eval>:
   0:	14d8      	push      	r4-r11, r15
   2:	1422      	subi      	r14, r14, 8
   4:	1296      	lrw      	r4, 0x0	// 15c <lmac_obss_eval+0x15c>
   6:	d864432a 	ld.bs      	r3, (r4, 0x32a)
   a:	e9a300a3 	bhsz      	r3, 0x150	// 150 <lmac_obss_eval+0x150>
   e:	d8e40310 	ld.b      	r7, (r4, 0x310)
  12:	e4672002 	andi      	r3, r7, 2
  16:	e903009d 	bez      	r3, 0x150	// 150 <lmac_obss_eval+0x150>
  1a:	ea080000 	movi      	r8, 0
  1e:	3600      	movi      	r6, 0
  20:	e4a4023f 	addi      	r5, r4, 576
  24:	e508107f 	subi      	r8, r8, 128
  28:	6e9b      	mov      	r10, r6
  2a:	ea8c004e 	lrw      	r12, 0x0	// 160 <lmac_obss_eval+0x160>
  2e:	e4e72004 	andi      	r7, r7, 4
  32:	d9252000 	ld.w      	r9, (r5, 0x0)
  36:	e9090034 	bez      	r9, 0x9e	// 9e <lmac_obss_eval+0x9e>
  3a:	d86c2000 	ld.w      	r3, (r12, 0x0)
  3e:	64e6      	cmpne      	r9, r3
  40:	0c07      	bf      	0x4e	// 4e <lmac_obss_eval+0x4e>
  42:	d86420ce 	ld.w      	r3, (r4, 0x338)
  46:	c4835763 	zext      	r3, r3, 27, 4
  4a:	64e6      	cmpne      	r9, r3
  4c:	0804      	bt      	0x54	// 54 <lmac_obss_eval+0x54>
  4e:	8567      	ld.b      	r3, (r5, 0x7)
  50:	2305      	addi      	r3, 6
  52:	a567      	st.b      	r3, (r5, 0x7)
  54:	d9654007 	ld.bs      	r11, (r5, 0x7)
  58:	d8644a4d 	ld.bs      	r3, (r4, 0xa4d)
  5c:	60ee      	subu      	r3, r11
  5e:	d8444300 	ld.bs      	r2, (r4, 0x300)
  62:	648d      	cmplt      	r3, r2
  64:	0c1a      	bf      	0x98	// 98 <lmac_obss_eval+0x98>
  66:	d844483d 	ld.bs      	r2, (r4, 0x83d)
  6a:	d86403e1 	ld.b      	r3, (r4, 0x3e1)
  6e:	648d      	cmplt      	r3, r2
  70:	0c14      	bf      	0x98	// 98 <lmac_obss_eval+0x98>
  72:	3305      	movi      	r3, 5
  74:	dc640301 	st.b      	r3, (r4, 0x301)
  78:	e907000c 	bez      	r7, 0x90	// 90 <lmac_obss_eval+0x90>
  7c:	113a      	lrw      	r1, 0x0	// 164 <lmac_obss_eval+0x164>
  7e:	3234      	movi      	r2, 52
  80:	e4011067 	subi      	r0, r1, 104
  84:	dd8e2001 	st.w      	r12, (r14, 0x4)
  88:	e0000000 	bsr      	0x0	// 0 <memcpy>
  8c:	d98e2001 	ld.w      	r12, (r14, 0x4)
  90:	66e1      	cmplt      	r8, r11
  92:	0c03      	bf      	0x98	// 98 <lmac_obss_eval+0x98>
  94:	6e2f      	mov      	r8, r11
  96:	6da7      	mov      	r6, r9
  98:	3300      	movi      	r3, 0
  9a:	2b7f      	subi      	r3, 128
  9c:	a567      	st.b      	r3, (r5, 0x7)
  9e:	e54a0000 	addi      	r10, r10, 1
  a2:	eb4a0010 	cmpnei      	r10, 16
  a6:	250b      	addi      	r5, 12
  a8:	0bc5      	bt      	0x32	// 32 <lmac_obss_eval+0x32>
  aa:	d8244301 	ld.bs      	r1, (r4, 0x301)
  ae:	e961001f 	blsz      	r1, 0xec	// ec <lmac_obss_eval+0xec>
  b2:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
  b6:	2900      	subi      	r1, 1
  b8:	e4632001 	andi      	r3, r3, 1
  bc:	7444      	zextb      	r1, r1
  be:	dc240301 	st.b      	r1, (r4, 0x301)
  c2:	e9030005 	bez      	r3, 0xcc	// cc <lmac_obss_eval+0xcc>
  c6:	1109      	lrw      	r0, 0x0	// 168 <hgprintf+0x168>
  c8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  cc:	d8644301 	ld.bs      	r3, (r4, 0x301)
  d0:	e923000e 	bnez      	r3, 0xec	// ec <lmac_obss_eval+0xec>
  d4:	d8640310 	ld.b      	r3, (r4, 0x310)
  d8:	e4632004 	andi      	r3, r3, 4
  dc:	e9030008 	bez      	r3, 0xec	// ec <lmac_obss_eval+0xec>
  e0:	1123      	lrw      	r1, 0x0	// 16c <lmac_obss_eval+0x16c>
  e2:	3234      	movi      	r2, 52
  e4:	e4011033 	subi      	r0, r1, 52
  e8:	e0000000 	bsr      	0x0	// 0 <memcpy>
  ec:	e9660032 	blsz      	r6, 0x150	// 150 <lmac_obss_eval+0x150>
  f0:	d86420ce 	ld.w      	r3, (r4, 0x338)
  f4:	c4835763 	zext      	r3, r3, 27, 4
  f8:	64da      	cmpne      	r6, r3
  fa:	0c2b      	bf      	0x150	// 150 <lmac_obss_eval+0x150>
  fc:	10b9      	lrw      	r5, 0x0	// 160 <lmac_obss_eval+0x160>
  fe:	10fd      	lrw      	r7, 0x0	// 170 <lmac_obss_eval+0x170>
 100:	9540      	ld.w      	r2, (r5, 0x0)
 102:	649a      	cmpne      	r6, r2
 104:	0c28      	bf      	0x154	// 154 <lmac_obss_eval+0x154>
 106:	b5c0      	st.w      	r6, (r5, 0x0)
 108:	3200      	movi      	r2, 0
 10a:	658d      	cmplt      	r3, r6
 10c:	3304      	movi      	r3, 4
 10e:	3602      	movi      	r6, 2
 110:	a740      	st.b      	r2, (r7, 0x0)
 112:	c4c30c40 	inct      	r6, r3, 0
 116:	8760      	ld.b      	r3, (r7, 0x0)
 118:	b8c0      	st.w      	r6, (r14, 0x0)
 11a:	9540      	ld.w      	r2, (r5, 0x0)
 11c:	6c63      	mov      	r1, r8
 11e:	1016      	lrw      	r0, 0x0	// 174 <lmac_obss_eval+0x174>
 120:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 124:	8760      	ld.b      	r3, (r7, 0x0)
 126:	658c      	cmphs      	r3, r6
 128:	0c14      	bf      	0x150	// 150 <lmac_obss_eval+0x150>
 12a:	9520      	ld.w      	r1, (r5, 0x0)
 12c:	1073      	lrw      	r3, 0xfff551a0	// 178 <lmac_obss_eval+0x178>
 12e:	32fa      	movi      	r2, 250
 130:	60c4      	addu      	r3, r1
 132:	4242      	lsli      	r2, r2, 2
 134:	c4438043 	divs      	r3, r3, r2
 138:	dc640348 	st.b      	r3, (r4, 0x348)
 13c:	330a      	movi      	r3, 10
 13e:	1010      	lrw      	r0, 0x0	// 17c <lmac_obss_eval+0x17c>
 140:	dc64032a 	st.b      	r3, (r4, 0x32a)
 144:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 148:	3300      	movi      	r3, 0
 14a:	a760      	st.b      	r3, (r7, 0x0)
 14c:	3300      	movi      	r3, 0
 14e:	b560      	st.w      	r3, (r5, 0x0)
 150:	1402      	addi      	r14, r14, 8
 152:	1498      	pop      	r4-r11, r15
 154:	8740      	ld.b      	r2, (r7, 0x0)
 156:	2200      	addi      	r2, 1
 158:	07d9      	br      	0x10a	// 10a <lmac_obss_eval+0x10a>
	...
 176:	0000      	.short	0x0000
 178:	fff551a0 	.long	0xfff551a0
 17c:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_chan_list_eval:

00000000 <lmac_chan_list_eval>:
   0:	14d8      	push      	r4-r11, r15
   2:	1626      	subi      	r14, r14, 280
   4:	0194      	lrw      	r4, 0x0	// 330 <lmac_chan_list_eval+0x330>
   6:	d8a44301 	ld.bs      	r5, (r4, 0x301)
   a:	e9250008 	bnez      	r5, 0x1a	// 1a <lmac_chan_list_eval+0x1a>
   e:	d864037c 	ld.b      	r3, (r4, 0x37c)
  12:	e4632002 	andi      	r3, r3, 2
  16:	e9230009 	bnez      	r3, 0x28	// 28 <lmac_chan_list_eval+0x28>
  1a:	0158      	lrw      	r2, 0x0	// 334 <lmac_chan_list_eval+0x334>
  1c:	3300      	movi      	r3, 0
  1e:	b260      	st.w      	r3, (r2, 0x0)
  20:	0159      	lrw      	r2, 0x0	// 338 <lmac_chan_list_eval+0x338>
  22:	a260      	st.b      	r3, (r2, 0x0)
  24:	1606      	addi      	r14, r14, 280
  26:	1498      	pop      	r4-r11, r15
  28:	ea8a00c5 	lrw      	r10, 0x0	// 33c <lmac_chan_list_eval+0x33c>
  2c:	e52400bf 	addi      	r9, r4, 192
  30:	e50e0017 	addi      	r8, r14, 24
  34:	dd4e2003 	st.w      	r10, (r14, 0xc)
  38:	d8640378 	ld.b      	r3, (r4, 0x378)
  3c:	64d5      	cmplt      	r5, r3
  3e:	1f16      	addi      	r7, r14, 88
  40:	1e26      	addi      	r6, r14, 152
  42:	0c7a      	bf      	0x136	// 136 <lmac_chan_list_eval+0x136>
  44:	d86420ce 	ld.w      	r3, (r4, 0x338)
  48:	d8292000 	ld.w      	r1, (r9, 0x0)
  4c:	c4835763 	zext      	r3, r3, 27, 4
  50:	64c6      	cmpne      	r1, r3
  52:	086e      	bt      	0x12e	// 12e <lmac_chan_list_eval+0x12e>
  54:	d8444a4e 	ld.bs      	r2, (r4, 0xa4e)
  58:	d864431d 	ld.bs      	r3, (r4, 0x31d)
  5c:	64c9      	cmplt      	r2, r3
  5e:	0868      	bt      	0x12e	// 12e <lmac_chan_list_eval+0x12e>
  60:	d864483d 	ld.bs      	r3, (r4, 0x83d)
  64:	3205      	movi      	r2, 5
  66:	c4438043 	divs      	r3, r3, r2
  6a:	3b33      	cmplti      	r3, 20
  6c:	0c63      	bf      	0x132	// 132 <lmac_chan_list_eval+0x132>
  6e:	3b22      	cmplti      	r3, 3
  70:	3200      	movi      	r2, 0
  72:	c4620c40 	inct      	r3, r2, 0
  76:	d8490007 	ld.b      	r2, (r9, 0x7)
  7a:	60c8      	addu      	r3, r2
  7c:	74ce      	sextb      	r3, r3
  7e:	1a36      	addi      	r2, r14, 216
  80:	d4a20883 	str.w      	r3, (r2, r5 << 2)
  84:	d8440690 	ld.b      	r2, (r4, 0x690)
  88:	7c8d      	mulsh      	r2, r3
  8a:	d4a80881 	str.w      	r1, (r8, r5 << 2)
  8e:	3164      	movi      	r1, 100
  90:	c4228042 	divs      	r2, r2, r1
  94:	d4a70882 	str.w      	r2, (r7, r5 << 2)
  98:	d8440691 	ld.b      	r2, (r4, 0x691)
  9c:	7cc9      	mulsh      	r3, r2
  9e:	c4238043 	divs      	r3, r3, r1
  a2:	d4a60883 	str.w      	r3, (r6, r5 << 2)
  a6:	d86a0000 	ld.b      	r3, (r10, 0x0)
  aa:	e9030012 	bez      	r3, 0xce	// ce <lmac_chan_list_eval+0xce>
  ae:	1b36      	addi      	r3, r14, 216
  b0:	d0a30883 	ldr.w      	r3, (r3, r5 << 2)
  b4:	b862      	st.w      	r3, (r14, 0x8)
  b6:	b8a1      	st.w      	r5, (r14, 0x4)
  b8:	d0a80883 	ldr.w      	r3, (r8, r5 << 2)
  bc:	b860      	st.w      	r3, (r14, 0x0)
  be:	d8440378 	ld.b      	r2, (r4, 0x378)
  c2:	6cd7      	mov      	r3, r5
  c4:	ea0101c7 	movi      	r1, 455
  c8:	0301      	lrw      	r0, 0x0	// 340 <hgprintf+0x340>
  ca:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ce:	2500      	addi      	r5, 1
  d0:	3d50      	cmpnei      	r5, 16
  d2:	e5290017 	addi      	r9, r9, 24
  d6:	0bb1      	bt      	0x38	// 38 <lmac_chan_list_eval+0x38>
  d8:	d8641504 	ld.h      	r3, (r4, 0xa08)
  dc:	e9230033 	bnez      	r3, 0x142	// 142 <lmac_chan_list_eval+0x142>
  e0:	3500      	movi      	r5, 0
  e2:	ea08007f 	movi      	r8, 127
  e6:	6d97      	mov      	r6, r5
  e8:	6de3      	mov      	r7, r8
  ea:	e54e0017 	addi      	r10, r14, 24
  ee:	e52e00d7 	addi      	r9, r14, 216
  f2:	ea8b0095 	lrw      	r11, 0x0	// 344 <lmac_chan_list_eval+0x344>
  f6:	d8640378 	ld.b      	r3, (r4, 0x378)
  fa:	64d5      	cmplt      	r5, r3
  fc:	08c3      	bt      	0x282	// 282 <lmac_chan_list_eval+0x282>
  fe:	eb47007f 	cmpnei      	r7, 127
 102:	0c06      	bf      	0x10e	// 10e <lmac_chan_list_eval+0x10e>
 104:	eb48007f 	cmpnei      	r8, 127
 108:	0c03      	bf      	0x10e	// 10e <lmac_chan_list_eval+0x10e>
 10a:	e92600e7 	bnez      	r6, 0x2d8	// 2d8 <lmac_chan_list_eval+0x2d8>
 10e:	0310      	lrw      	r0, 0x0	// 348 <hgprintf+0x348>
 110:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 114:	3500      	movi      	r5, 0
 116:	1e36      	addi      	r6, r14, 216
 118:	1f06      	addi      	r7, r14, 24
 11a:	ea88008d 	lrw      	r8, 0x0	// 34c <lmac_chan_list_eval+0x34c>
 11e:	d8640378 	ld.b      	r3, (r4, 0x378)
 122:	64d5      	cmplt      	r5, r3
 124:	08d1      	bt      	0x2c6	// 2c6 <lmac_chan_list_eval+0x2c6>
 126:	9863      	ld.w      	r3, (r14, 0xc)
 128:	3201      	movi      	r2, 1
 12a:	a340      	st.b      	r2, (r3, 0x0)
 12c:	077c      	br      	0x24	// 24 <lmac_chan_list_eval+0x24>
 12e:	3300      	movi      	r3, 0
 130:	07a3      	br      	0x76	// 76 <lmac_chan_list_eval+0x76>
 132:	3314      	movi      	r3, 20
 134:	07a1      	br      	0x76	// 76 <lmac_chan_list_eval+0x76>
 136:	3300      	movi      	r3, 0
 138:	d4a80883 	str.w      	r3, (r8, r5 << 2)
 13c:	d4a70883 	str.w      	r3, (r7, r5 << 2)
 140:	07b1      	br      	0xa2	// a2 <lmac_chan_list_eval+0xa2>
 142:	3100      	movi      	r1, 0
 144:	2900      	subi      	r1, 1
 146:	031c      	lrw      	r0, 0x0	// 350 <lmac_chan_list_eval+0x350>
 148:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
 14c:	03bd      	lrw      	r5, 0x0	// 354 <lmac_chan_list_eval+0x354>
 14e:	d9a40378 	ld.b      	r13, (r4, 0x378)
 152:	d824227e 	ld.w      	r1, (r4, 0x9f8)
 156:	3000      	movi      	r0, 0
 158:	ea0c0064 	movi      	r12, 100
 15c:	6546      	cmpne      	r1, r5
 15e:	0853      	bt      	0x204	// 204 <lmac_chan_list_eval+0x204>
 160:	131c      	lrw      	r0, 0x0	// 350 <lmac_chan_list_eval+0x350>
 162:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
 166:	d9a40378 	ld.b      	r13, (r4, 0x378)
 16a:	e46d1000 	subi      	r3, r13, 1
 16e:	3000      	movi      	r0, 0
 170:	74cc      	zextb      	r3, r3
 172:	6d43      	mov      	r5, r0
 174:	b864      	st.w      	r3, (r14, 0x10)
 176:	ea0c00ff 	movi      	r12, 255
 17a:	2d00      	subi      	r5, 1
 17c:	1e26      	addi      	r6, r14, 152
 17e:	3721      	movi      	r7, 33
 180:	e50e0057 	addi      	r8, r14, 88
 184:	ea090043 	movi      	r9, 67
 188:	ea0a0064 	movi      	r10, 100
 18c:	6741      	cmplt      	r0, r13
 18e:	0fa9      	bf      	0xe0	// e0 <lmac_chan_list_eval+0xe0>
 190:	74f2      	sextb      	r3, r12
 192:	e42c0001 	addi      	r1, r12, 2
 196:	654e      	cmpne      	r3, r5
 198:	3200      	movi      	r2, 0
 19a:	e5600000 	addi      	r11, r0, 1
 19e:	c4620c20 	incf      	r3, r2, 0
 1a2:	7444      	zextb      	r1, r1
 1a4:	9844      	ld.w      	r2, (r14, 0x10)
 1a6:	676d      	cmplt      	r11, r13
 1a8:	c4220c20 	incf      	r1, r2, 0
 1ac:	d0660882 	ldr.w      	r2, (r6, r3 << 2)
 1b0:	d0680883 	ldr.w      	r3, (r8, r3 << 2)
 1b4:	7ce4      	mult      	r3, r9
 1b6:	7c9c      	mult      	r2, r7
 1b8:	608c      	addu      	r2, r3
 1ba:	c5428042 	divs      	r2, r2, r10
 1be:	5262      	asri      	r3, r2, 2
 1c0:	b865      	st.w      	r3, (r14, 0x14)
 1c2:	d0060883 	ldr.w      	r3, (r6, r0 << 2)
 1c6:	7cdc      	mult      	r3, r7
 1c8:	6c8f      	mov      	r2, r3
 1ca:	d0080883 	ldr.w      	r3, (r8, r0 << 2)
 1ce:	7ce4      	mult      	r3, r9
 1d0:	608c      	addu      	r2, r3
 1d2:	c5428043 	divs      	r3, r2, r10
 1d6:	7446      	sextb      	r1, r1
 1d8:	5361      	asri      	r3, r3, 1
 1da:	9845      	ld.w      	r2, (r14, 0x14)
 1dc:	608c      	addu      	r2, r3
 1de:	d0260883 	ldr.w      	r3, (r6, r1 << 2)
 1e2:	d0280881 	ldr.w      	r1, (r8, r1 << 2)
 1e6:	7cdc      	mult      	r3, r7
 1e8:	7c64      	mult      	r1, r9
 1ea:	60c4      	addu      	r3, r1
 1ec:	c5438043 	divs      	r3, r3, r10
 1f0:	5362      	asri      	r3, r3, 2
 1f2:	608c      	addu      	r2, r3
 1f4:	e58c0000 	addi      	r12, r12, 1
 1f8:	1b36      	addi      	r3, r14, 216
 1fa:	d4030882 	str.w      	r2, (r3, r0 << 2)
 1fe:	7730      	zextb      	r12, r12
 200:	6c2f      	mov      	r0, r11
 202:	07c5      	br      	0x18c	// 18c <lmac_chan_list_eval+0x18c>
 204:	d861006b 	ld.b      	r3, (r1, 0x6b)
 208:	e4432040 	andi      	r2, r3, 64
 20c:	e9220004 	bnez      	r2, 0x214	// 214 <lmac_chan_list_eval+0x214>
 210:	9120      	ld.w      	r1, (r1, 0x0)
 212:	07a5      	br      	0x15c	// 15c <lmac_chan_list_eval+0x15c>
 214:	e4632002 	andi      	r3, r3, 2
 218:	e923fffc 	bnez      	r3, 0x210	// 210 <lmac_chan_list_eval+0x210>
 21c:	674d      	cmplt      	r3, r13
 21e:	0ff9      	bf      	0x210	// 210 <lmac_chan_list_eval+0x210>
 220:	d068088a 	ldr.w      	r10, (r8, r3 << 2)
 224:	e90a0023 	bez      	r10, 0x26a	// 26a <lmac_chan_list_eval+0x26a>
 228:	3200      	movi      	r2, 0
 22a:	c4424829 	lsli      	r9, r2, 2
 22e:	6244      	addu      	r9, r1
 230:	d9292006 	ld.w      	r9, (r9, 0x18)
 234:	666a      	cmpne      	r10, r9
 236:	081c      	bt      	0x26e	// 26e <lmac_chan_list_eval+0x26e>
 238:	6084      	addu      	r2, r1
 23a:	d92100b2 	ld.b      	r9, (r1, 0xb2)
 23e:	d9424058 	ld.bs      	r10, (r2, 0x58)
 242:	7e69      	mulsh      	r9, r10
 244:	c5898049 	divs      	r9, r9, r12
 248:	d0670882 	ldr.w      	r2, (r7, r3 << 2)
 24c:	7666      	sextb      	r9, r9
 24e:	6248      	addu      	r9, r2
 250:	d84100b3 	ld.b      	r2, (r1, 0xb3)
 254:	7ca9      	mulsh      	r2, r10
 256:	c5828042 	divs      	r2, r2, r12
 25a:	d4670889 	str.w      	r9, (r7, r3 << 2)
 25e:	748a      	sextb      	r2, r2
 260:	d0660889 	ldr.w      	r9, (r6, r3 << 2)
 264:	60a4      	addu      	r2, r9
 266:	d4660882 	str.w      	r2, (r6, r3 << 2)
 26a:	2300      	addi      	r3, 1
 26c:	07d8      	br      	0x21c	// 21c <lmac_chan_list_eval+0x21c>
 26e:	2200      	addi      	r2, 1
 270:	3a50      	cmpnei      	r2, 16
 272:	0bdc      	bt      	0x22a	// 22a <lmac_chan_list_eval+0x22a>
 274:	d4680880 	str.w      	r0, (r8, r3 << 2)
 278:	d4670880 	str.w      	r0, (r7, r3 << 2)
 27c:	d4660880 	str.w      	r0, (r6, r3 << 2)
 280:	07f5      	br      	0x26a	// 26a <lmac_chan_list_eval+0x26a>
 282:	d0aa0883 	ldr.w      	r3, (r10, r5 << 2)
 286:	e9030010 	bez      	r3, 0x2a6	// 2a6 <lmac_chan_list_eval+0x2a6>
 28a:	d84420ce 	ld.w      	r2, (r4, 0x338)
 28e:	c4825762 	zext      	r2, r2, 27, 4
 292:	648e      	cmpne      	r3, r2
 294:	0803      	bt      	0x29a	// 29a <lmac_chan_list_eval+0x29a>
 296:	d0a91087 	ldr.bs      	r7, (r9, r5 << 2)
 29a:	d0a90882 	ldr.w      	r2, (r9, r5 << 2)
 29e:	6609      	cmplt      	r2, r8
 2a0:	0c03      	bf      	0x2a6	// 2a6 <lmac_chan_list_eval+0x2a6>
 2a2:	760a      	sextb      	r8, r2
 2a4:	6d8f      	mov      	r6, r3
 2a6:	9843      	ld.w      	r2, (r14, 0xc)
 2a8:	8240      	ld.b      	r2, (r2, 0x0)
 2aa:	e902000c 	bez      	r2, 0x2c2	// 2c2 <lmac_chan_list_eval+0x2c2>
 2ae:	d0a90882 	ldr.w      	r2, (r9, r5 << 2)
 2b2:	3180      	movi      	r1, 128
 2b4:	b841      	st.w      	r2, (r14, 0x4)
 2b6:	b8a0      	st.w      	r5, (r14, 0x0)
 2b8:	6c97      	mov      	r2, r5
 2ba:	4122      	lsli      	r1, r1, 2
 2bc:	6c2f      	mov      	r0, r11
 2be:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2c2:	2500      	addi      	r5, 1
 2c4:	0719      	br      	0xf6	// f6 <lmac_chan_list_eval+0xf6>
 2c6:	d0a60882 	ldr.w      	r2, (r6, r5 << 2)
 2ca:	d0a70881 	ldr.w      	r1, (r7, r5 << 2)
 2ce:	6c23      	mov      	r0, r8
 2d0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2d4:	2500      	addi      	r5, 1
 2d6:	0724      	br      	0x11e	// 11e <lmac_chan_list_eval+0x11e>
 2d8:	9863      	ld.w      	r3, (r14, 0xc)
 2da:	3200      	movi      	r2, 0
 2dc:	a340      	st.b      	r2, (r3, 0x0)
 2de:	d864432a 	ld.bs      	r3, (r4, 0x32a)
 2e2:	10b6      	lrw      	r5, 0x0	// 338 <lmac_chan_list_eval+0x338>
 2e4:	e9a30041 	bhsz      	r3, 0x366	// 366 <lmac_chan_list_eval+0x366>
 2e8:	d86411be 	ld.h      	r3, (r4, 0x37c)
 2ec:	c4435523 	zext      	r3, r3, 9, 2
 2f0:	61ce      	subu      	r7, r3
 2f2:	65e1      	cmplt      	r8, r7
 2f4:	0c39      	bf      	0x366	// 366 <lmac_chan_list_eval+0x366>
 2f6:	10f0      	lrw      	r7, 0x0	// 334 <lmac_chan_list_eval+0x334>
 2f8:	9760      	ld.w      	r3, (r7, 0x0)
 2fa:	64da      	cmpne      	r6, r3
 2fc:	0832      	bt      	0x360	// 360 <lmac_chan_list_eval+0x360>
 2fe:	8560      	ld.b      	r3, (r5, 0x0)
 300:	2300      	addi      	r3, 1
 302:	74ce      	sextb      	r3, r3
 304:	3b24      	cmplti      	r3, 5
 306:	a560      	st.b      	r3, (r5, 0x0)
 308:	0a8e      	bt      	0x24	// 24 <lmac_chan_list_eval+0x24>
 30a:	1074      	lrw      	r3, 0xfff551a0	// 358 <lmac_chan_list_eval+0x358>
 30c:	32fa      	movi      	r2, 250
 30e:	4242      	lsli      	r2, r2, 2
 310:	60d8      	addu      	r3, r6
 312:	c4438023 	divu      	r3, r3, r2
 316:	dc640348 	st.b      	r3, (r4, 0x348)
 31a:	6c5b      	mov      	r1, r6
 31c:	330a      	movi      	r3, 10
 31e:	1010      	lrw      	r0, 0x0	// 35c <lmac_chan_list_eval+0x35c>
 320:	dc64032a 	st.b      	r3, (r4, 0x32a)
 324:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 328:	3300      	movi      	r3, 0
 32a:	b760      	st.w      	r3, (r7, 0x0)
 32c:	a560      	st.b      	r3, (r5, 0x0)
 32e:	067b      	br      	0x24	// 24 <lmac_chan_list_eval+0x24>
	...
 358:	fff551a0 	.long	0xfff551a0
 35c:	00000000 	.long	0x00000000
 360:	b7c0      	st.w      	r6, (r7, 0x0)
 362:	3301      	movi      	r3, 1
 364:	07e4      	br      	0x32c	// 32c <lmac_chan_list_eval+0x32c>
 366:	d8654000 	ld.bs      	r3, (r5, 0x0)
 36a:	e9630004 	blsz      	r3, 0x372	// 372 <lmac_chan_list_eval+0x372>
 36e:	2b00      	subi      	r3, 1
 370:	07de      	br      	0x32c	// 32c <lmac_chan_list_eval+0x32c>
 372:	1063      	lrw      	r3, 0x0	// 37c <lmac_chan_list_eval+0x37c>
 374:	3200      	movi      	r2, 0
 376:	b340      	st.w      	r2, (r3, 0x0)
 378:	0656      	br      	0x24	// 24 <lmac_chan_list_eval+0x24>
 37a:	0000      	.short	0x0000
 37c:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_doze_enter:

00000000 <lmac_doze_enter>:
   0:	14d2      	push      	r4-r5, r15
   2:	3400      	movi      	r4, 0
   4:	10ad      	lrw      	r5, 0x0	// 38 <lmac_doze_enter+0x38>
   6:	2c00      	subi      	r4, 1
   8:	9540      	ld.w      	r2, (r5, 0x0)
   a:	9270      	ld.w      	r3, (r2, 0x40)
   c:	3b87      	bclri      	r3, 7
   e:	b270      	st.w      	r3, (r2, 0x40)
  10:	e0000000 	bsr      	0x0	// 0 <lhw_abort_fsm>
  14:	9560      	ld.w      	r3, (r5, 0x0)
  16:	9350      	ld.w      	r2, (r3, 0x40)
  18:	ec420080 	ori      	r2, r2, 128
  1c:	b350      	st.w      	r2, (r3, 0x40)
  1e:	b392      	st.w      	r4, (r3, 0x48)
  20:	936d      	ld.w      	r3, (r3, 0x34)
  22:	e923fff3 	bnez      	r3, 0x8	// 8 <lmac_doze_enter+0x8>
  26:	1066      	lrw      	r3, 0x0	// 3c <lmac_doze_enter+0x3c>
  28:	3101      	movi      	r1, 1
  2a:	d8430680 	ld.b      	r2, (r3, 0x680)
  2e:	c4415c00 	ins      	r2, r1, 0, 0
  32:	dc430680 	st.b      	r2, (r3, 0x680)
  36:	1492      	pop      	r4-r5, r15
	...

Disassembly of section .text.lmac_doze_exit:

00000000 <lmac_doze_exit>:
   0:	14d0      	push      	r15
   2:	1069      	lrw      	r3, 0x0	// 24 <lmac_doze_exit+0x24>
   4:	3000      	movi      	r0, 0
   6:	9340      	ld.w      	r2, (r3, 0x0)
   8:	9270      	ld.w      	r3, (r2, 0x40)
   a:	3b87      	bclri      	r3, 7
   c:	b270      	st.w      	r3, (r2, 0x40)
   e:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
  12:	1066      	lrw      	r3, 0x0	// 28 <lmac_doze_exit+0x28>
  14:	3100      	movi      	r1, 0
  16:	d8430680 	ld.b      	r2, (r3, 0x680)
  1a:	c4415c00 	ins      	r2, r1, 0, 0
  1e:	dc430680 	st.b      	r2, (r3, 0x680)
  22:	1490      	pop      	r15
	...

Disassembly of section .text.lmac_rf_reset:

00000000 <lmac_rf_reset>:
   0:	14d0      	push      	r15
   2:	e0000000 	bsr      	0x0	// 0 <lmac_rf_reset>
   6:	e0000000 	bsr      	0x0	// 0 <ah_rf_close>
   a:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
   e:	e0000000 	bsr      	0x0	// 0 <lmac_rf_reset>
  12:	1490      	pop      	r15

Disassembly of section .text.lmac_chip_monitor:

00000000 <lmac_chip_monitor>:
   0:	14d8      	push      	r4-r11, r15
   2:	1425      	subi      	r14, r14, 20
   4:	3002      	movi      	r0, 2
   6:	e0000000 	bsr      	0x0	// 0 <tsensor_meas>
   a:	7443      	sexth      	r1, r0
   c:	eb210095 	cmplti      	r1, 150
  10:	018d      	lrw      	r4, 0x0	// 358 <lmac_chip_monitor+0x358>
  12:	0cce      	bf      	0x1ae	// 1ae <lmac_chip_monitor+0x1ae>
  14:	dc24219e 	st.w      	r1, (r4, 0x678)
  18:	e0000000 	bsr      	0x0	// 0 <vcc_meas>
  1c:	ea8900d0 	lrw      	r9, 0x0	// 35c <lmac_chip_monitor+0x35c>
  20:	dc04219f 	st.w      	r0, (r4, 0x67c)
  24:	e0000000 	bsr      	0x0	// 0 <vdd13b_meas>
  28:	dc0421b6 	st.w      	r0, (r4, 0x6d8)
  2c:	e0000000 	bsr      	0x0	// 0 <vdd13c_meas>
  30:	dc0421b7 	st.w      	r0, (r4, 0x6dc)
  34:	d8694009 	ld.bs      	r3, (r9, 0x9)
  38:	3023      	movi      	r0, 35
  3a:	d844219e 	ld.w      	r2, (r4, 0x678)
  3e:	586d      	subu      	r3, r0, r3
  40:	60c8      	addu      	r3, r2
  42:	dc64219e 	st.w      	r3, (r4, 0x678)
  46:	600e      	subu      	r0, r3
  48:	e0000000 	bsr      	0x0	// 0 <__floatsisf>
  4c:	ea214120 	movih      	r1, 16672
  50:	e0000000 	bsr      	0x0	// 0 <__divsf3>
  54:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
  58:	015d      	lrw      	r2, 0xcccccccd	// 360 <lmac_chip_monitor+0x360>
  5a:	017c      	lrw      	r3, 0x3fe4cccc	// 364 <lmac_chip_monitor+0x364>
  5c:	e0000000 	bsr      	0x0	// 0 <__muldf3>
  60:	3200      	movi      	r2, 0
  62:	ea233fe0 	movih      	r3, 16352
  66:	6e83      	mov      	r10, r0
  68:	6e07      	mov      	r8, r1
  6a:	e0000000 	bsr      	0x0	// 0 <__adddf3>
  6e:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
  72:	6ec3      	mov      	r11, r0
  74:	0262      	lrw      	r3, 0x3fc99999	// 368 <lmac_chip_monitor+0x368>
  76:	0241      	lrw      	r2, 0x9999999a	// 36c <lmac_chip_monitor+0x36c>
  78:	6c63      	mov      	r1, r8
  7a:	6d43      	mov      	r5, r0
  7c:	6c2b      	mov      	r0, r10
  7e:	e0000000 	bsr      	0x0	// 0 <__adddf3>
  82:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
  86:	6dc3      	mov      	r7, r0
  88:	6c63      	mov      	r1, r8
  8a:	6d83      	mov      	r6, r0
  8c:	6c2b      	mov      	r0, r10
  8e:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
  92:	d8690007 	ld.b      	r3, (r9, 0x7)
  96:	3b42      	cmpnei      	r3, 2
  98:	6e83      	mov      	r10, r0
  9a:	6e03      	mov      	r8, r0
  9c:	09a3      	bt      	0x3e2	// 3e2 <lmac_chip_monitor+0x3e2>
  9e:	d86420ce 	ld.w      	r3, (r4, 0x338)
  a2:	c4835763 	zext      	r3, r3, 27, 4
  a6:	024c      	lrw      	r2, 0xd6d7f	// 370 <lmac_chip_monitor+0x370>
  a8:	64c9      	cmplt      	r2, r3
  aa:	0886      	bt      	0x1b6	// 1b6 <lmac_chip_monitor+0x1b6>
  ac:	6c2f      	mov      	r0, r11
  ae:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
  b2:	0250      	lrw      	r2, 0x9999999a	// 36c <lmac_chip_monitor+0x36c>
  b4:	026f      	lrw      	r3, 0x3fd99999	// 374 <lmac_chip_monitor+0x374>
  b6:	e0000000 	bsr      	0x0	// 0 <__subdf3>
  ba:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
  be:	6d43      	mov      	r5, r0
  c0:	6c1f      	mov      	r0, r7
  c2:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
  c6:	0255      	lrw      	r2, 0x9999999a	// 36c <lmac_chip_monitor+0x36c>
  c8:	0274      	lrw      	r3, 0x3fd99999	// 374 <lmac_chip_monitor+0x374>
  ca:	e0000000 	bsr      	0x0	// 0 <__subdf3>
  ce:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
  d2:	6d83      	mov      	r6, r0
  d4:	6c2b      	mov      	r0, r10
  d6:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
  da:	025a      	lrw      	r2, 0x9999999a	// 36c <lmac_chip_monitor+0x36c>
  dc:	0279      	lrw      	r3, 0x3fd99999	// 374 <lmac_chip_monitor+0x374>
  de:	e0000000 	bsr      	0x0	// 0 <__subdf3>
  e2:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
  e6:	6e03      	mov      	r8, r0
  e8:	ea21c0c0 	movih      	r1, 49344
  ec:	6c17      	mov      	r0, r5
  ee:	e0000000 	bsr      	0x0	// 0 <__ltsf2>
  f2:	ea27c0c0 	movih      	r7, 49344
  f6:	38df      	btsti      	r0, 31
  f8:	6c5f      	mov      	r1, r7
  fa:	6c1b      	mov      	r0, r6
  fc:	c4a70c40 	inct      	r5, r7, 0
 100:	e0000000 	bsr      	0x0	// 0 <__ltsf2>
 104:	38df      	btsti      	r0, 31
 106:	6c5f      	mov      	r1, r7
 108:	6c23      	mov      	r0, r8
 10a:	c4c70c40 	inct      	r6, r7, 0
 10e:	e0000000 	bsr      	0x0	// 0 <__ltsf2>
 112:	38df      	btsti      	r0, 31
 114:	c4e80c20 	incf      	r7, r8, 0
 118:	d90403df 	ld.b      	r8, (r4, 0x3df)
 11c:	e5082004 	andi      	r8, r8, 4
 120:	e9280026 	bnez      	r8, 0x16c	// 16c <lmac_chip_monitor+0x16c>
 124:	6c17      	mov      	r0, r5
 126:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 12a:	6c87      	mov      	r2, r1
 12c:	6c43      	mov      	r1, r0
 12e:	d8041346 	ld.h      	r0, (r4, 0x68c)
 132:	e0000000 	bsr      	0x0	// 0 <lmac_amp_atten_calc>
 136:	3105      	movi      	r1, 5
 138:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
 13c:	6c1b      	mov      	r0, r6
 13e:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 142:	6c87      	mov      	r2, r1
 144:	6c43      	mov      	r1, r0
 146:	d8041342 	ld.h      	r0, (r4, 0x684)
 14a:	e0000000 	bsr      	0x0	// 0 <lmac_amp_atten_calc>
 14e:	3101      	movi      	r1, 1
 150:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
 154:	6c1f      	mov      	r0, r7
 156:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 15a:	6c87      	mov      	r2, r1
 15c:	6c43      	mov      	r1, r0
 15e:	d8041341 	ld.h      	r0, (r4, 0x682)
 162:	e0000000 	bsr      	0x0	// 0 <lmac_amp_atten_calc>
 166:	6c63      	mov      	r1, r8
 168:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
 16c:	d8690008 	ld.b      	r3, (r9, 0x8)
 170:	e9230067 	bnez      	r3, 0x23e	// 23e <lmac_chip_monitor+0x23e>
 174:	d844219e 	ld.w      	r2, (r4, 0x678)
 178:	d8640680 	ld.b      	r3, (r4, 0x680)
 17c:	e942005b 	bhz      	r2, 0x232	// 232 <lmac_chip_monitor+0x232>
 180:	e4432070 	andi      	r2, r3, 112
 184:	eb420070 	cmpnei      	r2, 112
 188:	0c5b      	bf      	0x23e	// 23e <lmac_chip_monitor+0x23e>
 18a:	c4235460 	zext      	r0, r3, 3, 1
 18e:	3825      	cmplti      	r0, 6
 190:	0c4f      	bf      	0x22e	// 22e <lmac_chip_monitor+0x22e>
 192:	c48354c2 	zext      	r2, r3, 6, 4
 196:	2001      	addi      	r0, 2
 198:	640a      	cmpne      	r2, r0
 19a:	0c52      	bf      	0x23e	// 23e <lmac_chip_monitor+0x23e>
 19c:	e4002007 	andi      	r0, r0, 7
 1a0:	c4605c44 	ins      	r3, r0, 6, 4
 1a4:	dc640680 	st.b      	r3, (r4, 0x680)
 1a8:	e0000000 	bsr      	0x0	// 0 <pmu_vref_vol_set_sec>
 1ac:	0449      	br      	0x23e	// 23e <lmac_chip_monitor+0x23e>
 1ae:	1313      	lrw      	r0, 0x0	// 378 <lmac_chip_monitor+0x378>
 1b0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1b4:	0732      	br      	0x18	// 18 <lmac_chip_monitor+0x18>
 1b6:	d8640308 	ld.b      	r3, (r4, 0x308)
 1ba:	3b01      	cmphsi      	r3, 2
 1bc:	081d      	bt      	0x1f6	// 1f6 <lmac_chip_monitor+0x1f6>
 1be:	6c2f      	mov      	r0, r11
 1c0:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 1c4:	1347      	lrw      	r2, 0xcccccccd	// 360 <lmac_chip_monitor+0x360>
 1c6:	136e      	lrw      	r3, 0x3feccccc	// 37c <lmac_chip_monitor+0x37c>
 1c8:	e0000000 	bsr      	0x0	// 0 <__adddf3>
 1cc:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
 1d0:	6d43      	mov      	r5, r0
 1d2:	6c1f      	mov      	r0, r7
 1d4:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 1d8:	1342      	lrw      	r2, 0xcccccccd	// 360 <lmac_chip_monitor+0x360>
 1da:	1369      	lrw      	r3, 0x3feccccc	// 37c <lmac_chip_monitor+0x37c>
 1dc:	e0000000 	bsr      	0x0	// 0 <__adddf3>
 1e0:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
 1e4:	6d83      	mov      	r6, r0
 1e6:	6c2b      	mov      	r0, r10
 1e8:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 1ec:	125d      	lrw      	r2, 0xcccccccd	// 360 <lmac_chip_monitor+0x360>
 1ee:	1364      	lrw      	r3, 0x3feccccc	// 37c <lmac_chip_monitor+0x37c>
 1f0:	e0000000 	bsr      	0x0	// 0 <__adddf3>
 1f4:	0777      	br      	0xe2	// e2 <lmac_chip_monitor+0xe2>
 1f6:	3b42      	cmpnei      	r3, 2
 1f8:	0b78      	bt      	0xe8	// e8 <lmac_chip_monitor+0xe8>
 1fa:	6c2f      	mov      	r0, r11
 1fc:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 200:	1340      	lrw      	r2, 0x66666666	// 380 <lmac_chip_monitor+0x380>
 202:	1361      	lrw      	r3, 0x3fe66666	// 384 <lmac_chip_monitor+0x384>
 204:	e0000000 	bsr      	0x0	// 0 <__adddf3>
 208:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
 20c:	6d43      	mov      	r5, r0
 20e:	6c1f      	mov      	r0, r7
 210:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 214:	125d      	lrw      	r2, 0x33333333	// 388 <lmac_chip_monitor+0x388>
 216:	127e      	lrw      	r3, 0x3fe33333	// 38c <lmac_chip_monitor+0x38c>
 218:	e0000000 	bsr      	0x0	// 0 <__adddf3>
 21c:	e0000000 	bsr      	0x0	// 0 <__truncdfsf2>
 220:	6d83      	mov      	r6, r0
 222:	6c2b      	mov      	r0, r10
 224:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 228:	1258      	lrw      	r2, 0x33333333	// 388 <lmac_chip_monitor+0x388>
 22a:	1279      	lrw      	r3, 0x3fe33333	// 38c <lmac_chip_monitor+0x38c>
 22c:	07e2      	br      	0x1f0	// 1f0 <lmac_chip_monitor+0x1f0>
 22e:	3007      	movi      	r0, 7
 230:	07b8      	br      	0x1a0	// 1a0 <lmac_chip_monitor+0x1a0>
 232:	c4235460 	zext      	r0, r3, 3, 1
 236:	c48354c2 	zext      	r2, r3, 6, 4
 23a:	640a      	cmpne      	r2, r0
 23c:	0bb2      	bt      	0x1a0	// 1a0 <lmac_chip_monitor+0x1a0>
 23e:	d864219e 	ld.w      	r3, (r4, 0x678)
 242:	eb230054 	cmplti      	r3, 85
 246:	080d      	bt      	0x260	// 260 <lmac_chip_monitor+0x260>
 248:	1212      	lrw      	r0, 0x0	// 390 <lmac_chip_monitor+0x390>
 24a:	3207      	movi      	r2, 7
 24c:	d9802009 	ld.w      	r12, (r0, 0x24)
 250:	b841      	st.w      	r2, (r14, 0x4)
 252:	b862      	st.w      	r3, (r14, 0x8)
 254:	e90c0006 	bez      	r12, 0x260	// 260 <lmac_chip_monitor+0x260>
 258:	3310      	movi      	r3, 16
 25a:	1a01      	addi      	r2, r14, 4
 25c:	311b      	movi      	r1, 27
 25e:	7bf1      	jsr      	r12
 260:	d844219e 	ld.w      	r2, (r4, 0x678)
 264:	eb220059 	cmplti      	r2, 90
 268:	d864036d 	ld.b      	r3, (r4, 0x36d)
 26c:	c48354a1 	zext      	r1, r3, 5, 4
 270:	0c98      	bf      	0x3a0	// 3a0 <lmac_chip_monitor+0x3a0>
 272:	c4435462 	zext      	r2, r3, 3, 2
 276:	644a      	cmpne      	r2, r1
 278:	0c0e      	bf      	0x294	// 294 <lmac_chip_monitor+0x294>
 27a:	d84409e2 	ld.b      	r2, (r4, 0x9e2)
 27e:	e4422002 	andi      	r2, r2, 2
 282:	e9220009 	bnez      	r2, 0x294	// 294 <lmac_chip_monitor+0x294>
 286:	c4615c22 	ins      	r3, r1, 3, 2
 28a:	dc64036d 	st.b      	r3, (r4, 0x36d)
 28e:	1202      	lrw      	r0, 0x0	// 394 <hgprintf+0x394>
 290:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 294:	d864219e 	ld.w      	r3, (r4, 0x678)
 298:	eb230069 	cmplti      	r3, 106
 29c:	0c8e      	bf      	0x3b8	// 3b8 <lmac_chip_monitor+0x3b8>
 29e:	9460      	ld.w      	r3, (r4, 0x0)
 2a0:	836a      	ld.b      	r3, (r3, 0xa)
 2a2:	e4632001 	andi      	r3, r3, 1
 2a6:	e9030014 	bez      	r3, 0x2ce	// 2ce <lmac_chip_monitor+0x2ce>
 2aa:	d8640680 	ld.b      	r3, (r4, 0x680)
 2ae:	e4632001 	andi      	r3, r3, 1
 2b2:	e903000e 	bez      	r3, 0x2ce	// 2ce <lmac_chip_monitor+0x2ce>
 2b6:	e0000000 	bsr      	0x0	// 0 <lmac_chip_monitor>
 2ba:	d8640680 	ld.b      	r3, (r4, 0x680)
 2be:	3200      	movi      	r2, 0
 2c0:	c4625c00 	ins      	r3, r2, 0, 0
 2c4:	dc640680 	st.b      	r3, (r4, 0x680)
 2c8:	1114      	lrw      	r0, 0x0	// 398 <hgprintf+0x398>
 2ca:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2ce:	3300      	movi      	r3, 0
 2d0:	d844219e 	ld.w      	r2, (r4, 0x678)
 2d4:	2b22      	subi      	r3, 35
 2d6:	64c9      	cmplt      	r2, r3
 2d8:	0882      	bt      	0x3dc	// 3dc <lmac_chip_monitor+0x3dc>
 2da:	74cb      	sexth      	r3, r2
 2dc:	eb220055 	cmplti      	r2, 86
 2e0:	325a      	movi      	r2, 90
 2e2:	c4620c20 	incf      	r3, r2, 0
 2e6:	320a      	movi      	r2, 10
 2e8:	232c      	addi      	r3, 45
 2ea:	c4438043 	divs      	r3, r3, r2
 2ee:	114c      	lrw      	r2, 0x0	// 39c <lmac_chip_monitor+0x39c>
 2f0:	d0620023 	ldr.b      	r3, (r2, r3 << 0)
 2f4:	d844068f 	ld.b      	r2, (r4, 0x68f)
 2f8:	60c8      	addu      	r3, r2
 2fa:	6c0f      	mov      	r0, r3
 2fc:	74ce      	sextb      	r3, r3
 2fe:	3b3f      	cmplti      	r3, 32
 300:	0802      	bt      	0x304	// 304 <lmac_chip_monitor+0x304>
 302:	301f      	movi      	r0, 31
 304:	74c2      	sextb      	r3, r0
 306:	e9a30003 	bhsz      	r3, 0x30c	// 30c <lmac_chip_monitor+0x30c>
 30a:	3000      	movi      	r0, 0
 30c:	7400      	zextb      	r0, r0
 30e:	e0000000 	bsr      	0x0	// 0 <xo_set_cs_sec>
 312:	3500      	movi      	r5, 0
 314:	6c97      	mov      	r2, r5
 316:	3105      	movi      	r1, 5
 318:	6c3b      	mov      	r0, r14
 31a:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_get_rx_dcoc>
 31e:	d86e1000 	ld.h      	r3, (r14, 0x0)
 322:	d8441389 	ld.h      	r2, (r4, 0x712)
 326:	608c      	addu      	r2, r3
 328:	d82e1001 	ld.h      	r1, (r14, 0x2)
 32c:	dc64141c 	st.h      	r3, (r4, 0x838)
 330:	dc4e1000 	st.h      	r2, (r14, 0x0)
 334:	d864138a 	ld.h      	r3, (r4, 0x714)
 338:	6c97      	mov      	r2, r5
 33a:	2500      	addi      	r5, 1
 33c:	60c4      	addu      	r3, r1
 33e:	dc24141d 	st.h      	r1, (r4, 0x83a)
 342:	6c3b      	mov      	r0, r14
 344:	3105      	movi      	r1, 5
 346:	7554      	zextb      	r5, r5
 348:	dc6e1001 	st.h      	r3, (r14, 0x2)
 34c:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_dcoc>
 350:	3d44      	cmpnei      	r5, 4
 352:	0be1      	bt      	0x314	// 314 <lmac_chip_monitor+0x314>
 354:	1405      	addi      	r14, r14, 20
 356:	1498      	pop      	r4-r11, r15
	...
 360:	cccccccd 	.long	0xcccccccd
 364:	3fe4cccc 	.long	0x3fe4cccc
 368:	3fc99999 	.long	0x3fc99999
 36c:	9999999a 	.long	0x9999999a
 370:	000d6d7f 	.long	0x000d6d7f
 374:	3fd99999 	.long	0x3fd99999
 378:	0000      	.short	0x0000
 37a:	0000      	.short	0x0000
 37c:	3feccccc 	.long	0x3feccccc
 380:	66666666 	.long	0x66666666
 384:	3fe66666 	.long	0x3fe66666
 388:	3333      	.short	0x3333
 38a:	3333      	.short	0x3333
 38c:	3fe33333 	.long	0x3fe33333
	...
 3a0:	e901ff7a 	bez      	r1, 0x294	// 294 <lmac_chip_monitor+0x294>
 3a4:	3100      	movi      	r1, 0
 3a6:	eb22006d 	cmplti      	r2, 110
 3aa:	c4615c22 	ins      	r3, r1, 3, 2
 3ae:	dc64036d 	st.b      	r3, (r4, 0x36d)
 3b2:	0f71      	bf      	0x294	// 294 <lmac_chip_monitor+0x294>
 3b4:	1012      	lrw      	r0, 0x0	// 3fc <lmac_chip_monitor+0x3fc>
 3b6:	076d      	br      	0x290	// 290 <lmac_chip_monitor+0x290>
 3b8:	eb23006d 	cmplti      	r3, 110
 3bc:	0b89      	bt      	0x2ce	// 2ce <lmac_chip_monitor+0x2ce>
 3be:	d8640680 	ld.b      	r3, (r4, 0x680)
 3c2:	e4432001 	andi      	r2, r3, 1
 3c6:	e9220009 	bnez      	r2, 0x3d8	// 3d8 <lmac_chip_monitor+0x3d8>
 3ca:	3201      	movi      	r2, 1
 3cc:	c4625c00 	ins      	r3, r2, 0, 0
 3d0:	dc640680 	st.b      	r3, (r4, 0x680)
 3d4:	e0000000 	bsr      	0x0	// 0 <lmac_chip_monitor>
 3d8:	100a      	lrw      	r0, 0x0	// 400 <lmac_chip_monitor+0x400>
 3da:	0778      	br      	0x2ca	// 2ca <lmac_chip_monitor+0x2ca>
 3dc:	3300      	movi      	r3, 0
 3de:	2b27      	subi      	r3, 40
 3e0:	0783      	br      	0x2e6	// 2e6 <lmac_chip_monitor+0x2e6>
 3e2:	3b43      	cmpnei      	r3, 3
 3e4:	0ae9      	bt      	0x1b6	// 1b6 <lmac_chip_monitor+0x1b6>
 3e6:	d8640308 	ld.b      	r3, (r4, 0x308)
 3ea:	3b01      	cmphsi      	r3, 2
 3ec:	0a7e      	bt      	0xe8	// e8 <lmac_chip_monitor+0xe8>
 3ee:	31fc      	movi      	r1, 252
 3f0:	4136      	lsli      	r1, r1, 22
 3f2:	6c2f      	mov      	r0, r11
 3f4:	e0000000 	bsr      	0x0	// 0 <__addsf3>
 3f8:	6d43      	mov      	r5, r0
 3fa:	0677      	br      	0xe8	// e8 <lmac_chip_monitor+0xe8>
	...

Disassembly of section .text.lmac_main_task:

00000000 <lmac_main_task>:
   0:	14d4      	push      	r4-r7, r15
   2:	1430      	subi      	r14, r14, 64
   4:	10fe      	lrw      	r7, 0x0	// 7c <lmac_main_task+0x7c>
   6:	10bf      	lrw      	r5, 0x0	// 80 <lmac_main_task+0x80>
   8:	6d17      	mov      	r4, r5
   a:	d86549df 	ld.bs      	r3, (r5, 0x9df)
   e:	e9a30004 	bhsz      	r3, 0x16	// 16 <lmac_main_task+0x16>
  12:	1410      	addi      	r14, r14, 64
  14:	1494      	pop      	r4-r7, r15
  16:	3100      	movi      	r1, 0
  18:	2900      	subi      	r1, 1
  1a:	e4040b8f 	addi      	r0, r4, 2960
  1e:	e0000000 	bsr      	0x0	// 0 <os_sema_down>
  22:	d8650319 	ld.b      	r3, (r5, 0x319)
  26:	e4632002 	andi      	r3, r3, 2
  2a:	e923ffee 	bnez      	r3, 0x6	// 6 <lmac_main_task+0x6>
  2e:	d8652267 	ld.w      	r3, (r5, 0x99c)
  32:	e923ffea 	bnez      	r3, 0x6	// 6 <lmac_main_task+0x6>
  36:	10d4      	lrw      	r6, 0x0	// 84 <lmac_main_task+0x84>
  38:	d84422a1 	ld.w      	r2, (r4, 0xa84)
  3c:	d98422a2 	ld.w      	r12, (r4, 0xa88)
  40:	d86422a0 	ld.w      	r3, (r4, 0xa80)
  44:	3000      	movi      	r0, 0
  46:	64ca      	cmpne      	r2, r3
  48:	0806      	bt      	0x54	// 54 <lmac_main_task+0x54>
  4a:	e900ffde 	bez      	r0, 0x6	// 6 <lmac_main_task+0x6>
  4e:	dc4522a0 	st.w      	r2, (r5, 0xa80)
  52:	07da      	br      	0x6	// 6 <lmac_main_task+0x6>
  54:	e42302a2 	addi      	r1, r3, 675
  58:	d0240881 	ldr.w      	r1, (r4, r1 << 2)
  5c:	2300      	addi      	r3, 1
  5e:	c5830080 	subu      	r0, r3, r12
  62:	670d      	cmplt      	r3, r12
  64:	e5a11000 	subi      	r13, r1, 1
  68:	c4600c20 	incf      	r3, r0, 0
  6c:	eb0d000c 	cmphsi      	r13, 13
  70:	3001      	movi      	r0, 1
  72:	08a7      	bt      	0x1c0	// 1c0 <lmac_main_task+0x1c0>
  74:	d1a7088d 	ldr.w      	r13, (r7, r13 << 2)
  78:	7834      	jmp      	r13
	...
  86:	0000      	.short	0x0000
  88:	3100      	movi      	r1, 0
  8a:	2900      	subi      	r1, 1
  8c:	1210      	lrw      	r0, 0x0	// 1cc <lmac_main_task+0x1cc>
  8e:	dc6422a0 	st.w      	r3, (r4, 0xa80)
  92:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  96:	e0000000 	bsr      	0x0	// 0 <lmac_auto_channel_select>
  9a:	120d      	lrw      	r0, 0x0	// 1cc <os_mutex_unlock+0x1cc>
  9c:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  a0:	07cc      	br      	0x38	// 38 <lmac_main_task+0x38>
  a2:	120c      	lrw      	r0, 0x0	// 1d0 <lmac_main_task+0x1d0>
  a4:	dc6422a0 	st.w      	r3, (r4, 0xa80)
  a8:	e0000000 	bsr      	0x0	// 0 <lmac_auto_rate_ctrl>
  ac:	07c6      	br      	0x38	// 38 <lmac_main_task+0x38>
  ae:	dc6422a0 	st.w      	r3, (r4, 0xa80)
  b2:	d86420dc 	ld.w      	r3, (r4, 0x370)
  b6:	4b41      	lsri      	r2, r3, 1
  b8:	d9862009 	ld.w      	r12, (r6, 0x24)
  bc:	4b71      	lsri      	r3, r3, 17
  be:	dc6e0002 	st.b      	r3, (r14, 0x2)
  c2:	dc4e0000 	st.b      	r2, (r14, 0x0)
  c6:	4b68      	lsri      	r3, r3, 8
  c8:	c50255e2 	zext      	r2, r2, 15, 8
  cc:	dc6e0003 	st.b      	r3, (r14, 0x3)
  d0:	dc4e0001 	st.b      	r2, (r14, 0x1)
  d4:	e90cffb2 	bez      	r12, 0x38	// 38 <lmac_main_task+0x38>
  d8:	3304      	movi      	r3, 4
  da:	6cbb      	mov      	r2, r14
  dc:	3107      	movi      	r1, 7
  de:	6c1b      	mov      	r0, r6
  e0:	7bf1      	jsr      	r12
  e2:	07ab      	br      	0x38	// 38 <lmac_main_task+0x38>
  e4:	dc6422a0 	st.w      	r3, (r4, 0xa80)
  e8:	e0000000 	bsr      	0x0	// 0 <lmac_send_scan_probe>
  ec:	07a6      	br      	0x38	// 38 <lmac_main_task+0x38>
  ee:	dc6422a0 	st.w      	r3, (r4, 0xa80)
  f2:	e0000000 	bsr      	0x0	// 0 <lmac_send_mgmt_meas_report>
  f6:	07a1      	br      	0x38	// 38 <lmac_main_task+0x38>
  f8:	dc6422a0 	st.w      	r3, (r4, 0xa80)
  fc:	e0000000 	bsr      	0x0	// 0 <lmac_send_bss_announcement>
 100:	079c      	br      	0x38	// 38 <lmac_main_task+0x38>
 102:	dc6422a0 	st.w      	r3, (r4, 0xa80)
 106:	e0000000 	bsr      	0x0	// 0 <lmac_main_task>
 10a:	0797      	br      	0x38	// 38 <lmac_main_task+0x38>
 10c:	dc6422a0 	st.w      	r3, (r4, 0xa80)
 110:	e0000000 	bsr      	0x0	// 0 <lmac_main_task>
 114:	0792      	br      	0x38	// 38 <lmac_main_task+0x38>
 116:	dc6422a0 	st.w      	r3, (r4, 0xa80)
 11a:	e0000000 	bsr      	0x0	// 0 <lmac_main_task>
 11e:	078d      	br      	0x38	// 38 <lmac_main_task+0x38>
 120:	dc6422a0 	st.w      	r3, (r4, 0xa80)
 124:	e0000000 	bsr      	0x0	// 0 <lmac_send_ant_pkt>
 128:	0788      	br      	0x38	// 38 <lmac_main_task+0x38>
 12a:	3100      	movi      	r1, 0
 12c:	2900      	subi      	r1, 1
 12e:	1108      	lrw      	r0, 0x0	// 1cc <lmac_main_task+0x1cc>
 130:	dc6422a0 	st.w      	r3, (r4, 0xa80)
 134:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
 138:	d9a40378 	ld.b      	r13, (r4, 0x378)
 13c:	e46d1000 	subi      	r3, r13, 1
 140:	74cc      	zextb      	r3, r3
 142:	3b0f      	cmphsi      	r3, 16
 144:	0b7a      	bt      	0x38	// 38 <lmac_main_task+0x38>
 146:	d804034a 	ld.b      	r0, (r4, 0x34a)
 14a:	d98411a5 	ld.h      	r12, (r4, 0x34a)
 14e:	3200      	movi      	r2, 0
 150:	e4002001 	andi      	r0, r0, 1
 154:	c42c55ec 	zext      	r12, r12, 15, 1
 158:	6ccb      	mov      	r3, r2
 15a:	674d      	cmplt      	r3, r13
 15c:	0824      	bt      	0x1a4	// 1a4 <lmac_main_task+0x1a4>
 15e:	e0000000 	bsr      	0x0	// 0 <lhw_abort_fsm>
 162:	3000      	movi      	r0, 0
 164:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_table_ctrl>
 168:	d8240378 	ld.b      	r1, (r4, 0x378)
 16c:	6c3b      	mov      	r0, r14
 16e:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_table_cfg>
 172:	3300      	movi      	r3, 0
 174:	2b00      	subi      	r3, 1
 176:	64c2      	cmpne      	r0, r3
 178:	0804      	bt      	0x180	// 180 <lmac_main_task+0x180>
 17a:	1017      	lrw      	r0, 0x0	// 1d4 <lmac_main_task+0x1d4>
 17c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 180:	3001      	movi      	r0, 1
 182:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_table_ctrl>
 186:	d804033c 	ld.b      	r0, (r4, 0x33c)
 18a:	e0000000 	bsr      	0x0	// 0 <lmac_lo_table_kick>
 18e:	3000      	movi      	r0, 0
 190:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
 194:	d864037d 	ld.b      	r3, (r4, 0x37d)
 198:	3200      	movi      	r2, 0
 19a:	c4625c03 	ins      	r3, r2, 3, 3
 19e:	dc64037d 	st.b      	r3, (r4, 0x37d)
 1a2:	077c      	br      	0x9a	// 9a <lmac_main_task+0x9a>
 1a4:	102d      	lrw      	r1, 0x0	// 1d8 <lmac_main_task+0x1d8>
 1a6:	6048      	addu      	r1, r2
 1a8:	d8212030 	ld.w      	r1, (r1, 0xc0)
 1ac:	d46e0881 	str.w      	r1, (r14, r3 << 2)
 1b0:	e9000005 	bez      	r0, 0x1ba	// 1ba <lmac_main_task+0x1ba>
 1b4:	6070      	addu      	r1, r12
 1b6:	d46e0881 	str.w      	r1, (r14, r3 << 2)
 1ba:	2300      	addi      	r3, 1
 1bc:	2217      	addi      	r2, 24
 1be:	07ce      	br      	0x15a	// 15a <lmac_main_task+0x15a>
 1c0:	1007      	lrw      	r0, 0x0	// 1dc <lmac_main_task+0x1dc>
 1c2:	dc6422a0 	st.w      	r3, (r4, 0xa80)
 1c6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1ca:	0737      	br      	0x38	// bfc <core_sec_opt_func+0xbfc>
	...

Disassembly of section .text.ap_sleep_enter:

00000000 <ap_sleep_enter>:
   0:	14d7      	push      	r4-r10, r15
   2:	029a      	lrw      	r4, 0x0	// 294 <ap_sleep_enter+0x294>
   4:	e0000000 	bsr      	0x0	// 0 <lmac_next_dtim_calc>
   8:	d8642267 	ld.w      	r3, (r4, 0x99c)
   c:	e903012e 	bez      	r3, 0x268	// 268 <ap_sleep_enter+0x268>
  10:	35fa      	movi      	r5, 250
  12:	45a2      	lsli      	r5, r5, 2
  14:	c4a08025 	divu      	r5, r0, r5
  18:	3d08      	cmphsi      	r5, 9
  1a:	0d27      	bf      	0x268	// 268 <ap_sleep_enter+0x268>
  1c:	0360      	lrw      	r3, 0x0	// 298 <ap_sleep_enter+0x298>
  1e:	3600      	movi      	r6, 0
  20:	834a      	ld.b      	r2, (r3, 0xa)
  22:	c4465c00 	ins      	r2, r6, 0, 0
  26:	a34a      	st.b      	r2, (r3, 0xa)
  28:	3701      	movi      	r7, 1
  2a:	d8640319 	ld.b      	r3, (r4, 0x319)
  2e:	c4675c01 	ins      	r3, r7, 1, 1
  32:	e5032040 	andi      	r8, r3, 64
  36:	3203      	movi      	r2, 3
  38:	dc640319 	st.b      	r3, (r4, 0x319)
  3c:	dc442267 	st.w      	r2, (r4, 0x99c)
  40:	e90800e3 	bez      	r8, 0x206	// 206 <ap_sleep_enter+0x206>
  44:	0369      	lrw      	r3, 0x0	// 29c <ap_sleep_enter+0x29c>
  46:	6c9b      	mov      	r2, r6
  48:	9360      	ld.w      	r3, (r3, 0x0)
  4a:	6f5b      	mov      	r13, r6
  4c:	d9832005 	ld.w      	r12, (r3, 0x14)
  50:	9324      	ld.w      	r1, (r3, 0x10)
  52:	6cf3      	mov      	r3, r12
  54:	6f07      	mov      	r12, r1
  56:	6731      	cmplt      	r12, r12
  58:	6309      	addc      	r12, r2
  5a:	634d      	addc      	r13, r3
  5c:	6c83      	mov      	r2, r0
  5e:	6cdb      	mov      	r3, r6
  60:	6731      	cmplt      	r12, r12
  62:	6309      	addc      	r12, r2
  64:	634d      	addc      	r13, r3
  66:	dd8422e7 	st.w      	r12, (r4, 0xb9c)
  6a:	dda422e8 	st.w      	r13, (r4, 0xba0)
  6e:	ea8a008d 	lrw      	r10, 0xe000e100	// 2a0 <ap_sleep_enter+0x2a0>
  72:	e0000000 	bsr      	0x0	// 0 <lmac_beacon_timer_abort>
  76:	3380      	movi      	r3, 128
  78:	436e      	lsli      	r3, r3, 14
  7a:	ea098003 	movi      	r9, 32771
  7e:	c5e94909 	rotli      	r9, r9, 15
  82:	dc6a2020 	st.w      	r3, (r10, 0x80)
  86:	d8292028 	ld.w      	r1, (r9, 0xa0)
  8a:	39b0      	bseti      	r1, 16
  8c:	39b1      	bseti      	r1, 17
  8e:	30a0      	movi      	r0, 160
  90:	e0000000 	bsr      	0x0	// 0 <ap_sleep_enter>
  94:	e0000000 	bsr      	0x0	// 0 <pmu_pd_timer_clear_pnd_sec>
  98:	d8640319 	ld.b      	r3, (r4, 0x319)
  9c:	c4665c07 	ins      	r3, r6, 7, 7
  a0:	2d06      	subi      	r5, 7
  a2:	6c1b      	mov      	r0, r6
  a4:	dc640319 	st.b      	r3, (r4, 0x319)
  a8:	e0000000 	bsr      	0x0	// 0 <mcu_watchdog_timeout>
  ac:	6c17      	mov      	r0, r5
  ae:	e0000000 	bsr      	0x0	// 0 <csi_kernel_update_tick>
  b2:	6c17      	mov      	r0, r5
  b4:	e0000000 	bsr      	0x0	// 0 <pd_timer_start>
  b8:	e0000000 	bsr      	0x0	// 0 <lhw_abort_fsm>
  bc:	6c1b      	mov      	r0, r6
  be:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
  c2:	1379      	lrw      	r3, 0x40026000	// 2a4 <ap_sleep_enter+0x2a4>
  c4:	30a0      	movi      	r0, 160
  c6:	9347      	ld.w      	r2, (r3, 0x1c)
  c8:	3a92      	bclri      	r2, 18
  ca:	b347      	st.w      	r2, (r3, 0x1c)
  cc:	9342      	ld.w      	r2, (r3, 0x8)
  ce:	3a92      	bclri      	r2, 18
  d0:	b342      	st.w      	r2, (r3, 0x8)
  d2:	9342      	ld.w      	r2, (r3, 0x8)
  d4:	3ab2      	bseti      	r2, 18
  d6:	b342      	st.w      	r2, (r3, 0x8)
  d8:	9345      	ld.w      	r2, (r3, 0x14)
  da:	3a97      	bclri      	r2, 23
  dc:	b345      	st.w      	r2, (r3, 0x14)
  de:	9345      	ld.w      	r2, (r3, 0x14)
  e0:	3a9c      	bclri      	r2, 28
  e2:	b345      	st.w      	r2, (r3, 0x14)
  e4:	9345      	ld.w      	r2, (r3, 0x14)
  e6:	3a9b      	bclri      	r2, 27
  e8:	b345      	st.w      	r2, (r3, 0x14)
  ea:	9345      	ld.w      	r2, (r3, 0x14)
  ec:	3a9a      	bclri      	r2, 26
  ee:	b345      	st.w      	r2, (r3, 0x14)
  f0:	9345      	ld.w      	r2, (r3, 0x14)
  f2:	3a9d      	bclri      	r2, 29
  f4:	b345      	st.w      	r2, (r3, 0x14)
  f6:	9345      	ld.w      	r2, (r3, 0x14)
  f8:	3a93      	bclri      	r2, 19
  fa:	b345      	st.w      	r2, (r3, 0x14)
  fc:	9345      	ld.w      	r2, (r3, 0x14)
  fe:	3a8f      	bclri      	r2, 15
 100:	b345      	st.w      	r2, (r3, 0x14)
 102:	9345      	ld.w      	r2, (r3, 0x14)
 104:	3a8b      	bclri      	r2, 11
 106:	b345      	st.w      	r2, (r3, 0x14)
 108:	9345      	ld.w      	r2, (r3, 0x14)
 10a:	3a89      	bclri      	r2, 9
 10c:	b345      	st.w      	r2, (r3, 0x14)
 10e:	9345      	ld.w      	r2, (r3, 0x14)
 110:	3a88      	bclri      	r2, 8
 112:	b345      	st.w      	r2, (r3, 0x14)
 114:	9345      	ld.w      	r2, (r3, 0x14)
 116:	3a85      	bclri      	r2, 5
 118:	b345      	st.w      	r2, (r3, 0x14)
 11a:	9345      	ld.w      	r2, (r3, 0x14)
 11c:	3a84      	bclri      	r2, 4
 11e:	b345      	st.w      	r2, (r3, 0x14)
 120:	3380      	movi      	r3, 128
 122:	4372      	lsli      	r3, r3, 18
 124:	d8a4031a 	ld.b      	r5, (r4, 0x31a)
 128:	d904031b 	ld.b      	r8, (r4, 0x31b)
 12c:	dc6a2020 	st.w      	r3, (r10, 0x80)
 130:	d8292028 	ld.w      	r1, (r9, 0xa0)
 134:	c40155e1 	zext      	r1, r1, 15, 0
 138:	715d      	lsr      	r5, r7
 13a:	39b0      	bseti      	r1, 16
 13c:	e0000000 	bsr      	0x0	// 0 <ap_sleep_enter>
 140:	eb050032 	cmphsi      	r5, 51
 144:	6a1c      	and      	r8, r7
 146:	085e      	bt      	0x202	// 202 <ap_sleep_enter+0x202>
 148:	6c5b      	mov      	r1, r6
 14a:	6c17      	mov      	r0, r5
 14c:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
 150:	6c9f      	mov      	r2, r7
 152:	6c5f      	mov      	r1, r7
 154:	6c17      	mov      	r0, r5
 156:	e0000000 	bsr      	0x0	// 0 <gpio_set_mode>
 15a:	ea068003 	movi      	r6, 32771
 15e:	c5e64906 	rotli      	r6, r6, 15
 162:	3300      	movi      	r3, 0
 164:	d8262028 	ld.w      	r1, (r6, 0xa0)
 168:	2bfc      	subi      	r3, 253
 16a:	684c      	and      	r1, r3
 16c:	45a2      	lsli      	r5, r5, 2
 16e:	6c54      	or      	r1, r5
 170:	30a0      	movi      	r0, 160
 172:	e0000000 	bsr      	0x0	// 0 <ap_sleep_enter>
 176:	d8262028 	ld.w      	r1, (r6, 0xa0)
 17a:	3981      	bclri      	r1, 1
 17c:	30a0      	movi      	r0, 160
 17e:	e0000000 	bsr      	0x0	// 0 <ap_sleep_enter>
 182:	e9080009 	bez      	r8, 0x194	// 194 <ap_sleep_enter+0x194>
 186:	d8262028 	ld.w      	r1, (r6, 0xa0)
 18a:	ec210002 	ori      	r1, r1, 2
 18e:	30a0      	movi      	r0, 160
 190:	e0000000 	bsr      	0x0	// 0 <ap_sleep_enter>
 194:	ea058003 	movi      	r5, 32771
 198:	c5e54905 	rotli      	r5, r5, 15
 19c:	30a0      	movi      	r0, 160
 19e:	d8252028 	ld.w      	r1, (r5, 0xa0)
 1a2:	ec210200 	ori      	r1, r1, 512
 1a6:	e0000000 	bsr      	0x0	// 0 <ap_sleep_enter>
 1aa:	d8252028 	ld.w      	r1, (r5, 0xa0)
 1ae:	ec210001 	ori      	r1, r1, 1
 1b2:	30a0      	movi      	r0, 160
 1b4:	e0000000 	bsr      	0x0	// 0 <ap_sleep_enter>
 1b8:	113c      	lrw      	r1, 0x0	// 2a8 <ap_sleep_enter+0x2a8>
 1ba:	1157      	lrw      	r2, 0x0	// 294 <ap_sleep_enter+0x294>
 1bc:	3019      	movi      	r0, 25
 1be:	e0000000 	bsr      	0x0	// 0 <request_irq>
 1c2:	1158      	lrw      	r2, 0xe000e100	// 2a0 <ap_sleep_enter+0x2a0>
 1c4:	3380      	movi      	r3, 128
 1c6:	4372      	lsli      	r3, r3, 18
 1c8:	b260      	st.w      	r3, (r2, 0x0)
 1ca:	e0000000 	bsr      	0x0	// 0 <tsensor_close>
 1ce:	3200      	movi      	r2, 0
 1d0:	6c4b      	mov      	r1, r2
 1d2:	6c0b      	mov      	r0, r2
 1d4:	e0000000 	bsr      	0x0	// 0 <sysctrl_sysclk_cfg>
 1d8:	3300      	movi      	r3, 0
 1da:	6c8f      	mov      	r2, r3
 1dc:	6c4f      	mov      	r1, r3
 1de:	6c0f      	mov      	r0, r3
 1e0:	e0000000 	bsr      	0x0	// 0 <sysctrl_syspll_set>
 1e4:	3300      	movi      	r3, 0
 1e6:	6c0f      	mov      	r0, r3
 1e8:	6c8f      	mov      	r2, r3
 1ea:	6c4f      	mov      	r1, r3
 1ec:	e0000000 	bsr      	0x0	// 0 <sysctrl_adcpll_set>
 1f0:	3000      	movi      	r0, 0
 1f2:	e0000000 	bsr      	0x0	// 0 <pd_hxosc_en_sec>
 1f6:	d86411e5 	ld.h      	r3, (r4, 0x3ca)
 1fa:	3000      	movi      	r0, 0
 1fc:	dc6411e4 	st.h      	r3, (r4, 0x3c8)
 200:	1497      	pop      	r4-r10, r15
 202:	3533      	movi      	r5, 51
 204:	07ab      	br      	0x15a	// 15a <ap_sleep_enter+0x15a>
 206:	e4001fff 	subi      	r0, r0, 4096
 20a:	e0000000 	bsr      	0x0	// 0 <lf_timer_start>
 20e:	1108      	lrw      	r0, 0x0	// 2ac <hgprintf+0x2ac>
 210:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 214:	e0000000 	bsr      	0x0	// 0 <lhw_abort_fsm>
 218:	6c23      	mov      	r0, r8
 21a:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_rf_en>
 21e:	1162      	lrw      	r3, 0x40026000	// 2a4 <ap_sleep_enter+0x2a4>
 220:	9347      	ld.w      	r2, (r3, 0x1c)
 222:	3a92      	bclri      	r2, 18
 224:	b347      	st.w      	r2, (r3, 0x1c)
 226:	9345      	ld.w      	r2, (r3, 0x14)
 228:	3a9c      	bclri      	r2, 28
 22a:	b345      	st.w      	r2, (r3, 0x14)
 22c:	9345      	ld.w      	r2, (r3, 0x14)
 22e:	3a9b      	bclri      	r2, 27
 230:	b345      	st.w      	r2, (r3, 0x14)
 232:	9345      	ld.w      	r2, (r3, 0x14)
 234:	3a9a      	bclri      	r2, 26
 236:	b345      	st.w      	r2, (r3, 0x14)
 238:	9345      	ld.w      	r2, (r3, 0x14)
 23a:	3a93      	bclri      	r2, 19
 23c:	b345      	st.w      	r2, (r3, 0x14)
 23e:	9345      	ld.w      	r2, (r3, 0x14)
 240:	3a8f      	bclri      	r2, 15
 242:	b345      	st.w      	r2, (r3, 0x14)
 244:	9345      	ld.w      	r2, (r3, 0x14)
 246:	3a8b      	bclri      	r2, 11
 248:	b345      	st.w      	r2, (r3, 0x14)
 24a:	9345      	ld.w      	r2, (r3, 0x14)
 24c:	3a89      	bclri      	r2, 9
 24e:	b345      	st.w      	r2, (r3, 0x14)
 250:	9345      	ld.w      	r2, (r3, 0x14)
 252:	3a88      	bclri      	r2, 8
 254:	b345      	st.w      	r2, (r3, 0x14)
 256:	9345      	ld.w      	r2, (r3, 0x14)
 258:	3a85      	bclri      	r2, 5
 25a:	b345      	st.w      	r2, (r3, 0x14)
 25c:	9345      	ld.w      	r2, (r3, 0x14)
 25e:	3a84      	bclri      	r2, 4
 260:	b345      	st.w      	r2, (r3, 0x14)
 262:	e0000000 	bsr      	0x0	// 0 <tsensor_close>
 266:	07c8      	br      	0x1f6	// 1f6 <ap_sleep_enter+0x1f6>
 268:	9460      	ld.w      	r3, (r4, 0x0)
 26a:	3101      	movi      	r1, 1
 26c:	834a      	ld.b      	r2, (r3, 0xa)
 26e:	c4415c00 	ins      	r2, r1, 0, 0
 272:	a34a      	st.b      	r2, (r3, 0xa)
 274:	3500      	movi      	r5, 0
 276:	d8640319 	ld.b      	r3, (r4, 0x319)
 27a:	c4655c01 	ins      	r3, r5, 1, 1
 27e:	dc640319 	st.b      	r3, (r4, 0x319)
 282:	e0000000 	bsr      	0x0	// 0 <lhw_enable_irq_ac>
 286:	6c17      	mov      	r0, r5
 288:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
 28c:	e0000000 	bsr      	0x0	// 0 <lmac_tdma_start>
 290:	07b3      	br      	0x1f6	// 1f6 <ap_sleep_enter+0x1f6>
	...
 29e:	0000      	.short	0x0000
 2a0:	e000e100 	.long	0xe000e100
 2a4:	40026000 	.long	0x40026000
	...

Disassembly of section .text.lmac_dsleep_psdata:

00000000 <lmac_dsleep_psdata>:
   0:	1064      	lrw      	r3, 0x0	// 10 <lmac_dsleep_psdata+0x10>
   2:	d8032233 	ld.w      	r0, (r3, 0x8cc)
   6:	3840      	cmpnei      	r0, 0
   8:	c4000c44 	inct      	r0, r0, 4
   c:	783c      	jmp      	r15
   e:	0000      	.short	0x0000
  10:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_snprint:

00000000 <lmac_snprint>:
   0:	1423      	subi      	r14, r14, 12
   2:	b862      	st.w      	r3, (r14, 0x8)
   4:	b841      	st.w      	r2, (r14, 0x4)
   6:	b820      	st.w      	r1, (r14, 0x0)
   8:	14d3      	push      	r4-r6, r15
   a:	1421      	subi      	r14, r14, 4
   c:	9089      	ld.w      	r4, (r0, 0x24)
   e:	6d83      	mov      	r6, r0
  10:	9006      	ld.w      	r0, (r0, 0x18)
  12:	6102      	subu      	r4, r0
  14:	2c00      	subi      	r4, 1
  16:	3c21      	cmplti      	r4, 2
  18:	9865      	ld.w      	r3, (r14, 0x14)
  1a:	b860      	st.w      	r3, (r14, 0x0)
  1c:	081d      	bt      	0x56	// 56 <lmac_snprint+0x56>
  1e:	1b06      	addi      	r3, r14, 24
  20:	9840      	ld.w      	r2, (r14, 0x0)
  22:	6c53      	mov      	r1, r4
  24:	e0000000 	bsr      	0x0	// 0 <vsnprintf>
  28:	6d43      	mov      	r5, r0
  2a:	e9600012 	blsz      	r0, 0x4e	// 4e <lmac_snprint+0x4e>
  2e:	6501      	cmplt      	r0, r4
  30:	6c53      	mov      	r1, r4
  32:	c4200c40 	inct      	r1, r0, 0
  36:	6c1b      	mov      	r0, r6
  38:	e0000000 	bsr      	0x0	// 0 <skb_put>
  3c:	6c17      	mov      	r0, r5
  3e:	1401      	addi      	r14, r14, 4
  40:	d9ee2003 	ld.w      	r15, (r14, 0xc)
  44:	98c2      	ld.w      	r6, (r14, 0x8)
  46:	98a1      	ld.w      	r5, (r14, 0x4)
  48:	9880      	ld.w      	r4, (r14, 0x0)
  4a:	1407      	addi      	r14, r14, 28
  4c:	783c      	jmp      	r15
  4e:	1004      	lrw      	r0, 0x0	// 5c <lmac_snprint+0x5c>
  50:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  54:	07f4      	br      	0x3c	// 3c <lmac_snprint+0x3c>
  56:	3500      	movi      	r5, 0
  58:	07f2      	br      	0x3c	// 3c <lmac_snprint+0x3c>
  5a:	0000      	.short	0x0000
  5c:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_sta_info_statics_print:

00000000 <lmac_sta_info_statics_print>:
   0:	14d7      	push      	r4-r10, r15
   2:	1428      	subi      	r14, r14, 32
   4:	02a9      	lrw      	r5, 0x0	// 2dc <lmac_sta_info_statics_print+0x2dc>
   6:	6d03      	mov      	r4, r0
   8:	6d87      	mov      	r6, r1
   a:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
   e:	d8e52207 	ld.w      	r7, (r5, 0x81c)
  12:	58fd      	subu      	r7, r0, r7
  14:	d80520ee 	ld.w      	r0, (r5, 0x3b8)
  18:	e4002004 	andi      	r0, r0, 4
  1c:	d8640070 	ld.b      	r3, (r4, 0x70)
  20:	d844006f 	ld.b      	r2, (r4, 0x6f)
  24:	d8241034 	ld.h      	r1, (r4, 0x68)
  28:	d9240074 	ld.b      	r9, (r4, 0x74)
  2c:	d9040073 	ld.b      	r8, (r4, 0x73)
  30:	d9a40072 	ld.b      	r13, (r4, 0x72)
  34:	d9840071 	ld.b      	r12, (r4, 0x71)
  38:	e9000131 	bez      	r0, 0x29a	// 29a <lmac_sta_info_statics_print+0x29a>
  3c:	d80400ae 	ld.b      	r0, (r4, 0xae)
  40:	4804      	lsri      	r0, r0, 4
  42:	b807      	st.w      	r0, (r14, 0x1c)
  44:	d80400ad 	ld.b      	r0, (r4, 0xad)
  48:	e540200f 	andi      	r10, r0, 15
  4c:	dd4e2006 	st.w      	r10, (r14, 0x18)
  50:	d94400af 	ld.b      	r10, (r4, 0xaf)
  54:	4804      	lsri      	r0, r0, 4
  56:	e54a200f 	andi      	r10, r10, 15
  5a:	b804      	st.w      	r0, (r14, 0x10)
  5c:	dd4e2005 	st.w      	r10, (r14, 0x14)
  60:	dd2e2003 	st.w      	r9, (r14, 0xc)
  64:	dd0e2002 	st.w      	r8, (r14, 0x8)
  68:	ddae2001 	st.w      	r13, (r14, 0x4)
  6c:	dd8e2000 	st.w      	r12, (r14, 0x0)
  70:	7445      	zexth      	r1, r1
  72:	0303      	lrw      	r0, 0x0	// 2e0 <lmac_sta_info_statics_print+0x2e0>
  74:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  78:	d80410e3 	ld.h      	r0, (r4, 0x1c6)
  7c:	d86410ea 	ld.h      	r3, (r4, 0x1d4)
  80:	640c      	cmphs      	r3, r0
  82:	0924      	bt      	0x2ca	// 2ca <lmac_sta_info_statics_print+0x2ca>
  84:	e9000008 	bez      	r0, 0x94	// 94 <lmac_sta_info_statics_print+0x94>
  88:	586d      	subu      	r3, r0, r3
  8a:	3264      	movi      	r2, 100
  8c:	7cc8      	mult      	r3, r2
  8e:	c4038040 	divs      	r0, r3, r0
  92:	7400      	zextb      	r0, r0
  94:	d865483d 	ld.bs      	r3, (r5, 0x83d)
  98:	640d      	cmplt      	r3, r0
  9a:	0c03      	bf      	0xa0	// a0 <lmac_sta_info_statics_print+0xa0>
  9c:	dc05083d 	st.b      	r0, (r5, 0x83d)
  a0:	d8650866 	ld.b      	r3, (r5, 0x866)
  a4:	3b07      	cmphsi      	r3, 8
  a6:	d8241034 	ld.h      	r1, (r4, 0x68)
  aa:	0d12      	bf      	0x2ce	// 2ce <lmac_sta_info_statics_print+0x2ce>
  ac:	3b4a      	cmpnei      	r3, 10
  ae:	0351      	lrw      	r2, 0x0	// 2e4 <lmac_sta_info_statics_print+0x2e4>
  b0:	0371      	lrw      	r3, 0x0	// 2e8 <lmac_sta_info_statics_print+0x2e8>
  b2:	c4430c20 	incf      	r2, r3, 0
  b6:	d86400ae 	ld.b      	r3, (r4, 0xae)
  ba:	d9842072 	ld.w      	r12, (r4, 0x1c8)
  be:	e463200f 	andi      	r3, r3, 15
  c2:	d9a440b4 	ld.bs      	r13, (r4, 0xb4)
  c6:	c54c4888 	asri      	r8, r12, 10
  ca:	e9070104 	bez      	r7, 0x2d2	// 2d2 <lmac_sta_info_statics_print+0x2d2>
  ce:	ea090064 	movi      	r9, 100
  d2:	6242      	subu      	r9, r0
  d4:	c4ec488c 	asri      	r12, r12, 7
  d8:	7f24      	mult      	r12, r9
  da:	ea09000a 	movi      	r9, 10
  de:	7f24      	mult      	r12, r9
  e0:	c4ec802c 	divu      	r12, r12, r7
  e4:	b803      	st.w      	r0, (r14, 0xc)
  e6:	dd8e2002 	st.w      	r12, (r14, 0x8)
  ea:	dd0e2001 	st.w      	r8, (r14, 0x4)
  ee:	ddae2000 	st.w      	r13, (r14, 0x0)
  f2:	131f      	lrw      	r0, 0x0	// 2ec <hgprintf+0x2ec>
  f4:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  f8:	3e41      	cmpnei      	r6, 1
  fa:	0835      	bt      	0x164	// 164 <lmac_sta_info_statics_print+0x164>
  fc:	d82400af 	ld.b      	r1, (r4, 0xaf)
 100:	e46120f0 	andi      	r3, r1, 240
 104:	eb430030 	cmpnei      	r3, 48
 108:	0ce7      	bf      	0x2d6	// 2d6 <lmac_sta_info_statics_print+0x2d6>
 10a:	4924      	lsri      	r1, r1, 4
 10c:	3302      	movi      	r3, 2
 10e:	c4234021 	lsl      	r1, r3, r1
 112:	d86410e2 	ld.h      	r3, (r4, 0x1c4)
 116:	6c8f      	mov      	r2, r3
 118:	e9030006 	bez      	r3, 0x124	// 124 <lmac_sta_info_statics_print+0x124>
 11c:	d80410e3 	ld.h      	r0, (r4, 0x1c6)
 120:	c4608023 	divu      	r3, r0, r3
 124:	d80410eb 	ld.h      	r0, (r4, 0x1d6)
 128:	b807      	st.w      	r0, (r14, 0x1c)
 12a:	d8042077 	ld.w      	r0, (r4, 0x1dc)
 12e:	500a      	asri      	r0, r0, 10
 130:	b806      	st.w      	r0, (r14, 0x18)
 132:	d80410ea 	ld.h      	r0, (r4, 0x1d4)
 136:	b805      	st.w      	r0, (r14, 0x14)
 138:	d8042076 	ld.w      	r0, (r4, 0x1d8)
 13c:	500a      	asri      	r0, r0, 10
 13e:	b804      	st.w      	r0, (r14, 0x10)
 140:	d8042074 	ld.w      	r0, (r4, 0x1d0)
 144:	b803      	st.w      	r0, (r14, 0xc)
 146:	9404      	ld.w      	r0, (r4, 0x10)
 148:	b802      	st.w      	r0, (r14, 0x8)
 14a:	d80400b2 	ld.b      	r0, (r4, 0xb2)
 14e:	b801      	st.w      	r0, (r14, 0x4)
 150:	ea0c0019 	movi      	r12, 25
 154:	d8042073 	ld.w      	r0, (r4, 0x1cc)
 158:	c5808040 	divs      	r0, r0, r12
 15c:	b800      	st.w      	r0, (r14, 0x0)
 15e:	1305      	lrw      	r0, 0x0	// 2f0 <lmac_sta_info_statics_print+0x2f0>
 160:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 164:	d80543e0 	ld.bs      	r0, (r5, 0x3e0)
 168:	d98440b8 	ld.bs      	r12, (r4, 0xb8)
 16c:	d84400b7 	ld.b      	r2, (r4, 0xb7)
 170:	6300      	addu      	r12, r0
 172:	d8042079 	ld.w      	r0, (r4, 0x1e4)
 176:	d8241034 	ld.h      	r1, (r4, 0x68)
 17a:	e442200f 	andi      	r2, r2, 15
 17e:	d86440b6 	ld.bs      	r3, (r4, 0xb6)
 182:	d90440a3 	ld.bs      	r8, (r4, 0xa3)
 186:	c5404849 	lsri      	r9, r0, 10
 18a:	e907000a 	bez      	r7, 0x19e	// 19e <lmac_sta_info_statics_print+0x19e>
 18e:	ea0d00fa 	movi      	r13, 250
 192:	4807      	lsri      	r0, r0, 7
 194:	c44d482d 	lsli      	r13, r13, 2
 198:	7c34      	mult      	r0, r13
 19a:	c4e08027 	divu      	r7, r0, r7
 19e:	d80400ac 	ld.b      	r0, (r4, 0xac)
 1a2:	b807      	st.w      	r0, (r14, 0x1c)
 1a4:	d80400ab 	ld.b      	r0, (r4, 0xab)
 1a8:	b806      	st.w      	r0, (r14, 0x18)
 1aa:	d80400aa 	ld.b      	r0, (r4, 0xaa)
 1ae:	b805      	st.w      	r0, (r14, 0x14)
 1b0:	d80400a9 	ld.b      	r0, (r4, 0xa9)
 1b4:	b804      	st.w      	r0, (r14, 0x10)
 1b6:	b8e3      	st.w      	r7, (r14, 0xc)
 1b8:	dd2e2002 	st.w      	r9, (r14, 0x8)
 1bc:	dd8e2001 	st.w      	r12, (r14, 0x4)
 1c0:	dd0e2000 	st.w      	r8, (r14, 0x0)
 1c4:	120c      	lrw      	r0, 0x0	// 2f4 <hgprintf+0x2f4>
 1c6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1ca:	3e41      	cmpnei      	r6, 1
 1cc:	0824      	bt      	0x214	// 214 <lmac_sta_info_statics_print+0x214>
 1ce:	d86410f0 	ld.h      	r3, (r4, 0x1e0)
 1d2:	d8241036 	ld.h      	r1, (r4, 0x6c)
 1d6:	6c8f      	mov      	r2, r3
 1d8:	e9030006 	bez      	r3, 0x1e4	// 1e4 <lmac_sta_info_statics_print+0x1e4>
 1dc:	d80410f1 	ld.h      	r0, (r4, 0x1e2)
 1e0:	c4608023 	divu      	r3, r0, r3
 1e4:	d804207b 	ld.w      	r0, (r4, 0x1ec)
 1e8:	b803      	st.w      	r0, (r14, 0xc)
 1ea:	d804207c 	ld.w      	r0, (r4, 0x1f0)
 1ee:	b802      	st.w      	r0, (r14, 0x8)
 1f0:	d80400b3 	ld.b      	r0, (r4, 0xb3)
 1f4:	ea0c0028 	movi      	r12, 40
 1f8:	b801      	st.w      	r0, (r14, 0x4)
 1fa:	d804207a 	ld.w      	r0, (r4, 0x1e8)
 1fe:	7c30      	mult      	r0, r12
 200:	ea0c00fa 	movi      	r12, 250
 204:	c44c482c 	lsli      	r12, r12, 2
 208:	c5808020 	divu      	r0, r0, r12
 20c:	b800      	st.w      	r0, (r14, 0x0)
 20e:	111b      	lrw      	r0, 0x0	// 2f8 <lmac_sta_info_statics_print+0x2f8>
 210:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 214:	111a      	lrw      	r0, 0x0	// 2fc <hgprintf+0x2fc>
 216:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 21a:	d86520ee 	ld.w      	r3, (r5, 0x3b8)
 21e:	e4632006 	andi      	r3, r3, 6
 222:	e9030010 	bez      	r3, 0x242	// 242 <lmac_sta_info_statics_print+0x242>
 226:	d804105f 	ld.h      	r0, (r4, 0xbe)
 22a:	c4205500 	zext      	r0, r0, 8, 1
 22e:	b800      	st.w      	r0, (r14, 0x0)
 230:	d864012c 	ld.b      	r3, (r4, 0x12c)
 234:	d8440128 	ld.b      	r2, (r4, 0x128)
 238:	d8241034 	ld.h      	r1, (r4, 0x68)
 23c:	1111      	lrw      	r0, 0x0	// 300 <hgprintf+0x300>
 23e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 242:	d8650338 	ld.b      	r3, (r5, 0x338)
 246:	e4632008 	andi      	r3, r3, 8
 24a:	e9030026 	bez      	r3, 0x296	// 296 <lmac_sta_info_statics_print+0x296>
 24e:	d86520ee 	ld.w      	r3, (r5, 0x3b8)
 252:	e4632002 	andi      	r3, r3, 2
 256:	e9030020 	bez      	r3, 0x296	// 296 <lmac_sta_info_statics_print+0x296>
 25a:	e4c400c1 	addi      	r6, r4, 194
 25e:	3500      	movi      	r5, 0
 260:	11e9      	lrw      	r7, 0x0	// 304 <lmac_sta_info_statics_print+0x304>
 262:	ea88002a 	lrw      	r8, 0x0	// 308 <lmac_sta_info_statics_print+0x308>
 266:	5c74      	addu      	r3, r4, r5
 268:	d8430102 	ld.b      	r2, (r3, 0x102)
 26c:	e9220005 	bnez      	r2, 0x276	// 276 <lmac_sta_info_statics_print+0x276>
 270:	8e60      	ld.h      	r3, (r6, 0x0)
 272:	e903000d 	bez      	r3, 0x28c	// 28c <lmac_sta_info_statics_print+0x28c>
 276:	8e20      	ld.h      	r1, (r6, 0x0)
 278:	d0a70443 	ldr.h      	r3, (r7, r5 << 1)
 27c:	4928      	lsri      	r1, r1, 8
 27e:	74cd      	zexth      	r3, r3
 280:	b820      	st.w      	r1, (r14, 0x0)
 282:	7cc4      	mult      	r3, r1
 284:	6c23      	mov      	r0, r8
 286:	6c57      	mov      	r1, r5
 288:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 28c:	2500      	addi      	r5, 1
 28e:	eb450020 	cmpnei      	r5, 32
 292:	2601      	addi      	r6, 2
 294:	0be9      	bt      	0x266	// 266 <lmac_sta_info_statics_print+0x266>
 296:	1408      	addi      	r14, r14, 32
 298:	1497      	pop      	r4-r10, r15
 29a:	d80400b9 	ld.b      	r0, (r4, 0xb9)
 29e:	e4002001 	andi      	r0, r0, 1
 2a2:	3840      	cmpnei      	r0, 0
 2a4:	ea8a001a 	lrw      	r10, 0x0	// 30c <lmac_sta_info_statics_print+0x30c>
 2a8:	101a      	lrw      	r0, 0x0	// 310 <lmac_sta_info_statics_print+0x310>
 2aa:	c40a0c20 	incf      	r0, r10, 0
 2ae:	b804      	st.w      	r0, (r14, 0x10)
 2b0:	dd2e2003 	st.w      	r9, (r14, 0xc)
 2b4:	dd0e2002 	st.w      	r8, (r14, 0x8)
 2b8:	ddae2001 	st.w      	r13, (r14, 0x4)
 2bc:	dd8e2000 	st.w      	r12, (r14, 0x0)
 2c0:	7445      	zexth      	r1, r1
 2c2:	1015      	lrw      	r0, 0x0	// 314 <lmac_sta_info_statics_print+0x314>
 2c4:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2c8:	06d8      	br      	0x78	// 78 <lmac_sta_info_statics_print+0x78>
 2ca:	3000      	movi      	r0, 0
 2cc:	06e4      	br      	0x94	// 94 <lmac_sta_info_statics_print+0x94>
 2ce:	1047      	lrw      	r2, 0x0	// 2e8 <lmac_sta_info_statics_print+0x2e8>
 2d0:	06f3      	br      	0xb6	// b6 <lmac_sta_info_statics_print+0xb6>
 2d2:	6f1f      	mov      	r12, r7
 2d4:	0708      	br      	0xe4	// e4 <lmac_sta_info_statics_print+0xe4>
 2d6:	6c5b      	mov      	r1, r6
 2d8:	071d      	br      	0x112	// 112 <lmac_sta_info_statics_print+0x112>
	...

Disassembly of section .text.lmac_channel_utilization_calc:

00000000 <lmac_channel_utilization_calc>:
   0:	14d8      	push      	r4-r11, r15
   2:	1423      	subi      	r14, r14, 12
   4:	6e03      	mov      	r8, r0
   6:	e90000bd 	bez      	r0, 0x180	// 180 <lmac_channel_utilization_calc+0x180>
   a:	12df      	lrw      	r6, 0x0	// 184 <lmac_channel_utilization_calc+0x184>
   c:	d86621d3 	ld.w      	r3, (r6, 0x74c)
  10:	d84621de 	ld.w      	r2, (r6, 0x778)
  14:	608c      	addu      	r2, r3
  16:	3328      	movi      	r3, 40
  18:	7c8c      	mult      	r2, r3
  1a:	33fa      	movi      	r3, 250
  1c:	4362      	lsli      	r3, r3, 2
  1e:	c4628022 	divu      	r2, r2, r3
  22:	6408      	cmphs      	r2, r0
  24:	0c09      	bf      	0x36	// 36 <lmac_channel_utilization_calc+0x36>
  26:	6c43      	mov      	r1, r0
  28:	1218      	lrw      	r0, 0x0	// 188 <lmac_channel_utilization_calc+0x188>
  2a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  2e:	3400      	movi      	r4, 0
  30:	6c13      	mov      	r0, r4
  32:	1403      	addi      	r14, r14, 12
  34:	1498      	pop      	r4-r11, r15
  36:	d86620ee 	ld.w      	r3, (r6, 0x3b8)
  3a:	e4632040 	andi      	r3, r3, 64
  3e:	58a9      	subu      	r5, r0, r2
  40:	e9030007 	bez      	r3, 0x4e	// 4e <lmac_channel_utilization_calc+0x4e>
  44:	6c43      	mov      	r1, r0
  46:	6cd7      	mov      	r3, r5
  48:	1211      	lrw      	r0, 0x0	// 18c <lmac_channel_utilization_calc+0x18c>
  4a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  4e:	3100      	movi      	r1, 0
  50:	2900      	subi      	r1, 1
  52:	1210      	lrw      	r0, 0x0	// 190 <lmac_channel_utilization_calc+0x190>
  54:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  58:	d8e6227e 	ld.w      	r7, (r6, 0x9f8)
  5c:	126e      	lrw      	r3, 0x0	// 194 <lmac_channel_utilization_calc+0x194>
  5e:	64de      	cmpne      	r7, r3
  60:	0882      	bt      	0x164	// 164 <lmac_channel_utilization_calc+0x164>
  62:	ea0b0000 	movi      	r11, 0
  66:	120b      	lrw      	r0, 0x0	// 190 <os_mutex_unlock+0x190>
  68:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  6c:	d8660308 	ld.b      	r3, (r6, 0x308)
  70:	4363      	lsli      	r3, r3, 3
  72:	e4632018 	andi      	r3, r3, 24
  76:	ea8a0049 	lrw      	r10, 0x0	// 198 <lmac_channel_utilization_calc+0x198>
  7a:	2306      	addi      	r3, 7
  7c:	d06a0449 	ldr.h      	r9, (r10, r3 << 1)
  80:	7665      	zexth      	r9, r9
  82:	4da1      	lsri      	r5, r5, 1
  84:	e90b007c 	bez      	r11, 0x17c	// 17c <lmac_channel_utilization_calc+0x17c>
  88:	d84710e3 	ld.h      	r2, (r7, 0x1c6)
  8c:	e9020074 	bez      	r2, 0x174	// 174 <lmac_channel_utilization_calc+0x174>
  90:	d86710ea 	ld.h      	r3, (r7, 0x1d4)
  94:	4367      	lsli      	r3, r3, 7
  96:	c4438043 	divs      	r3, r3, r2
  9a:	e46320ff 	andi      	r3, r3, 255
  9e:	d82b0128 	ld.b      	r1, (r11, 0x128)
  a2:	c4a38424 	mult      	r4, r3, r5
  a6:	d02a0441 	ldr.h      	r1, (r10, r1 << 1)
  aa:	7445      	zexth      	r1, r1
  ac:	4c87      	lsri      	r4, r4, 7
  ae:	c4290020 	addu      	r0, r9, r1
  b2:	7d04      	mult      	r4, r1
  b4:	c4048024 	divu      	r4, r4, r0
  b8:	d80620ee 	ld.w      	r0, (r6, 0x3b8)
  bc:	e4002040 	andi      	r0, r0, 64
  c0:	e900000b 	bez      	r0, 0xd6	// d6 <lmac_channel_utilization_calc+0xd6>
  c4:	b882      	st.w      	r4, (r14, 0x8)
  c6:	b841      	st.w      	r2, (r14, 0x4)
  c8:	d84710ea 	ld.h      	r2, (r7, 0x1d4)
  cc:	b840      	st.w      	r2, (r14, 0x0)
  ce:	6ca7      	mov      	r2, r9
  d0:	1113      	lrw      	r0, 0x0	// 19c <lmac_channel_utilization_calc+0x19c>
  d2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  d6:	d80710f1 	ld.h      	r0, (r7, 0x1e2)
  da:	d987207c 	ld.w      	r12, (r7, 0x1f0)
  de:	6300      	addu      	r12, r0
  e0:	e90c004c 	bez      	r12, 0x178	// 178 <lmac_channel_utilization_calc+0x178>
  e4:	4067      	lsli      	r3, r0, 7
  e6:	c5838023 	divu      	r3, r3, r12
  ea:	d82b00b7 	ld.b      	r1, (r11, 0xb7)
  ee:	4944      	lsri      	r2, r1, 4
  f0:	2200      	addi      	r2, 1
  f2:	4243      	lsli      	r2, r2, 3
  f4:	e4212007 	andi      	r1, r1, 7
  f8:	e4422018 	andi      	r2, r2, 24
  fc:	6c84      	or      	r2, r1
  fe:	e46320ff 	andi      	r3, r3, 255
 102:	d04a0441 	ldr.h      	r1, (r10, r2 << 1)
 106:	7d4c      	mult      	r5, r3
 108:	7445      	zexth      	r1, r1
 10a:	4da7      	lsri      	r5, r5, 7
 10c:	c4290022 	addu      	r2, r9, r1
 110:	7d44      	mult      	r5, r1
 112:	c4458025 	divu      	r5, r5, r2
 116:	d84620ee 	ld.w      	r2, (r6, 0x3b8)
 11a:	e4422040 	andi      	r2, r2, 64
 11e:	e902000a 	bez      	r2, 0x132	// 132 <lmac_channel_utilization_calc+0x132>
 122:	b800      	st.w      	r0, (r14, 0x0)
 124:	b8a2      	st.w      	r5, (r14, 0x8)
 126:	dd8e2001 	st.w      	r12, (r14, 0x4)
 12a:	6ca7      	mov      	r2, r9
 12c:	101d      	lrw      	r0, 0x0	// 1a0 <lmac_channel_utilization_calc+0x1a0>
 12e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 132:	5c34      	addu      	r1, r4, r5
 134:	c4280081 	subu      	r1, r8, r1
 138:	34ff      	movi      	r4, 255
 13a:	d86620ee 	ld.w      	r3, (r6, 0x3b8)
 13e:	7c50      	mult      	r1, r4
 140:	e4632040 	andi      	r3, r3, 64
 144:	c5018021 	divu      	r1, r1, r8
 148:	7504      	zextb      	r4, r1
 14a:	e903ff73 	bez      	r3, 0x30	// 30 <lmac_channel_utilization_calc+0x30>
 14e:	d84621de 	ld.w      	r2, (r6, 0x778)
 152:	d86621d3 	ld.w      	r3, (r6, 0x74c)
 156:	60c8      	addu      	r3, r2
 158:	6c53      	mov      	r1, r4
 15a:	6ca3      	mov      	r2, r8
 15c:	1012      	lrw      	r0, 0x0	// 1a4 <lmac_channel_utilization_calc+0x1a4>
 15e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 162:	0767      	br      	0x30	// 30 <lmac_channel_utilization_calc+0x30>
 164:	d8471034 	ld.h      	r2, (r7, 0x68)
 168:	e9020004 	bez      	r2, 0x170	// 170 <lmac_channel_utilization_calc+0x170>
 16c:	97e0      	ld.w      	r7, (r7, 0x0)
 16e:	0778      	br      	0x5e	// 5e <lmac_channel_utilization_calc+0x5e>
 170:	6edf      	mov      	r11, r7
 172:	077a      	br      	0x66	// 66 <lmac_channel_utilization_calc+0x66>
 174:	3380      	movi      	r3, 128
 176:	0792      	br      	0x9a	// 9a <lmac_channel_utilization_calc+0x9a>
 178:	3380      	movi      	r3, 128
 17a:	07b8      	br      	0xea	// ea <lmac_channel_utilization_calc+0xea>
 17c:	6d17      	mov      	r4, r5
 17e:	07da      	br      	0x132	// 132 <lmac_channel_utilization_calc+0x132>
 180:	6d03      	mov      	r4, r0
 182:	0757      	br      	0x30	// 30 <lmac_channel_utilization_calc+0x30>
	...

Disassembly of section .text.lmac_transceive_statics:

00000000 <lmac_transceive_statics>:
   0:	14d8      	push      	r4-r11, r15
   2:	1436      	subi      	r14, r14, 88
   4:	0096      	lrw      	r4, 0x0	// 3a8 <lmac_transceive_statics+0x3a8>
   6:	6dc3      	mov      	r7, r0
   8:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
   c:	d8c42207 	ld.w      	r6, (r4, 0x81c)
  10:	58d9      	subu      	r6, r0, r6
  12:	6c1b      	mov      	r0, r6
  14:	e0000000 	bsr      	0x0	// 0 <lmac_transceive_statics>
  18:	d8a421d0 	ld.w      	r5, (r4, 0x740)
  1c:	dc040a6a 	st.b      	r0, (r4, 0xa6a)
  20:	e9050051 	bez      	r5, 0xc2	// c2 <lmac_transceive_statics+0xc2>
  24:	c7e54889 	asri      	r9, r5, 31
  28:	6c97      	mov      	r2, r5
  2a:	6ce7      	mov      	r3, r9
  2c:	d8042202 	ld.w      	r0, (r4, 0x808)
  30:	d8242203 	ld.w      	r1, (r4, 0x80c)
  34:	e0000000 	bsr      	0x0	// 0 <__divdi3>
  38:	6e03      	mov      	r8, r0
  3a:	6c97      	mov      	r2, r5
  3c:	6ce7      	mov      	r3, r9
  3e:	d8042204 	ld.w      	r0, (r4, 0x810)
  42:	d8242205 	ld.w      	r1, (r4, 0x814)
  46:	e0000000 	bsr      	0x0	// 0 <__divdi3>
  4a:	3d29      	cmplti      	r5, 10
  4c:	083b      	bt      	0xc2	// c2 <lmac_transceive_statics+0xc2>
  4e:	3314      	movi      	r3, 20
  50:	7c0c      	mult      	r0, r3
  52:	620c      	addu      	r8, r3
  54:	c5008020 	divu      	r0, r0, r8
  58:	d86409e0 	ld.b      	r3, (r4, 0x9e0)
  5c:	e4632001 	andi      	r3, r3, 1
  60:	dc0420dc 	st.w      	r0, (r4, 0x370)
  64:	e9230032 	bnez      	r3, 0xc8	// c8 <lmac_transceive_statics+0xc8>
  68:	d8440319 	ld.b      	r2, (r4, 0x319)
  6c:	e4422002 	andi      	r2, r2, 2
  70:	e9220006 	bnez      	r2, 0x7c	// 7c <lmac_transceive_statics+0x7c>
  74:	3f40      	cmpnei      	r7, 0
  76:	c4000503 	mvc      	r3
  7a:	74cc      	zextb      	r3, r3
  7c:	d8442267 	ld.w      	r2, (r4, 0x99c)
  80:	2a01      	subi      	r2, 2
  82:	3a01      	cmphsi      	r2, 2
  84:	0c03      	bf      	0x8a	// 8a <lmac_transceive_statics+0x8a>
  86:	e9230031 	bnez      	r3, 0xe8	// e8 <lmac_transceive_statics+0xe8>
  8a:	3100      	movi      	r1, 0
  8c:	2900      	subi      	r1, 1
  8e:	0117      	lrw      	r0, 0x0	// 3ac <lmac_transceive_statics+0x3ac>
  90:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  94:	01d8      	lrw      	r6, 0x0	// 3b0 <lmac_transceive_statics+0x3b0>
  96:	d8a4227e 	ld.w      	r5, (r4, 0x9f8)
  9a:	6596      	cmpne      	r5, r6
  9c:	0818      	bt      	0xcc	// cc <lmac_transceive_statics+0xcc>
  9e:	5d1e      	addi      	r0, r5, 8
  a0:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  a4:	3286      	movi      	r2, 134
  a6:	4241      	lsli      	r2, r2, 1
  a8:	3100      	movi      	r1, 0
  aa:	e40512eb 	subi      	r0, r5, 748
  ae:	e0000000 	bsr      	0x0	// 0 <memset>
  b2:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  b6:	dc042207 	st.w      	r0, (r4, 0x81c)
  ba:	dc242208 	st.w      	r1, (r4, 0x820)
  be:	1416      	addi      	r14, r14, 88
  c0:	1498      	pop      	r4-r11, r15
  c2:	d80420dc 	ld.w      	r0, (r4, 0x370)
  c6:	07c9      	br      	0x58	// 58 <lmac_transceive_statics+0x58>
  c8:	3300      	movi      	r3, 0
  ca:	07d9      	br      	0x7c	// 7c <lmac_transceive_statics+0x7c>
  cc:	321c      	movi      	r2, 28
  ce:	3100      	movi      	r1, 0
  d0:	e40501c3 	addi      	r0, r5, 452
  d4:	e0000000 	bsr      	0x0	// 0 <memset>
  d8:	e40501df 	addi      	r0, r5, 480
  dc:	3214      	movi      	r2, 20
  de:	3100      	movi      	r1, 0
  e0:	e0000000 	bsr      	0x0	// 0 <memset>
  e4:	95a0      	ld.w      	r5, (r5, 0x0)
  e6:	07da      	br      	0x9a	// 9a <lmac_transceive_statics+0x9a>
  e8:	3f02      	cmphsi      	r7, 3
  ea:	6d5f      	mov      	r5, r7
  ec:	0c02      	bf      	0xf0	// f0 <lmac_transceive_statics+0xf0>
  ee:	3502      	movi      	r5, 2
  f0:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
  f4:	e4432002 	andi      	r2, r3, 2
  f8:	7554      	zextb      	r5, r5
  fa:	e90200d7 	bez      	r2, 0x2a8	// 2a8 <lmac_transceive_statics+0x2a8>
  fe:	e4632008 	andi      	r3, r3, 8
 102:	e9230004 	bnez      	r3, 0x10a	// 10a <lmac_transceive_statics+0x10a>
 106:	e0000000 	bsr      	0x0	// 0 <lhw_abort_fsm>
 10a:	d80409e2 	ld.b      	r0, (r4, 0x9e2)
 10e:	e4002004 	andi      	r0, r0, 4
 112:	e9200004 	bnez      	r0, 0x11a	// 11a <lmac_transceive_statics+0x11a>
 116:	e0000000 	bsr      	0x0	// 0 <disable_print>
 11a:	d86421d1 	ld.w      	r3, (r4, 0x744)
 11e:	dc6421b8 	st.w      	r3, (r4, 0x6e0)
 122:	d86421d6 	ld.w      	r3, (r4, 0x758)
 126:	dc6421b9 	st.w      	r3, (r4, 0x6e4)
 12a:	d86421db 	ld.w      	r3, (r4, 0x76c)
 12e:	d84421e4 	ld.w      	r2, (r4, 0x790)
 132:	dc6421bc 	st.w      	r3, (r4, 0x6f0)
 136:	d86421e2 	ld.w      	r3, (r4, 0x788)
 13a:	60c8      	addu      	r3, r2
 13c:	0301      	lrw      	r0, 0x0	// 3b4 <lmac_transceive_statics+0x3b4>
 13e:	03e0      	lrw      	r7, 0x0	// 3b8 <lmac_transceive_statics+0x3b8>
 140:	dc6421bd 	st.w      	r3, (r4, 0x6f4)
 144:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 148:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
 14c:	e4632008 	andi      	r3, r3, 8
 150:	3b40      	cmpnei      	r3, 0
 152:	d804219f 	ld.w      	r0, (r4, 0x67c)
 156:	d90420ce 	ld.w      	r8, (r4, 0x338)
 15a:	c4885768 	zext      	r8, r8, 27, 4
 15e:	0367      	lrw      	r3, 0x0	// 3bc <lmac_transceive_statics+0x3bc>
 160:	c4e30c20 	incf      	r7, r3, 0
 164:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 168:	d9a421b8 	ld.w      	r13, (r4, 0x6e0)
 16c:	d92421c0 	ld.w      	r9, (r4, 0x700)
 170:	d944219e 	ld.w      	r10, (r4, 0x678)
 174:	d84421b9 	ld.w      	r2, (r4, 0x6e4)
 178:	e90d0142 	bez      	r13, 0x3fc	// 3fc <lmac_transceive_statics+0x3fc>
 17c:	ea0c0064 	movi      	r12, 100
 180:	7f08      	mult      	r12, r2
 182:	c5ac804c 	divs      	r12, r12, r13
 186:	d86421ba 	ld.w      	r3, (r4, 0x6e8)
 18a:	b866      	st.w      	r3, (r14, 0x18)
 18c:	dd8e2005 	st.w      	r12, (r14, 0x14)
 190:	b844      	st.w      	r2, (r14, 0x10)
 192:	ddae2003 	st.w      	r13, (r14, 0xc)
 196:	b801      	st.w      	r0, (r14, 0x4)
 198:	b822      	st.w      	r1, (r14, 0x8)
 19a:	6ce7      	mov      	r3, r9
 19c:	6ca3      	mov      	r2, r8
 19e:	6c5f      	mov      	r1, r7
 1a0:	0317      	lrw      	r0, 0x0	// 3c0 <lmac_transceive_statics+0x3c0>
 1a2:	dd4e2000 	st.w      	r10, (r14, 0x0)
 1a6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1aa:	d86421bf 	ld.w      	r3, (r4, 0x6fc)
 1ae:	b862      	st.w      	r3, (r14, 0x8)
 1b0:	d86421c1 	ld.w      	r3, (r4, 0x704)
 1b4:	d82421bc 	ld.w      	r1, (r4, 0x6f0)
 1b8:	d84421e4 	ld.w      	r2, (r4, 0x790)
 1bc:	b861      	st.w      	r3, (r14, 0x4)
 1be:	d86421be 	ld.w      	r3, (r4, 0x6f8)
 1c2:	b860      	st.w      	r3, (r14, 0x0)
 1c4:	5949      	subu      	r2, r1, r2
 1c6:	d86421bd 	ld.w      	r3, (r4, 0x6f4)
 1ca:	131f      	lrw      	r0, 0x0	// 3c4 <hgprintf+0x3c4>
 1cc:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1d0:	d8640892 	ld.b      	r3, (r4, 0x892)
 1d4:	e4632001 	andi      	r3, r3, 1
 1d8:	e9030059 	bez      	r3, 0x28a	// 28a <lmac_transceive_statics+0x28a>
 1dc:	d80408c4 	ld.b      	r0, (r4, 0x8c4)
 1e0:	b800      	st.w      	r0, (r14, 0x0)
 1e2:	d80408c5 	ld.b      	r0, (r4, 0x8c5)
 1e6:	d9a448be 	ld.bs      	r13, (r4, 0x8be)
 1ea:	d8e4489a 	ld.bs      	r7, (r4, 0x89a)
 1ee:	b801      	st.w      	r0, (r14, 0x4)
 1f0:	d80408c6 	ld.b      	r0, (r4, 0x8c6)
 1f4:	675d      	cmplt      	r7, r13
 1f6:	b802      	st.w      	r0, (r14, 0x8)
 1f8:	d80408c8 	ld.b      	r0, (r4, 0x8c8)
 1fc:	ea8b0073 	lrw      	r11, 0x0	// 3c8 <lmac_transceive_statics+0x3c8>
 200:	ea8c0073 	lrw      	r12, 0x0	// 3cc <lmac_transceive_statics+0x3cc>
 204:	c58b0c40 	inct      	r12, r11, 0
 208:	d90408c7 	ld.b      	r8, (r4, 0x8c7)
 20c:	d9241459 	ld.h      	r9, (r4, 0x8b2)
 210:	d94448c9 	ld.bs      	r10, (r4, 0x8c9)
 214:	e400203f 	andi      	r0, r0, 63
 218:	d824489b 	ld.bs      	r1, (r4, 0x89b)
 21c:	d84408c2 	ld.b      	r2, (r4, 0x8c2)
 220:	d86408c3 	ld.b      	r3, (r4, 0x8c3)
 224:	dd8e2009 	st.w      	r12, (r14, 0x24)
 228:	ddae2007 	st.w      	r13, (r14, 0x1c)
 22c:	b806      	st.w      	r0, (r14, 0x18)
 22e:	b8e8      	st.w      	r7, (r14, 0x20)
 230:	dd4e2005 	st.w      	r10, (r14, 0x14)
 234:	dd2e2004 	st.w      	r9, (r14, 0x10)
 238:	dd0e2003 	st.w      	r8, (r14, 0xc)
 23c:	1305      	lrw      	r0, 0x0	// 3d0 <hgprintf+0x3d0>
 23e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 242:	d80448b8 	ld.bs      	r0, (r4, 0x8b8)
 246:	b802      	st.w      	r0, (r14, 0x8)
 248:	d80448ae 	ld.bs      	r0, (r4, 0x8ae)
 24c:	b801      	st.w      	r0, (r14, 0x4)
 24e:	d80448b7 	ld.bs      	r0, (r4, 0x8b7)
 252:	d86448ad 	ld.bs      	r3, (r4, 0x8ad)
 256:	d84448b6 	ld.bs      	r2, (r4, 0x8b6)
 25a:	d82448ac 	ld.bs      	r1, (r4, 0x8ac)
 25e:	b800      	st.w      	r0, (r14, 0x0)
 260:	121d      	lrw      	r0, 0x0	// 3d4 <lmac_transceive_statics+0x3d4>
 262:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 266:	d80448a6 	ld.bs      	r0, (r4, 0x8a6)
 26a:	b802      	st.w      	r0, (r14, 0x8)
 26c:	d804489e 	ld.bs      	r0, (r4, 0x89e)
 270:	b801      	st.w      	r0, (r14, 0x4)
 272:	d80448a5 	ld.bs      	r0, (r4, 0x8a5)
 276:	b800      	st.w      	r0, (r14, 0x0)
 278:	d864489d 	ld.bs      	r3, (r4, 0x89d)
 27c:	d84448a4 	ld.bs      	r2, (r4, 0x8a4)
 280:	d824489c 	ld.bs      	r1, (r4, 0x89c)
 284:	1215      	lrw      	r0, 0x0	// 3d8 <hgprintf+0x3d8>
 286:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 28a:	3001      	movi      	r0, 1
 28c:	e0000000 	bsr      	0x0	// 0 <disable_print>
 290:	d8e409e2 	ld.b      	r7, (r4, 0x9e2)
 294:	e4e72008 	andi      	r7, r7, 8
 298:	e9270008 	bnez      	r7, 0x2a8	// 2a8 <lmac_transceive_statics+0x2a8>
 29c:	300a      	movi      	r0, 10
 29e:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
 2a2:	6c1f      	mov      	r0, r7
 2a4:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
 2a8:	120d      	lrw      	r0, 0x0	// 3dc <hgprintf+0x3dc>
 2aa:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2ae:	1202      	lrw      	r0, 0x0	// 3b4 <hgprintf+0x3b4>
 2b0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2b4:	d804202f 	ld.w      	r0, (r4, 0xbc)
 2b8:	b804      	st.w      	r0, (r14, 0x10)
 2ba:	d8041198 	ld.h      	r0, (r4, 0x330)
 2be:	b803      	st.w      	r0, (r14, 0xc)
 2c0:	d8040307 	ld.b      	r0, (r4, 0x307)
 2c4:	b802      	st.w      	r0, (r14, 0x8)
 2c6:	d8040306 	ld.b      	r0, (r4, 0x306)
 2ca:	b801      	st.w      	r0, (r14, 0x4)
 2cc:	d8040305 	ld.b      	r0, (r4, 0x305)
 2d0:	d8640304 	ld.b      	r3, (r4, 0x304)
 2d4:	b800      	st.w      	r0, (r14, 0x0)
 2d6:	d8440303 	ld.b      	r2, (r4, 0x303)
 2da:	d8240302 	ld.b      	r1, (r4, 0x302)
 2de:	1201      	lrw      	r0, 0x0	// 3e0 <hgprintf+0x3e0>
 2e0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2e4:	d86420ee 	ld.w      	r3, (r4, 0x3b8)
 2e8:	e4632080 	andi      	r3, r3, 128
 2ec:	e903001d 	bez      	r3, 0x326	// 326 <lmac_transceive_statics+0x326>
 2f0:	d8041506 	ld.h      	r0, (r4, 0xa0c)
 2f4:	b805      	st.w      	r0, (r14, 0x14)
 2f6:	d8041505 	ld.h      	r0, (r4, 0xa0a)
 2fa:	b804      	st.w      	r0, (r14, 0x10)
 2fc:	d80422e9 	ld.w      	r0, (r4, 0xba4)
 300:	b803      	st.w      	r0, (r14, 0xc)
 302:	d804052b 	ld.b      	r0, (r4, 0x52b)
 306:	b802      	st.w      	r0, (r14, 0x8)
 308:	d804052a 	ld.b      	r0, (r4, 0x52a)
 30c:	b801      	st.w      	r0, (r14, 0x4)
 30e:	d8040529 	ld.b      	r0, (r4, 0x529)
 312:	b800      	st.w      	r0, (r14, 0x0)
 314:	d8640528 	ld.b      	r3, (r4, 0x528)
 318:	d8440527 	ld.b      	r2, (r4, 0x527)
 31c:	d8240526 	ld.b      	r1, (r4, 0x526)
 320:	1111      	lrw      	r0, 0x0	// 3e4 <hgprintf+0x3e4>
 322:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 326:	d84420ce 	ld.w      	r2, (r4, 0x338)
 32a:	33fa      	movi      	r3, 250
 32c:	c4825762 	zext      	r2, r2, 27, 4
 330:	4362      	lsli      	r3, r3, 2
 332:	c4628041 	divs      	r1, r2, r3
 336:	d804034a 	ld.b      	r0, (r4, 0x34a)
 33a:	7cc4      	mult      	r3, r1
 33c:	e4002001 	andi      	r0, r0, 1
 340:	608e      	subu      	r2, r3
 342:	3364      	movi      	r3, 100
 344:	c4628042 	divs      	r2, r2, r3
 348:	3301      	movi      	r3, 1
 34a:	e9200005 	bnez      	r0, 0x354	// 354 <lmac_transceive_statics+0x354>
 34e:	d8040308 	ld.b      	r0, (r4, 0x308)
 352:	70c0      	lsl      	r3, r0
 354:	d80443e0 	ld.bs      	r0, (r4, 0x3e0)
 358:	d984431e 	ld.bs      	r12, (r4, 0x31e)
 35c:	6300      	addu      	r12, r0
 35e:	d80453f4 	ld.hs      	r0, (r4, 0x7e8)
 362:	e9000007 	bez      	r0, 0x370	// 370 <lmac_transceive_statics+0x370>
 366:	4006      	lsli      	r0, r0, 6
 368:	d9a421f8 	ld.w      	r13, (r4, 0x7e0)
 36c:	c40d8040 	divs      	r0, r13, r0
 370:	b801      	st.w      	r0, (r14, 0x4)
 372:	dd8e2000 	st.w      	r12, (r14, 0x0)
 376:	101d      	lrw      	r0, 0x0	// 3e8 <hgprintf+0x3e8>
 378:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 37c:	105c      	lrw      	r2, 0x0	// 3ec <lmac_transceive_statics+0x3ec>
 37e:	300c      	movi      	r0, 12
 380:	8260      	ld.b      	r3, (r2, 0x0)
 382:	c4038021 	divu      	r1, r3, r0
 386:	7c40      	mult      	r1, r0
 388:	60c6      	subu      	r3, r1
 38a:	74cc      	zextb      	r3, r3
 38c:	ea8c0019 	lrw      	r12, 0x0	// 3f0 <lmac_transceive_statics+0x3f0>
 390:	1019      	lrw      	r0, 0x0	// 3f4 <lmac_transceive_statics+0x3f4>
 392:	103a      	lrw      	r1, 0x0	// 3f8 <lmac_transceive_statics+0x3f8>
 394:	e9230036 	bnez      	r3, 0x400	// 400 <lmac_transceive_statics+0x400>
 398:	a260      	st.b      	r3, (r2, 0x0)
 39a:	d864431e 	ld.bs      	r3, (r4, 0x31e)
 39e:	dc6c2000 	st.w      	r3, (r12, 0x0)
 3a2:	b060      	st.w      	r3, (r0, 0x0)
 3a4:	b160      	st.w      	r3, (r1, 0x0)
 3a6:	043c      	br      	0x41e	// 41e <lmac_transceive_statics+0x41e>
	...
 3fc:	6f37      	mov      	r12, r13
 3fe:	06c4      	br      	0x186	// 186 <lmac_transceive_statics+0x186>
 400:	d9ac2000 	ld.w      	r13, (r12, 0x0)
 404:	d864431e 	ld.bs      	r3, (r4, 0x31e)
 408:	634c      	addu      	r13, r3
 40a:	ddac2000 	st.w      	r13, (r12, 0x0)
 40e:	d9802000 	ld.w      	r12, (r0, 0x0)
 412:	64f1      	cmplt      	r12, r3
 414:	0c02      	bf      	0x418	// 418 <lmac_transceive_statics+0x418>
 416:	b060      	st.w      	r3, (r0, 0x0)
 418:	9100      	ld.w      	r0, (r1, 0x0)
 41a:	640d      	cmplt      	r3, r0
 41c:	0bc4      	bt      	0x3a4	// 3a4 <lmac_transceive_statics+0x3a4>
 41e:	8260      	ld.b      	r3, (r2, 0x0)
 420:	2300      	addi      	r3, 1
 422:	a260      	st.b      	r3, (r2, 0x0)
 424:	d8640378 	ld.b      	r3, (r4, 0x378)
 428:	2b00      	subi      	r3, 1
 42a:	74cc      	zextb      	r3, r3
 42c:	3b0f      	cmphsi      	r3, 16
 42e:	082b      	bt      	0x484	// 484 <lmac_transceive_statics+0x484>
 430:	ea80016f 	lrw      	r0, 0x0	// 9ec <lmac_transceive_statics+0x9ec>
 434:	3700      	movi      	r7, 0
 436:	ea0800fa 	movi      	r8, 250
 43a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 43e:	6e5f      	mov      	r9, r7
 440:	c4484828 	lsli      	r8, r8, 2
 444:	ea0a0064 	movi      	r10, 100
 448:	ea8b016a 	lrw      	r11, 0x0	// 9f0 <lmac_transceive_statics+0x9f0>
 44c:	d8640378 	ld.b      	r3, (r4, 0x378)
 450:	64e5      	cmplt      	r9, r3
 452:	2717      	addi      	r7, 24
 454:	e860030e 	bt      	0xa70	// a70 <lmac_transceive_statics+0xa70>
 458:	ea800167 	lrw      	r0, 0x0	// 9f4 <lmac_transceive_statics+0x9f4>
 45c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 460:	3700      	movi      	r7, 0
 462:	ea800166 	lrw      	r0, 0x0	// 9f8 <lmac_transceive_statics+0x9f8>
 466:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 46a:	6e1f      	mov      	r8, r7
 46c:	ea890164 	lrw      	r9, 0x0	// 9fc <lmac_transceive_statics+0x9fc>
 470:	d8640378 	ld.b      	r3, (r4, 0x378)
 474:	64e1      	cmplt      	r8, r3
 476:	2717      	addi      	r7, 24
 478:	e860030e 	bt      	0xa94	// a94 <lmac_transceive_statics+0xa94>
 47c:	ea80015e 	lrw      	r0, 0x0	// 9f4 <lmac_transceive_statics+0x9f4>
 480:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 484:	3d41      	cmpnei      	r5, 1
 486:	0853      	bt      	0x52c	// 52c <lmac_transceive_statics+0x52c>
 488:	d86453f4 	ld.hs      	r3, (r4, 0x7e8)
 48c:	e9030312 	bez      	r3, 0xab0	// ab0 <lmac_transceive_statics+0xab0>
 490:	4326      	lsli      	r1, r3, 6
 492:	d84421f8 	ld.w      	r2, (r4, 0x7e0)
 496:	c4228041 	divs      	r1, r2, r1
 49a:	d8445196 	ld.hs      	r2, (r4, 0x32c)
 49e:	e963030c 	blsz      	r3, 0xab6	// ab6 <lmac_transceive_statics+0xab6>
 4a2:	d80453f3 	ld.hs      	r0, (r4, 0x7e6)
 4a6:	c4608043 	divs      	r3, r0, r3
 4aa:	d8040338 	ld.b      	r0, (r4, 0x338)
 4ae:	e4002001 	andi      	r0, r0, 1
 4b2:	3840      	cmpnei      	r0, 0
 4b4:	ea8c0153 	lrw      	r12, 0x0	// a00 <lmac_transceive_statics+0xa00>
 4b8:	ea800153 	lrw      	r0, 0x0	// a04 <lmac_transceive_statics+0xa04>
 4bc:	c40c0c20 	incf      	r0, r12, 0
 4c0:	d98421f0 	ld.w      	r12, (r4, 0x7c0)
 4c4:	dd8e200c 	st.w      	r12, (r14, 0x30)
 4c8:	d98421ef 	ld.w      	r12, (r4, 0x7bc)
 4cc:	dd8e200b 	st.w      	r12, (r14, 0x2c)
 4d0:	d98421ee 	ld.w      	r12, (r4, 0x7b8)
 4d4:	dd8e200a 	st.w      	r12, (r14, 0x28)
 4d8:	d98421ea 	ld.w      	r12, (r4, 0x7a8)
 4dc:	dd8e2009 	st.w      	r12, (r14, 0x24)
 4e0:	d98421e9 	ld.w      	r12, (r4, 0x7a4)
 4e4:	dd8e2008 	st.w      	r12, (r14, 0x20)
 4e8:	d98421e8 	ld.w      	r12, (r4, 0x7a0)
 4ec:	d9a453f2 	ld.hs      	r13, (r4, 0x7e4)
 4f0:	d8e45389 	ld.hs      	r7, (r4, 0x712)
 4f4:	d904538a 	ld.hs      	r8, (r4, 0x714)
 4f8:	d924541c 	ld.hs      	r9, (r4, 0x838)
 4fc:	d944541d 	ld.hs      	r10, (r4, 0x83a)
 500:	dd8e2007 	st.w      	r12, (r14, 0x1c)
 504:	d984036c 	ld.b      	r12, (r4, 0x36c)
 508:	e58c201f 	andi      	r12, r12, 31
 50c:	b805      	st.w      	r0, (r14, 0x14)
 50e:	dd4e2004 	st.w      	r10, (r14, 0x10)
 512:	dd2e2003 	st.w      	r9, (r14, 0xc)
 516:	dd0e2002 	st.w      	r8, (r14, 0x8)
 51a:	b8e1      	st.w      	r7, (r14, 0x4)
 51c:	ddae2000 	st.w      	r13, (r14, 0x0)
 520:	dd8e2006 	st.w      	r12, (r14, 0x18)
 524:	ea800139 	lrw      	r0, 0x0	// a08 <lmac_transceive_statics+0xa08>
 528:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 52c:	3001      	movi      	r0, 1
 52e:	e0000000 	bsr      	0x0	// 0 <skbpool_freesize>
 532:	6dc3      	mov      	r7, r0
 534:	e0000000 	bsr      	0x0	// 0 <lmac_txq_count>
 538:	6e03      	mov      	r8, r0
 53a:	e0000000 	bsr      	0x0	// 0 <lmac_txsq_count>
 53e:	6cc3      	mov      	r3, r0
 540:	6ca3      	mov      	r2, r8
 542:	4f2b      	lsri      	r1, r7, 11
 544:	ea800132 	lrw      	r0, 0x0	// a0c <lmac_transceive_statics+0xa0c>
 548:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 54c:	3d41      	cmpnei      	r5, 1
 54e:	084b      	bt      	0x5e4	// 5e4 <lmac_transceive_statics+0x5e4>
 550:	3000      	movi      	r0, 0
 552:	e0000000 	bsr      	0x0	// 0 <lmac_acq_count>
 556:	6dc3      	mov      	r7, r0
 558:	6c17      	mov      	r0, r5
 55a:	e0000000 	bsr      	0x0	// 0 <lmac_acq_count>
 55e:	6e03      	mov      	r8, r0
 560:	3002      	movi      	r0, 2
 562:	e0000000 	bsr      	0x0	// 0 <lmac_acq_count>
 566:	6e43      	mov      	r9, r0
 568:	3003      	movi      	r0, 3
 56a:	e0000000 	bsr      	0x0	// 0 <lmac_acq_count>
 56e:	6e83      	mov      	r10, r0
 570:	3000      	movi      	r0, 0
 572:	e0000000 	bsr      	0x0	// 0 <lmac_txagg_count>
 576:	6ec3      	mov      	r11, r0
 578:	6c17      	mov      	r0, r5
 57a:	e0000000 	bsr      	0x0	// 0 <lmac_txagg_count>
 57e:	b811      	st.w      	r0, (r14, 0x44)
 580:	3002      	movi      	r0, 2
 582:	e0000000 	bsr      	0x0	// 0 <lmac_txagg_count>
 586:	b810      	st.w      	r0, (r14, 0x40)
 588:	3003      	movi      	r0, 3
 58a:	e0000000 	bsr      	0x0	// 0 <lmac_txagg_count>
 58e:	b80f      	st.w      	r0, (r14, 0x3c)
 590:	e0000000 	bsr      	0x0	// 0 <lmac_statq_count>
 594:	b80e      	st.w      	r0, (r14, 0x38)
 596:	e0000000 	bsr      	0x0	// 0 <lmac_rx_data_queue_count>
 59a:	b80d      	st.w      	r0, (r14, 0x34)
 59c:	e0000000 	bsr      	0x0	// 0 <lmac_rx_iface_queue_count>
 5a0:	982f      	ld.w      	r1, (r14, 0x3c)
 5a2:	9850      	ld.w      	r2, (r14, 0x40)
 5a4:	9871      	ld.w      	r3, (r14, 0x44)
 5a6:	d9ae200d 	ld.w      	r13, (r14, 0x34)
 5aa:	d98e200e 	ld.w      	r12, (r14, 0x38)
 5ae:	b807      	st.w      	r0, (r14, 0x1c)
 5b0:	b824      	st.w      	r1, (r14, 0x10)
 5b2:	b843      	st.w      	r2, (r14, 0xc)
 5b4:	b862      	st.w      	r3, (r14, 0x8)
 5b6:	6ca3      	mov      	r2, r8
 5b8:	6c5f      	mov      	r1, r7
 5ba:	ea800116 	lrw      	r0, 0x0	// a10 <lmac_transceive_statics+0xa10>
 5be:	6ce7      	mov      	r3, r9
 5c0:	ddae2006 	st.w      	r13, (r14, 0x18)
 5c4:	dd8e2005 	st.w      	r12, (r14, 0x14)
 5c8:	dd6e2001 	st.w      	r11, (r14, 0x4)
 5cc:	dd4e2000 	st.w      	r10, (r14, 0x0)
 5d0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 5d4:	d844553d 	ld.hs      	r2, (r4, 0xa7a)
 5d8:	d824553c 	ld.hs      	r1, (r4, 0xa78)
 5dc:	ea80010e 	lrw      	r0, 0x0	// a14 <lmac_transceive_statics+0xa14>
 5e0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 5e4:	d86421cf 	ld.w      	r3, (r4, 0x73c)
 5e8:	b866      	st.w      	r3, (r14, 0x18)
 5ea:	d86421cd 	ld.w      	r3, (r4, 0x734)
 5ee:	b865      	st.w      	r3, (r14, 0x14)
 5f0:	d86421ce 	ld.w      	r3, (r4, 0x738)
 5f4:	b864      	st.w      	r3, (r14, 0x10)
 5f6:	d86421ca 	ld.w      	r3, (r4, 0x728)
 5fa:	b863      	st.w      	r3, (r14, 0xc)
 5fc:	d86421c9 	ld.w      	r3, (r4, 0x724)
 600:	b862      	st.w      	r3, (r14, 0x8)
 602:	d86421c8 	ld.w      	r3, (r4, 0x720)
 606:	b861      	st.w      	r3, (r14, 0x4)
 608:	d86421c7 	ld.w      	r3, (r4, 0x71c)
 60c:	b860      	st.w      	r3, (r14, 0x0)
 60e:	d82421c6 	ld.w      	r1, (r4, 0x718)
 612:	d86421cb 	ld.w      	r3, (r4, 0x72c)
 616:	d84421cc 	ld.w      	r2, (r4, 0x730)
 61a:	ea800100 	lrw      	r0, 0x0	// a18 <lmac_transceive_statics+0xa18>
 61e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 622:	d82421d1 	ld.w      	r1, (r4, 0x744)
 626:	e901024c 	bez      	r1, 0xabe	// abe <lmac_transceive_statics+0xabe>
 62a:	3264      	movi      	r2, 100
 62c:	d86421d6 	ld.w      	r3, (r4, 0x758)
 630:	7cc8      	mult      	r3, r2
 632:	c4238043 	divs      	r3, r3, r1
 636:	d84421d9 	ld.w      	r2, (r4, 0x764)
 63a:	75cc      	zextb      	r7, r3
 63c:	dc64083d 	st.b      	r3, (r4, 0x83d)
 640:	c4228042 	divs      	r2, r2, r1
 644:	d8040338 	ld.b      	r0, (r4, 0x338)
 648:	e4002001 	andi      	r0, r0, 1
 64c:	d86421d8 	ld.w      	r3, (r4, 0x760)
 650:	d98420dc 	ld.w      	r12, (r4, 0x370)
 654:	e9000239 	bez      	r0, 0xac6	// ac6 <lmac_transceive_statics+0xac6>
 658:	d8040840 	ld.b      	r0, (r4, 0x840)
 65c:	d9a421d7 	ld.w      	r13, (r4, 0x75c)
 660:	ddae2003 	st.w      	r13, (r14, 0xc)
 664:	d9a421d6 	ld.w      	r13, (r4, 0x758)
 668:	b801      	st.w      	r0, (r14, 0x4)
 66a:	ddae2002 	st.w      	r13, (r14, 0x8)
 66e:	dd8e2000 	st.w      	r12, (r14, 0x0)
 672:	0014      	lrw      	r0, 0x0	// a1c <hgprintf+0xa1c>
 674:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 678:	3d41      	cmpnei      	r5, 1
 67a:	0841      	bt      	0x6fc	// 6fc <lmac_transceive_statics+0x6fc>
 67c:	d864070f 	ld.b      	r3, (r4, 0x70f)
 680:	5b42      	addi      	r2, r3, 1
 682:	d98421d0 	ld.w      	r12, (r4, 0x740)
 686:	e4422003 	andi      	r2, r2, 3
 68a:	d824483d 	ld.bs      	r1, (r4, 0x83d)
 68e:	c4454022 	lsl      	r2, r5, r2
 692:	4b64      	lsri      	r3, r3, 4
 694:	e90c0006 	bez      	r12, 0x6a0	// 6a0 <lmac_transceive_statics+0x6a0>
 698:	d80421d1 	ld.w      	r0, (r4, 0x744)
 69c:	c580804c 	divs      	r12, r0, r12
 6a0:	d80421d2 	ld.w      	r0, (r4, 0x748)
 6a4:	d9a421eb 	ld.w      	r13, (r4, 0x7ac)
 6a8:	d90421ec 	ld.w      	r8, (r4, 0x7b0)
 6ac:	d92421ed 	ld.w      	r9, (r4, 0x7b4)
 6b0:	c540488a 	asri      	r10, r0, 10
 6b4:	e906020f 	bez      	r6, 0xad2	// ad2 <lmac_transceive_statics+0xad2>
 6b8:	ea0b0064 	movi      	r11, 100
 6bc:	c4eb0087 	subu      	r7, r11, r7
 6c0:	5007      	asri      	r0, r0, 7
 6c2:	7c1c      	mult      	r0, r7
 6c4:	370a      	movi      	r7, 10
 6c6:	7c1c      	mult      	r0, r7
 6c8:	c4c08020 	divu      	r0, r0, r6
 6cc:	d8e421d4 	ld.w      	r7, (r4, 0x750)
 6d0:	b8e7      	st.w      	r7, (r14, 0x1c)
 6d2:	ea0b0019 	movi      	r11, 25
 6d6:	d8e421d3 	ld.w      	r7, (r4, 0x74c)
 6da:	c5678047 	divs      	r7, r7, r11
 6de:	b805      	st.w      	r0, (r14, 0x14)
 6e0:	b8e6      	st.w      	r7, (r14, 0x18)
 6e2:	dd4e2004 	st.w      	r10, (r14, 0x10)
 6e6:	dd2e2003 	st.w      	r9, (r14, 0xc)
 6ea:	dd0e2002 	st.w      	r8, (r14, 0x8)
 6ee:	ddae2001 	st.w      	r13, (r14, 0x4)
 6f2:	dd8e2000 	st.w      	r12, (r14, 0x0)
 6f6:	0114      	lrw      	r0, 0x0	// a20 <hgprintf+0xa20>
 6f8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 6fc:	d84421d1 	ld.w      	r2, (r4, 0x744)
 700:	e902001a 	bez      	r2, 0x734	// 734 <lmac_transceive_statics+0x734>
 704:	d86421d9 	ld.w      	r3, (r4, 0x764)
 708:	c4438043 	divs      	r3, r3, r2
 70c:	eb2301f3 	cmplti      	r3, 500
 710:	0812      	bt      	0x734	// 734 <lmac_transceive_statics+0x734>
 712:	b874      	st.w      	r3, (r14, 0x50)
 714:	3300      	movi      	r3, 0
 716:	3205      	movi      	r2, 5
 718:	b875      	st.w      	r3, (r14, 0x54)
 71a:	9460      	ld.w      	r3, (r4, 0x0)
 71c:	b852      	st.w      	r2, (r14, 0x48)
 71e:	d84421d8 	ld.w      	r2, (r4, 0x760)
 722:	b853      	st.w      	r2, (r14, 0x4c)
 724:	d9832009 	ld.w      	r12, (r3, 0x24)
 728:	1a12      	addi      	r2, r14, 72
 72a:	0200      	lrw      	r0, 0x0	// a24 <lmac_transceive_statics+0xa24>
 72c:	3310      	movi      	r3, 16
 72e:	311b      	movi      	r1, 27
 730:	9000      	ld.w      	r0, (r0, 0x0)
 732:	7bf1      	jsr      	r12
 734:	d84421e7 	ld.w      	r2, (r4, 0x79c)
 738:	d82421db 	ld.w      	r1, (r4, 0x76c)
 73c:	0204      	lrw      	r0, 0x0	// a28 <hgprintf+0xa28>
 73e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 742:	3d41      	cmpnei      	r5, 1
 744:	08a6      	bt      	0x890	// 890 <lmac_transceive_statics+0x890>
 746:	d84421f7 	ld.w      	r2, (r4, 0x7dc)
 74a:	e90201c7 	bez      	r2, 0xad8	// ad8 <lmac_transceive_statics+0xad8>
 74e:	d82421f6 	ld.w      	r1, (r4, 0x7d8)
 752:	d86421f5 	ld.w      	r3, (r4, 0x7d4)
 756:	c4418041 	divs      	r1, r1, r2
 75a:	c4438042 	divs      	r2, r3, r2
 75e:	d80421dd 	ld.w      	r0, (r4, 0x774)
 762:	d86421dc 	ld.w      	r3, (r4, 0x770)
 766:	c540488d 	asri      	r13, r0, 10
 76a:	e906000a 	bez      	r6, 0x77e	// 77e <lmac_transceive_statics+0x77e>
 76e:	ea0c00fa 	movi      	r12, 250
 772:	5007      	asri      	r0, r0, 7
 774:	c44c482c 	lsli      	r12, r12, 2
 778:	7c30      	mult      	r0, r12
 77a:	c4c08026 	divu      	r6, r0, r6
 77e:	d8041403 	ld.h      	r0, (r4, 0x806)
 782:	b807      	st.w      	r0, (r14, 0x1c)
 784:	d8041402 	ld.h      	r0, (r4, 0x804)
 788:	b806      	st.w      	r0, (r14, 0x18)
 78a:	d80421e3 	ld.w      	r0, (r4, 0x78c)
 78e:	b805      	st.w      	r0, (r14, 0x14)
 790:	d80421e4 	ld.w      	r0, (r4, 0x790)
 794:	b804      	st.w      	r0, (r14, 0x10)
 796:	d80421e2 	ld.w      	r0, (r4, 0x788)
 79a:	ea0c0019 	movi      	r12, 25
 79e:	b803      	st.w      	r0, (r14, 0xc)
 7a0:	d80421de 	ld.w      	r0, (r4, 0x778)
 7a4:	c5808040 	divs      	r0, r0, r12
 7a8:	ddae2000 	st.w      	r13, (r14, 0x0)
 7ac:	b802      	st.w      	r0, (r14, 0x8)
 7ae:	b8c1      	st.w      	r6, (r14, 0x4)
 7b0:	0300      	lrw      	r0, 0x0	// a2c <lmac_transceive_statics+0xa2c>
 7b2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 7b6:	d844153f 	ld.h      	r2, (r4, 0xa7e)
 7ba:	d824153e 	ld.h      	r1, (r4, 0xa7c)
 7be:	0302      	lrw      	r0, 0x0	// a30 <hgprintf+0xa30>
 7c0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 7c4:	d86414ed 	ld.h      	r3, (r4, 0x9da)
 7c8:	b868      	st.w      	r3, (r14, 0x20)
 7ca:	d86414ec 	ld.h      	r3, (r4, 0x9d8)
 7ce:	b867      	st.w      	r3, (r14, 0x1c)
 7d0:	d86421fe 	ld.w      	r3, (r4, 0x7f8)
 7d4:	b866      	st.w      	r3, (r14, 0x18)
 7d6:	d8642209 	ld.w      	r3, (r4, 0x824)
 7da:	b865      	st.w      	r3, (r14, 0x14)
 7dc:	d864220a 	ld.w      	r3, (r4, 0x828)
 7e0:	b864      	st.w      	r3, (r14, 0x10)
 7e2:	d8642200 	ld.w      	r3, (r4, 0x800)
 7e6:	b863      	st.w      	r3, (r14, 0xc)
 7e8:	d864226d 	ld.w      	r3, (r4, 0x9b4)
 7ec:	b862      	st.w      	r3, (r14, 0x8)
 7ee:	d864229d 	ld.w      	r3, (r4, 0xa74)
 7f2:	b861      	st.w      	r3, (r14, 0x4)
 7f4:	d864229c 	ld.w      	r3, (r4, 0xa70)
 7f8:	b860      	st.w      	r3, (r14, 0x0)
 7fa:	d84421fc 	ld.w      	r2, (r4, 0x7f0)
 7fe:	d86421fd 	ld.w      	r3, (r4, 0x7f4)
 802:	d82421fb 	ld.w      	r1, (r4, 0x7ec)
 806:	ea88008c 	lrw      	r8, 0x0	// a34 <lmac_transceive_statics+0xa34>
 80a:	0313      	lrw      	r0, 0x0	// a38 <hgprintf+0xa38>
 80c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 810:	d8640361 	ld.b      	r3, (r4, 0x361)
 814:	e4632008 	andi      	r3, r3, 8
 818:	3b40      	cmpnei      	r3, 0
 81a:	d8240680 	ld.b      	r1, (r4, 0x680)
 81e:	d864219e 	ld.w      	r3, (r4, 0x678)
 822:	e4212001 	andi      	r1, r1, 1
 826:	0319      	lrw      	r0, 0x0	// a3c <lmac_transceive_statics+0xa3c>
 828:	c4080c20 	incf      	r0, r8, 0
 82c:	eb230055 	cmplti      	r3, 86
 830:	037b      	lrw      	r3, 0x0	// a40 <lmac_transceive_statics+0xa40>
 832:	c4680c40 	inct      	r3, r8, 0
 836:	d8e411b1 	ld.h      	r7, (r4, 0x362)
 83a:	3940      	cmpnei      	r1, 0
 83c:	035d      	lrw      	r2, 0x0	// a44 <lmac_transceive_statics+0xa44>
 83e:	c4480c20 	incf      	r2, r8, 0
 842:	d9844a4e 	ld.bs      	r12, (r4, 0xa4e)
 846:	d9a44a4d 	ld.bs      	r13, (r4, 0xa4d)
 84a:	d8c40690 	ld.b      	r6, (r4, 0x690)
 84e:	c4875567 	zext      	r7, r7, 11, 4
 852:	b846      	st.w      	r2, (r14, 0x18)
 854:	b865      	st.w      	r3, (r14, 0x14)
 856:	b803      	st.w      	r0, (r14, 0xc)
 858:	d82421f1 	ld.w      	r1, (r4, 0x7c4)
 85c:	b8e4      	st.w      	r7, (r14, 0x10)
 85e:	b8c2      	st.w      	r6, (r14, 0x8)
 860:	ddae2001 	st.w      	r13, (r14, 0x4)
 864:	dd8e2000 	st.w      	r12, (r14, 0x0)
 868:	d86421e6 	ld.w      	r3, (r4, 0x798)
 86c:	d84421e5 	ld.w      	r2, (r4, 0x794)
 870:	1316      	lrw      	r0, 0x0	// a48 <hgprintf+0xa48>
 872:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 876:	d82422ea 	ld.w      	r1, (r4, 0xba8)
 87a:	e9210006 	bnez      	r1, 0x886	// 886 <lmac_transceive_statics+0x886>
 87e:	d86422eb 	ld.w      	r3, (r4, 0xbac)
 882:	e9030007 	bez      	r3, 0x890	// 890 <lmac_transceive_statics+0x890>
 886:	d84422eb 	ld.w      	r2, (r4, 0xbac)
 88a:	1311      	lrw      	r0, 0x0	// a4c <hgprintf+0xa4c>
 88c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 890:	1310      	lrw      	r0, 0x0	// a50 <lhw_get_cca_observ+0xa50>
 892:	e0000000 	bsr      	0x0	// 0 <lhw_get_cca_observ>
 896:	e9200123 	bnez      	r0, 0xadc	// adc <lmac_transceive_statics+0xadc>
 89a:	d804142a 	ld.h      	r0, (r4, 0x854)
 89e:	b800      	st.w      	r0, (r14, 0x0)
 8a0:	d864142b 	ld.h      	r3, (r4, 0x856)
 8a4:	d8441428 	ld.h      	r2, (r4, 0x850)
 8a8:	d8241429 	ld.h      	r1, (r4, 0x852)
 8ac:	130a      	lrw      	r0, 0x0	// a54 <hgprintf+0xa54>
 8ae:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 8b2:	3d41      	cmpnei      	r5, 1
 8b4:	0829      	bt      	0x906	// 906 <lmac_transceive_statics+0x906>
 8b6:	d824142e 	ld.h      	r1, (r4, 0x85c)
 8ba:	b824      	st.w      	r1, (r14, 0x10)
 8bc:	d824142f 	ld.h      	r1, (r4, 0x85e)
 8c0:	b823      	st.w      	r1, (r14, 0xc)
 8c2:	d824142c 	ld.h      	r1, (r4, 0x858)
 8c6:	d8640361 	ld.b      	r3, (r4, 0x361)
 8ca:	b822      	st.w      	r1, (r14, 0x8)
 8cc:	d824142d 	ld.h      	r1, (r4, 0x85a)
 8d0:	e4632004 	andi      	r3, r3, 4
 8d4:	d8440860 	ld.b      	r2, (r4, 0x860)
 8d8:	b821      	st.w      	r1, (r14, 0x4)
 8da:	d8241426 	ld.h      	r1, (r4, 0x84c)
 8de:	3b40      	cmpnei      	r3, 0
 8e0:	b820      	st.w      	r1, (r14, 0x0)
 8e2:	e4422007 	andi      	r2, r2, 7
 8e6:	1216      	lrw      	r0, 0x0	// a3c <lmac_transceive_statics+0xa3c>
 8e8:	1233      	lrw      	r1, 0x0	// a34 <lmac_transceive_statics+0xa34>
 8ea:	c4200c40 	inct      	r1, r0, 0
 8ee:	d8641427 	ld.h      	r3, (r4, 0x84e)
 8f2:	121a      	lrw      	r0, 0x0	// a58 <lmac_transceive_statics+0xa58>
 8f4:	c4454022 	lsl      	r2, r5, r2
 8f8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 8fc:	d8240a6a 	ld.b      	r1, (r4, 0xa6a)
 900:	1217      	lrw      	r0, 0x0	// a5c <hgprintf+0xa5c>
 902:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 906:	d8040860 	ld.b      	r0, (r4, 0x860)
 90a:	e4002007 	andi      	r0, r0, 7
 90e:	e0000000 	bsr      	0x0	// 0 <lhw_start_cca_observ>
 912:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
 916:	e4632002 	andi      	r3, r3, 2
 91a:	e923001e 	bnez      	r3, 0x956	// 956 <lmac_transceive_statics+0x956>
 91e:	e905001c 	bez      	r5, 0x956	// 956 <lmac_transceive_statics+0x956>
 922:	d804219f 	ld.w      	r0, (r4, 0x67c)
 926:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 92a:	6e03      	mov      	r8, r0
 92c:	d80421b7 	ld.w      	r0, (r4, 0x6dc)
 930:	6dc7      	mov      	r7, r1
 932:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 936:	b802      	st.w      	r0, (r14, 0x8)
 938:	d80421b6 	ld.w      	r0, (r4, 0x6d8)
 93c:	d8c4219e 	ld.w      	r6, (r4, 0x678)
 940:	b823      	st.w      	r1, (r14, 0xc)
 942:	e0000000 	bsr      	0x0	// 0 <__extendsfdf2>
 946:	b800      	st.w      	r0, (r14, 0x0)
 948:	b821      	st.w      	r1, (r14, 0x4)
 94a:	6ca3      	mov      	r2, r8
 94c:	6cdf      	mov      	r3, r7
 94e:	6c5b      	mov      	r1, r6
 950:	1204      	lrw      	r0, 0x0	// a60 <lmac_transceive_statics+0xa60>
 952:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 956:	3286      	movi      	r2, 134
 958:	4241      	lsli      	r2, r2, 1
 95a:	3100      	movi      	r1, 0
 95c:	1202      	lrw      	r0, 0x0	// a64 <lmac_transceive_statics+0xa64>
 95e:	e0000000 	bsr      	0x0	// 0 <memset>
 962:	d9241504 	ld.h      	r9, (r4, 0xa08)
 966:	e4691000 	subi      	r3, r9, 1
 96a:	3b07      	cmphsi      	r3, 8
 96c:	ea080000 	movi      	r8, 0
 970:	dd04226d 	st.w      	r8, (r4, 0x9b4)
 974:	0807      	bt      	0x982	// 982 <lmac_transceive_statics+0x982>
 976:	30fa      	movi      	r0, 250
 978:	4001      	lsli      	r0, r0, 1
 97a:	7c24      	mult      	r0, r9
 97c:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
 980:	6e03      	mov      	r8, r0
 982:	3100      	movi      	r1, 0
 984:	2900      	subi      	r1, 1
 986:	1119      	lrw      	r0, 0x0	// a68 <lmac_transceive_statics+0xa68>
 988:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
 98c:	ea0b0000 	movi      	r11, 0
 990:	d8e4227e 	ld.w      	r7, (r4, 0x9f8)
 994:	1136      	lrw      	r1, 0x0	// a6c <lmac_transceive_statics+0xa6c>
 996:	6c9f      	mov      	r2, r7
 998:	6daf      	mov      	r6, r11
 99a:	b82d      	st.w      	r1, (r14, 0x34)
 99c:	644a      	cmpne      	r2, r1
 99e:	08a5      	bt      	0xae8	// ae8 <lmac_transceive_statics+0xae8>
 9a0:	ea0a0000 	movi      	r10, 0
 9a4:	61ac      	addu      	r6, r11
 9a6:	986d      	ld.w      	r3, (r14, 0x34)
 9a8:	64de      	cmpne      	r7, r3
 9aa:	08a7      	bt      	0xaf8	// af8 <lmac_transceive_statics+0xaf8>
 9ac:	5f1e      	addi      	r0, r7, 8
 9ae:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
 9b2:	eb480000 	cmpnei      	r8, 0
 9b6:	c52a0c40 	inct      	r9, r10, 0
 9ba:	e9060007 	bez      	r6, 0x9c8	// 9c8 <lmac_transceive_statics+0x9c8>
 9be:	3264      	movi      	r2, 100
 9c0:	c44b8423 	mult      	r3, r11, r2
 9c4:	c4c38046 	divs      	r6, r3, r6
 9c8:	7598      	zextb      	r6, r6
 9ca:	3364      	movi      	r3, 100
 9cc:	dcc40690 	st.b      	r6, (r4, 0x690)
 9d0:	5bd9      	subu      	r6, r3, r6
 9d2:	dcc40691 	st.b      	r6, (r4, 0x691)
 9d6:	e90800c5 	bez      	r8, 0xb60	// b60 <lmac_transceive_statics+0xb60>
 9da:	6c23      	mov      	r0, r8
 9dc:	3600      	movi      	r6, 0
 9de:	665a      	cmpne      	r6, r9
 9e0:	08d4      	bt      	0xb88	// b88 <lmac_transceive_statics+0xb88>
 9e2:	6c23      	mov      	r0, r8
 9e4:	e0000000 	bsr      	0x0	// 0 <_os_free>
 9e8:	e800fb65 	br      	0xb2	// b2 <lmac_transceive_statics+0xb2>
	...
 a70:	126a      	lrw      	r3, 0x0	// b98 <hgprintf+0xb98>
 a72:	60dc      	addu      	r3, r7
 a74:	6c2f      	mov      	r0, r11
 a76:	d843202a 	ld.w      	r2, (r3, 0xa8)
 a7a:	c5028021 	divu      	r1, r2, r8
 a7e:	c5018423 	mult      	r3, r1, r8
 a82:	608e      	subu      	r2, r3
 a84:	c5428022 	divu      	r2, r2, r10
 a88:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 a8c:	e5290000 	addi      	r9, r9, 1
 a90:	e800fcde 	br      	0x44c	// 44c <lmac_transceive_statics+0x44c>
 a94:	1261      	lrw      	r3, 0x0	// b98 <lmac_transceive_statics+0xb98>
 a96:	60dc      	addu      	r3, r7
 a98:	6c27      	mov      	r0, r9
 a9a:	d82340af 	ld.bs      	r1, (r3, 0xaf)
 a9e:	d86443e0 	ld.bs      	r3, (r4, 0x3e0)
 aa2:	604c      	addu      	r1, r3
 aa4:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 aa8:	e5080000 	addi      	r8, r8, 1
 aac:	e800fce2 	br      	0x470	// 470 <lmac_transceive_statics+0x470>
 ab0:	6c4f      	mov      	r1, r3
 ab2:	e800fcf4 	br      	0x49a	// 49a <lmac_transceive_statics+0x49a>
 ab6:	3300      	movi      	r3, 0
 ab8:	2b00      	subi      	r3, 1
 aba:	e800fcf8 	br      	0x4aa	// 4aa <lmac_transceive_statics+0x4aa>
 abe:	6dc7      	mov      	r7, r1
 ac0:	6c87      	mov      	r2, r1
 ac2:	e800fdc1 	br      	0x644	// 644 <lmac_transceive_statics+0x644>
 ac6:	d80411b6 	ld.h      	r0, (r4, 0x36c)
 aca:	c4a05520 	zext      	r0, r0, 9, 5
 ace:	e800fdc7 	br      	0x65c	// 65c <lmac_transceive_statics+0x65c>
 ad2:	6c1b      	mov      	r0, r6
 ad4:	e800fdfc 	br      	0x6cc	// 6cc <lmac_transceive_statics+0x6cc>
 ad8:	6c4b      	mov      	r1, r2
 ada:	0642      	br      	0x75e	// 75e <lmac_transceive_statics+0x75e>
 adc:	3d41      	cmpnei      	r5, 1
 ade:	0b14      	bt      	0x906	// 906 <lmac_transceive_statics+0x906>
 ae0:	d8240a6a 	ld.b      	r1, (r4, 0xa6a)
 ae4:	110e      	lrw      	r0, 0x0	// b9c <lmac_transceive_statics+0xb9c>
 ae6:	070e      	br      	0x902	// 902 <lmac_transceive_statics+0x902>
 ae8:	d8022073 	ld.w      	r0, (r2, 0x1cc)
 aec:	6180      	addu      	r6, r0
 aee:	d802207a 	ld.w      	r0, (r2, 0x1e8)
 af2:	62c0      	addu      	r11, r0
 af4:	9240      	ld.w      	r2, (r2, 0x0)
 af6:	0753      	br      	0x99c	// 99c <lmac_transceive_statics+0x99c>
 af8:	e9060030 	bez      	r6, 0xb58	// b58 <lmac_transceive_statics+0xb58>
 afc:	d8472073 	ld.w      	r2, (r7, 0x1cc)
 b00:	3364      	movi      	r3, 100
 b02:	7c8c      	mult      	r2, r3
 b04:	c4c28042 	divs      	r2, r2, r6
 b08:	dc4700b2 	st.b      	r2, (r7, 0xb2)
 b0c:	e9060028 	bez      	r6, 0xb5c	// b5c <lmac_transceive_statics+0xb5c>
 b10:	d847207a 	ld.w      	r2, (r7, 0x1e8)
 b14:	3364      	movi      	r3, 100
 b16:	7c8c      	mult      	r2, r3
 b18:	c4c28022 	divu      	r2, r2, r6
 b1c:	dc4700b3 	st.b      	r2, (r7, 0xb3)
 b20:	e908000e 	bez      	r8, 0xb3c	// b3c <lmac_transceive_statics+0xb3c>
 b24:	6668      	cmphs      	r10, r9
 b26:	080b      	bt      	0xb3c	// b3c <lmac_transceive_statics+0xb3c>
 b28:	32fa      	movi      	r2, 250
 b2a:	4241      	lsli      	r2, r2, 1
 b2c:	c44a8420 	mult      	r0, r10, r2
 b30:	6c5f      	mov      	r1, r7
 b32:	6020      	addu      	r0, r8
 b34:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
 b38:	e54a0000 	addi      	r10, r10, 1
 b3c:	321c      	movi      	r2, 28
 b3e:	3100      	movi      	r1, 0
 b40:	e40701c3 	addi      	r0, r7, 452
 b44:	e0000000 	bsr      	0x0	// 0 <memset>
 b48:	e40701df 	addi      	r0, r7, 480
 b4c:	3214      	movi      	r2, 20
 b4e:	3100      	movi      	r1, 0
 b50:	e0000000 	bsr      	0x0	// 0 <memset>
 b54:	97e0      	ld.w      	r7, (r7, 0x0)
 b56:	0728      	br      	0x9a6	// 9a6 <lmac_transceive_statics+0x9a6>
 b58:	6c9b      	mov      	r2, r6
 b5a:	07d7      	br      	0xb08	// b08 <lmac_transceive_statics+0xb08>
 b5c:	6c9b      	mov      	r2, r6
 b5e:	07df      	br      	0xb1c	// b1c <lmac_transceive_statics+0xb1c>
 b60:	e4691000 	subi      	r3, r9, 1
 b64:	3b07      	cmphsi      	r3, 8
 b66:	0807      	bt      	0xb74	// b74 <lmac_transceive_statics+0xb74>
 b68:	6c67      	mov      	r1, r9
 b6a:	100e      	lrw      	r0, 0x0	// ba0 <lmac_transceive_statics+0xba0>
 b6c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 b70:	e800faa1 	br      	0xb2	// b2 <lmac_transceive_statics+0xb2>
 b74:	e9290007 	bnez      	r9, 0xb82	// b82 <lmac_transceive_statics+0xb82>
 b78:	100b      	lrw      	r0, 0x0	// ba4 <hgprintf+0xba4>
 b7a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 b7e:	e800fa9a 	br      	0xb2	// b2 <lmac_transceive_statics+0xb2>
 b82:	6c67      	mov      	r1, r9
 b84:	1009      	lrw      	r0, 0x0	// ba8 <lmac_transceive_statics+0xba8>
 b86:	07f3      	br      	0xb6c	// b6c <lmac_transceive_statics+0xb6c>
 b88:	e4e001f3 	addi      	r7, r0, 500
 b8c:	6c57      	mov      	r1, r5
 b8e:	e0000000 	bsr      	0x0	// 0 <lmac_transceive_statics>
 b92:	2600      	addi      	r6, 1
 b94:	6c1f      	mov      	r0, r7
 b96:	0724      	br      	0x9de	// 9de <lmac_transceive_statics+0x9de>
	...

Disassembly of section .text.lmac_notify_channel_switch:

00000000 <lmac_notify_channel_switch>:
   0:	14d1      	push      	r4, r15
   2:	1421      	subi      	r14, r14, 4
   4:	6d03      	mov      	r4, r0
   6:	6c43      	mov      	r1, r0
   8:	100f      	lrw      	r0, 0x0	// 44 <lmac_notify_channel_switch+0x44>
   a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
   e:	3064      	movi      	r0, 100
  10:	c4048020 	divu      	r0, r4, r0
  14:	4870      	lsri      	r3, r0, 16
  16:	dc0e0000 	st.b      	r0, (r14, 0x0)
  1a:	c50055e0 	zext      	r0, r0, 15, 8
  1e:	dc0e0001 	st.b      	r0, (r14, 0x1)
  22:	dc6e0002 	st.b      	r3, (r14, 0x2)
  26:	4b68      	lsri      	r3, r3, 8
  28:	1008      	lrw      	r0, 0x0	// 48 <lmac_notify_channel_switch+0x48>
  2a:	dc6e0003 	st.b      	r3, (r14, 0x3)
  2e:	d9802009 	ld.w      	r12, (r0, 0x24)
  32:	e90c0006 	bez      	r12, 0x3e	// 3e <lmac_notify_channel_switch+0x3e>
  36:	3304      	movi      	r3, 4
  38:	6cbb      	mov      	r2, r14
  3a:	3102      	movi      	r1, 2
  3c:	7bf1      	jsr      	r12
  3e:	1401      	addi      	r14, r14, 4
  40:	1491      	pop      	r4, r15
	...

Disassembly of section .text.lmac_irq_handler:

00000000 <lmac_irq_handler>:
   0:	14d2      	push      	r4-r5, r15
   2:	0398      	lrw      	r4, 0x0	// 21c <lmac_irq_handler+0x21c>
   4:	9460      	ld.w      	r3, (r4, 0x0)
   6:	9372      	ld.w      	r3, (r3, 0x48)
   8:	e4632080 	andi      	r3, r3, 128
   c:	e9030004 	bez      	r3, 0x14	// 14 <lmac_irq_handler+0x14>
  10:	e0000000 	bsr      	0x0	// 0 <lmac_irq_ac_pd>
  14:	9460      	ld.w      	r3, (r4, 0x0)
  16:	9372      	ld.w      	r3, (r3, 0x48)
  18:	e4632020 	andi      	r3, r3, 32
  1c:	e9030004 	bez      	r3, 0x24	// 24 <lmac_irq_handler+0x24>
  20:	e0000000 	bsr      	0x0	// 0 <lmac_irq_bo_fns>
  24:	9460      	ld.w      	r3, (r4, 0x0)
  26:	9372      	ld.w      	r3, (r3, 0x48)
  28:	e4632004 	andi      	r3, r3, 4
  2c:	e9030004 	bez      	r3, 0x34	// 34 <lmac_irq_handler+0x34>
  30:	e0000000 	bsr      	0x0	// 0 <lmac_irq_tx_end>
  34:	9460      	ld.w      	r3, (r4, 0x0)
  36:	9352      	ld.w      	r2, (r3, 0x48)
  38:	e4422100 	andi      	r2, r2, 256
  3c:	e9020010 	bez      	r2, 0x5c	// 5c <lmac_irq_handler+0x5c>
  40:	9351      	ld.w      	r2, (r3, 0x44)
  42:	3a88      	bclri      	r2, 8
  44:	b351      	st.w      	r2, (r3, 0x44)
  46:	3280      	movi      	r2, 128
  48:	4241      	lsli      	r2, r2, 1
  4a:	b352      	st.w      	r2, (r3, 0x48)
  4c:	3000      	movi      	r0, 0
  4e:	1355      	lrw      	r2, 0x0	// 220 <lmac_irq_handler+0x220>
  50:	d82209dc 	ld.b      	r1, (r2, 0x9dc)
  54:	c4205c07 	ins      	r1, r0, 7, 7
  58:	dc2209dc 	st.b      	r1, (r2, 0x9dc)
  5c:	3280      	movi      	r2, 128
  5e:	9332      	ld.w      	r1, (r3, 0x48)
  60:	4246      	lsli      	r2, r2, 6
  62:	6848      	and      	r1, r2
  64:	e9010052 	bez      	r1, 0x108	// 108 <lmac_irq_handler+0x108>
  68:	b352      	st.w      	r2, (r3, 0x48)
  6a:	e0000000 	bsr      	0x0	// 0 <lmac_next_beacon_calc>
  6e:	e0000000 	bsr      	0x0	// 0 <lmac_beacon_timer_start>
  72:	136c      	lrw      	r3, 0x0	// 220 <lmac_irq_handler+0x220>
  74:	d84303e2 	ld.b      	r2, (r3, 0x3e2)
  78:	e4422008 	andi      	r2, r2, 8
  7c:	e9020046 	bez      	r2, 0x108	// 108 <lmac_irq_handler+0x108>
  80:	d8432267 	ld.w      	r2, (r3, 0x99c)
  84:	e922000b 	bnez      	r2, 0x9a	// 9a <lmac_irq_handler+0x9a>
  88:	d84314ef 	ld.h      	r2, (r3, 0x9de)
  8c:	c4c25501 	zext      	r1, r2, 8, 6
  90:	2106      	addi      	r1, 7
  92:	c4415c46 	ins      	r2, r1, 8, 6
  96:	dc4314ef 	st.h      	r2, (r3, 0x9de)
  9a:	3100      	movi      	r1, 0
  9c:	dc230555 	st.b      	r1, (r3, 0x555)
  a0:	d8230556 	ld.b      	r1, (r3, 0x556)
  a4:	d8432197 	ld.w      	r2, (r3, 0x65c)
  a8:	3901      	cmphsi      	r1, 2
  aa:	2200      	addi      	r2, 1
  ac:	dc432197 	st.w      	r2, (r3, 0x65c)
  b0:	0c09      	bf      	0xc2	// c2 <lmac_irq_handler+0xc2>
  b2:	c422802c 	divu      	r12, r2, r1
  b6:	5903      	subi      	r0, r1, 1
  b8:	7c70      	mult      	r1, r12
  ba:	6086      	subu      	r2, r1
  bc:	5849      	subu      	r2, r0, r2
  be:	dc430555 	st.b      	r2, (r3, 0x555)
  c2:	d84309e0 	ld.b      	r2, (r3, 0x9e0)
  c6:	e4422001 	andi      	r2, r2, 1
  ca:	e922001f 	bnez      	r2, 0x108	// 108 <lmac_irq_handler+0x108>
  ce:	d84309dd 	ld.b      	r2, (r3, 0x9dd)
  d2:	3101      	movi      	r1, 1
  d4:	c4415c60 	ins      	r2, r1, 3, 0
  d8:	dc4309dd 	st.b      	r2, (r3, 0x9dd)
  dc:	d843031a 	ld.b      	r2, (r3, 0x31a)
  e0:	6884      	and      	r2, r1
  e2:	e9020013 	bez      	r2, 0x108	// 108 <lmac_irq_handler+0x108>
  e6:	d843033c 	ld.b      	r2, (r3, 0x33c)
  ea:	e902000f 	bez      	r2, 0x108	// 108 <lmac_irq_handler+0x108>
  ee:	d84309df 	ld.b      	r2, (r3, 0x9df)
  f2:	c4415c61 	ins      	r2, r1, 4, 1
  f6:	dc4309df 	st.b      	r2, (r3, 0x9df)
  fa:	3102      	movi      	r1, 2
  fc:	d84309dd 	ld.b      	r2, (r3, 0x9dd)
 100:	c4415c60 	ins      	r2, r1, 3, 0
 104:	dc4309dd 	st.b      	r2, (r3, 0x9dd)
 108:	9460      	ld.w      	r3, (r4, 0x0)
 10a:	3280      	movi      	r2, 128
 10c:	9372      	ld.w      	r3, (r3, 0x48)
 10e:	4247      	lsli      	r2, r2, 7
 110:	68c8      	and      	r3, r2
 112:	e9030004 	bez      	r3, 0x11a	// 11a <lmac_irq_handler+0x11a>
 116:	e0000000 	bsr      	0x0	// 0 <lmac_irq_tx_tmo>
 11a:	9420      	ld.w      	r1, (r4, 0x0)
 11c:	3380      	movi      	r3, 128
 11e:	9152      	ld.w      	r2, (r1, 0x48)
 120:	4365      	lsli      	r3, r3, 5
 122:	688c      	and      	r2, r3
 124:	e9020009 	bez      	r2, 0x136	// 136 <lmac_irq_handler+0x136>
 128:	115f      	lrw      	r2, 0x0	// 224 <lmac_irq_handler+0x224>
 12a:	b172      	st.w      	r3, (r1, 0x48)
 12c:	9260      	ld.w      	r3, (r2, 0x0)
 12e:	2300      	addi      	r3, 1
 130:	3b04      	cmphsi      	r3, 5
 132:	082a      	bt      	0x186	// 186 <lmac_irq_handler+0x186>
 134:	b260      	st.w      	r3, (r2, 0x0)
 136:	9460      	ld.w      	r3, (r4, 0x0)
 138:	9372      	ld.w      	r3, (r3, 0x48)
 13a:	e4632400 	andi      	r3, r3, 1024
 13e:	e9030004 	bez      	r3, 0x146	// 146 <lmac_irq_handler+0x146>
 142:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_end>
 146:	9420      	ld.w      	r1, (r4, 0x0)
 148:	3380      	movi      	r3, 128
 14a:	9152      	ld.w      	r2, (r1, 0x48)
 14c:	436b      	lsli      	r3, r3, 11
 14e:	688c      	and      	r2, r3
 150:	e9020050 	bez      	r2, 0x1f0	// 1f0 <lmac_irq_handler+0x1f0>
 154:	11b3      	lrw      	r5, 0x0	// 220 <lmac_irq_handler+0x220>
 156:	b172      	st.w      	r3, (r1, 0x48)
 158:	e0000000 	bsr      	0x0	// 0 <lhw_abort_fsm>
 15c:	d84520ce 	ld.w      	r2, (r5, 0x338)
 160:	d86520d1 	ld.w      	r3, (r5, 0x344)
 164:	c4825762 	zext      	r2, r2, 27, 4
 168:	648e      	cmpne      	r3, r2
 16a:	0c40      	bf      	0x1ea	// 1ea <lmac_irq_handler+0x1ea>
 16c:	3200      	movi      	r2, 0
 16e:	d8250378 	ld.b      	r1, (r5, 0x378)
 172:	6c0b      	mov      	r0, r2
 174:	6441      	cmplt      	r0, r1
 176:	080d      	bt      	0x190	// 190 <lmac_irq_handler+0x190>
 178:	d865226d 	ld.w      	r3, (r5, 0x9b4)
 17c:	ec630008 	ori      	r3, r3, 8
 180:	dc65226d 	st.w      	r3, (r5, 0x9b4)
 184:	0433      	br      	0x1ea	// 1ea <lmac_irq_handler+0x1ea>
 186:	3300      	movi      	r3, 0
 188:	b260      	st.w      	r3, (r2, 0x0)
 18a:	e0000000 	bsr      	0x0	// 0 <lmac_irq_rx_subframe>
 18e:	07d4      	br      	0x136	// 136 <lmac_irq_handler+0x136>
 190:	2217      	addi      	r2, 24
 192:	ea8c0024 	lrw      	r12, 0x0	// 220 <lmac_irq_handler+0x220>
 196:	6308      	addu      	r12, r2
 198:	d98c202a 	ld.w      	r12, (r12, 0xa8)
 19c:	670e      	cmpne      	r3, r12
 19e:	0c03      	bf      	0x1a4	// 1a4 <lmac_irq_handler+0x1a4>
 1a0:	2000      	addi      	r0, 1
 1a2:	07e9      	br      	0x174	// 174 <lmac_irq_handler+0x174>
 1a4:	1121      	lrw      	r1, 0x0	// 228 <lmac_irq_handler+0x228>
 1a6:	dc05033c 	st.b      	r0, (r5, 0x33c)
 1aa:	e4432fff 	andi      	r2, r3, 4095
 1ae:	c482482c 	lsli      	r12, r2, 4
 1b2:	8943      	ld.h      	r2, (r1, 0x6)
 1b4:	e442200f 	andi      	r2, r2, 15
 1b8:	6cb0      	or      	r2, r12
 1ba:	a943      	st.h      	r2, (r1, 0x6)
 1bc:	ea0c0fff 	movi      	r12, 4095
 1c0:	6f32      	nor      	r12, r12
 1c2:	8944      	ld.h      	r2, (r1, 0x8)
 1c4:	68b0      	and      	r2, r12
 1c6:	c58356e3 	zext      	r3, r3, 23, 12
 1ca:	6cc8      	or      	r3, r2
 1cc:	a964      	st.h      	r3, (r1, 0x8)
 1ce:	7401      	zexth      	r0, r0
 1d0:	e0000000 	bsr      	0x0	// 0 <lmac_lo_table_kick>
 1d4:	d80520ce 	ld.w      	r0, (r5, 0x338)
 1d8:	c4805760 	zext      	r0, r0, 27, 4
 1dc:	e0000000 	bsr      	0x0	// 0 <lmac_irq_handler>
 1e0:	d86514ed 	ld.h      	r3, (r5, 0x9da)
 1e4:	2300      	addi      	r3, 1
 1e6:	dc6514ed 	st.h      	r3, (r5, 0x9da)
 1ea:	3034      	movi      	r0, 52
 1ec:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
 1f0:	9420      	ld.w      	r1, (r4, 0x0)
 1f2:	3380      	movi      	r3, 128
 1f4:	9152      	ld.w      	r2, (r1, 0x48)
 1f6:	4368      	lsli      	r3, r3, 8
 1f8:	688c      	and      	r2, r3
 1fa:	e9020006 	bez      	r2, 0x206	// 206 <lmac_irq_handler+0x206>
 1fe:	b172      	st.w      	r3, (r1, 0x48)
 200:	3000      	movi      	r0, 0
 202:	e0000000 	bsr      	0x0	// 0 <lmac_irq_handler>
 206:	9420      	ld.w      	r1, (r4, 0x0)
 208:	3380      	movi      	r3, 128
 20a:	9152      	ld.w      	r2, (r1, 0x48)
 20c:	436d      	lsli      	r3, r3, 13
 20e:	688c      	and      	r2, r3
 210:	e9020005 	bez      	r2, 0x21a	// 21a <lmac_irq_handler+0x21a>
 214:	b172      	st.w      	r3, (r1, 0x48)
 216:	e0000000 	bsr      	0x0	// 0 <lmac_irq_handler>
 21a:	1492      	pop      	r4-r5, r15
	...

Disassembly of section .text.lmac_notify_testmode_state:

00000000 <lmac_notify_testmode_state>:
   0:	14d0      	push      	r15
   2:	1421      	subi      	r14, r14, 4
   4:	dc0e0003 	st.b      	r0, (r14, 0x3)
   8:	1006      	lrw      	r0, 0x0	// 20 <lmac_notify_testmode_state+0x20>
   a:	d9802009 	ld.w      	r12, (r0, 0x24)
   e:	e90c0007 	bez      	r12, 0x1c	// 1c <lmac_notify_testmode_state+0x1c>
  12:	3300      	movi      	r3, 0
  14:	e44e0002 	addi      	r2, r14, 3
  18:	3111      	movi      	r1, 17
  1a:	7bf1      	jsr      	r12
  1c:	1401      	addi      	r14, r14, 4
  1e:	1490      	pop      	r15
  20:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_ioctl:

00000000 <lmac_ioctl>:
   0:	14d0      	push      	r15
   2:	d9802012 	ld.w      	r12, (r0, 0x48)
   6:	e90c0004 	bez      	r12, 0xe	// e <lmac_ioctl+0xe>
   a:	7bf1      	jsr      	r12
   c:	1490      	pop      	r15
   e:	3000      	movi      	r0, 0
  10:	2800      	subi      	r0, 1
  12:	07fd      	br      	0xc	// c <lmac_ioctl+0xc>

Disassembly of section .text.lmac_ah_init:

00000000 <lmac_ah_init>:
   0:	14d5      	push      	r4-r8, r15
   2:	007c      	lrw      	r3, 0x40026000	// 38c <lmac_ah_init+0x38c>
   4:	009c      	lrw      	r4, 0xe000e100	// 390 <lmac_ah_init+0x390>
   6:	9342      	ld.w      	r2, (r3, 0x8)
   8:	3a94      	bclri      	r2, 20
   a:	b342      	st.w      	r2, (r3, 0x8)
   c:	9342      	ld.w      	r2, (r3, 0x8)
   e:	3ab4      	bseti      	r2, 20
  10:	b342      	st.w      	r2, (r3, 0x8)
  12:	3380      	movi      	r3, 128
  14:	4370      	lsli      	r3, r3, 16
  16:	dc642020 	st.w      	r3, (r4, 0x80)
  1a:	3380      	movi      	r3, 128
  1c:	4372      	lsli      	r3, r3, 18
  1e:	dc642020 	st.w      	r3, (r4, 0x80)
  22:	6e03      	mov      	r8, r0
  24:	0163      	lrw      	r3, 0x0	// 394 <lmac_ah_init+0x394>
  26:	01c2      	lrw      	r6, 0x0	// 398 <lmac_ah_init+0x398>
  28:	01a2      	lrw      	r5, 0x0	// 39c <lmac_ah_init+0x39c>
  2a:	9340      	ld.w      	r2, (r3, 0x0)
  2c:	3300      	movi      	r3, 0
  2e:	2b00      	subi      	r3, 1
  30:	b272      	st.w      	r3, (r2, 0x48)
  32:	e0000000 	bsr      	0x0	// 0 <lf_timer_init>
  36:	3380      	movi      	r3, 128
  38:	4368      	lsli      	r3, r3, 8
  3a:	3250      	movi      	r2, 80
  3c:	3100      	movi      	r1, 0
  3e:	dc642020 	st.w      	r3, (r4, 0x80)
  42:	6c1b      	mov      	r0, r6
  44:	e0000000 	bsr      	0x0	// 0 <memset>
  48:	3348      	movi      	r3, 72
  4a:	a668      	st.b      	r3, (r6, 0x8)
  4c:	3320      	movi      	r3, 32
  4e:	a669      	st.b      	r3, (r6, 0x9)
  50:	016b      	lrw      	r3, 0x0	// 3a0 <lmac_ah_init+0x3a0>
  52:	b663      	st.w      	r3, (r6, 0xc)
  54:	016b      	lrw      	r3, 0x0	// 3a4 <lmac_ah_init+0x3a4>
  56:	b664      	st.w      	r3, (r6, 0x10)
  58:	016b      	lrw      	r3, 0x0	// 3a8 <lmac_ah_init+0x3a8>
  5a:	b665      	st.w      	r3, (r6, 0x14)
  5c:	016b      	lrw      	r3, 0x0	// 3ac <lmac_ah_init+0x3ac>
  5e:	b666      	st.w      	r3, (r6, 0x18)
  60:	016b      	lrw      	r3, 0x0	// 3b0 <lmac_ah_init+0x3b0>
  62:	b66b      	st.w      	r3, (r6, 0x2c)
  64:	016b      	lrw      	r3, 0x0	// 3b4 <lmac_ah_init+0x3b4>
  66:	b66c      	st.w      	r3, (r6, 0x30)
  68:	016b      	lrw      	r3, 0x0	// 3b8 <lmac_ah_init+0x3b8>
  6a:	b66d      	st.w      	r3, (r6, 0x34)
  6c:	016b      	lrw      	r3, 0x0	// 3bc <lmac_ah_init+0x3bc>
  6e:	b66e      	st.w      	r3, (r6, 0x38)
  70:	016b      	lrw      	r3, 0x0	// 3c0 <lmac_ah_init+0x3c0>
  72:	b66f      	st.w      	r3, (r6, 0x3c)
  74:	016b      	lrw      	r3, 0x0	// 3c4 <lmac_ah_init+0x3c4>
  76:	b670      	st.w      	r3, (r6, 0x40)
  78:	016b      	lrw      	r3, 0x0	// 3c8 <lmac_ah_init+0x3c8>
  7a:	b66a      	st.w      	r3, (r6, 0x28)
  7c:	016b      	lrw      	r3, 0x0	// 3cc <lmac_ah_init+0x3cc>
  7e:	b671      	st.w      	r3, (r6, 0x44)
  80:	016b      	lrw      	r3, 0x0	// 3d0 <lmac_ah_init+0x3d0>
  82:	b672      	st.w      	r3, (r6, 0x48)
  84:	3301      	movi      	r3, 1
  86:	a66a      	st.b      	r3, (r6, 0xa)
  88:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_bios_id>
  8c:	a500      	st.b      	r0, (r5, 0x0)
  8e:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_xtal_id>
  92:	a501      	st.b      	r0, (r5, 0x1)
  94:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_dcn>
  98:	a508      	st.b      	r0, (r5, 0x8)
  9a:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_crc_check>
  9e:	a502      	st.b      	r0, (r5, 0x2)
  a0:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_module_crc>
  a4:	e90001c6 	bez      	r0, 0x430	// 430 <lmac_ah_init+0x430>
  a8:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_test_temp>
  ac:	6c43      	mov      	r1, r0
  ae:	a509      	st.b      	r0, (r5, 0x9)
  b0:	0116      	lrw      	r0, 0x0	// 3d4 <lmac_ah_init+0x3d4>
  b2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  b6:	d8654002 	ld.bs      	r3, (r5, 0x2)
  ba:	e92301c1 	bnez      	r3, 0x43c	// 43c <lmac_ah_init+0x43c>
  be:	8560      	ld.b      	r3, (r5, 0x0)
  c0:	3b02      	cmphsi      	r3, 3
  c2:	0dbd      	bf      	0x43c	// 43c <lmac_ah_init+0x43c>
  c4:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_vref>
  c8:	a504      	st.b      	r0, (r5, 0x4)
  ca:	e0000000 	bsr      	0x0	// 0 <pmu_vref_vol_set_sec>
  ce:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_xo_vbg>
  d2:	e0000000 	bsr      	0x0	// 0 <pmu_xo_vbg_set_sec>
  d6:	8568      	ld.b      	r3, (r5, 0x8)
  d8:	e92301b5 	bnez      	r3, 0x442	// 442 <lmac_ah_init+0x442>
  dc:	3007      	movi      	r0, 7
  de:	e0000000 	bsr      	0x0	// 0 <pmu_vdd_vol_set_sec>
  e2:	3314      	movi      	r3, 20
  e4:	3214      	movi      	r2, 20
  e6:	6c63      	mov      	r1, r8
  e8:	0203      	lrw      	r0, 0x0	// 3d8 <lmac_ah_init+0x3d8>
  ea:	a566      	st.b      	r3, (r5, 0x6)
  ec:	e0000000 	bsr      	0x0	// 0 <memcpy>
  f0:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_init>
  f4:	e0000000 	bsr      	0x0	// 0 <lmac_rc_init>
  f8:	e0000000 	bsr      	0x0	// 0 <ah_wphy_open>
  fc:	e0000000 	bsr      	0x0	// 0 <ah_wphy_enable>
 100:	e0000000 	bsr      	0x0	// 0 <ah_wphy_auto_sig_err_rst_enable>
 104:	e0000000 	bsr      	0x0	// 0 <ah_init_dbgpath_device>
 108:	e0000000 	bsr      	0x0	// 0 <ah_rf_open>
 10c:	8567      	ld.b      	r3, (r5, 0x7)
 10e:	3b41      	cmpnei      	r3, 1
 110:	09a6      	bt      	0x45c	// 45c <lmac_ah_init+0x45c>
 112:	3308      	movi      	r3, 8
 114:	ea021e96 	movi      	r2, 7830
 118:	ea011da6 	movi      	r1, 7590
 11c:	0300      	lrw      	r0, 0x0	// 398 <lmac_cfg_set_freq_range+0x398>
 11e:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_set_freq_range>
 122:	3001      	movi      	r0, 1
 124:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_table_ctrl>
 128:	d8682002 	ld.w      	r3, (r8, 0x8)
 12c:	0293      	lrw      	r4, 0x0	// 3dc <lmac_ah_init+0x3dc>
 12e:	e903002e 	bez      	r3, 0x18a	// 18a <lmac_ah_init+0x18a>
 132:	d8682003 	ld.w      	r3, (r8, 0xc)
 136:	e903002a 	bez      	r3, 0x18a	// 18a <lmac_ah_init+0x18a>
 13a:	d8642236 	ld.w      	r3, (r4, 0x8d8)
 13e:	dc642279 	st.w      	r3, (r4, 0x9e4)
 142:	d8642237 	ld.w      	r3, (r4, 0x8dc)
 146:	dc64227a 	st.w      	r3, (r4, 0x9e8)
 14a:	e0000000 	bsr      	0x0	// 0 <ah_tdma_abort>
 14e:	d824227a 	ld.w      	r1, (r4, 0x9e8)
 152:	d8042279 	ld.w      	r0, (r4, 0x9e4)
 156:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_buff>
 15a:	3101      	movi      	r1, 1
 15c:	6c07      	mov      	r0, r1
 15e:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_mode>
 162:	3004      	movi      	r0, 4
 164:	e0000000 	bsr      	0x0	// 0 <ah_set_dbgpath_device_path_mode>
 168:	3000      	movi      	r0, 0
 16a:	e0000000 	bsr      	0x0	// 0 <ah_config_dbgpath_device_dmaend_cond>
 16e:	d864227a 	ld.w      	r3, (r4, 0x9e8)
 172:	4b1f      	lsri      	r0, r3, 31
 174:	600c      	addu      	r0, r3
 176:	5001      	asri      	r0, r0, 1
 178:	e0000000 	bsr      	0x0	// 0 <ah_tdma_set_trig_len>
 17c:	d86409f4 	ld.b      	r3, (r4, 0x9f4)
 180:	3201      	movi      	r2, 1
 182:	c4625c00 	ins      	r3, r2, 0, 0
 186:	dc6409f4 	st.b      	r3, (r4, 0x9f4)
 18a:	d80411b6 	ld.h      	r0, (r4, 0x36c)
 18e:	c4a05520 	zext      	r0, r0, 9, 5
 192:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_tx_pwr>
 196:	3001      	movi      	r0, 1
 198:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_gain_idx_src>
 19c:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_rx_filter_auto>
 1a0:	3108      	movi      	r1, 8
 1a2:	6c07      	mov      	r0, r1
 1a4:	3210      	movi      	r2, 16
 1a6:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_hw_rx_dcoc>
 1aa:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_rx_dcoc_hw_trig_en>
 1ae:	3303      	movi      	r3, 3
 1b0:	3003      	movi      	r0, 3
 1b2:	dc640309 	st.b      	r3, (r4, 0x309)
 1b6:	e0000000 	bsr      	0x0	// 0 <ah_wphy_pri_channel_cfg>
 1ba:	d8040308 	ld.b      	r0, (r4, 0x308)
 1be:	e0000000 	bsr      	0x0	// 0 <ah_wphy_bw_cfg>
 1c2:	8567      	ld.b      	r3, (r5, 0x7)
 1c4:	3b41      	cmpnei      	r3, 1
 1c6:	0969      	bt      	0x498	// 498 <lmac_ah_init+0x498>
 1c8:	3000      	movi      	r0, 0
 1ca:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_rx_conv_gain>
 1ce:	6dc3      	mov      	r7, r0
 1d0:	e9000008 	bez      	r0, 0x1e0	// 1e0 <lmac_ah_init+0x1e0>
 1d4:	e0000000 	bsr      	0x0	// 0 <ah_wphy_rx_conv_gain_config>
 1d8:	6c5f      	mov      	r1, r7
 1da:	031d      	lrw      	r0, 0x0	// 3e0 <lmac_ah_init+0x3e0>
 1dc:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 1e0:	3700      	movi      	r7, 0
 1e2:	741c      	zextb      	r0, r7
 1e4:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_get_tx_digi_gain>
 1e8:	5f7c      	addu      	r3, r7, r7
 1ea:	135d      	lrw      	r2, 0x0	// 3dc <lmac_ah_init+0x3dc>
 1ec:	2700      	addi      	r7, 1
 1ee:	60c8      	addu      	r3, r2
 1f0:	3f46      	cmpnei      	r7, 6
 1f2:	dc031341 	st.h      	r0, (r3, 0x682)
 1f6:	0bf6      	bt      	0x1e2	// 1e2 <lmac_ah_init+0x1e2>
 1f8:	ea038003 	movi      	r3, 32771
 1fc:	c5e34903 	rotli      	r3, r3, 15
 200:	3700      	movi      	r7, 0
 202:	936a      	ld.w      	r3, (r3, 0x28)
 204:	c66356e3 	zext      	r3, r3, 23, 19
 208:	6c5f      	mov      	r1, r7
 20a:	1304      	lrw      	r0, 0x0	// 398 <lmac_ah_init+0x398>
 20c:	dc64068f 	st.b      	r3, (r4, 0x68f)
 210:	e0000000 	bsr      	0x0	// 0 <lmac_set_bgrssi>
 214:	1334      	lrw      	r1, 0x0	// 3e4 <lmac_ah_init+0x3e4>
 216:	5917      	subi      	r0, r1, 6
 218:	e0000000 	bsr      	0x0	// 0 <ah_wphy_rx_gain_para_get>
 21c:	1333      	lrw      	r1, 0x0	// 3e8 <lmac_ah_init+0x3e8>
 21e:	6c1f      	mov      	r0, r7
 220:	e0000000 	bsr      	0x0	// 0 <ah_ce_init>
 224:	d8240316 	ld.b      	r1, (r4, 0x316)
 228:	d8040308 	ld.b      	r0, (r4, 0x308)
 22c:	e0000000 	bsr      	0x0	// 0 <lmac_hw_init>
 230:	e0000000 	bsr      	0x0	// 0 <lmac_tx_init>
 234:	6c23      	mov      	r0, r8
 236:	e0000000 	bsr      	0x0	// 0 <lmac_rx_init>
 23a:	e0000000 	bsr      	0x0	// 0 <lmac_test_init>
 23e:	e0000000 	bsr      	0x0	// 0 <lmac_dsleep_init>
 242:	132b      	lrw      	r1, 0x0	// 3ec <lmac_ah_init+0x3ec>
 244:	1346      	lrw      	r2, 0x0	// 3dc <lmac_ah_init+0x3dc>
 246:	3017      	movi      	r0, 23
 248:	e0000000 	bsr      	0x0	// 0 <request_irq>
 24c:	1251      	lrw      	r2, 0xe000e100	// 390 <lmac_ah_init+0x390>
 24e:	3380      	movi      	r3, 128
 250:	4370      	lsli      	r3, r3, 16
 252:	b260      	st.w      	r3, (r2, 0x0)
 254:	e0000000 	bsr      	0x0	// 0 <lmac_ah_init>
 258:	6c5f      	mov      	r1, r7
 25a:	1306      	lrw      	r0, 0x0	// 3f0 <lmac_ah_init+0x3f0>
 25c:	e0000000 	bsr      	0x0	// 0 <os_sema_init>
 260:	3340      	movi      	r3, 64
 262:	dc6422a2 	st.w      	r3, (r4, 0xa88)
 266:	dce422a0 	st.w      	r7, (r4, 0xa80)
 26a:	dce422a1 	st.w      	r7, (r4, 0xa84)
 26e:	1342      	lrw      	r2, 0x0	// 3f4 <lmac_ah_init+0x3f4>
 270:	127b      	lrw      	r3, 0x0	// 3dc <lmac_ah_init+0x3dc>
 272:	e423099f 	addi      	r1, r3, 2464
 276:	1301      	lrw      	r0, 0x0	// 3f8 <os_task_init+0x3f8>
 278:	e0000000 	bsr      	0x0	// 0 <os_task_init>
 27c:	3180      	movi      	r1, 128
 27e:	4123      	lsli      	r1, r1, 3
 280:	121f      	lrw      	r0, 0x0	// 3fc <lmac_ah_init+0x3fc>
 282:	e0000000 	bsr      	0x0	// 0 <os_task_set_stacksize>
 286:	3130      	movi      	r1, 48
 288:	121d      	lrw      	r0, 0x0	// 3fc <lmac_ah_init+0x3fc>
 28a:	e0000000 	bsr      	0x0	// 0 <os_task_set_priority>
 28e:	121c      	lrw      	r0, 0x0	// 3fc <os_task_run+0x3fc>
 290:	e0000000 	bsr      	0x0	// 0 <os_task_run>
 294:	6c5f      	mov      	r1, r7
 296:	121b      	lrw      	r0, 0x0	// 400 <lmac_ah_init+0x400>
 298:	e0000000 	bsr      	0x0	// 0 <os_sema_init>
 29c:	1270      	lrw      	r3, 0x0	// 3dc <lmac_ah_init+0x3dc>
 29e:	e42309c3 	addi      	r1, r3, 2500
 2a2:	1259      	lrw      	r2, 0x0	// 404 <lmac_ah_init+0x404>
 2a4:	1219      	lrw      	r0, 0x0	// 408 <lmac_ah_init+0x408>
 2a6:	e0000000 	bsr      	0x0	// 0 <os_task_init>
 2aa:	3180      	movi      	r1, 128
 2ac:	4122      	lsli      	r1, r1, 2
 2ae:	1218      	lrw      	r0, 0x0	// 40c <lmac_ah_init+0x40c>
 2b0:	e0000000 	bsr      	0x0	// 0 <os_task_set_stacksize>
 2b4:	3110      	movi      	r1, 16
 2b6:	1216      	lrw      	r0, 0x0	// 40c <lmac_ah_init+0x40c>
 2b8:	e0000000 	bsr      	0x0	// 0 <os_task_set_priority>
 2bc:	1214      	lrw      	r0, 0x0	// 40c <os_task_run+0x40c>
 2be:	e0000000 	bsr      	0x0	// 0 <os_task_run>
 2c2:	1274      	lrw      	r3, 0x0	// 410 <lmac_ah_init+0x410>
 2c4:	3201      	movi      	r2, 1
 2c6:	e403106f 	subi      	r0, r3, 112
 2ca:	1233      	lrw      	r1, 0x0	// 414 <os_timer_init+0x414>
 2cc:	e0000000 	bsr      	0x0	// 0 <os_timer_init>
 2d0:	d82420e5 	ld.w      	r1, (r4, 0x394)
 2d4:	1211      	lrw      	r0, 0x0	// 418 <os_timer_start+0x418>
 2d6:	e0000000 	bsr      	0x0	// 0 <os_timer_start>
 2da:	126e      	lrw      	r3, 0x0	// 410 <lmac_ah_init+0x410>
 2dc:	6c9f      	mov      	r2, r7
 2de:	e4031053 	subi      	r0, r3, 84
 2e2:	122f      	lrw      	r1, 0x0	// 41c <os_timer_init+0x41c>
 2e4:	e0000000 	bsr      	0x0	// 0 <os_timer_init>
 2e8:	8520      	ld.b      	r1, (r5, 0x0)
 2ea:	120e      	lrw      	r0, 0x0	// 420 <lmac_ah_init+0x420>
 2ec:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2f0:	8521      	ld.b      	r1, (r5, 0x1)
 2f2:	120d      	lrw      	r0, 0x0	// 424 <lmac_ah_init+0x424>
 2f4:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2f8:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_smt_dat>
 2fc:	6c43      	mov      	r1, r0
 2fe:	e92000d5 	bnez      	r0, 0x4a8	// 4a8 <lmac_ah_init+0x4a8>
 302:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_sip_ind>
 306:	e92000cf 	bnez      	r0, 0x4a4	// 4a4 <lmac_ah_init+0x4a4>
 30a:	1208      	lrw      	r0, 0x0	// 428 <hgprintf+0x428>
 30c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 310:	e0000000 	bsr      	0x0	// 0 <dsleep_cfg_get>
 314:	dc042233 	st.w      	r0, (r4, 0x8cc)
 318:	e9000016 	bez      	r0, 0x344	// 344 <lmac_ah_init+0x344>
 31c:	d860025b 	ld.b      	r3, (r0, 0x25b)
 320:	e4632003 	andi      	r3, r3, 3
 324:	3b42      	cmpnei      	r3, 2
 326:	0807      	bt      	0x334	// 334 <lmac_ah_init+0x334>
 328:	3005      	movi      	r0, 5
 32a:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13c_vol_set_sec>
 32e:	3005      	movi      	r0, 5
 330:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13b_vol_set_sec>
 334:	d8642233 	ld.w      	r3, (r4, 0x8cc)
 338:	d8634a52 	ld.bs      	r3, (r3, 0xa52)
 33c:	e9030004 	bez      	r3, 0x344	// 344 <lmac_ah_init+0x344>
 340:	dc64031e 	st.b      	r3, (r4, 0x31e)
 344:	3101      	movi      	r1, 1
 346:	3020      	movi      	r0, 32
 348:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
 34c:	3100      	movi      	r1, 0
 34e:	3020      	movi      	r0, 32
 350:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
 354:	3000      	movi      	r0, 0
 356:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
 35a:	d8640875 	ld.b      	r3, (r4, 0x875)
 35e:	e4632004 	andi      	r3, r3, 4
 362:	b4c0      	st.w      	r6, (r4, 0x0)
 364:	e903000b 	bez      	r3, 0x37a	// 37a <lmac_ah_init+0x37a>
 368:	1111      	lrw      	r0, 0x0	// 42c <hgprintf+0x42c>
 36a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 36e:	3300      	movi      	r3, 0
 370:	321f      	movi      	r2, 31
 372:	312a      	movi      	r1, 42
 374:	9400      	ld.w      	r0, (r4, 0x0)
 376:	e0000000 	bsr      	0x0	// 0 <lmac_ah_init>
 37a:	3001      	movi      	r0, 1
 37c:	e0000000 	bsr      	0x0	// 0 <skbpool_freesize>
 380:	480b      	lsri      	r0, r0, 11
 382:	dc0422ec 	st.w      	r0, (r4, 0xbb0)
 386:	9400      	ld.w      	r0, (r4, 0x0)
 388:	1495      	pop      	r4-r8, r15
 38a:	0000      	.short	0x0000
 38c:	40026000 	.long	0x40026000
 390:	e000e100 	.long	0xe000e100
	...
 430:	331e      	movi      	r3, 30
 432:	1103      	lrw      	r0, 0x0	// 4bc <lmac_ah_init+0x4bc>
 434:	a569      	st.b      	r3, (r5, 0x9)
 436:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 43a:	063e      	br      	0xb6	// b6 <lmac_ah_init+0xb6>
 43c:	3304      	movi      	r3, 4
 43e:	a564      	st.b      	r3, (r5, 0x4)
 440:	064b      	br      	0xd6	// d6 <lmac_ah_init+0xd6>
 442:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_vdd13_trim_valid>
 446:	3841      	cmpnei      	r0, 1
 448:	0a4d      	bt      	0xe2	// e2 <lmac_ah_init+0xe2>
 44a:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_vdd13b_trim>
 44e:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13b_vol_set_sec>
 452:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_vdd13c_trim>
 456:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13c_vol_set_sec>
 45a:	0644      	br      	0xe2	// e2 <lmac_ah_init+0xe2>
 45c:	3b45      	cmpnei      	r3, 5
 45e:	0807      	bt      	0x46c	// 46c <lmac_ah_init+0x46c>
 460:	3308      	movi      	r3, 8
 462:	ea021fcc 	movi      	r2, 8140
 466:	ea011f7c 	movi      	r1, 8060
 46a:	0659      	br      	0x11c	// 11c <lmac_ah_init+0x11c>
 46c:	3b50      	cmpnei      	r3, 16
 46e:	0807      	bt      	0x47c	// 47c <lmac_ah_init+0x47c>
 470:	3302      	movi      	r3, 2
 472:	ea022166 	movi      	r2, 8550
 476:	ea012102 	movi      	r1, 8450
 47a:	0651      	br      	0x11c	// 11c <lmac_ah_init+0x11c>
 47c:	3b43      	cmpnei      	r3, 3
 47e:	0807      	bt      	0x48c	// 48c <lmac_ah_init+0x48c>
 480:	3302      	movi      	r3, 2
 482:	ea0221de 	movi      	r2, 8670
 486:	ea0121d4 	movi      	r1, 8660
 48a:	0649      	br      	0x11c	// 11c <lmac_ah_init+0x11c>
 48c:	3308      	movi      	r3, 8
 48e:	ea022418 	movi      	r2, 9240
 492:	ea012378 	movi      	r1, 9080
 496:	0643      	br      	0x11c	// 11c <lmac_ah_init+0x11c>
 498:	3b43      	cmpnei      	r3, 3
 49a:	0803      	bt      	0x4a0	// 4a0 <lmac_ah_init+0x4a0>
 49c:	3001      	movi      	r0, 1
 49e:	0696      	br      	0x1ca	// 1ca <lmac_ah_init+0x1ca>
 4a0:	3002      	movi      	r0, 2
 4a2:	0694      	br      	0x1ca	// 1ca <lmac_ah_init+0x1ca>
 4a4:	1007      	lrw      	r0, 0x0	// 4c0 <lmac_ah_init+0x4c0>
 4a6:	0733      	br      	0x30c	// 30c <lmac_ah_init+0x30c>
 4a8:	1067      	lrw      	r3, 0x5b8d7f	// 4c4 <lmac_ah_init+0x4c4>
 4aa:	640c      	cmphs      	r3, r0
 4ac:	0c05      	bf      	0x4b6	// 4b6 <lmac_ah_init+0x4b6>
 4ae:	1007      	lrw      	r0, 0x0	// 4c8 <lmac_ah_init+0x4c8>
 4b0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 4b4:	072e      	br      	0x310	// 310 <lmac_ah_init+0x310>
 4b6:	1006      	lrw      	r0, 0x0	// 4cc <lmac_ah_init+0x4cc>
 4b8:	07fc      	br      	0x4b0	// 4b0 <lmac_ah_init+0x4b0>
	...
 4c2:	0000      	.short	0x0000
 4c4:	005b8d7f 	.long	0x005b8d7f
	...

Disassembly of section .text.lmac_set_chan_list:

00000000 <lmac_set_chan_list>:
   0:	14d0      	push      	r15
   2:	906a      	ld.w      	r3, (r0, 0x28)
   4:	e9030004 	bez      	r3, 0xc	// c <lmac_set_chan_list+0xc>
   8:	7bcd      	jsr      	r3
   a:	1490      	pop      	r15
   c:	3000      	movi      	r0, 0
   e:	2800      	subi      	r0, 1
  10:	07fd      	br      	0xa	// a <lmac_set_chan_list+0xa>

Disassembly of section .text.lmac_start_acs:

00000000 <lmac_start_acs>:
   0:	14d0      	push      	r15
   2:	906d      	ld.w      	r3, (r0, 0x34)
   4:	e9030004 	bez      	r3, 0xc	// c <lmac_start_acs+0xc>
   8:	7bcd      	jsr      	r3
   a:	1490      	pop      	r15
   c:	3000      	movi      	r0, 0
   e:	2800      	subi      	r0, 1
  10:	07fd      	br      	0xa	// a <lmac_start_acs+0xa>
