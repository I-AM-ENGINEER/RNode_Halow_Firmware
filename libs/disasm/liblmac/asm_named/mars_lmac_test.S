
libs\obj\liblmac\mars_lmac_test.o:     file format elf32-csky-little


Disassembly of section .text.lo_freq_valid_check:

00000000 <lo_freq_valid_check>: // arg_bytes: 4
   0:	1070      	lrw	r3, 0xfff4dc70	// regs: r3=0xfff4dc70
   2:	584c      	addu	r2, r0, r3	// regs: r2=(<arg0> + 0xfff4dc70)
   4:	ea03c350 	movi	r3, 50000	// regs: r3=0xc350
   8:	c4434903 	rotli	r3, r3, 2	// regs: r3=rotl(0xc350, 0x2)
   c:	648c      	cmphs	r3, r2
   e:	0c15      	bf	0x38	// if (!T) goto loc_38;
  10:	106d      	lrw	r3, 0x0	// regs: r3=0x0
  12:	8367      	ld.b	r3, (r3, 0x7)	// regs: r3=*(0x7)
  14:	e46320fb 	andi	r3, r3, 251	// regs: r3=(*(0x7) & 0xfb)
  18:	3b41      	cmpnei	r3, 1
  1a:	3300      	movi	r3, 0	// regs: r3=0x0
  1c:	0809      	bt	0x2e	// if (r3 != 0x1) goto loc_2e;
  1e:	ea02cd14 	movi	r2, 52500	// regs: r2=0xcd14
  22:	c4824902 	rotli	r2, r2, 4	// regs: r2=rotl(0xcd14, 0x4)
  26:	6408      	cmphs	r2, r0
  28:	6403      	mvcv	r0	// regs: r0=<cond>
loc_2a:
  2a:	5b01      	subu	r0, r3, r0	// regs: r0=(0x0 - <cond>)
loc_2c:
  2c:	783c      	jmp	r15	// return;
loc_2e:
  2e:	1047      	lrw	r2, 0xcd13f	// regs: r2=0xcd13f
  30:	6408      	cmphs	r2, r0
  32:	c4000500 	mvc	r0	// regs: r0=<cond>
  36:	07fa      	br	0x2a	// goto loc_2a;
loc_38:
  38:	3000      	movi	r0, 0	// regs: r0=0x0
  3a:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  3c:	07f8      	br	0x2c	// goto loc_2c;
  3e:	0000      	.short	0x0000
  40:	dc70      	.short	0xdc70
  42:	fff4      	.short	0xfff4
  44:	0000      	.short	0x0000	// <module_efuse_info>
  46:	0000      	.short	0x0000
  48:	d13f      	.short	0xd13f
  4a:	000c      	.short	0x000c

Disassembly of section .text.lmac_test_enable:

00000000 <lmac_test_enable>: // arg_bytes: 4
   0:	14d3      	push	r4-r6, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	12c7      	lrw	r6, 0x0	// regs: r6=0x0
   6:	1288      	lrw	r4, 0x0	// regs: r4=0x0
   8:	e9000037 	bez	r0, 0x76	// if (r0 == 0x0) goto loc_76;
   c:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0xc>, r1=<clobbered>
  10:	1206      	lrw	r0, 0x0	// regs: r0=0x0
  12:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x12>, r1=<clobbered>
  16:	d86420ce 	ld.w	r3, (r4, 0x338)	// regs: r3=*(0x338)
  1a:	c4835763 	zext	r3, r3, 27, 4	// regs: r3=zext(*(0x338))
  1e:	b671      	st.w	r3, (r6, 0x44)	// *(0x44) = zext(*(0x338))
  20:	3264      	movi	r2, 100	// regs: r2=0x64
  22:	d86411b0 	ld.h	r3, (r4, 0x360)	// regs: r3=*(0x360)
  26:	c4625d01 	ins	r3, r2, 9, 1
  2a:	dc6411b0 	st.h	r3, (r4, 0x360)	// *(0x360) = *(0x360)
  2e:	3301      	movi	r3, 1	// regs: r3=0x1
  30:	dc640315 	st.b	r3, (r4, 0x315)	// *(0x315) = 0x1
  34:	3300      	movi	r3, 0	// regs: r3=0x0
  36:	dc640a4e 	st.b	r3, (r4, 0xa4e)	// *(0xa4e) = 0x0
  3a:	3200      	movi	r2, 0	// regs: r2=0x0
  3c:	d864036d 	ld.b	r3, (r4, 0x36d)	// regs: r3=*(0x36d)
  40:	c4625c22 	ins	r3, r2, 3, 2
  44:	3501      	movi	r5, 1	// regs: r5=0x1
  46:	dc64036d 	st.b	r3, (r4, 0x36d)	// *(0x36d) = *(0x36d)
  4a:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  4e:	c4655c01 	ins	r3, r5, 1, 1
  52:	6c17      	mov	r0, r5	// regs: r0=0x1
  54:	dc6409e2 	st.b	r3, (r4, 0x9e2)	// *(0x9e2) = *(0x9e2)
  58:	e0000000 	bsr	0x0	// <lmac_notify_testmode_state>; regs: r0=<ret lmac_notify_testmode_state@0x58>, r1=<clobbered>
  5c:	d86403df 	ld.b	r3, (r4, 0x3df)	// regs: r3=*(0x3df)
  60:	c4655c03 	ins	r3, r5, 3, 3
  64:	3002      	movi	r0, 2	// regs: r0=0x2
  66:	dc6403df 	st.b	r3, (r4, 0x3df)	// *(0x3df) = *(0x3df)
  6a:	e0000000 	bsr	0x0	// <lmac_spec_cca_cfg>; regs: r0=<ret lmac_spec_cca_cfg@0x6a>, r1=<clobbered>
loc_6e:
  6e:	3000      	movi	r0, 0	// regs: r0=0x0
  70:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x70>, r1=<clobbered>
  74:	1493      	pop	r4-r6, r15
loc_76:
  76:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  7a:	c4605c05 	ins	r3, r0, 5, 5
  7e:	c4605c03 	ins	r3, r0, 3, 3
  82:	d8460042 	ld.b	r2, (r6, 0x42)	// regs: r2=*(0x42)
  86:	c4405c00 	ins	r2, r0, 0, 0
  8a:	c4605c04 	ins	r3, r0, 4, 4
  8e:	dc460042 	st.b	r2, (r6, 0x42)	// *(0x42) = *(0x42)
  92:	dc6409e2 	st.b	r3, (r4, 0x9e2)	// *(0x9e2) = *(0x9e2)
  96:	e0000000 	bsr	0x0	// <ah_wphy_cont_tx_disable>; regs: r0=<ret ah_wphy_cont_tx_disable@0x96>, r1=<clobbered>
  9a:	301e      	movi	r0, 30	// regs: r0=0x1e
  9c:	e0000000 	bsr	0x0	// <os_sleep_ms>; regs: r0=<ret os_sleep_ms@0x9c>, r1=<clobbered>
  a0:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0xa0>, r1=<clobbered>
  a4:	6c17      	mov	r0, r5	// regs: r0=<arg0>
  a6:	e0000000 	bsr	0x0	// <disable_print>; regs: r0=<ret disable_print@0xa6>, r1=<clobbered>
  aa:	e0000000 	bsr	0x0	// <update_rx_buff_addr>; regs: r0=<ret update_rx_buff_addr@0xaa>, r1=<clobbered>
  ae:	9608      	ld.w	r0, (r6, 0x20)	// regs: r0=*(0x20)
  b0:	e9000004 	bez	r0, 0xb8	// if (r0 == 0x0) goto loc_b8;
  b4:	e0000000 	bsr	0x0	// <kfree_skb>; regs: r0=<ret kfree_skb@0xb4>, r1=<clobbered>
loc_b8:
  b8:	9611      	ld.w	r0, (r6, 0x44)	// regs: r0=*(0x44)
  ba:	e0000000 	bsr	0x0	// <lmac_lo_freq_set>; regs: r0=<ret lmac_lo_freq_set@0xba>, r1=<clobbered>
  be:	3500      	movi	r5, 0	// regs: r5=0x0
  c0:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  c4:	c4655c01 	ins	r3, r5, 1, 1
  c8:	dc6409e2 	st.b	r3, (r4, 0x9e2)	// *(0x9e2) = *(0x9e2)
  cc:	3318      	movi	r3, 24	// regs: r3=0x18
  ce:	ea0201ff 	movi	r2, 511	// regs: r2=0x1ff
  d2:	dc640315 	st.b	r3, (r4, 0x315)	// *(0x315) = 0x18
  d6:	d86411b0 	ld.h	r3, (r4, 0x360)	// regs: r3=*(0x360)
  da:	c4625d01 	ins	r3, r2, 9, 1
  de:	6c17      	mov	r0, r5	// regs: r0=0x0
  e0:	dc6411b0 	st.h	r3, (r4, 0x360)	// *(0x360) = *(0x360)
  e4:	e0000000 	bsr	0x0	// <lmac_notify_testmode_state>; regs: r0=<ret lmac_notify_testmode_state@0xe4>, r1=<clobbered>
  e8:	d86403df 	ld.b	r3, (r4, 0x3df)	// regs: r3=*(0x3df)
  ec:	c4655c03 	ins	r3, r5, 3, 3
  f0:	3201      	movi	r2, 1	// regs: r2=0x1
  f2:	dc6403df 	st.b	r3, (r4, 0x3df)	// *(0x3df) = *(0x3df)
  f6:	6c17      	mov	r0, r5	// regs: r0=0x0
  f8:	d8640361 	ld.b	r3, (r4, 0x361)	// regs: r3=*(0x361)
  fc:	c4625c02 	ins	r3, r2, 2, 2
 100:	283b      	subi	r0, 60	// regs: r0=0xffffffc4
 102:	dc640361 	st.b	r3, (r4, 0x361)	// *(0x361) = *(0x361)
 106:	dc04031e 	st.b	r0, (r4, 0x31e)	// *(0x31e) = 0xffffffc4
 10a:	e0000000 	bsr	0x0	// <lmac_adjust_cca_threshold>; regs: r0=<ret lmac_adjust_cca_threshold@0x10a>, r1=<clobbered>
 10e:	d864036d 	ld.b	r3, (r4, 0x36d)	// regs: r3=*(0x36d)
 112:	c48354a2 	zext	r2, r3, 5, 4	// regs: r2=zext(*(0x36d))
 116:	c4625c22 	ins	r3, r2, 3, 2
 11a:	dc64036d 	st.b	r3, (r4, 0x36d)	// *(0x36d) = *(0x36d)
 11e:	07a8      	br	0x6e	// goto loc_6e;
 120:	00000000 	.long	0x00000000	// <lmactest>
 124:	00000000 	.long	0x00000000	// <ah_lmac>
 128:	00000000 	.long	0x00000000	// <.rodata.lmac_test_enable.str1.1>

Disassembly of section .text.lmac_test_txskb_init:

00000000 <lmac_test_txskb_init>: // arg_bytes: 4
   0:	14d5      	push	r4-r8, r15
   2:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   4:	3180      	movi	r1, 128	// regs: r1=0x80
   6:	4121      	lsli	r1, r1, 1	// regs: r1=0x100
   8:	e0000000 	bsr	0x0	// <skb_reserve>; regs: r0=<ret skb_reserve@0x8>, r1=<clobbered>
   c:	d866002a 	ld.b	r3, (r6, 0x2a)	// regs: r3=*(<arg0> + 0x2a)
  10:	3201      	movi	r2, 1	// regs: r2=0x1
  12:	c4625c06 	ins	r3, r2, 6, 6
  16:	96a6      	ld.w	r5, (r6, 0x18)	// regs: r5=*(<arg0> + 0x18)
  18:	dc66002a 	st.b	r3, (r6, 0x2a)	// *(<arg0> + 0x2a) = *(<arg0> + 0x2a)
  1c:	3120      	movi	r1, 32	// regs: r1=0x20
  1e:	6c1b      	mov	r0, r6	// regs: r0=<arg0>
  20:	e0000000 	bsr	0x0	// <skb_reserve>; regs: r0=<ret skb_reserve@0x20>, r1=<clobbered>
  24:	3220      	movi	r2, 32	// regs: r2=0x20
  26:	3100      	movi	r1, 0	// regs: r1=0x0
  28:	6c17      	mov	r0, r5	// regs: r0=*(<arg0> + 0x18)
  2a:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x2a>, r1=<clobbered>
  2e:	3300      	movi	r3, 0	// regs: r3=0x0
  30:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  32:	a568      	st.b	r3, (r5, 0x8)	// *((*(<arg0> + 0x18) + 0x8)) = 0xffffffff
  34:	a569      	st.b	r3, (r5, 0x9)	// *((*(<arg0> + 0x18) + 0x9)) = 0xffffffff
  36:	a56a      	st.b	r3, (r5, 0xa)	// *((*(<arg0> + 0x18) + 0xa)) = 0xffffffff
  38:	3300      	movi	r3, 0	// regs: r3=0x0
  3a:	2b1f      	subi	r3, 32	// regs: r3=0xffffffe0
  3c:	a56b      	st.b	r3, (r5, 0xb)	// *((*(<arg0> + 0x18) + 0xb)) = 0xffffffe0
  3e:	330f      	movi	r3, 15	// regs: r3=0xf
  40:	1391      	lrw	r4, 0x0	// regs: r4=0x0
  42:	2507      	addi	r5, 8	// regs: r5=(*(<arg0> + 0x18) + 0x8)
  44:	a56a      	st.b	r3, (r5, 0xa)	// *((*(<arg0> + 0x18) + 0x12)) = 0xf
  46:	d864003c 	ld.b	r3, (r4, 0x3c)	// regs: r3=*(0x3c)
  4a:	a564      	st.b	r3, (r5, 0x4)	// *((*(<arg0> + 0x18) + 0xc)) = *(0x3c)
  4c:	d864003d 	ld.b	r3, (r4, 0x3d)	// regs: r3=*(0x3d)
  50:	a565      	st.b	r3, (r5, 0x5)	// *((*(<arg0> + 0x18) + 0xd)) = *(0x3d)
  52:	d864003e 	ld.b	r3, (r4, 0x3e)	// regs: r3=*(0x3e)
  56:	a566      	st.b	r3, (r5, 0x6)	// *((*(<arg0> + 0x18) + 0xe)) = *(0x3e)
  58:	d864003f 	ld.b	r3, (r4, 0x3f)	// regs: r3=*(0x3f)
  5c:	a567      	st.b	r3, (r5, 0x7)	// *((*(<arg0> + 0x18) + 0xf)) = *(0x3f)
  5e:	3218      	movi	r2, 24	// regs: r2=0x18
  60:	e4240023 	addi	r1, r4, 36	// regs: r1=0x24
  64:	b6ad      	st.w	r5, (r6, 0x34)	// *(<arg0> + 0x34) = (*(<arg0> + 0x18) + 0x8)
  66:	9606      	ld.w	r0, (r6, 0x18)	// regs: r0=*(<arg0> + 0x18)
  68:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x68>, r1=<clobbered>
  6c:	3118      	movi	r1, 24	// regs: r1=0x18
  6e:	6c1b      	mov	r0, r6	// regs: r0=<arg0>
  70:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x70>, r1=<clobbered>
  74:	9606      	ld.w	r0, (r6, 0x18)	// regs: r0=*(<arg0> + 0x18)
  76:	6c83      	mov	r2, r0	// regs: r2=*(<arg0> + 0x18)
  78:	ea0c0006 	movi	r12, 6	// regs: r12=0x6
loc_7c:
  7c:	5a61      	subu	r3, r2, r0	// regs: r3=(r2 - *(<arg0> + 0x18))
  7e:	d8241020 	ld.h	r1, (r4, 0x40)	// regs: r1=*(0x40)
  82:	644c      	cmphs	r3, r1
  84:	0c89      	bf	0x196	// if (!T) goto loc_196;
  86:	6c1b      	mov	r0, r6	// regs: r0=<arg0>
  88:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x88>, r1=<clobbered>
  8c:	96a8      	ld.w	r5, (r6, 0x20)	// regs: r5=*(<arg0> + 0x20)
  8e:	3244      	movi	r2, 68	// regs: r2=0x44
  90:	6c17      	mov	r0, r5	// regs: r0=*(<arg0> + 0x20)
  92:	3100      	movi	r1, 0	// regs: r1=0x0
  94:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x94>, r1=<clobbered>
  98:	3318      	movi	r3, 24	// regs: r3=0x18
  9a:	dc65002a 	st.b	r3, (r5, 0x2a)	// *((*(<arg0> + 0x20) + 0x2a)) = 0x18
  9e:	3300      	movi	r3, 0	// regs: r3=0x0
  a0:	dc650026 	st.b	r3, (r5, 0x26)	// *((*(<arg0> + 0x20) + 0x26)) = 0x0
  a4:	96e7      	ld.w	r7, (r6, 0x1c)	// regs: r7=*(<arg0> + 0x1c)
  a6:	12b9      	lrw	r5, 0x0	// regs: r5=0x0
  a8:	ea880059 	lrw	r8, 0x0	// regs: r8=0x0
  ac:	d8650892 	ld.b	r3, (r5, 0x892)	// regs: r3=*(0x892)
  b0:	e4432001 	andi	r2, r3, 1	// regs: r2=(*(0x892) & 0x1)
  b4:	e902005a 	bez	r2, 0x168	// if (r2 == 0x0) goto loc_168;
  b8:	e4432002 	andi	r2, r3, 2	// regs: r2=(*(0x892) & 0x2)
  bc:	e9020077 	bez	r2, 0x1aa	// if (r2 == 0x0) goto loc_1aa;
  c0:	3300      	movi	r3, 0	// regs: r3=0x0
  c2:	dc640028 	st.b	r3, (r4, 0x28)	// *(0x28) = 0x0
  c6:	3310      	movi	r3, 16	// regs: r3=0x10
  c8:	dc640029 	st.b	r3, (r4, 0x29)	// *(0x29) = 0x10
  cc:	3320      	movi	r3, 32	// regs: r3=0x20
  ce:	dc64002a 	st.b	r3, (r4, 0x2a)	// *(0x2a) = 0x20
  d2:	3330      	movi	r3, 48	// regs: r3=0x30
  d4:	dc64002b 	st.b	r3, (r4, 0x2b)	// *(0x2b) = 0x30
  d8:	3340      	movi	r3, 64	// regs: r3=0x40
  da:	dc64002c 	st.b	r3, (r4, 0x2c)	// *(0x2c) = 0x40
  de:	3350      	movi	r3, 80	// regs: r3=0x50
  e0:	dc64002d 	st.b	r3, (r4, 0x2d)	// *(0x2d) = 0x50
  e4:	d865089b 	ld.b	r3, (r5, 0x89b)	// regs: r3=*(0x89b)
loc_e8:
  e8:	96c7      	ld.w	r6, (r6, 0x1c)	// regs: r6=*(<arg0> + 0x1c)
  ea:	dc681000 	st.h	r3, (r8, 0x0)	// *(0x0) = r3
  ee:	3300      	movi	r3, 0	// regs: r3=0x0
  f0:	2b22      	subi	r3, 35	// regs: r3=0xffffffdd
  f2:	a678      	st.b	r3, (r6, 0x18)	// *((*(<arg0> + 0x1c) + 0x18)) = 0xffffffdd
  f4:	3309      	movi	r3, 9	// regs: r3=0x9
  f6:	a679      	st.b	r3, (r6, 0x19)	// *((*(<arg0> + 0x1c) + 0x19)) = 0x9
  f8:	3300      	movi	r3, 0	// regs: r3=0x0
  fa:	2b7f      	subi	r3, 128	// regs: r3=0xffffff80
  fc:	e486001a 	addi	r4, r6, 27	// regs: r4=(*(<arg0> + 0x1c) + 0x1b)
 100:	a67a      	st.b	r3, (r6, 0x1a)	// *((*(<arg0> + 0x1c) + 0x1a)) = 0xffffff80
 102:	3208      	movi	r2, 8	// regs: r2=0x8
 104:	3100      	movi	r1, 0	// regs: r1=0x0
 106:	6c13      	mov	r0, r4	// regs: r0=(*(<arg0> + 0x1c) + 0x1b)
 108:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x108>, r1=<clobbered>
 10c:	d865034a 	ld.b	r3, (r5, 0x34a)	// regs: r3=*(0x34a)
 110:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x34a) & 0x1)
 114:	865b      	ld.b	r2, (r6, 0x1b)	// regs: r2=*((*(<arg0> + 0x1c) + 0x1b))
 116:	e9030069 	bez	r3, 0x1e8	// if (r3 == 0x0) goto loc_1e8;
 11a:	ec620001 	ori	r3, r2, 1	// regs: r3=(*((*(<arg0> + 0x1c) + 0x1b)) | 0x1)
loc_11e:
 11e:	a67b      	st.b	r3, (r6, 0x1b)	// *((*(<arg0> + 0x1c) + 0x1b)) = r3
 120:	3200      	movi	r2, 0	// regs: r2=0x0
 122:	867b      	ld.b	r3, (r6, 0x1b)	// regs: r3=*((*(<arg0> + 0x1c) + 0x1b))
 124:	2a5f      	subi	r2, 96	// regs: r2=0xffffffa0
 126:	6cc8      	or	r3, r2	// regs: r3=(*((*(<arg0> + 0x1c) + 0x1b)) | 0xffffffa0)
 128:	a67b      	st.b	r3, (r6, 0x1b)	// *((*(<arg0> + 0x1c) + 0x1b)) = (*((*(<arg0> + 0x1c) + 0x1b)) | 0xffffffa0)
 12a:	d8650349 	ld.b	r3, (r5, 0x349)	// regs: r3=*(0x349)
 12e:	a461      	st.b	r3, (r4, 0x1)	// *((*(<arg0> + 0x1c) + 0x1c)) = *(0x349)
 130:	d8650309 	ld.b	r3, (r5, 0x309)	// regs: r3=*(0x309)
 134:	a462      	st.b	r3, (r4, 0x2)	// *((*(<arg0> + 0x1c) + 0x1d)) = *(0x309)
 136:	d86520ce 	ld.w	r3, (r5, 0x338)	// regs: r3=*(0x338)
 13a:	c4835763 	zext	r3, r3, 27, 4	// regs: r3=zext(*(0x338))
 13e:	1155      	lrw	r2, 0xfff551a0	// regs: r2=0xfff551a0
 140:	31fa      	movi	r1, 250	// regs: r1=0xfa
 142:	4122      	lsli	r1, r1, 2	// regs: r1=0x3e8
 144:	608c      	addu	r2, r3	// regs: r2=(0xfff551a0 + zext(*(0x338)))
 146:	c4228042 	divs	r2, r2, r1	// regs: r2=((0xfff551a0 + zext(*(0x338))) / 0x3e8)
 14a:	3001      	movi	r0, 1	// regs: r0=0x1
 14c:	a443      	st.b	r2, (r4, 0x3)	// *((*(<arg0> + 0x1c) + 0x1e)) = ((0xfff551a0 + zext(*(0x338))) / 0x3e8)
 14e:	8444      	ld.b	r2, (r4, 0x4)	// regs: r2=*((*(<arg0> + 0x1c) + 0x1f))
 150:	c4405c00 	ins	r2, r0, 0, 0
 154:	c4238040 	divs	r0, r3, r1	// regs: r0=(zext(*(0x338)) / 0x3e8)
 158:	7c40      	mult	r1, r0	// regs: r1=(0x3e8 * (zext(*(0x338)) / 0x3e8))
 15a:	60c6      	subu	r3, r1	// regs: r3=(zext(*(0x338)) - (0x3e8 * (zext(*(0x338)) / 0x3e8)))
 15c:	3164      	movi	r1, 100	// regs: r1=0x64
 15e:	c4238043 	divs	r3, r3, r1	// regs: r3=((zext(*(0x338)) - (0x3e8 * (zext(*(0x338)) / 0x3e8))) / 0x64)
 162:	c4435c61 	ins	r2, r3, 4, 1
 166:	a444      	st.b	r2, (r4, 0x4)	// *((*(<arg0> + 0x1c) + 0x1f)) = *((*(<arg0> + 0x1c) + 0x1f))
loc_168:
 168:	d8481000 	ld.h	r2, (r8, 0x0)	// regs: r2=*(0x0)
 16c:	4264      	lsli	r3, r2, 4	// regs: r3=(*(0x0) << 0x4)
 16e:	74cd      	zexth	r3, r3	// regs: r3=zext16((*(0x0) << 0x4))
 170:	a776      	st.b	r3, (r7, 0x16)	// *((*(<arg0> + 0x1c) + 0x16)) = zext16((*(0x0) << 0x4))
 172:	4b68      	lsri	r3, r3, 8	// regs: r3=(zext16((*(0x0) << 0x4)) >> 0x8)
 174:	a777      	st.b	r3, (r7, 0x17)	// *((*(<arg0> + 0x1c) + 0x17)) = (zext16((*(0x0) << 0x4)) >> 0x8)
 176:	d8650315 	ld.b	r3, (r5, 0x315)	// regs: r3=*(0x315)
 17a:	3b41      	cmpnei	r3, 1
 17c:	0840      	bt	0x1fc	// if (r3 != 0x1) goto loc_1fc;
 17e:	3300      	movi	r3, 0	// regs: r3=0x0
 180:	dc681000 	st.h	r3, (r8, 0x0)	// *(0x0) = 0x0
loc_184:
 184:	d8681000 	ld.h	r3, (r8, 0x0)	// regs: r3=*(0x0)
 188:	eb030fff 	cmphsi	r3, 4096
 18c:	0c04      	bf	0x194	// if (r3 < 0x1000) goto loc_194;
 18e:	3300      	movi	r3, 0	// regs: r3=0x0
 190:	dc681000 	st.h	r3, (r8, 0x0)	// *(0x0) = 0x0
loc_194:
 194:	1495      	pop	r4-r8, r15
loc_196:
 196:	c5838021 	divu	r1, r3, r12	// regs: r1=((r2 - *(<arg0> + 0x18)) / 0x6)
 19a:	7c70      	mult	r1, r12	// regs: r1=(((r2 - *(<arg0> + 0x18)) / 0x6) * 0x6)
 19c:	60c6      	subu	r3, r1	// regs: r3=((r2 - *(<arg0> + 0x18)) - (((r2 - *(<arg0> + 0x18)) / 0x6) * 0x6))
 19e:	60d0      	addu	r3, r4	// regs: r3=(((r2 - *(<arg0> + 0x18)) - (((r2 - *(<arg0> + 0x18)) / 0x6) * 0x6)) )
 1a0:	d8630028 	ld.b	r3, (r3, 0x28)	// regs: r3=*(((((r2 - *(<arg0> + 0x18)) - (((r2 - *(<arg0> + 0x18)) / 0x6) * 0x6)) ) + 0x28))
 1a4:	a260      	st.b	r3, (r2, 0x0)	// *(r2) = *(((((r2 - *(<arg0> + 0x18)) - (((r2 - *(<arg0> + 0x18)) / 0x6) * 0x6)) ) + 0x28))
 1a6:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
 1a8:	076a      	br	0x7c	// goto loc_7c;
loc_1aa:
 1aa:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(0x892) & 0x4)
 1ae:	e903000b 	bez	r3, 0x1c4	// if (r3 == 0x0) goto loc_1c4;
 1b2:	3206      	movi	r2, 6	// regs: r2=0x6
 1b4:	e42508c1 	addi	r1, r5, 2242	// regs: r1=0x8c2
 1b8:	1017      	lrw	r0, 0x0	// regs: r0=0x0
 1ba:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x1ba>, r1=<clobbered>
loc_1be:
 1be:	d865089c 	ld.b	r3, (r5, 0x89c)	// regs: r3=*(0x89c)
 1c2:	0793      	br	0xe8	// goto loc_e8;
loc_1c4:
 1c4:	dc640028 	st.b	r3, (r4, 0x28)	// *(0x28) = (*(0x892) & 0x4)
 1c8:	3310      	movi	r3, 16	// regs: r3=0x10
 1ca:	dc640029 	st.b	r3, (r4, 0x29)	// *(0x29) = 0x10
 1ce:	3320      	movi	r3, 32	// regs: r3=0x20
 1d0:	dc64002a 	st.b	r3, (r4, 0x2a)	// *(0x2a) = 0x20
 1d4:	3330      	movi	r3, 48	// regs: r3=0x30
 1d6:	dc64002b 	st.b	r3, (r4, 0x2b)	// *(0x2b) = 0x30
 1da:	3340      	movi	r3, 64	// regs: r3=0x40
 1dc:	dc64002c 	st.b	r3, (r4, 0x2c)	// *(0x2c) = 0x40
 1e0:	3350      	movi	r3, 80	// regs: r3=0x50
 1e2:	dc64002d 	st.b	r3, (r4, 0x2d)	// *(0x2d) = 0x50
 1e6:	07ec      	br	0x1be	// goto loc_1be;
loc_1e8:
 1e8:	d8250308 	ld.b	r1, (r5, 0x308)	// regs: r1=*(0x308)
 1ec:	3301      	movi	r3, 1	// regs: r3=0x1
 1ee:	70c4      	lsl	r3, r1
 1f0:	2b00      	subi	r3, 1	// regs: r3=0x0
 1f2:	4361      	lsli	r3, r3, 1	// regs: r3=0x0
 1f4:	e463201e 	andi	r3, r3, 30	// regs: r3=(0x0 & 0x1e)
 1f8:	6cc8      	or	r3, r2	// regs: r3=((0x0 & 0x1e) | *((*(<arg0> + 0x1c) + 0x1b)))
 1fa:	0792      	br	0x11e	// goto loc_11e;
loc_1fc:
 1fc:	2200      	addi	r2, 1	// regs: r2=(*(0x0) + 0x1)
 1fe:	dc481000 	st.h	r2, (r8, 0x0)	// *(0x0) = (*(0x0) + 0x1)
 202:	07c1      	br	0x184	// goto loc_184;
 204:	00000000 	.long	0x00000000	// <lmactest>
 208:	00000000 	.long	0x00000000	// <ah_lmac>
 20c:	00000000 	.long	0x00000000	// <.bss.seq_num.13558>
 210:	fff551a0 	.long	0xfff551a0
 214:	00000000 	.long	0x00000000	// <lmactest+0x28>

Disassembly of section .text.lmac_test_task:

00000000 <lmac_test_task>: // arg_bytes: 0
   0:	14d5      	push	r4-r8, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	3037      	movi	r0, 55	// regs: r0=0x37
   6:	e0000000 	bsr	0x0	// <dev_get>; regs: r0=<ret dev_get@0x6>, r1=<clobbered>
   a:	ea880043 	lrw	r8, 0x0	// regs: r8=0x0
   e:	6d43      	mov	r5, r0	// regs: r5=<ret dev_get@0x6>
  10:	6d23      	mov	r4, r8	// regs: r4=0x0
  12:	12e2      	lrw	r7, 0x0	// regs: r7=0x0
loc_14:
  14:	d8680000 	ld.b	r3, (r8, 0x0)	// regs: r3=*(r8)
  18:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r8) & 0x1)
  1c:	e9030004 	bez	r3, 0x24	// if (r3 == 0x0) goto loc_24;
  20:	1402      	addi	r14, r14, 8	// regs: r14=(sp + 0x8)
  22:	1495      	pop	r4-r8, r15
loc_24:
  24:	d86709e2 	ld.b	r3, (r7, 0x9e2)	// regs: r3=*(r7 + 0x9e2)
  28:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(r7 + 0x9e2) & 0x8)
  2c:	e923000e 	bnez	r3, 0x48	// if (r3 != 0x0) goto loc_48;
loc_30:
  30:	84c1      	ld.b	r6, (r4, 0x1)	// regs: r6=*(r4 + 0x1)
  32:	e4c62004 	andi	r6, r6, 4	// regs: r6=(*(r4 + 0x1) & 0x4)
  36:	e926005d 	bnez	r6, 0xf0	// if (r6 != 0x0) goto loc_f0;
  3a:	9408      	ld.w	r0, (r4, 0x20)	// regs: r0=*(r4 + 0x20)
  3c:	e9000038 	bez	r0, 0xac	// if (r0 == 0x0) goto loc_ac;
  40:	e0000000 	bsr	0x0	// <kfree_skb>; regs: r0=<ret kfree_skb@0x40>, r1=<clobbered>
  44:	b4c8      	st.w	r6, (r4, 0x20)	// *(r4 + 0x20) = (*(r4 + 0x1) & 0x4)
  46:	0433      	br	0xac	// goto loc_ac;
loc_48:
  48:	3206      	movi	r2, 6	// regs: r2=0x6
  4a:	1135      	lrw	r1, 0x0	// regs: r1=0x0
  4c:	1115      	lrw	r0, 0x0	// regs: r0=0x0
  4e:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x4e>, r1=<clobbered>
loc_52:
  52:	3001      	movi	r0, 1	// regs: r0=0x1
  54:	e0000000 	bsr	0x0	// <skbpool_freesize>; regs: r0=<ret skbpool_freesize@0x54>, r1=<clobbered>
  58:	eb0087ff 	cmphsi	r0, 34816
  5c:	0fea      	bf	0x30	// if (r0 < 0x8800) goto loc_30;
  5e:	3001      	movi	r0, 1	// regs: r0=0x1
  60:	e0000000 	bsr	0x0	// <os_sleep_ms>; regs: r0=<ret os_sleep_ms@0x60>, r1=<clobbered>
  64:	d8041020 	ld.h	r0, (r4, 0x40)	// regs: r0=*(r4 + 0x40)
  68:	e4000137 	addi	r0, r0, 312	// regs: r0=(*(r4 + 0x40) + 0x138)
  6c:	e0000000 	bsr	0x0	// <alloc_tx_skb>; regs: r0=<ret alloc_tx_skb@0x6c>, r1=<clobbered>
  70:	6d83      	mov	r6, r0	// regs: r6=<ret alloc_tx_skb@0x6c>
  72:	e900ffdf 	bez	r0, 0x30	// if (r0 == 0x0) goto loc_30;
  76:	e0000000 	bsr	0x0	// <lmac_test_txskb_init> // arg_bytes: 4; regs: r0=<ret lmac_test_txskb_init@0x76>, r1=<clobbered>
  7a:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(r7)
  7c:	6c5b      	mov	r1, r6	// regs: r1=<ret alloc_tx_skb@0x6c>
  7e:	9346      	ld.w	r2, (r3, 0x18)	// regs: r2=*((*(r7) + 0x18))
  80:	9300      	ld.w	r0, (r3, 0x0)	// regs: r0=*(*(r7))
  82:	7bc9      	jsr	r2
  84:	e900ffe7 	bez	r0, 0x52	// if (r0 == 0x0) goto loc_52;
  88:	6c1b      	mov	r0, r6	// regs: r0=<ret alloc_tx_skb@0x6c>
  8a:	e0000000 	bsr	0x0	// <kfree_skb>; regs: r0=<ret kfree_skb@0x8a>, r1=<clobbered>
  8e:	07e2      	br	0x52	// goto loc_52;
loc_90:
  90:	9468      	ld.w	r3, (r4, 0x20)	// regs: r3=*(r4 + 0x20)
  92:	e903000d 	bez	r3, 0xac	// if (r3 == 0x0) goto loc_ac;
  96:	9367      	ld.w	r3, (r3, 0x1c)	// regs: r3=*((*(r4 + 0x20) + 0x1c))
  98:	3101      	movi	r1, 1	// regs: r1=0x1
  9a:	6c3b      	mov	r0, r14	// regs: r0=sp
  9c:	b860      	st.w	r3, (r14, 0x0)	// stack_0 = *((*(r4 + 0x20) + 0x1c))
  9e:	b8c1      	st.w	r6, (r14, 0x4)	// stack_p4 = r6
  a0:	e0000000 	bsr	0x0	// <lmac_rx_data_queue_put>; regs: r0=<ret lmac_rx_data_queue_put@0xa0>, r1=<clobbered>
loc_a4:
  a4:	e0000000 	bsr	0x0	// <lmac_rx_data_queue_count>; regs: r0=<ret lmac_rx_data_queue_count@0xa4>, r1=<clobbered>
  a8:	383f      	cmplti	r0, 32
  aa:	0bf3      	bt	0x90	// if (r0 < 0x20) goto loc_90;
loc_ac:
  ac:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(r4 + 0x1)
  ae:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(r4 + 0x1) & 0x8)
  b2:	e9030022 	bez	r3, 0xf6	// if (r3 == 0x0) goto loc_f6;
  b6:	e9050020 	bez	r5, 0xf6	// if (r5 == 0x0) goto loc_f6;
  ba:	6c17      	mov	r0, r5	// regs: r0=r5
  bc:	e0000000 	bsr	0x0	// <spi_nor_open>; regs: r0=<ret spi_nor_open@0xbc>, r1=<clobbered>
  c0:	6c17      	mov	r0, r5	// regs: r0=r5
  c2:	9462      	ld.w	r3, (r4, 0x8)	// regs: r3=*(r4 + 0x8)
  c4:	9441      	ld.w	r2, (r4, 0x4)	// regs: r2=*(r4 + 0x4)
  c6:	3100      	movi	r1, 0	// regs: r1=0x0
  c8:	e0000000 	bsr	0x0	// <spi_nor_read>; regs: r0=<ret spi_nor_read@0xc8>, r1=<clobbered>
  cc:	6c17      	mov	r0, r5	// regs: r0=r5
  ce:	e0000000 	bsr	0x0	// <spi_nor_close>; regs: r0=<ret spi_nor_close@0xce>, r1=<clobbered>
loc_d2:
  d2:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(r4 + 0x1)
  d4:	e463200c 	andi	r3, r3, 12	// regs: r3=(*(r4 + 0x1) & 0xc)
  d8:	e923ff9e 	bnez	r3, 0x14	// if (r3 != 0x0) goto loc_14;
  dc:	d86709e2 	ld.b	r3, (r7, 0x9e2)	// regs: r3=*(r7 + 0x9e2)
  e0:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(r7 + 0x9e2) & 0x8)
  e4:	e9230011 	bnez	r3, 0x106	// if (r3 != 0x0) goto loc_106;
loc_e8:
  e8:	300a      	movi	r0, 10	// regs: r0=0xa
  ea:	e0000000 	bsr	0x0	// <os_sleep_ms>; regs: r0=<ret os_sleep_ms@0xea>, r1=<clobbered>
  ee:	0793      	br	0x14	// goto loc_14;
loc_f0:
  f0:	ea0605b4 	movi	r6, 1460	// regs: r6=0x5b4
  f4:	07d8      	br	0xa4	// goto loc_a4;
loc_f6:
  f6:	9401      	ld.w	r0, (r4, 0x4)	// regs: r0=*(r4 + 0x4)
  f8:	e900ffed 	bez	r0, 0xd2	// if (r0 == 0x0) goto loc_d2;
  fc:	e0000000 	bsr	0x0	// <_os_free>; regs: r0=<ret _os_free@0xfc>, r1=<clobbered>
 100:	3300      	movi	r3, 0	// regs: r3=0x0
 102:	b461      	st.w	r3, (r4, 0x4)	// *(r4 + 0x4) = 0x0
 104:	07e7      	br	0xd2	// goto loc_d2;
loc_106:
 106:	3001      	movi	r0, 1	// regs: r0=0x1
 108:	e0000000 	bsr	0x0	// <skbpool_freesize>; regs: r0=<ret skbpool_freesize@0x108>, r1=<clobbered>
 10c:	eb0087ff 	cmphsi	r0, 34816
 110:	0fec      	bf	0xe8	// if (r0 < 0x8800) goto loc_e8;
 112:	0781      	br	0x14	// goto loc_14;
 114:	00000000 	.long	0x00000000	// <lmactest>
 118:	00000000 	.long	0x00000000	// <ah_lmac>
 11c:	00000000 	.long	0x00000000	// <ah_lmac+0x302>
 120:	00000000 	.long	0x00000000	// <lmactest+0x2e>

Disassembly of section .text.lmac_test_temp_sensor_rd_hdl:

00000000 <lmac_test_temp_sensor_rd_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	3002      	movi	r0, 2	// regs: r0=0x2
   4:	e0000000 	bsr	0x0	// <tsensor_meas>; regs: r0=<ret tsensor_meas@0x4>, r1=<clobbered>
   8:	1490      	pop	r15

Disassembly of section .text.ft_att_delay:

00000000 <ft_att_delay>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	3005      	movi	r0, 5	// regs: r0=0x5
   4:	e0000000 	bsr	0x0	// <os_sleep_us>; regs: r0=<ret os_sleep_us@0x4>, r1=<clobbered>
   8:	1490      	pop	r15

Disassembly of section .text.ft_att1_write:

00000000 <ft_att1_write>: // arg_bytes: 4
   0:	14d2      	push	r4-r5, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	3101      	movi	r1, 1	// regs: r1=0x1
   6:	301f      	movi	r0, 31	// regs: r0=0x1f
   8:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x8>, r1=<clobbered>
   c:	3101      	movi	r1, 1	// regs: r1=0x1
   e:	301e      	movi	r0, 30	// regs: r0=0x1e
  10:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x10>, r1=<clobbered>
  14:	3101      	movi	r1, 1	// regs: r1=0x1
  16:	3002      	movi	r0, 2	// regs: r0=0x2
  18:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x18>, r1=<clobbered>
  1c:	3101      	movi	r1, 1	// regs: r1=0x1
  1e:	3003      	movi	r0, 3	// regs: r0=0x3
  20:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x20>, r1=<clobbered>
  24:	3100      	movi	r1, 0	// regs: r1=0x0
  26:	301f      	movi	r0, 31	// regs: r0=0x1f
  28:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x28>, r1=<clobbered>
  2c:	3100      	movi	r1, 0	// regs: r1=0x0
  2e:	301e      	movi	r0, 30	// regs: r0=0x1e
  30:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x30>, r1=<clobbered>
  34:	3100      	movi	r1, 0	// regs: r1=0x0
  36:	3002      	movi	r0, 2	// regs: r0=0x2
  38:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x38>, r1=<clobbered>
  3c:	3100      	movi	r1, 0	// regs: r1=0x0
  3e:	3003      	movi	r0, 3	// regs: r0=0x3
  40:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x40>, r1=<clobbered>
  44:	6110      	addu	r4, r4	// regs: r4=(<arg0> + <arg0>)
  46:	e0000000 	bsr	0x0	// <ft_att_delay> // arg_bytes: 0; regs: r0=<ret ft_att_delay@0x46>, r1=<clobbered>
  4a:	7510      	zextb	r4, r4	// regs: r4=zext8((<arg0> + <arg0>))
  4c:	3505      	movi	r5, 5	// regs: r5=0x5
loc_4e:
  4e:	c4a44081 	asr	r1, r4, r5
  52:	e4212001 	andi	r1, r1, 1	// regs: r1=(<clobbered> & 0x1)
  56:	3003      	movi	r0, 3	// regs: r0=0x3
  58:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x58>, r1=<clobbered>
  5c:	3101      	movi	r1, 1	// regs: r1=0x1
  5e:	3002      	movi	r0, 2	// regs: r0=0x2
  60:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x60>, r1=<clobbered>
  64:	e0000000 	bsr	0x0	// <ft_att_delay> // arg_bytes: 0; regs: r0=<ret ft_att_delay@0x64>, r1=<clobbered>
  68:	3100      	movi	r1, 0	// regs: r1=0x0
  6a:	3002      	movi	r0, 2	// regs: r0=0x2
  6c:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x6c>, r1=<clobbered>
  70:	e0000000 	bsr	0x0	// <ft_att_delay> // arg_bytes: 0; regs: r0=<ret ft_att_delay@0x70>, r1=<clobbered>
  74:	3300      	movi	r3, 0	// regs: r3=0x0
  76:	2d00      	subi	r5, 1	// regs: r5=(r5 - 0x1)
  78:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  7a:	64d6      	cmpne	r5, r3
  7c:	0be9      	bt	0x4e	// if (T) goto loc_4e;
  7e:	3101      	movi	r1, 1	// regs: r1=0x1
  80:	301f      	movi	r0, 31	// regs: r0=0x1f
  82:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x82>, r1=<clobbered>
  86:	e0000000 	bsr	0x0	// <ft_att_delay> // arg_bytes: 0; regs: r0=<ret ft_att_delay@0x86>, r1=<clobbered>
  8a:	3100      	movi	r1, 0	// regs: r1=0x0
  8c:	301f      	movi	r0, 31	// regs: r0=0x1f
  8e:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x8e>, r1=<clobbered>
  92:	e0000000 	bsr	0x0	// <ft_att_delay> // arg_bytes: 0; regs: r0=<ret ft_att_delay@0x92>, r1=<clobbered>
  96:	1492      	pop	r4-r5, r15

Disassembly of section .text.ft_att2_write:

00000000 <ft_att2_write>: // arg_bytes: 4
   0:	14d2      	push	r4-r5, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	3101      	movi	r1, 1	// regs: r1=0x1
   6:	301f      	movi	r0, 31	// regs: r0=0x1f
   8:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x8>, r1=<clobbered>
   c:	3101      	movi	r1, 1	// regs: r1=0x1
   e:	301e      	movi	r0, 30	// regs: r0=0x1e
  10:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x10>, r1=<clobbered>
  14:	3101      	movi	r1, 1	// regs: r1=0x1
  16:	3002      	movi	r0, 2	// regs: r0=0x2
  18:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x18>, r1=<clobbered>
  1c:	3101      	movi	r1, 1	// regs: r1=0x1
  1e:	3003      	movi	r0, 3	// regs: r0=0x3
  20:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x20>, r1=<clobbered>
  24:	3100      	movi	r1, 0	// regs: r1=0x0
  26:	301f      	movi	r0, 31	// regs: r0=0x1f
  28:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x28>, r1=<clobbered>
  2c:	3100      	movi	r1, 0	// regs: r1=0x0
  2e:	301e      	movi	r0, 30	// regs: r0=0x1e
  30:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x30>, r1=<clobbered>
  34:	3100      	movi	r1, 0	// regs: r1=0x0
  36:	3002      	movi	r0, 2	// regs: r0=0x2
  38:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x38>, r1=<clobbered>
  3c:	3100      	movi	r1, 0	// regs: r1=0x0
  3e:	3003      	movi	r0, 3	// regs: r0=0x3
  40:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x40>, r1=<clobbered>
  44:	6110      	addu	r4, r4	// regs: r4=(<arg0> + <arg0>)
  46:	e0000000 	bsr	0x0	// <ft_att_delay> // arg_bytes: 0; regs: r0=<ret ft_att_delay@0x46>, r1=<clobbered>
  4a:	7510      	zextb	r4, r4	// regs: r4=zext8((<arg0> + <arg0>))
  4c:	3505      	movi	r5, 5	// regs: r5=0x5
loc_4e:
  4e:	c4a44081 	asr	r1, r4, r5
  52:	e4212001 	andi	r1, r1, 1	// regs: r1=(<clobbered> & 0x1)
  56:	3003      	movi	r0, 3	// regs: r0=0x3
  58:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x58>, r1=<clobbered>
  5c:	3101      	movi	r1, 1	// regs: r1=0x1
  5e:	3002      	movi	r0, 2	// regs: r0=0x2
  60:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x60>, r1=<clobbered>
  64:	e0000000 	bsr	0x0	// <ft_att_delay> // arg_bytes: 0; regs: r0=<ret ft_att_delay@0x64>, r1=<clobbered>
  68:	3100      	movi	r1, 0	// regs: r1=0x0
  6a:	3002      	movi	r0, 2	// regs: r0=0x2
  6c:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x6c>, r1=<clobbered>
  70:	e0000000 	bsr	0x0	// <ft_att_delay> // arg_bytes: 0; regs: r0=<ret ft_att_delay@0x70>, r1=<clobbered>
  74:	3300      	movi	r3, 0	// regs: r3=0x0
  76:	2d00      	subi	r5, 1	// regs: r5=(r5 - 0x1)
  78:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  7a:	64d6      	cmpne	r5, r3
  7c:	0be9      	bt	0x4e	// if (T) goto loc_4e;
  7e:	3101      	movi	r1, 1	// regs: r1=0x1
  80:	301e      	movi	r0, 30	// regs: r0=0x1e
  82:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x82>, r1=<clobbered>
  86:	e0000000 	bsr	0x0	// <ft_att_delay> // arg_bytes: 0; regs: r0=<ret ft_att_delay@0x86>, r1=<clobbered>
  8a:	3100      	movi	r1, 0	// regs: r1=0x0
  8c:	301e      	movi	r0, 30	// regs: r0=0x1e
  8e:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x8e>, r1=<clobbered>
  92:	e0000000 	bsr	0x0	// <ft_att_delay> // arg_bytes: 0; regs: r0=<ret ft_att_delay@0x92>, r1=<clobbered>
  96:	1492      	pop	r4-r5, r15

Disassembly of section .text.atcmd_reg_rd_hdl:

00000000 <atcmd_reg_rd_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1013      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	e0000000 	bsr	0x0	// <os_atoh>; regs: r0=<ret os_atoh@0x14>, r1=<clobbered>
  18:	33e0      	movi	r3, 224	// regs: r3=0xe0
  1a:	4378      	lsli	r3, r3, 24	// regs: r3=0xe0000000
  1c:	584c      	addu	r2, r0, r3	// regs: r2=(<ret os_atoh@0x14> + 0xe0000000)
  1e:	ea232004 	movih	r3, 8196	// regs: r3=(0x2004 << 0x10)
  22:	2311      	addi	r3, 18	// regs: r3=((0x2004 << 0x10) + 0x12)
  24:	648c      	cmphs	r3, r2
  26:	6d03      	mov	r4, r0	// regs: r4=<ret os_atoh@0x14>
  28:	0c08      	bf	0x38	// if (!T) goto loc_38;
  2a:	9060      	ld.w	r3, (r0, 0x0)	// regs: r3=*(<ret os_atoh@0x14>)
loc_2c:
  2c:	6c93      	mov	r2, r4	// regs: r2=<ret os_atoh@0x14>
  2e:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  30:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  32:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x32>, r1=<clobbered>
  36:	07ec      	br	0xe	// goto loc_e;
loc_38:
  38:	eb00ffff 	cmphsi	r0, 65536
  3c:	0806      	bt	0x48	// if (r0 >= 0x10000) goto loc_48;
  3e:	7401      	zexth	r0, r0	// regs: r0=zext16(<ret os_atoh@0x14>)
  40:	e0000000 	bsr	0x0	// <ah_rf_reg_read>; regs: r0=<ret ah_rf_reg_read@0x40>, r1=<clobbered>
  44:	6cc3      	mov	r3, r0	// regs: r3=<ret ah_rf_reg_read@0x40>
  46:	07f3      	br	0x2c	// goto loc_2c;
loc_48:
  48:	1065      	lrw	r3, 0x0	// regs: r3=0x0
  4a:	3200      	movi	r2, 0	// regs: r2=0x0
  4c:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  4e:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  50:	1064      	lrw	r3, 0xdeaddead	// regs: r3=0xdeaddead
  52:	07ed      	br	0x2c	// goto loc_2c;
  54:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1+0x8>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <lmactest>
  5e:	0000      	.short	0x0000
  60:	deaddead 	.long	0xdeaddead

Disassembly of section .text.atcmd_reg_wt_hdl:

00000000 <atcmd_reg_wt_hdl>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	3a01      	cmphsi	r2, 2
   4:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   6:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   8:	0806      	bt	0x14	// if (r2 >= 0x2) goto loc_14;
   a:	1016      	lrw	r0, 0x0	// regs: r0=0x0
   c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xc>, r1=<clobbered>
loc_10:
  10:	3000      	movi	r0, 0	// regs: r0=0x0
  12:	1493      	pop	r4-r6, r15
loc_14:
  14:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  16:	e0000000 	bsr	0x0	// <os_atoh>; regs: r0=<ret os_atoh@0x16>, r1=<clobbered>
  1a:	6d03      	mov	r4, r0	// regs: r4=<ret os_atoh@0x16>
  1c:	9501      	ld.w	r0, (r5, 0x4)	// regs: r0=*(<arg1> + 0x4)
  1e:	e0000000 	bsr	0x0	// <os_atoh>; regs: r0=<ret os_atoh@0x1e>, r1=<clobbered>
  22:	33e0      	movi	r3, 224	// regs: r3=0xe0
  24:	4378      	lsli	r3, r3, 24	// regs: r3=0xe0000000
  26:	5c4c      	addu	r2, r4, r3	// regs: r2=(<ret os_atoh@0x16> + 0xe0000000)
  28:	ea232004 	movih	r3, 8196	// regs: r3=(0x2004 << 0x10)
  2c:	2311      	addi	r3, 18	// regs: r3=((0x2004 << 0x10) + 0x12)
  2e:	648c      	cmphs	r3, r2
  30:	6d43      	mov	r5, r0	// regs: r5=<ret os_atoh@0x1e>
  32:	0c09      	bf	0x44	// if (!T) goto loc_44;
  34:	b400      	st.w	r0, (r4, 0x0)	// *(<ret os_atoh@0x16>) = <ret os_atoh@0x1e>
loc_36:
  36:	6cd7      	mov	r3, r5	// regs: r3=<ret os_atoh@0x1e>
  38:	6c93      	mov	r2, r4	// regs: r2=<ret os_atoh@0x16>
  3a:	5e26      	addi	r1, r6, 2	// regs: r1=(<arg0> + 0x2)
  3c:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  3e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x3e>, r1=<clobbered>
  42:	07e7      	br	0x10	// goto loc_10;
loc_44:
  44:	eb04ffff 	cmphsi	r4, 65536
  48:	0806      	bt	0x54	// if (r4 >= 0x10000) goto loc_54;
  4a:	7441      	zexth	r1, r0	// regs: r1=zext16(<ret os_atoh@0x1e>)
  4c:	7411      	zexth	r0, r4	// regs: r0=zext16(<ret os_atoh@0x16>)
  4e:	e0000000 	bsr	0x0	// <ah_rf_reg_write>; regs: r0=<ret ah_rf_reg_write@0x4e>, r1=<clobbered>
  52:	07f2      	br	0x36	// goto loc_36;
loc_54:
  54:	1065      	lrw	r3, 0x0	// regs: r3=0x0
  56:	3200      	movi	r2, 0	// regs: r2=0x0
  58:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  5a:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  5c:	07ed      	br	0x36	// goto loc_36;
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_reg_wt_hdl.str1.1>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <lmactest>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_test_start_hdl:

00000000 <atcmd_test_start_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1018      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	1057      	lrw	r2, 0x0	// regs: r2=0x0
  14:	6d4b      	mov	r5, r2	// regs: r5=0x0
  16:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*(0x0)
  18:	e9030019 	bez	r3, 0x4a	// if (r3 == 0x0) goto loc_4a;
  1c:	9140      	ld.w	r2, (r1, 0x0)	// regs: r2=*(<arg1>)
  1e:	8240      	ld.b	r2, (r2, 0x0)	// regs: r2=*(*(<arg1>))
  20:	eb420030 	cmpnei	r2, 48
  24:	0c0b      	bf	0x3a	// if (r2 == 0x30) goto loc_3a;
  26:	eb42003f 	cmpnei	r2, 63
  2a:	0c10      	bf	0x4a	// if (r2 == 0x3f) goto loc_4a;
  2c:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*((*(0x0) + 0xa))
  2e:	3100      	movi	r1, 0	// regs: r1=0x0
  30:	c4415c00 	ins	r2, r1, 0, 0
  34:	a34a      	st.b	r2, (r3, 0xa)	// *((*(0x0) + 0xa)) = *((*(0x0) + 0xa))
  36:	3001      	movi	r0, 1	// regs: r0=0x1
  38:	0407      	br	0x46	// goto loc_46;
loc_3a:
  3a:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*((*(0x0) + 0xa))
  3c:	3101      	movi	r1, 1	// regs: r1=0x1
  3e:	c4415c00 	ins	r2, r1, 0, 0
  42:	a34a      	st.b	r2, (r3, 0xa)	// *((*(0x0) + 0xa)) = *((*(0x0) + 0xa))
  44:	3000      	movi	r0, 0	// regs: r0=0x0
loc_46:
  46:	e0000000 	bsr	0x0	// <lmac_test_enable> // arg_bytes: 4; regs: r0=<ret lmac_test_enable@0x46>, r1=<clobbered>
loc_4a:
  4a:	d86509e2 	ld.b	r3, (r5, 0x9e2)	// regs: r3=*(0x9e2)
  4e:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  52:	3b40      	cmpnei	r3, 0
  54:	1047      	lrw	r2, 0x0	// regs: r2=0x0
  56:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  58:	c4430c20 	incf	r2, r3, 0
  5c:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  5e:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  60:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x60>, r1=<clobbered>
  64:	07d5      	br	0xe	// goto loc_e;
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  6a:	0000      	.short	0x0000
  6c:	0000      	.short	0x0000	// <ah_lmac>
  6e:	0000      	.short	0x0000
  70:	00000000 	.long	0x00000000	// <.rodata.atcmd_test_start_hdl.str1.1>
  74:	0000      	.short	0x0000	// <.rodata.atcmd_test_start_hdl.str1.1+0x8>
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000	// <.rodata.atcmd_test_start_hdl.str1.1+0xf>

Disassembly of section .text.atcmd_tx_dst_addr_hdl:

00000000 <atcmd_tx_dst_addr_hdl>: // arg_bytes: 12
   0:	14d1      	push	r4, r15
   2:	1424      	subi	r14, r14, 16	// regs: r14=(sp - 0x10)
   4:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   6:	e9220008 	bnez	r2, 0x16	// if (r2 != 0x0) goto loc_16;
   a:	1013      	lrw	r0, 0x0	// regs: r0=0x0
   c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xc>, r1=<clobbered>
loc_10:
  10:	3000      	movi	r0, 0	// regs: r0=0x0
  12:	1404      	addi	r14, r14, 16	// regs: r14=((sp - 0x10) + 0x10)
  14:	1491      	pop	r4, r15
loc_16:
  16:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  18:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  1a:	eb43003f 	cmpnei	r3, 63
  1e:	0c04      	bf	0x26	// if (r3 == 0x3f) goto loc_26;
  20:	102e      	lrw	r1, 0x0	// regs: r1=0x0
  22:	e0000000 	bsr	0x0	// <str2mac>; regs: r0=<ret str2mac@0x22>, r1=<clobbered>
loc_26:
  26:	102e      	lrw	r1, 0x0	// regs: r1=0x0
  28:	d801002d 	ld.b	r0, (r1, 0x2d)	// regs: r0=*(0x2d)
  2c:	d8610029 	ld.b	r3, (r1, 0x29)	// regs: r3=*(0x29)
  30:	d8410028 	ld.b	r2, (r1, 0x28)	// regs: r2=*(0x28)
  34:	b803      	st.w	r0, (r14, 0xc)	// local_4 = *(0x2d)
  36:	d801002c 	ld.b	r0, (r1, 0x2c)	// regs: r0=*(0x2c)
  3a:	b802      	st.w	r0, (r14, 0x8)	// local_8 = *(0x2c)
  3c:	d801002b 	ld.b	r0, (r1, 0x2b)	// regs: r0=*(0x2b)
  40:	b801      	st.w	r0, (r14, 0x4)	// local_c = *(0x2b)
  42:	d821002a 	ld.b	r1, (r1, 0x2a)	// regs: r1=*(0x2a)
  46:	b820      	st.w	r1, (r14, 0x0)	// local_10 = *(0x2a)
  48:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  4a:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  4c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4c>, r1=<clobbered>
  50:	07e0      	br	0x10	// goto loc_10;
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <lmactest+0x28>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <lmactest>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_dst_addr_hdl.str1.1>

Disassembly of section .text.atcmd_tx_fc_hdl:

00000000 <atcmd_tx_fc_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100a      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1088      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c04      	bf	0x24	// if (r3 == 0x3f) goto loc_24;
  1e:	e0000000 	bsr	0x0	// <os_atoh>; regs: r0=<ret os_atoh@0x1e>, r1=<clobbered>
  22:	ac12      	st.h	r0, (r4, 0x24)	// *(0x24) = <ret os_atoh@0x1e>
loc_24:
  24:	8c52      	ld.h	r2, (r4, 0x24)	// regs: r2=*(0x24)
  26:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  28:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2a>, r1=<clobbered>
  2e:	07f0      	br	0xe	// goto loc_e;
  30:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <lmactest>
  38:	0000      	.short	0x0000	// <.rodata.atcmd_tx_fc_hdl.str1.1>
  3a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_flags_hdl:

00000000 <atcmd_tx_flags_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100a      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1088      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c04      	bf	0x24	// if (r3 == 0x3f) goto loc_24;
  1e:	e0000000 	bsr	0x0	// <os_atoh>; regs: r0=<ret os_atoh@0x1e>, r1=<clobbered>
  22:	b40f      	st.w	r0, (r4, 0x3c)	// *(0x3c) = <ret os_atoh@0x1e>
loc_24:
  24:	944f      	ld.w	r2, (r4, 0x3c)	// regs: r2=*(0x3c)
  26:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  28:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2a>, r1=<clobbered>
  2e:	07f0      	br	0xe	// goto loc_e;
  30:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <lmactest>
  38:	0000      	.short	0x0000	// <.rodata.atcmd_tx_flags_hdl.str1.1>
  3a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_len_hdl:

00000000 <atcmd_tx_len_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100e      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108c      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c07      	bf	0x2a	// if (r3 == 0x3f) goto loc_2a;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	e960000b 	blsz	r0, 0x38
  26:	dc041020 	st.h	r0, (r4, 0x40)	// *(0x40) = <ret atoi@0x1e>
loc_2a:
  2a:	d8441020 	ld.h	r2, (r4, 0x40)	// regs: r2=*(r4 + 0x40)
  2e:	5d26      	addi	r1, r5, 2	// regs: r1=(r5 + 0x2)
  30:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  32:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x32>, r1=<clobbered>
  36:	07ec      	br	0xe	// goto loc_e;
  38:	3300      	movi	r3, 0	// regs: r3=0x0
  3a:	2b01      	subi	r3, 2	// regs: r3=0xfffffffe
  3c:	b472      	st.w	r3, (r4, 0x48)	// *(r4 + 0x48) = 0xfffffffe
  3e:	07f6      	br	0x2a	// goto loc_2a;
  40:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <lmactest>
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <.rodata.atcmd_tx_len_hdl.str1.1>
  4a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_type_hdl:

00000000 <atcmd_tx_type_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1203      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  14:	1281      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c23      	bf	0x62	// if (r3 == 0x3f) goto loc_62;
  1e:	eb430054 	cmpnei	r3, 84
  22:	0c51      	bf	0xc4	// if (r3 == 0x54) goto loc_c4;
  24:	eb030054 	cmphsi	r3, 85
  28:	080b      	bt	0x3e	// if (r3 >= 0x55) goto loc_3e;
  2a:	eb43004e 	cmpnei	r3, 78
  2e:	0c11      	bf	0x50	// if (r3 == 0x4e) goto loc_50;
  30:	eb430053 	cmpnei	r3, 83
  34:	0c20      	bf	0x74	// if (r3 == 0x53) goto loc_74;
loc_36:
  36:	3300      	movi	r3, 0	// regs: r3=0x0
  38:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  3a:	b472      	st.w	r3, (r4, 0x48)	// *(0x48) = 0xffffffff
  3c:	0413      	br	0x62	// goto loc_62;
loc_3e:
  3e:	eb430073 	cmpnei	r3, 115
  42:	0c19      	bf	0x74	// if (r3 == 0x73) goto loc_74;
  44:	eb430074 	cmpnei	r3, 116
  48:	0c3e      	bf	0xc4	// if (r3 == 0x74) goto loc_c4;
  4a:	eb43006e 	cmpnei	r3, 110
  4e:	0bf4      	bt	0x36	// if (r3 != 0x6e) goto loc_36;
loc_50:
  50:	d8640042 	ld.b	r3, (r4, 0x42)	// regs: r3=*(0x42)
  54:	3200      	movi	r2, 0	// regs: r2=0x0
  56:	c4625c21 	ins	r3, r2, 2, 1
  5a:	dc640042 	st.b	r3, (r4, 0x42)	// *(0x42) = *(0x42)
  5e:	e0000000 	bsr	0x0	// <ah_wphy_tx_norm_mode_cfg>; regs: r0=<ret ah_wphy_tx_norm_mode_cfg@0x5e>, r1=<clobbered>
loc_62:
  62:	d8440042 	ld.b	r2, (r4, 0x42)	// regs: r2=*(0x42)
  66:	c4225442 	zext	r2, r2, 2, 1	// regs: r2=zext(*(0x42))
  6a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  6c:	110c      	lrw	r0, 0x0	// regs: r0=0x0
  6e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x6e>, r1=<clobbered>
  72:	07ce      	br	0xe	// goto loc_e;
loc_74:
  74:	d8640042 	ld.b	r3, (r4, 0x42)	// regs: r3=*(0x42)
  78:	3201      	movi	r2, 1	// regs: r2=0x1
  7a:	c4625c21 	ins	r3, r2, 2, 1
  7e:	dc640042 	st.b	r3, (r4, 0x42)	// *(0x42) = *(0x42)
  82:	74cc      	zextb	r3, r3	// regs: r3=zext8(*(0x42))
  84:	e4432018 	andi	r2, r3, 24	// regs: r2=(zext8(*(0x42)) & 0x18)
  88:	e9220007 	bnez	r2, 0x96	// if (r2 != 0x0) goto loc_96;
  8c:	3202      	movi	r2, 2	// regs: r2=0x2
  8e:	c4625c23 	ins	r3, r2, 4, 3
  92:	dc640042 	st.b	r3, (r4, 0x42)	// *(0x42) = zext8(*(0x42))
loc_96:
  96:	d8641021 	ld.h	r3, (r4, 0x42)	// regs: r3=*(0x42)
  9a:	ea023fe0 	movi	r2, 16352	// regs: r2=0x3fe0
  9e:	688c      	and	r2, r3	// regs: r2=(0x3fe0 & *(0x42))
  a0:	e9220007 	bnez	r2, 0xae	// if (r2 != 0x0) goto loc_ae;
  a4:	3201      	movi	r2, 1	// regs: r2=0x1
  a6:	c4625d05 	ins	r3, r2, 13, 5
  aa:	dc641021 	st.h	r3, (r4, 0x42)	// *(0x42) = *(0x42)
loc_ae:
  ae:	d8241021 	ld.h	r1, (r4, 0x42)	// regs: r1=*(0x42)
  b2:	d8040042 	ld.b	r0, (r4, 0x42)	// regs: r0=*(0x42)
  b6:	c4a155a1 	zext	r1, r1, 13, 5	// regs: r1=zext(*(0x42))
  ba:	c4605480 	zext	r0, r0, 4, 3	// regs: r0=zext(*(0x42))
  be:	e0000000 	bsr	0x0	// <ah_wphy_tx_sine_mode_cfg>; regs: r0=<ret ah_wphy_tx_sine_mode_cfg@0xbe>, r1=<clobbered>
  c2:	07d0      	br	0x62	// goto loc_62;
loc_c4:
  c4:	d8640042 	ld.b	r3, (r4, 0x42)	// regs: r3=*(0x42)
  c8:	3202      	movi	r2, 2	// regs: r2=0x2
  ca:	c4625c21 	ins	r3, r2, 2, 1
  ce:	dc640042 	st.b	r3, (r4, 0x42)	// *(0x42) = *(0x42)
  d2:	74cc      	zextb	r3, r3	// regs: r3=zext8(*(0x42))
  d4:	e4232018 	andi	r1, r3, 24	// regs: r1=(zext8(*(0x42)) & 0x18)
  d8:	e9210006 	bnez	r1, 0xe4	// if (r1 != 0x0) goto loc_e4;
  dc:	c4625c23 	ins	r3, r2, 4, 3
  e0:	dc640042 	st.b	r3, (r4, 0x42)	// *(0x42) = zext8(*(0x42))
loc_e4:
  e4:	d8641021 	ld.h	r3, (r4, 0x42)	// regs: r3=*(0x42)
  e8:	ea023fe0 	movi	r2, 16352	// regs: r2=0x3fe0
  ec:	688c      	and	r2, r3	// regs: r2=(0x3fe0 & *(0x42))
  ee:	e9220007 	bnez	r2, 0xfc	// if (r2 != 0x0) goto loc_fc;
  f2:	3201      	movi	r2, 1	// regs: r2=0x1
  f4:	c4625d05 	ins	r3, r2, 13, 5
  f8:	dc641021 	st.h	r3, (r4, 0x42)	// *(0x42) = *(0x42)
loc_fc:
  fc:	d8241021 	ld.h	r1, (r4, 0x42)	// regs: r1=*(0x42)
 100:	d8040042 	ld.b	r0, (r4, 0x42)	// regs: r0=*(0x42)
 104:	c4a155a1 	zext	r1, r1, 13, 5	// regs: r1=zext(*(0x42))
 108:	c4605480 	zext	r0, r0, 4, 3	// regs: r0=zext(*(0x42))
 10c:	e0000000 	bsr	0x0	// <ah_wphy_tx_tri_mode_cfg>; regs: r0=<ret ah_wphy_tx_tri_mode_cfg@0x10c>, r1=<clobbered>
 110:	07a9      	br	0x62	// goto loc_62;
 112:	0000      	.short	0x0000
 114:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
 118:	00000000 	.long	0x00000000	// <lmactest>
 11c:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_type_hdl.str1.1>

Disassembly of section .text.atcmd_tx_pha_amp_hdl:

00000000 <atcmd_tx_pha_amp_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1102      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1180      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c1f      	bf	0x5a	// if (r3 == 0x3f) goto loc_5a;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	3803      	cmphsi	r0, 4
  24:	0815      	bt	0x4e	// if (r0 >= 0x4) goto loc_4e;
  26:	d8640042 	ld.b	r3, (r4, 0x42)	// regs: r3=*(0x42)
  2a:	c4605c23 	ins	r3, r0, 4, 3
  2e:	dc640042 	st.b	r3, (r4, 0x42)	// *(0x42) = *(0x42)
loc_32:
  32:	d8040042 	ld.b	r0, (r4, 0x42)	// regs: r0=*(0x42)
  36:	c4205443 	zext	r3, r0, 2, 1	// regs: r3=zext(*(0x42))
  3a:	3b41      	cmpnei	r3, 1
  3c:	0c18      	bf	0x6c	// if (r3 == 0x1) goto loc_6c;
  3e:	3b40      	cmpnei	r3, 0
  40:	0c0b      	bf	0x56	// if (r3 == 0x0) goto loc_56;
  42:	3b42      	cmpnei	r3, 2
  44:	0c1d      	bf	0x7e	// if (r3 == 0x2) goto loc_7e;
  46:	3300      	movi	r3, 0	// regs: r3=0x0
  48:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  4a:	b472      	st.w	r3, (r4, 0x48)	// *(0x48) = 0xffffffff
  4c:	0407      	br	0x5a	// goto loc_5a;
loc_4e:
  4e:	3300      	movi	r3, 0	// regs: r3=0x0
  50:	2b02      	subi	r3, 3	// regs: r3=0xfffffffd
  52:	b472      	st.w	r3, (r4, 0x48)	// *(0x48) = 0xfffffffd
  54:	07ef      	br	0x32	// goto loc_32;
loc_56:
  56:	e0000000 	bsr	0x0	// <ah_wphy_tx_norm_mode_cfg>; regs: r0=<ret ah_wphy_tx_norm_mode_cfg@0x56>, r1=<clobbered>
loc_5a:
  5a:	d8440042 	ld.b	r2, (r4, 0x42)	// regs: r2=*(0x42)
  5e:	c4625482 	zext	r2, r2, 4, 3	// regs: r2=zext(*(0x42))
  62:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  64:	100d      	lrw	r0, 0x0	// regs: r0=0x0
  66:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x66>, r1=<clobbered>
  6a:	07d2      	br	0xe	// goto loc_e;
loc_6c:
  6c:	d8241021 	ld.h	r1, (r4, 0x42)	// regs: r1=*(0x42)
  70:	c4a155a1 	zext	r1, r1, 13, 5	// regs: r1=zext(*(0x42))
  74:	c4605480 	zext	r0, r0, 4, 3	// regs: r0=zext(*(0x42))
  78:	e0000000 	bsr	0x0	// <ah_wphy_tx_sine_mode_cfg>; regs: r0=<ret ah_wphy_tx_sine_mode_cfg@0x78>, r1=<clobbered>
  7c:	07ef      	br	0x5a	// goto loc_5a;
loc_7e:
  7e:	d8241021 	ld.h	r1, (r4, 0x42)	// regs: r1=*(0x42)
  82:	c4a155a1 	zext	r1, r1, 13, 5	// regs: r1=zext(*(0x42))
  86:	c4605480 	zext	r0, r0, 4, 3	// regs: r0=zext(*(0x42))
  8a:	e0000000 	bsr	0x0	// <ah_wphy_tx_tri_mode_cfg>; regs: r0=<ret ah_wphy_tx_tri_mode_cfg@0x8a>, r1=<clobbered>
  8e:	07e6      	br	0x5a	// goto loc_5a;
  90:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  92:	0000      	.short	0x0000
  94:	0000      	.short	0x0000	// <lmactest>
  96:	0000      	.short	0x0000
  98:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_pha_amp_hdl.str1.1>

Disassembly of section .text.atcmd_tx_step_hdl:

00000000 <atcmd_tx_step_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1103      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1181      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c28      	bf	0x6c	// if (r3 == 0x3f) goto loc_6c;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	eb2001ff 	cmplti	r0, 512
  26:	081a      	bt	0x5a	// if (r0 < 0x200) goto loc_5a;
  28:	3300      	movi	r3, 0	// regs: r3=0x0
  2a:	2b02      	subi	r3, 3	// regs: r3=0xfffffffd
  2c:	b472      	st.w	r3, (r4, 0x48)	// *(0x48) = 0xfffffffd
  2e:	ea0001ff 	movi	r0, 511	// regs: r0=0x1ff
loc_32:
  32:	d8641021 	ld.h	r3, (r4, 0x42)	// regs: r3=*(0x42)
  36:	c4605d05 	ins	r3, r0, 13, 5
  3a:	7441      	zexth	r1, r0	// regs: r1=zext16(r0)
  3c:	740c      	zextb	r0, r3	// regs: r0=zext8(*(0x42))
  3e:	dc641021 	st.h	r3, (r4, 0x42)	// *(0x42) = *(0x42)
  42:	c4205443 	zext	r3, r0, 2, 1	// regs: r3=zext(zext8(*(0x42)))
  46:	3b41      	cmpnei	r3, 1
  48:	0c1b      	bf	0x7e	// if (r3 == 0x1) goto loc_7e;
  4a:	3b40      	cmpnei	r3, 0
  4c:	0c0e      	bf	0x68	// if (r3 == 0x0) goto loc_68;
  4e:	3b42      	cmpnei	r3, 2
  50:	0c1c      	bf	0x88	// if (r3 == 0x2) goto loc_88;
  52:	3300      	movi	r3, 0	// regs: r3=0x0
  54:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  56:	b472      	st.w	r3, (r4, 0x48)	// *(0x48) = 0xffffffff
  58:	040a      	br	0x6c	// goto loc_6c;
loc_5a:
  5a:	e9a0ffec 	bhsz	r0, 0x32	// if (r0 >= 0x0) goto loc_32;
  5e:	3300      	movi	r3, 0	// regs: r3=0x0
  60:	2b01      	subi	r3, 2	// regs: r3=0xfffffffe
  62:	b472      	st.w	r3, (r4, 0x48)	// *(0x48) = 0xfffffffe
  64:	3000      	movi	r0, 0	// regs: r0=0x0
  66:	07e6      	br	0x32	// goto loc_32;
loc_68:
  68:	e0000000 	bsr	0x0	// <ah_wphy_tx_norm_mode_cfg>; regs: r0=<ret ah_wphy_tx_norm_mode_cfg@0x68>, r1=<clobbered>
loc_6c:
  6c:	d8441021 	ld.h	r2, (r4, 0x42)	// regs: r2=*(0x42)
  70:	c4a255a2 	zext	r2, r2, 13, 5	// regs: r2=zext(*(0x42))
  74:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  76:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  78:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x78>, r1=<clobbered>
  7c:	07c9      	br	0xe	// goto loc_e;
loc_7e:
  7e:	c4605480 	zext	r0, r0, 4, 3	// regs: r0=zext(zext8(*(0x42)))
  82:	e0000000 	bsr	0x0	// <ah_wphy_tx_sine_mode_cfg>; regs: r0=<ret ah_wphy_tx_sine_mode_cfg@0x82>, r1=<clobbered>
  86:	07f3      	br	0x6c	// goto loc_6c;
loc_88:
  88:	c4605480 	zext	r0, r0, 4, 3	// regs: r0=zext(zext8(*(0x42)))
  8c:	e0000000 	bsr	0x0	// <ah_wphy_tx_tri_mode_cfg>; regs: r0=<ret ah_wphy_tx_tri_mode_cfg@0x8c>, r1=<clobbered>
  90:	07ee      	br	0x6c	// goto loc_6c;
  92:	0000      	.short	0x0000
  94:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  96:	0000      	.short	0x0000
  98:	00000000 	.long	0x00000000	// <lmactest>
  9c:	0000      	.short	0x0000	// <.rodata.atcmd_tx_step_hdl.str1.1>
  9e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_cont_hdl:

00000000 <atcmd_tx_cont_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1107      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  14:	1185      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c20      	bf	0x5c	// if (r3 == 0x3f) goto loc_5c;
  1e:	eb430030 	cmpnei	r3, 48
  22:	0c08      	bf	0x32	// if (r3 == 0x30) goto loc_32;
  24:	eb430031 	cmpnei	r3, 49
  28:	0c28      	bf	0x78	// if (r3 == 0x31) goto loc_78;
  2a:	3300      	movi	r3, 0	// regs: r3=0x0
  2c:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  2e:	b472      	st.w	r3, (r4, 0x48)	// *(0x48) = 0xffffffff
  30:	0416      	br	0x5c	// goto loc_5c;
loc_32:
  32:	d8640042 	ld.b	r3, (r4, 0x42)	// regs: r3=*(0x42)
  36:	3100      	movi	r1, 0	// regs: r1=0x0
  38:	c4615c00 	ins	r3, r1, 0, 0
  3c:	dc640042 	st.b	r3, (r4, 0x42)	// *(0x42) = *(0x42)
  40:	107b      	lrw	r3, 0x0	// regs: r3=0x0
  42:	d84309e2 	ld.b	r2, (r3, 0x9e2)	// regs: r2=*(0x9e2)
  46:	c4415c04 	ins	r2, r1, 4, 4
  4a:	dc4309e2 	st.b	r2, (r3, 0x9e2)	// *(0x9e2) = *(0x9e2)
  4e:	e0000000 	bsr	0x0	// <ah_wphy_cont_tx_disable>; regs: r0=<ret ah_wphy_cont_tx_disable@0x4e>, r1=<clobbered>
  52:	1078      	lrw	r3, 0x0	// regs: r3=0x0
  54:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
  56:	9271      	ld.w	r3, (r2, 0x44)	// regs: r3=*((*(0x0) + 0x44))
  58:	3bb4      	bseti	r3, 20	// regs: r3=(*((*(0x0) + 0x44)) | (0x1 << 0x14))
loc_5a:
  5a:	b271      	st.w	r3, (r2, 0x44)	// *((*(0x0) + 0x44)) = r3
loc_5c:
  5c:	d8640042 	ld.b	r3, (r4, 0x42)	// regs: r3=*(0x42)
  60:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x42) & 0x1)
  64:	3b40      	cmpnei	r3, 0
  66:	1054      	lrw	r2, 0x0	// regs: r2=0x0
  68:	1074      	lrw	r3, 0x0	// regs: r3=0x0
  6a:	c4430c20 	incf	r2, r3, 0
  6e:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  70:	1013      	lrw	r0, 0x0	// regs: r0=0x0
  72:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x72>, r1=<clobbered>
  76:	07cc      	br	0xe	// goto loc_e;
loc_78:
  78:	d8640042 	ld.b	r3, (r4, 0x42)	// regs: r3=*(0x42)
  7c:	3101      	movi	r1, 1	// regs: r1=0x1
  7e:	c4615c00 	ins	r3, r1, 0, 0
  82:	dc640042 	st.b	r3, (r4, 0x42)	// *(0x42) = *(0x42)
  86:	106a      	lrw	r3, 0x0	// regs: r3=0x0
  88:	d84309e2 	ld.b	r2, (r3, 0x9e2)	// regs: r2=*(0x9e2)
  8c:	c4415c04 	ins	r2, r1, 4, 4
  90:	dc4309e2 	st.b	r2, (r3, 0x9e2)	// *(0x9e2) = *(0x9e2)
  94:	e0000000 	bsr	0x0	// <ah_wphy_cont_tx_enable>; regs: r0=<ret ah_wphy_cont_tx_enable@0x94>, r1=<clobbered>
  98:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  9a:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
  9c:	9271      	ld.w	r3, (r2, 0x44)	// regs: r3=*((*(0x0) + 0x44))
  9e:	3b94      	bclri	r3, 20	// regs: r3=(*((*(0x0) + 0x44)) & ~(0x1 << 0x14))
  a0:	07dd      	br	0x5a	// goto loc_5a;
  a2:	0000      	.short	0x0000
  a4:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  a6:	0000      	.short	0x0000
  a8:	00000000 	.long	0x00000000	// <lmactest>
  ac:	00000000 	.long	0x00000000	// <ah_lmac>
  b0:	00000000 	.long	0x00000000	// <LMAC>
  b4:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  b6:	0000      	.short	0x0000
  b8:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  bc:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x11>

Disassembly of section .text.atcmd_tx_start_hdl:

00000000 <atcmd_tx_start_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	101d      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	105b      	lrw	r2, 0x0	// regs: r2=0x0
  14:	8320      	ld.b	r1, (r3, 0x0)	// regs: r1=*(*(<arg1>))
  16:	eb41003f 	cmpnei	r1, 63
  1a:	0c19      	bf	0x4c	// if (r1 == 0x3f) goto loc_4c;
  1c:	d86209e2 	ld.b	r3, (r2, 0x9e2)	// regs: r3=*(0x9e2)
  20:	e5832002 	andi	r12, r3, 2	// regs: r12=(*(0x9e2) & 0x2)
  24:	e90c0026 	bez	r12, 0x70	// if (r12 == 0x0) goto loc_70;
  28:	eb410030 	cmpnei	r1, 48
  2c:	0c09      	bf	0x3e	// if (r1 == 0x30) goto loc_3e;
  2e:	eb410031 	cmpnei	r1, 49
  32:	0c1b      	bf	0x68	// if (r1 == 0x31) goto loc_68;
  34:	3100      	movi	r1, 0	// regs: r1=0x0
  36:	1073      	lrw	r3, 0x0	// regs: r3=0x0
  38:	2901      	subi	r1, 2	// regs: r1=0xfffffffe
loc_3a:
  3a:	b332      	st.w	r1, (r3, 0x48)	// *(0x48) = r1
  3c:	0408      	br	0x4c	// goto loc_4c;
loc_3e:
  3e:	e46320f7 	andi	r3, r3, 247	// regs: r3=(*(0x9e2) & 0xf7)
loc_42:
  42:	3100      	movi	r1, 0	// regs: r1=0x0
  44:	c4615c05 	ins	r3, r1, 5, 5
  48:	dc6209e2 	st.b	r3, (r2, 0x9e2)	// *(0x9e2) = r3
loc_4c:
  4c:	d86209e2 	ld.b	r3, (r2, 0x9e2)	// regs: r3=*(0x9e2)
  50:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x9e2) & 0x8)
  54:	3b40      	cmpnei	r3, 0
  56:	104c      	lrw	r2, 0x0	// regs: r2=0x0
  58:	106c      	lrw	r3, 0x0	// regs: r3=0x0
  5a:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  5c:	c4430c20 	incf	r2, r3, 0
  60:	100b      	lrw	r0, 0x0	// regs: r0=0x0
  62:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x62>, r1=<clobbered>
  66:	07d3      	br	0xc	// goto loc_c;
loc_68:
  68:	3101      	movi	r1, 1	// regs: r1=0x1
  6a:	c4615c03 	ins	r3, r1, 3, 3
  6e:	07ea      	br	0x42	// goto loc_42;
loc_70:
  70:	3100      	movi	r1, 0	// regs: r1=0x0
  72:	1064      	lrw	r3, 0x0	// regs: r3=0x0
  74:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  76:	07e2      	br	0x3a	// goto loc_3a;
  78:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  7c:	00000000 	.long	0x00000000	// <ah_lmac>
  80:	00000000 	.long	0x00000000	// <lmactest>
  84:	0000      	.short	0x0000	// <.rodata.atcmd_test_start_hdl.str1.1>
  86:	0000      	.short	0x0000
  88:	00000000 	.long	0x00000000	// <.rodata.atcmd_test_start_hdl.str1.1+0x8>
  8c:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_start_hdl.str1.1>

Disassembly of section .text.atcmd_tx_trig_hdl:

00000000 <atcmd_tx_trig_hdl>: // arg_bytes: 12
   0:	14d4      	push	r4-r7, r15
   2:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1104      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1494      	pop	r4-r7, r15
loc_12:
  12:	1183      	lrw	r4, 0x0	// regs: r4=0x0
  14:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  18:	e4432002 	andi	r2, r3, 2	// regs: r2=(*(0x9e2) & 0x2)
  1c:	e9020038 	bez	r2, 0x8c	// if (r2 == 0x0) goto loc_8c;
  20:	9140      	ld.w	r2, (r1, 0x0)	// regs: r2=*(<arg1>)
  22:	8240      	ld.b	r2, (r2, 0x0)	// regs: r2=*(*(<arg1>))
  24:	eb420031 	cmpnei	r2, 49
  28:	082c      	bt	0x80	// if (r2 != 0x31) goto loc_80;
  2a:	e46320f7 	andi	r3, r3, 247	// regs: r3=(*(0x9e2) & 0xf7)
  2e:	3201      	movi	r2, 1	// regs: r2=0x1
  30:	c4625c05 	ins	r3, r2, 5, 5
  34:	dc6409e2 	st.b	r3, (r4, 0x9e2)	// *(0x9e2) = (*(0x9e2) & 0xf7)
  38:	10fa      	lrw	r7, 0x0	// regs: r7=0x0
loc_3a:
  3a:	d8071020 	ld.h	r0, (r7, 0x40)	// regs: r0=*(0x40)
  3e:	209d      	addi	r0, 158	// regs: r0=(*(0x40) + 0x9e)
  40:	e0000000 	bsr	0x0	// <alloc_tx_skb>; regs: r0=<ret alloc_tx_skb@0x40>, r1=<clobbered>
  44:	6d43      	mov	r5, r0	// regs: r5=<ret alloc_tx_skb@0x40>
  46:	e900fffa 	bez	r0, 0x3a	// if (r0 == 0x0) goto loc_3a;
  4a:	3206      	movi	r2, 6	// regs: r2=0x6
  4c:	1036      	lrw	r1, 0x0	// regs: r1=0x0
  4e:	1017      	lrw	r0, 0x0	// regs: r0=0x0
  50:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x50>, r1=<clobbered>
  54:	6c17      	mov	r0, r5	// regs: r0=<ret alloc_tx_skb@0x40>
  56:	e0000000 	bsr	0x0	// <lmac_test_txskb_init> // arg_bytes: 4; regs: r0=<ret lmac_test_txskb_init@0x56>, r1=<clobbered>
  5a:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
  5c:	6c57      	mov	r1, r5	// regs: r1=<ret alloc_tx_skb@0x40>
  5e:	9346      	ld.w	r2, (r3, 0x18)	// regs: r2=*((*(0x0) + 0x18))
  60:	9300      	ld.w	r0, (r3, 0x0)	// regs: r0=*(*(0x0))
  62:	7bc9      	jsr	r2
loc_64:
  64:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  68:	e4632020 	andi	r3, r3, 32	// regs: r3=(*(0x9e2) & 0x20)
  6c:	3b40      	cmpnei	r3, 0
  6e:	1050      	lrw	r2, 0x0	// regs: r2=0x0
  70:	1070      	lrw	r3, 0x0	// regs: r3=0x0
  72:	c4430c20 	incf	r2, r3, 0
  76:	5e26      	addi	r1, r6, 2	// regs: r1=(<arg0> + 0x2)
  78:	100f      	lrw	r0, 0x0	// regs: r0=0x0
  7a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x7a>, r1=<clobbered>
  7e:	07c8      	br	0xe	// goto loc_e;
loc_80:
  80:	3200      	movi	r2, 0	// regs: r2=0x0
  82:	c4625c05 	ins	r3, r2, 5, 5
  86:	dc6409e2 	st.b	r3, (r4, 0x9e2)	// *(0x9e2) = *(0x9e2)
  8a:	07ed      	br	0x64	// goto loc_64;
loc_8c:
  8c:	1065      	lrw	r3, 0x0	// regs: r3=0x0
  8e:	3200      	movi	r2, 0	// regs: r2=0x0
  90:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  92:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  94:	07e8      	br	0x64	// goto loc_64;
  96:	0000      	.short	0x0000
  98:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  9c:	0000      	.short	0x0000	// <ah_lmac>
  9e:	0000      	.short	0x0000
  a0:	0000      	.short	0x0000	// <lmactest>
  a2:	0000      	.short	0x0000
  a4:	0000      	.short	0x0000	// <ah_lmac+0x302>
  a6:	0000      	.short	0x0000
  a8:	00000000 	.long	0x00000000	// <lmactest+0x2e>
  ac:	00000000 	.long	0x00000000	// <.rodata.atcmd_test_start_hdl.str1.1>
  b0:	00000000 	.long	0x00000000	// <.rodata.atcmd_test_start_hdl.str1.1+0x8>
  b4:	0000      	.short	0x0000	// <.rodata.atcmd_tx_trig_hdl.str1.1>
  b6:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_mcs_hdl:

00000000 <atcmd_tx_mcs_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1089      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c05      	bf	0x26	// if (r3 == 0x3f) goto loc_26;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	dc040866 	st.b	r0, (r4, 0x866)	// *(0x866) = <ret atoi@0x1e>
loc_26:
  26:	d8440866 	ld.b	r2, (r4, 0x866)	// regs: r2=*(0x866)
  2a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  2c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2e>, r1=<clobbered>
  32:	07ee      	br	0xe	// goto loc_e;
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_tx_mcs_hdl.str1.1>
  3e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_mcast_mcs_hdl:

00000000 <atcmd_mcast_mcs_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1089      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c05      	bf	0x26	// if (r3 == 0x3f) goto loc_26;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	dc040868 	st.b	r0, (r4, 0x868)	// *(0x868) = <ret atoi@0x1e>
loc_26:
  26:	d8440868 	ld.b	r2, (r4, 0x868)	// regs: r2=*(0x868)
  2a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  2c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2e>, r1=<clobbered>
  32:	07ee      	br	0xe	// goto loc_e;
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_mcast_mcs_hdl.str1.1>
  3e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_mcs_max_hdl:

00000000 <atcmd_tx_mcs_max_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1089      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c05      	bf	0x26	// if (r3 == 0x3f) goto loc_26;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	dc040864 	st.b	r0, (r4, 0x864)	// *(0x864) = <ret atoi@0x1e>
loc_26:
  26:	d8440864 	ld.b	r2, (r4, 0x864)	// regs: r2=*(0x864)
  2a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  2c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2e>, r1=<clobbered>
  32:	07ee      	br	0xe	// goto loc_e;
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_tx_mcs_max_hdl.str1.1>
  3e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_mcs_min_hdl:

00000000 <atcmd_tx_mcs_min_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100c      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108a      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c07      	bf	0x2a	// if (r3 == 0x3f) goto loc_2a;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	3807      	cmphsi	r0, 8
  24:	0803      	bt	0x2a	// if (r0 >= 0x8) goto loc_2a;
  26:	dc040865 	st.b	r0, (r4, 0x865)	// *(0x865) = <ret atoi@0x1e>
loc_2a:
  2a:	d8440865 	ld.b	r2, (r4, 0x865)	// regs: r2=*(0x865)
  2e:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  30:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  32:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x32>, r1=<clobbered>
  36:	07ec      	br	0xe	// goto loc_e;
  38:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <ah_lmac>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.rodata.atcmd_tx_mcs_min_hdl.str1.1>
  42:	0000      	.short	0x0000

Disassembly of section .text.atcmd_ant_dual_hdl:

00000000 <atcmd_ant_dual_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1011      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108f      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c09      	bf	0x2e	// if (r3 == 0x3f) goto loc_2e;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	6c83      	mov	r2, r0	// regs: r2=<ret atoi@0x1e>
  24:	3300      	movi	r3, 0	// regs: r3=0x0
  26:	3129      	movi	r1, 41	// regs: r1=0x29
  28:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(0x0)
  2a:	e0000000 	bsr	0x0	// <lmac_ioctl>; regs: r0=<ret lmac_ioctl@0x2a>, r1=<clobbered>
loc_2e:
  2e:	d8640875 	ld.b	r3, (r4, 0x875)	// regs: r3=*(0x875)
  32:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(0x875) & 0x4)
  36:	3b40      	cmpnei	r3, 0
  38:	1047      	lrw	r2, 0x0	// regs: r2=0x0
  3a:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  3c:	c4430c20 	incf	r2, r3, 0
  40:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  42:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  44:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x44>, r1=<clobbered>
  48:	07e3      	br	0xe	// goto loc_e;
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  4e:	0000      	.short	0x0000
  50:	0000      	.short	0x0000	// <ah_lmac>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1+0x7>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1+0xf>
  5e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_ant_ctrl_hdl:

00000000 <atcmd_ant_ctrl_hdl>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1018      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1493      	pop	r4-r6, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	10b6      	lrw	r5, 0x0	// regs: r5=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0818      	bt	0x4c	// if (r3 != 0x3f) goto loc_4c;
  1e:	d8450876 	ld.b	r2, (r5, 0x876)	// regs: r2=*(0x876)
  22:	74ca      	sextb	r3, r2	// regs: r3=sext8(*(0x876))
  24:	e9a30008 	bhsz	r3, 0x34	// if (r3 >= 0x0) goto loc_34;
  28:	e442207f 	andi	r2, r2, 127	// regs: r2=(*(0x876) & 0x7f)
  2c:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  2e:	1011      	lrw	r0, 0x0	// regs: r0=0x0
  30:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x30>, r1=<clobbered>
loc_34:
  34:	d8450877 	ld.b	r2, (r5, 0x877)	// regs: r2=*(0x877)
  38:	74ca      	sextb	r3, r2	// regs: r3=sext8(*(0x877))
  3a:	e9a3ffea 	bhsz	r3, 0xe	// if (r3 >= 0x0) goto loc_e;
  3e:	e442207f 	andi	r2, r2, 127	// regs: r2=(*(0x877) & 0x7f)
  42:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  44:	100c      	lrw	r0, 0x0	// regs: r0=0x0
loc_46:
  46:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x46>, r1=<clobbered>
  4a:	07e2      	br	0xe	// goto loc_e;
loc_4c:
  4c:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x4c>, r1=<clobbered>
  50:	6c83      	mov	r2, r0	// regs: r2=<ret atoi@0x4c>
  52:	6d83      	mov	r6, r0	// regs: r6=<ret atoi@0x4c>
  54:	312a      	movi	r1, 42	// regs: r1=0x2a
  56:	3300      	movi	r3, 0	// regs: r3=0x0
  58:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(0x0)
  5a:	e0000000 	bsr	0x0	// <lmac_ioctl>; regs: r0=<ret lmac_ioctl@0x5a>, r1=<clobbered>
  5e:	6c9b      	mov	r2, r6	// regs: r2=<ret atoi@0x4c>
  60:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  62:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  64:	07f1      	br	0x46	// goto loc_46;
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  6a:	0000      	.short	0x0000
  6c:	0000      	.short	0x0000	// <ah_lmac>
  6e:	0000      	.short	0x0000
  70:	00000000 	.long	0x00000000	// <.rodata.atcmd_ant_ctrl_hdl.str1.1>
  74:	0000      	.short	0x0000	// <.rodata.atcmd_ant_ctrl_hdl.str1.1+0x1d>
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000	// <.rodata.atcmd_ant_ctrl_hdl.str1.1+0x3a>

Disassembly of section .text.atcmd_ant_auto_hdl:

00000000 <atcmd_ant_auto_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1012      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1090      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	3840      	cmpnei	r0, 0
  24:	d8640875 	ld.b	r3, (r4, 0x875)	// regs: r3=*(0x875)
  28:	c4000502 	mvc	r2	// regs: r2=<cond>
  2c:	c4625c03 	ins	r3, r2, 3, 3
  30:	dc640875 	st.b	r3, (r4, 0x875)	// *(0x875) = *(0x875)
loc_34:
  34:	d8640875 	ld.b	r3, (r4, 0x875)	// regs: r3=*(0x875)
  38:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x875) & 0x8)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1047      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
  50:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <ah_lmac>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_ant_auto_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_ant_auto_hdl.str1.1+0x5>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_ant_auto_hdl.str1.1+0xb>

Disassembly of section .text.atcmd_ant_def_hdl:

00000000 <atcmd_ant_def_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1010      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108e      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	3840      	cmpnei	r0, 0
  24:	d8640875 	ld.b	r3, (r4, 0x875)	// regs: r3=*(0x875)
  28:	c4000502 	mvc	r2	// regs: r2=<cond>
  2c:	c4625c04 	ins	r3, r2, 4, 4
  30:	dc640875 	st.b	r3, (r4, 0x875)	// *(0x875) = *(0x875)
loc_34:
  34:	d8440875 	ld.b	r2, (r4, 0x875)	// regs: r2=*(0x875)
  38:	c4825482 	zext	r2, r2, 4, 4	// regs: r2=zext(*(0x875))
  3c:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  3e:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  40:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x40>, r1=<clobbered>
  44:	07e5      	br	0xe	// goto loc_e;
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <ah_lmac>
  4e:	0000      	.short	0x0000
  50:	0000      	.short	0x0000	// <.rodata.atcmd_ant_def_hdl.str1.1>
  52:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_bw_hdl:

00000000 <atcmd_tx_bw_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0b      	bf	0x32	// if (r3 == 0x3f) goto loc_32;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	6c83      	mov	r2, r0	// regs: r2=<ret atoi@0x1e>
  24:	e9600014 	blsz	r0, 0x4c
  28:	3300      	movi	r3, 0	// regs: r3=0x0
  2a:	3103      	movi	r1, 3	// regs: r1=0x3
  2c:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(0x0)
  2e:	e0000000 	bsr	0x0	// <lmac_ioctl>; regs: r0=<ret lmac_ioctl@0x2e>, r1=<clobbered>
loc_32:
  32:	d8440867 	ld.b	r2, (r4, 0x867)	// regs: r2=*(r4 + 0x867)
  36:	3302      	movi	r3, 2	// regs: r3=0x2
  38:	70c8      	lsl	r3, r2
  3a:	3b28      	cmplti	r3, 9
  3c:	3201      	movi	r2, 1	// regs: r2=0x1
  3e:	c4430c40 	inct	r2, r3, 0
  42:	5d26      	addi	r1, r5, 2	// regs: r1=(r5 + 0x2)
  44:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  46:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x46>, r1=<clobbered>
  4a:	07e2      	br	0xe	// goto loc_e;
  4c:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  4e:	3200      	movi	r2, 0	// regs: r2=0x0
  50:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  52:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  54:	07ef      	br	0x32	// goto loc_32;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_bw_hdl.str1.1>
  64:	0000      	.short	0x0000	// <lmactest>
  66:	0000      	.short	0x0000

Disassembly of section .text.atcmd_mcast_bw_hdl:

00000000 <atcmd_mcast_bw_hdl>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	1101      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1492      	pop	r4-r5, r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	58a6      	addi	r5, r0, 2	// regs: r5=(<arg0> + 0x2)
  14:	8340      	ld.b	r2, (r3, 0x0)	// regs: r2=*(*(<arg1>))
  16:	eb42003f 	cmpnei	r2, 63
  1a:	109d      	lrw	r4, 0x0	// regs: r4=0x0
  1c:	0c11      	bf	0x3e	// if (r2 == 0x3f) goto loc_3e;
  1e:	6c0f      	mov	r0, r3	// regs: r0=*(<arg1>)
  20:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x20>, r1=<clobbered>
  24:	5863      	subi	r3, r0, 1	// regs: r3=(<ret atoi@0x20> - 0x1)
  26:	3b01      	cmphsi	r3, 2
  28:	6c83      	mov	r2, r0	// regs: r2=<ret atoi@0x20>
  2a:	081a      	bt	0x5e	// if (r3 >= 0x2) goto loc_5e;
  2c:	d864034a 	ld.b	r3, (r4, 0x34a)	// regs: r3=*(0x34a)
  30:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x34a) & 0x1)
  34:	3b40      	cmpnei	r3, 0
  36:	64c3      	mvcv	r3	// regs: r3=<cond>
  38:	2300      	addi	r3, 1	// regs: r3=(<cond> + 0x1)
  3a:	dc640869 	st.b	r3, (r4, 0x869)	// *(0x869) = (<cond> + 0x1)
loc_3e:
  3e:	d8440869 	ld.b	r2, (r4, 0x869)	// regs: r2=*(0x869)
  42:	3a03      	cmphsi	r2, 4
  44:	0808      	bt	0x54	// if (r2 >= 0x4) goto loc_54;
  46:	d864034a 	ld.b	r3, (r4, 0x34a)	// regs: r3=*(0x34a)
  4a:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x34a) & 0x1)
  4e:	3b40      	cmpnei	r3, 0
  50:	6483      	mvcv	r2	// regs: r2=<cond>
  52:	2200      	addi	r2, 1	// regs: r2=(<cond> + 0x1)
loc_54:
  54:	6c57      	mov	r1, r5	// regs: r1=(<arg0> + 0x2)
  56:	100f      	lrw	r0, 0x0	// regs: r0=0x0
  58:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x58>, r1=<clobbered>
  5c:	07d8      	br	0xc	// goto loc_c;
loc_5e:
  5e:	3844      	cmpnei	r0, 4
  60:	0808      	bt	0x70	// if (r0 != 0x4) goto loc_70;
  62:	d8640308 	ld.b	r3, (r4, 0x308)	// regs: r3=*(0x308)
  66:	3b01      	cmphsi	r3, 2
loc_68:
  68:	0c0a      	bf	0x7c	// if (r3 < 0x2) goto loc_7c;
  6a:	dc440869 	st.b	r2, (r4, 0x869)	// *(0x869) = <ret atoi@0x20>
  6e:	07e8      	br	0x3e	// goto loc_3e;
loc_70:
  70:	3848      	cmpnei	r0, 8
  72:	0805      	bt	0x7c	// if (r0 != 0x8) goto loc_7c;
  74:	d8640308 	ld.b	r3, (r4, 0x308)	// regs: r3=*(0x308)
  78:	3b02      	cmphsi	r3, 3
  7a:	07f7      	br	0x68	// goto loc_68;
loc_7c:
  7c:	6c57      	mov	r1, r5	// regs: r1=(<arg0> + 0x2)
  7e:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  80:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x80>, r1=<clobbered>
  84:	07dd      	br	0x3e	// goto loc_3e;
  86:	0000      	.short	0x0000
  88:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  8c:	00000000 	.long	0x00000000	// <ah_lmac>
  90:	0000      	.short	0x0000	// <.rodata.atcmd_tx_bw_hdl.str1.1>
  92:	0000      	.short	0x0000
  94:	0000      	.short	0x0000	// <.rodata.atcmd_mcast_bw_hdl.str1.1>
  96:	0000      	.short	0x0000

Disassembly of section .text.atcmd_lo_freq_hdl:

00000000 <atcmd_lo_freq_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1012      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  16:	eb43003f 	cmpnei	r3, 63
  1a:	0c0b      	bf	0x30	// if (r3 == 0x3f) goto loc_30;
  1c:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1c>, r1=<clobbered>
  20:	6d43      	mov	r5, r0	// regs: r5=<ret atoi@0x1c>
  22:	e0000000 	bsr	0x0	// <lo_freq_valid_check> // arg_bytes: 4; regs: r0=<ret lo_freq_valid_check@0x22>, r1=<clobbered>
  26:	e920000f 	bnez	r0, 0x44	// if (r0 != 0x0) goto loc_44;
  2a:	6c17      	mov	r0, r5	// regs: r0=<ret atoi@0x1c>
  2c:	e0000000 	bsr	0x0	// <lmac_lo_freq_set>; regs: r0=<ret lmac_lo_freq_set@0x2c>, r1=<clobbered>
loc_30:
  30:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  32:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  34:	d84320ce 	ld.w	r2, (r3, 0x338)	// regs: r2=*(0x338)
  38:	c4825762 	zext	r2, r2, 27, 4	// regs: r2=zext(*(0x338))
  3c:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  3e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x3e>, r1=<clobbered>
  42:	07e6      	br	0xe	// goto loc_e;
loc_44:
  44:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  46:	3200      	movi	r2, 0	// regs: r2=0x0
  48:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  4a:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  4c:	07f2      	br	0x30	// goto loc_30;
  4e:	0000      	.short	0x0000
  50:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <ah_lmac>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_lo_freq_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <lmactest>
  5e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_freq_list_hdl:

00000000 <atcmd_freq_list_hdl>: // arg_bytes: 0
   0:	14d6      	push	r4-r9, r15
   2:	1428      	subi	r14, r14, 32	// regs: r14=(sp - 0x20)
   4:	6dc7      	mov	r7, r1	// regs: r7=<arg1>
   6:	6e0b      	mov	r8, r2	// regs: r8=<arg2>
   8:	e9220008 	bnez	r2, 0x18	// if (r2 != 0x0) goto loc_18;
   c:	1106      	lrw	r0, 0x0	// regs: r0=0x0
loc_e:
   e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xe>, r1=<clobbered>
  12:	3000      	movi	r0, 0	// regs: r0=0x0
  14:	1408      	addi	r14, r14, 32	// regs: r14=((sp - 0x20) + 0x20)
  16:	1496      	pop	r4-r9, r15
loc_18:
  18:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  1a:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  1c:	eb43003f 	cmpnei	r3, 63
  20:	0c21      	bf	0x62	// if (r3 == 0x3f) goto loc_62;
  22:	3400      	movi	r4, 0	// regs: r4=0x0
  24:	6d53      	mov	r5, r4	// regs: r5=0x0
  26:	ea090064 	movi	r9, 100	// regs: r9=0x64
loc_2a:
  2a:	3c50      	cmpnei	r4, 16
  2c:	0c13      	bf	0x52	// if (r4 == 0x10) goto loc_52;
  2e:	d0870880 	ldr.w	r0, (r7, r4 << 2)	// regs: r0=*(<arg1> + (r4 << 2))
  32:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x32>, r1=<clobbered>
  36:	6d83      	mov	r6, r0	// regs: r6=<ret atoi@0x32>
  38:	e0000000 	bsr	0x0	// <lo_freq_valid_check> // arg_bytes: 4; regs: r0=<ret lo_freq_valid_check@0x38>, r1=<clobbered>
  3c:	e9200008 	bnez	r0, 0x4c	// if (r0 != 0x0) goto loc_4c;
  40:	5d62      	addi	r3, r5, 1	// regs: r3=(r5 + 0x1)
  42:	c5268046 	divs	r6, r6, r9	// regs: r6=(<ret atoi@0x32> / 0x64)
  46:	d4ae0446 	str.h	r6, (r14, r5 << 1)
  4a:	754d      	zexth	r5, r3	// regs: r5=zext16((r5 + 0x1))
loc_4c:
  4c:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  4e:	6612      	cmpne	r4, r8
  50:	0bed      	bt	0x2a	// if (T) goto loc_2a;
loc_52:
  52:	e9050019 	bez	r5, 0x84	// if (r5 == 0x0) goto loc_84;
  56:	1075      	lrw	r3, 0x0	// regs: r3=0x0
  58:	6c97      	mov	r2, r5	// regs: r2=r5
  5a:	6c7b      	mov	r1, r14	// regs: r1=(sp - 0x20)
  5c:	9300      	ld.w	r0, (r3, 0x0)	// regs: r0=*(0x0)
  5e:	e0000000 	bsr	0x0	// <lmac_cfg_set_chanlist>; regs: r0=<ret lmac_cfg_set_chanlist@0x5e>, r1=<clobbered>
loc_62:
  62:	1013      	lrw	r0, 0x0	// regs: r0=0x0
  64:	3500      	movi	r5, 0	// regs: r5=0x0
  66:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x66>, r1=<clobbered>
  6a:	6d17      	mov	r4, r5	// regs: r4=0x0
  6c:	10cf      	lrw	r6, 0x0	// regs: r6=0x0
  6e:	10f1      	lrw	r7, 0x0	// regs: r7=0x0
loc_70:
  70:	d8660378 	ld.b	r3, (r6, 0x378)	// regs: r3=*(0x378)
  74:	64d1      	cmplt	r4, r3
  76:	2517      	addi	r5, 24	// regs: r5=(r5 + 0x18)
  78:	080b      	bt	0x8e	// if (T) goto loc_8e;
  7a:	100f      	lrw	r0, 0x0	// regs: r0=0x0
  7c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x7c>, r1=<clobbered>
  80:	100e      	lrw	r0, 0x0	// regs: r0=0x0
  82:	07c6      	br	0xe	// goto loc_e;
loc_84:
  84:	106e      	lrw	r3, 0x0	// regs: r3=0x0
  86:	3200      	movi	r2, 0	// regs: r2=0x0
  88:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  8a:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  8c:	07eb      	br	0x62	// goto loc_62;
loc_8e:
  8e:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  90:	60d4      	addu	r3, r5	// regs: r3=(0x0 + (r5 + 0x18))
  92:	6c53      	mov	r1, r4	// regs: r1=r4
  94:	d843202a 	ld.w	r2, (r3, 0xa8)	// regs: r2=*(((0x0 + (r5 + 0x18)) + 0xa8))
  98:	6c1f      	mov	r0, r7	// regs: r0=0x0
  9a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x9a>, r1=<clobbered>
  9e:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  a0:	07e8      	br	0x70	// goto loc_70;
  a2:	0000      	.short	0x0000
  a4:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  a6:	0000      	.short	0x0000
  a8:	00000000 	.long	0x00000000	// <ah_lmac>
  ac:	00000000 	.long	0x00000000	// <.rodata.atcmd_freq_list_hdl.str1.1>
  b0:	00000000 	.long	0x00000000	// <.rodata.atcmd_freq_list_hdl.str1.1+0x11>
  b4:	0000      	.short	0x0000	// <.rodata.atcmd_freq_list_hdl.str1.1+0x1b>
  b6:	0000      	.short	0x0000
  b8:	00000000 	.long	0x00000000	// <.rodata.atcmd_freq_list_hdl.str1.1+0x1e>
  bc:	00000000 	.long	0x00000000	// <lmactest>

Disassembly of section .text.atcmd_tx_pwr_auto_hdl:

00000000 <atcmd_tx_pwr_auto_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1016      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  14:	1094      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0b      	bf	0x32	// if (r3 == 0x3f) goto loc_32;
  1e:	eb430030 	cmpnei	r3, 48
  22:	d8640338 	ld.b	r3, (r4, 0x338)	// regs: r3=*(0x338)
  26:	0814      	bt	0x4e	// if (r3 != 0x30) goto loc_4e;
  28:	3200      	movi	r2, 0	// regs: r2=0x0
  2a:	c4625c00 	ins	r3, r2, 0, 0
  2e:	dc640338 	st.b	r3, (r4, 0x338)	// *(0x338) = *(0x338)
loc_32:
  32:	d8640338 	ld.b	r3, (r4, 0x338)	// regs: r3=*(0x338)
  36:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x338) & 0x1)
  3a:	3b40      	cmpnei	r3, 0
  3c:	104b      	lrw	r2, 0x0	// regs: r2=0x0
  3e:	106c      	lrw	r3, 0x0	// regs: r3=0x0
  40:	c4430c20 	incf	r2, r3, 0
  44:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  46:	100b      	lrw	r0, 0x0	// regs: r0=0x0
  48:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x48>, r1=<clobbered>
  4c:	07e1      	br	0xe	// goto loc_e;
loc_4e:
  4e:	3201      	movi	r2, 1	// regs: r2=0x1
  50:	c4625c00 	ins	r3, r2, 0, 0
  54:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  56:	dc640338 	st.b	r3, (r4, 0x338)	// *(0x338) = *(0x338)
  5a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x5a>, r1=<clobbered>
  5e:	07ea      	br	0x32	// goto loc_32;
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  64:	0000      	.short	0x0000	// <ah_lmac>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  6a:	0000      	.short	0x0000
  6c:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  6e:	0000      	.short	0x0000
  70:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_pwr_auto_hdl.str1.1+0x1f>
  74:	0000      	.short	0x0000	// <.rodata.atcmd_tx_pwr_auto_hdl.str1.1>
  76:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_pwr_max_hdl:

00000000 <atcmd_tx_pwr_max_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c14      	bf	0x44	// if (r3 == 0x3f) goto loc_44;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	3825      	cmplti	r0, 6
  24:	0c10      	bf	0x44	// if (r0 >= 0x6) goto loc_44;
  26:	d864036d 	ld.b	r3, (r4, 0x36d)	// regs: r3=*(0x36d)
  2a:	e463200c 	andi	r3, r3, 12	// regs: r3=(*(0x36d) & 0xc)
  2e:	e9030009 	bez	r3, 0x40	// if (r3 == 0x0) goto loc_40;
loc_32:
  32:	d86411b6 	ld.h	r3, (r4, 0x36c)	// regs: r3=*(0x36c)
  36:	c4605c85 	ins	r3, r0, 9, 5
  3a:	dc6411b6 	st.h	r3, (r4, 0x36c)	// *(0x36c) = *(0x36c)
  3e:	0403      	br	0x44	// goto loc_44;
loc_40:
  40:	3822      	cmplti	r0, 3
  42:	0ff8      	bf	0x32	// if (r0 >= 0x3) goto loc_32;
loc_44:
  44:	d84411b6 	ld.h	r2, (r4, 0x36c)	// regs: r2=*(0x36c)
  48:	c4a25522 	zext	r2, r2, 9, 5	// regs: r2=zext(*(0x36c))
  4c:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  4e:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  50:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x50>, r1=<clobbered>
  54:	07dd      	br	0xe	// goto loc_e;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_pwr_max_hdl.str1.1>

Disassembly of section .text.atcmd_tx_pwr_super_hdl:

00000000 <atcmd_tx_pwr_super_hdl>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	1104      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1492      	pop	r4-r5, r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	5886      	addi	r4, r0, 2	// regs: r4=(<arg0> + 0x2)
  14:	8340      	ld.b	r2, (r3, 0x0)	// regs: r2=*(*(<arg1>))
  16:	eb42003f 	cmpnei	r2, 63
  1a:	11a0      	lrw	r5, 0x0	// regs: r5=0x0
  1c:	0814      	bt	0x44	// if (r2 != 0x3f) goto loc_44;
  1e:	d845036d 	ld.b	r2, (r5, 0x36d)	// regs: r2=*(0x36d)
  22:	c4425462 	zext	r2, r2, 3, 2	// regs: r2=zext(*(0x36d))
  26:	6c53      	mov	r1, r4	// regs: r1=(<arg0> + 0x2)
  28:	101d      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2a>, r1=<clobbered>
loc_2e:
  2e:	d865036d 	ld.b	r3, (r5, 0x36d)	// regs: r3=*(0x36d)
  32:	e463200c 	andi	r3, r3, 12	// regs: r3=(*(0x36d) & 0xc)
  36:	3b48      	cmpnei	r3, 8
  38:	081e      	bt	0x74	// if (r3 != 0x8) goto loc_74;
  3a:	6c53      	mov	r1, r4	// regs: r1=(<arg0> + 0x2)
  3c:	1019      	lrw	r0, 0x0	// regs: r0=0x0
loc_3e:
  3e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x3e>, r1=<clobbered>
  42:	07e5      	br	0xc	// goto loc_c;
loc_44:
  44:	6c0f      	mov	r0, r3	// regs: r0=*(<arg1>)
  46:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x46>, r1=<clobbered>
  4a:	3803      	cmphsi	r0, 4
  4c:	080c      	bt	0x64	// if (r0 >= 0x4) goto loc_64;
  4e:	e4002003 	andi	r0, r0, 3	// regs: r0=(<ret atoi@0x46> & 0x3)
  52:	d865036d 	ld.b	r3, (r5, 0x36d)	// regs: r3=*(0x36d)
  56:	c4605c22 	ins	r3, r0, 3, 2
  5a:	c4605c24 	ins	r3, r0, 5, 4
loc_5e:
  5e:	dc65036d 	st.b	r3, (r5, 0x36d)	// *(0x36d) = r3
  62:	07e6      	br	0x2e	// goto loc_2e;
loc_64:
  64:	d865036d 	ld.b	r3, (r5, 0x36d)	// regs: r3=*(0x36d)
  68:	e46320f3 	andi	r3, r3, 243	// regs: r3=(*(0x36d) & 0xf3)
  6c:	3200      	movi	r2, 0	// regs: r2=0x0
  6e:	c4625c24 	ins	r3, r2, 5, 4
  72:	07f6      	br	0x5e	// goto loc_5e;
loc_74:
  74:	3b4c      	cmpnei	r3, 12
  76:	0804      	bt	0x7e	// if (r3 != 0xc) goto loc_7e;
  78:	6c53      	mov	r1, r4	// regs: r1=(<arg0> + 0x2)
  7a:	100b      	lrw	r0, 0x0	// regs: r0=0x0
  7c:	07e1      	br	0x3e	// goto loc_3e;
loc_7e:
  7e:	3b40      	cmpnei	r3, 0
  80:	104a      	lrw	r2, 0x0	// regs: r2=0x0
  82:	106b      	lrw	r3, 0x0	// regs: r3=0x0
  84:	c4430c20 	incf	r2, r3, 0
  88:	6c53      	mov	r1, r4	// regs: r1=(<arg0> + 0x2)
  8a:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  8c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8c>, r1=<clobbered>
  90:	07be      	br	0xc	// goto loc_c;
  92:	0000      	.short	0x0000
  94:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  96:	0000      	.short	0x0000
  98:	00000000 	.long	0x00000000	// <ah_lmac>
  9c:	0000      	.short	0x0000	// <.rodata.atcmd_tx_pwr_super_hdl.str1.1>
  9e:	0000      	.short	0x0000
  a0:	0000      	.short	0x0000	// <.rodata.atcmd_tx_pwr_super_hdl.str1.1+0x1c>
  a2:	0000      	.short	0x0000
  a4:	0000      	.short	0x0000	// <.rodata.atcmd_tx_pwr_super_hdl.str1.1+0x47>
  a6:	0000      	.short	0x0000
  a8:	00000000 	.long	0x00000000	// <.rodata.atcmd_ant_dual_hdl.str1.1>
  ac:	00000000 	.long	0x00000000	// <.rodata.atcmd_ant_dual_hdl.str1.1+0x7>
  b0:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_pwr_super_hdl.str1.1+0x72>

Disassembly of section .text.atcmd_tx_pwr_super_th_hdl:

00000000 <atcmd_tx_pwr_super_th_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1010      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108e      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0b      	bf	0x32	// if (r3 == 0x3f) goto loc_32;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	e9600008 	blsz	r0, 0x32
  26:	d86420db 	ld.w	r3, (r4, 0x36c)	// regs: r3=*(0x36c)
  2a:	c4605cee 	ins	r3, r0, 21, 14
  2e:	dc6420db 	st.w	r3, (r4, 0x36c)	// *(0x36c) = *(0x36c)
loc_32:
  32:	d84420db 	ld.w	r2, (r4, 0x36c)	// regs: r2=*(0x36c)
  36:	c5c256a2 	zext	r2, r2, 21, 14	// regs: r2=zext(*(0x36c))
  3a:	e4620008 	addi	r3, r2, 9	// regs: r3=(zext(*(0x36c)) + 0x9)
  3e:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  40:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  42:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x42>, r1=<clobbered>
  46:	07e4      	br	0xe	// goto loc_e;
  48:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <ah_lmac>
  4e:	0000      	.short	0x0000
  50:	0000      	.short	0x0000	// <.rodata.atcmd_tx_pwr_super_th_hdl.str1.1>
  52:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_rate_fixed_hdl:

00000000 <atcmd_tx_rate_fixed_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d864036e 	ld.b	r3, (r4, 0x36e)	// regs: r3=*(0x36e)
  26:	e9000015 	bez	r0, 0x50	// if (r0 == 0x0) goto loc_50;
  2a:	3201      	movi	r2, 1	// regs: r2=0x1
  2c:	c4625c06 	ins	r3, r2, 6, 6
loc_30:
  30:	dc64036e 	st.b	r3, (r4, 0x36e)	// *(0x36e) = *(0x36e)
loc_34:
  34:	d864036e 	ld.b	r3, (r4, 0x36e)	// regs: r3=*(0x36e)
  38:	e4632040 	andi	r3, r3, 64	// regs: r3=(*(0x36e) & 0x40)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1049      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
loc_50:
  50:	c4605c06 	ins	r3, r0, 6, 6
  54:	07ee      	br	0x30	// goto loc_30;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_tx_rate_fixed_hdl.str1.1>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_attn_hdl:

00000000 <atcmd_tx_attn_hdl>: // arg_bytes: 12
   0:	14d7      	push	r4-r10, r15
   2:	6e03      	mov	r8, r0	// regs: r8=<arg0>
   4:	6e47      	mov	r9, r1	// regs: r9=<arg1>
   6:	e9220007 	bnez	r2, 0x14	// if (r2 != 0x0) goto loc_14;
   a:	1217      	lrw	r0, 0x0	// regs: r0=0x0
   c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xc>, r1=<clobbered>
loc_10:
  10:	3000      	movi	r0, 0	// regs: r0=0x0
  12:	1497      	pop	r4-r10, r15
loc_14:
  14:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  16:	12b5      	lrw	r5, 0x0	// regs: r5=0x0
  18:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  1a:	eb43003f 	cmpnei	r3, 63
  1e:	081f      	bt	0x5c	// if (r3 != 0x3f) goto loc_5c;
  20:	d80511b6 	ld.h	r0, (r5, 0x36c)	// regs: r0=*(0x36c)
  24:	c4a05520 	zext	r0, r0, 9, 5	// regs: r0=zext(*(0x36c))
  28:	e0000000 	bsr	0x0	// <ah_rfdigicali_get_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_get_tx_digi_gain@0x28>, r1=<clobbered>
  2c:	e0000000 	bsr	0x0	// <__floatunsidf>; regs: r0=<ret __floatunsidf@0x2c>, r1=<clobbered>
  30:	3200      	movi	r2, 0	// regs: r2=0x0
  32:	ea233f50 	movih	r3, 16208	// regs: r3=(0x3f50 << 0x10)
  36:	e0000000 	bsr	0x0	// <__muldf3>; regs: r0=<ret __muldf3@0x36>, r1=<clobbered>
  3a:	e0000000 	bsr	0x0	// <log10>; regs: r0=<ret log10@0x3a>, r1=<clobbered>
  3e:	3200      	movi	r2, 0	// regs: r2=0x0
  40:	ea23c034 	movih	r3, 49204	// regs: r3=(0xc034 << 0x10)
  44:	e0000000 	bsr	0x0	// <__muldf3>; regs: r0=<ret __muldf3@0x44>, r1=<clobbered>
  48:	6d03      	mov	r4, r0	// regs: r4=<ret __muldf3@0x44>
  4a:	6d87      	mov	r6, r1	// regs: r6=<clobbered>
loc_4c:
  4c:	6c93      	mov	r2, r4	// regs: r2=r4
  4e:	6cdb      	mov	r3, r6	// regs: r3=r6
  50:	e4280001 	addi	r1, r8, 2	// regs: r1=(<arg0> + 0x2)
  54:	1206      	lrw	r0, 0x0	// regs: r0=0x0
  56:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x56>, r1=<clobbered>
  5a:	07db      	br	0x10	// goto loc_10;
loc_5c:
  5c:	d8650338 	ld.b	r3, (r5, 0x338)	// regs: r3=*(0x338)
  60:	3400      	movi	r4, 0	// regs: r4=0x0
  62:	c4645c00 	ins	r3, r4, 0, 0
  66:	dc650338 	st.b	r3, (r5, 0x338)	// *(0x338) = *(0x338)
  6a:	3201      	movi	r2, 1	// regs: r2=0x1
  6c:	d86503df 	ld.b	r3, (r5, 0x3df)	// regs: r3=*(0x3df)
  70:	c4625c02 	ins	r3, r2, 2, 2
  74:	6dd3      	mov	r7, r4	// regs: r7=0x0
  76:	dc6503df 	st.b	r3, (r5, 0x3df)	// *(0x3df) = *(0x3df)
  7a:	2f05      	subi	r7, 6	// regs: r7=0xfffffffa
  7c:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x7c>, r1=<clobbered>
  80:	65c1      	cmplt	r0, r7
  82:	6d83      	mov	r6, r0	// regs: r6=<ret atoi@0x7c>
  84:	0863      	bt	0x14a	// if (T) goto loc_14a;
  86:	d9492000 	ld.w	r10, (r9, 0x0)	// regs: r10=*(<arg1>)
  8a:	312d      	movi	r1, 45	// regs: r1=0x2d
  8c:	6c2b      	mov	r0, r10	// regs: r0=*(<arg1>)
  8e:	e0000000 	bsr	0x0	// <strchr>; regs: r0=<ret strchr@0x8e>, r1=<clobbered>
  92:	6e43      	mov	r9, r0	// regs: r9=<ret strchr@0x8e>
  94:	312e      	movi	r1, 46	// regs: r1=0x2e
  96:	6c2b      	mov	r0, r10	// regs: r0=*(<arg1>)
  98:	e0000000 	bsr	0x0	// <strchr>; regs: r0=<ret strchr@0x98>, r1=<clobbered>
  9c:	e920003b 	bnez	r0, 0x112	// if (r0 != 0x0) goto loc_112;
loc_a0:
  a0:	3400      	movi	r4, 0	// regs: r4=0x0
loc_a2:
  a2:	e9090040 	bez	r9, 0x122	// if (r9 == 0x0) goto loc_122;
  a6:	6c1b      	mov	r0, r6	// regs: r0=<ret atoi@0x7c>
  a8:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0xa8>, r1=<clobbered>
  ac:	6dc3      	mov	r7, r0	// regs: r7=<ret __floatsidf@0xa8>
  ae:	6c13      	mov	r0, r4	// regs: r0=r4
  b0:	6d87      	mov	r6, r1	// regs: r6=<clobbered>
  b2:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0xb2>, r1=<clobbered>
  b6:	3200      	movi	r2, 0	// regs: r2=0x0
  b8:	ea234024 	movih	r3, 16420	// regs: r3=(0x4024 << 0x10)
  bc:	e0000000 	bsr	0x0	// <__divdf3>; regs: r0=<ret __divdf3@0xbc>, r1=<clobbered>
  c0:	6c83      	mov	r2, r0	// regs: r2=<ret __divdf3@0xbc>
  c2:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
  c4:	6c1f      	mov	r0, r7	// regs: r0=<ret __floatsidf@0xa8>
  c6:	6c5b      	mov	r1, r6	// regs: r1=<clobbered>
  c8:	e0000000 	bsr	0x0	// <__subdf3>; regs: r0=<ret __subdf3@0xc8>, r1=<clobbered>
loc_cc:
  cc:	3200      	movi	r2, 0	// regs: r2=0x0
  ce:	ea234034 	movih	r3, 16436	// regs: r3=(0x4034 << 0x10)
  d2:	6d03      	mov	r4, r0	// regs: r4=r0
  d4:	6d87      	mov	r6, r1	// regs: r6=<clobbered>
  d6:	e0000000 	bsr	0x0	// <__divdf3>; regs: r0=<ret __divdf3@0xd6>, r1=<clobbered>
  da:	6c83      	mov	r2, r0	// regs: r2=<ret __divdf3@0xd6>
  dc:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
  de:	3000      	movi	r0, 0	// regs: r0=0x0
  e0:	ea214024 	movih	r1, 16420	// regs: r1=(0x4024 << 0x10)
  e4:	e0000000 	bsr	0x0	// <pow>; regs: r0=<ret pow@0xe4>, r1=<clobbered>
  e8:	6c83      	mov	r2, r0	// regs: r2=<ret pow@0xe4>
  ea:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
  ec:	3000      	movi	r0, 0	// regs: r0=0x0
  ee:	ea214090 	movih	r1, 16528	// regs: r1=(0x4090 << 0x10)
  f2:	e0000000 	bsr	0x0	// <__divdf3>; regs: r0=<ret __divdf3@0xf2>, r1=<clobbered>
  f6:	e0000000 	bsr	0x0	// <__fixunsdfsi>; regs: r0=<ret __fixunsdfsi@0xf6>, r1=<clobbered>
  fa:	75c1      	zexth	r7, r0	// regs: r7=zext16(<ret __fixunsdfsi@0xf6>)
  fc:	d82511b6 	ld.h	r1, (r5, 0x36c)	// regs: r1=*(0x36c)
 100:	6c1f      	mov	r0, r7	// regs: r0=zext16(<ret __fixunsdfsi@0xf6>)
 102:	c4a15521 	zext	r1, r1, 9, 5	// regs: r1=zext(*(0x36c))
 106:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0x106>, r1=<clobbered>
 10a:	6c1f      	mov	r0, r7	// regs: r0=zext16(<ret __fixunsdfsi@0xf6>)
 10c:	e0000000 	bsr	0x0	// <tx_digi_gain_store>; regs: r0=<ret tx_digi_gain_store@0x10c>, r1=<clobbered>
 110:	079e      	br	0x4c	// goto loc_4c;
loc_112:
 112:	65da      	cmpne	r6, r7
 114:	a082      	st.b	r4, (r0, 0x2)	// *(<ret strchr@0x98> + 0x2) = 0x0
 116:	0fc5      	bf	0xa0	// if (!T) goto loc_a0;
 118:	2000      	addi	r0, 1	// regs: r0=(<ret strchr@0x98> + 0x1)
 11a:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x11a>, r1=<clobbered>
 11e:	6d03      	mov	r4, r0	// regs: r4=<ret atoi@0x11a>
 120:	07c1      	br	0xa2	// goto loc_a2;
loc_122:
 122:	6c13      	mov	r0, r4	// regs: r0=r4
 124:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0x124>, r1=<clobbered>
 128:	3200      	movi	r2, 0	// regs: r2=0x0
 12a:	ea234024 	movih	r3, 16420	// regs: r3=(0x4024 << 0x10)
 12e:	e0000000 	bsr	0x0	// <__divdf3>; regs: r0=<ret __divdf3@0x12e>, r1=<clobbered>
 132:	6dc3      	mov	r7, r0	// regs: r7=<ret __divdf3@0x12e>
 134:	6c1b      	mov	r0, r6	// regs: r0=<ret atoi@0x7c>
 136:	6d07      	mov	r4, r1	// regs: r4=<clobbered>
 138:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0x138>, r1=<clobbered>
 13c:	6c83      	mov	r2, r0	// regs: r2=<ret __floatsidf@0x138>
 13e:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
 140:	6c1f      	mov	r0, r7	// regs: r0=<ret __divdf3@0x12e>
 142:	6c53      	mov	r1, r4	// regs: r1=<clobbered>
 144:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x144>, r1=<clobbered>
 148:	07c2      	br	0xcc	// goto loc_cc;
loc_14a:
 14a:	d86503df 	ld.b	r3, (r5, 0x3df)	// regs: r3=*(0x3df)
 14e:	c4645c02 	ins	r3, r4, 2, 2
 152:	dc6503df 	st.b	r3, (r5, 0x3df)	// *(0x3df) = *(0x3df)
 156:	3200      	movi	r2, 0	// regs: r2=0x0
 158:	1066      	lrw	r3, 0x0	// regs: r3=0x0
 15a:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
 15c:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
 15e:	ea267ff8 	movih	r6, 32760	// regs: r6=(0x7ff8 << 0x10)
 162:	0775      	br	0x4c	// goto loc_4c;
 164:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
 168:	00000000 	.long	0x00000000	// <ah_lmac>
 16c:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_attn_hdl.str1.1>
 170:	00000000 	.long	0x00000000	// <lmactest>

Disassembly of section .text.atcmd_tx_cw_hdl:

00000000 <atcmd_tx_cw_hdl>: // arg_bytes: 0
   0:	14d6      	push	r4-r9, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	ea0301ff 	movi	r3, 511	// regs: r3=0x1ff
   8:	dc6e1000 	st.h	r3, (r14, 0x0)	// local_4 = 0x1ff
   c:	ea0301ff 	movi	r3, 511	// regs: r3=0x1ff
  10:	6cce      	nor	r3, r3	// regs: r3=(~0x1ff)
  12:	dc6e1001 	st.h	r3, (r14, 0x2)	// local_2 = (~0x1ff)
  16:	e9220008 	bnez	r2, 0x26	// if (r2 != 0x0) goto loc_26;
  1a:	1212      	lrw	r0, 0x0	// regs: r0=0x0
  1c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x1c>, r1=<clobbered>
loc_20:
  20:	3000      	movi	r0, 0	// regs: r0=0x0
  22:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  24:	1496      	pop	r4-r9, r15
loc_26:
  26:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  28:	58c6      	addi	r6, r0, 2	// regs: r6=(<arg0> + 0x2)
  2a:	8340      	ld.b	r2, (r3, 0x0)	// regs: r2=*(*(<arg1>))
  2c:	eb42003f 	cmpnei	r2, 63
  30:	080e      	bt	0x4c	// if (r2 != 0x3f) goto loc_4c;
  32:	126d      	lrw	r3, 0x0	// regs: r3=0x0
  34:	124d      	lrw	r2, 0x0	// regs: r2=0x0
  36:	d86303e3 	ld.b	r3, (r3, 0x3e3)	// regs: r3=*(0x3e3)
  3a:	3b40      	cmpnei	r3, 0
  3c:	126c      	lrw	r3, 0x0	// regs: r3=0x0
  3e:	c4430c20 	incf	r2, r3, 0
  42:	6c5b      	mov	r1, r6	// regs: r1=(<arg0> + 0x2)
  44:	120b      	lrw	r0, 0x0	// regs: r0=0x0
  46:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x46>, r1=<clobbered>
  4a:	07eb      	br	0x20	// goto loc_20;
loc_4c:
  4c:	6c0f      	mov	r0, r3	// regs: r0=*(<arg1>)
  4e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x4e>, r1=<clobbered>
  52:	3841      	cmpnei	r0, 1
  54:	6d03      	mov	r4, r0	// regs: r4=<ret atoi@0x4e>
  56:	084c      	bt	0xee	// if (r0 != 0x1) goto loc_ee;
  58:	12a3      	lrw	r5, 0x0	// regs: r5=0x0
  5a:	d86503e3 	ld.b	r3, (r5, 0x3e3)	// regs: r3=*(0x3e3)
  5e:	3b41      	cmpnei	r3, 1
  60:	0c42      	bf	0xe4	// if (r3 == 0x1) goto loc_e4;
  62:	ea080000 	movi	r8, 0	// regs: r8=0x0
  66:	d8650338 	ld.b	r3, (r5, 0x338)	// regs: r3=*(0x338)
  6a:	c4685c00 	ins	r3, r8, 0, 0
  6e:	12e2      	lrw	r7, 0x0	// regs: r7=0x0
  70:	ea890042 	lrw	r9, 0x0	// regs: r9=0x0
  74:	dc650338 	st.b	r3, (r5, 0x338)	// *(0x338) = *(0x338)
  78:	d86503df 	ld.b	r3, (r5, 0x3df)	// regs: r3=*(0x3df)
  7c:	c4605c02 	ins	r3, r0, 2, 2
  80:	dc6503df 	st.b	r3, (r5, 0x3df)	// *(0x3df) = *(0x3df)
  84:	d8670042 	ld.b	r3, (r7, 0x42)	// regs: r3=*(0x42)
  88:	c4685c00 	ins	r3, r8, 0, 0
  8c:	dc670042 	st.b	r3, (r7, 0x42)	// *(0x42) = *(0x42)
  90:	d86509e2 	ld.b	r3, (r5, 0x9e2)	// regs: r3=*(0x9e2)
  94:	c4685c04 	ins	r3, r8, 4, 4
  98:	dc6509e2 	st.b	r3, (r5, 0x9e2)	// *(0x9e2) = *(0x9e2)
  9c:	e0000000 	bsr	0x0	// <ah_wphy_cont_tx_disable>; regs: r0=<ret ah_wphy_cont_tx_disable@0x9c>, r1=<clobbered>
  a0:	d8492000 	ld.w	r2, (r9, 0x0)	// regs: r2=*(0x0)
  a4:	3105      	movi	r1, 5	// regs: r1=0x5
  a6:	9271      	ld.w	r3, (r2, 0x44)	// regs: r3=*((*(0x0) + 0x44))
  a8:	3bb4      	bseti	r3, 20	// regs: r3=(*((*(0x0) + 0x44)) | (0x1 << 0x14))
  aa:	b271      	st.w	r3, (r2, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | (0x1 << 0x14))
  ac:	6c23      	mov	r0, r8	// regs: r0=0x0
  ae:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0xae>, r1=<clobbered>
  b2:	3105      	movi	r1, 5	// regs: r1=0x5
  b4:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0x4)
  b6:	e0000000 	bsr	0x0	// <ah_rfdigicali_tx_dcoc>; regs: r0=<ret ah_rfdigicali_tx_dcoc@0xb6>, r1=<clobbered>
  ba:	d8670042 	ld.b	r3, (r7, 0x42)	// regs: r3=*(0x42)
  be:	c4645c00 	ins	r3, r4, 0, 0
  c2:	dc670042 	st.b	r3, (r7, 0x42)	// *(0x42) = *(0x42)
  c6:	d86509e2 	ld.b	r3, (r5, 0x9e2)	// regs: r3=*(0x9e2)
  ca:	c4645c04 	ins	r3, r4, 4, 4
  ce:	dc6509e2 	st.b	r3, (r5, 0x9e2)	// *(0x9e2) = *(0x9e2)
  d2:	dc8503e3 	st.b	r4, (r5, 0x3e3)	// *(0x3e3) = <ret atoi@0x4e>
  d6:	e0000000 	bsr	0x0	// <ah_wphy_cont_tx_enable>; regs: r0=<ret ah_wphy_cont_tx_enable@0xd6>, r1=<clobbered>
  da:	d8492000 	ld.w	r2, (r9, 0x0)	// regs: r2=*(0x0)
  de:	9271      	ld.w	r3, (r2, 0x44)	// regs: r3=*((*(0x0) + 0x44))
  e0:	3b94      	bclri	r3, 20	// regs: r3=(*((*(0x0) + 0x44)) & ~(0x1 << 0x14))
  e2:	b271      	st.w	r3, (r2, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) & ~(0x1 << 0x14))
loc_e4:
  e4:	6c5b      	mov	r1, r6	// regs: r1=(<arg0> + 0x2)
  e6:	1106      	lrw	r0, 0x0	// regs: r0=0x0
loc_e8:
  e8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xe8>, r1=<clobbered>
  ec:	079a      	br	0x20	// goto loc_20;
loc_ee:
  ee:	e9200031 	bnez	r0, 0x150	// if (r0 != 0x0) goto loc_150;
  f2:	10bd      	lrw	r5, 0x0	// regs: r5=0x0
  f4:	d86503e3 	ld.b	r3, (r5, 0x3e3)	// regs: r3=*(0x3e3)
  f8:	e9030029 	bez	r3, 0x14a	// if (r3 == 0x0) goto loc_14a;
  fc:	d8650338 	ld.b	r3, (r5, 0x338)	// regs: r3=*(0x338)
 100:	3201      	movi	r2, 1	// regs: r2=0x1
 102:	c4625c00 	ins	r3, r2, 0, 0
 106:	dc650338 	st.b	r3, (r5, 0x338)	// *(0x338) = *(0x338)
 10a:	d86503df 	ld.b	r3, (r5, 0x3df)	// regs: r3=*(0x3df)
 10e:	c4605c02 	ins	r3, r0, 2, 2
 112:	dc6503df 	st.b	r3, (r5, 0x3df)	// *(0x3df) = *(0x3df)
 116:	1078      	lrw	r3, 0x0	// regs: r3=0x0
 118:	d8430042 	ld.b	r2, (r3, 0x42)	// regs: r2=*(0x42)
 11c:	c4405c00 	ins	r2, r0, 0, 0
 120:	dc430042 	st.b	r2, (r3, 0x42)	// *(0x42) = *(0x42)
 124:	d86509e2 	ld.b	r3, (r5, 0x9e2)	// regs: r3=*(0x9e2)
 128:	c4605c04 	ins	r3, r0, 4, 4
 12c:	dc6509e2 	st.b	r3, (r5, 0x9e2)	// *(0x9e2) = *(0x9e2)
 130:	e0000000 	bsr	0x0	// <ah_wphy_cont_tx_disable>; regs: r0=<ret ah_wphy_cont_tx_disable@0x130>, r1=<clobbered>
 134:	1071      	lrw	r3, 0x0	// regs: r3=0x0
 136:	3105      	movi	r1, 5	// regs: r1=0x5
 138:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
 13a:	1012      	lrw	r0, 0x0	// regs: r0=0x0
 13c:	9271      	ld.w	r3, (r2, 0x44)	// regs: r3=*((*(0x0) + 0x44))
 13e:	3bb4      	bseti	r3, 20	// regs: r3=(*((*(0x0) + 0x44)) | (0x1 << 0x14))
 140:	b271      	st.w	r3, (r2, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | (0x1 << 0x14))
 142:	e0000000 	bsr	0x0	// <ah_rfdigicali_tx_dcoc>; regs: r0=<ret ah_rfdigicali_tx_dcoc@0x142>, r1=<clobbered>
 146:	dc8503e3 	st.b	r4, (r5, 0x3e3)	// *(0x3e3) = <ret atoi@0x4e>
loc_14a:
 14a:	6c5b      	mov	r1, r6	// regs: r1=(<arg0> + 0x2)
 14c:	100e      	lrw	r0, 0x0	// regs: r0=0x0
 14e:	07cd      	br	0xe8	// goto loc_e8;
loc_150:
 150:	1069      	lrw	r3, 0x0	// regs: r3=0x0
 152:	3200      	movi	r2, 0	// regs: r2=0x0
 154:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
 156:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
 158:	6c5b      	mov	r1, r6	// regs: r1=(<arg0> + 0x2)
 15a:	100c      	lrw	r0, 0x0	// regs: r0=0x0
 15c:	07c6      	br	0xe8	// goto loc_e8;
 15e:	0000      	.short	0x0000
 160:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
 164:	00000000 	.long	0x00000000	// <ah_lmac>
 168:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
 16c:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
 170:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cw_hdl.str1.1>
 174:	00000000 	.long	0x00000000	// <lmactest>
 178:	00000000 	.long	0x00000000	// <LMAC>
 17c:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cw_hdl.str1.1+0x1c>
 180:	00000000 	.long	0x00000000	// <tx_dcoc_res>
 184:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cw_hdl.str1.1+0x3d>
 188:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cw_hdl.str1.1+0x5f>

Disassembly of section .text.atcmd_tx_max_agg_hdl:

00000000 <atcmd_tx_max_agg_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100f      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108d      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c09      	bf	0x2e	// if (r3 == 0x3f) goto loc_2e;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	5863      	subi	r3, r0, 1	// regs: r3=(<ret atoi@0x1e> - 0x1)
  24:	eb03003f 	cmphsi	r3, 64
  28:	080a      	bt	0x3c	// if (r3 >= 0x40) goto loc_3c;
  2a:	dc040315 	st.b	r0, (r4, 0x315)	// *(0x315) = <ret atoi@0x1e>
loc_2e:
  2e:	d8440315 	ld.b	r2, (r4, 0x315)	// regs: r2=*(0x315)
  32:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  34:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  36:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x36>, r1=<clobbered>
  3a:	07ea      	br	0xe	// goto loc_e;
loc_3c:
  3c:	3318      	movi	r3, 24	// regs: r3=0x18
  3e:	dc640315 	st.b	r3, (r4, 0x315)	// *(0x315) = 0x18
  42:	07f6      	br	0x2e	// goto loc_2e;
  44:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <ah_lmac>
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_tx_max_agg_hdl.str1.1>
  4e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_max_syms_hdl:

00000000 <atcmd_tx_max_syms_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1013      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1091      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0d      	bf	0x36	// if (r3 == 0x3f) goto loc_36;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	5863      	subi	r3, r0, 1	// regs: r3=(<ret atoi@0x1e> - 0x1)
  24:	eb0301fe 	cmphsi	r3, 511
  28:	0810      	bt	0x48	// if (r3 >= 0x1ff) goto loc_48;
  2a:	d86411b0 	ld.h	r3, (r4, 0x360)	// regs: r3=*(0x360)
  2e:	c4605d01 	ins	r3, r0, 9, 1
  32:	dc6411b0 	st.h	r3, (r4, 0x360)	// *(0x360) = *(0x360)
loc_36:
  36:	d84411b0 	ld.h	r2, (r4, 0x360)	// regs: r2=*(0x360)
  3a:	c4225522 	zext	r2, r2, 9, 1	// regs: r2=zext(*(0x360))
  3e:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  40:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  42:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x42>, r1=<clobbered>
  46:	07e4      	br	0xe	// goto loc_e;
loc_48:
  48:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  4a:	3200      	movi	r2, 0	// regs: r2=0x0
  4c:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  4e:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  50:	07f3      	br	0x36	// goto loc_36;
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <ah_lmac>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_tx_max_syms_hdl.str1.1>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <lmactest>

Disassembly of section .text.atcmd_xo_cs_hdl:

00000000 <atcmd_xo_cs_hdl>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1016      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1493      	pop	r4-r6, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  16:	eb43003f 	cmpnei	r3, 63
  1a:	080e      	bt	0x36	// if (r3 != 0x3f) goto loc_36;
  1c:	ea038003 	movi	r3, 32771	// regs: r3=0x8003
  20:	c5e34903 	rotli	r3, r3, 15	// regs: r3=rotl(0x8003, 0xf)
  24:	938a      	ld.w	r4, (r3, 0x28)	// regs: r4=*((rotl(0x8003, 0xf) + 0x28))
  26:	c66456e4 	zext	r4, r4, 23, 19	// regs: r4=zext(*((rotl(0x8003, 0xf) + 0x28)))
loc_2a:
  2a:	6c93      	mov	r2, r4	// regs: r2=r4
  2c:	5e26      	addi	r1, r6, 2	// regs: r1=(<arg0> + 0x2)
  2e:	100e      	lrw	r0, 0x0	// regs: r0=0x0
  30:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x30>, r1=<clobbered>
  34:	07ed      	br	0xe	// goto loc_e;
loc_36:
  36:	e0000000 	bsr	0x0	// <os_atoh>; regs: r0=<ret os_atoh@0x36>, r1=<clobbered>
  3a:	381f      	cmphsi	r0, 32
  3c:	080a      	bt	0x50	// if (r0 >= 0x20) goto loc_50;
  3e:	7540      	zextb	r5, r0	// regs: r5=zext8(<ret os_atoh@0x36>)
  40:	6d03      	mov	r4, r0	// regs: r4=<ret os_atoh@0x36>
  42:	6c17      	mov	r0, r5	// regs: r0=zext8(<ret os_atoh@0x36>)
  44:	e0000000 	bsr	0x0	// <xo_set_cs_sec>; regs: r0=<ret xo_set_cs_sec@0x44>, r1=<clobbered>
  48:	6c17      	mov	r0, r5	// regs: r0=zext8(<ret os_atoh@0x36>)
  4a:	e0000000 	bsr	0x0	// <xo_cs_store>; regs: r0=<ret xo_cs_store@0x4a>, r1=<clobbered>
  4e:	07ee      	br	0x2a	// goto loc_2a;
loc_50:
  50:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  52:	3200      	movi	r2, 0	// regs: r2=0x0
  54:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  56:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  58:	ea04dead 	movi	r4, 57005	// regs: r4=0xdead
  5c:	07e7      	br	0x2a	// goto loc_2a;
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_xo_cs_hdl.str1.1>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <lmactest>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_xo_cs_auto_hdl:

00000000 <atcmd_xo_cs_auto_hdl>: // arg_bytes: 12
   0:	14d8      	push	r4-r11, r15
   2:	6e03      	mov	r8, r0	// regs: r8=<arg0>
   4:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   6:	e9220007 	bnez	r2, 0x14	// if (r2 != 0x0) goto loc_14;
   a:	111e      	lrw	r0, 0x0	// regs: r0=0x0
   c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xc>, r1=<clobbered>
loc_10:
  10:	3000      	movi	r0, 0	// regs: r0=0x0
  12:	1498      	pop	r4-r11, r15
loc_14:
  14:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	080f      	bt	0x3a	// if (r3 != 0x3f) goto loc_3a;
  1e:	ea038003 	movi	r3, 32771	// regs: r3=0x8003
  22:	c5e34903 	rotli	r3, r3, 15	// regs: r3=rotl(0x8003, 0xf)
  26:	938a      	ld.w	r4, (r3, 0x28)	// regs: r4=*((rotl(0x8003, 0xf) + 0x28))
  28:	c66456e4 	zext	r4, r4, 23, 19	// regs: r4=zext(*((rotl(0x8003, 0xf) + 0x28)))
loc_2c:
  2c:	6c93      	mov	r2, r4	// regs: r2=r4
  2e:	e4280001 	addi	r1, r8, 2	// regs: r1=(<arg0> + 0x2)
  32:	1115      	lrw	r0, 0x0	// regs: r0=0x0
  34:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x34>, r1=<clobbered>
  38:	07ec      	br	0x10	// goto loc_10;
loc_3a:
  3a:	3a01      	cmphsi	r2, 2
  3c:	0c59      	bf	0xee	// if (r2 < 0x2) goto loc_ee;
  3e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x3e>, r1=<clobbered>
  42:	6d43      	mov	r5, r0	// regs: r5=<ret atoi@0x3e>
  44:	9401      	ld.w	r0, (r4, 0x4)	// regs: r0=*(<arg1> + 0x4)
  46:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x46>, r1=<clobbered>
  4a:	6541      	cmplt	r0, r5
  4c:	0823      	bt	0x92	// if (T) goto loc_92;
  4e:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
  50:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x50>, r1=<clobbered>
  54:	6dc3      	mov	r7, r0	// regs: r7=<ret atoi@0x50>
  56:	9401      	ld.w	r0, (r4, 0x4)	// regs: r0=*(<arg1> + 0x4)
loc_58:
  58:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x58>, r1=<clobbered>
  5c:	11cb      	lrw	r6, 0x0	// regs: r6=0x0
  5e:	6c83      	mov	r2, r0	// regs: r2=<ret atoi@0x58>
  60:	6e43      	mov	r9, r0	// regs: r9=<ret atoi@0x58>
  62:	6c5f      	mov	r1, r7	// regs: r1=r7
  64:	110a      	lrw	r0, 0x0	// regs: r0=0x0
  66:	11ab      	lrw	r5, 0x0	// regs: r5=0x0
  68:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x68>, r1=<clobbered>
  6c:	d86621da 	ld.w	r3, (r6, 0x768)	// regs: r3=*(0x768)
  70:	b560      	st.w	r3, (r5, 0x0)	// *(0x0) = *(0x768)
  72:	ea038003 	movi	r3, 32771	// regs: r3=0x8003
  76:	c5e34903 	rotli	r3, r3, 15	// regs: r3=rotl(0x8003, 0xf)
  7a:	ea0a0000 	movi	r10, 0	// regs: r10=0x0
  7e:	938a      	ld.w	r4, (r3, 0x28)	// regs: r4=*((rotl(0x8003, 0xf) + 0x28))
  80:	c66456e4 	zext	r4, r4, 23, 19	// regs: r4=zext(*((rotl(0x8003, 0xf) + 0x28)))
loc_84:
  84:	9560      	ld.w	r3, (r5, 0x0)	// regs: r3=*(0x0)
  86:	65cd      	cmplt	r3, r7
  88:	080b      	bt	0x9e	// if (T) goto loc_9e;
  8a:	64e5      	cmplt	r9, r3
  8c:	0fd0      	bf	0x2c	// if (!T) goto loc_2c;
  8e:	2c00      	subi	r4, 1	// regs: r4=(r4 - 0x1)
  90:	0408      	br	0xa0	// goto loc_a0;
loc_92:
  92:	9401      	ld.w	r0, (r4, 0x4)	// regs: r0=*(<arg1> + 0x4)
  94:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x94>, r1=<clobbered>
  98:	6dc3      	mov	r7, r0	// regs: r7=<ret atoi@0x94>
  9a:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
  9c:	07de      	br	0x58	// goto loc_58;
loc_9e:
  9e:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
loc_a0:
  a0:	3c1f      	cmphsi	r4, 32
  a2:	0c11      	bf	0xc4	// if (r4 < 0x20) goto loc_c4;
  a4:	3300      	movi	r3, 0	// regs: r3=0x0
  a6:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  a8:	64d2      	cmpne	r4, r3
  aa:	0c0b      	bf	0xc0	// if (!T) goto loc_c0;
  ac:	eb440020 	cmpnei	r4, 32
  b0:	331f      	movi	r3, 31	// regs: r3=0x1f
  b2:	c4830c20 	incf	r4, r3, 0
loc_b6:
  b6:	6c53      	mov	r1, r4	// regs: r1=r4
  b8:	1017      	lrw	r0, 0x0	// regs: r0=0x0
  ba:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xba>, r1=<clobbered>
  be:	07b7      	br	0x2c	// goto loc_2c;
loc_c0:
  c0:	3400      	movi	r4, 0	// regs: r4=0x0
  c2:	07fa      	br	0xb6	// goto loc_b6;
loc_c4:
  c4:	76d0      	zextb	r11, r4	// regs: r11=zext8(r4)
  c6:	6c2f      	mov	r0, r11	// regs: r0=zext8(r4)
  c8:	e0000000 	bsr	0x0	// <xo_set_cs_sec>; regs: r0=<ret xo_set_cs_sec@0xc8>, r1=<clobbered>
  cc:	6c2f      	mov	r0, r11	// regs: r0=zext8(r4)
  ce:	e0000000 	bsr	0x0	// <xo_cs_store>; regs: r0=<ret xo_cs_store@0xce>, r1=<clobbered>
  d2:	3050      	movi	r0, 80	// regs: r0=0x50
  d4:	dd4621da 	st.w	r10, (r6, 0x768)	// *(0x768) = 0x0
  d8:	e0000000 	bsr	0x0	// <os_sleep_ms>; regs: r0=<ret os_sleep_ms@0xd8>, r1=<clobbered>
  dc:	d86621da 	ld.w	r3, (r6, 0x768)	// regs: r3=*(0x768)
  e0:	b560      	st.w	r3, (r5, 0x0)	// *(0x0) = *(0x768)
  e2:	e923ffd1 	bnez	r3, 0x84	// if (r3 != 0x0) goto loc_84;
  e6:	100d      	lrw	r0, 0x0	// regs: r0=0x0
  e8:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xe8>, r1=<clobbered>
  ec:	07a0      	br	0x2c	// goto loc_2c;
loc_ee:
  ee:	100c      	lrw	r0, 0x0	// regs: r0=0x0
  f0:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xf0>, r1=<clobbered>
  f4:	106b      	lrw	r3, 0x0	// regs: r3=0x0
  f6:	3200      	movi	r2, 0	// regs: r2=0x0
  f8:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  fa:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  fc:	3400      	movi	r4, 0	// regs: r4=0x0
  fe:	0797      	br	0x2c	// goto loc_2c;
 100:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
 104:	00000000 	.long	0x00000000	// <.rodata.atcmd_xo_cs_hdl.str1.1>
 108:	00000000 	.long	0x00000000	// <ah_lmac>
 10c:	00000000 	.long	0x00000000	// <.rodata.atcmd_xo_cs_auto_hdl.str1.1>
 110:	0000      	.short	0x0000	// <.bss.freq_dev.13872>
 112:	0000      	.short	0x0000
 114:	00000000 	.long	0x00000000	// <.rodata.atcmd_xo_cs_auto_hdl.str1.1+0x16>
 118:	00000000 	.long	0x00000000	// <.rodata.atcmd_xo_cs_auto_hdl.str1.1+0x35>
 11c:	00000000 	.long	0x00000000	// <.rodata.atcmd_xo_cs_auto_hdl.str1.1+0x59>
 120:	00000000 	.long	0x00000000	// <lmactest>

Disassembly of section .text.atcmd_t_sensor_hdl:

00000000 <atcmd_t_sensor_hdl>: // arg_bytes: 12
   0:	14d1      	push	r4, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100c      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1491      	pop	r4, r15
loc_12:
  12:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  14:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  16:	eb43003f 	cmpnei	r3, 63
  1a:	0809      	bt	0x2c	// if (r3 != 0x3f) goto loc_2c;
  1c:	e0000000 	bsr	0x0	// <lmac_test_temp_sensor_rd_hdl> // arg_bytes: 0; regs: r0=<ret lmac_test_temp_sensor_rd_hdl@0x1c>, r1=<clobbered>
  20:	6c83      	mov	r2, r0	// regs: r2=<ret lmac_test_temp_sensor_rd_hdl@0x1c>
loc_22:
  22:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  24:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  26:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x26>, r1=<clobbered>
  2a:	07f2      	br	0xe	// goto loc_e;
loc_2c:
  2c:	1065      	lrw	r3, 0x0	// regs: r3=0x0
  2e:	3200      	movi	r2, 0	// regs: r2=0x0
  30:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  32:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  34:	1044      	lrw	r2, 0xdeaddead	// regs: r2=0xdeaddead
  36:	07f6      	br	0x22	// goto loc_22;
  38:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_t_sensor_hdl.str1.1>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <lmactest>
  42:	0000      	.short	0x0000
  44:	dead      	.short	0xdead
  46:	dead      	.short	0xdead

Disassembly of section .text.atcmd_mac_addr_hdl:

00000000 <atcmd_mac_addr_hdl>: // arg_bytes: 12
   0:	14d1      	push	r4, r15
   2:	1424      	subi	r14, r14, 16	// regs: r14=(sp - 0x10)
   4:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   6:	e9220008 	bnez	r2, 0x16	// if (r2 != 0x0) goto loc_16;
   a:	1015      	lrw	r0, 0x0	// regs: r0=0x0
   c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xc>, r1=<clobbered>
loc_10:
  10:	3000      	movi	r0, 0	// regs: r0=0x0
  12:	1404      	addi	r14, r14, 16	// regs: r14=((sp - 0x10) + 0x10)
  14:	1491      	pop	r4, r15
loc_16:
  16:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  18:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  1a:	eb43003f 	cmpnei	r3, 63
  1e:	0c08      	bf	0x2e	// if (r3 == 0x3f) goto loc_2e;
  20:	eb430030 	cmpnei	r3, 48
  24:	102f      	lrw	r1, 0x0	// regs: r1=0x0
  26:	0802      	bt	0x2a	// if (r3 != 0x30) goto loc_2a;
  28:	100f      	lrw	r0, 0x0	// regs: r0=0x0
loc_2a:
  2a:	e0000000 	bsr	0x0	// <str2mac>; regs: r0=<ret str2mac@0x2a>, r1=<clobbered>
loc_2e:
  2e:	102f      	lrw	r1, 0x0	// regs: r1=0x0
  30:	d8010307 	ld.b	r0, (r1, 0x307)	// regs: r0=*(0x307)
  34:	d8610303 	ld.b	r3, (r1, 0x303)	// regs: r3=*(0x303)
  38:	d8410302 	ld.b	r2, (r1, 0x302)	// regs: r2=*(0x302)
  3c:	b803      	st.w	r0, (r14, 0xc)	// local_4 = *(0x307)
  3e:	d8010306 	ld.b	r0, (r1, 0x306)	// regs: r0=*(0x306)
  42:	b802      	st.w	r0, (r14, 0x8)	// local_8 = *(0x306)
  44:	d8010305 	ld.b	r0, (r1, 0x305)	// regs: r0=*(0x305)
  48:	b801      	st.w	r0, (r14, 0x4)	// local_c = *(0x305)
  4a:	d8210304 	ld.b	r1, (r1, 0x304)	// regs: r1=*(0x304)
  4e:	b820      	st.w	r1, (r14, 0x0)	// local_10 = *(0x304)
  50:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  52:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  54:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x54>, r1=<clobbered>
  58:	07dc      	br	0x10	// goto loc_10;
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <ah_lmac+0x302>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_mac_addr_hdl.str1.1>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <ah_lmac>
  6a:	0000      	.short	0x0000
  6c:	0000      	.short	0x0000	// <.rodata.atcmd_mac_addr_hdl.str1.1+0x12>
  6e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_mcast_dup_hdl:

00000000 <atcmd_mcast_dup_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1012      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1090      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0b      	bf	0x32	// if (r3 == 0x3f) goto loc_32;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	e9800011 	blz	r0, 0x44	// if (r0 < 0x0) goto loc_44;
  26:	d8640314 	ld.b	r3, (r4, 0x314)	// regs: r3=*(0x314)
  2a:	c4605c80 	ins	r3, r0, 4, 0
  2e:	dc640314 	st.b	r3, (r4, 0x314)	// *(0x314) = *(0x314)
loc_32:
  32:	d8440314 	ld.b	r2, (r4, 0x314)	// regs: r2=*(0x314)
  36:	e442201f 	andi	r2, r2, 31	// regs: r2=(*(0x314) & 0x1f)
  3a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  3c:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  3e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x3e>, r1=<clobbered>
  42:	07e6      	br	0xe	// goto loc_e;
loc_44:
  44:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  46:	3200      	movi	r2, 0	// regs: r2=0x0
  48:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  4a:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  4c:	07f3      	br	0x32	// goto loc_32;
  4e:	0000      	.short	0x0000
  50:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <ah_lmac>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_mcast_dup_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <lmactest>
  5e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_mcast_reorder_hdl:

00000000 <atcmd_mcast_reorder_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1011      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108f      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c09      	bf	0x2e	// if (r3 == 0x3f) goto loc_2e;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d8640314 	ld.b	r3, (r4, 0x314)	// regs: r3=*(0x314)
  26:	c4605c26 	ins	r3, r0, 7, 6
  2a:	dc640314 	st.b	r3, (r4, 0x314)	// *(0x314) = *(0x314)
loc_2e:
  2e:	d8640314 	ld.b	r3, (r4, 0x314)	// regs: r3=*(0x314)
  32:	e46320c0 	andi	r3, r3, 192	// regs: r3=(*(0x314) & 0xc0)
  36:	3b40      	cmpnei	r3, 0
  38:	1047      	lrw	r2, 0x0	// regs: r2=0x0
  3a:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  3c:	c4430c20 	incf	r2, r3, 0
  40:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  42:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  44:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x44>, r1=<clobbered>
  48:	07e3      	br	0xe	// goto loc_e;
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  4e:	0000      	.short	0x0000
  50:	0000      	.short	0x0000	// <ah_lmac>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_mcast_reorder_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_mcast_reorder_hdl.str1.1+0x8>
  5e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_mcast_rts_hdl:

00000000 <atcmd_mcast_rts_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1012      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1090      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	3840      	cmpnei	r0, 0
  24:	d8640314 	ld.b	r3, (r4, 0x314)	// regs: r3=*(0x314)
  28:	c4000502 	mvc	r2	// regs: r2=<cond>
  2c:	c4625c05 	ins	r3, r2, 5, 5
  30:	dc640314 	st.b	r3, (r4, 0x314)	// *(0x314) = *(0x314)
loc_34:
  34:	d8640314 	ld.b	r3, (r4, 0x314)	// regs: r3=*(0x314)
  38:	e4632020 	andi	r3, r3, 32	// regs: r3=(*(0x314) & 0x20)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1047      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
  50:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <ah_lmac>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1+0x7>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_mcast_rts_hdl.str1.1>

Disassembly of section .text.atcmd_tx_cnt_max_hdl:

00000000 <atcmd_tx_cnt_max_hdl>: // arg_bytes: 12
   0:	14d4      	push	r4-r7, r15
   2:	6dc3      	mov	r7, r0	// regs: r7=<arg0>
   4:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   6:	6d8b      	mov	r6, r2	// regs: r6=<arg2>
   8:	e9220007 	bnez	r2, 0x16	// if (r2 != 0x0) goto loc_16;
   c:	1019      	lrw	r0, 0x0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xe>, r1=<clobbered>
loc_12:
  12:	3000      	movi	r0, 0	// regs: r0=0x0
  14:	1494      	pop	r4-r7, r15
loc_16:
  16:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  18:	1097      	lrw	r4, 0x0	// regs: r4=0x0
  1a:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  1c:	eb43003f 	cmpnei	r3, 63
  20:	0c14      	bf	0x48	// if (r3 == 0x3f) goto loc_48;
  22:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x22>, r1=<clobbered>
  26:	5863      	subi	r3, r0, 1	// regs: r3=(<ret atoi@0x22> - 0x1)
  28:	eb0300fe 	cmphsi	r3, 255
  2c:	0817      	bt	0x5a	// if (r3 >= 0xff) goto loc_5a;
  2e:	dc040313 	st.b	r0, (r4, 0x313)	// *(0x313) = <ret atoi@0x22>
loc_32:
  32:	3e01      	cmphsi	r6, 2
  34:	0c0a      	bf	0x48	// if (r6 < 0x2) goto loc_48;
  36:	9501      	ld.w	r0, (r5, 0x4)	// regs: r0=*(<arg1> + 0x4)
  38:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x38>, r1=<clobbered>
  3c:	5863      	subi	r3, r0, 1	// regs: r3=(<ret atoi@0x38> - 0x1)
  3e:	eb0300fe 	cmphsi	r3, 255
  42:	0811      	bt	0x64	// if (r3 >= 0xff) goto loc_64;
  44:	dc040312 	st.b	r0, (r4, 0x312)	// *(0x312) = <ret atoi@0x38>
loc_48:
  48:	d8640312 	ld.b	r3, (r4, 0x312)	// regs: r3=*(0x312)
  4c:	d8440313 	ld.b	r2, (r4, 0x313)	// regs: r2=*(0x313)
  50:	5f26      	addi	r1, r7, 2	// regs: r1=(<arg0> + 0x2)
  52:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  54:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x54>, r1=<clobbered>
  58:	07dd      	br	0x12	// goto loc_12;
loc_5a:
  5a:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  5c:	3200      	movi	r2, 0	// regs: r2=0x0
  5e:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  60:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  62:	07e8      	br	0x32	// goto loc_32;
loc_64:
  64:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  66:	3200      	movi	r2, 0	// regs: r2=0x0
  68:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  6a:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  6c:	07ee      	br	0x48	// goto loc_48;
  6e:	0000      	.short	0x0000
  70:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  74:	0000      	.short	0x0000	// <ah_lmac>
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cnt_max_hdl.str1.1>
  7c:	00000000 	.long	0x00000000	// <lmactest>

Disassembly of section .text.atcmd_set_rts_hdl:

00000000 <atcmd_set_rts_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1011      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108f      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0b      	bf	0x32	// if (r3 == 0x3f) goto loc_32;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	6c83      	mov	r2, r0	// regs: r2=<ret atoi@0x1e>
  24:	e960000e 	blsz	r0, 0x40
  28:	3300      	movi	r3, 0	// regs: r3=0x0
  2a:	3105      	movi	r1, 5	// regs: r1=0x5
  2c:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(0x0)
  2e:	e0000000 	bsr	0x0	// <lmac_ioctl>; regs: r0=<ret lmac_ioctl@0x2e>, r1=<clobbered>
loc_32:
  32:	d8441197 	ld.h	r2, (r4, 0x32e)	// regs: r2=*(r4 + 0x32e)
  36:	5d26      	addi	r1, r5, 2	// regs: r1=(r5 + 0x2)
  38:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  3a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x3a>, r1=<clobbered>
  3e:	07e8      	br	0xe	// goto loc_e;
  40:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  42:	3200      	movi	r2, 0	// regs: r2=0x0
  44:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  46:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  48:	07f5      	br	0x32	// goto loc_32;
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  4e:	0000      	.short	0x0000
  50:	0000      	.short	0x0000	// <ah_lmac>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <.rodata.atcmd_set_rts_hdl.str1.1>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <lmactest>
  5a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_set_bgrssi_hdl:

00000000 <atcmd_set_bgrssi_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100c      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108a      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c07      	bf	0x2a	// if (r3 == 0x3f) goto loc_2a;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	7442      	sextb	r1, r0	// regs: r1=sext8(<ret atoi@0x1e>)
  24:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(0x0)
  26:	e0000000 	bsr	0x0	// <lmac_set_bgrssi>; regs: r0=<ret lmac_set_bgrssi@0x26>, r1=<clobbered>
loc_2a:
  2a:	d844431e 	ld.bs	r2, (r4, 0x31e)	// regs: r2=*(0x31e)
  2e:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  30:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  32:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x32>, r1=<clobbered>
  36:	07ec      	br	0xe	// goto loc_e;
  38:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <ah_lmac>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.rodata.atcmd_set_bgrssi_hdl.str1.1>
  42:	0000      	.short	0x0000

Disassembly of section .text.atcmd_set_bgrssi_avg_hdl:

00000000 <atcmd_set_bgrssi_avg_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100f      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108d      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0b      	bf	0x32	// if (r3 == 0x3f) goto loc_32;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	3823      	cmplti	r0, 4
  24:	0807      	bt	0x32	// if (r0 < 0x4) goto loc_32;
  26:	d86420d8 	ld.w	r3, (r4, 0x360)	// regs: r3=*(0x360)
  2a:	c4605cec 	ins	r3, r0, 19, 12
  2e:	dc6420d8 	st.w	r3, (r4, 0x360)	// *(0x360) = *(0x360)
loc_32:
  32:	d84420d8 	ld.w	r2, (r4, 0x360)	// regs: r2=*(0x360)
  36:	c5825662 	zext	r2, r2, 19, 12	// regs: r2=zext(*(0x360))
  3a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  3c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  3e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x3e>, r1=<clobbered>
  42:	07e6      	br	0xe	// goto loc_e;
  44:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <ah_lmac>
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_set_bgrssi_avg_hdl.str1.1>
  4e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_set_pri_chan_hdl:

00000000 <atcmd_set_pri_chan_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100e      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108c      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0a      	bf	0x30	// if (r3 == 0x3f) goto loc_30;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	3807      	cmphsi	r0, 8
  24:	0806      	bt	0x30	// if (r0 >= 0x8) goto loc_30;
  26:	7400      	zextb	r0, r0	// regs: r0=zext8(<ret atoi@0x1e>)
  28:	dc040309 	st.b	r0, (r4, 0x309)	// *(0x309) = zext8(<ret atoi@0x1e>)
  2c:	e0000000 	bsr	0x0	// <ah_wphy_pri_channel_cfg>; regs: r0=<ret ah_wphy_pri_channel_cfg@0x2c>, r1=<clobbered>
loc_30:
  30:	d8440309 	ld.b	r2, (r4, 0x309)	// regs: r2=*(0x309)
  34:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  36:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  38:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x38>, r1=<clobbered>
  3c:	07e9      	br	0xe	// goto loc_e;
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <ah_lmac>
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <.rodata.atcmd_set_pri_chan_hdl.str1.1>
  4a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_edca_cw_hdl:

00000000 <atcmd_edca_cw_hdl>: // arg_bytes: 12
   0:	14d4      	push	r4-r7, r15
   2:	1426      	subi	r14, r14, 24	// regs: r14=(sp - 0x18)
   4:	6dc3      	mov	r7, r0	// regs: r7=<arg0>
   6:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   8:	e9220008 	bnez	r2, 0x18	// if (r2 != 0x0) goto loc_18;
   c:	1107      	lrw	r0, 0x0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xe>, r1=<clobbered>
loc_12:
  12:	3000      	movi	r0, 0	// regs: r0=0x0
  14:	1406      	addi	r14, r14, 24	// regs: r14=(sp + 0x18)
  16:	1494      	pop	r4-r7, r15
loc_18:
  18:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  1a:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  1c:	eb43003f 	cmpnei	r3, 63
  20:	0c1a      	bf	0x54	// if (r3 == 0x3f) goto loc_54;
  22:	3a43      	cmpnei	r2, 3
  24:	083d      	bt	0x9e	// if (r2 != 0x3) goto loc_9e;
  26:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x26>, r1=<clobbered>
  2a:	3803      	cmphsi	r0, 4
  2c:	6d83      	mov	r6, r0	// regs: r6=<ret atoi@0x26>
  2e:	0834      	bt	0x96	// if (r0 >= 0x4) goto loc_96;
  30:	9501      	ld.w	r0, (r5, 0x4)	// regs: r0=*(<arg1> + 0x4)
  32:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x32>, r1=<clobbered>
  36:	6d03      	mov	r4, r0	// regs: r4=<ret atoi@0x32>
  38:	e960002b 	blsz	r0, 0x8e
  3c:	9502      	ld.w	r0, (r5, 0x8)	// regs: r0=*(<arg1> + 0x8)
  3e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x3e>, r1=<clobbered>
  42:	6c83      	mov	r2, r0	// regs: r2=<ret atoi@0x3e>
  44:	e9600021 	blsz	r0, 0x86
  48:	6501      	cmplt	r0, r4
  4a:	0819      	bt	0x7c	// if (T) goto loc_7c;
  4c:	6c53      	mov	r1, r4	// regs: r1=<ret atoi@0x32>
  4e:	7418      	zextb	r0, r6	// regs: r0=zext8(<ret atoi@0x26>)
  50:	e0000000 	bsr	0x0	// <lmac_cfg_cw_param>; regs: r0=<ret lmac_cfg_cw_param@0x50>, r1=<clobbered>
loc_54:
  54:	1036      	lrw	r1, 0x0	// regs: r1=0x0
  56:	891f      	ld.h	r0, (r1, 0x3e)	// regs: r0=*(0x3e)
  58:	897c      	ld.h	r3, (r1, 0x38)	// regs: r3=*(0x38)
  5a:	8954      	ld.h	r2, (r1, 0x28)	// regs: r2=*(0x28)
  5c:	b805      	st.w	r0, (r14, 0x14)	// stack_p14 = *(0x3e)
  5e:	8917      	ld.h	r0, (r1, 0x2e)	// regs: r0=*(0x2e)
  60:	b804      	st.w	r0, (r14, 0x10)	// stack_p10 = *(0x2e)
  62:	891e      	ld.h	r0, (r1, 0x3c)	// regs: r0=*(0x3c)
  64:	b803      	st.w	r0, (r14, 0xc)	// stack_pc = *(0x3c)
  66:	8916      	ld.h	r0, (r1, 0x2c)	// regs: r0=*(0x2c)
  68:	b802      	st.w	r0, (r14, 0x8)	// stack_p8 = *(0x2c)
  6a:	891d      	ld.h	r0, (r1, 0x3a)	// regs: r0=*(0x3a)
  6c:	b801      	st.w	r0, (r14, 0x4)	// stack_p4 = *(0x3a)
  6e:	8935      	ld.h	r1, (r1, 0x2a)	// regs: r1=*(0x2a)
  70:	b820      	st.w	r1, (r14, 0x0)	// stack_0 = *(0x2a)
  72:	5f26      	addi	r1, r7, 2	// regs: r1=(r7 + 0x2)
  74:	100f      	lrw	r0, 0x0	// regs: r0=0x0
  76:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x76>, r1=<clobbered>
  7a:	07cc      	br	0x12	// goto loc_12;
loc_7c:
  7c:	3200      	movi	r2, 0	// regs: r2=0x0
  7e:	106e      	lrw	r3, 0x0	// regs: r3=0x0
  80:	2a04      	subi	r2, 5	// regs: r2=0xfffffffb
loc_82:
  82:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = r2
  84:	07e8      	br	0x54	// goto loc_54;
  86:	3200      	movi	r2, 0	// regs: r2=0x0
  88:	106b      	lrw	r3, 0x0	// regs: r3=0x0
  8a:	2a03      	subi	r2, 4	// regs: r2=0xfffffffc
  8c:	07fb      	br	0x82	// goto loc_82;
  8e:	3200      	movi	r2, 0	// regs: r2=0x0
  90:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  92:	2a02      	subi	r2, 3	// regs: r2=0xfffffffd
  94:	07f7      	br	0x82	// goto loc_82;
loc_96:
  96:	3200      	movi	r2, 0	// regs: r2=0x0
  98:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  9a:	2a01      	subi	r2, 2	// regs: r2=0xfffffffe
  9c:	07f3      	br	0x82	// goto loc_82;
loc_9e:
  9e:	3200      	movi	r2, 0	// regs: r2=0x0
  a0:	1065      	lrw	r3, 0x0	// regs: r3=0x0
  a2:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  a4:	07ef      	br	0x82	// goto loc_82;
  a6:	0000      	.short	0x0000
  a8:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  ac:	00000000 	.long	0x00000000	// <ah_lmac>
  b0:	00000000 	.long	0x00000000	// <.rodata.atcmd_edca_cw_hdl.str1.1>
  b4:	0000      	.short	0x0000	// <lmactest>
  b6:	0000      	.short	0x0000

Disassembly of section .text.atcmd_edca_aifs_hdl:

00000000 <atcmd_edca_aifs_hdl>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   6:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   8:	e9220008 	bnez	r2, 0x18	// if (r2 != 0x0) goto loc_18;
   c:	101a      	lrw	r0, 0x0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xe>, r1=<clobbered>
loc_12:
  12:	3000      	movi	r0, 0	// regs: r0=0x0
  14:	1402      	addi	r14, r14, 8	// regs: r14=(sp + 0x8)
  16:	1493      	pop	r4-r6, r15
loc_18:
  18:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  1a:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  1c:	eb43003f 	cmpnei	r3, 63
  20:	0c11      	bf	0x42	// if (r3 == 0x3f) goto loc_42;
  22:	3a42      	cmpnei	r2, 2
  24:	0824      	bt	0x6c	// if (r2 != 0x2) goto loc_6c;
  26:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x26>, r1=<clobbered>
  2a:	3803      	cmphsi	r0, 4
  2c:	6d03      	mov	r4, r0	// regs: r4=<ret atoi@0x26>
  2e:	081b      	bt	0x64	// if (r0 >= 0x4) goto loc_64;
  30:	9501      	ld.w	r0, (r5, 0x4)	// regs: r0=*(<arg1> + 0x4)
  32:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x32>, r1=<clobbered>
  36:	6c43      	mov	r1, r0	// regs: r1=<ret atoi@0x32>
  38:	e9600011 	blsz	r0, 0x5a
  3c:	7410      	zextb	r0, r4	// regs: r0=zext8(<ret atoi@0x26>)
  3e:	e0000000 	bsr	0x0	// <lmac_cfg_aifs_param>; regs: r0=<ret lmac_cfg_aifs_param@0x3e>, r1=<clobbered>
loc_42:
  42:	102e      	lrw	r1, 0x0	// regs: r1=0x0
  44:	811f      	ld.b	r0, (r1, 0x1f)	// regs: r0=*(0x1f)
  46:	817d      	ld.b	r3, (r1, 0x1d)	// regs: r3=*(0x1d)
  48:	815c      	ld.b	r2, (r1, 0x1c)	// regs: r2=*(0x1c)
  4a:	b801      	st.w	r0, (r14, 0x4)	// stack_p4 = *(0x1f)
  4c:	813e      	ld.b	r1, (r1, 0x1e)	// regs: r1=*(0x1e)
  4e:	b820      	st.w	r1, (r14, 0x0)	// stack_0 = *(0x1e)
  50:	5e26      	addi	r1, r6, 2	// regs: r1=(r6 + 0x2)
  52:	100b      	lrw	r0, 0x0	// regs: r0=0x0
  54:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x54>, r1=<clobbered>
  58:	07dd      	br	0x12	// goto loc_12;
  5a:	3200      	movi	r2, 0	// regs: r2=0x0
  5c:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  5e:	2a02      	subi	r2, 3	// regs: r2=0xfffffffd
loc_60:
  60:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = r2
  62:	07f0      	br	0x42	// goto loc_42;
loc_64:
  64:	3200      	movi	r2, 0	// regs: r2=0x0
  66:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  68:	2a01      	subi	r2, 2	// regs: r2=0xfffffffe
  6a:	07fb      	br	0x60	// goto loc_60;
loc_6c:
  6c:	3200      	movi	r2, 0	// regs: r2=0x0
  6e:	1065      	lrw	r3, 0x0	// regs: r3=0x0
  70:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  72:	07f7      	br	0x60	// goto loc_60;
  74:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000	// <ah_lmac>
  7c:	00000000 	.long	0x00000000	// <.rodata.atcmd_edca_aifs_hdl.str1.1>
  80:	00000000 	.long	0x00000000	// <lmactest>

Disassembly of section .text.atcmd_edca_txop_hdl:

00000000 <atcmd_edca_txop_hdl>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   6:	6d87      	mov	r6, r1	// regs: r6=<arg1>
   8:	e9220008 	bnez	r2, 0x18	// if (r2 != 0x0) goto loc_18;
   c:	1100      	lrw	r0, 0x0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xe>, r1=<clobbered>
loc_12:
  12:	3000      	movi	r0, 0	// regs: r0=0x0
  14:	1402      	addi	r14, r14, 8	// regs: r14=((sp - 0x8) + 0x8)
  16:	1493      	pop	r4-r6, r15
loc_18:
  18:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  1a:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  1c:	eb43003f 	cmpnei	r3, 63
  20:	0c12      	bf	0x44	// if (r3 == 0x3f) goto loc_44;
  22:	3a42      	cmpnei	r2, 2
  24:	0830      	bt	0x84	// if (r2 != 0x2) goto loc_84;
  26:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x26>, r1=<clobbered>
  2a:	3803      	cmphsi	r0, 4
  2c:	6d03      	mov	r4, r0	// regs: r4=<ret atoi@0x26>
  2e:	0827      	bt	0x7c	// if (r0 >= 0x4) goto loc_7c;
  30:	9601      	ld.w	r0, (r6, 0x4)	// regs: r0=*(<arg1> + 0x4)
  32:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x32>, r1=<clobbered>
  36:	eb00fffe 	cmphsi	r0, 65535
  3a:	081c      	bt	0x72	// if (r0 >= 0xffff) goto loc_72;
  3c:	7441      	zexth	r1, r0	// regs: r1=zext16(<ret atoi@0x32>)
  3e:	7410      	zextb	r0, r4	// regs: r0=zext8(<ret atoi@0x26>)
  40:	e0000000 	bsr	0x0	// <lmac_cfg_txop_param>; regs: r0=<ret lmac_cfg_txop_param@0x40>, r1=<clobbered>
loc_44:
  44:	1033      	lrw	r1, 0x0	// regs: r1=0x0
  46:	32fa      	movi	r2, 250	// regs: r2=0xfa
  48:	4242      	lsli	r2, r2, 2	// regs: r2=0x3e8
  4a:	9113      	ld.w	r0, (r1, 0x4c)	// regs: r0=*(0x4c)
  4c:	c4408020 	divu	r0, r0, r2	// regs: r0=(*(0x4c) / 0x3e8)
  50:	d9812010 	ld.w	r12, (r1, 0x40)	// regs: r12=*(0x40)
  54:	9171      	ld.w	r3, (r1, 0x44)	// regs: r3=*(0x44)
  56:	b801      	st.w	r0, (r14, 0x4)	// local_4 = (*(0x4c) / 0x3e8)
  58:	9132      	ld.w	r1, (r1, 0x48)	// regs: r1=*(0x48)
  5a:	c4418021 	divu	r1, r1, r2	// regs: r1=(*(0x48) / 0x3e8)
  5e:	b820      	st.w	r1, (r14, 0x0)	// local_8 = (*(0x48) / 0x3e8)
  60:	c4438023 	divu	r3, r3, r2	// regs: r3=(*(0x44) / 0x3e8)
  64:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  66:	c44c8022 	divu	r2, r12, r2	// regs: r2=(*(0x40) / 0x3e8)
  6a:	100b      	lrw	r0, 0x0	// regs: r0=0x0
  6c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x6c>, r1=<clobbered>
  70:	07d1      	br	0x12	// goto loc_12;
loc_72:
  72:	3200      	movi	r2, 0	// regs: r2=0x0
  74:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  76:	2a02      	subi	r2, 3	// regs: r2=0xfffffffd
loc_78:
  78:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = r2
  7a:	07e5      	br	0x44	// goto loc_44;
loc_7c:
  7c:	3200      	movi	r2, 0	// regs: r2=0x0
  7e:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  80:	2a01      	subi	r2, 2	// regs: r2=0xfffffffe
  82:	07fb      	br	0x78	// goto loc_78;
loc_84:
  84:	3200      	movi	r2, 0	// regs: r2=0x0
  86:	1065      	lrw	r3, 0x0	// regs: r3=0x0
  88:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  8a:	07f7      	br	0x78	// goto loc_78;
  8c:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  90:	0000      	.short	0x0000	// <ah_lmac>
  92:	0000      	.short	0x0000
  94:	0000      	.short	0x0000	// <.rodata.atcmd_edca_txop_hdl.str1.1>
  96:	0000      	.short	0x0000
  98:	00000000 	.long	0x00000000	// <lmactest>

Disassembly of section .text.atcmd_tx_trv_pilot_en_hdl:

00000000 <atcmd_tx_trv_pilot_en_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1011      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108f      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c08      	bf	0x2c	// if (r3 == 0x3f) goto loc_2c;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	e9000011 	bez	r0, 0x44	// if (r0 == 0x0) goto loc_44;
  26:	3301      	movi	r3, 1	// regs: r3=0x1
  28:	dc6403e4 	st.b	r3, (r4, 0x3e4)	// *(0x3e4) = 0x1
loc_2c:
  2c:	d86403e4 	ld.b	r3, (r4, 0x3e4)	// regs: r3=*(0x3e4)
  30:	3b40      	cmpnei	r3, 0
  32:	1049      	lrw	r2, 0x0	// regs: r2=0x0
  34:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  36:	c4430c20 	incf	r2, r3, 0
  3a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  3c:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  3e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x3e>, r1=<clobbered>
  42:	07e6      	br	0xe	// goto loc_e;
loc_44:
  44:	dc0403e4 	st.b	r0, (r4, 0x3e4)	// *(0x3e4) = <ret atoi@0x1e>
  48:	07f2      	br	0x2c	// goto loc_2c;
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  4e:	0000      	.short	0x0000
  50:	0000      	.short	0x0000	// <ah_lmac>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_tx_trv_pilot_en_hdl.str1.1>
  5e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_evm_margin_hdl:

00000000 <atcmd_evm_margin_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1089      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c05      	bf	0x26	// if (r3 == 0x3f) goto loc_26;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	dc040870 	st.b	r0, (r4, 0x870)	// *(0x870) = <ret atoi@0x1e>
loc_26:
  26:	d8444870 	ld.bs	r2, (r4, 0x870)	// regs: r2=*(0x870)
  2a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  2c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2e>, r1=<clobbered>
  32:	07ee      	br	0xe	// goto loc_e;
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_evm_margin_hdl.str1.1>
  3e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_ccmp_support_hdl:

00000000 <atcmd_ccmp_support_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	1018      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	8340      	ld.b	r2, (r3, 0x0)	// regs: r2=*(*(<arg1>))
  14:	eb420031 	cmpnei	r2, 49
  18:	1074      	lrw	r3, 0x0	// regs: r3=0x0
  1a:	0c1c      	bf	0x52	// if (r2 == 0x31) goto loc_52;
  1c:	eb42003f 	cmpnei	r2, 63
  20:	0c0b      	bf	0x36	// if (r2 == 0x3f) goto loc_36;
  22:	eb420030 	cmpnei	r2, 48
  26:	081a      	bt	0x5a	// if (r2 != 0x30) goto loc_5a;
  28:	d8430336 	ld.b	r2, (r3, 0x336)	// regs: r2=*(0x336)
  2c:	3100      	movi	r1, 0	// regs: r1=0x0
loc_2e:
  2e:	c4415c00 	ins	r2, r1, 0, 0
  32:	dc430336 	st.b	r2, (r3, 0x336)	// *(0x336) = *(0x336)
loc_36:
  36:	d8630336 	ld.b	r3, (r3, 0x336)	// regs: r3=*(0x336)
  3a:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x336) & 0x1)
  3e:	3b40      	cmpnei	r3, 0
  40:	104b      	lrw	r2, 0x0	// regs: r2=0x0
  42:	106c      	lrw	r3, 0x0	// regs: r3=0x0
  44:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  46:	c4430c20 	incf	r2, r3, 0
  4a:	100b      	lrw	r0, 0x0	// regs: r0=0x0
  4c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4c>, r1=<clobbered>
  50:	07de      	br	0xc	// goto loc_c;
loc_52:
  52:	d8430336 	ld.b	r2, (r3, 0x336)	// regs: r2=*(0x336)
  56:	3101      	movi	r1, 1	// regs: r1=0x1
  58:	07eb      	br	0x2e	// goto loc_2e;
loc_5a:
  5a:	1048      	lrw	r2, 0x0	// regs: r2=0x0
  5c:	3100      	movi	r1, 0	// regs: r1=0x0
  5e:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  60:	b232      	st.w	r1, (r2, 0x48)	// *(0x48) = 0xffffffff
  62:	07ea      	br	0x36	// goto loc_36;
  64:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <ah_lmac>
  6a:	0000      	.short	0x0000
  6c:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  6e:	0000      	.short	0x0000
  70:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  74:	0000      	.short	0x0000	// <.rodata.atcmd_ccmp_support_hdl.str1.1>
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000	// <lmactest>

Disassembly of section .text.atcmd_lmac_print_period_hdl:

00000000 <atcmd_lmac_print_period_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100f      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108d      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c07      	bf	0x2a	// if (r3 == 0x3f) goto loc_2a;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	e980000b 	blz	r0, 0x38	// if (r0 < 0x0) goto loc_38;
  26:	dc0420e6 	st.w	r0, (r4, 0x398)	// *(0x398) = <ret atoi@0x1e>
loc_2a:
  2a:	d84420e6 	ld.w	r2, (r4, 0x398)	// regs: r2=*(0x398)
  2e:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  30:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  32:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x32>, r1=<clobbered>
  36:	07ec      	br	0xe	// goto loc_e;
loc_38:
  38:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  3a:	3200      	movi	r2, 0	// regs: r2=0x0
  3c:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  3e:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  40:	07f5      	br	0x2a	// goto loc_2a;
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <ah_lmac>
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_lmac_print_period_hdl.str1.1>
  4e:	0000      	.short	0x0000
  50:	0000      	.short	0x0000	// <lmactest>
  52:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_pkts_rd_hdl:

00000000 <atcmd_tx_pkts_rd_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	100c      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  14:	eb43003f 	cmpnei	r3, 63
  18:	0c05      	bf	0x22	// if (r3 == 0x3f) goto loc_22;
  1a:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  1c:	3200      	movi	r2, 0	// regs: r2=0x0
  1e:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  20:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
loc_22:
  22:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  24:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  26:	d84321b8 	ld.w	r2, (r3, 0x6e0)	// regs: r2=*(0x6e0)
  2a:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  2c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2c>, r1=<clobbered>
  30:	07ee      	br	0xc	// goto loc_c;
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <lmactest>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <ah_lmac>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.rodata.atcmd_tx_pkts_rd_hdl.str1.1>
  42:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_fail_rd_hdl:

00000000 <atcmd_tx_fail_rd_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	100c      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  14:	eb43003f 	cmpnei	r3, 63
  18:	0c05      	bf	0x22	// if (r3 == 0x3f) goto loc_22;
  1a:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  1c:	3200      	movi	r2, 0	// regs: r2=0x0
  1e:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  20:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
loc_22:
  22:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  24:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  26:	d84321b9 	ld.w	r2, (r3, 0x6e4)	// regs: r2=*(0x6e4)
  2a:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  2c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2c>, r1=<clobbered>
  30:	07ee      	br	0xc	// goto loc_c;
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <lmactest>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <ah_lmac>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.rodata.atcmd_tx_fail_rd_hdl.str1.1>
  42:	0000      	.short	0x0000

Disassembly of section .text.atcmd_rx_rssi_rd_hdl:

00000000 <atcmd_rx_rssi_rd_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	100c      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  14:	eb43003f 	cmpnei	r3, 63
  18:	0c05      	bf	0x22	// if (r3 == 0x3f) goto loc_22;
  1a:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  1c:	3200      	movi	r2, 0	// regs: r2=0x0
  1e:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  20:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
loc_22:
  22:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  24:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  26:	d84321be 	ld.w	r2, (r3, 0x6f8)	// regs: r2=*(0x6f8)
  2a:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  2c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2c>, r1=<clobbered>
  30:	07ee      	br	0xc	// goto loc_c;
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <lmactest>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <ah_lmac>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.rodata.atcmd_rx_rssi_rd_hdl.str1.1>
  42:	0000      	.short	0x0000

Disassembly of section .text.atcmd_rx_evm_rd_hdl:

00000000 <atcmd_rx_evm_rd_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	100c      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  14:	eb43003f 	cmpnei	r3, 63
  18:	0c05      	bf	0x22	// if (r3 == 0x3f) goto loc_22;
  1a:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  1c:	3200      	movi	r2, 0	// regs: r2=0x0
  1e:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  20:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
loc_22:
  22:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  24:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  26:	d84321bf 	ld.w	r2, (r3, 0x6fc)	// regs: r2=*(0x6fc)
  2a:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  2c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2c>, r1=<clobbered>
  30:	07ee      	br	0xc	// goto loc_c;
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <lmactest>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <ah_lmac>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.rodata.atcmd_rx_evm_rd_hdl.str1.1>
  42:	0000      	.short	0x0000

Disassembly of section .text.atcmd_rx_pkts_rd_hdl:

00000000 <atcmd_rx_pkts_rd_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	100c      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  14:	eb43003f 	cmpnei	r3, 63
  18:	0c05      	bf	0x22	// if (r3 == 0x3f) goto loc_22;
  1a:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  1c:	3200      	movi	r2, 0	// regs: r2=0x0
  1e:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  20:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
loc_22:
  22:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  24:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  26:	d84321bc 	ld.w	r2, (r3, 0x6f0)	// regs: r2=*(0x6f0)
  2a:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  2c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2c>, r1=<clobbered>
  30:	07ee      	br	0xc	// goto loc_c;
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <lmactest>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <ah_lmac>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.rodata.atcmd_rx_pkts_rd_hdl.str1.1>
  42:	0000      	.short	0x0000

Disassembly of section .text.atcmd_rx_err_rd_hdl:

00000000 <atcmd_rx_err_rd_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	100c      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  14:	eb43003f 	cmpnei	r3, 63
  18:	0c05      	bf	0x22	// if (r3 == 0x3f) goto loc_22;
  1a:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  1c:	3200      	movi	r2, 0	// regs: r2=0x0
  1e:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  20:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
loc_22:
  22:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  24:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  26:	d84321bd 	ld.w	r2, (r3, 0x6f4)	// regs: r2=*(0x6f4)
  2a:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  2c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2c>, r1=<clobbered>
  30:	07ee      	br	0xc	// goto loc_c;
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <lmactest>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <ah_lmac>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.rodata.atcmd_rx_err_rd_hdl.str1.1>
  42:	0000      	.short	0x0000

Disassembly of section .text.atcmd_rx_agc_rd_hdl:

00000000 <atcmd_rx_agc_rd_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	100c      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  14:	eb43003f 	cmpnei	r3, 63
  18:	0c05      	bf	0x22	// if (r3 == 0x3f) goto loc_22;
  1a:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  1c:	3200      	movi	r2, 0	// regs: r2=0x0
  1e:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  20:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
loc_22:
  22:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  24:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  26:	d84321c1 	ld.w	r2, (r3, 0x704)	// regs: r2=*(0x704)
  2a:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  2c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2c>, r1=<clobbered>
  30:	07ee      	br	0xc	// goto loc_c;
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <lmactest>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <ah_lmac>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.rodata.atcmd_rx_agc_rd_hdl.str1.1>
  42:	0000      	.short	0x0000

Disassembly of section .text.atcmd_bus_wt_hdl:

00000000 <atcmd_bus_wt_hdl>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	1107      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1493      	pop	r4-r6, r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	58a6      	addi	r5, r0, 2	// regs: r5=(<arg0> + 0x2)
  14:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  16:	eb430031 	cmpnei	r3, 49
  1a:	1183      	lrw	r4, 0x0	// regs: r4=0x0
  1c:	0c1d      	bf	0x56	// if (r3 == 0x31) goto loc_56;
  1e:	eb43003f 	cmpnei	r3, 63
  22:	0c0f      	bf	0x40	// if (r3 == 0x3f) goto loc_40;
  24:	eb430030 	cmpnei	r3, 48
  28:	0835      	bt	0x92	// if (r3 != 0x30) goto loc_92;
  2a:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(0x1)
  2c:	3600      	movi	r6, 0	// regs: r6=0x0
  2e:	9408      	ld.w	r0, (r4, 0x20)	// regs: r0=*(0x20)
  30:	c4665c02 	ins	r3, r6, 2, 2
  34:	a461      	st.b	r3, (r4, 0x1)	// *(0x1) = *(0x1)
  36:	e9000032 	bez	r0, 0x9a	// if (r0 == 0x0) goto loc_9a;
  3a:	e0000000 	bsr	0x0	// <kfree_skb>; regs: r0=<ret kfree_skb@0x3a>, r1=<clobbered>
  3e:	b4c8      	st.w	r6, (r4, 0x20)	// *(0x20) = 0x0
loc_40:
  40:	9468      	ld.w	r3, (r4, 0x20)	// regs: r3=*(0x20)
  42:	3b40      	cmpnei	r3, 0
  44:	1059      	lrw	r2, 0x0	// regs: r2=0x0
  46:	107a      	lrw	r3, 0x0	// regs: r3=0x0
  48:	c4430c20 	incf	r2, r3, 0
loc_4c:
  4c:	6c57      	mov	r1, r5	// regs: r1=(<arg0> + 0x2)
  4e:	1019      	lrw	r0, 0x0	// regs: r0=0x0
  50:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x50>, r1=<clobbered>
  54:	07dc      	br	0xc	// goto loc_c;
loc_56:
  56:	1078      	lrw	r3, 0x0	// regs: r3=0x0
  58:	d86309e2 	ld.b	r3, (r3, 0x9e2)	// regs: r3=*(0x9e2)
  5c:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  60:	e903fff0 	bez	r3, 0x40	// if (r3 == 0x0) goto loc_40;
  64:	ea0006b4 	movi	r0, 1716	// regs: r0=0x6b4
  68:	e0000000 	bsr	0x0	// <alloc_tx_skb>; regs: r0=<ret alloc_tx_skb@0x68>, r1=<clobbered>
  6c:	b408      	st.w	r0, (r4, 0x20)	// *(0x20) = <ret alloc_tx_skb@0x68>
  6e:	e9000016 	bez	r0, 0x9a	// if (r0 == 0x0) goto loc_9a;
  72:	d840002a 	ld.b	r2, (r0, 0x2a)	// regs: r2=*(<ret alloc_tx_skb@0x68> + 0x2a)
  76:	3601      	movi	r6, 1	// regs: r6=0x1
  78:	c4465c06 	ins	r2, r6, 6, 6
  7c:	3180      	movi	r1, 128	// regs: r1=0x80
  7e:	dc40002a 	st.b	r2, (r0, 0x2a)	// *(<ret alloc_tx_skb@0x68> + 0x2a) = *(<ret alloc_tx_skb@0x68> + 0x2a)
  82:	7058      	lsl	r1, r6
  84:	e0000000 	bsr	0x0	// <skb_reserve>; regs: r0=<ret skb_reserve@0x84>, r1=<clobbered>
  88:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(0x1)
  8a:	c4665c02 	ins	r3, r6, 2, 2
  8e:	a461      	st.b	r3, (r4, 0x1)	// *(0x1) = *(0x1)
  90:	07d8      	br	0x40	// goto loc_40;
loc_92:
  92:	3300      	movi	r3, 0	// regs: r3=0x0
  94:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  96:	b472      	st.w	r3, (r4, 0x48)	// *(0x48) = 0xffffffff
  98:	07d4      	br	0x40	// goto loc_40;
loc_9a:
  9a:	1045      	lrw	r2, 0x0	// regs: r2=0x0
  9c:	07d8      	br	0x4c	// goto loc_4c;
  9e:	0000      	.short	0x0000
  a0:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  a2:	0000      	.short	0x0000
  a4:	0000      	.short	0x0000	// <lmactest>
  a6:	0000      	.short	0x0000
  a8:	00000000 	.long	0x00000000	// <.rodata.atcmd_ant_dual_hdl.str1.1>
  ac:	00000000 	.long	0x00000000	// <.rodata.atcmd_ant_dual_hdl.str1.1+0x7>
  b0:	00000000 	.long	0x00000000	// <.rodata.atcmd_bus_wt_hdl.str1.1>
  b4:	0000      	.short	0x0000	// <ah_lmac>
  b6:	0000      	.short	0x0000

Disassembly of section .text.atcmd_nor_rd_hdl:

00000000 <atcmd_nor_rd_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	101c      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  14:	109a      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb430031 	cmpnei	r3, 49
  1c:	0c19      	bf	0x4e	// if (r3 == 0x31) goto loc_4e;
  1e:	eb43003f 	cmpnei	r3, 63
  22:	0c09      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  24:	eb430030 	cmpnei	r3, 48
  28:	0823      	bt	0x6e	// if (r3 != 0x30) goto loc_6e;
  2a:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(0x1)
  2c:	3200      	movi	r2, 0	// regs: r2=0x0
loc_2e:
  2e:	c4625c03 	ins	r3, r2, 3, 3
  32:	a461      	st.b	r3, (r4, 0x1)	// *(0x1) = *(0x1)
loc_34:
  34:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(0x1)
  36:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x1) & 0x8)
  3a:	3b40      	cmpnei	r3, 0
  3c:	1051      	lrw	r2, 0x0	// regs: r2=0x0
  3e:	1072      	lrw	r3, 0x0	// regs: r3=0x0
  40:	c4430c20 	incf	r2, r3, 0
  44:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  46:	1011      	lrw	r0, 0x0	// regs: r0=0x0
  48:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x48>, r1=<clobbered>
  4c:	07e1      	br	0xe	// goto loc_e;
loc_4e:
  4e:	1070      	lrw	r3, 0x0	// regs: r3=0x0
  50:	d86309e2 	ld.b	r3, (r3, 0x9e2)	// regs: r3=*(0x9e2)
  54:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  58:	e903ffee 	bez	r3, 0x34	// if (r3 == 0x0) goto loc_34;
  5c:	9402      	ld.w	r0, (r4, 0x8)	// regs: r0=*(0x8)
  5e:	e0000000 	bsr	0x0	// <_os_malloc>; regs: r0=<ret _os_malloc@0x5e>, r1=<clobbered>
  62:	b401      	st.w	r0, (r4, 0x4)	// *(0x4) = <ret _os_malloc@0x5e>
  64:	e900ffe8 	bez	r0, 0x34	// if (r0 == 0x0) goto loc_34;
  68:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(0x1)
  6a:	3201      	movi	r2, 1	// regs: r2=0x1
  6c:	07e1      	br	0x2e	// goto loc_2e;
loc_6e:
  6e:	3300      	movi	r3, 0	// regs: r3=0x0
  70:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  72:	b472      	st.w	r3, (r4, 0x48)	// *(0x48) = 0xffffffff
  74:	07e0      	br	0x34	// goto loc_34;
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  7c:	00000000 	.long	0x00000000	// <lmactest>
  80:	00000000 	.long	0x00000000	// <.rodata.atcmd_ant_dual_hdl.str1.1>
  84:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1+0x7>
  86:	0000      	.short	0x0000
  88:	00000000 	.long	0x00000000	// <.rodata.atcmd_nor_rd_hdl.str1.1>
  8c:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.atcmd_cs_num_hdl:

00000000 <atcmd_cs_num_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1089      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c05      	bf	0x26	// if (r3 == 0x3f) goto loc_26;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	dc040348 	st.b	r0, (r4, 0x348)	// *(0x348) = <ret atoi@0x1e>
loc_26:
  26:	d8440348 	ld.b	r2, (r4, 0x348)	// regs: r2=*(0x348)
  2a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  2c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2e>, r1=<clobbered>
  32:	07ee      	br	0xe	// goto loc_e;
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_cs_num_hdl.str1.1>
  3e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_cs_cnt_hdl:

00000000 <atcmd_cs_cnt_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1089      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c05      	bf	0x26	// if (r3 == 0x3f) goto loc_26;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	dc04032a 	st.b	r0, (r4, 0x32a)	// *(0x32a) = <ret atoi@0x1e>
loc_26:
  26:	d844432a 	ld.bs	r2, (r4, 0x32a)	// regs: r2=*(0x32a)
  2a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  2c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2e>, r1=<clobbered>
  32:	07ee      	br	0xe	// goto loc_e;
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_cs_cnt_hdl.str1.1>
  3e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_chan_scan_hdl:

00000000 <atcmd_chan_scan_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1011      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108f      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c09      	bf	0x2e	// if (r3 == 0x3f) goto loc_2e;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d864037c 	ld.b	r3, (r4, 0x37c)	// regs: r3=*(0x37c)
  26:	c4605c00 	ins	r3, r0, 0, 0
  2a:	dc64037c 	st.b	r3, (r4, 0x37c)	// *(0x37c) = *(0x37c)
loc_2e:
  2e:	d864037c 	ld.b	r3, (r4, 0x37c)	// regs: r3=*(0x37c)
  32:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x37c) & 0x1)
  36:	3b40      	cmpnei	r3, 0
  38:	1047      	lrw	r2, 0x0	// regs: r2=0x0
  3a:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  3c:	c4430c20 	incf	r2, r3, 0
  40:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  42:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  44:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x44>, r1=<clobbered>
  48:	07e3      	br	0xe	// goto loc_e;
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  4e:	0000      	.short	0x0000
  50:	0000      	.short	0x0000	// <ah_lmac>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_chan_scan_hdl.str1.1>
  5e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_cs_enable_hdl:

00000000 <atcmd_cs_enable_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1011      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108f      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c09      	bf	0x2e	// if (r3 == 0x3f) goto loc_2e;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d864037c 	ld.b	r3, (r4, 0x37c)	// regs: r3=*(0x37c)
  26:	c4605c01 	ins	r3, r0, 1, 1
  2a:	dc64037c 	st.b	r3, (r4, 0x37c)	// *(0x37c) = *(0x37c)
loc_2e:
  2e:	d864037c 	ld.b	r3, (r4, 0x37c)	// regs: r3=*(0x37c)
  32:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x37c) & 0x2)
  36:	3b40      	cmpnei	r3, 0
  38:	1047      	lrw	r2, 0x0	// regs: r2=0x0
  3a:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  3c:	c4430c20 	incf	r2, r3, 0
  40:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  42:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  44:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x44>, r1=<clobbered>
  48:	07e3      	br	0xe	// goto loc_e;
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  4e:	0000      	.short	0x0000
  50:	0000      	.short	0x0000	// <ah_lmac>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_cs_enable_hdl.str1.1>
  5e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_cs_th_hdl:

00000000 <atcmd_cs_th_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100e      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108c      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c09      	bf	0x2e	// if (r3 == 0x3f) goto loc_2e;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d86411be 	ld.h	r3, (r4, 0x37c)	// regs: r3=*(0x37c)
  26:	c4605ce2 	ins	r3, r0, 9, 2
  2a:	dc6411be 	st.h	r3, (r4, 0x37c)	// *(0x37c) = *(0x37c)
loc_2e:
  2e:	d84411be 	ld.h	r2, (r4, 0x37c)	// regs: r2=*(0x37c)
  32:	c4425522 	zext	r2, r2, 9, 2	// regs: r2=zext(*(0x37c))
  36:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  38:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  3a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x3a>, r1=<clobbered>
  3e:	07e8      	br	0xe	// goto loc_e;
  40:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <ah_lmac>
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <.rodata.atcmd_cs_th_hdl.str1.1>
  4a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_cs_period_hdl:

00000000 <atcmd_cs_period_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1089      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c05      	bf	0x26	// if (r3 == 0x3f) goto loc_26;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	dc0420e4 	st.w	r0, (r4, 0x390)	// *(0x390) = <ret atoi@0x1e>
loc_26:
  26:	d84420e4 	ld.w	r2, (r4, 0x390)	// regs: r2=*(0x390)
  2a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  2c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2e>, r1=<clobbered>
  32:	07ee      	br	0xe	// goto loc_e;
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_cs_period_hdl.str1.1>
  3e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_acs_start_hdl:

00000000 <atcmd_acs_start_hdl>: // arg_bytes: 12
   0:	14d5      	push	r4-r8, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	6dc7      	mov	r7, r1	// regs: r7=<arg1>
   6:	6e0b      	mov	r8, r2	// regs: r8=<arg2>
   8:	e9220007 	bnez	r2, 0x16	// if (r2 != 0x0) goto loc_16;
   c:	1107      	lrw	r0, 0x0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xe>, r1=<clobbered>
loc_12:
  12:	3000      	movi	r0, 0	// regs: r0=0x0
  14:	1495      	pop	r4-r8, r15
loc_16:
  16:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  18:	1185      	lrw	r4, 0x0	// regs: r4=0x0
  1a:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  1c:	eb43003f 	cmpnei	r3, 63
  20:	0c2e      	bf	0x7c	// if (r3 == 0x3f) goto loc_7c;
  22:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x22>, r1=<clobbered>
  26:	eb080001 	cmphsi	r8, 2
  2a:	6d83      	mov	r6, r0	// regs: r6=<ret atoi@0x22>
  2c:	0c08      	bf	0x3c	// if (r8 < 0x2) goto loc_3c;
  2e:	9701      	ld.w	r0, (r7, 0x4)	// regs: r0=*(<arg1> + 0x4)
  30:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x30>, r1=<clobbered>
  34:	e9000004 	bez	r0, 0x3c	// if (r0 == 0x0) goto loc_3c;
  38:	dc0420d7 	st.w	r0, (r4, 0x35c)	// *(0x35c) = <ret atoi@0x30>
loc_3c:
  3c:	d86409e0 	ld.b	r3, (r4, 0x9e0)	// regs: r3=*(0x9e0)
  40:	e906002e 	bez	r6, 0x9c	// if (r6 == 0x0) goto loc_9c;
  44:	3101      	movi	r1, 1	// regs: r1=0x1
  46:	c4615c00 	ins	r3, r1, 0, 0
  4a:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(0xa84)
  4e:	d80422a2 	ld.w	r0, (r4, 0xa88)	// regs: r0=*(0xa88)
  52:	dc6409e0 	st.b	r3, (r4, 0x9e0)	// *(0x9e0) = *(0x9e0)
  56:	5a64      	addu	r3, r2, r1	// regs: r3=(*(0xa84) + 0x1)
  58:	640d      	cmplt	r3, r0
  5a:	c403008c 	subu	r12, r3, r0	// regs: r12=((*(0xa84) + 0x1) - *(0xa88))
  5e:	c46c0c20 	incf	r3, r12, 0
  62:	d80422a0 	ld.w	r0, (r4, 0xa80)	// regs: r0=*(0xa80)
  66:	640e      	cmpne	r3, r0
  68:	0c07      	bf	0x76	// if (!T) goto loc_76;
  6a:	e44202a2 	addi	r2, r2, 675	// regs: r2=(*(0xa84) + 0x2a3)
  6e:	d4440881 	str.w	r1, (r4, r2 << 2)
  72:	dc6422a1 	st.w	r3, (r4, 0xa84)	// *(0xa84) = (*(0xa84) + 0x1)
loc_76:
  76:	100f      	lrw	r0, 0x0	// regs: r0=0x0
  78:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x78>, r1=<clobbered>
loc_7c:
  7c:	d86409e0 	ld.b	r3, (r4, 0x9e0)	// regs: r3=*(0x9e0)
  80:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x9e0) & 0x1)
  84:	3b40      	cmpnei	r3, 0
  86:	102c      	lrw	r1, 0x0	// regs: r1=0x0
  88:	104c      	lrw	r2, 0x0	// regs: r2=0x0
  8a:	c4410c40 	inct	r2, r1, 0
  8e:	d86420d7 	ld.w	r3, (r4, 0x35c)	// regs: r3=*(0x35c)
  92:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  94:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  96:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x96>, r1=<clobbered>
  9a:	07bc      	br	0x12	// goto loc_12;
loc_9c:
  9c:	c4665c00 	ins	r3, r6, 0, 0
  a0:	dc6409e0 	st.b	r3, (r4, 0x9e0)	// *(0x9e0) = *(0x9e0)
  a4:	07ec      	br	0x7c	// goto loc_7c;
  a6:	0000      	.short	0x0000
  a8:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  ac:	00000000 	.long	0x00000000	// <ah_lmac>
  b0:	00000000 	.long	0x00000000	// <ah_lmac+0xb90>
  b4:	0000      	.short	0x0000	// <.rodata.atcmd_test_start_hdl.str1.1>
  b6:	0000      	.short	0x0000
  b8:	00000000 	.long	0x00000000	// <.rodata.atcmd_acs_start_hdl.str1.1>
  bc:	00000000 	.long	0x00000000	// <.rodata.atcmd_acs_start_hdl.str1.1+0x5>

Disassembly of section .text.atcmd_ack_to_extra_hdl:

00000000 <atcmd_ack_to_extra_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1089      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c05      	bf	0x26	// if (r3 == 0x3f) goto loc_26;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	dc0411ee 	st.h	r0, (r4, 0x3dc)	// *(0x3dc) = <ret atoi@0x1e>
loc_26:
  26:	d84411ee 	ld.h	r2, (r4, 0x3dc)	// regs: r2=*(0x3dc)
  2a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  2c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2e>, r1=<clobbered>
  32:	07ee      	br	0xe	// goto loc_e;
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_ack_to_extra_hdl.str1.1>
  3e:	0000      	.short	0x0000

Disassembly of section .text.config_ft_att_val:

00000000 <config_ft_att_val>: // arg_bytes: 4
   0:	14d1      	push	r4, r15
   2:	381f      	cmphsi	r0, 32
   4:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   6:	0808      	bt	0x16	// if (r0 >= 0x20) goto loc_16;
   8:	7400      	zextb	r0, r0	// regs: r0=zext8(<arg0>)
   a:	e0000000 	bsr	0x0	// <ft_att1_write> // arg_bytes: 4; regs: r0=<ret ft_att1_write@0xa>, r1=<clobbered>
   e:	3000      	movi	r0, 0	// regs: r0=0x0
loc_10:
  10:	e0000000 	bsr	0x0	// <ft_att2_write> // arg_bytes: 4; regs: r0=<ret ft_att2_write@0x10>, r1=<clobbered>
loc_14:
  14:	1491      	pop	r4, r15
loc_16:
  16:	e460101f 	subi	r3, r0, 32	// regs: r3=(<arg0> - 0x20)
  1a:	3b1e      	cmphsi	r3, 31
  1c:	0bfc      	bt	0x14	// if (r3 >= 0x1f) goto loc_14;
  1e:	301f      	movi	r0, 31	// regs: r0=0x1f
  20:	e0000000 	bsr	0x0	// <ft_att1_write> // arg_bytes: 4; regs: r0=<ret ft_att1_write@0x20>, r1=<clobbered>
  24:	e404101e 	subi	r0, r4, 31	// regs: r0=(<arg0> - 0x1f)
  28:	7400      	zextb	r0, r0	// regs: r0=zext8((<arg0> - 0x1f))
  2a:	07f3      	br	0x10	// goto loc_10;

Disassembly of section .text.atcmd_ft_att_hdl:

00000000 <atcmd_ft_att_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c14      	bf	0x44	// if (r3 == 0x3f) goto loc_44;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	eb00003e 	cmphsi	r0, 63
  26:	080f      	bt	0x44	// if (r0 >= 0x3f) goto loc_44;
  28:	d8640708 	ld.b	r3, (r4, 0x708)	// regs: r3=*(0x708)
  2c:	c4605ca0 	ins	r3, r0, 5, 0
  30:	dc640708 	st.b	r3, (r4, 0x708)	// *(0x708) = *(0x708)
  34:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  38:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x9e2) & 0x8)
  3c:	e9230004 	bnez	r3, 0x44	// if (r3 != 0x0) goto loc_44;
  40:	e0000000 	bsr	0x0	// <config_ft_att_val> // arg_bytes: 4; regs: r0=<ret config_ft_att_val@0x40>, r1=<clobbered>
loc_44:
  44:	d8440708 	ld.b	r2, (r4, 0x708)	// regs: r2=*(0x708)
  48:	e442203f 	andi	r2, r2, 63	// regs: r2=(*(0x708) & 0x3f)
  4c:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  4e:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  50:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x50>, r1=<clobbered>
  54:	07dd      	br	0xe	// goto loc_e;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_ft_att_hdl.str1.1>

Disassembly of section .text.atcmd_bgrssi_margin_hdl:

00000000 <atcmd_bgrssi_margin_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1089      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c05      	bf	0x26	// if (r3 == 0x3f) goto loc_26;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	dc040328 	st.b	r0, (r4, 0x328)	// *(0x328) = <ret atoi@0x1e>
loc_26:
  26:	d8444328 	ld.bs	r2, (r4, 0x328)	// regs: r2=*(0x328)
  2a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  2c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2e>, r1=<clobbered>
  32:	07ee      	br	0xe	// goto loc_e;
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_bgrssi_margin_hdl.str1.1>
  3e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_bgrssi_spur_hdl:

00000000 <atcmd_bgrssi_spur_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100f      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108d      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c08      	bf	0x2c	// if (r3 == 0x3f) goto loc_2c;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	74c3      	sexth	r3, r0	// regs: r3=sext16(<ret atoi@0x1e>)
  24:	e983000b 	blz	r3, 0x3a	// if (r3 < 0x0) goto loc_3a;
  28:	dc641196 	st.h	r3, (r4, 0x32c)	// *(0x32c) = sext16(<ret atoi@0x1e>)
loc_2c:
  2c:	d8445196 	ld.hs	r2, (r4, 0x32c)	// regs: r2=*(0x32c)
  30:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  32:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  34:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x34>, r1=<clobbered>
  38:	07eb      	br	0xe	// goto loc_e;
loc_3a:
  3a:	3300      	movi	r3, 0	// regs: r3=0x0
  3c:	5b01      	subu	r0, r3, r0	// regs: r0=(0x0 - <ret atoi@0x1e>)
  3e:	dc041196 	st.h	r0, (r4, 0x32c)	// *(0x32c) = (0x0 - <ret atoi@0x1e>)
  42:	07f5      	br	0x2c	// goto loc_2c;
  44:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <ah_lmac>
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_bgrssi_spur_hdl.str1.1>
  4e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_pcf_en_hdl:

00000000 <atcmd_pcf_en_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d8640360 	ld.b	r3, (r4, 0x360)	// regs: r3=*(0x360)
  26:	e9000015 	bez	r0, 0x50	// if (r0 == 0x0) goto loc_50;
  2a:	3201      	movi	r2, 1	// regs: r2=0x1
  2c:	c4625c00 	ins	r3, r2, 0, 0
loc_30:
  30:	dc640360 	st.b	r3, (r4, 0x360)	// *(0x360) = *(0x360)
loc_34:
  34:	d8640360 	ld.b	r3, (r4, 0x360)	// regs: r3=*(0x360)
  38:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x360) & 0x1)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1049      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
loc_50:
  50:	c4605c00 	ins	r3, r0, 0, 0
  54:	07ee      	br	0x30	// goto loc_30;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_pcf_en_hdl.str1.1>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_pcf_period_hdl:

00000000 <atcmd_pcf_period_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100e      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108c      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c07      	bf	0x2a	// if (r3 == 0x3f) goto loc_2a;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	e960000b 	blsz	r0, 0x38
  26:	dc040364 	st.b	r0, (r4, 0x364)	// *(0x364) = <ret atoi@0x1e>
loc_2a:
  2a:	d8440364 	ld.b	r2, (r4, 0x364)	// regs: r2=*(r4 + 0x364)
  2e:	5d26      	addi	r1, r5, 2	// regs: r1=(r5 + 0x2)
  30:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  32:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x32>, r1=<clobbered>
  36:	07ec      	br	0xe	// goto loc_e;
  38:	3300      	movi	r3, 0	// regs: r3=0x0
  3a:	dc640364 	st.b	r3, (r4, 0x364)	// *(r4 + 0x364) = 0x0
  3e:	07f6      	br	0x2a	// goto loc_2a;
  40:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <ah_lmac>
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <.rodata.atcmd_pcf_period_hdl.str1.1>
  4a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_pcf_percent_hdl:

00000000 <atcmd_pcf_percent_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100f      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108d      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c08      	bf	0x2c	// if (r3 == 0x3f) goto loc_2c;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	eb000064 	cmphsi	r0, 101
  26:	080a      	bt	0x3a	// if (r0 >= 0x65) goto loc_3a;
  28:	dc040365 	st.b	r0, (r4, 0x365)	// *(0x365) = <ret atoi@0x1e>
loc_2c:
  2c:	d8440365 	ld.b	r2, (r4, 0x365)	// regs: r2=*(0x365)
  30:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  32:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  34:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x34>, r1=<clobbered>
  38:	07eb      	br	0xe	// goto loc_e;
loc_3a:
  3a:	3300      	movi	r3, 0	// regs: r3=0x0
  3c:	dc640365 	st.b	r3, (r4, 0x365)	// *(0x365) = 0x0
  40:	07f6      	br	0x2c	// goto loc_2c;
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <ah_lmac>
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_pcf_percent_hdl.str1.1>
  4e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_obss_nav_diff_hdl:

00000000 <atcmd_obss_nav_diff_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	101b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1099      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c12      	bf	0x40	// if (r3 == 0x3f) goto loc_40;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d86420df 	ld.w	r3, (r4, 0x37c)	// regs: r3=*(0x37c)
  26:	e960001f 	blsz	r0, 0x64
  2a:	c4605cad 	ins	r3, r0, 18, 13
  2e:	dc6420df 	st.w	r3, (r4, 0x37c)	// *(0x37c) = *(0x37c)
  32:	d864037d 	ld.b	r3, (r4, 0x37d)	// regs: r3=*(0x37d)
  36:	3201      	movi	r2, 1	// regs: r2=0x1
loc_38:
  38:	c4625c04 	ins	r3, r2, 4, 4
  3c:	dc64037d 	st.b	r3, (r4, 0x37d)	// *(r4 + 0x37d) = r3
loc_40:
  40:	d864037d 	ld.b	r3, (r4, 0x37d)	// regs: r3=*(r4 + 0x37d)
  44:	e4632010 	andi	r3, r3, 16	// regs: r3=(*(r4 + 0x37d) & 0x10)
  48:	3b40      	cmpnei	r3, 0
  4a:	102d      	lrw	r1, 0x0	// regs: r1=0x0
  4c:	104d      	lrw	r2, 0x0	// regs: r2=0x0
  4e:	c4410c40 	inct	r2, r1, 0
  52:	d86420df 	ld.w	r3, (r4, 0x37c)	// regs: r3=*(r4 + 0x37c)
  56:	c5a35643 	zext	r3, r3, 18, 13	// regs: r3=zext(*(r4 + 0x37c))
  5a:	5d26      	addi	r1, r5, 2	// regs: r1=(r5 + 0x2)
  5c:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  5e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x5e>, r1=<clobbered>
  62:	07d6      	br	0xe	// goto loc_e;
  64:	3200      	movi	r2, 0	// regs: r2=0x0
  66:	c4625cad 	ins	r3, r2, 18, 13
  6a:	dc6420df 	st.w	r3, (r4, 0x37c)	// *(r4 + 0x37c) = <arg3>
  6e:	d864037d 	ld.b	r3, (r4, 0x37d)	// regs: r3=*(r4 + 0x37d)
  72:	07e3      	br	0x38	// goto loc_38;
  74:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000	// <ah_lmac>
  7c:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  80:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  84:	0000      	.short	0x0000	// <.rodata.atcmd_obss_nav_diff_hdl.str1.1>
  86:	0000      	.short	0x0000

Disassembly of section .text.atcmd_obss_cca_diff_hdl:

00000000 <atcmd_obss_cca_diff_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	101f      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	109d      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c16      	bf	0x48	// if (r3 == 0x3f) goto loc_48;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d86411bf 	ld.h	r3, (r4, 0x37e)	// regs: r3=*(0x37e)
  26:	e9600023 	blsz	r0, 0x6c
  2a:	c4605ca4 	ins	r3, r0, 9, 4
  2e:	3201      	movi	r2, 1	// regs: r2=0x1
  30:	dc6411bf 	st.h	r3, (r4, 0x37e)	// *(0x37e) = *(0x37e)
  34:	d804431e 	ld.bs	r0, (r4, 0x31e)	// regs: r0=*(0x31e)
  38:	c4625c03 	ins	r3, r2, 3, 3
  3c:	dc64037e 	st.b	r3, (r4, 0x37e)	// *(0x37e) = *(0x37e)
  40:	e0000000 	bsr	0x0	// <lmac_adjust_cca_threshold>; regs: r0=<ret lmac_adjust_cca_threshold@0x40>, r1=<clobbered>
  44:	e0000000 	bsr	0x0	// <ah_wphy_obss_sd_det_enable>; regs: r0=<ret ah_wphy_obss_sd_det_enable@0x44>, r1=<clobbered>
loc_48:
  48:	d864037e 	ld.b	r3, (r4, 0x37e)	// regs: r3=*(r4 + 0x37e)
  4c:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(r4 + 0x37e) & 0x8)
  50:	3b40      	cmpnei	r3, 0
  52:	102f      	lrw	r1, 0x0	// regs: r1=0x0
  54:	d86411bf 	ld.h	r3, (r4, 0x37e)	// regs: r3=*(r4 + 0x37e)
  58:	104e      	lrw	r2, 0x0	// regs: r2=0x0
  5a:	c4410c40 	inct	r2, r1, 0
  5e:	c4835523 	zext	r3, r3, 9, 4	// regs: r3=zext(*(r4 + 0x37e))
  62:	5d26      	addi	r1, r5, 2	// regs: r1=(r5 + 0x2)
  64:	100c      	lrw	r0, 0x0	// regs: r0=0x0
  66:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x66>, r1=<clobbered>
  6a:	07d2      	br	0xe	// goto loc_e;
  6c:	3200      	movi	r2, 0	// regs: r2=0x0
  6e:	c4625ca4 	ins	r3, r2, 9, 4
  72:	dc6411bf 	st.h	r3, (r4, 0x37e)	// *(r4 + 0x37e) = <arg3>
  76:	c4625c03 	ins	r3, r2, 3, 3
  7a:	dc64037e 	st.b	r3, (r4, 0x37e)	// *(r4 + 0x37e) = <arg3>
  7e:	e0000000 	bsr	0x0	// <ah_wphy_obss_sd_det_disable>; regs: r0=<ret ah_wphy_obss_sd_det_disable@0x7e>, r1=<clobbered>
  82:	07e3      	br	0x48	// goto loc_48;
  84:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  86:	0000      	.short	0x0000
  88:	00000000 	.long	0x00000000	// <ah_lmac>
  8c:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  90:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  92:	0000      	.short	0x0000
  94:	0000      	.short	0x0000	// <.rodata.atcmd_obss_cca_diff_hdl.str1.1>
  96:	0000      	.short	0x0000

Disassembly of section .text.atcmd_set_agc_hdl:

00000000 <atcmd_set_agc_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1019      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1097      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c10      	bf	0x3c	// if (r3 == 0x3f) goto loc_3c;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	586f      	subi	r3, r0, 4	// regs: r3=(<ret atoi@0x1e> - 0x4)
  24:	3b01      	cmphsi	r3, 2
  26:	d8640361 	ld.b	r3, (r4, 0x361)	// regs: r3=*(0x361)
  2a:	081b      	bt	0x60	// if (r3 >= 0x2) goto loc_60;
  2c:	3200      	movi	r2, 0	// regs: r2=0x0
  2e:	c4625c03 	ins	r3, r2, 3, 3
  32:	7400      	zextb	r0, r0	// regs: r0=zext8(<ret atoi@0x1e>)
  34:	dc640361 	st.b	r3, (r4, 0x361)	// *(0x361) = *(0x361)
  38:	e0000000 	bsr	0x0	// <lmac_rx_gain_cfg>; regs: r0=<ret lmac_rx_gain_cfg@0x38>, r1=<clobbered>
loc_3c:
  3c:	d8640361 	ld.b	r3, (r4, 0x361)	// regs: r3=*(0x361)
  40:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x361) & 0x8)
  44:	3b40      	cmpnei	r3, 0
  46:	102c      	lrw	r1, 0x0	// regs: r1=0x0
  48:	d86411b1 	ld.h	r3, (r4, 0x362)	// regs: r3=*(0x362)
  4c:	104b      	lrw	r2, 0x0	// regs: r2=0x0
  4e:	c4410c40 	inct	r2, r1, 0
  52:	c4835563 	zext	r3, r3, 11, 4	// regs: r3=zext(*(0x362))
  56:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  58:	1009      	lrw	r0, 0x0	// regs: r0=0x0
  5a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x5a>, r1=<clobbered>
  5e:	07d8      	br	0xe	// goto loc_e;
loc_60:
  60:	3201      	movi	r2, 1	// regs: r2=0x1
  62:	c4625c03 	ins	r3, r2, 3, 3
  66:	dc640361 	st.b	r3, (r4, 0x361)	// *(0x361) = *(0x361)
  6a:	07e9      	br	0x3c	// goto loc_3c;
  6c:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  6e:	0000      	.short	0x0000
  70:	00000000 	.long	0x00000000	// <ah_lmac>
  74:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  7c:	00000000 	.long	0x00000000	// <.rodata.atcmd_set_agc_hdl.str1.1>

Disassembly of section .text.atcmd_set_agc_threshold_hdl:

00000000 <atcmd_set_agc_threshold_hdl>: // arg_bytes: 12
   0:	14d4      	push	r4-r7, r15
   2:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   4:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   6:	e9220007 	bnez	r2, 0x14	// if (r2 != 0x0) goto loc_14;
   a:	1010      	lrw	r0, 0x0	// regs: r0=0x0
   c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xc>, r1=<clobbered>
loc_10:
  10:	3000      	movi	r0, 0	// regs: r0=0x0
  12:	1494      	pop	r4-r7, r15
loc_14:
  14:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  16:	108e      	lrw	r4, 0x0	// regs: r4=0x0
  18:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  1a:	eb43003f 	cmpnei	r3, 63
  1e:	0c0b      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  20:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x20>, r1=<clobbered>
  24:	6dc3      	mov	r7, r0	// regs: r7=<ret atoi@0x20>
  26:	9501      	ld.w	r0, (r5, 0x4)	// regs: r0=*(<arg1> + 0x4)
  28:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x28>, r1=<clobbered>
  2c:	dc040320 	st.b	r0, (r4, 0x320)	// *(0x320) = <ret atoi@0x28>
  30:	dce4031f 	st.b	r7, (r4, 0x31f)	// *(0x31f) = <ret atoi@0x20>
loc_34:
  34:	d8644320 	ld.bs	r3, (r4, 0x320)	// regs: r3=*(0x320)
  38:	d844431f 	ld.bs	r2, (r4, 0x31f)	// regs: r2=*(0x31f)
  3c:	5e26      	addi	r1, r6, 2	// regs: r1=(<arg0> + 0x2)
  3e:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  40:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x40>, r1=<clobbered>
  44:	07e6      	br	0x10	// goto loc_10;
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <ah_lmac>
  4e:	0000      	.short	0x0000
  50:	0000      	.short	0x0000	// <.rodata.atcmd_set_agc_threshold_hdl.str1.1>
  52:	0000      	.short	0x0000

Disassembly of section .text.atcmd_txop_en_hdl:

00000000 <atcmd_txop_en_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d864037f 	ld.b	r3, (r4, 0x37f)	// regs: r3=*(0x37f)
  26:	e9000015 	bez	r0, 0x50	// if (r0 == 0x0) goto loc_50;
  2a:	3201      	movi	r2, 1	// regs: r2=0x1
  2c:	c4625c03 	ins	r3, r2, 3, 3
loc_30:
  30:	dc64037f 	st.b	r3, (r4, 0x37f)	// *(0x37f) = *(0x37f)
loc_34:
  34:	d864037f 	ld.b	r3, (r4, 0x37f)	// regs: r3=*(0x37f)
  38:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x37f) & 0x8)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1049      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
loc_50:
  50:	c4605c03 	ins	r3, r0, 3, 3
  54:	07ee      	br	0x30	// goto loc_30;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_txop_en_hdl.str1.1>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_bw_dynamic_hdl:

00000000 <atcmd_tx_bw_dynamic_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d864037f 	ld.b	r3, (r4, 0x37f)	// regs: r3=*(0x37f)
  26:	e9000015 	bez	r0, 0x50	// if (r0 == 0x0) goto loc_50;
  2a:	3201      	movi	r2, 1	// regs: r2=0x1
  2c:	c4625c02 	ins	r3, r2, 2, 2
loc_30:
  30:	dc64037f 	st.b	r3, (r4, 0x37f)	// *(0x37f) = *(0x37f)
loc_34:
  34:	d864037f 	ld.b	r3, (r4, 0x37f)	// regs: r3=*(0x37f)
  38:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(0x37f) & 0x4)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1049      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
loc_50:
  50:	c4605c02 	ins	r3, r0, 2, 2
  54:	07ee      	br	0x30	// goto loc_30;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_tx_bw_dynamic_hdl.str1.1>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_cca_obsv_hdl:

00000000 <atcmd_cca_obsv_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1100      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	109e      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	080c      	bt	0x34	// if (r3 != 0x3f) goto loc_34;
loc_1e:
  1e:	d8440860 	ld.b	r2, (r4, 0x860)	// regs: r2=*(0x860)
  22:	e4622007 	andi	r3, r2, 7	// regs: r3=(*(0x860) & 0x7)
  26:	3201      	movi	r2, 1	// regs: r2=0x1
  28:	708c      	lsl	r2, r3
  2a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  2c:	1019      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2e>, r1=<clobbered>
  32:	07ee      	br	0xe	// goto loc_e;
loc_34:
  34:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x34>, r1=<clobbered>
  38:	e960fff3 	blsz	r0, 0x1e
  3c:	3841      	cmpnei	r0, 1
  3e:	d8640860 	ld.b	r3, (r4, 0x860)	// regs: r3=*(0x860)
  42:	0807      	bt	0x50	// if (r0 != 0x1) goto loc_50;
  44:	3200      	movi	r2, 0	// regs: r2=0x0
loc_46:
  46:	c4625c40 	ins	r3, r2, 2, 0
  4a:	dc640860 	st.b	r3, (r4, 0x860)	// *(0x860) = *(0x860)
  4e:	07e8      	br	0x1e	// goto loc_1e;
loc_50:
  50:	3823      	cmplti	r0, 4
  52:	0c03      	bf	0x58	// if (r0 >= 0x4) goto loc_58;
  54:	3201      	movi	r2, 1	// regs: r2=0x1
  56:	07f8      	br	0x46	// goto loc_46;
loc_58:
  58:	3827      	cmplti	r0, 8
  5a:	0c03      	bf	0x60	// if (r0 >= 0x8) goto loc_60;
  5c:	3202      	movi	r2, 2	// regs: r2=0x2
  5e:	07f4      	br	0x46	// goto loc_46;
loc_60:
  60:	382f      	cmplti	r0, 16
  62:	0c03      	bf	0x68	// if (r0 >= 0x10) goto loc_68;
  64:	3203      	movi	r2, 3	// regs: r2=0x3
  66:	07f0      	br	0x46	// goto loc_46;
loc_68:
  68:	383f      	cmplti	r0, 32
  6a:	0c03      	bf	0x70	// if (r0 >= 0x20) goto loc_70;
  6c:	3204      	movi	r2, 4	// regs: r2=0x4
  6e:	07ec      	br	0x46	// goto loc_46;
loc_70:
  70:	eb20003f 	cmplti	r0, 64
  74:	0c03      	bf	0x7a	// if (r0 >= 0x40) goto loc_7a;
  76:	3205      	movi	r2, 5	// regs: r2=0x5
  78:	07e7      	br	0x46	// goto loc_46;
loc_7a:
  7a:	eb20007f 	cmplti	r0, 128
  7e:	0c03      	bf	0x84	// if (r0 >= 0x80) goto loc_84;
  80:	3206      	movi	r2, 6	// regs: r2=0x6
  82:	07e2      	br	0x46	// goto loc_46;
loc_84:
  84:	3207      	movi	r2, 7	// regs: r2=0x7
  86:	07e0      	br	0x46	// goto loc_46;
  88:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  8c:	00000000 	.long	0x00000000	// <ah_lmac>
  90:	0000      	.short	0x0000	// <.rodata.atcmd_cca_obsv_hdl.str1.1>
  92:	0000      	.short	0x0000

Disassembly of section .text.atcmd_cts_dup_hdl:

00000000 <atcmd_cts_dup_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	1013      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	8340      	ld.b	r2, (r3, 0x0)	// regs: r2=*(*(<arg1>))
  14:	eb42003f 	cmpnei	r2, 63
  18:	106f      	lrw	r3, 0x0	// regs: r3=0x0
  1a:	0c0b      	bf	0x30	// if (r2 == 0x3f) goto loc_30;
  1c:	eb420030 	cmpnei	r2, 48
  20:	d8430338 	ld.b	r2, (r3, 0x338)	// regs: r2=*(0x338)
  24:	0814      	bt	0x4c	// if (r2 != 0x30) goto loc_4c;
  26:	3100      	movi	r1, 0	// regs: r1=0x0
loc_28:
  28:	c4415c02 	ins	r2, r1, 2, 2
  2c:	dc430338 	st.b	r2, (r3, 0x338)	// *(0x338) = *(0x338)
loc_30:
  30:	d8630338 	ld.b	r3, (r3, 0x338)	// regs: r3=*(0x338)
  34:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(0x338) & 0x4)
  38:	3b40      	cmpnei	r3, 0
  3a:	1048      	lrw	r2, 0x0	// regs: r2=0x0
  3c:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  3e:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  40:	c4430c20 	incf	r2, r3, 0
  44:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  46:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x46>, r1=<clobbered>
  4a:	07e1      	br	0xc	// goto loc_c;
loc_4c:
  4c:	3101      	movi	r1, 1	// regs: r1=0x1
  4e:	07ed      	br	0x28	// goto loc_28;
  50:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <ah_lmac>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1+0x7>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_cts_dup_hdl.str1.1>

Disassembly of section .text.atcmd_lmac_dbgsel_hdl:

00000000 <atcmd_lmac_dbgsel_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1089      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c05      	bf	0x26	// if (r3 == 0x3f) goto loc_26;
  1e:	e0000000 	bsr	0x0	// <os_atoh>; regs: r0=<ret os_atoh@0x1e>, r1=<clobbered>
  22:	dc0420ee 	st.w	r0, (r4, 0x3b8)	// *(0x3b8) = <ret os_atoh@0x1e>
loc_26:
  26:	d84420ee 	ld.w	r2, (r4, 0x3b8)	// regs: r2=*(0x3b8)
  2a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  2c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2e>, r1=<clobbered>
  32:	07ee      	br	0xe	// goto loc_e;
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_lmac_dbgsel_hdl.str1.1>
  3e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_rts_dup_hdl:

00000000 <atcmd_rts_dup_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	1013      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	8340      	ld.b	r2, (r3, 0x0)	// regs: r2=*(*(<arg1>))
  14:	eb42003f 	cmpnei	r2, 63
  18:	106f      	lrw	r3, 0x0	// regs: r3=0x0
  1a:	0c0b      	bf	0x30	// if (r2 == 0x3f) goto loc_30;
  1c:	eb420030 	cmpnei	r2, 48
  20:	d8430338 	ld.b	r2, (r3, 0x338)	// regs: r2=*(0x338)
  24:	0814      	bt	0x4c	// if (r2 != 0x30) goto loc_4c;
  26:	3100      	movi	r1, 0	// regs: r1=0x0
loc_28:
  28:	c4415c01 	ins	r2, r1, 1, 1
  2c:	dc430338 	st.b	r2, (r3, 0x338)	// *(0x338) = *(0x338)
loc_30:
  30:	d8630338 	ld.b	r3, (r3, 0x338)	// regs: r3=*(0x338)
  34:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x338) & 0x2)
  38:	3b40      	cmpnei	r3, 0
  3a:	1048      	lrw	r2, 0x0	// regs: r2=0x0
  3c:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  3e:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  40:	c4430c20 	incf	r2, r3, 0
  44:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  46:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x46>, r1=<clobbered>
  4a:	07e1      	br	0xc	// goto loc_c;
loc_4c:
  4c:	3101      	movi	r1, 1	// regs: r1=0x1
  4e:	07ed      	br	0x28	// goto loc_28;
  50:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <ah_lmac>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1+0x7>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_rts_dup_hdl.str1.1>

Disassembly of section .text.atcmd_sleep_en_hdl:

00000000 <atcmd_sleep_en_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	100c      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1490      	pop	r15
loc_10:
  10:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  12:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  14:	eb43003f 	cmpnei	r3, 63
  18:	0ffa      	bf	0xc	// if (r3 == 0x3f) goto loc_c;
  1a:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1a>, r1=<clobbered>
  1e:	3840      	cmpnei	r0, 0
  20:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  22:	c4000503 	mvc	r3	// regs: r3=<cond>
  26:	3200      	movi	r2, 0	// regs: r2=0x0
  28:	3101      	movi	r1, 1	// regs: r1=0x1
  2a:	9000      	ld.w	r0, (r0, 0x0)	// regs: r0=*(0x0)
  2c:	e0000000 	bsr	0x0	// <lmac_psm_enter>; regs: r0=<ret lmac_psm_enter@0x2c>, r1=<clobbered>
  30:	07ee      	br	0xc	// goto loc_c;
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_ap_sleep_mode:

00000000 <atcmd_ap_sleep_mode>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1012      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1090      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	3840      	cmpnei	r0, 0
  24:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
  28:	c4000502 	mvc	r2	// regs: r2=<cond>
  2c:	c4625c06 	ins	r3, r2, 6, 6
  30:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = *(0x319)
loc_34:
  34:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
  38:	e4632040 	andi	r3, r3, 64	// regs: r3=(*(0x319) & 0x40)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1047      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
  50:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <ah_lmac>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_ant_dual_hdl.str1.1+0x7>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_ap_sleep_mode.str1.1>

Disassembly of section .text.atcmd_wake_stas_hdl:

00000000 <atcmd_wake_stas_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100e      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108c      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c09      	bf	0x2e	// if (r3 == 0x3f) goto loc_2e;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
  26:	c4605c62 	ins	r3, r0, 5, 2
  2a:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = *(0x319)
loc_2e:
  2e:	d8440319 	ld.b	r2, (r4, 0x319)	// regs: r2=*(0x319)
  32:	c44254a2 	zext	r2, r2, 5, 2	// regs: r2=zext(*(0x319))
  36:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  38:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  3a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x3a>, r1=<clobbered>
  3e:	07e8      	br	0xe	// goto loc_e;
  40:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <ah_lmac>
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <.rodata.atcmd_wake_stas_hdl.str1.1>
  4a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_strictly_ordered_hdl:

00000000 <atcmd_strictly_ordered_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  26:	e9000015 	bez	r0, 0x50	// if (r0 == 0x0) goto loc_50;
  2a:	3201      	movi	r2, 1	// regs: r2=0x1
  2c:	c4625c03 	ins	r3, r2, 3, 3
loc_30:
  30:	dc640310 	st.b	r3, (r4, 0x310)	// *(0x310) = *(0x310)
loc_34:
  34:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  38:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x310) & 0x8)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1049      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
loc_50:
  50:	c4605c03 	ins	r3, r0, 3, 3
  54:	07ee      	br	0x30	// goto loc_30;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_strictly_ordered_hdl.str1.1>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_agg_auto_hdl:

00000000 <atcmd_agg_auto_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  26:	e9000015 	bez	r0, 0x50	// if (r0 == 0x0) goto loc_50;
  2a:	3201      	movi	r2, 1	// regs: r2=0x1
  2c:	c4625c04 	ins	r3, r2, 4, 4
loc_30:
  30:	dc640310 	st.b	r3, (r4, 0x310)	// *(0x310) = *(0x310)
loc_34:
  34:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  38:	e4632010 	andi	r3, r3, 16	// regs: r3=(*(0x310) & 0x10)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1049      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
loc_50:
  50:	c4605c04 	ins	r3, r0, 4, 4
  54:	07ee      	br	0x30	// goto loc_30;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_agg_auto_hdl.str1.1>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_rx_ordered_hdl:

00000000 <atcmd_rx_ordered_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  26:	e9000015 	bez	r0, 0x50	// if (r0 == 0x0) goto loc_50;
  2a:	3201      	movi	r2, 1	// regs: r2=0x1
  2c:	c4625c05 	ins	r3, r2, 5, 5
loc_30:
  30:	dc640310 	st.b	r3, (r4, 0x310)	// *(0x310) = *(0x310)
loc_34:
  34:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  38:	e4632020 	andi	r3, r3, 32	// regs: r3=(*(0x310) & 0x20)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1049      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
loc_50:
  50:	c4605c05 	ins	r3, r0, 5, 5
  54:	07ee      	br	0x30	// goto loc_30;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_rx_ordered_hdl.str1.1>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_qa_cfg_hdl:

00000000 <atcmd_qa_cfg_hdl>: // arg_bytes: 12
   0:	14d5      	push	r4-r8, r15
   2:	1423      	subi	r14, r14, 12	// regs: r14=(sp - 0xc)
   4:	6e03      	mov	r8, r0	// regs: r8=<arg0>
   6:	6d87      	mov	r6, r1	// regs: r6=<arg1>
   8:	6dcb      	mov	r7, r2	// regs: r7=<arg2>
   a:	e9220008 	bnez	r2, 0x1a	// if (r2 != 0x0) goto loc_1a;
   e:	111d      	lrw	r0, 0x0	// regs: r0=0x0
  10:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x10>, r1=<clobbered>
loc_14:
  14:	3000      	movi	r0, 0	// regs: r0=0x0
  16:	1403      	addi	r14, r14, 12	// regs: r14=(sp + 0xc)
  18:	1495      	pop	r4-r8, r15
loc_1a:
  1a:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  1c:	119a      	lrw	r4, 0x0	// regs: r4=0x0
  1e:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  20:	eb43003f 	cmpnei	r3, 63
  24:	0c47      	bf	0xb2	// if (r3 == 0x3f) goto loc_b2;
  26:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x26>, r1=<clobbered>
  2a:	6d43      	mov	r5, r0	// regs: r5=<ret atoi@0x26>
  2c:	e9600056 	blsz	r0, 0xd8
  30:	e0000000 	bsr	0x0	// <lmac_lo_freq_set>; regs: r0=<ret lmac_lo_freq_set@0x30>, r1=<clobbered>
  34:	e9000007 	bez	r0, 0x42	// if (r0 == 0x0) goto loc_42;
  38:	1174      	lrw	r3, 0x0	// regs: r3=0x0
  3a:	3200      	movi	r2, 0	// regs: r2=0x0
  3c:	2a01      	subi	r2, 2	// regs: r2=0xfffffffe
  3e:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xfffffffe
  40:	3500      	movi	r5, 0	// regs: r5=0x0
loc_42:
  42:	4d70      	lsri	r3, r5, 16	// regs: r3=(r5 >> 0x10)
  44:	3f01      	cmphsi	r7, 2
  46:	dc640896 	st.b	r3, (r4, 0x896)	// *(r4 + 0x896) = (r5 >> 0x10)
  4a:	dca40894 	st.b	r5, (r4, 0x894)	// *(r4 + 0x894) = r5
  4e:	4b68      	lsri	r3, r3, 8	// regs: r3=((r5 >> 0x10) >> 0x8)
  50:	c50555e5 	zext	r5, r5, 15, 8	// regs: r5=zext(r5)
  54:	dc640897 	st.b	r3, (r4, 0x897)	// *(r4 + 0x897) = ((r5 >> 0x10) >> 0x8)
  58:	dca40895 	st.b	r5, (r4, 0x895)	// *(r4 + 0x895) = zext(r5)
  5c:	0c2b      	bf	0xb2	// if (r7 < 0x2) goto loc_b2;
  5e:	9601      	ld.w	r0, (r6, 0x4)	// regs: r0=*(r6 + 0x4)
  60:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x60>, r1=<clobbered>
  64:	7482      	sextb	r2, r0	// regs: r2=sext8(<ret atoi@0x60>)
  66:	2800      	subi	r0, 1	// regs: r0=(<ret atoi@0x60> - 0x1)
  68:	7400      	zextb	r0, r0	// regs: r0=zext8((<ret atoi@0x60> - 0x1))
  6a:	3801      	cmphsi	r0, 2
  6c:	0c05      	bf	0x76	// if (r0 < 0x2) goto loc_76;
  6e:	3a44      	cmpnei	r2, 4
  70:	0c03      	bf	0x76	// if (r2 == 0x4) goto loc_76;
  72:	3a48      	cmpnei	r2, 8
  74:	0837      	bt	0xe2	// if (r2 != 0x8) goto loc_e2;
loc_76:
  76:	3300      	movi	r3, 0	// regs: r3=0x0
  78:	3102      	movi	r1, 2	// regs: r1=0x2
  7a:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(r4)
  7c:	dc440898 	st.b	r2, (r4, 0x898)	// *(r4 + 0x898) = sext8(<ret atoi@0x60>)
  80:	e0000000 	bsr	0x0	// <lmac_ioctl>; regs: r0=<ret lmac_ioctl@0x80>, r1=<clobbered>
loc_84:
  84:	3f42      	cmpnei	r7, 2
  86:	0c16      	bf	0xb2	// if (r7 == 0x2) goto loc_b2;
  88:	9602      	ld.w	r0, (r6, 0x8)	// regs: r0=*(r6 + 0x8)
  8a:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x8a>, r1=<clobbered>
  8e:	74c0      	zextb	r3, r0	// regs: r3=zext8(<ret atoi@0x8a>)
  90:	3b07      	cmphsi	r3, 8
  92:	082d      	bt	0xec	// if (r3 >= 0x8) goto loc_ec;
  94:	dc040899 	st.b	r0, (r4, 0x899)	// *(r4 + 0x899) = <ret atoi@0x8a>
  98:	dc640866 	st.b	r3, (r4, 0x866)	// *(r4 + 0x866) = zext8(<ret atoi@0x8a>)
loc_9c:
  9c:	3f43      	cmpnei	r7, 3
  9e:	0c0a      	bf	0xb2	// if (r7 == 0x3) goto loc_b2;
  a0:	9603      	ld.w	r0, (r6, 0xc)	// regs: r0=*(r6 + 0xc)
  a2:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0xa2>, r1=<clobbered>
  a6:	74c0      	zextb	r3, r0	// regs: r3=zext8(<ret atoi@0xa2>)
  a8:	eb030064 	cmphsi	r3, 101
  ac:	0825      	bt	0xf6	// if (r3 >= 0x65) goto loc_f6;
  ae:	dc04089a 	st.b	r0, (r4, 0x89a)	// *(r4 + 0x89a) = <ret atoi@0xa2>
loc_b2:
  b2:	d824489b 	ld.bs	r1, (r4, 0x89b)	// regs: r1=*(r4 + 0x89b)
  b6:	b822      	st.w	r1, (r14, 0x8)	// stack_p8 = *(r4 + 0x89b)
  b8:	d824489a 	ld.bs	r1, (r4, 0x89a)	// regs: r1=*(r4 + 0x89a)
  bc:	b821      	st.w	r1, (r14, 0x4)	// stack_p4 = *(r4 + 0x89a)
  be:	d8244899 	ld.bs	r1, (r4, 0x899)	// regs: r1=*(r4 + 0x899)
  c2:	b820      	st.w	r1, (r14, 0x0)	// stack_0 = *(r4 + 0x899)
  c4:	d8644898 	ld.bs	r3, (r4, 0x898)	// regs: r3=*(r4 + 0x898)
  c8:	d8442225 	ld.w	r2, (r4, 0x894)	// regs: r2=*(r4 + 0x894)
  cc:	e4280001 	addi	r1, r8, 2	// regs: r1=(r8 + 0x2)
  d0:	100f      	lrw	r0, 0x0	// regs: r0=0x0
  d2:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xd2>, r1=<clobbered>
  d6:	079f      	br	0x14	// goto loc_14;
  d8:	106c      	lrw	r3, 0x0	// regs: r3=0x0
  da:	3200      	movi	r2, 0	// regs: r2=0x0
  dc:	2a02      	subi	r2, 3	// regs: r2=0xfffffffd
  de:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xfffffffd
  e0:	07b1      	br	0x42	// goto loc_42;
loc_e2:
  e2:	106a      	lrw	r3, 0x0	// regs: r3=0x0
  e4:	3200      	movi	r2, 0	// regs: r2=0x0
  e6:	2a03      	subi	r2, 4	// regs: r2=0xfffffffc
  e8:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xfffffffc
  ea:	07cd      	br	0x84	// goto loc_84;
loc_ec:
  ec:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  ee:	3200      	movi	r2, 0	// regs: r2=0x0
  f0:	2a04      	subi	r2, 5	// regs: r2=0xfffffffb
  f2:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xfffffffb
  f4:	07d4      	br	0x9c	// goto loc_9c;
loc_f6:
  f6:	1065      	lrw	r3, 0x0	// regs: r3=0x0
  f8:	3200      	movi	r2, 0	// regs: r2=0x0
  fa:	2a05      	subi	r2, 6	// regs: r2=0xfffffffa
  fc:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xfffffffa
  fe:	07da      	br	0xb2	// goto loc_b2;
 100:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
 104:	00000000 	.long	0x00000000	// <ah_lmac>
 108:	00000000 	.long	0x00000000	// <lmactest>
 10c:	00000000 	.long	0x00000000	// <.rodata.atcmd_qa_cfg_hdl.str1.1>

Disassembly of section .text.atcmd_qa_rxthd_hdl:

00000000 <atcmd_qa_rxthd_hdl>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   6:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   8:	e9220008 	bnez	r2, 0x18	// if (r2 != 0x0) goto loc_18;
   c:	1103      	lrw	r0, 0x0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xe>, r1=<clobbered>
loc_12:
  12:	3000      	movi	r0, 0	// regs: r0=0x0
  14:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  16:	1493      	pop	r4-r6, r15
loc_18:
  18:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  1a:	1181      	lrw	r4, 0x0	// regs: r4=0x0
  1c:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  1e:	eb43003f 	cmpnei	r3, 63
  22:	0c2a      	bf	0x76	// if (r3 == 0x3f) goto loc_76;
  24:	3a48      	cmpnei	r2, 8
  26:	0834      	bt	0x8e	// if (r2 != 0x8) goto loc_8e;
  28:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x28>, r1=<clobbered>
  2c:	dc04089c 	st.b	r0, (r4, 0x89c)	// *(0x89c) = <ret atoi@0x28>
  30:	9501      	ld.w	r0, (r5, 0x4)	// regs: r0=*(<arg1> + 0x4)
  32:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x32>, r1=<clobbered>
  36:	dc04089d 	st.b	r0, (r4, 0x89d)	// *(0x89d) = <ret atoi@0x32>
  3a:	9502      	ld.w	r0, (r5, 0x8)	// regs: r0=*(<arg1> + 0x8)
  3c:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x3c>, r1=<clobbered>
  40:	dc04089e 	st.b	r0, (r4, 0x89e)	// *(0x89e) = <ret atoi@0x3c>
  44:	9503      	ld.w	r0, (r5, 0xc)	// regs: r0=*(<arg1> + 0xc)
  46:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x46>, r1=<clobbered>
  4a:	dc04089f 	st.b	r0, (r4, 0x89f)	// *(0x89f) = <ret atoi@0x46>
  4e:	9504      	ld.w	r0, (r5, 0x10)	// regs: r0=*(<arg1> + 0x10)
  50:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x50>, r1=<clobbered>
  54:	dc0408a0 	st.b	r0, (r4, 0x8a0)	// *(0x8a0) = <ret atoi@0x50>
  58:	9505      	ld.w	r0, (r5, 0x14)	// regs: r0=*(<arg1> + 0x14)
  5a:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x5a>, r1=<clobbered>
  5e:	dc0408a1 	st.b	r0, (r4, 0x8a1)	// *(0x8a1) = <ret atoi@0x5a>
  62:	9506      	ld.w	r0, (r5, 0x18)	// regs: r0=*(<arg1> + 0x18)
  64:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x64>, r1=<clobbered>
  68:	dc0408a2 	st.b	r0, (r4, 0x8a2)	// *(0x8a2) = <ret atoi@0x64>
  6c:	9507      	ld.w	r0, (r5, 0x1c)	// regs: r0=*(<arg1> + 0x1c)
  6e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x6e>, r1=<clobbered>
  72:	dc0408a3 	st.b	r0, (r4, 0x8a3)	// *(0x8a3) = <ret atoi@0x6e>
loc_76:
  76:	d824489e 	ld.bs	r1, (r4, 0x89e)	// regs: r1=*(0x89e)
  7a:	b820      	st.w	r1, (r14, 0x0)	// local_4 = *(0x89e)
  7c:	d864489d 	ld.bs	r3, (r4, 0x89d)	// regs: r3=*(0x89d)
  80:	d844489c 	ld.bs	r2, (r4, 0x89c)	// regs: r2=*(0x89c)
  84:	5e26      	addi	r1, r6, 2	// regs: r1=(<arg0> + 0x2)
  86:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  88:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x88>, r1=<clobbered>
  8c:	07c3      	br	0x12	// goto loc_12;
loc_8e:
  8e:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  90:	3200      	movi	r2, 0	// regs: r2=0x0
  92:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  94:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  96:	07f0      	br	0x76	// goto loc_76;
  98:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  9c:	0000      	.short	0x0000	// <ah_lmac>
  9e:	0000      	.short	0x0000
  a0:	0000      	.short	0x0000	// <.rodata.atcmd_qa_rxthd_hdl.str1.1>
  a2:	0000      	.short	0x0000
  a4:	0000      	.short	0x0000	// <lmactest>
  a6:	0000      	.short	0x0000

Disassembly of section .text.atcmd_qa_txthd_hdl:

00000000 <atcmd_qa_txthd_hdl>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   6:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   8:	e9220008 	bnez	r2, 0x18	// if (r2 != 0x0) goto loc_18;
   c:	1103      	lrw	r0, 0x0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xe>, r1=<clobbered>
loc_12:
  12:	3000      	movi	r0, 0	// regs: r0=0x0
  14:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  16:	1493      	pop	r4-r6, r15
loc_18:
  18:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  1a:	1181      	lrw	r4, 0x0	// regs: r4=0x0
  1c:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  1e:	eb43003f 	cmpnei	r3, 63
  22:	0c2a      	bf	0x76	// if (r3 == 0x3f) goto loc_76;
  24:	3a48      	cmpnei	r2, 8
  26:	0834      	bt	0x8e	// if (r2 != 0x8) goto loc_8e;
  28:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x28>, r1=<clobbered>
  2c:	dc0408a4 	st.b	r0, (r4, 0x8a4)	// *(0x8a4) = <ret atoi@0x28>
  30:	9501      	ld.w	r0, (r5, 0x4)	// regs: r0=*(<arg1> + 0x4)
  32:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x32>, r1=<clobbered>
  36:	dc0408a5 	st.b	r0, (r4, 0x8a5)	// *(0x8a5) = <ret atoi@0x32>
  3a:	9502      	ld.w	r0, (r5, 0x8)	// regs: r0=*(<arg1> + 0x8)
  3c:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x3c>, r1=<clobbered>
  40:	dc0408a6 	st.b	r0, (r4, 0x8a6)	// *(0x8a6) = <ret atoi@0x3c>
  44:	9503      	ld.w	r0, (r5, 0xc)	// regs: r0=*(<arg1> + 0xc)
  46:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x46>, r1=<clobbered>
  4a:	dc0408a7 	st.b	r0, (r4, 0x8a7)	// *(0x8a7) = <ret atoi@0x46>
  4e:	9504      	ld.w	r0, (r5, 0x10)	// regs: r0=*(<arg1> + 0x10)
  50:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x50>, r1=<clobbered>
  54:	dc0408a8 	st.b	r0, (r4, 0x8a8)	// *(0x8a8) = <ret atoi@0x50>
  58:	9505      	ld.w	r0, (r5, 0x14)	// regs: r0=*(<arg1> + 0x14)
  5a:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x5a>, r1=<clobbered>
  5e:	dc0408a9 	st.b	r0, (r4, 0x8a9)	// *(0x8a9) = <ret atoi@0x5a>
  62:	9506      	ld.w	r0, (r5, 0x18)	// regs: r0=*(<arg1> + 0x18)
  64:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x64>, r1=<clobbered>
  68:	dc0408aa 	st.b	r0, (r4, 0x8aa)	// *(0x8aa) = <ret atoi@0x64>
  6c:	9507      	ld.w	r0, (r5, 0x1c)	// regs: r0=*(<arg1> + 0x1c)
  6e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x6e>, r1=<clobbered>
  72:	dc0408ab 	st.b	r0, (r4, 0x8ab)	// *(0x8ab) = <ret atoi@0x6e>
loc_76:
  76:	d82448a6 	ld.bs	r1, (r4, 0x8a6)	// regs: r1=*(0x8a6)
  7a:	b820      	st.w	r1, (r14, 0x0)	// local_4 = *(0x8a6)
  7c:	d86448a5 	ld.bs	r3, (r4, 0x8a5)	// regs: r3=*(0x8a5)
  80:	d84448a4 	ld.bs	r2, (r4, 0x8a4)	// regs: r2=*(0x8a4)
  84:	5e26      	addi	r1, r6, 2	// regs: r1=(<arg0> + 0x2)
  86:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  88:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x88>, r1=<clobbered>
  8c:	07c3      	br	0x12	// goto loc_12;
loc_8e:
  8e:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  90:	3200      	movi	r2, 0	// regs: r2=0x0
  92:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  94:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  96:	07f0      	br	0x76	// goto loc_76;
  98:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  9c:	0000      	.short	0x0000	// <ah_lmac>
  9e:	0000      	.short	0x0000
  a0:	0000      	.short	0x0000	// <.rodata.atcmd_qa_txthd_hdl.str1.1>
  a2:	0000      	.short	0x0000
  a4:	0000      	.short	0x0000	// <lmactest>
  a6:	0000      	.short	0x0000

Disassembly of section .text.atcmd_qa_start_hdl:

00000000 <atcmd_qa_start_hdl>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1217      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1493      	pop	r4-r6, r15
loc_12:
  12:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  14:	1295      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c4a      	bf	0xb0	// if (r3 == 0x3f) goto loc_b0;
  1e:	eb430031 	cmpnei	r3, 49
  22:	0855      	bt	0xcc	// if (r3 != 0x31) goto loc_cc;
  24:	3301      	movi	r3, 1	// regs: r3=0x1
  26:	dc640866 	st.b	r3, (r4, 0x866)	// *(0x866) = 0x1
  2a:	32ff      	movi	r2, 255	// regs: r2=0xff
  2c:	1270      	lrw	r3, 0x0	// regs: r3=0x0
  2e:	4242      	lsli	r2, r2, 2	// regs: r2=0x3fc
  30:	ab52      	st.h	r2, (r3, 0x24)	// *(0x24) = 0x3fc
  32:	3200      	movi	r2, 0	// regs: r2=0x0
  34:	ab53      	st.h	r2, (r3, 0x26)	// *(0x26) = 0x0
  36:	ab5d      	st.h	r2, (r3, 0x3a)	// *(0x3a) = 0x0
  38:	3280      	movi	r2, 128	// regs: r2=0x80
  3a:	4241      	lsli	r2, r2, 1	// regs: r2=0x100
  3c:	3501      	movi	r5, 1	// regs: r5=0x1
  3e:	dc431020 	st.h	r2, (r3, 0x40)	// *(0x40) = 0x100
  42:	d8640892 	ld.b	r3, (r4, 0x892)	// regs: r3=*(0x892)
  46:	c4655c01 	ins	r3, r5, 1, 1
  4a:	3206      	movi	r2, 6	// regs: r2=0x6
  4c:	3100      	movi	r1, 0	// regs: r1=0x0
  4e:	e40408c1 	addi	r0, r4, 2242	// regs: r0=0x8c2
  52:	dc640892 	st.b	r3, (r4, 0x892)	// *(0x892) = *(0x892)
  56:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x56>, r1=<clobbered>
  5a:	327f      	movi	r2, 127	// regs: r2=0x7f
  5c:	313f      	movi	r1, 63	// regs: r1=0x3f
  5e:	3000      	movi	r0, 0	// regs: r0=0x0
  60:	e0000000 	bsr	0x0	// <lmac_cfg_cw_param>; regs: r0=<ret lmac_cfg_cw_param@0x60>, r1=<clobbered>
  64:	327f      	movi	r2, 127	// regs: r2=0x7f
  66:	313f      	movi	r1, 63	// regs: r1=0x3f
  68:	6c17      	mov	r0, r5	// regs: r0=0x1
  6a:	e0000000 	bsr	0x0	// <lmac_cfg_cw_param>; regs: r0=<ret lmac_cfg_cw_param@0x6a>, r1=<clobbered>
  6e:	327f      	movi	r2, 127	// regs: r2=0x7f
  70:	313f      	movi	r1, 63	// regs: r1=0x3f
  72:	3002      	movi	r0, 2	// regs: r0=0x2
  74:	e0000000 	bsr	0x0	// <lmac_cfg_cw_param>; regs: r0=<ret lmac_cfg_cw_param@0x74>, r1=<clobbered>
  78:	327f      	movi	r2, 127	// regs: r2=0x7f
  7a:	313f      	movi	r1, 63	// regs: r1=0x3f
  7c:	3003      	movi	r0, 3	// regs: r0=0x3
  7e:	e0000000 	bsr	0x0	// <lmac_cfg_cw_param>; regs: r0=<ret lmac_cfg_cw_param@0x7e>, r1=<clobbered>
  82:	6c17      	mov	r0, r5	// regs: r0=0x1
  84:	e0000000 	bsr	0x0	// <lmac_test_enable> // arg_bytes: 4; regs: r0=<ret lmac_test_enable@0x84>, r1=<clobbered>
  88:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
  8a:	3100      	movi	r1, 0	// regs: r1=0x0
  8c:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*((*(0x0) + 0xa))
  8e:	c4415c00 	ins	r2, r1, 0, 0
  92:	a34a      	st.b	r2, (r3, 0xa)	// *((*(0x0) + 0xa)) = *((*(0x0) + 0xa))
  94:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  98:	d8440892 	ld.b	r2, (r4, 0x892)	// regs: r2=*(0x892)
  9c:	e46320df 	andi	r3, r3, 223	// regs: r3=(*(0x9e2) & 0xdf)
  a0:	c4455c00 	ins	r2, r5, 0, 0
  a4:	c4655c03 	ins	r3, r5, 3, 3
  a8:	dc440892 	st.b	r2, (r4, 0x892)	// *(0x892) = *(0x892)
  ac:	dc6409e2 	st.b	r3, (r4, 0x9e2)	// *(0x9e2) = (*(0x9e2) & 0xdf)
loc_b0:
  b0:	d8640892 	ld.b	r3, (r4, 0x892)	// regs: r3=*(0x892)
  b4:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x892) & 0x1)
  b8:	3b40      	cmpnei	r3, 0
  ba:	114e      	lrw	r2, 0x0	// regs: r2=0x0
  bc:	116e      	lrw	r3, 0x0	// regs: r3=0x0
  be:	c4430c20 	incf	r2, r3, 0
  c2:	5e26      	addi	r1, r6, 2	// regs: r1=(<arg0> + 0x2)
  c4:	110d      	lrw	r0, 0x0	// regs: r0=0x0
  c6:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xc6>, r1=<clobbered>
  ca:	07a2      	br	0xe	// goto loc_e;
loc_cc:
  cc:	eb430030 	cmpnei	r3, 48
  d0:	0bf0      	bt	0xb0	// if (r3 != 0x30) goto loc_b0;
  d2:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  d6:	3000      	movi	r0, 0	// regs: r0=0x0
  d8:	e46320f7 	andi	r3, r3, 247	// regs: r3=(*(0x9e2) & 0xf7)
  dc:	c4605c05 	ins	r3, r0, 5, 5
  e0:	d84408bf 	ld.b	r2, (r4, 0x8bf)	// regs: r2=*(0x8bf)
  e4:	dc6409e2 	st.b	r3, (r4, 0x9e2)	// *(0x9e2) = (*(0x9e2) & 0xf7)
  e8:	c4405c00 	ins	r2, r0, 0, 0
  ec:	d8640892 	ld.b	r3, (r4, 0x892)	// regs: r3=*(0x892)
  f0:	dc4408bf 	st.b	r2, (r4, 0x8bf)	// *(0x8bf) = *(0x8bf)
  f4:	e46320fe 	andi	r3, r3, 254	// regs: r3=(*(0x892) & 0xfe)
  f8:	6c83      	mov	r2, r0	// regs: r2=0x0
  fa:	c4605c01 	ins	r3, r0, 1, 1
  fe:	2a7f      	subi	r2, 128	// regs: r2=0xffffff80
 100:	dc4408ac 	st.b	r2, (r4, 0x8ac)	// *(0x8ac) = 0xffffff80
 104:	dc4408b6 	st.b	r2, (r4, 0x8b6)	// *(0x8b6) = 0xffffff80
 108:	dc640892 	st.b	r3, (r4, 0x892)	// *(0x892) = (*(0x892) & 0xfe)
 10c:	32c2      	movi	r2, 194	// regs: r2=0xc2
 10e:	1078      	lrw	r3, 0x0	// regs: r3=0x0
 110:	4242      	lsli	r2, r2, 2	// regs: r2=0x308
 112:	ab52      	st.h	r2, (r3, 0x24)	// *(0x24) = 0x308
 114:	3200      	movi	r2, 0	// regs: r2=0x0
 116:	317f      	movi	r1, 127	// regs: r1=0x7f
 118:	b30a      	st.w	r0, (r3, 0x28)	// *(0x28) = 0x0
 11a:	ab56      	st.h	r2, (r3, 0x2c)	// *(0x2c) = 0x0
 11c:	3300      	movi	r3, 0	// regs: r3=0x0
 11e:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 120:	dc2408ae 	st.b	r1, (r4, 0x8ae)	// *(0x8ae) = 0x7f
 124:	dc2408b8 	st.b	r1, (r4, 0x8b8)	// *(0x8b8) = 0x7f
 128:	8c5c      	ld.h	r2, (r4, 0x38)	// regs: r2=*(0x38)
 12a:	8c34      	ld.h	r1, (r4, 0x28)	// regs: r1=*(0x28)
 12c:	dc640866 	st.b	r3, (r4, 0x866)	// *(0x866) = 0xffffffff
 130:	dc0408ad 	st.b	r0, (r4, 0x8ad)	// *(0x8ad) = 0x0
 134:	dc0408b7 	st.b	r0, (r4, 0x8b7)	// *(0x8b7) = 0x0
 138:	dc0408c0 	st.b	r0, (r4, 0x8c0)	// *(0x8c0) = 0x0
 13c:	dc0408c1 	st.b	r0, (r4, 0x8c1)	// *(0x8c1) = 0x0
 140:	e0000000 	bsr	0x0	// <lmac_cfg_cw_param>; regs: r0=<ret lmac_cfg_cw_param@0x140>, r1=<clobbered>
 144:	8c5d      	ld.h	r2, (r4, 0x3a)	// regs: r2=*(0x3a)
 146:	8c35      	ld.h	r1, (r4, 0x2a)	// regs: r1=*(0x2a)
 148:	3001      	movi	r0, 1	// regs: r0=0x1
 14a:	e0000000 	bsr	0x0	// <lmac_cfg_cw_param>; regs: r0=<ret lmac_cfg_cw_param@0x14a>, r1=<clobbered>
 14e:	8c5e      	ld.h	r2, (r4, 0x3c)	// regs: r2=*(0x3c)
 150:	8c36      	ld.h	r1, (r4, 0x2c)	// regs: r1=*(0x2c)
 152:	3002      	movi	r0, 2	// regs: r0=0x2
 154:	e0000000 	bsr	0x0	// <lmac_cfg_cw_param>; regs: r0=<ret lmac_cfg_cw_param@0x154>, r1=<clobbered>
 158:	8c5f      	ld.h	r2, (r4, 0x3e)	// regs: r2=*(0x3e)
 15a:	8c37      	ld.h	r1, (r4, 0x2e)	// regs: r1=*(0x2e)
 15c:	3003      	movi	r0, 3	// regs: r0=0x3
 15e:	e0000000 	bsr	0x0	// <lmac_cfg_cw_param>; regs: r0=<ret lmac_cfg_cw_param@0x15e>, r1=<clobbered>
 162:	07a7      	br	0xb0	// goto loc_b0;
 164:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
 168:	00000000 	.long	0x00000000	// <ah_lmac>
 16c:	00000000 	.long	0x00000000	// <lmactest>
 170:	00000000 	.long	0x00000000	// <.rodata.atcmd_test_start_hdl.str1.1>
 174:	00000000 	.long	0x00000000	// <.rodata.atcmd_test_start_hdl.str1.1+0x8>
 178:	00000000 	.long	0x00000000	// <.rodata.atcmd_qa_start_hdl.str1.1>

Disassembly of section .text.atcmd_qa_results_hdl:

00000000 <atcmd_qa_results_hdl>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	e9220007 	bnez	r2, 0x10	// if (r2 != 0x0) goto loc_10;
   6:	101d      	lrw	r0, 0x0	// regs: r0=0x0
   8:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x8>, r1=<clobbered>
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	1491      	pop	r4, r15
loc_10:
  10:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  12:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  14:	eb43003f 	cmpnei	r3, 63
  18:	082a      	bt	0x6c	// if (r3 != 0x3f) goto loc_6c;
  1a:	c0006024 	mfcr	r4, cr<0, 0>
  1e:	c0807020 	psrclr	ie
  22:	1077      	lrw	r3, 0x0	// regs: r3=0x0
  24:	3200      	movi	r2, 0	// regs: r2=0x0
  26:	2a58      	subi	r2, 89	// regs: r2=0xffffffa7
  28:	d82348b0 	ld.bs	r1, (r3, 0x8b0)	// regs: r1=*(0x8b0)
  2c:	6485      	cmplt	r1, r2
  2e:	e4842040 	andi	r4, r4, 64	// regs: r4=(r4 & 0x40)
  32:	d84308c0 	ld.b	r2, (r3, 0x8c0)	// regs: r2=*(0x8c0)
  36:	0c16      	bf	0x62	// if (!T) goto loc_62;
  38:	ec420010 	ori	r2, r2, 16	// regs: r2=(*(0x8c0) | 0x10)
loc_3c:
  3c:	d8231459 	ld.h	r1, (r3, 0x8b2)	// regs: r1=*(0x8b2)
  40:	dc4308c0 	st.b	r2, (r3, 0x8c0)	// *(0x8c0) = r2
  44:	d84308c0 	ld.b	r2, (r3, 0x8c0)	// regs: r2=*(0x8c0)
  48:	e901000f 	bez	r1, 0x66	// if (r1 == 0x0) goto loc_66;
  4c:	ec420060 	ori	r2, r2, 96	// regs: r2=(*(0x8c0) | 0x60)
loc_50:
  50:	dc4308c0 	st.b	r2, (r3, 0x8c0)	// *(0x8c0) = r2
  54:	e0000000 	bsr	0x0	// <lmac_qa_results_valid_check>; regs: r0=<ret lmac_qa_results_valid_check@0x54>, r1=<clobbered>
  58:	e904ffda 	bez	r4, 0xc	// if (r4 == 0x0) goto loc_c;
  5c:	c0807420 	psrset	ie
  60:	07d6      	br	0xc	// goto loc_c;
loc_62:
  62:	3a84      	bclri	r2, 4	// regs: r2=(*(0x8c0) & ~(0x1 << 0x4))
  64:	07ec      	br	0x3c	// goto loc_3c;
loc_66:
  66:	3a85      	bclri	r2, 5	// regs: r2=(*(0x8c0) & ~(0x1 << 0x5))
  68:	3a86      	bclri	r2, 6	// regs: r2=((*(0x8c0) & ~(0x1 << 0x5)) & ~(0x1 << 0x6))
  6a:	07f3      	br	0x50	// goto loc_50;
loc_6c:
  6c:	1065      	lrw	r3, 0x0	// regs: r3=0x0
  6e:	3200      	movi	r2, 0	// regs: r2=0x0
  70:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  72:	b352      	st.w	r2, (r3, 0x48)	// *(0x48) = 0xffffffff
  74:	07cc      	br	0xc	// goto loc_c;
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  7c:	00000000 	.long	0x00000000	// <ah_lmac>
  80:	00000000 	.long	0x00000000	// <lmactest>

Disassembly of section .text.atcmd_short_gi_hdl:

00000000 <atcmd_short_gi_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  26:	e9000015 	bez	r0, 0x50	// if (r0 == 0x0) goto loc_50;
  2a:	3201      	movi	r2, 1	// regs: r2=0x1
  2c:	c4625c00 	ins	r3, r2, 0, 0
loc_30:
  30:	dc640310 	st.b	r3, (r4, 0x310)	// *(0x310) = *(0x310)
loc_34:
  34:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  38:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x310) & 0x1)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1049      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
loc_50:
  50:	c4605c00 	ins	r3, r0, 0, 0
  54:	07ee      	br	0x30	// goto loc_30;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_short_gi_hdl.str1.1>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_obss_switch_hdl:

00000000 <atcmd_obss_switch_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  26:	e9000015 	bez	r0, 0x50	// if (r0 == 0x0) goto loc_50;
  2a:	3201      	movi	r2, 1	// regs: r2=0x1
  2c:	c4625c01 	ins	r3, r2, 1, 1
loc_30:
  30:	dc640310 	st.b	r3, (r4, 0x310)	// *(0x310) = *(0x310)
loc_34:
  34:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  38:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x310) & 0x2)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1049      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
loc_50:
  50:	c4605c01 	ins	r3, r0, 1, 1
  54:	07ee      	br	0x30	// goto loc_30;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_obss_switch_hdl.str1.1>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_obss_edca_hdl:

00000000 <atcmd_obss_edca_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1014      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1092      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0c      	bf	0x34	// if (r3 == 0x3f) goto loc_34;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  26:	e9000015 	bez	r0, 0x50	// if (r0 == 0x0) goto loc_50;
  2a:	3201      	movi	r2, 1	// regs: r2=0x1
  2c:	c4625c02 	ins	r3, r2, 2, 2
loc_30:
  30:	dc640310 	st.b	r3, (r4, 0x310)	// *(0x310) = *(0x310)
loc_34:
  34:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
  38:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(0x310) & 0x4)
  3c:	3b40      	cmpnei	r3, 0
  3e:	1049      	lrw	r2, 0x0	// regs: r2=0x0
  40:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  42:	c4430c20 	incf	r2, r3, 0
  46:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  48:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  4a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x4a>, r1=<clobbered>
  4e:	07e0      	br	0xe	// goto loc_e;
loc_50:
  50:	c4605c02 	ins	r3, r0, 2, 2
  54:	07ee      	br	0x30	// goto loc_30;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_obss_edca_hdl.str1.1>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_obss_th_hdl:

00000000 <atcmd_obss_th_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1089      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c05      	bf	0x26	// if (r3 == 0x3f) goto loc_26;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	dc040300 	st.b	r0, (r4, 0x300)	// *(0x300) = <ret atoi@0x1e>
loc_26:
  26:	d8444300 	ld.bs	r2, (r4, 0x300)	// regs: r2=*(0x300)
  2a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  2c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2e>, r1=<clobbered>
  32:	07ee      	br	0xe	// goto loc_e;
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_obss_th_hdl.str1.1>
  3e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_tx_delay_hdl:

00000000 <atcmd_tx_delay_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100f      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108d      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0b      	bf	0x32	// if (r3 == 0x3f) goto loc_32;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	e9800008 	blz	r0, 0x32	// if (r0 < 0x0) goto loc_32;
  26:	d86414f1 	ld.h	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  2a:	c4605ce6 	ins	r3, r0, 13, 6
  2e:	dc6414f1 	st.h	r3, (r4, 0x9e2)	// *(0x9e2) = *(0x9e2)
loc_32:
  32:	d84414f1 	ld.h	r2, (r4, 0x9e2)	// regs: r2=*(0x9e2)
  36:	c4c255a2 	zext	r2, r2, 13, 6	// regs: r2=zext(*(0x9e2))
  3a:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  3c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  3e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x3e>, r1=<clobbered>
  42:	07e6      	br	0xe	// goto loc_e;
  44:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <ah_lmac>
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_tx_delay_hdl.str1.1>
  4e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_rc_new_hdl:

00000000 <atcmd_rc_new_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1016      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	1094      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c0e      	bf	0x38	// if (r3 == 0x3f) goto loc_38;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	dc040311 	st.b	r0, (r4, 0x311)	// *(0x311) = <ret atoi@0x1e>
  26:	d8640338 	ld.b	r3, (r4, 0x338)	// regs: r3=*(0x338)
  2a:	e9000017 	bez	r0, 0x58	// if (r0 == 0x0) goto loc_58;
  2e:	3201      	movi	r2, 1	// regs: r2=0x1
  30:	c4625c03 	ins	r3, r2, 3, 3
loc_34:
  34:	dc640338 	st.b	r3, (r4, 0x338)	// *(0x338) = *(0x338)
loc_38:
  38:	d8640338 	ld.b	r3, (r4, 0x338)	// regs: r3=*(0x338)
  3c:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x338) & 0x8)
  40:	3b40      	cmpnei	r3, 0
  42:	102a      	lrw	r1, 0x0	// regs: r1=0x0
  44:	104a      	lrw	r2, 0x0	// regs: r2=0x0
  46:	c4410c40 	inct	r2, r1, 0
  4a:	d8640311 	ld.b	r3, (r4, 0x311)	// regs: r3=*(0x311)
  4e:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  50:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  52:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x52>, r1=<clobbered>
  56:	07dc      	br	0xe	// goto loc_e;
loc_58:
  58:	c4605c03 	ins	r3, r0, 3, 3
  5c:	07ec      	br	0x34	// goto loc_34;
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  64:	0000      	.short	0x0000	// <ah_lmac>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1>
  6a:	0000      	.short	0x0000
  6c:	0000      	.short	0x0000	// <.rodata.atcmd_tx_cont_hdl.str1.1+0x8>
  6e:	0000      	.short	0x0000
  70:	00000000 	.long	0x00000000	// <.rodata.atcmd_rc_new_hdl.str1.1>

Disassembly of section .text.atcmd_rf_reset_hdl:

00000000 <atcmd_rf_reset_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	e9220008 	bnez	r2, 0x14	// if (r2 != 0x0) goto loc_14;
   8:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  12:	1490      	pop	r15
loc_14:
  14:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  16:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  18:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  1a:	eb430031 	cmpnei	r3, 49
  1e:	0809      	bt	0x30	// if (r3 != 0x31) goto loc_30;
  20:	b820      	st.w	r1, (r14, 0x0)	// local_4 = (<arg0> + 0x2)
  22:	e0000000 	bsr	0x0	// <lmac_rf_reset>; regs: r0=<ret lmac_rf_reset@0x22>, r1=<clobbered>
  26:	9820      	ld.w	r1, (r14, 0x0)	// regs: r1=local_4
  28:	1004      	lrw	r0, 0x0	// regs: r0=0x0
loc_2a:
  2a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2a>, r1=<clobbered>
  2e:	07f0      	br	0xe	// goto loc_e;
loc_30:
  30:	1003      	lrw	r0, 0x0	// regs: r0=0x0
  32:	07fc      	br	0x2a	// goto loc_2a;
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  38:	0000      	.short	0x0000	// <.rodata.atcmd_rf_reset_hdl.str1.1>
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_rf_reset_hdl.str1.1+0x14>
  3e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_phy_reset_hdl:

00000000 <atcmd_phy_reset_hdl>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	e9220008 	bnez	r2, 0x14	// if (r2 != 0x0) goto loc_14;
   8:	100f      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  12:	1490      	pop	r15
loc_14:
  14:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  16:	5826      	addi	r1, r0, 2	// regs: r1=(<arg0> + 0x2)
  18:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  1a:	eb430031 	cmpnei	r3, 49
  1e:	0810      	bt	0x3e	// if (r3 != 0x31) goto loc_3e;
  20:	b820      	st.w	r1, (r14, 0x0)	// local_4 = (<arg0> + 0x2)
  22:	e0000000 	bsr	0x0	// <ah_wphy_soft_reset>; regs: r0=<ret ah_wphy_soft_reset@0x22>, r1=<clobbered>
  26:	6c03      	mov	r0, r0	// regs: r0=<ret ah_wphy_soft_reset@0x22>
  28:	6c03      	mov	r0, r0	// regs: r0=<ret ah_wphy_soft_reset@0x22>
  2a:	6c03      	mov	r0, r0	// regs: r0=<ret ah_wphy_soft_reset@0x22>
  2c:	6c03      	mov	r0, r0	// regs: r0=<ret ah_wphy_soft_reset@0x22>
  2e:	6c03      	mov	r0, r0	// regs: r0=<ret ah_wphy_soft_reset@0x22>
  30:	e0000000 	bsr	0x0	// <ah_wphy_soft_dereset>; regs: r0=<ret ah_wphy_soft_dereset@0x30>, r1=<clobbered>
  34:	9820      	ld.w	r1, (r14, 0x0)	// regs: r1=local_4
  36:	1005      	lrw	r0, 0x0	// regs: r0=0x0
loc_38:
  38:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x38>, r1=<clobbered>
  3c:	07e9      	br	0xe	// goto loc_e;
loc_3e:
  3e:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  40:	07fc      	br	0x38	// goto loc_38;
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <.rodata.atcmd_phy_reset_hdl.str1.1>
  4a:	0000      	.short	0x0000
  4c:	0000      	.short	0x0000	// <.rodata.atcmd_phy_reset_hdl.str1.1+0x15>
  4e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_adc_dump_hdl:

00000000 <atcmd_adc_dump_hdl>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100d      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1492      	pop	r4-r5, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	108b      	lrw	r4, 0x0	// regs: r4=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0c08      	bf	0x2c	// if (r3 == 0x3f) goto loc_2c;
  1e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1e>, r1=<clobbered>
  22:	eb0000ff 	cmphsi	r0, 256
  26:	0803      	bt	0x2c	// if (r0 >= 0x100) goto loc_2c;
  28:	dc040332 	st.b	r0, (r4, 0x332)	// *(0x332) = <ret atoi@0x1e>
loc_2c:
  2c:	d8440332 	ld.b	r2, (r4, 0x332)	// regs: r2=*(0x332)
  30:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  32:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  34:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x34>, r1=<clobbered>
  38:	07eb      	br	0xe	// goto loc_e;
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <ah_lmac>
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <.rodata.atcmd_adc_dump_hdl.str1.1>
  46:	0000      	.short	0x0000

Disassembly of section .text.atcmd_short_th_hdl:

00000000 <atcmd_short_th_hdl>: // arg_bytes: 12
   0:	14d1      	push	r4, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100a      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1491      	pop	r4, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x14>, r1=<clobbered>
  18:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  1a:	e9600004 	blsz	r0, 0x22
  1e:	dc03119a 	st.h	r0, (r3, 0x334)	// *(0x334) = <ret atoi@0x14>
  22:	d843119a 	ld.h	r2, (r3, 0x334)	// regs: r2=*(0x334)
  26:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  28:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2a>, r1=<clobbered>
  2e:	07f0      	br	0xe	// goto loc_e;
  30:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <ah_lmac>
  38:	0000      	.short	0x0000	// <.rodata.atcmd_short_th_hdl.str1.1>
  3a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_qa_att_hdl:

00000000 <atcmd_qa_att_hdl>: // arg_bytes: 12
   0:	14d1      	push	r4, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	100a      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1491      	pop	r4, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x14>, r1=<clobbered>
  18:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  1a:	e9600004 	blsz	r0, 0x22
  1e:	dc03089b 	st.b	r0, (r3, 0x89b)	// *(0x89b) = <ret atoi@0x14>
  22:	d843119a 	ld.h	r2, (r3, 0x334)	// regs: r2=*(0x334)
  26:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  28:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2a>, r1=<clobbered>
  2e:	07f0      	br	0xe	// goto loc_e;
  30:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <ah_lmac>
  38:	0000      	.short	0x0000	// <.rodata.atcmd_qa_att_hdl.str1.1>
  3a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_lo_table_read_hdl:

00000000 <atcmd_lo_table_read_hdl>: // arg_bytes: 12
   0:	14d1      	push	r4, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1013      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1491      	pop	r4, r15
loc_12:
  12:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  14:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(<arg1>))
  16:	eb43003f 	cmpnei	r3, 63
  1a:	0808      	bt	0x2a	// if (r3 != 0x3f) goto loc_2a;
  1c:	e0000000 	bsr	0x0	// <lmac_lo_table_read>; regs: r0=<ret lmac_lo_table_read@0x1c>, r1=<clobbered>
loc_20:
  20:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  22:	100e      	lrw	r0, 0x0	// regs: r0=0x0
  24:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x24>, r1=<clobbered>
  28:	07f3      	br	0xe	// goto loc_e;
loc_2a:
  2a:	eb43006b 	cmpnei	r3, 107
  2e:	0807      	bt	0x3c	// if (r3 != 0x6b) goto loc_3c;
  30:	106b      	lrw	r3, 0x0	// regs: r3=0x0
  32:	d803033c 	ld.b	r0, (r3, 0x33c)	// regs: r0=*(0x33c)
  36:	e0000000 	bsr	0x0	// <lmac_lo_table_kick>; regs: r0=<ret lmac_lo_table_kick@0x36>, r1=<clobbered>
  3a:	07f3      	br	0x20	// goto loc_20;
loc_3c:
  3c:	eb430073 	cmpnei	r3, 115
  40:	0bf0      	bt	0x20	// if (r3 != 0x73) goto loc_20;
  42:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  44:	d80320ce 	ld.w	r0, (r3, 0x338)	// regs: r0=*(0x338)
  48:	c4805760 	zext	r0, r0, 27, 4	// regs: r0=zext(*(0x338))
  4c:	e0000000 	bsr	0x0	// <lmac_lo_freq_set>; regs: r0=<ret lmac_lo_freq_set@0x4c>, r1=<clobbered>
  50:	07e8      	br	0x20	// goto loc_20;
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <.rodata.atcmd_lo_table_read_hdl.str1.1>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000

Disassembly of section .text.atcmd_ps_check_hdl:

00000000 <atcmd_ps_check_hdl>: // arg_bytes: 12
   0:	14d4      	push	r4-r7, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	6dc3      	mov	r7, r0	// regs: r7=<arg0>
   6:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   8:	e9220008 	bnez	r2, 0x18	// if (r2 != 0x0) goto loc_18;
   c:	1018      	lrw	r0, 0x0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xe>, r1=<clobbered>
loc_12:
  12:	3000      	movi	r0, 0	// regs: r0=0x0
  14:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  16:	1494      	pop	r4-r7, r15
loc_18:
  18:	3a43      	cmpnei	r2, 3
  1a:	1096      	lrw	r4, 0x0	// regs: r4=0x0
  1c:	0817      	bt	0x4a	// if (r2 != 0x3) goto loc_4a;
  1e:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  20:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x20>, r1=<clobbered>
  24:	94c0      	ld.w	r6, (r4, 0x0)	// regs: r6=*(0x0)
  26:	dc042267 	st.w	r0, (r4, 0x99c)	// *(0x99c) = <ret atoi@0x20>
  2a:	9501      	ld.w	r0, (r5, 0x4)	// regs: r0=*(<arg1> + 0x4)
  2c:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x2c>, r1=<clobbered>
  30:	866a      	ld.b	r3, (r6, 0xa)	// regs: r3=*((*(0x0) + 0xa))
  32:	c4605c00 	ins	r3, r0, 0, 0
  36:	a66a      	st.b	r3, (r6, 0xa)	// *((*(0x0) + 0xa)) = *((*(0x0) + 0xa))
  38:	9502      	ld.w	r0, (r5, 0x8)	// regs: r0=*(<arg1> + 0x8)
  3a:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x3a>, r1=<clobbered>
  3e:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
  42:	c4605c01 	ins	r3, r0, 1, 1
  46:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = *(0x319)
loc_4a:
  4a:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
  4c:	d8240319 	ld.b	r1, (r4, 0x319)	// regs: r1=*(0x319)
  50:	836a      	ld.b	r3, (r3, 0xa)	// regs: r3=*((*(0x0) + 0xa))
  52:	c4215421 	zext	r1, r1, 1, 1	// regs: r1=zext(*(0x319))
  56:	b820      	st.w	r1, (r14, 0x0)	// local_4 = zext(*(0x319))
  58:	d8442267 	ld.w	r2, (r4, 0x99c)	// regs: r2=*(0x99c)
  5c:	e4632001 	andi	r3, r3, 1	// regs: r3=(*((*(0x0) + 0xa)) & 0x1)
  60:	5f26      	addi	r1, r7, 2	// regs: r1=(<arg0> + 0x2)
  62:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  64:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x64>, r1=<clobbered>
  68:	07d5      	br	0x12	// goto loc_12;
  6a:	0000      	.short	0x0000
  6c:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  6e:	0000      	.short	0x0000
  70:	00000000 	.long	0x00000000	// <ah_lmac>
  74:	0000      	.short	0x0000	// <.rodata.atcmd_ps_check_hdl.str1.1>
  76:	0000      	.short	0x0000

Disassembly of section .text.atcmd_radio_onoff_hdl:

00000000 <atcmd_radio_onoff_hdl>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	1013      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1493      	pop	r4-r6, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	10d1      	lrw	r6, 0x0	// regs: r6=0x0
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0811      	bt	0x3e	// if (r3 != 0x3f) goto loc_3e;
  1e:	9660      	ld.w	r3, (r6, 0x0)	// regs: r3=*(0x0)
  20:	838a      	ld.b	r4, (r3, 0xa)	// regs: r4=*((*(0x0) + 0xa))
  22:	e4842001 	andi	r4, r4, 1	// regs: r4=(*((*(0x0) + 0xa)) & 0x1)
loc_26:
  26:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  28:	e9040013 	bez	r4, 0x4e	// if (r4 == 0x0) goto loc_4e;
  2c:	3c41      	cmpnei	r4, 1
  2e:	106c      	lrw	r3, 0x0	// regs: r3=0x0
  30:	104c      	lrw	r2, 0x0	// regs: r2=0x0
  32:	c4430c40 	inct	r2, r3, 0
loc_36:
  36:	100c      	lrw	r0, 0x0	// regs: r0=0x0
  38:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x38>, r1=<clobbered>
  3c:	07e9      	br	0xe	// goto loc_e;
loc_3e:
  3e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x3e>, r1=<clobbered>
  42:	6d03      	mov	r4, r0	// regs: r4=<ret atoi@0x3e>
  44:	6c43      	mov	r1, r0	// regs: r1=<ret atoi@0x3e>
  46:	9600      	ld.w	r0, (r6, 0x0)	// regs: r0=*(0x0)
  48:	e0000000 	bsr	0x0	// <lmac_set_radio_onoff>; regs: r0=<ret lmac_set_radio_onoff@0x48>, r1=<clobbered>
  4c:	07ed      	br	0x26	// goto loc_26;
loc_4e:
  4e:	1047      	lrw	r2, 0x0	// regs: r2=0x0
  50:	07f3      	br	0x36	// goto loc_36;
  52:	0000      	.short	0x0000
  54:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <ah_lmac>
  5a:	0000      	.short	0x0000
  5c:	0000      	.short	0x0000	// <.rodata.atcmd_radio_onoff_hdl.str1.1>
  5e:	0000      	.short	0x0000
  60:	00000000 	.long	0x00000000	// <.rodata.atcmd_radio_onoff_hdl.str1.1+0x11>
  64:	0000      	.short	0x0000	// <.rodata.atcmd_radio_onoff_hdl.str1.1+0x1a>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <.rodata.atcmd_radio_onoff_hdl.str1.1+0x7>
  6a:	0000      	.short	0x0000

Disassembly of section .text.atcmd_sta_info_hdl:

00000000 <atcmd_sta_info_hdl>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
loc_8:
   8:	101f      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1493      	pop	r4-r6, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  16:	eb43003f 	cmpnei	r3, 63
  1a:	0c2b      	bf	0x70	// if (r3 == 0x3f) goto loc_70;
  1c:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x1c>, r1=<clobbered>
  20:	6d43      	mov	r5, r0	// regs: r5=<ret atoi@0x1c>
  22:	e900fff3 	bez	r0, 0x8	// if (r0 == 0x0) goto loc_8;
  26:	30fa      	movi	r0, 250	// regs: r0=0xfa
  28:	4001      	lsli	r0, r0, 1	// regs: r0=0x1f4
  2a:	e0000000 	bsr	0x0	// <_os_malloc>; regs: r0=<ret _os_malloc@0x2a>, r1=<clobbered>
  2e:	6d03      	mov	r4, r0	// regs: r4=<ret _os_malloc@0x2a>
  30:	e900ffec 	bez	r0, 0x8	// if (r0 == 0x0) goto loc_8;
  34:	3100      	movi	r1, 0	// regs: r1=0x0
  36:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  38:	1014      	lrw	r0, 0x0	// regs: r0=0x0
  3a:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0x3a>, r1=<clobbered>
  3e:	1074      	lrw	r3, 0x0	// regs: r3=0x0
  40:	e46309f7 	addi	r3, r3, 2552	// regs: r3=0x9f8
  44:	9320      	ld.w	r1, (r3, 0x0)	// regs: r1=*(0x9f8)
loc_46:
  46:	64c6      	cmpne	r1, r3
  48:	0c0e      	bf	0x64	// if (!T) goto loc_64;
  4a:	d8411034 	ld.h	r2, (r1, 0x68)	// regs: r2=*(r1 + 0x68)
  4e:	6496      	cmpne	r5, r2
  50:	0818      	bt	0x80	// if (T) goto loc_80;
  52:	32fa      	movi	r2, 250	// regs: r2=0xfa
  54:	6c13      	mov	r0, r4	// regs: r0=<ret _os_malloc@0x2a>
  56:	4241      	lsli	r2, r2, 1	// regs: r2=0x1f4
  58:	e0000000 	bsr	0x0	// <hw_memcpy>; regs: r0=<ret hw_memcpy@0x58>, r1=<clobbered>
  5c:	3101      	movi	r1, 1	// regs: r1=0x1
  5e:	6c13      	mov	r0, r4	// regs: r0=<ret _os_malloc@0x2a>
  60:	e0000000 	bsr	0x0	// <lmac_sta_info_statics_print>; regs: r0=<ret lmac_sta_info_statics_print@0x60>, r1=<clobbered>
loc_64:
  64:	1009      	lrw	r0, 0x0	// regs: r0=0x0
  66:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0x66>, r1=<clobbered>
  6a:	6c13      	mov	r0, r4	// regs: r0=<ret _os_malloc@0x2a>
  6c:	e0000000 	bsr	0x0	// <_os_free>; regs: r0=<ret _os_free@0x6c>, r1=<clobbered>
loc_70:
  70:	1067      	lrw	r3, 0x0	// regs: r3=0x0
  72:	5e26      	addi	r1, r6, 2	// regs: r1=(<arg0> + 0x2)
  74:	d8431504 	ld.h	r2, (r3, 0xa08)	// regs: r2=*(0xa08)
  78:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  7a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x7a>, r1=<clobbered>
  7e:	07c8      	br	0xe	// goto loc_e;
loc_80:
  80:	9120      	ld.w	r1, (r1, 0x0)	// regs: r1=*(r1)
  82:	07e2      	br	0x46	// goto loc_46;
  84:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  86:	0000      	.short	0x0000
  88:	00000000 	.long	0x00000000	// <ah_lmac+0xa00>
  8c:	00000000 	.long	0x00000000	// <ah_lmac>
  90:	0000      	.short	0x0000	// <.rodata.atcmd_sta_info_hdl.str1.1>
  92:	0000      	.short	0x0000

Disassembly of section .text.atcmd_sta_psk_hdl:

00000000 <atcmd_sta_psk_hdl>: // arg_bytes: 12
   0:	14d6      	push	r4-r9, r15
   2:	1424      	subi	r14, r14, 16	// regs: r14=(sp - 0x10)
   4:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   6:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   8:	e9220008 	bnez	r2, 0x18	// if (r2 != 0x0) goto loc_18;
   c:	1114      	lrw	r0, 0x0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xe>, r1=<clobbered>
loc_12:
  12:	3000      	movi	r0, 0	// regs: r0=0x0
  14:	1404      	addi	r14, r14, 16	// regs: r14=((sp - 0x10) + 0x10)
  16:	1496      	pop	r4-r9, r15
loc_18:
  18:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  1a:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  1c:	eb43003f 	cmpnei	r3, 63
  20:	0844      	bt	0xa8	// if (r3 != 0x3f) goto loc_a8;
  22:	3100      	movi	r1, 0	// regs: r1=0x0
  24:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  26:	110f      	lrw	r0, 0x0	// regs: r0=0x0
  28:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0x28>, r1=<clobbered>
  2c:	110e      	lrw	r0, 0x0	// regs: r0=0x0
  2e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2e>, r1=<clobbered>
  32:	116e      	lrw	r3, 0x0	// regs: r3=0x0
  34:	e4e309f7 	addi	r7, r3, 2552	// regs: r7=0x9f8
  38:	d883227e 	ld.w	r4, (r3, 0x9f8)	// regs: r4=*(0x9f8)
  3c:	ea88002c 	lrw	r8, 0x0	// regs: r8=0x0
  40:	ea89002c 	lrw	r9, 0x0	// regs: r9=0x0
loc_44:
  44:	65d2      	cmpne	r4, r7
  46:	0809      	bt	0x58	// if (T) goto loc_58;
  48:	5c1e      	addi	r0, r4, 8	// regs: r0=(r4 + 0x8)
  4a:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0x4a>, r1=<clobbered>
loc_4e:
  4e:	5e26      	addi	r1, r6, 2	// regs: r1=(<arg0> + 0x2)
  50:	1109      	lrw	r0, 0x0	// regs: r0=0x0
  52:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x52>, r1=<clobbered>
  56:	07de      	br	0x12	// goto loc_12;
loc_58:
  58:	d8040074 	ld.b	r0, (r4, 0x74)	// regs: r0=*(r4 + 0x74)
  5c:	d8640070 	ld.b	r3, (r4, 0x70)	// regs: r3=*(r4 + 0x70)
  60:	d844006f 	ld.b	r2, (r4, 0x6f)	// regs: r2=*(r4 + 0x6f)
  64:	d8241034 	ld.h	r1, (r4, 0x68)	// regs: r1=*(r4 + 0x68)
  68:	b803      	st.w	r0, (r14, 0xc)	// local_4 = *(r4 + 0x74)
  6a:	d8040073 	ld.b	r0, (r4, 0x73)	// regs: r0=*(r4 + 0x73)
  6e:	b802      	st.w	r0, (r14, 0x8)	// local_8 = *(r4 + 0x73)
  70:	d8040072 	ld.b	r0, (r4, 0x72)	// regs: r0=*(r4 + 0x72)
  74:	b801      	st.w	r0, (r14, 0x4)	// local_c = *(r4 + 0x72)
  76:	d8040071 	ld.b	r0, (r4, 0x71)	// regs: r0=*(r4 + 0x71)
  7a:	b800      	st.w	r0, (r14, 0x0)	// local_10 = *(r4 + 0x71)
  7c:	6c23      	mov	r0, r8	// regs: r0=0x0
  7e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x7e>, r1=<clobbered>
  82:	3500      	movi	r5, 0	// regs: r5=0x0
loc_84:
  84:	d8640076 	ld.b	r3, (r4, 0x76)	// regs: r3=*(r4 + 0x76)
  88:	64d4      	cmphs	r5, r3
  8a:	0c06      	bf	0x96	// if (!T) goto loc_96;
  8c:	101b      	lrw	r0, 0x0	// regs: r0=0x0
  8e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x8e>, r1=<clobbered>
  92:	9480      	ld.w	r4, (r4, 0x0)	// regs: r4=*(r4)
  94:	07d8      	br	0x44	// goto loc_44;
loc_96:
  96:	5c74      	addu	r3, r4, r5	// regs: r3=(r4 + r5)
  98:	6c27      	mov	r0, r9	// regs: r0=0x0
  9a:	d8230077 	ld.b	r1, (r3, 0x77)	// regs: r1=*(((r4 + r5) + 0x77))
  9e:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  a0:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xa0>, r1=<clobbered>
  a4:	7554      	zextb	r5, r5	// regs: r5=zext8((r5 + 0x1))
  a6:	07ef      	br	0x84	// goto loc_84;
loc_a8:
  a8:	3a42      	cmpnei	r2, 2
  aa:	0bd2      	bt	0x4e	// if (r2 != 0x2) goto loc_4e;
  ac:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0xac>, r1=<clobbered>
  b0:	7401      	zexth	r0, r0	// regs: r0=zext16(<ret atoi@0xac>)
  b2:	3100      	movi	r1, 0	// regs: r1=0x0
  b4:	e0000000 	bsr	0x0	// <lmac_sta_get>; regs: r0=<ret lmac_sta_get@0xb4>, r1=<clobbered>
  b8:	6d03      	mov	r4, r0	// regs: r4=<ret lmac_sta_get@0xb4>
  ba:	e900000c 	bez	r0, 0xd2	// if (r0 == 0x0) goto loc_d2;
  be:	e4200076 	addi	r1, r0, 119	// regs: r1=(<ret lmac_sta_get@0xb4> + 0x77)
  c2:	3220      	movi	r2, 32	// regs: r2=0x20
  c4:	9501      	ld.w	r0, (r5, 0x4)	// regs: r0=*(<arg1> + 0x4)
  c6:	e0000000 	bsr	0x0	// <hex2bin>; regs: r0=<ret hex2bin@0xc6>, r1=<clobbered>
  ca:	6c13      	mov	r0, r4	// regs: r0=<ret lmac_sta_get@0xb4>
  cc:	e0000000 	bsr	0x0	// <lmac_sta_put>; regs: r0=<ret lmac_sta_put@0xcc>, r1=<clobbered>
  d0:	07bf      	br	0x4e	// goto loc_4e;
loc_d2:
  d2:	1003      	lrw	r0, 0x0	// regs: r0=0x0
  d4:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xd4>, r1=<clobbered>
  d8:	07bb      	br	0x4e	// goto loc_4e;
  da:	0000      	.short	0x0000
  dc:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  e0:	00000000 	.long	0x00000000	// <ah_lmac+0xa00>
  e4:	00000000 	.long	0x00000000	// <.rodata.atcmd_sta_psk_hdl.str1.1>
  e8:	00000000 	.long	0x00000000	// <ah_lmac>
  ec:	00000000 	.long	0x00000000	// <.rodata.atcmd_sta_psk_hdl.str1.1+0xc>
  f0:	00000000 	.long	0x00000000	// <.rodata.atcmd_sta_psk_hdl.str1.1+0x30>
  f4:	00000000 	.long	0x00000000	// <.rodata.atcmd_lo_table_read_hdl.str1.1>
  f8:	00000000 	.long	0x00000000	// <.rodata.atcmd_freq_list_hdl.str1.1+0x1b>

Disassembly of section .text.atcmd_txpower_hdl:

00000000 <atcmd_txpower_hdl>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	3a41      	cmpnei	r2, 1
   4:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   6:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   8:	0c06      	bf	0x14	// if (r2 == 0x1) goto loc_14;
loc_a:
   a:	1017      	lrw	r0, 0x0	// regs: r0=0x0
   c:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xc>, r1=<clobbered>
loc_10:
  10:	3000      	movi	r0, 0	// regs: r0=0x0
  12:	1493      	pop	r4-r6, r15
loc_14:
  14:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  16:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  18:	eb43003f 	cmpnei	r3, 63
  1c:	0809      	bt	0x2e	// if (r3 != 0x3f) goto loc_2e;
  1e:	1073      	lrw	r3, 0x0	// regs: r3=0x0
  20:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  22:	d843468e 	ld.bs	r2, (r3, 0x68e)	// regs: r2=*(0x68e)
  26:	1012      	lrw	r0, 0x0	// regs: r0=0x0
loc_28:
  28:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x28>, r1=<clobbered>
  2c:	07f2      	br	0x10	// goto loc_10;
loc_2e:
  2e:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x2e>, r1=<clobbered>
  32:	e960ffec 	blsz	r0, 0xa
  36:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
  38:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x38>, r1=<clobbered>
  3c:	3834      	cmplti	r0, 21
  3e:	0fe6      	bf	0xa	// if (r0 >= 0x15) goto loc_a;
  40:	106a      	lrw	r3, 0x0	// regs: r3=0x0
  42:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
  44:	93c0      	ld.w	r6, (r3, 0x0)	// regs: r6=*(0x0)
  46:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x46>, r1=<clobbered>
  4a:	6c83      	mov	r2, r0	// regs: r2=<ret atoi@0x46>
  4c:	3106      	movi	r1, 6	// regs: r1=0x6
  4e:	3300      	movi	r3, 0	// regs: r3=0x0
  50:	6c1b      	mov	r0, r6	// regs: r0=*(0x0)
  52:	e0000000 	bsr	0x0	// <lmac_ioctl>; regs: r0=<ret lmac_ioctl@0x52>, r1=<clobbered>
  56:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
  58:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x58>, r1=<clobbered>
  5c:	6c83      	mov	r2, r0	// regs: r2=<ret atoi@0x58>
  5e:	5d26      	addi	r1, r5, 2	// regs: r1=(<arg0> + 0x2)
  60:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  62:	07e3      	br	0x28	// goto loc_28;
  64:	0000      	.short	0x0000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  66:	0000      	.short	0x0000
  68:	0000      	.short	0x0000	// <ah_lmac>
  6a:	0000      	.short	0x0000
  6c:	0000      	.short	0x0000	// <.rodata.atcmd_txpower_hdl.str1.1>
  6e:	0000      	.short	0x0000
  70:	00000000 	.long	0x00000000	// <.rodata.atcmd_txpower_hdl.str1.1+0xe>

Disassembly of section .text.atcmd_set_vdd13_hdl:

00000000 <atcmd_set_vdd13_hdl>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	e9220007 	bnez	r2, 0x12	// if (r2 != 0x0) goto loc_12;
   8:	110c      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xa>, r1=<clobbered>
loc_e:
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	1493      	pop	r4-r6, r15
loc_12:
  12:	9100      	ld.w	r0, (r1, 0x0)	// regs: r0=*(<arg1>)
  14:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(*(<arg1>))
  16:	eb43003f 	cmpnei	r3, 63
  1a:	080b      	bt	0x30	// if (r3 != 0x3f) goto loc_30;
  1c:	1168      	lrw	r3, 0x0	// regs: r3=0x0
  1e:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  20:	d84303df 	ld.b	r2, (r3, 0x3df)	// regs: r2=*(0x3df)
  24:	e4422003 	andi	r2, r2, 3	// regs: r2=(*(0x3df) & 0x3)
  28:	1106      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x2a>, r1=<clobbered>
  2e:	07f0      	br	0xe	// goto loc_e;
loc_30:
  30:	3a41      	cmpnei	r2, 1
  32:	0bee      	bt	0xe	// if (r2 != 0x1) goto loc_e;
  34:	e0000000 	bsr	0x0	// <atoi>; regs: r0=<ret atoi@0x34>, r1=<clobbered>
  38:	7400      	zextb	r0, r0	// regs: r0=zext8(<ret atoi@0x34>)
  3a:	3802      	cmphsi	r0, 3
  3c:	0838      	bt	0xac	// if (r0 >= 0x3) goto loc_ac;
  3e:	1160      	lrw	r3, 0x0	// regs: r3=0x0
  40:	e4c02003 	andi	r6, r0, 3	// regs: r6=(zext8(<ret atoi@0x34>) & 0x3)
  44:	d84303df 	ld.b	r2, (r3, 0x3df)	// regs: r2=*(0x3df)
  48:	3841      	cmpnei	r0, 1
  4a:	c4465c20 	ins	r2, r6, 1, 0
  4e:	dc4303df 	st.b	r2, (r3, 0x3df)	// *(0x3df) = *(0x3df)
  52:	6d4f      	mov	r5, r3	// regs: r5=0x0
  54:	0812      	bt	0x78	// if (r0 != 0x1) goto loc_78;
  56:	e0000000 	bsr	0x0	// <pmu_vdd13_ldo_dis_sec>; regs: r0=<ret pmu_vdd13_ldo_dis_sec@0x56>, r1=<clobbered>
  5a:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  5c:	101a      	lrw	r0, 0x0	// regs: r0=0x0
loc_5e:
  5e:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x5e>, r1=<clobbered>
loc_62:
  62:	d8652233 	ld.w	r3, (r5, 0x8cc)	// regs: r3=*(0x8cc)
  66:	e903001f 	bez	r3, 0xa4	// if (r3 == 0x0) goto loc_a4;
  6a:	d843025b 	ld.b	r2, (r3, 0x25b)	// regs: r2=*((*(0x8cc) + 0x25b))
  6e:	c4465c20 	ins	r2, r6, 1, 0
  72:	dc43025b 	st.b	r2, (r3, 0x25b)	// *((*(0x8cc) + 0x25b)) = *((*(0x8cc) + 0x25b))
  76:	07cc      	br	0xe	// goto loc_e;
loc_78:
  78:	3842      	cmpnei	r0, 2
  7a:	080a      	bt	0x8e	// if (r0 != 0x2) goto loc_8e;
  7c:	3005      	movi	r0, 5	// regs: r0=0x5
  7e:	e0000000 	bsr	0x0	// <pmu_vdd13c_vol_set_sec>; regs: r0=<ret pmu_vdd13c_vol_set_sec@0x7e>, r1=<clobbered>
  82:	3005      	movi	r0, 5	// regs: r0=0x5
  84:	e0000000 	bsr	0x0	// <pmu_vdd13b_vol_set_sec>; regs: r0=<ret pmu_vdd13b_vol_set_sec@0x84>, r1=<clobbered>
  88:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  8a:	1010      	lrw	r0, 0x0	// regs: r0=0x0
  8c:	07e9      	br	0x5e	// goto loc_5e;
loc_8e:
  8e:	e920ffea 	bnez	r0, 0x62	// if (r0 != 0x0) goto loc_62;
  92:	3004      	movi	r0, 4	// regs: r0=0x4
  94:	e0000000 	bsr	0x0	// <pmu_vdd13c_vol_set_sec>; regs: r0=<ret pmu_vdd13c_vol_set_sec@0x94>, r1=<clobbered>
  98:	3004      	movi	r0, 4	// regs: r0=0x4
  9a:	e0000000 	bsr	0x0	// <pmu_vdd13b_vol_set_sec>; regs: r0=<ret pmu_vdd13b_vol_set_sec@0x9a>, r1=<clobbered>
  9e:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  a0:	100b      	lrw	r0, 0x0	// regs: r0=0x0
  a2:	07de      	br	0x5e	// goto loc_5e;
loc_a4:
  a4:	100b      	lrw	r0, 0x0	// regs: r0=0x0
  a6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xa6>, r1=<clobbered>
  aa:	07b2      	br	0xe	// goto loc_e;
loc_ac:
  ac:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
  ae:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  b0:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0xb0>, r1=<clobbered>
  b4:	07ad      	br	0xe	// goto loc_e;
  b6:	0000      	.short	0x0000
  b8:	00000000 	.long	0x00000000	// <.rodata.atcmd_reg_rd_hdl.str1.1>
  bc:	00000000 	.long	0x00000000	// <ah_lmac>
  c0:	00000000 	.long	0x00000000	// <.rodata.atcmd_set_vdd13_hdl.str1.1>
  c4:	00000000 	.long	0x00000000	// <.rodata.atcmd_set_vdd13_hdl.str1.1+0x1a>
  c8:	00000000 	.long	0x00000000	// <.rodata.atcmd_set_vdd13_hdl.str1.1+0x3e>
  cc:	00000000 	.long	0x00000000	// <.rodata.atcmd_set_vdd13_hdl.str1.1+0x66>
  d0:	00000000 	.long	0x00000000	// <.rodata.atcmd_set_vdd13_hdl.str1.1+0x84>
  d4:	00000000 	.long	0x00000000	// <.rodata.atcmd_set_vdd13_hdl.str1.1+0x8f>

Disassembly of section .text.atcmd_smt_dat_hdl:

00000000 <atcmd_smt_dat_hdl>: // arg_bytes: 8
   0:	14d1      	push	r4, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	e0000000 	bsr	0x0	// <sysctrl_efuse_get_smt_dat>; regs: r0=<ret sysctrl_efuse_get_smt_dat@0x4>, r1=<clobbered>
   8:	6c83      	mov	r2, r0	// regs: r2=<ret sysctrl_efuse_get_smt_dat@0x4>
   a:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg0> + 0x2)
   c:	e9200007 	bnez	r0, 0x1a	// if (r0 != 0x0) goto loc_1a;
  10:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  12:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x12>, r1=<clobbered>
loc_16:
  16:	3000      	movi	r0, 0	// regs: r0=0x0
  18:	1491      	pop	r4, r15
loc_1a:
  1a:	1066      	lrw	r3, 0x5b8d7f	// regs: r3=0x5b8d7f
  1c:	640c      	cmphs	r3, r0
  1e:	0c05      	bf	0x28	// if (!T) goto loc_28;
  20:	1005      	lrw	r0, 0x0	// regs: r0=0x0
loc_22:
  22:	e0000000 	bsr	0x0	// <atcmd_printf>; regs: r0=<ret atcmd_printf@0x22>, r1=<clobbered>
  26:	07f8      	br	0x16	// goto loc_16;
loc_28:
  28:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	07fc      	br	0x22	// goto loc_22;
  2c:	00000000 	.long	0x00000000	// <.rodata.atcmd_smt_dat_hdl.str1.1>
  30:	8d7f      	.short	0x8d7f
  32:	005b      	.short	0x005b
  34:	00000000 	.long	0x00000000	// <.rodata.atcmd_smt_dat_hdl.str1.1+0x1a>
  38:	0000      	.short	0x0000	// <.rodata.atcmd_smt_dat_hdl.str1.1+0x29>
  3a:	0000      	.short	0x0000

Disassembly of section .text.lmac_test_init:

00000000 <lmac_test_init>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	1186      	lrw	r4, 0x0	// regs: r4=0x0
   4:	324c      	movi	r2, 76	// regs: r2=0x4c
   6:	3100      	movi	r1, 0	// regs: r1=0x0
   8:	6c13      	mov	r0, r4	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0xa>, r1=<clobbered>
   e:	33c2      	movi	r3, 194	// regs: r3=0xc2
  10:	4362      	lsli	r3, r3, 2	// regs: r3=0x308
  12:	ac72      	st.h	r3, (r4, 0x24)	// *(0x24) = 0x308
  14:	3380      	movi	r3, 128	// regs: r3=0x80
  16:	1142      	lrw	r2, 0x0	// regs: r2=0x0
  18:	4361      	lsli	r3, r3, 1	// regs: r3=0x100
  1a:	dc641020 	st.h	r3, (r4, 0x40)	// *(0x40) = 0x100
  1e:	330a      	movi	r3, 10	// regs: r3=0xa
  20:	dc62089a 	st.b	r3, (r2, 0x89a)	// *(0x89a) = 0xa
  24:	3300      	movi	r3, 0	// regs: r3=0x0
  26:	2b3b      	subi	r3, 60	// regs: r3=0xffffffc4
  28:	dc62089b 	st.b	r3, (r2, 0x89b)	// *(0x89b) = 0xffffffc4
  2c:	dc62089c 	st.b	r3, (r2, 0x89c)	// *(0x89c) = 0xffffffc4
  30:	dc6208a4 	st.b	r3, (r2, 0x8a4)	// *(0x8a4) = 0xffffffc4
  34:	3600      	movi	r6, 0	// regs: r6=0x0
  36:	d8620892 	ld.b	r3, (r2, 0x892)	// regs: r3=*(0x892)
  3a:	3100      	movi	r1, 0	// regs: r1=0x0
  3c:	291a      	subi	r1, 27	// regs: r1=0xffffffe5
  3e:	c4665c02 	ins	r3, r6, 2, 2
  42:	dc22089d 	st.b	r1, (r2, 0x89d)	// *(0x89d) = 0xffffffe5
  46:	dc2208a5 	st.b	r1, (r2, 0x8a5)	// *(0x8a5) = 0xffffffe5
  4a:	dc620892 	st.b	r3, (r2, 0x892)	// *(0x892) = *(0x892)
  4e:	3105      	movi	r1, 5	// regs: r1=0x5
  50:	d86214f1 	ld.h	r3, (r2, 0x9e2)	// regs: r3=*(0x9e2)
  54:	c4615ce6 	ins	r3, r1, 13, 6
  58:	dc6214f1 	st.h	r3, (r2, 0x9e2)	// *(0x9e2) = *(0x9e2)
  5c:	3380      	movi	r3, 128	// regs: r3=0x80
  5e:	e4a4000b 	addi	r5, r4, 12	// regs: r5=0xc
  62:	3003      	movi	r0, 3	// regs: r0=0x3
  64:	4364      	lsli	r3, r3, 4	// regs: r3=0x800
  66:	dc02089e 	st.b	r0, (r2, 0x89e)	// *(0x89e) = 0x3
  6a:	dc0208a6 	st.b	r0, (r2, 0x8a6)	// *(0x8a6) = 0x3
  6e:	b462      	st.w	r3, (r4, 0x8)	// *(0x8) = 0x800
  70:	6c57      	mov	r1, r5	// regs: r1=0xc
  72:	6cd3      	mov	r3, r4	// regs: r3=0x0
  74:	104b      	lrw	r2, 0x0	// regs: r2=0x0
  76:	100c      	lrw	r0, 0x0	// regs: r0=0x0
  78:	e0000000 	bsr	0x0	// <os_task_init>; regs: r0=<ret os_task_init@0x78>, r1=<clobbered>
  7c:	3180      	movi	r1, 128	// regs: r1=0x80
  7e:	4122      	lsli	r1, r1, 2	// regs: r1=0x200
  80:	6c17      	mov	r0, r5	// regs: r0=0xc
  82:	e0000000 	bsr	0x0	// <os_task_set_stacksize>; regs: r0=<ret os_task_set_stacksize@0x82>, r1=<clobbered>
  86:	3130      	movi	r1, 48	// regs: r1=0x30
  88:	6c17      	mov	r0, r5	// regs: r0=0xc
  8a:	e0000000 	bsr	0x0	// <os_task_set_priority>; regs: r0=<ret os_task_set_priority@0x8a>, r1=<clobbered>
  8e:	6c17      	mov	r0, r5	// regs: r0=0xc
  90:	e0000000 	bsr	0x0	// <os_task_run>; regs: r0=<ret os_task_run@0x90>, r1=<clobbered>
  94:	6c1b      	mov	r0, r6	// regs: r0=0x0
  96:	1493      	pop	r4-r6, r15
  98:	00000000 	.long	0x00000000	// <lmactest>
  9c:	0000      	.short	0x0000	// <ah_lmac>
  9e:	0000      	.short	0x0000
  a0:	0000      	.short	0x0000	// <.text.lmac_test_task>
  a2:	0000      	.short	0x0000
  a4:	0000      	.short	0x0000	// <.rodata.lmac_test_init.str1.1>
  a6:	0000      	.short	0x0000
