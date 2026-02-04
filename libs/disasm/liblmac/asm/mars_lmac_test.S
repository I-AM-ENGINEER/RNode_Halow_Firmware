
disasm/liblmac/obj/mars_lmac_test.o:     file format elf32-csky-little


Disassembly of section .text.lo_freq_valid_check:

00000000 <lo_freq_valid_check>:
   0:	1070      	lrw      	r3, 0xfff4dc70	// 40 <lo_freq_valid_check+0x40>
   2:	584c      	addu      	r2, r0, r3
   4:	ea03c350 	movi      	r3, 50000
   8:	c4434903 	rotli      	r3, r3, 2
   c:	648c      	cmphs      	r3, r2
   e:	0c15      	bf      	0x38	// 38 <lo_freq_valid_check+0x38>
  10:	106d      	lrw      	r3, 0x0	// 44 <lo_freq_valid_check+0x44>
  12:	8367      	ld.b      	r3, (r3, 0x7)
  14:	e46320fb 	andi      	r3, r3, 251
  18:	3b41      	cmpnei      	r3, 1
  1a:	3300      	movi      	r3, 0
  1c:	0809      	bt      	0x2e	// 2e <lo_freq_valid_check+0x2e>
  1e:	ea02cd14 	movi      	r2, 52500
  22:	c4824902 	rotli      	r2, r2, 4
  26:	6408      	cmphs      	r2, r0
  28:	6403      	mvcv      	r0
  2a:	5b01      	subu      	r0, r3, r0
  2c:	783c      	jmp      	r15
  2e:	1047      	lrw      	r2, 0xcd13f	// 48 <lo_freq_valid_check+0x48>
  30:	6408      	cmphs      	r2, r0
  32:	c4000500 	mvc      	r0
  36:	07fa      	br      	0x2a	// 2a <lo_freq_valid_check+0x2a>
  38:	3000      	movi      	r0, 0
  3a:	2800      	subi      	r0, 1
  3c:	07f8      	br      	0x2c	// 2c <lo_freq_valid_check+0x2c>
  3e:	0000      	.short	0x0000
  40:	dc70      	.short	0xdc70
  42:	fff4      	.short	0xfff4
  44:	0000      	.short	0x0000
  46:	0000      	.short	0x0000
  48:	d13f      	.short	0xd13f
  4a:	000c      	.short	0x000c

Disassembly of section .text.lmac_test_enable:

00000000 <lmac_test_enable>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d43      	mov      	r5, r0
   4:	12c7      	lrw      	r6, 0x0	// 120 <lmac_test_enable+0x120>
   6:	1288      	lrw      	r4, 0x0	// 124 <lmac_test_enable+0x124>
   8:	e9000037 	bez      	r0, 0x76	// 76 <lmac_test_enable+0x76>
   c:	e0000000 	bsr      	0x0	// 0 <lhw_abort_fsm>
  10:	1206      	lrw      	r0, 0x0	// 128 <hgprintf+0x128>
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	d86420ce 	ld.w      	r3, (r4, 0x338)
  1a:	c4835763 	zext      	r3, r3, 27, 4
  1e:	b671      	st.w      	r3, (r6, 0x44)
  20:	3264      	movi      	r2, 100
  22:	d86411b0 	ld.h      	r3, (r4, 0x360)
  26:	c4625d01 	ins      	r3, r2, 9, 1
  2a:	dc6411b0 	st.h      	r3, (r4, 0x360)
  2e:	3301      	movi      	r3, 1
  30:	dc640315 	st.b      	r3, (r4, 0x315)
  34:	3300      	movi      	r3, 0
  36:	dc640a4e 	st.b      	r3, (r4, 0xa4e)
  3a:	3200      	movi      	r2, 0
  3c:	d864036d 	ld.b      	r3, (r4, 0x36d)
  40:	c4625c22 	ins      	r3, r2, 3, 2
  44:	3501      	movi      	r5, 1
  46:	dc64036d 	st.b      	r3, (r4, 0x36d)
  4a:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
  4e:	c4655c01 	ins      	r3, r5, 1, 1
  52:	6c17      	mov      	r0, r5
  54:	dc6409e2 	st.b      	r3, (r4, 0x9e2)
  58:	e0000000 	bsr      	0x0	// 0 <lmac_notify_testmode_state>
  5c:	d86403df 	ld.b      	r3, (r4, 0x3df)
  60:	c4655c03 	ins      	r3, r5, 3, 3
  64:	3002      	movi      	r0, 2
  66:	dc6403df 	st.b      	r3, (r4, 0x3df)
  6a:	e0000000 	bsr      	0x0	// 0 <lmac_spec_cca_cfg>
  6e:	3000      	movi      	r0, 0
  70:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
  74:	1493      	pop      	r4-r6, r15
  76:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
  7a:	c4605c05 	ins      	r3, r0, 5, 5
  7e:	c4605c03 	ins      	r3, r0, 3, 3
  82:	d8460042 	ld.b      	r2, (r6, 0x42)
  86:	c4405c00 	ins      	r2, r0, 0, 0
  8a:	c4605c04 	ins      	r3, r0, 4, 4
  8e:	dc460042 	st.b      	r2, (r6, 0x42)
  92:	dc6409e2 	st.b      	r3, (r4, 0x9e2)
  96:	e0000000 	bsr      	0x0	// 0 <ah_wphy_cont_tx_disable>
  9a:	301e      	movi      	r0, 30
  9c:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
  a0:	e0000000 	bsr      	0x0	// 0 <lhw_abort_fsm>
  a4:	6c17      	mov      	r0, r5
  a6:	e0000000 	bsr      	0x0	// 0 <disable_print>
  aa:	e0000000 	bsr      	0x0	// 0 <update_rx_buff_addr>
  ae:	9608      	ld.w      	r0, (r6, 0x20)
  b0:	e9000004 	bez      	r0, 0xb8	// b8 <lmac_test_enable+0xb8>
  b4:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
  b8:	9611      	ld.w      	r0, (r6, 0x44)
  ba:	e0000000 	bsr      	0x0	// 0 <lmac_lo_freq_set>
  be:	3500      	movi      	r5, 0
  c0:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
  c4:	c4655c01 	ins      	r3, r5, 1, 1
  c8:	dc6409e2 	st.b      	r3, (r4, 0x9e2)
  cc:	3318      	movi      	r3, 24
  ce:	ea0201ff 	movi      	r2, 511
  d2:	dc640315 	st.b      	r3, (r4, 0x315)
  d6:	d86411b0 	ld.h      	r3, (r4, 0x360)
  da:	c4625d01 	ins      	r3, r2, 9, 1
  de:	6c17      	mov      	r0, r5
  e0:	dc6411b0 	st.h      	r3, (r4, 0x360)
  e4:	e0000000 	bsr      	0x0	// 0 <lmac_notify_testmode_state>
  e8:	d86403df 	ld.b      	r3, (r4, 0x3df)
  ec:	c4655c03 	ins      	r3, r5, 3, 3
  f0:	3201      	movi      	r2, 1
  f2:	dc6403df 	st.b      	r3, (r4, 0x3df)
  f6:	6c17      	mov      	r0, r5
  f8:	d8640361 	ld.b      	r3, (r4, 0x361)
  fc:	c4625c02 	ins      	r3, r2, 2, 2
 100:	283b      	subi      	r0, 60
 102:	dc640361 	st.b      	r3, (r4, 0x361)
 106:	dc04031e 	st.b      	r0, (r4, 0x31e)
 10a:	e0000000 	bsr      	0x0	// 0 <lmac_adjust_cca_threshold>
 10e:	d864036d 	ld.b      	r3, (r4, 0x36d)
 112:	c48354a2 	zext      	r2, r3, 5, 4
 116:	c4625c22 	ins      	r3, r2, 3, 2
 11a:	dc64036d 	st.b      	r3, (r4, 0x36d)
 11e:	07a8      	br      	0x6e	// ba <lmac_test_enable+0xba>
	...

Disassembly of section .text.lmac_test_txskb_init:

00000000 <lmac_test_txskb_init>:
   0:	14d5      	push      	r4-r8, r15
   2:	6d83      	mov      	r6, r0
   4:	3180      	movi      	r1, 128
   6:	4121      	lsli      	r1, r1, 1
   8:	e0000000 	bsr      	0x0	// 0 <skb_reserve>
   c:	d866002a 	ld.b      	r3, (r6, 0x2a)
  10:	3201      	movi      	r2, 1
  12:	c4625c06 	ins      	r3, r2, 6, 6
  16:	96a6      	ld.w      	r5, (r6, 0x18)
  18:	dc66002a 	st.b      	r3, (r6, 0x2a)
  1c:	3120      	movi      	r1, 32
  1e:	6c1b      	mov      	r0, r6
  20:	e0000000 	bsr      	0x0	// 0 <skb_reserve>
  24:	3220      	movi      	r2, 32
  26:	3100      	movi      	r1, 0
  28:	6c17      	mov      	r0, r5
  2a:	e0000000 	bsr      	0x0	// 0 <memset>
  2e:	3300      	movi      	r3, 0
  30:	2b00      	subi      	r3, 1
  32:	a568      	st.b      	r3, (r5, 0x8)
  34:	a569      	st.b      	r3, (r5, 0x9)
  36:	a56a      	st.b      	r3, (r5, 0xa)
  38:	3300      	movi      	r3, 0
  3a:	2b1f      	subi      	r3, 32
  3c:	a56b      	st.b      	r3, (r5, 0xb)
  3e:	330f      	movi      	r3, 15
  40:	1391      	lrw      	r4, 0x0	// 204 <lmac_test_txskb_init+0x204>
  42:	2507      	addi      	r5, 8
  44:	a56a      	st.b      	r3, (r5, 0xa)
  46:	d864003c 	ld.b      	r3, (r4, 0x3c)
  4a:	a564      	st.b      	r3, (r5, 0x4)
  4c:	d864003d 	ld.b      	r3, (r4, 0x3d)
  50:	a565      	st.b      	r3, (r5, 0x5)
  52:	d864003e 	ld.b      	r3, (r4, 0x3e)
  56:	a566      	st.b      	r3, (r5, 0x6)
  58:	d864003f 	ld.b      	r3, (r4, 0x3f)
  5c:	a567      	st.b      	r3, (r5, 0x7)
  5e:	3218      	movi      	r2, 24
  60:	e4240023 	addi      	r1, r4, 36
  64:	b6ad      	st.w      	r5, (r6, 0x34)
  66:	9606      	ld.w      	r0, (r6, 0x18)
  68:	e0000000 	bsr      	0x0	// 0 <memcpy>
  6c:	3118      	movi      	r1, 24
  6e:	6c1b      	mov      	r0, r6
  70:	e0000000 	bsr      	0x0	// 0 <skb_put>
  74:	9606      	ld.w      	r0, (r6, 0x18)
  76:	6c83      	mov      	r2, r0
  78:	ea0c0006 	movi      	r12, 6
  7c:	5a61      	subu      	r3, r2, r0
  7e:	d8241020 	ld.h      	r1, (r4, 0x40)
  82:	644c      	cmphs      	r3, r1
  84:	0c89      	bf      	0x196	// 196 <lmac_test_txskb_init+0x196>
  86:	6c1b      	mov      	r0, r6
  88:	e0000000 	bsr      	0x0	// 0 <skb_put>
  8c:	96a8      	ld.w      	r5, (r6, 0x20)
  8e:	3244      	movi      	r2, 68
  90:	6c17      	mov      	r0, r5
  92:	3100      	movi      	r1, 0
  94:	e0000000 	bsr      	0x0	// 0 <memset>
  98:	3318      	movi      	r3, 24
  9a:	dc65002a 	st.b      	r3, (r5, 0x2a)
  9e:	3300      	movi      	r3, 0
  a0:	dc650026 	st.b      	r3, (r5, 0x26)
  a4:	96e7      	ld.w      	r7, (r6, 0x1c)
  a6:	12b9      	lrw      	r5, 0x0	// 208 <lmac_test_txskb_init+0x208>
  a8:	ea880059 	lrw      	r8, 0x0	// 20c <lmac_test_txskb_init+0x20c>
  ac:	d8650892 	ld.b      	r3, (r5, 0x892)
  b0:	e4432001 	andi      	r2, r3, 1
  b4:	e902005a 	bez      	r2, 0x168	// 168 <lmac_test_txskb_init+0x168>
  b8:	e4432002 	andi      	r2, r3, 2
  bc:	e9020077 	bez      	r2, 0x1aa	// 1aa <lmac_test_txskb_init+0x1aa>
  c0:	3300      	movi      	r3, 0
  c2:	dc640028 	st.b      	r3, (r4, 0x28)
  c6:	3310      	movi      	r3, 16
  c8:	dc640029 	st.b      	r3, (r4, 0x29)
  cc:	3320      	movi      	r3, 32
  ce:	dc64002a 	st.b      	r3, (r4, 0x2a)
  d2:	3330      	movi      	r3, 48
  d4:	dc64002b 	st.b      	r3, (r4, 0x2b)
  d8:	3340      	movi      	r3, 64
  da:	dc64002c 	st.b      	r3, (r4, 0x2c)
  de:	3350      	movi      	r3, 80
  e0:	dc64002d 	st.b      	r3, (r4, 0x2d)
  e4:	d865089b 	ld.b      	r3, (r5, 0x89b)
  e8:	96c7      	ld.w      	r6, (r6, 0x1c)
  ea:	dc681000 	st.h      	r3, (r8, 0x0)
  ee:	3300      	movi      	r3, 0
  f0:	2b22      	subi      	r3, 35
  f2:	a678      	st.b      	r3, (r6, 0x18)
  f4:	3309      	movi      	r3, 9
  f6:	a679      	st.b      	r3, (r6, 0x19)
  f8:	3300      	movi      	r3, 0
  fa:	2b7f      	subi      	r3, 128
  fc:	e486001a 	addi      	r4, r6, 27
 100:	a67a      	st.b      	r3, (r6, 0x1a)
 102:	3208      	movi      	r2, 8
 104:	3100      	movi      	r1, 0
 106:	6c13      	mov      	r0, r4
 108:	e0000000 	bsr      	0x0	// 0 <memset>
 10c:	d865034a 	ld.b      	r3, (r5, 0x34a)
 110:	e4632001 	andi      	r3, r3, 1
 114:	865b      	ld.b      	r2, (r6, 0x1b)
 116:	e9030069 	bez      	r3, 0x1e8	// 1e8 <lmac_test_txskb_init+0x1e8>
 11a:	ec620001 	ori      	r3, r2, 1
 11e:	a67b      	st.b      	r3, (r6, 0x1b)
 120:	3200      	movi      	r2, 0
 122:	867b      	ld.b      	r3, (r6, 0x1b)
 124:	2a5f      	subi      	r2, 96
 126:	6cc8      	or      	r3, r2
 128:	a67b      	st.b      	r3, (r6, 0x1b)
 12a:	d8650349 	ld.b      	r3, (r5, 0x349)
 12e:	a461      	st.b      	r3, (r4, 0x1)
 130:	d8650309 	ld.b      	r3, (r5, 0x309)
 134:	a462      	st.b      	r3, (r4, 0x2)
 136:	d86520ce 	ld.w      	r3, (r5, 0x338)
 13a:	c4835763 	zext      	r3, r3, 27, 4
 13e:	1155      	lrw      	r2, 0xfff551a0	// 210 <lmac_test_txskb_init+0x210>
 140:	31fa      	movi      	r1, 250
 142:	4122      	lsli      	r1, r1, 2
 144:	608c      	addu      	r2, r3
 146:	c4228042 	divs      	r2, r2, r1
 14a:	3001      	movi      	r0, 1
 14c:	a443      	st.b      	r2, (r4, 0x3)
 14e:	8444      	ld.b      	r2, (r4, 0x4)
 150:	c4405c00 	ins      	r2, r0, 0, 0
 154:	c4238040 	divs      	r0, r3, r1
 158:	7c40      	mult      	r1, r0
 15a:	60c6      	subu      	r3, r1
 15c:	3164      	movi      	r1, 100
 15e:	c4238043 	divs      	r3, r3, r1
 162:	c4435c61 	ins      	r2, r3, 4, 1
 166:	a444      	st.b      	r2, (r4, 0x4)
 168:	d8481000 	ld.h      	r2, (r8, 0x0)
 16c:	4264      	lsli      	r3, r2, 4
 16e:	74cd      	zexth      	r3, r3
 170:	a776      	st.b      	r3, (r7, 0x16)
 172:	4b68      	lsri      	r3, r3, 8
 174:	a777      	st.b      	r3, (r7, 0x17)
 176:	d8650315 	ld.b      	r3, (r5, 0x315)
 17a:	3b41      	cmpnei      	r3, 1
 17c:	0840      	bt      	0x1fc	// 1fc <lmac_test_txskb_init+0x1fc>
 17e:	3300      	movi      	r3, 0
 180:	dc681000 	st.h      	r3, (r8, 0x0)
 184:	d8681000 	ld.h      	r3, (r8, 0x0)
 188:	eb030fff 	cmphsi      	r3, 4096
 18c:	0c04      	bf      	0x194	// 194 <lmac_test_txskb_init+0x194>
 18e:	3300      	movi      	r3, 0
 190:	dc681000 	st.h      	r3, (r8, 0x0)
 194:	1495      	pop      	r4-r8, r15
 196:	c5838021 	divu      	r1, r3, r12
 19a:	7c70      	mult      	r1, r12
 19c:	60c6      	subu      	r3, r1
 19e:	60d0      	addu      	r3, r4
 1a0:	d8630028 	ld.b      	r3, (r3, 0x28)
 1a4:	a260      	st.b      	r3, (r2, 0x0)
 1a6:	2200      	addi      	r2, 1
 1a8:	076a      	br      	0x7c	// 7c <lmac_test_txskb_init+0x7c>
 1aa:	e4632004 	andi      	r3, r3, 4
 1ae:	e903000b 	bez      	r3, 0x1c4	// 1c4 <lmac_test_txskb_init+0x1c4>
 1b2:	3206      	movi      	r2, 6
 1b4:	e42508c1 	addi      	r1, r5, 2242
 1b8:	1017      	lrw      	r0, 0x0	// 214 <memcpy+0x214>
 1ba:	e0000000 	bsr      	0x0	// 0 <memcpy>
 1be:	d865089c 	ld.b      	r3, (r5, 0x89c)
 1c2:	0793      	br      	0xe8	// e8 <lmac_test_txskb_init+0xe8>
 1c4:	dc640028 	st.b      	r3, (r4, 0x28)
 1c8:	3310      	movi      	r3, 16
 1ca:	dc640029 	st.b      	r3, (r4, 0x29)
 1ce:	3320      	movi      	r3, 32
 1d0:	dc64002a 	st.b      	r3, (r4, 0x2a)
 1d4:	3330      	movi      	r3, 48
 1d6:	dc64002b 	st.b      	r3, (r4, 0x2b)
 1da:	3340      	movi      	r3, 64
 1dc:	dc64002c 	st.b      	r3, (r4, 0x2c)
 1e0:	3350      	movi      	r3, 80
 1e2:	dc64002d 	st.b      	r3, (r4, 0x2d)
 1e6:	07ec      	br      	0x1be	// 1be <lmac_test_txskb_init+0x1be>
 1e8:	d8250308 	ld.b      	r1, (r5, 0x308)
 1ec:	3301      	movi      	r3, 1
 1ee:	70c4      	lsl      	r3, r1
 1f0:	2b00      	subi      	r3, 1
 1f2:	4361      	lsli      	r3, r3, 1
 1f4:	e463201e 	andi      	r3, r3, 30
 1f8:	6cc8      	or      	r3, r2
 1fa:	0792      	br      	0x11e	// 11e <lmac_test_txskb_init+0x11e>
 1fc:	2200      	addi      	r2, 1
 1fe:	dc481000 	st.h      	r2, (r8, 0x0)
 202:	07c1      	br      	0x184	// 1d0 <lmac_test_txskb_init+0x1d0>
	...
 210:	fff551a0 	.long	0xfff551a0
 214:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_test_task:

00000000 <lmac_test_task>:
   0:	14d5      	push      	r4-r8, r15
   2:	1422      	subi      	r14, r14, 8
   4:	3037      	movi      	r0, 55
   6:	e0000000 	bsr      	0x0	// 0 <dev_get>
   a:	ea880043 	lrw      	r8, 0x0	// 114 <lmac_test_task+0x114>
   e:	6d43      	mov      	r5, r0
  10:	6d23      	mov      	r4, r8
  12:	12e2      	lrw      	r7, 0x0	// 118 <lmac_test_task+0x118>
  14:	d8680000 	ld.b      	r3, (r8, 0x0)
  18:	e4632001 	andi      	r3, r3, 1
  1c:	e9030004 	bez      	r3, 0x24	// 24 <lmac_test_task+0x24>
  20:	1402      	addi      	r14, r14, 8
  22:	1495      	pop      	r4-r8, r15
  24:	d86709e2 	ld.b      	r3, (r7, 0x9e2)
  28:	e4632008 	andi      	r3, r3, 8
  2c:	e923000e 	bnez      	r3, 0x48	// 48 <lmac_test_task+0x48>
  30:	84c1      	ld.b      	r6, (r4, 0x1)
  32:	e4c62004 	andi      	r6, r6, 4
  36:	e926005d 	bnez      	r6, 0xf0	// f0 <lmac_test_task+0xf0>
  3a:	9408      	ld.w      	r0, (r4, 0x20)
  3c:	e9000038 	bez      	r0, 0xac	// ac <lmac_test_task+0xac>
  40:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
  44:	b4c8      	st.w      	r6, (r4, 0x20)
  46:	0433      	br      	0xac	// ac <lmac_test_task+0xac>
  48:	3206      	movi      	r2, 6
  4a:	1135      	lrw      	r1, 0x0	// 11c <lmac_test_task+0x11c>
  4c:	1115      	lrw      	r0, 0x0	// 120 <lmac_test_task+0x120>
  4e:	e0000000 	bsr      	0x0	// 0 <memcpy>
  52:	3001      	movi      	r0, 1
  54:	e0000000 	bsr      	0x0	// 0 <skbpool_freesize>
  58:	eb0087ff 	cmphsi      	r0, 34816
  5c:	0fea      	bf      	0x30	// 30 <lmac_test_task+0x30>
  5e:	3001      	movi      	r0, 1
  60:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
  64:	d8041020 	ld.h      	r0, (r4, 0x40)
  68:	e4000137 	addi      	r0, r0, 312
  6c:	e0000000 	bsr      	0x0	// 0 <alloc_tx_skb>
  70:	6d83      	mov      	r6, r0
  72:	e900ffdf 	bez      	r0, 0x30	// 30 <lmac_test_task+0x30>
  76:	e0000000 	bsr      	0x0	// 0 <lmac_test_task>
  7a:	9760      	ld.w      	r3, (r7, 0x0)
  7c:	6c5b      	mov      	r1, r6
  7e:	9346      	ld.w      	r2, (r3, 0x18)
  80:	9300      	ld.w      	r0, (r3, 0x0)
  82:	7bc9      	jsr      	r2
  84:	e900ffe7 	bez      	r0, 0x52	// 52 <lmac_test_task+0x52>
  88:	6c1b      	mov      	r0, r6
  8a:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
  8e:	07e2      	br      	0x52	// 52 <lmac_test_task+0x52>
  90:	9468      	ld.w      	r3, (r4, 0x20)
  92:	e903000d 	bez      	r3, 0xac	// ac <lmac_test_task+0xac>
  96:	9367      	ld.w      	r3, (r3, 0x1c)
  98:	3101      	movi      	r1, 1
  9a:	6c3b      	mov      	r0, r14
  9c:	b860      	st.w      	r3, (r14, 0x0)
  9e:	b8c1      	st.w      	r6, (r14, 0x4)
  a0:	e0000000 	bsr      	0x0	// 0 <lmac_rx_data_queue_put>
  a4:	e0000000 	bsr      	0x0	// 0 <lmac_rx_data_queue_count>
  a8:	383f      	cmplti      	r0, 32
  aa:	0bf3      	bt      	0x90	// 90 <lmac_test_task+0x90>
  ac:	8461      	ld.b      	r3, (r4, 0x1)
  ae:	e4632008 	andi      	r3, r3, 8
  b2:	e9030022 	bez      	r3, 0xf6	// f6 <lmac_test_task+0xf6>
  b6:	e9050020 	bez      	r5, 0xf6	// f6 <lmac_test_task+0xf6>
  ba:	6c17      	mov      	r0, r5
  bc:	e0000000 	bsr      	0x0	// 0 <spi_nor_open>
  c0:	6c17      	mov      	r0, r5
  c2:	9462      	ld.w      	r3, (r4, 0x8)
  c4:	9441      	ld.w      	r2, (r4, 0x4)
  c6:	3100      	movi      	r1, 0
  c8:	e0000000 	bsr      	0x0	// 0 <spi_nor_read>
  cc:	6c17      	mov      	r0, r5
  ce:	e0000000 	bsr      	0x0	// 0 <spi_nor_close>
  d2:	8461      	ld.b      	r3, (r4, 0x1)
  d4:	e463200c 	andi      	r3, r3, 12
  d8:	e923ff9e 	bnez      	r3, 0x14	// 14 <lmac_test_task+0x14>
  dc:	d86709e2 	ld.b      	r3, (r7, 0x9e2)
  e0:	e4632008 	andi      	r3, r3, 8
  e4:	e9230011 	bnez      	r3, 0x106	// 106 <lmac_test_task+0x106>
  e8:	300a      	movi      	r0, 10
  ea:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
  ee:	0793      	br      	0x14	// 14 <lmac_test_task+0x14>
  f0:	ea0605b4 	movi      	r6, 1460
  f4:	07d8      	br      	0xa4	// a4 <lmac_test_task+0xa4>
  f6:	9401      	ld.w      	r0, (r4, 0x4)
  f8:	e900ffed 	bez      	r0, 0xd2	// d2 <lmac_test_task+0xd2>
  fc:	e0000000 	bsr      	0x0	// 0 <_os_free>
 100:	3300      	movi      	r3, 0
 102:	b461      	st.w      	r3, (r4, 0x4)
 104:	07e7      	br      	0xd2	// d2 <lmac_test_task+0xd2>
 106:	3001      	movi      	r0, 1
 108:	e0000000 	bsr      	0x0	// 0 <skbpool_freesize>
 10c:	eb0087ff 	cmphsi      	r0, 34816
 110:	0fec      	bf      	0xe8	// e8 <lmac_test_task+0xe8>
 112:	0781      	br      	0x14	// 14 <lmac_test_task+0x14>
	...

Disassembly of section .text.lmac_test_temp_sensor_rd_hdl:

00000000 <lmac_test_temp_sensor_rd_hdl>:
   0:	14d0      	push      	r15
   2:	3002      	movi      	r0, 2
   4:	e0000000 	bsr      	0x0	// 0 <tsensor_meas>
   8:	1490      	pop      	r15

Disassembly of section .text.ft_att_delay:

00000000 <ft_att_delay>:
   0:	14d0      	push      	r15
   2:	3005      	movi      	r0, 5
   4:	e0000000 	bsr      	0x0	// 0 <os_sleep_us>
   8:	1490      	pop      	r15

Disassembly of section .text.ft_att1_write:

00000000 <ft_att1_write>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	3101      	movi      	r1, 1
   6:	301f      	movi      	r0, 31
   8:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
   c:	3101      	movi      	r1, 1
   e:	301e      	movi      	r0, 30
  10:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  14:	3101      	movi      	r1, 1
  16:	3002      	movi      	r0, 2
  18:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  1c:	3101      	movi      	r1, 1
  1e:	3003      	movi      	r0, 3
  20:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  24:	3100      	movi      	r1, 0
  26:	301f      	movi      	r0, 31
  28:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  2c:	3100      	movi      	r1, 0
  2e:	301e      	movi      	r0, 30
  30:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  34:	3100      	movi      	r1, 0
  36:	3002      	movi      	r0, 2
  38:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  3c:	3100      	movi      	r1, 0
  3e:	3003      	movi      	r0, 3
  40:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  44:	6110      	addu      	r4, r4
  46:	e0000000 	bsr      	0x0	// 0 <ft_att1_write>
  4a:	7510      	zextb      	r4, r4
  4c:	3505      	movi      	r5, 5
  4e:	c4a44081 	asr      	r1, r4, r5
  52:	e4212001 	andi      	r1, r1, 1
  56:	3003      	movi      	r0, 3
  58:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  5c:	3101      	movi      	r1, 1
  5e:	3002      	movi      	r0, 2
  60:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  64:	e0000000 	bsr      	0x0	// 0 <ft_att1_write>
  68:	3100      	movi      	r1, 0
  6a:	3002      	movi      	r0, 2
  6c:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  70:	e0000000 	bsr      	0x0	// 0 <ft_att1_write>
  74:	3300      	movi      	r3, 0
  76:	2d00      	subi      	r5, 1
  78:	2b00      	subi      	r3, 1
  7a:	64d6      	cmpne      	r5, r3
  7c:	0be9      	bt      	0x4e	// 4e <ft_att1_write+0x4e>
  7e:	3101      	movi      	r1, 1
  80:	301f      	movi      	r0, 31
  82:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  86:	e0000000 	bsr      	0x0	// 0 <ft_att1_write>
  8a:	3100      	movi      	r1, 0
  8c:	301f      	movi      	r0, 31
  8e:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  92:	e0000000 	bsr      	0x0	// 0 <ft_att1_write>
  96:	1492      	pop      	r4-r5, r15

Disassembly of section .text.ft_att2_write:

00000000 <ft_att2_write>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	3101      	movi      	r1, 1
   6:	301f      	movi      	r0, 31
   8:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
   c:	3101      	movi      	r1, 1
   e:	301e      	movi      	r0, 30
  10:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  14:	3101      	movi      	r1, 1
  16:	3002      	movi      	r0, 2
  18:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  1c:	3101      	movi      	r1, 1
  1e:	3003      	movi      	r0, 3
  20:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  24:	3100      	movi      	r1, 0
  26:	301f      	movi      	r0, 31
  28:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  2c:	3100      	movi      	r1, 0
  2e:	301e      	movi      	r0, 30
  30:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  34:	3100      	movi      	r1, 0
  36:	3002      	movi      	r0, 2
  38:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  3c:	3100      	movi      	r1, 0
  3e:	3003      	movi      	r0, 3
  40:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  44:	6110      	addu      	r4, r4
  46:	e0000000 	bsr      	0x0	// 0 <ft_att2_write>
  4a:	7510      	zextb      	r4, r4
  4c:	3505      	movi      	r5, 5
  4e:	c4a44081 	asr      	r1, r4, r5
  52:	e4212001 	andi      	r1, r1, 1
  56:	3003      	movi      	r0, 3
  58:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  5c:	3101      	movi      	r1, 1
  5e:	3002      	movi      	r0, 2
  60:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  64:	e0000000 	bsr      	0x0	// 0 <ft_att2_write>
  68:	3100      	movi      	r1, 0
  6a:	3002      	movi      	r0, 2
  6c:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  70:	e0000000 	bsr      	0x0	// 0 <ft_att2_write>
  74:	3300      	movi      	r3, 0
  76:	2d00      	subi      	r5, 1
  78:	2b00      	subi      	r3, 1
  7a:	64d6      	cmpne      	r5, r3
  7c:	0be9      	bt      	0x4e	// 4e <ft_att2_write+0x4e>
  7e:	3101      	movi      	r1, 1
  80:	301e      	movi      	r0, 30
  82:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  86:	e0000000 	bsr      	0x0	// 0 <ft_att2_write>
  8a:	3100      	movi      	r1, 0
  8c:	301e      	movi      	r0, 30
  8e:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
  92:	e0000000 	bsr      	0x0	// 0 <ft_att2_write>
  96:	1492      	pop      	r4-r5, r15

Disassembly of section .text.atcmd_reg_rd_hdl:

00000000 <atcmd_reg_rd_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_reg_rd_hdl+0x12>
   8:	1013      	lrw      	r0, 0x0	// 54 <atcmd_printf+0x54>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	e0000000 	bsr      	0x0	// 0 <os_atoh>
  18:	33e0      	movi      	r3, 224
  1a:	4378      	lsli      	r3, r3, 24
  1c:	584c      	addu      	r2, r0, r3
  1e:	ea232004 	movih      	r3, 8196
  22:	2311      	addi      	r3, 18
  24:	648c      	cmphs      	r3, r2
  26:	6d03      	mov      	r4, r0
  28:	0c08      	bf      	0x38	// 38 <atcmd_reg_rd_hdl+0x38>
  2a:	9060      	ld.w      	r3, (r0, 0x0)
  2c:	6c93      	mov      	r2, r4
  2e:	5d26      	addi      	r1, r5, 2
  30:	100a      	lrw      	r0, 0x0	// 58 <atcmd_reg_rd_hdl+0x58>
  32:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  36:	07ec      	br      	0xe	// e <atcmd_reg_rd_hdl+0xe>
  38:	eb00ffff 	cmphsi      	r0, 65536
  3c:	0806      	bt      	0x48	// 48 <atcmd_reg_rd_hdl+0x48>
  3e:	7401      	zexth      	r0, r0
  40:	e0000000 	bsr      	0x0	// 0 <ah_rf_reg_read>
  44:	6cc3      	mov      	r3, r0
  46:	07f3      	br      	0x2c	// 2c <atcmd_reg_rd_hdl+0x2c>
  48:	1065      	lrw      	r3, 0x0	// 5c <atcmd_reg_rd_hdl+0x5c>
  4a:	3200      	movi      	r2, 0
  4c:	2a00      	subi      	r2, 1
  4e:	b352      	st.w      	r2, (r3, 0x48)
  50:	1064      	lrw      	r3, 0xdeaddead	// 60 <atcmd_reg_rd_hdl+0x60>
  52:	07ed      	br      	0x2c	// 2c <atcmd_reg_rd_hdl+0x2c>
	...
  60:	deaddead 	.long	0xdeaddead

Disassembly of section .text.atcmd_reg_wt_hdl:

00000000 <atcmd_reg_wt_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	3a01      	cmphsi      	r2, 2
   4:	6d83      	mov      	r6, r0
   6:	6d47      	mov      	r5, r1
   8:	0806      	bt      	0x14	// 14 <atcmd_reg_wt_hdl+0x14>
   a:	1016      	lrw      	r0, 0x0	// 60 <atcmd_reg_wt_hdl+0x60>
   c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  10:	3000      	movi      	r0, 0
  12:	1493      	pop      	r4-r6, r15
  14:	9100      	ld.w      	r0, (r1, 0x0)
  16:	e0000000 	bsr      	0x0	// 0 <os_atoh>
  1a:	6d03      	mov      	r4, r0
  1c:	9501      	ld.w      	r0, (r5, 0x4)
  1e:	e0000000 	bsr      	0x0	// 0 <os_atoh>
  22:	33e0      	movi      	r3, 224
  24:	4378      	lsli      	r3, r3, 24
  26:	5c4c      	addu      	r2, r4, r3
  28:	ea232004 	movih      	r3, 8196
  2c:	2311      	addi      	r3, 18
  2e:	648c      	cmphs      	r3, r2
  30:	6d43      	mov      	r5, r0
  32:	0c09      	bf      	0x44	// 44 <atcmd_reg_wt_hdl+0x44>
  34:	b400      	st.w      	r0, (r4, 0x0)
  36:	6cd7      	mov      	r3, r5
  38:	6c93      	mov      	r2, r4
  3a:	5e26      	addi      	r1, r6, 2
  3c:	100a      	lrw      	r0, 0x0	// 64 <atcmd_reg_wt_hdl+0x64>
  3e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  42:	07e7      	br      	0x10	// 10 <atcmd_reg_wt_hdl+0x10>
  44:	eb04ffff 	cmphsi      	r4, 65536
  48:	0806      	bt      	0x54	// 54 <atcmd_reg_wt_hdl+0x54>
  4a:	7441      	zexth      	r1, r0
  4c:	7411      	zexth      	r0, r4
  4e:	e0000000 	bsr      	0x0	// 0 <ah_rf_reg_write>
  52:	07f2      	br      	0x36	// 36 <atcmd_reg_wt_hdl+0x36>
  54:	1065      	lrw      	r3, 0x0	// 68 <atcmd_reg_wt_hdl+0x68>
  56:	3200      	movi      	r2, 0
  58:	2a00      	subi      	r2, 1
  5a:	b352      	st.w      	r2, (r3, 0x48)
  5c:	07ed      	br      	0x36	// 36 <atcmd_reg_wt_hdl+0x36>
	...

Disassembly of section .text.atcmd_test_start_hdl:

00000000 <atcmd_test_start_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_test_start_hdl+0x12>
   8:	1018      	lrw      	r0, 0x0	// 68 <atcmd_printf+0x68>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	1057      	lrw      	r2, 0x0	// 6c <atcmd_test_start_hdl+0x6c>
  14:	6d4b      	mov      	r5, r2
  16:	9260      	ld.w      	r3, (r2, 0x0)
  18:	e9030019 	bez      	r3, 0x4a	// 4a <atcmd_test_start_hdl+0x4a>
  1c:	9140      	ld.w      	r2, (r1, 0x0)
  1e:	8240      	ld.b      	r2, (r2, 0x0)
  20:	eb420030 	cmpnei      	r2, 48
  24:	0c0b      	bf      	0x3a	// 3a <atcmd_test_start_hdl+0x3a>
  26:	eb42003f 	cmpnei      	r2, 63
  2a:	0c10      	bf      	0x4a	// 4a <atcmd_test_start_hdl+0x4a>
  2c:	834a      	ld.b      	r2, (r3, 0xa)
  2e:	3100      	movi      	r1, 0
  30:	c4415c00 	ins      	r2, r1, 0, 0
  34:	a34a      	st.b      	r2, (r3, 0xa)
  36:	3001      	movi      	r0, 1
  38:	0407      	br      	0x46	// 46 <atcmd_test_start_hdl+0x46>
  3a:	834a      	ld.b      	r2, (r3, 0xa)
  3c:	3101      	movi      	r1, 1
  3e:	c4415c00 	ins      	r2, r1, 0, 0
  42:	a34a      	st.b      	r2, (r3, 0xa)
  44:	3000      	movi      	r0, 0
  46:	e0000000 	bsr      	0x0	// 0 <atcmd_test_start_hdl>
  4a:	d86509e2 	ld.b      	r3, (r5, 0x9e2)
  4e:	e4632002 	andi      	r3, r3, 2
  52:	3b40      	cmpnei      	r3, 0
  54:	1047      	lrw      	r2, 0x0	// 70 <atcmd_test_start_hdl+0x70>
  56:	1068      	lrw      	r3, 0x0	// 74 <atcmd_test_start_hdl+0x74>
  58:	c4430c20 	incf      	r2, r3, 0
  5c:	5c26      	addi      	r1, r4, 2
  5e:	1007      	lrw      	r0, 0x0	// 78 <atcmd_test_start_hdl+0x78>
  60:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  64:	07d5      	br      	0xe	// e <atcmd_test_start_hdl+0xe>
	...

Disassembly of section .text.atcmd_tx_dst_addr_hdl:

00000000 <atcmd_tx_dst_addr_hdl>:
   0:	14d1      	push      	r4, r15
   2:	1424      	subi      	r14, r14, 16
   4:	6d03      	mov      	r4, r0
   6:	e9220008 	bnez      	r2, 0x16	// 16 <atcmd_tx_dst_addr_hdl+0x16>
   a:	1013      	lrw      	r0, 0x0	// 54 <atcmd_printf+0x54>
   c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  10:	3000      	movi      	r0, 0
  12:	1404      	addi      	r14, r14, 16
  14:	1491      	pop      	r4, r15
  16:	9100      	ld.w      	r0, (r1, 0x0)
  18:	8060      	ld.b      	r3, (r0, 0x0)
  1a:	eb43003f 	cmpnei      	r3, 63
  1e:	0c04      	bf      	0x26	// 26 <atcmd_tx_dst_addr_hdl+0x26>
  20:	102e      	lrw      	r1, 0x0	// 58 <atcmd_tx_dst_addr_hdl+0x58>
  22:	e0000000 	bsr      	0x0	// 0 <str2mac>
  26:	102e      	lrw      	r1, 0x0	// 5c <atcmd_tx_dst_addr_hdl+0x5c>
  28:	d801002d 	ld.b      	r0, (r1, 0x2d)
  2c:	d8610029 	ld.b      	r3, (r1, 0x29)
  30:	d8410028 	ld.b      	r2, (r1, 0x28)
  34:	b803      	st.w      	r0, (r14, 0xc)
  36:	d801002c 	ld.b      	r0, (r1, 0x2c)
  3a:	b802      	st.w      	r0, (r14, 0x8)
  3c:	d801002b 	ld.b      	r0, (r1, 0x2b)
  40:	b801      	st.w      	r0, (r14, 0x4)
  42:	d821002a 	ld.b      	r1, (r1, 0x2a)
  46:	b820      	st.w      	r1, (r14, 0x0)
  48:	5c26      	addi      	r1, r4, 2
  4a:	1006      	lrw      	r0, 0x0	// 60 <atcmd_tx_dst_addr_hdl+0x60>
  4c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  50:	07e0      	br      	0x10	// 10 <atcmd_tx_dst_addr_hdl+0x10>
	...

Disassembly of section .text.atcmd_tx_fc_hdl:

00000000 <atcmd_tx_fc_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_fc_hdl+0x12>
   8:	100a      	lrw      	r0, 0x0	// 30 <atcmd_printf+0x30>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1088      	lrw      	r4, 0x0	// 34 <atcmd_tx_fc_hdl+0x34>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c04      	bf      	0x24	// 24 <os_atoh+0x24>
  1e:	e0000000 	bsr      	0x0	// 0 <os_atoh>
  22:	ac12      	st.h      	r0, (r4, 0x24)
  24:	8c52      	ld.h      	r2, (r4, 0x24)
  26:	5d26      	addi      	r1, r5, 2
  28:	1004      	lrw      	r0, 0x0	// 38 <atcmd_tx_fc_hdl+0x38>
  2a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  2e:	07f0      	br      	0xe	// e <atcmd_tx_fc_hdl+0xe>
	...

Disassembly of section .text.atcmd_tx_flags_hdl:

00000000 <atcmd_tx_flags_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_flags_hdl+0x12>
   8:	100a      	lrw      	r0, 0x0	// 30 <atcmd_printf+0x30>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1088      	lrw      	r4, 0x0	// 34 <atcmd_tx_flags_hdl+0x34>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c04      	bf      	0x24	// 24 <os_atoh+0x24>
  1e:	e0000000 	bsr      	0x0	// 0 <os_atoh>
  22:	b40f      	st.w      	r0, (r4, 0x3c)
  24:	944f      	ld.w      	r2, (r4, 0x3c)
  26:	5d26      	addi      	r1, r5, 2
  28:	1004      	lrw      	r0, 0x0	// 38 <atcmd_tx_flags_hdl+0x38>
  2a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  2e:	07f0      	br      	0xe	// e <atcmd_tx_flags_hdl+0xe>
	...

Disassembly of section .text.atcmd_tx_len_hdl:

00000000 <atcmd_tx_len_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_len_hdl+0x12>
   8:	100e      	lrw      	r0, 0x0	// 40 <atcmd_printf+0x40>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108c      	lrw      	r4, 0x0	// 44 <atcmd_tx_len_hdl+0x44>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c07      	bf      	0x2a	// 2a <atoi+0x2a>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	e960000b 	blsz      	r0, 0x38	// 38 <atcmd_tx_len_hdl+0x38>
  26:	dc041020 	st.h      	r0, (r4, 0x40)
  2a:	d8441020 	ld.h      	r2, (r4, 0x40)
  2e:	5d26      	addi      	r1, r5, 2
  30:	1006      	lrw      	r0, 0x0	// 48 <atcmd_tx_len_hdl+0x48>
  32:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  36:	07ec      	br      	0xe	// e <atcmd_tx_len_hdl+0xe>
  38:	3300      	movi      	r3, 0
  3a:	2b01      	subi      	r3, 2
  3c:	b472      	st.w      	r3, (r4, 0x48)
  3e:	07f6      	br      	0x2a	// 2a <atcmd_tx_len_hdl+0x2a>
	...

Disassembly of section .text.atcmd_tx_type_hdl:

00000000 <atcmd_tx_type_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_type_hdl+0x12>
   8:	1203      	lrw      	r0, 0x0	// 114 <atcmd_printf+0x114>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9160      	ld.w      	r3, (r1, 0x0)
  14:	1281      	lrw      	r4, 0x0	// 118 <atcmd_tx_type_hdl+0x118>
  16:	8360      	ld.b      	r3, (r3, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c23      	bf      	0x62	// 62 <atcmd_tx_type_hdl+0x62>
  1e:	eb430054 	cmpnei      	r3, 84
  22:	0c51      	bf      	0xc4	// c4 <atcmd_tx_type_hdl+0xc4>
  24:	eb030054 	cmphsi      	r3, 85
  28:	080b      	bt      	0x3e	// 3e <atcmd_tx_type_hdl+0x3e>
  2a:	eb43004e 	cmpnei      	r3, 78
  2e:	0c11      	bf      	0x50	// 50 <atcmd_tx_type_hdl+0x50>
  30:	eb430053 	cmpnei      	r3, 83
  34:	0c20      	bf      	0x74	// 74 <atcmd_tx_type_hdl+0x74>
  36:	3300      	movi      	r3, 0
  38:	2b00      	subi      	r3, 1
  3a:	b472      	st.w      	r3, (r4, 0x48)
  3c:	0413      	br      	0x62	// 62 <atcmd_tx_type_hdl+0x62>
  3e:	eb430073 	cmpnei      	r3, 115
  42:	0c19      	bf      	0x74	// 74 <atcmd_tx_type_hdl+0x74>
  44:	eb430074 	cmpnei      	r3, 116
  48:	0c3e      	bf      	0xc4	// c4 <atcmd_tx_type_hdl+0xc4>
  4a:	eb43006e 	cmpnei      	r3, 110
  4e:	0bf4      	bt      	0x36	// 36 <atcmd_tx_type_hdl+0x36>
  50:	d8640042 	ld.b      	r3, (r4, 0x42)
  54:	3200      	movi      	r2, 0
  56:	c4625c21 	ins      	r3, r2, 2, 1
  5a:	dc640042 	st.b      	r3, (r4, 0x42)
  5e:	e0000000 	bsr      	0x0	// 0 <ah_wphy_tx_norm_mode_cfg>
  62:	d8440042 	ld.b      	r2, (r4, 0x42)
  66:	c4225442 	zext      	r2, r2, 2, 1
  6a:	5d26      	addi      	r1, r5, 2
  6c:	110c      	lrw      	r0, 0x0	// 11c <atcmd_tx_type_hdl+0x11c>
  6e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  72:	07ce      	br      	0xe	// e <atcmd_tx_type_hdl+0xe>
  74:	d8640042 	ld.b      	r3, (r4, 0x42)
  78:	3201      	movi      	r2, 1
  7a:	c4625c21 	ins      	r3, r2, 2, 1
  7e:	dc640042 	st.b      	r3, (r4, 0x42)
  82:	74cc      	zextb      	r3, r3
  84:	e4432018 	andi      	r2, r3, 24
  88:	e9220007 	bnez      	r2, 0x96	// 96 <atcmd_tx_type_hdl+0x96>
  8c:	3202      	movi      	r2, 2
  8e:	c4625c23 	ins      	r3, r2, 4, 3
  92:	dc640042 	st.b      	r3, (r4, 0x42)
  96:	d8641021 	ld.h      	r3, (r4, 0x42)
  9a:	ea023fe0 	movi      	r2, 16352
  9e:	688c      	and      	r2, r3
  a0:	e9220007 	bnez      	r2, 0xae	// ae <atcmd_tx_type_hdl+0xae>
  a4:	3201      	movi      	r2, 1
  a6:	c4625d05 	ins      	r3, r2, 13, 5
  aa:	dc641021 	st.h      	r3, (r4, 0x42)
  ae:	d8241021 	ld.h      	r1, (r4, 0x42)
  b2:	d8040042 	ld.b      	r0, (r4, 0x42)
  b6:	c4a155a1 	zext      	r1, r1, 13, 5
  ba:	c4605480 	zext      	r0, r0, 4, 3
  be:	e0000000 	bsr      	0x0	// 0 <ah_wphy_tx_sine_mode_cfg>
  c2:	07d0      	br      	0x62	// 62 <atcmd_tx_type_hdl+0x62>
  c4:	d8640042 	ld.b      	r3, (r4, 0x42)
  c8:	3202      	movi      	r2, 2
  ca:	c4625c21 	ins      	r3, r2, 2, 1
  ce:	dc640042 	st.b      	r3, (r4, 0x42)
  d2:	74cc      	zextb      	r3, r3
  d4:	e4232018 	andi      	r1, r3, 24
  d8:	e9210006 	bnez      	r1, 0xe4	// e4 <atcmd_tx_type_hdl+0xe4>
  dc:	c4625c23 	ins      	r3, r2, 4, 3
  e0:	dc640042 	st.b      	r3, (r4, 0x42)
  e4:	d8641021 	ld.h      	r3, (r4, 0x42)
  e8:	ea023fe0 	movi      	r2, 16352
  ec:	688c      	and      	r2, r3
  ee:	e9220007 	bnez      	r2, 0xfc	// fc <atcmd_tx_type_hdl+0xfc>
  f2:	3201      	movi      	r2, 1
  f4:	c4625d05 	ins      	r3, r2, 13, 5
  f8:	dc641021 	st.h      	r3, (r4, 0x42)
  fc:	d8241021 	ld.h      	r1, (r4, 0x42)
 100:	d8040042 	ld.b      	r0, (r4, 0x42)
 104:	c4a155a1 	zext      	r1, r1, 13, 5
 108:	c4605480 	zext      	r0, r0, 4, 3
 10c:	e0000000 	bsr      	0x0	// 0 <ah_wphy_tx_tri_mode_cfg>
 110:	07a9      	br      	0x62	// 62 <atcmd_tx_type_hdl+0x62>
	...

Disassembly of section .text.atcmd_tx_pha_amp_hdl:

00000000 <atcmd_tx_pha_amp_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_pha_amp_hdl+0x12>
   8:	1102      	lrw      	r0, 0x0	// 90 <atcmd_printf+0x90>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1180      	lrw      	r4, 0x0	// 94 <atcmd_tx_pha_amp_hdl+0x94>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c1f      	bf      	0x5a	// 5a <atoi+0x5a>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	3803      	cmphsi      	r0, 4
  24:	0815      	bt      	0x4e	// 4e <atcmd_tx_pha_amp_hdl+0x4e>
  26:	d8640042 	ld.b      	r3, (r4, 0x42)
  2a:	c4605c23 	ins      	r3, r0, 4, 3
  2e:	dc640042 	st.b      	r3, (r4, 0x42)
  32:	d8040042 	ld.b      	r0, (r4, 0x42)
  36:	c4205443 	zext      	r3, r0, 2, 1
  3a:	3b41      	cmpnei      	r3, 1
  3c:	0c18      	bf      	0x6c	// 6c <atcmd_tx_pha_amp_hdl+0x6c>
  3e:	3b40      	cmpnei      	r3, 0
  40:	0c0b      	bf      	0x56	// 56 <atcmd_tx_pha_amp_hdl+0x56>
  42:	3b42      	cmpnei      	r3, 2
  44:	0c1d      	bf      	0x7e	// 7e <atcmd_tx_pha_amp_hdl+0x7e>
  46:	3300      	movi      	r3, 0
  48:	2b00      	subi      	r3, 1
  4a:	b472      	st.w      	r3, (r4, 0x48)
  4c:	0407      	br      	0x5a	// 5a <atcmd_tx_pha_amp_hdl+0x5a>
  4e:	3300      	movi      	r3, 0
  50:	2b02      	subi      	r3, 3
  52:	b472      	st.w      	r3, (r4, 0x48)
  54:	07ef      	br      	0x32	// 32 <atcmd_tx_pha_amp_hdl+0x32>
  56:	e0000000 	bsr      	0x0	// 0 <ah_wphy_tx_norm_mode_cfg>
  5a:	d8440042 	ld.b      	r2, (r4, 0x42)
  5e:	c4625482 	zext      	r2, r2, 4, 3
  62:	5d26      	addi      	r1, r5, 2
  64:	100d      	lrw      	r0, 0x0	// 98 <atcmd_tx_pha_amp_hdl+0x98>
  66:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  6a:	07d2      	br      	0xe	// e <atcmd_tx_pha_amp_hdl+0xe>
  6c:	d8241021 	ld.h      	r1, (r4, 0x42)
  70:	c4a155a1 	zext      	r1, r1, 13, 5
  74:	c4605480 	zext      	r0, r0, 4, 3
  78:	e0000000 	bsr      	0x0	// 0 <ah_wphy_tx_sine_mode_cfg>
  7c:	07ef      	br      	0x5a	// 5a <atcmd_tx_pha_amp_hdl+0x5a>
  7e:	d8241021 	ld.h      	r1, (r4, 0x42)
  82:	c4a155a1 	zext      	r1, r1, 13, 5
  86:	c4605480 	zext      	r0, r0, 4, 3
  8a:	e0000000 	bsr      	0x0	// 0 <ah_wphy_tx_tri_mode_cfg>
  8e:	07e6      	br      	0x5a	// 5a <atcmd_tx_pha_amp_hdl+0x5a>
	...

Disassembly of section .text.atcmd_tx_step_hdl:

00000000 <atcmd_tx_step_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_step_hdl+0x12>
   8:	1103      	lrw      	r0, 0x0	// 94 <atcmd_printf+0x94>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1181      	lrw      	r4, 0x0	// 98 <atcmd_tx_step_hdl+0x98>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c28      	bf      	0x6c	// 6c <atoi+0x6c>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	eb2001ff 	cmplti      	r0, 512
  26:	081a      	bt      	0x5a	// 5a <atcmd_tx_step_hdl+0x5a>
  28:	3300      	movi      	r3, 0
  2a:	2b02      	subi      	r3, 3
  2c:	b472      	st.w      	r3, (r4, 0x48)
  2e:	ea0001ff 	movi      	r0, 511
  32:	d8641021 	ld.h      	r3, (r4, 0x42)
  36:	c4605d05 	ins      	r3, r0, 13, 5
  3a:	7441      	zexth      	r1, r0
  3c:	740c      	zextb      	r0, r3
  3e:	dc641021 	st.h      	r3, (r4, 0x42)
  42:	c4205443 	zext      	r3, r0, 2, 1
  46:	3b41      	cmpnei      	r3, 1
  48:	0c1b      	bf      	0x7e	// 7e <atcmd_tx_step_hdl+0x7e>
  4a:	3b40      	cmpnei      	r3, 0
  4c:	0c0e      	bf      	0x68	// 68 <atcmd_tx_step_hdl+0x68>
  4e:	3b42      	cmpnei      	r3, 2
  50:	0c1c      	bf      	0x88	// 88 <atcmd_tx_step_hdl+0x88>
  52:	3300      	movi      	r3, 0
  54:	2b00      	subi      	r3, 1
  56:	b472      	st.w      	r3, (r4, 0x48)
  58:	040a      	br      	0x6c	// 6c <atcmd_tx_step_hdl+0x6c>
  5a:	e9a0ffec 	bhsz      	r0, 0x32	// 32 <atcmd_tx_step_hdl+0x32>
  5e:	3300      	movi      	r3, 0
  60:	2b01      	subi      	r3, 2
  62:	b472      	st.w      	r3, (r4, 0x48)
  64:	3000      	movi      	r0, 0
  66:	07e6      	br      	0x32	// 32 <atcmd_tx_step_hdl+0x32>
  68:	e0000000 	bsr      	0x0	// 0 <ah_wphy_tx_norm_mode_cfg>
  6c:	d8441021 	ld.h      	r2, (r4, 0x42)
  70:	c4a255a2 	zext      	r2, r2, 13, 5
  74:	5d26      	addi      	r1, r5, 2
  76:	100a      	lrw      	r0, 0x0	// 9c <atcmd_tx_step_hdl+0x9c>
  78:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  7c:	07c9      	br      	0xe	// e <atcmd_tx_step_hdl+0xe>
  7e:	c4605480 	zext      	r0, r0, 4, 3
  82:	e0000000 	bsr      	0x0	// 0 <ah_wphy_tx_sine_mode_cfg>
  86:	07f3      	br      	0x6c	// 6c <atcmd_tx_step_hdl+0x6c>
  88:	c4605480 	zext      	r0, r0, 4, 3
  8c:	e0000000 	bsr      	0x0	// 0 <ah_wphy_tx_tri_mode_cfg>
  90:	07ee      	br      	0x6c	// 6c <atcmd_tx_step_hdl+0x6c>
	...

Disassembly of section .text.atcmd_tx_cont_hdl:

00000000 <atcmd_tx_cont_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_cont_hdl+0x12>
   8:	1107      	lrw      	r0, 0x0	// a4 <atcmd_printf+0xa4>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9160      	ld.w      	r3, (r1, 0x0)
  14:	1185      	lrw      	r4, 0x0	// a8 <atcmd_tx_cont_hdl+0xa8>
  16:	8360      	ld.b      	r3, (r3, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c20      	bf      	0x5c	// 5c <atcmd_tx_cont_hdl+0x5c>
  1e:	eb430030 	cmpnei      	r3, 48
  22:	0c08      	bf      	0x32	// 32 <atcmd_tx_cont_hdl+0x32>
  24:	eb430031 	cmpnei      	r3, 49
  28:	0c28      	bf      	0x78	// 78 <atcmd_tx_cont_hdl+0x78>
  2a:	3300      	movi      	r3, 0
  2c:	2b00      	subi      	r3, 1
  2e:	b472      	st.w      	r3, (r4, 0x48)
  30:	0416      	br      	0x5c	// 5c <atcmd_tx_cont_hdl+0x5c>
  32:	d8640042 	ld.b      	r3, (r4, 0x42)
  36:	3100      	movi      	r1, 0
  38:	c4615c00 	ins      	r3, r1, 0, 0
  3c:	dc640042 	st.b      	r3, (r4, 0x42)
  40:	107b      	lrw      	r3, 0x0	// ac <atcmd_tx_cont_hdl+0xac>
  42:	d84309e2 	ld.b      	r2, (r3, 0x9e2)
  46:	c4415c04 	ins      	r2, r1, 4, 4
  4a:	dc4309e2 	st.b      	r2, (r3, 0x9e2)
  4e:	e0000000 	bsr      	0x0	// 0 <ah_wphy_cont_tx_disable>
  52:	1078      	lrw      	r3, 0x0	// b0 <atcmd_tx_cont_hdl+0xb0>
  54:	9340      	ld.w      	r2, (r3, 0x0)
  56:	9271      	ld.w      	r3, (r2, 0x44)
  58:	3bb4      	bseti      	r3, 20
  5a:	b271      	st.w      	r3, (r2, 0x44)
  5c:	d8640042 	ld.b      	r3, (r4, 0x42)
  60:	e4632001 	andi      	r3, r3, 1
  64:	3b40      	cmpnei      	r3, 0
  66:	1054      	lrw      	r2, 0x0	// b4 <atcmd_tx_cont_hdl+0xb4>
  68:	1074      	lrw      	r3, 0x0	// b8 <atcmd_tx_cont_hdl+0xb8>
  6a:	c4430c20 	incf      	r2, r3, 0
  6e:	5d26      	addi      	r1, r5, 2
  70:	1013      	lrw      	r0, 0x0	// bc <atcmd_tx_cont_hdl+0xbc>
  72:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  76:	07cc      	br      	0xe	// e <atcmd_tx_cont_hdl+0xe>
  78:	d8640042 	ld.b      	r3, (r4, 0x42)
  7c:	3101      	movi      	r1, 1
  7e:	c4615c00 	ins      	r3, r1, 0, 0
  82:	dc640042 	st.b      	r3, (r4, 0x42)
  86:	106a      	lrw      	r3, 0x0	// ac <atcmd_tx_cont_hdl+0xac>
  88:	d84309e2 	ld.b      	r2, (r3, 0x9e2)
  8c:	c4415c04 	ins      	r2, r1, 4, 4
  90:	dc4309e2 	st.b      	r2, (r3, 0x9e2)
  94:	e0000000 	bsr      	0x0	// 0 <ah_wphy_cont_tx_enable>
  98:	1066      	lrw      	r3, 0x0	// b0 <atcmd_tx_cont_hdl+0xb0>
  9a:	9340      	ld.w      	r2, (r3, 0x0)
  9c:	9271      	ld.w      	r3, (r2, 0x44)
  9e:	3b94      	bclri      	r3, 20
  a0:	07dd      	br      	0x5a	// 5a <atcmd_tx_cont_hdl+0x5a>
	...

Disassembly of section .text.atcmd_tx_start_hdl:

00000000 <atcmd_tx_start_hdl>:
   0:	14d0      	push      	r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_tx_start_hdl+0x10>
   6:	101d      	lrw      	r0, 0x0	// 78 <atcmd_printf+0x78>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	105b      	lrw      	r2, 0x0	// 7c <atcmd_tx_start_hdl+0x7c>
  14:	8320      	ld.b      	r1, (r3, 0x0)
  16:	eb41003f 	cmpnei      	r1, 63
  1a:	0c19      	bf      	0x4c	// 4c <atcmd_tx_start_hdl+0x4c>
  1c:	d86209e2 	ld.b      	r3, (r2, 0x9e2)
  20:	e5832002 	andi      	r12, r3, 2
  24:	e90c0026 	bez      	r12, 0x70	// 70 <atcmd_tx_start_hdl+0x70>
  28:	eb410030 	cmpnei      	r1, 48
  2c:	0c09      	bf      	0x3e	// 3e <atcmd_tx_start_hdl+0x3e>
  2e:	eb410031 	cmpnei      	r1, 49
  32:	0c1b      	bf      	0x68	// 68 <atcmd_tx_start_hdl+0x68>
  34:	3100      	movi      	r1, 0
  36:	1073      	lrw      	r3, 0x0	// 80 <atcmd_tx_start_hdl+0x80>
  38:	2901      	subi      	r1, 2
  3a:	b332      	st.w      	r1, (r3, 0x48)
  3c:	0408      	br      	0x4c	// 4c <atcmd_tx_start_hdl+0x4c>
  3e:	e46320f7 	andi      	r3, r3, 247
  42:	3100      	movi      	r1, 0
  44:	c4615c05 	ins      	r3, r1, 5, 5
  48:	dc6209e2 	st.b      	r3, (r2, 0x9e2)
  4c:	d86209e2 	ld.b      	r3, (r2, 0x9e2)
  50:	e4632008 	andi      	r3, r3, 8
  54:	3b40      	cmpnei      	r3, 0
  56:	104c      	lrw      	r2, 0x0	// 84 <atcmd_tx_start_hdl+0x84>
  58:	106c      	lrw      	r3, 0x0	// 88 <atcmd_tx_start_hdl+0x88>
  5a:	5826      	addi      	r1, r0, 2
  5c:	c4430c20 	incf      	r2, r3, 0
  60:	100b      	lrw      	r0, 0x0	// 8c <atcmd_printf+0x8c>
  62:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  66:	07d3      	br      	0xc	// c <atcmd_tx_start_hdl+0xc>
  68:	3101      	movi      	r1, 1
  6a:	c4615c03 	ins      	r3, r1, 3, 3
  6e:	07ea      	br      	0x42	// 42 <atcmd_tx_start_hdl+0x42>
  70:	3100      	movi      	r1, 0
  72:	1064      	lrw      	r3, 0x0	// 80 <atcmd_tx_start_hdl+0x80>
  74:	2900      	subi      	r1, 1
  76:	07e2      	br      	0x3a	// 3a <atcmd_tx_start_hdl+0x3a>
	...

Disassembly of section .text.atcmd_tx_trig_hdl:

00000000 <atcmd_tx_trig_hdl>:
   0:	14d4      	push      	r4-r7, r15
   2:	6d83      	mov      	r6, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_trig_hdl+0x12>
   8:	1104      	lrw      	r0, 0x0	// 98 <atcmd_printf+0x98>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1494      	pop      	r4-r7, r15
  12:	1183      	lrw      	r4, 0x0	// 9c <atcmd_tx_trig_hdl+0x9c>
  14:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
  18:	e4432002 	andi      	r2, r3, 2
  1c:	e9020038 	bez      	r2, 0x8c	// 8c <atcmd_tx_trig_hdl+0x8c>
  20:	9140      	ld.w      	r2, (r1, 0x0)
  22:	8240      	ld.b      	r2, (r2, 0x0)
  24:	eb420031 	cmpnei      	r2, 49
  28:	082c      	bt      	0x80	// 80 <atcmd_tx_trig_hdl+0x80>
  2a:	e46320f7 	andi      	r3, r3, 247
  2e:	3201      	movi      	r2, 1
  30:	c4625c05 	ins      	r3, r2, 5, 5
  34:	dc6409e2 	st.b      	r3, (r4, 0x9e2)
  38:	10fa      	lrw      	r7, 0x0	// a0 <atcmd_tx_trig_hdl+0xa0>
  3a:	d8071020 	ld.h      	r0, (r7, 0x40)
  3e:	209d      	addi      	r0, 158
  40:	e0000000 	bsr      	0x0	// 0 <alloc_tx_skb>
  44:	6d43      	mov      	r5, r0
  46:	e900fffa 	bez      	r0, 0x3a	// 3a <atcmd_tx_trig_hdl+0x3a>
  4a:	3206      	movi      	r2, 6
  4c:	1036      	lrw      	r1, 0x0	// a4 <atcmd_tx_trig_hdl+0xa4>
  4e:	1017      	lrw      	r0, 0x0	// a8 <atcmd_tx_trig_hdl+0xa8>
  50:	e0000000 	bsr      	0x0	// 0 <memcpy>
  54:	6c17      	mov      	r0, r5
  56:	e0000000 	bsr      	0x0	// 0 <atcmd_tx_trig_hdl>
  5a:	9460      	ld.w      	r3, (r4, 0x0)
  5c:	6c57      	mov      	r1, r5
  5e:	9346      	ld.w      	r2, (r3, 0x18)
  60:	9300      	ld.w      	r0, (r3, 0x0)
  62:	7bc9      	jsr      	r2
  64:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
  68:	e4632020 	andi      	r3, r3, 32
  6c:	3b40      	cmpnei      	r3, 0
  6e:	1050      	lrw      	r2, 0x0	// ac <atcmd_tx_trig_hdl+0xac>
  70:	1070      	lrw      	r3, 0x0	// b0 <atcmd_tx_trig_hdl+0xb0>
  72:	c4430c20 	incf      	r2, r3, 0
  76:	5e26      	addi      	r1, r6, 2
  78:	100f      	lrw      	r0, 0x0	// b4 <atcmd_tx_trig_hdl+0xb4>
  7a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  7e:	07c8      	br      	0xe	// e <atcmd_tx_trig_hdl+0xe>
  80:	3200      	movi      	r2, 0
  82:	c4625c05 	ins      	r3, r2, 5, 5
  86:	dc6409e2 	st.b      	r3, (r4, 0x9e2)
  8a:	07ed      	br      	0x64	// 64 <atcmd_tx_trig_hdl+0x64>
  8c:	1065      	lrw      	r3, 0x0	// a0 <atcmd_tx_trig_hdl+0xa0>
  8e:	3200      	movi      	r2, 0
  90:	2a00      	subi      	r2, 1
  92:	b352      	st.w      	r2, (r3, 0x48)
  94:	07e8      	br      	0x64	// 64 <atcmd_tx_trig_hdl+0x64>
	...

Disassembly of section .text.atcmd_tx_mcs_hdl:

00000000 <atcmd_tx_mcs_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_mcs_hdl+0x12>
   8:	100b      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1089      	lrw      	r4, 0x0	// 38 <atcmd_tx_mcs_hdl+0x38>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c05      	bf      	0x26	// 26 <atoi+0x26>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	dc040866 	st.b      	r0, (r4, 0x866)
  26:	d8440866 	ld.b      	r2, (r4, 0x866)
  2a:	5d26      	addi      	r1, r5, 2
  2c:	1004      	lrw      	r0, 0x0	// 3c <atcmd_tx_mcs_hdl+0x3c>
  2e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  32:	07ee      	br      	0xe	// e <atcmd_tx_mcs_hdl+0xe>
	...

Disassembly of section .text.atcmd_mcast_mcs_hdl:

00000000 <atcmd_mcast_mcs_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_mcast_mcs_hdl+0x12>
   8:	100b      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1089      	lrw      	r4, 0x0	// 38 <atcmd_mcast_mcs_hdl+0x38>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c05      	bf      	0x26	// 26 <atoi+0x26>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	dc040868 	st.b      	r0, (r4, 0x868)
  26:	d8440868 	ld.b      	r2, (r4, 0x868)
  2a:	5d26      	addi      	r1, r5, 2
  2c:	1004      	lrw      	r0, 0x0	// 3c <atcmd_mcast_mcs_hdl+0x3c>
  2e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  32:	07ee      	br      	0xe	// e <atcmd_mcast_mcs_hdl+0xe>
	...

Disassembly of section .text.atcmd_tx_mcs_max_hdl:

00000000 <atcmd_tx_mcs_max_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_mcs_max_hdl+0x12>
   8:	100b      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1089      	lrw      	r4, 0x0	// 38 <atcmd_tx_mcs_max_hdl+0x38>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c05      	bf      	0x26	// 26 <atoi+0x26>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	dc040864 	st.b      	r0, (r4, 0x864)
  26:	d8440864 	ld.b      	r2, (r4, 0x864)
  2a:	5d26      	addi      	r1, r5, 2
  2c:	1004      	lrw      	r0, 0x0	// 3c <atcmd_tx_mcs_max_hdl+0x3c>
  2e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  32:	07ee      	br      	0xe	// e <atcmd_tx_mcs_max_hdl+0xe>
	...

Disassembly of section .text.atcmd_tx_mcs_min_hdl:

00000000 <atcmd_tx_mcs_min_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_mcs_min_hdl+0x12>
   8:	100c      	lrw      	r0, 0x0	// 38 <atcmd_printf+0x38>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108a      	lrw      	r4, 0x0	// 3c <atcmd_tx_mcs_min_hdl+0x3c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c07      	bf      	0x2a	// 2a <atoi+0x2a>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	3807      	cmphsi      	r0, 8
  24:	0803      	bt      	0x2a	// 2a <atcmd_tx_mcs_min_hdl+0x2a>
  26:	dc040865 	st.b      	r0, (r4, 0x865)
  2a:	d8440865 	ld.b      	r2, (r4, 0x865)
  2e:	5d26      	addi      	r1, r5, 2
  30:	1004      	lrw      	r0, 0x0	// 40 <atcmd_tx_mcs_min_hdl+0x40>
  32:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  36:	07ec      	br      	0xe	// e <atcmd_tx_mcs_min_hdl+0xe>
	...

Disassembly of section .text.atcmd_ant_dual_hdl:

00000000 <atcmd_ant_dual_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_ant_dual_hdl+0x12>
   8:	1011      	lrw      	r0, 0x0	// 4c <atcmd_printf+0x4c>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108f      	lrw      	r4, 0x0	// 50 <atcmd_ant_dual_hdl+0x50>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c09      	bf      	0x2e	// 2e <atoi+0x2e>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	6c83      	mov      	r2, r0
  24:	3300      	movi      	r3, 0
  26:	3129      	movi      	r1, 41
  28:	9400      	ld.w      	r0, (r4, 0x0)
  2a:	e0000000 	bsr      	0x0	// 0 <lmac_ioctl>
  2e:	d8640875 	ld.b      	r3, (r4, 0x875)
  32:	e4632004 	andi      	r3, r3, 4
  36:	3b40      	cmpnei      	r3, 0
  38:	1047      	lrw      	r2, 0x0	// 54 <atcmd_ant_dual_hdl+0x54>
  3a:	1068      	lrw      	r3, 0x0	// 58 <atcmd_ant_dual_hdl+0x58>
  3c:	c4430c20 	incf      	r2, r3, 0
  40:	5d26      	addi      	r1, r5, 2
  42:	1007      	lrw      	r0, 0x0	// 5c <atcmd_ant_dual_hdl+0x5c>
  44:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  48:	07e3      	br      	0xe	// e <atcmd_ant_dual_hdl+0xe>
	...

Disassembly of section .text.atcmd_ant_ctrl_hdl:

00000000 <atcmd_ant_ctrl_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_ant_ctrl_hdl+0x12>
   8:	1018      	lrw      	r0, 0x0	// 68 <atcmd_printf+0x68>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1493      	pop      	r4-r6, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	10b6      	lrw      	r5, 0x0	// 6c <atcmd_ant_ctrl_hdl+0x6c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0818      	bt      	0x4c	// 4c <atcmd_ant_ctrl_hdl+0x4c>
  1e:	d8450876 	ld.b      	r2, (r5, 0x876)
  22:	74ca      	sextb      	r3, r2
  24:	e9a30008 	bhsz      	r3, 0x34	// 34 <atcmd_ant_ctrl_hdl+0x34>
  28:	e442207f 	andi      	r2, r2, 127
  2c:	5c26      	addi      	r1, r4, 2
  2e:	1011      	lrw      	r0, 0x0	// 70 <atcmd_ant_ctrl_hdl+0x70>
  30:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  34:	d8450877 	ld.b      	r2, (r5, 0x877)
  38:	74ca      	sextb      	r3, r2
  3a:	e9a3ffea 	bhsz      	r3, 0xe	// e <atcmd_ant_ctrl_hdl+0xe>
  3e:	e442207f 	andi      	r2, r2, 127
  42:	5c26      	addi      	r1, r4, 2
  44:	100c      	lrw      	r0, 0x0	// 74 <atcmd_ant_ctrl_hdl+0x74>
  46:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4a:	07e2      	br      	0xe	// e <atoi+0xe>
  4c:	e0000000 	bsr      	0x0	// 0 <atoi>
  50:	6c83      	mov      	r2, r0
  52:	6d83      	mov      	r6, r0
  54:	312a      	movi      	r1, 42
  56:	3300      	movi      	r3, 0
  58:	9500      	ld.w      	r0, (r5, 0x0)
  5a:	e0000000 	bsr      	0x0	// 0 <lmac_ioctl>
  5e:	6c9b      	mov      	r2, r6
  60:	5c26      	addi      	r1, r4, 2
  62:	1006      	lrw      	r0, 0x0	// 78 <atcmd_ant_ctrl_hdl+0x78>
  64:	07f1      	br      	0x46	// 46 <atcmd_ant_ctrl_hdl+0x46>
	...

Disassembly of section .text.atcmd_ant_auto_hdl:

00000000 <atcmd_ant_auto_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_ant_auto_hdl+0x12>
   8:	1012      	lrw      	r0, 0x0	// 50 <atcmd_printf+0x50>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1090      	lrw      	r4, 0x0	// 54 <atcmd_ant_auto_hdl+0x54>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	3840      	cmpnei      	r0, 0
  24:	d8640875 	ld.b      	r3, (r4, 0x875)
  28:	c4000502 	mvc      	r2
  2c:	c4625c03 	ins      	r3, r2, 3, 3
  30:	dc640875 	st.b      	r3, (r4, 0x875)
  34:	d8640875 	ld.b      	r3, (r4, 0x875)
  38:	e4632008 	andi      	r3, r3, 8
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1047      	lrw      	r2, 0x0	// 58 <atcmd_ant_auto_hdl+0x58>
  40:	1067      	lrw      	r3, 0x0	// 5c <atcmd_ant_auto_hdl+0x5c>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1006      	lrw      	r0, 0x0	// 60 <atcmd_ant_auto_hdl+0x60>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_ant_auto_hdl+0xe>
	...

Disassembly of section .text.atcmd_ant_def_hdl:

00000000 <atcmd_ant_def_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_ant_def_hdl+0x12>
   8:	1010      	lrw      	r0, 0x0	// 48 <atcmd_printf+0x48>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108e      	lrw      	r4, 0x0	// 4c <atcmd_ant_def_hdl+0x4c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	3840      	cmpnei      	r0, 0
  24:	d8640875 	ld.b      	r3, (r4, 0x875)
  28:	c4000502 	mvc      	r2
  2c:	c4625c04 	ins      	r3, r2, 4, 4
  30:	dc640875 	st.b      	r3, (r4, 0x875)
  34:	d8440875 	ld.b      	r2, (r4, 0x875)
  38:	c4825482 	zext      	r2, r2, 4, 4
  3c:	5d26      	addi      	r1, r5, 2
  3e:	1005      	lrw      	r0, 0x0	// 50 <atcmd_ant_def_hdl+0x50>
  40:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  44:	07e5      	br      	0xe	// e <atcmd_ant_def_hdl+0xe>
	...

Disassembly of section .text.atcmd_tx_bw_hdl:

00000000 <atcmd_tx_bw_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_bw_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_tx_bw_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0b      	bf      	0x32	// 32 <atoi+0x32>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	6c83      	mov      	r2, r0
  24:	e9600014 	blsz      	r0, 0x4c	// 4c <atcmd_tx_bw_hdl+0x4c>
  28:	3300      	movi      	r3, 0
  2a:	3103      	movi      	r1, 3
  2c:	9400      	ld.w      	r0, (r4, 0x0)
  2e:	e0000000 	bsr      	0x0	// 0 <lmac_ioctl>
  32:	d8440867 	ld.b      	r2, (r4, 0x867)
  36:	3302      	movi      	r3, 2
  38:	70c8      	lsl      	r3, r2
  3a:	3b28      	cmplti      	r3, 9
  3c:	3201      	movi      	r2, 1
  3e:	c4430c40 	inct      	r2, r3, 0
  42:	5d26      	addi      	r1, r5, 2
  44:	1007      	lrw      	r0, 0x0	// 60 <atcmd_tx_bw_hdl+0x60>
  46:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4a:	07e2      	br      	0xe	// e <atcmd_tx_bw_hdl+0xe>
  4c:	1066      	lrw      	r3, 0x0	// 64 <atcmd_tx_bw_hdl+0x64>
  4e:	3200      	movi      	r2, 0
  50:	2a00      	subi      	r2, 1
  52:	b352      	st.w      	r2, (r3, 0x48)
  54:	07ef      	br      	0x32	// 32 <atcmd_tx_bw_hdl+0x32>
	...

Disassembly of section .text.atcmd_mcast_bw_hdl:

00000000 <atcmd_mcast_bw_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_mcast_bw_hdl+0x10>
   6:	1101      	lrw      	r0, 0x0	// 88 <atcmd_printf+0x88>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1492      	pop      	r4-r5, r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	58a6      	addi      	r5, r0, 2
  14:	8340      	ld.b      	r2, (r3, 0x0)
  16:	eb42003f 	cmpnei      	r2, 63
  1a:	109d      	lrw      	r4, 0x0	// 8c <atcmd_mcast_bw_hdl+0x8c>
  1c:	0c11      	bf      	0x3e	// 3e <atcmd_mcast_bw_hdl+0x3e>
  1e:	6c0f      	mov      	r0, r3
  20:	e0000000 	bsr      	0x0	// 0 <atoi>
  24:	5863      	subi      	r3, r0, 1
  26:	3b01      	cmphsi      	r3, 2
  28:	6c83      	mov      	r2, r0
  2a:	081a      	bt      	0x5e	// 5e <atcmd_mcast_bw_hdl+0x5e>
  2c:	d864034a 	ld.b      	r3, (r4, 0x34a)
  30:	e4632001 	andi      	r3, r3, 1
  34:	3b40      	cmpnei      	r3, 0
  36:	64c3      	mvcv      	r3
  38:	2300      	addi      	r3, 1
  3a:	dc640869 	st.b      	r3, (r4, 0x869)
  3e:	d8440869 	ld.b      	r2, (r4, 0x869)
  42:	3a03      	cmphsi      	r2, 4
  44:	0808      	bt      	0x54	// 54 <atcmd_mcast_bw_hdl+0x54>
  46:	d864034a 	ld.b      	r3, (r4, 0x34a)
  4a:	e4632001 	andi      	r3, r3, 1
  4e:	3b40      	cmpnei      	r3, 0
  50:	6483      	mvcv      	r2
  52:	2200      	addi      	r2, 1
  54:	6c57      	mov      	r1, r5
  56:	100f      	lrw      	r0, 0x0	// 90 <atcmd_mcast_bw_hdl+0x90>
  58:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  5c:	07d8      	br      	0xc	// c <atcmd_mcast_bw_hdl+0xc>
  5e:	3844      	cmpnei      	r0, 4
  60:	0808      	bt      	0x70	// 70 <atcmd_mcast_bw_hdl+0x70>
  62:	d8640308 	ld.b      	r3, (r4, 0x308)
  66:	3b01      	cmphsi      	r3, 2
  68:	0c0a      	bf      	0x7c	// 7c <atcmd_mcast_bw_hdl+0x7c>
  6a:	dc440869 	st.b      	r2, (r4, 0x869)
  6e:	07e8      	br      	0x3e	// 3e <atcmd_mcast_bw_hdl+0x3e>
  70:	3848      	cmpnei      	r0, 8
  72:	0805      	bt      	0x7c	// 7c <atcmd_mcast_bw_hdl+0x7c>
  74:	d8640308 	ld.b      	r3, (r4, 0x308)
  78:	3b02      	cmphsi      	r3, 3
  7a:	07f7      	br      	0x68	// 68 <atcmd_mcast_bw_hdl+0x68>
  7c:	6c57      	mov      	r1, r5
  7e:	1006      	lrw      	r0, 0x0	// 94 <atcmd_mcast_bw_hdl+0x94>
  80:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  84:	07dd      	br      	0x3e	// 3e <atcmd_mcast_bw_hdl+0x3e>
	...

Disassembly of section .text.atcmd_lo_freq_hdl:

00000000 <atcmd_lo_freq_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d03      	mov      	r4, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_lo_freq_hdl+0x12>
   8:	1012      	lrw      	r0, 0x0	// 50 <atcmd_printf+0x50>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	8060      	ld.b      	r3, (r0, 0x0)
  16:	eb43003f 	cmpnei      	r3, 63
  1a:	0c0b      	bf      	0x30	// 30 <atoi+0x30>
  1c:	e0000000 	bsr      	0x0	// 0 <atoi>
  20:	6d43      	mov      	r5, r0
  22:	e0000000 	bsr      	0x0	// 0 <atcmd_lo_freq_hdl>
  26:	e920000f 	bnez      	r0, 0x44	// 44 <atcmd_lo_freq_hdl+0x44>
  2a:	6c17      	mov      	r0, r5
  2c:	e0000000 	bsr      	0x0	// 0 <lmac_lo_freq_set>
  30:	1069      	lrw      	r3, 0x0	// 54 <atcmd_lo_freq_hdl+0x54>
  32:	5c26      	addi      	r1, r4, 2
  34:	d84320ce 	ld.w      	r2, (r3, 0x338)
  38:	c4825762 	zext      	r2, r2, 27, 4
  3c:	1007      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
  3e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  42:	07e6      	br      	0xe	// e <atcmd_lo_freq_hdl+0xe>
  44:	1066      	lrw      	r3, 0x0	// 5c <atcmd_lo_freq_hdl+0x5c>
  46:	3200      	movi      	r2, 0
  48:	2a00      	subi      	r2, 1
  4a:	b352      	st.w      	r2, (r3, 0x48)
  4c:	07f2      	br      	0x30	// 30 <atcmd_lo_freq_hdl+0x30>
	...

Disassembly of section .text.atcmd_freq_list_hdl:

00000000 <atcmd_freq_list_hdl>:
   0:	14d6      	push      	r4-r9, r15
   2:	1428      	subi      	r14, r14, 32
   4:	6dc7      	mov      	r7, r1
   6:	6e0b      	mov      	r8, r2
   8:	e9220008 	bnez      	r2, 0x18	// 18 <atcmd_freq_list_hdl+0x18>
   c:	1106      	lrw      	r0, 0x0	// a4 <atcmd_printf+0xa4>
   e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  12:	3000      	movi      	r0, 0
  14:	1408      	addi      	r14, r14, 32
  16:	1496      	pop      	r4-r9, r15
  18:	9160      	ld.w      	r3, (r1, 0x0)
  1a:	8360      	ld.b      	r3, (r3, 0x0)
  1c:	eb43003f 	cmpnei      	r3, 63
  20:	0c21      	bf      	0x62	// 62 <atcmd_freq_list_hdl+0x62>
  22:	3400      	movi      	r4, 0
  24:	6d53      	mov      	r5, r4
  26:	ea090064 	movi      	r9, 100
  2a:	3c50      	cmpnei      	r4, 16
  2c:	0c13      	bf      	0x52	// 52 <atcmd_freq_list_hdl+0x52>
  2e:	d0870880 	ldr.w      	r0, (r7, r4 << 2)
  32:	e0000000 	bsr      	0x0	// 0 <atoi>
  36:	6d83      	mov      	r6, r0
  38:	e0000000 	bsr      	0x0	// 0 <atcmd_freq_list_hdl>
  3c:	e9200008 	bnez      	r0, 0x4c	// 4c <atcmd_freq_list_hdl+0x4c>
  40:	5d62      	addi      	r3, r5, 1
  42:	c5268046 	divs      	r6, r6, r9
  46:	d4ae0446 	str.h      	r6, (r14, r5 << 1)
  4a:	754d      	zexth      	r5, r3
  4c:	2400      	addi      	r4, 1
  4e:	6612      	cmpne      	r4, r8
  50:	0bed      	bt      	0x2a	// 2a <atcmd_freq_list_hdl+0x2a>
  52:	e9050019 	bez      	r5, 0x84	// 84 <atcmd_freq_list_hdl+0x84>
  56:	1075      	lrw      	r3, 0x0	// a8 <atcmd_freq_list_hdl+0xa8>
  58:	6c97      	mov      	r2, r5
  5a:	6c7b      	mov      	r1, r14
  5c:	9300      	ld.w      	r0, (r3, 0x0)
  5e:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_set_chanlist>
  62:	1013      	lrw      	r0, 0x0	// ac <atcmd_freq_list_hdl+0xac>
  64:	3500      	movi      	r5, 0
  66:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  6a:	6d17      	mov      	r4, r5
  6c:	10cf      	lrw      	r6, 0x0	// a8 <atcmd_freq_list_hdl+0xa8>
  6e:	10f1      	lrw      	r7, 0x0	// b0 <atcmd_freq_list_hdl+0xb0>
  70:	d8660378 	ld.b      	r3, (r6, 0x378)
  74:	64d1      	cmplt      	r4, r3
  76:	2517      	addi      	r5, 24
  78:	080b      	bt      	0x8e	// 8e <atcmd_freq_list_hdl+0x8e>
  7a:	100f      	lrw      	r0, 0x0	// b4 <atcmd_freq_list_hdl+0xb4>
  7c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  80:	100e      	lrw      	r0, 0x0	// b8 <atcmd_freq_list_hdl+0xb8>
  82:	07c6      	br      	0xe	// e <atcmd_freq_list_hdl+0xe>
  84:	106e      	lrw      	r3, 0x0	// bc <atcmd_freq_list_hdl+0xbc>
  86:	3200      	movi      	r2, 0
  88:	2a00      	subi      	r2, 1
  8a:	b352      	st.w      	r2, (r3, 0x48)
  8c:	07eb      	br      	0x62	// 62 <atcmd_freq_list_hdl+0x62>
  8e:	1067      	lrw      	r3, 0x0	// a8 <atcmd_freq_list_hdl+0xa8>
  90:	60d4      	addu      	r3, r5
  92:	6c53      	mov      	r1, r4
  94:	d843202a 	ld.w      	r2, (r3, 0xa8)
  98:	6c1f      	mov      	r0, r7
  9a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  9e:	2400      	addi      	r4, 1
  a0:	07e8      	br      	0x70	// 70 <atcmd_freq_list_hdl+0x70>
	...

Disassembly of section .text.atcmd_tx_pwr_auto_hdl:

00000000 <atcmd_tx_pwr_auto_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_pwr_auto_hdl+0x12>
   8:	1016      	lrw      	r0, 0x0	// 60 <atcmd_printf+0x60>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9160      	ld.w      	r3, (r1, 0x0)
  14:	1094      	lrw      	r4, 0x0	// 64 <atcmd_tx_pwr_auto_hdl+0x64>
  16:	8360      	ld.b      	r3, (r3, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0b      	bf      	0x32	// 32 <atcmd_tx_pwr_auto_hdl+0x32>
  1e:	eb430030 	cmpnei      	r3, 48
  22:	d8640338 	ld.b      	r3, (r4, 0x338)
  26:	0814      	bt      	0x4e	// 4e <atcmd_tx_pwr_auto_hdl+0x4e>
  28:	3200      	movi      	r2, 0
  2a:	c4625c00 	ins      	r3, r2, 0, 0
  2e:	dc640338 	st.b      	r3, (r4, 0x338)
  32:	d8640338 	ld.b      	r3, (r4, 0x338)
  36:	e4632001 	andi      	r3, r3, 1
  3a:	3b40      	cmpnei      	r3, 0
  3c:	104b      	lrw      	r2, 0x0	// 68 <atcmd_tx_pwr_auto_hdl+0x68>
  3e:	106c      	lrw      	r3, 0x0	// 6c <atcmd_tx_pwr_auto_hdl+0x6c>
  40:	c4430c20 	incf      	r2, r3, 0
  44:	5d26      	addi      	r1, r5, 2
  46:	100b      	lrw      	r0, 0x0	// 70 <atcmd_tx_pwr_auto_hdl+0x70>
  48:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4c:	07e1      	br      	0xe	// e <atcmd_tx_pwr_auto_hdl+0xe>
  4e:	3201      	movi      	r2, 1
  50:	c4625c00 	ins      	r3, r2, 0, 0
  54:	1008      	lrw      	r0, 0x0	// 74 <atcmd_tx_pwr_auto_hdl+0x74>
  56:	dc640338 	st.b      	r3, (r4, 0x338)
  5a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  5e:	07ea      	br      	0x32	// 32 <atcmd_tx_pwr_auto_hdl+0x32>
	...

Disassembly of section .text.atcmd_tx_pwr_max_hdl:

00000000 <atcmd_tx_pwr_max_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_pwr_max_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_tx_pwr_max_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c14      	bf      	0x44	// 44 <atoi+0x44>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	3825      	cmplti      	r0, 6
  24:	0c10      	bf      	0x44	// 44 <atcmd_tx_pwr_max_hdl+0x44>
  26:	d864036d 	ld.b      	r3, (r4, 0x36d)
  2a:	e463200c 	andi      	r3, r3, 12
  2e:	e9030009 	bez      	r3, 0x40	// 40 <atcmd_tx_pwr_max_hdl+0x40>
  32:	d86411b6 	ld.h      	r3, (r4, 0x36c)
  36:	c4605c85 	ins      	r3, r0, 9, 5
  3a:	dc6411b6 	st.h      	r3, (r4, 0x36c)
  3e:	0403      	br      	0x44	// 44 <atcmd_tx_pwr_max_hdl+0x44>
  40:	3822      	cmplti      	r0, 3
  42:	0ff8      	bf      	0x32	// 32 <atcmd_tx_pwr_max_hdl+0x32>
  44:	d84411b6 	ld.h      	r2, (r4, 0x36c)
  48:	c4a25522 	zext      	r2, r2, 9, 5
  4c:	5d26      	addi      	r1, r5, 2
  4e:	1005      	lrw      	r0, 0x0	// 60 <atcmd_tx_pwr_max_hdl+0x60>
  50:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  54:	07dd      	br      	0xe	// e <atcmd_tx_pwr_max_hdl+0xe>
	...

Disassembly of section .text.atcmd_tx_pwr_super_hdl:

00000000 <atcmd_tx_pwr_super_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_tx_pwr_super_hdl+0x10>
   6:	1104      	lrw      	r0, 0x0	// 94 <atcmd_printf+0x94>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1492      	pop      	r4-r5, r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	5886      	addi      	r4, r0, 2
  14:	8340      	ld.b      	r2, (r3, 0x0)
  16:	eb42003f 	cmpnei      	r2, 63
  1a:	11a0      	lrw      	r5, 0x0	// 98 <atcmd_tx_pwr_super_hdl+0x98>
  1c:	0814      	bt      	0x44	// 44 <atcmd_tx_pwr_super_hdl+0x44>
  1e:	d845036d 	ld.b      	r2, (r5, 0x36d)
  22:	c4425462 	zext      	r2, r2, 3, 2
  26:	6c53      	mov      	r1, r4
  28:	101d      	lrw      	r0, 0x0	// 9c <atcmd_tx_pwr_super_hdl+0x9c>
  2a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  2e:	d865036d 	ld.b      	r3, (r5, 0x36d)
  32:	e463200c 	andi      	r3, r3, 12
  36:	3b48      	cmpnei      	r3, 8
  38:	081e      	bt      	0x74	// 74 <atcmd_tx_pwr_super_hdl+0x74>
  3a:	6c53      	mov      	r1, r4
  3c:	1019      	lrw      	r0, 0x0	// a0 <atcmd_tx_pwr_super_hdl+0xa0>
  3e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  42:	07e5      	br      	0xc	// c <atcmd_tx_pwr_super_hdl+0xc>
  44:	6c0f      	mov      	r0, r3
  46:	e0000000 	bsr      	0x0	// 0 <atoi>
  4a:	3803      	cmphsi      	r0, 4
  4c:	080c      	bt      	0x64	// 64 <atcmd_tx_pwr_super_hdl+0x64>
  4e:	e4002003 	andi      	r0, r0, 3
  52:	d865036d 	ld.b      	r3, (r5, 0x36d)
  56:	c4605c22 	ins      	r3, r0, 3, 2
  5a:	c4605c24 	ins      	r3, r0, 5, 4
  5e:	dc65036d 	st.b      	r3, (r5, 0x36d)
  62:	07e6      	br      	0x2e	// 2e <atcmd_tx_pwr_super_hdl+0x2e>
  64:	d865036d 	ld.b      	r3, (r5, 0x36d)
  68:	e46320f3 	andi      	r3, r3, 243
  6c:	3200      	movi      	r2, 0
  6e:	c4625c24 	ins      	r3, r2, 5, 4
  72:	07f6      	br      	0x5e	// 5e <atcmd_tx_pwr_super_hdl+0x5e>
  74:	3b4c      	cmpnei      	r3, 12
  76:	0804      	bt      	0x7e	// 7e <atcmd_tx_pwr_super_hdl+0x7e>
  78:	6c53      	mov      	r1, r4
  7a:	100b      	lrw      	r0, 0x0	// a4 <atcmd_tx_pwr_super_hdl+0xa4>
  7c:	07e1      	br      	0x3e	// 3e <atcmd_tx_pwr_super_hdl+0x3e>
  7e:	3b40      	cmpnei      	r3, 0
  80:	104a      	lrw      	r2, 0x0	// a8 <atcmd_tx_pwr_super_hdl+0xa8>
  82:	106b      	lrw      	r3, 0x0	// ac <atcmd_tx_pwr_super_hdl+0xac>
  84:	c4430c20 	incf      	r2, r3, 0
  88:	6c53      	mov      	r1, r4
  8a:	100a      	lrw      	r0, 0x0	// b0 <atcmd_tx_pwr_super_hdl+0xb0>
  8c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  90:	07be      	br      	0xc	// c <atcmd_tx_pwr_super_hdl+0xc>
	...

Disassembly of section .text.atcmd_tx_pwr_super_th_hdl:

00000000 <atcmd_tx_pwr_super_th_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_pwr_super_th_hdl+0x12>
   8:	1010      	lrw      	r0, 0x0	// 48 <atcmd_printf+0x48>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108e      	lrw      	r4, 0x0	// 4c <atcmd_tx_pwr_super_th_hdl+0x4c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0b      	bf      	0x32	// 32 <atoi+0x32>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	e9600008 	blsz      	r0, 0x32	// 32 <atcmd_tx_pwr_super_th_hdl+0x32>
  26:	d86420db 	ld.w      	r3, (r4, 0x36c)
  2a:	c4605cee 	ins      	r3, r0, 21, 14
  2e:	dc6420db 	st.w      	r3, (r4, 0x36c)
  32:	d84420db 	ld.w      	r2, (r4, 0x36c)
  36:	c5c256a2 	zext      	r2, r2, 21, 14
  3a:	e4620008 	addi      	r3, r2, 9
  3e:	5d26      	addi      	r1, r5, 2
  40:	1004      	lrw      	r0, 0x0	// 50 <atcmd_tx_pwr_super_th_hdl+0x50>
  42:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  46:	07e4      	br      	0xe	// e <atcmd_tx_pwr_super_th_hdl+0xe>
	...

Disassembly of section .text.atcmd_tx_rate_fixed_hdl:

00000000 <atcmd_tx_rate_fixed_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_rate_fixed_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_tx_rate_fixed_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d864036e 	ld.b      	r3, (r4, 0x36e)
  26:	e9000015 	bez      	r0, 0x50	// 50 <atcmd_tx_rate_fixed_hdl+0x50>
  2a:	3201      	movi      	r2, 1
  2c:	c4625c06 	ins      	r3, r2, 6, 6
  30:	dc64036e 	st.b      	r3, (r4, 0x36e)
  34:	d864036e 	ld.b      	r3, (r4, 0x36e)
  38:	e4632040 	andi      	r3, r3, 64
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1049      	lrw      	r2, 0x0	// 60 <atcmd_tx_rate_fixed_hdl+0x60>
  40:	1069      	lrw      	r3, 0x0	// 64 <atcmd_tx_rate_fixed_hdl+0x64>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1008      	lrw      	r0, 0x0	// 68 <atcmd_tx_rate_fixed_hdl+0x68>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_tx_rate_fixed_hdl+0xe>
  50:	c4605c06 	ins      	r3, r0, 6, 6
  54:	07ee      	br      	0x30	// 30 <atcmd_tx_rate_fixed_hdl+0x30>
	...

Disassembly of section .text.atcmd_tx_attn_hdl:

00000000 <atcmd_tx_attn_hdl>:
   0:	14d7      	push      	r4-r10, r15
   2:	6e03      	mov      	r8, r0
   4:	6e47      	mov      	r9, r1
   6:	e9220007 	bnez      	r2, 0x14	// 14 <atcmd_tx_attn_hdl+0x14>
   a:	1217      	lrw      	r0, 0x0	// 164 <atcmd_printf+0x164>
   c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  10:	3000      	movi      	r0, 0
  12:	1497      	pop      	r4-r10, r15
  14:	9100      	ld.w      	r0, (r1, 0x0)
  16:	12b5      	lrw      	r5, 0x0	// 168 <atcmd_tx_attn_hdl+0x168>
  18:	8060      	ld.b      	r3, (r0, 0x0)
  1a:	eb43003f 	cmpnei      	r3, 63
  1e:	081f      	bt      	0x5c	// 5c <atcmd_tx_attn_hdl+0x5c>
  20:	d80511b6 	ld.h      	r0, (r5, 0x36c)
  24:	c4a05520 	zext      	r0, r0, 9, 5
  28:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_get_tx_digi_gain>
  2c:	e0000000 	bsr      	0x0	// 0 <__floatunsidf>
  30:	3200      	movi      	r2, 0
  32:	ea233f50 	movih      	r3, 16208
  36:	e0000000 	bsr      	0x0	// 0 <__muldf3>
  3a:	e0000000 	bsr      	0x0	// 0 <log10>
  3e:	3200      	movi      	r2, 0
  40:	ea23c034 	movih      	r3, 49204
  44:	e0000000 	bsr      	0x0	// 0 <__muldf3>
  48:	6d03      	mov      	r4, r0
  4a:	6d87      	mov      	r6, r1
  4c:	6c93      	mov      	r2, r4
  4e:	6cdb      	mov      	r3, r6
  50:	e4280001 	addi      	r1, r8, 2
  54:	1206      	lrw      	r0, 0x0	// 16c <atcmd_printf+0x16c>
  56:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  5a:	07db      	br      	0x10	// 10 <atcmd_tx_attn_hdl+0x10>
  5c:	d8650338 	ld.b      	r3, (r5, 0x338)
  60:	3400      	movi      	r4, 0
  62:	c4645c00 	ins      	r3, r4, 0, 0
  66:	dc650338 	st.b      	r3, (r5, 0x338)
  6a:	3201      	movi      	r2, 1
  6c:	d86503df 	ld.b      	r3, (r5, 0x3df)
  70:	c4625c02 	ins      	r3, r2, 2, 2
  74:	6dd3      	mov      	r7, r4
  76:	dc6503df 	st.b      	r3, (r5, 0x3df)
  7a:	2f05      	subi      	r7, 6
  7c:	e0000000 	bsr      	0x0	// 0 <atoi>
  80:	65c1      	cmplt      	r0, r7
  82:	6d83      	mov      	r6, r0
  84:	0863      	bt      	0x14a	// 14a <atcmd_tx_attn_hdl+0x14a>
  86:	d9492000 	ld.w      	r10, (r9, 0x0)
  8a:	312d      	movi      	r1, 45
  8c:	6c2b      	mov      	r0, r10
  8e:	e0000000 	bsr      	0x0	// 0 <strchr>
  92:	6e43      	mov      	r9, r0
  94:	312e      	movi      	r1, 46
  96:	6c2b      	mov      	r0, r10
  98:	e0000000 	bsr      	0x0	// 0 <strchr>
  9c:	e920003b 	bnez      	r0, 0x112	// 112 <atcmd_tx_attn_hdl+0x112>
  a0:	3400      	movi      	r4, 0
  a2:	e9090040 	bez      	r9, 0x122	// 122 <atcmd_tx_attn_hdl+0x122>
  a6:	6c1b      	mov      	r0, r6
  a8:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
  ac:	6dc3      	mov      	r7, r0
  ae:	6c13      	mov      	r0, r4
  b0:	6d87      	mov      	r6, r1
  b2:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
  b6:	3200      	movi      	r2, 0
  b8:	ea234024 	movih      	r3, 16420
  bc:	e0000000 	bsr      	0x0	// 0 <__divdf3>
  c0:	6c83      	mov      	r2, r0
  c2:	6cc7      	mov      	r3, r1
  c4:	6c1f      	mov      	r0, r7
  c6:	6c5b      	mov      	r1, r6
  c8:	e0000000 	bsr      	0x0	// 0 <__subdf3>
  cc:	3200      	movi      	r2, 0
  ce:	ea234034 	movih      	r3, 16436
  d2:	6d03      	mov      	r4, r0
  d4:	6d87      	mov      	r6, r1
  d6:	e0000000 	bsr      	0x0	// 0 <__divdf3>
  da:	6c83      	mov      	r2, r0
  dc:	6cc7      	mov      	r3, r1
  de:	3000      	movi      	r0, 0
  e0:	ea214024 	movih      	r1, 16420
  e4:	e0000000 	bsr      	0x0	// 0 <pow>
  e8:	6c83      	mov      	r2, r0
  ea:	6cc7      	mov      	r3, r1
  ec:	3000      	movi      	r0, 0
  ee:	ea214090 	movih      	r1, 16528
  f2:	e0000000 	bsr      	0x0	// 0 <__divdf3>
  f6:	e0000000 	bsr      	0x0	// 0 <__fixunsdfsi>
  fa:	75c1      	zexth      	r7, r0
  fc:	d82511b6 	ld.h      	r1, (r5, 0x36c)
 100:	6c1f      	mov      	r0, r7
 102:	c4a15521 	zext      	r1, r1, 9, 5
 106:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
 10a:	6c1f      	mov      	r0, r7
 10c:	e0000000 	bsr      	0x0	// 0 <tx_digi_gain_store>
 110:	079e      	br      	0x4c	// 4c <atcmd_tx_attn_hdl+0x4c>
 112:	65da      	cmpne      	r6, r7
 114:	a082      	st.b      	r4, (r0, 0x2)
 116:	0fc5      	bf      	0xa0	// a0 <atcmd_tx_attn_hdl+0xa0>
 118:	2000      	addi      	r0, 1
 11a:	e0000000 	bsr      	0x0	// 0 <atoi>
 11e:	6d03      	mov      	r4, r0
 120:	07c1      	br      	0xa2	// a2 <atcmd_tx_attn_hdl+0xa2>
 122:	6c13      	mov      	r0, r4
 124:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
 128:	3200      	movi      	r2, 0
 12a:	ea234024 	movih      	r3, 16420
 12e:	e0000000 	bsr      	0x0	// 0 <__divdf3>
 132:	6dc3      	mov      	r7, r0
 134:	6c1b      	mov      	r0, r6
 136:	6d07      	mov      	r4, r1
 138:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
 13c:	6c83      	mov      	r2, r0
 13e:	6cc7      	mov      	r3, r1
 140:	6c1f      	mov      	r0, r7
 142:	6c53      	mov      	r1, r4
 144:	e0000000 	bsr      	0x0	// 0 <__adddf3>
 148:	07c2      	br      	0xcc	// cc <atcmd_tx_attn_hdl+0xcc>
 14a:	d86503df 	ld.b      	r3, (r5, 0x3df)
 14e:	c4645c02 	ins      	r3, r4, 2, 2
 152:	dc6503df 	st.b      	r3, (r5, 0x3df)
 156:	3200      	movi      	r2, 0
 158:	1066      	lrw      	r3, 0x0	// 170 <atcmd_tx_attn_hdl+0x170>
 15a:	2a00      	subi      	r2, 1
 15c:	b352      	st.w      	r2, (r3, 0x48)
 15e:	ea267ff8 	movih      	r6, 32760
 162:	0775      	br      	0x4c	// 4c <atcmd_tx_attn_hdl+0x4c>
	...

Disassembly of section .text.atcmd_tx_cw_hdl:

00000000 <atcmd_tx_cw_hdl>:
   0:	14d6      	push      	r4-r9, r15
   2:	1421      	subi      	r14, r14, 4
   4:	ea0301ff 	movi      	r3, 511
   8:	dc6e1000 	st.h      	r3, (r14, 0x0)
   c:	ea0301ff 	movi      	r3, 511
  10:	6cce      	nor      	r3, r3
  12:	dc6e1001 	st.h      	r3, (r14, 0x2)
  16:	e9220008 	bnez      	r2, 0x26	// 26 <atcmd_tx_cw_hdl+0x26>
  1a:	1212      	lrw      	r0, 0x0	// 160 <atcmd_printf+0x160>
  1c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  20:	3000      	movi      	r0, 0
  22:	1401      	addi      	r14, r14, 4
  24:	1496      	pop      	r4-r9, r15
  26:	9160      	ld.w      	r3, (r1, 0x0)
  28:	58c6      	addi      	r6, r0, 2
  2a:	8340      	ld.b      	r2, (r3, 0x0)
  2c:	eb42003f 	cmpnei      	r2, 63
  30:	080e      	bt      	0x4c	// 4c <atcmd_tx_cw_hdl+0x4c>
  32:	126d      	lrw      	r3, 0x0	// 164 <atcmd_tx_cw_hdl+0x164>
  34:	124d      	lrw      	r2, 0x0	// 168 <atcmd_tx_cw_hdl+0x168>
  36:	d86303e3 	ld.b      	r3, (r3, 0x3e3)
  3a:	3b40      	cmpnei      	r3, 0
  3c:	126c      	lrw      	r3, 0x0	// 16c <atcmd_tx_cw_hdl+0x16c>
  3e:	c4430c20 	incf      	r2, r3, 0
  42:	6c5b      	mov      	r1, r6
  44:	120b      	lrw      	r0, 0x0	// 170 <atcmd_tx_cw_hdl+0x170>
  46:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4a:	07eb      	br      	0x20	// 20 <atcmd_tx_cw_hdl+0x20>
  4c:	6c0f      	mov      	r0, r3
  4e:	e0000000 	bsr      	0x0	// 0 <atoi>
  52:	3841      	cmpnei      	r0, 1
  54:	6d03      	mov      	r4, r0
  56:	084c      	bt      	0xee	// ee <atcmd_tx_cw_hdl+0xee>
  58:	12a3      	lrw      	r5, 0x0	// 164 <atcmd_tx_cw_hdl+0x164>
  5a:	d86503e3 	ld.b      	r3, (r5, 0x3e3)
  5e:	3b41      	cmpnei      	r3, 1
  60:	0c42      	bf      	0xe4	// e4 <atcmd_tx_cw_hdl+0xe4>
  62:	ea080000 	movi      	r8, 0
  66:	d8650338 	ld.b      	r3, (r5, 0x338)
  6a:	c4685c00 	ins      	r3, r8, 0, 0
  6e:	12e2      	lrw      	r7, 0x0	// 174 <atcmd_tx_cw_hdl+0x174>
  70:	ea890042 	lrw      	r9, 0x0	// 178 <atcmd_tx_cw_hdl+0x178>
  74:	dc650338 	st.b      	r3, (r5, 0x338)
  78:	d86503df 	ld.b      	r3, (r5, 0x3df)
  7c:	c4605c02 	ins      	r3, r0, 2, 2
  80:	dc6503df 	st.b      	r3, (r5, 0x3df)
  84:	d8670042 	ld.b      	r3, (r7, 0x42)
  88:	c4685c00 	ins      	r3, r8, 0, 0
  8c:	dc670042 	st.b      	r3, (r7, 0x42)
  90:	d86509e2 	ld.b      	r3, (r5, 0x9e2)
  94:	c4685c04 	ins      	r3, r8, 4, 4
  98:	dc6509e2 	st.b      	r3, (r5, 0x9e2)
  9c:	e0000000 	bsr      	0x0	// 0 <ah_wphy_cont_tx_disable>
  a0:	d8492000 	ld.w      	r2, (r9, 0x0)
  a4:	3105      	movi      	r1, 5
  a6:	9271      	ld.w      	r3, (r2, 0x44)
  a8:	3bb4      	bseti      	r3, 20
  aa:	b271      	st.w      	r3, (r2, 0x44)
  ac:	6c23      	mov      	r0, r8
  ae:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
  b2:	3105      	movi      	r1, 5
  b4:	6c3b      	mov      	r0, r14
  b6:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_tx_dcoc>
  ba:	d8670042 	ld.b      	r3, (r7, 0x42)
  be:	c4645c00 	ins      	r3, r4, 0, 0
  c2:	dc670042 	st.b      	r3, (r7, 0x42)
  c6:	d86509e2 	ld.b      	r3, (r5, 0x9e2)
  ca:	c4645c04 	ins      	r3, r4, 4, 4
  ce:	dc6509e2 	st.b      	r3, (r5, 0x9e2)
  d2:	dc8503e3 	st.b      	r4, (r5, 0x3e3)
  d6:	e0000000 	bsr      	0x0	// 0 <ah_wphy_cont_tx_enable>
  da:	d8492000 	ld.w      	r2, (r9, 0x0)
  de:	9271      	ld.w      	r3, (r2, 0x44)
  e0:	3b94      	bclri      	r3, 20
  e2:	b271      	st.w      	r3, (r2, 0x44)
  e4:	6c5b      	mov      	r1, r6
  e6:	1106      	lrw      	r0, 0x0	// 17c <atcmd_tx_cw_hdl+0x17c>
  e8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  ec:	079a      	br      	0x20	// 20 <atcmd_tx_cw_hdl+0x20>
  ee:	e9200031 	bnez      	r0, 0x150	// 150 <atcmd_tx_cw_hdl+0x150>
  f2:	10bd      	lrw      	r5, 0x0	// 164 <atcmd_tx_cw_hdl+0x164>
  f4:	d86503e3 	ld.b      	r3, (r5, 0x3e3)
  f8:	e9030029 	bez      	r3, 0x14a	// 14a <atcmd_tx_cw_hdl+0x14a>
  fc:	d8650338 	ld.b      	r3, (r5, 0x338)
 100:	3201      	movi      	r2, 1
 102:	c4625c00 	ins      	r3, r2, 0, 0
 106:	dc650338 	st.b      	r3, (r5, 0x338)
 10a:	d86503df 	ld.b      	r3, (r5, 0x3df)
 10e:	c4605c02 	ins      	r3, r0, 2, 2
 112:	dc6503df 	st.b      	r3, (r5, 0x3df)
 116:	1078      	lrw      	r3, 0x0	// 174 <atcmd_tx_cw_hdl+0x174>
 118:	d8430042 	ld.b      	r2, (r3, 0x42)
 11c:	c4405c00 	ins      	r2, r0, 0, 0
 120:	dc430042 	st.b      	r2, (r3, 0x42)
 124:	d86509e2 	ld.b      	r3, (r5, 0x9e2)
 128:	c4605c04 	ins      	r3, r0, 4, 4
 12c:	dc6509e2 	st.b      	r3, (r5, 0x9e2)
 130:	e0000000 	bsr      	0x0	// 0 <ah_wphy_cont_tx_disable>
 134:	1071      	lrw      	r3, 0x0	// 178 <atcmd_tx_cw_hdl+0x178>
 136:	3105      	movi      	r1, 5
 138:	9340      	ld.w      	r2, (r3, 0x0)
 13a:	1012      	lrw      	r0, 0x0	// 180 <atcmd_tx_cw_hdl+0x180>
 13c:	9271      	ld.w      	r3, (r2, 0x44)
 13e:	3bb4      	bseti      	r3, 20
 140:	b271      	st.w      	r3, (r2, 0x44)
 142:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_tx_dcoc>
 146:	dc8503e3 	st.b      	r4, (r5, 0x3e3)
 14a:	6c5b      	mov      	r1, r6
 14c:	100e      	lrw      	r0, 0x0	// 184 <atcmd_tx_cw_hdl+0x184>
 14e:	07cd      	br      	0xe8	// e8 <atcmd_tx_cw_hdl+0xe8>
 150:	1069      	lrw      	r3, 0x0	// 174 <atcmd_tx_cw_hdl+0x174>
 152:	3200      	movi      	r2, 0
 154:	2a00      	subi      	r2, 1
 156:	b352      	st.w      	r2, (r3, 0x48)
 158:	6c5b      	mov      	r1, r6
 15a:	100c      	lrw      	r0, 0x0	// 188 <atcmd_tx_cw_hdl+0x188>
 15c:	07c6      	br      	0xe8	// e8 <atcmd_tx_cw_hdl+0xe8>
	...

Disassembly of section .text.atcmd_tx_max_agg_hdl:

00000000 <atcmd_tx_max_agg_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_max_agg_hdl+0x12>
   8:	100f      	lrw      	r0, 0x0	// 44 <atcmd_printf+0x44>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108d      	lrw      	r4, 0x0	// 48 <atcmd_tx_max_agg_hdl+0x48>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c09      	bf      	0x2e	// 2e <atoi+0x2e>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	5863      	subi      	r3, r0, 1
  24:	eb03003f 	cmphsi      	r3, 64
  28:	080a      	bt      	0x3c	// 3c <atcmd_tx_max_agg_hdl+0x3c>
  2a:	dc040315 	st.b      	r0, (r4, 0x315)
  2e:	d8440315 	ld.b      	r2, (r4, 0x315)
  32:	5d26      	addi      	r1, r5, 2
  34:	1006      	lrw      	r0, 0x0	// 4c <atcmd_tx_max_agg_hdl+0x4c>
  36:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  3a:	07ea      	br      	0xe	// e <atcmd_tx_max_agg_hdl+0xe>
  3c:	3318      	movi      	r3, 24
  3e:	dc640315 	st.b      	r3, (r4, 0x315)
  42:	07f6      	br      	0x2e	// 2e <atcmd_tx_max_agg_hdl+0x2e>
	...

Disassembly of section .text.atcmd_tx_max_syms_hdl:

00000000 <atcmd_tx_max_syms_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_max_syms_hdl+0x12>
   8:	1013      	lrw      	r0, 0x0	// 54 <atcmd_printf+0x54>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1091      	lrw      	r4, 0x0	// 58 <atcmd_tx_max_syms_hdl+0x58>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0d      	bf      	0x36	// 36 <atoi+0x36>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	5863      	subi      	r3, r0, 1
  24:	eb0301fe 	cmphsi      	r3, 511
  28:	0810      	bt      	0x48	// 48 <atcmd_tx_max_syms_hdl+0x48>
  2a:	d86411b0 	ld.h      	r3, (r4, 0x360)
  2e:	c4605d01 	ins      	r3, r0, 9, 1
  32:	dc6411b0 	st.h      	r3, (r4, 0x360)
  36:	d84411b0 	ld.h      	r2, (r4, 0x360)
  3a:	c4225522 	zext      	r2, r2, 9, 1
  3e:	5d26      	addi      	r1, r5, 2
  40:	1007      	lrw      	r0, 0x0	// 5c <atcmd_tx_max_syms_hdl+0x5c>
  42:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  46:	07e4      	br      	0xe	// e <atcmd_tx_max_syms_hdl+0xe>
  48:	1066      	lrw      	r3, 0x0	// 60 <atcmd_tx_max_syms_hdl+0x60>
  4a:	3200      	movi      	r2, 0
  4c:	2a00      	subi      	r2, 1
  4e:	b352      	st.w      	r2, (r3, 0x48)
  50:	07f3      	br      	0x36	// 36 <atcmd_tx_max_syms_hdl+0x36>
	...

Disassembly of section .text.atcmd_xo_cs_hdl:

00000000 <atcmd_xo_cs_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d83      	mov      	r6, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_xo_cs_hdl+0x12>
   8:	1016      	lrw      	r0, 0x0	// 60 <atcmd_printf+0x60>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1493      	pop      	r4-r6, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	8060      	ld.b      	r3, (r0, 0x0)
  16:	eb43003f 	cmpnei      	r3, 63
  1a:	080e      	bt      	0x36	// 36 <atcmd_xo_cs_hdl+0x36>
  1c:	ea038003 	movi      	r3, 32771
  20:	c5e34903 	rotli      	r3, r3, 15
  24:	938a      	ld.w      	r4, (r3, 0x28)
  26:	c66456e4 	zext      	r4, r4, 23, 19
  2a:	6c93      	mov      	r2, r4
  2c:	5e26      	addi      	r1, r6, 2
  2e:	100e      	lrw      	r0, 0x0	// 64 <atcmd_xo_cs_hdl+0x64>
  30:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  34:	07ed      	br      	0xe	// e <os_atoh+0xe>
  36:	e0000000 	bsr      	0x0	// 0 <os_atoh>
  3a:	381f      	cmphsi      	r0, 32
  3c:	080a      	bt      	0x50	// 50 <atcmd_xo_cs_hdl+0x50>
  3e:	7540      	zextb      	r5, r0
  40:	6d03      	mov      	r4, r0
  42:	6c17      	mov      	r0, r5
  44:	e0000000 	bsr      	0x0	// 0 <xo_set_cs_sec>
  48:	6c17      	mov      	r0, r5
  4a:	e0000000 	bsr      	0x0	// 0 <xo_cs_store>
  4e:	07ee      	br      	0x2a	// 2a <atcmd_xo_cs_hdl+0x2a>
  50:	1066      	lrw      	r3, 0x0	// 68 <atcmd_xo_cs_hdl+0x68>
  52:	3200      	movi      	r2, 0
  54:	2a00      	subi      	r2, 1
  56:	b352      	st.w      	r2, (r3, 0x48)
  58:	ea04dead 	movi      	r4, 57005
  5c:	07e7      	br      	0x2a	// 2a <atcmd_xo_cs_hdl+0x2a>
	...

Disassembly of section .text.atcmd_xo_cs_auto_hdl:

00000000 <atcmd_xo_cs_auto_hdl>:
   0:	14d8      	push      	r4-r11, r15
   2:	6e03      	mov      	r8, r0
   4:	6d07      	mov      	r4, r1
   6:	e9220007 	bnez      	r2, 0x14	// 14 <atcmd_xo_cs_auto_hdl+0x14>
   a:	111e      	lrw      	r0, 0x0	// 100 <atcmd_printf+0x100>
   c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  10:	3000      	movi      	r0, 0
  12:	1498      	pop      	r4-r11, r15
  14:	9100      	ld.w      	r0, (r1, 0x0)
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	080f      	bt      	0x3a	// 3a <atcmd_xo_cs_auto_hdl+0x3a>
  1e:	ea038003 	movi      	r3, 32771
  22:	c5e34903 	rotli      	r3, r3, 15
  26:	938a      	ld.w      	r4, (r3, 0x28)
  28:	c66456e4 	zext      	r4, r4, 23, 19
  2c:	6c93      	mov      	r2, r4
  2e:	e4280001 	addi      	r1, r8, 2
  32:	1115      	lrw      	r0, 0x0	// 104 <atcmd_printf+0x104>
  34:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  38:	07ec      	br      	0x10	// 10 <atcmd_xo_cs_auto_hdl+0x10>
  3a:	3a01      	cmphsi      	r2, 2
  3c:	0c59      	bf      	0xee	// ee <atcmd_xo_cs_auto_hdl+0xee>
  3e:	e0000000 	bsr      	0x0	// 0 <atoi>
  42:	6d43      	mov      	r5, r0
  44:	9401      	ld.w      	r0, (r4, 0x4)
  46:	e0000000 	bsr      	0x0	// 0 <atoi>
  4a:	6541      	cmplt      	r0, r5
  4c:	0823      	bt      	0x92	// 92 <atcmd_xo_cs_auto_hdl+0x92>
  4e:	9400      	ld.w      	r0, (r4, 0x0)
  50:	e0000000 	bsr      	0x0	// 0 <atoi>
  54:	6dc3      	mov      	r7, r0
  56:	9401      	ld.w      	r0, (r4, 0x4)
  58:	e0000000 	bsr      	0x0	// 0 <atoi>
  5c:	11cb      	lrw      	r6, 0x0	// 108 <atcmd_xo_cs_auto_hdl+0x108>
  5e:	6c83      	mov      	r2, r0
  60:	6e43      	mov      	r9, r0
  62:	6c5f      	mov      	r1, r7
  64:	110a      	lrw      	r0, 0x0	// 10c <atcmd_xo_cs_auto_hdl+0x10c>
  66:	11ab      	lrw      	r5, 0x0	// 110 <atcmd_xo_cs_auto_hdl+0x110>
  68:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  6c:	d86621da 	ld.w      	r3, (r6, 0x768)
  70:	b560      	st.w      	r3, (r5, 0x0)
  72:	ea038003 	movi      	r3, 32771
  76:	c5e34903 	rotli      	r3, r3, 15
  7a:	ea0a0000 	movi      	r10, 0
  7e:	938a      	ld.w      	r4, (r3, 0x28)
  80:	c66456e4 	zext      	r4, r4, 23, 19
  84:	9560      	ld.w      	r3, (r5, 0x0)
  86:	65cd      	cmplt      	r3, r7
  88:	080b      	bt      	0x9e	// 9e <atcmd_xo_cs_auto_hdl+0x9e>
  8a:	64e5      	cmplt      	r9, r3
  8c:	0fd0      	bf      	0x2c	// 2c <atcmd_xo_cs_auto_hdl+0x2c>
  8e:	2c00      	subi      	r4, 1
  90:	0408      	br      	0xa0	// a0 <atcmd_xo_cs_auto_hdl+0xa0>
  92:	9401      	ld.w      	r0, (r4, 0x4)
  94:	e0000000 	bsr      	0x0	// 0 <atoi>
  98:	6dc3      	mov      	r7, r0
  9a:	9400      	ld.w      	r0, (r4, 0x0)
  9c:	07de      	br      	0x58	// 58 <atcmd_xo_cs_auto_hdl+0x58>
  9e:	2400      	addi      	r4, 1
  a0:	3c1f      	cmphsi      	r4, 32
  a2:	0c11      	bf      	0xc4	// c4 <atcmd_xo_cs_auto_hdl+0xc4>
  a4:	3300      	movi      	r3, 0
  a6:	2b00      	subi      	r3, 1
  a8:	64d2      	cmpne      	r4, r3
  aa:	0c0b      	bf      	0xc0	// c0 <atcmd_xo_cs_auto_hdl+0xc0>
  ac:	eb440020 	cmpnei      	r4, 32
  b0:	331f      	movi      	r3, 31
  b2:	c4830c20 	incf      	r4, r3, 0
  b6:	6c53      	mov      	r1, r4
  b8:	1017      	lrw      	r0, 0x0	// 114 <atcmd_xo_cs_auto_hdl+0x114>
  ba:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  be:	07b7      	br      	0x2c	// 2c <atcmd_xo_cs_auto_hdl+0x2c>
  c0:	3400      	movi      	r4, 0
  c2:	07fa      	br      	0xb6	// b6 <atcmd_xo_cs_auto_hdl+0xb6>
  c4:	76d0      	zextb      	r11, r4
  c6:	6c2f      	mov      	r0, r11
  c8:	e0000000 	bsr      	0x0	// 0 <xo_set_cs_sec>
  cc:	6c2f      	mov      	r0, r11
  ce:	e0000000 	bsr      	0x0	// 0 <xo_cs_store>
  d2:	3050      	movi      	r0, 80
  d4:	dd4621da 	st.w      	r10, (r6, 0x768)
  d8:	e0000000 	bsr      	0x0	// 0 <os_sleep_ms>
  dc:	d86621da 	ld.w      	r3, (r6, 0x768)
  e0:	b560      	st.w      	r3, (r5, 0x0)
  e2:	e923ffd1 	bnez      	r3, 0x84	// 84 <atcmd_xo_cs_auto_hdl+0x84>
  e6:	100d      	lrw      	r0, 0x0	// 118 <hgprintf+0x118>
  e8:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ec:	07a0      	br      	0x2c	// 2c <atcmd_xo_cs_auto_hdl+0x2c>
  ee:	100c      	lrw      	r0, 0x0	// 11c <atcmd_xo_cs_auto_hdl+0x11c>
  f0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  f4:	106b      	lrw      	r3, 0x0	// 120 <atcmd_xo_cs_auto_hdl+0x120>
  f6:	3200      	movi      	r2, 0
  f8:	2a00      	subi      	r2, 1
  fa:	b352      	st.w      	r2, (r3, 0x48)
  fc:	3400      	movi      	r4, 0
  fe:	0797      	br      	0x2c	// 2c <atcmd_xo_cs_auto_hdl+0x2c>
	...

Disassembly of section .text.atcmd_t_sensor_hdl:

00000000 <atcmd_t_sensor_hdl>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_t_sensor_hdl+0x12>
   8:	100c      	lrw      	r0, 0x0	// 38 <atcmd_printf+0x38>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1491      	pop      	r4, r15
  12:	9160      	ld.w      	r3, (r1, 0x0)
  14:	8360      	ld.b      	r3, (r3, 0x0)
  16:	eb43003f 	cmpnei      	r3, 63
  1a:	0809      	bt      	0x2c	// 2c <atcmd_t_sensor_hdl+0x2c>
  1c:	e0000000 	bsr      	0x0	// 0 <atcmd_t_sensor_hdl>
  20:	6c83      	mov      	r2, r0
  22:	5c26      	addi      	r1, r4, 2
  24:	1006      	lrw      	r0, 0x0	// 3c <atcmd_t_sensor_hdl+0x3c>
  26:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  2a:	07f2      	br      	0xe	// e <atcmd_t_sensor_hdl+0xe>
  2c:	1065      	lrw      	r3, 0x0	// 40 <atcmd_t_sensor_hdl+0x40>
  2e:	3200      	movi      	r2, 0
  30:	2a00      	subi      	r2, 1
  32:	b352      	st.w      	r2, (r3, 0x48)
  34:	1044      	lrw      	r2, 0xdeaddead	// 44 <atcmd_t_sensor_hdl+0x44>
  36:	07f6      	br      	0x22	// 22 <atcmd_t_sensor_hdl+0x22>
	...
  44:	dead      	.short	0xdead
  46:	dead      	.short	0xdead

Disassembly of section .text.atcmd_mac_addr_hdl:

00000000 <atcmd_mac_addr_hdl>:
   0:	14d1      	push      	r4, r15
   2:	1424      	subi      	r14, r14, 16
   4:	6d03      	mov      	r4, r0
   6:	e9220008 	bnez      	r2, 0x16	// 16 <atcmd_mac_addr_hdl+0x16>
   a:	1015      	lrw      	r0, 0x0	// 5c <atcmd_printf+0x5c>
   c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  10:	3000      	movi      	r0, 0
  12:	1404      	addi      	r14, r14, 16
  14:	1491      	pop      	r4, r15
  16:	9100      	ld.w      	r0, (r1, 0x0)
  18:	8060      	ld.b      	r3, (r0, 0x0)
  1a:	eb43003f 	cmpnei      	r3, 63
  1e:	0c08      	bf      	0x2e	// 2e <atcmd_mac_addr_hdl+0x2e>
  20:	eb430030 	cmpnei      	r3, 48
  24:	102f      	lrw      	r1, 0x0	// 60 <atcmd_mac_addr_hdl+0x60>
  26:	0802      	bt      	0x2a	// 2a <atcmd_mac_addr_hdl+0x2a>
  28:	100f      	lrw      	r0, 0x0	// 64 <atcmd_mac_addr_hdl+0x64>
  2a:	e0000000 	bsr      	0x0	// 0 <str2mac>
  2e:	102f      	lrw      	r1, 0x0	// 68 <atcmd_mac_addr_hdl+0x68>
  30:	d8010307 	ld.b      	r0, (r1, 0x307)
  34:	d8610303 	ld.b      	r3, (r1, 0x303)
  38:	d8410302 	ld.b      	r2, (r1, 0x302)
  3c:	b803      	st.w      	r0, (r14, 0xc)
  3e:	d8010306 	ld.b      	r0, (r1, 0x306)
  42:	b802      	st.w      	r0, (r14, 0x8)
  44:	d8010305 	ld.b      	r0, (r1, 0x305)
  48:	b801      	st.w      	r0, (r14, 0x4)
  4a:	d8210304 	ld.b      	r1, (r1, 0x304)
  4e:	b820      	st.w      	r1, (r14, 0x0)
  50:	5c26      	addi      	r1, r4, 2
  52:	1007      	lrw      	r0, 0x0	// 6c <atcmd_mac_addr_hdl+0x6c>
  54:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  58:	07dc      	br      	0x10	// 10 <atcmd_mac_addr_hdl+0x10>
	...

Disassembly of section .text.atcmd_mcast_dup_hdl:

00000000 <atcmd_mcast_dup_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_mcast_dup_hdl+0x12>
   8:	1012      	lrw      	r0, 0x0	// 50 <atcmd_printf+0x50>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1090      	lrw      	r4, 0x0	// 54 <atcmd_mcast_dup_hdl+0x54>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0b      	bf      	0x32	// 32 <atoi+0x32>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	e9800011 	blz      	r0, 0x44	// 44 <atcmd_mcast_dup_hdl+0x44>
  26:	d8640314 	ld.b      	r3, (r4, 0x314)
  2a:	c4605c80 	ins      	r3, r0, 4, 0
  2e:	dc640314 	st.b      	r3, (r4, 0x314)
  32:	d8440314 	ld.b      	r2, (r4, 0x314)
  36:	e442201f 	andi      	r2, r2, 31
  3a:	5d26      	addi      	r1, r5, 2
  3c:	1007      	lrw      	r0, 0x0	// 58 <atcmd_mcast_dup_hdl+0x58>
  3e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  42:	07e6      	br      	0xe	// e <atcmd_mcast_dup_hdl+0xe>
  44:	1066      	lrw      	r3, 0x0	// 5c <atcmd_mcast_dup_hdl+0x5c>
  46:	3200      	movi      	r2, 0
  48:	2a00      	subi      	r2, 1
  4a:	b352      	st.w      	r2, (r3, 0x48)
  4c:	07f3      	br      	0x32	// 32 <atcmd_mcast_dup_hdl+0x32>
	...

Disassembly of section .text.atcmd_mcast_reorder_hdl:

00000000 <atcmd_mcast_reorder_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_mcast_reorder_hdl+0x12>
   8:	1011      	lrw      	r0, 0x0	// 4c <atcmd_printf+0x4c>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108f      	lrw      	r4, 0x0	// 50 <atcmd_mcast_reorder_hdl+0x50>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c09      	bf      	0x2e	// 2e <atoi+0x2e>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d8640314 	ld.b      	r3, (r4, 0x314)
  26:	c4605c26 	ins      	r3, r0, 7, 6
  2a:	dc640314 	st.b      	r3, (r4, 0x314)
  2e:	d8640314 	ld.b      	r3, (r4, 0x314)
  32:	e46320c0 	andi      	r3, r3, 192
  36:	3b40      	cmpnei      	r3, 0
  38:	1047      	lrw      	r2, 0x0	// 54 <atcmd_mcast_reorder_hdl+0x54>
  3a:	1068      	lrw      	r3, 0x0	// 58 <atcmd_mcast_reorder_hdl+0x58>
  3c:	c4430c20 	incf      	r2, r3, 0
  40:	5d26      	addi      	r1, r5, 2
  42:	1007      	lrw      	r0, 0x0	// 5c <atcmd_mcast_reorder_hdl+0x5c>
  44:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  48:	07e3      	br      	0xe	// e <atcmd_mcast_reorder_hdl+0xe>
	...

Disassembly of section .text.atcmd_mcast_rts_hdl:

00000000 <atcmd_mcast_rts_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_mcast_rts_hdl+0x12>
   8:	1012      	lrw      	r0, 0x0	// 50 <atcmd_printf+0x50>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1090      	lrw      	r4, 0x0	// 54 <atcmd_mcast_rts_hdl+0x54>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	3840      	cmpnei      	r0, 0
  24:	d8640314 	ld.b      	r3, (r4, 0x314)
  28:	c4000502 	mvc      	r2
  2c:	c4625c05 	ins      	r3, r2, 5, 5
  30:	dc640314 	st.b      	r3, (r4, 0x314)
  34:	d8640314 	ld.b      	r3, (r4, 0x314)
  38:	e4632020 	andi      	r3, r3, 32
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1047      	lrw      	r2, 0x0	// 58 <atcmd_mcast_rts_hdl+0x58>
  40:	1067      	lrw      	r3, 0x0	// 5c <atcmd_mcast_rts_hdl+0x5c>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1006      	lrw      	r0, 0x0	// 60 <atcmd_mcast_rts_hdl+0x60>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_mcast_rts_hdl+0xe>
	...

Disassembly of section .text.atcmd_tx_cnt_max_hdl:

00000000 <atcmd_tx_cnt_max_hdl>:
   0:	14d4      	push      	r4-r7, r15
   2:	6dc3      	mov      	r7, r0
   4:	6d47      	mov      	r5, r1
   6:	6d8b      	mov      	r6, r2
   8:	e9220007 	bnez      	r2, 0x16	// 16 <atcmd_tx_cnt_max_hdl+0x16>
   c:	1019      	lrw      	r0, 0x0	// 70 <atcmd_printf+0x70>
   e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  12:	3000      	movi      	r0, 0
  14:	1494      	pop      	r4-r7, r15
  16:	9100      	ld.w      	r0, (r1, 0x0)
  18:	1097      	lrw      	r4, 0x0	// 74 <atcmd_tx_cnt_max_hdl+0x74>
  1a:	8060      	ld.b      	r3, (r0, 0x0)
  1c:	eb43003f 	cmpnei      	r3, 63
  20:	0c14      	bf      	0x48	// 48 <atoi+0x48>
  22:	e0000000 	bsr      	0x0	// 0 <atoi>
  26:	5863      	subi      	r3, r0, 1
  28:	eb0300fe 	cmphsi      	r3, 255
  2c:	0817      	bt      	0x5a	// 5a <atcmd_tx_cnt_max_hdl+0x5a>
  2e:	dc040313 	st.b      	r0, (r4, 0x313)
  32:	3e01      	cmphsi      	r6, 2
  34:	0c0a      	bf      	0x48	// 48 <atcmd_tx_cnt_max_hdl+0x48>
  36:	9501      	ld.w      	r0, (r5, 0x4)
  38:	e0000000 	bsr      	0x0	// 0 <atoi>
  3c:	5863      	subi      	r3, r0, 1
  3e:	eb0300fe 	cmphsi      	r3, 255
  42:	0811      	bt      	0x64	// 64 <atcmd_tx_cnt_max_hdl+0x64>
  44:	dc040312 	st.b      	r0, (r4, 0x312)
  48:	d8640312 	ld.b      	r3, (r4, 0x312)
  4c:	d8440313 	ld.b      	r2, (r4, 0x313)
  50:	5f26      	addi      	r1, r7, 2
  52:	100a      	lrw      	r0, 0x0	// 78 <atcmd_tx_cnt_max_hdl+0x78>
  54:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  58:	07dd      	br      	0x12	// 12 <atcmd_tx_cnt_max_hdl+0x12>
  5a:	1069      	lrw      	r3, 0x0	// 7c <atcmd_tx_cnt_max_hdl+0x7c>
  5c:	3200      	movi      	r2, 0
  5e:	2a00      	subi      	r2, 1
  60:	b352      	st.w      	r2, (r3, 0x48)
  62:	07e8      	br      	0x32	// 32 <atcmd_tx_cnt_max_hdl+0x32>
  64:	1066      	lrw      	r3, 0x0	// 7c <atcmd_tx_cnt_max_hdl+0x7c>
  66:	3200      	movi      	r2, 0
  68:	2a00      	subi      	r2, 1
  6a:	b352      	st.w      	r2, (r3, 0x48)
  6c:	07ee      	br      	0x48	// 48 <atcmd_tx_cnt_max_hdl+0x48>
	...

Disassembly of section .text.atcmd_set_rts_hdl:

00000000 <atcmd_set_rts_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_set_rts_hdl+0x12>
   8:	1011      	lrw      	r0, 0x0	// 4c <atcmd_printf+0x4c>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108f      	lrw      	r4, 0x0	// 50 <atcmd_set_rts_hdl+0x50>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0b      	bf      	0x32	// 32 <atoi+0x32>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	6c83      	mov      	r2, r0
  24:	e960000e 	blsz      	r0, 0x40	// 40 <atcmd_set_rts_hdl+0x40>
  28:	3300      	movi      	r3, 0
  2a:	3105      	movi      	r1, 5
  2c:	9400      	ld.w      	r0, (r4, 0x0)
  2e:	e0000000 	bsr      	0x0	// 0 <lmac_ioctl>
  32:	d8441197 	ld.h      	r2, (r4, 0x32e)
  36:	5d26      	addi      	r1, r5, 2
  38:	1007      	lrw      	r0, 0x0	// 54 <atcmd_set_rts_hdl+0x54>
  3a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  3e:	07e8      	br      	0xe	// e <atcmd_set_rts_hdl+0xe>
  40:	1066      	lrw      	r3, 0x0	// 58 <atcmd_set_rts_hdl+0x58>
  42:	3200      	movi      	r2, 0
  44:	2a00      	subi      	r2, 1
  46:	b352      	st.w      	r2, (r3, 0x48)
  48:	07f5      	br      	0x32	// 32 <atcmd_set_rts_hdl+0x32>
	...

Disassembly of section .text.atcmd_set_bgrssi_hdl:

00000000 <atcmd_set_bgrssi_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_set_bgrssi_hdl+0x12>
   8:	100c      	lrw      	r0, 0x0	// 38 <atcmd_printf+0x38>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108a      	lrw      	r4, 0x0	// 3c <atcmd_set_bgrssi_hdl+0x3c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c07      	bf      	0x2a	// 2a <atoi+0x2a>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	7442      	sextb      	r1, r0
  24:	9400      	ld.w      	r0, (r4, 0x0)
  26:	e0000000 	bsr      	0x0	// 0 <lmac_set_bgrssi>
  2a:	d844431e 	ld.bs      	r2, (r4, 0x31e)
  2e:	5d26      	addi      	r1, r5, 2
  30:	1004      	lrw      	r0, 0x0	// 40 <atcmd_set_bgrssi_hdl+0x40>
  32:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  36:	07ec      	br      	0xe	// e <atcmd_set_bgrssi_hdl+0xe>
	...

Disassembly of section .text.atcmd_set_bgrssi_avg_hdl:

00000000 <atcmd_set_bgrssi_avg_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_set_bgrssi_avg_hdl+0x12>
   8:	100f      	lrw      	r0, 0x0	// 44 <atcmd_printf+0x44>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108d      	lrw      	r4, 0x0	// 48 <atcmd_set_bgrssi_avg_hdl+0x48>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0b      	bf      	0x32	// 32 <atoi+0x32>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	3823      	cmplti      	r0, 4
  24:	0807      	bt      	0x32	// 32 <atcmd_set_bgrssi_avg_hdl+0x32>
  26:	d86420d8 	ld.w      	r3, (r4, 0x360)
  2a:	c4605cec 	ins      	r3, r0, 19, 12
  2e:	dc6420d8 	st.w      	r3, (r4, 0x360)
  32:	d84420d8 	ld.w      	r2, (r4, 0x360)
  36:	c5825662 	zext      	r2, r2, 19, 12
  3a:	5d26      	addi      	r1, r5, 2
  3c:	1004      	lrw      	r0, 0x0	// 4c <atcmd_set_bgrssi_avg_hdl+0x4c>
  3e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  42:	07e6      	br      	0xe	// e <atcmd_set_bgrssi_avg_hdl+0xe>
	...

Disassembly of section .text.atcmd_set_pri_chan_hdl:

00000000 <atcmd_set_pri_chan_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_set_pri_chan_hdl+0x12>
   8:	100e      	lrw      	r0, 0x0	// 40 <atcmd_printf+0x40>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108c      	lrw      	r4, 0x0	// 44 <atcmd_set_pri_chan_hdl+0x44>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0a      	bf      	0x30	// 30 <atoi+0x30>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	3807      	cmphsi      	r0, 8
  24:	0806      	bt      	0x30	// 30 <atcmd_set_pri_chan_hdl+0x30>
  26:	7400      	zextb      	r0, r0
  28:	dc040309 	st.b      	r0, (r4, 0x309)
  2c:	e0000000 	bsr      	0x0	// 0 <ah_wphy_pri_channel_cfg>
  30:	d8440309 	ld.b      	r2, (r4, 0x309)
  34:	5d26      	addi      	r1, r5, 2
  36:	1005      	lrw      	r0, 0x0	// 48 <atcmd_set_pri_chan_hdl+0x48>
  38:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  3c:	07e9      	br      	0xe	// e <atcmd_set_pri_chan_hdl+0xe>
	...

Disassembly of section .text.atcmd_edca_cw_hdl:

00000000 <atcmd_edca_cw_hdl>:
   0:	14d4      	push      	r4-r7, r15
   2:	1426      	subi      	r14, r14, 24
   4:	6dc3      	mov      	r7, r0
   6:	6d47      	mov      	r5, r1
   8:	e9220008 	bnez      	r2, 0x18	// 18 <atcmd_edca_cw_hdl+0x18>
   c:	1107      	lrw      	r0, 0x0	// a8 <atcmd_printf+0xa8>
   e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  12:	3000      	movi      	r0, 0
  14:	1406      	addi      	r14, r14, 24
  16:	1494      	pop      	r4-r7, r15
  18:	9100      	ld.w      	r0, (r1, 0x0)
  1a:	8060      	ld.b      	r3, (r0, 0x0)
  1c:	eb43003f 	cmpnei      	r3, 63
  20:	0c1a      	bf      	0x54	// 54 <atcmd_edca_cw_hdl+0x54>
  22:	3a43      	cmpnei      	r2, 3
  24:	083d      	bt      	0x9e	// 9e <atcmd_edca_cw_hdl+0x9e>
  26:	e0000000 	bsr      	0x0	// 0 <atoi>
  2a:	3803      	cmphsi      	r0, 4
  2c:	6d83      	mov      	r6, r0
  2e:	0834      	bt      	0x96	// 96 <atcmd_edca_cw_hdl+0x96>
  30:	9501      	ld.w      	r0, (r5, 0x4)
  32:	e0000000 	bsr      	0x0	// 0 <atoi>
  36:	6d03      	mov      	r4, r0
  38:	e960002b 	blsz      	r0, 0x8e	// 8e <atcmd_edca_cw_hdl+0x8e>
  3c:	9502      	ld.w      	r0, (r5, 0x8)
  3e:	e0000000 	bsr      	0x0	// 0 <atoi>
  42:	6c83      	mov      	r2, r0
  44:	e9600021 	blsz      	r0, 0x86	// 86 <atcmd_edca_cw_hdl+0x86>
  48:	6501      	cmplt      	r0, r4
  4a:	0819      	bt      	0x7c	// 7c <atcmd_edca_cw_hdl+0x7c>
  4c:	6c53      	mov      	r1, r4
  4e:	7418      	zextb      	r0, r6
  50:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_cw_param>
  54:	1036      	lrw      	r1, 0x0	// ac <atcmd_edca_cw_hdl+0xac>
  56:	891f      	ld.h      	r0, (r1, 0x3e)
  58:	897c      	ld.h      	r3, (r1, 0x38)
  5a:	8954      	ld.h      	r2, (r1, 0x28)
  5c:	b805      	st.w      	r0, (r14, 0x14)
  5e:	8917      	ld.h      	r0, (r1, 0x2e)
  60:	b804      	st.w      	r0, (r14, 0x10)
  62:	891e      	ld.h      	r0, (r1, 0x3c)
  64:	b803      	st.w      	r0, (r14, 0xc)
  66:	8916      	ld.h      	r0, (r1, 0x2c)
  68:	b802      	st.w      	r0, (r14, 0x8)
  6a:	891d      	ld.h      	r0, (r1, 0x3a)
  6c:	b801      	st.w      	r0, (r14, 0x4)
  6e:	8935      	ld.h      	r1, (r1, 0x2a)
  70:	b820      	st.w      	r1, (r14, 0x0)
  72:	5f26      	addi      	r1, r7, 2
  74:	100f      	lrw      	r0, 0x0	// b0 <atcmd_edca_cw_hdl+0xb0>
  76:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  7a:	07cc      	br      	0x12	// 12 <atcmd_edca_cw_hdl+0x12>
  7c:	3200      	movi      	r2, 0
  7e:	106e      	lrw      	r3, 0x0	// b4 <atcmd_edca_cw_hdl+0xb4>
  80:	2a04      	subi      	r2, 5
  82:	b352      	st.w      	r2, (r3, 0x48)
  84:	07e8      	br      	0x54	// 54 <atcmd_edca_cw_hdl+0x54>
  86:	3200      	movi      	r2, 0
  88:	106b      	lrw      	r3, 0x0	// b4 <atcmd_edca_cw_hdl+0xb4>
  8a:	2a03      	subi      	r2, 4
  8c:	07fb      	br      	0x82	// 82 <atcmd_edca_cw_hdl+0x82>
  8e:	3200      	movi      	r2, 0
  90:	1069      	lrw      	r3, 0x0	// b4 <atcmd_edca_cw_hdl+0xb4>
  92:	2a02      	subi      	r2, 3
  94:	07f7      	br      	0x82	// 82 <atcmd_edca_cw_hdl+0x82>
  96:	3200      	movi      	r2, 0
  98:	1067      	lrw      	r3, 0x0	// b4 <atcmd_edca_cw_hdl+0xb4>
  9a:	2a01      	subi      	r2, 2
  9c:	07f3      	br      	0x82	// 82 <atcmd_edca_cw_hdl+0x82>
  9e:	3200      	movi      	r2, 0
  a0:	1065      	lrw      	r3, 0x0	// b4 <atcmd_edca_cw_hdl+0xb4>
  a2:	2a00      	subi      	r2, 1
  a4:	07ef      	br      	0x82	// 82 <atcmd_edca_cw_hdl+0x82>
	...

Disassembly of section .text.atcmd_edca_aifs_hdl:

00000000 <atcmd_edca_aifs_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	1422      	subi      	r14, r14, 8
   4:	6d83      	mov      	r6, r0
   6:	6d47      	mov      	r5, r1
   8:	e9220008 	bnez      	r2, 0x18	// 18 <atcmd_edca_aifs_hdl+0x18>
   c:	101a      	lrw      	r0, 0x0	// 74 <atcmd_printf+0x74>
   e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  12:	3000      	movi      	r0, 0
  14:	1402      	addi      	r14, r14, 8
  16:	1493      	pop      	r4-r6, r15
  18:	9100      	ld.w      	r0, (r1, 0x0)
  1a:	8060      	ld.b      	r3, (r0, 0x0)
  1c:	eb43003f 	cmpnei      	r3, 63
  20:	0c11      	bf      	0x42	// 42 <atcmd_edca_aifs_hdl+0x42>
  22:	3a42      	cmpnei      	r2, 2
  24:	0824      	bt      	0x6c	// 6c <atcmd_edca_aifs_hdl+0x6c>
  26:	e0000000 	bsr      	0x0	// 0 <atoi>
  2a:	3803      	cmphsi      	r0, 4
  2c:	6d03      	mov      	r4, r0
  2e:	081b      	bt      	0x64	// 64 <atcmd_edca_aifs_hdl+0x64>
  30:	9501      	ld.w      	r0, (r5, 0x4)
  32:	e0000000 	bsr      	0x0	// 0 <atoi>
  36:	6c43      	mov      	r1, r0
  38:	e9600011 	blsz      	r0, 0x5a	// 5a <atcmd_edca_aifs_hdl+0x5a>
  3c:	7410      	zextb      	r0, r4
  3e:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_aifs_param>
  42:	102e      	lrw      	r1, 0x0	// 78 <atcmd_edca_aifs_hdl+0x78>
  44:	811f      	ld.b      	r0, (r1, 0x1f)
  46:	817d      	ld.b      	r3, (r1, 0x1d)
  48:	815c      	ld.b      	r2, (r1, 0x1c)
  4a:	b801      	st.w      	r0, (r14, 0x4)
  4c:	813e      	ld.b      	r1, (r1, 0x1e)
  4e:	b820      	st.w      	r1, (r14, 0x0)
  50:	5e26      	addi      	r1, r6, 2
  52:	100b      	lrw      	r0, 0x0	// 7c <atcmd_edca_aifs_hdl+0x7c>
  54:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  58:	07dd      	br      	0x12	// 12 <atcmd_edca_aifs_hdl+0x12>
  5a:	3200      	movi      	r2, 0
  5c:	1069      	lrw      	r3, 0x0	// 80 <atcmd_edca_aifs_hdl+0x80>
  5e:	2a02      	subi      	r2, 3
  60:	b352      	st.w      	r2, (r3, 0x48)
  62:	07f0      	br      	0x42	// 42 <atcmd_edca_aifs_hdl+0x42>
  64:	3200      	movi      	r2, 0
  66:	1067      	lrw      	r3, 0x0	// 80 <atcmd_edca_aifs_hdl+0x80>
  68:	2a01      	subi      	r2, 2
  6a:	07fb      	br      	0x60	// 60 <atcmd_edca_aifs_hdl+0x60>
  6c:	3200      	movi      	r2, 0
  6e:	1065      	lrw      	r3, 0x0	// 80 <atcmd_edca_aifs_hdl+0x80>
  70:	2a00      	subi      	r2, 1
  72:	07f7      	br      	0x60	// 60 <atcmd_edca_aifs_hdl+0x60>
	...

Disassembly of section .text.atcmd_edca_txop_hdl:

00000000 <atcmd_edca_txop_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	1422      	subi      	r14, r14, 8
   4:	6d43      	mov      	r5, r0
   6:	6d87      	mov      	r6, r1
   8:	e9220008 	bnez      	r2, 0x18	// 18 <atcmd_edca_txop_hdl+0x18>
   c:	1100      	lrw      	r0, 0x0	// 8c <atcmd_printf+0x8c>
   e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  12:	3000      	movi      	r0, 0
  14:	1402      	addi      	r14, r14, 8
  16:	1493      	pop      	r4-r6, r15
  18:	9100      	ld.w      	r0, (r1, 0x0)
  1a:	8060      	ld.b      	r3, (r0, 0x0)
  1c:	eb43003f 	cmpnei      	r3, 63
  20:	0c12      	bf      	0x44	// 44 <atcmd_edca_txop_hdl+0x44>
  22:	3a42      	cmpnei      	r2, 2
  24:	0830      	bt      	0x84	// 84 <atcmd_edca_txop_hdl+0x84>
  26:	e0000000 	bsr      	0x0	// 0 <atoi>
  2a:	3803      	cmphsi      	r0, 4
  2c:	6d03      	mov      	r4, r0
  2e:	0827      	bt      	0x7c	// 7c <atcmd_edca_txop_hdl+0x7c>
  30:	9601      	ld.w      	r0, (r6, 0x4)
  32:	e0000000 	bsr      	0x0	// 0 <atoi>
  36:	eb00fffe 	cmphsi      	r0, 65535
  3a:	081c      	bt      	0x72	// 72 <atcmd_edca_txop_hdl+0x72>
  3c:	7441      	zexth      	r1, r0
  3e:	7410      	zextb      	r0, r4
  40:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_txop_param>
  44:	1033      	lrw      	r1, 0x0	// 90 <atcmd_edca_txop_hdl+0x90>
  46:	32fa      	movi      	r2, 250
  48:	4242      	lsli      	r2, r2, 2
  4a:	9113      	ld.w      	r0, (r1, 0x4c)
  4c:	c4408020 	divu      	r0, r0, r2
  50:	d9812010 	ld.w      	r12, (r1, 0x40)
  54:	9171      	ld.w      	r3, (r1, 0x44)
  56:	b801      	st.w      	r0, (r14, 0x4)
  58:	9132      	ld.w      	r1, (r1, 0x48)
  5a:	c4418021 	divu      	r1, r1, r2
  5e:	b820      	st.w      	r1, (r14, 0x0)
  60:	c4438023 	divu      	r3, r3, r2
  64:	5d26      	addi      	r1, r5, 2
  66:	c44c8022 	divu      	r2, r12, r2
  6a:	100b      	lrw      	r0, 0x0	// 94 <atcmd_printf+0x94>
  6c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  70:	07d1      	br      	0x12	// 12 <atcmd_edca_txop_hdl+0x12>
  72:	3200      	movi      	r2, 0
  74:	1069      	lrw      	r3, 0x0	// 98 <atcmd_edca_txop_hdl+0x98>
  76:	2a02      	subi      	r2, 3
  78:	b352      	st.w      	r2, (r3, 0x48)
  7a:	07e5      	br      	0x44	// 44 <atcmd_edca_txop_hdl+0x44>
  7c:	3200      	movi      	r2, 0
  7e:	1067      	lrw      	r3, 0x0	// 98 <atcmd_edca_txop_hdl+0x98>
  80:	2a01      	subi      	r2, 2
  82:	07fb      	br      	0x78	// 78 <atcmd_edca_txop_hdl+0x78>
  84:	3200      	movi      	r2, 0
  86:	1065      	lrw      	r3, 0x0	// 98 <atcmd_edca_txop_hdl+0x98>
  88:	2a00      	subi      	r2, 1
  8a:	07f7      	br      	0x78	// 78 <atcmd_edca_txop_hdl+0x78>
	...

Disassembly of section .text.atcmd_tx_trv_pilot_en_hdl:

00000000 <atcmd_tx_trv_pilot_en_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_trv_pilot_en_hdl+0x12>
   8:	1011      	lrw      	r0, 0x0	// 4c <atcmd_printf+0x4c>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108f      	lrw      	r4, 0x0	// 50 <atcmd_tx_trv_pilot_en_hdl+0x50>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c08      	bf      	0x2c	// 2c <atoi+0x2c>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	e9000011 	bez      	r0, 0x44	// 44 <atcmd_tx_trv_pilot_en_hdl+0x44>
  26:	3301      	movi      	r3, 1
  28:	dc6403e4 	st.b      	r3, (r4, 0x3e4)
  2c:	d86403e4 	ld.b      	r3, (r4, 0x3e4)
  30:	3b40      	cmpnei      	r3, 0
  32:	1049      	lrw      	r2, 0x0	// 54 <atcmd_tx_trv_pilot_en_hdl+0x54>
  34:	1069      	lrw      	r3, 0x0	// 58 <atcmd_tx_trv_pilot_en_hdl+0x58>
  36:	c4430c20 	incf      	r2, r3, 0
  3a:	5d26      	addi      	r1, r5, 2
  3c:	1008      	lrw      	r0, 0x0	// 5c <atcmd_tx_trv_pilot_en_hdl+0x5c>
  3e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  42:	07e6      	br      	0xe	// e <atcmd_tx_trv_pilot_en_hdl+0xe>
  44:	dc0403e4 	st.b      	r0, (r4, 0x3e4)
  48:	07f2      	br      	0x2c	// 2c <atcmd_tx_trv_pilot_en_hdl+0x2c>
	...

Disassembly of section .text.atcmd_evm_margin_hdl:

00000000 <atcmd_evm_margin_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_evm_margin_hdl+0x12>
   8:	100b      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1089      	lrw      	r4, 0x0	// 38 <atcmd_evm_margin_hdl+0x38>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c05      	bf      	0x26	// 26 <atoi+0x26>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	dc040870 	st.b      	r0, (r4, 0x870)
  26:	d8444870 	ld.bs      	r2, (r4, 0x870)
  2a:	5d26      	addi      	r1, r5, 2
  2c:	1004      	lrw      	r0, 0x0	// 3c <atcmd_evm_margin_hdl+0x3c>
  2e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  32:	07ee      	br      	0xe	// e <atcmd_evm_margin_hdl+0xe>
	...

Disassembly of section .text.atcmd_ccmp_support_hdl:

00000000 <atcmd_ccmp_support_hdl>:
   0:	14d0      	push      	r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_ccmp_support_hdl+0x10>
   6:	1018      	lrw      	r0, 0x0	// 64 <atcmd_printf+0x64>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	8340      	ld.b      	r2, (r3, 0x0)
  14:	eb420031 	cmpnei      	r2, 49
  18:	1074      	lrw      	r3, 0x0	// 68 <atcmd_ccmp_support_hdl+0x68>
  1a:	0c1c      	bf      	0x52	// 52 <atcmd_ccmp_support_hdl+0x52>
  1c:	eb42003f 	cmpnei      	r2, 63
  20:	0c0b      	bf      	0x36	// 36 <atcmd_ccmp_support_hdl+0x36>
  22:	eb420030 	cmpnei      	r2, 48
  26:	081a      	bt      	0x5a	// 5a <atcmd_ccmp_support_hdl+0x5a>
  28:	d8430336 	ld.b      	r2, (r3, 0x336)
  2c:	3100      	movi      	r1, 0
  2e:	c4415c00 	ins      	r2, r1, 0, 0
  32:	dc430336 	st.b      	r2, (r3, 0x336)
  36:	d8630336 	ld.b      	r3, (r3, 0x336)
  3a:	e4632001 	andi      	r3, r3, 1
  3e:	3b40      	cmpnei      	r3, 0
  40:	104b      	lrw      	r2, 0x0	// 6c <atcmd_ccmp_support_hdl+0x6c>
  42:	106c      	lrw      	r3, 0x0	// 70 <atcmd_ccmp_support_hdl+0x70>
  44:	5826      	addi      	r1, r0, 2
  46:	c4430c20 	incf      	r2, r3, 0
  4a:	100b      	lrw      	r0, 0x0	// 74 <atcmd_printf+0x74>
  4c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  50:	07de      	br      	0xc	// c <atcmd_ccmp_support_hdl+0xc>
  52:	d8430336 	ld.b      	r2, (r3, 0x336)
  56:	3101      	movi      	r1, 1
  58:	07eb      	br      	0x2e	// 2e <atcmd_ccmp_support_hdl+0x2e>
  5a:	1048      	lrw      	r2, 0x0	// 78 <atcmd_ccmp_support_hdl+0x78>
  5c:	3100      	movi      	r1, 0
  5e:	2900      	subi      	r1, 1
  60:	b232      	st.w      	r1, (r2, 0x48)
  62:	07ea      	br      	0x36	// 36 <atcmd_ccmp_support_hdl+0x36>
	...

Disassembly of section .text.atcmd_lmac_print_period_hdl:

00000000 <atcmd_lmac_print_period_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_lmac_print_period_hdl+0x12>
   8:	100f      	lrw      	r0, 0x0	// 44 <atcmd_printf+0x44>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108d      	lrw      	r4, 0x0	// 48 <atcmd_lmac_print_period_hdl+0x48>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c07      	bf      	0x2a	// 2a <atoi+0x2a>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	e980000b 	blz      	r0, 0x38	// 38 <atcmd_lmac_print_period_hdl+0x38>
  26:	dc0420e6 	st.w      	r0, (r4, 0x398)
  2a:	d84420e6 	ld.w      	r2, (r4, 0x398)
  2e:	5d26      	addi      	r1, r5, 2
  30:	1007      	lrw      	r0, 0x0	// 4c <atcmd_lmac_print_period_hdl+0x4c>
  32:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  36:	07ec      	br      	0xe	// e <atcmd_lmac_print_period_hdl+0xe>
  38:	1066      	lrw      	r3, 0x0	// 50 <atcmd_lmac_print_period_hdl+0x50>
  3a:	3200      	movi      	r2, 0
  3c:	2a00      	subi      	r2, 1
  3e:	b352      	st.w      	r2, (r3, 0x48)
  40:	07f5      	br      	0x2a	// 2a <atcmd_lmac_print_period_hdl+0x2a>
	...

Disassembly of section .text.atcmd_tx_pkts_rd_hdl:

00000000 <atcmd_tx_pkts_rd_hdl>:
   0:	14d0      	push      	r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_tx_pkts_rd_hdl+0x10>
   6:	100c      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	8360      	ld.b      	r3, (r3, 0x0)
  14:	eb43003f 	cmpnei      	r3, 63
  18:	0c05      	bf      	0x22	// 22 <atcmd_tx_pkts_rd_hdl+0x22>
  1a:	1068      	lrw      	r3, 0x0	// 38 <atcmd_tx_pkts_rd_hdl+0x38>
  1c:	3200      	movi      	r2, 0
  1e:	2a00      	subi      	r2, 1
  20:	b352      	st.w      	r2, (r3, 0x48)
  22:	1067      	lrw      	r3, 0x0	// 3c <atcmd_tx_pkts_rd_hdl+0x3c>
  24:	5826      	addi      	r1, r0, 2
  26:	d84321b8 	ld.w      	r2, (r3, 0x6e0)
  2a:	1006      	lrw      	r0, 0x0	// 40 <atcmd_printf+0x40>
  2c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  30:	07ee      	br      	0xc	// c <atcmd_tx_pkts_rd_hdl+0xc>
	...

Disassembly of section .text.atcmd_tx_fail_rd_hdl:

00000000 <atcmd_tx_fail_rd_hdl>:
   0:	14d0      	push      	r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_tx_fail_rd_hdl+0x10>
   6:	100c      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	8360      	ld.b      	r3, (r3, 0x0)
  14:	eb43003f 	cmpnei      	r3, 63
  18:	0c05      	bf      	0x22	// 22 <atcmd_tx_fail_rd_hdl+0x22>
  1a:	1068      	lrw      	r3, 0x0	// 38 <atcmd_tx_fail_rd_hdl+0x38>
  1c:	3200      	movi      	r2, 0
  1e:	2a00      	subi      	r2, 1
  20:	b352      	st.w      	r2, (r3, 0x48)
  22:	1067      	lrw      	r3, 0x0	// 3c <atcmd_tx_fail_rd_hdl+0x3c>
  24:	5826      	addi      	r1, r0, 2
  26:	d84321b9 	ld.w      	r2, (r3, 0x6e4)
  2a:	1006      	lrw      	r0, 0x0	// 40 <atcmd_printf+0x40>
  2c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  30:	07ee      	br      	0xc	// c <atcmd_tx_fail_rd_hdl+0xc>
	...

Disassembly of section .text.atcmd_rx_rssi_rd_hdl:

00000000 <atcmd_rx_rssi_rd_hdl>:
   0:	14d0      	push      	r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_rx_rssi_rd_hdl+0x10>
   6:	100c      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	8360      	ld.b      	r3, (r3, 0x0)
  14:	eb43003f 	cmpnei      	r3, 63
  18:	0c05      	bf      	0x22	// 22 <atcmd_rx_rssi_rd_hdl+0x22>
  1a:	1068      	lrw      	r3, 0x0	// 38 <atcmd_rx_rssi_rd_hdl+0x38>
  1c:	3200      	movi      	r2, 0
  1e:	2a00      	subi      	r2, 1
  20:	b352      	st.w      	r2, (r3, 0x48)
  22:	1067      	lrw      	r3, 0x0	// 3c <atcmd_rx_rssi_rd_hdl+0x3c>
  24:	5826      	addi      	r1, r0, 2
  26:	d84321be 	ld.w      	r2, (r3, 0x6f8)
  2a:	1006      	lrw      	r0, 0x0	// 40 <atcmd_printf+0x40>
  2c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  30:	07ee      	br      	0xc	// c <atcmd_rx_rssi_rd_hdl+0xc>
	...

Disassembly of section .text.atcmd_rx_evm_rd_hdl:

00000000 <atcmd_rx_evm_rd_hdl>:
   0:	14d0      	push      	r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_rx_evm_rd_hdl+0x10>
   6:	100c      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	8360      	ld.b      	r3, (r3, 0x0)
  14:	eb43003f 	cmpnei      	r3, 63
  18:	0c05      	bf      	0x22	// 22 <atcmd_rx_evm_rd_hdl+0x22>
  1a:	1068      	lrw      	r3, 0x0	// 38 <atcmd_rx_evm_rd_hdl+0x38>
  1c:	3200      	movi      	r2, 0
  1e:	2a00      	subi      	r2, 1
  20:	b352      	st.w      	r2, (r3, 0x48)
  22:	1067      	lrw      	r3, 0x0	// 3c <atcmd_rx_evm_rd_hdl+0x3c>
  24:	5826      	addi      	r1, r0, 2
  26:	d84321bf 	ld.w      	r2, (r3, 0x6fc)
  2a:	1006      	lrw      	r0, 0x0	// 40 <atcmd_printf+0x40>
  2c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  30:	07ee      	br      	0xc	// c <atcmd_rx_evm_rd_hdl+0xc>
	...

Disassembly of section .text.atcmd_rx_pkts_rd_hdl:

00000000 <atcmd_rx_pkts_rd_hdl>:
   0:	14d0      	push      	r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_rx_pkts_rd_hdl+0x10>
   6:	100c      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	8360      	ld.b      	r3, (r3, 0x0)
  14:	eb43003f 	cmpnei      	r3, 63
  18:	0c05      	bf      	0x22	// 22 <atcmd_rx_pkts_rd_hdl+0x22>
  1a:	1068      	lrw      	r3, 0x0	// 38 <atcmd_rx_pkts_rd_hdl+0x38>
  1c:	3200      	movi      	r2, 0
  1e:	2a00      	subi      	r2, 1
  20:	b352      	st.w      	r2, (r3, 0x48)
  22:	1067      	lrw      	r3, 0x0	// 3c <atcmd_rx_pkts_rd_hdl+0x3c>
  24:	5826      	addi      	r1, r0, 2
  26:	d84321bc 	ld.w      	r2, (r3, 0x6f0)
  2a:	1006      	lrw      	r0, 0x0	// 40 <atcmd_printf+0x40>
  2c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  30:	07ee      	br      	0xc	// c <atcmd_rx_pkts_rd_hdl+0xc>
	...

Disassembly of section .text.atcmd_rx_err_rd_hdl:

00000000 <atcmd_rx_err_rd_hdl>:
   0:	14d0      	push      	r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_rx_err_rd_hdl+0x10>
   6:	100c      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	8360      	ld.b      	r3, (r3, 0x0)
  14:	eb43003f 	cmpnei      	r3, 63
  18:	0c05      	bf      	0x22	// 22 <atcmd_rx_err_rd_hdl+0x22>
  1a:	1068      	lrw      	r3, 0x0	// 38 <atcmd_rx_err_rd_hdl+0x38>
  1c:	3200      	movi      	r2, 0
  1e:	2a00      	subi      	r2, 1
  20:	b352      	st.w      	r2, (r3, 0x48)
  22:	1067      	lrw      	r3, 0x0	// 3c <atcmd_rx_err_rd_hdl+0x3c>
  24:	5826      	addi      	r1, r0, 2
  26:	d84321bd 	ld.w      	r2, (r3, 0x6f4)
  2a:	1006      	lrw      	r0, 0x0	// 40 <atcmd_printf+0x40>
  2c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  30:	07ee      	br      	0xc	// c <atcmd_rx_err_rd_hdl+0xc>
	...

Disassembly of section .text.atcmd_rx_agc_rd_hdl:

00000000 <atcmd_rx_agc_rd_hdl>:
   0:	14d0      	push      	r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_rx_agc_rd_hdl+0x10>
   6:	100c      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	8360      	ld.b      	r3, (r3, 0x0)
  14:	eb43003f 	cmpnei      	r3, 63
  18:	0c05      	bf      	0x22	// 22 <atcmd_rx_agc_rd_hdl+0x22>
  1a:	1068      	lrw      	r3, 0x0	// 38 <atcmd_rx_agc_rd_hdl+0x38>
  1c:	3200      	movi      	r2, 0
  1e:	2a00      	subi      	r2, 1
  20:	b352      	st.w      	r2, (r3, 0x48)
  22:	1067      	lrw      	r3, 0x0	// 3c <atcmd_rx_agc_rd_hdl+0x3c>
  24:	5826      	addi      	r1, r0, 2
  26:	d84321c1 	ld.w      	r2, (r3, 0x704)
  2a:	1006      	lrw      	r0, 0x0	// 40 <atcmd_printf+0x40>
  2c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  30:	07ee      	br      	0xc	// c <atcmd_rx_agc_rd_hdl+0xc>
	...

Disassembly of section .text.atcmd_bus_wt_hdl:

00000000 <atcmd_bus_wt_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_bus_wt_hdl+0x10>
   6:	1107      	lrw      	r0, 0x0	// a0 <atcmd_printf+0xa0>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1493      	pop      	r4-r6, r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	58a6      	addi      	r5, r0, 2
  14:	8360      	ld.b      	r3, (r3, 0x0)
  16:	eb430031 	cmpnei      	r3, 49
  1a:	1183      	lrw      	r4, 0x0	// a4 <atcmd_bus_wt_hdl+0xa4>
  1c:	0c1d      	bf      	0x56	// 56 <atcmd_bus_wt_hdl+0x56>
  1e:	eb43003f 	cmpnei      	r3, 63
  22:	0c0f      	bf      	0x40	// 40 <atcmd_bus_wt_hdl+0x40>
  24:	eb430030 	cmpnei      	r3, 48
  28:	0835      	bt      	0x92	// 92 <atcmd_bus_wt_hdl+0x92>
  2a:	8461      	ld.b      	r3, (r4, 0x1)
  2c:	3600      	movi      	r6, 0
  2e:	9408      	ld.w      	r0, (r4, 0x20)
  30:	c4665c02 	ins      	r3, r6, 2, 2
  34:	a461      	st.b      	r3, (r4, 0x1)
  36:	e9000032 	bez      	r0, 0x9a	// 9a <atcmd_bus_wt_hdl+0x9a>
  3a:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
  3e:	b4c8      	st.w      	r6, (r4, 0x20)
  40:	9468      	ld.w      	r3, (r4, 0x20)
  42:	3b40      	cmpnei      	r3, 0
  44:	1059      	lrw      	r2, 0x0	// a8 <atcmd_bus_wt_hdl+0xa8>
  46:	107a      	lrw      	r3, 0x0	// ac <atcmd_bus_wt_hdl+0xac>
  48:	c4430c20 	incf      	r2, r3, 0
  4c:	6c57      	mov      	r1, r5
  4e:	1019      	lrw      	r0, 0x0	// b0 <atcmd_bus_wt_hdl+0xb0>
  50:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  54:	07dc      	br      	0xc	// c <atcmd_bus_wt_hdl+0xc>
  56:	1078      	lrw      	r3, 0x0	// b4 <atcmd_bus_wt_hdl+0xb4>
  58:	d86309e2 	ld.b      	r3, (r3, 0x9e2)
  5c:	e4632002 	andi      	r3, r3, 2
  60:	e903fff0 	bez      	r3, 0x40	// 40 <atcmd_bus_wt_hdl+0x40>
  64:	ea0006b4 	movi      	r0, 1716
  68:	e0000000 	bsr      	0x0	// 0 <alloc_tx_skb>
  6c:	b408      	st.w      	r0, (r4, 0x20)
  6e:	e9000016 	bez      	r0, 0x9a	// 9a <atcmd_bus_wt_hdl+0x9a>
  72:	d840002a 	ld.b      	r2, (r0, 0x2a)
  76:	3601      	movi      	r6, 1
  78:	c4465c06 	ins      	r2, r6, 6, 6
  7c:	3180      	movi      	r1, 128
  7e:	dc40002a 	st.b      	r2, (r0, 0x2a)
  82:	7058      	lsl      	r1, r6
  84:	e0000000 	bsr      	0x0	// 0 <skb_reserve>
  88:	8461      	ld.b      	r3, (r4, 0x1)
  8a:	c4665c02 	ins      	r3, r6, 2, 2
  8e:	a461      	st.b      	r3, (r4, 0x1)
  90:	07d8      	br      	0x40	// 40 <atcmd_bus_wt_hdl+0x40>
  92:	3300      	movi      	r3, 0
  94:	2b00      	subi      	r3, 1
  96:	b472      	st.w      	r3, (r4, 0x48)
  98:	07d4      	br      	0x40	// 40 <atcmd_bus_wt_hdl+0x40>
  9a:	1045      	lrw      	r2, 0x0	// ac <atcmd_bus_wt_hdl+0xac>
  9c:	07d8      	br      	0x4c	// 4c <atcmd_bus_wt_hdl+0x4c>
	...

Disassembly of section .text.atcmd_nor_rd_hdl:

00000000 <atcmd_nor_rd_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_nor_rd_hdl+0x12>
   8:	101c      	lrw      	r0, 0x0	// 78 <atcmd_printf+0x78>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9160      	ld.w      	r3, (r1, 0x0)
  14:	109a      	lrw      	r4, 0x0	// 7c <atcmd_nor_rd_hdl+0x7c>
  16:	8360      	ld.b      	r3, (r3, 0x0)
  18:	eb430031 	cmpnei      	r3, 49
  1c:	0c19      	bf      	0x4e	// 4e <atcmd_nor_rd_hdl+0x4e>
  1e:	eb43003f 	cmpnei      	r3, 63
  22:	0c09      	bf      	0x34	// 34 <atcmd_nor_rd_hdl+0x34>
  24:	eb430030 	cmpnei      	r3, 48
  28:	0823      	bt      	0x6e	// 6e <atcmd_nor_rd_hdl+0x6e>
  2a:	8461      	ld.b      	r3, (r4, 0x1)
  2c:	3200      	movi      	r2, 0
  2e:	c4625c03 	ins      	r3, r2, 3, 3
  32:	a461      	st.b      	r3, (r4, 0x1)
  34:	8461      	ld.b      	r3, (r4, 0x1)
  36:	e4632008 	andi      	r3, r3, 8
  3a:	3b40      	cmpnei      	r3, 0
  3c:	1051      	lrw      	r2, 0x0	// 80 <atcmd_nor_rd_hdl+0x80>
  3e:	1072      	lrw      	r3, 0x0	// 84 <atcmd_nor_rd_hdl+0x84>
  40:	c4430c20 	incf      	r2, r3, 0
  44:	5d26      	addi      	r1, r5, 2
  46:	1011      	lrw      	r0, 0x0	// 88 <atcmd_nor_rd_hdl+0x88>
  48:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4c:	07e1      	br      	0xe	// e <atcmd_nor_rd_hdl+0xe>
  4e:	1070      	lrw      	r3, 0x0	// 8c <atcmd_nor_rd_hdl+0x8c>
  50:	d86309e2 	ld.b      	r3, (r3, 0x9e2)
  54:	e4632002 	andi      	r3, r3, 2
  58:	e903ffee 	bez      	r3, 0x34	// 34 <atcmd_nor_rd_hdl+0x34>
  5c:	9402      	ld.w      	r0, (r4, 0x8)
  5e:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  62:	b401      	st.w      	r0, (r4, 0x4)
  64:	e900ffe8 	bez      	r0, 0x34	// 34 <atcmd_nor_rd_hdl+0x34>
  68:	8461      	ld.b      	r3, (r4, 0x1)
  6a:	3201      	movi      	r2, 1
  6c:	07e1      	br      	0x2e	// 2e <atcmd_nor_rd_hdl+0x2e>
  6e:	3300      	movi      	r3, 0
  70:	2b00      	subi      	r3, 1
  72:	b472      	st.w      	r3, (r4, 0x48)
  74:	07e0      	br      	0x34	// 34 <atcmd_nor_rd_hdl+0x34>
	...

Disassembly of section .text.atcmd_cs_num_hdl:

00000000 <atcmd_cs_num_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_cs_num_hdl+0x12>
   8:	100b      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1089      	lrw      	r4, 0x0	// 38 <atcmd_cs_num_hdl+0x38>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c05      	bf      	0x26	// 26 <atoi+0x26>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	dc040348 	st.b      	r0, (r4, 0x348)
  26:	d8440348 	ld.b      	r2, (r4, 0x348)
  2a:	5d26      	addi      	r1, r5, 2
  2c:	1004      	lrw      	r0, 0x0	// 3c <atcmd_cs_num_hdl+0x3c>
  2e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  32:	07ee      	br      	0xe	// e <atcmd_cs_num_hdl+0xe>
	...

Disassembly of section .text.atcmd_cs_cnt_hdl:

00000000 <atcmd_cs_cnt_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_cs_cnt_hdl+0x12>
   8:	100b      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1089      	lrw      	r4, 0x0	// 38 <atcmd_cs_cnt_hdl+0x38>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c05      	bf      	0x26	// 26 <atoi+0x26>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	dc04032a 	st.b      	r0, (r4, 0x32a)
  26:	d844432a 	ld.bs      	r2, (r4, 0x32a)
  2a:	5d26      	addi      	r1, r5, 2
  2c:	1004      	lrw      	r0, 0x0	// 3c <atcmd_cs_cnt_hdl+0x3c>
  2e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  32:	07ee      	br      	0xe	// e <atcmd_cs_cnt_hdl+0xe>
	...

Disassembly of section .text.atcmd_chan_scan_hdl:

00000000 <atcmd_chan_scan_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_chan_scan_hdl+0x12>
   8:	1011      	lrw      	r0, 0x0	// 4c <atcmd_printf+0x4c>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108f      	lrw      	r4, 0x0	// 50 <atcmd_chan_scan_hdl+0x50>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c09      	bf      	0x2e	// 2e <atoi+0x2e>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d864037c 	ld.b      	r3, (r4, 0x37c)
  26:	c4605c00 	ins      	r3, r0, 0, 0
  2a:	dc64037c 	st.b      	r3, (r4, 0x37c)
  2e:	d864037c 	ld.b      	r3, (r4, 0x37c)
  32:	e4632001 	andi      	r3, r3, 1
  36:	3b40      	cmpnei      	r3, 0
  38:	1047      	lrw      	r2, 0x0	// 54 <atcmd_chan_scan_hdl+0x54>
  3a:	1068      	lrw      	r3, 0x0	// 58 <atcmd_chan_scan_hdl+0x58>
  3c:	c4430c20 	incf      	r2, r3, 0
  40:	5d26      	addi      	r1, r5, 2
  42:	1007      	lrw      	r0, 0x0	// 5c <atcmd_chan_scan_hdl+0x5c>
  44:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  48:	07e3      	br      	0xe	// e <atcmd_chan_scan_hdl+0xe>
	...

Disassembly of section .text.atcmd_cs_enable_hdl:

00000000 <atcmd_cs_enable_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_cs_enable_hdl+0x12>
   8:	1011      	lrw      	r0, 0x0	// 4c <atcmd_printf+0x4c>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108f      	lrw      	r4, 0x0	// 50 <atcmd_cs_enable_hdl+0x50>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c09      	bf      	0x2e	// 2e <atoi+0x2e>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d864037c 	ld.b      	r3, (r4, 0x37c)
  26:	c4605c01 	ins      	r3, r0, 1, 1
  2a:	dc64037c 	st.b      	r3, (r4, 0x37c)
  2e:	d864037c 	ld.b      	r3, (r4, 0x37c)
  32:	e4632002 	andi      	r3, r3, 2
  36:	3b40      	cmpnei      	r3, 0
  38:	1047      	lrw      	r2, 0x0	// 54 <atcmd_cs_enable_hdl+0x54>
  3a:	1068      	lrw      	r3, 0x0	// 58 <atcmd_cs_enable_hdl+0x58>
  3c:	c4430c20 	incf      	r2, r3, 0
  40:	5d26      	addi      	r1, r5, 2
  42:	1007      	lrw      	r0, 0x0	// 5c <atcmd_cs_enable_hdl+0x5c>
  44:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  48:	07e3      	br      	0xe	// e <atcmd_cs_enable_hdl+0xe>
	...

Disassembly of section .text.atcmd_cs_th_hdl:

00000000 <atcmd_cs_th_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_cs_th_hdl+0x12>
   8:	100e      	lrw      	r0, 0x0	// 40 <atcmd_printf+0x40>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108c      	lrw      	r4, 0x0	// 44 <atcmd_cs_th_hdl+0x44>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c09      	bf      	0x2e	// 2e <atoi+0x2e>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d86411be 	ld.h      	r3, (r4, 0x37c)
  26:	c4605ce2 	ins      	r3, r0, 9, 2
  2a:	dc6411be 	st.h      	r3, (r4, 0x37c)
  2e:	d84411be 	ld.h      	r2, (r4, 0x37c)
  32:	c4425522 	zext      	r2, r2, 9, 2
  36:	5d26      	addi      	r1, r5, 2
  38:	1004      	lrw      	r0, 0x0	// 48 <atcmd_cs_th_hdl+0x48>
  3a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  3e:	07e8      	br      	0xe	// e <atcmd_cs_th_hdl+0xe>
	...

Disassembly of section .text.atcmd_cs_period_hdl:

00000000 <atcmd_cs_period_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_cs_period_hdl+0x12>
   8:	100b      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1089      	lrw      	r4, 0x0	// 38 <atcmd_cs_period_hdl+0x38>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c05      	bf      	0x26	// 26 <atoi+0x26>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	dc0420e4 	st.w      	r0, (r4, 0x390)
  26:	d84420e4 	ld.w      	r2, (r4, 0x390)
  2a:	5d26      	addi      	r1, r5, 2
  2c:	1004      	lrw      	r0, 0x0	// 3c <atcmd_cs_period_hdl+0x3c>
  2e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  32:	07ee      	br      	0xe	// e <atcmd_cs_period_hdl+0xe>
	...

Disassembly of section .text.atcmd_acs_start_hdl:

00000000 <atcmd_acs_start_hdl>:
   0:	14d5      	push      	r4-r8, r15
   2:	6d43      	mov      	r5, r0
   4:	6dc7      	mov      	r7, r1
   6:	6e0b      	mov      	r8, r2
   8:	e9220007 	bnez      	r2, 0x16	// 16 <atcmd_acs_start_hdl+0x16>
   c:	1107      	lrw      	r0, 0x0	// a8 <atcmd_printf+0xa8>
   e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  12:	3000      	movi      	r0, 0
  14:	1495      	pop      	r4-r8, r15
  16:	9100      	ld.w      	r0, (r1, 0x0)
  18:	1185      	lrw      	r4, 0x0	// ac <atcmd_acs_start_hdl+0xac>
  1a:	8060      	ld.b      	r3, (r0, 0x0)
  1c:	eb43003f 	cmpnei      	r3, 63
  20:	0c2e      	bf      	0x7c	// 7c <atoi+0x7c>
  22:	e0000000 	bsr      	0x0	// 0 <atoi>
  26:	eb080001 	cmphsi      	r8, 2
  2a:	6d83      	mov      	r6, r0
  2c:	0c08      	bf      	0x3c	// 3c <atcmd_acs_start_hdl+0x3c>
  2e:	9701      	ld.w      	r0, (r7, 0x4)
  30:	e0000000 	bsr      	0x0	// 0 <atoi>
  34:	e9000004 	bez      	r0, 0x3c	// 3c <atcmd_acs_start_hdl+0x3c>
  38:	dc0420d7 	st.w      	r0, (r4, 0x35c)
  3c:	d86409e0 	ld.b      	r3, (r4, 0x9e0)
  40:	e906002e 	bez      	r6, 0x9c	// 9c <atcmd_acs_start_hdl+0x9c>
  44:	3101      	movi      	r1, 1
  46:	c4615c00 	ins      	r3, r1, 0, 0
  4a:	d84422a1 	ld.w      	r2, (r4, 0xa84)
  4e:	d80422a2 	ld.w      	r0, (r4, 0xa88)
  52:	dc6409e0 	st.b      	r3, (r4, 0x9e0)
  56:	5a64      	addu      	r3, r2, r1
  58:	640d      	cmplt      	r3, r0
  5a:	c403008c 	subu      	r12, r3, r0
  5e:	c46c0c20 	incf      	r3, r12, 0
  62:	d80422a0 	ld.w      	r0, (r4, 0xa80)
  66:	640e      	cmpne      	r3, r0
  68:	0c07      	bf      	0x76	// 76 <atcmd_acs_start_hdl+0x76>
  6a:	e44202a2 	addi      	r2, r2, 675
  6e:	d4440881 	str.w      	r1, (r4, r2 << 2)
  72:	dc6422a1 	st.w      	r3, (r4, 0xa84)
  76:	100f      	lrw      	r0, 0x0	// b0 <os_sema_up+0xb0>
  78:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  7c:	d86409e0 	ld.b      	r3, (r4, 0x9e0)
  80:	e4632001 	andi      	r3, r3, 1
  84:	3b40      	cmpnei      	r3, 0
  86:	102c      	lrw      	r1, 0x0	// b4 <atcmd_acs_start_hdl+0xb4>
  88:	104c      	lrw      	r2, 0x0	// b8 <atcmd_acs_start_hdl+0xb8>
  8a:	c4410c40 	inct      	r2, r1, 0
  8e:	d86420d7 	ld.w      	r3, (r4, 0x35c)
  92:	5d26      	addi      	r1, r5, 2
  94:	100a      	lrw      	r0, 0x0	// bc <atcmd_acs_start_hdl+0xbc>
  96:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  9a:	07bc      	br      	0x12	// 12 <atcmd_acs_start_hdl+0x12>
  9c:	c4665c00 	ins      	r3, r6, 0, 0
  a0:	dc6409e0 	st.b      	r3, (r4, 0x9e0)
  a4:	07ec      	br      	0x7c	// 7c <atcmd_acs_start_hdl+0x7c>
	...

Disassembly of section .text.atcmd_ack_to_extra_hdl:

00000000 <atcmd_ack_to_extra_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_ack_to_extra_hdl+0x12>
   8:	100b      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1089      	lrw      	r4, 0x0	// 38 <atcmd_ack_to_extra_hdl+0x38>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c05      	bf      	0x26	// 26 <atoi+0x26>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	dc0411ee 	st.h      	r0, (r4, 0x3dc)
  26:	d84411ee 	ld.h      	r2, (r4, 0x3dc)
  2a:	5d26      	addi      	r1, r5, 2
  2c:	1004      	lrw      	r0, 0x0	// 3c <atcmd_ack_to_extra_hdl+0x3c>
  2e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  32:	07ee      	br      	0xe	// e <atcmd_ack_to_extra_hdl+0xe>
	...

Disassembly of section .text.config_ft_att_val:

00000000 <config_ft_att_val>:
   0:	14d1      	push      	r4, r15
   2:	381f      	cmphsi      	r0, 32
   4:	6d03      	mov      	r4, r0
   6:	0808      	bt      	0x16	// 16 <config_ft_att_val+0x16>
   8:	7400      	zextb      	r0, r0
   a:	e0000000 	bsr      	0x0	// 0 <config_ft_att_val>
   e:	3000      	movi      	r0, 0
  10:	e0000000 	bsr      	0x0	// 0 <config_ft_att_val>
  14:	1491      	pop      	r4, r15
  16:	e460101f 	subi      	r3, r0, 32
  1a:	3b1e      	cmphsi      	r3, 31
  1c:	0bfc      	bt      	0x14	// 14 <config_ft_att_val+0x14>
  1e:	301f      	movi      	r0, 31
  20:	e0000000 	bsr      	0x0	// 0 <config_ft_att_val>
  24:	e404101e 	subi      	r0, r4, 31
  28:	7400      	zextb      	r0, r0
  2a:	07f3      	br      	0x10	// 10 <config_ft_att_val+0x10>

Disassembly of section .text.atcmd_ft_att_hdl:

00000000 <atcmd_ft_att_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_ft_att_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_ft_att_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c14      	bf      	0x44	// 44 <atoi+0x44>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	eb00003e 	cmphsi      	r0, 63
  26:	080f      	bt      	0x44	// 44 <atcmd_ft_att_hdl+0x44>
  28:	d8640708 	ld.b      	r3, (r4, 0x708)
  2c:	c4605ca0 	ins      	r3, r0, 5, 0
  30:	dc640708 	st.b      	r3, (r4, 0x708)
  34:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
  38:	e4632008 	andi      	r3, r3, 8
  3c:	e9230004 	bnez      	r3, 0x44	// 44 <atcmd_ft_att_hdl+0x44>
  40:	e0000000 	bsr      	0x0	// 0 <atcmd_ft_att_hdl>
  44:	d8440708 	ld.b      	r2, (r4, 0x708)
  48:	e442203f 	andi      	r2, r2, 63
  4c:	5d26      	addi      	r1, r5, 2
  4e:	1005      	lrw      	r0, 0x0	// 60 <atcmd_ft_att_hdl+0x60>
  50:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  54:	07dd      	br      	0xe	// e <atcmd_ft_att_hdl+0xe>
	...

Disassembly of section .text.atcmd_bgrssi_margin_hdl:

00000000 <atcmd_bgrssi_margin_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_bgrssi_margin_hdl+0x12>
   8:	100b      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1089      	lrw      	r4, 0x0	// 38 <atcmd_bgrssi_margin_hdl+0x38>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c05      	bf      	0x26	// 26 <atoi+0x26>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	dc040328 	st.b      	r0, (r4, 0x328)
  26:	d8444328 	ld.bs      	r2, (r4, 0x328)
  2a:	5d26      	addi      	r1, r5, 2
  2c:	1004      	lrw      	r0, 0x0	// 3c <atcmd_bgrssi_margin_hdl+0x3c>
  2e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  32:	07ee      	br      	0xe	// e <atcmd_bgrssi_margin_hdl+0xe>
	...

Disassembly of section .text.atcmd_bgrssi_spur_hdl:

00000000 <atcmd_bgrssi_spur_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_bgrssi_spur_hdl+0x12>
   8:	100f      	lrw      	r0, 0x0	// 44 <atcmd_printf+0x44>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108d      	lrw      	r4, 0x0	// 48 <atcmd_bgrssi_spur_hdl+0x48>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c08      	bf      	0x2c	// 2c <atoi+0x2c>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	74c3      	sexth      	r3, r0
  24:	e983000b 	blz      	r3, 0x3a	// 3a <atcmd_bgrssi_spur_hdl+0x3a>
  28:	dc641196 	st.h      	r3, (r4, 0x32c)
  2c:	d8445196 	ld.hs      	r2, (r4, 0x32c)
  30:	5d26      	addi      	r1, r5, 2
  32:	1007      	lrw      	r0, 0x0	// 4c <atcmd_bgrssi_spur_hdl+0x4c>
  34:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  38:	07eb      	br      	0xe	// e <atcmd_bgrssi_spur_hdl+0xe>
  3a:	3300      	movi      	r3, 0
  3c:	5b01      	subu      	r0, r3, r0
  3e:	dc041196 	st.h      	r0, (r4, 0x32c)
  42:	07f5      	br      	0x2c	// 2c <atcmd_bgrssi_spur_hdl+0x2c>
	...

Disassembly of section .text.atcmd_pcf_en_hdl:

00000000 <atcmd_pcf_en_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_pcf_en_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_pcf_en_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d8640360 	ld.b      	r3, (r4, 0x360)
  26:	e9000015 	bez      	r0, 0x50	// 50 <atcmd_pcf_en_hdl+0x50>
  2a:	3201      	movi      	r2, 1
  2c:	c4625c00 	ins      	r3, r2, 0, 0
  30:	dc640360 	st.b      	r3, (r4, 0x360)
  34:	d8640360 	ld.b      	r3, (r4, 0x360)
  38:	e4632001 	andi      	r3, r3, 1
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1049      	lrw      	r2, 0x0	// 60 <atcmd_pcf_en_hdl+0x60>
  40:	1069      	lrw      	r3, 0x0	// 64 <atcmd_pcf_en_hdl+0x64>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1008      	lrw      	r0, 0x0	// 68 <atcmd_pcf_en_hdl+0x68>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_pcf_en_hdl+0xe>
  50:	c4605c00 	ins      	r3, r0, 0, 0
  54:	07ee      	br      	0x30	// 30 <atcmd_pcf_en_hdl+0x30>
	...

Disassembly of section .text.atcmd_pcf_period_hdl:

00000000 <atcmd_pcf_period_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_pcf_period_hdl+0x12>
   8:	100e      	lrw      	r0, 0x0	// 40 <atcmd_printf+0x40>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108c      	lrw      	r4, 0x0	// 44 <atcmd_pcf_period_hdl+0x44>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c07      	bf      	0x2a	// 2a <atoi+0x2a>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	e960000b 	blsz      	r0, 0x38	// 38 <atcmd_pcf_period_hdl+0x38>
  26:	dc040364 	st.b      	r0, (r4, 0x364)
  2a:	d8440364 	ld.b      	r2, (r4, 0x364)
  2e:	5d26      	addi      	r1, r5, 2
  30:	1006      	lrw      	r0, 0x0	// 48 <atcmd_pcf_period_hdl+0x48>
  32:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  36:	07ec      	br      	0xe	// e <atcmd_pcf_period_hdl+0xe>
  38:	3300      	movi      	r3, 0
  3a:	dc640364 	st.b      	r3, (r4, 0x364)
  3e:	07f6      	br      	0x2a	// 2a <atcmd_pcf_period_hdl+0x2a>
	...

Disassembly of section .text.atcmd_pcf_percent_hdl:

00000000 <atcmd_pcf_percent_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_pcf_percent_hdl+0x12>
   8:	100f      	lrw      	r0, 0x0	// 44 <atcmd_printf+0x44>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108d      	lrw      	r4, 0x0	// 48 <atcmd_pcf_percent_hdl+0x48>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c08      	bf      	0x2c	// 2c <atoi+0x2c>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	eb000064 	cmphsi      	r0, 101
  26:	080a      	bt      	0x3a	// 3a <atcmd_pcf_percent_hdl+0x3a>
  28:	dc040365 	st.b      	r0, (r4, 0x365)
  2c:	d8440365 	ld.b      	r2, (r4, 0x365)
  30:	5d26      	addi      	r1, r5, 2
  32:	1007      	lrw      	r0, 0x0	// 4c <atcmd_pcf_percent_hdl+0x4c>
  34:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  38:	07eb      	br      	0xe	// e <atcmd_pcf_percent_hdl+0xe>
  3a:	3300      	movi      	r3, 0
  3c:	dc640365 	st.b      	r3, (r4, 0x365)
  40:	07f6      	br      	0x2c	// 2c <atcmd_pcf_percent_hdl+0x2c>
	...

Disassembly of section .text.atcmd_obss_nav_diff_hdl:

00000000 <atcmd_obss_nav_diff_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_obss_nav_diff_hdl+0x12>
   8:	101b      	lrw      	r0, 0x0	// 74 <atcmd_printf+0x74>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1099      	lrw      	r4, 0x0	// 78 <atcmd_obss_nav_diff_hdl+0x78>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c12      	bf      	0x40	// 40 <atoi+0x40>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d86420df 	ld.w      	r3, (r4, 0x37c)
  26:	e960001f 	blsz      	r0, 0x64	// 64 <atcmd_obss_nav_diff_hdl+0x64>
  2a:	c4605cad 	ins      	r3, r0, 18, 13
  2e:	dc6420df 	st.w      	r3, (r4, 0x37c)
  32:	d864037d 	ld.b      	r3, (r4, 0x37d)
  36:	3201      	movi      	r2, 1
  38:	c4625c04 	ins      	r3, r2, 4, 4
  3c:	dc64037d 	st.b      	r3, (r4, 0x37d)
  40:	d864037d 	ld.b      	r3, (r4, 0x37d)
  44:	e4632010 	andi      	r3, r3, 16
  48:	3b40      	cmpnei      	r3, 0
  4a:	102d      	lrw      	r1, 0x0	// 7c <atcmd_obss_nav_diff_hdl+0x7c>
  4c:	104d      	lrw      	r2, 0x0	// 80 <atcmd_obss_nav_diff_hdl+0x80>
  4e:	c4410c40 	inct      	r2, r1, 0
  52:	d86420df 	ld.w      	r3, (r4, 0x37c)
  56:	c5a35643 	zext      	r3, r3, 18, 13
  5a:	5d26      	addi      	r1, r5, 2
  5c:	100a      	lrw      	r0, 0x0	// 84 <atcmd_obss_nav_diff_hdl+0x84>
  5e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  62:	07d6      	br      	0xe	// e <atcmd_obss_nav_diff_hdl+0xe>
  64:	3200      	movi      	r2, 0
  66:	c4625cad 	ins      	r3, r2, 18, 13
  6a:	dc6420df 	st.w      	r3, (r4, 0x37c)
  6e:	d864037d 	ld.b      	r3, (r4, 0x37d)
  72:	07e3      	br      	0x38	// 38 <atcmd_obss_nav_diff_hdl+0x38>
	...

Disassembly of section .text.atcmd_obss_cca_diff_hdl:

00000000 <atcmd_obss_cca_diff_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_obss_cca_diff_hdl+0x12>
   8:	101f      	lrw      	r0, 0x0	// 84 <atcmd_printf+0x84>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	109d      	lrw      	r4, 0x0	// 88 <atcmd_obss_cca_diff_hdl+0x88>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c16      	bf      	0x48	// 48 <atoi+0x48>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d86411bf 	ld.h      	r3, (r4, 0x37e)
  26:	e9600023 	blsz      	r0, 0x6c	// 6c <atcmd_obss_cca_diff_hdl+0x6c>
  2a:	c4605ca4 	ins      	r3, r0, 9, 4
  2e:	3201      	movi      	r2, 1
  30:	dc6411bf 	st.h      	r3, (r4, 0x37e)
  34:	d804431e 	ld.bs      	r0, (r4, 0x31e)
  38:	c4625c03 	ins      	r3, r2, 3, 3
  3c:	dc64037e 	st.b      	r3, (r4, 0x37e)
  40:	e0000000 	bsr      	0x0	// 0 <lmac_adjust_cca_threshold>
  44:	e0000000 	bsr      	0x0	// 0 <ah_wphy_obss_sd_det_enable>
  48:	d864037e 	ld.b      	r3, (r4, 0x37e)
  4c:	e4632008 	andi      	r3, r3, 8
  50:	3b40      	cmpnei      	r3, 0
  52:	102f      	lrw      	r1, 0x0	// 8c <atcmd_obss_cca_diff_hdl+0x8c>
  54:	d86411bf 	ld.h      	r3, (r4, 0x37e)
  58:	104e      	lrw      	r2, 0x0	// 90 <atcmd_obss_cca_diff_hdl+0x90>
  5a:	c4410c40 	inct      	r2, r1, 0
  5e:	c4835523 	zext      	r3, r3, 9, 4
  62:	5d26      	addi      	r1, r5, 2
  64:	100c      	lrw      	r0, 0x0	// 94 <atcmd_obss_cca_diff_hdl+0x94>
  66:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  6a:	07d2      	br      	0xe	// e <atcmd_obss_cca_diff_hdl+0xe>
  6c:	3200      	movi      	r2, 0
  6e:	c4625ca4 	ins      	r3, r2, 9, 4
  72:	dc6411bf 	st.h      	r3, (r4, 0x37e)
  76:	c4625c03 	ins      	r3, r2, 3, 3
  7a:	dc64037e 	st.b      	r3, (r4, 0x37e)
  7e:	e0000000 	bsr      	0x0	// 0 <ah_wphy_obss_sd_det_disable>
  82:	07e3      	br      	0x48	// 48 <atcmd_obss_cca_diff_hdl+0x48>
	...

Disassembly of section .text.atcmd_set_agc_hdl:

00000000 <atcmd_set_agc_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_set_agc_hdl+0x12>
   8:	1019      	lrw      	r0, 0x0	// 6c <atcmd_printf+0x6c>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1097      	lrw      	r4, 0x0	// 70 <atcmd_set_agc_hdl+0x70>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c10      	bf      	0x3c	// 3c <atoi+0x3c>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	586f      	subi      	r3, r0, 4
  24:	3b01      	cmphsi      	r3, 2
  26:	d8640361 	ld.b      	r3, (r4, 0x361)
  2a:	081b      	bt      	0x60	// 60 <atcmd_set_agc_hdl+0x60>
  2c:	3200      	movi      	r2, 0
  2e:	c4625c03 	ins      	r3, r2, 3, 3
  32:	7400      	zextb      	r0, r0
  34:	dc640361 	st.b      	r3, (r4, 0x361)
  38:	e0000000 	bsr      	0x0	// 0 <lmac_rx_gain_cfg>
  3c:	d8640361 	ld.b      	r3, (r4, 0x361)
  40:	e4632008 	andi      	r3, r3, 8
  44:	3b40      	cmpnei      	r3, 0
  46:	102c      	lrw      	r1, 0x0	// 74 <atcmd_set_agc_hdl+0x74>
  48:	d86411b1 	ld.h      	r3, (r4, 0x362)
  4c:	104b      	lrw      	r2, 0x0	// 78 <atcmd_set_agc_hdl+0x78>
  4e:	c4410c40 	inct      	r2, r1, 0
  52:	c4835563 	zext      	r3, r3, 11, 4
  56:	5d26      	addi      	r1, r5, 2
  58:	1009      	lrw      	r0, 0x0	// 7c <atcmd_set_agc_hdl+0x7c>
  5a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  5e:	07d8      	br      	0xe	// e <atcmd_set_agc_hdl+0xe>
  60:	3201      	movi      	r2, 1
  62:	c4625c03 	ins      	r3, r2, 3, 3
  66:	dc640361 	st.b      	r3, (r4, 0x361)
  6a:	07e9      	br      	0x3c	// 3c <atcmd_set_agc_hdl+0x3c>
	...

Disassembly of section .text.atcmd_set_agc_threshold_hdl:

00000000 <atcmd_set_agc_threshold_hdl>:
   0:	14d4      	push      	r4-r7, r15
   2:	6d83      	mov      	r6, r0
   4:	6d47      	mov      	r5, r1
   6:	e9220007 	bnez      	r2, 0x14	// 14 <atcmd_set_agc_threshold_hdl+0x14>
   a:	1010      	lrw      	r0, 0x0	// 48 <atcmd_printf+0x48>
   c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  10:	3000      	movi      	r0, 0
  12:	1494      	pop      	r4-r7, r15
  14:	9100      	ld.w      	r0, (r1, 0x0)
  16:	108e      	lrw      	r4, 0x0	// 4c <atcmd_set_agc_threshold_hdl+0x4c>
  18:	8060      	ld.b      	r3, (r0, 0x0)
  1a:	eb43003f 	cmpnei      	r3, 63
  1e:	0c0b      	bf      	0x34	// 34 <atoi+0x34>
  20:	e0000000 	bsr      	0x0	// 0 <atoi>
  24:	6dc3      	mov      	r7, r0
  26:	9501      	ld.w      	r0, (r5, 0x4)
  28:	e0000000 	bsr      	0x0	// 0 <atoi>
  2c:	dc040320 	st.b      	r0, (r4, 0x320)
  30:	dce4031f 	st.b      	r7, (r4, 0x31f)
  34:	d8644320 	ld.bs      	r3, (r4, 0x320)
  38:	d844431f 	ld.bs      	r2, (r4, 0x31f)
  3c:	5e26      	addi      	r1, r6, 2
  3e:	1005      	lrw      	r0, 0x0	// 50 <atcmd_set_agc_threshold_hdl+0x50>
  40:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  44:	07e6      	br      	0x10	// 10 <atcmd_set_agc_threshold_hdl+0x10>
	...

Disassembly of section .text.atcmd_txop_en_hdl:

00000000 <atcmd_txop_en_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_txop_en_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_txop_en_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d864037f 	ld.b      	r3, (r4, 0x37f)
  26:	e9000015 	bez      	r0, 0x50	// 50 <atcmd_txop_en_hdl+0x50>
  2a:	3201      	movi      	r2, 1
  2c:	c4625c03 	ins      	r3, r2, 3, 3
  30:	dc64037f 	st.b      	r3, (r4, 0x37f)
  34:	d864037f 	ld.b      	r3, (r4, 0x37f)
  38:	e4632008 	andi      	r3, r3, 8
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1049      	lrw      	r2, 0x0	// 60 <atcmd_txop_en_hdl+0x60>
  40:	1069      	lrw      	r3, 0x0	// 64 <atcmd_txop_en_hdl+0x64>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1008      	lrw      	r0, 0x0	// 68 <atcmd_txop_en_hdl+0x68>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_txop_en_hdl+0xe>
  50:	c4605c03 	ins      	r3, r0, 3, 3
  54:	07ee      	br      	0x30	// 30 <atcmd_txop_en_hdl+0x30>
	...

Disassembly of section .text.atcmd_tx_bw_dynamic_hdl:

00000000 <atcmd_tx_bw_dynamic_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_bw_dynamic_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_tx_bw_dynamic_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d864037f 	ld.b      	r3, (r4, 0x37f)
  26:	e9000015 	bez      	r0, 0x50	// 50 <atcmd_tx_bw_dynamic_hdl+0x50>
  2a:	3201      	movi      	r2, 1
  2c:	c4625c02 	ins      	r3, r2, 2, 2
  30:	dc64037f 	st.b      	r3, (r4, 0x37f)
  34:	d864037f 	ld.b      	r3, (r4, 0x37f)
  38:	e4632004 	andi      	r3, r3, 4
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1049      	lrw      	r2, 0x0	// 60 <atcmd_tx_bw_dynamic_hdl+0x60>
  40:	1069      	lrw      	r3, 0x0	// 64 <atcmd_tx_bw_dynamic_hdl+0x64>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1008      	lrw      	r0, 0x0	// 68 <atcmd_tx_bw_dynamic_hdl+0x68>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_tx_bw_dynamic_hdl+0xe>
  50:	c4605c02 	ins      	r3, r0, 2, 2
  54:	07ee      	br      	0x30	// 30 <atcmd_tx_bw_dynamic_hdl+0x30>
	...

Disassembly of section .text.atcmd_cca_obsv_hdl:

00000000 <atcmd_cca_obsv_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_cca_obsv_hdl+0x12>
   8:	1100      	lrw      	r0, 0x0	// 88 <atcmd_printf+0x88>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	109e      	lrw      	r4, 0x0	// 8c <atcmd_cca_obsv_hdl+0x8c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	080c      	bt      	0x34	// 34 <atcmd_cca_obsv_hdl+0x34>
  1e:	d8440860 	ld.b      	r2, (r4, 0x860)
  22:	e4622007 	andi      	r3, r2, 7
  26:	3201      	movi      	r2, 1
  28:	708c      	lsl      	r2, r3
  2a:	5d26      	addi      	r1, r5, 2
  2c:	1019      	lrw      	r0, 0x0	// 90 <atcmd_cca_obsv_hdl+0x90>
  2e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  32:	07ee      	br      	0xe	// e <atoi+0xe>
  34:	e0000000 	bsr      	0x0	// 0 <atoi>
  38:	e960fff3 	blsz      	r0, 0x1e	// 1e <atcmd_cca_obsv_hdl+0x1e>
  3c:	3841      	cmpnei      	r0, 1
  3e:	d8640860 	ld.b      	r3, (r4, 0x860)
  42:	0807      	bt      	0x50	// 50 <atcmd_cca_obsv_hdl+0x50>
  44:	3200      	movi      	r2, 0
  46:	c4625c40 	ins      	r3, r2, 2, 0
  4a:	dc640860 	st.b      	r3, (r4, 0x860)
  4e:	07e8      	br      	0x1e	// 1e <atcmd_cca_obsv_hdl+0x1e>
  50:	3823      	cmplti      	r0, 4
  52:	0c03      	bf      	0x58	// 58 <atcmd_cca_obsv_hdl+0x58>
  54:	3201      	movi      	r2, 1
  56:	07f8      	br      	0x46	// 46 <atcmd_cca_obsv_hdl+0x46>
  58:	3827      	cmplti      	r0, 8
  5a:	0c03      	bf      	0x60	// 60 <atcmd_cca_obsv_hdl+0x60>
  5c:	3202      	movi      	r2, 2
  5e:	07f4      	br      	0x46	// 46 <atcmd_cca_obsv_hdl+0x46>
  60:	382f      	cmplti      	r0, 16
  62:	0c03      	bf      	0x68	// 68 <atcmd_cca_obsv_hdl+0x68>
  64:	3203      	movi      	r2, 3
  66:	07f0      	br      	0x46	// 46 <atcmd_cca_obsv_hdl+0x46>
  68:	383f      	cmplti      	r0, 32
  6a:	0c03      	bf      	0x70	// 70 <atcmd_cca_obsv_hdl+0x70>
  6c:	3204      	movi      	r2, 4
  6e:	07ec      	br      	0x46	// 46 <atcmd_cca_obsv_hdl+0x46>
  70:	eb20003f 	cmplti      	r0, 64
  74:	0c03      	bf      	0x7a	// 7a <atcmd_cca_obsv_hdl+0x7a>
  76:	3205      	movi      	r2, 5
  78:	07e7      	br      	0x46	// 46 <atcmd_cca_obsv_hdl+0x46>
  7a:	eb20007f 	cmplti      	r0, 128
  7e:	0c03      	bf      	0x84	// 84 <atcmd_cca_obsv_hdl+0x84>
  80:	3206      	movi      	r2, 6
  82:	07e2      	br      	0x46	// 46 <atcmd_cca_obsv_hdl+0x46>
  84:	3207      	movi      	r2, 7
  86:	07e0      	br      	0x46	// 46 <atcmd_cca_obsv_hdl+0x46>
	...

Disassembly of section .text.atcmd_cts_dup_hdl:

00000000 <atcmd_cts_dup_hdl>:
   0:	14d0      	push      	r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_cts_dup_hdl+0x10>
   6:	1013      	lrw      	r0, 0x0	// 50 <atcmd_printf+0x50>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	8340      	ld.b      	r2, (r3, 0x0)
  14:	eb42003f 	cmpnei      	r2, 63
  18:	106f      	lrw      	r3, 0x0	// 54 <atcmd_cts_dup_hdl+0x54>
  1a:	0c0b      	bf      	0x30	// 30 <atcmd_cts_dup_hdl+0x30>
  1c:	eb420030 	cmpnei      	r2, 48
  20:	d8430338 	ld.b      	r2, (r3, 0x338)
  24:	0814      	bt      	0x4c	// 4c <atcmd_cts_dup_hdl+0x4c>
  26:	3100      	movi      	r1, 0
  28:	c4415c02 	ins      	r2, r1, 2, 2
  2c:	dc430338 	st.b      	r2, (r3, 0x338)
  30:	d8630338 	ld.b      	r3, (r3, 0x338)
  34:	e4632004 	andi      	r3, r3, 4
  38:	3b40      	cmpnei      	r3, 0
  3a:	1048      	lrw      	r2, 0x0	// 58 <atcmd_cts_dup_hdl+0x58>
  3c:	1068      	lrw      	r3, 0x0	// 5c <atcmd_cts_dup_hdl+0x5c>
  3e:	5826      	addi      	r1, r0, 2
  40:	c4430c20 	incf      	r2, r3, 0
  44:	1007      	lrw      	r0, 0x0	// 60 <atcmd_printf+0x60>
  46:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4a:	07e1      	br      	0xc	// c <atcmd_cts_dup_hdl+0xc>
  4c:	3101      	movi      	r1, 1
  4e:	07ed      	br      	0x28	// 28 <atcmd_cts_dup_hdl+0x28>
	...

Disassembly of section .text.atcmd_lmac_dbgsel_hdl:

00000000 <atcmd_lmac_dbgsel_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_lmac_dbgsel_hdl+0x12>
   8:	100b      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1089      	lrw      	r4, 0x0	// 38 <atcmd_lmac_dbgsel_hdl+0x38>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c05      	bf      	0x26	// 26 <os_atoh+0x26>
  1e:	e0000000 	bsr      	0x0	// 0 <os_atoh>
  22:	dc0420ee 	st.w      	r0, (r4, 0x3b8)
  26:	d84420ee 	ld.w      	r2, (r4, 0x3b8)
  2a:	5d26      	addi      	r1, r5, 2
  2c:	1004      	lrw      	r0, 0x0	// 3c <atcmd_lmac_dbgsel_hdl+0x3c>
  2e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  32:	07ee      	br      	0xe	// e <atcmd_lmac_dbgsel_hdl+0xe>
	...

Disassembly of section .text.atcmd_rts_dup_hdl:

00000000 <atcmd_rts_dup_hdl>:
   0:	14d0      	push      	r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_rts_dup_hdl+0x10>
   6:	1013      	lrw      	r0, 0x0	// 50 <atcmd_printf+0x50>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	8340      	ld.b      	r2, (r3, 0x0)
  14:	eb42003f 	cmpnei      	r2, 63
  18:	106f      	lrw      	r3, 0x0	// 54 <atcmd_rts_dup_hdl+0x54>
  1a:	0c0b      	bf      	0x30	// 30 <atcmd_rts_dup_hdl+0x30>
  1c:	eb420030 	cmpnei      	r2, 48
  20:	d8430338 	ld.b      	r2, (r3, 0x338)
  24:	0814      	bt      	0x4c	// 4c <atcmd_rts_dup_hdl+0x4c>
  26:	3100      	movi      	r1, 0
  28:	c4415c01 	ins      	r2, r1, 1, 1
  2c:	dc430338 	st.b      	r2, (r3, 0x338)
  30:	d8630338 	ld.b      	r3, (r3, 0x338)
  34:	e4632002 	andi      	r3, r3, 2
  38:	3b40      	cmpnei      	r3, 0
  3a:	1048      	lrw      	r2, 0x0	// 58 <atcmd_rts_dup_hdl+0x58>
  3c:	1068      	lrw      	r3, 0x0	// 5c <atcmd_rts_dup_hdl+0x5c>
  3e:	5826      	addi      	r1, r0, 2
  40:	c4430c20 	incf      	r2, r3, 0
  44:	1007      	lrw      	r0, 0x0	// 60 <atcmd_printf+0x60>
  46:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4a:	07e1      	br      	0xc	// c <atcmd_rts_dup_hdl+0xc>
  4c:	3101      	movi      	r1, 1
  4e:	07ed      	br      	0x28	// 28 <atcmd_rts_dup_hdl+0x28>
	...

Disassembly of section .text.atcmd_sleep_en_hdl:

00000000 <atcmd_sleep_en_hdl>:
   0:	14d0      	push      	r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_sleep_en_hdl+0x10>
   6:	100c      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1490      	pop      	r15
  10:	9100      	ld.w      	r0, (r1, 0x0)
  12:	8060      	ld.b      	r3, (r0, 0x0)
  14:	eb43003f 	cmpnei      	r3, 63
  18:	0ffa      	bf      	0xc	// c <atoi+0xc>
  1a:	e0000000 	bsr      	0x0	// 0 <atoi>
  1e:	3840      	cmpnei      	r0, 0
  20:	1006      	lrw      	r0, 0x0	// 38 <atcmd_sleep_en_hdl+0x38>
  22:	c4000503 	mvc      	r3
  26:	3200      	movi      	r2, 0
  28:	3101      	movi      	r1, 1
  2a:	9000      	ld.w      	r0, (r0, 0x0)
  2c:	e0000000 	bsr      	0x0	// 0 <lmac_psm_enter>
  30:	07ee      	br      	0xc	// c <atcmd_sleep_en_hdl+0xc>
	...

Disassembly of section .text.atcmd_ap_sleep_mode:

00000000 <atcmd_ap_sleep_mode>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_ap_sleep_mode+0x12>
   8:	1012      	lrw      	r0, 0x0	// 50 <atcmd_printf+0x50>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1090      	lrw      	r4, 0x0	// 54 <atcmd_ap_sleep_mode+0x54>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	3840      	cmpnei      	r0, 0
  24:	d8640319 	ld.b      	r3, (r4, 0x319)
  28:	c4000502 	mvc      	r2
  2c:	c4625c06 	ins      	r3, r2, 6, 6
  30:	dc640319 	st.b      	r3, (r4, 0x319)
  34:	d8640319 	ld.b      	r3, (r4, 0x319)
  38:	e4632040 	andi      	r3, r3, 64
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1047      	lrw      	r2, 0x0	// 58 <atcmd_ap_sleep_mode+0x58>
  40:	1067      	lrw      	r3, 0x0	// 5c <atcmd_ap_sleep_mode+0x5c>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1006      	lrw      	r0, 0x0	// 60 <atcmd_ap_sleep_mode+0x60>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_ap_sleep_mode+0xe>
	...

Disassembly of section .text.atcmd_wake_stas_hdl:

00000000 <atcmd_wake_stas_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_wake_stas_hdl+0x12>
   8:	100e      	lrw      	r0, 0x0	// 40 <atcmd_printf+0x40>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108c      	lrw      	r4, 0x0	// 44 <atcmd_wake_stas_hdl+0x44>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c09      	bf      	0x2e	// 2e <atoi+0x2e>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d8640319 	ld.b      	r3, (r4, 0x319)
  26:	c4605c62 	ins      	r3, r0, 5, 2
  2a:	dc640319 	st.b      	r3, (r4, 0x319)
  2e:	d8440319 	ld.b      	r2, (r4, 0x319)
  32:	c44254a2 	zext      	r2, r2, 5, 2
  36:	5d26      	addi      	r1, r5, 2
  38:	1004      	lrw      	r0, 0x0	// 48 <atcmd_wake_stas_hdl+0x48>
  3a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  3e:	07e8      	br      	0xe	// e <atcmd_wake_stas_hdl+0xe>
	...

Disassembly of section .text.atcmd_strictly_ordered_hdl:

00000000 <atcmd_strictly_ordered_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_strictly_ordered_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_strictly_ordered_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d8640310 	ld.b      	r3, (r4, 0x310)
  26:	e9000015 	bez      	r0, 0x50	// 50 <atcmd_strictly_ordered_hdl+0x50>
  2a:	3201      	movi      	r2, 1
  2c:	c4625c03 	ins      	r3, r2, 3, 3
  30:	dc640310 	st.b      	r3, (r4, 0x310)
  34:	d8640310 	ld.b      	r3, (r4, 0x310)
  38:	e4632008 	andi      	r3, r3, 8
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1049      	lrw      	r2, 0x0	// 60 <atcmd_strictly_ordered_hdl+0x60>
  40:	1069      	lrw      	r3, 0x0	// 64 <atcmd_strictly_ordered_hdl+0x64>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1008      	lrw      	r0, 0x0	// 68 <atcmd_strictly_ordered_hdl+0x68>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_strictly_ordered_hdl+0xe>
  50:	c4605c03 	ins      	r3, r0, 3, 3
  54:	07ee      	br      	0x30	// 30 <atcmd_strictly_ordered_hdl+0x30>
	...

Disassembly of section .text.atcmd_agg_auto_hdl:

00000000 <atcmd_agg_auto_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_agg_auto_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_agg_auto_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d8640310 	ld.b      	r3, (r4, 0x310)
  26:	e9000015 	bez      	r0, 0x50	// 50 <atcmd_agg_auto_hdl+0x50>
  2a:	3201      	movi      	r2, 1
  2c:	c4625c04 	ins      	r3, r2, 4, 4
  30:	dc640310 	st.b      	r3, (r4, 0x310)
  34:	d8640310 	ld.b      	r3, (r4, 0x310)
  38:	e4632010 	andi      	r3, r3, 16
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1049      	lrw      	r2, 0x0	// 60 <atcmd_agg_auto_hdl+0x60>
  40:	1069      	lrw      	r3, 0x0	// 64 <atcmd_agg_auto_hdl+0x64>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1008      	lrw      	r0, 0x0	// 68 <atcmd_agg_auto_hdl+0x68>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_agg_auto_hdl+0xe>
  50:	c4605c04 	ins      	r3, r0, 4, 4
  54:	07ee      	br      	0x30	// 30 <atcmd_agg_auto_hdl+0x30>
	...

Disassembly of section .text.atcmd_rx_ordered_hdl:

00000000 <atcmd_rx_ordered_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_rx_ordered_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_rx_ordered_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d8640310 	ld.b      	r3, (r4, 0x310)
  26:	e9000015 	bez      	r0, 0x50	// 50 <atcmd_rx_ordered_hdl+0x50>
  2a:	3201      	movi      	r2, 1
  2c:	c4625c05 	ins      	r3, r2, 5, 5
  30:	dc640310 	st.b      	r3, (r4, 0x310)
  34:	d8640310 	ld.b      	r3, (r4, 0x310)
  38:	e4632020 	andi      	r3, r3, 32
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1049      	lrw      	r2, 0x0	// 60 <atcmd_rx_ordered_hdl+0x60>
  40:	1069      	lrw      	r3, 0x0	// 64 <atcmd_rx_ordered_hdl+0x64>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1008      	lrw      	r0, 0x0	// 68 <atcmd_rx_ordered_hdl+0x68>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_rx_ordered_hdl+0xe>
  50:	c4605c05 	ins      	r3, r0, 5, 5
  54:	07ee      	br      	0x30	// 30 <atcmd_rx_ordered_hdl+0x30>
	...

Disassembly of section .text.atcmd_qa_cfg_hdl:

00000000 <atcmd_qa_cfg_hdl>:
   0:	14d5      	push      	r4-r8, r15
   2:	1423      	subi      	r14, r14, 12
   4:	6e03      	mov      	r8, r0
   6:	6d87      	mov      	r6, r1
   8:	6dcb      	mov      	r7, r2
   a:	e9220008 	bnez      	r2, 0x1a	// 1a <atcmd_qa_cfg_hdl+0x1a>
   e:	111d      	lrw      	r0, 0x0	// 100 <atcmd_printf+0x100>
  10:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  14:	3000      	movi      	r0, 0
  16:	1403      	addi      	r14, r14, 12
  18:	1495      	pop      	r4-r8, r15
  1a:	9100      	ld.w      	r0, (r1, 0x0)
  1c:	119a      	lrw      	r4, 0x0	// 104 <atcmd_qa_cfg_hdl+0x104>
  1e:	8060      	ld.b      	r3, (r0, 0x0)
  20:	eb43003f 	cmpnei      	r3, 63
  24:	0c47      	bf      	0xb2	// b2 <atoi+0xb2>
  26:	e0000000 	bsr      	0x0	// 0 <atoi>
  2a:	6d43      	mov      	r5, r0
  2c:	e9600056 	blsz      	r0, 0xd8	// d8 <atcmd_qa_cfg_hdl+0xd8>
  30:	e0000000 	bsr      	0x0	// 0 <lmac_lo_freq_set>
  34:	e9000007 	bez      	r0, 0x42	// 42 <atcmd_qa_cfg_hdl+0x42>
  38:	1174      	lrw      	r3, 0x0	// 108 <atcmd_qa_cfg_hdl+0x108>
  3a:	3200      	movi      	r2, 0
  3c:	2a01      	subi      	r2, 2
  3e:	b352      	st.w      	r2, (r3, 0x48)
  40:	3500      	movi      	r5, 0
  42:	4d70      	lsri      	r3, r5, 16
  44:	3f01      	cmphsi      	r7, 2
  46:	dc640896 	st.b      	r3, (r4, 0x896)
  4a:	dca40894 	st.b      	r5, (r4, 0x894)
  4e:	4b68      	lsri      	r3, r3, 8
  50:	c50555e5 	zext      	r5, r5, 15, 8
  54:	dc640897 	st.b      	r3, (r4, 0x897)
  58:	dca40895 	st.b      	r5, (r4, 0x895)
  5c:	0c2b      	bf      	0xb2	// b2 <atcmd_qa_cfg_hdl+0xb2>
  5e:	9601      	ld.w      	r0, (r6, 0x4)
  60:	e0000000 	bsr      	0x0	// 0 <atoi>
  64:	7482      	sextb      	r2, r0
  66:	2800      	subi      	r0, 1
  68:	7400      	zextb      	r0, r0
  6a:	3801      	cmphsi      	r0, 2
  6c:	0c05      	bf      	0x76	// 76 <atcmd_qa_cfg_hdl+0x76>
  6e:	3a44      	cmpnei      	r2, 4
  70:	0c03      	bf      	0x76	// 76 <atcmd_qa_cfg_hdl+0x76>
  72:	3a48      	cmpnei      	r2, 8
  74:	0837      	bt      	0xe2	// e2 <atcmd_qa_cfg_hdl+0xe2>
  76:	3300      	movi      	r3, 0
  78:	3102      	movi      	r1, 2
  7a:	9400      	ld.w      	r0, (r4, 0x0)
  7c:	dc440898 	st.b      	r2, (r4, 0x898)
  80:	e0000000 	bsr      	0x0	// 0 <lmac_ioctl>
  84:	3f42      	cmpnei      	r7, 2
  86:	0c16      	bf      	0xb2	// b2 <atcmd_qa_cfg_hdl+0xb2>
  88:	9602      	ld.w      	r0, (r6, 0x8)
  8a:	e0000000 	bsr      	0x0	// 0 <atoi>
  8e:	74c0      	zextb      	r3, r0
  90:	3b07      	cmphsi      	r3, 8
  92:	082d      	bt      	0xec	// ec <atcmd_qa_cfg_hdl+0xec>
  94:	dc040899 	st.b      	r0, (r4, 0x899)
  98:	dc640866 	st.b      	r3, (r4, 0x866)
  9c:	3f43      	cmpnei      	r7, 3
  9e:	0c0a      	bf      	0xb2	// b2 <atcmd_qa_cfg_hdl+0xb2>
  a0:	9603      	ld.w      	r0, (r6, 0xc)
  a2:	e0000000 	bsr      	0x0	// 0 <atoi>
  a6:	74c0      	zextb      	r3, r0
  a8:	eb030064 	cmphsi      	r3, 101
  ac:	0825      	bt      	0xf6	// f6 <atcmd_qa_cfg_hdl+0xf6>
  ae:	dc04089a 	st.b      	r0, (r4, 0x89a)
  b2:	d824489b 	ld.bs      	r1, (r4, 0x89b)
  b6:	b822      	st.w      	r1, (r14, 0x8)
  b8:	d824489a 	ld.bs      	r1, (r4, 0x89a)
  bc:	b821      	st.w      	r1, (r14, 0x4)
  be:	d8244899 	ld.bs      	r1, (r4, 0x899)
  c2:	b820      	st.w      	r1, (r14, 0x0)
  c4:	d8644898 	ld.bs      	r3, (r4, 0x898)
  c8:	d8442225 	ld.w      	r2, (r4, 0x894)
  cc:	e4280001 	addi      	r1, r8, 2
  d0:	100f      	lrw      	r0, 0x0	// 10c <atcmd_printf+0x10c>
  d2:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  d6:	079f      	br      	0x14	// 14 <atcmd_qa_cfg_hdl+0x14>
  d8:	106c      	lrw      	r3, 0x0	// 108 <atcmd_qa_cfg_hdl+0x108>
  da:	3200      	movi      	r2, 0
  dc:	2a02      	subi      	r2, 3
  de:	b352      	st.w      	r2, (r3, 0x48)
  e0:	07b1      	br      	0x42	// 42 <atcmd_qa_cfg_hdl+0x42>
  e2:	106a      	lrw      	r3, 0x0	// 108 <atcmd_qa_cfg_hdl+0x108>
  e4:	3200      	movi      	r2, 0
  e6:	2a03      	subi      	r2, 4
  e8:	b352      	st.w      	r2, (r3, 0x48)
  ea:	07cd      	br      	0x84	// 84 <atcmd_qa_cfg_hdl+0x84>
  ec:	1067      	lrw      	r3, 0x0	// 108 <atcmd_qa_cfg_hdl+0x108>
  ee:	3200      	movi      	r2, 0
  f0:	2a04      	subi      	r2, 5
  f2:	b352      	st.w      	r2, (r3, 0x48)
  f4:	07d4      	br      	0x9c	// 9c <atcmd_qa_cfg_hdl+0x9c>
  f6:	1065      	lrw      	r3, 0x0	// 108 <atcmd_qa_cfg_hdl+0x108>
  f8:	3200      	movi      	r2, 0
  fa:	2a05      	subi      	r2, 6
  fc:	b352      	st.w      	r2, (r3, 0x48)
  fe:	07da      	br      	0xb2	// b2 <atcmd_qa_cfg_hdl+0xb2>
	...

Disassembly of section .text.atcmd_qa_rxthd_hdl:

00000000 <atcmd_qa_rxthd_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	1421      	subi      	r14, r14, 4
   4:	6d83      	mov      	r6, r0
   6:	6d47      	mov      	r5, r1
   8:	e9220008 	bnez      	r2, 0x18	// 18 <atcmd_qa_rxthd_hdl+0x18>
   c:	1103      	lrw      	r0, 0x0	// 98 <atcmd_printf+0x98>
   e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  12:	3000      	movi      	r0, 0
  14:	1401      	addi      	r14, r14, 4
  16:	1493      	pop      	r4-r6, r15
  18:	9100      	ld.w      	r0, (r1, 0x0)
  1a:	1181      	lrw      	r4, 0x0	// 9c <atcmd_qa_rxthd_hdl+0x9c>
  1c:	8060      	ld.b      	r3, (r0, 0x0)
  1e:	eb43003f 	cmpnei      	r3, 63
  22:	0c2a      	bf      	0x76	// 76 <atcmd_qa_rxthd_hdl+0x76>
  24:	3a48      	cmpnei      	r2, 8
  26:	0834      	bt      	0x8e	// 8e <atcmd_qa_rxthd_hdl+0x8e>
  28:	e0000000 	bsr      	0x0	// 0 <atoi>
  2c:	dc04089c 	st.b      	r0, (r4, 0x89c)
  30:	9501      	ld.w      	r0, (r5, 0x4)
  32:	e0000000 	bsr      	0x0	// 0 <atoi>
  36:	dc04089d 	st.b      	r0, (r4, 0x89d)
  3a:	9502      	ld.w      	r0, (r5, 0x8)
  3c:	e0000000 	bsr      	0x0	// 0 <atoi>
  40:	dc04089e 	st.b      	r0, (r4, 0x89e)
  44:	9503      	ld.w      	r0, (r5, 0xc)
  46:	e0000000 	bsr      	0x0	// 0 <atoi>
  4a:	dc04089f 	st.b      	r0, (r4, 0x89f)
  4e:	9504      	ld.w      	r0, (r5, 0x10)
  50:	e0000000 	bsr      	0x0	// 0 <atoi>
  54:	dc0408a0 	st.b      	r0, (r4, 0x8a0)
  58:	9505      	ld.w      	r0, (r5, 0x14)
  5a:	e0000000 	bsr      	0x0	// 0 <atoi>
  5e:	dc0408a1 	st.b      	r0, (r4, 0x8a1)
  62:	9506      	ld.w      	r0, (r5, 0x18)
  64:	e0000000 	bsr      	0x0	// 0 <atoi>
  68:	dc0408a2 	st.b      	r0, (r4, 0x8a2)
  6c:	9507      	ld.w      	r0, (r5, 0x1c)
  6e:	e0000000 	bsr      	0x0	// 0 <atoi>
  72:	dc0408a3 	st.b      	r0, (r4, 0x8a3)
  76:	d824489e 	ld.bs      	r1, (r4, 0x89e)
  7a:	b820      	st.w      	r1, (r14, 0x0)
  7c:	d864489d 	ld.bs      	r3, (r4, 0x89d)
  80:	d844489c 	ld.bs      	r2, (r4, 0x89c)
  84:	5e26      	addi      	r1, r6, 2
  86:	1007      	lrw      	r0, 0x0	// a0 <atcmd_qa_rxthd_hdl+0xa0>
  88:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  8c:	07c3      	br      	0x12	// 12 <atcmd_qa_rxthd_hdl+0x12>
  8e:	1066      	lrw      	r3, 0x0	// a4 <atcmd_qa_rxthd_hdl+0xa4>
  90:	3200      	movi      	r2, 0
  92:	2a00      	subi      	r2, 1
  94:	b352      	st.w      	r2, (r3, 0x48)
  96:	07f0      	br      	0x76	// 76 <atcmd_qa_rxthd_hdl+0x76>
	...

Disassembly of section .text.atcmd_qa_txthd_hdl:

00000000 <atcmd_qa_txthd_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	1421      	subi      	r14, r14, 4
   4:	6d83      	mov      	r6, r0
   6:	6d47      	mov      	r5, r1
   8:	e9220008 	bnez      	r2, 0x18	// 18 <atcmd_qa_txthd_hdl+0x18>
   c:	1103      	lrw      	r0, 0x0	// 98 <atcmd_printf+0x98>
   e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  12:	3000      	movi      	r0, 0
  14:	1401      	addi      	r14, r14, 4
  16:	1493      	pop      	r4-r6, r15
  18:	9100      	ld.w      	r0, (r1, 0x0)
  1a:	1181      	lrw      	r4, 0x0	// 9c <atcmd_qa_txthd_hdl+0x9c>
  1c:	8060      	ld.b      	r3, (r0, 0x0)
  1e:	eb43003f 	cmpnei      	r3, 63
  22:	0c2a      	bf      	0x76	// 76 <atcmd_qa_txthd_hdl+0x76>
  24:	3a48      	cmpnei      	r2, 8
  26:	0834      	bt      	0x8e	// 8e <atcmd_qa_txthd_hdl+0x8e>
  28:	e0000000 	bsr      	0x0	// 0 <atoi>
  2c:	dc0408a4 	st.b      	r0, (r4, 0x8a4)
  30:	9501      	ld.w      	r0, (r5, 0x4)
  32:	e0000000 	bsr      	0x0	// 0 <atoi>
  36:	dc0408a5 	st.b      	r0, (r4, 0x8a5)
  3a:	9502      	ld.w      	r0, (r5, 0x8)
  3c:	e0000000 	bsr      	0x0	// 0 <atoi>
  40:	dc0408a6 	st.b      	r0, (r4, 0x8a6)
  44:	9503      	ld.w      	r0, (r5, 0xc)
  46:	e0000000 	bsr      	0x0	// 0 <atoi>
  4a:	dc0408a7 	st.b      	r0, (r4, 0x8a7)
  4e:	9504      	ld.w      	r0, (r5, 0x10)
  50:	e0000000 	bsr      	0x0	// 0 <atoi>
  54:	dc0408a8 	st.b      	r0, (r4, 0x8a8)
  58:	9505      	ld.w      	r0, (r5, 0x14)
  5a:	e0000000 	bsr      	0x0	// 0 <atoi>
  5e:	dc0408a9 	st.b      	r0, (r4, 0x8a9)
  62:	9506      	ld.w      	r0, (r5, 0x18)
  64:	e0000000 	bsr      	0x0	// 0 <atoi>
  68:	dc0408aa 	st.b      	r0, (r4, 0x8aa)
  6c:	9507      	ld.w      	r0, (r5, 0x1c)
  6e:	e0000000 	bsr      	0x0	// 0 <atoi>
  72:	dc0408ab 	st.b      	r0, (r4, 0x8ab)
  76:	d82448a6 	ld.bs      	r1, (r4, 0x8a6)
  7a:	b820      	st.w      	r1, (r14, 0x0)
  7c:	d86448a5 	ld.bs      	r3, (r4, 0x8a5)
  80:	d84448a4 	ld.bs      	r2, (r4, 0x8a4)
  84:	5e26      	addi      	r1, r6, 2
  86:	1007      	lrw      	r0, 0x0	// a0 <atcmd_qa_txthd_hdl+0xa0>
  88:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  8c:	07c3      	br      	0x12	// 12 <atcmd_qa_txthd_hdl+0x12>
  8e:	1066      	lrw      	r3, 0x0	// a4 <atcmd_qa_txthd_hdl+0xa4>
  90:	3200      	movi      	r2, 0
  92:	2a00      	subi      	r2, 1
  94:	b352      	st.w      	r2, (r3, 0x48)
  96:	07f0      	br      	0x76	// 76 <atcmd_qa_txthd_hdl+0x76>
	...

Disassembly of section .text.atcmd_qa_start_hdl:

00000000 <atcmd_qa_start_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d83      	mov      	r6, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_qa_start_hdl+0x12>
   8:	1217      	lrw      	r0, 0x0	// 164 <atcmd_printf+0x164>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1493      	pop      	r4-r6, r15
  12:	9160      	ld.w      	r3, (r1, 0x0)
  14:	1295      	lrw      	r4, 0x0	// 168 <atcmd_qa_start_hdl+0x168>
  16:	8360      	ld.b      	r3, (r3, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c4a      	bf      	0xb0	// b0 <atcmd_qa_start_hdl+0xb0>
  1e:	eb430031 	cmpnei      	r3, 49
  22:	0855      	bt      	0xcc	// cc <atcmd_qa_start_hdl+0xcc>
  24:	3301      	movi      	r3, 1
  26:	dc640866 	st.b      	r3, (r4, 0x866)
  2a:	32ff      	movi      	r2, 255
  2c:	1270      	lrw      	r3, 0x0	// 16c <atcmd_qa_start_hdl+0x16c>
  2e:	4242      	lsli      	r2, r2, 2
  30:	ab52      	st.h      	r2, (r3, 0x24)
  32:	3200      	movi      	r2, 0
  34:	ab53      	st.h      	r2, (r3, 0x26)
  36:	ab5d      	st.h      	r2, (r3, 0x3a)
  38:	3280      	movi      	r2, 128
  3a:	4241      	lsli      	r2, r2, 1
  3c:	3501      	movi      	r5, 1
  3e:	dc431020 	st.h      	r2, (r3, 0x40)
  42:	d8640892 	ld.b      	r3, (r4, 0x892)
  46:	c4655c01 	ins      	r3, r5, 1, 1
  4a:	3206      	movi      	r2, 6
  4c:	3100      	movi      	r1, 0
  4e:	e40408c1 	addi      	r0, r4, 2242
  52:	dc640892 	st.b      	r3, (r4, 0x892)
  56:	e0000000 	bsr      	0x0	// 0 <memset>
  5a:	327f      	movi      	r2, 127
  5c:	313f      	movi      	r1, 63
  5e:	3000      	movi      	r0, 0
  60:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_cw_param>
  64:	327f      	movi      	r2, 127
  66:	313f      	movi      	r1, 63
  68:	6c17      	mov      	r0, r5
  6a:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_cw_param>
  6e:	327f      	movi      	r2, 127
  70:	313f      	movi      	r1, 63
  72:	3002      	movi      	r0, 2
  74:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_cw_param>
  78:	327f      	movi      	r2, 127
  7a:	313f      	movi      	r1, 63
  7c:	3003      	movi      	r0, 3
  7e:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_cw_param>
  82:	6c17      	mov      	r0, r5
  84:	e0000000 	bsr      	0x0	// 0 <atcmd_qa_start_hdl>
  88:	9460      	ld.w      	r3, (r4, 0x0)
  8a:	3100      	movi      	r1, 0
  8c:	834a      	ld.b      	r2, (r3, 0xa)
  8e:	c4415c00 	ins      	r2, r1, 0, 0
  92:	a34a      	st.b      	r2, (r3, 0xa)
  94:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
  98:	d8440892 	ld.b      	r2, (r4, 0x892)
  9c:	e46320df 	andi      	r3, r3, 223
  a0:	c4455c00 	ins      	r2, r5, 0, 0
  a4:	c4655c03 	ins      	r3, r5, 3, 3
  a8:	dc440892 	st.b      	r2, (r4, 0x892)
  ac:	dc6409e2 	st.b      	r3, (r4, 0x9e2)
  b0:	d8640892 	ld.b      	r3, (r4, 0x892)
  b4:	e4632001 	andi      	r3, r3, 1
  b8:	3b40      	cmpnei      	r3, 0
  ba:	114e      	lrw      	r2, 0x0	// 170 <atcmd_qa_start_hdl+0x170>
  bc:	116e      	lrw      	r3, 0x0	// 174 <atcmd_qa_start_hdl+0x174>
  be:	c4430c20 	incf      	r2, r3, 0
  c2:	5e26      	addi      	r1, r6, 2
  c4:	110d      	lrw      	r0, 0x0	// 178 <atcmd_qa_start_hdl+0x178>
  c6:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  ca:	07a2      	br      	0xe	// e <atcmd_qa_start_hdl+0xe>
  cc:	eb430030 	cmpnei      	r3, 48
  d0:	0bf0      	bt      	0xb0	// b0 <atcmd_qa_start_hdl+0xb0>
  d2:	d86409e2 	ld.b      	r3, (r4, 0x9e2)
  d6:	3000      	movi      	r0, 0
  d8:	e46320f7 	andi      	r3, r3, 247
  dc:	c4605c05 	ins      	r3, r0, 5, 5
  e0:	d84408bf 	ld.b      	r2, (r4, 0x8bf)
  e4:	dc6409e2 	st.b      	r3, (r4, 0x9e2)
  e8:	c4405c00 	ins      	r2, r0, 0, 0
  ec:	d8640892 	ld.b      	r3, (r4, 0x892)
  f0:	dc4408bf 	st.b      	r2, (r4, 0x8bf)
  f4:	e46320fe 	andi      	r3, r3, 254
  f8:	6c83      	mov      	r2, r0
  fa:	c4605c01 	ins      	r3, r0, 1, 1
  fe:	2a7f      	subi      	r2, 128
 100:	dc4408ac 	st.b      	r2, (r4, 0x8ac)
 104:	dc4408b6 	st.b      	r2, (r4, 0x8b6)
 108:	dc640892 	st.b      	r3, (r4, 0x892)
 10c:	32c2      	movi      	r2, 194
 10e:	1078      	lrw      	r3, 0x0	// 16c <atcmd_qa_start_hdl+0x16c>
 110:	4242      	lsli      	r2, r2, 2
 112:	ab52      	st.h      	r2, (r3, 0x24)
 114:	3200      	movi      	r2, 0
 116:	317f      	movi      	r1, 127
 118:	b30a      	st.w      	r0, (r3, 0x28)
 11a:	ab56      	st.h      	r2, (r3, 0x2c)
 11c:	3300      	movi      	r3, 0
 11e:	2b00      	subi      	r3, 1
 120:	dc2408ae 	st.b      	r1, (r4, 0x8ae)
 124:	dc2408b8 	st.b      	r1, (r4, 0x8b8)
 128:	8c5c      	ld.h      	r2, (r4, 0x38)
 12a:	8c34      	ld.h      	r1, (r4, 0x28)
 12c:	dc640866 	st.b      	r3, (r4, 0x866)
 130:	dc0408ad 	st.b      	r0, (r4, 0x8ad)
 134:	dc0408b7 	st.b      	r0, (r4, 0x8b7)
 138:	dc0408c0 	st.b      	r0, (r4, 0x8c0)
 13c:	dc0408c1 	st.b      	r0, (r4, 0x8c1)
 140:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_cw_param>
 144:	8c5d      	ld.h      	r2, (r4, 0x3a)
 146:	8c35      	ld.h      	r1, (r4, 0x2a)
 148:	3001      	movi      	r0, 1
 14a:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_cw_param>
 14e:	8c5e      	ld.h      	r2, (r4, 0x3c)
 150:	8c36      	ld.h      	r1, (r4, 0x2c)
 152:	3002      	movi      	r0, 2
 154:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_cw_param>
 158:	8c5f      	ld.h      	r2, (r4, 0x3e)
 15a:	8c37      	ld.h      	r1, (r4, 0x2e)
 15c:	3003      	movi      	r0, 3
 15e:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_cw_param>
 162:	07a7      	br      	0xb0	// b0 <atcmd_qa_start_hdl+0xb0>
	...

Disassembly of section .text.atcmd_qa_results_hdl:

00000000 <atcmd_qa_results_hdl>:
   0:	14d1      	push      	r4, r15
   2:	e9220007 	bnez      	r2, 0x10	// 10 <atcmd_qa_results_hdl+0x10>
   6:	101d      	lrw      	r0, 0x0	// 78 <atcmd_printf+0x78>
   8:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   c:	3000      	movi      	r0, 0
   e:	1491      	pop      	r4, r15
  10:	9160      	ld.w      	r3, (r1, 0x0)
  12:	8360      	ld.b      	r3, (r3, 0x0)
  14:	eb43003f 	cmpnei      	r3, 63
  18:	082a      	bt      	0x6c	// 6c <atcmd_qa_results_hdl+0x6c>
  1a:	c0006024 	mfcr      	r4, cr<0, 0>
  1e:	c0807020 	psrclr      	ie
  22:	1077      	lrw      	r3, 0x0	// 7c <atcmd_qa_results_hdl+0x7c>
  24:	3200      	movi      	r2, 0
  26:	2a58      	subi      	r2, 89
  28:	d82348b0 	ld.bs      	r1, (r3, 0x8b0)
  2c:	6485      	cmplt      	r1, r2
  2e:	e4842040 	andi      	r4, r4, 64
  32:	d84308c0 	ld.b      	r2, (r3, 0x8c0)
  36:	0c16      	bf      	0x62	// 62 <atcmd_qa_results_hdl+0x62>
  38:	ec420010 	ori      	r2, r2, 16
  3c:	d8231459 	ld.h      	r1, (r3, 0x8b2)
  40:	dc4308c0 	st.b      	r2, (r3, 0x8c0)
  44:	d84308c0 	ld.b      	r2, (r3, 0x8c0)
  48:	e901000f 	bez      	r1, 0x66	// 66 <atcmd_qa_results_hdl+0x66>
  4c:	ec420060 	ori      	r2, r2, 96
  50:	dc4308c0 	st.b      	r2, (r3, 0x8c0)
  54:	e0000000 	bsr      	0x0	// 0 <lmac_qa_results_valid_check>
  58:	e904ffda 	bez      	r4, 0xc	// c <atcmd_qa_results_hdl+0xc>
  5c:	c0807420 	psrset      	ie
  60:	07d6      	br      	0xc	// c <atcmd_qa_results_hdl+0xc>
  62:	3a84      	bclri      	r2, 4
  64:	07ec      	br      	0x3c	// 3c <atcmd_qa_results_hdl+0x3c>
  66:	3a85      	bclri      	r2, 5
  68:	3a86      	bclri      	r2, 6
  6a:	07f3      	br      	0x50	// 50 <atcmd_qa_results_hdl+0x50>
  6c:	1065      	lrw      	r3, 0x0	// 80 <atcmd_qa_results_hdl+0x80>
  6e:	3200      	movi      	r2, 0
  70:	2a00      	subi      	r2, 1
  72:	b352      	st.w      	r2, (r3, 0x48)
  74:	07cc      	br      	0xc	// c <atcmd_qa_results_hdl+0xc>
	...

Disassembly of section .text.atcmd_short_gi_hdl:

00000000 <atcmd_short_gi_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_short_gi_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_short_gi_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d8640310 	ld.b      	r3, (r4, 0x310)
  26:	e9000015 	bez      	r0, 0x50	// 50 <atcmd_short_gi_hdl+0x50>
  2a:	3201      	movi      	r2, 1
  2c:	c4625c00 	ins      	r3, r2, 0, 0
  30:	dc640310 	st.b      	r3, (r4, 0x310)
  34:	d8640310 	ld.b      	r3, (r4, 0x310)
  38:	e4632001 	andi      	r3, r3, 1
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1049      	lrw      	r2, 0x0	// 60 <atcmd_short_gi_hdl+0x60>
  40:	1069      	lrw      	r3, 0x0	// 64 <atcmd_short_gi_hdl+0x64>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1008      	lrw      	r0, 0x0	// 68 <atcmd_short_gi_hdl+0x68>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_short_gi_hdl+0xe>
  50:	c4605c00 	ins      	r3, r0, 0, 0
  54:	07ee      	br      	0x30	// 30 <atcmd_short_gi_hdl+0x30>
	...

Disassembly of section .text.atcmd_obss_switch_hdl:

00000000 <atcmd_obss_switch_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_obss_switch_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_obss_switch_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d8640310 	ld.b      	r3, (r4, 0x310)
  26:	e9000015 	bez      	r0, 0x50	// 50 <atcmd_obss_switch_hdl+0x50>
  2a:	3201      	movi      	r2, 1
  2c:	c4625c01 	ins      	r3, r2, 1, 1
  30:	dc640310 	st.b      	r3, (r4, 0x310)
  34:	d8640310 	ld.b      	r3, (r4, 0x310)
  38:	e4632002 	andi      	r3, r3, 2
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1049      	lrw      	r2, 0x0	// 60 <atcmd_obss_switch_hdl+0x60>
  40:	1069      	lrw      	r3, 0x0	// 64 <atcmd_obss_switch_hdl+0x64>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1008      	lrw      	r0, 0x0	// 68 <atcmd_obss_switch_hdl+0x68>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_obss_switch_hdl+0xe>
  50:	c4605c01 	ins      	r3, r0, 1, 1
  54:	07ee      	br      	0x30	// 30 <atcmd_obss_switch_hdl+0x30>
	...

Disassembly of section .text.atcmd_obss_edca_hdl:

00000000 <atcmd_obss_edca_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_obss_edca_hdl+0x12>
   8:	1014      	lrw      	r0, 0x0	// 58 <atcmd_printf+0x58>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1092      	lrw      	r4, 0x0	// 5c <atcmd_obss_edca_hdl+0x5c>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0c      	bf      	0x34	// 34 <atoi+0x34>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	d8640310 	ld.b      	r3, (r4, 0x310)
  26:	e9000015 	bez      	r0, 0x50	// 50 <atcmd_obss_edca_hdl+0x50>
  2a:	3201      	movi      	r2, 1
  2c:	c4625c02 	ins      	r3, r2, 2, 2
  30:	dc640310 	st.b      	r3, (r4, 0x310)
  34:	d8640310 	ld.b      	r3, (r4, 0x310)
  38:	e4632004 	andi      	r3, r3, 4
  3c:	3b40      	cmpnei      	r3, 0
  3e:	1049      	lrw      	r2, 0x0	// 60 <atcmd_obss_edca_hdl+0x60>
  40:	1069      	lrw      	r3, 0x0	// 64 <atcmd_obss_edca_hdl+0x64>
  42:	c4430c20 	incf      	r2, r3, 0
  46:	5d26      	addi      	r1, r5, 2
  48:	1008      	lrw      	r0, 0x0	// 68 <atcmd_obss_edca_hdl+0x68>
  4a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  4e:	07e0      	br      	0xe	// e <atcmd_obss_edca_hdl+0xe>
  50:	c4605c02 	ins      	r3, r0, 2, 2
  54:	07ee      	br      	0x30	// 30 <atcmd_obss_edca_hdl+0x30>
	...

Disassembly of section .text.atcmd_obss_th_hdl:

00000000 <atcmd_obss_th_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_obss_th_hdl+0x12>
   8:	100b      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1089      	lrw      	r4, 0x0	// 38 <atcmd_obss_th_hdl+0x38>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c05      	bf      	0x26	// 26 <atoi+0x26>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	dc040300 	st.b      	r0, (r4, 0x300)
  26:	d8444300 	ld.bs      	r2, (r4, 0x300)
  2a:	5d26      	addi      	r1, r5, 2
  2c:	1004      	lrw      	r0, 0x0	// 3c <atcmd_obss_th_hdl+0x3c>
  2e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  32:	07ee      	br      	0xe	// e <atcmd_obss_th_hdl+0xe>
	...

Disassembly of section .text.atcmd_tx_delay_hdl:

00000000 <atcmd_tx_delay_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_tx_delay_hdl+0x12>
   8:	100f      	lrw      	r0, 0x0	// 44 <atcmd_printf+0x44>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108d      	lrw      	r4, 0x0	// 48 <atcmd_tx_delay_hdl+0x48>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0b      	bf      	0x32	// 32 <atoi+0x32>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	e9800008 	blz      	r0, 0x32	// 32 <atcmd_tx_delay_hdl+0x32>
  26:	d86414f1 	ld.h      	r3, (r4, 0x9e2)
  2a:	c4605ce6 	ins      	r3, r0, 13, 6
  2e:	dc6414f1 	st.h      	r3, (r4, 0x9e2)
  32:	d84414f1 	ld.h      	r2, (r4, 0x9e2)
  36:	c4c255a2 	zext      	r2, r2, 13, 6
  3a:	5d26      	addi      	r1, r5, 2
  3c:	1004      	lrw      	r0, 0x0	// 4c <atcmd_tx_delay_hdl+0x4c>
  3e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  42:	07e6      	br      	0xe	// e <atcmd_tx_delay_hdl+0xe>
	...

Disassembly of section .text.atcmd_rc_new_hdl:

00000000 <atcmd_rc_new_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_rc_new_hdl+0x12>
   8:	1016      	lrw      	r0, 0x0	// 60 <atcmd_printf+0x60>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	1094      	lrw      	r4, 0x0	// 64 <atcmd_rc_new_hdl+0x64>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c0e      	bf      	0x38	// 38 <atoi+0x38>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	dc040311 	st.b      	r0, (r4, 0x311)
  26:	d8640338 	ld.b      	r3, (r4, 0x338)
  2a:	e9000017 	bez      	r0, 0x58	// 58 <atcmd_rc_new_hdl+0x58>
  2e:	3201      	movi      	r2, 1
  30:	c4625c03 	ins      	r3, r2, 3, 3
  34:	dc640338 	st.b      	r3, (r4, 0x338)
  38:	d8640338 	ld.b      	r3, (r4, 0x338)
  3c:	e4632008 	andi      	r3, r3, 8
  40:	3b40      	cmpnei      	r3, 0
  42:	102a      	lrw      	r1, 0x0	// 68 <atcmd_rc_new_hdl+0x68>
  44:	104a      	lrw      	r2, 0x0	// 6c <atcmd_rc_new_hdl+0x6c>
  46:	c4410c40 	inct      	r2, r1, 0
  4a:	d8640311 	ld.b      	r3, (r4, 0x311)
  4e:	5d26      	addi      	r1, r5, 2
  50:	1008      	lrw      	r0, 0x0	// 70 <atcmd_rc_new_hdl+0x70>
  52:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  56:	07dc      	br      	0xe	// e <atcmd_rc_new_hdl+0xe>
  58:	c4605c03 	ins      	r3, r0, 3, 3
  5c:	07ec      	br      	0x34	// 34 <atcmd_rc_new_hdl+0x34>
	...

Disassembly of section .text.atcmd_rf_reset_hdl:

00000000 <atcmd_rf_reset_hdl>:
   0:	14d0      	push      	r15
   2:	1421      	subi      	r14, r14, 4
   4:	e9220008 	bnez      	r2, 0x14	// 14 <atcmd_rf_reset_hdl+0x14>
   8:	100b      	lrw      	r0, 0x0	// 34 <atcmd_printf+0x34>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1401      	addi      	r14, r14, 4
  12:	1490      	pop      	r15
  14:	9160      	ld.w      	r3, (r1, 0x0)
  16:	5826      	addi      	r1, r0, 2
  18:	8360      	ld.b      	r3, (r3, 0x0)
  1a:	eb430031 	cmpnei      	r3, 49
  1e:	0809      	bt      	0x30	// 30 <atcmd_rf_reset_hdl+0x30>
  20:	b820      	st.w      	r1, (r14, 0x0)
  22:	e0000000 	bsr      	0x0	// 0 <lmac_rf_reset>
  26:	9820      	ld.w      	r1, (r14, 0x0)
  28:	1004      	lrw      	r0, 0x0	// 38 <atcmd_rf_reset_hdl+0x38>
  2a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  2e:	07f0      	br      	0xe	// e <atcmd_rf_reset_hdl+0xe>
  30:	1003      	lrw      	r0, 0x0	// 3c <atcmd_rf_reset_hdl+0x3c>
  32:	07fc      	br      	0x2a	// 2a <atcmd_rf_reset_hdl+0x2a>
	...

Disassembly of section .text.atcmd_phy_reset_hdl:

00000000 <atcmd_phy_reset_hdl>:
   0:	14d0      	push      	r15
   2:	1421      	subi      	r14, r14, 4
   4:	e9220008 	bnez      	r2, 0x14	// 14 <atcmd_phy_reset_hdl+0x14>
   8:	100f      	lrw      	r0, 0x0	// 44 <atcmd_printf+0x44>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1401      	addi      	r14, r14, 4
  12:	1490      	pop      	r15
  14:	9160      	ld.w      	r3, (r1, 0x0)
  16:	5826      	addi      	r1, r0, 2
  18:	8360      	ld.b      	r3, (r3, 0x0)
  1a:	eb430031 	cmpnei      	r3, 49
  1e:	0810      	bt      	0x3e	// 3e <atcmd_phy_reset_hdl+0x3e>
  20:	b820      	st.w      	r1, (r14, 0x0)
  22:	e0000000 	bsr      	0x0	// 0 <ah_wphy_soft_reset>
  26:	6c03      	mov      	r0, r0
  28:	6c03      	mov      	r0, r0
  2a:	6c03      	mov      	r0, r0
  2c:	6c03      	mov      	r0, r0
  2e:	6c03      	mov      	r0, r0
  30:	e0000000 	bsr      	0x0	// 0 <ah_wphy_soft_dereset>
  34:	9820      	ld.w      	r1, (r14, 0x0)
  36:	1005      	lrw      	r0, 0x0	// 48 <atcmd_phy_reset_hdl+0x48>
  38:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  3c:	07e9      	br      	0xe	// e <atcmd_phy_reset_hdl+0xe>
  3e:	1004      	lrw      	r0, 0x0	// 4c <atcmd_phy_reset_hdl+0x4c>
  40:	07fc      	br      	0x38	// 38 <atcmd_phy_reset_hdl+0x38>
	...

Disassembly of section .text.atcmd_adc_dump_hdl:

00000000 <atcmd_adc_dump_hdl>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_adc_dump_hdl+0x12>
   8:	100d      	lrw      	r0, 0x0	// 3c <atcmd_printf+0x3c>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1492      	pop      	r4-r5, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	108b      	lrw      	r4, 0x0	// 40 <atcmd_adc_dump_hdl+0x40>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0c08      	bf      	0x2c	// 2c <atoi+0x2c>
  1e:	e0000000 	bsr      	0x0	// 0 <atoi>
  22:	eb0000ff 	cmphsi      	r0, 256
  26:	0803      	bt      	0x2c	// 2c <atcmd_adc_dump_hdl+0x2c>
  28:	dc040332 	st.b      	r0, (r4, 0x332)
  2c:	d8440332 	ld.b      	r2, (r4, 0x332)
  30:	5d26      	addi      	r1, r5, 2
  32:	1005      	lrw      	r0, 0x0	// 44 <atcmd_adc_dump_hdl+0x44>
  34:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  38:	07eb      	br      	0xe	// e <atcmd_adc_dump_hdl+0xe>
	...

Disassembly of section .text.atcmd_short_th_hdl:

00000000 <atcmd_short_th_hdl>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_short_th_hdl+0x12>
   8:	100a      	lrw      	r0, 0x0	// 30 <atcmd_printf+0x30>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1491      	pop      	r4, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	e0000000 	bsr      	0x0	// 0 <atoi>
  18:	1067      	lrw      	r3, 0x0	// 34 <atcmd_short_th_hdl+0x34>
  1a:	e9600004 	blsz      	r0, 0x22	// 22 <atcmd_short_th_hdl+0x22>
  1e:	dc03119a 	st.h      	r0, (r3, 0x334)
  22:	d843119a 	ld.h      	r2, (r3, 0x334)
  26:	5c26      	addi      	r1, r4, 2
  28:	1004      	lrw      	r0, 0x0	// 38 <atcmd_short_th_hdl+0x38>
  2a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  2e:	07f0      	br      	0xe	// e <atcmd_short_th_hdl+0xe>
	...

Disassembly of section .text.atcmd_qa_att_hdl:

00000000 <atcmd_qa_att_hdl>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_qa_att_hdl+0x12>
   8:	100a      	lrw      	r0, 0x0	// 30 <atcmd_printf+0x30>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1491      	pop      	r4, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	e0000000 	bsr      	0x0	// 0 <atoi>
  18:	1067      	lrw      	r3, 0x0	// 34 <atcmd_qa_att_hdl+0x34>
  1a:	e9600004 	blsz      	r0, 0x22	// 22 <atcmd_qa_att_hdl+0x22>
  1e:	dc03089b 	st.b      	r0, (r3, 0x89b)
  22:	d843119a 	ld.h      	r2, (r3, 0x334)
  26:	5c26      	addi      	r1, r4, 2
  28:	1004      	lrw      	r0, 0x0	// 38 <atcmd_qa_att_hdl+0x38>
  2a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  2e:	07f0      	br      	0xe	// e <atcmd_qa_att_hdl+0xe>
	...

Disassembly of section .text.atcmd_lo_table_read_hdl:

00000000 <atcmd_lo_table_read_hdl>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_lo_table_read_hdl+0x12>
   8:	1013      	lrw      	r0, 0x0	// 54 <atcmd_printf+0x54>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1491      	pop      	r4, r15
  12:	9160      	ld.w      	r3, (r1, 0x0)
  14:	8360      	ld.b      	r3, (r3, 0x0)
  16:	eb43003f 	cmpnei      	r3, 63
  1a:	0808      	bt      	0x2a	// 2a <lmac_lo_table_read+0x2a>
  1c:	e0000000 	bsr      	0x0	// 0 <lmac_lo_table_read>
  20:	5c26      	addi      	r1, r4, 2
  22:	100e      	lrw      	r0, 0x0	// 58 <atcmd_lo_table_read_hdl+0x58>
  24:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  28:	07f3      	br      	0xe	// e <atcmd_lo_table_read_hdl+0xe>
  2a:	eb43006b 	cmpnei      	r3, 107
  2e:	0807      	bt      	0x3c	// 3c <atcmd_lo_table_read_hdl+0x3c>
  30:	106b      	lrw      	r3, 0x0	// 5c <atcmd_lo_table_read_hdl+0x5c>
  32:	d803033c 	ld.b      	r0, (r3, 0x33c)
  36:	e0000000 	bsr      	0x0	// 0 <lmac_lo_table_kick>
  3a:	07f3      	br      	0x20	// 20 <atcmd_lo_table_read_hdl+0x20>
  3c:	eb430073 	cmpnei      	r3, 115
  40:	0bf0      	bt      	0x20	// 20 <atcmd_lo_table_read_hdl+0x20>
  42:	1067      	lrw      	r3, 0x0	// 5c <atcmd_lo_table_read_hdl+0x5c>
  44:	d80320ce 	ld.w      	r0, (r3, 0x338)
  48:	c4805760 	zext      	r0, r0, 27, 4
  4c:	e0000000 	bsr      	0x0	// 0 <lmac_lo_freq_set>
  50:	07e8      	br      	0x20	// 20 <atcmd_lo_table_read_hdl+0x20>
	...

Disassembly of section .text.atcmd_ps_check_hdl:

00000000 <atcmd_ps_check_hdl>:
   0:	14d4      	push      	r4-r7, r15
   2:	1421      	subi      	r14, r14, 4
   4:	6dc3      	mov      	r7, r0
   6:	6d47      	mov      	r5, r1
   8:	e9220008 	bnez      	r2, 0x18	// 18 <atcmd_ps_check_hdl+0x18>
   c:	1018      	lrw      	r0, 0x0	// 6c <atcmd_printf+0x6c>
   e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  12:	3000      	movi      	r0, 0
  14:	1401      	addi      	r14, r14, 4
  16:	1494      	pop      	r4-r7, r15
  18:	3a43      	cmpnei      	r2, 3
  1a:	1096      	lrw      	r4, 0x0	// 70 <atcmd_ps_check_hdl+0x70>
  1c:	0817      	bt      	0x4a	// 4a <atcmd_ps_check_hdl+0x4a>
  1e:	9100      	ld.w      	r0, (r1, 0x0)
  20:	e0000000 	bsr      	0x0	// 0 <atoi>
  24:	94c0      	ld.w      	r6, (r4, 0x0)
  26:	dc042267 	st.w      	r0, (r4, 0x99c)
  2a:	9501      	ld.w      	r0, (r5, 0x4)
  2c:	e0000000 	bsr      	0x0	// 0 <atoi>
  30:	866a      	ld.b      	r3, (r6, 0xa)
  32:	c4605c00 	ins      	r3, r0, 0, 0
  36:	a66a      	st.b      	r3, (r6, 0xa)
  38:	9502      	ld.w      	r0, (r5, 0x8)
  3a:	e0000000 	bsr      	0x0	// 0 <atoi>
  3e:	d8640319 	ld.b      	r3, (r4, 0x319)
  42:	c4605c01 	ins      	r3, r0, 1, 1
  46:	dc640319 	st.b      	r3, (r4, 0x319)
  4a:	9460      	ld.w      	r3, (r4, 0x0)
  4c:	d8240319 	ld.b      	r1, (r4, 0x319)
  50:	836a      	ld.b      	r3, (r3, 0xa)
  52:	c4215421 	zext      	r1, r1, 1, 1
  56:	b820      	st.w      	r1, (r14, 0x0)
  58:	d8442267 	ld.w      	r2, (r4, 0x99c)
  5c:	e4632001 	andi      	r3, r3, 1
  60:	5f26      	addi      	r1, r7, 2
  62:	1005      	lrw      	r0, 0x0	// 74 <atcmd_ps_check_hdl+0x74>
  64:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  68:	07d5      	br      	0x12	// 12 <atcmd_ps_check_hdl+0x12>
	...

Disassembly of section .text.atcmd_radio_onoff_hdl:

00000000 <atcmd_radio_onoff_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d43      	mov      	r5, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_radio_onoff_hdl+0x12>
   8:	1013      	lrw      	r0, 0x0	// 54 <atcmd_printf+0x54>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1493      	pop      	r4-r6, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	10d1      	lrw      	r6, 0x0	// 58 <atcmd_radio_onoff_hdl+0x58>
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0811      	bt      	0x3e	// 3e <atcmd_radio_onoff_hdl+0x3e>
  1e:	9660      	ld.w      	r3, (r6, 0x0)
  20:	838a      	ld.b      	r4, (r3, 0xa)
  22:	e4842001 	andi      	r4, r4, 1
  26:	5d26      	addi      	r1, r5, 2
  28:	e9040013 	bez      	r4, 0x4e	// 4e <atcmd_radio_onoff_hdl+0x4e>
  2c:	3c41      	cmpnei      	r4, 1
  2e:	106c      	lrw      	r3, 0x0	// 5c <atcmd_radio_onoff_hdl+0x5c>
  30:	104c      	lrw      	r2, 0x0	// 60 <atcmd_radio_onoff_hdl+0x60>
  32:	c4430c40 	inct      	r2, r3, 0
  36:	100c      	lrw      	r0, 0x0	// 64 <atcmd_printf+0x64>
  38:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  3c:	07e9      	br      	0xe	// e <atoi+0xe>
  3e:	e0000000 	bsr      	0x0	// 0 <atoi>
  42:	6d03      	mov      	r4, r0
  44:	6c43      	mov      	r1, r0
  46:	9600      	ld.w      	r0, (r6, 0x0)
  48:	e0000000 	bsr      	0x0	// 0 <lmac_set_radio_onoff>
  4c:	07ed      	br      	0x26	// 26 <atcmd_radio_onoff_hdl+0x26>
  4e:	1047      	lrw      	r2, 0x0	// 68 <atcmd_radio_onoff_hdl+0x68>
  50:	07f3      	br      	0x36	// 36 <atcmd_radio_onoff_hdl+0x36>
	...

Disassembly of section .text.atcmd_sta_info_hdl:

00000000 <atcmd_sta_info_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d83      	mov      	r6, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_sta_info_hdl+0x12>
   8:	101f      	lrw      	r0, 0x0	// 84 <atcmd_printf+0x84>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1493      	pop      	r4-r6, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	8060      	ld.b      	r3, (r0, 0x0)
  16:	eb43003f 	cmpnei      	r3, 63
  1a:	0c2b      	bf      	0x70	// 70 <atoi+0x70>
  1c:	e0000000 	bsr      	0x0	// 0 <atoi>
  20:	6d43      	mov      	r5, r0
  22:	e900fff3 	bez      	r0, 0x8	// 8 <atcmd_sta_info_hdl+0x8>
  26:	30fa      	movi      	r0, 250
  28:	4001      	lsli      	r0, r0, 1
  2a:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  2e:	6d03      	mov      	r4, r0
  30:	e900ffec 	bez      	r0, 0x8	// 8 <atcmd_sta_info_hdl+0x8>
  34:	3100      	movi      	r1, 0
  36:	2900      	subi      	r1, 1
  38:	1014      	lrw      	r0, 0x0	// 88 <atcmd_sta_info_hdl+0x88>
  3a:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  3e:	1074      	lrw      	r3, 0x0	// 8c <atcmd_sta_info_hdl+0x8c>
  40:	e46309f7 	addi      	r3, r3, 2552
  44:	9320      	ld.w      	r1, (r3, 0x0)
  46:	64c6      	cmpne      	r1, r3
  48:	0c0e      	bf      	0x64	// 64 <atcmd_sta_info_hdl+0x64>
  4a:	d8411034 	ld.h      	r2, (r1, 0x68)
  4e:	6496      	cmpne      	r5, r2
  50:	0818      	bt      	0x80	// 80 <atcmd_sta_info_hdl+0x80>
  52:	32fa      	movi      	r2, 250
  54:	6c13      	mov      	r0, r4
  56:	4241      	lsli      	r2, r2, 1
  58:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
  5c:	3101      	movi      	r1, 1
  5e:	6c13      	mov      	r0, r4
  60:	e0000000 	bsr      	0x0	// 0 <lmac_sta_info_statics_print>
  64:	1009      	lrw      	r0, 0x0	// 88 <os_mutex_unlock+0x88>
  66:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  6a:	6c13      	mov      	r0, r4
  6c:	e0000000 	bsr      	0x0	// 0 <_os_free>
  70:	1067      	lrw      	r3, 0x0	// 8c <atcmd_sta_info_hdl+0x8c>
  72:	5e26      	addi      	r1, r6, 2
  74:	d8431504 	ld.h      	r2, (r3, 0xa08)
  78:	1006      	lrw      	r0, 0x0	// 90 <atcmd_printf+0x90>
  7a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  7e:	07c8      	br      	0xe	// e <atcmd_sta_info_hdl+0xe>
  80:	9120      	ld.w      	r1, (r1, 0x0)
  82:	07e2      	br      	0x46	// 46 <atcmd_sta_info_hdl+0x46>
	...

Disassembly of section .text.atcmd_sta_psk_hdl:

00000000 <atcmd_sta_psk_hdl>:
   0:	14d6      	push      	r4-r9, r15
   2:	1424      	subi      	r14, r14, 16
   4:	6d83      	mov      	r6, r0
   6:	6d47      	mov      	r5, r1
   8:	e9220008 	bnez      	r2, 0x18	// 18 <atcmd_sta_psk_hdl+0x18>
   c:	1114      	lrw      	r0, 0x0	// dc <atcmd_printf+0xdc>
   e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  12:	3000      	movi      	r0, 0
  14:	1404      	addi      	r14, r14, 16
  16:	1496      	pop      	r4-r9, r15
  18:	9100      	ld.w      	r0, (r1, 0x0)
  1a:	8060      	ld.b      	r3, (r0, 0x0)
  1c:	eb43003f 	cmpnei      	r3, 63
  20:	0844      	bt      	0xa8	// a8 <atcmd_sta_psk_hdl+0xa8>
  22:	3100      	movi      	r1, 0
  24:	2900      	subi      	r1, 1
  26:	110f      	lrw      	r0, 0x0	// e0 <atcmd_sta_psk_hdl+0xe0>
  28:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  2c:	110e      	lrw      	r0, 0x0	// e4 <hgprintf+0xe4>
  2e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  32:	116e      	lrw      	r3, 0x0	// e8 <atcmd_sta_psk_hdl+0xe8>
  34:	e4e309f7 	addi      	r7, r3, 2552
  38:	d883227e 	ld.w      	r4, (r3, 0x9f8)
  3c:	ea88002c 	lrw      	r8, 0x0	// ec <atcmd_sta_psk_hdl+0xec>
  40:	ea89002c 	lrw      	r9, 0x0	// f0 <atcmd_sta_psk_hdl+0xf0>
  44:	65d2      	cmpne      	r4, r7
  46:	0809      	bt      	0x58	// 58 <atcmd_sta_psk_hdl+0x58>
  48:	5c1e      	addi      	r0, r4, 8
  4a:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  4e:	5e26      	addi      	r1, r6, 2
  50:	1109      	lrw      	r0, 0x0	// f4 <atcmd_sta_psk_hdl+0xf4>
  52:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  56:	07de      	br      	0x12	// 12 <atcmd_sta_psk_hdl+0x12>
  58:	d8040074 	ld.b      	r0, (r4, 0x74)
  5c:	d8640070 	ld.b      	r3, (r4, 0x70)
  60:	d844006f 	ld.b      	r2, (r4, 0x6f)
  64:	d8241034 	ld.h      	r1, (r4, 0x68)
  68:	b803      	st.w      	r0, (r14, 0xc)
  6a:	d8040073 	ld.b      	r0, (r4, 0x73)
  6e:	b802      	st.w      	r0, (r14, 0x8)
  70:	d8040072 	ld.b      	r0, (r4, 0x72)
  74:	b801      	st.w      	r0, (r14, 0x4)
  76:	d8040071 	ld.b      	r0, (r4, 0x71)
  7a:	b800      	st.w      	r0, (r14, 0x0)
  7c:	6c23      	mov      	r0, r8
  7e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  82:	3500      	movi      	r5, 0
  84:	d8640076 	ld.b      	r3, (r4, 0x76)
  88:	64d4      	cmphs      	r5, r3
  8a:	0c06      	bf      	0x96	// 96 <atcmd_sta_psk_hdl+0x96>
  8c:	101b      	lrw      	r0, 0x0	// f8 <atcmd_sta_psk_hdl+0xf8>
  8e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  92:	9480      	ld.w      	r4, (r4, 0x0)
  94:	07d8      	br      	0x44	// 44 <atcmd_sta_psk_hdl+0x44>
  96:	5c74      	addu      	r3, r4, r5
  98:	6c27      	mov      	r0, r9
  9a:	d8230077 	ld.b      	r1, (r3, 0x77)
  9e:	2500      	addi      	r5, 1
  a0:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  a4:	7554      	zextb      	r5, r5
  a6:	07ef      	br      	0x84	// 84 <atcmd_sta_psk_hdl+0x84>
  a8:	3a42      	cmpnei      	r2, 2
  aa:	0bd2      	bt      	0x4e	// 4e <atcmd_sta_psk_hdl+0x4e>
  ac:	e0000000 	bsr      	0x0	// 0 <atoi>
  b0:	7401      	zexth      	r0, r0
  b2:	3100      	movi      	r1, 0
  b4:	e0000000 	bsr      	0x0	// 0 <lmac_sta_get>
  b8:	6d03      	mov      	r4, r0
  ba:	e900000c 	bez      	r0, 0xd2	// d2 <atcmd_sta_psk_hdl+0xd2>
  be:	e4200076 	addi      	r1, r0, 119
  c2:	3220      	movi      	r2, 32
  c4:	9501      	ld.w      	r0, (r5, 0x4)
  c6:	e0000000 	bsr      	0x0	// 0 <hex2bin>
  ca:	6c13      	mov      	r0, r4
  cc:	e0000000 	bsr      	0x0	// 0 <lmac_sta_put>
  d0:	07bf      	br      	0x4e	// 4e <atcmd_sta_psk_hdl+0x4e>
  d2:	1003      	lrw      	r0, 0x0	// dc <atcmd_sta_psk_hdl+0xdc>
  d4:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  d8:	07bb      	br      	0x4e	// 4e <atcmd_sta_psk_hdl+0x4e>
	...

Disassembly of section .text.atcmd_txpower_hdl:

00000000 <atcmd_txpower_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	3a41      	cmpnei      	r2, 1
   4:	6d43      	mov      	r5, r0
   6:	6d07      	mov      	r4, r1
   8:	0c06      	bf      	0x14	// 14 <atcmd_txpower_hdl+0x14>
   a:	1017      	lrw      	r0, 0x0	// 64 <atcmd_txpower_hdl+0x64>
   c:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  10:	3000      	movi      	r0, 0
  12:	1493      	pop      	r4-r6, r15
  14:	9100      	ld.w      	r0, (r1, 0x0)
  16:	8060      	ld.b      	r3, (r0, 0x0)
  18:	eb43003f 	cmpnei      	r3, 63
  1c:	0809      	bt      	0x2e	// 2e <atcmd_txpower_hdl+0x2e>
  1e:	1073      	lrw      	r3, 0x0	// 68 <atcmd_txpower_hdl+0x68>
  20:	5d26      	addi      	r1, r5, 2
  22:	d843468e 	ld.bs      	r2, (r3, 0x68e)
  26:	1012      	lrw      	r0, 0x0	// 6c <atcmd_printf+0x6c>
  28:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  2c:	07f2      	br      	0x10	// 10 <atoi+0x10>
  2e:	e0000000 	bsr      	0x0	// 0 <atoi>
  32:	e960ffec 	blsz      	r0, 0xa	// a <atcmd_txpower_hdl+0xa>
  36:	9400      	ld.w      	r0, (r4, 0x0)
  38:	e0000000 	bsr      	0x0	// 0 <atoi>
  3c:	3834      	cmplti      	r0, 21
  3e:	0fe6      	bf      	0xa	// a <atcmd_txpower_hdl+0xa>
  40:	106a      	lrw      	r3, 0x0	// 68 <atcmd_txpower_hdl+0x68>
  42:	9400      	ld.w      	r0, (r4, 0x0)
  44:	93c0      	ld.w      	r6, (r3, 0x0)
  46:	e0000000 	bsr      	0x0	// 0 <atoi>
  4a:	6c83      	mov      	r2, r0
  4c:	3106      	movi      	r1, 6
  4e:	3300      	movi      	r3, 0
  50:	6c1b      	mov      	r0, r6
  52:	e0000000 	bsr      	0x0	// 0 <lmac_ioctl>
  56:	9400      	ld.w      	r0, (r4, 0x0)
  58:	e0000000 	bsr      	0x0	// 0 <atoi>
  5c:	6c83      	mov      	r2, r0
  5e:	5d26      	addi      	r1, r5, 2
  60:	1004      	lrw      	r0, 0x0	// 70 <atcmd_txpower_hdl+0x70>
  62:	07e3      	br      	0x28	// 28 <atcmd_txpower_hdl+0x28>
	...

Disassembly of section .text.atcmd_set_vdd13_hdl:

00000000 <atcmd_set_vdd13_hdl>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d03      	mov      	r4, r0
   4:	e9220007 	bnez      	r2, 0x12	// 12 <atcmd_set_vdd13_hdl+0x12>
   8:	110c      	lrw      	r0, 0x0	// b8 <atcmd_printf+0xb8>
   a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
   e:	3000      	movi      	r0, 0
  10:	1493      	pop      	r4-r6, r15
  12:	9100      	ld.w      	r0, (r1, 0x0)
  14:	8060      	ld.b      	r3, (r0, 0x0)
  16:	eb43003f 	cmpnei      	r3, 63
  1a:	080b      	bt      	0x30	// 30 <atcmd_set_vdd13_hdl+0x30>
  1c:	1168      	lrw      	r3, 0x0	// bc <atcmd_set_vdd13_hdl+0xbc>
  1e:	5c26      	addi      	r1, r4, 2
  20:	d84303df 	ld.b      	r2, (r3, 0x3df)
  24:	e4422003 	andi      	r2, r2, 3
  28:	1106      	lrw      	r0, 0x0	// c0 <atcmd_printf+0xc0>
  2a:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  2e:	07f0      	br      	0xe	// e <atcmd_set_vdd13_hdl+0xe>
  30:	3a41      	cmpnei      	r2, 1
  32:	0bee      	bt      	0xe	// e <atcmd_set_vdd13_hdl+0xe>
  34:	e0000000 	bsr      	0x0	// 0 <atoi>
  38:	7400      	zextb      	r0, r0
  3a:	3802      	cmphsi      	r0, 3
  3c:	0838      	bt      	0xac	// ac <atcmd_set_vdd13_hdl+0xac>
  3e:	1160      	lrw      	r3, 0x0	// bc <atcmd_set_vdd13_hdl+0xbc>
  40:	e4c02003 	andi      	r6, r0, 3
  44:	d84303df 	ld.b      	r2, (r3, 0x3df)
  48:	3841      	cmpnei      	r0, 1
  4a:	c4465c20 	ins      	r2, r6, 1, 0
  4e:	dc4303df 	st.b      	r2, (r3, 0x3df)
  52:	6d4f      	mov      	r5, r3
  54:	0812      	bt      	0x78	// 78 <atcmd_set_vdd13_hdl+0x78>
  56:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13_ldo_dis_sec>
  5a:	5c26      	addi      	r1, r4, 2
  5c:	101a      	lrw      	r0, 0x0	// c4 <atcmd_set_vdd13_hdl+0xc4>
  5e:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  62:	d8652233 	ld.w      	r3, (r5, 0x8cc)
  66:	e903001f 	bez      	r3, 0xa4	// a4 <atcmd_set_vdd13_hdl+0xa4>
  6a:	d843025b 	ld.b      	r2, (r3, 0x25b)
  6e:	c4465c20 	ins      	r2, r6, 1, 0
  72:	dc43025b 	st.b      	r2, (r3, 0x25b)
  76:	07cc      	br      	0xe	// e <atcmd_set_vdd13_hdl+0xe>
  78:	3842      	cmpnei      	r0, 2
  7a:	080a      	bt      	0x8e	// 8e <atcmd_set_vdd13_hdl+0x8e>
  7c:	3005      	movi      	r0, 5
  7e:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13c_vol_set_sec>
  82:	3005      	movi      	r0, 5
  84:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13b_vol_set_sec>
  88:	5c26      	addi      	r1, r4, 2
  8a:	1010      	lrw      	r0, 0x0	// c8 <atcmd_set_vdd13_hdl+0xc8>
  8c:	07e9      	br      	0x5e	// 5e <atcmd_set_vdd13_hdl+0x5e>
  8e:	e920ffea 	bnez      	r0, 0x62	// 62 <atcmd_set_vdd13_hdl+0x62>
  92:	3004      	movi      	r0, 4
  94:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13c_vol_set_sec>
  98:	3004      	movi      	r0, 4
  9a:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13b_vol_set_sec>
  9e:	5c26      	addi      	r1, r4, 2
  a0:	100b      	lrw      	r0, 0x0	// cc <atcmd_set_vdd13_hdl+0xcc>
  a2:	07de      	br      	0x5e	// 5e <atcmd_set_vdd13_hdl+0x5e>
  a4:	100b      	lrw      	r0, 0x0	// d0 <atcmd_set_vdd13_hdl+0xd0>
  a6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  aa:	07b2      	br      	0xe	// e <atcmd_set_vdd13_hdl+0xe>
  ac:	5c26      	addi      	r1, r4, 2
  ae:	100a      	lrw      	r0, 0x0	// d4 <atcmd_set_vdd13_hdl+0xd4>
  b0:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  b4:	07ad      	br      	0xe	// e <atcmd_set_vdd13_hdl+0xe>
	...

Disassembly of section .text.atcmd_smt_dat_hdl:

00000000 <atcmd_smt_dat_hdl>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e0000000 	bsr      	0x0	// 0 <sysctrl_efuse_get_smt_dat>
   8:	6c83      	mov      	r2, r0
   a:	5c26      	addi      	r1, r4, 2
   c:	e9200007 	bnez      	r0, 0x1a	// 1a <atcmd_smt_dat_hdl+0x1a>
  10:	1007      	lrw      	r0, 0x0	// 2c <atcmd_printf+0x2c>
  12:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  16:	3000      	movi      	r0, 0
  18:	1491      	pop      	r4, r15
  1a:	1066      	lrw      	r3, 0x5b8d7f	// 30 <atcmd_smt_dat_hdl+0x30>
  1c:	640c      	cmphs      	r3, r0
  1e:	0c05      	bf      	0x28	// 28 <atcmd_smt_dat_hdl+0x28>
  20:	1005      	lrw      	r0, 0x0	// 34 <atcmd_smt_dat_hdl+0x34>
  22:	e0000000 	bsr      	0x0	// 0 <atcmd_printf>
  26:	07f8      	br      	0x16	// 16 <atcmd_smt_dat_hdl+0x16>
  28:	1004      	lrw      	r0, 0x0	// 38 <atcmd_smt_dat_hdl+0x38>
  2a:	07fc      	br      	0x22	// 22 <atcmd_smt_dat_hdl+0x22>
  2c:	00000000 	.long	0x00000000
  30:	8d7f      	.short	0x8d7f
  32:	005b      	.short	0x005b
	...

Disassembly of section .text.lmac_test_init:

00000000 <lmac_test_init>:
   0:	14d3      	push      	r4-r6, r15
   2:	1186      	lrw      	r4, 0x0	// 98 <lmac_test_init+0x98>
   4:	324c      	movi      	r2, 76
   6:	3100      	movi      	r1, 0
   8:	6c13      	mov      	r0, r4
   a:	e0000000 	bsr      	0x0	// 0 <memset>
   e:	33c2      	movi      	r3, 194
  10:	4362      	lsli      	r3, r3, 2
  12:	ac72      	st.h      	r3, (r4, 0x24)
  14:	3380      	movi      	r3, 128
  16:	1142      	lrw      	r2, 0x0	// 9c <lmac_test_init+0x9c>
  18:	4361      	lsli      	r3, r3, 1
  1a:	dc641020 	st.h      	r3, (r4, 0x40)
  1e:	330a      	movi      	r3, 10
  20:	dc62089a 	st.b      	r3, (r2, 0x89a)
  24:	3300      	movi      	r3, 0
  26:	2b3b      	subi      	r3, 60
  28:	dc62089b 	st.b      	r3, (r2, 0x89b)
  2c:	dc62089c 	st.b      	r3, (r2, 0x89c)
  30:	dc6208a4 	st.b      	r3, (r2, 0x8a4)
  34:	3600      	movi      	r6, 0
  36:	d8620892 	ld.b      	r3, (r2, 0x892)
  3a:	3100      	movi      	r1, 0
  3c:	291a      	subi      	r1, 27
  3e:	c4665c02 	ins      	r3, r6, 2, 2
  42:	dc22089d 	st.b      	r1, (r2, 0x89d)
  46:	dc2208a5 	st.b      	r1, (r2, 0x8a5)
  4a:	dc620892 	st.b      	r3, (r2, 0x892)
  4e:	3105      	movi      	r1, 5
  50:	d86214f1 	ld.h      	r3, (r2, 0x9e2)
  54:	c4615ce6 	ins      	r3, r1, 13, 6
  58:	dc6214f1 	st.h      	r3, (r2, 0x9e2)
  5c:	3380      	movi      	r3, 128
  5e:	e4a4000b 	addi      	r5, r4, 12
  62:	3003      	movi      	r0, 3
  64:	4364      	lsli      	r3, r3, 4
  66:	dc02089e 	st.b      	r0, (r2, 0x89e)
  6a:	dc0208a6 	st.b      	r0, (r2, 0x8a6)
  6e:	b462      	st.w      	r3, (r4, 0x8)
  70:	6c57      	mov      	r1, r5
  72:	6cd3      	mov      	r3, r4
  74:	104b      	lrw      	r2, 0x0	// a0 <lmac_test_init+0xa0>
  76:	100c      	lrw      	r0, 0x0	// a4 <lmac_test_init+0xa4>
  78:	e0000000 	bsr      	0x0	// 0 <os_task_init>
  7c:	3180      	movi      	r1, 128
  7e:	4122      	lsli      	r1, r1, 2
  80:	6c17      	mov      	r0, r5
  82:	e0000000 	bsr      	0x0	// 0 <os_task_set_stacksize>
  86:	3130      	movi      	r1, 48
  88:	6c17      	mov      	r0, r5
  8a:	e0000000 	bsr      	0x0	// 0 <os_task_set_priority>
  8e:	6c17      	mov      	r0, r5
  90:	e0000000 	bsr      	0x0	// 0 <os_task_run>
  94:	6c1b      	mov      	r0, r6
  96:	1493      	pop      	r4-r6, r15
	...
