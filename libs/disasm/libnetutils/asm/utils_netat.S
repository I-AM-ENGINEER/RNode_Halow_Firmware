
disasm/libnetutils/obj/utils_netat.o:     file format elf32-csky-little


Disassembly of section .text.netAT_send_resp:

00000000 <netAT_send_resp>:
   0:	14d3      	push      	r4-r6, r15
   2:	1428      	subi      	r14, r14, 32
   4:	6d8f      	mov      	r6, r3
   6:	e460000d 	addi      	r3, r0, 14
   a:	b860      	st.w      	r3, (r14, 0x0)
   c:	5866      	addi      	r3, r0, 2
   e:	b861      	st.w      	r3, (r14, 0x4)
  10:	3300      	movi      	r3, 0
  12:	2b00      	subi      	r3, 1
  14:	b862      	st.w      	r3, (r14, 0x8)
  16:	3300      	movi      	r3, 0
  18:	b864      	st.w      	r3, (r14, 0x10)
  1a:	886c      	ld.h      	r3, (r0, 0x18)
  1c:	b863      	st.w      	r3, (r14, 0xc)
  1e:	6d43      	mov      	r5, r0
  20:	ea03ddd5 	movi      	r3, 56789
  24:	e4020069 	addi      	r0, r2, 106
  28:	b865      	st.w      	r3, (r14, 0x14)
  2a:	b826      	st.w      	r1, (r14, 0x18)
  2c:	b847      	st.w      	r2, (r14, 0x1c)
  2e:	e0000000 	bsr      	0x0	// 0 <alloc_skb>
  32:	6d03      	mov      	r4, r0
  34:	e9000018 	bez      	r0, 0x64	// 64 <netAT_send_resp+0x64>
  38:	3120      	movi      	r1, 32
  3a:	e0000000 	bsr      	0x0	// 0 <skb_reserve>
  3e:	9427      	ld.w      	r1, (r4, 0x1c)
  40:	6c3b      	mov      	r0, r14
  42:	e0000000 	bsr      	0x0	// 0 <net_setup_udpdata>
  46:	6c43      	mov      	r1, r0
  48:	6c13      	mov      	r0, r4
  4a:	e0000000 	bsr      	0x0	// 0 <skb_put>
  4e:	8c54      	ld.h      	r2, (r4, 0x28)
  50:	9427      	ld.w      	r1, (r4, 0x1c)
  52:	8500      	ld.b      	r0, (r5, 0x0)
  54:	7489      	zexth      	r2, r2
  56:	e9060009 	bez      	r6, 0x68	// 68 <netAT_send_resp+0x68>
  5a:	e0000000 	bsr      	0x0	// 0 <ieee80211_tx>
  5e:	6c13      	mov      	r0, r4
  60:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
  64:	1408      	addi      	r14, r14, 32
  66:	1493      	pop      	r4-r6, r15
  68:	e0000000 	bsr      	0x0	// 0 <ieee80211_input>
  6c:	07f9      	br      	0x5e	// 5e <netAT_send_resp+0x5e>

Disassembly of section .text.netAT_outhdl:

00000000 <netAT_outhdl>:
   0:	14d5      	push      	r4-r8, r15
   2:	e4e2000e 	addi      	r7, r2, 15
   6:	6d43      	mov      	r5, r0
   8:	6c1f      	mov      	r0, r7
   a:	6e07      	mov      	r8, r1
   c:	6d8b      	mov      	r6, r2
   e:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  12:	6d03      	mov      	r4, r0
  14:	e9000023 	bez      	r0, 0x5a	// 5a <netAT_outhdl+0x5a>
  18:	3304      	movi      	r3, 4
  1a:	a060      	st.b      	r3, (r0, 0x0)
  1c:	c50655e3 	zext      	r3, r6, 15, 8
  20:	a061      	st.b      	r3, (r0, 0x1)
  22:	a0c2      	st.b      	r6, (r0, 0x2)
  24:	3206      	movi      	r2, 6
  26:	5d3e      	addi      	r1, r5, 8
  28:	2002      	addi      	r0, 3
  2a:	e0000000 	bsr      	0x0	// 0 <memcpy>
  2e:	3206      	movi      	r2, 6
  30:	5d26      	addi      	r1, r5, 2
  32:	e4040008 	addi      	r0, r4, 9
  36:	e0000000 	bsr      	0x0	// 0 <memcpy>
  3a:	6c9b      	mov      	r2, r6
  3c:	6c63      	mov      	r1, r8
  3e:	e404000e 	addi      	r0, r4, 15
  42:	e0000000 	bsr      	0x0	// 0 <memcpy>
  46:	6c17      	mov      	r0, r5
  48:	8561      	ld.b      	r3, (r5, 0x1)
  4a:	6c9f      	mov      	r2, r7
  4c:	6c53      	mov      	r1, r4
  4e:	e0000000 	bsr      	0x0	// 0 <netAT_outhdl>
  52:	6c13      	mov      	r0, r4
  54:	e0000000 	bsr      	0x0	// 0 <_os_free>
  58:	1495      	pop      	r4-r8, r15
  5a:	1003      	lrw      	r0, 0x0	// 64 <netAT_outhdl+0x64>
  5c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  60:	07fc      	br      	0x58	// 58 <netAT_outhdl+0x58>
  62:	0000      	.short	0x0000
  64:	00000000 	.long	0x00000000

Disassembly of section .text.netAT_hook_proc.isra.1:

00000000 <netAT_hook_proc.isra.1>:
   0:	14d6      	push      	r4-r9, r15
   2:	1424      	subi      	r14, r14, 16
   4:	9280      	ld.w      	r4, (r2, 0x0)
   6:	6dcf      	mov      	r7, r3
   8:	8477      	ld.b      	r3, (r4, 0x17)
   a:	3b51      	cmpnei      	r3, 17
   c:	6f03      	mov      	r12, r0
   e:	6d4b      	mov      	r5, r2
  10:	6c07      	mov      	r0, r1
  12:	0874      	bt      	0xfa	// fa <netAT_hook_proc.isra.1+0xfa>
  14:	d8640024 	ld.b      	r3, (r4, 0x24)
  18:	d8440025 	ld.b      	r2, (r4, 0x25)
  1c:	4368      	lsli      	r3, r3, 8
  1e:	6cc8      	or      	r3, r2
  20:	74cf      	sexth      	r3, r3
  22:	ea02222a 	movi      	r2, 8746
  26:	6c8a      	nor      	r2, r2
  28:	648e      	cmpne      	r3, r2
  2a:	0868      	bt      	0xfa	// fa <netAT_hook_proc.isra.1+0xfa>
  2c:	8d62      	ld.h      	r3, (r5, 0x4)
  2e:	eb030030 	cmphsi      	r3, 49
  32:	0c64      	bf      	0xfa	// fa <netAT_hook_proc.isra.1+0xfa>
  34:	d8640022 	ld.b      	r3, (r4, 0x22)
  38:	d8cc2001 	ld.w      	r6, (r12, 0x4)
  3c:	d8440023 	ld.b      	r2, (r4, 0x23)
  40:	4368      	lsli      	r3, r3, 8
  42:	6cc8      	or      	r3, r2
  44:	a620      	st.b      	r1, (r6, 0x0)
  46:	ae6c      	st.h      	r3, (r6, 0x18)
  48:	847a      	ld.b      	r3, (r4, 0x1a)
  4a:	845b      	ld.b      	r2, (r4, 0x1b)
  4c:	4250      	lsli      	r2, r2, 16
  4e:	4378      	lsli      	r3, r3, 24
  50:	6cc8      	or      	r3, r2
  52:	845d      	ld.b      	r2, (r4, 0x1d)
  54:	6cc8      	or      	r3, r2
  56:	845c      	ld.b      	r2, (r4, 0x1c)
  58:	4248      	lsli      	r2, r2, 8
  5a:	6cc8      	or      	r3, r2
  5c:	e5060001 	addi      	r8, r6, 2
  60:	b665      	st.w      	r3, (r6, 0x14)
  62:	6c63      	mov      	r1, r8
  64:	e5240032 	addi      	r9, r4, 51
  68:	e0000000 	bsr      	0x0	// 0 <ieee80211_conf_get_mac>
  6c:	3206      	movi      	r2, 6
  6e:	6c67      	mov      	r1, r9
  70:	5e1e      	addi      	r0, r6, 8
  72:	e0000000 	bsr      	0x0	// 0 <memcpy>
  76:	9520      	ld.w      	r1, (r5, 0x0)
  78:	3206      	movi      	r2, 6
  7a:	6048      	addu      	r1, r2
  7c:	e406000d 	addi      	r0, r6, 14
  80:	e0000000 	bsr      	0x0	// 0 <memcpy>
  84:	d8a4002a 	ld.b      	r5, (r4, 0x2a)
  88:	3d41      	cmpnei      	r5, 1
  8a:	0c05      	bf      	0x94	// 94 <netAT_hook_proc.isra.1+0x94>
  8c:	3d43      	cmpnei      	r5, 3
  8e:	0c1e      	bf      	0xca	// ca <netAT_hook_proc.isra.1+0xca>
  90:	3001      	movi      	r0, 1
  92:	0435      	br      	0xfc	// fc <netAT_hook_proc.isra.1+0xfc>
  94:	320f      	movi      	r2, 15
  96:	3100      	movi      	r1, 0
  98:	6c3b      	mov      	r0, r14
  9a:	e0000000 	bsr      	0x0	// 0 <memset>
  9e:	3302      	movi      	r3, 2
  a0:	6c67      	mov      	r1, r9
  a2:	3206      	movi      	r2, 6
  a4:	e40e0002 	addi      	r0, r14, 3
  a8:	dc6e0000 	st.b      	r3, (r14, 0x0)
  ac:	e0000000 	bsr      	0x0	// 0 <memcpy>
  b0:	6c63      	mov      	r1, r8
  b2:	3206      	movi      	r2, 6
  b4:	e40e0008 	addi      	r0, r14, 9
  b8:	e0000000 	bsr      	0x0	// 0 <memcpy>
  bc:	6cdf      	mov      	r3, r7
  be:	320f      	movi      	r2, 15
  c0:	6c7b      	mov      	r1, r14
  c2:	6c1b      	mov      	r0, r6
  c4:	e0000000 	bsr      	0x0	// 0 <netAT_hook_proc.isra.1>
  c8:	07e4      	br      	0x90	// 90 <netAT_hook_proc.isra.1+0x90>
  ca:	3206      	movi      	r2, 6
  cc:	e424002c 	addi      	r1, r4, 45
  d0:	6c23      	mov      	r0, r8
  d2:	e0000000 	bsr      	0x0	// 0 <memcmp>
  d6:	e920ffdd 	bnez      	r0, 0x90	// 90 <netAT_hook_proc.isra.1+0x90>
  da:	6c5b      	mov      	r1, r6
  dc:	a6e1      	st.b      	r7, (r6, 0x1)
  de:	1009      	lrw      	r0, 0x0	// 100 <netAT_hook_proc.isra.1+0x100>
  e0:	e0000000 	bsr      	0x0	// 0 <atcmd_output_hdl>
  e4:	d864002b 	ld.b      	r3, (r4, 0x2b)
  e8:	4368      	lsli      	r3, r3, 8
  ea:	d824002c 	ld.b      	r1, (r4, 0x2c)
  ee:	6c4c      	or      	r1, r3
  f0:	e4040038 	addi      	r0, r4, 57
  f4:	e0000000 	bsr      	0x0	// 0 <atcmd_recv>
  f8:	07cc      	br      	0x90	// 90 <netAT_hook_proc.isra.1+0x90>
  fa:	3000      	movi      	r0, 0
  fc:	1404      	addi      	r14, r14, 16
  fe:	1496      	pop      	r4-r9, r15
 100:	00000000 	.long	0x00000000

Disassembly of section .text.netAT_proc_rx:

00000000 <netAT_proc_rx>:
   0:	14d0      	push      	r15
   2:	9001      	ld.w      	r0, (r0, 0x4)
   4:	3301      	movi      	r3, 1
   6:	e0000000 	bsr      	0x0	// 0 <netAT_proc_rx>
   a:	1490      	pop      	r15

Disassembly of section .text.netAT_proc_tx:

00000000 <netAT_proc_tx>:
   0:	14d0      	push      	r15
   2:	9001      	ld.w      	r0, (r0, 0x4)
   4:	3300      	movi      	r3, 0
   6:	e0000000 	bsr      	0x0	// 0 <netAT_proc_tx>
   a:	1490      	pop      	r15

Disassembly of section .text.net_atcmd_init:

00000000 <net_atcmd_init>:
   0:	14d0      	push      	r15
   2:	1003      	lrw      	r0, 0x0	// c <net_atcmd_init+0xc>
   4:	e0000000 	bsr      	0x0	// 0 <ieee80211_register_pkthook>
   8:	1490      	pop      	r15
   a:	0000      	.short	0x0000
   c:	00000000 	.long	0x00000000
