
disasm/libnetutils/obj/utils_netlog.o:     file format elf32-csky-little


Disassembly of section .text.__get_unaligned_be32:

00000000 <__get_unaligned_be32>:
   0:	8060      	ld.b      	r3, (r0, 0x0)
   2:	8041      	ld.b      	r2, (r0, 0x1)
   4:	4250      	lsli      	r2, r2, 16
   6:	4378      	lsli      	r3, r3, 24
   8:	6cc8      	or      	r3, r2
   a:	8043      	ld.b      	r2, (r0, 0x3)
   c:	8002      	ld.b      	r0, (r0, 0x2)
   e:	6cc8      	or      	r3, r2
  10:	4008      	lsli      	r0, r0, 8
  12:	6c0c      	or      	r0, r3
  14:	783c      	jmp      	r15

Disassembly of section .text.netlog_proc_rx:

00000000 <netlog_proc_rx>:
   0:	9240      	ld.w      	r2, (r2, 0x0)
   2:	8277      	ld.b      	r3, (r2, 0x17)
   4:	3b51      	cmpnei      	r3, 17
   6:	080e      	bt      	0x22	// 22 <netlog_proc_rx+0x22>
   8:	d8620024 	ld.b      	r3, (r2, 0x24)
   c:	d8220025 	ld.b      	r1, (r2, 0x25)
  10:	9041      	ld.w      	r2, (r0, 0x4)
  12:	4368      	lsli      	r3, r3, 8
  14:	9241      	ld.w      	r2, (r2, 0x4)
  16:	6cc4      	or      	r3, r1
  18:	8a4f      	ld.h      	r2, (r2, 0x1e)
  1a:	64ca      	cmpne      	r2, r3
  1c:	6403      	mvcv      	r0
  1e:	7400      	zextb      	r0, r0
  20:	783c      	jmp      	r15
  22:	3000      	movi      	r0, 0
  24:	07fe      	br      	0x20	// 20 <netlog_proc_rx+0x20>

Disassembly of section .text.netlog_proc_tx:

00000000 <netlog_proc_tx>:
   0:	14d8      	push      	r4-r11, r15
   2:	1428      	subi      	r14, r14, 32
   4:	92a0      	ld.w      	r5, (r2, 0x0)
   6:	6e07      	mov      	r8, r1
   8:	8577      	ld.b      	r3, (r5, 0x17)
   a:	3b51      	cmpnei      	r3, 17
   c:	6e4b      	mov      	r9, r2
   e:	08d2      	bt      	0x1b2	// 1b2 <netlog_proc_tx+0x1b2>
  10:	9061      	ld.w      	r3, (r0, 0x4)
  12:	d8250025 	ld.b      	r1, (r5, 0x25)
  16:	9381      	ld.w      	r4, (r3, 0x4)
  18:	d8650024 	ld.b      	r3, (r5, 0x24)
  1c:	4368      	lsli      	r3, r3, 8
  1e:	8c4f      	ld.h      	r2, (r4, 0x1e)
  20:	6cc4      	or      	r3, r1
  22:	64ca      	cmpne      	r2, r3
  24:	08c7      	bt      	0x1b2	// 1b2 <netlog_proc_tx+0x1b2>
  26:	d8e50022 	ld.b      	r7, (r5, 0x22)
  2a:	d8650023 	ld.b      	r3, (r5, 0x23)
  2e:	47e8      	lsli      	r7, r7, 8
  30:	e4050019 	addi      	r0, r5, 26
  34:	6dcc      	or      	r7, r3
  36:	e0000000 	bsr      	0x0	// 0 <netlog_proc_tx>
  3a:	6d83      	mov      	r6, r0
  3c:	e405001d 	addi      	r0, r5, 30
  40:	e0000000 	bsr      	0x0	// 0 <netlog_proc_tx>
  44:	6e83      	mov      	r10, r0
  46:	d805002a 	ld.b      	r0, (r5, 0x2a)
  4a:	3841      	cmpnei      	r0, 1
  4c:	0c05      	bf      	0x56	// 56 <netlog_proc_tx+0x56>
  4e:	3843      	cmpnei      	r0, 3
  50:	0c76      	bf      	0x13c	// 13c <netlog_proc_tx+0x13c>
  52:	3001      	movi      	r0, 1
  54:	04b0      	br      	0x1b4	// 1b4 <netlog_proc_tx+0x1b4>
  56:	9465      	ld.w      	r3, (r4, 0x14)
  58:	e9030007 	bez      	r3, 0x66	// 66 <netlog_proc_tx+0x66>
  5c:	658e      	cmpne      	r3, r6
  5e:	08ab      	bt      	0x1b4	// 1b4 <netlog_proc_tx+0x1b4>
  60:	8c6e      	ld.h      	r3, (r4, 0x1c)
  62:	65ce      	cmpne      	r3, r7
  64:	08a8      	bt      	0x1b4	// 1b4 <netlog_proc_tx+0x1b4>
  66:	8560      	ld.b      	r3, (r5, 0x0)
  68:	e4632001 	andi      	r3, r3, 1
  6c:	5cda      	addi      	r6, r4, 7
  6e:	e903005b 	bez      	r3, 0x124	// 124 <netlog_proc_tx+0x124>
  72:	6c5b      	mov      	r1, r6
  74:	6c23      	mov      	r0, r8
  76:	e0000000 	bsr      	0x0	// 0 <ieee80211_conf_get_mac>
  7a:	d8a92000 	ld.w      	r5, (r9, 0x0)
  7e:	e4050019 	addi      	r0, r5, 26
  82:	e0000000 	bsr      	0x0	// 0 <netlog_proc_tx>
  86:	6e43      	mov      	r9, r0
  88:	e405001d 	addi      	r0, r5, 30
  8c:	e0000000 	bsr      	0x0	// 0 <netlog_proc_tx>
  90:	e5450030 	addi      	r10, r5, 49
  94:	3302      	movi      	r3, 2
  96:	dc65002a 	st.b      	r3, (r5, 0x2a)
  9a:	3206      	movi      	r2, 6
  9c:	6c6b      	mov      	r1, r10
  9e:	6ec3      	mov      	r11, r0
  a0:	e405002a 	addi      	r0, r5, 43
  a4:	e0000000 	bsr      	0x0	// 0 <memcpy>
  a8:	3206      	movi      	r2, 6
  aa:	6c5b      	mov      	r1, r6
  ac:	6c2b      	mov      	r0, r10
  ae:	e0000000 	bsr      	0x0	// 0 <memcpy>
  b2:	5d76      	addi      	r3, r5, 6
  b4:	b860      	st.w      	r3, (r14, 0x0)
  b6:	b8c1      	st.w      	r6, (r14, 0x4)
  b8:	dd2e2002 	st.w      	r9, (r14, 0x8)
  bc:	8560      	ld.b      	r3, (r5, 0x0)
  be:	e4632001 	andi      	r3, r3, 1
  c2:	e4e50029 	addi      	r7, r5, 42
  c6:	e9030038 	bez      	r3, 0x136	// 136 <netlog_proc_tx+0x136>
  ca:	e46920ff 	andi      	r3, r9, 255
  ce:	3b0a      	cmphsi      	r3, 11
  d0:	0c30      	bf      	0x130	// 130 <netlog_proc_tx+0x130>
  d2:	e4091000 	subi      	r0, r9, 1
  d6:	b804      	st.w      	r0, (r14, 0x10)
  d8:	d8650022 	ld.b      	r3, (r5, 0x22)
  dc:	d8450023 	ld.b      	r2, (r5, 0x23)
  e0:	4368      	lsli      	r3, r3, 8
  e2:	6cc8      	or      	r3, r2
  e4:	b863      	st.w      	r3, (r14, 0xc)
  e6:	8c6f      	ld.h      	r3, (r4, 0x1e)
  e8:	b865      	st.w      	r3, (r14, 0x14)
  ea:	3077      	movi      	r0, 119
  ec:	330d      	movi      	r3, 13
  ee:	b8e6      	st.w      	r7, (r14, 0x18)
  f0:	b867      	st.w      	r3, (r14, 0x1c)
  f2:	e0000000 	bsr      	0x0	// 0 <alloc_skb>
  f6:	6d03      	mov      	r4, r0
  f8:	e900ffad 	bez      	r0, 0x52	// 52 <netlog_proc_tx+0x52>
  fc:	3120      	movi      	r1, 32
  fe:	e0000000 	bsr      	0x0	// 0 <skb_reserve>
 102:	9427      	ld.w      	r1, (r4, 0x1c)
 104:	6c3b      	mov      	r0, r14
 106:	e0000000 	bsr      	0x0	// 0 <net_setup_udpdata>
 10a:	6c43      	mov      	r1, r0
 10c:	6c13      	mov      	r0, r4
 10e:	e0000000 	bsr      	0x0	// 0 <skb_put>
 112:	6c23      	mov      	r0, r8
 114:	8c54      	ld.h      	r2, (r4, 0x28)
 116:	9427      	ld.w      	r1, (r4, 0x1c)
 118:	e0000000 	bsr      	0x0	// 0 <ieee80211_input>
 11c:	6c13      	mov      	r0, r4
 11e:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
 122:	0798      	br      	0x52	// 52 <netlog_proc_tx+0x52>
 124:	3206      	movi      	r2, 6
 126:	6c57      	mov      	r1, r5
 128:	6c1b      	mov      	r0, r6
 12a:	e0000000 	bsr      	0x0	// 0 <memcpy>
 12e:	07a6      	br      	0x7a	// 7a <netlog_proc_tx+0x7a>
 130:	e4090000 	addi      	r0, r9, 1
 134:	07d1      	br      	0xd6	// d6 <netlog_proc_tx+0xd6>
 136:	dd6e2004 	st.w      	r11, (r14, 0x10)
 13a:	07cf      	br      	0xd8	// d8 <netlog_proc_tx+0xd8>
 13c:	3206      	movi      	r2, 6
 13e:	5c3a      	addi      	r1, r4, 7
 140:	e405002a 	addi      	r0, r5, 43
 144:	e0000000 	bsr      	0x0	// 0 <memcmp>
 148:	e920ff85 	bnez      	r0, 0x52	// 52 <netlog_proc_tx+0x52>
 14c:	9465      	ld.w      	r3, (r4, 0x14)
 14e:	e9030007 	bez      	r3, 0x15c	// 15c <netlog_proc_tx+0x15c>
 152:	658e      	cmpne      	r3, r6
 154:	0b7f      	bt      	0x52	// 52 <netlog_proc_tx+0x52>
 156:	8c6e      	ld.h      	r3, (r4, 0x1c)
 158:	65ce      	cmpne      	r3, r7
 15a:	0b7c      	bt      	0x52	// 52 <netlog_proc_tx+0x52>
 15c:	3206      	movi      	r2, 6
 15e:	5d28      	addu      	r1, r5, r2
 160:	dd040000 	st.b      	r8, (r4, 0x0)
 164:	b4c5      	st.w      	r6, (r4, 0x14)
 166:	acee      	st.h      	r7, (r4, 0x1c)
 168:	e404000c 	addi      	r0, r4, 13
 16c:	e0000000 	bsr      	0x0	// 0 <memcpy>
 170:	3206      	movi      	r2, 6
 172:	e4250030 	addi      	r1, r5, 49
 176:	5c02      	addi      	r0, r4, 1
 178:	e0000000 	bsr      	0x0	// 0 <memcpy>
 17c:	d8692000 	ld.w      	r3, (r9, 0x0)
 180:	8360      	ld.b      	r3, (r3, 0x0)
 182:	e4632001 	andi      	r3, r3, 1
 186:	e9030013 	bez      	r3, 0x1ac	// 1ac <netlog_proc_tx+0x1ac>
 18a:	e46620ff 	andi      	r3, r6, 255
 18e:	3b0a      	cmphsi      	r3, 11
 190:	0c0c      	bf      	0x1a8	// 1a8 <netlog_proc_tx+0x1a8>
 192:	2e00      	subi      	r6, 1
 194:	b4c6      	st.w      	r6, (r4, 0x18)
 196:	6c53      	mov      	r1, r4
 198:	1008      	lrw      	r0, 0x0	// 1b8 <netlog_proc_tx+0x1b8>
 19a:	e0000000 	bsr      	0x0	// 0 <print_redirect>
 19e:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
 1a2:	b408      	st.w      	r0, (r4, 0x20)
 1a4:	b429      	st.w      	r1, (r4, 0x24)
 1a6:	0756      	br      	0x52	// 52 <netlog_proc_tx+0x52>
 1a8:	2600      	addi      	r6, 1
 1aa:	07f5      	br      	0x194	// 194 <netlog_proc_tx+0x194>
 1ac:	dd442006 	st.w      	r10, (r4, 0x18)
 1b0:	07f3      	br      	0x196	// 196 <netlog_proc_tx+0x196>
 1b2:	3000      	movi      	r0, 0
 1b4:	1408      	addi      	r14, r14, 32
 1b6:	1498      	pop      	r4-r11, r15
 1b8:	00000000 	.long	0x00000000

Disassembly of section .text.netlog_print:

00000000 <netlog_print>:
   0:	14d6      	push      	r4-r9, r15
   2:	1428      	subi      	r14, r14, 32
   4:	6d03      	mov      	r4, r0
   6:	6c07      	mov      	r0, r1
   8:	6dc7      	mov      	r7, r1
   a:	e0000000 	bsr      	0x0	// 0 <strlen>
   e:	6e03      	mov      	r8, r0
  10:	e0000000 	bsr      	0x0	// 0 <os_jiffies>
  14:	9448      	ld.w      	r2, (r4, 0x20)
  16:	9469      	ld.w      	r3, (r4, 0x24)
  18:	6400      	cmphs      	r0, r0
  1a:	600b      	subc      	r0, r2
  1c:	604f      	subc      	r1, r3
  1e:	e9210005 	bnez      	r1, 0x28	// 28 <netlog_print+0x28>
  22:	eb0007d0 	cmphsi      	r0, 2001
  26:	0c13      	bf      	0x4c	// 4c <netlog_print+0x4c>
  28:	3500      	movi      	r5, 0
  2a:	3206      	movi      	r2, 6
  2c:	6c57      	mov      	r1, r5
  2e:	b4a5      	st.w      	r5, (r4, 0x14)
  30:	acae      	st.h      	r5, (r4, 0x1c)
  32:	5c1a      	addi      	r0, r4, 7
  34:	e0000000 	bsr      	0x0	// 0 <memset>
  38:	6c57      	mov      	r1, r5
  3a:	6c17      	mov      	r0, r5
  3c:	e0000000 	bsr      	0x0	// 0 <print_redirect>
  40:	6c5f      	mov      	r1, r7
  42:	1107      	lrw      	r0, 0x0	// dc <netlog_print+0xdc>
  44:	e0000000 	bsr      	0x0	// 0 <printf>
  48:	1408      	addi      	r14, r14, 32
  4a:	1496      	pop      	r4-r9, r15
  4c:	e528000c 	addi      	r9, r8, 13
  50:	6c27      	mov      	r0, r9
  52:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  56:	6d43      	mov      	r5, r0
  58:	e900fff8 	bez      	r0, 0x48	// 48 <netlog_print+0x48>
  5c:	3304      	movi      	r3, 4
  5e:	a060      	st.b      	r3, (r0, 0x0)
  60:	5cda      	addi      	r6, r4, 7
  62:	3206      	movi      	r2, 6
  64:	5c22      	addi      	r1, r4, 1
  66:	2000      	addi      	r0, 1
  68:	e0000000 	bsr      	0x0	// 0 <memcpy>
  6c:	6c5b      	mov      	r1, r6
  6e:	3206      	movi      	r2, 6
  70:	5d1a      	addi      	r0, r5, 7
  72:	e0000000 	bsr      	0x0	// 0 <memcpy>
  76:	6ca3      	mov      	r2, r8
  78:	6c5f      	mov      	r1, r7
  7a:	e405000c 	addi      	r0, r5, 13
  7e:	e0000000 	bsr      	0x0	// 0 <hw_memcpy>
  82:	e464000c 	addi      	r3, r4, 13
  86:	b860      	st.w      	r3, (r14, 0x0)
  88:	9465      	ld.w      	r3, (r4, 0x14)
  8a:	b862      	st.w      	r3, (r14, 0x8)
  8c:	9466      	ld.w      	r3, (r4, 0x18)
  8e:	b864      	st.w      	r3, (r14, 0x10)
  90:	8c6e      	ld.h      	r3, (r4, 0x1c)
  92:	b863      	st.w      	r3, (r14, 0xc)
  94:	e4080076 	addi      	r0, r8, 119
  98:	8c6f      	ld.h      	r3, (r4, 0x1e)
  9a:	b8c1      	st.w      	r6, (r14, 0x4)
  9c:	b865      	st.w      	r3, (r14, 0x14)
  9e:	b8a6      	st.w      	r5, (r14, 0x18)
  a0:	dd2e2007 	st.w      	r9, (r14, 0x1c)
  a4:	e0000000 	bsr      	0x0	// 0 <alloc_skb>
  a8:	6d83      	mov      	r6, r0
  aa:	e9000015 	bez      	r0, 0xd4	// d4 <netlog_print+0xd4>
  ae:	3120      	movi      	r1, 32
  b0:	e0000000 	bsr      	0x0	// 0 <skb_reserve>
  b4:	9627      	ld.w      	r1, (r6, 0x1c)
  b6:	6c3b      	mov      	r0, r14
  b8:	e0000000 	bsr      	0x0	// 0 <net_setup_udpdata>
  bc:	6c43      	mov      	r1, r0
  be:	6c1b      	mov      	r0, r6
  c0:	e0000000 	bsr      	0x0	// 0 <skb_put>
  c4:	8400      	ld.b      	r0, (r4, 0x0)
  c6:	8e54      	ld.h      	r2, (r6, 0x28)
  c8:	9627      	ld.w      	r1, (r6, 0x1c)
  ca:	e0000000 	bsr      	0x0	// 0 <ieee80211_input>
  ce:	6c1b      	mov      	r0, r6
  d0:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
  d4:	6c17      	mov      	r0, r5
  d6:	e0000000 	bsr      	0x0	// 0 <_os_free>
  da:	07b7      	br      	0x48	// 48 <netlog_print+0x48>
  dc:	00000000 	.long	0x00000000

Disassembly of section .text.netlog_init:

00000000 <netlog_init>:
   0:	14d0      	push      	r15
   2:	1064      	lrw      	r3, 0x0	// 10 <netlog_init+0x10>
   4:	ab0f      	st.h      	r0, (r3, 0x1e)
   6:	1004      	lrw      	r0, 0x0	// 14 <netlog_init+0x14>
   8:	e0000000 	bsr      	0x0	// 0 <ieee80211_register_pkthook>
   c:	1490      	pop      	r15
	...
