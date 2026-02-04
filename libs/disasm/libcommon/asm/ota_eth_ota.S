
disasm/libcommon/obj/ota_eth_ota.o:     file format elf32-csky-little


Disassembly of section .text.libota_check_sum:

00000000 <libota_check_sum>:
   0:	3300      	movi      	r3, 0
   2:	3921      	cmplti      	r1, 2
   4:	0c0c      	bf      	0x1c	// 1c <libota_check_sum+0x1c>
   6:	3941      	cmpnei      	r1, 1
   8:	0803      	bt      	0xe	// e <libota_check_sum+0xe>
   a:	8040      	ld.b      	r2, (r0, 0x0)
   c:	60c8      	addu      	r3, r2
   e:	5350      	asri      	r2, r3, 16
  10:	e922000b 	bnez      	r2, 0x26	// 26 <libota_check_sum+0x26>
  14:	c4632480 	nor      	r0, r3, r3
  18:	7401      	zexth      	r0, r0
  1a:	783c      	jmp      	r15
  1c:	8840      	ld.h      	r2, (r0, 0x0)
  1e:	60c8      	addu      	r3, r2
  20:	2001      	addi      	r0, 2
  22:	2901      	subi      	r1, 2
  24:	07ef      	br      	0x2	// 2 <libota_check_sum+0x2>
  26:	c40355e3 	zext      	r3, r3, 15, 0
  2a:	07f1      	br      	0xc	// c <libota_check_sum+0xc>

Disassembly of section .text.libota_proc:

00000000 <libota_proc>:
   0:	14d6      	push      	r4-r9, r15
   2:	91c7      	ld.w      	r6, (r1, 0x1c)
   4:	6d43      	mov      	r5, r0
   6:	6d07      	mov      	r4, r1
   8:	e0000000 	bsr      	0x0	// 0 <sysctrl_get_chip_id>
   c:	866e      	ld.b      	r3, (r6, 0xe)
   e:	3b42      	cmpnei      	r3, 2
  10:	6dc3      	mov      	r7, r0
  12:	0c11      	bf      	0x34	// 34 <libota_proc+0x34>
  14:	3b44      	cmpnei      	r3, 4
  16:	0c3e      	bf      	0x92	// 92 <libota_proc+0x92>
  18:	3b41      	cmpnei      	r3, 1
  1a:	0872      	bt      	0xfe	// fe <libota_proc+0xfe>
  1c:	9467      	ld.w      	r3, (r4, 0x1c)
  1e:	9364      	ld.w      	r3, (r3, 0x10)
  20:	e4632001 	andi      	r3, r3, 1
  24:	e9030004 	bez      	r3, 0x2c	// 2c <libota_proc+0x2c>
  28:	e0000000 	bsr      	0x0	// 0 <syscfg_loaddef>
  2c:	e0000000 	bsr      	0x0	// 0 <mcu_reset>
  30:	6c13      	mov      	r0, r4
  32:	1496      	pop      	r4-r9, r15
  34:	30b0      	movi      	r0, 176
  36:	4001      	lsli      	r0, r0, 1
  38:	e0000000 	bsr      	0x0	// 0 <alloc_skb>
  3c:	6d03      	mov      	r4, r0
  3e:	e900fff9 	bez      	r0, 0x30	// 30 <libota_proc+0x30>
  42:	3180      	movi      	r1, 128
  44:	4121      	lsli      	r1, r1, 1
  46:	e0000000 	bsr      	0x0	// 0 <skb_reserve>
  4a:	9467      	ld.w      	r3, (r4, 0x1c)
  4c:	6c5b      	mov      	r1, r6
  4e:	320c      	movi      	r2, 12
  50:	6c0f      	mov      	r0, r3
  52:	e0000000 	bsr      	0x0	// 0 <memcpy>
  56:	ea024748 	movi      	r2, 18248
  5a:	a846      	st.h      	r2, (r0, 0xc)
  5c:	3203      	movi      	r2, 3
  5e:	a04e      	st.b      	r2, (r0, 0xe)
  60:	3200      	movi      	r2, 0
  62:	a04f      	st.b      	r2, (r0, 0xf)
  64:	6cc3      	mov      	r3, r0
  66:	1148      	lrw      	r2, 0x0	// 104 <libota_proc+0x104>
  68:	a3b6      	st.b      	r5, (r3, 0x16)
  6a:	9200      	ld.w      	r0, (r2, 0x0)
  6c:	7802      	revb      	r0, r0
  6e:	1147      	lrw      	r2, 0x0	// 108 <libota_proc+0x108>
  70:	b304      	st.w      	r0, (r3, 0x10)
  72:	9220      	ld.w      	r1, (r2, 0x0)
  74:	7846      	revb      	r1, r1
  76:	1146      	lrw      	r2, 0x0	// 10c <libota_proc+0x10c>
  78:	6c13      	mov      	r0, r4
  7a:	9240      	ld.w      	r2, (r2, 0x0)
  7c:	788a      	revb      	r2, r2
  7e:	b347      	st.w      	r2, (r3, 0x1c)
  80:	4748      	lsli      	r2, r7, 8
  82:	4fe8      	lsri      	r7, r7, 8
  84:	6dc8      	or      	r7, r2
  86:	b326      	st.w      	r1, (r3, 0x18)
  88:	abea      	st.h      	r7, (r3, 0x14)
  8a:	3120      	movi      	r1, 32
  8c:	e0000000 	bsr      	0x0	// 0 <skb_put>
  90:	07d0      	br      	0x30	// 30 <libota_proc+0x30>
  92:	94a7      	ld.w      	r5, (r4, 0x1c)
  94:	9564      	ld.w      	r3, (r5, 0x10)
  96:	78ce      	revb      	r3, r3
  98:	e46320ff 	andi      	r3, r3, 255
  9c:	3b43      	cmpnei      	r3, 3
  9e:	082c      	bt      	0xf6	// f6 <libota_proc+0xf6>
  a0:	8d50      	ld.h      	r2, (r5, 0x20)
  a2:	4268      	lsli      	r3, r2, 8
  a4:	c50255e2 	zext      	r2, r2, 15, 8
  a8:	6cc8      	or      	r3, r2
  aa:	74cd      	zexth      	r3, r3
  ac:	64c2      	cmpne      	r0, r3
  ae:	0824      	bt      	0xf6	// f6 <libota_proc+0xf6>
  b0:	8d2e      	ld.h      	r1, (r5, 0x1c)
  b2:	41e8      	lsli      	r7, r1, 8
  b4:	4928      	lsri      	r1, r1, 8
  b6:	e5050021 	addi      	r8, r5, 34
  ba:	7645      	zexth      	r9, r1
  bc:	6c5c      	or      	r1, r7
  be:	7445      	zexth      	r1, r1
  c0:	6c23      	mov      	r0, r8
  c2:	e0000000 	bsr      	0x0	// 0 <libota_proc>
  c6:	8d4f      	ld.h      	r2, (r5, 0x1e)
  c8:	4228      	lsli      	r1, r2, 8
  ca:	c50255e2 	zext      	r2, r2, 15, 8
  ce:	6c48      	or      	r1, r2
  d0:	7445      	zexth      	r1, r1
  d2:	6442      	cmpne      	r0, r1
  d4:	0811      	bt      	0xf6	// f6 <libota_proc+0xf6>
  d6:	9506      	ld.w      	r0, (r5, 0x18)
  d8:	9525      	ld.w      	r1, (r5, 0x14)
  da:	c5272423 	or      	r3, r7, r9
  de:	74cd      	zexth      	r3, r3
  e0:	6ca3      	mov      	r2, r8
  e2:	7846      	revb      	r1, r1
  e4:	7802      	revb      	r0, r0
  e6:	e0000000 	bsr      	0x0	// 0 <libota_write_fw_ah>
  ea:	a60f      	st.b      	r0, (r6, 0xf)
  ec:	3305      	movi      	r3, 5
  ee:	a66e      	st.b      	r3, (r6, 0xe)
  f0:	3324      	movi      	r3, 36
  f2:	ac74      	st.h      	r3, (r4, 0x28)
  f4:	079e      	br      	0x30	// 30 <libota_proc+0x30>
  f6:	3300      	movi      	r3, 0
  f8:	2b00      	subi      	r3, 1
  fa:	a66f      	st.b      	r3, (r6, 0xf)
  fc:	07f8      	br      	0xec	// ec <libota_proc+0xec>
  fe:	3400      	movi      	r4, 0
 100:	0798      	br      	0x30	// 30 <libota_proc+0x30>
	...
