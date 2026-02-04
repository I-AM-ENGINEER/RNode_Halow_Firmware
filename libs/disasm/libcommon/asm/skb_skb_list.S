
disasm/libcommon/obj/skb_skb_list.o:     file format elf32-csky-little


Disassembly of section .text.__skb_list_insert.isra.1.part.2:

00000000 <__skb_list_insert.isra.1.part.2>:
   0:	14d0      	push      	r15
   2:	1044      	lrw      	r2, 0x0	// 10 <__skb_list_insert.isra.1.part.2+0x10>
   4:	3124      	movi      	r1, 36
   6:	1004      	lrw      	r0, 0x0	// 14 <__skb_list_insert.isra.1.part.2+0x14>
   8:	e0000000 	bsr      	0x0	// 0 <assert_internal>
   c:	1490      	pop      	r15
	...

Disassembly of section .text.skb_list_init:

00000000 <skb_list_init>:
   0:	6cc3      	mov      	r3, r0
   2:	b300      	st.w      	r0, (r3, 0x0)
   4:	b301      	st.w      	r0, (r3, 0x4)
   6:	3000      	movi      	r0, 0
   8:	b302      	st.w      	r0, (r3, 0x8)
   a:	783c      	jmp      	r15

Disassembly of section .text.skb_list_count:

00000000 <skb_list_count>:
   0:	9002      	ld.w      	r0, (r0, 0x8)
   2:	783c      	jmp      	r15

Disassembly of section .text.skb_list_move:

00000000 <skb_list_move>:
   0:	14c1      	push      	r4
   2:	c0006022 	mfcr      	r2, cr<0, 0>
   6:	c0807020 	psrclr      	ie
   a:	9160      	ld.w      	r3, (r1, 0x0)
   c:	64c6      	cmpne      	r1, r3
   e:	ea0d0000 	movi      	r13, 0
  12:	d9812001 	ld.w      	r12, (r1, 0x4)
  16:	c46d0c20 	incf      	r3, r13, 0
  1a:	6706      	cmpne      	r1, r12
  1c:	e4422040 	andi      	r2, r2, 64
  20:	0c15      	bf      	0x4a	// 4a <skb_list_move+0x4a>
  22:	e9030014 	bez      	r3, 0x4a	// 4a <skb_list_move+0x4a>
  26:	e90c0012 	bez      	r12, 0x4a	// 4a <skb_list_move+0x4a>
  2a:	9081      	ld.w      	r4, (r0, 0x4)
  2c:	b460      	st.w      	r3, (r4, 0x0)
  2e:	b381      	st.w      	r4, (r3, 0x4)
  30:	dc0c2000 	st.w      	r0, (r12, 0x0)
  34:	9062      	ld.w      	r3, (r0, 0x8)
  36:	dd802001 	st.w      	r12, (r0, 0x4)
  3a:	d9812002 	ld.w      	r12, (r1, 0x8)
  3e:	60f0      	addu      	r3, r12
  40:	b062      	st.w      	r3, (r0, 0x8)
  42:	b120      	st.w      	r1, (r1, 0x0)
  44:	b121      	st.w      	r1, (r1, 0x4)
  46:	dda12002 	st.w      	r13, (r1, 0x8)
  4a:	e9020004 	bez      	r2, 0x52	// 52 <skb_list_move+0x52>
  4e:	c0807420 	psrset      	ie
  52:	3000      	movi      	r0, 0
  54:	1481      	pop      	r4

Disassembly of section .text.skb_list_queue:

00000000 <skb_list_queue>:
   0:	c0006023 	mfcr      	r3, cr<0, 0>
   4:	c0807020 	psrclr      	ie
   8:	9041      	ld.w      	r2, (r0, 0x4)
   a:	e4632040 	andi      	r3, r3, 64
   e:	b220      	st.w      	r1, (r2, 0x0)
  10:	b141      	st.w      	r2, (r1, 0x4)
  12:	9042      	ld.w      	r2, (r0, 0x8)
  14:	2200      	addi      	r2, 1
  16:	b100      	st.w      	r0, (r1, 0x0)
  18:	b021      	st.w      	r1, (r0, 0x4)
  1a:	b042      	st.w      	r2, (r0, 0x8)
  1c:	e9030004 	bez      	r3, 0x24	// 24 <skb_list_queue+0x24>
  20:	c0807420 	psrset      	ie
  24:	3000      	movi      	r0, 0
  26:	783c      	jmp      	r15

Disassembly of section .text.skb_list_queue_head:

00000000 <skb_list_queue_head>:
   0:	14d1      	push      	r4, r15
   2:	c0006024 	mfcr      	r4, cr<0, 0>
   6:	c0807020 	psrclr      	ie
   a:	9060      	ld.w      	r3, (r0, 0x0)
   c:	b160      	st.w      	r3, (r1, 0x0)
   e:	b101      	st.w      	r0, (r1, 0x4)
  10:	b020      	st.w      	r1, (r0, 0x0)
  12:	b321      	st.w      	r1, (r3, 0x4)
  14:	9062      	ld.w      	r3, (r0, 0x8)
  16:	2300      	addi      	r3, 1
  18:	b062      	st.w      	r3, (r0, 0x8)
  1a:	9160      	ld.w      	r3, (r1, 0x0)
  1c:	64c6      	cmpne      	r1, r3
  1e:	e4842040 	andi      	r4, r4, 64
  22:	0803      	bt      	0x28	// 28 <skb_list_queue_head+0x28>
  24:	e0000000 	bsr      	0x0	// 0 <skb_list_queue_head>
  28:	e9040004 	bez      	r4, 0x30	// 30 <skb_list_queue_head+0x30>
  2c:	c0807420 	psrset      	ie
  30:	3000      	movi      	r0, 0
  32:	1491      	pop      	r4, r15

Disassembly of section .text.skb_list_dequeue:

00000000 <skb_list_dequeue>:
   0:	c0006022 	mfcr      	r2, cr<0, 0>
   4:	c0807020 	psrclr      	ie
   8:	9060      	ld.w      	r3, (r0, 0x0)
   a:	64c2      	cmpne      	r0, r3
   c:	e4422040 	andi      	r2, r2, 64
  10:	0c14      	bf      	0x38	// 38 <skb_list_dequeue+0x38>
  12:	e903000d 	bez      	r3, 0x2c	// 2c <skb_list_dequeue+0x2c>
  16:	9022      	ld.w      	r1, (r0, 0x8)
  18:	2900      	subi      	r1, 1
  1a:	b022      	st.w      	r1, (r0, 0x8)
  1c:	9320      	ld.w      	r1, (r3, 0x0)
  1e:	9301      	ld.w      	r0, (r3, 0x4)
  20:	b101      	st.w      	r0, (r1, 0x4)
  22:	9301      	ld.w      	r0, (r3, 0x4)
  24:	b020      	st.w      	r1, (r0, 0x0)
  26:	3100      	movi      	r1, 0
  28:	b320      	st.w      	r1, (r3, 0x0)
  2a:	b321      	st.w      	r1, (r3, 0x4)
  2c:	e9020004 	bez      	r2, 0x34	// 34 <skb_list_dequeue+0x34>
  30:	c0807420 	psrset      	ie
  34:	6c0f      	mov      	r0, r3
  36:	783c      	jmp      	r15
  38:	3300      	movi      	r3, 0
  3a:	07f9      	br      	0x2c	// 2c <skb_list_dequeue+0x2c>

Disassembly of section .text.skb_list_destroy:

00000000 <skb_list_destroy>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	9402      	ld.w      	r0, (r4, 0x8)
   6:	e9200003 	bnez      	r0, 0xc	// c <skb_list_destroy+0xc>
   a:	1491      	pop      	r4, r15
   c:	6c13      	mov      	r0, r4
   e:	e0000000 	bsr      	0x0	// 0 <skb_list_destroy>
  12:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
  16:	07f7      	br      	0x4	// 4 <skb_list_destroy+0x4>

Disassembly of section .text.skb_list_first:

00000000 <skb_list_first>:
   0:	c0006023 	mfcr      	r3, cr<0, 0>
   4:	c0807020 	psrclr      	ie
   8:	9040      	ld.w      	r2, (r0, 0x0)
   a:	e4632040 	andi      	r3, r3, 64
   e:	6482      	cmpne      	r0, r2
  10:	3100      	movi      	r1, 0
  12:	c4410c20 	incf      	r2, r1, 0
  16:	e9030004 	bez      	r3, 0x1e	// 1e <skb_list_first+0x1e>
  1a:	c0807420 	psrset      	ie
  1e:	6c0b      	mov      	r0, r2
  20:	783c      	jmp      	r15

Disassembly of section .text.skb_list_last:

00000000 <skb_list_last>:
   0:	c0006023 	mfcr      	r3, cr<0, 0>
   4:	c0807020 	psrclr      	ie
   8:	9041      	ld.w      	r2, (r0, 0x4)
   a:	e4632040 	andi      	r3, r3, 64
   e:	6482      	cmpne      	r0, r2
  10:	3100      	movi      	r1, 0
  12:	c4410c20 	incf      	r2, r1, 0
  16:	e9030004 	bez      	r3, 0x1e	// 1e <skb_list_last+0x1e>
  1a:	c0807420 	psrset      	ie
  1e:	6c0b      	mov      	r0, r2
  20:	783c      	jmp      	r15

Disassembly of section .text.skb_list_unlink:

00000000 <skb_list_unlink>:
   0:	c0006023 	mfcr      	r3, cr<0, 0>
   4:	c0807020 	psrclr      	ie
   8:	9142      	ld.w      	r2, (r1, 0x8)
   a:	2a00      	subi      	r2, 1
   c:	b142      	st.w      	r2, (r1, 0x8)
   e:	9040      	ld.w      	r2, (r0, 0x0)
  10:	9021      	ld.w      	r1, (r0, 0x4)
  12:	b221      	st.w      	r1, (r2, 0x4)
  14:	9021      	ld.w      	r1, (r0, 0x4)
  16:	e4632040 	andi      	r3, r3, 64
  1a:	b140      	st.w      	r2, (r1, 0x0)
  1c:	3200      	movi      	r2, 0
  1e:	b040      	st.w      	r2, (r0, 0x0)
  20:	b041      	st.w      	r2, (r0, 0x4)
  22:	e9030004 	bez      	r3, 0x2a	// 2a <skb_list_unlink+0x2a>
  26:	c0807420 	psrset      	ie
  2a:	3000      	movi      	r0, 0
  2c:	783c      	jmp      	r15

Disassembly of section .text.skb_list_queue_before:

00000000 <skb_list_queue_before>:
   0:	14d1      	push      	r4, r15
   2:	c0006024 	mfcr      	r4, cr<0, 0>
   6:	c0807020 	psrclr      	ie
   a:	9161      	ld.w      	r3, (r1, 0x4)
   c:	b261      	st.w      	r3, (r2, 0x4)
   e:	b220      	st.w      	r1, (r2, 0x0)
  10:	b340      	st.w      	r2, (r3, 0x0)
  12:	9062      	ld.w      	r3, (r0, 0x8)
  14:	2300      	addi      	r3, 1
  16:	b141      	st.w      	r2, (r1, 0x4)
  18:	b062      	st.w      	r3, (r0, 0x8)
  1a:	9260      	ld.w      	r3, (r2, 0x0)
  1c:	64ca      	cmpne      	r2, r3
  1e:	e4842040 	andi      	r4, r4, 64
  22:	0803      	bt      	0x28	// 28 <skb_list_queue_before+0x28>
  24:	e0000000 	bsr      	0x0	// 0 <skb_list_queue_before>
  28:	e9040004 	bez      	r4, 0x30	// 30 <skb_list_queue_before+0x30>
  2c:	c0807420 	psrset      	ie
  30:	3000      	movi      	r0, 0
  32:	1491      	pop      	r4, r15

Disassembly of section .text.skb_list_queue_after:

00000000 <skb_list_queue_after>:
   0:	14d1      	push      	r4, r15
   2:	c0006024 	mfcr      	r4, cr<0, 0>
   6:	c0807020 	psrclr      	ie
   a:	9160      	ld.w      	r3, (r1, 0x0)
   c:	b260      	st.w      	r3, (r2, 0x0)
   e:	b221      	st.w      	r1, (r2, 0x4)
  10:	b140      	st.w      	r2, (r1, 0x0)
  12:	b341      	st.w      	r2, (r3, 0x4)
  14:	9062      	ld.w      	r3, (r0, 0x8)
  16:	2300      	addi      	r3, 1
  18:	b062      	st.w      	r3, (r0, 0x8)
  1a:	9260      	ld.w      	r3, (r2, 0x0)
  1c:	64ca      	cmpne      	r2, r3
  1e:	e4842040 	andi      	r4, r4, 64
  22:	0803      	bt      	0x28	// 28 <skb_list_queue_after+0x28>
  24:	e0000000 	bsr      	0x0	// 0 <skb_list_queue_after>
  28:	e9040004 	bez      	r4, 0x30	// 30 <skb_list_queue_after+0x30>
  2c:	c0807420 	psrset      	ie
  30:	3000      	movi      	r0, 0
  32:	1491      	pop      	r4, r15
