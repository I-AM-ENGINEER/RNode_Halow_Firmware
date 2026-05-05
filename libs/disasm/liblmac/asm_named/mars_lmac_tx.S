
libs\obj\liblmac\mars_lmac_tx.o:     file format elf32-csky-little


Disassembly of section .text.__put_unaligned_le32:

00000000 <__put_unaligned_le32>: // arg_bytes: 8
   0:	4870      	lsri	r3, r0, 16	// regs: r3=(<arg0> >> 0x10)
   2:	a162      	st.b	r3, (r1, 0x2)	// *(<arg1> + 0x2) = (<arg0> >> 0x10)
   4:	a100      	st.b	r0, (r1, 0x0)	// *(<arg1>) = <arg0>
   6:	4b68      	lsri	r3, r3, 8	// regs: r3=((<arg0> >> 0x10) >> 0x8)
   8:	c50055e0 	zext	r0, r0, 15, 8	// regs: r0=zext(<arg0>)
   c:	a163      	st.b	r3, (r1, 0x3)	// *(<arg1> + 0x3) = ((<arg0> >> 0x10) >> 0x8)
   e:	a101      	st.b	r0, (r1, 0x1)	// *(<arg1> + 0x1) = zext(<arg0>)
  10:	783c      	jmp	r15	// return;

Disassembly of section .text.lmac_tx_pv0_mgmt:

00000000 <lmac_tx_pv0_mgmt>: // arg_bytes: 4
   0:	ea8c003e 	lrw	r12, 0x0	// regs: r12=0x0
   4:	9068      	ld.w	r3, (r0, 0x20)	// regs: r3=*(<arg0> + 0x20)
   6:	d84c2295 	ld.w	r2, (r12, 0xa54)	// regs: r2=*(0xa54)
   a:	6482      	cmpne	r0, r2
   c:	0810      	bt	0x2c	// if (T) goto loc_2c;
   e:	d84c0308 	ld.b	r2, (r12, 0x308)	// regs: r2=*(0x308)
  12:	3a01      	cmphsi	r2, 2
  14:	c4000501 	mvc	r1	// regs: r1=<cond>
  18:	d8430025 	ld.b	r2, (r3, 0x25)	// regs: r2=*((*(<arg0> + 0x20) + 0x25))
  1c:	c4415c05 	ins	r2, r1, 5, 5
  20:	dc430025 	st.b	r2, (r3, 0x25)	// *((*(<arg0> + 0x20) + 0x25)) = *((*(<arg0> + 0x20) + 0x25))
  24:	9342      	ld.w	r2, (r3, 0x8)	// regs: r2=*((*(<arg0> + 0x20) + 0x8))
  26:	ec420009 	ori	r2, r2, 9	// regs: r2=(*((*(<arg0> + 0x20) + 0x8)) | 0x9)
  2a:	b342      	st.w	r2, (r3, 0x8)	// *((*(<arg0> + 0x20) + 0x8)) = (*((*(<arg0> + 0x20) + 0x8)) | 0x9)
loc_2c:
  2c:	9341      	ld.w	r2, (r3, 0x4)	// regs: r2=*((*(<arg0> + 0x20) + 0x4))
  2e:	e4422002 	andi	r2, r2, 2	// regs: r2=(*((*(<arg0> + 0x20) + 0x4)) & 0x2)
  32:	e902000d 	bez	r2, 0x4c	// if (r2 == 0x0) goto loc_4c;
  36:	d8434026 	ld.bs	r2, (r3, 0x26)	// regs: r2=*((*(<arg0> + 0x20) + 0x26))
  3a:	e9820009 	blz	r2, 0x4c	// if (r2 < 0x0) goto loc_4c;
  3e:	d8430025 	ld.b	r2, (r3, 0x25)	// regs: r2=*((*(<arg0> + 0x20) + 0x25))
  42:	3100      	movi	r1, 0	// regs: r1=0x0
  44:	c4415c01 	ins	r2, r1, 1, 1
  48:	dc430025 	st.b	r2, (r3, 0x25)	// *((*(<arg0> + 0x20) + 0x25)) = *((*(<arg0> + 0x20) + 0x25))
loc_4c:
  4c:	8b52      	ld.h	r2, (r3, 0x24)	// regs: r2=*((*(<arg0> + 0x20) + 0x24))
  4e:	c4a25501 	zext	r1, r2, 8, 5	// regs: r1=zext(*((*(<arg0> + 0x20) + 0x24)))
  52:	3945      	cmpnei	r1, 5
  54:	0c05      	bf	0x5e	// if (r1 == 0x5) goto loc_5e;
  56:	394d      	cmpnei	r1, 13
  58:	0c13      	bf	0x7e	// if (r1 == 0xd) goto loc_7e;
loc_5a:
  5a:	3000      	movi	r0, 0	// regs: r0=0x0
  5c:	783c      	jmp	r15	// return;
loc_5e:
  5e:	9067      	ld.w	r3, (r0, 0x1c)	// regs: r3=*(<arg0> + 0x1c)
  60:	9026      	ld.w	r1, (r0, 0x18)	// regs: r1=*(<arg0> + 0x18)
  62:	d8434001 	ld.bs	r2, (r3, 0x1)	// regs: r2=*((*(<arg0> + 0x1c) + 0x1))
  66:	e982000a 	blz	r2, 0x7a	// if (r2 < 0x0) goto loc_7a;
  6a:	2317      	addi	r3, 24	// regs: r3=(*(<arg0> + 0x1c) + 0x18)
loc_6c:
  6c:	2309      	addi	r3, 10	// regs: r3=(r3 + 0xa)
loc_6e:
  6e:	644c      	cmphs	r3, r1
  70:	0bf5      	bt	0x5a	// if (T) goto loc_5a;
  72:	8341      	ld.b	r2, (r3, 0x1)	// regs: r2=*(r3 + 0x1)
  74:	2201      	addi	r2, 2	// regs: r2=(*(r3 + 0x1) + 0x2)
  76:	60c8      	addu	r3, r2	// regs: r3=(r3 + (*(r3 + 0x1) + 0x2))
  78:	07fb      	br	0x6e	// goto loc_6e;
loc_7a:
  7a:	231b      	addi	r3, 28	// regs: r3=(*(<arg0> + 0x1c) + 0x1c)
  7c:	07f8      	br	0x6c	// goto loc_6c;
loc_7e:
  7e:	d820002a 	ld.b	r1, (r0, 0x2a)	// regs: r1=*(<arg0> + 0x2a)
  82:	e4212040 	andi	r1, r1, 64	// regs: r1=(*(<arg0> + 0x2a) & 0x40)
  86:	e901ffea 	bez	r1, 0x5a	// if (r1 == 0x0) goto loc_5a;
  8a:	e44221ff 	andi	r2, r2, 511	// regs: r2=(*((*(<arg0> + 0x20) + 0x24)) & 0x1ff)
  8e:	eb4201a0 	cmpnei	r2, 416
  92:	0be4      	bt	0x5a	// if (r2 != 0x1a0) goto loc_5a;
  94:	9324      	ld.w	r1, (r3, 0x10)	// regs: r1=*((*(<arg0> + 0x20) + 0x10))
  96:	e4410017 	addi	r2, r1, 24	// regs: r2=(*((*(<arg0> + 0x20) + 0x10)) + 0x18)
  9a:	8138      	ld.b	r1, (r1, 0x18)	// regs: r1=*((*((*(<arg0> + 0x20) + 0x10)) + 0x18))
  9c:	eb4100dd 	cmpnei	r1, 221
  a0:	0c09      	bf	0xb2	// if (r1 == 0xdd) goto loc_b2;
  a2:	eb410027 	cmpnei	r1, 39
  a6:	0bda      	bt	0x5a	// if (r1 != 0x27) goto loc_5a;
  a8:	9342      	ld.w	r2, (r3, 0x8)	// regs: r2=*((*(<arg0> + 0x20) + 0x8))
  aa:	ec420003 	ori	r2, r2, 3	// regs: r2=(*((*(<arg0> + 0x20) + 0x8)) | 0x3)
  ae:	b342      	st.w	r2, (r3, 0x8)	// *((*(<arg0> + 0x20) + 0x8)) = (*((*(<arg0> + 0x20) + 0x8)) | 0x3)
  b0:	07d5      	br	0x5a	// goto loc_5a;
loc_b2:
  b2:	8222      	ld.b	r1, (r2, 0x2)	// regs: r1=*((*((*(<arg0> + 0x20) + 0x10)) + 0x1a))
  b4:	e921ffd3 	bnez	r1, 0x5a	// if (r1 != 0x0) goto loc_5a;
  b8:	8223      	ld.b	r1, (r2, 0x3)	// regs: r1=*((*((*(<arg0> + 0x20) + 0x10)) + 0x1b))
  ba:	eb410040 	cmpnei	r1, 64
  be:	0bce      	bt	0x5a	// if (r1 != 0x40) goto loc_5a;
  c0:	8224      	ld.b	r1, (r2, 0x4)	// regs: r1=*((*((*(<arg0> + 0x20) + 0x10)) + 0x1c))
  c2:	3941      	cmpnei	r1, 1
  c4:	0bcb      	bt	0x5a	// if (r1 != 0x1) goto loc_5a;
  c6:	8247      	ld.b	r2, (r2, 0x7)	// regs: r2=*((*((*(<arg0> + 0x20) + 0x10)) + 0x1f))
  c8:	3a42      	cmpnei	r2, 2
  ca:	0bc8      	bt	0x5a	// if (r2 != 0x2) goto loc_5a;
  cc:	9342      	ld.w	r2, (r3, 0x8)	// regs: r2=*((*(<arg0> + 0x20) + 0x8))
  ce:	ec420005 	ori	r2, r2, 5	// regs: r2=(*((*(<arg0> + 0x20) + 0x8)) | 0x5)
  d2:	102b      	lrw	r1, 0x0	// regs: r1=0x0
  d4:	d803003f 	ld.b	r0, (r3, 0x3f)	// regs: r0=*((*(<arg0> + 0x20) + 0x3f))
  d8:	b342      	st.w	r2, (r3, 0x8)	// *((*(<arg0> + 0x20) + 0x8)) = (*((*(<arg0> + 0x20) + 0x8)) | 0x5)
  da:	8140      	ld.b	r2, (r1, 0x0)	// regs: r2=*(0x0)
  dc:	2200      	addi	r2, 1	// regs: r2=(*(0x0) + 0x1)
  de:	7488      	zextb	r2, r2	// regs: r2=zext8((*(0x0) + 0x1))
  e0:	c4025c80 	ins	r0, r2, 4, 0
  e4:	dc03003f 	st.b	r0, (r3, 0x3f)	// *((*(<arg0> + 0x20) + 0x3f)) = *((*(<arg0> + 0x20) + 0x3f))
  e8:	d86c0378 	ld.b	r3, (r12, 0x378)	// regs: r3=*(0x378)
  ec:	64c8      	cmphs	r2, r3
  ee:	a140      	st.b	r2, (r1, 0x0)	// *(0x0) = zext8((*(0x0) + 0x1))
  f0:	0fb5      	bf	0x5a	// if (!T) goto loc_5a;
  f2:	3300      	movi	r3, 0	// regs: r3=0x0
  f4:	a160      	st.b	r3, (r1, 0x0)	// *(0x0) = 0x0
  f6:	07b2      	br	0x5a	// goto loc_5a;
  f8:	00000000 	.long	0x00000000	// <ah_lmac>
  fc:	0000      	.short	0x0000	// <.bss.bss_ann_freq_idx.13317>
  fe:	0000      	.short	0x0000

Disassembly of section .text.lmac_tx_pv0_data:

00000000 <lmac_tx_pv0_data>: // arg_bytes: 4
   0:	1129      	lrw	r1, 0x0	// regs: r1=0x0
   2:	9068      	ld.w	r3, (r0, 0x20)	// regs: r3=*(<arg0> + 0x20)
   4:	9047      	ld.w	r2, (r0, 0x1c)	// regs: r2=*(<arg0> + 0x1c)
   6:	d8010336 	ld.b	r0, (r1, 0x336)	// regs: r0=*(0x336)
   a:	e4002001 	andi	r0, r0, 1	// regs: r0=(*(0x336) & 0x1)
   e:	e900003f 	bez	r0, 0x8c	// if (r0 == 0x0) goto loc_8c;
  12:	d9832003 	ld.w	r12, (r3, 0xc)	// regs: r12=*((*(<arg0> + 0x20) + 0xc))
  16:	d8030026 	ld.b	r0, (r3, 0x26)	// regs: r0=*((*(<arg0> + 0x20) + 0x26))
  1a:	e90c002f 	bez	r12, 0x78	// if (r12 == 0x0) goto loc_78;
  1e:	7742      	sextb	r13, r0	// regs: r13=sext8(*((*(<arg0> + 0x20) + 0x26)))
  20:	e98d002c 	blz	r13, 0x78	// if (r13 < 0x0) goto loc_78;
  24:	d98c0076 	ld.b	r12, (r12, 0x76)	// regs: r12=*((*((*(<arg0> + 0x20) + 0xc)) + 0x76))
  28:	eb4c0010 	cmpnei	r12, 16
  2c:	0c04      	bf	0x34	// if (r12 == 0x10) goto loc_34;
  2e:	eb4c0020 	cmpnei	r12, 32
  32:	0823      	bt	0x78	// if (r12 != 0x20) goto loc_78;
loc_34:
  34:	d803500a 	ld.hs	r0, (r3, 0x14)	// regs: r0=*((*(<arg0> + 0x20) + 0x14))
  38:	d823002a 	ld.b	r1, (r3, 0x2a)	// regs: r1=*((*(<arg0> + 0x20) + 0x2a))
  3c:	6405      	cmplt	r1, r0
  3e:	0c0a      	bf	0x52	// if (!T) goto loc_52;
  40:	8221      	ld.b	r1, (r2, 0x1)	// regs: r1=*((*(<arg0> + 0x1c) + 0x1))
  42:	d8030026 	ld.b	r0, (r3, 0x26)	// regs: r0=*((*(<arg0> + 0x20) + 0x26))
  46:	c4c154c1 	zext	r1, r1, 6, 6	// regs: r1=zext(*((*(<arg0> + 0x1c) + 0x1)))
  4a:	c4015c04 	ins	r0, r1, 4, 4
  4e:	dc030026 	st.b	r0, (r3, 0x26)	// *((*(<arg0> + 0x20) + 0x26)) = *((*(<arg0> + 0x20) + 0x26))
loc_52:
  52:	d8230027 	ld.b	r1, (r3, 0x27)	// regs: r1=*((*(<arg0> + 0x20) + 0x27))
  56:	e4212008 	andi	r1, r1, 8	// regs: r1=(*((*(<arg0> + 0x20) + 0x27)) & 0x8)
  5a:	e901000d 	bez	r1, 0x74	// if (r1 == 0x0) goto loc_74;
  5e:	d8030026 	ld.b	r0, (r3, 0x26)	// regs: r0=*((*(<arg0> + 0x20) + 0x26))
  62:	3100      	movi	r1, 0	// regs: r1=0x0
  64:	c4015c04 	ins	r0, r1, 4, 4
  68:	dc030026 	st.b	r0, (r3, 0x26)	// *((*(<arg0> + 0x20) + 0x26)) = *((*(<arg0> + 0x20) + 0x26))
  6c:	8261      	ld.b	r3, (r2, 0x1)	// regs: r3=*((*(<arg0> + 0x1c) + 0x1))
  6e:	c4615c06 	ins	r3, r1, 6, 6
  72:	a261      	st.b	r3, (r2, 0x1)	// *((*(<arg0> + 0x1c) + 0x1)) = *((*(<arg0> + 0x1c) + 0x1))
loc_74:
  74:	3000      	movi	r0, 0	// regs: r0=0x0
  76:	783c      	jmp	r15	// return;
loc_78:
  78:	7402      	sextb	r0, r0	// regs: r0=sext8(*((*(<arg0> + 0x20) + 0x26)))
  7a:	e9a00009 	bhsz	r0, 0x8c	// if (r0 >= 0x0) goto loc_8c;
  7e:	d8210693 	ld.b	r1, (r1, 0x693)	// regs: r1=*(0x693)
  82:	3950      	cmpnei	r1, 16
  84:	0fd8      	bf	0x34	// if (r1 == 0x10) goto loc_34;
  86:	eb410020 	cmpnei	r1, 32
  8a:	0fd5      	bf	0x34	// if (r1 == 0x20) goto loc_34;
loc_8c:
  8c:	8221      	ld.b	r1, (r2, 0x1)	// regs: r1=*((*(<arg0> + 0x1c) + 0x1))
  8e:	3000      	movi	r0, 0	// regs: r0=0x0
  90:	c4205c06 	ins	r1, r0, 6, 6
  94:	a221      	st.b	r1, (r2, 0x1)	// *((*(<arg0> + 0x1c) + 0x1)) = *((*(<arg0> + 0x1c) + 0x1))
  96:	d8230026 	ld.b	r1, (r3, 0x26)	// regs: r1=*((*(<arg0> + 0x20) + 0x26))
  9a:	c4205c04 	ins	r1, r0, 4, 4
  9e:	dc230026 	st.b	r1, (r3, 0x26)	// *((*(<arg0> + 0x20) + 0x26)) = *((*(<arg0> + 0x20) + 0x26))
  a2:	07d8      	br	0x52	// goto loc_52;
  a4:	0000      	.short	0x0000	// <ah_lmac>
  a6:	0000      	.short	0x0000

Disassembly of section .text.lmac_tx_pv1_ctrl:

00000000 <lmac_tx_pv1_ctrl>: // arg_bytes: 4
   0:	9068      	ld.w	r3, (r0, 0x20)	// regs: r3=*(<arg0> + 0x20)
   2:	3101      	movi	r1, 1	// regs: r1=0x1
   4:	d8430027 	ld.b	r2, (r3, 0x27)	// regs: r2=*((*(<arg0> + 0x20) + 0x27))
   8:	c4415c00 	ins	r2, r1, 0, 0
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	dc430027 	st.b	r2, (r3, 0x27)	// *((*(<arg0> + 0x20) + 0x27)) = *((*(<arg0> + 0x20) + 0x27))
  12:	783c      	jmp	r15	// return;

Disassembly of section .text.lmac_tx_pv1_data2:

00000000 <lmac_tx_pv1_data2>: // arg_bytes: 0
   0:	3000      	movi	r0, 0	// regs: r0=0x0
   2:	783c      	jmp	r15	// return;

Disassembly of section .text.lmac_check_tx_queue_empty:

00000000 <lmac_check_tx_queue_empty>: // arg_bytes: 4
   0:	14d5      	push	r4-r8, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	3301      	movi	r3, 1	// regs: r3=0x1
   6:	dc6e0000 	st.b	r3, (r14, 0x0)	// local_4 = 0x1
   a:	3300      	movi	r3, 0	// regs: r3=0x0
   c:	dc6e0001 	st.b	r3, (r14, 0x1)	// local_3 = 0x0
  10:	3302      	movi	r3, 2	// regs: r3=0x2
  12:	dc6e0002 	st.b	r3, (r14, 0x2)	// local_2 = 0x2
  16:	3500      	movi	r5, 0	// regs: r5=0x0
  18:	3303      	movi	r3, 3	// regs: r3=0x3
  1a:	3690      	movi	r6, 144	// regs: r6=0x90
  1c:	dc6e0003 	st.b	r3, (r14, 0x3)	// local_1 = 0x3
  20:	6d17      	mov	r4, r5	// regs: r4=0x0
  22:	10f1      	lrw	r7, 0x0	// regs: r7=0x0
  24:	46c1      	lsli	r6, r6, 1	// regs: r6=0x120
  26:	ea880011 	lrw	r8, 0x0	// regs: r8=0x0
loc_2a:
  2a:	e4050087 	addi	r0, r5, 136	// regs: r0=(r5 + 0x88)
  2e:	601c      	addu	r0, r7	// regs: r0=((r5 + 0x88) )
  30:	e0000000 	bsr	0x0	// <skb_list_count>; regs: r0=<ret skb_list_count@0x30>, r1=<clobbered>
  34:	c4c48423 	mult	r3, r4, r6	// regs: r3=(r4 * 0x120)
  38:	60dc      	addu	r3, r7	// regs: r3=((r4 * 0x120) )
  3a:	d86301c5 	ld.b	r3, (r3, 0x1c5)	// regs: r3=*((((r4 * 0x120) ) + 0x1c5))
  3e:	600c      	addu	r0, r3	// regs: r0=(<ret skb_list_count@0x30> + *((((r4 * 0x120) ) + 0x1c5)))
  40:	e920000c 	bnez	r0, 0x58	// if (r0 != 0x0) goto loc_58;
  44:	d8482000 	ld.w	r2, (r8, 0x0)	// regs: r2=*(0x0)
  48:	3300      	movi	r3, 0	// regs: r3=0x0
  4a:	d08e0020 	ldr.b	r0, (r14, r4 << 0)	// regs: r0=*((sp - 0x4) + (r4 << 0))
  4e:	2b01      	subi	r3, 2	// regs: r3=0xfffffffe
  50:	9233      	ld.w	r1, (r2, 0x4c)	// regs: r1=*((*(0x0) + 0x4c))
  52:	70c3      	rotl	r3, r0
  54:	68c4      	and	r3, r1	// regs: r3=(0xfffffffe & *((*(0x0) + 0x4c)))
  56:	b273      	st.w	r3, (r2, 0x4c)	// *((*(0x0) + 0x4c)) = (0xfffffffe & *((*(0x0) + 0x4c)))
loc_58:
  58:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  5a:	3c44      	cmpnei	r4, 4
  5c:	250b      	addi	r5, 12	// regs: r5=(r5 + 0xc)
  5e:	0be6      	bt	0x2a	// if (r4 != 0x4) goto loc_2a;
  60:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  62:	1495      	pop	r4-r8, r15
  64:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  68:	00000000 	.long	0x00000000	// <LMAC>

Disassembly of section .text.lmac_tx_pv0_ctrl:

00000000 <lmac_tx_pv0_ctrl>: // arg_bytes: 4
   0:	14d2      	push	r4-r5, r15
   2:	d860002a 	ld.b	r3, (r0, 0x2a)	// regs: r3=*(<arg0> + 0x2a)
   6:	e4632040 	andi	r3, r3, 64	// regs: r3=(*(<arg0> + 0x2a) & 0x40)
   a:	9088      	ld.w	r4, (r0, 0x20)	// regs: r4=*(<arg0> + 0x20)
   c:	e9030032 	bez	r3, 0x70	// if (r3 == 0x0) goto loc_70;
  10:	8c72      	ld.h	r3, (r4, 0x24)	// regs: r3=*((*(<arg0> + 0x20) + 0x24))
  12:	e46321e0 	andi	r3, r3, 480	// regs: r3=(*((*(<arg0> + 0x20) + 0x24)) & 0x1e0)
  16:	eb430160 	cmpnei	r3, 352
  1a:	082b      	bt	0x70	// if (r3 != 0x160) goto loc_70;
  1c:	9462      	ld.w	r3, (r4, 0x8)	// regs: r3=*((*(<arg0> + 0x20) + 0x8))
  1e:	ec630011 	ori	r3, r3, 17	// regs: r3=(*((*(<arg0> + 0x20) + 0x8)) | 0x11)
  22:	1059      	lrw	r2, 0x0	// regs: r2=0x0
  24:	10b9      	lrw	r5, 0x0	// regs: r5=0x0
  26:	101a      	lrw	r0, 0x0	// regs: r0=0x0
  28:	8520      	ld.b	r1, (r5, 0x0)	// regs: r1=*(0x0)
  2a:	b462      	st.w	r3, (r4, 0x8)	// *((*(<arg0> + 0x20) + 0x8)) = (*((*(<arg0> + 0x20) + 0x8)) | 0x11)
  2c:	d8620313 	ld.b	r3, (r2, 0x313)	// regs: r3=*(0x313)
  30:	2b00      	subi	r3, 1	// regs: r3=(*(0x313) - 0x1)
  32:	d8420875 	ld.b	r2, (r2, 0x875)	// regs: r2=*(0x875)
  36:	dc640028 	st.b	r3, (r4, 0x28)	// *((*(<arg0> + 0x20) + 0x28)) = (*(0x313) - 0x1)
  3a:	c4825483 	zext	r3, r2, 4, 4	// regs: r3=zext(*(0x875))
  3e:	c4625462 	zext	r2, r2, 3, 3	// regs: r2=zext(*(0x875))
  42:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x42>, r1=<clobbered>
  46:	8560      	ld.b	r3, (r5, 0x0)	// regs: r3=*(0x0)
  48:	e4432001 	andi	r2, r3, 1	// regs: r2=(*(0x0) & 0x1)
  4c:	3a40      	cmpnei	r2, 0
  4e:	6483      	mvcv	r2	// regs: r2=<cond>
  50:	2200      	addi	r2, 1	// regs: r2=(<cond> + 0x1)
  52:	d824003f 	ld.b	r1, (r4, 0x3f)	// regs: r1=*((*(<arg0> + 0x20) + 0x3f))
  56:	c4225c25 	ins	r1, r2, 6, 5
  5a:	dc24003f 	st.b	r1, (r4, 0x3f)	// *((*(<arg0> + 0x20) + 0x3f)) = *((*(<arg0> + 0x20) + 0x3f))
  5e:	d8440025 	ld.b	r2, (r4, 0x25)	// regs: r2=*((*(<arg0> + 0x20) + 0x25))
  62:	3100      	movi	r1, 0	// regs: r1=0x0
  64:	c4415c01 	ins	r2, r1, 1, 1
  68:	2300      	addi	r3, 1	// regs: r3=(*(0x0) + 0x1)
  6a:	dc440025 	st.b	r2, (r4, 0x25)	// *((*(<arg0> + 0x20) + 0x25)) = *((*(<arg0> + 0x20) + 0x25))
  6e:	a560      	st.b	r3, (r5, 0x0)	// *(0x0) = (*(0x0) + 0x1)
loc_70:
  70:	d8640027 	ld.b	r3, (r4, 0x27)	// regs: r3=*((*(<arg0> + 0x20) + 0x27))
  74:	3201      	movi	r2, 1	// regs: r2=0x1
  76:	c4625c00 	ins	r3, r2, 0, 0
  7a:	3000      	movi	r0, 0	// regs: r0=0x0
  7c:	dc640027 	st.b	r3, (r4, 0x27)	// *((*(<arg0> + 0x20) + 0x27)) = *((*(<arg0> + 0x20) + 0x27))
  80:	1492      	pop	r4-r5, r15
  82:	0000      	.short	0x0000
  84:	0000      	.short	0x0000	// <ah_lmac>
  86:	0000      	.short	0x0000
  88:	0000      	.short	0x0000	// <.bss.ant_cnt.13341>
  8a:	0000      	.short	0x0000
  8c:	0000      	.short	0x0000	// <.rodata.lmac_tx_pv0_ctrl.str1.1>
  8e:	0000      	.short	0x0000

Disassembly of section .text.lmac_cfp_timer_remain:

00000000 <lmac_cfp_timer_remain>: // arg_bytes: 8
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x2>, r1=<clobbered>
   6:	ea8c001a 	lrw	r12, 0x0	// regs: r12=0x0
   a:	d86c0878 	ld.b	r3, (r12, 0x878)	// regs: r3=*(0x878)
   e:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x878) & 0x1)
  12:	e903001c 	bez	r3, 0x4a	// if (r3 == 0x0) goto loc_4a;
  16:	d84c2223 	ld.w	r2, (r12, 0x88c)	// regs: r2=*(0x88c)
  1a:	d86c2222 	ld.w	r3, (r12, 0x888)	// regs: r3=*(0x888)
  1e:	d9ac2220 	ld.w	r13, (r12, 0x880)	// regs: r13=*(0x880)
  22:	d98c2221 	ld.w	r12, (r12, 0x884)	// regs: r12=*(0x884)
  26:	64b0      	cmphs	r12, r2
  28:	0c05      	bf	0x32	// if (!T) goto loc_32;
  2a:	670a      	cmpne	r2, r12
  2c:	0811      	bt	0x4e	// if (T) goto loc_4e;
  2e:	64f4      	cmphs	r13, r3
  30:	080f      	bt	0x4e	// if (T) goto loc_4e;
loc_32:
  32:	6704      	cmphs	r1, r12
  34:	0c0b      	bf	0x4a	// if (!T) goto loc_4a;
  36:	6472      	cmpne	r12, r1
  38:	0803      	bt	0x3e	// if (T) goto loc_3e;
  3a:	6740      	cmphs	r0, r13
  3c:	0c07      	bf	0x4a	// if (!T) goto loc_4a;
loc_3e:
  3e:	6448      	cmphs	r2, r1
  40:	0c05      	bf	0x4a	// if (!T) goto loc_4a;
  42:	6486      	cmpne	r1, r2
  44:	0812      	bt	0x68	// if (T) goto loc_68;
  46:	640c      	cmphs	r3, r0
  48:	0810      	bt	0x68	// if (T) goto loc_68;
loc_4a:
  4a:	3000      	movi	r0, 0	// regs: r0=0x0
  4c:	040f      	br	0x6a	// goto loc_6a;
loc_4e:
  4e:	6708      	cmphs	r2, r12
  50:	0c05      	bf	0x5a	// if (!T) goto loc_5a;
  52:	64b2      	cmpne	r12, r2
  54:	0bfb      	bt	0x4a	// if (T) goto loc_4a;
  56:	674c      	cmphs	r3, r13
  58:	0bf9      	bt	0x4a	// if (T) goto loc_4a;
loc_5a:
  5a:	6704      	cmphs	r1, r12
  5c:	0ff1      	bf	0x3e	// if (!T) goto loc_3e;
  5e:	6472      	cmpne	r12, r1
  60:	0803      	bt	0x66	// if (T) goto loc_66;
  62:	6740      	cmphs	r0, r13
  64:	0fed      	bf	0x3e	// if (!T) goto loc_3e;
loc_66:
  66:	2b00      	subi	r3, 1	// regs: r3=(*(0x888) - 0x1)
loc_68:
  68:	5b01      	subu	r0, r3, r0	// regs: r0=(r3 - <ret os_jiffies@0x2>)
loc_6a:
  6a:	1490      	pop	r15
  6c:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_gen_tx_agglist:

00000000 <lmac_gen_tx_agglist>: // arg_bytes: 16
   0:	14d8      	push	r4-r11, r15
   2:	142c      	subi	r14, r14, 48	// regs: r14=(sp - 0x30)
   4:	3803      	cmphsi	r0, 4
   6:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   8:	6e87      	mov	r10, r1	// regs: r10=<arg1>
   a:	6e4b      	mov	r9, r2	// regs: r9=<arg2>
   c:	6ecf      	mov	r11, r3	// regs: r11=<arg3>
   e:	0c08      	bf	0x1e	// if (r0 < 0x4) goto loc_1e;
  10:	6c43      	mov	r1, r0	// regs: r1=<arg0>
  12:	001b      	lrw	r0, 0x0	// regs: r0=0x0
  14:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x14>, r1=<clobbered>
loc_18:
  18:	3000      	movi	r0, 0	// regs: r0=0x0
loc_1a:
  1a:	140c      	addi	r14, r14, 48	// regs: r14=(sp + 0x30)
  1c:	1498      	pop	r4-r11, r15
loc_1e:
  1e:	3390      	movi	r3, 144	// regs: r3=0x90
  20:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  22:	c4608422 	mult	r2, r0, r3	// regs: r2=(<arg0> * 0x120)
  26:	009f      	lrw	r4, 0x0	// regs: r4=0x0
  28:	6090      	addu	r2, r4	// regs: r2=((<arg0> * 0x120) )
  2a:	3100      	movi	r1, 0	// regs: r1=0x0
  2c:	dc2201c4 	st.b	r1, (r2, 0x1c4)	// *((((<arg0> * 0x120) ) + 0x1c4)) = 0x0
  30:	3100      	movi	r1, 0	// regs: r1=0x0
  32:	dc22206e 	st.w	r1, (r2, 0x1b8)	// *((((<arg0> * 0x120) ) + 0x1b8)) = 0x0
  36:	dc22206f 	st.w	r1, (r2, 0x1bc)	// *((((<arg0> * 0x120) ) + 0x1bc)) = 0x0
  3a:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  3c:	e40201bf 	addi	r0, r2, 448	// regs: r0=(((<arg0> * 0x120) ) + 0x1c0)
  40:	dc2210e0 	st.h	r1, (r2, 0x1c0)	// *((((<arg0> * 0x120) ) + 0x1c0)) = 0xffffffff
  44:	dc2210e1 	st.h	r1, (r2, 0x1c2)	// *((((<arg0> * 0x120) ) + 0x1c2)) = 0xffffffff
  48:	eb090007 	cmphsi	r9, 8
  4c:	d84201c6 	ld.b	r2, (r2, 0x1c6)	// regs: r2=*((((<arg0> * 0x120) ) + 0x1c6))
  50:	c44a5c20 	ins	r2, r10, 1, 0
  54:	a046      	st.b	r2, (r0, 0x6)	// *((((<arg0> * 0x120) ) + 0x1c6)) = *((((<arg0> * 0x120) ) + 0x1c6))
  56:	0c04      	bf	0x5e	// if (r9 < 0x8) goto loc_5e;
  58:	eb49000a 	cmpnei	r9, 10
  5c:	0809      	bt	0x6e	// if (r9 != 0xa) goto loc_6e;
loc_5e:
  5e:	7cd4      	mult	r3, r5	// regs: r3=(0x120 * <arg0>)
  60:	60d0      	addu	r3, r4	// regs: r3=((0x120 * <arg0>) )
  62:	d84301c6 	ld.b	r2, (r3, 0x1c6)	// regs: r2=*((((0x120 * <arg0>) ) + 0x1c6))
  66:	c4495c62 	ins	r2, r9, 5, 2
  6a:	dc4301c6 	st.b	r2, (r3, 0x1c6)	// *((((0x120 * <arg0>) ) + 0x1c6)) = *((((0x120 * <arg0>) ) + 0x1c6))
loc_6e:
  6e:	01f0      	lrw	r7, 0x0	// regs: r7=0x0
  70:	d90711b0 	ld.h	r8, (r7, 0x360)	// regs: r8=*(0x360)
  74:	c4285528 	zext	r8, r8, 9, 1	// regs: r8=zext(*(0x360))
  78:	74e1      	zexth	r3, r8	// regs: r3=zext16(zext(*(0x360)))
  7a:	64ec      	cmphs	r11, r3
  7c:	0802      	bt	0x80	// if (T) goto loc_80;
  7e:	6e2f      	mov	r8, r11	// regs: r8=<arg3>
loc_80:
  80:	6c67      	mov	r1, r9	// regs: r1=<arg2>
  82:	6c2b      	mov	r0, r10	// regs: r0=<arg1>
  84:	e0000000 	bsr	0x0	// <calc_max_agg_bytes>; regs: r0=<ret calc_max_agg_bytes@0x84>, r1=<clobbered>
  88:	d827034a 	ld.b	r1, (r7, 0x34a)	// regs: r1=*(0x34a)
  8c:	7621      	zexth	r8, r8	// regs: r8=zext16(r8)
  8e:	e4212001 	andi	r1, r1, 1	// regs: r1=(*(0x34a) & 0x1)
  92:	7c20      	mult	r0, r8	// regs: r0=(<ret calc_max_agg_bytes@0x84> * zext16(r8))
  94:	ea0301ff 	movi	r3, 511	// regs: r3=0x1ff
  98:	c4608026 	divu	r6, r0, r3	// regs: r6=((<ret calc_max_agg_bytes@0x84> * zext16(r8)) / 0x1ff)
  9c:	e9010042 	bez	r1, 0x120	// if (r1 == 0x0) goto loc_120;
  a0:	3100      	movi	r1, 0	// regs: r1=0x0
  a2:	3003      	movi	r0, 3	// regs: r0=0x3
loc_a4:
  a4:	e0000000 	bsr	0x0	// <calc_max_agg_bytes>; regs: r0=<ret calc_max_agg_bytes@0xa4>, r1=<clobbered>
  a8:	ea0c0090 	movi	r12, 144	// regs: r12=0x90
  ac:	c42c482c 	lsli	r12, r12, 1	// regs: r12=0x120
  b0:	7f14      	mult	r12, r5	// regs: r12=(0x120 * <arg0>)
  b2:	6310      	addu	r12, r4	// regs: r12=((0x120 * <arg0>) )
  b4:	e44c01c4 	addi	r2, r12, 453	// regs: r2=(((0x120 * <arg0>) ) + 0x1c5)
  b8:	b846      	st.w	r2, (r14, 0x18)	// local_18 = (((0x120 * <arg0>) ) + 0x1c5)
  ba:	3248      	movi	r2, 72	// regs: r2=0x48
  bc:	7c94      	mult	r2, r5	// regs: r2=(0x48 * <arg0>)
  be:	6580      	cmphs	r0, r6
  c0:	b847      	st.w	r2, (r14, 0x1c)	// local_14 = (0x48 * <arg0>)
  c2:	c4c00c40 	inct	r6, r0, 0
  c6:	0245      	lrw	r2, 0x0	// regs: r2=0x0
  c8:	3300      	movi	r3, 0	// regs: r3=0x0
  ca:	b848      	st.w	r2, (r14, 0x20)	// local_10 = 0x0
  cc:	b8c5      	st.w	r6, (r14, 0x14)	// local_1c = ((<ret calc_max_agg_bytes@0x84> * zext16(r8)) / 0x1ff)
  ce:	6c0f      	mov	r0, r3	// regs: r0=0x0
  d0:	0247      	lrw	r2, 0x0	// regs: r2=0x0
  d2:	6d8f      	mov	r6, r3	// regs: r6=0x0
  d4:	b849      	st.w	r2, (r14, 0x24)	// local_c = 0x0
loc_d6:
  d6:	9846      	ld.w	r2, (r14, 0x18)	// regs: r2=local_18
  d8:	8240      	ld.b	r2, (r2, 0x0)	// regs: r2=*(local_18)
  da:	6498      	cmphs	r6, r2
  dc:	0c24      	bf	0x124	// if (!T) goto loc_124;
  de:	ea0d0000 	movi	r13, 0	// regs: r13=0x0
loc_e2:
  e2:	3290      	movi	r2, 144	// regs: r2=0x90
  e4:	4241      	lsli	r2, r2, 1	// regs: r2=0x120
  e6:	7c94      	mult	r2, r5	// regs: r2=(0x120 * <arg0>)
  e8:	6090      	addu	r2, r4	// regs: r2=((0x120 * <arg0>) )
  ea:	d98201c4 	ld.b	r12, (r2, 0x1c4)	// regs: r12=*((((0x120 * <arg0>) ) + 0x1c4))
  ee:	e92c0080 	bnez	r12, 0x1ee	// if (r12 != 0x0) goto loc_1ee;
  f2:	d82201c5 	ld.b	r1, (r2, 0x1c5)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1c5))
  f6:	e9010045 	bez	r1, 0x180	// if (r1 == 0x0) goto loc_180;
  fa:	9865      	ld.w	r3, (r14, 0x14)	// regs: r3=local_1c
  fc:	dd0e2004 	st.w	r8, (r14, 0x10)	// local_20 = zext16(r8)
 100:	b863      	st.w	r3, (r14, 0xc)	// local_24 = local_1c
 102:	d860500b 	ld.hs	r3, (r0, 0x16)	// regs: r3=*(r0 + 0x16)
 106:	b862      	st.w	r3, (r14, 0x8)	// local_28 = *(r0 + 0x16)
 108:	dd6e2001 	st.w	r11, (r14, 0x4)	// local_2c = <arg3>
 10c:	dd2e2000 	st.w	r9, (r14, 0x0)	// local_30 = <arg2>
 110:	6ceb      	mov	r3, r10	// regs: r3=<arg1>
 112:	6c97      	mov	r2, r5	// regs: r2=<arg0>
 114:	0217      	lrw	r0, 0x0	// regs: r0=0x0
 116:	dd8e2006 	st.w	r12, (r14, 0x18)	// local_18 = *((((0x120 * <arg0>) ) + 0x1c4))
 11a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x11a>, r1=<clobbered>
 11e:	077d      	br	0x18	// goto loc_18;
loc_120:
 120:	6c07      	mov	r0, r1	// regs: r0=(*(0x34a) & 0x1)
 122:	07c1      	br	0xa4	// goto loc_a4;
loc_124:
 124:	9867      	ld.w	r3, (r14, 0x1c)	// regs: r3=local_14
 126:	60d8      	addu	r3, r6	// regs: r3=(local_14 + r6)
 128:	232d      	addi	r3, 46	// regs: r3=((local_14 + r6) + 0x2e)
 12a:	d0640883 	ldr.w	r3, (r4, r3 << 2)	// regs: r3=*(0x0 + (((local_14 + r6) + 0x2e) << 2))
 12e:	e923000e 	bnez	r3, 0x14a	// if (r3 != 0x0) goto loc_14a;
 132:	9848      	ld.w	r2, (r14, 0x20)	// regs: r2=local_10
 134:	ea010789 	movi	r1, 1929	// regs: r1=0x789
 138:	9809      	ld.w	r0, (r14, 0x24)	// regs: r0=local_c
 13a:	dd8e200b 	st.w	r12, (r14, 0x2c)	// local_4 = r12
 13e:	b86a      	st.w	r3, (r14, 0x28)	// local_8 = *(0x0 + (((local_14 + r6) + 0x2e) << 2))
 140:	e0000000 	bsr	0x0	// <assert_internal>; regs: r0=<ret assert_internal@0x140>, r1=<clobbered>
 144:	d98e200b 	ld.w	r12, (r14, 0x2c)	// regs: r12=local_4
 148:	986a      	ld.w	r3, (r14, 0x28)	// regs: r3=local_8
loc_14a:
 14a:	d82c01c4 	ld.b	r1, (r12, 0x1c4)	// regs: r1=*(r12 + 0x1c4)
 14e:	d8470315 	ld.b	r2, (r7, 0x315)	// regs: r2=*(0x315)
 152:	6484      	cmphs	r1, r2
 154:	9308      	ld.w	r0, (r3, 0x20)	// regs: r0=*(r3 + 0x20)
 156:	0812      	bt	0x17a	// if (T) goto loc_17a;
 158:	d9a0500b 	ld.hs	r13, (r0, 0x16)	// regs: r13=*((*(r3 + 0x20) + 0x16))
 15c:	d84c206e 	ld.w	r2, (r12, 0x1b8)	// regs: r2=*(r12 + 0x1b8)
 160:	60b4      	addu	r2, r13	// regs: r2=(*(r12 + 0x1b8) + *((*(r3 + 0x20) + 0x16)))
 162:	d9ae2005 	ld.w	r13, (r14, 0x14)	// regs: r13=local_1c
 166:	64b4      	cmphs	r13, r2
 168:	0c09      	bf	0x17a	// if (!T) goto loc_17a;
 16a:	2600      	addi	r6, 1	// regs: r6=(r6 + 0x1)
 16c:	2100      	addi	r1, 1	// regs: r1=(*(r12 + 0x1c4) + 0x1)
 16e:	7598      	zextb	r6, r6	// regs: r6=zext8((r6 + 0x1))
 170:	dc2c01c4 	st.b	r1, (r12, 0x1c4)	// *(r12 + 0x1c4) = (*(r12 + 0x1c4) + 0x1)
 174:	dc4c206e 	st.w	r2, (r12, 0x1b8)	// *(r12 + 0x1b8) = (*(r12 + 0x1b8) + *((*(r3 + 0x20) + 0x16)))
 178:	07af      	br	0xd6	// goto loc_d6;
loc_17a:
 17a:	ea0d0001 	movi	r13, 1	// regs: r13=0x1
 17e:	07b2      	br	0xe2	// goto loc_e2;
loc_180:
 180:	74d7      	sexth	r3, r5	// regs: r3=sext16(<arg0>)
 182:	5b0c      	addu	r0, r3, r3	// regs: r0=(sext16(<arg0>) + sext16(<arg0>))
 184:	600c      	addu	r0, r3	// regs: r0=((sext16(<arg0>) + sext16(<arg0>)) + sext16(<arg0>))
 186:	4002      	lsli	r0, r0, 2	// regs: r0=(((sext16(<arg0>) + sext16(<arg0>)) + sext16(<arg0>)) << 0x2)
 188:	2087      	addi	r0, 136	// regs: r0=((((sext16(<arg0>) + sext16(<arg0>)) + sext16(<arg0>)) << 0x2) + 0x88)
 18a:	6010      	addu	r0, r4	// regs: r0=(((((sext16(<arg0>) + sext16(<arg0>)) + sext16(<arg0>)) << 0x2) + 0x88) )
 18c:	ddae2006 	st.w	r13, (r14, 0x18)	// local_18 = r13
 190:	e0000000 	bsr	0x0	// <skb_list_dequeue>; regs: r0=<ret skb_list_dequeue@0x190>, r1=<clobbered>
 194:	6cc3      	mov	r3, r0	// regs: r3=<ret skb_list_dequeue@0x190>
 196:	d9ae2006 	ld.w	r13, (r14, 0x18)	// regs: r13=local_18
 19a:	e920000c 	bnez	r0, 0x1b2	// if (r0 != 0x0) goto loc_1b2;
 19e:	b807      	st.w	r0, (r14, 0x1c)	// local_14 = <ret skb_list_dequeue@0x190>
 1a0:	ea01079f 	movi	r1, 1951	// regs: r1=0x79f
 1a4:	035d      	lrw	r2, 0x0	// regs: r2=0x0
 1a6:	031c      	lrw	r0, 0x0	// regs: r0=0x0
 1a8:	e0000000 	bsr	0x0	// <assert_internal>; regs: r0=<ret assert_internal@0x1a8>, r1=<clobbered>
 1ac:	9867      	ld.w	r3, (r14, 0x1c)	// regs: r3=local_14
 1ae:	d9ae2006 	ld.w	r13, (r14, 0x18)	// regs: r13=local_18
loc_1b2:
 1b2:	3248      	movi	r2, 72	// regs: r2=0x48
 1b4:	7c94      	mult	r2, r5	// regs: r2=(0x48 * <arg0>)
 1b6:	6098      	addu	r2, r6	// regs: r2=((0x48 * <arg0>) + r6)
 1b8:	222d      	addi	r2, 46	// regs: r2=(((0x48 * <arg0>) + r6) + 0x2e)
 1ba:	9328      	ld.w	r1, (r3, 0x20)	// regs: r1=*(r3 + 0x20)
 1bc:	d4440883 	str.w	r3, (r4, r2 << 2)
 1c0:	3290      	movi	r2, 144	// regs: r2=0x90
 1c2:	4241      	lsli	r2, r2, 1	// regs: r2=0x120
 1c4:	7c94      	mult	r2, r5	// regs: r2=(0x120 * <arg0>)
 1c6:	6090      	addu	r2, r4	// regs: r2=((0x120 * <arg0>) )
 1c8:	2600      	addi	r6, 1	// regs: r6=(r6 + 0x1)
 1ca:	d80201c4 	ld.b	r0, (r2, 0x1c4)	// regs: r0=*((((0x120 * <arg0>) ) + 0x1c4))
 1ce:	2000      	addi	r0, 1	// regs: r0=(*((((0x120 * <arg0>) ) + 0x1c4)) + 0x1)
 1d0:	dc0201c4 	st.b	r0, (r2, 0x1c4)	// *((((0x120 * <arg0>) ) + 0x1c4)) = (*((((0x120 * <arg0>) ) + 0x1c4)) + 0x1)
 1d4:	d80201c5 	ld.b	r0, (r2, 0x1c5)	// regs: r0=*((((0x120 * <arg0>) ) + 0x1c5))
 1d8:	2000      	addi	r0, 1	// regs: r0=(*((((0x120 * <arg0>) ) + 0x1c5)) + 0x1)
 1da:	dc0201c5 	st.b	r0, (r2, 0x1c5)	// *((((0x120 * <arg0>) ) + 0x1c5)) = (*((((0x120 * <arg0>) ) + 0x1c5)) + 0x1)
 1de:	d801500b 	ld.hs	r0, (r1, 0x16)	// regs: r0=*((*(r3 + 0x20) + 0x16))
 1e2:	d822206e 	ld.w	r1, (r2, 0x1b8)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1b8))
 1e6:	6040      	addu	r1, r0	// regs: r1=(*((((0x120 * <arg0>) ) + 0x1b8)) + *((*(r3 + 0x20) + 0x16)))
 1e8:	7598      	zextb	r6, r6	// regs: r6=zext8((r6 + 0x1))
 1ea:	dc22206e 	st.w	r1, (r2, 0x1b8)	// *((((0x120 * <arg0>) ) + 0x1b8)) = (*((((0x120 * <arg0>) ) + 0x1b8)) + *((*(r3 + 0x20) + 0x16)))
loc_1ee:
 1ee:	3290      	movi	r2, 144	// regs: r2=0x90
 1f0:	4241      	lsli	r2, r2, 1	// regs: r2=0x120
 1f2:	7c94      	mult	r2, r5	// regs: r2=(0x120 * <arg0>)
 1f4:	6090      	addu	r2, r4	// regs: r2=((0x120 * <arg0>) )
 1f6:	d822202e 	ld.w	r1, (r2, 0xb8)	// regs: r1=*((((0x120 * <arg0>) ) + 0xb8))
 1fa:	9128      	ld.w	r1, (r1, 0x20)	// regs: r1=*((*((((0x120 * <arg0>) ) + 0xb8)) + 0x20))
 1fc:	892c      	ld.h	r1, (r1, 0x18)	// regs: r1=*((*((*((((0x120 * <arg0>) ) + 0xb8)) + 0x20)) + 0x18))
 1fe:	dc2210e0 	st.h	r1, (r2, 0x1c0)	// *((((0x120 * <arg0>) ) + 0x1c0)) = *((*((*((((0x120 * <arg0>) ) + 0xb8)) + 0x20)) + 0x18))
 202:	d82201c4 	ld.b	r1, (r2, 0x1c4)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1c4))
 206:	2900      	subi	r1, 1	// regs: r1=(*((((0x120 * <arg0>) ) + 0x1c4)) - 0x1)
 208:	7404      	zextb	r0, r1	// regs: r0=zext8((*((((0x120 * <arg0>) ) + 0x1c4)) - 0x1))
 20a:	3148      	movi	r1, 72	// regs: r1=0x48
 20c:	7c54      	mult	r1, r5	// regs: r1=(0x48 * <arg0>)
 20e:	6040      	addu	r1, r0	// regs: r1=((0x48 * <arg0>) + zext8((*((((0x120 * <arg0>) ) + 0x1c4)) - 0x1)))
 210:	212d      	addi	r1, 46	// regs: r1=(((0x48 * <arg0>) + zext8((*((((0x120 * <arg0>) ) + 0x1c4)) - 0x1))) + 0x2e)
 212:	d0240881 	ldr.w	r1, (r4, r1 << 2)	// regs: r1=*(0x0 + ((((0x48 * <arg0>) + zext8((*((((0x120 * <arg0>) ) + 0x1c4)) - 0x1))) + 0x2e) << 2))
 216:	9128      	ld.w	r1, (r1, 0x20)	// regs: r1=*((*(0x0 + ((((0x48 * <arg0>) + zext8((*((((0x120 * <arg0>) ) + 0x1c4)) - 0x1))) + 0x2e) << 2)) + 0x20))
 218:	890c      	ld.h	r0, (r1, 0x18)	// regs: r0=*((*((*(0x0 + ((((0x48 * <arg0>) + zext8((*((((0x120 * <arg0>) ) + 0x1c4)) - 0x1))) + 0x2e) << 2)) + 0x20)) + 0x18))
 21a:	dc0210e1 	st.h	r0, (r2, 0x1c2)	// *((((0x120 * <arg0>) ) + 0x1c2)) = *((*((*(0x0 + ((((0x48 * <arg0>) + zext8((*((((0x120 * <arg0>) ) + 0x1c4)) - 0x1))) + 0x2e) << 2)) + 0x20)) + 0x18))
 21e:	d8410028 	ld.b	r2, (r1, 0x28)	// regs: r2=*((*((*(0x0 + ((((0x48 * <arg0>) + zext8((*((((0x120 * <arg0>) ) + 0x1c4)) - 0x1))) + 0x2e) << 2)) + 0x20)) + 0x28))
 222:	b847      	st.w	r2, (r14, 0x1c)	// local_14 = *((*((*(0x0 + ((((0x48 * <arg0>) + zext8((*((((0x120 * <arg0>) ) + 0x1c4)) - 0x1))) + 0x2e) << 2)) + 0x20)) + 0x28))
 224:	d8470310 	ld.b	r2, (r7, 0x310)	// regs: r2=*(0x310)
 228:	e4422010 	andi	r2, r2, 16	// regs: r2=(*(0x310) & 0x10)
 22c:	e902005b 	bez	r2, 0x2e2	// if (r2 == 0x0) goto loc_2e2;
 230:	9143      	ld.w	r2, (r1, 0xc)	// regs: r2=*((*((*(0x0 + ((((0x48 * <arg0>) + zext8((*((((0x120 * <arg0>) ) + 0x1c4)) - 0x1))) + 0x2e) << 2)) + 0x20)) + 0xc))
 232:	e9020006 	bez	r2, 0x23e	// if (r2 == 0x0) goto loc_23e;
 236:	d84210eb 	ld.h	r2, (r2, 0x1d6)	// regs: r2=*((*((*((*(0x0 + ((((0x48 * <arg0>) + zext8((*((((0x120 * <arg0>) ) + 0x1c4)) - 0x1))) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d6))
 23a:	e9220050 	bnez	r2, 0x2da	// if (r2 != 0x0) goto loc_2da;
loc_23e:
 23e:	eb490007 	cmpnei	r9, 7
 242:	084e      	bt	0x2de	// if (r9 != 0x7) goto loc_2de;
 244:	e44a0000 	addi	r2, r10, 1	// regs: r2=(<arg1> + 0x1)
 248:	e4422003 	andi	r2, r2, 3	// regs: r2=((<arg1> + 0x1) & 0x3)
 24c:	d8270308 	ld.b	r1, (r7, 0x308)	// regs: r1=*(0x308)
 250:	644a      	cmpne	r2, r1
 252:	0846      	bt	0x2de	// if (T) goto loc_2de;
 254:	d8270315 	ld.b	r1, (r7, 0x315)	// regs: r1=*(0x315)
 258:	6c87      	mov	r2, r1	// regs: r2=*(0x315)
 25a:	7444      	zextb	r1, r1	// regs: r1=zext8(*(0x315))
 25c:	eb010020 	cmphsi	r1, 33
 260:	0c02      	bf	0x264	// if (r1 < 0x21) goto loc_264;
 262:	3220      	movi	r2, 32	// regs: r2=0x20
loc_264:
 264:	7488      	zextb	r2, r2	// regs: r2=zext8(r2)
loc_266:
 266:	ea0b0090 	movi	r11, 144	// regs: r11=0x90
 26a:	c42b482b 	lsli	r11, r11, 1	// regs: r11=0x120
 26e:	7457      	sexth	r1, r5	// regs: r1=sext16(<arg0>)
 270:	7ed4      	mult	r11, r5	// regs: r11=(0x120 * <arg0>)
 272:	c4210028 	addu	r8, r1, r1	// regs: r8=(sext16(<arg0>) + sext16(<arg0>))
 276:	62d0      	addu	r11, r4	// regs: r11=((0x120 * <arg0>) )
 278:	6204      	addu	r8, r1	// regs: r8=((sext16(<arg0>) + sext16(<arg0>)) + sext16(<arg0>))
 27a:	e42b01c1 	addi	r1, r11, 450	// regs: r1=(((0x120 * <arg0>) ) + 0x1c2)
 27e:	c4484828 	lsli	r8, r8, 2	// regs: r8=(((sext16(<arg0>) + sext16(<arg0>)) + sext16(<arg0>)) << 0x2)
 282:	b826      	st.w	r1, (r14, 0x18)	// local_18 = (((0x120 * <arg0>) ) + 0x1c2)
 284:	3148      	movi	r1, 72	// regs: r1=0x48
 286:	e5080087 	addi	r8, r8, 136	// regs: r8=((((sext16(<arg0>) + sext16(<arg0>)) + sext16(<arg0>)) << 0x2) + 0x88)
 28a:	7c54      	mult	r1, r5	// regs: r1=(0x48 * <arg0>)
 28c:	6210      	addu	r8, r4	// regs: r8=(((((sext16(<arg0>) + sext16(<arg0>)) + sext16(<arg0>)) << 0x2) + 0x88) )
 28e:	b828      	st.w	r1, (r14, 0x20)	// local_10 = (0x48 * <arg0>)
 290:	e90d002c 	bez	r13, 0x2e8	// if (r13 == 0x0) goto loc_2e8;
loc_294:
 294:	3390      	movi	r3, 144	// regs: r3=0x90
 296:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
 298:	7cd4      	mult	r3, r5	// regs: r3=(0x120 * r5)
 29a:	60d0      	addu	r3, r4	// regs: r3=((0x120 * r5) + r4)
 29c:	d84301c4 	ld.b	r2, (r3, 0x1c4)	// regs: r2=*((((0x120 * r5) + r4) + 0x1c4))
 2a0:	d8670315 	ld.b	r3, (r7, 0x315)	// regs: r3=*(r7 + 0x315)
 2a4:	64c8      	cmphs	r2, r3
 2a6:	0809      	bt	0x2b8	// if (T) goto loc_2b8;
 2a8:	eb4d0002 	cmpnei	r13, 2
 2ac:	088c      	bt	0x3c4	// if (r13 != 0x2) goto loc_3c4;
 2ae:	d86721ec 	ld.w	r3, (r7, 0x7b0)	// regs: r3=*(r7 + 0x7b0)
 2b2:	2300      	addi	r3, 1	// regs: r3=(*(r7 + 0x7b0) + 0x1)
 2b4:	dc6721ec 	st.w	r3, (r7, 0x7b0)	// *(r7 + 0x7b0) = (*(r7 + 0x7b0) + 0x1)
loc_2b8:
 2b8:	3390      	movi	r3, 144	// regs: r3=0x90
 2ba:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
 2bc:	7d4c      	mult	r5, r3	// regs: r5=(r5 * 0x120)
 2be:	6150      	addu	r5, r4	// regs: r5=((r5 * 0x120) + r4)
 2c0:	6ca7      	mov	r2, r9	// regs: r2=r9
 2c2:	d805206e 	ld.w	r0, (r5, 0x1b8)	// regs: r0=*((((r5 * 0x120) + r4) + 0x1b8))
 2c6:	6c6b      	mov	r1, r10	// regs: r1=r10
 2c8:	2003      	addi	r0, 4	// regs: r0=(*((((r5 * 0x120) + r4) + 0x1b8)) + 0x4)
 2ca:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0x2ca>, r1=<clobbered>
 2ce:	d865202e 	ld.w	r3, (r5, 0xb8)	// regs: r3=*((((r5 * 0x120) + r4) + 0xb8))
 2d2:	dc05206f 	st.w	r0, (r5, 0x1bc)	// *((((r5 * 0x120) + r4) + 0x1bc)) = <ret calc_symbol_len@0x2ca>
 2d6:	9308      	ld.w	r0, (r3, 0x20)	// regs: r0=*((*((((r5 * 0x120) + r4) + 0xb8)) + 0x20))
 2d8:	06a1      	br	0x1a	// goto loc_1a;
loc_2da:
 2da:	3208      	movi	r2, 8	// regs: r2=0x8
 2dc:	07c5      	br	0x266	// goto loc_266;
loc_2de:
 2de:	3210      	movi	r2, 16	// regs: r2=0x10
 2e0:	07c3      	br	0x266	// goto loc_266;
loc_2e2:
 2e2:	d8470315 	ld.b	r2, (r7, 0x315)	// regs: r2=*(0x315)
 2e6:	07c0      	br	0x266	// goto loc_266;
loc_2e8:
 2e8:	6c23      	mov	r0, r8	// regs: r0=(((((sext16(<arg0>) + sext16(<arg0>)) + sext16(<arg0>)) << 0x2) + 0x88) )
 2ea:	b869      	st.w	r3, (r14, 0x24)	// local_c = r3
 2ec:	b84a      	st.w	r2, (r14, 0x28)	// local_8 = r2
 2ee:	e0000000 	bsr	0x0	// <skb_list_first>; regs: r0=<ret skb_list_first@0x2ee>, r1=<clobbered>
 2f2:	9869      	ld.w	r3, (r14, 0x24)	// regs: r3=local_c
 2f4:	b300      	st.w	r0, (r3, 0x0)	// *(local_c) = <ret skb_list_first@0x2ee>
 2f6:	e9000061 	bez	r0, 0x3b8	// if (r0 == 0x0) goto loc_3b8;
 2fa:	d9802008 	ld.w	r12, (r0, 0x20)	// regs: r12=*(<ret skb_list_first@0x2ee> + 0x20)
 2fe:	9866      	ld.w	r3, (r14, 0x18)	// regs: r3=local_18
 300:	d80c100c 	ld.h	r0, (r12, 0x18)	// regs: r0=*((*(<ret skb_list_first@0x2ee> + 0x20) + 0x18))
 304:	8b60      	ld.h	r3, (r3, 0x0)	// regs: r3=*(local_18)
 306:	640c      	cmphs	r3, r0
 308:	085b      	bt	0x3be	// if (T) goto loc_3be;
 30a:	d82b01c4 	ld.b	r1, (r11, 0x1c4)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1c4))
 30e:	984a      	ld.w	r2, (r14, 0x28)	// regs: r2=local_8
 310:	6484      	cmphs	r1, r2
 312:	0856      	bt	0x3be	// if (T) goto loc_3be;
 314:	d82b10e0 	ld.h	r1, (r11, 0x1c0)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1c0))
 318:	5825      	subu	r1, r0, r1	// regs: r1=(*((*(<ret skb_list_first@0x2ee> + 0x20) + 0x18)) - *((((0x120 * <arg0>) ) + 0x1c0)))
 31a:	eb21003e 	cmplti	r1, 63
 31e:	0c50      	bf	0x3be	// if (r1 >= 0x3f) goto loc_3be;
 320:	d9ab206e 	ld.w	r13, (r11, 0x1b8)	// regs: r13=*((((0x120 * <arg0>) ) + 0x1b8))
 324:	d82c500b 	ld.hs	r1, (r12, 0x16)	// regs: r1=*((*(<ret skb_list_first@0x2ee> + 0x20) + 0x16))
 328:	6074      	addu	r1, r13	// regs: r1=(*((*(<ret skb_list_first@0x2ee> + 0x20) + 0x16)) + *((((0x120 * <arg0>) ) + 0x1b8)))
 32a:	d9ae2005 	ld.w	r13, (r14, 0x14)	// regs: r13=local_1c
 32e:	6474      	cmphs	r13, r1
 330:	0c47      	bf	0x3be	// if (!T) goto loc_3be;
 332:	d8270310 	ld.b	r1, (r7, 0x310)	// regs: r1=*(0x310)
 336:	e5a12010 	andi	r13, r1, 16	// regs: r13=(*(0x310) & 0x10)
 33a:	e90d0008 	bez	r13, 0x34a	// if (r13 == 0x0) goto loc_34a;
 33e:	d98c0028 	ld.b	r12, (r12, 0x28)	// regs: r12=*((*(<ret skb_list_first@0x2ee> + 0x20) + 0x28))
 342:	d9ae2007 	ld.w	r13, (r14, 0x1c)	// regs: r13=local_14
 346:	6772      	cmpne	r12, r13
 348:	083b      	bt	0x3be	// if (T) goto loc_3be;
loc_34a:
 34a:	e4212008 	andi	r1, r1, 8	// regs: r1=(*(0x310) & 0x8)
 34e:	e9010005 	bez	r1, 0x358	// if (r1 == 0x0) goto loc_358;
 352:	2300      	addi	r3, 1	// regs: r3=(*(local_18) + 0x1)
 354:	64c2      	cmpne	r0, r3
 356:	0834      	bt	0x3be	// if (T) goto loc_3be;
loc_358:
 358:	6c23      	mov	r0, r8	// regs: r0=(((((sext16(<arg0>) + sext16(<arg0>)) + sext16(<arg0>)) << 0x2) + 0x88) )
 35a:	b849      	st.w	r2, (r14, 0x24)	// local_c = local_8
 35c:	e0000000 	bsr	0x0	// <skb_list_dequeue>; regs: r0=<ret skb_list_dequeue@0x35c>, r1=<clobbered>
 360:	9848      	ld.w	r2, (r14, 0x20)	// regs: r2=local_10
 362:	5a38      	addu	r1, r2, r6	// regs: r1=(local_10 + r6)
 364:	6cc3      	mov	r3, r0	// regs: r3=<ret skb_list_dequeue@0x35c>
 366:	212d      	addi	r1, 46	// regs: r1=((local_10 + r6) + 0x2e)
 368:	9008      	ld.w	r0, (r0, 0x20)	// regs: r0=*(<ret skb_list_dequeue@0x35c> + 0x20)
 36a:	d4240883 	str.w	r3, (r4, r1 << 2)
 36e:	d82b01c4 	ld.b	r1, (r11, 0x1c4)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1c4))
 372:	2100      	addi	r1, 1	// regs: r1=(*((((0x120 * <arg0>) ) + 0x1c4)) + 0x1)
 374:	dc2b01c4 	st.b	r1, (r11, 0x1c4)	// *((((0x120 * <arg0>) ) + 0x1c4)) = (*((((0x120 * <arg0>) ) + 0x1c4)) + 0x1)
 378:	d82b01c5 	ld.b	r1, (r11, 0x1c5)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1c5))
 37c:	2100      	addi	r1, 1	// regs: r1=(*((((0x120 * <arg0>) ) + 0x1c5)) + 0x1)
 37e:	d980500b 	ld.hs	r12, (r0, 0x16)	// regs: r12=*((*(<ret skb_list_dequeue@0x35c> + 0x20) + 0x16))
 382:	dc2b01c5 	st.b	r1, (r11, 0x1c5)	// *((((0x120 * <arg0>) ) + 0x1c5)) = (*((((0x120 * <arg0>) ) + 0x1c5)) + 0x1)
 386:	d82b206e 	ld.w	r1, (r11, 0x1b8)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1b8))
 38a:	6070      	addu	r1, r12	// regs: r1=(*((((0x120 * <arg0>) ) + 0x1b8)) + *((*(<ret skb_list_dequeue@0x35c> + 0x20) + 0x16)))
 38c:	9846      	ld.w	r2, (r14, 0x18)	// regs: r2=local_18
 38e:	2600      	addi	r6, 1	// regs: r6=(r6 + 0x1)
 390:	dc2b206e 	st.w	r1, (r11, 0x1b8)	// *((((0x120 * <arg0>) ) + 0x1b8)) = (*((((0x120 * <arg0>) ) + 0x1b8)) + *((*(<ret skb_list_dequeue@0x35c> + 0x20) + 0x16)))
 394:	882c      	ld.h	r1, (r0, 0x18)	// regs: r1=*((*(<ret skb_list_dequeue@0x35c> + 0x20) + 0x18))
 396:	aa20      	st.h	r1, (r2, 0x0)	// *(local_18) = *((*(<ret skb_list_dequeue@0x35c> + 0x20) + 0x18))
 398:	7598      	zextb	r6, r6	// regs: r6=zext8((r6 + 0x1))
 39a:	9849      	ld.w	r2, (r14, 0x24)	// regs: r2=local_c
 39c:	07a6      	br	0x2e8	// goto loc_2e8;
 39e:	0000      	.short	0x0000
 3a0:	00000000 	.long	0x00000000	// <.rodata.lmac_gen_tx_agglist.str1.1>
 3a4:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
 3a6:	0000      	.short	0x0000
 3a8:	00000000 	.long	0x00000000	// <ah_lmac>
 3ac:	00000000 	.long	0x00000000	// <.rodata.lmac_gen_tx_agglist.str1.1+0x15>
 3b0:	00000000 	.long	0x00000000	// <.rodata.__func__.13543>
 3b4:	00000000 	.long	0x00000000	// <.rodata.lmac_gen_tx_agglist.str1.1+0x19>
loc_3b8:
 3b8:	ea0d0002 	movi	r13, 2	// regs: r13=0x2
 3bc:	076c      	br	0x294	// goto loc_294;
loc_3be:
 3be:	ea0d0003 	movi	r13, 3	// regs: r13=0x3
 3c2:	0769      	br	0x294	// goto loc_294;
loc_3c4:
 3c4:	eb4d0003 	cmpnei	r13, 3
 3c8:	0b78      	bt	0x2b8	// if (r13 != 0x3) goto loc_2b8;
 3ca:	d86721ed 	ld.w	r3, (r7, 0x7b4)	// regs: r3=*(r7 + 0x7b4)
 3ce:	2300      	addi	r3, 1	// regs: r3=(*(r7 + 0x7b4) + 0x1)
 3d0:	dc6721ed 	st.w	r3, (r7, 0x7b4)	// *(r7 + 0x7b4) = (*(r7 + 0x7b4) + 0x1)
 3d4:	0772      	br	0x2b8	// goto loc_2b8;

Disassembly of section .text.lmac_tx_queue_init:

00000000 <lmac_tx_queue_init>: // arg_bytes: 0
   0:	14d4      	push	r4-r7, r15
   2:	1103      	lrw	r0, 0x0	// regs: r0=0x0
   4:	e0000000 	bsr	0x0	// <skb_list_init>; regs: r0=<ret skb_list_init@0x4>, r1=<clobbered>
   8:	e9000008 	bez	r0, 0x18	// if (r0 == 0x0) goto loc_18;
   c:	1141      	lrw	r2, 0x0	// regs: r2=0x0
   e:	ea011751 	movi	r1, 5969	// regs: r1=0x1751
  12:	1101      	lrw	r0, 0x0	// regs: r0=0x0
  14:	e0000000 	bsr	0x0	// <assert_internal>; regs: r0=<ret assert_internal@0x14>, r1=<clobbered>
loc_18:
  18:	1100      	lrw	r0, 0x0	// regs: r0=0x0
  1a:	e0000000 	bsr	0x0	// <skb_list_init>; regs: r0=<ret skb_list_init@0x1a>, r1=<clobbered>
  1e:	e9000008 	bez	r0, 0x2e	// if (r0 == 0x0) goto loc_2e;
  22:	105c      	lrw	r2, 0x0	// regs: r2=0x0
  24:	ea011757 	movi	r1, 5975	// regs: r1=0x1757
  28:	101b      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	e0000000 	bsr	0x0	// <assert_internal>; regs: r0=<ret assert_internal@0x2a>, r1=<clobbered>
loc_2e:
  2e:	101c      	lrw	r0, 0x0	// regs: r0=0x0
  30:	e0000000 	bsr	0x0	// <skb_list_init>; regs: r0=<ret skb_list_init@0x30>, r1=<clobbered>
  34:	e9000008 	bez	r0, 0x44	// if (r0 == 0x0) goto loc_44;
  38:	1056      	lrw	r2, 0x0	// regs: r2=0x0
  3a:	ea011759 	movi	r1, 5977	// regs: r1=0x1759
  3e:	1016      	lrw	r0, 0x0	// regs: r0=0x0
  40:	e0000000 	bsr	0x0	// <assert_internal>; regs: r0=<ret assert_internal@0x40>, r1=<clobbered>
loc_44:
  44:	3400      	movi	r4, 0	// regs: r4=0x0
  46:	10b7      	lrw	r5, 0x0	// regs: r5=0x0
  48:	10d2      	lrw	r6, 0x0	// regs: r6=0x0
  4a:	10f3      	lrw	r7, 0x0	// regs: r7=0x0
loc_4c:
  4c:	e4040087 	addi	r0, r4, 136	// regs: r0=(r4 + 0x88)
  50:	6014      	addu	r0, r5	// regs: r0=((r4 + 0x88) )
  52:	e0000000 	bsr	0x0	// <skb_list_init>; regs: r0=<ret skb_list_init@0x52>, r1=<clobbered>
  56:	e9000008 	bez	r0, 0x66	// if (r0 == 0x0) goto loc_66;
  5a:	6c9b      	mov	r2, r6	// regs: r2=0x0
  5c:	ea01175c 	movi	r1, 5980	// regs: r1=0x175c
  60:	6c1f      	mov	r0, r7	// regs: r0=0x0
  62:	e0000000 	bsr	0x0	// <assert_internal>; regs: r0=<ret assert_internal@0x62>, r1=<clobbered>
loc_66:
  66:	240b      	addi	r4, 12	// regs: r4=(r4 + 0xc)
  68:	eb440030 	cmpnei	r4, 48
  6c:	0bf0      	bt	0x4c	// if (r4 != 0x30) goto loc_4c;
  6e:	100e      	lrw	r0, 0x0	// regs: r0=0x0
  70:	e0000000 	bsr	0x0	// <skb_list_init>; regs: r0=<ret skb_list_init@0x70>, r1=<clobbered>
  74:	6d03      	mov	r4, r0	// regs: r4=<ret skb_list_init@0x70>
  76:	e9000008 	bez	r0, 0x86	// if (r0 == 0x0) goto loc_86;
  7a:	1046      	lrw	r2, 0x0	// regs: r2=0x0
  7c:	ea01175f 	movi	r1, 5983	// regs: r1=0x175f
  80:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  82:	e0000000 	bsr	0x0	// <assert_internal>; regs: r0=<ret assert_internal@0x82>, r1=<clobbered>
loc_86:
  86:	6c13      	mov	r0, r4	// regs: r0=<ret skb_list_init@0x70>
  88:	1494      	pop	r4-r7, r15
  8a:	0000      	.short	0x0000
  8c:	0000      	.short	0x0000	// <.bss.ah_lmac_tx+0x64>
  8e:	0000      	.short	0x0000
  90:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_queue_init.str1.1>
  94:	00000000 	.long	0x00000000	// <.rodata.__func__.14327>
  98:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x70>
  9c:	0000      	.short	0x0000	// <.bss.ah_lmac_tx+0x7c>
  9e:	0000      	.short	0x0000
  a0:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  a4:	0000      	.short	0x0000	// <.bss.ah_lmac_tx+0x538>
  a6:	0000      	.short	0x0000

Disassembly of section .text.lmac_tx_status_task:

00000000 <lmac_tx_status_task>: // arg_bytes: 0
   0:	14d4      	push	r4-r7, r15
   2:	1198      	lrw	r4, 0x0	// regs: r4=0x0
loc_4:
   4:	11b8      	lrw	r5, 0x0	// regs: r5=0x0
   6:	8560      	ld.b	r3, (r5, 0x0)	// regs: r3=*(0x0)
   8:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x0) & 0x1)
   c:	e9030007 	bez	r3, 0x1a	// if (r3 == 0x0) goto loc_1a;
  10:	1136      	lrw	r1, 0x0	// regs: r1=0x0
  12:	1117      	lrw	r0, 0x0	// regs: r0=0x0
  14:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x14>, r1=<clobbered>
  18:	1494      	pop	r4-r7, r15
loc_1a:
  1a:	3100      	movi	r1, 0	// regs: r1=0x0
  1c:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  1e:	e405005b 	addi	r0, r5, 92	// regs: r0=0x5c
  22:	e0000000 	bsr	0x0	// <os_sema_down>; regs: r0=<ret os_sema_down@0x22>, r1=<clobbered>
  26:	e4050537 	addi	r0, r5, 1336	// regs: r0=0x538
  2a:	e0000000 	bsr	0x0	// <skb_list_dequeue>; regs: r0=<ret skb_list_dequeue@0x2a>, r1=<clobbered>
  2e:	6d43      	mov	r5, r0	// regs: r5=<ret skb_list_dequeue@0x2a>
  30:	11d0      	lrw	r6, 0x0	// regs: r6=0x0
loc_32:
  32:	e905ffe9 	bez	r5, 0x4	// if (r5 == 0x0) goto loc_4;
  36:	d8640a4f 	ld.b	r3, (r4, 0xa4f)	// regs: r3=*(0xa4f)
  3a:	3200      	movi	r2, 0	// regs: r2=0x0
  3c:	c4625c00 	ins	r3, r2, 0, 0
  40:	95e8      	ld.w	r7, (r5, 0x20)	// regs: r7=*(r5 + 0x20)
  42:	dc640a4f 	st.b	r3, (r4, 0xa4f)	// *(0xa4f) = *(0xa4f)
  46:	d864153c 	ld.h	r3, (r4, 0xa78)	// regs: r3=*(0xa78)
  4a:	2b00      	subi	r3, 1	// regs: r3=(*(0xa78) - 0x1)
  4c:	dc64153c 	st.h	r3, (r4, 0xa78)	// *(0xa78) = (*(0xa78) - 0x1)
  50:	956f      	ld.w	r3, (r5, 0x3c)	// regs: r3=*(r5 + 0x3c)
  52:	3b01      	cmphsi	r3, 2
  54:	0c06      	bf	0x60	// if (r3 < 0x2) goto loc_60;
  56:	d864153d 	ld.h	r3, (r4, 0xa7a)	// regs: r3=*(0xa7a)
  5a:	2300      	addi	r3, 1	// regs: r3=(*(0xa7a) + 0x1)
  5c:	dc64153d 	st.h	r3, (r4, 0xa7a)	// *(0xa7a) = (*(0xa7a) + 0x1)
loc_60:
  60:	9703      	ld.w	r0, (r7, 0xc)	// regs: r0=*((*(r5 + 0x20) + 0xc))
  62:	e0000000 	bsr	0x0	// <lmac_sta_put>; regs: r0=<ret lmac_sta_put@0x62>, r1=<clobbered>
  66:	d8670027 	ld.b	r3, (r7, 0x27)	// regs: r3=*((*(r5 + 0x20) + 0x27))
  6a:	e4632002 	andi	r3, r3, 2	// regs: r3=(*((*(r5 + 0x20) + 0x27)) & 0x2)
  6e:	e9030011 	bez	r3, 0x90	// if (r3 == 0x0) goto loc_90;
  72:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x72>, r1=<clobbered>
  76:	956b      	ld.w	r3, (r5, 0x2c)	// regs: r3=*(r5 + 0x2c)
  78:	600e      	subu	r0, r3	// regs: r0=(<ret os_jiffies@0x72> - *(r5 + 0x2c))
  7a:	d86421d9 	ld.w	r3, (r4, 0x764)	// regs: r3=*(0x764)
  7e:	60c0      	addu	r3, r0	// regs: r3=(*(0x764) + (<ret os_jiffies@0x72> - *(r5 + 0x2c)))
  80:	dc6421d9 	st.w	r3, (r4, 0x764)	// *(0x764) = (*(0x764) + (<ret os_jiffies@0x72> - *(r5 + 0x2c)))
  84:	d86421d8 	ld.w	r3, (r4, 0x760)	// regs: r3=*(0x760)
  88:	640d      	cmplt	r3, r0
  8a:	0c03      	bf	0x90	// if (!T) goto loc_90;
  8c:	dc0421d8 	st.w	r0, (r4, 0x760)	// *(0x760) = (<ret os_jiffies@0x72> - *(r5 + 0x2c))
loc_90:
  90:	d865002a 	ld.b	r3, (r5, 0x2a)	// regs: r3=*(r5 + 0x2a)
  94:	e4632040 	andi	r3, r3, 64	// regs: r3=(*(r5 + 0x2a) & 0x40)
  98:	e903001f 	bez	r3, 0xd6	// if (r3 == 0x0) goto loc_d6;
  9c:	d8642295 	ld.w	r3, (r4, 0xa54)	// regs: r3=*(0xa54)
  a0:	64d6      	cmpne	r5, r3
  a2:	0816      	bt	0xce	// if (T) goto loc_ce;
  a4:	d86420ee 	ld.w	r3, (r4, 0x3b8)	// regs: r3=*(0x3b8)
  a8:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x3b8) & 0x8)
  ac:	e9030005 	bez	r3, 0xb6	// if (r3 == 0x0) goto loc_b6;
  b0:	1011      	lrw	r0, 0x0	// regs: r0=0x0
  b2:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xb2>, r1=<clobbered>
loc_b6:
  b6:	d8640a4f 	ld.b	r3, (r4, 0xa4f)	// regs: r3=*(0xa4f)
  ba:	3200      	movi	r2, 0	// regs: r2=0x0
  bc:	c4625c04 	ins	r3, r2, 4, 4
  c0:	dc640a4f 	st.b	r3, (r4, 0xa4f)	// *(0xa4f) = *(0xa4f)
loc_c4:
  c4:	100d      	lrw	r0, 0x0	// regs: r0=0x0
  c6:	e0000000 	bsr	0x0	// <skb_list_dequeue>; regs: r0=<ret skb_list_dequeue@0xc6>, r1=<clobbered>
  ca:	6d43      	mov	r5, r0	// regs: r5=<ret skb_list_dequeue@0xc6>
  cc:	07b3      	br	0x32	// goto loc_32;
loc_ce:
  ce:	6c17      	mov	r0, r5	// regs: r0=r5
  d0:	e0000000 	bsr	0x0	// <kfree_skb>; regs: r0=<ret kfree_skb@0xd0>, r1=<clobbered>
  d4:	07f8      	br	0xc4	// goto loc_c4;
loc_d6:
  d6:	6c57      	mov	r1, r5	// regs: r1=r5
  d8:	9667      	ld.w	r3, (r6, 0x1c)	// regs: r3=*(0x1c)
  da:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  dc:	7bcd      	jsr	r3
  de:	07f3      	br	0xc4	// goto loc_c4;
  e0:	0000      	.short	0x0000	// <ah_lmac>
  e2:	0000      	.short	0x0000
  e4:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  e6:	0000      	.short	0x0000
  e8:	00000000 	.long	0x00000000	// <.rodata.__func__.13742>
  ec:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_status_task.str1.1+0xe>
  f0:	0000      	.short	0x0000	// <ah_ops>
  f2:	0000      	.short	0x0000
  f4:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_status_task.str1.1>
  f8:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x538>

Disassembly of section .text.tx_pwr_adjust_by_mcs:

00000000 <tx_pwr_adjust_by_mcs>: // arg_bytes: 8
   0:	106b      	lrw	r3, 0x0	// regs: r3=0x0
   2:	d863036d 	ld.b	r3, (r3, 0x36d)	// regs: r3=*(0x36d)
   6:	e463200c 	andi	r3, r3, 12	// regs: r3=(*(0x36d) & 0xc)
   a:	e903000e 	bez	r3, 0x26	// if (r3 == 0x0) goto loc_26;
   e:	3845      	cmpnei	r0, 5
  10:	080b      	bt	0x26	// if (r0 != 0x5) goto loc_26;
  12:	394a      	cmpnei	r1, 10
  14:	0c0a      	bf	0x28	// if (r1 == 0xa) goto loc_28;
  16:	3902      	cmphsi	r1, 3
  18:	0c08      	bf	0x28	// if (r1 < 0x3) goto loc_28;
  1a:	2902      	subi	r1, 3	// regs: r1=(<arg1> - 0x3)
  1c:	7444      	zextb	r1, r1	// regs: r1=zext8((<arg1> - 0x3))
  1e:	3901      	cmphsi	r1, 2
  20:	3301      	movi	r3, 1	// regs: r3=0x1
  22:	c4030c20 	incf	r0, r3, 0
loc_26:
  26:	783c      	jmp	r15	// return;
loc_28:
  28:	3000      	movi	r0, 0	// regs: r0=0x0
  2a:	07fe      	br	0x26	// goto loc_26;
  2c:	0000      	.short	0x0000	// <ah_lmac>
  2e:	0000      	.short	0x0000

Disassembly of section .text.seq_num_space_update:

00000000 <seq_num_space_update>: // arg_bytes: 4
   0:	6cc3      	mov	r3, r0	// regs: r3=<arg0>
   2:	e9200010 	bnez	r0, 0x22	// if (r0 != 0x0) goto loc_22;
   6:	102d      	lrw	r1, 0x0	// regs: r1=0x0
   8:	d84121b3 	ld.w	r2, (r1, 0x6cc)	// regs: r2=*(0x6cc)
   c:	7409      	zexth	r0, r2	// regs: r0=zext16(*(0x6cc))
   e:	2200      	addi	r2, 1	// regs: r2=(*(0x6cc) + 0x1)
  10:	e4422fff 	andi	r2, r2, 4095	// regs: r2=((*(0x6cc) + 0x1) & 0xfff)
  14:	eb420fff 	cmpnei	r2, 4095
  18:	c4620c40 	inct	r3, r2, 0
  1c:	dc6121b3 	st.w	r3, (r1, 0x6cc)	// *(0x6cc) = <arg0>
loc_20:
  20:	783c      	jmp	r15	// return;
loc_22:
  22:	4124      	lsli	r1, r1, 4	// regs: r1=(<arg1> << 0x4)
  24:	60c4      	addu	r3, r1	// regs: r3=(<arg0> + (<arg1> << 0x4))
  26:	d80310a9 	ld.h	r0, (r3, 0x152)	// regs: r0=*(((<arg0> + (<arg1> << 0x4)) + 0x152))
  2a:	5842      	addi	r2, r0, 1	// regs: r2=(*(((<arg0> + (<arg1> << 0x4)) + 0x152)) + 0x1)
  2c:	e4422fff 	andi	r2, r2, 4095	// regs: r2=((*(((<arg0> + (<arg1> << 0x4)) + 0x152)) + 0x1) & 0xfff)
  30:	dc4310a9 	st.h	r2, (r3, 0x152)	// *(((<arg0> + (<arg1> << 0x4)) + 0x152)) = ((*(((<arg0> + (<arg1> << 0x4)) + 0x152)) + 0x1) & 0xfff)
  34:	07f6      	br	0x20	// goto loc_20;
  36:	0000      	.short	0x0000
  38:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  3a:	0000      	.short	0x0000

Disassembly of section .text.lmac_qa_freq_hopping:

00000000 <lmac_qa_freq_hopping>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	1423      	subi	r14, r14, 12	// regs: r14=(sp - 0xc)
   4:	1191      	lrw	r4, 0x0	// regs: r4=0x0
   6:	11b2      	lrw	r5, 0x0	// regs: r5=0x0
   8:	d8240378 	ld.b	r1, (r4, 0x378)	// regs: r1=*(0x378)
   c:	8540      	ld.b	r2, (r5, 0x0)	// regs: r2=*(0x0)
   e:	4162      	lsli	r3, r1, 2	// regs: r3=(*(0x378) << 0x2)
  10:	2200      	addi	r2, 1	// regs: r2=(*(0x0) + 0x1)
  12:	60c4      	addu	r3, r1	// regs: r3=((*(0x378) << 0x2) + *(0x378))
  14:	7488      	zextb	r2, r2	// regs: r2=zext8((*(0x0) + 0x1))
  16:	60cc      	addu	r3, r3	// regs: r3=(((*(0x378) << 0x2) + *(0x378)) + ((*(0x378) << 0x2) + *(0x378)))
  18:	64c9      	cmplt	r2, r3
  1a:	a540      	st.b	r2, (r5, 0x0)	// *(0x0) = zext8((*(0x0) + 0x1))
  1c:	0803      	bt	0x22	// if (T) goto loc_22;
  1e:	3300      	movi	r3, 0	// regs: r3=0x0
  20:	a560      	st.b	r3, (r5, 0x0)	// *(0x0) = 0x0
loc_22:
  22:	330a      	movi	r3, 10	// regs: r3=0xa
  24:	8500      	ld.b	r0, (r5, 0x0)	// regs: r0=*(0x0)
  26:	c4608020 	divu	r0, r0, r3	// regs: r0=(*(0x0) / 0xa)
  2a:	e0000000 	bsr	0x0	// <lmac_lo_table_kick>; regs: r0=<ret lmac_lo_table_kick@0x2a>, r1=<clobbered>
  2e:	d8640892 	ld.b	r3, (r4, 0x892)	// regs: r3=*(0x892)
  32:	3201      	movi	r2, 1	// regs: r2=0x1
  34:	c4625c01 	ins	r3, r2, 1, 1
  38:	dc640892 	st.b	r3, (r4, 0x892)	// *(0x892) = *(0x892)
  3c:	d844033c 	ld.b	r2, (r4, 0x33c)	// regs: r2=*(0x33c)
  40:	3364      	movi	r3, 100	// regs: r3=0x64
  42:	dc6408be 	st.b	r3, (r4, 0x8be)	// *(0x8be) = 0x64
  46:	4262      	lsli	r3, r2, 2	// regs: r3=(*(0x33c) << 0x2)
  48:	60c8      	addu	r3, r2	// regs: r3=((*(0x33c) << 0x2) + *(0x33c))
  4a:	8520      	ld.b	r1, (r5, 0x0)	// regs: r1=*(0x0)
  4c:	60cc      	addu	r3, r3	// regs: r3=(((*(0x33c) << 0x2) + *(0x33c)) + ((*(0x33c) << 0x2) + *(0x33c)))
  4e:	64c6      	cmpne	r1, r3
  50:	0837      	bt	0xbe	// if (T) goto loc_be;
  52:	3000      	movi	r0, 0	// regs: r0=0x0
  54:	e0000000 	bsr	0x0	// <disable_print>; regs: r0=<ret disable_print@0x54>, r1=<clobbered>
  58:	d80408c7 	ld.b	r0, (r4, 0x8c7)	// regs: r0=*(0x8c7)
  5c:	b802      	st.w	r0, (r14, 0x8)	// local_4 = *(0x8c7)
  5e:	d80408c6 	ld.b	r0, (r4, 0x8c6)	// regs: r0=*(0x8c6)
  62:	b801      	st.w	r0, (r14, 0x4)	// local_8 = *(0x8c6)
  64:	d80408c5 	ld.b	r0, (r4, 0x8c5)	// regs: r0=*(0x8c5)
  68:	d86408c4 	ld.b	r3, (r4, 0x8c4)	// regs: r3=*(0x8c4)
  6c:	d84408c3 	ld.b	r2, (r4, 0x8c3)	// regs: r2=*(0x8c3)
  70:	b800      	st.w	r0, (r14, 0x0)	// local_c = *(0x8c5)
  72:	d82408c2 	ld.b	r1, (r4, 0x8c2)	// regs: r1=*(0x8c2)
  76:	1017      	lrw	r0, 0x0	// regs: r0=0x0
  78:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x78>, r1=<clobbered>
  7c:	d84408c3 	ld.b	r2, (r4, 0x8c3)	// regs: r2=*(0x8c3)
  80:	d86408c2 	ld.b	r3, (r4, 0x8c2)	// regs: r3=*(0x8c2)
  84:	6cc8      	or	r3, r2	// regs: r3=(*(0x8c2) | *(0x8c3))
  86:	d84408c4 	ld.b	r2, (r4, 0x8c4)	// regs: r2=*(0x8c4)
  8a:	6cc8      	or	r3, r2	// regs: r3=((*(0x8c2) | *(0x8c3)) | *(0x8c4))
  8c:	d84408c5 	ld.b	r2, (r4, 0x8c5)	// regs: r2=*(0x8c5)
  90:	6cc8      	or	r3, r2	// regs: r3=(((*(0x8c2) | *(0x8c3)) | *(0x8c4)) | *(0x8c5))
  92:	d84408c6 	ld.b	r2, (r4, 0x8c6)	// regs: r2=*(0x8c6)
  96:	6cc8      	or	r3, r2	// regs: r3=((((*(0x8c2) | *(0x8c3)) | *(0x8c4)) | *(0x8c5)) | *(0x8c6))
  98:	d84408c7 	ld.b	r2, (r4, 0x8c7)	// regs: r2=*(0x8c7)
  9c:	6cc8      	or	r3, r2	// regs: r3=(((((*(0x8c2) | *(0x8c3)) | *(0x8c4)) | *(0x8c5)) | *(0x8c6)) | *(0x8c7))
  9e:	e9030012 	bez	r3, 0xc2	// if (r3 == 0x0) goto loc_c2;
  a2:	3300      	movi	r3, 0	// regs: r3=0x0
  a4:	d8440892 	ld.b	r2, (r4, 0x892)	// regs: r2=*(0x892)
  a8:	c4435c01 	ins	r2, r3, 1, 1
  ac:	dc440892 	st.b	r2, (r4, 0x892)	// *(0x892) = *(0x892)
  b0:	dc640890 	st.b	r3, (r4, 0x890)	// *(0x890) = 0x0
  b4:	dc640891 	st.b	r3, (r4, 0x891)	// *(0x891) = 0x0
  b8:	1007      	lrw	r0, 0x0	// regs: r0=0x0
loc_ba:
  ba:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xba>, r1=<clobbered>
loc_be:
  be:	1403      	addi	r14, r14, 12	// regs: r14=((sp - 0xc) + 0xc)
  c0:	1492      	pop	r4-r5, r15
loc_c2:
  c2:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  c4:	07fb      	br	0xba	// goto loc_ba;
  c6:	0000      	.short	0x0000
  c8:	00000000 	.long	0x00000000	// <ah_lmac>
  cc:	00000000 	.long	0x00000000	// <.bss.freq_idx.14185>
  d0:	00000000 	.long	0x00000000	// <.rodata.lmac_qa_freq_hopping.str1.1>
  d4:	0000      	.short	0x0000	// <.rodata.lmac_qa_freq_hopping.str1.1+0x29>
  d6:	0000      	.short	0x0000
  d8:	00000000 	.long	0x00000000	// <.rodata.lmac_qa_freq_hopping.str1.1+0x38>

Disassembly of section .text.lmac_cfg_tx_ce_para.isra.5.constprop.21:

00000000 <lmac_cfg_tx_ce_para.isra.5.constprop.21>: // arg_bytes: 4
   0:	14d3      	push	r4-r6, r15
   2:	d8604026 	ld.bs	r3, (r0, 0x26)	// regs: r3=*(<arg0> + 0x26)
   6:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   8:	e9a30011 	bhsz	r3, 0x2a	// if (r3 >= 0x0) goto loc_2a;
   c:	11ab      	lrw	r5, 0x0	// regs: r5=0x0
   e:	d8250693 	ld.b	r1, (r5, 0x693)	// regs: r1=*(0x693)
  12:	e4a50693 	addi	r5, r5, 1684	// regs: r5=0x694
loc_16:
  16:	3950      	cmpnei	r1, 16
  18:	1189      	lrw	r4, 0x0	// regs: r4=0x0
  1a:	0c0d      	bf	0x34	// if (r1 == 0x10) goto loc_34;
  1c:	eb410020 	cmpnei	r1, 32
  20:	0c44      	bf	0xa8	// if (r1 == 0x20) goto loc_a8;
  22:	1108      	lrw	r0, 0x0	// regs: r0=0x0
  24:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x24>, r1=<clobbered>
  28:	0409      	br	0x3a	// goto loc_3a;
loc_2a:
  2a:	90a3      	ld.w	r5, (r0, 0xc)	// regs: r5=*(<arg0> + 0xc)
  2c:	d8250076 	ld.b	r1, (r5, 0x76)	// regs: r1=*((*(<arg0> + 0xc) + 0x76))
  30:	2576      	addi	r5, 119	// regs: r5=(*(<arg0> + 0xc) + 0x77)
  32:	07f2      	br	0x16	// goto loc_16;
loc_34:
  34:	3300      	movi	r3, 0	// regs: r3=0x0
loc_36:
  36:	dc6406ac 	st.b	r3, (r4, 0x6ac)	// *(0x6ac) = r3
loc_3a:
  3a:	d864069a 	ld.b	r3, (r4, 0x69a)	// regs: r3=*(0x69a)
  3e:	c4035463 	zext	r3, r3, 3, 0	// regs: r3=zext(*(0x69a))
  42:	dc6406ad 	st.b	r3, (r4, 0x6ad)	// *(0x6ad) = zext(*(0x69a))
  46:	d864069a 	ld.b	r3, (r4, 0x69a)	// regs: r3=*(0x69a)
  4a:	c4835483 	zext	r3, r3, 4, 4	// regs: r3=zext(*(0x69a))
  4e:	dc6406ae 	st.b	r3, (r4, 0x6ae)	// *(0x6ae) = zext(*(0x69a))
  52:	d864069a 	ld.b	r3, (r4, 0x69a)	// regs: r3=*(0x69a)
  56:	c4a354a3 	zext	r3, r3, 5, 5	// regs: r3=zext(*(0x69a))
  5a:	dc6406af 	st.b	r3, (r4, 0x6af)	// *(0x6af) = zext(*(0x69a))
  5e:	107a      	lrw	r3, 0x0	// regs: r3=0x0
  60:	dc6421ac 	st.w	r3, (r4, 0x6b0)	// *(0x6b0) = 0x0
  64:	2305      	addi	r3, 6	// regs: r3=0x6
  66:	dc6421ad 	st.w	r3, (r4, 0x6b4)	// *(0x6b4) = 0x6
  6a:	d86406c8 	ld.b	r3, (r4, 0x6c8)	// regs: r3=*(0x6c8)
  6e:	dc6406bc 	st.b	r3, (r4, 0x6bc)	// *(0x6bc) = *(0x6c8)
  72:	d826002a 	ld.b	r1, (r6, 0x2a)	// regs: r1=*(<arg0> + 0x2a)
  76:	8e4a      	ld.h	r2, (r6, 0x14)	// regs: r2=*(<arg0> + 0x14)
  78:	6086      	subu	r2, r1	// regs: r2=(*(<arg0> + 0x14) - *(<arg0> + 0x2a))
  7a:	dc44135f 	st.h	r2, (r4, 0x6be)	// *(0x6be) = (*(<arg0> + 0x14) - *(<arg0> + 0x2a))
  7e:	d8460024 	ld.b	r2, (r6, 0x24)	// regs: r2=*(<arg0> + 0x24)
  82:	9664      	ld.w	r3, (r6, 0x10)	// regs: r3=*(<arg0> + 0x10)
  84:	e4422003 	andi	r2, r2, 3	// regs: r2=(*(<arg0> + 0x24) & 0x3)
  88:	60c4      	addu	r3, r1	// regs: r3=(*(<arg0> + 0x10) + *(<arg0> + 0x2a))
  8a:	dca421aa 	st.w	r5, (r4, 0x6a8)	// *(0x6a8) = r5
  8e:	dc6421b0 	st.w	r3, (r4, 0x6c0)	// *(0x6c0) = (*(<arg0> + 0x10) + *(<arg0> + 0x2a))
  92:	e902000d 	bez	r2, 0xac	// if (r2 == 0x0) goto loc_ac;
  96:	104d      	lrw	r2, 0x0	// regs: r2=0x0
  98:	dc4421ae 	st.w	r2, (r4, 0x6b8)	// *(0x6b8) = 0x0
loc_9c:
  9c:	dc6421b1 	st.w	r3, (r4, 0x6c4)	// *(0x6c4) = r3
  a0:	3300      	movi	r3, 0	// regs: r3=0x0
  a2:	dc6406bd 	st.b	r3, (r4, 0x6bd)	// *(0x6bd) = 0x0
  a6:	1493      	pop	r4-r6, r15
loc_a8:
  a8:	3302      	movi	r3, 2	// regs: r3=0x2
  aa:	07c6      	br	0x36	// goto loc_36;
loc_ac:
  ac:	1048      	lrw	r2, 0x0	// regs: r2=0x0
  ae:	dc4421ae 	st.w	r2, (r4, 0x6b8)	// *(0x6b8) = 0x0
  b2:	2307      	addi	r3, 8	// regs: r3=((*(<arg0> + 0x10) + *(<arg0> + 0x2a)) + 0x8)
  b4:	07f4      	br	0x9c	// goto loc_9c;
  b6:	0000      	.short	0x0000
  b8:	00000000 	.long	0x00000000	// <ah_lmac>
  bc:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  c0:	0000      	.short	0x0000	// <.rodata.lmac_cfg_tx_ce_para.isra.5.constprop.21.str1.1>
  c2:	0000      	.short	0x0000
  c4:	0000      	.short	0x0000	// <.bss.ah_lmac_tx+0x69b>
  c6:	0000      	.short	0x0000
  c8:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x67e>
  cc:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x660>

Disassembly of section .text.lmac_tx_pv1_data1:

00000000 <lmac_tx_pv1_data1>: // arg_bytes: 0
   0:	3000      	movi	r0, 0	// regs: r0=0x0
   2:	783c      	jmp	r15	// return;

Disassembly of section .text.lmac_tx_pv1_mgmt:

00000000 <lmac_tx_pv1_mgmt>: // arg_bytes: 0
   0:	3000      	movi	r0, 0	// regs: r0=0x0
   2:	783c      	jmp	r15	// return;

Disassembly of section .text.lmac_tx_pv0_s1g_beacon:

00000000 <lmac_tx_pv0_s1g_beacon>: // arg_bytes: 4
   0:	14d8      	push	r4-r11, r15
   2:	1424      	subi	r14, r14, 16	// regs: r14=(sp - 0x10)
   4:	90a7      	ld.w	r5, (r0, 0x1c)	// regs: r5=*(<arg0> + 0x1c)
   6:	9066      	ld.w	r3, (r0, 0x18)	// regs: r3=*(<arg0> + 0x18)
   8:	b860      	st.w	r3, (r14, 0x0)	// local_10 = *(<arg0> + 0x18)
   a:	8541      	ld.b	r2, (r5, 0x1)	// regs: r2=*((*(<arg0> + 0x1c) + 0x1))
   c:	0291      	lrw	r4, 0x0	// regs: r4=0x0
   e:	856e      	ld.b	r3, (r5, 0xe)	// regs: r3=*((*(<arg0> + 0x1c) + 0xe))
  10:	dc6403f0 	st.b	r3, (r4, 0x3f0)	// *(0x3f0) = *((*(<arg0> + 0x1c) + 0xe))
  14:	e4622001 	andi	r3, r2, 1	// regs: r3=(*((*(<arg0> + 0x1c) + 0x1)) & 0x1)
  18:	6dc3      	mov	r7, r0	// regs: r7=<arg0>
  1a:	e9230085 	bnez	r3, 0x124	// if (r3 != 0x0) goto loc_124;
  1e:	e505000e 	addi	r8, r5, 15	// regs: r8=(*(<arg0> + 0x1c) + 0xf)
loc_22:
  22:	e4222002 	andi	r1, r2, 2	// regs: r1=(*((*(<arg0> + 0x1c) + 0x1)) & 0x2)
  26:	3940      	cmpnei	r1, 0
  28:	e4422004 	andi	r2, r2, 4	// regs: r2=(*((*(<arg0> + 0x1c) + 0x1)) & 0x4)
  2c:	c5080c44 	inct	r8, r8, 4
  30:	3a40      	cmpnei	r2, 0
  32:	c5080c41 	inct	r8, r8, 1
  36:	c0006022 	mfcr	r2, cr<0, 0>
  3a:	c0807020 	psrclr	ie
  3e:	3107      	movi	r1, 7	// regs: r1=0x7
  40:	e4622040 	andi	r3, r2, 64	// regs: r3=((*((*(<arg0> + 0x1c) + 0x1)) & 0x4) & 0x40)
  44:	d84414ef 	ld.h	r2, (r4, 0x9de)	// regs: r2=*(0x9de)
  48:	02df      	lrw	r6, 0x0	// regs: r6=0x0
  4a:	c4415c46 	ins	r2, r1, 8, 6
  4e:	dc4414ef 	st.h	r2, (r4, 0x9de)	// *(0x9de) = *(0x9de)
  52:	3200      	movi	r2, 0	// regs: r2=0x0
  54:	b861      	st.w	r3, (r14, 0x4)	// local_c = ((*((*(<arg0> + 0x1c) + 0x1)) & 0x4) & 0x40)
  56:	e42610ed 	subi	r1, r6, 238	// regs: r1=0xffffff12
  5a:	a641      	st.b	r2, (r6, 0x1)	// *(0x1) = 0x0
  5c:	a642      	st.b	r2, (r6, 0x2)	// *(0x2) = 0x0
  5e:	e4060135 	addi	r0, r6, 310	// regs: r0=0x136
  62:	3206      	movi	r2, 6	// regs: r2=0x6
  64:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x64>, r1=<clobbered>
  68:	e4660111 	addi	r3, r6, 274	// regs: r3=0x112
  6c:	b862      	st.w	r3, (r14, 0x8)	// local_8 = 0x112
  6e:	ea8b0098 	lrw	r11, 0x0	// regs: r11=0x0
  72:	0367      	lrw	r3, 0x0	// regs: r3=0x0
  74:	b863      	st.w	r3, (r14, 0xc)	// local_4 = 0x0
loc_76:
  76:	9860      	ld.w	r3, (r14, 0x0)	// regs: r3=local_10
  78:	64e0      	cmphs	r8, r3
  7a:	0c58      	bf	0x12a	// if (r2 == 0x0) goto loc_12a;
  7c:	0369      	lrw	r3, 0x0	// regs: r3=0x0
  7e:	8547      	ld.b	r2, (r5, 0x7)	// regs: r2=*((*(<arg0> + 0x1c) + 0x7))
  80:	9320      	ld.w	r1, (r3, 0x0)	// regs: r1=*(0x0)
  82:	4248      	lsli	r2, r2, 8	// regs: r2=(*((*(<arg0> + 0x1c) + 0x7)) << 0x8)
  84:	8566      	ld.b	r3, (r5, 0x6)	// regs: r3=*((*(<arg0> + 0x1c) + 0x6))
  86:	6c8c      	or	r2, r3	// regs: r2=((*((*(<arg0> + 0x1c) + 0x7)) << 0x8) | *((*(<arg0> + 0x1c) + 0x6)))
  88:	8568      	ld.b	r3, (r5, 0x8)	// regs: r3=*((*(<arg0> + 0x1c) + 0x8))
  8a:	4370      	lsli	r3, r3, 16	// regs: r3=(*((*(<arg0> + 0x1c) + 0x8)) << 0x10)
  8c:	6c8c      	or	r2, r3	// regs: r2=(((*((*(<arg0> + 0x1c) + 0x7)) << 0x8) | *((*(<arg0> + 0x1c) + 0x6))) | (*((*(<arg0> + 0x1c) + 0x8)) << 0x10))
  8e:	8569      	ld.b	r3, (r5, 0x9)	// regs: r3=*((*(<arg0> + 0x1c) + 0x9))
  90:	4378      	lsli	r3, r3, 24	// regs: r3=(*((*(<arg0> + 0x1c) + 0x9)) << 0x18)
  92:	6cc8      	or	r3, r2	// regs: r3=((*((*(<arg0> + 0x1c) + 0x9)) << 0x18) | (((*((*(<arg0> + 0x1c) + 0x7)) << 0x8) | *((*(<arg0> + 0x1c) + 0x6))) | (*((*(<arg0> + 0x1c) + 0x8)) << 0x10)))
  94:	b16f      	st.w	r3, (r1, 0x3c)	// *((*(0x0) + 0x3c)) = ((*((*(<arg0> + 0x1c) + 0x9)) << 0x18) | (((*((*(<arg0> + 0x1c) + 0x7)) << 0x8) | *((*(<arg0> + 0x1c) + 0x6))) | (*((*(<arg0> + 0x1c) + 0x8)) << 0x10)))
  96:	916f      	ld.w	r3, (r1, 0x3c)	// regs: r3=*((*(0x0) + 0x3c))
  98:	3114      	movi	r1, 20	// regs: r1=0x14
  9a:	c4238022 	divu	r2, r3, r1	// regs: r2=(*((*(0x0) + 0x3c)) / 0x14)
  9e:	7c84      	mult	r2, r1	// regs: r2=((*((*(0x0) + 0x3c)) / 0x14) * 0x14)
  a0:	60ca      	subu	r3, r2	// regs: r3=(*((*(0x0) + 0x3c)) - ((*((*(0x0) + 0x3c)) / 0x14) * 0x14))
  a2:	d844132b 	ld.h	r2, (r4, 0x656)	// regs: r2=*(0x656)
  a6:	60c8      	addu	r3, r2	// regs: r3=((*((*(0x0) + 0x3c)) - ((*((*(0x0) + 0x3c)) / 0x14) * 0x14)) + *(0x656))
  a8:	74cd      	zexth	r3, r3	// regs: r3=zext16(((*((*(0x0) + 0x3c)) - ((*((*(0x0) + 0x3c)) / 0x14) * 0x14)) + *(0x656)))
  aa:	dc64132b 	st.h	r3, (r4, 0x656)	// *(0x656) = zext16(((*((*(0x0) + 0x3c)) - ((*((*(0x0) + 0x3c)) / 0x14) * 0x14)) + *(0x656)))
  ae:	436a      	lsli	r3, r3, 10	// regs: r3=(zext16(((*((*(0x0) + 0x3c)) - ((*((*(0x0) + 0x3c)) / 0x14) * 0x14)) + *(0x656))) << 0xa)
  b0:	dc642196 	st.w	r3, (r4, 0x658)	// *(0x658) = (zext16(((*((*(0x0) + 0x3c)) - ((*((*(0x0) + 0x3c)) / 0x14) * 0x14)) + *(0x656))) << 0xa)
  b4:	9861      	ld.w	r3, (r14, 0x4)	// regs: r3=local_c
  b6:	e9030004 	bez	r3, 0xbe	// if (r3 == 0x0) goto loc_be;
  ba:	c0807420 	psrset	ie
loc_be:
  be:	d867002a 	ld.b	r3, (r7, 0x2a)	// regs: r3=*(<arg0> + 0x2a)
  c2:	3601      	movi	r6, 1	// regs: r6=0x1
  c4:	c4665c04 	ins	r3, r6, 4, 4
  c8:	dc67002a 	st.b	r3, (r7, 0x2a)	// *(<arg0> + 0x2a) = *(<arg0> + 0x2a)
  cc:	3244      	movi	r2, 68	// regs: r2=0x44
  ce:	3100      	movi	r1, 0	// regs: r1=0x0
  d0:	9708      	ld.w	r0, (r7, 0x20)	// regs: r0=*(<arg0> + 0x20)
  d2:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0xd2>, r1=<clobbered>
  d6:	6c5f      	mov	r1, r7	// regs: r1=<arg0>
  d8:	031f      	lrw	r0, 0x0	// regs: r0=0x0
  da:	e0000000 	bsr	0x0	// <skb_list_queue>; regs: r0=<ret skb_list_queue@0xda>, r1=<clobbered>
  de:	031f      	lrw	r0, 0x0	// regs: r0=0x0
  e0:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0xe0>, r1=<clobbered>
  e4:	d8a409de 	ld.b	r5, (r4, 0x9de)	// regs: r5=*(0x9de)
  e8:	e4a52020 	andi	r5, r5, 32	// regs: r5=(*(0x9de) & 0x20)
  ec:	e9250012 	bnez	r5, 0x110	// if (r5 != 0x0) goto loc_110;
  f0:	30fa      	movi	r0, 250	// regs: r0=0xfa
  f2:	4002      	lsli	r0, r0, 2	// regs: r0=0x3e8
  f4:	e0000000 	bsr	0x0	// <lmac_beacon_timer_start>; regs: r0=<ret lmac_beacon_timer_start@0xf4>, r1=<clobbered>
  f8:	d86409de 	ld.b	r3, (r4, 0x9de)	// regs: r3=*(0x9de)
  fc:	c4665c05 	ins	r3, r6, 5, 5
 100:	dc6409de 	st.b	r3, (r4, 0x9de)	// *(0x9de) = *(0x9de)
 104:	d86409df 	ld.b	r3, (r4, 0x9df)	// regs: r3=*(0x9df)
 108:	c4655c05 	ins	r3, r5, 5, 5
 10c:	dc6409df 	st.b	r3, (r4, 0x9df)	// *(0x9df) = *(0x9df)
loc_110:
 110:	d864202f 	ld.w	r3, (r4, 0xbc)	// regs: r3=*(0xbc)
 114:	e92300d3 	bnez	r3, 0x2ba	// if (r3 != 0x0) goto loc_2ba;
 118:	3302      	movi	r3, 2	// regs: r3=0x2
loc_11a:
 11a:	dc64202f 	st.w	r3, (r4, 0xbc)	// *(0xbc) = r3
loc_11e:
 11e:	3000      	movi	r0, 0	// regs: r0=0x0
 120:	1404      	addi	r14, r14, 16	// regs: r14=((sp - 0x10) + 0x10)
 122:	1498      	pop	r4-r11, r15
loc_124:
 124:	e5050011 	addi	r8, r5, 18	// regs: r8=(*(<arg0> + 0x1c) + 0x12)
 128:	077d      	br	0x22	// goto loc_22;
loc_12a:
 12a:	d9480000 	ld.b	r10, (r8, 0x0)	// regs: r10=*(r8)
 12e:	eb4a000c 	cmpnei	r10, 12
 132:	d9280001 	ld.b	r9, (r8, 0x1)	// regs: r9=*(r8 + 0x1)
 136:	0cb8      	bf	0x2a6	// if (r10 == 0xc) goto loc_2a6;
 138:	eb0a000c 	cmphsi	r10, 13
 13c:	0825      	bt	0x186	// if (r10 >= 0xd) goto loc_186;
 13e:	e90a0041 	bez	r10, 0x1c0	// if (r10 == 0x0) goto loc_1c0;
 142:	eb4a0005 	cmpnei	r10, 5
 146:	0c58      	bf	0x1f6	// if (r10 == 0x5) goto loc_1f6;
loc_148:
 148:	d80420fc 	ld.w	r0, (r4, 0x3f0)	// regs: r0=*(0x3f0)
 14c:	c50056e0 	zext	r0, r0, 23, 8	// regs: r0=zext(*(0x3f0))
 150:	c5200022 	addu	r2, r0, r9	// regs: r2=(zext(*(0x3f0)) + *(r8 + 0x1))
 154:	eb2200fd 	cmplti	r2, 254
 158:	0cae      	bf	0x2b4	// if (r2 >= 0xfe) goto loc_2b4;
 15a:	1362      	lrw	r3, 0x0	// regs: r3=0x0
 15c:	e4490001 	addi	r2, r9, 2	// regs: r2=(*(r8 + 0x1) + 0x2)
 160:	6c63      	mov	r1, r8	// regs: r1=r8
 162:	600c      	addu	r0, r3	// regs: r0=(zext(*(0x3f0)) )
 164:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x164>, r1=<clobbered>
 168:	d84420fc 	ld.w	r2, (r4, 0x3f0)	// regs: r2=*(0x3f0)
 16c:	c50256e2 	zext	r2, r2, 23, 8	// regs: r2=zext(*(0x3f0))
 170:	2201      	addi	r2, 2	// regs: r2=(zext(*(0x3f0)) + 0x2)
 172:	c522002c 	addu	r12, r2, r9	// regs: r12=((zext(*(0x3f0)) + 0x2) + *(r8 + 0x1))
 176:	7731      	zexth	r12, r12	// regs: r12=zext16(((zext(*(0x3f0)) + 0x2) + *(r8 + 0x1)))
 178:	dd860001 	st.b	r12, (r6, 0x1)	// *(0x1) = zext16(((zext(*(0x3f0)) + 0x2) + *(r8 + 0x1)))
 17c:	c50c484c 	lsri	r12, r12, 8	// regs: r12=(zext16(((zext(*(0x3f0)) + 0x2) + *(r8 + 0x1))) >> 0x8)
 180:	dd860002 	st.b	r12, (r6, 0x2)	// *(0x2) = (zext16(((zext(*(0x3f0)) + 0x2) + *(r8 + 0x1))) >> 0x8)
 184:	042c      	br	0x1dc	// goto loc_1dc;
loc_186:
 186:	eb4a00d6 	cmpnei	r10, 214
 18a:	0c82      	bf	0x28e	// if (r10 == 0xd6) goto loc_28e;
 18c:	eb4a00d9 	cmpnei	r10, 217
 190:	0c5e      	bf	0x24c	// if (r10 == 0xd9) goto loc_24c;
 192:	eb4a00d5 	cmpnei	r10, 213
 196:	0bd9      	bt	0x148	// if (r10 != 0xd5) goto loc_148;
 198:	eb490008 	cmpnei	r9, 8
 19c:	082a      	bt	0x1f0	// if (r9 != 0x8) goto loc_1f0;
 19e:	d8480003 	ld.b	r2, (r8, 0x3)	// regs: r2=*(r8 + 0x3)
 1a2:	d8280002 	ld.b	r1, (r8, 0x2)	// regs: r1=*(r8 + 0x2)
 1a6:	4248      	lsli	r2, r2, 8	// regs: r2=(*(r8 + 0x3) << 0x8)
 1a8:	6c84      	or	r2, r1	// regs: r2=((*(r8 + 0x3) << 0x8) | *(r8 + 0x2))
 1aa:	dc44132a 	st.h	r2, (r4, 0x654)	// *(0x654) = ((*(r8 + 0x3) << 0x8) | *(r8 + 0x2))
 1ae:	d8480005 	ld.b	r2, (r8, 0x5)	// regs: r2=*(r8 + 0x5)
 1b2:	d8280004 	ld.b	r1, (r8, 0x4)	// regs: r1=*(r8 + 0x4)
 1b6:	4248      	lsli	r2, r2, 8	// regs: r2=(*(r8 + 0x5) << 0x8)
 1b8:	6c84      	or	r2, r1	// regs: r2=((*(r8 + 0x5) << 0x8) | *(r8 + 0x4))
 1ba:	dc44132b 	st.h	r2, (r4, 0x656)	// *(0x656) = ((*(r8 + 0x5) << 0x8) | *(r8 + 0x4))
 1be:	040f      	br	0x1dc	// goto loc_1dc;
loc_1c0:
 1c0:	eb090020 	cmphsi	r9, 33
 1c4:	0811      	bt	0x1e6	// if (r9 >= 0x21) goto loc_1e6;
 1c6:	e5290001 	addi	r9, r9, 2	// regs: r9=(*(r8 + 0x1) + 0x2)
 1ca:	6ca7      	mov	r2, r9	// regs: r2=(*(r8 + 0x1) + 0x2)
 1cc:	6c63      	mov	r1, r8	// regs: r1=r8
 1ce:	1206      	lrw	r0, 0x0	// regs: r0=0x0
 1d0:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x1d0>, r1=<clobbered>
 1d4:	c524002c 	addu	r12, r4, r9	// regs: r12=(0x0 + (*(r8 + 0x1) + 0x2))
 1d8:	dd4c052c 	st.b	r10, (r12, 0x52c)	// *(((0x0 + (*(r8 + 0x1) + 0x2)) + 0x52c)) = *(r8)
loc_1dc:
 1dc:	d8480001 	ld.b	r2, (r8, 0x1)	// regs: r2=*(r8 + 0x1)
 1e0:	2201      	addi	r2, 2	// regs: r2=(*(r8 + 0x1) + 0x2)
 1e2:	6208      	addu	r8, r2	// regs: r8=(r8 + (*(r8 + 0x1) + 0x2))
 1e4:	0749      	br	0x76	// goto loc_76;
loc_1e6:
 1e6:	6c67      	mov	r1, r9	// regs: r1=*(r8 + 0x1)
 1e8:	1200      	lrw	r0, 0x0	// regs: r0=0x0
loc_1ea:
 1ea:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1ea>, r1=<clobbered>
 1ee:	07f7      	br	0x1dc	// goto loc_1dc;
loc_1f0:
 1f0:	6c67      	mov	r1, r9	// regs: r1=*(r8 + 0x1)
 1f2:	111f      	lrw	r0, 0x0	// regs: r0=0x0
 1f4:	07fb      	br	0x1ea	// goto loc_1ea;
loc_1f6:
 1f6:	e5480001 	addi	r10, r8, 2	// regs: r10=(r8 + 0x2)
 1fa:	dd240554 	st.b	r9, (r4, 0x554)	// *(0x554) = *(r8 + 0x1)
 1fe:	d86a0001 	ld.b	r3, (r10, 0x1)	// regs: r3=*(r8 + 0x3)
 202:	dc640556 	st.b	r3, (r4, 0x556)	// *(0x556) = *(r8 + 0x3)
 206:	d84a0002 	ld.b	r2, (r10, 0x2)	// regs: r2=*(r8 + 0x4)
 20a:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(r8 + 0x4) & 0x1)
 20e:	dc440557 	st.b	r2, (r4, 0x557)	// *(0x557) = (*(r8 + 0x4) & 0x1)
 212:	e42a0001 	addi	r1, r10, 2	// regs: r1=((r8 + 0x2) + 0x2)
 216:	e4491001 	subi	r2, r9, 2	// regs: r2=(*(r8 + 0x1) - 0x2)
 21a:	1116      	lrw	r0, 0x0	// regs: r0=0x0
 21c:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x21c>, r1=<clobbered>
 220:	e4280004 	addi	r1, r8, 5	// regs: r1=(r8 + 0x5)
 224:	6c87      	mov	r2, r1	// regs: r2=(r8 + 0x5)
 226:	e5891002 	subi	r12, r9, 3	// regs: r12=(*(r8 + 0x1) - 0x3)
loc_22a:
 22a:	5a05      	subu	r0, r2, r1	// regs: r0=(r2 - r1)
 22c:	6701      	cmplt	r0, r12
 22e:	0fd7      	bf	0x1dc	// if (!T) goto loc_1dc;
 230:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
 232:	5a03      	subi	r0, r2, 1	// regs: r0=((r2 + 0x1) - 0x1)
 234:	8000      	ld.b	r0, (r0, 0x0)	// regs: r0=*(((r2 + 0x1) - 0x1))
 236:	e900fffa 	bez	r0, 0x22a	// if (r0 == 0x0) goto loc_22a;
 23a:	110f      	lrw	r0, 0x0	// regs: r0=0x0
 23c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x23c>, r1=<clobbered>
 240:	d8240554 	ld.b	r1, (r4, 0x554)	// regs: r1=*(0x554)
 244:	6c2b      	mov	r0, r10	// regs: r0=r10
 246:	e0000000 	bsr	0x0	// <hgics_print_hex>; regs: r0=<ret hgics_print_hex@0x246>, r1=<clobbered>
 24a:	07c9      	br	0x1dc	// goto loc_1dc;
loc_24c:
 24c:	eb49000f 	cmpnei	r9, 15
 250:	081c      	bt	0x288	// if (r9 != 0xf) goto loc_288;
 252:	e4280001 	addi	r1, r8, 2	// regs: r1=(r8 + 0x2)
 256:	6ca7      	mov	r2, r9	// regs: r2=*(r8 + 0x1)
 258:	1108      	lrw	r0, 0x0	// regs: r0=0x0
 25a:	6e47      	mov	r9, r1	// regs: r9=(r8 + 0x2)
 25c:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x25c>, r1=<clobbered>
 260:	8528      	ld.b	r1, (r5, 0x8)	// regs: r1=*((*(<arg0> + 0x1c) + 0x8))
 262:	8547      	ld.b	r2, (r5, 0x7)	// regs: r2=*((*(<arg0> + 0x1c) + 0x7))
 264:	6084      	addu	r2, r1	// regs: r2=(*((*(<arg0> + 0x1c) + 0x7)) + *((*(<arg0> + 0x1c) + 0x8)))
 266:	8529      	ld.b	r1, (r5, 0x9)	// regs: r1=*((*(<arg0> + 0x1c) + 0x9))
 268:	6084      	addu	r2, r1	// regs: r2=((*((*(<arg0> + 0x1c) + 0x7)) + *((*(<arg0> + 0x1c) + 0x8))) + *((*(<arg0> + 0x1c) + 0x9)))
 26a:	e4422007 	andi	r2, r2, 7	// regs: r2=(((*((*(<arg0> + 0x1c) + 0x7)) + *((*(<arg0> + 0x1c) + 0x8))) + *((*(<arg0> + 0x1c) + 0x9))) & 0x7)
 26e:	d8240668 	ld.b	r1, (r4, 0x668)	// regs: r1=*(0x668)
 272:	c4225c40 	ins	r1, r2, 2, 0
 276:	dc240668 	st.b	r1, (r4, 0x668)	// *(0x668) = *(0x668)
 27a:	d8290008 	ld.b	r1, (r9, 0x8)	// regs: r1=*(r8 + 0xa)
 27e:	c4225c42 	ins	r1, r2, 4, 2
 282:	dc290008 	st.b	r1, (r9, 0x8)	// *(r8 + 0xa) = *(r8 + 0xa)
 286:	07ab      	br	0x1dc	// goto loc_1dc;
loc_288:
 288:	6c67      	mov	r1, r9	// regs: r1=*(r8 + 0x1)
 28a:	101d      	lrw	r0, 0x0	// regs: r0=0x0
 28c:	07af      	br	0x1ea	// goto loc_1ea;
loc_28e:
 28e:	d8480003 	ld.b	r2, (r8, 0x3)	// regs: r2=*(r8 + 0x3)
 292:	d8280002 	ld.b	r1, (r8, 0x2)	// regs: r1=*(r8 + 0x2)
 296:	4248      	lsli	r2, r2, 8	// regs: r2=(*(r8 + 0x3) << 0x8)
 298:	6c84      	or	r2, r1	// regs: r2=((*(r8 + 0x3) << 0x8) | *(r8 + 0x2))
 29a:	dc44132b 	st.h	r2, (r4, 0x656)	// *(0x656) = ((*(r8 + 0x3) << 0x8) | *(r8 + 0x2))
 29e:	424a      	lsli	r2, r2, 10	// regs: r2=(((*(r8 + 0x3) << 0x8) | *(r8 + 0x2)) << 0xa)
 2a0:	dc442196 	st.w	r2, (r4, 0x658)	// *(0x658) = (((*(r8 + 0x3) << 0x8) | *(r8 + 0x2)) << 0xa)
 2a4:	079c      	br	0x1dc	// goto loc_1dc;
loc_2a6:
 2a6:	3212      	movi	r2, 18	// regs: r2=0x12
 2a8:	e4280001 	addi	r1, r8, 2	// regs: r1=(r8 + 0x2)
 2ac:	9802      	ld.w	r0, (r14, 0x8)	// regs: r0=local_8
 2ae:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x2ae>, r1=<clobbered>
 2b2:	0795      	br	0x1dc	// goto loc_1dc;
loc_2b4:
 2b4:	9823      	ld.w	r1, (r14, 0xc)	// regs: r1=local_4
 2b6:	6c2f      	mov	r0, r11	// regs: r0=0x0
 2b8:	0799      	br	0x1ea	// goto loc_1ea;
loc_2ba:
 2ba:	3b41      	cmpnei	r3, 1
 2bc:	0b31      	bt	0x11e	// if (r3 != 0x1) goto loc_11e;
 2be:	3303      	movi	r3, 3	// regs: r3=0x3
 2c0:	072d      	br	0x11a	// goto loc_11a;
 2c2:	0000      	.short	0x0000
 2c4:	00000000 	.long	0x00000000	// <ah_lmac>
 2c8:	00000000 	.long	0x00000000	// <ah_lmac+0x3f0>
 2cc:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_pv0_s1g_beacon.str1.1+0x77>
 2d0:	00000000 	.long	0x00000000	// <.rodata.__func__.13356>
 2d4:	00000000 	.long	0x00000000	// <LMAC>
 2d8:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x538>
 2dc:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x5c>
 2e0:	00000000 	.long	0x00000000	// <ah_lmac+0x3f3>
 2e4:	00000000 	.long	0x00000000	// <ah_lmac+0x52c>
 2e8:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_pv0_s1g_beacon.str1.1>
 2ec:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_pv0_s1g_beacon.str1.1+0x1d>
 2f0:	00000000 	.long	0x00000000	// <ah_lmac+0x558>
 2f4:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_pv0_s1g_beacon.str1.1+0x3c>
 2f8:	00000000 	.long	0x00000000	// <ah_lmac+0x4f3>
 2fc:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_pv0_s1g_beacon.str1.1+0x57>

Disassembly of section .text.lmac_tx_pv0_ext:

00000000 <lmac_tx_pv0_ext>: // arg_bytes: 4
   0:	14d1      	push	r4, r15
   2:	9067      	ld.w	r3, (r0, 0x1c)	// regs: r3=*(<arg0> + 0x1c)
   4:	8380      	ld.b	r4, (r3, 0x0)	// regs: r4=*(*(<arg0> + 0x1c))
   6:	4c84      	lsri	r4, r4, 4	// regs: r4=(*(*(<arg0> + 0x1c)) >> 0x4)
   8:	e9240008 	bnez	r4, 0x18	// if (r4 != 0x0) goto loc_18;
   c:	102a      	lrw	r1, 0x0	// regs: r1=0x0
   e:	100b      	lrw	r0, 0x0	// regs: r0=0x0
  10:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x10>, r1=<clobbered>
loc_14:
  14:	3000      	movi	r0, 0	// regs: r0=0x0
  16:	040d      	br	0x30	// goto loc_30;
loc_18:
  18:	3c41      	cmpnei	r4, 1
  1a:	0804      	bt	0x22	// if (r4 != 0x1) goto loc_22;
  1c:	e0000000 	bsr	0x0	// <lmac_tx_pv0_s1g_beacon> // arg_bytes: 4; regs: r0=<ret lmac_tx_pv0_s1g_beacon@0x1c>, r1=<clobbered>
  20:	07fa      	br	0x14	// goto loc_14;
loc_22:
  22:	3c4f      	cmpnei	r4, 15
  24:	0ff8      	bf	0x14	// if (r4 == 0xf) goto loc_14;
  26:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  28:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x28>, r1=<clobbered>
  2c:	3000      	movi	r0, 0	// regs: r0=0x0
  2e:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_30:
  30:	1491      	pop	r4, r15
  32:	0000      	.short	0x0000
  34:	0000      	.short	0x0000	// <.rodata.__func__.13253>
  36:	0000      	.short	0x0000
  38:	0000      	.short	0x0000	// <.rodata.lmac_tx_pv0_s1g_beacon.str1.1+0x77>
  3a:	0000      	.short	0x0000
  3c:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_pv0_ext.str1.1>

Disassembly of section .text.lmac_txsq_count:

00000000 <lmac_txsq_count>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	1003      	lrw	r0, 0x0	// regs: r0=0x0
   4:	e0000000 	bsr	0x0	// <skb_list_count>; regs: r0=<ret skb_list_count@0x4>, r1=<clobbered>
   8:	1490      	pop	r15
   a:	0000      	.short	0x0000
   c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x70>

Disassembly of section .text.lmac_statq_count:

00000000 <lmac_statq_count>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	1003      	lrw	r0, 0x0	// regs: r0=0x0
   4:	e0000000 	bsr	0x0	// <skb_list_count>; regs: r0=<ret skb_list_count@0x4>, r1=<clobbered>
   8:	1490      	pop	r15
   a:	0000      	.short	0x0000
   c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x538>

Disassembly of section .text.lmac_txq_count:

00000000 <lmac_txq_count>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	1003      	lrw	r0, 0x0	// regs: r0=0x0
   4:	e0000000 	bsr	0x0	// <skb_list_count>; regs: r0=<ret skb_list_count@0x4>, r1=<clobbered>
   8:	1490      	pop	r15
   a:	0000      	.short	0x0000
   c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x64>

Disassembly of section .text.lmac_acq_count:

00000000 <lmac_acq_count>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	5860      	addu	r3, r0, r0	// regs: r3=(<arg0> + <arg0>)
   4:	600c      	addu	r0, r3	// regs: r0=(<arg0> + (<arg0> + <arg0>))
   6:	4002      	lsli	r0, r0, 2	// regs: r0=((<arg0> + (<arg0> + <arg0>)) << 0x2)
   8:	1063      	lrw	r3, 0x0	// regs: r3=0x0
   a:	600c      	addu	r0, r3	// regs: r0=(((<arg0> + (<arg0> + <arg0>)) << 0x2) )
   c:	e0000000 	bsr	0x0	// <skb_list_count>; regs: r0=<ret skb_list_count@0xc>, r1=<clobbered>
  10:	1490      	pop	r15
  12:	0000      	.short	0x0000
  14:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x88>

Disassembly of section .text.lmac_cfg_txvec_part1:

00000000 <lmac_cfg_txvec_part1>: // arg_bytes: 0
   0:	14d4      	push	r4-r7, r15
   2:	11ba      	lrw	r5, 0x0	// regs: r5=0x0
   4:	9541      	ld.w	r2, (r5, 0x4)	// regs: r2=*(0x4)
   6:	8260      	ld.b	r3, (r2, 0x0)	// regs: r3=*(*(0x4))
   8:	e42320c0 	andi	r1, r3, 192	// regs: r1=(*(*(0x4)) & 0xc0)
   c:	eb4100c0 	cmpnei	r1, 192
  10:	0805      	bt	0x1a	// if (r1 != 0xc0) goto loc_1a;
  12:	3100      	movi	r1, 0	// regs: r1=0x0
  14:	c4615c26 	ins	r3, r1, 7, 6
  18:	a260      	st.b	r3, (r2, 0x0)	// *(*(0x4)) = *(*(0x4))
loc_1a:
  1a:	11d5      	lrw	r6, 0x0	// regs: r6=0x0
  1c:	1195      	lrw	r4, 0x0	// regs: r4=0x0
  1e:	9660      	ld.w	r3, (r6, 0x0)	// regs: r3=*(0x0)
  20:	9220      	ld.w	r1, (r2, 0x0)	// regs: r1=*(*(0x4))
  22:	b339      	st.w	r1, (r3, 0x64)	// *((*(0x0) + 0x64)) = *(*(0x4))
  24:	d8240338 	ld.b	r1, (r4, 0x338)	// regs: r1=*(0x338)
  28:	e4212001 	andi	r1, r1, 1	// regs: r1=(*(0x338) & 0x1)
  2c:	d86411b6 	ld.h	r3, (r4, 0x36c)	// regs: r3=*(0x36c)
  30:	e9010053 	bez	r1, 0xd6	// if (r1 == 0x0) goto loc_d6;
  34:	8200      	ld.b	r0, (r2, 0x0)	// regs: r0=*(*(0x4))
  36:	e440201f 	andi	r2, r0, 31	// regs: r2=(*(*(0x4)) & 0x1f)
  3a:	c4a35520 	zext	r0, r3, 9, 5	// regs: r0=zext(*(0x36c))
  3e:	6481      	cmplt	r0, r2
  40:	0844      	bt	0xc8	// if (T) goto loc_c8;
  42:	6c0b      	mov	r0, r2	// regs: r0=(*(*(0x4)) & 0x1f)
loc_44:
  44:	d864036d 	ld.b	r3, (r4, 0x36d)	// regs: r3=*(0x36d)
  48:	e463200c 	andi	r3, r3, 12	// regs: r3=(*(0x36d) & 0xc)
  4c:	e923000b 	bnez	r3, 0x62	// if (r3 != 0x0) goto loc_62;
  50:	3802      	cmphsi	r0, 3
  52:	0808      	bt	0x62	// if (r0 >= 0x3) goto loc_62;
  54:	d864226d 	ld.w	r3, (r4, 0x9b4)	// regs: r3=*(0x9b4)
  58:	ec632000 	ori	r3, r3, 8192	// regs: r3=(*(0x9b4) | 0x2000)
  5c:	dc64226d 	st.w	r3, (r4, 0x9b4)	// *(0x9b4) = (*(0x9b4) | 0x2000)
  60:	3003      	movi	r0, 3	// regs: r0=0x3
loc_62:
  62:	d864036d 	ld.b	r3, (r4, 0x36d)	// regs: r3=*(0x36d)
  66:	e463200c 	andi	r3, r3, 12	// regs: r3=(*(0x36d) & 0xc)
  6a:	e9030008 	bez	r3, 0x7a	// if (r3 == 0x0) goto loc_7a;
  6e:	3b48      	cmpnei	r3, 8
  70:	0836      	bt	0xdc	// if (r3 != 0x8) goto loc_dc;
  72:	3840      	cmpnei	r0, 0
  74:	3301      	movi	r3, 1	// regs: r3=0x1
loc_76:
  76:	c4030c20 	incf	r0, r3, 0
loc_7a:
  7a:	dc040710 	st.b	r0, (r4, 0x710)	// *(0x710) = r0
  7e:	e0000000 	bsr	0x0	// <ah_rfdigicali_tx_pwr>; regs: r0=<ret ah_rfdigicali_tx_pwr@0x7e>, r1=<clobbered>
  82:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  86:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  8a:	e9030011 	bez	r3, 0xac	// if (r3 == 0x0) goto loc_ac;
  8e:	10fa      	lrw	r7, 0x0	// regs: r7=0x0
  90:	d8040708 	ld.b	r0, (r4, 0x708)	// regs: r0=*(0x708)
  94:	e400203f 	andi	r0, r0, 63	// regs: r0=(*(0x708) & 0x3f)
  98:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(0x0)
  9a:	64c2      	cmpne	r0, r3
  9c:	0c08      	bf	0xac	// if (!T) goto loc_ac;
  9e:	e0000000 	bsr	0x0	// <config_ft_att_val>; regs: r0=<ret config_ft_att_val@0x9e>, r1=<clobbered>
  a2:	d8640708 	ld.b	r3, (r4, 0x708)	// regs: r3=*(0x708)
  a6:	e463203f 	andi	r3, r3, 63	// regs: r3=(*(0x708) & 0x3f)
  aa:	b760      	st.w	r3, (r7, 0x0)	// *(0x0) = (*(0x708) & 0x3f)
loc_ac:
  ac:	9640      	ld.w	r2, (r6, 0x0)	// regs: r2=*(0x0)
  ae:	9521      	ld.w	r1, (r5, 0x4)	// regs: r1=*(0x4)
  b0:	9279      	ld.w	r3, (r2, 0x64)	// regs: r3=*((*(0x0) + 0x64))
  b2:	9120      	ld.w	r1, (r1, 0x0)	// regs: r1=*(*(0x4))
  b4:	6cc5      	xor	r3, r1	// regs: r3=(*((*(0x0) + 0x64)) ^ *(*(0x4)))
  b6:	c40356e3 	zext	r3, r3, 23, 0	// regs: r3=zext((*((*(0x0) + 0x64)) ^ *(*(0x4))))
  ba:	e9030006 	bez	r3, 0xc6	// if (r3 == 0x0) goto loc_c6;
  be:	9259      	ld.w	r2, (r2, 0x64)	// regs: r2=*((*(0x0) + 0x64))
  c0:	100e      	lrw	r0, 0x0	// regs: r0=0x0
  c2:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xc2>, r1=<clobbered>
loc_c6:
  c6:	1494      	pop	r4-r7, r15
loc_c8:
  c8:	d864226d 	ld.w	r3, (r4, 0x9b4)	// regs: r3=*(0x9b4)
  cc:	ec632000 	ori	r3, r3, 8192	// regs: r3=(*(0x9b4) | 0x2000)
  d0:	dc64226d 	st.w	r3, (r4, 0x9b4)	// *(0x9b4) = (*(0x9b4) | 0x2000)
  d4:	07b8      	br	0x44	// goto loc_44;
loc_d6:
  d6:	c4a35520 	zext	r0, r3, 9, 5	// regs: r0=zext(*(0x36c))
  da:	07c4      	br	0x62	// goto loc_62;
loc_dc:
  dc:	3b4c      	cmpnei	r3, 12
  de:	0bce      	bt	0x7a	// if (r3 != 0xc) goto loc_7a;
  e0:	3841      	cmpnei	r0, 1
  e2:	3305      	movi	r3, 5	// regs: r3=0x5
  e4:	07c9      	br	0x76	// goto loc_76;
  e6:	0000      	.short	0x0000
  e8:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  ec:	00000000 	.long	0x00000000	// <LMAC>
  f0:	0000      	.short	0x0000	// <ah_lmac>
  f2:	0000      	.short	0x0000
  f4:	00000000 	.long	0x00000000	// <.bss.ft_att_pre>
  f8:	00000000 	.long	0x00000000	// <.rodata.lmac_cfg_txvec_part1.str1.1>

Disassembly of section .text.lmac_ant_sel:

00000000 <lmac_ant_sel>: // arg_bytes: 4
   0:	14d2      	push	r4-r5, r15
   2:	1181      	lrw	r4, 0x0	// regs: r4=0x0
   4:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   6:	d8640875 	ld.b	r3, (r4, 0x875)	// regs: r3=*(0x875)
   a:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(0x875) & 0x4)
   e:	e903003a 	bez	r3, 0x82	// if (r3 == 0x0) goto loc_82;
  12:	d804143b 	ld.h	r0, (r4, 0x876)	// regs: r0=*(0x876)
  16:	ea038080 	movi	r3, 32896	// regs: r3=0x8080
  1a:	680c      	and	r0, r3	// regs: r0=(*(0x876) & 0x8080)
  1c:	e9200015 	bnez	r0, 0x46	// if (r0 != 0x0) goto loc_46;
  20:	e0000000 	bsr	0x0	// <jtag_map_set>; regs: r0=<ret jtag_map_set@0x20>, r1=<clobbered>
  24:	d8640876 	ld.b	r3, (r4, 0x876)	// regs: r3=*(0x876)
  28:	301f      	movi	r0, 31	// regs: r0=0x1f
  2a:	c4605cc0 	ins	r3, r0, 6, 0
  2e:	3101      	movi	r1, 1	// regs: r1=0x1
  30:	dc640876 	st.b	r3, (r4, 0x876)	// *(0x876) = *(0x876)
  34:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x34>, r1=<clobbered>
  38:	d8640876 	ld.b	r3, (r4, 0x876)	// regs: r3=*(0x876)
  3c:	3201      	movi	r2, 1	// regs: r2=0x1
  3e:	c4625c07 	ins	r3, r2, 7, 7
  42:	dc640876 	st.b	r3, (r4, 0x876)	// *(0x876) = *(0x876)
loc_46:
  46:	d8040876 	ld.b	r0, (r4, 0x876)	// regs: r0=*(0x876)
  4a:	74c2      	sextb	r3, r0	// regs: r3=sext8(*(0x876))
  4c:	e9a30009 	bhsz	r3, 0x5e	// if (r3 >= 0x0) goto loc_5e;
  50:	3d40      	cmpnei	r5, 0
  52:	c4000501 	mvc	r1	// regs: r1=<cond>
  56:	e400207f 	andi	r0, r0, 127	// regs: r0=(*(0x876) & 0x7f)
  5a:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x5a>, r1=<clobbered>
loc_5e:
  5e:	d8040877 	ld.b	r0, (r4, 0x877)	// regs: r0=*(0x877)
  62:	74c2      	sextb	r3, r0	// regs: r3=sext8(*(0x877))
  64:	e9a30008 	bhsz	r3, 0x74	// if (r3 >= 0x0) goto loc_74;
  68:	3d40      	cmpnei	r5, 0
  6a:	6443      	mvcv	r1	// regs: r1=<cond>
  6c:	e400207f 	andi	r0, r0, 127	// regs: r0=(*(0x877) & 0x7f)
  70:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x70>, r1=<clobbered>
loc_74:
  74:	1065      	lrw	r3, 0x0	// regs: r3=0x0
  76:	d843055d 	ld.b	r2, (r3, 0x55d)	// regs: r2=*(0x55d)
  7a:	c4455c02 	ins	r2, r5, 2, 2
  7e:	dc43055d 	st.b	r2, (r3, 0x55d)	// *(0x55d) = *(0x55d)
loc_82:
  82:	1492      	pop	r4-r5, r15
  84:	0000      	.short	0x0000	// <ah_lmac>
  86:	0000      	.short	0x0000
  88:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  8a:	0000      	.short	0x0000

Disassembly of section .text.lmac_cfg_txvec_part2:

00000000 <lmac_cfg_txvec_part2>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	106f      	lrw	r3, 0x0	// regs: r3=0x0
   4:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   6:	106f      	lrw	r3, 0x0	// regs: r3=0x0
   8:	9361      	ld.w	r3, (r3, 0x4)	// regs: r3=*(0x4)
   a:	9321      	ld.w	r1, (r3, 0x4)	// regs: r1=*((*(0x4) + 0x4))
   c:	b23a      	st.w	r1, (r2, 0x68)	// *((*(0x0) + 0x68)) = *((*(0x4) + 0x4))
   e:	9322      	ld.w	r1, (r3, 0x8)	// regs: r1=*((*(0x4) + 0x8))
  10:	b23b      	st.w	r1, (r2, 0x6c)	// *((*(0x0) + 0x6c)) = *((*(0x4) + 0x8))
  12:	9323      	ld.w	r1, (r3, 0xc)	// regs: r1=*((*(0x4) + 0xc))
  14:	b23c      	st.w	r1, (r2, 0x70)	// *((*(0x0) + 0x70)) = *((*(0x4) + 0xc))
  16:	8363      	ld.b	r3, (r3, 0x3)	// regs: r3=*((*(0x4) + 0x3))
  18:	e4632003 	andi	r3, r3, 3	// regs: r3=(*((*(0x4) + 0x3)) & 0x3)
  1c:	3b41      	cmpnei	r3, 1
  1e:	0805      	bt	0x28	// if (r3 != 0x1) goto loc_28;
  20:	3000      	movi	r0, 0	// regs: r0=0x0
loc_22:
  22:	e0000000 	bsr	0x0	// <lmac_ant_sel> // arg_bytes: 4; regs: r0=<ret lmac_ant_sel@0x22>, r1=<clobbered>
  26:	1490      	pop	r15
loc_28:
  28:	3b42      	cmpnei	r3, 2
  2a:	0803      	bt	0x30	// if (r3 != 0x2) goto loc_30;
  2c:	3001      	movi	r0, 1	// regs: r0=0x1
  2e:	07fa      	br	0x22	// goto loc_22;
loc_30:
  30:	1065      	lrw	r3, 0x0	// regs: r3=0x0
  32:	d8030875 	ld.b	r0, (r3, 0x875)	// regs: r0=*(0x875)
  36:	c4805480 	zext	r0, r0, 4, 4	// regs: r0=zext(*(0x875))
  3a:	07f4      	br	0x22	// goto loc_22;
  3c:	00000000 	.long	0x00000000	// <LMAC>
  40:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  42:	0000      	.short	0x0000
  44:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_tx_date_prepared:

00000000 <lmac_tx_date_prepared>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	106f      	lrw	r3, 0x0	// regs: r3=0x0
   4:	d86309dc 	ld.b	r3, (r3, 0x9dc)	// regs: r3=*(0x9dc)
   8:	e463200f 	andi	r3, r3, 15	// regs: r3=(*(0x9dc) & 0xf)
   c:	3b03      	cmphsi	r3, 4
   e:	0814      	bt	0x36	// if (r3 >= 0x4) goto loc_36;
  10:	3190      	movi	r1, 144	// regs: r1=0x90
  12:	4121      	lsli	r1, r1, 1	// regs: r1=0x120
  14:	104b      	lrw	r2, 0x0	// regs: r2=0x0
  16:	7cc4      	mult	r3, r1	// regs: r3=((*(0x9dc) & 0xf) * 0x120)
  18:	5a2c      	addu	r1, r2, r3	// regs: r1=(0x0 + ((*(0x9dc) & 0xf) * 0x120))
  1a:	d82101c7 	ld.b	r1, (r1, 0x1c7)	// regs: r1=*(((0x0 + ((*(0x9dc) & 0xf) * 0x120)) + 0x1c7))
  1e:	c4415441 	zext	r1, r1, 2, 2	// regs: r1=zext(*(((0x0 + ((*(0x9dc) & 0xf) * 0x120)) + 0x1c7)))
  22:	e901000a 	bez	r1, 0x36	// if (r1 == 0x0) goto loc_36;
  26:	e46301c7 	addi	r3, r3, 456	// regs: r3=(((*(0x9dc) & 0xf) * 0x120) + 0x1c8)
  2a:	60c8      	addu	r3, r2	// regs: r3=((((*(0x9dc) & 0xf) * 0x120) + 0x1c8) )
  2c:	b261      	st.w	r3, (r2, 0x4)	// *(0x4) = ((((*(0x9dc) & 0xf) * 0x120) + 0x1c8) )
  2e:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part1> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part1@0x2e>, r1=<clobbered>
  32:	3000      	movi	r0, 0	// regs: r0=0x0
loc_34:
  34:	1490      	pop	r15
loc_36:
  36:	3000      	movi	r0, 0	// regs: r0=0x0
  38:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  3a:	07fd      	br	0x34	// goto loc_34;
  3c:	00000000 	.long	0x00000000	// <ah_lmac>
  40:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  42:	0000      	.short	0x0000

Disassembly of section .text.lmac_tx_pwr_sel:

00000000 <lmac_tx_pwr_sel>: // arg_bytes: 8
   0:	14d4      	push	r4-r7, r15
   2:	d8600027 	ld.b	r3, (r0, 0x27)	// regs: r3=*(<arg0> + 0x27)
   6:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(<arg0> + 0x27) & 0x2)
   a:	6dc3      	mov	r7, r0	// regs: r7=<arg0>
   c:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   e:	1189      	lrw	r4, 0x0	// regs: r4=0x0
  10:	e9030048 	bez	r3, 0xa0	// if (r3 == 0x0) goto loc_a0;
  14:	90c3      	ld.w	r6, (r0, 0xc)	// regs: r6=*(<arg0> + 0xc)
  16:	e9060045 	bez	r6, 0xa0	// if (r6 == 0x0) goto loc_a0;
  1a:	d8640338 	ld.b	r3, (r4, 0x338)	// regs: r3=*(0x338)
  1e:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x338) & 0x1)
  22:	e903003a 	bez	r3, 0x96	// if (r3 == 0x0) goto loc_96;
  26:	d86420db 	ld.w	r3, (r4, 0x36c)	// regs: r3=*(0x36c)
  2a:	d8444a4e 	ld.bs	r2, (r4, 0xa4e)	// regs: r2=*(0xa4e)
  2e:	c5c356a3 	zext	r3, r3, 21, 14	// regs: r3=zext(*(0x36c))
  32:	64c9      	cmplt	r2, r3
  34:	d804036c 	ld.b	r0, (r4, 0x36c)	// regs: r0=*(0x36c)
  38:	0807      	bt	0x46	// if (T) goto loc_46;
  3a:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  3e:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  42:	e9030027 	bez	r3, 0x90	// if (r3 == 0x0) goto loc_90;
loc_46:
  46:	6c57      	mov	r1, r5	// regs: r1=<arg1>
  48:	e400201f 	andi	r0, r0, 31	// regs: r0=(*(0x36c) & 0x1f)
  4c:	e0000000 	bsr	0x0	// <tx_pwr_adjust_by_mcs> // arg_bytes: 8; regs: r0=<ret tx_pwr_adjust_by_mcs@0x4c>, r1=<clobbered>
loc_50:
  50:	d8640312 	ld.b	r3, (r4, 0x312)	// regs: r3=*(0x312)
  54:	d8470029 	ld.b	r2, (r7, 0x29)	// regs: r2=*(<arg0> + 0x29)
  58:	2b01      	subi	r3, 2	// regs: r3=(*(0x312) - 0x2)
  5a:	64c9      	cmplt	r2, r3
  5c:	0808      	bt	0x6c	// if (T) goto loc_6c;
  5e:	d80411b6 	ld.h	r0, (r4, 0x36c)	// regs: r0=*(0x36c)
  62:	6c57      	mov	r1, r5	// regs: r1=<arg1>
  64:	c4a05520 	zext	r0, r0, 9, 5	// regs: r0=zext(*(0x36c))
  68:	e0000000 	bsr	0x0	// <tx_pwr_adjust_by_mcs> // arg_bytes: 8; regs: r0=<ret tx_pwr_adjust_by_mcs@0x68>, r1=<clobbered>
loc_6c:
  6c:	d8661034 	ld.h	r3, (r6, 0x68)	// regs: r3=*((*(<arg0> + 0xc) + 0x68))
  70:	dc642212 	st.w	r3, (r4, 0x848)	// *(0x848) = *((*(<arg0> + 0xc) + 0x68))
  74:	d8640a4e 	ld.b	r3, (r4, 0xa4e)	// regs: r3=*(0xa4e)
  78:	dc640841 	st.b	r3, (r4, 0x841)	// *(0x841) = *(0xa4e)
  7c:	d8642211 	ld.w	r3, (r4, 0x844)	// regs: r3=*(0x844)
  80:	2300      	addi	r3, 1	// regs: r3=(*(0x844) + 0x1)
  82:	dca4083e 	st.b	r5, (r4, 0x83e)	// *(0x83e) = <arg1>
  86:	dc040840 	st.b	r0, (r4, 0x840)	// *(0x840) = r0
  8a:	dc642211 	st.w	r3, (r4, 0x844)	// *(0x844) = (*(0x844) + 0x1)
loc_8e:
  8e:	1494      	pop	r4-r7, r15
loc_90:
  90:	e400201f 	andi	r0, r0, 31	// regs: r0=(*(0x36c) & 0x1f)
  94:	07de      	br	0x50	// goto loc_50;
loc_96:
  96:	d80411b6 	ld.h	r0, (r4, 0x36c)	// regs: r0=*(0x36c)
  9a:	c4a05520 	zext	r0, r0, 9, 5	// regs: r0=zext(*(0x36c))
  9e:	07e7      	br	0x6c	// goto loc_6c;
loc_a0:
  a0:	d80411b6 	ld.h	r0, (r4, 0x36c)	// regs: r0=*(0x36c)
  a4:	6c57      	mov	r1, r5	// regs: r1=<arg1>
  a6:	c4a05520 	zext	r0, r0, 9, 5	// regs: r0=zext(*(0x36c))
  aa:	e0000000 	bsr	0x0	// <tx_pwr_adjust_by_mcs> // arg_bytes: 8; regs: r0=<ret tx_pwr_adjust_by_mcs@0xaa>, r1=<clobbered>
  ae:	07f0      	br	0x8e	// goto loc_8e;
  b0:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.pv0_ctrl_uplink_txpwr_gen:

00000000 <pv0_ctrl_uplink_txpwr_gen>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	107e      	lrw	r3, 0x0	// regs: r3=0x0
   4:	105e      	lrw	r2, 0x0	// regs: r2=0x0
   6:	9381      	ld.w	r4, (r3, 0x4)	// regs: r4=*(0x4)
   8:	d80211b6 	ld.h	r0, (r2, 0x36c)	// regs: r0=*(0x36c)
   c:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*((*(0x4) + 0x1))
   e:	e463200c 	andi	r3, r3, 12	// regs: r3=(*((*(0x4) + 0x1)) & 0xc)
  12:	3b44      	cmpnei	r3, 4
  14:	c4a05520 	zext	r0, r0, 9, 5	// regs: r0=zext(*(0x36c))
  18:	0817      	bt	0x46	// if (r3 != 0x4) goto loc_46;
  1a:	d822202f 	ld.w	r1, (r2, 0xbc)	// regs: r1=*(0xbc)
  1e:	3941      	cmpnei	r1, 1
  20:	8468      	ld.b	r3, (r4, 0x8)	// regs: r3=*((*(0x4) + 0x8))
  22:	081d      	bt	0x5c	// if (r1 != 0x1) goto loc_5c;
  24:	c4615c02 	ins	r3, r1, 2, 2
  28:	a468      	st.b	r3, (r4, 0x8)	// *((*(0x4) + 0x8)) = *((*(0x4) + 0x8))
  2a:	8c64      	ld.h	r3, (r4, 0x8)	// regs: r3=*((*(0x4) + 0x8))
  2c:	3200      	movi	r2, 0	// regs: r2=0x0
  2e:	c4625d07 	ins	r3, r2, 15, 7
  32:	ac64      	st.h	r3, (r4, 0x8)	// *((*(0x4) + 0x8)) = *((*(0x4) + 0x8))
loc_34:
  34:	8421      	ld.b	r1, (r4, 0x1)	// regs: r1=*((*(0x4) + 0x1))
  36:	4924      	lsri	r1, r1, 4	// regs: r1=(*((*(0x4) + 0x1)) >> 0x4)
  38:	e0000000 	bsr	0x0	// <tx_pwr_adjust_by_mcs> // arg_bytes: 8; regs: r0=<ret tx_pwr_adjust_by_mcs@0x38>, r1=<clobbered>
  3c:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(*(0x4))
  3e:	c4605c80 	ins	r3, r0, 4, 0
  42:	a460      	st.b	r3, (r4, 0x0)	// *(*(0x4)) = *(*(0x4))
  44:	1491      	pop	r4, r15
loc_46:
  46:	3b48      	cmpnei	r3, 8
  48:	0bf6      	bt	0x34	// if (r3 != 0x8) goto loc_34;
  4a:	d822202f 	ld.w	r1, (r2, 0xbc)	// regs: r1=*(0xbc)
  4e:	3941      	cmpnei	r1, 1
  50:	8468      	ld.b	r3, (r4, 0x8)	// regs: r3=*((*(0x4) + 0x8))
  52:	0805      	bt	0x5c	// if (r1 != 0x1) goto loc_5c;
  54:	c4615c02 	ins	r3, r1, 2, 2
  58:	a468      	st.b	r3, (r4, 0x8)	// *((*(0x4) + 0x8)) = *((*(0x4) + 0x8))
  5a:	07ed      	br	0x34	// goto loc_34;
loc_5c:
  5c:	3100      	movi	r1, 0	// regs: r1=0x0
  5e:	c4615c02 	ins	r3, r1, 2, 2
  62:	a468      	st.b	r3, (r4, 0x8)	// *((*(0x4) + 0x8)) = *((*(0x4) + 0x8))
  64:	d8620668 	ld.b	r3, (r2, 0x668)	// regs: r3=*(0x668)
  68:	e4632007 	andi	r3, r3, 7	// regs: r3=(*(0x668) & 0x7)
  6c:	8c44      	ld.h	r2, (r4, 0x8)	// regs: r2=*((*(0x4) + 0x8))
  6e:	c4435d07 	ins	r2, r3, 15, 7
  72:	ac44      	st.h	r2, (r4, 0x8)	// *((*(0x4) + 0x8)) = *((*(0x4) + 0x8))
  74:	07e0      	br	0x34	// goto loc_34;
  76:	0000      	.short	0x0000
  78:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  7a:	0000      	.short	0x0000
  7c:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_partial_aid_update:

00000000 <lmac_partial_aid_update>: // arg_bytes: 4
   0:	14d1      	push	r4, r15
   2:	9063      	ld.w	r3, (r0, 0xc)	// regs: r3=*(<arg0> + 0xc)
   4:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   6:	e9030016 	bez	r3, 0x32	// if (r3 == 0x0) goto loc_32;
   a:	d8031034 	ld.h	r0, (r3, 0x68)	// regs: r0=*((*(<arg0> + 0xc) + 0x68))
   e:	d8640027 	ld.b	r3, (r4, 0x27)	// regs: r3=*(<arg0> + 0x27)
  12:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(<arg0> + 0x27) & 0x1)
  16:	ac17      	st.h	r0, (r4, 0x2e)	// *(<arg0> + 0x2e) = *((*(<arg0> + 0xc) + 0x68))
  18:	e923000d 	bnez	r3, 0x32	// if (r3 != 0x0) goto loc_32;
  1c:	d8640025 	ld.b	r3, (r4, 0x25)	// regs: r3=*(<arg0> + 0x25)
  20:	e46320c0 	andi	r3, r3, 192	// regs: r3=(*(<arg0> + 0x25) & 0xc0)
  24:	eb430080 	cmpnei	r3, 128
  28:	0806      	bt	0x34	// if (r3 != 0x80) goto loc_34;
  2a:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  2c:	e0000000 	bsr	0x0	// <partial_bssid_calc>; regs: r0=<ret partial_bssid_calc@0x2c>, r1=<clobbered>
loc_30:
  30:	ac18      	st.h	r0, (r4, 0x30)	// *(<arg0> + 0x30) = r0
loc_32:
  32:	1491      	pop	r4, r15
loc_34:
  34:	eb430040 	cmpnei	r3, 64
  38:	0bfd      	bt	0x32	// if (r3 != 0x40) goto loc_32;
  3a:	1023      	lrw	r1, 0x0	// regs: r1=0x0
  3c:	e0000000 	bsr	0x0	// <partial_aid_calc>; regs: r0=<ret partial_aid_calc@0x3c>, r1=<clobbered>
  40:	07f8      	br	0x30	// goto loc_30;
  42:	0000      	.short	0x0000
  44:	00000000 	.long	0x00000000	// <ah_lmac+0x526>

Disassembly of section .text.ndp_pspoll_ack_rx_hdl:

00000000 <ndp_pspoll_ack_rx_hdl>: // arg_bytes: 0
   0:	1063      	lrw	r3, 0x0	// regs: r3=0x0
   2:	3000      	movi	r0, 0	// regs: r0=0x0
   4:	dc032265 	st.w	r0, (r3, 0x994)	// *(0x994) = 0x0
   8:	783c      	jmp	r15	// return;
   a:	0000      	.short	0x0000
   c:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_select_tx_acq:

00000000 <lmac_select_tx_acq>: // arg_bytes: 0
   0:	1176      	lrw	r3, 0x0	// regs: r3=0x0
   2:	1137      	lrw	r1, 0x0	// regs: r1=0x0
   4:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   6:	934f      	ld.w	r2, (r3, 0x3c)	// regs: r2=*((*(0x0) + 0x3c))
   8:	9313      	ld.w	r0, (r3, 0x4c)	// regs: r0=*((*(0x0) + 0x4c))
   a:	e400200f 	andi	r0, r0, 15	// regs: r0=(*((*(0x0) + 0x4c)) & 0xf)
   e:	e900005c 	bez	r0, 0xc6	// if (r0 == 0x0) goto loc_c6;
  12:	ea0c0064 	movi	r12, 100	// regs: r12=0x64
  16:	c5828020 	divu	r0, r2, r12	// regs: r0=(*((*(0x0) + 0x3c)) / 0x64)
  1a:	7c30      	mult	r0, r12	// regs: r0=((*((*(0x0) + 0x3c)) / 0x64) * 0x64)
  1c:	6082      	subu	r2, r0	// regs: r2=(*((*(0x0) + 0x3c)) - ((*((*(0x0) + 0x3c)) / 0x64) * 0x64))
  1e:	d981030c 	ld.b	r12, (r1, 0x30c)	// regs: r12=*(0x30c)
  22:	7408      	zextb	r0, r2	// regs: r0=zext8((*((*(0x0) + 0x3c)) - ((*((*(0x0) + 0x3c)) / 0x64) * 0x64)))
  24:	6430      	cmphs	r12, r0
  26:	0c19      	bf	0x58	// if (!T) goto loc_58;
  28:	9353      	ld.w	r2, (r3, 0x4c)	// regs: r2=*((*(0x0) + 0x4c))
  2a:	e4422001 	andi	r2, r2, 1	// regs: r2=(*((*(0x0) + 0x4c)) & 0x1)
  2e:	e922004e 	bnez	r2, 0xca	// if (r2 != 0x0) goto loc_ca;
  32:	9353      	ld.w	r2, (r3, 0x4c)	// regs: r2=*((*(0x0) + 0x4c))
  34:	e4422008 	andi	r2, r2, 8	// regs: r2=(*((*(0x0) + 0x4c)) & 0x8)
  38:	e922004d 	bnez	r2, 0xd2	// if (r2 != 0x0) goto loc_d2;
  3c:	9373      	ld.w	r3, (r3, 0x4c)	// regs: r3=*((*(0x0) + 0x4c))
  3e:	e4632004 	andi	r3, r3, 4	// regs: r3=(*((*(0x0) + 0x4c)) & 0x4)
  42:	3b40      	cmpnei	r3, 0
  44:	c4000500 	mvc	r0	// regs: r0=<cond>
  48:	4001      	lsli	r0, r0, 1	// regs: r0=(<cond> << 0x1)
loc_4a:
  4a:	d86109dc 	ld.b	r3, (r1, 0x9dc)	// regs: r3=*(0x9dc)
  4e:	c4605c60 	ins	r3, r0, 3, 0
  52:	dc6109dc 	st.b	r3, (r1, 0x9dc)	// *(0x9dc) = *(0x9dc)
  56:	783c      	jmp	r15	// return;
loc_58:
  58:	d801030d 	ld.b	r0, (r1, 0x30d)	// regs: r0=*(0x30d)
  5c:	6030      	addu	r0, r12	// regs: r0=(*(0x30d) + *(0x30c))
  5e:	6481      	cmplt	r0, r2
  60:	0813      	bt	0x86	// if (T) goto loc_86;
  62:	9353      	ld.w	r2, (r3, 0x4c)	// regs: r2=*((*(0x0) + 0x4c))
  64:	e4422002 	andi	r2, r2, 2	// regs: r2=(*((*(0x0) + 0x4c)) & 0x2)
  68:	e9220033 	bnez	r2, 0xce	// if (r2 != 0x0) goto loc_ce;
  6c:	9353      	ld.w	r2, (r3, 0x4c)	// regs: r2=*((*(0x0) + 0x4c))
  6e:	e4422008 	andi	r2, r2, 8	// regs: r2=(*((*(0x0) + 0x4c)) & 0x8)
  72:	e9220030 	bnez	r2, 0xd2	// if (r2 != 0x0) goto loc_d2;
  76:	9373      	ld.w	r3, (r3, 0x4c)	// regs: r3=*((*(0x0) + 0x4c))
  78:	e4632004 	andi	r3, r3, 4	// regs: r3=(*((*(0x0) + 0x4c)) & 0x4)
  7c:	3b40      	cmpnei	r3, 0
  7e:	c4000500 	mvc	r0	// regs: r0=<cond>
  82:	2000      	addi	r0, 1	// regs: r0=(<cond> + 0x1)
  84:	07e3      	br	0x4a	// goto loc_4a;
loc_86:
  86:	d981030e 	ld.b	r12, (r1, 0x30e)	// regs: r12=*(0x30e)
  8a:	6030      	addu	r0, r12	// regs: r0=((*(0x30d) + *(0x30c)) + *(0x30e))
  8c:	6481      	cmplt	r0, r2
  8e:	9353      	ld.w	r2, (r3, 0x4c)	// regs: r2=*((*(0x0) + 0x4c))
  90:	0810      	bt	0xb0	// if (T) goto loc_b0;
  92:	e4422004 	andi	r2, r2, 4	// regs: r2=(*((*(0x0) + 0x4c)) & 0x4)
  96:	e9220016 	bnez	r2, 0xc2	// if (r2 != 0x0) goto loc_c2;
  9a:	9353      	ld.w	r2, (r3, 0x4c)	// regs: r2=*((*(0x0) + 0x4c))
  9c:	e4422008 	andi	r2, r2, 8	// regs: r2=(*((*(0x0) + 0x4c)) & 0x8)
  a0:	e9220019 	bnez	r2, 0xd2	// if (r2 != 0x0) goto loc_d2;
loc_a4:
  a4:	9313      	ld.w	r0, (r3, 0x4c)	// regs: r0=*((*(0x0) + 0x4c))
  a6:	e4004002 	xori	r0, r0, 2	// regs: r0=(*((*(0x0) + 0x4c)) ^ 0x2)
  aa:	c4205420 	zext	r0, r0, 1, 1	// regs: r0=zext((*((*(0x0) + 0x4c)) ^ 0x2))
  ae:	07ce      	br	0x4a	// goto loc_4a;
loc_b0:
  b0:	e4422008 	andi	r2, r2, 8	// regs: r2=(*((*(0x0) + 0x4c)) & 0x8)
  b4:	e922000f 	bnez	r2, 0xd2	// if (r2 != 0x0) goto loc_d2;
  b8:	9353      	ld.w	r2, (r3, 0x4c)	// regs: r2=*((*(0x0) + 0x4c))
  ba:	e4422004 	andi	r2, r2, 4	// regs: r2=(*((*(0x0) + 0x4c)) & 0x4)
  be:	e902fff3 	bez	r2, 0xa4	// if (r2 == 0x0) goto loc_a4;
loc_c2:
  c2:	3002      	movi	r0, 2	// regs: r0=0x2
  c4:	07c3      	br	0x4a	// goto loc_4a;
loc_c6:
  c6:	3004      	movi	r0, 4	// regs: r0=0x4
  c8:	07c1      	br	0x4a	// goto loc_4a;
loc_ca:
  ca:	3001      	movi	r0, 1	// regs: r0=0x1
  cc:	07bf      	br	0x4a	// goto loc_4a;
loc_ce:
  ce:	3000      	movi	r0, 0	// regs: r0=0x0
  d0:	07bd      	br	0x4a	// goto loc_4a;
loc_d2:
  d2:	3003      	movi	r0, 3	// regs: r0=0x3
  d4:	07bb      	br	0x4a	// goto loc_4a;
  d6:	0000      	.short	0x0000
  d8:	00000000 	.long	0x00000000	// <LMAC>
  dc:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.ndp_tx_vec_init:

00000000 <ndp_tx_vec_init>: // arg_bytes: 4
   0:	330f      	movi	r3, 15	// regs: r3=0xf
   2:	ea0c0001 	movi	r12, 1	// regs: r12=0x1
   6:	ea0d0000 	movi	r13, 0	// regs: r13=0x0
   a:	3200      	movi	r2, 0	// regs: r2=0x0
   c:	dda02000 	st.w	r13, (r0, 0x0)	// *(<arg0>) = 0x0
  10:	c44c5c64 	ins	r2, r12, 7, 4
  14:	a062      	st.b	r3, (r0, 0x2)	// *(<arg0> + 0x2) = 0xf
  16:	a041      	st.b	r2, (r0, 0x1)	// *(<arg0> + 0x1) = 0x0
  18:	107c      	lrw	r3, 0x0	// regs: r3=0x0
  1a:	d8230308 	ld.b	r1, (r3, 0x308)	// regs: r1=*(0x308)
  1e:	c4415c20 	ins	r2, r1, 1, 0
  22:	a041      	st.b	r2, (r0, 0x1)	// *(<arg0> + 0x1) = 0x0
  24:	d823034a 	ld.b	r1, (r3, 0x34a)	// regs: r1=*(0x34a)
  28:	6870      	and	r1, r12	// regs: r1=(*(0x34a) & 0x1)
  2a:	8041      	ld.b	r2, (r0, 0x1)	// regs: r2=*(<arg0> + 0x1)
  2c:	e9010022 	bez	r1, 0x70	// if (r1 == 0x0) goto loc_70;
  30:	c44d5c22 	ins	r2, r13, 3, 2
  34:	a041      	st.b	r2, (r0, 0x1)	// *(<arg0> + 0x1) = *(<arg0> + 0x1)
  36:	328c      	movi	r2, 140	// regs: r2=0x8c
  38:	d823219a 	ld.w	r1, (r3, 0x668)	// regs: r1=*(0x668)
  3c:	4242      	lsli	r2, r2, 2	// regs: r2=0x230
  3e:	c4225dec 	ins	r1, r2, 27, 12
  42:	dc23219a 	st.w	r1, (r3, 0x668)	// *(0x668) = *(0x668)
loc_46:
  46:	8022      	ld.b	r1, (r0, 0x2)	// regs: r1=*(<arg0> + 0x2)
  48:	3200      	movi	r2, 0	// regs: r2=0x0
  4a:	c4225c07 	ins	r1, r2, 7, 7
  4e:	a022      	st.b	r1, (r0, 0x2)	// *(<arg0> + 0x2) = *(<arg0> + 0x2)
  50:	ea0c0001 	movi	r12, 1	// regs: r12=0x1
  54:	8020      	ld.b	r1, (r0, 0x0)	// regs: r1=*(<arg0>)
  56:	c42c5c05 	ins	r1, r12, 5, 5
  5a:	a020      	st.b	r1, (r0, 0x0)	// *(<arg0>) = *(<arg0>)
  5c:	d86311b6 	ld.h	r3, (r3, 0x36c)	// regs: r3=*(0x36c)
  60:	8020      	ld.b	r1, (r0, 0x0)	// regs: r1=*(<arg0>)
  62:	c4a35523 	zext	r3, r3, 9, 5	// regs: r3=zext(*(0x36c))
  66:	c4235c80 	ins	r1, r3, 4, 0
  6a:	a020      	st.b	r1, (r0, 0x0)	// *(<arg0>) = *(<arg0>)
  6c:	b041      	st.w	r2, (r0, 0x4)	// *(<arg0> + 0x4) = 0x0
  6e:	783c      	jmp	r15	// return;
loc_70:
  70:	c44c5c22 	ins	r2, r12, 3, 2
  74:	a041      	st.b	r2, (r0, 0x1)	// *(<arg0> + 0x1) = *(<arg0> + 0x1)
  76:	d843219a 	ld.w	r2, (r3, 0x668)	// regs: r2=*(0x668)
  7a:	31f0      	movi	r1, 240	// regs: r1=0xf0
  7c:	c4415dec 	ins	r2, r1, 27, 12
  80:	dc43219a 	st.w	r2, (r3, 0x668)	// *(0x668) = *(0x668)
  84:	07e1      	br	0x46	// goto loc_46;
  86:	0000      	.short	0x0000
  88:	0000      	.short	0x0000	// <ah_lmac>
  8a:	0000      	.short	0x0000

Disassembly of section .text.lmac_check_aggregation:

00000000 <lmac_check_aggregation>: // arg_bytes: 8
   0:	14d3      	push	r4-r6, r15
   2:	6d87      	mov	r6, r1	// regs: r6=<arg1>
   4:	e900006e 	bez	r0, 0xe0	// if (r0 == 0x0) goto loc_e0;
   8:	e901006c 	bez	r1, 0xe0	// if (r1 == 0x0) goto loc_e0;
   c:	9088      	ld.w	r4, (r0, 0x20)	// regs: r4=*(<arg0> + 0x20)
   e:	91a8      	ld.w	r5, (r1, 0x20)	// regs: r5=*(<arg1> + 0x20)
  10:	9462      	ld.w	r3, (r4, 0x8)	// regs: r3=*((*(<arg0> + 0x20) + 0x8))
  12:	e4632001 	andi	r3, r3, 1	// regs: r3=(*((*(<arg0> + 0x20) + 0x8)) & 0x1)
  16:	e9230065 	bnez	r3, 0xe0	// if (r3 != 0x0) goto loc_e0;
  1a:	9562      	ld.w	r3, (r5, 0x8)	// regs: r3=*((*(<arg1> + 0x20) + 0x8))
  1c:	e4632001 	andi	r3, r3, 1	// regs: r3=(*((*(<arg1> + 0x20) + 0x8)) & 0x1)
  20:	e9230060 	bnez	r3, 0xe0	// if (r3 != 0x0) goto loc_e0;
  24:	d8640027 	ld.b	r3, (r4, 0x27)	// regs: r3=*((*(<arg0> + 0x20) + 0x27))
  28:	e4632008 	andi	r3, r3, 8	// regs: r3=(*((*(<arg0> + 0x20) + 0x27)) & 0x8)
  2c:	e923005a 	bnez	r3, 0xe0	// if (r3 != 0x0) goto loc_e0;
  30:	d8650027 	ld.b	r3, (r5, 0x27)	// regs: r3=*((*(<arg1> + 0x20) + 0x27))
  34:	e4632008 	andi	r3, r3, 8	// regs: r3=(*((*(<arg1> + 0x20) + 0x27)) & 0x8)
  38:	e9230054 	bnez	r3, 0xe0	// if (r3 != 0x0) goto loc_e0;
  3c:	d8640025 	ld.b	r3, (r4, 0x25)	// regs: r3=*((*(<arg0> + 0x20) + 0x25))
  40:	d8450025 	ld.b	r2, (r5, 0x25)	// regs: r2=*((*(<arg1> + 0x20) + 0x25))
  44:	6cc9      	xor	r3, r2	// regs: r3=(*((*(<arg0> + 0x20) + 0x25)) ^ *((*(<arg1> + 0x20) + 0x25)))
  46:	e4632040 	andi	r3, r3, 64	// regs: r3=((*((*(<arg0> + 0x20) + 0x25)) ^ *((*(<arg1> + 0x20) + 0x25))) & 0x40)
  4a:	e923004b 	bnez	r3, 0xe0	// if (r3 != 0x0) goto loc_e0;
  4e:	d844003c 	ld.b	r2, (r4, 0x3c)	// regs: r2=*((*(<arg0> + 0x20) + 0x3c))
  52:	d865003c 	ld.b	r3, (r5, 0x3c)	// regs: r3=*((*(<arg1> + 0x20) + 0x3c))
  56:	64ca      	cmpne	r2, r3
  58:	0844      	bt	0xe0	// if (T) goto loc_e0;
  5a:	d844003d 	ld.b	r2, (r4, 0x3d)	// regs: r2=*((*(<arg0> + 0x20) + 0x3d))
  5e:	d865003d 	ld.b	r3, (r5, 0x3d)	// regs: r3=*((*(<arg1> + 0x20) + 0x3d))
  62:	64ca      	cmpne	r2, r3
  64:	083e      	bt	0xe0	// if (T) goto loc_e0;
  66:	d864003f 	ld.b	r3, (r4, 0x3f)	// regs: r3=*((*(<arg0> + 0x20) + 0x3f))
  6a:	d845003f 	ld.b	r2, (r5, 0x3f)	// regs: r2=*((*(<arg1> + 0x20) + 0x3f))
  6e:	6cc9      	xor	r3, r2	// regs: r3=(*((*(<arg0> + 0x20) + 0x3f)) ^ *((*(<arg1> + 0x20) + 0x3f)))
  70:	e4632060 	andi	r3, r3, 96	// regs: r3=((*((*(<arg0> + 0x20) + 0x3f)) ^ *((*(<arg1> + 0x20) + 0x3f))) & 0x60)
  74:	e9230036 	bnez	r3, 0xe0	// if (r3 != 0x0) goto loc_e0;
  78:	d8640026 	ld.b	r3, (r4, 0x26)	// regs: r3=*((*(<arg0> + 0x20) + 0x26))
  7c:	d8450026 	ld.b	r2, (r5, 0x26)	// regs: r2=*((*(<arg1> + 0x20) + 0x26))
  80:	6cc9      	xor	r3, r2	// regs: r3=(*((*(<arg0> + 0x20) + 0x26)) ^ *((*(<arg1> + 0x20) + 0x26)))
  82:	e463200f 	andi	r3, r3, 15	// regs: r3=((*((*(<arg0> + 0x20) + 0x26)) ^ *((*(<arg1> + 0x20) + 0x26))) & 0xf)
  86:	e923002d 	bnez	r3, 0xe0	// if (r3 != 0x0) goto loc_e0;
  8a:	9047      	ld.w	r2, (r0, 0x1c)	// regs: r2=*(<arg0> + 0x1c)
  8c:	8261      	ld.b	r3, (r2, 0x1)	// regs: r3=*((*(<arg0> + 0x1c) + 0x1))
  8e:	4368      	lsli	r3, r3, 8	// regs: r3=(*((*(<arg0> + 0x1c) + 0x1)) << 0x8)
  90:	8200      	ld.b	r0, (r2, 0x0)	// regs: r0=*(*(<arg0> + 0x1c))
  92:	6c0c      	or	r0, r3	// regs: r0=(*(*(<arg0> + 0x1c)) | (*((*(<arg0> + 0x1c) + 0x1)) << 0x8))
  94:	e0000000 	bsr	0x0	// <ieee80211_is_data>; regs: r0=<ret ieee80211_is_data@0x94>, r1=<clobbered>
  98:	e9000024 	bez	r0, 0xe0	// if (r0 == 0x0) goto loc_e0;
  9c:	9647      	ld.w	r2, (r6, 0x1c)	// regs: r2=*(<arg1> + 0x1c)
  9e:	8261      	ld.b	r3, (r2, 0x1)	// regs: r3=*((*(<arg1> + 0x1c) + 0x1))
  a0:	4368      	lsli	r3, r3, 8	// regs: r3=(*((*(<arg1> + 0x1c) + 0x1)) << 0x8)
  a2:	8200      	ld.b	r0, (r2, 0x0)	// regs: r0=*(*(<arg1> + 0x1c))
  a4:	6c0c      	or	r0, r3	// regs: r0=(*(*(<arg1> + 0x1c)) | (*((*(<arg1> + 0x1c) + 0x1)) << 0x8))
  a6:	e0000000 	bsr	0x0	// <ieee80211_is_data>; regs: r0=<ret ieee80211_is_data@0xa6>, r1=<clobbered>
  aa:	e900001b 	bez	r0, 0xe0	// if (r0 == 0x0) goto loc_e0;
  ae:	8c72      	ld.h	r3, (r4, 0x24)	// regs: r3=*((*(<arg0> + 0x20) + 0x24))
  b0:	e46321fc 	andi	r3, r3, 508	// regs: r3=(*((*(<arg0> + 0x20) + 0x24)) & 0x1fc)
  b4:	eb430188 	cmpnei	r3, 392
  b8:	0c14      	bf	0xe0	// if (r3 == 0x188) goto loc_e0;
  ba:	847a      	ld.b	r3, (r4, 0x1a)	// regs: r3=*((*(<arg0> + 0x20) + 0x1a))
  bc:	851a      	ld.b	r0, (r5, 0x1a)	// regs: r0=*((*(<arg1> + 0x20) + 0x1a))
  be:	6c0d      	xor	r0, r3	// regs: r0=(*((*(<arg1> + 0x20) + 0x1a)) ^ *((*(<arg0> + 0x20) + 0x1a)))
  c0:	e4402001 	andi	r2, r0, 1	// regs: r2=((*((*(<arg1> + 0x20) + 0x1a)) ^ *((*(<arg0> + 0x20) + 0x1a))) & 0x1)
  c4:	e922000e 	bnez	r2, 0xe0	// if (r2 != 0x0) goto loc_e0;
  c8:	e4032001 	andi	r0, r3, 1	// regs: r0=(*((*(<arg0> + 0x20) + 0x1a)) & 0x1)
  cc:	e920000d 	bnez	r0, 0xe6	// if (r0 != 0x0) goto loc_e6;
  d0:	8c4d      	ld.h	r2, (r4, 0x1a)	// regs: r2=*((*(<arg0> + 0x20) + 0x1a))
  d2:	8d6d      	ld.h	r3, (r5, 0x1a)	// regs: r3=*((*(<arg1> + 0x20) + 0x1a))
  d4:	64ca      	cmpne	r2, r3
  d6:	0805      	bt	0xe0	// if (T) goto loc_e0;
  d8:	9447      	ld.w	r2, (r4, 0x1c)	// regs: r2=*((*(<arg0> + 0x20) + 0x1c))
  da:	9567      	ld.w	r3, (r5, 0x1c)	// regs: r3=*((*(<arg1> + 0x20) + 0x1c))
  dc:	64ca      	cmpne	r2, r3
  de:	0c03      	bf	0xe4	// if (!T) goto loc_e4;
loc_e0:
  e0:	3000      	movi	r0, 0	// regs: r0=0x0
  e2:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_e4:
  e4:	1493      	pop	r4-r6, r15
loc_e6:
  e6:	6c0b      	mov	r0, r2	// regs: r0=((*((*(<arg1> + 0x20) + 0x1a)) ^ *((*(<arg0> + 0x20) + 0x1a))) & 0x1)
  e8:	07fe      	br	0xe4	// goto loc_e4;

Disassembly of section .text.lmac_tx_data_reload:

00000000 <lmac_tx_data_reload>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	1426      	subi	r14, r14, 24	// regs: r14=(sp - 0x18)
   4:	ea89003f 	lrw	r9, 0x0	// regs: r9=0x0
   8:	3600      	movi	r6, 0	// regs: r6=0x0
   a:	e469006f 	addi	r3, r9, 112	// regs: r3=0x70
   e:	6d5b      	mov	r5, r6	// regs: r5=0x0
  10:	ea88003d 	lrw	r8, 0x0	// regs: r8=0x0
  14:	b865      	st.w	r3, (r14, 0x14)	// local_4 = 0x70
loc_16:
  16:	74d4      	zextb	r3, r5	// regs: r3=zext8(r5)
  18:	115c      	lrw	r2, 0x0	// regs: r2=0x0
  1a:	3401      	movi	r4, 1	// regs: r4=0x1
  1c:	b862      	st.w	r3, (r14, 0x8)	// local_10 = zext8(r5)
  1e:	d8682000 	ld.w	r3, (r8, 0x0)	// regs: r3=*(0x0)
  22:	d0a20022 	ldr.b	r2, (r2, r5 << 0)	// regs: r2=*(0x0 + (r5 << 0))
  26:	9373      	ld.w	r3, (r3, 0x4c)	// regs: r3=*((*(0x0) + 0x4c))
  28:	7108      	lsl	r4, r2
  2a:	690c      	and	r4, r3	// regs: r4=(0x1 & *((*(0x0) + 0x4c)))
  2c:	e9040016 	bez	r4, 0x58	// if (r4 == 0x0) goto loc_58;
loc_30:
  30:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  32:	3d44      	cmpnei	r5, 4
  34:	260b      	addi	r6, 12	// regs: r6=(r6 + 0xc)
  36:	0bf0      	bt	0x16	// if (r5 != 0x4) goto loc_16;
loc_38:
  38:	1115      	lrw	r0, 0x0	// regs: r0=0x0
  3a:	e0000000 	bsr	0x0	// <skb_list_count>; regs: r0=<ret skb_list_count@0x3a>, r1=<clobbered>
  3e:	e9000059 	bez	r0, 0xf0	// if (r0 == 0x0) goto loc_f0;
loc_42:
  42:	d8682000 	ld.w	r3, (r8, 0x0)	// regs: r3=*(0x0)
  46:	3200      	movi	r2, 0	// regs: r2=0x0
  48:	b353      	st.w	r2, (r3, 0x4c)	// *((*(0x0) + 0x4c)) = 0x0
  4a:	320f      	movi	r2, 15	// regs: r2=0xf
  4c:	b353      	st.w	r2, (r3, 0x4c)	// *((*(0x0) + 0x4c)) = 0xf
  4e:	1111      	lrw	r0, 0x0	// regs: r0=0x0
  50:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x50>, r1=<clobbered>
  54:	1406      	addi	r14, r14, 24	// regs: r14=((sp - 0x18) + 0x18)
  56:	1498      	pop	r4-r11, r15
loc_58:
  58:	9805      	ld.w	r0, (r14, 0x14)	// regs: r0=local_4
  5a:	e0000000 	bsr	0x0	// <skb_list_first>; regs: r0=<ret skb_list_first@0x5a>, r1=<clobbered>
  5e:	6ec3      	mov	r11, r0	// regs: r11=<ret skb_list_first@0x5a>
  60:	e900ffec 	bez	r0, 0x38	// if (r0 == 0x0) goto loc_38;
  64:	e4460087 	addi	r2, r6, 136	// regs: r2=(r6 + 0x88)
  68:	c4490023 	addu	r3, r9, r2	// regs: r3=(0x0 + (r6 + 0x88))
  6c:	b861      	st.w	r3, (r14, 0x4)	// local_14 = (0x0 + (r6 + 0x88))
  6e:	11e8      	lrw	r7, 0x0	// regs: r7=0x0
  70:	1169      	lrw	r3, 0x0	// regs: r3=0x0
  72:	b863      	st.w	r3, (r14, 0xc)	// local_c = 0x0
  74:	e46704c7 	addi	r3, r7, 1224	// regs: r3=0x4c8
  78:	b864      	st.w	r3, (r14, 0x10)	// local_8 = 0x4c8
loc_7a:
  7a:	65ee      	cmpne	r11, r7
  7c:	0fda      	bf	0x30	// if (!T) goto loc_30;
  7e:	d94b2008 	ld.w	r10, (r11, 0x20)	// regs: r10=*(r11 + 0x20)
  82:	d86b2000 	ld.w	r3, (r11, 0x0)	// regs: r3=*(r11)
  86:	b860      	st.w	r3, (r14, 0x0)	// local_18 = *(r11)
  88:	d84a0026 	ld.b	r2, (r10, 0x26)	// regs: r2=*((*(r11 + 0x20) + 0x26))
  8c:	9863      	ld.w	r3, (r14, 0xc)	// regs: r3=local_c
  8e:	e4422007 	andi	r2, r2, 7	// regs: r2=(*((*(r11 + 0x20) + 0x26)) & 0x7)
  92:	d0430022 	ldr.b	r2, (r3, r2 << 0)	// regs: r2=*(local_c + ((*((*(r11 + 0x20) + 0x26)) & 0x7) << 0))
  96:	9862      	ld.w	r3, (r14, 0x8)	// regs: r3=local_10
  98:	64ca      	cmpne	r2, r3
  9a:	0822      	bt	0xde	// if (T) goto loc_de;
  9c:	6c53      	mov	r1, r4	// regs: r1=r4
  9e:	6c2f      	mov	r0, r11	// regs: r0=r11
  a0:	e0000000 	bsr	0x0	// <lmac_check_aggregation> // arg_bytes: 8; regs: r0=<ret lmac_check_aggregation@0xa0>, r1=<clobbered>
  a4:	e9000004 	bez	r0, 0xac	// if (r0 == 0x0) goto loc_ac;
  a8:	e924001b 	bnez	r4, 0xde	// if (r4 != 0x0) goto loc_de;
loc_ac:
  ac:	6c5f      	mov	r1, r7	// regs: r1=0x0
  ae:	6c2f      	mov	r0, r11	// regs: r0=r11
  b0:	e0000000 	bsr	0x0	// <skb_list_unlink>; regs: r0=<ret skb_list_unlink@0xb0>, r1=<clobbered>
  b4:	d84a2003 	ld.w	r2, (r10, 0xc)	// regs: r2=*((*(r11 + 0x20) + 0xc))
  b8:	e9020016 	bez	r2, 0xe4	// if (r2 == 0x0) goto loc_e4;
  bc:	d842006b 	ld.b	r2, (r2, 0x6b)	// regs: r2=*((*((*(r11 + 0x20) + 0xc)) + 0x6b))
  c0:	e4422030 	andi	r2, r2, 48	// regs: r2=(*((*((*(r11 + 0x20) + 0xc)) + 0x6b)) & 0x30)
  c4:	e9020010 	bez	r2, 0xe4	// if (r2 == 0x0) goto loc_e4;
  c8:	d84b002a 	ld.b	r2, (r11, 0x2a)	// regs: r2=*(r11 + 0x2a)
  cc:	3100      	movi	r1, 0	// regs: r1=0x0
  ce:	c4415c04 	ins	r2, r1, 4, 4
  d2:	dc4b002a 	st.b	r2, (r11, 0x2a)	// *(r11 + 0x2a) = *(r11 + 0x2a)
  d6:	6c6f      	mov	r1, r11	// regs: r1=r11
  d8:	9804      	ld.w	r0, (r14, 0x10)	// regs: r0=local_8
  da:	e0000000 	bsr	0x0	// <skb_list_queue>; regs: r0=<ret skb_list_queue@0xda>, r1=<clobbered>
loc_de:
  de:	d96e2000 	ld.w	r11, (r14, 0x0)	// regs: r11=local_18
  e2:	07cc      	br	0x7a	// goto loc_7a;
loc_e4:
  e4:	6c6f      	mov	r1, r11	// regs: r1=r11
  e6:	9801      	ld.w	r0, (r14, 0x4)	// regs: r0=local_14
  e8:	e0000000 	bsr	0x0	// <skb_list_queue>; regs: r0=<ret skb_list_queue@0xe8>, r1=<clobbered>
  ec:	6d2f      	mov	r4, r11	// regs: r4=r11
  ee:	07f8      	br	0xde	// goto loc_de;
loc_f0:
  f0:	104a      	lrw	r2, 0x0	// regs: r2=0x0
  f2:	d86221eb 	ld.w	r3, (r2, 0x7ac)	// regs: r3=*(0x7ac)
  f6:	2300      	addi	r3, 1	// regs: r3=(*(0x7ac) + 0x1)
  f8:	dc6221eb 	st.w	r3, (r2, 0x7ac)	// *(0x7ac) = (*(0x7ac) + 0x1)
  fc:	07a3      	br	0x42	// goto loc_42;
  fe:	0000      	.short	0x0000
 100:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
 102:	0000      	.short	0x0000
 104:	00000000 	.long	0x00000000	// <LMAC>
 108:	00000000 	.long	0x00000000	// <.rodata.reg_ac_pd_mapping>
 10c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x70>
 110:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x5c>
 114:	0000      	.short	0x0000	// <.rodata.ieee802_1d_to_ac>
 116:	0000      	.short	0x0000
 118:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_update_frm_tx_vec:

00000000 <lmac_update_frm_tx_vec>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	1072      	lrw	r3, 0x0	// regs: r3=0x0
   4:	d88309dc 	ld.b	r4, (r3, 0x9dc)	// regs: r4=*(0x9dc)
   8:	e484200f 	andi	r4, r4, 15	// regs: r4=(*(0x9dc) & 0xf)
   c:	3c03      	cmphsi	r4, 4
   e:	0819      	bt	0x40	// if (r4 >= 0x4) goto loc_40;
  10:	3390      	movi	r3, 144	// regs: r3=0x90
  12:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  14:	10ce      	lrw	r6, 0x0	// regs: r6=0x0
  16:	c4648422 	mult	r2, r4, r3	// regs: r2=((*(0x9dc) & 0xf) * 0x120)
  1a:	6098      	addu	r2, r6	// regs: r2=(((*(0x9dc) & 0xf) * 0x120) )
  1c:	6d4f      	mov	r5, r3	// regs: r5=0x120
  1e:	d84201c7 	ld.b	r2, (r2, 0x1c7)	// regs: r2=*(((((*(0x9dc) & 0xf) * 0x120) ) + 0x1c7))
  22:	c4425442 	zext	r2, r2, 2, 2	// regs: r2=zext(*(((((*(0x9dc) & 0xf) * 0x120) ) + 0x1c7)))
  26:	e9220005 	bnez	r2, 0x30	// if (r2 != 0x0) goto loc_30;
  2a:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  2c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2c>, r1=<clobbered>
loc_30:
  30:	7d14      	mult	r4, r5	// regs: r4=((*(0x9dc) & 0xf) * 0x120)
  32:	e48401c7 	addi	r4, r4, 456	// regs: r4=(((*(0x9dc) & 0xf) * 0x120) + 0x1c8)
  36:	6118      	addu	r4, r6	// regs: r4=((((*(0x9dc) & 0xf) * 0x120) + 0x1c8) )
  38:	b681      	st.w	r4, (r6, 0x4)	// *(0x4) = ((((*(0x9dc) & 0xf) * 0x120) + 0x1c8) )
  3a:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part1> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part1@0x3a>, r1=<clobbered>
loc_3e:
  3e:	1493      	pop	r4-r6, r15
loc_40:
  40:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  42:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x42>, r1=<clobbered>
  46:	07fc      	br	0x3e	// goto loc_3e;
  48:	0000      	.short	0x0000	// <ah_lmac>
  4a:	0000      	.short	0x0000
  4c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  50:	0000      	.short	0x0000	// <.rodata.lmac_update_frm_tx_vec.str1.1>
  52:	0000      	.short	0x0000
  54:	00000000 	.long	0x00000000	// <.rodata.lmac_update_frm_tx_vec.str1.1+0x1f>

Disassembly of section .text.lmac_update_ndp_cts_tx_vec:

00000000 <lmac_update_ndp_cts_tx_vec>: // arg_bytes: 8
   0:	14d0      	push	r15
   2:	1056      	lrw	r2, 0x0	// regs: r2=0x0
   4:	1076      	lrw	r3, 0x0	// regs: r3=0x0
   6:	d842034a 	ld.b	r2, (r2, 0x34a)	// regs: r2=*(0x34a)
   a:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(0x34a) & 0x1)
   e:	dc03215b 	st.w	r0, (r3, 0x56c)	// *(0x56c) = <arg0>
  12:	dc23215c 	st.w	r1, (r3, 0x570)	// *(0x570) = <arg1>
  16:	e902000e 	bez	r2, 0x32	// if (r2 == 0x0) goto loc_32;
  1a:	d843056f 	ld.b	r2, (r3, 0x56f)	// regs: r2=*(0x56f)
  1e:	3101      	movi	r1, 1	// regs: r1=0x1
  20:	c4415c01 	ins	r2, r1, 1, 1
  24:	dc43056f 	st.b	r2, (r3, 0x56f)	// *(0x56f) = *(0x56f)
loc_28:
  28:	104e      	lrw	r2, 0x0	// regs: r2=0x0
  2a:	b341      	st.w	r2, (r3, 0x4)	// *(0x4) = 0x0
  2c:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part1> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part1@0x2c>, r1=<clobbered>
  30:	1490      	pop	r15
loc_32:
  32:	e4212001 	andi	r1, r1, 1	// regs: r1=(<arg1> & 0x1)
  36:	481e      	lsri	r0, r0, 30	// regs: r0=(<arg0> >> 0x1e)
  38:	4122      	lsli	r1, r1, 2	// regs: r1=((<arg1> & 0x1) << 0x2)
  3a:	6c40      	or	r1, r0	// regs: r1=(((<arg1> & 0x1) << 0x2) | (<arg0> >> 0x1e))
  3c:	d8430565 	ld.b	r2, (r3, 0x565)	// regs: r2=*(0x565)
  40:	c4415c20 	ins	r2, r1, 1, 0
  44:	dc430565 	st.b	r2, (r3, 0x565)	// *(0x565) = *(0x565)
  48:	3101      	movi	r1, 1	// regs: r1=0x1
  4a:	d8430570 	ld.b	r2, (r3, 0x570)	// regs: r2=*(0x570)
  4e:	c4415c05 	ins	r2, r1, 5, 5
  52:	dc430570 	st.b	r2, (r3, 0x570)	// *(0x570) = *(0x570)
  56:	07e9      	br	0x28	// goto loc_28;
  58:	00000000 	.long	0x00000000	// <ah_lmac>
  5c:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  5e:	0000      	.short	0x0000
  60:	0000      	.short	0x0000	// <.bss.ah_lmac_tx+0x564>
  62:	0000      	.short	0x0000

Disassembly of section .text.lmac_update_ndp_ack_tx_vec:

00000000 <lmac_update_ndp_ack_tx_vec>: // arg_bytes: 8
   0:	14d0      	push	r15
   2:	1050      	lrw	r2, 0x0	// regs: r2=0x0
   4:	1070      	lrw	r3, 0x0	// regs: r3=0x0
   6:	d842034a 	ld.b	r2, (r2, 0x34a)	// regs: r2=*(0x34a)
   a:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(0x34a) & 0x1)
   e:	dc03215f 	st.w	r0, (r3, 0x57c)	// *(0x57c) = <arg0>
  12:	dc232160 	st.w	r1, (r3, 0x580)	// *(0x580) = <arg1>
  16:	3101      	movi	r1, 1	// regs: r1=0x1
  18:	e902000d 	bez	r2, 0x32	// if (r2 == 0x0) goto loc_32;
  1c:	d843057f 	ld.b	r2, (r3, 0x57f)	// regs: r2=*(0x57f)
  20:	c4415c01 	ins	r2, r1, 1, 1
  24:	dc43057f 	st.b	r2, (r3, 0x57f)	// *(0x57f) = *(0x57f)
loc_28:
  28:	1048      	lrw	r2, 0x0	// regs: r2=0x0
  2a:	b341      	st.w	r2, (r3, 0x4)	// *(0x4) = 0x0
  2c:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part1> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part1@0x2c>, r1=<clobbered>
  30:	1490      	pop	r15
loc_32:
  32:	d8430580 	ld.b	r2, (r3, 0x580)	// regs: r2=*(0x580)
  36:	c4415c05 	ins	r2, r1, 5, 5
  3a:	dc430580 	st.b	r2, (r3, 0x580)	// *(0x580) = *(0x580)
  3e:	07f5      	br	0x28	// goto loc_28;
  40:	0000      	.short	0x0000	// <ah_lmac>
  42:	0000      	.short	0x0000
  44:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  48:	0000      	.short	0x0000	// <.bss.ah_lmac_tx+0x574>
  4a:	0000      	.short	0x0000

Disassembly of section .text.lmac_update_ndp_ba_tx_vec:

00000000 <lmac_update_ndp_ba_tx_vec>: // arg_bytes: 8
   0:	14d0      	push	r15
   2:	1050      	lrw	r2, 0x0	// regs: r2=0x0
   4:	1070      	lrw	r3, 0x0	// regs: r3=0x0
   6:	d842034a 	ld.b	r2, (r2, 0x34a)	// regs: r2=*(0x34a)
   a:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(0x34a) & 0x1)
   e:	dc032163 	st.w	r0, (r3, 0x58c)	// *(0x58c) = <arg0>
  12:	dc232164 	st.w	r1, (r3, 0x590)	// *(0x590) = <arg1>
  16:	3101      	movi	r1, 1	// regs: r1=0x1
  18:	e902000d 	bez	r2, 0x32	// if (r2 == 0x0) goto loc_32;
  1c:	d843058f 	ld.b	r2, (r3, 0x58f)	// regs: r2=*(0x58f)
  20:	c4415c01 	ins	r2, r1, 1, 1
  24:	dc43058f 	st.b	r2, (r3, 0x58f)	// *(0x58f) = *(0x58f)
loc_28:
  28:	1048      	lrw	r2, 0x0	// regs: r2=0x0
  2a:	b341      	st.w	r2, (r3, 0x4)	// *(0x4) = 0x0
  2c:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part1> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part1@0x2c>, r1=<clobbered>
  30:	1490      	pop	r15
loc_32:
  32:	d8430590 	ld.b	r2, (r3, 0x590)	// regs: r2=*(0x590)
  36:	c4415c05 	ins	r2, r1, 5, 5
  3a:	dc430590 	st.b	r2, (r3, 0x590)	// *(0x590) = *(0x590)
  3e:	07f5      	br	0x28	// goto loc_28;
  40:	0000      	.short	0x0000	// <ah_lmac>
  42:	0000      	.short	0x0000
  44:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  48:	0000      	.short	0x0000	// <.bss.ah_lmac_tx+0x584>
  4a:	0000      	.short	0x0000

Disassembly of section .text.lmac_update_pv0_wpba_tx_vec:

00000000 <lmac_update_pv0_wpba_tx_vec>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	1065      	lrw	r3, 0x0	// regs: r3=0x0
   4:	e44305d3 	addi	r2, r3, 1492	// regs: r2=0x5d4
   8:	b341      	st.w	r2, (r3, 0x4)	// *(0x4) = 0x5d4
   a:	e0000000 	bsr	0x0	// <pv0_ctrl_uplink_txpwr_gen> // arg_bytes: 0; regs: r0=<ret pv0_ctrl_uplink_txpwr_gen@0xa>, r1=<clobbered>
   e:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part1> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part1@0xe>, r1=<clobbered>
  12:	1490      	pop	r15
  14:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>

Disassembly of section .text.lmac_update_pv0_wpack_tx_vec:

00000000 <lmac_update_pv0_wpack_tx_vec>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	1065      	lrw	r3, 0x0	// regs: r3=0x0
   4:	e44305e3 	addi	r2, r3, 1508	// regs: r2=0x5e4
   8:	b341      	st.w	r2, (r3, 0x4)	// *(0x4) = 0x5e4
   a:	e0000000 	bsr	0x0	// <pv0_ctrl_uplink_txpwr_gen> // arg_bytes: 0; regs: r0=<ret pv0_ctrl_uplink_txpwr_gen@0xa>, r1=<clobbered>
   e:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part1> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part1@0xe>, r1=<clobbered>
  12:	1490      	pop	r15
  14:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>

Disassembly of section .text.lmac_update_pv0_wpcts_tx_vec:

00000000 <lmac_update_pv0_wpcts_tx_vec>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	106e      	lrw	r3, 0x0	// regs: r3=0x0
   4:	108e      	lrw	r4, 0x0	// regs: r4=0x0
   6:	d8630338 	ld.b	r3, (r3, 0x338)	// regs: r3=*(0x338)
   a:	d84405c6 	ld.b	r2, (r4, 0x5c6)	// regs: r2=*(0x5c6)
   e:	c4435443 	zext	r3, r3, 2, 2	// regs: r3=zext(*(0x338))
  12:	c4435c07 	ins	r2, r3, 7, 7
  16:	e46405c3 	addi	r3, r4, 1476	// regs: r3=0x5c4
  1a:	dc4405c6 	st.b	r2, (r4, 0x5c6)	// *(0x5c6) = *(0x5c6)
  1e:	b461      	st.w	r3, (r4, 0x4)	// *(0x4) = 0x5c4
  20:	e0000000 	bsr	0x0	// <pv0_ctrl_uplink_txpwr_gen> // arg_bytes: 0; regs: r0=<ret pv0_ctrl_uplink_txpwr_gen@0x20>, r1=<clobbered>
  24:	9461      	ld.w	r3, (r4, 0x4)	// regs: r3=*(0x4)
  26:	3100      	movi	r1, 0	// regs: r1=0x0
  28:	8342      	ld.b	r2, (r3, 0x2)	// regs: r2=*((*(0x4) + 0x2))
  2a:	c4415c07 	ins	r2, r1, 7, 7
  2e:	a342      	st.b	r2, (r3, 0x2)	// *((*(0x4) + 0x2)) = *((*(0x4) + 0x2))
  30:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part1> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part1@0x30>, r1=<clobbered>
  34:	1491      	pop	r4, r15
  36:	0000      	.short	0x0000
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>

Disassembly of section .text.lmac_update_pv0_cfend_tx_vec:

00000000 <lmac_update_pv0_cfend_tx_vec>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	108f      	lrw	r4, 0x0	// regs: r4=0x0
   4:	e4640603 	addi	r3, r4, 1540	// regs: r3=0x604
   8:	b461      	st.w	r3, (r4, 0x4)	// *(0x4) = 0x604
   a:	e0000000 	bsr	0x0	// <pv0_ctrl_uplink_txpwr_gen> // arg_bytes: 0; regs: r0=<ret pv0_ctrl_uplink_txpwr_gen@0xa>, r1=<clobbered>
   e:	106d      	lrw	r3, 0x0	// regs: r3=0x0
  10:	d843202f 	ld.w	r2, (r3, 0xbc)	// regs: r2=*(0xbc)
  14:	3a42      	cmpnei	r2, 2
  16:	6c93      	mov	r2, r4	// regs: r2=0x0
  18:	080e      	bt	0x34	// if (r2 != 0x2) goto loc_34;
  1a:	d8630308 	ld.b	r3, (r3, 0x308)	// regs: r3=*(0x308)
  1e:	3b01      	cmphsi	r3, 2
  20:	0c0a      	bf	0x34	// if (r3 < 0x2) goto loc_34;
  22:	9461      	ld.w	r3, (r4, 0x4)	// regs: r3=*(0x4)
  24:	3101      	movi	r1, 1	// regs: r1=0x1
  26:	8342      	ld.b	r2, (r3, 0x2)	// regs: r2=*((*(0x4) + 0x2))
loc_28:
  28:	c4415c07 	ins	r2, r1, 7, 7
  2c:	a342      	st.b	r2, (r3, 0x2)	// *((*(0x4) + 0x2)) = *((*(0x4) + 0x2))
  2e:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part1> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part1@0x2e>, r1=<clobbered>
  32:	1491      	pop	r4, r15
loc_34:
  34:	9261      	ld.w	r3, (r2, 0x4)	// regs: r3=*(0x4)
  36:	3100      	movi	r1, 0	// regs: r1=0x0
  38:	8342      	ld.b	r2, (r3, 0x2)	// regs: r2=*((*(0x4) + 0x2))
  3a:	07f7      	br	0x28	// goto loc_28;
  3c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  40:	0000      	.short	0x0000	// <ah_lmac>
  42:	0000      	.short	0x0000

Disassembly of section .text.lmac_reorder_tx_agglist:

00000000 <lmac_reorder_tx_agglist>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	1424      	subi	r14, r14, 16	// regs: r14=(sp - 0x10)
   4:	0375      	lrw	r3, 0x0	// regs: r3=0x0
   6:	3700      	movi	r7, 0	// regs: r7=0x0
   8:	b8e0      	st.w	r7, (r14, 0x0)	// local_10 = 0x0
   a:	b863      	st.w	r3, (r14, 0xc)	// local_4 = 0x0
   c:	6ecf      	mov	r11, r3	// regs: r11=0x0
   e:	ea880089 	lrw	r8, 0x0	// regs: r8=0x0
loc_12:
  12:	3690      	movi	r6, 144	// regs: r6=0x90
  14:	46c1      	lsli	r6, r6, 1	// regs: r6=0x120
  16:	7d9c      	mult	r6, r7	// regs: r6=(0x120 * r7)
  18:	9863      	ld.w	r3, (r14, 0xc)	// regs: r3=local_4
  1a:	60d8      	addu	r3, r6	// regs: r3=(local_4 + (0x120 * r7))
  1c:	ea0a0000 	movi	r10, 0	// regs: r10=0x0
  20:	d86301c5 	ld.b	r3, (r3, 0x1c5)	// regs: r3=*(((local_4 + (0x120 * r7)) + 0x1c5))
  24:	b862      	st.w	r3, (r14, 0x8)	// local_8 = *(((local_4 + (0x120 * r7)) + 0x1c5))
  26:	3348      	movi	r3, 72	// regs: r3=0x48
  28:	7cdc      	mult	r3, r7	// regs: r3=(0x48 * r7)
  2a:	6e6b      	mov	r9, r10	// regs: r9=0x0
  2c:	b861      	st.w	r3, (r14, 0x4)	// local_c = (0x48 * r7)
  2e:	61ac      	addu	r6, r11	// regs: r6=((0x120 * r7) )
loc_30:
  30:	9862      	ld.w	r3, (r14, 0x8)	// regs: r3=local_8
  32:	64e9      	cmplt	r10, r3
  34:	081c      	bt	0x6c	// if (T) goto loc_6c;
  36:	3390      	movi	r3, 144	// regs: r3=0x90
  38:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  3a:	7cdc      	mult	r3, r7	// regs: r3=(0x120 * r7)
  3c:	60ec      	addu	r3, r11	// regs: r3=((0x120 * r7) )
  3e:	2700      	addi	r7, 1	// regs: r7=(r7 + 0x1)
  40:	d82301c7 	ld.b	r1, (r3, 0x1c7)	// regs: r1=*((((0x120 * r7) ) + 0x1c7))
  44:	3000      	movi	r0, 0	// regs: r0=0x0
  46:	3f44      	cmpnei	r7, 4
  48:	c4205c02 	ins	r1, r0, 2, 2
  4c:	dc2301c7 	st.b	r1, (r3, 0x1c7)	// *((((0x120 * r7) ) + 0x1c7)) = *((((0x120 * r7) ) + 0x1c7))
  50:	0be1      	bt	0x12	// if (r7 != 0x4) goto loc_12;
  52:	9860      	ld.w	r3, (r14, 0x0)	// regs: r3=local_10
  54:	e9030009 	bez	r3, 0x66	// if (r3 == 0x0) goto loc_66;
  58:	1317      	lrw	r0, 0x0	// regs: r0=0x0
  5a:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x5a>, r1=<clobbered>
  5e:	ea00064c 	movi	r0, 1612	// regs: r0=0x64c
  62:	e0000000 	bsr	0x0	// <lmac_set_basic_nav>; regs: r0=<ret lmac_set_basic_nav@0x62>, r1=<clobbered>
loc_66:
  66:	9800      	ld.w	r0, (r14, 0x0)	// regs: r0=local_10
  68:	1404      	addi	r14, r14, 16	// regs: r14=((sp - 0x10) + 0x10)
  6a:	1498      	pop	r4-r11, r15
loc_6c:
  6c:	9861      	ld.w	r3, (r14, 0x4)	// regs: r3=local_c
  6e:	c5430021 	addu	r1, r3, r10	// regs: r1=(local_c + r10)
  72:	212d      	addi	r1, 46	// regs: r1=((local_c + r10) + 0x2e)
  74:	d02b0885 	ldr.w	r5, (r11, r1 << 2)	// regs: r5=*(0x0 + (((local_c + r10) + 0x2e) << 2))
  78:	d82809e2 	ld.b	r1, (r8, 0x9e2)	// regs: r1=*(0x9e2)
  7c:	9588      	ld.w	r4, (r5, 0x20)	// regs: r4=*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20))
  7e:	e421200a 	andi	r1, r1, 10	// regs: r1=(*(0x9e2) & 0xa)
  82:	3942      	cmpnei	r1, 2
  84:	d8044027 	ld.bs	r0, (r4, 0x27)	// regs: r0=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x27))
  88:	6443      	mvcv	r1	// regs: r1=<cond>
  8a:	7446      	sextb	r1, r1	// regs: r1=sext8(<cond>)
  8c:	e9a00029 	bhsz	r0, 0xde	// if (r0 >= 0x0) goto loc_de;
  90:	3001      	movi	r0, 1	// regs: r0=0x1
  92:	d985002a 	ld.b	r12, (r5, 0x2a)	// regs: r12=*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x2a))
  96:	c5805c04 	ins	r12, r0, 4, 4
  9a:	dd85002a 	st.b	r12, (r5, 0x2a)	// *((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x2a)) = *((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x2a))
  9e:	d984002c 	ld.b	r12, (r4, 0x2c)	// regs: r12=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x2c))
  a2:	eb4c0000 	cmpnei	r12, 0
  a6:	c4200c20 	incf	r1, r0, 0
  aa:	d8044026 	ld.bs	r0, (r4, 0x26)	// regs: r0=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x26))
  ae:	e980000c 	blz	r0, 0xc6	// if (r0 < 0x0) goto loc_c6;
  b2:	d80820f3 	ld.w	r0, (r8, 0x3cc)	// regs: r0=*(0x3cc)
  b6:	d98820f4 	ld.w	r12, (r8, 0x3d0)	// regs: r12=*(0x3d0)
  ba:	6c30      	or	r0, r12	// regs: r0=(*(0x3cc) | *(0x3d0))
  bc:	e9000005 	bez	r0, 0xc6	// if (r0 == 0x0) goto loc_c6;
  c0:	3396      	movi	r3, 150	// regs: r3=0x96
  c2:	dc6811e4 	st.h	r3, (r8, 0x3c8)	// *(0x3c8) = 0x96
loc_c6:
  c6:	e921002d 	bnez	r1, 0x120	// if (r1 != 0x0) goto loc_120;
loc_ca:
  ca:	9861      	ld.w	r3, (r14, 0x4)	// regs: r3=local_c
  cc:	c5230021 	addu	r1, r3, r9	// regs: r1=(local_c + r9)
  d0:	212d      	addi	r1, 46	// regs: r1=((local_c + r9) + 0x2e)
  d2:	e5290000 	addi	r9, r9, 1	// regs: r9=(r9 + 0x1)
  d6:	d42b0885 	str.w	r5, (r11, r1 << 2)
  da:	7666      	sextb	r9, r9	// regs: r9=sext8((r9 + 0x1))
  dc:	0460      	br	0x19c	// goto loc_19c;
loc_de:
  de:	d9840029 	ld.b	r12, (r4, 0x29)	// regs: r12=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x29))
  e2:	d8080312 	ld.b	r0, (r8, 0x312)	// regs: r0=*(0x312)
  e6:	6430      	cmphs	r12, r0
  e8:	0810      	bt	0x108	// if (T) goto loc_108;
  ea:	d9840028 	ld.b	r12, (r4, 0x28)	// regs: r12=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x28))
  ee:	d8080313 	ld.b	r0, (r8, 0x313)	// regs: r0=*(0x313)
  f2:	6430      	cmphs	r12, r0
  f4:	080a      	bt	0x108	// if (T) goto loc_108;
  f6:	9403      	ld.w	r0, (r4, 0xc)	// regs: r0=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc))
  f8:	e9000056 	bez	r0, 0x1a4	// if (r0 == 0x0) goto loc_1a4;
  fc:	d800006b 	ld.b	r0, (r0, 0x6b)	// regs: r0=*((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x6b))
 100:	e4002030 	andi	r0, r0, 48	// regs: r0=(*((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x6b)) & 0x30)
 104:	e9000050 	bez	r0, 0x1a4	// if (r0 == 0x0) goto loc_1a4;
loc_108:
 108:	d825002a 	ld.b	r1, (r5, 0x2a)	// regs: r1=*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x2a))
 10c:	3000      	movi	r0, 0	// regs: r0=0x0
 10e:	c4205c04 	ins	r1, r0, 4, 4
 112:	dc25002a 	st.b	r1, (r5, 0x2a)	// *((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x2a)) = *((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x2a))
 116:	d82821d7 	ld.w	r1, (r8, 0x75c)	// regs: r1=*(0x75c)
 11a:	2100      	addi	r1, 1	// regs: r1=(*(0x75c) + 0x1)
 11c:	dc2821d7 	st.w	r1, (r8, 0x75c)	// *(0x75c) = (*(0x75c) + 0x1)
loc_120:
 120:	d825002a 	ld.b	r1, (r5, 0x2a)	// regs: r1=*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x2a))
 124:	e4212010 	andi	r1, r1, 16	// regs: r1=(*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x2a)) & 0x10)
 128:	e9010050 	bez	r1, 0x1c8	// if (r1 == 0x0) goto loc_1c8;
 12c:	d8240024 	ld.b	r1, (r4, 0x24)	// regs: r1=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x24))
 130:	e421201c 	andi	r1, r1, 28	// regs: r1=(*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x24)) & 0x1c)
 134:	3948      	cmpnei	r1, 8
 136:	080a      	bt	0x14a	// if (r1 != 0x8) goto loc_14a;
 138:	8c32      	ld.h	r1, (r4, 0x24)	// regs: r1=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x24))
 13a:	e42120e0 	andi	r1, r1, 224	// regs: r1=(*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x24)) & 0xe0)
 13e:	eb410080 	cmpnei	r1, 128
 142:	0804      	bt	0x14a	// if (r1 != 0x80) goto loc_14a;
 144:	111d      	lrw	r0, 0x0	// regs: r0=0x0
 146:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x146>, r1=<clobbered>
loc_14a:
 14a:	9860      	ld.w	r3, (r14, 0x0)	// regs: r3=local_10
 14c:	9423      	ld.w	r1, (r4, 0xc)	// regs: r1=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc))
 14e:	2300      	addi	r3, 1	// regs: r3=(local_10 + 0x1)
 150:	b860      	st.w	r3, (r14, 0x0)	// local_10 = (local_10 + 0x1)
 152:	e9010015 	bez	r1, 0x17c	// if (r1 == 0x0) goto loc_17c;
 156:	d805002a 	ld.b	r0, (r5, 0x2a)	// regs: r0=*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x2a))
 15a:	e4002010 	andi	r0, r0, 16	// regs: r0=(*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x2a)) & 0x10)
 15e:	d984100b 	ld.h	r12, (r4, 0x16)	// regs: r12=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x16))
 162:	e9000058 	bez	r0, 0x212	// if (r0 == 0x0) goto loc_212;
 166:	d80110ea 	ld.h	r0, (r1, 0x1d4)	// regs: r0=*((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d4))
 16a:	2000      	addi	r0, 1	// regs: r0=(*((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d4)) + 0x1)
 16c:	dc0110ea 	st.h	r0, (r1, 0x1d4)	// *((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d4)) = (*((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d4)) + 0x1)
 170:	7733      	sexth	r12, r12	// regs: r12=sext16(*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x16)))
 172:	d8012076 	ld.w	r0, (r1, 0x1d8)	// regs: r0=*((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d8))
 176:	6300      	addu	r12, r0	// regs: r12=(sext16(*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x16))) + *((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d8)))
 178:	dd812076 	st.w	r12, (r1, 0x1d8)	// *((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d8)) = (sext16(*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x16))) + *((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d8)))
loc_17c:
 17c:	6c57      	mov	r1, r5	// regs: r1=*(0x0 + (((local_c + r10) + 0x2e) << 2))
 17e:	1110      	lrw	r0, 0x0	// regs: r0=0x0
 180:	e0000000 	bsr	0x0	// <skb_list_queue>; regs: r0=<ret skb_list_queue@0x180>, r1=<clobbered>
 184:	d82601c5 	ld.b	r1, (r6, 0x1c5)	// regs: r1=*(r6 + 0x1c5)
 188:	2900      	subi	r1, 1	// regs: r1=(*(r6 + 0x1c5) - 0x1)
 18a:	c4eb0020 	addu	r0, r11, r7	// regs: r0=(0x0 + r7)
 18e:	dc2601c5 	st.b	r1, (r6, 0x1c5)	// *(r6 + 0x1c5) = (*(r6 + 0x1c5) - 0x1)
 192:	d8200554 	ld.b	r1, (r0, 0x554)	// regs: r1=*(((0x0 + r7) + 0x554))
 196:	2900      	subi	r1, 1	// regs: r1=(*(((0x0 + r7) + 0x554)) - 0x1)
 198:	dc200554 	st.b	r1, (r0, 0x554)	// *(((0x0 + r7) + 0x554)) = (*(((0x0 + r7) + 0x554)) - 0x1)
loc_19c:
 19c:	e46a0000 	addi	r3, r10, 1	// regs: r3=(r10 + 0x1)
 1a0:	768e      	sextb	r10, r3	// regs: r10=sext8((r10 + 0x1))
 1a2:	0747      	br	0x30	// goto loc_30;
loc_1a4:
 1a4:	e90cff91 	bez	r12, 0xc6	// if (r12 == 0x0) goto loc_c6;
 1a8:	d8040024 	ld.b	r0, (r4, 0x24)	// regs: r0=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x24))
 1ac:	e4002014 	andi	r0, r0, 20	// regs: r0=(*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x24)) & 0x14)
 1b0:	e920ff8b 	bnez	r0, 0xc6	// if (r0 != 0x0) goto loc_c6;
 1b4:	9507      	ld.w	r0, (r5, 0x1c)	// regs: r0=*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x1c))
 1b6:	ea0d0001 	movi	r13, 1	// regs: r13=0x1
 1ba:	d9800001 	ld.b	r12, (r0, 0x1)	// regs: r12=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x1c)) + 0x1))
 1be:	c58d5c03 	ins	r12, r13, 3, 3
 1c2:	dd800001 	st.b	r12, (r0, 0x1)	// *((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x1c)) + 0x1)) = *((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x1c)) + 0x1))
 1c6:	0780      	br	0xc6	// goto loc_c6;
loc_1c8:
 1c8:	9403      	ld.w	r0, (r4, 0xc)	// regs: r0=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc))
 1ca:	e900ffc0 	bez	r0, 0x14a	// if (r0 == 0x0) goto loc_14a;
 1ce:	d800006b 	ld.b	r0, (r0, 0x6b)	// regs: r0=*((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x6b))
 1d2:	e4002002 	andi	r0, r0, 2	// regs: r0=(*((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x6b)) & 0x2)
 1d6:	e900ffba 	bez	r0, 0x14a	// if (r0 == 0x0) goto loc_14a;
 1da:	d8040024 	ld.b	r0, (r4, 0x24)	// regs: r0=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x24))
 1de:	e400201c 	andi	r0, r0, 28	// regs: r0=(*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x24)) & 0x1c)
 1e2:	3848      	cmpnei	r0, 8
 1e4:	0bb3      	bt	0x14a	// if (r0 != 0x8) goto loc_14a;
 1e6:	8c12      	ld.h	r0, (r4, 0x24)	// regs: r0=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x24))
 1e8:	e40020e0 	andi	r0, r0, 224	// regs: r0=(*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x24)) & 0xe0)
 1ec:	eb400080 	cmpnei	r0, 128
 1f0:	0bad      	bt	0x14a	// if (r0 != 0x80) goto loc_14a;
 1f2:	d8040027 	ld.b	r0, (r4, 0x27)	// regs: r0=*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x27))
 1f6:	ea0c0001 	movi	r12, 1	// regs: r12=0x1
 1fa:	c40c5c03 	ins	r0, r12, 3, 3
 1fe:	dc040027 	st.b	r0, (r4, 0x27)	// *((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x27)) = *((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x27))
 202:	dc240029 	st.b	r1, (r4, 0x29)	// *((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x29)) = (*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x2a)) & 0x10)
 206:	dc240028 	st.b	r1, (r4, 0x28)	// *((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x28)) = (*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x2a)) & 0x10)
 20a:	100e      	lrw	r0, 0x0	// regs: r0=0x0
 20c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x20c>, r1=<clobbered>
 210:	075d      	br	0xca	// goto loc_ca;
loc_212:
 212:	d80110eb 	ld.h	r0, (r1, 0x1d6)	// regs: r0=*((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d6))
 216:	2000      	addi	r0, 1	// regs: r0=(*((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d6)) + 0x1)
 218:	dc0110eb 	st.h	r0, (r1, 0x1d6)	// *((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d6)) = (*((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1d6)) + 0x1)
 21c:	7733      	sexth	r12, r12	// regs: r12=sext16(*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x16)))
 21e:	d8012077 	ld.w	r0, (r1, 0x1dc)	// regs: r0=*((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1dc))
 222:	6300      	addu	r12, r0	// regs: r12=(sext16(*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x16))) + *((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1dc)))
 224:	dd812077 	st.w	r12, (r1, 0x1dc)	// *((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1dc)) = (sext16(*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0x16))) + *((*((*((*(0x0 + (((local_c + r10) + 0x2e) << 2)) + 0x20)) + 0xc)) + 0x1dc)))
 228:	07aa      	br	0x17c	// goto loc_17c;
 22a:	0000      	.short	0x0000
 22c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
 230:	00000000 	.long	0x00000000	// <ah_lmac>
 234:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x5c>
 238:	00000000 	.long	0x00000000	// <.rodata.lmac_reorder_tx_agglist.str1.1>
 23c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x538>
 240:	00000000 	.long	0x00000000	// <.rodata.lmac_reorder_tx_agglist.str1.1+0xe>

Disassembly of section .text.lmac_get_first_skb:

00000000 <lmac_get_first_skb>: // arg_bytes: 4
   0:	14d1      	push	r4, r15
   2:	3803      	cmphsi	r0, 4
   4:	6c43      	mov	r1, r0	// regs: r1=<arg0>
   6:	0820      	bt	0x46	// if (r0 >= 0x4) goto loc_46;
   8:	3390      	movi	r3, 144	// regs: r3=0x90
   a:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
   c:	1011      	lrw	r0, 0x0	// regs: r0=0x0
   e:	7cc4      	mult	r3, r1	// regs: r3=(0x120 * <arg0>)
  10:	60c0      	addu	r3, r0	// regs: r3=((0x120 * <arg0>) )
  12:	d84301c5 	ld.b	r2, (r3, 0x1c5)	// regs: r2=*((((0x120 * <arg0>) ) + 0x1c5))
  16:	e902000b 	bez	r2, 0x2c	// if (r2 == 0x0) goto loc_2c;
  1a:	d883202e 	ld.w	r4, (r3, 0xb8)	// regs: r4=*((((0x120 * <arg0>) ) + 0xb8))
  1e:	e9240005 	bnez	r4, 0x28	// if (r4 != 0x0) goto loc_28;
  22:	100d      	lrw	r0, 0x0	// regs: r0=0x0
loc_24:
  24:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x24>, r1=<clobbered>
loc_28:
  28:	6c13      	mov	r0, r4	// regs: r0=r4
  2a:	1491      	pop	r4, r15
loc_2c:
  2c:	7447      	sexth	r1, r1	// regs: r1=sext16(<arg0>)
  2e:	5964      	addu	r3, r1, r1	// regs: r3=(sext16(<arg0>) + sext16(<arg0>))
  30:	604c      	addu	r1, r3	// regs: r1=(sext16(<arg0>) + (sext16(<arg0>) + sext16(<arg0>)))
  32:	4122      	lsli	r1, r1, 2	// regs: r1=((sext16(<arg0>) + (sext16(<arg0>) + sext16(<arg0>))) << 0x2)
  34:	2187      	addi	r1, 136	// regs: r1=(((sext16(<arg0>) + (sext16(<arg0>) + sext16(<arg0>))) << 0x2) + 0x88)
  36:	6004      	addu	r0, r1	// regs: r0=(0x0 + (((sext16(<arg0>) + (sext16(<arg0>) + sext16(<arg0>))) << 0x2) + 0x88))
  38:	e0000000 	bsr	0x0	// <skb_list_first>; regs: r0=<ret skb_list_first@0x38>, r1=<clobbered>
  3c:	6d03      	mov	r4, r0	// regs: r4=<ret skb_list_first@0x38>
  3e:	e920fff5 	bnez	r0, 0x28	// if (r0 != 0x0) goto loc_28;
  42:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  44:	07f0      	br	0x24	// goto loc_24;
loc_46:
  46:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  48:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x48>, r1=<clobbered>
  4c:	3400      	movi	r4, 0	// regs: r4=0x0
  4e:	07ed      	br	0x28	// goto loc_28;
  50:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  52:	0000      	.short	0x0000
  54:	00000000 	.long	0x00000000	// <.rodata.lmac_get_first_skb.str1.1>
  58:	00000000 	.long	0x00000000	// <.rodata.lmac_get_first_skb.str1.1+0x1c>
  5c:	0000      	.short	0x0000	// <.rodata.lmac_get_first_skb.str1.1+0x36>
  5e:	0000      	.short	0x0000

Disassembly of section .text.lmac_update_tx_rate:

00000000 <lmac_update_tx_rate>: // arg_bytes: 12
   0:	14d7      	push	r4-r10, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	3803      	cmphsi	r0, 4
   6:	6d87      	mov	r6, r1	// regs: r6=<arg1>
   8:	6dcb      	mov	r7, r2	// regs: r7=<arg2>
   a:	0c05      	bf	0x14	// if (r0 < 0x4) goto loc_14;
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_10:
  10:	1401      	addi	r14, r14, 4	// regs: r14=(sp + 0x4)
  12:	1497      	pop	r4-r10, r15
loc_14:
  14:	e0000000 	bsr	0x0	// <lmac_get_first_skb> // arg_bytes: 4; regs: r0=<ret lmac_get_first_skb@0x14>, r1=<clobbered>
  18:	e900fffa 	bez	r0, 0xc	// if (r0 == 0x0) goto loc_c;
  1c:	01b2      	lrw	r5, 0x0	// regs: r5=0x0
  1e:	ea8900ce 	lrw	r9, 0x0	// regs: r9=0x0
  22:	d86509e2 	ld.b	r3, (r5, 0x9e2)	// regs: r3=*(0x9e2)
  26:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  2a:	d9002008 	ld.w	r8, (r0, 0x20)	// regs: r8=*(<ret lmac_get_first_skb@0x14> + 0x20)
  2e:	e9030032 	bez	r3, 0x92	// if (r3 == 0x0) goto loc_92;
  32:	d868003d 	ld.b	r3, (r8, 0x3d)	// regs: r3=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x3d))
  36:	3b07      	cmphsi	r3, 8
  38:	0c09      	bf	0x4a	// if (r3 < 0x8) goto loc_4a;
  3a:	d8650866 	ld.b	r3, (r5, 0x866)	// regs: r3=*(0x866)
  3e:	3b07      	cmphsi	r3, 8
  40:	0c05      	bf	0x4a	// if (r3 < 0x8) goto loc_4a;
  42:	3b4a      	cmpnei	r3, 10
  44:	3207      	movi	r2, 7	// regs: r2=0x7
  46:	c4620c40 	inct	r3, r2, 0
loc_4a:
  4a:	d8450892 	ld.b	r2, (r5, 0x892)	// regs: r2=*(0x892)
  4e:	e4422002 	andi	r2, r2, 2	// regs: r2=(*(0x892) & 0x2)
  52:	e9020018 	bez	r2, 0x82	// if (r2 == 0x0) goto loc_82;
  56:	d8450308 	ld.b	r2, (r5, 0x308)	// regs: r2=*(0x308)
  5a:	3a01      	cmphsi	r2, 2
  5c:	c4000501 	mvc	r1	// regs: r1=<cond>
  60:	d8480025 	ld.b	r2, (r8, 0x25)	// regs: r2=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x25))
  64:	c4415c05 	ins	r2, r1, 5, 5
  68:	dc480025 	st.b	r2, (r8, 0x25)	// *((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x25)) = *((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x25))
  6c:	d845034a 	ld.b	r2, (r5, 0x34a)	// regs: r2=*(0x34a)
  70:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(0x34a) & 0x1)
  74:	3a40      	cmpnei	r2, 0
  76:	3100      	movi	r1, 0	// regs: r1=0x0
  78:	3203      	movi	r2, 3	// regs: r2=0x3
  7a:	c4410c20 	incf	r2, r1, 0
  7e:	dc48003c 	st.b	r2, (r8, 0x3c)	// *((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x3c)) = 0x3
loc_82:
  82:	d888003c 	ld.b	r4, (r8, 0x3c)	// regs: r4=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x3c))
  86:	eb4400ff 	cmpnei	r4, 255
  8a:	083d      	bt	0x104	// if (r4 != 0xff) goto loc_104;
loc_8c:
  8c:	d8850867 	ld.b	r4, (r5, 0x867)	// regs: r4=*(0x867)
  90:	043a      	br	0x104	// goto loc_104;
loc_92:
  92:	d8650338 	ld.b	r3, (r5, 0x338)	// regs: r3=*(0x338)
  96:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x338) & 0x8)
  9a:	e9030055 	bez	r3, 0x144	// if (r3 == 0x0) goto loc_144;
  9e:	6c23      	mov	r0, r8	// regs: r0=*(<ret lmac_get_first_skb@0x14> + 0x20)
  a0:	e0000000 	bsr	0x0	// <ah_get_rate>; regs: r0=<ret ah_get_rate@0xa0>, r1=<clobbered>
  a4:	5063      	asri	r3, r0, 3	// regs: r3=(<ret ah_get_rate@0xa0> >> 0x3)
  a6:	e4432008 	andi	r2, r3, 8	// regs: r2=((<ret ah_get_rate@0xa0> >> 0x3) & 0x8)
  aa:	dc081021 	st.h	r0, (r8, 0x42)	// *((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x42)) = <ret ah_get_rate@0xa0>
  ae:	e4002007 	andi	r0, r0, 7	// regs: r0=(<ret ah_get_rate@0xa0> & 0x7)
  b2:	6c08      	or	r0, r2	// regs: r0=((<ret ah_get_rate@0xa0> & 0x7) | ((<ret ah_get_rate@0xa0> >> 0x3) & 0x8))
  b4:	d8450875 	ld.b	r2, (r5, 0x875)	// regs: r2=*(0x875)
  b8:	e4422002 	andi	r2, r2, 2	// regs: r2=(*(0x875) & 0x2)
  bc:	e902003b 	bez	r2, 0x132	// if (r2 == 0x0) goto loc_132;
  c0:	d8850867 	ld.b	r4, (r5, 0x867)	// regs: r4=*(0x867)
loc_c4:
  c4:	d0890023 	ldr.b	r3, (r9, r4 << 0)	// regs: r3=*(0x0 + (r4 << 0))
  c8:	d8450308 	ld.b	r2, (r5, 0x308)	// regs: r2=*(0x308)
  cc:	64c8      	cmphs	r2, r3
  ce:	080a      	bt	0xe2	// if (T) goto loc_e2;
  d0:	d865034a 	ld.b	r3, (r5, 0x34a)	// regs: r3=*(0x34a)
  d4:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x34a) & 0x1)
  d8:	3b40      	cmpnei	r3, 0
  da:	3403      	movi	r4, 3	// regs: r4=0x3
  dc:	3300      	movi	r3, 0	// regs: r3=0x0
  de:	c4830c20 	incf	r4, r3, 0
loc_e2:
  e2:	d8680027 	ld.b	r3, (r8, 0x27)	// regs: r3=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x27))
  e6:	e4632002 	andi	r3, r3, 2	// regs: r3=(*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x27)) & 0x2)
  ea:	e903009c 	bez	r3, 0x222	// if (r3 == 0x0) goto loc_222;
  ee:	d8650866 	ld.b	r3, (r5, 0x866)	// regs: r3=*(0x866)
  f2:	3b07      	cmphsi	r3, 8
  f4:	0c08      	bf	0x104	// if (r3 < 0x8) goto loc_104;
  f6:	3b4a      	cmpnei	r3, 10
  f8:	0c06      	bf	0x104	// if (r3 == 0xa) goto loc_104;
  fa:	d868003d 	ld.b	r3, (r8, 0x3d)	// regs: r3=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x3d))
  fe:	3b07      	cmphsi	r3, 8
 100:	c4600c40 	inct	r3, r0, 0
loc_104:
 104:	d8481013 	ld.h	r2, (r8, 0x26)	// regs: r2=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x26))
 108:	e4422280 	andi	r2, r2, 640	// regs: r2=(*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x26)) & 0x280)
 10c:	eb420280 	cmpnei	r2, 640
 110:	08f3      	bt	0x2f6	// if (r2 != 0x280) goto loc_2f6;
 112:	d8650868 	ld.b	r3, (r5, 0x868)	// regs: r3=*(0x868)
 116:	3b07      	cmphsi	r3, 8
 118:	3401      	movi	r4, 1	// regs: r4=0x1
 11a:	d8450869 	ld.b	r2, (r5, 0x869)	// regs: r2=*(0x869)
 11e:	c4640c40 	inct	r3, r4, 0
 122:	3a44      	cmpnei	r2, 4
 124:	0c82      	bf	0x228	// if (r2 == 0x4) goto loc_228;
 126:	3a48      	cmpnei	r2, 8
 128:	0c7f      	bf	0x226	// if (r2 == 0x8) goto loc_226;
 12a:	3a42      	cmpnei	r2, 2
 12c:	08d0      	bt	0x2cc	// if (r2 != 0x2) goto loc_2cc;
 12e:	3400      	movi	r4, 0	// regs: r4=0x0
 130:	047c      	br	0x228	// goto loc_228;
loc_132:
 132:	d888003c 	ld.b	r4, (r8, 0x3c)	// regs: r4=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x3c))
 136:	eb4400ff 	cmpnei	r4, 255
 13a:	0bc5      	bt	0xc4	// if (r4 != 0xff) goto loc_c4;
 13c:	5b8a      	addi	r4, r3, 3	// regs: r4=((<ret ah_get_rate@0xa0> >> 0x3) + 0x3)
 13e:	e4842003 	andi	r4, r4, 3	// regs: r4=(((<ret ah_get_rate@0xa0> >> 0x3) + 0x3) & 0x3)
 142:	07c1      	br	0xc4	// goto loc_c4;
loc_144:
 144:	d8482003 	ld.w	r2, (r8, 0xc)	// regs: r2=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0xc))
 148:	d868003d 	ld.b	r3, (r8, 0x3d)	// regs: r3=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x3d))
 14c:	d888003c 	ld.b	r4, (r8, 0x3c)	// regs: r4=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x3c))
 150:	e9020012 	bez	r2, 0x174	// if (r2 == 0x0) goto loc_174;
 154:	ea210a00 	movih	r1, 2560	// regs: r1=(0xa00 << 0x10)
 158:	39a9      	bseti	r1, 9	// regs: r1=((0xa00 << 0x10) | (0x1 << 0x9))
 15a:	d8082009 	ld.w	r0, (r8, 0x24)	// regs: r0=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x24))
 15e:	6804      	and	r0, r1	// regs: r0=(*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x24)) & ((0xa00 << 0x10) | (0x1 << 0x9)))
 160:	3180      	movi	r1, 128	// regs: r1=0x80
 162:	4132      	lsli	r1, r1, 18	// regs: r1=0x2000000
 164:	6442      	cmpne	r0, r1
 166:	0807      	bt	0x174	// if (T) goto loc_174;
 168:	d8280024 	ld.b	r1, (r8, 0x24)	// regs: r1=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x24))
 16c:	e4212003 	andi	r1, r1, 3	// regs: r1=(*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x24)) & 0x3)
 170:	3941      	cmpnei	r1, 1
 172:	0826      	bt	0x1be	// if (r1 != 0x1) goto loc_1be;
loc_174:
 174:	74cc      	zextb	r3, r3	// regs: r3=zext8(*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x3d)))
 176:	3b07      	cmphsi	r3, 8
 178:	0c13      	bf	0x19e	// if (r3 < 0x8) goto loc_19e;
 17a:	d8650866 	ld.b	r3, (r5, 0x866)	// regs: r3=*(0x866)
 17e:	3b07      	cmphsi	r3, 8
 180:	0c0f      	bf	0x19e	// if (r3 < 0x8) goto loc_19e;
 182:	3b4a      	cmpnei	r3, 10
 184:	0c0d      	bf	0x19e	// if (r3 == 0xa) goto loc_19e;
 186:	d8650875 	ld.b	r3, (r5, 0x875)	// regs: r3=*(0x875)
 18a:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x875) & 0x2)
 18e:	e9030016 	bez	r3, 0x1ba	// if (r3 == 0x0) goto loc_1ba;
 192:	d8650867 	ld.b	r3, (r5, 0x867)	// regs: r3=*(0x867)
 196:	3b43      	cmpnei	r3, 3
 198:	c4000503 	mvc	r3	// regs: r3=<cond>
 19c:	74cc      	zextb	r3, r3	// regs: r3=zext8(<cond>)
loc_19e:
 19e:	7510      	zextb	r4, r4	// regs: r4=zext8(*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x3c)))
 1a0:	eb4400ff 	cmpnei	r4, 255
 1a4:	0bb0      	bt	0x104	// if (r4 != 0xff) goto loc_104;
 1a6:	d845034a 	ld.b	r2, (r5, 0x34a)	// regs: r2=*(0x34a)
 1aa:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(0x34a) & 0x1)
 1ae:	3a40      	cmpnei	r2, 0
 1b0:	3403      	movi	r4, 3	// regs: r4=0x3
 1b2:	3200      	movi	r2, 0	// regs: r2=0x0
 1b4:	c4820c20 	incf	r4, r2, 0
 1b8:	07a6      	br	0x104	// goto loc_104;
loc_1ba:
 1ba:	3301      	movi	r3, 1	// regs: r3=0x1
 1bc:	07f1      	br	0x19e	// goto loc_19e;
loc_1be:
 1be:	74cc      	zextb	r3, r3	// regs: r3=zext8(*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x3d)))
 1c0:	3b07      	cmphsi	r3, 8
 1c2:	0c0a      	bf	0x1d6	// if (r3 < 0x8) goto loc_1d6;
 1c4:	d8650866 	ld.b	r3, (r5, 0x866)	// regs: r3=*(0x866)
 1c8:	3b07      	cmphsi	r3, 8
 1ca:	0c06      	bf	0x1d6	// if (r3 < 0x8) goto loc_1d6;
 1cc:	3b4a      	cmpnei	r3, 10
 1ce:	0c04      	bf	0x1d6	// if (r3 == 0xa) goto loc_1d6;
 1d0:	d86200ad 	ld.b	r3, (r2, 0xad)	// regs: r3=*((*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0xc)) + 0xad))
 1d4:	4b64      	lsri	r3, r3, 4	// regs: r3=(*((*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0xc)) + 0xad)) >> 0x4)
loc_1d6:
 1d6:	7510      	zextb	r4, r4	// regs: r4=zext8(*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x3c)))
 1d8:	eb4400ff 	cmpnei	r4, 255
 1dc:	0b94      	bt	0x104	// if (r4 != 0xff) goto loc_104;
 1de:	d825037f 	ld.b	r1, (r5, 0x37f)	// regs: r1=*(0x37f)
 1e2:	e4212004 	andi	r1, r1, 4	// regs: r1=(*(0x37f) & 0x4)
 1e6:	e901ff53 	bez	r1, 0x8c	// if (r1 == 0x0) goto loc_8c;
 1ea:	d88200af 	ld.b	r4, (r2, 0xaf)	// regs: r4=*((*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0xc)) + 0xaf))
 1ee:	e484200f 	andi	r4, r4, 15	// regs: r4=(*((*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0xc)) + 0xaf)) & 0xf)
 1f2:	d8050308 	ld.b	r0, (r5, 0x308)	// regs: r0=*(0x308)
 1f6:	d0890021 	ldr.b	r1, (r9, r4 << 0)	// regs: r1=*(0x0 + ((*((*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0xc)) + 0xaf)) & 0xf) << 0))
 1fa:	6406      	cmpne	r1, r0
 1fc:	0805      	bt	0x206	// if (T) goto loc_206;
loc_1fe:
 1fe:	3100      	movi	r1, 0	// regs: r1=0x0
 200:	dc2200b0 	st.b	r1, (r2, 0xb0)	// *((*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0xc)) + 0xb0)) = 0x0
 204:	0780      	br	0x104	// goto loc_104;
loc_206:
 206:	d82200b0 	ld.b	r1, (r2, 0xb0)	// regs: r1=*((*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0xc)) + 0xb0))
 20a:	2100      	addi	r1, 1	// regs: r1=(*((*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0xc)) + 0xb0)) + 0x1)
 20c:	7444      	zextb	r1, r1	// regs: r1=zext8((*((*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0xc)) + 0xb0)) + 0x1))
 20e:	dc2200b0 	st.b	r1, (r2, 0xb0)	// *((*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0xc)) + 0xb0)) = zext8((*((*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0xc)) + 0xb0)) + 0x1))
 212:	d98511de 	ld.h	r12, (r5, 0x3bc)	// regs: r12=*(0x3bc)
 216:	6472      	cmpne	r12, r1
 218:	0b76      	bt	0x104	// if (T) goto loc_104;
 21a:	1230      	lrw	r1, 0x0	// regs: r1=0x0
 21c:	d0010024 	ldr.b	r4, (r1, r0 << 0)	// regs: r4=*(0x0 + (*(0x308) << 0))
 220:	07ef      	br	0x1fe	// goto loc_1fe;
loc_222:
 222:	6cc3      	mov	r3, r0	// regs: r3=((<ret ah_get_rate@0xa0> & 0x7) | ((<ret ah_get_rate@0xa0> >> 0x3) & 0x8))
 224:	0770      	br	0x104	// goto loc_104;
loc_226:
 226:	3402      	movi	r4, 2	// regs: r4=0x2
loc_228:
 228:	d845034a 	ld.b	r2, (r5, 0x34a)	// regs: r2=*(r5 + 0x34a)
 22c:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(r5 + 0x34a) & 0x1)
 230:	e9020054 	bez	r2, 0x2d8	// if (r2 == 0x0) goto loc_2d8;
 234:	d8250864 	ld.b	r1, (r5, 0x864)	// regs: r1=*(r5 + 0x864)
 238:	644c      	cmphs	r3, r1
 23a:	6c87      	mov	r2, r1	// regs: r2=*(r5 + 0x864)
 23c:	0802      	bt	0x240	// if (T) goto loc_240;
 23e:	6c8f      	mov	r2, r3	// regs: r2=r3
loc_240:
 240:	d9450865 	ld.b	r10, (r5, 0x865)	// regs: r10=*(r5 + 0x865)
 244:	74c8      	zextb	r3, r2	// regs: r3=zext8(r2)
 246:	e90a00a3 	bez	r10, 0x38c	// if (r10 == 0x0) goto loc_38c;
 24a:	3b4a      	cmpnei	r3, 10
 24c:	0c04      	bf	0x254	// if (r3 == 0xa) goto loc_254;
 24e:	668c      	cmphs	r3, r10
 250:	c5430c40 	inct	r10, r3, 0
loc_254:
 254:	3c43      	cmpnei	r4, 3
 256:	0c0f      	bf	0x274	// if (r4 == 0x3) goto loc_274;
 258:	eb0a0007 	cmphsi	r10, 8
 25c:	0c0c      	bf	0x274	// if (r10 < 0x8) goto loc_274;
 25e:	d8650308 	ld.b	r3, (r5, 0x308)	// regs: r3=*(r5 + 0x308)
 262:	b860      	st.w	r3, (r14, 0x0)	// stack_0 = *(r5 + 0x308)
 264:	6c93      	mov	r2, r4	// regs: r2=r4
 266:	6ceb      	mov	r3, r10	// regs: r3=r10
 268:	113d      	lrw	r1, 0x0	// regs: r1=0x0
 26a:	111e      	lrw	r0, 0x0	// regs: r0=0x0
 26c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x26c>, r1=<clobbered>
 270:	ea0a0001 	movi	r10, 1	// regs: r10=0x1
loc_274:
 274:	d8650308 	ld.b	r3, (r5, 0x308)	// regs: r3=*(r5 + 0x308)
 278:	d0890022 	ldr.b	r2, (r9, r4 << 0)	// regs: r2=*(r9 + (r4 << 0))
 27c:	648c      	cmphs	r3, r2
 27e:	080f      	bt	0x29c	// if (T) goto loc_29c;
 280:	6c93      	mov	r2, r4	// regs: r2=r4
 282:	1137      	lrw	r1, 0x0	// regs: r1=0x0
 284:	1118      	lrw	r0, 0x0	// regs: r0=0x0
 286:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x286>, r1=<clobbered>
 28a:	d865034a 	ld.b	r3, (r5, 0x34a)	// regs: r3=*(r5 + 0x34a)
 28e:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r5 + 0x34a) & 0x1)
 292:	3b40      	cmpnei	r3, 0
 294:	3403      	movi	r4, 3	// regs: r4=0x3
 296:	3300      	movi	r3, 0	// regs: r3=0x0
 298:	c4830c20 	incf	r4, r3, 0
loc_29c:
 29c:	d848500a 	ld.hs	r2, (r8, 0x14)	// regs: r2=*(r8 + 0x14)
 2a0:	d865119a 	ld.h	r3, (r5, 0x334)	// regs: r3=*(r5 + 0x334)
 2a4:	64c9      	cmplt	r2, r3
 2a6:	0c0a      	bf	0x2ba	// if (r3 == 0x0) goto loc_2ba;
 2a8:	d865034a 	ld.b	r3, (r5, 0x34a)	// regs: r3=*(r5 + 0x34a)
 2ac:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r5 + 0x34a) & 0x1)
 2b0:	3b40      	cmpnei	r3, 0
 2b2:	3403      	movi	r4, 3	// regs: r4=0x3
 2b4:	3300      	movi	r3, 0	// regs: r3=0x0
 2b6:	c4830c20 	incf	r4, r3, 0
loc_2ba:
 2ba:	dd470000 	st.b	r10, (r7, 0x0)	// *(r7) = r10
 2be:	3000      	movi	r0, 0	// regs: r0=0x0
 2c0:	a680      	st.b	r4, (r6, 0x0)	// *(r6) = r4
 2c2:	dd4521ba 	st.w	r10, (r5, 0x6e8)	// *(r5 + 0x6e8) = r10
 2c6:	dc8521bb 	st.w	r4, (r5, 0x6ec)	// *(r5 + 0x6ec) = r4
 2ca:	06a3      	br	0x10	// goto loc_10;
loc_2cc:
 2cc:	d885034a 	ld.b	r4, (r5, 0x34a)	// regs: r4=*(0x34a)
 2d0:	e4842001 	andi	r4, r4, 1	// regs: r4=(*(0x34a) & 0x1)
 2d4:	e924005a 	bnez	r4, 0x388	// if (r4 != 0x0) goto loc_388;
loc_2d8:
 2d8:	d8250864 	ld.b	r1, (r5, 0x864)	// regs: r1=*(r5 + 0x864)
 2dc:	644c      	cmphs	r3, r1
 2de:	6c87      	mov	r2, r1	// regs: r2=*(r5 + 0x864)
 2e0:	0802      	bt	0x2e4	// if (T) goto loc_2e4;
 2e2:	6c8f      	mov	r2, r3	// regs: r2=r3
loc_2e4:
 2e4:	d8650865 	ld.b	r3, (r5, 0x865)	// regs: r3=*(r5 + 0x865)
 2e8:	7448      	zextb	r1, r2	// regs: r1=zext8(r2)
 2ea:	644c      	cmphs	r3, r1
 2ec:	6e8f      	mov	r10, r3	// regs: r10=*(r5 + 0x865)
 2ee:	0802      	bt	0x2f2	// if (T) goto loc_2f2;
 2f0:	6e8b      	mov	r10, r2	// regs: r10=r2
loc_2f2:
 2f2:	76a8      	zextb	r10, r10	// regs: r10=zext8(r10)
 2f4:	07b0      	br	0x254	// goto loc_254;
loc_2f6:
 2f6:	d8450338 	ld.b	r2, (r5, 0x338)	// regs: r2=*(0x338)
 2fa:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0x338) & 0x8)
 2fe:	e9220022 	bnez	r2, 0x342	// if (r2 != 0x0) goto loc_342;
 302:	d845036e 	ld.b	r2, (r5, 0x36e)	// regs: r2=*(0x36e)
 306:	e4422040 	andi	r2, r2, 64	// regs: r2=(*(0x36e) & 0x40)
 30a:	e922001c 	bnez	r2, 0x342	// if (r2 != 0x0) goto loc_342;
 30e:	d84509e2 	ld.b	r2, (r5, 0x9e2)	// regs: r2=*(0x9e2)
 312:	e4422002 	andi	r2, r2, 2	// regs: r2=(*(0x9e2) & 0x2)
 316:	e9220016 	bnez	r2, 0x342	// if (r2 != 0x0) goto loc_342;
 31a:	d8480028 	ld.b	r2, (r8, 0x28)	// regs: r2=*((*(<ret lmac_get_first_skb@0x14> + 0x20) + 0x28))
 31e:	e9020012 	bez	r2, 0x342	// if (r2 == 0x0) goto loc_342;
 322:	3a41      	cmpnei	r2, 1
 324:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
 326:	e4842003 	andi	r4, r4, 3	// regs: r4=((r4 + 0x1) & 0x3)
 32a:	4362      	lsli	r3, r3, 2	// regs: r3=(r3 << 0x2)
 32c:	0820      	bt	0x36c	// if (r2 != 0x1) goto loc_36c;
 32e:	104f      	lrw	r2, 0x0	// regs: r2=0x0
loc_330:
 330:	60c8      	addu	r3, r2	// regs: r3=(r3 )
 332:	d0830024 	ldr.b	r4, (r3, r4 << 0)	// regs: r4=*((r3 ) + (r4 << 0))
 336:	e464200f 	andi	r3, r4, 15	// regs: r3=(*((r3 ) + (r4 << 0)) & 0xf)
 33a:	4c84      	lsri	r4, r4, 4	// regs: r4=(*((r3 ) + (r4 << 0)) >> 0x4)
 33c:	2402      	addi	r4, 3	// regs: r4=((*((r3 ) + (r4 << 0)) >> 0x4) + 0x3)
 33e:	e4842003 	andi	r4, r4, 3	// regs: r4=(((*((r3 ) + (r4 << 0)) >> 0x4) + 0x3) & 0x3)
loc_342:
 342:	3c43      	cmpnei	r4, 3
 344:	0f72      	bf	0x228	// if (r4 == 0x3) goto loc_228;
 346:	3b4a      	cmpnei	r3, 10
 348:	3201      	movi	r2, 1	// regs: r2=0x1
 34a:	c4620c20 	incf	r3, r2, 0
 34e:	076d      	br	0x228	// goto loc_228;
 350:	00000000 	.long	0x00000000	// <ah_lmac>
 354:	00000000 	.long	0x00000000	// <bw_map_sig2bss>
 358:	00000000 	.long	0x00000000	// <bw_map_bss2sig>
 35c:	00000000 	.long	0x00000000	// <.rodata.__func__.13526>
 360:	00000000 	.long	0x00000000	// <.rodata.lmac_update_tx_rate.str1.1>
 364:	00000000 	.long	0x00000000	// <.rodata.lmac_update_tx_rate.str1.1+0x2d>
 368:	00000000 	.long	0x00000000	// <.rodata.rc_tb1>
loc_36c:
 36c:	3a42      	cmpnei	r2, 2
 36e:	0803      	bt	0x374	// if (r2 != 0x2) goto loc_374;
 370:	1048      	lrw	r2, 0x0	// regs: r2=0x0
 372:	07df      	br	0x330	// goto loc_330;
loc_374:
 374:	3a43      	cmpnei	r2, 3
 376:	0803      	bt	0x37c	// if (r2 != 0x3) goto loc_37c;
 378:	1047      	lrw	r2, 0x0	// regs: r2=0x0
 37a:	07db      	br	0x330	// goto loc_330;
loc_37c:
 37c:	3a44      	cmpnei	r2, 4
 37e:	0803      	bt	0x384	// if (r2 != 0x4) goto loc_384;
 380:	1046      	lrw	r2, 0x0	// regs: r2=0x0
 382:	07d7      	br	0x330	// goto loc_330;
loc_384:
 384:	1046      	lrw	r2, 0x0	// regs: r2=0x0
 386:	07d5      	br	0x330	// goto loc_330;
loc_388:
 388:	3403      	movi	r4, 3	// regs: r4=0x3
 38a:	074f      	br	0x228	// goto loc_228;
loc_38c:
 38c:	6e8f      	mov	r10, r3	// regs: r10=zext8(r2)
 38e:	0763      	br	0x254	// goto loc_254;
 390:	00000000 	.long	0x00000000	// <.rodata.rc_tb2>
 394:	00000000 	.long	0x00000000	// <.rodata.rc_tb3>
 398:	00000000 	.long	0x00000000	// <.rodata.rc_tb4>
 39c:	0000      	.short	0x0000	// <.rodata.rc_tb5>
 39e:	0000      	.short	0x0000

Disassembly of section .text.lmac_gen_pspack_ndp2m:

00000000 <lmac_gen_pspack_ndp2m>: // arg_bytes: 0
   0:	783c      	jmp	r15	// return;

Disassembly of section .text.lmac_gen_pspoll_ndp2m:

00000000 <lmac_gen_pspoll_ndp2m>: // arg_bytes: 0
   0:	783c      	jmp	r15	// return;

Disassembly of section .text.lmac_gen_pv0_cfpoll:

00000000 <lmac_gen_pv0_cfpoll>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	1188      	lrw	r4, 0x0	// regs: r4=0x0
   4:	3200      	movi	r2, 0	// regs: r2=0x0
   6:	d864221e 	ld.w	r3, (r4, 0x878)	// regs: r3=*(0x878)
   a:	c5235603 	zext	r3, r3, 16, 9	// regs: r3=zext(*(0x878))
   e:	d8a4227e 	ld.w	r5, (r4, 0x9f8)	// regs: r5=*(0x9f8)
  12:	e42409f7 	addi	r1, r4, 2552	// regs: r1=0x9f8
loc_16:
  16:	6456      	cmpne	r5, r1
  18:	0806      	bt	0x24	// if (T) goto loc_24;
  1a:	64ca      	cmpne	r2, r3
  1c:	3200      	movi	r2, 0	// regs: r2=0x0
  1e:	c4a20c40 	inct	r5, r2, 0
  22:	0403      	br	0x28	// goto loc_28;
loc_24:
  24:	64ca      	cmpne	r2, r3
  26:	0832      	bt	0x8a	// if (T) goto loc_8a;
loc_28:
  28:	2300      	addi	r3, 1	// regs: r3=(zext(*(0x878)) + 0x1)
  2a:	74cc      	zextb	r3, r3	// regs: r3=zext8((zext(*(0x878)) + 0x1))
  2c:	d8241504 	ld.h	r1, (r4, 0xa08)	// regs: r1=*(0xa08)
  30:	d844221e 	ld.w	r2, (r4, 0x878)	// regs: r2=*(0x878)
  34:	644c      	cmphs	r3, r1
  36:	c4435ce9 	ins	r2, r3, 16, 9
  3a:	dc44221e 	st.w	r2, (r4, 0x878)	// *(0x878) = *(0x878)
  3e:	0c06      	bf	0x4a	// if (!T) goto loc_4a;
  40:	3300      	movi	r3, 0	// regs: r3=0x0
  42:	c4435ce9 	ins	r2, r3, 16, 9
  46:	dc44221e 	st.w	r2, (r4, 0x878)	// *(0x878) = *(0x878)
loc_4a:
  4a:	e9050027 	bez	r5, 0x98	// if (r5 == 0x0) goto loc_98;
  4e:	3206      	movi	r2, 6	// regs: r2=0x6
  50:	e425006e 	addi	r1, r5, 111	// regs: r1=(r5 + 0x6f)
  54:	1014      	lrw	r0, 0x0	// regs: r0=0x0
  56:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x56>, r1=<clobbered>
  5a:	1074      	lrw	r3, 0x0	// regs: r3=0x0
  5c:	d84305f5 	ld.b	r2, (r3, 0x5f5)	// regs: r2=*(0x5f5)
  60:	e442200c 	andi	r2, r2, 12	// regs: r2=(*(0x5f5) & 0xc)
  64:	3a44      	cmpnei	r2, 4
  66:	0815      	bt	0x90	// if (r2 != 0x4) goto loc_90;
loc_68:
  68:	d8451035 	ld.h	r2, (r5, 0x6a)	// regs: r2=*(r5 + 0x6a)
  6c:	4243      	lsli	r2, r2, 3	// regs: r2=(*(r5 + 0x6a) << 0x3)
  6e:	e42221f8 	andi	r1, r2, 504	// regs: r1=((*(r5 + 0x6a) << 0x3) & 0x1f8)
  72:	d8440668 	ld.b	r2, (r4, 0x668)	// regs: r2=*(0x668)
  76:	e4422007 	andi	r2, r2, 7	// regs: r2=(*(0x668) & 0x7)
  7a:	6c84      	or	r2, r1	// regs: r2=((*(0x668) & 0x7) | ((*(r5 + 0x6a) << 0x3) & 0x1f8))
  7c:	d82312fe 	ld.h	r1, (r3, 0x5fc)	// regs: r1=*(0x5fc)
  80:	c4225d07 	ins	r1, r2, 15, 7
  84:	dc2312fe 	st.h	r1, (r3, 0x5fc)	// *(0x5fc) = *(0x5fc)
  88:	0406      	br	0x94	// goto loc_94;
loc_8a:
  8a:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
  8c:	95a0      	ld.w	r5, (r5, 0x0)	// regs: r5=*(r5)
  8e:	07c4      	br	0x16	// goto loc_16;
loc_90:
  90:	3a48      	cmpnei	r2, 8
  92:	0feb      	bf	0x68	// if (r2 == 0x8) goto loc_68;
loc_94:
  94:	3000      	movi	r0, 0	// regs: r0=0x0
  96:	0403      	br	0x9c	// goto loc_9c;
loc_98:
  98:	3000      	movi	r0, 0	// regs: r0=0x0
  9a:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_9c:
  9c:	1492      	pop	r4-r5, r15
  9e:	0000      	.short	0x0000
  a0:	00000000 	.long	0x00000000	// <ah_lmac>
  a4:	0000      	.short	0x0000	// <ah_lmac+0x93c>
  a6:	0000      	.short	0x0000
  a8:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>

Disassembly of section .text.lmac_gen_pspoll_ack_ndp2m:

00000000 <lmac_gen_pspoll_ack_ndp2m>: // arg_bytes: 0
   0:	783c      	jmp	r15	// return;

Disassembly of section .text.lmac_get_ack_policy:

00000000 <lmac_get_ack_policy>: // arg_bytes: 4
   0:	9063      	ld.w	r3, (r0, 0xc)	// regs: r3=*(<arg0> + 0xc)
   2:	d9802004 	ld.w	r12, (r0, 0x10)	// regs: r12=*(<arg0> + 0x10)
   6:	103d      	lrw	r1, 0x0	// regs: r1=0x0
   8:	e9230008 	bnez	r3, 0x18	// if (r3 != 0x0) goto loc_18;
   c:	d86109e2 	ld.b	r3, (r1, 0x9e2)	// regs: r3=*(0x9e2)
  10:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  14:	e903002e 	bez	r3, 0x70	// if (r3 == 0x0) goto loc_70;
loc_18:
  18:	d86c1000 	ld.h	r3, (r12, 0x0)	// regs: r3=*(*(<arg0> + 0x10))
  1c:	e443200f 	andi	r2, r3, 15	// regs: r2=(*(*(<arg0> + 0x10)) & 0xf)
  20:	3a48      	cmpnei	r2, 8
  22:	0c0b      	bf	0x38	// if (r2 == 0x8) goto loc_38;
  24:	748c      	zextb	r2, r3	// regs: r2=zext8(*(*(<arg0> + 0x10)))
  26:	eb4200d0 	cmpnei	r2, 208
  2a:	0c07      	bf	0x38	// if (r2 == 0xd0) goto loc_38;
  2c:	eb4200e0 	cmpnei	r2, 224
  30:	0c04      	bf	0x38	// if (r2 == 0xe0) goto loc_38;
  32:	eb4200fc 	cmpnei	r2, 252
  36:	080d      	bt	0x50	// if (r2 != 0xfc) goto loc_50;
loc_38:
  38:	807a      	ld.b	r3, (r0, 0x1a)	// regs: r3=*(<arg0> + 0x1a)
  3a:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(<arg0> + 0x1a) & 0x1)
loc_3e:
  3e:	d84109e2 	ld.b	r2, (r1, 0x9e2)	// regs: r2=*(0x9e2)
  42:	e4422020 	andi	r2, r2, 32	// regs: r2=(*(0x9e2) & 0x20)
  46:	3a40      	cmpnei	r2, 0
  48:	3001      	movi	r0, 1	// regs: r0=0x1
  4a:	c4030c20 	incf	r0, r3, 0
  4e:	783c      	jmp	r15	// return;
loc_50:
  50:	e4432003 	andi	r2, r3, 3	// regs: r2=(*(*(<arg0> + 0x10)) & 0x3)
  54:	3a41      	cmpnei	r2, 1
  56:	080d      	bt	0x70	// if (r2 != 0x1) goto loc_70;
  58:	c4435482 	zext	r2, r3, 4, 2	// regs: r2=zext(*(*(<arg0> + 0x10)))
  5c:	3a41      	cmpnei	r2, 1
  5e:	0805      	bt	0x68	// if (r2 != 0x1) goto loc_68;
  60:	c4a354e3 	zext	r3, r3, 7, 5	// regs: r3=zext(*(*(<arg0> + 0x10)))
  64:	3b42      	cmpnei	r3, 2
  66:	0c07      	bf	0x74	// if (r3 == 0x2) goto loc_74;
loc_68:
  68:	d86c0001 	ld.b	r3, (r12, 0x1)	// regs: r3=*((*(<arg0> + 0x10) + 0x1))
  6c:	4b67      	lsri	r3, r3, 7	// regs: r3=(*((*(<arg0> + 0x10) + 0x1)) >> 0x7)
  6e:	07e8      	br	0x3e	// goto loc_3e;
loc_70:
  70:	3301      	movi	r3, 1	// regs: r3=0x1
  72:	07e6      	br	0x3e	// goto loc_3e;
loc_74:
  74:	3300      	movi	r3, 0	// regs: r3=0x0
  76:	07e4      	br	0x3e	// goto loc_3e;
  78:	0000      	.short	0x0000	// <ah_lmac>
  7a:	0000      	.short	0x0000

Disassembly of section .text.lmac_tx_task:

00000000 <lmac_tx_task>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	ea890125 	lrw	r9, 0x0	// regs: r9=0x0
loc_8:
   8:	ea850125 	lrw	r5, 0x0	// regs: r5=0x0
   c:	8560      	ld.b	r3, (r5, 0x0)	// regs: r3=*(0x0)
   e:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x0) & 0x1)
  12:	e9030008 	bez	r3, 0x22	// if (r3 == 0x0) goto loc_22;
  16:	ea800123 	lrw	r0, 0x0	// regs: r0=0x0
  1a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1a>, r1=<clobbered>
  1e:	1401      	addi	r14, r14, 4	// regs: r14=(sp + 0x4)
  20:	1498      	pop	r4-r11, r15
loc_22:
  22:	3101      	movi	r1, 1	// regs: r1=0x1
  24:	e4050053 	addi	r0, r5, 84	// regs: r0=0x54
  28:	e0000000 	bsr	0x0	// <os_sema_down>; regs: r0=<ret os_sema_down@0x28>, r1=<clobbered>
  2c:	6e83      	mov	r10, r0	// regs: r10=<ret os_sema_down@0x28>
loc_2e:
  2e:	ea87011e 	lrw	r7, 0x0	// regs: r7=0x0
  32:	0409      	br	0x44	// goto loc_44;
loc_34:
  34:	d9002007 	ld.w	r8, (r0, 0x1c)	// regs: r8=*(<ret skb_list_dequeue@0x4c> + 0x1c)
  38:	d8680000 	ld.b	r3, (r8, 0x0)	// regs: r3=*(*(<ret skb_list_dequeue@0x4c> + 0x1c))
  3c:	3b5c      	cmpnei	r3, 28
  3e:	080f      	bt	0x5c	// if (r3 != 0x1c) goto loc_5c;
  40:	e0000000 	bsr	0x0	// <lmac_tx_pv0_s1g_beacon> // arg_bytes: 4; regs: r0=<ret lmac_tx_pv0_s1g_beacon@0x40>, r1=<clobbered>
loc_44:
  44:	e90a0009 	bez	r10, 0x56	// if (r10 == 0x0) goto loc_56;
  48:	ea800118 	lrw	r0, 0x0	// regs: r0=0x0
  4c:	e0000000 	bsr	0x0	// <skb_list_dequeue>; regs: r0=<ret skb_list_dequeue@0x4c>, r1=<clobbered>
  50:	6d83      	mov	r6, r0	// regs: r6=<ret skb_list_dequeue@0x4c>
  52:	e920fff1 	bnez	r0, 0x34	// if (r0 != 0x0) goto loc_34;
loc_56:
  56:	e0000000 	bsr	0x0	// <lmac_tx_data_reload> // arg_bytes: 0; regs: r0=<ret lmac_tx_data_reload@0x56>, r1=<clobbered>
  5a:	07d7      	br	0x8	// goto loc_8;
loc_5c:
  5c:	e4282001 	andi	r1, r8, 1	// regs: r1=(*(<ret skb_list_dequeue@0x4c> + 0x1c) & 0x1)
  60:	9088      	ld.w	r4, (r0, 0x20)	// regs: r4=*(<ret skb_list_dequeue@0x4c> + 0x20)
  62:	d960200d 	ld.w	r11, (r0, 0x34)	// regs: r11=*(<ret skb_list_dequeue@0x4c> + 0x34)
  66:	e901000f 	bez	r1, 0x84	// if (r1 == 0x0) goto loc_84;
  6a:	6c63      	mov	r1, r8	// regs: r1=*(<ret skb_list_dequeue@0x4c> + 0x1c)
  6c:	ea800110 	lrw	r0, 0x0	// regs: r0=0x0
  70:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x70>, r1=<clobbered>
  74:	8e34      	ld.h	r1, (r6, 0x28)	// regs: r1=*(<ret skb_list_dequeue@0x4c> + 0x28)
  76:	9607      	ld.w	r0, (r6, 0x1c)	// regs: r0=*(<ret skb_list_dequeue@0x4c> + 0x1c)
  78:	e0000000 	bsr	0x0	// <hgics_print_hex>; regs: r0=<ret hgics_print_hex@0x78>, r1=<clobbered>
loc_7c:
  7c:	ea80010d 	lrw	r0, 0x0	// regs: r0=0x0
  80:	e800041c 	br	0x8b8	// goto loc_8b8;
loc_84:
  84:	3244      	movi	r2, 68	// regs: r2=0x44
  86:	6c13      	mov	r0, r4	// regs: r0=*(<ret skb_list_dequeue@0x4c> + 0x20)
  88:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x88>, r1=<clobbered>
  8c:	d844003f 	ld.b	r2, (r4, 0x3f)	// regs: r2=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3f))
  90:	e90b0069 	bez	r11, 0x162	// if (r11 == 0x0) goto loc_162;
  94:	d86b2001 	ld.w	r3, (r11, 0x4)	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x34) + 0x4))
  98:	b460      	st.w	r3, (r4, 0x0)	// *(*(<ret skb_list_dequeue@0x4c> + 0x20)) = *((*(<ret skb_list_dequeue@0x4c> + 0x34) + 0x4))
  9a:	d8040025 	ld.b	r0, (r4, 0x25)	// regs: r0=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x25))
  9e:	4b7f      	lsri	r3, r3, 31	// regs: r3=(*((*(<ret skb_list_dequeue@0x4c> + 0x34) + 0x4)) >> 0x1f)
  a0:	d82b1004 	ld.h	r1, (r11, 0x8)	// regs: r1=*((*(<ret skb_list_dequeue@0x4c> + 0x34) + 0x8))
  a4:	c4035c05 	ins	r0, r3, 5, 5
  a8:	d8640027 	ld.b	r3, (r4, 0x27)	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x27))
  ac:	c4615c03 	ins	r3, r1, 3, 3
  b0:	dc040025 	st.b	r0, (r4, 0x25)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x25)) = *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x25))
  b4:	dc640027 	st.b	r3, (r4, 0x27)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x27)) = *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x27))
  b8:	b421      	st.w	r1, (r4, 0x4)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x4)) = *((*(<ret skb_list_dequeue@0x4c> + 0x34) + 0x8))
  ba:	d86b0001 	ld.b	r3, (r11, 0x1)	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x34) + 0x1))
  be:	dc64003c 	st.b	r3, (r4, 0x3c)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3c)) = *((*(<ret skb_list_dequeue@0x4c> + 0x34) + 0x1))
  c2:	3300      	movi	r3, 0	// regs: r3=0x0
  c4:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  c6:	dc64003d 	st.b	r3, (r4, 0x3d)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3d)) = 0xffffffff
  ca:	d82b0003 	ld.b	r1, (r11, 0x3)	// regs: r1=*((*(<ret skb_list_dequeue@0x4c> + 0x34) + 0x3))
  ce:	6ccb      	mov	r3, r2	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3f))
  d0:	c4a154e1 	zext	r1, r1, 7, 5	// regs: r1=zext(*((*(<ret skb_list_dequeue@0x4c> + 0x34) + 0x3)))
  d4:	c4615c25 	ins	r3, r1, 6, 5
  d8:	dc64003f 	st.b	r3, (r4, 0x3f)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3f)) = *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3f))
  dc:	d86b000a 	ld.b	r3, (r11, 0xa)	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x34) + 0xa))
  e0:	dc64003e 	st.b	r3, (r4, 0x3e)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3e)) = *((*(<ret skb_list_dequeue@0x4c> + 0x34) + 0xa))
  e4:	d84b0003 	ld.b	r2, (r11, 0x3)	// regs: r2=*((*(<ret skb_list_dequeue@0x4c> + 0x34) + 0x3))
  e8:	d864003f 	ld.b	r3, (r4, 0x3f)	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3f))
  ec:	c4625c80 	ins	r3, r2, 4, 0
loc_f0:
  f0:	dc64003f 	st.b	r3, (r4, 0x3f)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3f)) = *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3f))
  f4:	d8640027 	ld.b	r3, (r4, 0x27)	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x27))
  f8:	e4632008 	andi	r3, r3, 8	// regs: r3=(*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x27)) & 0x8)
  fc:	e9030013 	bez	r3, 0x122	// if (r3 == 0x0) goto loc_122;
 100:	3307      	movi	r3, 7	// regs: r3=0x7
 102:	dc64003e 	st.b	r3, (r4, 0x3e)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3e)) = 0x7
 106:	3301      	movi	r3, 1	// regs: r3=0x1
 108:	dc64003d 	st.b	r3, (r4, 0x3d)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3d)) = 0x1
 10c:	d867034a 	ld.b	r3, (r7, 0x34a)	// regs: r3=*(r7 + 0x34a)
 110:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r7 + 0x34a) & 0x1)
 114:	3b40      	cmpnei	r3, 0
 116:	3200      	movi	r2, 0	// regs: r2=0x0
 118:	3303      	movi	r3, 3	// regs: r3=0x3
 11a:	c4620c20 	incf	r3, r2, 0
 11e:	dc64003c 	st.b	r3, (r4, 0x3c)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3c)) = 0x3
loc_122:
 122:	d867034a 	ld.b	r3, (r7, 0x34a)	// regs: r3=*(r7 + 0x34a)
 126:	d844003d 	ld.b	r2, (r4, 0x3d)	// regs: r2=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3d))
 12a:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r7 + 0x34a) & 0x1)
 12e:	7488      	zextb	r2, r2	// regs: r2=zext8(*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3d)))
 130:	3a07      	cmphsi	r2, 8
 132:	e9030026 	bez	r3, 0x17e	// if (r3 == 0x0) goto loc_17e;
 136:	0c0b      	bf	0x14c	// if (!T) goto loc_14c;
 138:	3a4a      	cmpnei	r2, 10
 13a:	0c09      	bf	0x14c	// if (r2 == 0xa) goto loc_14c;
 13c:	d8470866 	ld.b	r2, (r7, 0x866)	// regs: r2=*(r7 + 0x866)
 140:	3a07      	cmphsi	r2, 8
 142:	0c03      	bf	0x148	// if (r2 < 0x8) goto loc_148;
 144:	3a4a      	cmpnei	r2, 10
loc_146:
 146:	0821      	bt	0x188	// if (r2 != 0xa) goto loc_188;
loc_148:
 148:	dc44003d 	st.b	r2, (r4, 0x3d)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3d)) = r2
loc_14c:
 14c:	d844003c 	ld.b	r2, (r4, 0x3c)	// regs: r2=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3c))
 150:	3a42      	cmpnei	r2, 2
 152:	0c2f      	bf	0x1b0	// if (r2 == 0x2) goto loc_1b0;
 154:	3a02      	cmphsi	r2, 3
 156:	081c      	bt	0x18e	// if (r2 >= 0x3) goto loc_18e;
 158:	3a41      	cmpnei	r2, 1
 15a:	0c35      	bf	0x1c4	// if (r2 == 0x1) goto loc_1c4;
loc_15c:
 15c:	3300      	movi	r3, 0	// regs: r3=0x0
 15e:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 160:	042a      	br	0x1b4	// goto loc_1b4;
loc_162:
 162:	3300      	movi	r3, 0	// regs: r3=0x0
 164:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 166:	dc64003c 	st.b	r3, (r4, 0x3c)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3c)) = 0xffffffff
 16a:	dc64003d 	st.b	r3, (r4, 0x3d)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3d)) = 0xffffffff
 16e:	330f      	movi	r3, 15	// regs: r3=0xf
 170:	dc64003e 	st.b	r3, (r4, 0x3e)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3e)) = 0xf
 174:	6ccb      	mov	r3, r2	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3f))
 176:	3203      	movi	r2, 3	// regs: r2=0x3
 178:	c4625c25 	ins	r3, r2, 6, 5
 17c:	07ba      	br	0xf0	// goto loc_f0;
loc_17e:
 17e:	0fe7      	bf	0x14c	// if (!T) goto loc_14c;
 180:	d8470866 	ld.b	r2, (r7, 0x866)	// regs: r2=*(r7 + 0x866)
 184:	3a07      	cmphsi	r2, 8
 186:	07e0      	br	0x146	// goto loc_146;
loc_188:
 188:	3200      	movi	r2, 0	// regs: r2=0x0
 18a:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
 18c:	07de      	br	0x148	// goto loc_148;
loc_18e:
 18e:	3a44      	cmpnei	r2, 4
 190:	0c15      	bf	0x1ba	// if (r2 == 0x4) goto loc_1ba;
 192:	3a48      	cmpnei	r2, 8
 194:	0be4      	bt	0x15c	// if (r2 != 0x8) goto loc_15c;
 196:	3202      	movi	r2, 2	// regs: r2=0x2
 198:	dc44003c 	st.b	r2, (r4, 0x3c)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3c)) = 0x2
 19c:	e9230014 	bnez	r3, 0x1c4	// if (r3 != 0x0) goto loc_1c4;
 1a0:	d8470308 	ld.b	r2, (r7, 0x308)	// regs: r2=*(r7 + 0x308)
 1a4:	3a41      	cmpnei	r2, 1
 1a6:	0c07      	bf	0x1b4	// if (r2 == 0x1) goto loc_1b4;
 1a8:	3a42      	cmpnei	r2, 2
 1aa:	0813      	bt	0x1d0	// if (r2 != 0x2) goto loc_1d0;
 1ac:	3301      	movi	r3, 1	// regs: r3=0x1
 1ae:	0403      	br	0x1b4	// goto loc_1b4;
loc_1b0:
 1b0:	e923000a 	bnez	r3, 0x1c4	// if (r3 != 0x0) goto loc_1c4;
loc_1b4:
 1b4:	dc64003c 	st.b	r3, (r4, 0x3c)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3c)) = r3
 1b8:	040c      	br	0x1d0	// goto loc_1d0;
loc_1ba:
 1ba:	3201      	movi	r2, 1	// regs: r2=0x1
 1bc:	dc44003c 	st.b	r2, (r4, 0x3c)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3c)) = 0x1
 1c0:	e9030004 	bez	r3, 0x1c8	// if (r3 == 0x0) goto loc_1c8;
loc_1c4:
 1c4:	3303      	movi	r3, 3	// regs: r3=0x3
 1c6:	07f7      	br	0x1b4	// goto loc_1b4;
loc_1c8:
 1c8:	d8470308 	ld.b	r2, (r7, 0x308)	// regs: r2=*(r7 + 0x308)
 1cc:	3a41      	cmpnei	r2, 1
 1ce:	0ff3      	bf	0x1b4	// if (r2 == 0x1) goto loc_1b4;
loc_1d0:
 1d0:	d864003f 	ld.b	r3, (r4, 0x3f)	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3f))
 1d4:	e423201f 	andi	r1, r3, 31	// regs: r1=(*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3f)) & 0x1f)
 1d8:	d8470378 	ld.b	r2, (r7, 0x378)	// regs: r2=*(r7 + 0x378)
 1dc:	6449      	cmplt	r2, r1
 1de:	0c06      	bf	0x1ea	// if (!T) goto loc_1ea;
 1e0:	3200      	movi	r2, 0	// regs: r2=0x0
 1e2:	c4625c80 	ins	r3, r2, 4, 0
 1e6:	dc64003f 	st.b	r3, (r4, 0x3f)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3f)) = *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x3f))
loc_1ea:
 1ea:	9667      	ld.w	r3, (r6, 0x1c)	// regs: r3=*(<ret skb_list_dequeue@0x4c> + 0x1c)
 1ec:	8e54      	ld.h	r2, (r6, 0x28)	// regs: r2=*(<ret skb_list_dequeue@0x4c> + 0x28)
 1ee:	b464      	st.w	r3, (r4, 0x10)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x10)) = *(<ret skb_list_dequeue@0x4c> + 0x1c)
 1f0:	ac4a      	st.h	r2, (r4, 0x14)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x14)) = *(<ret skb_list_dequeue@0x4c> + 0x28)
 1f2:	8320      	ld.b	r1, (r3, 0x0)	// regs: r1=*(*(<ret skb_list_dequeue@0x4c> + 0x1c))
 1f4:	e4212003 	andi	r1, r1, 3	// regs: r1=(*(*(<ret skb_list_dequeue@0x4c> + 0x1c)) & 0x3)
 1f8:	d8640024 	ld.b	r3, (r4, 0x24)	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x24))
 1fc:	c4615c20 	ins	r3, r1, 1, 0
 200:	dc640024 	st.b	r3, (r4, 0x24)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x24)) = *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x24))
 204:	e4632003 	andi	r3, r3, 3	// regs: r3=(*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x24)) & 0x3)
 208:	e9030006 	bez	r3, 0x214	// if (r3 == 0x0) goto loc_214;
 20c:	0215      	lrw	r0, 0x0	// regs: r0=0x0
loc_20e:
 20e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x20e>, r1=<clobbered>
 212:	0735      	br	0x7c	// goto loc_7c;
loc_214:
 214:	d8081000 	ld.h	r0, (r8, 0x0)	// regs: r0=*(*(<ret skb_list_dequeue@0x4c> + 0x1c))
 218:	e0000000 	bsr	0x0	// <ieee80211_is_data>; regs: r0=<ret ieee80211_is_data@0x218>, r1=<clobbered>
 21c:	d8640027 	ld.b	r3, (r4, 0x27)	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x27))
 220:	c4605c01 	ins	r3, r0, 1, 1
 224:	dc640027 	st.b	r3, (r4, 0x27)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x27)) = *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x27))
 228:	e5640019 	addi	r11, r4, 26	// regs: r11=(*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x1a)
 22c:	9627      	ld.w	r1, (r6, 0x1c)	// regs: r1=*(<ret skb_list_dequeue@0x4c> + 0x1c)
 22e:	6c2f      	mov	r0, r11	// regs: r0=(*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x1a)
 230:	e0000000 	bsr	0x0	// <lmac_get_rx_addr>; regs: r0=<ret lmac_get_rx_addr@0x230>, r1=<clobbered>
 234:	6c6f      	mov	r1, r11	// regs: r1=(*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x1a)
 236:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
 23a:	e0000000 	bsr	0x0	// <lmac_sta_get>; regs: r0=<ret lmac_sta_get@0x23a>, r1=<clobbered>
 23e:	847a      	ld.b	r3, (r4, 0x1a)	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x1a))
 240:	e4632001 	andi	r3, r3, 1	// regs: r3=(*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x1a)) & 0x1)
 244:	b403      	st.w	r0, (r4, 0xc)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0xc)) = <ret lmac_sta_get@0x23a>
 246:	e9030141 	bez	r3, 0x4c8	// if (r3 == 0x0) goto loc_4c8;
 24a:	d8640026 	ld.b	r3, (r4, 0x26)	// regs: r3=*((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x26))
 24e:	3201      	movi	r2, 1	// regs: r2=0x1
 250:	c4625c07 	ins	r3, r2, 7, 7
 254:	dc640026 	st.b	r3, (r4, 0x26)	// *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x26)) = *((*(<ret skb_list_dequeue@0x4c> + 0x20) + 0x26))
loc_258:
 258:	6c13      	mov	r0, r4	// regs: r0=r4
 25a:	e0000000 	bsr	0x0	// <lmac_get_ack_policy> // arg_bytes: 4; regs: r0=<ret lmac_get_ack_policy@0x25a>, r1=<clobbered>
 25e:	d8640025 	ld.b	r3, (r4, 0x25)	// regs: r3=*(r4 + 0x25)
 262:	c4605c01 	ins	r3, r0, 1, 1
 266:	d844003e 	ld.b	r2, (r4, 0x3e)	// regs: r2=*(r4 + 0x3e)
 26a:	dc640025 	st.b	r3, (r4, 0x25)	// *(r4 + 0x25) = *(r4 + 0x25)
 26e:	5a63      	subi	r3, r2, 1	// regs: r3=(*(r4 + 0x3e) - 0x1)
 270:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(r4 + 0x3e) - 0x1))
 272:	3b06      	cmphsi	r3, 7
 274:	0948      	bt	0x504	// if (r3 >= 0x7) goto loc_504;
 276:	d8640026 	ld.b	r3, (r4, 0x26)	// regs: r3=*(r4 + 0x26)
 27a:	c4625c60 	ins	r3, r2, 3, 0
loc_27e:
 27e:	dc640026 	st.b	r3, (r4, 0x26)	// *(r4 + 0x26) = *(r4 + 0x26)
 282:	d8640026 	ld.b	r3, (r4, 0x26)	// regs: r3=*(r4 + 0x26)
 286:	e443200f 	andi	r2, r3, 15	// regs: r2=(*(r4 + 0x26) & 0xf)
 28a:	3a27      	cmplti	r2, 8
 28c:	0806      	bt	0x298	// if (r2 < 0x8) goto loc_298;
 28e:	3207      	movi	r2, 7	// regs: r2=0x7
 290:	c4625c60 	ins	r3, r2, 3, 0
 294:	dc640026 	st.b	r3, (r4, 0x26)	// *(r4 + 0x26) = *(r4 + 0x26)
loc_298:
 298:	8c73      	ld.h	r3, (r4, 0x26)	// regs: r3=*(r4 + 0x26)
 29a:	e4632280 	andi	r3, r3, 640	// regs: r3=(*(r4 + 0x26) & 0x280)
 29e:	eb430280 	cmpnei	r3, 640
 2a2:	0827      	bt	0x2f0	// if (r3 != 0x280) goto loc_2f0;
 2a4:	d8670314 	ld.b	r3, (r7, 0x314)	// regs: r3=*(r7 + 0x314)
 2a8:	c4035483 	zext	r3, r3, 4, 0	// regs: r3=zext(*(r7 + 0x314))
 2ac:	748c      	zextb	r2, r3	// regs: r2=zext8(zext(*(r7 + 0x314)))
 2ae:	dc64002c 	st.b	r3, (r4, 0x2c)	// *(r4 + 0x2c) = zext(*(r7 + 0x314))
 2b2:	e902001f 	bez	r2, 0x2f0	// if (r2 == 0x0) goto loc_2f0;
 2b6:	d8640026 	ld.b	r3, (r4, 0x26)	// regs: r3=*(r4 + 0x26)
 2ba:	3201      	movi	r2, 1	// regs: r2=0x1
 2bc:	c4625c60 	ins	r3, r2, 3, 0
 2c0:	dc640026 	st.b	r3, (r4, 0x26)	// *(r4 + 0x26) = *(r4 + 0x26)
 2c4:	d8670310 	ld.b	r3, (r7, 0x310)	// regs: r3=*(r7 + 0x310)
 2c8:	e4632020 	andi	r3, r3, 32	// regs: r3=(*(r7 + 0x310) & 0x20)
 2cc:	e9230018 	bnez	r3, 0x2fc	// if (r3 != 0x0) goto loc_2fc;
 2d0:	9462      	ld.w	r3, (r4, 0x8)	// regs: r3=*(r4 + 0x8)
 2d2:	6cc8      	or	r3, r2	// regs: r3=(*(r4 + 0x8) | 0x1)
 2d4:	1339      	lrw	r1, 0x0	// regs: r1=0x0
 2d6:	b462      	st.w	r3, (r4, 0x8)	// *(r4 + 0x8) = (*(r4 + 0x8) | 0x1)
 2d8:	8960      	ld.h	r3, (r1, 0x0)	// regs: r3=*(0x0)
 2da:	4344      	lsli	r2, r3, 4	// regs: r2=(*(0x0) << 0x4)
 2dc:	7489      	zexth	r2, r2	// regs: r2=zext16((*(0x0) << 0x4))
 2de:	2300      	addi	r3, 1	// regs: r3=(*(0x0) + 0x1)
 2e0:	dc480016 	st.b	r2, (r8, 0x16)	// *(r8 + 0x16) = zext16((*(0x0) << 0x4))
 2e4:	e4632fff 	andi	r3, r3, 4095	// regs: r3=((*(0x0) + 0x1) & 0xfff)
 2e8:	4a48      	lsri	r2, r2, 8	// regs: r2=(zext16((*(0x0) << 0x4)) >> 0x8)
 2ea:	dc480017 	st.b	r2, (r8, 0x17)	// *(r8 + 0x17) = (zext16((*(0x0) << 0x4)) >> 0x8)
 2ee:	a960      	st.h	r3, (r1, 0x0)	// *(0x0) = ((*(0x0) + 0x1) & 0xfff)
loc_2f0:
 2f0:	d8670310 	ld.b	r3, (r7, 0x310)	// regs: r3=*(r7 + 0x310)
 2f4:	e4632020 	andi	r3, r3, 32	// regs: r3=(*(r7 + 0x310) & 0x20)
 2f8:	e9030131 	bez	r3, 0x55a	// if (r3 == 0x0) goto loc_55a;
loc_2fc:
 2fc:	d9642004 	ld.w	r11, (r4, 0x10)	// regs: r11=*(r4 + 0x10)
 300:	d8240026 	ld.b	r1, (r4, 0x26)	// regs: r1=*(r4 + 0x26)
 304:	d86b0001 	ld.b	r3, (r11, 0x1)	// regs: r3=*((*(r4 + 0x10) + 0x1))
 308:	d84b0000 	ld.b	r2, (r11, 0x0)	// regs: r2=*(*(r4 + 0x10))
 30c:	4368      	lsli	r3, r3, 8	// regs: r3=(*((*(r4 + 0x10) + 0x1)) << 0x8)
 30e:	6cc8      	or	r3, r2	// regs: r3=((*((*(r4 + 0x10) + 0x1)) << 0x8) | *(*(r4 + 0x10)))
 310:	e4432003 	andi	r2, r3, 3	// regs: r2=(((*((*(r4 + 0x10) + 0x1)) << 0x8) | *(*(r4 + 0x10))) & 0x3)
 314:	9403      	ld.w	r0, (r4, 0xc)	// regs: r0=*(r4 + 0xc)
 316:	e421200f 	andi	r1, r1, 15	// regs: r1=(*(r4 + 0x26) & 0xf)
 31a:	e92200fd 	bnez	r2, 0x514	// if (r2 != 0x0) goto loc_514;
 31e:	c4435463 	zext	r3, r3, 3, 2	// regs: r3=zext(((*((*(r4 + 0x10) + 0x1)) << 0x8) | *(*(r4 + 0x10))))
 322:	e9030004 	bez	r3, 0x32a	// if (r3 == 0x0) goto loc_32a;
 326:	3b42      	cmpnei	r3, 2
 328:	0906      	bt	0x534	// if (r3 != 0x2) goto loc_534;
loc_32a:
 32a:	e0000000 	bsr	0x0	// <seq_num_space_update> // arg_bytes: 4; regs: r0=<ret seq_num_space_update@0x32a>, r1=<clobbered>
 32e:	4064      	lsli	r3, r0, 4	// regs: r3=(<ret seq_num_space_update@0x32a> << 0x4)
 330:	74cd      	zexth	r3, r3	// regs: r3=zext16((<ret seq_num_space_update@0x32a> << 0x4))
 332:	dc6b0016 	st.b	r3, (r11, 0x16)	// *((*(r4 + 0x10) + 0x16)) = zext16((<ret seq_num_space_update@0x32a> << 0x4))
 336:	4b68      	lsri	r3, r3, 8	// regs: r3=(zext16((<ret seq_num_space_update@0x32a> << 0x4)) >> 0x8)
 338:	dc6b0017 	st.b	r3, (r11, 0x17)	// *((*(r4 + 0x10) + 0x17)) = (zext16((<ret seq_num_space_update@0x32a> << 0x4)) >> 0x8)
loc_33c:
 33c:	d8640024 	ld.b	r3, (r4, 0x24)	// regs: r3=*(r4 + 0x24)
 340:	e4432003 	andi	r2, r3, 3	// regs: r2=(*(r4 + 0x24) & 0x3)
 344:	ac0c      	st.h	r0, (r4, 0x18)	// *(r4 + 0x18) = r0
 346:	e902010e 	bez	r2, 0x562	// if (r2 == 0x0) goto loc_562;
 34a:	3a41      	cmpnei	r2, 1
 34c:	0daf      	bf	0x6aa	// if (r2 == 0x1) goto loc_6aa;
loc_34e:
 34e:	8e34      	ld.h	r1, (r6, 0x28)	// regs: r1=*(r6 + 0x28)
 350:	e4612003 	andi	r3, r1, 3	// regs: r3=(*(r6 + 0x28) & 0x3)
 354:	2107      	addi	r1, 8	// regs: r1=(*(r6 + 0x28) + 0x8)
 356:	e92301de 	bnez	r3, 0x712	// if (r3 != 0x0) goto loc_712;
loc_35a:
 35a:	d867034a 	ld.b	r3, (r7, 0x34a)	// regs: r3=*(r7 + 0x34a)
 35e:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r7 + 0x34a) & 0x1)
 362:	7447      	sexth	r1, r1	// regs: r1=sext16(r1)
 364:	ac2b      	st.h	r1, (r4, 0x16)	// *(r4 + 0x16) = sext16(r1)
 366:	e90301da 	bez	r3, 0x71a	// if (r3 == 0x0) goto loc_71a;
 36a:	d8670865 	ld.b	r3, (r7, 0x865)	// regs: r3=*(r7 + 0x865)
 36e:	e90301d9 	bez	r3, 0x720	// if (r3 == 0x0) goto loc_720;
 372:	4364      	lsli	r3, r3, 4	// regs: r3=(*(r7 + 0x865) << 0x4)
 374:	1252      	lrw	r2, 0x0	// regs: r2=0x0
 376:	d0430823 	ldr.w	r3, (r3, r2 << 0)	// regs: r3=*((*(r7 + 0x865) << 0x4) + (0x0 << 0))
loc_37a:
 37a:	644d      	cmplt	r3, r1
 37c:	09d8      	bt	0x72c	// if (T) goto loc_72c;
 37e:	6c13      	mov	r0, r4	// regs: r0=r4
 380:	e0000000 	bsr	0x0	// <lmac_partial_aid_update> // arg_bytes: 4; regs: r0=<ret lmac_partial_aid_update@0x380>, r1=<clobbered>
 384:	d847202f 	ld.w	r2, (r7, 0xbc)	// regs: r2=*(r7 + 0xbc)
 388:	3a41      	cmpnei	r2, 1
 38a:	0810      	bt	0x3aa	// if (r2 != 0x1) goto loc_3aa;
 38c:	d867034a 	ld.b	r3, (r7, 0x34a)	// regs: r3=*(r7 + 0x34a)
 390:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r7 + 0x34a) & 0x1)
 394:	e923000b 	bnez	r3, 0x3aa	// if (r3 != 0x0) goto loc_3aa;
 398:	9463      	ld.w	r3, (r4, 0xc)	// regs: r3=*(r4 + 0xc)
 39a:	e9030008 	bez	r3, 0x3aa	// if (r3 == 0x0) goto loc_3aa;
 39e:	d8640026 	ld.b	r3, (r4, 0x26)	// regs: r3=*(r4 + 0x26)
 3a2:	c4625c06 	ins	r3, r2, 6, 6
 3a6:	dc640026 	st.b	r3, (r4, 0x26)	// *(r4 + 0x26) = *(r4 + 0x26)
loc_3aa:
 3aa:	d8470319 	ld.b	r2, (r7, 0x319)	// regs: r2=*(r7 + 0x319)
 3ae:	e4422002 	andi	r2, r2, 2	// regs: r2=(*(r7 + 0x319) & 0x2)
 3b2:	d8681000 	ld.h	r3, (r8, 0x0)	// regs: r3=*(r8)
 3b6:	e92201b8 	bnez	r2, 0x726	// if (r2 != 0x0) goto loc_726;
 3ba:	3b8c      	bclri	r3, 12	// regs: r3=(*(r8) & ~(0x1 << 0xc))
loc_3bc:
 3bc:	dc681000 	st.h	r3, (r8, 0x0)	// *(r8) = r3
 3c0:	d8672267 	ld.w	r3, (r7, 0x99c)	// regs: r3=*(r7 + 0x99c)
 3c4:	2b01      	subi	r3, 2	// regs: r3=(*(r7 + 0x99c) - 0x2)
 3c6:	3b01      	cmphsi	r3, 2
 3c8:	0807      	bt	0x3d6	// if (r3 >= 0x2) goto loc_3d6;
 3ca:	d8681000 	ld.h	r3, (r8, 0x0)	// regs: r3=*(r8)
 3ce:	ec631000 	ori	r3, r3, 4096	// regs: r3=(*(r8) | 0x1000)
 3d2:	dc681000 	st.h	r3, (r8, 0x0)	// *(r8) = (*(r8) | 0x1000)
loc_3d6:
 3d6:	d9062008 	ld.w	r8, (r6, 0x20)	// regs: r8=*(r6 + 0x20)
 3da:	d8280026 	ld.b	r1, (r8, 0x26)	// regs: r1=*((*(r6 + 0x20) + 0x26))
 3de:	e4612010 	andi	r3, r1, 16	// regs: r3=(*((*(r6 + 0x20) + 0x26)) & 0x10)
 3e2:	e92301a8 	bnez	r3, 0x732	// if (r3 != 0x0) goto loc_732;
loc_3e6:
 3e6:	9688      	ld.w	r4, (r6, 0x20)	// regs: r4=*(r6 + 0x20)
 3e8:	c0006028 	mfcr	r8, cr<0, 0>
 3ec:	c0807020 	psrclr	ie
 3f0:	d8640026 	ld.b	r3, (r4, 0x26)	// regs: r3=*((*(r6 + 0x20) + 0x26))
 3f4:	e443200f 	andi	r2, r3, 15	// regs: r2=(*((*(r6 + 0x20) + 0x26)) & 0xf)
 3f8:	3a27      	cmplti	r2, 8
 3fa:	080d      	bt	0x414	// if (r2 < 0x8) goto loc_414;
 3fc:	3107      	movi	r1, 7	// regs: r1=0x7
 3fe:	c4615c60 	ins	r3, r1, 3, 0
 402:	1110      	lrw	r0, 0x0	// regs: r0=0x0
 404:	dc640026 	st.b	r3, (r4, 0x26)	// *((*(r6 + 0x20) + 0x26)) = *((*(r6 + 0x20) + 0x26))
 408:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x408>, r1=<clobbered>
 40c:	3120      	movi	r1, 32	// regs: r1=0x20
 40e:	9404      	ld.w	r0, (r4, 0x10)	// regs: r0=*((*(r6 + 0x20) + 0x10))
 410:	e0000000 	bsr	0x0	// <hgics_print_hex>; regs: r0=<ret hgics_print_hex@0x410>, r1=<clobbered>
loc_414:
 414:	d8640026 	ld.b	r3, (r4, 0x26)	// regs: r3=*((*(r6 + 0x20) + 0x26))
 418:	114b      	lrw	r2, 0x0	// regs: r2=0x0
 41a:	e4632007 	andi	r3, r3, 7	// regs: r3=(*((*(r6 + 0x20) + 0x26)) & 0x7)
 41e:	d0620024 	ldr.b	r4, (r2, r3 << 0)	// regs: r4=*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0))
 422:	7493      	sexth	r2, r4	// regs: r2=sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)))
 424:	5a68      	addu	r3, r2, r2	// regs: r3=(sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0))))
 426:	60c8      	addu	r3, r2	// regs: r3=((sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0))))
 428:	4362      	lsli	r3, r3, 2	// regs: r3=(((sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)))) << 0x2)
 42a:	2387      	addi	r3, 136	// regs: r3=((((sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)))) << 0x2) + 0x88)
 42c:	60d4      	addu	r3, r5	// regs: r3=(((((sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)))) << 0x2) + 0x88) + r5)
 42e:	6c0f      	mov	r0, r3	// regs: r0=(((((sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)))) << 0x2) + 0x88) + r5)
 430:	b860      	st.w	r3, (r14, 0x0)	// stack_0 = (((((sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)))) + sext16(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)))) << 0x2) + 0x88) + r5)
 432:	e0000000 	bsr	0x0	// <skb_list_last>; regs: r0=<ret skb_list_last@0x432>, r1=<clobbered>
 436:	6c43      	mov	r1, r0	// regs: r1=<ret skb_list_last@0x432>
 438:	6ec3      	mov	r11, r0	// regs: r11=<ret skb_list_last@0x432>
 43a:	6c1b      	mov	r0, r6	// regs: r0=r6
 43c:	e0000000 	bsr	0x0	// <lmac_check_aggregation> // arg_bytes: 8; regs: r0=<ret lmac_check_aggregation@0x43c>, r1=<clobbered>
 440:	6c5b      	mov	r1, r6	// regs: r1=r6
 442:	e92003eb 	bnez	r0, 0xc18	// if (r0 != 0x0) goto loc_c18;
 446:	9860      	ld.w	r3, (r14, 0x0)	// regs: r3=stack_0
 448:	6c0f      	mov	r0, r3	// regs: r0=stack_0
loc_44a:
 44a:	6114      	addu	r4, r5	// regs: r4=(*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)) + r5)
 44c:	e0000000 	bsr	0x0	// <skb_list_queue>; regs: r0=<ret skb_list_queue@0x44c>, r1=<clobbered>
 450:	d8640554 	ld.b	r3, (r4, 0x554)	// regs: r3=*(((*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)) + r5) + 0x554))
 454:	2300      	addi	r3, 1	// regs: r3=(*(((*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)) + r5) + 0x554)) + 0x1)
 456:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(((*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)) + r5) + 0x554)) + 0x1))
 458:	dc640554 	st.b	r3, (r4, 0x554)	// *(((*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)) + r5) + 0x554)) = zext8((*(((*(0x0 + ((*((*(r6 + 0x20) + 0x26)) & 0x7) << 0)) + r5) + 0x554)) + 0x1))
 45c:	d8450557 	ld.b	r2, (r5, 0x557)	// regs: r2=*(r5 + 0x557)
 460:	e5082040 	andi	r8, r8, 64	// regs: r8=(r8 & 0x40)
 464:	e9020004 	bez	r2, 0x46c	// if (r2 == 0x0) goto loc_46c;
 468:	e90b03db 	bez	r11, 0xc1e	// if (r11 == 0x0) goto loc_c1e;
loc_46c:
 46c:	d8470315 	ld.b	r2, (r7, 0x315)	// regs: r2=*(r7 + 0x315)
 470:	d8050556 	ld.b	r0, (r5, 0x556)	// regs: r0=*(r5 + 0x556)
 474:	4a21      	lsri	r1, r2, 1	// regs: r1=(*(r7 + 0x315) >> 0x1)
 476:	6440      	cmphs	r0, r1
 478:	e86003d3 	bt	0xc1e	// if (T) goto loc_c1e;
 47c:	648c      	cmphs	r3, r2
 47e:	e86003d0 	bt	0xc1e	// if (T) goto loc_c1e;
 482:	e908fde1 	bez	r8, 0x44	// if (r8 == 0x0) goto loc_44;
 486:	3300      	movi	r3, 0	// regs: r3=0x0
loc_488:
 488:	c0807420 	psrset	ie
 48c:	e903fddc 	bez	r3, 0x44	// if (r3 == 0x0) goto loc_44;
loc_490:
 490:	e0000000 	bsr	0x0	// <lmac_tx_data_reload> // arg_bytes: 0; regs: r0=<ret lmac_tx_data_reload@0x490>, r1=<clobbered>
 494:	e800fdd8 	br	0x44	// goto loc_44;
 498:	00000000 	.long	0x00000000	// <.bss.pn_num.13617>
 49c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
 4a0:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x233>
 4a4:	00000000 	.long	0x00000000	// <ah_lmac>
 4a8:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x64>
 4ac:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1>
 4b0:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x250>
 4b4:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x25>
 4b8:	00000000 	.long	0x00000000	// <.bss.sn_dup.13763>
 4bc:	00000000 	.long	0x00000000	// <max_byte_table>
 4c0:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x21a>
 4c4:	00000000 	.long	0x00000000	// <.rodata.ieee802_1d_to_ac>
loc_4c8:
 4c8:	e900fec8 	bez	r0, 0x258	// if (r0 == 0x0) goto loc_258;
 4cc:	d860006b 	ld.b	r3, (r0, 0x6b)	// regs: r3=*(r0 + 0x6b)
 4d0:	e4432010 	andi	r2, r3, 16	// regs: r2=(*(r0 + 0x6b) & 0x10)
 4d4:	e9020009 	bez	r2, 0x4e6	// if (r2 == 0x0) goto loc_4e6;
 4d8:	d8240027 	ld.b	r1, (r4, 0x27)	// regs: r1=*(r4 + 0x27)
 4dc:	c4215421 	zext	r1, r1, 1, 1	// regs: r1=zext(*(r4 + 0x27))
 4e0:	ea800101 	lrw	r0, 0x0	// regs: r0=0x0
 4e4:	0695      	br	0x20e	// goto loc_20e;
loc_4e6:
 4e6:	e4632020 	andi	r3, r3, 32	// regs: r3=(*(r0 + 0x6b) & 0x20)
 4ea:	e903feb7 	bez	r3, 0x258	// if (r3 == 0x0) goto loc_258;
 4ee:	d8640027 	ld.b	r3, (r4, 0x27)	// regs: r3=*(r4 + 0x27)
 4f2:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(r4 + 0x27) & 0x2)
 4f6:	e903feb1 	bez	r3, 0x258	// if (r3 == 0x0) goto loc_258;
 4fa:	0003      	lrw	r0, 0x0	// regs: r0=0x0
 4fc:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x4fc>, r1=<clobbered>
 500:	e800fdbe 	br	0x7c	// goto loc_7c;
loc_504:
 504:	9607      	ld.w	r0, (r6, 0x1c)	// regs: r0=*(r6 + 0x1c)
 506:	e0000000 	bsr	0x0	// <lmac_get_tid>; regs: r0=<ret lmac_get_tid@0x506>, r1=<clobbered>
 50a:	d8640026 	ld.b	r3, (r4, 0x26)	// regs: r3=*(r4 + 0x26)
 50e:	c4605c60 	ins	r3, r0, 3, 0
 512:	06b6      	br	0x27e	// goto loc_27e;
loc_514:
 514:	3a41      	cmpnei	r2, 1
 516:	080f      	bt	0x534	// if (r2 != 0x1) goto loc_534;
 518:	c4435482 	zext	r2, r3, 4, 2	// regs: r2=zext(((*((*(r4 + 0x10) + 0x1)) << 0x8) | *(*(r4 + 0x10))))
 51c:	3a41      	cmpnei	r2, 1
 51e:	0c0e      	bf	0x53a	// if (r2 == 0x1) goto loc_53a;
 520:	3a40      	cmpnei	r2, 0
 522:	0c10      	bf	0x542	// if (r2 == 0x0) goto loc_542;
 524:	3a42      	cmpnei	r2, 2
 526:	0c07      	bf	0x534	// if (r2 == 0x2) goto loc_534;
 528:	3a43      	cmpnei	r2, 3
 52a:	0c12      	bf	0x54e	// if (r2 == 0x3) goto loc_54e;
 52c:	6c4b      	mov	r1, r2	// regs: r1=zext(((*((*(r4 + 0x10) + 0x1)) << 0x8) | *(*(r4 + 0x10))))
 52e:	000f      	lrw	r0, 0x0	// regs: r0=0x0
 530:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x530>, r1=<clobbered>
loc_534:
 534:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
 538:	0702      	br	0x33c	// goto loc_33c;
loc_53a:
 53a:	c4a354e3 	zext	r3, r3, 7, 5	// regs: r3=zext(((*((*(r4 + 0x10) + 0x1)) << 0x8) | *(*(r4 + 0x10))))
 53e:	3b01      	cmphsi	r3, 2
 540:	0bfa      	bt	0x534	// if (r3 >= 0x2) goto loc_534;
loc_542:
 542:	e0000000 	bsr	0x0	// <seq_num_space_update> // arg_bytes: 4; regs: r0=<ret seq_num_space_update@0x542>, r1=<clobbered>
 546:	4064      	lsli	r3, r0, 4	// regs: r3=(<ret seq_num_space_update@0x542> << 0x4)
 548:	dc6b1005 	st.h	r3, (r11, 0xa)	// *((*(r4 + 0x10) + 0xa)) = (<ret seq_num_space_update@0x542> << 0x4)
 54c:	06f8      	br	0x33c	// goto loc_33c;
loc_54e:
 54e:	e0000000 	bsr	0x0	// <seq_num_space_update> // arg_bytes: 4; regs: r0=<ret seq_num_space_update@0x54e>, r1=<clobbered>
 552:	4064      	lsli	r3, r0, 4	// regs: r3=(<ret seq_num_space_update@0x54e> << 0x4)
 554:	dc6b1007 	st.h	r3, (r11, 0xe)	// *((*(r4 + 0x10) + 0xe)) = (<ret seq_num_space_update@0x54e> << 0x4)
 558:	06f2      	br	0x33c	// goto loc_33c;
loc_55a:
 55a:	9404      	ld.w	r0, (r4, 0x10)	// regs: r0=*(r4 + 0x10)
 55c:	e0000000 	bsr	0x0	// <lmac_get_seq_num>; regs: r0=<ret lmac_get_seq_num@0x55c>, r1=<clobbered>
 560:	06ee      	br	0x33c	// goto loc_33c;
loc_562:
 562:	d8481000 	ld.h	r2, (r8, 0x0)	// regs: r2=*(r8)
 566:	c4425461 	zext	r1, r2, 3, 2	// regs: r1=zext(*(r8))
 56a:	c4615c42 	ins	r3, r1, 4, 2
 56e:	dc640024 	st.b	r3, (r4, 0x24)	// *(r4 + 0x24) = *(r4 + 0x24)
 572:	8c72      	ld.h	r3, (r4, 0x24)	// regs: r3=*(r4 + 0x24)
 574:	5244      	asri	r2, r2, 4	// regs: r2=(*(r8) >> 0x4)
 576:	c4625c65 	ins	r3, r2, 8, 5
 57a:	ac72      	st.h	r3, (r4, 0x24)	// *(r4 + 0x24) = *(r4 + 0x24)
 57c:	d8680001 	ld.b	r3, (r8, 0x1)	// regs: r3=*(r8 + 0x1)
 580:	d8440025 	ld.b	r2, (r4, 0x25)	// regs: r2=*(r4 + 0x25)
 584:	c4235423 	zext	r3, r3, 1, 1	// regs: r3=zext(*(r8 + 0x1))
 588:	c4435c06 	ins	r2, r3, 6, 6
 58c:	dc440025 	st.b	r2, (r4, 0x25)	// *(r4 + 0x25) = *(r4 + 0x25)
 590:	d8480001 	ld.b	r2, (r8, 0x1)	// regs: r2=*(r8 + 0x1)
 594:	d8640025 	ld.b	r3, (r4, 0x25)	// regs: r3=*(r4 + 0x25)
 598:	c4625c07 	ins	r3, r2, 7, 7
 59c:	dc640025 	st.b	r3, (r4, 0x25)	// *(r4 + 0x25) = *(r4 + 0x25)
 5a0:	9607      	ld.w	r0, (r6, 0x1c)	// regs: r0=*(r6 + 0x1c)
 5a2:	e0000000 	bsr	0x0	// <lmac_get_hdr_len_pv0>; regs: r0=<ret lmac_get_hdr_len_pv0@0x5a2>, r1=<clobbered>
 5a6:	dc04002a 	st.b	r0, (r4, 0x2a)	// *(r4 + 0x2a) = <ret lmac_get_hdr_len_pv0@0x5a2>
 5aa:	d864002b 	ld.b	r3, (r4, 0x2b)	// regs: r3=*(r4 + 0x2b)
 5ae:	d8470308 	ld.b	r2, (r7, 0x308)	// regs: r2=*(r7 + 0x308)
 5b2:	c4625c23 	ins	r3, r2, 4, 3
 5b6:	dc64002b 	st.b	r3, (r4, 0x2b)	// *(r4 + 0x2b) = *(r4 + 0x2b)
 5ba:	d8680001 	ld.b	r3, (r8, 0x1)	// regs: r3=*(r8 + 0x1)
 5be:	e4632010 	andi	r3, r3, 16	// regs: r3=(*(r8 + 0x1) & 0x10)
 5c2:	e9030005 	bez	r3, 0x5cc	// if (r3 == 0x0) goto loc_5cc;
 5c6:	0114      	lrw	r0, 0x0	// regs: r0=0x0
 5c8:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x5c8>, r1=<clobbered>
loc_5cc:
 5cc:	d8640024 	ld.b	r3, (r4, 0x24)	// regs: r3=*(r4 + 0x24)
 5d0:	e463201c 	andi	r3, r3, 28	// regs: r3=(*(r4 + 0x24) & 0x1c)
 5d4:	3b48      	cmpnei	r3, 8
 5d6:	0815      	bt	0x600	// if (r3 != 0x8) goto loc_600;
 5d8:	8c72      	ld.h	r3, (r4, 0x24)	// regs: r3=*(r4 + 0x24)
 5da:	e46320e0 	andi	r3, r3, 224	// regs: r3=(*(r4 + 0x24) & 0xe0)
 5de:	eb430080 	cmpnei	r3, 128
 5e2:	080f      	bt	0x600	// if (r3 != 0x80) goto loc_600;
 5e4:	d8640027 	ld.b	r3, (r4, 0x27)	// regs: r3=*(r4 + 0x27)
 5e8:	3201      	movi	r2, 1	// regs: r2=0x1
 5ea:	c4625c03 	ins	r3, r2, 3, 3
 5ee:	011d      	lrw	r0, 0x0	// regs: r0=0x0
 5f0:	dc640027 	st.b	r3, (r4, 0x27)	// *(r4 + 0x27) = *(r4 + 0x27)
 5f4:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x5f4>, r1=<clobbered>
 5f8:	8e34      	ld.h	r1, (r6, 0x28)	// regs: r1=*(r6 + 0x28)
 5fa:	9607      	ld.w	r0, (r6, 0x1c)	// regs: r0=*(r6 + 0x1c)
 5fc:	e0000000 	bsr	0x0	// <hgics_print_hex>; regs: r0=<ret hgics_print_hex@0x5fc>, r1=<clobbered>
loc_600:
 600:	d8640024 	ld.b	r3, (r4, 0x24)	// regs: r3=*(r4 + 0x24)
 604:	c4435483 	zext	r3, r3, 4, 2	// regs: r3=zext(*(r4 + 0x24))
 608:	3b23      	cmplti	r3, 4
 60a:	0c7f      	bf	0x708	// if (r3 >= 0x4) goto loc_708;
 60c:	d8072233 	ld.w	r0, (r7, 0x8cc)	// regs: r0=*(r7 + 0x8cc)
 610:	8075      	ld.b	r3, (r0, 0x15)	// regs: r3=*((*(r7 + 0x8cc) + 0x15))
 612:	e4632007 	andi	r3, r3, 7	// regs: r3=(*((*(r7 + 0x8cc) + 0x15)) & 0x7)
 616:	3b41      	cmpnei	r3, 1
 618:	083c      	bt	0x690	// if (r3 != 0x1) goto loc_690;
 61a:	d9802001 	ld.w	r12, (r0, 0x4)	// regs: r12=*((*(r7 + 0x8cc) + 0x4))
 61e:	e90c0039 	bez	r12, 0x690	// if (r12 == 0x0) goto loc_690;
 622:	9668      	ld.w	r3, (r6, 0x20)	// regs: r3=*(r6 + 0x20)
 624:	9627      	ld.w	r1, (r6, 0x1c)	// regs: r1=*(r6 + 0x1c)
 626:	d863002a 	ld.b	r3, (r3, 0x2a)	// regs: r3=*((*(r6 + 0x20) + 0x2a))
 62a:	60c4      	addu	r3, r1	// regs: r3=(*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c))
 62c:	8346      	ld.b	r2, (r3, 0x6)	// regs: r2=*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x6))
 62e:	4248      	lsli	r2, r2, 8	// regs: r2=(*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x6)) << 0x8)
 630:	d9a30007 	ld.b	r13, (r3, 0x7)	// regs: r13=*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x7))
 634:	6cb4      	or	r2, r13	// regs: r2=((*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x6)) << 0x8) | *(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x7)))
 636:	748b      	sexth	r2, r2	// regs: r2=sext16(((*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x6)) << 0x8) | *(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x7))))
 638:	eb420800 	cmpnei	r2, 2048
 63c:	082a      	bt	0x690	// if (r2 != 0x800) goto loc_690;
 63e:	8351      	ld.b	r2, (r3, 0x11)	// regs: r2=*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x11))
 640:	3a51      	cmpnei	r2, 17
 642:	0c03      	bf	0x648	// if (r2 == 0x11) goto loc_648;
 644:	3a46      	cmpnei	r2, 6
 646:	0825      	bt	0x690	// if (r2 != 0x6) goto loc_690;
loc_648:
 648:	8358      	ld.b	r2, (r3, 0x18)	// regs: r2=*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x18))
 64a:	d9a30019 	ld.b	r13, (r3, 0x19)	// regs: r13=*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x19))
 64e:	c60d482d 	lsli	r13, r13, 16	// regs: r13=(*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x19)) << 0x10)
 652:	4258      	lsli	r2, r2, 24	// regs: r2=(*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x18)) << 0x18)
 654:	6cb4      	or	r2, r13	// regs: r2=((*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x18)) << 0x18) | (*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x19)) << 0x10))
 656:	d9a3001b 	ld.b	r13, (r3, 0x1b)	// regs: r13=*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x1b))
 65a:	6cb4      	or	r2, r13	// regs: r2=(((*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x18)) << 0x18) | (*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x19)) << 0x10)) | *(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x1b)))
 65c:	d9a3001a 	ld.b	r13, (r3, 0x1a)	// regs: r13=*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x1a))
 660:	c50d482d 	lsli	r13, r13, 8	// regs: r13=(*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x1a)) << 0x8)
 664:	6cb4      	or	r2, r13	// regs: r2=((((*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x18)) << 0x18) | (*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x19)) << 0x10)) | *(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x1b))) | (*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x1a)) << 0x8))
 666:	64b2      	cmpne	r12, r2
 668:	0814      	bt	0x690	// if (T) goto loc_690;
 66a:	835e      	ld.b	r2, (r3, 0x1e)	// regs: r2=*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x1e))
 66c:	4248      	lsli	r2, r2, 8	// regs: r2=(*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x1e)) << 0x8)
 66e:	837f      	ld.b	r3, (r3, 0x1f)	// regs: r3=*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x1f))
 670:	d9801004 	ld.h	r12, (r0, 0x8)	// regs: r12=*((*(r7 + 0x8cc) + 0x8))
 674:	6cc8      	or	r3, r2	// regs: r3=(*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x1f)) | (*(((*((*(r6 + 0x20) + 0x2a)) + *(r6 + 0x1c)) + 0x1e)) << 0x8))
 676:	64f2      	cmpne	r12, r3
 678:	080c      	bt	0x690	// if (T) goto loc_690;
 67a:	8e54      	ld.h	r2, (r6, 0x28)	// regs: r2=*(r6 + 0x28)
 67c:	a052      	st.b	r2, (r0, 0x12)	// *((*(r7 + 0x8cc) + 0x12)) = *(r6 + 0x28)
 67e:	2016      	addi	r0, 23	// regs: r0=(*(r7 + 0x8cc) + 0x17)
 680:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x680>, r1=<clobbered>
 684:	d8672233 	ld.w	r3, (r7, 0x8cc)	// regs: r3=*(r7 + 0x8cc)
 688:	0303      	lrw	r0, 0x0	// regs: r0=0x0
 68a:	8332      	ld.b	r1, (r3, 0x12)	// regs: r1=*((*(r7 + 0x8cc) + 0x12))
 68c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x68c>, r1=<clobbered>
loc_690:
 690:	d8640024 	ld.b	r3, (r4, 0x24)	// regs: r3=*(r4 + 0x24)
 694:	c4435483 	zext	r3, r3, 4, 2	// regs: r3=zext(*(r4 + 0x24))
 698:	0346      	lrw	r2, 0x0	// regs: r2=0x0
loc_69a:
 69a:	d0620883 	ldr.w	r3, (r2, r3 << 2)	// regs: r3=*(0x0 + (zext(*(r4 + 0x24)) << 2))
 69e:	6c1b      	mov	r0, r6	// regs: r0=r6
 6a0:	7bcd      	jsr	r3
 6a2:	e900fe56 	bez	r0, 0x34e	// if (r0 == 0x0) goto loc_34e;
 6a6:	e800fceb 	br	0x7c	// goto loc_7c;
loc_6aa:
 6aa:	d8481000 	ld.h	r2, (r8, 0x0)	// regs: r2=*(r8)
 6ae:	5222      	asri	r1, r2, 2	// regs: r1=(*(r8) >> 0x2)
 6b0:	c4615c42 	ins	r3, r1, 4, 2
 6b4:	dc640024 	st.b	r3, (r4, 0x24)	// *(r4 + 0x24) = *(r4 + 0x24)
 6b8:	8c72      	ld.h	r3, (r4, 0x24)	// regs: r3=*(r4 + 0x24)
 6ba:	c4a254e2 	zext	r2, r2, 7, 5	// regs: r2=zext(*(r8))
 6be:	c4625c65 	ins	r3, r2, 8, 5
 6c2:	ac72      	st.h	r3, (r4, 0x24)	// *(r4 + 0x24) = *(r4 + 0x24)
 6c4:	d8680001 	ld.b	r3, (r8, 0x1)	// regs: r3=*(r8 + 0x1)
 6c8:	3200      	movi	r2, 0	// regs: r2=0x0
 6ca:	c4625c04 	ins	r3, r2, 4, 4
 6ce:	dc680001 	st.b	r3, (r8, 0x1)	// *(r8 + 0x1) = *(r8 + 0x1)
 6d2:	d8640026 	ld.b	r3, (r4, 0x26)	// regs: r3=*(r4 + 0x26)
 6d6:	c4625c04 	ins	r3, r2, 4, 4
 6da:	dc640026 	st.b	r3, (r4, 0x26)	// *(r4 + 0x26) = *(r4 + 0x26)
 6de:	d8480001 	ld.b	r2, (r8, 0x1)	// regs: r2=*(r8 + 0x1)
 6e2:	d8640025 	ld.b	r3, (r4, 0x25)	// regs: r3=*(r4 + 0x25)
 6e6:	c4625c06 	ins	r3, r2, 6, 6
 6ea:	dc640025 	st.b	r3, (r4, 0x25)	// *(r4 + 0x25) = *(r4 + 0x25)
 6ee:	9607      	ld.w	r0, (r6, 0x1c)	// regs: r0=*(r6 + 0x1c)
 6f0:	e0000000 	bsr	0x0	// <lmac_get_hdr_len_pv1>; regs: r0=<ret lmac_get_hdr_len_pv1@0x6f0>, r1=<clobbered>
 6f4:	d8640024 	ld.b	r3, (r4, 0x24)	// regs: r3=*(r4 + 0x24)
 6f8:	c4435483 	zext	r3, r3, 4, 2	// regs: r3=zext(*(r4 + 0x24))
 6fc:	3b23      	cmplti	r3, 4
 6fe:	dc04002a 	st.b	r0, (r4, 0x2a)	// *(r4 + 0x2a) = <ret lmac_get_hdr_len_pv1@0x6f0>
 702:	0c03      	bf	0x708	// if (r3 >= 0x4) goto loc_708;
 704:	135f      	lrw	r2, 0x0	// regs: r2=0x0
 706:	07ca      	br	0x69a	// goto loc_69a;
loc_708:
 708:	d8281000 	ld.h	r1, (r8, 0x0)	// regs: r1=*(r8)
 70c:	131e      	lrw	r0, 0x0	// regs: r0=0x0
 70e:	e800fd80 	br	0x20e	// goto loc_20e;
loc_712:
 712:	3980      	bclri	r1, 0	// regs: r1=((*(r6 + 0x28) + 0x8) & ~(0x1 << 0x0))
 714:	3981      	bclri	r1, 1	// regs: r1=(((*(r6 + 0x28) + 0x8) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
 716:	2103      	addi	r1, 4	// regs: r1=((((*(r6 + 0x28) + 0x8) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)) + 0x4)
 718:	0621      	br	0x35a	// goto loc_35a;
loc_71a:
 71a:	ea03067b 	movi	r3, 1659	// regs: r3=0x67b
 71e:	062e      	br	0x37a	// goto loc_37a;
loc_720:
 720:	ea03017f 	movi	r3, 383	// regs: r3=0x17f
 724:	062b      	br	0x37a	// goto loc_37a;
loc_726:
 726:	ec631000 	ori	r3, r3, 4096	// regs: r3=(*(r8) | 0x1000)
 72a:	0649      	br	0x3bc	// goto loc_3bc;
loc_72c:
 72c:	1317      	lrw	r0, 0x0	// regs: r0=0x0
 72e:	e800fd70 	br	0x20e	// goto loc_20e;
loc_732:
 732:	d8452192 	ld.w	r2, (r5, 0x648)	// regs: r2=*(r5 + 0x648)
 736:	d8652193 	ld.w	r3, (r5, 0x64c)	// regs: r3=*(r5 + 0x64c)
 73a:	2200      	addi	r2, 1	// regs: r2=(*(r5 + 0x648) + 0x1)
 73c:	3a40      	cmpnei	r2, 0
 73e:	c4630c21 	incf	r3, r3, 1
 742:	eb03ffff 	cmphsi	r3, 65536
 746:	081b      	bt	0x77c	// if (r3 >= 0x10000) goto loc_77c;
 748:	dc452192 	st.w	r2, (r5, 0x648)	// *(r5 + 0x648) = (*(r5 + 0x648) + 0x1)
 74c:	dc652193 	st.w	r3, (r5, 0x64c)	// *(r5 + 0x64c) = *(r5 + 0x64c)
loc_750:
 750:	d8680024 	ld.b	r3, (r8, 0x24)	// regs: r3=*((*(r6 + 0x20) + 0x24))
 754:	e4632003 	andi	r3, r3, 3	// regs: r3=(*((*(r6 + 0x20) + 0x24)) & 0x3)
 758:	138d      	lrw	r4, 0x0	// regs: r4=0x0
 75a:	e9030169 	bez	r3, 0xa2c	// if (r3 == 0x0) goto loc_a2c;
 75e:	3310      	movi	r3, 16	// regs: r3=0x10
 760:	dc6506c8 	st.b	r3, (r5, 0x6c8)	// *(r5 + 0x6c8) = 0x10
 764:	d8680024 	ld.b	r3, (r8, 0x24)	// regs: r3=*((*(r6 + 0x20) + 0x24))
 768:	c4435483 	zext	r3, r3, 4, 2	// regs: r3=zext(*((*(r6 + 0x20) + 0x24)))
 76c:	3b02      	cmphsi	r3, 3
 76e:	080e      	bt	0x78a	// if (r3 >= 0x3) goto loc_78a;
 770:	3b40      	cmpnei	r3, 0
 772:	0c10      	bf	0x792	// if (r3 == 0x0) goto loc_792;
 774:	1307      	lrw	r0, 0x0	// regs: r0=0x0
loc_776:
 776:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x776>, r1=<clobbered>
 77a:	0454      	br	0x822	// goto loc_822;
loc_77c:
 77c:	3301      	movi	r3, 1	// regs: r3=0x1
 77e:	3400      	movi	r4, 0	// regs: r4=0x0
 780:	dc652192 	st.w	r3, (r5, 0x648)	// *(r5 + 0x648) = 0x1
 784:	dc852193 	st.w	r4, (r5, 0x64c)	// *(r5 + 0x64c) = 0x0
 788:	07e4      	br	0x750	// goto loc_750;
loc_78a:
 78a:	3b43      	cmpnei	r3, 3
 78c:	0d1f      	bf	0x9ca	// if (r3 == 0x3) goto loc_9ca;
 78e:	1302      	lrw	r0, 0x0	// regs: r0=0x0
 790:	07f3      	br	0x776	// goto loc_776;
loc_792:
 792:	d8680025 	ld.b	r3, (r8, 0x25)	// regs: r3=*((*(r6 + 0x20) + 0x25))
 796:	e4632040 	andi	r3, r3, 64	// regs: r3=(*((*(r6 + 0x20) + 0x25)) & 0x40)
 79a:	d9662007 	ld.w	r11, (r6, 0x1c)	// regs: r11=*(r6 + 0x1c)
 79e:	3206      	movi	r2, 6	// regs: r2=0x6
 7a0:	e90300cf 	bez	r3, 0x93e	// if (r3 == 0x0) goto loc_93e;
 7a4:	123d      	lrw	r1, 0x0	// regs: r1=0x0
 7a6:	e404067f 	addi	r0, r4, 1664	// regs: r0=0x680
 7aa:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x7aa>, r1=<clobbered>
 7ae:	3206      	movi	r2, 6	// regs: r2=0x6
 7b0:	e4280019 	addi	r1, r8, 26	// regs: r1=(*(r6 + 0x20) + 0x1a)
 7b4:	e4040685 	addi	r0, r4, 1670	// regs: r0=0x686
 7b8:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x7b8>, r1=<clobbered>
 7bc:	d86b0003 	ld.b	r3, (r11, 0x3)	// regs: r3=*((*(r6 + 0x1c) + 0x3))
 7c0:	e4632020 	andi	r3, r3, 32	// regs: r3=(*((*(r6 + 0x1c) + 0x3)) & 0x20)
 7c4:	e90300ba 	bez	r3, 0x938	// if (r3 == 0x0) goto loc_938;
 7c8:	9627      	ld.w	r1, (r6, 0x1c)	// regs: r1=*(r6 + 0x1c)
 7ca:	3206      	movi	r2, 6	// regs: r2=0x6
 7cc:	210b      	addi	r1, 12	// regs: r1=(*(r6 + 0x1c) + 0xc)
 7ce:	e404068d 	addi	r0, r4, 1678	// regs: r0=0x68e
 7d2:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x7d2>, r1=<clobbered>
 7d6:	3316      	movi	r3, 22	// regs: r3=0x16
 7d8:	dc6506c8 	st.b	r3, (r5, 0x6c8)	// *(r5 + 0x6c8) = 0x16
 7dc:	e4040693 	addi	r0, r4, 1684	// regs: r0=0x694
loc_7e0:
 7e0:	d86b0003 	ld.b	r3, (r11, 0x3)	// regs: r3=*(r11 + 0x3)
loc_7e4:
 7e4:	e4632040 	andi	r3, r3, 64	// regs: r3=(r3 & 0x40)
 7e8:	e903000c 	bez	r3, 0x800	// if (r3 == 0x0) goto loc_800;
 7ec:	9627      	ld.w	r1, (r6, 0x1c)	// regs: r1=*(r6 + 0x1c)
 7ee:	3206      	movi	r2, 6	// regs: r2=0x6
 7f0:	2111      	addi	r1, 18	// regs: r1=(*(r6 + 0x1c) + 0x12)
 7f2:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x7f2>, r1=<clobbered>
 7f6:	d86406c8 	ld.b	r3, (r4, 0x6c8)	// regs: r3=*(r4 + 0x6c8)
 7fa:	2305      	addi	r3, 6	// regs: r3=(*(r4 + 0x6c8) + 0x6)
 7fc:	dc6406c8 	st.b	r3, (r4, 0x6c8)	// *(r4 + 0x6c8) = (*(r4 + 0x6c8) + 0x6)
loc_800:
 800:	9647      	ld.w	r2, (r6, 0x1c)	// regs: r2=*(r6 + 0x1c)
 802:	8261      	ld.b	r3, (r2, 0x1)	// regs: r3=*((*(r6 + 0x1c) + 0x1))
 804:	4368      	lsli	r3, r3, 8	// regs: r3=(*((*(r6 + 0x1c) + 0x1)) << 0x8)
 806:	8240      	ld.b	r2, (r2, 0x0)	// regs: r2=*(*(r6 + 0x1c))
 808:	6cc8      	or	r3, r2	// regs: r3=((*((*(r6 + 0x1c) + 0x1)) << 0x8) | *(*(r6 + 0x1c)))
 80a:	e46323ff 	andi	r3, r3, 1023	// regs: r3=(((*((*(r6 + 0x1c) + 0x1)) << 0x8) | *(*(r6 + 0x1c))) & 0x3ff)
 80e:	ec631000 	ori	r3, r3, 4096	// regs: r3=((((*((*(r6 + 0x1c) + 0x1)) << 0x8) | *(*(r6 + 0x1c))) & 0x3ff) | 0x1000)
 812:	dc65133f 	st.h	r3, (r5, 0x67e)	// *(r5 + 0x67e) = ((((*((*(r6 + 0x1c) + 0x1)) << 0x8) | *(*(r6 + 0x1c))) & 0x3ff) | 0x1000)
 816:	d868100c 	ld.h	r3, (r8, 0x18)	// regs: r3=*(r8 + 0x18)
 81a:	e463200f 	andi	r3, r3, 15	// regs: r3=(*(r8 + 0x18) & 0xf)
 81e:	dc651346 	st.h	r3, (r5, 0x68c)	// *(r5 + 0x68c) = (*(r8 + 0x18) & 0xf)
loc_822:
 822:	d9662008 	ld.w	r11, (r6, 0x20)	// regs: r11=*(r6 + 0x20)
 826:	3203      	movi	r2, 3	// regs: r2=0x3
 828:	d86b0026 	ld.b	r3, (r11, 0x26)	// regs: r3=*((*(r6 + 0x20) + 0x26))
 82c:	c4625c60 	ins	r3, r2, 3, 0
 830:	dc6b0026 	st.b	r3, (r11, 0x26)	// *((*(r6 + 0x20) + 0x26)) = *((*(r6 + 0x20) + 0x26))
 834:	d865069a 	ld.b	r3, (r5, 0x69a)	// regs: r3=*(r5 + 0x69a)
 838:	3201      	movi	r2, 1	// regs: r2=0x1
 83a:	e46320e0 	andi	r3, r3, 224	// regs: r3=(*(r5 + 0x69a) & 0xe0)
 83e:	3400      	movi	r4, 0	// regs: r4=0x0
 840:	1137      	lrw	r1, 0x0	// regs: r1=0x0
 842:	c4625c05 	ins	r3, r2, 5, 5
 846:	c4645c26 	ins	r3, r4, 7, 6
 84a:	e4010014 	addi	r0, r1, 21	// regs: r0=0x15
 84e:	3206      	movi	r2, 6	// regs: r2=0x6
 850:	dc65069a 	st.b	r3, (r5, 0x69a)	// *(r5 + 0x69a) = (*(r5 + 0x69a) & 0xe0)
 854:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x854>, r1=<clobbered>
 858:	337b      	movi	r3, 123	// regs: r3=0x7b
 85a:	dc8506a6 	st.b	r4, (r5, 0x6a6)	// *(r5 + 0x6a6) = 0x0
 85e:	dc8506a5 	st.b	r4, (r5, 0x6a5)	// *(r5 + 0x6a5) = 0x0
 862:	dc8506a4 	st.b	r4, (r5, 0x6a4)	// *(r5 + 0x6a4) = 0x0
 866:	dc6506a3 	st.b	r3, (r5, 0x6a3)	// *(r5 + 0x6a3) = 0x7b
 86a:	d86b100c 	ld.h	r3, (r11, 0x18)	// regs: r3=*((*(r6 + 0x20) + 0x18))
 86e:	4b48      	lsri	r2, r3, 8	// regs: r2=(*((*(r6 + 0x20) + 0x18)) >> 0x8)
 870:	dc6506a1 	st.b	r3, (r5, 0x6a1)	// *(r5 + 0x6a1) = *((*(r6 + 0x20) + 0x18))
 874:	dc4506a2 	st.b	r2, (r5, 0x6a2)	// *(r5 + 0x6a2) = (*((*(r6 + 0x20) + 0x18)) >> 0x8)
 878:	9608      	ld.w	r0, (r6, 0x20)	// regs: r0=*(r6 + 0x20)
 87a:	e0000000 	bsr	0x0	// <lmac_cfg_tx_ce_para.isra.5.constprop.21> // arg_bytes: 4; regs: r0=<ret lmac_cfg_tx_ce_para.isra.5.constprop.21@0x87a>, r1=<clobbered>
 87e:	1129      	lrw	r1, 0x0	// regs: r1=0x0
 880:	1109      	lrw	r0, 0x0	// regs: r0=0x0
 882:	e0000000 	bsr	0x0	// <ah_ce_start>; regs: r0=<ret ah_ce_start@0x882>, r1=<clobbered>
 886:	d8684026 	ld.bs	r3, (r8, 0x26)	// regs: r3=*(r8 + 0x26)
 88a:	6d03      	mov	r4, r0	// regs: r4=<ret ah_ce_start@0x882>
 88c:	e9a300cb 	bhsz	r3, 0xa22	// if (r3 >= 0x0) goto loc_a22;
 890:	d8270693 	ld.b	r1, (r7, 0x693)	// regs: r1=*(r7 + 0x693)
loc_894:
 894:	4921      	lsri	r1, r1, 1	// regs: r1=(r1 >> 0x1)
loc_896:
 896:	6c1b      	mov	r0, r6	// regs: r0=r6
 898:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x898>, r1=<clobbered>
 89c:	8e74      	ld.h	r3, (r6, 0x28)	// regs: r3=*(r6 + 0x28)
 89e:	e4432003 	andi	r2, r3, 3	// regs: r2=(*(r6 + 0x28) & 0x3)
 8a2:	dc68100a 	st.h	r3, (r8, 0x14)	// *(r8 + 0x14) = *(r6 + 0x28)
 8a6:	2307      	addi	r3, 8	// regs: r3=(*(r6 + 0x28) + 0x8)
 8a8:	e92201b4 	bnez	r2, 0xc10	// if (r2 != 0x0) goto loc_c10;
loc_8ac:
 8ac:	74cf      	sexth	r3, r3	// regs: r3=sext16(r3)
 8ae:	dc68100b 	st.h	r3, (r8, 0x16)	// *(r8 + 0x16) = sext16(r3)
 8b2:	e904fd9a 	bez	r4, 0x3e6	// if (r4 == 0x0) goto loc_3e6;
 8b6:	101d      	lrw	r0, 0x0	// regs: r0=0x0
loc_8b8:
 8b8:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x8b8>, r1=<clobbered>
 8bc:	d866002a 	ld.b	r3, (r6, 0x2a)	// regs: r3=*(r6 + 0x2a)
 8c0:	3200      	movi	r2, 0	// regs: r2=0x0
 8c2:	c4625c04 	ins	r3, r2, 4, 4
 8c6:	dc66002a 	st.b	r3, (r6, 0x2a)	// *(r6 + 0x2a) = *(r6 + 0x2a)
 8ca:	6c5b      	mov	r1, r6	// regs: r1=r6
 8cc:	1018      	lrw	r0, 0x0	// regs: r0=0x0
 8ce:	e0000000 	bsr	0x0	// <skb_list_queue>; regs: r0=<ret skb_list_queue@0x8ce>, r1=<clobbered>
 8d2:	1018      	lrw	r0, 0x0	// regs: r0=0x0
 8d4:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x8d4>, r1=<clobbered>
 8d8:	1017      	lrw	r0, 0x0	// regs: r0=0x0
 8da:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x8da>, r1=<clobbered>
 8de:	e800fba8 	br	0x2e	// goto loc_2e;
 8e2:	0000      	.short	0x0000
 8e4:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x3c>
 8e8:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x59>
 8ec:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x72>
 8f0:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x9f>
 8f4:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0xac>
 8f8:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0xb8>
 8fc:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_pv0_hdl>
 900:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_pv1_hdl>
 904:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0xd4>
 908:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0xeb>
 90c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
 910:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x167>
 914:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x1a5>
 918:	00000000 	.long	0x00000000	// <ah_lmac+0x526>
 91c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x686>
 920:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x6a8>
 924:	00000000 	.long	0x00000000	// <ah_lmac+0x4>
 928:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x1fa>
 92c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x538>
 930:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x5c>
 934:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x270>
loc_938:
 938:	e404068d 	addi	r0, r4, 1678	// regs: r0=(r4 + 0x68e)
 93c:	0752      	br	0x7e0	// goto loc_7e0;
loc_93e:
 93e:	e42b0001 	addi	r1, r11, 2	// regs: r1=(*(r6 + 0x1c) + 0x2)
 942:	e404067f 	addi	r0, r4, 1664	// regs: r0=0x680
 946:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x946>, r1=<clobbered>
 94a:	d80b1004 	ld.h	r0, (r11, 0x8)	// regs: r0=*((*(r6 + 0x1c) + 0x8))
 94e:	e0000000 	bsr	0x0	// <lmac_convert_sid2mac>; regs: r0=<ret lmac_convert_sid2mac@0x94e>, r1=<clobbered>
 952:	6c43      	mov	r1, r0	// regs: r1=<ret lmac_convert_sid2mac@0x94e>
 954:	3206      	movi	r2, 6	// regs: r2=0x6
 956:	e4040685 	addi	r0, r4, 1670	// regs: r0=0x686
 95a:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x95a>, r1=<clobbered>
 95e:	d86b0009 	ld.b	r3, (r11, 0x9)	// regs: r3=*((*(r6 + 0x1c) + 0x9))
 962:	e4632020 	andi	r3, r3, 32	// regs: r3=(*((*(r6 + 0x1c) + 0x9)) & 0x20)
 966:	e9030013 	bez	r3, 0x98c	// if (r3 == 0x0) goto loc_98c;
 96a:	9627      	ld.w	r1, (r6, 0x1c)	// regs: r1=*(r6 + 0x1c)
 96c:	3206      	movi	r2, 6	// regs: r2=0x6
 96e:	210b      	addi	r1, 12	// regs: r1=(*(r6 + 0x1c) + 0xc)
 970:	e404068d 	addi	r0, r4, 1678	// regs: r0=0x68e
 974:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x974>, r1=<clobbered>
loc_978:
 978:	d86506c8 	ld.b	r3, (r5, 0x6c8)	// regs: r3=*(r5 + 0x6c8)
 97c:	2305      	addi	r3, 6	// regs: r3=(*(r5 + 0x6c8) + 0x6)
 97e:	dc6506c8 	st.b	r3, (r5, 0x6c8)	// *(r5 + 0x6c8) = (*(r5 + 0x6c8) + 0x6)
 982:	e4040693 	addi	r0, r4, 1684	// regs: r0=0x694
loc_986:
 986:	d86b0009 	ld.b	r3, (r11, 0x9)	// regs: r3=*((*(r6 + 0x1c) + 0x9))
 98a:	072d      	br	0x7e4	// goto loc_7e4;
loc_98c:
 98c:	d8680026 	ld.b	r3, (r8, 0x26)	// regs: r3=*((*(r6 + 0x20) + 0x26))
 990:	e4632020 	andi	r3, r3, 32	// regs: r3=(*((*(r6 + 0x20) + 0x26)) & 0x20)
 994:	e9030018 	bez	r3, 0x9c4	// if (r3 == 0x0) goto loc_9c4;
 998:	3302      	movi	r3, 2	// regs: r3=0x2
 99a:	dc65068e 	st.b	r3, (r5, 0x68e)	// *(r5 + 0x68e) = 0x2
 99e:	3300      	movi	r3, 0	// regs: r3=0x0
 9a0:	2b2d      	subi	r3, 46	// regs: r3=0xffffffd2
 9a2:	dc65068f 	st.b	r3, (r5, 0x68f)	// *(r5 + 0x68f) = 0xffffffd2
 9a6:	3300      	movi	r3, 0	// regs: r3=0x0
 9a8:	2b1e      	subi	r3, 31	// regs: r3=0xffffffe1
 9aa:	dc650690 	st.b	r3, (r5, 0x690)	// *(r5 + 0x690) = 0xffffffe1
 9ae:	3328      	movi	r3, 40	// regs: r3=0x28
 9b0:	dc650691 	st.b	r3, (r5, 0x691)	// *(r5 + 0x691) = 0x28
 9b4:	3300      	movi	r3, 0	// regs: r3=0x0
 9b6:	2b5a      	subi	r3, 91	// regs: r3=0xffffffa5
 9b8:	dc650692 	st.b	r3, (r5, 0x692)	// *(r5 + 0x692) = 0xffffffa5
 9bc:	337c      	movi	r3, 124	// regs: r3=0x7c
 9be:	dc650693 	st.b	r3, (r5, 0x693)	// *(r5 + 0x693) = 0x7c
 9c2:	07db      	br	0x978	// goto loc_978;
loc_9c4:
 9c4:	e404068d 	addi	r0, r4, 1678	// regs: r0=0x68e
 9c8:	07df      	br	0x986	// goto loc_986;
loc_9ca:
 9ca:	0307      	lrw	r0, 0x0	// regs: r0=0x0
 9cc:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x9cc>, r1=<clobbered>
 9d0:	9627      	ld.w	r1, (r6, 0x1c)	// regs: r1=*(r6 + 0x1c)
 9d2:	3206      	movi	r2, 6	// regs: r2=0x6
 9d4:	2101      	addi	r1, 2	// regs: r1=(*(r6 + 0x1c) + 0x2)
 9d6:	e404067f 	addi	r0, r4, 1664	// regs: r0=0x680
 9da:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x9da>, r1=<clobbered>
 9de:	9627      	ld.w	r1, (r6, 0x1c)	// regs: r1=*(r6 + 0x1c)
 9e0:	3206      	movi	r2, 6	// regs: r2=0x6
 9e2:	2107      	addi	r1, 8	// regs: r1=(*(r6 + 0x1c) + 0x8)
 9e4:	e4040685 	addi	r0, r4, 1670	// regs: r0=0x686
 9e8:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x9e8>, r1=<clobbered>
 9ec:	3302      	movi	r3, 2	// regs: r3=0x2
 9ee:	dc65068e 	st.b	r3, (r5, 0x68e)	// *(r5 + 0x68e) = 0x2
 9f2:	3300      	movi	r3, 0	// regs: r3=0x0
 9f4:	2b2d      	subi	r3, 46	// regs: r3=0xffffffd2
 9f6:	dc65068f 	st.b	r3, (r5, 0x68f)	// *(r5 + 0x68f) = 0xffffffd2
 9fa:	3300      	movi	r3, 0	// regs: r3=0x0
 9fc:	2b1e      	subi	r3, 31	// regs: r3=0xffffffe1
 9fe:	dc650690 	st.b	r3, (r5, 0x690)	// *(r5 + 0x690) = 0xffffffe1
 a02:	3328      	movi	r3, 40	// regs: r3=0x28
 a04:	dc650691 	st.b	r3, (r5, 0x691)	// *(r5 + 0x691) = 0x28
 a08:	3300      	movi	r3, 0	// regs: r3=0x0
 a0a:	2b5a      	subi	r3, 91	// regs: r3=0xffffffa5
 a0c:	dc650692 	st.b	r3, (r5, 0x692)	// *(r5 + 0x692) = 0xffffffa5
 a10:	337c      	movi	r3, 124	// regs: r3=0x7c
 a12:	dc650693 	st.b	r3, (r5, 0x693)	// *(r5 + 0x693) = 0x7c
 a16:	d86506c8 	ld.b	r3, (r5, 0x6c8)	// regs: r3=*(r5 + 0x6c8)
 a1a:	2305      	addi	r3, 6	// regs: r3=(*(r5 + 0x6c8) + 0x6)
 a1c:	dc6506c8 	st.b	r3, (r5, 0x6c8)	// *(r5 + 0x6c8) = (*(r5 + 0x6c8) + 0x6)
 a20:	06f0      	br	0x800	// goto loc_800;
loc_a22:
 a22:	d8682003 	ld.w	r3, (r8, 0xc)	// regs: r3=*(r8 + 0xc)
 a26:	d8230076 	ld.b	r1, (r3, 0x76)	// regs: r1=*((*(r8 + 0xc) + 0x76))
 a2a:	0735      	br	0x894	// goto loc_894;
loc_a2c:
 a2c:	d8492000 	ld.w	r2, (r9, 0x0)	// regs: r2=*(r9)
 a30:	d8692001 	ld.w	r3, (r9, 0x4)	// regs: r3=*(r9 + 0x4)
 a34:	7446      	sextb	r1, r1	// regs: r1=sext8(*((*(r6 + 0x20) + 0x26)))
 a36:	2200      	addi	r2, 1	// regs: r2=(*(r9) + 0x1)
 a38:	3a40      	cmpnei	r2, 0
 a3a:	c4630c21 	incf	r3, r3, 1
 a3e:	dc492000 	st.w	r2, (r9, 0x0)	// *(r9) = (*(r9) + 0x1)
 a42:	dc692001 	st.w	r3, (r9, 0x4)	// *(r9 + 0x4) = *(r9 + 0x4)
 a46:	ea8b007a 	lrw	r11, 0x0	// regs: r11=0x0
 a4a:	e9a100d0 	bhsz	r1, 0xbea	// if (r1 >= 0x0) goto loc_bea;
 a4e:	d8670692 	ld.b	r3, (r7, 0x692)	// regs: r3=*(r7 + 0x692)
loc_a52:
 a52:	dc6b0000 	st.b	r3, (r11, 0x0)	// *(0x0) = r3
loc_a56:
 a56:	d8492000 	ld.w	r2, (r9, 0x0)	// regs: r2=*(r9)
 a5a:	4a68      	lsri	r3, r2, 8	// regs: r3=(*(r9) >> 0x8)
 a5c:	dc650659 	st.b	r3, (r5, 0x659)	// *(r5 + 0x659) = (*(r9) >> 0x8)
 a60:	3300      	movi	r3, 0	// regs: r3=0x0
 a62:	dc65065a 	st.b	r3, (r5, 0x65a)	// *(r5 + 0x65a) = 0x0
 a66:	d865065b 	ld.b	r3, (r5, 0x65b)	// regs: r3=*(r5 + 0x65b)
 a6a:	3001      	movi	r0, 1	// regs: r0=0x1
 a6c:	e46320e0 	andi	r3, r3, 224	// regs: r3=(*(r5 + 0x65b) & 0xe0)
 a70:	c4605c05 	ins	r3, r0, 5, 5
 a74:	d80b0000 	ld.b	r0, (r11, 0x0)	// regs: r0=*(0x0)
 a78:	d8292001 	ld.w	r1, (r9, 0x4)	// regs: r1=*(r9 + 0x4)
 a7c:	c4605c26 	ins	r3, r0, 7, 6
 a80:	dc450658 	st.b	r2, (r5, 0x658)	// *(r5 + 0x658) = *(r9)
 a84:	dc25065e 	st.b	r1, (r5, 0x65e)	// *(r5 + 0x65e) = *(r9 + 0x4)
 a88:	dc65065b 	st.b	r3, (r5, 0x65b)	// *(r5 + 0x65b) = (*(r5 + 0x65b) & 0xe0)
 a8c:	4928      	lsri	r1, r1, 8	// regs: r1=(*(r9 + 0x4) >> 0x8)
 a8e:	4a70      	lsri	r3, r2, 16	// regs: r3=(*(r9) >> 0x10)
 a90:	4a58      	lsri	r2, r2, 24	// regs: r2=(*(r9) >> 0x18)
 a92:	dc25065f 	st.b	r1, (r5, 0x65f)	// *(r5 + 0x65f) = (*(r9 + 0x4) >> 0x8)
 a96:	dc65065c 	st.b	r3, (r5, 0x65c)	// *(r5 + 0x65c) = (*(r9) >> 0x10)
 a9a:	dc45065d 	st.b	r2, (r5, 0x65d)	// *(r5 + 0x65d) = (*(r9) >> 0x18)
 a9e:	d9662007 	ld.w	r11, (r6, 0x1c)	// regs: r11=*(r6 + 0x1c)
 aa2:	d9862008 	ld.w	r12, (r6, 0x20)	// regs: r12=*(r6 + 0x20)
 aa6:	d86b0001 	ld.b	r3, (r11, 0x1)	// regs: r3=*((*(r6 + 0x1c) + 0x1))
 aaa:	d84b0000 	ld.b	r2, (r11, 0x0)	// regs: r2=*(*(r6 + 0x1c))
 aae:	4368      	lsli	r3, r3, 8	// regs: r3=(*((*(r6 + 0x1c) + 0x1)) << 0x8)
 ab0:	6cc8      	or	r3, r2	// regs: r3=((*((*(r6 + 0x1c) + 0x1)) << 0x8) | *(*(r6 + 0x1c)))
 ab2:	ea023870 	movi	r2, 14448	// regs: r2=0x3870
 ab6:	6c8a      	nor	r2, r2	// regs: r2=(~0x3870)
 ab8:	68c8      	and	r3, r2	// regs: r3=(((*((*(r6 + 0x1c) + 0x1)) << 0x8) | *(*(r6 + 0x1c))) & (~0x3870))
 aba:	ec634000 	ori	r3, r3, 16384	// regs: r3=((((*((*(r6 + 0x1c) + 0x1)) << 0x8) | *(*(r6 + 0x1c))) & (~0x3870)) | 0x4000)
 abe:	e42b0003 	addi	r1, r11, 4	// regs: r1=(*(r6 + 0x1c) + 0x4)
 ac2:	3212      	movi	r2, 18	// regs: r2=0x12
 ac4:	121b      	lrw	r0, 0x0	// regs: r0=0x0
 ac6:	dd8e2000 	st.w	r12, (r14, 0x0)	// stack_0 = *(r6 + 0x20)
 aca:	dc651330 	st.h	r3, (r5, 0x660)	// *(r5 + 0x660) = ((((*((*(r6 + 0x1c) + 0x1)) << 0x8) | *(*(r6 + 0x1c))) & (~0x3870)) | 0x4000)
 ace:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xace>, r1=<clobbered>
 ad2:	d98e2000 	ld.w	r12, (r14, 0x0)	// regs: r12=stack_0
 ad6:	e42b0017 	addi	r1, r11, 24	// regs: r1=(*(r6 + 0x1c) + 0x18)
 ada:	d86c2003 	ld.w	r3, (r12, 0xc)	// regs: r3=*(stack_0 + 0xc)
 ade:	d86300b9 	ld.b	r3, (r3, 0xb9)	// regs: r3=*((*(stack_0 + 0xc) + 0xb9))
 ae2:	e4632001 	andi	r3, r3, 1	// regs: r3=(*((*(stack_0 + 0xc) + 0xb9)) & 0x1)
 ae6:	e9030006 	bez	r3, 0xaf2	// if (r3 == 0x0) goto loc_af2;
 aea:	d86c100c 	ld.h	r3, (r12, 0x18)	// regs: r3=*(stack_0 + 0x18)
 aee:	e463200f 	andi	r3, r3, 15	// regs: r3=(*(stack_0 + 0x18) & 0xf)
loc_af2:
 af2:	dc65133a 	st.h	r3, (r5, 0x674)	// *(r5 + 0x674) = r3
 af6:	3316      	movi	r3, 22	// regs: r3=0x16
 af8:	dc6506c8 	st.b	r3, (r5, 0x6c8)	// *(r5 + 0x6c8) = 0x16
 afc:	d86c0025 	ld.b	r3, (r12, 0x25)	// regs: r3=*(stack_0 + 0x25)
 b00:	e46320c0 	andi	r3, r3, 192	// regs: r3=(*(stack_0 + 0x25) & 0xc0)
 b04:	eb4300c0 	cmpnei	r3, 192
 b08:	087c      	bt	0xc00	// if (r3 != 0xc0) goto loc_c00;
 b0a:	3206      	movi	r2, 6	// regs: r2=0x6
 b0c:	120a      	lrw	r0, 0x0	// regs: r0=0x0
 b0e:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xb0e>, r1=<clobbered>
 b12:	331c      	movi	r3, 28	// regs: r3=0x1c
 b14:	e42b001d 	addi	r1, r11, 30	// regs: r1=(*(r6 + 0x1c) + 0x1e)
 b18:	dc6506c8 	st.b	r3, (r5, 0x6c8)	// *(r5 + 0x6c8) = 0x1c
 b1c:	ea8b0047 	lrw	r11, 0x0	// regs: r11=0x0
loc_b20:
 b20:	9647      	ld.w	r2, (r6, 0x1c)	// regs: r2=*(r6 + 0x1c)
 b22:	b820      	st.w	r1, (r14, 0x0)	// stack_0 = r1
 b24:	8261      	ld.b	r3, (r2, 0x1)	// regs: r3=*((*(r6 + 0x1c) + 0x1))
 b26:	4368      	lsli	r3, r3, 8	// regs: r3=(*((*(r6 + 0x1c) + 0x1)) << 0x8)
 b28:	8200      	ld.b	r0, (r2, 0x0)	// regs: r0=*(*(r6 + 0x1c))
 b2a:	6c0c      	or	r0, r3	// regs: r0=(*(*(r6 + 0x1c)) | (*((*(r6 + 0x1c) + 0x1)) << 0x8))
 b2c:	e0000000 	bsr	0x0	// <ieee80211_is_data_qos>; regs: r0=<ret ieee80211_is_data_qos@0xb2c>, r1=<clobbered>
 b30:	9820      	ld.w	r1, (r14, 0x0)	// regs: r1=stack_0
 b32:	e9000013 	bez	r0, 0xb58	// if (r0 == 0x0) goto loc_b58;
 b36:	d8641330 	ld.h	r3, (r4, 0x660)	// regs: r3=*(0x660)
 b3a:	c40355c3 	zext	r3, r3, 14, 0	// regs: r3=zext(*(0x660))
 b3e:	dc641330 	st.h	r3, (r4, 0x660)	// *(0x660) = zext(*(0x660))
 b42:	8160      	ld.b	r3, (r1, 0x0)	// regs: r3=*(stack_0)
 b44:	dc6b0000 	st.b	r3, (r11, 0x0)	// *(0x0) = *(stack_0)
 b48:	8161      	ld.b	r3, (r1, 0x1)	// regs: r3=*(stack_0 + 0x1)
 b4a:	dc6b0001 	st.b	r3, (r11, 0x1)	// *(0x1) = *(stack_0 + 0x1)
 b4e:	d86406c8 	ld.b	r3, (r4, 0x6c8)	// regs: r3=*(0x6c8)
 b52:	2301      	addi	r3, 2	// regs: r3=(*(0x6c8) + 0x2)
 b54:	dc6406c8 	st.b	r3, (r4, 0x6c8)	// *(0x6c8) = (*(0x6c8) + 0x2)
loc_b58:
 b58:	9607      	ld.w	r0, (r6, 0x1c)	// regs: r0=*(r6 + 0x1c)
 b5a:	e0000000 	bsr	0x0	// <lmac_get_tid>; regs: r0=<ret lmac_get_tid@0xb5a>, r1=<clobbered>
 b5e:	d864069a 	ld.b	r3, (r4, 0x69a)	// regs: r3=*(0x69a)
 b62:	c4605c60 	ins	r3, r0, 3, 0
 b66:	3200      	movi	r2, 0	// regs: r2=0x0
 b68:	9627      	ld.w	r1, (r6, 0x1c)	// regs: r1=*(r6 + 0x1c)
 b6a:	e46320cf 	andi	r3, r3, 207	// regs: r3=(*(0x69a) & 0xcf)
 b6e:	c4625c26 	ins	r3, r2, 7, 6
 b72:	2109      	addi	r1, 10	// regs: r1=(*(r6 + 0x1c) + 0xa)
 b74:	3206      	movi	r2, 6	// regs: r2=0x6
 b76:	1112      	lrw	r0, 0x0	// regs: r0=0x0
 b78:	dc64069a 	st.b	r3, (r4, 0x69a)	// *(0x69a) = (*(0x69a) & 0xcf)
 b7c:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xb7c>, r1=<clobbered>
 b80:	d8640658 	ld.b	r3, (r4, 0x658)	// regs: r3=*(0x658)
 b84:	dc6406a1 	st.b	r3, (r4, 0x6a1)	// *(0x6a1) = *(0x658)
 b88:	d8640659 	ld.b	r3, (r4, 0x659)	// regs: r3=*(0x659)
 b8c:	dc6406a2 	st.b	r3, (r4, 0x6a2)	// *(0x6a2) = *(0x659)
 b90:	d864065c 	ld.b	r3, (r4, 0x65c)	// regs: r3=*(0x65c)
 b94:	dc6406a3 	st.b	r3, (r4, 0x6a3)	// *(0x6a3) = *(0x65c)
 b98:	d864065d 	ld.b	r3, (r4, 0x65d)	// regs: r3=*(0x65d)
 b9c:	dc6406a4 	st.b	r3, (r4, 0x6a4)	// *(0x6a4) = *(0x65d)
 ba0:	d864065e 	ld.b	r3, (r4, 0x65e)	// regs: r3=*(0x65e)
 ba4:	dc6406a5 	st.b	r3, (r4, 0x6a5)	// *(0x6a5) = *(0x65e)
 ba8:	d864065f 	ld.b	r3, (r4, 0x65f)	// regs: r3=*(0x65f)
 bac:	dc6406a6 	st.b	r3, (r4, 0x6a6)	// *(0x6a6) = *(0x65f)
 bb0:	9608      	ld.w	r0, (r6, 0x20)	// regs: r0=*(r6 + 0x20)
 bb2:	e0000000 	bsr	0x0	// <lmac_cfg_tx_ce_para.isra.5.constprop.21> // arg_bytes: 4; regs: r0=<ret lmac_cfg_tx_ce_para.isra.5.constprop.21@0xbb2>, r1=<clobbered>
 bb6:	1123      	lrw	r1, 0x0	// regs: r1=0x0
 bb8:	1103      	lrw	r0, 0x0	// regs: r0=0x0
 bba:	e0000000 	bsr	0x0	// <ah_ce_start>; regs: r0=<ret ah_ce_start@0xbba>, r1=<clobbered>
 bbe:	d8684026 	ld.bs	r3, (r8, 0x26)	// regs: r3=*((*(r6 + 0x20) + 0x26))
 bc2:	6d03      	mov	r4, r0	// regs: r4=<ret ah_ce_start@0xbba>
 bc4:	e9a30021 	bhsz	r3, 0xc06	// if (r3 >= 0x0) goto loc_c06;
 bc8:	d9670693 	ld.b	r11, (r7, 0x693)	// regs: r11=*(r7 + 0x693)
loc_bcc:
 bcc:	d868002a 	ld.b	r3, (r8, 0x2a)	// regs: r3=*((*(r6 + 0x20) + 0x2a))
 bd0:	d8082004 	ld.w	r0, (r8, 0x10)	// regs: r0=*((*(r6 + 0x20) + 0x10))
 bd4:	c42b484b 	lsri	r11, r11, 1	// regs: r11=(r11 >> 0x1)
 bd8:	103c      	lrw	r1, 0x0	// regs: r1=0x0
 bda:	e56b0007 	addi	r11, r11, 8	// regs: r11=((r11 >> 0x1) + 0x8)
 bde:	3208      	movi	r2, 8	// regs: r2=0x8
 be0:	600c      	addu	r0, r3	// regs: r0=(*((*(r6 + 0x20) + 0x10)) + *((*(r6 + 0x20) + 0x2a)))
 be2:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xbe2>, r1=<clobbered>
 be6:	6c6f      	mov	r1, r11	// regs: r1=((r11 >> 0x1) + 0x8)
 be8:	0657      	br	0x896	// goto loc_896;
loc_bea:
 bea:	d8682003 	ld.w	r3, (r8, 0xc)	// regs: r3=*((*(r6 + 0x20) + 0xc))
 bee:	e9030005 	bez	r3, 0xbf8	// if (r3 == 0x0) goto loc_bf8;
 bf2:	d8630075 	ld.b	r3, (r3, 0x75)	// regs: r3=*((*((*(r6 + 0x20) + 0xc)) + 0x75))
 bf6:	072e      	br	0xa52	// goto loc_a52;
loc_bf8:
 bf8:	1015      	lrw	r0, 0x0	// regs: r0=0x0
 bfa:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xbfa>, r1=<clobbered>
 bfe:	072c      	br	0xa56	// goto loc_a56;
loc_c00:
 c00:	ea8b000d 	lrw	r11, 0x0	// regs: r11=0x0
 c04:	078e      	br	0xb20	// goto loc_b20;
loc_c06:
 c06:	d8682003 	ld.w	r3, (r8, 0xc)	// regs: r3=*((*(r6 + 0x20) + 0xc))
 c0a:	d9630076 	ld.b	r11, (r3, 0x76)	// regs: r11=*((*((*(r6 + 0x20) + 0xc)) + 0x76))
 c0e:	07df      	br	0xbcc	// goto loc_bcc;
loc_c10:
 c10:	3b80      	bclri	r3, 0	// regs: r3=((*(r6 + 0x28) + 0x8) & ~(0x1 << 0x0))
 c12:	3b81      	bclri	r3, 1	// regs: r3=(((*(r6 + 0x28) + 0x8) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
 c14:	2303      	addi	r3, 4	// regs: r3=((((*(r6 + 0x28) + 0x8) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)) + 0x4)
 c16:	064b      	br	0x8ac	// goto loc_8ac;
loc_c18:
 c18:	100e      	lrw	r0, 0x0	// regs: r0=0x0
 c1a:	e800fc18 	br	0x44a	// goto loc_44a;
loc_c1e:
 c1e:	e908fc39 	bez	r8, 0x490	// if (r8 == 0x0) goto loc_490;
 c22:	3301      	movi	r3, 1	// regs: r3=0x1
 c24:	e800fc32 	br	0x488	// goto loc_488;
 c28:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x117>
 c2c:	00000000 	.long	0x00000000	// <.bss.key_id.13616>
 c30:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x662>
 c34:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x676>
 c38:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x67c>
 c3c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x69b>
 c40:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x6a8>
 c44:	00000000 	.long	0x00000000	// <ah_lmac+0x4>
 c48:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x658>
 c4c:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_task.str1.1+0x1d8>
 c50:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x70>

Disassembly of section .text.lmac_vht_info_get:

00000000 <lmac_vht_info_get>: // arg_bytes: 4
   0:	14c5      	push	r4-r8
   2:	136e      	lrw	r3, 0x0	// regs: r3=0x0
   4:	d8432294 	ld.w	r2, (r3, 0xa50)	// regs: r2=*(0xa50)
   8:	e9020065 	bez	r2, 0xd2	// if (r2 == 0x0) goto loc_d2;
   c:	d8232266 	ld.w	r1, (r3, 0x998)	// regs: r1=*(0x998)
  10:	2900      	subi	r1, 1	// regs: r1=(*(0x998) - 0x1)
  12:	3901      	cmphsi	r1, 2
  14:	085f      	bt	0xd2	// if (r1 >= 0x2) goto loc_d2;
  16:	c5e0562c 	zext	r12, r0, 17, 15	// regs: r12=zext(<arg0>)
  1a:	ea8d0069 	lrw	r13, 0x0	// regs: r13=0x0
  1e:	7470      	zextb	r1, r12	// regs: r1=zext8(zext(<arg0>))
  20:	d02d002d 	ldr.b	r13, (r13, r1 << 0)	// regs: r13=*(0x0 + (zext8(zext(<arg0>)) << 0))
  24:	d8230308 	ld.b	r1, (r3, 0x308)	// regs: r1=*(0x308)
  28:	6744      	cmphs	r1, r13
  2a:	d82200af 	ld.b	r1, (r2, 0xaf)	// regs: r1=*((*(0xa50) + 0xaf))
  2e:	0c17      	bf	0x5c	// if (!T) goto loc_5c;
  30:	e58c200f 	andi	r12, r12, 15	// regs: r12=(zext(<arg0>) & 0xf)
loc_34:
  34:	c56055cd 	zext	r13, r0, 14, 11	// regs: r13=zext(<arg0>)
  38:	eb0d0007 	cmphsi	r13, 8
  3c:	c42c5c60 	ins	r1, r12, 3, 0
  40:	dc2200af 	st.b	r1, (r2, 0xaf)	// *((*(0xa50) + 0xaf)) = *((*(0xa50) + 0xaf))
  44:	d82200ad 	ld.b	r1, (r2, 0xad)	// regs: r1=*((*(0xa50) + 0xad))
  48:	0846      	bt	0xd4	// if (r13 >= 0x8) goto loc_d4;
  4a:	c481484c 	lsri	r12, r1, 4	// regs: r12=(*((*(0xa50) + 0xad)) >> 0x4)
  4e:	6771      	cmplt	r12, r13
  50:	0c13      	bf	0x76	// if (!T) goto loc_76;
  52:	e58c0000 	addi	r12, r12, 1	// regs: r12=((*((*(0xa50) + 0xad)) >> 0x4) + 0x1)
loc_56:
  56:	c42c5c64 	ins	r1, r12, 7, 4
  5a:	0410      	br	0x7a	// goto loc_7a;
loc_5c:
  5c:	d983034a 	ld.b	r12, (r3, 0x34a)	// regs: r12=*(0x34a)
  60:	e58c2001 	andi	r12, r12, 1	// regs: r12=(*(0x34a) & 0x1)
  64:	eb4c0000 	cmpnei	r12, 0
  68:	ea0d0000 	movi	r13, 0	// regs: r13=0x0
  6c:	ea0c0003 	movi	r12, 3	// regs: r12=0x3
  70:	c58d0c20 	incf	r12, r13, 0
  74:	07e0      	br	0x34	// goto loc_34;
loc_76:
  76:	c42d5c64 	ins	r1, r13, 7, 4
loc_7a:
  7a:	dc2200ad 	st.b	r1, (r2, 0xad)	// *(r2 + 0xad) = r1
  7e:	ea0c0000 	movi	r12, 0	// regs: r12=0x0
  82:	1230      	lrw	r1, 0x0	// regs: r1=0x0
  84:	d82112ae 	ld.h	r1, (r1, 0x55c)	// regs: r1=*(0x55c)
  88:	c4e15521 	zext	r1, r1, 9, 7	// regs: r1=zext(*(0x55c))
  8c:	3901      	cmphsi	r1, 2
  8e:	080e      	bt	0xaa	// if (r1 >= 0x2) goto loc_aa;
  90:	ea0d0000 	movi	r13, 0	// regs: r13=0x0
  94:	3940      	cmpnei	r1, 0
  96:	e58c1005 	subi	r12, r12, 6	// regs: r12=0xfffffffa
  9a:	e5ad1002 	subi	r13, r13, 3	// regs: r13=0xfffffffd
  9e:	d82311b6 	ld.h	r1, (r3, 0x36c)	// regs: r1=*(r3 + 0x36c)
  a2:	c58d0c40 	inct	r12, r13, 0
  a6:	c4a15521 	zext	r1, r1, 9, 5	// regs: r1=zext(*(r3 + 0x36c))
loc_aa:
  aa:	c64056e0 	zext	r0, r0, 23, 18	// regs: r0=zext(r0)
  ae:	6000      	addu	r0, r0	// regs: r0=(zext(r0) + zext(r0))
  b0:	6030      	addu	r0, r12	// regs: r0=((zext(r0) + zext(r0)) + r12)
  b2:	dc0200b4 	st.b	r0, (r2, 0xb4)	// *(r2 + 0xb4) = ((zext(r0) + zext(r0)) + r12)
  b6:	d883036c 	ld.b	r4, (r3, 0x36c)	// regs: r4=*(r3 + 0x36c)
  ba:	e484201f 	andi	r4, r4, 31	// regs: r4=(*(r3 + 0x36c) & 0x1f)
  be:	6506      	cmpne	r1, r4
  c0:	0809      	bt	0xd2	// if (r1 != 0x0) goto loc_d2;
  c2:	1201      	lrw	r0, 0x0	// regs: r0=0x0
  c4:	6f03      	mov	r12, r0	// regs: r12=0x0
  c6:	d8404000 	ld.bs	r2, (r0, 0x0)	// regs: r2=*(0x0)
  ca:	e9620008 	blsz	r2, 0xda
  ce:	2a00      	subi	r2, 1	// regs: r2=(*(0x0) - 0x1)
  d0:	a040      	st.b	r2, (r0, 0x0)	// *(0x0) = (*(0x0) - 0x1)
loc_d2:
  d2:	1485      	pop	r4-r8
loc_d4:
  d4:	ea0c0001 	movi	r12, 1	// regs: r12=0x1
  d8:	07bf      	br	0x56	// goto loc_56;
  da:	327f      	movi	r2, 127	// regs: r2=0x7f
  dc:	307f      	movi	r0, 127	// regs: r0=0x7f
  de:	dc430a4d 	st.b	r2, (r3, 0xa4d)	// *(<arg3> + 0xa4d) = 0x7f
  e2:	d9a3227e 	ld.w	r13, (r3, 0x9f8)	// regs: r13=*(<arg3> + 0x9f8)
  e6:	3600      	movi	r6, 0	// regs: r6=0x0
  e8:	6c83      	mov	r2, r0	// regs: r2=0x7f
  ea:	ea880038 	lrw	r8, 0x0	// regs: r8=0x0
loc_ee:
  ee:	6636      	cmpne	r13, r8
  f0:	0813      	bt	0x116	// if (T) goto loc_116;
  f2:	e906000c 	bez	r6, 0x10a	// if (r6 == 0x0) goto loc_10a;
  f6:	eb42007f 	cmpnei	r2, 127
  fa:	dc030a4d 	st.b	r0, (r3, 0xa4d)	// *(<arg3> + 0xa4d) = r0
  fe:	0c06      	bf	0x10a	// if (r2 == 0x7f) goto loc_10a;
 100:	d8034a4d 	ld.bs	r0, (r3, 0xa4d)	// regs: r0=*(<arg3> + 0xa4d)
 104:	eb40007f 	cmpnei	r0, 127
 108:	081a      	bt	0x13c	// if (r0 != 0x7f) goto loc_13c;
loc_10a:
 10a:	3200      	movi	r2, 0	// regs: r2=0x0
 10c:	dc430a4d 	st.b	r2, (r3, 0xa4d)	// *(<arg3> + 0xa4d) = 0x0
 110:	dc430a4e 	st.b	r2, (r3, 0xa4e)	// *(<arg3> + 0xa4e) = 0x0
 114:	07df      	br	0xd2	// goto loc_d2;
loc_116:
 116:	d8ad00b4 	ld.b	r5, (r13, 0xb4)	// regs: r5=*(r13 + 0xb4)
 11a:	6dd7      	mov	r7, r5	// regs: r7=*(r13 + 0xb4)
 11c:	7556      	sextb	r5, r5	// regs: r5=sext8(*(r13 + 0xb4))
 11e:	6549      	cmplt	r2, r5
 120:	0c02      	bf	0x124	// if (!T) goto loc_124;
 122:	6dcb      	mov	r7, r2	// regs: r7=r2
loc_124:
 124:	d8ad40b5 	ld.bs	r5, (r13, 0xb5)	// regs: r5=*(r13 + 0xb5)
 128:	6415      	cmplt	r5, r0
 12a:	749e      	sextb	r2, r7	// regs: r2=sext8(r7)
 12c:	0806      	bt	0x138	// if (T) goto loc_138;
 12e:	6d43      	mov	r5, r0	// regs: r5=r0
loc_130:
 130:	d9ad2000 	ld.w	r13, (r13, 0x0)	// regs: r13=*(r13)
 134:	6c17      	mov	r0, r5	// regs: r0=r5
 136:	07dc      	br	0xee	// goto loc_ee;
loc_138:
 138:	3601      	movi	r6, 1	// regs: r6=0x1
 13a:	07fb      	br	0x130	// goto loc_130;
loc_13c:
 13c:	d8034a4e 	ld.bs	r0, (r3, 0xa4e)	// regs: r0=*(<arg3> + 0xa4e)
 140:	e5a00001 	addi	r13, r0, 2	// regs: r13=(*(<arg3> + 0xa4e) + 0x2)
 144:	64b5      	cmplt	r13, r2
 146:	0804      	bt	0x14e	// if (T) goto loc_14e;
 148:	2801      	subi	r0, 2	// regs: r0=(*(<arg3> + 0xa4e) - 0x2)
 14a:	6409      	cmplt	r2, r0
 14c:	0c03      	bf	0x152	// if (!T) goto loc_152;
loc_14e:
 14e:	dc430a4e 	st.b	r2, (r3, 0xa4e)	// *(<arg3> + 0xa4e) = r2
loc_152:
 152:	d8434a4e 	ld.bs	r2, (r3, 0xa4e)	// regs: r2=*(<arg3> + 0xa4e)
 156:	d9a3431c 	ld.bs	r13, (r3, 0x31c)	// regs: r13=*(<arg3> + 0x31c)
 15a:	64b5      	cmplt	r13, r2
 15c:	0805      	bt	0x166	// if (T) goto loc_166;
 15e:	d803431d 	ld.bs	r0, (r3, 0x31d)	// regs: r0=*(<arg3> + 0x31d)
 162:	6409      	cmplt	r2, r0
 164:	0fb7      	bf	0xd2	// if (!T) goto loc_d2;
loc_166:
 166:	d803431d 	ld.bs	r0, (r3, 0x31d)	// regs: r0=*(<arg3> + 0x31d)
 16a:	6034      	addu	r0, r13	// regs: r0=(*(<arg3> + 0x31d) + *(<arg3> + 0x31c))
 16c:	5001      	asri	r0, r0, 1	// regs: r0=((*(<arg3> + 0x31d) + *(<arg3> + 0x31c)) >> 0x1)
 16e:	6082      	subu	r2, r0	// regs: r2=(*(<arg3> + 0xa4e) - ((*(<arg3> + 0x31d) + *(<arg3> + 0x31c)) >> 0x1))
 170:	7488      	zextb	r2, r2	// regs: r2=zext8((*(<arg3> + 0xa4e) - ((*(<arg3> + 0x31d) + *(<arg3> + 0x31c)) >> 0x1)))
 172:	e902ffb0 	bez	r2, 0xd2	// if (r2 == 0x0) goto loc_d2;
 176:	ea8d0016 	lrw	r13, 0x0	// regs: r13=0x0
 17a:	d08d0020 	ldr.b	r0, (r13, r4 << 0)	// regs: r0=*(0x0 + (r4 << 0))
 17e:	5849      	subu	r2, r0, r2	// regs: r2=(*(0x0 + (r4 << 0)) - zext8((*(<arg3> + 0xa4e) - ((*(<arg3> + 0x31d) + *(<arg3> + 0x31c)) >> 0x1))))
 180:	748a      	sextb	r2, r2	// regs: r2=sext8((*(0x0 + (r4 << 0)) - zext8((*(<arg3> + 0xa4e) - ((*(<arg3> + 0x31d) + *(<arg3> + 0x31c)) >> 0x1)))))
 182:	3000      	movi	r0, 0	// regs: r0=0x0
loc_184:
 184:	d00d1025 	ldr.bs	r5, (r13, r0 << 0)	// regs: r5=*(0x0 + (r0 << 0))
 188:	6549      	cmplt	r2, r5
 18a:	7500      	zextb	r4, r0	// regs: r4=zext8(r0)
 18c:	0805      	bt	0x196	// if (T) goto loc_196;
 18e:	2000      	addi	r0, 1	// regs: r0=(r0 + 0x1)
 190:	3845      	cmpnei	r0, 5
 192:	0bf9      	bt	0x184	// if (r0 != 0x5) goto loc_184;
 194:	6d03      	mov	r4, r0	// regs: r4=(r0 + 0x1)
loc_196:
 196:	3c02      	cmphsi	r4, 3
 198:	6c93      	mov	r2, r4	// regs: r2=r4
 19a:	0802      	bt	0x19e	// if (r4 >= 0x3) goto loc_19e;
 19c:	3203      	movi	r2, 3	// regs: r2=0x3
loc_19e:
 19e:	7488      	zextb	r2, r2	// regs: r2=zext8(r2)
 1a0:	6486      	cmpne	r1, r2
 1a2:	0f98      	bf	0xd2	// if (!T) goto loc_d2;
 1a4:	d823036c 	ld.b	r1, (r3, 0x36c)	// regs: r1=*(<arg3> + 0x36c)
 1a8:	c4225c80 	ins	r1, r2, 4, 0
 1ac:	dc23036c 	st.b	r1, (r3, 0x36c)	// *(<arg3> + 0x36c) = *(<arg3> + 0x36c)
 1b0:	3306      	movi	r3, 6	// regs: r3=0x6
 1b2:	dc6c0000 	st.b	r3, (r12, 0x0)	// *(r12) = 0x6
 1b6:	078e      	br	0xd2	// goto loc_d2;
 1b8:	00000000 	.long	0x00000000	// <ah_lmac>
 1bc:	00000000 	.long	0x00000000	// <bw_map_sig2bss>
 1c0:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
 1c4:	0000      	.short	0x0000	// <.bss.wait_cnt.13783>
 1c6:	0000      	.short	0x0000
 1c8:	00000000 	.long	0x00000000	// <ah_lmac+0x9f8>
 1cc:	00000000 	.long	0x00000000	// <tx_pwr_tbl>

Disassembly of section .text.lmac_update_tx_state_cts:

00000000 <lmac_update_tx_state_cts>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	1065      	lrw	r3, 0x0	// regs: r3=0x0
   4:	6c43      	mov	r1, r0	// regs: r1=<arg0>
   6:	d863055d 	ld.b	r3, (r3, 0x55d)	// regs: r3=*(0x55d)
   a:	c4435440 	zext	r0, r3, 2, 2	// regs: r0=zext(*(0x55d))
   e:	e0000000 	bsr	0x0	// <ah_ant_status>; regs: r0=<ret ah_ant_status@0xe>, r1=<clobbered>
  12:	1490      	pop	r15
  14:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>

Disassembly of section .text.lmac_update_tx_state_ba:

00000000 <lmac_update_tx_state_ba>: // arg_bytes: 12
   0:	14d8      	push	r4-r11, r15
   2:	1429      	subi	r14, r14, 36	// regs: r14=(sp - 0x24)
   4:	03bf      	lrw	r5, 0x0	// regs: r5=0x0
   6:	6ec3      	mov	r11, r0	// regs: r11=<arg0>
   8:	d8e509dc 	ld.b	r7, (r5, 0x9dc)	// regs: r7=*(0x9dc)
   c:	e4e7200f 	andi	r7, r7, 15	// regs: r7=(*(0x9dc) & 0xf)
  10:	3f03      	cmphsi	r7, 4
  12:	b822      	st.w	r1, (r14, 0x8)	// local_1c = <arg1>
  14:	b843      	st.w	r2, (r14, 0xc)	// local_18 = <arg2>
  16:	0c09      	bf	0x28	// if (r7 < 0x4) goto loc_28;
  18:	131c      	lrw	r0, 0x0	// regs: r0=0x0
  1a:	6c5f      	mov	r1, r7	// regs: r1=(*(0x9dc) & 0xf)
  1c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1c>, r1=<clobbered>
  20:	3000      	movi	r0, 0	// regs: r0=0x0
  22:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_24:
  24:	1409      	addi	r14, r14, 36	// regs: r14=(sp + 0x24)
  26:	1498      	pop	r4-r11, r15
loc_28:
  28:	9862      	ld.w	r3, (r14, 0x8)	// regs: r3=local_1c
  2a:	9843      	ld.w	r2, (r14, 0xc)	// regs: r2=local_18
  2c:	6cc8      	or	r3, r2	// regs: r3=(local_1c | local_18)
  2e:	ea880078 	lrw	r8, 0x0	// regs: r8=0x0
  32:	e903002e 	bez	r3, 0x8e	// if (r3 == 0x0) goto loc_8e;
  36:	3390      	movi	r3, 144	// regs: r3=0x90
  38:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  3a:	7cdc      	mult	r3, r7	// regs: r3=(0x120 * (*(0x9dc) & 0xf))
  3c:	60e0      	addu	r3, r8	// regs: r3=((0x120 * (*(0x9dc) & 0xf)) )
  3e:	d84350e0 	ld.hs	r2, (r3, 0x1c0)	// regs: r2=*((((0x120 * (*(0x9dc) & 0xf)) ) + 0x1c0))
  42:	d86350e1 	ld.hs	r3, (r3, 0x1c2)	// regs: r3=*((((0x120 * (*(0x9dc) & 0xf)) ) + 0x1c2))
  46:	648d      	cmplt	r3, r2
  48:	081c      	bt	0x80	// if (T) goto loc_80;
  4a:	6481      	cmplt	r0, r2
  4c:	0803      	bt	0x52	// if (T) goto loc_52;
  4e:	640d      	cmplt	r3, r0
  50:	0cd5      	bf	0x1fa	// if (!T) goto loc_1fa;
loc_52:
  52:	64c9      	cmplt	r2, r3
  54:	081d      	bt	0x8e	// if (T) goto loc_8e;
loc_56:
  56:	ea090090 	movi	r9, 144	// regs: r9=0x90
  5a:	c4294829 	lsli	r9, r9, 1	// regs: r9=0x120
  5e:	c5278423 	mult	r3, r7, r9	// regs: r3=((*(0x9dc) & 0xf) * 0x120)
  62:	c4680022 	addu	r2, r8, r3	// regs: r2=(0x0 + ((*(0x9dc) & 0xf) * 0x120))
  66:	b865      	st.w	r3, (r14, 0x14)	// local_10 = ((*(0x9dc) & 0xf) * 0x120)
  68:	e46201c3 	addi	r3, r2, 452	// regs: r3=((0x0 + ((*(0x9dc) & 0xf) * 0x120)) + 0x1c4)
  6c:	ea090000 	movi	r9, 0	// regs: r9=0x0
  70:	b866      	st.w	r3, (r14, 0x18)	// local_c = ((0x0 + ((*(0x9dc) & 0xf) * 0x120)) + 0x1c4)
  72:	6d27      	mov	r4, r9	// regs: r4=0x0
  74:	1367      	lrw	r3, 0x0	// regs: r3=0x0
  76:	6ea7      	mov	r10, r9	// regs: r10=0x0
  78:	dd2e2004 	st.w	r9, (r14, 0x10)	// local_14 = 0x0
  7c:	b867      	st.w	r3, (r14, 0x1c)	// local_8 = 0x0
  7e:	0478      	br	0x16e	// goto loc_16e;
loc_80:
  80:	3100      	movi	r1, 0	// regs: r1=0x0
loc_82:
  82:	64ed      	cmplt	r11, r3
  84:	0fe9      	bf	0x56	// if (!T) goto loc_56;
  86:	66c9      	cmplt	r2, r11
  88:	0fe7      	bf	0x56	// if (!T) goto loc_56;
  8a:	e921ffe6 	bnez	r1, 0x56	// if (r1 != 0x0) goto loc_56;
loc_8e:
  8e:	3390      	movi	r3, 144	// regs: r3=0x90
  90:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  92:	c4678429 	mult	r9, r7, r3	// regs: r9=((*(0x9dc) & 0xf) * 0x120)
  96:	ea0a0000 	movi	r10, 0	// regs: r10=0x0
  9a:	c5280026 	addu	r6, r8, r9	// regs: r6=(0x0 + ((*(0x9dc) & 0xf) * 0x120))
  9e:	6d2b      	mov	r4, r10	// regs: r4=0x0
  a0:	e4c601c3 	addi	r6, r6, 452	// regs: r6=((0x0 + ((*(0x9dc) & 0xf) * 0x120)) + 0x1c4)
  a4:	ea8b005b 	lrw	r11, 0x0	// regs: r11=0x0
  a8:	0421      	br	0xea	// goto loc_ea;
loc_aa:
  aa:	c44a4823 	lsli	r3, r10, 2	// regs: r3=(r10 << 0x2)
  ae:	60e4      	addu	r3, r9	// regs: r3=((r10 << 0x2) + r9)
  b0:	60e0      	addu	r3, r8	// regs: r3=(((r10 << 0x2) + r9) + r8)
  b2:	d863202e 	ld.w	r3, (r3, 0xb8)	// regs: r3=*(((((r10 << 0x2) + r9) + r8) + 0xb8))
  b6:	e923000a 	bnez	r3, 0xca	// if (r3 != 0x0) goto loc_ca;
  ba:	6caf      	mov	r2, r11	// regs: r2=r11
  bc:	ea010d3f 	movi	r1, 3391	// regs: r1=0xd3f
  c0:	1215      	lrw	r0, 0x0	// regs: r0=0x0
  c2:	b862      	st.w	r3, (r14, 0x8)	// stack_p8 = *(((((r10 << 0x2) + r9) + r8) + 0xb8))
  c4:	e0000000 	bsr	0x0	// <assert_internal>; regs: r0=<ret assert_internal@0xc4>, r1=<clobbered>
  c8:	9862      	ld.w	r3, (r14, 0x8)	// regs: r3=stack_p8
loc_ca:
  ca:	9368      	ld.w	r3, (r3, 0x20)	// regs: r3=*(r3 + 0x20)
  cc:	3101      	movi	r1, 1	// regs: r1=0x1
  ce:	d8430025 	ld.b	r2, (r3, 0x25)	// regs: r2=*((*(r3 + 0x20) + 0x25))
  d2:	e4422002 	andi	r2, r2, 2	// regs: r2=(*((*(r3 + 0x20) + 0x25)) & 0x2)
  d6:	e9020026 	bez	r2, 0x122	// if (r2 == 0x0) goto loc_122;
  da:	d8430027 	ld.b	r2, (r3, 0x27)	// regs: r2=*((*(r3 + 0x20) + 0x27))
  de:	c4415c07 	ins	r2, r1, 7, 7
  e2:	dc430027 	st.b	r2, (r3, 0x27)	// *((*(r3 + 0x20) + 0x27)) = *((*(r3 + 0x20) + 0x27))
loc_e6:
  e6:	e54a0000 	addi	r10, r10, 1	// regs: r10=(r10 + 0x1)
loc_ea:
  ea:	8660      	ld.b	r3, (r6, 0x0)	// regs: r3=*(r6)
  ec:	64e9      	cmplt	r10, r3
  ee:	0bde      	bt	0xaa	// if (T) goto loc_aa;
  f0:	ea0a0000 	movi	r10, 0	// regs: r10=0x0
loc_f4:
  f4:	e9040015 	bez	r4, 0x11e	// if (r4 == 0x0) goto loc_11e;
  f8:	3390      	movi	r3, 144	// regs: r3=0x90
  fa:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  fc:	7dcc      	mult	r7, r3	// regs: r7=(r7 * 0x120)
  fe:	d868055d 	ld.b	r3, (r8, 0x55d)	// regs: r3=*(r8 + 0x55d)
 102:	4b45      	lsri	r2, r3, 5	// regs: r2=(*(r8 + 0x55d) >> 0x5)
 104:	61e0      	addu	r7, r8	// regs: r7=((r7 * 0x120) + r8)
 106:	c4635483 	zext	r3, r3, 4, 3	// regs: r3=zext(*(r8 + 0x55d))
 10a:	b841      	st.w	r2, (r14, 0x4)	// stack_p4 = (*(r8 + 0x55d) >> 0x5)
 10c:	b860      	st.w	r3, (r14, 0x0)	// stack_0 = zext(*(r8 + 0x55d))
 10e:	d8052294 	ld.w	r0, (r5, 0xa50)	// regs: r0=*(r5 + 0xa50)
 112:	3300      	movi	r3, 0	// regs: r3=0x0
 114:	6cab      	mov	r2, r10	// regs: r2=r10
 116:	d827206e 	ld.w	r1, (r7, 0x1b8)	// regs: r1=*((((r7 * 0x120) + r8) + 0x1b8))
 11a:	e0000000 	bsr	0x0	// <ah_tx_status>; regs: r0=<ret ah_tx_status@0x11a>, r1=<clobbered>
loc_11e:
 11e:	3000      	movi	r0, 0	// regs: r0=0x0
 120:	0782      	br	0x24	// goto loc_24;
loc_122:
 122:	6d07      	mov	r4, r1	// regs: r4=0x1
 124:	07e1      	br	0xe6	// goto loc_e6;
loc_126:
 126:	3001      	movi	r0, 1	// regs: r0=0x1
 128:	3100      	movi	r1, 0	// regs: r1=0x0
 12a:	ddae2008 	st.w	r13, (r14, 0x20)	// stack_p20 = stack_p20
 12e:	e0000000 	bsr	0x0	// <__ashldi3>; regs: r0=<ret __ashldi3@0x12e>, r1=<clobbered>
 132:	9842      	ld.w	r2, (r14, 0x8)	// regs: r2=stack_p8
 134:	9863      	ld.w	r3, (r14, 0xc)	// regs: r3=stack_pc
 136:	6880      	and	r2, r0	// regs: r2=(stack_p8 & <ret __ashldi3@0x12e>)
 138:	68c4      	and	r3, r1	// regs: r3=(stack_pc & <clobbered>)
 13a:	6c0b      	mov	r0, r2	// regs: r0=(stack_p8 & <ret __ashldi3@0x12e>)
 13c:	6c4f      	mov	r1, r3	// regs: r1=(stack_pc & <clobbered>)
 13e:	6c04      	or	r0, r1	// regs: r0=((stack_p8 & <ret __ashldi3@0x12e>) | (stack_pc & <clobbered>))
 140:	d9ae2008 	ld.w	r13, (r14, 0x20)	// regs: r13=stack_p20
 144:	e9000040 	bez	r0, 0x1c4	// if (r0 == 0x0) goto loc_1c4;
 148:	d8460027 	ld.b	r2, (r6, 0x27)	// regs: r2=*((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x27))
 14c:	c44d5c07 	ins	r2, r13, 7, 7
 150:	dc460027 	st.b	r2, (r6, 0x27)	// *((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x27)) = *((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x27))
 154:	d846500b 	ld.hs	r2, (r6, 0x16)	// regs: r2=*((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x16))
 158:	6288      	addu	r10, r2	// regs: r10=(r10 + *((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x16)))
 15a:	d84521d5 	ld.w	r2, (r5, 0x754)	// regs: r2=*(r5 + 0x754)
 15e:	2200      	addi	r2, 1	// regs: r2=(*(r5 + 0x754) + 0x1)
 160:	dc4521d5 	st.w	r2, (r5, 0x754)	// *(r5 + 0x754) = (*(r5 + 0x754) + 0x1)
loc_164:
 164:	9864      	ld.w	r3, (r14, 0x10)	// regs: r3=stack_p10
 166:	e923003a 	bnez	r3, 0x1da	// if (r3 != 0x0) goto loc_1da;
loc_16a:
 16a:	e5290000 	addi	r9, r9, 1	// regs: r9=(r9 + 0x1)
loc_16e:
 16e:	9866      	ld.w	r3, (r14, 0x18)	// regs: r3=stack_p18
 170:	8340      	ld.b	r2, (r3, 0x0)	// regs: r2=*(stack_p18)
 172:	64a5      	cmplt	r9, r2
 174:	0fc0      	bf	0xf4	// if (!T) goto loc_f4;
 176:	c4494822 	lsli	r2, r9, 2	// regs: r2=(r9 << 0x2)
 17a:	9865      	ld.w	r3, (r14, 0x14)	// regs: r3=stack_p14
 17c:	608c      	addu	r2, r3	// regs: r2=((r9 << 0x2) + stack_p14)
 17e:	60a0      	addu	r2, r8	// regs: r2=(((r9 << 0x2) + stack_p14) + r8)
 180:	d8c2202e 	ld.w	r6, (r2, 0xb8)	// regs: r6=*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8))
 184:	e9260008 	bnez	r6, 0x194	// if (r6 != 0x0) goto loc_194;
 188:	9847      	ld.w	r2, (r14, 0x1c)	// regs: r2=stack_p1c
 18a:	ea010d4a 	movi	r1, 3402	// regs: r1=0xd4a
 18e:	1102      	lrw	r0, 0x0	// regs: r0=0x0
 190:	e0000000 	bsr	0x0	// <assert_internal>; regs: r0=<ret assert_internal@0x190>, r1=<clobbered>
loc_194:
 194:	96c8      	ld.w	r6, (r6, 0x20)	// regs: r6=*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20))
 196:	ea0d0001 	movi	r13, 1	// regs: r13=0x1
 19a:	d8460025 	ld.b	r2, (r6, 0x25)	// regs: r2=*((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x25))
 19e:	e4422002 	andi	r2, r2, 2	// regs: r2=(*((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x25)) & 0x2)
 1a2:	3a40      	cmpnei	r2, 0
 1a4:	6c6f      	mov	r1, r11	// regs: r1=r11
 1a6:	d806500c 	ld.hs	r0, (r6, 0x18)	// regs: r0=*((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x18))
 1aa:	c48d0c20 	incf	r4, r13, 0
 1ae:	ddae2008 	st.w	r13, (r14, 0x20)	// stack_p20 = 0x1
 1b2:	e0000000 	bsr	0x0	// <calc_bitmap_offset>; regs: r0=<ret calc_bitmap_offset@0x1b2>, r1=<clobbered>
 1b6:	3100      	movi	r1, 0	// regs: r1=0x0
 1b8:	2900      	subi	r1, 1	// regs: r1=0xffffffff
 1ba:	6442      	cmpne	r0, r1
 1bc:	6c83      	mov	r2, r0	// regs: r2=<ret calc_bitmap_offset@0x1b2>
 1be:	d9ae2008 	ld.w	r13, (r14, 0x20)	// regs: r13=stack_p20
 1c2:	0bb2      	bt	0x126	// if (r2 != 0x0) goto loc_126;
loc_1c4:
 1c4:	d8460025 	ld.b	r2, (r6, 0x25)	// regs: r2=*((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x25))
 1c8:	e4422002 	andi	r2, r2, 2	// regs: r2=(*((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x25)) & 0x2)
 1cc:	e9220010 	bnez	r2, 0x1ec	// if (r2 != 0x0) goto loc_1ec;
 1d0:	d84521d6 	ld.w	r2, (r5, 0x758)	// regs: r2=*(r5 + 0x758)
 1d4:	2200      	addi	r2, 1	// regs: r2=(*(r5 + 0x758) + 0x1)
 1d6:	dc4521d6 	st.w	r2, (r5, 0x758)	// *(r5 + 0x758) = (*(r5 + 0x758) + 0x1)
loc_1da:
 1da:	d8450310 	ld.b	r2, (r5, 0x310)	// regs: r2=*(r5 + 0x310)
 1de:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(r5 + 0x310) & 0x8)
 1e2:	e922ff89 	bnez	r2, 0xf4	// if (r2 != 0x0) goto loc_f4;
 1e6:	3301      	movi	r3, 1	// regs: r3=0x1
 1e8:	b864      	st.w	r3, (r14, 0x10)	// stack_p10 = 0x1
 1ea:	07c0      	br	0x16a	// goto loc_16a;
loc_1ec:
 1ec:	d8460027 	ld.b	r2, (r6, 0x27)	// regs: r2=*((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x27))
 1f0:	c44d5c07 	ins	r2, r13, 7, 7
 1f4:	dc460027 	st.b	r2, (r6, 0x27)	// *((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x27)) = *((*((*(((((r9 << 0x2) + stack_p14) + r8) + 0xb8)) + 0x20)) + 0x27))
 1f8:	07b6      	br	0x164	// goto loc_164;
loc_1fa:
 1fa:	64c9      	cmplt	r2, r3
 1fc:	0b2d      	bt	0x56	// if (T) goto loc_56;
 1fe:	3101      	movi	r1, 1	// regs: r1=0x1
 200:	0741      	br	0x82	// goto loc_82;
 202:	0000      	.short	0x0000
 204:	0000      	.short	0x0000	// <ah_lmac>
 206:	0000      	.short	0x0000
 208:	00000000 	.long	0x00000000	// <.rodata.lmac_update_tx_state_ba.str1.1>
 20c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
 210:	0000      	.short	0x0000	// <.rodata.lmac_gen_tx_agglist.str1.1+0x15>
 212:	0000      	.short	0x0000
 214:	00000000 	.long	0x00000000	// <.rodata.__func__.13825>

Disassembly of section .text.ndp_ba_rx_hdl:

00000000 <ndp_ba_rx_hdl>: // arg_bytes: 12
   0:	14d5      	push	r4-r8, r15
   2:	10df      	lrw	r6, 0x0	// regs: r6=0x0
   4:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   6:	d86603e2 	ld.b	r3, (r6, 0x3e2)	// regs: r3=*(0x3e2)
   a:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x3e2) & 0x1)
   e:	6d07      	mov	r4, r1	// regs: r4=<arg1>
  10:	6e0b      	mov	r8, r2	// regs: r8=<arg2>
  12:	10fc      	lrw	r7, 0x0	// regs: r7=0x0
  14:	e9030008 	bez	r3, 0x24	// if (r3 == 0x0) goto loc_24;
  18:	d807055c 	ld.b	r0, (r7, 0x55c)	// regs: r0=*(0x55c)
  1c:	e400207f 	andi	r0, r0, 127	// regs: r0=(*(0x55c) & 0x7f)
  20:	e0000000 	bsr	0x0	// <data_scrambler>; regs: r0=<ret data_scrambler@0x20>, r1=<clobbered>
loc_24:
  24:	d867055c 	ld.b	r3, (r7, 0x55c)	// regs: r3=*(0x55c)
  28:	e9280019 	bnez	r8, 0x5a	// if (r8 != 0x0) goto loc_5a;
  2c:	e4632003 	andi	r3, r3, 3	// regs: r3=(*(0x55c) & 0x3)
  30:	c4655482 	zext	r2, r5, 4, 3	// regs: r2=zext(<arg0>)
  34:	c4a55600 	zext	r0, r5, 16, 5	// regs: r0=zext(<arg0>)
  38:	c6255701 	zext	r1, r5, 24, 17	// regs: r1=zext(<arg0>)
loc_3c:
  3c:	d9862266 	ld.w	r12, (r6, 0x998)	// regs: r12=*(0x998)
  40:	eb4c0001 	cmpnei	r12, 1
  44:	0809      	bt	0x56	// if (r12 != 0x1) goto loc_56;
  46:	64ca      	cmpne	r2, r3
  48:	0815      	bt	0x72	// if (T) goto loc_72;
  4a:	3200      	movi	r2, 0	// regs: r2=0x0
  4c:	e0000000 	bsr	0x0	// <lmac_update_tx_state_ba> // arg_bytes: 12; regs: r0=<ret lmac_update_tx_state_ba@0x4c>, r1=<clobbered>
loc_50:
  50:	3300      	movi	r3, 0	// regs: r3=0x0
  52:	dc662266 	st.w	r3, (r6, 0x998)	// *(0x998) = 0x0
loc_56:
  56:	3000      	movi	r0, 0	// regs: r0=0x0
  58:	1495      	pop	r4-r8, r15
loc_5a:
  5a:	e424201f 	andi	r1, r4, 31	// regs: r1=(<arg1> & 0x1f)
  5e:	c4655502 	zext	r2, r5, 8, 3	// regs: r2=zext(<arg0>)
  62:	c5255680 	zext	r0, r5, 20, 9	// regs: r0=zext(<arg0>)
  66:	412b      	lsli	r1, r1, 11	// regs: r1=((<arg1> & 0x1f) << 0xb)
  68:	4db5      	lsri	r5, r5, 21	// regs: r5=(<arg0> >> 0x15)
  6a:	e463203f 	andi	r3, r3, 63	// regs: r3=(*(0x55c) & 0x3f)
  6e:	6c54      	or	r1, r5	// regs: r1=(((<arg1> & 0x1f) << 0xb) | (<arg0> >> 0x15))
  70:	07e6      	br	0x3c	// goto loc_3c;
loc_72:
  72:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  74:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x74>, r1=<clobbered>
  78:	07ec      	br	0x50	// goto loc_50;
  7a:	0000      	.short	0x0000
  7c:	00000000 	.long	0x00000000	// <ah_lmac>
  80:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  82:	0000      	.short	0x0000
  84:	0000      	.short	0x0000	// <.rodata.ndp_ba_rx_hdl.str1.1>
  86:	0000      	.short	0x0000

Disassembly of section .text.lmac_update_tx_state_ack:

00000000 <lmac_update_tx_state_ack>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	1165      	lrw	r3, 0x0	// regs: r3=0x0
   6:	d82309dc 	ld.b	r1, (r3, 0x9dc)	// regs: r1=*(0x9dc)
   a:	e421200f 	andi	r1, r1, 15	// regs: r1=(*(0x9dc) & 0xf)
   e:	3903      	cmphsi	r1, 4
  10:	0c06      	bf	0x1c	// if (r1 < 0x4) goto loc_1c;
  12:	1103      	lrw	r0, 0x0	// regs: r0=0x0
  14:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x14>, r1=<clobbered>
loc_18:
  18:	1402      	addi	r14, r14, 8	// regs: r14=((sp - 0x8) + 0x8)
  1a:	1491      	pop	r4, r15
loc_1c:
  1c:	3290      	movi	r2, 144	// regs: r2=0x90
  1e:	4241      	lsli	r2, r2, 1	// regs: r2=0x120
  20:	ea8c0020 	lrw	r12, 0x0	// regs: r12=0x0
  24:	7c48      	mult	r1, r2	// regs: r1=((*(0x9dc) & 0xf) * 0x120)
  26:	6070      	addu	r1, r12	// regs: r1=(((*(0x9dc) & 0xf) * 0x120) )
  28:	6f73      	mov	r13, r12	// regs: r13=0x0
  2a:	d841202e 	ld.w	r2, (r1, 0xb8)	// regs: r2=*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8))
  2e:	9228      	ld.w	r1, (r2, 0x20)	// regs: r1=*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20))
  30:	d8410025 	ld.b	r2, (r1, 0x25)	// regs: r2=*((*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20)) + 0x25))
  34:	e4422002 	andi	r2, r2, 2	// regs: r2=(*((*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20)) + 0x25)) & 0x2)
  38:	e9020027 	bez	r2, 0x86	// if (r2 == 0x0) goto loc_86;
  3c:	3000      	movi	r0, 0	// regs: r0=0x0
  3e:	6c83      	mov	r2, r0	// regs: r2=0x0
loc_40:
  40:	d9810027 	ld.b	r12, (r1, 0x27)	// regs: r12=*((*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20)) + 0x27))
  44:	3401      	movi	r4, 1	// regs: r4=0x1
  46:	c5845c07 	ins	r12, r4, 7, 7
  4a:	dd810027 	st.b	r12, (r1, 0x27)	// *((*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20)) + 0x27)) = *((*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20)) + 0x27))
  4e:	d98321d5 	ld.w	r12, (r3, 0x754)	// regs: r12=*(0x754)
  52:	6310      	addu	r12, r4	// regs: r12=(*(0x754) + 0x1)
  54:	dd8321d5 	st.w	r12, (r3, 0x754)	// *(0x754) = (*(0x754) + 0x1)
  58:	e900ffe0 	bez	r0, 0x18	// if (r0 == 0x0) goto loc_18;
loc_5c:
  5c:	d8032294 	ld.w	r0, (r3, 0xa50)	// regs: r0=*(0xa50)
  60:	d86d055d 	ld.b	r3, (r13, 0x55d)	// regs: r3=*(0x55d)
  64:	c4a3484c 	lsri	r12, r3, 5	// regs: r12=(*(0x55d) >> 0x5)
  68:	c4635483 	zext	r3, r3, 4, 3	// regs: r3=zext(*(0x55d))
  6c:	d821500b 	ld.hs	r1, (r1, 0x16)	// regs: r1=*((*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20)) + 0x16))
  70:	b860      	st.w	r3, (r14, 0x0)	// local_8 = zext(*(0x55d))
  72:	dd8e2001 	st.w	r12, (r14, 0x4)	// local_4 = (*(0x55d) >> 0x5)
  76:	3300      	movi	r3, 0	// regs: r3=0x0
  78:	e0000000 	bsr	0x0	// <ah_tx_status>; regs: r0=<ret ah_tx_status@0x78>, r1=<clobbered>
  7c:	07ce      	br	0x18	// goto loc_18;
loc_7e:
  7e:	d841500b 	ld.hs	r2, (r1, 0x16)	// regs: r2=*((*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20)) + 0x16))
  82:	3001      	movi	r0, 1	// regs: r0=0x1
  84:	07de      	br	0x40	// goto loc_40;
loc_86:
  86:	e920fffc 	bnez	r0, 0x7e	// if (r0 != 0x0) goto loc_7e;
  8a:	d84321d6 	ld.w	r2, (r3, 0x758)	// regs: r2=*(0x758)
  8e:	2200      	addi	r2, 1	// regs: r2=(*(0x758) + 0x1)
  90:	dc4321d6 	st.w	r2, (r3, 0x758)	// *(0x758) = (*(0x758) + 0x1)
  94:	6c83      	mov	r2, r0	// regs: r2=<arg0>
  96:	07e3      	br	0x5c	// goto loc_5c;
  98:	00000000 	.long	0x00000000	// <ah_lmac>
  9c:	0000      	.short	0x0000	// <.rodata.lmac_update_tx_state_ba.str1.1>
  9e:	0000      	.short	0x0000
  a0:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>

Disassembly of section .text.ndp_ack_rx_hdl:

00000000 <ndp_ack_rx_hdl>: // arg_bytes: 12
   0:	14d5      	push	r4-r8, r15
   2:	1184      	lrw	r4, 0x0	// regs: r4=0x0
   4:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   6:	d86403e2 	ld.b	r3, (r4, 0x3e2)	// regs: r3=*(0x3e2)
   a:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x3e2) & 0x1)
   e:	6dc7      	mov	r7, r1	// regs: r7=<arg1>
  10:	6e0b      	mov	r8, r2	// regs: r8=<arg2>
  12:	11a1      	lrw	r5, 0x0	// regs: r5=0x0
  14:	e9030008 	bez	r3, 0x24	// if (r3 == 0x0) goto loc_24;
  18:	d805055c 	ld.b	r0, (r5, 0x55c)	// regs: r0=*(0x55c)
  1c:	e400207f 	andi	r0, r0, 127	// regs: r0=(*(0x55c) & 0x7f)
  20:	e0000000 	bsr	0x0	// <data_scrambler>; regs: r0=<ret data_scrambler@0x20>, r1=<clobbered>
loc_24:
  24:	e928001f 	bnez	r8, 0x62	// if (r8 != 0x0) goto loc_62;
  28:	d8652156 	ld.w	r3, (r5, 0x558)	// regs: r3=*(0x558)
  2c:	4b77      	lsri	r3, r3, 23	// regs: r3=(*(0x558) >> 0x17)
  2e:	e4432180 	andi	r2, r3, 384	// regs: r2=((*(0x558) >> 0x17) & 0x180)
  32:	d865055c 	ld.b	r3, (r5, 0x55c)	// regs: r3=*(0x55c)
  36:	e463207f 	andi	r3, r3, 127	// regs: r3=(*(0x55c) & 0x7f)
  3a:	6cc8      	or	r3, r2	// regs: r3=((*(0x55c) & 0x7f) | ((*(0x558) >> 0x17) & 0x180))
  3c:	c7065701 	zext	r1, r6, 24, 24	// regs: r1=zext(<arg0>)
  40:	c4665562 	zext	r2, r6, 11, 3	// regs: r2=zext(<arg0>)
loc_44:
  44:	d8042266 	ld.w	r0, (r4, 0x998)	// regs: r0=*(0x998)
  48:	3841      	cmpnei	r0, 1
  4a:	080a      	bt	0x5e	// if (r0 != 0x1) goto loc_5e;
  4c:	e921001a 	bnez	r1, 0x80	// if (r1 != 0x0) goto loc_80;
  50:	648e      	cmpne	r3, r2
  52:	0817      	bt	0x80	// if (T) goto loc_80;
  54:	e0000000 	bsr	0x0	// <lmac_update_tx_state_ack> // arg_bytes: 0; regs: r0=<ret lmac_update_tx_state_ack@0x54>, r1=<clobbered>
loc_58:
  58:	3300      	movi	r3, 0	// regs: r3=0x0
  5a:	dc642266 	st.w	r3, (r4, 0x998)	// *(0x998) = 0x0
loc_5e:
  5e:	3000      	movi	r0, 0	// regs: r0=0x0
  60:	1495      	pop	r4-r8, r15
loc_62:
  62:	3200      	movi	r2, 0	// regs: r2=0x0
  64:	d86512ad 	ld.h	r3, (r5, 0x55a)	// regs: r3=*(0x55a)
  68:	2a7f      	subi	r2, 128	// regs: r2=0xffffff80
  6a:	688c      	and	r2, r3	// regs: r2=(0xffffff80 & *(0x55a))
  6c:	d865055c 	ld.b	r3, (r5, 0x55c)	// regs: r3=*(0x55c)
  70:	e463207f 	andi	r3, r3, 127	// regs: r3=(*(0x55c) & 0x7f)
  74:	6cc8      	or	r3, r2	// regs: r3=((*(0x55c) & 0x7f) | (0xffffff80 & *(0x55a)))
  76:	c4675461 	zext	r1, r7, 3, 3	// regs: r1=zext(<arg1>)
  7a:	c4665642 	zext	r2, r6, 18, 3	// regs: r2=zext(<arg0>)
  7e:	07e3      	br	0x44	// goto loc_44;
loc_80:
  80:	3000      	movi	r0, 0	// regs: r0=0x0
  82:	e0000000 	bsr	0x0	// <lmac_update_tx_state_ack> // arg_bytes: 0; regs: r0=<ret lmac_update_tx_state_ack@0x82>, r1=<clobbered>
  86:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  88:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x88>, r1=<clobbered>
  8c:	07e6      	br	0x58	// goto loc_58;
  8e:	0000      	.short	0x0000
  90:	00000000 	.long	0x00000000	// <ah_lmac>
  94:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  98:	00000000 	.long	0x00000000	// <.rodata.ndp_ack_rx_hdl.str1.1>

Disassembly of section .text.lmac_select_resp_ind:

00000000 <lmac_select_resp_ind>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	1077      	lrw	r3, 0x0	// regs: r3=0x0
   4:	3290      	movi	r2, 144	// regs: r2=0x90
   6:	d86309dc 	ld.b	r3, (r3, 0x9dc)	// regs: r3=*(0x9dc)
   a:	4241      	lsli	r2, r2, 1	// regs: r2=0x120
   c:	e463200f 	andi	r3, r3, 15	// regs: r3=(*(0x9dc) & 0xf)
  10:	7cc8      	mult	r3, r2	// regs: r3=((*(0x9dc) & 0xf) * 0x120)
  12:	1054      	lrw	r2, 0x0	// regs: r2=0x0
  14:	60c8      	addu	r3, r2	// regs: r3=(((*(0x9dc) & 0xf) * 0x120) )
  16:	d843202e 	ld.w	r2, (r3, 0xb8)	// regs: r2=*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8))
  1a:	9248      	ld.w	r2, (r2, 0x20)	// regs: r2=*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20))
  1c:	821a      	ld.b	r0, (r2, 0x1a)	// regs: r0=*((*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20)) + 0x1a))
  1e:	e4802001 	andi	r4, r0, 1	// regs: r4=(*((*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20)) + 0x1a)) & 0x1)
  22:	e9240019 	bnez	r4, 0x54	// if (r4 != 0x0) goto loc_54;
  26:	d82301c2 	ld.b	r1, (r3, 0x1c2)	// regs: r1=*(((((*(0x9dc) & 0xf) * 0x120) ) + 0x1c2))
  2a:	2100      	addi	r1, 1	// regs: r1=(*(((((*(0x9dc) & 0xf) * 0x120) ) + 0x1c2)) + 0x1)
  2c:	d86301c0 	ld.b	r3, (r3, 0x1c0)	// regs: r3=*(((((*(0x9dc) & 0xf) * 0x120) ) + 0x1c0))
  30:	604e      	subu	r1, r3	// regs: r1=((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0x1c2)) + 0x1) - *(((((*(0x9dc) & 0xf) * 0x120) ) + 0x1c0)))
  32:	7444      	zextb	r1, r1	// regs: r1=zext8(((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0x1c2)) + 0x1) - *(((((*(0x9dc) & 0xf) * 0x120) ) + 0x1c0))))
  34:	3941      	cmpnei	r1, 1
  36:	0809      	bt	0x48	// if (r1 != 0x1) goto loc_48;
  38:	d8620025 	ld.b	r3, (r2, 0x25)	// regs: r3=*((*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20)) + 0x25))
  3c:	e4632002 	andi	r3, r3, 2	// regs: r3=(*((*((*(((((*(0x9dc) & 0xf) * 0x120) ) + 0xb8)) + 0x20)) + 0x25)) & 0x2)
  40:	3b40      	cmpnei	r3, 0
  42:	6403      	mvcv	r0	// regs: r0=<cond>
  44:	4001      	lsli	r0, r0, 1	// regs: r0=(<cond> << 0x1)
loc_46:
  46:	1491      	pop	r4, r15
loc_48:
  48:	eb010040 	cmphsi	r1, 65
  4c:	0c06      	bf	0x58	// if (r1 < 0x41) goto loc_58;
  4e:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  50:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x50>, r1=<clobbered>
loc_54:
  54:	3000      	movi	r0, 0	// regs: r0=0x0
  56:	07f8      	br	0x46	// goto loc_46;
loc_58:
  58:	3002      	movi	r0, 2	// regs: r0=0x2
  5a:	07f6      	br	0x46	// goto loc_46;
  5c:	0000      	.short	0x0000	// <ah_lmac>
  5e:	0000      	.short	0x0000
  60:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  62:	0000      	.short	0x0000
  64:	00000000 	.long	0x00000000	// <.rodata.lmac_select_resp_ind.str1.1>

Disassembly of section .text.lmac_gen_txvec:

00000000 <lmac_gen_txvec>: // arg_bytes: 12
   0:	14d7      	push	r4-r10, r15
   2:	3790      	movi	r7, 144	// regs: r7=0x90
   4:	47e1      	lsli	r7, r7, 1	// regs: r7=0x120
   6:	7dc0      	mult	r7, r0	// regs: r7=(0x120 * <arg0>)
   8:	ea8500ff 	lrw	r5, 0x0	// regs: r5=0x0
   c:	c4e5002a 	addu	r10, r5, r7	// regs: r10=(0x0 + (0x120 * <arg0>))
  10:	6e47      	mov	r9, r1	// regs: r9=<arg1>
  12:	d86a202e 	ld.w	r3, (r10, 0xb8)	// regs: r3=*(((0x0 + (0x120 * <arg0>)) + 0xb8))
  16:	6c4b      	mov	r1, r2	// regs: r1=<arg2>
  18:	9388      	ld.w	r4, (r3, 0x20)	// regs: r4=*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20))
  1a:	6e03      	mov	r8, r0	// regs: r8=<arg0>
  1c:	6c13      	mov	r0, r4	// regs: r0=*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20))
  1e:	6d8b      	mov	r6, r2	// regs: r6=<arg2>
  20:	e0000000 	bsr	0x0	// <lmac_tx_pwr_sel> // arg_bytes: 8; regs: r0=<ret lmac_tx_pwr_sel@0x20>, r1=<clobbered>
  24:	d86a01c8 	ld.b	r3, (r10, 0x1c8)	// regs: r3=*(((0x0 + (0x120 * <arg0>)) + 0x1c8))
  28:	c4605c80 	ins	r3, r0, 4, 0
  2c:	3003      	movi	r0, 3	// regs: r0=0x3
  2e:	c4098022 	divu	r2, r9, r0	// regs: r2=(<arg1> / 0x3)
  32:	7c80      	mult	r2, r0	// regs: r2=((<arg1> / 0x3) * 0x3)
  34:	c4490082 	subu	r2, r9, r2	// regs: r2=(<arg1> - ((<arg1> / 0x3) * 0x3))
  38:	e46320df 	andi	r3, r3, 223	// regs: r3=(*(((0x0 + (0x120 * <arg0>)) + 0x1c8)) & 0xdf)
  3c:	c4625c26 	ins	r3, r2, 7, 6
  40:	dc6a01c8 	st.b	r3, (r10, 0x1c8)	// *(((0x0 + (0x120 * <arg0>)) + 0x1c8)) = (*(((0x0 + (0x120 * <arg0>)) + 0x1c8)) & 0xdf)
  44:	d864002b 	ld.b	r3, (r4, 0x2b)	// regs: r3=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b))
  48:	d84a01c9 	ld.b	r2, (r10, 0x1c9)	// regs: r2=*(((0x0 + (0x120 * <arg0>)) + 0x1c9))
  4c:	c4635483 	zext	r3, r3, 4, 3	// regs: r3=zext(*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b)))
  50:	eb490003 	cmpnei	r9, 3
  54:	e4e701c7 	addi	r7, r7, 456	// regs: r7=((0x120 * <arg0>) + 0x1c8)
  58:	c4435c20 	ins	r2, r3, 1, 0
  5c:	61d4      	addu	r7, r5	// regs: r7=(((0x120 * <arg0>) + 0x1c8) )
  5e:	dc4a01c9 	st.b	r2, (r10, 0x1c9)	// *(((0x0 + (0x120 * <arg0>)) + 0x1c9)) = *(((0x0 + (0x120 * <arg0>)) + 0x1c9))
  62:	0809      	bt	0x74	// if (r9 != 0x3) goto loc_74;
  64:	d864002b 	ld.b	r3, (r4, 0x2b)	// regs: r3=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b))
  68:	3200      	movi	r2, 0	// regs: r2=0x0
loc_6a:
  6a:	c4625c21 	ins	r3, r2, 2, 1
  6e:	dc64002b 	st.b	r3, (r4, 0x2b)	// *((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b)) = *((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b))
  72:	040d      	br	0x8c	// goto loc_8c;
loc_74:
  74:	d8640024 	ld.b	r3, (r4, 0x24)	// regs: r3=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x24))
  78:	c4435483 	zext	r3, r3, 4, 2	// regs: r3=zext(*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x24)))
  7c:	3b41      	cmpnei	r3, 1
  7e:	0cba      	bf	0x1f2	// if (r3 == 0x1) goto loc_1f2;
  80:	3b40      	cmpnei	r3, 0
  82:	0cc3      	bf	0x208	// if (r3 == 0x0) goto loc_208;
  84:	3b42      	cmpnei	r3, 2
  86:	0cba      	bf	0x1fa	// if (r3 == 0x2) goto loc_1fa;
  88:	3b43      	cmpnei	r3, 3
  8a:	0cbf      	bf	0x208	// if (r3 == 0x3) goto loc_208;
loc_8c:
  8c:	3390      	movi	r3, 144	// regs: r3=0x90
  8e:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  90:	7ce0      	mult	r3, r8	// regs: r3=(0x120 * <arg0>)
  92:	5d2c      	addu	r1, r5, r3	// regs: r1=(0x0 + (0x120 * <arg0>))
  94:	d844002b 	ld.b	r2, (r4, 0x2b)	// regs: r2=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b))
  98:	c4225442 	zext	r2, r2, 2, 1	// regs: r2=zext(*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b)))
  9c:	d86101c9 	ld.b	r3, (r1, 0x1c9)	// regs: r3=*(((0x0 + (0x120 * <arg0>)) + 0x1c9))
  a0:	c4625c22 	ins	r3, r2, 3, 2
  a4:	e446200f 	andi	r2, r6, 15	// regs: r2=(<arg2> & 0xf)
  a8:	c4625c64 	ins	r3, r2, 7, 4
  ac:	dc6101c9 	st.b	r3, (r1, 0x1c9)	// *(((0x0 + (0x120 * <arg0>)) + 0x1c9)) = *(((0x0 + (0x120 * <arg0>)) + 0x1c9))
  b0:	ea0d007f 	movi	r13, 127	// regs: r13=0x7f
  b4:	016a      	lrw	r3, 0x0	// regs: r3=0x0
  b6:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  b8:	936f      	ld.w	r3, (r3, 0x3c)	// regs: r3=*((*(0x0) + 0x3c))
  ba:	c5a3802c 	divu	r12, r3, r13	// regs: r12=(*((*(0x0) + 0x3c)) / 0x7f)
  be:	7f34      	mult	r12, r13	// regs: r12=((*((*(0x0) + 0x3c)) / 0x7f) * 0x7f)
  c0:	60f2      	subu	r3, r12	// regs: r3=(*((*(0x0) + 0x3c)) - ((*((*(0x0) + 0x3c)) / 0x7f) * 0x7f))
  c2:	2300      	addi	r3, 1	// regs: r3=((*((*(0x0) + 0x3c)) - ((*((*(0x0) + 0x3c)) / 0x7f) * 0x7f)) + 0x1)
  c4:	d98101ca 	ld.b	r12, (r1, 0x1ca)	// regs: r12=*(((0x0 + (0x120 * <arg0>)) + 0x1ca))
  c8:	c5835cc0 	ins	r12, r3, 6, 0
  cc:	d86101c8 	ld.b	r3, (r1, 0x1c8)	// regs: r3=*(((0x0 + (0x120 * <arg0>)) + 0x1c8))
  d0:	e46320c0 	andi	r3, r3, 192	// regs: r3=(*(((0x0 + (0x120 * <arg0>)) + 0x1c8)) & 0xc0)
  d4:	dd8101ca 	st.b	r12, (r1, 0x1ca)	// *(((0x0 + (0x120 * <arg0>)) + 0x1ca)) = *(((0x0 + (0x120 * <arg0>)) + 0x1ca))
  d8:	e9230007 	bnez	r3, 0xe6	// if (r3 != 0x0) goto loc_e6;
  dc:	0173      	lrw	r3, 0x0	// regs: r3=0x0
  de:	d8630308 	ld.b	r3, (r3, 0x308)	// regs: r3=*(0x308)
  e2:	3b01      	cmphsi	r3, 2
  e4:	0808      	bt	0xf4	// if (r3 >= 0x2) goto loc_f4;
loc_e6:
  e6:	d8640025 	ld.b	r3, (r4, 0x25)	// regs: r3=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x25))
  ea:	3100      	movi	r1, 0	// regs: r1=0x0
  ec:	c4615c05 	ins	r3, r1, 5, 5
  f0:	dc640025 	st.b	r3, (r4, 0x25)	// *((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x25)) = *((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x25))
loc_f4:
  f4:	3390      	movi	r3, 144	// regs: r3=0x90
  f6:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  f8:	7ce0      	mult	r3, r8	// regs: r3=(0x120 * <arg0>)
  fa:	60d4      	addu	r3, r5	// regs: r3=((0x120 * <arg0>) )
  fc:	d8240025 	ld.b	r1, (r4, 0x25)	// regs: r1=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x25))
 100:	d98301ca 	ld.b	r12, (r3, 0x1ca)	// regs: r12=*((((0x120 * <arg0>) ) + 0x1ca))
 104:	c4a154a1 	zext	r1, r1, 5, 5	// regs: r1=zext(*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x25)))
 108:	c5815c07 	ins	r12, r1, 7, 7
 10c:	dd8301ca 	st.b	r12, (r3, 0x1ca)	// *((((0x120 * <arg0>) ) + 0x1ca)) = *((((0x120 * <arg0>) ) + 0x1ca))
 110:	d803206f 	ld.w	r0, (r3, 0x1bc)	// regs: r0=*((((0x120 * <arg0>) ) + 0x1bc))
 114:	ea0c0000 	movi	r12, 0	// regs: r12=0x0
 118:	ea0d0000 	movi	r13, 0	// regs: r13=0x0
 11c:	dc032073 	st.w	r0, (r3, 0x1cc)	// *((((0x120 * <arg0>) ) + 0x1cc)) = *((((0x120 * <arg0>) ) + 0x1bc))
 120:	dd832074 	st.w	r12, (r3, 0x1d0)	// *((((0x120 * <arg0>) ) + 0x1d0)) = 0x0
 124:	dda32075 	st.w	r13, (r3, 0x1d4)	// *((((0x120 * <arg0>) ) + 0x1d4)) = 0x0
 128:	d86301c8 	ld.b	r3, (r3, 0x1c8)	// regs: r3=*((((0x120 * <arg0>) ) + 0x1c8))
 12c:	e463201f 	andi	r3, r3, 31	// regs: r3=(*((((0x120 * <arg0>) ) + 0x1c8)) & 0x1f)
 130:	2b02      	subi	r3, 3	// regs: r3=((*((((0x120 * <arg0>) ) + 0x1c8)) & 0x1f) - 0x3)
 132:	74cc      	zextb	r3, r3	// regs: r3=zext8(((*((((0x120 * <arg0>) ) + 0x1c8)) & 0x1f) - 0x3))
 134:	3b01      	cmphsi	r3, 2
 136:	0c09      	bf	0x148	// if (r3 < 0x2) goto loc_148;
 138:	9463      	ld.w	r3, (r4, 0xc)	// regs: r3=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0xc))
 13a:	e903001d 	bez	r3, 0x174	// if (r3 == 0x0) goto loc_174;
 13e:	d86340b4 	ld.bs	r3, (r3, 0xb4)	// regs: r3=*((*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0xc)) + 0xb4))
 142:	eb230025 	cmplti	r3, 38
 146:	0817      	bt	0x174	// if (r3 < 0x26) goto loc_174;
loc_148:
 148:	3390      	movi	r3, 144	// regs: r3=0x90
 14a:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
 14c:	7ce0      	mult	r3, r8	// regs: r3=(0x120 * <arg0>)
 14e:	60d4      	addu	r3, r5	// regs: r3=((0x120 * <arg0>) )
 150:	d86301c9 	ld.b	r3, (r3, 0x1c9)	// regs: r3=*((((0x120 * <arg0>) ) + 0x1c9))
 154:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*((((0x120 * <arg0>) ) + 0x1c9)))
 158:	230a      	addi	r3, 11	// regs: r3=(zext(*((((0x120 * <arg0>) ) + 0x1c9))) + 0xb)
 15a:	e463200f 	andi	r3, r3, 15	// regs: r3=((zext(*((((0x120 * <arg0>) ) + 0x1c9))) + 0xb) & 0xf)
 15e:	3b02      	cmphsi	r3, 3
 160:	080a      	bt	0x174	// if (r3 >= 0x3) goto loc_174;
 162:	0274      	lrw	r3, 0x0	// regs: r3=0x0
 164:	d8230310 	ld.b	r1, (r3, 0x310)	// regs: r1=*(0x310)
 168:	d864002b 	ld.b	r3, (r4, 0x2b)	// regs: r3=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b))
 16c:	c4615c00 	ins	r3, r1, 0, 0
 170:	dc64002b 	st.b	r3, (r4, 0x2b)	// *((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b)) = *((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b))
loc_174:
 174:	3390      	movi	r3, 144	// regs: r3=0x90
 176:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
 178:	7ce0      	mult	r3, r8	// regs: r3=(0x120 * <arg0>)
 17a:	60d4      	addu	r3, r5	// regs: r3=((0x120 * <arg0>) )
 17c:	e58301c7 	addi	r12, r3, 456	// regs: r12=(((0x120 * <arg0>) ) + 0x1c8)
 180:	d8cc0001 	ld.b	r6, (r12, 0x1)	// regs: r6=*((((0x120 * <arg0>) ) + 0x1c9))
 184:	d824003f 	ld.b	r1, (r4, 0x3f)	// regs: r1=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x3f))
 188:	c4465466 	zext	r6, r6, 3, 2	// regs: r6=zext(*((((0x120 * <arg0>) ) + 0x1c9)))
 18c:	d9ac0003 	ld.b	r13, (r12, 0x3)	// regs: r13=*((((0x120 * <arg0>) ) + 0x1cb))
 190:	c4a154c1 	zext	r1, r1, 6, 5	// regs: r1=zext(*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x3f)))
 194:	3e41      	cmpnei	r6, 1
 196:	c5a15c20 	ins	r13, r1, 1, 0
 19a:	ddac0003 	st.b	r13, (r12, 0x3)	// *((((0x120 * <arg0>) ) + 0x1cb)) = *((((0x120 * <arg0>) ) + 0x1cb))
 19e:	0c77      	bf	0x28c	// if (r6 == 0x1) goto loc_28c;
 1a0:	3e40      	cmpnei	r6, 0
 1a2:	0c37      	bf	0x210	// if (r6 == 0x0) goto loc_210;
 1a4:	3e42      	cmpnei	r6, 2
 1a6:	0cdc      	bf	0x35e	// if (r6 == 0x2) goto loc_35e;
loc_1a8:
 1a8:	d8640027 	ld.b	r3, (r4, 0x27)	// regs: r3=*(r4 + 0x27)
 1ac:	e4632040 	andi	r3, r3, 64	// regs: r3=(*(r4 + 0x27) & 0x40)
 1b0:	e9030012 	bez	r3, 0x1d4	// if (r3 == 0x0) goto loc_1d4;
 1b4:	3390      	movi	r3, 144	// regs: r3=0x90
 1b6:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
 1b8:	7ce0      	mult	r3, r8	// regs: r3=(0x120 * r8)
 1ba:	60d4      	addu	r3, r5	// regs: r3=((0x120 * r8) + r5)
 1bc:	d84310e3 	ld.h	r2, (r3, 0x1c6)	// regs: r2=*((((0x120 * r8) + r5) + 0x1c6))
 1c0:	c4c25522 	zext	r2, r2, 9, 6	// regs: r2=zext(*((((0x120 * r8) + r5) + 0x1c6)))
 1c4:	d8632073 	ld.w	r3, (r3, 0x1cc)	// regs: r3=*((((0x120 * r8) + r5) + 0x1cc))
 1c8:	60c8      	addu	r3, r2	// regs: r3=(*((((0x120 * r8) + r5) + 0x1cc)) + zext(*((((0x120 * r8) + r5) + 0x1c6))))
 1ca:	3228      	movi	r2, 40	// regs: r2=0x28
 1cc:	7cc8      	mult	r3, r2	// regs: r3=((*((((0x120 * r8) + r5) + 0x1cc)) + zext(*((((0x120 * r8) + r5) + 0x1c6)))) * 0x28)
 1ce:	034f      	lrw	r2, 0x0	// regs: r2=0x0
 1d0:	dc62133a 	st.h	r3, (r2, 0x674)	// *(0x674) = ((*((((0x120 * r8) + r5) + 0x1cc)) + zext(*((((0x120 * r8) + r5) + 0x1c6)))) * 0x28)
loc_1d4:
 1d4:	3390      	movi	r3, 144	// regs: r3=0x90
 1d6:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
 1d8:	7e0c      	mult	r8, r3	// regs: r8=(r8 * 0x120)
 1da:	6160      	addu	r5, r8	// regs: r5=(r5 + (r8 * 0x120))
 1dc:	3201      	movi	r2, 1	// regs: r2=0x1
 1de:	d86501c7 	ld.b	r3, (r5, 0x1c7)	// regs: r3=*(((r5 + (r8 * 0x120)) + 0x1c7))
 1e2:	c4625c02 	ins	r3, r2, 2, 2
 1e6:	dc6501c7 	st.b	r3, (r5, 0x1c7)	// *(((r5 + (r8 * 0x120)) + 0x1c7)) = *(((r5 + (r8 * 0x120)) + 0x1c7))
 1ea:	6c1f      	mov	r0, r7	// regs: r0=r7
 1ec:	e4a501bf 	addi	r5, r5, 448	// regs: r5=((r5 + (r8 * 0x120)) + 0x1c0)
 1f0:	1497      	pop	r4-r10, r15
loc_1f2:
 1f2:	d864002b 	ld.b	r3, (r4, 0x2b)	// regs: r3=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b))
 1f6:	3202      	movi	r2, 2	// regs: r2=0x2
 1f8:	0739      	br	0x6a	// goto loc_6a;
loc_1fa:
 1fa:	d844002b 	ld.b	r2, (r4, 0x2b)	// regs: r2=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b))
 1fe:	c4435c21 	ins	r2, r3, 2, 1
 202:	dc44002b 	st.b	r2, (r4, 0x2b)	// *((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b)) = *((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b))
 206:	0743      	br	0x8c	// goto loc_8c;
loc_208:
 208:	d864002b 	ld.b	r3, (r4, 0x2b)	// regs: r3=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b))
 20c:	3201      	movi	r2, 1	// regs: r2=0x1
 20e:	072e      	br	0x6a	// goto loc_6a;
loc_210:
 210:	d98310e3 	ld.h	r12, (r3, 0x1c6)	// regs: r12=*((((0x120 * <arg0>) ) + 0x1c6))
 214:	ea0d000e 	movi	r13, 14	// regs: r13=0xe
 218:	c58d5c66 	ins	r12, r13, 9, 6
 21c:	dd8310e3 	st.h	r12, (r3, 0x1c6)	// *((((0x120 * <arg0>) ) + 0x1c6)) = *((((0x120 * <arg0>) ) + 0x1c6))
 220:	d984002b 	ld.b	r12, (r4, 0x2b)	// regs: r12=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b))
 224:	d82301d0 	ld.b	r1, (r3, 0x1d0)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1d0))
 228:	c42c5c02 	ins	r1, r12, 2, 2
 22c:	ea0c0001 	movi	r12, 1	// regs: r12=0x1
 230:	c42c5c04 	ins	r1, r12, 4, 4
 234:	c42c5c06 	ins	r1, r12, 6, 6
 238:	dc2301d0 	st.b	r1, (r3, 0x1d0)	// *((((0x120 * <arg0>) ) + 0x1d0)) = *((((0x120 * <arg0>) ) + 0x1d0))
 23c:	d82310e8 	ld.h	r1, (r3, 0x1d0)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1d0))
 240:	c4225c67 	ins	r1, r2, 10, 7
 244:	dc2310e8 	st.h	r1, (r3, 0x1d0)	// *((((0x120 * <arg0>) ) + 0x1d0)) = *((((0x120 * <arg0>) ) + 0x1d0))
 248:	d84301d1 	ld.b	r2, (r3, 0x1d1)	// regs: r2=*((((0x120 * <arg0>) ) + 0x1d1))
 24c:	c44c5c03 	ins	r2, r12, 3, 3
 250:	dc4301d1 	st.b	r2, (r3, 0x1d1)	// *((((0x120 * <arg0>) ) + 0x1d1)) = *((((0x120 * <arg0>) ) + 0x1d1))
 254:	d8432074 	ld.w	r2, (r3, 0x1d0)	// regs: r2=*((((0x120 * <arg0>) ) + 0x1d0))
 258:	e52301cf 	addi	r9, r3, 464	// regs: r9=(((0x120 * <arg0>) ) + 0x1d0)
 25c:	c4405d0c 	ins	r2, r0, 20, 12
 260:	dc432074 	st.w	r2, (r3, 0x1d0)	// *((((0x120 * <arg0>) ) + 0x1d0)) = *((((0x120 * <arg0>) ) + 0x1d0))
 264:	e0000000 	bsr	0x0	// <lmac_select_resp_ind> // arg_bytes: 0; regs: r0=<ret lmac_select_resp_ind@0x264>, r1=<clobbered>
 268:	d8690002 	ld.b	r3, (r9, 0x2)	// regs: r3=*((((0x120 * <arg0>) ) + 0x1d2))
 26c:	1348      	lrw	r2, 0x0	// regs: r2=0x0
 26e:	c4605c25 	ins	r3, r0, 6, 5
 272:	dc690002 	st.b	r3, (r9, 0x2)	// *((((0x120 * <arg0>) ) + 0x1d2)) = *((((0x120 * <arg0>) ) + 0x1d2))
 276:	d84203e4 	ld.b	r2, (r2, 0x3e4)	// regs: r2=*(0x3e4)
 27a:	d8690003 	ld.b	r3, (r9, 0x3)	// regs: r3=*((((0x120 * <arg0>) ) + 0x1d3))
 27e:	c4625c00 	ins	r3, r2, 0, 0
 282:	c4665c01 	ins	r3, r6, 1, 1
 286:	dc690003 	st.b	r3, (r9, 0x3)	// *((((0x120 * <arg0>) ) + 0x1d3)) = *((((0x120 * <arg0>) ) + 0x1d3))
 28a:	078f      	br	0x1a8	// goto loc_1a8;
loc_28c:
 28c:	d82301d0 	ld.b	r1, (r3, 0x1d0)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1d0))
 290:	d9a310e3 	ld.h	r13, (r3, 0x1c6)	// regs: r13=*((((0x120 * <arg0>) ) + 0x1c6))
 294:	ea090006 	movi	r9, 6	// regs: r9=0x6
 298:	c5a95c66 	ins	r13, r9, 9, 6
 29c:	c4265c00 	ins	r1, r6, 0, 0
 2a0:	dc2301d0 	st.b	r1, (r3, 0x1d0)	// *((((0x120 * <arg0>) ) + 0x1d0)) = *((((0x120 * <arg0>) ) + 0x1d0))
 2a4:	dda310e3 	st.h	r13, (r3, 0x1c6)	// *((((0x120 * <arg0>) ) + 0x1c6)) = *((((0x120 * <arg0>) ) + 0x1c6))
 2a8:	d9a40026 	ld.b	r13, (r4, 0x26)	// regs: r13=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x26))
 2ac:	c4cd54cd 	zext	r13, r13, 6, 6	// regs: r13=zext(*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x26)))
 2b0:	d82301d0 	ld.b	r1, (r3, 0x1d0)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1d0))
 2b4:	c42d5c02 	ins	r1, r13, 2, 2
 2b8:	d9a301c8 	ld.b	r13, (r3, 0x1c8)	// regs: r13=*((((0x120 * <arg0>) ) + 0x1c8))
 2bc:	c4cd54ed 	zext	r13, r13, 7, 6	// regs: r13=zext(*((((0x120 * <arg0>) ) + 0x1c8)))
 2c0:	c42d5c23 	ins	r1, r13, 4, 3
 2c4:	dc2301d0 	st.b	r1, (r3, 0x1d0)	// *((((0x120 * <arg0>) ) + 0x1d0)) = *((((0x120 * <arg0>) ) + 0x1d0))
 2c8:	d9ac0008 	ld.b	r13, (r12, 0x8)	// regs: r13=*((((0x120 * <arg0>) ) + 0x1d0))
 2cc:	e5ad2004 	andi	r13, r13, 4	// regs: r13=(*((((0x120 * <arg0>) ) + 0x1d0)) & 0x4)
 2d0:	ea89004f 	lrw	r9, 0x0	// regs: r9=0x0
 2d4:	d98310e8 	ld.h	r12, (r3, 0x1d0)	// regs: r12=*((((0x120 * <arg0>) ) + 0x1d0))
 2d8:	8c38      	ld.h	r1, (r4, 0x30)	// regs: r1=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x30))
 2da:	e90d0039 	bez	r13, 0x34c	// if (r13 == 0x0) goto loc_34c;
loc_2de:
 2de:	3690      	movi	r6, 144	// regs: r6=0x90
 2e0:	46c1      	lsli	r6, r6, 1	// regs: r6=0x120
 2e2:	7da0      	mult	r6, r8	// regs: r6=(0x120 * <arg0>)
 2e4:	6194      	addu	r6, r5	// regs: r6=((0x120 * <arg0>) )
 2e6:	c5815d07 	ins	r12, r1, 15, 7
 2ea:	dd8310e8 	st.h	r12, (r3, 0x1d0)	// *((((0x120 * <arg0>) ) + 0x1d0)) = *((((0x120 * <arg0>) ) + 0x1d0))
 2ee:	d824002b 	ld.b	r1, (r4, 0x2b)	// regs: r1=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x2b))
 2f2:	d86601d2 	ld.b	r3, (r6, 0x1d2)	// regs: r3=*((((0x120 * <arg0>) ) + 0x1d2))
 2f6:	c4615c00 	ins	r3, r1, 0, 0
 2fa:	3101      	movi	r1, 1	// regs: r1=0x1
 2fc:	c4615c02 	ins	r3, r1, 2, 2
 300:	c4625c63 	ins	r3, r2, 6, 3
 304:	7401      	zexth	r0, r0	// regs: r0=zext16(*((((0x120 * <arg0>) ) + 0x1bc)))
 306:	dc6601d2 	st.b	r3, (r6, 0x1d2)	// *((((0x120 * <arg0>) ) + 0x1d2)) = *((((0x120 * <arg0>) ) + 0x1d2))
 30a:	e460207f 	andi	r3, r0, 127	// regs: r3=(zext16(*((((0x120 * <arg0>) ) + 0x1bc))) & 0x7f)
 30e:	60cc      	addu	r3, r3	// regs: r3=((zext16(*((((0x120 * <arg0>) ) + 0x1bc))) & 0x7f) + (zext16(*((((0x120 * <arg0>) ) + 0x1bc))) & 0x7f))
 310:	6c4c      	or	r1, r3	// regs: r1=(0x1 | ((zext16(*((((0x120 * <arg0>) ) + 0x1bc))) & 0x7f) + (zext16(*((((0x120 * <arg0>) ) + 0x1bc))) & 0x7f)))
 312:	c4e05503 	zext	r3, r0, 8, 7	// regs: r3=zext(zext16(*((((0x120 * <arg0>) ) + 0x1bc))))
 316:	d80601d4 	ld.b	r0, (r6, 0x1d4)	// regs: r0=*((((0x120 * <arg0>) ) + 0x1d4))
 31a:	3880      	bclri	r0, 0	// regs: r0=(*((((0x120 * <arg0>) ) + 0x1d4)) & ~(0x1 << 0x0))
 31c:	3881      	bclri	r0, 1	// regs: r0=((*((((0x120 * <arg0>) ) + 0x1d4)) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
 31e:	6c0c      	or	r0, r3	// regs: r0=(((*((((0x120 * <arg0>) ) + 0x1d4)) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)) | zext(zext16(*((((0x120 * <arg0>) ) + 0x1bc)))))
 320:	dc2601d3 	st.b	r1, (r6, 0x1d3)	// *((((0x120 * <arg0>) ) + 0x1d3)) = (0x1 | ((zext16(*((((0x120 * <arg0>) ) + 0x1bc))) & 0x7f) + (zext16(*((((0x120 * <arg0>) ) + 0x1bc))) & 0x7f)))
 324:	dc0601d4 	st.b	r0, (r6, 0x1d4)	// *((((0x120 * <arg0>) ) + 0x1d4)) = (((*((((0x120 * <arg0>) ) + 0x1d4)) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)) | zext(zext16(*((((0x120 * <arg0>) ) + 0x1bc)))))
 328:	e0000000 	bsr	0x0	// <lmac_select_resp_ind> // arg_bytes: 0; regs: r0=<ret lmac_select_resp_ind@0x328>, r1=<clobbered>
 32c:	d86601d4 	ld.b	r3, (r6, 0x1d4)	// regs: r3=*((((0x120 * <arg0>) ) + 0x1d4))
 330:	d84903e4 	ld.b	r2, (r9, 0x3e4)	// regs: r2=*(0x3e4)
 334:	c4605c22 	ins	r3, r0, 3, 2
 338:	c4625c04 	ins	r3, r2, 4, 4
 33c:	3200      	movi	r2, 0	// regs: r2=0x0
loc_33e:
 33e:	c4625c05 	ins	r3, r2, 5, 5
 342:	dc6601d4 	st.b	r3, (r6, 0x1d4)	// *(r6 + 0x1d4) = r3
 346:	e4c601cf 	addi	r6, r6, 464	// regs: r6=(r6 + 0x1d0)
 34a:	072f      	br	0x1a8	// goto loc_1a8;
loc_34c:
 34c:	4123      	lsli	r1, r1, 3	// regs: r1=(*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x30)) << 0x3)
 34e:	d9a90668 	ld.b	r13, (r9, 0x668)	// regs: r13=*(0x668)
 352:	e42121f8 	andi	r1, r1, 504	// regs: r1=((*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x30)) << 0x3) & 0x1f8)
 356:	e5ad2007 	andi	r13, r13, 7	// regs: r13=(*(0x668) & 0x7)
 35a:	6c74      	or	r1, r13	// regs: r1=(((*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x30)) << 0x3) & 0x1f8) | (*(0x668) & 0x7))
 35c:	07c1      	br	0x2de	// goto loc_2de;
loc_35e:
 35e:	d9a310e3 	ld.h	r13, (r3, 0x1c6)	// regs: r13=*((((0x120 * <arg0>) ) + 0x1c6))
 362:	3608      	movi	r6, 8	// regs: r6=0x8
 364:	c5a65c66 	ins	r13, r6, 9, 6
 368:	dda310e3 	st.h	r13, (r3, 0x1c6)	// *((((0x120 * <arg0>) ) + 0x1c6)) = *((((0x120 * <arg0>) ) + 0x1c6))
 36c:	d9a40026 	ld.b	r13, (r4, 0x26)	// regs: r13=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x26))
 370:	c4cd54cd 	zext	r13, r13, 6, 6	// regs: r13=zext(*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x26)))
 374:	d82301d0 	ld.b	r1, (r3, 0x1d0)	// regs: r1=*((((0x120 * <arg0>) ) + 0x1d0))
 378:	c42d5c02 	ins	r1, r13, 2, 2
 37c:	d9a301c8 	ld.b	r13, (r3, 0x1c8)	// regs: r13=*((((0x120 * <arg0>) ) + 0x1c8))
 380:	c4cd54ed 	zext	r13, r13, 7, 6	// regs: r13=zext(*((((0x120 * <arg0>) ) + 0x1c8)))
 384:	c42d5c23 	ins	r1, r13, 4, 3
 388:	dc2301d0 	st.b	r1, (r3, 0x1d0)	// *((((0x120 * <arg0>) ) + 0x1d0)) = *((((0x120 * <arg0>) ) + 0x1d0))
 38c:	d9ac0008 	ld.b	r13, (r12, 0x8)	// regs: r13=*((((0x120 * <arg0>) ) + 0x1d0))
 390:	e5ad2004 	andi	r13, r13, 4	// regs: r13=(*((((0x120 * <arg0>) ) + 0x1d0)) & 0x4)
 394:	ea89001e 	lrw	r9, 0x0	// regs: r9=0x0
 398:	8c38      	ld.h	r1, (r4, 0x30)	// regs: r1=*((*((*(((0x0 + (0x120 * <arg0>)) + 0xb8)) + 0x20)) + 0x30))
 39a:	d98310e8 	ld.h	r12, (r3, 0x1d0)	// regs: r12=*((((0x120 * <arg0>) ) + 0x1d0))
 39e:	e90d0039 	bez	r13, 0x410	// if (r13 == 0x0) goto loc_410;
loc_3a2:
 3a2:	3690      	movi	r6, 144	// regs: r6=0x90
 3a4:	46c1      	lsli	r6, r6, 1	// regs: r6=0x120
 3a6:	7da0      	mult	r6, r8	// regs: r6=(0x120 * r8)
 3a8:	6194      	addu	r6, r5	// regs: r6=((0x120 * r8) + r5)
 3aa:	c5815d07 	ins	r12, r1, 15, 7
 3ae:	dd8310e8 	st.h	r12, (r3, 0x1d0)	// *(r3 + 0x1d0) = r12
 3b2:	d824002b 	ld.b	r1, (r4, 0x2b)	// regs: r1=*(r4 + 0x2b)
 3b6:	d86601d2 	ld.b	r3, (r6, 0x1d2)	// regs: r3=*((((0x120 * r8) + r5) + 0x1d2))
 3ba:	ea0a0001 	movi	r10, 1	// regs: r10=0x1
 3be:	c4615c00 	ins	r3, r1, 0, 0
 3c2:	c46a5c02 	ins	r3, r10, 2, 2
 3c6:	c4625c63 	ins	r3, r2, 6, 3
 3ca:	7401      	zexth	r0, r0	// regs: r0=zext16(r0)
 3cc:	dc6601d2 	st.b	r3, (r6, 0x1d2)	// *((((0x120 * r8) + r5) + 0x1d2)) = *((((0x120 * r8) + r5) + 0x1d2))
 3d0:	e460207f 	andi	r3, r0, 127	// regs: r3=(zext16(r0) & 0x7f)
 3d4:	60cc      	addu	r3, r3	// regs: r3=((zext16(r0) & 0x7f) + (zext16(r0) & 0x7f))
 3d6:	6ce8      	or	r3, r10	// regs: r3=(((zext16(r0) & 0x7f) + (zext16(r0) & 0x7f)) | 0x1)
 3d8:	dc6601d3 	st.b	r3, (r6, 0x1d3)	// *((((0x120 * r8) + r5) + 0x1d3)) = (((zext16(r0) & 0x7f) + (zext16(r0) & 0x7f)) | 0x1)
 3dc:	d86601d4 	ld.b	r3, (r6, 0x1d4)	// regs: r3=*((((0x120 * r8) + r5) + 0x1d4))
 3e0:	3b80      	bclri	r3, 0	// regs: r3=(*((((0x120 * r8) + r5) + 0x1d4)) & ~(0x1 << 0x0))
 3e2:	3b81      	bclri	r3, 1	// regs: r3=((*((((0x120 * r8) + r5) + 0x1d4)) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
 3e4:	c4e05500 	zext	r0, r0, 8, 7	// regs: r0=zext(zext16(r0))
 3e8:	6c0c      	or	r0, r3	// regs: r0=(zext(zext16(r0)) | ((*((((0x120 * r8) + r5) + 0x1d4)) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)))
 3ea:	dc0601d4 	st.b	r0, (r6, 0x1d4)	// *((((0x120 * r8) + r5) + 0x1d4)) = (zext(zext16(r0)) | ((*((((0x120 * r8) + r5) + 0x1d4)) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)))
 3ee:	e0000000 	bsr	0x0	// <lmac_select_resp_ind> // arg_bytes: 0; regs: r0=<ret lmac_select_resp_ind@0x3ee>, r1=<clobbered>
 3f2:	d86601d4 	ld.b	r3, (r6, 0x1d4)	// regs: r3=*((((0x120 * r8) + r5) + 0x1d4))
 3f6:	c4605c22 	ins	r3, r0, 3, 2
 3fa:	c46a5c04 	ins	r3, r10, 4, 4
 3fe:	d84903e4 	ld.b	r2, (r9, 0x3e4)	// regs: r2=*(r9 + 0x3e4)
 402:	079e      	br	0x33e	// goto loc_33e;
 404:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
 408:	00000000 	.long	0x00000000	// <LMAC>
 40c:	00000000 	.long	0x00000000	// <ah_lmac>
loc_410:
 410:	4123      	lsli	r1, r1, 3	// regs: r1=(r1 << 0x3)
 412:	d9a90668 	ld.b	r13, (r9, 0x668)	// regs: r13=*(r9 + 0x668)
 416:	e42121f8 	andi	r1, r1, 504	// regs: r1=((r1 << 0x3) & 0x1f8)
 41a:	e5ad2007 	andi	r13, r13, 7	// regs: r13=(*(r9 + 0x668) & 0x7)
 41e:	6c74      	or	r1, r13	// regs: r1=(((r1 << 0x3) & 0x1f8) | (*(r9 + 0x668) & 0x7))
 420:	07c1      	br	0x3a2	// goto loc_3a2;

Disassembly of section .text.tx_skbs_cached:

00000000 <tx_skbs_cached>: // arg_bytes: 4
   0:	14d5      	push	r4-r8, r15
   2:	e0000000 	bsr	0x0	// <lmac_txsq_count> // arg_bytes: 0; regs: r0=<ret lmac_txsq_count@0x2>, r1=<clobbered>
   6:	1094      	lrw	r4, 0x0	// regs: r4=0x0
   8:	6e03      	mov	r8, r0	// regs: r8=<ret lmac_txsq_count@0x2>
   a:	e4040087 	addi	r0, r4, 136	// regs: r0=0x88
   e:	e0000000 	bsr	0x0	// <skb_list_count>; regs: r0=<ret skb_list_count@0xe>, r1=<clobbered>
  12:	6dc3      	mov	r7, r0	// regs: r7=<ret skb_list_count@0xe>
  14:	e4040093 	addi	r0, r4, 148	// regs: r0=0x94
  18:	e0000000 	bsr	0x0	// <skb_list_count>; regs: r0=<ret skb_list_count@0x18>, r1=<clobbered>
  1c:	6d83      	mov	r6, r0	// regs: r6=<ret skb_list_count@0x18>
  1e:	e404009f 	addi	r0, r4, 160	// regs: r0=0xa0
  22:	e0000000 	bsr	0x0	// <skb_list_count>; regs: r0=<ret skb_list_count@0x22>, r1=<clobbered>
  26:	6d43      	mov	r5, r0	// regs: r5=<ret skb_list_count@0x22>
  28:	e40400ab 	addi	r0, r4, 172	// regs: r0=0xac
  2c:	e0000000 	bsr	0x0	// <skb_list_count>; regs: r0=<ret skb_list_count@0x2c>, r1=<clobbered>
  30:	d84402e5 	ld.b	r2, (r4, 0x2e5)	// regs: r2=*(0x2e5)
  34:	d86401c5 	ld.b	r3, (r4, 0x1c5)	// regs: r3=*(0x1c5)
  38:	60c8      	addu	r3, r2	// regs: r3=(*(0x1c5) + *(0x2e5))
  3a:	d8440405 	ld.b	r2, (r4, 0x405)	// regs: r2=*(0x405)
  3e:	60c8      	addu	r3, r2	// regs: r3=((*(0x1c5) + *(0x2e5)) + *(0x405))
  40:	d8440525 	ld.b	r2, (r4, 0x525)	// regs: r2=*(0x525)
  44:	60c8      	addu	r3, r2	// regs: r3=(((*(0x1c5) + *(0x2e5)) + *(0x405)) + *(0x525))
  46:	60e0      	addu	r3, r8	// regs: r3=((((*(0x1c5) + *(0x2e5)) + *(0x405)) + *(0x525)) + <ret lmac_txsq_count@0x2>)
  48:	60dc      	addu	r3, r7	// regs: r3=(((((*(0x1c5) + *(0x2e5)) + *(0x405)) + *(0x525)) + <ret lmac_txsq_count@0x2>) + <ret skb_list_count@0xe>)
  4a:	60d8      	addu	r3, r6	// regs: r3=((((((*(0x1c5) + *(0x2e5)) + *(0x405)) + *(0x525)) + <ret lmac_txsq_count@0x2>) + <ret skb_list_count@0xe>) + <ret skb_list_count@0x18>)
  4c:	60d4      	addu	r3, r5	// regs: r3=(((((((*(0x1c5) + *(0x2e5)) + *(0x405)) + *(0x525)) + <ret lmac_txsq_count@0x2>) + <ret skb_list_count@0xe>) + <ret skb_list_count@0x18>) + <ret skb_list_count@0x22>)
  4e:	600c      	addu	r0, r3	// regs: r0=(<ret skb_list_count@0x2c> + (((((((*(0x1c5) + *(0x2e5)) + *(0x405)) + *(0x525)) + <ret lmac_txsq_count@0x2>) + <ret skb_list_count@0xe>) + <ret skb_list_count@0x18>) + <ret skb_list_count@0x22>))
  50:	1495      	pop	r4-r8, r15
  52:	0000      	.short	0x0000
  54:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>

Disassembly of section .text.get_worst_node:

00000000 <get_worst_node>: // arg_bytes: 0
   0:	1049      	lrw	r2, 0x0	// regs: r2=0x0
   2:	317f      	movi	r1, 127	// regs: r1=0x7f
   4:	d862227e 	ld.w	r3, (r2, 0x9f8)	// regs: r3=*(0x9f8)
   8:	3000      	movi	r0, 0	// regs: r0=0x0
   a:	e44209f7 	addi	r2, r2, 2552	// regs: r2=0x9f8
loc_e:
   e:	648e      	cmpne	r3, r2
  10:	0802      	bt	0x14	// if (T) goto loc_14;
  12:	783c      	jmp	r15	// return;
loc_14:
  14:	d98340b4 	ld.bs	r12, (r3, 0xb4)	// regs: r12=*(r3 + 0xb4)
  18:	6471      	cmplt	r12, r1
  1a:	0c03      	bf	0x20	// if (!T) goto loc_20;
  1c:	6c73      	mov	r1, r12	// regs: r1=*(r3 + 0xb4)
  1e:	6c0f      	mov	r0, r3	// regs: r0=r3
loc_20:
  20:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(r3)
  22:	07f6      	br	0xe	// goto loc_e;
  24:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_tx_to_pm_ap:

00000000 <lmac_tx_to_pm_ap>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	10d9      	lrw	r6, 0x0	// regs: r6=0x0
   4:	d8661504 	ld.h	r3, (r6, 0xa08)	// regs: r3=*(0xa08)
   8:	e9230004 	bnez	r3, 0x10	// if (r3 != 0x0) goto loc_10;
loc_c:
   c:	3000      	movi	r0, 0	// regs: r0=0x0
loc_e:
   e:	1493      	pop	r4-r6, r15
loc_10:
  10:	d866202f 	ld.w	r3, (r6, 0xbc)	// regs: r3=*(0xbc)
  14:	3b41      	cmpnei	r3, 1
  16:	0bfb      	bt	0xc	// if (r3 != 0x1) goto loc_c;
  18:	d8661505 	ld.h	r3, (r6, 0xa0a)	// regs: r3=*(0xa0a)
  1c:	e903fff8 	bez	r3, 0xc	// if (r3 == 0x0) goto loc_c;
  20:	d88620f3 	ld.w	r4, (r6, 0x3cc)	// regs: r4=*(0x3cc)
  24:	d8a620f4 	ld.w	r5, (r6, 0x3d0)	// regs: r5=*(0x3d0)
  28:	c4a42423 	or	r3, r4, r5	// regs: r3=(*(0x3cc) | *(0x3d0))
  2c:	e9030018 	bez	r3, 0x5c	// if (r3 == 0x0) goto loc_5c;
  30:	d86611e4 	ld.h	r3, (r6, 0x3c8)	// regs: r3=*(0x3c8)
  34:	5b07      	subi	r0, r3, 2	// regs: r0=(*(0x3c8) - 0x2)
  36:	503f      	asri	r1, r0, 31	// regs: r1=((*(0x3c8) - 0x2) >> 0x1f)
  38:	6511      	cmplt	r4, r4
  3a:	6101      	addc	r4, r0
  3c:	6145      	addc	r5, r1
  3e:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x3e>, r1=<clobbered>
  42:	6400      	cmphs	r0, r0
  44:	c4040100 	subc	r0, r4, r0
  48:	c4250101 	subc	r1, r5, r1
  4c:	e9a1ffe0 	bhsz	r1, 0xc	// if (r1 >= 0x0) goto loc_c;
  50:	3300      	movi	r3, 0	// regs: r3=0x0
  52:	3400      	movi	r4, 0	// regs: r4=0x0
  54:	dc6620f3 	st.w	r3, (r6, 0x3cc)	// *(0x3cc) = 0x0
  58:	dc8620f4 	st.w	r4, (r6, 0x3d0)	// *(0x3d0) = 0x0
loc_5c:
  5c:	3000      	movi	r0, 0	// regs: r0=0x0
  5e:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  60:	07d7      	br	0xe	// goto loc_e;
  62:	0000      	.short	0x0000
  64:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_attempt_tx_obss:

00000000 <lmac_attempt_tx_obss>: // arg_bytes: 4
   0:	14d3      	push	r4-r6, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e0000000 	bsr	0x0	// <lmac_tx_to_pm_ap> // arg_bytes: 0; regs: r0=<ret lmac_tx_to_pm_ap@0x4>, r1=<clobbered>
   8:	e920004c 	bnez	r0, 0xa0	// if (r0 != 0x0) goto loc_a0;
   c:	1167      	lrw	r3, 0x0	// regs: r3=0x0
   e:	6d0f      	mov	r4, r3	// regs: r4=0x0
  10:	d84309e0 	ld.b	r2, (r3, 0x9e0)	// regs: r2=*(0x9e0)
  14:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(0x9e0) & 0x1)
  18:	e9220044 	bnez	r2, 0xa0	// if (r2 != 0x0) goto loc_a0;
  1c:	d8430a4f 	ld.b	r2, (r3, 0xa4f)	// regs: r2=*(0xa4f)
  20:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0xa4f) & 0x8)
  24:	e922003e 	bnez	r2, 0xa0	// if (r2 != 0x0) goto loc_a0;
  28:	d86309e2 	ld.b	r3, (r3, 0x9e2)	// regs: r3=*(0x9e2)
  2c:	e4432002 	andi	r2, r3, 2	// regs: r2=(*(0x9e2) & 0x2)
  30:	e9020006 	bez	r2, 0x3c	// if (r2 == 0x0) goto loc_3c;
  34:	e4632028 	andi	r3, r3, 40	// regs: r3=(*(0x9e2) & 0x28)
  38:	e9030034 	bez	r3, 0xa0	// if (r3 == 0x0) goto loc_a0;
loc_3c:
  3c:	105c      	lrw	r2, 0x0	// regs: r2=0x0
  3e:	6d8b      	mov	r6, r2	// regs: r6=0x0
  40:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*(0x0)
  42:	d8232034 	ld.w	r1, (r3, 0xd0)	// regs: r1=*((*(0x0) + 0xd0))
  46:	e921002d 	bnez	r1, 0xa0	// if (r1 != 0x0) goto loc_a0;
  4a:	d8432035 	ld.w	r2, (r3, 0xd4)	// regs: r2=*((*(0x0) + 0xd4))
  4e:	e9220029 	bnez	r2, 0xa0	// if (r2 != 0x0) goto loc_a0;
  52:	934d      	ld.w	r2, (r3, 0x34)	// regs: r2=*((*(0x0) + 0x34))
  54:	c5025542 	zext	r2, r2, 10, 8	// regs: r2=zext(*((*(0x0) + 0x34)))
  58:	e9220024 	bnez	r2, 0xa0	// if (r2 != 0x0) goto loc_a0;
  5c:	936d      	ld.w	r3, (r3, 0x34)	// regs: r3=*((*(0x0) + 0x34))
  5e:	c7035743 	zext	r3, r3, 26, 24	// regs: r3=zext(*((*(0x0) + 0x34)))
  62:	3b41      	cmpnei	r3, 1
  64:	081e      	bt	0xa0	// if (r3 != 0x1) goto loc_a0;
  66:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0x66>, r1=<clobbered>
  6a:	e9850005 	blz	r5, 0x74	// if (r5 < 0x0) goto loc_74;
  6e:	7415      	zexth	r0, r5	// regs: r0=zext16(<arg0>)
  70:	e0000000 	bsr	0x0	// <lmac_lo_table_kick>; regs: r0=<ret lmac_lo_table_kick@0x70>, r1=<clobbered>
loc_74:
  74:	9660      	ld.w	r3, (r6, 0x0)	// regs: r3=*(0x0)
  76:	3100      	movi	r1, 0	// regs: r1=0x0
  78:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
  7a:	3a89      	bclri	r2, 9	// regs: r2=(*((*(0x0) + 0x30)) & ~(0x1 << 0x9))
  7c:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) & ~(0x1 << 0x9))
  7e:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
  80:	ec420400 	ori	r2, r2, 1024	// regs: r2=(*((*(0x0) + 0x30)) | 0x400)
  84:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) | 0x400)
  86:	3002      	movi	r0, 2	// regs: r0=0x2
  88:	e0000000 	bsr	0x0	// <lhw_start_cca>; regs: r0=<ret lhw_start_cca@0x88>, r1=<clobbered>
  8c:	d8040670 	ld.b	r0, (r4, 0x670)	// regs: r0=*(0x670)
  90:	285f      	subi	r0, 96	// regs: r0=(*(0x670) - 0x60)
  92:	7400      	zextb	r0, r0	// regs: r0=zext8((*(0x670) - 0x60))
  94:	e0000000 	bsr	0x0	// <lhw_start_tx>; regs: r0=<ret lhw_start_tx@0x94>, r1=<clobbered>
  98:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part1> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part1@0x98>, r1=<clobbered>
  9c:	3000      	movi	r0, 0	// regs: r0=0x0
loc_9e:
  9e:	1493      	pop	r4-r6, r15
loc_a0:
  a0:	3000      	movi	r0, 0	// regs: r0=0x0
  a2:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  a4:	07fd      	br	0x9e	// goto loc_9e;
  a6:	0000      	.short	0x0000
  a8:	00000000 	.long	0x00000000	// <ah_lmac>
  ac:	00000000 	.long	0x00000000	// <LMAC>

Disassembly of section .text.lmac_attempt_tx:

00000000 <lmac_attempt_tx>: // arg_bytes: 8
   0:	14d6      	push	r4-r9, r15
   2:	6e43      	mov	r9, r0	// regs: r9=<arg0>
   4:	e0000000 	bsr	0x0	// <lmac_tx_to_pm_ap> // arg_bytes: 0; regs: r0=<ret lmac_tx_to_pm_ap@0x4>, r1=<clobbered>
   8:	e92000ca 	bnez	r0, 0x19c	// if (r0 != 0x0) goto loc_19c;
   c:	1366      	lrw	r3, 0x0	// regs: r3=0x0
   e:	6d4f      	mov	r5, r3	// regs: r5=0x0
  10:	d84309e0 	ld.b	r2, (r3, 0x9e0)	// regs: r2=*(0x9e0)
  14:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(0x9e0) & 0x1)
  18:	e92200c2 	bnez	r2, 0x19c	// if (r2 != 0x0) goto loc_19c;
  1c:	d8430a4f 	ld.b	r2, (r3, 0xa4f)	// regs: r2=*(0xa4f)
  20:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0xa4f) & 0x8)
  24:	e92200bc 	bnez	r2, 0x19c	// if (r2 != 0x0) goto loc_19c;
  28:	d86309e2 	ld.b	r3, (r3, 0x9e2)	// regs: r3=*(0x9e2)
  2c:	e4432002 	andi	r2, r3, 2	// regs: r2=(*(0x9e2) & 0x2)
  30:	e9020006 	bez	r2, 0x3c	// if (r2 == 0x0) goto loc_3c;
  34:	e4632028 	andi	r3, r3, 40	// regs: r3=(*(0x9e2) & 0x28)
  38:	e90300b2 	bez	r3, 0x19c	// if (r3 == 0x0) goto loc_19c;
loc_3c:
  3c:	12fb      	lrw	r7, 0x0	// regs: r7=0x0
  3e:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(0x0)
  40:	d8432034 	ld.w	r2, (r3, 0xd0)	// regs: r2=*((*(0x0) + 0xd0))
  44:	e92200ac 	bnez	r2, 0x19c	// if (r2 != 0x0) goto loc_19c;
  48:	d8432035 	ld.w	r2, (r3, 0xd4)	// regs: r2=*((*(0x0) + 0xd4))
  4c:	e92200a8 	bnez	r2, 0x19c	// if (r2 != 0x0) goto loc_19c;
  50:	934d      	ld.w	r2, (r3, 0x34)	// regs: r2=*((*(0x0) + 0x34))
  52:	c5025542 	zext	r2, r2, 10, 8	// regs: r2=zext(*((*(0x0) + 0x34)))
  56:	e92200a0 	bnez	r2, 0x196	// if (r2 != 0x0) goto loc_196;
  5a:	936d      	ld.w	r3, (r3, 0x34)	// regs: r3=*((*(0x0) + 0x34))
  5c:	c7035743 	zext	r3, r3, 26, 24	// regs: r3=zext(*((*(0x0) + 0x34)))
  60:	3b41      	cmpnei	r3, 1
  62:	089a      	bt	0x196	// if (r3 != 0x1) goto loc_196;
  64:	d8650892 	ld.b	r3, (r5, 0x892)	// regs: r3=*(0x892)
  68:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x892) & 0x2)
  6c:	e9230006 	bnez	r3, 0x78	// if (r3 != 0x0) goto loc_78;
  70:	d805033c 	ld.b	r0, (r5, 0x33c)	// regs: r0=*(0x33c)
  74:	e0000000 	bsr	0x0	// <lmac_lo_table_kick>; regs: r0=<ret lmac_lo_table_kick@0x74>, r1=<clobbered>
loc_78:
  78:	eb090003 	cmphsi	r9, 4
  7c:	ea88004c 	lrw	r8, 0x0	// regs: r8=0x0
  80:	0877      	bt	0x16e	// if (r9 >= 0x4) goto loc_16e;
  82:	3390      	movi	r3, 144	// regs: r3=0x90
  84:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  86:	7ce4      	mult	r3, r9	// regs: r3=(0x120 * <arg0>)
  88:	60e0      	addu	r3, r8	// regs: r3=((0x120 * <arg0>) )
  8a:	d84301c5 	ld.b	r2, (r3, 0x1c5)	// regs: r2=*((((0x120 * <arg0>) ) + 0x1c5))
  8e:	e9020070 	bez	r2, 0x16e	// if (r2 == 0x0) goto loc_16e;
  92:	d863202e 	ld.w	r3, (r3, 0xb8)	// regs: r3=*((((0x120 * <arg0>) ) + 0xb8))
  96:	e429001b 	addi	r1, r9, 28	// regs: r1=(<arg0> + 0x1c)
  9a:	9368      	ld.w	r3, (r3, 0x20)	// regs: r3=*((*((((0x120 * <arg0>) ) + 0xb8)) + 0x20))
  9c:	d0250446 	ldr.h	r6, (r5, r1 << 1)	// regs: r6=*(0x0 + ((<arg0> + 0x1c) << 1))
  a0:	d8230029 	ld.b	r1, (r3, 0x29)	// regs: r1=*((*((*((((0x120 * <arg0>) ) + 0xb8)) + 0x20)) + 0x29))
  a4:	d8630028 	ld.b	r3, (r3, 0x28)	// regs: r3=*((*((*((((0x120 * <arg0>) ) + 0xb8)) + 0x20)) + 0x28))
  a8:	604c      	addu	r1, r3	// regs: r1=(*((*((*((((0x120 * <arg0>) ) + 0xb8)) + 0x20)) + 0x29)) + *((*((*((((0x120 * <arg0>) ) + 0xb8)) + 0x20)) + 0x28)))
  aa:	e4490013 	addi	r2, r9, 20	// regs: r2=(<arg0> + 0x14)
  ae:	392f      	cmplti	r1, 16
  b0:	74c5      	zexth	r3, r1	// regs: r3=zext16((*((*((*((((0x120 * <arg0>) ) + 0xb8)) + 0x20)) + 0x29)) + *((*((*((((0x120 * <arg0>) ) + 0xb8)) + 0x20)) + 0x28))))
  b2:	d0450442 	ldr.h	r2, (r5, r2 << 1)	// regs: r2=*(0x0 + ((<arg0> + 0x14) << 1))
  b6:	3110      	movi	r1, 16	// regs: r1=0x10
  b8:	7489      	zexth	r2, r2	// regs: r2=zext16(*(0x0 + ((<arg0> + 0x14) << 1)))
  ba:	c4610c20 	incf	r3, r1, 0
  be:	7599      	zexth	r6, r6	// regs: r6=zext16(*(0x0 + ((<arg0> + 0x1c) << 1)))
  c0:	c4624023 	lsl	r3, r2, r3
  c4:	658c      	cmphs	r3, r6
  c6:	c4c30c20 	incf	r6, r3, 0
  ca:	6498      	cmphs	r6, r2
  cc:	0c55      	bf	0x176	// if (r1 >= 0x10) goto loc_176;
loc_ce:
  ce:	e9260009 	bnez	r6, 0xe0	// if (r6 != 0x0) goto loc_e0;
  d2:	d865226d 	ld.w	r3, (r5, 0x9b4)	// regs: r3=*(0x9b4)
  d6:	ec630004 	ori	r3, r3, 4	// regs: r3=(*(0x9b4) | 0x4)
  da:	dc65226d 	st.w	r3, (r5, 0x9b4)	// *(0x9b4) = (*(0x9b4) | 0x4)
  de:	3607      	movi	r6, 7	// regs: r6=0x7
loc_e0:
  e0:	c5250020 	addu	r0, r5, r9	// regs: r0=(0x0 + r9)
  e4:	d920001c 	ld.b	r9, (r0, 0x1c)	// regs: r9=*(((0x0 + r9) + 0x1c))
  e8:	e0000000 	bsr	0x0	// <lhw_get_cca_remain>; regs: r0=<ret lhw_get_cca_remain@0xe8>, r1=<clobbered>
  ec:	e5290002 	addi	r9, r9, 3	// regs: r9=(*(((0x0 + r9) + 0x1c)) + 0x3)
  f0:	7664      	zextb	r9, r9	// regs: r9=zext8((*(((0x0 + r9) + 0x1c)) + 0x3))
  f2:	6d03      	mov	r4, r0	// regs: r4=<ret lhw_get_cca_remain@0xe8>
  f4:	e9200009 	bnez	r0, 0x106	// if (r0 != 0x0) goto loc_106;
  f8:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(0x0)
  fa:	938f      	ld.w	r4, (r3, 0x3c)	// regs: r4=*((*(0x0) + 0x3c))
  fc:	c4c48023 	divu	r3, r4, r6	// regs: r3=(*((*(0x0) + 0x3c)) / r6)
 100:	7d8c      	mult	r6, r3	// regs: r6=(r6 * (*((*(0x0) + 0x3c)) / r6))
 102:	611a      	subu	r4, r6	// regs: r4=(*((*(0x0) + 0x3c)) - (r6 * (*((*(0x0) + 0x3c)) / r6)))
 104:	7511      	zexth	r4, r4	// regs: r4=zext16((*((*(0x0) + 0x3c)) - (r6 * (*((*(0x0) + 0x3c)) / r6))))
loc_106:
 106:	d865202f 	ld.w	r3, (r5, 0xbc)	// regs: r3=*(0xbc)
 10a:	3b42      	cmpnei	r3, 2
 10c:	080c      	bt	0x124	// if (r3 != 0x2) goto loc_124;
 10e:	d8650360 	ld.b	r3, (r5, 0x360)	// regs: r3=*(0x360)
 112:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x360) & 0x1)
 116:	e9230007 	bnez	r3, 0x124	// if (r3 != 0x0) goto loc_124;
 11a:	d8454301 	ld.bs	r2, (r5, 0x301)	// regs: r2=*(0x301)
 11e:	3a40      	cmpnei	r2, 0
 120:	c4830c20 	incf	r4, r3, 0
loc_124:
 124:	d8652265 	ld.w	r3, (r5, 0x994)	// regs: r3=*(0x994)
 128:	3b47      	cmpnei	r3, 7
 12a:	d86509e2 	ld.b	r3, (r5, 0x9e2)	// regs: r3=*(0x9e2)
 12e:	e4632020 	andi	r3, r3, 32	// regs: r3=(*(0x9e2) & 0x20)
 132:	3100      	movi	r1, 0	// regs: r1=0x0
 134:	c4810c20 	incf	r4, r1, 0
 138:	e9030021 	bez	r3, 0x17a	// if (r3 == 0x0) goto loc_17a;
 13c:	3002      	movi	r0, 2	// regs: r0=0x2
 13e:	e0000000 	bsr	0x0	// <lhw_start_cca>; regs: r0=<ret lhw_start_cca@0x13e>, r1=<clobbered>
 142:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(0x0)
 144:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
 146:	3a89      	bclri	r2, 9	// regs: r2=(*((*(0x0) + 0x30)) & ~(0x1 << 0x9))
 148:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) & ~(0x1 << 0x9))
 14a:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
 14c:	ec420400 	ori	r2, r2, 1024	// regs: r2=(*((*(0x0) + 0x30)) | 0x400)
 150:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) | 0x400)
loc_152:
 152:	3000      	movi	r0, 0	// regs: r0=0x0
 154:	dc8812b1 	st.h	r4, (r8, 0x562)	// *(0x562) = r4
 158:	dd2812b0 	st.h	r9, (r8, 0x560)	// *(0x560) = zext8((*(((0x0 + r9) + 0x1c)) + 0x3))
 15c:	e0000000 	bsr	0x0	// <lhw_start_tx>; regs: r0=<ret lhw_start_tx@0x15c>, r1=<clobbered>
 160:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part1> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part1@0x160>, r1=<clobbered>
 164:	3400      	movi	r4, 0	// regs: r4=0x0
loc_166:
 166:	e0000000 	bsr	0x0	// <lmac_tdma_start>; regs: r0=<ret lmac_tdma_start@0x166>, r1=<clobbered>
loc_16a:
 16a:	6c13      	mov	r0, r4	// regs: r0=r4
 16c:	1496      	pop	r4-r9, r15
loc_16e:
 16e:	8dd7      	ld.h	r6, (r5, 0x2e)	// regs: r6=*(0x2e)
 170:	ea090003 	movi	r9, 3	// regs: r9=0x3
 174:	07ad      	br	0xce	// goto loc_ce;
loc_176:
 176:	6d8b      	mov	r6, r2	// regs: r6=zext16(*(0x0 + ((<arg0> + 0x14) << 1)))
 178:	07b4      	br	0xe0	// goto loc_e0;
loc_17a:
 17a:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(0x0)
 17c:	6c53      	mov	r1, r4	// regs: r1=r4
 17e:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
 180:	ec420200 	ori	r2, r2, 512	// regs: r2=(*((*(0x0) + 0x30)) | 0x200)
 184:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) | 0x200)
 186:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
 188:	ec420400 	ori	r2, r2, 1024	// regs: r2=(*((*(0x0) + 0x30)) | 0x400)
 18c:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) | 0x400)
 18e:	6c27      	mov	r0, r9	// regs: r0=zext8((*(((0x0 + r9) + 0x1c)) + 0x3))
 190:	e0000000 	bsr	0x0	// <lhw_start_cca>; regs: r0=<ret lhw_start_cca@0x190>, r1=<clobbered>
 194:	07df      	br	0x152	// goto loc_152;
loc_196:
 196:	3400      	movi	r4, 0	// regs: r4=0x0
 198:	2c00      	subi	r4, 1	// regs: r4=0xffffffff
 19a:	07e6      	br	0x166	// goto loc_166;
loc_19c:
 19c:	3400      	movi	r4, 0	// regs: r4=0x0
 19e:	2c00      	subi	r4, 1	// regs: r4=0xffffffff
 1a0:	07e5      	br	0x16a	// goto loc_16a;
 1a2:	0000      	.short	0x0000
 1a4:	00000000 	.long	0x00000000	// <ah_lmac>
 1a8:	00000000 	.long	0x00000000	// <LMAC>
 1ac:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
 1ae:	0000      	.short	0x0000

Disassembly of section .text.lmac_tx_frame_regen:

00000000 <lmac_tx_frame_regen>: // arg_bytes: 16
   0:	14d5      	push	r4-r8, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	e50e0003 	addi	r8, r14, 4	// regs: r8=((sp - 0x8) + 0x4)
   8:	6d0f      	mov	r4, r3	// regs: r4=<arg3>
   a:	3301      	movi	r3, 1	// regs: r3=0x1
   c:	dc680000 	st.b	r3, (r8, 0x0)	// local_4 = 0x1
  10:	3300      	movi	r3, 0	// regs: r3=0x0
  12:	dc680001 	st.b	r3, (r8, 0x1)	// local_3 = 0x0
  16:	3903      	cmphsi	r1, 4
  18:	3302      	movi	r3, 2	// regs: r3=0x2
  1a:	dc680002 	st.b	r3, (r8, 0x2)	// local_2 = 0x2
  1e:	3303      	movi	r3, 3	// regs: r3=0x3
  20:	6d43      	mov	r5, r0	// regs: r5=<arg0>
  22:	6dc7      	mov	r7, r1	// regs: r7=<arg1>
  24:	6d8b      	mov	r6, r2	// regs: r6=<arg2>
  26:	dc680003 	st.b	r3, (r8, 0x3)	// local_1 = 0x3
  2a:	0c09      	bf	0x3c	// if (r1 < 0x4) goto loc_3c;
  2c:	3390      	movi	r3, 144	// regs: r3=0x90
  2e:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  30:	7cc0      	mult	r3, r0	// regs: r3=(0x120 * <arg0>)
  32:	1144      	lrw	r2, 0x0	// regs: r2=0x0
  34:	60c8      	addu	r3, r2	// regs: r3=((0x120 * <arg0>) )
  36:	83e2      	ld.b	r7, (r3, 0x2)	// regs: r7=*((((0x120 * <arg0>) ) + 0x2))
  38:	e4e72003 	andi	r7, r7, 3	// regs: r7=(*((((0x120 * <arg0>) ) + 0x2)) & 0x3)
loc_3c:
  3c:	3e07      	cmphsi	r6, 8
  3e:	0c0b      	bf	0x54	// if (r6 < 0x8) goto loc_54;
  40:	3e4a      	cmpnei	r6, 10
  42:	0c09      	bf	0x54	// if (r6 == 0xa) goto loc_54;
  44:	3390      	movi	r3, 144	// regs: r3=0x90
  46:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  48:	7cd4      	mult	r3, r5	// regs: r3=(0x120 * <arg0>)
  4a:	105e      	lrw	r2, 0x0	// regs: r2=0x0
  4c:	60c8      	addu	r3, r2	// regs: r3=((0x120 * <arg0>) )
  4e:	83c2      	ld.b	r6, (r3, 0x2)	// regs: r6=*((((0x120 * <arg0>) ) + 0x2))
  50:	c44654a6 	zext	r6, r6, 5, 2	// regs: r6=zext(*((((0x120 * <arg0>) ) + 0x2)))
loc_54:
  54:	e0000000 	bsr	0x0	// <lmac_reorder_tx_agglist> // arg_bytes: 0; regs: r0=<ret lmac_reorder_tx_agglist@0x54>, r1=<clobbered>
  58:	e0000000 	bsr	0x0	// <lmac_check_tx_queue_empty> // arg_bytes: 4; regs: r0=<ret lmac_check_tx_queue_empty@0x58>, r1=<clobbered>
  5c:	107a      	lrw	r3, 0x0	// regs: r3=0x0
  5e:	d0a80021 	ldr.b	r1, (r8, r5 << 0)	// regs: r1=*(((sp - 0x8) + 0x4) + (<arg0> << 0))
  62:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  64:	9353      	ld.w	r2, (r3, 0x4c)	// regs: r2=*((*(0x0) + 0x4c))
  66:	3301      	movi	r3, 1	// regs: r3=0x1
  68:	70c4      	lsl	r3, r1
  6a:	68c8      	and	r3, r2	// regs: r3=(0x1 & *((*(0x0) + 0x4c)))
  6c:	e9230005 	bnez	r3, 0x76	// if (r3 != 0x0) goto loc_76;
  70:	e0000000 	bsr	0x0	// <lmac_select_tx_acq> // arg_bytes: 0; regs: r0=<ret lmac_select_tx_acq@0x70>, r1=<clobbered>
  74:	6d43      	mov	r5, r0	// regs: r5=<ret lmac_select_tx_acq@0x70>
loc_76:
  76:	3d03      	cmphsi	r5, 4
  78:	0821      	bt	0xba	// if (r5 >= 0x4) goto loc_ba;
  7a:	6cd3      	mov	r3, r4	// regs: r3=<arg3>
  7c:	6c9b      	mov	r2, r6	// regs: r2=r6
  7e:	6c5f      	mov	r1, r7	// regs: r1=r7
  80:	6c17      	mov	r0, r5	// regs: r0=r5
  82:	e0000000 	bsr	0x0	// <lmac_gen_tx_agglist> // arg_bytes: 16; regs: r0=<ret lmac_gen_tx_agglist@0x82>, r1=<clobbered>
  86:	e9000013 	bez	r0, 0xac	// if (r0 == 0x0) goto loc_ac;
  8a:	d8600025 	ld.b	r3, (r0, 0x25)	// regs: r3=*(<ret lmac_gen_tx_agglist@0x82> + 0x25)
  8e:	3400      	movi	r4, 0	// regs: r4=0x0
  90:	c4645c05 	ins	r3, r4, 5, 5
  94:	dc600025 	st.b	r3, (r0, 0x25)	// *(<ret lmac_gen_tx_agglist@0x82> + 0x25) = *(<ret lmac_gen_tx_agglist@0x82> + 0x25)
  98:	6c9b      	mov	r2, r6	// regs: r2=r6
  9a:	6c5f      	mov	r1, r7	// regs: r1=r7
  9c:	6c17      	mov	r0, r5	// regs: r0=r5
  9e:	e0000000 	bsr	0x0	// <lmac_gen_txvec> // arg_bytes: 12; regs: r0=<ret lmac_gen_txvec@0x9e>, r1=<clobbered>
  a2:	106a      	lrw	r3, 0x0	// regs: r3=0x0
  a4:	b301      	st.w	r0, (r3, 0x4)	// *(0x4) = <ret lmac_gen_txvec@0x9e>
  a6:	6c13      	mov	r0, r4	// regs: r0=0x0
loc_a8:
  a8:	1402      	addi	r14, r14, 8	// regs: r14=((sp - 0x8) + 0x8)
  aa:	1495      	pop	r4-r8, r15
loc_ac:
  ac:	b880      	st.w	r4, (r14, 0x0)	// local_8 = <arg3>
  ae:	6cdb      	mov	r3, r6	// regs: r3=r6
  b0:	6c9f      	mov	r2, r7	// regs: r2=r7
  b2:	6c57      	mov	r1, r5	// regs: r1=r5
  b4:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  b6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xb6>, r1=<clobbered>
loc_ba:
  ba:	3000      	movi	r0, 0	// regs: r0=0x0
  bc:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  be:	07f5      	br	0xa8	// goto loc_a8;
  c0:	0000      	.short	0x0000	// <.bss.ah_lmac_tx+0x1c4>
  c2:	0000      	.short	0x0000
  c4:	0000      	.short	0x0000	// <LMAC>
  c6:	0000      	.short	0x0000
  c8:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  cc:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_frame_regen.str1.1>

Disassembly of section .text.lmac_beacon_add_s1g_beacon_compatibility:

00000000 <lmac_beacon_add_s1g_beacon_compatibility>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	310a      	movi	r1, 10	// regs: r1=0xa
   4:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x4>, r1=<clobbered>
   8:	3300      	movi	r3, 0	// regs: r3=0x0
   a:	2b2a      	subi	r3, 43	// regs: r3=0xffffffd5
   c:	a060      	st.b	r3, (r0, 0x0)	// *(<ret skb_put@0x4>) = 0xffffffd5
   e:	3308      	movi	r3, 8	// regs: r3=0x8
  10:	104a      	lrw	r2, 0x0	// regs: r2=0x0
  12:	a061      	st.b	r3, (r0, 0x1)	// *(<ret skb_put@0x4> + 0x1) = 0x8
  14:	d862132a 	ld.h	r3, (r2, 0x654)	// regs: r3=*(0x654)
  18:	a062      	st.b	r3, (r0, 0x2)	// *(<ret skb_put@0x4> + 0x2) = *(0x654)
  1a:	4b68      	lsri	r3, r3, 8	// regs: r3=(*(0x654) >> 0x8)
  1c:	a063      	st.b	r3, (r0, 0x3)	// *(<ret skb_put@0x4> + 0x3) = (*(0x654) >> 0x8)
  1e:	d862132b 	ld.h	r3, (r2, 0x656)	// regs: r3=*(0x656)
  22:	a064      	st.b	r3, (r0, 0x4)	// *(<ret skb_put@0x4> + 0x4) = *(0x656)
  24:	4b68      	lsri	r3, r3, 8	// regs: r3=(*(0x656) >> 0x8)
  26:	a065      	st.b	r3, (r0, 0x5)	// *(<ret skb_put@0x4> + 0x5) = (*(0x656) >> 0x8)
  28:	3300      	movi	r3, 0	// regs: r3=0x0
  2a:	a068      	st.b	r3, (r0, 0x8)	// *(<ret skb_put@0x4> + 0x8) = 0x0
  2c:	a069      	st.b	r3, (r0, 0x9)	// *(<ret skb_put@0x4> + 0x9) = 0x0
  2e:	a066      	st.b	r3, (r0, 0x6)	// *(<ret skb_put@0x4> + 0x6) = 0x0
  30:	a067      	st.b	r3, (r0, 0x7)	// *(<ret skb_put@0x4> + 0x7) = 0x0
  32:	2001      	addi	r0, 2	// regs: r0=(<ret skb_put@0x4> + 0x2)
  34:	1490      	pop	r15
  36:	0000      	.short	0x0000
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000

Disassembly of section .text.lmac_beacon_build_s1gbeacon:

00000000 <lmac_beacon_build_s1gbeacon>: // arg_bytes: 4
   0:	14d6      	push	r4-r9, r15
   2:	01f2      	lrw	r7, 0x0	// regs: r7=0x0
   4:	3400      	movi	r4, 0	// regs: r4=0x0
   6:	9762      	ld.w	r3, (r7, 0x8)	// regs: r3=*(0x8)
   8:	d9002008 	ld.w	r8, (r0, 0x20)	// regs: r8=*(<arg0> + 0x20)
   c:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*((*(0x8) + 0x1c))
   e:	90c7      	ld.w	r6, (r0, 0x1c)	// regs: r6=*(<arg0> + 0x1c)
  10:	6d43      	mov	r5, r0	// regs: r5=<arg0>
  12:	b346      	st.w	r2, (r3, 0x18)	// *((*(0x8) + 0x18)) = *((*(0x8) + 0x1c))
  14:	ab94      	st.h	r4, (r3, 0x28)	// *((*(0x8) + 0x28)) = 0x0
  16:	3244      	movi	r2, 68	// regs: r2=0x44
  18:	3100      	movi	r1, 0	// regs: r1=0x0
  1a:	6c23      	mov	r0, r8	// regs: r0=*(<arg0> + 0x20)
  1c:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x1c>, r1=<clobbered>
  20:	3220      	movi	r2, 32	// regs: r2=0x20
  22:	3100      	movi	r1, 0	// regs: r1=0x0
  24:	e407000b 	addi	r0, r7, 12	// regs: r0=0xc
  28:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x28>, r1=<clobbered>
  2c:	310f      	movi	r1, 15	// regs: r1=0xf
  2e:	6c17      	mov	r0, r5	// regs: r0=<arg0>
  30:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x30>, r1=<clobbered>
  34:	8660      	ld.b	r3, (r6, 0x0)	// regs: r3=*(*(<arg0> + 0x1c))
  36:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(*(<arg0> + 0x1c)) & 0xfc)
  3a:	ea090003 	movi	r9, 3	// regs: r9=0x3
  3e:	3101      	movi	r1, 1	// regs: r1=0x1
  40:	c4695c22 	ins	r3, r9, 3, 2
  44:	c4615c64 	ins	r3, r1, 7, 4
  48:	a660      	st.b	r3, (r6, 0x0)	// *(*(<arg0> + 0x1c)) = (*(*(<arg0> + 0x1c)) & 0xfc)
  4a:	8661      	ld.b	r3, (r6, 0x1)	// regs: r3=*((*(<arg0> + 0x1c) + 0x1))
  4c:	c4615c00 	ins	r3, r1, 0, 0
  50:	3004      	movi	r0, 4	// regs: r0=0x4
  52:	e46320f9 	andi	r3, r3, 249	// regs: r3=(*((*(<arg0> + 0x1c) + 0x1)) & 0xf9)
  56:	c4605c43 	ins	r3, r0, 5, 3
  5a:	3200      	movi	r2, 0	// regs: r2=0x0
  5c:	c4615c06 	ins	r3, r1, 6, 6
  60:	c4625c07 	ins	r3, r2, 7, 7
  64:	a682      	st.b	r4, (r6, 0x2)	// *((*(<arg0> + 0x1c) + 0x2)) = 0x0
  66:	a661      	st.b	r3, (r6, 0x1)	// *((*(<arg0> + 0x1c) + 0x1)) = (*((*(<arg0> + 0x1c) + 0x1)) & 0xf9)
  68:	a643      	st.b	r2, (r6, 0x3)	// *((*(<arg0> + 0x1c) + 0x3)) = 0x0
  6a:	6018      	addu	r0, r6	// regs: r0=(0x4 + *(<arg0> + 0x1c))
  6c:	028c      	lrw	r4, 0x0	// regs: r4=0x0
  6e:	3206      	movi	r2, 6	// regs: r2=0x6
  70:	e4240301 	addi	r1, r4, 770	// regs: r1=0x302
  74:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x74>, r1=<clobbered>
  78:	d86403f0 	ld.b	r3, (r4, 0x3f0)	// regs: r3=*(0x3f0)
  7c:	a66e      	st.b	r3, (r6, 0xe)	// *((*(<arg0> + 0x1c) + 0xe)) = *(0x3f0)
  7e:	8661      	ld.b	r3, (r6, 0x1)	// regs: r3=*((*(<arg0> + 0x1c) + 0x1))
  80:	e4632001 	andi	r3, r3, 1	// regs: r3=(*((*(<arg0> + 0x1c) + 0x1)) & 0x1)
  84:	e9030006 	bez	r3, 0x90	// if (r3 == 0x0) goto loc_90;
  88:	6c67      	mov	r1, r9	// regs: r1=0x3
  8a:	6c17      	mov	r0, r5	// regs: r0=<arg0>
  8c:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x8c>, r1=<clobbered>
loc_90:
  90:	8661      	ld.b	r3, (r6, 0x1)	// regs: r3=*((*(<arg0> + 0x1c) + 0x1))
  92:	e4632002 	andi	r3, r3, 2	// regs: r3=(*((*(<arg0> + 0x1c) + 0x1)) & 0x2)
  96:	e903000c 	bez	r3, 0xae	// if (r3 == 0x0) goto loc_ae;
  9a:	3104      	movi	r1, 4	// regs: r1=0x4
  9c:	6c17      	mov	r0, r5	// regs: r0=<arg0>
  9e:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x9e>, r1=<clobbered>
  a2:	e4260011 	addi	r1, r6, 18	// regs: r1=(*(<arg0> + 0x1c) + 0x12)
  a6:	d8042154 	ld.w	r0, (r4, 0x550)	// regs: r0=*(0x550)
  aa:	e0000000 	bsr	0x0	// <__put_unaligned_le32> // arg_bytes: 8; regs: r0=<ret __put_unaligned_le32@0xaa>, r1=<clobbered>
loc_ae:
  ae:	8661      	ld.b	r3, (r6, 0x1)	// regs: r3=*((*(<arg0> + 0x1c) + 0x1))
  b0:	e4632002 	andi	r3, r3, 2	// regs: r3=(*((*(<arg0> + 0x1c) + 0x1)) & 0x2)
  b4:	e9030008 	bez	r3, 0xc4	// if (r3 == 0x0) goto loc_c4;
  b8:	3101      	movi	r1, 1	// regs: r1=0x1
  ba:	6c17      	mov	r0, r5	// regs: r0=<arg0>
  bc:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0xbc>, r1=<clobbered>
  c0:	3300      	movi	r3, 0	// regs: r3=0x0
  c2:	a676      	st.b	r3, (r6, 0x16)	// *((*(<arg0> + 0x1c) + 0x16)) = 0x0
loc_c4:
  c4:	6c17      	mov	r0, r5	// regs: r0=<arg0>
  c6:	e0000000 	bsr	0x0	// <lmac_beacon_add_s1g_beacon_compatibility> // arg_bytes: 4; regs: r0=<ret lmac_beacon_add_s1g_beacon_compatibility@0xc6>, r1=<clobbered>
  ca:	d9240554 	ld.b	r9, (r4, 0x554)	// regs: r9=*(0x554)
  ce:	b704      	st.w	r0, (r7, 0x10)	// *(0x10) = <ret lmac_beacon_add_s1g_beacon_compatibility@0xc6>
  d0:	e909001a 	bez	r9, 0x104	// if (r9 == 0x0) goto loc_104;
  d4:	e4290001 	addi	r1, r9, 2	// regs: r1=(*(0x554) + 0x2)
  d8:	6c17      	mov	r0, r5	// regs: r0=<arg0>
  da:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0xda>, r1=<clobbered>
  de:	3305      	movi	r3, 5	// regs: r3=0x5
  e0:	a060      	st.b	r3, (r0, 0x0)	// *(<ret skb_put@0xda>) = 0x5
  e2:	d8640554 	ld.b	r3, (r4, 0x554)	// regs: r3=*(0x554)
  e6:	a061      	st.b	r3, (r0, 0x1)	// *(<ret skb_put@0xda> + 0x1) = *(0x554)
  e8:	3300      	movi	r3, 0	// regs: r3=0x0
  ea:	a062      	st.b	r3, (r0, 0x2)	// *(<ret skb_put@0xda> + 0x2) = 0x0
  ec:	d8640556 	ld.b	r3, (r4, 0x556)	// regs: r3=*(0x556)
  f0:	a063      	st.b	r3, (r0, 0x3)	// *(<ret skb_put@0xda> + 0x3) = *(0x556)
  f2:	d8440554 	ld.b	r2, (r4, 0x554)	// regs: r2=*(0x554)
  f6:	e5200001 	addi	r9, r0, 2	// regs: r9=(<ret skb_put@0xda> + 0x2)
  fa:	2a01      	subi	r2, 2	// regs: r2=(*(0x554) - 0x2)
  fc:	032f      	lrw	r1, 0x0	// regs: r1=0x0
  fe:	2003      	addi	r0, 4	// regs: r0=(<ret skb_put@0xda> + 0x4)
 100:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x100>, r1=<clobbered>
loc_104:
 104:	dd272005 	st.w	r9, (r7, 0x14)	// *(0x14) = r9
 108:	e9290005 	bnez	r9, 0x112	// if (r9 != 0x0) goto loc_112;
 10c:	0312      	lrw	r0, 0x0	// regs: r0=0x0
 10e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x10e>, r1=<clobbered>
loc_112:
 112:	3104      	movi	r1, 4	// regs: r1=0x4
 114:	6c17      	mov	r0, r5	// regs: r0=<arg0>
 116:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x116>, r1=<clobbered>
 11a:	3300      	movi	r3, 0	// regs: r3=0x0
 11c:	2b29      	subi	r3, 42	// regs: r3=0xffffffd6
 11e:	a060      	st.b	r3, (r0, 0x0)	// *(<ret skb_put@0x116>) = 0xffffffd6
 120:	3302      	movi	r3, 2	// regs: r3=0x2
 122:	a061      	st.b	r3, (r0, 0x1)	// *(<ret skb_put@0x116> + 0x1) = 0x2
 124:	d864132b 	ld.h	r3, (r4, 0x656)	// regs: r3=*(0x656)
 128:	a062      	st.b	r3, (r0, 0x2)	// *(<ret skb_put@0x116> + 0x2) = *(0x656)
 12a:	4b68      	lsri	r3, r3, 8	// regs: r3=(*(0x656) >> 0x8)
 12c:	a063      	st.b	r3, (r0, 0x3)	// *(<ret skb_put@0x116> + 0x3) = (*(0x656) >> 0x8)
 12e:	d8641505 	ld.h	r3, (r4, 0xa0a)	// regs: r3=*(0xa0a)
 132:	e9030025 	bez	r3, 0x17c	// if (r3 == 0x0) goto loc_17c;
 136:	9566      	ld.w	r3, (r5, 0x18)	// regs: r3=*(<arg0> + 0x18)
 138:	9549      	ld.w	r2, (r5, 0x24)	// regs: r2=*(<arg0> + 0x24)
 13a:	608e      	subu	r2, r3	// regs: r2=(*(<arg0> + 0x24) - *(<arg0> + 0x18))
 13c:	3a31      	cmplti	r2, 18
 13e:	090f      	bt	0x35c	// if (r2 < 0x12) goto loc_35c;
 140:	3200      	movi	r2, 0	// regs: r2=0x0
 142:	2a22      	subi	r2, 35	// regs: r2=0xffffffdd
 144:	a340      	st.b	r2, (r3, 0x0)	// *(*(<arg0> + 0x18)) = 0xffffffdd
 146:	320f      	movi	r2, 15	// regs: r2=0xf
 148:	a341      	st.b	r2, (r3, 0x1)	// *((*(<arg0> + 0x18) + 0x1)) = 0xf
 14a:	3200      	movi	r2, 0	// regs: r2=0x0
 14c:	a342      	st.b	r2, (r3, 0x2)	// *((*(<arg0> + 0x18) + 0x2)) = 0x0
 14e:	3240      	movi	r2, 64	// regs: r2=0x40
 150:	a343      	st.b	r2, (r3, 0x3)	// *((*(<arg0> + 0x18) + 0x3)) = 0x40
 152:	3201      	movi	r2, 1	// regs: r2=0x1
 154:	a344      	st.b	r2, (r3, 0x4)	// *((*(<arg0> + 0x18) + 0x4)) = 0x1
 156:	d8441198 	ld.h	r2, (r4, 0x330)	// regs: r2=*(0x330)
 15a:	a345      	st.b	r2, (r3, 0x5)	// *((*(<arg0> + 0x18) + 0x5)) = *(0x330)
 15c:	4a48      	lsri	r2, r2, 8	// regs: r2=(*(0x330) >> 0x8)
 15e:	a346      	st.b	r2, (r3, 0x6)	// *((*(<arg0> + 0x18) + 0x6)) = (*(0x330) >> 0x8)
 160:	3204      	movi	r2, 4	// regs: r2=0x4
 162:	3108      	movi	r1, 8	// regs: r1=0x8
 164:	a347      	st.b	r2, (r3, 0x7)	// *((*(<arg0> + 0x18) + 0x7)) = 0x4
 166:	6c17      	mov	r0, r5	// regs: r0=<arg0>
 168:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x168>, r1=<clobbered>
 16c:	3109      	movi	r1, 9	// regs: r1=0x9
 16e:	6c17      	mov	r0, r5	// regs: r0=<arg0>
 170:	d9252006 	ld.w	r9, (r5, 0x18)	// regs: r9=*(<arg0> + 0x18)
 174:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x174>, r1=<clobbered>
loc_178:
 178:	dd272009 	st.w	r9, (r7, 0x24)	// *(r7 + 0x24) = r9
loc_17c:
 17c:	3111      	movi	r1, 17	// regs: r1=0x11
 17e:	6c17      	mov	r0, r5	// regs: r0=r5
 180:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x180>, r1=<clobbered>
 184:	3300      	movi	r3, 0	// regs: r3=0x0
 186:	2b26      	subi	r3, 39	// regs: r3=0xffffffd9
 188:	a060      	st.b	r3, (r0, 0x0)	// *(<ret skb_put@0x180>) = 0xffffffd9
 18a:	330f      	movi	r3, 15	// regs: r3=0xf
 18c:	a061      	st.b	r3, (r0, 0x1)	// *(<ret skb_put@0x180> + 0x1) = 0xf
 18e:	5866      	addi	r3, r0, 2	// regs: r3=(<ret skb_put@0x180> + 0x2)
 190:	320f      	movi	r2, 15	// regs: r2=0xf
 192:	6c0f      	mov	r0, r3	// regs: r0=(<ret skb_put@0x180> + 0x2)
 194:	132c      	lrw	r1, 0x0	// regs: r1=0x0
 196:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x196>, r1=<clobbered>
 19a:	b706      	st.w	r0, (r7, 0x18)	// *(r7 + 0x18) = <ret memcpy@0x196>
 19c:	3114      	movi	r1, 20	// regs: r1=0x14
 19e:	6c17      	mov	r0, r5	// regs: r0=r5
 1a0:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x1a0>, r1=<clobbered>
 1a4:	330c      	movi	r3, 12	// regs: r3=0xc
 1a6:	a060      	st.b	r3, (r0, 0x0)	// *(<ret skb_put@0x1a0>) = 0xc
 1a8:	3312      	movi	r3, 18	// regs: r3=0x12
 1aa:	a061      	st.b	r3, (r0, 0x1)	// *(<ret skb_put@0x1a0> + 0x1) = 0x12
 1ac:	d8444301 	ld.bs	r2, (r4, 0x301)	// regs: r2=*(r4 + 0x301)
 1b0:	6e43      	mov	r9, r0	// regs: r9=<ret skb_put@0x1a0>
 1b2:	1366      	lrw	r3, 0x0	// regs: r3=0x0
 1b4:	2001      	addi	r0, 2	// regs: r0=(<ret skb_put@0x1a0> + 0x2)
 1b6:	e90200da 	bez	r2, 0x36a	// if (r2 == 0x0) goto loc_36a;
 1ba:	d8440310 	ld.b	r2, (r4, 0x310)	// regs: r2=*(r4 + 0x310)
 1be:	e4422004 	andi	r2, r2, 4	// regs: r2=(*(r4 + 0x310) & 0x4)
 1c2:	e90200d4 	bez	r2, 0x36a	// if (r2 == 0x0) goto loc_36a;
 1c6:	8340      	ld.b	r2, (r3, 0x0)	// regs: r2=*(0x0)
 1c8:	e9220008 	bnez	r2, 0x1d8	// if (r2 != 0x0) goto loc_1d8;
 1cc:	3201      	movi	r2, 1	// regs: r2=0x1
 1ce:	a340      	st.b	r2, (r3, 0x0)	// *(0x0) = 0x1
 1d0:	125f      	lrw	r2, 0x0	// regs: r2=0x0
 1d2:	8260      	ld.b	r3, (r2, 0x0)	// regs: r3=*(0x0)
 1d4:	2300      	addi	r3, 1	// regs: r3=(*(0x0) + 0x1)
 1d6:	a260      	st.b	r3, (r2, 0x0)	// *(0x0) = (*(0x0) + 0x1)
loc_1d8:
 1d8:	3212      	movi	r2, 18	// regs: r2=0x12
 1da:	123e      	lrw	r1, 0x0	// regs: r1=0x0
loc_1dc:
 1dc:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x1dc>, r1=<clobbered>
 1e0:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(r4 + 0x310)
 1e4:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(r4 + 0x310) & 0x4)
 1e8:	e903000a 	bez	r3, 0x1fc	// if (r3 == 0x0) goto loc_1fc;
 1ec:	1258      	lrw	r2, 0x0	// regs: r2=0x0
 1ee:	d8690002 	ld.b	r3, (r9, 0x2)	// regs: r3=*(<ret skb_put@0x1a0> + 0x2)
 1f2:	8240      	ld.b	r2, (r2, 0x0)	// regs: r2=*(0x0)
 1f4:	c4625c60 	ins	r3, r2, 3, 0
 1f8:	dc690002 	st.b	r3, (r9, 0x2)	// *(<ret skb_put@0x1a0> + 0x2) = *(<ret skb_put@0x1a0> + 0x2)
loc_1fc:
 1fc:	d804432a 	ld.bs	r0, (r4, 0x32a)	// regs: r0=*(r4 + 0x32a)
 200:	e9800020 	blz	r0, 0x240	// if (r0 < 0x0) goto loc_240;
 204:	9566      	ld.w	r3, (r5, 0x18)	// regs: r3=*(r5 + 0x18)
 206:	9549      	ld.w	r2, (r5, 0x24)	// regs: r2=*(r5 + 0x24)
 208:	608e      	subu	r2, r3	// regs: r2=(*(r5 + 0x24) - *(r5 + 0x18))
 20a:	3a25      	cmplti	r2, 6
 20c:	08bb      	bt	0x382	// if (r2 < 0x6) goto loc_382;
 20e:	31fa      	movi	r1, 250	// regs: r1=0xfa
 210:	8343      	ld.b	r2, (r3, 0x3)	// regs: r2=*((*(r5 + 0x18) + 0x3))
 212:	4122      	lsli	r1, r1, 2	// regs: r1=0x3e8
 214:	7c84      	mult	r2, r1	// regs: r2=(*((*(r5 + 0x18) + 0x3)) * 0x3e8)
 216:	ea01aae6 	movi	r1, 43750	// regs: r1=0xaae6
 21a:	c4814901 	rotli	r1, r1, 4	// regs: r1=rotl(0xaae6, 0x4)
 21e:	6084      	addu	r2, r1	// regs: r2=((*((*(r5 + 0x18) + 0x3)) * 0x3e8) + rotl(0xaae6, 0x4))
 220:	dc4420d1 	st.w	r2, (r4, 0x344)	// *(r4 + 0x344) = ((*((*(r5 + 0x18) + 0x3)) * 0x3e8) + rotl(0xaae6, 0x4))
 224:	3225      	movi	r2, 37	// regs: r2=0x25
 226:	a340      	st.b	r2, (r3, 0x0)	// *(*(r5 + 0x18)) = 0x25
 228:	3203      	movi	r2, 3	// regs: r2=0x3
 22a:	a341      	st.b	r2, (r3, 0x1)	// *((*(r5 + 0x18) + 0x1)) = 0x3
 22c:	3200      	movi	r2, 0	// regs: r2=0x0
 22e:	a342      	st.b	r2, (r3, 0x2)	// *((*(r5 + 0x18) + 0x2)) = 0x0
 230:	d8440348 	ld.b	r2, (r4, 0x348)	// regs: r2=*(r4 + 0x348)
 234:	a343      	st.b	r2, (r3, 0x3)	// *((*(r5 + 0x18) + 0x3)) = *(r4 + 0x348)
 236:	a304      	st.b	r0, (r3, 0x4)	// *((*(r5 + 0x18) + 0x4)) = *(r4 + 0x32a)
 238:	3105      	movi	r1, 5	// regs: r1=0x5
 23a:	6c17      	mov	r0, r5	// regs: r0=r5
 23c:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x23c>, r1=<clobbered>
loc_240:
 240:	d8640360 	ld.b	r3, (r4, 0x360)	// regs: r3=*(r4 + 0x360)
 244:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r4 + 0x360) & 0x1)
 248:	e9030032 	bez	r3, 0x2ac	// if (r3 == 0x0) goto loc_2ac;
 24c:	d8641504 	ld.h	r3, (r4, 0xa08)	// regs: r3=*(r4 + 0xa08)
 250:	e903002e 	bez	r3, 0x2ac	// if (r3 == 0x0) goto loc_2ac;
 254:	d8440556 	ld.b	r2, (r4, 0x556)	// regs: r2=*(r4 + 0x556)
 258:	d864132b 	ld.h	r3, (r4, 0x656)	// regs: r3=*(r4 + 0x656)
 25c:	7cc8      	mult	r3, r2	// regs: r3=(*(r4 + 0x656) * *(r4 + 0x556))
 25e:	d8040364 	ld.b	r0, (r4, 0x364)	// regs: r0=*(r4 + 0x364)
 262:	d8440365 	ld.b	r2, (r4, 0x365)	// regs: r2=*(r4 + 0x365)
 266:	7cc0      	mult	r3, r0	// regs: r3=((*(r4 + 0x656) * *(r4 + 0x556)) * *(r4 + 0x364))
 268:	7cc8      	mult	r3, r2	// regs: r3=(((*(r4 + 0x656) * *(r4 + 0x556)) * *(r4 + 0x364)) * *(r4 + 0x365))
 26a:	3264      	movi	r2, 100	// regs: r2=0x64
 26c:	c4438043 	divs	r3, r3, r2	// regs: r3=((((*(r4 + 0x656) * *(r4 + 0x556)) * *(r4 + 0x364)) * *(r4 + 0x365)) / 0x64)
 270:	748d      	zexth	r2, r3	// regs: r2=zext16(((((*(r4 + 0x656) * *(r4 + 0x556)) * *(r4 + 0x364)) * *(r4 + 0x365)) / 0x64))
 272:	dc44143e 	st.h	r2, (r4, 0x87c)	// *(r4 + 0x87c) = zext16(((((*(r4 + 0x656) * *(r4 + 0x556)) * *(r4 + 0x364)) * *(r4 + 0x365)) / 0x64))
 276:	e902008b 	bez	r2, 0x38c	// if (r2 == 0x0) goto loc_38c;
 27a:	d9252006 	ld.w	r9, (r5, 0x18)	// regs: r9=*(r5 + 0x18)
 27e:	9529      	ld.w	r1, (r5, 0x24)	// regs: r1=*(r5 + 0x24)
 280:	6066      	subu	r1, r9	// regs: r1=(*(r5 + 0x24) - *(r5 + 0x18))
 282:	3928      	cmplti	r1, 9
 284:	0884      	bt	0x38c	// if (r1 < 0x9) goto loc_38c;
 286:	3104      	movi	r1, 4	// regs: r1=0x4
 288:	dc290000 	st.b	r1, (r9, 0x0)	// *(*(r5 + 0x18)) = 0x4
 28c:	4a48      	lsri	r2, r2, 8	// regs: r2=(zext16(((((*(r4 + 0x656) * *(r4 + 0x556)) * *(r4 + 0x364)) * *(r4 + 0x365)) / 0x64)) >> 0x8)
 28e:	3106      	movi	r1, 6	// regs: r1=0x6
 290:	dc290001 	st.b	r1, (r9, 0x1)	// *((*(r5 + 0x18) + 0x1)) = 0x6
 294:	dc090003 	st.b	r0, (r9, 0x3)	// *((*(r5 + 0x18) + 0x3)) = *(r4 + 0x364)
 298:	dc690004 	st.b	r3, (r9, 0x4)	// *((*(r5 + 0x18) + 0x4)) = ((((*(r4 + 0x656) * *(r4 + 0x556)) * *(r4 + 0x364)) * *(r4 + 0x365)) / 0x64)
 29c:	dc490005 	st.b	r2, (r9, 0x5)	// *((*(r5 + 0x18) + 0x5)) = (zext16(((((*(r4 + 0x656) * *(r4 + 0x556)) * *(r4 + 0x364)) * *(r4 + 0x365)) / 0x64)) >> 0x8)
 2a0:	3108      	movi	r1, 8	// regs: r1=0x8
 2a2:	6c17      	mov	r0, r5	// regs: r0=r5
 2a4:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x2a4>, r1=<clobbered>
loc_2a8:
 2a8:	dd272008 	st.w	r9, (r7, 0x20)	// *(r7 + 0x20) = r9
loc_2ac:
 2ac:	d924052d 	ld.b	r9, (r4, 0x52d)	// regs: r9=*(r4 + 0x52d)
 2b0:	e5290001 	addi	r9, r9, 2	// regs: r9=(*(r4 + 0x52d) + 0x2)
 2b4:	7664      	zextb	r9, r9	// regs: r9=zext8((*(r4 + 0x52d) + 0x2))
 2b6:	eb090022 	cmphsi	r9, 35
 2ba:	9506      	ld.w	r0, (r5, 0x18)	// regs: r0=*(r5 + 0x18)
 2bc:	9549      	ld.w	r2, (r5, 0x24)	// regs: r2=*(r5 + 0x24)
 2be:	086e      	bt	0x39a	// if (r9 >= 0x23) goto loc_39a;
 2c0:	5a61      	subu	r3, r2, r0	// regs: r3=(*(r5 + 0x24) - *(r5 + 0x18))
 2c2:	64e5      	cmplt	r9, r3
 2c4:	0c6b      	bf	0x39a	// if (!T) goto loc_39a;
 2c6:	1124      	lrw	r1, 0x0	// regs: r1=0x0
 2c8:	6ca7      	mov	r2, r9	// regs: r2=zext8((*(r4 + 0x52d) + 0x2))
 2ca:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x2ca>, r1=<clobbered>
 2ce:	6c67      	mov	r1, r9	// regs: r1=zext8((*(r4 + 0x52d) + 0x2))
 2d0:	6c17      	mov	r0, r5	// regs: r0=r5
 2d2:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x2d2>, r1=<clobbered>
loc_2d6:
 2d6:	d84420fc 	ld.w	r2, (r4, 0x3f0)	// regs: r2=*(r4 + 0x3f0)
 2da:	ea230100 	movih	r3, 256	// regs: r3=(0x100 << 0x10)
 2de:	2bff      	subi	r3, 256	// regs: r3=((0x100 << 0x10) - 0x100)
 2e0:	68c8      	and	r3, r2	// regs: r3=(((0x100 << 0x10) - 0x100) & *(r4 + 0x3f0))
 2e2:	e9030013 	bez	r3, 0x308	// if (r3 == 0x0) goto loc_308;
 2e6:	9506      	ld.w	r0, (r5, 0x18)	// regs: r0=*(r5 + 0x18)
 2e8:	9569      	ld.w	r3, (r5, 0x24)	// regs: r3=*(r5 + 0x24)
 2ea:	c50256e2 	zext	r2, r2, 23, 8	// regs: r2=zext(*(r4 + 0x3f0))
 2ee:	60c2      	subu	r3, r0	// regs: r3=(*(r5 + 0x24) - *(r5 + 0x18))
 2f0:	64c9      	cmplt	r2, r3
 2f2:	0c0b      	bf	0x308	// if (!T) goto loc_308;
 2f4:	1039      	lrw	r1, 0x0	// regs: r1=0x0
 2f6:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x2f6>, r1=<clobbered>
 2fa:	d82420fc 	ld.w	r1, (r4, 0x3f0)	// regs: r1=*(r4 + 0x3f0)
 2fe:	c50156e1 	zext	r1, r1, 23, 8	// regs: r1=zext(*(r4 + 0x3f0))
 302:	6c17      	mov	r0, r5	// regs: r0=r5
 304:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x304>, r1=<clobbered>
loc_308:
 308:	d8680027 	ld.b	r3, (r8, 0x27)	// regs: r3=*(r8 + 0x27)
 30c:	3201      	movi	r2, 1	// regs: r2=0x1
 30e:	c4625c06 	ins	r3, r2, 6, 6
 312:	dc680027 	st.b	r3, (r8, 0x27)	// *(r8 + 0x27) = *(r8 + 0x27)
 316:	d8640308 	ld.b	r3, (r4, 0x308)	// regs: r3=*(r4 + 0x308)
 31a:	b7c3      	st.w	r6, (r7, 0xc)	// *(r7 + 0xc) = r6
 31c:	260e      	addi	r6, 15	// regs: r6=(r6 + 0xf)
 31e:	b7ca      	st.w	r6, (r7, 0x28)	// *(r7 + 0x28) = (r6 + 0xf)
 320:	3b01      	cmphsi	r3, 2
 322:	c4000502 	mvc	r2	// regs: r2=<cond>
 326:	d8680025 	ld.b	r3, (r8, 0x25)	// regs: r3=*(r8 + 0x25)
 32a:	c4625c05 	ins	r3, r2, 5, 5
 32e:	dc680025 	st.b	r3, (r8, 0x25)	// *(r8 + 0x25) = *(r8 + 0x25)
 332:	1496      	pop	r4-r9, r15
 334:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
 338:	00000000 	.long	0x00000000	// <ah_lmac>
 33c:	0000      	.short	0x0000	// <ah_lmac+0x558>
 33e:	0000      	.short	0x0000
 340:	00000000 	.long	0x00000000	// <.rodata.lmac_beacon_build_s1gbeacon.str1.1>
 344:	00000000 	.long	0x00000000	// <ah_lmac+0x4f3>
 348:	00000000 	.long	0x00000000	// <.bss.obss_det_ind.14022>
 34c:	00000000 	.long	0x00000000	// <.bss.edca_update_cnt.14021>
 350:	00000000 	.long	0x00000000	// <ah_lmac+0x514>
 354:	00000000 	.long	0x00000000	// <ah_lmac+0x52c>
 358:	00000000 	.long	0x00000000	// <ah_lmac+0x3f3>
loc_35c:
 35c:	1033      	lrw	r1, 0x0	// regs: r1=0x0
 35e:	1014      	lrw	r0, 0x0	// regs: r0=0x0
 360:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x360>, r1=<clobbered>
 364:	ea090000 	movi	r9, 0	// regs: r9=0x0
 368:	0708      	br	0x178	// goto loc_178;
loc_36a:
 36a:	8340      	ld.b	r2, (r3, 0x0)	// regs: r2=*(0x0)
 36c:	3a41      	cmpnei	r2, 1
 36e:	0807      	bt	0x37c	// if (r2 != 0x1) goto loc_37c;
 370:	3200      	movi	r2, 0	// regs: r2=0x0
 372:	a340      	st.b	r2, (r3, 0x0)	// *(0x0) = 0x0
 374:	104f      	lrw	r2, 0x0	// regs: r2=0x0
 376:	8260      	ld.b	r3, (r2, 0x0)	// regs: r3=*(0x0)
 378:	2300      	addi	r3, 1	// regs: r3=(*(0x0) + 0x1)
 37a:	a260      	st.b	r3, (r2, 0x0)	// *(0x0) = (*(0x0) + 0x1)
loc_37c:
 37c:	3212      	movi	r2, 18	// regs: r2=0x12
 37e:	102e      	lrw	r1, 0x0	// regs: r1=0x0
 380:	072e      	br	0x1dc	// goto loc_1dc;
loc_382:
 382:	102e      	lrw	r1, 0x0	// regs: r1=0x0
 384:	100a      	lrw	r0, 0x0	// regs: r0=0x0
 386:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x386>, r1=<clobbered>
 38a:	075b      	br	0x240	// goto loc_240;
loc_38c:
 38c:	102c      	lrw	r1, 0x0	// regs: r1=0x0
 38e:	1008      	lrw	r0, 0x0	// regs: r0=0x0
 390:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x390>, r1=<clobbered>
 394:	ea090000 	movi	r9, 0	// regs: r9=0x0
 398:	0788      	br	0x2a8	// goto loc_2a8;
loc_39a:
 39a:	6082      	subu	r2, r0	// regs: r2=(*(r5 + 0x24) - *(r5 + 0x18))
 39c:	6c67      	mov	r1, r9	// regs: r1=zext8((*(r4 + 0x52d) + 0x2))
 39e:	1009      	lrw	r0, 0x0	// regs: r0=0x0
 3a0:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x3a0>, r1=<clobbered>
 3a4:	0799      	br	0x2d6	// goto loc_2d6;
 3a6:	0000      	.short	0x0000
 3a8:	00000000 	.long	0x00000000	// <.rodata.__func__.14031>
 3ac:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_pv0_s1g_beacon.str1.1+0x77>
 3b0:	00000000 	.long	0x00000000	// <.bss.edca_update_cnt.14021>
 3b4:	00000000 	.long	0x00000000	// <ah_lmac+0x502>
 3b8:	00000000 	.long	0x00000000	// <.rodata.__func__.13259>
 3bc:	00000000 	.long	0x00000000	// <.rodata.__func__.13265>
 3c0:	00000000 	.long	0x00000000	// <.rodata.lmac_beacon_build_s1gbeacon.str1.1+0x1c>

Disassembly of section .text.lmac_dtim_timer_rem:

00000000 <lmac_dtim_timer_rem>: // arg_bytes: 0
   0:	104f      	lrw	r2, 0x0	// regs: r2=0x0
   2:	d862202f 	ld.w	r3, (r2, 0xbc)	// regs: r3=*(0xbc)
   6:	3b42      	cmpnei	r3, 2
   8:	0816      	bt	0x34	// if (r3 != 0x2) goto loc_34;
   a:	d8621505 	ld.h	r3, (r2, 0xa0a)	// regs: r3=*(0xa0a)
   e:	e9030013 	bez	r3, 0x34	// if (r3 == 0x0) goto loc_34;
  12:	d8620555 	ld.b	r3, (r2, 0x555)	// regs: r3=*(0x555)
  16:	e903000c 	bez	r3, 0x2e	// if (r3 == 0x0) goto loc_2e;
loc_1a:
  1a:	102a      	lrw	r1, 0x0	// regs: r1=0x0
  1c:	2b00      	subi	r3, 1	// regs: r3=(r3 - 0x1)
  1e:	9120      	ld.w	r1, (r1, 0x0)	// regs: r1=*(0x0)
  20:	d8022196 	ld.w	r0, (r2, 0x658)	// regs: r0=*(0x658)
  24:	d8212030 	ld.w	r1, (r1, 0xc0)	// regs: r1=*((*(0x0) + 0xc0))
  28:	7c0c      	mult	r0, r3	// regs: r0=(*(0x658) * (r3 - 0x1))
  2a:	6004      	addu	r0, r1	// regs: r0=((*(0x658) * (r3 - 0x1)) + *((*(0x0) + 0xc0)))
loc_2c:
  2c:	783c      	jmp	r15	// return;
loc_2e:
  2e:	d8620556 	ld.b	r3, (r2, 0x556)	// regs: r3=*(0x556)
  32:	07f4      	br	0x1a	// goto loc_1a;
loc_34:
  34:	3000      	movi	r0, 0	// regs: r0=0x0
  36:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  38:	07fa      	br	0x2c	// goto loc_2c;
  3a:	0000      	.short	0x0000
  3c:	00000000 	.long	0x00000000	// <ah_lmac>
  40:	0000      	.short	0x0000	// <LMAC>
  42:	0000      	.short	0x0000

Disassembly of section .text.lmac_hdr_dur_calc:

00000000 <lmac_hdr_dur_calc>: // arg_bytes: 4
   0:	106c      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   4:	d8632037 	ld.w	r3, (r3, 0xdc)	// regs: r3=*((*(0x0) + 0xdc))
   8:	c40355e2 	zext	r2, r3, 15, 0	// regs: r2=zext(*((*(0x0) + 0xdc)))
   c:	6480      	cmphs	r0, r2
   e:	080e      	bt	0x2a	// if (T) goto loc_2a;
  10:	5b01      	subu	r0, r3, r0	// regs: r0=(*((*(0x0) + 0xdc)) - <arg0>)
  12:	7401      	zexth	r0, r0	// regs: r0=zext16((*((*(0x0) + 0xdc)) - <arg0>))
loc_14:
  14:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  16:	d8430878 	ld.b	r2, (r3, 0x878)	// regs: r2=*(0x878)
  1a:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(0x878) & 0x1)
  1e:	3380      	movi	r3, 128	// regs: r3=0x80
  20:	4368      	lsli	r3, r3, 8	// regs: r3=0x8000
  22:	3a40      	cmpnei	r2, 0
  24:	c4030c40 	inct	r0, r3, 0
  28:	783c      	jmp	r15	// return;
loc_2a:
  2a:	3000      	movi	r0, 0	// regs: r0=0x0
  2c:	07f4      	br	0x14	// goto loc_14;
  2e:	0000      	.short	0x0000
  30:	0000      	.short	0x0000	// <LMAC>
  32:	0000      	.short	0x0000
  34:	0000      	.short	0x0000	// <ah_lmac>
  36:	0000      	.short	0x0000

Disassembly of section .text.lmac_send_data_to_phy:

00000000 <lmac_send_data_to_phy>: // arg_bytes: 4
   0:	14d7      	push	r4-r10, r15
   2:	3390      	movi	r3, 144	// regs: r3=0x90
   4:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
   6:	1190      	lrw	r4, 0x0	// regs: r4=0x0
   8:	7cc0      	mult	r3, r0	// regs: r3=(0x120 * <arg0>)
   a:	60d0      	addu	r3, r4	// regs: r3=((0x120 * <arg0>) )
   c:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   e:	d8e301c4 	ld.b	r7, (r3, 0x1c4)	// regs: r7=*((((0x120 * <arg0>) ) + 0x1c4))
  12:	e9070050 	bez	r7, 0xb2	// if (r7 == 0x0) goto loc_b2;
  16:	d80310e3 	ld.h	r0, (r3, 0x1c6)	// regs: r0=*((((0x120 * <arg0>) ) + 0x1c6))
  1a:	c4c05520 	zext	r0, r0, 9, 6	// regs: r0=zext(*((((0x120 * <arg0>) ) + 0x1c6)))
  1e:	d863206f 	ld.w	r3, (r3, 0x1bc)	// regs: r3=*((((0x120 * <arg0>) ) + 0x1bc))
  22:	60c0      	addu	r3, r0	// regs: r3=(*((((0x120 * <arg0>) ) + 0x1bc)) + zext(*((((0x120 * <arg0>) ) + 0x1c6))))
  24:	3028      	movi	r0, 40	// regs: r0=0x28
  26:	7c0c      	mult	r0, r3	// regs: r0=(0x28 * (*((((0x120 * <arg0>) ) + 0x1bc)) + zext(*((((0x120 * <arg0>) ) + 0x1c6)))))
  28:	e0000000 	bsr	0x0	// <lmac_hdr_dur_calc> // arg_bytes: 4; regs: r0=<ret lmac_hdr_dur_calc@0x28>, r1=<clobbered>
  2c:	d8a412af 	ld.h	r5, (r4, 0x55e)	// regs: r5=*(0x55e)
  30:	74d5      	zexth	r3, r5	// regs: r3=zext16(*(0x55e))
  32:	640c      	cmphs	r3, r0
  34:	0802      	bt	0x38	// if (T) goto loc_38;
  36:	6d43      	mov	r5, r0	// regs: r5=<ret lmac_hdr_dur_calc@0x28>
loc_38:
  38:	6c1f      	mov	r0, r7	// regs: r0=*((((0x120 * <arg0>) ) + 0x1c4))
  3a:	e0000000 	bsr	0x0	// <lhw_cfg_dma_list_cnt>; regs: r0=<ret lhw_cfg_dma_list_cnt@0x3a>, r1=<clobbered>
  3e:	3390      	movi	r3, 144	// regs: r3=0x90
  40:	7555      	zexth	r5, r5	// regs: r5=zext16(r5)
  42:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  44:	c5054849 	lsri	r9, r5, 8	// regs: r9=(zext16(r5) >> 0x8)
  48:	c466842a 	mult	r10, r6, r3	// regs: r10=(<arg0> * 0x120)
  4c:	ea080000 	movi	r8, 0	// regs: r8=0x0
loc_50:
  50:	7420      	zextb	r0, r8	// regs: r0=zext8(r8)
  52:	65c0      	cmphs	r0, r7
  54:	0c1b      	bf	0x8a	// if (!T) goto loc_8a;
  56:	3290      	movi	r2, 144	// regs: r2=0x90
  58:	4241      	lsli	r2, r2, 1	// regs: r2=0x120
  5a:	7d88      	mult	r6, r2	// regs: r6=(<arg0> * 0x120)
  5c:	107b      	lrw	r3, 0x0	// regs: r3=0x0
  5e:	6118      	addu	r4, r6	// regs: r4=(0x0 + (<arg0> * 0x120))
  60:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  62:	d844206e 	ld.w	r2, (r4, 0x1b8)	// regs: r2=*(((0x0 + (<arg0> * 0x120)) + 0x1b8))
  66:	b35f      	st.w	r2, (r3, 0x7c)	// *((*(0x0) + 0x7c)) = *(((0x0 + (<arg0> * 0x120)) + 0x1b8))
  68:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  6a:	3a81      	bclri	r2, 1	// regs: r2=(*((*(0x0) + 0x58)) & ~(0x1 << 0x1))
  6c:	3f41      	cmpnei	r7, 1
  6e:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) & ~(0x1 << 0x1))
  70:	6483      	mvcv	r2	// regs: r2=<cond>
  72:	9336      	ld.w	r1, (r3, 0x58)	// regs: r1=*((*(0x0) + 0x58))
  74:	4241      	lsli	r2, r2, 1	// regs: r2=(<cond> << 0x1)
  76:	6c84      	or	r2, r1	// regs: r2=((<cond> << 0x1) | *((*(0x0) + 0x58)))
  78:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = ((<cond> << 0x1) | *((*(0x0) + 0x58)))
  7a:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  7c:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  7e:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  80:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  82:	ec420001 	ori	r2, r2, 1	// regs: r2=(*((*(0x0) + 0x58)) | 0x1)
  86:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) | 0x1)
loc_88:
  88:	1497      	pop	r4-r10, r15
loc_8a:
  8a:	c4484823 	lsli	r3, r8, 2	// regs: r3=(r8 << 0x2)
  8e:	60e8      	addu	r3, r10	// regs: r3=((r8 << 0x2) + (<arg0> * 0x120))
  90:	60d0      	addu	r3, r4	// regs: r3=(((r8 << 0x2) + (<arg0> * 0x120)) )
  92:	d863202e 	ld.w	r3, (r3, 0xb8)	// regs: r3=*(((((r8 << 0x2) + (<arg0> * 0x120)) ) + 0xb8))
  96:	9327      	ld.w	r1, (r3, 0x1c)	// regs: r1=*((*(((((r8 << 0x2) + (<arg0> * 0x120)) ) + 0xb8)) + 0x1c))
  98:	8b54      	ld.h	r2, (r3, 0x28)	// regs: r2=*((*(((((r8 << 0x2) + (<arg0> * 0x120)) ) + 0xb8)) + 0x28))
  9a:	8160      	ld.b	r3, (r1, 0x0)	// regs: r3=*(*((*(((((r8 << 0x2) + (<arg0> * 0x120)) ) + 0xb8)) + 0x1c)))
  9c:	eb4300b4 	cmpnei	r3, 180
  a0:	0c04      	bf	0xa8	// if (r3 == 0xb4) goto loc_a8;
  a2:	a1a2      	st.b	r5, (r1, 0x2)	// *((*((*(((((r8 << 0x2) + (<arg0> * 0x120)) ) + 0xb8)) + 0x1c)) + 0x2)) = zext16(r5)
  a4:	dd210003 	st.b	r9, (r1, 0x3)	// *((*((*(((((r8 << 0x2) + (<arg0> * 0x120)) ) + 0xb8)) + 0x1c)) + 0x3)) = (zext16(r5) >> 0x8)
loc_a8:
  a8:	e0000000 	bsr	0x0	// <lhw_cfg_tx_sub_frm>; regs: r0=<ret lhw_cfg_tx_sub_frm@0xa8>, r1=<clobbered>
  ac:	e5080000 	addi	r8, r8, 1	// regs: r8=(r8 + 0x1)
  b0:	07d0      	br	0x50	// goto loc_50;
loc_b2:
  b2:	1047      	lrw	r2, 0x0	// regs: r2=0x0
  b4:	d862226d 	ld.w	r3, (r2, 0x9b4)	// regs: r3=*(0x9b4)
  b8:	ec634000 	ori	r3, r3, 16384	// regs: r3=(*(0x9b4) | 0x4000)
  bc:	dc62226d 	st.w	r3, (r2, 0x9b4)	// *(0x9b4) = (*(0x9b4) | 0x4000)
  c0:	07e4      	br	0x88	// goto loc_88;
  c2:	0000      	.short	0x0000
  c4:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  c6:	0000      	.short	0x0000
  c8:	00000000 	.long	0x00000000	// <LMAC>
  cc:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_tx_ba:

00000000 <lmac_tx_ba>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	1098      	lrw	r4, 0x0	// regs: r4=0x0
   4:	d86409dc 	ld.b	r3, (r4, 0x9dc)	// regs: r3=*(0x9dc)
   8:	e4632020 	andi	r3, r3, 32	// regs: r3=(*(0x9dc) & 0x20)
   c:	e923001f 	bnez	r3, 0x4a	// if (r3 != 0x0) goto loc_4a;
  10:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  14:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  18:	e9230008 	bnez	r3, 0x28	// if (r3 != 0x0) goto loc_28;
  1c:	d8041338 	ld.h	r0, (r4, 0x670)	// regs: r0=*(0x670)
  20:	e0000000 	bsr	0x0	// <lmac_hdr_dur_calc> // arg_bytes: 4; regs: r0=<ret lmac_hdr_dur_calc@0x20>, r1=<clobbered>
  24:	dc04148b 	st.h	r0, (r4, 0x916)	// *(0x916) = <ret lmac_hdr_dur_calc@0x20>
loc_28:
  28:	3001      	movi	r0, 1	// regs: r0=0x1
  2a:	e0000000 	bsr	0x0	// <lhw_cfg_dma_list_cnt>; regs: r0=<ret lhw_cfg_dma_list_cnt@0x2a>, r1=<clobbered>
  2e:	3222      	movi	r2, 34	// regs: r2=0x22
  30:	102d      	lrw	r1, 0x0	// regs: r1=0x0
  32:	3000      	movi	r0, 0	// regs: r0=0x0
  34:	e0000000 	bsr	0x0	// <lhw_cfg_tx_sub_frm>; regs: r0=<ret lhw_cfg_tx_sub_frm@0x34>, r1=<clobbered>
  38:	106c      	lrw	r3, 0x0	// regs: r3=0x0
  3a:	3226      	movi	r2, 38	// regs: r2=0x26
  3c:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  3e:	b35f      	st.w	r2, (r3, 0x7c)	// *((*(0x0) + 0x7c)) = 0x26
  40:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  42:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  44:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  46:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  48:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = *((*(0x0) + 0x58))
loc_4a:
  4a:	1029      	lrw	r1, 0x0	// regs: r1=0x0
  4c:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
  50:	e0000000 	bsr	0x0	// <lmac_sta_search>; regs: r0=<ret lmac_sta_search@0x50>, r1=<clobbered>
  54:	dc042294 	st.w	r0, (r4, 0xa50)	// *(0xa50) = <ret lmac_sta_search@0x50>
  58:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part2> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part2@0x58>, r1=<clobbered>
  5c:	1491      	pop	r4, r15
  5e:	0000      	.short	0x0000
  60:	0000      	.short	0x0000	// <ah_lmac>
  62:	0000      	.short	0x0000
  64:	00000000 	.long	0x00000000	// <ah_lmac+0x914>
  68:	00000000 	.long	0x00000000	// <LMAC>
  6c:	00000000 	.long	0x00000000	// <ah_lmac+0x918>

Disassembly of section .text.lmac_tx_ack:

00000000 <lmac_tx_ack>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	1095      	lrw	r4, 0x0	// regs: r4=0x0
   4:	d8a409dc 	ld.b	r5, (r4, 0x9dc)	// regs: r5=*(0x9dc)
   8:	e4a52040 	andi	r5, r5, 64	// regs: r5=(*(0x9dc) & 0x40)
   c:	e925001a 	bnez	r5, 0x40	// if (r5 != 0x0) goto loc_40;
  10:	d8041337 	ld.h	r0, (r4, 0x66e)	// regs: r0=*(0x66e)
  14:	e0000000 	bsr	0x0	// <lmac_hdr_dur_calc> // arg_bytes: 4; regs: r0=<ret lmac_hdr_dur_calc@0x14>, r1=<clobbered>
  18:	dc041483 	st.h	r0, (r4, 0x906)	// *(0x906) = <ret lmac_hdr_dur_calc@0x14>
  1c:	3001      	movi	r0, 1	// regs: r0=0x1
  1e:	e0000000 	bsr	0x0	// <lhw_cfg_dma_list_cnt>; regs: r0=<ret lhw_cfg_dma_list_cnt@0x1e>, r1=<clobbered>
  22:	3210      	movi	r2, 16	// regs: r2=0x10
  24:	e4240903 	addi	r1, r4, 2308	// regs: r1=0x904
  28:	6c17      	mov	r0, r5	// regs: r0=(*(0x9dc) & 0x40)
  2a:	e0000000 	bsr	0x0	// <lhw_cfg_tx_sub_frm>; regs: r0=<ret lhw_cfg_tx_sub_frm@0x2a>, r1=<clobbered>
  2e:	106b      	lrw	r3, 0x0	// regs: r3=0x0
  30:	3214      	movi	r2, 20	// regs: r2=0x14
  32:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  34:	b35f      	st.w	r2, (r3, 0x7c)	// *((*(0x0) + 0x7c)) = 0x14
  36:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  38:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  3a:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  3c:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  3e:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = *((*(0x0) + 0x58))
loc_40:
  40:	1027      	lrw	r1, 0x0	// regs: r1=0x0
  42:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
  46:	e0000000 	bsr	0x0	// <lmac_sta_search>; regs: r0=<ret lmac_sta_search@0x46>, r1=<clobbered>
  4a:	dc042294 	st.w	r0, (r4, 0xa50)	// *(0xa50) = <ret lmac_sta_search@0x46>
  4e:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part2> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part2@0x4e>, r1=<clobbered>
  52:	1492      	pop	r4-r5, r15
  54:	00000000 	.long	0x00000000	// <ah_lmac>
  58:	00000000 	.long	0x00000000	// <LMAC>
  5c:	0000      	.short	0x0000	// <ah_lmac+0x908>
  5e:	0000      	.short	0x0000

Disassembly of section .text.lmac_tx_cts:

00000000 <lmac_tx_cts>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	109d      	lrw	r4, 0x0	// regs: r4=0x0
   4:	d8a409dc 	ld.b	r5, (r4, 0x9dc)	// regs: r5=*(0x9dc)
   8:	e4a52010 	andi	r5, r5, 16	// regs: r5=(*(0x9dc) & 0x10)
   c:	e9250029 	bnez	r5, 0x5e	// if (r5 != 0x0) goto loc_5e;
  10:	3001      	movi	r0, 1	// regs: r0=0x1
  12:	e0000000 	bsr	0x0	// <lhw_cfg_dma_list_cnt>; regs: r0=<ret lhw_cfg_dma_list_cnt@0x12>, r1=<clobbered>
  16:	3210      	movi	r2, 16	// regs: r2=0x10
  18:	e42408f3 	addi	r1, r4, 2292	// regs: r1=0x8f4
  1c:	6c17      	mov	r0, r5	// regs: r0=(*(0x9dc) & 0x10)
  1e:	e0000000 	bsr	0x0	// <lhw_cfg_tx_sub_frm>; regs: r0=<ret lhw_cfg_tx_sub_frm@0x1e>, r1=<clobbered>
  22:	1076      	lrw	r3, 0x0	// regs: r3=0x0
  24:	3114      	movi	r1, 20	// regs: r1=0x14
  26:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
  28:	6d4f      	mov	r5, r3	// regs: r5=0x0
  2a:	b23f      	st.w	r1, (r2, 0x7c)	// *((*(0x0) + 0x7c)) = 0x14
  2c:	d84409dd 	ld.b	r2, (r4, 0x9dd)	// regs: r2=*(0x9dd)
  30:	e4422010 	andi	r2, r2, 16	// regs: r2=(*(0x9dd) & 0x10)
  34:	e902000f 	bez	r2, 0x52	// if (r2 == 0x0) goto loc_52;
  38:	e0000000 	bsr	0x0	// <lmac_dtim_timer_rem> // arg_bytes: 0; regs: r0=<ret lmac_dtim_timer_rem@0x38>, r1=<clobbered>
  3c:	e4000f9f 	addi	r0, r0, 4000	// regs: r0=(<ret lmac_dtim_timer_rem@0x38> + 0xfa0)
  40:	dc04147b 	st.h	r0, (r4, 0x8f6)	// *(0x8f6) = (<ret lmac_dtim_timer_rem@0x38> + 0xfa0)
  44:	3206      	movi	r2, 6	// regs: r2=0x6
  46:	e4240301 	addi	r1, r4, 770	// regs: r1=0x302
  4a:	e40408f7 	addi	r0, r4, 2296	// regs: r0=0x8f8
  4e:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x4e>, r1=<clobbered>
loc_52:
  52:	9560      	ld.w	r3, (r5, 0x0)	// regs: r3=*(0x0)
  54:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  56:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  58:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  5a:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  5c:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = *((*(0x0) + 0x58))
loc_5e:
  5e:	1028      	lrw	r1, 0x0	// regs: r1=0x0
  60:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
  64:	e0000000 	bsr	0x0	// <lmac_sta_search>; regs: r0=<ret lmac_sta_search@0x64>, r1=<clobbered>
  68:	dc042294 	st.w	r0, (r4, 0xa50)	// *(0xa50) = <ret lmac_sta_search@0x64>
  6c:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part2> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part2@0x6c>, r1=<clobbered>
  70:	1492      	pop	r4-r5, r15
  72:	0000      	.short	0x0000
  74:	0000      	.short	0x0000	// <ah_lmac>
  76:	0000      	.short	0x0000
  78:	0000      	.short	0x0000	// <LMAC>
  7a:	0000      	.short	0x0000
  7c:	00000000 	.long	0x00000000	// <ah_lmac+0x8f8>

Disassembly of section .text.lmac_tx_pv0_cfpoll:

00000000 <lmac_tx_pv0_cfpoll>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	108f      	lrw	r4, 0x0	// regs: r4=0x0
   4:	3001      	movi	r0, 1	// regs: r0=0x1
   6:	e0000000 	bsr	0x0	// <lhw_cfg_dma_list_cnt>; regs: r0=<ret lhw_cfg_dma_list_cnt@0x6>, r1=<clobbered>
   a:	6c53      	mov	r1, r4	// regs: r1=0x0
   c:	3220      	movi	r2, 32	// regs: r2=0x20
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	e0000000 	bsr	0x0	// <lhw_cfg_tx_sub_frm>; regs: r0=<ret lhw_cfg_tx_sub_frm@0x10>, r1=<clobbered>
  14:	106b      	lrw	r3, 0x0	// regs: r3=0x0
  16:	3224      	movi	r2, 36	// regs: r2=0x24
  18:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  1a:	5c2e      	addi	r1, r4, 4	// regs: r1=0x4
  1c:	b35f      	st.w	r2, (r3, 0x7c)	// *((*(0x0) + 0x7c)) = 0x24
  1e:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  20:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  22:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  24:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  26:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = *((*(0x0) + 0x58))
  28:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
  2c:	e0000000 	bsr	0x0	// <lmac_sta_search>; regs: r0=<ret lmac_sta_search@0x2c>, r1=<clobbered>
  30:	dc042046 	st.w	r0, (r4, 0x118)	// *(0x118) = <ret lmac_sta_search@0x2c>
  34:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part2> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part2@0x34>, r1=<clobbered>
  38:	1491      	pop	r4, r15
  3a:	0000      	.short	0x0000
  3c:	00000000 	.long	0x00000000	// <ah_lmac+0x938>
  40:	0000      	.short	0x0000	// <LMAC>
  42:	0000      	.short	0x0000

Disassembly of section .text.lmac_tx_pv0_cfend:

00000000 <lmac_tx_pv0_cfend>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	3001      	movi	r0, 1	// regs: r0=0x1
   4:	e0000000 	bsr	0x0	// <lhw_cfg_dma_list_cnt>; regs: r0=<ret lhw_cfg_dma_list_cnt@0x4>, r1=<clobbered>
   8:	3210      	movi	r2, 16	// regs: r2=0x10
   a:	1031      	lrw	r1, 0x0	// regs: r1=0x0
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <lhw_cfg_tx_sub_frm>; regs: r0=<ret lhw_cfg_tx_sub_frm@0xe>, r1=<clobbered>
  12:	1070      	lrw	r3, 0x0	// regs: r3=0x0
  14:	3214      	movi	r2, 20	// regs: r2=0x14
  16:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  18:	102f      	lrw	r1, 0x0	// regs: r1=0x0
  1a:	b35f      	st.w	r2, (r3, 0x7c)	// *((*(0x0) + 0x7c)) = 0x14
  1c:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  1e:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  20:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  22:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  24:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = *((*(0x0) + 0x58))
  26:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
  2a:	108c      	lrw	r4, 0x0	// regs: r4=0x0
  2c:	e0000000 	bsr	0x0	// <lmac_sta_search>; regs: r0=<ret lmac_sta_search@0x2c>, r1=<clobbered>
  30:	dc042294 	st.w	r0, (r4, 0xa50)	// *(0xa50) = <ret lmac_sta_search@0x2c>
  34:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part2> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part2@0x34>, r1=<clobbered>
  38:	d864202f 	ld.w	r3, (r4, 0xbc)	// regs: r3=*(0xbc)
  3c:	3b41      	cmpnei	r3, 1
  3e:	0805      	bt	0x48	// if (r3 != 0x1) goto loc_48;
  40:	30fa      	movi	r0, 250	// regs: r0=0xfa
  42:	4003      	lsli	r0, r0, 3	// regs: r0=0x7d0
  44:	e0000000 	bsr	0x0	// <lmac_set_basic_nav>; regs: r0=<ret lmac_set_basic_nav@0x44>, r1=<clobbered>
loc_48:
  48:	1491      	pop	r4, r15
  4a:	0000      	.short	0x0000
  4c:	00000000 	.long	0x00000000	// <ah_lmac+0x958>
  50:	0000      	.short	0x0000	// <LMAC>
  52:	0000      	.short	0x0000
  54:	00000000 	.long	0x00000000	// <ah_lmac+0x95c>
  58:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_tx_pv0_null:

00000000 <lmac_tx_pv0_null>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	108f      	lrw	r4, 0x0	// regs: r4=0x0
   4:	3001      	movi	r0, 1	// regs: r0=0x1
   6:	e0000000 	bsr	0x0	// <lhw_cfg_dma_list_cnt>; regs: r0=<ret lhw_cfg_dma_list_cnt@0x6>, r1=<clobbered>
   a:	6c53      	mov	r1, r4	// regs: r1=0x0
   c:	321a      	movi	r2, 26	// regs: r2=0x1a
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	e0000000 	bsr	0x0	// <lhw_cfg_tx_sub_frm>; regs: r0=<ret lhw_cfg_tx_sub_frm@0x10>, r1=<clobbered>
  14:	106b      	lrw	r3, 0x0	// regs: r3=0x0
  16:	321e      	movi	r2, 30	// regs: r2=0x1e
  18:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  1a:	5c2e      	addi	r1, r4, 4	// regs: r1=0x4
  1c:	b35f      	st.w	r2, (r3, 0x7c)	// *((*(0x0) + 0x7c)) = 0x1e
  1e:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  20:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  22:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  24:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  26:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = *((*(0x0) + 0x58))
  28:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
  2c:	e0000000 	bsr	0x0	// <lmac_sta_search>; regs: r0=<ret lmac_sta_search@0x2c>, r1=<clobbered>
  30:	dc042036 	st.w	r0, (r4, 0xd8)	// *(0xd8) = <ret lmac_sta_search@0x2c>
  34:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part2> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part2@0x34>, r1=<clobbered>
  38:	1491      	pop	r4, r15
  3a:	0000      	.short	0x0000
  3c:	00000000 	.long	0x00000000	// <ah_lmac+0x978>
  40:	0000      	.short	0x0000	// <LMAC>
  42:	0000      	.short	0x0000

Disassembly of section .text.lmac_tx_pv0_pspoll:

00000000 <lmac_tx_pv0_pspoll>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	108f      	lrw	r4, 0x0	// regs: r4=0x0
   4:	3001      	movi	r0, 1	// regs: r0=0x1
   6:	e0000000 	bsr	0x0	// <lhw_cfg_dma_list_cnt>; regs: r0=<ret lhw_cfg_dma_list_cnt@0x6>, r1=<clobbered>
   a:	6c53      	mov	r1, r4	// regs: r1=0x0
   c:	3210      	movi	r2, 16	// regs: r2=0x10
   e:	3000      	movi	r0, 0	// regs: r0=0x0
  10:	e0000000 	bsr	0x0	// <lhw_cfg_tx_sub_frm>; regs: r0=<ret lhw_cfg_tx_sub_frm@0x10>, r1=<clobbered>
  14:	106b      	lrw	r3, 0x0	// regs: r3=0x0
  16:	3214      	movi	r2, 20	// regs: r2=0x14
  18:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  1a:	5c2e      	addi	r1, r4, 4	// regs: r1=0x4
  1c:	b35f      	st.w	r2, (r3, 0x7c)	// *((*(0x0) + 0x7c)) = 0x14
  1e:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  20:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  22:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  24:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  26:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = *((*(0x0) + 0x58))
  28:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
  2c:	e0000000 	bsr	0x0	// <lmac_sta_search>; regs: r0=<ret lmac_sta_search@0x2c>, r1=<clobbered>
  30:	dc04203a 	st.w	r0, (r4, 0xe8)	// *(0xe8) = <ret lmac_sta_search@0x2c>
  34:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part2> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part2@0x34>, r1=<clobbered>
  38:	1491      	pop	r4, r15
  3a:	0000      	.short	0x0000
  3c:	00000000 	.long	0x00000000	// <ah_lmac+0x968>
  40:	0000      	.short	0x0000	// <LMAC>
  42:	0000      	.short	0x0000

Disassembly of section .text.lmac_tx_rts:

00000000 <lmac_tx_rts>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	3001      	movi	r0, 1	// regs: r0=0x1
   4:	e0000000 	bsr	0x0	// <lhw_cfg_dma_list_cnt>; regs: r0=<ret lhw_cfg_dma_list_cnt@0x4>, r1=<clobbered>
   8:	3210      	movi	r2, 16	// regs: r2=0x10
   a:	1121      	lrw	r1, 0x0	// regs: r1=0x0
   c:	3000      	movi	r0, 0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <lhw_cfg_tx_sub_frm>; regs: r0=<ret lhw_cfg_tx_sub_frm@0xe>, r1=<clobbered>
  12:	1160      	lrw	r3, 0x0	// regs: r3=0x0
  14:	3218      	movi	r2, 24	// regs: r2=0x18
  16:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  18:	103f      	lrw	r1, 0x0	// regs: r1=0x0
  1a:	b35f      	st.w	r2, (r3, 0x7c)	// *((*(0x0) + 0x7c)) = 0x18
  1c:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  1e:	3a81      	bclri	r2, 1	// regs: r2=(*((*(0x0) + 0x58)) & ~(0x1 << 0x1))
  20:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) & ~(0x1 << 0x1))
  22:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  24:	ec420002 	ori	r2, r2, 2	// regs: r2=(*((*(0x0) + 0x58)) | 0x2)
  28:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) | 0x2)
  2a:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  2c:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  2e:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) & ~(0x1 << 0x0))
  30:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  32:	ec420001 	ori	r2, r2, 1	// regs: r2=(*((*(0x0) + 0x58)) | 0x1)
  36:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) | 0x1)
  38:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
  3c:	1097      	lrw	r4, 0x0	// regs: r4=0x0
  3e:	e0000000 	bsr	0x0	// <lmac_sta_search>; regs: r0=<ret lmac_sta_search@0x3e>, r1=<clobbered>
  42:	dc042294 	st.w	r0, (r4, 0xa50)	// *(0xa50) = <ret lmac_sta_search@0x3e>
  46:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part2> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part2@0x46>, r1=<clobbered>
  4a:	d86409dc 	ld.b	r3, (r4, 0x9dc)	// regs: r3=*(0x9dc)
  4e:	e463200f 	andi	r3, r3, 15	// regs: r3=(*(0x9dc) & 0xf)
  52:	3b23      	cmplti	r3, 4
  54:	0c0c      	bf	0x6c	// if (r3 >= 0x4) goto loc_6c;
  56:	3190      	movi	r1, 144	// regs: r1=0x90
  58:	4121      	lsli	r1, r1, 1	// regs: r1=0x120
  5a:	1051      	lrw	r2, 0x0	// regs: r2=0x0
  5c:	7cc4      	mult	r3, r1	// regs: r3=((*(0x9dc) & 0xf) * 0x120)
  5e:	5a2c      	addu	r1, r2, r3	// regs: r1=(0x0 + ((*(0x9dc) & 0xf) * 0x120))
  60:	6c0b      	mov	r0, r2	// regs: r0=0x0
  62:	d9a101c4 	ld.b	r13, (r1, 0x1c4)	// regs: r13=*(((0x0 + ((*(0x9dc) & 0xf) * 0x120)) + 0x1c4))
  66:	3100      	movi	r1, 0	// regs: r1=0x0
loc_68:
  68:	6745      	cmplt	r1, r13
  6a:	0802      	bt	0x6e	// if (T) goto loc_6e;
loc_6c:
  6c:	1491      	pop	r4, r15
loc_6e:
  6e:	4142      	lsli	r2, r1, 2	// regs: r2=(r1 << 0x2)
  70:	608c      	addu	r2, r3	// regs: r2=((r1 << 0x2) + ((*(0x9dc) & 0xf) * 0x120))
  72:	6080      	addu	r2, r0	// regs: r2=(((r1 << 0x2) + ((*(0x9dc) & 0xf) * 0x120)) )
  74:	2100      	addi	r1, 1	// regs: r1=(r1 + 0x1)
  76:	d842202e 	ld.w	r2, (r2, 0xb8)	// regs: r2=*(((((r1 << 0x2) + ((*(0x9dc) & 0xf) * 0x120)) ) + 0xb8))
  7a:	d9822008 	ld.w	r12, (r2, 0x20)	// regs: r12=*((*(((((r1 << 0x2) + ((*(0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20))
  7e:	d84c0029 	ld.b	r2, (r12, 0x29)	// regs: r2=*((*((*(((((r1 << 0x2) + ((*(0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x29))
  82:	2200      	addi	r2, 1	// regs: r2=(*((*((*(((((r1 << 0x2) + ((*(0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x29)) + 0x1)
  84:	dc4c0029 	st.b	r2, (r12, 0x29)	// *((*((*(((((r1 << 0x2) + ((*(0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x29)) = (*((*((*(((((r1 << 0x2) + ((*(0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x29)) + 0x1)
  88:	07f0      	br	0x68	// goto loc_68;
  8a:	0000      	.short	0x0000
  8c:	0000      	.short	0x0000	// <ah_lmac+0x8e4>
  8e:	0000      	.short	0x0000
  90:	00000000 	.long	0x00000000	// <LMAC>
  94:	00000000 	.long	0x00000000	// <ah_lmac+0x8e8>
  98:	00000000 	.long	0x00000000	// <ah_lmac>
  9c:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  9e:	0000      	.short	0x0000

Disassembly of section .text.lmac_tx_frm:

00000000 <lmac_tx_frm>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	10b8      	lrw	r5, 0x0	// regs: r5=0x0
   4:	d80509dc 	ld.b	r0, (r5, 0x9dc)	// regs: r0=*(0x9dc)
   8:	e400200f 	andi	r0, r0, 15	// regs: r0=(*(0x9dc) & 0xf)
   c:	3803      	cmphsi	r0, 4
   e:	0827      	bt	0x5c	// if (r0 >= 0x4) goto loc_5c;
  10:	3390      	movi	r3, 144	// regs: r3=0x90
  12:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  14:	7cc0      	mult	r3, r0	// regs: r3=(0x120 * (*(0x9dc) & 0xf))
  16:	1054      	lrw	r2, 0x0	// regs: r2=0x0
  18:	5b88      	addu	r4, r3, r2	// regs: r4=((0x120 * (*(0x9dc) & 0xf)) )
  1a:	d86401c7 	ld.b	r3, (r4, 0x1c7)	// regs: r3=*((((0x120 * (*(0x9dc) & 0xf)) ) + 0x1c7))
  1e:	c4435443 	zext	r3, r3, 2, 2	// regs: r3=zext(*((((0x120 * (*(0x9dc) & 0xf)) ) + 0x1c7)))
  22:	e9030019 	bez	r3, 0x54	// if (r3 == 0x0) goto loc_54;
  26:	e0000000 	bsr	0x0	// <lmac_send_data_to_phy> // arg_bytes: 4; regs: r0=<ret lmac_send_data_to_phy@0x26>, r1=<clobbered>
  2a:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part2> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part2@0x2a>, r1=<clobbered>
  2e:	d86401c7 	ld.b	r3, (r4, 0x1c7)	// regs: r3=*((((0x120 * (*(0x9dc) & 0xf)) ) + 0x1c7))
  32:	3200      	movi	r2, 0	// regs: r2=0x0
  34:	c4625c02 	ins	r3, r2, 2, 2
  38:	dc6401c7 	st.b	r3, (r4, 0x1c7)	// *((((0x120 * (*(0x9dc) & 0xf)) ) + 0x1c7)) = *((((0x120 * (*(0x9dc) & 0xf)) ) + 0x1c7))
  3c:	d86509dc 	ld.b	r3, (r5, 0x9dc)	// regs: r3=*(0x9dc)
  40:	e463200f 	andi	r3, r3, 15	// regs: r3=(*(0x9dc) & 0xf)
  44:	e46301c6 	addi	r3, r3, 455	// regs: r3=((*(0x9dc) & 0xf) + 0x1c7)
  48:	d0650882 	ldr.w	r2, (r5, r3 << 2)	// regs: r2=*(0x0 + (((*(0x9dc) & 0xf) + 0x1c7) << 2))
  4c:	2200      	addi	r2, 1	// regs: r2=(*(0x0 + (((*(0x9dc) & 0xf) + 0x1c7) << 2)) + 0x1)
  4e:	d4650882 	str.w	r2, (r5, r3 << 2)
loc_52:
  52:	1492      	pop	r4-r5, r15
loc_54:
  54:	1005      	lrw	r0, 0x0	// regs: r0=0x0
loc_56:
  56:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x56>, r1=<clobbered>
  5a:	07fc      	br	0x52	// goto loc_52;
loc_5c:
  5c:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  5e:	07fc      	br	0x56	// goto loc_56;
  60:	0000      	.short	0x0000	// <ah_lmac>
  62:	0000      	.short	0x0000
  64:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  68:	00000000 	.long	0x00000000	// <.rodata.lmac_update_frm_tx_vec.str1.1>
  6c:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_frm.str1.1>

Disassembly of section .text.switch_ctrl_normal_mode:

00000000 <switch_ctrl_normal_mode>: // arg_bytes: 0
   0:	1066      	lrw	r3, 0x40026000	// regs: r3=0x40026000
   2:	1047      	lrw	r2, 0x0	// regs: r2=0x0
   4:	9335      	ld.w	r1, (r3, 0x54)	// regs: r1=*(0x40026054)
   6:	b220      	st.w	r1, (r2, 0x0)	// *(0x0) = *(0x40026054)
   8:	9355      	ld.w	r2, (r3, 0x54)	// regs: r2=*(0x40026054)
   a:	3a9e      	bclri	r2, 30	// regs: r2=(*(0x40026054) & ~(0x1 << 0x1e))
   c:	b355      	st.w	r2, (r3, 0x54)	// *(0x40026054) = (*(0x40026054) & ~(0x1 << 0x1e))
   e:	9355      	ld.w	r2, (r3, 0x54)	// regs: r2=*(0x40026054)
  10:	c40257c2 	zext	r2, r2, 30, 0	// regs: r2=zext(*(0x40026054))
  14:	b355      	st.w	r2, (r3, 0x54)	// *(0x40026054) = zext(*(0x40026054))
  16:	783c      	jmp	r15	// return;
  18:	40026000 	.long	0x40026000
  1c:	00000000 	.long	0x00000000	// <.bss.sys_con8_bak>

Disassembly of section .text.switch_ctrl_recover:

00000000 <switch_ctrl_recover>: // arg_bytes: 0
   0:	1063      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   4:	1063      	lrw	r3, 0x40026000	// regs: r3=0x40026000
   6:	b355      	st.w	r2, (r3, 0x54)	// *(0x40026054) = *(0x0)
   8:	783c      	jmp	r15	// return;
   a:	0000      	.short	0x0000
   c:	00000000 	.long	0x00000000	// <.bss.sys_con8_bak>
  10:	6000      	.short	0x6000
  12:	4002      	.short	0x4002

Disassembly of section .text.lmac_bknoise_calc_en:

00000000 <lmac_bknoise_calc_en>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_calc_en>; regs: r0=<ret ah_rfdigicali_bknoise_calc_en@0x2>, r1=<clobbered>
   6:	1490      	pop	r15

Disassembly of section .text.lmac_bknoise_calc_dis:

00000000 <lmac_bknoise_calc_dis>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_calc_dis>; regs: r0=<ret ah_rfdigicali_bknoise_calc_dis@0x2>, r1=<clobbered>
   6:	1490      	pop	r15

Disassembly of section .text.lmac_bknoise_valid_pd_get:

00000000 <lmac_bknoise_valid_pd_get>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_valid_pd_get>; regs: r0=<ret ah_rfdigicali_bknoise_valid_pd_get@0x2>, r1=<clobbered>
   6:	1490      	pop	r15

Disassembly of section .text.lmac_bknoise_valid_pd_clr:

00000000 <lmac_bknoise_valid_pd_clr>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_valid_pd_clr>; regs: r0=<ret ah_rfdigicali_bknoise_valid_pd_clr@0x2>, r1=<clobbered>
   6:	1490      	pop	r15

Disassembly of section .text.lmac_bknoise_get:

00000000 <lmac_bknoise_get>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	3001      	movi	r0, 1	// regs: r0=0x1
   4:	e0000000 	bsr	0x0	// <os_sleep_us>; regs: r0=<ret os_sleep_us@0x4>, r1=<clobbered>
   8:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_get>; regs: r0=<ret ah_rfdigicali_bknoise_get@0x8>, r1=<clobbered>
   c:	6d03      	mov	r4, r0	// regs: r4=<ret ah_rfdigicali_bknoise_get@0x8>
   e:	e900001a 	bez	r0, 0x42	// if (r0 == 0x0) goto loc_42;
  12:	e0000000 	bsr	0x0	// <ah_wphy_agc_info_get>; regs: r0=<ret ah_wphy_agc_info_get@0x12>, r1=<clobbered>
  16:	102d      	lrw	r1, 0x0	// regs: r1=0x0
  18:	6d43      	mov	r5, r0	// regs: r5=<ret ah_wphy_agc_info_get@0x12>
  1a:	5917      	subi	r0, r1, 6	// regs: r0=0xfffffffa
  1c:	e0000000 	bsr	0x0	// <ah_wphy_rx_gain_para_get>; regs: r0=<ret ah_wphy_rx_gain_para_get@0x1c>, r1=<clobbered>
  20:	e405200f 	andi	r0, r5, 15	// regs: r0=(<ret ah_wphy_agc_info_get@0x12> & 0xf)
  24:	3805      	cmphsi	r0, 6
  26:	106a      	lrw	r3, 0x0	// regs: r3=0x0
  28:	6c83      	mov	r2, r0	// regs: r2=(<ret ah_wphy_agc_info_get@0x12> & 0xf)
  2a:	6c4f      	mov	r1, r3	// regs: r1=0x0
  2c:	0c02      	bf	0x30	// if (r0 < 0x6) goto loc_30;
  2e:	3205      	movi	r2, 5	// regs: r2=0x5
loc_30:
  30:	7488      	zextb	r2, r2	// regs: r2=zext8(r2)
  32:	60c8      	addu	r3, r2	// regs: r3=(0x0 + zext8(r2))
  34:	d8034321 	ld.bs	r0, (r3, 0x321)	// regs: r0=*(((0x0 + zext8(r2)) + 0x321))
  38:	d8614327 	ld.bs	r3, (r1, 0x327)	// regs: r3=*(0x327)
  3c:	600c      	addu	r0, r3	// regs: r0=(*(((0x0 + zext8(r2)) + 0x321)) + *(0x327))
  3e:	5c01      	subu	r0, r4, r0	// regs: r0=(<ret ah_rfdigicali_bknoise_get@0x8> - (*(((0x0 + zext8(r2)) + 0x321)) + *(0x327)))
loc_40:
  40:	1492      	pop	r4-r5, r15
loc_42:
  42:	3000      	movi	r0, 0	// regs: r0=0x0
  44:	283b      	subi	r0, 60	// regs: r0=0xffffffc4
  46:	07fd      	br	0x40	// goto loc_40;
  48:	0000      	.short	0x0000	// <ah_lmac+0x327>
  4a:	0000      	.short	0x0000
  4c:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_irq_tx_end:

00000000 <lmac_irq_tx_end>: // arg_bytes: 0
   0:	14d6      	push	r4-r9, r15
   2:	1428      	subi	r14, r14, 32	// regs: r14=(sp - 0x20)
   4:	03ee      	lrw	r7, 0x0	// regs: r7=0x0
   6:	3204      	movi	r2, 4	// regs: r2=0x4
   8:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(0x0)
   a:	038e      	lrw	r4, 0x0	// regs: r4=0x0
   c:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x4
   e:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0xe>, r1=<clobbered>
  12:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x12>, r1=<clobbered>
  16:	d804033c 	ld.b	r0, (r4, 0x33c)	// regs: r0=*(0x33c)
  1a:	d8640340 	ld.b	r3, (r4, 0x340)	// regs: r3=*(0x340)
  1e:	640e      	cmpne	r3, r0
  20:	0c12      	bf	0x44	// if (!T) goto loc_44;
  22:	d8640a4f 	ld.b	r3, (r4, 0xa4f)	// regs: r3=*(0xa4f)
  26:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0xa4f) & 0x8)
  2a:	e923000d 	bnez	r3, 0x44	// if (r3 != 0x0) goto loc_44;
  2e:	d8640892 	ld.b	r3, (r4, 0x892)	// regs: r3=*(0x892)
  32:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x892) & 0x2)
  36:	e9230007 	bnez	r3, 0x44	// if (r3 != 0x0) goto loc_44;
  3a:	e0000000 	bsr	0x0	// <lmac_lo_table_kick>; regs: r0=<ret lmac_lo_table_kick@0x3a>, r1=<clobbered>
  3e:	3034      	movi	r0, 52	// regs: r0=0x34
  40:	e0000000 	bsr	0x0	// <lmac_delay_us>; regs: r0=<ret lmac_delay_us@0x40>, r1=<clobbered>
loc_44:
  44:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(0x0)
  46:	03dc      	lrw	r6, 0x0	// regs: r6=0x0
  48:	93bd      	ld.w	r5, (r3, 0x74)	// regs: r5=*((*(0x0) + 0x74))
  4a:	e4a52003 	andi	r5, r5, 3	// regs: r5=(*((*(0x0) + 0x74)) & 0x3)
  4e:	e905009a 	bez	r5, 0x182	// if (r5 == 0x0) goto loc_182;
  52:	d864226d 	ld.w	r3, (r4, 0x9b4)	// regs: r3=*(0x9b4)
  56:	ec630002 	ori	r3, r3, 2	// regs: r3=(*(0x9b4) | 0x2)
  5a:	dc64226d 	st.w	r3, (r4, 0x9b4)	// *(0x9b4) = (*(0x9b4) | 0x2)
  5e:	d86420ee 	ld.w	r3, (r4, 0x3b8)	// regs: r3=*(0x3b8)
  62:	e4632010 	andi	r3, r3, 16	// regs: r3=(*(0x3b8) & 0x10)
  66:	e903002a 	bez	r3, 0xba	// if (r3 == 0x0) goto loc_ba;
  6a:	d8a42265 	ld.w	r5, (r4, 0x994)	// regs: r5=*(0x994)
  6e:	e0000000 	bsr	0x0	// <ah_wphy_err_code_get>; regs: r0=<ret ah_wphy_err_code_get@0x6e>, r1=<clobbered>
  72:	9740      	ld.w	r2, (r7, 0x0)	// regs: r2=*(0x0)
  74:	927d      	ld.w	r3, (r2, 0x74)	// regs: r3=*((*(0x0) + 0x74))
  76:	9239      	ld.w	r1, (r2, 0x64)	// regs: r1=*((*(0x0) + 0x64))
  78:	d982201a 	ld.w	r12, (r2, 0x68)	// regs: r12=*((*(0x0) + 0x68))
  7c:	d9a2201b 	ld.w	r13, (r2, 0x6c)	// regs: r13=*((*(0x0) + 0x6c))
  80:	d902201c 	ld.w	r8, (r2, 0x70)	// regs: r8=*((*(0x0) + 0x70))
  84:	9641      	ld.w	r2, (r6, 0x4)	// regs: r2=*(0x4)
  86:	d9222003 	ld.w	r9, (r2, 0xc)	// regs: r9=*((*(0x4) + 0xc))
  8a:	dd2e2007 	st.w	r9, (r14, 0x1c)	// local_4 = *((*(0x4) + 0xc))
  8e:	d9222002 	ld.w	r9, (r2, 0x8)	// regs: r9=*((*(0x4) + 0x8))
  92:	dd2e2006 	st.w	r9, (r14, 0x18)	// local_8 = *((*(0x4) + 0x8))
  96:	d9222001 	ld.w	r9, (r2, 0x4)	// regs: r9=*((*(0x4) + 0x4))
  9a:	dd2e2005 	st.w	r9, (r14, 0x14)	// local_c = *((*(0x4) + 0x4))
  9e:	9240      	ld.w	r2, (r2, 0x0)	// regs: r2=*(*(0x4))
  a0:	b844      	st.w	r2, (r14, 0x10)	// local_10 = *(*(0x4))
  a2:	b820      	st.w	r1, (r14, 0x0)	// local_20 = *((*(0x0) + 0x64))
  a4:	6c83      	mov	r2, r0	// regs: r2=<ret ah_wphy_err_code_get@0x6e>
  a6:	dd0e2003 	st.w	r8, (r14, 0xc)	// local_14 = *((*(0x0) + 0x70))
  aa:	ddae2002 	st.w	r13, (r14, 0x8)	// local_18 = *((*(0x0) + 0x6c))
  ae:	dd8e2001 	st.w	r12, (r14, 0x4)	// local_1c = *((*(0x0) + 0x68))
  b2:	6c57      	mov	r1, r5	// regs: r1=*(0x994)
  b4:	1308      	lrw	r0, 0x0	// regs: r0=0x0
  b6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xb6>, r1=<clobbered>
loc_ba:
  ba:	9740      	ld.w	r2, (r7, 0x0)	// regs: r2=*(0x0)
  bc:	d80411b1 	ld.h	r0, (r4, 0x362)	// regs: r0=*(0x362)
  c0:	927d      	ld.w	r3, (r2, 0x74)	// regs: r3=*((*(0x0) + 0x74))
  c2:	ec630003 	ori	r3, r3, 3	// regs: r3=(*((*(0x0) + 0x74)) | 0x3)
  c6:	b27d      	st.w	r3, (r2, 0x74)	// *((*(0x0) + 0x74)) = (*((*(0x0) + 0x74)) | 0x3)
  c8:	3500      	movi	r5, 0	// regs: r5=0x0
  ca:	c4805560 	zext	r0, r0, 11, 4	// regs: r0=zext(*(0x362))
  ce:	dca42294 	st.w	r5, (r4, 0xa50)	// *(0xa50) = 0x0
  d2:	dca42266 	st.w	r5, (r4, 0x998)	// *(0x998) = 0x0
  d6:	e0000000 	bsr	0x0	// <lmac_rx_gain_cfg>; regs: r0=<ret lmac_rx_gain_cfg@0xd6>, r1=<clobbered>
loc_da:
  da:	3300      	movi	r3, 0	// regs: r3=0x0
  dc:	dc642265 	st.w	r3, (r4, 0x994)	// *(0x994) = 0x0
  e0:	e0000000 	bsr	0x0	// <update_rx_buff_addr>; regs: r0=<ret update_rx_buff_addr@0xe0>, r1=<clobbered>
  e4:	e0000000 	bsr	0x0	// <lmac_tdma_start>; regs: r0=<ret lmac_tdma_start@0xe4>, r1=<clobbered>
  e8:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  ec:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x9e2) & 0x8)
  f0:	e903000b 	bez	r3, 0x106	// if (r3 == 0x0) goto loc_106;
  f4:	d80414f1 	ld.h	r0, (r4, 0x9e2)	// regs: r0=*(0x9e2)
  f8:	33fa      	movi	r3, 250	// regs: r3=0xfa
  fa:	c4c055a0 	zext	r0, r0, 13, 6	// regs: r0=zext(*(0x9e2))
  fe:	4362      	lsli	r3, r3, 2	// regs: r3=0x3e8
 100:	7c0c      	mult	r0, r3	// regs: r0=(zext(*(0x9e2)) * 0x3e8)
 102:	e0000000 	bsr	0x0	// <lmac_set_basic_nav>; regs: r0=<ret lmac_set_basic_nav@0x102>, r1=<clobbered>
loc_106:
 106:	6c17      	mov	r0, r5	// regs: r0=r5
 108:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x108>, r1=<clobbered>
 10c:	d82612af 	ld.h	r1, (r6, 0x55e)	// regs: r1=*(0x55e)
 110:	e9010014 	bez	r1, 0x138	// if (r1 == 0x0) goto loc_138;
 114:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(0x0)
 116:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
 11a:	ec422000 	ori	r2, r2, 8192	// regs: r2=(*((*(0x0) + 0xcc)) | 0x2000)
 11e:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x2000)
 122:	3280      	movi	r2, 128	// regs: r2=0x80
 124:	424c      	lsli	r2, r2, 12	// regs: r2=0x80000
 126:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x80000
 128:	dc232037 	st.w	r1, (r3, 0xdc)	// *((*(0x0) + 0xdc)) = *(0x55e)
 12c:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
 130:	ec421000 	ori	r2, r2, 4096	// regs: r2=(*((*(0x0) + 0xcc)) | 0x1000)
 134:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x1000)
loc_138:
 138:	d8642266 	ld.w	r3, (r4, 0x998)	// regs: r3=*(0x998)
 13c:	3b41      	cmpnei	r3, 1
 13e:	0804      	bt	0x146	// if (r3 != 0x1) goto loc_146;
 140:	3300      	movi	r3, 0	// regs: r3=0x0
 142:	dc6612af 	st.h	r3, (r6, 0x55e)	// *(0x55e) = 0x0
loc_146:
 146:	d864090f 	ld.b	r3, (r4, 0x90f)	// regs: r3=*(0x90f)
 14a:	d844090e 	ld.b	r2, (r4, 0x90e)	// regs: r2=*(0x90e)
 14e:	4368      	lsli	r3, r3, 8	// regs: r3=(*(0x90f) << 0x8)
 150:	6cc8      	or	r3, r2	// regs: r3=((*(0x90f) << 0x8) | *(0x90e))
 152:	ea02dfff 	movi	r2, 57343	// regs: r2=0xdfff
 156:	68c8      	and	r3, r2	// regs: r3=(((*(0x90f) << 0x8) | *(0x90e)) & 0xdfff)
 158:	dc64090e 	st.b	r3, (r4, 0x90e)	// *(0x90e) = (((*(0x90f) << 0x8) | *(0x90e)) & 0xdfff)
 15c:	4b68      	lsri	r3, r3, 8	// regs: r3=((((*(0x90f) << 0x8) | *(0x90e)) & 0xdfff) >> 0x8)
 15e:	dc64090f 	st.b	r3, (r4, 0x90f)	// *(0x90f) = ((((*(0x90f) << 0x8) | *(0x90e)) & 0xdfff) >> 0x8)
 162:	d864091f 	ld.b	r3, (r4, 0x91f)	// regs: r3=*(0x91f)
 166:	d844091e 	ld.b	r2, (r4, 0x91e)	// regs: r2=*(0x91e)
 16a:	4368      	lsli	r3, r3, 8	// regs: r3=(*(0x91f) << 0x8)
 16c:	6cc8      	or	r3, r2	// regs: r3=((*(0x91f) << 0x8) | *(0x91e))
 16e:	ea02dfff 	movi	r2, 57343	// regs: r2=0xdfff
 172:	68c8      	and	r3, r2	// regs: r3=(((*(0x91f) << 0x8) | *(0x91e)) & 0xdfff)
 174:	dc64091e 	st.b	r3, (r4, 0x91e)	// *(0x91e) = (((*(0x91f) << 0x8) | *(0x91e)) & 0xdfff)
 178:	4b68      	lsri	r3, r3, 8	// regs: r3=((((*(0x91f) << 0x8) | *(0x91e)) & 0xdfff) >> 0x8)
 17a:	dc64091f 	st.b	r3, (r4, 0x91f)	// *(0x91f) = ((((*(0x91f) << 0x8) | *(0x91e)) & 0xdfff) >> 0x8)
 17e:	1408      	addi	r14, r14, 32	// regs: r14=((sp - 0x20) + 0x20)
 180:	1496      	pop	r4-r9, r15
loc_182:
 182:	9355      	ld.w	r2, (r3, 0x54)	// regs: r2=*((*(0x0) + 0x54))
 184:	dc462156 	st.w	r2, (r6, 0x558)	// *(0x558) = *((*(0x0) + 0x54))
 188:	9359      	ld.w	r2, (r3, 0x64)	// regs: r2=*((*(0x0) + 0x64))
 18a:	d826055c 	ld.b	r1, (r6, 0x55c)	// regs: r1=*(0x55c)
 18e:	4a50      	lsri	r2, r2, 16	// regs: r2=(*((*(0x0) + 0x64)) >> 0x10)
 190:	c4225cc0 	ins	r1, r2, 6, 0
 194:	dc26055c 	st.b	r1, (r6, 0x55c)	// *(0x55c) = *(0x55c)
 198:	9339      	ld.w	r1, (r3, 0x64)	// regs: r1=*((*(0x0) + 0x64))
 19a:	d84612ae 	ld.h	r2, (r6, 0x55c)	// regs: r2=*(0x55c)
 19e:	c4415c47 	ins	r2, r1, 9, 7
 1a2:	dc4612ae 	st.h	r2, (r6, 0x55c)	// *(0x55c) = *(0x55c)
 1a6:	9359      	ld.w	r2, (r3, 0x64)	// regs: r2=*((*(0x0) + 0x64))
 1a8:	d826055d 	ld.b	r1, (r6, 0x55d)	// regs: r1=*(0x55d)
 1ac:	4a46      	lsri	r2, r2, 6	// regs: r2=(*((*(0x0) + 0x64)) >> 0x6)
 1ae:	c4225c23 	ins	r1, r2, 4, 3
 1b2:	dc26055d 	st.b	r1, (r6, 0x55d)	// *(0x55d) = *(0x55d)
 1b6:	9379      	ld.w	r3, (r3, 0x64)	// regs: r3=*((*(0x0) + 0x64))
 1b8:	4b6c      	lsri	r3, r3, 12	// regs: r3=(*((*(0x0) + 0x64)) >> 0xc)
 1ba:	d846055d 	ld.b	r2, (r6, 0x55d)	// regs: r2=*(0x55d)
 1be:	c4435c45 	ins	r2, r3, 7, 5
 1c2:	d8642266 	ld.w	r3, (r4, 0x998)	// regs: r3=*(0x998)
 1c6:	3b06      	cmphsi	r3, 7
 1c8:	dc46055d 	st.b	r2, (r6, 0x55d)	// *(0x55d) = *(0x55d)
 1cc:	0b87      	bt	0xda	// if (r3 >= 0x7) goto loc_da;
 1ce:	3501      	movi	r5, 1	// regs: r5=0x1
 1d0:	714c      	lsl	r5, r3
 1d2:	e465206e 	andi	r3, r5, 110	// regs: r3=(0x1 & 0x6e)
 1d6:	e9230033 	bnez	r3, 0x23c	// if (r3 != 0x0) goto loc_23c;
 1da:	e4a52010 	andi	r5, r5, 16	// regs: r5=(0x1 & 0x10)
 1de:	e905ff7e 	bez	r5, 0xda	// if (r5 == 0x0) goto loc_da;
 1e2:	d864037c 	ld.b	r3, (r4, 0x37c)	// regs: r3=*(0x37c)
 1e6:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x37c) & 0x1)
 1ea:	e903000b 	bez	r3, 0x200	// if (r3 == 0x0) goto loc_200;
 1ee:	d8040379 	ld.b	r0, (r4, 0x379)	// regs: r0=*(0x379)
 1f2:	e0000000 	bsr	0x0	// <lmac_lo_table_kick>; regs: r0=<ret lmac_lo_table_kick@0x1f2>, r1=<clobbered>
 1f6:	d86414ec 	ld.h	r3, (r4, 0x9d8)	// regs: r3=*(0x9d8)
 1fa:	2300      	addi	r3, 1	// regs: r3=(*(0x9d8) + 0x1)
 1fc:	dc6414ec 	st.h	r3, (r4, 0x9d8)	// *(0x9d8) = (*(0x9d8) + 0x1)
loc_200:
 200:	e0000000 	bsr	0x0	// <switch_ctrl_normal_mode> // arg_bytes: 0; regs: r0=<ret switch_ctrl_normal_mode@0x200>, r1=<clobbered>
 204:	d8640361 	ld.b	r3, (r4, 0x361)	// regs: r3=*(0x361)
 208:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x361) & 0x8)
 20c:	e903000a 	bez	r3, 0x220	// if (r3 == 0x0) goto loc_220;
 210:	3005      	movi	r0, 5	// regs: r0=0x5
 212:	d8240308 	ld.b	r1, (r4, 0x308)	// regs: r1=*(0x308)
 216:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_gain>; regs: r0=<ret ah_rfdigicali_config_rx_gain@0x216>, r1=<clobbered>
 21a:	3005      	movi	r0, 5	// regs: r0=0x5
 21c:	e0000000 	bsr	0x0	// <ah_wphy_rx_gain_stage_cfg>; regs: r0=<ret ah_wphy_rx_gain_stage_cfg@0x21c>, r1=<clobbered>
loc_220:
 220:	30c8      	movi	r0, 200	// regs: r0=0xc8
 222:	3101      	movi	r1, 1	// regs: r1=0x1
 224:	4003      	lsli	r0, r0, 3	// regs: r0=0x640
 226:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_hw_bknoise>; regs: r0=<ret ah_rfdigicali_config_hw_bknoise@0x226>, r1=<clobbered>
 22a:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_valid_pd_clr>; regs: r0=<ret ah_rfdigicali_bknoise_valid_pd_clr@0x22a>, r1=<clobbered>
 22e:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_calc_en>; regs: r0=<ret ah_rfdigicali_bknoise_calc_en@0x22e>, r1=<clobbered>
 232:	3050      	movi	r0, 80	// regs: r0=0x50
 234:	e0000000 	bsr	0x0	// <lmac_wait_bgscan>; regs: r0=<ret lmac_wait_bgscan@0x234>, r1=<clobbered>
 238:	3500      	movi	r5, 0	// regs: r5=0x0
 23a:	0750      	br	0xda	// goto loc_da;
loc_23c:
 23c:	30e0      	movi	r0, 224	// regs: r0=0xe0
 23e:	4001      	lsli	r0, r0, 1	// regs: r0=0x1c0
 240:	e0000000 	bsr	0x0	// <lmac_wait_sync>; regs: r0=<ret lmac_wait_sync@0x240>, r1=<clobbered>
 244:	6d43      	mov	r5, r0	// regs: r5=<ret lmac_wait_sync@0x240>
 246:	074a      	br	0xda	// goto loc_da;
 248:	00000000 	.long	0x00000000	// <LMAC>
 24c:	00000000 	.long	0x00000000	// <ah_lmac>
 250:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
 254:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_tx_end.str1.1>

Disassembly of section .text.lmac_spec_cca_cfg:

00000000 <lmac_spec_cca_cfg>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	1423      	subi	r14, r14, 12	// regs: r14=(sp - 0xc)
   4:	1161      	lrw	r3, 0x0	// regs: r3=0x0
   6:	3100      	movi	r1, 0	// regs: r1=0x0
   8:	d8430361 	ld.b	r2, (r3, 0x361)	// regs: r2=*(0x361)
   c:	3841      	cmpnei	r0, 1
   e:	c4415c02 	ins	r2, r1, 2, 2
  12:	dc430361 	st.b	r2, (r3, 0x361)	// *(0x361) = *(0x361)
  16:	0c0c      	bf	0x2e	// if (r0 == 0x1) goto loc_2e;
  18:	d8630308 	ld.b	r3, (r3, 0x308)	// regs: r3=*(0x308)
  1c:	3b43      	cmpnei	r3, 3
  1e:	0c2f      	bf	0x7c	// if (r3 == 0x3) goto loc_7c;
  20:	6c87      	mov	r2, r1	// regs: r2=0x0
  22:	6cc7      	mov	r3, r1	// regs: r3=0x0
  24:	2a51      	subi	r2, 82	// regs: r2=0xffffffae
  26:	2b58      	subi	r3, 89	// regs: r3=0xffffffa7
  28:	2955      	subi	r1, 86	// regs: r1=0xffffffaa
loc_2a:
  2a:	6c0f      	mov	r0, r3	// regs: r0=r3
  2c:	0409      	br	0x3e	// goto loc_3e;
loc_2e:
  2e:	3200      	movi	r2, 0	// regs: r2=0x0
  30:	3300      	movi	r3, 0	// regs: r3=0x0
  32:	3100      	movi	r1, 0	// regs: r1=0x0
  34:	3000      	movi	r0, 0	// regs: r0=0x0
  36:	2a55      	subi	r2, 86	// regs: r2=0xffffffaa
  38:	2b5b      	subi	r3, 92	// regs: r3=0xffffffa4
  3a:	2958      	subi	r1, 89	// regs: r1=0xffffffa7
  3c:	2861      	subi	r0, 98	// regs: r0=0xffffff9e
loc_3e:
  3e:	dc6e0001 	st.b	r3, (r14, 0x1)	// local_b = r3
  42:	3300      	movi	r3, 0	// regs: r3=0x0
  44:	2b4a      	subi	r3, 75	// regs: r3=0xffffffb5
  46:	dc6e0006 	st.b	r3, (r14, 0x6)	// local_6 = 0xffffffb5
  4a:	3300      	movi	r3, 0	// regs: r3=0x0
  4c:	2b47      	subi	r3, 72	// regs: r3=0xffffffb8
  4e:	dc6e0007 	st.b	r3, (r14, 0x7)	// local_5 = 0xffffffb8
  52:	dc6e0008 	st.b	r3, (r14, 0x8)	// local_4 = 0xffffffb8
  56:	3300      	movi	r3, 0	// regs: r3=0x0
  58:	dc0e0000 	st.b	r0, (r14, 0x0)	// local_c = r0
  5c:	2b44      	subi	r3, 69	// regs: r3=0xffffffbb
  5e:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0xc)
  60:	dc2e0002 	st.b	r1, (r14, 0x2)	// local_a = r1
  64:	dc2e0003 	st.b	r1, (r14, 0x3)	// local_9 = r1
  68:	dc4e0004 	st.b	r2, (r14, 0x4)	// local_8 = r2
  6c:	dc4e0005 	st.b	r2, (r14, 0x5)	// local_7 = r2
  70:	dc6e0009 	st.b	r3, (r14, 0x9)	// local_3 = 0xffffffbb
  74:	e0000000 	bsr	0x0	// <ah_wphy_cca_th_cfg>; regs: r0=<ret ah_wphy_cca_th_cfg@0x74>, r1=<clobbered>
  78:	1403      	addi	r14, r14, 12	// regs: r14=((sp - 0xc) + 0xc)
  7a:	1490      	pop	r15
loc_7c:
  7c:	3300      	movi	r3, 0	// regs: r3=0x0
  7e:	3200      	movi	r2, 0	// regs: r2=0x0
  80:	2b55      	subi	r3, 86	// regs: r3=0xffffffaa
  82:	2a51      	subi	r2, 82	// regs: r2=0xffffffae
  84:	6c4f      	mov	r1, r3	// regs: r1=0xffffffaa
  86:	07d2      	br	0x2a	// goto loc_2a;
  88:	0000      	.short	0x0000	// <ah_lmac>
  8a:	0000      	.short	0x0000

Disassembly of section .text.lmac_adjust_cca_threshold:

00000000 <lmac_adjust_cca_threshold>: // arg_bytes: 8
   0:	14d2      	push	r4-r5, r15
   2:	1423      	subi	r14, r14, 12	// regs: r14=(sp - 0xc)
   4:	3300      	movi	r3, 0	// regs: r3=0x0
   6:	2b59      	subi	r3, 90	// regs: r3=0xffffffa6
   8:	64c1      	cmplt	r0, r3
   a:	6c83      	mov	r2, r0	// regs: r2=<arg0>
   c:	0c02      	bf	0x10	// if (!T) goto loc_10;
   e:	6c8f      	mov	r2, r3	// regs: r2=0xffffffa6
loc_10:
  10:	118c      	lrw	r4, 0x0	// regs: r4=0x0
  12:	74ca      	sextb	r3, r2	// regs: r3=sext8(r2)
  14:	d8444329 	ld.bs	r2, (r4, 0x329)	// regs: r2=*(0x329)
  18:	e9020005 	bez	r2, 0x22	// if (r2 == 0x0) goto loc_22;
  1c:	648d      	cmplt	r3, r2
  1e:	c4620c20 	incf	r3, r2, 0
loc_22:
  22:	d8440308 	ld.b	r2, (r4, 0x308)	// regs: r2=*(0x308)
  26:	3a42      	cmpnei	r2, 2
  28:	0c47      	bf	0xb6	// if (r2 == 0x2) goto loc_b6;
  2a:	3a43      	cmpnei	r2, 3
  2c:	0c48      	bf	0xbc	// if (r2 == 0x3) goto loc_bc;
loc_2e:
  2e:	d8440328 	ld.b	r2, (r4, 0x328)	// regs: r2=*(0x328)
  32:	608c      	addu	r2, r3	// regs: r2=(*(0x328) + sext8(r2))
  34:	7488      	zextb	r2, r2	// regs: r2=zext8((*(0x328) + sext8(r2)))
  36:	e462000c 	addi	r3, r2, 13	// regs: r3=(zext8((*(0x328) + sext8(r2))) + 0xd)
  3a:	dc6e0000 	st.b	r3, (r14, 0x0)	// local_c = (zext8((*(0x328) + sext8(r2))) + 0xd)
  3e:	e4620009 	addi	r3, r2, 10	// regs: r3=(zext8((*(0x328) + sext8(r2))) + 0xa)
  42:	dc6e0001 	st.b	r3, (r14, 0x1)	// local_b = (zext8((*(0x328) + sext8(r2))) + 0xa)
  46:	e4a20011 	addi	r5, r2, 18	// regs: r5=(zext8((*(0x328) + sext8(r2))) + 0x12)
  4a:	e4620010 	addi	r3, r2, 17	// regs: r3=(zext8((*(0x328) + sext8(r2))) + 0x11)
  4e:	74ce      	sextb	r3, r3	// regs: r3=sext8((zext8((*(0x328) + sext8(r2))) + 0x11))
  50:	e422000d 	addi	r1, r2, 14	// regs: r1=(zext8((*(0x328) + sext8(r2))) + 0xe)
  54:	7554      	zextb	r5, r5	// regs: r5=zext8((zext8((*(0x328) + sext8(r2))) + 0x12))
  56:	2214      	addi	r2, 21	// regs: r2=(zext8((*(0x328) + sext8(r2))) + 0x15)
  58:	7446      	sextb	r1, r1	// regs: r1=sext8((zext8((*(0x328) + sext8(r2))) + 0xe))
  5a:	748a      	sextb	r2, r2	// regs: r2=sext8((zext8((*(0x328) + sext8(r2))) + 0x15))
  5c:	dc6e0002 	st.b	r3, (r14, 0x2)	// local_a = sext8((zext8((*(0x328) + sext8(r2))) + 0x11))
  60:	dc6e0005 	st.b	r3, (r14, 0x5)	// local_7 = sext8((zext8((*(0x328) + sext8(r2))) + 0x11))
  64:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0xc)
  66:	74d6      	sextb	r3, r5	// regs: r3=sext8(zext8((zext8((*(0x328) + sext8(r2))) + 0x12)))
  68:	dc6e0007 	st.b	r3, (r14, 0x7)	// local_5 = sext8(zext8((zext8((*(0x328) + sext8(r2))) + 0x12)))
  6c:	dc6e0008 	st.b	r3, (r14, 0x8)	// local_4 = sext8(zext8((zext8((*(0x328) + sext8(r2))) + 0x12)))
  70:	dc2e0003 	st.b	r1, (r14, 0x3)	// local_9 = sext8((zext8((*(0x328) + sext8(r2))) + 0xe))
  74:	dc2e0004 	st.b	r1, (r14, 0x4)	// local_8 = sext8((zext8((*(0x328) + sext8(r2))) + 0xe))
  78:	dc4e0006 	st.b	r2, (r14, 0x6)	// local_6 = sext8((zext8((*(0x328) + sext8(r2))) + 0x15))
  7c:	dc4e0009 	st.b	r2, (r14, 0x9)	// local_3 = sext8((zext8((*(0x328) + sext8(r2))) + 0x15))
  80:	e0000000 	bsr	0x0	// <ah_wphy_cca_th_cfg>; regs: r0=<ret ah_wphy_cca_th_cfg@0x80>, r1=<clobbered>
  84:	d864037e 	ld.b	r3, (r4, 0x37e)	// regs: r3=*(0x37e)
  88:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x37e) & 0x8)
  8c:	e9030013 	bez	r3, 0xb2	// if (r3 == 0x0) goto loc_b2;
  90:	d86411bf 	ld.h	r3, (r4, 0x37e)	// regs: r3=*(0x37e)
  94:	c4835523 	zext	r3, r3, 9, 4	// regs: r3=zext(*(0x37e))
  98:	60d4      	addu	r3, r5	// regs: r3=(zext(*(0x37e)) + zext8((zext8((*(0x328) + sext8(r2))) + 0x12)))
  9a:	d8241334 	ld.h	r1, (r4, 0x668)	// regs: r1=*(0x668)
  9e:	d8040668 	ld.b	r0, (r4, 0x668)	// regs: r0=*(0x668)
  a2:	74ce      	sextb	r3, r3	// regs: r3=sext8((zext(*(0x37e)) + zext8((zext8((*(0x328) + sext8(r2))) + 0x12))))
  a4:	3200      	movi	r2, 0	// regs: r2=0x0
  a6:	c4615561 	zext	r1, r1, 11, 3	// regs: r1=zext(*(0x668))
  aa:	e4002007 	andi	r0, r0, 7	// regs: r0=(*(0x668) & 0x7)
  ae:	e0000000 	bsr	0x0	// <ah_wphy_obss_para_cfg>; regs: r0=<ret ah_wphy_obss_para_cfg@0xae>, r1=<clobbered>
loc_b2:
  b2:	1403      	addi	r14, r14, 12	// regs: r14=((sp - 0xc) + 0xc)
  b4:	1492      	pop	r4-r5, r15
loc_b6:
  b6:	5b4b      	subi	r2, r3, 3	// regs: r2=(sext8(r2) - 0x3)
loc_b8:
  b8:	74ca      	sextb	r3, r2	// regs: r3=sext8(r2)
  ba:	07ba      	br	0x2e	// goto loc_2e;
loc_bc:
  bc:	5b57      	subi	r2, r3, 6	// regs: r2=(sext8(r2) - 0x6)
  be:	07fd      	br	0xb8	// goto loc_b8;
  c0:	0000      	.short	0x0000	// <ah_lmac>
  c2:	0000      	.short	0x0000

Disassembly of section .text.lmac_irq_ac_pd:

00000000 <lmac_irq_ac_pd>: // arg_bytes: 4
   0:	14d8      	push	r4-r11, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	01c8      	lrw	r6, 0x0	// regs: r6=0x0
   6:	3280      	movi	r2, 128	// regs: r2=0x80
   8:	9660      	ld.w	r3, (r6, 0x0)	// regs: r3=*(0x0)
   a:	0188      	lrw	r4, 0x0	// regs: r4=0x0
   c:	ea8800d7 	lrw	r8, 0x0	// regs: r8=0x0
  10:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x80
  12:	e0000000 	bsr	0x0	// <lmac_reorder_tx_agglist> // arg_bytes: 0; regs: r0=<ret lmac_reorder_tx_agglist@0x12>, r1=<clobbered>
  16:	e0000000 	bsr	0x0	// <lmac_check_tx_queue_empty> // arg_bytes: 4; regs: r0=<ret lmac_check_tx_queue_empty@0x16>, r1=<clobbered>
  1a:	3300      	movi	r3, 0	// regs: r3=0x0
  1c:	dc642294 	st.w	r3, (r4, 0xa50)	// *(0xa50) = 0x0
  20:	dc642265 	st.w	r3, (r4, 0x994)	// *(0x994) = 0x0
  24:	dc642266 	st.w	r3, (r4, 0x998)	// *(0x998) = 0x0
  28:	d86409dd 	ld.b	r3, (r4, 0x9dd)	// regs: r3=*(0x9dd)
  2c:	e463200f 	andi	r3, r3, 15	// regs: r3=(*(0x9dd) & 0xf)
  30:	e903013b 	bez	r3, 0x2a6	// if (r3 == 0x0) goto loc_2a6;
  34:	d868000a 	ld.b	r3, (r8, 0xa)	// regs: r3=*(0xa)
  38:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0xa) & 0x1)
  3c:	e9230006 	bnez	r3, 0x48	// if (r3 != 0x0) goto loc_48;
  40:	d8642267 	ld.w	r3, (r4, 0x99c)	// regs: r3=*(0x99c)
  44:	3b42      	cmpnei	r3, 2
  46:	0930      	bt	0x2a6	// if (r3 != 0x2) goto loc_2a6;
loc_48:
  48:	01b6      	lrw	r5, 0x0	// regs: r5=0x0
  4a:	9502      	ld.w	r0, (r5, 0x8)	// regs: r0=*(0x8)
  4c:	e0000000 	bsr	0x0	// <lmac_beacon_build_s1gbeacon> // arg_bytes: 4; regs: r0=<ret lmac_beacon_build_s1gbeacon@0x4c>, r1=<clobbered>
  50:	9562      	ld.w	r3, (r5, 0x8)	// regs: r3=*(0x8)
  52:	8bd4      	ld.h	r6, (r3, 0x28)	// regs: r6=*((*(0x8) + 0x28))
  54:	e4662003 	andi	r3, r6, 3	// regs: r3=(*((*(0x8) + 0x28)) & 0x3)
  58:	2603      	addi	r6, 4	// regs: r6=(*((*(0x8) + 0x28)) + 0x4)
  5a:	e9030005 	bez	r3, 0x64	// if (r3 == 0x0) goto loc_64;
  5e:	3e80      	bclri	r6, 0	// regs: r6=((*((*(0x8) + 0x28)) + 0x4) & ~(0x1 << 0x0))
  60:	3e81      	bclri	r6, 1	// regs: r6=(((*((*(0x8) + 0x28)) + 0x4) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
  62:	2603      	addi	r6, 4	// regs: r6=((((*((*(0x8) + 0x28)) + 0x4) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)) + 0x4)
loc_64:
  64:	d8e4036d 	ld.b	r7, (r4, 0x36d)	// regs: r7=*(0x36d)
  68:	d82411b6 	ld.h	r1, (r4, 0x36c)	// regs: r1=*(0x36c)
  6c:	e4e7200c 	andi	r7, r7, 12	// regs: r7=(*(0x36d) & 0xc)
  70:	c4a15521 	zext	r1, r1, 9, 5	// regs: r1=zext(*(0x36c))
  74:	d8650634 	ld.b	r3, (r5, 0x634)	// regs: r3=*(0x634)
  78:	ea0c0000 	movi	r12, 0	// regs: r12=0x0
  7c:	3f40      	cmpnei	r7, 0
  7e:	c42c0c40 	inct	r1, r12, 0
  82:	e46320df 	andi	r3, r3, 223	// regs: r3=(*(0x634) & 0xdf)
  86:	d8040308 	ld.b	r0, (r4, 0x308)	// regs: r0=*(0x308)
  8a:	ea0d0001 	movi	r13, 1	// regs: r13=0x1
  8e:	c4615c80 	ins	r3, r1, 4, 0
  92:	d8450635 	ld.b	r2, (r5, 0x635)	// regs: r2=*(0x635)
  96:	d824034a 	ld.b	r1, (r4, 0x34a)	// regs: r1=*(0x34a)
  9a:	c4405c20 	ins	r2, r0, 1, 0
  9e:	6874      	and	r1, r13	// regs: r1=(*(0x34a) & 0x1)
  a0:	d8050636 	ld.b	r0, (r5, 0x636)	// regs: r0=*(0x636)
  a4:	c40d5cc0 	ins	r0, r13, 6, 0
  a8:	7488      	zextb	r2, r2	// regs: r2=zext8(*(0x635))
  aa:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(0x634) & 0xdf))
  ac:	7400      	zextb	r0, r0	// regs: r0=zext8(*(0x636))
  ae:	e901003d 	bez	r1, 0x128	// if (r1 == 0x0) goto loc_128;
  b2:	c46c5c26 	ins	r3, r12, 7, 6
  b6:	dc650634 	st.b	r3, (r5, 0x634)	// *(0x634) = zext8((*(0x634) & 0xdf))
  ba:	6cc3      	mov	r3, r0	// regs: r3=zext8(*(0x636))
  bc:	c44c5c22 	ins	r2, r12, 3, 2
  c0:	c46c5c07 	ins	r3, r12, 7, 7
  c4:	dc450635 	st.b	r2, (r5, 0x635)	// *(0x635) = zext8(*(0x635))
  c8:	dc650636 	st.b	r3, (r5, 0x636)	// *(0x636) = zext8(*(0x636))
  cc:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(zext8(*(0x635)))
  d0:	3103      	movi	r1, 3	// regs: r1=0x3
  d2:	6c1b      	mov	r0, r6	// regs: r0=r6
  d4:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0xd4>, r1=<clobbered>
  d8:	dc05218e 	st.w	r0, (r5, 0x638)	// *(0x638) = <ret calc_symbol_len@0xd4>
  dc:	370e      	movi	r7, 14	// regs: r7=0xe
loc_de:
  de:	d8640875 	ld.b	r3, (r4, 0x875)	// regs: r3=*(0x875)
  e2:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x875) & 0x2)
  e6:	e9030037 	bez	r3, 0x154	// if (r3 == 0x0) goto loc_154;
  ea:	d8640867 	ld.b	r3, (r4, 0x867)	// regs: r3=*(0x867)
  ee:	3b43      	cmpnei	r3, 3
  f0:	0832      	bt	0x154	// if (r3 != 0x3) goto loc_154;
  f2:	d8650635 	ld.b	r3, (r5, 0x635)	// regs: r3=*(0x635)
  f6:	3200      	movi	r2, 0	// regs: r2=0x0
loc_f8:
  f8:	c4625c64 	ins	r3, r2, 7, 4
  fc:	dc650635 	st.b	r3, (r5, 0x635)	// *(0x635) = *(0x635)
 100:	3200      	movi	r2, 0	// regs: r2=0x0
 102:	3300      	movi	r3, 0	// regs: r3=0x0
 104:	dc45218f 	st.w	r2, (r5, 0x63c)	// *(0x63c) = 0x0
 108:	dc652190 	st.w	r3, (r5, 0x640)	// *(0x640) = 0x0
 10c:	d8650635 	ld.b	r3, (r5, 0x635)	// regs: r3=*(0x635)
 110:	c4435462 	zext	r2, r3, 3, 2	// regs: r2=zext(*(0x635))
 114:	3a41      	cmpnei	r2, 1
 116:	0c74      	bf	0x1fe	// if (r2 == 0x1) goto loc_1fe;
 118:	3a40      	cmpnei	r2, 0
 11a:	0c21      	bf	0x15c	// if (r2 == 0x0) goto loc_15c;
 11c:	3a42      	cmpnei	r2, 2
 11e:	0c9b      	bf	0x254	// if (r2 == 0x2) goto loc_254;
 120:	030b      	lrw	r0, 0x0	// regs: r0=0x0
 122:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x122>, r1=<clobbered>
 126:	0448      	br	0x1b6	// goto loc_1b6;
loc_128:
 128:	c4615c26 	ins	r3, r1, 7, 6
 12c:	dc650634 	st.b	r3, (r5, 0x634)	// *(0x634) = zext8((*(0x634) & 0xdf))
 130:	6cc3      	mov	r3, r0	// regs: r3=zext8(*(0x636))
 132:	c44d5c22 	ins	r2, r13, 3, 2
 136:	c4615c07 	ins	r3, r1, 7, 7
 13a:	dc450635 	st.b	r2, (r5, 0x635)	// *(0x635) = zext8(*(0x635))
 13e:	dc650636 	st.b	r3, (r5, 0x636)	// *(0x636) = zext8(*(0x636))
 142:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(zext8(*(0x635)))
 146:	6c1b      	mov	r0, r6	// regs: r0=r6
 148:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0x148>, r1=<clobbered>
 14c:	dc05218e 	st.w	r0, (r5, 0x638)	// *(0x638) = <ret calc_symbol_len@0x148>
 150:	3706      	movi	r7, 6	// regs: r7=0x6
 152:	07c6      	br	0xde	// goto loc_de;
loc_154:
 154:	d8650635 	ld.b	r3, (r5, 0x635)	// regs: r3=*(0x635)
 158:	3202      	movi	r2, 2	// regs: r2=0x2
 15a:	07cf      	br	0xf8	// goto loc_f8;
loc_15c:
 15c:	d825063c 	ld.b	r1, (r5, 0x63c)	// regs: r1=*(0x63c)
 160:	3001      	movi	r0, 1	// regs: r0=0x1
 162:	c4225c02 	ins	r1, r2, 2, 2
 166:	c4205c04 	ins	r1, r0, 4, 4
 16a:	c4205c06 	ins	r1, r0, 6, 6
 16e:	dc25063c 	st.b	r1, (r5, 0x63c)	// *(0x63c) = *(0x63c)
 172:	d825131e 	ld.h	r1, (r5, 0x63c)	// regs: r1=*(0x63c)
 176:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(0x635))
 17a:	c4235c67 	ins	r1, r3, 10, 7
 17e:	dc25131e 	st.h	r1, (r5, 0x63c)	// *(0x63c) = *(0x63c)
 182:	d865063d 	ld.b	r3, (r5, 0x63d)	// regs: r3=*(0x63d)
 186:	c4625c03 	ins	r3, r2, 3, 3
 18a:	dc65063d 	st.b	r3, (r5, 0x63d)	// *(0x63d) = *(0x63d)
 18e:	d865218f 	ld.w	r3, (r5, 0x63c)	// regs: r3=*(0x63c)
 192:	c4665d0c 	ins	r3, r6, 20, 12
 196:	dc65218f 	st.w	r3, (r5, 0x63c)	// *(0x63c) = *(0x63c)
 19a:	d865063e 	ld.b	r3, (r5, 0x63e)	// regs: r3=*(0x63e)
 19e:	c4625c25 	ins	r3, r2, 6, 5
 1a2:	dc65063e 	st.b	r3, (r5, 0x63e)	// *(0x63e) = *(0x63e)
 1a6:	d865063f 	ld.b	r3, (r5, 0x63f)	// regs: r3=*(0x63f)
 1aa:	c4625c00 	ins	r3, r2, 0, 0
 1ae:	c4625c01 	ins	r3, r2, 1, 1
 1b2:	dc65063f 	st.b	r3, (r5, 0x63f)	// *(0x63f) = *(0x63f)
loc_1b6:
 1b6:	d865218e 	ld.w	r3, (r5, 0x638)	// regs: r3=*(0x638)
 1ba:	61cc      	addu	r7, r3	// regs: r7=(r7 + *(0x638))
 1bc:	3328      	movi	r3, 40	// regs: r3=0x28
 1be:	7dcc      	mult	r7, r3	// regs: r7=((r7 + *(0x638)) * 0x28)
 1c0:	136d      	lrw	r3, 0x0	// regs: r3=0x0
 1c2:	b561      	st.w	r3, (r5, 0x4)	// *(0x4) = 0x0
 1c4:	d8641505 	ld.h	r3, (r4, 0xa0a)	// regs: r3=*(0xa0a)
 1c8:	dce4133a 	st.h	r7, (r4, 0x674)	// *(0x674) = ((r7 + *(0x638)) * 0x28)
 1cc:	e903000c 	bez	r3, 0x1e4	// if (r3 == 0x0) goto loc_1e4;
 1d0:	e0000000 	bsr	0x0	// <lmac_clr_basic_nav>; regs: r0=<ret lmac_clr_basic_nav@0x1d0>, r1=<clobbered>
 1d4:	e0000000 	bsr	0x0	// <lmac_clr_obss_nav>; regs: r0=<ret lmac_clr_obss_nav@0x1d4>, r1=<clobbered>
 1d8:	d804031e 	ld.b	r0, (r4, 0x31e)	// regs: r0=*(0x31e)
 1dc:	2005      	addi	r0, 6	// regs: r0=(*(0x31e) + 0x6)
 1de:	7402      	sextb	r0, r0	// regs: r0=sext8((*(0x31e) + 0x6))
 1e0:	e0000000 	bsr	0x0	// <lmac_adjust_cca_threshold> // arg_bytes: 8; regs: r0=<ret lmac_adjust_cca_threshold@0x1e0>, r1=<clobbered>
loc_1e4:
 1e4:	d80409df 	ld.b	r0, (r4, 0x9df)	// regs: r0=*(0x9df)
 1e8:	c4205480 	zext	r0, r0, 4, 1	// regs: r0=zext(*(0x9df))
 1ec:	2800      	subi	r0, 1	// regs: r0=(zext(*(0x9df)) - 0x1)
 1ee:	e0000000 	bsr	0x0	// <lmac_attempt_tx_obss> // arg_bytes: 4; regs: r0=<ret lmac_attempt_tx_obss@0x1ee>, r1=<clobbered>
 1f2:	e9200089 	bnez	r0, 0x304	// if (r0 != 0x0) goto loc_304;
 1f6:	3308      	movi	r3, 8	// regs: r3=0x8
loc_1f8:
 1f8:	dc642265 	st.w	r3, (r4, 0x994)	// *(r4 + 0x994) = r3
 1fc:	0484      	br	0x304	// goto loc_304;
loc_1fe:
 1fe:	d825063c 	ld.b	r1, (r5, 0x63c)	// regs: r1=*(0x63c)
 202:	d8050634 	ld.b	r0, (r5, 0x634)	// regs: r0=*(0x634)
 206:	c4225c00 	ins	r1, r2, 0, 0
 20a:	c4c054e0 	zext	r0, r0, 7, 6	// regs: r0=zext(*(0x634))
 20e:	c4205c23 	ins	r1, r0, 4, 3
 212:	dc25063c 	st.b	r1, (r5, 0x63c)	// *(0x63c) = *(0x63c)
 216:	d825063e 	ld.b	r1, (r5, 0x63e)	// regs: r1=*(0x63e)
 21a:	e42120fe 	andi	r1, r1, 254	// regs: r1=(*(0x63e) & 0xfe)
 21e:	c4225c02 	ins	r1, r2, 2, 2
 222:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(0x635))
 226:	6c87      	mov	r2, r1	// regs: r2=(*(0x63e) & 0xfe)
 228:	c4435c63 	ins	r2, r3, 6, 3
 22c:	4661      	lsli	r3, r6, 1	// regs: r3=(r6 << 0x1)
 22e:	dc65063f 	st.b	r3, (r5, 0x63f)	// *(0x63f) = (r6 << 0x1)
 232:	c4e65503 	zext	r3, r6, 8, 7	// regs: r3=zext(r6)
 236:	d8c50640 	ld.b	r6, (r5, 0x640)	// regs: r6=*(0x640)
 23a:	3e80      	bclri	r6, 0	// regs: r6=(*(0x640) & ~(0x1 << 0x0))
 23c:	3e81      	bclri	r6, 1	// regs: r6=((*(0x640) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
 23e:	6d8c      	or	r6, r3	// regs: r6=(((*(0x640) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)) | zext(r6))
 240:	e4c620e3 	andi	r6, r6, 227	// regs: r6=((((*(0x640) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)) | zext(r6)) & 0xe3)
 244:	3300      	movi	r3, 0	// regs: r3=0x0
 246:	c4c35c05 	ins	r6, r3, 5, 5
 24a:	dc45063e 	st.b	r2, (r5, 0x63e)	// *(0x63e) = (*(0x63e) & 0xfe)
 24e:	dcc50640 	st.b	r6, (r5, 0x640)	// *(0x640) = ((((*(0x640) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)) | zext(r6)) & 0xe3)
 252:	07b2      	br	0x1b6	// goto loc_1b6;
loc_254:
 254:	d845063e 	ld.b	r2, (r5, 0x63e)	// regs: r2=*(0x63e)
 258:	3101      	movi	r1, 1	// regs: r1=0x1
 25a:	e44220fe 	andi	r2, r2, 254	// regs: r2=(*(0x63e) & 0xfe)
 25e:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(0x635))
 262:	c4415c02 	ins	r2, r1, 2, 2
 266:	c4435c63 	ins	r2, r3, 6, 3
 26a:	d8650634 	ld.b	r3, (r5, 0x634)	// regs: r3=*(0x634)
 26e:	c4c354e3 	zext	r3, r3, 7, 6	// regs: r3=zext(*(0x634))
 272:	dc45063e 	st.b	r2, (r5, 0x63e)	// *(0x63e) = (*(0x63e) & 0xfe)
 276:	d845063c 	ld.b	r2, (r5, 0x63c)	// regs: r2=*(0x63c)
 27a:	c4435c23 	ins	r2, r3, 4, 3
 27e:	d8650640 	ld.b	r3, (r5, 0x640)	// regs: r3=*(0x640)
 282:	e46320f3 	andi	r3, r3, 243	// regs: r3=(*(0x640) & 0xf3)
 286:	c4615c04 	ins	r3, r1, 4, 4
 28a:	dc45063c 	st.b	r2, (r5, 0x63c)	// *(0x63c) = *(0x63c)
 28e:	e46320fc 	andi	r3, r3, 252	// regs: r3=((*(0x640) & 0xf3) & 0xfc)
 292:	c4264022 	lsl	r2, r6, r1
 296:	c4e65506 	zext	r6, r6, 8, 7	// regs: r6=zext(r6)
 29a:	6d8c      	or	r6, r3	// regs: r6=(zext(r6) | ((*(0x640) & 0xf3) & 0xfc))
 29c:	dcc50640 	st.b	r6, (r5, 0x640)	// *(0x640) = (zext(r6) | ((*(0x640) & 0xf3) & 0xfc))
 2a0:	dc45063f 	st.b	r2, (r5, 0x63f)	// *(0x63f) = *(0x63c)
 2a4:	0789      	br	0x1b6	// goto loc_1b6;
loc_2a6:
 2a6:	d868000a 	ld.b	r3, (r8, 0xa)	// regs: r3=*(0xa)
 2aa:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0xa) & 0x1)
 2ae:	e9230006 	bnez	r3, 0x2ba	// if (r3 != 0x0) goto loc_2ba;
 2b2:	d8642267 	ld.w	r3, (r4, 0x99c)	// regs: r3=*(0x99c)
 2b6:	3b42      	cmpnei	r3, 2
 2b8:	0828      	bt	0x308	// if (r3 != 0x2) goto loc_308;
loc_2ba:
 2ba:	d86409dd 	ld.b	r3, (r4, 0x9dd)	// regs: r3=*(0x9dd)
 2be:	3500      	movi	r5, 0	// regs: r5=0x0
 2c0:	c4655c04 	ins	r3, r5, 4, 4
 2c4:	dc6409dd 	st.b	r3, (r4, 0x9dd)	// *(0x9dd) = *(0x9dd)
 2c8:	e0000000 	bsr	0x0	// <lmac_dtim_timer_rem> // arg_bytes: 0; regs: r0=<ret lmac_dtim_timer_rem@0x2c8>, r1=<clobbered>
 2cc:	e40017d0 	subi	r0, r0, 2001	// regs: r0=(<ret lmac_dtim_timer_rem@0x2c8> - 0x7d1)
 2d0:	eb001f3e 	cmphsi	r0, 7999
 2d4:	081a      	bt	0x308	// if (r0 >= 0x1f3f) goto loc_308;
 2d6:	e0000000 	bsr	0x0	// <lmac_update_pv0_wpcts_tx_vec> // arg_bytes: 0; regs: r0=<ret lmac_update_pv0_wpcts_tx_vec@0x2d6>, r1=<clobbered>
 2da:	d86409dc 	ld.b	r3, (r4, 0x9dc)	// regs: r3=*(0x9dc)
 2de:	c4655c04 	ins	r3, r5, 4, 4
 2e2:	6c17      	mov	r0, r5	// regs: r0=0x0
 2e4:	dc6409dc 	st.b	r3, (r4, 0x9dc)	// *(0x9dc) = *(0x9dc)
 2e8:	e0000000 	bsr	0x0	// <lmac_attempt_tx> // arg_bytes: 8; regs: r0=<ret lmac_attempt_tx@0x2e8>, r1=<clobbered>
 2ec:	e920000c 	bnez	r0, 0x304	// if (r0 != 0x0) goto loc_304;
 2f0:	3305      	movi	r3, 5	// regs: r3=0x5
 2f2:	dc642265 	st.w	r3, (r4, 0x994)	// *(0x994) = 0x5
 2f6:	3201      	movi	r2, 1	// regs: r2=0x1
 2f8:	d86409dd 	ld.b	r3, (r4, 0x9dd)	// regs: r3=*(0x9dd)
 2fc:	c4625c04 	ins	r3, r2, 4, 4
 300:	dc6409dd 	st.b	r3, (r4, 0x9dd)	// *(0x9dd) = *(0x9dd)
loc_304:
 304:	1401      	addi	r14, r14, 4	// regs: r14=(sp + 0x4)
 306:	1498      	pop	r4-r11, r15
loc_308:
 308:	d864202f 	ld.w	r3, (r4, 0xbc)	// regs: r3=*(0xbc)
 30c:	3b42      	cmpnei	r3, 2
 30e:	0835      	bt	0x378	// if (r3 != 0x2) goto loc_378;
 310:	d8642267 	ld.w	r3, (r4, 0x99c)	// regs: r3=*(0x99c)
 314:	3b42      	cmpnei	r3, 2
 316:	0831      	bt	0x378	// if (r3 != 0x2) goto loc_378;
 318:	d94420f0 	ld.w	r10, (r4, 0x3c0)	// regs: r10=*(0x3c0)
 31c:	d96420f1 	ld.w	r11, (r4, 0x3c4)	// regs: r11=*(0x3c4)
 320:	c56a2423 	or	r3, r10, r11	// regs: r3=(*(0x3c0) | *(0x3c4))
 324:	e903002a 	bez	r3, 0x378	// if (r3 == 0x0) goto loc_378;
 328:	d80411e4 	ld.h	r0, (r4, 0x3c8)	// regs: r0=*(0x3c8)
 32c:	3100      	movi	r1, 0	// regs: r1=0x0
 32e:	66a9      	cmplt	r10, r10
 330:	6281      	addc	r10, r0
 332:	62c5      	addc	r11, r1
 334:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x334>, r1=<clobbered>
 338:	6400      	cmphs	r0, r0
 33a:	c40a0100 	subc	r0, r10, r0
 33e:	c42b0101 	subc	r1, r11, r1
 342:	e9a1001b 	bhsz	r1, 0x378	// if (r1 >= 0x0) goto loc_378;
 346:	e0000000 	bsr	0x0	// <lmac_rx_data_queue_count>; regs: r0=<ret lmac_rx_data_queue_count@0x346>, r1=<clobbered>
 34a:	e9200017 	bnez	r0, 0x378	// if (r0 != 0x0) goto loc_378;
 34e:	3200      	movi	r2, 0	// regs: r2=0x0
 350:	3300      	movi	r3, 0	// regs: r3=0x0
 352:	dc4420f0 	st.w	r2, (r4, 0x3c0)	// *(0x3c0) = 0x0
 356:	dc6420f1 	st.w	r3, (r4, 0x3c4)	// *(0x3c4) = 0x0
 35a:	e0000000 	bsr	0x0	// <ap_sleep_enter>; regs: r0=<ret ap_sleep_enter@0x35a>, r1=<clobbered>
 35e:	07d3      	br	0x304	// goto loc_304;
 360:	00000000 	.long	0x00000000	// <LMAC>
 364:	00000000 	.long	0x00000000	// <ah_lmac>
 368:	00000000 	.long	0x00000000	// <ah_ops>
 36c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
 370:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_ac_pd.str1.1>
 374:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x634>
loc_378:
 378:	e0000000 	bsr	0x0	// <lmac_select_tx_acq> // arg_bytes: 0; regs: r0=<ret lmac_select_tx_acq@0x378>, r1=<clobbered>
 37c:	3803      	cmphsi	r0, 4
 37e:	6dc3      	mov	r7, r0	// regs: r7=<ret lmac_select_tx_acq@0x378>
 380:	0918      	bt	0x5b0	// if (r0 >= 0x4) goto loc_5b0;
 382:	e44e0002 	addi	r2, r14, 3	// regs: r2=(sp + 0x3)
 386:	e42e0001 	addi	r1, r14, 2	// regs: r1=(sp + 0x2)
 38a:	e0000000 	bsr	0x0	// <lmac_update_tx_rate> // arg_bytes: 12; regs: r0=<ret lmac_update_tx_rate@0x38a>, r1=<clobbered>
 38e:	3300      	movi	r3, 0	// regs: r3=0x0
 390:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 392:	64c2      	cmpne	r0, r3
 394:	0fb8      	bf	0x304	// if (!T) goto loc_304;
 396:	ea0301ff 	movi	r3, 511	// regs: r3=0x1ff
 39a:	d84e0003 	ld.b	r2, (r14, 0x3)	// regs: r2=stack_p3
 39e:	d82e0002 	ld.b	r1, (r14, 0x2)	// regs: r1=stack_p2
 3a2:	6c1f      	mov	r0, r7	// regs: r0=<ret lmac_select_tx_acq@0x378>
 3a4:	e0000000 	bsr	0x0	// <lmac_gen_tx_agglist> // arg_bytes: 16; regs: r0=<ret lmac_gen_tx_agglist@0x3a4>, r1=<clobbered>
 3a8:	6d43      	mov	r5, r0	// regs: r5=<ret lmac_gen_tx_agglist@0x3a4>
 3aa:	ea8800ce 	lrw	r8, 0x0	// regs: r8=0x0
 3ae:	e90000e7 	bez	r0, 0x57c	// if (r0 == 0x0) goto loc_57c;
 3b2:	3390      	movi	r3, 144	// regs: r3=0x90
 3b4:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
 3b6:	7cdc      	mult	r3, r7	// regs: r3=(0x120 * <ret lmac_select_tx_acq@0x378>)
 3b8:	60e0      	addu	r3, r8	// regs: r3=((0x120 * <ret lmac_select_tx_acq@0x378>) )
 3ba:	d84e0003 	ld.b	r2, (r14, 0x3)	// regs: r2=stack_p3
 3be:	d82e0002 	ld.b	r1, (r14, 0x2)	// regs: r1=stack_p2
 3c2:	6c1f      	mov	r0, r7	// regs: r0=<ret lmac_select_tx_acq@0x378>
 3c4:	d943206f 	ld.w	r10, (r3, 0x1bc)	// regs: r10=*((((0x120 * <ret lmac_select_tx_acq@0x378>) ) + 0x1bc))
 3c8:	e0000000 	bsr	0x0	// <lmac_gen_txvec> // arg_bytes: 12; regs: r0=<ret lmac_gen_txvec@0x3c8>, r1=<clobbered>
 3cc:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(r4 + 0x9e2)
 3d0:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(r4 + 0x9e2) & 0x2)
 3d4:	dc082001 	st.w	r0, (r8, 0x4)	// *(0x4) = <ret lmac_gen_txvec@0x3c8>
 3d8:	e92301e3 	bnez	r3, 0x79e	// if (r3 != 0x0) goto loc_79e;
 3dc:	d8640878 	ld.b	r3, (r4, 0x878)	// regs: r3=*(r4 + 0x878)
 3e0:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r4 + 0x878) & 0x1)
 3e4:	e92301dd 	bnez	r3, 0x79e	// if (r3 != 0x0) goto loc_79e;
 3e8:	9660      	ld.w	r3, (r6, 0x0)	// regs: r3=*(r6)
 3ea:	d8c32037 	ld.w	r6, (r3, 0xdc)	// regs: r6=*((*(r6) + 0xdc))
 3ee:	e92601d8 	bnez	r6, 0x79e	// if (r6 != 0x0) goto loc_79e;
 3f2:	d8240314 	ld.b	r1, (r4, 0x314)	// regs: r1=*(r4 + 0x314)
 3f6:	e4212020 	andi	r1, r1, 32	// regs: r1=(*(r4 + 0x314) & 0x20)
 3fa:	e9010089 	bez	r1, 0x50c	// if (r1 == 0x0) goto loc_50c;
 3fe:	8d73      	ld.h	r3, (r5, 0x26)	// regs: r3=*(<ret lmac_gen_tx_agglist@0x3a4> + 0x26)
 400:	e4632280 	andi	r3, r3, 640	// regs: r3=(*(<ret lmac_gen_tx_agglist@0x3a4> + 0x26) & 0x280)
 404:	eb430280 	cmpnei	r3, 640
 408:	0883      	bt	0x50e	// if (r3 != 0x280) goto loc_50e;
 40a:	e0000000 	bsr	0x0	// <get_worst_node> // arg_bytes: 0; regs: r0=<ret get_worst_node@0x40a>, r1=<clobbered>
 40e:	3840      	cmpnei	r0, 0
 410:	c4000509 	mvc	r9	// regs: r9=<cond>
 414:	6d83      	mov	r6, r0	// regs: r6=<ret get_worst_node@0x40a>
 416:	7664      	zextb	r9, r9	// regs: r9=zext8(<cond>)
loc_418:
 418:	9563      	ld.w	r3, (r5, 0xc)	// regs: r3=*(<ret lmac_gen_tx_agglist@0x3a4> + 0xc)
 41a:	e9230004 	bnez	r3, 0x422	// if (r3 != 0x0) goto loc_422;
 41e:	e90901c0 	bez	r9, 0x79e	// if (r9 == 0x0) goto loc_79e;
loc_422:
 422:	d8650027 	ld.b	r3, (r5, 0x27)	// regs: r3=*(<ret lmac_gen_tx_agglist@0x3a4> + 0x27)
 426:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(<ret lmac_gen_tx_agglist@0x3a4> + 0x27) & 0x8)
 42a:	e92301ba 	bnez	r3, 0x79e	// if (r3 != 0x0) goto loc_79e;
 42e:	9544      	ld.w	r2, (r5, 0x10)	// regs: r2=*(<ret lmac_gen_tx_agglist@0x3a4> + 0x10)
 430:	8261      	ld.b	r3, (r2, 0x1)	// regs: r3=*((*(<ret lmac_gen_tx_agglist@0x3a4> + 0x10) + 0x1))
 432:	4368      	lsli	r3, r3, 8	// regs: r3=(*((*(<ret lmac_gen_tx_agglist@0x3a4> + 0x10) + 0x1)) << 0x8)
 434:	8200      	ld.b	r0, (r2, 0x0)	// regs: r0=*(*(<ret lmac_gen_tx_agglist@0x3a4> + 0x10))
 436:	6c0c      	or	r0, r3	// regs: r0=(*(*(<ret lmac_gen_tx_agglist@0x3a4> + 0x10)) | (*((*(<ret lmac_gen_tx_agglist@0x3a4> + 0x10) + 0x1)) << 0x8))
 438:	e0000000 	bsr	0x0	// <ieee80211_is_data>; regs: r0=<ret ieee80211_is_data@0x438>, r1=<clobbered>
 43c:	e90001b1 	bez	r0, 0x79e	// if (r0 == 0x0) goto loc_79e;
 440:	d8640312 	ld.b	r3, (r4, 0x312)	// regs: r3=*(r4 + 0x312)
 444:	d8240313 	ld.b	r1, (r4, 0x313)	// regs: r1=*(r4 + 0x313)
 448:	d8450029 	ld.b	r2, (r5, 0x29)	// regs: r2=*(<ret lmac_gen_tx_agglist@0x3a4> + 0x29)
 44c:	60c6      	subu	r3, r1	// regs: r3=(*(r4 + 0x312) - *(r4 + 0x313))
 44e:	64c9      	cmplt	r2, r3
 450:	0da7      	bf	0x79e	// if (!T) goto loc_79e;
 452:	d8441197 	ld.h	r2, (r4, 0x32e)	// regs: r2=*(r4 + 0x32e)
 456:	74e9      	zexth	r3, r10	// regs: r3=zext16(*((((0x120 * <ret lmac_select_tx_acq@0x378>) ) + 0x1bc)))
 458:	648c      	cmphs	r3, r2
 45a:	0da2      	bf	0x79e	// if (!T) goto loc_79e;
 45c:	d865002b 	ld.b	r3, (r5, 0x2b)	// regs: r3=*(<ret lmac_gen_tx_agglist@0x3a4> + 0x2b)
 460:	e4432001 	andi	r2, r3, 1	// regs: r2=(*(<ret lmac_gen_tx_agglist@0x3a4> + 0x2b) & 0x1)
 464:	3a40      	cmpnei	r2, 0
 466:	3124      	movi	r1, 36	// regs: r1=0x24
 468:	3228      	movi	r2, 40	// regs: r2=0x28
 46a:	c4220c20 	incf	r1, r2, 0
 46e:	d844037f 	ld.b	r2, (r4, 0x37f)	// regs: r2=*(r4 + 0x37f)
 472:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(r4 + 0x37f) & 0x8)
 476:	e9020009 	bez	r2, 0x488	// if (r2 == 0x0) goto loc_488;
 47a:	d84409dc 	ld.b	r2, (r4, 0x9dc)	// regs: r2=*(r4 + 0x9dc)
 47e:	e442200f 	andi	r2, r2, 15	// regs: r2=(*(r4 + 0x9dc) & 0xf)
 482:	220f      	addi	r2, 16	// regs: r2=((*(r4 + 0x9dc) & 0xf) + 0x10)
 484:	d0440882 	ldr.w	r2, (r4, r2 << 2)	// regs: r2=*(r4 + (((*(r4 + 0x9dc) & 0xf) + 0x10) << 2))
loc_488:
 488:	c40a55e0 	zext	r0, r10, 15, 0	// regs: r0=zext(*((((0x120 * <ret lmac_select_tx_acq@0x378>) ) + 0x1bc)))
 48c:	c4228022 	divu	r2, r2, r1	// regs: r2=(r2 / 0x24)
 490:	6480      	cmphs	r0, r2
 492:	c4400c40 	inct	r2, r0, 0
 496:	c4418420 	mult	r0, r1, r2	// regs: r0=(0x24 * (r2 / 0x24))
 49a:	e4632006 	andi	r3, r3, 6	// regs: r3=(*(<ret lmac_gen_tx_agglist@0x3a4> + 0x2b) & 0x6)
 49e:	dc0420e1 	st.w	r0, (r4, 0x384)	// *(r4 + 0x384) = (0x24 * (r2 / 0x24))
 4a2:	d98409dc 	ld.b	r12, (r4, 0x9dc)	// regs: r12=*(r4 + 0x9dc)
 4a6:	d804037f 	ld.b	r0, (r4, 0x37f)	// regs: r0=*(r4 + 0x37f)
 4aa:	3b42      	cmpnei	r3, 2
 4ac:	c40c5c44 	ins	r0, r12, 6, 4
 4b0:	dc04037f 	st.b	r0, (r4, 0x37f)	// *(r4 + 0x37f) = *(r4 + 0x37f)
 4b4:	0c2f      	bf	0x512	// if (r3 == 0x2) goto loc_512;
 4b6:	3b44      	cmpnei	r3, 4
 4b8:	3008      	movi	r0, 8	// regs: r0=0x8
 4ba:	330e      	movi	r3, 14	// regs: r3=0xe
 4bc:	c4030c40 	inct	r0, r3, 0
loc_4c0:
 4c0:	d8641336 	ld.h	r3, (r4, 0x66c)	// regs: r3=*(r4 + 0x66c)
 4c4:	d9841338 	ld.h	r12, (r4, 0x670)	// regs: r12=*(r4 + 0x670)
 4c8:	6008      	addu	r0, r2	// regs: r0=(r0 + (r2 / 0x24))
 4ca:	60f0      	addu	r3, r12	// regs: r3=(*(r4 + 0x66c) + *(r4 + 0x670))
 4cc:	7c40      	mult	r1, r0	// regs: r1=(0x24 * (r0 + (r2 / 0x24)))
 4ce:	d84408e5 	ld.b	r2, (r4, 0x8e5)	// regs: r2=*(r4 + 0x8e5)
 4d2:	e46301f9 	addi	r3, r3, 506	// regs: r3=((*(r4 + 0x66c) + *(r4 + 0x670)) + 0x1fa)
 4d6:	60c4      	addu	r3, r1	// regs: r3=(((*(r4 + 0x66c) + *(r4 + 0x670)) + 0x1fa) + (0x24 * (r0 + (r2 / 0x24))))
 4d8:	e4422084 	andi	r2, r2, 132	// regs: r2=(*(r4 + 0x8e5) & 0x84)
 4dc:	3100      	movi	r1, 0	// regs: r1=0x0
 4de:	c4415c07 	ins	r2, r1, 7, 7
 4e2:	dc4408e5 	st.b	r2, (r4, 0x8e5)	// *(r4 + 0x8e5) = (*(r4 + 0x8e5) & 0x84)
 4e6:	eb037fff 	cmphsi	r3, 32768
 4ea:	ea027fff 	movi	r2, 32767	// regs: r2=0x7fff
 4ee:	c4620c40 	inct	r3, r2, 0
 4f2:	dc641473 	st.h	r3, (r4, 0x8e6)	// *(r4 + 0x8e6) = (((*(r4 + 0x66c) + *(r4 + 0x670)) + 0x1fa) + (0x24 * (r0 + (r2 / 0x24))))
 4f6:	e909003b 	bez	r9, 0x56c	// if (r9 == 0x0) goto loc_56c;
 4fa:	e906000e 	bez	r6, 0x516	// if (r6 == 0x0) goto loc_516;
 4fe:	3206      	movi	r2, 6	// regs: r2=0x6
 500:	e426006e 	addi	r1, r6, 111	// regs: r1=(r6 + 0x6f)
loc_504:
 504:	1318      	lrw	r0, 0x0	// regs: r0=0x0
 506:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x506>, r1=<clobbered>
 50a:	0409      	br	0x51c	// goto loc_51c;
loc_50c:
 50c:	6d87      	mov	r6, r1	// regs: r6=(*(r4 + 0x314) & 0x20)
loc_50e:
 50e:	6e5b      	mov	r9, r6	// regs: r9=r6
 510:	0784      	br	0x418	// goto loc_418;
loc_512:
 512:	3006      	movi	r0, 6	// regs: r0=0x6
 514:	07d6      	br	0x4c0	// goto loc_4c0;
loc_516:
 516:	1315      	lrw	r0, 0x0	// regs: r0=0x0
 518:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x518>, r1=<clobbered>
loc_51c:
 51c:	1334      	lrw	r1, 0x0	// regs: r1=0x0
 51e:	3206      	movi	r2, 6	// regs: r2=0x6
 520:	e40105eb 	addi	r0, r1, 1516	// regs: r0=0x5ec
 524:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x524>, r1=<clobbered>
 528:	d8640338 	ld.b	r3, (r4, 0x338)	// regs: r3=*(r4 + 0x338)
 52c:	d84805b6 	ld.b	r2, (r8, 0x5b6)	// regs: r2=*(0x5b6)
 530:	c4235423 	zext	r3, r3, 1, 1	// regs: r3=zext(*(r4 + 0x338))
 534:	c4435c07 	ins	r2, r3, 7, 7
 538:	dc4805b6 	st.b	r2, (r8, 0x5b6)	// *(0x5b6) = *(0x5b6)
 53c:	136d      	lrw	r3, 0x0	// regs: r3=0x0
 53e:	dc682001 	st.w	r3, (r8, 0x4)	// *(0x4) = 0x0
 542:	e0000000 	bsr	0x0	// <pv0_ctrl_uplink_txpwr_gen> // arg_bytes: 0; regs: r0=<ret pv0_ctrl_uplink_txpwr_gen@0x542>, r1=<clobbered>
 546:	3304      	movi	r3, 4	// regs: r3=0x4
loc_548:
 548:	d805003f 	ld.b	r0, (r5, 0x3f)	// regs: r0=*(<ret lmac_gen_tx_agglist@0x3a4> + 0x3f)
 54c:	dc642265 	st.w	r3, (r4, 0x994)	// *(r4 + 0x994) = r3
 550:	e460201f 	andi	r3, r0, 31	// regs: r3=(*(<ret lmac_gen_tx_agglist@0x3a4> + 0x3f) & 0x1f)
 554:	e9030010 	bez	r3, 0x574	// if (r3 == 0x0) goto loc_574;
 558:	6c0f      	mov	r0, r3	// regs: r0=(*(<ret lmac_gen_tx_agglist@0x3a4> + 0x3f) & 0x1f)
 55a:	2800      	subi	r0, 1	// regs: r0=((*(<ret lmac_gen_tx_agglist@0x3a4> + 0x3f) & 0x1f) - 0x1)
 55c:	e0000000 	bsr	0x0	// <lmac_attempt_tx_obss> // arg_bytes: 4; regs: r0=<ret lmac_attempt_tx_obss@0x55c>, r1=<clobbered>
loc_560:
 560:	3300      	movi	r3, 0	// regs: r3=0x0
 562:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 564:	64c2      	cmpne	r0, r3
 566:	080b      	bt	0x57c	// if (T) goto loc_57c;
loc_568:
 568:	3300      	movi	r3, 0	// regs: r3=0x0
 56a:	0647      	br	0x1f8	// goto loc_1f8;
loc_56c:
 56c:	3206      	movi	r2, 6	// regs: r2=0x6
 56e:	e4250019 	addi	r1, r5, 26	// regs: r1=(<ret lmac_gen_tx_agglist@0x3a4> + 0x1a)
 572:	07c9      	br	0x504	// goto loc_504;
loc_574:
 574:	6c1f      	mov	r0, r7	// regs: r0=<ret lmac_select_tx_acq@0x378>
 576:	e0000000 	bsr	0x0	// <lmac_attempt_tx> // arg_bytes: 8; regs: r0=<ret lmac_attempt_tx@0x576>, r1=<clobbered>
 57a:	07f3      	br	0x560	// goto loc_560;
loc_57c:
 57c:	3300      	movi	r3, 0	// regs: r3=0x0
 57e:	dc6812af 	st.h	r3, (r8, 0x55e)	// *(0x55e) = 0x0
 582:	d86421c6 	ld.w	r3, (r4, 0x718)	// regs: r3=*(r4 + 0x718)
 586:	2300      	addi	r3, 1	// regs: r3=(*(r4 + 0x718) + 0x1)
 588:	dc6421c6 	st.w	r3, (r4, 0x718)	// *(r4 + 0x718) = (*(r4 + 0x718) + 0x1)
 58c:	954e      	ld.w	r2, (r5, 0x38)	// regs: r2=*(<ret lmac_gen_tx_agglist@0x3a4> + 0x38)
 58e:	956d      	ld.w	r3, (r5, 0x34)	// regs: r3=*(<ret lmac_gen_tx_agglist@0x3a4> + 0x34)
 590:	6cc8      	or	r3, r2	// regs: r3=(*(<ret lmac_gen_tx_agglist@0x3a4> + 0x34) | *(<ret lmac_gen_tx_agglist@0x3a4> + 0x38))
 592:	e9230006 	bnez	r3, 0x59e	// if (r3 != 0x0) goto loc_59e;
 596:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x596>, r1=<clobbered>
 59a:	b50d      	st.w	r0, (r5, 0x34)	// *(<ret lmac_gen_tx_agglist@0x3a4> + 0x34) = <ret os_jiffies@0x596>
 59c:	b52e      	st.w	r1, (r5, 0x38)	// *(<ret lmac_gen_tx_agglist@0x3a4> + 0x38) = <clobbered>
loc_59e:
 59e:	d864143f 	ld.h	r3, (r4, 0x87e)	// regs: r3=*(r4 + 0x87e)
 5a2:	e903feb1 	bez	r3, 0x304	// if (r3 == 0x0) goto loc_304;
 5a6:	3300      	movi	r3, 0	// regs: r3=0x0
 5a8:	3400      	movi	r4, 0	// regs: r4=0x0
 5aa:	b56d      	st.w	r3, (r5, 0x34)	// *(<ret lmac_gen_tx_agglist@0x3a4> + 0x34) = 0x0
 5ac:	b58e      	st.w	r4, (r5, 0x38)	// *(<ret lmac_gen_tx_agglist@0x3a4> + 0x38) = 0x0
 5ae:	06ab      	br	0x304	// goto loc_304;
loc_5b0:
 5b0:	d8640360 	ld.b	r3, (r4, 0x360)	// regs: r3=*(r4 + 0x360)
 5b4:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r4 + 0x360) & 0x1)
 5b8:	e90300f5 	bez	r3, 0x7a2	// if (r3 == 0x0) goto loc_7a2;
 5bc:	d8640878 	ld.b	r3, (r4, 0x878)	// regs: r3=*(r4 + 0x878)
 5c0:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r4 + 0x878) & 0x1)
 5c4:	e90300ef 	bez	r3, 0x7a2	// if (r3 == 0x0) goto loc_7a2;
 5c8:	d864202f 	ld.w	r3, (r4, 0xbc)	// regs: r3=*(r4 + 0xbc)
 5cc:	3b42      	cmpnei	r3, 2
 5ce:	08ea      	bt	0x7a2	// if (r3 != 0x2) goto loc_7a2;
 5d0:	e0000000 	bsr	0x0	// <lmac_cfp_timer_remain> // arg_bytes: 8; regs: r0=<ret lmac_cfp_timer_remain@0x5d0>, r1=<clobbered>
 5d4:	e90000e7 	bez	r0, 0x7a2	// if (r0 == 0x0) goto loc_7a2;
 5d8:	e0000000 	bsr	0x0	// <lmac_gen_pv0_cfpoll> // arg_bytes: 0; regs: r0=<ret lmac_gen_pv0_cfpoll@0x5d8>, r1=<clobbered>
 5dc:	e92000e3 	bnez	r0, 0x7a2	// if (r0 != 0x0) goto loc_7a2;
 5e0:	1260      	lrw	r3, 0x0	// regs: r3=0x0
 5e2:	e44305f3 	addi	r2, r3, 1524	// regs: r2=0x5f4
 5e6:	b341      	st.w	r2, (r3, 0x4)	// *(0x4) = 0x5f4
 5e8:	3306      	movi	r3, 6	// regs: r3=0x6
loc_5ea:
 5ea:	dc642265 	st.w	r3, (r4, 0x994)	// *(r4 + 0x994) = r3
loc_5ee:
 5ee:	6c1f      	mov	r0, r7	// regs: r0=r7
 5f0:	e0000000 	bsr	0x0	// <lmac_attempt_tx> // arg_bytes: 8; regs: r0=<ret lmac_attempt_tx@0x5f0>, r1=<clobbered>
 5f4:	3300      	movi	r3, 0	// regs: r3=0x0
 5f6:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 5f8:	64c2      	cmpne	r0, r3
 5fa:	0a85      	bt	0x304	// if (T) goto loc_304;
 5fc:	07b6      	br	0x568	// goto loc_568;
loc_5fe:
 5fe:	9640      	ld.w	r2, (r6, 0x0)	// regs: r2=*(r6)
 600:	d8222037 	ld.w	r1, (r2, 0xdc)	// regs: r1=*((*(r6) + 0xdc))
 604:	eb0103e7 	cmphsi	r1, 1000
 608:	0c30      	bf	0x668	// if (r1 < 0x3e8) goto loc_668;
 60a:	3107      	movi	r1, 7	// regs: r1=0x7
 60c:	dc242265 	st.w	r1, (r4, 0x994)	// *(r4 + 0x994) = 0x7
loc_610:
 610:	d8222033 	ld.w	r1, (r2, 0xcc)	// regs: r1=*((*(r6) + 0xcc))
 614:	ec212000 	ori	r1, r1, 8192	// regs: r1=(*((*(r6) + 0xcc)) | 0x2000)
 618:	dc222033 	st.w	r1, (r2, 0xcc)	// *((*(r6) + 0xcc)) = (*((*(r6) + 0xcc)) | 0x2000)
 61c:	3180      	movi	r1, 128	// regs: r1=0x80
 61e:	412c      	lsli	r1, r1, 12	// regs: r1=0x80000
 620:	b232      	st.w	r1, (r2, 0x48)	// *((*(r6) + 0x48)) = 0x80000
 622:	3200      	movi	r2, 0	// regs: r2=0x0
 624:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
 626:	648e      	cmpne	r3, r2
 628:	0be3      	bt	0x5ee	// if (T) goto loc_5ee;
 62a:	d8a40319 	ld.b	r5, (r4, 0x319)	// regs: r5=*(r4 + 0x319)
 62e:	e4a52001 	andi	r5, r5, 1	// regs: r5=(*(r4 + 0x319) & 0x1)
 632:	e9050020 	bez	r5, 0x672	// if (r5 == 0x0) goto loc_672;
 636:	d8640969 	ld.b	r3, (r4, 0x969)	// regs: r3=*(r4 + 0x969)
 63a:	3200      	movi	r2, 0	// regs: r2=0x0
 63c:	c4625c04 	ins	r3, r2, 4, 4
 640:	112b      	lrw	r1, 0x0	// regs: r1=0x0
 642:	dc640969 	st.b	r3, (r4, 0x969)	// *(r4 + 0x969) = *(r4 + 0x969)
 646:	3206      	movi	r2, 6	// regs: r2=0x6
 648:	d8641198 	ld.h	r3, (r4, 0x330)	// regs: r3=*(r4 + 0x330)
 64c:	e401066f 	addi	r0, r1, 1648	// regs: r0=0x670
 650:	dc6414b5 	st.h	r3, (r4, 0x96a)	// *(r4 + 0x96a) = *(r4 + 0x330)
 654:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x654>, r1=<clobbered>
 658:	1162      	lrw	r3, 0x0	// regs: r3=0x0
 65a:	e4430613 	addi	r2, r3, 1556	// regs: r2=0x614
 65e:	b341      	st.w	r2, (r3, 0x4)	// *(0x4) = 0x614
 660:	e0000000 	bsr	0x0	// <pv0_ctrl_uplink_txpwr_gen> // arg_bytes: 0; regs: r0=<ret pv0_ctrl_uplink_txpwr_gen@0x660>, r1=<clobbered>
 664:	330a      	movi	r3, 10	// regs: r3=0xa
 666:	07c2      	br	0x5ea	// goto loc_5ea;
loc_668:
 668:	dc642265 	st.w	r3, (r4, 0x994)	// *(r4 + 0x994) = (*(r4 + 0x878) & 0x1)
 66c:	3300      	movi	r3, 0	// regs: r3=0x0
 66e:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 670:	07d0      	br	0x610	// goto loc_610;
loc_672:
 672:	d8240318 	ld.b	r1, (r4, 0x318)	// regs: r1=*(r4 + 0x318)
 676:	e901ff79 	bez	r1, 0x568	// if (r1 == 0x0) goto loc_568;
 67a:	d8640556 	ld.b	r3, (r4, 0x556)	// regs: r3=*(r4 + 0x556)
 67e:	e903ff75 	bez	r3, 0x568	// if (r3 == 0x0) goto loc_568;
 682:	d848000a 	ld.b	r2, (r8, 0xa)	// regs: r2=*(r8 + 0xa)
 686:	6c8a      	nor	r2, r2	// regs: r2=(~*(r8 + 0xa))
 688:	d8640979 	ld.b	r3, (r4, 0x979)	// regs: r3=*(r4 + 0x979)
 68c:	3901      	cmphsi	r1, 2
 68e:	c4625c04 	ins	r3, r2, 4, 4
 692:	c4000502 	mvc	r2	// regs: r2=<cond>
 696:	c4625c03 	ins	r3, r2, 3, 3
 69a:	dc640979 	st.b	r3, (r4, 0x979)	// *(r4 + 0x979) = *(r4 + 0x979)
 69e:	d864202f 	ld.w	r3, (r4, 0xbc)	// regs: r3=*(r4 + 0xbc)
 6a2:	3b42      	cmpnei	r3, 2
 6a4:	083e      	bt	0x720	// if (r3 != 0x2) goto loc_720;
 6a6:	d8641506 	ld.h	r3, (r4, 0xa0c)	// regs: r3=*(r4 + 0xa0c)
 6aa:	d824227e 	ld.w	r1, (r4, 0x9f8)	// regs: r1=*(r4 + 0x9f8)
 6ae:	ea8c0012 	lrw	r12, 0x0	// regs: r12=0x0
 6b2:	ea0d0001 	movi	r13, 1	// regs: r13=0x1
loc_6b6:
 6b6:	6706      	cmpne	r1, r12
 6b8:	0820      	bt	0x6f8	// if (T) goto loc_6f8;
 6ba:	e9050004 	bez	r5, 0x6c2	// if (r5 == 0x0) goto loc_6c2;
 6be:	dc641506 	st.h	r3, (r4, 0xa0c)	// *(r4 + 0xa0c) = r3
loc_6c2:
 6c2:	d8441506 	ld.h	r2, (r4, 0xa0c)	// regs: r2=*(r4 + 0xa0c)
 6c6:	d8641504 	ld.h	r3, (r4, 0xa08)	// regs: r3=*(r4 + 0xa08)
 6ca:	64c8      	cmphs	r2, r3
 6cc:	0f4e      	bf	0x568	// if (!T) goto loc_568;
 6ce:	3300      	movi	r3, 0	// regs: r3=0x0
 6d0:	dc640318 	st.b	r3, (r4, 0x318)	// *(r4 + 0x318) = 0x0
 6d4:	3300      	movi	r3, 0	// regs: r3=0x0
 6d6:	dc642265 	st.w	r3, (r4, 0x994)	// *(r4 + 0x994) = 0x0
 6da:	e0000000 	bsr	0x0	// <ap_sleep_enter>; regs: r0=<ret ap_sleep_enter@0x6da>, r1=<clobbered>
 6de:	0745      	br	0x568	// goto loc_568;
 6e0:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
 6e4:	00000000 	.long	0x00000000	// <ah_lmac+0x8e8>
 6e8:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_ac_pd.str1.1+0x24>
 6ec:	00000000 	.long	0x00000000	// <ah_lmac+0x302>
 6f0:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x5b4>
 6f4:	00000000 	.long	0x00000000	// <ah_lmac+0x9f8>
loc_6f8:
 6f8:	d841006b 	ld.b	r2, (r1, 0x6b)	// regs: r2=*(r1 + 0x6b)
 6fc:	7408      	zextb	r0, r2	// regs: r0=zext8(*(r1 + 0x6b))
 6fe:	e4c02008 	andi	r6, r0, 8	// regs: r6=(zext8(*(r1 + 0x6b)) & 0x8)
 702:	e926000d 	bnez	r6, 0x71c	// if (r6 != 0x0) goto loc_71c;
 706:	e4002002 	andi	r0, r0, 2	// regs: r0=(zext8(*(r1 + 0x6b)) & 0x2)
 70a:	e9000065 	bez	r0, 0x7d4	// if (r0 == 0x0) goto loc_7d4;
 70e:	c44d5c03 	ins	r2, r13, 3, 3
 712:	2300      	addi	r3, 1	// regs: r3=(r3 + 0x1)
 714:	dc41006b 	st.b	r2, (r1, 0x6b)	// *(r1 + 0x6b) = *(r1 + 0x6b)
 718:	74cd      	zexth	r3, r3	// regs: r3=zext16((r3 + 0x1))
 71a:	3501      	movi	r5, 1	// regs: r5=0x1
loc_71c:
 71c:	9120      	ld.w	r1, (r1, 0x0)	// regs: r1=*(r1)
 71e:	07cc      	br	0x6b6	// goto loc_6b6;
loc_720:
 720:	d8642267 	ld.w	r3, (r4, 0x99c)	// regs: r3=*(r4 + 0x99c)
 724:	3b41      	cmpnei	r3, 1
 726:	0809      	bt	0x738	// if (r3 != 0x1) goto loc_738;
 728:	3302      	movi	r3, 2	// regs: r3=0x2
 72a:	dc642267 	st.w	r3, (r4, 0x99c)	// *(r4 + 0x99c) = 0x2
loc_72e:
 72e:	1138      	lrw	r1, 0x0	// regs: r1=0x0
 730:	3206      	movi	r2, 6	// regs: r2=0x6
 732:	e4010455 	addi	r0, r1, 1110	// regs: r0=0x456
 736:	0456      	br	0x7e2	// goto loc_7e2;
loc_738:
 738:	d8641505 	ld.h	r3, (r4, 0xa0a)	// regs: r3=*(r4 + 0xa0a)
 73c:	e903fff9 	bez	r3, 0x72e	// if (r3 == 0x0) goto loc_72e;
 740:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(r4 + 0x319)
 744:	3601      	movi	r6, 1	// regs: r6=0x1
 746:	c4665c01 	ins	r3, r6, 1, 1
 74a:	d8042233 	ld.w	r0, (r4, 0x8cc)	// regs: r0=*(r4 + 0x8cc)
 74e:	dca40318 	st.b	r5, (r4, 0x318)	// *(r4 + 0x318) = (*(r4 + 0x319) & 0x1)
 752:	dc640319 	st.b	r3, (r4, 0x319)	// *(r4 + 0x319) = *(r4 + 0x319)
 756:	dca42265 	st.w	r5, (r4, 0x994)	// *(r4 + 0x994) = (*(r4 + 0x319) & 0x1)
 75a:	e0000000 	bsr	0x0	// <dsleep_cfg_init>; regs: r0=<ret dsleep_cfg_init@0x75a>, r1=<clobbered>
 75e:	e920000f 	bnez	r0, 0x77c	// if (r0 != 0x0) goto loc_77c;
 762:	3303      	movi	r3, 3	// regs: r3=0x3
 764:	d80420fa 	ld.w	r0, (r4, 0x3e8)	// regs: r0=*(r4 + 0x3e8)
 768:	d82420fb 	ld.w	r1, (r4, 0x3ec)	// regs: r1=*(r4 + 0x3ec)
 76c:	dc642267 	st.w	r3, (r4, 0x99c)	// *(r4 + 0x99c) = 0x3
 770:	e0000000 	bsr	0x0	// <dsleep_dur_calc>; regs: r0=<ret dsleep_dur_calc@0x770>, r1=<clobbered>
 774:	3107      	movi	r1, 7	// regs: r1=0x7
 776:	e0000000 	bsr	0x0	// <dsleep_enter>; regs: r0=<ret dsleep_enter@0x776>, r1=<clobbered>
 77a:	07da      	br	0x72e	// goto loc_72e;
loc_77c:
 77c:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(r4)
 77e:	1105      	lrw	r0, 0x0	// regs: r0=0x0
 780:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*((*(r4) + 0xa))
 782:	c4465c00 	ins	r2, r6, 0, 0
 786:	a34a      	st.b	r2, (r3, 0xa)	// *((*(r4) + 0xa)) = *((*(r4) + 0xa))
 788:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(r4 + 0x319)
 78c:	c4655c01 	ins	r3, r5, 1, 1
 790:	dc640319 	st.b	r3, (r4, 0x319)	// *(r4 + 0x319) = *(r4 + 0x319)
 794:	dca42267 	st.w	r5, (r4, 0x99c)	// *(r4 + 0x99c) = (*(r4 + 0x319) & 0x1)
 798:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x798>, r1=<clobbered>
 79c:	06e6      	br	0x568	// goto loc_568;
loc_79e:
 79e:	3301      	movi	r3, 1	// regs: r3=0x1
 7a0:	06d4      	br	0x548	// goto loc_548;
loc_7a2:
 7a2:	e0000000 	bsr	0x0	// <lmac_update_pv0_cfend_addr>; regs: r0=<ret lmac_update_pv0_cfend_addr@0x7a2>, r1=<clobbered>
 7a6:	e0000000 	bsr	0x0	// <lmac_update_pv0_cfend_tx_vec> // arg_bytes: 0; regs: r0=<ret lmac_update_pv0_cfend_tx_vec@0x7a6>, r1=<clobbered>
 7aa:	d8440878 	ld.b	r2, (r4, 0x878)	// regs: r2=*(r4 + 0x878)
 7ae:	e4622001 	andi	r3, r2, 1	// regs: r3=(*(r4 + 0x878) & 0x1)
 7b2:	e903ff26 	bez	r3, 0x5fe	// if (r3 == 0x0) goto loc_5fe;
 7b6:	3300      	movi	r3, 0	// regs: r3=0x0
 7b8:	c4435c00 	ins	r2, r3, 0, 0
 7bc:	dc440878 	st.b	r2, (r4, 0x878)	// *(r4 + 0x878) = *(r4 + 0x878)
 7c0:	d8442220 	ld.w	r2, (r4, 0x880)	// regs: r2=*(r4 + 0x880)
 7c4:	d8642221 	ld.w	r3, (r4, 0x884)	// regs: r3=*(r4 + 0x884)
 7c8:	dc442222 	st.w	r2, (r4, 0x888)	// *(r4 + 0x888) = *(r4 + 0x880)
 7cc:	dc642223 	st.w	r3, (r4, 0x88c)	// *(r4 + 0x88c) = *(r4 + 0x884)
 7d0:	3307      	movi	r3, 7	// regs: r3=0x7
 7d2:	070c      	br	0x5ea	// goto loc_5ea;
loc_7d4:
 7d4:	e9050004 	bez	r5, 0x7dc	// if (r5 == 0x0) goto loc_7dc;
 7d8:	dc641506 	st.h	r3, (r4, 0xa0c)	// *(r4 + 0xa0c) = r3
loc_7dc:
 7dc:	3206      	movi	r2, 6	// regs: r2=0x6
 7de:	216e      	addi	r1, 111	// regs: r1=(r1 + 0x6f)
 7e0:	100d      	lrw	r0, 0x0	// regs: r0=0x0
loc_7e2:
 7e2:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x7e2>, r1=<clobbered>
 7e6:	102d      	lrw	r1, 0x0	// regs: r1=0x0
 7e8:	3206      	movi	r2, 6	// regs: r2=0x6
 7ea:	e401067f 	addi	r0, r1, 1664	// regs: r0=0x680
 7ee:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x7ee>, r1=<clobbered>
 7f2:	1027      	lrw	r1, 0x0	// regs: r1=0x0
 7f4:	3206      	movi	r2, 6	// regs: r2=0x6
 7f6:	e4010461 	addi	r0, r1, 1122	// regs: r0=0x462
 7fa:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x7fa>, r1=<clobbered>
 7fe:	1068      	lrw	r3, 0x0	// regs: r3=0x0
 800:	e4430623 	addi	r2, r3, 1572	// regs: r2=0x624
 804:	b341      	st.w	r2, (r3, 0x4)	// *(0x4) = 0x624
 806:	3309      	movi	r3, 9	// regs: r3=0x9
 808:	06f1      	br	0x5ea	// goto loc_5ea;
 80a:	0000      	.short	0x0000
 80c:	00000000 	.long	0x00000000	// <ah_lmac+0x526>
 810:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_ac_pd.str1.1+0x45>
 814:	00000000 	.long	0x00000000	// <ah_lmac+0x97c>
 818:	00000000 	.long	0x00000000	// <ah_lmac+0x302>
 81c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>

Disassembly of section .text.lmac_tx_beacon:

00000000 <lmac_tx_beacon>: // arg_bytes: 4
   0:	14d6      	push	r4-r9, r15
   2:	01af      	lrw	r5, 0x0	// regs: r5=0x0
   4:	018f      	lrw	r4, 0x0	// regs: r4=0x0
   6:	01ee      	lrw	r7, 0x0	// regs: r7=0x0
   8:	9562      	ld.w	r3, (r5, 0x8)	// regs: r3=*(0x8)
   a:	9368      	ld.w	r3, (r3, 0x20)	// regs: r3=*((*(0x8) + 0x20))
   c:	d8630027 	ld.b	r3, (r3, 0x27)	// regs: r3=*((*((*(0x8) + 0x20)) + 0x27))
  10:	e4632040 	andi	r3, r3, 64	// regs: r3=(*((*((*(0x8) + 0x20)) + 0x27)) & 0x40)
  14:	e9030154 	bez	r3, 0x2bc	// if (r3 == 0x0) goto loc_2bc;
  18:	d864033c 	ld.b	r3, (r4, 0x33c)	// regs: r3=*(0x33c)
  1c:	d84409df 	ld.b	r2, (r4, 0x9df)	// regs: r2=*(0x9df)
  20:	2300      	addi	r3, 1	// regs: r3=(*(0x33c) + 0x1)
  22:	c4435c61 	ins	r2, r3, 4, 1
  26:	dc4409df 	st.b	r2, (r4, 0x9df)	// *(0x9df) = *(0x9df)
  2a:	d8642267 	ld.w	r3, (r4, 0x99c)	// regs: r3=*(0x99c)
  2e:	9543      	ld.w	r2, (r5, 0xc)	// regs: r2=*(0xc)
  30:	3b40      	cmpnei	r3, 0
  32:	c4000501 	mvc	r1	// regs: r1=<cond>
  36:	8261      	ld.b	r3, (r2, 0x1)	// regs: r3=*((*(0xc) + 0x1))
  38:	c4615c07 	ins	r3, r1, 7, 7
  3c:	a261      	st.b	r3, (r2, 0x1)	// *((*(0xc) + 0x1)) = *((*(0xc) + 0x1))
  3e:	74ce      	sextb	r3, r3	// regs: r3=sext8(*((*(0xc) + 0x1)))
  40:	e9a30008 	bhsz	r3, 0x50	// if (r3 >= 0x0) goto loc_50;
  44:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x44>, r1=<clobbered>
  48:	dc0420f0 	st.w	r0, (r4, 0x3c0)	// *(0x3c0) = <ret os_jiffies@0x44>
  4c:	dc2420f1 	st.w	r1, (r4, 0x3c4)	// *(0x3c4) = <clobbered>
loc_50:
  50:	d8c409df 	ld.b	r6, (r4, 0x9df)	// regs: r6=*(0x9df)
  54:	e4c62020 	andi	r6, r6, 32	// regs: r6=(*(0x9df) & 0x20)
  58:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(0x0)
  5a:	e906017b 	bez	r6, 0x350	// if (r6 == 0x0) goto loc_350;
  5e:	9523      	ld.w	r1, (r5, 0xc)	// regs: r1=*(0xc)
  60:	9304      	ld.w	r0, (r3, 0x10)	// regs: r0=*((*(0x0) + 0x10))
  62:	2109      	addi	r1, 10	// regs: r1=(*(0xc) + 0xa)
  64:	e0000000 	bsr	0x0	// <__put_unaligned_le32> // arg_bytes: 8; regs: r0=<ret __put_unaligned_le32@0x64>, r1=<clobbered>
loc_68:
  68:	9524      	ld.w	r1, (r5, 0x10)	// regs: r1=*(r5 + 0x10)
  6a:	e9010007 	bez	r1, 0x78	// if (r1 == 0x0) goto loc_78;
  6e:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(r7)
  70:	2103      	addi	r1, 4	// regs: r1=(*(r5 + 0x10) + 0x4)
  72:	9305      	ld.w	r0, (r3, 0x14)	// regs: r0=*((*(r7) + 0x14))
  74:	e0000000 	bsr	0x0	// <__put_unaligned_le32> // arg_bytes: 8; regs: r0=<ret __put_unaligned_le32@0x74>, r1=<clobbered>
loc_78:
  78:	9563      	ld.w	r3, (r5, 0xc)	// regs: r3=*(r5 + 0xc)
  7a:	e4230009 	addi	r1, r3, 10	// regs: r1=(*(r5 + 0xc) + 0xa)
  7e:	8141      	ld.b	r2, (r1, 0x1)	// regs: r2=*((*(r5 + 0xc) + 0xb))
  80:	836a      	ld.b	r3, (r3, 0xa)	// regs: r3=*((*(r5 + 0xc) + 0xa))
  82:	4248      	lsli	r2, r2, 8	// regs: r2=(*((*(r5 + 0xc) + 0xb)) << 0x8)
  84:	6c8c      	or	r2, r3	// regs: r2=((*((*(r5 + 0xc) + 0xb)) << 0x8) | *((*(r5 + 0xc) + 0xa)))
  86:	8162      	ld.b	r3, (r1, 0x2)	// regs: r3=*((*(r5 + 0xc) + 0xc))
  88:	4370      	lsli	r3, r3, 16	// regs: r3=(*((*(r5 + 0xc) + 0xc)) << 0x10)
  8a:	6c8c      	or	r2, r3	// regs: r2=(((*((*(r5 + 0xc) + 0xb)) << 0x8) | *((*(r5 + 0xc) + 0xa))) | (*((*(r5 + 0xc) + 0xc)) << 0x10))
  8c:	8163      	ld.b	r3, (r1, 0x3)	// regs: r3=*((*(r5 + 0xc) + 0xd))
  8e:	4378      	lsli	r3, r3, 24	// regs: r3=(*((*(r5 + 0xc) + 0xd)) << 0x18)
  90:	6cc8      	or	r3, r2	// regs: r3=((*((*(r5 + 0xc) + 0xd)) << 0x18) | (((*((*(r5 + 0xc) + 0xb)) << 0x8) | *((*(r5 + 0xc) + 0xa))) | (*((*(r5 + 0xc) + 0xc)) << 0x10)))
  92:	dc642198 	st.w	r3, (r4, 0x660)	// *(r4 + 0x660) = ((*((*(r5 + 0xc) + 0xd)) << 0x18) | (((*((*(r5 + 0xc) + 0xb)) << 0x8) | *((*(r5 + 0xc) + 0xa))) | (*((*(r5 + 0xc) + 0xc)) << 0x10)))
  96:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(r7)
  98:	9365      	ld.w	r3, (r3, 0x14)	// regs: r3=*((*(r7) + 0x14))
  9a:	dc642199 	st.w	r3, (r4, 0x664)	// *(r4 + 0x664) = *((*(r7) + 0x14))
  9e:	9565      	ld.w	r3, (r5, 0x14)	// regs: r3=*(r5 + 0x14)
  a0:	e9030173 	bez	r3, 0x386	// if (r3 == 0x0) goto loc_386;
  a4:	d8440555 	ld.b	r2, (r4, 0x555)	// regs: r2=*(r4 + 0x555)
  a8:	a340      	st.b	r2, (r3, 0x0)	// *(*(r5 + 0x14)) = *(r4 + 0x555)
  aa:	e9220019 	bnez	r2, 0xdc	// if (r2 != 0x0) goto loc_dc;
  ae:	d8440319 	ld.b	r2, (r4, 0x319)	// regs: r2=*(r4 + 0x319)
  b2:	c44254a1 	zext	r1, r2, 5, 2	// regs: r1=zext(*(r4 + 0x319))
  b6:	3927      	cmplti	r1, 8
  b8:	0c12      	bf	0xdc	// if (r1 >= 0x8) goto loc_dc;
  ba:	e442203c 	andi	r2, r2, 60	// regs: r2=(*(r4 + 0x319) & 0x3c)
  be:	e9220009 	bnez	r2, 0xd0	// if (r2 != 0x0) goto loc_d0;
  c2:	8302      	ld.b	r0, (r3, 0x2)	// regs: r0=*((*(r5 + 0x14) + 0x2))
  c4:	3200      	movi	r2, 0	// regs: r2=0x0
  c6:	ec000001 	ori	r0, r0, 1	// regs: r0=(*((*(r5 + 0x14) + 0x2)) | 0x1)
  ca:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  cc:	a302      	st.b	r0, (r3, 0x2)	// *((*(r5 + 0x14) + 0x2)) = (*((*(r5 + 0x14) + 0x2)) | 0x1)
  ce:	a343      	st.b	r2, (r3, 0x3)	// *((*(r5 + 0x14) + 0x3)) = 0xffffffff
loc_d0:
  d0:	3201      	movi	r2, 1	// regs: r2=0x1
  d2:	c4224021 	lsl	r1, r2, r1
  d6:	8343      	ld.b	r2, (r3, 0x3)	// regs: r2=*((*(r5 + 0x14) + 0x3))
  d8:	6c84      	or	r2, r1	// regs: r2=(*((*(r5 + 0x14) + 0x3)) | zext(*(r4 + 0x319)))
  da:	a343      	st.b	r2, (r3, 0x3)	// *((*(r5 + 0x14) + 0x3)) = (*((*(r5 + 0x14) + 0x3)) | zext(*(r4 + 0x319)))
loc_dc:
  dc:	d905200a 	ld.w	r8, (r5, 0x28)	// regs: r8=*(r5 + 0x28)
  e0:	e908001c 	bez	r8, 0x118	// if (r8 == 0x0) goto loc_118;
  e4:	e0000000 	bsr	0x0	// <lmac_next_dtim_calc>; regs: r0=<ret lmac_next_dtim_calc@0xe4>, r1=<clobbered>
  e8:	d8442196 	ld.w	r2, (r4, 0x658)	// regs: r2=*(r4 + 0x658)
  ec:	4a61      	lsri	r3, r2, 1	// regs: r3=(*(r4 + 0x658) >> 0x1)
  ee:	64c0      	cmphs	r0, r3
  f0:	6e03      	mov	r8, r0	// regs: r8=<ret lmac_next_dtim_calc@0xe4>
  f2:	0805      	bt	0xfc	// if (T) goto loc_fc;
  f4:	d8640556 	ld.b	r3, (r4, 0x556)	// regs: r3=*(r4 + 0x556)
  f8:	7cc8      	mult	r3, r2	// regs: r3=(*(r4 + 0x556) * *(r4 + 0x658))
  fa:	620c      	addu	r8, r3	// regs: r8=(<ret lmac_next_dtim_calc@0xe4> + (*(r4 + 0x556) * *(r4 + 0x658)))
loc_fc:
  fc:	956a      	ld.w	r3, (r5, 0x28)	// regs: r3=*(r5 + 0x28)
  fe:	c5084842 	lsri	r2, r8, 8	// regs: r2=(r8 >> 0x8)
 102:	a340      	st.b	r2, (r3, 0x0)	// *(*(r5 + 0x28)) = (r8 >> 0x8)
 104:	956a      	ld.w	r3, (r5, 0x28)	// regs: r3=*(r5 + 0x28)
 106:	c6084842 	lsri	r2, r8, 16	// regs: r2=(r8 >> 0x10)
 10a:	a341      	st.b	r2, (r3, 0x1)	// *((*(r5 + 0x28) + 0x1)) = (r8 >> 0x10)
 10c:	956a      	ld.w	r3, (r5, 0x28)	// regs: r3=*(r5 + 0x28)
 10e:	c7084842 	lsri	r2, r8, 24	// regs: r2=(r8 >> 0x18)
 112:	a342      	st.b	r2, (r3, 0x2)	// *((*(r5 + 0x28) + 0x2)) = (r8 >> 0x18)
 114:	dd0521b4 	st.w	r8, (r5, 0x6d0)	// *(r5 + 0x6d0) = r8
loc_118:
 118:	d864227e 	ld.w	r3, (r4, 0x9f8)	// regs: r3=*(r4 + 0x9f8)
 11c:	ea090000 	movi	r9, 0	// regs: r9=0x0
 120:	0334      	lrw	r1, 0x0	// regs: r1=0x0
 122:	3001      	movi	r0, 1	// regs: r0=0x1
loc_124:
 124:	644e      	cmpne	r3, r1
 126:	0934      	bt	0x38e	// if (T) goto loc_38e;
 128:	95c9      	ld.w	r6, (r5, 0x24)	// regs: r6=*(r5 + 0x24)
 12a:	dd24229c 	st.w	r9, (r4, 0xa70)	// *(r4 + 0xa70) = r9
 12e:	e9060013 	bez	r6, 0x154	// if (r6 == 0x0) goto loc_154;
 132:	e0000000 	bsr	0x0	// <lmac_bkn_dly_calc>; regs: r0=<ret lmac_bkn_dly_calc@0x132>, r1=<clobbered>
 136:	9529      	ld.w	r1, (r5, 0x24)	// regs: r1=*(r5 + 0x24)
 138:	5068      	asri	r3, r0, 8	// regs: r3=(<ret lmac_bkn_dly_calc@0x132> >> 0x8)
 13a:	a161      	st.b	r3, (r1, 0x1)	// *((*(r5 + 0x24) + 0x1)) = (<ret lmac_bkn_dly_calc@0x132> >> 0x8)
 13c:	5070      	asri	r3, r0, 16	// regs: r3=(<ret lmac_bkn_dly_calc@0x132> >> 0x10)
 13e:	a162      	st.b	r3, (r1, 0x2)	// *((*(r5 + 0x24) + 0x2)) = (<ret lmac_bkn_dly_calc@0x132> >> 0x10)
 140:	4878      	lsri	r3, r0, 24	// regs: r3=(<ret lmac_bkn_dly_calc@0x132> >> 0x18)
 142:	a100      	st.b	r0, (r1, 0x0)	// *(*(r5 + 0x24)) = <ret lmac_bkn_dly_calc@0x132>
 144:	6d83      	mov	r6, r0	// regs: r6=<ret lmac_bkn_dly_calc@0x132>
 146:	dd010004 	st.b	r8, (r1, 0x4)	// *((*(r5 + 0x24) + 0x4)) = r8
 14a:	a163      	st.b	r3, (r1, 0x3)	// *((*(r5 + 0x24) + 0x3)) = (<ret lmac_bkn_dly_calc@0x132> >> 0x18)
 14c:	6c27      	mov	r0, r9	// regs: r0=r9
 14e:	2104      	addi	r1, 5	// regs: r1=(*(r5 + 0x24) + 0x5)
 150:	e0000000 	bsr	0x0	// <__put_unaligned_le32> // arg_bytes: 8; regs: r0=<ret __put_unaligned_le32@0x150>, r1=<clobbered>
loc_154:
 154:	9568      	ld.w	r3, (r5, 0x20)	// regs: r3=*(r5 + 0x20)
 156:	e903005e 	bez	r3, 0x212	// if (r3 == 0x0) goto loc_212;
 15a:	9565      	ld.w	r3, (r5, 0x14)	// regs: r3=*(r5 + 0x14)
 15c:	e9030012 	bez	r3, 0x180	// if (r3 == 0x0) goto loc_180;
 160:	8360      	ld.b	r3, (r3, 0x0)	// regs: r3=*(*(r5 + 0x14))
 162:	e923000f 	bnez	r3, 0x180	// if (r3 != 0x0) goto loc_180;
 166:	d864143c 	ld.h	r3, (r4, 0x878)	// regs: r3=*(r4 + 0x878)
 16a:	e44321fe 	andi	r2, r3, 510	// regs: r2=(*(r4 + 0x878) & 0x1fe)
 16e:	e9020009 	bez	r2, 0x180	// if (r2 == 0x0) goto loc_180;
 172:	c4235502 	zext	r2, r3, 8, 1	// regs: r2=zext(*(r4 + 0x878))
 176:	2a00      	subi	r2, 1	// regs: r2=(zext(*(r4 + 0x878)) - 0x1)
 178:	c4625ce1 	ins	r3, r2, 8, 1
 17c:	dc64143c 	st.h	r3, (r4, 0x878)	// *(r4 + 0x878) = *(r4 + 0x878)
loc_180:
 180:	d864143c 	ld.h	r3, (r4, 0x878)	// regs: r3=*(r4 + 0x878)
 184:	e46321fe 	andi	r3, r3, 510	// regs: r3=(*(r4 + 0x878) & 0x1fe)
 188:	e903010c 	bez	r3, 0x3a0	// if (r3 == 0x0) goto loc_3a0;
 18c:	e0000000 	bsr	0x0	// <lmac_cfp_timer_remain> // arg_bytes: 8; regs: r0=<ret lmac_cfp_timer_remain@0x18c>, r1=<clobbered>
 190:	7401      	zexth	r0, r0	// regs: r0=zext16(<ret lmac_cfp_timer_remain@0x18c>)
loc_192:
 192:	d844143c 	ld.h	r2, (r4, 0x878)	// regs: r2=*(r4 + 0x878)
 196:	9568      	ld.w	r3, (r5, 0x20)	// regs: r3=*(r5 + 0x20)
 198:	c4225502 	zext	r2, r2, 8, 1	// regs: r2=zext(*(r4 + 0x878))
 19c:	a342      	st.b	r2, (r3, 0x2)	// *((*(r5 + 0x20) + 0x2)) = zext(*(r4 + 0x878))
 19e:	4848      	lsri	r2, r0, 8	// regs: r2=(r0 >> 0x8)
 1a0:	a306      	st.b	r0, (r3, 0x6)	// *((*(r5 + 0x20) + 0x6)) = r0
 1a2:	a347      	st.b	r2, (r3, 0x7)	// *((*(r5 + 0x20) + 0x7)) = (r0 >> 0x8)
 1a4:	d924143c 	ld.h	r9, (r4, 0x878)	// regs: r9=*(r4 + 0x878)
 1a8:	e52921fe 	andi	r9, r9, 510	// regs: r9=(*(r4 + 0x878) & 0x1fe)
 1ac:	dc04143f 	st.h	r0, (r4, 0x87e)	// *(r4 + 0x87e) = r0
 1b0:	e9290031 	bnez	r9, 0x212	// if (r9 != 0x0) goto loc_212;
 1b4:	ea0800fa 	movi	r8, 250	// regs: r8=0xfa
 1b8:	400a      	lsli	r0, r0, 10	// regs: r0=(r0 << 0xa)
 1ba:	c4484828 	lsli	r8, r8, 2	// regs: r8=0x3e8
 1be:	c5008048 	divs	r8, r0, r8	// regs: r8=((r0 << 0xa) / 0x3e8)
 1c2:	e908001e 	bez	r8, 0x1fe	// if (r8 == 0x0) goto loc_1fe;
 1c6:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x1c6>, r1=<clobbered>
 1ca:	c4002483 	nor	r3, r0, r0	// regs: r3=(~(<ret os_jiffies@0x1c6> | <ret os_jiffies@0x1c6>))
 1ce:	660c      	cmphs	r3, r8
 1d0:	dc042220 	st.w	r0, (r4, 0x880)	// *(r4 + 0x880) = <ret os_jiffies@0x1c6>
 1d4:	dc242221 	st.w	r1, (r4, 0x884)	// *(r4 + 0x884) = <clobbered>
 1d8:	0ce7      	bf	0x3a6	// if (!T) goto loc_3a6;
 1da:	6ca3      	mov	r2, r8	// regs: r2=((r0 << 0xa) / 0x3e8)
 1dc:	6ce7      	mov	r3, r9	// regs: r3=(*(r4 + 0x878) & 0x1fe)
 1de:	6401      	cmplt	r0, r0
 1e0:	6009      	addc	r0, r2
 1e2:	604d      	addc	r1, r3
 1e4:	dc042222 	st.w	r0, (r4, 0x888)	// *(r4 + 0x888) = <ret os_jiffies@0x1c6>
 1e8:	dc242223 	st.w	r1, (r4, 0x88c)	// *(r4 + 0x88c) = <clobbered>
loc_1ec:
 1ec:	d8640878 	ld.b	r3, (r4, 0x878)	// regs: r3=*(r4 + 0x878)
 1f0:	3201      	movi	r2, 1	// regs: r2=0x1
 1f2:	c4625c00 	ins	r3, r2, 0, 0
 1f6:	dd04143f 	st.h	r8, (r4, 0x87e)	// *(r4 + 0x87e) = ((r0 << 0xa) / 0x3e8)
 1fa:	dc640878 	st.b	r3, (r4, 0x878)	// *(r4 + 0x878) = *(r4 + 0x878)
loc_1fe:
 1fe:	d8240364 	ld.b	r1, (r4, 0x364)	// regs: r1=*(r4 + 0x364)
 202:	e90100d9 	bez	r1, 0x3b4	// if (r1 == 0x0) goto loc_3b4;
 206:	d864143c 	ld.h	r3, (r4, 0x878)	// regs: r3=*(r4 + 0x878)
 20a:	c4615ce1 	ins	r3, r1, 8, 1
 20e:	dc64143c 	st.h	r3, (r4, 0x878)	// *(r4 + 0x878) = *(r4 + 0x878)
loc_212:
 212:	d86409dd 	ld.b	r3, (r4, 0x9dd)	// regs: r3=*(r4 + 0x9dd)
 216:	e443200f 	andi	r2, r3, 15	// regs: r2=(*(r4 + 0x9dd) & 0xf)
 21a:	e9020008 	bez	r2, 0x22a	// if (r2 == 0x0) goto loc_22a;
 21e:	e443000e 	addi	r2, r3, 15	// regs: r2=(*(r4 + 0x9dd) + 0xf)
 222:	c4625c60 	ins	r3, r2, 3, 0
 226:	dc6409dd 	st.b	r3, (r4, 0x9dd)	// *(r4 + 0x9dd) = *(r4 + 0x9dd)
loc_22a:
 22a:	d8640555 	ld.b	r3, (r4, 0x555)	// regs: r3=*(r4 + 0x555)
 22e:	e9230035 	bnez	r3, 0x298	// if (r3 != 0x0) goto loc_298;
 232:	d8641505 	ld.h	r3, (r4, 0xa0a)	// regs: r3=*(r4 + 0xa0a)
 236:	e9030031 	bez	r3, 0x298	// if (r3 == 0x0) goto loc_298;
 23a:	d8642277 	ld.w	r3, (r4, 0x9dc)	// regs: r3=*(r4 + 0x9dc)
 23e:	c5a35682 	zext	r2, r3, 20, 13	// regs: r2=zext(*(r4 + 0x9dc))
 242:	2200      	addi	r2, 1	// regs: r2=(zext(*(r4 + 0x9dc)) + 0x1)
 244:	c4625ced 	ins	r3, r2, 20, 13
 248:	dc642277 	st.w	r3, (r4, 0x9dc)	// *(r4 + 0x9dc) = *(r4 + 0x9dc)
 24c:	e0000000 	bsr	0x0	// <lmac_get_beacon_retry_limit>; regs: r0=<ret lmac_get_beacon_retry_limit@0x24c>, r1=<clobbered>
 250:	32ff      	movi	r2, 255	// regs: r2=0xff
 252:	d8642277 	ld.w	r3, (r4, 0x9dc)	// regs: r3=*(r4 + 0x9dc)
 256:	424d      	lsli	r2, r2, 13	// regs: r2=0x1fe000
 258:	68c8      	and	r3, r2	// regs: r3=(*(r4 + 0x9dc) & 0x1fe000)
 25a:	eb432000 	cmpnei	r3, 8192
 25e:	0803      	bt	0x264	// if (r3 != 0x2000) goto loc_264;
 260:	dcc421fb 	st.w	r6, (r4, 0x7ec)	// *(r4 + 0x7ec) = r6
loc_264:
 264:	5822      	addi	r1, r0, 1	// regs: r1=(<ret lmac_get_beacon_retry_limit@0x24c> + 0x1)
 266:	495f      	lsri	r2, r1, 31	// regs: r2=((<ret lmac_get_beacon_retry_limit@0x24c> + 0x1) >> 0x1f)
 268:	d8642277 	ld.w	r3, (r4, 0x9dc)	// regs: r3=*(r4 + 0x9dc)
 26c:	6084      	addu	r2, r1	// regs: r2=(((<ret lmac_get_beacon_retry_limit@0x24c> + 0x1) >> 0x1f) + (<ret lmac_get_beacon_retry_limit@0x24c> + 0x1))
 26e:	c5a35683 	zext	r3, r3, 20, 13	// regs: r3=zext(*(r4 + 0x9dc))
 272:	5241      	asri	r2, r2, 1	// regs: r2=((((<ret lmac_get_beacon_retry_limit@0x24c> + 0x1) >> 0x1f) + (<ret lmac_get_beacon_retry_limit@0x24c> + 0x1)) >> 0x1)
 274:	648e      	cmpne	r3, r2
 276:	0803      	bt	0x27c	// if (T) goto loc_27c;
 278:	dcc421fc 	st.w	r6, (r4, 0x7f0)	// *(r4 + 0x7f0) = r6
loc_27c:
 27c:	5843      	subi	r2, r0, 1	// regs: r2=(<ret lmac_get_beacon_retry_limit@0x24c> - 0x1)
 27e:	648e      	cmpne	r3, r2
 280:	0803      	bt	0x286	// if (T) goto loc_286;
 282:	dcc421fd 	st.w	r6, (r4, 0x7f4)	// *(r4 + 0x7f4) = r6
loc_286:
 286:	640d      	cmplt	r3, r0
 288:	0c9a      	bf	0x3bc	// if (!T) goto loc_3bc;
 28a:	d86409dd 	ld.b	r3, (r4, 0x9dd)	// regs: r3=*(r4 + 0x9dd)
 28e:	3201      	movi	r2, 1	// regs: r2=0x1
 290:	c4625c60 	ins	r3, r2, 3, 0
 294:	dc6409dd 	st.b	r3, (r4, 0x9dd)	// *(r4 + 0x9dd) = *(r4 + 0x9dd)
loc_298:
 298:	d8640555 	ld.b	r3, (r4, 0x555)	// regs: r3=*(r4 + 0x555)
 29c:	e9230010 	bnez	r3, 0x2bc	// if (r3 != 0x0) goto loc_2bc;
 2a0:	32ff      	movi	r2, 255	// regs: r2=0xff
 2a2:	d8642277 	ld.w	r3, (r4, 0x9dc)	// regs: r3=*(r4 + 0x9dc)
 2a6:	424d      	lsli	r2, r2, 13	// regs: r2=0x1fe000
 2a8:	68c8      	and	r3, r2	// regs: r3=(*(r4 + 0x9dc) & 0x1fe000)
 2aa:	e9230009 	bnez	r3, 0x2bc	// if (r3 != 0x0) goto loc_2bc;
 2ae:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(r4 + 0x319)
 2b2:	320f      	movi	r2, 15	// regs: r2=0xf
 2b4:	c4625c62 	ins	r3, r2, 5, 2
 2b8:	dc640319 	st.b	r3, (r4, 0x319)	// *(r4 + 0x319) = *(r4 + 0x319)
loc_2bc:
 2bc:	3001      	movi	r0, 1	// regs: r0=0x1
 2be:	e0000000 	bsr	0x0	// <lhw_cfg_dma_list_cnt>; regs: r0=<ret lhw_cfg_dma_list_cnt@0x2be>, r1=<clobbered>
 2c2:	9562      	ld.w	r3, (r5, 0x8)	// regs: r3=*(r5 + 0x8)
 2c4:	3000      	movi	r0, 0	// regs: r0=0x0
 2c6:	8b54      	ld.h	r2, (r3, 0x28)	// regs: r2=*((*(r5 + 0x8) + 0x28))
 2c8:	9327      	ld.w	r1, (r3, 0x1c)	// regs: r1=*((*(r5 + 0x8) + 0x1c))
 2ca:	e0000000 	bsr	0x0	// <lhw_cfg_tx_sub_frm>; regs: r0=<ret lhw_cfg_tx_sub_frm@0x2ca>, r1=<clobbered>
 2ce:	9542      	ld.w	r2, (r5, 0x8)	// regs: r2=*(r5 + 0x8)
 2d0:	9760      	ld.w	r3, (r7, 0x0)	// regs: r3=*(r7)
 2d2:	8a54      	ld.h	r2, (r2, 0x28)	// regs: r2=*((*(r5 + 0x8) + 0x28))
 2d4:	2203      	addi	r2, 4	// regs: r2=(*((*(r5 + 0x8) + 0x28)) + 0x4)
 2d6:	b35f      	st.w	r2, (r3, 0x7c)	// *((*(r7) + 0x7c)) = (*((*(r5 + 0x8) + 0x28)) + 0x4)
 2d8:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(r7) + 0x58))
 2da:	3a80      	bclri	r2, 0	// regs: r2=(*((*(r7) + 0x58)) & ~(0x1 << 0x0))
 2dc:	b356      	st.w	r2, (r3, 0x58)	// *((*(r7) + 0x58)) = (*((*(r7) + 0x58)) & ~(0x1 << 0x0))
 2de:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(r7) + 0x58))
 2e0:	b356      	st.w	r2, (r3, 0x58)	// *((*(r7) + 0x58)) = *((*(r7) + 0x58))
 2e2:	3300      	movi	r3, 0	// regs: r3=0x0
 2e4:	dc642294 	st.w	r3, (r4, 0xa50)	// *(r4 + 0xa50) = 0x0
 2e8:	e0000000 	bsr	0x0	// <lmac_cfg_txvec_part2> // arg_bytes: 0; regs: r0=<ret lmac_cfg_txvec_part2@0x2e8>, r1=<clobbered>
 2ec:	d86409dd 	ld.b	r3, (r4, 0x9dd)	// regs: r3=*(r4 + 0x9dd)
 2f0:	e463200f 	andi	r3, r3, 15	// regs: r3=(*(r4 + 0x9dd) & 0xf)
 2f4:	e923001d 	bnez	r3, 0x32e	// if (r3 != 0x0) goto loc_32e;
 2f8:	d864432a 	ld.bs	r3, (r4, 0x32a)	// regs: r3=*(r4 + 0x32a)
 2fc:	e9830019 	blz	r3, 0x32e	// if (r3 < 0x0) goto loc_32e;
 300:	e9230014 	bnez	r3, 0x328	// if (r3 != 0x0) goto loc_328;
 304:	9740      	ld.w	r2, (r7, 0x0)	// regs: r2=*(r7)
 306:	d8222033 	ld.w	r1, (r2, 0xcc)	// regs: r1=*((*(r7) + 0xcc))
 30a:	ec210800 	ori	r1, r1, 2048	// regs: r1=(*((*(r7) + 0xcc)) | 0x800)
 30e:	dc222033 	st.w	r1, (r2, 0xcc)	// *((*(r7) + 0xcc)) = (*((*(r7) + 0xcc)) | 0x800)
 312:	d824133a 	ld.h	r1, (r4, 0x674)	// regs: r1=*(r4 + 0x674)
 316:	214f      	addi	r1, 80	// regs: r1=(*(r4 + 0x674) + 0x50)
 318:	dc222036 	st.w	r1, (r2, 0xd8)	// *((*(r7) + 0xd8)) = (*(r4 + 0x674) + 0x50)
 31c:	d8222033 	ld.w	r1, (r2, 0xcc)	// regs: r1=*((*(r7) + 0xcc))
 320:	ec210400 	ori	r1, r1, 1024	// regs: r1=(*((*(r7) + 0xcc)) | 0x400)
 324:	dc222033 	st.w	r1, (r2, 0xcc)	// *((*(r7) + 0xcc)) = (*((*(r7) + 0xcc)) | 0x400)
loc_328:
 328:	2b00      	subi	r3, 1	// regs: r3=(*(r4 + 0x32a) - 0x1)
 32a:	dc64032a 	st.b	r3, (r4, 0x32a)	// *(r4 + 0x32a) = (*(r4 + 0x32a) - 0x1)
loc_32e:
 32e:	d804431e 	ld.bs	r0, (r4, 0x31e)	// regs: r0=*(r4 + 0x31e)
 332:	e0000000 	bsr	0x0	// <lmac_adjust_cca_threshold> // arg_bytes: 8; regs: r0=<ret lmac_adjust_cca_threshold@0x332>, r1=<clobbered>
 336:	3300      	movi	r3, 0	// regs: r3=0x0
 338:	dc642294 	st.w	r3, (r4, 0xa50)	// *(r4 + 0xa50) = 0x0
 33c:	1496      	pop	r4-r9, r15
 33e:	0000      	.short	0x0000
 340:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
 344:	00000000 	.long	0x00000000	// <ah_lmac>
 348:	00000000 	.long	0x00000000	// <LMAC>
 34c:	00000000 	.long	0x00000000	// <ah_lmac+0x9f8>
loc_350:
 350:	d8042196 	ld.w	r0, (r4, 0x658)	// regs: r0=*(r4 + 0x658)
 354:	9523      	ld.w	r1, (r5, 0xc)	// regs: r1=*(r5 + 0xc)
 356:	b304      	st.w	r0, (r3, 0x10)	// *(r3 + 0x10) = *(r4 + 0x658)
 358:	2109      	addi	r1, 10	// regs: r1=(*(r5 + 0xc) + 0xa)
 35a:	b3c5      	st.w	r6, (r3, 0x14)	// *(r3 + 0x14) = r6
 35c:	e0000000 	bsr	0x0	// <__put_unaligned_le32> // arg_bytes: 8; regs: r0=<ret __put_unaligned_le32@0x35c>, r1=<clobbered>
 360:	d86409df 	ld.b	r3, (r4, 0x9df)	// regs: r3=*(r4 + 0x9df)
 364:	3201      	movi	r2, 1	// regs: r2=0x1
 366:	c4625c05 	ins	r3, r2, 5, 5
 36a:	dc6409df 	st.b	r3, (r4, 0x9df)	// *(r4 + 0x9df) = *(r4 + 0x9df)
 36e:	d8640556 	ld.b	r3, (r4, 0x556)	// regs: r3=*(r4 + 0x556)
 372:	2b00      	subi	r3, 1	// regs: r3=(*(r4 + 0x556) - 0x1)
 374:	dc640555 	st.b	r3, (r4, 0x555)	// *(r4 + 0x555) = (*(r4 + 0x556) - 0x1)
 378:	dcc42197 	st.w	r6, (r4, 0x65c)	// *(r4 + 0x65c) = r6
 37c:	e0000000 	bsr	0x0	// <lmac_next_beacon_calc>; regs: r0=<ret lmac_next_beacon_calc@0x37c>, r1=<clobbered>
 380:	e0000000 	bsr	0x0	// <lmac_beacon_timer_start>; regs: r0=<ret lmac_beacon_timer_start@0x380>, r1=<clobbered>
 384:	0672      	br	0x68	// goto loc_68;
loc_386:
 386:	1012      	lrw	r0, 0x0	// regs: r0=0x0
 388:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x388>, r1=<clobbered>
 38c:	06a8      	br	0xdc	// goto loc_dc;
loc_38e:
 38e:	d8431034 	ld.h	r2, (r3, 0x68)	// regs: r2=*(r3 + 0x68)
 392:	3a1f      	cmphsi	r2, 32
 394:	0804      	bt	0x39c	// if (r2 >= 0x20) goto loc_39c;
 396:	c4404022 	lsl	r2, r0, r2
 39a:	6e48      	or	r9, r2	// regs: r9=(r9 | *(r3 + 0x68))
loc_39c:
 39c:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(r3)
 39e:	06c3      	br	0x124	// goto loc_124;
loc_3a0:
 3a0:	d804143e 	ld.h	r0, (r4, 0x87c)	// regs: r0=*(r4 + 0x87c)
 3a4:	06f7      	br	0x192	// goto loc_192;
loc_3a6:
 3a6:	c4680083 	subu	r3, r8, r3	// regs: r3=(((r0 << 0xa) / 0x3e8) - (~(<ret os_jiffies@0x1c6> | <ret os_jiffies@0x1c6>)))
 3aa:	dc642222 	st.w	r3, (r4, 0x888)	// *(r4 + 0x888) = (((r0 << 0xa) / 0x3e8) - (~(<ret os_jiffies@0x1c6> | <ret os_jiffies@0x1c6>)))
 3ae:	dd242223 	st.w	r9, (r4, 0x88c)	// *(r4 + 0x88c) = (*(r4 + 0x878) & 0x1fe)
 3b2:	071d      	br	0x1ec	// goto loc_1ec;
loc_3b4:
 3b4:	1007      	lrw	r0, 0x0	// regs: r0=0x0
 3b6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x3b6>, r1=<clobbered>
 3ba:	072c      	br	0x212	// goto loc_212;
loc_3bc:
 3bc:	d8642277 	ld.w	r3, (r4, 0x9dc)	// regs: r3=*(r4 + 0x9dc)
 3c0:	3200      	movi	r2, 0	// regs: r2=0x0
 3c2:	c4625ced 	ins	r3, r2, 20, 13
 3c6:	dc642277 	st.w	r3, (r4, 0x9dc)	// *(r4 + 0x9dc) = *(r4 + 0x9dc)
 3ca:	0767      	br	0x298	// goto loc_298;
 3cc:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_beacon.str1.1>
 3d0:	0000      	.short	0x0000	// <.rodata.lmac_tx_beacon.str1.1+0x17>
 3d2:	0000      	.short	0x0000

Disassembly of section .text.lmac_irq_bo_fns:

00000000 <lmac_irq_bo_fns>: // arg_bytes: 4
   0:	14d5      	push	r4-r8, r15
   2:	ea88000d 	lrw	r8, 0x0	// regs: r8=0x0
   6:	3220      	movi	r2, 32	// regs: r2=0x20
   8:	d8682000 	ld.w	r3, (r8, 0x0)	// regs: r3=*(0x0)
   c:	3100      	movi	r1, 0	// regs: r1=0x0
   e:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x20
  10:	32ff      	movi	r2, 255	// regs: r2=0xff
  12:	10ca      	lrw	r6, 0x0	// regs: r6=0x0
  14:	4244      	lsli	r2, r2, 4	// regs: r2=0xff0
  16:	b328      	st.w	r1, (r3, 0x20)	// *((*(0x0) + 0x20)) = 0x0
  18:	dc43202f 	st.w	r2, (r3, 0xbc)	// *((*(0x0) + 0xbc)) = 0xff0
  1c:	d8662265 	ld.w	r3, (r6, 0x994)	// regs: r3=*(0x994)
  20:	2b00      	subi	r3, 1	// regs: r3=(*(0x994) - 0x1)
  22:	3b09      	cmphsi	r3, 10
  24:	dc262266 	st.w	r1, (r6, 0x998)	// *(0x998) = 0x0
  28:	1085      	lrw	r4, 0x0	// regs: r4=0x0
  2a:	09cd      	bt	0x3c4	// if (r3 >= 0xa) goto loc_3c4;
  2c:	1045      	lrw	r2, 0x0	// regs: r2=0x0
  2e:	d0620883 	ldr.w	r3, (r2, r3 << 2)	// regs: r3=*(0x0 + ((*(0x994) - 0x1) << 2))
  32:	780c      	jmp	r3	// goto *r3;
  34:	0000      	.short	0x0000	// <LMAC>
  36:	0000      	.short	0x0000
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000
  3c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  40:	0000      	.short	0x0000	// <.rodata.lmac_irq_bo_fns>
  42:	0000      	.short	0x0000
  44:	e0000000 	bsr	0x0	// <lmac_tx_ack> // arg_bytes: 0; regs: r0=<ret lmac_tx_ack@0x44>, r1=<clobbered>
loc_48:
  48:	3304      	movi	r3, 4	// regs: r3=0x4
loc_4a:
  4a:	dc662266 	st.w	r3, (r6, 0x998)	// *(r6 + 0x998) = r3
  4e:	0409      	br	0x60	// goto loc_60;
  50:	e0000000 	bsr	0x0	// <lmac_tx_ba> // arg_bytes: 0; regs: r0=<ret lmac_tx_ba@0x50>, r1=<clobbered>
  54:	d866092a 	ld.b	r3, (r6, 0x92a)	// regs: r3=*(r6 + 0x92a)
  58:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(r6 + 0x92a) & 0x8)
  5c:	e903fff6 	bez	r3, 0x48	// if (r3 == 0x0) goto loc_48;
loc_60:
  60:	d86609e2 	ld.b	r3, (r6, 0x9e2)	// regs: r3=*(r6 + 0x9e2)
  64:	3200      	movi	r2, 0	// regs: r2=0x0
  66:	c4625c05 	ins	r3, r2, 5, 5
  6a:	dc6609e2 	st.b	r3, (r6, 0x9e2)	// *(r6 + 0x9e2) = *(r6 + 0x9e2)
  6e:	9461      	ld.w	r3, (r4, 0x4)	// regs: r3=*(r4 + 0x4)
  70:	d84621d3 	ld.w	r2, (r6, 0x74c)	// regs: r2=*(r6 + 0x74c)
  74:	9361      	ld.w	r3, (r3, 0x4)	// regs: r3=*((*(r4 + 0x4) + 0x4))
  76:	60c8      	addu	r3, r2	// regs: r3=(*((*(r4 + 0x4) + 0x4)) + *(r6 + 0x74c))
  78:	dc6621d3 	st.w	r3, (r6, 0x74c)	// *(r6 + 0x74c) = (*((*(r4 + 0x4) + 0x4)) + *(r6 + 0x74c))
  7c:	d84620f1 	ld.w	r2, (r6, 0x3c4)	// regs: r2=*(r6 + 0x3c4)
  80:	d86620f0 	ld.w	r3, (r6, 0x3c0)	// regs: r3=*(r6 + 0x3c0)
  84:	6cc8      	or	r3, r2	// regs: r3=(*(r6 + 0x3c0) | *(r6 + 0x3c4))
  86:	e9030008 	bez	r3, 0x96	// if (r3 == 0x0) goto loc_96;
  8a:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x8a>, r1=<clobbered>
  8e:	dc0620f0 	st.w	r0, (r6, 0x3c0)	// *(r6 + 0x3c0) = <ret os_jiffies@0x8a>
  92:	dc2620f1 	st.w	r1, (r6, 0x3c4)	// *(r6 + 0x3c4) = <clobbered>
loc_96:
  96:	d86620f3 	ld.w	r3, (r6, 0x3cc)	// regs: r3=*(r6 + 0x3cc)
  9a:	d84620f4 	ld.w	r2, (r6, 0x3d0)	// regs: r2=*(r6 + 0x3d0)
  9e:	6cc8      	or	r3, r2	// regs: r3=(*(r6 + 0x3cc) | *(r6 + 0x3d0))
  a0:	e9030008 	bez	r3, 0xb0	// if (r3 == 0x0) goto loc_b0;
  a4:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0xa4>, r1=<clobbered>
  a8:	dc0620f3 	st.w	r0, (r6, 0x3cc)	// *(r6 + 0x3cc) = <ret os_jiffies@0xa4>
  ac:	dc2620f4 	st.w	r1, (r6, 0x3d0)	// *(r6 + 0x3d0) = <clobbered>
loc_b0:
  b0:	1495      	pop	r4-r8, r15
  b2:	e0000000 	bsr	0x0	// <lmac_tx_rts> // arg_bytes: 0; regs: r0=<ret lmac_tx_rts@0xb2>, r1=<clobbered>
  b6:	d86621cb 	ld.w	r3, (r6, 0x72c)	// regs: r3=*(r6 + 0x72c)
  ba:	2300      	addi	r3, 1	// regs: r3=(*(r6 + 0x72c) + 0x1)
  bc:	dc6621cb 	st.w	r3, (r6, 0x72c)	// *(r6 + 0x72c) = (*(r6 + 0x72c) + 0x1)
  c0:	3302      	movi	r3, 2	// regs: r3=0x2
  c2:	07c4      	br	0x4a	// goto loc_4a;
  c4:	e0000000 	bsr	0x0	// <lmac_tx_cts> // arg_bytes: 0; regs: r0=<ret lmac_tx_cts@0xc4>, r1=<clobbered>
  c8:	07cc      	br	0x60	// goto loc_60;
  ca:	e0000000 	bsr	0x0	// <lmac_tx_pv0_cfpoll> // arg_bytes: 0; regs: r0=<ret lmac_tx_pv0_cfpoll@0xca>, r1=<clobbered>
  ce:	3303      	movi	r3, 3	// regs: r3=0x3
  d0:	07bd      	br	0x4a	// goto loc_4a;
  d2:	e0000000 	bsr	0x0	// <lmac_tx_pv0_cfend> // arg_bytes: 0; regs: r0=<ret lmac_tx_pv0_cfend@0xd2>, r1=<clobbered>
  d6:	07c5      	br	0x60	// goto loc_60;
  d8:	e0000000 	bsr	0x0	// <lmac_tx_pv0_null> // arg_bytes: 0; regs: r0=<ret lmac_tx_pv0_null@0xd8>, r1=<clobbered>
  dc:	d86620ee 	ld.w	r3, (r6, 0x3b8)	// regs: r3=*(r6 + 0x3b8)
  e0:	e4632080 	andi	r3, r3, 128	// regs: r3=(*(r6 + 0x3b8) & 0x80)
  e4:	e9030005 	bez	r3, 0xee	// if (r3 == 0x0) goto loc_ee;
  e8:	0204      	lrw	r0, 0x0	// regs: r0=0x0
  ea:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xea>, r1=<clobbered>
loc_ee:
  ee:	3305      	movi	r3, 5	// regs: r3=0x5
  f0:	07ad      	br	0x4a	// goto loc_4a;
  f2:	e0000000 	bsr	0x0	// <lmac_tx_pv0_pspoll> // arg_bytes: 0; regs: r0=<ret lmac_tx_pv0_pspoll@0xf2>, r1=<clobbered>
  f6:	d86620ee 	ld.w	r3, (r6, 0x3b8)	// regs: r3=*(r6 + 0x3b8)
  fa:	e4632080 	andi	r3, r3, 128	// regs: r3=(*(r6 + 0x3b8) & 0x80)
  fe:	e9030005 	bez	r3, 0x108	// if (r3 == 0x0) goto loc_108;
 102:	0209      	lrw	r0, 0x0	// regs: r0=0x0
 104:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x104>, r1=<clobbered>
loc_108:
 108:	3306      	movi	r3, 6	// regs: r3=0x6
 10a:	07a0      	br	0x4a	// goto loc_4a;
 10c:	e0000000 	bsr	0x0	// <lmac_tx_frm> // arg_bytes: 0; regs: r0=<ret lmac_tx_frm@0x10c>, r1=<clobbered>
 110:	d8a609dc 	ld.b	r5, (r6, 0x9dc)	// regs: r5=*(r6 + 0x9dc)
 114:	3290      	movi	r2, 144	// regs: r2=0x90
 116:	e4a5200f 	andi	r5, r5, 15	// regs: r5=(*(r6 + 0x9dc) & 0xf)
 11a:	4241      	lsli	r2, r2, 1	// regs: r2=0x120
 11c:	7c94      	mult	r2, r5	// regs: r2=(0x120 * (*(r6 + 0x9dc) & 0xf))
 11e:	6090      	addu	r2, r4	// regs: r2=((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4)
 120:	d86621d0 	ld.w	r3, (r6, 0x740)	// regs: r3=*(r6 + 0x740)
 124:	2300      	addi	r3, 1	// regs: r3=(*(r6 + 0x740) + 0x1)
 126:	dc6621d0 	st.w	r3, (r6, 0x740)	// *(r6 + 0x740) = (*(r6 + 0x740) + 0x1)
 12a:	d80201c4 	ld.b	r0, (r2, 0x1c4)	// regs: r0=*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1c4))
 12e:	d86621d1 	ld.w	r3, (r6, 0x744)	// regs: r3=*(r6 + 0x744)
 132:	60c0      	addu	r3, r0	// regs: r3=(*(r6 + 0x744) + *((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1c4)))
 134:	dc6621d1 	st.w	r3, (r6, 0x744)	// *(r6 + 0x744) = (*(r6 + 0x744) + *((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1c4)))
 138:	d9a2206e 	ld.w	r13, (r2, 0x1b8)	// regs: r13=*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1b8))
 13c:	d86621d2 	ld.w	r3, (r6, 0x748)	// regs: r3=*(r6 + 0x748)
 140:	60f4      	addu	r3, r13	// regs: r3=(*(r6 + 0x748) + *((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1b8)))
 142:	dc6621d2 	st.w	r3, (r6, 0x748)	// *(r6 + 0x748) = (*(r6 + 0x748) + *((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1b8)))
 146:	d82412b0 	ld.h	r1, (r4, 0x560)	// regs: r1=*(r4 + 0x560)
 14a:	d86412b1 	ld.h	r3, (r4, 0x562)	// regs: r3=*(r4 + 0x562)
 14e:	604c      	addu	r1, r3	// regs: r1=(*(r4 + 0x560) + *(r4 + 0x562))
 150:	d86621d4 	ld.w	r3, (r6, 0x750)	// regs: r3=*(r6 + 0x750)
 154:	60c4      	addu	r3, r1	// regs: r3=(*(r6 + 0x750) + (*(r4 + 0x560) + *(r4 + 0x562)))
 156:	dc6621d4 	st.w	r3, (r6, 0x750)	// *(r6 + 0x750) = (*(r6 + 0x750) + (*(r4 + 0x560) + *(r4 + 0x562)))
 15a:	d862202e 	ld.w	r3, (r2, 0xb8)	// regs: r3=*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8))
 15e:	93e8      	ld.w	r7, (r3, 0x20)	// regs: r7=*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20))
 160:	9763      	ld.w	r3, (r7, 0xc)	// regs: r3=*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc))
 162:	e903003a 	bez	r3, 0x1d6	// if (r3 == 0x0) goto loc_1d6;
 166:	d98310e2 	ld.h	r12, (r3, 0x1c4)	// regs: r12=*((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1c4))
 16a:	e58c0000 	addi	r12, r12, 1	// regs: r12=(*((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1c4)) + 0x1)
 16e:	dc662294 	st.w	r3, (r6, 0xa50)	// *(r6 + 0xa50) = *((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc))
 172:	dd8310e2 	st.h	r12, (r3, 0x1c4)	// *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1c4)) = (*((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1c4)) + 0x1)
 176:	d98310e3 	ld.h	r12, (r3, 0x1c6)	// regs: r12=*((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1c6))
 17a:	6030      	addu	r0, r12	// regs: r0=(*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1c4)) + *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1c6)))
 17c:	dc0310e3 	st.h	r0, (r3, 0x1c6)	// *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1c6)) = (*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1c4)) + *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1c6)))
 180:	d8032072 	ld.w	r0, (r3, 0x1c8)	// regs: r0=*((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1c8))
 184:	6034      	addu	r0, r13	// regs: r0=(*((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1c8)) + *((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1b8)))
 186:	d842206f 	ld.w	r2, (r2, 0x1bc)	// regs: r2=*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1bc))
 18a:	dc032072 	st.w	r0, (r3, 0x1c8)	// *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1c8)) = (*((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1c8)) + *((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1b8)))
 18e:	d8032073 	ld.w	r0, (r3, 0x1cc)	// regs: r0=*((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1cc))
 192:	6080      	addu	r2, r0	// regs: r2=(*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1bc)) + *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1cc)))
 194:	dc432073 	st.w	r2, (r3, 0x1cc)	// *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1cc)) = (*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0x1bc)) + *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1cc)))
 198:	d8432074 	ld.w	r2, (r3, 0x1d0)	// regs: r2=*((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1d0))
 19c:	6048      	addu	r1, r2	// regs: r1=((*(r4 + 0x560) + *(r4 + 0x562)) + *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1d0)))
 19e:	d8482000 	ld.w	r2, (r8, 0x0)	// regs: r2=*(r8)
 1a2:	dc232074 	st.w	r1, (r3, 0x1d0)	// *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1d0)) = ((*(r4 + 0x560) + *(r4 + 0x562)) + *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0x1d0)))
 1a6:	9219      	ld.w	r0, (r2, 0x64)	// regs: r0=*((*(r8) + 0x64))
 1a8:	d82300b1 	ld.b	r1, (r3, 0xb1)	// regs: r1=*((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0xb1))
 1ac:	c4205c40 	ins	r1, r0, 2, 0
 1b0:	dc2300b1 	st.b	r1, (r3, 0xb1)	// *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0xb1)) = *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0xb1))
 1b4:	9239      	ld.w	r1, (r2, 0x64)	// regs: r1=*((*(r8) + 0x64))
 1b6:	c4c154e1 	zext	r1, r1, 7, 6	// regs: r1=zext(*((*(r8) + 0x64)))
 1ba:	d80300af 	ld.b	r0, (r3, 0xaf)	// regs: r0=*((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0xaf))
 1be:	c4015c64 	ins	r0, r1, 7, 4
 1c2:	dc0300af 	st.b	r0, (r3, 0xaf)	// *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0xaf)) = *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0xaf))
 1c6:	9259      	ld.w	r2, (r2, 0x64)	// regs: r2=*((*(r8) + 0x64))
 1c8:	d82300ae 	ld.b	r1, (r3, 0xae)	// regs: r1=*((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0xae))
 1cc:	4a4c      	lsri	r2, r2, 12	// regs: r2=(*((*(r8) + 0x64)) >> 0xc)
 1ce:	c4225c60 	ins	r1, r2, 3, 0
 1d2:	dc2300ae 	st.b	r1, (r3, 0xae)	// *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0xae)) = *((*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0xc)) + 0xae))
loc_1d6:
 1d6:	8f73      	ld.h	r3, (r7, 0x26)	// regs: r3=*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0x26))
 1d8:	e4632280 	andi	r3, r3, 640	// regs: r3=(*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0x26)) & 0x280)
 1dc:	eb430280 	cmpnei	r3, 640
 1e0:	0814      	bt	0x208	// if (r3 != 0x280) goto loc_208;
 1e2:	d8482000 	ld.w	r2, (r8, 0x0)	// regs: r2=*(r8)
 1e6:	d826070f 	ld.b	r1, (r6, 0x70f)	// regs: r1=*(r6 + 0x70f)
 1ea:	9279      	ld.w	r3, (r2, 0x64)	// regs: r3=*((*(r8) + 0x64))
 1ec:	c4c354e3 	zext	r3, r3, 7, 6	// regs: r3=zext(*((*(r8) + 0x64)))
 1f0:	c4235c60 	ins	r1, r3, 3, 0
 1f4:	dc26070f 	st.b	r1, (r6, 0x70f)	// *(r6 + 0x70f) = *(r6 + 0x70f)
 1f8:	9279      	ld.w	r3, (r2, 0x64)	// regs: r3=*((*(r8) + 0x64))
 1fa:	4b6c      	lsri	r3, r3, 12	// regs: r3=(*((*(r8) + 0x64)) >> 0xc)
 1fc:	d846070f 	ld.b	r2, (r6, 0x70f)	// regs: r2=*(r6 + 0x70f)
 200:	c4435c64 	ins	r2, r3, 7, 4
 204:	dc46070f 	st.b	r2, (r6, 0x70f)	// *(r6 + 0x70f) = *(r6 + 0x70f)
loc_208:
 208:	d8482000 	ld.w	r2, (r8, 0x0)	// regs: r2=*(r8)
 20c:	9279      	ld.w	r3, (r2, 0x64)	// regs: r3=*((*(r8) + 0x64))
 20e:	c5435563 	zext	r3, r3, 11, 10	// regs: r3=zext(*((*(r8) + 0x64)))
 212:	e9030007 	bez	r3, 0x220	// if (r3 == 0x0) goto loc_220;
 216:	9279      	ld.w	r3, (r2, 0x64)	// regs: r3=*((*(r8) + 0x64))
 218:	4b66      	lsri	r3, r3, 6	// regs: r3=(*((*(r8) + 0x64)) >> 0x6)
 21a:	2300      	addi	r3, 1	// regs: r3=((*((*(r8) + 0x64)) >> 0x6) + 0x1)
 21c:	e4632003 	andi	r3, r3, 3	// regs: r3=(((*((*(r8) + 0x64)) >> 0x6) + 0x1) & 0x3)
loc_220:
 220:	9259      	ld.w	r2, (r2, 0x64)	// regs: r2=*((*(r8) + 0x64))
 222:	c58255c2 	zext	r2, r2, 14, 12	// regs: r2=zext(*((*(r8) + 0x64)))
 226:	4363      	lsli	r3, r3, 3	// regs: r3=(r3 << 0x3)
 228:	60c8      	addu	r3, r2	// regs: r3=((r3 << 0x3) + zext(*((*(r8) + 0x64))))
 22a:	134d      	lrw	r2, 0x0	// regs: r2=0x0
 22c:	ea0c0064 	movi	r12, 100	// regs: r12=0x64
 230:	d0620443 	ldr.h	r3, (r2, r3 << 1)	// regs: r3=*(0x0 + (((r3 << 0x3) + zext(*((*(r8) + 0x64)))) << 1))
 234:	d846483d 	ld.bs	r2, (r6, 0x83d)	// regs: r2=*(r6 + 0x83d)
 238:	c44c0082 	subu	r2, r12, r2	// regs: r2=(0x64 - *(r6 + 0x83d))
 23c:	74cd      	zexth	r3, r3	// regs: r3=zext16(*(0x0 + (((r3 << 0x3) + zext(*((*(r8) + 0x64)))) << 1)))
 23e:	7cc8      	mult	r3, r2	// regs: r3=(zext16(*(0x0 + (((r3 << 0x3) + zext(*((*(r8) + 0x64)))) << 1))) * (0x64 - *(r6 + 0x83d)))
 240:	c5838040 	divs	r0, r3, r12	// regs: r0=((zext16(*(0x0 + (((r3 << 0x3) + zext(*((*(r8) + 0x64)))) << 1))) * (0x64 - *(r6 + 0x83d))) / 0x64)
 244:	503f      	asri	r1, r0, 31	// regs: r1=(((zext16(*(0x0 + (((r3 << 0x3) + zext(*((*(r8) + 0x64)))) << 1))) * (0x64 - *(r6 + 0x83d))) / 0x64) >> 0x1f)
 246:	d8462204 	ld.w	r2, (r6, 0x810)	// regs: r2=*(r6 + 0x810)
 24a:	d8662205 	ld.w	r3, (r6, 0x814)	// regs: r3=*(r6 + 0x814)
 24e:	6489      	cmplt	r2, r2
 250:	6081      	addc	r2, r0
 252:	60c5      	addc	r3, r1
 254:	dc462204 	st.w	r2, (r6, 0x810)	// *(r6 + 0x810) = *(r6 + 0x810)
 258:	dc662205 	st.w	r3, (r6, 0x814)	// *(r6 + 0x814) = *(r6 + 0x814)
 25c:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x25c>, r1=<clobbered>
 260:	d8462202 	ld.w	r2, (r6, 0x808)	// regs: r2=*(r6 + 0x808)
 264:	d8662203 	ld.w	r3, (r6, 0x80c)	// regs: r3=*(r6 + 0x80c)
 268:	d987200d 	ld.w	r12, (r7, 0x34)	// regs: r12=*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0x34))
 26c:	d9a7200e 	ld.w	r13, (r7, 0x38)	// regs: r13=*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0x38))
 270:	6488      	cmphs	r2, r2
 272:	60b3      	subc	r2, r12
 274:	60f7      	subc	r3, r13
 276:	6489      	cmplt	r2, r2
 278:	6081      	addc	r2, r0
 27a:	60c5      	addc	r3, r1
 27c:	dc462202 	st.w	r2, (r6, 0x808)	// *(r6 + 0x808) = *(r6 + 0x808)
 280:	dc662203 	st.w	r3, (r6, 0x80c)	// *(r6 + 0x80c) = *(r6 + 0x80c)
 284:	9762      	ld.w	r3, (r7, 0x8)	// regs: r3=*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0x8))
 286:	e4432002 	andi	r2, r3, 2	// regs: r2=(*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0x8)) & 0x2)
 28a:	e9220046 	bnez	r2, 0x316	// if (r2 != 0x0) goto loc_316;
loc_28e:
 28e:	e4632008 	andi	r3, r3, 8	// regs: r3=(*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0x8)) & 0x8)
 292:	e903002c 	bez	r3, 0x2ea	// if (r3 == 0x0) goto loc_2ea;
 296:	d8660a4f 	ld.b	r3, (r6, 0xa4f)	// regs: r3=*(r6 + 0xa4f)
 29a:	3201      	movi	r2, 1	// regs: r2=0x1
 29c:	c4625c03 	ins	r3, r2, 3, 3
 2a0:	d82620ea 	ld.w	r1, (r6, 0x3a8)	// regs: r1=*(r6 + 0x3a8)
 2a4:	120f      	lrw	r0, 0x0	// regs: r0=0x0
 2a6:	dc660a4f 	st.b	r3, (r6, 0xa4f)	// *(r6 + 0xa4f) = *(r6 + 0xa4f)
 2aa:	e0000000 	bsr	0x0	// <os_timer_start>; regs: r0=<ret os_timer_start@0x2aa>, r1=<clobbered>
 2ae:	d86620ee 	ld.w	r3, (r6, 0x3b8)	// regs: r3=*(r6 + 0x3b8)
 2b2:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(r6 + 0x3b8) & 0x8)
 2b6:	e903001a 	bez	r3, 0x2ea	// if (r3 == 0x0) goto loc_2ea;
 2ba:	d8260340 	ld.b	r1, (r6, 0x340)	// regs: r1=*(r6 + 0x340)
 2be:	120a      	lrw	r0, 0x0	// regs: r0=0x0
 2c0:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2c0>, r1=<clobbered>
 2c4:	1269      	lrw	r3, 0x0	// regs: r3=0x0
 2c6:	d847003f 	ld.b	r2, (r7, 0x3f)	// regs: r2=*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0x3f))
 2ca:	d8234000 	ld.bs	r1, (r3, 0x0)	// regs: r1=*(0x0)
 2ce:	e442201f 	andi	r2, r2, 31	// regs: r2=(*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0x3f)) & 0x1f)
 2d2:	6486      	cmpne	r1, r2
 2d4:	6e0f      	mov	r8, r3	// regs: r8=0x0
 2d6:	0804      	bt	0x2de	// if (T) goto loc_2de;
 2d8:	1205      	lrw	r0, 0x0	// regs: r0=0x0
 2da:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2da>, r1=<clobbered>
loc_2de:
 2de:	d867003f 	ld.b	r3, (r7, 0x3f)	// regs: r3=*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0x3f))
 2e2:	c4035483 	zext	r3, r3, 4, 0	// regs: r3=zext(*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0x3f)))
 2e6:	dc680000 	st.b	r3, (r8, 0x0)	// *(0x0) = zext(*((*((*((((0x120 * (*(r6 + 0x9dc) & 0xf)) + r4) + 0xb8)) + 0x20)) + 0x3f)))
loc_2ea:
 2ea:	3390      	movi	r3, 144	// regs: r3=0x90
 2ec:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
 2ee:	7d4c      	mult	r5, r3	// regs: r5=((*(r6 + 0x9dc) & 0xf) * 0x120)
 2f0:	5c74      	addu	r3, r4, r5	// regs: r3=(r4 + ((*(r6 + 0x9dc) & 0xf) * 0x120))
 2f2:	3200      	movi	r2, 0	// regs: r2=0x0
 2f4:	d80301c4 	ld.b	r0, (r3, 0x1c4)	// regs: r0=*(((r4 + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + 0x1c4))
 2f8:	ea0c0001 	movi	r12, 1	// regs: r12=0x1
loc_2fc:
 2fc:	6409      	cmplt	r2, r0
 2fe:	0818      	bt	0x32e	// if (T) goto loc_32e;
 300:	d866227e 	ld.w	r3, (r6, 0x9f8)	// regs: r3=*(r6 + 0x9f8)
 304:	113b      	lrw	r1, 0x0	// regs: r1=0x0
 306:	3000      	movi	r0, 0	// regs: r0=0x0
loc_308:
 308:	644e      	cmpne	r3, r1
 30a:	0832      	bt	0x36e	// if (T) goto loc_36e;
 30c:	3300      	movi	r3, 0	// regs: r3=0x0
 30e:	dc661506 	st.h	r3, (r6, 0xa0c)	// *(r6 + 0xa0c) = 0x0
 312:	3301      	movi	r3, 1	// regs: r3=0x1
 314:	069b      	br	0x4a	// goto loc_4a;
loc_316:
 316:	3200      	movi	r2, 0	// regs: r2=0x0
 318:	6c4b      	mov	r1, r2	// regs: r1=0x0
 31a:	297f      	subi	r1, 128	// regs: r1=0xffffff80
loc_31c:
 31c:	1116      	lrw	r0, 0x0	// regs: r0=0x0
 31e:	6008      	addu	r0, r2	// regs: r0=(0x0 + r2)
 320:	220b      	addi	r2, 12	// regs: r2=(r2 + 0xc)
 322:	eb4200c0 	cmpnei	r2, 192
 326:	dc200247 	st.b	r1, (r0, 0x247)	// *(((0x0 + r2) + 0x247)) = 0xffffff80
 32a:	0bf9      	bt	0x31c	// if (r2 != 0xc0) goto loc_31c;
 32c:	07b1      	br	0x28e	// goto loc_28e;
loc_32e:
 32e:	4262      	lsli	r3, r2, 2	// regs: r3=(r2 << 0x2)
 330:	60d4      	addu	r3, r5	// regs: r3=((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120))
 332:	60d0      	addu	r3, r4	// regs: r3=(((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4)
 334:	d863202e 	ld.w	r3, (r3, 0xb8)	// regs: r3=*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8))
 338:	9368      	ld.w	r3, (r3, 0x20)	// regs: r3=*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20))
 33a:	d8230025 	ld.b	r1, (r3, 0x25)	// regs: r1=*((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x25))
 33e:	e4212002 	andi	r1, r1, 2	// regs: r1=(*((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x25)) & 0x2)
 342:	e9010008 	bez	r1, 0x352	// if (r1 == 0x0) goto loc_352;
 346:	d8230027 	ld.b	r1, (r3, 0x27)	// regs: r1=*((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x27))
 34a:	c42c5c07 	ins	r1, r12, 7, 7
 34e:	dc230027 	st.b	r1, (r3, 0x27)	// *((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x27)) = *((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x27))
loc_352:
 352:	d8230028 	ld.b	r1, (r3, 0x28)	// regs: r1=*((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x28))
 356:	2100      	addi	r1, 1	// regs: r1=(*((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x28)) + 0x1)
 358:	dc230028 	st.b	r1, (r3, 0x28)	// *((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x28)) = (*((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x28)) + 0x1)
 35c:	d823002c 	ld.b	r1, (r3, 0x2c)	// regs: r1=*((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x2c))
 360:	e9010005 	bez	r1, 0x36a	// if (r1 == 0x0) goto loc_36a;
 364:	2900      	subi	r1, 1	// regs: r1=(*((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x2c)) - 0x1)
 366:	dc23002c 	st.b	r1, (r3, 0x2c)	// *((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x2c)) = (*((*((*(((((r2 << 0x2) + ((*(r6 + 0x9dc) & 0xf) * 0x120)) + r4) + 0xb8)) + 0x20)) + 0x2c)) - 0x1)
loc_36a:
 36a:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
 36c:	07c8      	br	0x2fc	// goto loc_2fc;
loc_36e:
 36e:	d843006b 	ld.b	r2, (r3, 0x6b)	// regs: r2=*(r3 + 0x6b)
 372:	c4405c03 	ins	r2, r0, 3, 3
 376:	dc43006b 	st.b	r2, (r3, 0x6b)	// *(r3 + 0x6b) = *(r3 + 0x6b)
 37a:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(r3)
 37c:	07c6      	br	0x308	// goto loc_308;
 37e:	e0000000 	bsr	0x0	// <lmac_tx_beacon> // arg_bytes: 4; regs: r0=<ret lmac_tx_beacon@0x37e>, r1=<clobbered>
 382:	d86620ee 	ld.w	r3, (r6, 0x3b8)	// regs: r3=*(r6 + 0x3b8)
 386:	e4632080 	andi	r3, r3, 128	// regs: r3=(*(r6 + 0x3b8) & 0x80)
 38a:	e9030005 	bez	r3, 0x394	// if (r3 == 0x0) goto loc_394;
 38e:	101b      	lrw	r0, 0x0	// regs: r0=0x0
 390:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x390>, r1=<clobbered>
loc_394:
 394:	d86609dd 	ld.b	r3, (r6, 0x9dd)	// regs: r3=*(r6 + 0x9dd)
 398:	e463200f 	andi	r3, r3, 15	// regs: r3=(*(r6 + 0x9dd) & 0xf)
 39c:	e9230009 	bnez	r3, 0x3ae	// if (r3 != 0x0) goto loc_3ae;
 3a0:	d8661505 	ld.h	r3, (r6, 0xa0a)	// regs: r3=*(r6 + 0xa0a)
 3a4:	e9230005 	bnez	r3, 0x3ae	// if (r3 != 0x0) goto loc_3ae;
 3a8:	3304      	movi	r3, 4	// regs: r3=0x4
 3aa:	dc662266 	st.w	r3, (r6, 0x998)	// *(r6 + 0x998) = 0x4
loc_3ae:
 3ae:	d86621d0 	ld.w	r3, (r6, 0x740)	// regs: r3=*(r6 + 0x740)
 3b2:	2300      	addi	r3, 1	// regs: r3=(*(r6 + 0x740) + 0x1)
 3b4:	dc6621d0 	st.w	r3, (r6, 0x740)	// *(r6 + 0x740) = (*(r6 + 0x740) + 0x1)
 3b8:	d86621cc 	ld.w	r3, (r6, 0x730)	// regs: r3=*(r6 + 0x730)
 3bc:	2300      	addi	r3, 1	// regs: r3=(*(r6 + 0x730) + 0x1)
 3be:	dc6621cc 	st.w	r3, (r6, 0x730)	// *(r6 + 0x730) = (*(r6 + 0x730) + 0x1)
 3c2:	064f      	br	0x60	// goto loc_60;
loc_3c4:
 3c4:	d866226d 	ld.w	r3, (r6, 0x9b4)	// regs: r3=*(0x9b4)
 3c8:	ec630001 	ori	r3, r3, 1	// regs: r3=(*(0x9b4) | 0x1)
 3cc:	dc66226d 	st.w	r3, (r6, 0x9b4)	// *(0x9b4) = (*(0x9b4) | 0x1)
 3d0:	0648      	br	0x60	// goto loc_60;
 3d2:	0000      	.short	0x0000
 3d4:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_bo_fns.str1.1>
 3d8:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_bo_fns.str1.1+0x6>
 3dc:	00000000 	.long	0x00000000	// <rate_tbl>
 3e0:	00000000 	.long	0x00000000	// <ah_lmac+0xa2c>
 3e4:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_bo_fns.str1.1+0xc>
 3e8:	00000000 	.long	0x00000000	// <.bss.scan_prob_idx.14166>
 3ec:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_bo_fns.str1.1+0x1e>
 3f0:	00000000 	.long	0x00000000	// <ah_lmac+0x9f8>
 3f4:	00000000 	.long	0x00000000	// <ah_lmac>
 3f8:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_bo_fns.str1.1+0x41>

Disassembly of section .text.lmac_adjust_agc_threshold:

00000000 <lmac_adjust_agc_threshold>: // arg_bytes: 4
   0:	14d1      	push	r4, r15
   2:	1181      	lrw	r4, 0x0	// regs: r4=0x0
   4:	6c43      	mov	r1, r0	// regs: r1=<arg0>
   6:	d8640361 	ld.b	r3, (r4, 0x361)	// regs: r3=*(0x361)
   a:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x361) & 0x8)
   e:	e9030023 	bez	r3, 0x54	// if (r3 == 0x0) goto loc_54;
  12:	d8640308 	ld.b	r3, (r4, 0x308)	// regs: r3=*(0x308)
  16:	3b01      	cmphsi	r3, 2
  18:	0c1f      	bf	0x56	// if (r3 < 0x2) goto loc_56;
  1a:	3b42      	cmpnei	r3, 2
  1c:	0c20      	bf	0x5c	// if (r3 == 0x2) goto loc_5c;
loc_1e:
  1e:	d864431f 	ld.bs	r3, (r4, 0x31f)	// regs: r3=*(0x31f)
  22:	64c5      	cmplt	r1, r3
  24:	081e      	bt	0x60	// if (T) goto loc_60;
  26:	d86411b1 	ld.h	r3, (r4, 0x362)	// regs: r3=*(0x362)
  2a:	e4632ff0 	andi	r3, r3, 4080	// regs: r3=(*(0x362) & 0xff0)
  2e:	eb430040 	cmpnei	r3, 64
  32:	0c04      	bf	0x3a	// if (r3 == 0x40) goto loc_3a;
  34:	1015      	lrw	r0, 0x0	// regs: r0=0x0
  36:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x36>, r1=<clobbered>
loc_3a:
  3a:	d86411b1 	ld.h	r3, (r4, 0x362)	// regs: r3=*(0x362)
  3e:	3204      	movi	r2, 4	// regs: r2=0x4
loc_40:
  40:	c4625ce4 	ins	r3, r2, 11, 4
  44:	dc6411b1 	st.h	r3, (r4, 0x362)	// *(0x362) = *(0x362)
loc_48:
  48:	d80411b1 	ld.h	r0, (r4, 0x362)	// regs: r0=*(0x362)
  4c:	c4805560 	zext	r0, r0, 11, 4	// regs: r0=zext(*(0x362))
  50:	e0000000 	bsr	0x0	// <lmac_rx_gain_cfg>; regs: r0=<ret lmac_rx_gain_cfg@0x50>, r1=<clobbered>
loc_54:
  54:	1491      	pop	r4, r15
loc_56:
  56:	2105      	addi	r1, 6	// regs: r1=(<arg0> + 0x6)
loc_58:
  58:	7446      	sextb	r1, r1	// regs: r1=sext8(r1)
  5a:	07e2      	br	0x1e	// goto loc_1e;
loc_5c:
  5c:	2102      	addi	r1, 3	// regs: r1=(<arg0> + 0x3)
  5e:	07fd      	br	0x58	// goto loc_58;
loc_60:
  60:	d8644320 	ld.bs	r3, (r4, 0x320)	// regs: r3=*(0x320)
  64:	644d      	cmplt	r3, r1
  66:	0bf1      	bt	0x48	// if (T) goto loc_48;
  68:	d86411b1 	ld.h	r3, (r4, 0x362)	// regs: r3=*(0x362)
  6c:	e4632ff0 	andi	r3, r3, 4080	// regs: r3=(*(0x362) & 0xff0)
  70:	eb430050 	cmpnei	r3, 80
  74:	0c04      	bf	0x7c	// if (r3 == 0x50) goto loc_7c;
  76:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  78:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x78>, r1=<clobbered>
loc_7c:
  7c:	d86411b1 	ld.h	r3, (r4, 0x362)	// regs: r3=*(0x362)
  80:	3205      	movi	r2, 5	// regs: r2=0x5
  82:	07df      	br	0x40	// goto loc_40;
  84:	0000      	.short	0x0000	// <ah_lmac>
  86:	0000      	.short	0x0000
  88:	0000      	.short	0x0000	// <.rodata.lmac_adjust_agc_threshold.str1.1>
  8a:	0000      	.short	0x0000
  8c:	0000      	.short	0x0000	// <.rodata.lmac_adjust_agc_threshold.str1.1+0xe>
  8e:	0000      	.short	0x0000

Disassembly of section .text.lmac_bgrssi_update:

00000000 <lmac_bgrssi_update>: // arg_bytes: 4
   0:	14d3      	push	r4-r6, r15
   2:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_valid_pd_get>; regs: r0=<ret ah_rfdigicali_bknoise_valid_pd_get@0x2>, r1=<clobbered>
   6:	e90000a1 	bez	r0, 0x148	// if (r0 == 0x0) goto loc_148;
   a:	e0000000 	bsr	0x0	// <lmac_bknoise_get> // arg_bytes: 0; regs: r0=<ret lmac_bknoise_get@0xa>, r1=<clobbered>
   e:	1387      	lrw	r4, 0x0	// regs: r4=0x0
  10:	6d83      	mov	r6, r0	// regs: r6=<ret lmac_bknoise_get@0xa>
  12:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_calc_dis>; regs: r0=<ret ah_rfdigicali_bknoise_calc_dis@0x12>, r1=<clobbered>
  16:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_valid_pd_clr>; regs: r0=<ret ah_rfdigicali_bknoise_valid_pd_clr@0x16>, r1=<clobbered>
  1a:	d8a40379 	ld.b	r5, (r4, 0x379)	// regs: r5=*(0x379)
  1e:	3118      	movi	r1, 24	// regs: r1=0x18
  20:	c425842c 	mult	r12, r5, r1	// regs: r12=(*(0x379) * 0x18)
  24:	6310      	addu	r12, r4	// regs: r12=((*(0x379) * 0x18) )
  26:	d86c40c5 	ld.bs	r3, (r12, 0xc5)	// regs: r3=*((((*(0x379) * 0x18) ) + 0xc5))
  2a:	d84c2032 	ld.w	r2, (r12, 0xc8)	// regs: r2=*((((*(0x379) * 0x18) ) + 0xc8))
  2e:	d9ac2033 	ld.w	r13, (r12, 0xcc)	// regs: r13=*((((*(0x379) * 0x18) ) + 0xcc))
  32:	64d9      	cmplt	r6, r3
  34:	6098      	addu	r2, r6	// regs: r2=(*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>)
  36:	e40d0000 	addi	r0, r13, 1	// regs: r0=(*((((*(0x379) * 0x18) ) + 0xcc)) + 0x1)
  3a:	dc4c2032 	st.w	r2, (r12, 0xc8)	// *((((*(0x379) * 0x18) ) + 0xc8)) = (*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>)
  3e:	dc0c2033 	st.w	r0, (r12, 0xcc)	// *((((*(0x379) * 0x18) ) + 0xcc)) = (*((((*(0x379) * 0x18) ) + 0xcc)) + 0x1)
  42:	0c03      	bf	0x48	// if (!T) goto loc_48;
  44:	dccc00c5 	st.b	r6, (r12, 0xc5)	// *((((*(0x379) * 0x18) ) + 0xc5)) = <ret lmac_bknoise_get@0xa>
loc_48:
  48:	7c54      	mult	r1, r5	// regs: r1=(0x18 * *(0x379))
  4a:	6050      	addu	r1, r4	// regs: r1=((0x18 * *(0x379)) )
  4c:	d86140c6 	ld.bs	r3, (r1, 0xc6)	// regs: r3=*((((0x18 * *(0x379)) ) + 0xc6))
  50:	658d      	cmplt	r3, r6
  52:	0c03      	bf	0x58	// if (!T) goto loc_58;
  54:	dcc100c6 	st.b	r6, (r1, 0xc6)	// *((((0x18 * *(0x379)) ) + 0xc6)) = <ret lmac_bknoise_get@0xa>
loc_58:
  58:	d86420d8 	ld.w	r3, (r4, 0x360)	// regs: r3=*(0x360)
  5c:	c5835663 	zext	r3, r3, 19, 12	// regs: r3=zext(*(0x360))
  60:	64c1      	cmplt	r0, r3
  62:	0860      	bt	0x122	// if (T) goto loc_122;
  64:	3118      	movi	r1, 24	// regs: r1=0x18
  66:	7c54      	mult	r1, r5	// regs: r1=(0x18 * *(0x379))
  68:	6050      	addu	r1, r4	// regs: r1=((0x18 * *(0x379)) )
  6a:	e5ad1000 	subi	r13, r13, 1	// regs: r13=(*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1)
  6e:	d80140c6 	ld.bs	r0, (r1, 0xc6)	// regs: r0=*((((0x18 * *(0x379)) ) + 0xc6))
  72:	5a61      	subu	r3, r2, r0	// regs: r3=((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6)))
  74:	d98140c5 	ld.bs	r12, (r1, 0xc5)	// regs: r12=*((((0x18 * *(0x379)) ) + 0xc5))
  78:	60f2      	subu	r3, r12	// regs: r3=(((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5)))
  7a:	d844033c 	ld.b	r2, (r4, 0x33c)	// regs: r2=*(0x33c)
  7e:	c5a38043 	divs	r3, r3, r13	// regs: r3=((((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5))) / (*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1))
  82:	654a      	cmpne	r2, r5
  84:	74ce      	sextb	r3, r3	// regs: r3=sext8(((((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5))) / (*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1)))
  86:	dc6100c7 	st.b	r3, (r1, 0xc7)	// *((((0x18 * *(0x379)) ) + 0xc7)) = sext8(((((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5))) / (*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1)))
  8a:	083d      	bt	0x104	// if (T) goto loc_104;
  8c:	1248      	lrw	r2, 0x0	// regs: r2=0x0
  8e:	dc64070d 	st.b	r3, (r4, 0x70d)	// *(0x70d) = sext8(((((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5))) / (*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1)))
  92:	8220      	ld.b	r1, (r2, 0x0)	// regs: r1=*(0x0)
  94:	dd84070c 	st.b	r12, (r4, 0x70c)	// *(0x70c) = *((((0x18 * *(0x379)) ) + 0xc5))
  98:	dc04070e 	st.b	r0, (r4, 0x70e)	// *(0x70e) = *((((0x18 * *(0x379)) ) + 0xc6))
  9c:	e901005f 	bez	r1, 0x15a	// if (r1 == 0x0) goto loc_15a;
  a0:	d824431e 	ld.bs	r1, (r4, 0x31e)	// regs: r1=*(0x31e)
  a4:	644d      	cmplt	r3, r1
  a6:	0852      	bt	0x14a	// if (T) goto loc_14a;
loc_a8:
  a8:	dc64031e 	st.b	r3, (r4, 0x31e)	// *(0x31e) = r3
loc_ac:
  ac:	d8640361 	ld.b	r3, (r4, 0x361)	// regs: r3=*(0x361)
  b0:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(0x361) & 0x4)
  b4:	e9030006 	bez	r3, 0xc0	// if (r3 == 0x0) goto loc_c0;
  b8:	d804431e 	ld.bs	r0, (r4, 0x31e)	// regs: r0=*(0x31e)
  bc:	e0000000 	bsr	0x0	// <lmac_adjust_cca_threshold> // arg_bytes: 8; regs: r0=<ret lmac_adjust_cca_threshold@0xbc>, r1=<clobbered>
loc_c0:
  c0:	d804431e 	ld.bs	r0, (r4, 0x31e)	// regs: r0=*(0x31e)
  c4:	e0000000 	bsr	0x0	// <lmac_adjust_agc_threshold> // arg_bytes: 4; regs: r0=<ret lmac_adjust_agc_threshold@0xc4>, r1=<clobbered>
  c8:	d86409f4 	ld.b	r3, (r4, 0x9f4)	// regs: r3=*(0x9f4)
  cc:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x9f4) & 0x1)
  d0:	e903001a 	bez	r3, 0x104	// if (r3 == 0x0) goto loc_104;
  d4:	d864227a 	ld.w	r3, (r4, 0x9e8)	// regs: r3=*(0x9e8)
  d8:	eb2327ff 	cmplti	r3, 10240
  dc:	0814      	bt	0x104	// if (r3 < 0x2800) goto loc_104;
  de:	33f0      	movi	r3, 240	// regs: r3=0xf0
  e0:	d8242279 	ld.w	r1, (r4, 0x9e4)	// regs: r1=*(0x9e4)
  e4:	4365      	lsli	r3, r3, 5	// regs: r3=0x1e00
  e6:	594c      	addu	r2, r1, r3	// regs: r2=(*(0x9e4) + 0x1e00)
  e8:	33f4      	movi	r3, 244	// regs: r3=0xf4
  ea:	4365      	lsli	r3, r3, 5	// regs: r3=0x1e80
  ec:	d8045196 	ld.hs	r0, (r4, 0x32c)	// regs: r0=*(0x32c)
  f0:	604c      	addu	r1, r3	// regs: r1=(*(0x9e4) + 0x1e80)
  f2:	ea0c0000 	movi	r12, 0	// regs: r12=0x0
loc_f6:
  f6:	644a      	cmpne	r2, r1
  f8:	0836      	bt	0x164	// if (T) goto loc_164;
  fa:	d86413f4 	ld.h	r3, (r4, 0x7e8)	// regs: r3=*(0x7e8)
  fe:	2300      	addi	r3, 1	// regs: r3=(*(0x7e8) + 0x1)
 100:	dc6413f4 	st.h	r3, (r4, 0x7e8)	// *(0x7e8) = (*(0x7e8) + 0x1)
loc_104:
 104:	3318      	movi	r3, 24	// regs: r3=0x18
 106:	7d4c      	mult	r5, r3	// regs: r5=(*(0x379) * 0x18)
 108:	6150      	addu	r5, r4	// regs: r5=((*(0x379) * 0x18) )
 10a:	3300      	movi	r3, 0	// regs: r3=0x0
 10c:	dc6500c5 	st.b	r3, (r5, 0xc5)	// *((((*(0x379) * 0x18) ) + 0xc5)) = 0x0
 110:	3300      	movi	r3, 0	// regs: r3=0x0
 112:	2b7f      	subi	r3, 128	// regs: r3=0xffffff80
 114:	dc6500c6 	st.b	r3, (r5, 0xc6)	// *((((*(0x379) * 0x18) ) + 0xc6)) = 0xffffff80
 118:	3300      	movi	r3, 0	// regs: r3=0x0
 11a:	dc652032 	st.w	r3, (r5, 0xc8)	// *((((*(0x379) * 0x18) ) + 0xc8)) = 0x0
 11e:	dc652033 	st.w	r3, (r5, 0xcc)	// *((((*(0x379) * 0x18) ) + 0xcc)) = 0x0
loc_122:
 122:	d864037c 	ld.b	r3, (r4, 0x37c)	// regs: r3=*(0x37c)
 126:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x37c) & 0x1)
 12a:	e903003c 	bez	r3, 0x1a2	// if (r3 == 0x0) goto loc_1a2;
 12e:	d8640379 	ld.b	r3, (r4, 0x379)	// regs: r3=*(0x379)
 132:	2300      	addi	r3, 1	// regs: r3=(*(0x379) + 0x1)
 134:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(0x379) + 0x1))
 136:	d8440378 	ld.b	r2, (r4, 0x378)	// regs: r2=*(0x378)
 13a:	648c      	cmphs	r3, r2
 13c:	dc640379 	st.b	r3, (r4, 0x379)	// *(0x379) = zext8((*(0x379) + 0x1))
 140:	0c04      	bf	0x148	// if (!T) goto loc_148;
 142:	3300      	movi	r3, 0	// regs: r3=0x0
loc_144:
 144:	dc640379 	st.b	r3, (r4, 0x379)	// *(0x379) = r3
loc_148:
 148:	1493      	pop	r4-r6, r15
loc_14a:
 14a:	495f      	lsri	r2, r1, 31	// regs: r2=(*(0x31e) >> 0x1f)
 14c:	6084      	addu	r2, r1	// regs: r2=((*(0x31e) >> 0x1f) + *(0x31e))
 14e:	4b3f      	lsri	r1, r3, 31	// regs: r1=(sext8(((((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5))) / (*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1))) >> 0x1f)
 150:	60c4      	addu	r3, r1	// regs: r3=(sext8(((((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5))) / (*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1))) + (sext8(((((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5))) / (*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1))) >> 0x1f))
 152:	5241      	asri	r2, r2, 1	// regs: r2=(((*(0x31e) >> 0x1f) + *(0x31e)) >> 0x1)
 154:	5361      	asri	r3, r3, 1	// regs: r3=((sext8(((((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5))) / (*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1))) + (sext8(((((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5))) / (*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1))) >> 0x1f)) >> 0x1)
 156:	60c8      	addu	r3, r2	// regs: r3=(((sext8(((((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5))) / (*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1))) + (sext8(((((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5))) / (*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1))) >> 0x1f)) >> 0x1) + (((*(0x31e) >> 0x1f) + *(0x31e)) >> 0x1))
 158:	07a8      	br	0xa8	// goto loc_a8;
loc_15a:
 15a:	dc64031e 	st.b	r3, (r4, 0x31e)	// *(0x31e) = sext8(((((*((((*(0x379) * 0x18) ) + 0xc8)) + <ret lmac_bknoise_get@0xa>) - *((((0x18 * *(0x379)) ) + 0xc6))) - *((((0x18 * *(0x379)) ) + 0xc5))) / (*((((*(0x379) * 0x18) ) + 0xcc)) - 0x1)))
 15e:	3301      	movi	r3, 1	// regs: r3=0x1
 160:	a260      	st.b	r3, (r2, 0x0)	// *(0x0) = 0x1
 162:	07a5      	br	0xac	// goto loc_ac;
loc_164:
 164:	8261      	ld.b	r3, (r2, 0x1)	// regs: r3=*(r2 + 0x1)
 166:	4368      	lsli	r3, r3, 8	// regs: r3=(*(r2 + 0x1) << 0x8)
 168:	d9a20000 	ld.b	r13, (r2, 0x0)	// regs: r13=*(r2)
 16c:	6cf4      	or	r3, r13	// regs: r3=((*(r2 + 0x1) << 0x8) | *(r2))
 16e:	74cf      	sexth	r3, r3	// regs: r3=sext16(((*(r2 + 0x1) << 0x8) | *(r2)))
 170:	e9a30005 	bhsz	r3, 0x17a	// if (r3 >= 0x0) goto loc_17a;
 174:	c46c0083 	subu	r3, r12, r3	// regs: r3=(0x0 - sext16(((*(r2 + 0x1) << 0x8) | *(r2))))
 178:	74cf      	sexth	r3, r3	// regs: r3=sext16((0x0 - sext16(((*(r2 + 0x1) << 0x8) | *(r2)))))
loc_17a:
 17a:	d9a421f8 	ld.w	r13, (r4, 0x7e0)	// regs: r13=*(0x7e0)
 17e:	634c      	addu	r13, r3	// regs: r13=(*(0x7e0) + r3)
 180:	dda421f8 	st.w	r13, (r4, 0x7e0)	// *(0x7e0) = (*(0x7e0) + r3)
 184:	d9a453f2 	ld.hs	r13, (r4, 0x7e4)	// regs: r13=*(0x7e4)
 188:	64f5      	cmplt	r13, r3
 18a:	0c03      	bf	0x190	// if (!T) goto loc_190;
 18c:	dc6413f2 	st.h	r3, (r4, 0x7e4)	// *(0x7e4) = r3
loc_190:
 190:	64c1      	cmplt	r0, r3
 192:	0c06      	bf	0x19e	// if (!T) goto loc_19e;
 194:	d86413f3 	ld.h	r3, (r4, 0x7e6)	// regs: r3=*(0x7e6)
 198:	2300      	addi	r3, 1	// regs: r3=(*(0x7e6) + 0x1)
 19a:	dc6413f3 	st.h	r3, (r4, 0x7e6)	// *(0x7e6) = (*(0x7e6) + 0x1)
loc_19e:
 19e:	2201      	addi	r2, 2	// regs: r2=(r2 + 0x2)
 1a0:	07ab      	br	0xf6	// goto loc_f6;
loc_1a2:
 1a2:	d864033c 	ld.b	r3, (r4, 0x33c)	// regs: r3=*(0x33c)
 1a6:	07cf      	br	0x144	// goto loc_144;
 1a8:	00000000 	.long	0x00000000	// <ah_lmac>
 1ac:	0000      	.short	0x0000	// <.bss.bgrssi_init.14291>
 1ae:	0000      	.short	0x0000

Disassembly of section .text.lmac_irq_tx_tmo:

00000000 <lmac_irq_tx_tmo>: // arg_bytes: 0
   0:	14d6      	push	r4-r9, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	1086      	lrw	r4, 0x0	// regs: r4=0x0
   6:	e0000000 	bsr	0x0	// <lmac_cancle_tx_tmo>; regs: r0=<ret lmac_cancle_tx_tmo@0x6>, r1=<clobbered>
   a:	d8642266 	ld.w	r3, (r4, 0x998)	// regs: r3=*(0x998)
   e:	2b00      	subi	r3, 1	// regs: r3=(*(0x998) - 0x1)
  10:	3b05      	cmphsi	r3, 6
  12:	09f9      	bt	0x404	// if (r3 >= 0x6) goto loc_404;
  14:	1043      	lrw	r2, 0x0	// regs: r2=0x0
  16:	d0620883 	ldr.w	r3, (r2, r3 << 2)	// regs: r3=*(0x0 + ((*(0x998) - 0x1) << 2))
  1a:	780c      	jmp	r3	// goto *r3;
  1c:	00000000 	.long	0x00000000	// <ah_lmac>
  20:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_tx_tmo>
  24:	d86449dc 	ld.bs	r3, (r4, 0x9dc)	// regs: r3=*(r4 + 0x9dc)
  28:	e9a3000c 	bhsz	r3, 0x40	// if (r3 >= 0x0) goto loc_40;
  2c:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x2c>, r1=<clobbered>
  30:	d86421ce 	ld.w	r3, (r4, 0x738)	// regs: r3=*(r4 + 0x738)
  34:	2300      	addi	r3, 1	// regs: r3=(*(r4 + 0x738) + 0x1)
  36:	dc6421ce 	st.w	r3, (r4, 0x738)	// *(r4 + 0x738) = (*(r4 + 0x738) + 0x1)
loc_3a:
  3a:	3300      	movi	r3, 0	// regs: r3=0x0
  3c:	dc642266 	st.w	r3, (r4, 0x998)	// *(r4 + 0x998) = 0x0
loc_40:
  40:	d86409e0 	ld.b	r3, (r4, 0x9e0)	// regs: r3=*(r4 + 0x9e0)
  44:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(r4 + 0x9e0) & 0x1)
  48:	e9230004 	bnez	r3, 0x50	// if (r3 != 0x0) goto loc_50;
  4c:	e0000000 	bsr	0x0	// <lhw_enable_irq_ac>; regs: r0=<ret lhw_enable_irq_ac@0x4c>, r1=<clobbered>
loc_50:
  50:	1402      	addi	r14, r14, 8	// regs: r14=(sp + 0x8)
  52:	1496      	pop	r4-r9, r15
  54:	d8440892 	ld.b	r2, (r4, 0x892)	// regs: r2=*(r4 + 0x892)
  58:	e4622001 	andi	r3, r2, 1	// regs: r3=(*(r4 + 0x892) & 0x1)
  5c:	e9030008 	bez	r3, 0x6c	// if (r3 == 0x0) goto loc_6c;
  60:	e4422002 	andi	r2, r2, 2	// regs: r2=(*(r4 + 0x892) & 0x2)
  64:	e9020032 	bez	r2, 0xc8	// if (r2 == 0x0) goto loc_c8;
  68:	e0000000 	bsr	0x0	// <lmac_qa_freq_hopping> // arg_bytes: 0; regs: r0=<ret lmac_qa_freq_hopping@0x68>, r1=<clobbered>
loc_6c:
  6c:	d8a409dc 	ld.b	r5, (r4, 0x9dc)	// regs: r5=*(r4 + 0x9dc)
  70:	74d6      	sextb	r3, r5	// regs: r3=sext8(*(r4 + 0x9dc))
  72:	e9a3ffe7 	bhsz	r3, 0x40	// if (r3 >= 0x0) goto loc_40;
  76:	e4a5200f 	andi	r5, r5, 15	// regs: r5=(*(r4 + 0x9dc) & 0xf)
  7a:	3d03      	cmphsi	r5, 4
  7c:	08da      	bt	0x230	// if (r5 >= 0x4) goto loc_230;
  7e:	3390      	movi	r3, 144	// regs: r3=0x90
  80:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
  82:	7d4c      	mult	r5, r3	// regs: r5=((*(r4 + 0x9dc) & 0xf) * 0x120)
  84:	01c8      	lrw	r6, 0x0	// regs: r6=0x0
  86:	3700      	movi	r7, 0	// regs: r7=0x0
  88:	c4a60028 	addu	r8, r6, r5	// regs: r8=(0x0 + ((*(r4 + 0x9dc) & 0xf) * 0x120))
  8c:	6c5f      	mov	r1, r7	// regs: r1=0x0
  8e:	e52801c3 	addi	r9, r8, 452	// regs: r9=((0x0 + ((*(r4 + 0x9dc) & 0xf) * 0x120)) + 0x1c4)
loc_92:
  92:	d8690000 	ld.b	r3, (r9, 0x0)	// regs: r3=*(((0x0 + ((*(r4 + 0x9dc) & 0xf) * 0x120)) + 0x1c4))
  96:	64dd      	cmplt	r7, r3
  98:	088a      	bt	0x1ac	// if (T) goto loc_1ac;
  9a:	e901ffd0 	bez	r1, 0x3a	// if (r1 == 0x0) goto loc_3a;
  9e:	d86421cd 	ld.w	r3, (r4, 0x734)	// regs: r3=*(r4 + 0x734)
  a2:	2300      	addi	r3, 1	// regs: r3=(*(r4 + 0x734) + 0x1)
  a4:	dc6421cd 	st.w	r3, (r4, 0x734)	// *(r4 + 0x734) = (*(r4 + 0x734) + 0x1)
  a8:	d866055d 	ld.b	r3, (r6, 0x55d)	// regs: r3=*(0x55d)
  ac:	4b45      	lsri	r2, r3, 5	// regs: r2=(*(0x55d) >> 0x5)
  ae:	c4635483 	zext	r3, r3, 4, 3	// regs: r3=zext(*(0x55d))
  b2:	b841      	st.w	r2, (r14, 0x4)	// stack_p4 = (*(0x55d) >> 0x5)
  b4:	b860      	st.w	r3, (r14, 0x0)	// stack_0 = zext(*(0x55d))
  b6:	3300      	movi	r3, 0	// regs: r3=0x0
  b8:	6c8f      	mov	r2, r3	// regs: r2=0x0
  ba:	d828206e 	ld.w	r1, (r8, 0x1b8)	// regs: r1=*(((0x0 + ((*(r4 + 0x9dc) & 0xf) * 0x120)) + 0x1b8))
  be:	d8042294 	ld.w	r0, (r4, 0xa50)	// regs: r0=*(r4 + 0xa50)
  c2:	e0000000 	bsr	0x0	// <ah_tx_status>; regs: r0=<ret ah_tx_status@0xc2>, r1=<clobbered>
  c6:	07ba      	br	0x3a	// goto loc_3a;
loc_c8:
  c8:	d8640890 	ld.b	r3, (r4, 0x890)	// regs: r3=*(r4 + 0x890)
  cc:	2300      	addi	r3, 1	// regs: r3=(*(r4 + 0x890) + 0x1)
  ce:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(r4 + 0x890) + 0x1))
  d0:	744e      	sextb	r1, r3	// regs: r1=sext8(zext8((*(r4 + 0x890) + 0x1)))
  d2:	eb210063 	cmplti	r1, 100
  d6:	dc240890 	st.b	r1, (r4, 0x890)	// *(r4 + 0x890) = sext8(zext8((*(r4 + 0x890) + 0x1)))
  da:	0bc9      	bt	0x6c	// if (r1 < 0x64) goto loc_6c;
  dc:	d8244891 	ld.bs	r1, (r4, 0x891)	// regs: r1=*(r4 + 0x891)
  e0:	60c6      	subu	r3, r1	// regs: r3=(zext8((*(r4 + 0x890) + 0x1)) - *(r4 + 0x891))
  e2:	74ce      	sextb	r3, r3	// regs: r3=sext8((zext8((*(r4 + 0x890) + 0x1)) - *(r4 + 0x891)))
  e4:	e9830059 	blz	r3, 0x196	// if (r3 < 0x0) goto loc_196;
  e8:	dc6408be 	st.b	r3, (r4, 0x8be)	// *(r4 + 0x8be) = sext8((zext8((*(r4 + 0x890) + 0x1)) - *(r4 + 0x891)))
loc_ec:
  ec:	d84448be 	ld.bs	r2, (r4, 0x8be)	// regs: r2=*(r4 + 0x8be)
  f0:	d864489a 	ld.bs	r3, (r4, 0x89a)	// regs: r3=*(r4 + 0x89a)
  f4:	648d      	cmplt	r3, r2
  f6:	d86408bf 	ld.b	r3, (r4, 0x8bf)	// regs: r3=*(r4 + 0x8bf)
  fa:	0244      	lrw	r2, 0x0	// regs: r2=0x0
  fc:	0850      	bt	0x19c	// if (T) goto loc_19c;
  fe:	3001      	movi	r0, 1	// regs: r0=0x1
 100:	c4605c00 	ins	r3, r0, 0, 0
 104:	dc6408bf 	st.b	r3, (r4, 0x8bf)	// *(r4 + 0x8bf) = *(r4 + 0x8bf)
 108:	3300      	movi	r3, 0	// regs: r3=0x0
loc_10a:
 10a:	a260      	st.b	r3, (r2, 0x0)	// *(0x0) = r3
 10c:	e9010005 	bez	r1, 0x116	// if (r1 == 0x0) goto loc_116;
 110:	8260      	ld.b	r3, (r2, 0x0)	// regs: r3=*(0x0)
 112:	3b03      	cmphsi	r3, 4
 114:	0c33      	bf	0x17a	// if (r3 < 0x4) goto loc_17a;
loc_116:
 116:	3300      	movi	r3, 0	// regs: r3=0x0
 118:	317f      	movi	r1, 127	// regs: r1=0x7f
 11a:	a260      	st.b	r3, (r2, 0x0)	// *(0x0) = 0x0
 11c:	3007      	movi	r0, 7	// regs: r0=0x7
 11e:	dc6408ad 	st.b	r3, (r4, 0x8ad)	// *(r4 + 0x8ad) = 0x0
 122:	dc2408ae 	st.b	r1, (r4, 0x8ae)	// *(r4 + 0x8ae) = 0x7f
 126:	dc2408b8 	st.b	r1, (r4, 0x8b8)	// *(r4 + 0x8b8) = 0x7f
 12a:	dc6408c0 	st.b	r3, (r4, 0x8c0)	// *(r4 + 0x8c0) = 0x0
 12e:	3100      	movi	r1, 0	// regs: r1=0x0
 130:	dc6408c1 	st.b	r3, (r4, 0x8c1)	// *(r4 + 0x8c1) = 0x0
 134:	d86408bf 	ld.b	r3, (r4, 0x8bf)	// regs: r3=*(r4 + 0x8bf)
 138:	c4615c00 	ins	r3, r1, 0, 0
 13c:	3200      	movi	r2, 0	// regs: r2=0x0
 13e:	dc0408af 	st.b	r0, (r4, 0x8af)	// *(r4 + 0x8af) = 0x7
 142:	d804031e 	ld.b	r0, (r4, 0x31e)	// regs: r0=*(r4 + 0x31e)
 146:	2a7f      	subi	r2, 128	// regs: r2=0xffffff80
 148:	dc0408b0 	st.b	r0, (r4, 0x8b0)	// *(r4 + 0x8b0) = *(r4 + 0x31e)
 14c:	dc6408bf 	st.b	r3, (r4, 0x8bf)	// *(r4 + 0x8bf) = *(r4 + 0x8bf)
 150:	3000      	movi	r0, 0	// regs: r0=0x0
 152:	d8640892 	ld.b	r3, (r4, 0x892)	// regs: r3=*(r4 + 0x892)
 156:	c4615c02 	ins	r3, r1, 2, 2
 15a:	dc4408ac 	st.b	r2, (r4, 0x8ac)	// *(r4 + 0x8ac) = 0xffffff80
 15e:	dc041459 	st.h	r0, (r4, 0x8b2)	// *(r4 + 0x8b2) = 0x0
 162:	dc4408b6 	st.b	r2, (r4, 0x8b6)	// *(r4 + 0x8b6) = 0xffffff80
 166:	dc0408b7 	st.b	r0, (r4, 0x8b7)	// *(r4 + 0x8b7) = 0x0
 16a:	3206      	movi	r2, 6	// regs: r2=0x6
 16c:	0300      	lrw	r0, 0x0	// regs: r0=0x0
 16e:	dc640892 	st.b	r3, (r4, 0x892)	// *(r4 + 0x892) = *(r4 + 0x892)
 172:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x172>, r1=<clobbered>
 176:	e0000000 	bsr	0x0	// <lmac_qa_freq_hopping> // arg_bytes: 0; regs: r0=<ret lmac_qa_freq_hopping@0x176>, r1=<clobbered>
loc_17a:
 17a:	3300      	movi	r3, 0	// regs: r3=0x0
 17c:	d804431e 	ld.bs	r0, (r4, 0x31e)	// regs: r0=*(r4 + 0x31e)
 180:	dc640890 	st.b	r3, (r4, 0x890)	// *(r4 + 0x890) = 0x0
 184:	dc640891 	st.b	r3, (r4, 0x891)	// *(r4 + 0x891) = 0x0
 188:	e0000000 	bsr	0x0	// <lmac_adjust_cca_threshold> // arg_bytes: 8; regs: r0=<ret lmac_adjust_cca_threshold@0x188>, r1=<clobbered>
 18c:	d804431e 	ld.bs	r0, (r4, 0x31e)	// regs: r0=*(r4 + 0x31e)
 190:	e0000000 	bsr	0x0	// <lmac_adjust_agc_threshold> // arg_bytes: 4; regs: r0=<ret lmac_adjust_agc_threshold@0x190>, r1=<clobbered>
 194:	076c      	br	0x6c	// goto loc_6c;
loc_196:
 196:	dc4408be 	st.b	r2, (r4, 0x8be)	// *(r4 + 0x8be) = (*(r4 + 0x892) & 0x2)
 19a:	07a9      	br	0xec	// goto loc_ec;
loc_19c:
 19c:	3000      	movi	r0, 0	// regs: r0=0x0
 19e:	c4605c00 	ins	r3, r0, 0, 0
 1a2:	dc6408bf 	st.b	r3, (r4, 0x8bf)	// *(r4 + 0x8bf) = *(r4 + 0x8bf)
 1a6:	8260      	ld.b	r3, (r2, 0x0)	// regs: r3=*(0x0)
 1a8:	2300      	addi	r3, 1	// regs: r3=(*(0x0) + 0x1)
 1aa:	07b0      	br	0x10a	// goto loc_10a;
loc_1ac:
 1ac:	4762      	lsli	r3, r7, 2	// regs: r3=(r7 << 0x2)
 1ae:	60d4      	addu	r3, r5	// regs: r3=((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120))
 1b0:	60d8      	addu	r3, r6	// regs: r3=(((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120)) )
 1b2:	d863202e 	ld.w	r3, (r3, 0xb8)	// regs: r3=*(((((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120)) ) + 0xb8))
 1b6:	9368      	ld.w	r3, (r3, 0x20)	// regs: r3=*((*(((((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20))
 1b8:	d8430025 	ld.b	r2, (r3, 0x25)	// regs: r2=*((*((*(((((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x25))
 1bc:	e4422002 	andi	r2, r2, 2	// regs: r2=(*((*((*(((((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x25)) & 0x2)
 1c0:	e902000b 	bez	r2, 0x1d6	// if (r2 == 0x0) goto loc_1d6;
 1c4:	d8430027 	ld.b	r2, (r3, 0x27)	// regs: r2=*((*((*(((((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x27))
 1c8:	3001      	movi	r0, 1	// regs: r0=0x1
 1ca:	c4405c07 	ins	r2, r0, 7, 7
 1ce:	dc430027 	st.b	r2, (r3, 0x27)	// *((*((*(((((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x27)) = *((*((*(((((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x27))
loc_1d2:
 1d2:	2700      	addi	r7, 1	// regs: r7=(r7 + 0x1)
 1d4:	075f      	br	0x92	// goto loc_92;
loc_1d6:
 1d6:	9342      	ld.w	r2, (r3, 0x8)	// regs: r2=*((*((*(((((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x8))
 1d8:	e4422010 	andi	r2, r2, 16	// regs: r2=(*((*((*(((((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x8)) & 0x10)
 1dc:	e9020023 	bez	r2, 0x222	// if (r2 == 0x0) goto loc_222;
 1e0:	d8230029 	ld.b	r1, (r3, 0x29)	// regs: r1=*((*((*(((((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x29))
 1e4:	d8440312 	ld.b	r2, (r4, 0x312)	// regs: r2=*(r4 + 0x312)
 1e8:	6484      	cmphs	r1, r2
 1ea:	0807      	bt	0x1f8	// if (T) goto loc_1f8;
 1ec:	d8430028 	ld.b	r2, (r3, 0x28)	// regs: r2=*((*((*(((((r7 << 0x2) + ((*(r4 + 0x9dc) & 0xf) * 0x120)) ) + 0xb8)) + 0x20)) + 0x28))
 1f0:	d8640313 	ld.b	r3, (r4, 0x313)	// regs: r3=*(r4 + 0x313)
 1f4:	64c8      	cmphs	r2, r3
 1f6:	0c16      	bf	0x222	// if (!T) goto loc_222;
loc_1f8:
 1f8:	d806055d 	ld.b	r0, (r6, 0x55d)	// regs: r0=*(0x55d)
 1fc:	3100      	movi	r1, 0	// regs: r1=0x0
 1fe:	297f      	subi	r1, 128	// regs: r1=0xffffff80
 200:	c4405440 	zext	r0, r0, 2, 2	// regs: r0=zext(*(0x55d))
 204:	e0000000 	bsr	0x0	// <ah_ant_status>; regs: r0=<ret ah_ant_status@0x204>, r1=<clobbered>
 208:	d86420ee 	ld.w	r3, (r4, 0x3b8)	// regs: r3=*(r4 + 0x3b8)
 20c:	e4632100 	andi	r3, r3, 256	// regs: r3=(*(r4 + 0x3b8) & 0x100)
 210:	e9030009 	bez	r3, 0x222	// if (r3 == 0x0) goto loc_222;
 214:	d826055d 	ld.b	r1, (r6, 0x55d)	// regs: r1=*(0x55d)
 218:	c4415441 	zext	r1, r1, 2, 2	// regs: r1=zext(*(0x55d))
 21c:	1314      	lrw	r0, 0x0	// regs: r0=0x0
 21e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x21e>, r1=<clobbered>
loc_222:
 222:	d86421d6 	ld.w	r3, (r4, 0x758)	// regs: r3=*(r4 + 0x758)
 226:	2300      	addi	r3, 1	// regs: r3=(*(r4 + 0x758) + 0x1)
 228:	dc6421d6 	st.w	r3, (r4, 0x758)	// *(r4 + 0x758) = (*(r4 + 0x758) + 0x1)
 22c:	3101      	movi	r1, 1	// regs: r1=0x1
 22e:	07d2      	br	0x1d2	// goto loc_1d2;
loc_230:
 230:	1310      	lrw	r0, 0x0	// regs: r0=0x0
 232:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x232>, r1=<clobbered>
 236:	0702      	br	0x3a	// goto loc_3a;
 238:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x238>, r1=<clobbered>
 23c:	e0000000 	bsr	0x0	// <switch_ctrl_recover> // arg_bytes: 0; regs: r0=<ret switch_ctrl_recover@0x23c>, r1=<clobbered>
 240:	e0000000 	bsr	0x0	// <lmac_bgrssi_update> // arg_bytes: 4; regs: r0=<ret lmac_bgrssi_update@0x240>, r1=<clobbered>
 244:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0x244>, r1=<clobbered>
 248:	136b      	lrw	r3, 0x0	// regs: r3=0x0
 24a:	3280      	movi	r2, 128	// regs: r2=0x80
 24c:	9320      	ld.w	r1, (r3, 0x0)	// regs: r1=*(0x0)
 24e:	4243      	lsli	r2, r2, 3	// regs: r2=0x400
 250:	b152      	st.w	r2, (r1, 0x48)	// *((*(0x0) + 0x48)) = 0x400
 252:	d844037c 	ld.b	r2, (r4, 0x37c)	// regs: r2=*(r4 + 0x37c)
 256:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(r4 + 0x37c) & 0x1)
 25a:	6d4f      	mov	r5, r3	// regs: r5=0x0
 25c:	e902000b 	bez	r2, 0x272	// if (r2 == 0x0) goto loc_272;
 260:	d804033c 	ld.b	r0, (r4, 0x33c)	// regs: r0=*(r4 + 0x33c)
 264:	e0000000 	bsr	0x0	// <lmac_lo_table_kick>; regs: r0=<ret lmac_lo_table_kick@0x264>, r1=<clobbered>
 268:	d86414ec 	ld.h	r3, (r4, 0x9d8)	// regs: r3=*(r4 + 0x9d8)
 26c:	2b00      	subi	r3, 1	// regs: r3=(*(r4 + 0x9d8) - 0x1)
 26e:	dc6414ec 	st.h	r3, (r4, 0x9d8)	// *(r4 + 0x9d8) = (*(r4 + 0x9d8) - 0x1)
loc_272:
 272:	9540      	ld.w	r2, (r5, 0x0)	// regs: r2=*(0x0)
 274:	9271      	ld.w	r3, (r2, 0x44)	// regs: r3=*((*(0x0) + 0x44))
 276:	ec630400 	ori	r3, r3, 1024	// regs: r3=(*((*(0x0) + 0x44)) | 0x400)
 27a:	b271      	st.w	r3, (r2, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x400)
 27c:	e0000000 	bsr	0x0	// <lmac_tdma_start>; regs: r0=<ret lmac_tdma_start@0x27c>, r1=<clobbered>
 280:	d80411b1 	ld.h	r0, (r4, 0x362)	// regs: r0=*(r4 + 0x362)
 284:	c4805560 	zext	r0, r0, 11, 4	// regs: r0=zext(*(r4 + 0x362))
 288:	e0000000 	bsr	0x0	// <lmac_rx_gain_cfg>; regs: r0=<ret lmac_rx_gain_cfg@0x288>, r1=<clobbered>
 28c:	3034      	movi	r0, 52	// regs: r0=0x34
 28e:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x28e>, r1=<clobbered>
 292:	06d4      	br	0x3a	// goto loc_3a;
 294:	d86449dc 	ld.bs	r3, (r4, 0x9dc)	// regs: r3=*(r4 + 0x9dc)
 298:	e9a3fed4 	bhsz	r3, 0x40	// if (r3 >= 0x0) goto loc_40;
 29c:	d8640318 	ld.b	r3, (r4, 0x318)	// regs: r3=*(r4 + 0x318)
 2a0:	2300      	addi	r3, 1	// regs: r3=(*(r4 + 0x318) + 0x1)
 2a2:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(r4 + 0x318) + 0x1))
 2a4:	3b1d      	cmphsi	r3, 30
 2a6:	3500      	movi	r5, 0	// regs: r5=0x0
 2a8:	dca42266 	st.w	r5, (r4, 0x998)	// *(r4 + 0x998) = 0x0
 2ac:	dc640318 	st.b	r3, (r4, 0x318)	// *(r4 + 0x318) = zext8((*(r4 + 0x318) + 0x1))
 2b0:	0ec8      	bf	0x40	// if (r3 < 0x1e) goto loc_40;
 2b2:	d864202f 	ld.w	r3, (r4, 0xbc)	// regs: r3=*(r4 + 0xbc)
 2b6:	3b42      	cmpnei	r3, 2
 2b8:	082d      	bt	0x312	// if (r3 != 0x2) goto loc_312;
 2ba:	d8642267 	ld.w	r3, (r4, 0x99c)	// regs: r3=*(r4 + 0x99c)
 2be:	3b42      	cmpnei	r3, 2
 2c0:	0ac0      	bt	0x40	// if (r3 != 0x2) goto loc_40;
 2c2:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(r4)
 2c4:	dca40318 	st.b	r5, (r4, 0x318)	// *(r4 + 0x318) = 0x0
 2c8:	834a      	ld.b	r2, (r3, 0xa)	// regs: r2=*((*(r4) + 0xa))
 2ca:	3101      	movi	r1, 1	// regs: r1=0x1
 2cc:	c4415c00 	ins	r2, r1, 0, 0
 2d0:	d82411e4 	ld.h	r1, (r4, 0x3c8)	// regs: r1=*(r4 + 0x3c8)
 2d4:	2109      	addi	r1, 10	// regs: r1=(*(r4 + 0x3c8) + 0xa)
 2d6:	7445      	zexth	r1, r1	// regs: r1=zext16((*(r4 + 0x3c8) + 0xa))
 2d8:	eb010063 	cmphsi	r1, 100
 2dc:	a34a      	st.b	r2, (r3, 0xa)	// *((*(r4) + 0xa)) = *((*(r4) + 0xa))
 2de:	dc2411e4 	st.h	r1, (r4, 0x3c8)	// *(r4 + 0x3c8) = zext16((*(r4 + 0x3c8) + 0xa))
 2e2:	0c16      	bf	0x30e	// if (r1 < 0x64) goto loc_30e;
 2e4:	d86411e5 	ld.h	r3, (r4, 0x3ca)	// regs: r3=*(r4 + 0x3ca)
 2e8:	3014      	movi	r0, 20	// regs: r0=0x14
 2ea:	dc6411e4 	st.h	r3, (r4, 0x3c8)	// *(r4 + 0x3c8) = *(r4 + 0x3ca)
 2ee:	dca42267 	st.w	r5, (r4, 0x99c)	// *(r4 + 0x99c) = 0x0
 2f2:	e0000000 	bsr	0x0	// <lmac_report_sleep_exit>; regs: r0=<ret lmac_report_sleep_exit@0x2f2>, r1=<clobbered>
 2f6:	d82411e4 	ld.h	r1, (r4, 0x3c8)	// regs: r1=*(r4 + 0x3c8)
 2fa:	1200      	lrw	r0, 0x0	// regs: r0=0x0
loc_2fc:
 2fc:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2fc>, r1=<clobbered>
 300:	d80420ce 	ld.w	r0, (r4, 0x338)	// regs: r0=*(r4 + 0x338)
 304:	c4805760 	zext	r0, r0, 27, 4	// regs: r0=zext(*(r4 + 0x338))
 308:	e0000000 	bsr	0x0	// <lmac_lo_freq_set>; regs: r0=<ret lmac_lo_freq_set@0x308>, r1=<clobbered>
 30c:	069a      	br	0x40	// goto loc_40;
loc_30e:
 30e:	111c      	lrw	r0, 0x0	// regs: r0=0x0
 310:	07f6      	br	0x2fc	// goto loc_2fc;
loc_312:
 312:	3b41      	cmpnei	r3, 1
 314:	0a96      	bt	0x40	// if (r3 != 0x1) goto loc_40;
 316:	d8442233 	ld.w	r2, (r4, 0x8cc)	// regs: r2=*(r4 + 0x8cc)
 31a:	111a      	lrw	r0, 0x0	// regs: r0=0x0
 31c:	8235      	ld.b	r1, (r2, 0x15)	// regs: r1=*((*(r4 + 0x8cc) + 0x15))
 31e:	dc620257 	st.b	r3, (r2, 0x257)	// *((*(r4 + 0x8cc) + 0x257)) = *(r4 + 0xbc)
 322:	c4235c03 	ins	r1, r3, 3, 3
 326:	a235      	st.b	r1, (r2, 0x15)	// *((*(r4 + 0x8cc) + 0x15)) = *((*(r4 + 0x8cc) + 0x15))
 328:	3303      	movi	r3, 3	// regs: r3=0x3
 32a:	d82411e4 	ld.h	r1, (r4, 0x3c8)	// regs: r1=*(r4 + 0x3c8)
 32e:	dc642267 	st.w	r3, (r4, 0x99c)	// *(r4 + 0x99c) = 0x3
 332:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x332>, r1=<clobbered>
 336:	d8442233 	ld.w	r2, (r4, 0x8cc)	// regs: r2=*(r4 + 0x8cc)
 33a:	d862025b 	ld.b	r3, (r2, 0x25b)	// regs: r3=*((*(r4 + 0x8cc) + 0x25b))
 33e:	e46320c0 	andi	r3, r3, 192	// regs: r3=(*((*(r4 + 0x8cc) + 0x25b)) & 0xc0)
 342:	eb430040 	cmpnei	r3, 64
 346:	0816      	bt	0x372	// if (r3 != 0x40) goto loc_372;
 348:	d8620a4d 	ld.b	r3, (r2, 0xa4d)	// regs: r3=*((*(r4 + 0x8cc) + 0xa4d))
 34c:	3218      	movi	r2, 24	// regs: r2=0x18
 34e:	7cc8      	mult	r3, r2	// regs: r3=(*((*(r4 + 0x8cc) + 0xa4d)) * 0x18)
 350:	60d0      	addu	r3, r4	// regs: r3=((*((*(r4 + 0x8cc) + 0xa4d)) * 0x18) + r4)
 352:	d8032030 	ld.w	r0, (r3, 0xc0)	// regs: r0=*((((*((*(r4 + 0x8cc) + 0xa4d)) * 0x18) + r4) + 0xc0))
 356:	e0000000 	bsr	0x0	// <lmac_lo_freq_set>; regs: r0=<ret lmac_lo_freq_set@0x356>, r1=<clobbered>
 35a:	d8042233 	ld.w	r0, (r4, 0x8cc)	// regs: r0=*(r4 + 0x8cc)
 35e:	e0000000 	bsr	0x0	// <dsleep_cfg_init>; regs: r0=<ret dsleep_cfg_init@0x35e>, r1=<clobbered>
 362:	d8642233 	ld.w	r3, (r4, 0x8cc)	// regs: r3=*(r4 + 0x8cc)
 366:	3108      	movi	r1, 8	// regs: r1=0x8
 368:	d80320af 	ld.w	r0, (r3, 0x2bc)	// regs: r0=*((*(r4 + 0x8cc) + 0x2bc))
loc_36c:
 36c:	e0000000 	bsr	0x0	// <dsleep_enter>; regs: r0=<ret dsleep_enter@0x36c>, r1=<clobbered>
 370:	0668      	br	0x40	// goto loc_40;
loc_372:
 372:	d80403de 	ld.b	r0, (r4, 0x3de)	// regs: r0=*(r4 + 0x3de)
 376:	ea03f424 	movi	r3, 62500	// regs: r3=0xf424
 37a:	c4834903 	rotli	r3, r3, 4	// regs: r3=rotl(0xf424, 0x4)
 37e:	6c57      	mov	r1, r5	// regs: r1=0x0
 380:	7c0c      	mult	r0, r3	// regs: r0=(*(r4 + 0x3de) * rotl(0xf424, 0x4))
 382:	07f5      	br	0x36c	// goto loc_36c;
 384:	d86449dc 	ld.bs	r3, (r4, 0x9dc)	// regs: r3=*(r4 + 0x9dc)
 388:	e9a3fe5c 	bhsz	r3, 0x40	// if (r3 >= 0x0) goto loc_40;
 38c:	d8642294 	ld.w	r3, (r4, 0xa50)	// regs: r3=*(r4 + 0xa50)
 390:	e9030007 	bez	r3, 0x39e	// if (r3 == 0x0) goto loc_39e;
 394:	d843006e 	ld.b	r2, (r3, 0x6e)	// regs: r2=*((*(r4 + 0xa50) + 0x6e))
 398:	2200      	addi	r2, 1	// regs: r2=(*((*(r4 + 0xa50) + 0x6e)) + 0x1)
 39a:	dc43006e 	st.b	r2, (r3, 0x6e)	// *((*(r4 + 0xa50) + 0x6e)) = (*((*(r4 + 0xa50) + 0x6e)) + 0x1)
loc_39e:
 39e:	d82420f3 	ld.w	r1, (r4, 0x3cc)	// regs: r1=*(r4 + 0x3cc)
 3a2:	d84420f4 	ld.w	r2, (r4, 0x3d0)	// regs: r2=*(r4 + 0x3d0)
 3a6:	c4412423 	or	r3, r1, r2	// regs: r3=(*(r4 + 0x3cc) | *(r4 + 0x3d0))
 3aa:	e903fe48 	bez	r3, 0x3a	// if (r3 == 0x0) goto loc_3a;
 3ae:	d90411e4 	ld.h	r8, (r4, 0x3c8)	// regs: r8=*(r4 + 0x3c8)
 3b2:	ea090000 	movi	r9, 0	// regs: r9=0x0
 3b6:	6599      	cmplt	r6, r6
 3b8:	c5010046 	addc	r6, r1, r8
 3bc:	c5220047 	addc	r7, r2, r9
 3c0:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x3c0>, r1=<clobbered>
 3c4:	6488      	cmphs	r2, r2
 3c6:	c4060102 	subc	r2, r6, r0
 3ca:	c4270103 	subc	r3, r7, r1
 3ce:	e9a3fe36 	bhsz	r3, 0x3a	// if (r3 >= 0x0) goto loc_3a;
 3d2:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(r4 + 0x319)
 3d6:	c4695c00 	ins	r3, r9, 0, 0
 3da:	dc640319 	st.b	r3, (r4, 0x319)	// *(r4 + 0x319) = *(r4 + 0x319)
 3de:	062e      	br	0x3a	// goto loc_3a;
 3e0:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
 3e4:	00000000 	.long	0x00000000	// <.bss.dut_fail_cnt.14189>
 3e8:	00000000 	.long	0x00000000	// <ah_lmac+0x8c2>
 3ec:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_tx_tmo.str1.1>
 3f0:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_tx_tmo.str1.1+0x10>
 3f4:	00000000 	.long	0x00000000	// <LMAC>
 3f8:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_tx_tmo.str1.1+0x27>
 3fc:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_tx_tmo.str1.1+0x42>
 400:	00000000 	.long	0x00000000	// <.rodata.lmac_irq_tx_tmo.str1.1+0x58>
loc_404:
 404:	d86449dc 	ld.bs	r3, (r4, 0x9dc)	// regs: r3=*(r4 + 0x9dc)
 408:	e9a3fe19 	bhsz	r3, 0x3a	// if (r3 >= 0x0) goto loc_3a;
 40c:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x40c>, r1=<clobbered>
 410:	0615      	br	0x3a	// goto loc_3a;

Disassembly of section .text.lmac_pv0_rts_init:

00000000 <lmac_pv0_rts_init>: // arg_bytes: 8
   0:	14d1      	push	r4, r15
   2:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(<arg0>)
   4:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg0>) & 0xfc)
   8:	ea0c0001 	movi	r12, 1	// regs: r12=0x1
   c:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   e:	c46c5c22 	ins	r3, r12, 3, 2
  12:	310b      	movi	r1, 11	// regs: r1=0xb
  14:	c4615c64 	ins	r3, r1, 7, 4
  18:	a060      	st.b	r3, (r0, 0x0)	// *(<arg0>) = (*(<arg0>) & 0xfc)
  1a:	3200      	movi	r2, 0	// regs: r2=0x0
  1c:	8061      	ld.b	r3, (r0, 0x1)	// regs: r3=*(<arg0> + 0x1)
  1e:	c4625c02 	ins	r3, r2, 2, 2
  22:	a061      	st.b	r3, (r0, 0x1)	// *(<arg0> + 0x1) = *(<arg0> + 0x1)
  24:	b440      	st.w	r2, (r4, 0x0)	// *(<arg1>) = 0x0
  26:	b441      	st.w	r2, (r4, 0x4)	// *(<arg1> + 0x4) = 0x0
  28:	3300      	movi	r3, 0	// regs: r3=0x0
  2a:	3200      	movi	r2, 0	// regs: r2=0x0
  2c:	b442      	st.w	r2, (r4, 0x8)	// *(<arg1> + 0x8) = 0x0
  2e:	b463      	st.w	r3, (r4, 0xc)	// *(<arg1> + 0xc) = 0x0
  30:	1346      	lrw	r2, 0x0	// regs: r2=0x0
  32:	d8220308 	ld.b	r1, (r2, 0x308)	// regs: r1=*(0x308)
  36:	3901      	cmphsi	r1, 2
  38:	0c05      	bf	0x42	// if (r1 < 0x2) goto loc_42;
  3a:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  3c:	c46c5c07 	ins	r3, r12, 7, 7
  40:	a462      	st.b	r3, (r4, 0x2)	// *(<arg1> + 0x2) = *(<arg1> + 0x2)
loc_42:
  42:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  44:	300b      	movi	r0, 11	// regs: r0=0xb
  46:	c4605cc0 	ins	r3, r0, 6, 0
  4a:	a462      	st.b	r3, (r4, 0x2)	// *(<arg1> + 0x2) = *(<arg1> + 0x2)
  4c:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(<arg1>)
  4e:	3000      	movi	r0, 0	// regs: r0=0x0
  50:	e46320df 	andi	r3, r3, 223	// regs: r3=(*(<arg1>) & 0xdf)
  54:	c4605c26 	ins	r3, r0, 7, 6
  58:	a460      	st.b	r3, (r4, 0x0)	// *(<arg1>) = (*(<arg1>) & 0xdf)
  5a:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  5c:	c4615c20 	ins	r3, r1, 1, 0
  60:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  62:	d8220875 	ld.b	r1, (r2, 0x875)	// regs: r1=*(0x875)
  66:	e4212002 	andi	r1, r1, 2	// regs: r1=(*(0x875) & 0x2)
  6a:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  6c:	e9010028 	bez	r1, 0xbc	// if (r1 == 0x0) goto loc_bc;
  70:	d8220867 	ld.b	r1, (r2, 0x867)	// regs: r1=*(0x867)
  74:	3943      	cmpnei	r1, 3
  76:	0823      	bt	0xbc	// if (r1 != 0x3) goto loc_bc;
  78:	c4605c64 	ins	r3, r0, 7, 4
loc_7c:
  7c:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  7e:	d822034a 	ld.b	r1, (r2, 0x34a)	// regs: r1=*(0x34a)
  82:	e4212001 	andi	r1, r1, 1	// regs: r1=(*(0x34a) & 0x1)
  86:	8441      	ld.b	r2, (r4, 0x1)	// regs: r2=*(<arg1> + 0x1)
  88:	e901001e 	bez	r1, 0xc4	// if (r1 == 0x0) goto loc_c4;
  8c:	3300      	movi	r3, 0	// regs: r3=0x0
  8e:	c4435c22 	ins	r2, r3, 3, 2
  92:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  94:	3103      	movi	r1, 3	// regs: r1=0x3
  96:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
loc_9a:
  9a:	3018      	movi	r0, 24	// regs: r0=0x18
  9c:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0x9c>, r1=<clobbered>
  a0:	8441      	ld.b	r2, (r4, 0x1)	// regs: r2=*(<arg1> + 0x1)
  a2:	c4425463 	zext	r3, r2, 3, 2	// regs: r3=zext(*(<arg1> + 0x1))
  a6:	3b41      	cmpnei	r3, 1
  a8:	b401      	st.w	r0, (r4, 0x4)	// *(<arg1> + 0x4) = <ret calc_symbol_len@0x9c>
  aa:	0c38      	bf	0x11a	// if (r3 == 0x1) goto loc_11a;
  ac:	3b40      	cmpnei	r3, 0
  ae:	0c12      	bf	0xd2	// if (r3 == 0x0) goto loc_d2;
  b0:	3b42      	cmpnei	r3, 2
  b2:	0c5f      	bf	0x170	// if (r3 == 0x2) goto loc_170;
  b4:	1206      	lrw	r0, 0x0	// regs: r0=0x0
  b6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xb6>, r1=<clobbered>
  ba:	042f      	br	0x118	// goto loc_118;
loc_bc:
  bc:	3101      	movi	r1, 1	// regs: r1=0x1
  be:	c4615c64 	ins	r3, r1, 7, 4
  c2:	07dd      	br	0x7c	// goto loc_7c;
loc_c4:
  c4:	3301      	movi	r3, 1	// regs: r3=0x1
  c6:	c4435c22 	ins	r2, r3, 3, 2
  ca:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  cc:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
  d0:	07e5      	br	0x9a	// goto loc_9a;
loc_d2:
  d2:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
  d4:	3001      	movi	r0, 1	// regs: r0=0x1
  d6:	c4235c02 	ins	r1, r3, 2, 2
  da:	c4205c04 	ins	r1, r0, 4, 4
  de:	c4205c06 	ins	r1, r0, 6, 6
  e2:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
  e4:	8c24      	ld.h	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
  e6:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
  ea:	c4225c67 	ins	r1, r2, 10, 7
  ee:	ac24      	st.h	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
  f0:	8449      	ld.b	r2, (r4, 0x9)	// regs: r2=*(<arg1> + 0x9)
  f2:	c4405c03 	ins	r2, r0, 3, 3
  f6:	a449      	st.b	r2, (r4, 0x9)	// *(<arg1> + 0x9) = *(<arg1> + 0x9)
  f8:	9442      	ld.w	r2, (r4, 0x8)	// regs: r2=*(<arg1> + 0x8)
  fa:	9421      	ld.w	r1, (r4, 0x4)	// regs: r1=*(<arg1> + 0x4)
  fc:	c4415d0c 	ins	r2, r1, 20, 12
 100:	b442      	st.w	r2, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 102:	844a      	ld.b	r2, (r4, 0xa)	// regs: r2=*(<arg1> + 0xa)
 104:	3102      	movi	r1, 2	// regs: r1=0x2
 106:	c4415c25 	ins	r2, r1, 6, 5
 10a:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = *(<arg1> + 0xa)
 10c:	844b      	ld.b	r2, (r4, 0xb)	// regs: r2=*(<arg1> + 0xb)
 10e:	c4435c00 	ins	r2, r3, 0, 0
 112:	c4435c01 	ins	r2, r3, 1, 1
 116:	a44b      	st.b	r2, (r4, 0xb)	// *(<arg1> + 0xb) = *(<arg1> + 0xb)
loc_118:
 118:	1491      	pop	r4, r15
loc_11a:
 11a:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 11c:	8400      	ld.b	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
 11e:	c4235c00 	ins	r1, r3, 0, 0
 122:	c4c054e0 	zext	r0, r0, 7, 6	// regs: r0=zext(*(<arg1>))
 126:	c4205c23 	ins	r1, r0, 4, 3
 12a:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 12c:	842a      	ld.b	r1, (r4, 0xa)	// regs: r1=*(<arg1> + 0xa)
 12e:	e42120fe 	andi	r1, r1, 254	// regs: r1=(*(<arg1> + 0xa) & 0xfe)
 132:	c4235c02 	ins	r1, r3, 2, 2
 136:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
 13a:	c4225c63 	ins	r1, r2, 6, 3
 13e:	8c42      	ld.h	r2, (r4, 0x4)	// regs: r2=*(<arg1> + 0x4)
 140:	a42a      	st.b	r1, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 142:	e422207f 	andi	r1, r2, 127	// regs: r1=(*(<arg1> + 0x4) & 0x7f)
 146:	e4632001 	andi	r3, r3, 1	// regs: r3=(zext(*(<arg1> + 0x1)) & 0x1)
 14a:	6044      	addu	r1, r1	// regs: r1=((*(<arg1> + 0x4) & 0x7f) + (*(<arg1> + 0x4) & 0x7f))
 14c:	6c4c      	or	r1, r3	// regs: r1=(((*(<arg1> + 0x4) & 0x7f) + (*(<arg1> + 0x4) & 0x7f)) | (zext(*(<arg1> + 0x1)) & 0x1))
 14e:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 150:	c4e25502 	zext	r2, r2, 8, 7	// regs: r2=zext(*(<arg1> + 0x4))
 154:	3b80      	bclri	r3, 0	// regs: r3=(*(<arg1> + 0xc) & ~(0x1 << 0x0))
 156:	3b81      	bclri	r3, 1	// regs: r3=((*(<arg1> + 0xc) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
 158:	6cc8      	or	r3, r2	// regs: r3=(((*(<arg1> + 0xc) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)) | zext(*(<arg1> + 0x4)))
 15a:	3202      	movi	r2, 2	// regs: r2=0x2
 15c:	c4625c22 	ins	r3, r2, 3, 2
 160:	e46320ef 	andi	r3, r3, 239	// regs: r3=((((*(<arg1> + 0xc) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)) | zext(*(<arg1> + 0x4))) & 0xef)
 164:	3200      	movi	r2, 0	// regs: r2=0x0
 166:	c4625c05 	ins	r3, r2, 5, 5
 16a:	a42b      	st.b	r1, (r4, 0xb)	// *(<arg1> + 0xb) = (((*(<arg1> + 0x4) & 0x7f) + (*(<arg1> + 0x4) & 0x7f)) | (zext(*(<arg1> + 0x1)) & 0x1))
 16c:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = ((((*(<arg1> + 0xc) & ~(0x1 << 0x0)) & ~(0x1 << 0x1)) | zext(*(<arg1> + 0x4))) & 0xef)
 16e:	07d5      	br	0x118	// goto loc_118;
loc_170:
 170:	842a      	ld.b	r1, (r4, 0xa)	// regs: r1=*(<arg1> + 0xa)
 172:	3001      	movi	r0, 1	// regs: r0=0x1
 174:	e42120fe 	andi	r1, r1, 254	// regs: r1=(*(<arg1> + 0xa) & 0xfe)
 178:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
 17c:	c4205c02 	ins	r1, r0, 2, 2
 180:	c4225c63 	ins	r1, r2, 6, 3
 184:	8440      	ld.b	r2, (r4, 0x0)	// regs: r2=*(<arg1>)
 186:	c4c254e2 	zext	r2, r2, 7, 6	// regs: r2=zext(*(<arg1>))
 18a:	a42a      	st.b	r1, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 18c:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 18e:	c4225c23 	ins	r1, r2, 4, 3
 192:	844c      	ld.b	r2, (r4, 0xc)	// regs: r2=*(<arg1> + 0xc)
 194:	c4435c22 	ins	r2, r3, 3, 2
 198:	6ccb      	mov	r3, r2	// regs: r3=*(<arg1> + 0xc)
 19a:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 19c:	c4605c04 	ins	r3, r0, 4, 4
 1a0:	8c22      	ld.h	r1, (r4, 0x4)	// regs: r1=*(<arg1> + 0x4)
 1a2:	e441207f 	andi	r2, r1, 127	// regs: r2=(*(<arg1> + 0x4) & 0x7f)
 1a6:	d984000b 	ld.b	r12, (r4, 0xb)	// regs: r12=*(<arg1> + 0xb)
 1aa:	c4e15501 	zext	r1, r1, 8, 7	// regs: r1=zext(*(<arg1> + 0x4))
 1ae:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg1> + 0xc) & 0xfc)
 1b2:	6cc4      	or	r3, r1	// regs: r3=((*(<arg1> + 0xc) & 0xfc) | zext(*(<arg1> + 0x4)))
 1b4:	6b00      	and	r12, r0	// regs: r12=(*(<arg1> + 0xb) & 0x1)
 1b6:	7080      	lsl	r2, r0
 1b8:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = ((*(<arg1> + 0xc) & 0xfc) | zext(*(<arg1> + 0x4)))
 1ba:	c5822423 	or	r3, r2, r12	// regs: r3=((*(<arg1> + 0x4) & 0x7f) | (*(<arg1> + 0xb) & 0x1))
 1be:	c4605c00 	ins	r3, r0, 0, 0
 1c2:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = ((*(<arg1> + 0x4) & 0x7f) | (*(<arg1> + 0xb) & 0x1))
 1c4:	07aa      	br	0x118	// goto loc_118;
 1c6:	0000      	.short	0x0000
 1c8:	00000000 	.long	0x00000000	// <ah_lmac>
 1cc:	00000000 	.long	0x00000000	// <.rodata.lmac_pv0_rts_init.str1.1>

Disassembly of section .text.lmac_pv0_pspoll_init:

00000000 <lmac_pv0_pspoll_init>: // arg_bytes: 8
   0:	14d1      	push	r4, r15
   2:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(<arg0>)
   4:	3201      	movi	r2, 1	// regs: r2=0x1
   6:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg0>) & 0xfc)
   a:	c4625c22 	ins	r3, r2, 3, 2
   e:	320a      	movi	r2, 10	// regs: r2=0xa
  10:	c4625c64 	ins	r3, r2, 7, 4
  14:	a060      	st.b	r3, (r0, 0x0)	// *(<arg0>) = (*(<arg0>) & 0xfc)
  16:	8061      	ld.b	r3, (r0, 0x1)	// regs: r3=*(<arg0> + 0x1)
  18:	6d07      	mov	r4, r1	// regs: r4=<arg1>
  1a:	e46320fb 	andi	r3, r3, 251	// regs: r3=(*(<arg0> + 0x1) & 0xfb)
  1e:	3100      	movi	r1, 0	// regs: r1=0x0
  20:	c4615c04 	ins	r3, r1, 4, 4
  24:	a061      	st.b	r3, (r0, 0x1)	// *(<arg0> + 0x1) = (*(<arg0> + 0x1) & 0xfb)
  26:	ea0c0000 	movi	r12, 0	// regs: r12=0x0
  2a:	b420      	st.w	r1, (r4, 0x0)	// *(<arg1>) = 0x0
  2c:	3300      	movi	r3, 0	// regs: r3=0x0
  2e:	a442      	st.b	r2, (r4, 0x2)	// *(<arg1> + 0x2) = 0xa
  30:	ea0d0000 	movi	r13, 0	// regs: r13=0x0
  34:	1254      	lrw	r2, 0x0	// regs: r2=0x0
  36:	a460      	st.b	r3, (r4, 0x0)	// *(<arg1>) = 0x0
  38:	dd842002 	st.w	r12, (r4, 0x8)	// *(<arg1> + 0x8) = 0x0
  3c:	dda42003 	st.w	r13, (r4, 0xc)	// *(<arg1> + 0xc) = 0x0
  40:	d8020875 	ld.b	r0, (r2, 0x875)	// regs: r0=*(0x875)
  44:	e4002002 	andi	r0, r0, 2	// regs: r0=(*(0x875) & 0x2)
  48:	b421      	st.w	r1, (r4, 0x4)	// *(<arg1> + 0x4) = 0x0
  4a:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  4c:	e900002e 	bez	r0, 0xa8	// if (r0 == 0x0) goto loc_a8;
  50:	d8020867 	ld.b	r0, (r2, 0x867)	// regs: r0=*(0x867)
  54:	3843      	cmpnei	r0, 3
  56:	0829      	bt	0xa8	// if (r0 != 0x3) goto loc_a8;
loc_58:
  58:	c4615c64 	ins	r3, r1, 7, 4
  5c:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  5e:	d8220308 	ld.b	r1, (r2, 0x308)	// regs: r1=*(0x308)
  62:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  64:	c4615c20 	ins	r3, r1, 1, 0
  68:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  6a:	d822034a 	ld.b	r1, (r2, 0x34a)	// regs: r1=*(0x34a)
  6e:	e4212001 	andi	r1, r1, 1	// regs: r1=(*(0x34a) & 0x1)
  72:	8441      	ld.b	r2, (r4, 0x1)	// regs: r2=*(<arg1> + 0x1)
  74:	e901001c 	bez	r1, 0xac	// if (r1 == 0x0) goto loc_ac;
  78:	3300      	movi	r3, 0	// regs: r3=0x0
  7a:	c4435c22 	ins	r2, r3, 3, 2
  7e:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  80:	3103      	movi	r1, 3	// regs: r1=0x3
  82:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
loc_86:
  86:	3014      	movi	r0, 20	// regs: r0=0x14
  88:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0x88>, r1=<clobbered>
  8c:	8441      	ld.b	r2, (r4, 0x1)	// regs: r2=*(<arg1> + 0x1)
  8e:	c4425463 	zext	r3, r2, 3, 2	// regs: r3=zext(*(<arg1> + 0x1))
  92:	3b41      	cmpnei	r3, 1
  94:	b401      	st.w	r0, (r4, 0x4)	// *(<arg1> + 0x4) = <ret calc_symbol_len@0x88>
  96:	0c36      	bf	0x102	// if (r3 == 0x1) goto loc_102;
  98:	3b40      	cmpnei	r3, 0
  9a:	0c10      	bf	0xba	// if (r3 == 0x0) goto loc_ba;
  9c:	3b42      	cmpnei	r3, 2
  9e:	0c55      	bf	0x148	// if (r3 == 0x2) goto loc_148;
  a0:	111a      	lrw	r0, 0x0	// regs: r0=0x0
  a2:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xa2>, r1=<clobbered>
  a6:	042d      	br	0x100	// goto loc_100;
loc_a8:
  a8:	3101      	movi	r1, 1	// regs: r1=0x1
  aa:	07d7      	br	0x58	// goto loc_58;
loc_ac:
  ac:	3301      	movi	r3, 1	// regs: r3=0x1
  ae:	c4435c22 	ins	r2, r3, 3, 2
  b2:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  b4:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
  b8:	07e7      	br	0x86	// goto loc_86;
loc_ba:
  ba:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
  bc:	3001      	movi	r0, 1	// regs: r0=0x1
  be:	c4235c02 	ins	r1, r3, 2, 2
  c2:	c4205c04 	ins	r1, r0, 4, 4
  c6:	c4205c06 	ins	r1, r0, 6, 6
  ca:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
  cc:	8c24      	ld.h	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
  ce:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
  d2:	c4225c67 	ins	r1, r2, 10, 7
  d6:	ac24      	st.h	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
  d8:	8449      	ld.b	r2, (r4, 0x9)	// regs: r2=*(<arg1> + 0x9)
  da:	c4435c03 	ins	r2, r3, 3, 3
  de:	a449      	st.b	r2, (r4, 0x9)	// *(<arg1> + 0x9) = *(<arg1> + 0x9)
  e0:	9442      	ld.w	r2, (r4, 0x8)	// regs: r2=*(<arg1> + 0x8)
  e2:	3114      	movi	r1, 20	// regs: r1=0x14
  e4:	c4415d0c 	ins	r2, r1, 20, 12
  e8:	b442      	st.w	r2, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
  ea:	844a      	ld.b	r2, (r4, 0xa)	// regs: r2=*(<arg1> + 0xa)
  ec:	3102      	movi	r1, 2	// regs: r1=0x2
  ee:	c4415c25 	ins	r2, r1, 6, 5
  f2:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = *(<arg1> + 0xa)
  f4:	844b      	ld.b	r2, (r4, 0xb)	// regs: r2=*(<arg1> + 0xb)
  f6:	c4435c00 	ins	r2, r3, 0, 0
  fa:	c4435c01 	ins	r2, r3, 1, 1
  fe:	a44b      	st.b	r2, (r4, 0xb)	// *(<arg1> + 0xb) = *(<arg1> + 0xb)
loc_100:
 100:	1491      	pop	r4, r15
loc_102:
 102:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 104:	8400      	ld.b	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
 106:	c4235c00 	ins	r1, r3, 0, 0
 10a:	c4c054e0 	zext	r0, r0, 7, 6	// regs: r0=zext(*(<arg1>))
 10e:	c4205c23 	ins	r1, r0, 4, 3
 112:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 114:	842a      	ld.b	r1, (r4, 0xa)	// regs: r1=*(<arg1> + 0xa)
 116:	e42120fe 	andi	r1, r1, 254	// regs: r1=(*(<arg1> + 0xa) & 0xfe)
 11a:	c4235c02 	ins	r1, r3, 2, 2
 11e:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
 122:	6cc7      	mov	r3, r1	// regs: r3=(*(<arg1> + 0xa) & 0xfe)
 124:	c4625c63 	ins	r3, r2, 6, 3
 128:	a46a      	st.b	r3, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 12a:	3328      	movi	r3, 40	// regs: r3=0x28
 12c:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = 0x28
 12e:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 130:	3202      	movi	r2, 2	// regs: r2=0x2
 132:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg1> + 0xc) & 0xfc)
 136:	c4625c22 	ins	r3, r2, 3, 2
 13a:	e46320ec 	andi	r3, r3, 236	// regs: r3=((*(<arg1> + 0xc) & 0xfc) & 0xec)
 13e:	3200      	movi	r2, 0	// regs: r2=0x0
 140:	c4625c05 	ins	r3, r2, 5, 5
 144:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = ((*(<arg1> + 0xc) & 0xfc) & 0xec)
 146:	07dd      	br	0x100	// goto loc_100;
loc_148:
 148:	842a      	ld.b	r1, (r4, 0xa)	// regs: r1=*(<arg1> + 0xa)
 14a:	3001      	movi	r0, 1	// regs: r0=0x1
 14c:	e42120fe 	andi	r1, r1, 254	// regs: r1=(*(<arg1> + 0xa) & 0xfe)
 150:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
 154:	c4205c02 	ins	r1, r0, 2, 2
 158:	c4225c63 	ins	r1, r2, 6, 3
 15c:	8440      	ld.b	r2, (r4, 0x0)	// regs: r2=*(<arg1>)
 15e:	c4c254e2 	zext	r2, r2, 7, 6	// regs: r2=zext(*(<arg1>))
 162:	a42a      	st.b	r1, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 164:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 166:	c4225c23 	ins	r1, r2, 4, 3
 16a:	844c      	ld.b	r2, (r4, 0xc)	// regs: r2=*(<arg1> + 0xc)
 16c:	c4435c22 	ins	r2, r3, 3, 2
 170:	6ccb      	mov	r3, r2	// regs: r3=*(<arg1> + 0xc)
 172:	c4605c04 	ins	r3, r0, 4, 4
 176:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg1> + 0xc) & 0xfc)
 17a:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = (*(<arg1> + 0xc) & 0xfc)
 17c:	3328      	movi	r3, 40	// regs: r3=0x28
 17e:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 180:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = 0x28
 182:	07bf      	br	0x100	// goto loc_100;
 184:	00000000 	.long	0x00000000	// <ah_lmac>
 188:	00000000 	.long	0x00000000	// <.rodata.lmac_pv0_pspoll_init.str1.1>

Disassembly of section .text.lmac_pv0_wpack_init:

00000000 <lmac_pv0_wpack_init>: // arg_bytes: 8
   0:	14d2      	push	r4-r5, r15
   2:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(<arg0>)
   4:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   6:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg0>) & 0xfc)
   a:	3101      	movi	r1, 1	// regs: r1=0x1
   c:	c4615c22 	ins	r3, r1, 3, 2
  10:	ea0c0007 	movi	r12, 7	// regs: r12=0x7
  14:	c46c5c64 	ins	r3, r12, 7, 4
  18:	a060      	st.b	r3, (r0, 0x0)	// *(<arg0>) = (*(<arg0>) & 0xfc)
  1a:	3200      	movi	r2, 0	// regs: r2=0x0
  1c:	8061      	ld.b	r3, (r0, 0x1)	// regs: r3=*(<arg0> + 0x1)
  1e:	c4625c02 	ins	r3, r2, 2, 2
  22:	a061      	st.b	r3, (r0, 0x1)	// *(<arg0> + 0x1) = *(<arg0> + 0x1)
  24:	806c      	ld.b	r3, (r0, 0xc)	// regs: r3=*(<arg0> + 0xc)
  26:	c4615c00 	ins	r3, r1, 0, 0
  2a:	c4625c02 	ins	r3, r2, 2, 2
  2e:	a06c      	st.b	r3, (r0, 0xc)	// *(<arg0> + 0xc) = *(<arg0> + 0xc)
  30:	806f      	ld.b	r3, (r0, 0xf)	// regs: r3=*(<arg0> + 0xf)
  32:	c4615c05 	ins	r3, r1, 5, 5
  36:	e46320f8 	andi	r3, r3, 248	// regs: r3=(*(<arg0> + 0xf) & 0xf8)
  3a:	c4615c03 	ins	r3, r1, 3, 3
  3e:	c4625c04 	ins	r3, r2, 4, 4
  42:	a06f      	st.b	r3, (r0, 0xf)	// *(<arg0> + 0xf) = (*(<arg0> + 0xf) & 0xf8)
  44:	806a      	ld.b	r3, (r0, 0xa)	// regs: r3=*(<arg0> + 0xa)
  46:	d980000d 	ld.b	r12, (r0, 0xd)	// regs: r12=*(<arg0> + 0xd)
  4a:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg0> + 0xa) & 0xfc)
  4e:	c5815c21 	ins	r12, r1, 2, 1
  52:	c4615c22 	ins	r3, r1, 3, 2
  56:	310d      	movi	r1, 13	// regs: r1=0xd
  58:	c4615c64 	ins	r3, r1, 7, 4
  5c:	dd80000d 	st.b	r12, (r0, 0xd)	// *(<arg0> + 0xd) = *(<arg0> + 0xd)
  60:	a06a      	st.b	r3, (r0, 0xa)	// *(<arg0> + 0xa) = (*(<arg0> + 0xa) & 0xfc)
  62:	3100      	movi	r1, 0	// regs: r1=0x0
  64:	3000      	movi	r0, 0	// regs: r0=0x0
  66:	13a0      	lrw	r5, 0x0	// regs: r5=0x0
  68:	b440      	st.w	r2, (r4, 0x0)	// *(<arg1>) = 0x0
  6a:	b441      	st.w	r2, (r4, 0x4)	// *(<arg1> + 0x4) = 0x0
  6c:	b402      	st.w	r0, (r4, 0x8)	// *(<arg1> + 0x8) = 0x0
  6e:	b423      	st.w	r1, (r4, 0xc)	// *(<arg1> + 0xc) = 0x0
  70:	d8250308 	ld.b	r1, (r5, 0x308)	// regs: r1=*(0x308)
  74:	3901      	cmphsi	r1, 2
  76:	0c05      	bf	0x80	// if (r1 < 0x2) goto loc_80;
  78:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  7a:	c4625c07 	ins	r3, r2, 7, 7
  7e:	a462      	st.b	r3, (r4, 0x2)	// *(<arg1> + 0x2) = *(<arg1> + 0x2)
loc_80:
  80:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  82:	320d      	movi	r2, 13	// regs: r2=0xd
  84:	c4625cc0 	ins	r3, r2, 6, 0
  88:	a462      	st.b	r3, (r4, 0x2)	// *(<arg1> + 0x2) = *(<arg1> + 0x2)
  8a:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(<arg1>)
  8c:	3000      	movi	r0, 0	// regs: r0=0x0
  8e:	e46320df 	andi	r3, r3, 223	// regs: r3=(*(<arg1>) & 0xdf)
  92:	c4605c26 	ins	r3, r0, 7, 6
  96:	a460      	st.b	r3, (r4, 0x0)	// *(<arg1>) = (*(<arg1>) & 0xdf)
  98:	d8450875 	ld.b	r2, (r5, 0x875)	// regs: r2=*(0x875)
  9c:	e4422002 	andi	r2, r2, 2	// regs: r2=(*(0x875) & 0x2)
  a0:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  a2:	e9020032 	bez	r2, 0x106	// if (r2 == 0x0) goto loc_106;
  a6:	d8450867 	ld.b	r2, (r5, 0x867)	// regs: r2=*(0x867)
  aa:	3a43      	cmpnei	r2, 3
  ac:	082d      	bt	0x106	// if (r2 != 0x3) goto loc_106;
  ae:	c4605c64 	ins	r3, r0, 7, 4
loc_b2:
  b2:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  b4:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  b6:	c4615c20 	ins	r3, r1, 1, 0
  ba:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  bc:	d825034a 	ld.b	r1, (r5, 0x34a)	// regs: r1=*(0x34a)
  c0:	e4212001 	andi	r1, r1, 1	// regs: r1=(*(0x34a) & 0x1)
  c4:	8441      	ld.b	r2, (r4, 0x1)	// regs: r2=*(<arg1> + 0x1)
  c6:	e9010024 	bez	r1, 0x10e	// if (r1 == 0x0) goto loc_10e;
  ca:	3300      	movi	r3, 0	// regs: r3=0x0
  cc:	c4435c22 	ins	r2, r3, 3, 2
  d0:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  d2:	3103      	movi	r1, 3	// regs: r1=0x3
  d4:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
  d8:	3014      	movi	r0, 20	// regs: r0=0x14
  da:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0xda>, r1=<clobbered>
  de:	3328      	movi	r3, 40	// regs: r3=0x28
  e0:	b401      	st.w	r0, (r4, 0x4)	// *(<arg1> + 0x4) = <ret calc_symbol_len@0xda>
  e2:	7c0c      	mult	r0, r3	// regs: r0=(<ret calc_symbol_len@0xda> * 0x28)
  e4:	e400022f 	addi	r0, r0, 560	// regs: r0=((<ret calc_symbol_len@0xda> * 0x28) + 0x230)
loc_e8:
  e8:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  ea:	c4435462 	zext	r2, r3, 3, 2	// regs: r2=zext(*(<arg1> + 0x1))
  ee:	3a41      	cmpnei	r2, 1
  f0:	dc051337 	st.h	r0, (r5, 0x66e)	// *(0x66e) = r0
  f4:	0c3e      	bf	0x170	// if (r2 == 0x1) goto loc_170;
  f6:	3a40      	cmpnei	r2, 0
  f8:	0c19      	bf	0x12a	// if (r2 == 0x0) goto loc_12a;
  fa:	3a42      	cmpnei	r2, 2
  fc:	0c58      	bf	0x1ac	// if (r2 == 0x2) goto loc_1ac;
  fe:	111b      	lrw	r0, 0x0	// regs: r0=0x0
 100:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x100>, r1=<clobbered>
 104:	0453      	br	0x1aa	// goto loc_1aa;
loc_106:
 106:	3201      	movi	r2, 1	// regs: r2=0x1
 108:	c4625c64 	ins	r3, r2, 7, 4
 10c:	07d3      	br	0xb2	// goto loc_b2;
loc_10e:
 10e:	3301      	movi	r3, 1	// regs: r3=0x1
 110:	c4435c22 	ins	r2, r3, 3, 2
 114:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
 116:	3014      	movi	r0, 20	// regs: r0=0x14
 118:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
 11c:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0x11c>, r1=<clobbered>
 120:	3328      	movi	r3, 40	// regs: r3=0x28
 122:	b401      	st.w	r0, (r4, 0x4)	// *(<arg1> + 0x4) = <ret calc_symbol_len@0x11c>
 124:	7c0c      	mult	r0, r3	// regs: r0=(<ret calc_symbol_len@0x11c> * 0x28)
 126:	20ef      	addi	r0, 240	// regs: r0=((<ret calc_symbol_len@0x11c> * 0x28) + 0xf0)
 128:	07e0      	br	0xe8	// goto loc_e8;
loc_12a:
 12a:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 12c:	3001      	movi	r0, 1	// regs: r0=0x1
 12e:	c4225c02 	ins	r1, r2, 2, 2
 132:	c4205c04 	ins	r1, r0, 4, 4
 136:	c4205c06 	ins	r1, r0, 6, 6
 13a:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 13c:	8c24      	ld.h	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 13e:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 142:	c4235c67 	ins	r1, r3, 10, 7
 146:	ac24      	st.h	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 148:	8469      	ld.b	r3, (r4, 0x9)	// regs: r3=*(<arg1> + 0x9)
 14a:	c4625c03 	ins	r3, r2, 3, 3
 14e:	a469      	st.b	r3, (r4, 0x9)	// *(<arg1> + 0x9) = *(<arg1> + 0x9)
 150:	9462      	ld.w	r3, (r4, 0x8)	// regs: r3=*(<arg1> + 0x8)
 152:	3114      	movi	r1, 20	// regs: r1=0x14
 154:	c4615d0c 	ins	r3, r1, 20, 12
 158:	b462      	st.w	r3, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 15a:	846a      	ld.b	r3, (r4, 0xa)	// regs: r3=*(<arg1> + 0xa)
 15c:	c4625c25 	ins	r3, r2, 6, 5
 160:	a46a      	st.b	r3, (r4, 0xa)	// *(<arg1> + 0xa) = *(<arg1> + 0xa)
 162:	846b      	ld.b	r3, (r4, 0xb)	// regs: r3=*(<arg1> + 0xb)
 164:	c4625c00 	ins	r3, r2, 0, 0
 168:	c4625c01 	ins	r3, r2, 1, 1
loc_16c:
 16c:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = r3
 16e:	041e      	br	0x1aa	// goto loc_1aa;
loc_170:
 170:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 172:	8400      	ld.b	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
 174:	c4225c00 	ins	r1, r2, 0, 0
 178:	c4c054e0 	zext	r0, r0, 7, 6	// regs: r0=zext(*(<arg1>))
 17c:	c4205c23 	ins	r1, r0, 4, 3
 180:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 182:	842a      	ld.b	r1, (r4, 0xa)	// regs: r1=*(<arg1> + 0xa)
 184:	e42120fe 	andi	r1, r1, 254	// regs: r1=(*(<arg1> + 0xa) & 0xfe)
 188:	c4225c02 	ins	r1, r2, 2, 2
 18c:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 190:	6c87      	mov	r2, r1	// regs: r2=(*(<arg1> + 0xa) & 0xfe)
 192:	c4435c63 	ins	r2, r3, 6, 3
 196:	3328      	movi	r3, 40	// regs: r3=0x28
 198:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = 0x28
 19a:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 19c:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 19e:	e46320e0 	andi	r3, r3, 224	// regs: r3=(*(<arg1> + 0xc) & 0xe0)
 1a2:	3200      	movi	r2, 0	// regs: r2=0x0
 1a4:	c4625c05 	ins	r3, r2, 5, 5
 1a8:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = (*(<arg1> + 0xc) & 0xe0)
loc_1aa:
 1aa:	1492      	pop	r4-r5, r15
loc_1ac:
 1ac:	844a      	ld.b	r2, (r4, 0xa)	// regs: r2=*(<arg1> + 0xa)
 1ae:	3101      	movi	r1, 1	// regs: r1=0x1
 1b0:	e44220fe 	andi	r2, r2, 254	// regs: r2=(*(<arg1> + 0xa) & 0xfe)
 1b4:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 1b8:	c4415c02 	ins	r2, r1, 2, 2
 1bc:	c4435c63 	ins	r2, r3, 6, 3
 1c0:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(<arg1>)
 1c2:	c4c354e3 	zext	r3, r3, 7, 6	// regs: r3=zext(*(<arg1>))
 1c6:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 1c8:	8448      	ld.b	r2, (r4, 0x8)	// regs: r2=*(<arg1> + 0x8)
 1ca:	c4435c23 	ins	r2, r3, 4, 3
 1ce:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 1d0:	e46320f3 	andi	r3, r3, 243	// regs: r3=(*(<arg1> + 0xc) & 0xf3)
 1d4:	c4615c04 	ins	r3, r1, 4, 4
 1d8:	e46320fc 	andi	r3, r3, 252	// regs: r3=((*(<arg1> + 0xc) & 0xf3) & 0xfc)
 1dc:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = ((*(<arg1> + 0xc) & 0xf3) & 0xfc)
 1de:	a448      	st.b	r2, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 1e0:	3328      	movi	r3, 40	// regs: r3=0x28
 1e2:	07c5      	br	0x16c	// goto loc_16c;
 1e4:	0000      	.short	0x0000	// <ah_lmac>
 1e6:	0000      	.short	0x0000
 1e8:	00000000 	.long	0x00000000	// <.rodata.lmac_pv0_wpack_init.str1.1>

Disassembly of section .text.lmac_pv0_wpcts_init:

00000000 <lmac_pv0_wpcts_init>: // arg_bytes: 8
   0:	14d2      	push	r4-r5, r15
   2:	8060      	ld.b	r3, (r0, 0x0)	// regs: r3=*(<arg0>)
   4:	3201      	movi	r2, 1	// regs: r2=0x1
   6:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg0>) & 0xfc)
   a:	ea0c0007 	movi	r12, 7	// regs: r12=0x7
   e:	c4625c22 	ins	r3, r2, 3, 2
  12:	c46c5c64 	ins	r3, r12, 7, 4
  16:	a060      	st.b	r3, (r0, 0x0)	// *(<arg0>) = (*(<arg0>) & 0xfc)
  18:	6d07      	mov	r4, r1	// regs: r4=<arg1>
  1a:	8061      	ld.b	r3, (r0, 0x1)	// regs: r3=*(<arg0> + 0x1)
  1c:	3100      	movi	r1, 0	// regs: r1=0x0
  1e:	c4615c02 	ins	r3, r1, 2, 2
  22:	a061      	st.b	r3, (r0, 0x1)	// *(<arg0> + 0x1) = *(<arg0> + 0x1)
  24:	806c      	ld.b	r3, (r0, 0xc)	// regs: r3=*(<arg0> + 0xc)
  26:	c4625c00 	ins	r3, r2, 0, 0
  2a:	c4615c02 	ins	r3, r1, 2, 2
  2e:	a06c      	st.b	r3, (r0, 0xc)	// *(<arg0> + 0xc) = *(<arg0> + 0xc)
  30:	806f      	ld.b	r3, (r0, 0xf)	// regs: r3=*(<arg0> + 0xf)
  32:	c4625c05 	ins	r3, r2, 5, 5
  36:	e46320f8 	andi	r3, r3, 248	// regs: r3=(*(<arg0> + 0xf) & 0xf8)
  3a:	c4625c03 	ins	r3, r2, 3, 3
  3e:	c4615c04 	ins	r3, r1, 4, 4
  42:	d980000d 	ld.b	r12, (r0, 0xd)	// regs: r12=*(<arg0> + 0xd)
  46:	a06f      	st.b	r3, (r0, 0xf)	// *(<arg0> + 0xf) = (*(<arg0> + 0xf) & 0xf8)
  48:	806a      	ld.b	r3, (r0, 0xa)	// regs: r3=*(<arg0> + 0xa)
  4a:	c5825c21 	ins	r12, r2, 2, 1
  4e:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg0> + 0xa) & 0xfc)
  52:	dd80000d 	st.b	r12, (r0, 0xd)	// *(<arg0> + 0xd) = *(<arg0> + 0xd)
  56:	c4625c22 	ins	r3, r2, 3, 2
  5a:	ea0c000c 	movi	r12, 12	// regs: r12=0xc
  5e:	c46c5c64 	ins	r3, r12, 7, 4
  62:	a06a      	st.b	r3, (r0, 0xa)	// *(<arg0> + 0xa) = (*(<arg0> + 0xa) & 0xfc)
  64:	b420      	st.w	r1, (r4, 0x0)	// *(<arg1>) = 0x0
  66:	b421      	st.w	r1, (r4, 0x4)	// *(<arg1> + 0x4) = 0x0
  68:	3000      	movi	r0, 0	// regs: r0=0x0
  6a:	3100      	movi	r1, 0	// regs: r1=0x0
  6c:	12bf      	lrw	r5, 0x0	// regs: r5=0x0
  6e:	b402      	st.w	r0, (r4, 0x8)	// *(<arg1> + 0x8) = 0x0
  70:	b423      	st.w	r1, (r4, 0xc)	// *(<arg1> + 0xc) = 0x0
  72:	d8250308 	ld.b	r1, (r5, 0x308)	// regs: r1=*(0x308)
  76:	3901      	cmphsi	r1, 2
  78:	0c05      	bf	0x82	// if (r1 < 0x2) goto loc_82;
  7a:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  7c:	c4625c07 	ins	r3, r2, 7, 7
  80:	a462      	st.b	r3, (r4, 0x2)	// *(<arg1> + 0x2) = *(<arg1> + 0x2)
loc_82:
  82:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  84:	320c      	movi	r2, 12	// regs: r2=0xc
  86:	c4625cc0 	ins	r3, r2, 6, 0
  8a:	a462      	st.b	r3, (r4, 0x2)	// *(<arg1> + 0x2) = *(<arg1> + 0x2)
  8c:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(<arg1>)
  8e:	3000      	movi	r0, 0	// regs: r0=0x0
  90:	e46320df 	andi	r3, r3, 223	// regs: r3=(*(<arg1>) & 0xdf)
  94:	c4605c26 	ins	r3, r0, 7, 6
  98:	a460      	st.b	r3, (r4, 0x0)	// *(<arg1>) = (*(<arg1>) & 0xdf)
  9a:	d8450875 	ld.b	r2, (r5, 0x875)	// regs: r2=*(0x875)
  9e:	e4422002 	andi	r2, r2, 2	// regs: r2=(*(0x875) & 0x2)
  a2:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  a4:	e9020032 	bez	r2, 0x108	// if (r2 == 0x0) goto loc_108;
  a8:	d8450867 	ld.b	r2, (r5, 0x867)	// regs: r2=*(0x867)
  ac:	3a43      	cmpnei	r2, 3
  ae:	082d      	bt	0x108	// if (r2 != 0x3) goto loc_108;
  b0:	c4605c64 	ins	r3, r0, 7, 4
loc_b4:
  b4:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  b6:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  b8:	c4615c20 	ins	r3, r1, 1, 0
  bc:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  be:	d825034a 	ld.b	r1, (r5, 0x34a)	// regs: r1=*(0x34a)
  c2:	e4212001 	andi	r1, r1, 1	// regs: r1=(*(0x34a) & 0x1)
  c6:	8441      	ld.b	r2, (r4, 0x1)	// regs: r2=*(<arg1> + 0x1)
  c8:	e9010024 	bez	r1, 0x110	// if (r1 == 0x0) goto loc_110;
  cc:	3300      	movi	r3, 0	// regs: r3=0x0
  ce:	c4435c22 	ins	r2, r3, 3, 2
  d2:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  d4:	3103      	movi	r1, 3	// regs: r1=0x3
  d6:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
  da:	3014      	movi	r0, 20	// regs: r0=0x14
  dc:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0xdc>, r1=<clobbered>
  e0:	3328      	movi	r3, 40	// regs: r3=0x28
  e2:	b401      	st.w	r0, (r4, 0x4)	// *(<arg1> + 0x4) = <ret calc_symbol_len@0xdc>
  e4:	7c0c      	mult	r0, r3	// regs: r0=(<ret calc_symbol_len@0xdc> * 0x28)
  e6:	e400022f 	addi	r0, r0, 560	// regs: r0=((<ret calc_symbol_len@0xdc> * 0x28) + 0x230)
loc_ea:
  ea:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  ec:	c4435462 	zext	r2, r3, 3, 2	// regs: r2=zext(*(<arg1> + 0x1))
  f0:	3a41      	cmpnei	r2, 1
  f2:	dc051336 	st.h	r0, (r5, 0x66c)	// *(0x66c) = r0
  f6:	0c3e      	bf	0x172	// if (r2 == 0x1) goto loc_172;
  f8:	3a40      	cmpnei	r2, 0
  fa:	0c19      	bf	0x12c	// if (r2 == 0x0) goto loc_12c;
  fc:	3a42      	cmpnei	r2, 2
  fe:	0c58      	bf	0x1ae	// if (r2 == 0x2) goto loc_1ae;
 100:	111b      	lrw	r0, 0x0	// regs: r0=0x0
 102:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x102>, r1=<clobbered>
 106:	0453      	br	0x1ac	// goto loc_1ac;
loc_108:
 108:	3201      	movi	r2, 1	// regs: r2=0x1
 10a:	c4625c64 	ins	r3, r2, 7, 4
 10e:	07d3      	br	0xb4	// goto loc_b4;
loc_110:
 110:	3301      	movi	r3, 1	// regs: r3=0x1
 112:	c4435c22 	ins	r2, r3, 3, 2
 116:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
 118:	3014      	movi	r0, 20	// regs: r0=0x14
 11a:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
 11e:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0x11e>, r1=<clobbered>
 122:	3328      	movi	r3, 40	// regs: r3=0x28
 124:	b401      	st.w	r0, (r4, 0x4)	// *(<arg1> + 0x4) = <ret calc_symbol_len@0x11e>
 126:	7c0c      	mult	r0, r3	// regs: r0=(<ret calc_symbol_len@0x11e> * 0x28)
 128:	20ef      	addi	r0, 240	// regs: r0=((<ret calc_symbol_len@0x11e> * 0x28) + 0xf0)
 12a:	07e0      	br	0xea	// goto loc_ea;
loc_12c:
 12c:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 12e:	3001      	movi	r0, 1	// regs: r0=0x1
 130:	c4225c02 	ins	r1, r2, 2, 2
 134:	c4205c04 	ins	r1, r0, 4, 4
 138:	c4205c06 	ins	r1, r0, 6, 6
 13c:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 13e:	8c24      	ld.h	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 140:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 144:	c4235c67 	ins	r1, r3, 10, 7
 148:	ac24      	st.h	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 14a:	8469      	ld.b	r3, (r4, 0x9)	// regs: r3=*(<arg1> + 0x9)
 14c:	c4625c03 	ins	r3, r2, 3, 3
 150:	a469      	st.b	r3, (r4, 0x9)	// *(<arg1> + 0x9) = *(<arg1> + 0x9)
 152:	9462      	ld.w	r3, (r4, 0x8)	// regs: r3=*(<arg1> + 0x8)
 154:	3114      	movi	r1, 20	// regs: r1=0x14
 156:	c4615d0c 	ins	r3, r1, 20, 12
 15a:	b462      	st.w	r3, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 15c:	846a      	ld.b	r3, (r4, 0xa)	// regs: r3=*(<arg1> + 0xa)
 15e:	c4625c25 	ins	r3, r2, 6, 5
 162:	a46a      	st.b	r3, (r4, 0xa)	// *(<arg1> + 0xa) = *(<arg1> + 0xa)
 164:	846b      	ld.b	r3, (r4, 0xb)	// regs: r3=*(<arg1> + 0xb)
 166:	c4625c00 	ins	r3, r2, 0, 0
 16a:	c4625c01 	ins	r3, r2, 1, 1
loc_16e:
 16e:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = r3
 170:	041e      	br	0x1ac	// goto loc_1ac;
loc_172:
 172:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 174:	8400      	ld.b	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
 176:	c4225c00 	ins	r1, r2, 0, 0
 17a:	c4c054e0 	zext	r0, r0, 7, 6	// regs: r0=zext(*(<arg1>))
 17e:	c4205c23 	ins	r1, r0, 4, 3
 182:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 184:	842a      	ld.b	r1, (r4, 0xa)	// regs: r1=*(<arg1> + 0xa)
 186:	e42120fe 	andi	r1, r1, 254	// regs: r1=(*(<arg1> + 0xa) & 0xfe)
 18a:	c4225c02 	ins	r1, r2, 2, 2
 18e:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 192:	6c87      	mov	r2, r1	// regs: r2=(*(<arg1> + 0xa) & 0xfe)
 194:	c4435c63 	ins	r2, r3, 6, 3
 198:	3328      	movi	r3, 40	// regs: r3=0x28
 19a:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = 0x28
 19c:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 19e:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 1a0:	e46320e0 	andi	r3, r3, 224	// regs: r3=(*(<arg1> + 0xc) & 0xe0)
 1a4:	3200      	movi	r2, 0	// regs: r2=0x0
 1a6:	c4625c05 	ins	r3, r2, 5, 5
 1aa:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = (*(<arg1> + 0xc) & 0xe0)
loc_1ac:
 1ac:	1492      	pop	r4-r5, r15
loc_1ae:
 1ae:	844a      	ld.b	r2, (r4, 0xa)	// regs: r2=*(<arg1> + 0xa)
 1b0:	3101      	movi	r1, 1	// regs: r1=0x1
 1b2:	e44220fe 	andi	r2, r2, 254	// regs: r2=(*(<arg1> + 0xa) & 0xfe)
 1b6:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 1ba:	c4415c02 	ins	r2, r1, 2, 2
 1be:	c4435c63 	ins	r2, r3, 6, 3
 1c2:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(<arg1>)
 1c4:	c4c354e3 	zext	r3, r3, 7, 6	// regs: r3=zext(*(<arg1>))
 1c8:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 1ca:	8448      	ld.b	r2, (r4, 0x8)	// regs: r2=*(<arg1> + 0x8)
 1cc:	c4435c23 	ins	r2, r3, 4, 3
 1d0:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 1d2:	e46320f3 	andi	r3, r3, 243	// regs: r3=(*(<arg1> + 0xc) & 0xf3)
 1d6:	c4615c04 	ins	r3, r1, 4, 4
 1da:	e46320fc 	andi	r3, r3, 252	// regs: r3=((*(<arg1> + 0xc) & 0xf3) & 0xfc)
 1de:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = ((*(<arg1> + 0xc) & 0xf3) & 0xfc)
 1e0:	a448      	st.b	r2, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 1e2:	3328      	movi	r3, 40	// regs: r3=0x28
 1e4:	07c5      	br	0x16e	// goto loc_16e;
 1e6:	0000      	.short	0x0000
 1e8:	00000000 	.long	0x00000000	// <ah_lmac>
 1ec:	00000000 	.long	0x00000000	// <.rodata.lmac_pv0_wpack_init.str1.1>

Disassembly of section .text.lmac_pv0_wpba_init:

00000000 <lmac_pv0_wpba_init>: // arg_bytes: 8
   0:	14d2      	push	r4-r5, r15
   2:	3201      	movi	r2, 1	// regs: r2=0x1
   4:	4262      	lsli	r3, r2, 2	// regs: r3=0x4
   6:	ea0c0007 	movi	r12, 7	// regs: r12=0x7
   a:	c46c5c64 	ins	r3, r12, 7, 4
   e:	a060      	st.b	r3, (r0, 0x0)	// *(<arg0>) = 0x4
  10:	3300      	movi	r3, 0	// regs: r3=0x0
  12:	a061      	st.b	r3, (r0, 0x1)	// *(<arg0> + 0x1) = 0x0
  14:	806c      	ld.b	r3, (r0, 0xc)	// regs: r3=*(<arg0> + 0xc)
  16:	6d07      	mov	r4, r1	// regs: r4=<arg1>
  18:	c4625c00 	ins	r3, r2, 0, 0
  1c:	3100      	movi	r1, 0	// regs: r1=0x0
  1e:	c4615c02 	ins	r3, r1, 2, 2
  22:	a06c      	st.b	r3, (r0, 0xc)	// *(<arg0> + 0xc) = *(<arg0> + 0xc)
  24:	806f      	ld.b	r3, (r0, 0xf)	// regs: r3=*(<arg0> + 0xf)
  26:	c4625c05 	ins	r3, r2, 5, 5
  2a:	e46320f8 	andi	r3, r3, 248	// regs: r3=(*(<arg0> + 0xf) & 0xf8)
  2e:	c4625c03 	ins	r3, r2, 3, 3
  32:	c4615c04 	ins	r3, r1, 4, 4
  36:	d980000d 	ld.b	r12, (r0, 0xd)	// regs: r12=*(<arg0> + 0xd)
  3a:	a06f      	st.b	r3, (r0, 0xf)	// *(<arg0> + 0xf) = (*(<arg0> + 0xf) & 0xf8)
  3c:	806a      	ld.b	r3, (r0, 0xa)	// regs: r3=*(<arg0> + 0xa)
  3e:	c5825c21 	ins	r12, r2, 2, 1
  42:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg0> + 0xa) & 0xfc)
  46:	dd80000d 	st.b	r12, (r0, 0xd)	// *(<arg0> + 0xd) = *(<arg0> + 0xd)
  4a:	c4625c22 	ins	r3, r2, 3, 2
  4e:	ea0c0009 	movi	r12, 9	// regs: r12=0x9
  52:	c46c5c64 	ins	r3, r12, 7, 4
  56:	a06a      	st.b	r3, (r0, 0xa)	// *(<arg0> + 0xa) = (*(<arg0> + 0xa) & 0xfc)
  58:	8076      	ld.b	r3, (r0, 0x16)	// regs: r3=*(<arg0> + 0x16)
  5a:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg0> + 0x16) & 0xfc)
  5e:	c4625c02 	ins	r3, r2, 2, 2
  62:	c4615c03 	ins	r3, r1, 3, 3
  66:	a076      	st.b	r3, (r0, 0x16)	// *(<arg0> + 0x16) = (*(<arg0> + 0x16) & 0xfc)
  68:	8077      	ld.b	r3, (r0, 0x17)	// regs: r3=*(<arg0> + 0x17)
  6a:	c4615c64 	ins	r3, r1, 7, 4
  6e:	a077      	st.b	r3, (r0, 0x17)	// *(<arg0> + 0x17) = *(<arg0> + 0x17)
  70:	3200      	movi	r2, 0	// regs: r2=0x0
  72:	3300      	movi	r3, 0	// regs: r3=0x0
  74:	13a0      	lrw	r5, 0x0	// regs: r5=0x0
  76:	b420      	st.w	r1, (r4, 0x0)	// *(<arg1>) = 0x0
  78:	b421      	st.w	r1, (r4, 0x4)	// *(<arg1> + 0x4) = 0x0
  7a:	b442      	st.w	r2, (r4, 0x8)	// *(<arg1> + 0x8) = 0x0
  7c:	b463      	st.w	r3, (r4, 0xc)	// *(<arg1> + 0xc) = 0x0
  7e:	d8050308 	ld.b	r0, (r5, 0x308)	// regs: r0=*(0x308)
  82:	3801      	cmphsi	r0, 2
  84:	0c05      	bf	0x8e	// if (r0 < 0x2) goto loc_8e;
  86:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  88:	c4615c07 	ins	r3, r1, 7, 7
  8c:	a462      	st.b	r3, (r4, 0x2)	// *(<arg1> + 0x2) = *(<arg1> + 0x2)
loc_8e:
  8e:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  90:	3209      	movi	r2, 9	// regs: r2=0x9
  92:	c4625cc0 	ins	r3, r2, 6, 0
  96:	a462      	st.b	r3, (r4, 0x2)	// *(<arg1> + 0x2) = *(<arg1> + 0x2)
  98:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(<arg1>)
  9a:	3100      	movi	r1, 0	// regs: r1=0x0
  9c:	e46320df 	andi	r3, r3, 223	// regs: r3=(*(<arg1>) & 0xdf)
  a0:	c4615c26 	ins	r3, r1, 7, 6
  a4:	a460      	st.b	r3, (r4, 0x0)	// *(<arg1>) = (*(<arg1>) & 0xdf)
  a6:	d8450875 	ld.b	r2, (r5, 0x875)	// regs: r2=*(0x875)
  aa:	e4422002 	andi	r2, r2, 2	// regs: r2=(*(0x875) & 0x2)
  ae:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  b0:	e9020032 	bez	r2, 0x114	// if (r2 == 0x0) goto loc_114;
  b4:	d8450867 	ld.b	r2, (r5, 0x867)	// regs: r2=*(0x867)
  b8:	3a43      	cmpnei	r2, 3
  ba:	082d      	bt	0x114	// if (r2 != 0x3) goto loc_114;
  bc:	c4615c64 	ins	r3, r1, 7, 4
loc_c0:
  c0:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  c2:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  c4:	c4605c20 	ins	r3, r0, 1, 0
  c8:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  ca:	d825034a 	ld.b	r1, (r5, 0x34a)	// regs: r1=*(0x34a)
  ce:	e4212001 	andi	r1, r1, 1	// regs: r1=(*(0x34a) & 0x1)
  d2:	8441      	ld.b	r2, (r4, 0x1)	// regs: r2=*(<arg1> + 0x1)
  d4:	e9010024 	bez	r1, 0x11c	// if (r1 == 0x0) goto loc_11c;
  d8:	3300      	movi	r3, 0	// regs: r3=0x0
  da:	c4435c22 	ins	r2, r3, 3, 2
  de:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  e0:	3103      	movi	r1, 3	// regs: r1=0x3
  e2:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
  e6:	3028      	movi	r0, 40	// regs: r0=0x28
  e8:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0xe8>, r1=<clobbered>
  ec:	3328      	movi	r3, 40	// regs: r3=0x28
  ee:	b401      	st.w	r0, (r4, 0x4)	// *(<arg1> + 0x4) = <ret calc_symbol_len@0xe8>
  f0:	7c0c      	mult	r0, r3	// regs: r0=(<ret calc_symbol_len@0xe8> * 0x28)
  f2:	e400022f 	addi	r0, r0, 560	// regs: r0=((<ret calc_symbol_len@0xe8> * 0x28) + 0x230)
loc_f6:
  f6:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  f8:	c4435462 	zext	r2, r3, 3, 2	// regs: r2=zext(*(<arg1> + 0x1))
  fc:	3a41      	cmpnei	r2, 1
  fe:	dc051338 	st.h	r0, (r5, 0x670)	// *(0x670) = r0
 102:	0c3f      	bf	0x180	// if (r2 == 0x1) goto loc_180;
 104:	3a40      	cmpnei	r2, 0
 106:	0c1a      	bf	0x13a	// if (r2 == 0x0) goto loc_13a;
 108:	3a42      	cmpnei	r2, 2
 10a:	0c59      	bf	0x1bc	// if (r2 == 0x2) goto loc_1bc;
 10c:	111b      	lrw	r0, 0x0	// regs: r0=0x0
 10e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x10e>, r1=<clobbered>
 112:	0454      	br	0x1ba	// goto loc_1ba;
loc_114:
 114:	3201      	movi	r2, 1	// regs: r2=0x1
 116:	c4625c64 	ins	r3, r2, 7, 4
 11a:	07d3      	br	0xc0	// goto loc_c0;
loc_11c:
 11c:	3302      	movi	r3, 2	// regs: r3=0x2
 11e:	c4435c22 	ins	r2, r3, 3, 2
 122:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
 124:	3028      	movi	r0, 40	// regs: r0=0x28
 126:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
 12a:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0x12a>, r1=<clobbered>
 12e:	3328      	movi	r3, 40	// regs: r3=0x28
 130:	b401      	st.w	r0, (r4, 0x4)	// *(<arg1> + 0x4) = <ret calc_symbol_len@0x12a>
 132:	7c0c      	mult	r0, r3	// regs: r0=(<ret calc_symbol_len@0x12a> * 0x28)
 134:	e400013f 	addi	r0, r0, 320	// regs: r0=((<ret calc_symbol_len@0x12a> * 0x28) + 0x140)
 138:	07df      	br	0xf6	// goto loc_f6;
loc_13a:
 13a:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 13c:	3001      	movi	r0, 1	// regs: r0=0x1
 13e:	c4225c02 	ins	r1, r2, 2, 2
 142:	c4205c04 	ins	r1, r0, 4, 4
 146:	c4205c06 	ins	r1, r0, 6, 6
 14a:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 14c:	8c24      	ld.h	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 14e:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 152:	c4235c67 	ins	r1, r3, 10, 7
 156:	ac24      	st.h	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 158:	8469      	ld.b	r3, (r4, 0x9)	// regs: r3=*(<arg1> + 0x9)
 15a:	c4625c03 	ins	r3, r2, 3, 3
 15e:	a469      	st.b	r3, (r4, 0x9)	// *(<arg1> + 0x9) = *(<arg1> + 0x9)
 160:	9462      	ld.w	r3, (r4, 0x8)	// regs: r3=*(<arg1> + 0x8)
 162:	3128      	movi	r1, 40	// regs: r1=0x28
 164:	c4615d0c 	ins	r3, r1, 20, 12
 168:	b462      	st.w	r3, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 16a:	846a      	ld.b	r3, (r4, 0xa)	// regs: r3=*(<arg1> + 0xa)
 16c:	c4625c25 	ins	r3, r2, 6, 5
 170:	a46a      	st.b	r3, (r4, 0xa)	// *(<arg1> + 0xa) = *(<arg1> + 0xa)
 172:	846b      	ld.b	r3, (r4, 0xb)	// regs: r3=*(<arg1> + 0xb)
 174:	c4625c00 	ins	r3, r2, 0, 0
 178:	c4625c01 	ins	r3, r2, 1, 1
loc_17c:
 17c:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = r3
 17e:	041e      	br	0x1ba	// goto loc_1ba;
loc_180:
 180:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 182:	8400      	ld.b	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
 184:	c4225c00 	ins	r1, r2, 0, 0
 188:	c4c054e0 	zext	r0, r0, 7, 6	// regs: r0=zext(*(<arg1>))
 18c:	c4205c23 	ins	r1, r0, 4, 3
 190:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 192:	842a      	ld.b	r1, (r4, 0xa)	// regs: r1=*(<arg1> + 0xa)
 194:	e42120fe 	andi	r1, r1, 254	// regs: r1=(*(<arg1> + 0xa) & 0xfe)
 198:	c4225c02 	ins	r1, r2, 2, 2
 19c:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 1a0:	6c87      	mov	r2, r1	// regs: r2=(*(<arg1> + 0xa) & 0xfe)
 1a2:	c4435c63 	ins	r2, r3, 6, 3
 1a6:	3350      	movi	r3, 80	// regs: r3=0x50
 1a8:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = 0x50
 1aa:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 1ac:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 1ae:	e46320e0 	andi	r3, r3, 224	// regs: r3=(*(<arg1> + 0xc) & 0xe0)
 1b2:	3200      	movi	r2, 0	// regs: r2=0x0
 1b4:	c4625c05 	ins	r3, r2, 5, 5
 1b8:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = (*(<arg1> + 0xc) & 0xe0)
loc_1ba:
 1ba:	1492      	pop	r4-r5, r15
loc_1bc:
 1bc:	844a      	ld.b	r2, (r4, 0xa)	// regs: r2=*(<arg1> + 0xa)
 1be:	3101      	movi	r1, 1	// regs: r1=0x1
 1c0:	e44220fe 	andi	r2, r2, 254	// regs: r2=(*(<arg1> + 0xa) & 0xfe)
 1c4:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 1c8:	c4415c02 	ins	r2, r1, 2, 2
 1cc:	c4435c63 	ins	r2, r3, 6, 3
 1d0:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(<arg1>)
 1d2:	c4c354e3 	zext	r3, r3, 7, 6	// regs: r3=zext(*(<arg1>))
 1d6:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 1d8:	8448      	ld.b	r2, (r4, 0x8)	// regs: r2=*(<arg1> + 0x8)
 1da:	c4435c23 	ins	r2, r3, 4, 3
 1de:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 1e0:	e46320f3 	andi	r3, r3, 243	// regs: r3=(*(<arg1> + 0xc) & 0xf3)
 1e4:	c4615c04 	ins	r3, r1, 4, 4
 1e8:	e46320fc 	andi	r3, r3, 252	// regs: r3=((*(<arg1> + 0xc) & 0xf3) & 0xfc)
 1ec:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = ((*(<arg1> + 0xc) & 0xf3) & 0xfc)
 1ee:	a448      	st.b	r2, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 1f0:	3350      	movi	r3, 80	// regs: r3=0x50
 1f2:	07c5      	br	0x17c	// goto loc_17c;
 1f4:	00000000 	.long	0x00000000	// <ah_lmac>
 1f8:	00000000 	.long	0x00000000	// <.rodata.lmac_pv0_wpba_init.str1.1>

Disassembly of section .text.lmac_pv0_cfpoll_init:

00000000 <lmac_pv0_cfpoll_init>: // arg_bytes: 8
   0:	14d5      	push	r4-r8, r15
   2:	3300      	movi	r3, 0	// regs: r3=0x0
   4:	2b57      	subi	r3, 88	// regs: r3=0xffffffa8
   6:	a060      	st.b	r3, (r0, 0x0)	// *(<arg0>) = 0xffffffa8
   8:	3300      	movi	r3, 0	// regs: r3=0x0
   a:	2b7d      	subi	r3, 126	// regs: r3=0xffffff82
   c:	13df      	lrw	r6, 0x0	// regs: r6=0x0
   e:	6d43      	mov	r5, r0	// regs: r5=<arg0>
  10:	a061      	st.b	r3, (r0, 0x1)	// *(<arg0> + 0x1) = 0xffffff82
  12:	ea037fff 	movi	r3, 32767	// regs: r3=0x7fff
  16:	6cce      	nor	r3, r3	// regs: r3=(~0x7fff)
  18:	6d07      	mov	r4, r1	// regs: r4=<arg1>
  1a:	a861      	st.h	r3, (r0, 0x2)	// *(<arg0> + 0x2) = (~0x7fff)
  1c:	3206      	movi	r2, 6	// regs: r2=0x6
  1e:	e4260525 	addi	r1, r6, 1318	// regs: r1=0x526
  22:	2009      	addi	r0, 10	// regs: r0=(<arg0> + 0xa)
  24:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x24>, r1=<clobbered>
  28:	3206      	movi	r2, 6	// regs: r2=0x6
  2a:	e4260525 	addi	r1, r6, 1318	// regs: r1=0x526
  2e:	e405000f 	addi	r0, r5, 16	// regs: r0=(<arg0> + 0x10)
  32:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x32>, r1=<clobbered>
  36:	8578      	ld.b	r3, (r5, 0x18)	// regs: r3=*(<arg0> + 0x18)
  38:	3207      	movi	r2, 7	// regs: r2=0x7
  3a:	c4625c60 	ins	r3, r2, 3, 0
  3e:	3700      	movi	r7, 0	// regs: r7=0x0
  40:	e46320ef 	andi	r3, r3, 239	// regs: r3=(*(<arg0> + 0x18) & 0xef)
  44:	c4675c25 	ins	r3, r7, 6, 5
  48:	a578      	st.b	r3, (r5, 0x18)	// *(<arg0> + 0x18) = (*(<arg0> + 0x18) & 0xef)
  4a:	3300      	movi	r3, 0	// regs: r3=0x0
  4c:	a579      	st.b	r3, (r5, 0x19)	// *(<arg0> + 0x19) = 0x0
  4e:	ea080001 	movi	r8, 1	// regs: r8=0x1
  52:	857c      	ld.b	r3, (r5, 0x1c)	// regs: r3=*(<arg0> + 0x1c)
  54:	c4685c00 	ins	r3, r8, 0, 0
  58:	c4675c02 	ins	r3, r7, 2, 2
  5c:	a57c      	st.b	r3, (r5, 0x1c)	// *(<arg0> + 0x1c) = *(<arg0> + 0x1c)
  5e:	857f      	ld.b	r3, (r5, 0x1f)	// regs: r3=*(<arg0> + 0x1f)
  60:	853d      	ld.b	r1, (r5, 0x1d)	// regs: r1=*(<arg0> + 0x1d)
  62:	c4685c05 	ins	r3, r8, 5, 5
  66:	c4285c21 	ins	r1, r8, 2, 1
  6a:	c4625c40 	ins	r3, r2, 2, 0
  6e:	a53d      	st.b	r1, (r5, 0x1d)	// *(<arg0> + 0x1d) = *(<arg0> + 0x1d)
  70:	c4685c03 	ins	r3, r8, 3, 3
  74:	8d2e      	ld.h	r1, (r5, 0x1c)	// regs: r1=*(<arg0> + 0x1c)
  76:	c4675c04 	ins	r3, r7, 4, 4
  7a:	a57f      	st.b	r3, (r5, 0x1f)	// *(<arg0> + 0x1f) = *(<arg0> + 0x1f)
  7c:	c4225c46 	ins	r1, r2, 8, 6
  80:	3300      	movi	r3, 0	// regs: r3=0x0
  82:	3200      	movi	r2, 0	// regs: r2=0x0
  84:	adeb      	st.h	r7, (r5, 0x16)	// *(<arg0> + 0x16) = 0x0
  86:	ad2e      	st.h	r1, (r5, 0x1c)	// *(<arg0> + 0x1c) = *(<arg0> + 0x1c)
  88:	b442      	st.w	r2, (r4, 0x8)	// *(<arg1> + 0x8) = 0x0
  8a:	b463      	st.w	r3, (r4, 0xc)	// *(<arg1> + 0xc) = 0x0
  8c:	b4e0      	st.w	r7, (r4, 0x0)	// *(<arg1>) = 0x0
  8e:	b4e1      	st.w	r7, (r4, 0x4)	// *(<arg1> + 0x4) = 0x0
  90:	d8060308 	ld.b	r0, (r6, 0x308)	// regs: r0=*(0x308)
  94:	3801      	cmphsi	r0, 2
  96:	6c9b      	mov	r2, r6	// regs: r2=0x0
  98:	0c05      	bf	0xa2	// if (r0 < 0x2) goto loc_a2;
  9a:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  9c:	c4685c07 	ins	r3, r8, 7, 7
  a0:	a462      	st.b	r3, (r4, 0x2)	// *(<arg1> + 0x2) = *(<arg1> + 0x2)
loc_a2:
  a2:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  a4:	310a      	movi	r1, 10	// regs: r1=0xa
  a6:	c4615cc0 	ins	r3, r1, 6, 0
  aa:	8420      	ld.b	r1, (r4, 0x0)	// regs: r1=*(<arg1>)
  ac:	a462      	st.b	r3, (r4, 0x2)	// *(<arg1> + 0x2) = *(<arg1> + 0x2)
  ae:	e42120df 	andi	r1, r1, 223	// regs: r1=(*(<arg1>) & 0xdf)
  b2:	3300      	movi	r3, 0	// regs: r3=0x0
  b4:	c4235c26 	ins	r1, r3, 7, 6
  b8:	a420      	st.b	r1, (r4, 0x0)	// *(<arg1>) = (*(<arg1>) & 0xdf)
  ba:	d822036d 	ld.b	r1, (r2, 0x36d)	// regs: r1=*(0x36d)
  be:	e421200c 	andi	r1, r1, 12	// regs: r1=(*(0x36d) & 0xc)
  c2:	e9210006 	bnez	r1, 0xce	// if (r1 != 0x0) goto loc_ce;
  c6:	d86211b6 	ld.h	r3, (r2, 0x36c)	// regs: r3=*(0x36c)
  ca:	c4a35523 	zext	r3, r3, 9, 5	// regs: r3=zext(*(0x36c))
loc_ce:
  ce:	8420      	ld.b	r1, (r4, 0x0)	// regs: r1=*(<arg1>)
  d0:	c4235c80 	ins	r1, r3, 4, 0
  d4:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  d6:	c4605c20 	ins	r3, r0, 1, 0
  da:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  dc:	a420      	st.b	r1, (r4, 0x0)	// *(<arg1>) = *(<arg1>)
  de:	d8220875 	ld.b	r1, (r2, 0x875)	// regs: r1=*(0x875)
  e2:	e4212002 	andi	r1, r1, 2	// regs: r1=(*(0x875) & 0x2)
  e6:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  e8:	e9010029 	bez	r1, 0x13a	// if (r1 == 0x0) goto loc_13a;
  ec:	d8220867 	ld.b	r1, (r2, 0x867)	// regs: r1=*(0x867)
  f0:	3943      	cmpnei	r1, 3
  f2:	0824      	bt	0x13a	// if (r1 != 0x3) goto loc_13a;
  f4:	3100      	movi	r1, 0	// regs: r1=0x0
loc_f6:
  f6:	c4615c64 	ins	r3, r1, 7, 4
  fa:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  fc:	d822034a 	ld.b	r1, (r2, 0x34a)	// regs: r1=*(0x34a)
 100:	e4212001 	andi	r1, r1, 1	// regs: r1=(*(0x34a) & 0x1)
 104:	8441      	ld.b	r2, (r4, 0x1)	// regs: r2=*(<arg1> + 0x1)
 106:	e901001c 	bez	r1, 0x13e	// if (r1 == 0x0) goto loc_13e;
 10a:	3300      	movi	r3, 0	// regs: r3=0x0
 10c:	c4435c22 	ins	r2, r3, 3, 2
 110:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
 112:	3103      	movi	r1, 3	// regs: r1=0x3
 114:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
loc_118:
 118:	3024      	movi	r0, 36	// regs: r0=0x24
 11a:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0x11a>, r1=<clobbered>
 11e:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
 120:	c4435462 	zext	r2, r3, 3, 2	// regs: r2=zext(*(<arg1> + 0x1))
 124:	3a41      	cmpnei	r2, 1
 126:	b401      	st.w	r0, (r4, 0x4)	// *(<arg1> + 0x4) = <ret calc_symbol_len@0x11a>
 128:	0c35      	bf	0x192	// if (r2 == 0x1) goto loc_192;
 12a:	3a40      	cmpnei	r2, 0
 12c:	0c10      	bf	0x14c	// if (r2 == 0x0) goto loc_14c;
 12e:	3a42      	cmpnei	r2, 2
 130:	0c4f      	bf	0x1ce	// if (r2 == 0x2) goto loc_1ce;
 132:	1117      	lrw	r0, 0x0	// regs: r0=0x0
 134:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x134>, r1=<clobbered>
 138:	044a      	br	0x1cc	// goto loc_1cc;
loc_13a:
 13a:	3101      	movi	r1, 1	// regs: r1=0x1
 13c:	07dd      	br	0xf6	// goto loc_f6;
loc_13e:
 13e:	3301      	movi	r3, 1	// regs: r3=0x1
 140:	c4435c22 	ins	r2, r3, 3, 2
 144:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
 146:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
 14a:	07e7      	br	0x118	// goto loc_118;
loc_14c:
 14c:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 14e:	3001      	movi	r0, 1	// regs: r0=0x1
 150:	c4225c02 	ins	r1, r2, 2, 2
 154:	c4205c04 	ins	r1, r0, 4, 4
 158:	c4205c06 	ins	r1, r0, 6, 6
 15c:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 15e:	8c24      	ld.h	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 160:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 164:	c4235c67 	ins	r1, r3, 10, 7
 168:	ac24      	st.h	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 16a:	8469      	ld.b	r3, (r4, 0x9)	// regs: r3=*(<arg1> + 0x9)
 16c:	c4625c03 	ins	r3, r2, 3, 3
 170:	a469      	st.b	r3, (r4, 0x9)	// *(<arg1> + 0x9) = *(<arg1> + 0x9)
 172:	9462      	ld.w	r3, (r4, 0x8)	// regs: r3=*(<arg1> + 0x8)
 174:	3124      	movi	r1, 36	// regs: r1=0x24
 176:	c4615d0c 	ins	r3, r1, 20, 12
 17a:	b462      	st.w	r3, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 17c:	846a      	ld.b	r3, (r4, 0xa)	// regs: r3=*(<arg1> + 0xa)
 17e:	c4625c25 	ins	r3, r2, 6, 5
 182:	a46a      	st.b	r3, (r4, 0xa)	// *(<arg1> + 0xa) = *(<arg1> + 0xa)
 184:	846b      	ld.b	r3, (r4, 0xb)	// regs: r3=*(<arg1> + 0xb)
 186:	c4625c00 	ins	r3, r2, 0, 0
 18a:	c4625c01 	ins	r3, r2, 1, 1
loc_18e:
 18e:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = r3
 190:	041e      	br	0x1cc	// goto loc_1cc;
loc_192:
 192:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 194:	8400      	ld.b	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
 196:	c4225c00 	ins	r1, r2, 0, 0
 19a:	c4c054e0 	zext	r0, r0, 7, 6	// regs: r0=zext(*(<arg1>))
 19e:	c4205c23 	ins	r1, r0, 4, 3
 1a2:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 1a4:	842a      	ld.b	r1, (r4, 0xa)	// regs: r1=*(<arg1> + 0xa)
 1a6:	e42120fe 	andi	r1, r1, 254	// regs: r1=(*(<arg1> + 0xa) & 0xfe)
 1aa:	c4225c02 	ins	r1, r2, 2, 2
 1ae:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 1b2:	6c87      	mov	r2, r1	// regs: r2=(*(<arg1> + 0xa) & 0xfe)
 1b4:	c4435c63 	ins	r2, r3, 6, 3
 1b8:	3348      	movi	r3, 72	// regs: r3=0x48
 1ba:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = 0x48
 1bc:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 1be:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 1c0:	e46320e0 	andi	r3, r3, 224	// regs: r3=(*(<arg1> + 0xc) & 0xe0)
 1c4:	3200      	movi	r2, 0	// regs: r2=0x0
 1c6:	c4625c05 	ins	r3, r2, 5, 5
 1ca:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = (*(<arg1> + 0xc) & 0xe0)
loc_1cc:
 1cc:	1495      	pop	r4-r8, r15
loc_1ce:
 1ce:	844a      	ld.b	r2, (r4, 0xa)	// regs: r2=*(<arg1> + 0xa)
 1d0:	3101      	movi	r1, 1	// regs: r1=0x1
 1d2:	e44220fe 	andi	r2, r2, 254	// regs: r2=(*(<arg1> + 0xa) & 0xfe)
 1d6:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 1da:	c4415c02 	ins	r2, r1, 2, 2
 1de:	c4435c63 	ins	r2, r3, 6, 3
 1e2:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(<arg1>)
 1e4:	c4c354e3 	zext	r3, r3, 7, 6	// regs: r3=zext(*(<arg1>))
 1e8:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 1ea:	8448      	ld.b	r2, (r4, 0x8)	// regs: r2=*(<arg1> + 0x8)
 1ec:	c4435c23 	ins	r2, r3, 4, 3
 1f0:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 1f2:	e46320f3 	andi	r3, r3, 243	// regs: r3=(*(<arg1> + 0xc) & 0xf3)
 1f6:	c4615c04 	ins	r3, r1, 4, 4
 1fa:	e46320fc 	andi	r3, r3, 252	// regs: r3=((*(<arg1> + 0xc) & 0xf3) & 0xfc)
 1fe:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = ((*(<arg1> + 0xc) & 0xf3) & 0xfc)
 200:	a448      	st.b	r2, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 202:	3348      	movi	r3, 72	// regs: r3=0x48
 204:	07c5      	br	0x18e	// goto loc_18e;
 206:	0000      	.short	0x0000
 208:	00000000 	.long	0x00000000	// <ah_lmac>
 20c:	00000000 	.long	0x00000000	// <.rodata.lmac_pv0_wpba_init.str1.1>

Disassembly of section .text.lmac_pv0_cfend_init:

00000000 <lmac_pv0_cfend_init>: // arg_bytes: 8
   0:	14d2      	push	r4-r5, r15
   2:	3201      	movi	r2, 1	// regs: r2=0x1
   4:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   6:	ea0c000e 	movi	r12, 14	// regs: r12=0xe
   a:	4222      	lsli	r1, r2, 2	// regs: r1=0x4
   c:	c42c5c64 	ins	r1, r12, 7, 4
  10:	a020      	st.b	r1, (r0, 0x0)	// *(<arg0>) = 0x4
  12:	3300      	movi	r3, 0	// regs: r3=0x0
  14:	3100      	movi	r1, 0	// regs: r1=0x0
  16:	a021      	st.b	r1, (r0, 0x1)	// *(<arg0> + 0x1) = 0x0
  18:	a861      	st.h	r3, (r0, 0x2)	// *(<arg0> + 0x2) = 0x0
  1a:	3100      	movi	r1, 0	// regs: r1=0x0
  1c:	3000      	movi	r0, 0	// regs: r0=0x0
  1e:	13a0      	lrw	r5, 0x0	// regs: r5=0x0
  20:	b460      	st.w	r3, (r4, 0x0)	// *(<arg1>) = 0x0
  22:	b461      	st.w	r3, (r4, 0x4)	// *(<arg1> + 0x4) = 0x0
  24:	b402      	st.w	r0, (r4, 0x8)	// *(<arg1> + 0x8) = 0x0
  26:	b423      	st.w	r1, (r4, 0xc)	// *(<arg1> + 0xc) = 0x0
  28:	d8250308 	ld.b	r1, (r5, 0x308)	// regs: r1=*(0x308)
  2c:	3901      	cmphsi	r1, 2
  2e:	0c05      	bf	0x38	// if (r1 < 0x2) goto loc_38;
  30:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  32:	c4625c07 	ins	r3, r2, 7, 7
  36:	a462      	st.b	r3, (r4, 0x2)	// *(<arg1> + 0x2) = *(<arg1> + 0x2)
loc_38:
  38:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  3a:	320a      	movi	r2, 10	// regs: r2=0xa
  3c:	c4625cc0 	ins	r3, r2, 6, 0
  40:	a462      	st.b	r3, (r4, 0x2)	// *(<arg1> + 0x2) = *(<arg1> + 0x2)
  42:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(<arg1>)
  44:	3000      	movi	r0, 0	// regs: r0=0x0
  46:	e46320df 	andi	r3, r3, 223	// regs: r3=(*(<arg1>) & 0xdf)
  4a:	c4605c26 	ins	r3, r0, 7, 6
  4e:	a460      	st.b	r3, (r4, 0x0)	// *(<arg1>) = (*(<arg1>) & 0xdf)
  50:	d8450875 	ld.b	r2, (r5, 0x875)	// regs: r2=*(0x875)
  54:	e4422002 	andi	r2, r2, 2	// regs: r2=(*(0x875) & 0x2)
  58:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  5a:	e9020032 	bez	r2, 0xbe	// if (r2 == 0x0) goto loc_be;
  5e:	d8450867 	ld.b	r2, (r5, 0x867)	// regs: r2=*(0x867)
  62:	3a43      	cmpnei	r2, 3
  64:	082d      	bt	0xbe	// if (r2 != 0x3) goto loc_be;
  66:	c4605c64 	ins	r3, r0, 7, 4
loc_6a:
  6a:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  6c:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  6e:	c4615c20 	ins	r3, r1, 1, 0
  72:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  74:	d825034a 	ld.b	r1, (r5, 0x34a)	// regs: r1=*(0x34a)
  78:	e4212001 	andi	r1, r1, 1	// regs: r1=(*(0x34a) & 0x1)
  7c:	8441      	ld.b	r2, (r4, 0x1)	// regs: r2=*(<arg1> + 0x1)
  7e:	e9010024 	bez	r1, 0xc6	// if (r1 == 0x0) goto loc_c6;
  82:	3300      	movi	r3, 0	// regs: r3=0x0
  84:	c4435c22 	ins	r2, r3, 3, 2
  88:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  8a:	3103      	movi	r1, 3	// regs: r1=0x3
  8c:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
  90:	3014      	movi	r0, 20	// regs: r0=0x14
  92:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0x92>, r1=<clobbered>
  96:	3328      	movi	r3, 40	// regs: r3=0x28
  98:	b401      	st.w	r0, (r4, 0x4)	// *(<arg1> + 0x4) = <ret calc_symbol_len@0x92>
  9a:	7c0c      	mult	r0, r3	// regs: r0=(<ret calc_symbol_len@0x92> * 0x28)
  9c:	e400022f 	addi	r0, r0, 560	// regs: r0=((<ret calc_symbol_len@0x92> * 0x28) + 0x230)
loc_a0:
  a0:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  a2:	c4435462 	zext	r2, r3, 3, 2	// regs: r2=zext(*(<arg1> + 0x1))
  a6:	3a41      	cmpnei	r2, 1
  a8:	dc051339 	st.h	r0, (r5, 0x672)	// *(0x672) = r0
  ac:	0c3e      	bf	0x128	// if (r2 == 0x1) goto loc_128;
  ae:	3a40      	cmpnei	r2, 0
  b0:	0c19      	bf	0xe2	// if (r2 == 0x0) goto loc_e2;
  b2:	3a42      	cmpnei	r2, 2
  b4:	0c58      	bf	0x164	// if (r2 == 0x2) goto loc_164;
  b6:	111b      	lrw	r0, 0x0	// regs: r0=0x0
  b8:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xb8>, r1=<clobbered>
  bc:	0453      	br	0x162	// goto loc_162;
loc_be:
  be:	3201      	movi	r2, 1	// regs: r2=0x1
  c0:	c4625c64 	ins	r3, r2, 7, 4
  c4:	07d3      	br	0x6a	// goto loc_6a;
loc_c6:
  c6:	3301      	movi	r3, 1	// regs: r3=0x1
  c8:	c4435c22 	ins	r2, r3, 3, 2
  cc:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  ce:	3014      	movi	r0, 20	// regs: r0=0x14
  d0:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
  d4:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0xd4>, r1=<clobbered>
  d8:	3328      	movi	r3, 40	// regs: r3=0x28
  da:	b401      	st.w	r0, (r4, 0x4)	// *(<arg1> + 0x4) = <ret calc_symbol_len@0xd4>
  dc:	7c0c      	mult	r0, r3	// regs: r0=(<ret calc_symbol_len@0xd4> * 0x28)
  de:	20ef      	addi	r0, 240	// regs: r0=((<ret calc_symbol_len@0xd4> * 0x28) + 0xf0)
  e0:	07e0      	br	0xa0	// goto loc_a0;
loc_e2:
  e2:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
  e4:	3001      	movi	r0, 1	// regs: r0=0x1
  e6:	c4225c02 	ins	r1, r2, 2, 2
  ea:	c4205c04 	ins	r1, r0, 4, 4
  ee:	c4205c06 	ins	r1, r0, 6, 6
  f2:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
  f4:	8c24      	ld.h	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
  f6:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
  fa:	c4235c67 	ins	r1, r3, 10, 7
  fe:	ac24      	st.h	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 100:	8469      	ld.b	r3, (r4, 0x9)	// regs: r3=*(<arg1> + 0x9)
 102:	c4625c03 	ins	r3, r2, 3, 3
 106:	a469      	st.b	r3, (r4, 0x9)	// *(<arg1> + 0x9) = *(<arg1> + 0x9)
 108:	9462      	ld.w	r3, (r4, 0x8)	// regs: r3=*(<arg1> + 0x8)
 10a:	3114      	movi	r1, 20	// regs: r1=0x14
 10c:	c4615d0c 	ins	r3, r1, 20, 12
 110:	b462      	st.w	r3, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 112:	846a      	ld.b	r3, (r4, 0xa)	// regs: r3=*(<arg1> + 0xa)
 114:	c4625c25 	ins	r3, r2, 6, 5
 118:	a46a      	st.b	r3, (r4, 0xa)	// *(<arg1> + 0xa) = *(<arg1> + 0xa)
 11a:	846b      	ld.b	r3, (r4, 0xb)	// regs: r3=*(<arg1> + 0xb)
 11c:	c4625c00 	ins	r3, r2, 0, 0
 120:	c4625c01 	ins	r3, r2, 1, 1
loc_124:
 124:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = r3
 126:	041e      	br	0x162	// goto loc_162;
loc_128:
 128:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 12a:	8400      	ld.b	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
 12c:	c4225c00 	ins	r1, r2, 0, 0
 130:	c4c054e0 	zext	r0, r0, 7, 6	// regs: r0=zext(*(<arg1>))
 134:	c4205c23 	ins	r1, r0, 4, 3
 138:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 13a:	842a      	ld.b	r1, (r4, 0xa)	// regs: r1=*(<arg1> + 0xa)
 13c:	e42120fe 	andi	r1, r1, 254	// regs: r1=(*(<arg1> + 0xa) & 0xfe)
 140:	c4225c02 	ins	r1, r2, 2, 2
 144:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 148:	6c87      	mov	r2, r1	// regs: r2=(*(<arg1> + 0xa) & 0xfe)
 14a:	c4435c63 	ins	r2, r3, 6, 3
 14e:	3328      	movi	r3, 40	// regs: r3=0x28
 150:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = 0x28
 152:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 154:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 156:	e46320e0 	andi	r3, r3, 224	// regs: r3=(*(<arg1> + 0xc) & 0xe0)
 15a:	3200      	movi	r2, 0	// regs: r2=0x0
 15c:	c4625c05 	ins	r3, r2, 5, 5
 160:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = (*(<arg1> + 0xc) & 0xe0)
loc_162:
 162:	1492      	pop	r4-r5, r15
loc_164:
 164:	844a      	ld.b	r2, (r4, 0xa)	// regs: r2=*(<arg1> + 0xa)
 166:	3101      	movi	r1, 1	// regs: r1=0x1
 168:	e44220fe 	andi	r2, r2, 254	// regs: r2=(*(<arg1> + 0xa) & 0xfe)
 16c:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(*(<arg1> + 0x1))
 170:	c4415c02 	ins	r2, r1, 2, 2
 174:	c4435c63 	ins	r2, r3, 6, 3
 178:	8460      	ld.b	r3, (r4, 0x0)	// regs: r3=*(<arg1>)
 17a:	c4c354e3 	zext	r3, r3, 7, 6	// regs: r3=zext(*(<arg1>))
 17e:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 180:	8448      	ld.b	r2, (r4, 0x8)	// regs: r2=*(<arg1> + 0x8)
 182:	c4435c23 	ins	r2, r3, 4, 3
 186:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 188:	e46320f3 	andi	r3, r3, 243	// regs: r3=(*(<arg1> + 0xc) & 0xf3)
 18c:	c4615c04 	ins	r3, r1, 4, 4
 190:	e46320fc 	andi	r3, r3, 252	// regs: r3=((*(<arg1> + 0xc) & 0xf3) & 0xfc)
 194:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = ((*(<arg1> + 0xc) & 0xf3) & 0xfc)
 196:	a448      	st.b	r2, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 198:	3328      	movi	r3, 40	// regs: r3=0x28
 19a:	07c5      	br	0x124	// goto loc_124;
 19c:	00000000 	.long	0x00000000	// <ah_lmac>
 1a0:	0000      	.short	0x0000	// <.rodata.lmac_pv0_cfend_init.str1.1>
 1a2:	0000      	.short	0x0000

Disassembly of section .text.lmac_pv0_qos_null_init:

00000000 <lmac_pv0_qos_null_init>: // arg_bytes: 8
   0:	14d1      	push	r4, r15
   2:	3300      	movi	r3, 0	// regs: r3=0x0
   4:	2b37      	subi	r3, 56	// regs: r3=0xffffffc8
   6:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   8:	134a      	lrw	r2, 0x0	// regs: r2=0x0
   a:	3100      	movi	r1, 0	// regs: r1=0x0
   c:	a021      	st.b	r1, (r0, 0x1)	// *(<arg0> + 0x1) = 0x0
   e:	a060      	st.b	r3, (r0, 0x0)	// *(<arg0>) = 0xffffffc8
  10:	d862202f 	ld.w	r3, (r2, 0xbc)	// regs: r3=*(0xbc)
  14:	3b41      	cmpnei	r3, 1
  16:	085c      	bt	0xce	// if (r3 != 0x1) goto loc_ce;
  18:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0xbc) & 0x1)
  1c:	c4615c01 	ins	r3, r1, 1, 1
loc_20:
  20:	8038      	ld.b	r1, (r0, 0x18)	// regs: r1=*(<arg0> + 0x18)
  22:	e42120f0 	andi	r1, r1, 240	// regs: r1=(*(<arg0> + 0x18) & 0xf0)
  26:	ea0c0002 	movi	r12, 2	// regs: r12=0x2
  2a:	a061      	st.b	r3, (r0, 0x1)	// *(<arg0> + 0x1) = r3
  2c:	c42c5c25 	ins	r1, r12, 6, 5
  30:	3300      	movi	r3, 0	// regs: r3=0x0
  32:	a038      	st.b	r1, (r0, 0x18)	// *(<arg0> + 0x18) = (*(<arg0> + 0x18) & 0xf0)
  34:	a076      	st.b	r3, (r0, 0x16)	// *(<arg0> + 0x16) = 0x0
  36:	a077      	st.b	r3, (r0, 0x17)	// *(<arg0> + 0x17) = 0x0
  38:	3100      	movi	r1, 0	// regs: r1=0x0
  3a:	3000      	movi	r0, 0	// regs: r0=0x0
  3c:	b402      	st.w	r0, (r4, 0x8)	// *(<arg1> + 0x8) = 0x0
  3e:	b423      	st.w	r1, (r4, 0xc)	// *(<arg1> + 0xc) = 0x0
  40:	310c      	movi	r1, 12	// regs: r1=0xc
  42:	b460      	st.w	r3, (r4, 0x0)	// *(<arg1>) = 0x0
  44:	a422      	st.b	r1, (r4, 0x2)	// *(<arg1> + 0x2) = 0xc
  46:	3100      	movi	r1, 0	// regs: r1=0x0
  48:	a420      	st.b	r1, (r4, 0x0)	// *(<arg1>) = 0x0
  4a:	b461      	st.w	r3, (r4, 0x4)	// *(<arg1> + 0x4) = 0x0
  4c:	d8020308 	ld.b	r0, (r2, 0x308)	// regs: r0=*(0x308)
  50:	c4205c20 	ins	r1, r0, 1, 0
  54:	a421      	st.b	r1, (r4, 0x1)	// *(<arg1> + 0x1) = 0x0
  56:	d822036d 	ld.b	r1, (r2, 0x36d)	// regs: r1=*(0x36d)
  5a:	e421200c 	andi	r1, r1, 12	// regs: r1=(*(0x36d) & 0xc)
  5e:	e9210006 	bnez	r1, 0x6a	// if (r1 != 0x0) goto loc_6a;
  62:	d86211b6 	ld.h	r3, (r2, 0x36c)	// regs: r3=*(0x36c)
  66:	c4a35523 	zext	r3, r3, 9, 5	// regs: r3=zext(*(0x36c))
loc_6a:
  6a:	8420      	ld.b	r1, (r4, 0x0)	// regs: r1=*(<arg1>)
  6c:	c4235c80 	ins	r1, r3, 4, 0
  70:	a420      	st.b	r1, (r4, 0x0)	// *(<arg1>) = *(<arg1>)
  72:	d8220875 	ld.b	r1, (r2, 0x875)	// regs: r1=*(0x875)
  76:	e4212002 	andi	r1, r1, 2	// regs: r1=(*(0x875) & 0x2)
  7a:	8461      	ld.b	r3, (r4, 0x1)	// regs: r3=*(<arg1> + 0x1)
  7c:	e901002b 	bez	r1, 0xd2	// if (r1 == 0x0) goto loc_d2;
  80:	d8220867 	ld.b	r1, (r2, 0x867)	// regs: r1=*(0x867)
  84:	3943      	cmpnei	r1, 3
  86:	0826      	bt	0xd2	// if (r1 != 0x3) goto loc_d2;
  88:	3100      	movi	r1, 0	// regs: r1=0x0
loc_8a:
  8a:	c4615c64 	ins	r3, r1, 7, 4
  8e:	a461      	st.b	r3, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  90:	d822034a 	ld.b	r1, (r2, 0x34a)	// regs: r1=*(0x34a)
  94:	e4212001 	andi	r1, r1, 1	// regs: r1=(*(0x34a) & 0x1)
  98:	8441      	ld.b	r2, (r4, 0x1)	// regs: r2=*(<arg1> + 0x1)
  9a:	e901001e 	bez	r1, 0xd6	// if (r1 == 0x0) goto loc_d6;
  9e:	3300      	movi	r3, 0	// regs: r3=0x0
  a0:	c4435c22 	ins	r2, r3, 3, 2
  a4:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  a6:	3103      	movi	r1, 3	// regs: r1=0x3
  a8:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
loc_ac:
  ac:	3020      	movi	r0, 32	// regs: r0=0x20
  ae:	e0000000 	bsr	0x0	// <calc_symbol_len>; regs: r0=<ret calc_symbol_len@0xae>, r1=<clobbered>
  b2:	8441      	ld.b	r2, (r4, 0x1)	// regs: r2=*(<arg1> + 0x1)
  b4:	c4425463 	zext	r3, r2, 3, 2	// regs: r3=zext(*(<arg1> + 0x1))
  b8:	3b41      	cmpnei	r3, 1
  ba:	b401      	st.w	r0, (r4, 0x4)	// *(<arg1> + 0x4) = <ret calc_symbol_len@0xae>
  bc:	0c38      	bf	0x12c	// if (r3 == 0x1) goto loc_12c;
  be:	3b40      	cmpnei	r3, 0
  c0:	0c12      	bf	0xe4	// if (r3 == 0x0) goto loc_e4;
  c2:	3b42      	cmpnei	r3, 2
  c4:	0c57      	bf	0x172	// if (r3 == 0x2) goto loc_172;
  c6:	111c      	lrw	r0, 0x0	// regs: r0=0x0
  c8:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xc8>, r1=<clobbered>
  cc:	042f      	br	0x12a	// goto loc_12a;
loc_ce:
  ce:	3302      	movi	r3, 2	// regs: r3=0x2
  d0:	07a8      	br	0x20	// goto loc_20;
loc_d2:
  d2:	3101      	movi	r1, 1	// regs: r1=0x1
  d4:	07db      	br	0x8a	// goto loc_8a;
loc_d6:
  d6:	3301      	movi	r3, 1	// regs: r3=0x1
  d8:	c4435c22 	ins	r2, r3, 3, 2
  dc:	a441      	st.b	r2, (r4, 0x1)	// *(<arg1> + 0x1) = *(<arg1> + 0x1)
  de:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
  e2:	07e5      	br	0xac	// goto loc_ac;
loc_e4:
  e4:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
  e6:	3001      	movi	r0, 1	// regs: r0=0x1
  e8:	c4235c02 	ins	r1, r3, 2, 2
  ec:	c4205c04 	ins	r1, r0, 4, 4
  f0:	c4205c06 	ins	r1, r0, 6, 6
  f4:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
  f6:	8c24      	ld.h	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
  f8:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
  fc:	c4225c67 	ins	r1, r2, 10, 7
 100:	ac24      	st.h	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 102:	8449      	ld.b	r2, (r4, 0x9)	// regs: r2=*(<arg1> + 0x9)
 104:	c4435c03 	ins	r2, r3, 3, 3
 108:	a449      	st.b	r2, (r4, 0x9)	// *(<arg1> + 0x9) = *(<arg1> + 0x9)
 10a:	9442      	ld.w	r2, (r4, 0x8)	// regs: r2=*(<arg1> + 0x8)
 10c:	3120      	movi	r1, 32	// regs: r1=0x20
 10e:	c4415d0c 	ins	r2, r1, 20, 12
 112:	b442      	st.w	r2, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 114:	844a      	ld.b	r2, (r4, 0xa)	// regs: r2=*(<arg1> + 0xa)
 116:	3102      	movi	r1, 2	// regs: r1=0x2
 118:	c4415c25 	ins	r2, r1, 6, 5
 11c:	a44a      	st.b	r2, (r4, 0xa)	// *(<arg1> + 0xa) = *(<arg1> + 0xa)
 11e:	844b      	ld.b	r2, (r4, 0xb)	// regs: r2=*(<arg1> + 0xb)
 120:	c4435c00 	ins	r2, r3, 0, 0
 124:	c4435c01 	ins	r2, r3, 1, 1
 128:	a44b      	st.b	r2, (r4, 0xb)	// *(<arg1> + 0xb) = *(<arg1> + 0xb)
loc_12a:
 12a:	1491      	pop	r4, r15
loc_12c:
 12c:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 12e:	8400      	ld.b	r0, (r4, 0x0)	// regs: r0=*(<arg1>)
 130:	c4235c00 	ins	r1, r3, 0, 0
 134:	c4c054e0 	zext	r0, r0, 7, 6	// regs: r0=zext(*(<arg1>))
 138:	c4205c23 	ins	r1, r0, 4, 3
 13c:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 13e:	842a      	ld.b	r1, (r4, 0xa)	// regs: r1=*(<arg1> + 0xa)
 140:	e42120fe 	andi	r1, r1, 254	// regs: r1=(*(<arg1> + 0xa) & 0xfe)
 144:	c4235c02 	ins	r1, r3, 2, 2
 148:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
 14c:	6cc7      	mov	r3, r1	// regs: r3=(*(<arg1> + 0xa) & 0xfe)
 14e:	c4625c63 	ins	r3, r2, 6, 3
 152:	a46a      	st.b	r3, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 154:	3340      	movi	r3, 64	// regs: r3=0x40
 156:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = 0x40
 158:	846c      	ld.b	r3, (r4, 0xc)	// regs: r3=*(<arg1> + 0xc)
 15a:	3202      	movi	r2, 2	// regs: r2=0x2
 15c:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg1> + 0xc) & 0xfc)
 160:	c4625c22 	ins	r3, r2, 3, 2
 164:	e46320ec 	andi	r3, r3, 236	// regs: r3=((*(<arg1> + 0xc) & 0xfc) & 0xec)
 168:	3200      	movi	r2, 0	// regs: r2=0x0
 16a:	c4625c05 	ins	r3, r2, 5, 5
 16e:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = ((*(<arg1> + 0xc) & 0xfc) & 0xec)
 170:	07dd      	br	0x12a	// goto loc_12a;
loc_172:
 172:	842a      	ld.b	r1, (r4, 0xa)	// regs: r1=*(<arg1> + 0xa)
 174:	3001      	movi	r0, 1	// regs: r0=0x1
 176:	e42120fe 	andi	r1, r1, 254	// regs: r1=(*(<arg1> + 0xa) & 0xfe)
 17a:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg1> + 0x1))
 17e:	c4205c02 	ins	r1, r0, 2, 2
 182:	c4225c63 	ins	r1, r2, 6, 3
 186:	8440      	ld.b	r2, (r4, 0x0)	// regs: r2=*(<arg1>)
 188:	c4c254e2 	zext	r2, r2, 7, 6	// regs: r2=zext(*(<arg1>))
 18c:	a42a      	st.b	r1, (r4, 0xa)	// *(<arg1> + 0xa) = (*(<arg1> + 0xa) & 0xfe)
 18e:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg1> + 0x8)
 190:	c4225c23 	ins	r1, r2, 4, 3
 194:	844c      	ld.b	r2, (r4, 0xc)	// regs: r2=*(<arg1> + 0xc)
 196:	c4435c22 	ins	r2, r3, 3, 2
 19a:	6ccb      	mov	r3, r2	// regs: r3=*(<arg1> + 0xc)
 19c:	c4605c04 	ins	r3, r0, 4, 4
 1a0:	e46320fc 	andi	r3, r3, 252	// regs: r3=(*(<arg1> + 0xc) & 0xfc)
 1a4:	a46c      	st.b	r3, (r4, 0xc)	// *(<arg1> + 0xc) = (*(<arg1> + 0xc) & 0xfc)
 1a6:	3340      	movi	r3, 64	// regs: r3=0x40
 1a8:	a428      	st.b	r1, (r4, 0x8)	// *(<arg1> + 0x8) = *(<arg1> + 0x8)
 1aa:	a46b      	st.b	r3, (r4, 0xb)	// *(<arg1> + 0xb) = 0x40
 1ac:	07bf      	br	0x12a	// goto loc_12a;
 1ae:	0000      	.short	0x0000
 1b0:	00000000 	.long	0x00000000	// <ah_lmac>
 1b4:	00000000 	.long	0x00000000	// <.rodata.lmac_pv0_qos_null_init.str1.1>

Disassembly of section .text.lmac_tx_vec_init:

00000000 <lmac_tx_vec_init>: // arg_bytes: 8
   0:	14d2      	push	r4-r5, r15
   2:	1184      	lrw	r4, 0x0	// regs: r4=0x0
   4:	e4040563 	addi	r0, r4, 1380	// regs: r0=0x564
   8:	e0000000 	bsr	0x0	// <ndp_tx_vec_init> // arg_bytes: 4; regs: r0=<ret ndp_tx_vec_init@0x8>, r1=<clobbered>
   c:	e4040573 	addi	r0, r4, 1396	// regs: r0=0x574
  10:	e0000000 	bsr	0x0	// <ndp_tx_vec_init> // arg_bytes: 4; regs: r0=<ret ndp_tx_vec_init@0x10>, r1=<clobbered>
  14:	e4040583 	addi	r0, r4, 1412	// regs: r0=0x584
  18:	e0000000 	bsr	0x0	// <ndp_tx_vec_init> // arg_bytes: 4; regs: r0=<ret ndp_tx_vec_init@0x18>, r1=<clobbered>
  1c:	e4040593 	addi	r0, r4, 1428	// regs: r0=0x594
  20:	e0000000 	bsr	0x0	// <ndp_tx_vec_init> // arg_bytes: 4; regs: r0=<ret ndp_tx_vec_init@0x20>, r1=<clobbered>
  24:	10bc      	lrw	r5, 0x0	// regs: r5=0x0
  26:	e40405a3 	addi	r0, r4, 1444	// regs: r0=0x5a4
  2a:	e0000000 	bsr	0x0	// <ndp_tx_vec_init> // arg_bytes: 4; regs: r0=<ret ndp_tx_vec_init@0x2a>, r1=<clobbered>
  2e:	e42405b3 	addi	r1, r4, 1460	// regs: r1=0x5b4
  32:	6c17      	mov	r0, r5	// regs: r0=0x0
  34:	e0000000 	bsr	0x0	// <lmac_pv0_rts_init> // arg_bytes: 8; regs: r0=<ret lmac_pv0_rts_init@0x34>, r1=<clobbered>
  38:	e42405c3 	addi	r1, r4, 1476	// regs: r1=0x5c4
  3c:	e405000f 	addi	r0, r5, 16	// regs: r0=0x10
  40:	e0000000 	bsr	0x0	// <lmac_pv0_wpcts_init> // arg_bytes: 8; regs: r0=<ret lmac_pv0_wpcts_init@0x40>, r1=<clobbered>
  44:	e42405e3 	addi	r1, r4, 1508	// regs: r1=0x5e4
  48:	e405001f 	addi	r0, r5, 32	// regs: r0=0x20
  4c:	e0000000 	bsr	0x0	// <lmac_pv0_wpack_init> // arg_bytes: 8; regs: r0=<ret lmac_pv0_wpack_init@0x4c>, r1=<clobbered>
  50:	e42405d3 	addi	r1, r4, 1492	// regs: r1=0x5d4
  54:	e405002f 	addi	r0, r5, 48	// regs: r0=0x30
  58:	e0000000 	bsr	0x0	// <lmac_pv0_wpba_init> // arg_bytes: 8; regs: r0=<ret lmac_pv0_wpba_init@0x58>, r1=<clobbered>
  5c:	e42405f3 	addi	r1, r4, 1524	// regs: r1=0x5f4
  60:	e4050053 	addi	r0, r5, 84	// regs: r0=0x54
  64:	e0000000 	bsr	0x0	// <lmac_pv0_cfpoll_init> // arg_bytes: 8; regs: r0=<ret lmac_pv0_cfpoll_init@0x64>, r1=<clobbered>
  68:	e4240603 	addi	r1, r4, 1540	// regs: r1=0x604
  6c:	e4050073 	addi	r0, r5, 116	// regs: r0=0x74
  70:	e0000000 	bsr	0x0	// <lmac_pv0_cfend_init> // arg_bytes: 8; regs: r0=<ret lmac_pv0_cfend_init@0x70>, r1=<clobbered>
  74:	e4240623 	addi	r1, r4, 1572	// regs: r1=0x624
  78:	e4050093 	addi	r0, r5, 148	// regs: r0=0x94
  7c:	e0000000 	bsr	0x0	// <lmac_pv0_qos_null_init> // arg_bytes: 8; regs: r0=<ret lmac_pv0_qos_null_init@0x7c>, r1=<clobbered>
  80:	e4240613 	addi	r1, r4, 1556	// regs: r1=0x614
  84:	e4050083 	addi	r0, r5, 132	// regs: r0=0x84
  88:	e0000000 	bsr	0x0	// <lmac_pv0_pspoll_init> // arg_bytes: 8; regs: r0=<ret lmac_pv0_pspoll_init@0x88>, r1=<clobbered>
  8c:	1492      	pop	r4-r5, r15
  8e:	0000      	.short	0x0000
  90:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>
  94:	00000000 	.long	0x00000000	// <ah_lmac+0x8e4>

Disassembly of section .text.lmac_tx_queue_agglist_init:

00000000 <lmac_tx_queue_agglist_init>: // arg_bytes: 4
   0:	14d1      	push	r4, r15
   2:	e0000000 	bsr	0x0	// <lmac_tx_queue_init> // arg_bytes: 0; regs: r0=<ret lmac_tx_queue_init@0x2>, r1=<clobbered>
   6:	1071      	lrw	r3, 0x0	// regs: r3=0x0
   8:	3200      	movi	r2, 0	// regs: r2=0x0
   a:	ea0c0090 	movi	r12, 144	// regs: r12=0x90
   e:	6d0f      	mov	r4, r3	// regs: r4=0x0
  10:	6c4b      	mov	r1, r2	// regs: r1=0x0
  12:	c42c482c 	lsli	r12, r12, 1	// regs: r12=0x120
loc_16:
  16:	c5828420 	mult	r0, r2, r12	// regs: r0=(r2 * 0x120)
  1a:	6010      	addu	r0, r4	// regs: r0=((r2 * 0x120) )
  1c:	dc23206e 	st.w	r1, (r3, 0x1b8)	// *(r3 + 0x1b8) = 0x0
  20:	dc23206f 	st.w	r1, (r3, 0x1bc)	// *(r3 + 0x1bc) = 0x0
  24:	dc2001c5 	st.b	r1, (r0, 0x1c5)	// *((((r2 * 0x120) ) + 0x1c5)) = 0x0
  28:	3000      	movi	r0, 0	// regs: r0=0x0
loc_2a:
  2a:	c440482d 	lsli	r13, r0, 2	// regs: r13=(r0 << 0x2)
  2e:	2000      	addi	r0, 1	// regs: r0=(r0 + 0x1)
  30:	634c      	addu	r13, r3	// regs: r13=((r0 << 0x2) + r3)
  32:	eb400040 	cmpnei	r0, 64
  36:	dc2d202e 	st.w	r1, (r13, 0xb8)	// *((((r0 << 0x2) + r3) + 0xb8)) = 0x0
  3a:	0bf8      	bt	0x2a	// if (r0 != 0x40) goto loc_2a;
  3c:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
  3e:	3a44      	cmpnei	r2, 4
  40:	e463011f 	addi	r3, r3, 288	// regs: r3=(r3 + 0x120)
  44:	0be9      	bt	0x16	// if (r2 != 0x4) goto loc_16;
  46:	1491      	pop	r4, r15
  48:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  4a:	0000      	.short	0x0000

Disassembly of section .text.lmac_tx_init:

00000000 <lmac_tx_init>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	ea0206d4 	movi	r2, 1748	// regs: r2=0x6d4
   6:	3100      	movi	r1, 0	// regs: r1=0x0
   8:	1117      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0xa>, r1=<clobbered>
   e:	e0000000 	bsr	0x0	// <lmac_tx_queue_init> // arg_bytes: 0; regs: r0=<ret lmac_tx_queue_init@0xe>, r1=<clobbered>
  12:	1175      	lrw	r3, 0x0	// regs: r3=0x0
  14:	3200      	movi	r2, 0	// regs: r2=0x0
  16:	ea0c0090 	movi	r12, 144	// regs: r12=0x90
  1a:	6d0f      	mov	r4, r3	// regs: r4=0x0
  1c:	6c4b      	mov	r1, r2	// regs: r1=0x0
  1e:	c42c482c 	lsli	r12, r12, 1	// regs: r12=0x120
loc_22:
  22:	c5828420 	mult	r0, r2, r12	// regs: r0=(r2 * 0x120)
  26:	6010      	addu	r0, r4	// regs: r0=((r2 * 0x120) )
  28:	dc23206e 	st.w	r1, (r3, 0x1b8)	// *(r3 + 0x1b8) = 0x0
  2c:	dc23206f 	st.w	r1, (r3, 0x1bc)	// *(r3 + 0x1bc) = 0x0
  30:	dc2001c5 	st.b	r1, (r0, 0x1c5)	// *((((r2 * 0x120) ) + 0x1c5)) = 0x0
  34:	3000      	movi	r0, 0	// regs: r0=0x0
loc_36:
  36:	c440482d 	lsli	r13, r0, 2	// regs: r13=(r0 << 0x2)
  3a:	2000      	addi	r0, 1	// regs: r0=(r0 + 0x1)
  3c:	634c      	addu	r13, r3	// regs: r13=((r0 << 0x2) + r3)
  3e:	eb400040 	cmpnei	r0, 64
  42:	dc2d202e 	st.w	r1, (r13, 0xb8)	// *((((r0 << 0x2) + r3) + 0xb8)) = 0x0
  46:	0bf8      	bt	0x36	// if (r0 != 0x40) goto loc_36;
  48:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
  4a:	3a44      	cmpnei	r2, 4
  4c:	e463011f 	addi	r3, r3, 288	// regs: r3=(r3 + 0x120)
  50:	0be9      	bt	0x22	// if (r2 != 0x4) goto loc_22;
  52:	e0000000 	bsr	0x0	// <lmac_tx_vec_init> // arg_bytes: 8; regs: r0=<ret lmac_tx_vec_init@0x52>, r1=<clobbered>
  56:	3100      	movi	r1, 0	// regs: r1=0x0
  58:	1104      	lrw	r0, 0x0	// regs: r0=0x0
  5a:	e0000000 	bsr	0x0	// <os_sema_init>; regs: r0=<ret os_sema_init@0x5a>, r1=<clobbered>
  5e:	3100      	movi	r1, 0	// regs: r1=0x0
  60:	1103      	lrw	r0, 0x0	// regs: r0=0x0
  62:	e0000000 	bsr	0x0	// <os_sema_init>; regs: r0=<ret os_sema_init@0x62>, r1=<clobbered>
  66:	1160      	lrw	r3, 0x0	// regs: r3=0x0
  68:	e423002b 	addi	r1, r3, 44	// regs: r1=0x2c
  6c:	1141      	lrw	r2, 0x0	// regs: r2=0x0
  6e:	1102      	lrw	r0, 0x0	// regs: r0=0x0
  70:	e0000000 	bsr	0x0	// <os_task_init>; regs: r0=<ret os_task_init@0x70>, r1=<clobbered>
  74:	3180      	movi	r1, 128	// regs: r1=0x80
  76:	4122      	lsli	r1, r1, 2	// regs: r1=0x200
  78:	1100      	lrw	r0, 0x0	// regs: r0=0x0
  7a:	e0000000 	bsr	0x0	// <os_task_set_stacksize>; regs: r0=<ret os_task_set_stacksize@0x7a>, r1=<clobbered>
  7e:	3151      	movi	r1, 81	// regs: r1=0x51
  80:	101e      	lrw	r0, 0x0	// regs: r0=0x0
  82:	e0000000 	bsr	0x0	// <_os_task_set_priority>; regs: r0=<ret _os_task_set_priority@0x82>, r1=<clobbered>
  86:	101d      	lrw	r0, 0x0	// regs: r0=0x0
  88:	e0000000 	bsr	0x0	// <os_task_run>; regs: r0=<ret os_task_run@0x88>, r1=<clobbered>
  8c:	1076      	lrw	r3, 0x0	// regs: r3=0x0
  8e:	e423003f 	addi	r1, r3, 64	// regs: r1=0x40
  92:	105b      	lrw	r2, 0x0	// regs: r2=0x0
  94:	101b      	lrw	r0, 0x0	// regs: r0=0x0
  96:	e0000000 	bsr	0x0	// <os_task_init>; regs: r0=<ret os_task_init@0x96>, r1=<clobbered>
  9a:	3180      	movi	r1, 128	// regs: r1=0x80
  9c:	4122      	lsli	r1, r1, 2	// regs: r1=0x200
  9e:	101a      	lrw	r0, 0x0	// regs: r0=0x0
  a0:	e0000000 	bsr	0x0	// <os_task_set_stacksize>; regs: r0=<ret os_task_set_stacksize@0xa0>, r1=<clobbered>
  a4:	3150      	movi	r1, 80	// regs: r1=0x50
  a6:	1018      	lrw	r0, 0x0	// regs: r0=0x0
  a8:	e0000000 	bsr	0x0	// <_os_task_set_priority>; regs: r0=<ret _os_task_set_priority@0xa8>, r1=<clobbered>
  ac:	1016      	lrw	r0, 0x0	// regs: r0=0x0
  ae:	e0000000 	bsr	0x0	// <os_task_run>; regs: r0=<ret os_task_run@0xae>, r1=<clobbered>
  b2:	3080      	movi	r0, 128	// regs: r0=0x80
  b4:	4003      	lsli	r0, r0, 3	// regs: r0=0x400
  b6:	e0000000 	bsr	0x0	// <alloc_tx_skb>; regs: r0=<ret alloc_tx_skb@0xb6>, r1=<clobbered>
  ba:	b402      	st.w	r0, (r4, 0x8)	// *(0x8) = <ret alloc_tx_skb@0xb6>
  bc:	e900000f 	bez	r0, 0xda	// if (r0 == 0x0) goto loc_da;
  c0:	3180      	movi	r1, 128	// regs: r1=0x80
  c2:	4121      	lsli	r1, r1, 1	// regs: r1=0x100
  c4:	e0000000 	bsr	0x0	// <skb_reserve>; regs: r0=<ret skb_reserve@0xc4>, r1=<clobbered>
  c8:	9462      	ld.w	r3, (r4, 0x8)	// regs: r3=*(0x8)
  ca:	3101      	movi	r1, 1	// regs: r1=0x1
  cc:	d843002a 	ld.b	r2, (r3, 0x2a)	// regs: r2=*((*(0x8) + 0x2a))
  d0:	c4415c06 	ins	r2, r1, 6, 6
  d4:	dc43002a 	st.b	r2, (r3, 0x2a)	// *((*(0x8) + 0x2a)) = *((*(0x8) + 0x2a))
loc_d8:
  d8:	1491      	pop	r4, r15
loc_da:
  da:	100c      	lrw	r0, 0x0	// regs: r0=0x0
  dc:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xdc>, r1=<clobbered>
  e0:	07fc      	br	0xd8	// goto loc_d8;
  e2:	0000      	.short	0x0000
  e4:	0000      	.short	0x0000	// <.bss.ah_lmac_tx>
  e6:	0000      	.short	0x0000
  e8:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x54>
  ec:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x5c>
  f0:	0000      	.short	0x0000	// <.text.lmac_tx_task>
  f2:	0000      	.short	0x0000
  f4:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_init.str1.1>
  f8:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x2c>
  fc:	0000      	.short	0x0000	// <.text.lmac_tx_status_task>
  fe:	0000      	.short	0x0000
 100:	0000      	.short	0x0000	// <.rodata.lmac_tx_init.str1.1+0x8>
 102:	0000      	.short	0x0000
 104:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x40>
 108:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_init.str1.1+0x17>

Disassembly of section .text.lmac_kick_tx_task:

00000000 <lmac_kick_tx_task>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	1003      	lrw	r0, 0x0	// regs: r0=0x0
   4:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x4>, r1=<clobbered>
   8:	1490      	pop	r15
   a:	0000      	.short	0x0000
   c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x54>

Disassembly of section .text.lmac_ah_tx:

00000000 <lmac_ah_tx>: // arg_bytes: 8
   0:	14d1      	push	r4, r15
   2:	806a      	ld.b	r3, (r0, 0xa)	// regs: r3=*(<arg0> + 0xa)
   4:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(<arg0> + 0xa) & 0x1)
   8:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   a:	e9030028 	bez	r3, 0x5a	// if (r3 == 0x0) goto loc_5a;
   e:	e9010026 	bez	r1, 0x5a	// if (r1 == 0x0) goto loc_5a;
  12:	9127      	ld.w	r1, (r1, 0x1c)	// regs: r1=*(<arg1> + 0x1c)
  14:	9468      	ld.w	r3, (r4, 0x20)	// regs: r3=*(<arg1> + 0x20)
  16:	604e      	subu	r1, r3	// regs: r1=(*(<arg1> + 0x1c) - *(<arg1> + 0x20))
  18:	eb010047 	cmphsi	r1, 72
  1c:	0c1b      	bf	0x52	// if (r1 < 0x48) goto loc_52;
  1e:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x1e>, r1=<clobbered>
  22:	b40b      	st.w	r0, (r4, 0x2c)	// *(<arg1> + 0x2c) = <ret os_jiffies@0x1e>
  24:	b42c      	st.w	r1, (r4, 0x30)	// *(<arg1> + 0x30) = <clobbered>
  26:	6c53      	mov	r1, r4	// regs: r1=<arg1>
  28:	100e      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	e0000000 	bsr	0x0	// <skb_list_queue>; regs: r0=<ret skb_list_queue@0x2a>, r1=<clobbered>
  2e:	6d03      	mov	r4, r0	// regs: r4=<ret skb_list_queue@0x2a>
  30:	e920000d 	bnez	r0, 0x4a	// if (r0 != 0x0) goto loc_4a;
  34:	100c      	lrw	r0, 0x0	// regs: r0=0x0
  36:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x36>, r1=<clobbered>
  3a:	104c      	lrw	r2, 0x0	// regs: r2=0x0
  3c:	d862153c 	ld.h	r3, (r2, 0xa78)	// regs: r3=*(0xa78)
  40:	2300      	addi	r3, 1	// regs: r3=(*(0xa78) + 0x1)
  42:	dc62153c 	st.h	r3, (r2, 0xa78)	// *(0xa78) = (*(0xa78) + 0x1)
loc_46:
  46:	6c13      	mov	r0, r4	// regs: r0=r4
  48:	1491      	pop	r4, r15
loc_4a:
  4a:	1009      	lrw	r0, 0x0	// regs: r0=0x0
  4c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x4c>, r1=<clobbered>
  50:	07fb      	br	0x46	// goto loc_46;
loc_52:
  52:	3244      	movi	r2, 68	// regs: r2=0x44
  54:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  56:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x56>, r1=<clobbered>
loc_5a:
  5a:	3400      	movi	r4, 0	// regs: r4=0x0
  5c:	2c00      	subi	r4, 1	// regs: r4=0xffffffff
  5e:	07f4      	br	0x46	// goto loc_46;
  60:	0000      	.short	0x0000	// <.bss.ah_lmac_tx+0x64>
  62:	0000      	.short	0x0000
  64:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x54>
  68:	00000000 	.long	0x00000000	// <ah_lmac>
  6c:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_tx.str1.1>
  70:	0000      	.short	0x0000	// <.rodata.lmac_ah_tx.str1.1+0x22>
  72:	0000      	.short	0x0000

Disassembly of section .text.lmac_ah_test_tx:

00000000 <lmac_ah_test_tx>: // arg_bytes: 8
   0:	14d1      	push	r4, r15
   2:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   4:	e9010016 	bez	r1, 0x30	// if (r1 == 0x0) goto loc_30;
   8:	e0000000 	bsr	0x0	// <os_jiffies>; regs: r0=<ret os_jiffies@0x8>, r1=<clobbered>
   c:	b40b      	st.w	r0, (r4, 0x2c)	// *(<arg1> + 0x2c) = <ret os_jiffies@0x8>
   e:	b42c      	st.w	r1, (r4, 0x30)	// *(<arg1> + 0x30) = <clobbered>
  10:	6c53      	mov	r1, r4	// regs: r1=<arg1>
  12:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  14:	e0000000 	bsr	0x0	// <skb_list_queue>; regs: r0=<ret skb_list_queue@0x14>, r1=<clobbered>
  18:	6d03      	mov	r4, r0	// regs: r4=<ret skb_list_queue@0x14>
  1a:	e9200007 	bnez	r0, 0x28	// if (r0 != 0x0) goto loc_28;
  1e:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  20:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x20>, r1=<clobbered>
loc_24:
  24:	6c13      	mov	r0, r4	// regs: r0=r4
  26:	1491      	pop	r4, r15
loc_28:
  28:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2a>, r1=<clobbered>
  2e:	07fb      	br	0x24	// goto loc_24;
loc_30:
  30:	3400      	movi	r4, 0	// regs: r4=0x0
  32:	2c00      	subi	r4, 1	// regs: r4=0xffffffff
  34:	07f8      	br	0x24	// goto loc_24;
  36:	0000      	.short	0x0000
  38:	0000      	.short	0x0000	// <.bss.ah_lmac_tx+0x64>
  3a:	0000      	.short	0x0000
  3c:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx+0x54>
  40:	0000      	.short	0x0000	// <.rodata.lmac_ah_tx.str1.1>
  42:	0000      	.short	0x0000

Disassembly of section .text.lmac_txagg_count:

00000000 <lmac_txagg_count>: // arg_bytes: 4
   0:	3803      	cmphsi	r0, 4
   2:	0809      	bt	0x14	// if (r0 >= 0x4) goto loc_14;
   4:	3390      	movi	r3, 144	// regs: r3=0x90
   6:	4361      	lsli	r3, r3, 1	// regs: r3=0x120
   8:	7c0c      	mult	r0, r3	// regs: r0=(<arg0> * 0x120)
   a:	1064      	lrw	r3, 0x0	// regs: r3=0x0
   c:	600c      	addu	r0, r3	// regs: r0=((<arg0> * 0x120) )
   e:	d80001c5 	ld.b	r0, (r0, 0x1c5)	// regs: r0=*((((<arg0> * 0x120) ) + 0x1c5))
loc_12:
  12:	783c      	jmp	r15	// return;
loc_14:
  14:	3000      	movi	r0, 0	// regs: r0=0x0
  16:	07fe      	br	0x12	// goto loc_12;
  18:	00000000 	.long	0x00000000	// <.bss.ah_lmac_tx>

Disassembly of section .text.lmac_auto_channel_select:

00000000 <lmac_auto_channel_select>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	142a      	subi	r14, r14, 40	// regs: r14=(sp - 0x28)
   4:	0379      	lrw	r3, 0x0	// regs: r3=0x0
   6:	0398      	lrw	r4, 0x0	// regs: r4=0x0
   8:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   a:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
   c:	3a87      	bclri	r2, 7	// regs: r2=(*((*(0x0) + 0x44)) & ~(0x1 << 0x7))
   e:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) & ~(0x1 << 0x7))
  10:	3280      	movi	r2, 128	// regs: r2=0x80
  12:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x80
  14:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0x14>, r1=<clobbered>
  18:	d8640361 	ld.b	r3, (r4, 0x361)	// regs: r3=*(0x361)
  1c:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x361) & 0x8)
  20:	e9030005 	bez	r3, 0x2a	// if (r3 == 0x0) goto loc_2a;
  24:	3005      	movi	r0, 5	// regs: r0=0x5
  26:	e0000000 	bsr	0x0	// <lmac_rx_gain_cfg>; regs: r0=<ret lmac_rx_gain_cfg@0x26>, r1=<clobbered>
loc_2a:
  2a:	3101      	movi	r1, 1	// regs: r1=0x1
  2c:	30c0      	movi	r0, 192	// regs: r0=0xc0
  2e:	7004      	lsl	r0, r1
  30:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_hw_bknoise>; regs: r0=<ret ah_rfdigicali_config_hw_bknoise@0x30>, r1=<clobbered>
  34:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_valid_pd_clr>; regs: r0=<ret ah_rfdigicali_bknoise_valid_pd_clr@0x34>, r1=<clobbered>
  38:	3700      	movi	r7, 0	// regs: r7=0x0
  3a:	dce42265 	st.w	r7, (r4, 0x994)	// *(0x994) = 0x0
  3e:	dce42266 	st.w	r7, (r4, 0x998)	// *(0x998) = 0x0
  42:	e0000000 	bsr	0x0	// <ah_wphy_auto_sig_err_rst_disable>; regs: r0=<ret ah_wphy_auto_sig_err_rst_disable@0x42>, r1=<clobbered>
  46:	1318      	lrw	r0, 0x0	// regs: r0=0x0
  48:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x48>, r1=<clobbered>
  4c:	1317      	lrw	r0, 0x0	// regs: r0=0x0
  4e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x4e>, r1=<clobbered>
  52:	33ff      	movi	r3, 255	// regs: r3=0xff
  54:	b864      	st.w	r3, (r14, 0x10)	// local_18 = 0xff
  56:	33fa      	movi	r3, 250	// regs: r3=0xfa
  58:	ea0a0080 	movi	r10, 128	// regs: r10=0x80
  5c:	4362      	lsli	r3, r3, 2	// regs: r3=0x3e8
  5e:	c6ea482a 	lsli	r10, r10, 23	// regs: r10=0x40000000
  62:	e5271000 	subi	r9, r7, 1	// regs: r9=0xffffffff
  66:	e507103b 	subi	r8, r7, 60	// regs: r8=0xffffffc4
  6a:	13b1      	lrw	r5, 0x0	// regs: r5=0x0
  6c:	b865      	st.w	r3, (r14, 0x14)	// local_14 = 0x3e8
loc_6e:
  6e:	d86409e0 	ld.b	r3, (r4, 0x9e0)	// regs: r3=*(0x9e0)
  72:	e4432001 	andi	r2, r3, 1	// regs: r2=(*(0x9e0) & 0x1)
  76:	e90200cf 	bez	r2, 0x214	// if (r2 == 0x0) goto loc_214;
  7a:	d8440378 	ld.b	r2, (r4, 0x378)	// regs: r2=*(0x378)
  7e:	649d      	cmplt	r7, r2
  80:	0836      	bt	0xec	// if (T) goto loc_ec;
  82:	3200      	movi	r2, 0	// regs: r2=0x0
  84:	c4625c00 	ins	r3, r2, 0, 0
  88:	dc6409e0 	st.b	r3, (r4, 0x9e0)	// *(0x9e0) = *(0x9e0)
  8c:	9844      	ld.w	r2, (r14, 0x10)	// regs: r2=local_18
  8e:	6ceb      	mov	r3, r10	// regs: r3=r10
  90:	6c67      	mov	r1, r9	// regs: r1=r9
  92:	1308      	lrw	r0, 0x0	// regs: r0=0x0
  94:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x94>, r1=<clobbered>
  98:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0x98>, r1=<clobbered>
  9c:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  a0:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  a4:	e9230011 	bnez	r3, 0xc6	// if (r3 != 0x0) goto loc_c6;
  a8:	6c27      	mov	r0, r9	// regs: r0=r9
  aa:	e0000000 	bsr	0x0	// <lmac_lo_freq_set>; regs: r0=<ret lmac_lo_freq_set@0xaa>, r1=<clobbered>
  ae:	7422      	sextb	r0, r8	// regs: r0=sext8(r8)
  b0:	dc04031e 	st.b	r0, (r4, 0x31e)	// *(0x31e) = sext8(r8)
  b4:	e0000000 	bsr	0x0	// <lmac_adjust_cca_threshold> // arg_bytes: 8; regs: r0=<ret lmac_adjust_cca_threshold@0xb4>, r1=<clobbered>
  b8:	d804431e 	ld.bs	r0, (r4, 0x31e)	// regs: r0=*(0x31e)
  bc:	e0000000 	bsr	0x0	// <lmac_adjust_agc_threshold> // arg_bytes: 4; regs: r0=<ret lmac_adjust_agc_threshold@0xbc>, r1=<clobbered>
  c0:	6c27      	mov	r0, r9	// regs: r0=r9
  c2:	e0000000 	bsr	0x0	// <lmac_notify_channel_switch>; regs: r0=<ret lmac_notify_channel_switch@0xc2>, r1=<clobbered>
loc_c6:
  c6:	e0000000 	bsr	0x0	// <lhw_enable_irq_ac>; regs: r0=<ret lhw_enable_irq_ac@0xc6>, r1=<clobbered>
  ca:	e0000000 	bsr	0x0	// <ah_wphy_auto_sig_err_rst_enable>; regs: r0=<ret ah_wphy_auto_sig_err_rst_enable@0xca>, r1=<clobbered>
  ce:	d8040309 	ld.b	r0, (r4, 0x309)	// regs: r0=*(0x309)
  d2:	e0000000 	bsr	0x0	// <ah_wphy_pri_channel_cfg>; regs: r0=<ret ah_wphy_pri_channel_cfg@0xd2>, r1=<clobbered>
  d6:	3000      	movi	r0, 0	// regs: r0=0x0
  d8:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0xd8>, r1=<clobbered>
  dc:	1216      	lrw	r0, 0x0	// regs: r0=0x0
  de:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xde>, r1=<clobbered>
  e2:	d804033c 	ld.b	r0, (r4, 0x33c)	// regs: r0=*(0x33c)
  e6:	2000      	addi	r0, 1	// regs: r0=(*(0x33c) + 0x1)
  e8:	140a      	addi	r14, r14, 40	// regs: r14=((sp - 0x28) + 0x28)
  ea:	1498      	pop	r4-r11, r15
loc_ec:
  ec:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0xec>, r1=<clobbered>
  f0:	741d      	zexth	r0, r7	// regs: r0=zext16(r7)
  f2:	e0000000 	bsr	0x0	// <lmac_lo_table_kick>; regs: r0=<ret lmac_lo_table_kick@0xf2>, r1=<clobbered>
  f6:	3034      	movi	r0, 52	// regs: r0=0x34
  f8:	e0000000 	bsr	0x0	// <os_sleep_us>; regs: r0=<ret os_sleep_us@0xf8>, r1=<clobbered>
  fc:	3000      	movi	r0, 0	// regs: r0=0x0
  fe:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0xfe>, r1=<clobbered>
 102:	d9640309 	ld.b	r11, (r4, 0x309)	// regs: r11=*(0x309)
 106:	6c2f      	mov	r0, r11	// regs: r0=*(0x309)
 108:	e0000000 	bsr	0x0	// <ah_wphy_pri_channel_cfg>; regs: r0=<ret ah_wphy_pri_channel_cfg@0x108>, r1=<clobbered>
 10c:	ea0c0000 	movi	r12, 0	// regs: r12=0x0
 110:	d8642278 	ld.w	r3, (r4, 0x9e0)	// regs: r3=*(0x9e0)
 114:	c46c5de1 	ins	r3, r12, 16, 1
 118:	6c73      	mov	r1, r12	// regs: r1=0x0
 11a:	dc642278 	st.w	r3, (r4, 0x9e0)	// *(0x9e0) = *(0x9e0)
 11e:	6db3      	mov	r6, r12	// regs: r6=0x0
 120:	297f      	subi	r1, 128	// regs: r1=0xffffff80
 122:	6cf3      	mov	r3, r12	// regs: r3=0x0
loc_124:
 124:	d80409e0 	ld.b	r0, (r4, 0x9e0)	// regs: r0=*(0x9e0)
 128:	e4002001 	andi	r0, r0, 1	// regs: r0=(*(0x9e0) & 0x1)
 12c:	e920003a 	bnez	r0, 0x1a0	// if (r0 != 0x0) goto loc_1a0;
loc_130:
 130:	d8042278 	ld.w	r0, (r4, 0x9e0)	// regs: r0=*(0x9e0)
 134:	39df      	btsti	r1, 31
 136:	c4cc804c 	divs	r12, r12, r6	// regs: r12=(r12 / r6)
 13a:	ea0d0064 	movi	r13, 100	// regs: r13=0x64
 13e:	c4c10c20 	incf	r6, r1, 0
 142:	c4c10c43 	inct	r6, r1, 3
 146:	c4205600 	zext	r0, r0, 16, 1	// regs: r0=zext(*(0x9e0))
 14a:	7c34      	mult	r0, r13	// regs: r0=(zext(*(0x9e0)) * 0x64)
 14c:	56c2      	asri	r6, r6, 2	// regs: r6=(r6 >> 0x2)
 14e:	d9a420d7 	ld.w	r13, (r4, 0x35c)	// regs: r13=*(0x35c)
 152:	c5a08020 	divu	r0, r0, r13	// regs: r0=((zext(*(0x9e0)) * 0x64) / *(0x35c))
 156:	61b0      	addu	r6, r12	// regs: r6=((r6 >> 0x2) + (r12 / r6))
 158:	6180      	addu	r6, r0	// regs: r6=(((r6 >> 0x2) + (r12 / r6)) + ((zext(*(0x9e0)) * 0x64) / *(0x35c)))
 15a:	c7a0502d 	bmaski	r13, 30
 15e:	65b5      	cmplt	r13, r6
 160:	9844      	ld.w	r2, (r14, 0x10)	// regs: r2=local_18
 162:	c44b0c20 	incf	r2, r11, 0
 166:	b844      	st.w	r2, (r14, 0x10)	// local_18 = local_18
 168:	a526      	st.b	r1, (r5, 0x6)	// *(r5 + 0x6) = r1
 16a:	b504      	st.w	r0, (r5, 0x10)	// *(r5 + 0x10) = ((zext(*(0x9e0)) * 0x64) / *(0x35c))
 16c:	b802      	st.w	r0, (r14, 0x8)	// local_20 = ((zext(*(0x9e0)) * 0x64) / *(0x35c))
 16e:	b821      	st.w	r1, (r14, 0x4)	// local_24 = r1
 170:	b8c3      	st.w	r6, (r14, 0xc)	// local_1c = (((r6 >> 0x2) + (r12 / r6)) + ((zext(*(0x9e0)) * 0x64) / *(0x35c)))
 172:	dd8e2000 	st.w	r12, (r14, 0x0)	// local_28 = (r12 / r6)
 176:	6caf      	mov	r2, r11	// regs: r2=*(0x309)
 178:	9520      	ld.w	r1, (r5, 0x0)	// regs: r1=*(r5)
 17a:	dd650004 	st.b	r11, (r5, 0x4)	// *(r5 + 0x4) = *(0x309)
 17e:	dd850007 	st.b	r12, (r5, 0x7)	// *(r5 + 0x7) = (r12 / r6)
 182:	a565      	st.b	r3, (r5, 0x5)	// *(r5 + 0x5) = r3
 184:	110d      	lrw	r0, 0x0	// regs: r0=0x0
 186:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x186>, r1=<clobbered>
 18a:	6699      	cmplt	r6, r10
 18c:	0c07      	bf	0x19a	// if (!T) goto loc_19a;
 18e:	d9252000 	ld.w	r9, (r5, 0x0)	// regs: r9=*(r5)
 192:	d9054007 	ld.bs	r8, (r5, 0x7)	// regs: r8=*(r5 + 0x7)
 196:	b5c5      	st.w	r6, (r5, 0x14)	// *(r5 + 0x14) = (((r6 >> 0x2) + (r12 / r6)) + ((zext(*(0x9e0)) * 0x64) / *(0x35c)))
 198:	6e9b      	mov	r10, r6	// regs: r10=(((r6 >> 0x2) + (r12 / r6)) + ((zext(*(0x9e0)) * 0x64) / *(0x35c)))
loc_19a:
 19a:	2517      	addi	r5, 24	// regs: r5=(r5 + 0x18)
 19c:	2700      	addi	r7, 1	// regs: r7=(r7 + 0x1)
 19e:	0768      	br	0x6e	// goto loc_6e;
loc_1a0:
 1a0:	d80420d7 	ld.w	r0, (r4, 0x35c)	// regs: r0=*(0x35c)
 1a4:	9845      	ld.w	r2, (r14, 0x14)	// regs: r2=local_14
 1a6:	7c08      	mult	r0, r2	// regs: r0=(*(0x35c) * local_14)
 1a8:	4804      	lsri	r0, r0, 4	// regs: r0=((*(0x35c) * local_14) >> 0x4)
 1aa:	6418      	cmphs	r6, r0
 1ac:	0bc2      	bt	0x130	// if (T) goto loc_130;
 1ae:	dd8e2008 	st.w	r12, (r14, 0x20)	// local_8 = r12
 1b2:	b827      	st.w	r1, (r14, 0x1c)	// local_c = r1
 1b4:	b866      	st.w	r3, (r14, 0x18)	// local_10 = r3
 1b6:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0x1b6>, r1=<clobbered>
 1ba:	3000      	movi	r0, 0	// regs: r0=0x0
 1bc:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0x1bc>, r1=<clobbered>
 1c0:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_calc_en>; regs: r0=<ret ah_rfdigicali_bknoise_calc_en@0x1c0>, r1=<clobbered>
 1c4:	e0000000 	bsr	0x0	// <ah_tdma_start>; regs: r0=<ret ah_tdma_start@0x1c4>, r1=<clobbered>
 1c8:	3020      	movi	r0, 32	// regs: r0=0x20
 1ca:	e0000000 	bsr	0x0	// <os_sleep_us>; regs: r0=<ret os_sleep_us@0x1ca>, r1=<clobbered>
 1ce:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x1ce>, r1=<clobbered>
 1d2:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_valid_pd_get>; regs: r0=<ret ah_rfdigicali_bknoise_valid_pd_get@0x1d2>, r1=<clobbered>
 1d6:	9866      	ld.w	r3, (r14, 0x18)	// regs: r3=local_10
 1d8:	9827      	ld.w	r1, (r14, 0x1c)	// regs: r1=local_c
 1da:	d98e2008 	ld.w	r12, (r14, 0x20)	// regs: r12=local_8
 1de:	e900ffa3 	bez	r0, 0x124	// if (r0 == 0x0) goto loc_124;
 1e2:	dd8e2009 	st.w	r12, (r14, 0x24)	// local_4 = local_8
 1e6:	b828      	st.w	r1, (r14, 0x20)	// local_8 = local_c
 1e8:	b867      	st.w	r3, (r14, 0x1c)	// local_c = local_10
 1ea:	e0000000 	bsr	0x0	// <lmac_bknoise_get> // arg_bytes: 0; regs: r0=<ret lmac_bknoise_get@0x1ea>, r1=<clobbered>
 1ee:	b806      	st.w	r0, (r14, 0x18)	// local_10 = <ret lmac_bknoise_get@0x1ea>
 1f0:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_calc_dis>; regs: r0=<ret ah_rfdigicali_bknoise_calc_dis@0x1f0>, r1=<clobbered>
 1f4:	e0000000 	bsr	0x0	// <ah_rfdigicali_bknoise_valid_pd_clr>; regs: r0=<ret ah_rfdigicali_bknoise_valid_pd_clr@0x1f4>, r1=<clobbered>
 1f8:	9806      	ld.w	r0, (r14, 0x18)	// regs: r0=local_10
 1fa:	9828      	ld.w	r1, (r14, 0x20)	// regs: r1=local_8
 1fc:	6405      	cmplt	r1, r0
 1fe:	9867      	ld.w	r3, (r14, 0x1c)	// regs: r3=local_c
 200:	d98e2009 	ld.w	r12, (r14, 0x24)	// regs: r12=local_4
 204:	c4200c40 	inct	r1, r0, 0
 208:	64c1      	cmplt	r0, r3
 20a:	6300      	addu	r12, r0	// regs: r12=(local_4 + local_10)
 20c:	c4600c40 	inct	r3, r0, 0
 210:	2600      	addi	r6, 1	// regs: r6=(r6 + 0x1)
 212:	0789      	br	0x124	// goto loc_124;
loc_214:
 214:	100a      	lrw	r0, 0x0	// regs: r0=0x0
 216:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x216>, r1=<clobbered>
 21a:	0756      	br	0xc6	// goto loc_c6;
 21c:	00000000 	.long	0x00000000	// <LMAC>
 220:	00000000 	.long	0x00000000	// <ah_lmac>
 224:	00000000 	.long	0x00000000	// <.rodata.lmac_auto_channel_select.str1.1>
 228:	0000      	.short	0x0000	// <.rodata.lmac_auto_channel_select.str1.1+0xa>
 22a:	0000      	.short	0x0000
 22c:	00000000 	.long	0x00000000	// <ah_lmac+0xc0>
 230:	00000000 	.long	0x00000000	// <.rodata.lmac_auto_channel_select.str1.1+0xaf>
 234:	00000000 	.long	0x00000000	// <.rodata.lmac_auto_channel_select.str1.1+0x96>
 238:	00000000 	.long	0x00000000	// <.rodata.lmac_auto_channel_select.str1.1+0x58>
 23c:	00000000 	.long	0x00000000	// <.rodata.lmac_auto_channel_select.str1.1+0xa2>

Disassembly of section .text.lmac_send_mgmt_meas_req:

00000000 <lmac_send_mgmt_meas_req>: // arg_bytes: 4
   0:	14d5      	push	r4-r8, r15
   2:	6e03      	mov	r8, r0	// regs: r8=<arg0>
   4:	3080      	movi	r0, 128	// regs: r0=0x80
   6:	4004      	lsli	r0, r0, 4	// regs: r0=0x800
   8:	e0000000 	bsr	0x0	// <alloc_tx_skb>; regs: r0=<ret alloc_tx_skb@0x8>, r1=<clobbered>
   c:	6d03      	mov	r4, r0	// regs: r4=<ret alloc_tx_skb@0x8>
   e:	e9000081 	bez	r0, 0x110	// if (r0 == 0x0) goto loc_110;
  12:	3180      	movi	r1, 128	// regs: r1=0x80
  14:	4121      	lsli	r1, r1, 1	// regs: r1=0x100
  16:	e0000000 	bsr	0x0	// <skb_reserve>; regs: r0=<ret skb_reserve@0x16>, r1=<clobbered>
  1a:	3601      	movi	r6, 1	// regs: r6=0x1
  1c:	d864002a 	ld.b	r3, (r4, 0x2a)	// regs: r3=*(<ret alloc_tx_skb@0x8> + 0x2a)
  20:	c4665c06 	ins	r3, r6, 6, 6
  24:	94a7      	ld.w	r5, (r4, 0x1c)	// regs: r5=*(<ret alloc_tx_skb@0x8> + 0x1c)
  26:	dc64002a 	st.b	r3, (r4, 0x2a)	// *(<ret alloc_tx_skb@0x8> + 0x2a) = *(<ret alloc_tx_skb@0x8> + 0x2a)
  2a:	3300      	movi	r3, 0	// regs: r3=0x0
  2c:	2b2f      	subi	r3, 48	// regs: r3=0xffffffd0
  2e:	a560      	st.b	r3, (r5, 0x0)	// *(*(<ret alloc_tx_skb@0x8> + 0x1c)) = 0xffffffd0
  30:	3300      	movi	r3, 0	// regs: r3=0x0
  32:	c4665c01 	ins	r3, r6, 1, 1
  36:	3700      	movi	r7, 0	// regs: r7=0x0
  38:	a561      	st.b	r3, (r5, 0x1)	// *((*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x1)) = 0x0
  3a:	6c63      	mov	r1, r8	// regs: r1=<arg0>
  3c:	3206      	movi	r2, 6	// regs: r2=0x6
  3e:	ea880037 	lrw	r8, 0x0	// regs: r8=0x0
  42:	5d0e      	addi	r0, r5, 4	// regs: r0=(*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x4)
  44:	a5e2      	st.b	r7, (r5, 0x2)	// *((*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x2)) = 0x0
  46:	a5e3      	st.b	r7, (r5, 0x3)	// *((*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x3)) = 0x0
  48:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x48>, r1=<clobbered>
  4c:	3206      	movi	r2, 6	// regs: r2=0x6
  4e:	e4280301 	addi	r1, r8, 770	// regs: r1=0x302
  52:	e4050009 	addi	r0, r5, 10	// regs: r0=(*(<ret alloc_tx_skb@0x8> + 0x1c) + 0xa)
  56:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x56>, r1=<clobbered>
  5a:	3206      	movi	r2, 6	// regs: r2=0x6
  5c:	e4280525 	addi	r1, r8, 1318	// regs: r1=0x526
  60:	e405000f 	addi	r0, r5, 16	// regs: r0=(*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x10)
  64:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x64>, r1=<clobbered>
  68:	a5f6      	st.b	r7, (r5, 0x16)	// *((*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x16)) = 0x0
  6a:	a5f7      	st.b	r7, (r5, 0x17)	// *((*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x17)) = 0x0
  6c:	3118      	movi	r1, 24	// regs: r1=0x18
  6e:	6c13      	mov	r0, r4	// regs: r0=<ret alloc_tx_skb@0x8>
  70:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x70>, r1=<clobbered>
  74:	9466      	ld.w	r3, (r4, 0x18)	// regs: r3=*(<ret alloc_tx_skb@0x8> + 0x18)
  76:	9449      	ld.w	r2, (r4, 0x24)	// regs: r2=*(<ret alloc_tx_skb@0x8> + 0x24)
  78:	608e      	subu	r2, r3	// regs: r2=(*(<ret alloc_tx_skb@0x8> + 0x24) - *(<ret alloc_tx_skb@0x8> + 0x18))
  7a:	3a2b      	cmplti	r2, 12
  7c:	0845      	bt	0x106	// if (r2 < 0xc) goto loc_106;
  7e:	1108      	lrw	r0, 0x0	// regs: r0=0x0
  80:	3226      	movi	r2, 38	// regs: r2=0x26
  82:	a340      	st.b	r2, (r3, 0x0)	// *(*(<ret alloc_tx_skb@0x8> + 0x18)) = 0x26
  84:	8040      	ld.b	r2, (r0, 0x0)	// regs: r2=*(0x0)
  86:	a342      	st.b	r2, (r3, 0x2)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x2)) = *(0x0)
  88:	c4c2002c 	addu	r12, r2, r6	// regs: r12=(*(0x0) + 0x1)
  8c:	8343      	ld.b	r2, (r3, 0x3)	// regs: r2=*((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x3))
  8e:	e44220fe 	andi	r2, r2, 254	// regs: r2=(*((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x3)) & 0xfe)
  92:	c4465c01 	ins	r2, r6, 1, 1
  96:	e44220fb 	andi	r2, r2, 251	// regs: r2=((*((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x3)) & 0xfe) & 0xfb)
  9a:	dd800000 	st.b	r12, (r0, 0x0)	// *(0x0) = (*(0x0) + 0x1)
  9e:	c4465c03 	ins	r2, r6, 3, 3
  a2:	3000      	movi	r0, 0	// regs: r0=0x0
  a4:	c4405c04 	ins	r2, r0, 4, 4
  a8:	3103      	movi	r1, 3	// regs: r1=0x3
  aa:	a343      	st.b	r2, (r3, 0x3)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x3)) = ((*((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x3)) & 0xfe) & 0xfb)
  ac:	3204      	movi	r2, 4	// regs: r2=0x4
  ae:	a321      	st.b	r1, (r3, 0x1)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x1)) = 0x3
  b0:	a344      	st.b	r2, (r3, 0x4)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x4)) = 0x4
  b2:	d84820ce 	ld.w	r2, (r8, 0x338)	// regs: r2=*(0x338)
  b6:	3064      	movi	r0, 100	// regs: r0=0x64
  b8:	c4825762 	zext	r2, r2, 27, 4	// regs: r2=zext(*(0x338))
  bc:	c4028042 	divs	r2, r2, r0	// regs: r2=(zext(*(0x338)) / 0x64)
  c0:	a345      	st.b	r2, (r3, 0x5)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x5)) = (zext(*(0x338)) / 0x64)
  c2:	c50255e2 	zext	r2, r2, 15, 8	// regs: r2=zext((zext(*(0x338)) / 0x64))
  c6:	a346      	st.b	r2, (r3, 0x6)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x6)) = zext((zext(*(0x338)) / 0x64))
  c8:	3200      	movi	r2, 0	// regs: r2=0x0
  ca:	2a17      	subi	r2, 24	// regs: r2=0xffffffe8
  cc:	a328      	st.b	r1, (r3, 0x8)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x8)) = 0x3
  ce:	a347      	st.b	r2, (r3, 0x7)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x7)) = 0xffffffe8
  d0:	31fa      	movi	r1, 250	// regs: r1=0xfa
  d2:	d84820e4 	ld.w	r2, (r8, 0x390)	// regs: r2=*(0x390)
  d6:	4122      	lsli	r1, r1, 2	// regs: r1=0x3e8
  d8:	7c84      	mult	r2, r1	// regs: r2=(*(0x390) * 0x3e8)
  da:	4a4a      	lsri	r2, r2, 10	// regs: r2=((*(0x390) * 0x3e8) >> 0xa)
  dc:	a349      	st.b	r2, (r3, 0x9)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x9)) = ((*(0x390) * 0x3e8) >> 0xa)
  de:	c50255e2 	zext	r2, r2, 15, 8	// regs: r2=zext(((*(0x390) * 0x3e8) >> 0xa))
  e2:	a34a      	st.b	r2, (r3, 0xa)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0xa)) = zext(((*(0x390) * 0x3e8) >> 0xa))
  e4:	310b      	movi	r1, 11	// regs: r1=0xb
  e6:	6c13      	mov	r0, r4	// regs: r0=<ret alloc_tx_skb@0x8>
  e8:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0xe8>, r1=<clobbered>
loc_ec:
  ec:	6c53      	mov	r1, r4	// regs: r1=<ret alloc_tx_skb@0x8>
  ee:	d8082000 	ld.w	r0, (r8, 0x0)	// regs: r0=*(0x0)
  f2:	e0000000 	bsr	0x0	// <lmac_ah_tx> // arg_bytes: 8; regs: r0=<ret lmac_ah_tx@0xf2>, r1=<clobbered>
  f6:	6d43      	mov	r5, r0	// regs: r5=<ret lmac_ah_tx@0xf2>
  f8:	e9000005 	bez	r0, 0x102	// if (r0 == 0x0) goto loc_102;
  fc:	6c13      	mov	r0, r4	// regs: r0=<ret alloc_tx_skb@0x8>
  fe:	e0000000 	bsr	0x0	// <kfree_skb>; regs: r0=<ret kfree_skb@0xfe>, r1=<clobbered>
loc_102:
 102:	6c17      	mov	r0, r5	// regs: r0=r5
 104:	1495      	pop	r4-r8, r15
loc_106:
 106:	1027      	lrw	r1, 0x0	// regs: r1=0x0
 108:	1007      	lrw	r0, 0x0	// regs: r0=0x0
 10a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x10a>, r1=<clobbered>
 10e:	07ef      	br	0xec	// goto loc_ec;
loc_110:
 110:	3500      	movi	r5, 0	// regs: r5=0x0
 112:	2d00      	subi	r5, 1	// regs: r5=0xffffffff
 114:	07f7      	br	0x102	// goto loc_102;
 116:	0000      	.short	0x0000
 118:	00000000 	.long	0x00000000	// <ah_lmac>
 11c:	00000000 	.long	0x00000000	// <.bss.req_token.14476>
 120:	00000000 	.long	0x00000000	// <.rodata.__func__.14478>
 124:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_pv0_s1g_beacon.str1.1+0x77>

Disassembly of section .text.lmac_send_mgmt_meas_report:

00000000 <lmac_send_mgmt_meas_report>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	3080      	movi	r0, 128	// regs: r0=0x80
   6:	4004      	lsli	r0, r0, 4	// regs: r0=0x800
   8:	e0000000 	bsr	0x0	// <alloc_tx_skb>; regs: r0=<ret alloc_tx_skb@0x8>, r1=<clobbered>
   c:	6d03      	mov	r4, r0	// regs: r4=<ret alloc_tx_skb@0x8>
   e:	e90000ff 	bez	r0, 0x20c	// if (r0 == 0x0) goto loc_20c;
  12:	3180      	movi	r1, 128	// regs: r1=0x80
  14:	4121      	lsli	r1, r1, 1	// regs: r1=0x100
  16:	e0000000 	bsr	0x0	// <skb_reserve>; regs: r0=<ret skb_reserve@0x16>, r1=<clobbered>
  1a:	ea080001 	movi	r8, 1	// regs: r8=0x1
  1e:	d864002a 	ld.b	r3, (r4, 0x2a)	// regs: r3=*(<ret alloc_tx_skb@0x8> + 0x2a)
  22:	c4685c06 	ins	r3, r8, 6, 6
  26:	94e7      	ld.w	r7, (r4, 0x1c)	// regs: r7=*(<ret alloc_tx_skb@0x8> + 0x1c)
  28:	dc64002a 	st.b	r3, (r4, 0x2a)	// *(<ret alloc_tx_skb@0x8> + 0x2a) = *(<ret alloc_tx_skb@0x8> + 0x2a)
  2c:	3300      	movi	r3, 0	// regs: r3=0x0
  2e:	13ba      	lrw	r5, 0x0	// regs: r5=0x0
  30:	3600      	movi	r6, 0	// regs: r6=0x0
  32:	2b2f      	subi	r3, 48	// regs: r3=0xffffffd0
  34:	a760      	st.b	r3, (r7, 0x0)	// *(*(<ret alloc_tx_skb@0x8> + 0x1c)) = 0xffffffd0
  36:	dd070001 	st.b	r8, (r7, 0x1)	// *((*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x1)) = 0x1
  3a:	a7c2      	st.b	r6, (r7, 0x2)	// *((*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x2)) = 0x0
  3c:	a7c3      	st.b	r6, (r7, 0x3)	// *((*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x3)) = 0x0
  3e:	3206      	movi	r2, 6	// regs: r2=0x6
  40:	e4250525 	addi	r1, r5, 1318	// regs: r1=0x526
  44:	5f0e      	addi	r0, r7, 4	// regs: r0=(*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x4)
  46:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x46>, r1=<clobbered>
  4a:	3206      	movi	r2, 6	// regs: r2=0x6
  4c:	e4250301 	addi	r1, r5, 770	// regs: r1=0x302
  50:	e4070009 	addi	r0, r7, 10	// regs: r0=(*(<ret alloc_tx_skb@0x8> + 0x1c) + 0xa)
  54:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x54>, r1=<clobbered>
  58:	3206      	movi	r2, 6	// regs: r2=0x6
  5a:	e4250525 	addi	r1, r5, 1318	// regs: r1=0x526
  5e:	e407000f 	addi	r0, r7, 16	// regs: r0=(*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x10)
  62:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x62>, r1=<clobbered>
  66:	a7d6      	st.b	r6, (r7, 0x16)	// *((*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x16)) = 0x0
  68:	a7d7      	st.b	r6, (r7, 0x17)	// *((*(<ret alloc_tx_skb@0x8> + 0x1c) + 0x17)) = 0x0
  6a:	3118      	movi	r1, 24	// regs: r1=0x18
  6c:	6c13      	mov	r0, r4	// regs: r0=<ret alloc_tx_skb@0x8>
  6e:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x6e>, r1=<clobbered>
  72:	d9442006 	ld.w	r10, (r4, 0x18)	// regs: r10=*(<ret alloc_tx_skb@0x8> + 0x18)
  76:	3327      	movi	r3, 39	// regs: r3=0x27
  78:	1348      	lrw	r2, 0x0	// regs: r2=0x0
  7a:	ea090000 	movi	r9, 0	// regs: r9=0x0
  7e:	dc6a0000 	st.b	r3, (r10, 0x0)	// *(*(<ret alloc_tx_skb@0x8> + 0x18)) = 0x27
  82:	8260      	ld.b	r3, (r2, 0x0)	// regs: r3=*(0x0)
  84:	c5030021 	addu	r1, r3, r8	// regs: r1=(*(0x0) + 0x1)
  88:	dc6a0002 	st.b	r3, (r10, 0x2)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x2)) = *(0x0)
  8c:	d86a0003 	ld.b	r3, (r10, 0x3)	// regs: r3=*((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x3))
  90:	e46320fe 	andi	r3, r3, 254	// regs: r3=(*((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x3)) & 0xfe)
  94:	c4685c01 	ins	r3, r8, 1, 1
  98:	c4695c43 	ins	r3, r9, 5, 3
  9c:	dc6a0003 	st.b	r3, (r10, 0x3)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x3)) = (*((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x3)) & 0xfe)
  a0:	3304      	movi	r3, 4	// regs: r3=0x4
  a2:	a220      	st.b	r1, (r2, 0x0)	// *(0x0) = (*(0x0) + 0x1)
  a4:	dc6a0004 	st.b	r3, (r10, 0x4)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x4)) = 0x4
  a8:	3105      	movi	r1, 5	// regs: r1=0x5
  aa:	6c13      	mov	r0, r4	// regs: r0=<ret alloc_tx_skb@0x8>
  ac:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0xac>, r1=<clobbered>
  b0:	d86520ce 	ld.w	r3, (r5, 0x338)	// regs: r3=*(0x338)
  b4:	9446      	ld.w	r2, (r4, 0x18)	// regs: r2=*(<ret alloc_tx_skb@0x8> + 0x18)
  b6:	3164      	movi	r1, 100	// regs: r1=0x64
  b8:	c4835763 	zext	r3, r3, 27, 4	// regs: r3=zext(*(0x338))
  bc:	c4238043 	divs	r3, r3, r1	// regs: r3=(zext(*(0x338)) / 0x64)
  c0:	a260      	st.b	r3, (r2, 0x0)	// *(*(<ret alloc_tx_skb@0x8> + 0x18)) = (zext(*(0x338)) / 0x64)
  c2:	c50355e3 	zext	r3, r3, 15, 8	// regs: r3=zext((zext(*(0x338)) / 0x64))
  c6:	a261      	st.b	r3, (r2, 0x1)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x1)) = zext((zext(*(0x338)) / 0x64))
  c8:	a2cc      	st.b	r6, (r2, 0xc)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0xc)) = 0x0
  ca:	d865033c 	ld.b	r3, (r5, 0x33c)	// regs: r3=*(0x33c)
  ce:	3118      	movi	r1, 24	// regs: r1=0x18
  d0:	7cc4      	mult	r3, r1	// regs: r3=(*(0x33c) * 0x18)
  d2:	60d4      	addu	r3, r5	// regs: r3=((*(0x33c) * 0x18) )
  d4:	3119      	movi	r1, 25	// regs: r1=0x19
  d6:	d86300c7 	ld.b	r3, (r3, 0xc7)	// regs: r3=*((((*(0x33c) * 0x18) ) + 0xc7))
  da:	a26d      	st.b	r3, (r2, 0xd)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0xd)) = *((((*(0x33c) * 0x18) ) + 0xc7))
  dc:	6c13      	mov	r0, r4	// regs: r0=<ret alloc_tx_skb@0x8>
  de:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0xde>, r1=<clobbered>
  e2:	94e6      	ld.w	r7, (r4, 0x18)	// regs: r7=*(<ret alloc_tx_skb@0x8> + 0x18)
  e4:	3300      	movi	r3, 0	// regs: r3=0x0
  e6:	2b22      	subi	r3, 35	// regs: r3=0xffffffdd
  e8:	a760      	st.b	r3, (r7, 0x0)	// *(*(<ret alloc_tx_skb@0x8> + 0x18)) = 0xffffffdd
  ea:	3340      	movi	r3, 64	// regs: r3=0x40
  ec:	dd070004 	st.b	r8, (r7, 0x4)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x4)) = 0x1
  f0:	a7c2      	st.b	r6, (r7, 0x2)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x2)) = 0x0
  f2:	a763      	st.b	r3, (r7, 0x3)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x3)) = 0x40
  f4:	d8651198 	ld.h	r3, (r5, 0x330)	// regs: r3=*(0x330)
  f8:	a765      	st.b	r3, (r7, 0x5)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x5)) = *(0x330)
  fa:	4b68      	lsri	r3, r3, 8	// regs: r3=(*(0x330) >> 0x8)
  fc:	a766      	st.b	r3, (r7, 0x6)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x6)) = (*(0x330) >> 0x8)
  fe:	a7c7      	st.b	r6, (r7, 0x7)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x7)) = 0x0
 100:	3108      	movi	r1, 8	// regs: r1=0x8
 102:	6c13      	mov	r0, r4	// regs: r0=<ret alloc_tx_skb@0x8>
 104:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x104>, r1=<clobbered>
 108:	e56500bf 	addi	r11, r5, 192	// regs: r11=0xc0
 10c:	d9042006 	ld.w	r8, (r4, 0x18)	// regs: r8=*(<ret alloc_tx_skb@0x8> + 0x18)
 110:	3205      	movi	r2, 5	// regs: r2=0x5
 112:	6f27      	mov	r12, r9	// regs: r12=0x0
loc_114:
 114:	d8650378 	ld.b	r3, (r5, 0x378)	// regs: r3=*(0x378)
 118:	64e5      	cmplt	r9, r3
 11a:	0c6e      	bf	0x1f6	// if (!T) goto loc_1f6;
 11c:	d86520ce 	ld.w	r3, (r5, 0x338)	// regs: r3=*(0x338)
 120:	d80b2000 	ld.w	r0, (r11, 0x0)	// regs: r0=*(r11)
 124:	c4835763 	zext	r3, r3, 27, 4	// regs: r3=zext(*(0x338))
 128:	64c2      	cmpne	r0, r3
 12a:	0862      	bt	0x1ee	// if (T) goto loc_1ee;
 12c:	d8254a4e 	ld.bs	r1, (r5, 0xa4e)	// regs: r1=*(0xa4e)
 130:	d865431d 	ld.bs	r3, (r5, 0x31d)	// regs: r3=*(0x31d)
 134:	64c5      	cmplt	r1, r3
 136:	085c      	bt	0x1ee	// if (T) goto loc_1ee;
 138:	d865483d 	ld.bs	r3, (r5, 0x83d)	// regs: r3=*(0x83d)
 13c:	c4438043 	divs	r3, r3, r2	// regs: r3=(*(0x83d) / r2)
 140:	3b33      	cmplti	r3, 20
 142:	0c58      	bf	0x1f2	// if (r3 >= 0x14) goto loc_1f2;
 144:	3b22      	cmplti	r3, 3
 146:	c46c0c40 	inct	r3, r12, 0
loc_14a:
 14a:	d82b0007 	ld.b	r1, (r11, 0x7)	// regs: r1=*(r11 + 0x7)
 14e:	60c4      	addu	r3, r1	// regs: r3=(r3 + *(r11 + 0x7))
 150:	dc680004 	st.b	r3, (r8, 0x4)	// *(r8 + 0x4) = (r3 + *(r11 + 0x7))
 154:	6c63      	mov	r1, r8	// regs: r1=r8
 156:	dd8e2001 	st.w	r12, (r14, 0x4)	// local_4 = r12
 15a:	b840      	st.w	r2, (r14, 0x0)	// local_8 = r2
 15c:	e0000000 	bsr	0x0	// <__put_unaligned_le32> // arg_bytes: 8; regs: r0=<ret __put_unaligned_le32@0x15c>, r1=<clobbered>
 160:	9840      	ld.w	r2, (r14, 0x0)	// regs: r2=local_8
 162:	d98e2001 	ld.w	r12, (r14, 0x4)	// regs: r12=local_4
loc_166:
 166:	e5290000 	addi	r9, r9, 1	// regs: r9=(r9 + 0x1)
 16a:	eb490010 	cmpnei	r9, 16
 16e:	e5080004 	addi	r8, r8, 5	// regs: r8=(r8 + 0x5)
 172:	e56b0017 	addi	r11, r11, 24	// regs: r11=(r11 + 0x18)
 176:	0bcf      	bt	0x114	// if (r9 != 0x10) goto loc_114;
 178:	3150      	movi	r1, 80	// regs: r1=0x50
 17a:	6c13      	mov	r0, r4	// regs: r0=<ret alloc_tx_skb@0x8>
 17c:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x17c>, r1=<clobbered>
 180:	94c6      	ld.w	r6, (r4, 0x18)	// regs: r6=*(<ret alloc_tx_skb@0x8> + 0x18)
 182:	5e7d      	subu	r3, r6, r7	// regs: r3=(*(<ret alloc_tx_skb@0x8> + 0x18) - *(<ret alloc_tx_skb@0x8> + 0x18))
 184:	2b01      	subi	r3, 2	// regs: r3=((*(<ret alloc_tx_skb@0x8> + 0x18) - *(<ret alloc_tx_skb@0x8> + 0x18)) - 0x2)
 186:	a761      	st.b	r3, (r7, 0x1)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x1)) = ((*(<ret alloc_tx_skb@0x8> + 0x18) - *(<ret alloc_tx_skb@0x8> + 0x18)) - 0x2)
 188:	c5460083 	subu	r3, r6, r10	// regs: r3=(*(<ret alloc_tx_skb@0x8> + 0x18) - *(<ret alloc_tx_skb@0x8> + 0x18))
 18c:	2b01      	subi	r3, 2	// regs: r3=((*(<ret alloc_tx_skb@0x8> + 0x18) - *(<ret alloc_tx_skb@0x8> + 0x18)) - 0x2)
 18e:	dc6a0001 	st.b	r3, (r10, 0x1)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x1)) = ((*(<ret alloc_tx_skb@0x8> + 0x18) - *(<ret alloc_tx_skb@0x8> + 0x18)) - 0x2)
 192:	3300      	movi	r3, 0	// regs: r3=0x0
 194:	2b22      	subi	r3, 35	// regs: r3=0xffffffdd
 196:	a660      	st.b	r3, (r6, 0x0)	// *(*(<ret alloc_tx_skb@0x8> + 0x18)) = 0xffffffdd
 198:	3300      	movi	r3, 0	// regs: r3=0x0
 19a:	a662      	st.b	r3, (r6, 0x2)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x2)) = 0x0
 19c:	3340      	movi	r3, 64	// regs: r3=0x40
 19e:	a663      	st.b	r3, (r6, 0x3)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x3)) = 0x40
 1a0:	3301      	movi	r3, 1	// regs: r3=0x1
 1a2:	a664      	st.b	r3, (r6, 0x4)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x4)) = 0x1
 1a4:	d8651198 	ld.h	r3, (r5, 0x330)	// regs: r3=*(0x330)
 1a8:	a665      	st.b	r3, (r6, 0x5)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x5)) = *(0x330)
 1aa:	4b68      	lsri	r3, r3, 8	// regs: r3=(*(0x330) >> 0x8)
 1ac:	a666      	st.b	r3, (r6, 0x6)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x6)) = (*(0x330) >> 0x8)
 1ae:	3303      	movi	r3, 3	// regs: r3=0x3
 1b0:	a667      	st.b	r3, (r6, 0x7)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x7)) = 0x3
 1b2:	3108      	movi	r1, 8	// regs: r1=0x8
 1b4:	6c13      	mov	r0, r4	// regs: r0=<ret alloc_tx_skb@0x8>
 1b6:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x1b6>, r1=<clobbered>
 1ba:	32c0      	movi	r2, 192	// regs: r2=0xc0
 1bc:	1038      	lrw	r1, 0x0	// regs: r1=0x0
 1be:	9406      	ld.w	r0, (r4, 0x18)	// regs: r0=*(<ret alloc_tx_skb@0x8> + 0x18)
 1c0:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x1c0>, r1=<clobbered>
 1c4:	31c0      	movi	r1, 192	// regs: r1=0xc0
 1c6:	6c13      	mov	r0, r4	// regs: r0=<ret alloc_tx_skb@0x8>
 1c8:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x1c8>, r1=<clobbered>
 1cc:	9466      	ld.w	r3, (r4, 0x18)	// regs: r3=*(<ret alloc_tx_skb@0x8> + 0x18)
 1ce:	60da      	subu	r3, r6	// regs: r3=(*(<ret alloc_tx_skb@0x8> + 0x18) - *(<ret alloc_tx_skb@0x8> + 0x18))
 1d0:	2b01      	subi	r3, 2	// regs: r3=((*(<ret alloc_tx_skb@0x8> + 0x18) - *(<ret alloc_tx_skb@0x8> + 0x18)) - 0x2)
 1d2:	a661      	st.b	r3, (r6, 0x1)	// *((*(<ret alloc_tx_skb@0x8> + 0x18) + 0x1)) = ((*(<ret alloc_tx_skb@0x8> + 0x18) - *(<ret alloc_tx_skb@0x8> + 0x18)) - 0x2)
 1d4:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(0x0)
 1d6:	6c53      	mov	r1, r4	// regs: r1=<ret alloc_tx_skb@0x8>
 1d8:	e0000000 	bsr	0x0	// <lmac_ah_tx> // arg_bytes: 8; regs: r0=<ret lmac_ah_tx@0x1d8>, r1=<clobbered>
 1dc:	6d43      	mov	r5, r0	// regs: r5=<ret lmac_ah_tx@0x1d8>
 1de:	e9000005 	bez	r0, 0x1e8	// if (r0 == 0x0) goto loc_1e8;
 1e2:	6c13      	mov	r0, r4	// regs: r0=<ret alloc_tx_skb@0x8>
 1e4:	e0000000 	bsr	0x0	// <kfree_skb>; regs: r0=<ret kfree_skb@0x1e4>, r1=<clobbered>
loc_1e8:
 1e8:	6c17      	mov	r0, r5	// regs: r0=r5
 1ea:	1402      	addi	r14, r14, 8	// regs: r14=((sp - 0x8) + 0x8)
 1ec:	1498      	pop	r4-r11, r15
loc_1ee:
 1ee:	3300      	movi	r3, 0	// regs: r3=0x0
 1f0:	07ad      	br	0x14a	// goto loc_14a;
loc_1f2:
 1f2:	3314      	movi	r3, 20	// regs: r3=0x14
 1f4:	07ab      	br	0x14a	// goto loc_14a;
loc_1f6:
 1f6:	dcc80002 	st.b	r6, (r8, 0x2)	// *(r8 + 0x2) = 0x0
 1fa:	dcc80003 	st.b	r6, (r8, 0x3)	// *(r8 + 0x3) = 0x0
 1fe:	dcc80000 	st.b	r6, (r8, 0x0)	// *(r8) = 0x0
 202:	dcc80001 	st.b	r6, (r8, 0x1)	// *(r8 + 0x1) = 0x0
 206:	dcc80004 	st.b	r6, (r8, 0x4)	// *(r8 + 0x4) = 0x0
 20a:	07ae      	br	0x166	// goto loc_166;
loc_20c:
 20c:	3500      	movi	r5, 0	// regs: r5=0x0
 20e:	2d00      	subi	r5, 1	// regs: r5=0xffffffff
 210:	07ec      	br	0x1e8	// goto loc_1e8;
 212:	0000      	.short	0x0000
 214:	00000000 	.long	0x00000000	// <ah_lmac>
 218:	00000000 	.long	0x00000000	// <.bss.req_token.14493>
 21c:	00000000 	.long	0x00000000	// <ah_lmac+0x240>

Disassembly of section .text.lmac_send_bss_announcement:

00000000 <lmac_send_bss_announcement>: // arg_bytes: 0
   0:	14d5      	push	r4-r8, r15
   2:	1298      	lrw	r4, 0x0	// regs: r4=0x0
   4:	d8440527 	ld.b	r2, (r4, 0x527)	// regs: r2=*(0x527)
   8:	d8640526 	ld.b	r3, (r4, 0x526)	// regs: r3=*(0x526)
   c:	6cc8      	or	r3, r2	// regs: r3=(*(0x526) | *(0x527))
   e:	d8440528 	ld.b	r2, (r4, 0x528)	// regs: r2=*(0x528)
  12:	6cc8      	or	r3, r2	// regs: r3=((*(0x526) | *(0x527)) | *(0x528))
  14:	d8440529 	ld.b	r2, (r4, 0x529)	// regs: r2=*(0x529)
  18:	6cc8      	or	r3, r2	// regs: r3=(((*(0x526) | *(0x527)) | *(0x528)) | *(0x529))
  1a:	d844052a 	ld.b	r2, (r4, 0x52a)	// regs: r2=*(0x52a)
  1e:	6cc8      	or	r3, r2	// regs: r3=((((*(0x526) | *(0x527)) | *(0x528)) | *(0x529)) | *(0x52a))
  20:	d844052b 	ld.b	r2, (r4, 0x52b)	// regs: r2=*(0x52b)
  24:	6cc8      	or	r3, r2	// regs: r3=(((((*(0x526) | *(0x527)) | *(0x528)) | *(0x529)) | *(0x52a)) | *(0x52b))
  26:	e9230005 	bnez	r3, 0x30	// if (r3 != 0x0) goto loc_30;
loc_2a:
  2a:	3000      	movi	r0, 0	// regs: r0=0x0
  2c:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_2e:
  2e:	1495      	pop	r4-r8, r15
loc_30:
  30:	d8440303 	ld.b	r2, (r4, 0x303)	// regs: r2=*(0x303)
  34:	d8640302 	ld.b	r3, (r4, 0x302)	// regs: r3=*(0x302)
  38:	6cc8      	or	r3, r2	// regs: r3=(*(0x302) | *(0x303))
  3a:	d8440304 	ld.b	r2, (r4, 0x304)	// regs: r2=*(0x304)
  3e:	6cc8      	or	r3, r2	// regs: r3=((*(0x302) | *(0x303)) | *(0x304))
  40:	d8440305 	ld.b	r2, (r4, 0x305)	// regs: r2=*(0x305)
  44:	6cc8      	or	r3, r2	// regs: r3=(((*(0x302) | *(0x303)) | *(0x304)) | *(0x305))
  46:	d8440306 	ld.b	r2, (r4, 0x306)	// regs: r2=*(0x306)
  4a:	6cc8      	or	r3, r2	// regs: r3=((((*(0x302) | *(0x303)) | *(0x304)) | *(0x305)) | *(0x306))
  4c:	d8440307 	ld.b	r2, (r4, 0x307)	// regs: r2=*(0x307)
  50:	6cc8      	or	r3, r2	// regs: r3=(((((*(0x302) | *(0x303)) | *(0x304)) | *(0x305)) | *(0x306)) | *(0x307))
  52:	e903ffec 	bez	r3, 0x2a	// if (r3 == 0x0) goto loc_2a;
  56:	3080      	movi	r0, 128	// regs: r0=0x80
  58:	4004      	lsli	r0, r0, 4	// regs: r0=0x800
  5a:	e0000000 	bsr	0x0	// <alloc_tx_skb>; regs: r0=<ret alloc_tx_skb@0x5a>, r1=<clobbered>
  5e:	6d43      	mov	r5, r0	// regs: r5=<ret alloc_tx_skb@0x5a>
  60:	e900ffe5 	bez	r0, 0x2a	// if (r0 == 0x0) goto loc_2a;
  64:	3180      	movi	r1, 128	// regs: r1=0x80
  66:	4121      	lsli	r1, r1, 1	// regs: r1=0x100
  68:	e0000000 	bsr	0x0	// <skb_reserve>; regs: r0=<ret skb_reserve@0x68>, r1=<clobbered>
  6c:	ea080001 	movi	r8, 1	// regs: r8=0x1
  70:	d865002a 	ld.b	r3, (r5, 0x2a)	// regs: r3=*(<ret alloc_tx_skb@0x5a> + 0x2a)
  74:	c4685c06 	ins	r3, r8, 6, 6
  78:	95c7      	ld.w	r6, (r5, 0x1c)	// regs: r6=*(<ret alloc_tx_skb@0x5a> + 0x1c)
  7a:	dc65002a 	st.b	r3, (r5, 0x2a)	// *(<ret alloc_tx_skb@0x5a> + 0x2a) = *(<ret alloc_tx_skb@0x5a> + 0x2a)
  7e:	3300      	movi	r3, 0	// regs: r3=0x0
  80:	2b2f      	subi	r3, 48	// regs: r3=0xffffffd0
  82:	3700      	movi	r7, 0	// regs: r7=0x0
  84:	a660      	st.b	r3, (r6, 0x0)	// *(*(<ret alloc_tx_skb@0x5a> + 0x1c)) = 0xffffffd0
  86:	3206      	movi	r2, 6	// regs: r2=0x6
  88:	31ff      	movi	r1, 255	// regs: r1=0xff
  8a:	dd060001 	st.b	r8, (r6, 0x1)	// *((*(<ret alloc_tx_skb@0x5a> + 0x1c) + 0x1)) = 0x1
  8e:	a6e2      	st.b	r7, (r6, 0x2)	// *((*(<ret alloc_tx_skb@0x5a> + 0x1c) + 0x2)) = 0x0
  90:	a6e3      	st.b	r7, (r6, 0x3)	// *((*(<ret alloc_tx_skb@0x5a> + 0x1c) + 0x3)) = 0x0
  92:	5e0e      	addi	r0, r6, 4	// regs: r0=(*(<ret alloc_tx_skb@0x5a> + 0x1c) + 0x4)
  94:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x94>, r1=<clobbered>
  98:	3206      	movi	r2, 6	// regs: r2=0x6
  9a:	e4240301 	addi	r1, r4, 770	// regs: r1=0x302
  9e:	e4060009 	addi	r0, r6, 10	// regs: r0=(*(<ret alloc_tx_skb@0x5a> + 0x1c) + 0xa)
  a2:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xa2>, r1=<clobbered>
  a6:	3206      	movi	r2, 6	// regs: r2=0x6
  a8:	e4240525 	addi	r1, r4, 1318	// regs: r1=0x526
  ac:	e406000f 	addi	r0, r6, 16	// regs: r0=(*(<ret alloc_tx_skb@0x5a> + 0x1c) + 0x10)
  b0:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xb0>, r1=<clobbered>
  b4:	a6f6      	st.b	r7, (r6, 0x16)	// *((*(<ret alloc_tx_skb@0x5a> + 0x1c) + 0x16)) = 0x0
  b6:	a6f7      	st.b	r7, (r6, 0x17)	// *((*(<ret alloc_tx_skb@0x5a> + 0x1c) + 0x17)) = 0x0
  b8:	3118      	movi	r1, 24	// regs: r1=0x18
  ba:	6c17      	mov	r0, r5	// regs: r0=<ret alloc_tx_skb@0x5a>
  bc:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0xbc>, r1=<clobbered>
  c0:	9566      	ld.w	r3, (r5, 0x18)	// regs: r3=*(<ret alloc_tx_skb@0x5a> + 0x18)
  c2:	9549      	ld.w	r2, (r5, 0x24)	// regs: r2=*(<ret alloc_tx_skb@0x5a> + 0x24)
  c4:	608e      	subu	r2, r3	// regs: r2=(*(<ret alloc_tx_skb@0x5a> + 0x24) - *(<ret alloc_tx_skb@0x5a> + 0x18))
  c6:	eb220034 	cmplti	r2, 53
  ca:	0845      	bt	0x154	// if (r2 < 0x35) goto loc_154;
  cc:	3200      	movi	r2, 0	// regs: r2=0x0
  ce:	2a22      	subi	r2, 35	// regs: r2=0xffffffdd
  d0:	a340      	st.b	r2, (r3, 0x0)	// *(*(<ret alloc_tx_skb@0x5a> + 0x18)) = 0xffffffdd
  d2:	3232      	movi	r2, 50	// regs: r2=0x32
  d4:	a341      	st.b	r2, (r3, 0x1)	// *((*(<ret alloc_tx_skb@0x5a> + 0x18) + 0x1)) = 0x32
  d6:	3240      	movi	r2, 64	// regs: r2=0x40
  d8:	a3e2      	st.b	r7, (r3, 0x2)	// *((*(<ret alloc_tx_skb@0x5a> + 0x18) + 0x2)) = 0x0
  da:	a343      	st.b	r2, (r3, 0x3)	// *((*(<ret alloc_tx_skb@0x5a> + 0x18) + 0x3)) = 0x40
  dc:	dd030004 	st.b	r8, (r3, 0x4)	// *((*(<ret alloc_tx_skb@0x5a> + 0x18) + 0x4)) = 0x1
  e0:	d8441198 	ld.h	r2, (r4, 0x330)	// regs: r2=*(0x330)
  e4:	a345      	st.b	r2, (r3, 0x5)	// *((*(<ret alloc_tx_skb@0x5a> + 0x18) + 0x5)) = *(0x330)
  e6:	4a48      	lsri	r2, r2, 8	// regs: r2=(*(0x330) >> 0x8)
  e8:	a346      	st.b	r2, (r3, 0x6)	// *((*(<ret alloc_tx_skb@0x5a> + 0x18) + 0x6)) = (*(0x330) >> 0x8)
  ea:	3202      	movi	r2, 2	// regs: r2=0x2
  ec:	a347      	st.b	r2, (r3, 0x7)	// *((*(<ret alloc_tx_skb@0x5a> + 0x18) + 0x7)) = 0x2
  ee:	3108      	movi	r1, 8	// regs: r1=0x8
  f0:	6c17      	mov	r0, r5	// regs: r0=<ret alloc_tx_skb@0x5a>
  f2:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0xf2>, r1=<clobbered>
  f6:	95c6      	ld.w	r6, (r5, 0x18)	// regs: r6=*(<ret alloc_tx_skb@0x5a> + 0x18)
  f8:	322c      	movi	r2, 44	// regs: r2=0x2c
  fa:	3100      	movi	r1, 0	// regs: r1=0x0
  fc:	6c1b      	mov	r0, r6	// regs: r0=*(<ret alloc_tx_skb@0x5a> + 0x18)
  fe:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0xfe>, r1=<clobbered>
 102:	d80420ce 	ld.w	r0, (r4, 0x338)	// regs: r0=*(0x338)
 106:	6c5b      	mov	r1, r6	// regs: r1=*(<ret alloc_tx_skb@0x5a> + 0x18)
 108:	c4805760 	zext	r0, r0, 27, 4	// regs: r0=zext(*(0x338))
 10c:	e0000000 	bsr	0x0	// <__put_unaligned_le32> // arg_bytes: 8; regs: r0=<ret __put_unaligned_le32@0x10c>, r1=<clobbered>
 110:	d8640309 	ld.b	r3, (r4, 0x309)	// regs: r3=*(0x309)
 114:	a664      	st.b	r3, (r6, 0x4)	// *((*(<ret alloc_tx_skb@0x5a> + 0x18) + 0x4)) = *(0x309)
 116:	d8640308 	ld.b	r3, (r4, 0x308)	// regs: r3=*(0x308)
 11a:	a665      	st.b	r3, (r6, 0x5)	// *((*(<ret alloc_tx_skb@0x5a> + 0x18) + 0x5)) = *(0x308)
 11c:	d864031e 	ld.b	r3, (r4, 0x31e)	// regs: r3=*(0x31e)
 120:	a666      	st.b	r3, (r6, 0x6)	// *((*(<ret alloc_tx_skb@0x5a> + 0x18) + 0x6)) = *(0x31e)
 122:	d8640a08 	ld.b	r3, (r4, 0xa08)	// regs: r3=*(0xa08)
 126:	a667      	st.b	r3, (r6, 0x7)	// *((*(<ret alloc_tx_skb@0x5a> + 0x18) + 0x7)) = *(0xa08)
 128:	3220      	movi	r2, 32	// regs: r2=0x20
 12a:	e424052d 	addi	r1, r4, 1326	// regs: r1=0x52e
 12e:	5e1e      	addi	r0, r6, 8	// regs: r0=(*(<ret alloc_tx_skb@0x5a> + 0x18) + 0x8)
 130:	e0000000 	bsr	0x0	// <strncpy>; regs: r0=<ret strncpy@0x130>, r1=<clobbered>
 134:	312c      	movi	r1, 44	// regs: r1=0x2c
 136:	6c17      	mov	r0, r5	// regs: r0=<ret alloc_tx_skb@0x5a>
 138:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x138>, r1=<clobbered>
 13c:	6c57      	mov	r1, r5	// regs: r1=<ret alloc_tx_skb@0x5a>
 13e:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(0x0)
 140:	e0000000 	bsr	0x0	// <lmac_ah_tx> // arg_bytes: 8; regs: r0=<ret lmac_ah_tx@0x140>, r1=<clobbered>
 144:	3300      	movi	r3, 0	// regs: r3=0x0
 146:	60e2      	subu	r3, r8	// regs: r3=(0x0 - 0x1)
 148:	64c2      	cmpne	r0, r3
 14a:	0b72      	bt	0x2e	// if (T) goto loc_2e;
loc_14c:
 14c:	6c17      	mov	r0, r5	// regs: r0=<ret alloc_tx_skb@0x5a>
 14e:	e0000000 	bsr	0x0	// <kfree_skb>; regs: r0=<ret kfree_skb@0x14e>, r1=<clobbered>
 152:	076c      	br	0x2a	// goto loc_2a;
loc_154:
 154:	1024      	lrw	r1, 0x0	// regs: r1=0x0
 156:	1005      	lrw	r0, 0x0	// regs: r0=0x0
 158:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x158>, r1=<clobbered>
 15c:	07f8      	br	0x14c	// goto loc_14c;
 15e:	0000      	.short	0x0000
 160:	00000000 	.long	0x00000000	// <ah_lmac>
 164:	00000000 	.long	0x00000000	// <.rodata.__func__.14519>
 168:	00000000 	.long	0x00000000	// <.rodata.lmac_tx_pv0_s1g_beacon.str1.1+0x77>

Disassembly of section .text.lmac_send_scan_probe:

00000000 <lmac_send_scan_probe>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	1098      	lrw	r4, 0x0	// regs: r4=0x0
   4:	d8242295 	ld.w	r1, (r4, 0xa54)	// regs: r1=*(0xa54)
   8:	e921000f 	bnez	r1, 0x26	// if (r1 != 0x0) goto loc_26;
   c:	1016      	lrw	r0, 0x0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xe>, r1=<clobbered>
  12:	3000      	movi	r0, 0	// regs: r0=0x0
  14:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_16:
  16:	d8640a4f 	ld.b	r3, (r4, 0xa4f)	// regs: r3=*(0xa4f)
  1a:	3200      	movi	r2, 0	// regs: r2=0x0
  1c:	c4625c04 	ins	r3, r2, 4, 4
  20:	dc640a4f 	st.b	r3, (r4, 0xa4f)	// *(0xa4f) = *(0xa4f)
  24:	041d      	br	0x5e	// goto loc_5e;
loc_26:
  26:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(0x0)
  28:	e0000000 	bsr	0x0	// <lmac_ah_tx> // arg_bytes: 8; regs: r0=<ret lmac_ah_tx@0x28>, r1=<clobbered>
  2c:	e920fff5 	bnez	r0, 0x16	// if (r0 != 0x0) goto loc_16;
  30:	d8642295 	ld.w	r3, (r4, 0xa54)	// regs: r3=*(0xa54)
  34:	104d      	lrw	r2, 0x0	// regs: r2=0x0
  36:	932d      	ld.w	r1, (r3, 0x34)	// regs: r1=*((*(0xa54) + 0x34))
  38:	e901000c 	bez	r1, 0x50	// if (r1 == 0x0) goto loc_50;
  3c:	8260      	ld.b	r3, (r2, 0x0)	// regs: r3=*(0x0)
  3e:	2300      	addi	r3, 1	// regs: r3=(*(0x0) + 0x1)
  40:	74cc      	zextb	r3, r3	// regs: r3=zext8((*(0x0) + 0x1))
  42:	d9810003 	ld.b	r12, (r1, 0x3)	// regs: r12=*((*((*(0xa54) + 0x34)) + 0x3))
  46:	c5835c80 	ins	r12, r3, 4, 0
  4a:	dd810003 	st.b	r12, (r1, 0x3)	// *((*((*(0xa54) + 0x34)) + 0x3)) = *((*((*(0xa54) + 0x34)) + 0x3))
  4e:	a260      	st.b	r3, (r2, 0x0)	// *(0x0) = zext8((*(0x0) + 0x1))
loc_50:
  50:	d8240378 	ld.b	r1, (r4, 0x378)	// regs: r1=*(0x378)
  54:	8260      	ld.b	r3, (r2, 0x0)	// regs: r3=*(0x0)
  56:	644c      	cmphs	r3, r1
  58:	0c03      	bf	0x5e	// if (!T) goto loc_5e;
  5a:	3300      	movi	r3, 0	// regs: r3=0x0
  5c:	a260      	st.b	r3, (r2, 0x0)	// *(0x0) = 0x0
loc_5e:
  5e:	1491      	pop	r4, r15
  60:	0000      	.short	0x0000	// <ah_lmac>
  62:	0000      	.short	0x0000
  64:	00000000 	.long	0x00000000	// <.rodata.lmac_send_scan_probe.str1.1>
  68:	00000000 	.long	0x00000000	// <.bss.scan_freq_idx.14533>

Disassembly of section .text.lmac_send_ant_pkt:

00000000 <lmac_send_ant_pkt>: // arg_bytes: 0
   0:	14d5      	push	r4-r8, r15
   2:	119d      	lrw	r4, 0x0	// regs: r4=0x0
   4:	d8440303 	ld.b	r2, (r4, 0x303)	// regs: r2=*(0x303)
   8:	d8640302 	ld.b	r3, (r4, 0x302)	// regs: r3=*(0x302)
   c:	6cc8      	or	r3, r2	// regs: r3=(*(0x302) | *(0x303))
   e:	d8440304 	ld.b	r2, (r4, 0x304)	// regs: r2=*(0x304)
  12:	6cc8      	or	r3, r2	// regs: r3=((*(0x302) | *(0x303)) | *(0x304))
  14:	d8440305 	ld.b	r2, (r4, 0x305)	// regs: r2=*(0x305)
  18:	6cc8      	or	r3, r2	// regs: r3=(((*(0x302) | *(0x303)) | *(0x304)) | *(0x305))
  1a:	d8440306 	ld.b	r2, (r4, 0x306)	// regs: r2=*(0x306)
  1e:	6cc8      	or	r3, r2	// regs: r3=((((*(0x302) | *(0x303)) | *(0x304)) | *(0x305)) | *(0x306))
  20:	d8440307 	ld.b	r2, (r4, 0x307)	// regs: r2=*(0x307)
  24:	6cc8      	or	r3, r2	// regs: r3=(((((*(0x302) | *(0x303)) | *(0x304)) | *(0x305)) | *(0x306)) | *(0x307))
  26:	e9230009 	bnez	r3, 0x38	// if (r3 != 0x0) goto loc_38;
  2a:	1114      	lrw	r0, 0x0	// regs: r0=0x0
loc_2c:
  2c:	3400      	movi	r4, 0	// regs: r4=0x0
  2e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2e>, r1=<clobbered>
  32:	2c00      	subi	r4, 1	// regs: r4=0xffffffff
loc_34:
  34:	6c13      	mov	r0, r4	// regs: r0=r4
  36:	1495      	pop	r4-r8, r15
loc_38:
  38:	3080      	movi	r0, 128	// regs: r0=0x80
  3a:	4002      	lsli	r0, r0, 2	// regs: r0=0x200
  3c:	e0000000 	bsr	0x0	// <alloc_tx_skb>; regs: r0=<ret alloc_tx_skb@0x3c>, r1=<clobbered>
  40:	6d83      	mov	r6, r0	// regs: r6=<ret alloc_tx_skb@0x3c>
  42:	e9200004 	bnez	r0, 0x4a	// if (r0 != 0x0) goto loc_4a;
  46:	110e      	lrw	r0, 0x0	// regs: r0=0x0
  48:	07f2      	br	0x2c	// goto loc_2c;
loc_4a:
  4a:	3180      	movi	r1, 128	// regs: r1=0x80
  4c:	4121      	lsli	r1, r1, 1	// regs: r1=0x100
  4e:	e0000000 	bsr	0x0	// <skb_reserve>; regs: r0=<ret skb_reserve@0x4e>, r1=<clobbered>
  52:	ea080001 	movi	r8, 1	// regs: r8=0x1
  56:	d866002a 	ld.b	r3, (r6, 0x2a)	// regs: r3=*(<ret alloc_tx_skb@0x3c> + 0x2a)
  5a:	3700      	movi	r7, 0	// regs: r7=0x0
  5c:	c4685c06 	ins	r3, r8, 6, 6
  60:	dc66002a 	st.b	r3, (r6, 0x2a)	// *(<ret alloc_tx_skb@0x3c> + 0x2a) = *(<ret alloc_tx_skb@0x3c> + 0x2a)
  64:	3244      	movi	r2, 68	// regs: r2=0x44
  66:	6c5f      	mov	r1, r7	// regs: r1=0x0
  68:	b6ed      	st.w	r7, (r6, 0x34)	// *(<ret alloc_tx_skb@0x3c> + 0x34) = 0x0
  6a:	9608      	ld.w	r0, (r6, 0x20)	// regs: r0=*(<ret alloc_tx_skb@0x3c> + 0x20)
  6c:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x6c>, r1=<clobbered>
  70:	96a7      	ld.w	r5, (r6, 0x1c)	// regs: r5=*(<ret alloc_tx_skb@0x3c> + 0x1c)
  72:	320b      	movi	r2, 11	// regs: r2=0xb
  74:	c4484823 	lsli	r3, r8, 2	// regs: r3=0x4
  78:	ade0      	st.h	r7, (r5, 0x0)	// *(*(<ret alloc_tx_skb@0x3c> + 0x1c)) = 0x0
  7a:	c4625c64 	ins	r3, r2, 7, 4
  7e:	a560      	st.b	r3, (r5, 0x0)	// *(*(<ret alloc_tx_skb@0x3c> + 0x1c)) = 0x4
  80:	8561      	ld.b	r3, (r5, 0x1)	// regs: r3=*((*(<ret alloc_tx_skb@0x3c> + 0x1c) + 0x1))
  82:	c4685c00 	ins	r3, r8, 0, 0
  86:	a561      	st.b	r3, (r5, 0x1)	// *((*(<ret alloc_tx_skb@0x3c> + 0x1c) + 0x1)) = *((*(<ret alloc_tx_skb@0x3c> + 0x1c) + 0x1))
  88:	d8441338 	ld.h	r2, (r4, 0x670)	// regs: r2=*(0x670)
  8c:	d8641336 	ld.h	r3, (r4, 0x66c)	// regs: r3=*(0x66c)
  90:	60c8      	addu	r3, r2	// regs: r3=(*(0x66c) + *(0x670))
  92:	e46301f9 	addi	r3, r3, 506	// regs: r3=((*(0x66c) + *(0x670)) + 0x1fa)
  96:	74cd      	zexth	r3, r3	// regs: r3=zext16(((*(0x66c) + *(0x670)) + 0x1fa))
  98:	a562      	st.b	r3, (r5, 0x2)	// *((*(<ret alloc_tx_skb@0x3c> + 0x1c) + 0x2)) = zext16(((*(0x66c) + *(0x670)) + 0x1fa))
  9a:	4b68      	lsri	r3, r3, 8	// regs: r3=(zext16(((*(0x66c) + *(0x670)) + 0x1fa)) >> 0x8)
  9c:	a563      	st.b	r3, (r5, 0x3)	// *((*(<ret alloc_tx_skb@0x3c> + 0x1c) + 0x3)) = (zext16(((*(0x66c) + *(0x670)) + 0x1fa)) >> 0x8)
  9e:	e4240525 	addi	r1, r4, 1318	// regs: r1=0x526
  a2:	3206      	movi	r2, 6	// regs: r2=0x6
  a4:	5d0e      	addi	r0, r5, 4	// regs: r0=(*(<ret alloc_tx_skb@0x3c> + 0x1c) + 0x4)
  a6:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xa6>, r1=<clobbered>
  aa:	e4240301 	addi	r1, r4, 770	// regs: r1=0x302
  ae:	3206      	movi	r2, 6	// regs: r2=0x6
  b0:	e4050009 	addi	r0, r5, 10	// regs: r0=(*(<ret alloc_tx_skb@0x3c> + 0x1c) + 0xa)
  b4:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xb4>, r1=<clobbered>
  b8:	3206      	movi	r2, 6	// regs: r2=0x6
  ba:	e4240301 	addi	r1, r4, 770	// regs: r1=0x302
  be:	e405000f 	addi	r0, r5, 16	// regs: r0=(*(<ret alloc_tx_skb@0x3c> + 0x1c) + 0x10)
  c2:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xc2>, r1=<clobbered>
  c6:	3118      	movi	r1, 24	// regs: r1=0x18
  c8:	a5f6      	st.b	r7, (r5, 0x16)	// *((*(<ret alloc_tx_skb@0x3c> + 0x1c) + 0x16)) = 0x0
  ca:	a5f7      	st.b	r7, (r5, 0x17)	// *((*(<ret alloc_tx_skb@0x3c> + 0x1c) + 0x17)) = 0x0
  cc:	6c1b      	mov	r0, r6	// regs: r0=<ret alloc_tx_skb@0x3c>
  ce:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0xce>, r1=<clobbered>
  d2:	9400      	ld.w	r0, (r4, 0x0)	// regs: r0=*(0x0)
  d4:	6c5b      	mov	r1, r6	// regs: r1=<ret alloc_tx_skb@0x3c>
  d6:	9065      	ld.w	r3, (r0, 0x14)	// regs: r3=*((*(0x0) + 0x14))
  d8:	7bcd      	jsr	r3
  da:	6cdf      	mov	r3, r7	// regs: r3=0x0
  dc:	60e2      	subu	r3, r8	// regs: r3=(0x0 - 0x1)
  de:	64c2      	cmpne	r0, r3
  e0:	6d03      	mov	r4, r0	// regs: r4=*(0x0)
  e2:	0ba9      	bt	0x34	// if (T) goto loc_34;
  e4:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  e6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xe6>, r1=<clobbered>
  ea:	6c1b      	mov	r0, r6	// regs: r0=<ret alloc_tx_skb@0x3c>
  ec:	e0000000 	bsr	0x0	// <kfree_skb>; regs: r0=<ret kfree_skb@0xec>, r1=<clobbered>
  f0:	07a2      	br	0x34	// goto loc_34;
  f2:	0000      	.short	0x0000
  f4:	00000000 	.long	0x00000000	// <ah_lmac>
  f8:	00000000 	.long	0x00000000	// <.rodata.lmac_send_ant_pkt.str1.1>
  fc:	0000      	.short	0x0000	// <.rodata.lmac_send_ant_pkt.str1.1+0x10>
  fe:	0000      	.short	0x0000
 100:	0000      	.short	0x0000	// <.rodata.lmac_send_ant_pkt.str1.1+0x22>
 102:	0000      	.short	0x0000

Disassembly of section .text.lmac_send_probe_resp:

00000000 <lmac_send_probe_resp>: // arg_bytes: 0
   0:	14d5      	push	r4-r8, r15
   2:	12a1      	lrw	r5, 0x0	// regs: r5=0x0
   4:	d8450303 	ld.b	r2, (r5, 0x303)	// regs: r2=*(0x303)
   8:	d8650302 	ld.b	r3, (r5, 0x302)	// regs: r3=*(0x302)
   c:	6cc8      	or	r3, r2	// regs: r3=(*(0x302) | *(0x303))
   e:	d8450304 	ld.b	r2, (r5, 0x304)	// regs: r2=*(0x304)
  12:	6cc8      	or	r3, r2	// regs: r3=((*(0x302) | *(0x303)) | *(0x304))
  14:	d8450305 	ld.b	r2, (r5, 0x305)	// regs: r2=*(0x305)
  18:	6cc8      	or	r3, r2	// regs: r3=(((*(0x302) | *(0x303)) | *(0x304)) | *(0x305))
  1a:	d8450306 	ld.b	r2, (r5, 0x306)	// regs: r2=*(0x306)
  1e:	6cc8      	or	r3, r2	// regs: r3=((((*(0x302) | *(0x303)) | *(0x304)) | *(0x305)) | *(0x306))
  20:	d8450307 	ld.b	r2, (r5, 0x307)	// regs: r2=*(0x307)
  24:	6cc8      	or	r3, r2	// regs: r3=(((((*(0x302) | *(0x303)) | *(0x304)) | *(0x305)) | *(0x306)) | *(0x307))
  26:	e9230006 	bnez	r3, 0x32	// if (r3 != 0x0) goto loc_32;
loc_2a:
  2a:	3400      	movi	r4, 0	// regs: r4=0x0
  2c:	2c00      	subi	r4, 1	// regs: r4=0xffffffff
loc_2e:
  2e:	6c13      	mov	r0, r4	// regs: r0=r4
  30:	1495      	pop	r4-r8, r15
loc_32:
  32:	3080      	movi	r0, 128	// regs: r0=0x80
  34:	4004      	lsli	r0, r0, 4	// regs: r0=0x800
  36:	e0000000 	bsr	0x0	// <alloc_tx_skb>; regs: r0=<ret alloc_tx_skb@0x36>, r1=<clobbered>
  3a:	6d83      	mov	r6, r0	// regs: r6=<ret alloc_tx_skb@0x36>
  3c:	e900fff7 	bez	r0, 0x2a	// if (r0 == 0x0) goto loc_2a;
  40:	3180      	movi	r1, 128	// regs: r1=0x80
  42:	4121      	lsli	r1, r1, 1	// regs: r1=0x100
  44:	e0000000 	bsr	0x0	// <skb_reserve>; regs: r0=<ret skb_reserve@0x44>, r1=<clobbered>
  48:	ea080001 	movi	r8, 1	// regs: r8=0x1
  4c:	d866002a 	ld.b	r3, (r6, 0x2a)	// regs: r3=*(<ret alloc_tx_skb@0x36> + 0x2a)
  50:	9687      	ld.w	r4, (r6, 0x1c)	// regs: r4=*(<ret alloc_tx_skb@0x36> + 0x1c)
  52:	c4685c06 	ins	r3, r8, 6, 6
  56:	dc66002a 	st.b	r3, (r6, 0x2a)	// *(<ret alloc_tx_skb@0x36> + 0x2a) = *(<ret alloc_tx_skb@0x36> + 0x2a)
  5a:	3350      	movi	r3, 80	// regs: r3=0x50
  5c:	a460      	st.b	r3, (r4, 0x0)	// *(*(<ret alloc_tx_skb@0x36> + 0x1c)) = 0x50
  5e:	3300      	movi	r3, 0	// regs: r3=0x0
  60:	c4685c01 	ins	r3, r8, 1, 1
  64:	3700      	movi	r7, 0	// regs: r7=0x0
  66:	a461      	st.b	r3, (r4, 0x1)	// *((*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x1)) = 0x0
  68:	a4e2      	st.b	r7, (r4, 0x2)	// *((*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x2)) = 0x0
  6a:	a4e3      	st.b	r7, (r4, 0x3)	// *((*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x3)) = 0x0
  6c:	3206      	movi	r2, 6	// regs: r2=0x6
  6e:	31ff      	movi	r1, 255	// regs: r1=0xff
  70:	5c0e      	addi	r0, r4, 4	// regs: r0=(*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x4)
  72:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x72>, r1=<clobbered>
  76:	3206      	movi	r2, 6	// regs: r2=0x6
  78:	e4250301 	addi	r1, r5, 770	// regs: r1=0x302
  7c:	e4040009 	addi	r0, r4, 10	// regs: r0=(*(<ret alloc_tx_skb@0x36> + 0x1c) + 0xa)
  80:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x80>, r1=<clobbered>
  84:	3206      	movi	r2, 6	// regs: r2=0x6
  86:	e4250301 	addi	r1, r5, 770	// regs: r1=0x302
  8a:	e404000f 	addi	r0, r4, 16	// regs: r0=(*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x10)
  8e:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x8e>, r1=<clobbered>
  92:	e4240017 	addi	r1, r4, 24	// regs: r1=(*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x18)
  96:	a4f6      	st.b	r7, (r4, 0x16)	// *((*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x16)) = 0x0
  98:	a4f7      	st.b	r7, (r4, 0x17)	// *((*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x17)) = 0x0
  9a:	d8052198 	ld.w	r0, (r5, 0x660)	// regs: r0=*(0x660)
  9e:	e0000000 	bsr	0x0	// <__put_unaligned_le32> // arg_bytes: 8; regs: r0=<ret __put_unaligned_le32@0x9e>, r1=<clobbered>
  a2:	e424001b 	addi	r1, r4, 28	// regs: r1=(*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x1c)
  a6:	d8052199 	ld.w	r0, (r5, 0x664)	// regs: r0=*(0x664)
  aa:	e0000000 	bsr	0x0	// <__put_unaligned_le32> // arg_bytes: 8; regs: r0=<ret __put_unaligned_le32@0xaa>, r1=<clobbered>
  ae:	3300      	movi	r3, 0	// regs: r3=0x0
  b0:	2b0b      	subi	r3, 12	// regs: r3=0xfffffff4
  b2:	dc640020 	st.b	r3, (r4, 0x20)	// *((*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x20)) = 0xfffffff4
  b6:	dd040021 	st.b	r8, (r4, 0x21)	// *((*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x21)) = 0x1
  ba:	dd040022 	st.b	r8, (r4, 0x22)	// *((*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x22)) = 0x1
  be:	dce40023 	st.b	r7, (r4, 0x23)	// *((*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x23)) = 0x0
  c2:	3124      	movi	r1, 36	// regs: r1=0x24
  c4:	6c1b      	mov	r0, r6	// regs: r0=<ret alloc_tx_skb@0x36>
  c6:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0xc6>, r1=<clobbered>
  ca:	d845052d 	ld.b	r2, (r5, 0x52d)	// regs: r2=*(0x52d)
  ce:	2201      	addi	r2, 2	// regs: r2=(*(0x52d) + 0x2)
  d0:	e425052b 	addi	r1, r5, 1324	// regs: r1=0x52c
  d4:	e4040023 	addi	r0, r4, 36	// regs: r0=(*(<ret alloc_tx_skb@0x36> + 0x1c) + 0x24)
  d8:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xd8>, r1=<clobbered>
  dc:	d825052d 	ld.b	r1, (r5, 0x52d)	// regs: r1=*(0x52d)
  e0:	2101      	addi	r1, 2	// regs: r1=(*(0x52d) + 0x2)
  e2:	6c1b      	mov	r0, r6	// regs: r0=<ret alloc_tx_skb@0x36>
  e4:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0xe4>, r1=<clobbered>
  e8:	9500      	ld.w	r0, (r5, 0x0)	// regs: r0=*(0x0)
  ea:	6c5b      	mov	r1, r6	// regs: r1=<ret alloc_tx_skb@0x36>
  ec:	9065      	ld.w	r3, (r0, 0x14)	// regs: r3=*((*(0x0) + 0x14))
  ee:	7bcd      	jsr	r3
  f0:	3300      	movi	r3, 0	// regs: r3=0x0
  f2:	60e2      	subu	r3, r8	// regs: r3=(0x0 - 0x1)
  f4:	64c2      	cmpne	r0, r3
  f6:	6d03      	mov	r4, r0	// regs: r4=*(0x0)
  f8:	0b9b      	bt	0x2e	// if (T) goto loc_2e;
  fa:	6c1b      	mov	r0, r6	// regs: r0=<ret alloc_tx_skb@0x36>
  fc:	e0000000 	bsr	0x0	// <kfree_skb>; regs: r0=<ret kfree_skb@0xfc>, r1=<clobbered>
 100:	0797      	br	0x2e	// goto loc_2e;
 102:	0000      	.short	0x0000
 104:	00000000 	.long	0x00000000	// <ah_lmac>
