
libs\obj\liblmac\lmac_lmac_rxq.o:     file format elf32-csky-little


Disassembly of section .text.lmac_rxq_init:

00000000 <lmac_rxq_init>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	6d87      	mov	r6, r1	// regs: r6=<arg1>
   6:	6d4b      	mov	r5, r2	// regs: r5=<arg2>
   8:	3100      	movi	r1, 0	// regs: r1=0x0
   a:	3214      	movi	r2, 20	// regs: r2=0x14
   c:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0xc>, r1=<clobbered>
  10:	3100      	movi	r1, 0	// regs: r1=0x0
  12:	6c13      	mov	r0, r4	// regs: r0=<arg0>
  14:	e0000000 	bsr	0x0	// <os_sema_init>; regs: r0=<ret os_sema_init@0x14>, r1=<clobbered>
  18:	3000      	movi	r0, 0	// regs: r0=0x0
  1a:	b4c2      	st.w	r6, (r4, 0x8)	// *(<arg0> + 0x8) = <arg1>
  1c:	b4a4      	st.w	r5, (r4, 0x10)	// *(<arg0> + 0x10) = <arg2>
  1e:	1493      	pop	r4-r6, r15

Disassembly of section .text.lmac_rxq_put:

00000000 <lmac_rxq_put>: // arg_bytes: 12
   0:	14d4      	push	r4-r7, r15
   2:	6d4b      	mov	r5, r2	// regs: r5=<arg2>
   4:	e962003b 	blsz	r2, 0x7a
   8:	8866      	ld.h	r3, (r0, 0xc)	// regs: r3=*(<arg0> + 0xc)
   a:	8847      	ld.h	r2, (r0, 0xe)	// regs: r2=*(<arg0> + 0xe)
   c:	648c      	cmphs	r3, r2
   e:	d9802004 	ld.w	r12, (r0, 0x10)	// regs: r12=*(<arg0> + 0x10)
  12:	0c2f      	bf	0x70	// if (!T) goto loc_70;
loc_14:
  14:	60ca      	subu	r3, r2	// regs: r3=(r3 - *(<arg0> + 0xe))
  16:	60d4      	addu	r3, r5	// regs: r3=((r3 - *(<arg0> + 0xe)) + <arg2>)
  18:	670c      	cmphs	r3, r12
  1a:	082d      	bt	0x74	// if (T) goto loc_74;
  1c:	3400      	movi	r4, 0	// regs: r4=0x0
  1e:	6d93      	mov	r6, r4	// regs: r6=0x0
loc_20:
  20:	d9a01006 	ld.h	r13, (r0, 0xc)	// regs: r13=*(<arg0> + 0xc)
  24:	e46d0000 	addi	r3, r13, 1	// regs: r3=(*(<arg0> + 0xc) + 0x1)
  28:	670c      	cmphs	r3, r12
  2a:	6dcf      	mov	r7, r3	// regs: r7=(*(<arg0> + 0xc) + 0x1)
  2c:	c4660c40 	inct	r3, r6, 0
  30:	648e      	cmpne	r3, r2
  32:	0c14      	bf	0x5a	// if (!T) goto loc_5a;
  34:	9062      	ld.w	r3, (r0, 0x8)	// regs: r3=*(<arg0> + 0x8)
  36:	c46d482d 	lsli	r13, r13, 3	// regs: r13=(*(<arg0> + 0xc) << 0x3)
  3a:	634c      	addu	r13, r3	// regs: r13=((*(<arg0> + 0xc) << 0x3) + *(<arg0> + 0x8))
  3c:	9160      	ld.w	r3, (r1, 0x0)	// regs: r3=*(r1)
  3e:	dc6d2000 	st.w	r3, (r13, 0x0)	// *(((*(<arg0> + 0xc) << 0x3) + *(<arg0> + 0x8))) = *(r1)
  42:	9161      	ld.w	r3, (r1, 0x4)	// regs: r3=*(r1 + 0x4)
  44:	dc6d2001 	st.w	r3, (r13, 0x4)	// *((((*(<arg0> + 0xc) << 0x3) + *(<arg0> + 0x8)) + 0x4)) = *(r1 + 0x4)
  48:	671c      	cmphs	r7, r12
  4a:	74dd      	zexth	r3, r7	// regs: r3=zext16((*(<arg0> + 0xc) + 0x1))
  4c:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  4e:	c4660c40 	inct	r3, r6, 0
  52:	6516      	cmpne	r5, r4
  54:	a866      	st.h	r3, (r0, 0xc)	// *(<arg0> + 0xc) = zext16((*(<arg0> + 0xc) + 0x1))
  56:	2107      	addi	r1, 8	// regs: r1=(r1 + 0x8)
  58:	0be4      	bt	0x20	// if (T) goto loc_20;
loc_5a:
  5a:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x5a>, r1=<clobbered>
  5e:	6516      	cmpne	r5, r4
  60:	0c06      	bf	0x6c	// if (!T) goto loc_6c;
  62:	1048      	lrw	r2, 0x0	// regs: r2=0x0
  64:	313a      	movi	r1, 58	// regs: r1=0x3a
  66:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  68:	e0000000 	bsr	0x0	// <assert_internal>; regs: r0=<ret assert_internal@0x68>, r1=<clobbered>
loc_6c:
  6c:	6c13      	mov	r0, r4	// regs: r0=r4
  6e:	1494      	pop	r4-r7, r15
loc_70:
  70:	60f0      	addu	r3, r12	// regs: r3=(*(<arg0> + 0xc) + *(<arg0> + 0x10))
  72:	07d1      	br	0x14	// goto loc_14;
loc_74:
  74:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  76:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x76>, r1=<clobbered>
  7a:	3400      	movi	r4, 0	// regs: r4=0x0
  7c:	07f8      	br	0x6c	// goto loc_6c;
  7e:	0000      	.short	0x0000
  80:	00000000 	.long	0x00000000	// <.rodata.lmac_rxq_put.str1.1+0x10>
  84:	00000000 	.long	0x00000000	// <.rodata.__func__.5275>
  88:	00000000 	.long	0x00000000	// <.rodata.lmac_rxq_put.str1.1>

Disassembly of section .text.lmac_rxq_get:

00000000 <lmac_rxq_get>: // arg_bytes: 16
   0:	14d3      	push	r4-r6, r15
   2:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   4:	6d8b      	mov	r6, r2	// regs: r6=<arg2>
   6:	8826      	ld.h	r1, (r0, 0xc)	// regs: r1=*(<arg0> + 0xc)
   8:	8847      	ld.h	r2, (r0, 0xe)	// regs: r2=*(<arg0> + 0xe)
   a:	6486      	cmpne	r1, r2
   c:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   e:	0804      	bt	0x16	// if (T) goto loc_16;
  10:	6c4f      	mov	r1, r3	// regs: r1=<arg3>
  12:	e0000000 	bsr	0x0	// <os_sema_down>; regs: r0=<ret os_sema_down@0x12>, r1=<clobbered>
loc_16:
  16:	3000      	movi	r0, 0	// regs: r0=0x0
  18:	8c46      	ld.h	r2, (r4, 0xc)	// regs: r2=*(<arg0> + 0xc)
  1a:	6c57      	mov	r1, r5	// regs: r1=<arg1>
  1c:	6f43      	mov	r13, r0	// regs: r13=0x0
loc_1e:
  1e:	8c67      	ld.h	r3, (r4, 0xe)	// regs: r3=*(<arg0> + 0xe)
  20:	64ca      	cmpne	r2, r3
  22:	0c03      	bf	0x28	// if (!T) goto loc_28;
  24:	6581      	cmplt	r0, r6
  26:	0802      	bt	0x2a	// if (T) goto loc_2a;
loc_28:
  28:	1493      	pop	r4-r6, r15
loc_2a:
  2a:	43a3      	lsli	r5, r3, 3	// regs: r5=(*(<arg0> + 0xe) << 0x3)
  2c:	d9842002 	ld.w	r12, (r4, 0x8)	// regs: r12=*(<arg0> + 0x8)
  30:	6314      	addu	r12, r5	// regs: r12=(*(<arg0> + 0x8) + (*(<arg0> + 0xe) << 0x3))
  32:	2300      	addi	r3, 1	// regs: r3=(*(<arg0> + 0xe) + 0x1)
  34:	d8ac2000 	ld.w	r5, (r12, 0x0)	// regs: r5=*((*(<arg0> + 0x8) + (*(<arg0> + 0xe) << 0x3)))
  38:	d98c2001 	ld.w	r12, (r12, 0x4)	// regs: r12=*(((*(<arg0> + 0x8) + (*(<arg0> + 0xe) << 0x3)) + 0x4))
  3c:	dd812001 	st.w	r12, (r1, 0x4)	// *(r1 + 0x4) = *(((*(<arg0> + 0x8) + (*(<arg0> + 0xe) << 0x3)) + 0x4))
  40:	b1a0      	st.w	r5, (r1, 0x0)	// *(r1) = *((*(<arg0> + 0x8) + (*(<arg0> + 0xe) << 0x3)))
  42:	770d      	zexth	r12, r3	// regs: r12=zext16((*(<arg0> + 0xe) + 0x1))
  44:	94a4      	ld.w	r5, (r4, 0x10)	// regs: r5=*(<arg0> + 0x10)
  46:	654c      	cmphs	r3, r5
  48:	6cf3      	mov	r3, r12	// regs: r3=zext16((*(<arg0> + 0xe) + 0x1))
  4a:	c46d0c40 	inct	r3, r13, 0
  4e:	ac67      	st.h	r3, (r4, 0xe)	// *(<arg0> + 0xe) = zext16((*(<arg0> + 0xe) + 0x1))
  50:	2000      	addi	r0, 1	// regs: r0=(r0 + 0x1)
  52:	2107      	addi	r1, 8	// regs: r1=(r1 + 0x8)
  54:	07e5      	br	0x1e	// goto loc_1e;

Disassembly of section .text.lmac_rxq_free:

00000000 <lmac_rxq_free>: // arg_bytes: 4
   0:	8867      	ld.h	r3, (r0, 0xe)	// regs: r3=*(<arg0> + 0xe)
   2:	8846      	ld.h	r2, (r0, 0xc)	// regs: r2=*(<arg0> + 0xc)
   4:	64c8      	cmphs	r2, r3
   6:	0804      	bt	0xe	// if (T) goto loc_e;
   8:	5b09      	subu	r0, r3, r2	// regs: r0=(*(<arg0> + 0xe) - *(<arg0> + 0xc))
   a:	2800      	subi	r0, 1	// regs: r0=((*(<arg0> + 0xe) - *(<arg0> + 0xc)) - 0x1)
loc_c:
   c:	783c      	jmp	r15	// return;
loc_e:
   e:	9004      	ld.w	r0, (r0, 0x10)	// regs: r0=*(<arg0> + 0x10)
  10:	2800      	subi	r0, 1	// regs: r0=(*(<arg0> + 0x10) - 0x1)
  12:	600c      	addu	r0, r3	// regs: r0=((*(<arg0> + 0x10) - 0x1) + *(<arg0> + 0xe))
  14:	600a      	subu	r0, r2	// regs: r0=(((*(<arg0> + 0x10) - 0x1) + *(<arg0> + 0xe)) - *(<arg0> + 0xc))
  16:	07fb      	br	0xc	// goto loc_c;

Disassembly of section .text.lmac_rxq_count:

00000000 <lmac_rxq_count>: // arg_bytes: 4
   0:	8846      	ld.h	r2, (r0, 0xc)	// regs: r2=*(<arg0> + 0xc)
   2:	8867      	ld.h	r3, (r0, 0xe)	// regs: r3=*(<arg0> + 0xe)
   4:	64c8      	cmphs	r2, r3
   6:	0c03      	bf	0xc	// if (!T) goto loc_c;
   8:	5a0d      	subu	r0, r2, r3	// regs: r0=(*(<arg0> + 0xc) - *(<arg0> + 0xe))
loc_a:
   a:	783c      	jmp	r15	// return;
loc_c:
   c:	9004      	ld.w	r0, (r0, 0x10)	// regs: r0=*(<arg0> + 0x10)
   e:	6008      	addu	r0, r2	// regs: r0=(*(<arg0> + 0x10) + *(<arg0> + 0xc))
  10:	600e      	subu	r0, r3	// regs: r0=((*(<arg0> + 0x10) + *(<arg0> + 0xc)) - *(<arg0> + 0xe))
  12:	07fc      	br	0xa	// goto loc_a;
