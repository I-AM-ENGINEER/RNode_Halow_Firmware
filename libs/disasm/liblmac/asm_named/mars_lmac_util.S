
libs\obj\liblmac\mars_lmac_util.o:     file format elf32-csky-little


Disassembly of section .text.lmac_psm_info_update:

00000000 <lmac_psm_info_update>: // arg_bytes: 0
   0:	14c2      	push	r4-r5
   2:	1073      	lrw	r3, 0x0	// regs: r3=0x0
   4:	3200      	movi	r2, 0	// regs: r2=0x0
   6:	d983227e 	ld.w	r12, (r3, 0x9f8)	// regs: r12=*(0x9f8)
   a:	6c4b      	mov	r1, r2	// regs: r1=0x0
   c:	6c0b      	mov	r0, r2	// regs: r0=0x0
   e:	e48309f7 	addi	r4, r3, 2552	// regs: r4=0x9f8
loc_12:
  12:	6532      	cmpne	r12, r4
  14:	0808      	bt	0x24	// if (T) goto loc_24;
  16:	dc031504 	st.h	r0, (r3, 0xa08)	// *(0xa08) = r0
  1a:	dc231505 	st.h	r1, (r3, 0xa0a)	// *(0xa0a) = r1
  1e:	dc431506 	st.h	r2, (r3, 0xa0c)	// *(0xa0c) = r2
  22:	1482      	pop	r4-r5
loc_24:
  24:	d9ac006b 	ld.b	r13, (r12, 0x6b)	// regs: r13=*(r12 + 0x6b)
  28:	e4ad2002 	andi	r5, r13, 2	// regs: r5=(*(r12 + 0x6b) & 0x2)
  2c:	2000      	addi	r0, 1	// regs: r0=(r0 + 0x1)
  2e:	7401      	zexth	r0, r0	// regs: r0=zext16((r0 + 0x1))
  30:	e9050004 	bez	r5, 0x38	// if (r5 == 0x0) goto loc_38;
  34:	2100      	addi	r1, 1	// regs: r1=(r1 + 0x1)
  36:	7445      	zexth	r1, r1	// regs: r1=zext16((r1 + 0x1))
loc_38:
  38:	e5ad2008 	andi	r13, r13, 8	// regs: r13=(*(r12 + 0x6b) & 0x8)
  3c:	e90d0004 	bez	r13, 0x44	// if (r13 == 0x0) goto loc_44;
  40:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
  42:	7489      	zexth	r2, r2	// regs: r2=zext16((r2 + 0x1))
loc_44:
  44:	d98c2000 	ld.w	r12, (r12, 0x0)	// regs: r12=*(r12)
  48:	07e5      	br	0x12	// goto loc_12;
  4a:	0000      	.short	0x0000
  4c:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.__lmac_delay_asm:

00000000 <__lmac_delay_asm>: // arg_bytes: 4
loc_0:
   0:	c4201020 	decgt	r0, r0, 1
   4:	e860fffe 	bt	0x0	// if (T) goto loc_0;
   8:	783c      	jmp	r15	// return;

Disassembly of section .text.lmac_delay_us:

00000000 <lmac_delay_us>: // arg_bytes: 4
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	e0000000 	bsr	0x0	// <sys_get_sysclk>; regs: r0=<ret sys_get_sysclk@0x4>, r1=<clobbered>
   8:	106e      	lrw	r3, 0xf423f	// regs: r3=0xf423f
   a:	640d      	cmplt	r3, r0
   c:	ea04f424 	movi	r4, 62500	// regs: r4=0xf424
  10:	c4844904 	rotli	r4, r4, 4	// regs: r4=rotl(0xf424, 0x4)
  14:	0810      	bt	0x34	// if (T) goto loc_34;
  16:	e0000000 	bsr	0x0	// <sys_get_sysclk>; regs: r0=<ret sys_get_sysclk@0x16>, r1=<clobbered>
  1a:	7c14      	mult	r0, r5	// regs: r0=(<ret sys_get_sysclk@0x16> * <arg0>)
  1c:	c4808020 	divu	r0, r0, r4	// regs: r0=((<ret sys_get_sysclk@0x16> * <arg0>) / rotl(0xf424, 0x4))
loc_20:
  20:	eb00002f 	cmphsi	r0, 48
  24:	0c07      	bf	0x32	// if (r0 < 0x30) goto loc_32;
  26:	282e      	subi	r0, 47	// regs: r0=(r0 - 0x2f)
  28:	3303      	movi	r3, 3	// regs: r3=0x3
  2a:	c4608020 	divu	r0, r0, r3	// regs: r0=((r0 - 0x2f) / 0x3)
  2e:	e0000000 	bsr	0x0	// <__lmac_delay_asm> // arg_bytes: 4; regs: r0=<ret __lmac_delay_asm@0x2e>, r1=<clobbered>
loc_32:
  32:	1492      	pop	r4-r5, r15
loc_34:
  34:	e0000000 	bsr	0x0	// <sys_get_sysclk>; regs: r0=<ret sys_get_sysclk@0x34>, r1=<clobbered>
  38:	c4808040 	divs	r0, r0, r4	// regs: r0=(<ret sys_get_sysclk@0x34> / rotl(0xf424, 0x4))
  3c:	7c14      	mult	r0, r5	// regs: r0=((<ret sys_get_sysclk@0x34> / rotl(0xf424, 0x4)) * <arg0>)
  3e:	07f1      	br	0x20	// goto loc_20;
  40:	423f      	.short	0x423f
  42:	000f      	.short	0x000f

Disassembly of section .text.hgics_print_hex:

00000000 <hgics_print_hex>: // arg_bytes: 8
   0:	14d6      	push	r4-r9, r15
   2:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   4:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   6:	3400      	movi	r4, 0	// regs: r4=0x0
   8:	10f1      	lrw	r7, 0x0	// regs: r7=0x0
   a:	ea880012 	lrw	r8, 0x0	// regs: r8=0x0
   e:	ea890012 	lrw	r9, 0x0	// regs: r9=0x0
loc_12:
  12:	6551      	cmplt	r4, r5
  14:	0805      	bt	0x1e	// if (T) goto loc_1e;
  16:	1011      	lrw	r0, 0x0	// regs: r0=0x0
  18:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x18>, r1=<clobbered>
  1c:	1496      	pop	r4-r9, r15
loc_1e:
  1e:	e9640009 	blsz	r4, 0x30
  22:	e464200f 	andi	r3, r4, 15	// regs: r3=(r4 & 0xf)
  26:	e923000c 	bnez	r3, 0x3e	// if (r3 != 0x0) goto loc_3e;
  2a:	6c23      	mov	r0, r8	// regs: r0=0x0
loc_2c:
  2c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2c>, r1=<clobbered>
loc_30:
  30:	d0860021 	ldr.b	r1, (r6, r4 << 0)	// regs: r1=*(<arg0> + (r4 << 0))
  34:	6c27      	mov	r0, r9	// regs: r0=0x0
  36:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x36>, r1=<clobbered>
  3a:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  3c:	07eb      	br	0x12	// goto loc_12;
loc_3e:
  3e:	e4642007 	andi	r3, r4, 7	// regs: r3=(r4 & 0x7)
  42:	e923fff7 	bnez	r3, 0x30	// if (r3 != 0x0) goto loc_30;
  46:	6c1f      	mov	r0, r7	// regs: r0=0x0
  48:	07f2      	br	0x2c	// goto loc_2c;
  4a:	0000      	.short	0x0000
  4c:	00000000 	.long	0x00000000	// <.rodata.hgics_print_hex.str1.1+0x3>
  50:	00000000 	.long	0x00000000	// <.rodata.hgics_print_hex.str1.1>
  54:	00000000 	.long	0x00000000	// <.rodata.hgics_print_hex.str1.1+0x6>
  58:	00000000 	.long	0x00000000	// <.rodata.hgics_print_hex.str1.1+0xc>

Disassembly of section .text.hgics_print_char:

00000000 <hgics_print_char>: // arg_bytes: 8
   0:	14d5      	push	r4-r8, r15
   2:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   4:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   6:	3400      	movi	r4, 0	// regs: r4=0x0
   8:	10ed      	lrw	r7, 0x0	// regs: r7=0x0
   a:	ea88000e 	lrw	r8, 0x0	// regs: r8=0x0
loc_e:
   e:	6551      	cmplt	r4, r5
  10:	0805      	bt	0x1a	// if (T) goto loc_1a;
  12:	100d      	lrw	r0, 0x0	// regs: r0=0x0
  14:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x14>, r1=<clobbered>
  18:	1495      	pop	r4-r8, r15
loc_1a:
  1a:	e9640009 	blsz	r4, 0x2c
  1e:	e464201f 	andi	r3, r4, 31	// regs: r3=(r4 & 0x1f)
  22:	e9230005 	bnez	r3, 0x2c	// if (r3 != 0x0) goto loc_2c;
  26:	6c1f      	mov	r0, r7	// regs: r0=0x0
  28:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x28>, r1=<clobbered>
loc_2c:
  2c:	d0860021 	ldr.b	r1, (r6, r4 << 0)	// regs: r1=*(<arg0> + (r4 << 0))
  30:	6c23      	mov	r0, r8	// regs: r0=0x0
  32:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x32>, r1=<clobbered>
  36:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  38:	07eb      	br	0xe	// goto loc_e;
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.hgics_print_hex.str1.1>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.rodata.hgics_print_char.str1.1>
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <.rodata.hgics_print_hex.str1.1+0xc>
  46:	0000      	.short	0x0000

Disassembly of section .text.lmac_hw_init:

00000000 <lmac_hw_init>: // arg_bytes: 8
   0:	14d4      	push	r4-r7, r15
   2:	12ca      	lrw	r6, 0x0	// regs: r6=0x0
   4:	6dc7      	mov	r7, r1	// regs: r7=<arg1>
   6:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   8:	e0000000 	bsr	0x0	// <lhw_irq_init>; regs: r0=<ret lhw_irq_init@0x8>, r1=<clobbered>
   c:	9660      	ld.w	r3, (r6, 0x0)	// regs: r3=*(0x0)
   e:	3500      	movi	r5, 0	// regs: r5=0x0
  10:	b3b3      	st.w	r5, (r3, 0x4c)	// *((*(0x0) + 0x4c)) = 0x0
  12:	9344      	ld.w	r2, (r3, 0x10)	// regs: r2=*((*(0x0) + 0x10))
  14:	b34f      	st.w	r2, (r3, 0x3c)	// *((*(0x0) + 0x3c)) = *((*(0x0) + 0x10))
  16:	9350      	ld.w	r2, (r3, 0x40)	// regs: r2=*((*(0x0) + 0x40))
  18:	3a84      	bclri	r2, 4	// regs: r2=(*((*(0x0) + 0x40)) & ~(0x1 << 0x4))
  1a:	3a85      	bclri	r2, 5	// regs: r2=((*((*(0x0) + 0x40)) & ~(0x1 << 0x4)) & ~(0x1 << 0x5))
  1c:	b350      	st.w	r2, (r3, 0x40)	// *((*(0x0) + 0x40)) = ((*((*(0x0) + 0x40)) & ~(0x1 << 0x4)) & ~(0x1 << 0x5))
  1e:	4484      	lsli	r4, r4, 4	// regs: r4=(<arg0> << 0x4)
  20:	9310      	ld.w	r0, (r3, 0x40)	// regs: r0=*((*(0x0) + 0x40))
  22:	e4842030 	andi	r4, r4, 48	// regs: r4=((<arg0> << 0x4) & 0x30)
  26:	6d00      	or	r4, r0	// regs: r4=(((<arg0> << 0x4) & 0x30) | *((*(0x0) + 0x40)))
  28:	b390      	st.w	r4, (r3, 0x40)	// *((*(0x0) + 0x40)) = (((<arg0> << 0x4) & 0x30) | *((*(0x0) + 0x40)))
  2a:	3100      	movi	r1, 0	// regs: r1=0x0
  2c:	d843203f 	ld.w	r2, (r3, 0xfc)	// regs: r2=*((*(0x0) + 0xfc))
  30:	2907      	subi	r1, 8	// regs: r1=0xfffffff8
  32:	6884      	and	r2, r1	// regs: r2=(*((*(0x0) + 0xfc)) & 0xfffffff8)
  34:	dc43203f 	st.w	r2, (r3, 0xfc)	// *((*(0x0) + 0xfc)) = (*((*(0x0) + 0xfc)) & 0xfffffff8)
  38:	d843203f 	ld.w	r2, (r3, 0xfc)	// regs: r2=*((*(0x0) + 0xfc))
  3c:	e4272007 	andi	r1, r7, 7	// regs: r1=(<arg1> & 0x7)
  40:	6c48      	or	r1, r2	// regs: r1=((<arg1> & 0x7) | *((*(0x0) + 0xfc)))
  42:	dc23203f 	st.w	r1, (r3, 0xfc)	// *((*(0x0) + 0xfc)) = ((<arg1> & 0x7) | *((*(0x0) + 0xfc)))
  46:	6c17      	mov	r0, r5	// regs: r0=0x0
  48:	3315      	movi	r3, 21	// regs: r3=0x15
  4a:	3210      	movi	r2, 16	// regs: r2=0x10
  4c:	310b      	movi	r1, 11	// regs: r1=0xb
  4e:	e0000000 	bsr	0x0	// <lhw_cfg_tx_delay_before>; regs: r0=<ret lhw_cfg_tx_delay_before@0x4e>, r1=<clobbered>
  52:	3329      	movi	r3, 41	// regs: r3=0x29
  54:	6c8f      	mov	r2, r3	// regs: r2=0x29
  56:	6c4f      	mov	r1, r3	// regs: r1=0x29
  58:	6c0f      	mov	r0, r3	// regs: r0=0x29
  5a:	e0000000 	bsr	0x0	// <lhw_cfg_tx_delay_after>; regs: r0=<ret lhw_cfg_tx_delay_after@0x5a>, r1=<clobbered>
  5e:	6c57      	mov	r1, r5	// regs: r1=0x0
  60:	320a      	movi	r2, 10	// regs: r2=0xa
  62:	3082      	movi	r0, 130	// regs: r0=0x82
  64:	e0000000 	bsr	0x0	// <lhw_cfg_sifs>; regs: r0=<ret lhw_cfg_sifs@0x64>, r1=<clobbered>
  68:	3202      	movi	r2, 2	// regs: r2=0x2
  6a:	3101      	movi	r1, 1	// regs: r1=0x1
  6c:	6c17      	mov	r0, r5	// regs: r0=0x0
  6e:	e0000000 	bsr	0x0	// <lhw_cfg_tx_dalay_dac_rf>; regs: r0=<ret lhw_cfg_tx_dalay_dac_rf@0x6e>, r1=<clobbered>
  72:	3012      	movi	r0, 18	// regs: r0=0x12
  74:	e0000000 	bsr	0x0	// <lhw_cfg_tx_delay_pa>; regs: r0=<ret lhw_cfg_tx_delay_pa@0x74>, r1=<clobbered>
  78:	9660      	ld.w	r3, (r6, 0x0)	// regs: r3=*(0x0)
  7a:	3100      	movi	r1, 0	// regs: r1=0x0
  7c:	9350      	ld.w	r2, (r3, 0x40)	// regs: r2=*((*(0x0) + 0x40))
  7e:	ec421000 	ori	r2, r2, 4096	// regs: r2=(*((*(0x0) + 0x40)) | 0x1000)
  82:	b350      	st.w	r2, (r3, 0x40)	// *((*(0x0) + 0x40)) = (*((*(0x0) + 0x40)) | 0x1000)
  84:	9350      	ld.w	r2, (r3, 0x40)	// regs: r2=*((*(0x0) + 0x40))
  86:	3a8d      	bclri	r2, 13	// regs: r2=(*((*(0x0) + 0x40)) & ~(0x1 << 0xd))
  88:	b350      	st.w	r2, (r3, 0x40)	// *((*(0x0) + 0x40)) = (*((*(0x0) + 0x40)) & ~(0x1 << 0xd))
  8a:	9350      	ld.w	r2, (r3, 0x40)	// regs: r2=*((*(0x0) + 0x40))
  8c:	3a8e      	bclri	r2, 14	// regs: r2=(*((*(0x0) + 0x40)) & ~(0x1 << 0xe))
  8e:	b350      	st.w	r2, (r3, 0x40)	// *((*(0x0) + 0x40)) = (*((*(0x0) + 0x40)) & ~(0x1 << 0xe))
  90:	9350      	ld.w	r2, (r3, 0x40)	// regs: r2=*((*(0x0) + 0x40))
  92:	3a8f      	bclri	r2, 15	// regs: r2=(*((*(0x0) + 0x40)) & ~(0x1 << 0xf))
  94:	b350      	st.w	r2, (r3, 0x40)	// *((*(0x0) + 0x40)) = (*((*(0x0) + 0x40)) & ~(0x1 << 0xf))
  96:	9350      	ld.w	r2, (r3, 0x40)	// regs: r2=*((*(0x0) + 0x40))
  98:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0x40)) & ~(0x1 << 0x0))
  9a:	b350      	st.w	r2, (r3, 0x40)	// *((*(0x0) + 0x40)) = (*((*(0x0) + 0x40)) & ~(0x1 << 0x0))
  9c:	9350      	ld.w	r2, (r3, 0x40)	// regs: r2=*((*(0x0) + 0x40))
  9e:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0x40)) & ~(0x1 << 0x0))
  a0:	b350      	st.w	r2, (r3, 0x40)	// *((*(0x0) + 0x40)) = (*((*(0x0) + 0x40)) & ~(0x1 << 0x0))
  a2:	9350      	ld.w	r2, (r3, 0x40)	// regs: r2=*((*(0x0) + 0x40))
  a4:	3ab2      	bseti	r2, 18	// regs: r2=(*((*(0x0) + 0x40)) | (0x1 << 0x12))
  a6:	b350      	st.w	r2, (r3, 0x40)	// *((*(0x0) + 0x40)) = (*((*(0x0) + 0x40)) | (0x1 << 0x12))
  a8:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
  aa:	3a8d      	bclri	r2, 13	// regs: r2=(*((*(0x0) + 0x30)) & ~(0x1 << 0xd))
  ac:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) & ~(0x1 << 0xd))
  ae:	935e      	ld.w	r2, (r3, 0x78)	// regs: r2=*((*(0x0) + 0x78))
  b0:	c40256e2 	zext	r2, r2, 23, 0	// regs: r2=zext(*((*(0x0) + 0x78)))
  b4:	b35e      	st.w	r2, (r3, 0x78)	// *((*(0x0) + 0x78)) = zext(*((*(0x0) + 0x78)))
  b6:	935e      	ld.w	r2, (r3, 0x78)	// regs: r2=*((*(0x0) + 0x78))
  b8:	3ab8      	bseti	r2, 24	// regs: r2=(*((*(0x0) + 0x78)) | (0x1 << 0x18))
  ba:	3ab9      	bseti	r2, 25	// regs: r2=((*((*(0x0) + 0x78)) | (0x1 << 0x18)) | (0x1 << 0x19))
  bc:	b35e      	st.w	r2, (r3, 0x78)	// *((*(0x0) + 0x78)) = ((*((*(0x0) + 0x78)) | (0x1 << 0x18)) | (0x1 << 0x19))
  be:	d843203e 	ld.w	r2, (r3, 0xf8)	// regs: r2=*((*(0x0) + 0xf8))
  c2:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0xf8)) & ~(0x1 << 0x0))
  c4:	dc43203e 	st.w	r2, (r3, 0xf8)	// *((*(0x0) + 0xf8)) = (*((*(0x0) + 0xf8)) & ~(0x1 << 0x0))
  c8:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  ca:	29f0      	subi	r1, 241	// regs: r1=0xffffff0f
  cc:	6884      	and	r2, r1	// regs: r2=(*((*(0x0) + 0x58)) & 0xffffff0f)
  ce:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = (*((*(0x0) + 0x58)) & 0xffffff0f)
  d0:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*((*(0x0) + 0x58))
  d2:	b356      	st.w	r2, (r3, 0x58)	// *((*(0x0) + 0x58)) = *((*(0x0) + 0x58))
  d4:	ea224e79 	movih	r2, 20089	// regs: r2=(0x4e79 << 0x10)
  d8:	3aa0      	bseti	r2, 0	// regs: r2=((0x4e79 << 0x10) | (0x1 << 0x0))
  da:	dc432020 	st.w	r2, (r3, 0x80)	// *((*(0x0) + 0x80)) = ((0x4e79 << 0x10) | (0x1 << 0x0))
  de:	d8432028 	ld.w	r2, (r3, 0xa0)	// regs: r2=*((*(0x0) + 0xa0))
  e2:	3a80      	bclri	r2, 0	// regs: r2=(*((*(0x0) + 0xa0)) & ~(0x1 << 0x0))
  e4:	3a81      	bclri	r2, 1	// regs: r2=((*((*(0x0) + 0xa0)) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
  e6:	dc432028 	st.w	r2, (r3, 0xa0)	// *((*(0x0) + 0xa0)) = ((*((*(0x0) + 0xa0)) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
  ea:	300b      	movi	r0, 11	// regs: r0=0xb
  ec:	e0000000 	bsr	0x0	// <lhw_cfg_phy_rx_delay>; regs: r0=<ret lhw_cfg_phy_rx_delay@0xec>, r1=<clobbered>
  f0:	9660      	ld.w	r3, (r6, 0x0)	// regs: r3=*(0x0)
  f2:	3107      	movi	r1, 7	// regs: r1=0x7
  f4:	d8432100 	ld.w	r2, (r3, 0x400)	// regs: r2=*((*(0x0) + 0x400))
  f8:	3a82      	bclri	r2, 2	// regs: r2=(*((*(0x0) + 0x400)) & ~(0x1 << 0x2))
  fa:	3a83      	bclri	r2, 3	// regs: r2=((*((*(0x0) + 0x400)) & ~(0x1 << 0x2)) & ~(0x1 << 0x3))
  fc:	dc432100 	st.w	r2, (r3, 0x400)	// *((*(0x0) + 0x400)) = ((*((*(0x0) + 0x400)) & ~(0x1 << 0x2)) & ~(0x1 << 0x3))
 100:	d8432100 	ld.w	r2, (r3, 0x400)	// regs: r2=*((*(0x0) + 0x400))
 104:	ec42000c 	ori	r2, r2, 12	// regs: r2=(*((*(0x0) + 0x400)) | 0xc)
 108:	dc432100 	st.w	r2, (r3, 0x400)	// *((*(0x0) + 0x400)) = (*((*(0x0) + 0x400)) | 0xc)
 10c:	302f      	movi	r0, 47	// regs: r0=0x2f
 10e:	b3a8      	st.w	r5, (r3, 0x20)	// *((*(0x0) + 0x20)) = 0x0
 110:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x110>, r1=<clobbered>
 114:	3107      	movi	r1, 7	// regs: r1=0x7
 116:	3030      	movi	r0, 48	// regs: r0=0x30
 118:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x118>, r1=<clobbered>
 11c:	3107      	movi	r1, 7	// regs: r1=0x7
 11e:	3031      	movi	r0, 49	// regs: r0=0x31
 120:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x120>, r1=<clobbered>
 124:	6c17      	mov	r0, r5	// regs: r0=0x0
 126:	1494      	pop	r4-r7, r15
 128:	00000000 	.long	0x00000000	// <LMAC>

Disassembly of section .text.lmac_wait_bgscan:

00000000 <lmac_wait_bgscan>: // arg_bytes: 4
   0:	e9000017 	bez	r0, 0x2e	// if (r0 == 0x0) goto loc_2e;
   4:	106b      	lrw	r3, 0x0	// regs: r3=0x0
   6:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   8:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
   a:	3a87      	bclri	r2, 7	// regs: r2=(*((*(0x0) + 0x44)) & ~(0x1 << 0x7))
   c:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) & ~(0x1 << 0x7))
   e:	3280      	movi	r2, 128	// regs: r2=0x80
  10:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x80
  12:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  14:	3a8a      	bclri	r2, 10	// regs: r2=(*((*(0x0) + 0x44)) & ~(0x1 << 0xa))
  16:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) & ~(0x1 << 0xa))
  18:	3280      	movi	r2, 128	// regs: r2=0x80
  1a:	4243      	lsli	r2, r2, 3	// regs: r2=0x400
  1c:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x400
  1e:	dc032031 	st.w	r0, (r3, 0xc4)	// *((*(0x0) + 0xc4)) = <arg0>
  22:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
  26:	ec420004 	ori	r2, r2, 4	// regs: r2=(*((*(0x0) + 0xcc)) | 0x4)
  2a:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x4)
loc_2e:
  2e:	783c      	jmp	r15	// return;
  30:	00000000 	.long	0x00000000	// <LMAC>

Disassembly of section .text.lmac_wait_sync:

00000000 <lmac_wait_sync>: // arg_bytes: 4
   0:	1075      	lrw	r3, 0x0	// regs: r3=0x0
   2:	d843034a 	ld.b	r2, (r3, 0x34a)	// regs: r2=*(0x34a)
   6:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(0x34a) & 0x1)
   a:	e9020004 	bez	r2, 0x12	// if (r2 == 0x0) goto loc_12;
   e:	e400013f 	addi	r0, r0, 320	// regs: r0=(<arg0> + 0x140)
loc_12:
  12:	d84311ee 	ld.h	r2, (r3, 0x3dc)	// regs: r2=*(0x3dc)
  16:	6008      	addu	r0, r2	// regs: r0=(r0 + *(0x3dc))
  18:	e900001c 	bez	r0, 0x50	// if (r0 == 0x0) goto loc_50;
  1c:	d84309dc 	ld.b	r2, (r3, 0x9dc)	// regs: r2=*(0x9dc)
  20:	3101      	movi	r1, 1	// regs: r1=0x1
  22:	c4415c07 	ins	r2, r1, 7, 7
  26:	dc4309dc 	st.b	r2, (r3, 0x9dc)	// *(0x9dc) = *(0x9dc)
  2a:	106c      	lrw	r3, 0x0	// regs: r3=0x0
  2c:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  2e:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  30:	ec420100 	ori	r2, r2, 256	// regs: r2=(*((*(0x0) + 0x44)) | 0x100)
  34:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x100)
  36:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  38:	3a87      	bclri	r2, 7	// regs: r2=(*((*(0x0) + 0x44)) & ~(0x1 << 0x7))
  3a:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) & ~(0x1 << 0x7))
  3c:	3280      	movi	r2, 128	// regs: r2=0x80
  3e:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x80
  40:	dc032031 	st.w	r0, (r3, 0xc4)	// *((*(0x0) + 0xc4)) = (r0 + *(0x3dc))
  44:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
  48:	ec420004 	ori	r2, r2, 4	// regs: r2=(*((*(0x0) + 0xcc)) | 0x4)
  4c:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x4)
loc_50:
  50:	306c      	movi	r0, 108	// regs: r0=0x6c
  52:	783c      	jmp	r15	// return;
  54:	00000000 	.long	0x00000000	// <ah_lmac>
  58:	00000000 	.long	0x00000000	// <LMAC>

Disassembly of section .text.lmac_cancle_tx_tmo:

00000000 <lmac_cancle_tx_tmo>: // arg_bytes: 0
   0:	1069      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   4:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
   8:	ec420008 	ori	r2, r2, 8	// regs: r2=(*((*(0x0) + 0xcc)) | 0x8)
   c:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x8)
  10:	3280      	movi	r2, 128	// regs: r2=0x80
  12:	4247      	lsli	r2, r2, 7	// regs: r2=0x4000
  14:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x4000
  16:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  18:	3a88      	bclri	r2, 8	// regs: r2=(*((*(0x0) + 0x44)) & ~(0x1 << 0x8))
  1a:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) & ~(0x1 << 0x8))
  1c:	3280      	movi	r2, 128	// regs: r2=0x80
  1e:	4241      	lsli	r2, r2, 1	// regs: r2=0x100
  20:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x100
  22:	783c      	jmp	r15	// return;
  24:	0000      	.short	0x0000	// <LMAC>
  26:	0000      	.short	0x0000

Disassembly of section .text.calc_max_agg_bytes:

00000000 <calc_max_agg_bytes>: // arg_bytes: 8
   0:	2000      	addi	r0, 1	// regs: r0=(<arg0> + 0x1)
   2:	e4002003 	andi	r0, r0, 3	// regs: r0=((<arg0> + 0x1) & 0x3)
   6:	4122      	lsli	r1, r1, 2	// regs: r1=(<arg1> << 0x2)
   8:	6040      	addu	r1, r0	// regs: r1=((<arg1> << 0x2) + ((<arg0> + 0x1) & 0x3))
   a:	1063      	lrw	r3, 0x0	// regs: r3=0x0
   c:	d0230880 	ldr.w	r0, (r3, r1 << 2)	// regs: r0=*(0x0 + (((<arg1> << 0x2) + ((<arg0> + 0x1) & 0x3)) << 2))
  10:	2803      	subi	r0, 4	// regs: r0=(*(0x0 + (((<arg1> << 0x2) + ((<arg0> + 0x1) & 0x3)) << 2)) - 0x4)
  12:	783c      	jmp	r15	// return;
  14:	00000000 	.long	0x00000000	// <.data.max_byte_table>

Disassembly of section .text.calc_symbol_len:

00000000 <calc_symbol_len>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	3943      	cmpnei	r1, 3
   6:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   8:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   a:	6ccb      	mov	r3, r2	// regs: r3=<arg2>
   c:	0c09      	bf	0x1e	// if (r1 == 0x3) goto loc_1e;
   e:	3a07      	cmphsi	r2, 8
  10:	0c07      	bf	0x1e	// if (r2 < 0x8) goto loc_1e;
  12:	1123      	lrw	r1, 0x0	// regs: r1=0x0
  14:	1103      	lrw	r0, 0x0	// regs: r0=0x0
  16:	b841      	st.w	r2, (r14, 0x4)	// local_4 = <arg2>
  18:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x18>, r1=<clobbered>
  1c:	9861      	ld.w	r3, (r14, 0x4)	// regs: r3=local_4
loc_1e:
  1e:	5c22      	addi	r1, r4, 1	// regs: r1=(<arg1> + 0x1)
  20:	e4212003 	andi	r1, r1, 3	// regs: r1=((<arg1> + 0x1) & 0x3)
  24:	4342      	lsli	r2, r3, 2	// regs: r2=(r3 << 0x2)
  26:	6084      	addu	r2, r1	// regs: r2=((r3 << 0x2) + ((<arg1> + 0x1) & 0x3))
  28:	101f      	lrw	r0, 0x0	// regs: r0=0x0
  2a:	d0400444 	ldr.h	r4, (r0, r2 << 1)	// regs: r4=*(0x0 + (((r3 << 0x2) + ((<arg1> + 0x1) & 0x3)) << 1))
  2e:	7511      	zexth	r4, r4	// regs: r4=zext16(*(0x0 + (((r3 << 0x2) + ((<arg1> + 0x1) & 0x3)) << 1)))
  30:	e924000c 	bnez	r4, 0x48	// if (r4 != 0x0) goto loc_48;
  34:	6c8f      	mov	r2, r3	// regs: r2=r3
  36:	3301      	movi	r3, 1	// regs: r3=0x1
  38:	c4234021 	lsl	r1, r3, r1
  3c:	101b      	lrw	r0, 0x0	// regs: r0=0x0
  3e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x3e>, r1=<clobbered>
loc_42:
  42:	6c13      	mov	r0, r4	// regs: r0=r4
  44:	1402      	addi	r14, r14, 8	// regs: r14=((sp - 0x8) + 0x8)
  46:	1492      	pop	r4-r5, r15
loc_48:
  48:	4543      	lsli	r2, r5, 3	// regs: r2=(<arg0> << 0x3)
  4a:	220d      	addi	r2, 14	// regs: r2=((<arg0> << 0x3) + 0xe)
  4c:	c4828020 	divu	r0, r2, r4	// regs: r0=(((<arg0> << 0x3) + 0xe) / zext16(*(0x0 + (((r3 << 0x2) + ((<arg1> + 0x1) & 0x3)) << 1))))
  50:	6f13      	mov	r12, r4	// regs: r12=zext16(*(0x0 + (((r3 << 0x2) + ((<arg1> + 0x1) & 0x3)) << 1)))
  52:	7501      	zexth	r4, r0	// regs: r4=zext16((((<arg0> << 0x3) + 0xe) / zext16(*(0x0 + (((r3 << 0x2) + ((<arg1> + 0x1) & 0x3)) << 1)))))
  54:	7c30      	mult	r0, r12	// regs: r0=((((<arg0> << 0x3) + 0xe) / zext16(*(0x0 + (((r3 << 0x2) + ((<arg1> + 0x1) & 0x3)) << 1)))) * zext16(*(0x0 + (((r3 << 0x2) + ((<arg1> + 0x1) & 0x3)) << 1))))
  56:	6082      	subu	r2, r0	// regs: r2=(((<arg0> << 0x3) + 0xe) - ((((<arg0> << 0x3) + 0xe) / zext16(*(0x0 + (((r3 << 0x2) + ((<arg1> + 0x1) & 0x3)) << 1)))) * zext16(*(0x0 + (((r3 << 0x2) + ((<arg1> + 0x1) & 0x3)) << 1)))))
  58:	e9020004 	bez	r2, 0x60	// if (r2 == 0x0) goto loc_60;
  5c:	2400      	addi	r4, 1	// regs: r4=(zext16((((<arg0> << 0x3) + 0xe) / zext16(*(0x0 + (((r3 << 0x2) + ((<arg1> + 0x1) & 0x3)) << 1))))) + 0x1)
  5e:	7511      	zexth	r4, r4	// regs: r4=zext16((zext16((((<arg0> << 0x3) + 0xe) / zext16(*(0x0 + (((r3 << 0x2) + ((<arg1> + 0x1) & 0x3)) << 1))))) + 0x1))
loc_60:
  60:	3b07      	cmphsi	r3, 8
  62:	080c      	bt	0x7a	// if (r3 >= 0x8) goto loc_7a;
  64:	eb0401ff 	cmphsi	r4, 512
  68:	0fed      	bf	0x42	// if (r4 < 0x200) goto loc_42;
  6a:	3201      	movi	r2, 1	// regs: r2=0x1
  6c:	7084      	lsl	r2, r1
  6e:	b880      	st.w	r4, (r14, 0x0)	// local_8 = r4
  70:	6c57      	mov	r1, r5	// regs: r1=<arg0>
  72:	100f      	lrw	r0, 0x0	// regs: r0=0x0
loc_74:
  74:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x74>, r1=<clobbered>
  78:	07e5      	br	0x42	// goto loc_42;
loc_7a:
  7a:	3b4a      	cmpnei	r3, 10
  7c:	080a      	bt	0x90	// if (r3 != 0xa) goto loc_90;
  7e:	eb0402ac 	cmphsi	r4, 685
  82:	0fe0      	bf	0x42	// if (r4 < 0x2ad) goto loc_42;
  84:	3201      	movi	r2, 1	// regs: r2=0x1
  86:	7084      	lsl	r2, r1
  88:	b880      	st.w	r4, (r14, 0x0)	// local_8 = r4
  8a:	6c57      	mov	r1, r5	// regs: r1=<arg0>
  8c:	1009      	lrw	r0, 0x0	// regs: r0=0x0
  8e:	07f3      	br	0x74	// goto loc_74;
loc_90:
  90:	6c4f      	mov	r1, r3	// regs: r1=r3
  92:	1009      	lrw	r0, 0x0	// regs: r0=0x0
  94:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x94>, r1=<clobbered>
  98:	07d5      	br	0x42	// goto loc_42;
  9a:	0000      	.short	0x0000
  9c:	00000000 	.long	0x00000000	// <.rodata.__func__.13524>
  a0:	00000000 	.long	0x00000000	// <.rodata.calc_symbol_len.str1.1>
  a4:	00000000 	.long	0x00000000	// <.rodata.ndbps_table>
  a8:	00000000 	.long	0x00000000	// <.rodata.calc_symbol_len.str1.1+0x1b>
  ac:	00000000 	.long	0x00000000	// <.rodata.calc_symbol_len.str1.1+0x61>
  b0:	00000000 	.long	0x00000000	// <.rodata.calc_symbol_len.str1.1+0xb2>
  b4:	00000000 	.long	0x00000000	// <.rodata.calc_symbol_len.str1.1+0xff>

Disassembly of section .text.lmac_get_seq_num:

00000000 <lmac_get_seq_num>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	8061      	ld.b	r3, (r0, 0x1)	// regs: r3=*(<arg0> + 0x1)
   4:	8040      	ld.b	r2, (r0, 0x0)	// regs: r2=*(<arg0>)
   6:	4368      	lsli	r3, r3, 8	// regs: r3=(*(<arg0> + 0x1) << 0x8)
   8:	6cc8      	or	r3, r2	// regs: r3=((*(<arg0> + 0x1) << 0x8) | *(<arg0>))
   a:	e4432003 	andi	r2, r3, 3	// regs: r2=(((*(<arg0> + 0x1) << 0x8) | *(<arg0>)) & 0x3)
   e:	e9220017 	bnez	r2, 0x3c	// if (r2 != 0x0) goto loc_3c;
  12:	c4435462 	zext	r2, r3, 3, 2	// regs: r2=zext(((*(<arg0> + 0x1) << 0x8) | *(<arg0>)))
  16:	3a42      	cmpnei	r2, 2
  18:	0c05      	bf	0x22	// if (r2 == 0x2) goto loc_22;
  1a:	3a43      	cmpnei	r2, 3
  1c:	0c09      	bf	0x2e	// if (r2 == 0x3) goto loc_2e;
  1e:	e922000c 	bnez	r2, 0x36	// if (r2 != 0x0) goto loc_36;
loc_22:
  22:	8076      	ld.b	r3, (r0, 0x16)	// regs: r3=*(<arg0> + 0x16)
  24:	8017      	ld.b	r0, (r0, 0x17)	// regs: r0=*(<arg0> + 0x17)
  26:	4008      	lsli	r0, r0, 8	// regs: r0=(*(<arg0> + 0x17) << 0x8)
  28:	6c0c      	or	r0, r3	// regs: r0=((*(<arg0> + 0x17) << 0x8) | *(<arg0> + 0x16))
  2a:	4804      	lsri	r0, r0, 4	// regs: r0=(((*(<arg0> + 0x17) << 0x8) | *(<arg0> + 0x16)) >> 0x4)
loc_2c:
  2c:	1490      	pop	r15
loc_2e:
  2e:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(((*(<arg0> + 0x1) << 0x8) | *(<arg0>)))
  32:	3b4f      	cmpnei	r3, 15
  34:	0ff7      	bf	0x22	// if (r3 == 0xf) goto loc_22;
loc_36:
  36:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
  3a:	07f9      	br	0x2c	// goto loc_2c;
loc_3c:
  3c:	3a41      	cmpnei	r2, 1
  3e:	0bfc      	bt	0x36	// if (r2 != 0x1) goto loc_36;
  40:	c4435482 	zext	r2, r3, 4, 2	// regs: r2=zext(((*(<arg0> + 0x1) << 0x8) | *(<arg0>)))
  44:	3a41      	cmpnei	r2, 1
  46:	0c0b      	bf	0x5c	// if (r2 == 0x1) goto loc_5c;
  48:	3a40      	cmpnei	r2, 0
  4a:	0c0d      	bf	0x64	// if (r2 == 0x0) goto loc_64;
  4c:	3a42      	cmpnei	r2, 2
  4e:	0ff4      	bf	0x36	// if (r2 == 0x2) goto loc_36;
  50:	3a43      	cmpnei	r2, 3
  52:	0c0b      	bf	0x68	// if (r2 == 0x3) goto loc_68;
  54:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  56:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x56>, r1=<clobbered>
  5a:	07ee      	br	0x36	// goto loc_36;
loc_5c:
  5c:	c4a354e3 	zext	r3, r3, 7, 5	// regs: r3=zext(((*(<arg0> + 0x1) << 0x8) | *(<arg0>)))
  60:	3b01      	cmphsi	r3, 2
  62:	0bea      	bt	0x36	// if (r3 >= 0x2) goto loc_36;
loc_64:
  64:	8805      	ld.h	r0, (r0, 0xa)	// regs: r0=*(<arg0> + 0xa)
  66:	07e3      	br	0x2c	// goto loc_2c;
loc_68:
  68:	8807      	ld.h	r0, (r0, 0xe)	// regs: r0=*(<arg0> + 0xe)
  6a:	07e1      	br	0x2c	// goto loc_2c;
  6c:	00000000 	.long	0x00000000	// <.rodata.lmac_get_seq_num.str1.1>

Disassembly of section .text.lmac_quick_sort_sid:

00000000 <lmac_quick_sort_sid>: // arg_bytes: 8
   0:	14d8      	push	r4-r11, r15
   2:	1423      	subi	r14, r14, 12	// regs: r14=(sp - 0xc)
   4:	ea880044 	lrw	r8, 0x0	// regs: r8=0x0
   8:	12e4      	lrw	r7, 0x0	// regs: r7=0x0
   a:	3300      	movi	r3, 0	// regs: r3=0x0
   c:	6ec3      	mov	r11, r0	// regs: r11=<arg0>
   e:	dc681000 	st.h	r3, (r8, 0x0)	// *(0x0) = 0x0
  12:	af20      	st.h	r1, (r7, 0x0)	// *(0x0) = <arg1>
  14:	3500      	movi	r5, 0	// regs: r5=0x0
loc_16:
  16:	d0a70449 	ldr.h	r9, (r7, r5 << 1)	// regs: r9=*(r7 + (r5 << 1))
  1a:	7665      	zexth	r9, r9	// regs: r9=zext16(*(r7 + (r5 << 1)))
  1c:	e4c91000 	subi	r6, r9, 1	// regs: r6=(zext16(*(r7 + (r5 << 1))) - 0x1)
  20:	d0a81444 	ldr.hs	r4, (r8, r5 << 1)	// regs: r4=*(r8 + (r5 << 1))
  24:	759b      	sexth	r6, r6	// regs: r6=sext16((zext16(*(r7 + (r5 << 1))) - 0x1))
  26:	6591      	cmplt	r4, r6
  28:	b8a0      	st.w	r5, (r14, 0x0)	// stack_0 = r5
  2a:	0c72      	bf	0x10e	// if (!T) goto loc_10e;
  2c:	d08b050c 	ldr.h	r12, (r11, r4 << 3)	// regs: r12=*(r11 + (*(r8 + (r5 << 1)) << 3))
  30:	ea031fff 	movi	r3, 8191	// regs: r3=0x1fff
  34:	c46c202a 	and	r10, r12, r3	// regs: r10=(*(r11 + (*(r8 + (r5 << 1)) << 3)) & 0x1fff)
loc_38:
  38:	4663      	lsli	r3, r6, 3	// regs: r3=(r6 << 0x3)
  3a:	60ec      	addu	r3, r11	// regs: r3=((r6 << 0x3) + r11)
  3c:	0403      	br	0x42	// goto loc_42;
loc_3e:
  3e:	2e00      	subi	r6, 1	// regs: r6=(r6 - 0x1)
  40:	759b      	sexth	r6, r6	// regs: r6=sext16((r6 - 0x1))
loc_42:
  42:	8b40      	ld.h	r2, (r3, 0x0)	// regs: r2=*(r3)
  44:	ea011fff 	movi	r1, 8191	// regs: r1=0x1fff
  48:	6884      	and	r2, r1	// regs: r2=(*(r3) & 0x1fff)
  4a:	6689      	cmplt	r2, r10
  4c:	6f4f      	mov	r13, r3	// regs: r13=r3
  4e:	083d      	bt	0xc8	// if (T) goto loc_c8;
  50:	6591      	cmplt	r4, r6
  52:	2b07      	subi	r3, 8	// regs: r3=(r3 - 0x8)
  54:	0bf5      	bt	0x3e	// if (T) goto loc_3e;
loc_56:
  56:	4443      	lsli	r2, r4, 3	// regs: r2=(r4 << 0x3)
  58:	60ac      	addu	r2, r11	// regs: r2=((r4 << 0x3) + r11)
loc_5a:
  5a:	8a20      	ld.h	r1, (r2, 0x0)	// regs: r1=*(r2)
  5c:	ea001fff 	movi	r0, 8191	// regs: r0=0x1fff
  60:	6840      	and	r1, r0	// regs: r1=(*(r2) & 0x1fff)
  62:	6469      	cmplt	r10, r1
  64:	6ccb      	mov	r3, r2	// regs: r3=r2
  66:	0846      	bt	0xf2	// if (T) goto loc_f2;
  68:	6591      	cmplt	r4, r6
  6a:	2207      	addi	r2, 8	// regs: r2=(r2 + 0x8)
  6c:	0840      	bt	0xec	// if (T) goto loc_ec;
loc_6e:
  6e:	8b40      	ld.h	r2, (r3, 0x0)	// regs: r2=*(r3)
  70:	7511      	zexth	r4, r4	// regs: r4=zext16(r4)
  72:	c44a5d80 	ins	r2, r10, 12, 0
  76:	ab40      	st.h	r2, (r3, 0x0)	// *(r3) = *(r3)
  78:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  7a:	5c62      	addi	r3, r4, 1	// regs: r3=(zext16(r4) + 0x1)
  7c:	d4a80443 	str.h	r3, (r8, r5 << 1)
  80:	d4a70449 	str.h	r9, (r7, r5 << 1)
  84:	9860      	ld.w	r3, (r14, 0x0)	// regs: r3=stack_0
  86:	7557      	sexth	r5, r5	// regs: r5=sext16((r5 + 0x1))
  88:	d4670444 	str.h	r4, (r7, r3 << 1)
  8c:	5d63      	subi	r3, r5, 1	// regs: r3=(sext16((r5 + 0x1)) - 0x1)
  8e:	d0a70442 	ldr.h	r2, (r7, r5 << 1)	// regs: r2=*(r7 + (sext16((r5 + 0x1)) << 1))
  92:	d0a80440 	ldr.h	r0, (r8, r5 << 1)	// regs: r0=*(r8 + (sext16((r5 + 0x1)) << 1))
  96:	d0670441 	ldr.h	r1, (r7, r3 << 1)	// regs: r1=*(r7 + ((sext16((r5 + 0x1)) - 0x1) << 1))
  9a:	d068044c 	ldr.h	r12, (r8, r3 << 1)	// regs: r12=*(r8 + ((sext16((r5 + 0x1)) - 0x1) << 1))
  9e:	7489      	zexth	r2, r2	// regs: r2=zext16(*(r7 + (sext16((r5 + 0x1)) << 1)))
  a0:	7401      	zexth	r0, r0	// regs: r0=zext16(*(r8 + (sext16((r5 + 0x1)) << 1)))
  a2:	7445      	zexth	r1, r1	// regs: r1=zext16(*(r7 + ((sext16((r5 + 0x1)) - 0x1) << 1)))
  a4:	7731      	zexth	r12, r12	// regs: r12=zext16(*(r8 + ((sext16((r5 + 0x1)) - 0x1) << 1)))
  a6:	5a81      	subu	r4, r2, r0	// regs: r4=(zext16(*(r7 + (sext16((r5 + 0x1)) << 1))) - zext16(*(r8 + (sext16((r5 + 0x1)) << 1))))
  a8:	c581008d 	subu	r13, r1, r12	// regs: r13=(zext16(*(r7 + ((sext16((r5 + 0x1)) - 0x1) << 1))) - zext16(*(r8 + ((sext16((r5 + 0x1)) - 0x1) << 1))))
  ac:	6535      	cmplt	r13, r4
  ae:	0c09      	bf	0xc0	// if (!T) goto loc_c0;
  b0:	d4a8044c 	str.h	r12, (r8, r5 << 1)
  b4:	d4a70441 	str.h	r1, (r7, r5 << 1)
  b8:	d4680440 	str.h	r0, (r8, r3 << 1)
  bc:	d4670442 	str.h	r2, (r7, r3 << 1)
loc_c0:
  c0:	e9a5ffab 	bhsz	r5, 0x16	// if (r5 >= 0x0) goto loc_16;
  c4:	1403      	addi	r14, r14, 12	// regs: r14=(sp + 0xc)
  c6:	1498      	pop	r4-r11, r15
loc_c8:
  c8:	6591      	cmplt	r4, r6
  ca:	0fc6      	bf	0x56	// if (!T) goto loc_56;
  cc:	5c62      	addi	r3, r4, 1	// regs: r3=(r4 + 0x1)
  ce:	4403      	lsli	r0, r4, 3	// regs: r0=(r4 << 0x3)
  d0:	74cf      	sexth	r3, r3	// regs: r3=sext16((r4 + 0x1))
  d2:	6c77      	mov	r1, r13	// regs: r1=r3
  d4:	3208      	movi	r2, 8	// regs: r2=0x8
  d6:	602c      	addu	r0, r11	// regs: r0=((r4 << 0x3) + r11)
  d8:	b862      	st.w	r3, (r14, 0x8)	// stack_p8 = sext16((r4 + 0x1))
  da:	ddae2001 	st.w	r13, (r14, 0x4)	// stack_p4 = r3
  de:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xde>, r1=<clobbered>
  e2:	9862      	ld.w	r3, (r14, 0x8)	// regs: r3=stack_p8
  e4:	6d0f      	mov	r4, r3	// regs: r4=stack_p8
  e6:	d9ae2001 	ld.w	r13, (r14, 0x4)	// regs: r13=stack_p4
  ea:	07b6      	br	0x56	// goto loc_56;
loc_ec:
  ec:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  ee:	7513      	sexth	r4, r4	// regs: r4=sext16((r4 + 0x1))
  f0:	07b5      	br	0x5a	// goto loc_5a;
loc_f2:
  f2:	6591      	cmplt	r4, r6
  f4:	0fbd      	bf	0x6e	// if (!T) goto loc_6e;
  f6:	2e00      	subi	r6, 1	// regs: r6=(r6 - 0x1)
  f8:	6c4f      	mov	r1, r3	// regs: r1=r2
  fa:	759b      	sexth	r6, r6	// regs: r6=sext16((r6 - 0x1))
  fc:	3208      	movi	r2, 8	// regs: r2=0x8
  fe:	6c37      	mov	r0, r13	// regs: r0=r13
 100:	b861      	st.w	r3, (r14, 0x4)	// stack_p4 = r2
 102:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x102>, r1=<clobbered>
 106:	6591      	cmplt	r4, r6
 108:	9861      	ld.w	r3, (r14, 0x4)	// regs: r3=stack_p4
 10a:	0b97      	bt	0x38	// if (T) goto loc_38;
 10c:	07b1      	br	0x6e	// goto loc_6e;
loc_10e:
 10e:	2d00      	subi	r5, 1	// regs: r5=(r5 - 0x1)
 110:	7557      	sexth	r5, r5	// regs: r5=sext16((r5 - 0x1))
 112:	07d7      	br	0xc0	// goto loc_c0;
 114:	0000      	.short	0x0000	// <beg_sid>
 116:	0000      	.short	0x0000
 118:	00000000 	.long	0x00000000	// <end_sid>

Disassembly of section .text.lmac_convert_sid2mac:

00000000 <lmac_convert_sid2mac>: // arg_bytes: 0
   0:	3000      	movi	r0, 0	// regs: r0=0x0
   2:	783c      	jmp	r15	// return;

Disassembly of section .text.sid_mac_map_init:

00000000 <sid_mac_map_init>: // arg_bytes: 4
   0:	14c4      	push	r4-r7
   2:	3100      	movi	r1, 0	// regs: r1=0x0
   4:	ea0c0000 	movi	r12, 0	// regs: r12=0x0
   8:	3320      	movi	r3, 32	// regs: r3=0x20
   a:	ea0d0052 	movi	r13, 82	// regs: r13=0x52
   e:	3430      	movi	r4, 48	// regs: r4=0x30
  10:	290e      	subi	r1, 15	// regs: r1=0xfffffff1
  12:	e58c107b 	subi	r12, r12, 124	// regs: r12=0xffffff84
  16:	3544      	movi	r5, 68	// regs: r5=0x44
  18:	3608      	movi	r6, 8	// regs: r6=0x8
loc_1a:
  1a:	8840      	ld.h	r2, (r0, 0x0)	// regs: r2=*(r0)
  1c:	c4435d80 	ins	r2, r3, 12, 0
  20:	ea071fff 	movi	r7, 8191	// regs: r7=0x1fff
  24:	a840      	st.h	r2, (r0, 0x0)	// *(r0) = *(r0)
  26:	689c      	and	r2, r7	// regs: r2=(*(r0) & 0x1fff)
  28:	3a47      	cmpnei	r2, 7
  2a:	0811      	bt	0x4c	// if (r2 != 0x7) goto loc_4c;
  2c:	dda00002 	st.b	r13, (r0, 0x2)	// *(r0 + 0x2) = 0x52
  30:	a083      	st.b	r4, (r0, 0x3)	// *(r0 + 0x3) = 0x30
  32:	a024      	st.b	r1, (r0, 0x4)	// *(r0 + 0x4) = 0xfffffff1
  34:	dd800005 	st.b	r12, (r0, 0x5)	// *(r0 + 0x5) = 0xffffff84
  38:	a0a6      	st.b	r5, (r0, 0x6)	// *(r0 + 0x6) = 0x44
  3a:	a0c7      	st.b	r6, (r0, 0x7)	// *(r0 + 0x7) = 0x8
loc_3c:
  3c:	ea021fff 	movi	r2, 8191	// regs: r2=0x1fff
  40:	60c8      	addu	r3, r2	// regs: r3=(r3 + 0x1fff)
  42:	68c8      	and	r3, r2	// regs: r3=((r3 + 0x1fff) & 0x1fff)
  44:	2007      	addi	r0, 8	// regs: r0=(r0 + 0x8)
  46:	e923ffea 	bnez	r3, 0x1a	// if (r3 != 0x0) goto loc_1a;
  4a:	1484      	pop	r4-r7
loc_4c:
  4c:	748c      	zextb	r2, r3	// regs: r2=zext8(r3)
  4e:	a042      	st.b	r2, (r0, 0x2)	// *(r0 + 0x2) = zext8(r3)
  50:	a043      	st.b	r2, (r0, 0x3)	// *(r0 + 0x3) = zext8(r3)
  52:	a044      	st.b	r2, (r0, 0x4)	// *(r0 + 0x4) = zext8(r3)
  54:	a045      	st.b	r2, (r0, 0x5)	// *(r0 + 0x5) = zext8(r3)
  56:	a046      	st.b	r2, (r0, 0x6)	// *(r0 + 0x6) = zext8(r3)
  58:	a047      	st.b	r2, (r0, 0x7)	// *(r0 + 0x7) = zext8(r3)
  5a:	07f1      	br	0x3c	// goto loc_3c;

Disassembly of section .text.ieee80211_is_data:

00000000 <ieee80211_is_data>: // arg_bytes: 4
   0:	e4602003 	andi	r3, r0, 3	// regs: r3=(<arg0> & 0x3)
   4:	e9230008 	bnez	r3, 0x14	// if (r3 != 0x0) goto loc_14;
   8:	c4405460 	zext	r0, r0, 3, 2	// regs: r0=zext(<arg0>)
   c:	3842      	cmpnei	r0, 2
loc_e:
   e:	6403      	mvcv	r0	// regs: r0=<cond>
  10:	7400      	zextb	r0, r0	// regs: r0=zext8(<cond>)
loc_12:
  12:	783c      	jmp	r15	// return;
loc_14:
  14:	3b41      	cmpnei	r3, 1
  16:	0809      	bt	0x28	// if (r3 != 0x1) goto loc_28;
  18:	c4405480 	zext	r0, r0, 4, 2	// regs: r0=zext(<arg0>)
  1c:	e9000004 	bez	r0, 0x24	// if (r0 == 0x0) goto loc_24;
  20:	3843      	cmpnei	r0, 3
  22:	07f6      	br	0xe	// goto loc_e;
loc_24:
  24:	6c0f      	mov	r0, r3	// regs: r0=(<arg0> & 0x3)
  26:	07f6      	br	0x12	// goto loc_12;
loc_28:
  28:	3000      	movi	r0, 0	// regs: r0=0x0
  2a:	07f4      	br	0x12	// goto loc_12;

Disassembly of section .text.ieee80211_is_data_qos:

00000000 <ieee80211_is_data_qos>: // arg_bytes: 4
   0:	e4602003 	andi	r3, r0, 3	// regs: r3=(<arg0> & 0x3)
   4:	e923000c 	bnez	r3, 0x1c	// if (r3 != 0x0) goto loc_1c;
   8:	c4405462 	zext	r2, r0, 3, 2	// regs: r2=zext(<arg0>)
   c:	3a42      	cmpnei	r2, 2
   e:	080f      	bt	0x2c	// if (r2 != 0x2) goto loc_2c;
  10:	c48054e0 	zext	r0, r0, 7, 4	// regs: r0=zext(<arg0>)
  14:	3848      	cmpnei	r0, 8
loc_16:
  16:	6403      	mvcv	r0	// regs: r0=<cond>
  18:	7400      	zextb	r0, r0	// regs: r0=zext8(<cond>)
loc_1a:
  1a:	783c      	jmp	r15	// return;
loc_1c:
  1c:	3b41      	cmpnei	r3, 1
  1e:	0809      	bt	0x30	// if (r3 != 0x1) goto loc_30;
  20:	c4405480 	zext	r0, r0, 4, 2	// regs: r0=zext(<arg0>)
  24:	e9000004 	bez	r0, 0x2c	// if (r0 == 0x0) goto loc_2c;
  28:	3843      	cmpnei	r0, 3
  2a:	07f6      	br	0x16	// goto loc_16;
loc_2c:
  2c:	6c0f      	mov	r0, r3	// regs: r0=(<arg0> & 0x3)
  2e:	07f6      	br	0x1a	// goto loc_1a;
loc_30:
  30:	3000      	movi	r0, 0	// regs: r0=0x0
  32:	07f4      	br	0x1a	// goto loc_1a;

Disassembly of section .text.ieee80211_get_qos_ctl:

00000000 <ieee80211_get_qos_ctl>: // arg_bytes: 4
   0:	8860      	ld.h	r3, (r0, 0x0)	// regs: r3=*(<arg0>)
   2:	e4432003 	andi	r2, r3, 3	// regs: r2=(*(<arg0>) & 0x3)
   6:	e922000b 	bnez	r2, 0x1c	// if (r2 != 0x0) goto loc_1c;
   a:	8061      	ld.b	r3, (r0, 0x1)	// regs: r3=*(<arg0> + 0x1)
   c:	e4632003 	andi	r3, r3, 3	// regs: r3=(*(<arg0> + 0x1) & 0x3)
  10:	3b43      	cmpnei	r3, 3
  12:	0803      	bt	0x18	// if (r3 != 0x3) goto loc_18;
  14:	880f      	ld.h	r0, (r0, 0x1e)	// regs: r0=*(<arg0> + 0x1e)
loc_16:
  16:	783c      	jmp	r15	// return;
loc_18:
  18:	880c      	ld.h	r0, (r0, 0x18)	// regs: r0=*(<arg0> + 0x18)
  1a:	07fe      	br	0x16	// goto loc_16;
loc_1c:
  1c:	3a41      	cmpnei	r2, 1
  1e:	0821      	bt	0x60	// if (r2 != 0x1) goto loc_60;
  20:	c4435483 	zext	r3, r3, 4, 2	// regs: r3=zext(*(<arg0>))
  24:	e923001a 	bnez	r3, 0x58	// if (r3 != 0x0) goto loc_58;
  28:	8061      	ld.b	r3, (r0, 0x1)	// regs: r3=*(<arg0> + 0x1)
  2a:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(<arg0> + 0x1) & 0x1)
  2e:	e9030013 	bez	r3, 0x54	// if (r3 == 0x0) goto loc_54;
  32:	8043      	ld.b	r2, (r0, 0x3)	// regs: r2=*(<arg0> + 0x3)
loc_34:
  34:	e4622020 	andi	r3, r2, 32	// regs: r3=(r2 & 0x20)
  38:	3b40      	cmpnei	r3, 0
  3a:	3112      	movi	r1, 18	// regs: r1=0x12
  3c:	330c      	movi	r3, 12	// regs: r3=0xc
  3e:	e4422040 	andi	r2, r2, 64	// regs: r2=(r2 & 0x40)
  42:	c4610c40 	inct	r3, r1, 0
  46:	3a40      	cmpnei	r2, 0
  48:	c4630c46 	inct	r3, r3, 6
  4c:	d0600420 	ldr.h	r0, (r0, r3 << 0)	// regs: r0=*(<arg0> + (0xc << 0))
  50:	7401      	zexth	r0, r0	// regs: r0=zext16(*(<arg0> + (0xc << 0)))
  52:	07e2      	br	0x16	// goto loc_16;
loc_54:
  54:	8049      	ld.b	r2, (r0, 0x9)	// regs: r2=*(<arg0> + 0x9)
  56:	07ef      	br	0x34	// goto loc_34;
loc_58:
  58:	3b43      	cmpnei	r3, 3
  5a:	0803      	bt	0x60	// if (r3 != 0x3) goto loc_60;
  5c:	880e      	ld.h	r0, (r0, 0x1c)	// regs: r0=*(<arg0> + 0x1c)
  5e:	07dc      	br	0x16	// goto loc_16;
loc_60:
  60:	3000      	movi	r0, 0	// regs: r0=0x0
  62:	07da      	br	0x16	// goto loc_16;

Disassembly of section .text.lmac_get_tid:

00000000 <lmac_get_tid>: // arg_bytes: 4
   0:	14d3      	push	r4-r6, r15
   2:	88a0      	ld.h	r5, (r0, 0x0)	// regs: r5=*(<arg0>)
   4:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   6:	6c17      	mov	r0, r5	// regs: r0=*(<arg0>)
   8:	e0000000 	bsr	0x0	// <ieee80211_is_data> // arg_bytes: 4; regs: r0=<ret ieee80211_is_data@0x8>, r1=<clobbered>
   c:	e9000019 	bez	r0, 0x3e	// if (r0 == 0x0) goto loc_3e;
  10:	6c17      	mov	r0, r5	// regs: r0=*(<arg0>)
  12:	e0000000 	bsr	0x0	// <ieee80211_is_data_qos> // arg_bytes: 4; regs: r0=<ret ieee80211_is_data_qos@0x12>, r1=<clobbered>
  16:	6d03      	mov	r4, r0	// regs: r4=<ret ieee80211_is_data_qos@0x12>
  18:	e900000b 	bez	r0, 0x2e	// if (r0 == 0x0) goto loc_2e;
  1c:	e4652003 	andi	r3, r5, 3	// regs: r3=(*(<arg0>) & 0x3)
  20:	3b41      	cmpnei	r3, 1
  22:	0808      	bt	0x32	// if (r3 != 0x1) goto loc_32;
  24:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  26:	c4a554e4 	zext	r4, r5, 7, 5	// regs: r4=zext(*(<arg0>))
  2a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2a>, r1=<clobbered>
loc_2e:
  2e:	6c13      	mov	r0, r4	// regs: r0=r4
  30:	1493      	pop	r4-r6, r15
loc_32:
  32:	6c1b      	mov	r0, r6	// regs: r0=<arg0>
  34:	e0000000 	bsr	0x0	// <ieee80211_get_qos_ctl> // arg_bytes: 4; regs: r0=<ret ieee80211_get_qos_ctl@0x34>, r1=<clobbered>
  38:	e480200f 	andi	r4, r0, 15	// regs: r4=(<ret ieee80211_get_qos_ctl@0x34> & 0xf)
  3c:	07f9      	br	0x2e	// goto loc_2e;
loc_3e:
  3e:	3407      	movi	r4, 7	// regs: r4=0x7
  40:	07f7      	br	0x2e	// goto loc_2e;
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <.rodata.lmac_get_tid.str1.1>
  46:	0000      	.short	0x0000

Disassembly of section .text.lmac_get_hdr_len_pv1:

00000000 <lmac_get_hdr_len_pv1>: // arg_bytes: 4
   0:	8840      	ld.h	r2, (r0, 0x0)	// regs: r2=*(<arg0>)
   2:	c4425461 	zext	r1, r2, 3, 2	// regs: r1=zext(*(<arg0>))
   6:	3942      	cmpnei	r1, 2
   8:	0c4e      	bf	0xa4	// if (r1 == 0x2) goto loc_a4;
   a:	3943      	cmpnei	r1, 3
   c:	0c1e      	bf	0x48	// if (r1 == 0x3) goto loc_48;
   e:	3941      	cmpnei	r1, 1
  10:	8061      	ld.b	r3, (r0, 0x1)	// regs: r3=*(<arg0> + 0x1)
  12:	0823      	bt	0x58	// if (r1 != 0x1) goto loc_58;
  14:	c48254e2 	zext	r2, r2, 7, 4	// regs: r2=zext(*(<arg0>))
  18:	3a42      	cmpnei	r2, 2
  1a:	081f      	bt	0x58	// if (r2 != 0x2) goto loc_58;
  1c:	74cc      	zextb	r3, r3	// regs: r3=zext8(*(<arg0> + 0x1))
  1e:	e4432001 	andi	r2, r3, 1	// regs: r2=(zext8(*(<arg0> + 0x1)) & 0x1)
  22:	3a40      	cmpnei	r2, 0
  24:	3016      	movi	r0, 22	// regs: r0=0x16
  26:	3213      	movi	r2, 19	// regs: r2=0x13
  28:	c4020c20 	incf	r0, r2, 0
  2c:	e4432002 	andi	r2, r3, 2	// regs: r2=(zext8(*(<arg0> + 0x1)) & 0x2)
  30:	e4632004 	andi	r3, r3, 4	// regs: r3=(zext8(*(<arg0> + 0x1)) & 0x4)
  34:	3a40      	cmpnei	r2, 0
  36:	c4000c24 	incf	r0, r0, 4
  3a:	e9230044 	bnez	r3, 0xc2	// if (r3 != 0x0) goto loc_c2;
  3e:	2000      	addi	r0, 1	// regs: r0=0x17
  40:	7400      	zextb	r0, r0	// regs: r0=zext8(0x17)
loc_42:
  42:	6c8f      	mov	r2, r3	// regs: r2=r3
  44:	6f4f      	mov	r13, r3	// regs: r13=r3
  46:	0405      	br	0x50	// goto loc_50;
loc_48:
  48:	3002      	movi	r0, 2	// regs: r0=0x2
  4a:	3300      	movi	r3, 0	// regs: r3=0x0
  4c:	6c8f      	mov	r2, r3	// regs: r2=0x0
  4e:	6f43      	mov	r13, r0	// regs: r13=0x2
loc_50:
  50:	ea0c0006 	movi	r12, 6	// regs: r12=0x6
  54:	6c73      	mov	r1, r12	// regs: r1=0x6
  56:	042c      	br	0xae	// goto loc_ae;
loc_58:
  58:	e4432001 	andi	r2, r3, 1	// regs: r2=(*(<arg0> + 0x1) & 0x1)
  5c:	e9020014 	bez	r2, 0x84	// if (r2 == 0x0) goto loc_84;
  60:	8063      	ld.b	r3, (r0, 0x3)	// regs: r3=*(<arg0> + 0x3)
  62:	e4432020 	andi	r2, r3, 32	// regs: r2=(*(<arg0> + 0x3) & 0x20)
  66:	e4632040 	andi	r3, r3, 64	// regs: r3=(*(<arg0> + 0x3) & 0x40)
  6a:	3a40      	cmpnei	r2, 0
  6c:	3106      	movi	r1, 6	// regs: r1=0x6
  6e:	3200      	movi	r2, 0	// regs: r2=0x0
  70:	c4410c40 	inct	r2, r1, 0
  74:	3002      	movi	r0, 2	// regs: r0=0x2
  76:	e9030023 	bez	r3, 0xbc	// if (r3 == 0x0) goto loc_bc;
  7a:	6cc7      	mov	r3, r1	// regs: r3=0x6
  7c:	6f43      	mov	r13, r0	// regs: r13=0x2
  7e:	6f07      	mov	r12, r1	// regs: r12=0x6
loc_80:
  80:	6c43      	mov	r1, r0	// regs: r1=0x2
  82:	0416      	br	0xae	// goto loc_ae;
loc_84:
  84:	8069      	ld.b	r3, (r0, 0x9)	// regs: r3=*(<arg0> + 0x9)
  86:	e4032020 	andi	r0, r3, 32	// regs: r0=(*(<arg0> + 0x9) & 0x20)
  8a:	e4632040 	andi	r3, r3, 64	// regs: r3=(*(<arg0> + 0x9) & 0x40)
  8e:	3840      	cmpnei	r0, 0
  90:	3106      	movi	r1, 6	// regs: r1=0x6
  92:	c4410c40 	inct	r2, r1, 0
  96:	3002      	movi	r0, 2	// regs: r0=0x2
  98:	e9030003 	bez	r3, 0x9e	// if (r3 == 0x0) goto loc_9e;
  9c:	6cc7      	mov	r3, r1	// regs: r3=0x6
loc_9e:
  9e:	6f43      	mov	r13, r0	// regs: r13=0x2
  a0:	6f03      	mov	r12, r0	// regs: r12=0x2
  a2:	0406      	br	0xae	// goto loc_ae;
loc_a4:
  a4:	3300      	movi	r3, 0	// regs: r3=0x0
  a6:	6c07      	mov	r0, r1	// regs: r0=zext(*(<arg0>))
  a8:	6c8f      	mov	r2, r3	// regs: r2=0x0
  aa:	6f4f      	mov	r13, r3	// regs: r13=0x0
  ac:	6f0f      	mov	r12, r3	// regs: r12=0x0
loc_ae:
  ae:	6070      	addu	r1, r12	// regs: r1=(r1 + r12)
  b0:	6074      	addu	r1, r13	// regs: r1=((r1 + r12) + r13)
  b2:	6048      	addu	r1, r2	// regs: r1=(((r1 + r12) + r13) + r2)
  b4:	60c4      	addu	r3, r1	// regs: r3=(r3 + (((r1 + r12) + r13) + r2))
  b6:	600c      	addu	r0, r3	// regs: r0=(r0 + (r3 + (((r1 + r12) + r13) + r2)))
  b8:	7400      	zextb	r0, r0	// regs: r0=zext8((r0 + (r3 + (((r1 + r12) + r13) + r2))))
  ba:	783c      	jmp	r15	// return;
loc_bc:
  bc:	6f43      	mov	r13, r0	// regs: r13=0x2
  be:	6f07      	mov	r12, r1	// regs: r12=0x6
  c0:	07e0      	br	0x80	// goto loc_80;
loc_c2:
  c2:	3300      	movi	r3, 0	// regs: r3=0x0
  c4:	07bf      	br	0x42	// goto loc_42;

Disassembly of section .text.lmac_get_hdr_len_pv0:

00000000 <lmac_get_hdr_len_pv0>: // arg_bytes: 4
   0:	14d5      	push	r4-r8, r15
   2:	6cc3      	mov	r3, r0	// regs: r3=<arg0>
   4:	8800      	ld.h	r0, (r0, 0x0)	// regs: r0=*(<arg0>)
   6:	c4405466 	zext	r6, r0, 3, 2	// regs: r6=zext(*(<arg0>))
   a:	3e42      	cmpnei	r6, 2
   c:	c48054e1 	zext	r1, r0, 7, 4	// regs: r1=zext(*(<arg0>))
  10:	0c46      	bf	0x9c	// if (r6 == 0x2) goto loc_9c;
  12:	3e43      	cmpnei	r6, 3
  14:	0c5a      	bf	0xc8	// if (r6 == 0x3) goto loc_c8;
  16:	3e41      	cmpnei	r6, 1
  18:	0c0b      	bf	0x2e	// if (r6 == 0x1) goto loc_2e;
  1a:	d8634001 	ld.bs	r3, (r3, 0x1)	// regs: r3=*(<arg0> + 0x1)
  1e:	320a      	movi	r2, 10	// regs: r2=0xa
  20:	e9a30077 	bhsz	r3, 0x10e	// if (r3 >= 0x0) goto loc_10e;
  24:	3000      	movi	r0, 0	// regs: r0=0x0
  26:	3304      	movi	r3, 4	// regs: r3=0x4
  28:	6dc3      	mov	r7, r0	// regs: r7=0x0
loc_2a:
  2a:	3602      	movi	r6, 2	// regs: r6=0x2
  2c:	042a      	br	0x80	// goto loc_80;
loc_2e:
  2e:	594b      	subi	r2, r1, 3	// regs: r2=(zext(*(<arg0>)) - 0x3)
  30:	7488      	zextb	r2, r2	// regs: r2=zext8((zext(*(<arg0>)) - 0x3))
  32:	3a0c      	cmphsi	r2, 13
  34:	0829      	bt	0x86	// if (r2 >= 0xd) goto loc_86;
  36:	1003      	lrw	r0, 0x0	// regs: r0=0x0
  38:	d0400882 	ldr.w	r2, (r0, r2 << 2)	// regs: r2=*(0x0 + (zext8((zext(*(<arg0>)) - 0x3)) << 2))
  3c:	7808      	jmp	r2	// goto *r2;
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.rodata.lmac_get_hdr_len_pv0>
  42:	0000      	.short	0x0000
  44:	3300      	movi	r3, 0	// regs: r3=0x0
  46:	320a      	movi	r2, 10	// regs: r2=0xa
  48:	6c0f      	mov	r0, r3	// regs: r0=0x0
  4a:	6dcf      	mov	r7, r3	// regs: r7=0x0
  4c:	6d8f      	mov	r6, r3	// regs: r6=0x0
loc_4e:
  4e:	6c4f      	mov	r1, r3	// regs: r1=0x0
  50:	ea0c0006 	movi	r12, 6	// regs: r12=0x6
loc_54:
  54:	6070      	addu	r1, r12	// regs: r1=(r1 + r12)
  56:	6184      	addu	r6, r1	// regs: r6=(r6 + (r1 + r12))
  58:	619c      	addu	r6, r7	// regs: r6=((r6 + (r1 + r12)) + r7)
  5a:	6018      	addu	r0, r6	// regs: r0=(r0 + ((r6 + (r1 + r12)) + r7))
  5c:	60c0      	addu	r3, r0	// regs: r3=(r3 + (r0 + ((r6 + (r1 + r12)) + r7)))
  5e:	60c8      	addu	r3, r2	// regs: r3=((r3 + (r0 + ((r6 + (r1 + r12)) + r7))) + r2)
  60:	740c      	zextb	r0, r3	// regs: r0=zext8(((r3 + (r0 + ((r6 + (r1 + r12)) + r7))) + r2))
  62:	1495      	pop	r4-r8, r15
  64:	d8634001 	ld.bs	r3, (r3, 0x1)	// regs: r3=*(<arg3> + 0x1)
  68:	e9a3004c 	bhsz	r3, 0x100	// if (r3 >= 0x0) goto loc_100;
  6c:	3215      	movi	r2, 21	// regs: r2=0x15
loc_6e:
  6e:	3300      	movi	r3, 0	// regs: r3=0x0
  70:	6c0f      	mov	r0, r3	// regs: r0=0x0
  72:	6dcf      	mov	r7, r3	// regs: r7=0x0
  74:	07ed      	br	0x4e	// goto loc_4e;
  76:	3300      	movi	r3, 0	// regs: r3=0x0
  78:	320a      	movi	r2, 10	// regs: r2=0xa
  7a:	6c0f      	mov	r0, r3	// regs: r0=0x0
  7c:	6dcf      	mov	r7, r3	// regs: r7=0x0
  7e:	6d8f      	mov	r6, r3	// regs: r6=0x0
loc_80:
  80:	3106      	movi	r1, 6	// regs: r1=0x6
  82:	6f07      	mov	r12, r1	// regs: r12=0x6
  84:	07e8      	br	0x54	// goto loc_54;
loc_86:
  86:	1105      	lrw	r0, 0x0	// regs: r0=0x0
loc_88:
  88:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x88>, r1=<clobbered>
  8c:	3300      	movi	r3, 0	// regs: r3=0x0
  8e:	320a      	movi	r2, 10	// regs: r2=0xa
  90:	6c0f      	mov	r0, r3	// regs: r0=0x0
  92:	6dcf      	mov	r7, r3	// regs: r7=0x0
  94:	6d8f      	mov	r6, r3	// regs: r6=0x0
loc_96:
  96:	6c4f      	mov	r1, r3	// regs: r1=r3
  98:	6f0f      	mov	r12, r3	// regs: r12=r3
  9a:	07dd      	br	0x54	// goto loc_54;
loc_9c:
  9c:	d9030001 	ld.b	r8, (r3, 0x1)	// regs: r8=*(<arg0> + 0x1)
  a0:	c4285423 	zext	r3, r8, 1, 1	// regs: r3=zext(*(<arg0> + 0x1))
  a4:	68e0      	and	r3, r8	// regs: r3=(zext(*(<arg0> + 0x1)) & *(<arg0> + 0x1))
  a6:	3506      	movi	r5, 6	// regs: r5=0x6
  a8:	3b40      	cmpnei	r3, 0
  aa:	3400      	movi	r4, 0	// regs: r4=0x0
  ac:	6dd7      	mov	r7, r5	// regs: r7=0x6
  ae:	c4e40c20 	incf	r7, r4, 0
  b2:	7622      	sextb	r8, r8	// regs: r8=sext8(*(<arg0> + 0x1))
  b4:	e0000000 	bsr	0x0	// <ieee80211_is_data_qos> // arg_bytes: 4; regs: r0=<ret ieee80211_is_data_qos@0xb4>, r1=<clobbered>
  b8:	3840      	cmpnei	r0, 0
  ba:	c4060c40 	inct	r0, r6, 0
  be:	320a      	movi	r2, 10	// regs: r2=0xa
  c0:	e9880022 	blz	r8, 0x104	// if (r8 < 0x0) goto loc_104;
  c4:	6cd3      	mov	r3, r4	// regs: r3=0x0
  c6:	07dd      	br	0x80	// goto loc_80;
loc_c8:
  c8:	3941      	cmpnei	r1, 1
  ca:	0817      	bt	0xf8	// if (r1 != 0x1) goto loc_f8;
  cc:	8321      	ld.b	r1, (r3, 0x1)	// regs: r1=*(<arg0> + 0x1)
  ce:	e4612001 	andi	r3, r1, 1	// regs: r3=(*(<arg0> + 0x1) & 0x1)
  d2:	3b40      	cmpnei	r3, 0
  d4:	3011      	movi	r0, 17	// regs: r0=0x11
  d6:	320e      	movi	r2, 14	// regs: r2=0xe
  d8:	e4212002 	andi	r1, r1, 2	// regs: r1=(*(<arg0> + 0x1) & 0x2)
  dc:	c4400c40 	inct	r2, r0, 0
  e0:	3940      	cmpnei	r1, 0
  e2:	c4420c44 	inct	r2, r2, 4
  e6:	e9030011 	bez	r3, 0x108	// if (r3 == 0x0) goto loc_108;
  ea:	2200      	addi	r2, 1	// regs: r2=0xf
  ec:	7488      	zextb	r2, r2	// regs: r2=zext8(0xf)
  ee:	3601      	movi	r6, 1	// regs: r6=0x1
  f0:	3300      	movi	r3, 0	// regs: r3=0x0
loc_f2:
  f2:	6c0f      	mov	r0, r3	// regs: r0=r3
  f4:	6dcf      	mov	r7, r3	// regs: r7=r3
  f6:	07d0      	br	0x96	// goto loc_96;
loc_f8:
  f8:	394f      	cmpnei	r1, 15
  fa:	0c09      	bf	0x10c	// if (r1 == 0xf) goto loc_10c;
  fc:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  fe:	07c5      	br	0x88	// goto loc_88;
loc_100:
 100:	320f      	movi	r2, 15	// regs: r2=0xf
 102:	07b6      	br	0x6e	// goto loc_6e;
loc_104:
 104:	3304      	movi	r3, 4	// regs: r3=0x4
 106:	07bd      	br	0x80	// goto loc_80;
loc_108:
 108:	3601      	movi	r6, 1	// regs: r6=0x1
 10a:	07f4      	br	0xf2	// goto loc_f2;
loc_10c:
 10c:	320a      	movi	r2, 10	// regs: r2=0xa
loc_10e:
 10e:	3300      	movi	r3, 0	// regs: r3=0x0
 110:	6c0f      	mov	r0, r3	// regs: r0=0x0
 112:	6dcf      	mov	r7, r3	// regs: r7=0x0
 114:	078b      	br	0x2a	// goto loc_2a;
 116:	0000      	.short	0x0000
 118:	00000000 	.long	0x00000000	// <.rodata.lmac_get_hdr_len_pv0.str1.1>
 11c:	00000000 	.long	0x00000000	// <.rodata.lmac_get_hdr_len_pv0.str1.1+0x35>

Disassembly of section .text.lmac_get_tx_addr:

00000000 <lmac_get_tx_addr>: // arg_bytes: 8
   0:	14d1      	push	r4, r15
   2:	8141      	ld.b	r2, (r1, 0x1)	// regs: r2=*(<arg1> + 0x1)
   4:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   6:	4268      	lsli	r3, r2, 8	// regs: r3=(*(<arg1> + 0x1) << 0x8)
   8:	8120      	ld.b	r1, (r1, 0x0)	// regs: r1=*(<arg1>)
   a:	6cc4      	or	r3, r1	// regs: r3=((*(<arg1> + 0x1) << 0x8) | *(<arg1>))
   c:	e4232003 	andi	r1, r3, 3	// regs: r1=(((*(<arg1> + 0x1) << 0x8) | *(<arg1>)) & 0x3)
  10:	6f03      	mov	r12, r0	// regs: r12=<arg0>
  12:	e921001b 	bnez	r1, 0x48	// if (r1 != 0x0) goto loc_48;
  16:	c4435462 	zext	r2, r3, 3, 2	// regs: r2=zext(((*(<arg1> + 0x1) << 0x8) | *(<arg1>)))
  1a:	3a41      	cmpnei	r2, 1
  1c:	0c03      	bf	0x22	// if (r2 == 0x1) goto loc_22;
  1e:	3a43      	cmpnei	r2, 3
  20:	0c05      	bf	0x2a	// if (r2 == 0x3) goto loc_2a;
loc_22:
  22:	3206      	movi	r2, 6	// regs: r2=0x6
  24:	e4240009 	addi	r1, r4, 10	// regs: r1=(<arg1> + 0xa)
  28:	0408      	br	0x38	// goto loc_38;
loc_2a:
  2a:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(((*(<arg1> + 0x1) << 0x8) | *(<arg1>)))
  2e:	3b41      	cmpnei	r3, 1
  30:	0807      	bt	0x3e	// if (r3 != 0x1) goto loc_3e;
loc_32:
  32:	3206      	movi	r2, 6	// regs: r2=0x6
  34:	5c2e      	addi	r1, r4, 4	// regs: r1=(<arg1> + 0x4)
  36:	6c33      	mov	r0, r12	// regs: r0=<arg0>
loc_38:
  38:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x38>, r1=<clobbered>
  3c:	0405      	br	0x46	// goto loc_46;
loc_3e:
  3e:	3b4f      	cmpnei	r3, 15
  40:	0ff1      	bf	0x22	// if (r3 == 0xf) goto loc_22;
  42:	3301      	movi	r3, 1	// regs: r3=0x1
  44:	a060      	st.b	r3, (r0, 0x0)	// *(<arg0>) = 0x1
loc_46:
  46:	1491      	pop	r4, r15
loc_48:
  48:	3941      	cmpnei	r1, 1
  4a:	0815      	bt	0x74	// if (r1 != 0x1) goto loc_74;
  4c:	c4435483 	zext	r3, r3, 4, 2	// regs: r3=zext(((*(<arg1> + 0x1) << 0x8) | *(<arg1>)))
  50:	3b41      	cmpnei	r3, 1
  52:	0c0e      	bf	0x6e	// if (r3 == 0x1) goto loc_6e;
  54:	3b43      	cmpnei	r3, 3
  56:	0c0c      	bf	0x6e	// if (r3 == 0x3) goto loc_6e;
  58:	e923fff7 	bnez	r3, 0x46	// if (r3 != 0x0) goto loc_46;
  5c:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(<arg1> + 0x1) & 0x1)
  60:	e922ffe9 	bnez	r2, 0x32	// if (r2 != 0x0) goto loc_32;
  64:	8468      	ld.b	r3, (r4, 0x8)	// regs: r3=*(<arg1> + 0x8)
  66:	a060      	st.b	r3, (r0, 0x0)	// *(<arg0>) = *(<arg1> + 0x8)
  68:	8469      	ld.b	r3, (r4, 0x9)	// regs: r3=*(<arg1> + 0x9)
  6a:	a061      	st.b	r3, (r0, 0x1)	// *(<arg0> + 0x1) = *(<arg1> + 0x9)
  6c:	07ed      	br	0x46	// goto loc_46;
loc_6e:
  6e:	3206      	movi	r2, 6	// regs: r2=0x6
  70:	5c3e      	addi	r1, r4, 8	// regs: r1=(<arg1> + 0x8)
  72:	07e3      	br	0x38	// goto loc_38;
loc_74:
  74:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  76:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x76>, r1=<clobbered>
  7a:	3110      	movi	r1, 16	// regs: r1=0x10
  7c:	6c13      	mov	r0, r4	// regs: r0=<arg1>
  7e:	e0000000 	bsr	0x0	// <hgics_print_hex> // arg_bytes: 8; regs: r0=<ret hgics_print_hex@0x7e>, r1=<clobbered>
  82:	07e2      	br	0x46	// goto loc_46;
  84:	00000000 	.long	0x00000000	// <.rodata.lmac_get_tx_addr.str1.1>

Disassembly of section .text.lmac_get_rx_addr:

00000000 <lmac_get_rx_addr>: // arg_bytes: 8
   0:	14d1      	push	r4, r15
   2:	8141      	ld.b	r2, (r1, 0x1)	// regs: r2=*(<arg1> + 0x1)
   4:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   6:	4268      	lsli	r3, r2, 8	// regs: r3=(*(<arg1> + 0x1) << 0x8)
   8:	8120      	ld.b	r1, (r1, 0x0)	// regs: r1=*(<arg1>)
   a:	6cc4      	or	r3, r1	// regs: r3=((*(<arg1> + 0x1) << 0x8) | *(<arg1>))
   c:	e4232003 	andi	r1, r3, 3	// regs: r1=(((*(<arg1> + 0x1) << 0x8) | *(<arg1>)) & 0x3)
  10:	e9210014 	bnez	r1, 0x38	// if (r1 != 0x0) goto loc_38;
  14:	c4435462 	zext	r2, r3, 3, 2	// regs: r2=zext(((*(<arg1> + 0x1) << 0x8) | *(<arg1>)))
  18:	3a43      	cmpnei	r2, 3
  1a:	0c06      	bf	0x26	// if (r2 == 0x3) goto loc_26;
  1c:	3206      	movi	r2, 6	// regs: r2=0x6
loc_1e:
  1e:	5c2e      	addi	r1, r4, 4	// regs: r1=(<arg1> + 0x4)
loc_20:
  20:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x20>, r1=<clobbered>
  24:	0409      	br	0x36	// goto loc_36;
loc_26:
  26:	c48354e3 	zext	r3, r3, 7, 4	// regs: r3=zext(((*(<arg1> + 0x1) << 0x8) | *(<arg1>)))
  2a:	3b4f      	cmpnei	r3, 15
  2c:	3206      	movi	r2, 6	// regs: r2=0x6
  2e:	0ff8      	bf	0x1e	// if (r3 == 0xf) goto loc_1e;
  30:	31ff      	movi	r1, 255	// regs: r1=0xff
  32:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x32>, r1=<clobbered>
loc_36:
  36:	1491      	pop	r4, r15
loc_38:
  38:	3941      	cmpnei	r1, 1
  3a:	0818      	bt	0x6a	// if (r1 != 0x1) goto loc_6a;
  3c:	c4435483 	zext	r3, r3, 4, 2	// regs: r3=zext(((*(<arg1> + 0x1) << 0x8) | *(<arg1>)))
  40:	3b41      	cmpnei	r3, 1
  42:	0c11      	bf	0x64	// if (r3 == 0x1) goto loc_64;
  44:	3b43      	cmpnei	r3, 3
  46:	0c0f      	bf	0x64	// if (r3 == 0x3) goto loc_64;
  48:	e923fff7 	bnez	r3, 0x36	// if (r3 != 0x0) goto loc_36;
  4c:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(<arg1> + 0x1) & 0x1)
  50:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg1> + 0x2)
  52:	e9020007 	bez	r2, 0x60	// if (r2 == 0x0) goto loc_60;
  56:	8462      	ld.b	r3, (r4, 0x2)	// regs: r3=*(<arg1> + 0x2)
  58:	a060      	st.b	r3, (r0, 0x0)	// *(<arg0>) = *(<arg1> + 0x2)
  5a:	8161      	ld.b	r3, (r1, 0x1)	// regs: r3=*(<arg1> + 0x3)
  5c:	a061      	st.b	r3, (r0, 0x1)	// *(<arg0> + 0x1) = *(<arg1> + 0x3)
  5e:	07ec      	br	0x36	// goto loc_36;
loc_60:
  60:	3206      	movi	r2, 6	// regs: r2=0x6
  62:	07df      	br	0x20	// goto loc_20;
loc_64:
  64:	3206      	movi	r2, 6	// regs: r2=0x6
  66:	5c26      	addi	r1, r4, 2	// regs: r1=(<arg1> + 0x2)
  68:	07dc      	br	0x20	// goto loc_20;
loc_6a:
  6a:	1068      	lrw	r3, 0x0	// regs: r3=0x0
  6c:	d86309e2 	ld.b	r3, (r3, 0x9e2)	// regs: r3=*(0x9e2)
  70:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  74:	e923ffe1 	bnez	r3, 0x36	// if (r3 != 0x0) goto loc_36;
  78:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  7a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x7a>, r1=<clobbered>
  7e:	3110      	movi	r1, 16	// regs: r1=0x10
  80:	6c13      	mov	r0, r4	// regs: r0=<arg1>
  82:	e0000000 	bsr	0x0	// <hgics_print_hex> // arg_bytes: 8; regs: r0=<ret hgics_print_hex@0x82>, r1=<clobbered>
  86:	07d8      	br	0x36	// goto loc_36;
  88:	0000      	.short	0x0000	// <ah_lmac>
  8a:	0000      	.short	0x0000
  8c:	00000000 	.long	0x00000000	// <.rodata.lmac_get_tx_addr.str1.1>

Disassembly of section .text.lmac_set_basic_nav:

00000000 <lmac_set_basic_nav>: // arg_bytes: 4
   0:	1052      	lrw	r2, 0x0	// regs: r2=0x0
   2:	d86209e2 	ld.b	r3, (r2, 0x9e2)	// regs: r3=*(0x9e2)
   6:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
   a:	e9230006 	bnez	r3, 0x16	// if (r3 != 0x0) goto loc_16;
   e:	d862202f 	ld.w	r3, (r2, 0xbc)	// regs: r3=*(0xbc)
  12:	e9030019 	bez	r3, 0x44	// if (r3 == 0x0) goto loc_44;
loc_16:
  16:	106e      	lrw	r3, 0x0	// regs: r3=0x0
  18:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  1a:	d8432034 	ld.w	r2, (r3, 0xd0)	// regs: r2=*((*(0x0) + 0xd0))
  1e:	6408      	cmphs	r2, r0
  20:	d8232033 	ld.w	r1, (r3, 0xcc)	// regs: r1=*((*(0x0) + 0xcc))
  24:	c4020c40 	inct	r0, r2, 0
  28:	ec210080 	ori	r1, r1, 128	// regs: r1=(*((*(0x0) + 0xcc)) | 0x80)
  2c:	dc232033 	st.w	r1, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x80)
  30:	e900000a 	bez	r0, 0x44	// if (r0 == 0x0) goto loc_44;
  34:	dc032034 	st.w	r0, (r3, 0xd0)	// *((*(0x0) + 0xd0)) = <arg0>
  38:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
  3c:	ec420040 	ori	r2, r2, 64	// regs: r2=(*((*(0x0) + 0xcc)) | 0x40)
  40:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x40)
loc_44:
  44:	783c      	jmp	r15	// return;
  46:	0000      	.short	0x0000
  48:	0000      	.short	0x0000	// <ah_lmac>
  4a:	0000      	.short	0x0000
  4c:	00000000 	.long	0x00000000	// <LMAC>

Disassembly of section .text.lmac_clr_basic_nav:

00000000 <lmac_clr_basic_nav>: // arg_bytes: 0
   0:	1068      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   4:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
   8:	ec420080 	ori	r2, r2, 128	// regs: r2=(*((*(0x0) + 0xcc)) | 0x80)
   c:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x80)
  10:	3280      	movi	r2, 128	// regs: r2=0x80
  12:	4249      	lsli	r2, r2, 9	// regs: r2=0x10000
  14:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x10000
  16:	3200      	movi	r2, 0	// regs: r2=0x0
  18:	dc432034 	st.w	r2, (r3, 0xd0)	// *((*(0x0) + 0xd0)) = 0x0
  1c:	783c      	jmp	r15	// return;
  1e:	0000      	.short	0x0000
  20:	00000000 	.long	0x00000000	// <LMAC>

Disassembly of section .text.lmac_set_obss_nav:

00000000 <lmac_set_obss_nav>: // arg_bytes: 4
   0:	106f      	lrw	r3, 0x0	// regs: r3=0x0
   2:	d863202f 	ld.w	r3, (r3, 0xbc)	// regs: r3=*(0xbc)
   6:	3b81      	bclri	r3, 1	// regs: r3=(*(0xbc) & ~(0x1 << 0x1))
   8:	e9030019 	bez	r3, 0x3a	// if (r3 == 0x0) goto loc_3a;
   c:	106d      	lrw	r3, 0x0	// regs: r3=0x0
   e:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
  10:	d8432035 	ld.w	r2, (r3, 0xd4)	// regs: r2=*((*(0x0) + 0xd4))
  14:	6408      	cmphs	r2, r0
  16:	d8232033 	ld.w	r1, (r3, 0xcc)	// regs: r1=*((*(0x0) + 0xcc))
  1a:	c4020c40 	inct	r0, r2, 0
  1e:	ec210200 	ori	r1, r1, 512	// regs: r1=(*((*(0x0) + 0xcc)) | 0x200)
  22:	dc232033 	st.w	r1, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x200)
  26:	e900000a 	bez	r0, 0x3a	// if (r0 == 0x0) goto loc_3a;
  2a:	dc032035 	st.w	r0, (r3, 0xd4)	// *((*(0x0) + 0xd4)) = <arg0>
  2e:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
  32:	ec420100 	ori	r2, r2, 256	// regs: r2=(*((*(0x0) + 0xcc)) | 0x100)
  36:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x100)
loc_3a:
  3a:	783c      	jmp	r15	// return;
  3c:	0000      	.short	0x0000	// <ah_lmac>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <LMAC>
  42:	0000      	.short	0x0000

Disassembly of section .text.lmac_clr_obss_nav:

00000000 <lmac_clr_obss_nav>: // arg_bytes: 0
   0:	1068      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   4:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
   8:	ec420200 	ori	r2, r2, 512	// regs: r2=(*((*(0x0) + 0xcc)) | 0x200)
   c:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x200)
  10:	3280      	movi	r2, 128	// regs: r2=0x80
  12:	424a      	lsli	r2, r2, 10	// regs: r2=0x20000
  14:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x20000
  16:	3200      	movi	r2, 0	// regs: r2=0x0
  18:	dc432035 	st.w	r2, (r3, 0xd4)	// *((*(0x0) + 0xd4)) = 0x0
  1c:	783c      	jmp	r15	// return;
  1e:	0000      	.short	0x0000
  20:	00000000 	.long	0x00000000	// <LMAC>

Disassembly of section .text.lmac_select_mcs_by_evm:

00000000 <lmac_select_mcs_by_evm>: // arg_bytes: 8
   0:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   2:	3300      	movi	r3, 0	// regs: r3=0x0
   4:	2b07      	subi	r3, 8	// regs: r3=0xfffffff8
   6:	dc6e0000 	st.b	r3, (r14, 0x0)	// local_8 = 0xfffffff8
   a:	3300      	movi	r3, 0	// regs: r3=0x0
   c:	2b08      	subi	r3, 9	// regs: r3=0xfffffff7
   e:	dc6e0001 	st.b	r3, (r14, 0x1)	// local_7 = 0xfffffff7
  12:	3300      	movi	r3, 0	// regs: r3=0x0
  14:	2b0c      	subi	r3, 13	// regs: r3=0xfffffff3
  16:	dc6e0002 	st.b	r3, (r14, 0x2)	// local_6 = 0xfffffff3
  1a:	3300      	movi	r3, 0	// regs: r3=0x0
  1c:	2b0e      	subi	r3, 15	// regs: r3=0xfffffff1
  1e:	dc6e0003 	st.b	r3, (r14, 0x3)	// local_5 = 0xfffffff1
  22:	3300      	movi	r3, 0	// regs: r3=0x0
  24:	2b11      	subi	r3, 18	// regs: r3=0xffffffee
  26:	dc6e0004 	st.b	r3, (r14, 0x4)	// local_4 = 0xffffffee
  2a:	3300      	movi	r3, 0	// regs: r3=0x0
  2c:	2b13      	subi	r3, 20	// regs: r3=0xffffffec
  2e:	dc6e0005 	st.b	r3, (r14, 0x5)	// local_3 = 0xffffffec
  32:	3300      	movi	r3, 0	// regs: r3=0x0
  34:	2b15      	subi	r3, 22	// regs: r3=0xffffffea
  36:	dc6e0006 	st.b	r3, (r14, 0x6)	// local_2 = 0xffffffea
  3a:	3300      	movi	r3, 0	// regs: r3=0x0
  3c:	2b17      	subi	r3, 24	// regs: r3=0xffffffe8
  3e:	dc6e0007 	st.b	r3, (r14, 0x7)	// local_1 = 0xffffffe8
  42:	3200      	movi	r2, 0	// regs: r2=0x0
  44:	3307      	movi	r3, 7	// regs: r3=0x7
loc_46:
  46:	c44e002c 	addu	r12, r14, r2	// regs: r12=((sp - 0x8) + r2)
  4a:	d98c4007 	ld.bs	r12, (r12, 0x7)	// regs: r12=*((((sp - 0x8) + r2) + 0x7))
  4e:	6306      	subu	r12, r1	// regs: r12=(*((((sp - 0x8) + r2) + 0x7)) - <arg1>)
  50:	6701      	cmplt	r0, r12
  52:	0806      	bt	0x5e	// if (T) goto loc_5e;
  54:	2b00      	subi	r3, 1	// regs: r3=(r3 - 0x1)
  56:	74cc      	zextb	r3, r3	// regs: r3=zext8((r3 - 0x1))
  58:	2a00      	subi	r2, 1	// regs: r2=(r2 - 0x1)
  5a:	e923fff6 	bnez	r3, 0x46	// if (r3 != 0x0) goto loc_46;
loc_5e:
  5e:	6c0f      	mov	r0, r3	// regs: r0=r3
  60:	1402      	addi	r14, r14, 8	// regs: r14=((sp - 0x8) + 0x8)
  62:	783c      	jmp	r15	// return;

Disassembly of section .text.lmac_std_calc:

00000000 <lmac_std_calc>: // arg_bytes: 8
   0:	14d7      	push	r4-r10, r15
   2:	3400      	movi	r4, 0	// regs: r4=0x0
   4:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   6:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   8:	6dc3      	mov	r7, r0	// regs: r7=<arg0>
   a:	6e13      	mov	r8, r4	// regs: r8=0x0
loc_c:
   c:	5f79      	subu	r3, r7, r6	// regs: r3=(r7 - <arg0>)
   e:	654d      	cmplt	r3, r5
  10:	0826      	bt	0x5c	// if (T) goto loc_5c;
  12:	6c17      	mov	r0, r5	// regs: r0=<arg1>
  14:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0x14>, r1=<clobbered>
  18:	6c83      	mov	r2, r0	// regs: r2=<ret __floatsidf@0x14>
  1a:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
  1c:	6c13      	mov	r0, r4	// regs: r0=r4
  1e:	6c63      	mov	r1, r8	// regs: r1=r8
  20:	e0000000 	bsr	0x0	// <__divdf3>; regs: r0=<ret __divdf3@0x20>, r1=<clobbered>
  24:	3400      	movi	r4, 0	// regs: r4=0x0
  26:	6e43      	mov	r9, r0	// regs: r9=<ret __divdf3@0x20>
  28:	6e87      	mov	r10, r1	// regs: r10=<clobbered>
  2a:	6ddb      	mov	r7, r6	// regs: r7=<arg0>
  2c:	6e13      	mov	r8, r4	// regs: r8=0x0
loc_2e:
  2e:	5f79      	subu	r3, r7, r6	// regs: r3=(r7 - <arg0>)
  30:	654d      	cmplt	r3, r5
  32:	0823      	bt	0x78	// if (T) goto loc_78;
  34:	5d03      	subi	r0, r5, 1	// regs: r0=(<arg1> - 0x1)
  36:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0x36>, r1=<clobbered>
  3a:	6c83      	mov	r2, r0	// regs: r2=<ret __floatsidf@0x36>
  3c:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
  3e:	6c13      	mov	r0, r4	// regs: r0=r4
  40:	6c63      	mov	r1, r8	// regs: r1=r8
  42:	e0000000 	bsr	0x0	// <__divdf3>; regs: r0=<ret __divdf3@0x42>, r1=<clobbered>
  46:	e0000000 	bsr	0x0	// <sqrt>; regs: r0=<ret sqrt@0x46>, r1=<clobbered>
  4a:	3200      	movi	r2, 0	// regs: r2=0x0
  4c:	ea233fe0 	movih	r3, 16352	// regs: r3=(0x3fe0 << 0x10)
  50:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x50>, r1=<clobbered>
  54:	e0000000 	bsr	0x0	// <__fixdfsi>; regs: r0=<ret __fixdfsi@0x54>, r1=<clobbered>
  58:	7402      	sextb	r0, r0	// regs: r0=sext8(<ret __fixdfsi@0x54>)
  5a:	1497      	pop	r4-r10, r15
loc_5c:
  5c:	d8074000 	ld.bs	r0, (r7, 0x0)	// regs: r0=*(r7)
  60:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0x60>, r1=<clobbered>
  64:	6c83      	mov	r2, r0	// regs: r2=<ret __floatsidf@0x60>
  66:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
  68:	6c13      	mov	r0, r4	// regs: r0=r4
  6a:	6c63      	mov	r1, r8	// regs: r1=r8
  6c:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x6c>, r1=<clobbered>
  70:	6d03      	mov	r4, r0	// regs: r4=<ret __adddf3@0x6c>
  72:	6e07      	mov	r8, r1	// regs: r8=<clobbered>
  74:	2700      	addi	r7, 1	// regs: r7=(r7 + 0x1)
  76:	07cb      	br	0xc	// goto loc_c;
loc_78:
  78:	d8074000 	ld.bs	r0, (r7, 0x0)	// regs: r0=*(r7)
  7c:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0x7c>, r1=<clobbered>
  80:	6ca7      	mov	r2, r9	// regs: r2=<ret __divdf3@0x20>
  82:	6ceb      	mov	r3, r10	// regs: r3=<clobbered>
  84:	e0000000 	bsr	0x0	// <__subdf3>; regs: r0=<ret __subdf3@0x84>, r1=<clobbered>
  88:	6c83      	mov	r2, r0	// regs: r2=<ret __subdf3@0x84>
  8a:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
  8c:	e0000000 	bsr	0x0	// <__muldf3>; regs: r0=<ret __muldf3@0x8c>, r1=<clobbered>
  90:	6c83      	mov	r2, r0	// regs: r2=<ret __muldf3@0x8c>
  92:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
  94:	6c13      	mov	r0, r4	// regs: r0=r4
  96:	6c63      	mov	r1, r8	// regs: r1=r8
  98:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x98>, r1=<clobbered>
  9c:	6d03      	mov	r4, r0	// regs: r4=<ret __adddf3@0x98>
  9e:	6e07      	mov	r8, r1	// regs: r8=<clobbered>
  a0:	2700      	addi	r7, 1	// regs: r7=(r7 + 0x1)
  a2:	07c6      	br	0x2e	// goto loc_2e;

Disassembly of section .text.lmac_ewma_update:

00000000 <lmac_ewma_update>: // arg_bytes: 12
   0:	14d5      	push	r4-r8, r15
   2:	3305      	movi	r3, 5	// regs: r3=0x5
   4:	c4628023 	divu	r3, r2, r3	// regs: r3=(<arg2> / 0x5)
   8:	2b00      	subi	r3, 1	// regs: r3=((<arg2> / 0x5) - 0x1)
   a:	74cc      	zextb	r3, r3	// regs: r3=zext8(((<arg2> / 0x5) - 0x1))
   c:	1055      	lrw	r2, 0x0	// regs: r2=0x0
   e:	4363      	lsli	r3, r3, 3	// regs: r3=(zext8(((<arg2> / 0x5) - 0x1)) << 0x3)
  10:	60c8      	addu	r3, r2	// regs: r3=((zext8(((<arg2> / 0x5) - 0x1)) << 0x3) )
  12:	6dc3      	mov	r7, r0	// regs: r7=<arg0>
  14:	4110      	lsli	r0, r1, 16	// regs: r0=(<arg1> << 0x10)
  16:	93a0      	ld.w	r5, (r3, 0x0)	// regs: r5=*(((zext8(((<arg2> / 0x5) - 0x1)) << 0x3) ))
  18:	9381      	ld.w	r4, (r3, 0x4)	// regs: r4=*((((zext8(((<arg2> / 0x5) - 0x1)) << 0x3) ) + 0x4))
  1a:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0x1a>, r1=<clobbered>
  1e:	6e03      	mov	r8, r0	// regs: r8=<ret __floatsidf@0x1a>
  20:	6d87      	mov	r6, r1	// regs: r6=<clobbered>
  22:	6c97      	mov	r2, r5	// regs: r2=*(((zext8(((<arg2> / 0x5) - 0x1)) << 0x3) ))
  24:	6cd3      	mov	r3, r4	// regs: r3=*((((zext8(((<arg2> / 0x5) - 0x1)) << 0x3) ) + 0x4))
  26:	3000      	movi	r0, 0	// regs: r0=0x0
  28:	ea213ff0 	movih	r1, 16368	// regs: r1=(0x3ff0 << 0x10)
  2c:	e0000000 	bsr	0x0	// <__subdf3>; regs: r0=<ret __subdf3@0x2c>, r1=<clobbered>
  30:	6c83      	mov	r2, r0	// regs: r2=<ret __subdf3@0x2c>
  32:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
  34:	6c23      	mov	r0, r8	// regs: r0=<ret __floatsidf@0x1a>
  36:	6c5b      	mov	r1, r6	// regs: r1=<clobbered>
  38:	e0000000 	bsr	0x0	// <__muldf3>; regs: r0=<ret __muldf3@0x38>, r1=<clobbered>
  3c:	6e03      	mov	r8, r0	// regs: r8=<ret __muldf3@0x38>
  3e:	6c1f      	mov	r0, r7	// regs: r0=<arg0>
  40:	6d87      	mov	r6, r1	// regs: r6=<clobbered>
  42:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0x42>, r1=<clobbered>
  46:	6c97      	mov	r2, r5	// regs: r2=*(((zext8(((<arg2> / 0x5) - 0x1)) << 0x3) ))
  48:	6cd3      	mov	r3, r4	// regs: r3=*((((zext8(((<arg2> / 0x5) - 0x1)) << 0x3) ) + 0x4))
  4a:	e0000000 	bsr	0x0	// <__muldf3>; regs: r0=<ret __muldf3@0x4a>, r1=<clobbered>
  4e:	6c83      	mov	r2, r0	// regs: r2=<ret __muldf3@0x4a>
  50:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
  52:	6c23      	mov	r0, r8	// regs: r0=<ret __muldf3@0x38>
  54:	6c5b      	mov	r1, r6	// regs: r1=<clobbered>
  56:	e0000000 	bsr	0x0	// <__adddf3>; regs: r0=<ret __adddf3@0x56>, r1=<clobbered>
  5a:	e0000000 	bsr	0x0	// <__fixdfsi>; regs: r0=<ret __fixdfsi@0x5a>, r1=<clobbered>
  5e:	1495      	pop	r4-r8, r15
  60:	00000000 	.long	0x00000000	// <.rodata.ewma_weight_coef>

Disassembly of section .text.lmac_auto_rate_ctrl:

00000000 <lmac_auto_rate_ctrl>: // arg_bytes: 4
   0:	14d7      	push	r4-r10, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	9060      	ld.w	r3, (r0, 0x0)	// regs: r3=*(<arg0>)
   6:	64c2      	cmpne	r0, r3
   8:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   a:	0c75      	bf	0xf4	// if (!T) goto loc_f4;
   c:	3100      	movi	r1, 0	// regs: r1=0x0
   e:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  10:	111a      	lrw	r0, 0x0	// regs: r0=0x0
  12:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0x12>, r1=<clobbered>
  16:	11ba      	lrw	r5, 0x0	// regs: r5=0x0
  18:	11da      	lrw	r6, 0x0	// regs: r6=0x0
  1a:	94e0      	ld.w	r7, (r4, 0x0)	// regs: r7=*(<arg0>)
loc_1c:
  1c:	65d2      	cmpne	r4, r7
  1e:	0807      	bt	0x2c	// if (T) goto loc_2c;
  20:	1116      	lrw	r0, 0x0	// regs: r0=0x0
  22:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0x22>, r1=<clobbered>
  26:	6c13      	mov	r0, r4	// regs: r0=<arg0>
loc_28:
  28:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  2a:	1497      	pop	r4-r10, r15
loc_2c:
  2c:	d9050317 	ld.b	r8, (r5, 0x317)	// regs: r8=*(0x317)
  30:	d86700a0 	ld.b	r3, (r7, 0xa0)	// regs: r3=*(r7 + 0xa0)
  34:	660c      	cmphs	r3, r8
  36:	0c44      	bf	0xbe	// if (!T) goto loc_be;
  38:	d86740a2 	ld.bs	r3, (r7, 0xa2)	// regs: r3=*(r7 + 0xa2)
  3c:	d9272027 	ld.w	r9, (r7, 0x9c)	// regs: r9=*(r7 + 0x9c)
  40:	e9230046 	bnez	r3, 0xcc	// if (r3 != 0x0) goto loc_cc;
  44:	6c0f      	mov	r0, r3	// regs: r0=*(r7 + 0xa2)
loc_46:
  46:	660d      	cmplt	r3, r8
  48:	083d      	bt	0xc2	// if (T) goto loc_c2;
  4a:	c5008040 	divs	r0, r0, r8	// regs: r0=(r0 / *(0x317))
  4e:	4010      	lsli	r0, r0, 16	// regs: r0=((r0 / *(0x317)) << 0x10)
loc_50:
  50:	3380      	movi	r3, 128	// regs: r3=0x80
  52:	4368      	lsli	r3, r3, 8	// regs: r3=0x8000
  54:	60c0      	addu	r3, r0	// regs: r3=(0x8000 + r0)
  56:	5370      	asri	r3, r3, 16	// regs: r3=((0x8000 + r0) >> 0x10)
  58:	dc6700a2 	st.b	r3, (r7, 0xa2)	// *(r7 + 0xa2) = ((0x8000 + r0) >> 0x10)
  5c:	6c63      	mov	r1, r8	// regs: r1=*(0x317)
  5e:	6c27      	mov	r0, r9	// regs: r0=r9
  60:	e0000000 	bsr	0x0	// <lmac_std_calc> // arg_bytes: 8; regs: r0=<ret lmac_std_calc@0x60>, r1=<clobbered>
  64:	3823      	cmplti	r0, 4
  66:	dc0700a3 	st.b	r0, (r7, 0xa3)	// *(r7 + 0xa3) = <ret lmac_std_calc@0x60>
  6a:	d86700a2 	ld.b	r3, (r7, 0xa2)	// regs: r3=*(r7 + 0xa2)
  6e:	0c3c      	bf	0xe6	// if (r0 >= 0x4) goto loc_e6;
  70:	600c      	addu	r0, r3	// regs: r0=(<ret lmac_std_calc@0x60> + *(r7 + 0xa2))
loc_72:
  72:	d8254870 	ld.bs	r1, (r5, 0x870)	// regs: r1=*(0x870)
  76:	7402      	sextb	r0, r0	// regs: r0=sext8(r0)
  78:	e0000000 	bsr	0x0	// <lmac_select_mcs_by_evm> // arg_bytes: 8; regs: r0=<ret lmac_select_mcs_by_evm@0x78>, r1=<clobbered>
  7c:	d86700ad 	ld.b	r3, (r7, 0xad)	// regs: r3=*(r7 + 0xad)
  80:	e443200f 	andi	r2, r3, 15	// regs: r2=(*(r7 + 0xad) & 0xf)
  84:	6481      	cmplt	r0, r2
  86:	0c32      	bf	0xea	// if (!T) goto loc_ea;
  88:	220e      	addi	r2, 15	// regs: r2=((*(r7 + 0xad) & 0xf) + 0xf)
  8a:	c4625c60 	ins	r3, r2, 3, 0
loc_8e:
  8e:	dc6700ad 	st.b	r3, (r7, 0xad)	// *(r7 + 0xad) = *(r7 + 0xad)
loc_92:
  92:	3300      	movi	r3, 0	// regs: r3=0x0
  94:	dc6700a0 	st.b	r3, (r7, 0xa0)	// *(r7 + 0xa0) = 0x0
  98:	d86520ee 	ld.w	r3, (r5, 0x3b8)	// regs: r3=*(0x3b8)
  9c:	e4632004 	andi	r3, r3, 4	// regs: r3=(*(0x3b8) & 0x4)
  a0:	e903000f 	bez	r3, 0xbe	// if (r3 == 0x0) goto loc_be;
  a4:	d86700ad 	ld.b	r3, (r7, 0xad)	// regs: r3=*(r7 + 0xad)
  a8:	4b04      	lsri	r0, r3, 4	// regs: r0=(*(r7 + 0xad) >> 0x4)
  aa:	d84740a3 	ld.bs	r2, (r7, 0xa3)	// regs: r2=*(r7 + 0xa3)
  ae:	d82740a2 	ld.bs	r1, (r7, 0xa2)	// regs: r1=*(r7 + 0xa2)
  b2:	e463200f 	andi	r3, r3, 15	// regs: r3=(*(r7 + 0xad) & 0xf)
  b6:	b800      	st.w	r0, (r14, 0x0)	// local_4 = (*(r7 + 0xad) >> 0x4)
  b8:	6c1b      	mov	r0, r6	// regs: r0=0x0
  ba:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xba>, r1=<clobbered>
loc_be:
  be:	97e0      	ld.w	r7, (r7, 0x0)	// regs: r7=*(r7)
  c0:	07ae      	br	0x1c	// goto loc_1c;
loc_c2:
  c2:	d0691022 	ldr.bs	r2, (r9, r3 << 0)	// regs: r2=*(r9 + (r3 << 0))
  c6:	6008      	addu	r0, r2	// regs: r0=(r0 + *(r9 + (r3 << 0)))
  c8:	2300      	addi	r3, 1	// regs: r3=(r3 + 0x1)
  ca:	07be      	br	0x46	// goto loc_46;
loc_cc:
  cc:	4310      	lsli	r0, r3, 16	// regs: r0=(*(r7 + 0xa2) << 0x10)
  ce:	ea0a0000 	movi	r10, 0	// regs: r10=0x0
loc_d2:
  d2:	6629      	cmplt	r10, r8
  d4:	0fbe      	bf	0x50	// if (!T) goto loc_50;
  d6:	d1491021 	ldr.bs	r1, (r9, r10 << 0)	// regs: r1=*(r9 + (r10 << 0))
  da:	6ca3      	mov	r2, r8	// regs: r2=*(0x317)
  dc:	e0000000 	bsr	0x0	// <lmac_ewma_update> // arg_bytes: 12; regs: r0=<ret lmac_ewma_update@0xdc>, r1=<clobbered>
  e0:	e54a0000 	addi	r10, r10, 1	// regs: r10=(r10 + 0x1)
  e4:	07f7      	br	0xd2	// goto loc_d2;
loc_e6:
  e6:	5b0a      	addi	r0, r3, 3	// regs: r0=(*(r7 + 0xa2) + 0x3)
  e8:	07c5      	br	0x72	// goto loc_72;
loc_ea:
  ea:	6409      	cmplt	r2, r0
  ec:	0fd3      	bf	0x92	// if (!T) goto loc_92;
  ee:	c4605c60 	ins	r3, r0, 3, 0
  f2:	07ce      	br	0x8e	// goto loc_8e;
loc_f4:
  f4:	3000      	movi	r0, 0	// regs: r0=0x0
  f6:	0799      	br	0x28	// goto loc_28;
  f8:	00000000 	.long	0x00000000	// <ah_lmac+0xa00>
  fc:	00000000 	.long	0x00000000	// <ah_lmac>
 100:	00000000 	.long	0x00000000	// <.rodata.lmac_auto_rate_ctrl.str1.1>

Disassembly of section .text.lmac_bss_bw:

00000000 <lmac_bss_bw>: // arg_bytes: 0
   0:	104f      	lrw	r2, 0x0	// regs: r2=0x0
   2:	d8620308 	ld.b	r3, (r2, 0x308)	// regs: r3=*(0x308)
   6:	3b42      	cmpnei	r3, 2
   8:	0c11      	bf	0x2a	// if (r3 == 0x2) goto loc_2a;
   a:	3b43      	cmpnei	r3, 3
   c:	0c12      	bf	0x30	// if (r3 == 0x3) goto loc_30;
   e:	3b41      	cmpnei	r3, 1
  10:	0813      	bt	0x36	// if (r3 != 0x1) goto loc_36;
  12:	d842034a 	ld.b	r2, (r2, 0x34a)	// regs: r2=*(0x34a)
  16:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(0x34a) & 0x1)
  1a:	30fa      	movi	r0, 250	// regs: r0=0xfa
  1c:	33fa      	movi	r3, 250	// regs: r3=0xfa
  1e:	4002      	lsli	r0, r0, 2	// regs: r0=0x3e8
  20:	4363      	lsli	r3, r3, 3	// regs: r3=0x7d0
  22:	3a40      	cmpnei	r2, 0
  24:	c4030c20 	incf	r0, r3, 0
  28:	0403      	br	0x2e	// goto loc_2e;
loc_2a:
  2a:	30fa      	movi	r0, 250	// regs: r0=0xfa
  2c:	4004      	lsli	r0, r0, 4	// regs: r0=0xfa0
loc_2e:
  2e:	783c      	jmp	r15	// return;
loc_30:
  30:	30fa      	movi	r0, 250	// regs: r0=0xfa
  32:	4005      	lsli	r0, r0, 5	// regs: r0=0x1f40
  34:	07fd      	br	0x2e	// goto loc_2e;
loc_36:
  36:	30fa      	movi	r0, 250	// regs: r0=0xfa
  38:	4002      	lsli	r0, r0, 2	// regs: r0=0x3e8
  3a:	07fa      	br	0x2e	// goto loc_2e;
  3c:	0000      	.short	0x0000	// <ah_lmac>
  3e:	0000      	.short	0x0000

Disassembly of section .text.lmac_alloc_sta:

00000000 <lmac_alloc_sta>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	30fa      	movi	r0, 250	// regs: r0=0xfa
   4:	4001      	lsli	r0, r0, 1	// regs: r0=0x1f4
   6:	e0000000 	bsr	0x0	// <_os_zalloc>; regs: r0=<ret _os_zalloc@0x6>, r1=<clobbered>
   a:	6d03      	mov	r4, r0	// regs: r4=<ret _os_zalloc@0x6>
   c:	e9000008 	bez	r0, 0x1c	// if (r0 == 0x0) goto loc_1c;
  10:	e0000000 	bsr	0x0	// <cpu_intrpt_save>; regs: r0=<ret cpu_intrpt_save@0x10>, r1=<clobbered>
  14:	3301      	movi	r3, 1	// regs: r3=0x1
  16:	b465      	st.w	r3, (r4, 0x14)	// *(<ret _os_zalloc@0x6> + 0x14) = 0x1
  18:	e0000000 	bsr	0x0	// <cpu_intrpt_restore>; regs: r0=<ret cpu_intrpt_restore@0x18>, r1=<clobbered>
loc_1c:
  1c:	6c13      	mov	r0, r4	// regs: r0=<ret _os_zalloc@0x6>
  1e:	1491      	pop	r4, r15

Disassembly of section .text.lmac_sta_get:

00000000 <lmac_sta_get>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   4:	3100      	movi	r1, 0	// regs: r1=0x0
   6:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   8:	2900      	subi	r1, 1	// regs: r1=0xffffffff
   a:	1105      	lrw	r0, 0x0	// regs: r0=0x0
   c:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0xc>, r1=<clobbered>
  10:	1164      	lrw	r3, 0x0	// regs: r3=0x0
  12:	e44309f7 	addi	r2, r3, 2552	// regs: r2=0x9f8
  16:	d883227e 	ld.w	r4, (r3, 0x9f8)	// regs: r4=*(0x9f8)
loc_1a:
  1a:	6492      	cmpne	r4, r2
  1c:	0803      	bt	0x22	// if (T) goto loc_22;
  1e:	3400      	movi	r4, 0	// regs: r4=0x0
  20:	0415      	br	0x4a	// goto loc_4a;
loc_22:
  22:	eb46ffff 	cmpnei	r6, 65535
  26:	0c19      	bf	0x58	// if (r6 == 0xffff) goto loc_58;
  28:	d8641034 	ld.h	r3, (r4, 0x68)	// regs: r3=*(r4 + 0x68)
  2c:	658e      	cmpne	r3, r6
  2e:	0815      	bt	0x58	// if (T) goto loc_58;
  30:	d864006b 	ld.b	r3, (r4, 0x6b)	// regs: r3=*(r4 + 0x6b)
  34:	e4632020 	andi	r3, r3, 32	// regs: r3=(*(r4 + 0x6b) & 0x20)
  38:	e9230010 	bnez	r3, 0x58	// if (r3 != 0x0) goto loc_58;
loc_3c:
  3c:	e0000000 	bsr	0x0	// <cpu_intrpt_save>; regs: r0=<ret cpu_intrpt_save@0x3c>, r1=<clobbered>
  40:	9465      	ld.w	r3, (r4, 0x14)	// regs: r3=*(r4 + 0x14)
  42:	2300      	addi	r3, 1	// regs: r3=(*(r4 + 0x14) + 0x1)
  44:	b465      	st.w	r3, (r4, 0x14)	// *(r4 + 0x14) = (*(r4 + 0x14) + 0x1)
  46:	e0000000 	bsr	0x0	// <cpu_intrpt_restore>; regs: r0=<ret cpu_intrpt_restore@0x46>, r1=<clobbered>
loc_4a:
  4a:	e0000000 	bsr	0x0	// <lmac_psm_info_update> // arg_bytes: 0; regs: r0=<ret lmac_psm_info_update@0x4a>, r1=<clobbered>
  4e:	1014      	lrw	r0, 0x0	// regs: r0=0x0
  50:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0x50>, r1=<clobbered>
  54:	6c13      	mov	r0, r4	// regs: r0=r4
  56:	1493      	pop	r4-r6, r15
loc_58:
  58:	e9050020 	bez	r5, 0x98	// if (r5 == 0x0) goto loc_98;
  5c:	d824006f 	ld.b	r1, (r4, 0x6f)	// regs: r1=*(r4 + 0x6f)
  60:	8560      	ld.b	r3, (r5, 0x0)	// regs: r3=*(<arg1>)
  62:	64c6      	cmpne	r1, r3
  64:	081a      	bt	0x98	// if (T) goto loc_98;
  66:	d8240070 	ld.b	r1, (r4, 0x70)	// regs: r1=*(r4 + 0x70)
  6a:	8561      	ld.b	r3, (r5, 0x1)	// regs: r3=*(<arg1> + 0x1)
  6c:	64c6      	cmpne	r1, r3
  6e:	0815      	bt	0x98	// if (T) goto loc_98;
  70:	d8240071 	ld.b	r1, (r4, 0x71)	// regs: r1=*(r4 + 0x71)
  74:	8562      	ld.b	r3, (r5, 0x2)	// regs: r3=*(<arg1> + 0x2)
  76:	64c6      	cmpne	r1, r3
  78:	0810      	bt	0x98	// if (T) goto loc_98;
  7a:	d8240072 	ld.b	r1, (r4, 0x72)	// regs: r1=*(r4 + 0x72)
  7e:	8563      	ld.b	r3, (r5, 0x3)	// regs: r3=*(<arg1> + 0x3)
  80:	64c6      	cmpne	r1, r3
  82:	080b      	bt	0x98	// if (T) goto loc_98;
  84:	d8240073 	ld.b	r1, (r4, 0x73)	// regs: r1=*(r4 + 0x73)
  88:	8564      	ld.b	r3, (r5, 0x4)	// regs: r3=*(<arg1> + 0x4)
  8a:	64c6      	cmpne	r1, r3
  8c:	0806      	bt	0x98	// if (T) goto loc_98;
  8e:	d8240074 	ld.b	r1, (r4, 0x74)	// regs: r1=*(r4 + 0x74)
  92:	8565      	ld.b	r3, (r5, 0x5)	// regs: r3=*(<arg1> + 0x5)
  94:	64c6      	cmpne	r1, r3
  96:	0fd3      	bf	0x3c	// if (!T) goto loc_3c;
loc_98:
  98:	9480      	ld.w	r4, (r4, 0x0)	// regs: r4=*(r4)
  9a:	07c0      	br	0x1a	// goto loc_1a;
  9c:	00000000 	.long	0x00000000	// <ah_lmac+0xa00>
  a0:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_sta_search:

00000000 <lmac_sta_search>: // arg_bytes: 8
   0:	14d3      	push	r4-r6, r15
   2:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   4:	3100      	movi	r1, 0	// regs: r1=0x0
   6:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   8:	2900      	subi	r1, 1	// regs: r1=0xffffffff
   a:	101e      	lrw	r0, 0x0	// regs: r0=0x0
   c:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0xc>, r1=<clobbered>
  10:	107d      	lrw	r3, 0x0	// regs: r3=0x0
  12:	e46309f7 	addi	r3, r3, 2552	// regs: r3=0x9f8
  16:	9380      	ld.w	r4, (r3, 0x0)	// regs: r4=*(0x9f8)
loc_18:
  18:	64d2      	cmpne	r4, r3
  1a:	0809      	bt	0x2c	// if (T) goto loc_2c;
  1c:	3400      	movi	r4, 0	// regs: r4=0x0
loc_1e:
  1e:	e0000000 	bsr	0x0	// <lmac_psm_info_update> // arg_bytes: 0; regs: r0=<ret lmac_psm_info_update@0x1e>, r1=<clobbered>
  22:	1018      	lrw	r0, 0x0	// regs: r0=0x0
  24:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0x24>, r1=<clobbered>
  28:	6c13      	mov	r0, r4	// regs: r0=r4
  2a:	1493      	pop	r4-r6, r15
loc_2c:
  2c:	eb46ffff 	cmpnei	r6, 65535
  30:	0c05      	bf	0x3a	// if (r6 == 0xffff) goto loc_3a;
  32:	d8441034 	ld.h	r2, (r4, 0x68)	// regs: r2=*(r4 + 0x68)
  36:	658a      	cmpne	r2, r6
  38:	0ff3      	bf	0x1e	// if (!T) goto loc_1e;
loc_3a:
  3a:	e9050020 	bez	r5, 0x7a	// if (r5 == 0x0) goto loc_7a;
  3e:	d824006f 	ld.b	r1, (r4, 0x6f)	// regs: r1=*(r4 + 0x6f)
  42:	8540      	ld.b	r2, (r5, 0x0)	// regs: r2=*(<arg1>)
  44:	6486      	cmpne	r1, r2
  46:	081a      	bt	0x7a	// if (T) goto loc_7a;
  48:	d8240070 	ld.b	r1, (r4, 0x70)	// regs: r1=*(r4 + 0x70)
  4c:	8541      	ld.b	r2, (r5, 0x1)	// regs: r2=*(<arg1> + 0x1)
  4e:	6486      	cmpne	r1, r2
  50:	0815      	bt	0x7a	// if (T) goto loc_7a;
  52:	d8240071 	ld.b	r1, (r4, 0x71)	// regs: r1=*(r4 + 0x71)
  56:	8542      	ld.b	r2, (r5, 0x2)	// regs: r2=*(<arg1> + 0x2)
  58:	6486      	cmpne	r1, r2
  5a:	0810      	bt	0x7a	// if (T) goto loc_7a;
  5c:	d8240072 	ld.b	r1, (r4, 0x72)	// regs: r1=*(r4 + 0x72)
  60:	8543      	ld.b	r2, (r5, 0x3)	// regs: r2=*(<arg1> + 0x3)
  62:	6486      	cmpne	r1, r2
  64:	080b      	bt	0x7a	// if (T) goto loc_7a;
  66:	d8240073 	ld.b	r1, (r4, 0x73)	// regs: r1=*(r4 + 0x73)
  6a:	8544      	ld.b	r2, (r5, 0x4)	// regs: r2=*(<arg1> + 0x4)
  6c:	6486      	cmpne	r1, r2
  6e:	0806      	bt	0x7a	// if (T) goto loc_7a;
  70:	d8240074 	ld.b	r1, (r4, 0x74)	// regs: r1=*(r4 + 0x74)
  74:	8545      	ld.b	r2, (r5, 0x5)	// regs: r2=*(<arg1> + 0x5)
  76:	6486      	cmpne	r1, r2
  78:	0fd3      	bf	0x1e	// if (!T) goto loc_1e;
loc_7a:
  7a:	9480      	ld.w	r4, (r4, 0x0)	// regs: r4=*(r4)
  7c:	07ce      	br	0x18	// goto loc_18;
  7e:	0000      	.short	0x0000
  80:	00000000 	.long	0x00000000	// <ah_lmac+0xa00>
  84:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_sta_put:

00000000 <lmac_sta_put>: // arg_bytes: 4
   0:	14d2      	push	r4-r5, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	3100      	movi	r1, 0	// regs: r1=0x0
   6:	2900      	subi	r1, 1	// regs: r1=0xffffffff
   8:	101c      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0xa>, r1=<clobbered>
   e:	e904002c 	bez	r4, 0x66	// if (r4 == 0x0) goto loc_66;
  12:	e0000000 	bsr	0x0	// <cpu_intrpt_save>; regs: r0=<ret cpu_intrpt_save@0x12>, r1=<clobbered>
  16:	9465      	ld.w	r3, (r4, 0x14)	// regs: r3=*(<arg0> + 0x14)
  18:	e903002d 	bez	r3, 0x72	// if (r3 == 0x0) goto loc_72;
  1c:	2b00      	subi	r3, 1	// regs: r3=(*(<arg0> + 0x14) - 0x1)
  1e:	3b40      	cmpnei	r3, 0
  20:	b465      	st.w	r3, (r4, 0x14)	// *(<arg0> + 0x14) = (*(<arg0> + 0x14) - 0x1)
  22:	6543      	mvcv	r5	// regs: r5=<cond>
loc_24:
  24:	e0000000 	bsr	0x0	// <cpu_intrpt_restore>; regs: r0=<ret cpu_intrpt_restore@0x24>, r1=<clobbered>
  28:	e905001f 	bez	r5, 0x66	// if (r5 == 0x0) goto loc_66;
  2c:	1074      	lrw	r3, 0x0	// regs: r3=0x0
  2e:	d8241034 	ld.h	r1, (r4, 0x68)	// regs: r1=*(<arg0> + 0x68)
  32:	d8431504 	ld.h	r2, (r3, 0xa08)	// regs: r2=*(0xa08)
  36:	2a00      	subi	r2, 1	// regs: r2=(*(0xa08) - 0x1)
  38:	1012      	lrw	r0, 0x0	// regs: r0=0x0
  3a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x3a>, r1=<clobbered>
  3e:	9461      	ld.w	r3, (r4, 0x4)	// regs: r3=*(<arg0> + 0x4)
  40:	9440      	ld.w	r2, (r4, 0x0)	// regs: r2=*(<arg0>)
  42:	e9030006 	bez	r3, 0x4e	// if (r3 == 0x0) goto loc_4e;
  46:	e9020004 	bez	r2, 0x4e	// if (r2 == 0x0) goto loc_4e;
  4a:	b261      	st.w	r3, (r2, 0x4)	// *((*(<arg0>) + 0x4)) = *(<arg0> + 0x4)
  4c:	b340      	st.w	r2, (r3, 0x0)	// *(*(<arg0> + 0x4)) = *(<arg0>)
loc_4e:
  4e:	3500      	movi	r5, 0	// regs: r5=0x0
  50:	d8042027 	ld.w	r0, (r4, 0x9c)	// regs: r0=*(<arg0> + 0x9c)
  54:	b4a0      	st.w	r5, (r4, 0x0)	// *(<arg0>) = 0x0
  56:	b4a1      	st.w	r5, (r4, 0x4)	// *(<arg0> + 0x4) = 0x0
  58:	e0000000 	bsr	0x0	// <_os_free>; regs: r0=<ret _os_free@0x58>, r1=<clobbered>
  5c:	dca42027 	st.w	r5, (r4, 0x9c)	// *(<arg0> + 0x9c) = 0x0
  60:	6c13      	mov	r0, r4	// regs: r0=<arg0>
  62:	e0000000 	bsr	0x0	// <_os_free>; regs: r0=<ret _os_free@0x62>, r1=<clobbered>
loc_66:
  66:	e0000000 	bsr	0x0	// <lmac_psm_info_update> // arg_bytes: 0; regs: r0=<ret lmac_psm_info_update@0x66>, r1=<clobbered>
  6a:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  6c:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0x6c>, r1=<clobbered>
  70:	1492      	pop	r4-r5, r15
loc_72:
  72:	3501      	movi	r5, 1	// regs: r5=0x1
  74:	07d8      	br	0x24	// goto loc_24;
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000	// <ah_lmac+0xa00>
  7c:	0000      	.short	0x0000	// <ah_lmac>
  7e:	0000      	.short	0x0000
  80:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_put.str1.1>

Disassembly of section .text.lmac_sta_del:

00000000 <lmac_sta_del>: // arg_bytes: 12
   0:	14d6      	push	r4-r9, r15
   2:	6d87      	mov	r6, r1	// regs: r6=<arg1>
   4:	12b7      	lrw	r5, 0x0	// regs: r5=0x0
   6:	3100      	movi	r1, 0	// regs: r1=0x0
   8:	6e43      	mov	r9, r0	// regs: r9=<arg0>
   a:	2900      	subi	r1, 1	// regs: r1=0xffffffff
   c:	1216      	lrw	r0, 0x0	// regs: r0=0x0
   e:	6e3f      	mov	r8, r15	// regs: r8=lr
  10:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0x10>, r1=<clobbered>
  14:	d885227e 	ld.w	r4, (r5, 0x9f8)	// regs: r4=*(0x9f8)
  18:	e44509f7 	addi	r2, r5, 2552	// regs: r2=0x9f8
  1c:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(*(0x9f8))
  1e:	6dcb      	mov	r7, r2	// regs: r7=0x9f8
loc_20:
  20:	6492      	cmpne	r4, r2
  22:	0c40      	bf	0xa2	// if (!T) goto loc_a2;
  24:	eb49ffff 	cmpnei	r9, 65535
  28:	0c58      	bf	0xd8	// if (r9 == 0xffff) goto loc_d8;
  2a:	d8241034 	ld.h	r1, (r4, 0x68)	// regs: r1=*(r4 + 0x68)
  2e:	6646      	cmpne	r1, r9
  30:	0854      	bt	0xd8	// if (T) goto loc_d8;
loc_32:
  32:	d8641034 	ld.h	r3, (r4, 0x68)	// regs: r3=*(r4 + 0x68)
  36:	e9030074 	bez	r3, 0x11e	// if (r3 == 0x0) goto loc_11e;
loc_3a:
  3a:	d864006b 	ld.b	r3, (r4, 0x6b)	// regs: r3=*(r4 + 0x6b)
  3e:	e4432020 	andi	r2, r3, 32	// regs: r2=(*(r4 + 0x6b) & 0x20)
  42:	e9220078 	bnez	r2, 0x132	// if (r2 != 0x0) goto loc_132;
  46:	3601      	movi	r6, 1	// regs: r6=0x1
  48:	c4665c05 	ins	r3, r6, 5, 5
  4c:	dc64006b 	st.b	r3, (r4, 0x6b)	// *(r4 + 0x6b) = *(r4 + 0x6b)
  50:	e0000000 	bsr	0x0	// <cpu_intrpt_save>; regs: r0=<ret cpu_intrpt_save@0x50>, r1=<clobbered>
  54:	9465      	ld.w	r3, (r4, 0x14)	// regs: r3=*(r4 + 0x14)
  56:	e9030006 	bez	r3, 0x62	// if (r3 == 0x0) goto loc_62;
  5a:	2b00      	subi	r3, 1	// regs: r3=(*(r4 + 0x14) - 0x1)
  5c:	3b40      	cmpnei	r3, 0
  5e:	b465      	st.w	r3, (r4, 0x14)	// *(r4 + 0x14) = (*(r4 + 0x14) - 0x1)
  60:	6583      	mvcv	r6	// regs: r6=<cond>
loc_62:
  62:	e0000000 	bsr	0x0	// <cpu_intrpt_restore>; regs: r0=<ret cpu_intrpt_restore@0x62>, r1=<clobbered>
  66:	d8241034 	ld.h	r1, (r4, 0x68)	// regs: r1=*(r4 + 0x68)
  6a:	e906005d 	bez	r6, 0x124	// if (r6 == 0x0) goto loc_124;
  6e:	d8451504 	ld.h	r2, (r5, 0xa08)	// regs: r2=*(0xa08)
  72:	7445      	zexth	r1, r1	// regs: r1=zext16(*(r4 + 0x68))
  74:	111d      	lrw	r0, 0x0	// regs: r0=0x0
  76:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x76>, r1=<clobbered>
  7a:	9461      	ld.w	r3, (r4, 0x4)	// regs: r3=*(r4 + 0x4)
  7c:	9440      	ld.w	r2, (r4, 0x0)	// regs: r2=*(r4)
  7e:	e9030006 	bez	r3, 0x8a	// if (r3 == 0x0) goto loc_8a;
  82:	e9020004 	bez	r2, 0x8a	// if (r2 == 0x0) goto loc_8a;
  86:	b261      	st.w	r3, (r2, 0x4)	// *((*(r4) + 0x4)) = *(r4 + 0x4)
  88:	b340      	st.w	r2, (r3, 0x0)	// *(*(r4 + 0x4)) = *(r4)
loc_8a:
  8a:	3600      	movi	r6, 0	// regs: r6=0x0
  8c:	d8042027 	ld.w	r0, (r4, 0x9c)	// regs: r0=*(r4 + 0x9c)
  90:	b4c0      	st.w	r6, (r4, 0x0)	// *(r4) = 0x0
  92:	b4c1      	st.w	r6, (r4, 0x4)	// *(r4 + 0x4) = 0x0
  94:	e0000000 	bsr	0x0	// <_os_free>; regs: r0=<ret _os_free@0x94>, r1=<clobbered>
  98:	dcc42027 	st.w	r6, (r4, 0x9c)	// *(r4 + 0x9c) = 0x0
  9c:	6c13      	mov	r0, r4	// regs: r0=r4
  9e:	e0000000 	bsr	0x0	// <_os_free>; regs: r0=<ret _os_free@0x9e>, r1=<clobbered>
loc_a2:
  a2:	3000      	movi	r0, 0	// regs: r0=0x0
  a4:	d865227e 	ld.w	r3, (r5, 0x9f8)	// regs: r3=*(0x9f8)
  a8:	6c43      	mov	r1, r0	// regs: r1=0x0
  aa:	ea0d0001 	movi	r13, 1	// regs: r13=0x1
loc_ae:
  ae:	65ce      	cmpne	r3, r7
  b0:	0845      	bt	0x13a	// if (T) goto loc_13a;
  b2:	dc05229d 	st.w	r0, (r5, 0xa74)	// *(0xa74) = r0
  b6:	dc25229c 	st.w	r1, (r5, 0xa70)	// *(0xa70) = r1
  ba:	110d      	lrw	r0, 0x0	// regs: r0=0x0
  bc:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xbc>, r1=<clobbered>
  c0:	d825229d 	ld.w	r1, (r5, 0xa74)	// regs: r1=*(0xa74)
  c4:	110b      	lrw	r0, 0x0	// regs: r0=0x0
  c6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xc6>, r1=<clobbered>
  ca:	e0000000 	bsr	0x0	// <lmac_psm_info_update> // arg_bytes: 0; regs: r0=<ret lmac_psm_info_update@0xca>, r1=<clobbered>
  ce:	1106      	lrw	r0, 0x0	// regs: r0=0x0
  d0:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0xd0>, r1=<clobbered>
  d4:	3000      	movi	r0, 0	// regs: r0=0x0
  d6:	1496      	pop	r4-r9, r15
loc_d8:
  d8:	e9060020 	bez	r6, 0x118	// if (r6 == 0x0) goto loc_118;
  dc:	d804006f 	ld.b	r0, (r4, 0x6f)	// regs: r0=*(r4 + 0x6f)
  e0:	8620      	ld.b	r1, (r6, 0x0)	// regs: r1=*(<arg1>)
  e2:	6442      	cmpne	r0, r1
  e4:	081a      	bt	0x118	// if (T) goto loc_118;
  e6:	d8040070 	ld.b	r0, (r4, 0x70)	// regs: r0=*(r4 + 0x70)
  ea:	8621      	ld.b	r1, (r6, 0x1)	// regs: r1=*(<arg1> + 0x1)
  ec:	6442      	cmpne	r0, r1
  ee:	0815      	bt	0x118	// if (T) goto loc_118;
  f0:	d8040071 	ld.b	r0, (r4, 0x71)	// regs: r0=*(r4 + 0x71)
  f4:	8622      	ld.b	r1, (r6, 0x2)	// regs: r1=*(<arg1> + 0x2)
  f6:	6442      	cmpne	r0, r1
  f8:	0810      	bt	0x118	// if (T) goto loc_118;
  fa:	d8040072 	ld.b	r0, (r4, 0x72)	// regs: r0=*(r4 + 0x72)
  fe:	8623      	ld.b	r1, (r6, 0x3)	// regs: r1=*(<arg1> + 0x3)
 100:	6442      	cmpne	r0, r1
 102:	080b      	bt	0x118	// if (T) goto loc_118;
 104:	d8040073 	ld.b	r0, (r4, 0x73)	// regs: r0=*(r4 + 0x73)
 108:	8624      	ld.b	r1, (r6, 0x4)	// regs: r1=*(<arg1> + 0x4)
 10a:	6442      	cmpne	r0, r1
 10c:	0806      	bt	0x118	// if (T) goto loc_118;
 10e:	d8040074 	ld.b	r0, (r4, 0x74)	// regs: r0=*(r4 + 0x74)
 112:	8625      	ld.b	r1, (r6, 0x5)	// regs: r1=*(<arg1> + 0x5)
 114:	6442      	cmpne	r0, r1
 116:	0f8e      	bf	0x32	// if (!T) goto loc_32;
loc_118:
 118:	6d0f      	mov	r4, r3	// regs: r4=r3
 11a:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(r3)
 11c:	0782      	br	0x20	// goto loc_20;
loc_11e:
 11e:	dc65202f 	st.w	r3, (r5, 0xbc)	// *(0xbc) = *(r4 + 0x68)
 122:	078c      	br	0x3a	// goto loc_3a;
loc_124:
 124:	7485      	zexth	r2, r1	// regs: r2=zext16(*(r4 + 0x68))
 126:	6ce3      	mov	r3, r8	// regs: r3=lr
 128:	9425      	ld.w	r1, (r4, 0x14)	// regs: r1=*(r4 + 0x14)
 12a:	1013      	lrw	r0, 0x0	// regs: r0=0x0
 12c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x12c>, r1=<clobbered>
 130:	07b9      	br	0xa2	// goto loc_a2;
loc_132:
 132:	1012      	lrw	r0, 0x0	// regs: r0=0x0
 134:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x134>, r1=<clobbered>
 138:	07b5      	br	0xa2	// goto loc_a2;
loc_13a:
 13a:	d8431034 	ld.h	r2, (r3, 0x68)	// regs: r2=*(r3 + 0x68)
 13e:	3a1f      	cmphsi	r2, 32
 140:	0804      	bt	0x148	// if (r2 >= 0x20) goto loc_148;
 142:	c44d402c 	lsl	r12, r13, r2
 146:	6c70      	or	r1, r12	// regs: r1=(r1 | r12)
loc_148:
 148:	d983006b 	ld.b	r12, (r3, 0x6b)	// regs: r12=*(r3 + 0x6b)
 14c:	e58c2002 	andi	r12, r12, 2	// regs: r12=(*(r3 + 0x6b) & 0x2)
 150:	e90c0005 	bez	r12, 0x15a	// if (r12 == 0x0) goto loc_15a;
 154:	c44d4022 	lsl	r2, r13, r2
 158:	6c08      	or	r0, r2	// regs: r0=(r0 | *(r3 + 0x68))
loc_15a:
 15a:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(r3)
 15c:	07a9      	br	0xae	// goto loc_ae;
 15e:	0000      	.short	0x0000
 160:	00000000 	.long	0x00000000	// <ah_lmac>
 164:	00000000 	.long	0x00000000	// <ah_lmac+0xa00>
 168:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_del.str1.1>
 16c:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_del.str1.1+0x43>
 170:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_del.str1.1+0x52>
 174:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_del.str1.1+0x1c>
 178:	00000000 	.long	0x00000000	// <.rodata.lmac_sta_del.str1.1+0x38>

Disassembly of section .text.get_icmp_seq_num:

00000000 <get_icmp_seq_num>: // arg_bytes: 4
   0:	d8600029 	ld.b	r3, (r0, 0x29)	// regs: r3=*(<arg0> + 0x29)
   4:	3b41      	cmpnei	r3, 1
   6:	0808      	bt	0x16	// if (r3 != 0x1) goto loc_16;
   8:	d860003a 	ld.b	r3, (r0, 0x3a)	// regs: r3=*(<arg0> + 0x3a)
   c:	4368      	lsli	r3, r3, 8	// regs: r3=(*(<arg0> + 0x3a) << 0x8)
   e:	d800003b 	ld.b	r0, (r0, 0x3b)	// regs: r0=*(<arg0> + 0x3b)
  12:	600c      	addu	r0, r3	// regs: r0=(*(<arg0> + 0x3b) + (*(<arg0> + 0x3a) << 0x8))
loc_14:
  14:	783c      	jmp	r15	// return;
loc_16:
  16:	3000      	movi	r0, 0	// regs: r0=0x0
  18:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  1a:	07fd      	br	0x14	// goto loc_14;

Disassembly of section .text.partial_bssid_calc:

00000000 <partial_bssid_calc>: // arg_bytes: 4
   0:	8065      	ld.b	r3, (r0, 0x5)	// regs: r3=*(<arg0> + 0x5)
   2:	4368      	lsli	r3, r3, 8	// regs: r3=(*(<arg0> + 0x5) << 0x8)
   4:	8004      	ld.b	r0, (r0, 0x4)	// regs: r0=*(<arg0> + 0x4)
   6:	600c      	addu	r0, r3	// regs: r0=(*(<arg0> + 0x4) + (*(<arg0> + 0x5) << 0x8))
   8:	ea0201ff 	movi	r2, 511	// regs: r2=0x1ff
   c:	c4e056c0 	zext	r0, r0, 22, 7	// regs: r0=zext((*(<arg0> + 0x4) + (*(<arg0> + 0x5) << 0x8)))
  10:	c4408023 	divu	r3, r0, r2	// regs: r3=(zext((*(<arg0> + 0x4) + (*(<arg0> + 0x5) << 0x8))) / 0x1ff)
  14:	7cc8      	mult	r3, r2	// regs: r3=((zext((*(<arg0> + 0x4) + (*(<arg0> + 0x5) << 0x8))) / 0x1ff) * 0x1ff)
  16:	600e      	subu	r0, r3	// regs: r0=(zext((*(<arg0> + 0x4) + (*(<arg0> + 0x5) << 0x8))) - ((zext((*(<arg0> + 0x4) + (*(<arg0> + 0x5) << 0x8))) / 0x1ff) * 0x1ff))
  18:	2000      	addi	r0, 1	// regs: r0=((zext((*(<arg0> + 0x4) + (*(<arg0> + 0x5) << 0x8))) - ((zext((*(<arg0> + 0x4) + (*(<arg0> + 0x5) << 0x8))) / 0x1ff) * 0x1ff)) + 0x1)
  1a:	7401      	zexth	r0, r0	// regs: r0=zext16(((zext((*(<arg0> + 0x4) + (*(<arg0> + 0x5) << 0x8))) - ((zext((*(<arg0> + 0x4) + (*(<arg0> + 0x5) << 0x8))) / 0x1ff) * 0x1ff)) + 0x1))
  1c:	783c      	jmp	r15	// return;

Disassembly of section .text.partial_aid_ndp_calc:

00000000 <partial_aid_ndp_calc>: // arg_bytes: 12
   0:	8165      	ld.b	r3, (r1, 0x5)	// regs: r3=*(<arg1> + 0x5)
   2:	4b44      	lsri	r2, r3, 4	// regs: r2=(*(<arg1> + 0x5) >> 0x4)
   4:	6cc9      	xor	r3, r2	// regs: r3=(*(<arg1> + 0x5) ^ (*(<arg1> + 0x5) >> 0x4))
   6:	4365      	lsli	r3, r3, 5	// regs: r3=((*(<arg1> + 0x5) ^ (*(<arg1> + 0x5) >> 0x4)) << 0x5)
   8:	600c      	addu	r0, r3	// regs: r0=(<arg0> + ((*(<arg1> + 0x5) ^ (*(<arg1> + 0x5) >> 0x4)) << 0x5))
   a:	e40021ff 	andi	r0, r0, 511	// regs: r0=((<arg0> + ((*(<arg1> + 0x5) ^ (*(<arg1> + 0x5) >> 0x4)) << 0x5)) & 0x1ff)
   e:	783c      	jmp	r15	// return;

Disassembly of section .text.partial_aid_calc:

00000000 <partial_aid_calc>: // arg_bytes: 12
   0:	8165      	ld.b	r3, (r1, 0x5)	// regs: r3=*(<arg1> + 0x5)
   2:	4b44      	lsri	r2, r3, 4	// regs: r2=(*(<arg1> + 0x5) >> 0x4)
   4:	6cc9      	xor	r3, r2	// regs: r3=(*(<arg1> + 0x5) ^ (*(<arg1> + 0x5) >> 0x4))
   6:	4365      	lsli	r3, r3, 5	// regs: r3=((*(<arg1> + 0x5) ^ (*(<arg1> + 0x5) >> 0x4)) << 0x5)
   8:	600c      	addu	r0, r3	// regs: r0=(<arg0> + ((*(<arg1> + 0x5) ^ (*(<arg1> + 0x5) >> 0x4)) << 0x5))
   a:	e400203f 	andi	r0, r0, 63	// regs: r0=((<arg0> + ((*(<arg1> + 0x5) ^ (*(<arg1> + 0x5) >> 0x4)) << 0x5)) & 0x3f)
   e:	783c      	jmp	r15	// return;

Disassembly of section .text.element_short_beacon_interval_hdl:

00000000 <element_short_beacon_interval_hdl>: // arg_bytes: 4
   0:	8061      	ld.b	r3, (r0, 0x1)	// regs: r3=*(<arg0> + 0x1)
   2:	3b42      	cmpnei	r3, 2
   4:	0812      	bt	0x28	// if (r3 != 0x2) goto loc_28;
   6:	8063      	ld.b	r3, (r0, 0x3)	// regs: r3=*(<arg0> + 0x3)
   8:	8042      	ld.b	r2, (r0, 0x2)	// regs: r2=*(<arg0> + 0x2)
   a:	4368      	lsli	r3, r3, 8	// regs: r3=(*(<arg0> + 0x3) << 0x8)
   c:	6cc8      	or	r3, r2	// regs: r3=((*(<arg0> + 0x3) << 0x8) | *(<arg0> + 0x2))
   e:	1048      	lrw	r2, 0x0	// regs: r2=0x0
  10:	74cf      	sexth	r3, r3	// regs: r3=sext16(((*(<arg0> + 0x3) << 0x8) | *(<arg0> + 0x2)))
  12:	dc620656 	st.b	r3, (r2, 0x656)	// *(0x656) = sext16(((*(<arg0> + 0x3) << 0x8) | *(<arg0> + 0x2)))
  16:	c50355e3 	zext	r3, r3, 15, 8	// regs: r3=zext(sext16(((*(<arg0> + 0x3) << 0x8) | *(<arg0> + 0x2))))
  1a:	dc620657 	st.b	r3, (r2, 0x657)	// *(0x657) = zext(sext16(((*(<arg0> + 0x3) << 0x8) | *(<arg0> + 0x2))))
  1e:	d862132b 	ld.h	r3, (r2, 0x656)	// regs: r3=*(0x656)
  22:	436a      	lsli	r3, r3, 10	// regs: r3=(*(0x656) << 0xa)
  24:	dc622196 	st.w	r3, (r2, 0x658)	// *(0x658) = (*(0x656) << 0xa)
loc_28:
  28:	783c      	jmp	r15	// return;
  2a:	0000      	.short	0x0000
  2c:	0000      	.short	0x0000	// <ah_lmac>
  2e:	0000      	.short	0x0000

Disassembly of section .text.calc_bitmap_offset:

00000000 <calc_bitmap_offset>: // arg_bytes: 8
   0:	6441      	cmplt	r0, r1
   2:	5825      	subu	r1, r0, r1	// regs: r1=(<arg0> - <arg1>)
   4:	0809      	bt	0x16	// if (T) goto loc_16;
loc_6:
   6:	7447      	sexth	r1, r1	// regs: r1=sext16(r1)
   8:	3000      	movi	r0, 0	// regs: r0=0x0
   a:	eb21003f 	cmplti	r1, 64
   e:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  10:	c4010c40 	inct	r0, r1, 0
  14:	783c      	jmp	r15	// return;
loc_16:
  16:	e4210fff 	addi	r1, r1, 4096	// regs: r1=((<arg0> - <arg1>) + 0x1000)
  1a:	07f6      	br	0x6	// goto loc_6;

Disassembly of section .text.lmac_update_pv0_cfend_addr:

00000000 <lmac_update_pv0_cfend_addr>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	100b      	lrw	r0, 0x0	// regs: r0=0x0
   4:	3206      	movi	r2, 6	// regs: r2=0x6
   6:	d860202f 	ld.w	r3, (r0, 0xbc)	// regs: r3=*(0xbc)
   a:	3b42      	cmpnei	r3, 2
   c:	080d      	bt	0x26	// if (r3 != 0x2) goto loc_26;
   e:	1029      	lrw	r1, 0x0	// regs: r1=0x0
loc_10:
  10:	e400095b 	addi	r0, r0, 2396	// regs: r0=0x95c
  14:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x14>, r1=<clobbered>
  18:	1027      	lrw	r1, 0x0	// regs: r1=0x0
  1a:	3206      	movi	r2, 6	// regs: r2=0x6
  1c:	e401065f 	addi	r0, r1, 1632	// regs: r0=0x660
  20:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x20>, r1=<clobbered>
  24:	1490      	pop	r15
loc_26:
  26:	e4200525 	addi	r1, r0, 1318	// regs: r1=0x526
  2a:	07f3      	br	0x10	// goto loc_10;
  2c:	0000      	.short	0x0000	// <ah_lmac>
  2e:	0000      	.short	0x0000
  30:	00000000 	.long	0x00000000	// <.rodata.broadcast_addr>
  34:	00000000 	.long	0x00000000	// <ah_lmac+0x302>

Disassembly of section .text.lmac_amp_atten_calc:

00000000 <lmac_amp_atten_calc>: // arg_bytes: 12
   0:	14d3      	push	r4-r6, r15
   2:	6f0b      	mov	r12, r2	// regs: r12=<arg2>
   4:	6d83      	mov	r6, r0	// regs: r6=<arg0>
   6:	3200      	movi	r2, 0	// regs: r2=0x0
   8:	ea234034 	movih	r3, 16436	// regs: r3=(0x4034 << 0x10)
   c:	6c07      	mov	r0, r1	// regs: r0=<arg1>
   e:	6c73      	mov	r1, r12	// regs: r1=<arg2>
  10:	e0000000 	bsr	0x0	// <__divdf3>; regs: r0=<ret __divdf3@0x10>, r1=<clobbered>
  14:	6c83      	mov	r2, r0	// regs: r2=<ret __divdf3@0x10>
  16:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
  18:	3000      	movi	r0, 0	// regs: r0=0x0
  1a:	ea214024 	movih	r1, 16420	// regs: r1=(0x4024 << 0x10)
  1e:	e0000000 	bsr	0x0	// <pow>; regs: r0=<ret pow@0x1e>, r1=<clobbered>
  22:	6d43      	mov	r5, r0	// regs: r5=<ret pow@0x1e>
  24:	6d07      	mov	r4, r1	// regs: r4=<clobbered>
  26:	6c1b      	mov	r0, r6	// regs: r0=<arg0>
  28:	e0000000 	bsr	0x0	// <__floatunsidf>; regs: r0=<ret __floatunsidf@0x28>, r1=<clobbered>
  2c:	6cd3      	mov	r3, r4	// regs: r3=<clobbered>
  2e:	6c97      	mov	r2, r5	// regs: r2=<ret pow@0x1e>
  30:	e0000000 	bsr	0x0	// <__divdf3>; regs: r0=<ret __divdf3@0x30>, r1=<clobbered>
  34:	e0000000 	bsr	0x0	// <__fixunsdfsi>; regs: r0=<ret __fixunsdfsi@0x34>, r1=<clobbered>
  38:	6cc3      	mov	r3, r0	// regs: r3=<ret __fixunsdfsi@0x34>
  3a:	7401      	zexth	r0, r0	// regs: r0=zext16(<ret __fixunsdfsi@0x34>)
  3c:	eb0007ff 	cmphsi	r0, 2048
  40:	0c03      	bf	0x46	// if (r0 < 0x800) goto loc_46;
  42:	ea0307ff 	movi	r3, 2047	// regs: r3=0x7ff
loc_46:
  46:	740d      	zexth	r0, r3	// regs: r0=zext16(r3)
  48:	1493      	pop	r4-r6, r15

Disassembly of section .text.lmac_next_dtim_calc:

00000000 <lmac_next_dtim_calc>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	1070      	lrw	r3, 0x0	// regs: r3=0x0
   4:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   6:	d9832005 	ld.w	r12, (r3, 0x14)	// regs: r12=*((*(0x0) + 0x14))
   a:	9344      	ld.w	r2, (r3, 0x10)	// regs: r2=*((*(0x0) + 0x10))
   c:	106e      	lrw	r3, 0x0	// regs: r3=0x0
   e:	d8032196 	ld.w	r0, (r3, 0x658)	// regs: r0=*(0x658)
  12:	e9000013 	bez	r0, 0x38	// if (r0 == 0x0) goto loc_38;
  16:	d8830556 	ld.b	r4, (r3, 0x556)	// regs: r4=*(0x556)
  1a:	e9040010 	bez	r4, 0x3a	// if (r4 == 0x0) goto loc_3a;
  1e:	7d00      	mult	r4, r0	// regs: r4=(*(0x556) * *(0x658))
  20:	3000      	movi	r0, 0	// regs: r0=0x0
  22:	6c73      	mov	r1, r12	// regs: r1=*((*(0x0) + 0x14))
  24:	6f43      	mov	r13, r0	// regs: r13=0x0
  26:	6f0b      	mov	r12, r2	// regs: r12=*((*(0x0) + 0x10))
  28:	6cc3      	mov	r3, r0	// regs: r3=0x0
  2a:	6c93      	mov	r2, r4	// regs: r2=(*(0x556) * *(0x658))
  2c:	6401      	cmplt	r0, r0
  2e:	6031      	addc	r0, r12
  30:	6075      	addc	r1, r13
  32:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x32>, r1=<clobbered>
  36:	5c01      	subu	r0, r4, r0	// regs: r0=((*(0x556) * *(0x658)) - <ret __umoddi3@0x32>)
loc_38:
  38:	1491      	pop	r4, r15
loc_3a:
  3a:	6c13      	mov	r0, r4	// regs: r0=*(0x556)
  3c:	07fe      	br	0x38	// goto loc_38;
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <LMAC>
  42:	0000      	.short	0x0000
  44:	0000      	.short	0x0000	// <ah_lmac>
  46:	0000      	.short	0x0000

Disassembly of section .text.lmac_bkn_dly_calc:

00000000 <lmac_bkn_dly_calc>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	106f      	lrw	r3, 0x0	// regs: r3=0x0
   4:	102f      	lrw	r1, 0x0	// regs: r1=0x0
   6:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   8:	d8812196 	ld.w	r4, (r1, 0x658)	// regs: r4=*(0x658)
   c:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*((*(0x0) + 0x14))
   e:	9364      	ld.w	r3, (r3, 0x10)	// regs: r3=*((*(0x0) + 0x10))
  10:	e9040013 	bez	r4, 0x36	// if (r4 == 0x0) goto loc_36;
  14:	3000      	movi	r0, 0	// regs: r0=0x0
  16:	6f0f      	mov	r12, r3	// regs: r12=*((*(0x0) + 0x10))
  18:	6c4b      	mov	r1, r2	// regs: r1=*((*(0x0) + 0x14))
  1a:	6f43      	mov	r13, r0	// regs: r13=0x0
  1c:	6cc3      	mov	r3, r0	// regs: r3=0x0
  1e:	6c93      	mov	r2, r4	// regs: r2=*(0x658)
  20:	6401      	cmplt	r0, r0
  22:	6031      	addc	r0, r12
  24:	6075      	addc	r1, r13
  26:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x26>, r1=<clobbered>
  2a:	4c61      	lsri	r3, r4, 1	// regs: r3=(*(0x658) >> 0x1)
  2c:	640c      	cmphs	r3, r0
  2e:	5891      	subu	r4, r0, r4	// regs: r4=(<ret __umoddi3@0x26> - *(0x658))
  30:	c4040c20 	incf	r0, r4, 0
loc_34:
  34:	1491      	pop	r4, r15
loc_36:
  36:	6c13      	mov	r0, r4	// regs: r0=*(0x658)
  38:	07fe      	br	0x34	// goto loc_34;
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <LMAC>
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <ah_lmac>
  42:	0000      	.short	0x0000

Disassembly of section .text.lmac_beacon_timer_start:

00000000 <lmac_beacon_timer_start>: // arg_bytes: 4
   0:	106a      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   4:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
   8:	ec420002 	ori	r2, r2, 2	// regs: r2=(*((*(0x0) + 0xcc)) | 0x2)
   c:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x2)
  10:	3280      	movi	r2, 128	// regs: r2=0x80
  12:	4246      	lsli	r2, r2, 6	// regs: r2=0x2000
  14:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x2000
  16:	dc032030 	st.w	r0, (r3, 0xc0)	// *((*(0x0) + 0xc0)) = <arg0>
  1a:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
  1e:	ec420001 	ori	r2, r2, 1	// regs: r2=(*((*(0x0) + 0xcc)) | 0x1)
  22:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x1)
  26:	783c      	jmp	r15	// return;
  28:	0000      	.short	0x0000	// <LMAC>
  2a:	0000      	.short	0x0000

Disassembly of section .text.lmac_beacon_timer_abort:

00000000 <lmac_beacon_timer_abort>: // arg_bytes: 0
   0:	1066      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   4:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
   8:	ec420002 	ori	r2, r2, 2	// regs: r2=(*((*(0x0) + 0xcc)) | 0x2)
   c:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x2)
  10:	3280      	movi	r2, 128	// regs: r2=0x80
  12:	4246      	lsli	r2, r2, 6	// regs: r2=0x2000
  14:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x2000
  16:	783c      	jmp	r15	// return;
  18:	00000000 	.long	0x00000000	// <LMAC>

Disassembly of section .text.lf_timer_start:

00000000 <lf_timer_start>: // arg_bytes: 4
   0:	106a      	lrw	r3, 0x0	// regs: r3=0x0
   2:	4805      	lsri	r0, r0, 5	// regs: r0=(<arg0> >> 0x5)
   4:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   6:	d8432032 	ld.w	r2, (r3, 0xc8)	// regs: r2=*((*(0x0) + 0xc8))
   a:	dc432032 	st.w	r2, (r3, 0xc8)	// *((*(0x0) + 0xc8)) = *((*(0x0) + 0xc8))
   e:	d8432032 	ld.w	r2, (r3, 0xc8)	// regs: r2=*((*(0x0) + 0xc8))
  12:	6c08      	or	r0, r2	// regs: r0=((<arg0> >> 0x5) | *((*(0x0) + 0xc8)))
  14:	dc032032 	st.w	r0, (r3, 0xc8)	// *((*(0x0) + 0xc8)) = ((<arg0> >> 0x5) | *((*(0x0) + 0xc8)))
  18:	d8432033 	ld.w	r2, (r3, 0xcc)	// regs: r2=*((*(0x0) + 0xcc))
  1c:	ec420010 	ori	r2, r2, 16	// regs: r2=(*((*(0x0) + 0xcc)) | 0x10)
  20:	dc432033 	st.w	r2, (r3, 0xcc)	// *((*(0x0) + 0xcc)) = (*((*(0x0) + 0xcc)) | 0x10)
  24:	783c      	jmp	r15	// return;
  26:	0000      	.short	0x0000
  28:	0000      	.short	0x0000	// <LMAC>
  2a:	0000      	.short	0x0000

Disassembly of section .text.lmac_qa_results_valid_check:

00000000 <lmac_qa_results_valid_check>: // arg_bytes: 0
   0:	1269      	lrw	r3, 0x0	// regs: r3=0x0
   2:	d84308c0 	ld.b	r2, (r3, 0x8c0)	// regs: r2=*(0x8c0)
   6:	d98308ac 	ld.b	r12, (r3, 0x8ac)	// regs: r12=*(0x8ac)
   a:	d823089c 	ld.b	r1, (r3, 0x89c)	// regs: r1=*(0x89c)
   e:	e4022001 	andi	r0, r2, 1	// regs: r0=(*(0x8c0) & 0x1)
  12:	7732      	sextb	r12, r12	// regs: r12=sext8(*(0x8ac))
  14:	7446      	sextb	r1, r1	// regs: r1=sext8(*(0x89c))
  16:	6471      	cmplt	r12, r1
  18:	e9000056 	bez	r0, 0xc4	// if (r0 == 0x0) goto loc_c4;
  1c:	c4000500 	mvc	r0	// regs: r0=<cond>
  20:	3100      	movi	r1, 0	// regs: r1=0x0
  22:	5901      	subu	r0, r1, r0	// regs: r0=(0x0 - <cond>)
loc_24:
  24:	e4222002 	andi	r1, r2, 2	// regs: r1=(*(0x8c0) & 0x2)
  28:	d9a348ad 	ld.bs	r13, (r3, 0x8ad)	// regs: r13=*(0x8ad)
  2c:	d983489d 	ld.bs	r12, (r3, 0x89d)	// regs: r12=*(0x89d)
  30:	e901004d 	bez	r1, 0xca	// if (r1 == 0x0) goto loc_ca;
  34:	3100      	movi	r1, 0	// regs: r1=0x0
  36:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  38:	6771      	cmplt	r12, r13
  3a:	c4010c40 	inct	r0, r1, 0
loc_3e:
  3e:	e4422004 	andi	r2, r2, 4	// regs: r2=(*(0x8c0) & 0x4)
  42:	d98348ae 	ld.bs	r12, (r3, 0x8ae)	// regs: r12=*(0x8ae)
  46:	e9020048 	bez	r2, 0xd6	// if (r2 == 0x0) goto loc_d6;
  4a:	d843489e 	ld.bs	r2, (r3, 0x89e)	// regs: r2=*(0x89e)
  4e:	6709      	cmplt	r2, r12
  50:	084e      	bt	0xec	// if (T) goto loc_ec;
  52:	3100      	movi	r1, 0	// regs: r1=0x0
  54:	604a      	subu	r1, r2	// regs: r1=(0x0 - *(0x89e))
  56:	3200      	movi	r2, 0	// regs: r2=0x0
  58:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
  5a:	6471      	cmplt	r12, r1
  5c:	c4020c40 	inct	r0, r2, 0
loc_60:
  60:	d84308c1 	ld.b	r2, (r3, 0x8c1)	// regs: r2=*(0x8c1)
  64:	e5a22001 	andi	r13, r2, 1	// regs: r13=(*(0x8c1) & 0x1)
  68:	d98308b6 	ld.b	r12, (r3, 0x8b6)	// regs: r12=*(0x8b6)
  6c:	d82308a4 	ld.b	r1, (r3, 0x8a4)	// regs: r1=*(0x8a4)
  70:	7732      	sextb	r12, r12	// regs: r12=sext8(*(0x8b6))
  72:	7446      	sextb	r1, r1	// regs: r1=sext8(*(0x8a4))
  74:	e90d003f 	bez	r13, 0xf2	// if (r13 == 0x0) goto loc_f2;
  78:	ea0d0000 	movi	r13, 0	// regs: r13=0x0
  7c:	e5ad1000 	subi	r13, r13, 1	// regs: r13=0xffffffff
  80:	6471      	cmplt	r12, r1
  82:	c40d0c40 	inct	r0, r13, 0
loc_86:
  86:	e4222002 	andi	r1, r2, 2	// regs: r1=(*(0x8c1) & 0x2)
  8a:	d9a348b7 	ld.bs	r13, (r3, 0x8b7)	// regs: r13=*(0x8b7)
  8e:	d98348a5 	ld.bs	r12, (r3, 0x8a5)	// regs: r12=*(0x8a5)
  92:	e9010038 	bez	r1, 0x102	// if (r1 == 0x0) goto loc_102;
  96:	3100      	movi	r1, 0	// regs: r1=0x0
  98:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  9a:	6771      	cmplt	r12, r13
  9c:	c4010c40 	inct	r0, r1, 0
loc_a0:
  a0:	e4422004 	andi	r2, r2, 4	// regs: r2=(*(0x8c1) & 0x4)
  a4:	d82348b8 	ld.bs	r1, (r3, 0x8b8)	// regs: r1=*(0x8b8)
  a8:	d86348a6 	ld.bs	r3, (r3, 0x8a6)	// regs: r3=*(0x8a6)
  ac:	644d      	cmplt	r3, r1
  ae:	e9020030 	bez	r2, 0x10e	// if (r2 == 0x0) goto loc_10e;
  b2:	0836      	bt	0x11e	// if (T) goto loc_11e;
  b4:	3200      	movi	r2, 0	// regs: r2=0x0
  b6:	608e      	subu	r2, r3	// regs: r2=(0x0 - *(0x8a6))
  b8:	3300      	movi	r3, 0	// regs: r3=0x0
  ba:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
  bc:	6485      	cmplt	r1, r2
  be:	c4030c40 	inct	r0, r3, 0
loc_c2:
  c2:	783c      	jmp	r15	// return;
loc_c4:
  c4:	6443      	mvcv	r1	// regs: r1=<cond>
  c6:	6006      	subu	r0, r1	// regs: r0=((*(0x8c0) & 0x1) - <cond>)
  c8:	07ae      	br	0x24	// goto loc_24;
loc_ca:
  ca:	3100      	movi	r1, 0	// regs: r1=0x0
  cc:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  ce:	6771      	cmplt	r12, r13
  d0:	c4010c20 	incf	r0, r1, 0
  d4:	07b5      	br	0x3e	// goto loc_3e;
loc_d6:
  d6:	d823489e 	ld.bs	r1, (r3, 0x89e)	// regs: r1=*(0x89e)
  da:	6705      	cmplt	r1, r12
  dc:	0bc2      	bt	0x60	// if (T) goto loc_60;
  de:	6086      	subu	r2, r1	// regs: r2=((*(0x8c0) & 0x4) - *(0x89e))
  e0:	3100      	movi	r1, 0	// regs: r1=0x0
  e2:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  e4:	64b1      	cmplt	r12, r2
  e6:	c4010c20 	incf	r0, r1, 0
  ea:	07bb      	br	0x60	// goto loc_60;
loc_ec:
  ec:	3000      	movi	r0, 0	// regs: r0=0x0
  ee:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  f0:	07b8      	br	0x60	// goto loc_60;
loc_f2:
  f2:	ea0d0000 	movi	r13, 0	// regs: r13=0x0
  f6:	e5ad1000 	subi	r13, r13, 1	// regs: r13=0xffffffff
  fa:	6471      	cmplt	r12, r1
  fc:	c40d0c20 	incf	r0, r13, 0
 100:	07c3      	br	0x86	// goto loc_86;
loc_102:
 102:	3100      	movi	r1, 0	// regs: r1=0x0
 104:	2900      	subi	r1, 1	// regs: r1=0xffffffff
 106:	6771      	cmplt	r12, r13
 108:	c4010c20 	incf	r0, r1, 0
 10c:	07ca      	br	0xa0	// goto loc_a0;
loc_10e:
 10e:	0bda      	bt	0xc2	// if (T) goto loc_c2;
 110:	608e      	subu	r2, r3	// regs: r2=((*(0x8c1) & 0x4) - *(0x8a6))
 112:	3300      	movi	r3, 0	// regs: r3=0x0
 114:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 116:	6485      	cmplt	r1, r2
 118:	c4030c20 	incf	r0, r3, 0
 11c:	07d3      	br	0xc2	// goto loc_c2;
loc_11e:
 11e:	3000      	movi	r0, 0	// regs: r0=0x0
 120:	2800      	subi	r0, 1	// regs: r0=0xffffffff
 122:	07d0      	br	0xc2	// goto loc_c2;
 124:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_rx_dbg_info:

00000000 <lmac_rx_dbg_info>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	1100      	lrw	r0, 0x0	// regs: r0=0x0
   4:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x4>, r1=<clobbered>
   8:	3400      	movi	r4, 0	// regs: r4=0x0
   a:	10bf      	lrw	r5, 0x0	// regs: r5=0x0
loc_c:
   c:	ea038000 	movi	r3, 32768	// regs: r3=0x8000
  10:	3bbe      	bseti	r3, 30	// regs: r3=(0x8000 | (0x1 << 0x1e))
  12:	60d0      	addu	r3, r4	// regs: r3=((0x8000 | (0x1 << 0x1e)) + r4)
  14:	6c53      	mov	r1, r4	// regs: r1=r4
  16:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(((0x8000 | (0x1 << 0x1e)) + r4))
  18:	6c17      	mov	r0, r5	// regs: r0=0x0
  1a:	2403      	addi	r4, 4	// regs: r4=(r4 + 0x4)
  1c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1c>, r1=<clobbered>
  20:	eb440630 	cmpnei	r4, 1584
  24:	0bf4      	bt	0xc	// if (r4 != 0x630) goto loc_c;
  26:	1019      	lrw	r0, 0x0	// regs: r0=0x0
  28:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x28>, r1=<clobbered>
  2c:	3400      	movi	r4, 0	// regs: r4=0x0
  2e:	10b8      	lrw	r5, 0x0	// regs: r5=0x0
loc_30:
  30:	ea234002 	movih	r3, 16386	// regs: r3=(0x4002 << 0x10)
  34:	3bae      	bseti	r3, 14	// regs: r3=((0x4002 << 0x10) | (0x1 << 0xe))
  36:	60d0      	addu	r3, r4	// regs: r3=(((0x4002 << 0x10) | (0x1 << 0xe)) + r4)
  38:	6c53      	mov	r1, r4	// regs: r1=r4
  3a:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((((0x4002 << 0x10) | (0x1 << 0xe)) + r4))
  3c:	6c17      	mov	r0, r5	// regs: r0=0x0
  3e:	2403      	addi	r4, 4	// regs: r4=(r4 + 0x4)
  40:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x40>, r1=<clobbered>
  44:	eb44023c 	cmpnei	r4, 572
  48:	0bf4      	bt	0x30	// if (r4 != 0x23c) goto loc_30;
  4a:	3400      	movi	r4, 0	// regs: r4=0x0
  4c:	10b1      	lrw	r5, 0x0	// regs: r5=0x0
  4e:	10d2      	lrw	r6, 0x0	// regs: r6=0x0
loc_50:
  50:	9560      	ld.w	r3, (r5, 0x0)	// regs: r3=*(0x0)
  52:	d8632105 	ld.w	r3, (r3, 0x414)	// regs: r3=*((*(0x0) + 0x414))
  56:	e463207f 	andi	r3, r3, 127	// regs: r3=(*((*(0x0) + 0x414)) & 0x7f)
  5a:	64d0      	cmphs	r4, r3
  5c:	0c03      	bf	0x62	// if (!T) goto loc_62;
  5e:	3000      	movi	r0, 0	// regs: r0=0x0
  60:	1493      	pop	r4-r6, r15
loc_62:
  62:	6c53      	mov	r1, r4	// regs: r1=r4
  64:	6c1b      	mov	r0, r6	// regs: r0=0x0
  66:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x66>, r1=<clobbered>
  6a:	e4440083 	addi	r2, r4, 132	// regs: r2=(r4 + 0x84)
  6e:	9560      	ld.w	r3, (r5, 0x0)	// regs: r3=*(0x0)
  70:	d0430900 	ldr.w	r0, (r3, r2 << 3)	// regs: r0=*(*(0x0) + ((r4 + 0x84) << 3))
  74:	3160      	movi	r1, 96	// regs: r1=0x60
  76:	e0000000 	bsr	0x0	// <hgics_print_hex> // arg_bytes: 8; regs: r0=<ret hgics_print_hex@0x76>, r1=<clobbered>
  7a:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  7c:	07ea      	br	0x50	// goto loc_50;
  7e:	0000      	.short	0x0000
  80:	00000000 	.long	0x00000000	// <.rodata.lmac_rx_dbg_info.str1.1>
  84:	00000000 	.long	0x00000000	// <.rodata.lmac_rx_dbg_info.str1.1+0xd>
  88:	0000      	.short	0x0000	// <.rodata.lmac_rx_dbg_info.str1.1+0x20>
  8a:	0000      	.short	0x0000
  8c:	00000000 	.long	0x00000000	// <.rodata.lmac_rx_dbg_info.str1.1+0x2c>
  90:	00000000 	.long	0x00000000	// <LMAC>
  94:	00000000 	.long	0x00000000	// <.rodata.lmac_rx_dbg_info.str1.1+0x3f>

Disassembly of section .text.lmac_adc_dump:

00000000 <lmac_adc_dump>: // arg_bytes: 12
   0:	14d4      	push	r4-r7, r15
   2:	1182      	lrw	r4, 0x0	// regs: r4=0x0
   4:	6dc7      	mov	r7, r1	// regs: r7=<arg1>
   6:	d8640333 	ld.b	r3, (r4, 0x333)	// regs: r3=*(0x333)
   a:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x333) & 0x1)
   e:	6d8b      	mov	r6, r2	// regs: r6=<arg2>
  10:	e903003a 	bez	r3, 0x84	// if (r3 == 0x0) goto loc_84;
  14:	d8640332 	ld.b	r3, (r4, 0x332)	// regs: r3=*(0x332)
  18:	640e      	cmpne	r3, r0
  1a:	0835      	bt	0x84	// if (T) goto loc_84;
  1c:	c0006025 	mfcr	r5, cr<0, 0>
  20:	c0807020 	psrclr	ie
  24:	3000      	movi	r0, 0	// regs: r0=0x0
  26:	e0000000 	bsr	0x0	// <mcu_watchdog_timeout>; regs: r0=<ret mcu_watchdog_timeout@0x26>, r1=<clobbered>
  2a:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  2e:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  32:	e4a52040 	andi	r5, r5, 64	// regs: r5=(r5 & 0x40)
  36:	e9030005 	bez	r3, 0x40	// if (r3 == 0x0) goto loc_40;
  3a:	3000      	movi	r0, 0	// regs: r0=0x0
  3c:	e0000000 	bsr	0x0	// <disable_print>; regs: r0=<ret disable_print@0x3c>, r1=<clobbered>
loc_40:
  40:	e0000000 	bsr	0x0	// <lmac_rx_dbg_info> // arg_bytes: 0; regs: r0=<ret lmac_rx_dbg_info@0x40>, r1=<clobbered>
  44:	1012      	lrw	r0, 0x0	// regs: r0=0x0
  46:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x46>, r1=<clobbered>
  4a:	6c5b      	mov	r1, r6	// regs: r1=<arg2>
  4c:	6c1f      	mov	r0, r7	// regs: r0=<arg1>
  4e:	e0000000 	bsr	0x0	// <hgics_print_hex> // arg_bytes: 8; regs: r0=<ret hgics_print_hex@0x4e>, r1=<clobbered>
  52:	6c9b      	mov	r2, r6	// regs: r2=<arg2>
  54:	d8240332 	ld.b	r1, (r4, 0x332)	// regs: r1=*(0x332)
  58:	100e      	lrw	r0, 0x0	// regs: r0=0x0
  5a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x5a>, r1=<clobbered>
  5e:	3300      	movi	r3, 0	// regs: r3=0x0
  60:	dc640332 	st.b	r3, (r4, 0x332)	// *(0x332) = 0x0
  64:	d86409e2 	ld.b	r3, (r4, 0x9e2)	// regs: r3=*(0x9e2)
  68:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  6c:	e9030005 	bez	r3, 0x76	// if (r3 == 0x0) goto loc_76;
  70:	3001      	movi	r0, 1	// regs: r0=0x1
  72:	e0000000 	bsr	0x0	// <disable_print>; regs: r0=<ret disable_print@0x72>, r1=<clobbered>
loc_76:
  76:	3005      	movi	r0, 5	// regs: r0=0x5
  78:	e0000000 	bsr	0x0	// <mcu_watchdog_timeout>; regs: r0=<ret mcu_watchdog_timeout@0x78>, r1=<clobbered>
  7c:	e9050004 	bez	r5, 0x84	// if (r5 == 0x0) goto loc_84;
  80:	c0807420 	psrset	ie
loc_84:
  84:	3000      	movi	r0, 0	// regs: r0=0x0
  86:	1494      	pop	r4-r7, r15
  88:	0000      	.short	0x0000	// <ah_lmac>
  8a:	0000      	.short	0x0000
  8c:	00000000 	.long	0x00000000	// <.rodata.lmac_adc_dump.str1.1>
  90:	00000000 	.long	0x00000000	// <.rodata.lmac_adc_dump.str1.1+0xf>

Disassembly of section .text.lmac_tdma_start:

00000000 <lmac_tdma_start>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <ah_tdma_abort>; regs: r0=<ret ah_tdma_abort@0x2>, r1=<clobbered>
   6:	e0000000 	bsr	0x0	// <ah_tdma_start>; regs: r0=<ret ah_tdma_start@0x6>, r1=<clobbered>
   a:	1490      	pop	r15

Disassembly of section .text.lmac_is_icmp_ping:

00000000 <lmac_is_icmp_ping>: // arg_bytes: 4
   0:	14d1      	push	r4, r15
   2:	8066      	ld.b	r3, (r0, 0x6)	// regs: r3=*(<arg0> + 0x6)
   4:	4368      	lsli	r3, r3, 8	// regs: r3=(*(<arg0> + 0x6) << 0x8)
   6:	8047      	ld.b	r2, (r0, 0x7)	// regs: r2=*(<arg0> + 0x7)
   8:	6cc8      	or	r3, r2	// regs: r3=((*(<arg0> + 0x6) << 0x8) | *(<arg0> + 0x7))
   a:	74cf      	sexth	r3, r3	// regs: r3=sext16(((*(<arg0> + 0x6) << 0x8) | *(<arg0> + 0x7)))
   c:	eb430800 	cmpnei	r3, 2048
  10:	0813      	bt	0x36	// if (r3 != 0x800) goto loc_36;
  12:	8068      	ld.b	r3, (r0, 0x8)	// regs: r3=*(<arg0> + 0x8)
  14:	eb430045 	cmpnei	r3, 69
  18:	080f      	bt	0x36	// if (r3 != 0x45) goto loc_36;
  1a:	8091      	ld.b	r4, (r0, 0x11)	// regs: r4=*(<arg0> + 0x11)
  1c:	3c41      	cmpnei	r4, 1
  1e:	080c      	bt	0x36	// if (r4 != 0x1) goto loc_36;
  20:	d8600022 	ld.b	r3, (r0, 0x22)	// regs: r3=*(<arg0> + 0x22)
  24:	d8200023 	ld.b	r1, (r0, 0x23)	// regs: r1=*(<arg0> + 0x23)
  28:	4368      	lsli	r3, r3, 8	// regs: r3=(*(<arg0> + 0x22) << 0x8)
  2a:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  2c:	6c4c      	or	r1, r3	// regs: r1=(*(<arg0> + 0x23) | (*(<arg0> + 0x22) << 0x8))
  2e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2e>, r1=<clobbered>
  32:	6c13      	mov	r0, r4	// regs: r0=*(<arg0> + 0x11)
loc_34:
  34:	1491      	pop	r4, r15
loc_36:
  36:	3000      	movi	r0, 0	// regs: r0=0x0
  38:	07fe      	br	0x34	// goto loc_34;
  3a:	0000      	.short	0x0000
  3c:	0000      	.short	0x0000	// <.rodata.lmac_is_icmp_ping.str1.1>
  3e:	0000      	.short	0x0000

Disassembly of section .text.dsleep_dur_calc:

00000000 <dsleep_dur_calc>: // arg_bytes: 8
   0:	14c5      	push	r4-r8
   2:	1073      	lrw	r3, 0x0	// regs: r3=0x0
   4:	1053      	lrw	r2, 0x0	// regs: r2=0x0
   6:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   8:	d9832005 	ld.w	r12, (r3, 0x14)	// regs: r12=*((*(0x0) + 0x14))
   c:	d9032004 	ld.w	r8, (r3, 0x10)	// regs: r8=*((*(0x0) + 0x10))
  10:	d8620556 	ld.b	r3, (r2, 0x556)	// regs: r3=*(0x556)
  14:	d8422196 	ld.w	r2, (r2, 0x658)	// regs: r2=*(0x658)
  18:	7cc8      	mult	r3, r2	// regs: r3=(*(0x556) * *(0x658))
  1a:	e9030011 	bez	r3, 0x3c	// if (r3 == 0x0) goto loc_3c;
  1e:	3600      	movi	r6, 0	// regs: r6=0x0
  20:	6df3      	mov	r7, r12	// regs: r7=*((*(0x0) + 0x14))
  22:	6f5b      	mov	r13, r6	// regs: r13=0x0
  24:	6f23      	mov	r12, r8	// regs: r12=*((*(0x0) + 0x10))
  26:	6731      	cmplt	r12, r12
  28:	6319      	addc	r12, r6
  2a:	635d      	addc	r13, r7
loc_2c:
  2c:	6474      	cmphs	r13, r1
  2e:	0c05      	bf	0x38	// if (!T) goto loc_38;
  30:	6746      	cmpne	r1, r13
  32:	0807      	bt	0x40	// if (T) goto loc_40;
  34:	6430      	cmphs	r12, r0
  36:	0805      	bt	0x40	// if (T) goto loc_40;
loc_38:
  38:	60f2      	subu	r3, r12	// regs: r3=(r3 - r12)
  3a:	60c0      	addu	r3, r0	// regs: r3=((r3 - r12) + r0)
loc_3c:
  3c:	6c0f      	mov	r0, r3	// regs: r0=r3
  3e:	1485      	pop	r4-r8
loc_40:
  40:	6d0f      	mov	r4, r3	// regs: r4=r3
  42:	3500      	movi	r5, 0	// regs: r5=0x0
  44:	6401      	cmplt	r0, r0
  46:	6011      	addc	r0, r4
  48:	6055      	addc	r1, r5
  4a:	07f1      	br	0x2c	// goto loc_2c;
  4c:	00000000 	.long	0x00000000	// <LMAC>
  50:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_rx_gain_cfg:

00000000 <lmac_rx_gain_cfg>: // arg_bytes: 4
   0:	14d2      	push	r4-r5, r15
   2:	586f      	subi	r3, r0, 4	// regs: r3=(<arg0> - 0x4)
   4:	74cc      	zextb	r3, r3	// regs: r3=zext8((<arg0> - 0x4))
   6:	3b01      	cmphsi	r3, 2
   8:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   a:	0c06      	bf	0x16	// if (r3 < 0x2) goto loc_16;
   c:	6c43      	mov	r1, r0	// regs: r1=<arg0>
   e:	100a      	lrw	r0, 0x0	// regs: r0=0x0
  10:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x10>, r1=<clobbered>
loc_14:
  14:	1492      	pop	r4-r5, r15
loc_16:
  16:	10a9      	lrw	r5, 0x0	// regs: r5=0x0
  18:	d8250308 	ld.b	r1, (r5, 0x308)	// regs: r1=*(0x308)
  1c:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_rx_gain>; regs: r0=<ret ah_rfdigicali_config_rx_gain@0x1c>, r1=<clobbered>
  20:	6c13      	mov	r0, r4	// regs: r0=<arg0>
  22:	e0000000 	bsr	0x0	// <ah_wphy_rx_gain_stage_cfg>; regs: r0=<ret ah_wphy_rx_gain_stage_cfg@0x22>, r1=<clobbered>
  26:	d86511b1 	ld.h	r3, (r5, 0x362)	// regs: r3=*(0x362)
  2a:	c4645ce4 	ins	r3, r4, 11, 4
  2e:	dc6511b1 	st.h	r3, (r5, 0x362)	// *(0x362) = *(0x362)
  32:	07f1      	br	0x14	// goto loc_14;
  34:	00000000 	.long	0x00000000	// <.rodata.lmac_rx_gain_cfg.str1.1>
  38:	0000      	.short	0x0000	// <ah_lmac>
  3a:	0000      	.short	0x0000

Disassembly of section .text.lmac_get_avg_power:

00000000 <lmac_get_avg_power>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <ah_wphy_avg_power_get>; regs: r0=<ret ah_wphy_avg_power_get@0x2>, r1=<clobbered>
   6:	e9200009 	bnez	r0, 0x18	// if (r0 != 0x0) goto loc_18;
   a:	104a      	lrw	r2, 0x0	// regs: r2=0x0
   c:	d8621402 	ld.h	r3, (r2, 0x804)	// regs: r3=*(0x804)
  10:	2300      	addi	r3, 1	// regs: r3=(*(0x804) + 0x1)
  12:	dc621402 	st.h	r3, (r2, 0x804)	// *(0x804) = (*(0x804) + 0x1)
loc_16:
  16:	1490      	pop	r15
loc_18:
  18:	3300      	movi	r3, 0	// regs: r3=0x0
  1a:	2b7f      	subi	r3, 128	// regs: r3=0xffffff80
  1c:	64c2      	cmpne	r0, r3
  1e:	0bfc      	bt	0x16	// if (T) goto loc_16;
  20:	1044      	lrw	r2, 0x0	// regs: r2=0x0
  22:	d8621403 	ld.h	r3, (r2, 0x806)	// regs: r3=*(0x806)
  26:	2300      	addi	r3, 1	// regs: r3=(*(0x806) + 0x1)
  28:	dc621403 	st.h	r3, (r2, 0x806)	// *(0x806) = (*(0x806) + 0x1)
  2c:	07f5      	br	0x16	// goto loc_16;
  2e:	0000      	.short	0x0000
  30:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_arp_data_det:

00000000 <lmac_arp_data_det>: // arg_bytes: 4
   0:	d8604000 	ld.bs	r3, (r0, 0x0)	// regs: r3=*(<arg0>)
   4:	3bdf      	btsti	r3, 31
   6:	321a      	movi	r2, 26	// regs: r2=0x1a
   8:	3318      	movi	r3, 24	// regs: r3=0x18
   a:	c4620c40 	inct	r3, r2, 0
   e:	600c      	addu	r0, r3	// regs: r0=(<arg0> + 0x18)
  10:	8066      	ld.b	r3, (r0, 0x6)	// regs: r3=*(<arg0> + 0x1e)
  12:	8047      	ld.b	r2, (r0, 0x7)	// regs: r2=*(<arg0> + 0x1f)
  14:	4368      	lsli	r3, r3, 8	// regs: r3=(*(<arg0> + 0x1e) << 0x8)
  16:	6cc8      	or	r3, r2	// regs: r3=((*(<arg0> + 0x1e) << 0x8) | *(<arg0> + 0x1f))
  18:	74cf      	sexth	r3, r3	// regs: r3=sext16(((*(<arg0> + 0x1e) << 0x8) | *(<arg0> + 0x1f)))
  1a:	eb430806 	cmpnei	r3, 2054
  1e:	6403      	mvcv	r0	// regs: r0=<cond>
  20:	783c      	jmp	r15	// return;

Disassembly of section .text.data_scrambler:

00000000 <data_scrambler>: // arg_bytes: 4
   0:	14c3      	push	r4-r6
   2:	3300      	movi	r3, 0	// regs: r3=0x0
   4:	c4605cc0 	ins	r3, r0, 6, 0
   8:	c423542c 	zext	r12, r3, 1, 1	// regs: r12=zext(0x0)
   c:	e5a32001 	andi	r13, r3, 1	// regs: r13=(0x0 & 0x1)
  10:	c4835486 	zext	r6, r3, 4, 4	// regs: r6=zext(0x0)
  14:	c58d2442 	xor	r2, r13, r12	// regs: r2=((0x0 & 0x1) ^ zext(0x0))
  18:	c4435441 	zext	r1, r3, 2, 2	// regs: r1=zext(0x0)
  1c:	6c99      	xor	r2, r6	// regs: r2=(((0x0 & 0x1) ^ zext(0x0)) ^ zext(0x0))
  1e:	3000      	movi	r0, 0	// regs: r0=0x0
  20:	c4a354a5 	zext	r5, r3, 5, 5	// regs: r5=zext(0x0)
  24:	c4025c00 	ins	r0, r2, 0, 0
  28:	c42c2442 	xor	r2, r12, r1	// regs: r2=(zext(0x0) ^ zext(0x0))
  2c:	6c95      	xor	r2, r5	// regs: r2=((zext(0x0) ^ zext(0x0)) ^ zext(0x0))
  2e:	c4025c01 	ins	r0, r2, 1, 1
  32:	c4635462 	zext	r2, r3, 3, 3	// regs: r2=zext(0x0)
  36:	c4412444 	xor	r4, r1, r2	// regs: r4=(zext(0x0) ^ zext(0x0))
  3a:	c4c354c3 	zext	r3, r3, 6, 6	// regs: r3=zext(0x0)
  3e:	6d0d      	xor	r4, r3	// regs: r4=((zext(0x0) ^ zext(0x0)) ^ zext(0x0))
  40:	c4045c02 	ins	r0, r4, 2, 2
  44:	6f49      	xor	r13, r2	// regs: r13=((0x0 & 0x1) ^ zext(0x0))
  46:	c40d5c03 	ins	r0, r13, 3, 3
  4a:	6f19      	xor	r12, r6	// regs: r12=(zext(0x0) ^ zext(0x0))
  4c:	c40c5c04 	ins	r0, r12, 4, 4
  50:	6c55      	xor	r1, r5	// regs: r1=(zext(0x0) ^ zext(0x0))
  52:	c4015c05 	ins	r0, r1, 5, 5
  56:	6cc9      	xor	r3, r2	// regs: r3=(zext(0x0) ^ zext(0x0))
  58:	c4035c06 	ins	r0, r3, 6, 6
  5c:	e400207f 	andi	r0, r0, 127	// regs: r0=(0x0 & 0x7f)
  60:	1483      	pop	r4-r6

Disassembly of section .text.lmac_get_beacon_retry_limit:

00000000 <lmac_get_beacon_retry_limit>: // arg_bytes: 0
   0:	104b      	lrw	r2, 0x0	// regs: r2=0x0
   2:	301f      	movi	r0, 31	// regs: r0=0x1f
   4:	d8222196 	ld.w	r1, (r2, 0x658)	// regs: r1=*(0x658)
   8:	d8620556 	ld.b	r3, (r2, 0x556)	// regs: r3=*(0x556)
   c:	7cc4      	mult	r3, r1	// regs: r3=(*(0x556) * *(0x658))
   e:	d842034a 	ld.b	r2, (r2, 0x34a)	// regs: r2=*(0x34a)
  12:	1028      	lrw	r1, 0x4e1fff	// regs: r1=0x4e1fff
  14:	64c4      	cmphs	r1, r3
  16:	e4422001 	andi	r2, r2, 1	// regs: r2=(*(0x34a) & 0x1)
  1a:	3307      	movi	r3, 7	// regs: r3=0x7
  1c:	c4600c20 	incf	r3, r0, 0
  20:	3a40      	cmpnei	r2, 0
  22:	3003      	movi	r0, 3	// regs: r0=0x3
  24:	c4030c20 	incf	r0, r3, 0
  28:	783c      	jmp	r15	// return;
  2a:	0000      	.short	0x0000
  2c:	0000      	.short	0x0000	// <ah_lmac>
  2e:	0000      	.short	0x0000
  30:	004e1fff 	.long	0x004e1fff

Disassembly of section .text.lmac_next_beacon_calc:

00000000 <lmac_next_beacon_calc>: // arg_bytes: 4
   0:	14d4      	push	r4-r7, r15
   2:	e0000000 	bsr	0x0	// <lmac_get_beacon_retry_limit> // arg_bytes: 0; regs: r0=<ret lmac_get_beacon_retry_limit@0x2>, r1=<clobbered>
   6:	11e2      	lrw	r7, 0x0	// regs: r7=0x0
   8:	1162      	lrw	r3, 0x0	// regs: r3=0x0
   a:	6d43      	mov	r5, r0	// regs: r5=<ret lmac_get_beacon_retry_limit@0x2>
   c:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   e:	d8c72196 	ld.w	r6, (r7, 0x658)	// regs: r6=*(0x658)
  12:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*((*(0x0) + 0x14))
  14:	9364      	ld.w	r3, (r3, 0x10)	// regs: r3=*((*(0x0) + 0x10))
  16:	e9060030 	bez	r6, 0x76	// if (r6 == 0x0) goto loc_76;
  1a:	3000      	movi	r0, 0	// regs: r0=0x0
  1c:	6f0f      	mov	r12, r3	// regs: r12=*((*(0x0) + 0x10))
  1e:	6c4b      	mov	r1, r2	// regs: r1=*((*(0x0) + 0x14))
  20:	6f43      	mov	r13, r0	// regs: r13=0x0
  22:	6cc3      	mov	r3, r0	// regs: r3=0x0
  24:	6c9b      	mov	r2, r6	// regs: r2=*(0x658)
  26:	6401      	cmplt	r0, r0
  28:	6031      	addc	r0, r12
  2a:	6075      	addc	r1, r13
  2c:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x2c>, r1=<clobbered>
  30:	5e81      	subu	r4, r6, r0	// regs: r4=(*(0x658) - <ret __umoddi3@0x2c>)
  32:	4e61      	lsri	r3, r6, 1	// regs: r3=(*(0x658) >> 0x1)
  34:	64d0      	cmphs	r4, r3
  36:	6190      	addu	r6, r4	// regs: r6=(*(0x658) + (*(0x658) - <ret __umoddi3@0x2c>))
  38:	c4860c20 	incf	r4, r6, 0
loc_3c:
  3c:	d8670555 	ld.b	r3, (r7, 0x555)	// regs: r3=*(0x555)
  40:	3b41      	cmpnei	r3, 1
  42:	0818      	bt	0x72	// if (r3 != 0x1) goto loc_72;
  44:	d8671505 	ld.h	r3, (r7, 0xa0a)	// regs: r3=*(0xa0a)
  48:	e9030015 	bez	r3, 0x72	// if (r3 == 0x0) goto loc_72;
  4c:	877f      	ld.b	r3, (r7, 0x1f)	// regs: r3=*(0x1f)
  4e:	5b2c      	addu	r1, r3, r3	// regs: r1=(*(0x1f) + *(0x1f))
  50:	604c      	addu	r1, r3	// regs: r1=((*(0x1f) + *(0x1f)) + *(0x1f))
  52:	4144      	lsli	r2, r1, 4	// regs: r2=(((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4)
  54:	6084      	addu	r2, r1	// regs: r2=((((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4) + ((*(0x1f) + *(0x1f)) + *(0x1f)))
  56:	60c8      	addu	r3, r2	// regs: r3=(*(0x1f) + ((((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4) + ((*(0x1f) + *(0x1f)) + *(0x1f))))
  58:	e443009f 	addi	r2, r3, 160	// regs: r2=((*(0x1f) + ((((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4) + ((*(0x1f) + *(0x1f)) + *(0x1f)))) + 0xa0)
  5c:	d827133a 	ld.h	r1, (r7, 0x674)	// regs: r1=*(0x674)
  60:	6084      	addu	r2, r1	// regs: r2=(((*(0x1f) + ((((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4) + ((*(0x1f) + *(0x1f)) + *(0x1f)))) + 0xa0) + *(0x674))
  62:	2d00      	subi	r5, 1	// regs: r5=(<ret lmac_get_beacon_retry_limit@0x2> - 0x1)
  64:	7c94      	mult	r2, r5	// regs: r2=((((*(0x1f) + ((((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4) + ((*(0x1f) + *(0x1f)) + *(0x1f)))) + 0xa0) + *(0x674)) * (<ret lmac_get_beacon_retry_limit@0x2> - 0x1))
  66:	4a41      	lsri	r2, r2, 1	// regs: r2=(((((*(0x1f) + ((((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4) + ((*(0x1f) + *(0x1f)) + *(0x1f)))) + 0xa0) + *(0x674)) * (<ret lmac_get_beacon_retry_limit@0x2> - 0x1)) >> 0x1)
  68:	608e      	subu	r2, r3	// regs: r2=((((((*(0x1f) + ((((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4) + ((*(0x1f) + *(0x1f)) + *(0x1f)))) + 0xa0) + *(0x674)) * (<ret lmac_get_beacon_retry_limit@0x2> - 0x1)) >> 0x1) - (*(0x1f) + ((((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4) + ((*(0x1f) + *(0x1f)) + *(0x1f)))))
  6a:	2a9f      	subi	r2, 160	// regs: r2=(((((((*(0x1f) + ((((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4) + ((*(0x1f) + *(0x1f)) + *(0x1f)))) + 0xa0) + *(0x674)) * (<ret lmac_get_beacon_retry_limit@0x2> - 0x1)) >> 0x1) - (*(0x1f) + ((((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4) + ((*(0x1f) + *(0x1f)) + *(0x1f))))) - 0xa0)
  6c:	6508      	cmphs	r2, r4
  6e:	0809      	bt	0x80	// if (T) goto loc_80;
  70:	610a      	subu	r4, r2	// regs: r4=(r4 - (((((((*(0x1f) + ((((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4) + ((*(0x1f) + *(0x1f)) + *(0x1f)))) + 0xa0) + *(0x674)) * (<ret lmac_get_beacon_retry_limit@0x2> - 0x1)) >> 0x1) - (*(0x1f) + ((((*(0x1f) + *(0x1f)) + *(0x1f)) << 0x4) + ((*(0x1f) + *(0x1f)) + *(0x1f))))) - 0xa0))
loc_72:
  72:	6c13      	mov	r0, r4	// regs: r0=r4
  74:	1494      	pop	r4-r7, r15
loc_76:
  76:	1008      	lrw	r0, 0x0	// regs: r0=0x0
  78:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x78>, r1=<clobbered>
  7c:	6d1b      	mov	r4, r6	// regs: r4=*(0x658)
  7e:	07df      	br	0x3c	// goto loc_3c;
loc_80:
  80:	6c53      	mov	r1, r4	// regs: r1=r4
  82:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  84:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x84>, r1=<clobbered>
  88:	07f5      	br	0x72	// goto loc_72;
  8a:	0000      	.short	0x0000
  8c:	00000000 	.long	0x00000000	// <ah_lmac>
  90:	00000000 	.long	0x00000000	// <LMAC>
  94:	00000000 	.long	0x00000000	// <.rodata.lmac_next_beacon_calc.str1.1>
  98:	0000      	.short	0x0000	// <.rodata.lmac_next_beacon_calc.str1.1+0x12>
  9a:	0000      	.short	0x0000

Disassembly of section .text.lmac_report_sleep_exit:

00000000 <lmac_report_sleep_exit>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	106a      	lrw	r3, 0x0	// regs: r3=0x0
   6:	dc0e0003 	st.b	r0, (r14, 0x3)	// local_1 = <arg0>
   a:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   c:	d9832009 	ld.w	r12, (r3, 0x24)	// regs: r12=*((*(0x0) + 0x24))
  10:	e90c000b 	bez	r12, 0x26	// if (r12 == 0x0) goto loc_26;
  14:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  16:	3300      	movi	r3, 0	// regs: r3=0x0
  18:	e44e0002 	addi	r2, r14, 3	// regs: r2=((sp - 0x4) + 0x3)
  1c:	3114      	movi	r1, 20	// regs: r1=0x14
  1e:	9000      	ld.w	r0, (r0, 0x0)	// regs: r0=*(0x0)
  20:	7bf1      	jsr	r12
loc_22:
  22:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  24:	1490      	pop	r15
loc_26:
  26:	3000      	movi	r0, 0	// regs: r0=0x0
  28:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  2a:	07fc      	br	0x22	// goto loc_22;
  2c:	0000      	.short	0x0000	// <ah_lmac>
  2e:	0000      	.short	0x0000
  30:	00000000 	.long	0x00000000	// <ah_ops>
