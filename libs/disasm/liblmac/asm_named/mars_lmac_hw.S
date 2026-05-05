
libs\obj\liblmac\mars_lmac_hw.o:     file format elf32-csky-little


Disassembly of section .text.lhw_enable_irq_ac:

00000000 <lhw_enable_irq_ac>: // arg_bytes: 0
   0:	1064      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   4:	9271      	ld.w	r3, (r2, 0x44)	// regs: r3=*((*(0x0) + 0x44))
   6:	ec630080 	ori	r3, r3, 128	// regs: r3=(*((*(0x0) + 0x44)) | 0x80)
   a:	b271      	st.w	r3, (r2, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x80)
   c:	783c      	jmp	r15	// return;
   e:	0000      	.short	0x0000
  10:	00000000 	.long	0x00000000	// <.data.LMAC>

Disassembly of section .text.lhw_start_rx:

00000000 <lhw_start_rx>: // arg_bytes: 4
   0:	1071      	lrw	r3, 0x0	// regs: r3=0x0
   2:	1032      	lrw	r1, 0xf000f0	// regs: r1=0xf000f0
   4:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   6:	934d      	ld.w	r2, (r3, 0x34)	// regs: r2=*((*(0x0) + 0x34))
   8:	6884      	and	r2, r1	// regs: r2=(*((*(0x0) + 0x34)) & 0xf000f0)
   a:	e922001c 	bnez	r2, 0x42	// if (r2 != 0x0) goto loc_42;
   e:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*((*(0x0) + 0x1c))
  10:	ea01ffff 	movi	r1, 65535	// regs: r1=0xffff
  14:	c7014901 	rotli	r1, r1, 24	// regs: r1=rotl(0xffff, 0x18)
  18:	6884      	and	r2, r1	// regs: r2=(*((*(0x0) + 0x1c)) & rotl(0xffff, 0x18))
  1a:	b347      	st.w	r2, (r3, 0x1c)	// *((*(0x0) + 0x1c)) = (*((*(0x0) + 0x1c)) & rotl(0xffff, 0x18))
  1c:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*((*(0x0) + 0x1c))
  1e:	4008      	lsli	r0, r0, 8	// regs: r0=(<arg0> << 0x8)
  20:	6c08      	or	r0, r2	// regs: r0=((<arg0> << 0x8) | *((*(0x0) + 0x1c)))
  22:	b307      	st.w	r0, (r3, 0x1c)	// *((*(0x0) + 0x1c)) = ((<arg0> << 0x8) | *((*(0x0) + 0x1c)))
  24:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
  26:	3a84      	bclri	r2, 4	// regs: r2=(*((*(0x0) + 0x30)) & ~(0x1 << 0x4))
  28:	3a85      	bclri	r2, 5	// regs: r2=((*((*(0x0) + 0x30)) & ~(0x1 << 0x4)) & ~(0x1 << 0x5))
  2a:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = ((*((*(0x0) + 0x30)) & ~(0x1 << 0x4)) & ~(0x1 << 0x5))
  2c:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
  2e:	ec420020 	ori	r2, r2, 32	// regs: r2=(*((*(0x0) + 0x30)) | 0x20)
  32:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) | 0x20)
  34:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
  36:	ec420001 	ori	r2, r2, 1	// regs: r2=(*((*(0x0) + 0x30)) | 0x1)
  3a:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) | 0x1)
  3c:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
  3e:	3a8d      	bclri	r2, 13	// regs: r2=(*((*(0x0) + 0x30)) & ~(0x1 << 0xd))
  40:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) & ~(0x1 << 0xd))
loc_42:
  42:	783c      	jmp	r15	// return;
  44:	00000000 	.long	0x00000000	// <.data.LMAC>
  48:	00f0      	.short	0x00f0
  4a:	00f0      	.short	0x00f0

Disassembly of section .text.lhw_abort_fsm:

00000000 <lhw_abort_fsm>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	1053      	lrw	r2, 0x0	// regs: r2=0x0
   4:	31a0      	movi	r1, 160	// regs: r1=0xa0
   6:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*(0x0)
   8:	4125      	lsli	r1, r1, 5	// regs: r1=0x1400
   a:	b332      	st.w	r1, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x1400
   c:	9311      	ld.w	r0, (r3, 0x44)	// regs: r0=*((*(0x0) + 0x44))
   e:	388a      	bclri	r0, 10	// regs: r0=(*((*(0x0) + 0x44)) & ~(0x1 << 0xa))
  10:	388c      	bclri	r0, 12	// regs: r0=((*((*(0x0) + 0x44)) & ~(0x1 << 0xa)) & ~(0x1 << 0xc))
  12:	b311      	st.w	r0, (r3, 0x44)	// *((*(0x0) + 0x44)) = ((*((*(0x0) + 0x44)) & ~(0x1 << 0xa)) & ~(0x1 << 0xc))
  14:	b332      	st.w	r1, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0x1400
  16:	932c      	ld.w	r1, (r3, 0x30)	// regs: r1=*((*(0x0) + 0x30))
  18:	ec210002 	ori	r1, r1, 2	// regs: r1=(*((*(0x0) + 0x30)) | 0x2)
  1c:	b32c      	st.w	r1, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) | 0x2)
  1e:	6d0b      	mov	r4, r2	// regs: r4=0x0
  20:	3314      	movi	r3, 20	// regs: r3=0x14
loc_22:
  22:	6c03      	mov	r0, r0	// regs: r0=((*((*(0x0) + 0x44)) & ~(0x1 << 0xa)) & ~(0x1 << 0xc))
  24:	2b00      	subi	r3, 1	// regs: r3=(r3 - 0x1)
  26:	e923fffe 	bnez	r3, 0x22	// if (r3 != 0x0) goto loc_22;
  2a:	e0000000 	bsr	0x0	// <lmac_rx_cleanup_info>; regs: r0=<ret lmac_rx_cleanup_info@0x2a>, r1=<clobbered>
  2e:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x0)
  30:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
  32:	ec420002 	ori	r2, r2, 2	// regs: r2=(*((*(0x0) + 0x30)) | 0x2)
  36:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) | 0x2)
  38:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  3a:	ec420400 	ori	r2, r2, 1024	// regs: r2=(*((*(0x0) + 0x44)) | 0x400)
  3e:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x400)
  40:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  42:	ec421000 	ori	r2, r2, 4096	// regs: r2=(*((*(0x0) + 0x44)) | 0x1000)
  46:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x1000)
  48:	1491      	pop	r4, r15
  4a:	0000      	.short	0x0000
  4c:	00000000 	.long	0x00000000	// <.data.LMAC>

Disassembly of section .text.lhw_get_cca_remain:

00000000 <lhw_get_cca_remain>: // arg_bytes: 0
   0:	1063      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   4:	9308      	ld.w	r0, (r3, 0x20)	// regs: r0=*((*(0x0) + 0x20))
   6:	e40027ff 	andi	r0, r0, 2047	// regs: r0=(*((*(0x0) + 0x20)) & 0x7ff)
   a:	783c      	jmp	r15	// return;
   c:	0000      	.short	0x0000	// <.data.LMAC>
   e:	0000      	.short	0x0000

Disassembly of section .text.lhw_start_cca:

00000000 <lhw_start_cca>: // arg_bytes: 8
   0:	380f      	cmphsi	r0, 16
   2:	106b      	lrw	r3, 0x0	// regs: r3=0x0
   4:	d9832000 	ld.w	r12, (r3, 0x0)	// regs: r12=*(0x0)
   8:	6cc3      	mov	r3, r0	// regs: r3=<arg0>
   a:	0c02      	bf	0xe	// if (r0 < 0x10) goto loc_e;
   c:	330f      	movi	r3, 15	// regs: r3=0xf
loc_e:
   e:	eb0107ff 	cmphsi	r1, 2048
  12:	74cc      	zextb	r3, r3	// regs: r3=zext8(r3)
  14:	436c      	lsli	r3, r3, 12	// regs: r3=(zext8(r3) << 0xc)
  16:	6c87      	mov	r2, r1	// regs: r2=<arg1>
  18:	0c03      	bf	0x1e	// if (r1 < 0x800) goto loc_1e;
  1a:	ea0207ff 	movi	r2, 2047	// regs: r2=0x7ff
loc_1e:
  1e:	7489      	zexth	r2, r2	// regs: r2=zext16(r2)
  20:	60c8      	addu	r3, r2	// regs: r3=((zext8(r3) << 0xc) + zext16(r2))
  22:	e46307ff 	addi	r3, r3, 2048	// regs: r3=(((zext8(r3) << 0xc) + zext16(r2)) + 0x800)
  26:	dc6c2008 	st.w	r3, (r12, 0x20)	// *((*(0x0) + 0x20)) = (((zext8(r3) << 0xc) + zext16(r2)) + 0x800)
  2a:	783c      	jmp	r15	// return;
  2c:	0000      	.short	0x0000	// <.data.LMAC>
  2e:	0000      	.short	0x0000

Disassembly of section .text.lhw_start_tx:

00000000 <lhw_start_tx>: // arg_bytes: 4
   0:	106c      	lrw	r3, 0x0	// regs: r3=0x0
   2:	3100      	movi	r1, 0	// regs: r1=0x0
   4:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   6:	29ff      	subi	r1, 256	// regs: r1=0xffffff00
   8:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*((*(0x0) + 0x1c))
   a:	6884      	and	r2, r1	// regs: r2=(*((*(0x0) + 0x1c)) & 0xffffff00)
   c:	b347      	st.w	r2, (r3, 0x1c)	// *((*(0x0) + 0x1c)) = (*((*(0x0) + 0x1c)) & 0xffffff00)
   e:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*((*(0x0) + 0x1c))
  10:	6c08      	or	r0, r2	// regs: r0=(<arg0> | *((*(0x0) + 0x1c)))
  12:	b307      	st.w	r0, (r3, 0x1c)	// *((*(0x0) + 0x1c)) = (<arg0> | *((*(0x0) + 0x1c)))
  14:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
  16:	3a84      	bclri	r2, 4	// regs: r2=(*((*(0x0) + 0x30)) & ~(0x1 << 0x4))
  18:	3a85      	bclri	r2, 5	// regs: r2=((*((*(0x0) + 0x30)) & ~(0x1 << 0x4)) & ~(0x1 << 0x5))
  1a:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = ((*((*(0x0) + 0x30)) & ~(0x1 << 0x4)) & ~(0x1 << 0x5))
  1c:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
  1e:	ec420010 	ori	r2, r2, 16	// regs: r2=(*((*(0x0) + 0x30)) | 0x10)
  22:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) | 0x10)
  24:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*((*(0x0) + 0x30))
  26:	ec420001 	ori	r2, r2, 1	// regs: r2=(*((*(0x0) + 0x30)) | 0x1)
  2a:	b34c      	st.w	r2, (r3, 0x30)	// *((*(0x0) + 0x30)) = (*((*(0x0) + 0x30)) | 0x1)
  2c:	783c      	jmp	r15	// return;
  2e:	0000      	.short	0x0000
  30:	0000      	.short	0x0000	// <.data.LMAC>
  32:	0000      	.short	0x0000

Disassembly of section .text.lhw_irq_init:

00000000 <lhw_irq_init>: // arg_bytes: 0
   0:	1078      	lrw	r3, 0x0	// regs: r3=0x0
   2:	3200      	movi	r2, 0	// regs: r2=0x0
   4:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   6:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = 0x0
   8:	2a00      	subi	r2, 1	// regs: r2=0xffffffff
   a:	b352      	st.w	r2, (r3, 0x48)	// *((*(0x0) + 0x48)) = 0xffffffff
   c:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
   e:	ec420080 	ori	r2, r2, 128	// regs: r2=(*((*(0x0) + 0x44)) | 0x80)
  12:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x80)
  14:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  16:	ec420020 	ori	r2, r2, 32	// regs: r2=(*((*(0x0) + 0x44)) | 0x20)
  1a:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x20)
  1c:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  1e:	ec420004 	ori	r2, r2, 4	// regs: r2=(*((*(0x0) + 0x44)) | 0x4)
  22:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x4)
  24:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  26:	ec420400 	ori	r2, r2, 1024	// regs: r2=(*((*(0x0) + 0x44)) | 0x400)
  2a:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x400)
  2c:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  2e:	ec428000 	ori	r2, r2, 32768	// regs: r2=(*((*(0x0) + 0x44)) | 0x8000)
  32:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x8000)
  34:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  36:	ec422000 	ori	r2, r2, 8192	// regs: r2=(*((*(0x0) + 0x44)) | 0x2000)
  3a:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x2000)
  3c:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  3e:	ec424000 	ori	r2, r2, 16384	// regs: r2=(*((*(0x0) + 0x44)) | 0x4000)
  42:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x4000)
  44:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  46:	3ab2      	bseti	r2, 18	// regs: r2=(*((*(0x0) + 0x44)) | (0x1 << 0x12))
  48:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | (0x1 << 0x12))
  4a:	ea0261a8 	movi	r2, 25000	// regs: r2=0x61a8
  4e:	b357      	st.w	r2, (r3, 0x5c)	// *((*(0x0) + 0x5c)) = 0x61a8
  50:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  52:	3ab4      	bseti	r2, 20	// regs: r2=(*((*(0x0) + 0x44)) | (0x1 << 0x14))
  54:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | (0x1 << 0x14))
  56:	9351      	ld.w	r2, (r3, 0x44)	// regs: r2=*((*(0x0) + 0x44))
  58:	ec421000 	ori	r2, r2, 4096	// regs: r2=(*((*(0x0) + 0x44)) | 0x1000)
  5c:	b351      	st.w	r2, (r3, 0x44)	// *((*(0x0) + 0x44)) = (*((*(0x0) + 0x44)) | 0x1000)
  5e:	783c      	jmp	r15	// return;
  60:	00000000 	.long	0x00000000	// <.data.LMAC>

Disassembly of section .text.lhw_cfg_sifs:

00000000 <lhw_cfg_sifs>: // arg_bytes: 12
   0:	1069      	lrw	r3, 0x0	// regs: r3=0x0
   2:	4128      	lsli	r1, r1, 8	// regs: r1=(<arg1> << 0x8)
   4:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   6:	6c40      	or	r1, r0	// regs: r1=((<arg1> << 0x8) | <arg0>)
   8:	d9832007 	ld.w	r12, (r3, 0x1c)	// regs: r12=*((*(0x0) + 0x1c))
   c:	ea0c0000 	movi	r12, 0	// regs: r12=0x0
  10:	dd832007 	st.w	r12, (r3, 0x1c)	// *((*(0x0) + 0x1c)) = 0x0
  14:	4258      	lsli	r2, r2, 24	// regs: r2=(<arg2> << 0x18)
  16:	d9832007 	ld.w	r12, (r3, 0x1c)	// regs: r12=*((*(0x0) + 0x1c))
  1a:	6c48      	or	r1, r2	// regs: r1=(((<arg1> << 0x8) | <arg0>) | (<arg2> << 0x18))
  1c:	6c70      	or	r1, r12	// regs: r1=((((<arg1> << 0x8) | <arg0>) | (<arg2> << 0x18)) | *((*(0x0) + 0x1c)))
  1e:	b327      	st.w	r1, (r3, 0x1c)	// *((*(0x0) + 0x1c)) = ((((<arg1> << 0x8) | <arg0>) | (<arg2> << 0x18)) | *((*(0x0) + 0x1c)))
  20:	783c      	jmp	r15	// return;
  22:	0000      	.short	0x0000
  24:	00000000 	.long	0x00000000	// <.data.LMAC>

Disassembly of section .text.lhw_cfg_tx_delay_before:

00000000 <lhw_cfg_tx_delay_before>: // arg_bytes: 0
   0:	100d      	lrw	r0, 0x0	// regs: r0=0x0
   2:	ea0d7fff 	movi	r13, 32767	// regs: r13=0x7fff
   6:	6f76      	nor	r13, r13	// regs: r13=(~0x7fff)
   8:	9000      	ld.w	r0, (r0, 0x0)	// regs: r0=*(0x0)
   a:	e442201f 	andi	r2, r2, 31	// regs: r2=(<arg2> & 0x1f)
   e:	d980201e 	ld.w	r12, (r0, 0x78)	// regs: r12=*((*(0x0) + 0x78))
  12:	6b34      	and	r12, r13	// regs: r12=(*((*(0x0) + 0x78)) & (~0x7fff))
  14:	e463201f 	andi	r3, r3, 31	// regs: r3=(<arg3> & 0x1f)
  18:	4245      	lsli	r2, r2, 5	// regs: r2=((<arg2> & 0x1f) << 0x5)
  1a:	e421201f 	andi	r1, r1, 31	// regs: r1=(<arg1> & 0x1f)
  1e:	dd80201e 	st.w	r12, (r0, 0x78)	// *((*(0x0) + 0x78)) = (*((*(0x0) + 0x78)) & (~0x7fff))
  22:	6c8c      	or	r2, r3	// regs: r2=(((<arg2> & 0x1f) << 0x5) | (<arg3> & 0x1f))
  24:	412a      	lsli	r1, r1, 10	// regs: r1=((<arg1> & 0x1f) << 0xa)
  26:	d980201e 	ld.w	r12, (r0, 0x78)	// regs: r12=*((*(0x0) + 0x78))
  2a:	6c84      	or	r2, r1	// regs: r2=((((<arg2> & 0x1f) << 0x5) | (<arg3> & 0x1f)) | ((<arg1> & 0x1f) << 0xa))
  2c:	6cb0      	or	r2, r12	// regs: r2=(((((<arg2> & 0x1f) << 0x5) | (<arg3> & 0x1f)) | ((<arg1> & 0x1f) << 0xa)) | *((*(0x0) + 0x78)))
  2e:	b05e      	st.w	r2, (r0, 0x78)	// *((*(0x0) + 0x78)) = (((((<arg2> & 0x1f) << 0x5) | (<arg3> & 0x1f)) | ((<arg1> & 0x1f) << 0xa)) | *((*(0x0) + 0x78)))
  30:	783c      	jmp	r15	// return;
  32:	0000      	.short	0x0000
  34:	00000000 	.long	0x00000000	// <.data.LMAC>

Disassembly of section .text.lhw_cfg_tx_delay_after:

00000000 <lhw_cfg_tx_delay_after>: // arg_bytes: 16
   0:	14c1      	push	r4
   2:	ea8c0010 	lrw	r12, 0x0	// regs: r12=0x0
   6:	e442203f 	andi	r2, r2, 63	// regs: r2=(<arg2> & 0x3f)
   a:	d98c2000 	ld.w	r12, (r12, 0x0)	// regs: r12=*(0x0)
   e:	108e      	lrw	r4, 0xc0c0c0c0	// regs: r4=0xc0c0c0c0
  10:	d9ac2021 	ld.w	r13, (r12, 0x84)	// regs: r13=*((*(0x0) + 0x84))
  14:	e463203f 	andi	r3, r3, 63	// regs: r3=(<arg3> & 0x3f)
  18:	4248      	lsli	r2, r2, 8	// regs: r2=((<arg2> & 0x3f) << 0x8)
  1a:	e421203f 	andi	r1, r1, 63	// regs: r1=(<arg1> & 0x3f)
  1e:	6b50      	and	r13, r4	// regs: r13=(*((*(0x0) + 0x84)) & 0xc0c0c0c0)
  20:	6c8c      	or	r2, r3	// regs: r2=(((<arg2> & 0x3f) << 0x8) | (<arg3> & 0x3f))
  22:	4130      	lsli	r1, r1, 16	// regs: r1=((<arg1> & 0x3f) << 0x10)
  24:	e400203f 	andi	r0, r0, 63	// regs: r0=(<arg0> & 0x3f)
  28:	ddac2021 	st.w	r13, (r12, 0x84)	// *((*(0x0) + 0x84)) = (*((*(0x0) + 0x84)) & 0xc0c0c0c0)
  2c:	6c84      	or	r2, r1	// regs: r2=((((<arg2> & 0x3f) << 0x8) | (<arg3> & 0x3f)) | ((<arg1> & 0x3f) << 0x10))
  2e:	4018      	lsli	r0, r0, 24	// regs: r0=((<arg0> & 0x3f) << 0x18)
  30:	d9ac2021 	ld.w	r13, (r12, 0x84)	// regs: r13=*((*(0x0) + 0x84))
  34:	6c80      	or	r2, r0	// regs: r2=(((((<arg2> & 0x3f) << 0x8) | (<arg3> & 0x3f)) | ((<arg1> & 0x3f) << 0x10)) | ((<arg0> & 0x3f) << 0x18))
  36:	6cb4      	or	r2, r13	// regs: r2=((((((<arg2> & 0x3f) << 0x8) | (<arg3> & 0x3f)) | ((<arg1> & 0x3f) << 0x10)) | ((<arg0> & 0x3f) << 0x18)) | *((*(0x0) + 0x84)))
  38:	dc4c2021 	st.w	r2, (r12, 0x84)	// *((*(0x0) + 0x84)) = ((((((<arg2> & 0x3f) << 0x8) | (<arg3> & 0x3f)) | ((<arg1> & 0x3f) << 0x10)) | ((<arg0> & 0x3f) << 0x18)) | *((*(0x0) + 0x84)))
  3c:	1481      	pop	r4
  3e:	0000      	.short	0x0000
  40:	0000      	.short	0x0000	// <.data.LMAC>
  42:	0000      	.short	0x0000
  44:	c0c0c0c0 	.long	0xc0c0c0c0

Disassembly of section .text.lhw_cfg_tx_dalay_dac_rf:

00000000 <lhw_cfg_tx_dalay_dac_rf>: // arg_bytes: 12
   0:	106d      	lrw	r3, 0x0	// regs: r3=0x0
   2:	ea0d0f3f 	movi	r13, 3903	// regs: r13=0xf3f
   6:	6f76      	nor	r13, r13	// regs: r13=(~0xf3f)
   8:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   a:	e4422003 	andi	r2, r2, 3	// regs: r2=(<arg2> & 0x3)
   e:	d9832023 	ld.w	r12, (r3, 0x8c)	// regs: r12=*((*(0x0) + 0x8c))
  12:	6b34      	and	r12, r13	// regs: r12=(*((*(0x0) + 0x8c)) & (~0xf3f))
  14:	e421200f 	andi	r1, r1, 15	// regs: r1=(<arg1> & 0xf)
  18:	4244      	lsli	r2, r2, 4	// regs: r2=((<arg2> & 0x3) << 0x4)
  1a:	e400200f 	andi	r0, r0, 15	// regs: r0=(<arg0> & 0xf)
  1e:	dd832023 	st.w	r12, (r3, 0x8c)	// *((*(0x0) + 0x8c)) = (*((*(0x0) + 0x8c)) & (~0xf3f))
  22:	6c84      	or	r2, r1	// regs: r2=(((<arg2> & 0x3) << 0x4) | (<arg1> & 0xf))
  24:	4008      	lsli	r0, r0, 8	// regs: r0=((<arg0> & 0xf) << 0x8)
  26:	d9832023 	ld.w	r12, (r3, 0x8c)	// regs: r12=*((*(0x0) + 0x8c))
  2a:	6c80      	or	r2, r0	// regs: r2=((((<arg2> & 0x3) << 0x4) | (<arg1> & 0xf)) | ((<arg0> & 0xf) << 0x8))
  2c:	6cb0      	or	r2, r12	// regs: r2=(((((<arg2> & 0x3) << 0x4) | (<arg1> & 0xf)) | ((<arg0> & 0xf) << 0x8)) | *((*(0x0) + 0x8c)))
  2e:	dc432023 	st.w	r2, (r3, 0x8c)	// *((*(0x0) + 0x8c)) = (((((<arg2> & 0x3) << 0x4) | (<arg1> & 0xf)) | ((<arg0> & 0xf) << 0x8)) | *((*(0x0) + 0x8c)))
  32:	783c      	jmp	r15	// return;
  34:	00000000 	.long	0x00000000	// <.data.LMAC>

Disassembly of section .text.lhw_cfg_phy_rx_delay:

00000000 <lhw_cfg_phy_rx_delay>: // arg_bytes: 4
   0:	1068      	lrw	r3, 0x0	// regs: r3=0x0
   2:	401c      	lsli	r0, r0, 28	// regs: r0=(<arg0> << 0x1c)
   4:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   6:	d8432028 	ld.w	r2, (r3, 0xa0)	// regs: r2=*((*(0x0) + 0xa0))
   a:	c4025762 	zext	r2, r2, 27, 0	// regs: r2=zext(*((*(0x0) + 0xa0)))
   e:	dc432028 	st.w	r2, (r3, 0xa0)	// *((*(0x0) + 0xa0)) = zext(*((*(0x0) + 0xa0)))
  12:	d8432028 	ld.w	r2, (r3, 0xa0)	// regs: r2=*((*(0x0) + 0xa0))
  16:	6c08      	or	r0, r2	// regs: r0=((<arg0> << 0x1c) | *((*(0x0) + 0xa0)))
  18:	dc032028 	st.w	r0, (r3, 0xa0)	// *((*(0x0) + 0xa0)) = ((<arg0> << 0x1c) | *((*(0x0) + 0xa0)))
  1c:	783c      	jmp	r15	// return;
  1e:	0000      	.short	0x0000
  20:	0000      	.short	0x0000	// <.data.LMAC>
  22:	0000      	.short	0x0000

Disassembly of section .text.lhw_cfg_dma_list_cnt:

00000000 <lhw_cfg_dma_list_cnt>: // arg_bytes: 4
   0:	1069      	lrw	r3, 0x0	// regs: r3=0x0
   2:	3100      	movi	r1, 0	// regs: r1=0x0
   4:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   6:	297f      	subi	r1, 128	// regs: r1=0xffffff80
   8:	d8432040 	ld.w	r2, (r3, 0x100)	// regs: r2=*((*(0x0) + 0x100))
   c:	6884      	and	r2, r1	// regs: r2=(*((*(0x0) + 0x100)) & 0xffffff80)
   e:	dc432040 	st.w	r2, (r3, 0x100)	// *((*(0x0) + 0x100)) = (*((*(0x0) + 0x100)) & 0xffffff80)
  12:	d8432040 	ld.w	r2, (r3, 0x100)	// regs: r2=*((*(0x0) + 0x100))
  16:	e400207f 	andi	r0, r0, 127	// regs: r0=(<arg0> & 0x7f)
  1a:	6c08      	or	r0, r2	// regs: r0=((<arg0> & 0x7f) | *((*(0x0) + 0x100)))
  1c:	dc032040 	st.w	r0, (r3, 0x100)	// *((*(0x0) + 0x100)) = ((<arg0> & 0x7f) | *((*(0x0) + 0x100)))
  20:	783c      	jmp	r15	// return;
  22:	0000      	.short	0x0000
  24:	00000000 	.long	0x00000000	// <.data.LMAC>

Disassembly of section .text.lhw_cfg_tx_sub_frm:

00000000 <lhw_cfg_tx_sub_frm>: // arg_bytes: 12
   0:	1066      	lrw	r3, 0x0	// regs: r3=0x0
   2:	e5800023 	addi	r12, r0, 36	// regs: r12=(<arg0> + 0x24)
   6:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   8:	4003      	lsli	r0, r0, 3	// regs: r0=(<arg0> << 0x3)
   a:	d5830901 	str.w	r1, (r3, r12 << 3)
   e:	60c0      	addu	r3, r0	// regs: r3=(*(0x0) + (<arg0> << 0x3))
  10:	dc432049 	st.w	r2, (r3, 0x124)	// *(((*(0x0) + (<arg0> << 0x3)) + 0x124)) = <arg2>
  14:	783c      	jmp	r15	// return;
  16:	0000      	.short	0x0000
  18:	0000      	.short	0x0000	// <.data.LMAC>
  1a:	0000      	.short	0x0000

Disassembly of section .text.lhw_cfg_tx_delay_pa:

00000000 <lhw_cfg_tx_delay_pa>: // arg_bytes: 8
   0:	106a      	lrw	r3, 0x0	// regs: r3=0x0
   2:	c7405021 	bmaski	r1, 27
   6:	c6214901 	rotli	r1, r1, 17	// regs: r1=rotl(<arg1>, 0x11)
   a:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   c:	e400201f 	andi	r0, r0, 31	// regs: r0=(<arg0> & 0x1f)
  10:	d8432023 	ld.w	r2, (r3, 0x8c)	// regs: r2=*((*(0x0) + 0x8c))
  14:	6884      	and	r2, r1	// regs: r2=(*((*(0x0) + 0x8c)) & rotl(<arg1>, 0x11))
  16:	dc432023 	st.w	r2, (r3, 0x8c)	// *((*(0x0) + 0x8c)) = (*((*(0x0) + 0x8c)) & rotl(<arg1>, 0x11))
  1a:	d8432023 	ld.w	r2, (r3, 0x8c)	// regs: r2=*((*(0x0) + 0x8c))
  1e:	400c      	lsli	r0, r0, 12	// regs: r0=((<arg0> & 0x1f) << 0xc)
  20:	6c08      	or	r0, r2	// regs: r0=(((<arg0> & 0x1f) << 0xc) | *((*(0x0) + 0x8c)))
  22:	dc032023 	st.w	r0, (r3, 0x8c)	// *((*(0x0) + 0x8c)) = (((<arg0> & 0x1f) << 0xc) | *((*(0x0) + 0x8c)))
  26:	783c      	jmp	r15	// return;
  28:	0000      	.short	0x0000	// <.data.LMAC>
  2a:	0000      	.short	0x0000

Disassembly of section .text.lhw_get_rx_frm_type:

00000000 <lhw_get_rx_frm_type>: // arg_bytes: 0
   0:	1069      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   4:	d803202d 	ld.w	r0, (r3, 0xb4)	// regs: r0=*((*(0x0) + 0xb4))
   8:	e4002100 	andi	r0, r0, 256	// regs: r0=(*((*(0x0) + 0xb4)) & 0x100)
   c:	e900000a 	bez	r0, 0x20	// if (r0 == 0x0) goto loc_20;
  10:	d863202d 	ld.w	r3, (r3, 0xb4)	// regs: r3=*((*(0x0) + 0xb4))
  14:	e4632200 	andi	r3, r3, 512	// regs: r3=(*((*(0x0) + 0xb4)) & 0x200)
  18:	3b40      	cmpnei	r3, 0
  1a:	c4000500 	mvc	r0	// regs: r0=<cond>
  1e:	2000      	addi	r0, 1	// regs: r0=(<cond> + 0x1)
loc_20:
  20:	783c      	jmp	r15	// return;
  22:	0000      	.short	0x0000
  24:	00000000 	.long	0x00000000	// <.data.LMAC>

Disassembly of section .text.lhw_get_rx_ndp_ind:

00000000 <lhw_get_rx_ndp_ind>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	e0000000 	bsr	0x0	// <lhw_get_rx_frm_type> // arg_bytes: 0; regs: r0=<ret lhw_get_rx_frm_type@0x2>, r1=<clobbered>
   6:	3842      	cmpnei	r0, 2
   8:	0c0f      	bf	0x26	// if (r0 == 0x2) goto loc_26;
   a:	1069      	lrw	r3, 0x0	// regs: r3=0x0
   c:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   e:	e9200007 	bnez	r0, 0x1c	// if (r0 != 0x0) goto loc_1c;
  12:	d8032029 	ld.w	r0, (r3, 0xa4)	// regs: r0=*((*(0x0) + 0xa4))
  16:	c7205720 	zext	r0, r0, 25, 25	// regs: r0=zext(*((*(0x0) + 0xa4)))
loc_1a:
  1a:	1490      	pop	r15
loc_1c:
  1c:	d803202a 	ld.w	r0, (r3, 0xa8)	// regs: r0=*((*(0x0) + 0xa8))
  20:	c4a054a0 	zext	r0, r0, 5, 5	// regs: r0=zext(*((*(0x0) + 0xa8)))
  24:	07fb      	br	0x1a	// goto loc_1a;
loc_26:
  26:	3000      	movi	r0, 0	// regs: r0=0x0
  28:	07f9      	br	0x1a	// goto loc_1a;
  2a:	0000      	.short	0x0000
  2c:	0000      	.short	0x0000	// <.data.LMAC>
  2e:	0000      	.short	0x0000

Disassembly of section .text.lhw_get_ndp2m:

00000000 <lhw_get_ndp2m>: // arg_bytes: 0
   0:	1067      	lrw	r3, 0x0	// regs: r3=0x0
   2:	3200      	movi	r2, 0	// regs: r2=0x0
   4:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   6:	d823202a 	ld.w	r1, (r3, 0xa8)	// regs: r1=*((*(0x0) + 0xa8))
   a:	d9832029 	ld.w	r12, (r3, 0xa4)	// regs: r12=*((*(0x0) + 0xa4))
   e:	6c33      	mov	r0, r12	// regs: r0=*((*(0x0) + 0xa4))
  10:	6cc7      	mov	r3, r1	// regs: r3=*((*(0x0) + 0xa8))
  12:	6c4b      	mov	r1, r2	// regs: r1=0x0
  14:	6c08      	or	r0, r2	// regs: r0=(*((*(0x0) + 0xa4)) | 0x0)
  16:	6c4c      	or	r1, r3	// regs: r1=(0x0 | *((*(0x0) + 0xa8)))
  18:	783c      	jmp	r15	// return;
  1a:	0000      	.short	0x0000
  1c:	0000      	.short	0x0000	// <.data.LMAC>
  1e:	0000      	.short	0x0000

Disassembly of section .text.lmac_rf_sw_ctrl:

00000000 <lmac_rf_sw_ctrl>: // arg_bytes: 0
   0:	1064      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   4:	9270      	ld.w	r3, (r2, 0x40)	// regs: r3=*((*(0x0) + 0x40))
   6:	ec630200 	ori	r3, r3, 512	// regs: r3=(*((*(0x0) + 0x40)) | 0x200)
   a:	b270      	st.w	r3, (r2, 0x40)	// *((*(0x0) + 0x40)) = (*((*(0x0) + 0x40)) | 0x200)
   c:	783c      	jmp	r15	// return;
   e:	0000      	.short	0x0000
  10:	00000000 	.long	0x00000000	// <.data.LMAC>

Disassembly of section .text.lmac_rf_hw_ctrl:

00000000 <lmac_rf_hw_ctrl>: // arg_bytes: 0
   0:	1063      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   4:	9270      	ld.w	r3, (r2, 0x40)	// regs: r3=*((*(0x0) + 0x40))
   6:	3b89      	bclri	r3, 9	// regs: r3=(*((*(0x0) + 0x40)) & ~(0x1 << 0x9))
   8:	b270      	st.w	r3, (r2, 0x40)	// *((*(0x0) + 0x40)) = (*((*(0x0) + 0x40)) & ~(0x1 << 0x9))
   a:	783c      	jmp	r15	// return;
   c:	0000      	.short	0x0000	// <.data.LMAC>
   e:	0000      	.short	0x0000

Disassembly of section .text.lmac_cfg_rf_en:

00000000 <lmac_cfg_rf_en>: // arg_bytes: 4
   0:	1066      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   4:	9270      	ld.w	r3, (r2, 0x40)	// regs: r3=*((*(0x0) + 0x40))
   6:	e9000006 	bez	r0, 0x12	// if (r0 == 0x0) goto loc_12;
   a:	ec630100 	ori	r3, r3, 256	// regs: r3=(*((*(0x0) + 0x40)) | 0x100)
loc_e:
   e:	b270      	st.w	r3, (r2, 0x40)	// *((*(0x0) + 0x40)) = r3
  10:	783c      	jmp	r15	// return;
loc_12:
  12:	3b88      	bclri	r3, 8	// regs: r3=(*((*(0x0) + 0x40)) & ~(0x1 << 0x8))
  14:	07fd      	br	0xe	// goto loc_e;
  16:	0000      	.short	0x0000
  18:	0000      	.short	0x0000	// <.data.LMAC>
  1a:	0000      	.short	0x0000

Disassembly of section .text.lmac_cfg_tx_en:

00000000 <lmac_cfg_tx_en>: // arg_bytes: 4
   0:	1066      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   4:	9270      	ld.w	r3, (r2, 0x40)	// regs: r3=*((*(0x0) + 0x40))
   6:	e9000006 	bez	r0, 0x12	// if (r0 == 0x0) goto loc_12;
   a:	ec630400 	ori	r3, r3, 1024	// regs: r3=(*((*(0x0) + 0x40)) | 0x400)
loc_e:
   e:	b270      	st.w	r3, (r2, 0x40)	// *((*(0x0) + 0x40)) = r3
  10:	783c      	jmp	r15	// return;
loc_12:
  12:	3b8a      	bclri	r3, 10	// regs: r3=(*((*(0x0) + 0x40)) & ~(0x1 << 0xa))
  14:	07fd      	br	0xe	// goto loc_e;
  16:	0000      	.short	0x0000
  18:	0000      	.short	0x0000	// <.data.LMAC>
  1a:	0000      	.short	0x0000

Disassembly of section .text.lmac_cfg_rx_en:

00000000 <lmac_cfg_rx_en>: // arg_bytes: 4
   0:	1066      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   4:	9270      	ld.w	r3, (r2, 0x40)	// regs: r3=*((*(0x0) + 0x40))
   6:	e9000006 	bez	r0, 0x12	// if (r0 == 0x0) goto loc_12;
   a:	ec630800 	ori	r3, r3, 2048	// regs: r3=(*((*(0x0) + 0x40)) | 0x800)
loc_e:
   e:	b270      	st.w	r3, (r2, 0x40)	// *((*(0x0) + 0x40)) = r3
  10:	783c      	jmp	r15	// return;
loc_12:
  12:	3b8b      	bclri	r3, 11	// regs: r3=(*((*(0x0) + 0x40)) & ~(0x1 << 0xb))
  14:	07fd      	br	0xe	// goto loc_e;
  16:	0000      	.short	0x0000
  18:	0000      	.short	0x0000	// <.data.LMAC>
  1a:	0000      	.short	0x0000

Disassembly of section .text.lmac_cfg_pa_en:

00000000 <lmac_cfg_pa_en>: // arg_bytes: 4
   0:	1065      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   4:	9270      	ld.w	r3, (r2, 0x40)	// regs: r3=*((*(0x0) + 0x40))
   6:	e9000005 	bez	r0, 0x10	// if (r0 == 0x0) goto loc_10;
   a:	3bb0      	bseti	r3, 16	// regs: r3=(*((*(0x0) + 0x40)) | (0x1 << 0x10))
loc_c:
   c:	b270      	st.w	r3, (r2, 0x40)	// *((*(0x0) + 0x40)) = r3
   e:	783c      	jmp	r15	// return;
loc_10:
  10:	3b90      	bclri	r3, 16	// regs: r3=(*((*(0x0) + 0x40)) & ~(0x1 << 0x10))
  12:	07fd      	br	0xc	// goto loc_c;
  14:	0000      	.short	0x0000	// <.data.LMAC>
  16:	0000      	.short	0x0000

Disassembly of section .text.lmac_cfg_dac_en:

00000000 <lmac_cfg_dac_en>: // arg_bytes: 4
   0:	1065      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   4:	9270      	ld.w	r3, (r2, 0x40)	// regs: r3=*((*(0x0) + 0x40))
   6:	e9000005 	bez	r0, 0x10	// if (r0 == 0x0) goto loc_10;
   a:	3bb1      	bseti	r3, 17	// regs: r3=(*((*(0x0) + 0x40)) | (0x1 << 0x11))
loc_c:
   c:	b270      	st.w	r3, (r2, 0x40)	// *((*(0x0) + 0x40)) = r3
   e:	783c      	jmp	r15	// return;
loc_10:
  10:	3b91      	bclri	r3, 17	// regs: r3=(*((*(0x0) + 0x40)) & ~(0x1 << 0x11))
  12:	07fd      	br	0xc	// goto loc_c;
  14:	0000      	.short	0x0000	// <.data.LMAC>
  16:	0000      	.short	0x0000

Disassembly of section .text.lmac_cfg_end_to_limit:

00000000 <lmac_cfg_end_to_limit>: // arg_bytes: 4
   0:	1062      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   4:	b317      	st.w	r0, (r3, 0x5c)	// *((*(0x0) + 0x5c)) = <arg0>
   6:	783c      	jmp	r15	// return;
   8:	0000      	.short	0x0000	// <.data.LMAC>
   a:	0000      	.short	0x0000

Disassembly of section .text.lhw_set_bo_bypass:

00000000 <lhw_set_bo_bypass>: // arg_bytes: 4
   0:	1066      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   4:	926c      	ld.w	r3, (r2, 0x30)	// regs: r3=*((*(0x0) + 0x30))
   6:	e9000006 	bez	r0, 0x12	// if (r0 == 0x0) goto loc_12;
   a:	ec630100 	ori	r3, r3, 256	// regs: r3=(*((*(0x0) + 0x30)) | 0x100)
loc_e:
   e:	b26c      	st.w	r3, (r2, 0x30)	// *((*(0x0) + 0x30)) = r3
  10:	783c      	jmp	r15	// return;
loc_12:
  12:	3b88      	bclri	r3, 8	// regs: r3=(*((*(0x0) + 0x30)) & ~(0x1 << 0x8))
  14:	07fd      	br	0xe	// goto loc_e;
  16:	0000      	.short	0x0000
  18:	0000      	.short	0x0000	// <.data.LMAC>
  1a:	0000      	.short	0x0000

Disassembly of section .text.lhw_set_tsf:

00000000 <lhw_set_tsf>: // arg_bytes: 8
   0:	1063      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   4:	b304      	st.w	r0, (r3, 0x10)	// *((*(0x0) + 0x10)) = <arg0>
   6:	b325      	st.w	r1, (r3, 0x14)	// *((*(0x0) + 0x14)) = <arg1>
   8:	783c      	jmp	r15	// return;
   a:	0000      	.short	0x0000
   c:	0000      	.short	0x0000	// <.data.LMAC>
   e:	0000      	.short	0x0000

Disassembly of section .text.lhw_start_cca_observ:

00000000 <lhw_start_cca_observ>: // arg_bytes: 4
   0:	1067      	lrw	r3, 0x0	// regs: r3=0x0
   2:	4001      	lsli	r0, r0, 1	// regs: r0=(<arg0> << 0x1)
   4:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
   6:	e400200e 	andi	r0, r0, 14	// regs: r0=((<arg0> << 0x1) & 0xe)
   a:	dc03218c 	st.w	r0, (r3, 0x630)	// *((*(0x0) + 0x630)) = ((<arg0> << 0x1) & 0xe)
   e:	d843218c 	ld.w	r2, (r3, 0x630)	// regs: r2=*((*(0x0) + 0x630))
  12:	ec420001 	ori	r2, r2, 1	// regs: r2=(*((*(0x0) + 0x630)) | 0x1)
  16:	dc43218c 	st.w	r2, (r3, 0x630)	// *((*(0x0) + 0x630)) = (*((*(0x0) + 0x630)) | 0x1)
  1a:	783c      	jmp	r15	// return;
  1c:	0000      	.short	0x0000	// <.data.LMAC>
  1e:	0000      	.short	0x0000

Disassembly of section .text.lhw_get_cca_observ:

00000000 <lhw_get_cca_observ>: // arg_bytes: 4
   0:	1071      	lrw	r3, 0x0	// regs: r3=0x0
   2:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
   4:	d862218c 	ld.w	r3, (r2, 0x630)	// regs: r3=*((*(0x0) + 0x630))
   8:	e4632010 	andi	r3, r3, 16	// regs: r3=(*((*(0x0) + 0x630)) & 0x10)
   c:	e9030013 	bez	r3, 0x32	// if (r3 == 0x0) goto loc_32;
  10:	d862218d 	ld.w	r3, (r2, 0x634)	// regs: r3=*((*(0x0) + 0x634))
  14:	b060      	st.w	r3, (r0, 0x0)	// *(<arg0>) = *((*(0x0) + 0x634))
  16:	d862218e 	ld.w	r3, (r2, 0x638)	// regs: r3=*((*(0x0) + 0x638))
  1a:	b061      	st.w	r3, (r0, 0x4)	// *(<arg0> + 0x4) = *((*(0x0) + 0x638))
  1c:	d862218f 	ld.w	r3, (r2, 0x63c)	// regs: r3=*((*(0x0) + 0x63c))
  20:	b062      	st.w	r3, (r0, 0x8)	// *(<arg0> + 0x8) = *((*(0x0) + 0x63c))
  22:	d8622190 	ld.w	r3, (r2, 0x640)	// regs: r3=*((*(0x0) + 0x640))
  26:	b063      	st.w	r3, (r0, 0xc)	// *(<arg0> + 0xc) = *((*(0x0) + 0x640))
  28:	d8622191 	ld.w	r3, (r2, 0x644)	// regs: r3=*((*(0x0) + 0x644))
  2c:	b064      	st.w	r3, (r0, 0x10)	// *(<arg0> + 0x10) = *((*(0x0) + 0x644))
  2e:	3000      	movi	r0, 0	// regs: r0=0x0
loc_30:
  30:	783c      	jmp	r15	// return;
loc_32:
  32:	b060      	st.w	r3, (r0, 0x0)	// *(<arg0>) = (*((*(0x0) + 0x630)) & 0x10)
  34:	b061      	st.w	r3, (r0, 0x4)	// *(<arg0> + 0x4) = (*((*(0x0) + 0x630)) & 0x10)
  36:	b062      	st.w	r3, (r0, 0x8)	// *(<arg0> + 0x8) = (*((*(0x0) + 0x630)) & 0x10)
  38:	b063      	st.w	r3, (r0, 0xc)	// *(<arg0> + 0xc) = (*((*(0x0) + 0x630)) & 0x10)
  3a:	b064      	st.w	r3, (r0, 0x10)	// *(<arg0> + 0x10) = (*((*(0x0) + 0x630)) & 0x10)
  3c:	3000      	movi	r0, 0	// regs: r0=0x0
  3e:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  40:	07f8      	br	0x30	// goto loc_30;
  42:	0000      	.short	0x0000
  44:	00000000 	.long	0x00000000	// <.data.LMAC>
