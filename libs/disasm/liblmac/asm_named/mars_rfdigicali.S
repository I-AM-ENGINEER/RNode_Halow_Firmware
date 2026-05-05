
libs\obj\liblmac\mars_rfdigicali.o:     file format elf32-csky-little


Disassembly of section .text.ah_rfdigicali_stop_tx_cali:

00000000 <ah_rfdigicali_stop_tx_cali>: // arg_bytes: 0
   0:	1067      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   2:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x4001d000)
   4:	3a80      	bclri	r2, 0	// regs: r2=(*(0x4001d000) & ~(0x1 << 0x0))
   6:	3a81      	bclri	r2, 1	// regs: r2=((*(0x4001d000) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
   8:	b340      	st.w	r2, (r3, 0x0)	// *(0x4001d000) = ((*(0x4001d000) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
   a:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x4001d000)
   c:	3a86      	bclri	r2, 6	// regs: r2=(*(0x4001d000) & ~(0x1 << 0x6))
   e:	b340      	st.w	r2, (r3, 0x0)	// *(0x4001d000) = (*(0x4001d000) & ~(0x1 << 0x6))
  10:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x4001d000)
  12:	ec420008 	ori	r2, r2, 8	// regs: r2=(*(0x4001d000) | 0x8)
  16:	b340      	st.w	r2, (r3, 0x0)	// *(0x4001d000) = (*(0x4001d000) | 0x8)
  18:	783c      	jmp	r15	// return;
  1a:	0000      	.short	0x0000
  1c:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_power_calc_kick_start:

00000000 <ah_rfdigicali_power_calc_kick_start>: // arg_bytes: 0
   0:	106d      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   2:	3180      	movi	r1, 128	// regs: r1=0x80
   4:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x4001d014)
   6:	ec422000 	ori	r2, r2, 8192	// regs: r2=(*(0x4001d014) | 0x2000)
   a:	b345      	st.w	r2, (r3, 0x14)	// *(0x4001d014) = (*(0x4001d014) | 0x2000)
   c:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x4001d014)
   e:	ec420001 	ori	r2, r2, 1	// regs: r2=(*(0x4001d014) | 0x1)
  12:	b345      	st.w	r2, (r3, 0x14)	// *(0x4001d014) = (*(0x4001d014) | 0x1)
  14:	4126      	lsli	r1, r1, 6	// regs: r1=0x2000
loc_16:
  16:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x4001d014)
  18:	6884      	and	r2, r1	// regs: r2=(*(0x4001d014) & 0x2000)
  1a:	e902fffe 	bez	r2, 0x16	// if (r2 == 0x0) goto loc_16;
  1e:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x4001d014)
  20:	ec422000 	ori	r2, r2, 8192	// regs: r2=(*(0x4001d014) | 0x2000)
  24:	b345      	st.w	r2, (r3, 0x14)	// *(0x4001d014) = (*(0x4001d014) | 0x2000)
  26:	9306      	ld.w	r0, (r3, 0x18)	// regs: r0=*(0x4001d018)
  28:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x4001d014)
  2a:	3a80      	bclri	r2, 0	// regs: r2=(*(0x4001d014) & ~(0x1 << 0x0))
  2c:	4808      	lsri	r0, r0, 8	// regs: r0=(*(0x4001d018) >> 0x8)
  2e:	b345      	st.w	r2, (r3, 0x14)	// *(0x4001d014) = (*(0x4001d014) & ~(0x1 << 0x0))
  30:	783c      	jmp	r15	// return;
  32:	0000      	.short	0x0000
  34:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_dcoc_est_en:

00000000 <ah_rfdigicali_dcoc_est_en>: // arg_bytes: 0
   0:	1066      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   2:	ea02d058 	movi	r2, 53336	// regs: r2=0xd058
   6:	c4824902 	rotli	r2, r2, 4	// regs: r2=rotl(0xd058, 0x4)
   a:	b340      	st.w	r2, (r3, 0x0)	// *(0x4001d000) = rotl(0xd058, 0x4)
   c:	ea021e02 	movi	r2, 7682	// regs: r2=0x1e02
  10:	b341      	st.w	r2, (r3, 0x4)	// *(0x4001d004) = 0x1e02
  12:	3202      	movi	r2, 2	// regs: r2=0x2
  14:	b342      	st.w	r2, (r3, 0x8)	// *(0x4001d008) = 0x2
  16:	783c      	jmp	r15	// return;
  18:	d000      	.short	0xd000
  1a:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_rx_dcoc_hw_trig_en:

00000000 <ah_rfdigicali_rx_dcoc_hw_trig_en>: // arg_bytes: 0
   0:	1043      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
   2:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*(0x4001d000)
   4:	3bb9      	bseti	r3, 25	// regs: r3=(*(0x4001d000) | (0x1 << 0x19))
   6:	b260      	st.w	r3, (r2, 0x0)	// *(0x4001d000) = (*(0x4001d000) | (0x1 << 0x19))
   8:	783c      	jmp	r15	// return;
   a:	0000      	.short	0x0000
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_rx_dcoc_hw_trig_dis:

00000000 <ah_rfdigicali_rx_dcoc_hw_trig_dis>: // arg_bytes: 0
   0:	1043      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
   2:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*(0x4001d000)
   4:	3b99      	bclri	r3, 25	// regs: r3=(*(0x4001d000) & ~(0x1 << 0x19))
   6:	b260      	st.w	r3, (r2, 0x0)	// *(0x4001d000) = (*(0x4001d000) & ~(0x1 << 0x19))
   8:	783c      	jmp	r15	// return;
   a:	0000      	.short	0x0000
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_dcoc_est_kick_start:

00000000 <ah_rfdigicali_dcoc_est_kick_start>: // arg_bytes: 4
   0:	14d2      	push	r4-r5, r15
   2:	1093      	lrw	r4, 0x4001d000	// regs: r4=0x4001d000
   4:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   6:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x4001d000)
   8:	ec630003 	ori	r3, r3, 3	// regs: r3=(*(0x4001d000) | 0x3)
   c:	b460      	st.w	r3, (r4, 0x0)	// *(0x4001d000) = (*(0x4001d000) | 0x3)
   e:	3002      	movi	r0, 2	// regs: r0=0x2
  10:	e0000000 	bsr	0x0	// <os_sleep_ms>; regs: r0=<ret os_sleep_ms@0x10>, r1=<clobbered>
  14:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x4001d000)
  16:	ec630040 	ori	r3, r3, 64	// regs: r3=(*(0x4001d000) | 0x40)
  1a:	b460      	st.w	r3, (r4, 0x0)	// *(0x4001d000) = (*(0x4001d000) | 0x40)
  1c:	3002      	movi	r0, 2	// regs: r0=0x2
  1e:	e0000000 	bsr	0x0	// <os_sleep_us>; regs: r0=<ret os_sleep_us@0x1e>, r1=<clobbered>
  22:	9463      	ld.w	r3, (r4, 0xc)	// regs: r3=*(0x4001d00c)
  24:	c4035963 	sext	r3, r3, 11, 0	// regs: r3=sext(*(0x4001d00c))
  28:	b560      	st.w	r3, (r5, 0x0)	// *(<arg0>) = sext(*(0x4001d00c))
  2a:	9463      	ld.w	r3, (r4, 0xc)	// regs: r3=*(0x4001d00c)
  2c:	c5835ae3 	sext	r3, r3, 23, 12	// regs: r3=sext(*(0x4001d00c))
  30:	b561      	st.w	r3, (r5, 0x4)	// *(<arg0> + 0x4) = sext(*(0x4001d00c))
  32:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x4001d000)
  34:	3b80      	bclri	r3, 0	// regs: r3=(*(0x4001d000) & ~(0x1 << 0x0))
  36:	3b81      	bclri	r3, 1	// regs: r3=((*(0x4001d000) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
  38:	b460      	st.w	r3, (r4, 0x0)	// *(0x4001d000) = ((*(0x4001d000) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
  3a:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x4001d000)
  3c:	3b86      	bclri	r3, 6	// regs: r3=(*(0x4001d000) & ~(0x1 << 0x6))
  3e:	b460      	st.w	r3, (r4, 0x0)	// *(0x4001d000) = (*(0x4001d000) & ~(0x1 << 0x6))
  40:	9460      	ld.w	r3, (r4, 0x0)	// regs: r3=*(0x4001d000)
  42:	ec630008 	ori	r3, r3, 8	// regs: r3=(*(0x4001d000) | 0x8)
  46:	b460      	st.w	r3, (r4, 0x0)	// *(0x4001d000) = (*(0x4001d000) | 0x8)
  48:	1492      	pop	r4-r5, r15
  4a:	0000      	.short	0x0000
  4c:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_dcoc_imb_est_kick_start:

00000000 <ah_rfdigicali_dcoc_imb_est_kick_start>: // arg_bytes: 0
   0:	1066      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   2:	3280      	movi	r2, 128	// regs: r2=0x80
   4:	4252      	lsli	r2, r2, 18	// regs: r2=0x2000000
   6:	b344      	st.w	r2, (r3, 0x10)	// *(0x4001d010) = 0x2000000
   8:	3228      	movi	r2, 40	// regs: r2=0x28
   a:	b345      	st.w	r2, (r3, 0x14)	// *(0x4001d014) = 0x28
   c:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x4001d000)
   e:	ec420003 	ori	r2, r2, 3	// regs: r2=(*(0x4001d000) | 0x3)
  12:	b340      	st.w	r2, (r3, 0x0)	// *(0x4001d000) = (*(0x4001d000) | 0x3)
  14:	783c      	jmp	r15	// return;
  16:	0000      	.short	0x0000
  18:	d000      	.short	0xd000
  1a:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_config_hw_rx_dcoc:

00000000 <ah_rfdigicali_config_hw_rx_dcoc>: // arg_bytes: 12
   0:	1078      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   2:	ea8d0019 	lrw	r13, 0xfc001e00	// regs: r13=0xfc001e00
   6:	d9832000 	ld.w	r12, (r3, 0x0)	// regs: r12=*(0x4001d000)
   a:	6b34      	and	r12, r13	// regs: r12=(*(0x4001d000) & 0xfc001e00)
   c:	dd832000 	st.w	r12, (r3, 0x0)	// *(0x4001d000) = (*(0x4001d000) & 0xfc001e00)
  10:	d9a32000 	ld.w	r13, (r3, 0x0)	// regs: r13=*(0x4001d000)
  14:	c461484c 	lsri	r12, r1, 3	// regs: r12=(<arg1> >> 0x3)
  18:	edada704 	ori	r13, r13, 42756	// regs: r13=(*(0x4001d000) | 0xa704)
  1c:	c62c482c 	lsli	r12, r12, 17	// regs: r12=((<arg1> >> 0x3) << 0x11)
  20:	6f34      	or	r12, r13	// regs: r12=(((<arg1> >> 0x3) << 0x11) | (*(0x4001d000) | 0xa704))
  22:	dd832000 	st.w	r12, (r3, 0x0)	// *(0x4001d000) = (((<arg1> >> 0x3) << 0x11) | (*(0x4001d000) | 0xa704))
  26:	ea0d00ff 	movi	r13, 255	// regs: r13=0xff
  2a:	d9832001 	ld.w	r12, (r3, 0x4)	// regs: r12=*(0x4001d004)
  2e:	c70d482d 	lsli	r13, r13, 24	// regs: r13=0xff000000
  32:	6b34      	and	r12, r13	// regs: r12=(*(0x4001d004) & 0xff000000)
  34:	dd832001 	st.w	r12, (r3, 0x4)	// *(0x4001d004) = (*(0x4001d004) & 0xff000000)
  38:	6048      	addu	r1, r2	// regs: r1=(<arg1> + <arg2>)
  3a:	d9832001 	ld.w	r12, (r3, 0x4)	// regs: r12=*(0x4001d004)
  3e:	ea220100 	movih	r2, 256	// regs: r2=(0x100 << 0x10)
  42:	2aff      	subi	r2, 256	// regs: r2=((0x100 << 0x10) - 0x100)
  44:	4125      	lsli	r1, r1, 5	// regs: r1=((<arg1> + <arg2>) << 0x5)
  46:	6848      	and	r1, r2	// regs: r1=(((<arg1> + <arg2>) << 0x5) & ((0x100 << 0x10) - 0x100))
  48:	6c30      	or	r0, r12	// regs: r0=(<arg0> | *(0x4001d004))
  4a:	6c40      	or	r1, r0	// regs: r1=((((<arg1> + <arg2>) << 0x5) & ((0x100 << 0x10) - 0x100)) | (<arg0> | *(0x4001d004)))
  4c:	b321      	st.w	r1, (r3, 0x4)	// *(0x4001d004) = ((((<arg1> + <arg2>) << 0x5) & ((0x100 << 0x10) - 0x100)) | (<arg0> | *(0x4001d004)))
  4e:	3200      	movi	r2, 0	// regs: r2=0x0
  50:	31f2      	movi	r1, 242	// regs: r1=0xf2
  52:	b342      	st.w	r2, (r3, 0x8)	// *(0x4001d008) = 0x0
  54:	4138      	lsli	r1, r1, 24	// regs: r1=0xf2000000
  56:	9344      	ld.w	r2, (r3, 0x10)	// regs: r2=*(0x4001d010)
  58:	2900      	subi	r1, 1	// regs: r1=0xf1ffffff
  5a:	6884      	and	r2, r1	// regs: r2=(*(0x4001d010) & 0xf1ffffff)
  5c:	b344      	st.w	r2, (r3, 0x10)	// *(0x4001d010) = (*(0x4001d010) & 0xf1ffffff)
  5e:	783c      	jmp	r15	// return;
  60:	4001d000 	.long	0x4001d000
  64:	fc001e00 	.long	0xfc001e00

Disassembly of section .text.ah_rfdigicali_config_hw_bknoise:

00000000 <ah_rfdigicali_config_hw_bknoise>: // arg_bytes: 8
   0:	104d      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
   2:	33c0      	movi	r3, 192	// regs: r3=0xc0
   4:	4367      	lsli	r3, r3, 7	// regs: r3=0x6000
   6:	b265      	st.w	r3, (r2, 0x14)	// *(0x4001d014) = 0x6000
   8:	d9822005 	ld.w	r12, (r2, 0x14)	// regs: r12=*(0x4001d014)
   c:	4167      	lsli	r3, r1, 7	// regs: r3=(<arg1> << 0x7)
   e:	ea2d0001 	movih	r13, 1	// regs: r13=(0x1 << 0x10)
  12:	e5ad085f 	addi	r13, r13, 2144	// regs: r13=((0x1 << 0x10) + 0x860)
  16:	6f34      	or	r12, r13	// regs: r12=(*(0x4001d014) | ((0x1 << 0x10) + 0x860))
  18:	e4632780 	andi	r3, r3, 1920	// regs: r3=((<arg1> << 0x7) & 0x780)
  1c:	6044      	addu	r1, r1	// regs: r1=(<arg1> + <arg1>)
  1e:	6cf0      	or	r3, r12	// regs: r3=(((<arg1> << 0x7) & 0x780) | (*(0x4001d014) | ((0x1 << 0x10) + 0x860)))
  20:	e421201e 	andi	r1, r1, 30	// regs: r1=((<arg1> + <arg1>) & 0x1e)
  24:	6c4c      	or	r1, r3	// regs: r1=(((<arg1> + <arg1>) & 0x1e) | (((<arg1> << 0x7) & 0x780) | (*(0x4001d014) | ((0x1 << 0x10) + 0x860))))
  26:	4011      	lsli	r0, r0, 17	// regs: r0=(<arg0> << 0x11)
  28:	ea233ffe 	movih	r3, 16382	// regs: r3=(0x3ffe << 0x10)
  2c:	680c      	and	r0, r3	// regs: r0=((<arg0> << 0x11) & (0x3ffe << 0x10))
  2e:	6c40      	or	r1, r0	// regs: r1=((((<arg1> + <arg1>) & 0x1e) | (((<arg1> << 0x7) & 0x780) | (*(0x4001d014) | ((0x1 << 0x10) + 0x860)))) | ((<arg0> << 0x11) & (0x3ffe << 0x10)))
  30:	b225      	st.w	r1, (r2, 0x14)	// *(0x4001d014) = ((((<arg1> + <arg1>) & 0x1e) | (((<arg1> << 0x7) & 0x780) | (*(0x4001d014) | ((0x1 << 0x10) + 0x860)))) | ((<arg0> << 0x11) & (0x3ffe << 0x10)))
  32:	783c      	jmp	r15	// return;
  34:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_bknoise_hw_trig_en:

00000000 <ah_rfdigicali_bknoise_hw_trig_en>: // arg_bytes: 0
   0:	1043      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
   2:	9265      	ld.w	r3, (r2, 0x14)	// regs: r3=*(0x4001d014)
   4:	ec638000 	ori	r3, r3, 32768	// regs: r3=(*(0x4001d014) | 0x8000)
   8:	b265      	st.w	r3, (r2, 0x14)	// *(0x4001d014) = (*(0x4001d014) | 0x8000)
   a:	783c      	jmp	r15	// return;
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_bknoise_hw_trig_dis:

00000000 <ah_rfdigicali_bknoise_hw_trig_dis>: // arg_bytes: 0
   0:	1043      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
   2:	9265      	ld.w	r3, (r2, 0x14)	// regs: r3=*(0x4001d014)
   4:	3b8f      	bclri	r3, 15	// regs: r3=(*(0x4001d014) & ~(0x1 << 0xf))
   6:	b265      	st.w	r3, (r2, 0x14)	// *(0x4001d014) = (*(0x4001d014) & ~(0x1 << 0xf))
   8:	783c      	jmp	r15	// return;
   a:	0000      	.short	0x0000
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_bknoise_calc_en:

00000000 <ah_rfdigicali_bknoise_calc_en>: // arg_bytes: 0
   0:	1043      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
   2:	9265      	ld.w	r3, (r2, 0x14)	// regs: r3=*(0x4001d014)
   4:	ec630001 	ori	r3, r3, 1	// regs: r3=(*(0x4001d014) | 0x1)
   8:	b265      	st.w	r3, (r2, 0x14)	// *(0x4001d014) = (*(0x4001d014) | 0x1)
   a:	783c      	jmp	r15	// return;
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_bknoise_calc_dis:

00000000 <ah_rfdigicali_bknoise_calc_dis>: // arg_bytes: 0
   0:	1044      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
   2:	ea016001 	movi	r1, 24577	// regs: r1=0x6001
   6:	6c46      	nor	r1, r1	// regs: r1=(~0x6001)
   8:	9265      	ld.w	r3, (r2, 0x14)	// regs: r3=*(0x4001d014)
   a:	68c4      	and	r3, r1	// regs: r3=(*(0x4001d014) & (~0x6001))
   c:	b265      	st.w	r3, (r2, 0x14)	// *(0x4001d014) = (*(0x4001d014) & (~0x6001))
   e:	783c      	jmp	r15	// return;
  10:	d000      	.short	0xd000
  12:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_bknoise_valid_pd_get:

00000000 <ah_rfdigicali_bknoise_valid_pd_get>: // arg_bytes: 0
   0:	1063      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   2:	9305      	ld.w	r0, (r3, 0x14)	// regs: r0=*(0x4001d014)
   4:	3380      	movi	r3, 128	// regs: r3=0x80
   6:	4366      	lsli	r3, r3, 6	// regs: r3=0x2000
   8:	680c      	and	r0, r3	// regs: r0=(*(0x4001d014) & 0x2000)
   a:	783c      	jmp	r15	// return;
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_bknoise_valid_pd_clr:

00000000 <ah_rfdigicali_bknoise_valid_pd_clr>: // arg_bytes: 0
   0:	1043      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
   2:	9265      	ld.w	r3, (r2, 0x14)	// regs: r3=*(0x4001d014)
   4:	ec636000 	ori	r3, r3, 24576	// regs: r3=(*(0x4001d014) | 0x6000)
   8:	b265      	st.w	r3, (r2, 0x14)	// *(0x4001d014) = (*(0x4001d014) | 0x6000)
   a:	783c      	jmp	r15	// return;
   c:	d000      	.short	0xd000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_dcoci_get:

00000000 <ah_rfdigicali_dcoci_get>: // arg_bytes: 0
   0:	1049      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
   2:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*(0x4001d000)
   4:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x4001d000) & 0x1)
   8:	e923000b 	bnez	r3, 0x1e	// if (r3 != 0x0) goto loc_1e;
   c:	9203      	ld.w	r0, (r2, 0xc)	// regs: r0=*(0x4001d00c)
   e:	e4002fff 	andi	r0, r0, 4095	// regs: r0=(*(0x4001d00c) & 0xfff)
  12:	eb2007ff 	cmplti	r0, 2048
  16:	0803      	bt	0x1c	// if (r0 < 0x800) goto loc_1c;
  18:	e4001fff 	subi	r0, r0, 4096	// regs: r0=((*(0x4001d00c) & 0xfff) - 0x1000)
loc_1c:
  1c:	783c      	jmp	r15	// return;
loc_1e:
  1e:	ea007fff 	movi	r0, 32767	// regs: r0=0x7fff
  22:	07fd      	br	0x1c	// goto loc_1c;
  24:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_dcocq_get:

00000000 <ah_rfdigicali_dcocq_get>: // arg_bytes: 0
   0:	1049      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
   2:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*(0x4001d000)
   4:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x4001d000) & 0x2)
   8:	e923000b 	bnez	r3, 0x1e	// if (r3 != 0x0) goto loc_1e;
   c:	9203      	ld.w	r0, (r2, 0xc)	// regs: r0=*(0x4001d00c)
   e:	c58056e0 	zext	r0, r0, 23, 12	// regs: r0=zext(*(0x4001d00c))
  12:	eb2007ff 	cmplti	r0, 2048
  16:	0803      	bt	0x1c	// if (r0 < 0x800) goto loc_1c;
  18:	e4001fff 	subi	r0, r0, 4096	// regs: r0=(zext(*(0x4001d00c)) - 0x1000)
loc_1c:
  1c:	783c      	jmp	r15	// return;
loc_1e:
  1e:	ea007fff 	movi	r0, 32767	// regs: r0=0x7fff
  22:	07fd      	br	0x1c	// goto loc_1c;
  24:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_bknoise_get:

00000000 <ah_rfdigicali_bknoise_get>: // arg_bytes: 0
   0:	1069      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   2:	3180      	movi	r1, 128	// regs: r1=0x80
   4:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x4001d014)
   6:	4126      	lsli	r1, r1, 6	// regs: r1=0x2000
   8:	6884      	and	r2, r1	// regs: r2=(*(0x4001d014) & 0x2000)
   a:	e9020009 	bez	r2, 0x1c	// if (r2 == 0x0) goto loc_1c;
   e:	9306      	ld.w	r0, (r3, 0x18)	// regs: r0=*(0x4001d018)
  10:	7402      	sextb	r0, r0	// regs: r0=sext8(*(0x4001d018))
loc_12:
  12:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(0x4001d014)
  14:	ec422000 	ori	r2, r2, 8192	// regs: r2=(*(0x4001d014) | 0x2000)
  18:	b345      	st.w	r2, (r3, 0x14)	// *(0x4001d014) = (*(0x4001d014) | 0x2000)
  1a:	783c      	jmp	r15	// return;
loc_1c:
  1c:	3000      	movi	r0, 0	// regs: r0=0x0
  1e:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  20:	07f9      	br	0x12	// goto loc_12;
  22:	0000      	.short	0x0000
  24:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_tx_pwr:

00000000 <ah_rfdigicali_tx_pwr>: // arg_bytes: 4
   0:	106a      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   2:	3100      	movi	r1, 0	// regs: r1=0x0
   4:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(0x4001d02c)
   6:	3a8f      	bclri	r2, 15	// regs: r2=(*(0x4001d02c) & ~(0x1 << 0xf))
   8:	b34b      	st.w	r2, (r3, 0x2c)	// *(0x4001d02c) = (*(0x4001d02c) & ~(0x1 << 0xf))
   a:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(0x4001d02c)
   c:	2907      	subi	r1, 8	// regs: r1=0xfffffff8
   e:	6884      	and	r2, r1	// regs: r2=(*(0x4001d02c) & 0xfffffff8)
  10:	6c08      	or	r0, r2	// regs: r0=(<arg0> | (*(0x4001d02c) & 0xfffffff8))
  12:	b30b      	st.w	r0, (r3, 0x2c)	// *(0x4001d02c) = (<arg0> | (*(0x4001d02c) & 0xfffffff8))
  14:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(0x4001d02c)
  16:	ec420008 	ori	r2, r2, 8	// regs: r2=(*(0x4001d02c) | 0x8)
  1a:	b34b      	st.w	r2, (r3, 0x2c)	// *(0x4001d02c) = (*(0x4001d02c) | 0x8)
loc_1c:
  1c:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(0x4001d02c)
  1e:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0x4001d02c) & 0x8)
  22:	e922fffd 	bnez	r2, 0x1c	// if (r2 != 0x0) goto loc_1c;
  26:	783c      	jmp	r15	// return;
  28:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_tx_dcoc:

00000000 <ah_rfdigicali_tx_dcoc>: // arg_bytes: 8
   0:	4122      	lsli	r1, r1, 2	// regs: r1=(<arg1> << 0x2)
   2:	1071      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   4:	604c      	addu	r1, r3	// regs: r1=((<arg1> << 0x2) + 0x4001d000)
   6:	ea22fff0 	movih	r2, 65520	// regs: r2=(0xfff0 << 0x10)
   a:	916c      	ld.w	r3, (r1, 0x30)	// regs: r3=*(((<arg1> << 0x2) + 0x4001d030))
   c:	68c8      	and	r3, r2	// regs: r3=(*(((<arg1> << 0x2) + 0x4001d030)) & (0xfff0 << 0x10))
   e:	b16c      	st.w	r3, (r1, 0x30)	// *(((<arg1> << 0x2) + 0x4001d030)) = (*(((<arg1> << 0x2) + 0x4001d030)) & (0xfff0 << 0x10))
  10:	d8605001 	ld.hs	r3, (r0, 0x2)	// regs: r3=*(<arg0> + 0x2)
  14:	436a      	lsli	r3, r3, 10	// regs: r3=(*(<arg0> + 0x2) << 0xa)
  16:	ea2c0010 	movih	r12, 16	// regs: r12=(0x10 << 0x10)
  1a:	e58c13ff 	subi	r12, r12, 1024	// regs: r12=((0x10 << 0x10) - 0x400)
  1e:	914c      	ld.w	r2, (r1, 0x30)	// regs: r2=*(((<arg1> << 0x2) + 0x4001d030))
  20:	68f0      	and	r3, r12	// regs: r3=((*(<arg0> + 0x2) << 0xa) & ((0x10 << 0x10) - 0x400))
  22:	6cc8      	or	r3, r2	// regs: r3=(((*(<arg0> + 0x2) << 0xa) & ((0x10 << 0x10) - 0x400)) | *(((<arg1> << 0x2) + 0x4001d030)))
  24:	8840      	ld.h	r2, (r0, 0x0)	// regs: r2=*(<arg0>)
  26:	e44223ff 	andi	r2, r2, 1023	// regs: r2=(*(<arg0>) & 0x3ff)
  2a:	6cc8      	or	r3, r2	// regs: r3=((((*(<arg0> + 0x2) << 0xa) & ((0x10 << 0x10) - 0x400)) | *(((<arg1> << 0x2) + 0x4001d030))) | (*(<arg0>) & 0x3ff))
  2c:	b16c      	st.w	r3, (r1, 0x30)	// *(((<arg1> << 0x2) + 0x4001d030)) = ((((*(<arg0> + 0x2) << 0xa) & ((0x10 << 0x10) - 0x400)) | *(((<arg1> << 0x2) + 0x4001d030))) | (*(<arg0>) & 0x3ff))
  2e:	1066      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
  30:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(0x4001d02c)
  32:	ec420008 	ori	r2, r2, 8	// regs: r2=(*(0x4001d02c) | 0x8)
  36:	b34b      	st.w	r2, (r3, 0x2c)	// *(0x4001d02c) = (*(0x4001d02c) | 0x8)
loc_38:
  38:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(0x4001d02c)
  3a:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0x4001d02c) & 0x8)
  3e:	e922fffd 	bnez	r2, 0x38	// if (r2 != 0x0) goto loc_38;
  42:	783c      	jmp	r15	// return;
  44:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_tx_imb:

00000000 <ah_rfdigicali_config_tx_imb>: // arg_bytes: 12
   0:	4242      	lsli	r2, r2, 2	// regs: r2=(<arg2> << 0x2)
   2:	107c      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   4:	608c      	addu	r2, r3	// regs: r2=((<arg2> << 0x2) + 0x4001d000)
   6:	ea2ce010 	movih	r12, 57360	// regs: r12=(0xe010 << 0x10)
   a:	926c      	ld.w	r3, (r2, 0x30)	// regs: r3=*(((<arg2> << 0x2) + 0x4001d030))
   c:	e58c1000 	subi	r12, r12, 1	// regs: r12=((0xe010 << 0x10) - 0x1)
  10:	68f0      	and	r3, r12	// regs: r3=(*(((<arg2> << 0x2) + 0x4001d030)) & ((0xe010 << 0x10) - 0x1))
  12:	b26c      	st.w	r3, (r2, 0x30)	// *(((<arg2> << 0x2) + 0x4001d030)) = (*(((<arg2> << 0x2) + 0x4001d030)) & ((0xe010 << 0x10) - 0x1))
  14:	4014      	lsli	r0, r0, 20	// regs: r0=(<arg0> << 0x14)
  16:	ea2c1ff0 	movih	r12, 8176	// regs: r12=(0x1ff0 << 0x10)
  1a:	926c      	ld.w	r3, (r2, 0x30)	// regs: r3=*(((<arg2> << 0x2) + 0x4001d030))
  1c:	6830      	and	r0, r12	// regs: r0=((<arg0> << 0x14) & (0x1ff0 << 0x10))
  1e:	6c0c      	or	r0, r3	// regs: r0=(((<arg0> << 0x14) & (0x1ff0 << 0x10)) | *(((<arg2> << 0x2) + 0x4001d030)))
  20:	b20c      	st.w	r0, (r2, 0x30)	// *(((<arg2> << 0x2) + 0x4001d030)) = (((<arg0> << 0x14) & (0x1ff0 << 0x10)) | *(((<arg2> << 0x2) + 0x4001d030)))
  22:	30ff      	movi	r0, 255	// regs: r0=0xff
  24:	9272      	ld.w	r3, (r2, 0x48)	// regs: r3=*(((<arg2> << 0x2) + 0x4001d048))
  26:	4018      	lsli	r0, r0, 24	// regs: r0=0xff000000
  28:	eb010400 	cmphsi	r1, 1025
  2c:	68c0      	and	r3, r0	// regs: r3=(*(((<arg2> << 0x2) + 0x4001d048)) & 0xff000000)
  2e:	b272      	st.w	r3, (r2, 0x48)	// *(((<arg2> << 0x2) + 0x4001d048)) = (*(((<arg2> << 0x2) + 0x4001d048)) & 0xff000000)
  30:	0c1c      	bf	0x68	// if (r1 < 0x401) goto loc_68;
  32:	3380      	movi	r3, 128	// regs: r3=0x80
  34:	436f      	lsli	r3, r3, 15	// regs: r3=0x400000
  36:	c4238043 	divs	r3, r3, r1	// regs: r3=(0x400000 / <arg1>)
loc_3a:
  3a:	9212      	ld.w	r0, (r2, 0x48)	// regs: r0=*(((<arg2> << 0x2) + 0x4001d048))
  3c:	e4212fff 	andi	r1, r1, 4095	// regs: r1=(<arg1> & 0xfff)
  40:	6c40      	or	r1, r0	// regs: r1=((<arg1> & 0xfff) | *(((<arg2> << 0x2) + 0x4001d048)))
  42:	436c      	lsli	r3, r3, 12	// regs: r3=(r3 << 0xc)
  44:	ea00fff0 	movi	r0, 65520	// regs: r0=0xfff0
  48:	c5004900 	rotli	r0, r0, 8	// regs: r0=rotl(0xfff0, 0x8)
  4c:	68c0      	and	r3, r0	// regs: r3=((r3 << 0xc) & rotl(0xfff0, 0x8))
  4e:	6cc4      	or	r3, r1	// regs: r3=(((r3 << 0xc) & rotl(0xfff0, 0x8)) | ((<arg1> & 0xfff) | *(((<arg2> << 0x2) + 0x4001d048))))
  50:	b272      	st.w	r3, (r2, 0x48)	// *(((<arg2> << 0x2) + 0x4001d048)) = (((r3 << 0xc) & rotl(0xfff0, 0x8)) | ((<arg1> & 0xfff) | *(((<arg2> << 0x2) + 0x4001d048))))
  52:	1068      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
  54:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(0x4001d02c)
  56:	ec420008 	ori	r2, r2, 8	// regs: r2=(*(0x4001d02c) | 0x8)
  5a:	b34b      	st.w	r2, (r3, 0x2c)	// *(0x4001d02c) = (*(0x4001d02c) | 0x8)
loc_5c:
  5c:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(0x4001d02c)
  5e:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0x4001d02c) & 0x8)
  62:	e922fffd 	bnez	r2, 0x5c	// if (r2 != 0x0) goto loc_5c;
  66:	783c      	jmp	r15	// return;
loc_68:
  68:	ea030fff 	movi	r3, 4095	// regs: r3=0xfff
  6c:	07e7      	br	0x3a	// goto loc_3a;
  6e:	0000      	.short	0x0000
  70:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_tx_digi_gain:

00000000 <ah_rfdigicali_config_tx_digi_gain>: // arg_bytes: 8
   0:	eb0007ff 	cmphsi	r0, 2048
   4:	6cc3      	mov	r3, r0	// regs: r3=<arg0>
   6:	0c03      	bf	0xc	// if (r0 < 0x800) goto loc_c;
   8:	ea0307ff 	movi	r3, 2047	// regs: r3=0x7ff
loc_c:
   c:	3904      	cmphsi	r1, 5
   e:	74cd      	zexth	r3, r3	// regs: r3=zext16(r3)
  10:	1043      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
  12:	085b      	bt	0xc8	// if (r1 >= 0x5) goto loc_c8;
  14:	1003      	lrw	r0, 0x0	// regs: r0=0x0
  16:	d0200881 	ldr.w	r1, (r0, r1 << 2)	// regs: r1=*(0x0 + (<arg1> << 2))
  1a:	7804      	jmp	r1	// goto *r1;
  1c:	4001d000 	.long	0x4001d000
  20:	0000      	.short	0x0000	// <.rodata.ah_rfdigicali_config_tx_digi_gain>
  22:	0000      	.short	0x0000
  24:	d8222056 	ld.w	r1, (r2, 0x158)	// regs: r1=*(<arg2> + 0x158)
  28:	ea0007ff 	movi	r0, 2047	// regs: r0=0x7ff
  2c:	6c02      	nor	r0, r0	// regs: r0=(~0x7ff)
  2e:	6840      	and	r1, r0	// regs: r1=(*(<arg2> + 0x158) & (~0x7ff))
  30:	dc222056 	st.w	r1, (r2, 0x158)	// *(<arg2> + 0x158) = (*(<arg2> + 0x158) & (~0x7ff))
  34:	d8222056 	ld.w	r1, (r2, 0x158)	// regs: r1=*(<arg2> + 0x158)
loc_38:
  38:	6cc4      	or	r3, r1	// regs: r3=(r3 | *(<arg2> + 0x158))
  3a:	dc622056 	st.w	r3, (r2, 0x158)	// *(<arg2> + 0x158) = (r3 | *(<arg2> + 0x158))
loc_3e:
  3e:	116b      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
  40:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(0x4001d02c)
  42:	ec420008 	ori	r2, r2, 8	// regs: r2=(*(0x4001d02c) | 0x8)
  46:	b34b      	st.w	r2, (r3, 0x2c)	// *(0x4001d02c) = (*(0x4001d02c) | 0x8)
loc_48:
  48:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(0x4001d02c)
  4a:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0x4001d02c) & 0x8)
  4e:	e922fffd 	bnez	r2, 0x48	// if (r2 != 0x0) goto loc_48;
  52:	783c      	jmp	r15	// return;
  54:	ea20f801 	movih	r0, 63489	// regs: r0=(0xf801 << 0x10)
  58:	d8222056 	ld.w	r1, (r2, 0x158)	// regs: r1=*(<arg2> + 0x158)
  5c:	2800      	subi	r0, 1	// regs: r0=((0xf801 << 0x10) - 0x1)
  5e:	6840      	and	r1, r0	// regs: r1=(*(<arg2> + 0x158) & ((0xf801 << 0x10) - 0x1))
  60:	dc222056 	st.w	r1, (r2, 0x158)	// *(<arg2> + 0x158) = (*(<arg2> + 0x158) & ((0xf801 << 0x10) - 0x1))
  64:	4370      	lsli	r3, r3, 16	// regs: r3=(<arg3> << 0x10)
  66:	ea2007ff 	movih	r0, 2047	// regs: r0=(0x7ff << 0x10)
  6a:	d8222056 	ld.w	r1, (r2, 0x158)	// regs: r1=*(<arg2> + 0x158)
  6e:	68c0      	and	r3, r0	// regs: r3=((<arg3> << 0x10) & (0x7ff << 0x10))
  70:	07e4      	br	0x38	// goto loc_38;
  72:	d8222057 	ld.w	r1, (r2, 0x15c)	// regs: r1=*(<arg2> + 0x15c)
  76:	ea0007ff 	movi	r0, 2047	// regs: r0=0x7ff
  7a:	6c02      	nor	r0, r0	// regs: r0=(~0x7ff)
  7c:	6840      	and	r1, r0	// regs: r1=(*(<arg2> + 0x15c) & (~0x7ff))
  7e:	dc222057 	st.w	r1, (r2, 0x15c)	// *(<arg2> + 0x15c) = (*(<arg2> + 0x15c) & (~0x7ff))
  82:	d8222057 	ld.w	r1, (r2, 0x15c)	// regs: r1=*(<arg2> + 0x15c)
loc_86:
  86:	6cc4      	or	r3, r1	// regs: r3=(r3 | *(<arg2> + 0x15c))
  88:	dc622057 	st.w	r3, (r2, 0x15c)	// *(<arg2> + 0x15c) = (r3 | *(<arg2> + 0x15c))
  8c:	07d9      	br	0x3e	// goto loc_3e;
  8e:	ea20f801 	movih	r0, 63489	// regs: r0=(0xf801 << 0x10)
  92:	d8222057 	ld.w	r1, (r2, 0x15c)	// regs: r1=*(<arg2> + 0x15c)
  96:	2800      	subi	r0, 1	// regs: r0=((0xf801 << 0x10) - 0x1)
  98:	6840      	and	r1, r0	// regs: r1=(*(<arg2> + 0x15c) & ((0xf801 << 0x10) - 0x1))
  9a:	dc222057 	st.w	r1, (r2, 0x15c)	// *(<arg2> + 0x15c) = (*(<arg2> + 0x15c) & ((0xf801 << 0x10) - 0x1))
  9e:	4370      	lsli	r3, r3, 16	// regs: r3=(<arg3> << 0x10)
  a0:	ea2007ff 	movih	r0, 2047	// regs: r0=(0x7ff << 0x10)
  a4:	d8222057 	ld.w	r1, (r2, 0x15c)	// regs: r1=*(<arg2> + 0x15c)
  a8:	68c0      	and	r3, r0	// regs: r3=((<arg3> << 0x10) & (0x7ff << 0x10))
  aa:	07ee      	br	0x86	// goto loc_86;
  ac:	d8222058 	ld.w	r1, (r2, 0x160)	// regs: r1=*(<arg2> + 0x160)
  b0:	ea0007ff 	movi	r0, 2047	// regs: r0=0x7ff
  b4:	6c02      	nor	r0, r0	// regs: r0=(~0x7ff)
  b6:	6840      	and	r1, r0	// regs: r1=(*(<arg2> + 0x160) & (~0x7ff))
  b8:	dc222058 	st.w	r1, (r2, 0x160)	// *(<arg2> + 0x160) = (*(<arg2> + 0x160) & (~0x7ff))
  bc:	d8222058 	ld.w	r1, (r2, 0x160)	// regs: r1=*(<arg2> + 0x160)
loc_c0:
  c0:	6cc4      	or	r3, r1	// regs: r3=(r3 | r1)
  c2:	dc622058 	st.w	r3, (r2, 0x160)	// *(r2 + 0x160) = (r3 | r1)
  c6:	07bc      	br	0x3e	// goto loc_3e;
loc_c8:
  c8:	ea20f801 	movih	r0, 63489	// regs: r0=(0xf801 << 0x10)
  cc:	d8222058 	ld.w	r1, (r2, 0x160)	// regs: r1=*(0x4001d160)
  d0:	2800      	subi	r0, 1	// regs: r0=((0xf801 << 0x10) - 0x1)
  d2:	6840      	and	r1, r0	// regs: r1=(*(0x4001d160) & ((0xf801 << 0x10) - 0x1))
  d4:	dc222058 	st.w	r1, (r2, 0x160)	// *(0x4001d160) = (*(0x4001d160) & ((0xf801 << 0x10) - 0x1))
  d8:	4370      	lsli	r3, r3, 16	// regs: r3=(zext16(r3) << 0x10)
  da:	ea2007ff 	movih	r0, 2047	// regs: r0=(0x7ff << 0x10)
  de:	d8222058 	ld.w	r1, (r2, 0x160)	// regs: r1=*(0x4001d160)
  e2:	68c0      	and	r3, r0	// regs: r3=((zext16(r3) << 0x10) & (0x7ff << 0x10))
  e4:	07ee      	br	0xc0	// goto loc_c0;
  e6:	0000      	.short	0x0000
  e8:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_rx_gain:

00000000 <ah_rfdigicali_config_rx_gain>: // arg_bytes: 8
   0:	1071      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   2:	4128      	lsli	r1, r1, 8	// regs: r1=(<arg1> << 0x8)
   4:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
   6:	3a88      	bclri	r2, 8	// regs: r2=(*(0x4001d060) & ~(0x1 << 0x8))
   8:	3a89      	bclri	r2, 9	// regs: r2=((*(0x4001d060) & ~(0x1 << 0x8)) & ~(0x1 << 0x9))
   a:	6c84      	or	r2, r1	// regs: r2=(((*(0x4001d060) & ~(0x1 << 0x8)) & ~(0x1 << 0x9)) | (<arg1> << 0x8))
   c:	b358      	st.w	r2, (r3, 0x60)	// *(0x4001d060) = (((*(0x4001d060) & ~(0x1 << 0x8)) & ~(0x1 << 0x9)) | (<arg1> << 0x8))
   e:	3100      	movi	r1, 0	// regs: r1=0x0
  10:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
  12:	2907      	subi	r1, 8	// regs: r1=0xfffffff8
  14:	6884      	and	r2, r1	// regs: r2=(*(0x4001d060) & 0xfffffff8)
  16:	b358      	st.w	r2, (r3, 0x60)	// *(0x4001d060) = (*(0x4001d060) & 0xfffffff8)
  18:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
  1a:	6c80      	or	r2, r0	// regs: r2=(*(0x4001d060) | <arg0>)
  1c:	b358      	st.w	r2, (r3, 0x60)	// *(0x4001d060) = (*(0x4001d060) | <arg0>)
  1e:	3100      	movi	r1, 0	// regs: r1=0x0
  20:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
  22:	29e0      	subi	r1, 225	// regs: r1=0xffffff1f
  24:	6884      	and	r2, r1	// regs: r2=(*(0x4001d060) & 0xffffff1f)
  26:	b358      	st.w	r2, (r3, 0x60)	// *(0x4001d060) = (*(0x4001d060) & 0xffffff1f)
  28:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
  2a:	4005      	lsli	r0, r0, 5	// regs: r0=(<arg0> << 0x5)
  2c:	6c08      	or	r0, r2	// regs: r0=((<arg0> << 0x5) | *(0x4001d060))
  2e:	b318      	st.w	r0, (r3, 0x60)	// *(0x4001d060) = ((<arg0> << 0x5) | *(0x4001d060))
  30:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
  32:	ec420008 	ori	r2, r2, 8	// regs: r2=(*(0x4001d060) | 0x8)
  36:	b358      	st.w	r2, (r3, 0x60)	// *(0x4001d060) = (*(0x4001d060) | 0x8)
loc_38:
  38:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
  3a:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0x4001d060) & 0x8)
  3e:	e922fffd 	bnez	r2, 0x38	// if (r2 != 0x0) goto loc_38;
  42:	783c      	jmp	r15	// return;
  44:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_rx_dcoc:

00000000 <ah_rfdigicali_config_rx_dcoc>: // arg_bytes: 12
   0:	3a03      	cmphsi	r2, 4
   2:	8861      	ld.h	r3, (r0, 0x2)	// regs: r3=*(<arg0> + 0x2)
   4:	8800      	ld.h	r0, (r0, 0x0)	// regs: r0=*(<arg0>)
   6:	0826      	bt	0x52	// if (r2 >= 0x4) goto loc_52;
   8:	770b      	sexth	r12, r2	// regs: r12=sext16(<arg2>)
   a:	c58c0022 	addu	r2, r12, r12	// regs: r2=(sext16(<arg2>) + sext16(<arg2>))
   e:	60b0      	addu	r2, r12	// regs: r2=((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>))
  10:	4242      	lsli	r2, r2, 2	// regs: r2=(((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)
  12:	6048      	addu	r1, r2	// regs: r1=(<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2))
  14:	4122      	lsli	r1, r1, 2	// regs: r1=((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2)
  16:	105c      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
  18:	6048      	addu	r1, r2	// regs: r1=(((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d000)
  1a:	ea2cfff0 	movih	r12, 65520	// regs: r12=(0xfff0 << 0x10)
  1e:	9159      	ld.w	r2, (r1, 0x64)	// regs: r2=*((((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d064))
  20:	68b0      	and	r2, r12	// regs: r2=(*((((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d064)) & (0xfff0 << 0x10))
  22:	436a      	lsli	r3, r3, 10	// regs: r3=(*(<arg0> + 0x2) << 0xa)
  24:	ea2c0010 	movih	r12, 16	// regs: r12=(0x10 << 0x10)
  28:	e58c13ff 	subi	r12, r12, 1024	// regs: r12=((0x10 << 0x10) - 0x400)
  2c:	b159      	st.w	r2, (r1, 0x64)	// *((((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d064)) = (*((((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d064)) & (0xfff0 << 0x10))
  2e:	68f0      	and	r3, r12	// regs: r3=((*(<arg0> + 0x2) << 0xa) & ((0x10 << 0x10) - 0x400))
  30:	e40023ff 	andi	r0, r0, 1023	// regs: r0=(*(<arg0>) & 0x3ff)
  34:	9159      	ld.w	r2, (r1, 0x64)	// regs: r2=*((((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d064))
  36:	6cc0      	or	r3, r0	// regs: r3=(((*(<arg0> + 0x2) << 0xa) & ((0x10 << 0x10) - 0x400)) | (*(<arg0>) & 0x3ff))
  38:	6cc8      	or	r3, r2	// regs: r3=((((*(<arg0> + 0x2) << 0xa) & ((0x10 << 0x10) - 0x400)) | (*(<arg0>) & 0x3ff)) | *((((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d064)))
  3a:	b179      	st.w	r3, (r1, 0x64)	// *((((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d064)) = ((((*(<arg0> + 0x2) << 0xa) & ((0x10 << 0x10) - 0x400)) | (*(<arg0>) & 0x3ff)) | *((((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d064)))
loc_3c:
  3c:	1072      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
  3e:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
  40:	ec420008 	ori	r2, r2, 8	// regs: r2=(*(0x4001d060) | 0x8)
  44:	b358      	st.w	r2, (r3, 0x60)	// *(0x4001d060) = (*(0x4001d060) | 0x8)
loc_46:
  46:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
  48:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0x4001d060) & 0x8)
  4c:	e922fffd 	bnez	r2, 0x46	// if (r2 != 0x0) goto loc_46;
  50:	783c      	jmp	r15	// return;
loc_52:
  52:	104d      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
  54:	4122      	lsli	r1, r1, 2	// regs: r1=(<arg1> << 0x2)
  56:	6048      	addu	r1, r2	// regs: r1=((<arg1> << 0x2) + 0x4001d000)
  58:	ea2cfff0 	movih	r12, 65520	// regs: r12=(0xfff0 << 0x10)
  5c:	d8412049 	ld.w	r2, (r1, 0x124)	// regs: r2=*(((<arg1> << 0x2) + 0x4001d124))
  60:	68b0      	and	r2, r12	// regs: r2=(*(((<arg1> << 0x2) + 0x4001d124)) & (0xfff0 << 0x10))
  62:	dc412049 	st.w	r2, (r1, 0x124)	// *(((<arg1> << 0x2) + 0x4001d124)) = (*(((<arg1> << 0x2) + 0x4001d124)) & (0xfff0 << 0x10))
  66:	436a      	lsli	r3, r3, 10	// regs: r3=(*(<arg0> + 0x2) << 0xa)
  68:	ea2c0010 	movih	r12, 16	// regs: r12=(0x10 << 0x10)
  6c:	e58c13ff 	subi	r12, r12, 1024	// regs: r12=((0x10 << 0x10) - 0x400)
  70:	d8412049 	ld.w	r2, (r1, 0x124)	// regs: r2=*(((<arg1> << 0x2) + 0x4001d124))
  74:	68f0      	and	r3, r12	// regs: r3=((*(<arg0> + 0x2) << 0xa) & ((0x10 << 0x10) - 0x400))
  76:	6cc8      	or	r3, r2	// regs: r3=(((*(<arg0> + 0x2) << 0xa) & ((0x10 << 0x10) - 0x400)) | *(((<arg1> << 0x2) + 0x4001d124)))
  78:	e40023ff 	andi	r0, r0, 1023	// regs: r0=(*(<arg0>) & 0x3ff)
  7c:	6cc0      	or	r3, r0	// regs: r3=((((*(<arg0> + 0x2) << 0xa) & ((0x10 << 0x10) - 0x400)) | *(((<arg1> << 0x2) + 0x4001d124))) | (*(<arg0>) & 0x3ff))
  7e:	dc612049 	st.w	r3, (r1, 0x124)	// *(((<arg1> << 0x2) + 0x4001d124)) = ((((*(<arg0> + 0x2) << 0xa) & ((0x10 << 0x10) - 0x400)) | *(((<arg1> << 0x2) + 0x4001d124))) | (*(<arg0>) & 0x3ff))
  82:	07dd      	br	0x3c	// goto loc_3c;
  84:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_rx_imb:

00000000 <ah_rfdigicali_config_rx_imb>: // arg_bytes: 16
   0:	eb010400 	cmphsi	r1, 1025
   4:	0c3d      	bf	0x7e	// if (r1 < 0x401) goto loc_7e;
   6:	ea0c0080 	movi	r12, 128	// regs: r12=0x80
   a:	c5ec482c 	lsli	r12, r12, 15	// regs: r12=0x400000
   e:	c42c804c 	divs	r12, r12, r1	// regs: r12=(0x400000 / <arg1>)
loc_12:
  12:	3b03      	cmphsi	r3, 4
  14:	4014      	lsli	r0, r0, 20	// regs: r0=(<arg0> << 0x14)
  16:	c58c482d 	lsli	r13, r12, 12	// regs: r13=(r12 << 0xc)
  1a:	e4212fff 	andi	r1, r1, 4095	// regs: r1=(<arg1> & 0xfff)
  1e:	0833      	bt	0x84	// if (r3 >= 0x4) goto loc_84;
  20:	770f      	sexth	r12, r3	// regs: r12=sext16(<arg3>)
  22:	c58c0023 	addu	r3, r12, r12	// regs: r3=(sext16(<arg3>) + sext16(<arg3>))
  26:	60f0      	addu	r3, r12	// regs: r3=((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>))
  28:	4362      	lsli	r3, r3, 2	// regs: r3=(((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)
  2a:	608c      	addu	r2, r3	// regs: r2=(<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2))
  2c:	4242      	lsli	r2, r2, 2	// regs: r2=((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2)
  2e:	116a      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
  30:	608c      	addu	r2, r3	// regs: r2=(((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d000)
  32:	ea2cc010 	movih	r12, 49168	// regs: r12=(0xc010 << 0x10)
  36:	9279      	ld.w	r3, (r2, 0x64)	// regs: r3=*((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d064))
  38:	e58c1000 	subi	r12, r12, 1	// regs: r12=((0xc010 << 0x10) - 0x1)
  3c:	68f0      	and	r3, r12	// regs: r3=(*((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d064)) & ((0xc010 << 0x10) - 0x1))
  3e:	b279      	st.w	r3, (r2, 0x64)	// *((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d064)) = (*((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d064)) & ((0xc010 << 0x10) - 0x1))
  40:	ea2c3ff0 	movih	r12, 16368	// regs: r12=(0x3ff0 << 0x10)
  44:	9279      	ld.w	r3, (r2, 0x64)	// regs: r3=*((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d064))
  46:	6830      	and	r0, r12	// regs: r0=((<arg0> << 0x14) & (0x3ff0 << 0x10))
  48:	6c0c      	or	r0, r3	// regs: r0=(((<arg0> << 0x14) & (0x3ff0 << 0x10)) | *((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d064)))
  4a:	b219      	st.w	r0, (r2, 0x64)	// *((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d064)) = (((<arg0> << 0x14) & (0x3ff0 << 0x10)) | *((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d064)))
  4c:	30ff      	movi	r0, 255	// regs: r0=0xff
  4e:	927f      	ld.w	r3, (r2, 0x7c)	// regs: r3=*((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d07c))
  50:	4018      	lsli	r0, r0, 24	// regs: r0=0xff000000
  52:	68c0      	and	r3, r0	// regs: r3=(*((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d07c)) & 0xff000000)
  54:	b27f      	st.w	r3, (r2, 0x7c)	// *((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d07c)) = (*((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d07c)) & 0xff000000)
  56:	927f      	ld.w	r3, (r2, 0x7c)	// regs: r3=*((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d07c))
  58:	ea00fff0 	movi	r0, 65520	// regs: r0=0xfff0
  5c:	c5004900 	rotli	r0, r0, 8	// regs: r0=rotl(0xfff0, 0x8)
  60:	6b40      	and	r13, r0	// regs: r13=((r12 << 0xc) & rotl(0xfff0, 0x8))
  62:	6c4c      	or	r1, r3	// regs: r1=((<arg1> & 0xfff) | *((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d07c)))
  64:	6c74      	or	r1, r13	// regs: r1=(((<arg1> & 0xfff) | *((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d07c))) | ((r12 << 0xc) & rotl(0xfff0, 0x8)))
  66:	b23f      	st.w	r1, (r2, 0x7c)	// *((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d07c)) = (((<arg1> & 0xfff) | *((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d07c))) | ((r12 << 0xc) & rotl(0xfff0, 0x8)))
loc_68:
  68:	107b      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
  6a:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
  6c:	ec420008 	ori	r2, r2, 8	// regs: r2=(*(0x4001d060) | 0x8)
  70:	b358      	st.w	r2, (r3, 0x60)	// *(0x4001d060) = (*(0x4001d060) | 0x8)
loc_72:
  72:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
  74:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0x4001d060) & 0x8)
  78:	e922fffd 	bnez	r2, 0x72	// if (r2 != 0x0) goto loc_72;
  7c:	783c      	jmp	r15	// return;
loc_7e:
  7e:	ea0c0fff 	movi	r12, 4095	// regs: r12=0xfff
  82:	07c8      	br	0x12	// goto loc_12;
loc_84:
  84:	1074      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
  86:	4242      	lsli	r2, r2, 2	// regs: r2=(<arg2> << 0x2)
  88:	608c      	addu	r2, r3	// regs: r2=((<arg2> << 0x2) + 0x4001d000)
  8a:	ea2cc010 	movih	r12, 49168	// regs: r12=(0xc010 << 0x10)
  8e:	d8622049 	ld.w	r3, (r2, 0x124)	// regs: r3=*(((<arg2> << 0x2) + 0x4001d124))
  92:	e58c1000 	subi	r12, r12, 1	// regs: r12=((0xc010 << 0x10) - 0x1)
  96:	68f0      	and	r3, r12	// regs: r3=(*(((<arg2> << 0x2) + 0x4001d124)) & ((0xc010 << 0x10) - 0x1))
  98:	dc622049 	st.w	r3, (r2, 0x124)	// *(((<arg2> << 0x2) + 0x4001d124)) = (*(((<arg2> << 0x2) + 0x4001d124)) & ((0xc010 << 0x10) - 0x1))
  9c:	ea2c3ff0 	movih	r12, 16368	// regs: r12=(0x3ff0 << 0x10)
  a0:	d8622049 	ld.w	r3, (r2, 0x124)	// regs: r3=*(((<arg2> << 0x2) + 0x4001d124))
  a4:	6830      	and	r0, r12	// regs: r0=((<arg0> << 0x14) & (0x3ff0 << 0x10))
  a6:	6c0c      	or	r0, r3	// regs: r0=(((<arg0> << 0x14) & (0x3ff0 << 0x10)) | *(((<arg2> << 0x2) + 0x4001d124)))
  a8:	dc022049 	st.w	r0, (r2, 0x124)	// *(((<arg2> << 0x2) + 0x4001d124)) = (((<arg0> << 0x14) & (0x3ff0 << 0x10)) | *(((<arg2> << 0x2) + 0x4001d124)))
  ac:	30ff      	movi	r0, 255	// regs: r0=0xff
  ae:	d862204f 	ld.w	r3, (r2, 0x13c)	// regs: r3=*(((<arg2> << 0x2) + 0x4001d13c))
  b2:	4018      	lsli	r0, r0, 24	// regs: r0=0xff000000
  b4:	68c0      	and	r3, r0	// regs: r3=(*(((<arg2> << 0x2) + 0x4001d13c)) & 0xff000000)
  b6:	dc62204f 	st.w	r3, (r2, 0x13c)	// *(((<arg2> << 0x2) + 0x4001d13c)) = (*(((<arg2> << 0x2) + 0x4001d13c)) & 0xff000000)
  ba:	d862204f 	ld.w	r3, (r2, 0x13c)	// regs: r3=*(((<arg2> << 0x2) + 0x4001d13c))
  be:	6c4c      	or	r1, r3	// regs: r1=((<arg1> & 0xfff) | *(((<arg2> << 0x2) + 0x4001d13c)))
  c0:	ea03fff0 	movi	r3, 65520	// regs: r3=0xfff0
  c4:	c5034903 	rotli	r3, r3, 8	// regs: r3=rotl(0xfff0, 0x8)
  c8:	6b4c      	and	r13, r3	// regs: r13=((r12 << 0xc) & rotl(0xfff0, 0x8))
  ca:	6c74      	or	r1, r13	// regs: r1=(((<arg1> & 0xfff) | *(((<arg2> << 0x2) + 0x4001d13c))) | ((r12 << 0xc) & rotl(0xfff0, 0x8)))
  cc:	dc22204f 	st.w	r1, (r2, 0x13c)	// *(((<arg2> << 0x2) + 0x4001d13c)) = (((<arg1> & 0xfff) | *(((<arg2> << 0x2) + 0x4001d13c))) | ((r12 << 0xc) & rotl(0xfff0, 0x8)))
  d0:	07cc      	br	0x68	// goto loc_68;
  d2:	0000      	.short	0x0000
  d4:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_tx_gain_idx_src:

00000000 <ah_rfdigicali_config_tx_gain_idx_src>: // arg_bytes: 4
   0:	1066      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   2:	400f      	lsli	r0, r0, 15	// regs: r0=(<arg0> << 0xf)
   4:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(0x4001d02c)
   6:	3a8f      	bclri	r2, 15	// regs: r2=(*(0x4001d02c) & ~(0x1 << 0xf))
   8:	b34b      	st.w	r2, (r3, 0x2c)	// *(0x4001d02c) = (*(0x4001d02c) & ~(0x1 << 0xf))
   a:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(0x4001d02c)
   c:	c40055e0 	zext	r0, r0, 15, 0	// regs: r0=zext((<arg0> << 0xf))
  10:	6c08      	or	r0, r2	// regs: r0=(zext((<arg0> << 0xf)) | *(0x4001d02c))
  12:	b30b      	st.w	r0, (r3, 0x2c)	// *(0x4001d02c) = (zext((<arg0> << 0xf)) | *(0x4001d02c))
  14:	783c      	jmp	r15	// return;
  16:	0000      	.short	0x0000
  18:	d000      	.short	0xd000
  1a:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_config_rx_gain_idx_src:

00000000 <ah_rfdigicali_config_rx_gain_idx_src>: // arg_bytes: 4
   0:	1066      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   2:	4004      	lsli	r0, r0, 4	// regs: r0=(<arg0> << 0x4)
   4:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
   6:	3a84      	bclri	r2, 4	// regs: r2=(*(0x4001d060) & ~(0x1 << 0x4))
   8:	b358      	st.w	r2, (r3, 0x60)	// *(0x4001d060) = (*(0x4001d060) & ~(0x1 << 0x4))
   a:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
   c:	e4002010 	andi	r0, r0, 16	// regs: r0=((<arg0> << 0x4) & 0x10)
  10:	6c08      	or	r0, r2	// regs: r0=(((<arg0> << 0x4) & 0x10) | *(0x4001d060))
  12:	b318      	st.w	r0, (r3, 0x60)	// *(0x4001d060) = (((<arg0> << 0x4) & 0x10) | *(0x4001d060))
  14:	783c      	jmp	r15	// return;
  16:	0000      	.short	0x0000
  18:	d000      	.short	0xd000
  1a:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_config_rx_filter:

00000000 <ah_rfdigicali_config_rx_filter>: // arg_bytes: 4
   0:	4001      	lsli	r0, r0, 1	// regs: r0=(<arg0> << 0x1)
   2:	1047      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
   4:	3300      	movi	r3, 0	// regs: r3=0x0
   6:	e4002006 	andi	r0, r0, 6	// regs: r0=((<arg0> << 0x1) & 0x6)
   a:	2b1f      	subi	r3, 32	// regs: r3=0xffffffe0
   c:	ec000011 	ori	r0, r0, 17	// regs: r0=(((<arg0> << 0x1) & 0x6) | 0x11)
  10:	dc622055 	st.w	r3, (r2, 0x154)	// *(0x4001d154) = 0xffffffe0
  14:	dc022055 	st.w	r0, (r2, 0x154)	// *(0x4001d154) = (((<arg0> << 0x1) & 0x6) | 0x11)
  18:	783c      	jmp	r15	// return;
  1a:	0000      	.short	0x0000
  1c:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_config_rx_filter_auto:

00000000 <ah_rfdigicali_config_rx_filter_auto>: // arg_bytes: 0
   0:	1045      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
   2:	3300      	movi	r3, 0	// regs: r3=0x0
   4:	2b19      	subi	r3, 26	// regs: r3=0xffffffe6
   6:	dc622055 	st.w	r3, (r2, 0x154)	// *(0x4001d154) = 0xffffffe6
   a:	3319      	movi	r3, 25	// regs: r3=0x19
   c:	dc622055 	st.w	r3, (r2, 0x154)	// *(0x4001d154) = 0x19
  10:	783c      	jmp	r15	// return;
  12:	0000      	.short	0x0000
  14:	d000      	.short	0xd000
  16:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_get_rx_dcoc:

00000000 <ah_rfdigicali_get_rx_dcoc>: // arg_bytes: 16
   0:	3a03      	cmphsi	r2, 4
   2:	0812      	bt	0x26	// if (r2 >= 0x4) goto loc_26;
   4:	74cb      	sexth	r3, r2	// regs: r3=sext16(<arg2>)
   6:	5b4c      	addu	r2, r3, r3	// regs: r2=(sext16(<arg2>) + sext16(<arg2>))
   8:	608c      	addu	r2, r3	// regs: r2=((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>))
   a:	4242      	lsli	r2, r2, 2	// regs: r2=(((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)
   c:	6048      	addu	r1, r2	// regs: r1=(<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2))
   e:	106c      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
  10:	4122      	lsli	r1, r1, 2	// regs: r1=((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2)
  12:	604c      	addu	r1, r3	// regs: r1=(((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d000)
  14:	9179      	ld.w	r3, (r1, 0x64)	// regs: r3=*((((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d064))
  16:	e46323ff 	andi	r3, r3, 1023	// regs: r3=(*((((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d064)) & 0x3ff)
  1a:	a860      	st.h	r3, (r0, 0x0)	// *(<arg0>) = (*((((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d064)) & 0x3ff)
  1c:	9179      	ld.w	r3, (r1, 0x64)	// regs: r3=*((((<arg1> + (((sext16(<arg2>) + sext16(<arg2>)) + sext16(<arg2>)) << 0x2)) << 0x2) + 0x4001d064))
loc_1e:
  1e:	c5435663 	zext	r3, r3, 19, 10	// regs: r3=zext(r3)
  22:	a861      	st.h	r3, (r0, 0x2)	// *(<arg0> + 0x2) = zext(r3)
  24:	783c      	jmp	r15	// return;
loc_26:
  26:	1066      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
  28:	4122      	lsli	r1, r1, 2	// regs: r1=(<arg1> << 0x2)
  2a:	604c      	addu	r1, r3	// regs: r1=((<arg1> << 0x2) + 0x4001d000)
  2c:	d8612049 	ld.w	r3, (r1, 0x124)	// regs: r3=*(((<arg1> << 0x2) + 0x4001d124))
  30:	e46323ff 	andi	r3, r3, 1023	// regs: r3=(*(((<arg1> << 0x2) + 0x4001d124)) & 0x3ff)
  34:	a860      	st.h	r3, (r0, 0x0)	// *(<arg0>) = (*(((<arg1> << 0x2) + 0x4001d124)) & 0x3ff)
  36:	d8612049 	ld.w	r3, (r1, 0x124)	// regs: r3=*(((<arg1> << 0x2) + 0x4001d124))
  3a:	07f2      	br	0x1e	// goto loc_1e;
  3c:	d000      	.short	0xd000
  3e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfdigicali_get_rx_imb:

00000000 <ah_rfdigicali_get_rx_imb>: // arg_bytes: 16
   0:	3b03      	cmphsi	r3, 4
   2:	0813      	bt	0x28	// if (r3 >= 0x4) goto loc_28;
   4:	770f      	sexth	r12, r3	// regs: r12=sext16(<arg3>)
   6:	c58c0023 	addu	r3, r12, r12	// regs: r3=(sext16(<arg3>) + sext16(<arg3>))
   a:	60f0      	addu	r3, r12	// regs: r3=((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>))
   c:	4362      	lsli	r3, r3, 2	// regs: r3=(((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)
   e:	608c      	addu	r2, r3	// regs: r2=(<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2))
  10:	4242      	lsli	r2, r2, 2	// regs: r2=((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2)
  12:	106c      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
  14:	608c      	addu	r2, r3	// regs: r2=(((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d000)
  16:	9279      	ld.w	r3, (r2, 0x64)	// regs: r3=*((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d064))
  18:	c68357a3 	zext	r3, r3, 29, 20	// regs: r3=zext(*((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d064)))
  1c:	a860      	st.h	r3, (r0, 0x0)	// *(<arg0>) = zext(*((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d064)))
  1e:	927f      	ld.w	r3, (r2, 0x7c)	// regs: r3=*((((<arg2> + (((sext16(<arg3>) + sext16(<arg3>)) + sext16(<arg3>)) << 0x2)) << 0x2) + 0x4001d07c))
loc_20:
  20:	e4632fff 	andi	r3, r3, 4095	// regs: r3=(r3 & 0xfff)
  24:	a960      	st.h	r3, (r1, 0x0)	// *(<arg1>) = (r3 & 0xfff)
  26:	783c      	jmp	r15	// return;
loc_28:
  28:	1066      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
  2a:	4242      	lsli	r2, r2, 2	// regs: r2=(<arg2> << 0x2)
  2c:	608c      	addu	r2, r3	// regs: r2=((<arg2> << 0x2) + 0x4001d000)
  2e:	d8622049 	ld.w	r3, (r2, 0x124)	// regs: r3=*(((<arg2> << 0x2) + 0x4001d124))
  32:	c68357a3 	zext	r3, r3, 29, 20	// regs: r3=zext(*(((<arg2> << 0x2) + 0x4001d124)))
  36:	a860      	st.h	r3, (r0, 0x0)	// *(<arg0>) = zext(*(((<arg2> << 0x2) + 0x4001d124)))
  38:	d862204f 	ld.w	r3, (r2, 0x13c)	// regs: r3=*(((<arg2> << 0x2) + 0x4001d13c))
  3c:	07f2      	br	0x20	// goto loc_20;
  3e:	0000      	.short	0x0000
  40:	4001d000 	.long	0x4001d000

Disassembly of section .text.ah_rfdigicali_get_tx_digi_gain:

00000000 <ah_rfdigicali_get_tx_digi_gain>: // arg_bytes: 4
   0:	3804      	cmphsi	r0, 5
   2:	1064      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   4:	081d      	bt	0x3e	// if (r0 >= 0x5) goto loc_3e;
   6:	1044      	lrw	r2, 0x0	// regs: r2=0x0
   8:	d0020882 	ldr.w	r2, (r2, r0 << 2)	// regs: r2=*(0x0 + (<arg0> << 2))
   c:	7808      	jmp	r2	// goto *r2;
   e:	0000      	.short	0x0000
  10:	d000      	.short	0xd000
  12:	4001      	.short	0x4001
  14:	0000      	.short	0x0000	// <.rodata.ah_rfdigicali_get_tx_digi_gain>
  16:	0000      	.short	0x0000
  18:	d8032056 	ld.w	r0, (r3, 0x158)	// regs: r0=*(<arg3> + 0x158)
loc_1c:
  1c:	e40027ff 	andi	r0, r0, 2047	// regs: r0=(r0 & 0x7ff)
loc_20:
  20:	783c      	jmp	r15	// return;
  22:	d8032056 	ld.w	r0, (r3, 0x158)	// regs: r0=*(<arg3> + 0x158)
loc_26:
  26:	c6005740 	zext	r0, r0, 26, 16	// regs: r0=zext(r0)
  2a:	07fb      	br	0x20	// goto loc_20;
  2c:	d8032057 	ld.w	r0, (r3, 0x15c)	// regs: r0=*(<arg3> + 0x15c)
  30:	07f6      	br	0x1c	// goto loc_1c;
  32:	d8032057 	ld.w	r0, (r3, 0x15c)	// regs: r0=*(<arg3> + 0x15c)
  36:	07f8      	br	0x26	// goto loc_26;
  38:	d8032058 	ld.w	r0, (r3, 0x160)	// regs: r0=*(<arg3> + 0x160)
  3c:	07f0      	br	0x1c	// goto loc_1c;
loc_3e:
  3e:	d8032058 	ld.w	r0, (r3, 0x160)	// regs: r0=*(0x4001d160)
  42:	07f2      	br	0x26	// goto loc_26;

Disassembly of section .text.ah_rfdigicali_cfg_fb_comp:

00000000 <ah_rfdigicali_cfg_fb_comp>: // arg_bytes: 4
   0:	106f      	lrw	r3, 0x4001d000	// regs: r3=0x4001d000
   2:	9344      	ld.w	r2, (r3, 0x10)	// regs: r2=*(0x4001d010)
   4:	3a99      	bclri	r2, 25	// regs: r2=(*(0x4001d010) & ~(0x1 << 0x19))
   6:	b344      	st.w	r2, (r3, 0x10)	// *(0x4001d010) = (*(0x4001d010) & ~(0x1 << 0x19))
   8:	9358      	ld.w	r2, (r3, 0x60)	// regs: r2=*(0x4001d060)
   a:	e9200011 	bnez	r0, 0x2c	// if (r0 != 0x0) goto loc_2c;
   e:	3a8a      	bclri	r2, 10	// regs: r2=(*(0x4001d060) & ~(0x1 << 0xa))
  10:	b358      	st.w	r2, (r3, 0x60)	// *(0x4001d060) = (*(0x4001d060) & ~(0x1 << 0xa))
  12:	d8432055 	ld.w	r2, (r3, 0x154)	// regs: r2=*(0x4001d154)
  16:	3a80      	bclri	r2, 0	// regs: r2=(*(0x4001d154) & ~(0x1 << 0x0))
loc_18:
  18:	dc432055 	st.w	r2, (r3, 0x154)	// *(0x4001d154) = r2
  1c:	1048      	lrw	r2, 0x4001d000	// regs: r2=0x4001d000
  1e:	d8622055 	ld.w	r3, (r2, 0x154)	// regs: r3=*(0x4001d154)
  22:	ec630010 	ori	r3, r3, 16	// regs: r3=(*(0x4001d154) | 0x10)
  26:	dc622055 	st.w	r3, (r2, 0x154)	// *(0x4001d154) = (*(0x4001d154) | 0x10)
  2a:	783c      	jmp	r15	// return;
loc_2c:
  2c:	ec420400 	ori	r2, r2, 1024	// regs: r2=(*(0x4001d060) | 0x400)
  30:	b358      	st.w	r2, (r3, 0x60)	// *(0x4001d060) = (*(0x4001d060) | 0x400)
  32:	d8432055 	ld.w	r2, (r3, 0x154)	// regs: r2=*(0x4001d154)
  36:	ec420001 	ori	r2, r2, 1	// regs: r2=(*(0x4001d154) | 0x1)
  3a:	07ef      	br	0x18	// goto loc_18;
  3c:	d000      	.short	0xd000
  3e:	4001      	.short	0x4001
