
libs\obj\liblmac\mars_rfspi.o:     file format elf32-csky-little


Disassembly of section .text.rfspi_pin_func:

00000000 <rfspi_pin_func>: // arg_bytes: 4
   0:	14d0      	push	r15
   2:	3841      	cmpnei	r0, 1
   4:	116a      	lrw	r3, 0x40026000	// regs: r3=0x40026000
   6:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x40026000)
   8:	0817      	bt	0x36	// if (r0 != 0x1) goto loc_36;
   a:	3ab5      	bseti	r2, 21	// regs: r2=(*(0x40026000) | (0x1 << 0x15))
   c:	b340      	st.w	r2, (r3, 0x0)	// *(0x40026000) = (*(0x40026000) | (0x1 << 0x15))
   e:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x40026000)
  10:	3a96      	bclri	r2, 22	// regs: r2=(*(0x40026000) & ~(0x1 << 0x16))
  12:	b340      	st.w	r2, (r3, 0x0)	// *(0x40026000) = (*(0x40026000) & ~(0x1 << 0x16))
  14:	3103      	movi	r1, 3	// regs: r1=0x3
  16:	3016      	movi	r0, 22	// regs: r0=0x16
  18:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x18>, r1=<clobbered>
  1c:	3103      	movi	r1, 3	// regs: r1=0x3
  1e:	3017      	movi	r0, 23	// regs: r0=0x17
  20:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x20>, r1=<clobbered>
  24:	3103      	movi	r1, 3	// regs: r1=0x3
  26:	3018      	movi	r0, 24	// regs: r0=0x18
  28:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x28>, r1=<clobbered>
  2c:	3103      	movi	r1, 3	// regs: r1=0x3
loc_2e:
  2e:	3019      	movi	r0, 25	// regs: r0=0x19
  30:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x30>, r1=<clobbered>
loc_34:
  34:	1490      	pop	r15
loc_36:
  36:	3a95      	bclri	r2, 21	// regs: r2=(*(0x40026000) & ~(0x1 << 0x15))
  38:	3842      	cmpnei	r0, 2
  3a:	b340      	st.w	r2, (r3, 0x0)	// *(0x40026000) = (*(0x40026000) & ~(0x1 << 0x15))
  3c:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x40026000)
  3e:	0811      	bt	0x60	// if (r0 != 0x2) goto loc_60;
  40:	3a96      	bclri	r2, 22	// regs: r2=(*(0x40026000) & ~(0x1 << 0x16))
  42:	b340      	st.w	r2, (r3, 0x0)	// *(0x40026000) = (*(0x40026000) & ~(0x1 << 0x16))
  44:	3104      	movi	r1, 4	// regs: r1=0x4
  46:	3016      	movi	r0, 22	// regs: r0=0x16
  48:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x48>, r1=<clobbered>
  4c:	3104      	movi	r1, 4	// regs: r1=0x4
  4e:	3017      	movi	r0, 23	// regs: r0=0x17
  50:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x50>, r1=<clobbered>
  54:	3104      	movi	r1, 4	// regs: r1=0x4
  56:	3018      	movi	r0, 24	// regs: r0=0x18
  58:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x58>, r1=<clobbered>
  5c:	3104      	movi	r1, 4	// regs: r1=0x4
  5e:	07e8      	br	0x2e	// goto loc_2e;
loc_60:
  60:	3843      	cmpnei	r0, 3
  62:	0811      	bt	0x84	// if (r0 != 0x3) goto loc_84;
  64:	3ab6      	bseti	r2, 22	// regs: r2=(*(0x40026000) | (0x1 << 0x16))
  66:	b340      	st.w	r2, (r3, 0x0)	// *(0x40026000) = (*(0x40026000) | (0x1 << 0x16))
  68:	3101      	movi	r1, 1	// regs: r1=0x1
  6a:	3016      	movi	r0, 22	// regs: r0=0x16
  6c:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x6c>, r1=<clobbered>
  70:	3101      	movi	r1, 1	// regs: r1=0x1
  72:	3017      	movi	r0, 23	// regs: r0=0x17
  74:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x74>, r1=<clobbered>
  78:	3101      	movi	r1, 1	// regs: r1=0x1
  7a:	3018      	movi	r0, 24	// regs: r0=0x18
  7c:	e0000000 	bsr	0x0	// <gpio_set_altnt_func>; regs: r0=<ret gpio_set_altnt_func@0x7c>, r1=<clobbered>
  80:	3101      	movi	r1, 1	// regs: r1=0x1
  82:	07d6      	br	0x2e	// goto loc_2e;
loc_84:
  84:	3a96      	bclri	r2, 22	// regs: r2=(*(0x40026000) & ~(0x1 << 0x16))
  86:	b340      	st.w	r2, (r3, 0x0)	// *(0x40026000) = (*(0x40026000) & ~(0x1 << 0x16))
  88:	3100      	movi	r1, 0	// regs: r1=0x0
  8a:	3016      	movi	r0, 22	// regs: r0=0x16
  8c:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x8c>, r1=<clobbered>
  90:	3100      	movi	r1, 0	// regs: r1=0x0
  92:	3017      	movi	r0, 23	// regs: r0=0x17
  94:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x94>, r1=<clobbered>
  98:	3100      	movi	r1, 0	// regs: r1=0x0
  9a:	3018      	movi	r0, 24	// regs: r0=0x18
  9c:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x9c>, r1=<clobbered>
  a0:	3100      	movi	r1, 0	// regs: r1=0x0
  a2:	3019      	movi	r0, 25	// regs: r0=0x19
  a4:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0xa4>, r1=<clobbered>
  a8:	07c6      	br	0x34	// goto loc_34;
  aa:	0000      	.short	0x0000
  ac:	40026000 	.long	0x40026000

Disassembly of section .text.ah_rfspi_set_clk:

00000000 <ah_rfspi_set_clk>: // arg_bytes: 4
   0:	14d1      	push	r4, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	e0000000 	bsr	0x0	// <sys_get_apbclk>; regs: r0=<ret sys_get_apbclk@0x4>, r1=<clobbered>
   8:	104d      	lrw	r2, 0x4001b000	// regs: r2=0x4001b000
   a:	ea21ff01 	movih	r1, 65281	// regs: r1=(0xff01 << 0x10)
   e:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*(0x4001b000)
  10:	2900      	subi	r1, 1	// regs: r1=((0xff01 << 0x10) - 0x1)
  12:	68c4      	and	r3, r1	// regs: r3=(*(0x4001b000) & ((0xff01 << 0x10) - 0x1))
  14:	b260      	st.w	r3, (r2, 0x0)	// *(0x4001b000) = (*(0x4001b000) & ((0xff01 << 0x10) - 0x1))
  16:	ea0cf424 	movi	r12, 62500	// regs: r12=0xf424
  1a:	c4ac490c 	rotli	r12, r12, 5	// regs: r12=rotl(0xf424, 0x5)
  1e:	e46420ff 	andi	r3, r4, 255	// regs: r3=(<arg0> & 0xff)
  22:	7cf0      	mult	r3, r12	// regs: r3=((<arg0> & 0xff) * rotl(0xf424, 0x5))
  24:	c4608043 	divs	r3, r0, r3	// regs: r3=(<ret sys_get_apbclk@0x4> / ((<arg0> & 0xff) * rotl(0xf424, 0x5)))
  28:	e46320ff 	andi	r3, r3, 255	// regs: r3=((<ret sys_get_apbclk@0x4> / ((<arg0> & 0xff) * rotl(0xf424, 0x5))) & 0xff)
  2c:	2b00      	subi	r3, 1	// regs: r3=(((<ret sys_get_apbclk@0x4> / ((<arg0> & 0xff) * rotl(0xf424, 0x5))) & 0xff) - 0x1)
  2e:	9220      	ld.w	r1, (r2, 0x0)	// regs: r1=*(0x4001b000)
  30:	4370      	lsli	r3, r3, 16	// regs: r3=((((<ret sys_get_apbclk@0x4> / ((<arg0> & 0xff) * rotl(0xf424, 0x5))) & 0xff) - 0x1) << 0x10)
  32:	6cc4      	or	r3, r1	// regs: r3=(((((<ret sys_get_apbclk@0x4> / ((<arg0> & 0xff) * rotl(0xf424, 0x5))) & 0xff) - 0x1) << 0x10) | *(0x4001b000))
  34:	3000      	movi	r0, 0	// regs: r0=0x0
  36:	b260      	st.w	r3, (r2, 0x0)	// *(0x4001b000) = (((((<ret sys_get_apbclk@0x4> / ((<arg0> & 0xff) * rotl(0xf424, 0x5))) & 0xff) - 0x1) << 0x10) | *(0x4001b000))
  38:	1491      	pop	r4, r15
  3a:	0000      	.short	0x0000
  3c:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_set_rx_dly:

00000000 <ah_rfspi_set_rx_dly>: // arg_bytes: 4
   0:	3807      	cmphsi	r0, 8
   2:	080e      	bt	0x1e	// if (r0 >= 0x8) goto loc_1e;
   4:	1068      	lrw	r3, 0x4001b000	// regs: r3=0x4001b000
   6:	31f9      	movi	r1, 249	// regs: r1=0xf9
   8:	4138      	lsli	r1, r1, 24	// regs: r1=0xf9000000
   a:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x4001b000)
   c:	2900      	subi	r1, 1	// regs: r1=0xf8ffffff
   e:	6884      	and	r2, r1	// regs: r2=(*(0x4001b000) & 0xf8ffffff)
  10:	b340      	st.w	r2, (r3, 0x0)	// *(0x4001b000) = (*(0x4001b000) & 0xf8ffffff)
  12:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x4001b000)
  14:	4018      	lsli	r0, r0, 24	// regs: r0=(<arg0> << 0x18)
  16:	6c08      	or	r0, r2	// regs: r0=((<arg0> << 0x18) | *(0x4001b000))
  18:	b300      	st.w	r0, (r3, 0x0)	// *(0x4001b000) = ((<arg0> << 0x18) | *(0x4001b000))
  1a:	3000      	movi	r0, 0	// regs: r0=0x0
loc_1c:
  1c:	783c      	jmp	r15	// return;
loc_1e:
  1e:	3000      	movi	r0, 0	// regs: r0=0x0
  20:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  22:	07fd      	br	0x1c	// goto loc_1c;
  24:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_set_trig_mode:

00000000 <ah_rfspi_set_trig_mode>: // arg_bytes: 4
   0:	1065      	lrw	r3, 0x4001b000	// regs: r3=0x4001b000
   2:	4001      	lsli	r0, r0, 1	// regs: r0=(<arg0> << 0x1)
   4:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x4001b000)
   6:	3a81      	bclri	r2, 1	// regs: r2=(*(0x4001b000) & ~(0x1 << 0x1))
   8:	b340      	st.w	r2, (r3, 0x0)	// *(0x4001b000) = (*(0x4001b000) & ~(0x1 << 0x1))
   a:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x4001b000)
   c:	6c08      	or	r0, r2	// regs: r0=((<arg0> << 0x1) | *(0x4001b000))
   e:	b300      	st.w	r0, (r3, 0x0)	// *(0x4001b000) = ((<arg0> << 0x1) | *(0x4001b000))
  10:	3000      	movi	r0, 0	// regs: r0=0x0
  12:	783c      	jmp	r15	// return;
  14:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_open:

00000000 <ah_rfspi_open>: // arg_bytes: 12
   0:	14d2      	push	r4-r5, r15
   2:	107a      	lrw	r3, 0x40026000	// regs: r3=0x40026000
   4:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   6:	9325      	ld.w	r1, (r3, 0x14)	// regs: r1=*(0x40026014)
   8:	ec218000 	ori	r1, r1, 32768	// regs: r1=(*(0x40026014) | 0x8000)
   c:	b325      	st.w	r1, (r3, 0x14)	// *(0x40026014) = (*(0x40026014) | 0x8000)
   e:	9322      	ld.w	r1, (r3, 0x8)	// regs: r1=*(0x40026008)
  10:	3999      	bclri	r1, 25	// regs: r1=(*(0x40026008) & ~(0x1 << 0x19))
  12:	b322      	st.w	r1, (r3, 0x8)	// *(0x40026008) = (*(0x40026008) & ~(0x1 << 0x19))
  14:	9322      	ld.w	r1, (r3, 0x8)	// regs: r1=*(0x40026008)
  16:	39b9      	bseti	r1, 25	// regs: r1=(*(0x40026008) | (0x1 << 0x19))
  18:	b322      	st.w	r1, (r3, 0x8)	// *(0x40026008) = (*(0x40026008) | (0x1 << 0x19))
  1a:	1075      	lrw	r3, 0x4001b000	// regs: r3=0x4001b000
  1c:	e9200021 	bnez	r0, 0x5e	// if (r0 != 0x0) goto loc_5e;
  20:	1034      	lrw	r1, 0x40f038c	// regs: r1=0x40f038c
loc_22:
  22:	b320      	st.w	r1, (r3, 0x0)	// *(0x4001b000) = r1
  24:	1032      	lrw	r1, 0x4001b000	// regs: r1=0x4001b000
  26:	6c0b      	mov	r0, r2	// regs: r0=<arg2>
  28:	9161      	ld.w	r3, (r1, 0x4)	// regs: r3=*(0x4001b004)
  2a:	ec630004 	ori	r3, r3, 4	// regs: r3=(*(0x4001b004) | 0x4)
  2e:	b161      	st.w	r3, (r1, 0x4)	// *(0x4001b004) = (*(0x4001b004) | 0x4)
  30:	e0000000 	bsr	0x0	// <rfspi_pin_func> // arg_bytes: 4; regs: r0=<ret rfspi_pin_func@0x30>, r1=<clobbered>
  34:	6c13      	mov	r0, r4	// regs: r0=<arg1>
  36:	e0000000 	bsr	0x0	// <ah_rfspi_set_clk> // arg_bytes: 4; regs: r0=<ret ah_rfspi_set_clk@0x36>, r1=<clobbered>
  3a:	6d43      	mov	r5, r0	// regs: r5=<ret ah_rfspi_set_clk@0x36>
  3c:	e0000000 	bsr	0x0	// <sys_get_apbclk>; regs: r0=<ret sys_get_apbclk@0x3c>, r1=<clobbered>
  40:	487f      	lsri	r3, r0, 31	// regs: r3=(<ret sys_get_apbclk@0x3c> >> 0x1f)
  42:	ea01f424 	movi	r1, 62500	// regs: r1=0xf424
  46:	c4814901 	rotli	r1, r1, 4	// regs: r1=rotl(0xf424, 0x4)
  4a:	60c0      	addu	r3, r0	// regs: r3=((<ret sys_get_apbclk@0x3c> >> 0x1f) + <ret sys_get_apbclk@0x3c>)
  4c:	7d04      	mult	r4, r1	// regs: r4=(<arg1> * rotl(0xf424, 0x4))
  4e:	5361      	asri	r3, r3, 1	// regs: r3=(((<ret sys_get_apbclk@0x3c> >> 0x1f) + <ret sys_get_apbclk@0x3c>) >> 0x1)
  50:	64d2      	cmpne	r4, r3
  52:	0808      	bt	0x62	// if (T) goto loc_62;
  54:	3001      	movi	r0, 1	// regs: r0=0x1
loc_56:
  56:	e0000000 	bsr	0x0	// <ah_rfspi_set_rx_dly> // arg_bytes: 4; regs: r0=<ret ah_rfspi_set_rx_dly@0x56>, r1=<clobbered>
  5a:	6c17      	mov	r0, r5	// regs: r0=<ret ah_rfspi_set_clk@0x36>
  5c:	1492      	pop	r4-r5, r15
loc_5e:
  5e:	1026      	lrw	r1, 0x40f03cc	// regs: r1=0x40f03cc
  60:	07e1      	br	0x22	// goto loc_22;
loc_62:
  62:	3000      	movi	r0, 0	// regs: r0=0x0
  64:	07f9      	br	0x56	// goto loc_56;
  66:	0000      	.short	0x0000
  68:	40026000 	.long	0x40026000
  6c:	4001b000 	.long	0x4001b000
  70:	040f038c 	.long	0x040f038c
  74:	040f03cc 	.long	0x040f03cc

Disassembly of section .text.ah_rfspi_close:

00000000 <ah_rfspi_close>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	1069      	lrw	r3, 0x4001b000	// regs: r3=0x4001b000
   4:	3100      	movi	r1, 0	// regs: r1=0x0
   6:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x4001b000)
   8:	3a88      	bclri	r2, 8	// regs: r2=(*(0x4001b000) & ~(0x1 << 0x8))
   a:	3a89      	bclri	r2, 9	// regs: r2=((*(0x4001b000) & ~(0x1 << 0x8)) & ~(0x1 << 0x9))
   c:	b340      	st.w	r2, (r3, 0x0)	// *(0x4001b000) = ((*(0x4001b000) & ~(0x1 << 0x8)) & ~(0x1 << 0x9))
   e:	9341      	ld.w	r2, (r3, 0x4)	// regs: r2=*(0x4001b004)
  10:	2907      	subi	r1, 8	// regs: r1=0xfffffff8
  12:	3400      	movi	r4, 0	// regs: r4=0x0
  14:	6884      	and	r2, r1	// regs: r2=(*(0x4001b004) & 0xfffffff8)
  16:	6c13      	mov	r0, r4	// regs: r0=0x0
  18:	b341      	st.w	r2, (r3, 0x4)	// *(0x4001b004) = (*(0x4001b004) & 0xfffffff8)
  1a:	e0000000 	bsr	0x0	// <rfspi_pin_func> // arg_bytes: 4; regs: r0=<ret rfspi_pin_func@0x1a>, r1=<clobbered>
  1e:	6c13      	mov	r0, r4	// regs: r0=0x0
  20:	1491      	pop	r4, r15
  22:	0000      	.short	0x0000
  24:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_get_pd:

00000000 <ah_rfspi_get_pd>: // arg_bytes: 0
   0:	1063      	lrw	r3, 0x4001b000	// regs: r3=0x4001b000
   2:	9303      	ld.w	r0, (r3, 0xc)	// regs: r0=*(0x4001b00c)
   4:	e4002400 	andi	r0, r0, 1024	// regs: r0=(*(0x4001b00c) & 0x400)
   8:	783c      	jmp	r15	// return;
   a:	0000      	.short	0x0000
   c:	b000      	.short	0xb000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfspi_clear_pd:

00000000 <ah_rfspi_clear_pd>: // arg_bytes: 0
   0:	1044      	lrw	r2, 0x4001b000	// regs: r2=0x4001b000
   2:	3000      	movi	r0, 0	// regs: r0=0x0
   4:	9263      	ld.w	r3, (r2, 0xc)	// regs: r3=*(0x4001b00c)
   6:	ec630400 	ori	r3, r3, 1024	// regs: r3=(*(0x4001b00c) | 0x400)
   a:	b263      	st.w	r3, (r2, 0xc)	// *(0x4001b00c) = (*(0x4001b00c) | 0x400)
   c:	783c      	jmp	r15	// return;
   e:	0000      	.short	0x0000
  10:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_write:

00000000 <ah_rfspi_write>: // arg_bytes: 8
   0:	14d1      	push	r4, r15
   2:	1076      	lrw	r3, 0x4001b000	// regs: r3=0x4001b000
   4:	4010      	lsli	r0, r0, 16	// regs: r0=(<arg0> << 0x10)
   6:	9341      	ld.w	r2, (r3, 0x4)	// regs: r2=*(0x4001b004)
   8:	3a83      	bclri	r2, 3	// regs: r2=(*(0x4001b004) & ~(0x1 << 0x3))
   a:	b341      	st.w	r2, (r3, 0x4)	// *(0x4001b004) = (*(0x4001b004) & ~(0x1 << 0x3))
   c:	9341      	ld.w	r2, (r3, 0x4)	// regs: r2=*(0x4001b004)
   e:	3a80      	bclri	r2, 0	// regs: r2=(*(0x4001b004) & ~(0x1 << 0x0))
  10:	3a81      	bclri	r2, 1	// regs: r2=((*(0x4001b004) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
  12:	b341      	st.w	r2, (r3, 0x4)	// *(0x4001b004) = ((*(0x4001b004) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
  14:	9341      	ld.w	r2, (r3, 0x4)	// regs: r2=*(0x4001b004)
  16:	ec420002 	ori	r2, r2, 2	// regs: r2=(*(0x4001b004) | 0x2)
  1a:	b341      	st.w	r2, (r3, 0x4)	// *(0x4001b004) = (*(0x4001b004) | 0x2)
  1c:	3201      	movi	r2, 1	// regs: r2=0x1
  1e:	b348      	st.w	r2, (r3, 0x20)	// *(0x4001b020) = 0x1
  20:	3200      	movi	r2, 0	// regs: r2=0x0
  22:	b349      	st.w	r2, (r3, 0x24)	// *(0x4001b024) = 0x0
  24:	ea227fff 	movih	r2, 32767	// regs: r2=(0x7fff << 0x10)
  28:	6808      	and	r0, r2	// regs: r0=((<arg0> << 0x10) & (0x7fff << 0x10))
  2a:	39bf      	bseti	r1, 31	// regs: r1=(<arg1> | (0x1 << 0x1f))
  2c:	6c04      	or	r0, r1	// regs: r0=(((<arg0> << 0x10) & (0x7fff << 0x10)) | (<arg1> | (0x1 << 0x1f)))
  2e:	3280      	movi	r2, 128	// regs: r2=0x80
  30:	b304      	st.w	r0, (r3, 0x10)	// *(0x4001b010) = (((<arg0> << 0x10) & (0x7fff << 0x10)) | (<arg1> | (0x1 << 0x1f)))
  32:	4249      	lsli	r2, r2, 9	// regs: r2=0x10000
  34:	6d0f      	mov	r4, r3	// regs: r4=0x4001b000
loc_36:
  36:	9323      	ld.w	r1, (r3, 0xc)	// regs: r1=*(0x4001b00c)
  38:	e4212400 	andi	r1, r1, 1024	// regs: r1=(*(0x4001b00c) & 0x400)
  3c:	e9210005 	bnez	r1, 0x46	// if (r1 != 0x0) goto loc_46;
  40:	2a00      	subi	r2, 1	// regs: r2=(r2 - 0x1)
  42:	e922fffa 	bnez	r2, 0x36	// if (r2 != 0x0) goto loc_36;
loc_46:
  46:	e0000000 	bsr	0x0	// <ah_rfspi_clear_pd> // arg_bytes: 0; regs: r0=<ret ah_rfspi_clear_pd@0x46>, r1=<clobbered>
  4a:	9461      	ld.w	r3, (r4, 0x4)	// regs: r3=*(0x4001b004)
  4c:	ec630008 	ori	r3, r3, 8	// regs: r3=(*(0x4001b004) | 0x8)
  50:	3000      	movi	r0, 0	// regs: r0=0x0
  52:	b461      	st.w	r3, (r4, 0x4)	// *(0x4001b004) = (*(0x4001b004) | 0x8)
  54:	1491      	pop	r4, r15
  56:	0000      	.short	0x0000
  58:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_read:

00000000 <ah_rfspi_read>: // arg_bytes: 4
   0:	14d1      	push	r4, r15
   2:	1071      	lrw	r3, 0x4001b000	// regs: r3=0x4001b000
   4:	4010      	lsli	r0, r0, 16	// regs: r0=(<arg0> << 0x10)
   6:	9341      	ld.w	r2, (r3, 0x4)	// regs: r2=*(0x4001b004)
   8:	3a83      	bclri	r2, 3	// regs: r2=(*(0x4001b004) & ~(0x1 << 0x3))
   a:	b341      	st.w	r2, (r3, 0x4)	// *(0x4001b004) = (*(0x4001b004) & ~(0x1 << 0x3))
   c:	9341      	ld.w	r2, (r3, 0x4)	// regs: r2=*(0x4001b004)
   e:	ec420003 	ori	r2, r2, 3	// regs: r2=(*(0x4001b004) | 0x3)
  12:	b341      	st.w	r2, (r3, 0x4)	// *(0x4001b004) = (*(0x4001b004) | 0x3)
  14:	3201      	movi	r2, 1	// regs: r2=0x1
  16:	b348      	st.w	r2, (r3, 0x20)	// *(0x4001b020) = 0x1
  18:	3200      	movi	r2, 0	// regs: r2=0x0
  1a:	b349      	st.w	r2, (r3, 0x24)	// *(0x4001b024) = 0x0
  1c:	ea227fff 	movih	r2, 32767	// regs: r2=(0x7fff << 0x10)
  20:	6808      	and	r0, r2	// regs: r0=((<arg0> << 0x10) & (0x7fff << 0x10))
  22:	b304      	st.w	r0, (r3, 0x10)	// *(0x4001b010) = ((<arg0> << 0x10) & (0x7fff << 0x10))
  24:	6d0f      	mov	r4, r3	// regs: r4=0x4001b000
loc_26:
  26:	9463      	ld.w	r3, (r4, 0xc)	// regs: r3=*(0x4001b00c)
  28:	e4632400 	andi	r3, r3, 1024	// regs: r3=(*(0x4001b00c) & 0x400)
  2c:	e903fffd 	bez	r3, 0x26	// if (r3 == 0x0) goto loc_26;
  30:	e0000000 	bsr	0x0	// <ah_rfspi_clear_pd> // arg_bytes: 0; regs: r0=<ret ah_rfspi_clear_pd@0x30>, r1=<clobbered>
  34:	9461      	ld.w	r3, (r4, 0x4)	// regs: r3=*(0x4001b004)
  36:	ec630008 	ori	r3, r3, 8	// regs: r3=(*(0x4001b004) | 0x8)
  3a:	b461      	st.w	r3, (r4, 0x4)	// *(0x4001b004) = (*(0x4001b004) | 0x8)
  3c:	9405      	ld.w	r0, (r4, 0x14)	// regs: r0=*(0x4001b014)
  3e:	7401      	zexth	r0, r0	// regs: r0=zext16(*(0x4001b014))
  40:	1491      	pop	r4, r15
  42:	0000      	.short	0x0000
  44:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_write_and_read:

00000000 <ah_rfspi_write_and_read>: // arg_bytes: 8
   0:	14d1      	push	r4, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	e0000000 	bsr	0x0	// <ah_rfspi_write> // arg_bytes: 8; regs: r0=<ret ah_rfspi_write@0x4>, r1=<clobbered>
   8:	6c13      	mov	r0, r4	// regs: r0=<arg0>
   a:	e0000000 	bsr	0x0	// <ah_rfspi_read> // arg_bytes: 4; regs: r0=<ret ah_rfspi_read@0xa>, r1=<clobbered>
   e:	1491      	pop	r4, r15
