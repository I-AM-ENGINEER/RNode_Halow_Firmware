
disasm/liblmac/obj/mars_rfspi.o:     file format elf32-csky-little


Disassembly of section .text.rfspi_pin_func:

00000000 <rfspi_pin_func>:
   0:	14d0      	push      	r15
   2:	3841      	cmpnei      	r0, 1
   4:	116a      	lrw      	r3, 0x40026000	// ac <rfspi_pin_func+0xac>
   6:	9340      	ld.w      	r2, (r3, 0x0)
   8:	0817      	bt      	0x36	// 36 <rfspi_pin_func+0x36>
   a:	3ab5      	bseti      	r2, 21
   c:	b340      	st.w      	r2, (r3, 0x0)
   e:	9340      	ld.w      	r2, (r3, 0x0)
  10:	3a96      	bclri      	r2, 22
  12:	b340      	st.w      	r2, (r3, 0x0)
  14:	3103      	movi      	r1, 3
  16:	3016      	movi      	r0, 22
  18:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  1c:	3103      	movi      	r1, 3
  1e:	3017      	movi      	r0, 23
  20:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  24:	3103      	movi      	r1, 3
  26:	3018      	movi      	r0, 24
  28:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  2c:	3103      	movi      	r1, 3
  2e:	3019      	movi      	r0, 25
  30:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  34:	1490      	pop      	r15
  36:	3a95      	bclri      	r2, 21
  38:	3842      	cmpnei      	r0, 2
  3a:	b340      	st.w      	r2, (r3, 0x0)
  3c:	9340      	ld.w      	r2, (r3, 0x0)
  3e:	0811      	bt      	0x60	// 60 <rfspi_pin_func+0x60>
  40:	3a96      	bclri      	r2, 22
  42:	b340      	st.w      	r2, (r3, 0x0)
  44:	3104      	movi      	r1, 4
  46:	3016      	movi      	r0, 22
  48:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  4c:	3104      	movi      	r1, 4
  4e:	3017      	movi      	r0, 23
  50:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  54:	3104      	movi      	r1, 4
  56:	3018      	movi      	r0, 24
  58:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  5c:	3104      	movi      	r1, 4
  5e:	07e8      	br      	0x2e	// 2e <rfspi_pin_func+0x2e>
  60:	3843      	cmpnei      	r0, 3
  62:	0811      	bt      	0x84	// 84 <rfspi_pin_func+0x84>
  64:	3ab6      	bseti      	r2, 22
  66:	b340      	st.w      	r2, (r3, 0x0)
  68:	3101      	movi      	r1, 1
  6a:	3016      	movi      	r0, 22
  6c:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  70:	3101      	movi      	r1, 1
  72:	3017      	movi      	r0, 23
  74:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  78:	3101      	movi      	r1, 1
  7a:	3018      	movi      	r0, 24
  7c:	e0000000 	bsr      	0x0	// 0 <gpio_set_altnt_func>
  80:	3101      	movi      	r1, 1
  82:	07d6      	br      	0x2e	// 2e <rfspi_pin_func+0x2e>
  84:	3a96      	bclri      	r2, 22
  86:	b340      	st.w      	r2, (r3, 0x0)
  88:	3100      	movi      	r1, 0
  8a:	3016      	movi      	r0, 22
  8c:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  90:	3100      	movi      	r1, 0
  92:	3017      	movi      	r0, 23
  94:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  98:	3100      	movi      	r1, 0
  9a:	3018      	movi      	r0, 24
  9c:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  a0:	3100      	movi      	r1, 0
  a2:	3019      	movi      	r0, 25
  a4:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
  a8:	07c6      	br      	0x34	// 34 <rfspi_pin_func+0x34>
  aa:	0000      	.short	0x0000
  ac:	40026000 	.long	0x40026000

Disassembly of section .text.ah_rfspi_set_clk:

00000000 <ah_rfspi_set_clk>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e0000000 	bsr      	0x0	// 0 <sys_get_apbclk>
   8:	104d      	lrw      	r2, 0x4001b000	// 3c <ah_rfspi_set_clk+0x3c>
   a:	ea21ff01 	movih      	r1, 65281
   e:	9260      	ld.w      	r3, (r2, 0x0)
  10:	2900      	subi      	r1, 1
  12:	68c4      	and      	r3, r1
  14:	b260      	st.w      	r3, (r2, 0x0)
  16:	ea0cf424 	movi      	r12, 62500
  1a:	c4ac490c 	rotli      	r12, r12, 5
  1e:	e46420ff 	andi      	r3, r4, 255
  22:	7cf0      	mult      	r3, r12
  24:	c4608043 	divs      	r3, r0, r3
  28:	e46320ff 	andi      	r3, r3, 255
  2c:	2b00      	subi      	r3, 1
  2e:	9220      	ld.w      	r1, (r2, 0x0)
  30:	4370      	lsli      	r3, r3, 16
  32:	6cc4      	or      	r3, r1
  34:	3000      	movi      	r0, 0
  36:	b260      	st.w      	r3, (r2, 0x0)
  38:	1491      	pop      	r4, r15
  3a:	0000      	.short	0x0000
  3c:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_set_rx_dly:

00000000 <ah_rfspi_set_rx_dly>:
   0:	3807      	cmphsi      	r0, 8
   2:	080e      	bt      	0x1e	// 1e <ah_rfspi_set_rx_dly+0x1e>
   4:	1068      	lrw      	r3, 0x4001b000	// 24 <ah_rfspi_set_rx_dly+0x24>
   6:	31f9      	movi      	r1, 249
   8:	4138      	lsli      	r1, r1, 24
   a:	9340      	ld.w      	r2, (r3, 0x0)
   c:	2900      	subi      	r1, 1
   e:	6884      	and      	r2, r1
  10:	b340      	st.w      	r2, (r3, 0x0)
  12:	9340      	ld.w      	r2, (r3, 0x0)
  14:	4018      	lsli      	r0, r0, 24
  16:	6c08      	or      	r0, r2
  18:	b300      	st.w      	r0, (r3, 0x0)
  1a:	3000      	movi      	r0, 0
  1c:	783c      	jmp      	r15
  1e:	3000      	movi      	r0, 0
  20:	2800      	subi      	r0, 1
  22:	07fd      	br      	0x1c	// 1c <ah_rfspi_set_rx_dly+0x1c>
  24:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_set_trig_mode:

00000000 <ah_rfspi_set_trig_mode>:
   0:	1065      	lrw      	r3, 0x4001b000	// 14 <ah_rfspi_set_trig_mode+0x14>
   2:	4001      	lsli      	r0, r0, 1
   4:	9340      	ld.w      	r2, (r3, 0x0)
   6:	3a81      	bclri      	r2, 1
   8:	b340      	st.w      	r2, (r3, 0x0)
   a:	9340      	ld.w      	r2, (r3, 0x0)
   c:	6c08      	or      	r0, r2
   e:	b300      	st.w      	r0, (r3, 0x0)
  10:	3000      	movi      	r0, 0
  12:	783c      	jmp      	r15
  14:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_open:

00000000 <ah_rfspi_open>:
   0:	14d2      	push      	r4-r5, r15
   2:	107a      	lrw      	r3, 0x40026000	// 68 <ah_rfspi_open+0x68>
   4:	6d07      	mov      	r4, r1
   6:	9325      	ld.w      	r1, (r3, 0x14)
   8:	ec218000 	ori      	r1, r1, 32768
   c:	b325      	st.w      	r1, (r3, 0x14)
   e:	9322      	ld.w      	r1, (r3, 0x8)
  10:	3999      	bclri      	r1, 25
  12:	b322      	st.w      	r1, (r3, 0x8)
  14:	9322      	ld.w      	r1, (r3, 0x8)
  16:	39b9      	bseti      	r1, 25
  18:	b322      	st.w      	r1, (r3, 0x8)
  1a:	1075      	lrw      	r3, 0x4001b000	// 6c <ah_rfspi_open+0x6c>
  1c:	e9200021 	bnez      	r0, 0x5e	// 5e <ah_rfspi_open+0x5e>
  20:	1034      	lrw      	r1, 0x40f038c	// 70 <ah_rfspi_open+0x70>
  22:	b320      	st.w      	r1, (r3, 0x0)
  24:	1032      	lrw      	r1, 0x4001b000	// 6c <ah_rfspi_open+0x6c>
  26:	6c0b      	mov      	r0, r2
  28:	9161      	ld.w      	r3, (r1, 0x4)
  2a:	ec630004 	ori      	r3, r3, 4
  2e:	b161      	st.w      	r3, (r1, 0x4)
  30:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_open>
  34:	6c13      	mov      	r0, r4
  36:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_open>
  3a:	6d43      	mov      	r5, r0
  3c:	e0000000 	bsr      	0x0	// 0 <sys_get_apbclk>
  40:	487f      	lsri      	r3, r0, 31
  42:	ea01f424 	movi      	r1, 62500
  46:	c4814901 	rotli      	r1, r1, 4
  4a:	60c0      	addu      	r3, r0
  4c:	7d04      	mult      	r4, r1
  4e:	5361      	asri      	r3, r3, 1
  50:	64d2      	cmpne      	r4, r3
  52:	0808      	bt      	0x62	// 62 <ah_rfspi_open+0x62>
  54:	3001      	movi      	r0, 1
  56:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_open>
  5a:	6c17      	mov      	r0, r5
  5c:	1492      	pop      	r4-r5, r15
  5e:	1026      	lrw      	r1, 0x40f03cc	// 74 <ah_rfspi_open+0x74>
  60:	07e1      	br      	0x22	// 22 <ah_rfspi_open+0x22>
  62:	3000      	movi      	r0, 0
  64:	07f9      	br      	0x56	// 56 <ah_rfspi_open+0x56>
  66:	0000      	.short	0x0000
  68:	40026000 	.long	0x40026000
  6c:	4001b000 	.long	0x4001b000
  70:	040f038c 	.long	0x040f038c
  74:	040f03cc 	.long	0x040f03cc

Disassembly of section .text.ah_rfspi_close:

00000000 <ah_rfspi_close>:
   0:	14d1      	push      	r4, r15
   2:	1069      	lrw      	r3, 0x4001b000	// 24 <ah_rfspi_close+0x24>
   4:	3100      	movi      	r1, 0
   6:	9340      	ld.w      	r2, (r3, 0x0)
   8:	3a88      	bclri      	r2, 8
   a:	3a89      	bclri      	r2, 9
   c:	b340      	st.w      	r2, (r3, 0x0)
   e:	9341      	ld.w      	r2, (r3, 0x4)
  10:	2907      	subi      	r1, 8
  12:	3400      	movi      	r4, 0
  14:	6884      	and      	r2, r1
  16:	6c13      	mov      	r0, r4
  18:	b341      	st.w      	r2, (r3, 0x4)
  1a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_close>
  1e:	6c13      	mov      	r0, r4
  20:	1491      	pop      	r4, r15
  22:	0000      	.short	0x0000
  24:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_get_pd:

00000000 <ah_rfspi_get_pd>:
   0:	1063      	lrw      	r3, 0x4001b000	// c <ah_rfspi_get_pd+0xc>
   2:	9303      	ld.w      	r0, (r3, 0xc)
   4:	e4002400 	andi      	r0, r0, 1024
   8:	783c      	jmp      	r15
   a:	0000      	.short	0x0000
   c:	b000      	.short	0xb000
   e:	4001      	.short	0x4001

Disassembly of section .text.ah_rfspi_clear_pd:

00000000 <ah_rfspi_clear_pd>:
   0:	1044      	lrw      	r2, 0x4001b000	// 10 <ah_rfspi_clear_pd+0x10>
   2:	3000      	movi      	r0, 0
   4:	9263      	ld.w      	r3, (r2, 0xc)
   6:	ec630400 	ori      	r3, r3, 1024
   a:	b263      	st.w      	r3, (r2, 0xc)
   c:	783c      	jmp      	r15
   e:	0000      	.short	0x0000
  10:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_write:

00000000 <ah_rfspi_write>:
   0:	14d1      	push      	r4, r15
   2:	1076      	lrw      	r3, 0x4001b000	// 58 <ah_rfspi_write+0x58>
   4:	4010      	lsli      	r0, r0, 16
   6:	9341      	ld.w      	r2, (r3, 0x4)
   8:	3a83      	bclri      	r2, 3
   a:	b341      	st.w      	r2, (r3, 0x4)
   c:	9341      	ld.w      	r2, (r3, 0x4)
   e:	3a80      	bclri      	r2, 0
  10:	3a81      	bclri      	r2, 1
  12:	b341      	st.w      	r2, (r3, 0x4)
  14:	9341      	ld.w      	r2, (r3, 0x4)
  16:	ec420002 	ori      	r2, r2, 2
  1a:	b341      	st.w      	r2, (r3, 0x4)
  1c:	3201      	movi      	r2, 1
  1e:	b348      	st.w      	r2, (r3, 0x20)
  20:	3200      	movi      	r2, 0
  22:	b349      	st.w      	r2, (r3, 0x24)
  24:	ea227fff 	movih      	r2, 32767
  28:	6808      	and      	r0, r2
  2a:	39bf      	bseti      	r1, 31
  2c:	6c04      	or      	r0, r1
  2e:	3280      	movi      	r2, 128
  30:	b304      	st.w      	r0, (r3, 0x10)
  32:	4249      	lsli      	r2, r2, 9
  34:	6d0f      	mov      	r4, r3
  36:	9323      	ld.w      	r1, (r3, 0xc)
  38:	e4212400 	andi      	r1, r1, 1024
  3c:	e9210005 	bnez      	r1, 0x46	// 46 <ah_rfspi_write+0x46>
  40:	2a00      	subi      	r2, 1
  42:	e922fffa 	bnez      	r2, 0x36	// 36 <ah_rfspi_write+0x36>
  46:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write>
  4a:	9461      	ld.w      	r3, (r4, 0x4)
  4c:	ec630008 	ori      	r3, r3, 8
  50:	3000      	movi      	r0, 0
  52:	b461      	st.w      	r3, (r4, 0x4)
  54:	1491      	pop      	r4, r15
  56:	0000      	.short	0x0000
  58:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_read:

00000000 <ah_rfspi_read>:
   0:	14d1      	push      	r4, r15
   2:	1071      	lrw      	r3, 0x4001b000	// 44 <ah_rfspi_read+0x44>
   4:	4010      	lsli      	r0, r0, 16
   6:	9341      	ld.w      	r2, (r3, 0x4)
   8:	3a83      	bclri      	r2, 3
   a:	b341      	st.w      	r2, (r3, 0x4)
   c:	9341      	ld.w      	r2, (r3, 0x4)
   e:	ec420003 	ori      	r2, r2, 3
  12:	b341      	st.w      	r2, (r3, 0x4)
  14:	3201      	movi      	r2, 1
  16:	b348      	st.w      	r2, (r3, 0x20)
  18:	3200      	movi      	r2, 0
  1a:	b349      	st.w      	r2, (r3, 0x24)
  1c:	ea227fff 	movih      	r2, 32767
  20:	6808      	and      	r0, r2
  22:	b304      	st.w      	r0, (r3, 0x10)
  24:	6d0f      	mov      	r4, r3
  26:	9463      	ld.w      	r3, (r4, 0xc)
  28:	e4632400 	andi      	r3, r3, 1024
  2c:	e903fffd 	bez      	r3, 0x26	// 26 <ah_rfspi_read+0x26>
  30:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  34:	9461      	ld.w      	r3, (r4, 0x4)
  36:	ec630008 	ori      	r3, r3, 8
  3a:	b461      	st.w      	r3, (r4, 0x4)
  3c:	9405      	ld.w      	r0, (r4, 0x14)
  3e:	7401      	zexth      	r0, r0
  40:	1491      	pop      	r4, r15
  42:	0000      	.short	0x0000
  44:	4001b000 	.long	0x4001b000

Disassembly of section .text.ah_rfspi_write_and_read:

00000000 <ah_rfspi_write_and_read>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write_and_read>
   8:	6c13      	mov      	r0, r4
   a:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_write_and_read>
   e:	1491      	pop      	r4, r15
