
disasm/liblmac/obj/mars_dbgpath.o:     file format elf32-csky-little


Disassembly of section .text.ah_init_dbgpath_device:

00000000 <ah_init_dbgpath_device>:
   0:	1059      	lrw      	r2, 0x0	// 64 <ah_init_dbgpath_device+0x64>
   2:	ea035000 	movi      	r3, 20480
   6:	3bbe      	bseti      	r3, 30
   8:	9220      	ld.w      	r1, (r2, 0x0)
   a:	b320      	st.w      	r1, (r3, 0x0)
   c:	9221      	ld.w      	r1, (r2, 0x4)
   e:	b324      	st.w      	r1, (r3, 0x10)
  10:	9222      	ld.w      	r1, (r2, 0x8)
  12:	b325      	st.w      	r1, (r3, 0x14)
  14:	9223      	ld.w      	r1, (r2, 0xc)
  16:	b326      	st.w      	r1, (r3, 0x18)
  18:	9224      	ld.w      	r1, (r2, 0x10)
  1a:	b327      	st.w      	r1, (r3, 0x1c)
  1c:	9225      	ld.w      	r1, (r2, 0x14)
  1e:	b328      	st.w      	r1, (r3, 0x20)
  20:	9226      	ld.w      	r1, (r2, 0x18)
  22:	b329      	st.w      	r1, (r3, 0x24)
  24:	9227      	ld.w      	r1, (r2, 0x1c)
  26:	b32a      	st.w      	r1, (r3, 0x28)
  28:	9228      	ld.w      	r1, (r2, 0x20)
  2a:	b32b      	st.w      	r1, (r3, 0x2c)
  2c:	9229      	ld.w      	r1, (r2, 0x24)
  2e:	b32c      	st.w      	r1, (r3, 0x30)
  30:	922a      	ld.w      	r1, (r2, 0x28)
  32:	b32d      	st.w      	r1, (r3, 0x34)
  34:	922b      	ld.w      	r1, (r2, 0x2c)
  36:	b32e      	st.w      	r1, (r3, 0x38)
  38:	922c      	ld.w      	r1, (r2, 0x30)
  3a:	b32f      	st.w      	r1, (r3, 0x3c)
  3c:	922d      	ld.w      	r1, (r2, 0x34)
  3e:	b330      	st.w      	r1, (r3, 0x40)
  40:	922e      	ld.w      	r1, (r2, 0x38)
  42:	b331      	st.w      	r1, (r3, 0x44)
  44:	922f      	ld.w      	r1, (r2, 0x3c)
  46:	b332      	st.w      	r1, (r3, 0x48)
  48:	9230      	ld.w      	r1, (r2, 0x40)
  4a:	b333      	st.w      	r1, (r3, 0x4c)
  4c:	9231      	ld.w      	r1, (r2, 0x44)
  4e:	b334      	st.w      	r1, (r3, 0x50)
  50:	9232      	ld.w      	r1, (r2, 0x48)
  52:	b335      	st.w      	r1, (r3, 0x54)
  54:	9233      	ld.w      	r1, (r2, 0x4c)
  56:	b336      	st.w      	r1, (r3, 0x58)
  58:	9234      	ld.w      	r1, (r2, 0x50)
  5a:	9255      	ld.w      	r2, (r2, 0x54)
  5c:	b337      	st.w      	r1, (r3, 0x5c)
  5e:	b35c      	st.w      	r2, (r3, 0x70)
  60:	783c      	jmp      	r15
  62:	0000      	.short	0x0000
  64:	00000000 	.long	0x00000000

Disassembly of section .text.ah_set_dbgpath_device_tx_dly:

00000000 <ah_set_dbgpath_device_tx_dly>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	ea0107c0 	movi      	r1, 1984
   a:	6c46      	nor      	r1, r1
   c:	9340      	ld.w      	r2, (r3, 0x0)
   e:	6884      	and      	r2, r1
  10:	b340      	st.w      	r2, (r3, 0x0)
  12:	4006      	lsli      	r0, r0, 6
  14:	9340      	ld.w      	r2, (r3, 0x0)
  16:	e40027c0 	andi      	r0, r0, 1984
  1a:	6c08      	or      	r0, r2
  1c:	b300      	st.w      	r0, (r3, 0x0)
  1e:	783c      	jmp      	r15

Disassembly of section .text.ah_set_dbgpath_device_rx_dly:

00000000 <ah_set_dbgpath_device_rx_dly>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	ea01f800 	movi      	r1, 63488
   a:	6c46      	nor      	r1, r1
   c:	9340      	ld.w      	r2, (r3, 0x0)
   e:	6884      	and      	r2, r1
  10:	b340      	st.w      	r2, (r3, 0x0)
  12:	400b      	lsli      	r0, r0, 11
  14:	9340      	ld.w      	r2, (r3, 0x0)
  16:	c40055e0 	zext      	r0, r0, 15, 0
  1a:	6c08      	or      	r0, r2
  1c:	b300      	st.w      	r0, (r3, 0x0)
  1e:	783c      	jmp      	r15

Disassembly of section .text.ah_set_dbgpath_device_extspi_tx_pwr:

00000000 <ah_set_dbgpath_device_extspi_tx_pwr>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	c6a0502c 	bmaski      	r12, 22
   a:	c64c490c 	rotli      	r12, r12, 18
   e:	9344      	ld.w      	r2, (r3, 0x10)
  10:	68b0      	and      	r2, r12
  12:	b344      	st.w      	r2, (r3, 0x10)
  14:	9344      	ld.w      	r2, (r3, 0x10)
  16:	4008      	lsli      	r0, r0, 8
  18:	6c08      	or      	r0, r2
  1a:	b304      	st.w      	r0, (r3, 0x10)
  1c:	3000      	movi      	r0, 0
  1e:	9344      	ld.w      	r2, (r3, 0x10)
  20:	28ff      	subi      	r0, 256
  22:	6880      	and      	r2, r0
  24:	b344      	st.w      	r2, (r3, 0x10)
  26:	9344      	ld.w      	r2, (r3, 0x10)
  28:	6c48      	or      	r1, r2
  2a:	b324      	st.w      	r1, (r3, 0x10)
  2c:	9344      	ld.w      	r2, (r3, 0x10)
  2e:	3ab7      	bseti      	r2, 23
  30:	b344      	st.w      	r2, (r3, 0x10)
  32:	783c      	jmp      	r15

Disassembly of section .text.ah_set_dbgpath_device_extspi_rx_gain:

00000000 <ah_set_dbgpath_device_extspi_rx_gain>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	c6a0502c 	bmaski      	r12, 22
   a:	c64c490c 	rotli      	r12, r12, 18
   e:	9345      	ld.w      	r2, (r3, 0x14)
  10:	68b0      	and      	r2, r12
  12:	b345      	st.w      	r2, (r3, 0x14)
  14:	9345      	ld.w      	r2, (r3, 0x14)
  16:	4008      	lsli      	r0, r0, 8
  18:	6c08      	or      	r0, r2
  1a:	b305      	st.w      	r0, (r3, 0x14)
  1c:	3000      	movi      	r0, 0
  1e:	9345      	ld.w      	r2, (r3, 0x14)
  20:	28ff      	subi      	r0, 256
  22:	6880      	and      	r2, r0
  24:	b345      	st.w      	r2, (r3, 0x14)
  26:	9345      	ld.w      	r2, (r3, 0x14)
  28:	6c48      	or      	r1, r2
  2a:	b325      	st.w      	r1, (r3, 0x14)
  2c:	9345      	ld.w      	r2, (r3, 0x14)
  2e:	3ab7      	bseti      	r2, 23
  30:	b345      	st.w      	r2, (r3, 0x14)
  32:	783c      	jmp      	r15

Disassembly of section .text.ah_set_dbgpath_device_extspi_dpd_gain:

00000000 <ah_set_dbgpath_device_extspi_dpd_gain>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	c6a0502c 	bmaski      	r12, 22
   a:	c64c490c 	rotli      	r12, r12, 18
   e:	9346      	ld.w      	r2, (r3, 0x18)
  10:	68b0      	and      	r2, r12
  12:	b346      	st.w      	r2, (r3, 0x18)
  14:	9346      	ld.w      	r2, (r3, 0x18)
  16:	4008      	lsli      	r0, r0, 8
  18:	6c08      	or      	r0, r2
  1a:	b306      	st.w      	r0, (r3, 0x18)
  1c:	3000      	movi      	r0, 0
  1e:	9346      	ld.w      	r2, (r3, 0x18)
  20:	28ff      	subi      	r0, 256
  22:	6880      	and      	r2, r0
  24:	b346      	st.w      	r2, (r3, 0x18)
  26:	9346      	ld.w      	r2, (r3, 0x18)
  28:	6c48      	or      	r1, r2
  2a:	b326      	st.w      	r1, (r3, 0x18)
  2c:	9346      	ld.w      	r2, (r3, 0x18)
  2e:	3ab7      	bseti      	r2, 23
  30:	b346      	st.w      	r2, (r3, 0x18)
  32:	783c      	jmp      	r15

Disassembly of section .text.ah_enable_dbgpath_device_ext_dpd_gain:

00000000 <ah_enable_dbgpath_device_ext_dpd_gain>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	9340      	ld.w      	r2, (r3, 0x0)
   8:	3a95      	bclri      	r2, 21
   a:	b340      	st.w      	r2, (r3, 0x0)
   c:	9340      	ld.w      	r2, (r3, 0x0)
   e:	3ab5      	bseti      	r2, 21
  10:	b340      	st.w      	r2, (r3, 0x0)
  12:	783c      	jmp      	r15

Disassembly of section .text.ah_disable_dbgpath_device_ext_dpd_gain:

00000000 <ah_disable_dbgpath_device_ext_dpd_gain>:
   0:	ea025000 	movi      	r2, 20480
   4:	3abe      	bseti      	r2, 30
   6:	9260      	ld.w      	r3, (r2, 0x0)
   8:	3b95      	bclri      	r3, 21
   a:	b260      	st.w      	r3, (r2, 0x0)
   c:	783c      	jmp      	r15

Disassembly of section .text.ah_get_dbgpath_device_stop_pos:

00000000 <ah_get_dbgpath_device_stop_pos>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	9343      	ld.w      	r2, (r3, 0xc)
   8:	c4028023 	divu      	r3, r2, r0
   c:	7c0c      	mult      	r0, r3
   e:	5a01      	subu      	r0, r2, r0
  10:	783c      	jmp      	r15

Disassembly of section .text.ah_set_dbgpath_device_path_mode:

00000000 <ah_set_dbgpath_device_path_mode>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	3100      	movi      	r1, 0
   8:	9340      	ld.w      	r2, (r3, 0x0)
   a:	2907      	subi      	r1, 8
   c:	6884      	and      	r2, r1
   e:	b340      	st.w      	r2, (r3, 0x0)
  10:	9340      	ld.w      	r2, (r3, 0x0)
  12:	e4002007 	andi      	r0, r0, 7
  16:	6c08      	or      	r0, r2
  18:	b300      	st.w      	r0, (r3, 0x0)
  1a:	783c      	jmp      	r15

Disassembly of section .text.ah_set_dbgpath_device_tdma2_en_bit:

00000000 <ah_set_dbgpath_device_tdma2_en_bit>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	401f      	lsli      	r0, r0, 31
   8:	9349      	ld.w      	r2, (r3, 0x24)
   a:	c40257c2 	zext      	r2, r2, 30, 0
   e:	b349      	st.w      	r2, (r3, 0x24)
  10:	9349      	ld.w      	r2, (r3, 0x24)
  12:	6c08      	or      	r0, r2
  14:	b309      	st.w      	r0, (r3, 0x24)
  16:	783c      	jmp      	r15

Disassembly of section .text.ah_trig_dbgpath_device_dma:

00000000 <ah_trig_dbgpath_device_dma>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	9340      	ld.w      	r2, (r3, 0x0)
   8:	3a84      	bclri      	r2, 4
   a:	b340      	st.w      	r2, (r3, 0x0)
   c:	9340      	ld.w      	r2, (r3, 0x0)
   e:	ec420010 	ori      	r2, r2, 16
  12:	b340      	st.w      	r2, (r3, 0x0)
  14:	9340      	ld.w      	r2, (r3, 0x0)
  16:	e4422010 	andi      	r2, r2, 16
  1a:	e902fffd 	bez      	r2, 0x14	// 14 <ah_trig_dbgpath_device_dma+0x14>
  1e:	783c      	jmp      	r15

Disassembly of section .text.ah_trig_dbgpath_device_dma2:

00000000 <ah_trig_dbgpath_device_dma2>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	3180      	movi      	r1, 128
   8:	9340      	ld.w      	r2, (r3, 0x0)
   a:	3a96      	bclri      	r2, 22
   c:	b340      	st.w      	r2, (r3, 0x0)
   e:	9340      	ld.w      	r2, (r3, 0x0)
  10:	3ab6      	bseti      	r2, 22
  12:	b340      	st.w      	r2, (r3, 0x0)
  14:	9340      	ld.w      	r2, (r3, 0x0)
  16:	412f      	lsli      	r1, r1, 15
  18:	6884      	and      	r2, r1
  1a:	e9020003 	bez      	r2, 0x20	// 20 <ah_trig_dbgpath_device_dma2+0x20>
  1e:	783c      	jmp      	r15
  20:	9340      	ld.w      	r2, (r3, 0x0)
  22:	07fb      	br      	0x18	// 18 <ah_trig_dbgpath_device_dma2+0x18>

Disassembly of section .text.ah_abort_dbgpath_device_dma:

00000000 <ah_abort_dbgpath_device_dma>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	9340      	ld.w      	r2, (r3, 0x0)
   8:	3a85      	bclri      	r2, 5
   a:	b340      	st.w      	r2, (r3, 0x0)
   c:	9340      	ld.w      	r2, (r3, 0x0)
   e:	ec420020 	ori      	r2, r2, 32
  12:	b340      	st.w      	r2, (r3, 0x0)
  14:	9340      	ld.w      	r2, (r3, 0x0)
  16:	e4422020 	andi      	r2, r2, 32
  1a:	e902fffd 	bez      	r2, 0x14	// 14 <ah_abort_dbgpath_device_dma+0x14>
  1e:	783c      	jmp      	r15

Disassembly of section .text.ah_abort_dbgpath_device_dma2:

00000000 <ah_abort_dbgpath_device_dma2>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	3180      	movi      	r1, 128
   8:	9340      	ld.w      	r2, (r3, 0x0)
   a:	3a97      	bclri      	r2, 23
   c:	b340      	st.w      	r2, (r3, 0x0)
   e:	9340      	ld.w      	r2, (r3, 0x0)
  10:	3ab7      	bseti      	r2, 23
  12:	b340      	st.w      	r2, (r3, 0x0)
  14:	9340      	ld.w      	r2, (r3, 0x0)
  16:	4130      	lsli      	r1, r1, 16
  18:	6884      	and      	r2, r1
  1a:	e9020003 	bez      	r2, 0x20	// 20 <ah_abort_dbgpath_device_dma2+0x20>
  1e:	783c      	jmp      	r15
  20:	9340      	ld.w      	r2, (r3, 0x0)
  22:	07fb      	br      	0x18	// 18 <ah_abort_dbgpath_device_dma2+0x18>

Disassembly of section .text.ah_config_dbgpath_device_dmaend_cond:

00000000 <ah_config_dbgpath_device_dmaend_cond>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	31c0      	movi      	r1, 192
   8:	9340      	ld.w      	r2, (r3, 0x0)
   a:	3a92      	bclri      	r2, 18
   c:	3a93      	bclri      	r2, 19
   e:	b340      	st.w      	r2, (r3, 0x0)
  10:	412c      	lsli      	r1, r1, 12
  12:	4012      	lsli      	r0, r0, 18
  14:	9340      	ld.w      	r2, (r3, 0x0)
  16:	6804      	and      	r0, r1
  18:	6c08      	or      	r0, r2
  1a:	b300      	st.w      	r0, (r3, 0x0)
  1c:	783c      	jmp      	r15

Disassembly of section .text.ah_config_dbgpath_device_ext_path:

00000000 <ah_config_dbgpath_device_ext_path>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	9340      	ld.w      	r2, (r3, 0x0)
   8:	e9200006 	bnez      	r0, 0x14	// 14 <ah_config_dbgpath_device_ext_path+0x14>
   c:	3a94      	bclri      	r2, 20
   e:	3a95      	bclri      	r2, 21
  10:	b340      	st.w      	r2, (r3, 0x0)
  12:	783c      	jmp      	r15
  14:	3ab4      	bseti      	r2, 20
  16:	3ab5      	bseti      	r2, 21
  18:	07fc      	br      	0x10	// 10 <ah_config_dbgpath_device_ext_path+0x10>

Disassembly of section .text.ah_config_dbgpath_device_dbg_out:

00000000 <ah_config_dbgpath_device_dbg_out>:
   0:	3806      	cmphsi      	r0, 7
   2:	ea035000 	movi      	r3, 20480
   6:	3bbe      	bseti      	r3, 30
   8:	0845      	bt      	0x92	// 92 <ah_config_dbgpath_device_dbg_out+0x92>
   a:	1043      	lrw      	r2, 0x0	// 14 <ah_config_dbgpath_device_dbg_out+0x14>
   c:	d0020882 	ldr.w      	r2, (r2, r0 << 2)
  10:	7808      	jmp      	r2
  12:	0000      	.short	0x0000
  14:	00000000 	.long	0x00000000
  18:	3000      	movi      	r0, 0
  1a:	934a      	ld.w      	r2, (r3, 0x28)
  1c:	28ff      	subi      	r0, 256
  1e:	6880      	and      	r2, r0
  20:	b34a      	st.w      	r2, (r3, 0x28)
  22:	934a      	ld.w      	r2, (r3, 0x28)
  24:	6c48      	or      	r1, r2
  26:	b32a      	st.w      	r1, (r3, 0x28)
  28:	783c      	jmp      	r15
  2a:	934a      	ld.w      	r2, (r3, 0x28)
  2c:	ea00ff00 	movi      	r0, 65280
  30:	6c02      	nor      	r0, r0
  32:	6880      	and      	r2, r0
  34:	b34a      	st.w      	r2, (r3, 0x28)
  36:	934a      	ld.w      	r2, (r3, 0x28)
  38:	4128      	lsli      	r1, r1, 8
  3a:	07f5      	br      	0x24	// 24 <ah_config_dbgpath_device_dbg_out+0x24>
  3c:	ea20ff01 	movih      	r0, 65281
  40:	934a      	ld.w      	r2, (r3, 0x28)
  42:	2800      	subi      	r0, 1
  44:	6880      	and      	r2, r0
  46:	b34a      	st.w      	r2, (r3, 0x28)
  48:	934a      	ld.w      	r2, (r3, 0x28)
  4a:	4130      	lsli      	r1, r1, 16
  4c:	07ec      	br      	0x24	// 24 <ah_config_dbgpath_device_dbg_out+0x24>
  4e:	934a      	ld.w      	r2, (r3, 0x28)
  50:	c40256e2 	zext      	r2, r2, 23, 0
  54:	b34a      	st.w      	r2, (r3, 0x28)
  56:	934a      	ld.w      	r2, (r3, 0x28)
  58:	4138      	lsli      	r1, r1, 24
  5a:	07e5      	br      	0x24	// 24 <ah_config_dbgpath_device_dbg_out+0x24>
  5c:	3000      	movi      	r0, 0
  5e:	934b      	ld.w      	r2, (r3, 0x2c)
  60:	28ff      	subi      	r0, 256
  62:	6880      	and      	r2, r0
  64:	b34b      	st.w      	r2, (r3, 0x2c)
  66:	934b      	ld.w      	r2, (r3, 0x2c)
  68:	6c48      	or      	r1, r2
  6a:	b32b      	st.w      	r1, (r3, 0x2c)
  6c:	07de      	br      	0x28	// 28 <ah_config_dbgpath_device_dbg_out+0x28>
  6e:	934b      	ld.w      	r2, (r3, 0x2c)
  70:	ea00ff00 	movi      	r0, 65280
  74:	6c02      	nor      	r0, r0
  76:	6880      	and      	r2, r0
  78:	b34b      	st.w      	r2, (r3, 0x2c)
  7a:	934b      	ld.w      	r2, (r3, 0x2c)
  7c:	4128      	lsli      	r1, r1, 8
  7e:	07f5      	br      	0x68	// 68 <ah_config_dbgpath_device_dbg_out+0x68>
  80:	ea20ff01 	movih      	r0, 65281
  84:	934b      	ld.w      	r2, (r3, 0x2c)
  86:	2800      	subi      	r0, 1
  88:	6880      	and      	r2, r0
  8a:	b34b      	st.w      	r2, (r3, 0x2c)
  8c:	934b      	ld.w      	r2, (r3, 0x2c)
  8e:	4130      	lsli      	r1, r1, 16
  90:	07ec      	br      	0x68	// 68 <ah_config_dbgpath_device_dbg_out+0x68>
  92:	934b      	ld.w      	r2, (r3, 0x2c)
  94:	c40256e2 	zext      	r2, r2, 23, 0
  98:	b34b      	st.w      	r2, (r3, 0x2c)
  9a:	934b      	ld.w      	r2, (r3, 0x2c)
  9c:	4138      	lsli      	r1, r1, 24
  9e:	07e5      	br      	0x68	// 68 <ah_config_dbgpath_device_dbg_out+0x68>

Disassembly of section .text.ah_config_dbgpath_device_enable_bits:

00000000 <ah_config_dbgpath_device_enable_bits>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	31ff      	movi      	r1, 255
   8:	9347      	ld.w      	r2, (r3, 0x1c)
   a:	4128      	lsli      	r1, r1, 8
   c:	6884      	and      	r2, r1
   e:	7441      	zexth      	r1, r0
  10:	6c84      	or      	r2, r1
  12:	b347      	st.w      	r2, (r3, 0x1c)
  14:	c6005602 	zext      	r2, r0, 16, 16
  18:	4243      	lsli      	r2, r2, 3
  1a:	b34a      	st.w      	r2, (r3, 0x28)
  1c:	934c      	ld.w      	r2, (r3, 0x30)
  1e:	3a9d      	bclri      	r2, 29
  20:	3180      	movi      	r1, 128
  22:	b34c      	st.w      	r2, (r3, 0x30)
  24:	4136      	lsli      	r1, r1, 22
  26:	404c      	lsli      	r2, r0, 12
  28:	d983200c 	ld.w      	r12, (r3, 0x30)
  2c:	6884      	and      	r2, r1
  2e:	6cb0      	or      	r2, r12
  30:	b34c      	st.w      	r2, (r3, 0x30)
  32:	934e      	ld.w      	r2, (r3, 0x38)
  34:	3a9d      	bclri      	r2, 29
  36:	b34e      	st.w      	r2, (r3, 0x38)
  38:	c6405642 	zext      	r2, r0, 18, 18
  3c:	932e      	ld.w      	r1, (r3, 0x38)
  3e:	425d      	lsli      	r2, r2, 29
  40:	6c84      	or      	r2, r1
  42:	b34e      	st.w      	r2, (r3, 0x38)
  44:	9350      	ld.w      	r2, (r3, 0x40)
  46:	3a9d      	bclri      	r2, 29
  48:	b350      	st.w      	r2, (r3, 0x40)
  4a:	c6605662 	zext      	r2, r0, 19, 19
  4e:	9330      	ld.w      	r1, (r3, 0x40)
  50:	425d      	lsli      	r2, r2, 29
  52:	6c84      	or      	r2, r1
  54:	b350      	st.w      	r2, (r3, 0x40)
  56:	9352      	ld.w      	r2, (r3, 0x48)
  58:	3a9d      	bclri      	r2, 29
  5a:	b352      	st.w      	r2, (r3, 0x48)
  5c:	c6805682 	zext      	r2, r0, 20, 20
  60:	9332      	ld.w      	r1, (r3, 0x48)
  62:	425d      	lsli      	r2, r2, 29
  64:	6c84      	or      	r2, r1
  66:	b352      	st.w      	r2, (r3, 0x48)
  68:	9354      	ld.w      	r2, (r3, 0x50)
  6a:	3a9d      	bclri      	r2, 29
  6c:	b354      	st.w      	r2, (r3, 0x50)
  6e:	c6a056a2 	zext      	r2, r0, 21, 21
  72:	9334      	ld.w      	r1, (r3, 0x50)
  74:	425d      	lsli      	r2, r2, 29
  76:	6c84      	or      	r2, r1
  78:	b354      	st.w      	r2, (r3, 0x50)
  7a:	9356      	ld.w      	r2, (r3, 0x58)
  7c:	3a9d      	bclri      	r2, 29
  7e:	b356      	st.w      	r2, (r3, 0x58)
  80:	c6c056c0 	zext      	r0, r0, 22, 22
  84:	9356      	ld.w      	r2, (r3, 0x58)
  86:	401d      	lsli      	r0, r0, 29
  88:	6c08      	or      	r0, r2
  8a:	b316      	st.w      	r0, (r3, 0x58)
  8c:	783c      	jmp      	r15

Disassembly of section .text.ah_get_dbgpath_device_rfmipi_err_info:

00000000 <ah_get_dbgpath_device_rfmipi_err_info>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	9307      	ld.w      	r0, (r3, 0x1c)
   8:	c5805580 	zext      	r0, r0, 12, 12
   c:	783c      	jmp      	r15

Disassembly of section .text.ah_clear_dbgpath_device_rfmipi_err_info:

00000000 <ah_clear_dbgpath_device_rfmipi_err_info>:
   0:	ea035000 	movi      	r3, 20480
   4:	3bbe      	bseti      	r3, 30
   6:	9347      	ld.w      	r2, (r3, 0x1c)
   8:	3a8a      	bclri      	r2, 10
   a:	b347      	st.w      	r2, (r3, 0x1c)
   c:	9347      	ld.w      	r2, (r3, 0x1c)
   e:	ec420400 	ori      	r2, r2, 1024
  12:	b347      	st.w      	r2, (r3, 0x1c)
  14:	783c      	jmp      	r15
