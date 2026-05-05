
libs\obj\liblmac\mars_dbgpath.o:     file format elf32-csky-little


Disassembly of section .text.ah_init_dbgpath_device:

00000000 <ah_init_dbgpath_device>: // arg_bytes: 0
   0:	1059      	lrw	r2, 0x0	// regs: r2=0x0
   2:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   6:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   8:	9220      	ld.w	r1, (r2, 0x0)	// regs: r1=*(0x0)
   a:	b320      	st.w	r1, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = *(0x0)
   c:	9221      	ld.w	r1, (r2, 0x4)	// regs: r1=*(0x4)
   e:	b324      	st.w	r1, (r3, 0x10)	// *(((0x5000 | (0x1 << 0x1e)) + 0x10)) = *(0x4)
  10:	9222      	ld.w	r1, (r2, 0x8)	// regs: r1=*(0x8)
  12:	b325      	st.w	r1, (r3, 0x14)	// *(((0x5000 | (0x1 << 0x1e)) + 0x14)) = *(0x8)
  14:	9223      	ld.w	r1, (r2, 0xc)	// regs: r1=*(0xc)
  16:	b326      	st.w	r1, (r3, 0x18)	// *(((0x5000 | (0x1 << 0x1e)) + 0x18)) = *(0xc)
  18:	9224      	ld.w	r1, (r2, 0x10)	// regs: r1=*(0x10)
  1a:	b327      	st.w	r1, (r3, 0x1c)	// *(((0x5000 | (0x1 << 0x1e)) + 0x1c)) = *(0x10)
  1c:	9225      	ld.w	r1, (r2, 0x14)	// regs: r1=*(0x14)
  1e:	b328      	st.w	r1, (r3, 0x20)	// *(((0x5000 | (0x1 << 0x1e)) + 0x20)) = *(0x14)
  20:	9226      	ld.w	r1, (r2, 0x18)	// regs: r1=*(0x18)
  22:	b329      	st.w	r1, (r3, 0x24)	// *(((0x5000 | (0x1 << 0x1e)) + 0x24)) = *(0x18)
  24:	9227      	ld.w	r1, (r2, 0x1c)	// regs: r1=*(0x1c)
  26:	b32a      	st.w	r1, (r3, 0x28)	// *(((0x5000 | (0x1 << 0x1e)) + 0x28)) = *(0x1c)
  28:	9228      	ld.w	r1, (r2, 0x20)	// regs: r1=*(0x20)
  2a:	b32b      	st.w	r1, (r3, 0x2c)	// *(((0x5000 | (0x1 << 0x1e)) + 0x2c)) = *(0x20)
  2c:	9229      	ld.w	r1, (r2, 0x24)	// regs: r1=*(0x24)
  2e:	b32c      	st.w	r1, (r3, 0x30)	// *(((0x5000 | (0x1 << 0x1e)) + 0x30)) = *(0x24)
  30:	922a      	ld.w	r1, (r2, 0x28)	// regs: r1=*(0x28)
  32:	b32d      	st.w	r1, (r3, 0x34)	// *(((0x5000 | (0x1 << 0x1e)) + 0x34)) = *(0x28)
  34:	922b      	ld.w	r1, (r2, 0x2c)	// regs: r1=*(0x2c)
  36:	b32e      	st.w	r1, (r3, 0x38)	// *(((0x5000 | (0x1 << 0x1e)) + 0x38)) = *(0x2c)
  38:	922c      	ld.w	r1, (r2, 0x30)	// regs: r1=*(0x30)
  3a:	b32f      	st.w	r1, (r3, 0x3c)	// *(((0x5000 | (0x1 << 0x1e)) + 0x3c)) = *(0x30)
  3c:	922d      	ld.w	r1, (r2, 0x34)	// regs: r1=*(0x34)
  3e:	b330      	st.w	r1, (r3, 0x40)	// *(((0x5000 | (0x1 << 0x1e)) + 0x40)) = *(0x34)
  40:	922e      	ld.w	r1, (r2, 0x38)	// regs: r1=*(0x38)
  42:	b331      	st.w	r1, (r3, 0x44)	// *(((0x5000 | (0x1 << 0x1e)) + 0x44)) = *(0x38)
  44:	922f      	ld.w	r1, (r2, 0x3c)	// regs: r1=*(0x3c)
  46:	b332      	st.w	r1, (r3, 0x48)	// *(((0x5000 | (0x1 << 0x1e)) + 0x48)) = *(0x3c)
  48:	9230      	ld.w	r1, (r2, 0x40)	// regs: r1=*(0x40)
  4a:	b333      	st.w	r1, (r3, 0x4c)	// *(((0x5000 | (0x1 << 0x1e)) + 0x4c)) = *(0x40)
  4c:	9231      	ld.w	r1, (r2, 0x44)	// regs: r1=*(0x44)
  4e:	b334      	st.w	r1, (r3, 0x50)	// *(((0x5000 | (0x1 << 0x1e)) + 0x50)) = *(0x44)
  50:	9232      	ld.w	r1, (r2, 0x48)	// regs: r1=*(0x48)
  52:	b335      	st.w	r1, (r3, 0x54)	// *(((0x5000 | (0x1 << 0x1e)) + 0x54)) = *(0x48)
  54:	9233      	ld.w	r1, (r2, 0x4c)	// regs: r1=*(0x4c)
  56:	b336      	st.w	r1, (r3, 0x58)	// *(((0x5000 | (0x1 << 0x1e)) + 0x58)) = *(0x4c)
  58:	9234      	ld.w	r1, (r2, 0x50)	// regs: r1=*(0x50)
  5a:	9255      	ld.w	r2, (r2, 0x54)	// regs: r2=*(0x54)
  5c:	b337      	st.w	r1, (r3, 0x5c)	// *(((0x5000 | (0x1 << 0x1e)) + 0x5c)) = *(0x50)
  5e:	b35c      	st.w	r2, (r3, 0x70)	// *(((0x5000 | (0x1 << 0x1e)) + 0x70)) = *(0x54)
  60:	783c      	jmp	r15	// return;
  62:	0000      	.short	0x0000
  64:	00000000 	.long	0x00000000	// <ndbgpathcfg>

Disassembly of section .text.ah_set_dbgpath_device_tx_dly:

00000000 <ah_set_dbgpath_device_tx_dly>: // arg_bytes: 4
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	ea0107c0 	movi	r1, 1984	// regs: r1=0x7c0
   a:	6c46      	nor	r1, r1	// regs: r1=(~0x7c0)
   c:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   e:	6884      	and	r2, r1	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & (~0x7c0))
  10:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) & (~0x7c0))
  12:	4006      	lsli	r0, r0, 6	// regs: r0=(<arg0> << 0x6)
  14:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
  16:	e40027c0 	andi	r0, r0, 1984	// regs: r0=((<arg0> << 0x6) & 0x7c0)
  1a:	6c08      	or	r0, r2	// regs: r0=(((<arg0> << 0x6) & 0x7c0) | *((0x5000 | (0x1 << 0x1e))))
  1c:	b300      	st.w	r0, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (((<arg0> << 0x6) & 0x7c0) | *((0x5000 | (0x1 << 0x1e))))
  1e:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_set_dbgpath_device_rx_dly:

00000000 <ah_set_dbgpath_device_rx_dly>: // arg_bytes: 4
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	ea01f800 	movi	r1, 63488	// regs: r1=0xf800
   a:	6c46      	nor	r1, r1	// regs: r1=(~0xf800)
   c:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   e:	6884      	and	r2, r1	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & (~0xf800))
  10:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) & (~0xf800))
  12:	400b      	lsli	r0, r0, 11	// regs: r0=(<arg0> << 0xb)
  14:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
  16:	c40055e0 	zext	r0, r0, 15, 0	// regs: r0=zext((<arg0> << 0xb))
  1a:	6c08      	or	r0, r2	// regs: r0=(zext((<arg0> << 0xb)) | *((0x5000 | (0x1 << 0x1e))))
  1c:	b300      	st.w	r0, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (zext((<arg0> << 0xb)) | *((0x5000 | (0x1 << 0x1e))))
  1e:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_set_dbgpath_device_extspi_tx_pwr:

00000000 <ah_set_dbgpath_device_extspi_tx_pwr>: // arg_bytes: 8
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	c6a0502c 	bmaski	r12, 22
   a:	c64c490c 	rotli	r12, r12, 18	// regs: r12=rotl(r12, 0x12)
   e:	9344      	ld.w	r2, (r3, 0x10)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x10))
  10:	68b0      	and	r2, r12	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x10)) & rotl(r12, 0x12))
  12:	b344      	st.w	r2, (r3, 0x10)	// *(((0x5000 | (0x1 << 0x1e)) + 0x10)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x10)) & rotl(r12, 0x12))
  14:	9344      	ld.w	r2, (r3, 0x10)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x10))
  16:	4008      	lsli	r0, r0, 8	// regs: r0=(<arg0> << 0x8)
  18:	6c08      	or	r0, r2	// regs: r0=((<arg0> << 0x8) | *(((0x5000 | (0x1 << 0x1e)) + 0x10)))
  1a:	b304      	st.w	r0, (r3, 0x10)	// *(((0x5000 | (0x1 << 0x1e)) + 0x10)) = ((<arg0> << 0x8) | *(((0x5000 | (0x1 << 0x1e)) + 0x10)))
  1c:	3000      	movi	r0, 0	// regs: r0=0x0
  1e:	9344      	ld.w	r2, (r3, 0x10)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x10))
  20:	28ff      	subi	r0, 256	// regs: r0=0xffffff00
  22:	6880      	and	r2, r0	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x10)) & 0xffffff00)
  24:	b344      	st.w	r2, (r3, 0x10)	// *(((0x5000 | (0x1 << 0x1e)) + 0x10)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x10)) & 0xffffff00)
  26:	9344      	ld.w	r2, (r3, 0x10)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x10))
  28:	6c48      	or	r1, r2	// regs: r1=(<arg1> | *(((0x5000 | (0x1 << 0x1e)) + 0x10)))
  2a:	b324      	st.w	r1, (r3, 0x10)	// *(((0x5000 | (0x1 << 0x1e)) + 0x10)) = (<arg1> | *(((0x5000 | (0x1 << 0x1e)) + 0x10)))
  2c:	9344      	ld.w	r2, (r3, 0x10)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x10))
  2e:	3ab7      	bseti	r2, 23	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x10)) | (0x1 << 0x17))
  30:	b344      	st.w	r2, (r3, 0x10)	// *(((0x5000 | (0x1 << 0x1e)) + 0x10)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x10)) | (0x1 << 0x17))
  32:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_set_dbgpath_device_extspi_rx_gain:

00000000 <ah_set_dbgpath_device_extspi_rx_gain>: // arg_bytes: 8
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	c6a0502c 	bmaski	r12, 22
   a:	c64c490c 	rotli	r12, r12, 18	// regs: r12=rotl(r12, 0x12)
   e:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x14))
  10:	68b0      	and	r2, r12	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x14)) & rotl(r12, 0x12))
  12:	b345      	st.w	r2, (r3, 0x14)	// *(((0x5000 | (0x1 << 0x1e)) + 0x14)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x14)) & rotl(r12, 0x12))
  14:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x14))
  16:	4008      	lsli	r0, r0, 8	// regs: r0=(<arg0> << 0x8)
  18:	6c08      	or	r0, r2	// regs: r0=((<arg0> << 0x8) | *(((0x5000 | (0x1 << 0x1e)) + 0x14)))
  1a:	b305      	st.w	r0, (r3, 0x14)	// *(((0x5000 | (0x1 << 0x1e)) + 0x14)) = ((<arg0> << 0x8) | *(((0x5000 | (0x1 << 0x1e)) + 0x14)))
  1c:	3000      	movi	r0, 0	// regs: r0=0x0
  1e:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x14))
  20:	28ff      	subi	r0, 256	// regs: r0=0xffffff00
  22:	6880      	and	r2, r0	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x14)) & 0xffffff00)
  24:	b345      	st.w	r2, (r3, 0x14)	// *(((0x5000 | (0x1 << 0x1e)) + 0x14)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x14)) & 0xffffff00)
  26:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x14))
  28:	6c48      	or	r1, r2	// regs: r1=(<arg1> | *(((0x5000 | (0x1 << 0x1e)) + 0x14)))
  2a:	b325      	st.w	r1, (r3, 0x14)	// *(((0x5000 | (0x1 << 0x1e)) + 0x14)) = (<arg1> | *(((0x5000 | (0x1 << 0x1e)) + 0x14)))
  2c:	9345      	ld.w	r2, (r3, 0x14)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x14))
  2e:	3ab7      	bseti	r2, 23	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x14)) | (0x1 << 0x17))
  30:	b345      	st.w	r2, (r3, 0x14)	// *(((0x5000 | (0x1 << 0x1e)) + 0x14)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x14)) | (0x1 << 0x17))
  32:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_set_dbgpath_device_extspi_dpd_gain:

00000000 <ah_set_dbgpath_device_extspi_dpd_gain>: // arg_bytes: 8
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	c6a0502c 	bmaski	r12, 22
   a:	c64c490c 	rotli	r12, r12, 18	// regs: r12=rotl(r12, 0x12)
   e:	9346      	ld.w	r2, (r3, 0x18)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x18))
  10:	68b0      	and	r2, r12	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x18)) & rotl(r12, 0x12))
  12:	b346      	st.w	r2, (r3, 0x18)	// *(((0x5000 | (0x1 << 0x1e)) + 0x18)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x18)) & rotl(r12, 0x12))
  14:	9346      	ld.w	r2, (r3, 0x18)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x18))
  16:	4008      	lsli	r0, r0, 8	// regs: r0=(<arg0> << 0x8)
  18:	6c08      	or	r0, r2	// regs: r0=((<arg0> << 0x8) | *(((0x5000 | (0x1 << 0x1e)) + 0x18)))
  1a:	b306      	st.w	r0, (r3, 0x18)	// *(((0x5000 | (0x1 << 0x1e)) + 0x18)) = ((<arg0> << 0x8) | *(((0x5000 | (0x1 << 0x1e)) + 0x18)))
  1c:	3000      	movi	r0, 0	// regs: r0=0x0
  1e:	9346      	ld.w	r2, (r3, 0x18)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x18))
  20:	28ff      	subi	r0, 256	// regs: r0=0xffffff00
  22:	6880      	and	r2, r0	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x18)) & 0xffffff00)
  24:	b346      	st.w	r2, (r3, 0x18)	// *(((0x5000 | (0x1 << 0x1e)) + 0x18)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x18)) & 0xffffff00)
  26:	9346      	ld.w	r2, (r3, 0x18)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x18))
  28:	6c48      	or	r1, r2	// regs: r1=(<arg1> | *(((0x5000 | (0x1 << 0x1e)) + 0x18)))
  2a:	b326      	st.w	r1, (r3, 0x18)	// *(((0x5000 | (0x1 << 0x1e)) + 0x18)) = (<arg1> | *(((0x5000 | (0x1 << 0x1e)) + 0x18)))
  2c:	9346      	ld.w	r2, (r3, 0x18)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x18))
  2e:	3ab7      	bseti	r2, 23	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x18)) | (0x1 << 0x17))
  30:	b346      	st.w	r2, (r3, 0x18)	// *(((0x5000 | (0x1 << 0x1e)) + 0x18)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x18)) | (0x1 << 0x17))
  32:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_enable_dbgpath_device_ext_dpd_gain:

00000000 <ah_enable_dbgpath_device_ext_dpd_gain>: // arg_bytes: 0
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   8:	3a95      	bclri	r2, 21	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x15))
   a:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x15))
   c:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   e:	3ab5      	bseti	r2, 21	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) | (0x1 << 0x15))
  10:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) | (0x1 << 0x15))
  12:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_disable_dbgpath_device_ext_dpd_gain:

00000000 <ah_disable_dbgpath_device_ext_dpd_gain>: // arg_bytes: 0
   0:	ea025000 	movi	r2, 20480	// regs: r2=0x5000
   4:	3abe      	bseti	r2, 30	// regs: r2=(0x5000 | (0x1 << 0x1e))
   6:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0x5000 | (0x1 << 0x1e)))
   8:	3b95      	bclri	r3, 21	// regs: r3=(*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x15))
   a:	b260      	st.w	r3, (r2, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x15))
   c:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_get_dbgpath_device_stop_pos:

00000000 <ah_get_dbgpath_device_stop_pos>: // arg_bytes: 4
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	9343      	ld.w	r2, (r3, 0xc)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0xc))
   8:	c4028023 	divu	r3, r2, r0	// regs: r3=(*(((0x5000 | (0x1 << 0x1e)) + 0xc)) / <arg0>)
   c:	7c0c      	mult	r0, r3	// regs: r0=(<arg0> * (*(((0x5000 | (0x1 << 0x1e)) + 0xc)) / <arg0>))
   e:	5a01      	subu	r0, r2, r0	// regs: r0=(*(((0x5000 | (0x1 << 0x1e)) + 0xc)) - (<arg0> * (*(((0x5000 | (0x1 << 0x1e)) + 0xc)) / <arg0>)))
  10:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_set_dbgpath_device_path_mode:

00000000 <ah_set_dbgpath_device_path_mode>: // arg_bytes: 4
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	3100      	movi	r1, 0	// regs: r1=0x0
   8:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   a:	2907      	subi	r1, 8	// regs: r1=0xfffffff8
   c:	6884      	and	r2, r1	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & 0xfffffff8)
   e:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) & 0xfffffff8)
  10:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
  12:	e4002007 	andi	r0, r0, 7	// regs: r0=(<arg0> & 0x7)
  16:	6c08      	or	r0, r2	// regs: r0=((<arg0> & 0x7) | *((0x5000 | (0x1 << 0x1e))))
  18:	b300      	st.w	r0, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = ((<arg0> & 0x7) | *((0x5000 | (0x1 << 0x1e))))
  1a:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_set_dbgpath_device_tdma2_en_bit:

00000000 <ah_set_dbgpath_device_tdma2_en_bit>: // arg_bytes: 4
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	401f      	lsli	r0, r0, 31	// regs: r0=(<arg0> << 0x1f)
   8:	9349      	ld.w	r2, (r3, 0x24)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x24))
   a:	c40257c2 	zext	r2, r2, 30, 0	// regs: r2=zext(*(((0x5000 | (0x1 << 0x1e)) + 0x24)))
   e:	b349      	st.w	r2, (r3, 0x24)	// *(((0x5000 | (0x1 << 0x1e)) + 0x24)) = zext(*(((0x5000 | (0x1 << 0x1e)) + 0x24)))
  10:	9349      	ld.w	r2, (r3, 0x24)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x24))
  12:	6c08      	or	r0, r2	// regs: r0=((<arg0> << 0x1f) | *(((0x5000 | (0x1 << 0x1e)) + 0x24)))
  14:	b309      	st.w	r0, (r3, 0x24)	// *(((0x5000 | (0x1 << 0x1e)) + 0x24)) = ((<arg0> << 0x1f) | *(((0x5000 | (0x1 << 0x1e)) + 0x24)))
  16:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_trig_dbgpath_device_dma:

00000000 <ah_trig_dbgpath_device_dma>: // arg_bytes: 0
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   8:	3a84      	bclri	r2, 4	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x4))
   a:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x4))
   c:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   e:	ec420010 	ori	r2, r2, 16	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) | 0x10)
  12:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) | 0x10)
loc_14:
  14:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
  16:	e4422010 	andi	r2, r2, 16	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & 0x10)
  1a:	e902fffd 	bez	r2, 0x14	// if (r2 == 0x0) goto loc_14;
  1e:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_trig_dbgpath_device_dma2:

00000000 <ah_trig_dbgpath_device_dma2>: // arg_bytes: 0
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	3180      	movi	r1, 128	// regs: r1=0x80
   8:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   a:	3a96      	bclri	r2, 22	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x16))
   c:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x16))
   e:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
  10:	3ab6      	bseti	r2, 22	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) | (0x1 << 0x16))
  12:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) | (0x1 << 0x16))
  14:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
  16:	412f      	lsli	r1, r1, 15	// regs: r1=0x400000
loc_18:
  18:	6884      	and	r2, r1	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & 0x400000)
  1a:	e9020003 	bez	r2, 0x20	// if (r2 == 0x0) goto loc_20;
  1e:	783c      	jmp	r15	// return;
loc_20:
  20:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
  22:	07fb      	br	0x18	// goto loc_18;

Disassembly of section .text.ah_abort_dbgpath_device_dma:

00000000 <ah_abort_dbgpath_device_dma>: // arg_bytes: 0
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   8:	3a85      	bclri	r2, 5	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x5))
   a:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x5))
   c:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   e:	ec420020 	ori	r2, r2, 32	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) | 0x20)
  12:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) | 0x20)
loc_14:
  14:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
  16:	e4422020 	andi	r2, r2, 32	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & 0x20)
  1a:	e902fffd 	bez	r2, 0x14	// if (r2 == 0x0) goto loc_14;
  1e:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_abort_dbgpath_device_dma2:

00000000 <ah_abort_dbgpath_device_dma2>: // arg_bytes: 0
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	3180      	movi	r1, 128	// regs: r1=0x80
   8:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   a:	3a97      	bclri	r2, 23	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x17))
   c:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x17))
   e:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
  10:	3ab7      	bseti	r2, 23	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) | (0x1 << 0x17))
  12:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (*((0x5000 | (0x1 << 0x1e))) | (0x1 << 0x17))
  14:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
  16:	4130      	lsli	r1, r1, 16	// regs: r1=0x800000
loc_18:
  18:	6884      	and	r2, r1	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & 0x800000)
  1a:	e9020003 	bez	r2, 0x20	// if (r2 == 0x0) goto loc_20;
  1e:	783c      	jmp	r15	// return;
loc_20:
  20:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
  22:	07fb      	br	0x18	// goto loc_18;

Disassembly of section .text.ah_config_dbgpath_device_dmaend_cond:

00000000 <ah_config_dbgpath_device_dmaend_cond>: // arg_bytes: 4
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	31c0      	movi	r1, 192	// regs: r1=0xc0
   8:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   a:	3a92      	bclri	r2, 18	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x12))
   c:	3a93      	bclri	r2, 19	// regs: r2=((*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x12)) & ~(0x1 << 0x13))
   e:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = ((*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x12)) & ~(0x1 << 0x13))
  10:	412c      	lsli	r1, r1, 12	// regs: r1=0xc0000
  12:	4012      	lsli	r0, r0, 18	// regs: r0=(<arg0> << 0x12)
  14:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
  16:	6804      	and	r0, r1	// regs: r0=((<arg0> << 0x12) & 0xc0000)
  18:	6c08      	or	r0, r2	// regs: r0=(((<arg0> << 0x12) & 0xc0000) | *((0x5000 | (0x1 << 0x1e))))
  1a:	b300      	st.w	r0, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = (((<arg0> << 0x12) & 0xc0000) | *((0x5000 | (0x1 << 0x1e))))
  1c:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_config_dbgpath_device_ext_path:

00000000 <ah_config_dbgpath_device_ext_path>: // arg_bytes: 4
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*((0x5000 | (0x1 << 0x1e)))
   8:	e9200006 	bnez	r0, 0x14	// if (r0 != 0x0) goto loc_14;
   c:	3a94      	bclri	r2, 20	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x14))
   e:	3a95      	bclri	r2, 21	// regs: r2=((*((0x5000 | (0x1 << 0x1e))) & ~(0x1 << 0x14)) & ~(0x1 << 0x15))
loc_10:
  10:	b340      	st.w	r2, (r3, 0x0)	// *((0x5000 | (0x1 << 0x1e))) = r2
  12:	783c      	jmp	r15	// return;
loc_14:
  14:	3ab4      	bseti	r2, 20	// regs: r2=(*((0x5000 | (0x1 << 0x1e))) | (0x1 << 0x14))
  16:	3ab5      	bseti	r2, 21	// regs: r2=((*((0x5000 | (0x1 << 0x1e))) | (0x1 << 0x14)) | (0x1 << 0x15))
  18:	07fc      	br	0x10	// goto loc_10;

Disassembly of section .text.ah_config_dbgpath_device_dbg_out:

00000000 <ah_config_dbgpath_device_dbg_out>: // arg_bytes: 8
   0:	3806      	cmphsi	r0, 7
   2:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   6:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   8:	0845      	bt	0x92	// if (r0 >= 0x7) goto loc_92;
   a:	1043      	lrw	r2, 0x0	// regs: r2=0x0
   c:	d0020882 	ldr.w	r2, (r2, r0 << 2)	// regs: r2=*(0x0 + (<arg0> << 2))
  10:	7808      	jmp	r2	// goto *r2;
  12:	0000      	.short	0x0000
  14:	00000000 	.long	0x00000000	// <.rodata.ah_config_dbgpath_device_dbg_out>
  18:	3000      	movi	r0, 0	// regs: r0=0x0
  1a:	934a      	ld.w	r2, (r3, 0x28)	// regs: r2=*(<arg3> + 0x28)
  1c:	28ff      	subi	r0, 256	// regs: r0=0xffffff00
  1e:	6880      	and	r2, r0	// regs: r2=(*(<arg3> + 0x28) & 0xffffff00)
  20:	b34a      	st.w	r2, (r3, 0x28)	// *(<arg3> + 0x28) = (*(<arg3> + 0x28) & 0xffffff00)
  22:	934a      	ld.w	r2, (r3, 0x28)	// regs: r2=*(<arg3> + 0x28)
loc_24:
  24:	6c48      	or	r1, r2	// regs: r1=(r1 | *(<arg3> + 0x28))
  26:	b32a      	st.w	r1, (r3, 0x28)	// *(<arg3> + 0x28) = (r1 | *(<arg3> + 0x28))
loc_28:
  28:	783c      	jmp	r15	// return;
  2a:	934a      	ld.w	r2, (r3, 0x28)	// regs: r2=*(<arg3> + 0x28)
  2c:	ea00ff00 	movi	r0, 65280	// regs: r0=0xff00
  30:	6c02      	nor	r0, r0	// regs: r0=(~0xff00)
  32:	6880      	and	r2, r0	// regs: r2=(*(<arg3> + 0x28) & (~0xff00))
  34:	b34a      	st.w	r2, (r3, 0x28)	// *(<arg3> + 0x28) = (*(<arg3> + 0x28) & (~0xff00))
  36:	934a      	ld.w	r2, (r3, 0x28)	// regs: r2=*(<arg3> + 0x28)
  38:	4128      	lsli	r1, r1, 8	// regs: r1=(<arg1> << 0x8)
  3a:	07f5      	br	0x24	// goto loc_24;
  3c:	ea20ff01 	movih	r0, 65281	// regs: r0=(0xff01 << 0x10)
  40:	934a      	ld.w	r2, (r3, 0x28)	// regs: r2=*(<arg3> + 0x28)
  42:	2800      	subi	r0, 1	// regs: r0=((0xff01 << 0x10) - 0x1)
  44:	6880      	and	r2, r0	// regs: r2=(*(<arg3> + 0x28) & ((0xff01 << 0x10) - 0x1))
  46:	b34a      	st.w	r2, (r3, 0x28)	// *(<arg3> + 0x28) = (*(<arg3> + 0x28) & ((0xff01 << 0x10) - 0x1))
  48:	934a      	ld.w	r2, (r3, 0x28)	// regs: r2=*(<arg3> + 0x28)
  4a:	4130      	lsli	r1, r1, 16	// regs: r1=(<arg1> << 0x10)
  4c:	07ec      	br	0x24	// goto loc_24;
  4e:	934a      	ld.w	r2, (r3, 0x28)	// regs: r2=*(<arg3> + 0x28)
  50:	c40256e2 	zext	r2, r2, 23, 0	// regs: r2=zext(*(<arg3> + 0x28))
  54:	b34a      	st.w	r2, (r3, 0x28)	// *(<arg3> + 0x28) = zext(*(<arg3> + 0x28))
  56:	934a      	ld.w	r2, (r3, 0x28)	// regs: r2=*(<arg3> + 0x28)
  58:	4138      	lsli	r1, r1, 24	// regs: r1=(<arg1> << 0x18)
  5a:	07e5      	br	0x24	// goto loc_24;
  5c:	3000      	movi	r0, 0	// regs: r0=0x0
  5e:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(<arg3> + 0x2c)
  60:	28ff      	subi	r0, 256	// regs: r0=0xffffff00
  62:	6880      	and	r2, r0	// regs: r2=(*(<arg3> + 0x2c) & 0xffffff00)
  64:	b34b      	st.w	r2, (r3, 0x2c)	// *(<arg3> + 0x2c) = (*(<arg3> + 0x2c) & 0xffffff00)
  66:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(<arg3> + 0x2c)
loc_68:
  68:	6c48      	or	r1, r2	// regs: r1=(r1 | r2)
  6a:	b32b      	st.w	r1, (r3, 0x2c)	// *(r3 + 0x2c) = (r1 | r2)
  6c:	07de      	br	0x28	// goto loc_28;
  6e:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(<arg3> + 0x2c)
  70:	ea00ff00 	movi	r0, 65280	// regs: r0=0xff00
  74:	6c02      	nor	r0, r0	// regs: r0=(~0xff00)
  76:	6880      	and	r2, r0	// regs: r2=(*(<arg3> + 0x2c) & (~0xff00))
  78:	b34b      	st.w	r2, (r3, 0x2c)	// *(<arg3> + 0x2c) = (*(<arg3> + 0x2c) & (~0xff00))
  7a:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(<arg3> + 0x2c)
  7c:	4128      	lsli	r1, r1, 8	// regs: r1=(<arg1> << 0x8)
  7e:	07f5      	br	0x68	// goto loc_68;
  80:	ea20ff01 	movih	r0, 65281	// regs: r0=(0xff01 << 0x10)
  84:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(<arg3> + 0x2c)
  86:	2800      	subi	r0, 1	// regs: r0=((0xff01 << 0x10) - 0x1)
  88:	6880      	and	r2, r0	// regs: r2=(*(<arg3> + 0x2c) & ((0xff01 << 0x10) - 0x1))
  8a:	b34b      	st.w	r2, (r3, 0x2c)	// *(<arg3> + 0x2c) = (*(<arg3> + 0x2c) & ((0xff01 << 0x10) - 0x1))
  8c:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(<arg3> + 0x2c)
  8e:	4130      	lsli	r1, r1, 16	// regs: r1=(<arg1> << 0x10)
  90:	07ec      	br	0x68	// goto loc_68;
loc_92:
  92:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x2c))
  94:	c40256e2 	zext	r2, r2, 23, 0	// regs: r2=zext(*(((0x5000 | (0x1 << 0x1e)) + 0x2c)))
  98:	b34b      	st.w	r2, (r3, 0x2c)	// *(((0x5000 | (0x1 << 0x1e)) + 0x2c)) = zext(*(((0x5000 | (0x1 << 0x1e)) + 0x2c)))
  9a:	934b      	ld.w	r2, (r3, 0x2c)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x2c))
  9c:	4138      	lsli	r1, r1, 24	// regs: r1=(<arg1> << 0x18)
  9e:	07e5      	br	0x68	// goto loc_68;

Disassembly of section .text.ah_config_dbgpath_device_enable_bits:

00000000 <ah_config_dbgpath_device_enable_bits>: // arg_bytes: 4
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	31ff      	movi	r1, 255	// regs: r1=0xff
   8:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x1c))
   a:	4128      	lsli	r1, r1, 8	// regs: r1=0xff00
   c:	6884      	and	r2, r1	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x1c)) & 0xff00)
   e:	7441      	zexth	r1, r0	// regs: r1=zext16(<arg0>)
  10:	6c84      	or	r2, r1	// regs: r2=((*(((0x5000 | (0x1 << 0x1e)) + 0x1c)) & 0xff00) | zext16(<arg0>))
  12:	b347      	st.w	r2, (r3, 0x1c)	// *(((0x5000 | (0x1 << 0x1e)) + 0x1c)) = ((*(((0x5000 | (0x1 << 0x1e)) + 0x1c)) & 0xff00) | zext16(<arg0>))
  14:	c6005602 	zext	r2, r0, 16, 16	// regs: r2=zext(<arg0>)
  18:	4243      	lsli	r2, r2, 3	// regs: r2=(zext(<arg0>) << 0x3)
  1a:	b34a      	st.w	r2, (r3, 0x28)	// *(((0x5000 | (0x1 << 0x1e)) + 0x28)) = (zext(<arg0>) << 0x3)
  1c:	934c      	ld.w	r2, (r3, 0x30)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x30))
  1e:	3a9d      	bclri	r2, 29	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x30)) & ~(0x1 << 0x1d))
  20:	3180      	movi	r1, 128	// regs: r1=0x80
  22:	b34c      	st.w	r2, (r3, 0x30)	// *(((0x5000 | (0x1 << 0x1e)) + 0x30)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x30)) & ~(0x1 << 0x1d))
  24:	4136      	lsli	r1, r1, 22	// regs: r1=0x20000000
  26:	404c      	lsli	r2, r0, 12	// regs: r2=(<arg0> << 0xc)
  28:	d983200c 	ld.w	r12, (r3, 0x30)	// regs: r12=*(((0x5000 | (0x1 << 0x1e)) + 0x30))
  2c:	6884      	and	r2, r1	// regs: r2=((<arg0> << 0xc) & 0x20000000)
  2e:	6cb0      	or	r2, r12	// regs: r2=(((<arg0> << 0xc) & 0x20000000) | *(((0x5000 | (0x1 << 0x1e)) + 0x30)))
  30:	b34c      	st.w	r2, (r3, 0x30)	// *(((0x5000 | (0x1 << 0x1e)) + 0x30)) = (((<arg0> << 0xc) & 0x20000000) | *(((0x5000 | (0x1 << 0x1e)) + 0x30)))
  32:	934e      	ld.w	r2, (r3, 0x38)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x38))
  34:	3a9d      	bclri	r2, 29	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x38)) & ~(0x1 << 0x1d))
  36:	b34e      	st.w	r2, (r3, 0x38)	// *(((0x5000 | (0x1 << 0x1e)) + 0x38)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x38)) & ~(0x1 << 0x1d))
  38:	c6405642 	zext	r2, r0, 18, 18	// regs: r2=zext(<arg0>)
  3c:	932e      	ld.w	r1, (r3, 0x38)	// regs: r1=*(((0x5000 | (0x1 << 0x1e)) + 0x38))
  3e:	425d      	lsli	r2, r2, 29	// regs: r2=(zext(<arg0>) << 0x1d)
  40:	6c84      	or	r2, r1	// regs: r2=((zext(<arg0>) << 0x1d) | *(((0x5000 | (0x1 << 0x1e)) + 0x38)))
  42:	b34e      	st.w	r2, (r3, 0x38)	// *(((0x5000 | (0x1 << 0x1e)) + 0x38)) = ((zext(<arg0>) << 0x1d) | *(((0x5000 | (0x1 << 0x1e)) + 0x38)))
  44:	9350      	ld.w	r2, (r3, 0x40)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x40))
  46:	3a9d      	bclri	r2, 29	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x40)) & ~(0x1 << 0x1d))
  48:	b350      	st.w	r2, (r3, 0x40)	// *(((0x5000 | (0x1 << 0x1e)) + 0x40)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x40)) & ~(0x1 << 0x1d))
  4a:	c6605662 	zext	r2, r0, 19, 19	// regs: r2=zext(<arg0>)
  4e:	9330      	ld.w	r1, (r3, 0x40)	// regs: r1=*(((0x5000 | (0x1 << 0x1e)) + 0x40))
  50:	425d      	lsli	r2, r2, 29	// regs: r2=(zext(<arg0>) << 0x1d)
  52:	6c84      	or	r2, r1	// regs: r2=((zext(<arg0>) << 0x1d) | *(((0x5000 | (0x1 << 0x1e)) + 0x40)))
  54:	b350      	st.w	r2, (r3, 0x40)	// *(((0x5000 | (0x1 << 0x1e)) + 0x40)) = ((zext(<arg0>) << 0x1d) | *(((0x5000 | (0x1 << 0x1e)) + 0x40)))
  56:	9352      	ld.w	r2, (r3, 0x48)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x48))
  58:	3a9d      	bclri	r2, 29	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x48)) & ~(0x1 << 0x1d))
  5a:	b352      	st.w	r2, (r3, 0x48)	// *(((0x5000 | (0x1 << 0x1e)) + 0x48)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x48)) & ~(0x1 << 0x1d))
  5c:	c6805682 	zext	r2, r0, 20, 20	// regs: r2=zext(<arg0>)
  60:	9332      	ld.w	r1, (r3, 0x48)	// regs: r1=*(((0x5000 | (0x1 << 0x1e)) + 0x48))
  62:	425d      	lsli	r2, r2, 29	// regs: r2=(zext(<arg0>) << 0x1d)
  64:	6c84      	or	r2, r1	// regs: r2=((zext(<arg0>) << 0x1d) | *(((0x5000 | (0x1 << 0x1e)) + 0x48)))
  66:	b352      	st.w	r2, (r3, 0x48)	// *(((0x5000 | (0x1 << 0x1e)) + 0x48)) = ((zext(<arg0>) << 0x1d) | *(((0x5000 | (0x1 << 0x1e)) + 0x48)))
  68:	9354      	ld.w	r2, (r3, 0x50)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x50))
  6a:	3a9d      	bclri	r2, 29	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x50)) & ~(0x1 << 0x1d))
  6c:	b354      	st.w	r2, (r3, 0x50)	// *(((0x5000 | (0x1 << 0x1e)) + 0x50)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x50)) & ~(0x1 << 0x1d))
  6e:	c6a056a2 	zext	r2, r0, 21, 21	// regs: r2=zext(<arg0>)
  72:	9334      	ld.w	r1, (r3, 0x50)	// regs: r1=*(((0x5000 | (0x1 << 0x1e)) + 0x50))
  74:	425d      	lsli	r2, r2, 29	// regs: r2=(zext(<arg0>) << 0x1d)
  76:	6c84      	or	r2, r1	// regs: r2=((zext(<arg0>) << 0x1d) | *(((0x5000 | (0x1 << 0x1e)) + 0x50)))
  78:	b354      	st.w	r2, (r3, 0x50)	// *(((0x5000 | (0x1 << 0x1e)) + 0x50)) = ((zext(<arg0>) << 0x1d) | *(((0x5000 | (0x1 << 0x1e)) + 0x50)))
  7a:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x58))
  7c:	3a9d      	bclri	r2, 29	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x58)) & ~(0x1 << 0x1d))
  7e:	b356      	st.w	r2, (r3, 0x58)	// *(((0x5000 | (0x1 << 0x1e)) + 0x58)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x58)) & ~(0x1 << 0x1d))
  80:	c6c056c0 	zext	r0, r0, 22, 22	// regs: r0=zext(<arg0>)
  84:	9356      	ld.w	r2, (r3, 0x58)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x58))
  86:	401d      	lsli	r0, r0, 29	// regs: r0=(zext(<arg0>) << 0x1d)
  88:	6c08      	or	r0, r2	// regs: r0=((zext(<arg0>) << 0x1d) | *(((0x5000 | (0x1 << 0x1e)) + 0x58)))
  8a:	b316      	st.w	r0, (r3, 0x58)	// *(((0x5000 | (0x1 << 0x1e)) + 0x58)) = ((zext(<arg0>) << 0x1d) | *(((0x5000 | (0x1 << 0x1e)) + 0x58)))
  8c:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_get_dbgpath_device_rfmipi_err_info:

00000000 <ah_get_dbgpath_device_rfmipi_err_info>: // arg_bytes: 0
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	9307      	ld.w	r0, (r3, 0x1c)	// regs: r0=*(((0x5000 | (0x1 << 0x1e)) + 0x1c))
   8:	c5805580 	zext	r0, r0, 12, 12	// regs: r0=zext(*(((0x5000 | (0x1 << 0x1e)) + 0x1c)))
   c:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_clear_dbgpath_device_rfmipi_err_info:

00000000 <ah_clear_dbgpath_device_rfmipi_err_info>: // arg_bytes: 0
   0:	ea035000 	movi	r3, 20480	// regs: r3=0x5000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x5000 | (0x1 << 0x1e))
   6:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x1c))
   8:	3a8a      	bclri	r2, 10	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x1c)) & ~(0x1 << 0xa))
   a:	b347      	st.w	r2, (r3, 0x1c)	// *(((0x5000 | (0x1 << 0x1e)) + 0x1c)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x1c)) & ~(0x1 << 0xa))
   c:	9347      	ld.w	r2, (r3, 0x1c)	// regs: r2=*(((0x5000 | (0x1 << 0x1e)) + 0x1c))
   e:	ec420400 	ori	r2, r2, 1024	// regs: r2=(*(((0x5000 | (0x1 << 0x1e)) + 0x1c)) | 0x400)
  12:	b347      	st.w	r2, (r3, 0x1c)	// *(((0x5000 | (0x1 << 0x1e)) + 0x1c)) = (*(((0x5000 | (0x1 << 0x1e)) + 0x1c)) | 0x400)
  14:	783c      	jmp	r15	// return;
