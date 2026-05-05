
libs\obj\liblmac\mars_tdma.o:     file format elf32-csky-little


Disassembly of section .text.ah_tdma_set_mode:

00000000 <ah_tdma_set_mode>: // arg_bytes: 8
   0:	e9200012 	bnez	r0, 0x24	// if (r0 != 0x0) goto loc_24;
   4:	ea021000 	movi	r2, 4096	// regs: r2=0x1000
   8:	3abe      	bseti	r2, 30	// regs: r2=(0x1000 | (0x1 << 0x1e))
   a:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0x1000 | (0x1 << 0x1e)))
   c:	3b82      	bclri	r3, 2	// regs: r3=(*((0x1000 | (0x1 << 0x1e))) & ~(0x1 << 0x2))
loc_e:
   e:	b260      	st.w	r3, (r2, 0x0)	// *((0x1000 | (0x1 << 0x1e))) = r3
  10:	e9210016 	bnez	r1, 0x3c	// if (r1 != 0x0) goto loc_3c;
  14:	ea021000 	movi	r2, 4096	// regs: r2=0x1000
  18:	3abe      	bseti	r2, 30	// regs: r2=(0x1000 | (0x1 << 0x1e))
  1a:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0x1000 | (0x1 << 0x1e)))
  1c:	3b84      	bclri	r3, 4	// regs: r3=(*((0x1000 | (0x1 << 0x1e))) & ~(0x1 << 0x4))
loc_1e:
  1e:	b260      	st.w	r3, (r2, 0x0)	// *((0x1000 | (0x1 << 0x1e))) = r3
  20:	3000      	movi	r0, 0	// regs: r0=0x0
  22:	0405      	br	0x2c	// goto loc_2c;
loc_24:
  24:	3841      	cmpnei	r0, 1
  26:	0c04      	bf	0x2e	// if (r0 == 0x1) goto loc_2e;
loc_28:
  28:	3000      	movi	r0, 0	// regs: r0=0x0
  2a:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_2c:
  2c:	783c      	jmp	r15	// return;
loc_2e:
  2e:	ea021000 	movi	r2, 4096	// regs: r2=0x1000
  32:	3abe      	bseti	r2, 30	// regs: r2=(0x1000 | (0x1 << 0x1e))
  34:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0x1000 | (0x1 << 0x1e)))
  36:	ec630004 	ori	r3, r3, 4	// regs: r3=(*((0x1000 | (0x1 << 0x1e))) | 0x4)
  3a:	07ea      	br	0xe	// goto loc_e;
loc_3c:
  3c:	3941      	cmpnei	r1, 1
  3e:	0bf5      	bt	0x28	// if (r1 != 0x1) goto loc_28;
  40:	ea021000 	movi	r2, 4096	// regs: r2=0x1000
  44:	3abe      	bseti	r2, 30	// regs: r2=(0x1000 | (0x1 << 0x1e))
  46:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0x1000 | (0x1 << 0x1e)))
  48:	ec630010 	ori	r3, r3, 16	// regs: r3=(*((0x1000 | (0x1 << 0x1e))) | 0x10)
  4c:	07e9      	br	0x1e	// goto loc_1e;

Disassembly of section .text.ah_tdma_enable_irq:

00000000 <ah_tdma_enable_irq>: // arg_bytes: 0
   0:	ea021000 	movi	r2, 4096	// regs: r2=0x1000
   4:	3abe      	bseti	r2, 30	// regs: r2=(0x1000 | (0x1 << 0x1e))
   6:	3000      	movi	r0, 0	// regs: r0=0x0
   8:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0x1000 | (0x1 << 0x1e)))
   a:	ec630008 	ori	r3, r3, 8	// regs: r3=(*((0x1000 | (0x1 << 0x1e))) | 0x8)
   e:	b260      	st.w	r3, (r2, 0x0)	// *((0x1000 | (0x1 << 0x1e))) = (*((0x1000 | (0x1 << 0x1e))) | 0x8)
  10:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_tdma_set_buff:

00000000 <ah_tdma_set_buff>: // arg_bytes: 8
   0:	c6605023 	bmaski	r3, 20
   4:	644c      	cmphs	r3, r1
   6:	0c08      	bf	0x16	// if (!T) goto loc_16;
   8:	ea031000 	movi	r3, 4096	// regs: r3=0x1000
   c:	3bbe      	bseti	r3, 30	// regs: r3=(0x1000 | (0x1 << 0x1e))
   e:	b302      	st.w	r0, (r3, 0x8)	// *(((0x1000 | (0x1 << 0x1e)) + 0x8)) = <arg0>
  10:	b323      	st.w	r1, (r3, 0xc)	// *(((0x1000 | (0x1 << 0x1e)) + 0xc)) = <arg1>
  12:	3000      	movi	r0, 0	// regs: r0=0x0
loc_14:
  14:	783c      	jmp	r15	// return;
loc_16:
  16:	3000      	movi	r0, 0	// regs: r0=0x0
  18:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  1a:	07fd      	br	0x14	// goto loc_14;

Disassembly of section .text.ah_tdma_set_trig_len:

00000000 <ah_tdma_set_trig_len>: // arg_bytes: 4
   0:	c6605023 	bmaski	r3, 20
   4:	640c      	cmphs	r3, r0
   6:	0c07      	bf	0x14	// if (!T) goto loc_14;
   8:	ea031000 	movi	r3, 4096	// regs: r3=0x1000
   c:	3bbe      	bseti	r3, 30	// regs: r3=(0x1000 | (0x1 << 0x1e))
   e:	b305      	st.w	r0, (r3, 0x14)	// *(((0x1000 | (0x1 << 0x1e)) + 0x14)) = <arg0>
  10:	3000      	movi	r0, 0	// regs: r0=0x0
loc_12:
  12:	783c      	jmp	r15	// return;
loc_14:
  14:	3000      	movi	r0, 0	// regs: r0=0x0
  16:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  18:	07fd      	br	0x12	// goto loc_12;

Disassembly of section .text.ah_tdma_start:

00000000 <ah_tdma_start>: // arg_bytes: 0
   0:	ea021000 	movi	r2, 4096	// regs: r2=0x1000
   4:	3abe      	bseti	r2, 30	// regs: r2=(0x1000 | (0x1 << 0x1e))
   6:	3000      	movi	r0, 0	// regs: r0=0x0
   8:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0x1000 | (0x1 << 0x1e)))
   a:	ec630001 	ori	r3, r3, 1	// regs: r3=(*((0x1000 | (0x1 << 0x1e))) | 0x1)
   e:	b260      	st.w	r3, (r2, 0x0)	// *((0x1000 | (0x1 << 0x1e))) = (*((0x1000 | (0x1 << 0x1e))) | 0x1)
  10:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_tdma_abort:

00000000 <ah_tdma_abort>: // arg_bytes: 0
   0:	ea021000 	movi	r2, 4096	// regs: r2=0x1000
   4:	3abe      	bseti	r2, 30	// regs: r2=(0x1000 | (0x1 << 0x1e))
   6:	3000      	movi	r0, 0	// regs: r0=0x0
   8:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0x1000 | (0x1 << 0x1e)))
   a:	ec630002 	ori	r3, r3, 2	// regs: r3=(*((0x1000 | (0x1 << 0x1e))) | 0x2)
   e:	b260      	st.w	r3, (r2, 0x0)	// *((0x1000 | (0x1 << 0x1e))) = (*((0x1000 | (0x1 << 0x1e))) | 0x2)
  10:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_tdma_get_pd:

00000000 <ah_tdma_get_pd>: // arg_bytes: 0
   0:	ea031000 	movi	r3, 4096	// regs: r3=0x1000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0x1000 | (0x1 << 0x1e))
   6:	9301      	ld.w	r0, (r3, 0x4)	// regs: r0=*(((0x1000 | (0x1 << 0x1e)) + 0x4))
   8:	e4002001 	andi	r0, r0, 1	// regs: r0=(*(((0x1000 | (0x1 << 0x1e)) + 0x4)) & 0x1)
   c:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_tdma_clear_pd:

00000000 <ah_tdma_clear_pd>: // arg_bytes: 0
   0:	ea021000 	movi	r2, 4096	// regs: r2=0x1000
   4:	3abe      	bseti	r2, 30	// regs: r2=(0x1000 | (0x1 << 0x1e))
   6:	3000      	movi	r0, 0	// regs: r0=0x0
   8:	9261      	ld.w	r3, (r2, 0x4)	// regs: r3=*(((0x1000 | (0x1 << 0x1e)) + 0x4))
   a:	ec630001 	ori	r3, r3, 1	// regs: r3=(*(((0x1000 | (0x1 << 0x1e)) + 0x4)) | 0x1)
   e:	b261      	st.w	r3, (r2, 0x4)	// *(((0x1000 | (0x1 << 0x1e)) + 0x4)) = (*(((0x1000 | (0x1 << 0x1e)) + 0x4)) | 0x1)
  10:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_tdma2_set_mode:

00000000 <ah_tdma2_set_mode>: // arg_bytes: 8
   0:	e9200012 	bnez	r0, 0x24	// if (r0 != 0x0) goto loc_24;
   4:	ea02b000 	movi	r2, 45056	// regs: r2=0xb000
   8:	3abe      	bseti	r2, 30	// regs: r2=(0xb000 | (0x1 << 0x1e))
   a:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0xb000 | (0x1 << 0x1e)))
   c:	3b82      	bclri	r3, 2	// regs: r3=(*((0xb000 | (0x1 << 0x1e))) & ~(0x1 << 0x2))
loc_e:
   e:	b260      	st.w	r3, (r2, 0x0)	// *((0xb000 | (0x1 << 0x1e))) = r3
  10:	e9210016 	bnez	r1, 0x3c	// if (r1 != 0x0) goto loc_3c;
  14:	ea02b000 	movi	r2, 45056	// regs: r2=0xb000
  18:	3abe      	bseti	r2, 30	// regs: r2=(0xb000 | (0x1 << 0x1e))
  1a:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0xb000 | (0x1 << 0x1e)))
  1c:	3b84      	bclri	r3, 4	// regs: r3=(*((0xb000 | (0x1 << 0x1e))) & ~(0x1 << 0x4))
loc_1e:
  1e:	b260      	st.w	r3, (r2, 0x0)	// *((0xb000 | (0x1 << 0x1e))) = r3
  20:	3000      	movi	r0, 0	// regs: r0=0x0
  22:	0405      	br	0x2c	// goto loc_2c;
loc_24:
  24:	3841      	cmpnei	r0, 1
  26:	0c04      	bf	0x2e	// if (r0 == 0x1) goto loc_2e;
loc_28:
  28:	3000      	movi	r0, 0	// regs: r0=0x0
  2a:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_2c:
  2c:	783c      	jmp	r15	// return;
loc_2e:
  2e:	ea02b000 	movi	r2, 45056	// regs: r2=0xb000
  32:	3abe      	bseti	r2, 30	// regs: r2=(0xb000 | (0x1 << 0x1e))
  34:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0xb000 | (0x1 << 0x1e)))
  36:	ec630004 	ori	r3, r3, 4	// regs: r3=(*((0xb000 | (0x1 << 0x1e))) | 0x4)
  3a:	07ea      	br	0xe	// goto loc_e;
loc_3c:
  3c:	3941      	cmpnei	r1, 1
  3e:	0bf5      	bt	0x28	// if (r1 != 0x1) goto loc_28;
  40:	ea02b000 	movi	r2, 45056	// regs: r2=0xb000
  44:	3abe      	bseti	r2, 30	// regs: r2=(0xb000 | (0x1 << 0x1e))
  46:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0xb000 | (0x1 << 0x1e)))
  48:	ec630010 	ori	r3, r3, 16	// regs: r3=(*((0xb000 | (0x1 << 0x1e))) | 0x10)
  4c:	07e9      	br	0x1e	// goto loc_1e;

Disassembly of section .text.ah_tdma2_enable_irq:

00000000 <ah_tdma2_enable_irq>: // arg_bytes: 0
   0:	ea02b000 	movi	r2, 45056	// regs: r2=0xb000
   4:	3abe      	bseti	r2, 30	// regs: r2=(0xb000 | (0x1 << 0x1e))
   6:	3000      	movi	r0, 0	// regs: r0=0x0
   8:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0xb000 | (0x1 << 0x1e)))
   a:	ec630008 	ori	r3, r3, 8	// regs: r3=(*((0xb000 | (0x1 << 0x1e))) | 0x8)
   e:	b260      	st.w	r3, (r2, 0x0)	// *((0xb000 | (0x1 << 0x1e))) = (*((0xb000 | (0x1 << 0x1e))) | 0x8)
  10:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_tdma2_set_buff:

00000000 <ah_tdma2_set_buff>: // arg_bytes: 8
   0:	c6605023 	bmaski	r3, 20
   4:	644c      	cmphs	r3, r1
   6:	0c08      	bf	0x16	// if (!T) goto loc_16;
   8:	ea03b000 	movi	r3, 45056	// regs: r3=0xb000
   c:	3bbe      	bseti	r3, 30	// regs: r3=(0xb000 | (0x1 << 0x1e))
   e:	b302      	st.w	r0, (r3, 0x8)	// *(((0xb000 | (0x1 << 0x1e)) + 0x8)) = <arg0>
  10:	b323      	st.w	r1, (r3, 0xc)	// *(((0xb000 | (0x1 << 0x1e)) + 0xc)) = <arg1>
  12:	3000      	movi	r0, 0	// regs: r0=0x0
loc_14:
  14:	783c      	jmp	r15	// return;
loc_16:
  16:	3000      	movi	r0, 0	// regs: r0=0x0
  18:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  1a:	07fd      	br	0x14	// goto loc_14;

Disassembly of section .text.ah_tdma2_set_trig_len:

00000000 <ah_tdma2_set_trig_len>: // arg_bytes: 4
   0:	c6605023 	bmaski	r3, 20
   4:	640c      	cmphs	r3, r0
   6:	0c07      	bf	0x14	// if (!T) goto loc_14;
   8:	ea03b000 	movi	r3, 45056	// regs: r3=0xb000
   c:	3bbe      	bseti	r3, 30	// regs: r3=(0xb000 | (0x1 << 0x1e))
   e:	b305      	st.w	r0, (r3, 0x14)	// *(((0xb000 | (0x1 << 0x1e)) + 0x14)) = <arg0>
  10:	3000      	movi	r0, 0	// regs: r0=0x0
loc_12:
  12:	783c      	jmp	r15	// return;
loc_14:
  14:	3000      	movi	r0, 0	// regs: r0=0x0
  16:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  18:	07fd      	br	0x12	// goto loc_12;

Disassembly of section .text.ah_tdma2_start:

00000000 <ah_tdma2_start>: // arg_bytes: 0
   0:	ea02b000 	movi	r2, 45056	// regs: r2=0xb000
   4:	3abe      	bseti	r2, 30	// regs: r2=(0xb000 | (0x1 << 0x1e))
   6:	3000      	movi	r0, 0	// regs: r0=0x0
   8:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0xb000 | (0x1 << 0x1e)))
   a:	ec630001 	ori	r3, r3, 1	// regs: r3=(*((0xb000 | (0x1 << 0x1e))) | 0x1)
   e:	b260      	st.w	r3, (r2, 0x0)	// *((0xb000 | (0x1 << 0x1e))) = (*((0xb000 | (0x1 << 0x1e))) | 0x1)
  10:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_tdma2_abort:

00000000 <ah_tdma2_abort>: // arg_bytes: 0
   0:	ea02b000 	movi	r2, 45056	// regs: r2=0xb000
   4:	3abe      	bseti	r2, 30	// regs: r2=(0xb000 | (0x1 << 0x1e))
   6:	3000      	movi	r0, 0	// regs: r0=0x0
   8:	9260      	ld.w	r3, (r2, 0x0)	// regs: r3=*((0xb000 | (0x1 << 0x1e)))
   a:	ec630002 	ori	r3, r3, 2	// regs: r3=(*((0xb000 | (0x1 << 0x1e))) | 0x2)
   e:	b260      	st.w	r3, (r2, 0x0)	// *((0xb000 | (0x1 << 0x1e))) = (*((0xb000 | (0x1 << 0x1e))) | 0x2)
  10:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_tdma2_get_pd:

00000000 <ah_tdma2_get_pd>: // arg_bytes: 0
   0:	ea03b000 	movi	r3, 45056	// regs: r3=0xb000
   4:	3bbe      	bseti	r3, 30	// regs: r3=(0xb000 | (0x1 << 0x1e))
   6:	9301      	ld.w	r0, (r3, 0x4)	// regs: r0=*(((0xb000 | (0x1 << 0x1e)) + 0x4))
   8:	e4002001 	andi	r0, r0, 1	// regs: r0=(*(((0xb000 | (0x1 << 0x1e)) + 0x4)) & 0x1)
   c:	783c      	jmp	r15	// return;

Disassembly of section .text.ah_tdma2_clear_pd:

00000000 <ah_tdma2_clear_pd>: // arg_bytes: 0
   0:	ea02b000 	movi	r2, 45056	// regs: r2=0xb000
   4:	3abe      	bseti	r2, 30	// regs: r2=(0xb000 | (0x1 << 0x1e))
   6:	3000      	movi	r0, 0	// regs: r0=0x0
   8:	9261      	ld.w	r3, (r2, 0x4)	// regs: r3=*(((0xb000 | (0x1 << 0x1e)) + 0x4))
   a:	ec630001 	ori	r3, r3, 1	// regs: r3=(*(((0xb000 | (0x1 << 0x1e)) + 0x4)) | 0x1)
   e:	b261      	st.w	r3, (r2, 0x4)	// *(((0xb000 | (0x1 << 0x1e)) + 0x4)) = (*(((0xb000 | (0x1 << 0x1e)) + 0x4)) | 0x1)
  10:	783c      	jmp	r15	// return;
