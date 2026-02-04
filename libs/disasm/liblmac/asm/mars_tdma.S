
disasm/liblmac/obj/mars_tdma.o:     file format elf32-csky-little


Disassembly of section .text.ah_tdma_set_mode:

00000000 <ah_tdma_set_mode>:
   0:	e9200012 	bnez      	r0, 0x24	// 24 <ah_tdma_set_mode+0x24>
   4:	ea021000 	movi      	r2, 4096
   8:	3abe      	bseti      	r2, 30
   a:	9260      	ld.w      	r3, (r2, 0x0)
   c:	3b82      	bclri      	r3, 2
   e:	b260      	st.w      	r3, (r2, 0x0)
  10:	e9210016 	bnez      	r1, 0x3c	// 3c <ah_tdma_set_mode+0x3c>
  14:	ea021000 	movi      	r2, 4096
  18:	3abe      	bseti      	r2, 30
  1a:	9260      	ld.w      	r3, (r2, 0x0)
  1c:	3b84      	bclri      	r3, 4
  1e:	b260      	st.w      	r3, (r2, 0x0)
  20:	3000      	movi      	r0, 0
  22:	0405      	br      	0x2c	// 2c <ah_tdma_set_mode+0x2c>
  24:	3841      	cmpnei      	r0, 1
  26:	0c04      	bf      	0x2e	// 2e <ah_tdma_set_mode+0x2e>
  28:	3000      	movi      	r0, 0
  2a:	2800      	subi      	r0, 1
  2c:	783c      	jmp      	r15
  2e:	ea021000 	movi      	r2, 4096
  32:	3abe      	bseti      	r2, 30
  34:	9260      	ld.w      	r3, (r2, 0x0)
  36:	ec630004 	ori      	r3, r3, 4
  3a:	07ea      	br      	0xe	// e <ah_tdma_set_mode+0xe>
  3c:	3941      	cmpnei      	r1, 1
  3e:	0bf5      	bt      	0x28	// 28 <ah_tdma_set_mode+0x28>
  40:	ea021000 	movi      	r2, 4096
  44:	3abe      	bseti      	r2, 30
  46:	9260      	ld.w      	r3, (r2, 0x0)
  48:	ec630010 	ori      	r3, r3, 16
  4c:	07e9      	br      	0x1e	// 1e <ah_tdma_set_mode+0x1e>

Disassembly of section .text.ah_tdma_enable_irq:

00000000 <ah_tdma_enable_irq>:
   0:	ea021000 	movi      	r2, 4096
   4:	3abe      	bseti      	r2, 30
   6:	3000      	movi      	r0, 0
   8:	9260      	ld.w      	r3, (r2, 0x0)
   a:	ec630008 	ori      	r3, r3, 8
   e:	b260      	st.w      	r3, (r2, 0x0)
  10:	783c      	jmp      	r15

Disassembly of section .text.ah_tdma_set_buff:

00000000 <ah_tdma_set_buff>:
   0:	c6605023 	bmaski      	r3, 20
   4:	644c      	cmphs      	r3, r1
   6:	0c08      	bf      	0x16	// 16 <ah_tdma_set_buff+0x16>
   8:	ea031000 	movi      	r3, 4096
   c:	3bbe      	bseti      	r3, 30
   e:	b302      	st.w      	r0, (r3, 0x8)
  10:	b323      	st.w      	r1, (r3, 0xc)
  12:	3000      	movi      	r0, 0
  14:	783c      	jmp      	r15
  16:	3000      	movi      	r0, 0
  18:	2800      	subi      	r0, 1
  1a:	07fd      	br      	0x14	// 14 <ah_tdma_set_buff+0x14>

Disassembly of section .text.ah_tdma_set_trig_len:

00000000 <ah_tdma_set_trig_len>:
   0:	c6605023 	bmaski      	r3, 20
   4:	640c      	cmphs      	r3, r0
   6:	0c07      	bf      	0x14	// 14 <ah_tdma_set_trig_len+0x14>
   8:	ea031000 	movi      	r3, 4096
   c:	3bbe      	bseti      	r3, 30
   e:	b305      	st.w      	r0, (r3, 0x14)
  10:	3000      	movi      	r0, 0
  12:	783c      	jmp      	r15
  14:	3000      	movi      	r0, 0
  16:	2800      	subi      	r0, 1
  18:	07fd      	br      	0x12	// 12 <ah_tdma_set_trig_len+0x12>

Disassembly of section .text.ah_tdma_start:

00000000 <ah_tdma_start>:
   0:	ea021000 	movi      	r2, 4096
   4:	3abe      	bseti      	r2, 30
   6:	3000      	movi      	r0, 0
   8:	9260      	ld.w      	r3, (r2, 0x0)
   a:	ec630001 	ori      	r3, r3, 1
   e:	b260      	st.w      	r3, (r2, 0x0)
  10:	783c      	jmp      	r15

Disassembly of section .text.ah_tdma_abort:

00000000 <ah_tdma_abort>:
   0:	ea021000 	movi      	r2, 4096
   4:	3abe      	bseti      	r2, 30
   6:	3000      	movi      	r0, 0
   8:	9260      	ld.w      	r3, (r2, 0x0)
   a:	ec630002 	ori      	r3, r3, 2
   e:	b260      	st.w      	r3, (r2, 0x0)
  10:	783c      	jmp      	r15

Disassembly of section .text.ah_tdma_get_pd:

00000000 <ah_tdma_get_pd>:
   0:	ea031000 	movi      	r3, 4096
   4:	3bbe      	bseti      	r3, 30
   6:	9301      	ld.w      	r0, (r3, 0x4)
   8:	e4002001 	andi      	r0, r0, 1
   c:	783c      	jmp      	r15

Disassembly of section .text.ah_tdma_clear_pd:

00000000 <ah_tdma_clear_pd>:
   0:	ea021000 	movi      	r2, 4096
   4:	3abe      	bseti      	r2, 30
   6:	3000      	movi      	r0, 0
   8:	9261      	ld.w      	r3, (r2, 0x4)
   a:	ec630001 	ori      	r3, r3, 1
   e:	b261      	st.w      	r3, (r2, 0x4)
  10:	783c      	jmp      	r15

Disassembly of section .text.ah_tdma2_set_mode:

00000000 <ah_tdma2_set_mode>:
   0:	e9200012 	bnez      	r0, 0x24	// 24 <ah_tdma2_set_mode+0x24>
   4:	ea02b000 	movi      	r2, 45056
   8:	3abe      	bseti      	r2, 30
   a:	9260      	ld.w      	r3, (r2, 0x0)
   c:	3b82      	bclri      	r3, 2
   e:	b260      	st.w      	r3, (r2, 0x0)
  10:	e9210016 	bnez      	r1, 0x3c	// 3c <ah_tdma2_set_mode+0x3c>
  14:	ea02b000 	movi      	r2, 45056
  18:	3abe      	bseti      	r2, 30
  1a:	9260      	ld.w      	r3, (r2, 0x0)
  1c:	3b84      	bclri      	r3, 4
  1e:	b260      	st.w      	r3, (r2, 0x0)
  20:	3000      	movi      	r0, 0
  22:	0405      	br      	0x2c	// 2c <ah_tdma2_set_mode+0x2c>
  24:	3841      	cmpnei      	r0, 1
  26:	0c04      	bf      	0x2e	// 2e <ah_tdma2_set_mode+0x2e>
  28:	3000      	movi      	r0, 0
  2a:	2800      	subi      	r0, 1
  2c:	783c      	jmp      	r15
  2e:	ea02b000 	movi      	r2, 45056
  32:	3abe      	bseti      	r2, 30
  34:	9260      	ld.w      	r3, (r2, 0x0)
  36:	ec630004 	ori      	r3, r3, 4
  3a:	07ea      	br      	0xe	// e <ah_tdma2_set_mode+0xe>
  3c:	3941      	cmpnei      	r1, 1
  3e:	0bf5      	bt      	0x28	// 28 <ah_tdma2_set_mode+0x28>
  40:	ea02b000 	movi      	r2, 45056
  44:	3abe      	bseti      	r2, 30
  46:	9260      	ld.w      	r3, (r2, 0x0)
  48:	ec630010 	ori      	r3, r3, 16
  4c:	07e9      	br      	0x1e	// 1e <ah_tdma2_set_mode+0x1e>

Disassembly of section .text.ah_tdma2_enable_irq:

00000000 <ah_tdma2_enable_irq>:
   0:	ea02b000 	movi      	r2, 45056
   4:	3abe      	bseti      	r2, 30
   6:	3000      	movi      	r0, 0
   8:	9260      	ld.w      	r3, (r2, 0x0)
   a:	ec630008 	ori      	r3, r3, 8
   e:	b260      	st.w      	r3, (r2, 0x0)
  10:	783c      	jmp      	r15

Disassembly of section .text.ah_tdma2_set_buff:

00000000 <ah_tdma2_set_buff>:
   0:	c6605023 	bmaski      	r3, 20
   4:	644c      	cmphs      	r3, r1
   6:	0c08      	bf      	0x16	// 16 <ah_tdma2_set_buff+0x16>
   8:	ea03b000 	movi      	r3, 45056
   c:	3bbe      	bseti      	r3, 30
   e:	b302      	st.w      	r0, (r3, 0x8)
  10:	b323      	st.w      	r1, (r3, 0xc)
  12:	3000      	movi      	r0, 0
  14:	783c      	jmp      	r15
  16:	3000      	movi      	r0, 0
  18:	2800      	subi      	r0, 1
  1a:	07fd      	br      	0x14	// 14 <ah_tdma2_set_buff+0x14>

Disassembly of section .text.ah_tdma2_set_trig_len:

00000000 <ah_tdma2_set_trig_len>:
   0:	c6605023 	bmaski      	r3, 20
   4:	640c      	cmphs      	r3, r0
   6:	0c07      	bf      	0x14	// 14 <ah_tdma2_set_trig_len+0x14>
   8:	ea03b000 	movi      	r3, 45056
   c:	3bbe      	bseti      	r3, 30
   e:	b305      	st.w      	r0, (r3, 0x14)
  10:	3000      	movi      	r0, 0
  12:	783c      	jmp      	r15
  14:	3000      	movi      	r0, 0
  16:	2800      	subi      	r0, 1
  18:	07fd      	br      	0x12	// 12 <ah_tdma2_set_trig_len+0x12>

Disassembly of section .text.ah_tdma2_start:

00000000 <ah_tdma2_start>:
   0:	ea02b000 	movi      	r2, 45056
   4:	3abe      	bseti      	r2, 30
   6:	3000      	movi      	r0, 0
   8:	9260      	ld.w      	r3, (r2, 0x0)
   a:	ec630001 	ori      	r3, r3, 1
   e:	b260      	st.w      	r3, (r2, 0x0)
  10:	783c      	jmp      	r15

Disassembly of section .text.ah_tdma2_abort:

00000000 <ah_tdma2_abort>:
   0:	ea02b000 	movi      	r2, 45056
   4:	3abe      	bseti      	r2, 30
   6:	3000      	movi      	r0, 0
   8:	9260      	ld.w      	r3, (r2, 0x0)
   a:	ec630002 	ori      	r3, r3, 2
   e:	b260      	st.w      	r3, (r2, 0x0)
  10:	783c      	jmp      	r15

Disassembly of section .text.ah_tdma2_get_pd:

00000000 <ah_tdma2_get_pd>:
   0:	ea03b000 	movi      	r3, 45056
   4:	3bbe      	bseti      	r3, 30
   6:	9301      	ld.w      	r0, (r3, 0x4)
   8:	e4002001 	andi      	r0, r0, 1
   c:	783c      	jmp      	r15

Disassembly of section .text.ah_tdma2_clear_pd:

00000000 <ah_tdma2_clear_pd>:
   0:	ea02b000 	movi      	r2, 45056
   4:	3abe      	bseti      	r2, 30
   6:	3000      	movi      	r0, 0
   8:	9261      	ld.w      	r3, (r2, 0x4)
   a:	ec630001 	ori      	r3, r3, 1
   e:	b261      	st.w      	r3, (r2, 0x4)
  10:	783c      	jmp      	r15
