
disasm/libcore/obj/usb11_hgusb11_base.o:     file format elf32-csky-little


Disassembly of section .text.hgusb11_switch_otg:

00000000 <hgusb11_switch_otg>:
   0:	9043      	ld.w      	r2, (r0, 0xc)
   2:	3101      	movi      	r1, 1
   4:	dc2220c0 	st.w      	r1, (r2, 0x300)
   8:	d86220c3 	ld.w      	r3, (r2, 0x30c)
   c:	ea0cfffe 	movi      	r12, 65534
  10:	6f32      	nor      	r12, r12
  12:	68f0      	and      	r3, r12
  14:	ec630d9a 	ori      	r3, r3, 3482
  18:	dc6220c3 	st.w      	r3, (r2, 0x30c)
  1c:	3300      	movi      	r3, 0
  1e:	dc2000d8 	st.b      	r1, (r0, 0xd8)
  22:	dc6000d9 	st.b      	r3, (r0, 0xd9)
  26:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_switch_host:

00000000 <hgusb11_switch_host>:
   0:	9043      	ld.w      	r2, (r0, 0xc)
   2:	3301      	movi      	r3, 1
   4:	dc6220c0 	st.w      	r3, (r2, 0x300)
   8:	d86220c3 	ld.w      	r3, (r2, 0x30c)
   c:	ea01fffe 	movi      	r1, 65534
  10:	6c46      	nor      	r1, r1
  12:	68c4      	and      	r3, r1
  14:	ec630df2 	ori      	r3, r3, 3570
  18:	dc6220c3 	st.w      	r3, (r2, 0x30c)
  1c:	3300      	movi      	r3, 0
  1e:	dc6000d8 	st.b      	r3, (r0, 0xd8)
  22:	dc6000d9 	st.b      	r3, (r0, 0xd9)
  26:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_switch_stable_host:

00000000 <hgusb11_switch_stable_host>:
   0:	9043      	ld.w      	r2, (r0, 0xc)
   2:	3301      	movi      	r3, 1
   4:	dc6220c0 	st.w      	r3, (r2, 0x300)
   8:	d86220c3 	ld.w      	r3, (r2, 0x30c)
   c:	ea01fffe 	movi      	r1, 65534
  10:	6c46      	nor      	r1, r1
  12:	68c4      	and      	r3, r1
  14:	ec630df2 	ori      	r3, r3, 3570
  18:	dc6220c3 	st.w      	r3, (r2, 0x30c)
  1c:	3302      	movi      	r3, 2
  1e:	dc6000d8 	st.b      	r3, (r0, 0xd8)
  22:	3300      	movi      	r3, 0
  24:	dc6000d9 	st.b      	r3, (r0, 0xd9)
  28:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_switch_stable_device:

00000000 <hgusb11_switch_stable_device>:
   0:	9043      	ld.w      	r2, (r0, 0xc)
   2:	3301      	movi      	r3, 1
   4:	dc6220c0 	st.w      	r3, (r2, 0x300)
   8:	d86220c3 	ld.w      	r3, (r2, 0x30c)
   c:	ea01fffe 	movi      	r1, 65534
  10:	6c46      	nor      	r1, r1
  12:	68c4      	and      	r3, r1
  14:	ec630d96 	ori      	r3, r3, 3478
  18:	dc6220c3 	st.w      	r3, (r2, 0x30c)
  1c:	3303      	movi      	r3, 3
  1e:	dc6000d8 	st.b      	r3, (r0, 0xd8)
  22:	3300      	movi      	r3, 0
  24:	dc6000d9 	st.b      	r3, (r0, 0xd9)
  28:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_switch_stable_otg:

00000000 <hgusb11_switch_stable_otg>:
   0:	9043      	ld.w      	r2, (r0, 0xc)
   2:	3301      	movi      	r3, 1
   4:	dc6220c0 	st.w      	r3, (r2, 0x300)
   8:	d86220c3 	ld.w      	r3, (r2, 0x30c)
   c:	ea01fffe 	movi      	r1, 65534
  10:	6c46      	nor      	r1, r1
  12:	68c4      	and      	r3, r1
  14:	ec630d9a 	ori      	r3, r3, 3482
  18:	dc6220c3 	st.w      	r3, (r2, 0x30c)
  1c:	3303      	movi      	r3, 3
  1e:	dc6000d8 	st.b      	r3, (r0, 0xd8)
  22:	3300      	movi      	r3, 0
  24:	dc6000d9 	st.b      	r3, (r0, 0xd9)
  28:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_connected_do:

00000000 <hgusb11_connected_do>:
   0:	14d1      	push      	r4, r15
   2:	d86000d9 	ld.b      	r3, (r0, 0xd9)
   6:	2300      	addi      	r3, 1
   8:	dc6000d9 	st.b      	r3, (r0, 0xd9)
   c:	d86000d8 	ld.b      	r3, (r0, 0xd8)
  10:	3b41      	cmpnei      	r3, 1
  12:	0c23      	bf      	0x58	// 58 <hgusb11_connected_do+0x58>
  14:	3b40      	cmpnei      	r3, 0
  16:	0c0a      	bf      	0x2a	// 2a <hgusb11_connected_do+0x2a>
  18:	3b42      	cmpnei      	r3, 2
  1a:	0c05      	bf      	0x24	// 24 <hgusb11_connected_do+0x24>
  1c:	3b43      	cmpnei      	r3, 3
  1e:	0c1a      	bf      	0x52	// 52 <hgusb11_connected_do+0x52>
  20:	3000      	movi      	r0, 0
  22:	040f      	br      	0x40	// 40 <hgusb11_connected_do+0x40>
  24:	3300      	movi      	r3, 0
  26:	dc6000d9 	st.b      	r3, (r0, 0xd9)
  2a:	9063      	ld.w      	r3, (r0, 0xc)
  2c:	d88320c1 	ld.w      	r4, (r3, 0x304)
  30:	e4842002 	andi      	r4, r4, 2
  34:	e9040007 	bez      	r4, 0x42	// 42 <hgusb11_connected_do+0x42>
  38:	3300      	movi      	r3, 0
  3a:	dc6000d9 	st.b      	r3, (r0, 0xd9)
  3e:	3002      	movi      	r0, 2
  40:	1491      	pop      	r4, r15
  42:	d86000d9 	ld.b      	r3, (r0, 0xd9)
  46:	eb030045 	cmphsi      	r3, 70
  4a:	0feb      	bf      	0x20	// 20 <hgusb11_connected_do+0x20>
  4c:	e0000000 	bsr      	0x0	// 0 <hgusb11_connected_do>
  50:	07e8      	br      	0x20	// 20 <hgusb11_connected_do+0x20>
  52:	3300      	movi      	r3, 0
  54:	dc6000d9 	st.b      	r3, (r0, 0xd9)
  58:	9063      	ld.w      	r3, (r0, 0xc)
  5a:	d86320c1 	ld.w      	r3, (r3, 0x304)
  5e:	e4632004 	andi      	r3, r3, 4
  62:	e9230006 	bnez      	r3, 0x6e	// 6e <hgusb11_connected_do+0x6e>
  66:	dc6000d9 	st.b      	r3, (r0, 0xd9)
  6a:	3001      	movi      	r0, 1
  6c:	07ea      	br      	0x40	// 40 <hgusb11_connected_do+0x40>
  6e:	d86000d9 	ld.b      	r3, (r0, 0xd9)
  72:	3b09      	cmphsi      	r3, 10
  74:	0fd6      	bf      	0x20	// 20 <hgusb11_connected_do+0x20>
  76:	e0000000 	bsr      	0x0	// 0 <hgusb11_connected_do>
  7a:	07d3      	br      	0x20	// 20 <hgusb11_connected_do+0x20>

Disassembly of section .text.hgusb11_connected:

00000000 <hgusb11_connected>:
   0:	14d0      	push      	r15
   2:	d86000da 	ld.b      	r3, (r0, 0xda)
   6:	e903000e 	bez      	r3, 0x22	// 22 <hgusb11_connected+0x22>
   a:	2b00      	subi      	r3, 1
   c:	dc6000da 	st.b      	r3, (r0, 0xda)
  10:	d86000d8 	ld.b      	r3, (r0, 0xd8)
  14:	3b42      	cmpnei      	r3, 2
  16:	0c09      	bf      	0x28	// 28 <hgusb11_connected+0x28>
  18:	3b43      	cmpnei      	r3, 3
  1a:	0c09      	bf      	0x2c	// 2c <hgusb11_connected+0x2c>
  1c:	3300      	movi      	r3, 0
  1e:	dc6000da 	st.b      	r3, (r0, 0xda)
  22:	e0000000 	bsr      	0x0	// 0 <hgusb11_connected>
  26:	6cc3      	mov      	r3, r0
  28:	6c0f      	mov      	r0, r3
  2a:	1490      	pop      	r15
  2c:	3301      	movi      	r3, 1
  2e:	07fd      	br      	0x28	// 28 <hgusb11_connected+0x28>

Disassembly of section .text.hgusb11_intr_dis:

00000000 <hgusb11_intr_dis>:
   0:	9063      	ld.w      	r3, (r0, 0xc)
   2:	3200      	movi      	r2, 0
   4:	a34b      	st.b      	r2, (r3, 0xb)
   6:	a347      	st.b      	r2, (r3, 0x7)
   8:	a348      	st.b      	r2, (r3, 0x8)
   a:	a349      	st.b      	r2, (r3, 0x9)
   c:	a34a      	st.b      	r2, (r3, 0xa)
   e:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_suspend:

00000000 <hgusb11_suspend>:
   0:	9043      	ld.w      	r2, (r0, 0xc)
   2:	8261      	ld.b      	r3, (r2, 0x1)
   4:	ec630002 	ori      	r3, r3, 2
   8:	a261      	st.b      	r3, (r2, 0x1)
   a:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_resume:

00000000 <hgusb11_resume>:
   0:	9043      	ld.w      	r2, (r0, 0xc)
   2:	8261      	ld.b      	r3, (r2, 0x1)
   4:	74cc      	zextb      	r3, r3
   6:	e42320fd 	andi      	r1, r3, 253
   a:	ec210004 	ori      	r1, r1, 4
   e:	e46320f9 	andi      	r3, r3, 249
  12:	a221      	st.b      	r1, (r2, 0x1)
  14:	a261      	st.b      	r3, (r2, 0x1)
  16:	783c      	jmp      	r15

Disassembly of section .text.hgusb11_init_globle:

00000000 <hgusb11_init_globle>:
   0:	14d0      	push      	r15
   2:	9063      	ld.w      	r3, (r0, 0xc)
   4:	3100      	movi      	r1, 0
   6:	dc2320c0 	st.w      	r1, (r3, 0x300)
   a:	290f      	subi      	r1, 16
   c:	dc2320c1 	st.w      	r1, (r3, 0x304)
  10:	d82320c1 	ld.w      	r1, (r3, 0x304)
  14:	3995      	bclri      	r1, 21
  16:	dc2320c1 	st.w      	r1, (r3, 0x304)
  1a:	3180      	movi      	r1, 128
  1c:	4126      	lsli      	r1, r1, 6
  1e:	ea0c0001 	movi      	r12, 1
  22:	dc2320c2 	st.w      	r1, (r3, 0x308)
  26:	dd8320c0 	st.w      	r12, (r3, 0x300)
  2a:	d8200112 	ld.b      	r1, (r0, 0x112)
  2e:	e901000f 	bez      	r1, 0x4c	// 4c <hgusb11_init_globle+0x4c>
  32:	ea01200f 	movi      	r1, 8207
  36:	dc2320c2 	st.w      	r1, (r3, 0x308)
  3a:	ea010c13 	movi      	r1, 3091
  3e:	dc2320c3 	st.w      	r1, (r3, 0x30c)
  42:	dd800112 	st.b      	r12, (r0, 0x112)
  46:	e0000000 	bsr      	0x0	// 0 <hgusb11_init_globle>
  4a:	1490      	pop      	r15
  4c:	ea020df1 	movi      	r2, 3569
  50:	dc2320c2 	st.w      	r1, (r3, 0x308)
  54:	dc4320c3 	st.w      	r2, (r3, 0x30c)
  58:	834f      	ld.b      	r2, (r3, 0xf)
  5a:	ec420001 	ori      	r2, r2, 1
  5e:	a34f      	st.b      	r2, (r3, 0xf)
  60:	320e      	movi      	r2, 14
  62:	dc4320c2 	st.w      	r2, (r3, 0x308)
  66:	836f      	ld.b      	r3, (r3, 0xf)
  68:	e0000000 	bsr      	0x0	// 0 <hgusb11_init_globle>
  6c:	07ef      	br      	0x4a	// 4a <hgusb11_init_globle+0x4a>
