
libs\obj\liblmac\mars_lmac_cfg.o:     file format elf32-csky-little


Disassembly of section .text.lmac_cfg_init:

00000000 <lmac_cfg_init>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	ea84011e 	lrw	r4, 0x0	// regs: r4=0x0
   8:	3380      	movi	r3, 128	// regs: r3=0x80
   a:	4365      	lsli	r3, r3, 5	// regs: r3=0x1000
   c:	b860      	st.w	r3, (r14, 0x0)	// local_4 = 0x1000
   e:	b472      	st.w	r3, (r4, 0x48)	// *(0x48) = 0x1000
  10:	3382      	movi	r3, 130	// regs: r3=0x82
  12:	4364      	lsli	r3, r3, 4	// regs: r3=0x820
  14:	b473      	st.w	r3, (r4, 0x4c)	// *(0x4c) = 0x820
  16:	300f      	movi	r0, 15	// regs: r0=0xf
  18:	d864051a 	ld.b	r3, (r4, 0x51a)	// regs: r3=*(0x51a)
  1c:	c4605c60 	ins	r3, r0, 3, 0
  20:	dc64051a 	st.b	r3, (r4, 0x51a)	// *(0x51a) = *(0x51a)
  24:	300d      	movi	r0, 13	// regs: r0=0xd
  26:	d8640516 	ld.b	r3, (r4, 0x516)	// regs: r3=*(0x516)
  2a:	c4605c60 	ins	r3, r0, 3, 0
  2e:	dc640516 	st.b	r3, (r4, 0x516)	// *(0x516) = *(0x516)
  32:	ea0b000b 	movi	r11, 11	// regs: r11=0xb
  36:	d864051e 	ld.b	r3, (r4, 0x51e)	// regs: r3=*(0x51e)
  3a:	c46b5c60 	ins	r3, r11, 3, 0
  3e:	dc64051e 	st.b	r3, (r4, 0x51e)	// *(0x51e) = *(0x51e)
  42:	3009      	movi	r0, 9	// regs: r0=0x9
  44:	d8640522 	ld.b	r3, (r4, 0x522)	// regs: r3=*(0x522)
  48:	3500      	movi	r5, 0	// regs: r5=0x0
  4a:	ea0a000f 	movi	r10, 15	// regs: r10=0xf
  4e:	3603      	movi	r6, 3	// regs: r6=0x3
  50:	3207      	movi	r2, 7	// regs: r2=0x7
  52:	311f      	movi	r1, 31	// regs: r1=0x1f
  54:	ea080002 	movi	r8, 2	// regs: r8=0x2
  58:	c4605c60 	ins	r3, r0, 3, 0
  5c:	ac56      	st.h	r2, (r4, 0x2c)	// *(0x2c) = 0x7
  5e:	ac5a      	st.h	r2, (r4, 0x34)	// *(0x34) = 0x7
  60:	ac3d      	st.h	r1, (r4, 0x3a)	// *(0x3a) = 0x1f
  62:	ac3c      	st.h	r1, (r4, 0x38)	// *(0x38) = 0x1f
  64:	ac5f      	st.h	r2, (r4, 0x3e)	// *(0x3e) = 0x7
  66:	a45d      	st.b	r2, (r4, 0x1d)	// *(0x1d) = 0x7
  68:	dd04001e 	st.b	r8, (r4, 0x1e)	// *(0x1e) = 0x2
  6c:	dd04001f 	st.b	r8, (r4, 0x1f)	// *(0x1f) = 0x2
  70:	dc640522 	st.b	r3, (r4, 0x522)	// *(0x522) = *(0x522)
  74:	d8e4051b 	ld.b	r7, (r4, 0x51b)	// regs: r7=*(0x51b)
  78:	3306      	movi	r3, 6	// regs: r3=0x6
  7a:	dca420d3 	st.w	r5, (r4, 0x34c)	// *(0x34c) = 0x0
  7e:	dca420d4 	st.w	r5, (r4, 0x350)	// *(0x350) = 0x0
  82:	dd441015 	st.h	r10, (r4, 0x2a)	// *(0x2a) = 0xf
  86:	dd441014 	st.h	r10, (r4, 0x28)	// *(0x28) = 0xf
  8a:	acd7      	st.h	r6, (r4, 0x2e)	// *(0x2e) = 0x3
  8c:	dd441019 	st.h	r10, (r4, 0x32)	// *(0x32) = 0xf
  90:	dd441018 	st.h	r10, (r4, 0x30)	// *(0x30) = 0xf
  94:	acdb      	st.h	r6, (r4, 0x36)	// *(0x36) = 0x3
  96:	dd44101e 	st.h	r10, (r4, 0x3c)	// *(0x3c) = 0xf
  9a:	a4dc      	st.b	r6, (r4, 0x1c)	// *(0x1c) = 0x3
  9c:	b4b1      	st.w	r5, (r4, 0x44)	// *(0x44) = 0x0
  9e:	b4b0      	st.w	r5, (r4, 0x40)	// *(0x40) = 0x0
  a0:	ea090004 	movi	r9, 4	// regs: r9=0x4
  a4:	d9a40517 	ld.b	r13, (r4, 0x517)	// regs: r13=*(0x517)
  a8:	d8040523 	ld.b	r0, (r4, 0x523)	// regs: r0=*(0x523)
  ac:	c4e35c60 	ins	r7, r3, 3, 0
  b0:	c5a35c60 	ins	r13, r3, 3, 0
  b4:	c4095c60 	ins	r0, r9, 3, 0
  b8:	3305      	movi	r3, 5	// regs: r3=0x5
  ba:	ea090007 	movi	r9, 7	// regs: r9=0x7
  be:	c4035c64 	ins	r0, r3, 7, 4
  c2:	d984051f 	ld.b	r12, (r4, 0x51f)	// regs: r12=*(0x51f)
  c6:	c5a95c64 	ins	r13, r9, 7, 4
  ca:	dc040523 	st.b	r0, (r4, 0x523)	// *(0x523) = *(0x523)
  ce:	3009      	movi	r0, 9	// regs: r0=0x9
  d0:	dda40517 	st.b	r13, (r4, 0x517)	// *(0x517) = *(0x517)
  d4:	dc040084 	st.b	r0, (r4, 0x84)	// *(0x84) = 0x9
  d8:	c5835c60 	ins	r12, r3, 3, 0
  dc:	307f      	movi	r0, 127	// regs: r0=0x7f
  de:	ea0d0006 	movi	r13, 6	// regs: r13=0x6
  e2:	c58d5c64 	ins	r12, r13, 7, 4
  e6:	dc041051 	st.h	r0, (r4, 0xa2)	// *(0xa2) = 0x7f
  ea:	dc041050 	st.h	r0, (r4, 0xa0)	// *(0xa0) = 0x7f
  ee:	dc041052 	st.h	r0, (r4, 0xa4)	// *(0xa4) = 0x7f
  f2:	ea0d0032 	movi	r13, 50	// regs: r13=0x32
  f6:	303f      	movi	r0, 63	// regs: r0=0x3f
  f8:	dc041053 	st.h	r0, (r4, 0xa6)	// *(0xa6) = 0x3f
  fc:	dd040867 	st.b	r8, (r4, 0x867)	// *(0x867) = 0x2
 100:	dda41197 	st.h	r13, (r4, 0x32e)	// *(0x32e) = 0x32
 104:	300a      	movi	r0, 10	// regs: r0=0xa
 106:	d9a411b0 	ld.h	r13, (r4, 0x360)	// regs: r13=*(0x360)
 10a:	ea0801ff 	movi	r8, 511	// regs: r8=0x1ff
 10e:	c4e95c64 	ins	r7, r9, 7, 4
 112:	dd84051f 	st.b	r12, (r4, 0x51f)	// *(0x51f) = *(0x51f)
 116:	dd640085 	st.b	r11, (r4, 0x85)	// *(0x85) = 0xb
 11a:	dd24104b 	st.h	r9, (r4, 0x96)	// *(0x96) = 0x7
 11e:	dc04030c 	st.b	r0, (r4, 0x30c)	// *(0x30c) = 0xa
 122:	e5251000 	subi	r9, r5, 1	// regs: r9=0xffffffff
 126:	ea0c0014 	movi	r12, 20	// regs: r12=0x14
 12a:	ea0b0028 	movi	r11, 40	// regs: r11=0x28
 12e:	c5a85d01 	ins	r13, r8, 9, 1
 132:	301e      	movi	r0, 30	// regs: r0=0x1e
 134:	dce4051b 	st.b	r7, (r4, 0x51b)	// *(0x51b) = *(0x51b)
 138:	dc440086 	st.b	r2, (r4, 0x86)	// *(0x86) = 0x7
 13c:	dc640087 	st.b	r3, (r4, 0x87)	// *(0x87) = 0x5
 140:	dc241049 	st.h	r1, (r4, 0x92)	// *(0x92) = 0x1f
 144:	dc241048 	st.h	r1, (r4, 0x90)	// *(0x90) = 0x1f
 148:	dd240864 	st.b	r9, (r4, 0x864)	// *(0x864) = 0xffffffff
 14c:	dd84030d 	st.b	r12, (r4, 0x30d)	// *(0x30d) = 0x14
 150:	dc04030e 	st.b	r0, (r4, 0x30e)	// *(0x30e) = 0x1e
 154:	dd64030f 	st.b	r11, (r4, 0x30f)	// *(0x30f) = 0x28
 158:	d8040310 	ld.b	r0, (r4, 0x310)	// regs: r0=*(0x310)
 15c:	dd44104a 	st.h	r10, (r4, 0x94)	// *(0x94) = 0xf
 160:	dca4202f 	st.w	r5, (r4, 0xbc)	// *(0xbc) = 0x0
 164:	dcc40308 	st.b	r6, (r4, 0x308)	// *(0x308) = 0x3
 168:	dca40866 	st.b	r5, (r4, 0x866)	// *(0x866) = 0x0
 16c:	dcc40316 	st.b	r6, (r4, 0x316)	// *(0x316) = 0x3
 170:	dda411b0 	st.h	r13, (r4, 0x360)	// *(0x360) = *(0x360)
 174:	dc440313 	st.b	r2, (r4, 0x313)	// *(0x313) = 0x7
 178:	320a      	movi	r2, 10	// regs: r2=0xa
 17a:	dc4411de 	st.h	r2, (r4, 0x3bc)	// *(0x3bc) = 0xa
 17e:	3264      	movi	r2, 100	// regs: r2=0x64
 180:	dc4411df 	st.h	r2, (r4, 0x3be)	// *(0x3be) = 0x64
 184:	ea224001 	movih	r2, 16385	// regs: r2=(0x4001 << 0x10)
 188:	3701      	movi	r7, 1	// regs: r7=0x1
 18a:	b441      	st.w	r2, (r4, 0x4)	// *(0x4) = (0x4001 << 0x10)
 18c:	d8440361 	ld.b	r2, (r4, 0x361)	// regs: r2=*(0x361)
 190:	c4475c02 	ins	r2, r7, 2, 2
 194:	dd840317 	st.b	r12, (r4, 0x317)	// *(0x317) = 0x14
 198:	c4455c03 	ins	r2, r5, 3, 3
 19c:	d98403df 	ld.b	r12, (r4, 0x3df)	// regs: r12=*(0x3df)
 1a0:	dc440361 	st.b	r2, (r4, 0x361)	// *(0x361) = *(0x361)
 1a4:	c5855c03 	ins	r12, r5, 3, 3
 1a8:	d84420d8 	ld.w	r2, (r4, 0x360)	// regs: r2=*(0x360)
 1ac:	dd8403df 	st.b	r12, (r4, 0x3df)	// *(0x3df) = *(0x3df)
 1b0:	ea0c0016 	movi	r12, 22	// regs: r12=0x16
 1b4:	c44c5cec 	ins	r2, r12, 19, 12
 1b8:	dc4420d8 	st.w	r2, (r4, 0x360)	// *(0x360) = *(0x360)
 1bc:	3200      	movi	r2, 0	// regs: r2=0x0
 1be:	2a3b      	subi	r2, 60	// regs: r2=0xffffffc4
 1c0:	dc44031e 	st.b	r2, (r4, 0x31e)	// *(0x31e) = 0xffffffc4
 1c4:	d84411b1 	ld.h	r2, (r4, 0x362)	// regs: r2=*(0x362)
 1c8:	c4435ce4 	ins	r2, r3, 11, 4
 1cc:	dc4411b1 	st.h	r2, (r4, 0x362)	// *(0x362) = *(0x362)
 1d0:	3200      	movi	r2, 0	// regs: r2=0x0
 1d2:	2a53      	subi	r2, 84	// regs: r2=0xffffffac
 1d4:	dc44031f 	st.b	r2, (r4, 0x31f)	// *(0x31f) = 0xffffffac
 1d8:	3200      	movi	r2, 0	// regs: r2=0x0
 1da:	2a56      	subi	r2, 87	// regs: r2=0xffffffa9
 1dc:	dc440320 	st.b	r2, (r4, 0x320)	// *(0x320) = 0xffffffa9
 1e0:	320a      	movi	r2, 10	// regs: r2=0xa
 1e2:	dc4420d7 	st.w	r2, (r4, 0x35c)	// *(0x35c) = 0xa
 1e6:	d8440336 	ld.b	r2, (r4, 0x336)	// regs: r2=*(0x336)
 1ea:	c4475c00 	ins	r2, r7, 0, 0
 1ee:	dc440336 	st.b	r2, (r4, 0x336)	// *(0x336) = *(0x336)
 1f2:	d84411b6 	ld.h	r2, (r4, 0x36c)	// regs: r2=*(0x36c)
 1f6:	c4435c85 	ins	r2, r3, 9, 5
 1fa:	dc4411b6 	st.h	r2, (r4, 0x36c)	// *(0x36c) = *(0x36c)
 1fe:	c4435c80 	ins	r2, r3, 4, 0
 202:	dc44036c 	st.b	r2, (r4, 0x36c)	// *(0x36c) = *(0x36c)
 206:	9840      	ld.w	r2, (r14, 0x0)	// regs: r2=local_4
 208:	dc4420dd 	st.w	r2, (r4, 0x374)	// *(0x374) = local_4
 20c:	ea0800fa 	movi	r8, 250	// regs: r8=0xfa
 210:	3264      	movi	r2, 100	// regs: r2=0x64
 212:	ea0d0010 	movi	r13, 16	// regs: r13=0x10
 216:	721c      	lsl	r8, r7
 218:	dc240312 	st.b	r1, (r4, 0x312)	// *(0x312) = 0x1f
 21c:	333c      	movi	r3, 60	// regs: r3=0x3c
 21e:	3114      	movi	r1, 20	// regs: r1=0x14
 220:	dc4420e5 	st.w	r2, (r4, 0x394)	// *(0x394) = 0x64
 224:	ea020bb8 	movi	r2, 3000	// regs: r2=0xbb8
 228:	dda40315 	st.b	r13, (r4, 0x315)	// *(0x315) = 0x10
 22c:	b426      	st.w	r1, (r4, 0x18)	// *(0x18) = 0x14
 22e:	dd24032a 	st.b	r9, (r4, 0x32a)	// *(0x32a) = 0xffffffff
 232:	dc640348 	st.b	r3, (r4, 0x348)	// *(0x348) = 0x3c
 236:	dc2411bd 	st.h	r1, (r4, 0x37a)	// *(0x37a) = 0x14
 23a:	dcc40309 	st.b	r6, (r4, 0x309)	// *(0x309) = 0x3
 23e:	dd0420e2 	st.w	r8, (r4, 0x388)	// *(0x388) = 0xfa
 242:	dc4420e4 	st.w	r2, (r4, 0x390)	// *(0x390) = 0xbb8
 246:	ea022710 	movi	r2, 10000	// regs: r2=0x2710
 24a:	dc4420e3 	st.w	r2, (r4, 0x38c)	// *(0x38c) = 0x2710
 24e:	32fa      	movi	r2, 250	// regs: r2=0xfa
 250:	4243      	lsli	r2, r2, 3	// regs: r2=0x7d0
 252:	dc4420e7 	st.w	r2, (r4, 0x39c)	// *(0x39c) = 0x7d0
 256:	ea02cd14 	movi	r2, 52500	// regs: r2=0xcd14
 25a:	c4624902 	rotli	r2, r2, 3	// regs: r2=rotl(0xcd14, 0x3)
 25e:	dc4420eb 	st.w	r2, (r4, 0x3ac)	// *(0x3ac) = rotl(0xcd14, 0x3)
 262:	ea021770 	movi	r2, 6000	// regs: r2=0x1770
 266:	dc4420ec 	st.w	r2, (r4, 0x3b0)	// *(0x3b0) = 0x1770
 26a:	d844037c 	ld.b	r2, (r4, 0x37c)	// regs: r2=*(0x37c)
 26e:	d824037d 	ld.b	r1, (r4, 0x37d)	// regs: r1=*(0x37d)
 272:	c4475c01 	ins	r2, r7, 1, 1
 276:	c4275c02 	ins	r1, r7, 2, 2
 27a:	c4475c00 	ins	r2, r7, 0, 0
 27e:	dc24037d 	st.b	r1, (r4, 0x37d)	// *(0x37d) = *(0x37d)
 282:	dc44037c 	st.b	r2, (r4, 0x37c)	// *(0x37c) = *(0x37c)
 286:	d82411be 	ld.h	r1, (r4, 0x37c)	// regs: r1=*(0x37c)
 28a:	ea0c0006 	movi	r12, 6	// regs: r12=0x6
 28e:	dc64031c 	st.b	r3, (r4, 0x31c)	// *(0x31c) = 0x3c
 292:	d8640360 	ld.b	r3, (r4, 0x360)	// regs: r3=*(0x360)
 296:	c42c5ce2 	ins	r1, r12, 9, 2
 29a:	c4655c00 	ins	r3, r5, 0, 0
 29e:	dc2411be 	st.h	r1, (r4, 0x37c)	// *(0x37c) = *(0x37c)
 2a2:	dc640360 	st.b	r3, (r4, 0x360)	// *(0x360) = *(0x360)
 2a6:	3332      	movi	r3, 50	// regs: r3=0x32
 2a8:	dc640365 	st.b	r3, (r4, 0x365)	// *(0x365) = 0x32
 2ac:	d864037d 	ld.b	r3, (r4, 0x37d)	// regs: r3=*(0x37d)
 2b0:	c4655c04 	ins	r3, r5, 4, 4
 2b4:	dc64037d 	st.b	r3, (r4, 0x37d)	// *(0x37d) = *(0x37d)
 2b8:	d86420df 	ld.w	r3, (r4, 0x37c)	// regs: r3=*(0x37c)
 2bc:	c46c5cad 	ins	r3, r12, 18, 13
 2c0:	dc6420df 	st.w	r3, (r4, 0x37c)	// *(0x37c) = *(0x37c)
 2c4:	d864037e 	ld.b	r3, (r4, 0x37e)	// regs: r3=*(0x37e)
 2c8:	c4655c03 	ins	r3, r5, 3, 3
 2cc:	dc64037e 	st.b	r3, (r4, 0x37e)	// *(0x37e) = *(0x37e)
 2d0:	d86411bf 	ld.h	r3, (r4, 0x37e)	// regs: r3=*(0x37e)
 2d4:	3104      	movi	r1, 4	// regs: r1=0x4
 2d6:	c4615ca4 	ins	r3, r1, 9, 4
 2da:	dc6411bf 	st.h	r3, (r4, 0x37e)	// *(0x37e) = *(0x37e)
 2de:	d864037f 	ld.b	r3, (r4, 0x37f)	// regs: r3=*(0x37f)
 2e2:	e46320fb 	andi	r3, r3, 251	// regs: r3=(*(0x37f) & 0xfb)
 2e6:	c4675c03 	ins	r3, r7, 3, 3
 2ea:	dd64031d 	st.b	r11, (r4, 0x31d)	// *(0x31d) = 0x28
 2ee:	dc64037f 	st.b	r3, (r4, 0x37f)	// *(0x37f) = (*(0x37f) & 0xfb)
 2f2:	3102      	movi	r1, 2	// regs: r1=0x2
 2f4:	d8640860 	ld.b	r3, (r4, 0x860)	// regs: r3=*(0x860)
 2f8:	ea8b0062 	lrw	r11, 0x0	// regs: r11=0x0
 2fc:	ea091388 	movi	r9, 5000	// regs: r9=0x1388
 300:	c4615c40 	ins	r3, r1, 2, 0
 304:	d8440338 	ld.b	r2, (r4, 0x338)	// regs: r2=*(0x338)
 308:	dd2420e6 	st.w	r9, (r4, 0x398)	// *(0x398) = 0x1388
 30c:	dd2420e8 	st.w	r9, (r4, 0x3a0)	// *(0x3a0) = 0x1388
 310:	dd0420ed 	st.w	r8, (r4, 0x3b4)	// *(0x3b4) = 0xfa
 314:	dcc40364 	st.b	r6, (r4, 0x364)	// *(0x364) = 0x3
 318:	dc640860 	st.b	r3, (r4, 0x860)	// *(0x860) = *(0x860)
 31c:	d82b0004 	ld.b	r1, (r11, 0x4)	// regs: r1=*(0x4)
 320:	d8640680 	ld.b	r3, (r4, 0x680)	// regs: r3=*(0x680)
 324:	c4615c41 	ins	r3, r1, 3, 1
 328:	dc640680 	st.b	r3, (r4, 0x680)	// *(0x680) = *(0x680)
 32c:	3332      	movi	r3, 50	// regs: r3=0x32
 32e:	dc641196 	st.h	r3, (r4, 0x32c)	// *(0x32c) = 0x32
 332:	d864036d 	ld.b	r3, (r4, 0x36d)	// regs: r3=*(0x36d)
 336:	c4475c00 	ins	r2, r7, 0, 0
 33a:	e46320f3 	andi	r3, r3, 243	// regs: r3=(*(0x36d) & 0xf3)
 33e:	c4655c24 	ins	r3, r5, 5, 4
 342:	e44220fb 	andi	r2, r2, 251	// regs: r2=(*(0x338) & 0xfb)
 346:	dc64036d 	st.b	r3, (r4, 0x36d)	// *(0x36d) = (*(0x36d) & 0xf3)
 34a:	c4455c01 	ins	r2, r5, 1, 1
 34e:	d86420db 	ld.w	r3, (r4, 0x36c)	// regs: r3=*(0x36c)
 352:	dc440338 	st.b	r2, (r4, 0x338)	// *(0x338) = (*(0x338) & 0xfb)
 356:	321b      	movi	r2, 27	// regs: r2=0x1b
 358:	c4625cee 	ins	r3, r2, 21, 14
 35c:	dc6420db 	st.w	r3, (r4, 0x36c)	// *(0x36c) = *(0x36c)
 360:	3396      	movi	r3, 150	// regs: r3=0x96
 362:	c4075c00 	ins	r0, r7, 0, 0
 366:	4361      	lsli	r3, r3, 1	// regs: r3=0x12c
 368:	dc64133b 	st.h	r3, (r4, 0x676)	// *(0x676) = 0x12c
 36c:	c4075c01 	ins	r0, r7, 1, 1
 370:	3300      	movi	r3, 0	// regs: r3=0x0
 372:	2b1d      	subi	r3, 30	// regs: r3=0xffffffe2
 374:	e40020fb 	andi	r0, r0, 251	// regs: r0=(*(0x310) & 0xfb)
 378:	c4055c03 	ins	r0, r5, 3, 3
 37c:	dc640300 	st.b	r3, (r4, 0x300)	// *(0x300) = 0xffffffe2
 380:	320f      	movi	r2, 15	// regs: r2=0xf
 382:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
 386:	c4625c62 	ins	r3, r2, 5, 2
 38a:	dc040310 	st.b	r0, (r4, 0x310)	// *(0x310) = (*(0x310) & 0xfb)
 38e:	e40409ff 	addi	r0, r4, 2560	// regs: r0=0xa00
 392:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = *(0x319)
 396:	dca403e3 	st.b	r5, (r4, 0x3e3)	// *(0x3e3) = 0x0
 39a:	dce403e4 	st.b	r7, (r4, 0x3e4)	// *(0x3e4) = 0x1
 39e:	dca4119a 	st.h	r5, (r4, 0x334)	// *(0x334) = 0x0
 3a2:	e0000000 	bsr	0x0	// <os_mutex_init>; regs: r0=<ret os_mutex_init@0x3a2>, r1=<clobbered>
 3a6:	e46409f7 	addi	r3, r4, 2552	// regs: r3=0x9f8
 3aa:	dc64227e 	st.w	r3, (r4, 0x9f8)	// *(0x9f8) = 0x9f8
 3ae:	dc64227f 	st.w	r3, (r4, 0x9fc)	// *(0x9fc) = 0x9f8
 3b2:	3200      	movi	r2, 0	// regs: r2=0x0
 3b4:	3300      	movi	r3, 0	// regs: r3=0x0
 3b6:	dc4420f0 	st.w	r2, (r4, 0x3c0)	// *(0x3c0) = 0x0
 3ba:	dc6420f1 	st.w	r3, (r4, 0x3c4)	// *(0x3c4) = 0x0
 3be:	dc4420f3 	st.w	r2, (r4, 0x3cc)	// *(0x3cc) = 0x0
 3c2:	dc6420f4 	st.w	r3, (r4, 0x3d0)	// *(0x3d0) = 0x0
 3c6:	d8640338 	ld.b	r3, (r4, 0x338)	// regs: r3=*(0x338)
 3ca:	c4675c03 	ins	r3, r7, 3, 3
 3ce:	dc640338 	st.b	r3, (r4, 0x338)	// *(0x338) = *(0x338)
 3d2:	d86411a5 	ld.h	r3, (r4, 0x34a)	// regs: r3=*(0x34a)
 3d6:	c4685dc1 	ins	r3, r8, 15, 1
 3da:	dc6411a5 	st.h	r3, (r4, 0x34a)	// *(0x34a) = *(0x34a)
 3de:	3240      	movi	r2, 64	// regs: r2=0x40
 3e0:	d8640a63 	ld.b	r3, (r4, 0xa63)	// regs: r3=*(0xa63)
 3e4:	c4625cc0 	ins	r3, r2, 6, 0
 3e8:	dc640a63 	st.b	r3, (r4, 0xa63)	// *(0xa63) = *(0xa63)
 3ec:	d8640310 	ld.b	r3, (r4, 0x310)	// regs: r3=*(0x310)
 3f0:	c4655c05 	ins	r3, r5, 5, 5
 3f4:	dc640310 	st.b	r3, (r4, 0x310)	// *(0x310) = *(0x310)
 3f8:	d8640319 	ld.b	r3, (r4, 0x319)	// regs: r3=*(0x319)
 3fc:	c4655c06 	ins	r3, r5, 6, 6
 400:	dc640319 	st.b	r3, (r4, 0x319)	// *(0x319) = *(0x319)
 404:	3233      	movi	r2, 51	// regs: r2=0x33
 406:	d864031a 	ld.b	r3, (r4, 0x31a)	// regs: r3=*(0x31a)
 40a:	c4625cc1 	ins	r3, r2, 7, 1
 40e:	dc64031a 	st.b	r3, (r4, 0x31a)	// *(0x31a) = *(0x31a)
 412:	d864031b 	ld.b	r3, (r4, 0x31b)	// regs: r3=*(0x31b)
 416:	c4675c00 	ins	r3, r7, 0, 0
 41a:	dc64031b 	st.b	r3, (r4, 0x31b)	// *(0x31b) = *(0x31b)
 41e:	d86b0006 	ld.b	r3, (r11, 0x6)	// regs: r3=*(0x6)
 422:	dc64068e 	st.b	r3, (r4, 0x68e)	// *(0x68e) = *(0x6)
 426:	331e      	movi	r3, 30	// regs: r3=0x1e
 428:	dc6403e1 	st.b	r3, (r4, 0x3e1)	// *(0x3e1) = 0x1e
 42c:	d86403e2 	ld.b	r3, (r4, 0x3e2)	// regs: r3=*(0x3e2)
 430:	c4675c00 	ins	r3, r7, 0, 0
 434:	d84408e1 	ld.b	r2, (r4, 0x8e1)	// regs: r2=*(0x8e1)
 438:	689c      	and	r2, r7	// regs: r2=(*(0x8e1) & 0x1)
 43a:	dca41504 	st.h	r5, (r4, 0xa08)	// *(0xa08) = 0x0
 43e:	dca41506 	st.h	r5, (r4, 0xa0c)	// *(0xa0c) = 0x0
 442:	dca42267 	st.w	r5, (r4, 0x99c)	// *(0x99c) = 0x0
 446:	dd4411e5 	st.h	r10, (r4, 0x3ca)	// *(0x3ca) = 0xf
 44a:	dd4411e4 	st.h	r10, (r4, 0x3c8)	// *(0x3c8) = 0xf
 44e:	dcc40311 	st.b	r6, (r4, 0x311)	// *(0x311) = 0x3
 452:	dca411ee 	st.h	r5, (r4, 0x3dc)	// *(0x3dc) = 0x0
 456:	dd2420f5 	st.w	r9, (r4, 0x3d4)	// *(0x3d4) = 0x1388
 45a:	dc6403e2 	st.b	r3, (r4, 0x3e2)	// *(0x3e2) = *(0x3e2)
 45e:	d8640875 	ld.b	r3, (r4, 0x875)	// regs: r3=*(0x875)
 462:	c4625c02 	ins	r3, r2, 2, 2
 466:	c4625c03 	ins	r3, r2, 3, 3
 46a:	e4040bb7 	addi	r0, r4, 3000	// regs: r0=0xbb8
 46e:	dc640875 	st.b	r3, (r4, 0x875)	// *(0x875) = *(0x875)
 472:	e0000000 	bsr	0x0	// <os_mutex_init>; regs: r0=<ret os_mutex_init@0x472>, r1=<clobbered>
 476:	6c17      	mov	r0, r5	// regs: r0=0x0
 478:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
 47a:	1498      	pop	r4-r11, r15
 47c:	00000000 	.long	0x00000000	// <ah_lmac>
 480:	00000000 	.long	0x00000000	// <module_efuse_info>

Disassembly of section .text.lmac_cfg_cw_param:

00000000 <lmac_cfg_cw_param>: // arg_bytes: 12
   0:	3803      	cmphsi	r0, 4
   2:	0818      	bt	0x32	// if (r0 >= 0x4) goto loc_32;
   4:	ea0c7fff 	movi	r12, 32767	// regs: r12=0x7fff
   8:	eb017fff 	cmphsi	r1, 32768
   c:	c42c0c40 	inct	r1, r12, 0
  10:	1069      	lrw	r3, 0x0	// regs: r3=0x0
  12:	e5a00013 	addi	r13, r0, 20	// regs: r13=(<arg0> + 0x14)
  16:	7445      	zexth	r1, r1	// regs: r1=zext16(<arg1>)
  18:	eb027fff 	cmphsi	r2, 32768
  1c:	d5a30441 	str.h	r1, (r3, r13 << 1)
  20:	c44c0c40 	inct	r2, r12, 0
  24:	e5a0001b 	addi	r13, r0, 28	// regs: r13=(<arg0> + 0x1c)
  28:	2017      	addi	r0, 24	// regs: r0=(<arg0> + 0x18)
  2a:	d5a30442 	str.h	r2, (r3, r13 << 1)
  2e:	d4030441 	str.h	r1, (r3, r0 << 1)
loc_32:
  32:	783c      	jmp	r15	// return;
  34:	0000      	.short	0x0000	// <ah_lmac>
  36:	0000      	.short	0x0000

Disassembly of section .text.lmac_cfg_aifs_param:

00000000 <lmac_cfg_aifs_param>: // arg_bytes: 8
   0:	3803      	cmphsi	r0, 4
   2:	0808      	bt	0x12	// if (r0 >= 0x4) goto loc_12;
   4:	1064      	lrw	r3, 0x0	// regs: r3=0x0
   6:	600c      	addu	r0, r3	// regs: r0=(<arg0> )
   8:	390f      	cmphsi	r1, 16
   a:	330f      	movi	r3, 15	// regs: r3=0xf
   c:	c4230c40 	inct	r1, r3, 0
  10:	a03c      	st.b	r1, (r0, 0x1c)	// *(((<arg0> ) + 0x1c)) = <arg1>
loc_12:
  12:	783c      	jmp	r15	// return;
  14:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_cfg_txop_param:

00000000 <lmac_cfg_txop_param>: // arg_bytes: 8
   0:	3803      	cmphsi	r0, 4
   2:	0808      	bt	0x12	// if (r0 >= 0x4) goto loc_12;
   4:	33fa      	movi	r3, 250	// regs: r3=0xfa
   6:	4362      	lsli	r3, r3, 2	// regs: r3=0x3e8
   8:	7c4c      	mult	r1, r3	// regs: r1=(<arg1> * 0x3e8)
   a:	200f      	addi	r0, 16	// regs: r0=(<arg0> + 0x10)
   c:	1062      	lrw	r3, 0x0	// regs: r3=0x0
   e:	d4030881 	str.w	r1, (r3, r0 << 2)
loc_12:
  12:	783c      	jmp	r15	// return;
  14:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_cfg_set_aid:

00000000 <lmac_cfg_set_aid>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   4:	1095      	lrw	r4, 0x0	// regs: r4=0x0
   6:	6c87      	mov	r2, r1	// regs: r2=<arg1>
   8:	7595      	zexth	r6, r5	// regs: r6=zext16(<arg1>)
   a:	1035      	lrw	r1, 0x0	// regs: r1=0x0
   c:	1015      	lrw	r0, 0x0	// regs: r0=0x0
   e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xe>, r1=<clobbered>
  12:	e4240525 	addi	r1, r4, 1318	// regs: r1=0x526
  16:	6c1b      	mov	r0, r6	// regs: r0=zext16(<arg1>)
  18:	dcc41198 	st.h	r6, (r4, 0x330)	// *(0x330) = zext16(<arg1>)
  1c:	e0000000 	bsr	0x0	// <partial_aid_calc>; regs: r0=<ret partial_aid_calc@0x1c>, r1=<clobbered>
  20:	d8640336 	ld.b	r3, (r4, 0x336)	// regs: r3=*(0x336)
  24:	c4605ca1 	ins	r3, r0, 6, 1
  28:	e4240525 	addi	r1, r4, 1318	// regs: r1=0x526
  2c:	6c1b      	mov	r0, r6	// regs: r0=zext16(<arg1>)
  2e:	dc640336 	st.b	r3, (r4, 0x336)	// *(0x336) = *(0x336)
  32:	e0000000 	bsr	0x0	// <partial_aid_ndp_calc>; regs: r0=<ret partial_aid_ndp_calc@0x32>, r1=<clobbered>
  36:	d864119b 	ld.h	r3, (r4, 0x336)	// regs: r3=*(0x336)
  3a:	c4605d07 	ins	r3, r0, 15, 7
  3e:	dc64119b 	st.h	r3, (r4, 0x336)	// *(0x336) = *(0x336)
  42:	e9250009 	bnez	r5, 0x54	// if (r5 != 0x0) goto loc_54;
  46:	3206      	movi	r2, 6	// regs: r2=0x6
  48:	e4240301 	addi	r1, r4, 770	// regs: r1=0x302
  4c:	e4040525 	addi	r0, r4, 1318	// regs: r0=0x526
  50:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x50>, r1=<clobbered>
loc_54:
  54:	3000      	movi	r0, 0	// regs: r0=0x0
  56:	1493      	pop	r4-r6, r15
  58:	0000      	.short	0x0000	// <ah_lmac>
  5a:	0000      	.short	0x0000
  5c:	00000000 	.long	0x00000000	// <.rodata.__func__.13487>
  60:	00000000 	.long	0x00000000	// <.rodata.lmac_cfg_set_aid.str1.1>

Disassembly of section .text.lmac_cfg_set_mac:

00000000 <lmac_cfg_set_mac>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	1424      	subi	r14, r14, 16	// regs: r14=(sp - 0x10)
   4:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   6:	8161      	ld.b	r3, (r1, 0x1)	// regs: r3=*(<arg1> + 0x1)
   8:	8140      	ld.b	r2, (r1, 0x0)	// regs: r2=*(<arg1>)
   a:	8125      	ld.b	r1, (r1, 0x5)	// regs: r1=*(<arg1> + 0x5)
   c:	b823      	st.w	r1, (r14, 0xc)	// local_4 = *(<arg1> + 0x5)
   e:	8424      	ld.b	r1, (r4, 0x4)	// regs: r1=*(<arg1> + 0x4)
  10:	b822      	st.w	r1, (r14, 0x8)	// local_8 = *(<arg1> + 0x4)
  12:	8423      	ld.b	r1, (r4, 0x3)	// regs: r1=*(<arg1> + 0x3)
  14:	b821      	st.w	r1, (r14, 0x4)	// local_c = *(<arg1> + 0x3)
  16:	8422      	ld.b	r1, (r4, 0x2)	// regs: r1=*(<arg1> + 0x2)
  18:	b820      	st.w	r1, (r14, 0x0)	// local_10 = *(<arg1> + 0x2)
  1a:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  1c:	1027      	lrw	r1, 0x0	// regs: r1=0x0
  1e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1e>, r1=<clobbered>
  22:	3206      	movi	r2, 6	// regs: r2=0x6
  24:	6c53      	mov	r1, r4	// regs: r1=<arg1>
  26:	1006      	lrw	r0, 0x0	// regs: r0=0x0
  28:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x28>, r1=<clobbered>
  2c:	3000      	movi	r0, 0	// regs: r0=0x0
  2e:	1404      	addi	r14, r14, 16	// regs: r14=((sp - 0x10) + 0x10)
  30:	1491      	pop	r4, r15
  32:	0000      	.short	0x0000
  34:	0000      	.short	0x0000	// <.rodata.lmac_cfg_set_mac.str1.1>
  36:	0000      	.short	0x0000
  38:	00000000 	.long	0x00000000	// <.rodata.__func__.13492>
  3c:	00000000 	.long	0x00000000	// <ah_lmac+0x302>

Disassembly of section .text.lmac_ah_add_sta:

00000000 <lmac_ah_add_sta>: // arg_bytes: 0
   0:	14d8      	push	r4-r11, r15
   2:	1426      	subi	r14, r14, 24	// regs: r14=(sp - 0x18)
   4:	e50e0013 	addi	r8, r14, 20	// regs: r8=((sp - 0x18) + 0x14)
   8:	6d8f      	mov	r6, r3	// regs: r6=<arg3>
   a:	3303      	movi	r3, 3	// regs: r3=0x3
   c:	dc680000 	st.b	r3, (r8, 0x0)	// local_4 = 0x3
  10:	3300      	movi	r3, 0	// regs: r3=0x0
  12:	dc680001 	st.b	r3, (r8, 0x1)	// local_3 = 0x0
  16:	3301      	movi	r3, 1	// regs: r3=0x1
  18:	dc680002 	st.b	r3, (r8, 0x2)	// local_2 = 0x1
  1c:	8625      	ld.b	r1, (r6, 0x5)	// regs: r1=*(<arg3> + 0x5)
  1e:	3302      	movi	r3, 2	// regs: r3=0x2
  20:	dc680003 	st.b	r3, (r8, 0x3)	// local_1 = 0x2
  24:	b823      	st.w	r1, (r14, 0xc)	// local_c = *(<arg3> + 0x5)
  26:	8624      	ld.b	r1, (r6, 0x4)	// regs: r1=*(<arg3> + 0x4)
  28:	b822      	st.w	r1, (r14, 0x8)	// local_10 = *(<arg3> + 0x4)
  2a:	8623      	ld.b	r1, (r6, 0x3)	// regs: r1=*(<arg3> + 0x3)
  2c:	6e4b      	mov	r9, r2	// regs: r9=<arg2>
  2e:	b821      	st.w	r1, (r14, 0x4)	// local_14 = *(<arg3> + 0x3)
  30:	8622      	ld.b	r1, (r6, 0x2)	// regs: r1=*(<arg3> + 0x2)
  32:	8661      	ld.b	r3, (r6, 0x1)	// regs: r3=*(<arg3> + 0x1)
  34:	8640      	ld.b	r2, (r6, 0x0)	// regs: r2=*(<arg3>)
  36:	b820      	st.w	r1, (r14, 0x0)	// local_18 = *(<arg3> + 0x2)
  38:	6c67      	mov	r1, r9	// regs: r1=<arg2>
  3a:	0309      	lrw	r0, 0x0	// regs: r0=0x0
  3c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x3c>, r1=<clobbered>
  40:	6c5b      	mov	r1, r6	// regs: r1=<arg3>
  42:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
  46:	e0000000 	bsr	0x0	// <lmac_sta_get>; regs: r0=<ret lmac_sta_get@0x46>, r1=<clobbered>
  4a:	6d03      	mov	r4, r0	// regs: r4=<ret lmac_sta_get@0x46>
  4c:	e92000e8 	bnez	r0, 0x21c	// if (r0 != 0x0) goto loc_21c;
  50:	e0000000 	bsr	0x0	// <lmac_alloc_sta>; regs: r0=<ret lmac_alloc_sta@0x50>, r1=<clobbered>
  54:	6d03      	mov	r4, r0	// regs: r4=<ret lmac_alloc_sta@0x50>
  56:	e9200009 	bnez	r0, 0x68	// if (r0 != 0x0) goto loc_68;
  5a:	0310      	lrw	r0, 0x0	// regs: r0=0x0
loc_5c:
  5c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x5c>, r1=<clobbered>
  60:	3000      	movi	r0, 0	// regs: r0=0x0
  62:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_64:
  64:	1406      	addi	r14, r14, 24	// regs: r14=((sp - 0x18) + 0x18)
  66:	1498      	pop	r4-r11, r15
loc_68:
  68:	03b3      	lrw	r5, 0x0	// regs: r5=0x0
  6a:	d8050317 	ld.b	r0, (r5, 0x317)	// regs: r0=*(0x317)
  6e:	e0000000 	bsr	0x0	// <_os_malloc>; regs: r0=<ret _os_malloc@0x6e>, r1=<clobbered>
  72:	dc042027 	st.w	r0, (r4, 0x9c)	// *(<ret lmac_alloc_sta@0x50> + 0x9c) = <ret _os_malloc@0x6e>
  76:	e9200007 	bnez	r0, 0x84	// if (r0 != 0x0) goto loc_84;
  7a:	6c13      	mov	r0, r4	// regs: r0=<ret lmac_alloc_sta@0x50>
  7c:	e0000000 	bsr	0x0	// <_os_free>; regs: r0=<ret _os_free@0x7c>, r1=<clobbered>
  80:	0318      	lrw	r0, 0x0	// regs: r0=0x0
  82:	07ed      	br	0x5c	// goto loc_5c;
loc_84:
  84:	5c1e      	addi	r0, r4, 8	// regs: r0=(<ret lmac_alloc_sta@0x50> + 0x8)
  86:	e0000000 	bsr	0x0	// <skb_list_init>; regs: r0=<ret skb_list_init@0x86>, r1=<clobbered>
  8a:	3100      	movi	r1, 0	// regs: r1=0x0
  8c:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  8e:	e40509ff 	addi	r0, r5, 2560	// regs: r0=0xa00
  92:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0x92>, r1=<clobbered>
  96:	d865227f 	ld.w	r3, (r5, 0x9fc)	// regs: r3=*(0x9fc)
  9a:	e40509f7 	addi	r0, r5, 2552	// regs: r0=0x9f8
  9e:	dc85227f 	st.w	r4, (r5, 0x9fc)	// *(0x9fc) = <ret lmac_alloc_sta@0x50>
  a2:	b400      	st.w	r0, (r4, 0x0)	// *(<ret lmac_alloc_sta@0x50>) = 0x9f8
  a4:	b461      	st.w	r3, (r4, 0x4)	// *(<ret lmac_alloc_sta@0x50> + 0x4) = *(0x9fc)
  a6:	b380      	st.w	r4, (r3, 0x0)	// *(*(0x9fc)) = <ret lmac_alloc_sta@0x50>
  a8:	d8651504 	ld.h	r3, (r5, 0xa08)	// regs: r3=*(0xa08)
  ac:	2300      	addi	r3, 1	// regs: r3=(*(0xa08) + 0x1)
  ae:	e40509ff 	addi	r0, r5, 2560	// regs: r0=0xa00
  b2:	dc651504 	st.h	r3, (r5, 0xa08)	// *(0xa08) = (*(0xa08) + 0x1)
  b6:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0xb6>, r1=<clobbered>
loc_ba:
  ba:	3300      	movi	r3, 0	// regs: r3=0x0
  bc:	d844006b 	ld.b	r2, (r4, 0x6b)	// regs: r2=*(r4 + 0x6b)
  c0:	c4435c05 	ins	r2, r3, 5, 5
  c4:	dc44006b 	st.b	r2, (r4, 0x6b)	// *(r4 + 0x6b) = *(r4 + 0x6b)
  c8:	3701      	movi	r7, 1	// regs: r7=0x1
  ca:	3201      	movi	r2, 1	// regs: r2=0x1
  cc:	13b3      	lrw	r5, 0x0	// regs: r5=0x0
  ce:	1315      	lrw	r0, 0x0	// regs: r0=0x0
  d0:	e5840143 	addi	r12, r4, 324	// regs: r12=(r4 + 0x144)
  d4:	dc440097 	st.b	r2, (r4, 0x97)	// *(r4 + 0x97) = 0x1
  d8:	dc440098 	st.b	r2, (r4, 0x98)	// *(r4 + 0x98) = 0x1
  dc:	dd241034 	st.h	r9, (r4, 0x68)	// *(r4 + 0x68) = <arg2>
  e0:	dc640076 	st.b	r3, (r4, 0x76)	// *(r4 + 0x76) = 0x0
  e4:	dc6400a0 	st.b	r3, (r4, 0xa0)	// *(r4 + 0xa0) = 0x0
  e8:	dc6400a2 	st.b	r3, (r4, 0xa2)	// *(r4 + 0xa2) = 0x0
  ec:	dce400ad 	st.b	r7, (r4, 0xad)	// *(r4 + 0xad) = 0x1
  f0:	d8250308 	ld.b	r1, (r5, 0x308)	// regs: r1=*(0x308)
  f4:	d84400ae 	ld.b	r2, (r4, 0xae)	// regs: r2=*(r4 + 0xae)
  f8:	d0200021 	ldr.b	r1, (r0, r1 << 0)	// regs: r1=*(0x0 + (*(0x308) << 0))
  fc:	c4415c64 	ins	r2, r1, 7, 4
 100:	dc4400ae 	st.b	r2, (r4, 0xae)	// *(r4 + 0xae) = *(r4 + 0xae)
 104:	3240      	movi	r2, 64	// regs: r2=0x40
 106:	dc44013f 	st.b	r2, (r4, 0x13f)	// *(r4 + 0x13f) = 0x40
 10a:	b844      	st.w	r2, (r14, 0x10)	// local_8 = 0x40
loc_10c:
 10c:	3200      	movi	r2, 0	// regs: r2=0x0
 10e:	dc4c1007 	st.h	r2, (r12, 0xe)	// *(r12 + 0xe) = 0x0
 112:	e4430014 	addi	r2, r3, 21	// regs: r2=(r3 + 0x15)
 116:	4244      	lsli	r2, r2, 4	// regs: r2=((r3 + 0x15) << 0x4)
 118:	3132      	movi	r1, 50	// regs: r1=0x32
 11a:	d4820021 	str.b	r1, (r2, r4 << 0)
 11e:	4344      	lsli	r2, r3, 4	// regs: r2=(r3 << 0x4)
 120:	6090      	addu	r2, r4	// regs: r2=((r3 << 0x4) + r4)
 122:	d9ae2004 	ld.w	r13, (r14, 0x10)	// regs: r13=local_8
 126:	d802014f 	ld.b	r0, (r2, 0x14f)	// regs: r0=*((((r3 << 0x4) + r4) + 0x14f))
 12a:	c40d5cc0 	ins	r0, r13, 6, 0
 12e:	ea0a0000 	movi	r10, 0	// regs: r10=0x0
 132:	ea0b0000 	movi	r11, 0	// regs: r11=0x0
 136:	dc02014f 	st.b	r0, (r2, 0x14f)	// *((((r3 << 0x4) + r4) + 0x14f)) = *((((r3 << 0x4) + r4) + 0x14f))
 13a:	dd4c2000 	st.w	r10, (r12, 0x0)	// *(r12) = 0x0
 13e:	dd6c2001 	st.w	r11, (r12, 0x4)	// *(r12 + 0x4) = 0x0
 142:	d80210a6 	ld.h	r0, (r2, 0x14c)	// regs: r0=*((((r3 << 0x4) + r4) + 0x14c))
 146:	ea0d0000 	movi	r13, 0	// regs: r13=0x0
 14a:	c40d5d60 	ins	r0, r13, 11, 0
 14e:	dc0210a6 	st.h	r0, (r2, 0x14c)	// *((((r3 << 0x4) + r4) + 0x14c)) = *((((r3 << 0x4) + r4) + 0x14c))
 152:	d802014f 	ld.b	r0, (r2, 0x14f)	// regs: r0=*((((r3 << 0x4) + r4) + 0x14f))
 156:	e400207f 	andi	r0, r0, 127	// regs: r0=(*((((r3 << 0x4) + r4) + 0x14f)) & 0x7f)
 15a:	d9a22053 	ld.w	r13, (r2, 0x14c)	// regs: r13=*((((r3 << 0x4) + r4) + 0x14c))
 15e:	2800      	subi	r0, 1	// regs: r0=((*((((r3 << 0x4) + r4) + 0x14f)) & 0x7f) - 0x1)
 160:	c5a05d6c 	ins	r13, r0, 23, 12
 164:	dda22053 	st.w	r13, (r2, 0x14c)	// *((((r3 << 0x4) + r4) + 0x14c)) = *((((r3 << 0x4) + r4) + 0x14c))
 168:	2300      	addi	r3, 1	// regs: r3=(r3 + 0x1)
 16a:	e422014b 	addi	r1, r2, 332	// regs: r1=(((r3 << 0x4) + r4) + 0x14c)
 16e:	3b48      	cmpnei	r3, 8
 170:	d842014f 	ld.b	r2, (r2, 0x14f)	// regs: r2=*((((r3 << 0x4) + r4) + 0x14f))
 174:	c4475c07 	ins	r2, r7, 7, 7
 178:	a143      	st.b	r2, (r1, 0x3)	// *((((r3 << 0x4) + r4) + 0x14f)) = *((((r3 << 0x4) + r4) + 0x14f))
 17a:	e58c000f 	addi	r12, r12, 16	// regs: r12=(r12 + 0x10)
 17e:	0bc7      	bt	0x10c	// if (r3 != 0x8) goto loc_10c;
 180:	6c13      	mov	r0, r4	// regs: r0=r4
 182:	e0000000 	bsr	0x0	// <sta_rc_init>; regs: r0=<ret sta_rc_init@0x182>, r1=<clobbered>
 186:	6c5b      	mov	r1, r6	// regs: r1=<arg3>
 188:	3206      	movi	r2, 6	// regs: r2=0x6
 18a:	e404006e 	addi	r0, r4, 111	// regs: r0=(r4 + 0x6f)
 18e:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x18e>, r1=<clobbered>
 192:	d8250308 	ld.b	r1, (r5, 0x308)	// regs: r1=*(0x308)
 196:	3903      	cmphsi	r1, 4
 198:	084b      	bt	0x22e	// if (r1 >= 0x4) goto loc_22e;
 19a:	d86400af 	ld.b	r3, (r4, 0xaf)	// regs: r3=*(r4 + 0xaf)
 19e:	d0280022 	ldr.b	r2, (r8, r1 << 0)	// regs: r2=*(((sp - 0x18) + 0x14) + (*(0x308) << 0))
 1a2:	c4625c60 	ins	r3, r2, 3, 0
 1a6:	dc6400af 	st.b	r3, (r4, 0xaf)	// *(r4 + 0xaf) = *(r4 + 0xaf)
loc_1aa:
 1aa:	e9290048 	bnez	r9, 0x23a	// if (r9 != 0x0) goto loc_23a;
 1ae:	3301      	movi	r3, 1	// regs: r3=0x1
 1b0:	3206      	movi	r2, 6	// regs: r2=0x6
 1b2:	6c5b      	mov	r1, r6	// regs: r1=<arg3>
 1b4:	111c      	lrw	r0, 0x0	// regs: r0=0x0
 1b6:	dc65202f 	st.w	r3, (r5, 0xbc)	// *(0xbc) = 0x1
 1ba:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x1ba>, r1=<clobbered>
 1be:	111a      	lrw	r0, 0x0	// regs: r0=0x0
 1c0:	e0000000 	bsr	0x0	// <partial_bssid_calc>; regs: r0=<ret partial_bssid_calc@0x1c0>, r1=<clobbered>
 1c4:	d8641035 	ld.h	r3, (r4, 0x6a)	// regs: r3=*(r4 + 0x6a)
 1c8:	c4605d00 	ins	r3, r0, 8, 0
 1cc:	dc641035 	st.h	r3, (r4, 0x6a)	// *(r4 + 0x6a) = *(r4 + 0x6a)
loc_1d0:
 1d0:	1115      	lrw	r0, 0x0	// regs: r0=0x0
 1d2:	e0000000 	bsr	0x0	// <partial_bssid_calc>; regs: r0=<ret partial_bssid_calc@0x1d2>, r1=<clobbered>
 1d6:	d8651334 	ld.h	r3, (r5, 0x668)	// regs: r3=*(0x668)
 1da:	c4605d03 	ins	r3, r0, 11, 3
 1de:	dc651334 	st.h	r3, (r5, 0x668)	// *(0x668) = *(0x668)
 1e2:	d865037e 	ld.b	r3, (r5, 0x37e)	// regs: r3=*(0x37e)
 1e6:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x37e) & 0x8)
 1ea:	e9030008 	bez	r3, 0x1fa	// if (r3 == 0x0) goto loc_1fa;
 1ee:	d805431e 	ld.bs	r0, (r5, 0x31e)	// regs: r0=*(0x31e)
 1f2:	e0000000 	bsr	0x0	// <lmac_adjust_cca_threshold>; regs: r0=<ret lmac_adjust_cca_threshold@0x1f2>, r1=<clobbered>
 1f6:	e0000000 	bsr	0x0	// <ah_wphy_obss_sd_det_enable>; regs: r0=<ret ah_wphy_obss_sd_det_enable@0x1f6>, r1=<clobbered>
loc_1fa:
 1fa:	e0000000 	bsr	0x0	// <lmac_tx_vec_init>; regs: r0=<ret lmac_tx_vec_init@0x1fa>, r1=<clobbered>
 1fe:	d865227e 	ld.w	r3, (r5, 0x9f8)	// regs: r3=*(0x9f8)
 202:	3100      	movi	r1, 0	// regs: r1=0x0
 204:	1109      	lrw	r0, 0x0	// regs: r0=0x0
 206:	ea0c0001 	movi	r12, 1	// regs: r12=0x1
loc_20a:
 20a:	640e      	cmpne	r3, r0
 20c:	0838      	bt	0x27c	// if (T) goto loc_27c;
 20e:	1108      	lrw	r0, 0x0	// regs: r0=0x0
 210:	dc25229c 	st.w	r1, (r5, 0xa70)	// *(0xa70) = r1
 214:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x214>, r1=<clobbered>
 218:	3000      	movi	r0, 0	// regs: r0=0x0
 21a:	0725      	br	0x64	// goto loc_64;
loc_21c:
 21c:	d860006b 	ld.b	r3, (r0, 0x6b)	// regs: r3=*(<ret lmac_sta_get@0x46> + 0x6b)
 220:	e4632020 	andi	r3, r3, 32	// regs: r3=(*(<ret lmac_sta_get@0x46> + 0x6b) & 0x20)
 224:	e923ff4b 	bnez	r3, 0xba	// if (r3 != 0x0) goto loc_ba;
 228:	e0000000 	bsr	0x0	// <lmac_sta_put>; regs: r0=<ret lmac_sta_put@0x228>, r1=<clobbered>
 22c:	0747      	br	0xba	// goto loc_ba;
loc_22e:
 22e:	c4274021 	lsl	r1, r7, r1
 232:	1100      	lrw	r0, 0x0	// regs: r0=0x0
 234:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x234>, r1=<clobbered>
 238:	07b9      	br	0x1aa	// goto loc_1aa;
loc_23a:
 23a:	103f      	lrw	r1, 0x0	// regs: r1=0x0
 23c:	3706      	movi	r7, 6	// regs: r7=0x6
 23e:	6c9f      	mov	r2, r7	// regs: r2=0x6
 240:	e4010223 	addi	r0, r1, 548	// regs: r0=0x224
 244:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x244>, r1=<clobbered>
 248:	1037      	lrw	r1, 0x0	// regs: r1=0x0
 24a:	6c27      	mov	r0, r9	// regs: r0=<arg2>
 24c:	e0000000 	bsr	0x0	// <partial_aid_calc>; regs: r0=<ret partial_aid_calc@0x24c>, r1=<clobbered>
 250:	d8641035 	ld.h	r3, (r4, 0x6a)	// regs: r3=*(r4 + 0x6a)
 254:	c4605d00 	ins	r3, r0, 8, 0
 258:	dc641035 	st.h	r3, (r4, 0x6a)	// *(r4 + 0x6a) = *(r4 + 0x6a)
 25c:	3302      	movi	r3, 2	// regs: r3=0x2
 25e:	a57c      	st.b	r3, (r5, 0x1c)	// *(0x1c) = 0x2
 260:	3301      	movi	r3, 1	// regs: r3=0x1
 262:	a57e      	st.b	r3, (r5, 0x1e)	// *(0x1e) = 0x1
 264:	a57f      	st.b	r3, (r5, 0x1f)	// *(0x1f) = 0x1
 266:	d865037c 	ld.b	r3, (r5, 0x37c)	// regs: r3=*(0x37c)
 26a:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x37c) & 0x2)
 26e:	a5fd      	st.b	r7, (r5, 0x1d)	// *(0x1d) = 0x6
 270:	e903ffb0 	bez	r3, 0x1d0	// if (r3 == 0x0) goto loc_1d0;
 274:	6c1b      	mov	r0, r6	// regs: r0=<arg3>
 276:	e0000000 	bsr	0x0	// <lmac_send_mgmt_meas_req>; regs: r0=<ret lmac_send_mgmt_meas_req@0x276>, r1=<clobbered>
 27a:	07ab      	br	0x1d0	// goto loc_1d0;
loc_27c:
 27c:	d8431034 	ld.h	r2, (r3, 0x68)	// regs: r2=*(r3 + 0x68)
 280:	3a1f      	cmphsi	r2, 32
 282:	0804      	bt	0x28a	// if (r2 >= 0x20) goto loc_28a;
 284:	c44c4022 	lsl	r2, r12, r2
 288:	6c48      	or	r1, r2	// regs: r1=(r1 | *(r3 + 0x68))
loc_28a:
 28a:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(r3)
 28c:	07bf      	br	0x20a	// goto loc_20a;
 28e:	0000      	.short	0x0000
 290:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_add_sta.str1.1>
 294:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_add_sta.str1.1+0x32>
 298:	00000000 	.long	0x00000000	// <ah_lmac>
 29c:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_add_sta.str1.1+0x57>
 2a0:	00000000 	.long	0x00000000	// <bw_map_bss2sig>
 2a4:	00000000 	.long	0x00000000	// <ah_lmac+0x526>
 2a8:	00000000 	.long	0x00000000	// <ah_lmac+0x9f8>
 2ac:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_add_sta.str1.1+0x98>
 2b0:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_add_sta.str1.1+0x7d>
 2b4:	00000000 	.long	0x00000000	// <ah_lmac+0x302>

Disassembly of section .text.lmac_bss_load_get:

00000000 <lmac_bss_load_get>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	1094      	lrw	r4, 0x0	// regs: r4=0x0
   4:	e4240a67 	addi	r1, r4, 2664	// regs: r1=0xa68
   8:	d8641504 	ld.h	r3, (r4, 0xa08)	// regs: r3=*(0xa08)
   c:	dc640a68 	st.b	r3, (r4, 0xa68)	// *(0xa68) = *(0xa08)
  10:	4b68      	lsri	r3, r3, 8	// regs: r3=(*(0xa08) >> 0x8)
  12:	dc640a69 	st.b	r3, (r4, 0xa69)	// *(0xa69) = (*(0xa08) >> 0x8)
  16:	3312      	movi	r3, 18	// regs: r3=0x12
  18:	dc640a6b 	st.b	r3, (r4, 0xa6b)	// *(0xa6b) = 0x12
  1c:	3205      	movi	r2, 5	// regs: r2=0x5
  1e:	337a      	movi	r3, 122	// regs: r3=0x7a
  20:	dc640a6c 	st.b	r3, (r4, 0xa6c)	// *(0xa6c) = 0x7a
  24:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x24>, r1=<clobbered>
  28:	d8640a6c 	ld.b	r3, (r4, 0xa6c)	// regs: r3=*(0xa6c)
  2c:	d8240a69 	ld.b	r1, (r4, 0xa69)	// regs: r1=*(0xa69)
  30:	d8440a6b 	ld.b	r2, (r4, 0xa6b)	// regs: r2=*(0xa6b)
  34:	d8040a68 	ld.b	r0, (r4, 0xa68)	// regs: r0=*(0xa68)
  38:	4368      	lsli	r3, r3, 8	// regs: r3=(*(0xa6c) << 0x8)
  3a:	4128      	lsli	r1, r1, 8	// regs: r1=(*(0xa69) << 0x8)
  3c:	6cc8      	or	r3, r2	// regs: r3=((*(0xa6c) << 0x8) | *(0xa6b))
  3e:	6c40      	or	r1, r0	// regs: r1=((*(0xa69) << 0x8) | *(0xa68))
  40:	d8440a6a 	ld.b	r2, (r4, 0xa6a)	// regs: r2=*(0xa6a)
  44:	1004      	lrw	r0, 0x0	// regs: r0=0x0
  46:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x46>, r1=<clobbered>
  4a:	3000      	movi	r0, 0	// regs: r0=0x0
  4c:	1491      	pop	r4, r15
  4e:	0000      	.short	0x0000
  50:	00000000 	.long	0x00000000	// <ah_lmac>
  54:	0000      	.short	0x0000	// <.rodata.lmac_bss_load_get.str1.1>
  56:	0000      	.short	0x0000

Disassembly of section .text.lmac_ah_del_sta:

00000000 <lmac_ah_del_sta>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	1423      	subi	r14, r14, 12	// regs: r14=(sp - 0xc)
   4:	6d0b      	mov	r4, r2	// regs: r4=<arg2>
   6:	8262      	ld.b	r3, (r2, 0x2)	// regs: r3=*(<arg2> + 0x2)
   8:	8405      	ld.b	r0, (r4, 0x5)	// regs: r0=*(<arg2> + 0x5)
   a:	8241      	ld.b	r2, (r2, 0x1)	// regs: r2=*(<arg2> + 0x1)
   c:	b802      	st.w	r0, (r14, 0x8)	// local_4 = *(<arg2> + 0x5)
   e:	8404      	ld.b	r0, (r4, 0x4)	// regs: r0=*(<arg2> + 0x4)
  10:	b801      	st.w	r0, (r14, 0x4)	// local_8 = *(<arg2> + 0x4)
  12:	8403      	ld.b	r0, (r4, 0x3)	// regs: r0=*(<arg2> + 0x3)
  14:	8420      	ld.b	r1, (r4, 0x0)	// regs: r1=*(<arg2>)
  16:	b800      	st.w	r0, (r14, 0x0)	// local_c = *(<arg2> + 0x3)
  18:	1009      	lrw	r0, 0x0	// regs: r0=0x0
  1a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x1a>, r1=<clobbered>
  1e:	6c53      	mov	r1, r4	// regs: r1=<arg2>
  20:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
  24:	e0000000 	bsr	0x0	// <lmac_sta_del>; regs: r0=<ret lmac_sta_del@0x24>, r1=<clobbered>
  28:	1066      	lrw	r3, 0x0	// regs: r3=0x0
  2a:	d8431504 	ld.h	r2, (r3, 0xa08)	// regs: r2=*(0xa08)
  2e:	e9220004 	bnez	r2, 0x36	// if (r2 != 0x0) goto loc_36;
  32:	dc430a4e 	st.b	r2, (r3, 0xa4e)	// *(0xa4e) = *(0xa08)
loc_36:
  36:	3000      	movi	r0, 0	// regs: r0=0x0
  38:	1403      	addi	r14, r14, 12	// regs: r14=((sp - 0xc) + 0xc)
  3a:	1491      	pop	r4, r15
  3c:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_del_sta.str1.1>
  40:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_set_primary_chan:

00000000 <lmac_set_primary_chan>: // arg_bytes: 0
   0:	3000      	movi	r0, 0	// regs: r0=0x0
   2:	783c      	jmp	r15	// return;

Disassembly of section .text.lmac_set_radio_onoff:

00000000 <lmac_set_radio_onoff>: // arg_bytes: 8
   0:	14d2      	push	r4-r5, r15
   2:	3941      	cmpnei	r1, 1
   4:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   6:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   8:	0809      	bt	0x1a	// if (r1 != 0x1) goto loc_1a;
loc_a:
   a:	e0000000 	bsr	0x0	// <lmac_doze_exit>; regs: r0=<ret lmac_doze_exit@0xa>, r1=<clobbered>
loc_e:
   e:	846a      	ld.b	r3, (r4, 0xa)	// regs: r3=*(<arg0> + 0xa)
  10:	c4655c00 	ins	r3, r5, 0, 0
  14:	3000      	movi	r0, 0	// regs: r0=0x0
  16:	a46a      	st.b	r3, (r4, 0xa)	// *(<arg0> + 0xa) = *(<arg0> + 0xa)
  18:	1492      	pop	r4-r5, r15
loc_1a:
  1a:	3942      	cmpnei	r1, 2
  1c:	3500      	movi	r5, 0	// regs: r5=0x0
  1e:	0ff6      	bf	0xa	// if (r1 == 0x2) goto loc_a;
  20:	e0000000 	bsr	0x0	// <lmac_doze_enter>; regs: r0=<ret lmac_doze_enter@0x20>, r1=<clobbered>
  24:	07f5      	br	0xe	// goto loc_e;

Disassembly of section .text.lmac_set_bgrssi:

00000000 <lmac_set_bgrssi>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	1094      	lrw	r4, 0x0	// regs: r4=0x0
   4:	e981000f 	blz	r1, 0x22	// if (r1 < 0x0) goto loc_22;
   8:	d8640361 	ld.b	r3, (r4, 0x361)	// regs: r3=*(0x361)
   c:	3201      	movi	r2, 1	// regs: r2=0x1
   e:	c4625c02 	ins	r3, r2, 2, 2
  12:	d804431e 	ld.bs	r0, (r4, 0x31e)	// regs: r0=*(0x31e)
  16:	dc640361 	st.b	r3, (r4, 0x361)	// *(0x361) = *(0x361)
  1a:	e0000000 	bsr	0x0	// <lmac_adjust_cca_threshold>; regs: r0=<ret lmac_adjust_cca_threshold@0x1a>, r1=<clobbered>
loc_1e:
  1e:	3000      	movi	r0, 0	// regs: r0=0x0
  20:	1492      	pop	r4-r5, r15
loc_22:
  22:	6c07      	mov	r0, r1	// regs: r0=<arg1>
  24:	dc24031e 	st.b	r1, (r4, 0x31e)	// *(0x31e) = <arg1>
  28:	3500      	movi	r5, 0	// regs: r5=0x0
  2a:	e0000000 	bsr	0x0	// <lmac_adjust_cca_threshold>; regs: r0=<ret lmac_adjust_cca_threshold@0x2a>, r1=<clobbered>
  2e:	d8640361 	ld.b	r3, (r4, 0x361)	// regs: r3=*(0x361)
  32:	c4655c02 	ins	r3, r5, 2, 2
  36:	d804431e 	ld.bs	r0, (r4, 0x31e)	// regs: r0=*(0x31e)
  3a:	dc640361 	st.b	r3, (r4, 0x361)	// *(0x361) = *(0x361)
  3e:	e0000000 	bsr	0x0	// <lmac_adjust_agc_threshold>; regs: r0=<ret lmac_adjust_agc_threshold@0x3e>, r1=<clobbered>
  42:	d8640361 	ld.b	r3, (r4, 0x361)	// regs: r3=*(0x361)
  46:	c4655c03 	ins	r3, r5, 3, 3
  4a:	dc640361 	st.b	r3, (r4, 0x361)	// *(0x361) = *(0x361)
  4e:	07e8      	br	0x1e	// goto loc_1e;
  50:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_lo_table_kick:

00000000 <lmac_lo_table_kick>: // arg_bytes: 4
   0:	14d3      	push	r4-r6, r15
   2:	10b7      	lrw	r5, 0x0	// regs: r5=0x0
   4:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   6:	d8650378 	ld.b	r3, (r5, 0x378)	// regs: r3=*(0x378)
   a:	64c0      	cmphs	r0, r3
   c:	081a      	bt	0x40	// if (T) goto loc_40;
   e:	7580      	zextb	r6, r0	// regs: r6=zext8(<arg0>)
  10:	6c1b      	mov	r0, r6	// regs: r0=zext8(<arg0>)
  12:	e0000000 	bsr	0x0	// <sysctrl_internal_rf_sel_lo_freq>; regs: r0=<ret sysctrl_internal_rf_sel_lo_freq@0x12>, r1=<clobbered>
  16:	e0000000 	bsr	0x0	// <ah_rf_lo_table_kick>; regs: r0=<ret ah_rf_lo_table_kick@0x16>, r1=<clobbered>
  1a:	3118      	movi	r1, 24	// regs: r1=0x18
  1c:	7d04      	mult	r4, r1	// regs: r4=(<arg0> * 0x18)
  1e:	6114      	addu	r4, r5	// regs: r4=((<arg0> * 0x18) )
  20:	dcc50340 	st.b	r6, (r5, 0x340)	// *(0x340) = zext8(<arg0>)
  24:	d86400c0 	ld.b	r3, (r4, 0xc0)	// regs: r3=*((((<arg0> * 0x18) ) + 0xc0))
  28:	dc65033d 	st.b	r3, (r5, 0x33d)	// *(0x33d) = *((((<arg0> * 0x18) ) + 0xc0))
  2c:	d8642030 	ld.w	r3, (r4, 0xc0)	// regs: r3=*((((<arg0> * 0x18) ) + 0xc0))
  30:	c50356e3 	zext	r3, r3, 23, 8	// regs: r3=zext(*((((<arg0> * 0x18) ) + 0xc0)))
  34:	dc65119f 	st.h	r3, (r5, 0x33e)	// *(0x33e) = zext(*((((<arg0> * 0x18) ) + 0xc0)))
  38:	3000      	movi	r0, 0	// regs: r0=0x0
  3a:	e4a50331 	addi	r5, r5, 818	// regs: r5=0x332
loc_3e:
  3e:	1493      	pop	r4-r6, r15
loc_40:
  40:	d86509e2 	ld.b	r3, (r5, 0x9e2)	// regs: r3=*(0x9e2)
  44:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  48:	e9230006 	bnez	r3, 0x54	// if (r3 != 0x0) goto loc_54;
  4c:	6c43      	mov	r1, r0	// regs: r1=<arg0>
  4e:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  50:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x50>, r1=<clobbered>
loc_54:
  54:	3000      	movi	r0, 0	// regs: r0=0x0
  56:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  58:	07f3      	br	0x3e	// goto loc_3e;
  5a:	0000      	.short	0x0000
  5c:	00000000 	.long	0x00000000	// <ah_lmac>
  60:	00000000 	.long	0x00000000	// <.rodata.lmac_lo_table_kick.str1.1>

Disassembly of section .text.lmac_lo_table_read:

00000000 <lmac_lo_table_read>: // arg_bytes: 0
   0:	14d6      	push	r4-r9, r15
   2:	3400      	movi	r4, 0	// regs: r4=0x0
   4:	10d5      	lrw	r6, 0x0	// regs: r6=0x0
   6:	10f6      	lrw	r7, 0x0	// regs: r7=0x0
   8:	ea880016 	lrw	r8, 0x0	// regs: r8=0x0
loc_c:
   c:	d8660378 	ld.b	r3, (r6, 0x378)	// regs: r3=*(0x378)
  10:	64d0      	cmphs	r4, r3
  12:	0c02      	bf	0x16	// if (!T) goto loc_16;
  14:	1496      	pop	r4-r9, r15
loc_16:
  16:	d866033c 	ld.b	r3, (r6, 0x33c)	// regs: r3=*(0x33c)
  1a:	650e      	cmpne	r3, r4
  1c:	6c53      	mov	r1, r4	// regs: r1=r4
  1e:	081a      	bt	0x52	// if (T) goto loc_52;
  20:	1011      	lrw	r0, 0x0	// regs: r0=0x0
loc_22:
  22:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x22>, r1=<clobbered>
  26:	4464      	lsli	r3, r4, 4	// regs: r3=(r4 << 0x4)
  28:	e4a304ff 	addi	r5, r3, 1280	// regs: r5=((r4 << 0x4) + 0x500)
  2c:	e5230503 	addi	r9, r3, 1284	// regs: r9=((r4 << 0x4) + 0x504)
loc_30:
  30:	6c17      	mov	r0, r5	// regs: r0=r5
  32:	e0000000 	bsr	0x0	// <ah_rfspi_read>; regs: r0=<ret ah_rfspi_read@0x32>, r1=<clobbered>
  36:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
  38:	6c43      	mov	r1, r0	// regs: r1=<ret ah_rfspi_read@0x32>
  3a:	7555      	zexth	r5, r5	// regs: r5=zext16((r5 + 0x1))
  3c:	6c23      	mov	r0, r8	// regs: r0=0x0
  3e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x3e>, r1=<clobbered>
  42:	6656      	cmpne	r5, r9
  44:	0bf6      	bt	0x30	// if (T) goto loc_30;
  46:	1009      	lrw	r0, 0x0	// regs: r0=0x0
  48:	2400      	addi	r4, 1	// regs: r4=(r4 + 0x1)
  4a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x4a>, r1=<clobbered>
  4e:	7510      	zextb	r4, r4	// regs: r4=zext8((r4 + 0x1))
  50:	07de      	br	0xc	// goto loc_c;
loc_52:
  52:	6c1f      	mov	r0, r7	// regs: r0=0x0
  54:	07e7      	br	0x22	// goto loc_22;
  56:	0000      	.short	0x0000
  58:	0000      	.short	0x0000	// <ah_lmac>
  5a:	0000      	.short	0x0000
  5c:	00000000 	.long	0x00000000	// <.rodata.lmac_lo_table_read.str1.1+0xb>
  60:	00000000 	.long	0x00000000	// <.rodata.lmac_lo_table_read.str1.1+0x16>
  64:	00000000 	.long	0x00000000	// <.rodata.lmac_lo_table_read.str1.1>
  68:	0000      	.short	0x0000	// <.rodata.lmac_lo_table_read.str1.1+0x1c>
  6a:	0000      	.short	0x0000

Disassembly of section .text.lmac_cfg_set_chanlist:

00000000 <lmac_cfg_set_chanlist>: // arg_bytes: 0
   0:	14d3      	push	r4-r6, r15
   2:	1520      	subi	r14, r14, 128	// regs: r14=(sp - 0x80)
   4:	3a10      	cmphsi	r2, 17
   6:	6d0b      	mov	r4, r2	// regs: r4=<arg2>
   8:	080b      	bt	0x1e	// if (r2 >= 0x11) goto loc_1e;
   a:	e922000b 	bnez	r2, 0x20	// if (r2 != 0x0) goto loc_20;
   e:	1202      	lrw	r0, 0x0	// regs: r0=0x0
  10:	3600      	movi	r6, 0	// regs: r6=0x0
  12:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x12>, r1=<clobbered>
  16:	2e00      	subi	r6, 1	// regs: r6=0xffffffff
loc_18:
  18:	6c1b      	mov	r0, r6	// regs: r0=r6
  1a:	1500      	addi	r14, r14, 128	// regs: r14=((sp - 0x80) + 0x80)
  1c:	1493      	pop	r4-r6, r15
loc_1e:
  1e:	3410      	movi	r4, 16	// regs: r4=0x10
loc_20:
  20:	11be      	lrw	r5, 0x0	// regs: r5=0x0
  22:	3200      	movi	r2, 0	// regs: r2=0x0
  24:	d805034a 	ld.b	r0, (r5, 0x34a)	// regs: r0=*(0x34a)
  28:	d98511a5 	ld.h	r12, (r5, 0x34a)	// regs: r12=*(0x34a)
  2c:	e4002001 	andi	r0, r0, 1	// regs: r0=(*(0x34a) & 0x1)
  30:	c42c55ec 	zext	r12, r12, 15, 1	// regs: r12=zext(*(0x34a))
  34:	1e10      	addi	r6, r14, 64	// regs: r6=((sp - 0x80) + 0x40)
  36:	ea0d0064 	movi	r13, 100	// regs: r13=0x64
loc_3a:
  3a:	6509      	cmplt	r2, r4
  3c:	0859      	bt	0xee	// if (T) goto loc_ee;
  3e:	3100      	movi	r1, 0	// regs: r1=0x0
  40:	2900      	subi	r1, 1	// regs: r1=0xffffffff
  42:	1117      	lrw	r0, 0x0	// regs: r0=0x0
  44:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0x44>, r1=<clobbered>
  48:	e0000000 	bsr	0x0	// <lmac_doze_enter>; regs: r0=<ret lmac_doze_enter@0x48>, r1=<clobbered>
  4c:	3300      	movi	r3, 0	// regs: r3=0x0
  4e:	3000      	movi	r0, 0	// regs: r0=0x0
  50:	dc650378 	st.b	r3, (r5, 0x378)	// *(0x378) = 0x0
  54:	e0000000 	bsr	0x0	// <ah_rf_lo_table_ctrl>; regs: r0=<ret ah_rf_lo_table_ctrl@0x54>, r1=<clobbered>
  58:	6c1b      	mov	r0, r6	// regs: r0=((sp - 0x80) + 0x40)
  5a:	6c53      	mov	r1, r4	// regs: r1=r4
  5c:	e0000000 	bsr	0x0	// <ah_rf_lo_table_cfg>; regs: r0=<ret ah_rf_lo_table_cfg@0x5c>, r1=<clobbered>
  60:	6d83      	mov	r6, r0	// regs: r6=<ret ah_rf_lo_table_cfg@0x5c>
  62:	3001      	movi	r0, 1	// regs: r0=0x1
  64:	e0000000 	bsr	0x0	// <ah_rf_lo_table_ctrl>; regs: r0=<ret ah_rf_lo_table_ctrl@0x64>, r1=<clobbered>
  68:	e9260052 	bnez	r6, 0x10c	// if (r6 != 0x0) goto loc_10c;
  6c:	116d      	lrw	r3, 0x0	// regs: r3=0x0
  6e:	ea0c0000 	movi	r12, 0	// regs: r12=0x0
  72:	3000      	movi	r0, 0	// regs: r0=0x0
  74:	e423017f 	addi	r1, r3, 384	// regs: r1=0x180
  78:	6c9b      	mov	r2, r6	// regs: r2=<ret ah_rf_lo_table_cfg@0x5c>
  7a:	e58c103b 	subi	r12, r12, 60	// regs: r12=0xffffffc4
  7e:	287f      	subi	r0, 128	// regs: r0=0xffffff80
loc_80:
  80:	d04e088d 	ldr.w	r13, (r14, r2 << 2)	// regs: r13=*((sp - 0x80) + (r2 << 2))
  84:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
  86:	6509      	cmplt	r2, r4
  88:	dda32000 	st.w	r13, (r3, 0x0)	// *(r3) = *((sp - 0x80) + (r2 << 2))
  8c:	dd830007 	st.b	r12, (r3, 0x7)	// *(r3 + 0x7) = 0xffffffc4
  90:	a306      	st.b	r0, (r3, 0x6)	// *(r3 + 0x6) = 0xffffff80
  92:	dda12000 	st.w	r13, (r1, 0x0)	// *(r1) = *((sp - 0x80) + (r2 << 2))
  96:	a107      	st.b	r0, (r1, 0x7)	// *(r1 + 0x7) = 0xffffff80
  98:	2317      	addi	r3, 24	// regs: r3=(r3 + 0x18)
  9a:	210b      	addi	r1, 12	// regs: r1=(r1 + 0xc)
  9c:	0bf2      	bt	0x80	// if (T) goto loc_80;
  9e:	5c63      	subi	r3, r4, 1	// regs: r3=(r4 - 0x1)
  a0:	d06e0883 	ldr.w	r3, (r14, r3 << 2)	// regs: r3=*((sp - 0x80) + ((r4 - 0x1) << 2))
  a4:	1140      	lrw	r2, 0x0	// regs: r2=0x0
  a6:	c40356e3 	zext	r3, r3, 23, 0	// regs: r3=zext(*((sp - 0x80) + ((r4 - 0x1) << 2)))
  aa:	e4232fff 	andi	r1, r3, 4095	// regs: r1=(zext(*((sp - 0x80) + ((r4 - 0x1) << 2))) & 0xfff)
  ae:	4104      	lsli	r0, r1, 4	// regs: r0=((zext(*((sp - 0x80) + ((r4 - 0x1) << 2))) & 0xfff) << 0x4)
  b0:	8a23      	ld.h	r1, (r2, 0x6)	// regs: r1=*(0x6)
  b2:	e421200f 	andi	r1, r1, 15	// regs: r1=(*(0x6) & 0xf)
  b6:	6c40      	or	r1, r0	// regs: r1=((*(0x6) & 0xf) | ((zext(*((sp - 0x80) + ((r4 - 0x1) << 2))) & 0xfff) << 0x4))
  b8:	aa23      	st.h	r1, (r2, 0x6)	// *(0x6) = ((*(0x6) & 0xf) | ((zext(*((sp - 0x80) + ((r4 - 0x1) << 2))) & 0xfff) << 0x4))
  ba:	ea0c0fff 	movi	r12, 4095	// regs: r12=0xfff
  be:	6f32      	nor	r12, r12	// regs: r12=(~0xfff)
  c0:	8a24      	ld.h	r1, (r2, 0x8)	// regs: r1=*(0x8)
  c2:	4b0c      	lsri	r0, r3, 12	// regs: r0=(zext(*((sp - 0x80) + ((r4 - 0x1) << 2))) >> 0xc)
  c4:	6870      	and	r1, r12	// regs: r1=(*(0x8) & (~0xfff))
  c6:	6c40      	or	r1, r0	// regs: r1=((*(0x8) & (~0xfff)) | (zext(*((sp - 0x80) + ((r4 - 0x1) << 2))) >> 0xc))
  c8:	7510      	zextb	r4, r4	// regs: r4=zext8(r4)
  ca:	aa24      	st.h	r1, (r2, 0x8)	// *(0x8) = ((*(0x8) & (~0xfff)) | (zext(*((sp - 0x80) + ((r4 - 0x1) << 2))) >> 0xc))
  cc:	5c23      	subi	r1, r4, 1	// regs: r1=(zext8(r4) - 0x1)
  ce:	7444      	zextb	r1, r1	// regs: r1=zext8((zext8(r4) - 0x1))
  d0:	dc25033c 	st.b	r1, (r5, 0x33c)	// *(0x33c) = zext8((zext8(r4) - 0x1))
  d4:	a26b      	st.b	r3, (r2, 0xb)	// *(0xb) = zext(*((sp - 0x80) + ((r4 - 0x1) << 2)))
  d6:	4b68      	lsri	r3, r3, 8	// regs: r3=(zext(*((sp - 0x80) + ((r4 - 0x1) << 2))) >> 0x8)
  d8:	aa66      	st.h	r3, (r2, 0xc)	// *(0xc) = (zext(*((sp - 0x80) + ((r4 - 0x1) << 2))) >> 0x8)
  da:	dc250340 	st.b	r1, (r5, 0x340)	// *(0x340) = zext8((zext8(r4) - 0x1))
  de:	dc850378 	st.b	r4, (r5, 0x378)	// *(0x378) = zext8(r4)
loc_e2:
  e2:	e0000000 	bsr	0x0	// <lmac_doze_exit>; regs: r0=<ret lmac_doze_exit@0xe2>, r1=<clobbered>
  e6:	100e      	lrw	r0, 0x0	// regs: r0=0x0
  e8:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0xe8>, r1=<clobbered>
  ec:	0796      	br	0x18	// goto loc_18;
loc_ee:
  ee:	d0410443 	ldr.h	r3, (r1, r2 << 1)	// regs: r3=*(<arg1> + (r2 << 1))
  f2:	74cd      	zexth	r3, r3	// regs: r3=zext16(*(<arg1> + (r2 << 1)))
  f4:	7cf4      	mult	r3, r13	// regs: r3=(zext16(*(<arg1> + (r2 << 1))) * 0x64)
  f6:	d44e0883 	str.w	r3, (r14, r2 << 2)
  fa:	d4460883 	str.w	r3, (r6, r2 << 2)
  fe:	e9000005 	bez	r0, 0x108	// if (r0 == 0x0) goto loc_108;
 102:	60f0      	addu	r3, r12	// regs: r3=((zext16(*(<arg1> + (r2 << 1))) * 0x64) + zext(*(0x34a)))
 104:	d4460883 	str.w	r3, (r6, r2 << 2)
loc_108:
 108:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
 10a:	0798      	br	0x3a	// goto loc_3a;
loc_10c:
 10c:	1007      	lrw	r0, 0x0	// regs: r0=0x0
 10e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x10e>, r1=<clobbered>
 112:	07e8      	br	0xe2	// goto loc_e2;
 114:	00000000 	.long	0x00000000	// <.rodata.lmac_cfg_set_chanlist.str1.1>
 118:	00000000 	.long	0x00000000	// <ah_lmac>
 11c:	00000000 	.long	0x00000000	// <ah_lmac+0xbb8>
 120:	00000000 	.long	0x00000000	// <ah_lmac+0xc0>
 124:	00000000 	.long	0x00000000	// <ah_lmac+0x332>
 128:	00000000 	.long	0x00000000	// <.rodata.lmac_cfg_set_chanlist.str1.1+0x1c>

Disassembly of section .text.lmac_cfg_set_freq_range:

00000000 <lmac_cfg_set_freq_range>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	1428      	subi	r14, r14, 32	// regs: r14=(sp - 0x20)
   4:	ea8d001d 	lrw	r13, 0x0	// regs: r13=0x0
   8:	d98d09e2 	ld.b	r12, (r13, 0x9e2)	// regs: r12=*(0x9e2)
   c:	e58c2002 	andi	r12, r12, 2	// regs: r12=(*(0x9e2) & 0x2)
  10:	e92c0030 	bnez	r12, 0x70	// if (r12 != 0x0) goto loc_70;
  14:	e903002e 	bez	r3, 0x70	// if (r3 == 0x0) goto loc_70;
  18:	750f      	sexth	r4, r3	// regs: r4=sext16(<arg3>)
  1a:	c444482c 	lsli	r12, r4, 2	// regs: r12=(sext16(<arg3>) << 0x2)
  1e:	6310      	addu	r12, r4	// regs: r12=((sext16(<arg3>) << 0x2) + sext16(<arg3>))
  20:	6086      	subu	r2, r1	// regs: r2=(<arg2> - <arg1>)
  22:	6330      	addu	r12, r12	// regs: r12=(((sext16(<arg3>) << 0x2) + sext16(<arg3>)) + ((sext16(<arg3>) << 0x2) + sext16(<arg3>)))
  24:	c582804c 	divs	r12, r2, r12	// regs: r12=((<arg2> - <arg1>) / (((sext16(<arg3>) << 0x2) + sext16(<arg3>)) + ((sext16(<arg3>) << 0x2) + sext16(<arg3>))))
  28:	e58c0000 	addi	r12, r12, 1	// regs: r12=(((<arg2> - <arg1>) / (((sext16(<arg3>) << 0x2) + sext16(<arg3>)) + ((sext16(<arg3>) << 0x2) + sext16(<arg3>)))) + 0x1)
  2c:	7731      	zexth	r12, r12	// regs: r12=zext16((((<arg2> - <arg1>) / (((sext16(<arg3>) << 0x2) + sext16(<arg3>)) + ((sext16(<arg3>) << 0x2) + sext16(<arg3>)))) + 0x1))
  2e:	eb0c0010 	cmphsi	r12, 17
  32:	6cb3      	mov	r2, r12	// regs: r2=zext16((((<arg2> - <arg1>) / (((sext16(<arg3>) << 0x2) + sext16(<arg3>)) + ((sext16(<arg3>) << 0x2) + sext16(<arg3>)))) + 0x1))
  34:	0c02      	bf	0x38	// if (r12 < 0x11) goto loc_38;
  36:	3210      	movi	r2, 16	// regs: r2=0x10
loc_38:
  38:	3b41      	cmpnei	r3, 1
  3a:	d98d034a 	ld.b	r12, (r13, 0x34a)	// regs: r12=*(0x34a)
  3e:	6503      	mvcv	r4	// regs: r4=<cond>
  40:	c5845c00 	ins	r12, r4, 0, 0
  44:	dd8d034a 	st.b	r12, (r13, 0x34a)	// *(0x34a) = *(0x34a)
  48:	ea0c000a 	movi	r12, 10	// regs: r12=0xa
  4c:	7cf0      	mult	r3, r12	// regs: r3=(<arg3> * 0xa)
  4e:	7489      	zexth	r2, r2	// regs: r2=zext16(r2)
  50:	ea0c0000 	movi	r12, 0	// regs: r12=0x0
loc_54:
  54:	64b1      	cmplt	r12, r2
  56:	0806      	bt	0x62	// if (r3 != 0x1) goto loc_62;
  58:	6c7b      	mov	r1, r14	// regs: r1=(sp - 0x20)
  5a:	e0000000 	bsr	0x0	// <lmac_cfg_set_chanlist> // arg_bytes: 0; regs: r0=<ret lmac_cfg_set_chanlist@0x5a>, r1=<clobbered>
loc_5e:
  5e:	1408      	addi	r14, r14, 32	// regs: r14=((sp - 0x20) + 0x20)
  60:	1491      	pop	r4, r15
loc_62:
  62:	d58e0441 	str.h	r1, (r14, r12 << 1)
  66:	604c      	addu	r1, r3	// regs: r1=(r1 + (<arg3> * 0xa))
  68:	e58c0000 	addi	r12, r12, 1	// regs: r12=(r12 + 0x1)
  6c:	7445      	zexth	r1, r1	// regs: r1=zext16((r1 + (<arg3> * 0xa)))
  6e:	07f3      	br	0x54	// goto loc_54;
loc_70:
  70:	3000      	movi	r0, 0	// regs: r0=0x0
  72:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  74:	07f5      	br	0x5e	// goto loc_5e;
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_lo_freq_set:

00000000 <lmac_lo_freq_set>: // arg_bytes: 4
   0:	14d4      	push	r4-r7, r15
   2:	1421      	subi	r14, r14, 4	// regs: r14=(sp - 0x4)
   4:	1195      	lrw	r4, 0x0	// regs: r4=0x0
   6:	6dc3      	mov	r7, r0	// regs: r7=<arg0>
   8:	b800      	st.w	r0, (r14, 0x0)	// local_4 = <arg0>
   a:	e0000000 	bsr	0x0	// <lhw_abort_fsm>; regs: r0=<ret lhw_abort_fsm@0xa>, r1=<clobbered>
   e:	d864034a 	ld.b	r3, (r4, 0x34a)	// regs: r3=*(0x34a)
  12:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x34a) & 0x1)
  16:	e9030009 	bez	r3, 0x28	// if (r3 == 0x0) goto loc_28;
  1a:	d86411a5 	ld.h	r3, (r4, 0x34a)	// regs: r3=*(0x34a)
  1e:	9840      	ld.w	r2, (r14, 0x0)	// regs: r2=local_4
  20:	c42355e3 	zext	r3, r3, 15, 1	// regs: r3=zext(*(0x34a))
  24:	60c8      	addu	r3, r2	// regs: r3=(zext(*(0x34a)) + local_4)
  26:	b860      	st.w	r3, (r14, 0x0)	// local_4 = (zext(*(0x34a)) + local_4)
loc_28:
  28:	3000      	movi	r0, 0	// regs: r0=0x0
  2a:	e0000000 	bsr	0x0	// <ah_rf_lo_table_ctrl>; regs: r0=<ret ah_rf_lo_table_ctrl@0x2a>, r1=<clobbered>
  2e:	9800      	ld.w	r0, (r14, 0x0)	// regs: r0=local_4
  30:	e0000000 	bsr	0x0	// <ah_rf_lo_freq_set>; regs: r0=<ret ah_rf_lo_freq_set@0x30>, r1=<clobbered>
  34:	6d43      	mov	r5, r0	// regs: r5=<ret ah_rf_lo_freq_set@0x30>
  36:	11ca      	lrw	r6, 0x0	// regs: r6=0x0
  38:	e920004b 	bnez	r0, 0xce	// if (r0 != 0x0) goto loc_ce;
  3c:	e4672fff 	andi	r3, r7, 4095	// regs: r3=(<arg0> & 0xfff)
  40:	4344      	lsli	r2, r3, 4	// regs: r2=((<arg0> & 0xfff) << 0x4)
  42:	8e63      	ld.h	r3, (r6, 0x6)	// regs: r3=*(0x6)
  44:	e463200f 	andi	r3, r3, 15	// regs: r3=(*(0x6) & 0xf)
  48:	6cc8      	or	r3, r2	// regs: r3=((*(0x6) & 0xf) | ((<arg0> & 0xfff) << 0x4))
  4a:	ea010fff 	movi	r1, 4095	// regs: r1=0xfff
  4e:	6c46      	nor	r1, r1	// regs: r1=(~0xfff)
  50:	8e44      	ld.h	r2, (r6, 0x8)	// regs: r2=*(0x8)
  52:	6884      	and	r2, r1	// regs: r2=(*(0x8) & (~0xfff))
  54:	ae63      	st.h	r3, (r6, 0x6)	// *(0x6) = ((*(0x6) & 0xf) | ((<arg0> & 0xfff) << 0x4))
  56:	c58756e3 	zext	r3, r7, 23, 12	// regs: r3=zext(<arg0>)
  5a:	6cc8      	or	r3, r2	// regs: r3=(zext(<arg0>) | (*(0x8) & (~0xfff)))
  5c:	ae64      	st.h	r3, (r6, 0x8)	// *(0x8) = (zext(<arg0>) | (*(0x8) & (~0xfff)))
  5e:	6c83      	mov	r2, r0	// regs: r2=<ret ah_rf_lo_freq_set@0x30>
  60:	6cc3      	mov	r3, r0	// regs: r3=<ret ah_rf_lo_freq_set@0x30>
  62:	d8240378 	ld.b	r1, (r4, 0x378)	// regs: r1=*(0x378)
  66:	c40756e0 	zext	r0, r7, 23, 0	// regs: r0=zext(<arg0>)
loc_6a:
  6a:	644d      	cmplt	r3, r1
  6c:	080c      	bt	0x84	// if (T) goto loc_84;
  6e:	3101      	movi	r1, 1	// regs: r1=0x1
  70:	6c3b      	mov	r0, r14	// regs: r0=(sp - 0x4)
  72:	e0000000 	bsr	0x0	// <ah_rf_lo_table_cfg>; regs: r0=<ret ah_rf_lo_table_cfg@0x72>, r1=<clobbered>
  76:	6d43      	mov	r5, r0	// regs: r5=<ret ah_rf_lo_table_cfg@0x72>
  78:	e9000026 	bez	r0, 0xc4	// if (r0 == 0x0) goto loc_c4;
  7c:	1019      	lrw	r0, 0x0	// regs: r0=0x0
  7e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x7e>, r1=<clobbered>
  82:	040b      	br	0x98	// goto loc_98;
loc_84:
  84:	2217      	addi	r2, 24	// regs: r2=(r2 + 0x18)
  86:	ea8c0015 	lrw	r12, 0x0	// regs: r12=0x0
  8a:	6308      	addu	r12, r2	// regs: r12=(0x0 + (r2 + 0x18))
  8c:	d98c202a 	ld.w	r12, (r12, 0xa8)	// regs: r12=*(((0x0 + (r2 + 0x18)) + 0xa8))
  90:	6432      	cmpne	r12, r0
  92:	0817      	bt	0xc0	// if (T) goto loc_c0;
  94:	dc64033c 	st.b	r3, (r4, 0x33c)	// *(0x33c) = r3
loc_98:
  98:	d86420ce 	ld.w	r3, (r4, 0x338)	// regs: r3=*(0x338)
  9c:	c4835763 	zext	r3, r3, 27, 4	// regs: r3=zext(*(0x338))
  a0:	a66b      	st.b	r3, (r6, 0xb)	// *(0xb) = zext(*(0x338))
  a2:	4b68      	lsri	r3, r3, 8	// regs: r3=(zext(*(0x338)) >> 0x8)
  a4:	ae66      	st.h	r3, (r6, 0xc)	// *(0xc) = (zext(*(0x338)) >> 0x8)
  a6:	d864033c 	ld.b	r3, (r4, 0x33c)	// regs: r3=*(0x33c)
  aa:	3001      	movi	r0, 1	// regs: r0=0x1
  ac:	dc640340 	st.b	r3, (r4, 0x340)	// *(0x340) = *(0x33c)
  b0:	e0000000 	bsr	0x0	// <ah_rf_lo_table_ctrl>; regs: r0=<ret ah_rf_lo_table_ctrl@0xb0>, r1=<clobbered>
  b4:	3000      	movi	r0, 0	// regs: r0=0x0
  b6:	e0000000 	bsr	0x0	// <lhw_start_rx>; regs: r0=<ret lhw_start_rx@0xb6>, r1=<clobbered>
  ba:	6c17      	mov	r0, r5	// regs: r0=r5
  bc:	1401      	addi	r14, r14, 4	// regs: r14=((sp - 0x4) + 0x4)
  be:	1494      	pop	r4-r7, r15
loc_c0:
  c0:	2300      	addi	r3, 1	// regs: r3=(r3 + 0x1)
  c2:	07d4      	br	0x6a	// goto loc_6a;
loc_c4:
  c4:	dce42030 	st.w	r7, (r4, 0xc0)	// *(0xc0) = <arg0>
  c8:	dca4033c 	st.b	r5, (r4, 0x33c)	// *(0x33c) = <ret ah_rf_lo_table_cfg@0x72>
  cc:	07e6      	br	0x98	// goto loc_98;
loc_ce:
  ce:	6c5f      	mov	r1, r7	// regs: r1=<arg0>
  d0:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  d2:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xd2>, r1=<clobbered>
  d6:	07e1      	br	0x98	// goto loc_98;
  d8:	00000000 	.long	0x00000000	// <ah_lmac>
  dc:	00000000 	.long	0x00000000	// <ah_lmac+0x332>
  e0:	00000000 	.long	0x00000000	// <.rodata.lmac_cfg_set_chanlist.str1.1+0x1c>
  e4:	00000000 	.long	0x00000000	// <.rodata.lmac_lo_freq_set.str1.1>

Disassembly of section .text.lmac_cfg_set_bss_bw:

00000000 <lmac_cfg_set_bss_bw>: // arg_bytes: 8
   0:	14d5      	push	r4-r8, r15
   2:	1428      	subi	r14, r14, 32	// regs: r14=(sp - 0x20)
   4:	1296      	lrw	r4, 0x0	// regs: r4=0x0
   6:	6c87      	mov	r2, r1	// regs: r2=<arg1>
   8:	6e03      	mov	r8, r0	// regs: r8=<arg0>
   a:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   c:	1215      	lrw	r0, 0x0	// regs: r0=0x0
   e:	1236      	lrw	r1, 0x0	// regs: r1=0x0
  10:	d8e40867 	ld.b	r7, (r4, 0x867)	// regs: r7=*(0x867)
  14:	d8c420ce 	ld.w	r6, (r4, 0x338)	// regs: r6=*(0x338)
  18:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x18>, r1=<clobbered>
  1c:	d844034a 	ld.b	r2, (r4, 0x34a)	// regs: r2=*(0x34a)
  20:	3300      	movi	r3, 0	// regs: r3=0x0
  22:	c4435c00 	ins	r2, r3, 0, 0
  26:	dc44034a 	st.b	r2, (r4, 0x34a)	// *(0x34a) = *(0x34a)
  2a:	d8440338 	ld.b	r2, (r4, 0x338)	// regs: r2=*(0x338)
  2e:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0x338) & 0x8)
  32:	3103      	movi	r1, 3	// regs: r1=0x3
  34:	c4865766 	zext	r6, r6, 27, 4	// regs: r6=zext(*(0x338))
  38:	dc240309 	st.b	r1, (r4, 0x309)	// *(0x309) = 0x3
  3c:	dc640865 	st.b	r3, (r4, 0x865)	// *(0x865) = 0x0
  40:	e902002c 	bez	r2, 0x98	// if (r2 == 0x0) goto loc_98;
  44:	d8440875 	ld.b	r2, (r4, 0x875)	// regs: r2=*(0x875)
  48:	3d42      	cmpnei	r5, 2
  4a:	c4435c01 	ins	r2, r3, 1, 1
  4e:	dc440875 	st.b	r2, (r4, 0x875)	// *(0x875) = *(0x875)
  52:	0c0d      	bf	0x6c	// if (r5 == 0x2) goto loc_6c;
  54:	3d02      	cmphsi	r5, 3
  56:	0867      	bt	0x124	// if (r5 >= 0x3) goto loc_124;
  58:	3d41      	cmpnei	r5, 1
  5a:	0c6e      	bf	0x136	// if (r5 == 0x1) goto loc_136;
loc_5c:
  5c:	1203      	lrw	r0, 0x0	// regs: r0=0x0
  5e:	6c57      	mov	r1, r5	// regs: r1=<arg1>
  60:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x60>, r1=<clobbered>
  64:	3000      	movi	r0, 0	// regs: r0=0x0
  66:	2800      	subi	r0, 1	// regs: r0=0xffffffff
loc_68:
  68:	1408      	addi	r14, r14, 32	// regs: r14=(sp + 0x20)
  6a:	1495      	pop	r4-r8, r15
loc_6c:
  6c:	3301      	movi	r3, 1	// regs: r3=0x1
  6e:	dc640308 	st.b	r3, (r4, 0x308)	// *(0x308) = 0x1
  72:	3300      	movi	r3, 0	// regs: r3=0x0
loc_74:
  74:	dc640867 	st.b	r3, (r4, 0x867)	// *(0x867) = r3
  78:	0425      	br	0xc2	// goto loc_c2;
loc_7a:
  7a:	3302      	movi	r3, 2	// regs: r3=0x2
  7c:	dc640308 	st.b	r3, (r4, 0x308)	// *(0x308) = 0x2
  80:	3301      	movi	r3, 1	// regs: r3=0x1
  82:	07f9      	br	0x74	// goto loc_74;
loc_84:
  84:	1116      	lrw	r0, 0x0	// regs: r0=0x0
  86:	6004      	addu	r0, r1	// regs: r0=(0x0 + (r1 + 0x18))
  88:	d800202a 	ld.w	r0, (r0, 0xa8)	// regs: r0=*(((0x0 + (r1 + 0x18)) + 0xa8))
  8c:	c5808020 	divu	r0, r0, r12	// regs: r0=(*(((0x0 + (r1 + 0x18)) + 0xa8)) / r12)
  90:	d46e0440 	str.h	r0, (r14, r3 << 1)
  94:	2300      	addi	r3, 1	// regs: r3=(r3 + 0x1)
  96:	043b      	br	0x10c	// goto loc_10c;
loc_98:
  98:	3d42      	cmpnei	r5, 2
  9a:	0fe9      	bf	0x6c	// if (r5 == 0x2) goto loc_6c;
  9c:	3d02      	cmphsi	r5, 3
  9e:	0843      	bt	0x124	// if (r5 >= 0x3) goto loc_124;
  a0:	3d41      	cmpnei	r5, 1
  a2:	0bdd      	bt	0x5c	// if (r5 != 0x1) goto loc_5c;
  a4:	d864034a 	ld.b	r3, (r4, 0x34a)	// regs: r3=*(0x34a)
  a8:	c4655c00 	ins	r3, r5, 0, 0
  ac:	dca40308 	st.b	r5, (r4, 0x308)	// *(0x308) = <arg1>
  b0:	dc240867 	st.b	r1, (r4, 0x867)	// *(0x867) = 0x3
  b4:	dc64034a 	st.b	r3, (r4, 0x34a)	// *(0x34a) = *(0x34a)
  b8:	dc440309 	st.b	r2, (r4, 0x309)	// *(0x309) = (*(0x338) & 0x8)
loc_bc:
  bc:	3301      	movi	r3, 1	// regs: r3=0x1
  be:	dc640865 	st.b	r3, (r4, 0x865)	// *(0x865) = 0x1
loc_c2:
  c2:	116b      	lrw	r3, 0x0	// regs: r3=0x0
  c4:	9340      	ld.w	r2, (r3, 0x0)	// regs: r2=*(0x0)
  c6:	9270      	ld.w	r3, (r2, 0x40)	// regs: r3=*((*(0x0) + 0x40))
  c8:	3b84      	bclri	r3, 4	// regs: r3=(*((*(0x0) + 0x40)) & ~(0x1 << 0x4))
  ca:	3b85      	bclri	r3, 5	// regs: r3=((*((*(0x0) + 0x40)) & ~(0x1 << 0x4)) & ~(0x1 << 0x5))
  cc:	b270      	st.w	r3, (r2, 0x40)	// *((*(0x0) + 0x40)) = ((*((*(0x0) + 0x40)) & ~(0x1 << 0x4)) & ~(0x1 << 0x5))
  ce:	d8640308 	ld.b	r3, (r4, 0x308)	// regs: r3=*(0x308)
  d2:	4364      	lsli	r3, r3, 4	// regs: r3=(*(0x308) << 0x4)
  d4:	9230      	ld.w	r1, (r2, 0x40)	// regs: r1=*((*(0x0) + 0x40))
  d6:	e4632030 	andi	r3, r3, 48	// regs: r3=((*(0x308) << 0x4) & 0x30)
  da:	6cc4      	or	r3, r1	// regs: r3=(((*(0x308) << 0x4) & 0x30) | *((*(0x0) + 0x40)))
  dc:	b270      	st.w	r3, (r2, 0x40)	// *((*(0x0) + 0x40)) = (((*(0x308) << 0x4) & 0x30) | *((*(0x0) + 0x40)))
  de:	d8040309 	ld.b	r0, (r4, 0x309)	// regs: r0=*(0x309)
  e2:	e0000000 	bsr	0x0	// <ah_wphy_pri_channel_cfg>; regs: r0=<ret ah_wphy_pri_channel_cfg@0xe2>, r1=<clobbered>
  e6:	d8040308 	ld.b	r0, (r4, 0x308)	// regs: r0=*(0x308)
  ea:	e0000000 	bsr	0x0	// <ah_wphy_bw_cfg>; regs: r0=<ret ah_wphy_bw_cfg@0xea>, r1=<clobbered>
  ee:	3005      	movi	r0, 5	// regs: r0=0x5
  f0:	e0000000 	bsr	0x0	// <lmac_rx_gain_cfg>; regs: r0=<ret lmac_rx_gain_cfg@0xf0>, r1=<clobbered>
  f4:	e0000000 	bsr	0x0	// <lmac_tx_vec_init>; regs: r0=<ret lmac_tx_vec_init@0xf4>, r1=<clobbered>
  f8:	3d41      	cmpnei	r5, 1
  fa:	0c03      	bf	0x100	// if (r5 == 0x1) goto loc_100;
  fc:	3f43      	cmpnei	r7, 3
  fe:	080e      	bt	0x11a	// if (r7 != 0x3) goto loc_11a;
loc_100:
 100:	3100      	movi	r1, 0	// regs: r1=0x0
 102:	d8440378 	ld.b	r2, (r4, 0x378)	// regs: r2=*(0x378)
 106:	6cc7      	mov	r3, r1	// regs: r3=0x0
 108:	ea0c0064 	movi	r12, 100	// regs: r12=0x64
loc_10c:
 10c:	648d      	cmplt	r3, r2
 10e:	2117      	addi	r1, 24	// regs: r1=(r1 + 0x18)
 110:	0bba      	bt	0x84	// if (T) goto loc_84;
 112:	6c7b      	mov	r1, r14	// regs: r1=sp
 114:	6c23      	mov	r0, r8	// regs: r0=r8
 116:	e0000000 	bsr	0x0	// <lmac_set_chan_list>; regs: r0=<ret lmac_set_chan_list@0x116>, r1=<clobbered>
loc_11a:
 11a:	6c1b      	mov	r0, r6	// regs: r0=r6
 11c:	e0000000 	bsr	0x0	// <lmac_lo_freq_set> // arg_bytes: 4; regs: r0=<ret lmac_lo_freq_set@0x11c>, r1=<clobbered>
 120:	3000      	movi	r0, 0	// regs: r0=0x0
 122:	07a3      	br	0x68	// goto loc_68;
loc_124:
 124:	3d44      	cmpnei	r5, 4
 126:	0faa      	bf	0x7a	// if (r5 == 0x4) goto loc_7a;
 128:	3d48      	cmpnei	r5, 8
 12a:	0b99      	bt	0x5c	// if (r5 != 0x8) goto loc_5c;
 12c:	3303      	movi	r3, 3	// regs: r3=0x3
 12e:	dc640308 	st.b	r3, (r4, 0x308)	// *(0x308) = 0x3
 132:	3302      	movi	r3, 2	// regs: r3=0x2
 134:	07a0      	br	0x74	// goto loc_74;
loc_136:
 136:	d844034a 	ld.b	r2, (r4, 0x34a)	// regs: r2=*(0x34a)
 13a:	dc640309 	st.b	r3, (r4, 0x309)	// *(0x309) = 0x0
 13e:	d8640875 	ld.b	r3, (r4, 0x875)	// regs: r3=*(0x875)
 142:	c4455c00 	ins	r2, r5, 0, 0
 146:	c4655c01 	ins	r3, r5, 1, 1
 14a:	dca40308 	st.b	r5, (r4, 0x308)	// *(0x308) = <arg1>
 14e:	dc240867 	st.b	r1, (r4, 0x867)	// *(0x867) = 0x3
 152:	dc44034a 	st.b	r2, (r4, 0x34a)	// *(0x34a) = *(0x34a)
 156:	dc640875 	st.b	r3, (r4, 0x875)	// *(0x875) = *(0x875)
 15a:	07b1      	br	0xbc	// goto loc_bc;
 15c:	00000000 	.long	0x00000000	// <ah_lmac>
 160:	00000000 	.long	0x00000000	// <.rodata.lmac_cfg_set_bss_bw.str1.1>
 164:	00000000 	.long	0x00000000	// <.rodata.__func__.13599>
 168:	00000000 	.long	0x00000000	// <.rodata.lmac_cfg_set_bss_bw.str1.1+0x12>
 16c:	00000000 	.long	0x00000000	// <LMAC>

Disassembly of section .text.lmac_cfg_set_freq:

00000000 <lmac_cfg_set_freq>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	6d07      	mov	r4, r1	// regs: r4=<arg1>
   4:	3100      	movi	r1, 0	// regs: r1=0x0
   6:	2900      	subi	r1, 1	// regs: r1=0xffffffff
   8:	100c      	lrw	r0, 0x0	// regs: r0=0x0
   a:	e0000000 	bsr	0x0	// <os_mutex_lock>; regs: r0=<ret os_mutex_lock@0xa>, r1=<clobbered>
   e:	106c      	lrw	r3, 0x0	// regs: r3=0x0
  10:	d86309e2 	ld.b	r3, (r3, 0x9e2)	// regs: r3=*(0x9e2)
  14:	e4632002 	andi	r3, r3, 2	// regs: r3=(*(0x9e2) & 0x2)
  18:	e923000c 	bnez	r3, 0x30	// if (r3 != 0x0) goto loc_30;
  1c:	3064      	movi	r0, 100	// regs: r0=0x64
  1e:	7c10      	mult	r0, r4	// regs: r0=(0x64 * <arg1>)
  20:	e0000000 	bsr	0x0	// <lmac_lo_freq_set> // arg_bytes: 4; regs: r0=<ret lmac_lo_freq_set@0x20>, r1=<clobbered>
  24:	6d03      	mov	r4, r0	// regs: r4=<ret lmac_lo_freq_set@0x20>
loc_26:
  26:	1005      	lrw	r0, 0x0	// regs: r0=0x0
  28:	e0000000 	bsr	0x0	// <os_mutex_unlock>; regs: r0=<ret os_mutex_unlock@0x28>, r1=<clobbered>
  2c:	6c13      	mov	r0, r4	// regs: r0=r4
  2e:	1491      	pop	r4, r15
loc_30:
  30:	3400      	movi	r4, 0	// regs: r4=0x0
  32:	2c00      	subi	r4, 1	// regs: r4=0xffffffff
  34:	07f9      	br	0x26	// goto loc_26;
  36:	0000      	.short	0x0000
  38:	00000000 	.long	0x00000000	// <ah_lmac+0xbb8>
  3c:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_ah_open:

00000000 <lmac_ah_open>: // arg_bytes: 4
   0:	14d1      	push	r4, r15
   2:	6d03      	mov	r4, r0	// regs: r4=<arg0>
   4:	e0000000 	bsr	0x0	// <lmac_doze_exit>; regs: r0=<ret lmac_doze_exit@0x4>, r1=<clobbered>
   8:	846a      	ld.b	r3, (r4, 0xa)	// regs: r3=*(<arg0> + 0xa)
   a:	3201      	movi	r2, 1	// regs: r2=0x1
   c:	c4625c00 	ins	r3, r2, 0, 0
  10:	3000      	movi	r0, 0	// regs: r0=0x0
  12:	a46a      	st.b	r3, (r4, 0xa)	// *(<arg0> + 0xa) = *(<arg0> + 0xa)
  14:	1491      	pop	r4, r15

Disassembly of section .text.lmac_ah_close:

00000000 <lmac_ah_close>: // arg_bytes: 4
   0:	14d2      	push	r4-r5, r15
   2:	6d43      	mov	r5, r0	// regs: r5=<arg0>
   4:	3400      	movi	r4, 0	// regs: r4=0x0
   6:	e0000000 	bsr	0x0	// <lmac_doze_enter>; regs: r0=<ret lmac_doze_enter@0x6>, r1=<clobbered>
   a:	856a      	ld.b	r3, (r5, 0xa)	// regs: r3=*(<arg0> + 0xa)
   c:	c4645c00 	ins	r3, r4, 0, 0
  10:	a56a      	st.b	r3, (r5, 0xa)	// *(<arg0> + 0xa) = *(<arg0> + 0xa)
  12:	e0000000 	bsr	0x0	// <lmac_beacon_timer_abort>; regs: r0=<ret lmac_beacon_timer_abort@0x12>, r1=<clobbered>
  16:	1065      	lrw	r3, 0x0	// regs: r3=0x0
  18:	6c13      	mov	r0, r4	// regs: r0=0x0
  1a:	d84314ef 	ld.h	r2, (r3, 0x9de)	// regs: r2=*(0x9de)
  1e:	c4445c46 	ins	r2, r4, 8, 6
  22:	dc4314ef 	st.h	r2, (r3, 0x9de)	// *(0x9de) = *(0x9de)
  26:	1492      	pop	r4-r5, r15
  28:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_ah_set_key:

00000000 <lmac_ah_set_key>: // arg_bytes: 0
   0:	14d5      	push	r4-r8, r15
   2:	1429      	subi	r14, r14, 36	// regs: r14=(sp - 0x24)
   4:	6d0f      	mov	r4, r3	// regs: r4=<arg3>
   6:	6d8b      	mov	r6, r2	// regs: r6=<arg2>
   8:	9341      	ld.w	r2, (r3, 0x4)	// regs: r2=*(<arg3> + 0x4)
   a:	6dc7      	mov	r7, r1	// regs: r7=<arg1>
   c:	e4622008 	andi	r3, r2, 8	// regs: r3=(*(<arg3> + 0x4) & 0x8)
  10:	8429      	ld.b	r1, (r4, 0x9)	// regs: r1=*(<arg3> + 0x9)
  12:	3b40      	cmpnei	r3, 0
  14:	8660      	ld.b	r3, (r6, 0x0)	// regs: r3=*(<arg2>)
  16:	b828      	st.w	r1, (r14, 0x20)	// local_4 = *(<arg3> + 0x9)
  18:	b846      	st.w	r2, (r14, 0x18)	// local_c = *(<arg3> + 0x4)
  1a:	8428      	ld.b	r1, (r4, 0x8)	// regs: r1=*(<arg3> + 0x8)
  1c:	9440      	ld.w	r2, (r4, 0x0)	// regs: r2=*(<arg3>)
  1e:	b827      	st.w	r1, (r14, 0x1c)	// local_8 = *(<arg3> + 0x8)
  20:	b845      	st.w	r2, (r14, 0x14)	// local_10 = *(<arg3>)
  22:	8645      	ld.b	r2, (r6, 0x5)	// regs: r2=*(<arg2> + 0x5)
  24:	b844      	st.w	r2, (r14, 0x10)	// local_14 = *(<arg2> + 0x5)
  26:	8644      	ld.b	r2, (r6, 0x4)	// regs: r2=*(<arg2> + 0x4)
  28:	b843      	st.w	r2, (r14, 0xc)	// local_18 = *(<arg2> + 0x4)
  2a:	8643      	ld.b	r2, (r6, 0x3)	// regs: r2=*(<arg2> + 0x3)
  2c:	b842      	st.w	r2, (r14, 0x8)	// local_1c = *(<arg2> + 0x3)
  2e:	8642      	ld.b	r2, (r6, 0x2)	// regs: r2=*(<arg2> + 0x2)
  30:	b841      	st.w	r2, (r14, 0x4)	// local_20 = *(<arg2> + 0x2)
  32:	8641      	ld.b	r2, (r6, 0x1)	// regs: r2=*(<arg2> + 0x1)
  34:	1204      	lrw	r0, 0x0	// regs: r0=0x0
  36:	1225      	lrw	r1, 0x0	// regs: r1=0x0
  38:	c4200c40 	inct	r1, r0, 0
  3c:	b840      	st.w	r2, (r14, 0x0)	// local_24 = *(<arg2> + 0x1)
  3e:	e5040009 	addi	r8, r4, 10	// regs: r8=(<arg3> + 0xa)
  42:	6c9f      	mov	r2, r7	// regs: r2=<arg1>
  44:	1202      	lrw	r0, 0x0	// regs: r0=0x0
  46:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x46>, r1=<clobbered>
  4a:	3301      	movi	r3, 1	// regs: r3=0x1
  4c:	8449      	ld.b	r2, (r4, 0x9)	// regs: r2=*(<arg3> + 0x9)
  4e:	6c63      	mov	r1, r8	// regs: r1=(<arg3> + 0xa)
  50:	1200      	lrw	r0, 0x0	// regs: r0=0x0
  52:	e0000000 	bsr	0x0	// <dump_hex>; regs: r0=<ret dump_hex@0x52>, r1=<clobbered>
  56:	e927002a 	bnez	r7, 0xaa	// if (r7 != 0x0) goto loc_aa;
  5a:	8469      	ld.b	r3, (r4, 0x9)	// regs: r3=*(<arg3> + 0x9)
  5c:	3b50      	cmpnei	r3, 16
  5e:	0c26      	bf	0xaa	// if (r3 == 0x10) goto loc_aa;
  60:	eb430020 	cmpnei	r3, 32
  64:	0c25      	bf	0xae	// if (r3 == 0x20) goto loc_ae;
  66:	111c      	lrw	r0, 0x0	// regs: r0=0x0
  68:	3500      	movi	r5, 0	// regs: r5=0x0
  6a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x6a>, r1=<clobbered>
  6e:	2d00      	subi	r5, 1	// regs: r5=0xffffffff
loc_70:
  70:	9461      	ld.w	r3, (r4, 0x4)	// regs: r3=*(<arg3> + 0x4)
  72:	e5832008 	andi	r12, r3, 8	// regs: r12=(*(<arg3> + 0x4) & 0x8)
  76:	e90c002e 	bez	r12, 0xd2	// if (r12 == 0x0) goto loc_d2;
  7a:	6c5b      	mov	r1, r6	// regs: r1=<arg2>
  7c:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
  80:	e0000000 	bsr	0x0	// <lmac_sta_get>; regs: r0=<ret lmac_sta_get@0x80>, r1=<clobbered>
  84:	6d83      	mov	r6, r0	// regs: r6=<ret lmac_sta_get@0x80>
  86:	e9000020 	bez	r0, 0xc6	// if (r0 == 0x0) goto loc_c6;
  8a:	2076      	addi	r0, 119	// regs: r0=(<ret lmac_sta_get@0x80> + 0x77)
  8c:	e9070013 	bez	r7, 0xb2	// if (r7 == 0x0) goto loc_b2;
  90:	3300      	movi	r3, 0	// regs: r3=0x0
  92:	dc660076 	st.b	r3, (r6, 0x76)	// *(<ret lmac_sta_get@0x80> + 0x76) = 0x0
  96:	3220      	movi	r2, 32	// regs: r2=0x20
  98:	3100      	movi	r1, 0	// regs: r1=0x0
  9a:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x9a>, r1=<clobbered>
loc_9e:
  9e:	6c1b      	mov	r0, r6	// regs: r0=<ret lmac_sta_get@0x80>
  a0:	e0000000 	bsr	0x0	// <lmac_sta_put>; regs: r0=<ret lmac_sta_put@0xa0>, r1=<clobbered>
loc_a4:
  a4:	6c17      	mov	r0, r5	// regs: r0=r5
  a6:	1409      	addi	r14, r14, 36	// regs: r14=((sp - 0x24) + 0x24)
  a8:	1495      	pop	r4-r8, r15
loc_aa:
  aa:	3500      	movi	r5, 0	// regs: r5=0x0
  ac:	07e2      	br	0x70	// goto loc_70;
loc_ae:
  ae:	6d5f      	mov	r5, r7	// regs: r5=<arg1>
  b0:	07e0      	br	0x70	// goto loc_70;
loc_b2:
  b2:	8468      	ld.b	r3, (r4, 0x8)	// regs: r3=*(<arg3> + 0x8)
  b4:	dc660075 	st.b	r3, (r6, 0x75)	// *(<ret lmac_sta_get@0x80> + 0x75) = *(<arg3> + 0x8)
  b8:	8449      	ld.b	r2, (r4, 0x9)	// regs: r2=*(<arg3> + 0x9)
  ba:	dc460076 	st.b	r2, (r6, 0x76)	// *(<ret lmac_sta_get@0x80> + 0x76) = *(<arg3> + 0x9)
  be:	6c63      	mov	r1, r8	// regs: r1=(<arg3> + 0xa)
  c0:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0xc0>, r1=<clobbered>
  c4:	07ed      	br	0x9e	// goto loc_9e;
loc_c6:
  c6:	1105      	lrw	r0, 0x0	// regs: r0=0x0
  c8:	3500      	movi	r5, 0	// regs: r5=0x0
  ca:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xca>, r1=<clobbered>
  ce:	2d00      	subi	r5, 1	// regs: r5=0xffffffff
  d0:	07ea      	br	0xa4	// goto loc_a4;
loc_d2:
  d2:	e4232080 	andi	r1, r3, 128	// regs: r1=(*(<arg3> + 0x4) & 0x80)
  d6:	e9070019 	bez	r7, 0x108	// if (r7 == 0x0) goto loc_108;
  da:	e901000c 	bez	r1, 0xf2	// if (r1 == 0x0) goto loc_f2;
  de:	1100      	lrw	r0, 0x0	// regs: r0=0x0
  e0:	3220      	movi	r2, 32	// regs: r2=0x20
  e2:	dd800693 	st.b	r12, (r0, 0x693)	// *(0x693) = (*(<arg3> + 0x4) & 0x8)
  e6:	6c73      	mov	r1, r12	// regs: r1=(*(<arg3> + 0x4) & 0x8)
  e8:	e4000693 	addi	r0, r0, 1684	// regs: r0=0x694
loc_ec:
  ec:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0xec>, r1=<clobbered>
  f0:	07da      	br	0xa4	// goto loc_a4;
loc_f2:
  f2:	e4632100 	andi	r3, r3, 256	// regs: r3=(*(<arg3> + 0x4) & 0x100)
  f6:	e903ffd7 	bez	r3, 0xa4	// if (r3 == 0x0) goto loc_a4;
  fa:	1019      	lrw	r0, 0x0	// regs: r0=0x0
  fc:	3220      	movi	r2, 32	// regs: r2=0x20
  fe:	dc2006b5 	st.b	r1, (r0, 0x6b5)	// *(0x6b5) = (*(<arg3> + 0x4) & 0x80)
 102:	e40006b5 	addi	r0, r0, 1718	// regs: r0=0x6b6
 106:	07f3      	br	0xec	// goto loc_ec;
loc_108:
 108:	e901000f 	bez	r1, 0x126	// if (r1 == 0x0) goto loc_126;
 10c:	1014      	lrw	r0, 0x0	// regs: r0=0x0
 10e:	8468      	ld.b	r3, (r4, 0x8)	// regs: r3=*(<arg3> + 0x8)
 110:	dc600692 	st.b	r3, (r0, 0x692)	// *(0x692) = *(<arg3> + 0x8)
 114:	8449      	ld.b	r2, (r4, 0x9)	// regs: r2=*(<arg3> + 0x9)
 116:	dc400693 	st.b	r2, (r0, 0x693)	// *(0x693) = *(<arg3> + 0x9)
 11a:	6c63      	mov	r1, r8	// regs: r1=(<arg3> + 0xa)
 11c:	e4000693 	addi	r0, r0, 1684	// regs: r0=0x694
loc_120:
 120:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x120>, r1=<clobbered>
 124:	07c0      	br	0xa4	// goto loc_a4;
loc_126:
 126:	e4632100 	andi	r3, r3, 256	// regs: r3=(*(<arg3> + 0x4) & 0x100)
 12a:	e903ffbd 	bez	r3, 0xa4	// if (r3 == 0x0) goto loc_a4;
 12e:	100c      	lrw	r0, 0x0	// regs: r0=0x0
 130:	8468      	ld.b	r3, (r4, 0x8)	// regs: r3=*(<arg3> + 0x8)
 132:	dc6006b4 	st.b	r3, (r0, 0x6b4)	// *(0x6b4) = *(<arg3> + 0x8)
 136:	8449      	ld.b	r2, (r4, 0x9)	// regs: r2=*(<arg3> + 0x9)
 138:	dc4006b5 	st.b	r2, (r0, 0x6b5)	// *(0x6b5) = *(<arg3> + 0x9)
 13c:	6c63      	mov	r1, r8	// regs: r1=(<arg3> + 0xa)
 13e:	e40006b5 	addi	r0, r0, 1718	// regs: r0=0x6b6
 142:	07ef      	br	0x120	// goto loc_120;
 144:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_set_key.str1.1>
 148:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_set_key.str1.1+0x4>
 14c:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_set_key.str1.1+0x8>
 150:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_set_key.str1.1+0x71>
 154:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_set_key.str1.1+0x72>
 158:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_set_key.str1.1+0x92>
 15c:	00000000 	.long	0x00000000	// <ah_lmac>

Disassembly of section .text.lmac_ah_set_mcast_key:

00000000 <lmac_ah_set_mcast_key>: // arg_bytes: 0
   0:	3000      	movi	r0, 0	// regs: r0=0x0
   2:	2800      	subi	r0, 1	// regs: r0=0xffffffff
   4:	783c      	jmp	r15	// return;

Disassembly of section .text.lmac_ah_set_txq_param:

00000000 <lmac_ah_set_txq_param>: // arg_bytes: 0
   0:	14d2      	push	r4-r5, r15
   2:	1422      	subi	r14, r14, 8	// regs: r14=(sp - 0x8)
   4:	3903      	cmphsi	r1, 4
   6:	6d47      	mov	r5, r1	// regs: r5=<arg1>
   8:	6d0b      	mov	r4, r2	// regs: r4=<arg2>
   a:	082d      	bt	0x64	// if (r1 >= 0x4) goto loc_64;
   c:	1018      	lrw	r0, 0x0	// regs: r0=0x0
   e:	5864      	addu	r3, r0, r1	// regs: r3=(0x0 + <arg1>)
  10:	8246      	ld.b	r2, (r2, 0x6)	// regs: r2=*(<arg2> + 0x6)
  12:	a35c      	st.b	r2, (r3, 0x1c)	// *(((0x0 + <arg1>) + 0x1c)) = *(<arg2> + 0x6)
  14:	8c61      	ld.h	r3, (r4, 0x2)	// regs: r3=*(<arg2> + 0x2)
  16:	e4410017 	addi	r2, r1, 24	// regs: r2=(<arg1> + 0x18)
  1a:	d4400443 	str.h	r3, (r0, r2 << 1)
  1e:	e4410013 	addi	r2, r1, 20	// regs: r2=(<arg1> + 0x14)
  22:	d4400443 	str.h	r3, (r0, r2 << 1)
  26:	8c42      	ld.h	r2, (r4, 0x4)	// regs: r2=*(<arg2> + 0x4)
  28:	e461001b 	addi	r3, r1, 28	// regs: r3=(<arg1> + 0x1c)
  2c:	d4600442 	str.h	r2, (r0, r3 << 1)
  30:	32fa      	movi	r2, 250	// regs: r2=0xfa
  32:	8c60      	ld.h	r3, (r4, 0x0)	// regs: r3=*(<arg2>)
  34:	4242      	lsli	r2, r2, 2	// regs: r2=0x3e8
  36:	7cc8      	mult	r3, r2	// regs: r3=(*(<arg2>) * 0x3e8)
  38:	210f      	addi	r1, 16	// regs: r1=(<arg1> + 0x10)
  3a:	d4200883 	str.w	r3, (r0, r1 << 2)
  3e:	3234      	movi	r2, 52	// regs: r2=0x34
  40:	e420001b 	addi	r1, r0, 28	// regs: r1=0x1c
  44:	204f      	addi	r0, 80	// regs: r0=0x50
  46:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x46>, r1=<clobbered>
  4a:	8c20      	ld.h	r1, (r4, 0x0)	// regs: r1=*(<arg2>)
  4c:	b821      	st.w	r1, (r14, 0x4)	// local_4 = *(<arg2>)
  4e:	8c22      	ld.h	r1, (r4, 0x4)	// regs: r1=*(<arg2> + 0x4)
  50:	b820      	st.w	r1, (r14, 0x0)	// local_8 = *(<arg2> + 0x4)
  52:	8c61      	ld.h	r3, (r4, 0x2)	// regs: r3=*(<arg2> + 0x2)
  54:	1007      	lrw	r0, 0x0	// regs: r0=0x0
  56:	8446      	ld.b	r2, (r4, 0x6)	// regs: r2=*(<arg2> + 0x6)
  58:	6c57      	mov	r1, r5	// regs: r1=<arg1>
  5a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x5a>, r1=<clobbered>
  5e:	3000      	movi	r0, 0	// regs: r0=0x0
loc_60:
  60:	1402      	addi	r14, r14, 8	// regs: r14=((sp - 0x8) + 0x8)
  62:	1492      	pop	r4-r5, r15
loc_64:
  64:	3000      	movi	r0, 0	// regs: r0=0x0
  66:	2800      	subi	r0, 1	// regs: r0=0xffffffff
  68:	07fc      	br	0x60	// goto loc_60;
  6a:	0000      	.short	0x0000
  6c:	00000000 	.long	0x00000000	// <ah_lmac>
  70:	00000000 	.long	0x00000000	// <.rodata.lmac_ah_set_txq_param.str1.1>

Disassembly of section .text.lmac_ah_get_acs_result:

00000000 <lmac_ah_get_acs_result>: // arg_bytes: 8
   0:	106f      	lrw	r3, 0x0	// regs: r3=0x0
   2:	3200      	movi	r2, 0	// regs: r2=0x0
loc_4:
   4:	6449      	cmplt	r2, r1
   6:	0803      	bt	0xc	// if (T) goto loc_c;
   8:	4103      	lsli	r0, r1, 3	// regs: r0=(<arg1> << 0x3)
   a:	783c      	jmp	r15	// return;
loc_c:
   c:	d9832000 	ld.w	r12, (r3, 0x0)	// regs: r12=*(r3)
  10:	dd802000 	st.w	r12, (r0, 0x0)	// *(r0) = *(r3)
  14:	d9830006 	ld.b	r12, (r3, 0x6)	// regs: r12=*(r3 + 0x6)
  18:	dd800006 	st.b	r12, (r0, 0x6)	// *(r0 + 0x6) = *(r3 + 0x6)
  1c:	d9830005 	ld.b	r12, (r3, 0x5)	// regs: r12=*(r3 + 0x5)
  20:	dd800005 	st.b	r12, (r0, 0x5)	// *(r0 + 0x5) = *(r3 + 0x5)
  24:	d9830007 	ld.b	r12, (r3, 0x7)	// regs: r12=*(r3 + 0x7)
  28:	dd800007 	st.b	r12, (r0, 0x7)	// *(r0 + 0x7) = *(r3 + 0x7)
  2c:	d9830010 	ld.b	r12, (r3, 0x10)	// regs: r12=*(r3 + 0x10)
  30:	dd800004 	st.b	r12, (r0, 0x4)	// *(r0 + 0x4) = *(r3 + 0x10)
  34:	2200      	addi	r2, 1	// regs: r2=(r2 + 0x1)
  36:	2317      	addi	r3, 24	// regs: r3=(r3 + 0x18)
  38:	2007      	addi	r0, 8	// regs: r0=(r0 + 0x8)
  3a:	07e5      	br	0x4	// goto loc_4;
  3c:	00000000 	.long	0x00000000	// <ah_lmac+0xc0>

Disassembly of section .text.lmac_ah_start_acs:

00000000 <lmac_ah_start_acs>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	1182      	lrw	r4, 0x0	// regs: r4=0x0
   4:	e901003c 	bez	r1, 0x7c	// if (r1 == 0x0) goto loc_7c;
   8:	8160      	ld.b	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
   a:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(<arg1>) & 0x1)
   e:	e9030037 	bez	r3, 0x7c	// if (r3 == 0x0) goto loc_7c;
  12:	8960      	ld.h	r3, (r1, 0x0)	// regs: r3=*(<arg1>)
  14:	e42321fe 	andi	r1, r3, 510	// regs: r1=(*(<arg1>) & 0x1fe)
  18:	e9010006 	bez	r1, 0x24	// if (r1 == 0x0) goto loc_24;
  1c:	c4235503 	zext	r3, r3, 8, 1	// regs: r3=zext(*(<arg1>))
  20:	dc6420d7 	st.w	r3, (r4, 0x35c)	// *(0x35c) = zext(*(<arg1>))
loc_24:
  24:	d86409e0 	ld.b	r3, (r4, 0x9e0)	// regs: r3=*(0x9e0)
  28:	3101      	movi	r1, 1	// regs: r1=0x1
  2a:	c4615c00 	ins	r3, r1, 0, 0
  2e:	dc6409e0 	st.b	r3, (r4, 0x9e0)	// *(0x9e0) = *(0x9e0)
  32:	e922001b 	bnez	r2, 0x68	// if (r2 != 0x0) goto loc_68;
  36:	d84422a1 	ld.w	r2, (r4, 0xa84)	// regs: r2=*(0xa84)
  3a:	5a64      	addu	r3, r2, r1	// regs: r3=(*(0xa84) + 0x1)
  3c:	d80422a2 	ld.w	r0, (r4, 0xa88)	// regs: r0=*(0xa88)
  40:	640d      	cmplt	r3, r0
  42:	c403008c 	subu	r12, r3, r0	// regs: r12=((*(0xa84) + 0x1) - *(0xa88))
  46:	c46c0c20 	incf	r3, r12, 0
  4a:	d80422a0 	ld.w	r0, (r4, 0xa80)	// regs: r0=*(0xa80)
  4e:	640e      	cmpne	r3, r0
  50:	0c07      	bf	0x5e	// if (!T) goto loc_5e;
  52:	e44202a2 	addi	r2, r2, 675	// regs: r2=(*(0xa84) + 0x2a3)
  56:	d4440881 	str.w	r1, (r4, r2 << 2)
  5a:	dc6422a1 	st.w	r3, (r4, 0xa84)	// *(0xa84) = (*(0xa84) + 0x1)
loc_5e:
  5e:	100c      	lrw	r0, 0x0	// regs: r0=0x0
  60:	e0000000 	bsr	0x0	// <os_sema_up>; regs: r0=<ret os_sema_up@0x60>, r1=<clobbered>
  64:	3000      	movi	r0, 0	// regs: r0=0x0
loc_66:
  66:	1491      	pop	r4, r15
loc_68:
  68:	e0000000 	bsr	0x0	// <lmac_auto_channel_select>; regs: r0=<ret lmac_auto_channel_select@0x68>, r1=<clobbered>
  6c:	d86409e0 	ld.b	r3, (r4, 0x9e0)	// regs: r3=*(0x9e0)
  70:	3200      	movi	r2, 0	// regs: r2=0x0
  72:	c4625c00 	ins	r3, r2, 0, 0
loc_76:
  76:	dc6409e0 	st.b	r3, (r4, 0x9e0)	// *(0x9e0) = *(0x9e0)
  7a:	07f6      	br	0x66	// goto loc_66;
loc_7c:
  7c:	d86409e0 	ld.b	r3, (r4, 0x9e0)	// regs: r3=*(0x9e0)
  80:	3000      	movi	r0, 0	// regs: r0=0x0
  82:	c4605c00 	ins	r3, r0, 0, 0
  86:	07f8      	br	0x76	// goto loc_76;
  88:	00000000 	.long	0x00000000	// <ah_lmac>
  8c:	00000000 	.long	0x00000000	// <ah_lmac+0xb90>

Disassembly of section .text.lmac_eth_scan_report:

00000000 <lmac_eth_scan_report>: // arg_bytes: 0
   0:	1066      	lrw	r3, 0x0	// regs: r3=0x0
   2:	d84308bf 	ld.b	r2, (r3, 0x8bf)	// regs: r2=*(0x8bf)
   6:	e9010003 	bez	r1, 0xc	// if (r1 == 0x0) goto loc_c;
   a:	3101      	movi	r1, 1	// regs: r1=0x1
loc_c:
   c:	c4415c01 	ins	r2, r1, 1, 1
  10:	3000      	movi	r0, 0	// regs: r0=0x0
  12:	dc4308bf 	st.b	r2, (r3, 0x8bf)	// *(0x8bf) = *(0x8bf)
  16:	783c      	jmp	r15	// return;
  18:	0000      	.short	0x0000	// <ah_lmac>
  1a:	0000      	.short	0x0000

Disassembly of section .text.lmac_cfg_set_wnb_encrypt:

00000000 <lmac_cfg_set_wnb_encrypt>: // arg_bytes: 0
   0:	14d0      	push	r15
   2:	ea00ffff 	movi	r0, 65535	// regs: r0=0xffff
   6:	e0000000 	bsr	0x0	// <lmac_sta_get>; regs: r0=<ret lmac_sta_get@0x6>, r1=<clobbered>
   a:	e900000b 	bez	r0, 0x20	// if (r0 == 0x0) goto loc_20;
   e:	d84000b9 	ld.b	r2, (r0, 0xb9)	// regs: r2=*(<ret lmac_sta_get@0x6> + 0xb9)
  12:	3101      	movi	r1, 1	// regs: r1=0x1
  14:	c4415c00 	ins	r2, r1, 0, 0
  18:	dc4000b9 	st.b	r2, (r0, 0xb9)	// *(<ret lmac_sta_get@0x6> + 0xb9) = *(<ret lmac_sta_get@0x6> + 0xb9)
  1c:	e0000000 	bsr	0x0	// <lmac_sta_put>; regs: r0=<ret lmac_sta_put@0x1c>, r1=<clobbered>
loc_20:
  20:	3000      	movi	r0, 0	// regs: r0=0x0
  22:	1490      	pop	r15

Disassembly of section .text.lmac_set_cfg:

00000000 <lmac_set_cfg>: // arg_bytes: 16
   0:	14d8      	push	r4-r11, r15
   2:	142a      	subi	r14, r14, 40	// regs: r14=(sp - 0x28)
   4:	2900      	subi	r1, 1	// regs: r1=(<arg1> - 0x1)
   6:	eb010069 	cmphsi	r1, 106
   a:	6d0b      	mov	r4, r2	// regs: r4=<arg2>
   c:	6d4f      	mov	r5, r3	// regs: r5=<arg3>
   e:	0809      	bt	0x20	// if (r1 >= 0x6a) goto loc_20;
  10:	1062      	lrw	r3, 0x0	// regs: r3=0x0
  12:	d0230883 	ldr.w	r3, (r3, r1 << 2)	// regs: r3=*(0x0 + ((<arg1> - 0x1) << 2))
  16:	780c      	jmp	r3	// goto *r3;
  18:	0000      	.short	0x0000	// <.rodata.lmac_set_cfg>
  1a:	0000      	.short	0x0000
  1c:	e9220004 	bnez	r2, 0x24	// if (r2 != 0x0) goto loc_24;
loc_20:
  20:	3400      	movi	r4, 0	// regs: r4=0x0
  22:	0409      	br	0x34	// goto loc_34;
loc_24:
  24:	016e      	lrw	r3, 0x0	// regs: r3=0x0
  26:	dc430315 	st.b	r2, (r3, 0x315)	// *(0x315) = <arg2>
  2a:	07fb      	br	0x20	// goto loc_20;
  2c:	7448      	zextb	r1, r2	// regs: r1=zext8(<arg2>)
  2e:	e0000000 	bsr	0x0	// <lmac_cfg_set_bss_bw> // arg_bytes: 8; regs: r0=<ret lmac_cfg_set_bss_bw@0x2e>, r1=<clobbered>
  32:	6d03      	mov	r4, r0	// regs: r4=<ret lmac_cfg_set_bss_bw@0x2e>
loc_34:
  34:	6c13      	mov	r0, r4	// regs: r0=r4
  36:	140a      	addi	r14, r14, 40	// regs: r14=(sp + 0x28)
  38:	1498      	pop	r4-r11, r15
  3a:	0173      	lrw	r3, 0x0	// regs: r3=0x0
  3c:	7448      	zextb	r1, r2	// regs: r1=zext8(<arg2>)
  3e:	d8430338 	ld.b	r2, (r3, 0x338)	// regs: r2=*(0x338)
  42:	e4422008 	andi	r2, r2, 8	// regs: r2=(*(0x338) & 0x8)
  46:	e902000a 	bez	r2, 0x5a	// if (r2 == 0x0) goto loc_5a;
  4a:	d8030875 	ld.b	r0, (r3, 0x875)	// regs: r0=*(0x875)
  4e:	ea0c0001 	movi	r12, 1	// regs: r12=0x1
  52:	c40c5c01 	ins	r0, r12, 1, 1
  56:	dc030875 	st.b	r0, (r3, 0x875)	// *(0x875) = *(0x875)
loc_5a:
  5a:	d883034a 	ld.b	r4, (r3, 0x34a)	// regs: r4=*(0x34a)
  5e:	e4842001 	andi	r4, r4, 1	// regs: r4=(*(0x34a) & 0x1)
  62:	e9040011 	bez	r4, 0x84	// if (r4 == 0x0) goto loc_84;
  66:	3003      	movi	r0, 3	// regs: r0=0x3
  68:	dc030867 	st.b	r0, (r3, 0x867)	// *(0x867) = 0x3
  6c:	e902ffda 	bez	r2, 0x20	// if (r2 == 0x0) goto loc_20;
  70:	3941      	cmpnei	r1, 1
  72:	0fd7      	bf	0x20	// if (r1 == 0x1) goto loc_20;
loc_74:
  74:	d8430875 	ld.b	r2, (r3, 0x875)	// regs: r2=*(0x875)
  78:	3400      	movi	r4, 0	// regs: r4=0x0
  7a:	c4445c01 	ins	r2, r4, 1, 1
  7e:	dc430875 	st.b	r2, (r3, 0x875)	// *(0x875) = *(0x875)
  82:	07d9      	br	0x34	// goto loc_34;
loc_84:
  84:	3942      	cmpnei	r1, 2
  86:	0c23      	bf	0xcc	// if (r1 == 0x2) goto loc_cc;
  88:	3902      	cmphsi	r1, 3
  8a:	080d      	bt	0xa4	// if (r1 >= 0x3) goto loc_a4;
  8c:	3941      	cmpnei	r1, 1
  8e:	0c15      	bf	0xb8	// if (r1 == 0x1) goto loc_b8;
loc_90:
  90:	0208      	lrw	r0, 0x0	// regs: r0=0x0
  92:	d8230308 	ld.b	r1, (r3, 0x308)	// regs: r1=*(0x308)
  96:	d0200021 	ldr.b	r1, (r0, r1 << 0)	// regs: r1=*(0x0 + (*(0x308) << 0))
  9a:	dc230867 	st.b	r1, (r3, 0x867)	// *(0x867) = *(0x0 + (*(0x308) << 0))
  9e:	e922ffeb 	bnez	r2, 0x74	// if (r2 != 0x0) goto loc_74;
  a2:	07bf      	br	0x20	// goto loc_20;
loc_a4:
  a4:	3944      	cmpnei	r1, 4
  a6:	0c1b      	bf	0xdc	// if (r1 == 0x4) goto loc_dc;
  a8:	3948      	cmpnei	r1, 8
  aa:	0bf3      	bt	0x90	// if (r1 != 0x8) goto loc_90;
  ac:	d8430308 	ld.b	r2, (r3, 0x308)	// regs: r2=*(0x308)
  b0:	3a02      	cmphsi	r2, 3
  b2:	0c23      	bf	0xf8	// if (r2 < 0x3) goto loc_f8;
  b4:	3202      	movi	r2, 2	// regs: r2=0x2
  b6:	0418      	br	0xe6	// goto loc_e6;
loc_b8:
  b8:	3203      	movi	r2, 3	// regs: r2=0x3
  ba:	dc430867 	st.b	r2, (r3, 0x867)	// *(0x867) = 0x3
  be:	d8630308 	ld.b	r3, (r3, 0x308)	// regs: r3=*(0x308)
  c2:	704c      	lsl	r1, r3
  c4:	0214      	lrw	r0, 0x0	// regs: r0=0x0
loc_c6:
  c6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0xc6>, r1=<clobbered>
  ca:	07b5      	br	0x34	// goto loc_34;
loc_cc:
  cc:	dc830867 	st.b	r4, (r3, 0x867)	// *(0x867) = (*(0x34a) & 0x1)
  d0:	3101      	movi	r1, 1	// regs: r1=0x1
  d2:	d8630308 	ld.b	r3, (r3, 0x308)	// regs: r3=*(0x308)
  d6:	704c      	lsl	r1, r3
  d8:	0218      	lrw	r0, 0x0	// regs: r0=0x0
  da:	07f6      	br	0xc6	// goto loc_c6;
loc_dc:
  dc:	d8430308 	ld.b	r2, (r3, 0x308)	// regs: r2=*(0x308)
  e0:	3a01      	cmphsi	r2, 2
  e2:	0c05      	bf	0xec	// if (r2 < 0x2) goto loc_ec;
  e4:	3201      	movi	r2, 1	// regs: r2=0x1
loc_e6:
  e6:	dc430867 	st.b	r2, (r3, 0x867)	// *(0x867) = r2
  ea:	07a5      	br	0x34	// goto loc_34;
loc_ec:
  ec:	3101      	movi	r1, 1	// regs: r1=0x1
  ee:	dc830867 	st.b	r4, (r3, 0x867)	// *(0x867) = (*(0x34a) & 0x1)
  f2:	7048      	lsl	r1, r2
  f4:	021e      	lrw	r0, 0x0	// regs: r0=0x0
  f6:	07e8      	br	0xc6	// goto loc_c6;
loc_f8:
  f8:	3101      	movi	r1, 1	// regs: r1=0x1
  fa:	dc830867 	st.b	r4, (r3, 0x867)	// *(0x867) = (*(0x34a) & 0x1)
  fe:	7048      	lsl	r1, r2
 100:	0300      	lrw	r0, 0x0	// regs: r0=0x0
 102:	07e2      	br	0xc6	// goto loc_c6;
 104:	0366      	lrw	r3, 0x0	// regs: r3=0x0
 106:	dc430866 	st.b	r2, (r3, 0x866)	// *(0x866) = <arg2>
 10a:	078b      	br	0x20	// goto loc_20;
 10c:	0368      	lrw	r3, 0x0	// regs: r3=0x0
 10e:	dc431197 	st.h	r2, (r3, 0x32e)	// *(0x32e) = <arg2>
 112:	0787      	br	0x20	// goto loc_20;
 114:	0364      	lrw	r3, 0x0	// regs: r3=0x0
 116:	6d8f      	mov	r6, r3	// regs: r6=0x0
 118:	d8434006 	ld.bs	r2, (r3, 0x6)	// regs: r2=*(0x6)
 11c:	6509      	cmplt	r2, r4
 11e:	0848      	bt	0x1ae	// if (T) goto loc_1ae;
 120:	3c20      	cmplti	r4, 1
 122:	6d4b      	mov	r5, r2	// regs: r5=*(0x6)
 124:	3300      	movi	r3, 0	// regs: r3=0x0
 126:	c4a40c20 	incf	r5, r4, 0
 12a:	2b00      	subi	r3, 1	// regs: r3=0xffffffff
 12c:	3c20      	cmplti	r4, 1
 12e:	3400      	movi	r4, 0	// regs: r4=0x0
 130:	c4830c40 	inct	r4, r3, 0
loc_134:
 134:	0372      	lrw	r3, 0x0	// regs: r3=0x0
 136:	6c57      	mov	r1, r5	// regs: r1=*(0x6)
 138:	030c      	lrw	r0, 0x0	// regs: r0=0x0
 13a:	dca3068e 	st.b	r5, (r3, 0x68e)	// *(0x68e) = *(0x6)
 13e:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x13e>, r1=<clobbered>
 142:	d8064006 	ld.bs	r0, (r6, 0x6)	// regs: r0=*(0x6)
 146:	6016      	subu	r0, r5	// regs: r0=(*(0x6) - *(0x6))
 148:	e0000000 	bsr	0x0	// <__floatsidf>; regs: r0=<ret __floatsidf@0x148>, r1=<clobbered>
 14c:	3200      	movi	r2, 0	// regs: r2=0x0
 14e:	ea234034 	movih	r3, 16436	// regs: r3=(0x4034 << 0x10)
 152:	e0000000 	bsr	0x0	// <__divdf3>; regs: r0=<ret __divdf3@0x152>, r1=<clobbered>
 156:	6c83      	mov	r2, r0	// regs: r2=<ret __divdf3@0x152>
 158:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
 15a:	3000      	movi	r0, 0	// regs: r0=0x0
 15c:	ea214024 	movih	r1, 16420	// regs: r1=(0x4024 << 0x10)
 160:	e0000000 	bsr	0x0	// <pow>; regs: r0=<ret pow@0x160>, r1=<clobbered>
 164:	6c83      	mov	r2, r0	// regs: r2=<ret pow@0x160>
 166:	6cc7      	mov	r3, r1	// regs: r3=<clobbered>
 168:	3000      	movi	r0, 0	// regs: r0=0x0
 16a:	ea214090 	movih	r1, 16528	// regs: r1=(0x4090 << 0x10)
 16e:	e0000000 	bsr	0x0	// <__divdf3>; regs: r0=<ret __divdf3@0x16e>, r1=<clobbered>
 172:	e0000000 	bsr	0x0	// <__fixunsdfsi>; regs: r0=<ret __fixunsdfsi@0x172>, r1=<clobbered>
 176:	7541      	zexth	r5, r0	// regs: r5=zext16(<ret __fixunsdfsi@0x172>)
 178:	6c17      	mov	r0, r5	// regs: r0=zext16(<ret __fixunsdfsi@0x172>)
 17a:	3103      	movi	r1, 3	// regs: r1=0x3
 17c:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0x17c>, r1=<clobbered>
 180:	6c17      	mov	r0, r5	// regs: r0=zext16(<ret __fixunsdfsi@0x172>)
 182:	3104      	movi	r1, 4	// regs: r1=0x4
 184:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0x184>, r1=<clobbered>
 188:	6c17      	mov	r0, r5	// regs: r0=zext16(<ret __fixunsdfsi@0x172>)
 18a:	3105      	movi	r1, 5	// regs: r1=0x5
 18c:	e0000000 	bsr	0x0	// <ah_rfdigicali_config_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_config_tx_digi_gain@0x18c>, r1=<clobbered>
 190:	3600      	movi	r6, 0	// regs: r6=0x0
 192:	3503      	movi	r5, 3	// regs: r5=0x3
loc_194:
 194:	6c17      	mov	r0, r5	// regs: r0=r5
 196:	2500      	addi	r5, 1	// regs: r5=(r5 + 0x1)
 198:	e0000000 	bsr	0x0	// <ah_rfdigicali_get_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_get_tx_digi_gain@0x198>, r1=<clobbered>
 19c:	7554      	zextb	r5, r5	// regs: r5=zext8((r5 + 0x1))
 19e:	1373      	lrw	r3, 0x0	// regs: r3=0x0
 1a0:	60d8      	addu	r3, r6	// regs: r3=(0x0 + r6)
 1a2:	3d46      	cmpnei	r5, 6
 1a4:	dc031344 	st.h	r0, (r3, 0x688)	// *(((0x0 + r6) + 0x688)) = <ret ah_rfdigicali_get_tx_digi_gain@0x198>
 1a8:	2601      	addi	r6, 2	// regs: r6=(r6 + 0x2)
 1aa:	0bf5      	bt	0x194	// if (r5 != 0x6) goto loc_194;
 1ac:	0744      	br	0x34	// goto loc_34;
loc_1ae:
 1ae:	3400      	movi	r4, 0	// regs: r4=0x0
 1b0:	6d4b      	mov	r5, r2	// regs: r5=*(0x6)
 1b2:	2c00      	subi	r4, 1	// regs: r4=0xffffffff
 1b4:	07c0      	br	0x134	// goto loc_134;
 1b6:	136d      	lrw	r3, 0x0	// regs: r3=0x0
 1b8:	7509      	zexth	r4, r2	// regs: r4=zext16(<arg2>)
 1ba:	dc83133b 	st.h	r4, (r3, 0x676)	// *(0x676) = zext16(<arg2>)
 1be:	d8632233 	ld.w	r3, (r3, 0x8cc)	// regs: r3=*(0x8cc)
 1c2:	e903ff2f 	bez	r3, 0x20	// if (r3 == 0x0) goto loc_20;
 1c6:	dc831504 	st.h	r4, (r3, 0xa08)	// *((*(0x8cc) + 0xa08)) = zext16(<arg2>)
 1ca:	072b      	br	0x20	// goto loc_20;
 1cc:	1367      	lrw	r3, 0x0	// regs: r3=0x0
 1ce:	3a40      	cmpnei	r2, 0
 1d0:	c4000501 	mvc	r1	// regs: r1=<cond>
 1d4:	d8430310 	ld.b	r2, (r3, 0x310)	// regs: r2=*(0x310)
 1d8:	c4415c03 	ins	r2, r1, 3, 3
loc_1dc:
 1dc:	dc430310 	st.b	r2, (r3, 0x310)	// *(0x310) = *(0x310)
 1e0:	0720      	br	0x20	// goto loc_20;
 1e2:	1362      	lrw	r3, 0x0	// regs: r3=0x0
 1e4:	3a40      	cmpnei	r2, 0
 1e6:	c4000501 	mvc	r1	// regs: r1=<cond>
 1ea:	d843037c 	ld.b	r2, (r3, 0x37c)	// regs: r2=*(0x37c)
 1ee:	c4415c01 	ins	r2, r1, 1, 1
 1f2:	dc43037c 	st.b	r2, (r3, 0x37c)	// *(0x37c) = *(0x37c)
 1f6:	0715      	br	0x20	// goto loc_20;
 1f8:	6c4b      	mov	r1, r2	// regs: r1=<arg2>
 1fa:	e0000000 	bsr	0x0	// <lmac_set_radio_onoff> // arg_bytes: 8; regs: r0=<ret lmac_set_radio_onoff@0x1fa>, r1=<clobbered>
 1fe:	0711      	br	0x20	// goto loc_20;
 200:	6c0b      	mov	r0, r2	// regs: r0=<arg2>
 202:	e0000000 	bsr	0x0	// <strlen>; regs: r0=<ret strlen@0x202>, r1=<clobbered>
 206:	eb000020 	cmphsi	r0, 33
 20a:	6c43      	mov	r1, r0	// regs: r1=<ret strlen@0x202>
 20c:	0833      	bt	0x272	// if (r0 >= 0x21) goto loc_272;
 20e:	12b7      	lrw	r5, 0x0	// regs: r5=0x0
 210:	3300      	movi	r3, 0	// regs: r3=0x0
 212:	6c13      	mov	r0, r4	// regs: r0=r4
 214:	dc65052c 	st.b	r3, (r5, 0x52c)	// *(0x52c) = 0x0
 218:	e0000000 	bsr	0x0	// <strlen>; regs: r0=<ret strlen@0x218>, r1=<clobbered>
 21c:	dc05052d 	st.b	r0, (r5, 0x52d)	// *(0x52d) = <ret strlen@0x218>
 220:	3220      	movi	r2, 32	// regs: r2=0x20
 222:	6c53      	mov	r1, r4	// regs: r1=r4
 224:	e405052d 	addi	r0, r5, 1326	// regs: r0=0x52e
 228:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x228>, r1=<clobbered>
 22c:	d8052233 	ld.w	r0, (r5, 0x8cc)	// regs: r0=*(0x8cc)
 230:	e9000008 	bez	r0, 0x240	// if (r0 == 0x0) goto loc_240;
 234:	3220      	movi	r2, 32	// regs: r2=0x20
 236:	6c53      	mov	r1, r4	// regs: r1=r4
 238:	e400025b 	addi	r0, r0, 604	// regs: r0=(*(0x8cc) + 0x25c)
 23c:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x23c>, r1=<clobbered>
loc_240:
 240:	303b      	movi	r0, 59	// regs: r0=0x3b
 242:	e0000000 	bsr	0x0	// <dev_get>; regs: r0=<ret dev_get@0x242>, r1=<clobbered>
 246:	6d83      	mov	r6, r0	// regs: r6=<ret dev_get@0x242>
 248:	3307      	movi	r3, 7	// regs: r3=0x7
 24a:	6c13      	mov	r0, r4	// regs: r0=r4
 24c:	dc6e100e 	st.h	r3, (r14, 0x1c)	// stack_p1c = 0x7
 250:	b888      	st.w	r4, (r14, 0x20)	// stack_p20 = r4
 252:	e0000000 	bsr	0x0	// <strlen>; regs: r0=<ret strlen@0x252>, r1=<clobbered>
 256:	9642      	ld.w	r2, (r6, 0x8)	// regs: r2=*(<ret dev_get@0x242> + 0x8)
 258:	3300      	movi	r3, 0	// regs: r3=0x0
 25a:	d9822003 	ld.w	r12, (r2, 0xc)	// regs: r12=*((*(<ret dev_get@0x242> + 0x8) + 0xc))
 25e:	b809      	st.w	r0, (r14, 0x24)	// stack_p24 = <ret strlen@0x252>
 260:	dc652154 	st.w	r3, (r5, 0x550)	// *(0x550) = 0x0
 264:	e90cfede 	bez	r12, 0x20	// if (r12 == 0x0) goto loc_20;
 268:	1248      	lrw	r2, 0x0	// regs: r2=0x0
 26a:	1907      	addi	r1, r14, 28	// regs: r1=(sp + 0x1c)
 26c:	6c1b      	mov	r0, r6	// regs: r0=<ret dev_get@0x242>
 26e:	7bf1      	jsr	r12
 270:	06d8      	br	0x20	// goto loc_20;
loc_272:
 272:	1207      	lrw	r0, 0x0	// regs: r0=0x0
loc_274:
 274:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x274>, r1=<clobbered>
 278:	06d4      	br	0x20	// goto loc_20;
 27a:	117c      	lrw	r3, 0x0	// regs: r3=0x0
 27c:	d8632233 	ld.w	r3, (r3, 0x8cc)	// regs: r3=*(0x8cc)
 280:	e903fed0 	bez	r3, 0x20	// if (r3 == 0x0) goto loc_20;
 284:	8355      	ld.b	r2, (r3, 0x15)	// regs: r2=*((*(0x8cc) + 0x15))
 286:	c4445c40 	ins	r2, r4, 2, 0
 28a:	a355      	st.b	r2, (r3, 0x15)	// *((*(0x8cc) + 0x15)) = *((*(0x8cc) + 0x15))
 28c:	06ca      	br	0x20	// goto loc_20;
 28e:	1177      	lrw	r3, 0x0	// regs: r3=0x0
 290:	d8632233 	ld.w	r3, (r3, 0x8cc)	// regs: r3=*(0x8cc)
 294:	e903fec6 	bez	r3, 0x20	// if (r3 == 0x0) goto loc_20;
 298:	ab47      	st.h	r2, (r3, 0xe)	// *((*(0x8cc) + 0xe)) = <arg2>
 29a:	06c3      	br	0x20	// goto loc_20;
 29c:	e902fec2 	bez	r2, 0x20	// if (r2 == 0x0) goto loc_20;
 2a0:	1172      	lrw	r3, 0x0	// regs: r3=0x0
 2a2:	d8232233 	ld.w	r1, (r3, 0x8cc)	// regs: r1=*(0x8cc)
 2a6:	e901000a 	bez	r1, 0x2ba	// if (r1 == 0x0) goto loc_2ba;
 2aa:	d8410258 	ld.b	r2, (r1, 0x258)	// regs: r2=*((*(0x8cc) + 0x258))
 2ae:	c4445cc0 	ins	r2, r4, 6, 0
 2b2:	c4455c07 	ins	r2, r5, 7, 7
 2b6:	dc410258 	st.b	r2, (r1, 0x258)	// *((*(0x8cc) + 0x258)) = *((*(0x8cc) + 0x258))
loc_2ba:
 2ba:	d843031a 	ld.b	r2, (r3, 0x31a)	// regs: r2=*(0x31a)
 2be:	e424207f 	andi	r1, r4, 127	// regs: r1=(r4 & 0x7f)
 2c2:	c4415cc1 	ins	r2, r1, 7, 1
 2c6:	d803031b 	ld.b	r0, (r3, 0x31b)	// regs: r0=*(0x31b)
 2ca:	dc43031a 	st.b	r2, (r3, 0x31a)	// *(0x31a) = *(0x31a)
 2ce:	e4452001 	andi	r2, r5, 1	// regs: r2=(r5 & 0x1)
 2d2:	c4025c00 	ins	r0, r2, 0, 0
 2d6:	dc03031b 	st.b	r0, (r3, 0x31b)	// *(0x31b) = *(0x31b)
 2da:	110e      	lrw	r0, 0x0	// regs: r0=0x0
 2dc:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x2dc>, r1=<clobbered>
 2e0:	06a0      	br	0x20	// goto loc_20;
 2e2:	e4822003 	andi	r4, r2, 3	// regs: r4=(<arg2> & 0x3)
 2e6:	1141      	lrw	r2, 0x0	// regs: r2=0x0
 2e8:	d862036d 	ld.b	r3, (r2, 0x36d)	// regs: r3=*(0x36d)
 2ec:	c4645c22 	ins	r3, r4, 3, 2
 2f0:	c4645c24 	ins	r3, r4, 5, 4
 2f4:	dc62036d 	st.b	r3, (r2, 0x36d)	// *(0x36d) = *(0x36d)
 2f8:	0694      	br	0x20	// goto loc_20;
 2fa:	3a40      	cmpnei	r2, 0
 2fc:	1166      	lrw	r3, 0x0	// regs: r3=0x0
 2fe:	1127      	lrw	r1, 0x0	// regs: r1=0x0
 300:	10ba      	lrw	r5, 0x0	// regs: r5=0x0
 302:	c4230c20 	incf	r1, r3, 0
 306:	1106      	lrw	r0, 0x0	// regs: r0=0x0
 308:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x308>, r1=<clobbered>
 30c:	d8452233 	ld.w	r2, (r5, 0x8cc)	// regs: r2=*(0x8cc)
 310:	e902013c 	bez	r2, 0x588	// if (r2 == 0x0) goto loc_588;
 314:	d862025a 	ld.b	r3, (r2, 0x25a)	// regs: r3=*((*(0x8cc) + 0x25a))
 318:	c4645c00 	ins	r3, r4, 0, 0
 31c:	dc62025a 	st.b	r3, (r2, 0x25a)	// *((*(0x8cc) + 0x25a)) = *((*(0x8cc) + 0x25a))
 320:	74cc      	zextb	r3, r3	// regs: r3=zext8(*((*(0x8cc) + 0x25a)))
 322:	e4232001 	andi	r1, r3, 1	// regs: r1=(zext8(*((*(0x8cc) + 0x25a))) & 0x1)
 326:	e901fe7d 	bez	r1, 0x20	// if (r1 == 0x0) goto loc_20;
 32a:	311e      	movi	r1, 30	// regs: r1=0x1e
 32c:	c4615cc1 	ins	r3, r1, 7, 1
 330:	dc62025a 	st.b	r3, (r2, 0x25a)	// *((*(0x8cc) + 0x25a)) = zext8(*((*(0x8cc) + 0x25a)))
 334:	e46320fc 	andi	r3, r3, 252	// regs: r3=(zext8(*((*(0x8cc) + 0x25a))) & 0xfc)
 338:	eb43003c 	cmpnei	r3, 60
 33c:	0804      	bt	0x344	// if (r3 != 0x3c) goto loc_344;
 33e:	3000      	movi	r0, 0	// regs: r0=0x0
 340:	e0000000 	bsr	0x0	// <jtag_map_set>; regs: r0=<ret jtag_map_set@0x340>, r1=<clobbered>
loc_344:
 344:	d8652233 	ld.w	r3, (r5, 0x8cc)	// regs: r3=*(0x8cc)
 348:	3101      	movi	r1, 1	// regs: r1=0x1
 34a:	d803025a 	ld.b	r0, (r3, 0x25a)	// regs: r0=*((*(0x8cc) + 0x25a))
 34e:	7005      	lsr	r0, r1
 350:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x350>, r1=<clobbered>
 354:	d8652233 	ld.w	r3, (r5, 0x8cc)	// regs: r3=*(0x8cc)
 358:	3100      	movi	r1, 0	// regs: r1=0x0
 35a:	d803025a 	ld.b	r0, (r3, 0x25a)	// regs: r0=*((*(0x8cc) + 0x25a))
 35e:	4801      	lsri	r0, r0, 1	// regs: r0=(*((*(0x8cc) + 0x25a)) >> 0x1)
 360:	e0000000 	bsr	0x0	// <gpio_set_val>; regs: r0=<ret gpio_set_val@0x360>, r1=<clobbered>
 364:	065e      	br	0x20	// goto loc_20;
 366:	0000      	.short	0x0000
 368:	00000000 	.long	0x00000000	// <ah_lmac>
 36c:	00000000 	.long	0x00000000	// <bw_map_bss2sig>
 370:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x7>
 374:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x23>
 378:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x3f>
 37c:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x7e>
 380:	00000000 	.long	0x00000000	// <module_efuse_info>
 384:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0xbd>
 388:	00000000 	.long	0x00000000	// <ah_lmac+0x550>
 38c:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0xd7>
 390:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0xf4>
 394:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x4>
 398:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1>
 39c:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x109>
 3a0:	6c4b      	mov	r1, r2	// regs: r1=<arg2>
 3a2:	3000      	movi	r0, 0	// regs: r0=0x0
 3a4:	e0000000 	bsr	0x0	// <lmac_sta_get>; regs: r0=<ret lmac_sta_get@0x3a4>, r1=<clobbered>
 3a8:	e900fe3c 	bez	r0, 0x20	// if (r0 == 0x0) goto loc_20;
 3ac:	3d40      	cmpnei	r5, 0
 3ae:	d840006b 	ld.b	r2, (r0, 0x6b)	// regs: r2=*(<ret lmac_sta_get@0x3a4> + 0x6b)
 3b2:	c4000501 	mvc	r1	// regs: r1=<cond>
 3b6:	c4415c04 	ins	r2, r1, 4, 4
 3ba:	dc40006b 	st.b	r2, (r0, 0x6b)	// *(<ret lmac_sta_get@0x3a4> + 0x6b) = *(<ret lmac_sta_get@0x3a4> + 0x6b)
 3be:	e0000000 	bsr	0x0	// <lmac_sta_put>; regs: r0=<ret lmac_sta_put@0x3be>, r1=<clobbered>
 3c2:	062f      	br	0x20	// goto loc_20;
 3c4:	01f9      	lrw	r7, 0x0	// regs: r7=0x0
 3c6:	d8072295 	ld.w	r0, (r7, 0xa54)	// regs: r0=*(0xa54)
 3ca:	e0000000 	bsr	0x0	// <kfree_skb>; regs: r0=<ret kfree_skb@0x3ca>, r1=<clobbered>
 3ce:	3300      	movi	r3, 0	// regs: r3=0x0
 3d0:	dc672295 	st.w	r3, (r7, 0xa54)	// *(0xa54) = 0x0
 3d4:	dc6720e9 	st.w	r3, (r7, 0x3a4)	// *(0x3a4) = 0x0
 3d8:	331e      	movi	r3, 30	// regs: r3=0x1e
 3da:	dc6720ea 	st.w	r3, (r7, 0x3a8)	// *(0x3a8) = 0x1e
 3de:	e904fe21 	bez	r4, 0x20	// if (r4 == 0x0) goto loc_20;
 3e2:	6c57      	mov	r1, r5	// regs: r1=r5
 3e4:	0200      	lrw	r0, 0x0	// regs: r0=0x0
 3e6:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x3e6>, r1=<clobbered>
 3ea:	9468      	ld.w	r3, (r4, 0x20)	// regs: r3=*(r4 + 0x20)
 3ec:	9409      	ld.w	r0, (r4, 0x24)	// regs: r0=*(r4 + 0x24)
 3ee:	600e      	subu	r0, r3	// regs: r0=(*(r4 + 0x24) - *(r4 + 0x20))
 3f0:	e0000000 	bsr	0x0	// <alloc_tx_skb>; regs: r0=<ret alloc_tx_skb@0x3f0>, r1=<clobbered>
 3f4:	d86720ee 	ld.w	r3, (r7, 0x3b8)	// regs: r3=*(0x3b8)
 3f8:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x3b8) & 0x8)
 3fc:	6d83      	mov	r6, r0	// regs: r6=<ret alloc_tx_skb@0x3f0>
 3fe:	e903000a 	bez	r3, 0x412	// if (r3 == 0x0) goto loc_412;
 402:	8c34      	ld.h	r1, (r4, 0x28)	// regs: r1=*(r4 + 0x28)
 404:	0207      	lrw	r0, 0x0	// regs: r0=0x0
 406:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x406>, r1=<clobbered>
 40a:	8c34      	ld.h	r1, (r4, 0x28)	// regs: r1=*(r4 + 0x28)
 40c:	9407      	ld.w	r0, (r4, 0x1c)	// regs: r0=*(r4 + 0x1c)
 40e:	e0000000 	bsr	0x0	// <hgics_print_hex>; regs: r0=<ret hgics_print_hex@0x40e>, r1=<clobbered>
loc_412:
 412:	e906fe07 	bez	r6, 0x20	// if (r6 == 0x0) goto loc_20;
 416:	9468      	ld.w	r3, (r4, 0x20)	// regs: r3=*(r4 + 0x20)
 418:	9427      	ld.w	r1, (r4, 0x1c)	// regs: r1=*(r4 + 0x1c)
 41a:	604e      	subu	r1, r3	// regs: r1=(*(r4 + 0x1c) - *(r4 + 0x20))
 41c:	210f      	addi	r1, 16	// regs: r1=((*(r4 + 0x1c) - *(r4 + 0x20)) + 0x10)
 41e:	6c1b      	mov	r0, r6	// regs: r0=<ret alloc_tx_skb@0x3f0>
 420:	e0000000 	bsr	0x0	// <skb_reserve>; regs: r0=<ret skb_reserve@0x420>, r1=<clobbered>
 424:	9607      	ld.w	r0, (r6, 0x1c)	// regs: r0=*(<ret alloc_tx_skb@0x3f0> + 0x1c)
 426:	280c      	subi	r0, 13	// regs: r0=(*(<ret alloc_tx_skb@0x3f0> + 0x1c) - 0xd)
 428:	3880      	bclri	r0, 0	// regs: r0=((*(<ret alloc_tx_skb@0x3f0> + 0x1c) - 0xd) & ~(0x1 << 0x0))
 42a:	3881      	bclri	r0, 1	// regs: r0=(((*(<ret alloc_tx_skb@0x3f0> + 0x1c) - 0xd) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
 42c:	320c      	movi	r2, 12	// regs: r2=0xc
 42e:	3100      	movi	r1, 0	// regs: r1=0x0
 430:	b60d      	st.w	r0, (r6, 0x34)	// *(<ret alloc_tx_skb@0x3f0> + 0x34) = (((*(<ret alloc_tx_skb@0x3f0> + 0x1c) - 0xd) & ~(0x1 << 0x0)) & ~(0x1 << 0x1))
 432:	e0000000 	bsr	0x0	// <memset>; regs: r0=<ret memset@0x432>, r1=<clobbered>
 436:	8c54      	ld.h	r2, (r4, 0x28)	// regs: r2=*(r4 + 0x28)
 438:	9427      	ld.w	r1, (r4, 0x1c)	// regs: r1=*(r4 + 0x1c)
 43a:	9607      	ld.w	r0, (r6, 0x1c)	// regs: r0=*(<ret alloc_tx_skb@0x3f0> + 0x1c)
 43c:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x43c>, r1=<clobbered>
 440:	8c34      	ld.h	r1, (r4, 0x28)	// regs: r1=*(r4 + 0x28)
 442:	6c1b      	mov	r0, r6	// regs: r0=<ret alloc_tx_skb@0x3f0>
 444:	e0000000 	bsr	0x0	// <skb_put>; regs: r0=<ret skb_put@0x444>, r1=<clobbered>
 448:	32fa      	movi	r2, 250	// regs: r2=0xfa
 44a:	4242      	lsli	r2, r2, 2	// regs: r2=0x3e8
 44c:	7c94      	mult	r2, r5	// regs: r2=(0x3e8 * r5)
 44e:	dc4720e9 	st.w	r2, (r7, 0x3a4)	// *(0x3a4) = (0x3e8 * r5)
 452:	dcc72295 	st.w	r6, (r7, 0xa54)	// *(0xa54) = <ret alloc_tx_skb@0x3f0>
 456:	d866002a 	ld.b	r3, (r6, 0x2a)	// regs: r3=*(<ret alloc_tx_skb@0x3f0> + 0x2a)
 45a:	3201      	movi	r2, 1	// regs: r2=0x1
 45c:	c4625c06 	ins	r3, r2, 6, 6
 460:	dc66002a 	st.b	r3, (r6, 0x2a)	// *(<ret alloc_tx_skb@0x3f0> + 0x2a) = *(<ret alloc_tx_skb@0x3f0> + 0x2a)
 464:	d86720ee 	ld.w	r3, (r7, 0x3b8)	// regs: r3=*(0x3b8)
 468:	e4632008 	andi	r3, r3, 8	// regs: r3=(*(0x3b8) & 0x8)
 46c:	e903fdda 	bez	r3, 0x20	// if (r3 == 0x0) goto loc_20;
 470:	8e34      	ld.h	r1, (r6, 0x28)	// regs: r1=*(<ret alloc_tx_skb@0x3f0> + 0x28)
 472:	0302      	lrw	r0, 0x0	// regs: r0=0x0
 474:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x474>, r1=<clobbered>
 478:	8e34      	ld.h	r1, (r6, 0x28)	// regs: r1=*(<ret alloc_tx_skb@0x3f0> + 0x28)
 47a:	9607      	ld.w	r0, (r6, 0x1c)	// regs: r0=*(<ret alloc_tx_skb@0x3f0> + 0x1c)
 47c:	e0000000 	bsr	0x0	// <hgics_print_hex>; regs: r0=<ret hgics_print_hex@0x47c>, r1=<clobbered>
 480:	e800fdd0 	br	0x20	// goto loc_20;
 484:	0369      	lrw	r3, 0x0	// regs: r3=0x0
 486:	e4c22003 	andi	r6, r2, 3	// regs: r6=(<arg2> & 0x3)
 48a:	3c41      	cmpnei	r4, 1
 48c:	d84303df 	ld.b	r2, (r3, 0x3df)	// regs: r2=*(0x3df)
 490:	c4465c20 	ins	r2, r6, 1, 0
 494:	dc4303df 	st.b	r2, (r3, 0x3df)	// *(0x3df) = *(0x3df)
 498:	6d4f      	mov	r5, r3	// regs: r5=0x0
 49a:	0812      	bt	0x4be	// if (r4 != 0x1) goto loc_4be;
 49c:	e0000000 	bsr	0x0	// <pmu_vdd13_ldo_dis_sec>; regs: r0=<ret pmu_vdd13_ldo_dis_sec@0x49c>, r1=<clobbered>
 4a0:	030d      	lrw	r0, 0x0	// regs: r0=0x0
loc_4a2:
 4a2:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x4a2>, r1=<clobbered>
 4a6:	d8652233 	ld.w	r3, (r5, 0x8cc)	// regs: r3=*(0x8cc)
 4aa:	e903006f 	bez	r3, 0x588	// if (r3 == 0x0) goto loc_588;
 4ae:	d843025b 	ld.b	r2, (r3, 0x25b)	// regs: r2=*((*(0x8cc) + 0x25b))
 4b2:	c4465c20 	ins	r2, r6, 1, 0
loc_4b6:
 4b6:	dc43025b 	st.b	r2, (r3, 0x25b)	// *((*(0x8cc) + 0x25b)) = *((*(0x8cc) + 0x25b))
 4ba:	e800fdb3 	br	0x20	// goto loc_20;
loc_4be:
 4be:	3c42      	cmpnei	r4, 2
 4c0:	0809      	bt	0x4d2	// if (r4 != 0x2) goto loc_4d2;
 4c2:	3005      	movi	r0, 5	// regs: r0=0x5
 4c4:	e0000000 	bsr	0x0	// <pmu_vdd13c_vol_set_sec>; regs: r0=<ret pmu_vdd13c_vol_set_sec@0x4c4>, r1=<clobbered>
 4c8:	3005      	movi	r0, 5	// regs: r0=0x5
 4ca:	e0000000 	bsr	0x0	// <pmu_vdd13b_vol_set_sec>; regs: r0=<ret pmu_vdd13b_vol_set_sec@0x4ca>, r1=<clobbered>
 4ce:	0317      	lrw	r0, 0x0	// regs: r0=0x0
 4d0:	07e9      	br	0x4a2	// goto loc_4a2;
loc_4d2:
 4d2:	3004      	movi	r0, 4	// regs: r0=0x4
 4d4:	e0000000 	bsr	0x0	// <pmu_vdd13c_vol_set_sec>; regs: r0=<ret pmu_vdd13c_vol_set_sec@0x4d4>, r1=<clobbered>
 4d8:	3004      	movi	r0, 4	// regs: r0=0x4
 4da:	e0000000 	bsr	0x0	// <pmu_vdd13b_vol_set_sec>; regs: r0=<ret pmu_vdd13b_vol_set_sec@0x4da>, r1=<clobbered>
 4de:	031a      	lrw	r0, 0x0	// regs: r0=0x0
 4e0:	07e1      	br	0x4a2	// goto loc_4a2;
 4e2:	137f      	lrw	r3, 0x0	// regs: r3=0x0
 4e4:	dc4311ee 	st.h	r2, (r3, 0x3dc)	// *(0x3dc) = <arg2>
 4e8:	e800fd9c 	br	0x20	// goto loc_20;
 4ec:	5a63      	subi	r3, r2, 1	// regs: r3=(<arg2> - 0x1)
 4ee:	eb0300fe 	cmphsi	r3, 255
 4f2:	137b      	lrw	r3, 0x0	// regs: r3=0x0
 4f4:	080b      	bt	0x50a	// if (r3 >= 0xff) goto loc_50a;
 4f6:	dc430313 	st.b	r2, (r3, 0x313)	// *(0x313) = <arg2>
loc_4fa:
 4fa:	5d43      	subi	r2, r5, 1	// regs: r2=(r5 - 0x1)
 4fc:	eb0200fe 	cmphsi	r2, 255
 500:	0809      	bt	0x512	// if (r2 >= 0xff) goto loc_512;
 502:	dca30312 	st.b	r5, (r3, 0x312)	// *(0x312) = r5
 506:	e800fd8d 	br	0x20	// goto loc_20;
loc_50a:
 50a:	3207      	movi	r2, 7	// regs: r2=0x7
 50c:	dc430313 	st.b	r2, (r3, 0x313)	// *(0x313) = 0x7
 510:	07f5      	br	0x4fa	// goto loc_4fa;
loc_512:
 512:	321f      	movi	r2, 31	// regs: r2=0x1f
 514:	dc430312 	st.b	r2, (r3, 0x312)	// *(0x312) = 0x1f
 518:	e800fd84 	br	0x20	// goto loc_20;
 51c:	6c4b      	mov	r1, r2	// regs: r1=<arg2>
 51e:	1316      	lrw	r0, 0x0	// regs: r0=0x0
 520:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x520>, r1=<clobbered>
 524:	136e      	lrw	r3, 0x0	// regs: r3=0x0
 526:	d8632233 	ld.w	r3, (r3, 0x8cc)	// regs: r3=*(0x8cc)
 52a:	e903002f 	bez	r3, 0x588	// if (r3 == 0x0) goto loc_588;
 52e:	dc8320ad 	st.w	r4, (r3, 0x2b4)	// *((*(0x8cc) + 0x2b4)) = r4
 532:	e800fd77 	br	0x20	// goto loc_20;
 536:	6c4b      	mov	r1, r2	// regs: r1=<arg2>
 538:	1310      	lrw	r0, 0x0	// regs: r0=0x0
 53a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x53a>, r1=<clobbered>
 53e:	1368      	lrw	r3, 0x0	// regs: r3=0x0
 540:	d8632233 	ld.w	r3, (r3, 0x8cc)	// regs: r3=*(0x8cc)
 544:	e9030022 	bez	r3, 0x588	// if (r3 == 0x0) goto loc_588;
 548:	3c40      	cmpnei	r4, 0
 54a:	c4000501 	mvc	r1	// regs: r1=<cond>
 54e:	d843025b 	ld.b	r2, (r3, 0x25b)	// regs: r2=*((*(0x8cc) + 0x25b))
 552:	dc8320ae 	st.w	r4, (r3, 0x2b8)	// *((*(0x8cc) + 0x2b8)) = r4
 556:	c4415c03 	ins	r2, r1, 3, 3
 55a:	07ae      	br	0x4b6	// goto loc_4b6;
 55c:	1308      	lrw	r0, 0x0	// regs: r0=0x0
 55e:	0416      	br	0x58a	// goto loc_58a;
 560:	1308      	lrw	r0, 0x0	// regs: r0=0x0
 562:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x562>, r1=<clobbered>
 566:	127e      	lrw	r3, 0x0	// regs: r3=0x0
 568:	d8632233 	ld.w	r3, (r3, 0x8cc)	// regs: r3=*(0x8cc)
 56c:	e903000e 	bez	r3, 0x588	// if (r3 == 0x0) goto loc_588;
 570:	dc832298 	st.w	r4, (r3, 0xa60)	// *((*(0x8cc) + 0xa60)) = r4
 574:	e800fd56 	br	0x20	// goto loc_20;
 578:	1303      	lrw	r0, 0x0	// regs: r0=0x0
loc_57a:
 57a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x57a>, r1=<clobbered>
 57e:	1278      	lrw	r3, 0x0	// regs: r3=0x0
 580:	d8632233 	ld.w	r3, (r3, 0x8cc)	// regs: r3=*(0x8cc)
 584:	e923fd4e 	bnez	r3, 0x20	// if (r3 != 0x0) goto loc_20;
loc_588:
 588:	1300      	lrw	r0, 0x0	// regs: r0=0x0
loc_58a:
 58a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x58a>, r1=<clobbered>
 58e:	e800fd49 	br	0x20	// goto loc_20;
 592:	121f      	lrw	r0, 0x0	// regs: r0=0x0
 594:	07f3      	br	0x57a	// goto loc_57a;
 596:	1272      	lrw	r3, 0x0	// regs: r3=0x0
 598:	dc4303de 	st.b	r2, (r3, 0x3de)	// *(0x3de) = <arg2>
 59c:	e800fd42 	br	0x20	// goto loc_20;
 5a0:	126f      	lrw	r3, 0x0	// regs: r3=0x0
 5a2:	dc430868 	st.b	r2, (r3, 0x868)	// *(0x868) = <arg2>
 5a6:	e800fd3d 	br	0x20	// goto loc_20;
 5aa:	5a63      	subi	r3, r2, 1	// regs: r3=(<arg2> - 0x1)
 5ac:	3b01      	cmphsi	r3, 2
 5ae:	080d      	bt	0x5c8	// if (r3 >= 0x2) goto loc_5c8;
 5b0:	124b      	lrw	r2, 0x0	// regs: r2=0x0
 5b2:	d862034a 	ld.b	r3, (r2, 0x34a)	// regs: r3=*(0x34a)
 5b6:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x34a) & 0x1)
 5ba:	3b40      	cmpnei	r3, 0
 5bc:	64c3      	mvcv	r3	// regs: r3=<cond>
 5be:	2300      	addi	r3, 1	// regs: r3=(<cond> + 0x1)
 5c0:	dc620869 	st.b	r3, (r2, 0x869)	// *(0x869) = (<cond> + 0x1)
 5c4:	e800fd2e 	br	0x20	// goto loc_20;
loc_5c8:
 5c8:	3a44      	cmpnei	r2, 4
 5ca:	080b      	bt	0x5e0	// if (r2 != 0x4) goto loc_5e0;
 5cc:	1264      	lrw	r3, 0x0	// regs: r3=0x0
 5ce:	d8430308 	ld.b	r2, (r3, 0x308)	// regs: r2=*(0x308)
 5d2:	3a01      	cmphsi	r2, 2
loc_5d4:
 5d4:	e840fd26 	bf	0x20	// if (r2 < 0x2) goto loc_20;
 5d8:	dc830869 	st.b	r4, (r3, 0x869)	// *(0x869) = r4
 5dc:	e800fd22 	br	0x20	// goto loc_20;
loc_5e0:
 5e0:	3a48      	cmpnei	r2, 8
 5e2:	e860fd1f 	bt	0x20	// if (r2 != 0x8) goto loc_20;
 5e6:	117e      	lrw	r3, 0x0	// regs: r3=0x0
 5e8:	d8430308 	ld.b	r2, (r3, 0x308)	// regs: r2=*(0x308)
 5ec:	3a02      	cmphsi	r2, 3
 5ee:	07f3      	br	0x5d4	// goto loc_5d4;
 5f0:	117b      	lrw	r3, 0x0	// regs: r3=0x0
 5f2:	d8430314 	ld.b	r2, (r3, 0x314)	// regs: r2=*(0x314)
 5f6:	c4445c80 	ins	r2, r4, 4, 0
loc_5fa:
 5fa:	dc430314 	st.b	r2, (r3, 0x314)	// *(0x314) = *(0x314)
 5fe:	e800fd11 	br	0x20	// goto loc_20;
 602:	1177      	lrw	r3, 0x0	// regs: r3=0x0
 604:	3a40      	cmpnei	r2, 0
 606:	c4000501 	mvc	r1	// regs: r1=<cond>
 60a:	d8430314 	ld.b	r2, (r3, 0x314)	// regs: r2=*(0x314)
 60e:	c4415c05 	ins	r2, r1, 5, 5
 612:	07f4      	br	0x5fa	// goto loc_5fa;
 614:	e462101d 	subi	r3, r2, 30	// regs: r3=(<arg2> - 0x1e)
 618:	3b01      	cmphsi	r3, 2
 61a:	0804      	bt	0x622	// if (r3 >= 0x2) goto loc_622;
 61c:	3000      	movi	r0, 0	// regs: r0=0x0
 61e:	e0000000 	bsr	0x0	// <jtag_map_set>; regs: r0=<ret jtag_map_set@0x61e>, r1=<clobbered>
loc_622:
 622:	3101      	movi	r1, 1	// regs: r1=0x1
 624:	6c13      	mov	r0, r4	// regs: r0=r4
 626:	e0000000 	bsr	0x0	// <gpio_set_dir>; regs: r0=<ret gpio_set_dir@0x626>, r1=<clobbered>
 62a:	114d      	lrw	r2, 0x0	// regs: r2=0x0
 62c:	6c4b      	mov	r1, r2	// regs: r1=0x0
 62e:	d8620876 	ld.b	r3, (r2, 0x876)	// regs: r3=*(0x876)
 632:	740e      	sextb	r0, r3	// regs: r0=sext8(*(0x876))
 634:	e9a00012 	bhsz	r0, 0x658	// if (r0 >= 0x0) goto loc_658;
 638:	e463207f 	andi	r3, r3, 127	// regs: r3=(*(0x876) & 0x7f)
 63c:	64d2      	cmpne	r4, r3
 63e:	0c0d      	bf	0x658	// if (!T) goto loc_658;
 640:	d8620877 	ld.b	r3, (r2, 0x877)	// regs: r3=*(0x877)
 644:	3101      	movi	r1, 1	// regs: r1=0x1
 646:	c4645cc0 	ins	r3, r4, 6, 0
 64a:	c4615c07 	ins	r3, r1, 7, 7
 64e:	dc620877 	st.b	r3, (r2, 0x877)	// *(0x877) = *(0x877)
 652:	6c53      	mov	r1, r4	// regs: r1=r4
 654:	110f      	lrw	r0, 0x0	// regs: r0=0x0
 656:	060f      	br	0x274	// goto loc_274;
loc_658:
 658:	d8610876 	ld.b	r3, (r1, 0x876)	// regs: r3=*(0x876)
 65c:	c4645cc0 	ins	r3, r4, 6, 0
 660:	3201      	movi	r2, 1	// regs: r2=0x1
 662:	3c1f      	cmphsi	r4, 32
 664:	c4625c07 	ins	r3, r2, 7, 7
 668:	dc610876 	st.b	r3, (r1, 0x876)	// *(0x876) = *(0x876)
 66c:	0804      	bt	0x674	// if (r4 >= 0x20) goto loc_674;
 66e:	6c53      	mov	r1, r4	// regs: r1=r4
 670:	1109      	lrw	r0, 0x0	// regs: r0=0x0
 672:	0601      	br	0x274	// goto loc_274;
loc_674:
 674:	e424101f 	subi	r1, r4, 32	// regs: r1=(r4 - 0x20)
 678:	1108      	lrw	r0, 0x0	// regs: r0=0x0
 67a:	e800fdfd 	br	0x274	// goto loc_274;
 67e:	1078      	lrw	r3, 0x0	// regs: r3=0x0
 680:	3a40      	cmpnei	r2, 0
 682:	c4000501 	mvc	r1	// regs: r1=<cond>
 686:	d8430875 	ld.b	r2, (r3, 0x875)	// regs: r2=*(0x875)
 68a:	c4415c02 	ins	r2, r1, 2, 2
 68e:	dc430875 	st.b	r2, (r3, 0x875)	// *(0x875) = *(0x875)
 692:	e800fcc7 	br	0x20	// goto loc_20;
 696:	1052      	lrw	r2, 0x0	// regs: r2=0x0
 698:	3101      	movi	r1, 1	// regs: r1=0x1
 69a:	d8620875 	ld.b	r3, (r2, 0x875)	// regs: r3=*(0x875)
 69e:	3c40      	cmpnei	r4, 0
 6a0:	c4615c02 	ins	r3, r1, 2, 2
 6a4:	c4000501 	mvc	r1	// regs: r1=<cond>
 6a8:	c4615c03 	ins	r3, r1, 3, 3
 6ac:	dc620875 	st.b	r3, (r2, 0x875)	// *(0x875) = *(0x875)
 6b0:	e800fcb8 	br	0x20	// goto loc_20;
 6b4:	104a      	lrw	r2, 0x0	// regs: r2=0x0
 6b6:	3101      	movi	r1, 1	// regs: r1=0x1
 6b8:	d8620875 	ld.b	r3, (r2, 0x875)	// regs: r3=*(0x875)
 6bc:	3c40      	cmpnei	r4, 0
 6be:	c4615c02 	ins	r3, r1, 2, 2
 6c2:	c4000501 	mvc	r1	// regs: r1=<cond>
 6c6:	7444      	zextb	r1, r1	// regs: r1=zext8(<cond>)
 6c8:	e46320f7 	andi	r3, r3, 247	// regs: r3=(*(0x875) & 0xf7)
 6cc:	c4615c04 	ins	r3, r1, 4, 4
 6d0:	dc620875 	st.b	r3, (r2, 0x875)	// *(0x875) = (*(0x875) & 0xf7)
 6d4:	1012      	lrw	r0, 0x0	// regs: r0=0x0
 6d6:	e800fdcf 	br	0x274	// goto loc_274;
 6da:	0000      	.short	0x0000
 6dc:	00000000 	.long	0x00000000	// <ah_lmac>
 6e0:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x127>
 6e4:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x13d>
 6e8:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x15a>
 6ec:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x176>
 6f0:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x196>
 6f4:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x1ac>
 6f8:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x1c6>
 6fc:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x1e0>
 700:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x1ec>
 704:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x202>
 708:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x11c>
 70c:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x21d>
 710:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x235>
 714:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x24a>
 718:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x261>
 71c:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x278>
 720:	8525      	ld.b	r1, (r5, 0x5)	// regs: r1=*(r5 + 0x5)
 722:	8561      	ld.b	r3, (r5, 0x1)	// regs: r3=*(r5 + 0x1)
 724:	8540      	ld.b	r2, (r5, 0x0)	// regs: r2=*(r5)
 726:	b823      	st.w	r1, (r14, 0xc)	// stack_pc = *(r5 + 0x5)
 728:	8524      	ld.b	r1, (r5, 0x4)	// regs: r1=*(r5 + 0x4)
 72a:	b822      	st.w	r1, (r14, 0x8)	// stack_p8 = *(r5 + 0x4)
 72c:	8523      	ld.b	r1, (r5, 0x3)	// regs: r1=*(r5 + 0x3)
 72e:	b821      	st.w	r1, (r14, 0x4)	// stack_p4 = *(r5 + 0x3)
 730:	8522      	ld.b	r1, (r5, 0x2)	// regs: r1=*(r5 + 0x2)
 732:	b820      	st.w	r1, (r14, 0x0)	// stack_0 = *(r5 + 0x2)
 734:	7451      	zexth	r1, r4	// regs: r1=zext16(r4)
 736:	011a      	lrw	r0, 0x0	// regs: r0=0x0
 738:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x738>, r1=<clobbered>
 73c:	6c57      	mov	r1, r5	// regs: r1=r5
 73e:	7411      	zexth	r0, r4	// regs: r0=zext16(r4)
 740:	e0000000 	bsr	0x0	// <lmac_sta_search>; regs: r0=<ret lmac_sta_search@0x740>, r1=<clobbered>
 744:	e9200009 	bnez	r0, 0x756	// if (r0 != 0x0) goto loc_756;
 748:	011e      	lrw	r0, 0x0	// regs: r0=0x0
 74a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x74a>, r1=<clobbered>
loc_74e:
 74e:	3400      	movi	r4, 0	// regs: r4=0x0
 750:	2c00      	subi	r4, 1	// regs: r4=0xffffffff
 752:	e800fc71 	br	0x34	// goto loc_34;
loc_756:
 756:	3300      	movi	r3, 0	// regs: r3=0x0
 758:	3640      	movi	r6, 64	// regs: r6=0x40
 75a:	dcc0013f 	st.b	r6, (r0, 0x13f)	// *(<ret lmac_sta_search@0x740> + 0x13f) = 0x40
 75e:	e5a00143 	addi	r13, r0, 324	// regs: r13=(<ret lmac_sta_search@0x740> + 0x144)
 762:	6e8f      	mov	r10, r3	// regs: r10=0x0
 764:	ea090032 	movi	r9, 50	// regs: r9=0x32
 768:	3400      	movi	r4, 0	// regs: r4=0x0
 76a:	3500      	movi	r5, 0	// regs: r5=0x0
 76c:	6e0f      	mov	r8, r3	// regs: r8=0x0
 76e:	3701      	movi	r7, 1	// regs: r7=0x1
loc_770:
 770:	e4430014 	addi	r2, r3, 21	// regs: r2=(r3 + 0x15)
 774:	4244      	lsli	r2, r2, 4	// regs: r2=((r3 + 0x15) << 0x4)
 776:	dd4d1007 	st.h	r10, (r13, 0xe)	// *(r13 + 0xe) = 0x0
 77a:	d4020029 	str.b	r9, (r2, r0 << 0)
 77e:	4344      	lsli	r2, r3, 4	// regs: r2=(r3 << 0x4)
 780:	6080      	addu	r2, r0	// regs: r2=((r3 << 0x4) + <ret lmac_sta_search@0x740>)
 782:	2300      	addi	r3, 1	// regs: r3=(r3 + 0x1)
 784:	d982014f 	ld.b	r12, (r2, 0x14f)	// regs: r12=*((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14f))
 788:	c5865cc0 	ins	r12, r6, 6, 0
 78c:	dd82014f 	st.b	r12, (r2, 0x14f)	// *((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14f)) = *((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14f))
 790:	dc8d2000 	st.w	r4, (r13, 0x0)	// *(r13) = 0x0
 794:	dcad2001 	st.w	r5, (r13, 0x4)	// *(r13 + 0x4) = 0x0
 798:	d98210a6 	ld.h	r12, (r2, 0x14c)	// regs: r12=*((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14c))
 79c:	c5885d60 	ins	r12, r8, 11, 0
 7a0:	dd8210a6 	st.h	r12, (r2, 0x14c)	// *((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14c)) = *((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14c))
 7a4:	d982014f 	ld.b	r12, (r2, 0x14f)	// regs: r12=*((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14f))
 7a8:	e58c207f 	andi	r12, r12, 127	// regs: r12=(*((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14f)) & 0x7f)
 7ac:	d9622053 	ld.w	r11, (r2, 0x14c)	// regs: r11=*((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14c))
 7b0:	e58c1000 	subi	r12, r12, 1	// regs: r12=((*((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14f)) & 0x7f) - 0x1)
 7b4:	c56c5d6c 	ins	r11, r12, 23, 12
 7b8:	dd622053 	st.w	r11, (r2, 0x14c)	// *((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14c)) = *((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14c))
 7bc:	e422014b 	addi	r1, r2, 332	// regs: r1=(((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14c)
 7c0:	3b48      	cmpnei	r3, 8
 7c2:	d842014f 	ld.b	r2, (r2, 0x14f)	// regs: r2=*((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14f))
 7c6:	c4475c07 	ins	r2, r7, 7, 7
 7ca:	a143      	st.b	r2, (r1, 0x3)	// *((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14f)) = *((((r3 << 0x4) + <ret lmac_sta_search@0x740>) + 0x14f))
 7cc:	e5ad000f 	addi	r13, r13, 16	// regs: r13=(r13 + 0x10)
 7d0:	0bd0      	bt	0x770	// if (r3 != 0x8) goto loc_770;
 7d2:	e800fc27 	br	0x20	// goto loc_20;
 7d6:	0360      	lrw	r3, 0x0	// regs: r3=0x0
 7d8:	3a40      	cmpnei	r2, 0
 7da:	c4000501 	mvc	r1	// regs: r1=<cond>
 7de:	d8430319 	ld.b	r2, (r3, 0x319)	// regs: r2=*(0x319)
 7e2:	c4415c06 	ins	r2, r1, 6, 6
 7e6:	dc430319 	st.b	r2, (r3, 0x319)	// *(0x319) = *(0x319)
 7ea:	e800fc1b 	br	0x20	// goto loc_20;
 7ee:	03a6      	lrw	r5, 0x0	// regs: r5=0x0
 7f0:	6c53      	mov	r1, r4	// regs: r1=r4
 7f2:	3206      	movi	r2, 6	// regs: r2=0x6
 7f4:	e4050525 	addi	r0, r5, 1318	// regs: r0=0x526
 7f8:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x7f8>, r1=<clobbered>
 7fc:	d805052b 	ld.b	r0, (r5, 0x52b)	// regs: r0=*(0x52b)
 800:	d8650528 	ld.b	r3, (r5, 0x528)	// regs: r3=*(0x528)
 804:	d8450527 	ld.b	r2, (r5, 0x527)	// regs: r2=*(0x527)
 808:	d8250526 	ld.b	r1, (r5, 0x526)	// regs: r1=*(0x526)
 80c:	b802      	st.w	r0, (r14, 0x8)	// stack_p8 = *(0x52b)
 80e:	d805052a 	ld.b	r0, (r5, 0x52a)	// regs: r0=*(0x52a)
 812:	b801      	st.w	r0, (r14, 0x4)	// stack_p4 = *(0x52a)
 814:	d8050529 	ld.b	r0, (r5, 0x529)	// regs: r0=*(0x529)
 818:	b800      	st.w	r0, (r14, 0x0)	// stack_0 = *(0x529)
 81a:	0310      	lrw	r0, 0x0	// regs: r0=0x0
 81c:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x81c>, r1=<clobbered>
 820:	e800fc00 	br	0x20	// goto loc_20;
 824:	0354      	lrw	r2, 0x0	// regs: r2=0x0
 826:	3c40      	cmpnei	r4, 0
 828:	d862031a 	ld.b	r3, (r2, 0x31a)	// regs: r3=*(0x31a)
 82c:	c4000501 	mvc	r1	// regs: r1=<cond>
 830:	c4615c00 	ins	r3, r1, 0, 0
 834:	dc62031a 	st.b	r3, (r2, 0x31a)	// *(0x31a) = *(0x31a)
 838:	e4632001 	andi	r3, r3, 1	// regs: r3=(*(0x31a) & 0x1)
 83c:	e903fbf2 	bez	r3, 0x20	// if (r3 == 0x0) goto loc_20;
 840:	0319      	lrw	r0, 0x0	// regs: r0=0x0
 842:	06a4      	br	0x58a	// goto loc_58a;
 844:	6c97      	mov	r2, r5	// regs: r2=r5
 846:	6c53      	mov	r1, r4	// regs: r1=r4
 848:	031a      	lrw	r0, 0x0	// regs: r0=0x0
 84a:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x84a>, r1=<clobbered>
 84e:	037e      	lrw	r3, 0x0	// regs: r3=0x0
 850:	d8432233 	ld.w	r2, (r3, 0x8cc)	// regs: r2=*(0x8cc)
 854:	e902fe9a 	bez	r2, 0x588	// if (r2 == 0x0) goto loc_588;
 858:	d8620259 	ld.b	r3, (r2, 0x259)	// regs: r3=*((*(0x8cc) + 0x259))
 85c:	3d40      	cmpnei	r5, 0
 85e:	c4645cc0 	ins	r3, r4, 6, 0
 862:	c4000501 	mvc	r1	// regs: r1=<cond>
 866:	c4615c07 	ins	r3, r1, 7, 7
 86a:	dc620259 	st.b	r3, (r2, 0x259)	// *((*(0x8cc) + 0x259)) = *((*(0x8cc) + 0x259))
 86e:	e800fbd9 	br	0x20	// goto loc_20;
 872:	1378      	lrw	r3, 0x0	// regs: r3=0x0
 874:	d9032233 	ld.w	r8, (r3, 0x8cc)	// regs: r8=*(0x8cc)
 878:	e908ff6b 	bez	r8, 0x74e	// if (r8 == 0x0) goto loc_74e;
 87c:	3500      	movi	r5, 0	// regs: r5=0x0
 87e:	32fa      	movi	r2, 250	// regs: r2=0xfa
 880:	4242      	lsli	r2, r2, 2	// regs: r2=0x3e8
 882:	3300      	movi	r3, 0	// regs: r3=0x0
 884:	6c13      	mov	r0, r4	// regs: r0=r4
 886:	6c57      	mov	r1, r5	// regs: r1=0x0
 888:	e0000000 	bsr	0x0	// <__muldi3>; regs: r0=<ret __muldi3@0x888>, r1=<clobbered>
 88c:	ea02eebb 	movi	r2, 61115	// regs: r2=0xeebb
 890:	c5a24902 	rotli	r2, r2, 13	// regs: r2=rotl(0xeebb, 0xd)
 894:	3314      	movi	r3, 20	// regs: r3=0x14
 896:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x896>, r1=<clobbered>
 89a:	1372      	lrw	r3, 0x0	// regs: r3=0x0
 89c:	6f57      	mov	r13, r5	// regs: r13=0x0
 89e:	9360      	ld.w	r3, (r3, 0x0)	// regs: r3=*(0x0)
 8a0:	6c97      	mov	r2, r5	// regs: r2=0x0
 8a2:	d9832005 	ld.w	r12, (r3, 0x14)	// regs: r12=*((*(0x0) + 0x14))
 8a6:	9384      	ld.w	r4, (r3, 0x10)	// regs: r4=*((*(0x0) + 0x10))
 8a8:	6cf3      	mov	r3, r12	// regs: r3=*((*(0x0) + 0x14))
 8aa:	6f13      	mov	r12, r4	// regs: r12=*((*(0x0) + 0x10))
 8ac:	6489      	cmplt	r2, r2
 8ae:	60b1      	addc	r2, r12
 8b0:	60f5      	addc	r3, r13
 8b2:	dc4820b4 	st.w	r2, (r8, 0x2d0)	// *((*(0x8cc) + 0x2d0)) = 0x0
 8b6:	dc6820b5 	st.w	r3, (r8, 0x2d4)	// *((*(0x8cc) + 0x2d4)) = *((*(0x0) + 0x14))
 8ba:	dc4820b8 	st.w	r2, (r8, 0x2e0)	// *((*(0x8cc) + 0x2e0)) = 0x0
 8be:	dc6820b9 	st.w	r3, (r8, 0x2e4)	// *((*(0x8cc) + 0x2e4)) = *((*(0x0) + 0x14))
 8c2:	dc0820b6 	st.w	r0, (r8, 0x2d8)	// *((*(0x8cc) + 0x2d8)) = <ret __umoddi3@0x896>
 8c6:	dc2820b7 	st.w	r1, (r8, 0x2dc)	// *((*(0x8cc) + 0x2dc)) = <clobbered>
 8ca:	dc0820b2 	st.w	r0, (r8, 0x2c8)	// *((*(0x8cc) + 0x2c8)) = <ret __umoddi3@0x896>
 8ce:	dc2820b3 	st.w	r1, (r8, 0x2cc)	// *((*(0x8cc) + 0x2cc)) = <clobbered>
 8d2:	1345      	lrw	r2, 0xd693a400	// regs: r2=0xd693a400
 8d4:	3300      	movi	r3, 0	// regs: r3=0x0
 8d6:	6d83      	mov	r6, r0	// regs: r6=<ret __umoddi3@0x896>
 8d8:	6dc7      	mov	r7, r1	// regs: r7=<clobbered>
 8da:	e0000000 	bsr	0x0	// <__udivdi3>; regs: r0=<ret __udivdi3@0x8da>, r1=<clobbered>
 8de:	6d03      	mov	r4, r0	// regs: r4=<ret __udivdi3@0x8da>
 8e0:	6e07      	mov	r8, r1	// regs: r8=<clobbered>
 8e2:	ea02f424 	movi	r2, 62500	// regs: r2=0xf424
 8e6:	c4824902 	rotli	r2, r2, 4	// regs: r2=rotl(0xf424, 0x4)
 8ea:	3300      	movi	r3, 0	// regs: r3=0x0
 8ec:	6c1b      	mov	r0, r6	// regs: r0=<ret __umoddi3@0x896>
 8ee:	6c5f      	mov	r1, r7	// regs: r1=<clobbered>
 8f0:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x8f0>, r1=<clobbered>
 8f4:	32fa      	movi	r2, 250	// regs: r2=0xfa
 8f6:	4242      	lsli	r2, r2, 2	// regs: r2=0x3e8
 8f8:	3300      	movi	r3, 0	// regs: r3=0x0
 8fa:	e0000000 	bsr	0x0	// <__udivdi3>; regs: r0=<ret __udivdi3@0x8fa>, r1=<clobbered>
 8fe:	b805      	st.w	r0, (r14, 0x14)	// stack_p14 = <ret __udivdi3@0x8fa>
 900:	b826      	st.w	r1, (r14, 0x18)	// stack_p18 = <clobbered>
 902:	ea02f424 	movi	r2, 62500	// regs: r2=0xf424
 906:	c4824902 	rotli	r2, r2, 4	// regs: r2=rotl(0xf424, 0x4)
 90a:	3300      	movi	r3, 0	// regs: r3=0x0
 90c:	6c1b      	mov	r0, r6	// regs: r0=<ret __umoddi3@0x896>
 90e:	6c5f      	mov	r1, r7	// regs: r1=<clobbered>
 910:	e0000000 	bsr	0x0	// <__udivdi3>; regs: r0=<ret __udivdi3@0x910>, r1=<clobbered>
 914:	323c      	movi	r2, 60	// regs: r2=0x3c
 916:	3300      	movi	r3, 0	// regs: r3=0x0
 918:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x918>, r1=<clobbered>
 91c:	b803      	st.w	r0, (r14, 0xc)	// stack_pc = <ret __umoddi3@0x918>
 91e:	b824      	st.w	r1, (r14, 0x10)	// stack_p10 = <clobbered>
 920:	1252      	lrw	r2, 0x3938700	// regs: r2=0x3938700
 922:	3300      	movi	r3, 0	// regs: r3=0x0
 924:	6c1b      	mov	r0, r6	// regs: r0=<ret __umoddi3@0x896>
 926:	6c5f      	mov	r1, r7	// regs: r1=<clobbered>
 928:	e0000000 	bsr	0x0	// <__udivdi3>; regs: r0=<ret __udivdi3@0x928>, r1=<clobbered>
 92c:	323c      	movi	r2, 60	// regs: r2=0x3c
 92e:	3300      	movi	r3, 0	// regs: r3=0x0
 930:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x930>, r1=<clobbered>
 934:	b801      	st.w	r0, (r14, 0x4)	// stack_p4 = <ret __umoddi3@0x930>
 936:	b822      	st.w	r1, (r14, 0x8)	// stack_p8 = <clobbered>
 938:	dd0e2000 	st.w	r8, (r14, 0x0)	// stack_0 = <clobbered>
 93c:	6cd3      	mov	r3, r4	// regs: r3=<ret __udivdi3@0x8da>
 93e:	6c5b      	mov	r1, r6	// regs: r1=<ret __umoddi3@0x896>
 940:	6c9f      	mov	r2, r7	// regs: r2=<clobbered>
 942:	120b      	lrw	r0, 0x0	// regs: r0=0x0
 944:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x944>, r1=<clobbered>
 948:	e800fb6c 	br	0x20	// goto loc_20;
 94c:	1261      	lrw	r3, 0x0	// regs: r3=0x0
 94e:	d8632233 	ld.w	r3, (r3, 0x8cc)	// regs: r3=*(0x8cc)
 952:	e903fb67 	bez	r3, 0x20	// if (r3 == 0x0) goto loc_20;
 956:	dc430a4d 	st.b	r2, (r3, 0xa4d)	// *((*(0x8cc) + 0xa4d)) = <arg2>
 95a:	dca320af 	st.w	r5, (r3, 0x2bc)	// *((*(0x8cc) + 0x2bc)) = r5
 95e:	e800fb61 	br	0x20	// goto loc_20;
 962:	117c      	lrw	r3, 0x0	// regs: r3=0x0
 964:	d8632233 	ld.w	r3, (r3, 0x8cc)	// regs: r3=*(0x8cc)
 968:	e903fb5c 	bez	r3, 0x20	// if (r3 == 0x0) goto loc_20;
 96c:	d843025b 	ld.b	r2, (r3, 0x25b)	// regs: r2=*((*(0x8cc) + 0x25b))
 970:	c4445c26 	ins	r2, r4, 7, 6
 974:	e800fda1 	br	0x4b6	// goto loc_4b6;
 978:	e902fb54 	bez	r2, 0x20	// if (r2 == 0x0) goto loc_20;
 97c:	1175      	lrw	r3, 0x0	// regs: r3=0x0
 97e:	dc4320f5 	st.w	r2, (r3, 0x3d4)	// *(0x3d4) = <arg2>
 982:	e800fb4f 	br	0x20	// goto loc_20;
 986:	6c57      	mov	r1, r5	// regs: r1=r5
 988:	e0000000 	bsr	0x0	// <lmac_cfg_set_aid> // arg_bytes: 0; regs: r0=<ret lmac_cfg_set_aid@0x988>, r1=<clobbered>
 98c:	e800fb4a 	br	0x20	// goto loc_20;
 990:	6c97      	mov	r2, r5	// regs: r2=r5
 992:	7450      	zextb	r1, r4	// regs: r1=zext8(r4)
 994:	e0000000 	bsr	0x0	// <lmac_ah_set_txq_param> // arg_bytes: 0; regs: r0=<ret lmac_ah_set_txq_param@0x994>, r1=<clobbered>
 998:	e800fb44 	br	0x20	// goto loc_20;
 99c:	6c57      	mov	r1, r5	// regs: r1=r5
 99e:	e0000000 	bsr	0x0	// <lmac_cfg_set_mac> // arg_bytes: 0; regs: r0=<ret lmac_cfg_set_mac@0x99e>, r1=<clobbered>
 9a2:	e800fb3f 	br	0x20	// goto loc_20;
 9a6:	114b      	lrw	r2, 0x0	// regs: r2=0x0
 9a8:	3c40      	cmpnei	r4, 0
 9aa:	c4000501 	mvc	r1	// regs: r1=<cond>
 9ae:	d86203df 	ld.b	r3, (r2, 0x3df)	// regs: r3=*(0x3df)
 9b2:	c4615c03 	ins	r3, r1, 3, 3
 9b6:	e4232008 	andi	r1, r3, 8	// regs: r1=(*(0x3df) & 0x8)
 9ba:	dc6203df 	st.b	r3, (r2, 0x3df)	// *(0x3df) = *(0x3df)
 9be:	d8620361 	ld.b	r3, (r2, 0x361)	// regs: r3=*(0x361)
 9c2:	e901000f 	bez	r1, 0x9e0	// if (r1 == 0x0) goto loc_9e0;
 9c6:	3100      	movi	r1, 0	// regs: r1=0x0
 9c8:	c4615c02 	ins	r3, r1, 2, 2
 9cc:	dc620361 	st.b	r3, (r2, 0x361)	// *(0x361) = *(0x361)
 9d0:	3002      	movi	r0, 2	// regs: r0=0x2
 9d2:	e0000000 	bsr	0x0	// <lmac_spec_cca_cfg>; regs: r0=<ret lmac_spec_cca_cfg@0x9d2>, r1=<clobbered>
loc_9d6:
 9d6:	3002      	movi	r0, 2	// regs: r0=0x2
 9d8:	e0000000 	bsr	0x0	// <lmac_spec_cca_cfg>; regs: r0=<ret lmac_spec_cca_cfg@0x9d8>, r1=<clobbered>
 9dc:	e800fb22 	br	0x20	// goto loc_20;
loc_9e0:
 9e0:	3101      	movi	r1, 1	// regs: r1=0x1
 9e2:	c4615c02 	ins	r3, r1, 2, 2
 9e6:	dc620361 	st.b	r3, (r2, 0x361)	// *(0x361) = *(0x361)
 9ea:	d802431e 	ld.bs	r0, (r2, 0x31e)	// regs: r0=*(0x31e)
 9ee:	e0000000 	bsr	0x0	// <lmac_adjust_cca_threshold>; regs: r0=<ret lmac_adjust_cca_threshold@0x9ee>, r1=<clobbered>
 9f2:	07f2      	br	0x9d6	// goto loc_9d6;
 9f4:	1077      	lrw	r3, 0x0	// regs: r3=0x0
 9f6:	dc4303e0 	st.b	r2, (r3, 0x3e0)	// *(0x3e0) = <arg2>
 9fa:	e800fb13 	br	0x20	// goto loc_20;
 9fe:	1075      	lrw	r3, 0x0	// regs: r3=0x0
 a00:	3a40      	cmpnei	r2, 0
 a02:	c4000501 	mvc	r1	// regs: r1=<cond>
 a06:	d8430310 	ld.b	r2, (r3, 0x310)	// regs: r2=*(0x310)
 a0a:	c4415c01 	ins	r2, r1, 1, 1
 a0e:	e800fbe7 	br	0x1dc	// goto loc_1dc;
 a12:	1070      	lrw	r3, 0x0	// regs: r3=0x0
 a14:	dc430300 	st.b	r2, (r3, 0x300)	// *(0x300) = <arg2>
 a18:	e800fb04 	br	0x20	// goto loc_20;
 a1c:	106d      	lrw	r3, 0x0	// regs: r3=0x0
 a1e:	dc4303e1 	st.b	r2, (r3, 0x3e1)	// *(0x3e1) = <arg2>
 a22:	e800faff 	br	0x20	// goto loc_20;
 a26:	6c4b      	mov	r1, r2	// regs: r1=<arg2>
 a28:	e0000000 	bsr	0x0	// <lmac_cfg_set_wnb_encrypt> // arg_bytes: 0; regs: r0=<ret lmac_cfg_set_wnb_encrypt@0xa28>, r1=<clobbered>
 a2c:	e800fafa 	br	0x20	// goto loc_20;
 a30:	1068      	lrw	r3, 0x0	// regs: r3=0x0
 a32:	3a40      	cmpnei	r2, 0
 a34:	c4000501 	mvc	r1	// regs: r1=<cond>
 a38:	d84303e2 	ld.b	r2, (r3, 0x3e2)	// regs: r2=*(0x3e2)
 a3c:	c4415c03 	ins	r2, r1, 3, 3
 a40:	dc4303e2 	st.b	r2, (r3, 0x3e2)	// *(0x3e2) = *(0x3e2)
 a44:	e800faee 	br	0x20	// goto loc_20;
 a48:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x28a>
 a4c:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x2c6>
 a50:	00000000 	.long	0x00000000	// <ah_lmac>
 a54:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x2df>
 a58:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x30a>
 a5c:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x31e>
 a60:	00000000 	.long	0x00000000	// <LMAC>
 a64:	d693a400 	.long	0xd693a400
 a68:	03938700 	.long	0x03938700
 a6c:	00000000 	.long	0x00000000	// <.rodata.lmac_set_cfg.str1.1+0x340>

Disassembly of section .text.lmac_get_cfg:

00000000 <lmac_get_cfg>: // arg_bytes: 0
   0:	14d1      	push	r4, r15
   2:	6d0f      	mov	r4, r3	// regs: r4=<arg3>
   4:	33e0      	movi	r3, 224	// regs: r3=0xe0
   6:	4378      	lsli	r3, r3, 24	// regs: r3=0xe0000000
   8:	604c      	addu	r1, r3	// regs: r1=(<arg1> + 0xe0000000)
   a:	eb010025 	cmphsi	r1, 38
   e:	6c0b      	mov	r0, r2	// regs: r0=<arg2>
  10:	0860      	bt	0xd0	// if (r1 >= 0x26) goto loc_d0;
  12:	1063      	lrw	r3, 0x0	// regs: r3=0x0
  14:	d0230883 	ldr.w	r3, (r3, r1 << 2)	// regs: r3=*(0x0 + ((<arg1> + 0xe0000000) << 2))
  18:	780c      	jmp	r3	// goto *r3;
  1a:	0000      	.short	0x0000
  1c:	00000000 	.long	0x00000000	// <.rodata.lmac_get_cfg>
  20:	1369      	lrw	r3, 0x0	// regs: r3=0x0
  22:	d8830315 	ld.b	r4, (r3, 0x315)	// regs: r4=*(0x315)
loc_26:
  26:	6c13      	mov	r0, r4	// regs: r0=r4
  28:	1491      	pop	r4, r15
  2a:	1367      	lrw	r3, 0x0	// regs: r3=0x0
  2c:	d8830308 	ld.b	r4, (r3, 0x308)	// regs: r4=*(0x308)
  30:	07fb      	br	0x26	// goto loc_26;
  32:	1365      	lrw	r3, 0x0	// regs: r3=0x0
  34:	d8830867 	ld.b	r4, (r3, 0x867)	// regs: r4=*(0x867)
  38:	07f7      	br	0x26	// goto loc_26;
  3a:	1363      	lrw	r3, 0x0	// regs: r3=0x0
  3c:	d8830866 	ld.b	r4, (r3, 0x866)	// regs: r4=*(0x866)
  40:	07f3      	br	0x26	// goto loc_26;
  42:	1361      	lrw	r3, 0x0	// regs: r3=0x0
  44:	d8831197 	ld.h	r4, (r3, 0x32e)	// regs: r4=*(0x32e)
  48:	07ef      	br	0x26	// goto loc_26;
  4a:	129f      	lrw	r4, 0x0	// regs: r4=0x0
  4c:	d80411b6 	ld.h	r0, (r4, 0x36c)	// regs: r0=*(0x36c)
  50:	c4a05520 	zext	r0, r0, 9, 5	// regs: r0=zext(*(0x36c))
  54:	e0000000 	bsr	0x0	// <ah_rfdigicali_get_tx_digi_gain>; regs: r0=<ret ah_rfdigicali_get_tx_digi_gain@0x54>, r1=<clobbered>
  58:	d884468e 	ld.bs	r4, (r4, 0x68e)	// regs: r4=*(0x68e)
  5c:	6c53      	mov	r1, r4	// regs: r1=*(0x68e)
  5e:	121b      	lrw	r0, 0x0	// regs: r0=0x0
loc_60:
  60:	e0000000 	bsr	0x0	// <hgprintf>; regs: r0=<ret hgprintf@0x60>, r1=<clobbered>
  64:	07e1      	br	0x26	// goto loc_26;
  66:	1278      	lrw	r3, 0x0	// regs: r3=0x0
  68:	d883133b 	ld.h	r4, (r3, 0x676)	// regs: r4=*(0x676)
  6c:	07dd      	br	0x26	// goto loc_26;
  6e:	1276      	lrw	r3, 0x0	// regs: r3=0x0
  70:	d8830310 	ld.b	r4, (r3, 0x310)	// regs: r4=*(0x310)
  74:	c4645464 	zext	r4, r4, 3, 3	// regs: r4=zext(*(0x310))
  78:	07d7      	br	0x26	// goto loc_26;
  7a:	1273      	lrw	r3, 0x0	// regs: r3=0x0
  7c:	d88320ce 	ld.w	r4, (r3, 0x338)	// regs: r4=*(0x338)
  80:	c4845764 	zext	r4, r4, 27, 4	// regs: r4=zext(*(0x338))
  84:	07d1      	br	0x26	// goto loc_26;
  86:	1270      	lrw	r3, 0x0	// regs: r3=0x0
  88:	d8834898 	ld.bs	r4, (r3, 0x898)	// regs: r4=*(0x898)
  8c:	07cd      	br	0x26	// goto loc_26;
  8e:	126e      	lrw	r3, 0x0	// regs: r3=0x0
  90:	d8834899 	ld.bs	r4, (r3, 0x899)	// regs: r4=*(0x899)
  94:	07c9      	br	0x26	// goto loc_26;
  96:	126c      	lrw	r3, 0x0	// regs: r3=0x0
  98:	d883489a 	ld.bs	r4, (r3, 0x89a)	// regs: r4=*(0x89a)
  9c:	07c5      	br	0x26	// goto loc_26;
  9e:	126a      	lrw	r3, 0x0	// regs: r3=0x0
  a0:	d8831198 	ld.h	r4, (r3, 0x330)	// regs: r4=*(0x330)
  a4:	07c1      	br	0x26	// goto loc_26;
  a6:	1268      	lrw	r3, 0x0	// regs: r3=0x0
  a8:	d8830309 	ld.b	r4, (r3, 0x309)	// regs: r4=*(0x309)
  ac:	07bd      	br	0x26	// goto loc_26;
  ae:	1288      	lrw	r4, 0x0	// regs: r4=0x0
  b0:	07bb      	br	0x26	// goto loc_26;
  b2:	1288      	lrw	r4, 0x0	// regs: r4=0x0
  b4:	07b9      	br	0x26	// goto loc_26;
  b6:	1264      	lrw	r3, 0x0	// regs: r3=0x0
  b8:	d8832196 	ld.w	r4, (r3, 0x658)	// regs: r4=*(0x658)
  bc:	07b5      	br	0x26	// goto loc_26;
  be:	1262      	lrw	r3, 0x0	// regs: r3=0x0
  c0:	d8830556 	ld.b	r4, (r3, 0x556)	// regs: r4=*(0x556)
  c4:	07b1      	br	0x26	// goto loc_26;
  c6:	1260      	lrw	r3, 0x0	// regs: r3=0x0
  c8:	d8832233 	ld.w	r4, (r3, 0x8cc)	// regs: r4=*(0x8cc)
  cc:	e9240004 	bnez	r4, 0xd4	// if (r4 != 0x0) goto loc_d4;
loc_d0:
  d0:	3400      	movi	r4, 0	// regs: r4=0x0
  d2:	07aa      	br	0x26	// goto loc_26;
loc_d4:
  d4:	e4840a6b 	addi	r4, r4, 2668	// regs: r4=(*(0x8cc) + 0xa6c)
  d8:	07a7      	br	0x26	// goto loc_26;
  da:	117b      	lrw	r3, 0x0	// regs: r3=0x0
  dc:	d8632233 	ld.w	r3, (r3, 0x8cc)	// regs: r3=*(0x8cc)
  e0:	e903fff8 	bez	r3, 0xd0	// if (r3 == 0x0) goto loc_d0;
  e4:	3480      	movi	r4, 128	// regs: r4=0x80
  e6:	4482      	lsli	r4, r4, 2	// regs: r4=0x200
  e8:	079f      	br	0x26	// goto loc_26;
  ea:	1177      	lrw	r3, 0x0	// regs: r3=0x0
  ec:	d8830875 	ld.b	r4, (r3, 0x875)	// regs: r4=*(0x875)
  f0:	c4845484 	zext	r4, r4, 4, 4	// regs: r4=zext(*(0x875))
  f4:	0799      	br	0x26	// goto loc_26;
  f6:	e0000000 	bsr	0x0	// <lmac_bss_load_get> // arg_bytes: 0; regs: r0=<ret lmac_bss_load_get@0xf6>, r1=<clobbered>
loc_fa:
  fa:	6d03      	mov	r4, r0	// regs: r4=r0
  fc:	0795      	br	0x26	// goto loc_26;
  fe:	1172      	lrw	r3, 0x0	// regs: r3=0x0
 100:	d8232233 	ld.w	r1, (r3, 0x8cc)	// regs: r1=*(0x8cc)
 104:	e901ffe6 	bez	r1, 0xd0	// if (r1 == 0x0) goto loc_d0;
 108:	ea02eebb 	movi	r2, 61115	// regs: r2=0xeebb
 10c:	c5a24902 	rotli	r2, r2, 13	// regs: r2=rotl(0xeebb, 0xd)
 110:	3314      	movi	r3, 20	// regs: r3=0x14
 112:	d80120b2 	ld.w	r0, (r1, 0x2c8)	// regs: r0=*((*(0x8cc) + 0x2c8))
 116:	d82120b3 	ld.w	r1, (r1, 0x2cc)	// regs: r1=*((*(0x8cc) + 0x2cc))
 11a:	e0000000 	bsr	0x0	// <__umoddi3>; regs: r0=<ret __umoddi3@0x11a>, r1=<clobbered>
 11e:	32fa      	movi	r2, 250	// regs: r2=0xfa
 120:	4242      	lsli	r2, r2, 2	// regs: r2=0x3e8
 122:	3300      	movi	r3, 0	// regs: r3=0x0
 124:	e0000000 	bsr	0x0	// <__udivdi3>; regs: r0=<ret __udivdi3@0x124>, r1=<clobbered>
 128:	6d03      	mov	r4, r0	// regs: r4=<ret __udivdi3@0x124>
 12a:	6c43      	mov	r1, r0	// regs: r1=<ret __udivdi3@0x124>
 12c:	110a      	lrw	r0, 0x0	// regs: r0=0x0
 12e:	0799      	br	0x60	// goto loc_60;
 130:	1165      	lrw	r3, 0x0	// regs: r3=0x0
 132:	d88320f5 	ld.w	r4, (r3, 0x3d4)	// regs: r4=*(0x3d4)
 136:	0778      	br	0x26	// goto loc_26;
 138:	3100      	movi	r1, 0	// regs: r1=0x0
 13a:	7409      	zexth	r0, r2	// regs: r0=zext16(<arg2>)
 13c:	e0000000 	bsr	0x0	// <lmac_sta_get>; regs: r0=<ret lmac_sta_get@0x13c>, r1=<clobbered>
 140:	e900ffc8 	bez	r0, 0xd0	// if (r0 == 0x0) goto loc_d0;
 144:	d86000b4 	ld.b	r3, (r0, 0xb4)	// regs: r3=*(<ret lmac_sta_get@0x13c> + 0xb4)
 148:	103f      	lrw	r1, 0x0	// regs: r1=0x0
 14a:	3200      	movi	r2, 0	// regs: r2=0x0
 14c:	a460      	st.b	r3, (r4, 0x0)	// *(r4) = *(<ret lmac_sta_get@0x13c> + 0xb4)
 14e:	2a54      	subi	r2, 85	// regs: r2=0xffffffab
 150:	d861431e 	ld.bs	r3, (r1, 0x31e)	// regs: r3=*(0x31e)
 154:	648d      	cmplt	r3, r2
 156:	d84000b8 	ld.b	r2, (r0, 0xb8)	// regs: r2=*(<ret lmac_sta_get@0x13c> + 0xb8)
 15a:	0803      	bt	0x160	// if (T) goto loc_160;
loc_15c:
 15c:	608e      	subu	r2, r3	// regs: r2=(r2 - *(0x31e))
 15e:	0409      	br	0x170	// goto loc_170;
loc_160:
 160:	d821431d 	ld.bs	r1, (r1, 0x31d)	// regs: r1=*(0x31d)
 164:	748a      	sextb	r2, r2	// regs: r2=sext8(*(<ret lmac_sta_get@0x13c> + 0xb8))
 166:	e5811054 	subi	r12, r1, 85	// regs: r12=(*(0x31d) - 0x55)
 16a:	6709      	cmplt	r2, r12
 16c:	0804      	bt	0x174	// if (T) goto loc_174;
 16e:	2254      	addi	r2, 85	// regs: r2=(sext8(*(<ret lmac_sta_get@0x13c> + 0xb8)) + 0x55)
loc_170:
 170:	a441      	st.b	r2, (r4, 0x1)	// *(r4 + 0x1) = r2
 172:	0406      	br	0x17e	// goto loc_17e;
loc_174:
 174:	c423002c 	addu	r12, r3, r1	// regs: r12=(*(0x31e) + *(0x31d))
 178:	6709      	cmplt	r2, r12
 17a:	0bf1      	bt	0x15c	// if (T) goto loc_15c;
 17c:	a421      	st.b	r1, (r4, 0x1)	// *(r4 + 0x1) = *(0x31d)
loc_17e:
 17e:	e0000000 	bsr	0x0	// <lmac_sta_put>; regs: r0=<ret lmac_sta_put@0x17e>, r1=<clobbered>
 182:	07a7      	br	0xd0	// goto loc_d0;
 184:	3a0f      	cmphsi	r2, 16
 186:	0ba5      	bt	0xd0	// if (r2 >= 0x10) goto loc_d0;
 188:	3218      	movi	r2, 24	// regs: r2=0x18
 18a:	106f      	lrw	r3, 0x0	// regs: r3=0x0
 18c:	7c08      	mult	r0, r2	// regs: r0=(<arg0> * 0x18)
 18e:	600c      	addu	r0, r3	// regs: r0=((<arg0> * 0x18) )
 190:	d82303e0 	ld.b	r1, (r3, 0x3e0)	// regs: r1=*(0x3e0)
 194:	d84000c6 	ld.b	r2, (r0, 0xc6)	// regs: r2=*((((<arg0> * 0x18) ) + 0xc6))
 198:	6084      	addu	r2, r1	// regs: r2=(*((((<arg0> * 0x18) ) + 0xc6)) + *(0x3e0))
 19a:	a440      	st.b	r2, (r4, 0x0)	// *(r4) = (*((((<arg0> * 0x18) ) + 0xc6)) + *(0x3e0))
 19c:	d82303e0 	ld.b	r1, (r3, 0x3e0)	// regs: r1=*(0x3e0)
 1a0:	d84000c5 	ld.b	r2, (r0, 0xc5)	// regs: r2=*((((<arg0> * 0x18) ) + 0xc5))
 1a4:	6084      	addu	r2, r1	// regs: r2=(*((((<arg0> * 0x18) ) + 0xc5)) + *(0x3e0))
 1a6:	a441      	st.b	r2, (r4, 0x1)	// *(r4 + 0x1) = (*((((<arg0> * 0x18) ) + 0xc5)) + *(0x3e0))
 1a8:	d84000c7 	ld.b	r2, (r0, 0xc7)	// regs: r2=*((((<arg0> * 0x18) ) + 0xc7))
 1ac:	d86303e0 	ld.b	r3, (r3, 0x3e0)	// regs: r3=*(0x3e0)
 1b0:	60c8      	addu	r3, r2	// regs: r3=(*(0x3e0) + *((((<arg0> * 0x18) ) + 0xc7)))
 1b2:	a462      	st.b	r3, (r4, 0x2)	// *(r4 + 0x2) = (*(0x3e0) + *((((<arg0> * 0x18) ) + 0xc7)))
 1b4:	078e      	br	0xd0	// goto loc_d0;
 1b6:	1064      	lrw	r3, 0x0	// regs: r3=0x0
 1b8:	d8234378 	ld.bs	r1, (r3, 0x378)	// regs: r1=*(0x378)
 1bc:	e0000000 	bsr	0x0	// <lmac_ah_get_acs_result> // arg_bytes: 8; regs: r0=<ret lmac_ah_get_acs_result@0x1bc>, r1=<clobbered>
 1c0:	079d      	br	0xfa	// goto loc_fa;
 1c2:	0000      	.short	0x0000
 1c4:	00000000 	.long	0x00000000	// <ah_lmac>
 1c8:	00000000 	.long	0x00000000	// <.rodata.lmac_get_cfg.str1.1>
 1cc:	00000000 	.long	0x00000000	// <ah_lmac+0x302>
 1d0:	00000000 	.long	0x00000000	// <ah_lmac+0x526>
 1d4:	00000000 	.long	0x00000000	// <.rodata.lmac_get_cfg.str1.1+0x13>

Disassembly of section .text.dsleep_cfg_init:

00000000 <dsleep_cfg_init>: // arg_bytes: 4
   0:	14d8      	push	r4-r11, r15
   2:	137b      	lrw	r3, 0x0	// regs: r3=0x0
   4:	d8400a4e 	ld.b	r2, (r0, 0xa4e)	// regs: r2=*(<arg0> + 0xa4e)
   8:	d8231198 	ld.h	r1, (r3, 0x330)	// regs: r1=*(0x330)
   c:	dc2014e2 	st.h	r1, (r0, 0x9c4)	// *(<arg0> + 0x9c4) = *(0x330)
  10:	d8230556 	ld.b	r1, (r3, 0x556)	// regs: r1=*(0x556)
  14:	dc2009c6 	st.b	r1, (r0, 0x9c6)	// *(<arg0> + 0x9c6) = *(0x556)
  18:	d8c320ce 	ld.w	r6, (r3, 0x338)	// regs: r6=*(0x338)
  1c:	d8232196 	ld.w	r1, (r3, 0x658)	// regs: r1=*(0x658)
  20:	c4865767 	zext	r7, r6, 27, 4	// regs: r7=zext(*(0x338))
  24:	d9030308 	ld.b	r8, (r3, 0x308)	// regs: r8=*(0x308)
  28:	d8c30309 	ld.b	r6, (r3, 0x309)	// regs: r6=*(0x309)
  2c:	dc20227f 	st.w	r1, (r0, 0x9fc)	// *(<arg0> + 0x9fc) = *(0x658)
  30:	dd0009c7 	st.b	r8, (r0, 0x9c7)	// *(<arg0> + 0x9c7) = *(0x308)
  34:	d823133b 	ld.h	r1, (r3, 0x676)	// regs: r1=*(0x676)
  38:	dcc009c3 	st.b	r6, (r0, 0x9c3)	// *(<arg0> + 0x9c3) = *(0x309)
  3c:	dc201504 	st.h	r1, (r0, 0xa08)	// *(<arg0> + 0xa08) = *(0x676)
  40:	e44220fc 	andi	r2, r2, 252	// regs: r2=(*(<arg0> + 0xa4e) & 0xfc)
  44:	d823034a 	ld.b	r1, (r3, 0x34a)	// regs: r1=*(0x34a)
  48:	c4415c06 	ins	r2, r1, 6, 6
  4c:	dc400a4e 	st.b	r2, (r0, 0xa4e)	// *(<arg0> + 0xa4e) = (*(<arg0> + 0xa4e) & 0xfc)
  50:	d843031e 	ld.b	r2, (r3, 0x31e)	// regs: r2=*(0x31e)
  54:	dc400a52 	st.b	r2, (r0, 0xa52)	// *(<arg0> + 0xa52) = *(0x31e)
  58:	d8430840 	ld.b	r2, (r3, 0x840)	// regs: r2=*(0x840)
  5c:	3a05      	cmphsi	r2, 6
  5e:	d963001f 	ld.b	r11, (r3, 0x1f)	// regs: r11=*(0x1f)
  62:	d943002e 	ld.b	r10, (r3, 0x2e)	// regs: r10=*(0x2e)
  66:	d923003e 	ld.b	r9, (r3, 0x3e)	// regs: r9=*(0x3e)
  6a:	6d03      	mov	r4, r0	// regs: r4=<arg0>
  6c:	dce02281 	st.w	r7, (r0, 0xa04)	// *(<arg0> + 0xa04) = zext(*(0x338))
  70:	dd6009c0 	st.b	r11, (r0, 0x9c0)	// *(<arg0> + 0x9c0) = *(0x1f)
  74:	dd4009c1 	st.b	r10, (r0, 0x9c1)	// *(<arg0> + 0x9c1) = *(0x2e)
  78:	dd2009c2 	st.b	r9, (r0, 0x9c2)	// *(<arg0> + 0x9c2) = *(0x3e)
  7c:	6d4f      	mov	r5, r3	// regs: r5=0x0
  7e:	0807      	bt	0x8c	// if (r2 >= 0x6) goto loc_8c;
  80:	d8600a51 	ld.b	r3, (r0, 0xa51)	// regs: r3=*(<arg0> + 0xa51)
  84:	c4625c40 	ins	r3, r2, 2, 0
  88:	dc600a51 	st.b	r3, (r0, 0xa51)	// *(<arg0> + 0xa51) = *(<arg0> + 0xa51)
loc_8c:
  8c:	d8450875 	ld.b	r2, (r5, 0x875)	// regs: r2=*(0x875)
  90:	d8640a4e 	ld.b	r3, (r4, 0xa4e)	// regs: r3=*(<arg0> + 0xa4e)
  94:	c4425442 	zext	r2, r2, 2, 2	// regs: r2=zext(*(0x875))
  98:	c4625c02 	ins	r3, r2, 2, 2
  9c:	d8450875 	ld.b	r2, (r5, 0x875)	// regs: r2=*(0x875)
  a0:	c4825482 	zext	r2, r2, 4, 4	// regs: r2=zext(*(0x875))
  a4:	d8250876 	ld.b	r1, (r5, 0x876)	// regs: r1=*(0x876)
  a8:	c4625c03 	ins	r3, r2, 3, 3
  ac:	d8440a4f 	ld.b	r2, (r4, 0xa4f)	// regs: r2=*(<arg0> + 0xa4f)
  b0:	c4415cc0 	ins	r2, r1, 6, 0
  b4:	dc440a4f 	st.b	r2, (r4, 0xa4f)	// *(<arg0> + 0xa4f) = *(<arg0> + 0xa4f)
  b8:	d8450876 	ld.b	r2, (r5, 0x876)	// regs: r2=*(0x876)
  bc:	d8240a4f 	ld.b	r1, (r4, 0xa4f)	// regs: r1=*(<arg0> + 0xa4f)
  c0:	c4e254e2 	zext	r2, r2, 7, 7	// regs: r2=zext(*(0x876))
  c4:	c4225c07 	ins	r1, r2, 7, 7
  c8:	dc240a4f 	st.b	r1, (r4, 0xa4f)	// *(<arg0> + 0xa4f) = *(<arg0> + 0xa4f)
  cc:	d8250877 	ld.b	r1, (r5, 0x877)	// regs: r1=*(0x877)
  d0:	d8440a50 	ld.b	r2, (r4, 0xa50)	// regs: r2=*(<arg0> + 0xa50)
  d4:	c4415cc0 	ins	r2, r1, 6, 0
  d8:	dc440a50 	st.b	r2, (r4, 0xa50)	// *(<arg0> + 0xa50) = *(<arg0> + 0xa50)
  dc:	d8450877 	ld.b	r2, (r5, 0x877)	// regs: r2=*(0x877)
  e0:	d8240a50 	ld.b	r1, (r4, 0xa50)	// regs: r1=*(<arg0> + 0xa50)
  e4:	c4e254e2 	zext	r2, r2, 7, 7	// regs: r2=zext(*(0x877))
  e8:	c4225c07 	ins	r1, r2, 7, 7
  ec:	dc240a50 	st.b	r1, (r4, 0xa50)	// *(<arg0> + 0xa50) = *(<arg0> + 0xa50)
  f0:	d84508e0 	ld.b	r2, (r5, 0x8e0)	// regs: r2=*(0x8e0)
  f4:	c4625c24 	ins	r3, r2, 5, 4
  f8:	dc640a4e 	st.b	r3, (r4, 0xa4e)	// *(<arg0> + 0xa4e) = *(<arg0> + 0xa4e)
  fc:	d8652154 	ld.w	r3, (r5, 0x550)	// regs: r3=*(0x550)
 100:	dc642272 	st.w	r3, (r4, 0x9c8)	// *(<arg0> + 0x9c8) = *(0x550)
 104:	d86520f5 	ld.w	r3, (r5, 0x3d4)	// regs: r3=*(0x3d4)
 108:	dc642297 	st.w	r3, (r4, 0xa5c)	// *(<arg0> + 0xa5c) = *(0x3d4)
 10c:	3206      	movi	r2, 6	// regs: r2=0x6
 10e:	1139      	lrw	r1, 0x0	// regs: r1=0x0
 110:	e40409ef 	addi	r0, r4, 2544	// regs: r0=(<arg0> + 0x9f0)
 114:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x114>, r1=<clobbered>
 118:	3224      	movi	r2, 36	// regs: r2=0x24
 11a:	1137      	lrw	r1, 0x0	// regs: r1=0x0
 11c:	e40409cb 	addi	r0, r4, 2508	// regs: r0=(<arg0> + 0x9cc)
 120:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x120>, r1=<clobbered>
 124:	3206      	movi	r2, 6	// regs: r2=0x6
 126:	1135      	lrw	r1, 0x0	// regs: r1=0x0
 128:	e40409f5 	addi	r0, r4, 2550	// regs: r0=(<arg0> + 0x9f6)
 12c:	e0000000 	bsr	0x0	// <memcpy>; regs: r0=<ret memcpy@0x12c>, r1=<clobbered>
 130:	d9850378 	ld.b	r12, (r5, 0x378)	// regs: r12=*(0x378)
 134:	3200      	movi	r2, 0	// regs: r2=0x0
 136:	dd840a4c 	st.b	r12, (r4, 0xa4c)	// *(<arg0> + 0xa4c) = *(0x378)
 13a:	6ccb      	mov	r3, r2	// regs: r3=0x0
loc_13c:
 13c:	670d      	cmplt	r3, r12
 13e:	2217      	addi	r2, 24	// regs: r2=(r2 + 0x18)
 140:	082d      	bt	0x19a	// if (T) goto loc_19a;
 142:	e92b0005 	bnez	r11, 0x14c	// if (r11 != 0x0) goto loc_14c;
 146:	3302      	movi	r3, 2	// regs: r3=0x2
 148:	dc6409c0 	st.b	r3, (r4, 0x9c0)	// *(<arg0> + 0x9c0) = 0x2
loc_14c:
 14c:	e92a0005 	bnez	r10, 0x156	// if (r10 != 0x0) goto loc_156;
 150:	330f      	movi	r3, 15	// regs: r3=0xf
 152:	dc6409c1 	st.b	r3, (r4, 0x9c1)	// *(<arg0> + 0x9c1) = 0xf
loc_156:
 156:	e9290005 	bnez	r9, 0x160	// if (r9 != 0x0) goto loc_160;
 15a:	331f      	movi	r3, 31	// regs: r3=0x1f
 15c:	dc6409c2 	st.b	r3, (r4, 0x9c2)	// *(<arg0> + 0x9c2) = 0x1f
loc_160:
 160:	eb480001 	cmpnei	r8, 1
 164:	dce42280 	st.w	r7, (r4, 0xa00)	// *(<arg0> + 0xa00) = zext(*(0x338))
 168:	0c2e      	bf	0x1c4	// if (r8 == 0x1) goto loc_1c4;
 16a:	eb480000 	cmpnei	r8, 0
 16e:	0c3c      	bf	0x1e6	// if (r8 == 0x0) goto loc_1e6;
 170:	eb480002 	cmpnei	r8, 2
 174:	0c1d      	bf	0x1ae	// if (r8 == 0x2) goto loc_1ae;
 176:	eb480003 	cmpnei	r8, 3
 17a:	080e      	bt	0x196	// if (r8 != 0x3) goto loc_196;
 17c:	e4c62007 	andi	r6, r6, 7	// regs: r6=(*(0x309) & 0x7)
 180:	33fa      	movi	r3, 250	// regs: r3=0xfa
 182:	dcc409c3 	st.b	r6, (r4, 0x9c3)	// *(<arg0> + 0x9c3) = (*(0x309) & 0x7)
 186:	4363      	lsli	r3, r3, 3	// regs: r3=0x7d0
 188:	4ec1      	lsri	r6, r6, 1	// regs: r6=((*(0x309) & 0x7) >> 0x1)
 18a:	7d8c      	mult	r6, r3	// regs: r6=(((*(0x309) & 0x7) >> 0x1) * 0x7d0)
 18c:	e4e71bb7 	subi	r7, r7, 3000	// regs: r7=(zext(*(0x338)) - 0xbb8)
loc_190:
 190:	619c      	addu	r6, r7	// regs: r6=(r6 + r7)
loc_192:
 192:	dcc42280 	st.w	r6, (r4, 0xa00)	// *(<arg0> + 0xa00) = r6
loc_196:
 196:	3000      	movi	r0, 0	// regs: r0=0x0
 198:	1498      	pop	r4-r11, r15
loc_19a:
 19a:	1015      	lrw	r0, 0x0	// regs: r0=0x0
 19c:	4322      	lsli	r1, r3, 2	// regs: r1=(r3 << 0x2)
 19e:	6008      	addu	r0, r2	// regs: r0=(0x0 + (r2 + 0x18))
 1a0:	6050      	addu	r1, r4	// regs: r1=((r3 << 0x2) + <arg0>)
 1a2:	d800202a 	ld.w	r0, (r0, 0xa8)	// regs: r0=*(((0x0 + (r2 + 0x18)) + 0xa8))
 1a6:	dc012283 	st.w	r0, (r1, 0xa0c)	// *((((r3 << 0x2) + <arg0>) + 0xa0c)) = *(((0x0 + (r2 + 0x18)) + 0xa8))
 1aa:	2300      	addi	r3, 1	// regs: r3=(r3 + 0x1)
 1ac:	07c8      	br	0x13c	// goto loc_13c;
loc_1ae:
 1ae:	e4c62003 	andi	r6, r6, 3	// regs: r6=(*(0x309) & 0x3)
 1b2:	33fa      	movi	r3, 250	// regs: r3=0xfa
 1b4:	dcc409c3 	st.b	r6, (r4, 0x9c3)	// *(<arg0> + 0x9c3) = (*(0x309) & 0x3)
 1b8:	4363      	lsli	r3, r3, 3	// regs: r3=0x7d0
 1ba:	4ec1      	lsri	r6, r6, 1	// regs: r6=((*(0x309) & 0x3) >> 0x1)
 1bc:	7d8c      	mult	r6, r3	// regs: r6=(((*(0x309) & 0x3) >> 0x1) * 0x7d0)
 1be:	e4e713e7 	subi	r7, r7, 1000	// regs: r7=(zext(*(0x338)) - 0x3e8)
 1c2:	07e7      	br	0x190	// goto loc_190;
loc_1c4:
 1c4:	d8640a4e 	ld.b	r3, (r4, 0xa4e)	// regs: r3=*(<arg0> + 0xa4e)
 1c8:	e4632040 	andi	r3, r3, 64	// regs: r3=(*(<arg0> + 0xa4e) & 0x40)
 1cc:	e9030008 	bez	r3, 0x1dc	// if (r3 == 0x0) goto loc_1dc;
 1d0:	3300      	movi	r3, 0	// regs: r3=0x0
 1d2:	dc6409c3 	st.b	r3, (r4, 0x9c3)	// *(<arg0> + 0x9c3) = 0x0
 1d6:	e4c701f3 	addi	r6, r7, 500	// regs: r6=(zext(*(0x338)) + 0x1f4)
 1da:	07dc      	br	0x192	// goto loc_192;
loc_1dc:
 1dc:	e4c62001 	andi	r6, r6, 1	// regs: r6=(*(0x309) & 0x1)
 1e0:	dcc409c3 	st.b	r6, (r4, 0x9c3)	// *(<arg0> + 0x9c3) = (*(0x309) & 0x1)
 1e4:	07d9      	br	0x196	// goto loc_196;
loc_1e6:
 1e6:	dd0409c3 	st.b	r8, (r4, 0x9c3)	// *(<arg0> + 0x9c3) = *(0x308)
 1ea:	07d6      	br	0x196	// goto loc_196;
 1ec:	00000000 	.long	0x00000000	// <ah_lmac>
 1f0:	00000000 	.long	0x00000000	// <ah_lmac+0x526>
 1f4:	00000000 	.long	0x00000000	// <ah_lmac+0x52c>
 1f8:	00000000 	.long	0x00000000	// <ah_lmac+0x302>

Disassembly of section .text.lmac_ah_ioctl:

00000000 <lmac_ah_ioctl>: // arg_bytes: 16
   0:	14d0      	push	r15
   2:	e901000c 	bez	r1, 0x1a	// if (r1 == 0x0) goto loc_1a;
   6:	c700502d 	bmaski	r13, 25
   a:	6474      	cmphs	r13, r1
   c:	0c04      	bf	0x14	// if (!T) goto loc_14;
   e:	e0000000 	bsr	0x0	// <lmac_set_cfg> // arg_bytes: 16; regs: r0=<ret lmac_set_cfg@0xe>, r1=<clobbered>
loc_12:
  12:	1490      	pop	r15
loc_14:
  14:	e0000000 	bsr	0x0	// <lmac_get_cfg> // arg_bytes: 0; regs: r0=<ret lmac_get_cfg@0x14>, r1=<clobbered>
  18:	07fd      	br	0x12	// goto loc_12;
loc_1a:
  1a:	3000      	movi	r0, 0	// regs: r0=0x0
  1c:	2815      	subi	r0, 22	// regs: r0=0xffffffea
  1e:	07fa      	br	0x12	// goto loc_12;
