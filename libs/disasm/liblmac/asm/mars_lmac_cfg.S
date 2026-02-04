
disasm/liblmac/obj/mars_lmac_cfg.o:     file format elf32-csky-little


Disassembly of section .text.lmac_cfg_init:

00000000 <lmac_cfg_init>:
   0:	14d8      	push      	r4-r11, r15
   2:	1421      	subi      	r14, r14, 4
   4:	ea84011e 	lrw      	r4, 0x0	// 47c <lmac_cfg_init+0x47c>
   8:	3380      	movi      	r3, 128
   a:	4365      	lsli      	r3, r3, 5
   c:	b860      	st.w      	r3, (r14, 0x0)
   e:	b472      	st.w      	r3, (r4, 0x48)
  10:	3382      	movi      	r3, 130
  12:	4364      	lsli      	r3, r3, 4
  14:	b473      	st.w      	r3, (r4, 0x4c)
  16:	300f      	movi      	r0, 15
  18:	d864051a 	ld.b      	r3, (r4, 0x51a)
  1c:	c4605c60 	ins      	r3, r0, 3, 0
  20:	dc64051a 	st.b      	r3, (r4, 0x51a)
  24:	300d      	movi      	r0, 13
  26:	d8640516 	ld.b      	r3, (r4, 0x516)
  2a:	c4605c60 	ins      	r3, r0, 3, 0
  2e:	dc640516 	st.b      	r3, (r4, 0x516)
  32:	ea0b000b 	movi      	r11, 11
  36:	d864051e 	ld.b      	r3, (r4, 0x51e)
  3a:	c46b5c60 	ins      	r3, r11, 3, 0
  3e:	dc64051e 	st.b      	r3, (r4, 0x51e)
  42:	3009      	movi      	r0, 9
  44:	d8640522 	ld.b      	r3, (r4, 0x522)
  48:	3500      	movi      	r5, 0
  4a:	ea0a000f 	movi      	r10, 15
  4e:	3603      	movi      	r6, 3
  50:	3207      	movi      	r2, 7
  52:	311f      	movi      	r1, 31
  54:	ea080002 	movi      	r8, 2
  58:	c4605c60 	ins      	r3, r0, 3, 0
  5c:	ac56      	st.h      	r2, (r4, 0x2c)
  5e:	ac5a      	st.h      	r2, (r4, 0x34)
  60:	ac3d      	st.h      	r1, (r4, 0x3a)
  62:	ac3c      	st.h      	r1, (r4, 0x38)
  64:	ac5f      	st.h      	r2, (r4, 0x3e)
  66:	a45d      	st.b      	r2, (r4, 0x1d)
  68:	dd04001e 	st.b      	r8, (r4, 0x1e)
  6c:	dd04001f 	st.b      	r8, (r4, 0x1f)
  70:	dc640522 	st.b      	r3, (r4, 0x522)
  74:	d8e4051b 	ld.b      	r7, (r4, 0x51b)
  78:	3306      	movi      	r3, 6
  7a:	dca420d3 	st.w      	r5, (r4, 0x34c)
  7e:	dca420d4 	st.w      	r5, (r4, 0x350)
  82:	dd441015 	st.h      	r10, (r4, 0x2a)
  86:	dd441014 	st.h      	r10, (r4, 0x28)
  8a:	acd7      	st.h      	r6, (r4, 0x2e)
  8c:	dd441019 	st.h      	r10, (r4, 0x32)
  90:	dd441018 	st.h      	r10, (r4, 0x30)
  94:	acdb      	st.h      	r6, (r4, 0x36)
  96:	dd44101e 	st.h      	r10, (r4, 0x3c)
  9a:	a4dc      	st.b      	r6, (r4, 0x1c)
  9c:	b4b1      	st.w      	r5, (r4, 0x44)
  9e:	b4b0      	st.w      	r5, (r4, 0x40)
  a0:	ea090004 	movi      	r9, 4
  a4:	d9a40517 	ld.b      	r13, (r4, 0x517)
  a8:	d8040523 	ld.b      	r0, (r4, 0x523)
  ac:	c4e35c60 	ins      	r7, r3, 3, 0
  b0:	c5a35c60 	ins      	r13, r3, 3, 0
  b4:	c4095c60 	ins      	r0, r9, 3, 0
  b8:	3305      	movi      	r3, 5
  ba:	ea090007 	movi      	r9, 7
  be:	c4035c64 	ins      	r0, r3, 7, 4
  c2:	d984051f 	ld.b      	r12, (r4, 0x51f)
  c6:	c5a95c64 	ins      	r13, r9, 7, 4
  ca:	dc040523 	st.b      	r0, (r4, 0x523)
  ce:	3009      	movi      	r0, 9
  d0:	dda40517 	st.b      	r13, (r4, 0x517)
  d4:	dc040084 	st.b      	r0, (r4, 0x84)
  d8:	c5835c60 	ins      	r12, r3, 3, 0
  dc:	307f      	movi      	r0, 127
  de:	ea0d0006 	movi      	r13, 6
  e2:	c58d5c64 	ins      	r12, r13, 7, 4
  e6:	dc041051 	st.h      	r0, (r4, 0xa2)
  ea:	dc041050 	st.h      	r0, (r4, 0xa0)
  ee:	dc041052 	st.h      	r0, (r4, 0xa4)
  f2:	ea0d0032 	movi      	r13, 50
  f6:	303f      	movi      	r0, 63
  f8:	dc041053 	st.h      	r0, (r4, 0xa6)
  fc:	dd040867 	st.b      	r8, (r4, 0x867)
 100:	dda41197 	st.h      	r13, (r4, 0x32e)
 104:	300a      	movi      	r0, 10
 106:	d9a411b0 	ld.h      	r13, (r4, 0x360)
 10a:	ea0801ff 	movi      	r8, 511
 10e:	c4e95c64 	ins      	r7, r9, 7, 4
 112:	dd84051f 	st.b      	r12, (r4, 0x51f)
 116:	dd640085 	st.b      	r11, (r4, 0x85)
 11a:	dd24104b 	st.h      	r9, (r4, 0x96)
 11e:	dc04030c 	st.b      	r0, (r4, 0x30c)
 122:	e5251000 	subi      	r9, r5, 1
 126:	ea0c0014 	movi      	r12, 20
 12a:	ea0b0028 	movi      	r11, 40
 12e:	c5a85d01 	ins      	r13, r8, 9, 1
 132:	301e      	movi      	r0, 30
 134:	dce4051b 	st.b      	r7, (r4, 0x51b)
 138:	dc440086 	st.b      	r2, (r4, 0x86)
 13c:	dc640087 	st.b      	r3, (r4, 0x87)
 140:	dc241049 	st.h      	r1, (r4, 0x92)
 144:	dc241048 	st.h      	r1, (r4, 0x90)
 148:	dd240864 	st.b      	r9, (r4, 0x864)
 14c:	dd84030d 	st.b      	r12, (r4, 0x30d)
 150:	dc04030e 	st.b      	r0, (r4, 0x30e)
 154:	dd64030f 	st.b      	r11, (r4, 0x30f)
 158:	d8040310 	ld.b      	r0, (r4, 0x310)
 15c:	dd44104a 	st.h      	r10, (r4, 0x94)
 160:	dca4202f 	st.w      	r5, (r4, 0xbc)
 164:	dcc40308 	st.b      	r6, (r4, 0x308)
 168:	dca40866 	st.b      	r5, (r4, 0x866)
 16c:	dcc40316 	st.b      	r6, (r4, 0x316)
 170:	dda411b0 	st.h      	r13, (r4, 0x360)
 174:	dc440313 	st.b      	r2, (r4, 0x313)
 178:	320a      	movi      	r2, 10
 17a:	dc4411de 	st.h      	r2, (r4, 0x3bc)
 17e:	3264      	movi      	r2, 100
 180:	dc4411df 	st.h      	r2, (r4, 0x3be)
 184:	ea224001 	movih      	r2, 16385
 188:	3701      	movi      	r7, 1
 18a:	b441      	st.w      	r2, (r4, 0x4)
 18c:	d8440361 	ld.b      	r2, (r4, 0x361)
 190:	c4475c02 	ins      	r2, r7, 2, 2
 194:	dd840317 	st.b      	r12, (r4, 0x317)
 198:	c4455c03 	ins      	r2, r5, 3, 3
 19c:	d98403df 	ld.b      	r12, (r4, 0x3df)
 1a0:	dc440361 	st.b      	r2, (r4, 0x361)
 1a4:	c5855c03 	ins      	r12, r5, 3, 3
 1a8:	d84420d8 	ld.w      	r2, (r4, 0x360)
 1ac:	dd8403df 	st.b      	r12, (r4, 0x3df)
 1b0:	ea0c0016 	movi      	r12, 22
 1b4:	c44c5cec 	ins      	r2, r12, 19, 12
 1b8:	dc4420d8 	st.w      	r2, (r4, 0x360)
 1bc:	3200      	movi      	r2, 0
 1be:	2a3b      	subi      	r2, 60
 1c0:	dc44031e 	st.b      	r2, (r4, 0x31e)
 1c4:	d84411b1 	ld.h      	r2, (r4, 0x362)
 1c8:	c4435ce4 	ins      	r2, r3, 11, 4
 1cc:	dc4411b1 	st.h      	r2, (r4, 0x362)
 1d0:	3200      	movi      	r2, 0
 1d2:	2a53      	subi      	r2, 84
 1d4:	dc44031f 	st.b      	r2, (r4, 0x31f)
 1d8:	3200      	movi      	r2, 0
 1da:	2a56      	subi      	r2, 87
 1dc:	dc440320 	st.b      	r2, (r4, 0x320)
 1e0:	320a      	movi      	r2, 10
 1e2:	dc4420d7 	st.w      	r2, (r4, 0x35c)
 1e6:	d8440336 	ld.b      	r2, (r4, 0x336)
 1ea:	c4475c00 	ins      	r2, r7, 0, 0
 1ee:	dc440336 	st.b      	r2, (r4, 0x336)
 1f2:	d84411b6 	ld.h      	r2, (r4, 0x36c)
 1f6:	c4435c85 	ins      	r2, r3, 9, 5
 1fa:	dc4411b6 	st.h      	r2, (r4, 0x36c)
 1fe:	c4435c80 	ins      	r2, r3, 4, 0
 202:	dc44036c 	st.b      	r2, (r4, 0x36c)
 206:	9840      	ld.w      	r2, (r14, 0x0)
 208:	dc4420dd 	st.w      	r2, (r4, 0x374)
 20c:	ea0800fa 	movi      	r8, 250
 210:	3264      	movi      	r2, 100
 212:	ea0d0010 	movi      	r13, 16
 216:	721c      	lsl      	r8, r7
 218:	dc240312 	st.b      	r1, (r4, 0x312)
 21c:	333c      	movi      	r3, 60
 21e:	3114      	movi      	r1, 20
 220:	dc4420e5 	st.w      	r2, (r4, 0x394)
 224:	ea020bb8 	movi      	r2, 3000
 228:	dda40315 	st.b      	r13, (r4, 0x315)
 22c:	b426      	st.w      	r1, (r4, 0x18)
 22e:	dd24032a 	st.b      	r9, (r4, 0x32a)
 232:	dc640348 	st.b      	r3, (r4, 0x348)
 236:	dc2411bd 	st.h      	r1, (r4, 0x37a)
 23a:	dcc40309 	st.b      	r6, (r4, 0x309)
 23e:	dd0420e2 	st.w      	r8, (r4, 0x388)
 242:	dc4420e4 	st.w      	r2, (r4, 0x390)
 246:	ea022710 	movi      	r2, 10000
 24a:	dc4420e3 	st.w      	r2, (r4, 0x38c)
 24e:	32fa      	movi      	r2, 250
 250:	4243      	lsli      	r2, r2, 3
 252:	dc4420e7 	st.w      	r2, (r4, 0x39c)
 256:	ea02cd14 	movi      	r2, 52500
 25a:	c4624902 	rotli      	r2, r2, 3
 25e:	dc4420eb 	st.w      	r2, (r4, 0x3ac)
 262:	ea021770 	movi      	r2, 6000
 266:	dc4420ec 	st.w      	r2, (r4, 0x3b0)
 26a:	d844037c 	ld.b      	r2, (r4, 0x37c)
 26e:	d824037d 	ld.b      	r1, (r4, 0x37d)
 272:	c4475c01 	ins      	r2, r7, 1, 1
 276:	c4275c02 	ins      	r1, r7, 2, 2
 27a:	c4475c00 	ins      	r2, r7, 0, 0
 27e:	dc24037d 	st.b      	r1, (r4, 0x37d)
 282:	dc44037c 	st.b      	r2, (r4, 0x37c)
 286:	d82411be 	ld.h      	r1, (r4, 0x37c)
 28a:	ea0c0006 	movi      	r12, 6
 28e:	dc64031c 	st.b      	r3, (r4, 0x31c)
 292:	d8640360 	ld.b      	r3, (r4, 0x360)
 296:	c42c5ce2 	ins      	r1, r12, 9, 2
 29a:	c4655c00 	ins      	r3, r5, 0, 0
 29e:	dc2411be 	st.h      	r1, (r4, 0x37c)
 2a2:	dc640360 	st.b      	r3, (r4, 0x360)
 2a6:	3332      	movi      	r3, 50
 2a8:	dc640365 	st.b      	r3, (r4, 0x365)
 2ac:	d864037d 	ld.b      	r3, (r4, 0x37d)
 2b0:	c4655c04 	ins      	r3, r5, 4, 4
 2b4:	dc64037d 	st.b      	r3, (r4, 0x37d)
 2b8:	d86420df 	ld.w      	r3, (r4, 0x37c)
 2bc:	c46c5cad 	ins      	r3, r12, 18, 13
 2c0:	dc6420df 	st.w      	r3, (r4, 0x37c)
 2c4:	d864037e 	ld.b      	r3, (r4, 0x37e)
 2c8:	c4655c03 	ins      	r3, r5, 3, 3
 2cc:	dc64037e 	st.b      	r3, (r4, 0x37e)
 2d0:	d86411bf 	ld.h      	r3, (r4, 0x37e)
 2d4:	3104      	movi      	r1, 4
 2d6:	c4615ca4 	ins      	r3, r1, 9, 4
 2da:	dc6411bf 	st.h      	r3, (r4, 0x37e)
 2de:	d864037f 	ld.b      	r3, (r4, 0x37f)
 2e2:	e46320fb 	andi      	r3, r3, 251
 2e6:	c4675c03 	ins      	r3, r7, 3, 3
 2ea:	dd64031d 	st.b      	r11, (r4, 0x31d)
 2ee:	dc64037f 	st.b      	r3, (r4, 0x37f)
 2f2:	3102      	movi      	r1, 2
 2f4:	d8640860 	ld.b      	r3, (r4, 0x860)
 2f8:	ea8b0062 	lrw      	r11, 0x0	// 480 <lmac_cfg_init+0x480>
 2fc:	ea091388 	movi      	r9, 5000
 300:	c4615c40 	ins      	r3, r1, 2, 0
 304:	d8440338 	ld.b      	r2, (r4, 0x338)
 308:	dd2420e6 	st.w      	r9, (r4, 0x398)
 30c:	dd2420e8 	st.w      	r9, (r4, 0x3a0)
 310:	dd0420ed 	st.w      	r8, (r4, 0x3b4)
 314:	dcc40364 	st.b      	r6, (r4, 0x364)
 318:	dc640860 	st.b      	r3, (r4, 0x860)
 31c:	d82b0004 	ld.b      	r1, (r11, 0x4)
 320:	d8640680 	ld.b      	r3, (r4, 0x680)
 324:	c4615c41 	ins      	r3, r1, 3, 1
 328:	dc640680 	st.b      	r3, (r4, 0x680)
 32c:	3332      	movi      	r3, 50
 32e:	dc641196 	st.h      	r3, (r4, 0x32c)
 332:	d864036d 	ld.b      	r3, (r4, 0x36d)
 336:	c4475c00 	ins      	r2, r7, 0, 0
 33a:	e46320f3 	andi      	r3, r3, 243
 33e:	c4655c24 	ins      	r3, r5, 5, 4
 342:	e44220fb 	andi      	r2, r2, 251
 346:	dc64036d 	st.b      	r3, (r4, 0x36d)
 34a:	c4455c01 	ins      	r2, r5, 1, 1
 34e:	d86420db 	ld.w      	r3, (r4, 0x36c)
 352:	dc440338 	st.b      	r2, (r4, 0x338)
 356:	321b      	movi      	r2, 27
 358:	c4625cee 	ins      	r3, r2, 21, 14
 35c:	dc6420db 	st.w      	r3, (r4, 0x36c)
 360:	3396      	movi      	r3, 150
 362:	c4075c00 	ins      	r0, r7, 0, 0
 366:	4361      	lsli      	r3, r3, 1
 368:	dc64133b 	st.h      	r3, (r4, 0x676)
 36c:	c4075c01 	ins      	r0, r7, 1, 1
 370:	3300      	movi      	r3, 0
 372:	2b1d      	subi      	r3, 30
 374:	e40020fb 	andi      	r0, r0, 251
 378:	c4055c03 	ins      	r0, r5, 3, 3
 37c:	dc640300 	st.b      	r3, (r4, 0x300)
 380:	320f      	movi      	r2, 15
 382:	d8640319 	ld.b      	r3, (r4, 0x319)
 386:	c4625c62 	ins      	r3, r2, 5, 2
 38a:	dc040310 	st.b      	r0, (r4, 0x310)
 38e:	e40409ff 	addi      	r0, r4, 2560
 392:	dc640319 	st.b      	r3, (r4, 0x319)
 396:	dca403e3 	st.b      	r5, (r4, 0x3e3)
 39a:	dce403e4 	st.b      	r7, (r4, 0x3e4)
 39e:	dca4119a 	st.h      	r5, (r4, 0x334)
 3a2:	e0000000 	bsr      	0x0	// 0 <os_mutex_init>
 3a6:	e46409f7 	addi      	r3, r4, 2552
 3aa:	dc64227e 	st.w      	r3, (r4, 0x9f8)
 3ae:	dc64227f 	st.w      	r3, (r4, 0x9fc)
 3b2:	3200      	movi      	r2, 0
 3b4:	3300      	movi      	r3, 0
 3b6:	dc4420f0 	st.w      	r2, (r4, 0x3c0)
 3ba:	dc6420f1 	st.w      	r3, (r4, 0x3c4)
 3be:	dc4420f3 	st.w      	r2, (r4, 0x3cc)
 3c2:	dc6420f4 	st.w      	r3, (r4, 0x3d0)
 3c6:	d8640338 	ld.b      	r3, (r4, 0x338)
 3ca:	c4675c03 	ins      	r3, r7, 3, 3
 3ce:	dc640338 	st.b      	r3, (r4, 0x338)
 3d2:	d86411a5 	ld.h      	r3, (r4, 0x34a)
 3d6:	c4685dc1 	ins      	r3, r8, 15, 1
 3da:	dc6411a5 	st.h      	r3, (r4, 0x34a)
 3de:	3240      	movi      	r2, 64
 3e0:	d8640a63 	ld.b      	r3, (r4, 0xa63)
 3e4:	c4625cc0 	ins      	r3, r2, 6, 0
 3e8:	dc640a63 	st.b      	r3, (r4, 0xa63)
 3ec:	d8640310 	ld.b      	r3, (r4, 0x310)
 3f0:	c4655c05 	ins      	r3, r5, 5, 5
 3f4:	dc640310 	st.b      	r3, (r4, 0x310)
 3f8:	d8640319 	ld.b      	r3, (r4, 0x319)
 3fc:	c4655c06 	ins      	r3, r5, 6, 6
 400:	dc640319 	st.b      	r3, (r4, 0x319)
 404:	3233      	movi      	r2, 51
 406:	d864031a 	ld.b      	r3, (r4, 0x31a)
 40a:	c4625cc1 	ins      	r3, r2, 7, 1
 40e:	dc64031a 	st.b      	r3, (r4, 0x31a)
 412:	d864031b 	ld.b      	r3, (r4, 0x31b)
 416:	c4675c00 	ins      	r3, r7, 0, 0
 41a:	dc64031b 	st.b      	r3, (r4, 0x31b)
 41e:	d86b0006 	ld.b      	r3, (r11, 0x6)
 422:	dc64068e 	st.b      	r3, (r4, 0x68e)
 426:	331e      	movi      	r3, 30
 428:	dc6403e1 	st.b      	r3, (r4, 0x3e1)
 42c:	d86403e2 	ld.b      	r3, (r4, 0x3e2)
 430:	c4675c00 	ins      	r3, r7, 0, 0
 434:	d84408e1 	ld.b      	r2, (r4, 0x8e1)
 438:	689c      	and      	r2, r7
 43a:	dca41504 	st.h      	r5, (r4, 0xa08)
 43e:	dca41506 	st.h      	r5, (r4, 0xa0c)
 442:	dca42267 	st.w      	r5, (r4, 0x99c)
 446:	dd4411e5 	st.h      	r10, (r4, 0x3ca)
 44a:	dd4411e4 	st.h      	r10, (r4, 0x3c8)
 44e:	dcc40311 	st.b      	r6, (r4, 0x311)
 452:	dca411ee 	st.h      	r5, (r4, 0x3dc)
 456:	dd2420f5 	st.w      	r9, (r4, 0x3d4)
 45a:	dc6403e2 	st.b      	r3, (r4, 0x3e2)
 45e:	d8640875 	ld.b      	r3, (r4, 0x875)
 462:	c4625c02 	ins      	r3, r2, 2, 2
 466:	c4625c03 	ins      	r3, r2, 3, 3
 46a:	e4040bb7 	addi      	r0, r4, 3000
 46e:	dc640875 	st.b      	r3, (r4, 0x875)
 472:	e0000000 	bsr      	0x0	// 0 <os_mutex_init>
 476:	6c17      	mov      	r0, r5
 478:	1401      	addi      	r14, r14, 4
 47a:	1498      	pop      	r4-r11, r15
	...

Disassembly of section .text.lmac_cfg_cw_param:

00000000 <lmac_cfg_cw_param>:
   0:	3803      	cmphsi      	r0, 4
   2:	0818      	bt      	0x32	// 32 <lmac_cfg_cw_param+0x32>
   4:	ea0c7fff 	movi      	r12, 32767
   8:	eb017fff 	cmphsi      	r1, 32768
   c:	c42c0c40 	inct      	r1, r12, 0
  10:	1069      	lrw      	r3, 0x0	// 34 <lmac_cfg_cw_param+0x34>
  12:	e5a00013 	addi      	r13, r0, 20
  16:	7445      	zexth      	r1, r1
  18:	eb027fff 	cmphsi      	r2, 32768
  1c:	d5a30441 	str.h      	r1, (r3, r13 << 1)
  20:	c44c0c40 	inct      	r2, r12, 0
  24:	e5a0001b 	addi      	r13, r0, 28
  28:	2017      	addi      	r0, 24
  2a:	d5a30442 	str.h      	r2, (r3, r13 << 1)
  2e:	d4030441 	str.h      	r1, (r3, r0 << 1)
  32:	783c      	jmp      	r15
  34:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_cfg_aifs_param:

00000000 <lmac_cfg_aifs_param>:
   0:	3803      	cmphsi      	r0, 4
   2:	0808      	bt      	0x12	// 12 <lmac_cfg_aifs_param+0x12>
   4:	1064      	lrw      	r3, 0x0	// 14 <lmac_cfg_aifs_param+0x14>
   6:	600c      	addu      	r0, r3
   8:	390f      	cmphsi      	r1, 16
   a:	330f      	movi      	r3, 15
   c:	c4230c40 	inct      	r1, r3, 0
  10:	a03c      	st.b      	r1, (r0, 0x1c)
  12:	783c      	jmp      	r15
  14:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_cfg_txop_param:

00000000 <lmac_cfg_txop_param>:
   0:	3803      	cmphsi      	r0, 4
   2:	0808      	bt      	0x12	// 12 <lmac_cfg_txop_param+0x12>
   4:	33fa      	movi      	r3, 250
   6:	4362      	lsli      	r3, r3, 2
   8:	7c4c      	mult      	r1, r3
   a:	200f      	addi      	r0, 16
   c:	1062      	lrw      	r3, 0x0	// 14 <lmac_cfg_txop_param+0x14>
   e:	d4030881 	str.w      	r1, (r3, r0 << 2)
  12:	783c      	jmp      	r15
  14:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_cfg_set_aid:

00000000 <lmac_cfg_set_aid>:
   0:	14d3      	push      	r4-r6, r15
   2:	6d47      	mov      	r5, r1
   4:	1095      	lrw      	r4, 0x0	// 58 <lmac_cfg_set_aid+0x58>
   6:	6c87      	mov      	r2, r1
   8:	7595      	zexth      	r6, r5
   a:	1035      	lrw      	r1, 0x0	// 5c <lmac_cfg_set_aid+0x5c>
   c:	1015      	lrw      	r0, 0x0	// 60 <lmac_cfg_set_aid+0x60>
   e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  12:	e4240525 	addi      	r1, r4, 1318
  16:	6c1b      	mov      	r0, r6
  18:	dcc41198 	st.h      	r6, (r4, 0x330)
  1c:	e0000000 	bsr      	0x0	// 0 <partial_aid_calc>
  20:	d8640336 	ld.b      	r3, (r4, 0x336)
  24:	c4605ca1 	ins      	r3, r0, 6, 1
  28:	e4240525 	addi      	r1, r4, 1318
  2c:	6c1b      	mov      	r0, r6
  2e:	dc640336 	st.b      	r3, (r4, 0x336)
  32:	e0000000 	bsr      	0x0	// 0 <partial_aid_ndp_calc>
  36:	d864119b 	ld.h      	r3, (r4, 0x336)
  3a:	c4605d07 	ins      	r3, r0, 15, 7
  3e:	dc64119b 	st.h      	r3, (r4, 0x336)
  42:	e9250009 	bnez      	r5, 0x54	// 54 <lmac_cfg_set_aid+0x54>
  46:	3206      	movi      	r2, 6
  48:	e4240301 	addi      	r1, r4, 770
  4c:	e4040525 	addi      	r0, r4, 1318
  50:	e0000000 	bsr      	0x0	// 0 <memcpy>
  54:	3000      	movi      	r0, 0
  56:	1493      	pop      	r4-r6, r15
	...

Disassembly of section .text.lmac_cfg_set_mac:

00000000 <lmac_cfg_set_mac>:
   0:	14d1      	push      	r4, r15
   2:	1424      	subi      	r14, r14, 16
   4:	6d07      	mov      	r4, r1
   6:	8161      	ld.b      	r3, (r1, 0x1)
   8:	8140      	ld.b      	r2, (r1, 0x0)
   a:	8125      	ld.b      	r1, (r1, 0x5)
   c:	b823      	st.w      	r1, (r14, 0xc)
   e:	8424      	ld.b      	r1, (r4, 0x4)
  10:	b822      	st.w      	r1, (r14, 0x8)
  12:	8423      	ld.b      	r1, (r4, 0x3)
  14:	b821      	st.w      	r1, (r14, 0x4)
  16:	8422      	ld.b      	r1, (r4, 0x2)
  18:	b820      	st.w      	r1, (r14, 0x0)
  1a:	1007      	lrw      	r0, 0x0	// 34 <lmac_cfg_set_mac+0x34>
  1c:	1027      	lrw      	r1, 0x0	// 38 <lmac_cfg_set_mac+0x38>
  1e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  22:	3206      	movi      	r2, 6
  24:	6c53      	mov      	r1, r4
  26:	1006      	lrw      	r0, 0x0	// 3c <lmac_cfg_set_mac+0x3c>
  28:	e0000000 	bsr      	0x0	// 0 <memcpy>
  2c:	3000      	movi      	r0, 0
  2e:	1404      	addi      	r14, r14, 16
  30:	1491      	pop      	r4, r15
	...

Disassembly of section .text.lmac_ah_add_sta:

00000000 <lmac_ah_add_sta>:
   0:	14d8      	push      	r4-r11, r15
   2:	1426      	subi      	r14, r14, 24
   4:	e50e0013 	addi      	r8, r14, 20
   8:	6d8f      	mov      	r6, r3
   a:	3303      	movi      	r3, 3
   c:	dc680000 	st.b      	r3, (r8, 0x0)
  10:	3300      	movi      	r3, 0
  12:	dc680001 	st.b      	r3, (r8, 0x1)
  16:	3301      	movi      	r3, 1
  18:	dc680002 	st.b      	r3, (r8, 0x2)
  1c:	8625      	ld.b      	r1, (r6, 0x5)
  1e:	3302      	movi      	r3, 2
  20:	dc680003 	st.b      	r3, (r8, 0x3)
  24:	b823      	st.w      	r1, (r14, 0xc)
  26:	8624      	ld.b      	r1, (r6, 0x4)
  28:	b822      	st.w      	r1, (r14, 0x8)
  2a:	8623      	ld.b      	r1, (r6, 0x3)
  2c:	6e4b      	mov      	r9, r2
  2e:	b821      	st.w      	r1, (r14, 0x4)
  30:	8622      	ld.b      	r1, (r6, 0x2)
  32:	8661      	ld.b      	r3, (r6, 0x1)
  34:	8640      	ld.b      	r2, (r6, 0x0)
  36:	b820      	st.w      	r1, (r14, 0x0)
  38:	6c67      	mov      	r1, r9
  3a:	0309      	lrw      	r0, 0x0	// 290 <lmac_ah_add_sta+0x290>
  3c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  40:	6c5b      	mov      	r1, r6
  42:	ea00ffff 	movi      	r0, 65535
  46:	e0000000 	bsr      	0x0	// 0 <lmac_sta_get>
  4a:	6d03      	mov      	r4, r0
  4c:	e92000e8 	bnez      	r0, 0x21c	// 21c <lmac_ah_add_sta+0x21c>
  50:	e0000000 	bsr      	0x0	// 0 <lmac_alloc_sta>
  54:	6d03      	mov      	r4, r0
  56:	e9200009 	bnez      	r0, 0x68	// 68 <lmac_ah_add_sta+0x68>
  5a:	0310      	lrw      	r0, 0x0	// 294 <hgprintf+0x294>
  5c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  60:	3000      	movi      	r0, 0
  62:	2800      	subi      	r0, 1
  64:	1406      	addi      	r14, r14, 24
  66:	1498      	pop      	r4-r11, r15
  68:	03b3      	lrw      	r5, 0x0	// 298 <lmac_ah_add_sta+0x298>
  6a:	d8050317 	ld.b      	r0, (r5, 0x317)
  6e:	e0000000 	bsr      	0x0	// 0 <_os_malloc>
  72:	dc042027 	st.w      	r0, (r4, 0x9c)
  76:	e9200007 	bnez      	r0, 0x84	// 84 <lmac_ah_add_sta+0x84>
  7a:	6c13      	mov      	r0, r4
  7c:	e0000000 	bsr      	0x0	// 0 <_os_free>
  80:	0318      	lrw      	r0, 0x0	// 29c <lmac_ah_add_sta+0x29c>
  82:	07ed      	br      	0x5c	// 5c <lmac_ah_add_sta+0x5c>
  84:	5c1e      	addi      	r0, r4, 8
  86:	e0000000 	bsr      	0x0	// 0 <skb_list_init>
  8a:	3100      	movi      	r1, 0
  8c:	2900      	subi      	r1, 1
  8e:	e40509ff 	addi      	r0, r5, 2560
  92:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  96:	d865227f 	ld.w      	r3, (r5, 0x9fc)
  9a:	e40509f7 	addi      	r0, r5, 2552
  9e:	dc85227f 	st.w      	r4, (r5, 0x9fc)
  a2:	b400      	st.w      	r0, (r4, 0x0)
  a4:	b461      	st.w      	r3, (r4, 0x4)
  a6:	b380      	st.w      	r4, (r3, 0x0)
  a8:	d8651504 	ld.h      	r3, (r5, 0xa08)
  ac:	2300      	addi      	r3, 1
  ae:	e40509ff 	addi      	r0, r5, 2560
  b2:	dc651504 	st.h      	r3, (r5, 0xa08)
  b6:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  ba:	3300      	movi      	r3, 0
  bc:	d844006b 	ld.b      	r2, (r4, 0x6b)
  c0:	c4435c05 	ins      	r2, r3, 5, 5
  c4:	dc44006b 	st.b      	r2, (r4, 0x6b)
  c8:	3701      	movi      	r7, 1
  ca:	3201      	movi      	r2, 1
  cc:	13b3      	lrw      	r5, 0x0	// 298 <lmac_ah_add_sta+0x298>
  ce:	1315      	lrw      	r0, 0x0	// 2a0 <lmac_ah_add_sta+0x2a0>
  d0:	e5840143 	addi      	r12, r4, 324
  d4:	dc440097 	st.b      	r2, (r4, 0x97)
  d8:	dc440098 	st.b      	r2, (r4, 0x98)
  dc:	dd241034 	st.h      	r9, (r4, 0x68)
  e0:	dc640076 	st.b      	r3, (r4, 0x76)
  e4:	dc6400a0 	st.b      	r3, (r4, 0xa0)
  e8:	dc6400a2 	st.b      	r3, (r4, 0xa2)
  ec:	dce400ad 	st.b      	r7, (r4, 0xad)
  f0:	d8250308 	ld.b      	r1, (r5, 0x308)
  f4:	d84400ae 	ld.b      	r2, (r4, 0xae)
  f8:	d0200021 	ldr.b      	r1, (r0, r1 << 0)
  fc:	c4415c64 	ins      	r2, r1, 7, 4
 100:	dc4400ae 	st.b      	r2, (r4, 0xae)
 104:	3240      	movi      	r2, 64
 106:	dc44013f 	st.b      	r2, (r4, 0x13f)
 10a:	b844      	st.w      	r2, (r14, 0x10)
 10c:	3200      	movi      	r2, 0
 10e:	dc4c1007 	st.h      	r2, (r12, 0xe)
 112:	e4430014 	addi      	r2, r3, 21
 116:	4244      	lsli      	r2, r2, 4
 118:	3132      	movi      	r1, 50
 11a:	d4820021 	str.b      	r1, (r2, r4 << 0)
 11e:	4344      	lsli      	r2, r3, 4
 120:	6090      	addu      	r2, r4
 122:	d9ae2004 	ld.w      	r13, (r14, 0x10)
 126:	d802014f 	ld.b      	r0, (r2, 0x14f)
 12a:	c40d5cc0 	ins      	r0, r13, 6, 0
 12e:	ea0a0000 	movi      	r10, 0
 132:	ea0b0000 	movi      	r11, 0
 136:	dc02014f 	st.b      	r0, (r2, 0x14f)
 13a:	dd4c2000 	st.w      	r10, (r12, 0x0)
 13e:	dd6c2001 	st.w      	r11, (r12, 0x4)
 142:	d80210a6 	ld.h      	r0, (r2, 0x14c)
 146:	ea0d0000 	movi      	r13, 0
 14a:	c40d5d60 	ins      	r0, r13, 11, 0
 14e:	dc0210a6 	st.h      	r0, (r2, 0x14c)
 152:	d802014f 	ld.b      	r0, (r2, 0x14f)
 156:	e400207f 	andi      	r0, r0, 127
 15a:	d9a22053 	ld.w      	r13, (r2, 0x14c)
 15e:	2800      	subi      	r0, 1
 160:	c5a05d6c 	ins      	r13, r0, 23, 12
 164:	dda22053 	st.w      	r13, (r2, 0x14c)
 168:	2300      	addi      	r3, 1
 16a:	e422014b 	addi      	r1, r2, 332
 16e:	3b48      	cmpnei      	r3, 8
 170:	d842014f 	ld.b      	r2, (r2, 0x14f)
 174:	c4475c07 	ins      	r2, r7, 7, 7
 178:	a143      	st.b      	r2, (r1, 0x3)
 17a:	e58c000f 	addi      	r12, r12, 16
 17e:	0bc7      	bt      	0x10c	// 10c <lmac_ah_add_sta+0x10c>
 180:	6c13      	mov      	r0, r4
 182:	e0000000 	bsr      	0x0	// 0 <sta_rc_init>
 186:	6c5b      	mov      	r1, r6
 188:	3206      	movi      	r2, 6
 18a:	e404006e 	addi      	r0, r4, 111
 18e:	e0000000 	bsr      	0x0	// 0 <memcpy>
 192:	d8250308 	ld.b      	r1, (r5, 0x308)
 196:	3903      	cmphsi      	r1, 4
 198:	084b      	bt      	0x22e	// 22e <lmac_ah_add_sta+0x22e>
 19a:	d86400af 	ld.b      	r3, (r4, 0xaf)
 19e:	d0280022 	ldr.b      	r2, (r8, r1 << 0)
 1a2:	c4625c60 	ins      	r3, r2, 3, 0
 1a6:	dc6400af 	st.b      	r3, (r4, 0xaf)
 1aa:	e9290048 	bnez      	r9, 0x23a	// 23a <lmac_ah_add_sta+0x23a>
 1ae:	3301      	movi      	r3, 1
 1b0:	3206      	movi      	r2, 6
 1b2:	6c5b      	mov      	r1, r6
 1b4:	111c      	lrw      	r0, 0x0	// 2a4 <lmac_ah_add_sta+0x2a4>
 1b6:	dc65202f 	st.w      	r3, (r5, 0xbc)
 1ba:	e0000000 	bsr      	0x0	// 0 <memcpy>
 1be:	111a      	lrw      	r0, 0x0	// 2a4 <partial_bssid_calc+0x2a4>
 1c0:	e0000000 	bsr      	0x0	// 0 <partial_bssid_calc>
 1c4:	d8641035 	ld.h      	r3, (r4, 0x6a)
 1c8:	c4605d00 	ins      	r3, r0, 8, 0
 1cc:	dc641035 	st.h      	r3, (r4, 0x6a)
 1d0:	1115      	lrw      	r0, 0x0	// 2a4 <partial_bssid_calc+0x2a4>
 1d2:	e0000000 	bsr      	0x0	// 0 <partial_bssid_calc>
 1d6:	d8651334 	ld.h      	r3, (r5, 0x668)
 1da:	c4605d03 	ins      	r3, r0, 11, 3
 1de:	dc651334 	st.h      	r3, (r5, 0x668)
 1e2:	d865037e 	ld.b      	r3, (r5, 0x37e)
 1e6:	e4632008 	andi      	r3, r3, 8
 1ea:	e9030008 	bez      	r3, 0x1fa	// 1fa <lmac_ah_add_sta+0x1fa>
 1ee:	d805431e 	ld.bs      	r0, (r5, 0x31e)
 1f2:	e0000000 	bsr      	0x0	// 0 <lmac_adjust_cca_threshold>
 1f6:	e0000000 	bsr      	0x0	// 0 <ah_wphy_obss_sd_det_enable>
 1fa:	e0000000 	bsr      	0x0	// 0 <lmac_tx_vec_init>
 1fe:	d865227e 	ld.w      	r3, (r5, 0x9f8)
 202:	3100      	movi      	r1, 0
 204:	1109      	lrw      	r0, 0x0	// 2a8 <lmac_ah_add_sta+0x2a8>
 206:	ea0c0001 	movi      	r12, 1
 20a:	640e      	cmpne      	r3, r0
 20c:	0838      	bt      	0x27c	// 27c <lmac_ah_add_sta+0x27c>
 20e:	1108      	lrw      	r0, 0x0	// 2ac <lmac_ah_add_sta+0x2ac>
 210:	dc25229c 	st.w      	r1, (r5, 0xa70)
 214:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 218:	3000      	movi      	r0, 0
 21a:	0725      	br      	0x64	// 64 <lmac_ah_add_sta+0x64>
 21c:	d860006b 	ld.b      	r3, (r0, 0x6b)
 220:	e4632020 	andi      	r3, r3, 32
 224:	e923ff4b 	bnez      	r3, 0xba	// ba <lmac_ah_add_sta+0xba>
 228:	e0000000 	bsr      	0x0	// 0 <lmac_sta_put>
 22c:	0747      	br      	0xba	// ba <lmac_ah_add_sta+0xba>
 22e:	c4274021 	lsl      	r1, r7, r1
 232:	1100      	lrw      	r0, 0x0	// 2b0 <hgprintf+0x2b0>
 234:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 238:	07b9      	br      	0x1aa	// 1aa <lmac_ah_add_sta+0x1aa>
 23a:	103f      	lrw      	r1, 0x0	// 2b4 <lmac_ah_add_sta+0x2b4>
 23c:	3706      	movi      	r7, 6
 23e:	6c9f      	mov      	r2, r7
 240:	e4010223 	addi      	r0, r1, 548
 244:	e0000000 	bsr      	0x0	// 0 <memcpy>
 248:	1037      	lrw      	r1, 0x0	// 2a4 <lmac_ah_add_sta+0x2a4>
 24a:	6c27      	mov      	r0, r9
 24c:	e0000000 	bsr      	0x0	// 0 <partial_aid_calc>
 250:	d8641035 	ld.h      	r3, (r4, 0x6a)
 254:	c4605d00 	ins      	r3, r0, 8, 0
 258:	dc641035 	st.h      	r3, (r4, 0x6a)
 25c:	3302      	movi      	r3, 2
 25e:	a57c      	st.b      	r3, (r5, 0x1c)
 260:	3301      	movi      	r3, 1
 262:	a57e      	st.b      	r3, (r5, 0x1e)
 264:	a57f      	st.b      	r3, (r5, 0x1f)
 266:	d865037c 	ld.b      	r3, (r5, 0x37c)
 26a:	e4632002 	andi      	r3, r3, 2
 26e:	a5fd      	st.b      	r7, (r5, 0x1d)
 270:	e903ffb0 	bez      	r3, 0x1d0	// 1d0 <lmac_ah_add_sta+0x1d0>
 274:	6c1b      	mov      	r0, r6
 276:	e0000000 	bsr      	0x0	// 0 <lmac_send_mgmt_meas_req>
 27a:	07ab      	br      	0x1d0	// 1d0 <lmac_ah_add_sta+0x1d0>
 27c:	d8431034 	ld.h      	r2, (r3, 0x68)
 280:	3a1f      	cmphsi      	r2, 32
 282:	0804      	bt      	0x28a	// 28a <lmac_ah_add_sta+0x28a>
 284:	c44c4022 	lsl      	r2, r12, r2
 288:	6c48      	or      	r1, r2
 28a:	9360      	ld.w      	r3, (r3, 0x0)
 28c:	07bf      	br      	0x20a	// 20a <lmac_ah_add_sta+0x20a>
	...

Disassembly of section .text.lmac_bss_load_get:

00000000 <lmac_bss_load_get>:
   0:	14d1      	push      	r4, r15
   2:	1094      	lrw      	r4, 0x0	// 50 <lmac_bss_load_get+0x50>
   4:	e4240a67 	addi      	r1, r4, 2664
   8:	d8641504 	ld.h      	r3, (r4, 0xa08)
   c:	dc640a68 	st.b      	r3, (r4, 0xa68)
  10:	4b68      	lsri      	r3, r3, 8
  12:	dc640a69 	st.b      	r3, (r4, 0xa69)
  16:	3312      	movi      	r3, 18
  18:	dc640a6b 	st.b      	r3, (r4, 0xa6b)
  1c:	3205      	movi      	r2, 5
  1e:	337a      	movi      	r3, 122
  20:	dc640a6c 	st.b      	r3, (r4, 0xa6c)
  24:	e0000000 	bsr      	0x0	// 0 <memcpy>
  28:	d8640a6c 	ld.b      	r3, (r4, 0xa6c)
  2c:	d8240a69 	ld.b      	r1, (r4, 0xa69)
  30:	d8440a6b 	ld.b      	r2, (r4, 0xa6b)
  34:	d8040a68 	ld.b      	r0, (r4, 0xa68)
  38:	4368      	lsli      	r3, r3, 8
  3a:	4128      	lsli      	r1, r1, 8
  3c:	6cc8      	or      	r3, r2
  3e:	6c40      	or      	r1, r0
  40:	d8440a6a 	ld.b      	r2, (r4, 0xa6a)
  44:	1004      	lrw      	r0, 0x0	// 54 <hgprintf+0x54>
  46:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  4a:	3000      	movi      	r0, 0
  4c:	1491      	pop      	r4, r15
	...

Disassembly of section .text.lmac_ah_del_sta:

00000000 <lmac_ah_del_sta>:
   0:	14d1      	push      	r4, r15
   2:	1423      	subi      	r14, r14, 12
   4:	6d0b      	mov      	r4, r2
   6:	8262      	ld.b      	r3, (r2, 0x2)
   8:	8405      	ld.b      	r0, (r4, 0x5)
   a:	8241      	ld.b      	r2, (r2, 0x1)
   c:	b802      	st.w      	r0, (r14, 0x8)
   e:	8404      	ld.b      	r0, (r4, 0x4)
  10:	b801      	st.w      	r0, (r14, 0x4)
  12:	8403      	ld.b      	r0, (r4, 0x3)
  14:	8420      	ld.b      	r1, (r4, 0x0)
  16:	b800      	st.w      	r0, (r14, 0x0)
  18:	1009      	lrw      	r0, 0x0	// 3c <lmac_ah_del_sta+0x3c>
  1a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  1e:	6c53      	mov      	r1, r4
  20:	ea00ffff 	movi      	r0, 65535
  24:	e0000000 	bsr      	0x0	// 0 <lmac_sta_del>
  28:	1066      	lrw      	r3, 0x0	// 40 <lmac_ah_del_sta+0x40>
  2a:	d8431504 	ld.h      	r2, (r3, 0xa08)
  2e:	e9220004 	bnez      	r2, 0x36	// 36 <lmac_ah_del_sta+0x36>
  32:	dc430a4e 	st.b      	r2, (r3, 0xa4e)
  36:	3000      	movi      	r0, 0
  38:	1403      	addi      	r14, r14, 12
  3a:	1491      	pop      	r4, r15
	...

Disassembly of section .text.lmac_set_primary_chan:

00000000 <lmac_set_primary_chan>:
   0:	3000      	movi      	r0, 0
   2:	783c      	jmp      	r15

Disassembly of section .text.lmac_set_radio_onoff:

00000000 <lmac_set_radio_onoff>:
   0:	14d2      	push      	r4-r5, r15
   2:	3941      	cmpnei      	r1, 1
   4:	6d03      	mov      	r4, r0
   6:	6d47      	mov      	r5, r1
   8:	0809      	bt      	0x1a	// 1a <lmac_set_radio_onoff+0x1a>
   a:	e0000000 	bsr      	0x0	// 0 <lmac_doze_exit>
   e:	846a      	ld.b      	r3, (r4, 0xa)
  10:	c4655c00 	ins      	r3, r5, 0, 0
  14:	3000      	movi      	r0, 0
  16:	a46a      	st.b      	r3, (r4, 0xa)
  18:	1492      	pop      	r4-r5, r15
  1a:	3942      	cmpnei      	r1, 2
  1c:	3500      	movi      	r5, 0
  1e:	0ff6      	bf      	0xa	// a <lmac_set_radio_onoff+0xa>
  20:	e0000000 	bsr      	0x0	// 0 <lmac_doze_enter>
  24:	07f5      	br      	0xe	// e <lmac_set_radio_onoff+0xe>

Disassembly of section .text.lmac_set_bgrssi:

00000000 <lmac_set_bgrssi>:
   0:	14d2      	push      	r4-r5, r15
   2:	1094      	lrw      	r4, 0x0	// 50 <lmac_set_bgrssi+0x50>
   4:	e981000f 	blz      	r1, 0x22	// 22 <lmac_set_bgrssi+0x22>
   8:	d8640361 	ld.b      	r3, (r4, 0x361)
   c:	3201      	movi      	r2, 1
   e:	c4625c02 	ins      	r3, r2, 2, 2
  12:	d804431e 	ld.bs      	r0, (r4, 0x31e)
  16:	dc640361 	st.b      	r3, (r4, 0x361)
  1a:	e0000000 	bsr      	0x0	// 0 <lmac_adjust_cca_threshold>
  1e:	3000      	movi      	r0, 0
  20:	1492      	pop      	r4-r5, r15
  22:	6c07      	mov      	r0, r1
  24:	dc24031e 	st.b      	r1, (r4, 0x31e)
  28:	3500      	movi      	r5, 0
  2a:	e0000000 	bsr      	0x0	// 0 <lmac_adjust_cca_threshold>
  2e:	d8640361 	ld.b      	r3, (r4, 0x361)
  32:	c4655c02 	ins      	r3, r5, 2, 2
  36:	d804431e 	ld.bs      	r0, (r4, 0x31e)
  3a:	dc640361 	st.b      	r3, (r4, 0x361)
  3e:	e0000000 	bsr      	0x0	// 0 <lmac_adjust_agc_threshold>
  42:	d8640361 	ld.b      	r3, (r4, 0x361)
  46:	c4655c03 	ins      	r3, r5, 3, 3
  4a:	dc640361 	st.b      	r3, (r4, 0x361)
  4e:	07e8      	br      	0x1e	// 1e <ah_lmac+0x1e>
  50:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_lo_table_kick:

00000000 <lmac_lo_table_kick>:
   0:	14d3      	push      	r4-r6, r15
   2:	10b7      	lrw      	r5, 0x0	// 5c <lmac_lo_table_kick+0x5c>
   4:	6d03      	mov      	r4, r0
   6:	d8650378 	ld.b      	r3, (r5, 0x378)
   a:	64c0      	cmphs      	r0, r3
   c:	081a      	bt      	0x40	// 40 <lmac_lo_table_kick+0x40>
   e:	7580      	zextb      	r6, r0
  10:	6c1b      	mov      	r0, r6
  12:	e0000000 	bsr      	0x0	// 0 <sysctrl_internal_rf_sel_lo_freq>
  16:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_table_kick>
  1a:	3118      	movi      	r1, 24
  1c:	7d04      	mult      	r4, r1
  1e:	6114      	addu      	r4, r5
  20:	dcc50340 	st.b      	r6, (r5, 0x340)
  24:	d86400c0 	ld.b      	r3, (r4, 0xc0)
  28:	dc65033d 	st.b      	r3, (r5, 0x33d)
  2c:	d8642030 	ld.w      	r3, (r4, 0xc0)
  30:	c50356e3 	zext      	r3, r3, 23, 8
  34:	dc65119f 	st.h      	r3, (r5, 0x33e)
  38:	3000      	movi      	r0, 0
  3a:	e4a50331 	addi      	r5, r5, 818
  3e:	1493      	pop      	r4-r6, r15
  40:	d86509e2 	ld.b      	r3, (r5, 0x9e2)
  44:	e4632002 	andi      	r3, r3, 2
  48:	e9230006 	bnez      	r3, 0x54	// 54 <lmac_lo_table_kick+0x54>
  4c:	6c43      	mov      	r1, r0
  4e:	1005      	lrw      	r0, 0x0	// 60 <lmac_lo_table_kick+0x60>
  50:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  54:	3000      	movi      	r0, 0
  56:	2800      	subi      	r0, 1
  58:	07f3      	br      	0x3e	// 3e <lmac_lo_table_kick+0x3e>
	...

Disassembly of section .text.lmac_lo_table_read:

00000000 <lmac_lo_table_read>:
   0:	14d6      	push      	r4-r9, r15
   2:	3400      	movi      	r4, 0
   4:	10d5      	lrw      	r6, 0x0	// 58 <lmac_lo_table_read+0x58>
   6:	10f6      	lrw      	r7, 0x0	// 5c <lmac_lo_table_read+0x5c>
   8:	ea880016 	lrw      	r8, 0x0	// 60 <lmac_lo_table_read+0x60>
   c:	d8660378 	ld.b      	r3, (r6, 0x378)
  10:	64d0      	cmphs      	r4, r3
  12:	0c02      	bf      	0x16	// 16 <lmac_lo_table_read+0x16>
  14:	1496      	pop      	r4-r9, r15
  16:	d866033c 	ld.b      	r3, (r6, 0x33c)
  1a:	650e      	cmpne      	r3, r4
  1c:	6c53      	mov      	r1, r4
  1e:	081a      	bt      	0x52	// 52 <lmac_lo_table_read+0x52>
  20:	1011      	lrw      	r0, 0x0	// 64 <lmac_lo_table_read+0x64>
  22:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  26:	4464      	lsli      	r3, r4, 4
  28:	e4a304ff 	addi      	r5, r3, 1280
  2c:	e5230503 	addi      	r9, r3, 1284
  30:	6c17      	mov      	r0, r5
  32:	e0000000 	bsr      	0x0	// 0 <ah_rfspi_read>
  36:	2500      	addi      	r5, 1
  38:	6c43      	mov      	r1, r0
  3a:	7555      	zexth      	r5, r5
  3c:	6c23      	mov      	r0, r8
  3e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  42:	6656      	cmpne      	r5, r9
  44:	0bf6      	bt      	0x30	// 30 <lmac_lo_table_read+0x30>
  46:	1009      	lrw      	r0, 0x0	// 68 <lmac_lo_table_read+0x68>
  48:	2400      	addi      	r4, 1
  4a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  4e:	7510      	zextb      	r4, r4
  50:	07de      	br      	0xc	// c <lmac_lo_table_read+0xc>
  52:	6c1f      	mov      	r0, r7
  54:	07e7      	br      	0x22	// 22 <lmac_lo_table_read+0x22>
	...

Disassembly of section .text.lmac_cfg_set_chanlist:

00000000 <lmac_cfg_set_chanlist>:
   0:	14d3      	push      	r4-r6, r15
   2:	1520      	subi      	r14, r14, 128
   4:	3a10      	cmphsi      	r2, 17
   6:	6d0b      	mov      	r4, r2
   8:	080b      	bt      	0x1e	// 1e <lmac_cfg_set_chanlist+0x1e>
   a:	e922000b 	bnez      	r2, 0x20	// 20 <lmac_cfg_set_chanlist+0x20>
   e:	1202      	lrw      	r0, 0x0	// 114 <lmac_cfg_set_chanlist+0x114>
  10:	3600      	movi      	r6, 0
  12:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  16:	2e00      	subi      	r6, 1
  18:	6c1b      	mov      	r0, r6
  1a:	1500      	addi      	r14, r14, 128
  1c:	1493      	pop      	r4-r6, r15
  1e:	3410      	movi      	r4, 16
  20:	11be      	lrw      	r5, 0x0	// 118 <lmac_cfg_set_chanlist+0x118>
  22:	3200      	movi      	r2, 0
  24:	d805034a 	ld.b      	r0, (r5, 0x34a)
  28:	d98511a5 	ld.h      	r12, (r5, 0x34a)
  2c:	e4002001 	andi      	r0, r0, 1
  30:	c42c55ec 	zext      	r12, r12, 15, 1
  34:	1e10      	addi      	r6, r14, 64
  36:	ea0d0064 	movi      	r13, 100
  3a:	6509      	cmplt      	r2, r4
  3c:	0859      	bt      	0xee	// ee <lmac_cfg_set_chanlist+0xee>
  3e:	3100      	movi      	r1, 0
  40:	2900      	subi      	r1, 1
  42:	1117      	lrw      	r0, 0x0	// 11c <lmac_cfg_set_chanlist+0x11c>
  44:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
  48:	e0000000 	bsr      	0x0	// 0 <lmac_doze_enter>
  4c:	3300      	movi      	r3, 0
  4e:	3000      	movi      	r0, 0
  50:	dc650378 	st.b      	r3, (r5, 0x378)
  54:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_table_ctrl>
  58:	6c1b      	mov      	r0, r6
  5a:	6c53      	mov      	r1, r4
  5c:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_table_cfg>
  60:	6d83      	mov      	r6, r0
  62:	3001      	movi      	r0, 1
  64:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_table_ctrl>
  68:	e9260052 	bnez      	r6, 0x10c	// 10c <lmac_cfg_set_chanlist+0x10c>
  6c:	116d      	lrw      	r3, 0x0	// 120 <lmac_cfg_set_chanlist+0x120>
  6e:	ea0c0000 	movi      	r12, 0
  72:	3000      	movi      	r0, 0
  74:	e423017f 	addi      	r1, r3, 384
  78:	6c9b      	mov      	r2, r6
  7a:	e58c103b 	subi      	r12, r12, 60
  7e:	287f      	subi      	r0, 128
  80:	d04e088d 	ldr.w      	r13, (r14, r2 << 2)
  84:	2200      	addi      	r2, 1
  86:	6509      	cmplt      	r2, r4
  88:	dda32000 	st.w      	r13, (r3, 0x0)
  8c:	dd830007 	st.b      	r12, (r3, 0x7)
  90:	a306      	st.b      	r0, (r3, 0x6)
  92:	dda12000 	st.w      	r13, (r1, 0x0)
  96:	a107      	st.b      	r0, (r1, 0x7)
  98:	2317      	addi      	r3, 24
  9a:	210b      	addi      	r1, 12
  9c:	0bf2      	bt      	0x80	// 80 <lmac_cfg_set_chanlist+0x80>
  9e:	5c63      	subi      	r3, r4, 1
  a0:	d06e0883 	ldr.w      	r3, (r14, r3 << 2)
  a4:	1140      	lrw      	r2, 0x0	// 124 <lmac_cfg_set_chanlist+0x124>
  a6:	c40356e3 	zext      	r3, r3, 23, 0
  aa:	e4232fff 	andi      	r1, r3, 4095
  ae:	4104      	lsli      	r0, r1, 4
  b0:	8a23      	ld.h      	r1, (r2, 0x6)
  b2:	e421200f 	andi      	r1, r1, 15
  b6:	6c40      	or      	r1, r0
  b8:	aa23      	st.h      	r1, (r2, 0x6)
  ba:	ea0c0fff 	movi      	r12, 4095
  be:	6f32      	nor      	r12, r12
  c0:	8a24      	ld.h      	r1, (r2, 0x8)
  c2:	4b0c      	lsri      	r0, r3, 12
  c4:	6870      	and      	r1, r12
  c6:	6c40      	or      	r1, r0
  c8:	7510      	zextb      	r4, r4
  ca:	aa24      	st.h      	r1, (r2, 0x8)
  cc:	5c23      	subi      	r1, r4, 1
  ce:	7444      	zextb      	r1, r1
  d0:	dc25033c 	st.b      	r1, (r5, 0x33c)
  d4:	a26b      	st.b      	r3, (r2, 0xb)
  d6:	4b68      	lsri      	r3, r3, 8
  d8:	aa66      	st.h      	r3, (r2, 0xc)
  da:	dc250340 	st.b      	r1, (r5, 0x340)
  de:	dc850378 	st.b      	r4, (r5, 0x378)
  e2:	e0000000 	bsr      	0x0	// 0 <lmac_doze_exit>
  e6:	100e      	lrw      	r0, 0x0	// 11c <os_mutex_unlock+0x11c>
  e8:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  ec:	0796      	br      	0x18	// 18 <lmac_cfg_set_chanlist+0x18>
  ee:	d0410443 	ldr.h      	r3, (r1, r2 << 1)
  f2:	74cd      	zexth      	r3, r3
  f4:	7cf4      	mult      	r3, r13
  f6:	d44e0883 	str.w      	r3, (r14, r2 << 2)
  fa:	d4460883 	str.w      	r3, (r6, r2 << 2)
  fe:	e9000005 	bez      	r0, 0x108	// 108 <lmac_cfg_set_chanlist+0x108>
 102:	60f0      	addu      	r3, r12
 104:	d4460883 	str.w      	r3, (r6, r2 << 2)
 108:	2200      	addi      	r2, 1
 10a:	0798      	br      	0x3a	// 3a <lmac_cfg_set_chanlist+0x3a>
 10c:	1007      	lrw      	r0, 0x0	// 128 <lmac_cfg_set_chanlist+0x128>
 10e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 112:	07e8      	br      	0xe2	// e2 <lmac_cfg_set_chanlist+0xe2>
	...

Disassembly of section .text.lmac_cfg_set_freq_range:

00000000 <lmac_cfg_set_freq_range>:
   0:	14d1      	push      	r4, r15
   2:	1428      	subi      	r14, r14, 32
   4:	ea8d001d 	lrw      	r13, 0x0	// 78 <lmac_cfg_set_freq_range+0x78>
   8:	d98d09e2 	ld.b      	r12, (r13, 0x9e2)
   c:	e58c2002 	andi      	r12, r12, 2
  10:	e92c0030 	bnez      	r12, 0x70	// 70 <lmac_cfg_set_freq_range+0x70>
  14:	e903002e 	bez      	r3, 0x70	// 70 <lmac_cfg_set_freq_range+0x70>
  18:	750f      	sexth      	r4, r3
  1a:	c444482c 	lsli      	r12, r4, 2
  1e:	6310      	addu      	r12, r4
  20:	6086      	subu      	r2, r1
  22:	6330      	addu      	r12, r12
  24:	c582804c 	divs      	r12, r2, r12
  28:	e58c0000 	addi      	r12, r12, 1
  2c:	7731      	zexth      	r12, r12
  2e:	eb0c0010 	cmphsi      	r12, 17
  32:	6cb3      	mov      	r2, r12
  34:	0c02      	bf      	0x38	// 38 <lmac_cfg_set_freq_range+0x38>
  36:	3210      	movi      	r2, 16
  38:	3b41      	cmpnei      	r3, 1
  3a:	d98d034a 	ld.b      	r12, (r13, 0x34a)
  3e:	6503      	mvcv      	r4
  40:	c5845c00 	ins      	r12, r4, 0, 0
  44:	dd8d034a 	st.b      	r12, (r13, 0x34a)
  48:	ea0c000a 	movi      	r12, 10
  4c:	7cf0      	mult      	r3, r12
  4e:	7489      	zexth      	r2, r2
  50:	ea0c0000 	movi      	r12, 0
  54:	64b1      	cmplt      	r12, r2
  56:	0806      	bt      	0x62	// 62 <lmac_cfg_set_freq_range+0x62>
  58:	6c7b      	mov      	r1, r14
  5a:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_set_freq_range>
  5e:	1408      	addi      	r14, r14, 32
  60:	1491      	pop      	r4, r15
  62:	d58e0441 	str.h      	r1, (r14, r12 << 1)
  66:	604c      	addu      	r1, r3
  68:	e58c0000 	addi      	r12, r12, 1
  6c:	7445      	zexth      	r1, r1
  6e:	07f3      	br      	0x54	// 54 <lmac_cfg_set_freq_range+0x54>
  70:	3000      	movi      	r0, 0
  72:	2800      	subi      	r0, 1
  74:	07f5      	br      	0x5e	// 5e <lmac_cfg_set_freq_range+0x5e>
  76:	0000      	.short	0x0000
  78:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_lo_freq_set:

00000000 <lmac_lo_freq_set>:
   0:	14d4      	push      	r4-r7, r15
   2:	1421      	subi      	r14, r14, 4
   4:	1195      	lrw      	r4, 0x0	// d8 <lmac_lo_freq_set+0xd8>
   6:	6dc3      	mov      	r7, r0
   8:	b800      	st.w      	r0, (r14, 0x0)
   a:	e0000000 	bsr      	0x0	// 0 <lhw_abort_fsm>
   e:	d864034a 	ld.b      	r3, (r4, 0x34a)
  12:	e4632001 	andi      	r3, r3, 1
  16:	e9030009 	bez      	r3, 0x28	// 28 <lmac_lo_freq_set+0x28>
  1a:	d86411a5 	ld.h      	r3, (r4, 0x34a)
  1e:	9840      	ld.w      	r2, (r14, 0x0)
  20:	c42355e3 	zext      	r3, r3, 15, 1
  24:	60c8      	addu      	r3, r2
  26:	b860      	st.w      	r3, (r14, 0x0)
  28:	3000      	movi      	r0, 0
  2a:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_table_ctrl>
  2e:	9800      	ld.w      	r0, (r14, 0x0)
  30:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_freq_set>
  34:	6d43      	mov      	r5, r0
  36:	11ca      	lrw      	r6, 0x0	// dc <lmac_lo_freq_set+0xdc>
  38:	e920004b 	bnez      	r0, 0xce	// ce <lmac_lo_freq_set+0xce>
  3c:	e4672fff 	andi      	r3, r7, 4095
  40:	4344      	lsli      	r2, r3, 4
  42:	8e63      	ld.h      	r3, (r6, 0x6)
  44:	e463200f 	andi      	r3, r3, 15
  48:	6cc8      	or      	r3, r2
  4a:	ea010fff 	movi      	r1, 4095
  4e:	6c46      	nor      	r1, r1
  50:	8e44      	ld.h      	r2, (r6, 0x8)
  52:	6884      	and      	r2, r1
  54:	ae63      	st.h      	r3, (r6, 0x6)
  56:	c58756e3 	zext      	r3, r7, 23, 12
  5a:	6cc8      	or      	r3, r2
  5c:	ae64      	st.h      	r3, (r6, 0x8)
  5e:	6c83      	mov      	r2, r0
  60:	6cc3      	mov      	r3, r0
  62:	d8240378 	ld.b      	r1, (r4, 0x378)
  66:	c40756e0 	zext      	r0, r7, 23, 0
  6a:	644d      	cmplt      	r3, r1
  6c:	080c      	bt      	0x84	// 84 <lmac_lo_freq_set+0x84>
  6e:	3101      	movi      	r1, 1
  70:	6c3b      	mov      	r0, r14
  72:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_table_cfg>
  76:	6d43      	mov      	r5, r0
  78:	e9000026 	bez      	r0, 0xc4	// c4 <lmac_lo_freq_set+0xc4>
  7c:	1019      	lrw      	r0, 0x0	// e0 <hgprintf+0xe0>
  7e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  82:	040b      	br      	0x98	// 98 <lmac_lo_freq_set+0x98>
  84:	2217      	addi      	r2, 24
  86:	ea8c0015 	lrw      	r12, 0x0	// d8 <lmac_lo_freq_set+0xd8>
  8a:	6308      	addu      	r12, r2
  8c:	d98c202a 	ld.w      	r12, (r12, 0xa8)
  90:	6432      	cmpne      	r12, r0
  92:	0817      	bt      	0xc0	// c0 <lmac_lo_freq_set+0xc0>
  94:	dc64033c 	st.b      	r3, (r4, 0x33c)
  98:	d86420ce 	ld.w      	r3, (r4, 0x338)
  9c:	c4835763 	zext      	r3, r3, 27, 4
  a0:	a66b      	st.b      	r3, (r6, 0xb)
  a2:	4b68      	lsri      	r3, r3, 8
  a4:	ae66      	st.h      	r3, (r6, 0xc)
  a6:	d864033c 	ld.b      	r3, (r4, 0x33c)
  aa:	3001      	movi      	r0, 1
  ac:	dc640340 	st.b      	r3, (r4, 0x340)
  b0:	e0000000 	bsr      	0x0	// 0 <ah_rf_lo_table_ctrl>
  b4:	3000      	movi      	r0, 0
  b6:	e0000000 	bsr      	0x0	// 0 <lhw_start_rx>
  ba:	6c17      	mov      	r0, r5
  bc:	1401      	addi      	r14, r14, 4
  be:	1494      	pop      	r4-r7, r15
  c0:	2300      	addi      	r3, 1
  c2:	07d4      	br      	0x6a	// 6a <lmac_lo_freq_set+0x6a>
  c4:	dce42030 	st.w      	r7, (r4, 0xc0)
  c8:	dca4033c 	st.b      	r5, (r4, 0x33c)
  cc:	07e6      	br      	0x98	// 98 <lmac_lo_freq_set+0x98>
  ce:	6c5f      	mov      	r1, r7
  d0:	1005      	lrw      	r0, 0x0	// e4 <lmac_lo_freq_set+0xe4>
  d2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  d6:	07e1      	br      	0x98	// 98 <ah_lmac+0x98>
	...

Disassembly of section .text.lmac_cfg_set_bss_bw:

00000000 <lmac_cfg_set_bss_bw>:
   0:	14d5      	push      	r4-r8, r15
   2:	1428      	subi      	r14, r14, 32
   4:	1296      	lrw      	r4, 0x0	// 15c <lmac_cfg_set_bss_bw+0x15c>
   6:	6c87      	mov      	r2, r1
   8:	6e03      	mov      	r8, r0
   a:	6d47      	mov      	r5, r1
   c:	1215      	lrw      	r0, 0x0	// 160 <lmac_cfg_set_bss_bw+0x160>
   e:	1236      	lrw      	r1, 0x0	// 164 <lmac_cfg_set_bss_bw+0x164>
  10:	d8e40867 	ld.b      	r7, (r4, 0x867)
  14:	d8c420ce 	ld.w      	r6, (r4, 0x338)
  18:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  1c:	d844034a 	ld.b      	r2, (r4, 0x34a)
  20:	3300      	movi      	r3, 0
  22:	c4435c00 	ins      	r2, r3, 0, 0
  26:	dc44034a 	st.b      	r2, (r4, 0x34a)
  2a:	d8440338 	ld.b      	r2, (r4, 0x338)
  2e:	e4422008 	andi      	r2, r2, 8
  32:	3103      	movi      	r1, 3
  34:	c4865766 	zext      	r6, r6, 27, 4
  38:	dc240309 	st.b      	r1, (r4, 0x309)
  3c:	dc640865 	st.b      	r3, (r4, 0x865)
  40:	e902002c 	bez      	r2, 0x98	// 98 <lmac_cfg_set_bss_bw+0x98>
  44:	d8440875 	ld.b      	r2, (r4, 0x875)
  48:	3d42      	cmpnei      	r5, 2
  4a:	c4435c01 	ins      	r2, r3, 1, 1
  4e:	dc440875 	st.b      	r2, (r4, 0x875)
  52:	0c0d      	bf      	0x6c	// 6c <lmac_cfg_set_bss_bw+0x6c>
  54:	3d02      	cmphsi      	r5, 3
  56:	0867      	bt      	0x124	// 124 <lmac_cfg_set_bss_bw+0x124>
  58:	3d41      	cmpnei      	r5, 1
  5a:	0c6e      	bf      	0x136	// 136 <lmac_cfg_set_bss_bw+0x136>
  5c:	1203      	lrw      	r0, 0x0	// 168 <lmac_cfg_set_bss_bw+0x168>
  5e:	6c57      	mov      	r1, r5
  60:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  64:	3000      	movi      	r0, 0
  66:	2800      	subi      	r0, 1
  68:	1408      	addi      	r14, r14, 32
  6a:	1495      	pop      	r4-r8, r15
  6c:	3301      	movi      	r3, 1
  6e:	dc640308 	st.b      	r3, (r4, 0x308)
  72:	3300      	movi      	r3, 0
  74:	dc640867 	st.b      	r3, (r4, 0x867)
  78:	0425      	br      	0xc2	// c2 <lmac_cfg_set_bss_bw+0xc2>
  7a:	3302      	movi      	r3, 2
  7c:	dc640308 	st.b      	r3, (r4, 0x308)
  80:	3301      	movi      	r3, 1
  82:	07f9      	br      	0x74	// 74 <lmac_cfg_set_bss_bw+0x74>
  84:	1116      	lrw      	r0, 0x0	// 15c <lmac_cfg_set_bss_bw+0x15c>
  86:	6004      	addu      	r0, r1
  88:	d800202a 	ld.w      	r0, (r0, 0xa8)
  8c:	c5808020 	divu      	r0, r0, r12
  90:	d46e0440 	str.h      	r0, (r14, r3 << 1)
  94:	2300      	addi      	r3, 1
  96:	043b      	br      	0x10c	// 10c <lmac_cfg_set_bss_bw+0x10c>
  98:	3d42      	cmpnei      	r5, 2
  9a:	0fe9      	bf      	0x6c	// 6c <lmac_cfg_set_bss_bw+0x6c>
  9c:	3d02      	cmphsi      	r5, 3
  9e:	0843      	bt      	0x124	// 124 <lmac_cfg_set_bss_bw+0x124>
  a0:	3d41      	cmpnei      	r5, 1
  a2:	0bdd      	bt      	0x5c	// 5c <lmac_cfg_set_bss_bw+0x5c>
  a4:	d864034a 	ld.b      	r3, (r4, 0x34a)
  a8:	c4655c00 	ins      	r3, r5, 0, 0
  ac:	dca40308 	st.b      	r5, (r4, 0x308)
  b0:	dc240867 	st.b      	r1, (r4, 0x867)
  b4:	dc64034a 	st.b      	r3, (r4, 0x34a)
  b8:	dc440309 	st.b      	r2, (r4, 0x309)
  bc:	3301      	movi      	r3, 1
  be:	dc640865 	st.b      	r3, (r4, 0x865)
  c2:	116b      	lrw      	r3, 0x0	// 16c <lmac_cfg_set_bss_bw+0x16c>
  c4:	9340      	ld.w      	r2, (r3, 0x0)
  c6:	9270      	ld.w      	r3, (r2, 0x40)
  c8:	3b84      	bclri      	r3, 4
  ca:	3b85      	bclri      	r3, 5
  cc:	b270      	st.w      	r3, (r2, 0x40)
  ce:	d8640308 	ld.b      	r3, (r4, 0x308)
  d2:	4364      	lsli      	r3, r3, 4
  d4:	9230      	ld.w      	r1, (r2, 0x40)
  d6:	e4632030 	andi      	r3, r3, 48
  da:	6cc4      	or      	r3, r1
  dc:	b270      	st.w      	r3, (r2, 0x40)
  de:	d8040309 	ld.b      	r0, (r4, 0x309)
  e2:	e0000000 	bsr      	0x0	// 0 <ah_wphy_pri_channel_cfg>
  e6:	d8040308 	ld.b      	r0, (r4, 0x308)
  ea:	e0000000 	bsr      	0x0	// 0 <ah_wphy_bw_cfg>
  ee:	3005      	movi      	r0, 5
  f0:	e0000000 	bsr      	0x0	// 0 <lmac_rx_gain_cfg>
  f4:	e0000000 	bsr      	0x0	// 0 <lmac_tx_vec_init>
  f8:	3d41      	cmpnei      	r5, 1
  fa:	0c03      	bf      	0x100	// 100 <lmac_cfg_set_bss_bw+0x100>
  fc:	3f43      	cmpnei      	r7, 3
  fe:	080e      	bt      	0x11a	// 11a <lmac_cfg_set_bss_bw+0x11a>
 100:	3100      	movi      	r1, 0
 102:	d8440378 	ld.b      	r2, (r4, 0x378)
 106:	6cc7      	mov      	r3, r1
 108:	ea0c0064 	movi      	r12, 100
 10c:	648d      	cmplt      	r3, r2
 10e:	2117      	addi      	r1, 24
 110:	0bba      	bt      	0x84	// 84 <lmac_cfg_set_bss_bw+0x84>
 112:	6c7b      	mov      	r1, r14
 114:	6c23      	mov      	r0, r8
 116:	e0000000 	bsr      	0x0	// 0 <lmac_set_chan_list>
 11a:	6c1b      	mov      	r0, r6
 11c:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_set_bss_bw>
 120:	3000      	movi      	r0, 0
 122:	07a3      	br      	0x68	// 68 <lmac_cfg_set_bss_bw+0x68>
 124:	3d44      	cmpnei      	r5, 4
 126:	0faa      	bf      	0x7a	// 7a <lmac_cfg_set_bss_bw+0x7a>
 128:	3d48      	cmpnei      	r5, 8
 12a:	0b99      	bt      	0x5c	// 5c <lmac_cfg_set_bss_bw+0x5c>
 12c:	3303      	movi      	r3, 3
 12e:	dc640308 	st.b      	r3, (r4, 0x308)
 132:	3302      	movi      	r3, 2
 134:	07a0      	br      	0x74	// 74 <lmac_cfg_set_bss_bw+0x74>
 136:	d844034a 	ld.b      	r2, (r4, 0x34a)
 13a:	dc640309 	st.b      	r3, (r4, 0x309)
 13e:	d8640875 	ld.b      	r3, (r4, 0x875)
 142:	c4455c00 	ins      	r2, r5, 0, 0
 146:	c4655c01 	ins      	r3, r5, 1, 1
 14a:	dca40308 	st.b      	r5, (r4, 0x308)
 14e:	dc240867 	st.b      	r1, (r4, 0x867)
 152:	dc44034a 	st.b      	r2, (r4, 0x34a)
 156:	dc640875 	st.b      	r3, (r4, 0x875)
 15a:	07b1      	br      	0xbc	// bc <ah_lmac+0xbc>
	...

Disassembly of section .text.lmac_cfg_set_freq:

00000000 <lmac_cfg_set_freq>:
   0:	14d1      	push      	r4, r15
   2:	6d07      	mov      	r4, r1
   4:	3100      	movi      	r1, 0
   6:	2900      	subi      	r1, 1
   8:	100c      	lrw      	r0, 0x0	// 38 <lmac_cfg_set_freq+0x38>
   a:	e0000000 	bsr      	0x0	// 0 <os_mutex_lock>
   e:	106c      	lrw      	r3, 0x0	// 3c <lmac_cfg_set_freq+0x3c>
  10:	d86309e2 	ld.b      	r3, (r3, 0x9e2)
  14:	e4632002 	andi      	r3, r3, 2
  18:	e923000c 	bnez      	r3, 0x30	// 30 <lmac_cfg_set_freq+0x30>
  1c:	3064      	movi      	r0, 100
  1e:	7c10      	mult      	r0, r4
  20:	e0000000 	bsr      	0x0	// 0 <lmac_cfg_set_freq>
  24:	6d03      	mov      	r4, r0
  26:	1005      	lrw      	r0, 0x0	// 38 <lmac_cfg_set_freq+0x38>
  28:	e0000000 	bsr      	0x0	// 0 <os_mutex_unlock>
  2c:	6c13      	mov      	r0, r4
  2e:	1491      	pop      	r4, r15
  30:	3400      	movi      	r4, 0
  32:	2c00      	subi      	r4, 1
  34:	07f9      	br      	0x26	// 26 <lmac_cfg_set_freq+0x26>
	...

Disassembly of section .text.lmac_ah_open:

00000000 <lmac_ah_open>:
   0:	14d1      	push      	r4, r15
   2:	6d03      	mov      	r4, r0
   4:	e0000000 	bsr      	0x0	// 0 <lmac_doze_exit>
   8:	846a      	ld.b      	r3, (r4, 0xa)
   a:	3201      	movi      	r2, 1
   c:	c4625c00 	ins      	r3, r2, 0, 0
  10:	3000      	movi      	r0, 0
  12:	a46a      	st.b      	r3, (r4, 0xa)
  14:	1491      	pop      	r4, r15

Disassembly of section .text.lmac_ah_close:

00000000 <lmac_ah_close>:
   0:	14d2      	push      	r4-r5, r15
   2:	6d43      	mov      	r5, r0
   4:	3400      	movi      	r4, 0
   6:	e0000000 	bsr      	0x0	// 0 <lmac_doze_enter>
   a:	856a      	ld.b      	r3, (r5, 0xa)
   c:	c4645c00 	ins      	r3, r4, 0, 0
  10:	a56a      	st.b      	r3, (r5, 0xa)
  12:	e0000000 	bsr      	0x0	// 0 <lmac_beacon_timer_abort>
  16:	1065      	lrw      	r3, 0x0	// 28 <lmac_ah_close+0x28>
  18:	6c13      	mov      	r0, r4
  1a:	d84314ef 	ld.h      	r2, (r3, 0x9de)
  1e:	c4445c46 	ins      	r2, r4, 8, 6
  22:	dc4314ef 	st.h      	r2, (r3, 0x9de)
  26:	1492      	pop      	r4-r5, r15
  28:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_ah_set_key:

00000000 <lmac_ah_set_key>:
   0:	14d5      	push      	r4-r8, r15
   2:	1429      	subi      	r14, r14, 36
   4:	6d0f      	mov      	r4, r3
   6:	6d8b      	mov      	r6, r2
   8:	9341      	ld.w      	r2, (r3, 0x4)
   a:	6dc7      	mov      	r7, r1
   c:	e4622008 	andi      	r3, r2, 8
  10:	8429      	ld.b      	r1, (r4, 0x9)
  12:	3b40      	cmpnei      	r3, 0
  14:	8660      	ld.b      	r3, (r6, 0x0)
  16:	b828      	st.w      	r1, (r14, 0x20)
  18:	b846      	st.w      	r2, (r14, 0x18)
  1a:	8428      	ld.b      	r1, (r4, 0x8)
  1c:	9440      	ld.w      	r2, (r4, 0x0)
  1e:	b827      	st.w      	r1, (r14, 0x1c)
  20:	b845      	st.w      	r2, (r14, 0x14)
  22:	8645      	ld.b      	r2, (r6, 0x5)
  24:	b844      	st.w      	r2, (r14, 0x10)
  26:	8644      	ld.b      	r2, (r6, 0x4)
  28:	b843      	st.w      	r2, (r14, 0xc)
  2a:	8643      	ld.b      	r2, (r6, 0x3)
  2c:	b842      	st.w      	r2, (r14, 0x8)
  2e:	8642      	ld.b      	r2, (r6, 0x2)
  30:	b841      	st.w      	r2, (r14, 0x4)
  32:	8641      	ld.b      	r2, (r6, 0x1)
  34:	1204      	lrw      	r0, 0x0	// 144 <lmac_ah_set_key+0x144>
  36:	1225      	lrw      	r1, 0x0	// 148 <lmac_ah_set_key+0x148>
  38:	c4200c40 	inct      	r1, r0, 0
  3c:	b840      	st.w      	r2, (r14, 0x0)
  3e:	e5040009 	addi      	r8, r4, 10
  42:	6c9f      	mov      	r2, r7
  44:	1202      	lrw      	r0, 0x0	// 14c <lmac_ah_set_key+0x14c>
  46:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  4a:	3301      	movi      	r3, 1
  4c:	8449      	ld.b      	r2, (r4, 0x9)
  4e:	6c63      	mov      	r1, r8
  50:	1200      	lrw      	r0, 0x0	// 150 <lmac_ah_set_key+0x150>
  52:	e0000000 	bsr      	0x0	// 0 <dump_hex>
  56:	e927002a 	bnez      	r7, 0xaa	// aa <lmac_ah_set_key+0xaa>
  5a:	8469      	ld.b      	r3, (r4, 0x9)
  5c:	3b50      	cmpnei      	r3, 16
  5e:	0c26      	bf      	0xaa	// aa <lmac_ah_set_key+0xaa>
  60:	eb430020 	cmpnei      	r3, 32
  64:	0c25      	bf      	0xae	// ae <lmac_ah_set_key+0xae>
  66:	111c      	lrw      	r0, 0x0	// 154 <lmac_ah_set_key+0x154>
  68:	3500      	movi      	r5, 0
  6a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  6e:	2d00      	subi      	r5, 1
  70:	9461      	ld.w      	r3, (r4, 0x4)
  72:	e5832008 	andi      	r12, r3, 8
  76:	e90c002e 	bez      	r12, 0xd2	// d2 <lmac_ah_set_key+0xd2>
  7a:	6c5b      	mov      	r1, r6
  7c:	ea00ffff 	movi      	r0, 65535
  80:	e0000000 	bsr      	0x0	// 0 <lmac_sta_get>
  84:	6d83      	mov      	r6, r0
  86:	e9000020 	bez      	r0, 0xc6	// c6 <lmac_ah_set_key+0xc6>
  8a:	2076      	addi      	r0, 119
  8c:	e9070013 	bez      	r7, 0xb2	// b2 <lmac_ah_set_key+0xb2>
  90:	3300      	movi      	r3, 0
  92:	dc660076 	st.b      	r3, (r6, 0x76)
  96:	3220      	movi      	r2, 32
  98:	3100      	movi      	r1, 0
  9a:	e0000000 	bsr      	0x0	// 0 <memset>
  9e:	6c1b      	mov      	r0, r6
  a0:	e0000000 	bsr      	0x0	// 0 <lmac_sta_put>
  a4:	6c17      	mov      	r0, r5
  a6:	1409      	addi      	r14, r14, 36
  a8:	1495      	pop      	r4-r8, r15
  aa:	3500      	movi      	r5, 0
  ac:	07e2      	br      	0x70	// 70 <lmac_ah_set_key+0x70>
  ae:	6d5f      	mov      	r5, r7
  b0:	07e0      	br      	0x70	// 70 <lmac_ah_set_key+0x70>
  b2:	8468      	ld.b      	r3, (r4, 0x8)
  b4:	dc660075 	st.b      	r3, (r6, 0x75)
  b8:	8449      	ld.b      	r2, (r4, 0x9)
  ba:	dc460076 	st.b      	r2, (r6, 0x76)
  be:	6c63      	mov      	r1, r8
  c0:	e0000000 	bsr      	0x0	// 0 <memcpy>
  c4:	07ed      	br      	0x9e	// 9e <lmac_ah_set_key+0x9e>
  c6:	1105      	lrw      	r0, 0x0	// 158 <lmac_ah_set_key+0x158>
  c8:	3500      	movi      	r5, 0
  ca:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ce:	2d00      	subi      	r5, 1
  d0:	07ea      	br      	0xa4	// a4 <lmac_ah_set_key+0xa4>
  d2:	e4232080 	andi      	r1, r3, 128
  d6:	e9070019 	bez      	r7, 0x108	// 108 <lmac_ah_set_key+0x108>
  da:	e901000c 	bez      	r1, 0xf2	// f2 <lmac_ah_set_key+0xf2>
  de:	1100      	lrw      	r0, 0x0	// 15c <lmac_ah_set_key+0x15c>
  e0:	3220      	movi      	r2, 32
  e2:	dd800693 	st.b      	r12, (r0, 0x693)
  e6:	6c73      	mov      	r1, r12
  e8:	e4000693 	addi      	r0, r0, 1684
  ec:	e0000000 	bsr      	0x0	// 0 <memset>
  f0:	07da      	br      	0xa4	// a4 <lmac_ah_set_key+0xa4>
  f2:	e4632100 	andi      	r3, r3, 256
  f6:	e903ffd7 	bez      	r3, 0xa4	// a4 <lmac_ah_set_key+0xa4>
  fa:	1019      	lrw      	r0, 0x0	// 15c <lmac_ah_set_key+0x15c>
  fc:	3220      	movi      	r2, 32
  fe:	dc2006b5 	st.b      	r1, (r0, 0x6b5)
 102:	e40006b5 	addi      	r0, r0, 1718
 106:	07f3      	br      	0xec	// ec <lmac_ah_set_key+0xec>
 108:	e901000f 	bez      	r1, 0x126	// 126 <lmac_ah_set_key+0x126>
 10c:	1014      	lrw      	r0, 0x0	// 15c <lmac_ah_set_key+0x15c>
 10e:	8468      	ld.b      	r3, (r4, 0x8)
 110:	dc600692 	st.b      	r3, (r0, 0x692)
 114:	8449      	ld.b      	r2, (r4, 0x9)
 116:	dc400693 	st.b      	r2, (r0, 0x693)
 11a:	6c63      	mov      	r1, r8
 11c:	e4000693 	addi      	r0, r0, 1684
 120:	e0000000 	bsr      	0x0	// 0 <memcpy>
 124:	07c0      	br      	0xa4	// a4 <lmac_ah_set_key+0xa4>
 126:	e4632100 	andi      	r3, r3, 256
 12a:	e903ffbd 	bez      	r3, 0xa4	// a4 <lmac_ah_set_key+0xa4>
 12e:	100c      	lrw      	r0, 0x0	// 15c <lmac_ah_set_key+0x15c>
 130:	8468      	ld.b      	r3, (r4, 0x8)
 132:	dc6006b4 	st.b      	r3, (r0, 0x6b4)
 136:	8449      	ld.b      	r2, (r4, 0x9)
 138:	dc4006b5 	st.b      	r2, (r0, 0x6b5)
 13c:	6c63      	mov      	r1, r8
 13e:	e40006b5 	addi      	r0, r0, 1718
 142:	07ef      	br      	0x120	// 120 <lmac_ah_set_key+0x120>
	...

Disassembly of section .text.lmac_ah_set_mcast_key:

00000000 <lmac_ah_set_mcast_key>:
   0:	3000      	movi      	r0, 0
   2:	2800      	subi      	r0, 1
   4:	783c      	jmp      	r15

Disassembly of section .text.lmac_ah_set_txq_param:

00000000 <lmac_ah_set_txq_param>:
   0:	14d2      	push      	r4-r5, r15
   2:	1422      	subi      	r14, r14, 8
   4:	3903      	cmphsi      	r1, 4
   6:	6d47      	mov      	r5, r1
   8:	6d0b      	mov      	r4, r2
   a:	082d      	bt      	0x64	// 64 <lmac_ah_set_txq_param+0x64>
   c:	1018      	lrw      	r0, 0x0	// 6c <lmac_ah_set_txq_param+0x6c>
   e:	5864      	addu      	r3, r0, r1
  10:	8246      	ld.b      	r2, (r2, 0x6)
  12:	a35c      	st.b      	r2, (r3, 0x1c)
  14:	8c61      	ld.h      	r3, (r4, 0x2)
  16:	e4410017 	addi      	r2, r1, 24
  1a:	d4400443 	str.h      	r3, (r0, r2 << 1)
  1e:	e4410013 	addi      	r2, r1, 20
  22:	d4400443 	str.h      	r3, (r0, r2 << 1)
  26:	8c42      	ld.h      	r2, (r4, 0x4)
  28:	e461001b 	addi      	r3, r1, 28
  2c:	d4600442 	str.h      	r2, (r0, r3 << 1)
  30:	32fa      	movi      	r2, 250
  32:	8c60      	ld.h      	r3, (r4, 0x0)
  34:	4242      	lsli      	r2, r2, 2
  36:	7cc8      	mult      	r3, r2
  38:	210f      	addi      	r1, 16
  3a:	d4200883 	str.w      	r3, (r0, r1 << 2)
  3e:	3234      	movi      	r2, 52
  40:	e420001b 	addi      	r1, r0, 28
  44:	204f      	addi      	r0, 80
  46:	e0000000 	bsr      	0x0	// 0 <memcpy>
  4a:	8c20      	ld.h      	r1, (r4, 0x0)
  4c:	b821      	st.w      	r1, (r14, 0x4)
  4e:	8c22      	ld.h      	r1, (r4, 0x4)
  50:	b820      	st.w      	r1, (r14, 0x0)
  52:	8c61      	ld.h      	r3, (r4, 0x2)
  54:	1007      	lrw      	r0, 0x0	// 70 <lmac_ah_set_txq_param+0x70>
  56:	8446      	ld.b      	r2, (r4, 0x6)
  58:	6c57      	mov      	r1, r5
  5a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  5e:	3000      	movi      	r0, 0
  60:	1402      	addi      	r14, r14, 8
  62:	1492      	pop      	r4-r5, r15
  64:	3000      	movi      	r0, 0
  66:	2800      	subi      	r0, 1
  68:	07fc      	br      	0x60	// 60 <lmac_ah_set_txq_param+0x60>
	...

Disassembly of section .text.lmac_ah_get_acs_result:

00000000 <lmac_ah_get_acs_result>:
   0:	106f      	lrw      	r3, 0x0	// 3c <lmac_ah_get_acs_result+0x3c>
   2:	3200      	movi      	r2, 0
   4:	6449      	cmplt      	r2, r1
   6:	0803      	bt      	0xc	// c <lmac_ah_get_acs_result+0xc>
   8:	4103      	lsli      	r0, r1, 3
   a:	783c      	jmp      	r15
   c:	d9832000 	ld.w      	r12, (r3, 0x0)
  10:	dd802000 	st.w      	r12, (r0, 0x0)
  14:	d9830006 	ld.b      	r12, (r3, 0x6)
  18:	dd800006 	st.b      	r12, (r0, 0x6)
  1c:	d9830005 	ld.b      	r12, (r3, 0x5)
  20:	dd800005 	st.b      	r12, (r0, 0x5)
  24:	d9830007 	ld.b      	r12, (r3, 0x7)
  28:	dd800007 	st.b      	r12, (r0, 0x7)
  2c:	d9830010 	ld.b      	r12, (r3, 0x10)
  30:	dd800004 	st.b      	r12, (r0, 0x4)
  34:	2200      	addi      	r2, 1
  36:	2317      	addi      	r3, 24
  38:	2007      	addi      	r0, 8
  3a:	07e5      	br      	0x4	// 4 <lmac_ah_get_acs_result+0x4>
  3c:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_ah_start_acs:

00000000 <lmac_ah_start_acs>:
   0:	14d1      	push      	r4, r15
   2:	1182      	lrw      	r4, 0x0	// 88 <lmac_ah_start_acs+0x88>
   4:	e901003c 	bez      	r1, 0x7c	// 7c <lmac_ah_start_acs+0x7c>
   8:	8160      	ld.b      	r3, (r1, 0x0)
   a:	e4632001 	andi      	r3, r3, 1
   e:	e9030037 	bez      	r3, 0x7c	// 7c <lmac_ah_start_acs+0x7c>
  12:	8960      	ld.h      	r3, (r1, 0x0)
  14:	e42321fe 	andi      	r1, r3, 510
  18:	e9010006 	bez      	r1, 0x24	// 24 <lmac_ah_start_acs+0x24>
  1c:	c4235503 	zext      	r3, r3, 8, 1
  20:	dc6420d7 	st.w      	r3, (r4, 0x35c)
  24:	d86409e0 	ld.b      	r3, (r4, 0x9e0)
  28:	3101      	movi      	r1, 1
  2a:	c4615c00 	ins      	r3, r1, 0, 0
  2e:	dc6409e0 	st.b      	r3, (r4, 0x9e0)
  32:	e922001b 	bnez      	r2, 0x68	// 68 <lmac_ah_start_acs+0x68>
  36:	d84422a1 	ld.w      	r2, (r4, 0xa84)
  3a:	5a64      	addu      	r3, r2, r1
  3c:	d80422a2 	ld.w      	r0, (r4, 0xa88)
  40:	640d      	cmplt      	r3, r0
  42:	c403008c 	subu      	r12, r3, r0
  46:	c46c0c20 	incf      	r3, r12, 0
  4a:	d80422a0 	ld.w      	r0, (r4, 0xa80)
  4e:	640e      	cmpne      	r3, r0
  50:	0c07      	bf      	0x5e	// 5e <lmac_ah_start_acs+0x5e>
  52:	e44202a2 	addi      	r2, r2, 675
  56:	d4440881 	str.w      	r1, (r4, r2 << 2)
  5a:	dc6422a1 	st.w      	r3, (r4, 0xa84)
  5e:	100c      	lrw      	r0, 0x0	// 8c <os_sema_up+0x8c>
  60:	e0000000 	bsr      	0x0	// 0 <os_sema_up>
  64:	3000      	movi      	r0, 0
  66:	1491      	pop      	r4, r15
  68:	e0000000 	bsr      	0x0	// 0 <lmac_auto_channel_select>
  6c:	d86409e0 	ld.b      	r3, (r4, 0x9e0)
  70:	3200      	movi      	r2, 0
  72:	c4625c00 	ins      	r3, r2, 0, 0
  76:	dc6409e0 	st.b      	r3, (r4, 0x9e0)
  7a:	07f6      	br      	0x66	// 66 <lmac_ah_start_acs+0x66>
  7c:	d86409e0 	ld.b      	r3, (r4, 0x9e0)
  80:	3000      	movi      	r0, 0
  82:	c4605c00 	ins      	r3, r0, 0, 0
  86:	07f8      	br      	0x76	// 76 <ah_lmac+0x76>
	...

Disassembly of section .text.lmac_eth_scan_report:

00000000 <lmac_eth_scan_report>:
   0:	1066      	lrw      	r3, 0x0	// 18 <lmac_eth_scan_report+0x18>
   2:	d84308bf 	ld.b      	r2, (r3, 0x8bf)
   6:	e9010003 	bez      	r1, 0xc	// c <lmac_eth_scan_report+0xc>
   a:	3101      	movi      	r1, 1
   c:	c4415c01 	ins      	r2, r1, 1, 1
  10:	3000      	movi      	r0, 0
  12:	dc4308bf 	st.b      	r2, (r3, 0x8bf)
  16:	783c      	jmp      	r15
  18:	0000      	.short	0x0000
	...

Disassembly of section .text.lmac_cfg_set_wnb_encrypt:

00000000 <lmac_cfg_set_wnb_encrypt>:
   0:	14d0      	push      	r15
   2:	ea00ffff 	movi      	r0, 65535
   6:	e0000000 	bsr      	0x0	// 0 <lmac_sta_get>
   a:	e900000b 	bez      	r0, 0x20	// 20 <lmac_cfg_set_wnb_encrypt+0x20>
   e:	d84000b9 	ld.b      	r2, (r0, 0xb9)
  12:	3101      	movi      	r1, 1
  14:	c4415c00 	ins      	r2, r1, 0, 0
  18:	dc4000b9 	st.b      	r2, (r0, 0xb9)
  1c:	e0000000 	bsr      	0x0	// 0 <lmac_sta_put>
  20:	3000      	movi      	r0, 0
  22:	1490      	pop      	r15

Disassembly of section .text.lmac_set_cfg:

00000000 <lmac_set_cfg>:
   0:	14d8      	push      	r4-r11, r15
   2:	142a      	subi      	r14, r14, 40
   4:	2900      	subi      	r1, 1
   6:	eb010069 	cmphsi      	r1, 106
   a:	6d0b      	mov      	r4, r2
   c:	6d4f      	mov      	r5, r3
   e:	0809      	bt      	0x20	// 20 <lmac_set_cfg+0x20>
  10:	1062      	lrw      	r3, 0x0	// 18 <lmac_set_cfg+0x18>
  12:	d0230883 	ldr.w      	r3, (r3, r1 << 2)
  16:	780c      	jmp      	r3
  18:	0000      	.short	0x0000
  1a:	0000      	.short	0x0000
  1c:	e9220004 	bnez      	r2, 0x24	// 24 <lmac_set_cfg+0x24>
  20:	3400      	movi      	r4, 0
  22:	0409      	br      	0x34	// 34 <lmac_set_cfg+0x34>
  24:	016e      	lrw      	r3, 0x0	// 368 <lmac_set_cfg+0x368>
  26:	dc430315 	st.b      	r2, (r3, 0x315)
  2a:	07fb      	br      	0x20	// 20 <lmac_set_cfg+0x20>
  2c:	7448      	zextb      	r1, r2
  2e:	e0000000 	bsr      	0x0	// 0 <lmac_set_cfg>
  32:	6d03      	mov      	r4, r0
  34:	6c13      	mov      	r0, r4
  36:	140a      	addi      	r14, r14, 40
  38:	1498      	pop      	r4-r11, r15
  3a:	0173      	lrw      	r3, 0x0	// 368 <lmac_set_cfg+0x368>
  3c:	7448      	zextb      	r1, r2
  3e:	d8430338 	ld.b      	r2, (r3, 0x338)
  42:	e4422008 	andi      	r2, r2, 8
  46:	e902000a 	bez      	r2, 0x5a	// 5a <lmac_set_cfg+0x5a>
  4a:	d8030875 	ld.b      	r0, (r3, 0x875)
  4e:	ea0c0001 	movi      	r12, 1
  52:	c40c5c01 	ins      	r0, r12, 1, 1
  56:	dc030875 	st.b      	r0, (r3, 0x875)
  5a:	d883034a 	ld.b      	r4, (r3, 0x34a)
  5e:	e4842001 	andi      	r4, r4, 1
  62:	e9040011 	bez      	r4, 0x84	// 84 <lmac_set_cfg+0x84>
  66:	3003      	movi      	r0, 3
  68:	dc030867 	st.b      	r0, (r3, 0x867)
  6c:	e902ffda 	bez      	r2, 0x20	// 20 <lmac_set_cfg+0x20>
  70:	3941      	cmpnei      	r1, 1
  72:	0fd7      	bf      	0x20	// 20 <lmac_set_cfg+0x20>
  74:	d8430875 	ld.b      	r2, (r3, 0x875)
  78:	3400      	movi      	r4, 0
  7a:	c4445c01 	ins      	r2, r4, 1, 1
  7e:	dc430875 	st.b      	r2, (r3, 0x875)
  82:	07d9      	br      	0x34	// 34 <lmac_set_cfg+0x34>
  84:	3942      	cmpnei      	r1, 2
  86:	0c23      	bf      	0xcc	// cc <lmac_set_cfg+0xcc>
  88:	3902      	cmphsi      	r1, 3
  8a:	080d      	bt      	0xa4	// a4 <lmac_set_cfg+0xa4>
  8c:	3941      	cmpnei      	r1, 1
  8e:	0c15      	bf      	0xb8	// b8 <lmac_set_cfg+0xb8>
  90:	0208      	lrw      	r0, 0x0	// 36c <lmac_set_cfg+0x36c>
  92:	d8230308 	ld.b      	r1, (r3, 0x308)
  96:	d0200021 	ldr.b      	r1, (r0, r1 << 0)
  9a:	dc230867 	st.b      	r1, (r3, 0x867)
  9e:	e922ffeb 	bnez      	r2, 0x74	// 74 <lmac_set_cfg+0x74>
  a2:	07bf      	br      	0x20	// 20 <lmac_set_cfg+0x20>
  a4:	3944      	cmpnei      	r1, 4
  a6:	0c1b      	bf      	0xdc	// dc <lmac_set_cfg+0xdc>
  a8:	3948      	cmpnei      	r1, 8
  aa:	0bf3      	bt      	0x90	// 90 <lmac_set_cfg+0x90>
  ac:	d8430308 	ld.b      	r2, (r3, 0x308)
  b0:	3a02      	cmphsi      	r2, 3
  b2:	0c23      	bf      	0xf8	// f8 <lmac_set_cfg+0xf8>
  b4:	3202      	movi      	r2, 2
  b6:	0418      	br      	0xe6	// e6 <lmac_set_cfg+0xe6>
  b8:	3203      	movi      	r2, 3
  ba:	dc430867 	st.b      	r2, (r3, 0x867)
  be:	d8630308 	ld.b      	r3, (r3, 0x308)
  c2:	704c      	lsl      	r1, r3
  c4:	0214      	lrw      	r0, 0x0	// 370 <lmac_set_cfg+0x370>
  c6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  ca:	07b5      	br      	0x34	// 34 <lmac_set_cfg+0x34>
  cc:	dc830867 	st.b      	r4, (r3, 0x867)
  d0:	3101      	movi      	r1, 1
  d2:	d8630308 	ld.b      	r3, (r3, 0x308)
  d6:	704c      	lsl      	r1, r3
  d8:	0218      	lrw      	r0, 0x0	// 374 <lmac_set_cfg+0x374>
  da:	07f6      	br      	0xc6	// c6 <lmac_set_cfg+0xc6>
  dc:	d8430308 	ld.b      	r2, (r3, 0x308)
  e0:	3a01      	cmphsi      	r2, 2
  e2:	0c05      	bf      	0xec	// ec <lmac_set_cfg+0xec>
  e4:	3201      	movi      	r2, 1
  e6:	dc430867 	st.b      	r2, (r3, 0x867)
  ea:	07a5      	br      	0x34	// 34 <lmac_set_cfg+0x34>
  ec:	3101      	movi      	r1, 1
  ee:	dc830867 	st.b      	r4, (r3, 0x867)
  f2:	7048      	lsl      	r1, r2
  f4:	021e      	lrw      	r0, 0x0	// 378 <lmac_set_cfg+0x378>
  f6:	07e8      	br      	0xc6	// c6 <lmac_set_cfg+0xc6>
  f8:	3101      	movi      	r1, 1
  fa:	dc830867 	st.b      	r4, (r3, 0x867)
  fe:	7048      	lsl      	r1, r2
 100:	0300      	lrw      	r0, 0x0	// 37c <lmac_set_cfg+0x37c>
 102:	07e2      	br      	0xc6	// c6 <lmac_set_cfg+0xc6>
 104:	0366      	lrw      	r3, 0x0	// 368 <lmac_set_cfg+0x368>
 106:	dc430866 	st.b      	r2, (r3, 0x866)
 10a:	078b      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 10c:	0368      	lrw      	r3, 0x0	// 368 <lmac_set_cfg+0x368>
 10e:	dc431197 	st.h      	r2, (r3, 0x32e)
 112:	0787      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 114:	0364      	lrw      	r3, 0x0	// 380 <lmac_set_cfg+0x380>
 116:	6d8f      	mov      	r6, r3
 118:	d8434006 	ld.bs      	r2, (r3, 0x6)
 11c:	6509      	cmplt      	r2, r4
 11e:	0848      	bt      	0x1ae	// 1ae <lmac_set_cfg+0x1ae>
 120:	3c20      	cmplti      	r4, 1
 122:	6d4b      	mov      	r5, r2
 124:	3300      	movi      	r3, 0
 126:	c4a40c20 	incf      	r5, r4, 0
 12a:	2b00      	subi      	r3, 1
 12c:	3c20      	cmplti      	r4, 1
 12e:	3400      	movi      	r4, 0
 130:	c4830c40 	inct      	r4, r3, 0
 134:	0372      	lrw      	r3, 0x0	// 368 <lmac_set_cfg+0x368>
 136:	6c57      	mov      	r1, r5
 138:	030c      	lrw      	r0, 0x0	// 384 <lmac_set_cfg+0x384>
 13a:	dca3068e 	st.b      	r5, (r3, 0x68e)
 13e:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 142:	d8064006 	ld.bs      	r0, (r6, 0x6)
 146:	6016      	subu      	r0, r5
 148:	e0000000 	bsr      	0x0	// 0 <__floatsidf>
 14c:	3200      	movi      	r2, 0
 14e:	ea234034 	movih      	r3, 16436
 152:	e0000000 	bsr      	0x0	// 0 <__divdf3>
 156:	6c83      	mov      	r2, r0
 158:	6cc7      	mov      	r3, r1
 15a:	3000      	movi      	r0, 0
 15c:	ea214024 	movih      	r1, 16420
 160:	e0000000 	bsr      	0x0	// 0 <pow>
 164:	6c83      	mov      	r2, r0
 166:	6cc7      	mov      	r3, r1
 168:	3000      	movi      	r0, 0
 16a:	ea214090 	movih      	r1, 16528
 16e:	e0000000 	bsr      	0x0	// 0 <__divdf3>
 172:	e0000000 	bsr      	0x0	// 0 <__fixunsdfsi>
 176:	7541      	zexth      	r5, r0
 178:	6c17      	mov      	r0, r5
 17a:	3103      	movi      	r1, 3
 17c:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
 180:	6c17      	mov      	r0, r5
 182:	3104      	movi      	r1, 4
 184:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
 188:	6c17      	mov      	r0, r5
 18a:	3105      	movi      	r1, 5
 18c:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_config_tx_digi_gain>
 190:	3600      	movi      	r6, 0
 192:	3503      	movi      	r5, 3
 194:	6c17      	mov      	r0, r5
 196:	2500      	addi      	r5, 1
 198:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_get_tx_digi_gain>
 19c:	7554      	zextb      	r5, r5
 19e:	1373      	lrw      	r3, 0x0	// 368 <lmac_set_cfg+0x368>
 1a0:	60d8      	addu      	r3, r6
 1a2:	3d46      	cmpnei      	r5, 6
 1a4:	dc031344 	st.h      	r0, (r3, 0x688)
 1a8:	2601      	addi      	r6, 2
 1aa:	0bf5      	bt      	0x194	// 194 <lmac_set_cfg+0x194>
 1ac:	0744      	br      	0x34	// 34 <lmac_set_cfg+0x34>
 1ae:	3400      	movi      	r4, 0
 1b0:	6d4b      	mov      	r5, r2
 1b2:	2c00      	subi      	r4, 1
 1b4:	07c0      	br      	0x134	// 134 <lmac_set_cfg+0x134>
 1b6:	136d      	lrw      	r3, 0x0	// 368 <lmac_set_cfg+0x368>
 1b8:	7509      	zexth      	r4, r2
 1ba:	dc83133b 	st.h      	r4, (r3, 0x676)
 1be:	d8632233 	ld.w      	r3, (r3, 0x8cc)
 1c2:	e903ff2f 	bez      	r3, 0x20	// 20 <lmac_set_cfg+0x20>
 1c6:	dc831504 	st.h      	r4, (r3, 0xa08)
 1ca:	072b      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 1cc:	1367      	lrw      	r3, 0x0	// 368 <lmac_set_cfg+0x368>
 1ce:	3a40      	cmpnei      	r2, 0
 1d0:	c4000501 	mvc      	r1
 1d4:	d8430310 	ld.b      	r2, (r3, 0x310)
 1d8:	c4415c03 	ins      	r2, r1, 3, 3
 1dc:	dc430310 	st.b      	r2, (r3, 0x310)
 1e0:	0720      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 1e2:	1362      	lrw      	r3, 0x0	// 368 <lmac_set_cfg+0x368>
 1e4:	3a40      	cmpnei      	r2, 0
 1e6:	c4000501 	mvc      	r1
 1ea:	d843037c 	ld.b      	r2, (r3, 0x37c)
 1ee:	c4415c01 	ins      	r2, r1, 1, 1
 1f2:	dc43037c 	st.b      	r2, (r3, 0x37c)
 1f6:	0715      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 1f8:	6c4b      	mov      	r1, r2
 1fa:	e0000000 	bsr      	0x0	// 0 <lmac_set_cfg>
 1fe:	0711      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 200:	6c0b      	mov      	r0, r2
 202:	e0000000 	bsr      	0x0	// 0 <strlen>
 206:	eb000020 	cmphsi      	r0, 33
 20a:	6c43      	mov      	r1, r0
 20c:	0833      	bt      	0x272	// 272 <lmac_set_cfg+0x272>
 20e:	12b7      	lrw      	r5, 0x0	// 368 <lmac_set_cfg+0x368>
 210:	3300      	movi      	r3, 0
 212:	6c13      	mov      	r0, r4
 214:	dc65052c 	st.b      	r3, (r5, 0x52c)
 218:	e0000000 	bsr      	0x0	// 0 <strlen>
 21c:	dc05052d 	st.b      	r0, (r5, 0x52d)
 220:	3220      	movi      	r2, 32
 222:	6c53      	mov      	r1, r4
 224:	e405052d 	addi      	r0, r5, 1326
 228:	e0000000 	bsr      	0x0	// 0 <memcpy>
 22c:	d8052233 	ld.w      	r0, (r5, 0x8cc)
 230:	e9000008 	bez      	r0, 0x240	// 240 <lmac_set_cfg+0x240>
 234:	3220      	movi      	r2, 32
 236:	6c53      	mov      	r1, r4
 238:	e400025b 	addi      	r0, r0, 604
 23c:	e0000000 	bsr      	0x0	// 0 <memcpy>
 240:	303b      	movi      	r0, 59
 242:	e0000000 	bsr      	0x0	// 0 <dev_get>
 246:	6d83      	mov      	r6, r0
 248:	3307      	movi      	r3, 7
 24a:	6c13      	mov      	r0, r4
 24c:	dc6e100e 	st.h      	r3, (r14, 0x1c)
 250:	b888      	st.w      	r4, (r14, 0x20)
 252:	e0000000 	bsr      	0x0	// 0 <strlen>
 256:	9642      	ld.w      	r2, (r6, 0x8)
 258:	3300      	movi      	r3, 0
 25a:	d9822003 	ld.w      	r12, (r2, 0xc)
 25e:	b809      	st.w      	r0, (r14, 0x24)
 260:	dc652154 	st.w      	r3, (r5, 0x550)
 264:	e90cfede 	bez      	r12, 0x20	// 20 <lmac_set_cfg+0x20>
 268:	1248      	lrw      	r2, 0x0	// 388 <lmac_set_cfg+0x388>
 26a:	1907      	addi      	r1, r14, 28
 26c:	6c1b      	mov      	r0, r6
 26e:	7bf1      	jsr      	r12
 270:	06d8      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 272:	1207      	lrw      	r0, 0x0	// 38c <lmac_set_cfg+0x38c>
 274:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 278:	06d4      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 27a:	117c      	lrw      	r3, 0x0	// 368 <lmac_set_cfg+0x368>
 27c:	d8632233 	ld.w      	r3, (r3, 0x8cc)
 280:	e903fed0 	bez      	r3, 0x20	// 20 <lmac_set_cfg+0x20>
 284:	8355      	ld.b      	r2, (r3, 0x15)
 286:	c4445c40 	ins      	r2, r4, 2, 0
 28a:	a355      	st.b      	r2, (r3, 0x15)
 28c:	06ca      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 28e:	1177      	lrw      	r3, 0x0	// 368 <lmac_set_cfg+0x368>
 290:	d8632233 	ld.w      	r3, (r3, 0x8cc)
 294:	e903fec6 	bez      	r3, 0x20	// 20 <lmac_set_cfg+0x20>
 298:	ab47      	st.h      	r2, (r3, 0xe)
 29a:	06c3      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 29c:	e902fec2 	bez      	r2, 0x20	// 20 <lmac_set_cfg+0x20>
 2a0:	1172      	lrw      	r3, 0x0	// 368 <lmac_set_cfg+0x368>
 2a2:	d8232233 	ld.w      	r1, (r3, 0x8cc)
 2a6:	e901000a 	bez      	r1, 0x2ba	// 2ba <lmac_set_cfg+0x2ba>
 2aa:	d8410258 	ld.b      	r2, (r1, 0x258)
 2ae:	c4445cc0 	ins      	r2, r4, 6, 0
 2b2:	c4455c07 	ins      	r2, r5, 7, 7
 2b6:	dc410258 	st.b      	r2, (r1, 0x258)
 2ba:	d843031a 	ld.b      	r2, (r3, 0x31a)
 2be:	e424207f 	andi      	r1, r4, 127
 2c2:	c4415cc1 	ins      	r2, r1, 7, 1
 2c6:	d803031b 	ld.b      	r0, (r3, 0x31b)
 2ca:	dc43031a 	st.b      	r2, (r3, 0x31a)
 2ce:	e4452001 	andi      	r2, r5, 1
 2d2:	c4025c00 	ins      	r0, r2, 0, 0
 2d6:	dc03031b 	st.b      	r0, (r3, 0x31b)
 2da:	110e      	lrw      	r0, 0x0	// 390 <hgprintf+0x390>
 2dc:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 2e0:	06a0      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 2e2:	e4822003 	andi      	r4, r2, 3
 2e6:	1141      	lrw      	r2, 0x0	// 368 <lmac_set_cfg+0x368>
 2e8:	d862036d 	ld.b      	r3, (r2, 0x36d)
 2ec:	c4645c22 	ins      	r3, r4, 3, 2
 2f0:	c4645c24 	ins      	r3, r4, 5, 4
 2f4:	dc62036d 	st.b      	r3, (r2, 0x36d)
 2f8:	0694      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 2fa:	3a40      	cmpnei      	r2, 0
 2fc:	1166      	lrw      	r3, 0x0	// 394 <lmac_set_cfg+0x394>
 2fe:	1127      	lrw      	r1, 0x0	// 398 <lmac_set_cfg+0x398>
 300:	10ba      	lrw      	r5, 0x0	// 368 <lmac_set_cfg+0x368>
 302:	c4230c20 	incf      	r1, r3, 0
 306:	1106      	lrw      	r0, 0x0	// 39c <hgprintf+0x39c>
 308:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 30c:	d8452233 	ld.w      	r2, (r5, 0x8cc)
 310:	e902013c 	bez      	r2, 0x588	// 588 <lmac_set_cfg+0x588>
 314:	d862025a 	ld.b      	r3, (r2, 0x25a)
 318:	c4645c00 	ins      	r3, r4, 0, 0
 31c:	dc62025a 	st.b      	r3, (r2, 0x25a)
 320:	74cc      	zextb      	r3, r3
 322:	e4232001 	andi      	r1, r3, 1
 326:	e901fe7d 	bez      	r1, 0x20	// 20 <lmac_set_cfg+0x20>
 32a:	311e      	movi      	r1, 30
 32c:	c4615cc1 	ins      	r3, r1, 7, 1
 330:	dc62025a 	st.b      	r3, (r2, 0x25a)
 334:	e46320fc 	andi      	r3, r3, 252
 338:	eb43003c 	cmpnei      	r3, 60
 33c:	0804      	bt      	0x344	// 344 <lmac_set_cfg+0x344>
 33e:	3000      	movi      	r0, 0
 340:	e0000000 	bsr      	0x0	// 0 <jtag_map_set>
 344:	d8652233 	ld.w      	r3, (r5, 0x8cc)
 348:	3101      	movi      	r1, 1
 34a:	d803025a 	ld.b      	r0, (r3, 0x25a)
 34e:	7005      	lsr      	r0, r1
 350:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
 354:	d8652233 	ld.w      	r3, (r5, 0x8cc)
 358:	3100      	movi      	r1, 0
 35a:	d803025a 	ld.b      	r0, (r3, 0x25a)
 35e:	4801      	lsri      	r0, r0, 1
 360:	e0000000 	bsr      	0x0	// 0 <gpio_set_val>
 364:	065e      	br      	0x20	// 20 <lmac_set_cfg+0x20>
	...
 39e:	0000      	.short	0x0000
 3a0:	6c4b      	mov      	r1, r2
 3a2:	3000      	movi      	r0, 0
 3a4:	e0000000 	bsr      	0x0	// 0 <lmac_sta_get>
 3a8:	e900fe3c 	bez      	r0, 0x20	// 20 <lmac_set_cfg+0x20>
 3ac:	3d40      	cmpnei      	r5, 0
 3ae:	d840006b 	ld.b      	r2, (r0, 0x6b)
 3b2:	c4000501 	mvc      	r1
 3b6:	c4415c04 	ins      	r2, r1, 4, 4
 3ba:	dc40006b 	st.b      	r2, (r0, 0x6b)
 3be:	e0000000 	bsr      	0x0	// 0 <lmac_sta_put>
 3c2:	062f      	br      	0x20	// 20 <lmac_set_cfg+0x20>
 3c4:	01f9      	lrw      	r7, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 3c6:	d8072295 	ld.w      	r0, (r7, 0xa54)
 3ca:	e0000000 	bsr      	0x0	// 0 <kfree_skb>
 3ce:	3300      	movi      	r3, 0
 3d0:	dc672295 	st.w      	r3, (r7, 0xa54)
 3d4:	dc6720e9 	st.w      	r3, (r7, 0x3a4)
 3d8:	331e      	movi      	r3, 30
 3da:	dc6720ea 	st.w      	r3, (r7, 0x3a8)
 3de:	e904fe21 	bez      	r4, 0x20	// 20 <lmac_set_cfg+0x20>
 3e2:	6c57      	mov      	r1, r5
 3e4:	0200      	lrw      	r0, 0x0	// 6e0 <lmac_set_cfg+0x6e0>
 3e6:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 3ea:	9468      	ld.w      	r3, (r4, 0x20)
 3ec:	9409      	ld.w      	r0, (r4, 0x24)
 3ee:	600e      	subu      	r0, r3
 3f0:	e0000000 	bsr      	0x0	// 0 <alloc_tx_skb>
 3f4:	d86720ee 	ld.w      	r3, (r7, 0x3b8)
 3f8:	e4632008 	andi      	r3, r3, 8
 3fc:	6d83      	mov      	r6, r0
 3fe:	e903000a 	bez      	r3, 0x412	// 412 <lmac_set_cfg+0x412>
 402:	8c34      	ld.h      	r1, (r4, 0x28)
 404:	0207      	lrw      	r0, 0x0	// 6e4 <lmac_set_cfg+0x6e4>
 406:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 40a:	8c34      	ld.h      	r1, (r4, 0x28)
 40c:	9407      	ld.w      	r0, (r4, 0x1c)
 40e:	e0000000 	bsr      	0x0	// 0 <hgics_print_hex>
 412:	e906fe07 	bez      	r6, 0x20	// 20 <lmac_set_cfg+0x20>
 416:	9468      	ld.w      	r3, (r4, 0x20)
 418:	9427      	ld.w      	r1, (r4, 0x1c)
 41a:	604e      	subu      	r1, r3
 41c:	210f      	addi      	r1, 16
 41e:	6c1b      	mov      	r0, r6
 420:	e0000000 	bsr      	0x0	// 0 <skb_reserve>
 424:	9607      	ld.w      	r0, (r6, 0x1c)
 426:	280c      	subi      	r0, 13
 428:	3880      	bclri      	r0, 0
 42a:	3881      	bclri      	r0, 1
 42c:	320c      	movi      	r2, 12
 42e:	3100      	movi      	r1, 0
 430:	b60d      	st.w      	r0, (r6, 0x34)
 432:	e0000000 	bsr      	0x0	// 0 <memset>
 436:	8c54      	ld.h      	r2, (r4, 0x28)
 438:	9427      	ld.w      	r1, (r4, 0x1c)
 43a:	9607      	ld.w      	r0, (r6, 0x1c)
 43c:	e0000000 	bsr      	0x0	// 0 <memcpy>
 440:	8c34      	ld.h      	r1, (r4, 0x28)
 442:	6c1b      	mov      	r0, r6
 444:	e0000000 	bsr      	0x0	// 0 <skb_put>
 448:	32fa      	movi      	r2, 250
 44a:	4242      	lsli      	r2, r2, 2
 44c:	7c94      	mult      	r2, r5
 44e:	dc4720e9 	st.w      	r2, (r7, 0x3a4)
 452:	dcc72295 	st.w      	r6, (r7, 0xa54)
 456:	d866002a 	ld.b      	r3, (r6, 0x2a)
 45a:	3201      	movi      	r2, 1
 45c:	c4625c06 	ins      	r3, r2, 6, 6
 460:	dc66002a 	st.b      	r3, (r6, 0x2a)
 464:	d86720ee 	ld.w      	r3, (r7, 0x3b8)
 468:	e4632008 	andi      	r3, r3, 8
 46c:	e903fdda 	bez      	r3, 0x20	// 20 <lmac_set_cfg+0x20>
 470:	8e34      	ld.h      	r1, (r6, 0x28)
 472:	0302      	lrw      	r0, 0x0	// 6e4 <lmac_set_cfg+0x6e4>
 474:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 478:	8e34      	ld.h      	r1, (r6, 0x28)
 47a:	9607      	ld.w      	r0, (r6, 0x1c)
 47c:	e0000000 	bsr      	0x0	// 0 <hgics_print_hex>
 480:	e800fdd0 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 484:	0369      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 486:	e4c22003 	andi      	r6, r2, 3
 48a:	3c41      	cmpnei      	r4, 1
 48c:	d84303df 	ld.b      	r2, (r3, 0x3df)
 490:	c4465c20 	ins      	r2, r6, 1, 0
 494:	dc4303df 	st.b      	r2, (r3, 0x3df)
 498:	6d4f      	mov      	r5, r3
 49a:	0812      	bt      	0x4be	// 4be <lmac_set_cfg+0x4be>
 49c:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13_ldo_dis_sec>
 4a0:	030d      	lrw      	r0, 0x0	// 6e8 <hgprintf+0x6e8>
 4a2:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 4a6:	d8652233 	ld.w      	r3, (r5, 0x8cc)
 4aa:	e903006f 	bez      	r3, 0x588	// 588 <lmac_set_cfg+0x588>
 4ae:	d843025b 	ld.b      	r2, (r3, 0x25b)
 4b2:	c4465c20 	ins      	r2, r6, 1, 0
 4b6:	dc43025b 	st.b      	r2, (r3, 0x25b)
 4ba:	e800fdb3 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 4be:	3c42      	cmpnei      	r4, 2
 4c0:	0809      	bt      	0x4d2	// 4d2 <lmac_set_cfg+0x4d2>
 4c2:	3005      	movi      	r0, 5
 4c4:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13c_vol_set_sec>
 4c8:	3005      	movi      	r0, 5
 4ca:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13b_vol_set_sec>
 4ce:	0317      	lrw      	r0, 0x0	// 6ec <lmac_set_cfg+0x6ec>
 4d0:	07e9      	br      	0x4a2	// 4a2 <lmac_set_cfg+0x4a2>
 4d2:	3004      	movi      	r0, 4
 4d4:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13c_vol_set_sec>
 4d8:	3004      	movi      	r0, 4
 4da:	e0000000 	bsr      	0x0	// 0 <pmu_vdd13b_vol_set_sec>
 4de:	031a      	lrw      	r0, 0x0	// 6f0 <lmac_set_cfg+0x6f0>
 4e0:	07e1      	br      	0x4a2	// 4a2 <lmac_set_cfg+0x4a2>
 4e2:	137f      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 4e4:	dc4311ee 	st.h      	r2, (r3, 0x3dc)
 4e8:	e800fd9c 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 4ec:	5a63      	subi      	r3, r2, 1
 4ee:	eb0300fe 	cmphsi      	r3, 255
 4f2:	137b      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 4f4:	080b      	bt      	0x50a	// 50a <lmac_set_cfg+0x50a>
 4f6:	dc430313 	st.b      	r2, (r3, 0x313)
 4fa:	5d43      	subi      	r2, r5, 1
 4fc:	eb0200fe 	cmphsi      	r2, 255
 500:	0809      	bt      	0x512	// 512 <lmac_set_cfg+0x512>
 502:	dca30312 	st.b      	r5, (r3, 0x312)
 506:	e800fd8d 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 50a:	3207      	movi      	r2, 7
 50c:	dc430313 	st.b      	r2, (r3, 0x313)
 510:	07f5      	br      	0x4fa	// 4fa <lmac_set_cfg+0x4fa>
 512:	321f      	movi      	r2, 31
 514:	dc430312 	st.b      	r2, (r3, 0x312)
 518:	e800fd84 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 51c:	6c4b      	mov      	r1, r2
 51e:	1316      	lrw      	r0, 0x0	// 6f4 <lmac_set_cfg+0x6f4>
 520:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 524:	136e      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 526:	d8632233 	ld.w      	r3, (r3, 0x8cc)
 52a:	e903002f 	bez      	r3, 0x588	// 588 <lmac_set_cfg+0x588>
 52e:	dc8320ad 	st.w      	r4, (r3, 0x2b4)
 532:	e800fd77 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 536:	6c4b      	mov      	r1, r2
 538:	1310      	lrw      	r0, 0x0	// 6f8 <lmac_set_cfg+0x6f8>
 53a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 53e:	1368      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 540:	d8632233 	ld.w      	r3, (r3, 0x8cc)
 544:	e9030022 	bez      	r3, 0x588	// 588 <lmac_set_cfg+0x588>
 548:	3c40      	cmpnei      	r4, 0
 54a:	c4000501 	mvc      	r1
 54e:	d843025b 	ld.b      	r2, (r3, 0x25b)
 552:	dc8320ae 	st.w      	r4, (r3, 0x2b8)
 556:	c4415c03 	ins      	r2, r1, 3, 3
 55a:	07ae      	br      	0x4b6	// 4b6 <lmac_set_cfg+0x4b6>
 55c:	1308      	lrw      	r0, 0x0	// 6fc <lmac_set_cfg+0x6fc>
 55e:	0416      	br      	0x58a	// 58a <lmac_set_cfg+0x58a>
 560:	1308      	lrw      	r0, 0x0	// 700 <lmac_set_cfg+0x700>
 562:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 566:	127e      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 568:	d8632233 	ld.w      	r3, (r3, 0x8cc)
 56c:	e903000e 	bez      	r3, 0x588	// 588 <lmac_set_cfg+0x588>
 570:	dc832298 	st.w      	r4, (r3, 0xa60)
 574:	e800fd56 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 578:	1303      	lrw      	r0, 0x0	// 704 <hgprintf+0x704>
 57a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 57e:	1278      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 580:	d8632233 	ld.w      	r3, (r3, 0x8cc)
 584:	e923fd4e 	bnez      	r3, 0x20	// 20 <lmac_set_cfg+0x20>
 588:	1300      	lrw      	r0, 0x0	// 708 <hgprintf+0x708>
 58a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 58e:	e800fd49 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 592:	121f      	lrw      	r0, 0x0	// 70c <lmac_set_cfg+0x70c>
 594:	07f3      	br      	0x57a	// 57a <lmac_set_cfg+0x57a>
 596:	1272      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 598:	dc4303de 	st.b      	r2, (r3, 0x3de)
 59c:	e800fd42 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 5a0:	126f      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 5a2:	dc430868 	st.b      	r2, (r3, 0x868)
 5a6:	e800fd3d 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 5aa:	5a63      	subi      	r3, r2, 1
 5ac:	3b01      	cmphsi      	r3, 2
 5ae:	080d      	bt      	0x5c8	// 5c8 <lmac_set_cfg+0x5c8>
 5b0:	124b      	lrw      	r2, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 5b2:	d862034a 	ld.b      	r3, (r2, 0x34a)
 5b6:	e4632001 	andi      	r3, r3, 1
 5ba:	3b40      	cmpnei      	r3, 0
 5bc:	64c3      	mvcv      	r3
 5be:	2300      	addi      	r3, 1
 5c0:	dc620869 	st.b      	r3, (r2, 0x869)
 5c4:	e800fd2e 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 5c8:	3a44      	cmpnei      	r2, 4
 5ca:	080b      	bt      	0x5e0	// 5e0 <lmac_set_cfg+0x5e0>
 5cc:	1264      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 5ce:	d8430308 	ld.b      	r2, (r3, 0x308)
 5d2:	3a01      	cmphsi      	r2, 2
 5d4:	e840fd26 	bf      	0x20	// 20 <lmac_set_cfg+0x20>
 5d8:	dc830869 	st.b      	r4, (r3, 0x869)
 5dc:	e800fd22 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 5e0:	3a48      	cmpnei      	r2, 8
 5e2:	e860fd1f 	bt      	0x20	// 20 <lmac_set_cfg+0x20>
 5e6:	117e      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 5e8:	d8430308 	ld.b      	r2, (r3, 0x308)
 5ec:	3a02      	cmphsi      	r2, 3
 5ee:	07f3      	br      	0x5d4	// 5d4 <lmac_set_cfg+0x5d4>
 5f0:	117b      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 5f2:	d8430314 	ld.b      	r2, (r3, 0x314)
 5f6:	c4445c80 	ins      	r2, r4, 4, 0
 5fa:	dc430314 	st.b      	r2, (r3, 0x314)
 5fe:	e800fd11 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 602:	1177      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 604:	3a40      	cmpnei      	r2, 0
 606:	c4000501 	mvc      	r1
 60a:	d8430314 	ld.b      	r2, (r3, 0x314)
 60e:	c4415c05 	ins      	r2, r1, 5, 5
 612:	07f4      	br      	0x5fa	// 5fa <lmac_set_cfg+0x5fa>
 614:	e462101d 	subi      	r3, r2, 30
 618:	3b01      	cmphsi      	r3, 2
 61a:	0804      	bt      	0x622	// 622 <lmac_set_cfg+0x622>
 61c:	3000      	movi      	r0, 0
 61e:	e0000000 	bsr      	0x0	// 0 <jtag_map_set>
 622:	3101      	movi      	r1, 1
 624:	6c13      	mov      	r0, r4
 626:	e0000000 	bsr      	0x0	// 0 <gpio_set_dir>
 62a:	114d      	lrw      	r2, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 62c:	6c4b      	mov      	r1, r2
 62e:	d8620876 	ld.b      	r3, (r2, 0x876)
 632:	740e      	sextb      	r0, r3
 634:	e9a00012 	bhsz      	r0, 0x658	// 658 <lmac_set_cfg+0x658>
 638:	e463207f 	andi      	r3, r3, 127
 63c:	64d2      	cmpne      	r4, r3
 63e:	0c0d      	bf      	0x658	// 658 <lmac_set_cfg+0x658>
 640:	d8620877 	ld.b      	r3, (r2, 0x877)
 644:	3101      	movi      	r1, 1
 646:	c4645cc0 	ins      	r3, r4, 6, 0
 64a:	c4615c07 	ins      	r3, r1, 7, 7
 64e:	dc620877 	st.b      	r3, (r2, 0x877)
 652:	6c53      	mov      	r1, r4
 654:	110f      	lrw      	r0, 0x0	// 710 <lmac_set_cfg+0x710>
 656:	060f      	br      	0x274	// 274 <lmac_set_cfg+0x274>
 658:	d8610876 	ld.b      	r3, (r1, 0x876)
 65c:	c4645cc0 	ins      	r3, r4, 6, 0
 660:	3201      	movi      	r2, 1
 662:	3c1f      	cmphsi      	r4, 32
 664:	c4625c07 	ins      	r3, r2, 7, 7
 668:	dc610876 	st.b      	r3, (r1, 0x876)
 66c:	0804      	bt      	0x674	// 674 <lmac_set_cfg+0x674>
 66e:	6c53      	mov      	r1, r4
 670:	1109      	lrw      	r0, 0x0	// 714 <lmac_set_cfg+0x714>
 672:	0601      	br      	0x274	// 274 <lmac_set_cfg+0x274>
 674:	e424101f 	subi      	r1, r4, 32
 678:	1108      	lrw      	r0, 0x0	// 718 <lmac_set_cfg+0x718>
 67a:	e800fdfd 	br      	0x274	// 274 <lmac_set_cfg+0x274>
 67e:	1078      	lrw      	r3, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 680:	3a40      	cmpnei      	r2, 0
 682:	c4000501 	mvc      	r1
 686:	d8430875 	ld.b      	r2, (r3, 0x875)
 68a:	c4415c02 	ins      	r2, r1, 2, 2
 68e:	dc430875 	st.b      	r2, (r3, 0x875)
 692:	e800fcc7 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 696:	1052      	lrw      	r2, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 698:	3101      	movi      	r1, 1
 69a:	d8620875 	ld.b      	r3, (r2, 0x875)
 69e:	3c40      	cmpnei      	r4, 0
 6a0:	c4615c02 	ins      	r3, r1, 2, 2
 6a4:	c4000501 	mvc      	r1
 6a8:	c4615c03 	ins      	r3, r1, 3, 3
 6ac:	dc620875 	st.b      	r3, (r2, 0x875)
 6b0:	e800fcb8 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 6b4:	104a      	lrw      	r2, 0x0	// 6dc <lmac_set_cfg+0x6dc>
 6b6:	3101      	movi      	r1, 1
 6b8:	d8620875 	ld.b      	r3, (r2, 0x875)
 6bc:	3c40      	cmpnei      	r4, 0
 6be:	c4615c02 	ins      	r3, r1, 2, 2
 6c2:	c4000501 	mvc      	r1
 6c6:	7444      	zextb      	r1, r1
 6c8:	e46320f7 	andi      	r3, r3, 247
 6cc:	c4615c04 	ins      	r3, r1, 4, 4
 6d0:	dc620875 	st.b      	r3, (r2, 0x875)
 6d4:	1012      	lrw      	r0, 0x0	// 71c <lmac_set_cfg+0x71c>
 6d6:	e800fdcf 	br      	0x274	// 274 <lmac_set_cfg+0x274>
	...
 71e:	0000      	.short	0x0000
 720:	8525      	ld.b      	r1, (r5, 0x5)
 722:	8561      	ld.b      	r3, (r5, 0x1)
 724:	8540      	ld.b      	r2, (r5, 0x0)
 726:	b823      	st.w      	r1, (r14, 0xc)
 728:	8524      	ld.b      	r1, (r5, 0x4)
 72a:	b822      	st.w      	r1, (r14, 0x8)
 72c:	8523      	ld.b      	r1, (r5, 0x3)
 72e:	b821      	st.w      	r1, (r14, 0x4)
 730:	8522      	ld.b      	r1, (r5, 0x2)
 732:	b820      	st.w      	r1, (r14, 0x0)
 734:	7451      	zexth      	r1, r4
 736:	011a      	lrw      	r0, 0x0	// a48 <lmac_set_cfg+0xa48>
 738:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 73c:	6c57      	mov      	r1, r5
 73e:	7411      	zexth      	r0, r4
 740:	e0000000 	bsr      	0x0	// 0 <lmac_sta_search>
 744:	e9200009 	bnez      	r0, 0x756	// 756 <lmac_set_cfg+0x756>
 748:	011e      	lrw      	r0, 0x0	// a4c <hgprintf+0xa4c>
 74a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 74e:	3400      	movi      	r4, 0
 750:	2c00      	subi      	r4, 1
 752:	e800fc71 	br      	0x34	// 34 <lmac_set_cfg+0x34>
 756:	3300      	movi      	r3, 0
 758:	3640      	movi      	r6, 64
 75a:	dcc0013f 	st.b      	r6, (r0, 0x13f)
 75e:	e5a00143 	addi      	r13, r0, 324
 762:	6e8f      	mov      	r10, r3
 764:	ea090032 	movi      	r9, 50
 768:	3400      	movi      	r4, 0
 76a:	3500      	movi      	r5, 0
 76c:	6e0f      	mov      	r8, r3
 76e:	3701      	movi      	r7, 1
 770:	e4430014 	addi      	r2, r3, 21
 774:	4244      	lsli      	r2, r2, 4
 776:	dd4d1007 	st.h      	r10, (r13, 0xe)
 77a:	d4020029 	str.b      	r9, (r2, r0 << 0)
 77e:	4344      	lsli      	r2, r3, 4
 780:	6080      	addu      	r2, r0
 782:	2300      	addi      	r3, 1
 784:	d982014f 	ld.b      	r12, (r2, 0x14f)
 788:	c5865cc0 	ins      	r12, r6, 6, 0
 78c:	dd82014f 	st.b      	r12, (r2, 0x14f)
 790:	dc8d2000 	st.w      	r4, (r13, 0x0)
 794:	dcad2001 	st.w      	r5, (r13, 0x4)
 798:	d98210a6 	ld.h      	r12, (r2, 0x14c)
 79c:	c5885d60 	ins      	r12, r8, 11, 0
 7a0:	dd8210a6 	st.h      	r12, (r2, 0x14c)
 7a4:	d982014f 	ld.b      	r12, (r2, 0x14f)
 7a8:	e58c207f 	andi      	r12, r12, 127
 7ac:	d9622053 	ld.w      	r11, (r2, 0x14c)
 7b0:	e58c1000 	subi      	r12, r12, 1
 7b4:	c56c5d6c 	ins      	r11, r12, 23, 12
 7b8:	dd622053 	st.w      	r11, (r2, 0x14c)
 7bc:	e422014b 	addi      	r1, r2, 332
 7c0:	3b48      	cmpnei      	r3, 8
 7c2:	d842014f 	ld.b      	r2, (r2, 0x14f)
 7c6:	c4475c07 	ins      	r2, r7, 7, 7
 7ca:	a143      	st.b      	r2, (r1, 0x3)
 7cc:	e5ad000f 	addi      	r13, r13, 16
 7d0:	0bd0      	bt      	0x770	// 770 <lmac_set_cfg+0x770>
 7d2:	e800fc27 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 7d6:	0360      	lrw      	r3, 0x0	// a50 <lmac_set_cfg+0xa50>
 7d8:	3a40      	cmpnei      	r2, 0
 7da:	c4000501 	mvc      	r1
 7de:	d8430319 	ld.b      	r2, (r3, 0x319)
 7e2:	c4415c06 	ins      	r2, r1, 6, 6
 7e6:	dc430319 	st.b      	r2, (r3, 0x319)
 7ea:	e800fc1b 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 7ee:	03a6      	lrw      	r5, 0x0	// a50 <lmac_set_cfg+0xa50>
 7f0:	6c53      	mov      	r1, r4
 7f2:	3206      	movi      	r2, 6
 7f4:	e4050525 	addi      	r0, r5, 1318
 7f8:	e0000000 	bsr      	0x0	// 0 <memcpy>
 7fc:	d805052b 	ld.b      	r0, (r5, 0x52b)
 800:	d8650528 	ld.b      	r3, (r5, 0x528)
 804:	d8450527 	ld.b      	r2, (r5, 0x527)
 808:	d8250526 	ld.b      	r1, (r5, 0x526)
 80c:	b802      	st.w      	r0, (r14, 0x8)
 80e:	d805052a 	ld.b      	r0, (r5, 0x52a)
 812:	b801      	st.w      	r0, (r14, 0x4)
 814:	d8050529 	ld.b      	r0, (r5, 0x529)
 818:	b800      	st.w      	r0, (r14, 0x0)
 81a:	0310      	lrw      	r0, 0x0	// a54 <lmac_set_cfg+0xa54>
 81c:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 820:	e800fc00 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 824:	0354      	lrw      	r2, 0x0	// a50 <lmac_set_cfg+0xa50>
 826:	3c40      	cmpnei      	r4, 0
 828:	d862031a 	ld.b      	r3, (r2, 0x31a)
 82c:	c4000501 	mvc      	r1
 830:	c4615c00 	ins      	r3, r1, 0, 0
 834:	dc62031a 	st.b      	r3, (r2, 0x31a)
 838:	e4632001 	andi      	r3, r3, 1
 83c:	e903fbf2 	bez      	r3, 0x20	// 20 <lmac_set_cfg+0x20>
 840:	0319      	lrw      	r0, 0x0	// a58 <lmac_set_cfg+0xa58>
 842:	06a4      	br      	0x58a	// 58a <lmac_set_cfg+0x58a>
 844:	6c97      	mov      	r2, r5
 846:	6c53      	mov      	r1, r4
 848:	031a      	lrw      	r0, 0x0	// a5c <lmac_set_cfg+0xa5c>
 84a:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 84e:	037e      	lrw      	r3, 0x0	// a50 <lmac_set_cfg+0xa50>
 850:	d8432233 	ld.w      	r2, (r3, 0x8cc)
 854:	e902fe9a 	bez      	r2, 0x588	// 588 <lmac_set_cfg+0x588>
 858:	d8620259 	ld.b      	r3, (r2, 0x259)
 85c:	3d40      	cmpnei      	r5, 0
 85e:	c4645cc0 	ins      	r3, r4, 6, 0
 862:	c4000501 	mvc      	r1
 866:	c4615c07 	ins      	r3, r1, 7, 7
 86a:	dc620259 	st.b      	r3, (r2, 0x259)
 86e:	e800fbd9 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 872:	1378      	lrw      	r3, 0x0	// a50 <lmac_set_cfg+0xa50>
 874:	d9032233 	ld.w      	r8, (r3, 0x8cc)
 878:	e908ff6b 	bez      	r8, 0x74e	// 74e <lmac_set_cfg+0x74e>
 87c:	3500      	movi      	r5, 0
 87e:	32fa      	movi      	r2, 250
 880:	4242      	lsli      	r2, r2, 2
 882:	3300      	movi      	r3, 0
 884:	6c13      	mov      	r0, r4
 886:	6c57      	mov      	r1, r5
 888:	e0000000 	bsr      	0x0	// 0 <__muldi3>
 88c:	ea02eebb 	movi      	r2, 61115
 890:	c5a24902 	rotli      	r2, r2, 13
 894:	3314      	movi      	r3, 20
 896:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 89a:	1372      	lrw      	r3, 0x0	// a60 <lmac_set_cfg+0xa60>
 89c:	6f57      	mov      	r13, r5
 89e:	9360      	ld.w      	r3, (r3, 0x0)
 8a0:	6c97      	mov      	r2, r5
 8a2:	d9832005 	ld.w      	r12, (r3, 0x14)
 8a6:	9384      	ld.w      	r4, (r3, 0x10)
 8a8:	6cf3      	mov      	r3, r12
 8aa:	6f13      	mov      	r12, r4
 8ac:	6489      	cmplt      	r2, r2
 8ae:	60b1      	addc      	r2, r12
 8b0:	60f5      	addc      	r3, r13
 8b2:	dc4820b4 	st.w      	r2, (r8, 0x2d0)
 8b6:	dc6820b5 	st.w      	r3, (r8, 0x2d4)
 8ba:	dc4820b8 	st.w      	r2, (r8, 0x2e0)
 8be:	dc6820b9 	st.w      	r3, (r8, 0x2e4)
 8c2:	dc0820b6 	st.w      	r0, (r8, 0x2d8)
 8c6:	dc2820b7 	st.w      	r1, (r8, 0x2dc)
 8ca:	dc0820b2 	st.w      	r0, (r8, 0x2c8)
 8ce:	dc2820b3 	st.w      	r1, (r8, 0x2cc)
 8d2:	1345      	lrw      	r2, 0xd693a400	// a64 <lmac_set_cfg+0xa64>
 8d4:	3300      	movi      	r3, 0
 8d6:	6d83      	mov      	r6, r0
 8d8:	6dc7      	mov      	r7, r1
 8da:	e0000000 	bsr      	0x0	// 0 <__udivdi3>
 8de:	6d03      	mov      	r4, r0
 8e0:	6e07      	mov      	r8, r1
 8e2:	ea02f424 	movi      	r2, 62500
 8e6:	c4824902 	rotli      	r2, r2, 4
 8ea:	3300      	movi      	r3, 0
 8ec:	6c1b      	mov      	r0, r6
 8ee:	6c5f      	mov      	r1, r7
 8f0:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 8f4:	32fa      	movi      	r2, 250
 8f6:	4242      	lsli      	r2, r2, 2
 8f8:	3300      	movi      	r3, 0
 8fa:	e0000000 	bsr      	0x0	// 0 <__udivdi3>
 8fe:	b805      	st.w      	r0, (r14, 0x14)
 900:	b826      	st.w      	r1, (r14, 0x18)
 902:	ea02f424 	movi      	r2, 62500
 906:	c4824902 	rotli      	r2, r2, 4
 90a:	3300      	movi      	r3, 0
 90c:	6c1b      	mov      	r0, r6
 90e:	6c5f      	mov      	r1, r7
 910:	e0000000 	bsr      	0x0	// 0 <__udivdi3>
 914:	323c      	movi      	r2, 60
 916:	3300      	movi      	r3, 0
 918:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 91c:	b803      	st.w      	r0, (r14, 0xc)
 91e:	b824      	st.w      	r1, (r14, 0x10)
 920:	1252      	lrw      	r2, 0x3938700	// a68 <lmac_set_cfg+0xa68>
 922:	3300      	movi      	r3, 0
 924:	6c1b      	mov      	r0, r6
 926:	6c5f      	mov      	r1, r7
 928:	e0000000 	bsr      	0x0	// 0 <__udivdi3>
 92c:	323c      	movi      	r2, 60
 92e:	3300      	movi      	r3, 0
 930:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 934:	b801      	st.w      	r0, (r14, 0x4)
 936:	b822      	st.w      	r1, (r14, 0x8)
 938:	dd0e2000 	st.w      	r8, (r14, 0x0)
 93c:	6cd3      	mov      	r3, r4
 93e:	6c5b      	mov      	r1, r6
 940:	6c9f      	mov      	r2, r7
 942:	120b      	lrw      	r0, 0x0	// a6c <lmac_set_cfg+0xa6c>
 944:	e0000000 	bsr      	0x0	// 0 <hgprintf>
 948:	e800fb6c 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 94c:	1261      	lrw      	r3, 0x0	// a50 <lmac_set_cfg+0xa50>
 94e:	d8632233 	ld.w      	r3, (r3, 0x8cc)
 952:	e903fb67 	bez      	r3, 0x20	// 20 <lmac_set_cfg+0x20>
 956:	dc430a4d 	st.b      	r2, (r3, 0xa4d)
 95a:	dca320af 	st.w      	r5, (r3, 0x2bc)
 95e:	e800fb61 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 962:	117c      	lrw      	r3, 0x0	// a50 <lmac_set_cfg+0xa50>
 964:	d8632233 	ld.w      	r3, (r3, 0x8cc)
 968:	e903fb5c 	bez      	r3, 0x20	// 20 <lmac_set_cfg+0x20>
 96c:	d843025b 	ld.b      	r2, (r3, 0x25b)
 970:	c4445c26 	ins      	r2, r4, 7, 6
 974:	e800fda1 	br      	0x4b6	// 4b6 <lmac_set_cfg+0x4b6>
 978:	e902fb54 	bez      	r2, 0x20	// 20 <lmac_set_cfg+0x20>
 97c:	1175      	lrw      	r3, 0x0	// a50 <lmac_set_cfg+0xa50>
 97e:	dc4320f5 	st.w      	r2, (r3, 0x3d4)
 982:	e800fb4f 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 986:	6c57      	mov      	r1, r5
 988:	e0000000 	bsr      	0x0	// 0 <lmac_set_cfg>
 98c:	e800fb4a 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 990:	6c97      	mov      	r2, r5
 992:	7450      	zextb      	r1, r4
 994:	e0000000 	bsr      	0x0	// 0 <lmac_set_cfg>
 998:	e800fb44 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 99c:	6c57      	mov      	r1, r5
 99e:	e0000000 	bsr      	0x0	// 0 <lmac_set_cfg>
 9a2:	e800fb3f 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 9a6:	114b      	lrw      	r2, 0x0	// a50 <lmac_set_cfg+0xa50>
 9a8:	3c40      	cmpnei      	r4, 0
 9aa:	c4000501 	mvc      	r1
 9ae:	d86203df 	ld.b      	r3, (r2, 0x3df)
 9b2:	c4615c03 	ins      	r3, r1, 3, 3
 9b6:	e4232008 	andi      	r1, r3, 8
 9ba:	dc6203df 	st.b      	r3, (r2, 0x3df)
 9be:	d8620361 	ld.b      	r3, (r2, 0x361)
 9c2:	e901000f 	bez      	r1, 0x9e0	// 9e0 <lmac_set_cfg+0x9e0>
 9c6:	3100      	movi      	r1, 0
 9c8:	c4615c02 	ins      	r3, r1, 2, 2
 9cc:	dc620361 	st.b      	r3, (r2, 0x361)
 9d0:	3002      	movi      	r0, 2
 9d2:	e0000000 	bsr      	0x0	// 0 <lmac_spec_cca_cfg>
 9d6:	3002      	movi      	r0, 2
 9d8:	e0000000 	bsr      	0x0	// 0 <lmac_spec_cca_cfg>
 9dc:	e800fb22 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 9e0:	3101      	movi      	r1, 1
 9e2:	c4615c02 	ins      	r3, r1, 2, 2
 9e6:	dc620361 	st.b      	r3, (r2, 0x361)
 9ea:	d802431e 	ld.bs      	r0, (r2, 0x31e)
 9ee:	e0000000 	bsr      	0x0	// 0 <lmac_adjust_cca_threshold>
 9f2:	07f2      	br      	0x9d6	// 9d6 <lmac_set_cfg+0x9d6>
 9f4:	1077      	lrw      	r3, 0x0	// a50 <lmac_set_cfg+0xa50>
 9f6:	dc4303e0 	st.b      	r2, (r3, 0x3e0)
 9fa:	e800fb13 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 9fe:	1075      	lrw      	r3, 0x0	// a50 <lmac_set_cfg+0xa50>
 a00:	3a40      	cmpnei      	r2, 0
 a02:	c4000501 	mvc      	r1
 a06:	d8430310 	ld.b      	r2, (r3, 0x310)
 a0a:	c4415c01 	ins      	r2, r1, 1, 1
 a0e:	e800fbe7 	br      	0x1dc	// 1dc <lmac_set_cfg+0x1dc>
 a12:	1070      	lrw      	r3, 0x0	// a50 <lmac_set_cfg+0xa50>
 a14:	dc430300 	st.b      	r2, (r3, 0x300)
 a18:	e800fb04 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 a1c:	106d      	lrw      	r3, 0x0	// a50 <lmac_set_cfg+0xa50>
 a1e:	dc4303e1 	st.b      	r2, (r3, 0x3e1)
 a22:	e800faff 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 a26:	6c4b      	mov      	r1, r2
 a28:	e0000000 	bsr      	0x0	// 0 <lmac_set_cfg>
 a2c:	e800fafa 	br      	0x20	// 20 <lmac_set_cfg+0x20>
 a30:	1068      	lrw      	r3, 0x0	// a50 <lmac_set_cfg+0xa50>
 a32:	3a40      	cmpnei      	r2, 0
 a34:	c4000501 	mvc      	r1
 a38:	d84303e2 	ld.b      	r2, (r3, 0x3e2)
 a3c:	c4415c03 	ins      	r2, r1, 3, 3
 a40:	dc4303e2 	st.b      	r2, (r3, 0x3e2)
 a44:	e800faee 	br      	0x20	// 20 <lmac_set_cfg+0x20>
	...
 a64:	d693a400 	.long	0xd693a400
 a68:	03938700 	.long	0x03938700
 a6c:	00000000 	.long	0x00000000

Disassembly of section .text.lmac_get_cfg:

00000000 <lmac_get_cfg>:
   0:	14d1      	push      	r4, r15
   2:	6d0f      	mov      	r4, r3
   4:	33e0      	movi      	r3, 224
   6:	4378      	lsli      	r3, r3, 24
   8:	604c      	addu      	r1, r3
   a:	eb010025 	cmphsi      	r1, 38
   e:	6c0b      	mov      	r0, r2
  10:	0860      	bt      	0xd0	// d0 <lmac_get_cfg+0xd0>
  12:	1063      	lrw      	r3, 0x0	// 1c <lmac_get_cfg+0x1c>
  14:	d0230883 	ldr.w      	r3, (r3, r1 << 2)
  18:	780c      	jmp      	r3
  1a:	0000      	.short	0x0000
  1c:	00000000 	.long	0x00000000
  20:	1369      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  22:	d8830315 	ld.b      	r4, (r3, 0x315)
  26:	6c13      	mov      	r0, r4
  28:	1491      	pop      	r4, r15
  2a:	1367      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  2c:	d8830308 	ld.b      	r4, (r3, 0x308)
  30:	07fb      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  32:	1365      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  34:	d8830867 	ld.b      	r4, (r3, 0x867)
  38:	07f7      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  3a:	1363      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  3c:	d8830866 	ld.b      	r4, (r3, 0x866)
  40:	07f3      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  42:	1361      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  44:	d8831197 	ld.h      	r4, (r3, 0x32e)
  48:	07ef      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  4a:	129f      	lrw      	r4, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  4c:	d80411b6 	ld.h      	r0, (r4, 0x36c)
  50:	c4a05520 	zext      	r0, r0, 9, 5
  54:	e0000000 	bsr      	0x0	// 0 <ah_rfdigicali_get_tx_digi_gain>
  58:	d884468e 	ld.bs      	r4, (r4, 0x68e)
  5c:	6c53      	mov      	r1, r4
  5e:	121b      	lrw      	r0, 0x0	// 1c8 <lmac_get_cfg+0x1c8>
  60:	e0000000 	bsr      	0x0	// 0 <hgprintf>
  64:	07e1      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  66:	1278      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  68:	d883133b 	ld.h      	r4, (r3, 0x676)
  6c:	07dd      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  6e:	1276      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  70:	d8830310 	ld.b      	r4, (r3, 0x310)
  74:	c4645464 	zext      	r4, r4, 3, 3
  78:	07d7      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  7a:	1273      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  7c:	d88320ce 	ld.w      	r4, (r3, 0x338)
  80:	c4845764 	zext      	r4, r4, 27, 4
  84:	07d1      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  86:	1270      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  88:	d8834898 	ld.bs      	r4, (r3, 0x898)
  8c:	07cd      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  8e:	126e      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  90:	d8834899 	ld.bs      	r4, (r3, 0x899)
  94:	07c9      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  96:	126c      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  98:	d883489a 	ld.bs      	r4, (r3, 0x89a)
  9c:	07c5      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  9e:	126a      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  a0:	d8831198 	ld.h      	r4, (r3, 0x330)
  a4:	07c1      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  a6:	1268      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  a8:	d8830309 	ld.b      	r4, (r3, 0x309)
  ac:	07bd      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  ae:	1288      	lrw      	r4, 0x0	// 1cc <lmac_get_cfg+0x1cc>
  b0:	07bb      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  b2:	1288      	lrw      	r4, 0x0	// 1d0 <lmac_get_cfg+0x1d0>
  b4:	07b9      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  b6:	1264      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  b8:	d8832196 	ld.w      	r4, (r3, 0x658)
  bc:	07b5      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  be:	1262      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  c0:	d8830556 	ld.b      	r4, (r3, 0x556)
  c4:	07b1      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  c6:	1260      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  c8:	d8832233 	ld.w      	r4, (r3, 0x8cc)
  cc:	e9240004 	bnez      	r4, 0xd4	// d4 <lmac_get_cfg+0xd4>
  d0:	3400      	movi      	r4, 0
  d2:	07aa      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  d4:	e4840a6b 	addi      	r4, r4, 2668
  d8:	07a7      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  da:	117b      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  dc:	d8632233 	ld.w      	r3, (r3, 0x8cc)
  e0:	e903fff8 	bez      	r3, 0xd0	// d0 <lmac_get_cfg+0xd0>
  e4:	3480      	movi      	r4, 128
  e6:	4482      	lsli      	r4, r4, 2
  e8:	079f      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  ea:	1177      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
  ec:	d8830875 	ld.b      	r4, (r3, 0x875)
  f0:	c4845484 	zext      	r4, r4, 4, 4
  f4:	0799      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  f6:	e0000000 	bsr      	0x0	// 0 <lmac_get_cfg>
  fa:	6d03      	mov      	r4, r0
  fc:	0795      	br      	0x26	// 26 <lmac_get_cfg+0x26>
  fe:	1172      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
 100:	d8232233 	ld.w      	r1, (r3, 0x8cc)
 104:	e901ffe6 	bez      	r1, 0xd0	// d0 <lmac_get_cfg+0xd0>
 108:	ea02eebb 	movi      	r2, 61115
 10c:	c5a24902 	rotli      	r2, r2, 13
 110:	3314      	movi      	r3, 20
 112:	d80120b2 	ld.w      	r0, (r1, 0x2c8)
 116:	d82120b3 	ld.w      	r1, (r1, 0x2cc)
 11a:	e0000000 	bsr      	0x0	// 0 <__umoddi3>
 11e:	32fa      	movi      	r2, 250
 120:	4242      	lsli      	r2, r2, 2
 122:	3300      	movi      	r3, 0
 124:	e0000000 	bsr      	0x0	// 0 <__udivdi3>
 128:	6d03      	mov      	r4, r0
 12a:	6c43      	mov      	r1, r0
 12c:	110a      	lrw      	r0, 0x0	// 1d4 <lmac_get_cfg+0x1d4>
 12e:	0799      	br      	0x60	// 60 <lmac_get_cfg+0x60>
 130:	1165      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
 132:	d88320f5 	ld.w      	r4, (r3, 0x3d4)
 136:	0778      	br      	0x26	// 26 <lmac_get_cfg+0x26>
 138:	3100      	movi      	r1, 0
 13a:	7409      	zexth      	r0, r2
 13c:	e0000000 	bsr      	0x0	// 0 <lmac_sta_get>
 140:	e900ffc8 	bez      	r0, 0xd0	// d0 <lmac_get_cfg+0xd0>
 144:	d86000b4 	ld.b      	r3, (r0, 0xb4)
 148:	103f      	lrw      	r1, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
 14a:	3200      	movi      	r2, 0
 14c:	a460      	st.b      	r3, (r4, 0x0)
 14e:	2a54      	subi      	r2, 85
 150:	d861431e 	ld.bs      	r3, (r1, 0x31e)
 154:	648d      	cmplt      	r3, r2
 156:	d84000b8 	ld.b      	r2, (r0, 0xb8)
 15a:	0803      	bt      	0x160	// 160 <lmac_get_cfg+0x160>
 15c:	608e      	subu      	r2, r3
 15e:	0409      	br      	0x170	// 170 <lmac_get_cfg+0x170>
 160:	d821431d 	ld.bs      	r1, (r1, 0x31d)
 164:	748a      	sextb      	r2, r2
 166:	e5811054 	subi      	r12, r1, 85
 16a:	6709      	cmplt      	r2, r12
 16c:	0804      	bt      	0x174	// 174 <lmac_get_cfg+0x174>
 16e:	2254      	addi      	r2, 85
 170:	a441      	st.b      	r2, (r4, 0x1)
 172:	0406      	br      	0x17e	// 17e <lmac_get_cfg+0x17e>
 174:	c423002c 	addu      	r12, r3, r1
 178:	6709      	cmplt      	r2, r12
 17a:	0bf1      	bt      	0x15c	// 15c <lmac_get_cfg+0x15c>
 17c:	a421      	st.b      	r1, (r4, 0x1)
 17e:	e0000000 	bsr      	0x0	// 0 <lmac_sta_put>
 182:	07a7      	br      	0xd0	// d0 <lmac_get_cfg+0xd0>
 184:	3a0f      	cmphsi      	r2, 16
 186:	0ba5      	bt      	0xd0	// d0 <lmac_get_cfg+0xd0>
 188:	3218      	movi      	r2, 24
 18a:	106f      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
 18c:	7c08      	mult      	r0, r2
 18e:	600c      	addu      	r0, r3
 190:	d82303e0 	ld.b      	r1, (r3, 0x3e0)
 194:	d84000c6 	ld.b      	r2, (r0, 0xc6)
 198:	6084      	addu      	r2, r1
 19a:	a440      	st.b      	r2, (r4, 0x0)
 19c:	d82303e0 	ld.b      	r1, (r3, 0x3e0)
 1a0:	d84000c5 	ld.b      	r2, (r0, 0xc5)
 1a4:	6084      	addu      	r2, r1
 1a6:	a441      	st.b      	r2, (r4, 0x1)
 1a8:	d84000c7 	ld.b      	r2, (r0, 0xc7)
 1ac:	d86303e0 	ld.b      	r3, (r3, 0x3e0)
 1b0:	60c8      	addu      	r3, r2
 1b2:	a462      	st.b      	r3, (r4, 0x2)
 1b4:	078e      	br      	0xd0	// d0 <lmac_get_cfg+0xd0>
 1b6:	1064      	lrw      	r3, 0x0	// 1c4 <lmac_get_cfg+0x1c4>
 1b8:	d8234378 	ld.bs      	r1, (r3, 0x378)
 1bc:	e0000000 	bsr      	0x0	// 0 <lmac_get_cfg>
 1c0:	079d      	br      	0xfa	// fa <lmac_get_cfg+0xfa>
	...

Disassembly of section .text.dsleep_cfg_init:

00000000 <dsleep_cfg_init>:
   0:	14d8      	push      	r4-r11, r15
   2:	137b      	lrw      	r3, 0x0	// 1ec <dsleep_cfg_init+0x1ec>
   4:	d8400a4e 	ld.b      	r2, (r0, 0xa4e)
   8:	d8231198 	ld.h      	r1, (r3, 0x330)
   c:	dc2014e2 	st.h      	r1, (r0, 0x9c4)
  10:	d8230556 	ld.b      	r1, (r3, 0x556)
  14:	dc2009c6 	st.b      	r1, (r0, 0x9c6)
  18:	d8c320ce 	ld.w      	r6, (r3, 0x338)
  1c:	d8232196 	ld.w      	r1, (r3, 0x658)
  20:	c4865767 	zext      	r7, r6, 27, 4
  24:	d9030308 	ld.b      	r8, (r3, 0x308)
  28:	d8c30309 	ld.b      	r6, (r3, 0x309)
  2c:	dc20227f 	st.w      	r1, (r0, 0x9fc)
  30:	dd0009c7 	st.b      	r8, (r0, 0x9c7)
  34:	d823133b 	ld.h      	r1, (r3, 0x676)
  38:	dcc009c3 	st.b      	r6, (r0, 0x9c3)
  3c:	dc201504 	st.h      	r1, (r0, 0xa08)
  40:	e44220fc 	andi      	r2, r2, 252
  44:	d823034a 	ld.b      	r1, (r3, 0x34a)
  48:	c4415c06 	ins      	r2, r1, 6, 6
  4c:	dc400a4e 	st.b      	r2, (r0, 0xa4e)
  50:	d843031e 	ld.b      	r2, (r3, 0x31e)
  54:	dc400a52 	st.b      	r2, (r0, 0xa52)
  58:	d8430840 	ld.b      	r2, (r3, 0x840)
  5c:	3a05      	cmphsi      	r2, 6
  5e:	d963001f 	ld.b      	r11, (r3, 0x1f)
  62:	d943002e 	ld.b      	r10, (r3, 0x2e)
  66:	d923003e 	ld.b      	r9, (r3, 0x3e)
  6a:	6d03      	mov      	r4, r0
  6c:	dce02281 	st.w      	r7, (r0, 0xa04)
  70:	dd6009c0 	st.b      	r11, (r0, 0x9c0)
  74:	dd4009c1 	st.b      	r10, (r0, 0x9c1)
  78:	dd2009c2 	st.b      	r9, (r0, 0x9c2)
  7c:	6d4f      	mov      	r5, r3
  7e:	0807      	bt      	0x8c	// 8c <dsleep_cfg_init+0x8c>
  80:	d8600a51 	ld.b      	r3, (r0, 0xa51)
  84:	c4625c40 	ins      	r3, r2, 2, 0
  88:	dc600a51 	st.b      	r3, (r0, 0xa51)
  8c:	d8450875 	ld.b      	r2, (r5, 0x875)
  90:	d8640a4e 	ld.b      	r3, (r4, 0xa4e)
  94:	c4425442 	zext      	r2, r2, 2, 2
  98:	c4625c02 	ins      	r3, r2, 2, 2
  9c:	d8450875 	ld.b      	r2, (r5, 0x875)
  a0:	c4825482 	zext      	r2, r2, 4, 4
  a4:	d8250876 	ld.b      	r1, (r5, 0x876)
  a8:	c4625c03 	ins      	r3, r2, 3, 3
  ac:	d8440a4f 	ld.b      	r2, (r4, 0xa4f)
  b0:	c4415cc0 	ins      	r2, r1, 6, 0
  b4:	dc440a4f 	st.b      	r2, (r4, 0xa4f)
  b8:	d8450876 	ld.b      	r2, (r5, 0x876)
  bc:	d8240a4f 	ld.b      	r1, (r4, 0xa4f)
  c0:	c4e254e2 	zext      	r2, r2, 7, 7
  c4:	c4225c07 	ins      	r1, r2, 7, 7
  c8:	dc240a4f 	st.b      	r1, (r4, 0xa4f)
  cc:	d8250877 	ld.b      	r1, (r5, 0x877)
  d0:	d8440a50 	ld.b      	r2, (r4, 0xa50)
  d4:	c4415cc0 	ins      	r2, r1, 6, 0
  d8:	dc440a50 	st.b      	r2, (r4, 0xa50)
  dc:	d8450877 	ld.b      	r2, (r5, 0x877)
  e0:	d8240a50 	ld.b      	r1, (r4, 0xa50)
  e4:	c4e254e2 	zext      	r2, r2, 7, 7
  e8:	c4225c07 	ins      	r1, r2, 7, 7
  ec:	dc240a50 	st.b      	r1, (r4, 0xa50)
  f0:	d84508e0 	ld.b      	r2, (r5, 0x8e0)
  f4:	c4625c24 	ins      	r3, r2, 5, 4
  f8:	dc640a4e 	st.b      	r3, (r4, 0xa4e)
  fc:	d8652154 	ld.w      	r3, (r5, 0x550)
 100:	dc642272 	st.w      	r3, (r4, 0x9c8)
 104:	d86520f5 	ld.w      	r3, (r5, 0x3d4)
 108:	dc642297 	st.w      	r3, (r4, 0xa5c)
 10c:	3206      	movi      	r2, 6
 10e:	1139      	lrw      	r1, 0x0	// 1f0 <dsleep_cfg_init+0x1f0>
 110:	e40409ef 	addi      	r0, r4, 2544
 114:	e0000000 	bsr      	0x0	// 0 <memcpy>
 118:	3224      	movi      	r2, 36
 11a:	1137      	lrw      	r1, 0x0	// 1f4 <dsleep_cfg_init+0x1f4>
 11c:	e40409cb 	addi      	r0, r4, 2508
 120:	e0000000 	bsr      	0x0	// 0 <memcpy>
 124:	3206      	movi      	r2, 6
 126:	1135      	lrw      	r1, 0x0	// 1f8 <dsleep_cfg_init+0x1f8>
 128:	e40409f5 	addi      	r0, r4, 2550
 12c:	e0000000 	bsr      	0x0	// 0 <memcpy>
 130:	d9850378 	ld.b      	r12, (r5, 0x378)
 134:	3200      	movi      	r2, 0
 136:	dd840a4c 	st.b      	r12, (r4, 0xa4c)
 13a:	6ccb      	mov      	r3, r2
 13c:	670d      	cmplt      	r3, r12
 13e:	2217      	addi      	r2, 24
 140:	082d      	bt      	0x19a	// 19a <dsleep_cfg_init+0x19a>
 142:	e92b0005 	bnez      	r11, 0x14c	// 14c <dsleep_cfg_init+0x14c>
 146:	3302      	movi      	r3, 2
 148:	dc6409c0 	st.b      	r3, (r4, 0x9c0)
 14c:	e92a0005 	bnez      	r10, 0x156	// 156 <dsleep_cfg_init+0x156>
 150:	330f      	movi      	r3, 15
 152:	dc6409c1 	st.b      	r3, (r4, 0x9c1)
 156:	e9290005 	bnez      	r9, 0x160	// 160 <dsleep_cfg_init+0x160>
 15a:	331f      	movi      	r3, 31
 15c:	dc6409c2 	st.b      	r3, (r4, 0x9c2)
 160:	eb480001 	cmpnei      	r8, 1
 164:	dce42280 	st.w      	r7, (r4, 0xa00)
 168:	0c2e      	bf      	0x1c4	// 1c4 <dsleep_cfg_init+0x1c4>
 16a:	eb480000 	cmpnei      	r8, 0
 16e:	0c3c      	bf      	0x1e6	// 1e6 <dsleep_cfg_init+0x1e6>
 170:	eb480002 	cmpnei      	r8, 2
 174:	0c1d      	bf      	0x1ae	// 1ae <dsleep_cfg_init+0x1ae>
 176:	eb480003 	cmpnei      	r8, 3
 17a:	080e      	bt      	0x196	// 196 <dsleep_cfg_init+0x196>
 17c:	e4c62007 	andi      	r6, r6, 7
 180:	33fa      	movi      	r3, 250
 182:	dcc409c3 	st.b      	r6, (r4, 0x9c3)
 186:	4363      	lsli      	r3, r3, 3
 188:	4ec1      	lsri      	r6, r6, 1
 18a:	7d8c      	mult      	r6, r3
 18c:	e4e71bb7 	subi      	r7, r7, 3000
 190:	619c      	addu      	r6, r7
 192:	dcc42280 	st.w      	r6, (r4, 0xa00)
 196:	3000      	movi      	r0, 0
 198:	1498      	pop      	r4-r11, r15
 19a:	1015      	lrw      	r0, 0x0	// 1ec <dsleep_cfg_init+0x1ec>
 19c:	4322      	lsli      	r1, r3, 2
 19e:	6008      	addu      	r0, r2
 1a0:	6050      	addu      	r1, r4
 1a2:	d800202a 	ld.w      	r0, (r0, 0xa8)
 1a6:	dc012283 	st.w      	r0, (r1, 0xa0c)
 1aa:	2300      	addi      	r3, 1
 1ac:	07c8      	br      	0x13c	// 13c <dsleep_cfg_init+0x13c>
 1ae:	e4c62003 	andi      	r6, r6, 3
 1b2:	33fa      	movi      	r3, 250
 1b4:	dcc409c3 	st.b      	r6, (r4, 0x9c3)
 1b8:	4363      	lsli      	r3, r3, 3
 1ba:	4ec1      	lsri      	r6, r6, 1
 1bc:	7d8c      	mult      	r6, r3
 1be:	e4e713e7 	subi      	r7, r7, 1000
 1c2:	07e7      	br      	0x190	// 190 <dsleep_cfg_init+0x190>
 1c4:	d8640a4e 	ld.b      	r3, (r4, 0xa4e)
 1c8:	e4632040 	andi      	r3, r3, 64
 1cc:	e9030008 	bez      	r3, 0x1dc	// 1dc <dsleep_cfg_init+0x1dc>
 1d0:	3300      	movi      	r3, 0
 1d2:	dc6409c3 	st.b      	r3, (r4, 0x9c3)
 1d6:	e4c701f3 	addi      	r6, r7, 500
 1da:	07dc      	br      	0x192	// 192 <dsleep_cfg_init+0x192>
 1dc:	e4c62001 	andi      	r6, r6, 1
 1e0:	dcc409c3 	st.b      	r6, (r4, 0x9c3)
 1e4:	07d9      	br      	0x196	// 196 <dsleep_cfg_init+0x196>
 1e6:	dd0409c3 	st.b      	r8, (r4, 0x9c3)
 1ea:	07d6      	br      	0x196	// 196 <ah_lmac+0x196>
	...

Disassembly of section .text.lmac_ah_ioctl:

00000000 <lmac_ah_ioctl>:
   0:	14d0      	push      	r15
   2:	e901000c 	bez      	r1, 0x1a	// 1a <lmac_ah_ioctl+0x1a>
   6:	c700502d 	bmaski      	r13, 25
   a:	6474      	cmphs      	r13, r1
   c:	0c04      	bf      	0x14	// 14 <lmac_ah_ioctl+0x14>
   e:	e0000000 	bsr      	0x0	// 0 <lmac_ah_ioctl>
  12:	1490      	pop      	r15
  14:	e0000000 	bsr      	0x0	// 0 <lmac_ah_ioctl>
  18:	07fd      	br      	0x12	// 12 <lmac_ah_ioctl+0x12>
  1a:	3000      	movi      	r0, 0
  1c:	2815      	subi      	r0, 22
  1e:	07fa      	br      	0x12	// 12 <lmac_ah_ioctl+0x12>
