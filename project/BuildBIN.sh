csky-elfabiv2-objcopy -O binary ./Obj/RNode-Halow.elf ./RNode-Halow.bin
python  ../pack/prepare_firmware.py ./RNode-Halow.bin