CC = gcc

CFLAGS = -Wall -Wextra -Wno-unused-parameter \
    -Istubs \
    -I../../inc \
    -I../../sdk/include

BUILD_DIR = build
QBUILD = build_q

TARGET = $(BUILD_DIR)/test_ack.exe
SIZE_TARGET = $(BUILD_DIR)/test_size.exe

# real TCP->RF->TCP chain compiled into the test binary
RNS_SRC = ../../src/halow_pkg_handler.c \
          ../../src/rns/stream_parser.c \
          ../../src/rns/link_parser.c \
          ../../src/rns/link_utils.c \
          ../../src/rns/link_db.c \
          ../../sdk/lib/crypto/sha256.c

RNS_OBJS = $(addprefix $(BUILD_DIR)/,$(notdir $(RNS_SRC:.c=.o)))
QRNS_OBJS = $(addprefix $(QBUILD)/,$(notdir $(RNS_SRC:.c=.o)))

all: clean run

run: $(TARGET) $(SIZE_TARGET)
	./$(TARGET)
	./$(SIZE_TARGET)

$(TARGET): $(BUILD_DIR)/main.o $(BUILD_DIR)/harness.o $(BUILD_DIR)/halow_ack.o $(RNS_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(BUILD_DIR)/main.o $(BUILD_DIR)/harness.o $(BUILD_DIR)/halow_ack.o $(RNS_OBJS) -o $(TARGET)

$(SIZE_TARGET): $(BUILD_DIR)/size_test.o $(BUILD_DIR)/harness.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(BUILD_DIR)/size_test.o $(BUILD_DIR)/harness.o -o $(SIZE_TARGET)

$(BUILD_DIR)/main.o: main.c harness.h stubs/basic_include.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/size_test.o: size_test.c harness.h stubs/basic_include.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/harness.o: harness.c harness.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/halow_ack.o: ../../src/halow_ack.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/halow_pkg_handler.o: ../../src/halow_pkg_handler.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/stream_parser.o: ../../src/rns/stream_parser.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/link_parser.o: ../../src/rns/link_parser.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/link_utils.o: ../../src/rns/link_utils.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/link_db.o: ../../src/rns/link_db.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/sha256.o: ../../sdk/lib/crypto/sha256.c
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR) $(QBUILD)

.PHONY: all run clean qemu

# ---- ck803-in-QEMU run (T-Head cskysim, board: smartl_803) ----
CROSS    = /c/toolchain-scky/bin/csky-elfabiv2-gcc
QEMU_DIR = /d/C-Sky/CDKRepo/Simulator/xt-cskysim/V5.2.8/R
SOCCFG   = $(QEMU_DIR)/soccfg/cskyv2/smartl_803_cfg.xml
QFLAGS   = -mcpu=ck803 -std=c11 -O1 -g -Wall -Wno-unused-parameter \
           -fsigned-char -mno-required-printf -ffunction-sections -fdata-sections \
           -Istubs -I../../inc -I../../sdk/include

qemu: clean $(QBUILD)/test_ack.elf $(QBUILD)/test_size.elf
	PATH="$(QEMU_DIR):$$PATH" timeout 600 $(QEMU_DIR)/cskysim.exe \
	    -soc $(SOCCFG) -kernel $(QBUILD)/test_size.elf -nographic
	PATH="$(QEMU_DIR):$$PATH" timeout 900 $(QEMU_DIR)/cskysim.exe \
	    -soc $(SOCCFG) -kernel $(QBUILD)/test_ack.elf -nographic | tee $(QBUILD)/run.log
	@grep -q "0 failed" $(QBUILD)/run.log && echo "QEMU: ALL GREEN" || (echo "QEMU: FAILURES"; exit 1)

$(QBUILD)/main.o: main.c harness.h stubs/basic_include.h
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/size_test.o: size_test.c harness.h stubs/basic_include.h
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/harness.o: harness.c harness.h
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/halow_ack.o: ../../src/halow_ack.c
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/halow_pkg_handler.o: ../../src/halow_pkg_handler.c
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/stream_parser.o: ../../src/rns/stream_parser.c
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/link_parser.o: ../../src/rns/link_parser.c
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/link_utils.o: ../../src/rns/link_utils.c
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/link_db.o: ../../src/rns/link_db.c
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/sha256.o: ../../sdk/lib/crypto/sha256.c
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/support.o: qemu/support.c
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/startup.o: qemu/startup.s
	@mkdir -p $(QBUILD)
	$(CROSS) -mcpu=ck803 -c $< -o $@

$(QBUILD)/test_ack.elf: $(QBUILD)/startup.o $(QBUILD)/support.o $(QBUILD)/main.o $(QBUILD)/harness.o $(QBUILD)/halow_ack.o $(QRNS_OBJS)
	$(CROSS) -mcpu=ck803 -nostdlib -nostartfiles -T qemu/test.ld -Wl,--gc-sections \
	    -o $@ $^ -lgcc

$(QBUILD)/test_size.elf: $(QBUILD)/startup.o $(QBUILD)/support.o $(QBUILD)/size_test.o $(QBUILD)/harness.o
	$(CROSS) -mcpu=ck803 -nostdlib -nostartfiles -T qemu/test.ld -Wl,--gc-sections \
	    -o $@ $^ -lgcc

$(QBUILD)/bench.o: bench.c harness.h stubs/basic_include.h
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/bench.elf: $(QBUILD)/startup.o $(QBUILD)/support.o $(QBUILD)/bench.o $(QBUILD)/harness.o $(QBUILD)/halow_ack.o
	$(CROSS) -mcpu=ck803 -nostdlib -nostartfiles -T qemu/test.ld -Wl,--gc-sections \
	    -o $@ $^ -lgcc

qemu-bench: clean $(QBUILD)/bench.elf
	PATH="$(QEMU_DIR):$$PATH" timeout 600 $(QEMU_DIR)/cskysim.exe \
	    -soc $(SOCCFG) -kernel $(QBUILD)/bench.elf -nographic

.PHONY: qemu-bench
