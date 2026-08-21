CC = gcc

CFLAGS = -Wall -Wextra -Wno-unused-parameter \
    -I. -Istubs \
    -I../../inc \
    -I../../sdk/include \
    $(EXTRA_CFLAGS)

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

# scenario files, one per module under test; order lives in main.c registry
TEST_SRC = suite/test_ack_core.c \
           suite/test_ack_soak.c \
           suite/test_ack_edge.c \
           suite/test_pipeline.c \
           suite/test_ack_covfill.c \
           suite/test_rns_guards.c \
           suite/test_legacy_compat.c \
           suite/test_link_db.c

TEST_OBJS  = $(addprefix $(BUILD_DIR)/,$(TEST_SRC:.c=.o))
QTEST_OBJS = $(addprefix $(QBUILD)/,$(TEST_SRC:.c=.o))

all: clean run

run: $(TARGET) $(SIZE_TARGET)
	./$(TARGET)
	./$(SIZE_TARGET)

$(TARGET): $(BUILD_DIR)/main.o $(BUILD_DIR)/harness.o $(BUILD_DIR)/test_fw.o $(BUILD_DIR)/helpers.o $(BUILD_DIR)/halow_ack.o $(RNS_OBJS) $(TEST_OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(EXTRA_CFLAGS) $(BUILD_DIR)/main.o $(BUILD_DIR)/harness.o $(BUILD_DIR)/test_fw.o $(BUILD_DIR)/helpers.o $(BUILD_DIR)/halow_ack.o $(RNS_OBJS) $(TEST_OBJS) -o $(TARGET)

$(SIZE_TARGET): $(BUILD_DIR)/size_test.o $(BUILD_DIR)/harness.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(EXTRA_CFLAGS) $(BUILD_DIR)/size_test.o $(BUILD_DIR)/harness.o -o $(SIZE_TARGET)

$(BUILD_DIR)/main.o: main.c harness.h stubs/basic_include.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/size_test.o: size_test.c harness.h stubs/basic_include.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/harness.o: harness.c harness.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/test_fw.o: test_fw.c test_fw.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/helpers.o: helpers.c helpers.h test_fw.h
	@mkdir -p $(BUILD_DIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/suite/%.o: suite/%.c test_fw.h helpers.h harness.h stubs/basic_include.h
	@mkdir -p $(BUILD_DIR)/suite
	$(CC) $(CFLAGS) -c $< -o $@

$(QBUILD)/suite/%.o: suite/%.c test_fw.h helpers.h harness.h stubs/basic_include.h
	@mkdir -p $(QBUILD)/suite
	$(CROSS) $(QFLAGS) -c $< -o $@

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
	rm -rf $(BUILD_DIR) $(QBUILD) build_cov

.PHONY: all run clean qemu

# ---- ck803-in-QEMU run (T-Head cskysim, board: smartl_803) ----
# Medium (QEMU) tier toolchain: machine-specific, override via environment
# (e.g. CROSS=... QEMU_DIR=... mingw32-make qemu). Host (Small) tier above
# only needs gcc + make on PATH - see run_small.py.
CROSS    ?= /c/toolchain-scky/bin/csky-elfabiv2-gcc
QEMU_DIR ?= /d/C-Sky/CDKRepo/Simulator/xt-cskysim/V5.2.8/R
SOCCFG   ?= $(QEMU_DIR)/soccfg/cskyv2/smartl_803_cfg.xml
QFLAGS   = -mcpu=ck803 -std=c11 -O2 -g -Wall -Wno-unused-parameter \
           -fsigned-char -mno-required-printf -ffunction-sections -fdata-sections \
           -I. -Istubs -I../../inc -I../../sdk/include
# production memcpy/memset from the toolchain libc (word path when both
# pointers are 4-aligned, byte loop otherwise) - see qemu/support.c
LIBC_MEM_OBJS = qemu/memcpy_fast.o qemu/memset_fast.o

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

$(QBUILD)/test_fw.o: test_fw.c test_fw.h
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/helpers.o: helpers.c helpers.h test_fw.h
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
	$(CROSS) $(QFLAGS) -DUSE_LIBC_MEMCPY -c $< -o $@

$(QBUILD)/startup.o: qemu/startup.s
	@mkdir -p $(QBUILD)
	$(CROSS) -mcpu=ck803 -c $< -o $@

$(QBUILD)/test_ack.elf: $(QBUILD)/startup.o $(QBUILD)/support.o $(LIBC_MEM_OBJS) $(QBUILD)/main.o $(QBUILD)/harness.o $(QBUILD)/test_fw.o $(QBUILD)/helpers.o $(QBUILD)/halow_ack.o $(QRNS_OBJS) $(QTEST_OBJS)
	$(CROSS) -mcpu=ck803 -nostdlib -nostartfiles -T qemu/test.ld -Wl,--gc-sections \
	    -o $@ $^ -lgcc

$(QBUILD)/test_size.elf: $(QBUILD)/startup.o $(QBUILD)/support.o $(LIBC_MEM_OBJS) $(QBUILD)/size_test.o $(QBUILD)/harness.o
	$(CROSS) -mcpu=ck803 -nostdlib -nostartfiles -T qemu/test.ld -Wl,--gc-sections \
	    -o $@ $^ -lgcc

$(QBUILD)/bench.o: bench.c harness.h stubs/basic_include.h
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/bench.elf: $(QBUILD)/startup.o $(QBUILD)/support.o $(LIBC_MEM_OBJS) $(QBUILD)/bench.o $(QBUILD)/harness.o $(QBUILD)/halow_ack.o $(QRNS_OBJS)
	$(CROSS) -mcpu=ck803 -nostdlib -nostartfiles -T qemu/test.ld -Wl,--gc-sections \
	    -Wl,--wrap=memcpy \
	    -o $@ $^ -lgcc

# per-stage wall timing: the runner timestamps every UART line.
# -icount: virtual time is instruction-locked -> the in-bench APB-timer
# ticks (tks: lines) are exact instruction counts (1 tick = 1 instruction).
qemu-bench: clean $(QBUILD)/bench.elf
	PATH="$(QEMU_DIR):$$PATH" timeout 900 $(QEMU_DIR)/cskysim.exe \
	    -soc $(SOCCFG) -kernel $(QBUILD)/bench.elf -nographic -icount shift=0 | python bench_time.py

# instruction-counter calibration probe (coret vs APB timer, 1 tick = 1 instr)
$(QBUILD)/timer_probe.o: qemu/timer_probe.c
	@mkdir -p $(QBUILD)
	$(CROSS) $(QFLAGS) -c $< -o $@

$(QBUILD)/timer_probe.elf: $(QBUILD)/startup.o $(QBUILD)/support.o $(LIBC_MEM_OBJS) $(QBUILD)/timer_probe.o
	$(CROSS) -mcpu=ck803 -nostdlib -nostartfiles -T qemu/test.ld -Wl,--gc-sections \
	    -o $@ $^ -lgcc

qemu-probe: $(QBUILD)/timer_probe.elf
	PATH="$(QEMU_DIR):$$PATH" timeout 120 $(QEMU_DIR)/cskysim.exe \
	    -soc $(SOCCFG) -kernel $(QBUILD)/timer_probe.elf -nographic -icount shift=0

.PHONY: qemu-bench qemu-probe

# ---- coverage: host build with --coverage, then gcov line+branch summary ----
# coverage is a health signal, not a target: read the gaps, don't chase 100%.
cov:
	$(MAKE) BUILD_DIR=build_cov EXTRA_CFLAGS=--coverage run
	cd build_cov && gcov -b -o . halow_ack.gcno halow_pkg_handler.gcno stream_parser.gcno \
	    link_parser.gcno link_utils.gcno link_db.gcno sha256.gcno \
	    | grep -E "^File '|Lines executed|Branches executed|Taken at least|Creating"

.PHONY: cov
