CC = gcc

CFLAGS = -Wall -Wextra -Wno-unused-parameter \
    -Istubs \
    -I../../inc \
    -I../../sdk/include

BUILD_DIR = build

SRCS = \
    main.c \
    size_test.c \
    harness.c \
    ../../src/halow_ack.c

OBJS = $(addprefix $(BUILD_DIR)/,$(notdir $(SRCS:.c=.o)))

TARGET = $(BUILD_DIR)/test_ack.exe
SIZE_TARGET = $(BUILD_DIR)/test_size.exe

all: clean run

run: $(TARGET) $(SIZE_TARGET)
	./$(TARGET)
	./$(SIZE_TARGET)

$(TARGET): $(BUILD_DIR)/main.o $(BUILD_DIR)/harness.o $(BUILD_DIR)/halow_ack.o
	@mkdir -p $(BUILD_DIR)
	$(CC) $(BUILD_DIR)/main.o $(BUILD_DIR)/harness.o $(BUILD_DIR)/halow_ack.o -o $(TARGET)

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

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all run clean
