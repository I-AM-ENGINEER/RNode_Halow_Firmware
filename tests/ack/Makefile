CC = gcc

CFLAGS = -Wall -Wextra -Wno-unused-parameter \
    -Istubs \
    -I../../inc \
    -I../../sdk/include

BUILD_DIR = build

SRCS = \
    main.c \
    harness.c \
    ../../src/halow_ack.c

OBJS = $(addprefix $(BUILD_DIR)/,$(notdir $(SRCS:.c=.o)))

TARGET = $(BUILD_DIR)/test_ack.exe

all: clean run

run: $(TARGET)
	./$(TARGET)

$(TARGET): $(OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(OBJS) -o $(TARGET)

$(BUILD_DIR)/main.o: main.c harness.h stubs/basic_include.h
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
