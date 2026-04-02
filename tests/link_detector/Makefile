CC = gcc

CFLAGS = -Wall -Wextra \
    -I../../inc \
    -I../../sdk/include

BUILD_DIR = build

SRCS = \
    main.c \
    ../../src/rns/stream_parser.c \
    ../../src/rns/link_parser.c \
    ../../sdk/lib/logc/log.c \
	../../sdk/lib/crypto/sha256.c

OBJS = $(addprefix $(BUILD_DIR)/,$(patsubst ../../%,%,$(SRCS:.c=.o)))

TARGET = $(BUILD_DIR)/test_link_detector

all: clean run

$(TARGET): $(OBJS)
	@mkdir -p $(BUILD_DIR)
	$(CC) $(OBJS) -o $(TARGET)

$(BUILD_DIR)/%.o: %.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

$(BUILD_DIR)/%.o: ../../%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

run: $(TARGET)
	./$(TARGET) 0.0.0.0 8006 0.0.0.0 8007

clean:
	rm -rf $(BUILD_DIR)