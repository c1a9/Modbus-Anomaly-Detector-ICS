CC = gcc
CFLAGS = -Wall -Wextra -O2 -pthread -Iinclude
LDFLAGS = -lpcap -lm

SRC = src/main.c src/capture.c src/protocol.c src/session_manager.c \
      src/detector.c src/response.c src/logger.c src/config.c src/web.c

OBJ = $(SRC:.c=.o)
TARGET = bin/modbus-ids

all: $(TARGET)

$(TARGET): $(OBJ) | bin
	$(CC) $(CFLAGS) -o $@ $^ $(LDFLAGS)

bin:
	mkdir -p bin

clean:
	rm -f src/*.o
	rm -rf bin

.PHONY: all clean
