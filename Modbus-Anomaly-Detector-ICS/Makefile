CC = gcc
CFLAGS = -Wall -Wextra -O2 -Iinclude
LDFLAGS = -lpcap -lm

SRCDIR = src
OBJDIR = obj
TARGET = modbus_ids

SOURCES = $(wildcard $(SRCDIR)/*.c)
OBJECTS = $(patsubst $(SRCDIR)/%.c,$(OBJDIR)/%.o,$(SOURCES))

all: $(TARGET)

$(TARGET): $(OBJECTS)
	$(CC) -o $@ $^ $(LDFLAGS)

$(OBJDIR)/%.o: $(SRCDIR)/%.c | $(OBJDIR)
	$(CC) $(CFLAGS) -c $< -o $@

$(OBJDIR):
	mkdir -p $(OBJDIR)

clean:
	rm -rf $(OBJDIR) $(TARGET) web/status.json modbus_ids.log

.PHONY: all clean
