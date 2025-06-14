CC = gcc
CFLAGS = -Wall -Wextra -O2
TARGET = cpu_profiler

all: $(TARGET)

$(TARGET): cpu_profiler.c
	$(CC) $(CFLAGS) -o $@ $< -lm

clean:
	rm -f $(TARGET)
