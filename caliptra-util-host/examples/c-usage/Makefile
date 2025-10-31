# Makefile for C example

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O2
LDFLAGS = 
TARGET = caliptra_c_example
SOURCE = main.c

# In a real implementation, you would link against the actual library:
# LDFLAGS = -L../../target/release -lcaliptra_util_host_cbinding

all: $(TARGET)

$(TARGET): $(SOURCE)
	$(CC) $(CFLAGS) -o $(TARGET) $(SOURCE) $(LDFLAGS)

clean:
	rm -f $(TARGET)

run: $(TARGET)
	./$(TARGET)

run-doe: $(TARGET)
	./$(TARGET) doe

.PHONY: all clean run run-doe