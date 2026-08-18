# Licensed under the Apache-2.0 license

OUT := out
TARGET := $(OUT)/smoke_test
LIB := ../../../../target/debug/libcaliptra_mcu_hw_model_c_binding.a
CFLAGS += -std=c11 -Wall -Wextra -Werror -I../out
LDLIBS += -lpthread -ldl -lrt -lm

all: $(TARGET)

$(LIB):
	cargo build --manifest-path ../Cargo.toml

$(TARGET): smoke_test.c $(LIB)
	mkdir -p $(OUT)
	$(CC) $(CFLAGS) $< $(LIB) $(LDLIBS) -o $@

run: $(TARGET)
	$(TARGET)

clean:
	$(RM) -r $(OUT)
