CC ?= gcc
CFLAGS ?= -shared -fPIC -O3 -Wall -Wextra

# Detect OS for dynamic library extension
ifeq ($(OS),Windows_NT)
    TARGET_EXT = dll
else
    UNAME_S := $(shell uname -s)
    ifeq ($(UNAME_S),Darwin)
        TARGET_EXT = dylib
    else
        TARGET_EXT = so
    endif
endif

TARGET = ../libdpi.$(TARGET_EXT)

.PHONY: all clean fuzz

all: $(TARGET)

$(TARGET): dpi.c
	$(CC) $(CFLAGS) -o $@ $<

# Memory-safety fuzzing under AddressSanitizer + UndefinedBehaviorSanitizer.
#   make -C c_src fuzz [ITER=1000000]
ITER ?= 1000000
fuzz: fuzz_dpi.c dpi.c
	$(CC) -g -O1 -fsanitize=address,undefined -fno-omit-frame-pointer -fno-sanitize-recover=all -o fuzz_dpi fuzz_dpi.c
	./fuzz_dpi $(ITER)

clean:
	rm -f ../libdpi.so ../libdpi.dll ../libdpi.dylib fuzz_dpi
