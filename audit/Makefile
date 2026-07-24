# LD-Watch — Audit Library Makefile

CC     = gcc
CFLAGS = -shared -fPIC -Wall -Wextra -O2 -g -I./include
SRCS   = src/audit.c src/hooks.c src/ipc.c
OUT    = audit.so

.PHONY: all clean

all: $(OUT)

$(OUT): $(SRCS)
	$(CC) $(CFLAGS) -o $(OUT) $(SRCS) -ldl
	@echo "[audit] audit.so built successfully."

clean:
	rm -f $(OUT)
