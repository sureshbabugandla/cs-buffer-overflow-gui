# Builds two binaries from the SAME source to contrast "no protections" with
# "compiler hardening" — the heart of the prevention demonstration.
#
#   bufferdemo_vuln     : protections OFF  -> overflow silently corrupts / crashes
#   bufferdemo_hardened : protections ON   -> overflow is DETECTED and aborted
#
# Run `make` to build both, `make test` for a quick self-check, `make clean` to remove.

CC      = gcc
SRC     = bufferdemo.c

# Vulnerable build: stack protector disabled, no FORTIFY, no optimization.
# This lets the overflow reach the return address so the crash is observable.
VULN_FLAGS = -O0 -fno-stack-protector -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0 -g

# Hardened build: every standard compile-time defence turned ON.
#   -fstack-protector-all : insert a stack canary in every function
#   -D_FORTIFY_SOURCE=2   : compiler replaces unsafe libc calls with checked ones
#   -O2                   : required for FORTIFY_SOURCE to take effect
#   -fPIE -pie            : position-independent -> works with ASLR
HARD_FLAGS = -O2 -fstack-protector-all -D_FORTIFY_SOURCE=2 -fPIE -pie -Wall

all: bufferdemo_vuln bufferdemo_hardened

bufferdemo_vuln: $(SRC)
	$(CC) $(VULN_FLAGS) -o $@ $(SRC)

bufferdemo_hardened: $(SRC)
	$(CC) $(HARD_FLAGS) -o $@ $(SRC)

test: all
	@echo "== normal input (safe mode) =="; ./bufferdemo_vuln safe "hello"; echo "exit=$$?"
	@echo "== oversized input, VULN build (expect crash) =="; ./bufferdemo_vuln unsafe "$$(python3 -c 'print("A"*200)')"; echo "exit=$$?"
	@echo "== oversized input, HARDENED build (expect detected/aborted) =="; ./bufferdemo_hardened unsafe "$$(python3 -c 'print("A"*200)')"; echo "exit=$$?"
	@echo "== adjacent-variable corruption, VULN build =="; ./bufferdemo_vuln flag-unsafe "$$(python3 -c 'print("A"*20)')"; echo "exit=$$?"

clean:
	rm -f bufferdemo_vuln bufferdemo_hardened

.PHONY: all test clean
