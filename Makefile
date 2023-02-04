# SPDX-License-Identifier: GPL-2.0-only

CLANG = clang-15
TARGETS = proc-controller proc-controller.bpf.o

all: $(TARGETS)

clean:
	rm -f -- $(TARGETS)

proc-controller.bpf.o: proc-controller.bpf.c
	$(CLANG) -target bpf -g -O2 -Wall -o $@ -c $<

proc-controller: proc-controller.c
	$(CLANG) -g -o $@ $< -lbpf

proc-controller.bpf.o: Makefile
proc-controller: Makefile
