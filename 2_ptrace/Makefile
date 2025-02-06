CC = gcc
CFLAGS = -Wall -g
LDFLAGS = -lcapstone  # capston library

TARGETS = instruction_counter dynamic_disasm

all: $(TARGETS)

# instruction_counter
instruction_counter: instruction_counter.c
	$(CC) $(CFLAGS) -o instruction_counter instruction_counter.c
#  dynamic_disasm
dynamic_disasm: dynamic_disasm.c
	$(CC) $(CFLAGS) -o dynamic_disasm dynamic_disasm.c $(LDFLAGS)

clean:
	rm -f $(TARGETS)
