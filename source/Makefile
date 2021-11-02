CFLAGS = -Wall -Wextra -O9 -fomit-frame-pointer -I. -fanalyzer $(EXT)

OBJS = main.o gea1.o sort_cuckoo.o sched.o test.o print.o cpu.o args.o bench.o sort.o linear_alg.o stage1.o stage2.o stage3.o data.o

PROG = gea1_break

all: $(PROG)
$(PROG): $(OBJS)
	$(CC) $(OBJS) -o $(PROG) -lm4ri

clean:
	rm -f $(PROG) $(OBJS)
