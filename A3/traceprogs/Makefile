SRCS = simpleloop.c matmul.c blocked.c merge_sort.c
PROGS = simpleloop matmul blocked merge_sort

all : $(PROGS)

$(PROGS) : % : %.c
	gcc -Wall -g -o $@ $<


traces: $(PROGS)
	./runit simpleloop
	./runit matmul 100
	./runit blocked 100 25
	./runit bubble_sort

.PHONY: clean
clean : 
	rm -f simpleloop matmul blocked tr-*.ref *.marker *~ merge_sort
