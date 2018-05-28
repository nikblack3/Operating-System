#include "pagetable.h"
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>


extern int memsize;

extern int debug;

extern struct frame *coremap;

/*
 * Implement FIFO as a circular buffer. first_idx points to the earliest
 * in-frame
 */
int first_idx;

/* Page to evict is chosen using the fifo algorithm.
 * Returns the page frame number (which is also the index in the coremap)
 * for the page that is to be evicted.
 */
int fifo_evict() {
	int victim_frame = first_idx;
	first_idx = (first_idx + 1) % memsize;
	return victim_frame;
}

/* This function is called on each access to a page to update any information
 * needed by the fifo algorithm.
 * Input: The page table entry for the page that is being accessed.
 */
void fifo_ref(pgtbl_entry_t *p) {
	return;
}

/* Initialize any data structures needed for this
 * replacement algorithm
 */
void fifo_init() {
	first_idx = 0;
	return;
}
