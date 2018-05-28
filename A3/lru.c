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
 * Implemented using timestamp. timestamp implemented in struct frame.
 * evict frame with min timestamp.
 */
long unsigned current_time;

/* Page to evict is chosen using the accurate LRU algorithm.
 * Returns the page frame number (which is also the index in the coremap)
 * for the page that is to be evicted.
 */
int lru_evict() {
	int victim = 0;
	// arbitrary large for inf
	long unsigned min = 10000000000000;
	for (size_t frame_num = 0; frame_num < memsize; frame_num++) {
		if (coremap[frame_num].lru_timestamp < min) {
			min = coremap[frame_num].lru_timestamp;
			victim = frame_num;
		}
	}
	return victim;
}

/* This function is called on each access to a page to update any information
 * needed by the lru algorithm.
 * Input: The page table entry for the page that is being accessed.
 */
void lru_ref(pgtbl_entry_t *p) {
	for (size_t frame_num = 0; frame_num < memsize; frame_num++) {
		if (coremap[frame_num].pte == p) {
			coremap[frame_num].lru_timestamp = current_time;
			break;
		}
	}
	current_time++;
	return;
}


/* Initialize any data structures needed for this
 * replacement algorithm
 */
void lru_init() {
	current_time = 0;
	return;
}
