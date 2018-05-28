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
 * view coremap as a circular buffer. The potential victim is pointed by the
 * clock_hand
 */
int clock_hand;

/* Page to evict is chosen using the clock algorithm.
 * Returns the page frame number (which is also the index in the coremap)
 * for the page that is to be evicted.
 */

int clock_evict() {
	int victim = -1;
	while (victim == -1) {
		if (coremap[clock_hand].pte->frame & PG_REF) {
			coremap[clock_hand].pte->frame &= ~PG_REF;
		} else {
			victim = clock_hand;
		}
		clock_hand = (clock_hand + 1) % memsize;
	}
	return victim;
}

/* This function is called on each access to a page to update any information
 * needed by the clock algorithm.
 * Input: The page table entry for the page that is being accessed.
 */
void clock_ref(pgtbl_entry_t *p) {
	return;
}

/* Initialize any data structures needed for this replacement
 * algorithm.
 */
void clock_init() {
	clock_hand = 0;
	return;
}
