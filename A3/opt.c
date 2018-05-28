#include "pagetable.h"
#include <assert.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

#include "sim.h"
#include <string.h>

#define BUFSIZE 1024

// extern int memsize;
extern int debug;
extern struct frame *coremap;
extern char *tracefile;
extern char *physmem;

typedef struct addr_node {
	addr_t address;
	struct addr_node *next;
} addr_node;

addr_node *head;
int addr_ll_size;

// ---------------- HELPER FUNCTION ------------------
void init_addr_node(addr_node *node) {
	node->address = 0;
	node->next = NULL;
}

/*
 * Evict the most distant page. (the largest number of other instructions till
 * the next reference)
 */

/* Page to evict is chosen using the optimal (aka MIN) algorithm.
 * Returns the page frame number (which is also the index in the coremap)
 * for the page that is to be evicted.
 */
int opt_evict() {
	int victim = 0;
	int max_distance = 0;
	for (size_t i = 0; i < memsize; i++) {
		pgtbl_entry_t *pte = coremap[i].pte;

		// get the vaddr for the current idx
		char *mem_ptr = &physmem[(pte->frame >> PAGE_SHIFT) * SIMPAGESIZE];
		int *vaddr_ptr = (int *)(mem_ptr + sizeof(int));

		// loop over the ll and update the max_distance and victim
		addr_node *current = head;
		int current_distance = 0;
		while (current) {
			if (current->address != *vaddr_ptr) {
				current_distance++;
			} else {
				break;
			}
			current = current->next;
		}
		if (max_distance < current_distance) {
			victim = i;
			max_distance = current_distance;
		}
		if (!current) { // no reference anymore
			return i;
		}
	}
	return victim;
}

/* This function is called on each access to a page to update any information
 * needed by the opt algorithm.
 * Input: The page table entry for the page that is being accessed.
 */
void opt_ref(pgtbl_entry_t *p) {
	// current head is referenced. move to next one
	head = head->next;
	return;
}

/* Initializes any data structures needed for this
 * replacement algorithm.
 */
void opt_init() {
	head = malloc(sizeof(addr_node));
	if (!head) {
		perror("opt_init: malloc head");
		exit(-1);
	}

	init_addr_node(head);

	FILE *f = fopen(tracefile, "r");
	if (!f) {
		perror("opt_init: fopen");
		exit(-1);
	}

	// read all instructions into the ll
	addr_node *curr = head;
	char buf[BUFSIZE];
	char type;
	addr_t vaddr;
	addr_ll_size = 0;
	while (fgets(buf, BUFSIZE, f) != NULL) {
		if (buf[0] != '=') {
			sscanf(buf, "%c %lx", &type, &vaddr);
			curr->next = malloc(sizeof(addr_node));
			if (!curr->next) {
				perror("opt_init: malloc curr->next");
			}
			curr = curr->next;
			init_addr_node(curr);
			curr->address = vaddr;
			addr_ll_size++;
		}
	}
	return;
}
