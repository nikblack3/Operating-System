#include <stdio.h>
#include <stdlib.h>

void swap(int *x, int *y) {
	int temp = *x;
	*x = *y;
	*y = temp;
}

void bubble_sort(int arr[], int n) {
	int i, j;
	for (i = 0; i < n - 1; i++) {
		for (j = 0; j < n - i - 1; j++) {
			if (arr[j] > arr[j + 1]) {
				swap(&arr[j], &arr[j + 1]);
			}
		}
	}
}

int main(int argc, char const *argv[]) {
	int arr[100];
	for (size_t i = 0; i < 100; i++) {
		arr[i] = rand();
	}
	bubble_sort(arr, 100);
	return 0;
}
