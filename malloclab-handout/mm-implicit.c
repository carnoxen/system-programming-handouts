/*
 * mm-implicit.c - an empty malloc package
 *
 * NOTE TO STUDENTS: Replace this header comment with your own header
 * comment that gives a high level description of your solution.
 *
 * @id : 201402428 
 * @name : JIYOUNG JOUNG
 */
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include "mm.h"
#include "memlib.h"

/* If you want debugging output, use the following macro.  When you hand
 * in, remove the #define DEBUG line. */
#define DEBUG
#ifdef DEBUG
# define dbg_printf(...) printf(__VA_ARGS__)
#else
# define dbg_printf(...)
#endif


/* do not change the following! */
#ifdef DRIVER
/* create aliases for driver tests */
#define malloc mm_malloc
#define free mm_free
#define realloc mm_realloc
#define calloc mm_calloc
#endif /* def DRIVER */

/* single word (4) or double word (8) alignment */
#define ALIGNMENT 8

/* rounds up to the nearest multiple of ALIGNMENT */
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT) - 1) & ~0x7)

#define WSIZE 				4
#define DSIZE 				8

#define CHUNKSIZE 			(1 << 12)
#define OVERHEAD 			8
#define MAX(x, y) 			((x) > (y) ? (x) : (y))

#define PACK(size, alloc) 	((size) | (alloc))
#define GET(p) 				(*(unsigned int *)(p))
#define PUT(p, val) 		(*(unsigned int *)(p) = (val))

#define GET_SIZE(p) 		(GET(p) & ~0x7)
#define GET_ALLOC(p)		(GET(p) & 0x1)

#define HDRP(bp)			((char *)(bp) - WSIZE)
#define FTRP(bp)			((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

#define NEXT_BLKP(bp)		((char *)(bp) + GET_SIZE((char *)(bp) - WSIZE))
#define PREV_BLKP(bp)		((char *)(bp) - GET_SIZE((char *)(bp) - DSIZE))

static char *heap_listp = NULL;

static void *coalesce(void *ptr);
static void place(void *ptr, size_t size);
static void *extend_heap(size_t words);
static void *find_fit(size_t size);

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
	if ((heap_listp = mem_sbrk(4 * WSIZE)) == (void *) -1)
		return -1;

	PUT(heap_listp, 0);
	PUT(heap_listp + WSIZE, PACK(OVERHEAD, 1));

	heap_listp += DSIZE;
	PUT(heap_listp, PACK(OVERHEAD, 1));
	PUT(heap_listp + WSIZE, PACK(0, 1));

	if ((extend_heap(CHUNKSIZE / WSIZE)) == NULL)
		return -1;

	return 0;
}

/*
 * malloc
 */
void *malloc (size_t size) {
	if (size == 0) return NULL;

	size_t asize = ALIGN(size) + DSIZE;
	void *p = find_fit(asize);

	if (p > mem_heap_hi()) {
		size_t extended_words = MAX(asize, CHUNKSIZE) / WSIZE;
		p = extend_heap(extended_words);
	}

	if (p) {
		place(p, asize);
	}

	return p;
}

// coalesce a free block with next, or previous free block
static void *coalesce(void *ptr) {
	void *after_p = NEXT_BLKP(ptr);
	void *before_p = PREV_BLKP(ptr);
	size_t total_size = GET_SIZE(HDRP(ptr));

	if (!GET_ALLOC(HDRP(after_p))) {
		total_size += GET_SIZE(HDRP(after_p));
	}

	if (!GET_ALLOC(HDRP(before_p))) {
		total_size += GET_SIZE(HDRP(before_p));
		ptr = before_p;
	}
	
	PUT(HDRP(ptr), PACK(total_size, 0));
	PUT(FTRP(ptr), PACK(total_size, 0));

	return ptr;
}

// place an allocation in free block
static void place(void *ptr, size_t size) {
	size_t old_size = GET_SIZE(HDRP(ptr));
	size_t rest = old_size - size;
	
	PUT(HDRP(ptr), PACK(size, 1));
	PUT(FTRP(ptr), PACK(size, 1));

	if (rest) {
		ptr = NEXT_BLKP(ptr);
		PUT(HDRP(ptr), PACK(rest, 0));
		PUT(FTRP(ptr), PACK(rest, 0));
	}
}

// extend heap
static void *extend_heap(size_t words) {
	size_t block_size = ALIGN(words * WSIZE) + DSIZE;
	void *p = mem_sbrk(block_size);
	if (p <= 0) return NULL;

	PUT(HDRP(p), PACK(block_size, 0));
	PUT(FTRP(p), PACK(block_size, 0));
	PUT(HDRP(NEXT_BLKP(p)), PACK(0, 1));

	return coalesce(p);
}

// find the fittest free block by size - first fit(find the first fittest free block)
static void *find_fit(size_t size) {
	void *p = heap_listp;

	while ( ( GET_SIZE(HDRP(p)) > 0 ) && 
			( ( GET_ALLOC(HDRP(p)) & 0x1 ) || ( GET_SIZE(HDRP(p)) < size ) ) )
		p = NEXT_BLKP(p);

	return p;
}

/*
 * free
 */
void free (void *ptr) {
	if (!ptr) return;
	coalesce(ptr);
}

/*
 * realloc - you may want to look at mm-naive.c
 */
void *realloc(void *oldptr, size_t size) {
	/* If size == 0 then this is just free, and we return NULL. */
	if(size == 0) {
		free(oldptr);
		return 0;
	}

	/* If oldptr is NULL, then this is just malloc. */
	if(oldptr == NULL) {
		return malloc(size);
	}

	void *newptr = malloc(size);

	/* If realloc() fails the original block is left untouched  */
	if(!newptr) {
		return 0;
	}

	/* Copy the old data. */
	size_t oldsize = GET_SIZE(HDRP(oldptr));
	if(size < oldsize) oldsize = size;
	memcpy(newptr, oldptr, oldsize);

	/* Free the old block. */
	free(oldptr);

	return newptr;
}

/*
 * calloc - you may want to look at mm-naive.c
 * This function is not tested by mdriver, but it is
 * needed to run the traces.
 */
void *calloc (size_t nmemb, size_t size) {
	return malloc(nmemb * size);
}


/*
 * Return whether the pointer is in the heap.
 * May be useful for debugging.
 */
static int in_heap(const void *p) {
	return p < mem_heap_hi() && p >= mem_heap_lo();
}

/*
 * Return whether the pointer is aligned.
 * May be useful for debugging.
 */
static int aligned(const void *p) {
	return (size_t)ALIGN(p) == (size_t)p;
}

/*
 * mm_checkheap
 */
void mm_checkheap(int verbose) {
}
