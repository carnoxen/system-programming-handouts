/*
 * mm-explicit.c - an empty malloc package
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
#define ALIGN(p) (((size_t)(p) + (ALIGNMENT-1)) & ~0x7)

#define HDRSIZE             4
#define FTRSIZE             4

#define WSIZE 			    4
#define DSIZE 			    8

#define CHUNKSIZE 		    (1 << 12)
#define OVERHEAD 		    8

#define MAX(x, y) 		    ((x) > (y) ? (x) : (y))
#define MIN(x, y) 		    ((x) < (y) ? (x) : (y))

#define PACK(size, alloc) 	((size) | (alloc))

#define GET(p) 			    (*(unsigned *)(p))
#define PUT(p, val) 		(*(unsigned *)(p) = (unsigned int)(val))

#define GET8(p) 			(*(unsigned long *)(p))
#define PUT8(p, val) 		(*(unsigned long *)(p) = (unsigned long)(val))

#define GET_SIZE(p) 		(GET(p) & ~0x7)
#define GET_ALLOC(p)		(GET(p) & 0x1)

#define HDRP(bp)		    ((char *)(bp) - WSIZE)
#define FTRP(bp)		    ((char *)(bp) + GET_SIZE(HDRP(bp)) - DSIZE)

#define NEXT_FREEP(bp)      ((char *)(bp))
#define PREV_FREEP(bp)      ((char *)(bp) + DSIZE)

#define NEXT_FREE_BLKP(bp)  ((char *)GET8((char *)(bp)))
#define PREV_FREE_BLKP(bp)  ((char *)GET8((char *)(bp) + DSIZE))

#define NEXT_BLKP(bp)		((char *)(bp) + GET_SIZE((char *)(bp) - WSIZE))
#define PREV_BLKP(bp)		((char *)(bp) - GET_SIZE((char *)(bp) - DSIZE))

static void *heap_listp = NULL; // heap starts here
static void *free_root = NULL; // free block starting pointer
static const size_t MINSIZE = HDRSIZE + FTRSIZE + 2 * DSIZE; // it is a minimum size of data blocks

static void *coalesce(void *ptr);
static void place(void *ptr, size_t size);
static void *extend_heap(size_t words);
static void *find_fit(size_t size);

static void remove_fb(void *ptr);
static void insert_fb(void *ptr);

/*
 * Initialize: return -1 on error, 0 on success.
 */
int mm_init(void) {
	//dbg_printf("== startup\n");
    if ((heap_listp = mem_sbrk(DSIZE + 4 * HDRSIZE)) == (void *) -1)
        return -1;
    free_root = heap_listp;

    PUT8(heap_listp, NULL);

    PUT(heap_listp + DSIZE, 0);

    PUT(heap_listp + DSIZE + HDRSIZE, PACK(OVERHEAD, 1));
	heap_listp += (DSIZE + HDRSIZE + FTRSIZE);
    PUT(heap_listp, PACK(OVERHEAD, 1));
    PUT(heap_listp + HDRSIZE, PACK(0, 1));

    if (extend_heap(CHUNKSIZE / WSIZE) == NULL)
        return -1;

    return 0;
}

/*
 * malloc
 */
void *malloc (size_t size) {
	//dbg_printf("malloc...\n");
	if (size == 0) return NULL;

	size_t malloc_size = ALIGN(size) + MINSIZE - DSIZE;
	void *p = find_fit(malloc_size);

	if (!p) {
		size_t extended_words = MAX(malloc_size, CHUNKSIZE) / WSIZE;
		p = extend_heap(extended_words);
	}

	if (p) {
		place(p, malloc_size);
	}

	return p;
}

// remove free block in the free block list
// prev - this - next ==> prev - next
static void remove_fb(void *ptr) {
	void *next_fp = NEXT_FREE_BLKP(ptr);
	void *prev_fp = PREV_FREE_BLKP(ptr);
	if (!prev_fp) prev_fp = free_root;

	if (next_fp) {
		PUT8(PREV_FREEP(next_fp), prev_fp);
	}
	PUT8(NEXT_FREEP(prev_fp), next_fp);
}

// insert free block into front of free block list - it is LIFO
static void insert_fb(void *ptr) {
	void *first_fp = NEXT_FREE_BLKP(free_root);

	PUT8(PREV_FREEP(ptr), NULL);
	PUT8(NEXT_FREEP(ptr), first_fp);

	if (first_fp) {
		PUT8(PREV_FREEP(first_fp), ptr);
	}
	PUT8(NEXT_FREEP(free_root), ptr);
}

// remove_fb, insert_fb added
static void *coalesce(void *ptr) {
	void *after_p = NEXT_BLKP(ptr);
	void *before_p = PREV_BLKP(ptr);
	size_t total_size = GET_SIZE(HDRP(ptr));

	if (!GET_ALLOC(HDRP(after_p))) {
		total_size += GET_SIZE(HDRP(after_p));
		remove_fb(after_p);
	}

	if (!GET_ALLOC(HDRP(before_p))) {
		total_size += GET_SIZE(HDRP(before_p));
		remove_fb(before_p);
		ptr = before_p;
	}
	
	PUT(HDRP(ptr), PACK(total_size, 0));
	PUT(FTRP(ptr), PACK(total_size, 0));

	insert_fb(ptr);

	return ptr;
}

// remove_fb, insert_fb added
static void place(void *ptr, size_t size) {
	size_t old_size = GET_SIZE(HDRP(ptr));
	size_t rest = old_size - size;

	remove_fb(ptr);

	if (rest >= MINSIZE) {
		PUT(HDRP(ptr), PACK(size, 1));
		PUT(FTRP(ptr), PACK(size, 1));

		ptr = NEXT_BLKP(ptr);
		PUT(HDRP(ptr), PACK(rest, 0));
		PUT(FTRP(ptr), PACK(rest, 0));
		insert_fb(ptr);
	}
	else {
		PUT(HDRP(ptr), PACK(old_size, 1));
		PUT(FTRP(ptr), PACK(old_size, 1));
	}
}

// it is same with implicit
static void *extend_heap(size_t words) {
	size_t block_size = ALIGN(words * WSIZE) + MINSIZE;
	void *p = mem_sbrk(block_size);
	if (p <= 0) return NULL;

	PUT(HDRP(p), PACK(block_size, 0));
	PUT(FTRP(p), PACK(block_size, 0));
	PUT(HDRP(NEXT_BLKP(p)), PACK(0, 1));

	return coalesce(p);
}

// just iterate free block list
static void *find_fit(size_t size) {
	void *p = free_root;

	do {
		p = NEXT_FREE_BLKP(p);
	}
	while ( p && ( GET_SIZE(HDRP(p)) < size ) );

	return p;
}

/*
 * free
 */
void free (void *ptr) {
	//dbg_printf("free...\n");
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
	memcpy(newptr, oldptr, MIN(size, oldsize));

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
