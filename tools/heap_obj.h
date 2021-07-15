#ifndef _MIN_HEAP_H_
#define _MIN_HEAP_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

#define HEAP_DEFAULT_BUFF_LEN (1 << 7)

typedef struct heap_obj {
	/*	methods of comparing two objects,this will determine the nature of heap object.
	the return value is zero or other
	0: the left node will be replace by the right node
	*/
	int(*compare_func)(void*, void*);
	uint32_t elem_len;			//element length
	uint32_t buff_len;			//buffer length
	void** buffer;				//buffer object,child object type is void*
}heap_obj_t;

heap_obj_t* create_heapobj(int(*compare_func)(void*, void*));

void destroy_heapobj(heap_obj_t* obj);

void filter_down(heap_obj_t* obj, uint32_t idx);

void filter_up(heap_obj_t* obj, uint32_t idx);

int add_element2heapobj(heap_obj_t* obj, void* value);

void del_elementisvalue(heap_obj_t* obj, void* value);

void* pop_frontfromheap(heap_obj_t* obj);

void* pop_backfromheap(heap_obj_t* obj);

void* front_fromheap(heap_obj_t* obj);

void* back_fromheap(heap_obj_t* obj);

int is_empty(heap_obj_t* obj);

#ifdef __cplusplus
}
#endif

#endif//_MIN_HEAP_H_