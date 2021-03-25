#include "heap_obj.h"

#include <stdlib.h>
#include <string.h>

//#define my_malloc malloc
//#define my_realloc realloc
//#define my_free free

#define D (1)


heap_obj_t* create_heapobj(int(*compare_func)(void*, void*)) {
	if (!compare_func) { return 0; }

	heap_obj_t* obj = malloc(sizeof(heap_obj_t));
	memset(obj, 0, sizeof(heap_obj_t));
	
	obj->buff_len = HEAP_DEFAULT_BUFF_LEN;
	obj->compare_func = compare_func;

	obj->buffer = malloc(sizeof(void*) * obj->buff_len);

	memset(obj->buffer, 0, sizeof(void*) * obj->buff_len);
	return obj;
}

void destroy_heapobj(heap_obj_t* obj) {
	if (obj) {
		free(obj->buffer);
		free(obj);
	}
}

void filter_down(heap_obj_t* obj,uint32_t idx) {
	if (!obj->elem_len) { return; }

	uint32_t switch_idx = idx;
	//void* switch_obj = obj->buffer[idx] = obj->buffer[obj->elem_len - 1];
	void* switch_obj = obj->buffer[idx];
	
	while (switch_idx < obj->elem_len) {
		uint32_t left_idx = switch_idx * 2 + 1;
		uint32_t righ_idx = left_idx + 1;

		if (righ_idx < obj->elem_len) {
			/*
				find the idx that meets the condition
			*/
			uint32_t compare_idx = righ_idx;
			if (obj->compare_func(obj->buffer[left_idx], obj->buffer[righ_idx]) == 0) {
				compare_idx = left_idx;
			}
			
			if (obj->compare_func(obj->buffer[compare_idx], switch_obj) == 0) {
				obj->buffer[switch_idx] = obj->buffer[compare_idx];
				switch_idx = compare_idx;
			}
			else {
				break;
			}
		}
		else if (left_idx < obj->elem_len) {
			if (obj->compare_func(obj->buffer[left_idx], switch_obj) == 0) {
				obj->buffer[switch_idx] = obj->buffer[left_idx];
				switch_idx = left_idx;
			}
			else {
				break;
			}
		}
		else {
			break;
		}
	}

	obj->buffer[switch_idx] = switch_obj;
}

void filter_up(heap_obj_t* obj, uint32_t idx) {
	if (!idx)return;

	uint32_t parent_idx = idx;
	void* switch_obj = obj->buffer[idx];
	while (idx > 0) {
		parent_idx = (idx - 1) / 2;
		if (obj->compare_func(switch_obj, obj->buffer[parent_idx]) == 0) {
			obj->buffer[idx] = obj->buffer[parent_idx];
			/*
				put the object that meet the conditions into the bucket
			*/
		}
		else {	
			break;
		}
		idx = (idx - 1) / 2;
		/*
			update the position of the bucket
		*/
	}
	
	/*
		put into the last updated bucket
		the reason for writing here : the while loop will not process idx = 0
	*/
	obj->buffer[idx] = switch_obj;
}

int add_element2heapobj(heap_obj_t* obj, void* value) {
	if (obj->buff_len <= obj->elem_len) {
		/*void* new_buffer = my_malloc(sizeof(void*) * obj->buff_len * 2);
		memcpy(new_buffer, obj->buffer, sizeof(void*) * obj->elem_len);
		obj->buff_len *= 2;

		my_free(obj->buffer);
		obj->buffer = new_buffer;*/
		obj->buffer = realloc(obj->buffer, sizeof(void*) * obj->buff_len * 2);
		obj->buff_len *= 2;
	}

	obj->buffer[obj->elem_len] = value;
	filter_up(obj, obj->elem_len);
	++(obj->elem_len);
	return 0;
}

void del_elementisvalue(heap_obj_t* obj, void* value) {
	int i = 0;
	for (; i < obj->elem_len; ++i) {
		if (obj->buffer[i] == value) {
			obj->buffer[i] = obj->buffer[obj->elem_len -= 1];
			filter_down(obj, i);
			return;
		}
	}
}

void* pop_frontfromheap(heap_obj_t* obj) {
	void* rvar = 0;
	if (is_empty(obj)) {
		return rvar;
	}

	rvar = obj->buffer[0];
	obj->buffer[0] = obj->buffer[obj->elem_len -= 1];
	filter_down(obj, 0);
	return rvar;
}

void* pop_backfromheap(heap_obj_t* obj) {
	if (is_empty(obj)) {
		return 0;
	}

	return obj->buffer[--(obj->elem_len)];
}

void* front_fromheap(heap_obj_t* obj) {
	if (is_empty(obj)) {
		return 0;
	}
	return obj->buffer[0];
}

void* back_fromheap(heap_obj_t* obj) {
	if (is_empty(obj)) {
		return 0;
	}
	return obj->buffer[obj->elem_len - 1];
}

inline int is_empty(heap_obj_t* obj) {
	return obj->elem_len == 0;
}