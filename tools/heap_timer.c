#include "heap_timer.h"


#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <sys/time.h>

#include "heap_obj.h"



#define ht_malloc malloc
#define ht_realloc realloc
#define ht_free free


#ifdef WIN32

#include <Windows.h>
uint64_t get_local_ms() {
	SYSTEMTIME st;
	FILETIME ft;
	GetLocalTime(&st);
	SystemTimeToFileTime(&st, &ft);
	return (((LARGE_INTEGER*)&ft)->QuadPart / 10000);
}
#else

uint64_t get_local_ms() {
	//tv.tv_sec Seconds
	//tv.tv_usec Microseconds

	struct timeval tv;
	gettimeofday(&tv, 0);
	return (tv.tv_sec * 1000 + tv.tv_usec / 1000);
}

#endif//WIN32

int timer_heap_compare_func(timer_element_t* left, timer_element_t* right) {
	return left->ring_time < right->ring_time ? 0 : 1;
}

/*lock function*/
static void ht_enter_timerobj_lock(heap_timer_t* ht) {
#ifndef HT_SINGLE_THREAD_MOD

#ifndef _WIN32
	pthread_spin_lock(&(ht->lock_hp_timer));
#else
	EnterCriticalSection(&(ht->lock_hp_timer));
#endif//_WIN32

#endif//HT_SINGLE_THREAD_MOD
}

static void ht_leave_timerobj_lock(heap_timer_t* ht) {
#ifndef HT_SINGLE_THREAD_MOD

#ifndef _WIN32
	pthread_spin_unlock(&(ht->lock_hp_timer));
#else
	LeaveCriticalSection(&(ht->lock_hp_timer));
#endif//_WIN32

#endif//HT_SINGLE_THREAD_MOD
}


heap_timer_t* ht_create_heap_timer() {
	heap_timer_t* ht = ht_malloc(sizeof(heap_timer_t));
	if (ht) {
		memset(ht, 0, sizeof(heap_timer_t));
		ht->heap_timer_objs = create_heapobj(timer_heap_compare_func);
		if (ht->heap_timer_objs == 0) {
			ht_free(ht);
			return 0;
		}

		/*init critical_section*/

#ifndef HT_SINGLE_THREAD_MOD

#ifdef _WIN32
		InitializeCriticalSection(&ht->lock_hp_timer);
#else
		pthread_spin_init(&ht->lock_hp_timer, PTHREAD_PROCESS_PRIVATE);
#endif//_WIN32

#endif//HT_SINGLE_THREAD_MOD

		return ht;
	}
	return 0;
}

void ht_destroy_heap_timer(heap_timer_t* ht) {
	if (ht) {

#ifndef HT_SINGLE_THREAD_MOD

#ifdef _WIN32
		DeleteCriticalSection(&ht->lock_hp_timer);
#else
		pthread_spin_destroy(&ht->lock_hp_timer);
#endif//_WIN32

#endif//HT_SINGLE_THREAD_MOD

		while (1) {
			void* free_ptr = pop_frontfromheap(ht->heap_timer_objs);
			if (free_ptr == 0)
				break;
			else
				free(free_ptr);
		}


		destroy_heapobj(ht->heap_timer_objs);
		ht_free(ht);
	}
}

uint32_t ht_add_timer(heap_timer_t* ht, uint32_t interval, int32_t repeat, void(*on_timeout)(void*), void* user_data) {
	timer_element_t* te = ht_malloc(sizeof(timer_element_t));
	if (te) {
		te->interval = interval;
		te->repeat = repeat;
		te->on_timeout = on_timeout;
		te->user_data = user_data;
		te->ring_time = get_local_ms() + interval;

		ht_enter_timerobj_lock(ht);
		te->timer_id = ht->unique_id++;
		add_element2heapobj(ht->heap_timer_objs, te);
		ht_leave_timerobj_lock(ht);
		return te->timer_id;
	}
	return -1;
}

void ht_del_timer(heap_timer_t* ht, uint32_t timer_id) {
	ht_enter_timerobj_lock(ht);
	
	/*if timer_id is equal to current running timer*/
	if (ht->running_timer && ht->running_timer->timer_id == timer_id) {
		ht->running_timer->repeat = 1;
		ht_leave_timerobj_lock(ht);
		return;
	}


	for (int i = 0; i < ht->heap_timer_objs->elem_len; ++i) {
		if (((timer_element_t*)(ht->heap_timer_objs->buffer[i]))->timer_id == timer_id) {
			//ht->heap_timer_objs->buffer[i] = ht->heap_timer_objs->buffer[ht->heap_timer_objs->elem_len -= 1];
			//filter_down(ht->heap_timer_objs, i);
			del_elementisvalue(ht->heap_timer_objs, ht->heap_timer_objs->buffer[i]);
			break;
		}
	}
	ht_leave_timerobj_lock(ht);
}

void ht_del_timer_incallback(heap_timer_t* ht, uint32_t timer_id) {
	/*if timer_id is equal to current running timer*/
	if (ht->running_timer && ht->running_timer->timer_id == timer_id) {
		ht->running_timer->repeat = 1;
		return;
	}


	for (int i = 0; i < ht->heap_timer_objs->elem_len; ++i) {
		if (((timer_element_t*)(ht->heap_timer_objs->buffer[i]))->timer_id == timer_id) {
			/*ht->heap_timer_objs->buffer[i] = ht->heap_timer_objs->buffer[ht->heap_timer_objs->elem_len -= 1];
			filter_down(ht->heap_timer_objs, i);*/
			del_elementisvalue(ht->heap_timer_objs, ht->heap_timer_objs->buffer[i]);
			break;
		}
	}
}

uint32_t ht_update_timer(heap_timer_t* ht) {
	timer_element_t* te;
	uint32_t interval_time = -1;
	uint64_t cur_ms = get_local_ms();
	
	ht_enter_timerobj_lock(ht);
	
	while (te = front_fromheap(ht->heap_timer_objs)) {
		/*note left == right*/
		if (te->ring_time <= cur_ms) {
			ht->running_timer = te;
			if (te->on_timeout) {
				te->on_timeout(te->user_data);
			}

			if (te->repeat != -1 && (te->repeat -= 1) == 0) {
				del_elementisvalue(ht->heap_timer_objs, te);
				
				/*only release obj*/
				ht_free(te);
				continue;
			}

			/*update ring time*/
			te->ring_time = cur_ms + te->interval;
			filter_down(ht->heap_timer_objs, 0);

			/*reset running timer*/
			ht->running_timer = 0;
		}
		else {
			interval_time = te->ring_time - cur_ms;
			break;
		}
	}

	ht_leave_timerobj_lock(ht);
	return interval_time;
}