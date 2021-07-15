#ifndef _HEAP_TIMER_H_
#define _HEAP_TIMER_H_

#ifdef _WIN32
#include <Windows.h>
#else
//编译添加_GNU_SOURCE预处理
#include <pthread.h>
#endif//_WIN32

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif


/*
是否启用单线程模式,即便是单线程使用原子锁，也将带来时间的损耗，即便很小
但确定在单线程环境下使用，依然建议启动该预处理
*/
#define HT_SINGLE_THREAD_MOD

typedef struct heap_obj heap_obj_t;

typedef struct timer_element {
	uint32_t timer_id;	//定时器ID
	uint32_t interval;	//间隔时间
	uint64_t ring_time;	//响铃时间
	int32_t repeat;	//重复次数
	void* user_data;
	void(*on_timeout)(uint32_t, void*);
}timer_element_t;

typedef struct heap_timer {
	uint32_t unique_id;
	timer_element_t* running_timer;
	heap_obj_t* heap_timer_objs;

#ifndef HT_SINGLE_THREAD_MOD

#ifdef _WIN32
	CRITICAL_SECTION lock_hp_timer;
#else
	pthread_spinlock_t lock_hp_timer;
#endif//_WIN32

#endif//HT_SINGLE_THREAD_MOD
}heap_timer_t;

uint64_t get_local_ms();

heap_timer_t* ht_create_heap_timer();

void ht_destroy_heap_timer(heap_timer_t* ht);

/*
	return value:
	-1 failed;
	other timer_id;
*/
uint32_t ht_add_timer(heap_timer_t* ht, uint32_t interval, uint32_t delay_ms, int32_t repeat, void(*on_timeout)(uint32_t, void*), void* user_data);

void ht_del_timer(heap_timer_t* ht, uint32_t timer_id);

void ht_del_timer_incallback(heap_timer_t* ht, uint32_t timer_id);

uint32_t ht_update_timer(heap_timer_t* ht);

#ifdef __cplusplus
}
#endif

#endif//_HEAP_TIMER_H_