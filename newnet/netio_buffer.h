#ifndef _NETIO_BUFFER_H_
#define _NETIO_BUFFER_H_

#include <stdint.h>

//recv buffer
typedef struct neti_buffer {
	//	uint64_t		recv_prev_time;			//prev process time
	//	uint32_t		recv_count;				//unit time recv count
	uint32_t		recv_idx;				//processed data index
	uint32_t		recv_len;				//received lenth
	uint32_t		recv_buf_length;		//current input buffer length
	uint32_t		recv_buf_max;			//recv buffer max length
	char*			recv_buf;				//buffer
}neti_buffer_t;

//send buffer
typedef struct neto_buffer {
	uint32_t		send_len;				//to be send
	uint32_t		send_buf_length;		//send buffer length
	uint32_t		send_buf_max;			//send buffer max length
	char*			send_buf;
}neto_buffer_t;

#ifdef __cplusplus
extern "C"
{
#endif


int netio_ibuf_init(neti_buffer_t* nb,uint32_t min_length, uint32_t max_length);

void netio_ibuf_destroy(neti_buffer_t* nb);

int netio_ibuf_check_full(neti_buffer_t* nb);

static char* netio_ibuf_breakpoint(neti_buffer_t* nb) {
	return nb->recv_buf + nb->recv_len;
}

static uint32_t netio_ibuf_unused_length(neti_buffer_t* nb) {
	return nb->recv_buf_length - nb->recv_len;
}

int netio_obuf_init(neto_buffer_t* nb, uint32_t min_length, uint32_t max_length);

void netio_obuf_destroy(neto_buffer_t* nb);

/*
	return val: 
	-1: Parameter error, memory allocation failure, length more than twice the buffer
	 0: Buffer can hold
	 1: If the length to be sent is greater than the maximum length but less than twice the maximum length, the caller can copy part of it to the buffer and try to send it immediately,
		and then verify it again until the return value is 0, or close it in advance
*/

//int netio_obuf_check_full(neto_buffer_t* nb, const char* output_data, uint32_t output_len, int* out_processed_length);
int netio_obuf_check_full(neto_buffer_t* nb, uint32_t output_len);

static char* netio_obuf_breakpoint(neto_buffer_t* nb) {
	return nb->send_buf + nb->send_len;
}

static uint32_t netio_obuf_unused_length(neto_buffer_t* nb) {
	return nb->send_buf_length - nb->send_len;
}

#ifdef __cplusplus
}
#endif


#endif//_NETIO_BUFFER_H_