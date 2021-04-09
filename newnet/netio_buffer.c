#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>

#include "netio_buffer.h"

//#define netio_malloc malloc
//#define netio_free	free
/*
	为输入缓冲区提供内存
*/

int netio_ibuf_init(neti_buffer_t* nb, uint32_t min_length, uint32_t max_length) {
	if (nb == 0 || min_length > max_length)
		return -1;

	memset(nb, 0, sizeof(neti_buffer_t));

	nb->recv_buf_length = max_length;

	if (max_length) {
		//nb->recv_buf = (char*)netio_malloc(max_length);
		nb->recv_buf = (char*)malloc(max_length);

		if (nb->recv_buf == 0)
			return -1;
		nb->recv_buf_max = max_length;
	}
	return 0;
}

void netio_ibuf_destroy(neti_buffer_t* nb) {
	if (nb && nb->recv_buf) {
		free(nb->recv_buf);
		nb->recv_buf = 0;
	}
}

/*
	校验输入缓冲区
*/

int netio_ibuf_check_full(neti_buffer_t* nb) {
	if (nb == 0)
		return -1;
	if ((nb->recv_buf_length - nb->recv_len) == 0)
		return -1;
	return 0;
}


/*
	为输出缓冲区提供内存
	retrun，成功:0 失败-1 错误指示: errno
*/

int netio_obuf_init(neto_buffer_t* nb, uint32_t min_length, uint32_t max_length) {
	if (nb == 0 || min_length > max_length)
		return -1;

	memset(nb, 0, sizeof(neto_buffer_t));

	nb->send_buf_max = max_length;
	

	if (min_length) {
		//nb->send_buf = (char*)netio_malloc(min_length);
		nb->send_buf = (char*)malloc(min_length);

		if (nb->send_buf == 0)
			return -1;
		nb->send_buf_length = min_length;
	}
	return 0;
}

void netio_obuf_destroy(neto_buffer_t* nb) {
	if (nb && nb->send_buf) {
		free(nb->send_buf);
		nb->send_buf = 0;
	}
		
}


//int netio_obuf_check_full(neto_buffer_t* nb, const char* output_data, uint32_t output_len, int* out_processed_length) {
//
//}

int netio_obuf_check_full(neto_buffer_t* nb, uint32_t output_len) {
	if (nb == 0)
		return -1;

	int all_len = nb->send_len + output_len;

	//若已有长度+待发送长度 > 当前缓冲区长度
	if (all_len > nb->send_buf_length) {
		//若没有超过最大长度则尝试更换缓冲区,此处包含了0xffffffff的判断
		if (all_len <= nb->send_buf_max) {
			nb->send_buf = realloc(nb->send_buf, all_len);
			if (nb->send_buf == 0) {
				nb->send_buf_length = 0;
				return -1;
			}
			nb->send_buf_length = all_len;
			return 0;

		}else {
			//若大于最大长度两倍
			if (all_len > (nb->send_buf_max * 2)) {
				return -1;
			}
			//此处需要判断如果已经是最大值 则不需要再malloc
			//char* new_buf = (char*)netio_malloc(nb->send_buf_max);
			if (nb->send_buf_length < nb->send_buf_max) {
				nb->send_buf = realloc(nb->send_buf, nb->send_buf_max);
				if (nb->send_buf == 0) {
					nb->send_buf_length = 0;
					return -1;
				}
				nb->send_buf_length = nb->send_buf_max;
			}
			//若不大于两倍，则拷贝缓冲区剩余长度的数据到缓冲区，发送后再重试，若依旧为当前返回值，则关闭套接字
			return 1;
		}
	}
	return 0;
}