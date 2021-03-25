#ifndef _BASIC_TOOLS_H_
#define _BASIC_TOOLS_H_

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <sys/fcntl.h>
#include <sys/resource.h>

//需要libuuid-devel
#include <uuid/uuid.h>
#include <errno.h>

#ifndef _WIN32
#define __FILENAME__ (strrchr(__FILE__,'/') + 1)
#else
#define __FILENAME__ (strrchr(__FILE__,'\\') + 1)
#endif//_WIN32

#ifdef __cplusplus
extern "C"
{
#endif


//可重入 uuid_buf 不小于37字节缓冲区
const char* tools_get_uuid_r(char uuid_buf[40]);

//不可重入
const char* tools_get_uuid();

//计算hash
unsigned int tools_hash_func(const char* char_key, int klen);

//检查更新文件描述符
int tools_nofile_ckup();

//设置套接字为非阻塞
int tools_set_nonblocking(int fd);

/*
	计算num的值域, 值域与retval的关系: (1 << (retval - 1) , 1 << (retval)]
*/
int tools_bit_range2(uint8_t left, uint8_t right, uint32_t num);

/**
*	tools_get_time_format_string - Gets the time format string of the current time, non-reentrant
*/
const char* tools_get_time_format_string();

/**
*	tools_get_filename - Gets the current file name
*/
const char* tools_get_current_filename();

#ifdef __cplusplus
}
#endif

#endif//_BASIC_TOOLS_H_