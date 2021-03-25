#ifndef __BASE64_ENCODE_H__
#define __BASE64_ENCODE_H__

#include <stdint.h>

//char* base64_encode(uint8_t* text, int sz, int* encode_sz);
#ifdef __cplusplus
extern "C"
{
#endif

char* base64_encode(uint8_t* text, int sz, char* out_buf);

#ifdef __cplusplus
}
#endif

#endif

