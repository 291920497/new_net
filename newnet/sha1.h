#ifndef __CRYPT_SHA1_
#define __CRYPT_SHA1_

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

char* sz_sha1(uint8_t* buffer, int sz, char* out_buf);

#ifdef __cplusplus
}
#endif


#endif

