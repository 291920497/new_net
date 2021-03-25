#ifndef _WEBSOCKET_PROTOCOL_H_
#define _WEBSOCKET_PROTOCOL_H_

#include <stdint.h>

#ifdef __cplusplus
extern "C"
{
#endif

struct sock_session;
struct session_manager;

void web_protocol_recv(struct sock_session* ss);

int web_protocol_send(struct sock_session* ss, const char* data, unsigned short data_len);

void web_protocol_ping(struct sock_session* ss);

#ifdef __cplusplus
}
#endif

#endif//_WEBSOCKET_PROTOCOL_H_