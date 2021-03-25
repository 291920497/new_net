#ifndef _TCP_PROTOCOL_H_
#define _TCP_PROTOCOL_H_

#include <stdint.h>

struct sock_session;
struct session_manager;

typedef struct ping_pkg {
	uint64_t ping;
}ping_pkg_t;

typedef struct pong_pkg {
	uint64_t pong;
}pong_pkg_t;

static uint32_t s_length_type;

#define TBINARY_LENGTH_TYPE uint32_t

//json heart
#define JSON_KEEPALIVE "KeepAlive"
static uint32_t s_json_keepalive_len = 9;	//strlen(JSON_KEEPALIVE)


#ifdef __cplusplus
extern "C"
{
#endif

//binary
void tcp_binary_protocol_recv(struct sock_session* ss);

int tcp_binary_protocol_send(struct sock_session* ss, const char* data, TBINARY_LENGTH_TYPE data_len);

void tcp_binary_protocol_ping(struct sock_session* ss);

int tcp_binary_protocol_pong(struct sock_session* ss, const char* heart_data, uint16_t data_len);



//json
void tcp_json_protocol_recv(struct sock_session* ss);

int tcp_json_protocol_send(struct sock_session* ss, const char* data, uint32_t data_len);

void tcp_json_protocol_ping(struct sock_session* ss);

int tcp_json_protocol_pong(struct sock_session* ss, const char* heart_data, uint16_t data_len);



#ifdef __cplusplus
}
#endif

#endif//_TCP_PROTOCOL_H_