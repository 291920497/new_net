#ifndef _SOCK_SESSION_H_
#define _SOCK_SESSION_H_

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#include <unistd.h>
#include <sys/socket.h>
#include <sys/epoll.h>
#include <arpa/inet.h>

#include <signal.h>
#include <assert.h>
#include <errno.h>

#include "list.h"

#include "netio_buffer.h"
#include "tcp_protocol.h"
#include "websocket_protocol.h"

//-std=gnu9x 

/**
*	Optimization plan
*	1. Add session object pool
*	2. Different broadcast for different monitors, plan need @uuid_hash, filter is -1
*	3. If necessary in the future, Variable input buffer length
*/
#define MAX_EPOLL_SIZE (512)

#define MAX_HEART_TIMEOUT (10)
#define MAX_RECONN_SERVER_TIMEOUT (5)


#ifdef __cplusplus
extern "C"
{
#endif

/**
*	Protocol-Communication
*/
typedef enum session_protocol_communication {
	PROTO_COMMU_TCP_BINARY,
	PROTO_COMMU_TCP_JSON,
	PROTO_COMMU_WEBSOCKET_BINARY,
	PROTO_COMMU_WEBSOCKET_JSON,
	PROTO_COMMU_DIY,
}session_proto_commu_t;

typedef enum log_level {
	LOG_LEVEL_DEBUG,
	LOG_LEVEL_INFO,
	LOG_LEVEL_WARN,
	LOG_LEVEL_ERROR,
}log_level_t;

/**
*	session_flag_t - Flag session needs
*	@bit_closed: session is closed
*	@bit_etmod: The fd in the session are made of ET
*	@bit_is_server: The fd is server type
*	@bit_proto_commu: protocol-communication adopted
*	@bit_ping: Ping is currently initiated
*	@bit_web_handshake: Does websocket complete handshake
*	@bit_diy1: User can add
*/
typedef struct session_flag {
	int bit_closed : 1;
	int bit_etmod : 1;
	int bit_is_server : 1;
	session_proto_commu_t bit_proto_commu : 4;

	int bit_ping : 1;				
	int bit_web_handshake : 1;		
	int bit_diy1 : 1;				
}session_flag_t;

/**
*	@bit_closed: Does the manager contain close event
*	@bit_running: Is the manager running
*/
typedef struct manager_flag {
	char bit_closed : 1;
	char bit_running : 1;
}manager_flag_t;

struct sock_manager;
typedef struct sock_manager sock_manager_t;
struct sock_session;
typedef struct sock_session sock_session_t;


/**
*	@i_buf:	input buffer module
*	@o_buf: output buffer module, see netio_buffer.h
*	@manager_ptr: whitch manager contains session 
*	@on_recv_cb: readable events callback function
*	@on_protocol_recv_cb: communication-protocol recv callback function
*	@on_protocol_ping_cb: communication-protocol ping package function 
*	@on_complate_pkg_cb: callback of a complate package
*	@on_protocol_send_cb: communication-protocol send function
*	@on_disconn_event_cb: session before destruction
*/

typedef struct sock_session {
	int32_t			fd;
	session_flag_t	flag;		
	int32_t			epoll_state;			//epoll state flag
	uint64_t		last_active;			//last active time
	uint64_t		destruction_time;		//delay destruction time

	char			uuid[40];				//uuid
	uint32_t		uuid_hash;				//uuid hash value

	uint16_t		port;	
	char			ip[32];

	neti_buffer_t		i_buf;				
	neto_buffer_t		o_buf;				

	sock_manager_t*	manager_ptr;			
	void*			user_data;				

	void (*on_recv_cb)(sock_session_t*);	
	void (*on_protocol_recv_cb)(sock_session_t*);	
	void (*on_protocol_ping_cb)(sock_session_t*);	
	void (*on_complate_pkg_cb)(sock_session_t*, char*, uint32_t);
	int (*on_protocol_send_cb)(sock_session_t*, const char*, unsigned int);
	void (*on_disconn_event_cb)(sock_session_t*);

	list_head_t		elem_online;
	list_head_t		elem_offline;
	list_head_t		elem_servers;
	list_head_t		elem_listens;
	list_head_t		elem_pending_recv;
	list_head_t		elem_pending_send;
}sock_session_t;

//typedef struct sock_manager {
//	list_head_t list_online;
//	list_head_t list_offline;
//	list_head_t list_servers;
//	list_head_t list_listens;
//	list_head_t list_pending_recv;
//	list_head_t list_pending_send;
//
//	heap_timer_t* ht_timer;
//	int ep_fd;
//	manager_flag_t mng_flag;
//
//	log_level_t loglevel;
//	void* user_data;
//	char log_buffer[512];
//	void (*on_log)(log_level_t, char[512], void*);
//}sock_manager_t;

typedef struct sock_manager sock_manager_t;

/*
	websocket expand
*/
struct websock_protocol {
	unsigned int ws_name_hash;
	void (*ws_complate_pkg_cb)(struct sock_manager*, struct sock_session*, char*, unsigned short);
};

/**
*	sm_init_manager - Initialization manager
*	return the new manager, or -1 for errno
*/
sock_manager_t* sm_init_manager();


/**
*	sm_exit_manager - destruction manager
*	@sm: Created by sm_init_manager
*/
void sm_exit_manager(sock_manager_t* sm);

/*
	sm_ep_add_event,sm_ep_del_event - Add or Del epoll mode (EPOLLIN/EPOLLOUT)
*/
int sm_ep_add_event(struct sock_manager* sm, struct sock_session* ss, unsigned int epoll_event);

int sm_ep_del_event(struct sock_manager* sm, struct sock_session* ss, unsigned int epoll_event);

/**
*	running: is it running (0/~0)
*/
void sm_set_running(sock_manager_t* sm, uint8_t running);

/**
*	sm_add_defult_listen - Add a default protocol listener
*	@listen_port: Listening port
*	return 0 success, or -1 for error
*/
int sm_add_defult_listen(sock_manager_t* sm, uint16_t listen_port, uint32_t max_listen, session_proto_commu_t proto_commu, uint8_t enable_et,
	uint32_t client_min_recv_len, uint32_t client_max_recv_len, uint32_t client_min_send_len, uint32_t client_max_send_len,
	void (*client_on_complate_pkg_cb)(sock_session_t*, char*, uint32_t),
	void (*client_on_disconn_event_cb)(sock_session_t*),
	void* user_data);

/**
*	sm_add_diy_listen - Add a diy protocol listener
*	return 0 success, or -1 for error
*/
int sm_add_diy_listen(sock_manager_t* sm, uint16_t listen_port, uint32_t max_listen, uint8_t enable_et,
	uint32_t client_min_recv_len, uint32_t client_max_recv_len, uint32_t client_min_send_len, uint32_t client_max_send_len,
	void (*client_on_protocol_recv_cb)(sock_session_t*),
	int (*client_on_protocol_send_cb)(sock_session_t*, const char*, unsigned int),
	void (*client_on_protocol_ping_cb)(sock_session_t*),
	void (*client_on_complate_pkg_cb)(sock_session_t*, char*, uint32_t),
	void (*client_on_disconn_event_cb)(sock_session_t*),
	void* user_data);

/**
*	sm_add_client_session - Add a client session
*	return new session object, or 0 for error
*/
sock_session_t* sm_add_client_session(sock_manager_t* sm, int fd, const char* ip, uint16_t port, session_proto_commu_t proto_commu,uint8_t enable_et, uint8_t add_online,
	uint32_t min_recv_len, uint32_t max_recv_len, uint32_t min_send_len, uint32_t max_send_len,
	void (*on_protocol_recv_cb)(sock_session_t*),
	void (*on_protocol_ping_cb)(sock_session_t*),
	void (*on_complate_pkg_cb)(sock_session_t*, char*, uint32_t),
	int (*on_protocol_send_cb)(sock_session_t*, const char*, unsigned int),
	void (*on_disconn_event_cb)(sock_session_t*),
	void* user_data);

/**
*	sm_add_default_server_sessison - Add a default server session
*	return new session object, or 0 for error
*/
sock_session_t* sm_add_default_server_sessison(sock_manager_t* sm, const char* ip, uint16_t port, session_proto_commu_t proto_commu, uint8_t enable_et,
	uint32_t min_recv_len, uint32_t max_recv_len, uint32_t min_send_len, uint32_t max_send_len,
	void (*on_complate_pkg_cb)(sock_session_t*, char*, uint32_t),
	void (*on_disconn_event_cb)(sock_session_t*),
	void* user_data);

sock_session_t* sm_add_diy_server_session(sock_manager_t* sm, const char* ip, uint16_t port, uint8_t enable_et,
	uint32_t min_recv_len, uint32_t max_recv_len, uint32_t min_send_len, uint32_t max_send_len,
	void (*on_protocol_recv_cb)(sock_session_t*),
	void (*on_protocol_ping_cb)(sock_session_t*),
	void (*complate_pkg_cb)(sock_session_t*, char*, unsigned int),
	int (*on_protocol_send_cb)(sock_session_t*, const char*, unsigned int),
	void (*on_disconn_event_cb)(sock_session_t*),
	void* user_data);

/**
*	sm_del_session - Disconnect the session from the manager and delay the recovery
*	@ss: recovery session object
*	@delay_destruction: delay time(second)
*/
void sm_del_session(sock_session_t* ss, uint32_t delay_destruction);

/**
*	sm_add_timer - Add a timer event
*	@interval_ms: interval (millisecond)
*	@repeat: repeat times (-1: unlimited)
*	return timer id, or -1 for error
*/
uint32_t sm_add_timer(sock_manager_t* sm, uint32_t interval_ms, int32_t repeat, void(*callback_function)(void*), void* user_data);

/**
*	sm_del_timer - Remove a timer event
*	@timer_id: Created by sm_add_timer
*	@is_incallback: Call in callback function
*/
void sm_del_timer(sock_manager_t* sm, uint32_t timer_id, uint32_t is_incallback);

int sm_add_signal(sock_manager_t* sm, uint32_t sig, void (*cb)(int));

/**
*	sm_clear_offline - Clean up offline session
*/
void sm_clear_offline(sock_manager_t* sm);

/**
*	sm_broadcast_online - Broadcast data to online session
*/
void sm_broadcast_online(sock_manager_t* sm, const char* data, uint32_t data_len);

/**
*	sm_session_uuid - Get session uuid
*	return uuid, or null for error
*/
static const char* sm_session_uuid(sock_session_t* ss){
	if (ss)
		return ss->uuid;
	return 0;
}

/**
*	sm_session_hash - Get session uuid_hash
*	return uuid_hash, or 0 for error
*/
static uint32_t sm_session_hash(sock_session_t* ss) {
	if (ss)
		return ss->uuid_hash;
	return 0;
}

/**
*	sm_session_is_closed - Check whether the session is closed
*	return ~0 disconnect, or 0 for not disconnect
*/
static uint32_t sm_session_is_closed(sock_session_t* ss) {
	return ss->flag.bit_closed;
}

void sm_recv(sock_session_t* ss);

void sm_send(sock_session_t* ss);

/**
*	sm_pending_recv,sm_pending_send - Handling read / write pending events
*/
void sm_pending_recv(sock_manager_t* sm);

void sm_pending_send(sock_manager_t* sm);

int sm_run2(sock_manager_t* sm, uint64_t us);

int sm_run(sock_manager_t* sm);

#ifdef __cplusplus
}
#endif

#endif//_SOCK_SESSION_H_