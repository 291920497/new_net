#include "sock_session.h"
#include "netio_buffer.h"

#include "../tools/heap_timer.h"
#include "../tools/basic_tools.h"

typedef struct sock_manager {
	list_head_t list_online;
	list_head_t list_offline;
	list_head_t list_servers;
	list_head_t list_listens;
	list_head_t list_pending_recv;
	list_head_t list_pending_send;

	heap_timer_t* ht_timer;
	int ep_fd;
	manager_flag_t mng_flag;

	log_level_t loglevel;
	void* user_data;
	char log_buffer[512];
	void (*on_log)(log_level_t, char[512], void*);
}sock_manager_t;

typedef enum CREATE_SOCKFD_CTL {
	CREATE_SOCK_SOCKET,
	CREATE_SOCK_ACCPTE,
}CREATE_SOCKFD_CTL_ENUM;

/**
*	s_cache_session - Get a session object and initialization I/O buffer
*/
static sock_session_t* s_cache_session(sock_manager_t* sm, uint32_t min_recv_len, uint32_t max_recv_len, uint32_t min_send_len, uint32_t max_send_len) {
	int ret_flag = 0;
	sock_session_t* ss = (sock_session_t*)malloc(sizeof(sock_session_t));
	if (ss) {
		memset(ss, 0, sizeof(sock_session_t));

		ss->fd = -1;

		if (netio_ibuf_init(&(ss->i_buf), min_recv_len, max_recv_len))
			ret_flag = 1;
		if(netio_obuf_init(&(ss->o_buf), min_send_len, max_send_len))
			ret_flag = 1;

		if (ret_flag) {
			netio_ibuf_destroy(&(ss->i_buf));
			netio_obuf_destroy(&(ss->o_buf));
			free(ss);
			return 0;
		}

		INIT_LIST_HEAD(&ss->elem_online);
		INIT_LIST_HEAD(&ss->elem_offline);
		INIT_LIST_HEAD(&ss->elem_servers);
		INIT_LIST_HEAD(&ss->elem_listens);
		INIT_LIST_HEAD(&ss->elem_pending_recv);
		INIT_LIST_HEAD(&ss->elem_pending_send);


		return ss;
	}

	return 0;
}

/**
*	s_free_session - Recover session object
*/
static void s_free_session(sock_manager_t* sm, sock_session_t* ss) {
	//disconnect all session
	list_del_init(&ss->elem_online);
	list_del_init(&ss->elem_offline);
	list_del_init(&ss->elem_servers);
	list_del_init(&ss->elem_listens);
	list_del_init(&ss->elem_pending_recv);
	list_del_init(&ss->elem_pending_send);

	netio_ibuf_destroy(&(ss->i_buf));
	netio_obuf_destroy(&(ss->o_buf));
	free(ss);
	
	//You can try caching objects for reuse
}

/**
*	s_try_socket - Try to create a sock fileno
*/
static int s_try_socket(int _domain,int _type,int _protocol) {
	int fd, try_count = 1;
	do {
		fd = socket(AF_INET, SOCK_STREAM, 0);
		//failed and no attempt
		if (fd == -1 && try_count) {
			--try_count;

			if (tools_nofile_ckup() == 0)
				continue;
		}
	} while (0);
	return fd;
}

/**
*	s_try_accept - Try to accept a sock fileno
*/
static int s_try_accept(int __fd, __SOCKADDR_ARG __addr, socklen_t* __restrict __addr_len) {
	int fd = -1, try_count = 1;
	do {
		fd = accept(__fd, __addr, __addr_len);
		if (fd == -1) {
			int err = errno;

			//is nothing
			if (err == EAGAIN)
				return -2;
			//If the error is caused by fileno and the processing is complete
			else if (err == EMFILE && try_count) {
				--try_count;
				if (tools_nofile_ckup() == 0)
					continue;
			}
			return -1;
		}
		//if (fd == -1 && try_count) {
		//	--try_count;
		//	
		//	if (tools_nofile_ckup() == 0)
		//		continue;
		//}
	} while (0);
	return fd;
}

static void s_construction_session(sock_manager_t* sm, sock_session_t*ss, int fd, const char* ip, uint16_t port, uint8_t enable_et, void* user_data) {
	ss->fd = fd;

	unsigned int len = strlen(ip);
	if (len > 31) { len = 31; }
	strncpy(ss->ip, ip, len + 1);

	ss->port = port;
	ss->last_active = time(0);
	ss->destruction_time = -1;

	tools_get_uuid_r(ss->uuid);
	ss->uuid_hash = tools_hash_func(ss->uuid, -1);

	ss->manager_ptr = sm;
	ss->user_data = user_data;

	if (enable_et) {
		ss->flag.bit_etmod = enable_et == 0 ? 0 : ~0;
		ss->epoll_state |= EPOLLET;
		tools_set_nonblocking(fd);
	}
}

static void s_del_session(sock_session_t* ss, uint32_t delay_destruction) {
	if (ss) {
		ss->flag.bit_closed = ~0;
		ss->manager_ptr->mng_flag.bit_closed = ~0;

		ss->i_buf.recv_len = 0;
		ss->i_buf.recv_idx = 0;

		ss->o_buf.send_len = 0;

		if (delay_destruction) {
			if (delay_destruction == -1)
				ss->destruction_time = -1;
			else
				ss->destruction_time = time(0) + delay_destruction;
		}
		else
			ss->destruction_time = 0;

		sm_ep_del_event(ss->manager_ptr, ss, EPOLLIN | EPOLLOUT);

		//if in recv pending
		if (list_empty(&ss->elem_pending_recv) == 0)
			list_del_init(&ss->elem_pending_recv);
		//if in write pending
		if (list_empty(&ss->elem_pending_send) == 0)
			list_del_init(&ss->elem_pending_send);

		if (ss->on_disconn_event_cb) {
			ss->on_disconn_event_cb(ss);
		}
	}
}


/*
	重新连接服务去
*/

/**
*	s_reconnect_server - try reconnection to the server
*	@ss: Object waiting to be processed
*/
static int s_reconnect_server(sock_session_t* ss) {	
	if (ss->fd != -1) {
		close(ss->fd);
		ss->fd = -1;
	}

	struct sockaddr_in sin;
	int fd, ret;
	fd = s_try_socket(AF_INET, SOCK_STREAM, 0);
	if (fd == -1)
		return -1;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(ss->port);
	sin.sin_addr.s_addr = inet_addr(ss->ip);

	ss->fd = fd;
	ret = connect(ss->fd, (const struct sockaddr*) & sin, sizeof(sin));

	//If connect error
	if (ret == -1 && errno != EINPROGRESS) {
		//set need reconnect
		ss->flag.bit_closed = ~0;
		return -1;
	}
	//If you are in the third handshake pending, it's not a error
	else {
		ret = sm_ep_add_event(ss->manager_ptr, ss, EPOLLIN);
		if (ret) {
			printf("[%s] [%s:%d] [%s] Add event failed, ip: [%s], port: [%d] errmsg: [%s]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, strerror(errno));
			return -1;
		}
			
		ss->flag.bit_closed = 0;
	}
	return 0;
}

/*
	timer callback
*/

//heart callback
static void cb_on_heart_timeout(uint32_t timer_id, void* p) {
	sock_manager_t* sm = (sock_manager_t*)p;

	uint64_t cur_t = time(0);

	sock_session_t* pos, * n;
	list_for_each_entry_safe(pos, n, &sm->list_online, elem_online) {
		if ((cur_t - pos->last_active) > MAX_HEART_TIMEOUT) {
			if (pos->flag.bit_ping == 0 && pos->on_protocol_ping_cb) {
				pos->on_protocol_ping_cb(pos);
			}
			else {
				printf("[%s] [%s:%d] [%s] Remove session, ip: [%s], port: [%d] errmsg: [on heart time out]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port);
				sm_del_session(pos, pos->flag.bit_is_server ? -1 : 0);
			}
		}
	}
	/*
		此处需要注意，由于sm_del_client_session由服务器端主动从epoll移除，
		epoll将无法继续关注套接字的可读可写事件，
		且由于设计为延迟挥手，所以除非有新的事件发生否则客户端
		将推迟到下次事件产生才会收到挥手报文，
		这里为解决这个问题，将调用sm_clear_offline使未决事件提前处理
	*/
	sm_clear_offline(sm);
}

//reconnect server callback
static void cb_on_reconnection_timeout(uint32_t timer_id, void* p) {
	sock_manager_t* sm = (sock_manager_t*)p;

	int ret;
	uint64_t cur_t = time(0);

	sock_session_t* pos, * n;
	list_for_each_entry(pos, &(sm->list_servers), elem_servers) {
		if (pos->flag.bit_closed) {
			if (pos->destruction_time < cur_t)
				pos->manager_ptr->mng_flag.bit_closed = ~0;
			else {
				ret = s_reconnect_server(pos);
				if (ret == 0)
					printf("[%s] [%s:%d] [%s], ip: [%s], port: [%d], info: [ reconnect success ]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port);
			}
		}
	}
}


/*
	epoll event control
*/

int sm_ep_add_event(struct sock_manager* sm, struct sock_session* ss, unsigned int epoll_event) {
	//If the monitor status exists except for the ET flag
	if ((ss->epoll_state & (~(EPOLLET))) & epoll_event) {
		return 0;
	}

	struct epoll_event epev;
	epev.data.ptr = ss;
	int ctl = EPOLL_CTL_ADD;

	//If the original flag is not 0, the operation changes to modify
	if (ss->epoll_state & (~(EPOLLET))) {
		ctl = EPOLL_CTL_MOD;
	}

	ss->epoll_state |= epoll_event;
	epev.events = ss->epoll_state;

	return epoll_ctl(sm->ep_fd, ctl, ss->fd, &epev);
}

int sm_ep_del_event(struct sock_manager* sm, struct sock_session* ss, unsigned int epoll_event) {
	if (!((ss->epoll_state & (~(EPOLLET))) & epoll_event)) { return 0; }

	struct epoll_event epev;
	epev.data.ptr = ss;
	int ctl = EPOLL_CTL_DEL;

	if (ss->epoll_state & (~(EPOLLET | epoll_event))) {
		ctl = EPOLL_CTL_MOD;
	}

	ss->epoll_state &= (~epoll_event);
	epev.events = ss->epoll_state;

	return epoll_ctl(sm->ep_fd, ctl, ss->fd, &epev);
}


/*
	callback function
*/

static void accept_cb(sock_session_t* ss) {
	do {
		int ret;
		struct sockaddr_in c_sin;
		socklen_t s_len = sizeof(c_sin);
		memset(&c_sin, 0, sizeof(c_sin));

		int c_fd, try_count = 1;
		c_fd = s_try_accept(ss->fd, (struct sock_addr*) & c_sin, &s_len);
		if (c_fd == -2) {
			return;
		}
		else if (c_fd == -1) {
			printf("[%s] [%s:%d] [%s] Accept function failed. errmsg: [ %s ]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, strerror(errno));
			return;
		}
		/*if (c_fd == -1) {
			printf("[%s] [%s:%d] [%s] Accept function failed. errmsg: [ %s ]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, strerror(errno));
			return;
		}*/

		//tools_set_nonblocking(c_fd);

		void* cb_recv = 0, * cb_send = 0, * cb_ping = 0;

		switch (ss->flag.bit_proto_commu) {
		case PROTO_COMMU_TCP_BINARY:
			cb_recv = tcp_binary_protocol_recv;
			cb_send = tcp_binary_protocol_send;
			cb_ping = tcp_binary_protocol_ping;
			break;
		case PROTO_COMMU_TCP_JSON:
			cb_recv = tcp_json_protocol_recv;
			cb_send = tcp_json_protocol_send;
			cb_ping = tcp_json_protocol_ping;
			break;
		case PROTO_COMMU_WEBSOCKET_BINARY:
		case PROTO_COMMU_WEBSOCKET_JSON:
			cb_recv = web_protocol_recv;
			cb_send = web_protocol_send;
			cb_ping = web_protocol_ping;
			break;
		case PROTO_COMMU_DIY:
			cb_recv = ss->on_protocol_recv_cb;
			cb_send = ss->on_protocol_send_cb;
			cb_ping = ss->on_protocol_ping_cb;
			break;
		}

		const char* ip = inet_ntoa(c_sin.sin_addr);
		unsigned short port = ntohs(c_sin.sin_port);

		int et = 1;
		int add_online = 1;

		//ret = sm_add_client_session(ss->manager_ptr, c_fd, ip, port,ss->flag.bit_proto_commu, et, add_online,MIN_RECV_BUFFER_LENGTH,MAX_RECV_BUFFER_LENGTH,MIN_SEND_BUFFER_LENGTH,MAX_SEND_BUFFER_LENGTH, cb_recv, cb_ping, ss->on_complate_pkg_cb, cb_send, ss->on_disconn_event_cb, ss->user_data);
		ret = sm_add_client_session(ss->manager_ptr, c_fd, ip, port, ss->flag.bit_proto_commu, et, add_online, ss->i_buf.recv_buf_length, ss->i_buf.recv_buf_max, ss->o_buf.send_buf_length, ss->o_buf.send_buf_max, cb_recv, cb_ping, ss->on_complate_pkg_cb, cb_send, ss->on_create_event_cb, ss->on_disconn_event_cb, ss->user_data);
		if (!ret) {
			close(c_fd);
			printf("[%s] [%s:%d] [%s] function return failed. errmsg: [ %s ], ip: [%s], port: [%d]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, strerror(errno), ip, port);
		}
		else {
			printf("[%s] [%s:%d] [%s] accept success. ip: [%s], port: [%d]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, ip, port);
		}
	} while (ss->flag.bit_etmod);


	
}



/*
	API
*/

sock_manager_t* sm_init_manager() {
	sock_manager_t* sm = (sock_manager_t*)malloc(sizeof(sock_manager_t));
	if (!sm)return 0;

	memset(sm, 0, sizeof(sock_manager_t));
	sm_set_running(sm, 1);

	//Init all list
	INIT_LIST_HEAD(&(sm->list_online));
	INIT_LIST_HEAD(&(sm->list_offline));
	INIT_LIST_HEAD(&(sm->list_servers));
	INIT_LIST_HEAD(&(sm->list_listens));
	INIT_LIST_HEAD(&(sm->list_pending_recv));
	INIT_LIST_HEAD(&(sm->list_pending_send));

	//inti timer manager
	sm->ht_timer = ht_create_heap_timer();
	if (sm->ht_timer == 0)
		goto sm_init_manager_failed;

	//init epoll, try twice
	sm->ep_fd = epoll_create(EPOLL_CLOEXEC);
	if (sm->ep_fd == -1) {
		sm->ep_fd = epoll_create(1 << 15);	//32768
		if (sm->ep_fd == -1) {
			goto sm_init_manager_failed;
		}
	}

	//add default timer
	//heart cb
	ht_add_timer(sm->ht_timer, MAX_HEART_TIMEOUT * 1000, 0, -1, cb_on_heart_timeout, sm);
	//server reconnect cb
	ht_add_timer(sm->ht_timer, MAX_RECONN_SERVER_TIMEOUT * 1000, 0, -1, cb_on_reconnection_timeout, sm);

	return sm;

sm_init_manager_failed:
	if (sm->ht_timer) {
		ht_destroy_heap_timer(sm->ht_timer);
	}
	if (sm) {
		free(sm);
	}
	return 0;
}

void sm_exit_manager(sock_manager_t* sm) {
	if (sm == 0)
		return;

	//clean resources and all session
	sock_session_t* pos, *n;
	list_for_each_entry_safe(pos, n, &sm->list_online, elem_online) {
		printf("[%s] [%s:%d] [%s] Clean Online session, ip: [%s], port: [%d] errmsg: [Active cleaning]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port);
		sm_del_session(pos, 0);
	}

	list_for_each_entry_safe(pos, n, &sm->list_servers, elem_servers) {
		printf("[%s] [%s:%d] [%s] Clean server session, ip: [%s], port: [%d] errmsg: [Active cleaning]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port);
		sm_del_session(pos, 0);
	}

	list_for_each_entry_safe(pos, n, &sm->list_listens, elem_listens) {
		printf("[%s] [%s:%d] [%s] Clean listener session, ip: [%s], port: [%d] errmsg: [Active cleaning]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port);
		close(pos->fd);
		list_del_init(&pos->elem_listens);
		s_free_session(sm, pos);
	}

	sm_clear_offline(sm);

	if (sm->ht_timer) {
		ht_destroy_heap_timer(sm->ht_timer);
	}
	if (sm) {
		free(sm);
	}
}

void sm_set_running(sock_manager_t* sm, uint8_t running) {
	if (sm) {
		if (running) {
			sm->mng_flag.bit_running = ~0;
		}
		else {
			sm->mng_flag.bit_running = 0;
		}
	}
}

int sm_add_defult_listen(sock_manager_t* sm, uint16_t listen_port, uint32_t max_listen, session_proto_commu_t proto_commu, uint8_t enable_et,
	uint32_t client_min_recv_len, uint32_t client_max_recv_len, uint32_t client_min_send_len, uint32_t client_max_send_len,
	void (*client_on_complate_pkg_cb)(sock_session_t*, char*, uint32_t),
	void (*client_on_create_event_cb)(sock_session_t*),
	void (*client_on_disconn_event_cb)(sock_session_t*),
	void* user_data) {
	if (sm == 0)
		return -1;

	int ret, err, optval = 1;
	int fd, try_count = 1;
	sock_session_t* ss = 0;
	//do {
	//	fd = socket(AF_INET, SOCK_STREAM, 0);
	//	//若失败且尚未尝试
	//	if (fd == -1 && try_count) {
	//		--try_count;

	//		if (tools_nofile_ckup() == 0)
	//			continue;
	//	}
	//} while (0);

	fd = s_try_socket(AF_INET, SOCK_STREAM, 0);
	//if create fileno failed
	if (fd == -1) {
		//if (sm->on_log) {
		//	sprintf(sm->log_buffer, "[%s:%d] Create nofile failed. errno: [%d]", __FILENAME__, __LINE__, errno);
		//	sm->on_log(LOG_LEVEL_ERROR, sm->log_buffer, sm->user_data);
		//}
		return -1;
	}

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(listen_port);
	sin.sin_addr.s_addr = INADDR_ANY;

	//address reuse
	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	ret = bind(fd, (const struct sockaddr*) & sin, sizeof(sin));
	if (ret == -1) 
		goto sm_add_defult_listen_failed;
	
	ret = listen(fd, max_listen);
	if (ret == -1)
		goto sm_add_defult_listen_failed;
	
	/*ss = (sock_session_t*)malloc(sizeof(sock_session_t));
	if (ss == 0) 
		goto sm_add_defult_listen_failed;*/

	ss = s_cache_session(sm, 0, 0, 0, 0);
	if (ss == 0)
		goto sm_add_defult_listen_failed;

	s_construction_session(sm, ss, fd, "0.0.0.0", listen_port, enable_et, user_data);
	//This is the parameter of the client
	ss->i_buf.recv_buf_length = client_min_recv_len;
	ss->i_buf.recv_buf_max = client_max_recv_len;
	ss->o_buf.send_buf_length = client_min_send_len;
	ss->o_buf.send_buf_max = client_max_send_len;
	ss->flag.bit_proto_commu = proto_commu;
	
	ss->on_recv_cb = accept_cb;
	ss->on_complate_pkg_cb = client_on_complate_pkg_cb;
	ss->on_disconn_event_cb = client_on_disconn_event_cb;
	ss->on_create_event_cb = client_on_create_event_cb;

	//add to listener list
	list_add_tail(&(ss->elem_listens), &(sm->list_listens));

	//add epoll status
	ret = sm_ep_add_event(sm, ss, EPOLLIN);
	if (ret)
		goto sm_add_defult_listen_failed;

	printf("[%s] [%s:%d] [%s] Add default listener, port: [%d] info: [Success]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, listen_port);
	return 0;

sm_add_defult_listen_failed:
	if (ss) {
		free(ss);
	}
	if (fd != -1) {
		close(fd);
	}
	printf("[%s] [%s:%d] [%s] Add default listener port: [%d] errmsg: [%s]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, listen_port, strerror(errno));
	return -1;
}

int sm_add_diy_listen(sock_manager_t* sm, uint16_t listen_port, uint32_t max_listen, uint8_t enable_et,
	uint32_t client_min_recv_len, uint32_t client_max_recv_len, uint32_t client_min_send_len, uint32_t client_max_send_len,
	void (*client_on_protocol_recv_cb)(sock_session_t*),
	int (*client_on_protocol_send_cb)(sock_session_t*, const char*, unsigned int),
	void (*client_on_protocol_ping_cb)(sock_session_t*),
	void (*client_on_complate_pkg_cb)(sock_session_t*, char*, uint32_t),
	void (*client_on_create_event_cb)(sock_session_t*),
	void (*client_on_disconn_event_cb)(sock_session_t*),
	void* user_data) {
	
	if (sm == 0)
		return -1;

	int ret, err, optval = 1;
	int fd, try_count = 1;
	sock_session_t* ss;
	//do {
	//	fd = socket(AF_INET, SOCK_STREAM, 0);
	//	//若失败且尚未尝试
	//	if (fd == -1 && try_count) {
	//		--try_count;

	//		if (tools_nofile_ckup() == 0)
	//			continue;
	//	}
	//} while (0);

	fd = s_try_socket(AF_INET, SOCK_STREAM, 0);
	//if create fileno failed
	if (fd == -1) {
		/*if (sm->on_log) {
			sprintf(sm->log_buffer, "[%s:%d] Create nofile failed. errno: [%d]", __FILENAME__, __LINE__, errno);
			sm->on_log(LOG_LEVEL_ERROR, sm->log_buffer, sm->user_data);
		}*/
		return -1;
	}

	struct sockaddr_in sin;
	sin.sin_family = AF_INET;
	sin.sin_port = htons(listen_port);
	sin.sin_addr.s_addr = INADDR_ANY;

	//address reuse
	ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &optval, sizeof(optval));

	ret = bind(fd, (const struct sockaddr*) & sin, sizeof(sin));
	if (ret == -1)
		goto sm_add_diy_listen_failed;

	ret = listen(fd, max_listen);
	if (ret == -1) 
		goto sm_add_diy_listen_failed;

	//ss = (sock_session_t*)malloc(sizeof(sock_session_t));
	ss = s_cache_session(sm,0,0,0,0);
	if (ss == 0)
		goto sm_add_diy_listen_failed;

	s_construction_session(sm, ss, fd, "0,0,0,0", listen_port, enable_et, user_data);
	ss->i_buf.recv_buf_length = client_min_recv_len;
	ss->i_buf.recv_buf_max = client_max_recv_len;
	ss->o_buf.send_buf_length = client_min_send_len;
	ss->o_buf.send_buf_max = client_max_send_len;
	ss->flag.bit_proto_commu = PROTO_COMMU_DIY;

	ss->on_recv_cb = accept_cb;
	ss->on_protocol_recv_cb = client_on_protocol_recv_cb;
	ss->on_protocol_send_cb = client_on_protocol_send_cb;
	ss->on_protocol_ping_cb = client_on_protocol_ping_cb;
	ss->on_complate_pkg_cb = client_on_complate_pkg_cb;
	ss->on_disconn_event_cb = client_on_disconn_event_cb;
	ss->on_create_event_cb = client_on_create_event_cb;

	list_add_tail(&(ss->elem_listens), &(sm->list_listens));

	ret = sm_ep_add_event(sm, ss, EPOLLIN);
	if (ret) 
		goto sm_add_diy_listen_failed;

	printf("[%s] [%s:%d] [%s] Add diy listener, port: [%d] info: [Success]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, listen_port);
	return 0;

sm_add_diy_listen_failed:
	if (ss) {
		free(ss);
	}
	if (fd != -1) {
		close(fd);
	}
	printf("[%s] [%s:%d] [%s] Add diy listener, port: [%d] errmsg: [%s]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, listen_port, strerror(errno));
	return -1;
}

sock_session_t* sm_add_client_session(sock_manager_t* sm, int fd, const char* ip, uint16_t port, session_proto_commu_t proto_commu ,uint8_t enable_et, uint8_t add_online,
	uint32_t min_recv_len, uint32_t max_recv_len, uint32_t min_send_len, uint32_t max_send_len,
	void (*on_protocol_recv_cb)(sock_session_t*),
	void (*on_protocol_ping_cb)(sock_session_t*),
	void (*on_complate_pkg_cb)(sock_session_t*, char*, uint32_t),
	int (*on_protocol_send_cb)(sock_session_t*, const char*, unsigned int),
	void (*on_create_event_cb)(sock_session_t*),
	void (*on_disconn_event_cb)(sock_session_t*),
	void* user_data) {

	if (sm == 0 || fd == -1)
		return 0;

	sock_session_t* ss = s_cache_session(sm, min_recv_len, max_recv_len, min_send_len, max_send_len);
	if(ss == 0)
		return 0;

	s_construction_session(sm, ss, fd, ip, port, enable_et, user_data);
	ss->flag.bit_proto_commu = proto_commu;
	//ss->fd = fd;
	//unsigned int len = strlen(ip);
	//if (len > 31) { len = 31; }
	//strncpy(ss->ip, ip, len);

	//ss->port = port;
	//ss->last_active = time(0);
	//ss->destruction_time = -1;

	////记住修改add_listen内的epoll_state
	//if (enable_et) {
	//	ss->flag.bit_etmod = enable_et == 0 ? 0 : ~0;
	//	ss->epoll_state |= EPOLLET;
	//}

	//tools_get_uuid_r(ss->uuid);
	//ss->uuid_hash = tools_hash_func(ss->uuid, -1);

	//ss->manager_ptr = sm;
	//ss->user_data = user_data;
	
	ss->on_recv_cb = sm_recv;
	ss->on_protocol_recv_cb = on_protocol_recv_cb;
	ss->on_protocol_ping_cb = on_protocol_ping_cb;
	ss->on_complate_pkg_cb = on_complate_pkg_cb;
	ss->on_protocol_send_cb = on_protocol_send_cb;
	ss->on_disconn_event_cb = on_disconn_event_cb;
	ss->on_create_event_cb = on_create_event_cb;

	int ret = sm_ep_add_event(sm, ss, EPOLLIN);
	if (ret) {
		s_free_session(sm, ss);
		return 0;
	}

	if (add_online) {
		list_add_tail(&(ss->elem_online), &(sm->list_online));
	}

	if (ss->on_create_event_cb)
		ss->on_create_event_cb(ss);

	return ss;
}

sock_session_t* sm_add_default_server_sessison(sock_manager_t* sm, const char* ip, uint16_t port, session_proto_commu_t proto_commu, uint8_t enable_et,
	uint32_t min_recv_len, uint32_t max_recv_len, uint32_t min_send_len, uint32_t max_send_len,
	void (*on_complate_pkg_cb)(sock_session_t*, char*, uint32_t),
	void (*on_create_event_cb)(sock_session_t*),
	void (*on_disconn_event_cb)(sock_session_t*),
	void* user_data) {
	
	void* cb_recv = 0, * cb_send = 0, * cb_ping = 0;

	switch (proto_commu) {
	case PROTO_COMMU_TCP_BINARY:
		cb_recv = tcp_binary_protocol_recv;
		cb_send = tcp_binary_protocol_send;
		cb_ping = tcp_binary_protocol_ping;
		break;
	case PROTO_COMMU_TCP_JSON:
		cb_recv = tcp_json_protocol_recv;
		cb_send = tcp_json_protocol_send;
		cb_ping = tcp_json_protocol_ping;
		break;
	case PROTO_COMMU_WEBSOCKET_BINARY:
	case PROTO_COMMU_WEBSOCKET_JSON:
		cb_recv = web_protocol_recv;
		cb_send = web_protocol_send;
		cb_ping = web_protocol_ping;
		break;
	}

	sock_session_t* ss = sm_add_diy_server_session(sm, ip, port, enable_et, min_recv_len, max_recv_len, min_send_len, max_send_len,
		cb_recv, cb_ping, on_complate_pkg_cb, cb_send, on_create_event_cb, on_disconn_event_cb, user_data);

	//update to param value
	if (ss) {
		ss->flag.bit_proto_commu = proto_commu;
		return ss;
	}

	return 0;
}

sock_session_t* sm_add_diy_server_session(sock_manager_t* sm, const char* ip, uint16_t port, uint8_t enable_et,
	uint32_t min_recv_len, uint32_t max_recv_len, uint32_t min_send_len, uint32_t max_send_len,
	void (*on_protocol_recv_cb)(sock_session_t*),
	void (*on_protocol_ping_cb)(sock_session_t*),
	void (*on_complate_pkg_cb)(sock_session_t*, char*, unsigned int),
	int (*on_protocol_send_cb)(sock_session_t*, const char*, unsigned int),
	void (*on_create_event_cb)(sock_session_t*),
	void (*on_disconn_event_cb)(sock_session_t*),
	void* user_data) {

	if (sm == 0)
		return 0;

	struct sockaddr_in sin;
	int fd, ret;
	fd = s_try_socket(AF_INET, SOCK_STREAM, 0);
	sock_session_t* ss = s_cache_session(sm, min_recv_len, max_recv_len, min_send_len, max_send_len);
	if (sm == 0 || fd == -1 || ss == 0)
		goto sm_add_server_session_failed;

	s_construction_session(sm, ss, fd, ip, port, enable_et, user_data);
	ss->flag.bit_is_server = ~0;
	ss->flag.bit_proto_commu = PROTO_COMMU_DIY;

	ss->on_recv_cb = sm_recv;
	ss->on_protocol_recv_cb = on_protocol_recv_cb;
	ss->on_protocol_ping_cb = on_protocol_ping_cb;
	ss->on_complate_pkg_cb = on_complate_pkg_cb;
	ss->on_protocol_send_cb = on_protocol_send_cb;
	ss->on_disconn_event_cb = on_disconn_event_cb;
	ss->on_create_event_cb = on_create_event_cb;

	sin.sin_family = AF_INET;
	sin.sin_port = htons(port);
	sin.sin_addr.s_addr = inet_addr(ip);

	ret = connect(fd, (const struct sockaddr*) & sin, sizeof(sin));
	
	//if connect error
	if (ret == -1 && errno != EINPROGRESS) {
		////set need reconnect
		ss->flag.bit_closed = ~0;
	}
	////If you are in the third handshake pending, it's not a error
	else {
		ret = sm_ep_add_event(sm, ss, EPOLLIN);
		if (ret)
			goto sm_add_server_session_failed;
	}

	//If it is in ET mode and the connection fails, waiting reconnect
	if (enable_et == 0 && ss->flag.bit_closed) {
		goto sm_add_server_session_failed;
	}

	//add servers list
	list_add_tail(&(ss->elem_servers), &(sm->list_servers));
	printf("[%s] [%s:%d] [%s] Create server session, ip: [%s], port: [%d], info: [ success ]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port);

	if (ss->on_create_event_cb)
		ss->on_create_event_cb(ss);

	return ss;

sm_add_server_session_failed:
	if (fd != -1) 
		close(fd);
	if (ss) 
		s_free_session(sm, ss);
	return 0;
}

void sm_del_session(sock_session_t* ss, uint32_t delay_destruction) {
	if (ss == 0)
		return;

	s_del_session(ss, delay_destruction);

	/*
		Here, we need to consider making necessary changes according to the delay destruction of the session
	*/

	if (ss->flag.bit_is_server == 0) {
		//remove online
		list_del_init(&ss->elem_online);
		//add to offline
		//list_add_tail(&ss->manager_ptr->list_offline, &ss->elem_offline);
		list_add_tail(&ss->elem_offline ,&ss->manager_ptr->list_offline);
	}
}


uint32_t sm_add_timer(sock_manager_t* sm, uint32_t interval_ms, uint32_t delay_ms, int32_t repeat, void(*callback_function)(uint32_t, void*), void* user_data) {
	if (sm == 0 || sm->ht_timer == 0)
		return -1;

	return ht_add_timer(sm->ht_timer, interval_ms, delay_ms, repeat, callback_function, user_data);
}

/*
	移除一个定时器
*/

void sm_del_timer(sock_manager_t* sm, uint32_t timer_id, uint32_t is_incallback) {
	if (sm == 0 || timer_id < 0)
		return;

	if (is_incallback)
		ht_del_timer_incallback(sm->ht_timer, timer_id);
	else
		ht_del_timer(sm->ht_timer, timer_id);
}

/*
	信号处理
*/

int sm_add_signal(sock_manager_t* sm, uint32_t sig, void (*cb)(int)) {
	struct sigaction new_act;
	memset(&new_act, 0, sizeof(new_act));
	new_act.sa_handler = cb;
	sigfillset(&new_act.sa_mask);

	return sigaction(sig, &new_act, 0);
}


/*
	清理断开的session
*/

void sm_clear_offline(sock_manager_t* sm) {
	if (sm->mng_flag.bit_closed == 0)
		return;

	sock_session_t* pos, * n;

	//clean offline
	list_for_each_entry_safe(pos,n , &sm->list_offline, elem_offline) {
		//printf("[%s] [%s:%d] [%s] Clean offline session, ip: [%s], port: [%d] errmsg: [Active cleaning]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port);
		list_del_init(&pos->elem_offline);
		int ret = close(pos->fd);
		if (ret == -1) {
			printf("%s\n", strerror(errno));
		}
		s_free_session(sm, pos);
	}

	//clean up clients that need to be shut down immediately
	list_for_each_entry_safe(pos, n, &sm->list_servers, elem_servers) {
		if (pos->flag.bit_closed != 0 && pos->destruction_time < time(0)) {
			//printf("[%s] [%s:%d] [%s] Clean server session, ip: [%s], port: [%d] errmsg: [Active cleaning]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, pos->ip, pos->port);
			list_del_init(&pos->elem_servers);
			close(pos->fd);
			s_free_session(sm, pos);
		}
	}

	//update manager flag
	sm->mng_flag.bit_closed = 0;
}

void sm_broadcast_online(sock_manager_t* sm, const char* data, uint32_t data_len) {
	sock_session_t* pos, *n;
	list_for_each_entry_safe(pos, n, &sm->list_online, elem_online) {
		if (pos->flag.bit_closed == 0 && pos->on_protocol_send_cb) {
			pos->on_protocol_send_cb(pos, data, data_len);
		}
	}
}

void sm_recv(sock_session_t* ss) {
	if (ss->flag.bit_closed)
		return;

	uint32_t unused_len;
	const char* errmsg = 0;
	//if input buffer full
	int ret = netio_ibuf_check_full(&(ss->i_buf));
	if (ret)
		goto sm_recv_failed;

	unused_len = netio_ibuf_unused_length(&(ss->i_buf));
	int recved = recv(ss->fd, netio_ibuf_breakpoint(&(ss->i_buf)), unused_len, 0);
	if (recved == -1) {
		//If there is no data readability
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			//if in the recv pending
			if(list_empty(&ss->elem_pending_recv) == 0)
				list_del_init(&ss->elem_pending_recv);
			return;
		}
		//If it is caused by interruption
		else if (errno == EINTR) {
			//if not recv pending
			if(list_empty(&ss->elem_pending_recv) != 0)
				list_add_tail(&ss->elem_pending_recv ,&ss->manager_ptr->list_pending_recv);
			return;
		}
		ret = 1;
		goto sm_recv_failed;
	}
	//diconnect
	else if (recved == 0) {
		ret = 2;
		goto sm_recv_failed;
	}

	//If the length is less than the requested length
	/*
	if (recved < unused_len) {
		if (list_empty(&ss->elem_pending_recv) == 0)
			list_del_init(&ss->elem_pending_recv);

	}
	else {
		if (list_empty(&ss->elem_pending_recv) != 0)
			list_add_tail(&ss->elem_pending_recv, &ss->manager_ptr->list_pending_recv);
	}
	*/

	//et model add pending recv list
	if (ss->epoll_state & EPOLLET) {
		if (list_empty(&ss->elem_pending_recv) != 0)
			list_add_tail(&ss->elem_pending_recv, &ss->manager_ptr->list_pending_recv);
	}
	else {
		if (recved < unused_len) {
			if (list_empty(&ss->elem_pending_recv) == 0)
				list_del_init(&ss->elem_pending_recv);

		}
		else {
			if (list_empty(&ss->elem_pending_recv) != 0)
				list_add_tail(&ss->elem_pending_recv, &ss->manager_ptr->list_pending_recv);
		}
	}

	ss->i_buf.recv_len += recved;
	return;

sm_recv_failed:
	switch (ret) {
	case -1:
		errmsg = "User mode buffer full";
		break;
	case 2:
		errmsg = "client disconnect";
		break;
	default:
		errmsg = strerror(errno);
	}

	printf("[%s] [%s:%d] [%s] Remove session, ip: [%s], port: [%d] retcode: [%d] errmsg: [%s]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, ret, errmsg);
	sm_del_session(ss, ss->flag.bit_is_server ? -1 : 0);
}

void sm_send(sock_session_t* ss) {
	if (ss->flag.bit_closed)
		return;

	if (ss->o_buf.send_len) {
		int sended = send(ss->fd, ss->o_buf.send_buf, ss->o_buf.send_len, 0);
		if (sended == -1) {
			//If the interrupt or the kernel buffer is temporarily full
			if (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR) {
				//if (ss->elem_pending_send.next == 0)
				if (list_empty(&ss->elem_pending_send) != 0)
					list_add_tail(&ss->elem_pending_send, &ss->manager_ptr->list_pending_send);
				return;
			}
			//If is error
			else {
				//if (ss->elem_pending_send.next != 0)
				if (list_empty(&ss->elem_pending_send) == 0)
					list_del_init(&ss->elem_pending_send);
				goto sm_send_failed;
			}
		}

		//if not complated
		if (ss->o_buf.send_len - sended) {
			sm_ep_add_event(ss->manager_ptr, ss, EPOLLOUT);
			//move to head
			memmove(ss->o_buf.send_buf, ss->o_buf.send_buf + sended, ss->o_buf.send_len - sended);
			//add send pending
			if (list_empty(&ss->elem_pending_send) != 0)
				list_add_tail(&ss->elem_pending_send, &ss->manager_ptr->list_pending_send);
		}
		//if complated
		else {
			sm_ep_del_event(ss->manager_ptr, ss, EPOLLOUT);
			//remove send pending
			if (list_empty(&ss->elem_pending_send) == 0)
				list_del_init(&ss->elem_pending_send);
		}

		ss->o_buf.send_len -= sended;
	}
	return;

sm_send_failed:
	
	printf("[%s] [%s:%d] [%s] Remove session, ip: [%s], port: [%d] errmsg: [%s]", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, strerror(errno));
	sm_del_session(ss, ss->flag.bit_is_server ? -1 : 0);
}

void sm_pending_recv(sock_manager_t* sm) {
	if (sm == 0)
		return;
	
	sock_session_t* pos, * n;
	if (list_empty(&sm->list_pending_recv) == 0) {
		list_for_each_entry_safe(pos, n, &sm->list_pending_recv, elem_pending_recv) {
			pos->on_recv_cb(pos);
			if (pos->on_protocol_recv_cb)
				pos->on_protocol_recv_cb(pos);
		}
	}

	/*
	int try_count = 2;
	sock_session_t* pos, * n;

	do {
		//若不为空则至多尝试一次
		if (list_empty(&sm->list_pending_recv) == 0)
			--try_count;
		else
			break;

		list_for_each_entry_safe(pos, n, &sm->list_pending_recv, elem_pending_recv) {
			pos->on_recv_cb(pos);
			if (pos->on_protocol_recv_cb)
				pos->on_protocol_recv_cb(pos);
		}
		
	} while (try_count);

	*/
}

void sm_pending_send(sock_manager_t* sm) {
	if (sm == 0)
		return;

	sock_session_t* pos, * n;
	if (list_empty(&sm->list_pending_send) == 0) {
		list_for_each_entry_safe(pos, n, &sm->list_pending_send, elem_pending_send) {
			sm_send(pos);
		}
	}

	/*
	int try_count = 2;
	sock_session_t* pos, * n;

	do {
		//若不为空则至多尝试一次
		if (list_empty(&sm->list_pending_send) == 0)
			--try_count;
		else
			break;

		list_for_each_entry_safe(pos, n, &sm->list_pending_send, elem_pending_send) {
			sm_send(pos);
		}
	} while (try_count);
	*/
}

int sm_run2(sock_manager_t* sm, uint64_t us) {
	struct epoll_event events[MAX_EPOLL_SIZE];

	int ret = epoll_wait(sm->ep_fd, events, MAX_EPOLL_SIZE, us);

	if (ret == -1) {
		if (errno != EINTR) { return -1; }
		return 0;
	}

	for (int i = 0; i < ret; ++i) {
		sock_session_t* ss = (struct sock_session*) events[i].data.ptr;
		if (events[i].events & EPOLLIN) {
			ss->on_recv_cb(ss);
			if (ss->i_buf.recv_len && ss->on_protocol_recv_cb) {
				ss->on_protocol_recv_cb(ss);
			}
		}
		if (events[i].events & EPOLLOUT) {
			sm_send(ss);
		}
	}

	sm_pending_send(sm);
	sm_pending_recv(sm);
	sm_clear_offline(sm);
	return 0;
}

int sm_run(sock_manager_t* sm) {
	while (sm->mng_flag.bit_running) {
		uint64_t wait_time = ht_update_timer(sm->ht_timer);

		//signal
		if (sm_run2(sm, wait_time) == 0) {
			if (errno == SIGQUIT)
				sm->mng_flag.bit_running = 0;
		}
	}
}