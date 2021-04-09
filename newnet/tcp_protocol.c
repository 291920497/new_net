#include "tcp_protocol.h"
#include "sock_session.h"
//#include "netio_buffer.h"

#include "../tools/basic_tools.h"

//binary
void tcp_binary_protocol_recv(struct sock_session* ss) {
	if (ss->flag.bit_closed)
		return;

	int type_length = sizeof(TBINARY_LENGTH_TYPE);
	//若接收的长度标志不完整
	if (ss->i_buf.recv_len < type_length)
		return;

	uint32_t total = 0;
	do {
		//若剩余数据不满足一个完整的数据长度类型
		if (ss->i_buf.recv_len - total < type_length) {
			//若有数据已经被处理,则更改buffer
			if (total) {
				//还有剩余
				if (ss->i_buf.recv_len - total)
					memmove(ss->i_buf.recv_buf, ss->i_buf.recv_buf + total, ss->i_buf.recv_len - total);
				ss->i_buf.recv_len -= total;
			}
			break;
		}

		//typeof(s_length_type) pkg_len = *((typeof(s_length_type)*)(ss->i_buf.recv_buf + total));
		TBINARY_LENGTH_TYPE pkg_len = *((TBINARY_LENGTH_TYPE*)(ss->i_buf.recv_buf + total));

		//若单包长度超过最大长度-长度类型则关闭客户端
		if (pkg_len > (ss->i_buf.recv_buf_max - type_length) || !pkg_len) {
			printf("[%s:%d] function:[%s]  Remove session, ip: [%s], port: [%d], pkg_len: [%d], max_len: [%d], errmsg: [%s]\n", __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, pkg_len, ss->i_buf.recv_buf_max, "Received an incorrect packet length");
			sm_del_session(ss, ss->flag.bit_is_server ? -1 : 0);
			return;
		}
		else {
			//若已处理长度 + 当前包长度 + 当前包长类型 <= 接收长度 -> 未处理数据存在至少一个完整的数据包
			if ((total + pkg_len + type_length) <= ss->i_buf.recv_len) {
				//若这是一个心跳包则响应,否则回调
				if (!(pkg_len == sizeof(pong_pkg_t) && tcp_binary_protocol_pong(ss, ss->i_buf.recv_buf + total + type_length, pkg_len) == 0)) {
					if (ss->on_complate_pkg_cb) {
						ss->on_complate_pkg_cb(ss, ss->i_buf.recv_buf + total + type_length, pkg_len);
						ss->last_active = time(0);
						ss->flag.bit_ping = 0;
					}
				}
				total += (pkg_len + type_length);
			}
			//若剩下的数据无法组成一个完整的包
			else{
				//若有数据已经被处理,则更改buffer
				if (total) {
					//还有剩余
					if (ss->i_buf.recv_len - total) 
						memmove(ss->i_buf.recv_buf, ss->i_buf.recv_buf + total, ss->i_buf.recv_len - total);
					ss->i_buf.recv_len -= total;
				}
				return;
			}
		}
	} while (1);
}

int tcp_binary_protocol_send(struct sock_session* ss, const char* data, TBINARY_LENGTH_TYPE data_len) {
	if (ss->flag.bit_closed)
		return -1;

	if (!data_len)
		return 0;

	int type_length = sizeof(TBINARY_LENGTH_TYPE);
	//主要看这个函数调用的说明, type_length * 2 预留一个接收类型长度,偷懒 防止当前缓冲区达到临界值 例如: 剩下3字节,但是需要写入4字节的&data_len 
	//偷懒不想处理&data_len的分片
	int ret = netio_obuf_check_full(&ss->o_buf, data_len + type_length * 2);
	if (ret == 0) {
		memcpy(ss->o_buf.send_buf + ss->o_buf.send_len, &data_len, type_length);
		ss->o_buf.send_len += type_length;

		memcpy(ss->o_buf.send_buf + ss->o_buf.send_len, data, data_len);
		ss->o_buf.send_len += data_len;
	}
	//返回值1: 总待发送长度 大于最大长度并且小于最大长度的2倍
	else if (ret == 1) {
		uint32_t processed_len = 0;
		int unused_len = netio_obuf_unused_length(&ss->o_buf);
		//若能容纳,那么将长度及一部分数据写入缓冲区
		if (unused_len > type_length) {
			memcpy(ss->o_buf.send_buf + ss->o_buf.send_len, &data_len, type_length);
			ss->o_buf.send_len += type_length;

			//更新未使用的长度
			unused_len -= type_length;

			if (unused_len >= data_len) {
				unused_len -= data_len;
				processed_len += data_len;
			}
			else {
				unused_len = 0;
				processed_len += unused_len;
			}
			//将未使用的缓冲区塞满
			memcpy(ss->o_buf.send_buf + ss->o_buf.send_len, data, processed_len);
			ss->o_buf.send_len += processed_len;
		}
		//立即尝试发送
		sm_send(ss);
		//若在发送时已经被关闭
		if (ss->flag.bit_closed) 
			return -1;

		//再次校验
		ret = netio_obuf_check_full(&ss->o_buf, data_len - processed_len);
		if (ret == 1) {
			printf("[%s] [%s:%d] [%s] Remove session, ip: [%s], port: [%d] errmsg: [Kernel buffer full ,Remaining data out of buffer, Tried, but failed]\n", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port);
			sm_del_session(ss, ss->flag.bit_is_server ? -1 : 0);	
			return -1;
		}

		//校验通过则将剩余数据拷贝进缓冲区
		memcpy(ss->o_buf.send_buf + ss->o_buf.send_len, data + processed_len, data_len - processed_len);
		ss->o_buf.send_len += (data_len - processed_len);
	}
	else {
		//打印错误
		printf("[%s] [%s:%d] [%s] Remove session, ip: [%s], port: [%d] errmsg: [%s]\n ", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "The data length exceeds twice the buffer");
		sm_del_session(ss, ss->flag.bit_is_server ? -1 : 0);
		return -1;
	}

	return sm_ep_add_event(ss->manager_ptr, ss, EPOLLOUT);
}

void tcp_binary_protocol_ping(struct sock_session* ss) {
	int type_length = sizeof(TBINARY_LENGTH_TYPE);
	int ret = netio_obuf_check_full(&ss->o_buf, type_length + sizeof(ping_pkg_t));
	//能容纳则写,否则放弃
	if (ret == 0) {
		ping_pkg_t pp;
		pp.ping = 0xFF0DFF0AFF0DFF0A;
		if (ss->on_protocol_send_cb) {
			ss->on_protocol_send_cb(ss, &pp, sizeof(pp));
			ss->flag.bit_ping = ~0;
		}
	}
}

int tcp_binary_protocol_pong(struct sock_session* ss, const char* heart_data, uint16_t data_len) {
	ping_pkg_t pi;
	pi.ping = 0xFF0DFF0AFF0DFF0A;

	pong_pkg_t po;
	po.pong = 0xFFFFFFFFFFFFFFFF;

	//若为ping包
	if (data_len == sizeof(ping_pkg_t) && memcmp(&pi, heart_data, data_len) == 0) {
		if (ss->on_protocol_send_cb) {
			ss->on_protocol_send_cb(ss, &po, sizeof(po));
		}
		ss->last_active = time(0);
		ss->flag.bit_ping = 0;
	}
	//若为pong包
	else if (data_len == sizeof(pong_pkg_t) && memcmp(&po, heart_data, data_len) == 0) {
		ss->last_active = time(0);
		ss->flag.bit_ping = 0;
	}
	else {
		return -1;
	}
	return 0;
}



//json
void tcp_json_protocol_recv(struct sock_session* ss) {
	if (ss->flag.bit_closed || ss->i_buf.recv_len < 2)
		return;

	uint32_t total = 0;
	uint32_t len = ss->i_buf.recv_idx;

	//处理包长小于缓冲区已接收
	while ((total + len) < ss->i_buf.recv_len) {
		if (*(ss->i_buf.recv_buf + total + len) == '\n' && *(ss->i_buf.recv_buf + total + len - 1) == '\r') {
			len += 1;

			//若是ping包直接响应 否则调用用户回调
			if (tcp_json_protocol_pong(ss, ss->i_buf.recv_buf + total, len - sizeof(char) * 2)){
				if (ss->on_complate_pkg_cb) {
					ss->on_complate_pkg_cb(ss, ss->i_buf.recv_buf + total, len - sizeof(char) * 2);
					ss->last_active = time(0);
					ss->flag.bit_ping = 0;
				}
			}

			total += len;
			len = 0;
			continue;
		}
		++len;
	}

	//如果有数据被处理
	if (total) {
		//保存已处理索引
		ss->i_buf.recv_idx = ss->i_buf.recv_len = ss->i_buf.recv_len - total;
		if (ss->i_buf.recv_len) {
			memmove(ss->i_buf.recv_buf, ss->i_buf.recv_buf + total, ss->i_buf.recv_len);
		}
	}
	else {
		//如果是数据过大
		if (len > ss->i_buf.recv_buf_length - sizeof(char) * 2) {
			printf("[%s] [%s:%d] [%s] Remove session, ip: [%s], port: [%d] errmsg: [%s]\n ", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "Not found pkg tail");
			sm_del_session(ss, ss->flag.bit_is_server ? -1 : 0);
			return;
		}
		//保存已处理的索引
		ss->i_buf.recv_idx = len;
	}
}

int tcp_json_protocol_send(struct sock_session* ss, const char* data, uint32_t data_len) {
	if (data_len == 0)
		return 0;

	//检查发送缓冲区是否能够容纳
	int ret = netio_obuf_check_full(&ss->o_buf, data_len + 2);
	if (ret == 0) {
		memcpy(ss->o_buf.send_buf + ss->o_buf.send_len, data, data_len);
		ss->o_buf.send_len += data_len;

		memcpy(ss->o_buf.send_buf + ss->o_buf.send_len, "\r\n", 2);
		ss->o_buf.send_len += 2;
	}
	else if (ret == 1) {
		uint32_t processed_len = 0;
		uint32_t unused_len = netio_obuf_unused_length(&ss->o_buf);
		
		//写满缓冲区 更新已处理
		memcpy(ss->o_buf.send_buf + ss->o_buf.send_len, data, unused_len);
		ss->o_buf.send_len += unused_len;
		processed_len += unused_len;

		//尝试
		sm_send(ss);
		if (ss->flag.bit_closed)
			return -1;

		//再次校验剩余长度
		ret = netio_obuf_check_full(&ss->o_buf, data_len - processed_len);
		//只给一次机会,失败则放弃
		if (ret == 1 || ret == -1) {
			printf("[%s] [%s:%d] [%s], Remove session ip: [%s], port: [%d] errmsg: [%s]\n ", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "Kernel buffer full ,Remaining data out of buffer, Tried, but failed");
			sm_del_session(ss, ss->flag.bit_is_server ? -1 : 0);
			return -1;
		}

		//将剩余数据拷贝进缓冲区
		memcpy(ss->o_buf.send_buf + ss->o_buf.send_len, data + processed_len, data_len - processed_len);
		ss->o_buf.send_len += (data_len - processed_len);
	}
	else {
		//打印错误
		printf("[%s] [%s:%d] [%s], Remove session ip: [%s], port: [%d] errmsg: [%s]\n ", tools_get_time_format_string(), __FILENAME__, __LINE__, __FUNCTION__, ss->ip, ss->port, "Kernel buffer full ,Remaining data out of buffer");
		sm_del_session(ss, ss->flag.bit_is_server ? -1 : 0);
		return -1;
	}
	return sm_ep_add_event(ss->manager_ptr, ss, EPOLLOUT);
}

void tcp_json_protocol_ping(struct sock_session* ss) {
	if (ss->on_protocol_send_cb) {
		int ret = ss->on_protocol_send_cb(ss, JSON_KEEPALIVE, strlen(JSON_KEEPALIVE));
		if (ret == 0) {
			ss->flag.bit_ping = 1;
		}
	}
}

int tcp_json_protocol_pong(struct sock_session* ss, const char* heart_data, uint16_t data_len) {
	if (data_len == s_json_keepalive_len && strncmp(JSON_KEEPALIVE, heart_data, s_json_keepalive_len) == 0) {
		ss->last_active = time(0);
		ss->flag.bit_ping = 0;
		return 0;
	}
	return -1;
}