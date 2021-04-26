#include "websocket_protocol.h"
#include "sock_session.h"


#include "base64_encoder.h"
#include "sha1.h"
#include "../tools/basic_tools.h"


#include <string.h>
#include <sys/epoll.h>
#include <netinet/in.h>

#define RFC6455 "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"

struct ws_frame_protocol {
	char fin;
	char opcode;
	char mask;
	char mask_code[4];
	char head_len;
	char* data;
	unsigned int payload_len;
};

static void web_decode_data(const char* mask_arr, char* data, unsigned int data_len) {
	for (int i = 0; i < data_len; ++i) {
		data[i] ^= mask_arr[i & 3];
	}
}

static void web_decode_protocol(const char* frame, struct ws_frame_protocol* out_buf) {
	unsigned char fin_opcode = *(frame);
	unsigned char msk_paylen = *(frame + 1);
	out_buf->fin = fin_opcode & 0x80;
	out_buf->mask = msk_paylen & 0x80;
	out_buf->opcode = fin_opcode & 0x7F;
	out_buf->payload_len = msk_paylen & 0x7F;
	out_buf->head_len = 2;

	//按理此处是不需要的直接赋值6
	if (out_buf->mask) {
		out_buf->head_len += 4;
	}

	if (out_buf->payload_len == 126) {
		out_buf->head_len += 2;
	}
	else if (out_buf->payload_len > 126) {
		out_buf->head_len += 4;
	}

	out_buf->data = frame + out_buf->head_len;

	if (out_buf->payload_len == 126) {
		out_buf->payload_len = ntohs(*((unsigned short*)(frame + 2)));
	}
	else if (out_buf->payload_len > 126) {
		out_buf->payload_len = ntohl(*((unsigned int*)(frame + 2)));
	}

	if (out_buf->mask) {
		memcpy(out_buf->mask_code, frame + out_buf->head_len - 4, 4);
	}
}

static void web_encode_protocol(char* frame, struct ws_frame_protocol* in_buf) {
	unsigned char fin_opcode = 0;
	unsigned char msk_paylen = 0;
	char* encode = frame;

	fin_opcode |= (in_buf->opcode);
	if (in_buf->fin) {
		fin_opcode |= 0x80;
	}
	*encode++ = fin_opcode;

	if (in_buf->mask) {
		msk_paylen |= 0x80;
	}

	if (in_buf->payload_len < 126) {
		msk_paylen |= in_buf->payload_len;
		*encode++ = msk_paylen;
	}
	else if (in_buf->payload_len < 0xFFFF) {
		msk_paylen |= 126;
		*encode++ = msk_paylen;
		*((unsigned short*)encode) = ntohs(in_buf->payload_len);
		encode += 2;
	}
	else {
		msk_paylen |= 127;
		*encode++ = msk_paylen;
		*((unsigned int*)encode) = ntohl(in_buf->payload_len);
		encode += 4;
	}

	if (in_buf->mask) {
		memcpy(encode, in_buf->mask_code, sizeof(char) * 4);
	}
	in_buf->head_len = encode - frame;
}

//合并2帧数据
static int web_merge_protocol(struct ws_frame_protocol* in_prev_buf, struct ws_frame_protocol* in_cur_buf, unsigned char is_fin) {
	unsigned char new_head_len = 2;
	unsigned int new_data_len = in_prev_buf->payload_len + in_cur_buf->payload_len;

	if (in_prev_buf->mask) {
		new_head_len += 4;
	}

	if (new_data_len > 126 && new_data_len < 0xFFFF) {
		new_head_len += 2;
	}
	else if (new_data_len > 0xFFFF) {
		new_head_len += 4;
	}

	memmove(in_prev_buf->data + in_prev_buf->payload_len, in_cur_buf->data, in_cur_buf->payload_len);
	in_prev_buf->payload_len += (in_cur_buf->payload_len);

	if (new_head_len > in_prev_buf->head_len) {
		memmove(in_prev_buf->data + new_head_len - in_prev_buf->head_len, in_prev_buf->data, in_prev_buf->payload_len);
	}

	if (is_fin) {
		in_prev_buf->fin |= 0x80;
	}
	web_encode_protocol(in_prev_buf->data - in_prev_buf->head_len, in_prev_buf);
	return 0;
}

static int web_handshake(struct sock_manager* sm, struct sock_session* ss, const char* url, const char* host, const char* origin, const char* sec_key, const char* sec_version) {
	char sec_ws_key[64];
	char sha1[24] = { 0 };
	char b64[32] = { 0 };

	strcpy(sec_ws_key, sec_key);
	strcat(sec_ws_key, RFC6455);
	sz_sha1(sec_ws_key, strlen(sec_ws_key), sha1);
	base64_encode(sha1, 20, b64);

	sprintf(ss->o_buf.send_buf + ss->o_buf.send_len, "HTTP/1.1 101 Switching Protocols\r\n" \
		"Upgrade: websocket\r\n" \
		"Connection: Upgrade\r\n" \
		"Sec-WebSocket-Accept: %s\r\n" \
		"\r\n", b64);
	ss->o_buf.send_len += strlen(ss->o_buf.send_buf);

	int ret = sm_ep_add_event(sm, ss, EPOLLOUT);
	if (ret != 0) {
		printf("ep_add_event(sm, ss, EPOLLOUT) failed\n");
	}
	return ret;
	//return ep_add_event(sm, ss, EPOLLOUT);
}

void web_parse_head(struct sock_manager* sm, struct sock_session* ss, char* data, unsigned short len) {
	unsigned int total = 0, head_idx = 0, tail_idx = 0, line_len, key_hash;
	const char* fs_ptr = 0, * fe_ptr = 0;

	char key[128];
	char var[1024];
	char host[128];
	char origin[128];
	char secwskey[128];
	char secwsver[32];

	char url[256] = { 0 };
	char base64buf[32] = { 0 };
	char sec_accept[32] = { 0 };

	fs_ptr = data + total;
	fe_ptr = strstr(fs_ptr, "\r\n");
	line_len = fe_ptr - fs_ptr + sizeof(char) * 2;

	if (strncmp(fs_ptr, "GET", 3)) {
		goto handshake_failed;
	}
	else {
		total += (line_len);
		fs_ptr = strchr(fs_ptr, ' ');
		fe_ptr = strchr(++fs_ptr, ' ');
		if ((fe_ptr - fs_ptr) < line_len) {
			strncpy(url, fs_ptr, fe_ptr - fs_ptr);
		}
		else {
			goto handshake_failed;
		}
	}

	while (total < len - 2) {
		fs_ptr = data + total;
		fe_ptr = strchr(fs_ptr, ':');
		if (!fs_ptr || !fe_ptr) { goto handshake_failed; }
		strncpy(key, fs_ptr, fe_ptr - fs_ptr);
		key[fe_ptr - fs_ptr] = 0;

		fs_ptr = fe_ptr + sizeof(char) * 2;
		fe_ptr = strstr(fs_ptr, "\r\n");
		if (!fs_ptr || !fe_ptr) { goto handshake_failed; }
		strncpy(var, fs_ptr, fe_ptr - fs_ptr);
		var[fe_ptr - fs_ptr] = 0;

		//printf("key: [%s], var: [%s]\n", key, var);
		total += (fe_ptr - data - total + sizeof(char) * 2);

		key_hash = tools_hash_func(key, -1);
		switch (key_hash) {
		case 0x3B2793A8://Upgrade
			if (strcmp(var, "websocket"))
				goto handshake_failed;
			break;
		case 0x9CB49D90://Connection
			if (strcmp(var, "Upgrade"))
				goto handshake_failed;
			break;
		case 0x003AEEDE://Host
			strcpy(host, var);
			break;
		case 0x0B36DF28://Origin
			strcpy(origin, var);
			break;
		case 0x6B183CE5://Sec-WebSocket-Key
			strcpy(secwskey, var);
			break;
		case 0xD388F522://Sec-WebSocket-Version
			strcpy(secwsver, var);
			break;
		}//switch	
	}

	/*
		此处可能后续需要对url, origin做出校验或增加url对应不同的处理回调。这将需要在sock_session或者实现一个多态的url->cb 映射
	*/

	//此处完成回执
	if (web_handshake(sm, ss, url, host, origin, secwskey, secwsver)) {
		goto handshake_failed;
	}
	else {
		//ss->flag |= SESSION_FLAG_HANDSHAKE;
		//标记已经握手
		ss->flag.bit_web_handshake = ~0;
	}

	return;

handshake_failed:
	printf("[%s] [%s:%d] [%s] Remove session, ip: [%s] port: [%d] err_msg: [%s]\n", tools_get_time_format_string(), __FILE__, __LINE__, __FUNCTION__, ss->ip, ss->port, "websocket handshake failed");
	sm_del_session(ss, ss->flag.bit_is_server ? -1 : 0);
}

int web_parse_frame(struct sock_manager* sm, struct sock_session* ss) {
	if (ss->i_buf.recv_len < 2 || ss->flag.bit_closed) { return 0; }

	unsigned int prev_frame_idx = 0, cur_frame_idx = ss->i_buf.recv_idx;

	do {
		if (ss->i_buf.recv_len - cur_frame_idx < 2) {
		parse_frame_save_ret:
			//ss->recv_idx = cur_frame_idx;
			if (prev_frame_idx == cur_frame_idx) {
				ss->i_buf.recv_len -= cur_frame_idx;
				ss->i_buf.recv_idx -= cur_frame_idx;
			}
			else {
				ss->i_buf.recv_len -= prev_frame_idx;
				ss->i_buf.recv_idx -= prev_frame_idx;
			}

			if (prev_frame_idx && ss->i_buf.recv_len) {
				memmove(ss->i_buf.recv_buf, ss->i_buf.recv_buf + prev_frame_idx, ss->i_buf.recv_len);
			}
			return 0;
		}

		struct ws_frame_protocol wfp;
		memset(&wfp, 0, sizeof(wfp));

		unsigned char fin_opcode = *(ss->i_buf.recv_buf + cur_frame_idx);
		unsigned char msk_paylen = *(ss->i_buf.recv_buf + cur_frame_idx + 1);
		wfp.fin = fin_opcode & 0x80;
		wfp.mask = msk_paylen & 0x80;
		wfp.opcode = fin_opcode & 0x7F;
		wfp.payload_len = msk_paylen & 0x7F;
		wfp.head_len = 6;

		if (wfp.opcode == 0x08 || !(wfp.mask)) {
			goto parse_frame2_failed;
		}

		if (wfp.payload_len == 126) {
			wfp.head_len += 2;
		}
		else if (wfp.payload_len > 126) {
			wfp.head_len += 4;
		}
		wfp.data = ss->i_buf.recv_buf + cur_frame_idx + wfp.head_len;

		//校验是否满足一个协议头
		if (cur_frame_idx + wfp.head_len > ss->i_buf.recv_len) {
			//goto parse_frame_save_ret;	//可以替换为goto
			if (prev_frame_idx == cur_frame_idx) {
				ss->i_buf.recv_len -= cur_frame_idx;
				ss->i_buf.recv_idx -= cur_frame_idx;
			}
			else {
				ss->i_buf.recv_len -= prev_frame_idx;
				ss->i_buf.recv_idx -= prev_frame_idx;
			}

			if (prev_frame_idx && ss->i_buf.recv_len) {
				memmove(ss->i_buf.recv_buf, ss->i_buf.recv_buf + prev_frame_idx, ss->i_buf.recv_len);
			}
			return 0;
		}
		else {
			if (wfp.payload_len == 126) {
				wfp.payload_len = ntohs(*((uint16_t*)(ss->i_buf.recv_buf + cur_frame_idx + 2)));
			}
			else if (wfp.payload_len > 126) {
				wfp.payload_len = ntohl(*((uint32_t*)(ss->i_buf.recv_buf + cur_frame_idx + 2)));
			}

			/*
				此处对数据长度做出管控,也可以放开限制，但是需要对应的buffer长度
				如果需要可以修改BUF长度或修改为实时变更长度
				优化方案：协议完成接口，要求客户端按照指定接口请求足够长的buffer以供特定的客户端使用(避免不必要的内存浪费)
			*/
			if (cur_frame_idx + wfp.payload_len + wfp.head_len > ss->i_buf.recv_buf_length) {
				goto parse_frame2_failed;
			}

			memcpy(wfp.mask_code, ss->i_buf.recv_buf + cur_frame_idx + wfp.head_len - 4, 4);

			//包不完整
			if (cur_frame_idx + wfp.head_len + wfp.payload_len <= ss->i_buf.recv_len) {
				//满足包长即解码
				web_decode_data(wfp.mask_code, wfp.data, wfp.payload_len);
			}
			else {
				return 0;
			}
		}

		if (wfp.fin) {
			if (prev_frame_idx == cur_frame_idx) {
				//test

				switch (wfp.opcode) {
				case 0x01:
				case 0x02:
					if (ss->on_complate_pkg_cb) {
						ss->on_complate_pkg_cb(ss, wfp.data, wfp.payload_len);
					}
					break;
				case 0x0A:
					ss->last_active = time(0);
					ss->flag.bit_ping = 0;
					break;
				}

				//test end

				/*if (ss->complate_pkg_cb) {
					ss->complate_pkg_cb(sm, ss, wfp.data, wfp.payload_len);
				}*/
				ss->i_buf.recv_idx = prev_frame_idx = cur_frame_idx = cur_frame_idx + wfp.head_len + wfp.payload_len;
			}
			else {
				struct ws_frame_protocol prev_wfp;
				web_decode_protocol(ss->i_buf.recv_buf + prev_frame_idx, &prev_wfp);
				web_merge_protocol(&prev_wfp, &wfp, 1);
				if (ss->on_complate_pkg_cb) {
					ss->on_complate_pkg_cb(ss, prev_wfp.data, prev_wfp.payload_len);
				}
				ss->i_buf.recv_idx = prev_frame_idx = cur_frame_idx = cur_frame_idx + prev_wfp.head_len + wfp.payload_len;
			}
		}
		else {
			if (prev_frame_idx == cur_frame_idx) {
				ss->i_buf.recv_idx = cur_frame_idx += (wfp.head_len + wfp.payload_len);
			}
			else {
				struct ws_frame_protocol prev_wfp;
				web_decode_protocol(ss->i_buf.recv_buf + prev_frame_idx, &prev_wfp);
				web_merge_protocol(&prev_wfp, &wfp, 0);
				ss->i_buf.recv_idx = cur_frame_idx = cur_frame_idx + prev_wfp.head_len + wfp.payload_len;
			}
		}
	} while (1);

parse_frame2_failed:
	printf("[%s] [%s:%d] [%s] Remove session, ip: [%s], port: [%d] errmsg: [%s]\n ", tools_get_time_format_string(), __FILE__, __LINE__, __FUNCTION__, ss->ip, ss->port, "The received message is too long");
	sm_del_session(ss, ss->flag.bit_is_server ? -1 : 0);
	return -1;
}


void web_protocol_recv(struct sock_session* ss) {
	if (!(ss->i_buf.recv_len) || ss->flag.bit_closed) { return; }

	unsigned total = 0;
	unsigned int len = ss->i_buf.recv_idx;

	if (ss->flag.bit_web_handshake) {
		if (web_parse_frame(ss->manager_ptr, ss) != 0) {
			return;
		}
	}
	else {
		if (ss->i_buf.recv_len > 4) {
			while ((total + len) < ss->i_buf.recv_len - 3) {
				if (*((int*)(ss->i_buf.recv_buf + total + len)) == 0x0A0D0A0D) {
					//printf("begin handshake\n");
					web_parse_head(ss->manager_ptr, ss, ss->i_buf.recv_buf + total, len + 4);
					//printf("end handshake\n");
					total += (len + 4);
					len = 0;
					break;
				}
				++len;
			}

			if (total) {
				if (ss->i_buf.recv_len - total) {
					memmove(ss->i_buf.recv_buf, ss->i_buf.recv_buf + total, ss->i_buf.recv_len - total);
				}
				ss->i_buf.recv_idx = ss->i_buf.recv_len = ss->i_buf.recv_len - total;
			}
			else {
				ss->i_buf.recv_idx = len;
			}
		}
	}
}

int web_protocol_send(struct sock_session* ss, const char* data, unsigned short data_len) {
	unsigned int head_len = 0;
	if (data_len < 126) {
		head_len += 2;
	}
	else if (data_len < 0xFFFF) {
		head_len += 4;
	}
	else {
		head_len += 6;
	}

	/*
		此处不考虑考虑数据撑爆缓冲区，即始终为fin,若需要发送大量数据，可以扩大缓冲区或做
	*/

	int ret = netio_obuf_check_full(&ss->o_buf, data_len + head_len);
	//此处暂时不考虑数据截断,在默认最大缓冲区内工作,主要是代码太久,不知道自己的代码在干嘛了,得看着协议重新走一遍
	if (ret != 0) {
		printf("[%s] [%s:%d] [%s] Remove session, ip: [%s], port: [%d] errmsg: [%s]\n ", tools_get_time_format_string(), __FILE__, __LINE__, __FUNCTION__, ss->ip, ss->port, "The data length exceeds twice the buffer");
		sm_del_session(ss, ss->flag.bit_is_server ? -1 : 0);
		return -1;
	}

	struct ws_frame_protocol wfp;
	memset(&wfp, 0, sizeof(wfp));
	wfp.fin = 1;
	wfp.mask = 0;
	wfp.payload_len = data_len;

	if (ss->flag.bit_proto_commu == PROTO_COMMU_WEBSOCKET_JSON) {
		wfp.opcode = 0x01;
	}
	else {
		wfp.opcode = 0x02;
	}
	web_encode_protocol(ss->o_buf.send_buf + ss->o_buf.send_len, &wfp);
	memcpy(ss->o_buf.send_buf + ss->o_buf.send_len + wfp.head_len, data, data_len);
	ss->o_buf.send_len += (wfp.head_len + data_len);

	return sm_ep_add_event(ss->manager_ptr, ss, EPOLLOUT);
}

void web_protocol_ping(struct sock_session* ss) {
	struct ws_frame_protocol wfp;
	memset(&wfp, 0, sizeof(wfp));
	wfp.fin = 1;
	wfp.opcode = 0x09;

	web_encode_protocol(ss->o_buf.send_buf + ss->o_buf.send_len, &wfp);
	ss->o_buf.send_len += wfp.head_len;
	if (sm_ep_add_event(ss->manager_ptr, ss, EPOLLOUT) == 0) {
		ss->flag.bit_ping = 1;
	}
}