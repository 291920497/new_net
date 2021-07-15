#include "basic_tools.h"


const char* tools_get_uuid_r(char uuid_buf[40]) {
	uuid_t uu;
	uuid_generate(uu);
	uuid_generate_random(uu);
	uuid_unparse_upper(uu, uuid_buf);
	return uuid_buf;
}

const char* tools_get_uuid() {
	static char uuid[40];
	return tools_get_uuid_r(uuid);
}

unsigned int tools_hash_func(const char* char_key, int klen) {
	unsigned int hash = 0;
	const unsigned char* key = (const unsigned char*)char_key;
	const unsigned char* p;
	int i;
	if (!key) return hash;

	if (klen == -1) {
		for (p = key; *p; p++) {
			hash = hash * 33 + tolower(*p);
		}
		klen = p - key;
	}
	else {
		for (p = key, i = klen; i; i--, p++) {
			hash = hash * 33 + tolower(*p);
		}
	}

	return hash;
}

//检查更新文件描述符
int tools_nofile_ckup() {
	int err = errno;
	if (err != EMFILE) {
		printf("[%s:%d] Errors are caused by other reasons. errno: [%d]\n", __FILENAME__, __LINE__, err);
		return 0;
	}

	struct rlimit old_r, new_r;
	getrlimit(RLIMIT_NOFILE, &old_r);
	
	new_r.rlim_cur = old_r.rlim_cur * 2;

	//若超出了最大，则使用旧时最大
	if (new_r.rlim_cur > old_r.rlim_max) {
		new_r.rlim_max = new_r.rlim_cur = old_r.rlim_max;
	}
	else {
		new_r.rlim_max = old_r.rlim_max;
	}

	if (setrlimit(RLIMIT_NOFILE, &new_r) != 0) {
		//printf("[%s:%d] setrlimit function error. errno: [%d]\n", __FILENAME__, __LINE__, err);
		return -1;
	}

	return 0;
}

int tools_set_nonblocking(int fd) {
	int old_opt = fcntl(fd, F_GETFL);
	int new_opt = old_opt | O_NONBLOCK;
	fcntl(fd, F_SETFL, new_opt);
	return old_opt;
}

/*
	计算num的值域, 值域与retval的关系: (1 << (retval - 1) , 1 << (retval)]
*/
int tools_bit_range2(uint8_t left, uint8_t right, uint32_t num) {
	if (num > (1 << right)) {
		return -1;
	}
	else if (num <= (1 << left)) {
		return left;
	}

	char mid;
bit_range2_s:
	mid = left + ((right - left) / 2) + ((right - left) & 1);
	if ((1 << mid) < num && num <= (1 << (mid + 1))) {
		return mid + 1;
	}
	else if (mid == right) {
		return mid;
	}

	if ((1 << mid) < num) {
		left = mid;
	}
	else {
		right = mid;
	}
	goto bit_range2_s;
}

const char* tools_get_time_format_string() {
	struct timeval tv;
	gettimeofday(&tv, 0);
	struct tm t;
	localtime_r(&tv.tv_sec, &t);

	static char time_fmt[64];
	sprintf(time_fmt, "%04d-%02d-%02d %02d:%02d:%02d.%06d",
	//sprintf(time_fmt, "%04d-%02d-%02d %02d:%02d:%02d.%03d",
		t.tm_year + 1900, t.tm_mon + 1, t.tm_mday,
		t.tm_hour, t.tm_min, t.tm_sec, tv.tv_usec);
	return time_fmt;
}

const char* tools_get_current_filename() {
	const char* find_ptr = 0;
#ifdef _WIN32
	find_ptr = strstr(__FILE__, "\\");
#else
	find_ptr = strstr(__FILE__, "/");
#endif
	if (find_ptr) {
		return ++find_ptr;
	}
	return 0;
}