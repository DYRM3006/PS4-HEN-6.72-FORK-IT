#define printfsocket(format, ...)\
do {\
	char buffer[512];\
	int size = sprintf(buffer, format, ##__VA_ARGS__);\
	sceNetSend(sock, buffer, size, 0);\
} while(0)
