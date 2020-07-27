#include <ps4.h>

void notify(char *message)
{
	char buffer[512];
	sprintf(buffer, "%s", message);
	sceSysUtilSendSystemNotificationWithText(222, buffer);
}
