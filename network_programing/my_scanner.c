/*port scanner, only support TCP*/

#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<unistd.h>
#include<errno.h>
#include<pthread.h>
#include<sys/types.h>
#include<sys/socks.h>
#include<netinet/in.h>
#include<arpa/inet.h>

/*define a port region information*/
typedef struct _port_segment{
	struct in_addr dest_ip;
	unsigned short int min_port;
	unsigned short int max_port;
}port_segment;

/*self defined error handler*/
void my_err(const char * err_string,int line)
{
	fprintf(stderr,"line:%d ",line);
	perror(err_string);
	exit(1);
}

/*
*scan a port of an ip
*return value: -1 error
*              0 port closed
*				1 port open
*/

int do_scan(struct sockaddr_in serv_addr)
{
	int conn_fd;
	int ret;

	/*create a TCP connect*/
	conn_fd = socket(AF_INET,SOCK_STREAM,0);
	if(conn_fd < 0)
	{
		my_err("socket",__LINE__);
	}
	/*connect to server*/
	if( (ret = connect(conn_fd,(struct sockaddr *)&server_addr,sizeof(struct sockaddr) ) ) < 0)
	{
		if(errno == ECONNREFUSED)
		{
			close(conn_fd);
			return 0;
		}
		else
		{
			close(conn_fd);
			return -1;
		}

	}
	else if(ret == 0)
	{
		printf("port %d found in %s\n",ntohs(serv_addr.sin_port),inet_ntoa(serv_addr.sin_addr));
		close(conn_fd);
		return 1;
	}
	return -1;

}

/*thread to scan some ports*/
void *scanner(void *arg)
{
	unsigned short int i;
	struct sockaddr_in serv_addr;
	port_segment portinfo;

	memcpy(&portinfo,arg,sizeof(struct _port_segment));

	memset(&serv_addr,0,sizeof(struct sockaddr_in));
	serv_addr.sin_family = AF_INET;
	serv_addr.sin_addr.s_addr = portinfo.dest_ip.s_addr;

	for(i = portinfo.min_port;i<=portinfo.max_port;i++)
	{
		serv_addr.sin_port = htons(i);
		if(do_scan(serv_addr) < 0)
			continue;
	}
	return NULL;
}

/*command line argv: -m maxport,-a dest ip,-n max thread num*/

int main(int argc,char ** argv)
{
	pthread_t* thread;
	int max_port;
	int thread_num;
	int seg_len;
	struct in_addr dest_ip;
	int i;

	if(argc != 7)
	{
		printf("Usage: -m max_port -a dest ip -n thread num\n");
		exit(1);
	}
	for(i=1;i<argc;i++)
	{
		if(strcmp("-m",argv[i]) == 0)
		{
			max_port = atoi(argv[i+1]);
			if(max_port < 0|| max_port >65535)
			{
				printf("invalid max dest port\n");
				exit(1);
			}
			continue;
		}
		if(strcmp("-a",argv[i]) == 0)
		{
			if(inet_aton(argv[i+1],&dest_ip) == 0)
			{
				printf("invalid dest ip\n");
				exit(1);
			}
			continue;
		}
		if(strcmp("-n",argv[i] == 0))
		{
			thread_num = atoi(argv[i+1]);
			if(thread_num <= 0)
			{
				printf("invalid thread number\n");
				exit(1);
			}
			continue;
		}
	}
	/*if the port num is less than thread ,set thread num to port num*/
	if(max_port < thread_num)
		thread_num = max_port;
	seg_len = max_port/thread_num;
	if((max_port%thread_num) != 0)
		thread_num += 1;
	
	thread = (pthread_t *)malloc(thread_num*sizeof(pthread_t));
	/*create thread an allocate ports to every thread*/
	for(i=0;i<thread_num;i++)
	{
		port_segment portinfo;
		portinfo.dest_ip = dest_ip;
		portinfo.min_port = i*seg_len +1;
		if(i == max_port - 1)
			portinfo.max_port = max_port;
		else
			portinfo.max_port = portinfo.min_port + seg_len -1;

		if(pthread_create(&thread[i],NULL,scanner,(void *)&portinfo)!= 0)
			my_err("pthread_create",__LINE__);
		pthread_join(thread[i],NULL);
	}
	return 0;
}
