#include<sys/socket.h>
#include<sys/ioctl.h>
#include<linux/if_ether.h>
#include<net/if.h>
#include<netinet/in.h>
#include<linux/ip.h>
#include<linux/udp.h>
#include<linux/tcp.h>
#include<string.h>
#include<stdio.h>
int main(int argc, char *argv[])
{
	int fd;
	fd = socket(AF_INET,SOCK_PACKET,htons(0x0003));
	char *ethname = "eth0";
	struct ifreq ifr;
	strcpy(ifr.ifr_name,ethname);
	int i = ioctl(fd,SIOCGIFFLAGS,&ifr);
	if(i < 0)
	{
		close(fd);
		perror("cant get flags\n");
		return -1;
	}
	ifr.ifr_flags |= IFF_PROMISC;
	i = ioctl(fd,SIOCSIFFLAGS,&ifr);
	if(i < 0)
	{
		perror("promiscuous set error\n");
		return -2;
	}
	char ef[ETH_FRAME_LEN];
	struct ethhdr *p_ethhdr;
	int n;
	p_ethhdr = (struct ethhdr*)ef;
	n = read(fd,ef,ETH_FRAME_LEN);
	printf("dest MAC:");
	int j;
	for(j=0;j<ETH_ALEN-1;j++)
	{
		printf("%02x-",p_ethhdr->h_dest[j]);	
	}

		printf("%02x\n",p_ethhdr->h_dest[j]);	
	printf("source MAC:");
	for(j = 0;j<ETH_ALEN-1;j++)
		printf("%02x-",p_ethhdr->h_source[j]);
	printf("%02x-",p_ethhdr->h_source[j]);
	printf("protocol:0x%04x\n",ntohs(p_ethhdr->h_proto));
	
	if(ntohs(p_ethhdr->h_proto) == 0x800)
	{
		struct iphdr *p_iphdr = (struct iphdr*)(ef + ETH_HLEN);
		printf("src ip:%s \n",inet_ntoa(p_iphdr->saddr));
		printf("dest ip:%s \n",inet_ntoa(p_iphdr->daddr));
		if(p_iphdr->protocol == 6)
		{
			struct tcphdr *p_tcphdr = (struct tcphdr*)(p_iphdr->ihl*4);
			printf("src port:%d\n",ntohs(p_tcphdr->source));
			printf("dst port:%d\n",ntohs(p_tcphdr->dest));
		}
	}
	return 0;

}
