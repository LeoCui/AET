#include"./utils.h"
#include"./module.h"
void send_ip_pkt(int thread_index,u_int8_t dir,struct ip_pkt_send_queue* queue){
	int head=queue->head;
	int tail=queue->tail;
	int i;
	for(i=head;i<=tail;i++){
		struct iphdr *ip_pkt=queue->queue[i];
		int buf_len=ntohs(ip_pkt->tot_len);
		//u_int32_t addr=ip_packet->daddr;
		//my_send_ip_pkt((char*)ip_packet,buf_len,addr);
		int rtn=MESA_sendpacket_iplayer(thread_index,(const char*)ip_pkt,buf_len,dir);
		if(rtn==-1){
			printf("Error:fail to send IP packet\n");
		}
		else{
			printf("Succeed to send IP Packet,the len is %d\n",rtn);
		}
		if(i!=0)
			free(ip_pkt);
	}
}

void my_send_ip_pkt(char* pkt,int buf_len,u_int32_t addr){
	int sock;
	if((sock=socket(AF_INET,SOCK_RAW,IPPROTO_UDP)) == -1)
	{
		perror("socket");
		return;
	}
	printf("Socket is %d\n",sock);
	printf("tot_len is %d\n",buf_len);
	printf("IP is %0x\n",addr);
	struct sockaddr_in sockaddr;
	sockaddr.sin_family=AF_INET;
	sockaddr.sin_addr.s_addr=addr;
	int rtn=sendto(sock,pkt,buf_len,0,(struct sockaddr*)(&sockaddr),sizeof(struct sockaddr_in));
	if(rtn==-1){
			printf("Error:fail to send IP packet\n");
	}
	else{
			printf("Succeed to send IP Packet,the len is %d\n",rtn);
	}
}
