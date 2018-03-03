#include"./utils.h"
#include"./module.h"

void modify_tcp_flags(struct iphdr* old_ip_pkt,char* flag,
struct ip_pkt_send_queue* send_queue){
	int protocol=old_ip_pkt->protocol;
	if(protocol!=6){
		printf("Modify_tcp_flags error: the transport layer is not TCP\n");
		return;
	}
	u_int8_t ip_hdr_len=old_ip_pkt->ihl*4;
	u_int16_t tot_len=ntohs(old_ip_pkt->tot_len);
	//struct tcphdr* old_tcp_pkt=(struct tcphdr*)((char*)old_ip_pkt+ip_hdr_len);
	int flag1=-1;
	if(strcmp(flag,"syn")==0)
		flag1=0;
	if(strcmp(flag,"ack")==0)
		flag1=1;
	if(strcmp(flag,"fin")==0)
		flag1=2;
	if(strcmp(flag,"rst")==0)
		flag1=3;
	if(strcmp(flag,"psh")==0)
		flag1=4;
	if(strcmp(flag,"urg")==0)
		flag1=5;
	if(flag1==-1){
		printf("Error: %s is not a valid option\n",flag);
		return;
	}
	char* new_ip_pkt=malloc(tot_len);
	struct tcphdr* new_tcp_pkt=(struct tcphdr*)(new_ip_pkt+ip_hdr_len);
	copy_ip_header((struct iphdr*)new_ip_pkt,old_ip_pkt);
	copy_ip_data((struct iphdr*)new_ip_pkt,old_ip_pkt);
	switch(flag1){
		case(0):{
			new_tcp_pkt->syn=1;
			break;
		}
		case(1):{
			new_tcp_pkt->ack=1;
			break;
		}
		case(2):{
			new_tcp_pkt->fin=1;
			break;
		}
		case(3):{
			new_tcp_pkt->rst=1;
			break;
		}
		case(4):{
			new_tcp_pkt->psh=1;
			break;
		}
		case(5):{
			new_tcp_pkt->urg=1;
			break;
		}
		default:{
			break;
		}
	}
	modify_tcp_checksum((struct iphdr*)new_ip_pkt);
	send_queue->queue[++(send_queue->tail)]=(struct iphdr*)new_ip_pkt;
}
