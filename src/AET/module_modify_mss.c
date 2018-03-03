#include"./module.h"
#include"./utils.h"
void modify_mss(struct iphdr* old_ip_pkt,u_int16_t size,
struct ip_pkt_send_queue* send_queue){
	int protocol=old_ip_pkt->protocol;
	if(protocol!=6){
		printf("Modify_mss error: the transport layer is not TCP\n");
		return;
	}
	u_int8_t ip_hdr_len=old_ip_pkt->ihl*4;
	u_int16_t tot_len=ntohs(old_ip_pkt->tot_len);
	struct tcphdr* old_tcp_pkt=(struct tcphdr*)((char*)old_ip_pkt+ip_hdr_len);
	int tcp_hdr_len=old_tcp_pkt->doff*4;
	int rtn=is_mss_existed(old_tcp_pkt);
	if(rtn==-1)
		return;
	if(rtn==0){ //mss don't existed
		char* new_ip_pkt=malloc(tot_len+4);
		struct tcphdr* new_tcp_pkt=(struct tcphdr*)(new_ip_pkt+ip_hdr_len);
		copy_ip_header((struct iphdr*)new_ip_pkt,old_ip_pkt);
		copy_tcp_header(new_tcp_pkt,old_tcp_pkt);
		char* ptr=new_ip_pkt+ip_hdr_len+tcp_hdr_len;
		*(ptr++)=2;
		*(ptr++)=4;
		*(ptr++)=size/256;
		*(ptr++)=size%256;
		char *old_ip_pkt_ptr=(char*)(old_ip_pkt);
		int i=ip_hdr_len+tcp_hdr_len;
		for(;i<tot_len;i++){
			*(ptr++)=old_ip_pkt_ptr[i];
		}
		new_tcp_pkt->doff++;
		((struct iphdr*)new_ip_pkt)->tot_len=htons(tot_len+4);
		modify_tcp_checksum((struct iphdr*)new_ip_pkt);
		modify_ip_checksum((unsigned char*)new_ip_pkt);
		send_queue->queue[++(send_queue->tail)]=(struct iphdr*)new_ip_pkt;
	}
	else{  //mss have existed
		char* new_ip_pkt=malloc(tot_len);
		struct tcphdr* new_tcp_pkt=(struct tcphdr*)(new_ip_pkt+ip_hdr_len);
		copy_ip_header((struct iphdr*)new_ip_pkt,old_ip_pkt);
		copy_tcp_header(new_tcp_pkt,old_tcp_pkt);
		char*ptr=(char*)new_tcp_pkt;
		ptr[rtn++]=2;
		ptr[rtn++]=4;
		ptr[rtn++]=size/256;
		ptr[rtn++]=size%256;
		char *old_ip_pkt_ptr=(char*)(old_ip_pkt);
		int i=ip_hdr_len+tcp_hdr_len;
		for(;i<tot_len;i++){
			ptr[i-ip_hdr_len]=old_ip_pkt_ptr[i];
		}
		modify_tcp_checksum((struct iphdr*)new_ip_pkt);
		send_queue->queue[++(send_queue->tail)]=(struct iphdr*)new_ip_pkt;
	}	
}

int is_mss_existed(struct tcphdr* tcp_pkt){ //0 : not existed  -1: error   >0:existed
	int tcp_hdr_len=tcp_pkt->doff*4;
	int i;
	char* ptr=(char*)tcp_pkt;
	for(i=20;i<tcp_hdr_len;){   //20 is tcp header(no option)
		if(ptr[i]==0)
			break;
		if(ptr[i]==1){
			i++;
			continue;
		}
		switch(ptr[i]){
			case(2):{
				return i; //return position
			}
			case(3):{
				i+=ptr[i+1];
				break;
			}
			case(4):{
				i+=ptr[i+1];
				break;
			}
			case(5):{
				i+=ptr[i+1];
				break;
			}
			case(8):{
				i+=ptr[i+1];
				break;
			}
			case(30):{
				i+=ptr[i+1];
				break;
			}
			default:{
				printf("Wrong tcp option: %d",ptr[i]);
				return -1;
			}
		}
	}
	return 0;
}
