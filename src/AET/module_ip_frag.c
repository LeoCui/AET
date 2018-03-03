#include"./module.h"
#include"./utils.h"
void ip_frag(struct iphdr* ip_pkt,u_int16_t frag_size,struct ip_pkt_send_queue* send_queue){
	printf("----------ip_frag---------------------------------------\n");
	//print_ip_packet((struct iphdr *) ip_pkt,0);
	u_int16_t offset=ntohs(ip_pkt->frag_off);
	u_int16_t header_len=ip_pkt->ihl*4;
	u_int16_t total_len=ntohs(ip_pkt->tot_len);
	u_int16_t data_len=total_len-header_len;
	if(total_len>MAX_IP_LEN)
		printf("Error:the ip_pkt_len is %d,exceed the MAX_IP_LEN\n",total_len);
	char ip_data[MAX_IP_LEN];
	mystrcpy(ip_data,(char *)ip_pkt+header_len,data_len);
	//printf("before ip_frag: data is %s\n",ip_data);
	//u_int16_t frag_num=1;
	u_int16_t i;
	int df=offset&0x4000;
	int mf=offset&0x2000;
	int flag=0;
	if(df==0&&mf==1){  //already fraged,and not the last fragment
		flag=1;
	}
	for(i=0;i<data_len;i+=frag_size){
		u_int16_t new_offset=(offset&0x1fff)+i/8;
		new_offset=new_offset|0x2000;   //df=0,mf=1,not last fragment
		char new_ip_data[MAX_IP_LEN];
		u_int16_t new_data_len=frag_size;
		if(i+frag_size>=data_len){
			new_data_len=data_len-i;
			if(flag==0){
				new_offset=new_offset&0x1fff; //df=0,mf=0,last fragment
			}
		}
		mystrcpy(new_ip_data,ip_data+i,new_data_len);
		char* new_ip_pkt=malloc(new_data_len+header_len);
		copy_ip_header((struct iphdr*)new_ip_pkt,ip_pkt);
		((struct iphdr*)new_ip_pkt)->frag_off=htons(new_offset);
		((struct iphdr*)new_ip_pkt)->tot_len=htons(header_len+new_data_len);
		modify_ip_checksum((unsigned char*)new_ip_pkt);
		init_ip_data(new_ip_pkt,new_ip_data,new_data_len);
		
		send_queue->queue[++(send_queue->tail)]=(struct iphdr*)new_ip_pkt;
	}
}


