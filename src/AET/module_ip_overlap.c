#include"./module.h"
#include"./utils.h"
#define OVERLAP_CHAR '#'
void ip_overlap(struct iphdr* ip_pkt,u_int16_t frag_size,u_int16_t overlap_size,
u_int8_t mode,struct ip_pkt_send_queue* send_queue){
	printf("----------ip_overlap---------------------------------------\n");
	//print_ip_packet((struct iphdr *) ip_pkt,0);
	u_int16_t offset=ntohs(ip_pkt->frag_off);
	u_int16_t header_len=ip_pkt->ihl*4;
	u_int16_t tot_len=ntohs(ip_pkt->tot_len);
	u_int16_t data_len=tot_len-header_len;
	int rtn=ip_overlap_check(ip_pkt,tot_len,frag_size,overlap_size,send_queue);
	if(rtn==-1)
		return;
	char temp_data[MAX_IP_LEN];
	mystrcpy(temp_data,(char *)ip_pkt+header_len,data_len);
	char ip_data[2*MAX_IP_LEN];
	data_len+=overlap_size;
	if(mode==0){    // mode =0,  the second fragment overlap the first fragment
		u_int16_t  i;
		u_int16_t size=frag_size-overlap_size;
		for(i=0;i<size;i++)
			ip_data[i]=temp_data[i];
		for(i=size;i<frag_size;i++)
			ip_data[i]=OVERLAP_CHAR;
		for(i=frag_size;i<data_len;i++)
			ip_data[i]=temp_data[i-overlap_size];
	}
	else{           // mode =1,  the first fragment overlap the second fragment
		u_int16_t i;
		for(i=0;i<frag_size;i++)
			ip_data[i]=temp_data[i];
		for(i=0;i<overlap_size;i++)
			ip_data[i+frag_size]=OVERLAP_CHAR;
		for(i=frag_size+overlap_size;i<data_len;i++)
			ip_data[i]=temp_data[i-overlap_size];
	}

	//u_int16_t frag_num=1;
	u_int16_t i;
	int df=offset&0x4000;
	int mf=offset&0x2000;
	int flag=0;
	if(df==0&&mf==1){  //already fraged,and not the last fragment
		flag=1;
	}
	
	for(i=0;i<data_len;i+=frag_size){
		
		u_int16_t temp_offset;
		if(i!=0)
			temp_offset=i-overlap_size;
		u_int16_t new_offset=(offset&0x1fff)+temp_offset/8;
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


int ip_overlap_check(struct iphdr* ip_pkt,u_int16_t tot_len,u_int16_t frag_size,
	u_int16_t overlap_size,struct ip_pkt_send_queue* send_queue){
	u_int16_t ip_hdr_len=ip_pkt->ihl*4;
	if(tot_len>MAX_IP_LEN){
		send_queue->queue[++(send_queue->tail)]=(struct iphdr*)ip_pkt;
		printf("Error:the ip_pkt_len is %d,exceed the MAX_IP_LEN\n",tot_len);
		return -1;
	}

	if(frag_size%8!=0){
		send_queue->queue[++(send_queue->tail)]=(struct iphdr*)ip_pkt;
		printf("Overlap error: frag_size must be times of 8\n");
		return -1;
	}


	if(frag_size<overlap_size){
		send_queue->queue[++(send_queue->tail)]=(struct iphdr*)ip_pkt;
		printf("Overlap error: overlap_size exceed the frag_size\n");
		return -1;
	}

	if(tot_len-ip_hdr_len<=frag_size){  
		send_queue->queue[++(send_queue->tail)]=(struct iphdr*)ip_pkt;
		printf("Overlap error: frag_size exceed the data_len\n");
		return -1;
	}
	return 0;
}
