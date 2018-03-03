#include"./module.h"
#include"./utils.h"
#define OVERLAP_CHAR '#'
void tcp_overlap(struct iphdr* ip_pkt,u_int16_t segment_size,u_int16_t overlap_size,
u_int8_t mode,struct ip_pkt_send_queue* send_queue){
	u_int16_t offset=ntohs(ip_pkt->frag_off);
	int df=offset&0x4000;
	int protocol=ip_pkt->protocol;
	if(df==0){
		printf("TCP segment error: ip has been fraged\n");
		return;
	}
	if(protocol!=6){
		printf("TCP segment error: the transport layer is not TCP\n");
		return;
	}
	printf("---------------------------------------Tcp Overlap------------------------------\n");
	u_int8_t ip_hdr_len=ip_pkt->ihl*4;
	u_int16_t ip_tot_len=ntohs(ip_pkt->tot_len);
	struct tcphdr* tcp_pkt=(struct tcphdr*)((char*)ip_pkt+ip_hdr_len);
	u_int8_t tcp_hdr_len=tcp_pkt->doff*4;
	u_int16_t tcp_payload_len=ip_tot_len-ip_hdr_len-tcp_hdr_len+overlap_size;
	char* tcp_payload_str=malloc(tcp_payload_len);
	unsigned char* tcp_payload=(unsigned char*)tcp_pkt+tcp_hdr_len;
	int i;
	u_int16_t size=segment_size-overlap_size;
	if(mode==0){
		for(i=0;i<size;i++)
			tcp_payload_str[i]=tcp_payload[i];
		for(i=size;i<segment_size;i++)
			tcp_payload_str[i]=OVERLAP_CHAR;
		for(i=segment_size;i<tcp_payload_len;i++)
			tcp_payload_str[i]=tcp_payload[i-overlap_size];
	}
	else{
		for(i=0;i<segment_size;i++)
			tcp_payload_str[i]=tcp_payload[i];
		for(i=segment_size;i<segment_size+overlap_size;i++)
			tcp_payload_str[i]=OVERLAP_CHAR;
		for(i=segment_size+overlap_size;i<tcp_payload_len;i++)
			tcp_payload_str[i]=tcp_payload[i-overlap_size];
	}
	
	for(i=0;i<tcp_payload_len;){
			u_int16_t new_tcp_payload_len=segment_size;
			if(i+segment_size>tcp_payload_len){
				new_tcp_payload_len=tcp_payload_len-i;
			}
			char* new_ip_pkt=malloc(ip_hdr_len+tcp_hdr_len+new_tcp_payload_len);
			struct iphdr* new_ip_hdr=(struct iphdr*)new_ip_pkt;
			struct tcphdr* new_tcp_hdr=(struct tcphdr*)(new_ip_pkt+ip_hdr_len);
			copy_ip_header(new_ip_hdr,ip_pkt);
			copy_tcp_header(new_tcp_hdr,tcp_pkt); 
			mystrcpy(new_ip_pkt+ip_hdr_len+tcp_hdr_len,tcp_payload_str+i,
				new_tcp_payload_len);
	
			new_tcp_hdr->seq=htonl(ntohl(tcp_pkt->seq)+i);
			modify_tcp_checksum(new_ip_hdr);//tcp
			
			((struct iphdr*)new_ip_pkt)->tot_len=htons(ip_hdr_len+tcp_hdr_len+new_tcp_payload_len);
			modify_ip_checksum((unsigned char*)new_ip_pkt);  //ip
	
			i+=segment_size;
			
			send_queue->queue[++(send_queue->tail)]=(struct iphdr*)new_ip_pkt;
	}
	free(tcp_payload_str);
}

