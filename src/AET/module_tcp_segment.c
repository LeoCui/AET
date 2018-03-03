#include"./module.h"
#include"./utils.h"

void tcp_segment(struct iphdr* ip_pkt,u_int16_t tcp_segment_size,struct ip_pkt_send_queue* send_queue){
	//tcp segment: Ip layer:not ip_frag

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
	printf("---------------------------------------Tcp Segment------------------------------\n");
	u_int8_t ip_hdr_len=ip_pkt->ihl*4;
	u_int16_t ip_tot_len=ntohs(ip_pkt->tot_len);
	struct tcphdr* tcp_pkt=(struct tcphdr*)((char*)ip_pkt+ip_hdr_len);
	u_int8_t tcp_hdr_len=tcp_pkt->doff*4;
	u_int16_t tcp_payload_len=ip_tot_len-ip_hdr_len-tcp_hdr_len;
	u_int16_t i=0;
	for(i=0;i<tcp_payload_len;){
		u_int16_t new_tcp_payload_len=tcp_segment_size;
		if(i+tcp_segment_size>tcp_payload_len){
			new_tcp_payload_len=tcp_payload_len-i;
		}
		char* new_ip_pkt=malloc(ip_hdr_len+tcp_hdr_len+new_tcp_payload_len);
		struct iphdr* new_ip_hdr=(struct iphdr*)new_ip_pkt;
		struct tcphdr* new_tcp_hdr=(struct tcphdr*)(new_ip_pkt+ip_hdr_len);
		copy_ip_header(new_ip_hdr,ip_pkt);
		copy_tcp_header(new_tcp_hdr,tcp_pkt); 
		mystrcpy(new_ip_pkt+ip_hdr_len+tcp_hdr_len,(char *)ip_pkt+ip_hdr_len+tcp_hdr_len+i,
			new_tcp_payload_len);

		new_tcp_hdr->seq=htonl(ntohl(tcp_pkt->seq)+i);
		modify_tcp_checksum(new_ip_hdr);//tcp
		
		((struct iphdr*)new_ip_pkt)->tot_len=htons(ip_hdr_len+tcp_hdr_len+new_tcp_payload_len);
		modify_ip_checksum((unsigned char*)new_ip_pkt);  //ip

		i+=tcp_segment_size;
		
		send_queue->queue[++(send_queue->tail)]=(struct iphdr*)new_ip_pkt;
	}
}


