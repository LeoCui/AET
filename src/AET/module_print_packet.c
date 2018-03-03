#include"./utils.h"

void print_ip_packet(struct iphdr* ip_pkt){
	u_int16_t header_length;
	u_int16_t tot_len;
	u_int16_t offset;
	u_int8_t tos;
	u_int8_t trans_protocol;
	u_int16_t checksum;
	trans_protocol=ip_pkt->protocol;
	checksum=ntohs(ip_pkt->check);
	header_length=ip_pkt->ihl*4;
	tot_len=ntohs(ip_pkt->tot_len);
	tos=ip_pkt->tos;
	offset=ntohs(ip_pkt->frag_off);
	printf("------------IP Protocol Layer--------\n");
	//printf("The frag_num is %d\n",frag_num);
	//int j;
	//unsigned char* temp=(unsigned char*)ip_pkt;
	//for(j=0;j<20;j++){
	//	printf("0x:%0x ",*(temp+j));
	//}
	printf("\n");
	printf("IP Version:%d\n",ip_pkt->version);
	printf("Header length:%d\n",header_length);
	printf("TOS:%d\n",tos);
	printf("Total length:%d\n",tot_len);
	printf("Identification:%d\n",ntohs(ip_pkt->id));
	printf("Offset:%0x  %d\n",offset,(offset&0x1fff)*8);
	printf("TTL:%d\n",ip_pkt->ttl);
	printf("Protocol:%d\n",trans_protocol);
	switch(trans_protocol){
		case(6):
			printf("The Transport Layer protocol is TCP\n");
			break;
		case(17):
			printf("The Transport Layer protocol is UDP\n");
			break;
		case(1):
			printf("The Transport Layer protocol is ICMP\n");
			break;
		default:
			break;
	}
	printf("Header checksum:%0x\n",checksum);
	char dst[100];
        inet_ntop(AF_INET,(const void*)&(ip_pkt->saddr),dst,sizeof(dst));
	printf("Source address:%s\n",dst);
	inet_ntop(AF_INET,(const void*)&(ip_pkt->daddr),dst,sizeof(dst));
	printf("Destination address:%s\n",dst);
	u_int16_t i;
	printf("The IP data len is %d\n",tot_len-header_length);
	printf("The IP data is : ");
	for(i=header_length;i<tot_len;i++){
		printf("%c",*((char*)ip_pkt+i));
	}
	printf("\n");
}

void print_tcp_packet(struct iphdr* ip_pkt){
	int ip_hdr_len=ip_pkt->ihl*4;
	int protocol=ip_pkt->protocol;
	if(protocol!=6){
		printf("Print_tcp_packet error: the transport layer is not TCP\n");
		return;
	}
	u_int16_t tot_len=ntohs(ip_pkt->tot_len);
	struct tcphdr* tcp_pkt=(struct tcphdr*)((char*)ip_pkt+ip_hdr_len);
	u_int16_t source_port=ntohs(tcp_pkt->source);
	u_int16_t dst_port=ntohs(tcp_pkt->dest);
	u_int32_t seq=ntohl(tcp_pkt->seq);
	u_int32_t ack=ntohl(tcp_pkt->ack_seq);
	u_int8_t tcp_hdr_len=tcp_pkt->doff*4;
	u_int16_t checksum=ntohs(tcp_pkt->check);
	printf("----------------------------TCP Layer--------------------------------\n");
	printf("The tcp_hdr_len is %"PRIu8"\n",tcp_hdr_len);
	printf("The source port is %"PRIu16"\n",source_port);
	printf("The dst port is %"PRIu16"\n",dst_port);
	printf("The seq is %"PRIu32"\n",seq);
	printf("The ack is %"PRIu32"\n",ack);
	printf("The checksum is %"PRIu16"\n",checksum);
	printf("The flags is: ");
	if(tcp_pkt->syn!=0)
		printf("syn ");
	if(tcp_pkt->ack!=0)
		printf("ack ");
	if(tcp_pkt->psh!=0)
		printf("psh ");
	if(tcp_pkt->fin!=0)
		printf("fin ");
	if(tcp_pkt->rst!=0)
		printf("rst ");
	if(tcp_pkt->urg!=0)
		printf("urg ");
	printf("\n");
	int i;
	u_int8_t* ptr=(u_int8_t*)tcp_pkt;
	printf("Tcp options is:\n");
	for(i=20;i<tcp_hdr_len;){
		if(ptr[i]==0)
			break;
		if(ptr[i]==1){
			i++;
			continue;
		}
		switch(ptr[i]){
			case(2):{
				int len=(ptr[i+2]<<8)+ptr[i+3];
				printf("MSS: %d\n",len);
				i+=ptr[i+1];
				break;
			}
			case(3):{
				int window_scale=ptr[i+2];
				printf("Window_scale: %d\n",window_scale);
				i+=ptr[i+1];
				break;
			}
			case(4):{
				printf("SACK ");
				i+=ptr[i+1];
				break;
			}
			case(5):{
				printf("SACK OPTION ");
				i+=ptr[i+1];
				break;
			}
			case(8):{
				u_int32_t TimeStamps=(ptr[i+2]<<24)+(ptr[i+3]<<16)+(ptr[i+4]<<8)+ptr[i+5];
				u_int32_t Echo=(ptr[i+6]<<24)+(ptr[i+7]<<16)+(ptr[i+8]<<8)+ptr[i+9];
				printf("TimeStamps :%"PRIu32"  %"PRIu32"(echo)\n",TimeStamps,Echo);
				i+=ptr[i+1];
				break;
			}
			case(30):{
				printf("MPTCP ");
				i+=ptr[i+1];
				break;
			}
			default:{
				break;
			}
		}
	}
	printf("Tcp payload is:\n");
	for(i=tcp_hdr_len;i<tot_len-ip_hdr_len;i++){
		printf("%c",ptr[i]);
	}
	printf("\n");
}

