#include"./utils.h"
void mystrcpy(char* dst,char* src,int size){
		int i;
		for(i=0;i<size;i++){
			*(dst+i)=*(src+i);
		}
}

void copy_ip_header(struct iphdr* new_ip_pkt,struct iphdr* old_ip_pkt){
	new_ip_pkt->version=old_ip_pkt->version;
	new_ip_pkt->ihl=old_ip_pkt->ihl;
	new_ip_pkt->tos=old_ip_pkt->tos;
	new_ip_pkt->tot_len=old_ip_pkt->tot_len;
	new_ip_pkt->id=old_ip_pkt->id;
	new_ip_pkt->frag_off=old_ip_pkt->frag_off;   //TODO:offset
	new_ip_pkt->ttl=old_ip_pkt->ttl;
	new_ip_pkt->protocol=old_ip_pkt->protocol;
	new_ip_pkt->check=old_ip_pkt->check;
	new_ip_pkt->saddr=old_ip_pkt->saddr;
	new_ip_pkt->daddr=old_ip_pkt->daddr;

	//char* dst_ip="10.0.6.203";
	//u_int32_t* addr=&(new_ip_pkt->daddr);
	//inet_aton(dst_ip,(struct in_addr*)addr);

	modify_ip_checksum((unsigned char*)new_ip_pkt);
}

void  init_ip_data(char *ip_pkt,char *data,u_int16_t data_len){
	u_int16_t i;
	int ip_hdr_len=((struct iphdr*)ip_pkt)->ihl*4;
	for(i=0;i<data_len;i++)
		ip_pkt[ip_hdr_len+i]=data[i];
}

void copy_ip_data(struct iphdr*new_ip_pkt,struct iphdr*old_ip_pkt){
	u_int16_t tot_len=ntohs(old_ip_pkt->tot_len);
	u_int16_t i;
	u_int8_t ip_hdr_len=old_ip_pkt->ihl*4;
	char* new_ip_pkt_ptr=(char*)new_ip_pkt;
	char* old_ip_pkt_ptr=(char*)old_ip_pkt;
	for(i=ip_hdr_len;i<tot_len;i++){
		new_ip_pkt_ptr[i]=old_ip_pkt_ptr[i];
	}
}

void copy_tcp_header(struct tcphdr* new_tcp_pkt,struct tcphdr* old_tcp_pkt){
	u_int16_t tcp_hdr_len=old_tcp_pkt->doff*4;
	u_int16_t i=0;
	char* new_tcp_pkt1=(char*)new_tcp_pkt;
	char* old_tcp_pkt1=(char*)old_tcp_pkt;
	for(i=0;i<tcp_hdr_len;i++){
		*(new_tcp_pkt1+i)=*(old_tcp_pkt1+i);
	}
}
void  modify_ip_checksum(unsigned char* ip_pkt){
	//int j;
	//for(j=0;j<20;j++){
		//printf("0x:%"PRIx8,*(ip_pkt+j));
	//}
	//printf("\n");
    int32_t cksum = 0;
	int index = 0;
	*(ip_pkt + 10) = 0;
	*(ip_pkt + 11) = 0;
	while(index < 20)
	{        
		cksum += *(ip_pkt + index + 1);
		cksum += *(ip_pkt + index) << 8;
		index += 2;
	}

	while(cksum > 0xffff)
	{
		cksum = (cksum >> 16) + (cksum & 0xffff);
	}
	//printf("checksum is %0x %0x\n",cksum,~cksum);
	u_int16_t temp=~cksum;
	((struct iphdr*)ip_pkt)->check=htons(temp);
}

void  modify_tcp_checksum(struct iphdr* ip_pkt)
{
	int ip_hdr_len=ip_pkt->ihl*4;
	int ip_tot_len=ntohs(ip_pkt->tot_len);
	int size=ip_tot_len-ip_hdr_len;
	u_int16_t* buffer=(u_int16_t*)(((char*)ip_pkt)+ip_hdr_len);
	uint32_t saddr=ip_pkt->saddr;
	uint32_t daddr=ip_pkt->daddr;
	((struct tcphdr*)buffer)->check=0;
	
    uint32_t sum;
    uint16_t *w;
    int nleft;
    sum = 0;
    nleft = size;
    w = buffer;
    while (nleft > 1)
    {
        sum += *w++;
        --nleft;
		--nleft;
    }

    // add padding for odd length
    if (nleft)
        sum += *w & ntohs(0xFF00);

    // add pseudo header
    sum += (saddr & 0x0000FFFF) + (saddr >> 16);
    sum += (daddr & 0x0000FFFF) + (daddr >> 16);
    sum += htons(size);
    sum += htons(IPPROTO_TCP);

    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    sum = ~sum;
    ((struct tcphdr*)buffer)->check=(uint16_t)sum;
	
}

