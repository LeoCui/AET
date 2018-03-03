#include"./utils.h"
#include"./module.h"


void modify_ttl(struct iphdr* old_ip_pkt,u_int16_t ttl,struct ip_pkt_send_queue* send_queue){
	u_int16_t tot_len=ntohs(old_ip_pkt->tot_len);
	char* new_ip_pkt=malloc(tot_len);
	copy_ip_header((struct iphdr*)new_ip_pkt,old_ip_pkt);
	copy_ip_data((struct iphdr*)new_ip_pkt,old_ip_pkt);
	((struct iphdr*)new_ip_pkt)->ttl=ttl; 
	modify_ip_checksum((unsigned char*)new_ip_pkt);
	send_queue->queue[++(send_queue->tail)]=(struct iphdr*)new_ip_pkt;
}
