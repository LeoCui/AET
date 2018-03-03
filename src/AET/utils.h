#pragma once
#include<MESA/stream.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<arpa/inet.h>
#include<sys/types.h>
#include<sys/socket.h>
#include<inttypes.h>
#include<netinet/in.h>


#define MAX_IP_LEN 1500
#define DEFAULT_TTL 64
#define IP_PKT_SEND_QUEUE_SIEE 1500
struct ip_pkt_send_queue{
	struct iphdr* queue[IP_PKT_SEND_QUEUE_SIEE];
	int head;
	int tail;
};
void mystrcpy(char* dst,char* src,int size);
void copy_ip_header(struct iphdr* new_ip_pkt,struct iphdr* old_ip_pkt);
void copy_ip_data(struct iphdr*new_ip_pkt,struct iphdr*old_ip_pkt);
void copy_tcp_header(struct tcphdr* new_tcp_pkt,struct tcphdr* old_tcp_pkt);

void  init_ip_data(char *ip_pkt,char *data,u_int16_t data_len);
void  modify_ip_checksum(unsigned char* ip_pkt);
void  modify_tcp_checksum(struct iphdr* ip_pkt);




