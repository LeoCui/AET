#pragma once
#include"./utils.h"

void ip_frag(struct iphdr* ip_pkt,u_int16_t frag_size,struct ip_pkt_send_queue* send_queue);

void modify_ttl(struct iphdr* old_ip_pkt,u_int16_t ttl,struct ip_pkt_send_queue* send_queue);

void print_ip_packet(struct iphdr* ip_pkt);
void print_tcp_packet(struct iphdr* ip_pkt);
void ip_overlap(struct iphdr* ip_pkt,u_int16_t frag_size,u_int16_t overlap_size,
u_int8_t mode,struct ip_pkt_send_queue* send_queue);
int ip_overlap_check(struct iphdr*ip_pkt,u_int16_t tot_len,u_int16_t frag_size,
	u_int16_t overlap_size,struct ip_pkt_send_queue* send_queue);
void tcp_segment(struct iphdr* ip_pkt,u_int16_t tcp_segment_size,struct ip_pkt_send_queue* send_queue);

void tcp_overlap(struct iphdr* ip_pkt,u_int16_t segment_size,u_int16_t overlap_size,
u_int8_t mode,struct ip_pkt_send_queue* send_queue);

void send_ip_pkt(int thread_index,u_int8_t dir,struct ip_pkt_send_queue* queue);
void my_send_ip_pkt(char* pkt,int buf_len,u_int32_t addr);
void modify_tcp_flags(struct iphdr* old_ip_pkt,char* flag,struct ip_pkt_send_queue* queue);
void modify_mss(struct iphdr* old_ip_pkt,u_int16_t size,
struct ip_pkt_send_queue* send_queue);
void modify_wscale(struct iphdr* old_ip_pkt,u_int8_t num,
struct ip_pkt_send_queue* send_queue);

int is_mss_existed(struct tcphdr* tcp_pkt);
int is_wscale_existed(struct tcphdr* tcp_pkt);














