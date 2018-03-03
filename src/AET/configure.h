#pragma once
#include<./utils.h>
#define MAX_COMMAND_NUM 100
#define MAX_OPTION_SIZE 10
#define MAX_COMMAND_SIZE 128
#define DEFAULT_IP_FRAG_SIZE 8
#define DEFAULT_IP_OVERLAP_SIZE 2
#define DEFAULT_TCP_SEGMENT_SIZE 8
#define DEFAULT_TCP_OVERLAP_SIZE 2
struct command{
	char command_str[MAX_COMMAND_SIZE];
	int seq;
};
struct command_set{
	struct command command1[MAX_COMMAND_NUM];
	int num;
};
void init_command_set_system();
void init_command_set_user();
int  add_command(char *command_str,struct command_set* command_set1);
//void handle(struct ip_pkt_send_queue* send_queue);

void exec_command_set(struct ip_pkt_send_queue* send_queue);

int string_to_int(char* str,u_int16_t *result);
int split_command_str(char* src,char* dst,int begin,int end);
