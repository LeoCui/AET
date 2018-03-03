#pragma once
#include"./configure.h"
#include"./module.h"

static struct command_set command_set_system;
static struct command_set command_set_user;
void init_command_set_system(){
	command_set_system.num=0;
	add_command("ip_frag",&command_set_system);
	add_command("ip_overlap",&command_set_system);
	add_command("modify_ttl",&command_set_system);
	add_command("print_ip_pkt",&command_set_system);
	add_command("print_tcp_pkt",&command_set_system);
	add_command("tcp_segment",&command_set_system);
	add_command("tcp_overlap",&command_set_system);
	add_command("modify_tcp_flags",&command_set_system);
	add_command("modify_mss",&command_set_system);
	add_command("modify_wscale",&command_set_system);
}

void init_command_set_user(){
	command_set_user.num=0;
	FILE *fp;
	char conf_path[]="./plug/business/AET/AET.conf";
	if((fp=fopen(conf_path,"r"))==NULL){
		printf("File can not be opened\n");
		return;
	}
	char command_str[MAX_COMMAND_SIZE]="";
	while(fgets(command_str,MAX_COMMAND_SIZE,fp)!=NULL){
			int len=strlen(command_str);
			command_str[len-1]='\0';   // "abcd\n\0"--->"abcd\0"
			add_command(command_str,&command_set_user);
	}
	fclose(fp);
}
int  add_command(char *command_str,struct command_set*command_set1){
	int num=command_set1->num;
	if(num==MAX_COMMAND_NUM){
		printf("can not add command: exceed the max_command_num\n");
		return -1;
	}
	if(strlen(command_str)>=MAX_COMMAND_SIZE){
		printf("can not add command: exceed the max_command_size\n");
		return -1;
	}
	strcpy(command_set1->command1[num].command_str,command_str);
	command_set1->command1[num].seq=num;
	command_set1->num++;
	return 0;
}

void exec_command_set(struct ip_pkt_send_queue* send_queue){
	int user_command_num=command_set_user.num;
	int i;
	for(i=0;i<user_command_num;i++){
		char command_str[MAX_COMMAND_SIZE]="";
		strcpy(command_str,command_set_user.command1[i].command_str);
		int len=strlen(command_str);
		char command_type[MAX_COMMAND_SIZE]="";
		char option1[MAX_OPTION_SIZE]="";
		char option2[MAX_OPTION_SIZE]="";
		char option3[MAX_OPTION_SIZE]="";
		
		int begin=split_command_str(command_str,command_type,0,len-1);
		begin=split_command_str(command_str,option1,begin,len-1);
		begin=split_command_str(command_str,option2,begin,len-1);
		begin=split_command_str(command_str,option3,begin,len-1);

		int system_command_num=command_set_system.num;
		int j,command_seq=-1;
		for(j=0;j<system_command_num;j++){
			if(strcmp(command_set_system.command1[j].command_str,command_type)==0){
				command_seq=command_set_system.command1[j].seq;
				break;
			}
		}
		int head=send_queue->head;
	    int tail=send_queue->tail;
		for(j=head;j<=tail;j++){
			struct iphdr* ip_pkt=send_queue->queue[j];
			switch(command_seq){
				case(-1):{
					printf("Error: %s is not a valid command!\n",command_type);
					return;
				}
				case(0):{  //ip_frag
					u_int16_t frag_size=DEFAULT_IP_FRAG_SIZE; //default frag size
					int rtn=string_to_int(option1,&frag_size);
					if(rtn==-1){
						printf("Error: %s is not a valid option\n",option1);
						return;
					}
					ip_frag(ip_pkt,frag_size,send_queue);
					break;
				}
				
				case(1):{ //ip_overlap
					u_int16_t frag_size=DEFAULT_IP_FRAG_SIZE; //default frag size
					u_int16_t overlap_size=DEFAULT_IP_OVERLAP_SIZE; //default overlap size
					int rtn=string_to_int(option1,&frag_size);
					if(rtn==-1){
						printf("Error: %s is not a valid option\n",option1);
						return;
					}
					rtn=string_to_int(option2,&overlap_size);
					if(rtn==-1){
						printf("Error: %s is not a valid option\n",option2);
						return;
					}
					if(strcmp(option3,"new")!=0&&strcmp(option3,"old")!=0){
						printf("Error: %s is not a valid option\n",option3);
						return;
					}
					u_int8_t mode=-1;
					if(strcmp(option3,"new")==0) //new,mode=0, the second overlap the first
						mode=0;
					else
						mode=1;
					ip_overlap(ip_pkt,frag_size,overlap_size,mode,send_queue);
					break;
				}
				
				case(2):{ //modify_ttl
					u_int16_t ttl=64; //default ttl
					int rtn=string_to_int(option1,&ttl);
					if(rtn==-1){
						printf("Error: %s is not a valid option\n",option1);
						return;
					}
					modify_ttl(ip_pkt,ttl,send_queue);
					break;
				}
				case(3):{		
					print_ip_packet(ip_pkt);
					break;
				}
				case(4):{
					print_tcp_packet(ip_pkt);
					break;    //very important
				}
				case(5):{ //tcp segment
					u_int16_t segment_size=DEFAULT_TCP_SEGMENT_SIZE; 
					int rtn=string_to_int(option1,&segment_size);
					if(rtn==-1){
						printf("Error: %s is not a valid option\n",option1);
						return;
					}
					tcp_segment(ip_pkt,segment_size,send_queue);
					break;
				}
				case(6):{ //tcp_overlap
					u_int16_t segment_size=DEFAULT_TCP_SEGMENT_SIZE; //default frag size
					u_int16_t overlap_size=DEFAULT_TCP_OVERLAP_SIZE; //default overlap size
					int rtn=string_to_int(option1,&segment_size);
					if(rtn==-1){
						printf("Error: %s is not a valid option\n",option1);
						return;
					}
					rtn=string_to_int(option2,&overlap_size);
					if(rtn==-1){
						printf("Error: %s is not a valid option\n",option2);
						return;
					}
					if(strcmp(option3,"new")!=0&&strcmp(option3,"old")!=0){
						printf("Error: %s is not a valid option\n",option3);
						return;
					}
					u_int8_t mode=-1;
					if(strcmp(option3,"new")==0) //new,mode=0, the second overlap the first
						mode=0;
					else
						mode=1;
					tcp_overlap(ip_pkt,segment_size,overlap_size,mode,send_queue);
					break;
				}
				case(7):{  //modify_tcp_flags
					modify_tcp_flags(ip_pkt,option1,send_queue);
					break;
				}
				case(8):{
					u_int16_t size=-1;
					int rtn=string_to_int(option1,&size);
					if(rtn==-1){
						printf("Error: %s is not a valid option\n",option1);
						return;
					}
					modify_mss(ip_pkt,size,send_queue);
					break;
				}
				case(9):{
					u_int16_t num=-1;
					int rtn=string_to_int(option1,&num);
					if(num>0xff){
						printf("Error: the wscale must be no more than 255\n");
						return;
					}
					if(rtn==-1){
						printf("Error: %s is not a valid option\n",option1);
						return;
					}
					modify_wscale(ip_pkt,num,send_queue);
					break;
				}
				default:{
					break;
				}
			}
			if(command_seq!=3&&command_seq!=4){  //not print
				if(j!=0){
					free(send_queue->queue[j]);
				}
				send_queue->head++;
			}
		}
	}
}

int string_to_int(char* str,u_int16_t* result){
	if(*str=='\0')
		return 0; //default frag_size
	int len=strlen(str);
	int sum=0;
	int i;
	for(i=0;i<len;i++){
		if(str[i]>='0'&&str[i]<='9')
			sum=sum*10+str[i]-'0';
		else
			return -1;
	}
	*result=sum;
	return 0;
}
int split_command_str(char* src,char* dst,int begin,int end){
	while(begin<=end){
		if(src[begin]==' ')
			break;
		*dst=src[begin++];
		dst++;
	}
	*dst='\0';
	return begin+1;
}
