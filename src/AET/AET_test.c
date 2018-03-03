#include"./utils.h"
#include"./module.h"
#include"./AET_test.h"
#include"./configure.h"
int AET_init(){
	printf("AET: succeed to init\n");
	init_command_set_system();
	init_command_set_user();
	return 1;
	//TODO
}

void AET_destroy(){
	printf("AET: succeed to destroy\n");
}

char business_ip_entry(struct streaminfo*f_stream,unsigned char routedir,
int thread_seq,const void* entry_ip_pkt){

	printf("Succeed: business_ip_entry called\n");
	struct ip_pkt_send_queue   send_queue;
	send_queue.head=0;
	send_queue.tail=-1;
	struct iphdr* ip_pkt=(struct iphdr*)entry_ip_pkt;
	int tail=++(send_queue.tail);
	send_queue.queue[tail]=ip_pkt;
	exec_command_set(&send_queue);   //execute the command_set_user in turn
	send_ip_pkt(thread_seq,routedir,&send_queue);
	return APP_STATE_GIVEME;
}


