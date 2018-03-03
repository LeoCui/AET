#pragma once
#include<MESA/stream.h>
#include<stdio.h>
#include<arpa/inet.h>
int AET_init();
void AET_destroy();
char business_ip_entry(struct streaminfo*f_stream,unsigned char routedir,
int thread_seq,const void* entry_ip_pkt);

