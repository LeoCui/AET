cc=gcc
objects = AET_test.o module_ip_frag.o module_ip_overlap.o module_modify_ttl.o module_tcp_segment.o module_tcp_overlap.o module_print_packet.o module_send_packet.o module_modify_tcp_flags.o module_modify_mss.o  module_modify_wscale.o configure.o utils.o
AET_test.so : $(objects)
	cc -g -Wall -shared -o AET_test.so $(objects)
AET_test.o : AET_test.c
	cc -g -Wall -fPIC -c AET_test.c
module_ip_frag.o : module_ip_frag.c
	cc -g -Wall -fPIC -c module_ip_frag.c
module_ip_overlap.o : module_ip_overlap.c
	cc -g -Wall -fPIC -c module_ip_overlap.c
module_modify_ttl.o : module_modify_ttl.c
	cc -g -Wall -fPIC -c module_modify_ttl.c
module_tcp_segment.o : module_tcp_segment.c
	cc -g -Wall -fPIC -c module_tcp_segment.c
module_tcp_overlap.o : module_tcp_overlap.c
	cc -g -Wall -fPIC -c module_tcp_overlap.c
module_print_packet.o : module_print_packet.c
	cc -g -Wall -fPIC -c module_print_packet.c
module_send_packet.o : module_send_packet.c
	cc -g -Wall -fPIC -c module_send_packet.c
module_modify_tcp_flags.o : module_modify_tcp_flags.c
	cc -g -Wall -fPIC -c module_modify_tcp_flags.c
module_modify_mss.o : module_modify_mss.c
	cc -g -Wall -fPIC -c module_modify_mss.c
module_modify_wscale.o : module_modify_wscale.c
	cc -g -Wall -fPIC -c module_modify_wscale.c
configure.o : configure.c
	cc -g -Wall -fPIC -c configure.c
utils.o : utils.c
	cc -g -Wall -fPIC -c utils.c
.PHONY : clean
clean : 
	rm AET_test.so $(objects) 
