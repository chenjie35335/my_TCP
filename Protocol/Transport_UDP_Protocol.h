#include "Header_Include.h"
#include "Ethernet.h"
#include "Network_ARP_Protocol.h"


#define SOCKET_ERROR    (-1)
#define SOCKET_SUCCESS  1
#define MAXUDPLEN       2048
#define MAXIPLEN        4096
typedef unsigned int socklen_t;

typedef struct my_sock{
    u_int8_t * local_address;
    int local_port;
    u_int8_t * target_address;
    int target_port;
    int type;
}my_sock,*MY_SOCKET;

typedef struct UDP_header
{
    u_int16_t source_port;
    u_int16_t des_port;
    u_int16_t len;
    u_int16_t checksum;
}UDP_header;

typedef struct UDP_fake_header{
    u_int8_t source_address[4];
    u_int8_t des_address[4];
    u_int8_t zero;
    u_int8_t protocol;
    u_int16_t sum_len;
}UDP_fake_header;

extern pcap_t *handle;

int Transport_UDP_send(MY_SOCKET sockid,u_int8_t *buf,int len,int flags);
int network_ipv4_send(u_int8_t *source_address,u_int8_t *des_address, u_int8_t *ip_data_buffer,int data_len,u_int8_t protocol);
int transport_udp_recv(u_int8_t *source_address,u_int8_t *udp_buffer, int len);