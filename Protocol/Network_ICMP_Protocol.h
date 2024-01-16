#include"Header_Include.h"
#define icmp_req 0
#define icmp_ans 8
#define icmp_unreach 3
typedef struct icmp_header
{
    u_int8_t type;//类型字段
    u_int8_t code;//代码
    u_int16_t checksum;//校验和
    u_int16_t identifier;//标识符
    u_int16_t sequence_num;//序列号
}icmp_header;


int Network_ICMP_recv(u_int8_t *icmp_buffer,int len);
int network_ICMP_send( u_int8_t type);
