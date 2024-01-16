#include "Transport_UDP_Protocol.h"
extern u_int8_t local_ip[4];
extern int local_port;

struct my_in_addr{
    u_int32_t s_addr;
};

typedef struct my_socketaddr{
    int sa_family;
    u_int8_t sa_addr[18];
}my_socketaddr;

typedef struct my_socketaddr_in{
    int sin_family;
    int sin_port;
    struct my_in_addr sin_addr;
}socketaddr_in;


MY_SOCKET my_socket(int af, int type, int protocol);
int my_bind(MY_SOCKET sockid,my_socketaddr * Servaddr,socklen_t addrlen);
int my_sendto(MY_SOCKET sockid,u_int8_t *buf,int len,int flags,my_socketaddr * to,int tolen);
int my_recvfrom(MY_SOCKET sockid,u_int8_t *buf,int len,int flags,my_socketaddr *from,int fromlen);
int my_closesocket(MY_SOCKET sockid);