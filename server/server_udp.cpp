#include "../Protocol/Header_Include.h"
#include "../Protocol/Transport_UDP_Interface.h"
#include "../Protocol/Network_IPV4_Protocol.h"
u_int8_t server_buffer[MAXIPLEN];
int main()
{
    printf("----------server work begin----------\n");
    init_arp_table();
    output_arp_table();
    open_device();
    MY_SOCKET server_socket = my_socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);
    if(!server_socket){
        printf("can't get a socket\n");
        return 0;
    }
    my_socketaddr_in Servaddr;
    Servaddr.sin_family = AF_INET;
    Servaddr.sin_port = local_port;
    Servaddr.sin_addr.s_addr = *((u_int32_t *)local_ip);
    int nResult = my_bind(server_socket,(my_socketaddr *) &Servaddr,sizeof(Servaddr));
    if(nResult == SOCKET_ERROR)
    {
        printf("can't bind the socketaddr\n");
        return 0;
    }
    my_socketaddr* user_addr = (my_socketaddr *) malloc(sizeof(my_socketaddr_in));
    int recv_length = my_recvfrom(server_socket,server_buffer,MAXIPLEN,0,user_addr,sizeof(user_addr));
    FILE * fp = fopen("data.txt","w");
    fwrite(server_buffer+sizeof(UDP_header),recv_length,1,fp);
    fclose(fp);
    memset(server_buffer,0,recv_length);
    fp = fopen("reply.txt","r");
    int i = 0;
    char ch;
    while((ch = fgetc(fp)) != EOF)
    {
        *(server_buffer+i) = ch;
        i++;
    }
    my_sendto(server_socket,server_buffer,i,0,user_addr,sizeof(my_socketaddr_in));
    my_closesocket(server_socket);
    close_device();
    printf("----------server work done----------\n");
    return 0;
}