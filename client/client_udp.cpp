#include "../Protocol/Header_Include.h"
#include "../Protocol/Transport_UDP_Interface.h"

u_int8_t client_buffer[MAXIPLEN];
u_int8_t reply_buffer[MAXIPLEN];
extern u_int8_t target_ip[4];
extern int local_port;
extern int target_port;
int main()
{
    printf("----------client work begin----------\n");
    init_arp_table();
    output_arp_table();
    open_device();
    MY_SOCKET client_socket = my_socket(AF_INET,SOCK_DGRAM,IPPROTO_IP);
    if(!client_socket){
        printf("can't get a socket\n");
        return 0;
    }
    memcpy(client_socket->local_address,local_ip,4);
    client_socket->local_port  = local_port;
    //printf("1\n");
    FILE * fp = fopen("data.txt","rb");
    int i = 0;
    if(fp) {
        char ch;
        //printf("2\n");
        while ((ch = fgetc(fp)) != EOF) {
            //printf("2\n");
            *(client_buffer + i) = ch;
            //printf("2\n");
            i++;
        }
        fclose(fp);
    }
    else{
        printf("file is not found\n");
        return 0;
    }
    //printf("2\n");
    my_socketaddr_in* server_addr = (my_socketaddr_in *) malloc(sizeof(my_socketaddr_in));
    server_addr->sin_family = AF_INET;
    server_addr->sin_port = target_port;
    memcpy(&server_addr->sin_addr,target_ip,4);
    my_sendto(client_socket,client_buffer,i,0,(my_socketaddr*)server_addr,sizeof(my_socketaddr_in));
    //printf("3\n");
    my_socketaddr * from_addr = (my_socketaddr *) malloc(sizeof(from_addr));
    int recv_len = my_recvfrom(client_socket,reply_buffer,MAXIPLEN,0,from_addr,sizeof(my_socketaddr));
    //printf("3\n");
    fp = fopen("reply.txt","w");
    fwrite(reply_buffer+sizeof(UDP_header),recv_len,1,fp);
    fclose(fp);
    my_closesocket(client_socket);
    close_device();
    printf("----------client work done----------\n");
    return 0;
}