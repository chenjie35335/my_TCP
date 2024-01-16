#include "Transport_UDP_Interface.h"
#include "Network_ICMP_Protocol.h"

#include <cstdlib>

extern int recv_len;
u_int8_t * rf_buf;
int rf_len;
u_int16_t calculate_check_sum_udp(UDP_fake_header *UDP_fhd,UDP_header *UDP_hd,u_int8_t *buf,int len);
extern u_int8_t *source_ip;
MY_SOCKET my_socket(int af, int type, int protocol)
{
    if(af != AF_INET || protocol != IPPROTO_IP){
        printf("Not Implement!\n");
        return nullptr;
    }
    else{
        auto sk = (MY_SOCKET) malloc(sizeof(my_sock ));
        sk->local_address   = (u_int8_t *) malloc(sizeof(u_int8_t)*4);
        sk->target_address  = nullptr;
        sk->type            = type;
        sk->local_port      = local_port;
        sk->target_port     = -1;
        memcpy(sk->local_address,local_ip,4);
        printf("socket alloc success!\n");
        return sk;
    }
}

int my_bind(MY_SOCKET sockid,my_socketaddr * Servaddr,socklen_t addrlen)
{
    if(!sockid || !Servaddr || !addrlen) {
        printf("parameter can't be manifested\n");
        return SOCKET_ERROR;
    }
    else{
        sockid->target_address = nullptr;
        sockid->target_port    = -1;
        if(addrlen != sizeof(socketaddr_in)){
            printf("Not a IPV4 address, Not implement!\n");
            return SOCKET_ERROR;
        }
        else{
            auto *Servaddr_in = (my_socketaddr_in*) Servaddr;
            sockid->local_port = Servaddr_in->sin_port;
            memcpy(sockid->local_address,&Servaddr_in->sin_addr.s_addr,4);
        }
        return SOCKET_SUCCESS;
    }
}

int my_sendto(MY_SOCKET sockid,u_int8_t *buf,int len,int flags,my_socketaddr * to,int tolen)
{
    int send_number;
    if(!sockid || !buf || !to || !tolen){
        printf("parameter can't be manifested\n");
        return 0;
    }
    else{
        if(tolen != sizeof(socketaddr_in)){
            printf("Not a IPV4 address, Not implement!\n");
            return 0;
        }
        else{
            auto *to_in = (my_socketaddr_in *) to;
            printf("target port = %d\n",to_in->sin_port);
            sockid->target_port = to_in->sin_port;
            if(sockid->target_address == nullptr){
                sockid->target_address = (u_int8_t*) malloc(sizeof(u_int8_t)*4);
            }
            memcpy(sockid->target_address,&to_in->sin_addr.s_addr,4);
        }
    }
    if(sockid->type == SOCK_DGRAM){
        send_number = Transport_UDP_send(sockid,buf,len,flags);
        return send_number;
    }
    else{
        printf("Not implement!\n");
        return 0;
    }
}

int my_closesocket(MY_SOCKET sockid)
{
    if(sockid == nullptr) {
        printf("Sockid is not valid!\n");
        return -1;
    }
    else{
        free(sockid);
        return 1;
    }
}

int my_recvfrom(MY_SOCKET sockid,u_int8_t *buf,int len,int flags,my_socketaddr *from,int fromlen)
{
    rf_buf = (u_int8_t *) malloc(sizeof(u_int8_t)*len);
    rf_len = len;
    pcap_loop(handle, 0, ethernet_protocol_packet_callback, (u_char *)handle);
    auto rf_hd = (UDP_header *) rf_buf;
    sockid->target_address =(u_int8_t *) malloc(sizeof(u_int8_t)*4);
    printf("----------receive UDP package----------\n");
    printf("length:      %d\n",rf_hd->len);
    printf("source port: %d\n",rf_hd->source_port);
    printf("target port: %d\n",rf_hd->des_port);
    printf("check  sun : %d\n",rf_hd->checksum);
    printf("----------end UDP package----------\n");
    memcpy(sockid->target_address,source_ip,4);
    sockid->target_port = rf_hd->source_port;
    if(rf_hd->des_port != sockid-> local_port){
        printf("port wrong,local_port = %d,des_port = %d!\n",sockid->local_port,rf_hd->des_port);
        network_ICMP_send(icmp_unreach);
        return 0;
    }//server local:8080 target:57600
    //client local 57600 target:8080
    auto rf_fhd = (UDP_fake_header *) malloc(sizeof(UDP_fake_header));
    memcpy(rf_fhd->source_address,source_ip,4);
    memcpy(rf_fhd->des_address,local_ip,4);
    rf_fhd->zero = 0;
    rf_fhd->protocol = 17;
    rf_fhd->sum_len = rf_hd->len;
    u_int16_t checksum = rf_hd->checksum;
    rf_hd->checksum = 0;
    int cal_checksum = calculate_check_sum_udp(rf_fhd,rf_hd,rf_buf+sizeof(UDP_header),rf_hd->len-sizeof(UDP_header));
    if(checksum != cal_checksum){
        printf("cal_checksum = %d,checksum = %d\n",cal_checksum,checksum);
        printf("data has changed\n");
        return 0;
    }
    if(!from){
        from = (my_socketaddr *) malloc(sizeof(my_socketaddr));
    }
    auto temp_from = (my_socketaddr_in * )from;
    temp_from->sin_family = AF_INET;
    memcpy(&temp_from->sin_addr.s_addr, sockid->target_address,4);
    temp_from->sin_port = sockid->target_port;
    memcpy(buf,rf_buf,rf_hd->len-sizeof(UDP_header));
    return rf_hd->len-sizeof(UDP_header);
}