#include <cstdlib>
#include "Transport_UDP_Protocol.h"
u_int8_t UDP_buffer[MAXUDPLEN];
extern u_int8_t * rf_buf;
extern int rf_len;
int recv_len;
u_int8_t *source_ip;
u_int16_t calculate_check_sum_udp(UDP_fake_header *UDP_fhd,UDP_header *UDP_hd,u_int8_t *buf,int len)
{
    printf("check sun len = %d\n",len);
    auto *p = (u_int16_t *) UDP_fhd;
    int sum = 0, tmp = sizeof(UDP_fake_header)/2;
    for(int i = 0;i < tmp;i++)
    {
        sum += *p;
        p++;
    }
    tmp = sizeof(UDP_header)/2;
    p = (u_int16_t *) UDP_hd;
    for(int i = 0;i < tmp;i++)
    {
        sum+=*p;
        p++;
    }
    p = (u_int16_t *) buf;
    tmp = len;
    while(len > 1){
        sum += *p;
        p++;
        len -= 2;
    }
    if (len)
    {
        sum += *(buf + tmp - 1) << 8;
    }

    //fold 32 bits to 16 bits
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

int Transport_UDP_send(MY_SOCKET sockid,u_int8_t *buf,int len,int flags)
{
    auto * UDP_fhd = (UDP_fake_header *) malloc(sizeof(UDP_fake_header));
    auto* UDP_hd = (UDP_header *) malloc(sizeof(UDP_header));
    UDP_hd->source_port = sockid->local_port;
    UDP_hd->des_port    = sockid->target_port;
    UDP_hd->checksum    = 0;
    int buf_length      = sizeof(UDP_header)+len;
    if(buf_length > MAXUDPLEN)
    {
        printf("buf too long to send\n");
        return 0;
    }
    else{
        UDP_hd->len = buf_length;
        memcpy(UDP_fhd->source_address,sockid->local_address,4);
        memcpy(UDP_fhd->des_address,sockid->target_address,4);
        UDP_fhd->zero=0;
        UDP_fhd->protocol=17;
        UDP_fhd->sum_len = buf_length;
        UDP_hd->checksum =calculate_check_sum_udp(UDP_fhd,UDP_hd,buf,len);
        memcpy(UDP_buffer,UDP_hd,sizeof(UDP_header));
        memcpy(UDP_buffer+sizeof(UDP_header),buf,len);
        printf("----------send UDP package----------\n");
        printf("source ip = ");
        for(unsigned char source_addres : UDP_fhd->source_address){
            printf("%d:",source_addres);
        }
        printf("\n");
        printf("target ip = ");
        for(unsigned char des_addres : UDP_fhd->des_address){
            printf("%d:",des_addres);
        }
        printf("\n");
        printf("length:      %d\n",UDP_hd->len);
        printf("source port: %d\n",UDP_hd->source_port);
        printf("target port: %d\n",UDP_hd->des_port);
        printf("check  sun : %d\n",UDP_hd->checksum);
        printf("----------end UDP package----------\n");
        return network_ipv4_send(sockid->local_address,sockid->target_address,UDP_buffer,buf_length,IPPROTO_UDP);
    }
}

int transport_udp_recv(u_int8_t* source_address,u_int8_t *udp_buffer,int len)
{
    //source_ip = source_address;
    //printf("enter recv\n");
     source_ip = (u_int8_t *) malloc(sizeof(u_int8_t)*4);
     memcpy(source_ip,source_address,4);
     recv_len = (rf_len > len) ? len:rf_len;
     //printf("recv_len = %d\n",recv_len);

     if(rf_buf ==nullptr || udp_buffer == nullptr){
         printf("rf_buf not alloc\n");
     }
     else {
         memcpy(rf_buf, udp_buffer, recv_len);
     }
     return 1;
}

