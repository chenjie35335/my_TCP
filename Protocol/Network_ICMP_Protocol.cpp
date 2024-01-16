#include "Network_ICMP_Protocol.h"
#include "Network_IPV4_Protocol.h"
#include "Resource.h"
#include "Transport_UDP_Interface.h"

extern u_int8_t target_ip[4];

int getInt(u_int8_t *icmp_buffer, FILE *fp);

int network_ICMP_send(u_int8_t type)
{
    u_int8_t icmp_buffer[MAX_SIZE];
    FILE * fp = fopen("data.txt","rb");
    auto * icmp_hd = (icmp_header*) malloc(sizeof(icmp_header));
    icmp_hd->identifier = 0;
    icmp_hd->sequence_num = 0;
    icmp_hd->checksum = 0;
    icmp_hd->type = type;
    if(type == icmp_ans || type == icmp_req) {
        icmp_hd->code = 0;
        printf("---------------Send ICMP Protocol-------------------\n");
        printf("icmp type = %d\n", icmp_hd->type);
        printf("icmp code = %d\n", icmp_hd->code);
        printf("icmp checksum = %d\n", icmp_hd->checksum);
        printf("icmp identifier = %d\n",icmp_hd->identifier);
        printf("icmp sequence number = %d\n",icmp_hd->sequence_num);
        printf("-----------------End of ICMP Protocol---------------\n");
    }
    else if(type == icmp_unreach){
        icmp_hd->code = 3;
        printf("port can't reach\n");
    }
    memcpy(icmp_buffer,icmp_hd,sizeof(icmp_header));
    int i = getInt(icmp_buffer, fp);
    network_ipv4_send(local_ip, target_ip, icmp_buffer, i,IPPROTO_ICMP);
    return 1;
}

int getInt(u_int8_t *icmp_buffer, FILE *fp) {
    int i = sizeof(icmp_header);
    char ch;
    while((ch = fgetc(fp)) != EOF)
    {
        *(icmp_buffer+i) = ch;
        i++;
    }
    return i;
}

int load_icmp_data_to_file(u_int8_t *icmp_buffer,int data_len,FILE* fp){
    if(fwrite(icmp_buffer, sizeof(u_int8_t), data_len, fp) != data_len){
        printf("Write file error!\n");
        return 0;
    }
    fflush(fp);
    return 1;
}

int Network_ICMP_recv(u_int8_t *icmp_buffer,int len)
{
    auto* icmp_hd = (icmp_header *) icmp_buffer;
    //printf("len = %d,size of icmp_header = %lu\n",len,sizeof(icmp_header));
    printf("--------------ICMP Protocol-------------------\n");
    printf("icmp type = %d\n", icmp_hd->type);
    printf("icmp code = %d\n", icmp_hd->code);
    printf("icmp checksum = %d\n", icmp_hd->checksum);
    printf("icmp identifier = %d\n",icmp_hd->identifier);
    printf("icmp sequence number = %d\n",icmp_hd->sequence_num);
    printf("-----------------End of ICMP Protocol---------------\n");
    FILE * fp = fopen("data.txt","w");
    if(load_icmp_data_to_file(icmp_buffer+sizeof(icmp_header),len-sizeof(icmp_header),fp)){
        printf("Load to file Succeed.\n\n");
    }
    fclose(fp);
    if(icmp_hd->type == icmp_req)
    {
        //printf("no error\n");
        //printf("no error\n");

        //printf("no error\n");
        //printf("len = %d,size of icmp_header = %d\n",len,sizeof(icmp_header));
        network_ICMP_send(icmp_ans);
        return 1;
    }
    return 0;
}



