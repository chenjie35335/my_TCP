#include "Network_IPV4_Protocol.h"
#include <cassert>
#include "Resource.h"
#include "Network_ICMP_Protocol.h"
#include "Transport_UDP_Protocol.h"


//u_int8_t buffer[MAX_SIZE];
u_int16_t ip_packet_id = 0;//as flag in ip_header->id
u_int32_t ip_size_of_packet = 0;

extern int ethernet_upper_len;
extern u_int8_t broadcast_mac[6];
extern u_int8_t local_ip[4];
extern u_int8_t target_ip[4];
extern u_int8_t netmask[4];
extern u_int8_t gateway_ip[4];

extern u_int8_t local_mac[6];

#define MAX_DATA_SIZE 1000000
u_int16_t ip_id = 0;
u_int16_t i = 0;
u_int16_t data_len = 0;

u_int8_t data_buffer[MAX_DATA_SIZE];

int previous = 0, current = 0;

u_int16_t calculate_check_sum(ip_header *ip_hdr, int len)
{
    int sum = 0, tmp = len;
    auto *p = (u_int16_t*)ip_hdr;
    while (len > 1)
    {
        sum += *p;
        len -= 2;
        p++;
    }

    //len=1 last one byte
    if (len)
    {
        sum += *((u_int8_t*)ip_hdr + tmp - 1);
    }

    //fold 32 bits to 16 bits
    while (sum >> 16)
    {
        sum = (sum & 0xffff) + (sum >> 16);
    }

    return ~sum;
}

void load_ip_header(const u_int8_t *source_address,const u_int8_t *des_address,u_int8_t protocol,u_int8_t *ip_buffer)
{
    struct ip_header *ip_hdr = (struct ip_header*)ip_buffer;
    ip_size_of_packet = 0;
    //initial the ip header
    ip_hdr->version_hdrlen = 0x4f;//0100 1111 means ip version4 and header length: 60 bytes
    ip_hdr->type_of_service = 0xfe;/*111 1 1110: first 3 bits: priority level,
								   then 1 bit: delay, 1 bit: throughput, 1 bit: reliability
								   1 bit: routing cost, 1 bit: unused
								   */
    ip_hdr->total_length = 0;// wait for data length, 0 for now
    ip_hdr->id = ip_packet_id;//identification
    ip_hdr->fragment_offset = 0x0000;/*0 0 0 0 00...00: first 3 bits is flag: 1 bit: 0 the last fragment,
									 1 more fragmet. 1 bit: 0 allow fragment, 1 don't fragment. 1 bit: unused
									 the last 12 bits is offset
									 */
    ip_hdr->time_to_live = 64;//default 1000ms
    ip_hdr->upper_protocol_type = protocol;//default upper protocol is tcp
    ip_hdr->check_sum = 0;//initial zero

    int i;
    for (i = 0; i < 4; i++)
    {
        ip_hdr->source_ip[i] = source_address[i];
        ip_hdr->destination_ip[i] = des_address[i];
    }

    //initial check_sum is associate with offset. so in the data we need to calculate check_sum
    ip_size_of_packet += sizeof(ip_header);
}

void load_ip_data(u_int8_t *ip_buffer, const u_int8_t *ip_data_buffer, int len)
{
    int i = 0;
    char ch;
    while (i < len)
    {
        ch = ip_data_buffer[i];
        *(ip_buffer + i) = ch;
        i++;
    }
    ip_size_of_packet += len;
}

int is_same_lan(u_int8_t *local_ip, u_int8_t *destination_ip)
{
    int i;
    for (i = 0; i < 4; i++)
    {
        if ((local_ip[i] & netmask[i]) != (destination_ip[i] & netmask[i]))
            return 0;
    }
    return 1;
}

int network_ipv4_send(u_int8_t *source_address,u_int8_t *des_address, u_int8_t *ip_data_buffer,int data_length,u_int8_t protocol)
{
    //get the size of file
    //int file_len;
    //fseek(fp, 0, SEEK_END);
    //file_len = ftell(fp);
    //rewind(fp);

    //get how many fragments
    u_int8_t ip_buffer[MAX_SIZE];
    int number_of_fragment = (int)ceil(data_length*1.0 / MAX_IP_PACKET_SIZE);
    u_int16_t offset = 0;
    int ip_data_len;
    u_int16_t fragment_offset;
    while (number_of_fragment)
    {
        load_ip_header(source_address,des_address,protocol,ip_buffer);
        auto *ip_hdr = (struct ip_header *)ip_buffer;
        if (number_of_fragment == 1)
        {
            fragment_offset = 0x0000;//16bits
            ip_data_len = data_length - offset;
        }
        else
        {
            fragment_offset = 0x2000;//allow the next fragment
            ip_data_len = MAX_IP_PACKET_SIZE;
        }

        fragment_offset |= ((offset / 8) & 0x0fff);
        ip_hdr->fragment_offset = htons(fragment_offset);

        //printf("%04x\n", ip_hdr->fragment_offset);
        ip_hdr->total_length = htons(ip_data_len + sizeof(ip_header));
        ip_hdr->check_sum = calculate_check_sum(ip_hdr, 60);
        //printf("%04x\n", ip_hdr->check_sum);
        load_ip_data(ip_buffer + sizeof(ip_header), ip_data_buffer, ip_data_len);

        //check if the target pc mac is in arp_table
        u_int8_t *destination_mac = is_existed_ip(ip_hdr->destination_ip);
        if (destination_mac == nullptr)
        {
            //check if the target pc and the local host is in the same lan
            if (is_same_lan(local_ip, ip_hdr->destination_ip))
            {
                //�������ݣ���ARP���洦����Ŀ��IP��ַ-MAC��ַ�Ƿ����
                printf("send to destination\n");
                network_arp_send(ip_hdr->destination_ip, broadcast_mac,ARP_REQUEST);
            }
            else
            {
                //�������ݣ���ARP���洦��������IP��ַ-MAC��ַ�Ƿ����
                printf("send to gateway\n");
                network_arp_send(gateway_ip, broadcast_mac,ARP_REQUEST);
            }
            //printf("arp send\n");
            //wait for replying, get the destination mac
            struct pcap_pkthdr *pkt_hdr;
            u_int8_t *pkt_content;
            //printf("arp recv_1\n");
            while (pcap_next_ex(handle, &pkt_hdr, (const u_char **)&pkt_content) != 0)
            {
                //printf("arp recv_2\n");
                destination_mac = nullptr;
                auto *ethernet_hdr = (struct ethernet_header *)(pkt_content);
                //check if is acceptable packet
                if (ntohs(ethernet_hdr->ethernet_type) != ETHERNET_ARP)continue;
                int i;
                for (i = 0; i < 6; i++)
                {
                    if (ethernet_hdr->destination_mac[i] != local_mac[i])break;
                }
                if (i < 6)continue;

                switch (ntohs(ethernet_hdr->ethernet_type))
                {
                    case ETHERNET_ARP:
                        //printf("arp recv_3\n");
                        destination_mac = network_arp_recv(pkt_content + sizeof(struct ethernet_header));
                        break;
                    case ETHERNET_RARP:
                        break;
                }

                if (destination_mac != nullptr)
                    break;
            }

        }
        assert(destination_mac);

        //send the data
        ethernet_upper_len = ip_size_of_packet;//ip packet size
        ethernet_send_packet(ip_buffer, destination_mac, ETHERNET_IP);

        offset += MAX_IP_PACKET_SIZE;
        number_of_fragment--;
        printf("number_of_fragment = %d\n",number_of_fragment);
    }
    //printf("out of fragment\n");
    //fclose(fp);
    //printf("out of close\n");
    //auto increase one
    ip_packet_id++;
    return (int)ip_size_of_packet;
}


int is_accept_ip_packet(struct ip_header *ip_hdr)
{
    int i;
    int flag = 0;
    for (i = 0; i < 4; i++)
    {
        if (ip_hdr->destination_ip[i] != local_ip[i])break;
    }

    if (i == 4)
    {
        flag = 1;
        printf("It's sended to my IP.\n");
    }

    for (i = 0; i < 4; i++)
    {
        if (ip_hdr->destination_ip[i] != 0xff)break;
    }
    if (i == 4)
    {
        flag = 1;
        printf("It's broadcast IP.\n");
    }

    if (!flag)
        return 0;

    u_int16_t check_sum = calculate_check_sum(ip_hdr, 60);
    if (check_sum == 0xffff || check_sum == 0x0000)
    {
        printf("No error in ip_header.\n");
    }
    else
    {
        printf("Error in ip_header\n");
        return 0;
    }
    return 1;
}

void load_data_to_buffer(u_int8_t *buffer, u_int8_t *ip_data, int len)
{
    int i;
    for (i = 0; i < len; i++)
    {
        *(buffer + i) = *(ip_data + i);
    }
}



int network_ipv4_recv(u_int8_t *ip_buffer)
{
    auto *ip_hdr = (struct ip_header *)ip_buffer;
    int len = ntohs(ip_hdr->total_length) - sizeof(ip_header);


    //check the valid
    if (!is_accept_ip_packet(ip_hdr))
    {
        return 0;
    }

    u_int16_t fragment;
    fragment = ntohs(ip_hdr->fragment_offset);

    int dural = 0;
    if (previous == 0)
    {
        previous = time(nullptr);
    }
    else
    {
        //get current time
        current = time(nullptr);
        dural = current - previous;
        printf("%d %d\n", current, previous);
        //current time became previous
        previous = current;
    }

    //interval can not larger than 30s
    if (dural >= 30)
    {
        printf("Time Elapsed.\n");
        return 0;
    }

    if ((fragment & 0x2000) && (ip_id == ip_hdr->id))//true means more fragment
    {
        load_data_to_buffer(data_buffer + i, ip_buffer + sizeof(ip_header), len);
        i += len;
        return 1;
    }
    else if (ip_id == ip_hdr->id)
    {
        load_data_to_buffer(data_buffer + i, ip_buffer + sizeof(ip_header), len);
        i += len;
        data_len = i;
        printf("len = %d\n",data_len);
        //	FILE *fp = fopen("data.txt", "w");
        //	if (load_data_to_file(data_buffer, i, fp))
        //	{
        //		printf("Load to file Succeed.\n");
        //	}
        //	fclose(fp);
        //restore the value

        ip_id++;
    }
    else
    {
        printf("Lost packets.\n");
        //pass the last fragment make move
        i = 0;
        ip_id++;
        return 0;
    }

    printf("--------------IP Protocol-------------------\n");
    printf("IP version: %d\n", (ip_hdr->version_hdrlen & 0xf0));
    printf("Type of service: %02x\n", ip_hdr->type_of_service);
    printf("IP packet length: %lu\n", len + sizeof(ip_header));
    printf("IP identification: %d\n", ip_hdr->id);
    printf("IP fragment & offset: %04x\n", ntohs(ip_hdr->fragment_offset));
    printf("IP time to live: %d\n", ip_hdr->time_to_live);
    printf("Upper protocol type: %02x\n", ip_hdr->upper_protocol_type);
    printf("Check sum: %04x\n", ip_hdr->check_sum);
    printf("Source IP: ");
    int j;
    for (j = 0; j < 4; j++)
    {
        if (j)printf(".");
        printf("%d", ip_hdr->source_ip[j]);
    }
    printf("\nDestination IP: ");
    for (j = 0; j < 4; j++)
    {
        if (j)printf(".");
        printf("%d", ip_hdr->destination_ip[j]);
    }
    printf("\n");



    u_int8_t upper_protocol_type = ip_hdr->upper_protocol_type;
    switch (upper_protocol_type)
    {
        case IPPROTO_TCP:
            //transport_tcp_recv(buffer);
            break;
        case IPPROTO_UDP:
            //printf("enter udp\n");
            transport_udp_recv(ip_hdr->source_ip, data_buffer, data_len);
            //printf("out of udp\n");
            return 1;
            break;
        case IPPROTO_ICMP:
            Network_ICMP_recv(data_buffer,data_len);break;
        default:
            break;
    }
    i = 0;
    printf("-----------------End of IP Protocol---------------\n");
    return 0;
}