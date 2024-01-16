#include "Network_ARP_Protocol.h"
#include "Resource.h"
#include "Ethernet.h"

extern u_int8_t local_mac[6];
extern u_int8_t local_ip[4];
extern int ethernet_upper_len;
extern u_int8_t gateway_ip[4];
extern u_int8_t netmask[4];
extern u_int8_t dns_server_ip[4];
extern u_int8_t dhcp_server_ip[4];

u_int8_t arp_buffer[MAX_SIZE];
arp_table_header arp_table;

void load_arp_packet(const u_int8_t *destination_ip,int type)
{
    auto *arp_packet = (struct arp_pkt *)(arp_buffer);
    arp_packet->hardware_type = htons(ARP_HARDWARE);
    arp_packet->protocol_type = htons(ETHERNET_IP);
    arp_packet->hardware_addr_length = 6;
    arp_packet->protocol_addr_length = 4;
    arp_packet->op_code = htons(type);
    int i;
    for (i = 0; i < 6; i++)
    {
        arp_packet->source_mac[i] = local_mac[i];
    }
    for (i = 0; i < 4; i++)
    {
        arp_packet->source_ip[i] = local_ip[i];
    }

    for (i = 0; i < 6; i++)
    {
        arp_packet->destination_mac[i] = 0x00;
    }
    for (i = 0; i < 4; i++)
    {
        arp_packet->destination_ip[i] = destination_ip[i];
    }
}

void network_arp_send(u_int8_t *destination_ip, u_int8_t *ethernet_dest_mac,int type)
{
    auto *arp_packet = (struct arp_pkt *)arp_buffer;
    load_arp_packet(destination_ip,type);
    int i;
    for (i = 0; i < 6; i++)
    {
        arp_packet->destination_mac[i] = ethernet_dest_mac[i];
    }

    ethernet_upper_len = sizeof(struct arp_pkt);
    //send the packet
    ethernet_send_packet(arp_buffer, ethernet_dest_mac, ETHERNET_ARP);

}

int is_accept_arp_packet(struct arp_pkt *arp_packet)
{
    if (ntohs(arp_packet->hardware_type) != ARP_HARDWARE)return 0;
    if (ntohs(arp_packet->protocol_type) != ETHERNET_IP)return 0;
    //printf("enter 1\n");
    int i;
    //printf("local_ip = %d.%d.%d.%d\n",local_ip[0],local_ip[1],local_ip[2],local_ip[3]);
    for (i = 0; i < 4; i++)
    {
        if (arp_packet->destination_ip[i] != local_ip[i])
        {
            //printf("arp_packet->destination_ip[%d] = 0x%d\n",i,arp_packet->destination_ip[i]);
            return 0;
        }
    }
    //printf("enter 2\n");
    if (ntohs(arp_packet->op_code) == ARP_REQUEST)
    {
        //printf("enter 3\n");
        for (i = 0; i < 6; i++)
        {
            if (arp_packet->destination_mac[i] != 0xff)
            {
                //printf("arp_packet->destination_mac[%d] = 0x%02x\n",i,arp_packet->destination_mac[i]);
                return 0;
            }
        }
    }
    else if (ntohs(arp_packet->op_code) == ARP_REPLY)
    {
        //printf("enter 4\n");
        for (i = 0; i < 6; i++)
        {
            if (arp_packet->destination_mac[i] != local_mac[i])return 0;
        }
    }


    //add source ip and source mac
    struct arp_node *element;
    if (!is_existed_ip(arp_packet->source_ip))
    {
        element = make_arp_node(arp_packet->source_ip, arp_packet->source_mac, STATIC_STATE);
        insert_arp_node(element);
    }

    return 1;
}

u_int8_t* network_arp_recv(u_int8_t *arp_buffer)
{
    auto *arp_packet = (struct arp_pkt *)arp_buffer;
    if (!is_accept_arp_packet(arp_packet)){
        printf("It is not acceptable\n");
        return nullptr;
    }
    output(arp_packet);
    output_arp_table();

    /*if arp_request so reply
    else if arp_reply no operation
    */
    //printf("send arp pack\n");
    printf("--------End ARP Protocol---------\n");
    if (ntohs(arp_packet->op_code) == ARP_REQUEST)
    {
        network_arp_send(arp_packet->source_ip, arp_packet->source_mac,ARP_REPLY);
        return nullptr;
    }
    else if (ntohs(arp_packet->op_code) == ARP_REPLY)
    {
        return arp_packet->source_mac;
    }
}

void output(struct arp_pkt *arp_packet)
{
    printf("--------ARP Protocol---------\n");
    printf("Hardware Type: %04x\n", ntohs(arp_packet->hardware_type));
    printf("Protocol Type: %04x\n", ntohs(arp_packet->protocol_type));
    printf("Operation Code: %04x\n", ntohs(arp_packet->op_code));
    printf("Source MAC: ");
    int i;
    for (i = 0; i < 6; i++)
    {
        if (i)printf("-");
        printf("%02x", arp_packet->source_mac[i]);
    }
    printf("\nSourcee IP: ");
    for (i = 0; i < 4; i++)
    {
        if (i)printf(".");
        printf("%d", arp_packet->source_ip[i]);
    }
    printf("\n");
}

struct arp_node* make_arp_node(u_int8_t *ip, u_int8_t *mac, int state)
{
    int i;
    auto *node = (struct arp_node *)malloc(sizeof(struct arp_node));
    for (i = 0; i < 4; i++)
    {
        node->ip[i] = ip[i];
    }

    for (i = 0; i < 6; i++)
    {
        node->mac[i] = mac[i];
    }
    node->state = state;
    node->next = nullptr;
    return node;
}

void init_arp_table()
{
    struct arp_node *node;
    node = make_arp_node(local_ip, local_mac, STATIC_STATE);

    arp_table.queue = node;
    arp_table.head = node;
    arp_table.tail = node;
}

void insert_arp_node(struct arp_node *node)
{
    if (!is_existed_ip(node->ip))
    {
        arp_table.tail->next = node;
        arp_table.tail = node;
    }
}

int delete_arp_node(struct arp_node *node)
{
    struct arp_node *pre = arp_table.head;
    struct arp_node *p = pre->next;
    int flag = 1;
    while (p != nullptr)
    {
        int i;
        flag = 1;
        for (i = 0; i < 4; i++)
        {
            if (node->ip[i] != p->ip[i])
            {
                flag = 0;
                break;
            }
        }

        for (i = 0; i < 6; i++)
        {
            if (node->mac[i] != p->mac[i])
            {
                flag = 0;
                break;
            }
        }

        if (flag)
        {
            pre->next = p->next;
            free(p);
            break;
        }

        pre = p;
        p = p->next;
    }
    if (flag)
    {
        printf("delete arp node succeed!!!\n");
        return 1;
    }
    else
    {
        printf("Failed delete\n");
        return 0;
    }
}

u_int8_t* is_existed_ip(const u_int8_t *destination_ip)
{
    struct arp_node *p = arp_table.head;
    int flag = 1;
    while (p != nullptr)
    {
        int i;
        flag = 1;
        for (i = 0; i < 4; i++)
        {
            if (p->ip[i] != destination_ip[i])
            {
                flag = 0;
                break;
            }
        }

        if (flag)
        {
            return p->mac;
        }
        p = p->next;
    }
    return nullptr;
}

int update_arp_node(struct arp_node *node)
{
    u_int8_t *mac = is_existed_ip(node->ip);
    if (mac)
    {
        int i;
        for (i = 0; i < 6; i++)
        {
            mac[i] = node->mac[i];
        }
        printf("Update succeed.\n");
        return 1;
    }
    else
    {
        printf("Update failed.\n");
        return 0;
    }
}

void output_arp_table()
{
    struct arp_node *p = arp_table.head;
    while (p != nullptr)
    {
        int i;
        for (i = 0; i < 4; i++)
        {
            if (i)printf(".");
            printf("%d", p->ip[i]);
        }
        printf("\t");
        for (i = 0; i < 6; i++)
        {
            if (i)printf("-");
            printf("%02x", p->mac[i]);
        }
        printf("\n");

        p = p->next;
    }

}