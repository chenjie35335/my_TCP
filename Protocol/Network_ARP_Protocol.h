#include "Header_Include.h"

typedef struct arp_pkt
{
    u_int16_t hardware_type;
    u_int16_t protocol_type;
    u_int8_t hardware_addr_length;
    u_int8_t protocol_addr_length;
    u_int16_t op_code;
    u_int8_t source_mac[6];
    u_int8_t source_ip[4];
    u_int8_t destination_mac[6]; //request the mac addr
    u_int8_t destination_ip[4];
}arp_pkt;

typedef struct arp_node
{
    u_int8_t ip[4];
    u_int8_t mac[6];
    u_int8_t state;
    struct arp_node *next;
}arp_node;

typedef struct arp_table_header
{
    arp_node *queue;
    arp_node *head;
    arp_node *tail;
}arp_table_header;

void load_arp_packet(const u_int8_t *destination_ip);
/*
if the needer mac addr is not in arp_table, so request
*/
void network_arp_send(u_int8_t *destination_ip, u_int8_t *ethernet_dest_mac,int type);

void output(struct arp_pkt *arp_packet);

u_int8_t* network_arp_recv(u_int8_t *arp_buffer);

int is_accept_arp_packet(struct arp_pkt *arp_packet);
//add the local ip to mac
void init_arp_table();

struct arp_node* make_arp_node(u_int8_t *ip, u_int8_t *mac, int state);

void insert_arp_node(struct arp_node *node);

int delete_arp_node(struct arp_node *node);

int update_arp_node(struct arp_node *node);

/*
if ip existed, return mac
else  return NULL
*/
u_int8_t* is_existed_ip(const u_int8_t *destination_ip);

//check the queue;
void output_arp_table();
