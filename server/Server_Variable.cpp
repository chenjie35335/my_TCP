#include <cstdlib>
#include <pcap.h>

u_int8_t local_mac[6] = { 0x2C, 0xD0, 0x5A, 0xF0, 0xB7, 0xC5 };
u_int8_t local_ip[4] = { 10,10, 10, 1 };
u_int8_t gateway_ip[4] = { 10, 10, 11, 1 };
u_int8_t netmask[4] = { 255, 255, 248, 0 };
u_int8_t dns_server_ip[4] = { 211, 137, 130, 3 };
u_int8_t dhcp_server_ip[4] = { 111, 20, 62, 57 };
u_int8_t broadcast_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

u_int8_t target_ip[4] =  { 10, 10, 10, 10 };
int local_port = 57600;
int target_port = 8080;

pcap_t *handle;
int ethernet_upper_len;
