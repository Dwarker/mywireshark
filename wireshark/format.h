#ifndef FORMAT_H
#define FORMAT_H

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;
typedef unsigned long u_long;

/*Ethernet
+-------------------+-----------------+------+
|       6 byte      |     6 byte      |2 byte|
+-------------------+-----------------+------+
|destination address|  source address | type |
+-------------------+-----------------+------+
*/
typedef struct ether_header{
    u_char ethernet_des_host[6];
    u_char ethernet_src_host[6];
    u_short type;
}ETHER_HEADER;

/*IPV4
+-------+-----------+---------------+-------------------------+
| 4 bit |   4 bit   |    8 bit      |          16 bit         |
+-------+-----------+---------------+-------------------------+
|version|head length|  TOS/DS_byte  |        total length     |
+-------------------+--+---+---+----+-+-+-+-------------------+
|          identification           | |D|M|    offset         |
+-------------------+---------------+-+-+-+-------------------+
|       ttl         |     protocal  |         checksum        |
+-------------------+---------------+-------------------------+
|                   source ip address                         |
+-------------------------------------------------------------+
|                 destination ip address                      |
+-------------------------------------------------------------+
*/
typedef struct ip_header{
    u_char version_length; //version和head length分别占前四个位和后四个位
    u_char TOS;
    u_short total_length;
    u_short identification;
    u_short offset;
    u_char ttl;
    u_char protocol;    //上层的协议:如tcp udp
    u_short checksum;
    u_int  src_addr;
    u_int  des_addr;
}IP_HEADER;



#endif // FORMAT_H
