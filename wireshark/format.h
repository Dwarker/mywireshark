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
    //version和head length分别占前四个位和后四个位
    //(后四个位每个位单位长度是4个字节,并且后面四个位的大小经常是5,所以是ip的头部长度20个字节)
    u_char version_length;
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

/*tcp header
+----------------------+---------------------+
|         16 bit       |       16 bit        |
+----------------------+---------------------+
|      source port     |  destination port   |
+----------------------+---------------------+
|              sequence number               |
+----------------------+---------------------+
|                 ack number                 |
+----+---------+-------+---------------------+
|head| reserve | flags |     window size     |
+----+---------+-------+---------------------+
|     checksum         |   urgent pointer    |
+----------------------+---------------------+
*/
typedef struct tcp_header
{
    u_short src_port;
    u_short des_port;
    u_int   sequence;
    u_int   ack;
    u_char  header_length;
    u_char  flags;
    u_short window_size;
    u_short checksum;
    u_short urgent;
}TCP_HEADER;

/*udp
+---------------------+---------------------+
|        16 bit       |        16 bit       |
+---------------------+---------------------+
|    source port      |   destination port  |
+---------------------+---------------------+
| data package length |       checksum      |
+---------------------+---------------------+
*/
typedef struct udp_header
{
    u_short src_port;
    u_short des_port;
    u_short data_length;
    u_short checksum;
}UDP_HEADER;

/*
|<--------  ARP header  ------------>|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
|2 byte| 2 byte |1byte| 1byte|2 byte |  6 byte  | 4 byte  |     6 byte    |     4 byte   |
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
| type |protocol|e_len|ip_len|op_type|source mac|source ip|destination mac|destination ip|
+------+--------+-----+------+-------+----------+---------+---------------+--------------+
*/
typedef struct arp_header
{
    u_short type;
    u_short protocol;
    u_char mac_length;
    u_char ip_length;
    u_short op_code;

    u_char src_eth_addr[6];
    u_char src_ip_addr[4];
    u_char des_eth_addr[6];
    u_char des_ip_addr[4];
}ARP_HEADER;

/*ICMP:ICMP分很多种类型,不过后面解析只争对常见的几种类型
+---------------------+---------------------+
|  1 byte  |  1 byte  |        2 byte       |
+---------------------+---------------------+
|   type   |   code   |       checksum      |
+---------------------+---------------------+
|    identification   |       sequence      |
+---------------------+---------------------+
|                  option                   |
+-------------------------------------------+
*/
//协议里面有个可选项字段,因为长度不固定,所以不放在结构体里面
typedef struct icmp_header
{
    u_char type;
    u_char code;
    u_short checksum;
    u_short identification;
    u_short sequence;
}ICMPHEADER;

#endif // FORMAT_H
