#include "multhread.h"
#include "format.h"
#include "datapackage.h"
#include <QDebug>

multhread::multhread()
{
    //因为一开始线程还没起来,所以相当于结束了,可以直接设置为true
    this->isDone = true;
}

bool multhread::setPointer(pcap_t *pointer)
{
    this->pointer = pointer;
    if(pointer) return true;
    else return false;
}

void multhread::setFlag()
{
    this->isDone = false;
}

void multhread::resetFlag()
{
    this->isDone = true;
}

void multhread::run()
{
    while(true)
    {
        if(isDone) break;
        else
        {
            int res = pcap_next_ex(pointer, &header, &pkt_data);
            if(res == 0)
            {
                //无效数据包
                continue;
            }
            //暂时从数据包头部获取数据戳,并输出
            local_time_sec = header->ts.tv_sec;
            localtime_s(&local_time, &local_time_sec);
            strftime(timeString, sizeof(timeString), "%H:%M:%S", &local_time);

            //解析数据包
            QString info = "";
            int type = ethernetPackageHandle(pkt_data, info);
            if(type)
            {
                datapackage data;
                int len = header->len;
                data.setInfo(info);
                data.setDataLength(len);//设置数据包长度
                data.setTimeStamp(timeString);
                data.setPackageType(type);
                data.setPointer(pkt_data, len);

                emit send(data);
            }
        }
    }
}

//从mac层获取数据
int multhread::ethernetPackageHandle(const u_char *pkt_content, QString &info)
{
    ETHER_HEADER *ethenet;
    u_short content_type;//数据包类型

    ethenet = (ETHER_HEADER*)pkt_content;
    content_type = ntohs(ethenet->type);

    //判断封装的是什么数据包:这里只写ip,arp,其他协议比较少见到
    switch (content_type)
    {
        case 0x0800://ip
        {
            int ipPackage = 0;
            int res = ipPackageHandle(pkt_content, ipPackage);
            switch (res) {
                case 1:{//icmp
                    info = "ICMP";
                    return 2;
                }
                case 6:{//tcp
                    return tcpPackageHandle(pkt_content, info, ipPackage);
                }
                case 17:{//udp
                    return udpPackageHandle(pkt_content, info);
                }
                default:break;
            }
            break;
        }
        case 0x0806://arp
        {
            info = arpPackageHandle(pkt_content);
            return 1;
        }
        default: break;
    }
    return 0;
}
//处理ip数据包
int multhread::ipPackageHandle(const u_char *pkt_content, int &ipPackage)
{
    IP_HEADER *ip;
    ip = (IP_HEADER*)(pkt_content + 14);//跳过mac层,mac信息是14个字节
    int protocol = ip->protocol; //ip内部封装的上层协议,如tcp,udp,icmp等
    //计算有效载荷
    //ip的总长度-ip的头部长度
    ipPackage = (ntohs(ip->total_length) - ((ip->version_length) & 0x0F) * 4);//这里为什么乘以4,见version_length定义
    return protocol;
}

//tcp数据包处理
int multhread::tcpPackageHandle(const u_char *pkt_content, QString &info, int ipPackage)
{
    TCP_HEADER* tcp;
    //通过偏移找到tcp头部,先偏移14个字节的mac头部,再偏移20个字节的ip头部
    tcp = (TCP_HEADER*)(pkt_content + 14 + 20);
    u_short src = ntohs(tcp->src_port);
    u_short des = ntohs(tcp->des_port);

    QString proSend = "";
    QString proRecv = "";

    //处理tcp类型报文,getPackageType该函数中有对应的:3对应tcp
    int type = 3;

    //获取tcp首部长度: 四比特,每个单位4个字节,所以乘以4
    int delta = (tcp->header_length >> 4) * 4;

    //获取tcp的载荷长度
    int tcpLoader = ipPackage - delta;

    //判断是否是https
    if(src == 443 || des == 443)
    {
        if(src == 443)
            proSend = "(https)";
        else
            proRecv = "(https)";
    }

    info += QString::number(src) + proSend + "->"
                + QString::number(des) + proRecv;

    //判断标志位的情况
    QString flag = "";
    if(tcp->flags & 0x08) flag += "PSH,";
    if(tcp->flags & 0x10) flag += "ACK,";
    if(tcp->flags & 0x02) flag += "SYN,";
    if(tcp->flags & 0x20) flag += "URG,";
    if(tcp->flags & 0x01) flag += "FIN,";
    if(tcp->flags & 0x04) flag += "RST,";
    if(flag != "")
    {
        flag = flag.left(flag.length() - 1);
        info += "[" + flag + "]";
    }

    //序列号等字段
    u_int sequence = ntohl(tcp->sequence);
    u_int ack = ntohl(tcp->ack);
    u_short window = ntohs(tcp->window_size);//还有个缩放因子,后续处理

    info += " Seq=" + QString::number(sequence)
            + "ACK=" + QString::number(ack)
            + "win=" + QString::number(window)
            + "len=" + QString::number(tcpLoader);

    return type;
}

int multhread::udpPackageHandle(const u_char *pkt_content, QString &info)
{
    UDP_HEADER* udp;
    //跳过mac头,ip头,定位到udp部分
    udp = (UDP_HEADER*)(pkt_content + 14 + 20);
    u_short des = ntohs(udp->des_port);
    u_short src = ntohs(udp->src_port);
    if(des == 53 || src == 53)
    {
        return 5;//端口位53,则返回dns对应的枚举(这里暂时不用枚举)
    }
    else
    {
        QString res = QString::number(src) + "->" + QString::number(des);
        u_short data_len = ntohs(udp->data_length);
        res += "len = " + QString::number(data_len);
        info = res;
        return 4;//纯粹的udp类型
    }
}

QString multhread::arpPackageHandle(const u_char *pkt_content)
{
    ARP_HEADER* arp;
    //注意:arp和tcp,udp不一样,它是封装在mac帧里面,所以说是和ip同一层级
    //所以这里只需要偏移14个字节即可
    arp = (ARP_HEADER*)(pkt_content + 14);

    u_short op = ntohs(arp->op_code);
    QString res = "";
    u_char* des_addr = arp->des_ip_addr;
    QString desIp = QString::number(*des_addr) + "."
            + QString::number(*(des_addr + 1)) + "."
            + QString::number(*(des_addr + 2)) + "."
            + QString::number(*(des_addr + 3));

    u_char* src_ip = arp->src_ip_addr;
    QString srcIp = QString::number(*src_ip) + "."
            + QString::number(*(src_ip + 1)) + "."
            + QString::number(*(src_ip + 2)) + "."
            + QString::number(*(src_ip + 3));

    //解析源mac地址
    u_char* src_eth_addr = arp->src_eth_addr;
    QString srcEth = byteToString(src_eth_addr, 1) + ":"
                + byteToString((src_eth_addr + 1), 1) + ":"
                + byteToString((src_eth_addr + 2), 1) + ":"
                + byteToString((src_eth_addr + 3), 1) + ":"
                + byteToString((src_eth_addr + 4), 1) + ":"
                + byteToString((src_eth_addr + 5), 1);

    if(op == 1)//询问码
    {
        res = "who has " + desIp + "? Tell " + srcIp;
    }
    else if(op == 2)//应答字段
    {
        res = srcIp + " is at " + srcEth;
    }
    return res;
}

//将一个字节数据转换成十六进制u_
QString multhread::byteToString(u_char *str, int size)
{
    QString res = "";
    for(int i = 0; i < size; i++)
    {
        char one = str[i] >> 4;
        if(one >= 0x0A)
        {
            one += 0x41 - 0x0A;
        }
        else
        {
            one += 0x30;
        }

        char two = str[i] & 0x0F;
        if(two >= 0x0A)
        {
            two += 0x41 - 0x0A;
        }
        else
        {
            two += 0x30;
        }

        res.append(one);
        res.append(two);
    }
    return res;
}
