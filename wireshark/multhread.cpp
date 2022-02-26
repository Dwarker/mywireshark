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
            info = "ip";
            return 1;
        }
        case 0x0806://arp
        {
            info = "arp";
            return 1;
        }
        default: break;
    }
    return 0;
}
