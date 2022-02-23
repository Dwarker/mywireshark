#include "multhread.h"
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
            qDebug() << timeString;
        }
    }
}
