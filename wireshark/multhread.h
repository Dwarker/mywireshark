#ifndef MULTHREAD_H
#define MULTHREAD_H

#include <QThread>
#include "pcap.h"

class multhread:public QThread
{
    Q_OBJECT //信号和槽相关
public:
    multhread();

    bool setPointer(pcap_t* pointer);
    void setFlag();
    void resetFlag();

    void run() override;

private:
    pcap_t* pointer;
    struct pcap_pkthdr* header;//数据包头部
    const u_char* pkt_data;    //数据包内容

    //时间相关字段
    time_t local_time_sec;
    struct tm local_time;
    char timeString[16];

    //线程是否结束
    bool isDone;
};

#endif // MULTHREAD_H
