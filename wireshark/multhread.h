#ifndef MULTHREAD_H
#define MULTHREAD_H

#include <QThread>
#include "pcap.h"
#include "datapackage.h"

class multhread:public QThread
{
    Q_OBJECT //信号和槽相关
public:
    multhread();

    bool setPointer(pcap_t* pointer);
    void setFlag();
    void resetFlag();

    void run() override;
    int ethernetPackageHandle(const u_char* pkt_content, QString& info);

signals:
    void send(datapackage data);//信号的发送函数
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
