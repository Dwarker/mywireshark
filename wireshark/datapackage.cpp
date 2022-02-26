#include "datapackage.h"
#include <QMetaType>

datapackage::datapackage()
{
    qRegisterMetaType<datapackage>("datapackage");
    this->timeStamp = "";
    this->data_length = 0;
    this->package_type = 0;
}

void datapackage::setInfo(QString info)
{
    this->info = info;
}

void datapackage::setPointer(const u_char *pkt_content, int size)
{
    memcpy((char*)(this->pkt_content), pkt_content, size);
}

void datapackage::setTimeStamp(QString timeStamp)
{
    this->timeStamp = timeStamp;
}

void datapackage::setDataLength(u_int data_length)
{
    this->data_length = data_length;
}

QString datapackage::getInfo()
{
    return this->info;
}

QString datapackage::getTimeStamp()
{
    return this->timeStamp;
}

QString datapackage::getDataLength()
{
    return QString::number(this->data_length);
}

QString datapackage::getPackageType()
{
    switch (this->package_type) {
    case 1: return "ARP";
    case 2: return "ICMP";
    case 3: return "TCP";
    case 4: return "UDP";
    case 5: return "DNS";
    case 6: return "TLS";
    case 7: return "SSL";
    default: return "";
    }
}

//将一个字节数据转换成十六进制
QString datapackage::byteToString(char *str, int size)
{
    QString res = "";
    for(int i = 0; i < size; i++)
    {
        char one = str[i] >> 4;
        if(one > 0x0A)
        {
            one += 0x41 - 0x0A;
        }
        else
        {
            one += 0x30;
        }

        char two = str[i] & 0x0F;
        if(two > 0x0A)
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
