#ifndef DATAPACKAGE_H
#define DATAPACKAGE_H
#include "format.h"
#include <QString>

class datapackage
{
private:
    u_int   data_length;//数据包长度
    QString timeStamp;
    QString info;
    int package_type;

protected:
    //将一个字节数据转换成十六进制
    static QString byteToString(u_char* str, int size);

public:
    const u_char* pkt_content;

public:
    datapackage();
    //对成员变量的操作函数
    void setDataLength(u_int data_length);
    void setTimeStamp(QString timeStamp);
    void setPackageType(int type);
    void setPointer(const u_char* pkt_content, int size);
    void setInfo(QString info);

    QString getDataLength();
    QString getTimeStamp();
    QString getPackageType();
    QString getInfo();
};

#endif // DATAPACKAGE_H
