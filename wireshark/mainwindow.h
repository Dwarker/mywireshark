#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>

#include "pcap.h"
#include "winsock2.h"

namespace Ui {
class MainWindow;
}

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    explicit MainWindow(QWidget *parent = 0);
    ~MainWindow();

    void showNetworkCard();
    int capture();
private slots:
    void on_comboBox_currentIndexChanged(int index);

private:
    Ui::MainWindow *ui;

    pcap_if_t *all_device;
    pcap_if_t *device; //当前设备
    pcap_t *pointer;
    char errbuf[PCAP_ERRBUF_SIZE];
};

#endif // MAINWINDOW_H
