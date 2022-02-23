#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QString>
#include "multhread.h"

MainWindow::MainWindow(QWidget *parent) :
    QMainWindow(parent),
    ui(new Ui::MainWindow)
{
    ui->setupUi(this);
    showNetworkCard();

    //因为这里是gui线程,如果抓包逻辑也放在gui线程,会将界面卡死,所以将相关逻辑放在新线程中
    multhread* thread = new multhread;

    static bool index = false;
    //把信号和槽联系起来,选中runandup,然后执行capture()
    connect(ui->actionrunandstop, &QAction::triggered, this, [=](){
        index = !index;
        if(index)
        {
            int res = capture();
            if(res != -1 && pointer)
            {
                thread->setPointer(pointer);
                thread->setFlag();
                thread->start();
                //切换为抓包状态后,将开始图片切换为停止图片(共用按钮)
                ui->actionrunandstop->setIcon(QIcon(":/stop.png"));
                //因为选中网卡在抓包了,所以该下拉框不能再进行选择
                ui->comboBox->setEnabled(false);
            }
        }
        else
        {
            thread->resetFlag();
            thread->quit();
            thread->wait();
            ui->actionrunandstop->setIcon(QIcon(":/start.png"));
            ui->comboBox->setEnabled(true);
            pcap_close(pointer);
            pointer = nullptr;
        }
    });
}

MainWindow::~MainWindow()
{
    delete ui;
}

//显示所有网卡设备
void MainWindow::showNetworkCard()
{
    int n = pcap_findalldevs(&all_device, errbuf);

    if(n == -1)
    {
        ui->comboBox->addItem("error: " + QString(errbuf));
    }
    else
    {
        ui->comboBox->clear();
        ui->comboBox->addItem("please choose card!");
        for(device = all_device; device != nullptr; device = device->next)
        {
            QString device_name = device->name;
            device_name.replace("\\Device\\", "");//去掉多余的前缀
            QString des = device->description;
            QString item = device_name + des;
            ui->comboBox->addItem(item);
        }
    }
}

void MainWindow::on_comboBox_currentIndexChanged(int index)
{
    //选中哪个网卡时,会将该index的值传过来,锁定该设备
    int i = 0;
    if(index != 0)//第0个是提示信息,所以从后面开始
    {
        for(device = all_device; i < index - 1; device = device->next, i++)
            ;
        return;
    }
}

int MainWindow::capture()
{
    if(device)
    {
        pointer = pcap_open_live(device->name, 65535, 1, 1000, errbuf);
    }
    else
    {
        return -1;
    }

    if(!pointer)
    {
        pcap_freealldevs(all_device);
        device = nullptr;
        return -1;
    }
    else
    {
        if(pcap_datalink(pointer) != DLT_EN10MB)
        {
            pcap_close(pointer);
            pcap_freealldevs(all_device);
            device = nullptr;
            pointer = nullptr;
            return -1;
        }
        statusBar()->showMessage(device->name);
    }
    return 0;
}
