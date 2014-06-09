/*This program is free software: you can redistribute it and/or modify
it under the terms of the Lesser GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
Lesser GNU General Public License for more details.

You should have received a copy of the Lesser GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.

Copyright 2013
*/

#ifndef MAINWINDOW_H
#define MAINWINDOW_H

//#include <QMainWindow>
//#include <windows.h>
//#include <wincrypt.h>
//#include <fstream>
//#include <QSystemTrayIcon>
//#include <iostream>
//#include <istream>
//#include <stdio.h>
//#include <psapi.h>
//#include <dirent.h>
//#include <tchar.h>
//#include <unistd.h>
//#include <QString>
//#include <QStringList>
//#include <QSystemTrayIcon>
//#include <QFtp>
//#include "ui_mainwindow.h"
//#include <QBuffer>
//#include "ftp.h"
//#include <QMessageBox>
//#include <QTimer>
//#include <QFile>
//#include <QProcess>
//#include <QLibrary>


#include <QMainWindow>
#include <fstream>
#include <QSystemTrayIcon>
#include <iostream>
#include <istream>
#include <stdio.h>
#include <dirent.h>
#include <unistd.h>
#include <QString>
#include <QStringList>
#include <QSystemTrayIcon>
#include "ui_mainwindow.h"
#include <QBuffer>
#include "ftp.h"
#include <QMessageBox>
#include <QTimer>
#include <QFile>
#include <QProcess>
#include <QLibrary>

#include <QThread>
#include "Scanner.h"

namespace Ui {
  class MainWindow;
}

class MainWindow : public QMainWindow
{
  Q_OBJECT
  
public:
  explicit MainWindow(QWidget *parent = 0);
  ~MainWindow();
   QString CurrentDir;
   QStringList DirVector;
   QStringList DirVector2;
   QStringList Dirlist;
   QStringList Proclist;
   QStringList MalwareList;
   QStringList InfectionList;
   QStringList ProcessTasks;
   QStringList ScanDirectory;
   QStringList UpdateFiles;
   QSystemTrayIcon *trayIcon;
   QTimer timer;
   QLibrary DBLib;
   QString log;
   QString clean;
   bool gcvdbfound;
   int progress;
   int MalwareCount;
   int stopping;
   int ftpoption;
   int updating;
   int NoOfFilesDownloaded;
   QFile *UpdateFile;
   bool IsProcessScan;
   bool IsQuickScan;
   QStringList ProcessNameList;
   char* PDirName(quint32 PID);
   void ScanActiveProcesses();
   void GetProcessName(quint32 PID);

   //Runs GenCore minimized (Used in main.cpp in case /min argument was used)
   void MinArgument()
   {
       this->hide();
       trayIcon->setIcon(QIcon(":/new/prefix1/data/gencoreicn.png"));
       trayIcon->show();
       trayIcon->showMessage("Notification:","GenCore will remain hidden in your task bar. You can unhide it by clicking the GenCore icon.",QSystemTrayIcon::Information,5000);
   }



  
private slots:
  void on_startscan_clicked();

  void on_Browsedir_clicked();

  void closeEvent(QCloseEvent *event);

  void on_Removeallbutton_clicked();

  void on_stopscan_clicked();

  //Show GenCore window when the tray icon is double-clicked
  void showwindow(QSystemTrayIcon::ActivationReason reason)
      {
          if(reason == QSystemTrayIcon::DoubleClick)
          {
          this->show();
          trayIcon->hide();
          }
      }


 void on_ScanPageButton_clicked();

 void on_ScanLogPageButton_clicked();

 void on_SettingsPageButton_clicked();

 void on_AboutPageButton_clicked();

 void on_ProcessScan_clicked();

 void on_QuickScanSelect_clicked();

 void on_CustomScanSelect_clicked();

 void on_ProcessScanSelect_clicked();

 void on_QuickScan_clicked();

 void on_HomepageButton_clicked();



 //Scanner Thread
 void scanProgress(QString FileStack,int progress){
     ui->currentfilescanned->setText(FileStack);
     ui->FilesScanned->setNum(progress);
 }

 void checkmal_not_zero(QString FileStack,QString checkmal,int MalwareCount){

                ui->Scandirlog->appendHtml(FileStack + " <b>=> <font color='red'>" + checkmal + "</font></b>");
                ui->Scandirlog->appendHtml("");

                ui->Infectedlist->addItem(FileStack);
                ui->InfectionList->addItem(checkmal);
                //ui->objectsinfected->setStyleSheet("color: rgb(255, 0, 0); font: 75 9pt \"MS Shell Dlg 2\";");
                ui->objectsinfected->setNum(MalwareCount);
 }

 void checkmal_zero(QString FileStack){
           ui->Scandirlog->appendHtml(FileStack + " <b>=> <font color='blue'>Clean</font></b>");
           ui->Scandirlog->appendHtml("");
}

 void DirList_empty(){


          ui->startscan->setEnabled(true);
          ui->stopscan->setEnabled(false);
          ui->Browsedir->setEnabled(true);
          ui->ScanWidget->setEnabled(true);
          ui->ProcessScanSelect->setEnabled(true);
          ui->CustomScanSelect->setEnabled(true);
          ui->QuickScanSelect->setEnabled(true);

          ui->Infectedlist->setHidden(false);
          ui->InfectionList->setHidden(false);
          ui->currentfilescanned->setText("Scan Finished.");
          ui->MainWidget->setCurrentIndex(1);

 }

 void MalwareCount_zero(){
    ui->Removeallbutton->setHidden(false);
    ui->note5->setHidden(false);

 }

 void closethread(){
     progress = 0;
     ui->startscan->setEnabled(true);
     ui->stopscan->setEnabled(false);
     ui->Browsedir->setEnabled(true);
     if(MalwareCount > 0)
     {
     ui->Removeallbutton->setHidden(false);
     ui->MainWidget->setCurrentIndex(1);
     }
     ui->Infectedlist->setHidden(false);
     ui->InfectionList->setHidden(false);
     stopping = 1;
     IsProcessScan = false;
     IsQuickScan = false;
     ui->ScanWidget->setEnabled(true);
     ui->ProcessScanSelect->setEnabled(true);
     ui->CustomScanSelect->setEnabled(true);
     ui->QuickScanSelect->setEnabled(true);
     ui->currentfilescanned->setText("Scan has been terminated.");
 }

signals:
 void ScanFiles(QStringList,QStringList,QStringList, QStringList, QStringList, int,int,int);

private:
  Ui::MainWindow *ui;
  //Ftp ftp;
  QBuffer LatestVer;
  QBuffer NewsBuff;

  QThread *pthread = new QThread();
  Scanner *scanner = new Scanner();

  void StartScan();

  void PrepareDirectories();

  void StartWDirs();


};


#endif // MAINWINDOW_H
