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


#include "mainwindow.h"
#include "ui_mainwindow.h"
#include <QFile>
#include <QDir>
#include <QFileDialog>
#include <QDirIterator>
#include <QPalette>
#include <fcntl.h>
#include <QBuffer>
#include <QScrollBar>
#include "FileOperations.h"

#include <QDebug>
//#include <psapi.h>


int browsetimes = 0;
int StartDirs = 0;

using namespace std;


MainWindow::MainWindow(QWidget *parent) :
  QMainWindow(parent),
  ui(new Ui::MainWindow)
{
  //Setup the UI
  ui->setupUi(this);
  ui->ScanWidget->setCurrentIndex(0);
  ui->MainWidget->setCurrentIndex(0);
  ui->note5->setHidden(true);
  IsProcessScan = false;
  NoOfFilesDownloaded = 0;

  /*The detected viruses widgets in the ScanLog page are dual,
  but act like only one widget with the same scrollbar (For visual purposes)*/

  QScrollBar * InfectedScroll1 = ui->InfectionList->verticalScrollBar();
  QScrollBar * InfectedScroll2 = ui->Infectedlist->verticalScrollBar();

  connect(InfectedScroll1, SIGNAL(valueChanged(int)), InfectedScroll2, SLOT(setValue(int)));
  connect(InfectedScroll2, SIGNAL(valueChanged(int)), InfectedScroll1, SLOT(setValue(int)));

  //Load the database Dynamic linked library (gcvdb.dll)
  //And check if it was found
  DBLib.setFileName("gcvdb");
  DBLib.load();
  if(DBLib.isLoaded() == false)
  {
      qDebug() << "Found library";
      QMessageBox errdll;
      errdll.setIcon(QMessageBox::Critical);
      errdll.setText("Some files were not found, or found corrupted!");
      errdll.setInformativeText("gcvdb.dll was not found in PenguAV's directory.");
      errdll.exec();
      gcvdbfound = false;
  }
  else
  {
      qDebug() << "Found library";
      qDebug() << DBLib.resolve("ScanFile");
      gcvdbfound = true;
  }


  //Set up the UI to get ready for scans
  ui->Removeallbutton->setHidden(true);
  MalwareCount = 0;
  ui->Infectedlist->setHidden(true);
  ui->InfectionList->setHidden(true);
  ui->stopscan->setEnabled(false);
  trayIcon = new QSystemTrayIcon(this);
  ui->CleaningProcess->hide();

  //Connect the tray icon signal so that when its double clicked, PenguAV window is shown again
  connect(trayIcon, SIGNAL(activated(QSystemTrayIcon::ActivationReason)), this, SLOT(showwindow(QSystemTrayIcon::ActivationReason)));


  //Multithread
  scanner->moveToThread(pthread);
  connect(this,SIGNAL(ScanFiles(QStringList,QStringList,QStringList,QStringList,QStringList,int,int,int)),scanner,SLOT(ScanFun(QStringList,QStringList,QStringList,QStringList,QStringList,int,int,int)));
  connect(scanner,SIGNAL(scanProgress(QString,int)),this,SLOT(scanProgress(QString,int)));
  connect(scanner,SIGNAL(setStyleSheet(QString)),this,SLOT(setStyleSheet(QString)));
  connect(scanner,SIGNAL(checkmal_not_zero(QString,QString,int)),this,SLOT(checkmal_not_zero(QString,QString,int)));
  connect(scanner,SIGNAL(checkmal_zero(QString)),this,SLOT(checkmal_zero(QString)));
  connect(scanner,SIGNAL(DirList_empty()),this,SLOT(DirList_empty()));
  connect(scanner,SIGNAL(MalwareCount_zero()),this,SLOT(MalwareCount_zero()));
  //pthread->start();

  //Clean up threads
  connect(scanner,SIGNAL(close()),scanner,SLOT(closeall()));
  connect(scanner,SIGNAL(closethread()),pthread,SLOT(quit()));
  connect(scanner,SIGNAL(closethread()),this,SLOT(closethread()));
  //connect(pthread, SIGNAL(finished()), scanner, SLOT(deleteLater()));

}

MainWindow::~MainWindow()
{
  delete ui;
}

//Start scan clicked
void MainWindow::on_startscan_clicked()
{

    //Checks if the search directory is empty or meaningless, else prepares the directories for scan
    if(ui->scandir->text() == "\\" || ui->scandir->text() == "/" || ui->scandir->text() == " " || ui->scandir->text() == "" || ui->scandir->text().isNull() || ui->scandir->text().isEmpty())
    {
        QMessageBox emptydir;
        emptydir.setText("Scan directory is empty! Please click on 'Select Directory' to select your scan directory");
        emptydir.exec();
    }

   else{
   PrepareDirectories();
   }


}

//Prepares directories that the user wants to scan
//And add all the files and sub-directories in that directory/partition to the scan list
void MainWindow::PrepareDirectories()
{
    //Checks if the user wants a Process scan or not
    if(ui->ProcessScanSelect->isChecked() == false) IsProcessScan = false;
//    Checks if the user wants a Quick scan or not
//      Notice that Quick Scan scans only Partition C:
    if(ui->QuickScanSelect->isChecked() == false) IsQuickScan = false;

    //Setup the UI for a new scan session
    ui->stopscan->setEnabled(false);
    ui->startscan->setEnabled(false);
    ui->Browsedir->setEnabled(false);
    ui->ScanWidget->setEnabled(false);
    ui->ProcessScanSelect->setEnabled(false);
    ui->CustomScanSelect->setEnabled(false);
    ui->QuickScanSelect->setEnabled(false);
    log.clear();
    ui->Removeallbutton->setHidden(true);
    ui->scandir->setModified(true);
    ui->currentfilescanned->setText("Preparing scan, this might take a minute or two, depending on your computer.");

    //This Sleep function call prevents PenguAV to crash on old and weak CPUs
    //Sleep(500);

    QString filestr;

    //If the user requested a Quick Scan, set the scanning directory to C:
    //Else if not, set the scanning directory to the requested scanning directory
    if(IsQuickScan == false)filestr = ui->scandir->text();
    //if(IsQuickScan == true) filestr = "C:\\";
    if(IsQuickScan == true) filestr = "/home/justin";

    qDebug() << IsQuickScan;
    qDebug() << "walking";

    //Advanced Stuff! If you are a newbie, don't change!
    //Setup the directories to be walked on. (Not files)
    QDir scandir;
    QDirIterator directory_walker(filestr, QDir::Dirs | QDir::NoDotAndDotDot , QDirIterator::Subdirectories);

    scandir.setFilter(QDir::NoDotAndDotDot);
    scandir.setPath(filestr);

    DirVector = scandir.entryList(QDir::Dirs,QDir::Name);
    Dirlist.push_back(filestr);
    qDebug() << "preparing to scan";

    while(directory_walker.hasNext())
    {
        qDebug() << "walking";
        QApplication::processEvents();
        directory_walker.next();
        Dirlist.push_back(directory_walker.filePath() + "/");
    }

    qDebug() << "Start Scan";
 //Proceed to Scan and File Walking
 StartScan();
}


//Prepares the files to be scanned and walked on, then scans all those files at once
//Notice that the scanning process is done on a different thread than the one PenguAV is on.

void MainWindow::StartScan()
{
 if(gcvdbfound == true) //If gcvdb.dll is found, proceed, else don't
  {
    //Setup the UI for scan, clear and reset the variables, lists and buffers for a new scanning session
    ui->ScanWidget->setEnabled(false);
    ui->ProcessScanSelect->setEnabled(false);
    ui->CustomScanSelect->setEnabled(false);
    ui->QuickScanSelect->setEnabled(false);
    if(ui->ProcessScanSelect->isChecked() == false) IsProcessScan = false;
    stopping = 0;
    progress = 0;
    ui->stopscan->setEnabled(true);

    //Clear the lists to prevent the previous session results from interfering
    MalwareList.clear();
    InfectionList.clear();
    MalwareCount = 0;
    ui->objectsinfected->setStyleSheet("color: rgb(0, 0, 0); font: 75 9pt \"MS Shell Dlg 2\";");
    ui->FilesScanned->setStyleSheet("color: rgb(0, 0, 0); font: 75 9pt \"MS Shell Dlg 2\";");
    ui->objectsinfected->setNum(MalwareCount);
    ui->Infectedlist->clear();
    ui->InfectionList->clear();
    ui->Infectedlist->setHidden(true);
    ui->InfectionList->setHidden(true);
    ui->Scandirlog->clear();
    ui->Removeallbutton->setHidden(true);
    ProcessTasks.clear();

    //Check if its a proccess scan or not
    //If not, proceed with a normal scan
    if(IsProcessScan == false)
    {
        pthread->start();
        //emit ScanFiles(Dirlist,ScanDirectory,MalwareList,InfectionList,ProcessTasks,stopping,progress,MalwareCount);
        scanner->ScanFun(Dirlist,ScanDirectory,MalwareList,InfectionList,ProcessTasks,stopping,progress,MalwareCount);


    }

    //If the user requested a Process scan
    if(IsProcessScan == true)
    {
    //As long as the ToBeScanned Process list is not empty, set them up and scan them
    while(Proclist.isEmpty() == false && stopping != 1)
    {
      QApplication::processEvents();
      QString CurrentScannedProcess;
      CurrentScannedProcess = Proclist.takeFirst();
      QString NameCurrentProcess;
      NameCurrentProcess = ProcessNameList.takeFirst();

      //QString NameOfCurrentProcess;
     // NameOfCurrentProcess = ProcessNameList.takeFirst();




      ui->currentfilescanned->setText(CurrentScannedProcess);

      ui->FilesScanned->setNum(progress);
      progress += 1;

      ui->FilesScanned->setStyleSheet("color: rgb(0, 0, 0); font: 75 9pt \"MS Shell Dlg 2\";");


      QString checkmal;

      //Load the core scanning function from the DLL each time a process is going to be scanned
      //If the dll could be loaded, scan the process, else skip the process
      typedef const char* (*DLLPrt)(const char*);
      DLLPrt ScanFile = (DLLPrt) DBLib.resolve("ScanFile");
      if (ScanFile)
      {
      checkmal = ScanFile(CurrentScannedProcess.toStdString().c_str());
      }

      //If the returned value was not 0, that means a virus was detected
      //The following actions are taken:
      //1- Notify the user by adding the results in the scan log text box
      //2- Add the virus to the MalwareList so actions can be taken later
      //3- Add the Filename and the Malware name to the Scan Log page
      if(checkmal != 0)
      {
          ui->Scandirlog->appendHtml(CurrentScannedProcess + " <b>=> <font color='red'>" + checkmal + "</font></b>");
          ui->Scandirlog->appendHtml("");
          MalwareList.push_back(CurrentScannedProcess);
          InfectionList.push_back(checkmal);
          ProcessTasks.push_back(NameCurrentProcess);
          ui->Infectedlist->addItem(CurrentScannedProcess);
          ui->InfectionList->addItem(checkmal);
          MalwareCount += 1;
          ui->objectsinfected->setStyleSheet("color: rgb(255, 0, 0); font: 75 9pt \"MS Shell Dlg 2\";");
          ui->objectsinfected->setNum(MalwareCount);

      }
      //The scan function returned 0, the process is clean
      else
      {
          ui->Scandirlog->appendHtml(CurrentScannedProcess + " <b>=> <font color='blue'>Clean</font></b>");
          ui->Scandirlog->appendHtml("");

      }

     //The ToBeScanned Process List is empty, which means scan has finished
     //Stop the scan and reset the UI back to defaul
     if(Proclist.isEmpty())
     {
     progress = 0;
     ui->startscan->setEnabled(true);
     ui->stopscan->setEnabled(false);
     ui->Browsedir->setEnabled(true);
     if(MalwareCount > 0)
     {
     ui->Removeallbutton->setHidden(false);
     }
     ui->Infectedlist->setHidden(false);
     ui->InfectionList->setHidden(false);
     ui->currentfilescanned->setText("Scan Finished.");
     ui->MainWidget->setCurrentIndex(1);
     IsProcessScan = false;
     IsQuickScan = false;
     ui->ScanWidget->setEnabled(true);
     ui->ProcessScanSelect->setEnabled(true);
     ui->CustomScanSelect->setEnabled(true);
     ui->QuickScanSelect->setEnabled(true);


    }

}

    }
 }

//DLL was not found or an unexpected critical error occured
else
{
     QMessageBox errdll;
     errdll.setIcon(QMessageBox::Critical);
     errdll.setText("Could not start scan operation because gcvdb.dll was not found.");
     errdll.exec();

     on_stopscan_clicked(); //Stop the scan immediately to save PenguAV from crashing
}
}

//Open the Browse Directories Window so that the user can select the scan directory
void MainWindow::on_Browsedir_clicked()
{
    browsetimes += 1;
    CurrentDir = QFileDialog::getExistingDirectory(this,
         tr("Directory to scan"), "C:\\", QFileDialog::ShowDirsOnly);
#ifdef Q_WS_WIN
    CurrentDir.push_back(QString("\\"));
#endif

    ui->scandir->setText(CurrentDir);
}

//If Remove All button is clicked:
//1- Use the TASKKILL DOS command to stop the virus process if it was on
//2- Use the RemoveVirus function to remove the virus
void MainWindow::on_Removeallbutton_clicked()
{
    QApplication::processEvents();
    ui->InfectionList->clear();
    ui->Removeallbutton->setHidden(true);
    int MalwareInt = MalwareList.count();
    int cleanprocess = 0;
    ui->CleaningProcess->show();
    ui->CleaningProcess->setMaximum(MalwareInt);
    ui->CleaningProcess->setValue(cleanprocess);
    while(!MalwareList.isEmpty())
    {
        cleanprocess += 1;
        ui->CleaningProcess->setValue(cleanprocess);

        QString TaskKillCommand;

        TaskKillCommand.push_back("taskkill /f /im " + ProcessTasks.takeFirst());



        //WinExec(TaskKillCommand.toStdString().c_str(), SW_HIDE);  //Kill proccess if running
        TaskKillCommand.clear();
        //Sleep(500); //Sleep to ensure that the proccess is closed before deleting

        //Feleting the virus

        if(RemoveVirus(MalwareList.takeFirst()))
        {
            QListWidgetItem * FixedItem = new QListWidgetItem("Fixed");
            FixedItem->setForeground(QBrush(QColor(0,175,0),Qt::SolidPattern));
            ui->InfectionList->addItem(FixedItem);
        }
        else //The virus could not be deleted
        {
            QListWidgetItem * UnFixedItem = new QListWidgetItem("Could not fix");
            UnFixedItem->setForeground(QBrush(QColor(255,0,0),Qt::SolidPattern));
            ui->InfectionList->addItem(UnFixedItem);
        }
    }

     ui->ScanWidget->setEnabled(true);
     ui->ProcessScanSelect->setEnabled(true);
     ui->CustomScanSelect->setEnabled(true);
     ui->QuickScanSelect->setEnabled(true);



    //If there were more than 6 malwares found, recommend restarting the computer to ensure the computer is safe after restart
    if(MalwareCount > 6)
    {
    QMessageBox RestartComp;
    RestartComp.setWindowTitle("Restart your computer");
    RestartComp.setText("A system restart is required for your computer to take effect. Click Yes to restart your PC now, No if you want to restart it later.");
    RestartComp.setStandardButtons(QMessageBox::Yes | QMessageBox::No);
    RestartComp.setDefaultButton(QMessageBox::Yes);
    int ret = RestartComp.exec();

    switch (ret)
    {
    case QMessageBox::Yes:
        //Restart the computer using "shutdown" command
        //If someone has an alternate restart function to softly restart the computer
        //Please add it, since this one is not so professional
        QProcess::startDetached("shutdown -s -f -t 00");
           break;

    case QMessageBox::No:
           break;

    default:
          break;
    }
    }


}

//Stop scan was clicked
//Force the thread to stop scanning
void MainWindow::on_stopscan_clicked()
{

    qDebug() << "STOP PRESSED";
    scanner->close();
    ui->currentfilescanned->setText("Terminating scan...");



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




    qDebug() << "STOPPED";



}

//Hide PenguAV if it was closed (not yet needed)
void MainWindow::closeEvent(QCloseEvent *event)
{
          /*this->hide();
          trayIcon->setIcon(QIcon(":/new/prefix1/data/PremiumTray.png"));
          trayIcon->show();
          trayIcon->showMessage("Notification:","PenguAV will remain hidden in your task bar. You can unhide it by clicking the PenguAV icon.",QSystemTrayIcon::Information,5000);
          event->ignore();*/


}


//Advanced stuff!
//Process handling and setting up for scan if the user requesteda Process Scan
char* MainWindow::PDirName(quint32 PID){
#ifdef Q_WS_WIN
HANDLE Handle;
char buffer[MAX_PATH];
Handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, PID);
if (Handle != 0)
{
if (GetModuleFileNameExA(Handle, 0, buffer, MAX_PATH) != 0)
{
   Proclist.push_back(QString::fromAscii(buffer));


}else{

}
CloseHandle(Handle);
}
#endif
}

void MainWindow::ScanActiveProcesses()
{
   quint32 aProcesses[1024], cbNeeded, cProcesses;
   unsigned int i;

   //if ( !EnumProcesses( aProcesses, sizeof(aProcesses), &cbNeeded ) ) return;
   cProcesses = cbNeeded / sizeof(quint32);
   for ( i = 0; i <= cProcesses; i++ )
   {
      if( aProcesses[i] != 0 )
      {
         PDirName( aProcesses[i] );
         GetProcessName(aProcesses[i]);
      }
   }
   StartScan();

}
void MainWindow::GetProcessName(quint32 PID)
{
//    HANDLE Handle = OpenProcess(
//        PROCESS_QUERY_INFORMATION | PROCESS_VM_READ,
//        FALSE,
//        PID
//    );
//    if (Handle)
//    {
//        char Buffer[MAX_PATH];

//        GetModuleBaseNameA(Handle,NULL,Buffer,MAX_PATH);

//        ProcessNameList.push_back(Buffer);
//        CloseHandle(Handle);
//    }
}

//End of Process handling and setting

//UI Stuff
//Functions to change through pages on button clicks
void MainWindow::on_ScanPageButton_clicked()
{
    ui->MainWidget->setCurrentIndex(0);
}

void MainWindow::on_ScanLogPageButton_clicked()
{
    ui->MainWidget->setCurrentIndex(1);
}

void MainWindow::on_SettingsPageButton_clicked()
{
    ui->MainWidget->setCurrentIndex(2);
}


void MainWindow::on_AboutPageButton_clicked()
{
    ui->MainWidget->setCurrentIndex(3);
}

void MainWindow::on_ProcessScan_clicked()
{
    IsProcessScan = true;
    ScanActiveProcesses();
}

void MainWindow::on_QuickScanSelect_clicked()
{
    ui->ScanWidget->setCurrentIndex(0);
}

void MainWindow::on_CustomScanSelect_clicked()
{
    ui->ScanWidget->setCurrentIndex(1);
}

void MainWindow::on_ProcessScanSelect_clicked()
{
    ui->ScanWidget->setCurrentIndex(2);
}


//If QuickScan button was clicked, setup a Quick Scan
void MainWindow::on_QuickScan_clicked()
{
    IsQuickScan = true;
    PrepareDirectories();
}

void MainWindow::on_HomepageButton_clicked()
{
    //ShellExecuteA(NULL, "open", "http://gen-core.sourceforge.net/", NULL, NULL, SW_SHOWNORMAL);
}


