#ifndef SCANNER_H
#define SCANNER_H

#include "ScanPE.h" //For scanning PE sections

#include <QObject>
#include <QDebug>
#include <QDir>
#include <QApplication>
#include <QLibrary>

class Scanner : public QObject {
    Q_OBJECT



private:
    int stopping;
    int progress;


public slots:

    void ScanFun(QStringList Dirlist,QStringList ScanDirectory, QStringList MalwareList, QStringList InfectionList, QStringList ProcessTasks, int stop, int prog, int MalwareCount){
            QLibrary DBLib;
            DBLib.setFileName("mvdb");
            DBLib.load();

            stopping = stop;
            progress = prog;

//            QByteArray temp;

//            QFile file("test");
//            file.open(QIODevice::ReadOnly);
//            temp = file.readAll();
//            //qDebug() << temp.toHex();

//            qDebug() << temp.toHex().indexOf("564952555300");
//            qDebug() << "FOUND";
//            file.close();



            while(Dirlist.isEmpty() == false)
            {



              //Advanced Stuff! If you are a newbie, don't change!
              //Setup the files, set their scan names and detect their extension
              QString DirStack;
              DirStack.push_back(Dirlist.takeFirst());

              if(DirStack.isEmpty() || DirStack.isNull()) DirStack.push_back(Dirlist.takeFirst());

              QDir ScanDirs;
              ScanDirs.setPath(DirStack);


              ScanDirectory = ScanDirs.entryList(QDir::Files | QDir::Hidden | QDir::NoDotAndDotDot | QDir::NoSymLinks,QDir::Name);

//              qDebug() << ScanDirectory;
//              qDebug() << ScanDirs;

              if(stopping == 1)
              {
                  emit closethread();
                  return;}

              //Start scanning each file
              while(!ScanDirectory.isEmpty() && stopping != 1)
              {
              QApplication::processEvents(); //This function processes all of the below function in the While loop in a random thread

              QString FileName(ScanDirectory.takeFirst());
              QString FileStack;
              if(DirStack.endsWith("/"))
              FileStack = (DirStack + FileName);
              else
                  FileStack = DirStack + "/" + FileName;

              //Send Signal
              emit scanProgress(FileStack,progress);
              //ui->currentfilescanned->setText(FileStack);
              //ui->FilesScanned->setNum(progress);
              progress += 1;


              //If the file matches any of the extensions, scan it
              if ((FileStack.endsWith(".exe",Qt::CaseInsensitive) || /*FileStack.endsWith(".txt",Qt::CaseInsensitive) ||*/ FileStack.endsWith(".bat",Qt::CaseInsensitive) || FileStack.endsWith(".html",Qt::CaseInsensitive) || FileStack.endsWith(".php",Qt::CaseInsensitive) || FileStack.endsWith(".pl",Qt::CaseInsensitive) || FileStack.endsWith(".inf",Qt::CaseInsensitive) || FileStack.endsWith(".jar",Qt::CaseInsensitive) || FileStack.endsWith(".js",Qt::CaseInsensitive) || FileStack.endsWith(".java",Qt::CaseInsensitive) || FileStack.endsWith(".py",Qt::CaseInsensitive) || FileStack.endsWith(".dll",Qt::CaseInsensitive)  || FileStack.endsWith(".bmp",Qt::CaseInsensitive)  || FileStack.endsWith(".png",Qt::CaseInsensitive)  || FileStack.endsWith(".jpg",Qt::CaseInsensitive)  || FileStack.endsWith(".gif",Qt::CaseInsensitive)  || FileStack.endsWith(".jpeg",Qt::CaseInsensitive)))
              {
                  //Send Signal
                 // emit setStyleSheet("color: rgb(0, 0, 0); font: 75 9pt \"MS Shell Dlg 2\";");
                  //ui->FilesScanned->setStyleSheet("color: rgb(0, 0, 0); font: 75 9pt \"MS Shell Dlg 2\";"); //UI stuff


               QString checkmal;

              //Load the core scanning function from the DLL each time a file is going to be scanned
              //If the dll could be loaded, scan the file, else skip the file
              typedef const char* (*DLLPrt)(const char*);
              DLLPrt ScanFile = (DLLPrt) DBLib.resolve("ScanFile");
              if (ScanFile)
              {
              //The core scan function returns the virus file name if a virus was detected
              //Else it just returns 0
              checkmal = ScanFile(FileStack.toStdString().c_str());

              }


              //If the returned value was not 0, that means a virus was detected
              //The following actions are taken:
              //1- Notify the user by adding the results in the scan log text box
              //2- Add the virus to the MalwareList so actions can be taken later
              //3- Add the Filename and the Malware name to the Scan Log page
              if(checkmal != 0)
              {

                  qDebug() << "MALWARE DETECTED";
                  MalwareCount += 1;
                  emit checkmal_not_zero(FileStack,checkmal,MalwareCount);
        //          ui->Scandirlog->appendHtml(FileStack + " <b>=> <font color='red'>" + checkmal + "</font></b>");
        //          ui->Scandirlog->appendHtml("");
                  MalwareList.push_back(FileStack);
                  InfectionList.push_back(checkmal);
                  ProcessTasks.push_back(FileName);
        //          ui->Infectedlist->addItem(FileStack);
        //          ui->InfectionList->addItem(checkmal);

        //          ui->objectsinfected->setStyleSheet("color: rgb(255, 0, 0); font: 75 9pt \"MS Shell Dlg 2\";");
        //          ui->objectsinfected->setNum(MalwareCount);

              }
              //The return value is 0, no virus was detected, don't do any actions, just report the file as clean
              else
              {
                  emit checkmal_zero(FileStack);
        //          ui->Scandirlog->appendHtml(FileStack + " <b>=> <font color='blue'>Clean</font></b>");
        //          ui->Scandirlog->appendHtml("");

              }

              }

             //The ToBeScanned list has ended, which means no more files/directories to scan
             //Stop the scan and get the UI back to default (Before scan)
             if(Dirlist.isEmpty())
             {
             progress = 0;

        //     ui->startscan->setEnabled(true);
        //     ui->stopscan->setEnabled(false);
        //     ui->Browsedir->setEnabled(true);
        //     ui->ScanWidget->setEnabled(true);
        //     ui->ProcessScanSelect->setEnabled(true);
        //     ui->CustomScanSelect->setEnabled(true);
        //     ui->QuickScanSelect->setEnabled(true);
             //If malwares were found, show the "Remove All" button, else no need
             if(MalwareCount > 0)
             {
                 emit MalwareCount_zero();
        //     ui->Removeallbutton->setHidden(false);
        //     ui->note5->setHidden(false);
             }
        //     ui->Infectedlist->setHidden(false);
        //     ui->InfectionList->setHidden(false);
        //     ui->currentfilescanned->setText("Scan Finished.");
        //     ui->MainWidget->setCurrentIndex(1);

             emit DirList_empty();

             }

            }

            }

    }


    void closeall(){
        stopping = 1;
        progress = 0;
    }


signals:
   void scanProgress(QString,int);
   void setStyleSheet(QString);
   void checkmal_not_zero(QString,QString,int);
   void checkmal_zero(QString);
   void DirList_empty();
   void MalwareCount_zero();
   void close();
   void closethread();



};


#endif // SCANNER_H
