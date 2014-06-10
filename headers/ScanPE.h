/*
 *
 * Research:
 *
 * http://www.csn.ul.ie/~caolan/publink/winresdump/winresdump/doc/pefile.html
 * */

#ifndef SCANPE_H
#define SCANPE_H

#include <QObject>
#include <QDebug>
#include <QDir>
#include <QApplication>


#ifdef Q_OS_WIN
#include <stdio.h>
#include <windows.h>


IMAGE_NT_HEADERS peHead;
IMAGE_DOS_HEADER dosMZ;
IMAGE_SECTION_HEADER *secHead;

HANDLE host;
unsigned long numBytesRead;
char file[] = "";
unsigned char* buf = (unsigned char*)malloc(secHead[0].SizeOfRawData);  //buffer where PE section is to be read


host=CreateFileA(file,GENERIC_READ,FILE_SHARE_READ,NULL_OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,NULL);

SetFilePointer(host,sizeof(dosMZ))+dosMZ.e_lfanew,NULL,FILE_BEGIN); //PE Header located after MS-DOS Header and Stub

ReadFile(host,(void*)&peHead,sizeof(peHead),&d,NULL);
secHead=(IMAGE_SECTION_HEADER*)GlobalAlloc(GMEM_FIXED,sizeof(IMAGE_SECTION_HEADER)*peHead.FileHeader.NumberOfSections);


ReadFile(host,buf,secHead[0].SizeOfRawData,&d,0);

free(buf); //Clean up memory


qDebug() << "Scanning " << file;

#endif






#endif // SCANPE_H
