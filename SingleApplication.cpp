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

#include <QTimer>
#include <QByteArray>

#include "SingleApplication.h"

//Code stable, no need to change, unless new features wants to be added

SingleApplication::SingleApplication(int &argc, char *argv[], const QString uniqueKey) : QApplication(argc, argv)
{
    sharedMemory.setKey(uniqueKey);

    // when  can create it only if it doesn't exist
    if (sharedMemory.create(5000))
    {
        sharedMemory.lock();
        *(char*)sharedMemory.data() = '\0';
        sharedMemory.unlock();

        bAlreadyExists = false;

        QTimer *timer = new QTimer(this);
        connect(timer, SIGNAL(timeout()), this, SLOT(checkForMessage()));
        timer->start(200);
    }

    else if (sharedMemory.attach()){
        bAlreadyExists = true;
    }
    else{

    }

}

void SingleApplication::checkForMessage()
{
    QStringList arguments;

    sharedMemory.lock();
    char *from = (char*)sharedMemory.data();

    while(*from != '\0'){
        int sizeToRead = int(*from);
        ++from;

        QByteArray byteArray = QByteArray(from, sizeToRead);
        byteArray[sizeToRead] = '\0';
        from += sizeToRead;

        arguments << QString::fromUtf8(byteArray.constData());
    }

    *(char*)sharedMemory.data() = '\0';
    sharedMemory.unlock();

    if(arguments.size()) emit messageAvailable( arguments );
}


bool SingleApplication::sendMessage(const QString &message)
{

    if (isMasterApp()){
        return false;
    }

    QByteArray byteArray;
    byteArray.append(char(message.size()));
    byteArray.append(message.toUtf8());
    byteArray.append('\0');

    sharedMemory.lock();
    char *to = (char*)sharedMemory.data();
    while(*to != '\0'){
        int sizeToRead = int(*to);
        to += sizeToRead + 1;
    }

    const char *from = byteArray.data();
    memcpy(to, from, qMin(sharedMemory.size(), byteArray.size()));
    sharedMemory.unlock();

    return true;
}
