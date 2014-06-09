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

#ifndef SINGLEAPPLICATION_H
#define SINGLEAPPLICATION_H


#include <QApplication>
#include <QSharedMemory>
#include <QStringList>

//A subclass of QApplication to allow GenCore to be runned only once per session

class SingleApplication : public QApplication
{
        Q_OBJECT
public:
        SingleApplication(int &argc, char *argv[], const QString uniqueKey);

        bool alreadyExists() const{
            return bAlreadyExists;
        }
        bool isMasterApp() const{
            return !alreadyExists();
        }

        bool sendMessage(const QString &message);

public slots:
        void checkForMessage();

signals:
        void messageAvailable(const QStringList& messages);

private:
        bool bAlreadyExists;
        QSharedMemory sharedMemory;
};

#endif // SINGLEAPPLICATION_H
