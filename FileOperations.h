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

Copyright 2013 MJaoune
*/

#ifndef FILEOPERATIONS_H
#define FILEOPERATIONS_H
#include <QFile>
#include <QIODevice>
//#include <windows.h>
#include <string>
#include <QString>
using namespace std;

//Remove virus file function

/*Tries removing the virus file, if it couldn't,
 it opens the virus file and removes all the data in it,
else it returns false*/

bool RemoveVirus(QString Quedfile)
{
    string file = Quedfile.toStdString();

#ifdef Q_WS_WIN

    if(!DeleteFileA(file.c_str()))
    {
        QFile VirusFile(QString::fromStdString(file));
        if(!VirusFile.remove(QString::fromStdString(file)))
        {
        if(!VirusFile.open(QIODevice::WriteOnly, QIODevice::Truncate))
        {
            return false;
        }
        }
        else return true;
        VirusFile.close();
    }
else return true;

#endif

return true;
}

#endif // FILEOPERATIONS_H
