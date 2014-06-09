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

//#include <QtGui/QApplication>


#include <QApplication>

#include "SingleApplication.h"
#include <QMessageBox>
#include <QString>
#include "mainwindow.h"


int main(int argc, char *argv[])
{
    QString argv_string;
    //argv_string = QString::fromAscii(argv[1]);
    argv_string = QString(argv[1]);

    SingleApplication a(argc, argv,"PenguAV");

    if(a.alreadyExists()) //If PenguAV is already running, close the current session
    {
        QMessageBox alreadyrun;
        alreadyrun.setText("PenguAV is already running!");
        alreadyrun.exec();
        return 0;
    }

    MainWindow w;
    w.show();

    //Arguments

    if(argv_string == "/min") //Runs PenguAV minimized
    {
    w.MinArgument();
    }

    return a.exec();
}

