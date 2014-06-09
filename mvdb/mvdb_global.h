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

#ifndef MVDB_GLOBAL_H
#define MVDB_GLOBAL_H

#include <QtCore/qglobal.h>

#if defined(MVDB_LIBRARY)
#  define MVDBSHARED_EXPORT Q_DECL_EXPORT
#else
#  define MVDBSHARED_EXPORT Q_DECL_IMPORT
#endif

#endif // MVDB_GLOBAL_H
