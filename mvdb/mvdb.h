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

#ifndef MVDB_H
#define MVDB_H

#include "mvdb_global.h"

class MVDBSHARED_EXPORT Mvdb {
public:
    Mvdb();
    const char* scanfile(const char* file);
};

#endif // GCVDB_H
