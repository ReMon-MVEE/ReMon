/*
 * Multi Variant Execution Environment PoC
 * Copyright (C) 2010 Stijn Volckaert <stijnv@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include <stdio.h>
#include <stdlib.h>

int main(int argc, char** argv)
{
    #define max 0x0001FFFF
    int register tmp;

    for (int register i = 0; i < max; ++i)
    {
        for (int register j = 0; j < max; ++j)
        {
            tmp = i << j;
        }
    }

    printf("Done!\n");

    return 0;
}
