## r2dwarf

integrate r2/r2frida into dwarf.

Once installed, a new tab "r2" will appear in the main tabs.

In the disasm view, you can right click to display graph and decompiler

### Installation

```
cd %Dwarf%/plugins/

git clone https://github.com/iGio90/r2dwarf

~~~

# make sure r2frida is installed:
r2pm -ci r2frida

# optionally enable decompiler
r2pm -ci r2dec
```

### Features

* panel with r2 console
* disasm view enriched with graph view, decompiler and xrefs and data refs

![Alt text](/screenshots/1.png?raw=true "1")

![Alt text](/screenshots/2.png?raw=true "2")

```
Dwarf - Copyright (C) 2019 Giovanni Rocca (iGio90)

    This program is free software: you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation, either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program.  If not, see <https://www.gnu.org/licenses/>
```
