## r2dwarf

integrate r2/r2frida into dwarf.

### Installation

```
cd %Dwarf%/plugins/

git clone https://github.com/iGio90/r2dwarf

~~~

# optionally install r2dec decompiler (default uses pdc)
r2pm -ci r2dec
```

### Features

* panel with r2 console
* js api to use r2 commands in frida agent
* disasm view enriched with graph view, decompiler, xrefs and data refs
* option to enhance UI for widescreen monitors

![Alt text](/screenshots/1.png?raw=true "1")

![Alt text](/screenshots/2.png?raw=true "3")

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
