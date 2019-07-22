"""
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
"""
from PyQt5.QtCore import pyqtSignal, QThread


class R2Graph(QThread):
    onR2Graph = pyqtSignal(list, name='onR2Graph')

    def __init__(self, pipe):
        super(R2Graph, self).__init__()
        self._pipe = pipe

    def run(self):
        graph = self._pipe.cmd('agf')
        self.onR2Graph.emit([graph])
