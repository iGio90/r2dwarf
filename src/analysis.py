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
from PyQt5.QtCore import QThread, pyqtSignal


class R2Analysis(QThread):
    onR2AnalysisFinished = pyqtSignal(list, name='onR2AnalysisFinished')

    def __init__(self, pipe, info, data, offset):
        super(R2Analysis, self).__init__()
        self._pipe = pipe
        self._info = info
        self._data = data
        self._offset = offset

    def run(self):
        self._pipe.cmd('e anal.from = %d; e anal.to = %d; e anal.in = raw' % (
            self._info.base, self._info.base + self._info.size))

        self._pipe.cmd('aa')
        self._pipe.cmd('aac*')
        self._pipe.cmd('aar')
        self._pipe.cmd('af')

        self.onR2AnalysisFinished.emit([self._info.base, self._data, self._offset])
