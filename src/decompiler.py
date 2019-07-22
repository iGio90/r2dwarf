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
from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QCursor
from PyQt5.QtWidgets import QPlainTextEdit, QMenu

from lib import utils


class R2Decompiler(QThread):
    onR2Decompiler = pyqtSignal(list, name='onR2Decompiler')

    def __init__(self, pipe, with_r2dec):
        super(R2Decompiler, self).__init__()
        self._pipe = pipe
        self._with_r2dec = with_r2dec

    def run(self):
        decompile_data = self._pipe.cmd('pdcj --offset')
        self.onR2Decompiler.emit([decompile_data])


class R2DecompiledText(QPlainTextEdit):
    def __init__(self, parent=None, disasm_view=None):
        super().__init__(parent=parent)
        self._disasm_view = disasm_view
        self.setStyleSheet('a { color: #666; text-decoration: none; }')
        self.setFont(utils.get_os_monospace_font())

    def mousePressEvent(self, event):
        if not self._disasm_view:
            return

        mouse_btn = event.button()
        mouse_pos = event.pos()

        clicked_offset_link = self.anchorAt(mouse_pos)
        if clicked_offset_link:
            if clicked_offset_link.startswith('offset:'):
                if mouse_btn == Qt.LeftButton:
                    _offset = clicked_offset_link.split(':')
                    line = self._disasm_view.get_line_for_address(_offset[1])
                    self._disasm_view.verticalScrollBar().setValue(line)
                    self._disasm_view._current_line = line
                elif mouse_btn == Qt.RightButton:
                    _offset = clicked_offset_link.split(':')
                    _offset = _offset[1]
                    menu = QMenu()
                    menu.addAction('Copy Offset', lambda: utils.copy_hex_to_clipboard(_offset))
                    menu.exec_(QCursor.pos())

        return super().mousePressEvent(event)
