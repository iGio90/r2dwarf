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
        if self._with_r2dec:
            decompile_data = self._pipe.cmd('pddo')
        else:
            decompile_data = self._pipe.cmd('pdc')
        self.onR2Decompiler.emit([decompile_data])


class R2DecompiledText(QPlainTextEdit):
    def __init__(self, parent=None):
        super().__init__(parent=parent)

    def mousePressEvent(self, event):
        mouse_btn = event.button()
        mouse_pos = event.pos()

        clicked_offset_link = self.anchorAt(mouse_pos)
        if clicked_offset_link:
            if clicked_offset_link.startswith('offset:'):
                if mouse_btn == Qt.LeftButton:
                    _offset = clicked_offset_link.split(':')
                    self.doStuff(_offset[1])
                elif mouse_btn == Qt.RightButton:
                    _offset = clicked_offset_link.split(':')
                    _offset = _offset[1]
                    menu = QMenu()
                    menu.addAction('Copy Offset', lambda: utils.copy_hex_to_clipboard(_offset))
                    menu.exec_(QCursor.pos())

        return super().mousePressEvent(event)