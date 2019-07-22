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
from PyQt5.QtCore import Qt, QSize
from PyQt5.QtWidgets import QScrollArea, QSizePolicy, QFrame, QScroller, QLabel


class R2ScrollArea(QScrollArea):
    def __init__(self, *__args):
        super().__init__(*__args)

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setFrameStyle(QFrame.NoFrame)
        self.setFrameShadow(QFrame.Plain)
        self.viewport().setAttribute(Qt.WA_AcceptTouchEvents)
        QScroller.grabGesture(self.viewport(), QScroller.LeftMouseButtonGesture)
        self.setWidgetResizable(True)

        self.label = QLabel()
        self.label.setTextFormat(Qt.RichText)
        self.label.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)

        self.setWidget(self.label)

    def clearText(self):
        self.label.clear()

    def setText(self, text):
        self.label.setText(text)

    def sizeHint(self):
        return QSize(200, 200)
