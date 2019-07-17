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
