from PyQt5.QtCore import Qt
from PyQt5.QtWidgets import QDialog, QVBoxLayout, QLabel, QCheckBox, QHBoxLayout, QPushButton


#########
# PREFS #
#########
KEY_WIDESCREEN_MODE = 'r2_widescreen'


class OptionsDialog(QDialog):
    def __init__(self, prefs, parent=None):
        super(OptionsDialog, self).__init__(parent)
        self._prefs = prefs

        self.setMinimumWidth(500)
        self.setContentsMargins(5, 5, 5, 5)

        layout = QVBoxLayout(self)
        options = QVBoxLayout()
        options.setContentsMargins(0, 0, 0, 20)

        options.addWidget(QLabel('UI'))

        self.widescreen_mode = QCheckBox('widescreen mode')
        self.widescreen_mode.setCheckState(Qt.Checked if self._prefs.get(
            KEY_WIDESCREEN_MODE, False) else Qt.Unchecked)
        options.addWidget(self.widescreen_mode)

        buttons = QHBoxLayout()
        cancel = QPushButton('cancel')
        cancel.clicked.connect(self.close)
        buttons.addWidget(cancel)
        accept = QPushButton('accept')
        accept.clicked.connect(self.accept)
        buttons.addWidget(accept)

        layout.addLayout(options)
        layout.addLayout(buttons)

    @staticmethod
    def show_dialog(prefs):
        dialog = OptionsDialog(prefs)
        result = dialog.exec_()

        if result == QDialog.Accepted:
            try:
                dialog._prefs.put(
                    KEY_WIDESCREEN_MODE, True if dialog.widescreen_mode.checkState() == Qt.Checked else False
                )
            except:
                pass
