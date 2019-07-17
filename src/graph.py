from PyQt5.QtCore import pyqtSignal, QThread


class R2Graph(QThread):
    onR2Graph = pyqtSignal(list, name='onR2Graph')

    def __init__(self, pipe):
        super(R2Graph, self).__init__()
        self._pipe = pipe

    def run(self):
        graph = self._pipe.cmd('agf')
        self.onR2Graph.emit([graph])
