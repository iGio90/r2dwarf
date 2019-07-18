from PyQt5.QtCore import QThread, pyqtSignal


class R2Analysis(QThread):
    onR2AnalysisFinished = pyqtSignal(list, name='onR2AnalysisFinished')

    def __init__(self, pipe, dwarf_range):
        super(R2Analysis, self).__init__()
        self._pipe = pipe
        self._dwarf_range = dwarf_range

    def run(self):
        self._pipe.cmd('e anal.from = %d; e anal.to = %d; e anal.in = raw' % (
            self._dwarf_range.base, self._dwarf_range.tail))
        self._pipe.cmd('aa')
        self._pipe.cmd('aac')
        self._pipe.cmd('aar')
        self._pipe.cmd('afr')

        functions = self._pipe.cmdj('aflj')

        self.onR2AnalysisFinished.emit([self._dwarf_range, functions])
