from PyQt5.QtCore import pyqtSignal, QThread


class R2Graph(QThread):
    onR2Graph = pyqtSignal(list, name='onR2Graph')

    def __init__(self, pipe):
        super(R2Graph, self).__init__()
        self._pipe = pipe

    def run(self):
        function_prologue = int(self._pipe.cmd('?v $F'), 16)
        function = None

        if self._dwarf_range.module_info is not None:
            if function_prologue in self._dwarf_range.module_info.functions_map:
                function = self._dwarf_range.module_info.functions_map[function_prologue]
                try:
                    graph = function.r2_graph
                    if graph:
                        self.onR2Graph.emit([graph])
                        return
                except:
                    pass

        graph = self._pipe.cmd('agf')
        if function is not None:
            function.r2_graph = graph
        self.onR2Graph.emit([graph])
