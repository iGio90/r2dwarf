from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem

from ui.widgets.list_view import DwarfListView


class RefreshVars(QThread):
    onFinishVarsRefresh = pyqtSignal(list, name='onFinishVarsRefresh')

    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def run(self):
        e_vars = self.plugin.pipe.cmdj('ej')
        self.onFinishVarsRefresh.emit([e_vars])


class EVarsList(DwarfListView):
    def __init__(self, plugin):
        super().__init__()

        self.plugin = plugin

        self.e_list_model = QStandardItemModel(0, 2)
        self.e_list_model.setHeaderData(0, Qt.Horizontal, 'e vars')
        self.e_list_model.setHeaderData(1, Qt.Horizontal, '')
        self.setModel(self.e_list_model)

    def refresh_e_vars_list(self):
        if self.plugin.pipe is not None:
            self.e_list_model.setRowCount(0)

            self.e_vars_refresher = RefreshVars(self.plugin)
            self.e_vars_refresher.onFinishVarsRefresh.connect(self.on_vars_refresh)
            self.e_vars_refresher.start()

    def on_vars_refresh(self, data):
        e_vars = data[0]
        for key in e_vars:
            var_name = QStandardItem(key)
            var_value = QStandardItem(str(e_vars[key]))
            var_value.setEditable(True)

            self.e_list_model.appendRow([var_name, var_value])
