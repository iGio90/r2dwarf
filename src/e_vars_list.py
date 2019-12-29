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
import json

from PyQt5.QtCore import QThread, pyqtSignal, Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem

from dwarf_debugger.ui.dialogs.dialog_input import InputDialog
from dwarf_debugger.ui.widgets.list_view import DwarfListView


class RefreshVars(QThread):
    onFinishVarsRefresh = pyqtSignal(list, name='onFinishVarsRefresh')

    def __init__(self, plugin):
        super().__init__()
        self.plugin = plugin

    def run(self):
        e_vars = self.plugin.pipe._cmd_process('ej')
        self.onFinishVarsRefresh.emit([e_vars])


class EVarsList(DwarfListView):
    def __init__(self, plugin):
        super().__init__()

        self.plugin = plugin

        self.e_vars_refresher = RefreshVars(self.plugin)
        self.e_vars_refresher.onFinishVarsRefresh.connect(self.on_vars_refresh)

        self.e_list_model = QStandardItemModel(0, 2)
        self.e_list_model.setHeaderData(0, Qt.Horizontal, 'e vars')
        self.e_list_model.setHeaderData(1, Qt.Horizontal, '')
        self.setModel(self.e_list_model)

        self.doubleClicked.connect(self._item_double_clicked)

    def _item_double_clicked(self, model_index):
        row = self.e_list_model.itemFromIndex(model_index).row()
        item = self.e_list_model.item(row, 0).text()
        item_val = self.e_list_model.item(row, 1).text()
        accept, res = InputDialog.input(parent=self.plugin.app, hint=item, input_content=item_val, placeholder=item_val)
        if (accept and res) and self.plugin.pipe is not None:
            self.plugin.pipe.cmd('e %s = %s' % (item, res))

    def refresh_e_vars_list(self):
        if self.plugin.pipe is not None:
            self.clear()

            if not self.e_vars_refresher.isRunning():
                self.e_vars_refresher.start()

    def on_vars_refresh(self, data):
        import json
        e_vars = json.loads(data[0])
        for key in e_vars:
            var_name = QStandardItem(key)
            var_value = QStandardItem(str(e_vars[key]))
            var_value.setEditable(True)

            self.e_list_model.appendRow([var_name, var_value])
