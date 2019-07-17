from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QSplitter

from ui.widget_console import DwarfConsoleWidget
from ui.widgets.list_view import DwarfListView


class R2Widget(QSplitter):
    def __init__(self, plugin, *__args):
        super().__init__(*__args)

        self.plugin = plugin
        self.app = plugin.app

        self.console = DwarfConsoleWidget(self.app, input_placeholder='r2', completer=False)
        self.console.onCommandExecute.connect(self.on_r2_command)

        e_list = DwarfListView()
        self.e_list_model = QStandardItemModel(0, 2)
        self.e_list_model.setHeaderData(0, Qt.Horizontal, 'e vars')
        self.e_list_model.setHeaderData(1, Qt.Horizontal, '')
        e_list.setModel(self.e_list_model)

        self.addWidget(self.console)
        self.addWidget(e_list)

        self.setStretchFactor(0, 4)
        self.setStretchFactor(1, 1)

        self.refresh_e_vars_list()

    def refresh_e_vars_list(self):
        if self.plugin.pipe is not None:
            self.e_list_model.setRowCount(0)
            e_vars = self.plugin.pipe.cmdj('ej')
            for key in e_vars:
                var_name = QStandardItem(key)
                var_value = QStandardItem(str(e_vars[key]))
                var_value.setEditable(True)

                self.e_list_model.appendRow([var_name, var_value])

    def on_r2_command(self, cmd):
        if self.plugin.pipe is None:
            self.plugin._create_pipe()

        if cmd == 'clear' or cmd == 'clean':
            self.console.clear()
        else:
            if self.plugin._working:
                self.console.log('please wait for other works to finish', time_prefix=False)
            else:
                try:
                    result = self.plugin.pipe.cmd(cmd)
                    self.console.log(result, time_prefix=False)
                except BrokenPipeError:
                    self.console.log('pipe is broken. recreating...', time_prefix=False)
                    self.plugin._create_pipe()
                    self.plugin.pipe.cmd('s %s' % self.current_seek)
