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
from PyQt5.QtWidgets import QSplitter

from plugins.r2dwarf.src.e_vars_list import EVarsList
from ui.widgets.widget_console import DwarfConsoleWidget


class R2Widget(QSplitter):
    def __init__(self, plugin, *__args):
        super().__init__(*__args)

        self.plugin = plugin
        self.app = plugin.app

        self.console = DwarfConsoleWidget(self.app, input_placeholder='r2', completer=False)
        self.console.onCommandExecute.connect(self.on_r2_command)

        self.e_list = EVarsList(self.plugin)

        self.addWidget(self.console)
        self.addWidget(self.e_list)

        self.setStretchFactor(0, 4)
        self.setStretchFactor(1, 1)

        self.refresh_e_vars_list()

    def refresh_e_vars_list(self):
        self.e_list.refresh_e_vars_list()

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
