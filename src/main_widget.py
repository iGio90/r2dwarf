from PyQt5.QtWidgets import QSplitter

from plugins.r2.src.e_vars_list import EVarsList
from ui.widget_console import DwarfConsoleWidget


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
