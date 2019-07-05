import r2pipe

from ui.widget_console import DwarfConsoleWidget


class R2Dwarf:
    def __init__(self, dwarf, pid):
        self.dwarf = dwarf
        self.pipe = r2pipe.open("frida://attach/usb//%d" % pid)
        self.console = DwarfConsoleWidget(dwarf._app_window, input_placeholder='r2', completer=False)
        self.console.onCommandExecute.connect(self.on_r2_command)
        self.dwarf._app_window.console.qtabs.addTab(self.console, 'r2')

    def on_r2_command(self, cmd):
        self.console.log(self.pipe.cmd(cmd), time_prefix=False)


r2 = None


def init(dwarf):
    pass


def on_target_attached(dwarf, pid):
    global r2

    r2 = R2Dwarf(dwarf, pid)
