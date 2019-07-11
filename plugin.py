import os
import time
from subprocess import *
from threading import Thread

from lib.dwarf_plugin import DwarfPlugin
from ui.widget_console import DwarfConsoleWidget

from lib import utils

from PyQt5.QtCore import QObject


class R2Pipe(QObject):

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.process = None

        if os.name != 'nt':
            utils.do_shell_command("pkill radare2")
        else:
            utils.do_shell_command("tskill radare2")

    def open(self, filename=''):
        r2e = 'radare2'

        if os.name == 'nt':
            r2e += '.exe'
        cmd = [r2e, "-q0", filename]
        try:
            self.process = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, bufsize=0)
        except Exception as e:
            print(e)
        self.process.stdout.read(1)

    def cmd(self, cmd):
        return self._cmd_process(cmd)

    def _cmd_process(self, cmd):
        if not self.process:
            print('error')
            return
        cmd = cmd.strip().replace("\n", ";")
        self.process.stdin.write((cmd + '\n').encode('utf8'))
        stdout = self.process.stdout
        nonblocking = True
        self.process.stdin.flush()
        output = b''
        wait_max = 1000
        while True:
            if nonblocking:
                try:
                    result = stdout.read(4096)
                except:
                    continue
            else:
                result = stdout.read(1)
            if result:
                if result.endswith(b'\0'):
                    output += result[:-1]
                    break

                output += result
            else:
                if nonblocking:
                    wait_max -= 1
                    time.sleep(0.001)
                    if not wait_max:
                        break

        return output.decode('utf-8', errors='ignore')


class R2DwarfPlugin(DwarfPlugin):

    def __init__(self, app):
        self._main_app = app
        self.pipe = R2Pipe()
        #! required
        # plugininfo
        self.name = 'r2dwarf'
        self.description = 'r2frida in Dwarf'
        self.version = '1.0.0'
        self.author = 'iGio'
        self.homepage = 'https://github.com/iGio90/Dwarf'
        self.license = 'https://www.gnu.org/licenses/gpl-3.0'
        #
        self.supported_sessions = ['android', 'local', 'remote']
        self.supported_arch = ['ia32', 'x64', 'arm', 'arm64']
        self.supported_platforms = ['windows', 'darwin', 'linux']
        #! end required

    def on_session_started(self, app): # TODO: remove app from there
        """ This function gets executed when Session is started
        """
        self.console = DwarfConsoleWidget(self._main_app, input_placeholder='r2', completer=False)
        self.console.onCommandExecute.connect(self.on_r2_command)
        self._main_app.main_tabs.addTab(self.console, 'r2')
        self._main_app.dwarf.onScriptLoaded.connect(self._onScriptLoaded)

    def start_async(self):
        def init_cmds():
            self.pipe.cmd(".\\i*")
        Thread(target=init_cmds).start()

    def _onScriptLoaded(self):
        self.pipe.open('frida://attach/usb//%d' % self._main_app.dwarf.pid)

    def on_r2_command(self, cmd):
        result = self.pipe.cmd(cmd)

        self.console.log(result, time_prefix=False)
