import os
import sys
import time
from subprocess import *

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

    def open(self, filename='', flags=[], radare2home=None):
        if radare2home is not None:
            if not os.path.isdir(radare2home):
                raise Exception('`radare2home` passed is invalid, leave it None or put a valid path to r2 folder')
            r2e = os.path.join(radare2home, 'radare2')
        else:
            r2e = 'radare2'

        if os.name == 'nt':
            r2e += '.exe'
        cmd = [r2e, "-q0", filename]
        cmd = cmd[:1] + flags + cmd[1:]
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

    def _onScriptLoaded(self):
        time.sleep(3) # TODO: fix Cannot attach: Unable to find process with pid 5457 [r] Cannot open 'frida://attach/usb//5457'
        self.pipe.open('frida://attach/usb//%d' % self._main_app.dwarf.pid, radare2home='C:\\radare2\\bin\\')
        try:
            self.pipe.cmd(".\\i*")
        except Exception as e:
            print(e)

    def on_r2_command(self, cmd):
        result = self.pipe.cmd(cmd)

        self.console.log(result, time_prefix=False)
