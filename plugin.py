import os
import time
from subprocess import *

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
        self.process.stdin.flush()

        output = b''
        wait_max = 1000
        while True:
            try:
                result = self.process.stdout.read(4096)
            except:
                continue
            if result:
                if result.endswith(b'\0'):
                    output += result[:-1]
                    break

                output += result
            else:
                wait_max -= 1
                time.sleep(0.001)
                if not wait_max:
                    break

        return output.decode('utf-8', errors='ignore')


class Plugin:
    def __get_plugin_info__(self):
        return {
            'name': 'r2dwarf',
            'description':  'r2frida in Dwarf',
            'version': '1.0.0',
            'author': 'iGio90',
            'homepage': 'https://github.com/iGio90/Dwarf',
            'license': 'https://www.gnu.org/licenses/gpl-3.0'
        }

    def __init__(self, app):
        self.app = app
        self.pipe = R2Pipe()

        self.app.session_manager.sessionCreated.connect(self._on_session_created)

    def _on_session_created(self):
        self.app.dwarf.onScriptLoaded.connect(self._on_script_loaded)
        self.app.dwarf.onReceiveCmd.connect(self._on_receive_cmd)
        self.app.dwarf.onApplyContext.connect(self._on_apply_context)

        self.console = DwarfConsoleWidget(self.app, input_placeholder='r2', completer=False)
        self.console.onCommandExecute.connect(self.on_r2_command)
        self.app.main_tabs.addTab(self.console, 'r2')

    def _on_receive_cmd(self, args):
        message, data = args
        if 'payload' in message:
            payload = message['payload']
            if payload.startswith('r2 '):
                cmd = message['payload'][3:]
                self.on_r2_command(cmd)

    def _on_script_loaded(self):
        self.pipe.open('frida://attach/usb//%d' % self.app.dwarf.pid)
        self.pipe.cmd("e scr.color=2; e scr.html=1;")

        r2arch = self.app.dwarf.arch
        if r2arch == 'arm64':
            r2arch = 'arm'

        self.pipe.cmd('e asm.arch=%s; e asm.bits=%d; e asm.os=%s' % (
            r2arch, self.app.dwarf.pointer_size * 8, self.app.dwarf.platform))

        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agent.js'), 'r') as f:
            agent = f.read()
        self.app.dwarf.dwarf_api('evaluate', agent)

    def _on_apply_context(self, context_data):
        is_java = 'is_java' in context_data and context_data['is_java']

        if not is_java:
            if 'context' in context_data:
                native_context = context_data['context']
                pc = native_context['pc']['value']

                self.pipe.cmd('s %s' % pc)

    def on_r2_command(self, cmd):
        result = self.pipe.cmd(cmd)
        self.console.log(result, time_prefix=False)
