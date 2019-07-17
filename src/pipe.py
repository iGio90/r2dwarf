import json
import os
import shutil
import time

from PyQt5.QtCore import QObject, pyqtSignal, QThread

from lib import utils
from subprocess import *

from lib.range import Range
from plugins.r2.src.analysis import R2Analysis


class R2AsyncGetRange(QThread):
    onRangeParsed = pyqtSignal(list, name="onRangeParsed")

    def __init__(self, dwarf, ptr):
        super().__init__()

        self.dwarf = dwarf
        self.ptr = ptr

    def run(self):
        r = Range(Range.SOURCE_TARGET, self.dwarf)
        r.init_with_address(self.ptr, require_data=True)
        self.onRangeParsed.emit([r])


class R2Pipe(QObject):
    onPipeBroken = pyqtSignal(str, name='onPipeBroken')

    def __init__(self, plugin, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.plugin = plugin
        self.dwarf = plugin.app.dwarf
        self.process = None
        self._working = False

        self.r2_pipe_local_path = os.path.abspath('.r2pipe')
        if os.path.exists(self.r2_pipe_local_path):
            shutil.rmtree(self.r2_pipe_local_path)
        os.mkdir(self.r2_pipe_local_path)

        self.close()

    def close(self):
        if os.name != 'nt':
            utils.do_shell_command("pkill radare2")
        else:
            utils.do_shell_command("tskill radare2")

    def open(self):
        r2e = 'radare2'

        if os.name == 'nt':
            r2e += '.exe'
        cmd = [r2e, "-w", "-q0", '-']
        try:
            self.process = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, bufsize=0)
        except Exception as e:
            self.onPipeBroken.emit(str(e))
        self.process.stdout.read(1)

    def cmd(self, cmd):
        try:
            ret = self._cmd_process(cmd)

            if cmd.startswith('s '):
                ptr = utils.parse_ptr(cmd[2:])
                self.plugin.current_seek = hex(ptr)
                self.map_ptr(self.plugin.current_seek)
            return ret
        except Exception as e:
            self._working = False
            self.onPipeBroken.emit(str(e))
        return None

    def cmdj(self, cmd):
        ret = self.cmd(cmd)
        try:
            return json.loads(ret)
        except:
            return {}

    def map_ptr(self, hex_ptr):
        address_info = self._cmd_process('ai')

        if len(address_info) == 0:
            self.plugin.console.log('mapping range at %s' % hex_ptr)

            self.plugin.app.show_progress('r2: reading at %s' % hex_ptr)
            self.plugin._working = True

            self.async_get_range = R2AsyncGetRange(self.dwarf, int(hex_ptr, 16))
            self.async_get_range.onRangeParsed.connect(lambda x: self.map(x[0]))
            self.async_get_range.start()

    def map(self, dwarf_range):
        map_path = os.path.join(self.r2_pipe_local_path, hex(dwarf_range.base))
        if not os.path.exists(map_path):
            with open(map_path, 'wb') as f:
                f.write(dwarf_range.data)
            self.cmd('on %s %s %s' % (map_path, hex(dwarf_range.base), dwarf_range.permissions))

            self.plugin.app.show_progress('r2: running analysis at %s' % hex(dwarf_range.base))
            self.plugin._working = True

            self.r2analysis = R2Analysis(self, dwarf_range)
            self.r2analysis.onR2AnalysisFinished.connect(self.plugin._on_finish_analysis)
            self.r2analysis.start()

    def _cmd_process(self, cmd):
        if not self.process:
            return

        while self._working:
            time.sleep(.1)

        self._working = True

        cmd = cmd.strip().replace("\n", ";")
        self.process.stdin.write((cmd + '\n').encode('utf8'))
        self.process.stdin.flush()

        output = b''
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
                time.sleep(0.001)

        self._working = False
        output = output.decode('utf-8', errors='ignore')
        if output.endswith('\n'):
            output = output[:-1]
        return output
