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
import os
import shutil
import time

from PyQt5.QtCore import QObject, pyqtSignal, QThread

from dwarf.lib import utils
from subprocess import *

from r2dwarf.src.analysis import R2Analysis


class SimpleRangeInfo:
    def __init__(self, base, size):
        self.base = base
        self.size = size


class MemoryReader(QThread):
    onR2MemoryReaderFinish = pyqtSignal(object, bytes, int, name='onR2MemoryReaderFinish')

    def __init__(self, pipe, hex_ptr):
        super().__init__()
        self.pipe = pipe
        self.dwarf = pipe.dwarf
        self.hex_ptr = hex_ptr

    def run(self):
        self.read_memory()

    def read_memory(self):
        base, data, offset = self.dwarf.read_range(self.hex_ptr)
        info = SimpleRangeInfo(base, len(data))

        map_path = os.path.join(self.pipe.r2_pipe_local_path, hex(info.base))
        if not os.path.exists(map_path):
            with open(map_path, 'wb') as f:
                f.write(data)
            self.pipe.cmd('on %s %s %s' % (map_path, hex(info.base), 'rwx'))
        self.onR2MemoryReaderFinish.emit(info, data, offset)


class R2Pipe(QObject):
    onPipeBroken = pyqtSignal(str, name='onPipeBroken')
    onUpdateVars = pyqtSignal(name='onUpdateVars')

    def __init__(self, plugin, *args, **kwargs):
        super().__init__(*args, **kwargs)

        try:
            self.dwarf = plugin.app.dwarf
        except:
            # injector
            self.dwarf = None

        self.plugin = plugin
        self.process = None
        self._working = False

        self._cleanup()

        self.r2_pipe_local_path = os.path.abspath('.r2pipe_%d' % time.time())
        os.mkdir(self.r2_pipe_local_path)

    def _cleanup(self):
        if os.name != 'nt':
            utils.do_shell_command("pkill radare2")
        else:
            try:
                utils.do_shell_command("taskkill /IM radare2.exe /F")
                #utils.do_shell_command("tskill radare2")
            except IOError as io_error:
                if io_error.errno == 2:
                    print('error: cant execute tskill')

        for path in os.listdir('.'):
            if '.r2pipe' in path:
                try:
                    shutil.rmtree(path)
                except:
                    # instance of dwarf already running
                    pass

    def close(self):
        self._cleanup()

    def open(self):
        r2e = 'radare2'

        if os.name == 'nt':
            r2e += '.exe'
        cmd = [r2e, "-w", "-q0", '-']
        try:
            self.process = Popen(cmd, shell=False, stdin=PIPE, stdout=PIPE, stderr=PIPE, bufsize=0)
        except Exception as e:
            self.onPipeBroken.emit(str(e))
        self.process.stdout.read(1)

    def cmd(self, cmd, api=False):
        try:
            ret = self._cmd_process(cmd)

            if cmd.startswith('s') and len(cmd) > 1:
                new_seek = self._cmd_process('s')
                self.plugin.current_seek = new_seek
                self.map_ptr(new_seek, sync=api)
            elif cmd.startswith('e '):
                self.onUpdateVars.emit()
            return ret
        except Exception as e:
            print('r2pipe broken: %s' % str(e))
            self._working = False
            self.onPipeBroken.emit(str(e))
        return None

    def cmdj(self, cmd):
        self.cmd('e scr.html=0')
        ret = self.cmd(cmd)
        self.cmd('e scr.html=1')
        try:
            return ret
        except:
            return None

    def map_ptr(self, hex_ptr, sync=False):
        self.plugin._working = True

        if self.dwarf is not None:
            self.mem_reader = MemoryReader(self, hex_ptr)
            self.mem_reader.onR2MemoryReaderFinish.connect(self.memmap)
            if sync:
                self.mem_reader.read_memory()
            else:
                self.mem_reader.start()
        else:
            _range = self.plugin._script.exports.api(0, 'getRange', [hex_ptr])
            print(_range)

    def memmap(self, info, data, offset):
        if info is None or data is None:
            self.plugin._on_finish_analysis([info.base, data, offset])
        else:
            self.plugin.app.show_progress('r2: running analysis at %s' % hex(info.base))
            self.plugin._working = True

            self.r2analysis = R2Analysis(self, info, data, offset)
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
