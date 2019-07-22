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
import os
import shutil
import time

from PyQt5.QtCore import QObject, pyqtSignal

from lib import utils
from subprocess import *

from lib.types.range import Range
from plugins.r2dwarf.src.analysis import R2Analysis


class R2Pipe(QObject):
    onPipeBroken = pyqtSignal(str, name='onPipeBroken')
    onUpdateVars = pyqtSignal(name='onUpdateVars')

    def __init__(self, plugin, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.plugin = plugin
        self.dwarf = plugin.app.dwarf
        self.process = None
        self._working = False

        self.r2_pipe_local_path = os.path.abspath('.r2pipe_%d' % time.time())
        for path in os.listdir('.'):
            if '.r2pipe' in path:
                try:
                    shutil.rmtree(path)
                except:
                    # instance of dwarf already running
                    pass
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

        if sync:
            dwarf_range = Range.build_or_get(self.dwarf, hex_ptr)
            self.memmap(dwarf_range)
        else:
            Range.build_or_get(self.dwarf, hex_ptr, cb=self.memmap)

    def memmap(self, dwarf_range):
        map_path = os.path.join(self.r2_pipe_local_path, hex(dwarf_range.base))
        if not os.path.exists(map_path) and dwarf_range.data is not None:
            with open(map_path, 'wb') as f:
                f.write(dwarf_range.data)
            self.cmd('on %s %s %s' % (map_path, hex(dwarf_range.base), dwarf_range.permissions))

            self.plugin.app.show_progress('r2: running analysis at %s' % hex(dwarf_range.base))
            self.plugin._working = True

            self.r2analysis = R2Analysis(self, dwarf_range)
            self.r2analysis.onR2AnalysisFinished.connect(self.plugin._on_finish_analysis)
            self.r2analysis.start()
        else:
            self.plugin._on_finish_analysis([dwarf_range])

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
