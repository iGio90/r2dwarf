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

from r2dwarf.src.pipe import R2Pipe


class Plugin:
    @staticmethod
    def __get_plugin_info__():
        return {
            'name': 'r2dwarf',
            'description': 'radare2 for Dwarf',
            'version': '1.0.0',
            'author': 'iGio90',
            'homepage': 'https://github.com/iGio90/r2dwarf',
            'license': 'https://www.gnu.org/licenses/gpl-3.0',
        }

    def __get_agent__(self):
        self._create_pipe()

        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agent.js'), 'r') as f:
            return f.read()

    def __init__(self):
        self._script = None

        # block the creation of pipe on fatal errors
        self.pipe_locker = False

        self.pipe = None
        self.current_seek = ''
        self.with_r2dec = False
        self._working = False

    def set_script(self, script):
        self._script = script

    def on_frida_message(self, message, payload):
        if 'payload' in message:
            payload = message['payload']
            if payload.startswith('r2 '):
                if self.pipe is None:
                    self._create_pipe()

                cmd = message['payload'][3:]
                parts = cmd.split(' ')
                cmd = parts[0]
                parts = parts[1:]

                if cmd == 'init':
                    r2arch = parts[1]
                    r2bits = 32
                    if r2arch == 'arm64':
                        r2arch = 'arm'
                        r2bits = 64
                    elif r2arch == 'x64':
                        r2arch = 'x86'
                        r2bits = 64
                    elif r2arch == 'ia32':
                        r2arch = 'x86'
                    self.pipe.cmd('e asm.arch=%s; e asm.bits=%d; e asm.os=%s; e anal.arch=%s;' % (
                        r2arch, r2bits, payload[2], r2arch))
                else:
                    try:
                        result = self.pipe.cmd(cmd + ' ' + ' '.join(parts), api=True)
                        self._script.post(
                            {"type": 'r2', "payload": result})
                    except:
                        self._script.post(
                            {"type": 'r2', "payload": None})

    def _create_pipe(self):
        if self.pipe_locker:
            return None

        self.current_seek = ''
        self.pipe = self._open_pipe()

        if self.pipe is None:
            return None

        self.pipe.cmd(
            "e anal.autoname=true; e anal.hasnext=true; e asm.anal=true; e anal.fcnprefix=sub")
        return self.pipe

    def _open_pipe(self):
        pipe = R2Pipe(self)
        pipe.onPipeBroken.connect(self._on_pipe_error)

        pipe.open()
        return pipe

    def _on_pipe_error(self, reason):
        should_recreate_pipe = True

        if 'Broken' in reason:
            should_recreate_pipe = False

        if should_recreate_pipe:
            self._create_pipe()
