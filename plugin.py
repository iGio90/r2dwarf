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
import time
from subprocess import *

from PyQt5.QtCore import QObject, QThread, pyqtSignal, Qt, QSize
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QSizePolicy, QSplitter, QScrollArea, QScroller, QFrame, QLabel, QPlainTextEdit, \
    QScrollBar, QAction, QDialog, QVBoxLayout, QHBoxLayout, QPushButton, QCheckBox

from lib import utils
from lib.prefs import Prefs
from ui.widget_console import DwarfConsoleWidget
from ui.widgets.list_view import DwarfListView


#########
# PREFS #
#########
KEY_WIDESCREEN_MODE = 'r2_widescreen'


###########
# WIDGETS #
###########
class R2ScrollArea(QScrollArea):
    def __init__(self, *__args):
        super().__init__(*__args)

        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setFrameStyle(QFrame.NoFrame)
        self.setFrameShadow(QFrame.Plain)
        self.viewport().setAttribute(Qt.WA_AcceptTouchEvents)
        QScroller.grabGesture(self.viewport(), QScroller.LeftMouseButtonGesture)
        self.setWidgetResizable(True)

        self.label = QLabel()
        self.label.setTextFormat(Qt.RichText)
        self.label.setSizePolicy(QSizePolicy.Minimum, QSizePolicy.Minimum)

        self.setWidget(self.label)

    def clearText(self):
        self.label.clear()

    def setText(self, text):
        self.label.setText(text)

    def sizeHint(self):
        return QSize(200, 200)


class OptionsDialog(QDialog):
    def __init__(self, parent=None):
        super(OptionsDialog, self).__init__(parent)
        self._prefs = Prefs()

        self.setMinimumWidth(500)
        self.setContentsMargins(5, 5, 5, 5)

        layout = QVBoxLayout(self)
        options = QVBoxLayout()
        options.setContentsMargins(0, 0, 0, 20)

        options.addWidget(QLabel('UI'))

        self.widescreen_mode = QCheckBox('widescreen mode')
        self.widescreen_mode.setCheckState(Qt.Checked if self._prefs.get(
            KEY_WIDESCREEN_MODE, False) else Qt.Unchecked)
        options.addWidget(self.widescreen_mode)

        buttons = QHBoxLayout()
        cancel = QPushButton('cancel')
        cancel.clicked.connect(self.close)
        buttons.addWidget(cancel)
        accept = QPushButton('accept')
        accept.clicked.connect(self.accept)
        buttons.addWidget(accept)

        layout.addLayout(options)
        layout.addLayout(buttons)

    @staticmethod
    def show_dialog():
        dialog = OptionsDialog()
        result = dialog.exec_()

        if result == QDialog.Accepted:
            try:
                dialog._prefs.put(
                    KEY_WIDESCREEN_MODE, True if dialog.widescreen_mode.checkState() == Qt.Checked else False
                )
            except:
                pass


################
# CORE CLASSES #
################
class R2Database:
    def __init__(self):
        self.functions_analysis = {}
        self.graphs = {}
        self.decompilations = {}

    def get_decompilation(self, address):
        if isinstance(address, int):
            address = hex(address)
        if address in self.decompilations:
            return self.decompilations[address]
        return None

    def get_function_info(self, address):
        if isinstance(address, int):
            address = hex(address)
        if address in self.functions_analysis:
            return self.functions_analysis[address]
        return None

    def get_graph(self, address):
        if isinstance(address, int):
            address = hex(address)
        if address in self.graphs:
            return self.graphs[address]
        return None

    def put_decompilation(self, address, decompilitaiton):
        if isinstance(address, int):
            address = hex(address)
        self.decompilations[address] = decompilitaiton

    def put_function_info(self, address, info):
        if isinstance(address, int):
            address = hex(address)
        self.functions_analysis[address] = info

    def put_graph(self, address, graph):
        if isinstance(address, int):
            address = hex(address)
        self.graphs[address] = graph


class R2Analysis(QThread):
    onR2AnalysisFinished = pyqtSignal(list, name='onR2AnalysisFinished')

    def __init__(self, pipe, dwarf_range):
        super(R2Analysis, self).__init__()
        self._pipe = pipe
        self._dwarf_range = dwarf_range

    def run(self):
        function_prologue = int(self._pipe.cmd('?v $F'), 16)
        if function_prologue > 0:
            function_info = self._pipe.r2_database.get_function_info(function_prologue)
            if function_info is not None:
                self.onR2AnalysisFinished.emit([self._dwarf_range, function_info])
                return

        self._pipe.cmd('af')
        function_info = self._pipe.cmdj('afij')
        if len(function_info) > 0:
            function_info = function_info[0]
            self._pipe.r2_database.put_function_info(function_prologue, function_info)

        self.onR2AnalysisFinished.emit([self._dwarf_range, function_info])


class R2Graph(QThread):
    onR2Graph = pyqtSignal(list, name='onR2Graph')

    def __init__(self, pipe):
        super(R2Graph, self).__init__()
        self._pipe = pipe

    def run(self):
        function_prologue = int(self._pipe.cmd('?v $F'), 16)
        if function_prologue > 0:
            graph = self._pipe.r2_database.get_graph(function_prologue)
            if graph is not None:
                self.onR2Graph.emit([graph])
                return

        graph = self._pipe.cmd('agf')
        self._pipe.r2_database.put_graph(function_prologue, graph)
        self.onR2Graph.emit([graph])


class R2Decompiler(QThread):
    onR2Decompiler = pyqtSignal(list, name='onR2Decompiler')

    def __init__(self, pipe, with_r2dec):
        super(R2Decompiler, self).__init__()
        self._pipe = pipe
        self._with_r2dec = with_r2dec

    def run(self):
        function_prologue = int(self._pipe.cmd('?v $F'), 16)
        if function_prologue > 0:
            decompile_data = self._pipe.r2_database.get_decompilation(function_prologue)
            if decompile_data is not None:
                self.onR2Decompiler.emit([decompile_data])
                return

        if self._with_r2dec:
            decompile_data = self._pipe.cmd('pddo')
        else:
            decompile_data = self._pipe.cmd('pdc')

        # todo: wait for proper fix
        decompile_data = decompile_data.replace('#000', '#fff')

        self._pipe.r2_database.put_decompilation(function_prologue, decompile_data)
        self.onR2Decompiler.emit([decompile_data])


class R2Pipe(QObject):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.r2_database = R2Database()
        self.process = None
        self._working = False

        self.close()

    def close(self):
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
            print(e) # TODO: handle the stuff (unable to attach)
        self.process.stdout.read(1)

    def cmd(self, cmd):
        return self._cmd_process(cmd)

    def cmdj(self, cmd):
        ret = self._cmd_process(cmd)
        try:
            return json.loads(ret)
        except:
            return {}

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


class Plugin:
    # TODO: check the if not pipe createpipe when it fails why retrying on every disasm/apply_ctx

    def __get_plugin_info__(self):
        return {
            'name': 'r2dwarf',
            'description': 'r2frida in Dwarf',
            'version': '1.0.0',
            'author': 'iGio90',
            'homepage': 'https://github.com/iGio90/Dwarf',
            'license': 'https://www.gnu.org/licenses/gpl-3.0',
        }

    def __get_top_menu_actions__(self):
        if len(self.menu_items) > 0:
            return self.menu_items

        options = QAction('Options')
        options.triggered.connect(OptionsDialog.show_dialog)

        self.menu_items.append(options)
        return self.menu_items

    def __init__(self, app):
        self.app = app

        self._prefs = Prefs()
        self.pipe = None
        self.current_seek = ''
        self.with_r2dec = False
        self._working = False

        self.menu_items = []

        self.app.session_manager.sessionCreated.connect(self._on_session_created)
        self.app.session_manager.sessionStopped.connect(self._on_session_stopped)
        self.app.onUIElementCreated.connect(self._on_ui_element_created)

    def _create_pipe(self):
        device = self.app.dwarf.device

        self.pipe = R2Pipe()
        if device.type == 'usb':
            self.pipe.open('frida://attach/usb//%d' % self.app.dwarf.pid)
        elif device.type == 'local':
            self.pipe.open('frida://%d' % self.app.dwarf.pid)
        else:
            raise Exception('unsupported device type %s' % device.type)

        r2_decompilers = self.pipe.cmd('e cmd.pdc=?')
        r2_decompilers = r2_decompilers.split()
        if r2_decompilers and 'pdd' in r2_decompilers:
            self.with_r2dec = True
        self.pipe.cmd("e scr.color=2; e scr.html=1; e scr.utf8=true;")

        r2arch = self.app.dwarf.arch
        r2bits = 32
        if r2arch == 'arm64':
            r2arch = 'arm'
            r2bits = 64
        elif r2arch == 'x64':
            r2arch = 'x86'
            r2bits = 64
        elif r2arch == 'ia32':
            r2arch = 'x86'

        self.pipe.cmd('e asm.arch=%s; e asm.bits=%d; e asm.os=%s' % (
            r2arch, r2bits, self.app.dwarf.platform))

        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agent.js'), 'r') as f:
            agent = f.read()
        self.app.dwarf.dwarf_api('evaluate', agent)

    def _on_apply_context(self, context_data):
        if self.pipe is None:
            self._create_pipe()

        is_java = 'is_java' in context_data and context_data['is_java']

        if not is_java:
            if 'context' in context_data:
                native_context = context_data['context']
                pc = native_context['pc']['value']
                if self.current_seek != pc:
                    self.current_seek = pc
                    self.pipe.cmd('s %s' % self.current_seek)

    def _on_disassemble(self, dwarf_range):
        if self.pipe is None:
            self._create_pipe()

        if self.disassembly_view.decompilation_view is not None:
            self.disassembly_view.decompilation_view.setParent(None)
            self.disassembly_view.decompilation_view = None
        if self.disassembly_view.graph_view is not None:
            self.disassembly_view.graph_view.setParent(None)
            self.disassembly_view.graph_view = None

        start_address = hex(dwarf_range.start_address)
        if self.current_seek != start_address:
            self.current_seek = start_address
            self.pipe.cmd('s %s' % self.current_seek)

        self.app.show_progress('r2: analyzing function')
        self._working = True

        self.r2analysis = R2Analysis(self.pipe, dwarf_range)
        self.r2analysis.onR2AnalysisFinished.connect(self._on_finish_analysis)
        self.r2analysis.start()

    def _on_finish_analysis(self, data):
        self.app.hide_progress()
        self._working = False

        dwarf_range = data[0]
        function_info = data[1]

        num_instructions = 0
        if 'offset' in function_info:
            dwarf_range.start_offset = function_info['offset'] - dwarf_range.base
            num_instructions = int(self.pipe.cmd('pi~?'))
        self.disassembly_view.disasm_view.start_disassemble(dwarf_range, num_instructions=num_instructions)

        if 'callrefs' in function_info:
            for ref in function_info['callrefs']:
                self.call_refs_model.appendRow([
                    QStandardItem(hex(ref['addr'])),
                    QStandardItem(hex(ref['at'])),
                    QStandardItem(ref['type'])
                ])
        if 'codexrefs' in function_info:
            for ref in function_info['codexrefs']:
                self.code_xrefs_model.appendRow([
                    QStandardItem(hex(ref['addr'])),
                    QStandardItem(hex(ref['at'])),
                    QStandardItem(ref['type'])
                ])

    def _on_finish_graph(self, data):
        self.app.hide_progress()
        self._working = False

        graph_data = data[0]

        if self._prefs.get(KEY_WIDESCREEN_MODE, False):
            if self.disassembly_view.graph_view is None:
                self.disassembly_view.graph_view = R2ScrollArea()
                self.disassembly_view.addWidget(self.disassembly_view.graph_view)
            self.disassembly_view.graph_view.setText('<pre>' + graph_data + '</pre>')
        else:
            r2_graph_view = R2ScrollArea()
            r2_graph_view.setText('<pre>' + graph_data + '</pre>')

            self.app.main_tabs.addTab(r2_graph_view, 'graph view')
            index = self.app.main_tabs.indexOf(r2_graph_view)
            self.app.main_tabs.setCurrentIndex(index)

    def _on_finish_decompiler(self, data):
        self.app.hide_progress()
        self._working = False

        decompile_data = data[0]

        if self._prefs.get(KEY_WIDESCREEN_MODE, False):
            if self.disassembly_view.decompilation_view is None:
                self.disassembly_view.decompilation_view = R2ScrollArea()
            r2_decompiler_view = self.disassembly_view.decompilation_view
            self.disassembly_view.addWidget(self.disassembly_view.decompilation_view)
        else:
            r2_decompiler_view = QPlainTextEdit()
            r2_decompiler_view.setVerticalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            r2_decompiler_view.setHorizontalScrollBarPolicy(Qt.ScrollBarAsNeeded)
            self.app.main_tabs.addTab(r2_decompiler_view, 'decompiler')
            index = self.app.main_tabs.indexOf(r2_decompiler_view)
            self.app.main_tabs.setCurrentIndex(index)

        if decompile_data is not None:
            r2_decompiler_view.setText(
                '<pre>' + decompile_data + '</pre>')

    def _on_hook_menu(self, menu, address):
        menu.addSeparator()
        r2_menu = menu.addMenu('r2')

        graph = r2_menu.addAction('graph view', self.show_graph_view)
        decompile = r2_menu.addAction('decompile', self.show_decompiler_view)
        if address == -1:
            graph.setEnabled(False)
            decompile.setEnabled(False)

    def _on_receive_cmd(self, args):
        message, data = args
        if 'payload' in message:
            payload = message['payload']
            if payload.startswith('r2 '):
                cmd = message['payload'][3:]
                self.on_r2_command(cmd)

    def _on_session_created(self):
        self.app.dwarf.onReceiveCmd.connect(self._on_receive_cmd)
        self.app.dwarf.onApplyContext.connect(self._on_apply_context)

        self.console = DwarfConsoleWidget(self.app, input_placeholder='r2', completer=False)
        self.console.onCommandExecute.connect(self.on_r2_command)

        self.app.main_tabs.addTab(self.console, 'r2')

    def _on_session_stopped(self):
        # TODO: cleanup the stuff
        if self.pipe:
            self.pipe.close()

    def _on_ui_element_created(self, elem, widget):
        if elem == 'disassembly':
            self.disassembly_view = widget
            self.disassembly_view.graph_view = None
            self.disassembly_view.decompilation_view = None

            self.disassembly_view.disasm_view.run_default_disassembler = False
            self.disassembly_view.disasm_view.onDisassemble.connect(self._on_disassemble)

            r2_info = QSplitter()
            r2_info.setOrientation(Qt.Vertical)

            call_refs = DwarfListView()
            self.call_refs_model = QStandardItemModel(0, 3)
            self.call_refs_model.setHeaderData(0, Qt.Horizontal, 'call refs')
            self.call_refs_model.setHeaderData(1, Qt.Horizontal, '')
            self.call_refs_model.setHeaderData(2, Qt.Horizontal, '')
            call_refs.setModel(self.call_refs_model)

            code_xrefs = DwarfListView()
            self.code_xrefs_model = QStandardItemModel(0, 3)
            self.code_xrefs_model.setHeaderData(0, Qt.Horizontal, 'code xrefs')
            self.code_xrefs_model.setHeaderData(1, Qt.Horizontal, '')
            self.code_xrefs_model.setHeaderData(2, Qt.Horizontal, '')
            code_xrefs.setModel(self.code_xrefs_model)

            r2_info.addWidget(call_refs)
            r2_info.addWidget(code_xrefs)

            self.disassembly_view.insertWidget(0, r2_info)
            self.disassembly_view.setStretchFactor(0, 1)
            self.disassembly_view.setStretchFactor(1, 5)

            self.disassembly_view.disasm_view.menu_extra_menu_hooks.append(self._on_hook_menu)

    def show_decompiler_view(self):
        if self._working:
            utils.show_message_box('please wait for the other works to finish')
        else:
            self.app.show_progress('r2: decompiling function')
            self._working = True

            self.r2decompiler = R2Decompiler(self.pipe, self.with_r2dec)
            self.r2decompiler.onR2Decompiler.connect(self._on_finish_decompiler)
            self.r2decompiler.start()

    def show_graph_view(self):
        if self._working:
            utils.show_message_box('please wait for the other works to finish')
        else:
            self.app.show_progress('r2: building graph view')
            self._working = True

            self.r2graph = R2Graph(self.pipe)
            self.r2graph.onR2Graph.connect(self._on_finish_graph)
            self.r2graph.start()

    def on_r2_command(self, cmd):
        if cmd == 'clear' or cmd == 'clean':
            self.console.clear()
        else:
            if self._working:
                self.console.log('please wait for other works to finish', time_prefix=False)
            else:
                try:
                    result = self.pipe.cmd(cmd)
                    self.console.log(result, time_prefix=False)
                except BrokenPipeError:
                    self.console.log('pipe is broken. recreating...', time_prefix=False)
                    self._create_pipe()
                    self.pipe.cmd('s %s' % self.current_seek)
