import json
import os
import time
from subprocess import *

from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QPlainTextEdit, QSizePolicy, QScrollBar, QSplitter, QScrollArea

from ui.widget_console import DwarfConsoleWidget

from lib import utils

from PyQt5.QtCore import QObject, QThread, pyqtSignal, Qt

from ui.widgets.list_view import DwarfListView


class R2TextEdit(QPlainTextEdit):
    def __init__(self, *__args):
        super().__init__(*__args)
        self.setReadOnly(True)
        self.setSizePolicy(QSizePolicy.Preferred, QSizePolicy.Minimum)
        self.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
        self.setLineWrapMode(QPlainTextEdit.NoWrap)
        #self.setEnabled(False)


class R2Analysis(QThread):
    onR2AnalysisFinished = pyqtSignal(list, name='onR2AnalysisFinished')

    def __init__(self, pipe):
        super(R2Analysis, self).__init__()
        self._pipe = pipe
        self.decompile = False

    def run(self):
        self._pipe.cmd('aF')

        graph = self._pipe.cmd('agf')
        function_info = self._pipe.cmdj('afij')
        if len(function_info) > 0:
            function_info = function_info[0]

        decompile_data = None
        if self.decompile:
            decompile_data = self._pipe.cmd('pddo')

        self.onR2AnalysisFinished.emit([function_info, graph, decompile_data])

    def start(self, priority=QThread.HighPriority):
        return super().start(priority=priority)


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

    def cmdj(self, cmd):
        self._cmd_process('e scr.html=0')
        ret = self._cmd_process(cmd)
        self._cmd_process('e scr.html=1')
        try:
            return json.loads(ret)
        except:
            return {}

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
        self.pipe = None
        self.analysis_progress_dialog = None
        self.current_seek = ''
        self.have_r2dec = False

        self.app.session_manager.sessionCreated.connect(self._on_session_created)
        self.app.onUIElementCreated.connect(self._on_ui_element_created)

    def _create_pipe(self):
        self.pipe = R2Pipe()
        self.pipe.open('frida://attach/usb//%d' % self.app.dwarf.pid)
        self.pipe.cmd("e scr.color=2; e scr.html=1")

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
                self.current_seek = pc
                self.pipe.cmd('s %s' % self.current_seek)

    def _on_disassemble(self, ptr):
        if self.current_seek != ptr:
            self.current_seek = ptr
            self.pipe.cmd('s %s' % self.current_seek)

        self.analysis_progress_dialog = utils.progress_dialog('running r2 analysis...')
        self.analysis_progress_dialog.forceShow()

        r2analysis = R2Analysis(self.pipe)
        r2analysis.decompile = self.have_r2dec
        r2analysis.onR2AnalysisFinished.connect(self._on_finish_analysis)
        r2analysis.start()

    def _on_finish_analysis(self, data):
        self.analysis_progress_dialog.cancel()

        function_info = data[0]
        graph_data = data[1]
        decompile_data = data[2]

        self.r2_graph_view.appendHtml('<pre>' + graph_data + '</pre>')
        self.r2_graph_view.verticalScrollBar().triggerAction(QScrollBar.SliderToMinimum)

        if decompile_data is not None:

            self.r2_decompiler_view.appendHtml(
                '<p>' + decompile_data + '</pre>')
            self.r2_decompiler_view.verticalScrollBar().triggerAction(QScrollBar.SliderToMinimum)

        for ref in function_info['callrefs']:
            self.call_refs_model.appendRow([
                QStandardItem(hex(ref['addr'])),
                QStandardItem(hex(ref['at'])),
                QStandardItem(ref['type'])
            ])

        for ref in function_info['codexrefs']:
            self.code_xrefs_model.appendRow([
                QStandardItem(hex(ref['addr'])),
                QStandardItem(hex(ref['at'])),
                QStandardItem(ref['type'])
            ])

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

        self._create_pipe()

        self.console = DwarfConsoleWidget(self.app, input_placeholder='r2', completer=False)
        self.console.onCommandExecute.connect(self.on_r2_command)

        self.app.main_tabs.addTab(self.console, 'r2')

    def _on_ui_element_created(self, elem, widget):
        if elem == 'disassembly':
            widget.onDisassemble.connect(self._on_disassemble)

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

            r2_graph_container = QScrollArea()
            r2_graph_container.setWidgetResizable(True)
            self.r2_graph_view = R2TextEdit()
            r2_graph_container.setWidget(self.r2_graph_view)

            widget.insertWidget(0, r2_info)
            widget.addWidget(r2_graph_container)

            widget.setStretchFactor(0, 2)
            widget.setStretchFactor(1, 5)
            widget.setStretchFactor(2, 5)

            pdd = self.pipe.cmd('pdd --help')
            if pdd.startswith:
                self.have_r2dec = True
                r2_compiler_container = QScrollArea()
                r2_compiler_container.setWidgetResizable(True)
                self.r2_decompiler_view = R2TextEdit()
                r2_compiler_container.setWidget(self.r2_decompiler_view)

                widget.addWidget(r2_compiler_container)
                widget.setStretchFactor(3, 5)

    def on_r2_command(self, cmd):
        if cmd == 'clear' or cmd == 'clean':
            self.console.clear()
        else:
            try:
                result = self.pipe.cmd(cmd)
                self.console.log(result, time_prefix=False)
            except BrokenPipeError:
                self.console.log('pipe is broken. recreating...', time_prefix=False)
                self._create_pipe()
                self.pipe.cmd('s %s' % self.current_seek)
