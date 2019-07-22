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
import json

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QStandardItemModel, QStandardItem
from PyQt5.QtWidgets import QSplitter, QAction

from lib import utils
from lib.prefs import Prefs
from lib.types.range import Range
from plugins.r2dwarf.src.decompiler import R2DecompiledText, R2Decompiler
from plugins.r2dwarf.src.dialog_options import OptionsDialog, KEY_WIDESCREEN_MODE
from plugins.r2dwarf.src.graph import R2Graph
from plugins.r2dwarf.src.main_widget import R2Widget
from plugins.r2dwarf.src.pipe import R2Pipe
from plugins.r2dwarf.src.scrollarea import R2ScrollArea
from ui.widgets.list_view import DwarfListView


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

    def __get_top_menu_actions__(self):
        if self.menu_items:
            return self.menu_items

        options = QAction('Options')
        options.triggered.connect(
            lambda: OptionsDialog.show_dialog(self._prefs))

        self.menu_items.append(options)
        return self.menu_items

    def __get_agent__(self):
        self.app.dwarf.onReceiveCmd.connect(self._on_receive_cmd)

        # we create the first pipe here to be safe that the r2 agent is loaded before the first breakpoint
        # i.e if we start dwarf targetting a package from args and a script breaking at first open
        # dwarf will hang because r2frida try to load it's agent and frida turn to use some api uth which are
        # not usable before the breakpoint quit
        # __get_agent__ is request just after our agent load and it solved all the things
        # still not the best solution as if the pipe got broken for some reason and we re-attempt to create it
        # while we are in a bkp we will face the same shit
        self._create_pipe()

        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'agent.js'), 'r') as f:
            return f.read()

    def __init__(self, app):
        self.app = app

        # block the creation of pipe on fatal errors
        self.pipe_locker = False

        self._prefs = Prefs()
        self._prefs.prefsChanged.connect(self._on_prefs_changed)
        self.pipe = None
        self.current_seek = ''
        self.with_r2dec = False
        self._working = False

        self.r2_widget = None
        self.tabbed_graph_view = None

        self.disassembly_view = None
        self._decompiled_textview = None
        self.r2decompiler = None

        self.menu_items = []
        self._auto_sized = False

        self.app.session_manager.sessionCreated.connect(
            self._on_session_created)
        self.app.session_manager.sessionStopped.connect(
            self._on_session_stopped)
        self.app.onSystemUIElementCreated.connect(self._on_ui_element_created)
        self.app.onSystemUIElementRemoved.connect(self._on_close_tab)

    def _on_prefs_changed(self):
        if self._decompiled_textview:
            if self._prefs.get(KEY_WIDESCREEN_MODE, False):
                self._decompiled_textview.setParent(None)
                self._decompiled_textview = R2DecompiledText(
                    disasm_view=self.disassembly_view.disasm_view)
                self.disassembly_view.addWidget(self._decompiled_textview)
            else:
                self._decompiled_textview.setParent(None)
                self._decompiled_textview = R2DecompiledText(
                    disasm_view=self.disassembly_view.disasm_view)
                index = self.app.main_tabs.indexOf(self._decompiled_textview)
                if index < 0:
                    index = self.app.main_tabs.addTab(
                        self._decompiled_textview, 'Decompiler')

                self.app.main_tabs.setCurrentIndex(index)

            # decompile
            if not self.r2decompiler.isRunning():
                self.r2decompiler.start()

    def _create_pipe(self):
        if self.pipe_locker:
            return None

        self.current_seek = ''
        self.pipe = self._open_pipe()

        if self.pipe is None:
            return None

        if self.r2_widget is not None:
            self.pipe.onUpdateVars.connect(self.r2_widget.refresh_e_vars_list)

        r2_decompilers = self.pipe.cmd('e cmd.pdc=?')
        if r2_decompilers is None:
            return None
        r2_decompilers = r2_decompilers.split()
        if r2_decompilers and 'pdd' in r2_decompilers:
            # setup decompiler to use when doing pdc/pdcj
            self.pipe.cmd('e cmd.pdc=pdd')
            self.with_r2dec = True
        self.pipe.cmd("e scr.color=2; e scr.html=1; e scr.utf8=true;")
        self.pipe.cmd(
            "e anal.autoname=true; e anal.hasnext=true; e asm.anal=true; e anal.fcnprefix=sub")
        return self.pipe

    def _open_pipe(self):
        device = self.app.dwarf.device

        if device is None:
            return None

        pipe = R2Pipe(self)
        pipe.onPipeBroken.connect(self._on_pipe_error)

        pipe.open()
        return pipe

    def _on_disasm_view_key_press(self, event_key, event_modifiers):
        if event_key == Qt.Key_Space:
            self.show_graph_view()

    def _on_disassemble(self, dwarf_range):
        if self.pipe is None:
            self._create_pipe()

        self.disassembly_view.disasm_view._lines.clear()
        self.disassembly_view.disasm_view.viewport().update()

        if self.disassembly_view.graph_view is not None:
            self.disassembly_view.graph_view.setParent(None)
            self.disassembly_view.graph_view = None

        if self.pipe is not None:
            # TODO: analyze the location
            start_address = hex(dwarf_range.user_req_start_address)
            if self.current_seek != start_address:
                self.current_seek = start_address
                self.pipe.cmd('s %s' % self.current_seek)

            if self.call_refs_model is not None:
                self.call_refs_model.setRowCount(0)
            if self.code_xrefs_model is not None:
                self.code_xrefs_model.setRowCount(0)
        else:
            self._on_finish_analysis([dwarf_range, {}])

        # decompile when decompiledtext is open
        if self._decompiled_textview and self.r2decompiler:
            self.r2decompiler.start()

    def _on_finish_analysis(self, data):
        self.app.hide_progress()
        self._working = False

        dwarf_range = data[0]
        if not dwarf_range:
            dwarf_range = self.disassembly_view._range
            if not dwarf_range:
                return

        # NOTE: keep the replace for compatibility
        cmd_result = self.pipe.cmdj('afij').replace('&nbsp;', '')
        function_info = json.loads(cmd_result)
        if function_info:
            function_info = function_info[0]

        num_instructions = 0
        if 'offset' in function_info:
            dwarf_range.user_req_start_offset = function_info['offset'] - \
                dwarf_range.base
            num_instructions = int(self.pipe.cmd('pif~?'))

        if self.disassembly_view is not None:
            self.disassembly_view.disasm_view.start_disassemble(
                dwarf_range, num_instructions=num_instructions - 1)

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

            if data and len(data) > 1:
                func_map = data[1]
                self.disassembly_view.update_functions(functions_list=func_map)

    def _on_finish_graph(self, data):
        self.app.hide_progress()
        self._working = False

        graph_data = data[0]

        if self._prefs.get(KEY_WIDESCREEN_MODE, False):
            if self.disassembly_view.graph_view is None:
                self.disassembly_view.graph_view = R2ScrollArea()
                self.disassembly_view.addWidget(
                    self.disassembly_view.graph_view)
            self.disassembly_view.graph_view.setText(
                '<pre>' + graph_data + '</pre>')
        else:
            if self.tabbed_graph_view is None:
                self.tabbed_graph_view = R2ScrollArea()
            index = self.app.main_tabs.indexOf(self.tabbed_graph_view)
            if index < 0:
                self.app.main_tabs.addTab(self.tabbed_graph_view, 'graph')
                index = self.app.main_tabs.indexOf(self.tabbed_graph_view)
            self.tabbed_graph_view.setText('<pre>' + graph_data + '</pre>')
            self.app.main_tabs.setCurrentIndex(index)

    def _on_finish_decompiler(self, data):
        if not self.with_r2dec:
            return

        self.app.hide_progress()
        self._working = False
        import re

        # keep until ?
        data[0] = re.sub(r'\d+;\d+;\d+;\d+;', '', data[0])
        data[0] = data[0].replace('<', '&lt;').replace('>', '&gt;')
        # replace colors
        regex = r'\\u001b(\[[0-?]*[ -/]*[@-~])(.*?)\\u001b\[[0-?]*[ -/]*[@-~]'
        decompile_data = re.sub(regex, r"<font color='\1'>\2</font>", data[0])

        colors = {
            # comment == orgcolor
            '[30m': '#666',  # black
            '[31m': '#5C6370',  # red
            '[32m': '#D19A66',  # green
            '[33m': '#C678DD',  # yellow
            '[34m': 'blue',
            '[35m': '#C678DD',  # magenta
            '[36m': '#e06c75',  # cyan
            '[37m': 'white',
            '[39m': '#666',  # white
            '[90m': '#61AFEF',  # lightgray
            '[91m': 'lightred',
            '[92m': 'lightgreen'
        }

        for color in colors:
            decompile_data = decompile_data.replace(color, colors[color])

        decompile_data = json.loads(decompile_data)

        if decompile_data:
            if not self._decompiled_textview:
                self._decompiled_textview = R2DecompiledText(
                    disasm_view=self.disassembly_view.disasm_view)

            self._decompiled_textview.clear()
            if self._prefs.get(KEY_WIDESCREEN_MODE, False):
                if not self._decompiled_textview:
                    self.disassembly_view.addWidget(self._decompiled_textview)

                if not self._auto_sized:
                    self._auto_sized = True
                    main_width = self.disassembly_view.width()
                    childs = self.disassembly_view.count()
                    new_sizes = [1, 1]
                    for _ in range(2, childs):
                        new_sizes.append(main_width / childs)

                    self.disassembly_view.setSizes(new_sizes)
            else:
                index = self.app.main_tabs.indexOf(self._decompiled_textview)
                if index < 0:
                    index = self.app.main_tabs.addTab(
                        self._decompiled_textview, 'Decompiler')

                self.app.main_tabs.setCurrentIndex(index)

            # parse
            if 'lines' in decompile_data and decompile_data['lines']:
                for line in decompile_data['lines']:
                    if 'str' in line:
                        new_line = ''
                        for char in line['str']:
                            if char.isspace():
                                new_line += '&nbsp;'
                            else:
                                break

                        if 'offset' in line:
                            new_line += '<a href="offset:' + \
                                hex(line['offset']) + \
                                '" style="color: #666; text-decoration: none;">'

                        new_line += line['str'].lstrip()

                        if 'offset' in line:
                            new_line += '</a>'

                        self._decompiled_textview.appendHtml(new_line)

    def _on_hook_menu(self, menu, address):
        menu.addSeparator()
        r2_menu = menu.addMenu('r2')

        view_menu = r2_menu.addMenu('view')
        graph = view_menu.addAction('graph view', self.show_graph_view)
        # show only when r2dec is in place
        if self.with_r2dec:
            decompile = view_menu.addAction(
                'decompile', self.show_decompiler_view)
        if address == -1:
            graph.setEnabled(False)
            decompile.setEnabled(False)

    def _on_pipe_error(self, reason):
        should_recreate_pipe = True

        if 'Broken' in reason:
            should_recreate_pipe = False

        if should_recreate_pipe:
            self._create_pipe()

    def _on_receive_cmd(self, args):
        message, data = args
        if 'payload' in message:
            payload = message['payload']
            if payload.startswith('r2 '):
                if self.pipe is None:
                    self._create_pipe()

                cmd = message['payload'][3:]

                if cmd == 'init':
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
                    self.pipe.cmd('e asm.arch=%s; e asm.bits=%d; e asm.os=%s; e anal.arch=%s;' % (
                        r2arch, r2bits, self.app.dwarf.platform, r2arch))
                    return

                try:
                    result = self.pipe.cmd(cmd, api=True)
                    self.app.dwarf._script.post(
                        {"type": 'r2', "payload": result})
                except:
                    self.app.dwarf._script.post(
                        {"type": 'r2', "payload": None})

    def _on_session_created(self):
        self.app.panels_menu.addSeparator()
        self.app.panels_menu.addAction('r2', self.create_widget)

    def create_widget(self):
        if self.r2_widget is not None:
            return self.r2_widget

        self.r2_widget = R2Widget(self)
        if self.pipe is not None:
            self.pipe.onUpdateVars.connect(self.r2_widget.refresh_e_vars_list)
        self.app.main_tabs.addTab(self.r2_widget, 'r2')
        self.app.main_tabs.setCurrentIndex(
            self.app.main_tabs.indexOf(self.r2_widget))
        return self.r2_widget

    def _on_session_stopped(self):
        # TODO: cleanup the stuff
        if self.pipe:
            self.pipe.close()

    def _on_ui_element_created(self, elem, widget):
        if elem == 'disassembly':
            self.disassembly_view = widget
            self.disassembly_view.graph_view = None
            self._decompiled_textview = None

            self.disassembly_view.disasm_view.run_default_disassembler = False
            self.disassembly_view.disasm_view.onDisassemble.connect(
                self._on_disassemble)
            self.disassembly_view.disasm_view.onDisasmViewKeyPressEvent.connect(
                self._on_disasm_view_key_press)

            r2_function_refs = QSplitter()
            r2_function_refs.setOrientation(Qt.Vertical)

            call_refs = DwarfListView()
            self.call_refs_model = QStandardItemModel(0, 3)
            self.call_refs_model.setHeaderData(0, Qt.Horizontal, 'call refs')
            self.call_refs_model.setHeaderData(1, Qt.Horizontal, '')
            self.call_refs_model.setHeaderData(2, Qt.Horizontal, '')
            call_refs.doubleClicked.connect(
                lambda x: self.disasm_ref_double_click(self.call_refs_model, x))
            call_refs.setModel(self.call_refs_model)

            code_xrefs = DwarfListView()
            self.code_xrefs_model = QStandardItemModel(0, 3)
            self.code_xrefs_model.setHeaderData(0, Qt.Horizontal, 'code xrefs')
            self.code_xrefs_model.setHeaderData(1, Qt.Horizontal, '')
            self.code_xrefs_model.setHeaderData(2, Qt.Horizontal, '')
            code_xrefs.doubleClicked.connect(
                lambda x: self.disasm_ref_double_click(self.code_xrefs_model, x))
            code_xrefs.setModel(self.code_xrefs_model)

            r2_function_refs.addWidget(call_refs)
            r2_function_refs.addWidget(code_xrefs)
            r2_function_refs.setSizes([50, 50])

            self.disassembly_view.insertWidget(1, r2_function_refs)
            self.disassembly_view.setSizes(
                [50, 50, self.disassembly_view.width() - 100])

            self.disassembly_view.disasm_view.menu_extra_menu_hooks.append(
                self._on_hook_menu)

    def _on_close_tab(self, name):
        if name == 'r2':
            self.r2_widget = None

    def show_decompiler_view(self):
        if self._working:
            utils.show_message_box('please wait for the other works to finish')
        else:
            self.app.show_progress('r2: decompiling function')
            self._working = True

            if not self.r2decompiler:
                self.r2decompiler = R2Decompiler(self.pipe, self.with_r2dec)
                self.r2decompiler.onR2Decompiler.connect(
                    self._on_finish_decompiler)

            if not self.r2decompiler.isRunning():
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

    def disasm_ref_double_click(self, model, modelIndex):
        ptr = utils.parse_ptr(model.item(
            model.itemFromIndex(modelIndex).row(), 0).text())
        line = self.disassembly_view.disasm_view.get_line_for_address(ptr)
        if line >= 0:
            self.disassembly_view.disasm_view.verticalScrollBar().setValue(line)
        else:
            Range.build_or_get(self.app.dwarf, ptr, cb=self._on_disassemble)
