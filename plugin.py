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
from PyQt5.QtWidgets import QDockWidget

from dwarf.lib import utils
from r2dwarf.src.decompiler import R2DecompiledText, R2Decompiler
from r2dwarf.src.graph import R2Graph
from r2dwarf.src.main_widget import R2Widget
from r2dwarf.src.pipe import R2Pipe
from dwarf.ui.panels.panel_debug import DEBUG_VIEW_MEMORY, DEBUG_VIEW_DISASSEMBLY
from dwarf.ui.widgets.list_view import DwarfListView


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

        self.pipe = None
        self.current_seek = ''
        self.with_r2dec = False
        self._working = False

        self.r2_widget = None

        self.debug_panel = None

        self.graph_view = None
        self.dock_graph_view = None
        self.decompiled_view = None
        self.dock_decompiled_view = None

        self.r2decompiler = None

        self.menu_items = []
        self._auto_sized = False

        self._seek_view_type = DEBUG_VIEW_MEMORY

        self.app.session_manager.sessionCreated.connect(
            self._on_session_created)
        self.app.session_manager.sessionStopped.connect(
            self._on_session_stopped)
        self.app.onSystemUIElementCreated.connect(self._on_ui_element_created)
        self.app.onSystemUIElementRemoved.connect(self._on_close_tab)

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
            self.dock_decompiled_view.show()

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

    def _jump_to_address_impl(self, address, view=DEBUG_VIEW_MEMORY):
        address = utils.parse_ptr(address)

        if view == DEBUG_VIEW_MEMORY:
            if self.debug_panel.memory_panel.number_of_lines() > 0:
                if self.debug_panel.is_address_in_view(view, address):
                    return
        elif view == DEBUG_VIEW_DISASSEMBLY:
            if self.debug_panel.disassembly_panel.number_of_lines() > 0:
                if self.debug_panel.is_address_in_view(view, address):
                    return

        if not self._working:
            if self.pipe is None:
                self._create_pipe()

            self._working = True

            if self.pipe is not None:
                start_address = hex(address)
                if self.current_seek != start_address:
                    self.current_seek = start_address
                    self._seek_view_type = view
                    self.pipe.cmd('s %s' % self.current_seek)

                if self.call_refs_model is not None:
                    self.call_refs_model.setRowCount(0)
                if self.code_xrefs_model is not None:
                    self.code_xrefs_model.setRowCount(0)
            else:
                self._on_finish_analysis([0, bytes(), 0])

    def _on_finish_analysis(self, data):
        self._working = False
        self.app.hide_progress()

        if self._seek_view_type == DEBUG_VIEW_MEMORY:
            self.debug_panel.memory_panel.set_data(data[1], base=data[0], offset=data[2])
            if not self.debug_panel.dock_memory_panel.isVisible():
                self.debug_panel.dock_memory_panel.show()
            self.debug_panel.raise_memory_panel()

            if self.debug_panel.disassembly_panel.number_of_lines() == 0:
                self.debug_panel.disassembly_panel.disasm(data[0], data[1], data[2])
        elif self._seek_view_type == DEBUG_VIEW_DISASSEMBLY:
            # NOTE: keep the replace for compatibility
            cmd_result = self.pipe.cmdj('afij').replace('&nbsp;', '')
            function_info = None
            num_instructions = 0

            try:
                function_info = json.loads(cmd_result)
            except:
                pass

            if function_info is not None and len(function_info) > 0:
                function_info = function_info[0]

                if 'offset' in function_info:
                    data[2] = function_info['offset'] - data[0]
                    num_instructions = int(self.pipe.cmd('pif~?'))

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

            self.debug_panel.disassembly_panel.disasm(
                data[0], data[1], data[2], num_instructions=num_instructions)

            if not self.debug_panel.dock_disassembly_panel.isVisible():
                self.debug_panel.dock_disassembly_panel.show()
            self.debug_panel.raise_disassembly_panel()

            if self.debug_panel.memory_panel.number_of_lines() == 0:
                self.debug_panel.memory_panel.set_data(data[1], base=data[0], offset=data[2])

            self.graph_view.clear()
            self.decompiled_view.clear()

        self.r2graph = R2Graph(self.pipe)
        self.r2graph.onR2Graph.connect(self._on_finish_graph)
        self.r2graph.start()

    def _on_finish_graph(self, data):
        graph_data = data[0]

        self.graph_view.appendHtml('<pre>' + graph_data + '</pre>')

        if self.with_r2dec:
            self.r2decompiler = R2Decompiler(self.pipe, self.with_r2dec)
            self.r2decompiler.onR2Decompiler.connect(self._on_finish_decompiler)
            self.r2decompiler.start()

    def _on_finish_decompiler(self, data):
        import re
        # keep until ?
        data[0] = re.sub(r'\d+;\d+;\d+;\d+;', '', data[0])
        data[0] = data[0].replace('<', '&lt;').replace('>', '&gt;')
        # replace colors
        regex = r'\\u001b(\[[0-?]*[ -/]*[@-~])(.*?)\\u001b\[[0-?]*[ -/]*[@-~]'
        decompile_data = re.sub(regex, r"<font color='\1'>\2</font>", data[0])

        hex_regex = r'(0x[a-f0-9]+)'

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

                        line_content = line['str'].lstrip()
                        new_line += re.sub(
                            hex_regex, "<a style=\"color: #8B0000; text-decoration: none;\" href=\"jump:\\1\">\\1</a>", line_content)

                        if 'offset' in line:
                            new_line += '</a>'

                        self.decompiled_view.appendHtml(new_line)

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
        if elem == 'debug':
            self.debug_panel = widget
            self.debug_panel.jump_to_address = self._jump_to_address_impl

            call_refs = DwarfListView()
            self.call_refs_model = QStandardItemModel(0, 3)
            self.call_refs_model.setHeaderData(0, Qt.Horizontal, 'call refs')
            self.call_refs_model.setHeaderData(1, Qt.Horizontal, '')
            self.call_refs_model.setHeaderData(2, Qt.Horizontal, '')
            call_refs.doubleClicked.connect(
                lambda x: self.disasm_ref_double_click(self.call_refs_model, x))
            call_refs.setModel(self.call_refs_model)

            dock_call_refs = QDockWidget('Call refs', self.debug_panel)
            dock_call_refs.setObjectName('callrefs')
            dock_call_refs.setWidget(call_refs)
            self.debug_panel.addDockWidget(Qt.LeftDockWidgetArea, dock_call_refs, Qt.Vertical)
            self.app.debug_view_menu.addAction(dock_call_refs.toggleViewAction())

            code_xrefs = DwarfListView()
            self.code_xrefs_model = QStandardItemModel(0, 3)
            self.code_xrefs_model.setHeaderData(0, Qt.Horizontal, 'code xrefs')
            self.code_xrefs_model.setHeaderData(1, Qt.Horizontal, '')
            self.code_xrefs_model.setHeaderData(2, Qt.Horizontal, '')
            code_xrefs.doubleClicked.connect(
                lambda x: self.disasm_ref_double_click(self.code_xrefs_model, x))
            code_xrefs.setModel(self.code_xrefs_model)

            dock_code_xrefs = QDockWidget('Code xrefs', self.debug_panel)
            dock_code_xrefs.setObjectName('codexrefs')
            self.debug_panel.addDockWidget(Qt.LeftDockWidgetArea, dock_code_xrefs, Qt.Vertical)
            self.debug_panel.splitDockWidget(dock_call_refs, dock_code_xrefs, Qt.Vertical)
            dock_code_xrefs.setWidget(code_xrefs)
            self.app.debug_view_menu.addAction(dock_code_xrefs.toggleViewAction())

            self.add_graph_view()
            self.add_decompiler_view()

            if not self.with_r2dec:
                self.dock_decompiled_view.hide()

            self.debug_panel.raise_disassembly_panel()
            self.debug_panel.restoreUiState()

    def _on_close_tab(self, name):
        if name == 'r2':
            self.r2_widget = None

    def add_decompiler_view(self):
        self.decompiled_view = R2DecompiledText(debug_panel=self.debug_panel)
        self.dock_decompiled_view = QDockWidget('Decompiler', self.debug_panel)
        self.dock_decompiled_view.setObjectName('decompiler')
        self.dock_decompiled_view.setWidget(self.decompiled_view)
        self.debug_panel.addDockWidget(Qt.RightDockWidgetArea, self.dock_decompiled_view)
        self.debug_panel.tabifyDockWidget(self.debug_panel.dock_disassembly_panel, self.dock_decompiled_view)
        self.app.debug_view_menu.addAction(self.dock_decompiled_view.toggleViewAction())

    def add_graph_view(self):
        self.graph_view = R2DecompiledText(debug_panel=self.debug_panel)
        self.dock_graph_view = QDockWidget('Graph', self.debug_panel)
        self.dock_graph_view.setObjectName('graph')
        self.dock_graph_view.setWidget(self.graph_view)
        self.debug_panel.addDockWidget(Qt.RightDockWidgetArea, self.dock_graph_view)
        self.debug_panel.tabifyDockWidget(self.debug_panel.dock_disassembly_panel, self.dock_graph_view)
        self.app.debug_view_menu.addAction(self.dock_graph_view.toggleViewAction())

    def disasm_ref_double_click(self, model, modelIndex):
        ptr = utils.parse_ptr(model.item(
            model.itemFromIndex(modelIndex).row(), 0).text())
        self.debug_panel.jump_to_address(ptr, DEBUG_VIEW_DISASSEMBLY)
