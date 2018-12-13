#-------------------------------------------------------------------------------
#
#   IDA Pro Plug-in: Function Identification and Recovery Signature Tool (FIRST)
#   Copyright (C) 2016  Angel M. Villegas
#
#   This program is free software; you can redistribute it and/or modify
#   it under the terms of the GNU General Public License as published by
#   the Free Software Foundation; either version 2 of the License, or
#   (at your option) any later version.
#
#   This program is distributed in the hope that it will be useful,
#   but WITHOUT ANY WARRANTY; without even the implied warranty of
#   MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#   GNU General Public License for more details.
#
#   You should have received a copy of the GNU General Public License along
#   with this program; if not, write to the Free Software Foundation, Inc.,
#   51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
#
#   Requirements
#   ------------
#   Requests (docs.python-requests.org/)
#
#   Installation
#   ------------
#   Drag and drop into IDA Pro's plugin folder for IDA Pro 6.9 SP1 and higher
#
#-------------------------------------------------------------------------------
#   IDA Pro Python Modules
import idc
import idaapi
import idautils
import random

#   Third Party Python Modules
required_modules_loaded = True
try:
    import requests
except ImportError:
    required_modules_loaded &= False
    print 'FIRST requires Python module requests\n'

try:
    from requests_kerberos import HTTPKerberosAuth
except ImportError:
    print '[1st] Kerberos support is not avaialble'
    HTTPKerberosAuth = None

from PyQt5 import QtGui, QtWidgets, QtCore
from PyQt5.QtCore import Qt

#   Python Modules
import re
import csv
import sys
import math
import time
import json
import inspect
import os.path
import datetime
import calendar
import threading
import collections
import ConfigParser
from pprint import pprint
from os.path import exists
from hashlib import sha256, md5, sha1
from base64 import b64encode, b64decode

#   Constants
#-------------------------------------------------------------------------------
FIRST_INDEX = {
                'hashes' : 1,
                'malware_name' : 2,
              }

#   Global Variables
#-------------------------------------------------------------------------------
FIRST_ICON = None
FIRST_DB = 'FIRST_data'

class IDAWrapper(object):
    '''
    Class to wrap functions that are not thread safe.  These functions must
    be run on the main thread to avoid random crashes (and starting in 7.2,
    this is enforced by IDA, with an exception being generated if a
    thread-unsafe function is called from outside of the main thread.)
    '''
    mapping = {
        'get_tform_type' : 'get_widget_type',
    }
    def __init__(self):
        self.version = idaapi.IDA_SDK_VERSION

    def __getattribute__(self, name):
        default = '[1st] default'

        if (idaapi.IDA_SDK_VERSION >= 700) and (name in IDAWrapper.mapping):
            name = IDAWrapper.mapping[name]

        val = getattr(idaapi, name, default)
        if val == default:
            val = getattr(idautils, name, default)

        if val == default:
            val = getattr(idc, name, default)

        if val == default:
            msg = 'Unable to find {}'.format(name)
            idaapi.execute_ui_requests((FIRSTUI.Requests.Print(msg),))
            return

        if hasattr(val, '__call__'):
            def call(*args, **kwargs):
                holder = [None] # need a holder, because 'global' sucks

                def trampoline():
                    holder[0] = val(*args, **kwargs)
                    return 1

                # Execute the request using MFF_WRITE, which should be safe for
                # any possible request at the expense of speed.  In my testing,
                # though, it wasn't noticably slower than MFF_FAST.  If this
                # is observed to impact performance, consider creating a list
                # that maps API calls to the most appropriate flag.
                idaapi.execute_sync(trampoline, idaapi.MFF_WRITE)
                return holder[0]
            return call

        else:
            return val

IDAW = IDAWrapper()

# Some of the IDA API functions return generators that invoke thread-unsafe
# code during iteration.  Thus, making the initial API call via IDAW is not
# sufficient to have these underlying API calls be executed safely on the
# main thread.  This generator wraps those and performs the iteration safely.
def safe_generator(iterator):

    # Make the sentinel value something that isn't likely to be returned
    # by an API call (and isn't a fixed string that could be inserted into
    # a program to break FIRST maliciously)
    sentinel = '[1st] Sentinel %d' % (random.randint(0, 65535))

    holder = [sentinel] # need a holder, because 'global' sucks

    def trampoline():
        try:
            holder[0] = next(iterator)
        except StopIteration:
            holder[0] = sentinel
        return 1

    while True:
        # See notes above regarding why we use MFF_WRITE here
        idaapi.execute_sync(trampoline, idaapi.MFF_WRITE)
        if holder[0] == sentinel:
            return
        yield holder[0]

#   Main Plug-in Form Class
#-------------------------------------------------------------------------------
class FIRST_FormClass(idaapi.PluginForm):
    system = {0 : 'Unknown', 1 : 'Win', 6 : 'Linux', 9 : 'Osx'}

    def __init__(self):
        super(FIRST_FormClass, self).__init__()
        self.parent = None

    def OnCreate(self, form):
        self.form = form
        self.parent = self.FormToPyQtWidget(form)

        self.populate_model()
        self.populate_main_form()

    def populate_model(self):
        #   Selectable views in the main plug-in window
        self.views_ui = {'Configuration' : self.view_configuration_info,
                            'Management' : self.view_created,
                            'Currently Applied' : self.view_applied,
                            'About' : self.view_about}
        self.views = ['About', 'Configuration', 'Management', 'Currently Applied']

        self.views_model = FIRST.Model.Base(['Views'], self.views)

    def view_configuration_info(self):
        self.thread_stop = True
        container = QtWidgets.QVBoxLayout()

        label = QtWidgets.QLabel('Configuration Information')
        label.setStyleSheet('font: 18px;')
        container.addWidget(label)

        layout = QtWidgets.QHBoxLayout()
        self.message = QtWidgets.QLabel()
        layout.addWidget(self.message)
        layout.addStretch()
        save_button = QtWidgets.QPushButton('Save')
        layout.addWidget(save_button)

        scroll_layout = FIRSTUI.ScrollWidget(frame=QtWidgets.QFrame.NoFrame)
        FIRSTUI.SharedObjects.server_config_layout(self, scroll_layout, FIRST.config)

        container.addWidget(scroll_layout)
        container.addStretch()
        container.addLayout(layout)

        save_button.clicked.connect(self.save_config)

        return container

    def save_config(self):
        FIRST.config = FIRSTUI.SharedObjects.get_config(self)
        FIRST.config.save_config(FIRST.config_path)

        info = FIRST.Info.get_file_details()
        FIRST.server = FIRST.Server(FIRST.config,
                                    info['md5'],
                                    info['crc32'],
                                    h_sha1=info['sha1'],
                                    h_sha256=info['sha256'])

        title = 'FIRST: Configuration Changes'
        msg = 'FIRST\'s configuration information has been updated'
        idaapi.execute_ui_requests((FIRSTUI.Requests.MsgBox(title, msg, QtWidgets.QMessageBox.Information),))

    def view_created(self):
        container = QtWidgets.QVBoxLayout()
        groups = None

        label = QtWidgets.QLabel('FIRST Metadata')
        label.setStyleSheet('font: 18px;')
        container.addWidget(label)

        container.addSpacing(5)
        description = ('The metadata you\'ve created and added to FIRST '
                        'are shown below. You can delete them via right '
                        'clicking on them and selecting delete or '
                        'selecting one and hitting the delete key.')
        description = QtWidgets.QLabel(description)
        description.setWordWrap(True)
        container.addWidget(description)
        container.addSpacing(10)

        data_model = FIRST.Model.Check({})
        tree_view = FIRST.Model.TreeView(depth=1)
        tree_view.setExpandsOnDoubleClick(False)
        tree_view.setIndentation(15)
        tree_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        tree_view.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

        #   Setup the Model's header
        FIRSTUI.SharedObjects.make_model_headers(data_model, full=False)

        tree_view.setModel(data_model)
        self.created_data_model = data_model

        tree_view.setColumnWidth(0, 175)    #   Function
        tree_view.setColumnWidth(1, 35)     #   Rank
        tree_view.setColumnWidth(2, 150)    #   Prototype
        tree_view.setColumnWidth(3, 20)     #   i


        #   Add chunks to the list at a time receieved
        self.__received_data = False
        if FIRST.server:
            #   Spawn thread to get chunks of data back from server
            self.thread_stop = False
            idaapi.show_wait_box('Querying FIRST for metadata you\'ve created')
            server_thread = FIRST.server.created(self.__data_callback,
                                                    self.__complete_callback)

            #   wait several seconds
            for i in xrange(2):
                time.sleep(1)
                if idaapi.wasBreak():
                    self.thread_stop = True
                    FIRST.server.stop_operation(server_thread)

            idaapi.hide_wait_box()


        self.history_dialogs = []
        tree_view.setContextMenuPolicy(Qt.ActionsContextMenu)
        delete_action = QtWidgets.QAction('&Delete', self.parent)
        delete_action.setShortcut('Del')
        delete_action.triggered.connect(self.delete_metadata)
        history_action = QtWidgets.QAction('View &History', self.parent)
        history_action.setShortcut('H')
        history_action.triggered.connect(self.metadata_history)
        tree_view.addAction(delete_action)
        tree_view.addAction(history_action)

        self.created_tree_view = tree_view
        container.addWidget(self.created_tree_view)

        return container

    def __data_callback(self, thread, data):
        if self.thread_stop:
            FIRST.server.stop_operation(thread)

        #   Build the model
        root_node = self.created_data_model.invisibleRootItem()

        for match in data:
            self.__received_data = True
            row = FIRSTUI.SharedObjects.make_match_info(match, full=False)
            root_node.appendRow(row)

    def __complete_callback(self, thread, data):
        FIRST.server.remove_operation(thread)

        #   Alert the user if no matches were found in FIRST
        if not self.__received_data:
            title = 'FIRST: No Metadata Found'
            msg = 'You have not added any metadata to FIRST'
            idaapi.execute_ui_requests((FIRSTUI.Requests.MsgBox(title, msg, QtWidgets.QMessageBox.Information),))
            return

    def delete_metadata(self):
        selected = self.created_tree_view.selectedIndexes()
        if not selected:
            return

        ids = set([x.data(FIRSTUI.ROLE_ID) for x in selected])
        index = selected[0]

        for metadata_id in ids:
            #   Delete from FIRST
            if metadata_id:
                response = FIRST.server.delete(metadata_id)
                if (not response
                    or ('failed' not in response)
                    or response['failed']
                    or (('deleted' in response) and not response['deleted'])):

                    title = 'FIRST: Delete Created Metadata'
                    msg = 'Cannot delete the requested signature. '
                    if response and ('msg' in response):
                        msg += 'Error: {0[msg]} '.format(response)

                    idaapi.execute_ui_requests((FIRSTUI.Requests.MsgBox(title, msg),))
                    return

                #   Remove from view, get the top row of the tree
                if index.parent().isValid():
                    index = index.parent()

                root = self.created_data_model.invisibleRootItem()
                root.removeRow(index.row())

    def metadata_history(self):
        selected = self.created_tree_view.selectedIndexes()
        if not selected:
            return

        ids = [x.data(FIRSTUI.ROLE_ID) for x in selected]
        index = selected[0]

        if not ids:
            return

        dialog = FIRSTUI.Dialog(None, FIRSTUI.History, metadata_id=ids[0])
        dialog.show()

        self.history_dialogs.append(dialog)

    def view_about(self):
        self.thread_stop = True
        container = QtWidgets.QVBoxLayout()

        label = QtWidgets.QLabel('FIRST ')
        label.setStyleSheet('font: 24px;')
        container.addWidget(label)

        label = QtWidgets.QLabel('Function Identification and Recovery Signature Tool')
        label.setStyleSheet('font: 12px;')
        container.addWidget(label)

        grid_layout = QtWidgets.QGridLayout()
        grid_layout.addWidget(QtWidgets.QLabel('Version'), 0, 0)
        grid_layout.addWidget(QtWidgets.QLabel(str(FIRST.VERSION)), 0, 1)
        grid_layout.addWidget(QtWidgets.QLabel('Date'), 1, 0)
        grid_layout.addWidget(QtWidgets.QLabel(FIRST.DATE), 1, 1)

        grid_layout.addWidget(QtWidgets.QLabel('Report Issues'), 2, 0)
        label = QtWidgets.QLabel(('<a href="https://git.vrt.sourcefire.com/'
                                'demonduck/FIRST/issues/new">'
                                'git.vrt.sourcefire.com</a>'))
        label.setTextFormat(Qt.RichText)
        label.setTextInteractionFlags(Qt.TextBrowserInteraction)
        label.setOpenExternalLinks(True)
        grid_layout.addWidget(label, 2, 1)

        grid_layout.setColumnMinimumWidth(0, 100)
        grid_layout.setColumnStretch(1, 1)
        grid_layout.setContentsMargins(10, 0, 0, 0)

        container.addSpacing(10)
        container.addLayout(grid_layout)
        container.addStretch()

        copyright = '{}-{} Cisco Systems, Inc.'.format(FIRST.BEGIN, FIRST.END)
        label = QtWidgets.QLabel(copyright)
        label.setStyleSheet('font: 10px;')
        label.setAlignment(Qt.AlignCenter)

        container.addWidget(label)
        return container

    def view_applied(self):
        self.thread_stop = True
        container = QtWidgets.QVBoxLayout()
        groups = None

        label = QtWidgets.QLabel('Applied Metadata')
        label.setStyleSheet('font: 18px;')
        container.addWidget(label)

        container.addSpacing(5)
        description = ('FIRST metadata you\'ve applied in this IDB '
                        'are shown below. You can go to the function via '
                        'right clicking on the function and selecting View '
                        'or double clicking the function.')
        description = QtWidgets.QLabel(description)
        description.setWordWrap(True)
        container.addWidget(description)
        container.addSpacing(10)

        data = FIRST.Metadata.get_functions_with_applied_metadata()
        data = {d.address : d for d in data}
        data_model = FIRST.Model.Check(data)
        tree_view = FIRST.Model.TreeView(depth=1)
        tree_view.setExpandsOnDoubleClick(False)
        tree_view.setIndentation(15)
        tree_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
        tree_view.setSelectionMode(QtWidgets.QAbstractItemView.SingleSelection)

        #   Setup the Model's header
        headers = [ ('Function', 'function name and address in this IDB', 0),
                    ('Prototype', 'function prototype', 1),
                    ('User', 'creator of the metadata', 2)]

        for display_name, tooltip, i in headers:
            item_header = QtGui.QStandardItem(display_name)
            item_header.setToolTip(tooltip)
            data_model.setHorizontalHeaderItem(i, item_header)

        #   Setup all other rows
        name_str = '0x{0.address:08x}: {0.name}'
        if not FIRST.Info.is_32bit():
            name_str = name_str.replace(':08x}', ':016x}')
        root_node = data_model.invisibleRootItem()
        cmp_func = lambda x,y: cmp(x.address, y.address)
        for match in sorted(data.values(), cmp=cmp_func):
            #   Row: <address and name> <prototype> <creator>
            name = QtGui.QStandardItem(name_str.format(match))
            prototype = QtGui.QStandardItem(match.prototype)
            prototype.setToolTip(match.prototype)
            creator = QtGui.QStandardItem(match.creator)
            creator.setToolTip(match.creator)

            info = [name, prototype, creator]

            #   Add row:
            #   Comment:
            #   (comment)
            comment = match.comment
            if not comment:
                comment = '- No Comment -'
            comment = QtGui.QStandardItem('Comment:\n' + comment)
            comment.setColumnCount(8)
            comment.setData(True, role=FIRSTUI.ROLE_COMMENT)
            comment_list = [comment] + ([QtGui.QStandardItem()] * 2)
            info[0].appendRow(comment_list)

            #   Mark all items noneditable and add id associated with the match
            for item in info + comment_list:
                item.setEditable(False)
                item.setData(match.id, role=FIRSTUI.ROLE_ID)
                item.setData(match.address, role=FIRSTUI.ROLE_ADDRESS)

            root_node.appendRow(info)

        tree_view.setModel(data_model)
        self.applied_data_model = data_model

        tree_view.setColumnWidth(0, 200)    #   Address and Function
        tree_view.setColumnWidth(1, 400)    #   Prototype
        tree_view.setColumnWidth(2, 20)     #   Author

        #   Keep a reference to the dialog so it doesn't hide before the
        #   user is done with it
        self.history_dialogs = []

        tree_view.setContextMenuPolicy(Qt.CustomContextMenu)
        tree_view.customContextMenuRequested.connect(self.applied_custom_menu)

        self.applied_tree_view = tree_view
        container.addWidget(self.applied_tree_view)

        return container

    def applied_custom_menu(self, point):
        index = self.applied_tree_view.indexAt(point)
        address = index.data(FIRSTUI.ROLE_ADDRESS)
        if not address:
            return

        menu = QtWidgets.QMenu(self.applied_tree_view)
        goto_action = QtWidgets.QAction('&Go to Function', self.applied_tree_view)
        goto_action.triggered.connect(lambda:IDAW.Jump(address))
        menu.addAction(goto_action)

        metadata_id = index.data(FIRSTUI.ROLE_ID)
        if metadata_id:
            history_action = QtWidgets.QAction('View &History', self.applied_tree_view)
            history_action.triggered.connect(lambda:self._metadata_history(metadata_id))
            menu.addAction(history_action)

        menu.exec_(QtGui.QCursor.pos())

    def _metadata_history(self, metadata_id):
        dialog = FIRSTUI.Dialog(None, FIRSTUI.History, metadata_id=metadata_id)
        dialog.show()

        #   Keep a reference to the dialog so it doesn't hide before the
        #   user is done with it
        self.history_dialogs.append(dialog)

    def populate_main_form(self):
        list_view = QtWidgets.QListView()
        list_view.setFixedWidth(115)
        list_view.setModel(self.views_model)

        select = QtCore.QItemSelectionModel.Select
        list_view.selectionModel().select(self.views_model.createIndex(0, 0), select)
        list_view.clicked.connect(self.view_clicked)

        current_view = QtWidgets.QWidget()
        view = self.view_about()
        if not view:
            view = QtWidgets.QBoxLayout()
        current_view.setLayout(view)

        self.splitter = QtWidgets.QSplitter(Qt.Horizontal)
        self.splitter.addWidget(list_view)

        self.splitter.addWidget(current_view)
        self.splitter.setChildrenCollapsible(False)
        self.splitter.show()

        outer_layout = QtWidgets.QHBoxLayout()
        outer_layout.addWidget(self.splitter)

        self.parent.setLayout(outer_layout)

    def view_clicked(self, index):
        key = self.views_model.data(index)

        if key in self.views_ui:
            #   Get the new view
            widget = QtWidgets.QWidget()
            layout = self.views_ui[key]()
            if not layout:
                layout = QtWidgets.QVBoxLayout()
            widget.setLayout(layout)

            #   Remove the old view to the splitter
            old_widget = self.splitter.widget(1)
            if old_widget:
                old_widget.hide()
                old_widget.deleteLater()

            self.splitter.insertWidget(1, widget)

    def check_function_accept(self, dialog):
        FIRST.Callbacks.accepted(self, dialog)

    def check_function(self, ctx):
        if not IDAW.get_func(IDAW.ScreenEA()):
            title = 'Unable to derive function'
            msg = ( 'Cannot upload function. Ensure the cursor is '
                    'positioned within a defined function (cursor '
                    'currently at 0x{0:X})').format(IDAW.ScreenEA())
            idaapi.execute_ui_requests((FIRSTUI.Requests.MsgBox(title, msg),))
            return

        dialog = FIRSTUI.Dialog(None, FIRSTUI.Check)
        dialog.registerSuccessCallback(self.check_function_accept)
        dialog.show()

    def check_all_function(self, ctx):
        dialog = FIRSTUI.Dialog(None, FIRSTUI.CheckAll)
        dialog.registerSuccessCallback(self.check_function_accept)
        dialog.show()

    def upload_func(self, ctx):
        dialog = FIRSTUI.Dialog(None, FIRSTUI.Upload)
        dialog.registerSuccessCallback(self.check_function_accept)
        dialog.show()

    def upload_all_func(self, ctx):
        dialog = FIRSTUI.Dialog(None, FIRSTUI.UploadAll)
        dialog.registerSuccessCallback(self.check_function_accept)
        dialog.show()

    def update_funcs(self, ctx):
        FIRST.Callbacks.Update()

        data = FIRST.Metadata.get_functions_with_applied_metadata()
        if data:
            title = 'FIRST: Updating Metadata for Functions'
            msg = ('There are {} functions with FIRST data. They are '
                    'being updated to reflect the most recent '
                    'metadata for each function.').format(len(data))
            idaapi.execute_ui_requests((FIRSTUI.Requests.MsgBox(title, msg, QtWidgets.QMessageBox.Information),))

    def view_history(self, ctx):
        function = IDAW.get_func(IDAW.ScreenEA())
        if not function:
            msg = '[1st] Unable to retrieve function at 0x{0:x}\n'.format(IDAW.ScreenEA())
            idaapi.execute_ui_requests((FIRSTUI.Requests.Print(msg),))
            return

        metadata = FIRST.Metadata.get_function(function.startEA)
        if not metadata:
            message = '[1st] Unable to retrieve function at 0x{0:x}\n'
            idaapi.execute_ui_requests((FIRSTUI.Requests.Print(message.format(metadata.address)),))
            return

        if not metadata.id:
            message = '[1st] No FIRST metadata is applied to the function at 0x{0:x}\n'
            idaapi.execute_ui_requests((FIRSTUI.Requests.Print(message.format(metadata.address)),))
            return

        dialog = FIRSTUI.Dialog(None, FIRSTUI.History, metadata_id=metadata.id)
        dialog.show()

class FIRST(object):
    debug = False

    #   About Information
    #------------------------
    VERSION = 'BETA'
    DATE = 'May 2018'
    BEGIN = 2014
    END = 2018

    plugin_enabled = False
    show_welcome = False

    server = None
    config = None
    config_path = os.path.join(idaapi.get_user_idadir(), 'first_beta.cfg')
    installed_hooks = []
    function_list = None
    plugin = None
    iat = []

    #   Colors used
    color_changed = QtGui.QBrush(QtGui.QColor.fromRgb(255, 153, 139))
    color_unchanged = QtGui.QBrush(QtGui.QColor.fromRgb(238, 238, 238))
    color_default = QtGui.QBrush(QtGui.QColor.fromRgb(255, 255, 255))
    color_selected = QtGui.QBrush(QtGui.QColor.fromRgb(160, 216, 241))
    color_applied = QtGui.QBrush(QtGui.QColor.fromRgb(214, 227, 181))


    @staticmethod
    def initialize():
        '''Initializes FIRST by installing hooks and populating required data
        strucutres.'''
        FIRST.installed_hooks = [FIRST.Hook.IDP(), FIRST.Hook.UI()]
        [x.hook() for x in FIRST.installed_hooks]
        FIRST.plugin = FIRST_FormClass()

    @staticmethod
    def cleanup_hooks():
        if FIRST.installed_hooks:
            for x in FIRST.installed_hooks:
                x.unhook()
            FIRST.installed_hooks = []


    class Error(Exception):
        '''FIRST Exception Class'''
        def __init__(self, value):
            self.value = value
        def __str__(self):
            return repr(self.value)


    class Metadata():
        '''Class containing Misc Metadata functions.

        Contains helper functions that will allow interaction with the memory
        list containing all functions within the IDB.

        This class contains only static methods and should be accessed as such.
        '''
        @staticmethod
        def get_non_jmp_wrapped_functions():
            '''Returns a list of functions addresses

            Functions definited in the IDB, from auto analysis or manually
            definited, are part of the list returned. Functions that are
            just wrappers with a jmp instruction are not included.

            Returns:
                list: Empty list or list of integer values

                The list of integer values correspond to a function's start
                address
            '''
            addresses = []
            for function_ea in IDAW.Functions():
                function = IDAW.get_func(function_ea)
                if function:
                    mnem = IDAW.GetMnem(function.startEA)
                    op_type = IDAW.GetOpType(function.startEA, 0)
                    if not (('jmp' == mnem) and (op_type == IDAW.o_mem)):
                        addresses.append(function.startEA)

            return addresses

        @staticmethod
        def get_segments_with_functions():
            '''Returns a list of segments with defined functions in it.

            Returns:
                list: Empty list or list of segment_t objects
            '''
            data = []

            if not FIRST.function_list:
                return None

            for segment_offset in FIRST.function_list:
                data.append(IDAW.getseg(segment_offset + IDAW.get_imagebase()))

            return data

        @staticmethod
        def get_segment_functions(segment):
            '''Returns functions for a given segment.

            Args:
                segment (`segment_t`): The segment functions will be returned
                    from. segment_t objects are returned from IDA's getseg API.

            Returns:
                list: Empty list or list of MetadataShim objects on success.

                None: None on failure.

                Fails if argument is not a segment_t or there are no functions
                in that segment.
            '''
            if not isinstance(segment, idaapi.segment_t):
                return None

            segment_offset = segment.startEA - IDAW.get_imagebase()
            if segment_offset not in FIRST.function_list:
                return None

            return FIRST.function_list[segment_offset].values()

        @staticmethod
        def populate_function_list():
            '''Initializes FIRST's function list

            This should be called to initialize the FIRST.function_list global
            variable, thus it should be called once IDA's auto analysis is
            complete to ensure it gets as many functions as possible.

            Base case: User loads up sample in IDA for first time or IDB is
            opened in IDA with FIRST for the first time action: create new
            function list, save, monitor for changes

            Complex case: User reopens an IDB that already has FIRST data in it
            action: extract function list from IDB, monitor for changes
            '''
            if None != FIRST.function_list:
                return

            FIRST.function_list = {}
            idaapi.show_wait_box('Initializing FIRST\'s cache')
            for address in FIRST.Metadata.get_non_jmp_wrapped_functions():
                function_name = IDAW.GetFunctionName(address)
                function = FIRST.MetadataShim(address, function_name)
                db_function = FIRST.DB.get_function(function=function)

                #   Function has not been saved to DB, create it and save it
                if not db_function:
                    #   If we failed to create a FIRSTMetadata object for the
                    #   address then skip it
                    if not function:
                        temp_str = 'Cannot create function at address {0:x}\n'
                        idaapi.execute_ui_requests((FIRSTUI.Requests.Print(temp_str.format(address)),))
                        continue

                    FIRST.DB.save(function)

                else:
                    function = db_function

                segment = function.segment
                if not segment:
                    temp_str = 'Cannot get function segment {0:x}\n'
                    idaapi.execute_ui_requests((FIRSTUI.Requests.Print(temp_str.format(function.address)),))
                    continue

                seg_offset = segment - IDAW.get_imagebase()
                if seg_offset not in FIRST.function_list:
                    FIRST.function_list[seg_offset] = {}

                FIRST.function_list[seg_offset][function.offset] = function

            idaapi.hide_wait_box()

        @staticmethod
        def get_function(function_address):
            '''Get the MetadataShim object for a given function.

            Args:
                function_address (`int`): A functions start address. The value
                    should be the start address of the function or else the
                    function will return None.

            Returns:
                MetadataShim: object on success.

                None on failure.
            '''
            if dict != type(FIRST.function_list):
                return None

            #   Ensure this is the start of a function and not just a repeatable
            #   label somewhere else
            function = IDAW.get_func(function_address)
            if (not function) or (function_address != function.startEA):
                return None

            #   Calculate offset to function from segment
            segment = IDAW.getseg(function.startEA)
            if not segment:
                return None
            seg_offset = segment.startEA - IDAW.get_imagebase()
            offset = function.startEA - segment.startEA

            if ((seg_offset not in FIRST.function_list)
                or (offset not in FIRST.function_list[seg_offset])):
                return None

            return FIRST.function_list[seg_offset][offset]

        @staticmethod
        def get_functions_with_applied_metadata():
            '''Returns a list of functions with FIRST metadata applied to it.

            Returns:
                list: Empty list or list of `MetadataShim` objects
            '''
            applied_metadata = []
            segments = FIRST.Metadata.get_segments_with_functions()
            if segments:
                for segment in segments:
                    functions = FIRST.Metadata.get_segment_functions(segment)
                    for function in functions:
                        if function.id:
                            applied_metadata.append(function)

            return applied_metadata


    class Info():
        '''Information gathering functions.

        Will get different information required by FIRST to interact with
        server or other plug-in side operations.

        This class contains only static methods and should be accessed as such.

        Attributes:
            processor_map (:obj:`dict`): Dictionary mapping between IDA's naming
                convention to FIRST's.
            include_bits (:obj:`list`): List of processors that should include
                the number of bits.
        '''
        processor_map = {'metapc' : 'intel'}
        include_bits = ['intel', 'arm']

        @staticmethod
        def set_file_details(md5, crc32, sha1=None, sha256=None):
            '''Sets details about the sample.

            This is a work around for situations where there is no original
            sample on disk that IDA analyzes. FIRST requires a MD5 and CRC32 to
            store functions, without it the function will not be saved.

            Args:
                md5 (:obj:`str`): Valid MD5 hash
            '''
            #   Validate User Input
            md5 = md5.lower()
            if not re.match(r'^[a-f\d]{32}$', md5) or type(crc32) != int:
                return

            db = IDAW.GetArrayId(FIRST_DB)
            key = FIRST_INDEX['hashes']
            if -1 == db:
                db = IDAW.CreateArray(FIRST_DB)

            #   Get hashes from file
            data = {'md5' : md5,
                    'sha1' : sha1,
                    'sha256' : sha256,
                    'crc32' : crc32}
            IDAW.SetArrayString(db, key, json.dumps(data))

            #   Update server class
            if FIRST.server and hasattr(FIRST.server, 'binary_info'):
                FIRST.server = FIRST.Server(FIRST.config, md5, crc32, sha1, sha256)


        @staticmethod
        def get_file_details():
            '''Returns details about the sample.

            The MD5 and CRC32 fields will always be returned since IDA Pro
            provides that information. If the IDB is created with the original
            sample then the sample will be hashed to get the SHA1 and SHA256.
            All tthe data is stored in the IDB to prevent getting the
            information multiple times.

            Returns:
                dict. Dictionary of file hashes and CRC32.
            '''
            db = IDAW.GetArrayId(FIRST_DB)
            key = FIRST_INDEX['hashes']
            if -1 != db:
                data = IDAW.GetArrayElement(IDAW.AR_STR, db, key)
                if 0 != data:
                    return json.loads(data)

            else:
                db = IDAW.CreateArray(FIRST_DB)

            #   Get hashes from file
            data = {'md5' : IDAW.GetInputMD5(),
                    'sha1' : None,
                    'sha256' : None,
                    'crc32' : IDAW.retrieve_input_file_crc32()}

            file_path = IDAW.GetInputFilePath()
            if file_path and exists(file_path):
                with open(file_path, 'rb') as f:
                    f_data = f.read()
                    data['sha1'] = sha1(f_data).hexdigest()
                    data['sha256'] = sha256(f_data).hexdigest()

                #   Store this in the IDB so it can be retrieved
                IDAW.SetArrayString(db, key, json.dumps(data))

            return data

        @staticmethod
        def is_32bit():
            '''Returns if the sample is 32bit or not.

            Returns:
                bool: True is 32bit or False.
            '''
            info = IDAW.get_inf_structure()
            if info.is_64bit():
                return False
            elif info.is_32bit():
                return True

            return False

        @staticmethod
        def get_architecture():
            '''Returns the architecture the sample is built for.

            The values are normalized for the FIRST server. It altered then
            FIRST will not match on other functions with the same architecture.

            Returns:
                str. String representation of the architecture associated with
                    the sample. Examples: intel32, intel64, arm32, mips, etc.
            '''
            info = IDAW.get_inf_structure()
            proc = info.procName.lower()
            proc = FIRST.Info.processor_map.get(proc, proc)

            if proc in FIRST.Info.include_bits:
                bits = 16
                if info.is_64bit():
                    bits = 64
                elif info.is_32bit():
                    bits = 32

                return '{}{}'.format(proc, bits)

            return proc

        @staticmethod
        def signature(address):
            '''Returns opcodes for the function the address is associated with.

            Given a virtual address, this function will return it in a series
            of bytes or None. The opcodes are ordered in address ascending
            order.

            Args:
                address (`int`): An address associated with a function. The
                    address can be any address within the function.

            Returns:
                str: A string of binary data on success.

                None: On failure.
            '''
            function = IDAW.get_func(address)
            blocks = {}
            #   Ensure address is in a function
            if not function:
                return None

            fc = IDAW.FlowChart(function)

            for block in fc:
                data = {'start' : block.startEA, 'end' : block.endEA}
                data['size'] = block.endEA - block.startEA
                data['bytes'] = IDAW.GetManyBytes(block.startEA, data['size'])

                if data['size'] > 0:
                    blocks[block.startEA] = data

            if not blocks:
                return None

            sig = ''
            for address in sorted(blocks.keys()):
                if 'bytes' in blocks[address]:
                    sig += blocks[address]['bytes']

            return sig

        @staticmethod
        def get_apis(address):
            '''Returns a list of all APIs used by a function.

            The address provided will be used to get a function and each
            instruction in the function is examined for APIs in the sample's
            IAT.

            Args:
                address (`int`): An address associated with a function. The
                    address can be any address within the function.

            Returns:
                list: Empty list or list of `MetadataShim` objects
            '''
            apis = []
            #   populate iat
            if not FIRST.iat:
                func = lambda ea, name, ord: FIRST.iat.append(name) == None
                imports = IDAW.get_import_module_qty()
                if imports:
                    for i in xrange(imports):
                        IDAW.enum_import_names(i, func)

            #   Cycle through all instructions within the function
            for instr in safe_generator(IDAW.FuncItems(address)):
                name = None
                if not IDAW.is_call_insn(instr):
                    instruction = IDAW.DecodeInstruction(instr)
                    if not instruction:
                        continue

                    for i in xrange(len(instruction.Operands)):
                        if IDAW.GetOpType(instr, i) == idaapi.o_mem:
                            name = IDAW.Name(IDAW.GetOperandValue(instr, i))
                            break

                else:
                    #   It is a call instruction
                    for xref in safe_generator(IDAW.XrefsFrom(instr, IDAW.XREF_FAR)):
                        if xref.to == None:
                            break

                        name = IDAW.NameEx(0, xref.to)

                if (name in FIRST.iat) and (name not in apis):
                    apis.append(name)

            return apis


    class DB():
        '''FIRST DB Class

        Provides functions to save data to and retrieve data from IDA's
        IDB backend. Additionally, it contains functions for calculating the
        index functions should be saved to in the IDB to provide constant time
        lookups.

        This class contains only static methods and should be accessed as such.

        Attributes:
            record_size (:obj:`int`): The number of bytes that can be saved into
                one index in the IDB's array. Once the number of bytes are hit
                the record is split and will continue in the next index.

                Note:
                    IDA enforces a hard limit of 1024, setting this value higher
                    than that will result in information loss.
            max_records (:obj:`int`): Determines how many array indices can be
                used to store data for a given function.

                Note:
                    If this number is increased and there is enough data to use
                    all the indices, this could result in over writting other
                    FIRST function data saved in the IDB.
        '''
        record_size = 1024
        max_records = 16
        @staticmethod
        def save(functions):
            '''Saves one or more functions to the IDB DB.

            This function can be used to save one or more FIRSTMetadata objects
            to the IDB's database.

            Args:
                functions (`FIRSTMetadata` or `list` of `FIRSTMetadata`)

            Returns:
                None
            '''
            if list != type(functions):
                functions = [functions]

            for function in functions:
                if not isinstance(function, FIRST.MetadataShim):
                    continue

                tag = FIRST.DB.get_tag(function)
                key = FIRST.DB.get_index(function)
                if None in [tag, key]:
                    continue

                max_str = hex(FIRST.DB.max_records)[2:]
                if (len(max_str) % 2) != 0:
                    max_str = '0' + max_str
                max_str = max_str.decode('hex')

                data = function.to_db()
                records = len(data) + len(max_str)
                records = int(math.ceil(records / float(FIRST.DB.record_size)))

                record_str = hex(records)[2:]
                if (len(record_str) % 2) != 0:
                    record_str = '0' + record_str
                record_str = record_str.decode('hex')

                start = FIRST.DB.record_size - len(max_str)
                IDAW.SetArrayString(tag, key, record_str + data[:start])
                if records > FIRST.DB.max_records:
                    temp_str = 'Cannot store data for function: {0}\n'
                    idaapi.execute_ui_requests((FIRSTUI.Requests.Print(temp_str.format(function.name)),))
                    continue

                for i in xrange(1, records):
                    begin = start + ((i + 1) * FIRST.DB.record_size)
                    end = begin + FIRST.DB.record_size
                    IDAW.SetArrayString(tag, key + i, data[begin:end])

        @staticmethod
        def get_function(address=None, function=None):
            '''Retrieves function and all its details from the IDB DB.

            The data returned here may not match the current state of the IDB.
            Either the address or function argument should be provided.
            Providing neither will result in a return value of None.

            Args:
                address (`int`, optional): The start address of the function.
                function (:obj:`MetadataShim`, optional): The current
                    MetadataShim object for the function.

            Returns:
                FIRSTMetadata: If function exits and is saved it is returned.

                None: On failure.
            '''
            if isinstance(function, FIRST.MetadataShim):
                address = function.address

            elif None != address:
                function = FIRST.MetadataShim(address)

            else:
                return None

            tag = FIRST.DB.get_tag(function)
            key = FIRST.DB.get_index(function)

            if None in [tag, key]:
                return None

            max_str = hex(FIRST.DB.max_records)[2:]
            if (len(max_str) % 2) != 0:
                max_str = '0' + max_str
            max_str = max_str.decode('hex')

            first = IDAW.GetArrayElement(IDAW.AR_STR, tag, key)
            if not first:
                return None

            data = first[len(max_str):]
            records = 0
            for r in first[:len(max_str)]:
                records = (records << 16) | ord(r)

            for i in xrange(1, records):
                new_data = IDAW.GetArrayElement(IDAW.AR_STR, tag, key + i)
                if 0 == new_data:
                    break

                data += new_data

            function.from_db(data)
            return function

        @staticmethod
        def get_tag(function):
            '''Calculates and returns the tag for the given function.

            Function that will return array id corresponding to the array with
            the function data in it if the array exists. If the array does not
            exist then it is created and the created array id is returned.

            Args:
                function (:obj:`MetadataShim`): The function to get a tag for.

            Results:
                int: The array ID on success.

                None: On failure.
            '''
            if not isinstance(function, FIRST.MetadataShim):
                return None

            array_str = 'FIRST_{0}'.format(function.segment - IDAW.get_imagebase())
            tag = IDAW.GetArrayId(array_str)
            if -1 == tag:
                #   The array doesn't exist, create it
                tag = IDAW.CreateArray(array_str)
                if -1 == tag:
                    return None

            return tag

        @staticmethod
        def get_index(function):
            '''Computes the base index for the function.

            The index computed by thios function is index into an IDB array.

            Args:
                function (:obj:`MetadataShim`): The function to get an index
                    for.

            Results:
                int: The index into the array.

                None: On failure.
            '''
            if not isinstance(function, FIRST.MetadataShim):
                return None

            return function.offset << 4


    class MetadataShim(object):
        '''Shim between interacting with various IDA components and FIRST.

        FIRST Metadata Container provides thin shim for interacting with
        function and affecting IDA's UI. Changes made from FIRST are updated in
        the UI and IDA's IDB DB.

        When creating a MetadataShim instance, at least the address should be
        provided to the constructor. However, it can be useful to create an
        empty object and populate if with data by calling its ``from_db``
        method.

        Args:
            address (:obj:`int`, optional): The VA of the function.
            name (:obj:`str`, optional): The original name of the function. This
                should be used to set an original baseline for the function. The
                default name (sub_X, where X is the function start VA) can be
                overwritten if this is set.
            creator (:obj:`str`, optional): The creator's handle

        Examples:
            Creating MetadataShim instance from function.

            >>> m1 = MetadataShim(address=0x401000)

            Creating MetadataShim instance from function and setting original
            name.

            >>> m2 = MetadataShim(address=0x401e40, name='memcpy')

            Creating MetadataShim instace from a function with a creator.

            >>> m3 = MetadataShim(address=0x401330, creator='demonduck#1337')
        '''
        def __init__(self, address=0, name='', creator=None):
            self.__address = address
            self.__original_name = name
            self.__changed = False
            self.__id = None
            self.__author = creator

            self.__data = None
            self.__signature = None
            self.__apis = None

            self.__snapshots = {}

        def __eq__(self, other):
            if not isinstance(other, FIRST.MetadataShim):
                if isinstance(other, FIRST.MetadataServer):
                    return other == self
                return False

            return ((self.segment == other.segment)
                    and (self.offset == other.offset)
                    and (self.name == other.name)
                    and (self.prototype == other.prototype)
                    and (self.comment == other.comment))

        def snapshot(self):
            '''Saves off current function annotations

            Preserves the function name, comment, prototype and FIRST ID
            currently associated with the function. This will be used to
            compare with to detect future changes.
            '''
            data = {
                'name' : self.name,
                'comment' : self.comment,
                'prototype' : self.prototype,
                'id' : self.id
            }

            self.__snapshots = data

        def apply_metadata(self, data):
            '''Applies metadata to the function.

            The metadata will be applied and become visable in IDA Pro. Updates
            sample's IDB DB with the new function annotations.

            Args:
                data (:obj:`MetadataServer`): The metadata result from FIRST
                    server.
            '''

            if not isinstance(data, FIRST.MetadataServer):
                return

            #   Set function name
            self.name = data.name

            #   Set function repeatable comment
            self.comment = data.comment

            #   Set function prototype
            self.prototype = data.prototype

            #   Set applied id
            self.id = data.id

            #   Set the author of the metadata
            self.creator = data.creator

            self.update_db(False)

        @property
        def id(self):
            ''':obj:`str`: The FIRST ID associated with the function.'''
            return self.__id

        @id.setter
        def id(self, first_id):
            self.__id = first_id

        @property
        def creator(self):
            ''':obj:`str`: The handle of the annotation creator.'''
            return self.__author

        @creator.setter
        def creator(self, author):
            self.__author = author

        @property
        def address(self):
            ''':obj:`int`: The virtual address associated with the function.'''
            return self.__address

        @address.setter
        def address(self, address):
            if type(address) not in [int, long]:
                return

            self.__address = address

        @property
        def name(self):
            ''':obj:`str`: The name of the function'''
            return IDAW.GetFunctionName(self.__address)

        @name.setter
        def name(self, name):
            #   If name starts with 'sub_' then this will cause an error in
            #   IDA with enough errors it'll crash/hang errors
            if (None == name) or name.startswith('sub_'):
                return

            IDAW.MakeName(self.address, name.encode('utf-8'))

        def update_name(self):
            '''Updates IDB DB if name has changed since last snapshot.'''
            if self.name != self.__snapshots['name']:
                self.update_db(True)

        @property
        def original_name(self):
            ''':obj:`str`: The orginal name of the function.

            Unfortunately, this is a best guess. If the function has been
            detected as a library function by IDA then we use the current name
            since there is no way to get any of the previous names it might have
            had. If it is not a library function then the original name is
            sub_X, where X is the VA of the function.

            Returns:
                str: The original name of the function.
            '''
            if self.is_lib:
                self.__original_name

            return 'sub_{0:X}'.format(self.address)

        @original_name.setter
        def original_name(self, name):
            if self.is_lib:
                self.__original_name = name

        @property
        def comment(self):
            ''':obj:`str`: The repeatable comment associated with the function.

            Returns only the first 1024 bytes of the comment. If a comment is
            longer than that, then it will be truncated to 1024. This mean data
            could be lost.

            Returns:
                str: The function's repeatable comment
            '''
            function = IDAW.get_func(self.address)
            if function:
                comment = IDAW.get_func_cmt(function, 1)
                if comment:
                    return comment[:1024]

            return ''

        @comment.setter
        def comment(self, comment_str):
            if None == comment_str:
                return

            IDAW.SetFunctionCmt(self.address, comment_str.encode('utf-8'), 1)

        def update_comment(self):
            '''Updates IDB DB if comment has changed since last snapshot.'''
            if self.comment != self.__snapshots['comment']:
                self.update_db(True)

        @property
        def prototype(self):
            ''':obj:`str`: The prototype of the function'''
            prototype = IDAW.GetType(self.address)

            if not prototype:
                prototype = ''

            return prototype

        @prototype.setter
        def prototype(self, prototype_str):
            if None == prototype_str:
                return

            prototype_str = prototype_str.encode('utf-8')

            if prototype_str:
                prototype_str += ';'

            if not IDAW.SetType(self.address, prototype_str):
                IDAW.SetType(self.address, prototype_str.replace('(', ' f('))

        def update_prototype(self):
            '''Updates IDB DB if prototype has changed since last snapshot.'''
            if self.prototype != self.__snapshots['prototype']:
                self.update_db(True)

        @property
        def segment(self):
            ''':obj:`int`: The start address of the function's segment.

            Returns None if no segment can be retrieved
            '''
            segment = IDAW.getseg(self.__address)
            if segment:
                return segment.startEA

            return None

        @property
        def offset(self):
            ''':obj:`int`: The function offset from the start of the segment.'''
            return self.address - self.segment

        @property
        def created(self):
            ''':obj:`bool`: True if the annotations were created by user.'''
            return self.creator == None

        @property
        def is_lib(self):
            ''':obj:`bool`: True if function is a library function.'''
            function = IDAW.get_func(self.__address)
            return function and ((function.flags & IDAW.FUNC_LIB) != 0)

        @property
        def has_changed(self):
            ''':obj:`bool`: True if function metadata has changed.'''
            return self.__changed

        @has_changed.setter
        def has_changed(self, changed):
            self.__changed = changed

        @property
        def signature(self):
            ''':obj:`str`: The opcodes associated with the function.'''
            if not self.__signature:
                self.__signature = FIRST.Info.signature(self.address)

            return self.__signature

        @property
        def apis(self):
            ''':obj:`list`: The APIs called by the function.'''
            if not self.__apis:
                self.__apis = FIRST.Info.get_apis(self.address)

            return self.__apis

        def update_db(self, changed):
            '''Updates the IDB DB with FIRST identifiers.'''
            #   The function name was changed
            self.__changed = changed
            if changed and (self.creator != None):
                #   If the creator is set then another person created the
                #   signature. Clear the author and id to allow it to be
                #   added to FIRST as the current users creation
                self.creator = None
                self.id = None

            FIRST.DB.save(self)

        def to_db(self):
            '''Provides data structure for the IDB's DB.

            Returns:
                dict: FIRST information for the DB.

                    {
                        'offset' : :obj:`int`,

                        'original_name' : :obj:`str`,

                        'author' : :obj:`str`,

                        'id' : :obj:`str`,

                        'changed' : :obj:`bool`
                    }

            '''
            data = {
                    'offset' : self.offset,
                    'original_name' : self.original_name,
                    'author' : self.creator,
                    'id' : self.id,
                    'changed' : self.has_changed
                   }

            return json.dumps(data)

        def from_db(self, data_str):
            '''Converts IDB DB data to MetadataShim object.

            Args:
                data_str (`str`): JSON data in a string. JSON data keys
                    required: author, changed, original_name, offset, id.
            '''
            required = ['author', 'changed', 'original_name', 'offset', 'id']

            try:
                self.__data = json.loads(data_str)
                if set(required).issubset(self.__data.keys()):
                    if self.offset != self.__data['offset']:
                        msg = 'Incorrect offsets {0:x} != {1:x}\n'.format(
                                        self.offset, self.__data['offset'])
                        idaapi.execute_ui_requests((FIRSTUI.Requests.Print(msg),))
                        return

                    #   The below data is not saved by IDA, needs to restored
                    self.creator = self.__data['author']
                    self.has_changed = self.__data['changed']
                    self.original_name = self.__data['original_name']
                    self.id = self.__data['id']

            except TypeError:
                msg = ('TypeError: Could not load function data '
                        '(FIRST.MetadataShim.from_db)\n')
                idaapi.execute_ui_requests((FIRSTUI.Requests.Print(msg),))


    class MetadataServer(object):
        '''Class to contain a FIRST match and its data.

        FIRST Metadata container, it encapsulates the data received from the
        FIRST server.

        Args:
            data (:obj:`dict`): Dictionary with the following key values set:
                name, prototype, creator, id, comment, rank
            address (:obj:`int`): The VA associated with the function the
                instance refers to.
            engine_info (:obj:`dict`): Dictionary with engine names mapping to
                the engine's description.

        Raises:
            FIRST.Error: If data is not a :obj:`dict` or does not have the
                required keys.
        '''
        def __init__(self, data, address=None, engine_info=None):
            error_str = 'Cannot encapsulate server metadata'
            required = ['name', 'prototype', 'creator', 'id', 'comment', 'rank']

            if (dict != type(data) or not set(required).issubset(data.keys())):
                raise FIRST.Error(error_str)

            self.__data = data
            self.__address = address
            self.__engines = engine_info

            self.__id = data['id']
            self.__name = data['name']
            self.__rank = data['rank']
            self.__creator = data['creator']
            self.__comment = data['comment']
            self.__prototype = data['prototype']
            self.__similarity = 0

            if 'similarity' in data:
                self.__similarity = data['similarity']

        def __eq__(self, other):
            if not isinstance(other, FIRST.MetadataShim):
                return False

            return ((self.name == other.name)
                    and (self.prototype == other.prototype)
                    and (self.comment == other.comment)
                    and (self.id == other.id)
                    and (self.creator == other.created))

        @property
        def address(self):
            ''':obj:`int`: The virtual address associated with the function.'''
            return self.__address

        @property
        def name(self):
            ''':obj:`str`: The name of the function'''
            return self.__name

        @property
        def prototype(self):
            ''':obj:`str`: The prototype of the function'''
            if not self.__prototype:
                return ''

            return self.__prototype

        @property
        def comment(self):
            ''':obj:`str`: The comment associated with the function.'''
            if not self.__comment:
                return ''

            return self.__comment

        @property
        def creator(self):
            ''':obj:`str`: The handle of the annotation creator.'''
            return self.__creator

        @property
        def id(self):
            ''':obj:`str`: The FIRST ID associated with this metadata.'''
            return self.__id

        @property
        def rank(self):
            ''':obj:`int`: The number of unqiue applies of this metadata.'''
            return self.__rank

        @property
        def similarity(self):
            ''':obj:`float`: The percentage of similarity between this function
                and the original queried for function. This value can be very
                rough estimate depending on the engine.'''
            return self.__similarity

        @property
        def engine_info(self):
            ''':obj:`dict`: The mapping from engine name to its description.'''
            if not self.__engines:
                return {}

            return self.__engines


    class Configuration(object):
        '''Class containing configuration details for FIRST.

        Args:
            config (:obj:`RawConfigParser`): Configuration details for plugin.
        '''
        def __init__(self, config=None):
            self.__server = 'first.talosintelligence.com'
            self.__port = 80
            self.__protocol = 'http'
            self.__verify = False
            self.__auth = False
            self.__api_key = ''
            self.__data = {}

            #   Load configuration
            if isinstance(config, ConfigParser.RawConfigParser):
                self.load_config(config)

        @property
        def server(self):
            ''':obj:`str`: The FIRST server.'''
            return self.__server

        def set_server(self, _server):
            self.__server = _server

        @property
        def port(self):
            ''':obj:`int`: The FIRST server port (Default: 80)'''
            if isinstance(self.__port, int):
                return self.__port

            try:
                return int(self.__port)
            except ValueError:
                return 80

        def set_port(self, _port):
            self.__port = _port

        @property
        def protocol(self):
            ''':obj:`str`: The TCP protocol used to communicate with FIRST.'''
            return self.__protocol

        def set_protocol(self, _protocol):
            self.__protocol = _protocol

        @property
        def auth(self):
            ''':obj:`HTTPKeberosAuth`: Authenication used with FIRST
            (default: None).'''
            return self.__auth

        @property
        def authentication(self):
            ''':obj:`bool`: Flag set if authentication is used in connection.'''
            return self.__auth == True

        @property
        def verify(self):
            ''':obj:`bool`: Whether the SSL cert will be verified.'''
            return self.__verify == True

        def set_verify(self, _verify):
            self.__verify = _verify

        def set_authentication(self, _authentication):
            self.__auth = _authentication

        @property
        def api_key(self):
            ''':obj:`str`: The user's API key.'''
            return self.__api_key

        def set_api_key(self, key):
            self.__api_key = key

        def set_data(self, key, value):
            '''Sets a specific configuration setting.

            Args:
                key (:obj:`str`): The configuration setting.
                value (:obj:`str`): The configuration setting value.
            '''
            self.__data[key] = value

        def save_config(self, config_path):
            '''Saves the configuration set in this instance to disk.

            Args:
                config_path (:obj:`str`): File path to save configuration.
            '''
            config = ConfigParser.RawConfigParser()

            section = 'connection_info'
            values = {  'server' : self.server, 'port' : self.port,
                        'protocol' : self.protocol, 'verify' : self.verify,
                        'authentication' : self.authentication,
                        'api_key' : self.api_key}

            config.add_section(section)
            for option, value in values.iteritems():
                config.set(section, option, value)

            if len(self.__data):
                section = 'settings'
                config.add_section(section)
                for option, value in self.__data.iteritems():
                    config.set(section, option, value)

            try:
                with open(config_path, 'wb') as f:
                    config.write(f)
            except IOError as e:
                idaapi.execute_ui_requests((FIRSTUI.Requests.Print(str(e) + '\n'),))

        def load_config(self, config):
            '''Loads configuration details into this instance.

            Args:
                config (:obj:`RawConfigParser`): The configuration details to
                    load.
            '''
            if not isinstance(config, ConfigParser.RawConfigParser):
                return

            self.__data = {}

            #   Set connection information
            section = 'connection_info'
            if config.has_section(section):
                required = {'server' : self.set_server, 'port' : self.set_port,
                            'verify' : self.set_verify,
                            'protocol' : self.set_protocol,
                            'authentication' : self.set_authentication,
                            'api_key' : self.set_api_key}

                for option, set_function in required.iteritems():
                    if config.has_option(section, option):
                        set_function(config.get(section, option))

                section = 'settings'
                if config.has_section(section):
                    for option in config.options(section):
                        self.__data[option] = config.get(section, option)


    class Server(object):
        '''Encapsulate interacting with the FIRST server's REST API.

        Note:
            Using functions ``set_protocol``, ``set_server``, and ``set_port``
            do not update the configuration details, just the server instance
            represented with this class.


        Attributes:
            urn (:obj:`str`): URL format string.
            paths (:obj:`dict`): Mapping between operations and FIRST URI path
                format strings.
            MAX_CHUNK (:obj:`int`): The maximum number of entries sent to the
                server. Default: 20

                Note:
                    The FIRST server can set the max number of entries received.
                    If this value is greater than the server's then the server
                    will not perform the operation.

            Args:
                config (:obj:`Configuration`): FIRST configuration information.
                h_md5 (:obj:`str`): The MD5 of the sample.
                crc32 (:obj:`int`): The CRC32 of the sample.
                h_sha1 (:obj:`str`, optional): The SHA1 of the sample.
                h_sha256 (:obj:`str`, optional): The SHA256 of the sample.

        '''
        MAX_CHUNK = 20
        urn = '{0.protocol}://{0.server}:{0.port}/{1}'
        paths = {
                    #   Test Connection URL
                    'test' : 'api/test_connection/{0[api_key]}',

                    'checkin' : 'api/sample/checkin/{0[api_key]}',

                    #   Metadata URLs
                    'add' : 'api/metadata/add/{0[api_key]}',
                    'history' : 'api/metadata/history/{0[api_key]}',
                    'applied' : 'api/metadata/applied/{0[api_key]}',
                    'unapplied' : 'api/metadata/unapplied/{0[api_key]}',
                    'delete' : 'api/metadata/delete/{0[api_key]}/{0[id]}',
                    'created' : 'api/metadata/created/{0[api_key]}/{0[page]}',
                    'get' : 'api/metadata/get/{0[api_key]}',

                    #   Scan URLs
                    'scan' : 'api/metadata/scan/{0[api_key]}',
        }

        def __init__(self, config, h_md5, crc32, h_sha1=None, h_sha256=None):
            self.error_log = []
            self.threads = {}
            self.checkedin = False
            self.binary_info = {'md5' : h_md5, 'crc32' : crc32,
                                'sha1' : h_sha1, 'sha256' : h_sha256}

            self.auth, self.server, self.protocol = [None] * 3
            self.port, self.verify, self.api_key = [None] * 3
            if isinstance(config, FIRST.Configuration):
                self.auth = config.authentication
                self.server = config.server
                self.protocol = config.protocol
                self.port = config.port
                self.verify = config.verify
                self.api_key = config.api_key

        def set_port(self, port):
            '''Overrides the FIRST server port set in the configuration.

            Args:
                port (:obj:`int`): The FIRST server port.
            '''
            self.checkedin = False
            self.port = port

        def set_protocol(self, protocol):
            '''Overrides the FIRST server protocol set in the configuration.

            Args:
                protocol (:obj:`int`): The FIRST server protocol.
            '''
            self.checkedin = False
            self.protocol = protocol

        def set_server(self, server):
            '''Overrides the FIRST server set in the configuration.

            Args:
                port (:obj:`int`): The FIRST server.
            '''
            self.checkedin = False
            self.server = server

        def checkin(self, action):
            '''Checks in with FIRST server to ensure annotations can be added.

            This function must be called before any annotations are added to
            FIRST. This function allows the FIRST server to setup information
            about the sample, thereby allowing functions to be associated with
            the sample. This only needs to be called once and is attempted
            before the first user selected operation.

            This operation is not done if the operation to be performed is to
            test the connection to the server.

            Args:
                action (:obj:`str`): The FIRST operation to be performed
            '''
            if self.checkedin or action == 'test':
                return

            self.checkedin = True

            response = self._sendp('checkin', self.binary_info)
            if (not response
                or (('failed' in response) and response['failed'])
                or (('checkin' in response) and not response['checkin'])):
                #   Try to check in again with the next sever communication
                self.checkedin = False
                return

        def _sendp(self, action, params={}, raw=False):
            self.checkin(action)

            if action not in self.paths:
                return None

            #   Ensure all None values are converted to empty strings
            for key in params:
                if params[key] is None:
                    params[key] = ''

            authentication = None
            if self.auth:
                if not HTTPKerberosAuth:
                    idaapi.execute_ui_requests((FIRSTUI.Requests.Print('[1st] Kerberos module is not loaded\n'),))
                    return

                authentication = HTTPKerberosAuth()

            url = self.urn.format(self, self.paths[action])
            if FIRST.debug:
                idaapi.execute_ui_requests(
                    (FIRSTUI.Requests.Print(
                        '[POST] {}\nSending: '.format(url.format(self._user()))),)
                )
                pprint(params)

            try:
                response = requests.post(url.format(self._user()),
                                            data=params,
                                            verify=self.verify,
                                            auth=authentication)

                if raw:
                    return response

            except requests.exceptions.ConnectionError as e:
                title = 'Cannot connect to FIRST'
                msg = ('Unable to connect to FIRST server at {0}\n'
                        'Retry operation').format(self.server)
                idaapi.execute_ui_requests((FIRSTUI.Requests.MsgBox(title, msg),))
                raise FIRST.Error('cannot connect')

            except requests.exceptions.Timeout as e:
                title = 'Cannot connect to FIRST'
                msg = ( 'Unable to connect to FIRST server at {0}. '
                        'Connection timed out.').format(self.server)
                idaapi.execute_ui_requests((FIRSTUI.Requests.MsgBox(title, msg),))
                return

            if FIRST.debug:
                print response
                if 'content' in dir(response):
                    print response.content

            if 'status_code' not in dir(response):
                return None
            elif 200 != response.status_code:
                return None

            #idaapi.execute_ui_requests((FIRSTUI.Requests.Print('Server Raw Response:'),
            #                    (FIRSTUI.Requests.Print(response)))
            #try:
            #    pprint(response.text)
            #except:
            #    pass

            response = self.to_json(response)
            if FIRST.debug:
                idaapi.execute_ui_requests((FIRSTUI.Requests.Print('Server Response:'),))
                pprint(response)

            return response

        def _sendg(self, action, params={}, raw=False):
            self.checkin(action)

            if action not in self.paths:
                return None

            #   Ensure all None values are converted to empty strings
            for key in params:
                if params[key] is None:
                    params[key] = ''

            params.update(self._user())
            #idaapi.execute_ui_requests((FIRSTUI.Requests.Print('[GET] Sending: '),))
            #pprint(params)

            authentication = None
            if self.auth:
                if not HTTPKerberosAuth:
                    idaapi.execute_ui_requests((FIRSTUI.Requests.Print('[1st] Kerberos module is not loaded\n'),))
                    return

                authentication = HTTPKerberosAuth()

            url = self.urn.format(self, self.paths[action])
            try:
                response = requests.get(url.format(params),
                                            verify=self.verify,
                                            auth=authentication)

                if raw:
                    return response

            except requests.exceptions.ConnectionError as e:
                title = 'Cannot connect to FIRST'
                msg = ('Unable to connect to FIRST server at {0}\n'
                        'Retry operation').format(self.server)
                idaapi.execute_ui_requests((FIRSTUI.Requests.MsgBox(title, msg),))
                raise FIRST.Error('cannot connect')

            except requests.exceptions.Timeout as e:
                title = 'Cannot connect to FIRST'
                msg = ( 'Unable to connect to FIRST server at {0}. '
                        'Connection timed out.').format(self.server)
                idaapi.execute_ui_requests((FIRSTUI.Requests.MsgBox(title, msg),))
                return

            if 'status_code' not in dir(response):
                return None
            elif 200 != response.status_code:
                return None

            #idaapi.execute_ui_requests((FIRSTUI.Requests.Print('Server Raw Response:'),
            #                    FIRSTUI.Requests.Print(response))
            #try:
            #    pprint(response.text)
            #except:
            #    pass

            response = self.to_json(response)
            #idaapi.execute_ui_requests((FIRSTUI.Requests.Print('Server Response:'),))
            #pprint(response)

            return response

        def to_json(self, response):
            '''Converts Requests' response object to json.

            Args:
                response (:obj:`requests.models.Response`): A request response.

            Returns:
                dict: JSON data or empty dictionary.
            '''
            try:
                return response.json()
            except:
                return {}

        def _user(self):
            return {'api_key' : self.api_key}

        def _min_info(self):
            return {'md5' : self.binary_info['md5'],
                    'crc32' : self.binary_info['crc32']}

        def stop_operation(self, server_thread):
            '''Signals a server thread to stop its work.

            Args:
                server_thread (:obj:`threading.Thread`): The thread to stop.
            '''
            if server_thread not in self.threads:
                return

            self.threads[server_thread]['stop'] = True
            self.threads[server_thread]['complete'] = True

        def remove_operation(self, server_thread):
            '''Removes operation from server thread structure.

            Args:
                server_thread (:obj:`threading.Thread`): The thread to remove.
            '''
            if server_thread in self.threads:
                del self.threads[server_thread]

        #   Test connection URL
        def test_connection(self):
            '''Interacts with server to see if there is a valid connection.

            This is a short operation and is a blocking call.

            Returns:
                bool: True if connection can be made and FIRST returns a
                    success message. False otherwise.
            '''
            if not self.api_key:
                return False

            try:
                data = self._sendg('test', {'api_key' : self.api_key})
            except FIRST.Error as e:
                data = None

            return data and ('status' in data) and ('connected' == data['status'])

        #   Signature URLS
        def add(self, metadata, data_callback=None, complete_callback=None):
            '''Adds function metadata to FIRST.

            This is a long operation, thus it has the option of providing a
            ``data_callback`` and ``complete_callback`` arguments. Those
            arguments are functions that will be called with the newly returned
            data and when the whole operation is complete, respectively. Both
            functions should follow the below their respective prototypes;
            ``data_callback_prototype`` and ``complete_callback_prototype``.

            Args:
                metadata (:obj:`list` of :obj:`MetadataShim` or
                    :obj:`MetadataShim`): The metadata to be added to FIRST.
                data_callback (:obj:`data_callback_prototype`, optional):
                    A function to call when data is receieved from the server.
                complete_callback (:obj:`complete_callback_prototype`, optional):
                    A function to call when the whole long operation completes.

            Returns:
                threading.Thread. The thread created for the operation.
            '''
            args = (metadata, data_callback, complete_callback)
            thread = threading.Thread(target=self.__thread_add, args=args)
            thread.daemon = True
            thread.start()
            return thread

        def __thread_add(self, metadata, data_callback=None, complete_callback=None):
            '''thread'''
            thread = threading.current_thread()
            self.threads[thread] = {'results' : [], 'complete' : False,
                                    'stop' : False}

            if isinstance(metadata, FIRST.MetadataShim):
                metadata = [metadata]

            if False in [isinstance(m, FIRST.MetadataShim) for m in metadata]:
                self.threads[thread]['complete'] = True
                if complete_callback:
                    complete_callback(thread, self.threads[thread])

                return

            architecture = FIRST.Info.get_architecture()
            for i in xrange(0, len(metadata), self.MAX_CHUNK):
                params = self._min_info()
                data = {}
                for m in metadata[i:i + self.MAX_CHUNK]:
                    data[m.address] = { 'architecture' : architecture,
                                        'opcodes' : b64encode(m.signature),
                                        'name' : m.name,
                                        'prototype' : m.prototype,
                                        'comment' : m.comment,
                                        'apis' : m.apis,
                                        'id' : m.id}

                params['functions'] = json.dumps(data)
                try:
                    response = self._sendp('add', params)
                except FIRST.Error as e:
                    self.threads[thread]['complete'] = True
                    if complete_callback:
                        complete_callback(thread, self.threads[thread])
                    return

                if response:
                    self.threads[thread]['results'].append(response)
                    if data_callback:
                        data_callback(thread, response)

                if self.threads[thread]['stop']:
                    break

            self.threads[thread]['complete'] = True
            if complete_callback:
                complete_callback(thread, self.threads[thread])

        def history(self, metadata):
            '''Gets annotation history from FIRST.

            This is a short operation and is a blocking call.

            Args:
                metadata (:obj:`MetadataShim` or :obj:`MetadataServer`): The
                    FIRST annotation the history is being requested.

            Returns:
                dict: JSON data returned from server. None on failure.
            '''
            if (isinstance(metadata, FIRST.MetadataShim)
                or isinstance(metadata, FIRST.MetadataServer)):
                metadata = metadata.id

            try:
                response = self._sendp('history', {'metadata' : json.dumps([metadata])})
            except FIRST.Error as e:
                return None

            return response

        def applied(self, metadata_id):
            '''Sets a FIRST annotation as applied to this sample.

            This is a short operation and is a blocking call.

            Args:
                metadata_id (:obj:`str`): The FIRST annotation ID.

            Returns:
                dict: JSON data returned from the server. None on failure.
            '''
            params = self._min_info()
            params['id'] = metadata_id

            try:
                response = self._sendp('applied', params)
            except FIRST.Error as e:
                return None

            return response

        def unapplied(self, metadata_id):
            '''Sets a FIRST annotation as unapplied to this sample.

            This is a short operation and is a blocking call.

            Args:
                metadata_id (:obj:`str`): The FIRST annotation ID.

            Returns:
                dict: JSON data returned from the server. None on failure.
            '''
            params = self._min_info()
            params['id'] = metadata_id

            try:
                response = self._sendp('unapplied', params)
            except FIRST.Error as e:
                return None

            return response

        def delete(self, metadata_id):
            '''Deletes a FIRST annotation created by the user.

            This is a short operation and is a blocking call.

            Args:
                metadata_id (:obj:`str`): The FIRST annotation ID.

            Returns:
                dict: JSON data returned from the server. None on failure.
            '''
            params = {'id' : metadata_id}

            try:
                response = self._sendg('delete', params)
            except FIRST.Error as e:
                return None

            return response

        def created(self, data_callback=None, complete_callback=None):
            '''Retrieves FIRST annotations the user has created.

            This is a long operation, thus it has the option of providing a
            ``data_callback`` and ``complete_callback`` arguments. Those
            arguments are functions that will be called with the newly returned
            data and when the whole operation is complete, respectively. Both
            functions should follow the below their respective prototypes;
            ``data_callback_prototype`` and ``complete_callback_prototype``.

            Args:
                data_callback (:obj:`data_callback_prototype`, optional):
                    A function to call when data is receieved from the server.
                complete_callback (:obj:`complete_callback_prototype`, optional):
                    A function to call when the whole long operation completes.

            Returns:
                threading.Thread. The thread created for the operation.
            '''
            args = (data_callback, complete_callback)
            thread = threading.Thread(target=self.__thread_created, args=args)
            thread.daemon = True
            thread.start()
            return thread

        def __thread_created(self, data_callback=None, complete_callback=None):
            '''Thread to get created data'''
            thread = threading.current_thread()
            self.threads[thread] = {'results' : [], 'complete' : False,
                                    'stop' : False}
            page = 1
            total_pages = 0
            first_time = True
            while (first_time
                    or ((page <= total_pages) and (not self.threads[thread]['stop']))):
                if first_time:
                    first_time = False

                try:
                    response = self._sendg('created', {'page' : page})
                except FIRST.Error as e:
                    self.threads[thread]['complete'] = True
                    if complete_callback:
                        complete_callback(thread, self.threads[thread])

                if not response:
                    continue

                if 'pages' in response:
                    total_pages = response['pages']

                #   Print out page data very 10 percent
                ten_percent = total_pages / 10.0
                if (not ten_percent) or (0 == (page % ten_percent)):
                    idaapi.execute_ui_requests((FIRSTUI.Requests.Print('{} out of {} pages\n'.format(page, total_pages)),))

                if ('results' in response) and response['results']:
                    metadata = response['results']
                    data = [FIRST.MetadataServer(x, x['id']) for x in metadata]
                    self.threads[thread]['results'].append(data)
                    if data_callback:
                        data_callback(thread, data)

                page += 1

            self.threads[thread]['complete'] = True
            if complete_callback:
                complete_callback(thread, self.threads[thread])

        def get(self, metadata_ids, data_callback=None, complete_callback=None):
            '''Retrieves FIRST annotations the user has created.

            This is a long operation, thus it has the option of providing a
            ``data_callback`` and ``complete_callback`` arguments. Those
            arguments are functions that will be called with the newly returned
            data and when the whole operation is complete, respectively. Both
            functions should follow the below their respective prototypes;
            ``data_callback_prototype`` and ``complete_callback_prototype``.

            Args:
                metadata (:obj:`list` of :obj:`MetadataShim`): The metadata to
                    be retrieved from FIRST.
                data_callback (:obj:`data_callback_prototype`, optional):
                    A function to call when data is receieved from the server.
                complete_callback (:obj:`complete_callback_prototype`, optional):
                    A function to call when the whole long operation completes.

            Returns:
                threading.Thread. The thread created for the operation.
            '''
            args = (metadata_ids, data_callback, complete_callback)
            thread = threading.Thread(target=self.__thread_get, args=args)
            thread.daemon = True
            thread.start()
            return thread

        def __thread_get(self, metadata, data_callback=None, complete_callback=None):
            '''Thread to get metadata'''
            thread = threading.current_thread()
            self.threads[thread] = {'results' : [], 'complete' : False,
                                    'stop' : False}

            if isinstance(metadata, FIRST.MetadataShim):
                metadata = [metadata]

            if False in [isinstance(m, FIRST.MetadataShim) for m in metadata]:
                self.threads[thread]['complete'] = True
                return

            for i in xrange(0, len(metadata), self.MAX_CHUNK):
                if self.threads[thread]['stop']:
                    break

                data = [m.id for m in metadata[i:i + self.MAX_CHUNK]]

                try:
                    response = self._sendp('get', {'metadata' : json.dumps(data)})
                except FIRST.Error as e:
                    self.threads[thread]['complete'] = True
                    if complete_callback:
                        complete_callback(thread, self.threads[thread])
                    return

                if (not response or ('results' not in response)
                    or (dict != type(response['results']))
                    or (not len(response['results']))):
                    continue

                results = {}
                for metadata_id, details in response['results'].iteritems():
                    results[metadata_id] = FIRST.MetadataServer(details)

                if 0 < len(results):
                    self.threads[thread]['results'].append(results)
                    if data_callback:
                        data_callback(thread, results)


            self.threads[thread]['complete'] = True
            if complete_callback:
                complete_callback(thread, self.threads[thread])

        def scan(self, metadata, data_callback=None, complete_callback=None):
            '''Queries FIRST for matches.

            This is a long operation, thus it has the option of providing a
            ``data_callback`` and ``complete_callback`` arguments. Those
            arguments are functions that will be called with the newly returned
            data and when the whole operation is complete, respectively. Both
            functions should follow the below their respective prototypes;
            ``data_callback_prototype`` and ``complete_callback_prototype``.

            Args:
                metadata (:obj:`list` of :obj:`MetadataShim`): The metadata to
                    be queried for matches in FIRST.
                data_callback (:obj:`data_callback_prototype`, optional):
                    A function to call when data is receieved from the server.
                complete_callback (:obj:`complete_callback_prototype`, optional):
                    A function to call when the whole long operation completes.

            Returns:
                threading.Thread. The thread created for the operation.
            '''
            args = (metadata, data_callback, complete_callback)
            thread = threading.Thread(target=self.__thread_scan, args=args)
            thread.daemon = True
            thread.start()
            return thread

        def __thread_scan(self, metadata, data_callback=None, complete_callback=None):
            '''Thread to query FIRST for metadata'''
            thread = threading.current_thread()
            self.threads[thread] = {'results' : [], 'complete' : False,
                                    'stop' : False}

            if isinstance(metadata, FIRST.MetadataShim):
                metadata = [metadata]

            if False in [isinstance(m, FIRST.MetadataShim) for m in metadata]:
                self.threads[thread]['complete'] = True
                return

            subkeys = {'engines', 'matches'}
            architecture = FIRST.Info.get_architecture()
            for i in xrange(0, len(metadata), self.MAX_CHUNK):
                if self.threads[thread]['stop']:
                    break

                params = self._min_info()
                data = {}
                for m in metadata[i:i + self.MAX_CHUNK]:
                    signature = m.signature
                    if not signature:
                        continue

                    data[m.address] = { 'opcodes' : b64encode(m.signature),
                                        'apis' : m.apis,
                                        'architecture' : architecture}

                params['functions'] = json.dumps(data)

                try:
                    response = self._sendp('scan', params)
                except FIRST.Error as e:
                    self.threads[thread]['complete'] = True
                    if complete_callback:
                        complete_callback(thread, self.threads[thread])
                    return

                if (not response or ('results' not in response)
                    or (dict != type(response['results']))
                    or (not subkeys.issubset(response['results'].keys()))
                    or (0 == len(response['results']['matches']))):
                    continue

                results = {}
                engine_info = response['results']['engines']
                matches = response['results']['matches']
                for address_str in matches:
                    functions = []
                    address = int(address_str)

                    for match in matches[address_str]:
                        engines = {x : engine_info[x] for x in match['engines']}
                        data = FIRST.MetadataServer(match, address, engines)
                        functions.append(data)

                    if len(functions) > 0:
                        results[address] = functions

                if 0 < len(results):
                    self.threads[thread]['results'].append(results)
                    if data_callback:
                        data_callback(thread, results)

            self.threads[thread]['complete'] = True
            if complete_callback:
                complete_callback(thread, self.threads[thread])


    class Model(object):
        class Base(QtCore.QAbstractTableModel):
            '''A QT QAbstractTableModel Implementation.

            Args:
                header (:obj:`list`): The column values.
                data (:obj:`dict`): Dictionary of values.
                parent (:obj:`QtCore.QObject`): The parent object.

            Overloads many class methods to provide the functionality FIRST
            required.
            '''
            def __init__(self, header, data=None, parent=None):
                super(FIRST.Model.Base, self).__init__(parent)

                self.header = header
                self._data = data

                if None == data:
                    self._data = collections.OrderedDict()

            def rowCount(self, parent=QtCore.QModelIndex()):
                '''The number of rows under the given parent.

                When the parent is valid it means that rowCount is returning
                the number of children of parent.

                Args:
                    parent (:obj:`QtCore.QModelIndex`, optional): Parent

                Returns:
                    int: Number of rows
                '''
                if None == self._data:
                    return 0

                return len(self._data)

            def columnCount(self, parent=QtCore.QModelIndex()):
                '''The number of columns for the children of the given parent.

                Args:
                    parent (:obj:`QtCore.QModelIndex`, optional): Parent

                Returns:
                    int: Number of columns
                '''
                if None == self.header:
                    return 0

                return len(self.header)

            def data(self, index, role=Qt.DisplayRole):
                '''The data stored under the given role for the item referred
                to by the index.

                Args:
                    index (:obj:`QtCore.QModelIndex`): Index
                    role (:obj:`Qt.ItemDataRole`): Default :obj:`Qt.DisplayRole`

                Returns:
                    data
                '''
                if role == Qt.DisplayRole:
                    row = self._data[index.row()]
                    if (index.column() == 0) and (type(row) != dict):
                        return row

                    elif index.column() < self.columnCount():
                        if type(row) == dict:
                            if self.header[index.column()] in row:
                                return row[self.header[index.column()]]
                            elif self.header[index.column()].lower() in row:
                                return row[self.header[index.column()].lower()]

                        return row[index.column()]

                    return None

                elif role == Qt.FontRole:
                    return QtGui.QFont().setPointSize(30)

                elif role == Qt.DecorationRole and index.column() == 0:
                    return None

                elif role == Qt.TextAlignmentRole:
                    return Qt.AlignLeft;

            def headerData(self, section, orientation, role=Qt.DisplayRole):
                '''The data for the given role and section in the header with
                the specified orientation.

                Args:
                    section (:obj:`int`):
                    orientation (:obj:`Qt.Orientation`):
                    role (:obj:`Qt.DisplayRole`):

                Returns:
                    data
                '''
                if role != Qt.DisplayRole:
                    return None

                if (orientation == Qt.Horizontal) and (section < len(self.header)):
                    return self.header[section]

                return None

            def raw_data(self, i):
                '''Provides a way to get the raw data in the model.

                Args:
                    i (:obj:`int`): The data index to be retrieved.

                Returns:
                    dict. The data held at the given index, otherwise None.
                '''
                if i < len(self._data):
                    return self._data[i]

                return None

        class Upload(Base):
            '''Expands on the Base QAbstractTableModel for Add operation.

            Data held in this DataModel is sorted based on their offset within
            the IDB. A couple of additional functions are added to this model
            to provide more functionality to modify the selected underlying
            data.
            '''
            def __init__(self, header, data, parent=None):
                super(FIRST.Model.Upload, self).__init__(header, data, parent)
                self._data.sort(cmp=lambda x,y: cmp(x.offset, y.offset))
                self.__original_data = self._data

                self.select_all_flag = False
                self.rows_selected = set()

            def set_row_selected(self, row):
                '''Causes a row to be selected or deselected.

                Args:
                    row (:obj:`int`): The row index to be selected.
                '''
                if row in self.rows_selected:
                    self.rows_selected.remove(row)
                else:
                    self.rows_selected.add(row)

            def select_all(self, flag):
                '''Makes all visible functions selected or deselected.

                Args:
                    flag (:obj:`bool`): Flag to select or deselect all.
                '''
                self.rows_selected = set(xrange(len(self._data))) if flag else set()

            def filter_sub_functions(self, flag):
                '''Filters out or restores any sub_* functions.

                Args:
                    flag (:obj:`bool`): Flag to filter out or restore sub_*
                        functions
                '''
                self.beginResetModel()

                if flag:
                    self._data = [d for d in self._data if not d.name.startswith('sub_')]

                else:
                    self._data = self.__original_data

                self.endResetModel()

                self.select_all(False)

            def set_colors(self, changed='66d9ef', unchanged='d2d2d2', default='ffffff', select='a9c5ff'):
                '''Sets the colors associated with the various properties.

                Args:
                    changed (:obj:`str`): Change color, default: '66d9ef'
                    unchanged (:obj:`str`): Unchanged color, default: 'd2d2d2'
                    default (:obj:`str`): Default color, default: 'ffffff'
                    select (:obj:`str`): Selected color, default: 'a9c5ff'
                '''
                colors = [changed, unchanged, default, select]

                if None in [re.match('^[a-fA-F0-9]{6}$', x) for x in colors]:
                    #   Invalid color provided
                    return

                self.colors = []
                for c in colors:
                    r, g, b = int(c[:2], 16), int(c[2:4], 16), int(c[-2:], 16)
                    self.colors.append(QtGui.QBrush(QtGui.QColor.fromRgb(r, g, b)))

            def data(self, index, role):
                if not index.isValid():
                    return None

                if not (0 <= index.row() < self.rowCount()):
                    return None

                elif role == Qt.FontRole:
                    return QtGui.QFont().setPointSize(30)

                elif role == Qt.DecorationRole and index.column() == 0:
                    return None

                elif role == Qt.TextAlignmentRole:
                    return Qt.AlignLeft;

                #   Color background
                if role == Qt.BackgroundRole:
                    function = self._data[index.row()]

                    #   Row is selected
                    if index.row() in self.rows_selected:
                        return FIRST.color_selected

                    #   Data has been updated since original
                    if function.has_changed:
                        return FIRST.color_changed

                    #
                    if function.id is not None:
                        return FIRST.color_unchanged

                    #   Return the default color
                    return FIRST.color_default

                if role == Qt.DisplayRole:
                    function = self._data[index.row()]

                    column = index.column()
                    if 0 == column:
                        return '0x{0:X}'.format(function.address)

                    elif 1 == column:
                        return function.name

                    elif 2 == column:
                        return function.prototype

                    elif 3 == column:
                        return function.comment

                    return None

                return super(FIRST.Model.Upload, self).data(index, role)

            def get_selected_data(self):
                '''Returns the list of data selected in the model.'''
                return [self._data[x] for x in self.rows_selected]

        class Check(QtGui.QStandardItemModel):
            '''Expands on the Qt QStandardItemModel for Check operations.'''
            def __init__(self, data, parent=None):
                super(FIRST.Model.Check, self).__init__(parent)

                self._data = {}
                self.select_highest_flag = False
                self.ids_selected = set()

                self.applied_ids = set()
                self.add_data(data)

            def add_data(self, data):
                '''Provides a way to add more data to the model.

                Args:
                    data (:obj:`dict`): Data to be added to the model.
                '''
                self._data.update(data)

                for address in data:
                    function = FIRST.Metadata.get_function(address)
                    if function and function.id:
                        self.applied_ids.add((address, function.id))

            def set_id_selected(self, data):
                '''Add or removes data associated with an ID to/from the
                selected ids array.

                Args:
                    data (:obj:`list`): The data to be (de)selected.
                '''
                if not data or 2 != len(data):
                    return

                if data in self.ids_selected:
                    self.ids_selected.remove(data)

                else:
                    address, data_id = data
                    #   Find if any other matches that have been selected for
                    #   that address, id pair
                    for match in self._data[address]:
                        key = (address, match.id)
                        if key in self.ids_selected:
                            self.ids_selected.remove(key)

                    self.ids_selected.add(data)

            def select_highest_ranked(self, flag, hidden=[]):
                '''Sets the highsest rank annotations as (de)selected.

                Args:
                    flag (:obj:`bool`): Where to select or deselect the highest.
                        True to select highest, False to deselect highest.
                    hidden (:obj:`list` or :obj:`int`): Address that should be
                        skipped.
                '''
                self.ids_selected = set()
                func = lambda x: x[0]

                #   Iterate through each match set, selecting the highest ranked
                if flag:
                    #   Reset list
                    self.ids_selected = set()
                    for address, matches in self._data.iteritems():
                        #   If address is hidden then skip it
                        if address in hidden:
                            continue

                        ids = {}
                        #   Group highest similarity percentages first
                        for match in matches:
                            if match.similarity not in ids:
                                ids[match.similarity] = []

                            ids[match.similarity].append(match)

                        #   Get highest similiarity group
                        index = max(ids)
                        similar = ids[index]

                        #   Get highest ranked metadata
                        match = max(similar, key=lambda x: x.rank).id
                        self.set_id_selected((address, match))

            def unselect_group(self, data):
                '''Unselects a group of addresses at once.

                Args:
                    data (:obj:`list` of :obj:`int`): List of addresses.
                '''
                lookup = {d[0] : d for d in self.ids_selected}

                for address in data:
                    if address in lookup:
                        self.ids_selected.remove(lookup[address])

            def data(self, index, role):
                '''The data stored under the given role for the item referred
                to by the index.

                Args:
                    index (:obj:`QtCore.QModelIndex`): Index
                    role (:obj:`Qt.ItemDataRole`): Default :obj:`Qt.DisplayRole`

                Returns:
                    data
                '''
                if not index.isValid():
                    return None

                #   Color background
                if role == Qt.BackgroundRole:
                    metadata_id = index.data(FIRSTUI.ROLE_ID)
                    address = index.data(FIRSTUI.ROLE_ADDRESS)

                    if (metadata_id and address
                        and ((address, metadata_id) in self.ids_selected)):
                        return FIRST.color_selected

                    elif (metadata_id and address
                          and ((address, metadata_id) in self.applied_ids)):
                        return FIRST.color_applied

                    #   Data has been updated since original
                    elif not metadata_id:
                        return FIRST.color_unchanged

                    #   Return the default color
                    return FIRST.color_default

                return super(FIRST.Model.Check, self).data(index, role)

            def get_selected_data(self):
                '''Returns a dictionary of data selected in the model.'''
                data = {}
                for (address, _id) in self.ids_selected:
                    if address not in self._data:
                        continue

                    match = [x for x in self._data[address] if x.id == _id]
                    if match:
                        data[address] = match[0]

                return data

        class TreeView(QtWidgets.QTreeView):
            '''A QT QTreeView Implementation.

            Args:
                widget (:obj:`Qt.QObject`, optional): The parent.
                depth (:obj:`int`, optional): The depth of the tree.
            '''
            def __init__(self, widget=None, depth=2):
                super(FIRST.Model.TreeView, self).__init__(widget)
                self.__depth = depth

            def drawRow(self, painter, option, index):
                '''Draws the row in the tree view that contains the model item
                index, using the painter given. The option control how the item
                is displayed.

                Args:
                    painter (:obj:`QtGui.QPainter`): Painter
                    option (:obj:`QtGui.QStyleOptionViewItem`): Options
                    index (:obj:`QtCore.QModelIndex`): Index
                '''
                metadata_id = index.data(FIRSTUI.ROLE_ID)
                header = self.header()
                firstSection = header.logicalIndex(0)
                left = header.sectionViewportPosition(firstSection)
                indent = self.__depth * self.indentation()

                if (index.data(FIRSTUI.ROLE_COMMENT)
                    and (index.row() == 0) and (index.column() == 0)):
                    lastSection = header.logicalIndex(header.count() - 1)
                    right = header.sectionViewportPosition(lastSection) + header.sectionSize(lastSection)

                    left += indent;

                    option.rect.setX(left)
                    option.rect.setWidth(right - left)

                    self.itemDelegate(index).paint(painter, option, index)

                else:
                    super(FIRST.Model.TreeView, self).drawRow(painter, option, index)


    class Callbacks(object):
        '''Callbacks for FIRST's Dialog UI components.

        This class contains only static methods and should be accessed as such.
        '''
        @staticmethod
        def accepted(fclass, dialog):
            '''Registered callback for accept dialog action.

            Args:
                fclass (:obj:`idaapi.PluginForm`): The plugin form part of
                dialog (:obj:`FIRSTUI.*`): A dialog box object.
            '''
            if (isinstance(dialog, FIRSTUI.Upload)
                    or isinstance(dialog, FIRSTUI.UploadAll)):
                FIRST.Callbacks.Upload(dialog)

            elif (isinstance(dialog, FIRSTUI.Check)
                    or isinstance(dialog, FIRSTUI.CheckAll)):
                FIRST.Callbacks.check(dialog)

            elif isinstance(dialog, FIRSTUI.Welcome):
                FIRST.Callbacks.welcome(dialog)

        @staticmethod
        def welcome(dialog):
            '''Welcome dialog box handler.

            Args:
                dialog (:obj:`FIRSTUI.Welcome`): Welcome dialog box.
            '''
            FIRST.config = FIRSTUI.SharedObjects.get_config(dialog)
            FIRST.config.save_config(FIRST.config_path)

            info = FIRST.Info.get_file_details()
            FIRST.server = FIRST.Server(FIRST.config,
                                        info['md5'],
                                        info['crc32'],
                                        h_sha1=info['sha1'],
                                        h_sha256=info['sha256'])

            FIRST.Metadata.populate_function_list()
            FIRST.plugin_enabled = True

        @staticmethod
        def check(dialog):
            '''Check and CheckAll dialog box handler.

            Args:
                dialog (:obj:`FIRSTUI.Check` or :obj:`FIRSTUI.CheckAll`): Check
                    or CheckAll dialog box.
            '''
            data = dialog.data_model.get_selected_data()

            if data:
                message = ('Applying metadata to {0} signature(s)\n'
                           '          {1}% complete')
                i = 0.0
                total = len(data)
                idaapi.show_wait_box(message.format(total, int(i)))
                try:
                    for address, metadata in data.iteritems():
                        function = FIRST.Metadata.get_function(address)

                        if idaapi.wasBreak():
                            raise FIRST.Error('canceled')

                        if function:
                            percentage = int((i / total) * 100)
                            msg = message.format(total, percentage)
                            idaapi.replace_wait_box(msg)
                            #   Check if metadata was already applied to the file
                            #   If so, tell FIRST server it was unapplied
                            if function.id:
                                FIRST.server.unapplied(function.id)

                            #   Apply metadata and inform FIRST it was applied
                            function.apply_metadata(metadata)
                            FIRST.server.applied(metadata.id)

                        else:
                            msg = '[1st] Error: getting function at {0:x}\n'.format(address)
                            idaapi.execute_ui_requests((FIRSTUI.Requests.Print(msg),))

                        i += 1

                except FIRST.Error as e:
                    idaapi.replace_wait_box('Not all metadata was applied')
                    time.sleep(1)

                finally:
                    idaapi.hide_wait_box()

                message = 'Applied metadata data to {} out of {} functions\n'
                idaapi.execute_ui_requests((FIRSTUI.Requests.Print(message.format(int(i), total)),))

            else:
                idaapi.execute_ui_requests((FIRSTUI.Requests.Print('No functions were selected\n'),))


        class Upload(object):
            '''Uploading/Adding callback class.

            This class is basic and sets up data and complete callbacks for the
            add operation.

            Args:
                dialog (:obj:`FIRSTUI.Upload` or :obj:`FIRSTUI.UploadAll`):
                    Dialog box the accepted button was selected.

            Attributes:
                message (:obj:`str`): Format string for the wait box message.
            '''
            message = ('Uploading metadata for {0} function(s)\n'
                       '          {1}% complete')

            def __init__(self, dialog):
                data = []
                self.__to_update = []
                if isinstance(dialog, FIRSTUI.UploadAll):
                    data = dialog.get_selected_data()
                elif isinstance(dialog, FIRSTUI.Upload):
                    data.append(dialog.metadata)

                self.total = len(data)
                self.uploaded = 0.0

                #   If there is no data of incorrect dialog received then exit
                if not data:
                    return

                idaapi.show_wait_box(self.message.format(self.total, 0))
                thread = FIRST.server.add(data, self.__data, self.__complete)

            def __data(self, thread, data):
                if ('failed' in data) and data['failed']:
                    idaapi.hide_wait_box()
                    if 'msg' not in data:
                        return

                    msg = '[1st] Error: {}'.format(data['msg'])
                    print msg
                    #idaapi.execute_ui_requests((FIRSTUI.Requests.Print(msg),))
                    return

                if ('results' not in data):
                    idaapi.hide_wait_box()
                    msg = '[1st] Error: no results returned'
                    print msg
                    #idaapi.execute_ui_requests((FIRSTUI.Requests.Print(msg),))
                    return

                results = data['results']

                for address, metadata_id in results.iteritems():
                    #   Update Wait Box
                    self.uploaded += 1
                    percentage = int((self.uploaded / self.total) * 100)
                    msg = self.message.format(self.total, percentage)
                    idaapi.replace_wait_box(msg)

                    if idaapi.wasBreak():
                        FIRST.server.stop_operation(thread)
                        msg = 'Not all functions were added to FIRST'
                        idaapi.execute_ui_requests((FIRSTUI.Requests.Print(msg),))
                        return

                    f = FIRST.Metadata.get_function(int(address))
                    if f:
                        if f.id and (f.id != metadata_id):
                            FIRST.server.unapplied(f.id)

                        f.id = metadata_id
                        self.__to_update.append(f)

            def __complete(self, thread, data):
                FIRST.server.remove_operation(thread)

                idaapi.hide_wait_box()
                msg = 'Added {} function(s) to FIRST\n'.format(int(self.uploaded))
                idaapi.execute_ui_requests((FIRSTUI.Requests.Print(msg),))

                changed = {'changed' : False}
                func = FIRSTUI.Requests.Callback
                updates = [func(x.update_db, **changed) for x in self.__to_update]
                idaapi.execute_ui_requests(updates)


        class Update(object):
            '''Updating callback class.

            This class is basic and sets up data and complete callbacks for the
            add operation.

            Args:
                dialog (:obj:`FIRSTUI.Update`): Dialog box the accepted button
                    was selected.
            '''
            def __init__(self):
                to_update = FIRST.Metadata.get_functions_with_applied_metadata()
                self.functions = {f.id : f for f in to_update if f.id}
                self.total = len(self.functions)
                self.updated = 0

                server_thread = FIRST.server.get(self.functions.values(),
                                                    self.__data, self.__complete)

            def __data(self, thread, data):
                if (not data) and (dict != type(data)):
                    return

                for metadata_id, metadata in data.iteritems():
                    if metadata_id not in self.functions:
                        continue

                    self.updated += 1
                    function = self.functions[metadata_id]
                    function.apply_metadata(metadata)

                    #   Remove function from dictionary
                    del self.functions[metadata_id]

            def __complete(self, thread, data):
                msg = 'Updated {} function(s)\n'.format(self.updated)
                idaapi.execute_ui_requests((FIRSTUI.Requests.Print(msg),))

                #   If functions are still in the queue, this means the metadata
                #   was deleted on the server remove the id from it
                for function in self.functions.values():
                    function.id = None

    class Hook():
        @staticmethod
        def function_rptcmt(is_preprocess=True):
            '''Handler for creating function repeatable comments (UI Hook).

            Args:
                is_preprocess (:obj:`bool`, optional): True if called during
                    preprocess, False when called during postprocess.
            '''
            function = FIRST.Metadata.get_function(IDAW.ScreenEA())

            if not function:
                return

            if is_preprocess:
                function.snapshot()

            else:
                function.update_comment()

        @staticmethod
        def function_named(is_preprocess=True):
            '''Handler for when labels are changed (UI Hook).

            Args:
                is_preprocess (:obj:`bool`, optional): True if called during
                    preprocess, False when called during postprocess.
            '''
            function = FIRST.Metadata.get_function(IDAW.ScreenEA())

            if not function:
                return

            if is_preprocess:
                function.snapshot()

            else:
                function.update_name()

        @staticmethod
        def function_settype(is_preprocess=True):
            '''Handler for when a function prototype is changed (UI Hook).

            Args:
                is_preprocess (:obj:`bool`, optional): True if called during
                    preprocess, False when called during postprocess.
            '''
            function = FIRST.Metadata.get_function(IDAW.ScreenEA())

            if not function:
                return

            if is_preprocess:
                function.snapshot()

            else:
                function.update_prototype()

        @staticmethod
        def function_created(is_preprocess=True):
            '''Handler for when functions are created (UI Hook).

            Adds a new funciton to FIRST's function list.

            Args:
                is_preprocess (:obj:`bool`, optional): True if called during
                    preprocess, False when called during postprocess.
            '''
            if dict != type(FIRST.function_list):
                return

            #   No action needed for preprocess
            if is_preprocess:
                return

            ea = IDAW.ScreenEA()

            #   Ensure it is a function or was correctly created
            function = IDAW.get_func(ea)
            if not function:
                return

            #   Calculate offset to function from segment
            function = FIRST.MetadataShim(ea)

            seg_offset = function.segment - IDAW.get_imagebase()


            if seg_offset not in FIRST.function_list:
                FIRST.function_list[seg_offset] = {}

            if function.offset in FIRST.function_list[seg_offset]:
                return

            msg = 'Adding {0.name} (0x{0.address:x} to global list\n'
            idaapi.execute_ui_requests((FIRSTUI.Requests.Print(msg.format(function)),))
            FIRST.function_list[seg_offset][function.offset] = function

        old_imagebase = None
        @staticmethod
        def function_rebase(is_preprocess=True):
            '''Handler for when the program is rebased in IDA (UI Hook).

            Args:
                is_preprocess (:obj:`bool`, optional): True if called during
                    preprocess, False when called during postprocess.
            '''
            if is_preprocess:
                FIRST.Hook.old_imagebase = IDAW.get_imagebase()
                return

            if FIRST.Hook.old_imagebase == IDAW.get_imagebase():
                return

            for segment in FIRST.Metadata.get_segments_with_functions():
                offset = segment.startEA - IDAW.get_imagebase()

                for metadata in FIRST.Metadata.get_segment_functions(segment):
                    adjustment = IDAW.get_imagebase() - FIRST.Hook.old_imagebase
                    metadata.address = metadata.address + adjustment


        class IDP(idaapi.IDP_Hooks):
            '''FIRST's IDP Hook. Initializes most of the FIRST plugin.

            Attributes:
                executed (:obj:`bool`): Flag to understand if the hook has
                    fired or not.
            '''
            executed = False

            def __init__(self):
                super(FIRST.Hook.IDP, self).__init__()

            def on_auto_queue_empty(self, arg):
                if (arg == 200) and (not FIRST.Hook.IDP.executed):
                    FIRST.Hook.IDP.executed = True
                    self.unhook()

                    if self in FIRST.installed_hooks:
                        i = FIRST.installed_hooks.index(self)
                        del FIRST.installed_hooks[i]

                    FIRST.Metadata.populate_function_list()

                    #   Get/Initialize the hash details for the file
                    FIRST.Info.get_file_details()

                    config = ConfigParser.RawConfigParser()
                    if not config.read(FIRST.config_path):
                        FIRST.show_welcome = True
                        config = None

                    else:
                        #   Create connection to FIRST server
                        FIRST.config = FIRST.Configuration(config)

                        info = FIRST.Info.get_file_details()
                        FIRST.server = FIRST.Server(FIRST.config,
                                                    info['md5'],
                                                    info['crc32'],
                                                    h_sha1=info['sha1'],
                                                    h_sha256=info['sha256'])

                        FIRST.plugin_enabled = True

            if idaapi.get_kernel_version().startswith("7"):
                def ev_auto_queue_empty(self, arg):
                    self.on_auto_queue_empty(arg)
                    return super(self.__class__, self).ev_auto_queue_empty(arg)
            else:
                def auto_queue_empty(self, arg):
                    self.on_auto_queue_empty(arg)
                    return super(self.__class__, self).auto_queue_empty(arg)

        class UI(idaapi.UI_Hooks):
            '''FIRST's UI Hook. Sets UI change hooks and right click menu.'''
            def __init__(self):
                super(FIRST.Hook.UI, self).__init__()
                self.handlers_created = False

                self.action_names = [   'first:get_func', 'first:get_all_func',
                                        'first:upload_func', 'first:upload_all_func',
                                        'first:update_funcs', 'first:view_history']
                self.actions = None
                self.handlers = {'MakeRptCmt' : [FIRST.Hook.function_rptcmt],
                                'MakeName' : [FIRST.Hook.function_named],
                                'SetType' : [FIRST.Hook.function_settype],
                                'MakeFunction' : [FIRST.Hook.function_created],
                                'RebaseProgram' : [FIRST.Hook.function_rebase]}
                self.handler_action = ''

            def tform_visible(self, form, hwnd):
                '''Shows the FIRST Welcome dialog box if required.'''
                if ((IDAW.BWN_DISASMS == IDAW.get_tform_type(form))
                    and FIRST.show_welcome):
                    parent = idaapi.PluginForm.FormToPyQtWidget(form)

                    welcome_dialog = FIRSTUI.Dialog(parent, FIRSTUI.Welcome)
                    welcome_dialog.registerSuccessCallback(FIRST.Callbacks.welcome)
                    welcome_dialog.show()
                    FIRST.show_welcome = False

            def finish_populating_tform_popup(self, form, popup):
                '''Initializes UI change hooks and enables right click menu.'''
                if None == FIRST.plugin:
                    return

                if None == self.actions:
                    self.actions =  [
                        {'name' : self.action_names[0],
                         'text' : 'Check FIRST for this function',
                         'handler' : FIRST.plugin.check_function,
                         'shortcut' : None,
                         'tooltip' : ('See if metadata for this function'
                                        ' exists')},
                        {'name' : self.action_names[1],
                         'text' : 'Query FIRST for all function matches',
                         'handler' : FIRST.plugin.check_all_function,
                         'shortcut' : None,
                         'tooltip' : ('See if metadata for any defined '
                                        'function exists')},
                        {'name' : self.action_names[2],
                         'text' : 'Add this function to FIRST',
                         'handler' : FIRST.plugin.upload_func,
                         'shortcut' : None,
                         'tooltip' : 'Add this function to FIRST\'s database'},
                        {'name' : self.action_names[3],
                         'text' : 'Add multiple functions to FIRST',
                         'handler' : FIRST.plugin.upload_all_func,
                         'shortcut' : None,
                         'tooltip' : ('Add multiple functions to '
                                        'FIRST\'s database')},
                        {'name' : self.action_names[4],
                         'text' : 'Apply updated metadata from FIRST',
                         'handler' : FIRST.plugin.update_funcs,
                         'shortcut' : None,
                         'tooltip' : ('Any applied metadata will be updated '
                                        'from FIRST\'s database')},
                        {'name' : self.action_names[5],
                         'text' : 'View metadata history',
                         'handler' : FIRST.plugin.view_history,
                         'shortcut' : None,
                         'tooltip' : 'See how metadata has changed over time'},
                                    ]


                if not self.handlers_created:
                    self.init_actions()
                    self.handlers_created = True

                tform_type = IDAW.get_tform_type(form)
                if IDAW.BWN_DISASMS == tform_type and FIRST.plugin_enabled:
                    func = IDAW.get_func(IDAW.ScreenEA())

                    IDAW.attach_action_to_popup(form, popup, '')
                    for name in self.action_names[:-1]:
                        if ((type(func) != idaapi.func_t)
                            and (self.action_names.index(name) in [0, 2])):
                            continue

                        IDAW.attach_action_to_popup(form, popup, name)

                    if type(func) == idaapi.func_t:
                        function = FIRST.Metadata.get_function(func.startEA)
                        if function and function.id:
                            IDAW.attach_action_to_popup(form, popup, self.action_names[-1])

            def init_actions(self):
                '''Sets up action descriptors.'''
                global FIRST_ICON

                for action_item in self.actions:
                    handler = FIRST.Hook.ActionHandler(action_item['handler'])
                    action_desc = IDAW.action_desc_t(action_item['name'],
                                                    action_item['text'],
                                                    handler,
                                                    action_item['shortcut'],
                                                    action_item['tooltip'],
                                                    FIRST_ICON)
                    IDAW.register_action(action_desc)

            def preprocess(self, name):
                '''UI Hooks preprocessing call.

                Args:
                    name (:obj:`str`): The action that will occur.
                '''
                self.handler_action = name
                if self.handler_action in self.handlers:
                    handlers = self.handlers[self.handler_action]
                    for handler in handlers:
                        handler(True)
                return 0

            def postprocess(self):
                '''UI Hooks postprocessing call.'''
                if self.handler_action in self.handlers:
                    handlers = self.handlers[self.handler_action]
                    for handler in handlers:
                        handler(False)
                return 0

            def term(self):
                '''Removes all installed hooks.'''
                FIRST.cleanup_hooks()


        class ActionHandler(idaapi.action_handler_t):
            '''Action handler wrapper function.

            This function wraps callback functions with a class to prevent
            duplication of code.

            Args:
                fn (:obj:`function`): Function that will be used for callback.
            '''
            def __init__(self, fn):
                idaapi.action_handler_t.__init__(self)
                self.fn = fn

            def activate(self, ctx):
                self.fn(ctx)
                return 1

            def update(self, ctx):
                return IDAW.AST_ENABLE_ALWAYS

class FIRSTUI(object):
    ROLE_ID = 35
    ROLE_COMMENT = 36
    ROLE_ADDRESS = 37
    ROLE_NAME = 38

    class Requests(object):
        class MsgBox(object):
            def __init__(self, title, msg, icon=QtWidgets.QMessageBox.Critical):
                self.title = title
                self.msg = msg
                self.icon = icon

            def __call__(self):
                msg_box = QtWidgets.QMessageBox()
                msg_box.setIcon(self.icon)
                msg_box.setWindowTitle(self.title)

                msg_box.setText(self.msg)
                msg_box.exec_()
                return False # Don't reschedule

        class Print(object):
            def __init__(self, msg):
                self.msg = msg

            def __call__(self):
                IDAW.msg(self.msg)
                return False # Don't reschedule

        class Callback(object):
            def __init__(self, func, **kwargs):
                self.func = func
                self.kwargs = kwargs

            def __call__(self):
                self.func(**self.kwargs)
                return False # Don't reschedule


    class ScrollWidget(QtWidgets.QWidget):
        '''A scroll widget'''
        def __init__(self, parent=None, frame=QtWidgets.QFrame.Box):
            super(FIRSTUI.ScrollWidget, self).__init__()

            #   Container Widget
            widget = QtWidgets.QWidget()
            #   Layout of Container Widget
            self.layout = QtWidgets.QVBoxLayout(self)
            self.layout.setContentsMargins(0, 0, 0, 0)
            widget.setLayout(self.layout)

            #   Scroll Area Properties
            scroll = QtWidgets.QScrollArea()
            scroll.setFrameShape(frame)
            scroll.setVerticalScrollBarPolicy(Qt.ScrollBarAlwaysOn)
            scroll.setHorizontalScrollBarPolicy(Qt.ScrollBarAlwaysOff)
            scroll.setWidgetResizable(True)
            scroll.setWidget(widget)

            #   Scroll Area Layer add
            scroll_layout = QtWidgets.QVBoxLayout(self)
            scroll_layout.addWidget(scroll)
            scroll_layout.setContentsMargins(0, 0, 0, 0)
            self.setLayout(scroll_layout)

        def addWidget(self, widget):
            self.layout.addWidget(widget)

        def addLayout(self, layout):
            self.layout.addLayout(layout)


    class SharedObjects(object):
        #----------------------------------------------------------------------
        @staticmethod
        def server_config_layout(obj, outer_layout, config=None):
            '''Server Configuration GUI components'''
            if not isinstance(config, FIRST.Configuration):
                config = None

            server_groupbox = QtWidgets.QGroupBox()
            server_groupbox.setTitle('Server Configuration')
            vbox = QtWidgets.QVBoxLayout(server_groupbox)

            grid_layout = QtWidgets.QGridLayout(server_groupbox)
            vbox.addLayout(grid_layout)

            obj.server = QtWidgets.QLineEdit()
            obj.port = QtWidgets.QLineEdit()
            obj.api_key = QtWidgets.QLineEdit()


            obj.protocol = QtWidgets.QComboBox()
            proto_options = ['http', 'https']
            [obj.protocol.addItem(x.upper(), x) for x in proto_options]

            obj.verify = QtWidgets.QComboBox()
            options = ['No', 'Yes']
            [obj.verify.addItem(x, x.lower()) for x in options]

            obj.kerberos = QtWidgets.QComboBox()
            [obj.kerberos.addItem(x, x.lower()) for x in options]
            obj.kerberos.setEnabled(HTTPKerberosAuth is not None)

            if config:
                obj.server = QtWidgets.QLineEdit(config.server)
                obj.port = QtWidgets.QLineEdit(str(config.port))
                obj.protocol.setCurrentIndex(proto_options.index(config.protocol))
                obj.verify.setCurrentIndex(int(config.verify))
                obj.kerberos.setCurrentIndex(int(config.authentication))
                obj.kerberos.setEnabled(HTTPKerberosAuth is not None)
                obj.api_key.setText(config.api_key)

            layout = QtWidgets.QHBoxLayout()
            obj.server_message = QtWidgets.QLabel()
            layout.addWidget(obj.server_message)
            layout.addStretch()
            test_button = QtWidgets.QPushButton('Test')
            test_callback = lambda x: FIRSTUI.SharedObjects.test_connection(obj)
            test_button.clicked.connect(test_callback)
            layout.addWidget(test_button)
            vbox.addSpacing(20)
            vbox.addLayout(layout)

            grid_layout.addWidget(QtWidgets.QLabel('Server'), 0, 0)
            grid_layout.addWidget(obj.server, 0, 1)
            grid_layout.addWidget(QtWidgets.QLabel('Port'), 1, 0)
            grid_layout.addWidget(obj.port, 1, 1)
            grid_layout.addWidget(QtWidgets.QLabel('Protocol'), 2, 0)
            grid_layout.addWidget(obj.protocol, 2, 1)
            grid_layout.addWidget(QtWidgets.QLabel('Verify'), 3, 0)
            grid_layout.addWidget(obj.verify, 3, 1)
            grid_layout.addWidget(QtWidgets.QLabel('Use Kerberos'), 4, 0)
            grid_layout.addWidget(obj.kerberos, 4, 1)
            grid_layout.addWidget(QtWidgets.QLabel('API Key'), 5, 0)
            grid_layout.addWidget(obj.api_key, 5, 1)

            grid_layout.setColumnMinimumWidth(0, 75)
            grid_layout.setSpacing(10)
            grid_layout.setContentsMargins(10, 10, 10, 10)

            outer_layout.addWidget(server_groupbox)

        @staticmethod
        def test_connection(obj):
            obj.server_message.setText('... testing connection ...')
            data = {'server' : obj.server.text()}

            thread = threading.Thread(target=FIRSTUI.SharedObjects._thread_test_connection,
                                        args=(obj,))
            thread.daemon = True
            thread.start()

        @staticmethod
        def _thread_test_connection(obj):
            info = FIRST.Info.get_file_details()
            config = FIRSTUI.SharedObjects.get_config(obj)

            if not re.match('^[\da-f]{8}-([\da-f]{4}-){3}[\da-f]{12}$', config.api_key.lower()):
                obj.server_message.setText('Valid API Key not provided')
                return

            server = FIRST.Server(  FIRSTUI.SharedObjects.get_config(obj),
                                    info['md5'],
                                    info['crc32'],
                                    h_sha1=info['sha1'],
                                    h_sha256=info['sha256'])
            if not server.test_connection():
                obj.server_message.setText('Failed to establish connection with server')
            else:
                obj.server_message.setText('Connected to FIRST server')

        @staticmethod
        def get_config(obj):
            config = FIRST.Configuration(None)

            config.set_server(obj.server.text())
            config.set_port(obj.port.text())
            config.set_protocol(obj.protocol.currentText().lower())
            config.set_verify(obj.verify.currentText().lower() == 'yes')
            config.set_authentication(obj.kerberos.currentText().lower() == 'yes')
            config.set_api_key(obj.api_key.text())

            return config


        #   Check, CheckAll, and Management shared components
        #----------------------------------------------------------------------
        @staticmethod
        def make_model_headers(model, full=True, check_all=True):
            '''
            Set the model horizontal header data
            @param model: the QStandardItemModel which headers should be set

            When full is set to False this mean the headers are for the user
            to review metadata they've created.
            '''
            center_align = ['Rank', 'Similarity', 'i', 'Matches']
            headers = [ ('Function', 'function name'),
                        ('Rank', 'number of times metadata has been applied'),
                        ('Prototype', 'function prototype')]

            if full:
                full_headers = [headers[0]]
                if check_all:
                    full_headers.append(('Matches', 'number of unique matches'))

                full_headers += [
                            headers[1],
                            ('Similarity', 'percent of how similary the match is to the function'),
                            headers[2],
                            ('i', 'full prototype information'),
                            ('Engines', 'engines that matched on this function'),
                            ('i', 'detailed engine information'),
                            ('User', 'creator of the metadata')
                                ]

                headers = full_headers

            i = 0
            for display_name, tooltip in headers:
                item_header = QtGui.QStandardItem(display_name)
                item_header.setToolTip(tooltip)

                if display_name in center_align:
                    item_header.setTextAlignment(Qt.AlignCenter)

                model.setHorizontalHeaderItem(i, item_header)

                i += 1

        @staticmethod
        def make_match_info(match, full=True, check_all=True):
            '''
            Build a tree item for a function_ea node (level-1)
            This is the function match information (name, prototype, rank)
            @param function_context: a dbFunction_Context object
            @return: QStandradItemModel item for the function context
            '''

            #   Add (name, <empty> rank, similarity, prototype, ., engines, ., user) row
            name = QtGui.QStandardItem(match.name)

            rank = QtGui.QStandardItem('-')
            if 'rank' in dir(match):
                rank = QtGui.QStandardItem(str(match.rank))
            rank.setTextAlignment(Qt.AlignCenter)

            prototype = QtGui.QStandardItem(match.prototype)
            prototype_tooltip = QtGui.QStandardItem('...')

            info = [name, rank, prototype]

            if full:
                engine_info = match.engine_info
                msg = '<p><b>{}</b><br/>{}</p>'
                tooltip = [msg.format(k,v) for k,v in engine_info.iteritems()]
                tooltip = '<hr style="margin:1px"/>'.join(tooltip)

                prototype_tooltip.setToolTip(match.prototype)
                prototype_tooltip.setTextAlignment(Qt.AlignCenter)
                similarity = QtGui.QStandardItem(str(round(match.similarity, 2)) + '%')
                similarity.setTextAlignment(Qt.AlignCenter)
                engines = QtGui.QStandardItem(', '.join(engine_info.keys()))
                engines_tooltip = QtGui.QStandardItem('...')
                engines_tooltip.setTextAlignment(Qt.AlignCenter)
                engines_tooltip.setToolTip(tooltip)
                creator = QtGui.QStandardItem(match.creator)

                info = [name]
                if check_all:
                    info += [QtGui.QStandardItem()]

                info += [   rank, similarity, prototype, prototype_tooltip,
                            engines, engines_tooltip, creator]

            #   Add row:
            #   Comment:
            #   (comment)
            comment = match.comment
            if not comment:
                comment = '- No Comment -'
            comment = QtGui.QStandardItem('Comment:\n' + comment)
            comment.setColumnCount(8)
            comment.setData(True, role=FIRSTUI.ROLE_COMMENT)
            comment_list = [comment] + \
                            [QtGui.QStandardItem() for i in range(len(info)-1)]

            info[0].appendRow(comment_list)

            #   Mark all items noneditable and add id associated with the match
            for item in info + comment_list:
                item.setEditable(False)
                item.setData(match.id, role=FIRSTUI.ROLE_ID)
                item.setData(match.address, role=FIRSTUI.ROLE_ADDRESS)

            return info


    class Generic(object):
        def __init__(self):
            self.should_show = True

        def get_server_thread(self):
            return None

        def setupUi(self, dialog):
            self.dialog = dialog
            self.init_window()

            sizePolicy = QtWidgets.QSizePolicy(QtWidgets.QSizePolicy.Preferred, QtWidgets.QSizePolicy.Expanding)
            sizePolicy.setHorizontalStretch(0)
            sizePolicy.setVerticalStretch(2)

            self.msg = QtWidgets.QLabel('')

            #   top_layout
            #------------------------------
            self.top_layout = QtWidgets.QHBoxLayout()
            self.init_top_layout()

            #   table_layout
            #------------------------------
            self.data_layout = QtWidgets.QVBoxLayout()
            self.data_layout.setContentsMargins(0,0,0,0)
            self.data_layout.setSpacing(0)
            self.init_data_layout()

            #   mid_layout
            #------------------------------
            self.middle_layout = QtWidgets.QHBoxLayout()
            self.init_middle_layout()


            #   bottom_layout
            #------------------------------
            self.apply_button = QtWidgets.QPushButton('Apply')
            self.apply_button.setFixedWidth(100)
            self.cancel_button = QtWidgets.QPushButton('Cancel')
            self.cancel_button.setFixedWidth(100)
            self.bottom_layout = QtWidgets.QHBoxLayout()
            self.bottom_layout.addWidget(self.msg)
            self.bottom_layout.addWidget(self.apply_button)
            self.bottom_layout.addWidget(self.cancel_button)
            self.bottom_layout.setContentsMargins(0, 20, 0, 10)
            self.init_bottom_layout()


            #   Vertical Layout
            #------------------------------
            self.vbox_outer = QtWidgets.QVBoxLayout(dialog)
            self.vbox_outer.setObjectName('vbox_outer')
            self.vbox_outer.addLayout(self.top_layout)
            self.vbox_outer.addLayout(self.data_layout)
            self.vbox_outer.addLayout(self.middle_layout)
            self.vbox_outer.addLayout(self.bottom_layout)

            #   Signal Handling
            #------------------------------
            self.init_signals()

        def init_window(self):
            self.dialog.setWindowTitle('FIRST Dialog')
            self.dialog.setWindowIcon(get_first_icon())
            self.dialog.resize(732, 387)

        def init_top_layout(self):
            pass

        def init_middle_layout(self):
            pass

        def init_bottom_layout(self):
            pass

        def init_signals(self):
            self.apply_button.clicked.connect(self.dialog.ok_button_callback)
            self.cancel_button.clicked.connect(self.dialog.reject)

        def init_data_layout(self):
            pass


    class UploadAll(Generic):
        def init_window(self):
            self.dialog.setWindowTitle('FIRST: Mass Function Prototype Upload')
            self.dialog.setWindowIcon(get_first_icon())
            self.dialog.resize(600, 450)

        def init_top_layout(self):
            title = QtWidgets.QLabel('Mass Function Upload')
            title.setStyleSheet('font: 16pt;')

            description = QtWidgets.QLabel((
                'Upload function prototype to server for others to access.\n'
                'Select the functions you want to upload. Click to select a '
                'function and click again to deselect the function. Once '
                'uploaded you can manage prototypes you\'ve created in the '
                'management window.'))
            description.setWordWrap(True)
            description.setLineWidth(200)
            description.setStyleSheet('text-size: 90%')

            vbox_text = QtWidgets.QVBoxLayout()
            vbox_text.addWidget(title)
            vbox_text.addWidget(description)

            vbox_legend = QtWidgets.QVBoxLayout()
            grid_legend = QtWidgets.QGridLayout()
            style = 'background-color: #{0:06x}; border: 1px solid #c0c0c0;'
            colors = [  FIRST.color_changed, FIRST.color_unchanged,
                        FIRST.color_default, FIRST.color_selected]
            text = ['Changed', 'Unchanged', 'Default', 'Selected']
            for i in xrange(len(colors)):
                box = QtWidgets.QLabel()
                box.setFixedHeight(10)
                box.setFixedWidth(10)
                box.setStyleSheet(style.format(colors[i].color().rgb() & 0xFFFFFF))
                grid_legend.addWidget(box, i, 0)
                grid_legend.addWidget(QtWidgets.QLabel(text[i]), i, 1)

            vbox_legend.addLayout(grid_legend)
            vbox_legend.setAlignment(Qt.AlignRight | Qt.AlignBottom)

            self.top_layout.addLayout(vbox_text)
            self.top_layout.addStretch()
            self.top_layout.addLayout(vbox_legend)

        def init_data_layout(self):
            header = ['Address', 'Name', 'Prototype', 'Comment']

            self.table_views = []
            self.data_models = []
            self.total_functions = 0

            segment_str = '0x{0.startEA:08x}-0x{0.endEA:08x}: Name "{1}"'
            if not FIRST.Info.is_32bit():
                segment_str = segment_str.replace(':08x}', ':016x}')

            #   Cycle through segments
            segments = FIRST.Metadata.get_segments_with_functions()
            if not segments:
                msg_box = QtWidgets.QMessageBox()
                msg_box.setIcon(QtWidgets.QMessageBox.Critical)
                msg_box.setWindowTitle('Unable to derive functions')
                msg_box.setText(('Cannot upload function. FIRST cannot '
                                                'find any functions'))
                self.should_show = False
                return

            self.scroll_layout = FIRSTUI.ScrollWidget()

            idaapi.show_wait_box('Getting all defined functions...')
            try:
                first_segment = True
                for segment in segments:
                    segment_name = IDAW.SegName(segment.startEA)
                    segment_info = segment_str.format(segment, segment_name)
                    segment_label = QtWidgets.QLabel(segment_info)
                    segment_label.setContentsMargins(10, 5, 0, 5)

                    func_db = FIRST.Metadata.get_segment_functions(segment)
                    self.total_functions += len(func_db)
                    if idaapi.wasBreak():
                        raise FIRST.Error('canceled')

                    data_model = FIRST.Model.Upload(header, func_db)

                    table_view = QtWidgets.QTableView()
                    table_view.setModel(data_model)
                    table_view.setSortingEnabled(False)
                    table_view.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)
                    table_view.setAlternatingRowColors(False)
                    table_view.setShowGrid(False)
                    hdr = table_view.verticalHeader()
                    hdr.setHighlightSections(False)
                    hdr.setDefaultSectionSize(hdr.minimumSectionSize())
                    hdr.hide()
                    hdr = table_view.horizontalHeader()
                    hdr.setHighlightSections(False)
                    hdr.setDefaultAlignment(Qt.AlignLeft)
                    hdr.setStretchLastSection(True)
                    table_view.resizeColumnsToContents()
                    table_view.setColumnWidth(0, table_view.columnWidth(0) + 10)
                    table_view.setColumnWidth(1, table_view.columnWidth(1) + 10)
                    table_view.setColumnWidth(2, table_view.columnWidth(2) + 10)

                    self.table_views.append(table_view)
                    self.data_models.append(data_model)

                    if not first_segment:
                        self.data_layout.addSpacing(5)
                        first_segment = False

                    self.scroll_layout.addWidget(segment_label)
                    self.scroll_layout.addWidget(table_view)

                    if idaapi.wasBreak():
                        raise FIRST.Error('canceled')

            except FIRST.Error as e:
                if 'canceled' == e.value:
                    self.should_show = False

            finally:
                idaapi.hide_wait_box()

            self.data_layout.addWidget(self.scroll_layout)

        def init_middle_layout(self):
            if not self.should_show:
                return

            vbox = QtWidgets.QVBoxLayout()
            self.select_all = QtWidgets.QCheckBox('Select All ')
            self.filter_sub_funcs = QtWidgets.QCheckBox('Filter Out "sub_" functions ')
            vbox.addWidget(self.filter_sub_funcs)
            vbox.addWidget(self.select_all)

            format_str = '{} functions'.format(self.total_functions)
            self.function_number = QtWidgets.QLabel(format_str)
            self.function_number.setAlignment(Qt.AlignTop)
            self.middle_layout.addWidget(self.function_number)
            self.middle_layout.addStretch()
            self.middle_layout.addLayout(vbox)

        def init_bottom_layout(self):
            self.apply_button.setText('Upload')

        def init_signals(self):
            super(FIRSTUI.UploadAll, self).init_signals()

            self.select_all.stateChanged.connect(self.select_all_callback)
            self.filter_sub_funcs.stateChanged.connect(self.filter_sub_callback)

            callback = lambda y, z: lambda x: self.table_clicked(x, y, z)
            for i in xrange(len(self.table_views)):
                table_view = self.table_views[i]
                data_model = self.data_models[i]
                table_view.clicked.connect(callback(table_view, data_model))

        def filter_sub_callback(self, value):
            self.total_functions = 0
            for data_model in self.data_models:
                data_model.filter_sub_functions(self.filter_sub_funcs.isChecked())
                self.total_functions += data_model.rowCount()

            format_str = '{} functions'
            if self.filter_sub_funcs.isChecked():
                format_str = '{} filtered functions'
            self.function_number.setText(format_str.format(self.total_functions))

            if self.select_all.isChecked():
                self.select_all.setChecked(False)

        def select_all_callback(self, value):
            for data_model in self.data_models:
                data_model.select_all(self.select_all.isChecked())

            for table_view in self.table_views:
                table_view.reset()

        def table_clicked(self, index, table_view, data_model):
            #   If select all is selected then the user is trying to exclude some
            #   prototypes
            if self.select_all.isChecked():
                #   Disconnect checkbox signal to prevent reentry
                self.select_all.stateChanged.disconnect(self.select_all_callback)
                self.select_all.setChecked(False)
                self.select_all.stateChanged.connect(self.select_all_callback)

            data_model.set_row_selected(index.row())
            table_view.reset()

        def get_selected_data(self):
            metadata = []

            for data_model in self.data_models:
                metadata += data_model.get_selected_data()

            return metadata


    class Upload(Generic):
        def init_top_layout(self):
            self.dialog.setWindowTitle('FIRST: Function Prototype Upload')
            self.dialog.setWindowIcon(get_first_icon())
            self.dialog.resize(600, 250)

        def init_data_layout(self):
            function = IDAW.get_func(IDAW.ScreenEA())
            if not function:
                msg_box = QtWidgets.QMessageBox()
                msg_box.setIcon(QtWidgets.QMessageBox.Critical)
                msg_box.setWindowTitle('FIRST: No Function Selected')
                msg_box.setText('No address was selected in the IDA View. '
                                'Please select a function and try again.')
                self.should_show = False
                return

            self.metadata = FIRST.Metadata.get_function(function.startEA)
            if not self.metadata:
                temp_str = 'Unable to retrieve function at 0x{0:x}'
                raise FIRST.Error(temp_str.format(IDAW.ScreenEA()))

            data = [('Name:', self.metadata.name, QtWidgets.QLineEdit),
                    ('Prototype:', self.metadata.prototype, QtWidgets.QLineEdit),
                    ('Comments:', self.metadata.comment, QtWidgets.QPlainTextEdit)]

            hdr_font = lambda x : 'font: {0}pt;'.format(x)
            title = QtWidgets.QLabel('Function Upload')
            title.setStyleSheet(hdr_font(16))

            description = QtWidgets.QLabel((
                'Upload function prototype to server for others to access.\n'
                'Review the data below before uploading. If the metadata needs '
                'updating, then close window and modify the function metadata '
                'in IDA. Once uploaded you can manage prototypes you\'ve created '
                'in the management window.'))
            description.setWordWrap(True)
            description.setStyleSheet('text-size: 90%')

            l_metadata = QtWidgets.QLabel('Metadata')
            l_metadata.setStyleSheet(hdr_font(14))

            vbox_metadata = QtWidgets.QVBoxLayout()
            vbox_metadata.setContentsMargins(10, 0, 0, 0)

            for label, content, gui_component in data:
                hbox = QtWidgets.QHBoxLayout()
                hbox.setAlignment(Qt.AlignTop)

                label = QtWidgets.QLabel(label)
                label.setAlignment(Qt.AlignRight)
                label.setFixedWidth(80)
                label.setContentsMargins(0, 0, 5, 0)
                label.setStyleSheet(hdr_font(10))

                value = gui_component(content)
                value.setReadOnly(True)
                value.setStyleSheet(hdr_font(10))
                if isinstance(value, QtWidgets.QPlainTextEdit):
                    value.setFixedHeight(90)


                hbox.addWidget(label)
                hbox.addWidget(value)
                vbox_metadata.addLayout(hbox)

            vbox_text = QtWidgets.QVBoxLayout()
            vbox_text.addWidget(title)
            vbox_text.addWidget(description)
            vbox_text.addSpacing(10)
            vbox_text.addWidget(l_metadata)
            vbox_text.addLayout(vbox_metadata)


            self.top_layout.addLayout(vbox_text)

        def init_middle_layout(self):
            pass

        def init_bottom_layout(self):
            self.apply_button.setText('Upload')

        def init_signals(self):
            super(FIRSTUI.Upload, self).init_signals()


    class CheckAll(Generic):
        '''Check all docs'''
        def get_server_thread(self):
            try:
                return self._server_thread
            except:
                return None

        def init_window(self):
            self.dialog.setWindowTitle('FIRST: Check for Function Prototypes')
            self.dialog.setWindowIcon(get_first_icon())
            self.dialog.resize(750, 400)

        def init_top_layout(self):
            title = QtWidgets.QLabel('Check All Functions')
            title.setStyleSheet('font: 16pt;')

            description = QtWidgets.QLabel((
                'Query FIRST\'s server for function metadata.\n'
                'If a function within this IDB matches a signature found in '
                'FIRST then it and its metadata will be available for you to '
                'select below to apply to your IDB. Select the function you '
                'wish to apply existing metadata to in order to view the '
                'possible matches.'))
            description.setWordWrap(True)
            description.setStyleSheet('text-size: 90%')

            vbox_text = QtWidgets.QVBoxLayout()
            vbox_text.addWidget(title)
            vbox_text.addWidget(description)

            widget = QtWidgets.QWidget()
            widget.setFixedWidth(100)
            vbox_legend = QtWidgets.QVBoxLayout(widget)
            grid_legend = QtWidgets.QGridLayout()
            style = 'background-color: #{0:06x}; border: 1px solid #c0c0c0;'
            colors = [FIRST.color_applied, FIRST.color_selected]
            text = ['Applied', 'Selected']
            for i in xrange(len(colors)):
                box = QtWidgets.QLabel()
                box.setFixedHeight(10)
                box.setFixedWidth(10)
                box.setStyleSheet(style.format(colors[i].color().rgb() & 0xFFFFFF))
                grid_legend.addWidget(box, i, 0)
                grid_legend.addWidget(QtWidgets.QLabel(text[i]), i, 1)

            vbox_legend.addLayout(grid_legend)
            vbox_legend.setAlignment(Qt.AlignRight | Qt.AlignBottom)
            vbox_legend.setContentsMargins(20, 0, 0, 0)


            self.top_layout.addLayout(vbox_text)
            self.top_layout.addWidget(widget)

        def init_data_layout(self):
            self.groups = {}
            idaapi.show_wait_box('Checking FIRST for all functions')

            functions = FIRST.Metadata.get_non_jmp_wrapped_functions()
            metadata = set([FIRST.Metadata.get_function(x) for x in functions])

            if None in metadata:
                metadata.remove(None)

            metadata = list(metadata)

            if not len(metadata):
                idaapi.hide_wait_box()
                title = 'Unable to derive functions'
                msg = 'FIRST cannot find any functions'
                idaapi.execute_ui_requests((FIRSTUI.Requests.MsgBox(title, msg),))
                self.should_show = False
                return

            #   Initiailize data model with no data to prevent the same
            #   data from being added twice
            self.data_model = FIRST.Model.Check(self.groups)
            self._model_builder(self.data_model, self.groups, True)

            server_thread = FIRST.server.scan(  metadata,
                                                self.__data_callback,
                                                self._complete_callback)
            self._server_thread = server_thread

            idaapi.hide_wait_box()

            tree_view = FIRST.Model.TreeView()
            tree_view.setUniformRowHeights(False)
            tree_view.setExpandsOnDoubleClick(False)
            tree_view.setIndentation(15)
            tree_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
            tree_view.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)

            tree_view.setModel(self.data_model)

            tree_view.setColumnWidth(0, 175)    #   Function
            tree_view.setColumnWidth(1, 55)     #   Matches
            tree_view.setColumnWidth(2, 35)     #   Rank
            tree_view.setColumnWidth(3, 75)     #   Similarity
            tree_view.setColumnWidth(4, 150)    #   Prototype
            tree_view.setColumnWidth(5, 20)     #   i
            tree_view.setColumnWidth(7, 20)     #   i

            self.tree_view = tree_view
            self.data_layout.addWidget(self.tree_view)

            self.timer_i = 0
            self.timer = QtCore.QTimer()
            self.timer.timeout.connect(self._searching_text)
            self.timer.start(750)

        def _searching_text(self):
            #   Provide user with update if thread is still working
            self.timer_i = (self.timer_i + 1) % 4
            self.msg.setText('Searching FIRST' + ('.' * self.timer_i))

        def __data_callback(self, thread, data):
            if data and len(data):
                self.groups.update(data)
                self._model_builder(self.data_model, data)

                message = self.found_format.format(len(self.groups))
                self.found_label.setText(message)

                self.filter_only_subs()

        def _complete_callback(self, thread, data):
            self.timer.stop()
            FIRST.server.remove_operation(thread)

            #   Alert the user if no matches were found in FIRST
            if not self.groups:
                self.msg.setText('No matches found in FIRST\'s database')
                return

            self.msg.setText('Finished searching FIRST')

        def _make_function_item(self, function, matches):
            '''
            Top level function information (level-0)
            '''
            #if not isinstance(function, FIRST.MetadataShim):
            if not {'name', 'address'}.issubset(dir(function)):
                return QtGui.QStandardItem('-')

            label = '0x{0.address:08x} - {0.name}'
            if not FIRST.Info.is_32bit():
                label = label.replace(':08x}', ':016x}')

            function_label = QtGui.QStandardItem(label.format(function))
            function_label.setToolTip(function.name)
            function_label.setData(function.address, role=FIRSTUI.ROLE_ADDRESS)
            function_label.setData(function.name, role=FIRSTUI.ROLE_NAME)

            if 999999 < matches:
                matches = '{}M'.format(round(matches / 1000000.0, 1))
            elif 999 < matches:
                matches = '{}K'.format(round(matches / 1000.0, 1))
            else:
                matches = str(matches)

            matches = QtGui.QStandardItem(matches)
            matches.setTextAlignment(Qt.AlignCenter)

            row = [function_label, matches] + \
                    [QtGui.QStandardItem() for i in range(7)]

            [x.setEditable(False) for x in row]
            return row

        def _model_builder(self, model, data, initialize=False):
            '''
            Build the function model.
            @param model: QStandardItemModel object
            '''
            if initialize:
                model.clear()  # Clear the model
                FIRSTUI.SharedObjects.make_model_headers(model)

            if not data:
                return

            model.add_data(data)

            # Add db functions to the model
            root_node = model.invisibleRootItem()
            for address, matches in data.iteritems():
                function = FIRST.Metadata.get_function(address)

                func_row = self._make_function_item(function, len(matches))
                root_node.appendRow(func_row)

                for match in matches:
                    info_list = FIRSTUI.SharedObjects.make_match_info(match)
                    func_row[0].appendRow(info_list)

        def init_middle_layout(self):
            found = len(self.groups)
            total = len(FIRST.Metadata.get_non_jmp_wrapped_functions())
            s = 's' if 1 != total else ''
            label = 'Matched {0} out of {1} function{2}'

            self.select_highest_ranked = QtWidgets.QCheckBox('Select Highest Ranked ')
            self.filter_sub_funcs_only = QtWidgets.QCheckBox('Show only "sub_" functions')

            vbox = QtWidgets.QVBoxLayout()
            vbox.addWidget(self.filter_sub_funcs_only)
            vbox.addWidget(self.select_highest_ranked)

            self.found_format = label.format('{}', total, s)
            self.found_label = QtWidgets.QLabel(self.found_format.format(found))
            self.found_label.setAlignment(Qt.AlignTop)

            self.middle_layout.addWidget(self.found_label)
            self.middle_layout.addStretch()
            self.middle_layout.addLayout(vbox)

        def init_bottom_layout(self):
            pass

        def init_signals(self):
            if not self.should_show:
                return

            super(FIRSTUI.CheckAll, self).init_signals()
            self.select_highest_ranked.stateChanged.connect(self.select_highest)
            self.filter_sub_funcs_only.stateChanged.connect(self.filter_only_subs)
            self.tree_view.clicked.connect(self.tree_clicked)

            #   A reference is needed to the dialog or else it closes quickly
            #   after showing
            self.history_dialogs = []
            self.tree_view.setContextMenuPolicy(Qt.CustomContextMenu)
            self.tree_view.customContextMenuRequested.connect(self.custom_menu)

        def custom_menu(self, point):
            index = self.tree_view.indexAt(point)
            address = index.data(FIRSTUI.ROLE_ADDRESS)
            if not address:
                return

            menu = QtWidgets.QMenu(self.tree_view)
            goto_action = QtWidgets.QAction('&Go to Function', self.tree_view)
            goto_action.triggered.connect(lambda:IDAW.Jump(address))
            menu.addAction(goto_action)

            metadata_id = index.data(FIRSTUI.ROLE_ID)
            if metadata_id:
                history_action = QtWidgets.QAction('View &History', self.tree_view)
                history_action.triggered.connect(lambda:self.metadata_history(metadata_id))
                menu.addAction(history_action)

            menu.exec_(QtGui.QCursor.pos())

        def metadata_history(self, metadata_id):
            dialog = FIRSTUI.Dialog(None, FIRSTUI.History, metadata_id=metadata_id)
            dialog.show()

            #   Keep a reference to the dialog so it doesn't hide before the
            #   user is done with it
            self.history_dialogs.append(dialog)

        def tree_clicked(self, index):
            #   If select all is selected then the user is trying to exclude some
            #   metadata
            if self.select_highest_ranked.isChecked():
                #   Disconnect checkbox signal to prevent reentry
                self.select_highest_ranked.stateChanged.disconnect(self.select_highest)
                self.select_highest_ranked.setChecked(False)
                self.select_highest_ranked.stateChanged.connect(self.select_highest)

            data_id = index.data(FIRSTUI.ROLE_ID)
            address = index.data(FIRSTUI.ROLE_ADDRESS)
            if data_id and address:
                self.data_model.set_id_selected((address, data_id))
                self.tree_view.clearFocus()

        def get_groups(self):
            return self.groups

        def select_highest(self):
            flag = self.select_highest_ranked.isChecked()

            #   Get list of hidden addresses
            hidden = []
            if flag and self.filter_sub_funcs_only.isChecked():
                root = self.data_model.invisibleRootItem()
                for i in xrange(root.rowCount()):
                    child = root.child(i)
                    if child and self.tree_view.isIndexHidden(child.index()):
                        hidden.append(child.data(FIRSTUI.ROLE_ADDRESS))

            self.data_model.select_highest_ranked(flag, hidden)
            self.tree_view.setFocus()

        def filter_only_subs(self):
            flag = self.filter_sub_funcs_only.isChecked()

            hidden = []
            root = self.data_model.invisibleRootItem()
            for i in xrange(root.rowCount()):
                child = root.child(i)
                if not child:
                    continue

                name = child.data(FIRSTUI.ROLE_NAME)
                if not name:
                    continue

                hide = not name.startswith('sub_')
                self.tree_view.setRowHidden(i, root.index(), flag and hide)

                if flag and hide:
                    hidden.append(child.data(FIRSTUI.ROLE_ADDRESS))

            if hidden:
                self.data_model.unselect_group(hidden)


    class Check(CheckAll):
        def init_window(self):
            super(FIRSTUI.Check, self).init_window()
            self.dialog.setWindowTitle('FIRST: Check for Function Prototype')

        def init_top_layout(self):
            title = QtWidgets.QLabel('Check Function')
            title.setStyleSheet('font: 16pt;')

            description = QtWidgets.QLabel((
                'Query FIRST\'s server for function metadata.\n'
                'If a function within this IDB matches a signature found in '
                'FIRST then it and its metadata will be available for you to '
                'select below to apply to your IDB. Click to select a '
                'function\'s metadata and click again to deselect it.'))
            description.setWordWrap(True)
            description.setStyleSheet('text-size: 90%')

            vbox_text = QtWidgets.QVBoxLayout()
            vbox_text.addWidget(title)
            vbox_text.addWidget(description)

            widget = QtWidgets.QWidget()
            widget.setFixedWidth(100)
            vbox_legend = QtWidgets.QVBoxLayout(widget)
            grid_legend = QtWidgets.QGridLayout()
            style = 'background-color: #{0:06x}; border: 1px solid #c0c0c0;'
            colors = [FIRST.color_applied, FIRST.color_selected]
            text = ['Applied', 'Selected']
            for i in xrange(len(colors)):
                box = QtWidgets.QLabel()
                box.setFixedHeight(10)
                box.setFixedWidth(10)
                box.setStyleSheet(style.format(colors[i].color().rgb() & 0xFFFFFF))
                grid_legend.addWidget(box, i, 0)
                grid_legend.addWidget(QtWidgets.QLabel(text[i]), i, 1)

            vbox_legend.addLayout(grid_legend)
            vbox_legend.setAlignment(Qt.AlignRight | Qt.AlignBottom)
            vbox_legend.setContentsMargins(20, 0, 0, 0)


            self.top_layout.addLayout(vbox_text)
            self.top_layout.addWidget(widget)

        def __data_callback(self, thread, data):
            if data and len(data):
                self.groups.update(data)
                self.data_model.add_data(data)
                self._model_builder(self.data_model)

        def init_data_layout(self):
            function = IDAW.get_func(IDAW.ScreenEA())
            if not function:
                title = 'FIRST: No Function Selected'
                msg = ('No address was selected in the IDA View. '
                                'Please select a function and try again.')
                idaapi.execute_ui_requests((FIRSTUI.Requests.MsgBox(title, msg),))
                self.should_show = False
                return

            self.metadata = FIRST.Metadata.get_function(function.startEA)
            if not self.metadata:
                title = 'FIRST: Could not load function'
                msg = ('FIRST is unable to get the function\'s '
                        'metadata. Please select a function and try again.')
                idaapi.execute_ui_requests((FIRSTUI.Requests.MsgBox(title, msg),))
                self.should_show = False
                return

            self.groups = {}

            idaapi.show_wait_box('Checking FIRST for matches')


            #   Initiailize data model with no data to prevent the same
            #   data from being added twice
            self.data_model = FIRST.Model.Check(self.groups)
            self._model_builder(self.data_model)

            server_thread = FIRST.server.scan(  [self.metadata],
                                                self.__data_callback,
                                                self._complete_callback)
            self._server_thread = server_thread

            idaapi.hide_wait_box()

            tree_view = FIRST.Model.TreeView()
            tree_view.setUniformRowHeights(False)
            tree_view.setExpandsOnDoubleClick(False)
            tree_view.setIndentation(15)
            tree_view.setSelectionBehavior(QtWidgets.QAbstractItemView.SelectRows)
            tree_view.setSelectionMode(QtWidgets.QAbstractItemView.NoSelection)

            tree_view.setModel(self.data_model)

            tree_view.setColumnWidth(0, 200)    #   Function
            tree_view.setColumnWidth(1, 40)     #   Rank
            tree_view.setColumnWidth(2, 75)     #   Similarity
            tree_view.setColumnWidth(3, 150)    #   Prototype
            tree_view.setColumnWidth(4, 20)     #   i
            tree_view.setColumnWidth(6, 20)     #   i


            self.tree_view = tree_view
            self.data_layout.addWidget(self.tree_view)

            self.timer_i = 0
            self.timer = QtCore.QTimer()
            self.timer.timeout.connect(self._searching_text)
            self.timer.start(750)

        def _model_builder(self, model):
            model.clear()
            root_node = model.invisibleRootItem()

            FIRSTUI.SharedObjects.make_model_headers(model, check_all=False)

            matches = self.get_groups()
            if not matches:
                return

            address = matches.keys()[0]
            for match in matches[address]:
                row = FIRSTUI.SharedObjects.make_match_info(match, check_all=False)
                root_node.appendRow(row)

        def init_middle_layout(self):
            pass

        def init_signals(self):
            if self.should_show:
                super(FIRSTUI.CheckAll, self).init_signals()
                self.tree_view.clicked.connect(self.tree_clicked)

                #   A reference is needed to the dialog or else it closes quickly
                #   after showing
                self.history_dialogs = []
                self.tree_view.setContextMenuPolicy(Qt.CustomContextMenu)
                self.tree_view.customContextMenuRequested.connect(self.custom_menu)

        def tree_clicked(self, index):
            data_id = index.data(FIRSTUI.ROLE_ID)
            address = index.data(FIRSTUI.ROLE_ADDRESS)
            if data_id and address:
                self.data_model.set_id_selected((address, data_id))
                self.tree_view.clearFocus()


    class History(Generic):
        def __init__(self, metadata_id):
            self.should_show = True
            self.metadata_id = metadata_id

        def init_window(self):
            self.dialog.setWindowTitle('FIRST: Metadata Revision History')
            self.dialog.setWindowIcon(get_first_icon())
            self.dialog.resize(600, 400)

        def utc_to_local(self, utc_str):
            if not utc_str:
                return None

            utc_dt = datetime.datetime.strptime(utc_str[:26], '%Y-%m-%dT%H:%M:%S.%f')
            timestamp = calendar.timegm(utc_dt.timetuple())
            local = datetime.datetime.fromtimestamp(timestamp)
            return local.replace(microsecond=utc_dt.microsecond)

        def init_top_layout(self):
            history = FIRST.server.history(self.metadata_id)
            if (not history
                or ('results' not in history)
                or (self.metadata_id not in history['results'])
                or ('creator' not in history['results'][self.metadata_id])
                or ('history' not in history['results'][self.metadata_id])):
                self.should_show = False
                return

            self.creator = history['results'][self.metadata_id]['creator']
            self.history = history['results'][self.metadata_id]['history']

            title = QtWidgets.QLabel('Revision History')
            title.setStyleSheet('font: 16pt;')
            creator = QtWidgets.QLabel('by: <b>{}</b>'.format(self.creator))
            creator.setAlignment(Qt.AlignRight | Qt.AlignBottom)

            self.top_layout.addWidget(title)
            self.top_layout.addStretch()
            self.top_layout.addWidget(creator)

        def init_data_layout(self):
            if not self.should_show:
                return

            vbox_text = QtWidgets.QVBoxLayout()
            scroll_layout = FIRSTUI.ScrollWidget(frame=QtWidgets.QFrame.NoFrame)
            scroll_layout.addLayout(vbox_text)

            first_record = True
            cmp_func = lambda x,y: cmp( self.utc_to_local(y['committed']),
                                        self.utc_to_local(x['committed']))
            for details in sorted(self.history, cmp_func):
                if not first_record:
                    hr = QtWidgets.QFrame()
                    hr.setFrameShape(QtWidgets.QFrame.HLine)
                    hr.setFrameShadow(QtWidgets.QFrame.Sunken)

                    vbox_text.addWidget(hr)

                hbox = QtWidgets.QHBoxLayout()
                local = self.utc_to_local(details['committed'])

                vbox = QtWidgets.QVBoxLayout()
                vbox.setContentsMargins(0, 5, 0, 0)
                local_str = 'N/A'
                if local:
                    local_str = datetime.datetime.strftime(local, '%B %d, %Y\n%I:%M:%S %p')
                timestamp = QtWidgets.QLabel(local_str)
                timestamp.setFixedWidth(125)
                timestamp.setAlignment(Qt.AlignCenter | Qt.AlignVCenter)
                vbox.addWidget(timestamp)
                hbox.addLayout(vbox)

                #   Second Column
                vbox = QtWidgets.QVBoxLayout()
                vbox.setContentsMargins(0, 5, 0, 5)
                for label in ['Name', 'Prototype', 'Comment']:
                    l = QtWidgets.QLabel('<b>{}</b>'.format(label))
                    l.setFixedWidth(75)
                    l.setAlignment(Qt.AlignRight)
                    vbox.addWidget(l)

                vbox.addStretch()
                vbox.setAlignment(Qt.AlignTop)
                hbox.addLayout(vbox)

                #   Third Column
                vbox = QtWidgets.QVBoxLayout()
                vbox.setContentsMargins(0, 5, 0, 5)
                comment = QtWidgets.QLabel(details['comment'])
                if not details['comment']:
                    comment = QtWidgets.QLabel('- No Comment -')
                comment.setWordWrap(True)

                vbox.addWidget(QtWidgets.QLabel(details['name']))
                vbox.addWidget(QtWidgets.QLabel(details['prototype']))
                vbox.addWidget(comment)
                vbox.addStretch()

                hbox.addLayout(vbox)
                vbox_text.addLayout(hbox)
                first_record = False

            self.data_layout.addSpacing(5)
            self.data_layout.addWidget(scroll_layout)

        def init_middle_layout(self):
            vbox = QtWidgets.QVBoxLayout()
            vbox.addStretch()
            self.middle_layout.addLayout(vbox)

        def init_bottom_layout(self):
            self.bottom_layout.removeWidget(self.apply_button)
            self.cancel_button.setText('Close')

        def init_signals(self):
            super(FIRSTUI.History, self).init_signals()


    #   GUI Shown to user when first installed
    #-------------------------------------------------------------------------------
    class Welcome(Generic):
        def init_window(self):
            super(FIRSTUI.Welcome, self).init_window()
            self.dialog.setWindowTitle('FIRST')
            self.dialog.resize(375, 400)

        def init_top_layout(self):
            vbox = QtWidgets.QVBoxLayout()

            label = QtWidgets.QLabel('FIRST')
            label.setStyleSheet('font: 40px;')
            vbox.addWidget(label)

            label = QtWidgets.QLabel('Function Identification and Recovery Signature Tool')
            label.setStyleSheet('font: 12px;')
            vbox.addWidget(label)

            self.top_layout.addLayout(vbox)

            self.top_layout.addSpacing(10)

        def init_data_layout(self):
            FIRSTUI.SharedObjects.server_config_layout(self, self.data_layout)

        def init_middle_layout(self):
            #self.check_on_startup = QtWidgets.QCheckBox("Check FIRST on IDA startup")
            #self.middle_layout.addWidget(self.check_on_startup)
            self.middle_layout.addStretch()

        def init_signals(self):
            super(FIRSTUI.Welcome, self).init_signals()

        def show(self):
            super(FIRSTUI.Welcome, self).show()


    #   Class to interface with Dialog GUIs and the back end data
    #-------------------------------------------------------------------------------
    class Dialog(QtWidgets.QDialog):
        error_format = '<font color="#ff0000">{0}</font>'
        def __init__(self, parent, dialog, **kwargs):
            super(FIRSTUI.Dialog, self).__init__(parent)
            self.parent = parent
            self.data = None


            self.ui = dialog(**kwargs)
            self.ui.setupUi(self)

            self.should_show = self.ui.should_show

            self.accepted.connect(self.success_callback)
            self.rejected.connect(self.reject_callback)
            self.setWindowFlags(self.windowFlags() & ~Qt.WindowContextHelpButtonHint)

            self.hide_attempts = 0
            self.timer = QtCore.QTimer()
            self.timer.timeout.connect(self.__hide)
            self.timer.start(500)

        def registerSuccessCallback(self, fn):
            self.callback_fn = fn

        def success_callback(self):
            if self.callback_fn != None:
                self.callback_fn(self.ui)

        def ok_button_callback(self):
            if self.reject_accept():
                return

            self._stop_server_thread()

            self.accept()

        def reject_accept(self):
            return False

        def reject_callback(self):
            self._stop_server_thread()

            self.close()

        def _stop_server_thread(self):
            server_thread = self.ui.get_server_thread()
            if server_thread and (threading.Thread == type(server_thread)):
                if server_thread.is_alive():
                    FIRST.server.stop_operation(server_thread)

        def show(self):
            if self.should_show:
                super(type(self), self).show()

        def __hide(self):
            if not self.ui.should_show:
                self.hide()

            #   Check for up to 5 seconds whether the dialog needs to be
            #   closed or not
            self.hide_attempts += 1
            if self.hide_attempts > 10:
                self.timer.stop()



#   Create FIRST icon
def get_first_icon(return_hex=False, return_pixmap=False):
    first_icon = (  '89504e470d0a1a0a0000000d49484452000000700000008708030000'
                    '00f9a92dd80000001974455874536f6674776172650041646f626520'
                    '496d616765526561647971c9653c0000005d504c54458a8a84b7b6b3'
                    'eaeae9d8d8d6b1b1ad797872d6d5d4c1c1be6d6c66a2a19d8d8d87e2'
                    'e2e0acaca86e6d67c5c4c2f5f5f4e0e0decbcbc9989792cececc8382'
                    '7da7a7a394938e81807aecebebf5f5f5777670bbbab79e9d9964635c'
                    'ffffffe54bab180000001f74524e53ffffffffffffffffffffffffff'
                    'ffffffffffffffffffffffffffffffffff00cd1976100000026f4944'
                    '415478daecdae9b2822014006050cca55cd2b4ac8befff9837771445'
                    '30619ae69c5f05d1172207704295e140000208e0f78311a5288fcec6'
                    'c0b7d706ca5ff6433f38785ddc0b924d7b8b2f4dc50de3aaaa5fe226'
                    '98fa3a6eef0a4b069c7b4d78a368f96cc58d8a42068c969bdefbfa2b'
                    '550809305b6bdb5f2d7a2c78f6c4a09a474f5be0baf76cc72f3c165c'
                    'f768dbc65fa8b90d77d354919816028ffed51f88fb777efda5316e7c'
                    '773728f22861ef50779c71a953ed053391d782ed7ca7c1f20f560489'
                    '78f8edfa3369fb1aaf0c890a58222a0106f32bba1b145fce39f8710f'
                    '1fc5f68c6267852306ad0db0241e9504fb3ce37f003ea4b80e4cfa77'
                    '81b5043adb60f92799a3bac522180a2ef12eb0904d8a5d93135384f7'
                    '804811eca77e132136004e44ea5cb581f9d0e4eab0e5a92e90b05b28'
                    'b6c25703f33d6015b3cba2ab04925de07b428ef3233402be8772d86c'
                    '5ce799263902ccb82f491ceebe9148ded2a0cde795d37c4f2303a20f'
                    'c03ecf0d6b47ac1bc433d0e2069507ef3a4057004ece2b05b1ed4801'
                    '4c675baa4405bcbfcefc4f6062e194187713e332bf8bdcad31447956'
                    '2ef6993fca2c74701cb2d3eaba253a3dc98256c0651a571f68e17461'
                    '1dd600ba82a38c1630e1ca438b5fb6fc032fe9fc44ef24955ef0322d'
                    '9dee16758093410cddc5cc7328c80ca2835752dd98093e00fb872671'
                    'd06d10717cd493a88d5de2f18fbe000410400001041040007f007c98'
                    '066d00010410c0df035fa6410220805f0ffe99061180bf0a7aa641aa'
                    '0df44c8314400015c1d234680308e0d7839969900008e0d783b96910'
                    '0108e051e0531758c8fe35f128f0fc9cf40bb55144952e50530008a0'
                    '72fc0b3000d4bbb97bf44864540000000049454e44ae426082')

    if return_hex:
        return first_icon

    image = QtGui.QImage()
    image.loadFromData(QtCore.QByteArray.fromHex(first_icon))

    pixmap = QtGui.QPixmap()
    pixmap.convertFromImage(image)
    if return_pixmap:
        return pixmap

    return QtGui.QIcon(pixmap)

FIRST_ICON = get_first_icon(True).decode('hex')
FIRST_ICON = IDAW.load_custom_icon(data=FIRST_ICON, format='png')


#   Function Identification and Recovery Signature Tool (FIRST) Plug-in Class
#-------------------------------------------------------------------------------
class FIRST_Plugin(idaapi.plugin_t):
    flags = idaapi.PLUGIN_FIX
    comment = 'Function Identification and Recovery Signature Tool'

    #   IDA Pro display details
    help = 'Configure Function Identification and Recovery Signature Tool (FIRST)'
    wanted_name = 'FIRST'
    wanted_hotkey = '1'

    def init(self):
        FIRST.initialize()
        return idaapi.PLUGIN_KEEP

    def run(self, arg):
        if FIRST.plugin:
            FIRST.plugin.Show(self.wanted_name)

    def term(self):
        FIRST.cleanup_hooks()

def PLUGIN_ENTRY():
    global required_modules_loaded

    if required_modules_loaded:
        return FIRST_Plugin()

    idaapi.execute_ui_requests((FIRSTUI.Requests.Print('[1st] Unable to load all required modules.\n'),))
    return None
