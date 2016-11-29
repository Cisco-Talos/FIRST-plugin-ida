import os
import platform
import shutil

#   Third party Module, should be installed by prerequisites
import requests

class ExitException(Exception):
    pass

def main():
    print ( 'FIRST: Function Identification and Recovery Signature Tool\n'
            'IDA Pro Integration\n'
            'Requirements: \n'
            '- IDA Pro 6.9 sp1 or higher\n'
            '- Admin Privileges\n'
            '  (usually needed to copy plugin into IDA directory)\n\n')

    try:
        first_dir = os.path.dirname(__file__)
        first_path = os.path.join(first_dir, 'first.py')

        ida_plugin_path = raw_input('Enter full path to IDA\'s plugins folder: ')
        if not os.path.exists(ida_plugin_path):
            print '[Error] Path provided does not exist.'
            raise ExitException()

        if not os.path.isdir(ida_plugin_path):
            print '[Error] Path provided is not a directory.'
            raise ExitException()

        if (os.name == 'posix') and (platform.system() == 'Darwin'):
            #   Install for Mac

            requests_path = os.path.dirname(requests.__file__)
            ida_path = os.path.dirname(ida_plugin_path)

            #   Copy requests to IDA's python folder
            print '- Copying FIRST dependencies to IDA\'s python folder...'
            cmd = 'cp -r {} {}/python/requests/'.format(requests_path, ida_path)
            os.system(cmd)


        elif (os.name == 'nt') and (platform.system() == 'Windows'):
            #   Install for Windows - no additional steps required
            pass

        #elif (os.name == 'posix') and (platform.system() == 'Linux'):
        #   Currently not supported due to having no ida to bring in the
        #dependencies for Linux

        else:
            #   Doesn't support other systems
            print '- Unfortunately the current OS is not supported.'
            raise ExitException()

        #   Copy plugin to IDA's plugin directory
        shutil.copy(first_path, ida_plugin_path)
        msg = ( '- FIRST\'s IDA Pro Integration has been installed. Plugin is\n'
                '  located at:\n  {}')
        print msg.format(os.path.join(ida_plugin_path, 'first.py'))

    except ExitException:
        pass

    finally:
        print '...exiting...'
