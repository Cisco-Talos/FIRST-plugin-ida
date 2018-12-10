.. _ida-installing:

=================
Installing Plugin
=================

Since FIRST is an IDA Python plugin it only works with a license version of Hex Ray's IDA Pro. Due to the integrations with IDA Pro there is a minimum version number. The FIRST plugin only works with IDA 6.9 (service pack 1), relased May 2016, and higher.

.. important::
    It is easier to install Python from Python.org with the latest 2.7 build instead of using the outdated version of Python bundled in with IDA Pro.

.. attention::
    There are many ways to install FIRST, the quickest way is to use :program:`pip` and run the setup script. The setup's location differs depending on the OS being used and other possible configurations. The defaults for Mac and Windows are below.

    **Mac**

    .. code-block:: console

        $ pip install first-plugin-ida
        $ /usr/local/bin/first-plugin-ida

    **Windows**

    .. code-block:: html

        > pip install first-plugin-ida
        > C:\Python27\Scripts\first-plugin-ida

To use FIRST, you will need to download the plugin and save it to the Hex Rays IDA Pro plugin folder. Directions for this differ depending on the operating system and a basic guide can be found below.

FIRST is available on PyPI, so to use it you can use :program:`pip`:

.. code-block:: console

    $ pip install first-plugin-ida

Alternatively, if you don't have setuptools installed, `download it from PyPi
<http://pypi.python.org/pypi/first-plugin-ida/>`_ and run

.. code-block:: console

    $ python setup.py install

To use the bleeding-edge version of FIRST's IDA Pro Integration, you can get the source from
`GitHub <http://github.com/vrtadmin/FIRST-plugin-ida/>`_ and install it as above:

.. code-block:: console

    $ git clone git://github.com/vrtadmin/FIRST-plugin-ida
    $ python setup.py install

Once first-plugin-ida is installed with pip, the post installation script needs to be executed. The script simply copies over the plugin and its files to the IDA Pro installation of your choosing. Depending on your system setup, configuration, and user privileges you may need to be admin or root to successfully use the script.

+---------+-----------------------------------------+
| OS      | Default Path                            |
+=========+=========================================+
| Mac     | /usr/local/bin/first-plugin-ida         |
+---------+-----------------------------------------+
| Windows | C:\\Python27\\Scripts\\first-plugin-ida |
+---------+-----------------------------------------+

The script will ask you for the full path to the IDA Pro installation. Providing it will copy the plugin to IDA Pro and its dependencies. The default location for
IDA Pro installations are outline below.

+---------+--------------------------------------------------------------+
| OS      | Default Path                                                 |
+=========+==============================================================+
| Mac     | Applications/IDA\\ Pro\\ 6.9/idaq.app/Contents/MacOS/plugins |
+---------+--------------------------------------------------------------+
| Windows | C:\\Program Files (x86)\\IDA 6.9\\plugins                    |
+---------+--------------------------------------------------------------+

Once the script completes without any errors you will be able to use FIRST in IDA Pro.

Manual Installation
===================
If you do not wish to use pip or the post installation script then FIRST can be installed manually. To install the plugin you will need to get the plugin's source from `GitHub`_. The source for the plugin includes every file in the FIRST-plugin-ida/first_plugin_ida folder except FIRST-plugin-ida/first_plugin_ida/__init__.py file. All other files need to be copied over to IDA Pro's plugins directory. Depending on the OS IDA is running on you may need to copy over other dependencies to IDA Pro's folders.

Requirements
============
Additionally, FIRST requires one third party module to work and an optional module if Kerberos Authentication is used

* [Required] Requests (https://pypi.python.org/pypi/requests)
* [Optional] Requests-kerberos (https://pypi.python.org/pypi/requests-kerberos)

Windows
=======
Once you have a copy of the plug-in, installing the plug-in is as simple as copying the Python file into the plugins folder. For IDA 6.9, the default installation path can be found at:

.. list-table::
   :stub-columns: 1

   * - Default IDA Pro Path
     - C:\\Program Files (x86)\\IDA 6.9\\plugins
   * - Dependency Instructions
     - pip install requests


Mac OS X
========
Installing on Mac OS X requires a little more work, once you've installed IDA Pro, copy the FIRST plugin to the <installed_path>/Contents/MacOS/plugins/ folder and the required dependencies to <installed_path>/Contents/MacOS/python/

.. list-table::
   :stub-columns: 1

   * - Default IDA Pro Path
     - /Applications/IDA\\ Pro\\ 6.9/idaq.app/Contents/MacOS/plugins/
   * - Dependency Instructions
     - pip install requests

       cp /usr/local/lib/python2.7/site-packages/requests* /Applications/IDA\ Pro\ 6.9/idaq.app/Contents/MacOS/python

Linux
=====
During the setup, IDA asks whether to install with the bundled Python interpreter or use the local Python interpreter from the local system. Bundled Python is nice, everything just works by default. However the downside is that you can't really add and upgrade Python libraries, and the FIRST plugin requires the requests plugin which is not by default in the bundle.

If you installed with bundled Python, you can switch to use the local Python simply by renaming ``libpython2.7.so.1.0`` and ``python/lib/python27.zip``. For instance:

.. code-block:: console

    $ cd $IDA_DIR
    $ mv libpython2.7.so.1.0{,.orig}
    $ mv python/lib/python27.zip{,.orig}

You can revert back to bundle Python by reverting the renames.

Unfortunately the downside of using local Python is that if you are running under x86_64, IDA being a 32-bit binary, it won't work out of the box. Fortunately, under recent Debian (e.g. stretch) and Ubuntu, you can install libs from other architectures. For instance, what worked for us:

.. code-block:: console

    $ dpkg --add-architecture i386
    $ apt update
    $ apt install --no-install-recommends gtk2-engines-murrine:i386 gtk2-engines-pixbuf:i386 libc6-i686:i386 libcurl3:i386 libdbus-1-3:i386 libexpat1:i386 libffi6:i386 libfontconfig1:i386 libfreetype6:i386 libgcc1:i386 libglib2.0-0:i386 libgtk2.0-0:i386 libice6:i386 libpcre3:i386 libpng16-16:i386 libpython2.7:i386 libsm6:i386 libstdc++6:i386 libuuid1:i386 libx11-6:i386 libx11-xcb1:i386 libxau6:i386 libxcb1:i386 libxdmcp6:i386 libxext6:i386 libxi6:i386 libxrender1:i386 python-pyqt5:i386 xdg-utils zlib1g:i386 python-requests

Tip: if your distro is different or too old, try a chroot (e.g. debootstrap & schroot), works pretty well.

Copy the FIRST plugin (``first.py``) to your plugins directory (``~/.idapro/plugins``) and start IDA (32 or 64), it should all work!
