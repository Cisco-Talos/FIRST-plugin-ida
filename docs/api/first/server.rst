===============
FIRST :: Server
===============

.. py:function:: data_callback_prototype(thread, response)

    Function prototype for data_callback arguments.

    :param threading.Thread thread: The thread associated with the server
        operation.
    :param requests.models.response response: The response from the server
        in JSON form.


.. py:function:: complete_callback_prototype(thread, data)

    Function prototype for complete_callback arguments. This function should
    call ``FIRST.server.remove_operation`` to ensure data is released once it is
    not needed.

    :param threading.Thread thread: The thread associated with the server
        operation.
    :param dict data: All data received from the server.

.. autoclass:: first_plugin_ida.first.FIRST
    :noindex:
    :members: Server
    :undoc-members: 
