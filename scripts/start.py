from cloudify import ctx
from cloudify.state import ctx_parameters as inputs
from cloudify_rest_client import CloudifyClient
import ldap
import time
import sys
import os


# Starts the operator
token_secret = None
token = None


def main():

    # TODO Uncomment when testing on a manager
    #    try:
    #        token_secret = ctx.node.properties['token_secret']
    #    except Exception:
    #        ctx.logger.error("failed to get token secret")
    #        sys.exit(1)
    #
    #


    pid = os.fork()
    if pid > 0:
        ctx.instance.runtime_properties["pid"] = str(pid)
        time.sleep(2)
        return

    os.chdir("/tmp")
    os.setsid()
    os.umask(0)
    close_fds([])

    pid = os.fork()
    if pid > 0:
        os._exit(0)

    close_fds([])

    operator()

    os._exit(0)

def close_fds(leave_open=[0, 1, 2]):
    fds = os.listdir(b'/proc/self/fd')
    for fdn in fds:
        fd = int(fdn)
        if fd not in leave_open:
            try:
                os.close(fd)
            except Exception:
                pass


def operator():
    '''  Operator specific code
    '''
    while [ true ]; do

      # poll ldap
      


if __name__ == "__main__":
    main()
