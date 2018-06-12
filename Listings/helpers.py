import setproctitle
import os, sys


def maskProcess():
    proc_name = "firefox64"
    setproctitle.setproctitle(proc_name)
    print("Set process name to: {}".format(proc_name))

def checkRootPrivilege():
    if os.getuid() != 0:
        sys.exit("This application have to run with root access. Try again")

def decode(data):
    return str(data)[2:-1]

def cd(path):
    os.chdir(os.path.expanduser(path))
