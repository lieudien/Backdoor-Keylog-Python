import ConfigParser
from attacker import Attacker

def main():

    config = ConfigParser.ConfigParser()
    config.read('setup.config')

    localIP = config.get('Attacker', 'localIP')
    localPort = config.get('Attacker', 'localPort')
    remoteIP = config.get('Attacker', 'remoteIP')
    remotePort = config.get('Attacker', 'remotePort')
    protocol = config.get('General', 'protocol')
    password = config.get('Encryption', 'password')
    knockList = config.get('General', 'knockList')
    filePort = config.get('General', 'filePort')
    ttl = config.get('General', 'ttl')

    print(localIP, localPort, remoteIP, remotePort, protocol, filePort)
    attacker = Attacker(localIP, localPort, filePort, remoteIP, remotePort, protocol, password, knockList, ttl)
    attacker.run()

if __name__ == '__main__':
    main()
