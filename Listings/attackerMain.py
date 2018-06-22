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
    filePort = config.get('General', 'filePort')
    knockList = config.get('General', 'knockList')
    ttl = config.get('General', 'ttl')

    print(localIP, localPort, filePort, remoteIP, remotePort, protocol, password)
    attacker = Attacker(localIP, localPort, filePort, remoteIP, remotePort, protocol, password, knockList, ttl)
    attacker.run()

if __name__ == '__main__':
    main()
