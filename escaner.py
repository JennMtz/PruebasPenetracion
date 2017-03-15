#!/usr/bin/env python
import socket
import subprocess
import sys
from datetime import datetime

# Limpia la pantalla
subprocess.call('clear', shell=True)

# Pregunta por a una ip
remoteServer    = raw_input("Enter a remote host to scan: ")
remoteServerIP  = socket.gethostbyname(remoteServer)


print "-" * 60
print "Por favor espere, escaneando", remoteServerIP
print "-" * 60


t1 = datetime.now()
  



try:
    for port in range(1,1025):  
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((remoteServerIP, port))
        if result == 0:
            print "Port {}: 	 Open".format(port)
        sock.close()

except KeyboardInterrupt:
    print "You pressed Ctrl+C"
    sys.exit()

except socket.gaierror:
    print 'Hostname could not be resolved. Exiting'
    sys.exit()

except socket.error:
    print "Couldn't connect to server"
    sys.exit()


t2 = datetime.now()

# Calculates the difference of time, to see how long it took to run the script
total =  t2 - t1

# Imprime los resultados
print 'Scanning Completed in: ', total

