#!/usr/bin/python
from datetime import datetime
try: 
	interface = raw_input(" Escriba la interfaz de red: ")
	ips = raw_input(" Escribe el rango de ips: ")

except KeyboarInterrupt:
	print "\n[*] User Requested Shutdown"
	print "\n[*] Quitting..."
	sys.exit(1)
print "\n[*] Escaneando...." 
start_time = datetime.datetime.now()

from scapy.all import srp,Ether,ARP,conf #importando modulos necesarios

conf.verb = 0 
ans, unans = srp(Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst = ips), timeout = 2, iface=interface,inter=0.1)

print "MAC - IP\n" 
for snd,rcv in ans:
	print rcv.sprintf(r"%Ether.src% - %ARP.psrc%")
stop_time = datetime.now()
total_time = stop_time - star_time 
print "\n[*] Escaneo completo!"
print ("[*] Duracion del escaneo : %s" % (total_time)) 


