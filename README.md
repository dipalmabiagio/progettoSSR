# Semplice Wireless Attack tool multipurpose

## Componenti del modulo

Questo progetto è stato sviluppato in un contesto accademico, durante la preparazione dell'esame di Sicurezza dei Sistemi e delle Reti, presso l'Università degli Studi di Milano - La Statale.

Il progetto consiste nello sviluppo di un piccolo tool che al suo interno contiene diverse funzionalità per condurre diversi attacchi tramite una rete WiFi.

### IpTables
Nel modulo si fa uso di iptables per impostare delle regole sul firewall dell'host locale, in particolare vi sono due funzioni a riguardo:    
* iptables_rules: questa funzione serve ad impostare l'host locale come gatweway per i pacchetti della rete, in modo tale che tutto il traffico sia sotto controllo (fa uso di _arp poisoning_).

        def iptables_rules():
        os.system("iptables --flush")
        os.system("iptables --zero")
        os.system("iptables --delete-chain")
        #flush della tabella di natting
        os.system("iptables -F -t nat")
        #accettare il jump dei pacchetti dal localhost
        os.system("iptables --append FORWARD --in-interface {} --jump ACCEPT".format(iface))
        #regola per mascherare i pacchetti in uscita dalla lan, modificandone l'origine
        os.system("iptables --table nat --append POSTROUTING --out-interface {} --jump MASQUERADE".format(iface))
    
* iptables_clean: questo metodo serve solo quando si smette di usare il tool per eliminare le regole impostate con la funzione precedente.

        #funzione per pulire le regole del firewall 
        def iptables_clean():                      
        os.system("iptables --flush")	
   
### nmap

Nel modulo si fa uso del tool nmap per trovare gli host sulla rete, attraverso un arp scan. La funzione che implementa lo scan è _nmap_arp_lan_ ed accetta in input l'argomento **local_range** (ovvero il range degli indirizzi ip da controllare, es 192.168.1.0/24 - controlla 256 indirizzi).

### Azioni disponibili

Dopo aver impostato le regole iptables ed aver individuato gli host l'utente sceglie un'azione tra:
1. Bloccare tutto il traffico in uscita di un utente (DOS)
2. DNS Spoof : serve a fare un redirect dell'utente falsando le risposte alle richieste DNS dell'utente
3. Leggere la cronologia dell'utente: anche se si usa SSL le richieste DNS sono inviate in chiaro, viene generato un documento con tutte le richieste inoltrate.
4. Rubare le credenziali mail su tutti i protocolli, a condizione che non si faccia uso di SSL
5. Rubare le credenziali FTP (funziona solo in assenza di FTP con SSL)
6. Analizzare le richieste HTTP della vittima


# Contributors

* [Biagio Dipalma](https://www.linkedin.com/in/biagio-dipalma/) - Università degli Studi di Milano | La Statale. CDL Magistrale in Sicurezza Informatica.
* [Nicola Di Monte] (https://www.linkedin.com/in/nicola-di-monte-050bb8199/) - Università degli Studi di Milano | La Statale. CDL Magistrale in Sicurezza Informatica.

