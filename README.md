# Software_Security_2023

Progetto del corso di Software Security Università Federico II di Napoli anno accademico 2022/2023. 
Malware Analysis del Trojan EMOTET svolta in collaborazione con Daniele Fazzari e Vittorio De Iasio. 
Tra i file è presenta la presentazione dell'analisi svolta congiuntamente al disassemblato, con le opportune modifiche e rinominazioni, ottenuto a partire da IDA Freeware.

Il repository corrente contiene:
- un file zip "malware_samples" contenente i vari eseguibili malevoli, protetto dalla password "infected"
- Gli eventi catturati col tool sysmon (log_syslog.evtx)
- Le chiamate di sistema realizzate e monitorate tramite il tool Process Monitor (ProcessMonitor.PLM)
- Le regole yara elaborate
- Le regole SNORT (local.rules)
- Le regole SIGMA
- Il file "ww.ida" che tiene traccia dell'analisi statica avanzata realizzata col tool IDA Freeware contente le variabili e le funzioni rinominate opportunamente.
- La presentazione della malware analysis realizzata (EMOTET MALWARE ANALYSIS.pdf)

