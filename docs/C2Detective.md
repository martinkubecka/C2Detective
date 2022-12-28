# C2Detective

Aplikácia na detekciu Command and Control (C2) komunikácie prostredníctvom analýzy sieťovej prevádzky.

> zdrojový kód: https://github.com/martinkubecka/C2Detective

---
## Systémové požiadavky

- zdrojový kód
```
$ git clone https://github.com/martinkubecka/C2Detective.git
```

- Python 3.X (testované na verzii 3.10.8)
- inštalácia požadovaných modulov
```
$ pip install -r requirements.txt
```

- vytvoriť súbor `config/config.yml` podľa vzoru `config/example.yml` a pridať API kľúče pre nasledovné služby
    - AbuseIPDB
    - SecurityTrails
    - Shodan
    - VirusTotal
    
---
## Prehľad použitia
```
usage: c2detective [-h] [-q] [-n NAME] [-c FILE] [-s] [-r] [-e] [-a ACTION] [-o PATH] FILENAME

Application for detecting command and control (C2) communication through network traffic analysis.

positional arguments:
  FILENAME                    input file (.cap OR .pcap)

options:
  -h, --help                  show this help message and exit
  -q, --quiet                 do not print banner
  -n NAME, --name NAME        analysis keyword (e.g. Trickbot, Mirai, Zeus, ...)
  -c FILE, --config FILE      config file (default: ".config/config.yml")
  -s, --statistics            print packet capture statistics
  -r, --report-iocs           write extracted IOCs to JSON file
  -e, --enrich                enable data enrichment
  -a ACTION, --action ACTION  action to execute [sniffer/...]
  -o PATH, --output PATH      output directory file path for report files (default: 'reports/')
```

---
## Prehľad funkcií aplikácie

- tento zoznam nie je úplný a počas vývoja môžu byť pridané ďalšie funkcionality

### Implementované funkcie

#### Všeobecné funkcionality
- rozhranie príkazového riadka (CLI)
- implementovaný logging
- konfigurácia aplikácie prostredníctvom konfiguračného súboru

#### Analýza paketov
 - načítanie a parsovanie paketov (.cap a .pcap súbory)
 - extrakcia rôznych IOCs (Indicators of Compromise)
    - jedinečné spojenia (zdrojová-cieľová IP adresa)
    - verejné IP adresy
    - domény z DNS odpovedí
    - HTTP obsah
    - dopytované URL adresy 
 - zobrazenie vlastných štatistík zachytených paketov v termináli
 - zapís extrahovaných IOCs do JSON súboru 
    - verejné IP adresy a ich počet
    - domény z DNS odpovedí
    - HTTP GET požiadavky 
    - dopytované URL adresy 
    
#### Obohatenie dát a ich korelácia
- obohacovanie extrahovaných dát pomocou nasledujúcich služieb:
    - AbuseIPDB
    - CIRCL's BGP Ranking
    - SecurityTrails
    - Shodan
    - ThreatFox
    - URLhaus
    - VirusTotal
- korelácia obohatených dát do jedného JSON objektu, ktorý zapisujeme výstupného súboru

#### Detekcia
- detekcia na základe obohatených údajov pomocou takzvaných "Threat Feeds"
    - škodlivé IP adresy, ktoré prijali spojenia
    - škodlivé IP adresy, ktoré iniciovali spojenia
    - škodlivé domény, ktoré prijali spojenia
    - škodlivé domény, ktoré iniciovali spojenia
 - detekcia DGA domén pomocou integrácie projektu s názvom DGA Detective
    - DGAD zdrojový kód: https://github.com/COSSAS/dgad
 - detekcia TOR sieťovej prevádzky
 - detekcia odchádzajúcej sieťovej prevádzky do výstupných uzlov siete TOR (exit nodes)

### To-Do

#### Všeobecné funkcionality
- implementovať cashing (databázu) pre obohatené údaje a IOCs

#### Analýza paketov
- implmenetovať parsovanie HTTPS komunikácie za účelom extrackie dát z TLS certifikátov

#### Obohatenie dát a ich korelácia
- zapracovať Feodo Tracker, ktorý každých 5 minút generuju aktuálny zoznam C2 serverov
    - prepoužiť kód z vlastného programu "Maltracker"
        - https://github.com/martinkubecka/maltracker
        - najaktuálnejšia verzia kódu momentálne nezverejnená - fúzia s aplikáciou "C2Hunter" 
- zapracovať výstup z vlastného programu s názvom "C2Hunter", ktorý využíva vyhľadávanie v službe Shodan s cieľom detekovať predvolené nastavenia C2 frameworkov a budovania si lokálnej databázy potencionálnych C2 serverov 
    - https://github.com/martinkubecka/C2Hunter
    - repozitár a teda zdrojový kód tejto aplikácie bude čoskoro zverejnený 

#### Detekcia
- detekcia odchádzajúcej sieťovej prevádzky k populárnym doménam ("pool-om") na ťažbu kryptomien
- detekcia známych škodlivých (predvolených) HTTP hlavičky (napr. User-Agent a podobne)
- detekcia sieťových spojení s nadmernou frekvenciou
- detekcia príznakov C2 beaconing-u prichádzajúcich do siete a odchádzajúcich zo siete
- detekcia techniky DNS Tunneling
- detekcia dlhých spojení
- implementovať systém hodnotenia dôveryhodnosti detekcie

---

