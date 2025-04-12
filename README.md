# Keysight Challenge 2025 – Packet Processing Pipeline

Acest proiect implementeaza un simulator de rutare de pachete folosind:

- PCAP input (capturi de pachete) 
- Intel TBB flow graph (pentru procesare paralela) 
- SYCL (DPC++) pentru procesare GPU 
- Raw sockets pentru trimiterea pachetelor in retea 

Solutia este construita modular sub forma unui pipeline de procesare paralela. Pachetele sunt citite dintr-un fisier PCAP, sunt analizate, modificate, procesate cu SYCL pe GPU si apoi trimise in retea folosind un socket raw.

---

## Structura generala

```
Input PCAP  
   ↓  
Parse (filtrare & count protocoale)  
   ↓  
Route (modificare IP destinatie)  
   ↓  
GPU Inspect (incrementare bytes)  
   ↓  
Send (via raw socket)  
```

Fiecare etapa este implementata ca un nod in cadrul unui TBB flow graph, permitand procesarea asincrona si paralela a loturilor de pachete.

---

## Detalierea componentelor

### 1. `in_node` – Citirea pachetelor din fisier `.pcap`

- Se initializeaza handle-ul PCAP doar o singura data (lazy initialization)
- Se foloseste `pcap_open_offline` pentru a deschide fisierul de captura
- In fiecare activare, se citesc pana la `burst_size` pachete
- Fiecare pachet este copiat in vectorul `packets`, fiecare avand o dimensiune fixa (64 bytes)
- Daca nu mai sunt pachete, se apeleaza `fc.stop()` pentru a opri graful

Scopul acestui nod este de a simula o sursa continua de trafic in blocuri gestionabile.

### 2. `parse_node` – Filtrarea si contorizarea protocoalelor

- Parcurge fiecare pachet si identifica tipul protocolului pe baza EtherType-ului
- Pentru IPv4, se verifica campul protocol pentru a distinge ICMP, TCP sau UDP
- Pentru IPv6, se verifica Next Header (la offsetul corespunzator)
- Pachetele de tip ARP sunt ignorate
- Se construieste un vector cu doar pachetele IPv4 sau IPv6 care trec mai departe

Scopul acestui nod este de a reduce incarcarea nodurilor ulterioare, procesand doar pachetele utile.

### 3. `route_node` – Modificarea IP-ului de destinatie

- Selecteaza doar pachetele de tip IPv4
- Extragerea IP-ului de destinatie se face citind bytes 30–33
- Se construieste o copie a pachetului original si se modifica fiecare octet din IP cu `(byte + 1) % 256`
- Modificarile sunt logate pentru urmarire in consola
- Se creeaza un nou vector cu pachetele modificate pentru a evita alterarea starii initiale

Scopul acestui nod este sa simuleze o etapa de rutare care altereaza destinatia pachetului.

### 4. `inspect_packet_node` – Procesare GPU (SYCL)

- Se creeaza un SYCL queue (preferabil GPU, fallback pe CPU daca nu este disponibil)
- Se aloca memorie partajata (USM) pentru toate pachetele
- Fiecare pachet este copiat in bufferul SYCL
- Se lanseaza un kernel paralel 2D (pachet x byte) care incrementeaza fiecare byte
- Dupa finalizarea kernelului, datele procesate sunt copiate inapoi in vectorul host

Scopul acestui nod este de a demonstra utilizarea unei unitati de procesare accelerata (GPU/CPU) pentru o inspectie simbolica a pachetelor.

### 5. `send_node` – Trimiterea pachetelor prin raw socket

- Creeaza un socket raw de tip `AF_PACKET`, cu protocol `ETH_P_ALL`
- Se obtine indexul interfetei specificate (ex: "eth0") prin `if_nametoindex`
- Se construieste adresa destinatie folosind structura `sockaddr_ll`
- Fiecare pachet este trimis prin `sendto()` catre interfata de retea aleasa
- Se afiseaza primii bytes ai fiecarui pachet in consola pentru verificare

Scopul acestui nod este de a trimite efectiv pachetele in retea, simuland iesirea unui router sau switch fizic.

---

## Rulare

1. Configureaza build-ul:
```bash
mkdir -p build
cd build
cmake ..
```

2. Compileaza:
```bash
make
```

3. Ruleaza codul:
```bash
make run
```

---

## Output asteptat

```text
Parsed packets: IPv4=16, IPv6=0, ARP=0, ICMP=2, TCP=7, UDP=7
Original IPv4 destination: 1.1.1.1
Modified IPv4 destination: 2.2.2.2
Packet sent: ab 1f 33 ...
Done waiting
```

