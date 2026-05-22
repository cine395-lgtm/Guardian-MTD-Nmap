

# 🛡️ Guardian MTD & NDR Core
**Advanced Mobile Threat Defense & Network Detection Response Framework for Android**

Guardian MTD è una suite nativa e modulare progettata per l'analisi forense della rete, il monitoraggio della telemetria in tempo reale e il mitigamento attivo delle minacce (MitM/DNS Sinkhole) direttamente su dispositivi mobili basati su Android 17 contesti protetti.

Il progetto evolve l'architettura iniziale di un wrapper Nmap, trasformandola in un ecosistema di sicurezza aziendale orientato al Blue Team.

---

## 🔬 Architettura Ingegneristica & Componenti Core

Il framework si divide in moduli strategici a basso livello che cooperano in background in modo asincrono:

### 1. ⚙️ Porting Nativo Nmap (C++ via Android NDK)
Integrazione dei binari nativi di Nmap stabili, cross-compilati per architetture mobili (`arm64-v8a`, `armeabi-v7a`, `x86`, `x86_64`) tramite Android NDK. 
* Consente l'esecuzione di **Network Audit Task** avanzati, scansioni veloci (`-F`), script NSE (`--script banner`) e asset mapping di intere sottoreti direttamente dal dispositivo senza requisiti di root (`--unprivileged`).

### 2. 🔀 Network Detection & Response (NDR) Engine
Inizializzazione di un contesto di routing isolato tramite l'interfaccia nativa `VpnService` di Android.
* Creazione di un tunnel virtuale privato (interfaccia TUN) che cattura e ispeziona a basso livello la totalità dei pacchetti IP in transito generati dal dispositivo.

### 3. 🛑 DNS Firewall Policy Engine & Sinkhole
Intercettazione granulare di tutte le richieste UDP sulla porta `53`.
* Modulo di filtraggio deterministico che analizza le richieste DNS applicando istantaneamente regole di blocco (*Policy Deny Rules*) a caldo contro domini malevoli, server C2 o tracker pubblicitari, agendo come un sinkhole di rete locale.

### 4. 🔑 Crittografia Applicata & CertificateEngine (TLS Proxy)
Implementazione di logiche crittografiche avanzate per l'ispezione dei flussi cifrati:
* **Root CA Privata:** Generazione nativa di coppie di chiavi RSA a 2048 bit e certificati root X.509 archiviati in un keystore PKCS12 sicuro sul dispositivo.
* **Handshake SNI Extraction:** Un proxy trasparente ServerSocket estrae l'estensione SNI (*Server Name Indication*) durante l'handshake TLS, identificando la destinazione reale prima della cifratura.
* **On-the-fly Signing:** Predisposizione per la firma automatica dei certificati per sbloccare l'ispezione Deep Packet sulle connessioni HTTPS.

### 5. 📬 Automazione Forense e Reportistica Remota (WorkManager)
Progettato per l'auditing e il monitoraggio a lungo termine in mobilità:
* Un modulo `PcapWriter` proprietario scrive i pacchetti catturati direttamente in formato standard `.pcap` (struttura forense con timestamp granulari).
* Ogni 48 ore, un Worker asincrono di sistema gestito via **WorkManager** impacchetta la telemetria raccolta e la inoltra automaticamente tramite un canale sicuro via SMTP per l'analisi e il debriefing centralizzato su **Wireshark**.

---

## 🛠️ Stack Tecnologico
* **Core Language:** Kotlin / C++ (JNI Layer)
* **Android SDK / NDK:** Ottimizzato per API 34+ (Gestione dei servizi in foreground in contesti protetti)
* **Encryption Standards:** RSA 2048-bit, X.509 Certificates, PKCS12 Keystores
* **Forensic Analysis Tools:** Wireshark, Nmap Scripting Engine (NSE)

---

## 🚀 Sviluppo e Contributi

### Come compilare il Core Nmap (C++)
Lo script automatizzato gestisce il download delle sorgenti stabili, la configurazione e la compilazione incrociata delle librerie e l'importazione degli asset NSE:

```bash
cd app/src/main/cpp
./make_nmap.sh




📜 Licenza e Note
Questo software è sviluppato a scopi di ricerca, analisi difensiva e Penetration Testing nei laboratori di Cybersecurity.
This project is a port of Nmap 7.99 for Android and uses the original Nmap Public Source License (NPSL).
Questo progetto è un porting di Nmap 7.99 per Android e usa la licenza originale Nmap Public Source License (NPSL).
