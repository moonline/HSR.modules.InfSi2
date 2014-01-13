=======================================
InfSi2 HS13 Repetitionsfragen Ergänzung
=======================================


6 VoIP Security
===============

6.1 Grundlagen
--------------

**6.1.1.**
Erklären Sie am Beispiel SIP, wie VoIP Kommunikation funktioniert.

**6.1.2.**
Warum sind für VoIP Kommnikation 2 Channels notwendig?

**6.1.3.**
Warum sollte für das Signalling die Nachricht Authentisiert werden?

**6.1.4.**
Machen Sie eine Sequenzdiagrammskizze, wie bei SIP die Verbindung etabliert wird und zwschen welchen Teilnehmern welche Nachrichten versandt werden.

**6.1.5.**
Was ist RTP? Wozu dient es?


6.2 Sicherheit
--------------

**6.2.1.**
Wie unsicher sind gewöhnliche RTP Übertragungen zwischen zwei Peers über das Internet?

**6.2.2.**
Sie befinden sich in einem öffentlichen unverschlüsselten Wlan. Wie können Sie mit Wireshark ganz einfach den Mediastream anzapfen und mithören?

**6.2.3.**
Welchen Schutz bietet VLAN für SIP Telefone?

**6.2.4.**
Skizzieren Sie den Aufbau eines SRTP Pakets. Welche Teile sind authentifiziert und welche verschlüsselt?

**6.2.5.**
Beschreiben Sie den Algorithmus und das Verfahren, mit dem SRTP den Payload verschlüsselt.

**6.2.6.**
Wie authentisiert SRTP Payload & Header?

**6.2.7.**
Wozu dient der Masterkey?

**6.2.8.**
Wie wird der Masterkey zwischen den Peers ausgetauscht? Nennen Sie die Vor- und Nachteile beider Verfahren. Gehen Sie beim VoIP Spezifischen auf den Aufbau des Protokolls ein.

**6.2.9.**
Wie werden aus dem Master Key Session Keys für Encryption und Authentication abgeleitet?

**6.2.10.**
Welche Vor- und Nachteile bietet die Tunnelung des Media Streams über IPsec?


6.3 Sicherer Verbindungsaufbau
------------------------------

**6.3.1.**
Was ist SPIT? Wie kann es dazu kommen?

**6.3.2.**
Nennen Sie, wie VoIP Calls missbraucht werden können. Was ist der Hauptgrund für diese Probleme?

**6.3.3.**
Auf welchen Wegen und wie erfolgreich kann das Sessionmanagement bei SIP abgesichert werden?

**6.3.4.**
Wie sähe eine PKI-basierte, starke Verschlüsselung von SIP aus? Welche Probleme würde dies mit sich bringen?

**6.3.5.**
Wie sieht eine Absicherung mit DomainKeys via DNS aus?

**6.3.6.**
Wie sicher ist Skype?



9 IDS
=====

**9.0.1 **
Was ist ein Intrusion Detection System? Warum reicht eine Firewall nicht aus?


**9.0.2.**
Welche zwei Ziele verfolgen IDS?

**9.0.3.**
Erklären Sie Host-based IDS (HIDS) und Network IDS (NIDS). Was sind Hybrid IDS?

**9.0.4.**
Erklären Sie die Begriffe Sensor, Event, Alert, Correlation Engine, Management Console, False Positive und False Negative im Zusmmenhang mit IDS.

**9.0.5.**
Machen Sie eine Skizze eines Host-based IDS. Wo sind die Sensoren installiert, wo werden die Events gesammelt? Was wird alles analyisiert?

**9.0.6.**
Machen Sie eine Skizze eines Network IDS. Wo sind die Sensoren installiert und wo werden die Events gesammelt. Was wird analysiert?

**9.0.7.**
Nennen Sie Stärken und Schwächen von HIDS und NIDS.

**9.0.8.**
Was kann das Hybrid IDS mehr als die beiden Anderen?


9.1 IDS Configuration & Operation
---------------------------------

**9.1.1.**
Welche Hauptziele verfolgt die Konfiguration eines IDS nebst der erfolgreichen Installation?

**9.1.2.**
Erklären Sie die beiden Arbeitsweisen, nach denen IDS arbeiten: Signaruten, Anomalie Detection.

**9.1.3.**
Wie kommen Signatur-basierte IDS Systeme an neue Signaturen? Welche Herausforderungen gibt es grundsätzlich beim Arbeiten mit Signaturen zu bewältigen?

**9.1.4.**
Welche Herausforderungen gibt es bei IDS mit Anomaly Detection? Warum kann ein "Normal behaviour" Schema nicht auf dem gleichen Weg bezogen werden wie Signaturen?

**9.1.5.**
Was ist Protocol Anomaly Detection?

**9.1.6**
Erklären Sie die HIDS Beispiele

a) number of failed logins
b) execution path profiling

**9.1.7**
Erklären Sie das NIDS Beispiel "statistical properties of network trafic". Wie können damit auch kompromitierte Systeme in der eigenen Umgebung aufgespürt werden?


9.2 IDS Responses
-----------------

**9.2.1.**
Nennen Sie vier mögliche Arten, auf IDS Alterts zu reagieren.

**9.2.2.**
Wie funktioniert die folgenden Responses? Wo stossen Sie an ihre Genzen?

a) Send TCP reset
b) Block Attacker at Firewall

**9.2.3.**
Welche fundamentale Schwächen besitzen alle reaktiven IDS Responses?


9.3 Intrusion Prevention System
-------------------------------

**9.3.1.**
Was ist die Grundidee von IPS?

**9.3.2.**
Schützt IPS gegen "Signle packet attacks"?

**9.3.4.**
Welche Limitationen besitzen IPS Systeme?


9.4 IDS Evasion Techniques
--------------------------

**9.4.1.**
Was sind übliche Angriffsstragegien um IDS auszutricksen?

**9.4.2.**
Erklären Sie die folgenden Strategien um IDS auszutricksen. Zeigen Sie jeweils auch auf, wie IDS dies verhindern können.

a) Fragmentation
b) Encoding
	I) UTF-7, Base64
	II) HTTP transfer-encoding "chunked"
	III) Data Compression
	
	
9.5 Snort IDS
-------------

**9.5.1.**
Was ist Snort, was kann es?

**9.5.2.**
Erklären Sie die Snort Modi:

a) Sniffer mode
b) Packet logger mode
c) IDS mode
d) Inline mode

**9.5.3.**
Was sind preprocessors?

**9.5.4.**
Wie sind Rules aufgebaut (logisch, nicht syntax)?

**9.5.5.**
Welche Teile enthält ein Rule Header?

**9.5.6.**
Erklären Sie die Rule Options:

a) msg
b) reference
c) gid
d) sid
e) rev
f) priority

**9.5.7.**
Erklären Sie die Payload Detection Rule Options:

a) content
b) nocase
c) http_client, http_uri
d) pcre


**9.5.8.**
Erklären Sie die Header File Detection Rule:

a) IP packet header
b) TCP packet header
c) ICMP packet headers
d) flow
e) samelp

**9.5.9.**
Mit welcher Regel kann Snort Portscans detektieren?

**9.5.10.**
Wie müssen Regeln aufgebaut sein, damit Encodings korrekt gehandelt werden?

**9.5.11.**
Was ist die BASE Basicl Analysis and Security Engine?

**9.5.12.**
Welche Reaktiven Möglichkeiten kennt Snort?

**9.5.13.**
Welche Möglichkeiten bietet Snort inline?

**9.5.14.**
Wie kann mit Snort "Real Time Alerting" umgesetzt werden?

**9.5.15.**
Was ist ein Nessus Scan?


