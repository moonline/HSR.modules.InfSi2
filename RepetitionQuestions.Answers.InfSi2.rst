=======================================
InfSi2 FS13 Repetitionsfragen Antworten
=======================================

Dieses Dokument wird vorzu erweitert. Ergänzungen und Antworten sind herzlich willkommen.
Repetitionsfragen: https://github.com/moonline/InfSi2/blob/master/RepetitionQuestions.InfSi2.tex


Kryptographische Stärke
=======================
1)	+-------------------+--------------------+----------+--------------------+
	| Crypt. System     | Rec. Algorithmus   | Key Size | True Strength      |
	+===================+====================+==========+====================+
	| Symetric Encr.    | AES                | 256      | 220                |
	+-------------------+--------------------+----------+--------------------+
	| Hash              | SHA3 384           | 384      | 256                |
	+-------------------+--------------------+----------+--------------------+
	| Key Exchange      | DH                 | 2048     | 256                |
	+-------------------+--------------------+----------+--------------------+
	| Digit. Signature  | RSA                | 2048     | 256                |
	+-------------------+--------------------+----------+--------------------+
	| Public Key Enc.   | RSA, El Gamal      | 2048     | 256                |
	+-------------------+--------------------+----------+--------------------+
	| User Password     |                    | 22       | 128                |
	+-------------------+--------------------+----------+--------------------+
	
2) Definition eines Sets an Verschlüsselungs- Hash- und Signierungsalgorithmen, die eine gleiche Kryptographische Stärke aufweisen, damit es kein schwaches Gleid in der Kette gibt. A definiert sichere Schlüssellängen für die Stufe Vertraulich, B definiert sehr sichere Schlüssellängen für die Stufe Geheim.

3) 
	* Eine elliptische Kurve ist ein Polynom 3. Grades. 
	* Die Bits der Nachricht werden Punkten auf der elliptischen Kurve zugeordnet und anschliessend die Verschlüsselungsfunktion P->nP (Punkt n mal zu sich selbst addieren) auf jeden Punkt angewendet. 
	* Die Umkehrfunktion Pn->P muss dabei schwer zu berechnen sein. 
	* Der Empfänger kann P nur anhand der geheimen Informationen über die Kurve wieder berechnen.
	* Konkretes Vorgehen in der Praxis:
		1) A und B legen für sich jeweils ein geheimer Kurvenparameter a, bzw. b fest
		2) A und B tauschen eine Primzahl und den Startpunkt P auf der Kurve aus
		3) A und B wählen je eine Zahl n, die die anzahl Additionen von P zu sich selbst bestimmt
		4) A und B berechnen jeweils den neuen Punkt P und tauschen ihn aus
		5) Aus den übertragenen Elementen lässt sich nur mit sehr grossem Aufwand a, bzw. b bestimmen
		
4) A verschlüsselt den Key mit mit EC und überträgt ihn. B entschlüsselt ihn mit ihrem secret und den öffentlichen Parametern. 

5)
	ECDH
		Elliptic Curves mit Diffie Hellmann: Jeder Kommunikationspartner hat ein EC pub/priv Key Paar und damit wird ein gemeinsamer Schlüssel für die Kanalverschlüsselung verschlüsselt und ausgetauscht
	ECIES
		Elliptic Curve Integrated Encryption Scheme: Hybrides Verschlüsselungsverfahren basierend auf EC. Der symetrische Schlüssel wird mit asymetrischen EC Keys verschlüsselt und übertragen.
	ECDSA
		Elliptic Curve Digital Signature Algorithm: Der DSA Schlüssel wird mit EC verschlüsselt und übertragen.
		
6) Eine Kombination aus Verschlüsselung und Hash Algorithmus, der fast gleich schnell ist, wie Verschlüsselung alleine und viel schneller ist als Verschlüsselung + Signaturerstellung einzeln.


Physical Layer Security
=======================
7) 
	Voice Scrambling
		Sprachfrequenzspektren werden umgedreht (höchste Frequenz wird zur niedrigsten und umgekehrt) und verschoben im Frequenzspektrum. Beim Multiplexing werden mehrere solche Frequenzspektren nebeneinander gelegt. Der Empfänger muss wissen, wie breit die Frequenzspektren sind, und wo sie beginnen, damit er wieder demultiplexen kann. Das Verfahren basiert auf Security by Obscurity und ist daher nicht sicher.
	Frequency Hopping
		Der Datenkanal springt nach einem vorgegebenen Muster (Zeitabstände, Sprung) zwischen den Frequenzen hin- und her. Der Empfänger muss das Muster kennen, damit er mitspringen kann. Auch dieses Verfahren basiert auf Security by Obscurity.
		
8)
	1) Es werden verschränkte Photonen erzeugt, die zwei Polarisationen annehmen können. Die Polarisation wird erst durch die Messung festgelegt.
	2) Sender und Empfänger besitzen Filter Sets, mit denen Sie die Photonen Polarisiert messen können. Diese Messung kann nur einmal durchgeführt werden und daher muss man sich für ein Filterset entscheiden.
	3) Sender und Empfänger tauschen die benutzen Filtersets aus. Haben sie ein Photon mit unterschiedlichen Filer gemessen, wird der Wert verworfen, ansonsten behalten.
	4) Weil die Photonen verschränkt sind, bemerken die beiden, wenn es abgehört wird.
	5) Versucht jemand ein Photon einzuspeisen, so geht dies nicht weil sich Photonen nicht duplizieren lassen.
	6) Sender und Empfänger nutzen die übertragenen Photonenwerte als Key.
	
9) Die Quanten sind verschränkt. Sobald die eine Quante gemessen (abgehört) wird, wird auch die andere verändert.

10)
	* Die Photonen werden moduliert, das restliche Verfahren funktioniert wie bei 8 beschrieben.
	* Klaut jemand ein Photon (mithören), kriegt der Empfänger keines (Verschränkung)
	* Probleme:
		* Photonen können nicht kopiert werden, entsprechend kann das Signal nicht aufgefrischt/erneuert werden (kein Repeathing)
		* Die Dämpfung in der Leitung begrenzt damit die Übertragungsdistanz.
		* Es ist unmöglich einen Laser zu bauen, der nur ein Photon auf's Mal ausgibt. Daher werden im Durchschnitt zwar schon nur ein Photon geliefert, aber manchmal auch zwei oder mehr oder keines.
		* Werden mehr oder weniger als 1 Photon aufs Mal übertragen, müssen diese Verworfen werden.
		* Es ist schwierig zu unterscheiden, ob der Sender kein Photon abgeschickt hat, oder ob es geklaut wurde. Darum werden wenn mehr oder weniger als 1 Photon aufs Mal übertragen werden, diese Verworfen.
		* Die Datenrate ist damit extrem tief und eignet sich nicht für Streamcipher, sondern nur für Key Distribution.
		
11) In der Praxis sind die Distanzen viel zu klein, als das man das System vernünftig einsetzen kann, und man benötigt eine sepparate Faser. Zudem sind die System teuer. Ausserdem ist die Datenrate so klein, das für die Übertragung eines Schlüssels bis zu einer Minute gebraucht wird.

12) Einen Kanal für die Quantenübertragung des Keys (niedere Rate) und ein gewöhnlicher Datenkanal, auf dem die mit dem Key verschlüsselte Daten hochratig übertragen werden.


Schlüsselmaterial und Zufallszahlen
===================================
13) Die Nachricht wird zusammen mit dem inner Key (Key K xor verknüpft mit Konstante ipad) gehashed und der entstandene Hash zusammen mit dem Outer Key (Key k xor verknüpft mit Konstante opad) erneut gehashed -> HMAC.

14) 
	* PRF erzeugt aus einem Key einen Keystream. 
	* Ein Sied wird durch dem Key gehashed. Der Output wird als Input für die Nächste Hashrunde durch den Key anstelle dem Seed verwendet. Jeder Teil des Outputstreams wird nochmals zusammen mit dem Seed durch den Key gehashed. 
	* Es wird das Schlüsselmaterial vervielfälltig/verdünnt. Die Entropie wird dabei nicht verändert. 
	* Besitzt der Key eine miserable Entropie, besitzt der Schlüsselstream anschliessend die genau gleich miserable. -> Hashing verändert nur die Statistik, nicht aber die Entripie!

15) 
	Aufteilung auf MD5 und SHA-1
		Es wird befürchtet, das MD5 demnächst fällt, und das es in SHA-1 eine Backdoor gibt, darum wird auf nicht nur ein Hashing Verfahren gesetzt.
	TLS 1.1 Berechnung Master Secret
		Premaster Secret wird zur Hälfte mit MD5, zur Hälfte mit SHA-1 durch Seed gehashed und beide Teile anschliessend Verknüpft -> Master Secret.
	Schlüsselgenerierung
		Genau wie wie bei der Berechnung des Master Secrets werden neue Schlüssel erzeugt, indem die Hälfte des Master Secrets mit MD5 und die andere Hälfte mit SHA-1 gehashed und verknüpft werden.
		
16) 
	* Zeit zwischen Tastenanschlägen auf der Tastatur
	* Mausbewegungen
	* Soundkarte Rauschen
	* Zugriffszeiten Harddisk (Varianz durch Luftturbulenzen im Gehäuse)
	
17) Hardwarebauteile, die einen Strom von Zufallszahlen liefern, die eine hohe Entropie aufweisen. z.B. 
	* instabile Diodenschaltungen
	* Anzapfen des thermischen Rauschens.

18) Der IDQ besteht aus einer Taktung und zwei gegenseitig verschaltete Dioden, die einen instabilen Zustand herbeiführen (flackern / wildes hin- / herschalten) und damit zufällig 0 oder 1 liefern.

19) Liefert ein Zufallsgenerator deutlich mehr 0 als 1en oder umgekehrt, kann das zu häufig auftretende Zeichen nach Auftrittswahrscheinlichkeit substituiert werden und damit die Verteilung ausgeglichen werden.


Data Link Security
==================
20) Supplicants melden sich beim Authenticator (Access Point/Switch), dieser sendet erlaubte Anfragen weiter an den RADIUS Server. Kann der RADIUS Server den User erfolgreich anmelden, erhält er Access. Wichtig ist, das die Trunkleitung zum RADIUS Server verschlüsselt ist.

21) 
	DevId
		Die Secure Device ID sind RSA und EC Keys, die vom Hardwarehersteller erzeugt, signiert und hinterlegt werden. Da Sie eindeutig ist, kann sie zur Generierung von Authentication Keys genutzt werden. Die DevID kann vom Benutzer nicht verändern werden.
	DevId Modul
		Das DevID Modul sollte nebst einem Zugriffssicheren Storage für die DevID einen Zufallsgenerator und hardwarebasierte Hash Algorithmen besitzen.
	Key Generation
		Anwendungsschlüssel werden direkt im DevID Modul durch die DevID, den enthaltenen Zufallsgenerator und die Hashalgorithmen erzeugt und im DevId Modul gespeichert. Die Keys verlassen das DevID Modul nie, sondern werden im Modul genutzt, um weitere Schlüssel zu signieren.
		
22) 
	Secure Connectivity Association
		Eine Data Link Layer Gruppe, deren Teilnehmer den Datenverkehr verschlüsseln. Für jeden Teilnehmer gibt es einen Sicheren Channel, durch den er die Datenpakete an die andern Teilnehmer schickt. 
	Channel
		Jeder Channel besitzt einen eigenen Key. Die Channels sind somit unabhängig und gerichtet.
	Vorteile
		Der Datenverkehr zwischen den Teilnehmern ist bereits auf Data Link Level Verschlüsselt und über die höheren Verbindungen können keine Metadaten gesammelt werden.

23) 
	1) Jeder Teilnehmer besitzen einen persönlichen Connectivity Association Key CAK. 
	2) Ein Secure Association Key SAK wird gebildet, indem die Teilnehmer mit ihren CAKs Teile des SAK generieren. 
	3) Mittels einem Key Encryption Key KEK werden die SAKs verteilt.

24) Statt bei den Teilnehmer selbst gespeichert, liegen die Keys auf einem EAP Server, der damit dynamische CAKs generiert.