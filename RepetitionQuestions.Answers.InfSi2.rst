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

23) MACsecPackage::

	                [PT][User Data]
	[DA][SA][SecTag][Secure Data  ][ICV][FCS]
		
		
	* Der SecTag beinhaltet Controll Information, Association Nr., Länge wenn > 64Byte, Paket Nr. und Channel Identifier
	* Die Secure Data ist die verschlüsselte MAC Payload und den Type
	* Die ICV ist eine cryptographische Checksumme
	
	Bei getaggten VLAN Paketen wird der Ethernet Frame gesprengt!
	
24) 
	1) Jeder Teilnehmer besitzen einen persönlichen Connectivity Association Key CAK. 
	2) Ein Secure Association Key SAK wird gebildet, indem die Teilnehmer mit ihren CAKs Teile des SAK generieren. 
	3) Mittels einem Key Encryption Key KEK werden die SAKs verteilt.

25) Statt bei den Teilnehmer selbst gespeichert, liegen die Keys auf einem EAP Server, der damit dynamische CAKs generiert.


Application Security
====================
26) Open Web App Security Project

27) 
	Authentication
		Überprüfung, ob es sich wirklich um den entsprechenden Nutzer handelt
	Authorisation
		Prüfung der Berechtigung eines Nutzers
	Access Controll
		Der Nutzer erhält Zugriff auf die berechtigten Ressourcen
	Accounting
		Buchführung über Zugriffe
	Alerting
		Alarmierung bei unerlaubtem Zugriff
		
28) 3-Tier Web Application::

	[    Client / Browser     ]
	            |
	[ Web Server / App Server ]
	            |
	[      Data Storage       ]
	
	Auf jedem Tier muss die Identität des zugreifenden Users überprüft werden! Nicht nur auf den ersten 2!
	
	
29) Der Benutzer klickt auf etwas anderes, als er meint zu klicken. Beispiel: Der User klickt auf einen Bestellen Button. Darüber liegt jedoch ein transparenter Layer, der den Klick abfängt und dem Benutzer ein anderes, teureres Angebot in den Warenkorb wirft.

30) Ein Angreifen schleust Script Code oder Parameter über Felder oder Parameter in die Webseite ein. Andern Usern wird anschliessend die kompromitierte Webseite ausgeliefert.
	* Non-Persistent (Reflektiert): Eingaben, die der Server direkt an den Client zurücksendet. Auf einer Webseite werden vergangene Suchanfragen mit Kontaminieren Parametern aufgelistet
	* Persistent (Nicht reflektiert): Der Angreifer schleusst Script Code oder Formulare in die Daten der Webweite ein. Werden die Inhalte dem nächsten User geladen, werden auch die kompromitierten Inhalte geladen / ausgeführt, z.B. einen Image Tag, der vom Server des Angreifers ein Bild lädt und als Parameter das Cookie mitschickt, womit der Angreifer die Session übernehmen kann.
	* DOM Basiert (lokal): Der Webserver ist nicht beteilitg. Z.B. erhält der User einen Link, der als Parameter eine Codezeile beinhaltet. Das Javascript der Seite fügt den Schnipsel in die Seite ein und der Browser führt in anschliessend aus (z.B. fügt das Seitenskript einen href zu einem Link hinzu, womit sich ein onmouseover einschleusen lässt.). 
	
	Protection: Parameter oder Inhalte, die von einem User stammen, müssen zwingend Escaped werden
	
31) 
	* 80 gefundene Verletzlichkeiten/Webseite/Jahr (230 im 2010)
	* XSS ist die am meissten ausgenutzte Verletzlichkeit von Webseiten (55% der Webseiten betroffen)
	* Web Application Firewalls halfen viele der Risiken aufzudecken
	* Verletzlichkeiten in Webseiten werden im Durchschnitt nach 38 Tagen gefixt (nach 116 Tagen im 2010)
	* Die Zahl der insgesammt geschlossenen Verletzlichkeit stieg gegenüber 2010 um 10%
	* Im Durchschnitt waren Webseiten während 2/3 des Jahres von mindestens einer Verletzlichkeit betroffen.
	
32) 
	Confidentiality
		* Jemand erlangt unerlaubten Zugriff auf geschützte Daten der Webseite
	Integrity
		* Jemand modifiziert geschützte Daten der Webseite
		* Jemand verwendet die Plattform zum Angriff auf andere Plattformen oder User
	Accessability
		* Jemand legt die Webseite mit einem Angriff lahm
		
33) 
	OWASP Top 10
		Die grössten Risiken:
			1) Injection
			2) Fehler in Authentifizierung und Session Management
			3) Cross-Site Scripting (XSS)
			4) Unsichere direkte Objektreferenzen
			5) Sicherheitsrelevante Fehlkonfiguration
	Kriterien
		Die Risiken werden ermittelt durch eine Bewertung der Attacke, die Sicherheitslücke(n), das herrschende Sicherheitsmanagement für diesen Angriff, Technische Auswirkungen und Business Auswirkungen
		
34) Daten / Information (asset, value) werden durch Massnahmen geschützt (Protections, measures, controls). Angriffe (Threads) auf Verletzlichkeiten (Vulnerabilities) bedrohen die Informationen::

	.------------------------.
	| Protections, measures, |
	| controls               |
	| .----------------.  < <  Vulnerabilities
	| | Information    |     |   ,------------------.
	| | (asset, value) |     |  < Threads           |
	| '----------------'     |   '------------------'
	'------------------------'	
	
35) Faktoren, die die Verletzlichkeit beeinflussen:
	* Leichte Entdeckbarkeit
	* Einfachheit des Exploits
	* Bekanntheit der Verletzlichkeit
	* Bemerken des Ausnützens
	
36)
	1) Vor der Entwicklung: Sicherheitsdokumente bereitstellen und Vorhandensein im Ablauf überprüfen
	2) Design: Requirements Reviews, insbesondere security Reviews machen
	3) Development: Code Reviews
	4) Development/Testing: Penetration Testing
	5) Maintenance and Operations: periodical Health checks, operational management reviews
	
37) 
	* Busness Requirements
	* Infrastructure Requirements
	* Application Requirements
	* Security Programm Requirements

38) Falsche oder keine TLS Protection. Beispiele: Kein Schutz von Datenbankverbindungen des Webservers zu einem externen Server, kein Schutz von Webseitebereichen die eine Authentifizierung erfordern (Passwort Klartextübertragung),  Falsch konfigurierte TLS Zertifikate, die den User mit Fehler und Warnmeldungen bombardieren.


Web Application Security
------------------------
39) Die unteren Schichten sind heute relativ bewährt und grosse Angriffsmöglichkeiten gibt es immer weniger. Die Applikationen hingegen sind immer gleich verwundbar und werdne z.T. sogar schlampig programmiert.

40) Eine Serverseitige Applikation übernimmt nicht ecsapte Parameter über Post oder Get und baut diese in einen SQL Befehl ein. Wird ein Parameter so gestaltet, das er zuerst den aktuellen Befehl abschliesset und dann neue Befehle anhängt, können beliebige Befehle auf der Datenbank ausgeführt werden.

41) 
	Wlist/Blist Filter
		Bringen nur wenig
	Prepared Statements
		Verhindern SQL injections
	Stored Procedures
		Können SQL Injection verhindern, können aber selbst wieder Lücken auftun
	Escaping
		Verhindern SQL injection, müssen aber sehr konsequent durchgezogen werden
	Wenige Privilegien
		Verhindern SQL injection nicht, minimieren aber den Schaden.
		
42) Der Applikation wird vorgegaukelt, der User sei bereits authentifiziert. Z.B. durch direktes Anspringen der Seite mit geschützten Inhalten oder mitgeben von Parametern, die Zugriffserlaubnis signalisieren

43) Weil damit eine Brute Force Attacke wesentlich vereinfacht wird. Gibt der Angreifer einen fingierten Usernamen und Passwort ein und er erhält die Meldung "Passwort falsch" so hat er bereits die Information erhalten, das es diesen user gibt. Unterschiedliche Antwortzeiten des Servers, je nach dem ob user oder passwort falsch, können einem Angreifer ebenfalls Informationen darüber liefern.

44) Der Angreifer behält das Passwort bei und variiert den usernamen. Da Error Delay normalerweise auf den User gebunden ist, funktioniert dies.

45) 
	Authentisierung
		Identität des Users klären
	Authorisierung
		Erlaubte Aktionen klären
		
46) 
	* What I know: Passwörter, Slide-Figur, ...
	* What I have: Chipkarte, rsa Key, ...
	* What I am: Iris, Fingerabdruck, DNA, ...
	
47)
	* Einem andern Benutzer werden Daten des vorhergehenden verraten
	* Webentwickler können die Autocompletion über autocomplete=false abschalten
	

Data Leak Protection
--------------------
48
.. 
* Business basiert auf Vertrauen
* Geheime Informationen (z.B. Erfindungen noch ohne Patentschutz)
* Rechtliche Lage

49
..
Überall. Auf den Rechnern der User, auf mobilen Endgeräten, auf Druckern, Faxgeräten, Servern, im Altpapier, auf Ausdrucken

50
..
* Aus dem Data Storage (Document Server, DB, ...)
* Unterwegs zwischen Data Storage und Client (Netzwerk)
* Auf Client Hardware

51
.. 
Egress Controll
	Daten, die das Unternehmen verlassen werden kontrolliert
	* Es wird versucht, keine Daten in unerlaubte Hände fallen zu lassen
Usage Controll
	Es wird kontrolliert, was mit den Daten gemacht wird
	* Es wird kontrolliert, was mit den Daten gemacht wird
Egress Controll+Usage Controll
	Die beiden Verfahren können kombiniert werden. In erster Instanz werden die Daten daran gehindert das Unternehmen unerlaubt zu verlassen, in zweiter Instanz wird die unerlaubte Nutzung unterbunden.
	
52
..
Mit Testdaten wird oft sehr legere umgegangen, da sie ja scheinbar irellevant sind. Zumindest die ersten beiden Stufen von Testdaten können einem Angreifer jedoch eine Menge Informationen liefern:

Production Daten
	Reale Daten
Substituted Test Data
	Die Realen Daten werden mit Testdaten ersetzt. Es gibt ein Mapping zwischen den Testdaten und den Realen
Anonymized Test Data
	Wie bei Substituted Test Data, nur gibt es kein Mapping.
Synthetic Test Data
	Vollkommen erfundene Testdaten
	
53
..
Information Rights Management: Usage Controll + Encryption. IRM ist für innerhalb von Unternehmungen gedacht und beinhaltet nicht nur die Zugriffskontrolle auf die Information, sondern auch Edit, New, Publish, Print, ... Aktionen.

54
..
Eine IRM Lösung von Microsoft, die für Microsoft Office Dokumente und E-mails IRM Schutz ermöglicht.

55
..
Die Dokumente werden über eine Consumer Licence geschützt, die vom AD RMS Server der Firma entschlüsselt werden muss. Die Dokumente können nur zu Hause geöffnet werden, wenn dies erlaubt ist und der Key Server von extern verfügbar ist.

56
..
Weil für AD RMS alle Applikationen zusammenarbeiten müssen und den Schutz unterstützen müssen. Erlaubt z.B. das BS das Anlegen von Dokumenten, für die es keinen Schutz gibt, so ist es bereits wieder möglich Daten aus der Unternehmung rauszubringen. AD RMS lässt sich überhaupt nicht mit "Bring your own device" kombinieren.

57
..
* BYOD schafft den Mitarbeitern viele Möglichkeiten sich zu entfalten und nicht durch StandardIT an der Arbeit gehindert zu werden.
* BYOD schafft eine kaum kontrollierbare IT Landschaft, in der es auch sehr schwierig ist Mirarbeitern bestimmte Operationen mit Daten zu verbieten.
* Das Unternehmen verliert ein Stück weit die Kontrolle, wo überall Daten gespeichert sind
* Gehen Geräte verloren, werden Datenverluste möglicherweise viel zu spät bemerkt.
	
58
..
* In sehr inhomogenen Umgebungen ist IRM chancenlos
* Benötigen Mitarbeiter spontan und mobil neue Zugriffe / Aktionen, kann IRM nicht mithalten
* Die Erweiterung von IRM um weitere Applikationen ist aufwendig
* Grundsätzlicher Datiezugriff (auch wenn sie verschlüsselt sind) kann mit IRM nicht verhindert werden
		
59
..
a)
~~
Nur sehr wage angaben zum Autor, dahinter steckt eine Antivir/Firewall Firma, Datenherkunft z.T. unsicher -> nicht sehr vertrauenswürdig

b)
~~
* gut gesinnte Insider (versehentlich)
* zielgerichtete Attacken
* böswillige Insider

		
Anonymität
==========

60
--		
* Recht auf Schutz der Privatsphäre
* Meinungsfreiheit
* Geheimdienste schneiden Verkehr mit
* Aufdecken von Missständen (Whistle Blowing)

61
--
Der Remailer sendet eine Mail eines User unter einer andern Identität weiter und stellt dem User Mails entsprechend auch zu. Der Remailer entfernt alle Spuren, die auf die ursprüngliche Identität hinweisen.

* Wird der Remailer-Server auseinandergenommen, so fliegt die Identität auf.
* Single Point of Failure

62
--
Wer den Remailer in seiner Gewahlt hat, kennt das Identitätsmapping und kann den Service lahmlegen.


Mix Net
------

63
..
* verteiltes Anonymisierungsnetzwerk
* Den Weg durch das Netzwerk kennt nur der User
* Liegen die Server in unterschiedlichen Ländern, so ist es den Gerichten kaum möglich, gegen das Netzwerk vorzugehen

64
..
Der Client verschlüsselt das Paket inkl. den Adressen zwiebelschalenmässig für jede Knoten. Jeder Knote hat nur den Key, um seine Schicht zu entfernen. Anschliessend füllt er die Adressfelder mit Junk und Schickt das Paket an den nächsten Knoten, der wiederum nur seine Schicht auspacken kann.

65
..
Knoten unterwandert
	* Der Inhalt ist sicher, weil der Knoten nur das Verschlüsselte Paket sieht.
	* Der Angreifer weiss nur den vorherigen und den nächsten Knoten
Exitknoten unterwandert
	* Ist die Kommunikation unverschlüsselt, kommt der Angreifer an den Inhalt, kann ihn aber zu keinem User zuordnen.
	* Der Angreifer weiss die Zieldestination des Pakets (z.B. 20min.ch)

66
..
Damit Rechtshilfegesuche erschwert werden. Grenzüberschreitende Rechtshilfegesuche sind sehr schwierig umzusetzen.

Die Gerichte gehen als erstes auf den Exit Knoten los. Ist der Datenverkehr jedoch verschlüsselt, ist dieser aus dem Schneider.

67
..
Ein Mix Knoten entschlüsselt den Datenverkehr, misch die Ein- und Ausgangspakete, damit keine Korrelation möglich ist und löscht doppelte (Replay-Attacken).

68
..
High-Latency
	* Grosser Buffer
	* Mischt den Verkehr stark
	* Korrelation zwischen Eingangspakten und Ausgangspakten schwierig
	* Verzögert den Verkehr stark
Low-Latency
	* Kleiner Buffer
	* Mischt den Verkehr schwach
	* Korrelation zwischen Eingangspaketen durch Intensive überwachung möglich
	* Verzögert den Verkehr weniger stark
	* Die gleiche Anonymisierungskette sollte nicht zu lange gebraucht werden

69
..
Ist kaum Verkehr da, so ist die Anonymisierung im Eimer


Tor
---
70
..
Tor ist ein Anonymisierungsnetzwerk, das ursprünglich von der Navy entwickelt wurde.

71
..
Tor Datenformat::


	| CircId | CMD | Data |

	| CircId | Relay | StreamID | Digest | Len | CMD | Data |

	CircId: Zuordnung bei jedem Knoten zwischen Hin-/Rückverkehr
	StreamId: End-zu-End Stream ID (nur Exit Knoten bekannt)


72
..
Über die CircId in jedem Paket und in jeder Schale

73
..
Tor Circuit
	1) Client tauscht mit A Schlüssel aus
	2) Client tasucht mit B Schlüssel aus. Verkehr läuft über A:
		* verschlüsselt von Client bis A mit KeyA)
	3) Client tauscht mit C Schlüssel aus. Verkehr läuft über A, B:
		* verschlüsselt von Client bis B mit KeyB
		* verschlüsselt von Client bis A mit KeyA
	4) Client startet TCP Stream mit Handshake zu Target. Verkehr läuft über A, B, C
		* verschlüsselt von Client bis C mit KeyC
		* verschlüsselt von Client bis B mit KeyB
		* verschlüsselt von Client bis A mit KeyA
	5) Client sendet Daten (z.B. Anfrage) an Target. Verkehr läuft über A, B, C
		* verschlüsselt von Client bis C mit KeyC
		* verschlüsselt von Client bis B mit KeyB
		* verschlüsselt von Client bis A mit KeyA
	6) Target antwortet mit einem oder mehreren Datenströmen. Verkehr läuft über C, B, A
		* verschlüsselt von C bis Client mit KeyC
		* verschlüsselt von B bis Client mit KeyB
		* verschlüsselt von A bis Client mit KeyA

Tor Circuit Pakete
	::

		Client		                             | Zieladdr | Absender | Data | Padding |
		KeyC		                     | C | B | Encrypted Package (Client->Target)   |
		KeyB		             | B | C | Encrypted Package (B->C)                     |
		KeyA		| A | Client | Encrypted Package (A->B)                             |

		A			| A | Client | Encrypted Package (A->B)                             |
					| Junk       | B | C | Encrypted Package (B->C)                     |

		B			| Junk       | B | C | Encrypted Package (B->C)                     |
					| Junk               | C | B | Encrypted Package (Client->Target)   |

		C			| Junk               | C | B | Encrypted Package (Client->Target)   |
					| Junk                       | Zieladdr | Absender | Data | Padding |

		Target		| Junk                       | Zieladdr | Absender | Data | Padding |


Rückweg:
	Die Pakete werden bei jedem Knoten mit einer Schale versehen und vom Client ausgepackt

74
..
* Ein Server gibt eine Adresssequenz irgendwo bekannt.
* Wer mit dem Server Kontakt aufnehmen will, Adressiert diese Sequenz an einen ahnungslosen Rendez-Vous Server
* Server erhält Anfrage und meldet sich bei Rendez-Vous Server
* Kommunikation läuft über Rendez-Vous Server

75
..
Aufgrund des Exit Knotens und Javascript Eigenschaften, die der Browser ausplaudert.

**Massnahmen**

* Javascript abschalten
* Den Pfad im Tor Netzwerk über andere Knoten neu aufbauen


VPN
===
76
--
* Der Datenverkehr wird mit dem Point to Point Protocoll getunnelt.
* Keine Verschlüsselung, nur Authentication über PAP (Passwort), Challenge Response (CHAP) oder Extensible Authentication Protocoll EAP
* Nicht sehr sicher, keine Verschlüsselung

77
--
Mit ECP wird der Payload des PPP Protocols verschlüsselt über 3DES mit 168 bit Keys

78
--
Siehe 76.


Layer2/3/4 VPN
--------------
79
..
* Der L2TP Payload wird mit LCP verschlüsselt
* Gleiche Authentisierung wie PPP

::

	| L2TP [\\\ PPP | IP, IPX | Data \\\]

80
..
* Verschlüsselung mit LCP
* LCP kann auch ohne Verschlüsselung genutzt werden -> keine starke Verschlüsselung
* L2TP ohne Authentisierung ist anfällig auf Replay Attacken

81
..
L2TP wird mit IPSec getunnelt, indem das L2TP Paket von einem IPSec und einem UDP Paket gewrappt wird.
-> IPSec ist sicher und zuverlässig, aber etwas kompliziert

::

	| IP [/// UDP | L2TP [\\\ PPP | IP, IPX | Data \\\]///]

82
..
DatenPakete werden mit TCP gewrappt und somit verschlüsselt.

::
	| IP | TCP | SSL [/// IP | Data ///]

83
..
L2TP Tunnel
	* Nicht sicher
L2TP über IPSec
	* Sicher aber unnötig Overhead
IPSec Tunnel
	* Sicher
	* Wenig Oberhead, da 
	* etwas kompliziert
	* Alle höheren Layer sind unsichtbar
TLS
	* Simpel, kann jeder Browser
	* Verschlüsselung nur auf den höheren Layern
	* Unnötigen Overhead, da im TCP Paket nochmal IP Pakete sind.


MPLS
----

84
..
