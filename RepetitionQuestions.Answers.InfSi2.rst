=======================================
InfSi2 FS13 Repetitionsfragen Antworten
=======================================

Dieses Dokument wird vorzu erweitert. Ergänzungen und Antworten sind herzlich willkommen.
Repetitionsfragen: https://github.com/moonline/InfSi2/blob/master/RepetitionQuestions.InfSi2.tex


Kryptographische Stärke
=======================

1
-
+-------------------+--------------------+----------+--------------------+
| Crypt. System     | Rec. Algorithmus   | Key Size | True Strength      |
+===================+====================+==========+====================+
| Symetric Encr.    | AES                | 128      | 128                |
+-------------------+--------------------+----------+--------------------+
| Hash              | SHA2 256           | 256      | 128                |
+-------------------+--------------------+----------+--------------------+
| Key Exchange      | DH                 | 256      | 128                |
+-------------------+--------------------+----------+--------------------+
| Digit. Signature  | RSA                | 3072     | 128                |
+-------------------+--------------------+----------+--------------------+
| Public Key Enc.   | RSA, El Gamal      | 3072     | 128                |
+-------------------+--------------------+----------+--------------------+
| User Password     |                    | 22       | 128                |
+-------------------+--------------------+----------+--------------------+

2
-
Definition eines Sets an Verschlüsselungs- Hash- und Signierungsalgorithmen, die eine gleiche Kryptographische Stärke aufweisen, damit es kein schwaches Gleid in der Kette gibt. "B Secret" definiert sichere Schlüssellängen für die Stufe Vertraulich, "B Top Secret" definiert sehr sichere Schlüssellängen für die Stufe Geheim.

3
- 
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
		
4
-
A verschlüsselt den Key mit mit EC und überträgt ihn. B entschlüsselt ihn mit ihrem secret und den öffentlichen Parametern.

5
-
ECDH
	Elliptic Curves mit Diffie Hellmann: Jeder Kommunikationspartner hat ein EC pub/priv Key Paar und damit wird ein gemeinsamer Schlüssel für die Kanalverschlüsselung verschlüsselt und ausgetauscht
ECIES
	Elliptic Curve Integrated Encryption Scheme: Hybrides Verschlüsselungsverfahren basierend auf EC. Der symetrische Schlüssel wird mit asymetrischen EC Keys verschlüsselt und übertragen.
ECDSA
	Elliptic Curve Digital Signature Algorithm: Der DSA Schlüssel wird mit EC verschlüsselt und übertragen.
		
6
-
Eine Kombination aus Verschlüsselung und Hash Algorithmus, der fast gleich schnell ist, wie Verschlüsselung alleine und viel schneller ist als Verschlüsselung + Signaturerstellung einzeln.


Physical Layer Security
=======================

7
- 
Voice Scrambling
	Sprachfrequenzspektren werden umgedreht (höchste Frequenz wird zur niedrigsten und umgekehrt) und verschoben im Frequenzspektrum. Beim Multiplexing werden mehrere solche Frequenzspektren nebeneinander gelegt. Der Empfänger muss wissen, wie breit die Frequenzspektren sind, und wo sie beginnen, damit er wieder demultiplexen kann. Das Verfahren basiert auf Security by Obscurity und ist daher nicht sicher.
Frequency Hopping
	Der Datenkanal springt nach einem vorgegebenen Muster (Zeitabstände, Sprung) zwischen den Frequenzen hin- und her. Der Empfänger muss das Muster kennen, damit er mitspringen kann. Auch dieses Verfahren basiert auf Security by Obscurity.
		
8
-
1) Es werden verschränkte Photonen erzeugt, die zwei Polarisationen annehmen können. Die Polarisation wird erst durch die Messung festgelegt.
2) Sender und Empfänger besitzen Filter Sets, mit denen Sie die Photonen Polarisiert messen können. Diese Messung kann nur einmal durchgeführt werden und daher muss man sich für ein Filterset entscheiden.
3) Sender und Empfänger tauschen die benutzen Filtersets aus. Haben sie ein Photon mit unterschiedlichen Filer gemessen, wird der Wert verworfen, ansonsten behalten.
4) Weil die Photonen verschränkt sind, bemerken die beiden, wenn es abgehört wird.
5) Versucht jemand ein Photon einzuspeisen, so geht dies nicht weil sich Photonen nicht duplizieren lassen.
6) Sender und Empfänger nutzen die übertragenen Photonenwerte als Key.
	
9
-
Die Quanten sind verschränkt. Sobald die eine Quante gemessen (abgehört) wird, wird auch die andere verändert.

10
--
* Die Photonen werden moduliert, das restliche Verfahren funktioniert wie bei 8 beschrieben.
* Klaut jemand ein Photon (mithören), kriegt der Empfänger keines (Verschränkung)
* Probleme:
	* Photonen können nicht kopiert werden, entsprechend kann das Signal nicht aufgefrischt/erneuert werden (kein Repeathing)
	* Die Dämpfung in der Leitung begrenzt damit die Übertragungsdistanz.
	* Es ist unmöglich einen Laser zu bauen, der nur ein Photon auf's Mal ausgibt. Daher werden im Durchschnitt zwar schon nur ein Photon geliefert, aber manchmal auch zwei oder mehr oder keines.
	* Werden mehr oder weniger als 1 Photon aufs Mal übertragen, müssen diese Verworfen werden.
	* Es ist schwierig zu unterscheiden, ob der Sender kein Photon abgeschickt hat, oder ob es geklaut wurde. Darum werden wenn mehr oder weniger als 1 Photon aufs Mal übertragen werden, diese Verworfen.
	* Die Datenrate ist damit extrem tief und eignet sich nicht für Streamcipher, sondern nur für Key Distribution.
	
11
--
In der Praxis sind die Distanzen viel zu klein, als das man das System vernünftig einsetzen kann, und man benötigt eine sepparate Faser. Zudem sind die System teuer. Ausserdem ist die Datenrate so klein, das für die Übertragung eines Schlüssels bis zu einer Minute gebraucht wird.

12
--
Einen Kanal für die Quantenübertragung des Keys (niedere Rate) und ein gewöhnlicher Datenkanal, auf dem die mit dem Key verschlüsselte Daten hochratig übertragen werden.


Schlüsselmaterial und Zufallszahlen
===================================

13
--
Die Nachricht wird zusammen mit dem inner Key (Key K xor verknüpft mit Konstante ipad) gehashed und der entstandene Hash zusammen mit dem Outer Key (Key k xor verknüpft mit Konstante opad) erneut gehashed -> HMAC.

14
--
* PRF erzeugt aus einem Key einen Keystream.
* Ein Sied wird durch dem Key gehashed. Der Output wird als Input für die Nächste Hashrunde durch den Key anstelle dem Seed verwendet. Jeder Teil des Outputstreams wird nochmals zusammen mit dem Seed durch den Key gehashed.
* Es wird das Schlüsselmaterial vervielfälltig/verdünnt. Die Entropie wird dabei nicht verändert.
* Besitzt der Key eine miserable Entropie, besitzt der Schlüsselstream anschliessend die genau gleich miserable. -> Hashing verändert nur die Statistik, nicht aber die Entripie!

15
--
Aufteilung auf MD5 und SHA-1
	Es wird befürchtet, das MD5 demnächst fällt, und das es in SHA-1 eine Backdoor gibt, darum wird auf nicht nur ein Hashing Verfahren gesetzt.
TLS 1.1 Berechnung Master Secret
	Premaster Secret wird zur Hälfte mit MD5, zur Hälfte mit SHA-1 durch Seed gehashed und beide Teile anschliessend Verknüpft -> Master Secret.
Schlüsselgenerierung
	Genau wie wie bei der Berechnung des Master Secrets werden neue Schlüssel erzeugt, indem die Hälfte des Master Secrets mit MD5 und die andere Hälfte mit SHA-1 gehashed und verknüpft werden.
	
16
--
* Zeit zwischen Tastenanschlägen auf der Tastatur
* Mausbewegungen
* Soundkarte Rauschen
* Zugriffszeiten Harddisk (Varianz durch Luftturbulenzen im Gehäuse)

17
--
Hardwarebauteile, die einen Strom von Zufallszahlen liefern, die eine hohe Entropie aufweisen. z.B.

* instabile Diodenschaltungen
* Anzapfen des thermischen Rauschens.

18
--
Der IDQ besteht aus einer Taktung und zwei gegenseitig verschaltete Dioden, die einen instabilen Zustand herbeiführen (flackern / wildes hin- / herschalten) und damit zufällig 0 oder 1 liefern.

19
--
Liefert ein Zufallsgenerator deutlich mehr 0 als 1en oder umgekehrt, kann das zu häufig auftretende Zeichen nach Auftrittswahrscheinlichkeit substituiert werden und damit die Verteilung ausgeglichen werden.


Data Link Security
==================

20
--
Supplicants melden sich beim Authenticator (Access Point/Switch), dieser sendet erlaubte Anfragen weiter an den RADIUS Server. Kann der RADIUS Server den User erfolgreich anmelden, erhält er Access. Wichtig ist, das die Trunkleitung zum RADIUS Server verschlüsselt ist.

21
--
DevId
	Die Secure Device ID sind RSA und EC Keys, die vom Hardwarehersteller erzeugt, signiert und hinterlegt werden. Da Sie eindeutig ist, kann sie zur Generierung von Authentication Keys genutzt werden. Die DevID kann vom Benutzer nicht verändern werden.
DevId Modul
	Das DevID Modul sollte nebst einem Zugriffssicheren Storage für die DevID einen Zufallsgenerator und hardwarebasierte Hash Algorithmen besitzen.
Key Generation
	Anwendungsschlüssel werden direkt im DevID Modul durch die DevID, den enthaltenen Zufallsgenerator und die Hashalgorithmen erzeugt und im DevId Modul gespeichert. Die Keys verlassen das DevID Modul nie, sondern werden im Modul genutzt, um weitere Schlüssel zu signieren.
	
22
--
Secure Connectivity Association
	Eine Data Link Layer Gruppe, deren Teilnehmer den Datenverkehr verschlüsseln. Für jeden Teilnehmer gibt es einen Sicheren Channel, durch den er die Datenpakete an die andern Teilnehmer schickt.
Channel
	Jeder Channel besitzt einen eigenen Key. Die Channels sind somit unabhängig und gerichtet.
Vorteile
	Der Datenverkehr zwischen den Teilnehmern ist bereits auf Data Link Level Verschlüsselt und über die höheren Verbindungen können keine Metadaten gesammelt werden.

23
--
MACsecPackage::

	                [PT][User Data]
	[DA][SA][SecTag][Secure Data  ][ICV][FCS]
		
		
* Der SecTag beinhaltet Controll Information, Association Nr., Länge wenn > 64Byte, Paket Nr. und Channel Identifier
* Die Secure Data ist die verschlüsselte MAC Payload und den Type
* Die ICV ist eine cryptographische Checksumme
* Bei getaggten VLAN Paketen wird der Ethernet Frame gesprengt!
	
24
--
1) Jeder Teilnehmer besitzen einen persönlichen Connectivity Association Key CAK.
2) Ein Secure Association Key SAK wird gebildet, indem die Teilnehmer mit ihren CAKs Teile des SAK generieren.
3) Mittels einem Key Encryption Key KEK werden die SAKs verteilt.

25
--
Statt bei den Teilnehmer selbst gespeichert, liegen die Keys auf einem EAP Server, der damit dynamische CAKs generiert.


Application Security
====================

26
--
Open Web App Security Project

27
--
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
	
28
--
3-Tier Web Application::

	[    Client / Browser     ]
	            |
	[ Web Server / App Server ]
	            |
	[      Data Storage       ]
	
	Auf jedem Tier muss die Identität des zugreifenden Users überprüft werden! Nicht nur auf den ersten 2!
	
	
29
--
Der Benutzer klickt auf etwas anderes, als er meint zu klicken. Beispiel: Der User klickt auf einen Bestellen Button. Darüber liegt jedoch ein transparenter Layer, der den Klick abfängt und dem Benutzer ein anderes, teureres Angebot in den Warenkorb wirft.

30
--
Ein Angreifen schleust Script Code oder Parameter über Felder oder Parameter in die Webseite ein. Andern Usern wird anschliessend die kompromitierte Webseite ausgeliefert.

* Non-Persistent (Reflektiert): Eingaben, die der Server direkt an den Client zurücksendet. Auf einer Webseite werden vergangene Suchanfragen mit Kontaminieren Parametern aufgelistet
* Persistent (Nicht reflektiert): Der Angreifer schleusst Script Code oder Formulare in die Daten der Webweite ein. Werden die Inhalte dem nächsten User geladen, werden auch die kompromitierten Inhalte geladen / ausgeführt, z.B. einen Image Tag, der vom Server des Angreifers ein Bild lädt und als Parameter das Cookie mitschickt, womit der Angreifer die Session übernehmen kann.
* DOM Basiert (lokal): Der Webserver ist nicht beteilitg. Z.B. erhält der User einen Link, der als Parameter eine Codezeile beinhaltet. Das Javascript der Seite fügt den Schnipsel in die Seite ein und der Browser führt in anschliessend aus (z.B. fügt das Seitenskript einen href zu einem Link hinzu, womit sich ein onmouseover einschleusen lässt.).
	
Protection: Parameter oder Inhalte, die von einem User stammen, müssen zwingend Escaped werden
	
31
--
* 80 gefundene Verletzlichkeiten/Webseite/Jahr (230 im 2010)
* XSS ist die am meissten ausgenutzte Verletzlichkeit von Webseiten (55% der Webseiten betroffen)
* Web Application Firewalls halfen viele der Risiken aufzudecken
* Verletzlichkeiten in Webseiten werden im Durchschnitt nach 38 Tagen gefixt (nach 116 Tagen im 2010)
* Die Zahl der insgesammt geschlossenen Verletzlichkeit stieg gegenüber 2010 um 10%
* Im Durchschnitt waren Webseiten während 2/3 des Jahres von mindestens einer Verletzlichkeit betroffen.

32
--
Confidentiality
	* Jemand erlangt unerlaubten Zugriff auf geschützte Daten der Webseite
Integrity
	* Jemand modifiziert geschützte Daten der Webseite
	* Jemand verwendet die Plattform zum Angriff auf andere Plattformen oder User
Accessability
	* Jemand legt die Webseite mit einem Angriff lahm
	
33
--
OWASP Top 10
	Die grössten Risiken:
		1) Injection
		2) Fehler in Authentifizierung und Session Management
		3) Cross-Site Scripting (XSS)
		4) Unsichere direkte Objektreferenzen
		5) Sicherheitsrelevante Fehlkonfiguration
Kriterien
	Die Risiken werden ermittelt durch eine Bewertung der Attacke, die Sicherheitslücke(n), das herrschende Sicherheitsmanagement für diesen Angriff, Technische Auswirkungen und Business Auswirkungen
	
34
--
Daten / Information (asset, value) werden durch Massnahmen geschützt (Protections, measures, controls). Angriffe (Threads) auf Verletzlichkeiten (Vulnerabilities) bedrohen die Informationen

::

	.------------------------.
	| Protections, measures, |
	| controls               |
	| .----------------.  < <  Vulnerabilities
	| | Information    |     |   ,------------------.
	| | (asset, value) |     |  < Threads           |
	| '----------------'     |   '------------------'
	'------------------------'	
	
35
--
Faktoren, die die Verletzlichkeit beeinflussen:

* Leichte Entdeckbarkeit
* Einfachheit des Exploits
* Bekanntheit der Verletzlichkeit
* Bemerken des Ausnützens
	
36
--
1) Vor der Entwicklung: Sicherheitsdokumente bereitstellen und Vorhandensein im Ablauf überprüfen
2) Design: Requirements Reviews, insbesondere security Reviews machen
3) Development: Code Reviews
4) Development/Testing: Penetration Testing
5) Maintenance and Operations: periodical Health checks, operational management reviews

37
--
* Busness Requirements
* Infrastructure Requirements
* Application Requirements
* Security Programm Requirements

38
--
Falsche oder keine TLS Protection. Beispiele: Kein Schutz von Datenbankverbindungen des Webservers zu einem externen Server, kein Schutz von Webseitebereichen die eine Authentifizierung erfordern (Passwort Klartextübertragung),  Falsch konfigurierte TLS Zertifikate, die den User mit Fehler und Warnmeldungen bombardieren.


Web Application Security
------------------------

39
--
Die unteren Schichten sind heute relativ bewährt und grosse Angriffsmöglichkeiten gibt es immer weniger. Die Applikationen hingegen sind immer gleich verwundbar und werdne z.T. sogar schlampig programmiert.

40
--
Eine Serverseitige Applikation übernimmt nicht ecsapte Parameter über Post oder Get und baut diese in einen SQL Befehl ein. Wird ein Parameter so gestaltet, das er zuerst den aktuellen Befehl abschliesset und dann neue Befehle anhängt, können beliebige Befehle auf der Datenbank ausgeführt werden.

41
--
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
	
42
--
Der Applikation wird vorgegaukelt, der User sei bereits authentifiziert. Z.B. durch direktes Anspringen der Seite mit geschützten Inhalten oder mitgeben von Parametern, die Zugriffserlaubnis signalisieren

43
--
Weil damit eine Brute Force Attacke wesentlich vereinfacht wird. Gibt der Angreifer einen fingierten Usernamen und Passwort ein und er erhält die Meldung "Passwort falsch" so hat er bereits die Information erhalten, das es diesen user gibt. Unterschiedliche Antwortzeiten des Servers, je nach dem ob user oder passwort falsch, können einem Angreifer ebenfalls Informationen darüber liefern.

44
--
Der Angreifer behält das Passwort bei und variiert den usernamen. Da Error Delay normalerweise auf den User gebunden ist, funktioniert dies.

45
--
Authentisierung
	Identität des Users klären
Authorisierung
	Erlaubte Aktionen klären
	
46
--
* What I know: Passwörter, Slide-Figur, ...
* What I have: Chipkarte, rsa Key, ...
* What I am: Iris, Fingerabdruck, DNA, ...

47
--
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
	* Daten, die das Unternehmen verlassen werden kontrolliert
	* Es wird versucht, keine Daten in unerlaubte Hände fallen zu lassen
Usage Controll
	Es wird kontrolliert, was mit den Daten gemacht wird
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
-------

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

		Client                              | Zieladdr | Absender | Data | Padding |
		KeyC                        | C | B | Encrypted Package (Client->Target)   |
		KeyB                | B | C | Encrypted Package (B->C)                     |
		KeyA   | A | Client | Encrypted Package (A->B)                             |

		A      | A | Client | Encrypted Package (A->B)                             |
		       | Junk       | B | C | Encrypted Package (B->C)                     |

		B      | Junk       | B | C | Encrypted Package (B->C)                     |
		       | Junk               | C | B | Encrypted Package (Client->Target)   |

		C      | Junk               | C | B | Encrypted Package (Client->Target)   |
		       | Junk                       | Zieladdr | Absender | Data | Padding |

		Target | Junk                       | Zieladdr | Absender | Data | Padding |


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
* LCP kann auch ohne Verschlüsselung genutzt werden -> problematisch
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
* MPLS Sind Labels, die der Provider im Backbone Netzwerk vor die Pakete hängt, damit sie einfacher zu routen sind.
* Den Paketen wird ein Destination Label und ein Label, das jeweils den nächsten Knoten anzeigt, vorangestellt.

Shim Header::

	| Label,  ClassOfService, B, TimeToLive | IP ... |


IPSec Transport Mode
--------------------

85
..
**Mit AH**

* IPSec authentifiziert das IP Paket.
* Zwischen dem IP Header und dem Payload wird der Authentication Header eingefügt.
* IPSec ohne Authentsierung ist anfällig auf IP Spoofing oder Package Modification
* Authentication Header enthält MAC für gesammtes Paket

::

	| Orig. IP Header | Authentication Header | TCP | Payload |

**Mit ESP**

* IPsec verschlüsselt den Payload über den Encapsulation Security Payload ESP
* ESP Schützt zwar das Paket, jedoch nicht den IP Header im Vergleich zu AH

::

	| Orig. IP Header | ESP [/// TCP Paket | Payload | ESP Trailer ///] ESP Authentication |



86
..
?

IPSec Tunnel Mode
-----------------

87
--
* IPSec Tunnel Mode Wrapt das komplette IP Paket in ein ESP geschütztes IP Paket
* Dadurch ist das originale IP Paket komplett verborgen
* Mehr Overhead als Transport Mode
* Authentifiziert ist der ESP Header, nicht aber der äussere IP Header

::

	| IP Header | ESP [/// IP | TCP | Data | ESP Trailer ///] ESP Authentication |


88
..
* Statt Hashing und Verschlüsselung einzeln zu machen, wird gleichauf's Mal der Hash erzeugt und Verschlüsselt
* Wesentlich effizienter als wenn einzeln gehashed und verschlüsselt wird
* Overhead Hängt von der Verschlüsselung ab. Empfohlen AES-GSM weil schnell und Overhead klein


Internet Key Exchange
---------------------

89
..
Das Internet Key Exchange Protocol übernimmt die Schlüsselverwaltung für IPSec.
Ike Basiert auf UDP und handelt in einem ersten Schritt die Security Association SA aus, die im zweiten Schritt etabliert wird.

90
..
Die Security Association definiert die verwendete Verschlüsselung und Authentifizierung und wird zwischen den Endstellen ausgehandelt.


IKEv1
.....

91
~~
* Initiator schickt SA Angebot
	Paket::

		| IKE Header | SA Proposal |


* Responder antwortet und bestätigt SA mit ähnlichen Paket
* Initiator macht DH Key Exchange
	Paket::

		| IKE Header | DH Key Exchange | Ni |


* Responder macht ebenfalls Key Exchange mit ähnlichem Paket
* Initiator überträgt verschlüsselt ID, Zertifikat und Signatur
	Paket::

		 | IKE Header [/// ID | Zertifikat | Signatur ///]


* Responder antwortet mit gleichen Informationen

92
~~
Statt dem Zertifikat und der Signatur wird der Hash des Passwortes übertragen (in den beiden letzten Paketen).
Weil der Benutzer ebenfalls verschlüsselt ist, müsste ein VPN Router alle Benutzer durchprobieren wenn dynamisches Routing eingesetzt wird -> darum wird der Mode nie verwendet.

93
~~
* Im Agressive Mode werden bereits im ersten Paket nebst dem Proposal DH Keys, eine Zufallszahl und die ID übertragen.
	Paket::

		 | IKE Header | SA Proposal | DH Key Exchange | Ni | IDi |


* Der Responder sendet als Antwort ebenfalls DH Keys, Zufallszahl, ID und noch einen Hash.
	Paket::

		 | IKE Header | SA Response | DH Key Exchange | Nr | IDr | Hashr |


* Der Initiator überträgt ebenfalls den Hash offen
* Die ID's können gesnifft werden
* Hash könnte durch offline-Attacke geknackt werden, desto simpler das Passwort, desto einfacher

94
~~
* Der Man In The Middle simuliert einen Hotspot (hängt sich damit zwischem Client und VPN Gateway) und snifft ID und Passworthash, den er anschliessend knackt.
* Der VPN Gateway authentifiziert sich beim Client nur mit dem Gruppenpasswort und das kennt onehin jeder in einer Firma.

95
~~
Quick Mode: Kann eingesetzt werden, wenn beide Seiten die genau gleiche SA vorschlagen. Kann zur Erstverbindung genutzt werden, wird jedoch vor allem zum Erneuern der Verbindung genutzt.


IKEv2
.....

96
~~
* Weniger Pakete
* Bereits beim ersten Austausch werden genügend Informationen für die Verschlüsselung übertragen, sodass ab dem zweiten Austausch verschlüsselt kommuniziert wird
	Jeweils ersten Paket von I und R::

		 | IKE Header | SA | KE | N |


* Nur die eine Seite (I) macht retransmitt bei Paketverlust -> keine doppelten Sessions mehr
* Gateway wählt automatisch Trafic Selector

97
~~
Der Initiator schickt beim zweiten Austausch nebst IDi, Zertifikat und IDr eine weitere SA mit inklusiv Authentication mit, die der Responder bestätigt

Pakte::

	| IKE Header [/// IDi | Cert | IDr | Authentication | SA | TS | TS ///]


98
~~
Statt mit SA und DH Keys zu antworten, sendet der Responder ein Cookie mit dem Auftrag, die Anfrage zusammen mit dem Cookie nochmals zu senden. Erst dann berechnet der Responder den DH Key und antwortet.

99
~~
Der Initiator sendet eine SA mit Zufallszahl, Key Exchange und TS im verschlüsselten Paket. Der Responder antwortet entsprechend.

100
~~~
VPN zwischen Standorten
	Zwei Standorte werden zwischen zwei VPN Gateways mit einem VPN Tunnel verbunden.
VPN Remote Access
	Zwischen einem VPN Gateway an einem Standort und einem remote Client wird ein VPN Tunnel aufgebaut. Virtuelle IP's helfen dem Router den Remote Client intern richtig zu routen.

101
~~~
Extendended Authentication XAUTH
	Proprietärer Standard zur externen Authentifizierung
IKEv2 EAP
	Authentication über EAP, Übertragung im AUTH Part des Paketes

102
~~~
* Der Initiator sendet seine IP als Hash mit. Stimmt der Hash nicht überein, so ist ein NAT in der Verbindung.
* Die VPN Pakete werden in UDP getunnelt um durch das NAT zu kommen.

Paket::

		| IP | UDP | IKE Header | Payload |


DNS Sec
=======

103
---
Die Abfrage des ISP an den Root Server wird abgefangen und eine falsche IP  für den zuständigen Nameserver zurückgesendet.
Dadurch gehen sämmtliche Anfragen für diese Zone (z.B. die .net Zone) an den DNS Server des Angreifers und dieser kann beliebige Antworten liefern und den Client so an einen falschen Server umleiten.

104
---
* Client sendet Anfrage an DNS Server (wenn keiner Konfiguriert -> DNS Server des ISP)
* Dieser liefert die Antwort aus seinem Cache oder antwortet wie folgt:
	Rekursive Abfrage
		* ISP Nameserver Fragt Root Server
		* Fragt vom Root Server genannten zuständigen TLD Nameserver
		* Fragt vom TLD Server genannten zuständigen .....
	Nicht rekursive Anfrage
		* ISP Nameserver antwortet: keine Ahnung, frag Root Server
		* Client fragt Root Server
		* Client fragt vom Root Server genannten zuständigen TLD Nameserver
		* Client fragt...

105
---
* Jeder Server besitzt einen KSK (Priate Key, hoch geheim) und einen ZSK (privater Arbeitskey, vom KSK signiert)
* Der Root DNS Server signiert mit seinem ZSK die KSK's der Stufe darunter
* Die Stufe darunter signiert mit dem ZSK die KSK's der Stufe darunter
* ...

106
---
DNSSEC Resource Record Signature

107
---
* DNS Based Authentication of Naming Entries.
* Zertifizierung von Websever über DNS SEC.

108
---
* Bei der Anfrage a den DNS server liefert dieser gleich den TLSA Record mit, der das CA Zertifikat beinhaltet
* Der Browser kann damit das Zertifikat des Webservers überprüfen ohne eine Anfrage an die CA

109
---
* Self Signed Zertifikate werden im Zonenfile hinterlegt. Die Zone ist durch die DNS SEC Hirarchie gesichert.
* Der Server liefert bei der DNS Abfrage das Zertifikat mit
* Der Browser vergleicht das Zertifikat vom DNS Server mit dem Zertifikat vom Webserver
* Sind die beiden Zertifikate identisch, so befindet sich der Client beim richtigen Server
* Mit dem Im Zertifikat enthaltenen Public Key kann der Browser gleich eine TLS Verbindung aufbauen

110
---
Die Zertifikate können Seld-Signed sein, weil über DNS SEC das Eigene Zertifikat (mit dem das Self-signed Server Zertifikat signiert wurde) ausgeliefert wird, analog zur Auslieferung eines CA Zertifikates

111
---
Der Browser kann über DNSSEC den RSA Key verifizieren.

112
---
* Das "Root Zertifikat" (das Zertifikat im Zonenfile, mit dem das Zertifikat des Webservers signiert wurde) oder lediglich der Public Key werden über DANE vom DNS Server geladen.
* Jeder kann damit sein eigenes Root Zertifikat erstellen. Zertifizierungsstellen für Webserverzertifikate werden überflüssig.
*  Nur derjenige, der das Recht für Änderungen im Zonenfile besitzt, kann auch dort sein Root Zertifikat hinterlegen

113
---
* VeriSign (z.B.) zertifiziert den Root Server, durch Signierung des ZSK.
* Die ICANN generiert mit dem signierten ZSK einen KSK, mit dem sie Root Key Sets signiert.

114
---
Nein. Keys können nicht zurükgezogen werden. Sie laufen einfach aus.

115
---



6 VoIP Security
===============

6.1 Grundlagen
--------------

**6.1.1 VoIP Kommunkationsprinzip**

Zwei Channels:

* Signalling Channel, wird benutzt um den andern Kommunikationspartner über einen Serverdienst aufzufinden
* P2P Media Channel, wird benutzt um direkt zwischen den Teilnehmern Multimedia auszutauschen

::

	sA.tld                                                                       sB.tld
	SIP Server A  ------------- Signalling Messages (SIP) -------------->  SIP Server B
	   ^                                 Hop 2                                     |
	   |                                                                           |
	   | Hop 1                                                               Hop 3 |
	   |                                                                           |
	   |                                                                           v
	Peer 1  <------------------------ Media Stream (RTP) --------------------->  Peer 2
	
	peer1@sA.tld                                                           peer2@sB.tld


Sowohl die Verbindung der einzelnen Hops wie der Media Stream sollten verschlüsselt sein

Verbindungsaufbau
	1) die beiden Peers melden sich bei ihren Servern, sobald sie online sind
	2) Peer1 sendet eine SIP Message für peer2@sB.tld an sA.tld
	3) sA.tld sendet die Message weiter, da peer2@sB.tld keiner seiner Kunden ist
	4) sB.tld sendet die Message an den Client weiter. Die Message enthält eine SDP (Session Description, die Details über den Peer1 liefert)
	5) Peer2 sendet eine Nachricht zurück an Peer1 auf dem gleichen Weg und ebenfalls mit einer SDP in der SIP Message
	6) die beiden Peers versuchen sich gegenseitig direkt zu erreichen mit den Informationen aus den SDP's
	7) Die Peers etablieren die RTP Verbindung
Verbindungsabbau
	Geschieht direkt über den P2P Stream

**6.1.2 Channels**

Der P2P Channel kann erst etabliert werden, wenn die beiden Peers IP und Ports für den Stream kennen. Dazu tauschen sie sich über den 2. Channel (Signalingchannel) über einen gemeinsamen Treffpunkt aus.

**6.2.3 SIP Authentisierung**

Damit der Empfänger der Nachricht sicher sein kann, das die Nachricht wirklich vom angegebenen Empfänger stammt und dieser unter der angegebenenen Adresse erreichbar ist. Ansonsten kann die Nachricht auf dem Weg manipuliert werden.

**6.2.4 Verbindungsaufbau**

::

	P1                   SA                    SB                P2
	|                     |                    |                  |
	|-------invite------->|                    |                  |
	|<-----trying---------|------invite------->|                  |
	|                     |<-----trying--------|-----invite------>|
	|                     |                    |<----ringing------|
	|                     |<-----ringing-------|                  |
	|<-----ringing--------|                    |<-------OK--------|
	|                     |<-------OK----------|                  |
	|<-------OK-----------|                    |                  |
	|                                                             |
	|----------------------------ACK----------------------------->|
	|<======================== Media Stream =====================>|
	|<---------------------------BYE------------------------------|
	|-----------------------------OK----------------------------->|

	
**6.1.5 RTP**

Realttime Procotcol. Standard zur Übertragung von Echtzeitstreams. UDP-basiert.


6,2 Sicherheit
--------------

**6.2.1 RTP Übertragungen**

RTP Übertragungen sind nicht verschlüsselt. Der Payloadtype PT beschreibt den Codec des Payloads. Jeder, der die Pakete mitschneidet kann den Stream zusammensetzen und mithören.

**6.2.2 Wireshark**

Da das Wlan unverschlüsselt ist, kann jeder Teilnehmer auch die Pakete der Anderen mitlesen. Mit einer entsprechend konfigurierten Netzwerkkarte werden auch die Pakete der Anderen an die höheren Schichte weitergegeben womit sich die Pakete mit Wireshark mitsniffen lassen.

Wireshark selbst bietet in der Streamanalyse Support für RTP Streams. Einmal ausgewählt lassen sich diese gleich abspielen.

**6.2.3 VLAN**

Keinen. VLAN Hilft nur die QoS für VoIP Verkehr zu gewährleisten und die Pakete in einem eigenen Subnet verkehren zu lassen.

Wer auf der Trunkleitung sitzt kann alles mitschneiden.

**6.2.4 SRTP**

Die effektiven Streamdaten sind verschlüsselt, Header, Streamidentifier und timestamp sind authentifieziert.

::

	<--------------------- authenticated -------------------------->
	| Header | timespamp | SSRC | CSRC [/// RTP Payload, Padding ///] (MKI) | Authentiction Tag |
	
	<------------- authenticated -------------->
	| Header [/// sender info, report blocks ///] SRTCP index | (MKI) | Authentication Tag |
	
	
* SSRC: synchronization source identifier
* CSRC: contributing source identifiers
* MKI: Masterkey identifiert (optional)

**6.2.5 Payload Verschlüsselung**

Aus dem saltKey, SSRC und packetIndey als Initialisierungsbektor wird mit dem encryptionKey ein AES-CTR Cipherstream generiert, der mit dem Payload xor verknüpft wird.

**6.2.6 Authentisierung**

Der Payload wird SHA1 gehashed (HMAC) mit dem authenticationKey und dieser als Authentication Tag als letzen Teil in das Paket eingefügt.

**6.2.7 Masterkey**

Den Masterkey besitzen beide Teilnehmer. Aus ihm werden die Sessionkeys wie authenticationKey oder encryptionKey generiert.

**6.2.8 Masterkey exchange**

In SDP, TLS gesicherte SIP übertragung
	Nachteil: die Clients müssen TLS unterstützen und der Key ist jeweils nur zwischen den Hops verschlüsselt. Auf den SIP Servern selbst nicht. Damit könnte der SIP Provider die Peerkommunikation entschlüsseln.
In SDP, MIKY (Multiedia Internet Keying)
	* Garantiert eine effektive P2P Verschlüsselung und wird auch innerhalb der SDP übertragen.
	* Varianten
		* RSA: Der mit dem Public Key verschlüsselte Schlüssel wird nebst ID und Signatur in der SDP mitgesendet
		* DH: Die Parameter für die DH Schlüssel etablierung werden nebst ID und Zertifikat in der SDP mitgesendet
	
**6.2.9 Session Keys**

Aus dem Initialisierungsvektor (salt, label, packet index) und dem masterkey wird mit AES-CTR ein Keyblock generiert, der in encryptionKey, authenticationKey ud saltKey aufgeteilt wird.

**6.2.10 Tunneling über IPsec**

Vorteile
	* Mediastream P2P Verschlüsselt
	* Befinden sich die SIP Server innerhalb des Unternehmens, so ist auch  Kommunikation des Signallingchannels verschlüsselt, wenn der Client über einen IPsec Tunnel dem Unternehmen angegliedert ist
Nachteile
	* Viel Oberhead
	
	
6.3 Sicherer Verbindungsaufbau
------------------------------

**6.3.1 SPIT**

Spam over Internet Telephony. Kennt ein Spambot die sip Adresse des Empfängers, so kann er ihm voice-spam versenden.

Benutzer würden dauernd mit Werbe-Anrufanfragen oder sogar Werbesnippets im Stream genervt.

**6.3.2 Missbrauch**

* SIP Messages umleiten
* Dos Attacks
* Problem -> SIP Messages sind nicht authentifiziert und verschlüsselt, auch die Server nicht

**6.3.3 Absicherung Session Management**

* S/MIME (PKI authentication), zuverlässig
* TLS (PKI authentication), SIP Applikationen müssen TLS unterstützen
* IPsec (PKI authentication), Vertrauen liegt auf den Proxies

**6.3.4 Verschlüsselung**

* Clients wie Server bräuchen Private/Public Keys und Zertifikate.
* Die Messages könnten nur von denjenigen gelesen werden, die auch wirklich sollen
* Schlüsselmanagement wäre ein Albtraum. Die Server müssten an die Public Keys der Clients kommen und umgekehrt.

**6.3.4 DomainKeys**

Die MIKEY Messages werden verschlüsselt. Für Encryption und Authentication ist jeweils ein Lookup auf den DNS Server notwendig um den Key zu erhalten.

**6.3.5 Skype**

Skype verwendet zwar eine starke Verschlüsselung, durch die geschlossene Implementierung kann die effektive Sicherheit jedoch nicht überprüft werden.



Network Access Controll
=======================

116
---
Firewalls analysieren Pakete, um bösartige und unerlaubte Pakete auszufiltern.

Statische Paketfilter
	Filtert anhand des Pakettyps, Ports oder Absenders.
Statfull Firewalls
	* Schneiden den Verkehr mit und merken sich für jede Verbindung den Status. Passen Pakete nicht in den üblichen Paketflow, werden sie ausgefiltert.
	* z.B. darf nie ein DNS Reply vor einem Request kommen

117
---
Anhand des Verbindungsstatus wird der Datenverkehr inspiziert. Siehe 116 Statefull Firewalls


NAC
---

118
...
L2: switch / access point authentisiert mit IEEE 802.1X

L3/4: VPN mit IKEv2 oder TLS based

119
...
Um den Gesundheitszustand des Clients zu ermitteln werden installierte Programme und Einstellungen überprüft.

120
...
block
	* Ein Gerät wird geblockt und nicht zugelassen
isolate
	* Ein Geräte weisst Unregelmässigkeiten im Gesundheitszustand auf und wird nur in die isolierte Zone zugelassen
access
	* Ein Gerät ist in Ordnung und wird ins Netz reingelassen

121
...
Network Access Layer
	Zuerst wird der User authentifiziert
Integrity Evaluation Layer
	dann wird sein Gesundheitszustand gemessen
Integrity Connection Layer
	die Gesundheitswerte werden an den Server übermittelt, der sie überprüft

122
...
Über VPN oder TLS

123
...
Bezeichnet den ganzen Vorgang, den Endpunkt einem Gesundheitscheck zu unterziehen.

124
...
Ein Access Point, der den gesammten Datenverkehr mitschneidet, korreliert und daraus Angriffe erkennt.

125
...
Ein zentraler Metadata Map Service ermöglicht nebst der Messung des Gesundheitszustandes eines einzelnen Clients die Korrelation aller Gesundhetitszusände und des Netzwerkverkehrs und bieten somit eine detailierte Analyse über die komplette Angriffssituation.

126
...
Gegen Lieing Endpoints hilft TNC/NAC nicht. Der Client kann dem Server beliebige Messerte vorgaukeln.


Buffer Overflow
===============

127
---
Entsprechend gestaltete Pakete werden in so grossen Mengen an den Empfänger gesandt, bis die Paketinhalte den Buffer übersteigen und in einen Bereich mit ausführbarem Code geraten. Sobald das Programm diese Programmstelle aufruft, wird der eingeschleuste Code ausgeführt.

**Beispiel**

* Angreifer überflutet Buffer so, das die Adresse zu seinem über Buffer Overflow eingeschleusten Codefragment den Bereich mit der Rücksprungadresse auf dem Stack überschreibt.
* Sobald die Funktion verlassen wird, wird die kompromitierte Rücksprungadresse aufgerufen und der Code des Angreifers ausgeführt
* Den Bereich zwischen dem Buffer und der Rücksprungadresse muss der Angreifer mit Müll überschreiben
* Der Angreifer kann als Müll nicht 0 nehmen, weil dies den String beenden würde.

128
---
Stack Randomisation
	* Stack Inhalte werden randomisiert angeordnet.
	* Verringert die Wahrscheinlichkeit, das der Angreifer den Rücksprungpointer trifft
	* Verhindert Angriff nicht

Canary
	* Vor der Rücksprungadresse wird ein Bereich mit bekanntem Inhalt (meisst 0, warum siehe 127) gefüllt.
	* Überschreibt der Angreifer den Stack bis zur Rücksprungadresse, so hat sich der Inhalt des Bereiches geändert
	* Durch mehrfachen Bufferoverflow kann das Canary wiederhergestellt werden, ist aber sehr aufwendig

Schreibschutz
	* 64Bit Prozessoren versehen Stack Elemente wie Rücksprungadressen mit einem Schreibschutz
	* Verhindert den Angriff


Smart Cards
===========

129
---
Smart Cards können Daten speichern und besitzen je nach Modell einen Prozessor, ein USB Interface, Drahtlos Schnittstellen Tasten und sogar ein Display.

Ziel einer Smart Card ist das sichere Aufbewahren von Schlüsseln. Je nach Modell kann die Smart Card gleich Daten mit diesem Schlüssel signieren. Der Schlüssel ist gegen Überschreiben und Auslesen geschützt.

130
---
a) Memory Card
..............
* Kann Daten speichern und ist gegen Veränderung geschützt
* Beispiel: Telefonkarte

b) USB Token
............
* Karte und USB Kontroller als Stick umgesetzt.
* Hohe Transferrate
* Teuer

c) SIM Card
...........
* einfache Chip-Karte
* Speichert Daten

d) Crypto Card
..............
* Karte mit RSA unterstützung
* BS ist im ROM vor Veränderungen geschützt

e) Java Card
............
* Auf der Karte läuft ein minimal Java BS
* BS kann über Profiles aktualisiert werden

131
---
* Batterielose Karten mit Drahtlosschnittstelle
* Der Prozessor wird über die Luft mit Energie versorgt, daher Distanz zum Endpunkt nur gering

132
---
Smart Cards mit integriertem E-Ink Display, auf dem Zahlen oder Buchstaben dargestellt werden können.

Dislay Cards können z.B. Einmahl-Tokens für E-banking anzeigen

133
---
* Near Field Communication
* Über eine Drahtlosschnittstelle kann ein ausgerüstetes Endgerät mit der Karte oder dem Smartphone mit NFC kommunizieren
* Mit NFC können digital Geldbörsen umgesetz werden

**Secure NFC**

* Das NFC Modul ist über die Sim Karte abgesichert, um den Missbrauch durch Malware zu vermeiden.
* Die SIM Karte stellt ein Sicherheitsmodul in der Kette "APP -> SIM -> NFC" dar.
* Über die SIM kann mit NFC auch DRM umgesetz werden
* SIM und NFC Module kommunizieren über das Single Wire Protocoll SWP

134
---
* Vcc, GND: Speisung, Masse
* RST: Zur Initialisierung. Gibt z.B. Kartentyp zurück
* SWP: Single Wire Prtocoll, zum Beispiel für Kommunikation mit NFC Module
* CLK: Extern zugeführter Takt (Clock)
* AUX: USB

135
---
Challenge/Response
	Es wird gar kein Key ausgetauscht
Security By Obscurity
	Die Hardwarebausteine werden auf der Plattine wild vermischt. Wer den Bauplan nicht kennt, findet sich nicht zurecht
Leitende Deckschicht
	Die Deckschicht des Gusses stellt den oberen Teil eines Kondensators dar. Wird sie weggeätzt um Zugang zur Schaltung zu kriegen, bemerkt dies der Prozessor und zerstört die Karte
Scrambling
	Scrambling Algorithmus vertauscht RAM und EEPROM Speicherzellen. Nur werden den Alg. kennt, kommt an die Daten.

136
---
* Es besitzt eine Ordnerhirarchie, die einem Masterfile untergeordnet ist
* Ordner besitzen Identifier und Namen
* Dateien besitzen einen Head mit Informationen wie einem Identifiert und Metadaten sowie einem Content Pointer
* Dateiheader werden in einem Bereich abgelegt, der selten beschrieben werden soll, body in einem Bereich, der mehr Schreibzyklen verkaftet

137
---
* Command Message: Besteht aus Header und Body
* Response Message: Besteht aus Body und Trailer

138
---
Unterstützen Karten die standartisierten Interfaces PC/SC oder PKCS#11, so können über diese mit der Karte kommuniziert werden, bzw. Daten ausgetauscht werden.

139
---

140
---
Prepaid Karten (Vorauszahlung)
	* Telefonkarten

Electronic Purses (Vorauszahlung)
	* CASH
	* Modox

Debit Cards (Echtzeitbezahlung)
	* Maestro Karte
	* Bank Karte

Kreditkarten (spätere Bezahlung)
	* Master
	* Visa

141
---
* Single Sign On
* Public Key Kerberos Authentication
* TLS Authentication
* S/Mime Signatur und Verschlüsselung
* Softwaresignierung
* VPN Authentication


TPM
===

142
---
Trusted Plattform Module.

Ist ein Hardwaremodule, das Keys erzeugen, verschlüsseln, signieren und hashen kann sowie einen Schlüsselspeicher inklusive einem nicht veränderbaren Hardwarekey besitzt.

Das TPM stellt eine nicht unterwanderbare Verschlüsselungskomponente dar, mit deren Signaturen die Echtheit von Identitäten, Schlüsseln oder Software gewährleisten kann.

143
---
Crypto Funktionen
	* RNG
	* RSA key pair generator
	* symetric key generator
	* encryption/signature module RSA
	* Hashing module SHA-1/HMAC

Geschützter Speicher
	* EK Endorsmentkey (unique und nicht löschbar)
	* SRK Storage Root Key
	* PCR Plattform Config Register (können nur beim Booten gelöscht werden. Später können sie nur einmal beschrieben werden.)
	* AIK Attest Idendity Keys
	* flüchtigen Speicher 

144
---
Um mit dem TPM den Datenstrom einer Festplatte zu verschlüsseln, müsst das TPM über Gigabit angebunden sein.

Das TPM ist an LPC Bus angeschlossen, weil es ursprünglich für die Absicherung des BIOS gedacht war.

145
---
Der Storage Root Key wird benutzt, um sämmtliche andern Schlüssel zu sichern.

Wird der TPM Eigentümer gesetzt, wird der SRK generiert. Wechselt der Eigentümer, so wird ein neuer SRK generiert und der alte gelöscht. Daten, die von SRK geschützten Schlüsseln verschlüsselt wurden, sind somit verloren.

146
---
StorK
	Storage Key, wird zur Verschlüsselung von symetrischen Schlüsseln der Festplattenverschlüsselung benutzt
BindK
	Binding Keys, die Software an Hardware binden können.
AIK
	Attest Identity Key, wird zur bestätigung der Identität verwendet
SigK
	Signaturschlüssel, werden für Signaturen verwendet
MigrK
	Wird benutzt um verschlüsselte daten auf ein neues Gerät zu migrieren. Ist das Notebook defekt und es wurde kein MigrK rechtzeitig exportiert, so sind alle Daten verloren.
SymK
	Symetrische Keys, werden zur Verschlüsselung von Festplatten etc. genutzt.

147
---
Verschlüsselung
	1) TPM generiert Symetrischen Verschlüsselungskey SymK
	2) CPU verschlüsselt Datei mit SymK AES (ausserhalb des TPM)
	3) TMP generiert RSA Key Pair StorK
		1) PubKey wird zur RSA Verschlüsselung des SymK verwendet
		2) PriKey wird innerhalb des TPM mit dem SRK-pubkey durch RSA verschlüsselt
	4) verschlüsselter SymK, PubKey, verschlüsselter PriKey und das verschlüsselte File werden auf der Festplatte abgelegt

Entschlüsselung
	1) Der PriKey wird innerhalb des TPM mit dem SRK-prikey durch RSA entschlüsselt
	2) Der SymK wird mit dem PriKey durch RSA entschlüsselt
	3) Das File wird mit dem SymK über die CPU AES entschlüsselt

Wenn der Storage Key weg ist, lässt sich auch der SymK nicht mehr entschlüsseln. Die Daten sind verloren.

148
---
Binding
	* Software wird an eine bstimmte Voraussetzung, Hardware, Keys gebunden durch symetrische Verschlüsselung.
	* Bindung funktioniert auch ohne TPM
	* Mit MigrK ist es möglich, die Plattform zu wechseln -> ist daher nicht wirklich an die Hardware gebunden

Sealing
	* Software wird über TPM an bestimmte Hardware und Device Zustände (PCR) gebunden.
	* Sealing kann nur mit "non-migrateable keys" genutzt werden
	* Die Konfiguration/Zustand der Plattform kann einbezogen werden -> Software startet nur, wenn bestimmte Bedingungen erfüllt (z.B. Webcam off)
	* Daten können nur entschlüsselt werden, wenn die Plattform sich in einem vertrauenswürdigem Zustand befindet

149
---
BIOS speichert Messwerte über das System in den PCR.

SRTM hashed alle Werte und legt diese in PCR0 ab. Das komplette Vertrauen basiert auf PCR0.

PCR0 kann über TNC übermittelt werden, um die Gesundheit des Systems zu beweisen.

150
---
Weil das BS zu komplex ist und aus zu vielen Modulen besteht, ist es nicht möglich jedes Modul zu signieren und zu sichern. Vernünftiges Arbeiten wäre nicht mehr möglich.

151
---
Beim Bootprozess werden verschiedene System Properties gemessen (z.B. Hash über BIOS, Bootloader, ...) und im PCR abgelegt.

Die PCR Messungen werden zusammengehashed in PCR0.

Das PCR0 kann entweder lokal mit einem älteren Hash verglichen werden oder über TNC an einen Server übermittelt werden, der die Werte mit älteren Vergleicht um sicherzustellen, das das System unverändert ist.

152
---
* TPM Key protection für E-mail Verschlüsselung
* Multi-Faktor Authentifizierung (Something I have)
* VPN Key Protection
* Wlan Encryption Key Protection


