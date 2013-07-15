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