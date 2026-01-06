# Anforderungsdokument

## Einführung

Dieses Dokument beschreibt die Anforderungen für einen README-Generator, der automatisch umfassende README.md-Dateien für Entwicklungsframework-Projekte erstellt. Der Generator soll die Projektstruktur analysieren, vorhandene Dokumentation auswerten und eine standardisierte, professionelle README-Datei generieren, die alle wesentlichen Informationen über das Projekt, seine Umgebung und Verwendung enthält.

## Glossar

- **README-Generator**: Das System, das automatisch README.md-Dateien für Projekte erstellt
- **Projektstruktur**: Die Organisation von Dateien und Verzeichnissen in einem Softwareprojekt
- **Entwicklungsframework**: Standardisierte Entwicklungsumgebungen für verschiedene Programmiersprachen
- **Metadaten**: Informationen über das Projekt wie Name, Beschreibung, Abhängigkeiten und Konfiguration
- **Dokumentationsvorlage**: Strukturierte Vorlage für die Generierung konsistenter README-Inhalte
- **Projekttyp**: Die primäre Programmiersprache oder Technologie eines Projekts (Python, Shell, PowerShell)
- **Changelog-Datei**: Eine CHANGELOG.md-Datei, die chronologisch alle Änderungen am Projekt dokumentiert
- **Autor-Information**: Standardisierte Informationen über den Projektautor einschließlich GitHub-Kontaktdaten

## Anforderungen

### Anforderung 1

**User Story:** Als Entwickler möchte ich automatisch eine umfassende README.md-Datei für mein Projekt generieren lassen, damit ich Zeit spare und eine konsistente Dokumentation erhalte.

#### Akzeptanzkriterien

1. WHEN der README-Generator gestartet wird THEN das System SHALL die aktuelle Projektstruktur analysieren und den Projekttyp identifizieren
2. WHEN die Projektanalyse abgeschlossen ist THEN das System SHALL eine README.md-Datei mit allen erforderlichen Abschnitten erstellen
3. WHEN eine README.md-Datei bereits existiert THEN das System SHALL den Benutzer warnen und eine Bestätigung zum Überschreiben anfordern
4. WHEN der Generator ausgeführt wird THEN das System SHALL eine vollständige README.md-Datei im Projektverzeichnis erstellen
5. WHEN die README-Generierung fehlschlägt THEN das System SHALL eine aussagekräftige Fehlermeldung anzeigen

### Anforderung 2

**User Story:** Als Projektbetreuer möchte ich, dass die generierte README alle wesentlichen Projektinformationen enthält, damit neue Entwickler das Projekt schnell verstehen können.

#### Akzeptanzkriterien

1. WHEN eine README generiert wird THEN das System SHALL einen Projektüberblick mit Beschreibung und Zielen einschließen
2. WHEN Abhängigkeiten im Projekt vorhanden sind THEN das System SHALL diese in einem dedizierten Abschnitt auflisten
3. WHEN Installationsschritte erforderlich sind THEN das System SHALL detaillierte Installationsanweisungen bereitstellen
4. WHEN das Projekt ausführbare Komponenten enthält THEN das System SHALL Verwendungsbeispiele und Befehle dokumentieren
5. WHEN Entwicklungstools konfiguriert sind THEN das System SHALL Entwicklungsrichtlinien und -befehle einschließen

### Anforderung 3

**User Story:** Als Entwickler möchte ich, dass der Generator verschiedene Projekttypen erkennt und angepasste Inhalte erstellt, damit die README für den spezifischen Technologie-Stack relevant ist.

#### Akzeptanzkriterien

1. WHEN Python-Dateien (.py) erkannt werden THEN das System SHALL Python-spezifische Abschnitte wie Virtual Environment Setup einschließen
2. WHEN Shell-Skripte (.sh, .bash) erkannt werden THEN das System SHALL Shell-spezifische Ausführungsanweisungen bereitstellen
3. WHEN PowerShell-Dateien (.ps1, .psm1, .psd1) erkannt werden THEN das System SHALL PowerShell-spezifische Dokumentation erstellen
4. WHEN mehrere Projekttypen erkannt werden THEN das System SHALL eine Warnung ausgeben und den dominanten Typ verwenden
5. WHEN kein erkannter Projekttyp vorhanden ist THEN das System SHALL eine generische README-Vorlage verwenden

### Anforderung 4

**User Story:** Als Benutzer möchte ich die generierten README-Inhalte anpassen können, damit sie den spezifischen Anforderungen meines Projekts entsprechen.

#### Akzeptanzkriterien

1. WHEN der Generator konfigurierbare Optionen hat THEN das System SHALL diese über Kommandozeilenparameter bereitstellen
2. WHEN benutzerdefinierte Projektinformationen bereitgestellt werden THEN das System SHALL diese in die README einbinden
3. WHEN Vorlagendateien vorhanden sind THEN das System SHALL diese als Basis für die Generierung verwenden
4. WHEN zusätzliche Abschnitte gewünscht sind THEN das System SHALL die Möglichkeit bieten, diese hinzuzufügen
5. WHEN die README generiert wurde THEN das System SHALL dem Benutzer mitteilen, wo weitere Anpassungen vorgenommen werden können

### Anforderung 5

**User Story:** Als Qualitätssicherer möchte ich, dass die generierte README konsistent formatiert und vollständig ist, damit sie professionellen Standards entspricht.

#### Akzeptanzkriterien

1. WHEN eine README generiert wird THEN das System SHALL eine konsistente Markdown-Formatierung verwenden
2. WHEN Codeblöcke eingefügt werden THEN das System SHALL die korrekte Syntax-Hervorhebung für die jeweilige Sprache verwenden
3. WHEN Links eingefügt werden THEN das System SHALL deren Gültigkeit überprüfen wo möglich
4. WHEN die README erstellt wird THEN das System SHALL alle Pflichtabschnitte einschließen (Titel, Beschreibung, Installation, Verwendung)
5. WHEN die Generierung abgeschlossen ist THEN das System SHALL die README auf Vollständigkeit und Formatierung validieren

### Anforderung 6

**User Story:** Als Entwickler möchte ich, dass der Generator vorhandene Projektdateien analysiert und relevante Informationen extrahiert, damit die README automatisch aktuell und genau ist.

#### Akzeptanzkriterien

1. WHEN requirements.txt oder pyproject.toml vorhanden sind THEN das System SHALL Abhängigkeiten automatisch extrahieren und dokumentieren
2. WHEN package.json vorhanden ist THEN das System SHALL Node.js-Abhängigkeiten und Skripte dokumentieren
3. WHEN .gitignore vorhanden ist THEN das System SHALL auf Projekttyp-spezifische Konfigurationen schließen
4. WHEN Konfigurationsdateien vorhanden sind THEN das System SHALL deren Zweck in der README erklären
5. WHEN Testverzeichnisse vorhanden sind THEN das System SHALL Testausführungsanweisungen einschließen

### Anforderung 7

**User Story:** Als Projektautor möchte ich, dass standardisierte Autor-Informationen in die README eingebunden werden, damit die Urheberschaft und Kontaktmöglichkeiten klar dokumentiert sind.

#### Akzeptanzkriterien

1. WHEN eine README generiert wird THEN das System SHALL einen Author-Abschnitt mit "Andreas Huemmer" als Autor einschließen
2. WHEN Kontaktinformationen hinzugefügt werden THEN das System SHALL die E-Mail-Adresse "andreas.huemmer@adminsend.de" einbinden
3. WHEN GitHub-Informationen bereitgestellt werden THEN das System SHALL den GitHub-Benutzernamen "surreal70" verlinken
4. WHEN Autor-Informationen eingefügt werden THEN das System SHALL diese in einem dedizierten Abschnitt am Ende der README platzieren
5. WHEN die README erstellt wird THEN das System SHALL die Autor-Informationen konsistent formatieren

### Anforderung 8

**User Story:** Als Projektbetreuer möchte ich, dass eine CHANGELOG.md-Datei für das Projekt bereitgestellt wird, damit alle Änderungen systematisch dokumentiert werden können.

#### Akzeptanzkriterien

1. WHEN der README-Generator ausgeführt wird THEN das System SHALL prüfen, ob eine CHANGELOG.md-Datei existiert
2. WHEN keine CHANGELOG.md vorhanden ist THEN das System SHALL eine neue CHANGELOG.md-Datei mit Standardstruktur erstellen
3. WHEN eine CHANGELOG.md erstellt wird THEN das System SHALL das aktuelle Datum für den ersten Eintrag verwenden
4. WHEN die CHANGELOG.md generiert wird THEN das System SHALL Abschnitte für "Unreleased", "Added", "Changed", "Fixed" einschließen
5. WHEN die README generiert wird THEN das System SHALL einen Verweis auf die CHANGELOG.md-Datei einbinden

### Anforderung 9

**User Story:** Als Entwickler möchte ich, dass das System immer das aktuelle Datum verwendet, damit alle datumsbezogenen Informationen korrekt und aktuell sind.

#### Akzeptanzkriterien

1. WHEN Copyright-Informationen hinzugefügt werden THEN das System SHALL das aktuelle Jahr aus dem Systemdatum verwenden
2. WHEN Changelog-Einträge erstellt werden THEN das System SHALL das aktuelle Datum im ISO-Format (YYYY-MM-DD) verwenden
3. WHEN die README generiert wird THEN das System SHALL das Erstellungsdatum der README dokumentieren
4. WHEN datumsbezogene Informationen verarbeitet werden THEN das System SHALL die Systemzeit zur Laufzeit abfragen
5. WHEN Zeitstempel hinzugefügt werden THEN das System SHALL konsistente Datumsformate verwenden

### Anforderung 10

**User Story:** Als Benutzer möchte ich, dass die README.md ansprechende Icons am Anfang hat, damit das Projekt professionell und visuell ansprechend präsentiert wird.

#### Akzeptanzkriterien

1. WHEN eine README generiert wird THEN das System SHALL passende Icons am Anfang der Datei nach dem Projekttitel einbinden
2. WHEN Icons hinzugefügt werden THEN das System SHALL projekttyp-spezifische Icons verwenden (Python, Shell, PowerShell)
3. WHEN mehrere Technologien erkannt werden THEN das System SHALL Icons für alle relevanten Technologien einschließen
4. WHEN Icons eingefügt werden THEN das System SHALL diese als Markdown-Badges oder Emoji-Icons formatieren
5. WHEN die README erstellt wird THEN das System SHALL die Icons konsistent und professionell anordnen