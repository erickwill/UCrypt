# UCrypt — Benutzerhandbuch (Deutsch)

*Das Handbuch für alle. Wenn ein Schritt Sie einmal verwirrt, listet der
Fehlerbehebungs-Abschnitt am Ende jede Meldung, die UCrypt zeigen kann, und
was zu tun ist — nichts in diesem Handbuch endet in einer Sackgasse.*

> **Offizielle deutsche Ausgabe des UCrypt-Benutzerhandbuchs (Edition of
> Record).** Diese Fassung ist die vollständige deutsche Ausgabe und wird
> mit der englischen Ausgabe (`docs/USER-GUIDE.md`) synchron gehalten.
> Jeder in Anführungszeichen zitierte Oberflächentext ist der echte String
> aus der eigenen Sprachdatei von UCrypt (Sprachcode `de`,
> `_locales/de/messages.json`). Kurzformen in Klammern sind Erklärungen,
> keine Zitate.

---

## 1. Was UCrypt ist

UCrypt ist ein Passwort-Manager, der komplett in Ihrem Browser läuft.

- Ihre Passwörter liegen in einem **verschlüsselten Tresor** auf Ihrem Gerät.
- Ihre **Master-Passphrase** ist der einzige Schlüssel. Sie wird nirgendwohin
  gesendet — nicht einmal zu Ihrer Cloud.
- Wenn ein zweites Gerät den Tresor teilen soll, verknüpfen Sie beide Geräte
  mit einem **Sync-Code** (24 Wörter) und kopieren den verschlüsselten Tresor
  über **Ihren eigenen Cloud-Speicher** (Google Drive, Dropbox, GitHub Gist,
  WebDAV oder eine beliebige URL).
- Sie können eine Datei auch direkt an Ihr anderes Gerät senden — mit der
  **Direktübertragung**: Gerät zu Gerät, ohne Zwischenhändler.

> 🌟 Der eine Satz zum Merken: **UCrypt sieht Ihre Daten nie — nur Ihre
> Geräte sehen sie.**

---

## 2. Installation (aus dem Tarball)

1. Entpacken Sie `ucrypt-extension-v2.52.0.tar.gz` in einen Ordner, den Sie
   behalten (zum Beispiel `UCrypt/` in Ihren Dokumenten).
2. Öffnen Sie Chrome oder Chromium und rufen Sie `chrome://extensions` auf.
3. Schalten Sie den **Entwicklermodus** ein (Schalter oben rechts).
4. Klicken Sie auf **Load unpacked** (die Schaltfläche heißt je nach
   Browsersprache anders; gemeint ist: entpackte Erweiterung laden) und
   wählen Sie den entpackten Ordner.
5. Das UCrypt-Schild erscheint in Ihrer Symbolleiste. Klicken Sie auf das
   Nadel-Symbol, wenn es dort bleiben soll.

**Was Sie sehen werden:** das UCrypt-Popup öffnet sich mit
"Richten Sie Ihre Master-Passphrase ein".
**Wenn Sie nichts sehen:** prüfen Sie, ob Sie den Ordner gewählt haben, der
direkt die Datei `manifest.json` enthält — nicht den übergeordneten Ordner.

---

## 3. Den Tresor anlegen (das Master-Passwort)

1. Klicken Sie auf das UCrypt-Schild.
2. Tippen Sie eine Passphrase ein, die Sie sich merken können, die aber
   niemand erraten kann (mindestens 8 Zeichen).
3. Tippen Sie sie zur Bestätigung ein zweites Mal ein und drücken Sie dann
   auf "Tresor erstellen".

**Was Sie sehen werden:** das Popup wechselt zum Generator mit dem
freundlichen Hinweis "Klicken Sie auf Erzeugen ↓", und unten erscheint die
Schaltfläche "🔒 Jetzt sperren".

> ⚠️ **Die ehrliche Wahrheit:** wenn Sie das Master-Passwort vergessen,
> kann niemand Ihre Passwörter zurückholen — nicht UCrypt, nicht Ihr
> Cloud-Laufwerk, niemand. Schreiben Sie es auf und bewahren Sie es sicher
> auf. Das ist der Preis für echte Privatsphäre, und er ist es wert.

**Neu seit R97 — die Zwischenablage beim Sperren.** Wenn der Tresor sperrt,
leert UCrypt Geheimnisse aus der Zwischenablage, die UCrypt selbst dort
kopiert hat. Die Bestätigung ist diese Kurzmeldung:
"Zwischenablage geleert — der Tresor ist gesperrt."
Eine ehrliche Grenze: Haben Sie jedes UCrypt-Fenster geschlossen, bevor der
Tresor sperrt, kann UCrypt die Zwischenablage nicht mehr leeren.

---

## 4. Die Erste-Schritte-Checkliste

Öffnen Sie die **Einstellungen** (das ⚙ im Popup). Der Tresor-Tab zeigt die
Karte "Erste Schritte" mit 4 Schritten, jeder mit einer Schaltfläche
"Öffnen":

| Schritt | Was er macht |
|---|---|
| 1. Master-Passwort festlegen | Verschlüsselt den Tresor auf diesem Gerät |
| 2. 24-Wörter-Sync-Code erzeugen | Der EINZIGE Schlüssel, den andere Geräte brauchen |
| 3. Cloud-Laufwerk verbinden | Dort lebt das verschlüsselte Backup |
| 4. Erste Synchronisierung starten | Den verschlüsselten Tresor in Ihre Cloud schieben |

Machen Sie die Schritte der Reihe nach. Sie können einen Schritt
**Überspringen** und später nachholen — die Checkliste zählt ehrlich mit.

---

## 5. Ihr Sync-Code — ihn erstellen und Ihr Backup BEWEISEN

Der **Sync-Code** besteht aus 24 Wörtern. Er ist der eine Schlüssel, der
Ihre Geräte zu einer **Sync-Kette** verbindet.

1. Einstellungen → **Cloud-Sync** → "Neue Sync-Chain starten".
2. UCrypt zeigt die 24 Wörter. **Schreiben Sie sie auf Papier** (ja, echtes
   Papier) und bewahren Sie es sicher auf.
3. Klicken Sie zur Fertigstellung auf die Bestätigungsschaltfläche
   "Speichern & Sync aktivieren".

### Die Backup-Verifizierung (tun Sie das — sie dauert eine Minute)

Ein Backup, das Sie nie getestet haben, ist eine Hoffnung, kein Backup.
UCrypt lässt Sie BEWEISEN, dass Ihre Papierkopie funktioniert:

1. Klicken Sie auf "Backup verifizieren…" (im Sync-Tab).
2. Tippen Sie die Wörter, nach denen es fragt — genau so, wie sie auf Ihrem
   Papier stehen.
3. Warten Sie auf die grüne Zeile.

**Was Sie sehen werden:** "Backup verifiziert — deine Offline-Kopie passt zum gespeicherten Sync-Code."
**Wenn Sie sehen:** "Noch kein Treffer (Wort $WORDS$). Prüfe deine aufgeschriebene Kopie — der Status bleibt ehrlich, bis er verifiziert ist."
($WORDS$ ist die Nummer des Wortes) — vergleichen Sie dieses Wort mit Ihrer
Papierkopie und tippen Sie es neu. Der Status bleibt ehrlich (nicht
verifiziert), bis er wirklich verifiziert ist. Hier wird nichts vorgetäuscht.

Der Kettenstatus sagt immer die Wahrheit:

| Status | Bedeutung |
|---|---|
| "Sync-Code erstellt — Backup nicht verifiziert" | Die Kette funktioniert, aber testen Sie Ihre Papierkopie |
| "Backup verifiziert — Cloud-Kopie noch nicht bestätigt" | Papier ✓, Cloud noch nicht geschoben/gelesen |
| "Sync-Kette aktiv — verschlüsseltes Backup verifiziert" | Alles geprüft — entspannen |
| "Sync-Kette braucht Aufmerksamkeit — Hochladen blockiert, bis die Cloud-Kopie lesbar ist" | Lesen Sie die Meldung; meist ist es das Cloud-Laufwerk |

---

## 6. Ein Cloud-Laufwerk verbinden (dort lebt Ihr verschlüsseltes Backup)

Einstellungen → **Cloud-Sync** → klicken Sie auf eine Transport-Karte.
UCrypt unterstützt fünf. Der Tresor wird **verschlüsselt** hochgeladen —
Ihr Anbieter speichert nur eine versiegelte Datei, die er nicht lesen kann.

### WebDAV
Tragen Sie Server-URL, Benutzername und Passwort ein → drücken Sie auf
"Verbindung testen".
**Was Sie sehen werden:** "Server erreichbar" (mit grünem ✓)
→ drücken Sie auf "Transport speichern".

### Eigene URL
Jede HTTPS-URL, die wie ein Speicher-Endpunkt antwortet → "Verbindung testen" → "Server erreichbar" → "Transport speichern".

### Google Drive
Zwei Wege, beide privat für Sie:
- **Weg A — Ihre eigenen Google-Zugangsdaten:** erstellen Sie eine Client-ID
  und ein Client-Geheimnis in der Google Cloud Console, fügen Sie beide im
  Bereich Erweitert ein, drücken Sie auf Verbinden, melden Sie sich mit
  Ihrem Google-Konto an und wählen Sie die Drive-Dateiliste. Ihr Geheimnis
  wird versiegelt gespeichert — nur in Ihrem Tresor auf diesem Gerät.
- **Weg B — die Brücke:** richten Sie das kleine quelloffene Brücken-Skript
  ein (der Setup-Tab führt Sie mit einer Checkliste hindurch und korrigiert
  häufige Fehler von selbst), und verbinden Sie dann mit einem Klick.
**Was Sie sehen werden:** "Verbunden und erreichbar." und Ihre
Drive-Dateiliste auf der Karte.

### GitHub Gist
Fügen Sie ein GitHub-Token mit Gist-Berechtigung ein → "Verbindung testen"
→ "Server erreichbar" → "Transport speichern". Aus dem verschlüsselten
Tresor wird ein geheimer Gist, den nur Ihr Token lesen kann.

### Dropbox
Einmal verbinden; UCrypt speichert nur ein Refresh-Token, beschränkt auf
**seinen eigenen App-Ordner** — den Rest Ihrer Dropbox kann es nicht sehen.
**Was Sie sehen werden:** "Verbunden und erreichbar." plus den Ordnernamen.

> 🔒 **Das Geheimnis-Gesetz:** jedes Passwort, jeder Token und jedes
> Client-Geheimnis, das UCrypt speichert, ist mit Ihrem Tresor-Schlüssel
> versiegelt (verschlüsselt), lebt nur auf Ihrem Gerät, wird im Moment des
> Sperrens verworfen, vom **Trennen** (Disconnect) ausgelöscht und nie in
> einen Export aufgenommen.

---

## 6a. Die Anmelde-Leiter — ein Klick, wo Ihr Browser es erlaubt (neu in R119)

Jeder Cloud-Transport zeigt seine Anmeldung jetzt als kleine **Leiter mit
drei Sprossen**, von oben nach unten. Sie wählen die Sprosse, die zu
Ihnen passt — und keine Sprosse wird jemals weggenommen.

**Neu in R120:** die Anleitung zeichnet jeden Bildschirm für Sie —
bei jedem wichtigen Schritt sehen Sie eine kleine Zeichnung der
Konsole, mit dem Knopf, den Sie brauchen, in Farbe eingerahmt. So
prüfen Sie, was Sie sehen, bevor Sie klicken.

| Sprosse | Was es ist | Was Sie drücken |
|---|---|---|
| **Schnell** | Ein Klick, wo Ihr Browser es erlaubt. UCrypt borgt die Anmeldung Ihres Browsers — kein Schlüssel, kein Geheimnis, nichts zu kopieren oder zu speichern. | „Mit Google anmelden — ein Klick“ (nur sichtbar, wo Ihr Browser es wirklich kann) |
| **Geführt** | Ihr eigener Schlüssel, in wenigen Minuten, ein einziges Mal. Die eingebaute Anleitung zeigt jeden Klick. | die Schritte der Anleitung unten |
| **Manuell** | Die alten, verlässlichen Wege (die Brücke, eigene Zugangsdaten einfügen). | die Formulare, die Sie schon kennen |

Die Schnell-Sprosse erscheint **nur**, wo die automatische Erkennung
bestätigt, dass Ihr Browser es wirklich kann — in einem Browser, der es
nicht kann, wird sie einfach nicht angezeigt (nie eine tote
Schaltfläche). Die Geführt-Sprosse ist das Gesicht jeder Karte. Und
jeder Schnell-Knopf trägt den ehrlichen Satz: „Nutzt UCrypts gemeinsame
Anmeldung — falls sie jemals nicht geht, funktioniert Ihr eigener
Schlüssel (unten) immer.“

### Warum verlangt die Geführt-Sprosse meinen eigenen Schlüssel?

„Google verlangt Ihren eigenen Schlüssel, weil UCrypt keine Firma in der
Mitte ist — fünf Minuten, ein einziges Mal, und die Cloud gehört
nachweislich Ihnen.“

### Die Anleitung, Konsole für Konsole

**Google Drive (etwa 3 Minuten).**
1. Öffnen Sie `console.cloud.google.com` — die Anleitung trägt den
   Direktlink, einfach anklicken.
2. Console → **„Credentials“** → **„OAuth client“** → als Typ
   **„Chrome App“** wählen.
3. Fügen Sie die **Erweiterungs-ID** von UCrypt ein: öffnen Sie
   `chrome://extensions`, schalten Sie den **Entwicklermodus** ein und
   kopieren Sie die lange Buchstaben-Zahlen-Zeile unter UCrypt.
4. Der Bereich (Scope) bleibt auf `drive.file` festgelegt — die App darf
   nur Dateien berühren, die sie selbst erstellt hat. Es wird kein
   Geheimnis mit UCrypt oder irgendwem geteilt.
5. Zwei Google-Bildschirme sind bei der Anmeldung zu erwarten: die
   **Kontoauswahl**, dann der **Zustimmungs-Bildschirm** — drücken Sie
   auf **Allow** (Zulassen).
6. Solange der Client in **Testing** läuft, hören Anmeldungen nach 7
   Tagen auf. **Publish to production** (ein eigener Klick) nimmt diese
   Frist weg.

**GitHub (etwa 2 Minuten).**
1. Öffnen Sie `github.com/settings/developers` → **„OAuth Apps“** →
   **„New OAuth App“**.
2. Geben Sie ihm einen beliebigen Namen und registrieren Sie es.
3. Schalten Sie auf der Seite der App den Gerätefluss ein
   (**„Enable Device Flow“**) — das macht die 8-Zeichen-Codes-Anmeldung
   möglich: UCrypt zeigt den Code, Sie geben ihn auf
   `github.com/login/device` ein, autorisieren und kommen zurück. Drei
   Aktionen, insgesamt. Es existiert nie ein Geheimnis zum Speichern.

**Dropbox (etwa 5 Minuten).**
1. Öffnen Sie `dropbox.com/developers/apps` → **„Create app“**.
2. Wählen Sie **Scoped access** (die App-Ordner-Art passt — UCrypt sieht
   nur seinen eigenen Ordner).
3. Kopieren Sie den **App key** und fügen ihn in UCrypt ein. Mit
   **PKCE** ist das die ganze Geschichte — der App key ist öffentlich,
   eine Kennung und kein Geheimnis; es existiert nie ein Geheimnis zum
   Kopieren.

**Was Sie sehen werden:** jede Konsolen-Zeichenkette oben steht genau so,
wie die Konsole sie zeigt (die Konsolen gehören Google, GitHub und
Dropbox — ihre Menüs können in Ihrer Sprache erscheinen; die Namen
bleiben erkennbar).

### Die ehrliche Notiz zur Schnell-Sprosse

UCrypts gemeinsame Anmelde-Schlüssel kommen mit der Erweiterung selbst.
Bis sie in einer Version ankommen, wird die Schnell-Sprosse einfach
nicht angezeigt und die Geführt-Sprosse trägt jede Karte. Sobald sie da
sind: **ein Update, und die Ein-Klick-Sprossen leuchten von selbst** auf,
wo immer Ihr Browser es erlaubt — Sie müssen nichts nachholen.

---

## 7. Ihre erste Synchronisierung

1. Drücken Sie auf **Push** (oder auf "Jetzt synchronisieren") im Sync-Tab.
2. **Was Sie sehen werden:** eine Fortschrittszeile, dann einen ehrlichen
   Zeitstempel der letzten Synchronisierung und den Kettenstatus, der zu
   "Sync-Kette aktiv — verschlüsseltes Backup verifiziert" umspringt.
3. Konflikte? Haben beide Geräte getrennt voneinander etwas geändert,
   **führt UCrypt beide Seiten zusammen** und sagt Ihnen, was passiert ist.
   Es verwirft nie stillschweigend einen Eintrag.

---

## 8. Auf einem zweiten Gerät beitreten (QR, Wörter oder der vollständige Kopplungscode)

1. Installieren Sie UCrypt auf dem zweiten Gerät.
2. Auf Gerät 1: Sync-Tab → "Weiteres Gerät hinzufügen" → dann
   "Wörter & QR anzeigen" (zeigt die Sync-Code-Wörter und den QR).
3. Auf Gerät 2: Popup beim ersten Start → "Bestehender Sync-Chain beitreten"
   (oder Einstellungen → Cloud-Sync → "Bestehender Sync-Chain beitreten") →
   tippen Sie die 24 Wörter ein oder scannen Sie den QR.
   Sie können auch auf "Kopplungs-QR scannen" drücken (neu in R97) und ein
   Bild des QR einfügen (`Ctrl+V`) oder eine Screenshot-Datei wählen — der
   gelesene Code läuft durch dieselben Prüfungen wie ein getippter oder
   eingefügter. Gelingt das Lesen, sehen Sie:
   "Kopplungscode aus dem Bild gelesen — wird geprüft …"
4. Drücken Sie auf **Pull** ("Aus der Cloud abrufen"). Der Tresor kommt auf
   Gerät 2 an.

**Der vollständige Kopplungscode (v1.3):** auf dem Gerät-hinzufügen-Blatt
von Gerät 1 trägt der Code BEREITS die Cloud-Verbindungseinstellungen neben
den Wiederherstellungswörtern — Anbieter, Adresse und die öffentliche
Client-ID (nie ein Geheimnis). Drücken Sie auf "Pairing-Code kopieren" —
ein Code trägt die Wörter UND die Cloud-Einstellungen. Nur die
WebDAV-Anmeldung ist Opt-in: setzen Sie das Häkchen bei
"Die WebDAV-Anmeldung in diesen Code aufnehmen, damit sich das neue Gerät automatisch verbindet (Benutzername und Passwort)",
wenn sich das neue Gerät ohne Tippen verbinden soll. Auf Gerät 2 fügen Sie
diesen einen Code in das Beitritts-Feld ein: die Wörter landen von selbst,
und die geführte Einrichtung öffnet sich mit den bereits eingetragenen
Verbindungseinstellungen — drücken Sie Verbinden und melden Sie sich an.
Sie sehen
"Cloud eingerichtet: $NAME$ — bereit. Die Verbindungseinstellungen sind eingetragen; nur die Anmeldung fehlt noch."
Ein Einfügen, eine Anmeldung.

**Was Sie sehen werden:** Kettenstatus
"Sync-Kette aktiv — verschlüsseltes Backup verifiziert"
auf beiden Geräten nach einer Push/Pull-Runde.

> 💡 Bis zu 10 Geräte können eine Kette teilen. Eines zurückgelassen?
> Entfernen Sie es aus der Geräteliste — es bekommt einen Grabstein
> (Tombstone) und kann nie ungebeten zurückkehren.

## 8a. Der Sync-Beam — Beitritt ohne Cloud, Gerät zu Gerät (R98)

Sobald beide Geräte gleichzeitig offen sind, reist der Beitritt **direkt** —
der Sync-Beam. Die Cloud bleibt Ihr dauerhaftes Backup; der Beam ist der
schnelle Weg. Kein UCrypt-Server existiert in irgendeiner Rolle, niemals.

1. **Gerät 1 (das Ursprungsgerät):** Sync-Tab → **Gerät hinzufügen**. Der
   Kopplungsbogen öffnet sich und der Beam schaltet sich für 10 Minuten ein —
   eine ehrliche Zeile nennt das Fenster und erinnert daran, dass das
   Schließen des Bogens ihn ausschaltet.
2. **Gerät 2 (das beitretende Gerät):** Beitritt mit dem QR oder den 24
   Wörtern wie oben. Direkt nach dem Speichern der Wörter erscheint die
   Sync-Beam-Phase: sie zeigt den Geräte-Fingerabdruck und bittet das offene
   Gerät um Annahme.
3. **Gerät 1:** ein Dialog landet — der Name des beitretenden Geräts, der
   GLEICHE Fingerabdruck auf beiden Bildschirmen, die Anfragezeit. Vergleichen
   Sie die beiden Bildschirme und klicken Sie dann auf **Annehmen** (oder
   **Ablehnen** — das beitretende Gerät bekommt in beiden Fällen eine klare
   Antwort). Der Dialog verschwindet nie von selbst.
4. Annehmen zündet den Beam: Ihr verschlüsselter Tresor reist direkt zum
   neuen Gerät — mit Live-Fortschritt und SHA-256-Prüfung. Der Tresor des
   neuen Geräts ist sofort live.
5. **Der letzte Schritt ist benannt:** das beitretende Gerät sieht
   „verbinde denselben Cloud-Speicher“ mit Anbieter und Adresse des
   Ursprungsgeräts (niemals die Anmeldung) — ein Klick landet im
   Speicher-Raster. Ab dann ist die Cloud das Backup, und zwei offene
   Geräte können den Beam jederzeit wieder nutzen.

**Gar keine Cloud?** Der Beam funktioniert trotzdem: das Beitrittssignal
läuft über Kopieren/Einfügen (direkt in der Sync-Beam-Phase bereitgestellt)
und QR-zu-QR, wo verfügbar — eine Kette kann mit null Infrastruktur und
null Konten erstellt, betreten und synchronisiert werden.

> ⚠️ Die 20-MB-Beam-Grenze: ein größerer Tresor wird mit klarer Meldung
> abgelehnt und das beitretende Gerät auf den Cloud-Weg hingewiesen. Der
> Fingerabdruck ist die ehrliche Prüfung — stimmen die beiden Bildschirme
> je nicht überein, lehnen Sie ab.

### Tastenkürzel (die ehrliche Landkarte)

| Wo | Tasten | Was passiert |
|---|---|---|
| Beliebige Webseite | `Ctrl+Shift+L` | UCrypt öffnen und den Login für diese Seite füllen |
| Beliebige Webseite | `Ctrl+Shift+U` | Ein starkes Passwort in das fokussierte Passwortfeld vorschlagen |
| Popup — Erzeugen/Tresor/2FA/Check/Sync | `←` / `→` | Zwischen den Tabs wechseln |
| Popup — Listenzeilen | `Tab` + `Enter` | Die Zeilen durchgehen; Enter betätigt die fokussierte Schaltfläche |
| Popup — jede Zeile | `Esc` | Schließen, was UCrypt geöffnet hat (nichts schließt nach Ablauf einer Zeit von selbst) |
| Save-Bubble / Fill-Chip | `Esc` | Wegdrücken — Ihre Entscheidung, nie ein Auto-Ausblenden |
| Browser | `chrome://extensions/shortcuts` | Die Browser-Seite, auf der sich diese Tastenkürzel ändern lassen |

---

## 9. Direktübertragung — eine Datei von Gerät zu Gerät senden

Öffnen Sie die Übertragungsseite über den Sync/Share-Bereich des Popups
("Übertragungsfenster öffnen"). Zwei Modi:

### Modus 1 — durch die Kette (ein Klick)
1. **Empfänger:** klicken Sie auf "Empfangen" und schalten Sie dann die
   **Verfügbarkeit** ein (es erscheint "Verfügbar bis $TIME$" — die Uhrzeit,
   bis zu der Ihr Gerät sichtbar ist).
2. **Sender:** klicken Sie auf "Datei senden", wählen Sie eine Datei (in
   dieser Version bis 20 MB), wählen Sie das Gerät, senden.
3. Der Empfänger bekommt eine Karte: "Annehmen" oder "Ablehnen" — ohne ein
   menschliches Ja kommt nichts an.
4. Die Datei landet mit geprüftem SHA-256-Fingerabdruck. Wäre auch nur ein
   Bit anders, zerstört UCrypt die Kopie, statt sie zu speichern.

**Wie eine Übertragung enden kann (alle sechs, immer ehrlich gezeigt):**
zugestellt · vom Empfänger abgelehnt · abgebrochen (von Ihnen) ·
unterbrochen (die Verbindung riss ab — versuchen Sie es erneut, nichts wurde
halb gespeichert) · abgelaufen (das Angebot ist aus der Zeit — erneut
versuchen) · fehlgeschlagen (etwas ist gebrochen — die Meldung nennt es).

### Modus 2 — manuelle Signalisierung (ganz ohne Cloud)
Sind beide Geräte gleichzeitig offen, teilen aber keine Cloud: Die
Übertragungsseite zeigt "Notlösung — manuelle Signalisierung (Kopieren / Einfügen)".
Kopieren Sie das Signal von einem Gerät und fügen Sie es auf dem anderen
ein. Zwei Einfügungen insgesamt, dann läuft die Übertragung genau wie oben.

> ⚠️ Dateien über 20 MB werden mit einer klaren Meldung abgelehnt
> ("Diese Datei überschreitet das 20-MB-Standardlimit dieser Version."), und
> 0-Byte-Dateien bekommen "Diese Datei hat keinen Inhalt." Nichts
> Verwirrendes, nichts Stilles.

---

## 10. Auto-Ausfüllen — die zwei Modi

Einstellungen → **Sicherheit** → **Auto-Ausfüllen-Verhalten**:

- **Nachfrage-Modus** (Standard): "Nichts füllt sich von selbst. UCrypt zeigt das Konto-Dropdown und wartet jedes Mal auf Ihre ausdrückliche Auswahl. Passkey-Vorschläge bleiben ehrlich: UCrypt schlägt gespeicherte Zugangsdaten vor und füllt sie; es kann nicht der eingebaute Passkey-Authenticator Ihres Geräts sein."
- **Auto-Modus:** "Website-Passwort automatisch ausfüllen und sich anmelden oder verfügbare Passkeys vorschlagen."
  — für Menschen, die Tempo wollen.

**Einen Login speichern:** tippen Sie Ihre Zugangsdaten auf einer echten
Seite ein — UCrypt bietet eine Save-Bubble an. Klicken Sie sie an, prüfen
Sie, speichern Sie. Nichts wird ohne Ihren Klick gespeichert.

**Von Hand füllen:** Popup → den Eintrag der Seite öffnen →
"Auf dieser Seite ausfüllen".

---

## 11. Import & Export

Einstellungen → **Export / Import**:

- "Tresor exportieren (verschlüsselt)" — eine versiegelte Datei; sie lässt
  sich nur in UCrypt importieren und enthält nie Ihre Cloud-Freigaben oder
  Geheimnisse (das Geheimnis-Gesetz).
- "Entschlüsselte CSV exportieren…" — fragt zweimal nach (das ist
  Klartext!); kurz aufbewahren, dann schreddern.
- "Tresor importieren…" / CSV-Import — bringt Einträge mit einer Vorschau
  herein, bevor irgend etwas geschrieben wird.

---

## 12. Der 2FA-Authenticator (TOTP)

Der **2FA**-Tab des Popups ist ein echter Authenticator: fügen Sie die
`otpauth://`-URI ein, die Ihr Dienst zeigt (oder geben Sie das Geheimnis von
Hand ein), und er berechnet Live-Codes. Die Geheimnisse liegen verschlüsselt
im Tresor und synchronisieren mit ihm. Auf einer Login-Seite listet das
UCrypt-Dropdown zuerst die Tokens dieser Seite auf — klicken Sie eines an,
um das Bestätigungsfeld zu füllen.

**QR-Bild scannen (neu in R97):** statt die URI abzutippen drücken Sie im
Bereich "Token hinzufügen" auf die Schaltfläche
"QR-Bild scannen" und fügen ein Bild ein (`Ctrl+V`) oder wählen eine
Screenshot-Datei (der Dialog trägt den Titel "Einen QR-Code aus einem eingefügten Bild oder einer Datei lesen").
Der QR-Code wird auf
Ihrem Gerät gelesen — nichts wird hochgeladen — und die gelesene URI landet
im selben Einfüge-Feld, wo die Live-Vorschau den Code zeigt, bevor Sie
speichern. Nichts wird stillschweigend gespeichert: Sie sehen immer die
Live-Vorschau und drücken selbst auf Speichern. Die Bestätigung lautet:
"2FA-Code aus dem Bild gelesen — prüfe die Live-Vorschau und speichere dann."
Ein Bild, das kein 2FA-Code ist, wird mit einer Meldung abgelehnt, die Ihnen
sagt, wohin es gehört (ein Kopplungscode gehört in den Sync-Tab):
"Dieser QR-Code enthält einen Sync-Kopplungscode — benutze ihn im Sync-Tab, um einer Sync-Kette beizutreten."
Die übrigen möglichen Meldungen stehen im Fehlerbehebungs-Abschnitt
(Abschnitt 15).

---

## 13. Das Gesundheits-Panel (Check)

Popup → **Check**: ein Bericht über die Form Ihres Tresors —
wiederverwendete Passwörter, schwache Passphrasen, Einträge ohne
Benutzernamen. Jede Zeile nennt ihre Lösung. Den vollen Bericht öffnen Sie
im Tresor-Fenster ("Vollständigen Gesundheitsbericht öffnen").

Die Prüfung auf gehackten Passwörtern läuft komplett auf diesem Gerät gegen
eine mitgelieferte Liste der 10.001 am häufigsten geleakten Passwörter —
kein Netzwerk-Aufruf, keine Suche bei Dritten, Ihre Passwörter verlassen das
Gerät nie.

---

## 14. "Einrichtung prüfen" — ein Klick, sieben ehrliche Antworten

Einstellungen → **Sicherheit** → "Einrichtung prüfen". Die Prüfung ist
striktes Nur-Lesen (sie ändert nichts) und antwortet:

| Prüfung | Grün bedeutet |
|---|---|
| Cloud-Transport erreichbar | Ihr Laufwerk antwortet |
| Einer Sync-Kette beigetreten | Dieses Gerät hat einen Sync-Code |
| Sync-Code-Backup verifiziert | Ihre Papierkopie wurde bewiesen |
| Erfassungs-Pipeline scharf | Die Maschinerie für Speicher-Aufforderungen ist bereit |
| Toolbar-Badge berechnet | Das Badge folgt dem Gesetz |
| Speicher innerhalb seiner Grenzen | Keine Struktur ist aus den Grenzen gewachsen |
| Freigaben und Geheimnisse versiegelt | Jede gespeicherte Berechtigung ist versiegelt |

Eine rote Zeile nennt ihre Lösung in einem Satz. Das ist das Gesetz.

---

## 15. Fehlerbehebung — jede Meldung, indexiert

Die Meldungen stehen hier mit dem, was zu tun ist. Wiederholt sich eine
Meldung und die Lösung hilft nicht, drücken Sie zuerst auf
"Verbindung testen" auf Ihrer Transport-Karte — sie nennt in den meisten
Fällen das genaue Problem.

### Tresor & Sperre
| Meldung | Was zu tun ist |
|---|---|
| "Tresor gesperrt — entsperren, um Direktübertragung zu nutzen." | Entsperren Sie zuerst den Tresor. |
| "Tresor ist gesperrt — entsperren, um den Sicherheitsbericht zu erstellen." | Entsperren, dann den Check erneut öffnen. |

### Sync-Code & Kette
| Meldung | Was zu tun ist |
|---|---|
| "Noch keine Sync-Kette" / "Keine Synchronisationskette auf diesem Gerät — zuerst eine Kette erstellen oder ihr beitreten." | Eine Kette erstellen (Einstellungen → Cloud-Sync) oder auf Ihrem anderen Gerät einer Kette beitreten. |
| "Noch kein Treffer (Wort $WORDS$). Prüfe deine aufgeschriebene Kopie — der Status bleibt ehrlich, bis er verifiziert ist." | Vergleichen Sie dieses Wort mit Ihrer Papierkopie; tippen Sie es erneut. |
| "Sync-Code erstellt — Backup nicht verifiziert" | Führen Sie die Backup-Verifizierung durch (Abschnitt 5). |
| "Sync-Kette braucht Aufmerksamkeit — Hochladen blockiert, bis die Cloud-Kopie lesbar ist" | Öffnen Sie die Transport-Karte und drücken Sie auf "Verbindung testen". |

### Cloud-Transporte
| Meldung | Was zu tun ist |
|---|---|
| "Verbindung fehlgeschlagen — URL, Benutzer und Passwort prüfen, dann erneut Testen drücken." | URL/Benutzer/Passwort prüfen; bei Drive die Checklisten-Zeile auf der Setup-Karte suchen, die nicht grün ist. |
| "Der Cloud-Transport antwortet nicht — öffne den Sync-Tab, drücke Testen auf deiner Transport-Karte und folge der genannten Lösung." | Die Lösung der Selbstprüfung; Testen auf der Transport-Karte ausführen. |
| "Kein Cloud-Transport eingerichtet — Cloud-Sync ist optional; richte ihn im Sync-Tab ein, wenn du ihn willst." | Nur eine Information — Cloud-Sync ist von Entwurf wegen optional. |

### Direktübertragung
| Meldung | Was zu tun ist |
|---|---|
| "Diese Datei überschreitet das 20-MB-Standardlimit dieser Version." | Wählen Sie eine kleinere Datei. |
| "Diese Datei hat keinen Inhalt." | Die Datei ist leer; wählen Sie eine echte Datei. |
| "Es konnte keine direkte Verbindung hergestellt werden — die Übertragung wurde sicher beendet. Versuchen Sie es erneut." | Legen Sie beide Geräte ins selbe Netzwerk und versuchen Sie es erneut; der manuelle Signalisierungs-Modus funktioniert auch. |
| "Die Übertragung hat beim Warten auf das andere Gerät das Zeitlimit überschritten — es ist kein Schaden entstanden. Versuchen Sie es erneut." | Beide Seiten müssen offen sein; es erneut versuchen. |
| "Das andere Gerät hat die Übertragung abgelehnt." | Der Empfänger hat auf Ablehnen gedrückt — nichts wurde gesendet. |
| "Auf diesem Gerät ist bereits eine Übertragung aktiv — beenden oder brechen Sie diese zuerst ab." | Die laufende Übertragung beenden oder abbrechen. |
| "Dieses Signal ist verfallen, bevor es benutzt wurde — drücke auf dem anderen Gerät Neu erzeugen, oder füge ein frisches Signal ein." | Signale gelten nur einmal. Auf dem sendenden Gerät „Neu erzeugen“ für ein frisches Signal drücken; hier ein frisches einfügen. |
| "Der SHA-256-Digest stimmt nicht mit dem Angebot überein — nichts wurde gespeichert." | Netzwerk-Korruption wurde abgefangen; einfach erneut versuchen — die Sicherheit hat funktioniert. |
| "Zurzeit ist kein gekoppeltes Gerät verfügbar — die Sichtbarkeits-Checkliste oben nennt den fehlenden Schritt." | Sichtbarkeits-Checkliste im Übertragungsfenster öffnen; Verfügbarkeit einschalten, wenn diese Zeile ✗ zeigt. |
| "Der Transfer-Treffpunkt auf deiner Cloud antwortet gerade nicht (der Treffpunkt-Check ist eben fehlgeschlagen) — der manuelle Weg unten ist die Straße: einmal kopieren, einmal einfügen. UCrypt wiederholt den Cloud-Weg automatisch." | Die manuelle Route im Übertragungsfenster nutzen (Abschnitt 9, Modus 2): eigenes Signal kopieren, deren Signal einfügen, das eigene zurück auf das andere Gerät — oder warten; der Cloud-Weg wiederholt sich selbst. |
| "Der Rendezvous-Speicher ist nicht erreichbar — Cloud-Transport prüfen oder unten manuelles Kopieren/Einfügen nutzen." | Den Transport testen oder in den manuellen Modus wechseln. |
| "Das andere Gerät ist auf dieser Kette noch unbekannt — ein Präsenz-Erstkontakt ist erforderlich." | Die Geräteliste auf beiden Seiten einmal aktualisieren. |

### Sync-Engine
| Meldung | Was zu tun ist |
|---|---|
| Upload blockiert / "412"-artige Meldungen | Ein anderes Gerät hat die Cloud-Kopie geändert; UCrypt führt automatisch zusammen — wenn gefragt, auf **Jetzt synchronisieren** drücken. |
| "Die Badge-Entscheidung ist regelwidrig — einmal sperren und entsperren; besteht es fort, melde es über das Abnahmeprotokoll." | Einmal sperren und entsperren; das Badge rechnet neu. |
| "Eine gespeicherte Berechtigung ist NICHT versiegelt — Tresor einmal sperren und entsperren (die Migration versiegelt sie), dann erneut prüfen." | Einmal sperren + entsperren; die Prüfung wird grün. |

### QR-Scan (neu in R97)
| Meldung | Was zu tun ist |
|---|---|
| "Kein QR-Code in diesem Bild gefunden. Nimm die PNG-Datei vom „QR herunterladen“-Knopf des anderen Geräts (ucrypt-pairing-….png) — mit weißem Rand, keine Screenshots oder neu gespeicherten Bilder — oder füge die 24 Wörter unten ein." | Die Original-PNG verwenden (keinen Screenshot) oder die 24 Wörter als Text einfügen — beide Wege landen im selben Beitritt. |
| "Das Bild ist zu groß — das Limit ist 8 MB." | Das Bild verkleinern oder nur einen Ausschnitt scannen, dann erneut. |
| "Dieser Eintrag in der Zwischenablage ist kein Bild." | Einen Bildausschnitt kopieren (`Ctrl+V`) oder eine Datei wählen — kein Text. |
| "Dieses Bild konnte nicht gelesen werden — versuche PNG oder JPEG." | Das Bild als PNG oder JPEG speichern und erneut einfügen. |
| "Dieser QR-Code ist kein 2FA-Code (keine otpauth://-Daten)." | In dem Bild steckt kein Authenticator-Schlüssel; den richtigen QR suchen. |
| "Dieser QR-Code ist kein UCrypt-Kopplungscode." | Das ist kein UCrypt-Beitritts-QR. |
| "Dieser QR-Code enthält einen Sync-Kopplungscode — benutze ihn im Sync-Tab, um einer Sync-Kette beizutreten." | Der QR gehört in den Sync-Tab (einer Kette beitreten), nicht in den 2FA-Tab. |
| "Dieser QR-Code enthält einen 2FA-Code — scanne ihn im 2FA-Tab des Popups." | Der QR gehört in den 2FA-Tab des Popups, nicht in den Sync-Tab. |

**Immer noch festgehangen?** Führen Sie "Einrichtung prüfen" aus
(Abschnitt 14) — seine sieben Antworten zeigen den kaputten Teil genau, und
jede rote Zeile nennt ihre Lösung.

---

*UCrypt v2.52.0 — gebaut mit Liebe, die Menschen lieben werden. Alles in
diesem Handbuch ist an echtes Produktverhalten angebunden; nichts ist
Wunschdenken.*

## 9a. Direktfreigabe — eine Datei an jeden UCrypt-Nutzer, keine Kette nötig

Der Übertragungs-Tab in den Einstellungen trägt einen zweiten Handschlag
neben der Geräte-Übertragung: **"Datei teilen"** (Senden) und
**"Hast du einen Freigabecode?"** (Empfangen). Keine Kette, keine Cloud,
kein Konto — auf keiner der beiden Seiten. Die Einladung reist über einen
beliebigen Messenger; die Sicherheit bleibt in der Kryptografie.

### Senden (fünf Aktionen)
1. **"Datei wählen…"** — bis 20 MB ("Diese Datei liegt über dem
   Direktfreigabe-Limit von 20 MB — wähle eine kleinere Datei.", wenn sie
   größer ist).
2. Optional eine Notiz. Die Warnung ist Teil des Designs: "Diese Notiz ist
   für den Messenger lesbar, über den du sie sendest."
3. **"Einladung erstellen"** — eine Zeichenkette, die mit "UCRYPT-SHARE1:"
   beginnt, erscheint mit sichtbarem Countdown ("Läuft ab in $M$:$SS$",
   zehn Minuten) und einem Abbrechen, der sie sofort killt.
4. Schicke die Einladung über einen beliebigen Messenger
   ("Deine Einladung — schicke sie über einen beliebigen Messenger:").
   Trifft die Antwort ein, einfügen und **"Antwort verbinden"** drücken.
5. Die Datei überträgt erst, wenn der Empfänger zweimal zusagt.

### Empfangen (fünf Aktionen)
1. Die Einladung unter **"Hast du einen Freigabecode?"** einfügen (oder
   den QR scannen — der Persönlich-Modus zeigt bis zu acht Frames, scanne
   sie der Reihe nach).
2. Tür 1 fragt: "Jemand mit UCrypt möchte eine Datei mit dir teilen."
   **"Antworten & ansehen"** erzeugt deine Antwort (bereits kopiert) —
   schicke sie im selben Messenger zurück. **"Ablehnen"** sendet nichts.
3. Tür 2 zeigt die Datei: von wem, Name, Größe — und die
   **"Sicherheitswörter: $WORDS$"**: vier Wörter, die auf BEIDEN
   Bildschirmen gleich sein müssen. Im selben Raum: laut vorlesen.
4. **"Annehmen & empfangen"** — dann läuft der Empfang, und der
   SHA-256-Fingerabdruck wird gezeigt, bevor du speicherst.
5. Speichern behält die Datei; nichts anderes wird irgendwo geschrieben.

Freigaben gehen **eins nach dem anderen**: während eine Freigabe läuft,
wartet eine weitere Einladung — beende oder lehne die erste ab, und die Tür
öffnet von selbst wieder. Scheitert die direkte Verbindung, versucht UCrypt
einen Neustart und sagt es dann ehrlich: "gleiches Netzwerk versuchen —
oder persönlich mit den QRs."

**Bis zu fünf Dateien auf einmal.** Der Absender wählt bis zu fünf Dateien
(20 MB je, 50 MB zusammen) und EINE Einladung deckt sie alle — ein Code,
ein Handschlag, eine Annahme. Tür 2 listet jede Datei, bevor du annimmst,
und der Fortschritt nennt die Datei, die gerade läuft („Datei 2 von 5 wird
empfangen… 40%“). Der Fingerabdruck jeder Datei wird geprüft, sobald sie
ankommt, und die Liste „Geteilte Dateien“ zeichnet jede auf. Stirbt die
Verbindung auf halbem Weg, bleibt, was heil ankam, und die Wahrheit wird
klar gesagt: „Unterbrochen — 2 von 5 Dateien kamen heil an; der Rest kam
nie. Die Schlüssel sind vernichtet.“ Nichts Halbes wird je als Ganzes
ausgegeben.


### Die Abholung — wenn der Freund offline ist (opt-in, ein Klick)

Bleibt die Antwort aus und die Einladung läuft bald ab (ihre letzten drei
Minuten), bietet die Karte des Senders **"Zur Abholung in deiner Cloud
bereithalten"** an. Nimm sie an, wähle, wie lange die Abholung gültig
bleibt (1 Stunde, 24 Stunden oder 7 Tage — standardmäßig 24 Stunden), und
UCrypt versiegelt die Datei mit einem frischen 8-Wort-Code und lädt den
versiegelten Blob in DEINE EIGENE Cloud hoch (Google Drive, Dropbox oder
GitHub — WebDAV und Eigene URL können ehrlicherweise keine Abholung
bereithalten; die Live-Übertragung funktioniert, wenn beide online sind).
Du erhältst EINE einfügbare Notiz — "UCRYPT-PICKUP1:" + Link + Code — für
denselben Messenger. Deine Cloud sieht nur Chiffretext unter einem
neutralen Namen; der Messenger sieht nur Link und Code; niemand sieht den
Dateinamen, bevor nicht entschlüsselt wurde. Der Empfänger fügt die Notiz
unter **"Hast du einen Freigabecode?"** ein — UCrypt erkennt sie, lädt
OHNE Konto herunter, entschlüsselt mit dem Code, zeigt die Datei und
speichert sie nach einem Klick. Die Abholung tritt deiner Kette nie bei,
stirbt, sobald die Datei gespeichert ist, und du kannst sie jederzeit
beenden — die Datei verlässt deine Cloud sofort. Läuft eine Abholung ab,
sagen es beide Seiten ehrlich: "Diese Abholung ist abgelaufen — bitte um
eine neue Übertragung."

### Die ehrlichen Enden
- "Anfrage abgelaufen — keine Antwort oder abgelehnt." — der Sender kann
  nie wissen, welches davon geschah; das ist der Punkt.
- "Diese Einladung wurde bereits benutzt — Freigabecodes gelten genau
  einmal."
- Die vier Sicherheitswörter unterscheiden sich → nichts wurde empfangen;
  der Antwortcode wurde verändert oder beschädigt.

### Die Liste „Geteilte Dateien“ (die EINE Historie einer Freigabe)

Im Tab **Dateiübertragung** bewahrt die Karte **„Geteilte Dateien“** den
einzigen Eintrag, den Direktfreigabe jemals schreibt: Dateiname, Größe,
Zeitpunkt und ob sie gesendet (↑) oder empfangen (↓) wurde. Eine Person
steht nicht daran — der Handshake war anonym by design, die Liste hat
nichts zu vermerken. Die Liste lebt nur auf diesem Gerät (ein eigener,
abgeschotteter Speicherplatz — Tresor, Cloud-Kopie und jeder Export/
Backup überspringen sie), fasst höchstens die letzten 30 Zeilen, und
ältere Zeilen fallen von selbst heraus. Vor der ersten Freigabe steht
genau das: „Noch nichts geteilt — Freigaben hinterlassen keine Spur,
außer in dieser Liste.“

> ⚠️ Die flüchtigen Schlüssel sterben mit dem Ende der Übertragung: nach
> einer Freigabe kann keine Seite jemandem beweisen, was gesendet wurde —
> oder dass überhaupt etwas war.
