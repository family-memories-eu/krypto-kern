# Family Memories — Krypto-Kern zur Einsicht

*English below.*

Family Memories ist eine App, in der Familien Fotos, Videos, Sprachaufnahmen und Geschichten
sammeln. Die Inhalte werden **auf den Geräten der Familie** Ende-zu-Ende-verschlüsselt. Dieses
Repository zeigt den Teil des Codes, der das tut, damit ihr ihn lesen, prüfen und gegen unser
Whitepaper halten könnt.

**Das ist kein Open Source.** Der Code liegt zur Einsicht offen: lesen, ausführen und prüfen ja,
in eigenen Produkten verwenden oder weitergeben nein (`LICENSE`, PolyForm Strict 1.0.0). Für
Sicherheitsforschung erlaubt `LICENSE-ADDENDUM.md` zusätzlich, lokal zu ändern und Befunde mit
Code-Ausschnitten zu veröffentlichen.

## Was drin ist

| Pfad | Inhalt |
|---|---|
| `src/lib/e2e/` | der Krypto-Kern: Identitäten und Signaturen, Umschläge (HPKE), Familien- und Objektschlüssel, verschlüsselte Zeilen, Vertrauensspeicher und Sicherheitscodes, Wiederherstellungscode, Geräte-Speicher, Rotation (`keyRing.ts`, `vault.ts`) |
| `src/lib/crypto.ts`, `src/lib/videoCrypto.ts` | Verschlüsselung von Medien (AES-256-GCM, Videos in Blöcken) |
| `src/lib/native/deviceKey.ts`, `android/DeviceKeyPlugin.java` | der Geräteschlüssel im Android Keystore und seine Brücke in die App |
| `src/lib/mediaMime.ts`, `src/lib/clientApp/*.ts` | kleine Hilfsdateien, ohne die der Code nicht typgeprüft werden kann; `apiFetch.ts` zeigt, wie der Kern unsere API-Routen aufruft |
| `src/lib/e2e/*.test.ts` | die zehn Tests, die ohne Datenbank laufen |
| `MANIFEST.json` | aus welchem Commit der App dieser Stand stammt, und die SHA-256 jeder Datei |

Alle Dateien sind **byteidentisch** mit der App und liegen am selben Pfad (nur
`DeviceKeyPlugin.java` ist verlegt; das Manifest nennt den Originalpfad).

## Was fehlt — und warum

- **Die Datenbankregeln** (Zeilenrechte und Funktionen in den Migrationen) und die 24 Tests, die
  gegen eine Datenbank laufen. Sie hängen am ganzen Schema der App. Was die Datenbank prüft,
  beschreibt das Whitepaper (§8, §11).
- **Oberfläche, Server, Service Worker.** Sie verschlüsseln nichts selbst.
- **Ein Beweis, dass die Website genau diesen Code ausliefert.** Den gibt es bei keiner
  Web-App, die ihren Code bei jedem Aufruf neu lädt (Whitepaper §10.1). Die Android-App bringt
  ihren Code mit (§10.2). Reproduzierbare Builds sind geplant.

## Lesen

Am besten mit dem Whitepaper daneben: <https://family-memories.eu/de/sicherheit/whitepaper>
(englisch: <https://family-memories.eu/en/sicherheit/whitepaper>). Wo Kommentare
`docs/e2e-design.md` nennen, ist dieses Whitepaper gemeint; andere `docs/`-Verweise sind interne
Plandokumente und nicht veröffentlicht. Vorschlag für die Reihenfolge:

1. Whitepaper §2 (Bedrohungsmodell) und §3 (Schlüsselhierarchie)
2. `bytes.ts`, `identity.ts`, `hpke.ts`, `envelope.ts` — die Bausteine
3. `objectKey.ts`, `objBinding.ts`, `src/lib/crypto.ts`, `src/lib/videoCrypto.ts` — Medien
4. `rowCryptoV2.ts`, `rowVerify.ts`, `rowOpen.ts` — verschlüsselte und signierte Zeilen
5. `statements.ts`, `trustCodes.ts`, `trustStore.ts` — Vertrauen zwischen Geräten und Personen
6. `keyRing.ts`, `vault.ts` — wie alles zusammenspielt (Geräte, Mitglieder, Rotation, Rettung)

## Ausführen

Node.js 22 oder neuer:

```bash
npm ci
npm test
npm run typecheck
```

## Abgleich mit der Live-Seite

Die Build-ID der Website ist der Commit der App. Sie steht im HTML jeder Seite in den
eingebetteten Seitendaten (`"b":"<commit>"`), zum Beispiel:

```bash
curl -s https://family-memories.eu/de | grep -oE '[0-9a-f]{40}'
```

`MANIFEST.json` nennt den Commit, aus dem dieser Stand exportiert wurde. Die beiden müssen nicht
gleich sein: Ein neuer Stand entsteht nur, wenn sich eine dieser Dateien in der App ändert, und
dann vor dem nächsten Deploy. Jeder Stand trägt den Tag `app-<commit>`.

## Eine Schwachstelle gefunden?

Bitte zuerst melden: <https://family-memories.eu/de/sicherheit> oder
`security@family-memories.eu`. Eingangsbestätigung innerhalb von drei Werktagen, Offenlegung nach
der Behebung, längstens nach 90 Tagen. Issues und Pull Requests hier bitte **nicht** für
Schwachstellen verwenden.

---

# Family Memories — crypto core, source available for review

Family Memories is an app in which families collect photos, videos, voice recordings and stories.
The content is **end-to-end encrypted on the family's devices**. This repository shows the part
of the code that does this, so that you can read it, test it and hold it against our white paper.

**This is not open source.** The code is available for review: reading, running and testing yes;
using it in your own products or redistributing it no (`LICENSE`, PolyForm Strict 1.0.0). For
security research, `LICENSE-ADDENDUM.md` additionally allows local changes and publishing
findings with code excerpts.

**What is included:** the crypto core `src/lib/e2e/` (identities and signatures, HPKE envelopes,
family and object keys, encrypted rows, trust store and safety codes, recovery code, device
storage, rotation in `keyRing.ts` and `vault.ts`); media encryption (`src/lib/crypto.ts`,
`src/lib/videoCrypto.ts`); the device key in the Android Keystore
(`src/lib/native/deviceKey.ts`, `android/DeviceKeyPlugin.java`); small helpers needed for type
checking (`apiFetch.ts` shows how the core calls our API routes); the ten tests that run without a database; `MANIFEST.json` with the source commit
and the SHA-256 of every file. All files are **byte-identical** to the app and sit at the same
path (only `DeviceKeyPlugin.java` is moved; the manifest names its original path).

**What is missing:** the database rules (row-level security and functions in the migrations) and
the 24 tests that run against a database — they depend on the app's whole schema (white paper §8,
§11). The UI, server and service worker, which encrypt nothing themselves. And a proof that the
website serves exactly this code: no web app that loads its code on every visit can give one
(white paper §10.1). The Android app ships its code (§10.2). Reproducible builds are planned.

**Reading:** with the white paper alongside, <https://family-memories.eu/en/sicherheit/whitepaper>.
Where comments name `docs/e2e-design.md`, they mean this white paper; other `docs/` references
are internal planning documents and not published. Suggested order: §2 and §3 → `bytes.ts`, `identity.ts`, `hpke.ts`, `envelope.ts` → `objectKey.ts`,
`objBinding.ts`, `crypto.ts`, `videoCrypto.ts` → `rowCryptoV2.ts`, `rowVerify.ts`, `rowOpen.ts` →
`statements.ts`, `trustCodes.ts`, `trustStore.ts` → `keyRing.ts`, `vault.ts`.

**Running:** Node.js 22 or newer — `npm ci`, `npm test`, `npm run typecheck`.

**Matching the live site:** the website's build ID is the app commit. It appears in the HTML of
every page, in the embedded page data (`"b":"<commit>"`), e.g.
`curl -s https://family-memories.eu/de | grep -oE '[0-9a-f]{40}'`. `MANIFEST.json` names the commit
this snapshot was exported from. The two need not be equal: a new snapshot is only made when one of
these files changes in the app, and then before the next deploy. Every snapshot is tagged
`app-<commit>`.

**Found a vulnerability?** Please report it to us first: <https://family-memories.eu/en/sicherheit>
or `security@family-memories.eu`. Acknowledgement within three working days, disclosure after the
fix, at the latest after 90 days. Please do **not** use issues or pull requests for
vulnerabilities.
