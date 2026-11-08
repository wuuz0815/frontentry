// =============================================================================
// Datei:    app.js
// Zweck:    Tor-Steuerung für Shelly 1 Gen3 per Bluetooth (Web Bluetooth, RPC über BLE)
// Autor:    Stefan Weinzetl
// Hinweis:  Sendet einen Impuls (Relais ein, nach X Sekunden automatisch aus).
//           Unterstützt die Digest-Authentifizierung (SHA-256) des Shelly.
// =============================================================================
"use strict";

const APP_VERSION = "1.1.1";

// ---------------------------------------------------------------------------
// Konfiguration
// ---------------------------------------------------------------------------
const KONFIG = {
  namensPraefixe: ["Shelly", "shelly"], // Filter im Bluetooth-Auswahldialog
  schalterId: 0,                         // Relais-Kanal des Shelly 1 Gen3
  impulsSekunden: 1,                     // Relais fällt nach dieser Zeit selbst ab
  benutzer: "admin",                     // Shelly-Benutzername ist fix
  zeitlimitMs: 8000,                     // Zeitlimit je Verbindungsschritt
  verbindungsVersuche: 4,                // Wiederholungen bei Android-GATT-Fehler (Status 133)
  pauseZwischenVersuchenMs: 700,         // Wartezeit vor jedem weiteren Versuch (wächst linear)
  blockGroesse: 20,                      // kleinste Blockgröße (Rückfall)
  blockGross: 20,                        // 180 Byte scheiterte unter Android 10 („invalid attribute length“)
  txWiederholungen: 4,                   // Längenangabe in derselben Verbindung erneut senden
  txPauseMs: 150,                        // Wartezeit, bis die Verschlüsselung steht
  pauseNachLaengeMs: 50,                 // Pause zwischen Längenangabe und Daten (Shelly-Empfehlung)
  pauseNachVerbindungMs: 300,
  werbungWartenMs: 4000,                 // max. Wartezeit auf ein Lebenszeichen des gemerkten Geräts            // Android braucht nach dem Verbinden kurz Zeit für die Dienstsuche
  quelle: "tor-app",                     // Absenderkennung im RPC-Aufruf
};

// GATT-UUIDs des Shelly-RPC-Dienstes
const UUID = {
  dienst:      "5f6d4f53-5f52-5043-5f53-56435f49445f",
  daten:       "5f6d4f53-5f52-5043-5f64-6174615f5f5f",
  txSteuerung: "5f6d4f53-5f52-5043-5f74-785f63746c5f",
  rxSteuerung: "5f6d4f53-5f52-5043-5f72-785f63746c5f",
};

const SPEICHER_ZUGANG = "tor_zugang_v1";  // { realm, ha1 } – nie das Klartext-Passwort
const SPEICHER_GERAET = "tor_geraet_v1";  // ID des gewählten Bluetooth-Geräts

// ---------------------------------------------------------------------------
// Logging (Format analog Python: "%(asctime)s [%(levelname)s] %(message)s")
// Nur im Arbeitsspeicher, max. 200 Zeilen, keine Geheimnisse.
// ---------------------------------------------------------------------------
const logPuffer = [];
let kleineBloecke = false; // wird gesetzt, wenn der Shelly große Blöcke ablehnt
let debugModus = false;

function zeitstempel() {
  const d = new Date();
  const p = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${p(d.getMonth() + 1)}-${p(d.getDate())} ` +
         `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}`;
}

function log(stufe, nachricht) {
  if (stufe === "DEBUG" && !debugModus) return;
  const zeile = `${zeitstempel()} [${stufe}] ${nachricht}`;
  logPuffer.push(zeile);
  if (logPuffer.length > 200) logPuffer.shift();
  const ausgabe = stufe === "ERROR" ? console.error : stufe === "WARNING" ? console.warn : console.log;
  ausgabe(zeile);
  if (typeof document !== "undefined") {
    const el = document.getElementById("log");
    if (el) el.textContent = logPuffer.join("\n");
  }
}

// ---------------------------------------------------------------------------
// Hilfsfunktionen
// ---------------------------------------------------------------------------
const warten = (ms) => new Promise((r) => setTimeout(r, ms));

function mitZeitlimit(versprechen, ms, beschreibung) {
  let zeitgeber;
  const ablauf = new Promise((_, ablehnen) => {
    zeitgeber = setTimeout(() => ablehnen(new Error(`Zeitüberschreitung: ${beschreibung}`)), ms);
  });
  return Promise.race([versprechen, ablauf]).finally(() => clearTimeout(zeitgeber));
}

async function sha256Hex(text) {
  const hash = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(hash)].map((b) => b.toString(16).padStart(2, "0")).join("");
}

// ---------------------------------------------------------------------------
// Speicher (Browser-Speicher der PWA, Fehler werden abgefangen)
// Rückgabe der Schreibfunktionen: [erfolg, meldung]
// ---------------------------------------------------------------------------
function speicherLesen(schluessel) {
  try {
    const roh = localStorage.getItem(schluessel);
    return roh ? JSON.parse(roh) : null;
  } catch (e) {
    log("WARNING", `Speicher nicht lesbar (${schluessel})`);
    return null;
  }
}

function speicherSchreiben(schluessel, wert) {
  try {
    localStorage.setItem(schluessel, JSON.stringify(wert));
    return [true, "Gespeichert"];
  } catch (e) {
    return [false, "Speichern im Browser nicht möglich"];
  }
}

function speicherLoeschen(schluessel) {
  try {
    localStorage.removeItem(schluessel);
    return [true, "Gelöscht"];
  } catch (e) {
    return [false, "Löschen im Browser nicht möglich"];
  }
}

// ---------------------------------------------------------------------------
// RPC über BLE (Rahmen: Länge an tx_ctl, Daten an data, Antwortlänge aus rx_ctl)
// ---------------------------------------------------------------------------
class ShellyBleRpc {
  constructor(geraet) {
    this.geraet = geraet;
    this.zeichen = {};
    this.naechsteId = 1;
    this.datenBegonnen = false;
    this.schritt = "Verbindungsaufbau"; // für verständliche Fehlermeldungen
  }

  async verbinden() {
    this.schritt = "Verbindungsaufbau";
    const server = await mitZeitlimit(this.geraet.gatt.connect(), KONFIG.zeitlimitMs, "Verbindungsaufbau");
    await warten(KONFIG.pauseNachVerbindungMs);
    this.schritt = "Dienstsuche";
    const dienst = await mitZeitlimit(server.getPrimaryService(UUID.dienst), KONFIG.zeitlimitMs, "RPC-Dienst");
    this.zeichen.daten = await dienst.getCharacteristic(UUID.daten);
    this.zeichen.tx = await dienst.getCharacteristic(UUID.txSteuerung);
    this.zeichen.rx = await dienst.getCharacteristic(UUID.rxSteuerung);
    log("DEBUG", "GATT-Verbindung und RPC-Dienst bereit");
  }

  trennen() {
    // Immer trennen, auch wenn Chrome die Verbindung schon als getrennt meldet:
    // gibt halb aufgebaute Verbindungen frei, die sonst weitere Versuche blockieren.
    try {
      if (this.geraet && this.geraet.gatt) {
        this.geraet.gatt.disconnect();
        log("DEBUG", "Bluetooth-Verbindung freigegeben");
      }
    } catch (e) {
      log("DEBUG", `Trennen fehlgeschlagen: ${e.message}`);
    }
  }

  async rahmenSenden(objekt) {
    const bytes = new TextEncoder().encode(JSON.stringify(objekt));
    const laenge = new Uint8Array(4);
    new DataView(laenge.buffer).setUint32(0, bytes.length, false);
    // Längenangabe: wird direkt nach dem Verbinden gelegentlich abgelehnt, solange die
    // Verschlüsselung noch aufgebaut wird. Erneutes Senden ist gefahrlos.
    for (let versuch = 1; ; versuch++) {
      this.schritt = `Längenangabe (${bytes.length} Byte angekündigt, Anlauf ${versuch})`;
      try {
        await this.zeichen.tx.writeValueWithResponse(laenge);
        if (versuch > 1) log("DEBUG", `Längenangabe im ${versuch}. Anlauf angenommen`);
        break;
      } catch (e) {
        if (versuch >= KONFIG.txWiederholungen || !this.geraet.gatt.connected) throw e;
        log("DEBUG", `Längenangabe abgelehnt (${e.message}), neuer Anlauf in derselben Verbindung`);
        await warten(KONFIG.txPauseMs * versuch);
      }
    }
    await warten(KONFIG.pauseNachLaengeMs);
    const block = kleineBloecke ? KONFIG.blockGroesse : KONFIG.blockGross;
    let bloecke = 0;
    for (let i = 0; i < bytes.length; i += block) {
      const ende = Math.min(i + block, bytes.length);
      // Erst vor dem letzten Block kann der Shelly ausführen: ab hier keine automatische
      // Wiederholung mehr, sonst droht ein zweiter Impuls (Tor stoppt oder fährt zurück).
      if (ende === bytes.length) this.datenBegonnen = true;
      this.schritt = `Datenblock ${bloecke + 1}/${Math.ceil(bytes.length / block)} (${ende - i} Byte)`;
      try {
        await this.zeichen.daten.writeValueWithResponse(bytes.slice(i, ende));
      } catch (e) {
        // Verbindung steht noch = Shelly hat den Block abgelehnt, also nichts ausgeführt.
        // Dann ist eine Wiederholung gefahrlos.
        if (this.geraet.gatt.connected) this.datenBegonnen = false;
        if (block > KONFIG.blockGroesse && !kleineBloecke) {
          kleineBloecke = true;
          log("WARNING", `Große Datenblöcke abgelehnt, ab jetzt ${KONFIG.blockGroesse}-Byte-Blöcke`);
        }
        throw e;
      }
      bloecke++;
    }
    log("DEBUG", `Rahmen gesendet (${bytes.length} Byte in ${bloecke} Block/Blöcken)`);
  }

  async rahmenEmpfangen() {
    this.schritt = "Antwortlänge lesen";
    const start = Date.now();
    let laenge = 0;
    while (Date.now() - start < KONFIG.zeitlimitMs) {
      const wert = await this.zeichen.rx.readValue();
      laenge = wert.byteLength >= 4 ? wert.getUint32(0, false) : 0;
      if (laenge > 0) break;
      await warten(50);
    }
    if (!laenge) throw new Error("Keine Antwort vom Shelly");

    const teile = [];
    let empfangen = 0;
    this.schritt = "Antwort lesen";
    while (empfangen < laenge) {
      const wert = await this.zeichen.daten.readValue();
      const teil = new Uint8Array(wert.buffer, wert.byteOffset, wert.byteLength).slice();
      if (teil.length === 0) throw new Error("Unvollständige Antwort vom Shelly");
      teile.push(teil);
      empfangen += teil.length;
    }
    const gesamt = new Uint8Array(empfangen);
    let pos = 0;
    for (const t of teile) { gesamt.set(t, pos); pos += t.length; }
    log("DEBUG", `Antwort empfangen (${empfangen} Byte)`);
    return JSON.parse(new TextDecoder().decode(gesamt));
  }

  async aufrufen(methode, params, auth) {
    const anfrage = { id: this.naechsteId++, src: KONFIG.quelle, method: methode, params };
    if (auth) anfrage.auth = auth;
    await this.rahmenSenden(anfrage);
    return await this.rahmenEmpfangen();
  }
}

// ---------------------------------------------------------------------------
// Digest-Authentifizierung (Shelly Gen2+, SHA-256)
// ---------------------------------------------------------------------------
async function ha1Berechnen(realm, passwort) {
  return sha256Hex(`${KONFIG.benutzer}:${realm}:${passwort}`);
}

async function authObjektErstellen(herausforderung, ha1) {
  const zufall = new Uint32Array(1);
  crypto.getRandomValues(zufall);
  const cnonce = zufall[0];
  const nc = herausforderung.nc ?? 1;
  const ha2 = await sha256Hex("dummy_method:dummy_uri");
  const antwort = await sha256Hex(`${ha1}:${herausforderung.nonce}:${nc}:${cnonce}:auth:${ha2}`);
  return {
    realm: herausforderung.realm,
    username: KONFIG.benutzer,
    nonce: herausforderung.nonce,
    cnonce,
    response: antwort,
    algorithm: "SHA-256",
  };
}

function herausforderungLesen(antwort) {
  if (!antwort || !antwort.error || antwort.error.code !== 401) return null;
  try {
    return JSON.parse(antwort.error.message);
  } catch (e) {
    throw new Error("Authentifizierungsanfrage des Shelly nicht lesbar");
  }
}

// ---------------------------------------------------------------------------
// Ablaufsteuerung (GUI-frei, Rückmeldung über Callback)
// ---------------------------------------------------------------------------
let gemerktesGeraet = null;
let auswahlErzwingen = false;
let einrichtungsPasswort = null; // nur im Arbeitsspeicher, wird nach Erfolg verworfen

/**
 * Prüft, ob Chrome sich freigegebene Geräte merken kann (Funktion getDevices).
 * @returns {[boolean, string]}
 */
function geraetMerkenVerfuegbar() {
  if (navigator.bluetooth && typeof navigator.bluetooth.getDevices === "function") {
    return [true, "Chrome merkt sich das Gerät, kein Auswahldialog nötig"];
  }
  return [false, "Chrome kann sich das Gerät nicht merken. Flag 'enable-web-bluetooth-new-permissions-backend' aktivieren"];
}

/**
 * Wartet, bis das gemerkte Gerät in Reichweite funkt. Chrome braucht dieses
 * Lebenszeichen, bevor es ein Gerät ohne Auswahldialog verbinden kann.
 */
async function aufWerbungWarten(geraet) {
  if (typeof geraet.watchAdvertisements !== "function") {
    log("DEBUG", "watchAdvertisements nicht verfügbar, verbinde direkt");
    return [true, "übersprungen"];
  }
  const abbruch = new AbortController();
  try {
    const empfangen = new Promise((erfuellen) => {
      geraet.addEventListener("advertisementreceived", () => erfuellen(true), { once: true });
    });
    await geraet.watchAdvertisements({ signal: abbruch.signal });
    const ergebnis = await Promise.race([empfangen, warten(KONFIG.werbungWartenMs).then(() => false)]);
    return ergebnis ? [true, "Gerät in Reichweite"] : [false, "Gerät meldet sich nicht"];
  } catch (e) {
    log("DEBUG", `watchAdvertisements fehlgeschlagen: ${e.message}`);
    return [true, "übersprungen"];
  } finally {
    abbruch.abort();
  }
}

async function geraetErmitteln(statusMelden = () => {}) {
  if (gemerktesGeraet && !auswahlErzwingen) return [gemerktesGeraet, true];

  const gespeicherteId = speicherLesen(SPEICHER_GERAET);
  const [merkbar, merkHinweis] = geraetMerkenVerfuegbar();
  if (!merkbar) log("WARNING", merkHinweis);

  if (!auswahlErzwingen && gespeicherteId && merkbar) {
    try {
      const liste = await navigator.bluetooth.getDevices();
      const treffer = liste.find((g) => g.id === gespeicherteId);
      if (treffer) {
        log("DEBUG", "Bekanntes Gerät ohne Auswahldialog gefunden");
        statusMelden("Suche Tor …");
        const [inReichweite, meldung] = await aufWerbungWarten(treffer);
        log("DEBUG", `Reichweitenprüfung: ${meldung}`);
        if (!inReichweite) log("WARNING", "Gemerktes Gerät meldet sich nicht, Verbindungsversuch trotzdem");
        gemerktesGeraet = treffer;
        return [treffer, true];
      }
      log("WARNING", `Gemerktes Gerät nicht in der Freigabeliste (${liste.length} Einträge)`);
    } catch (e) {
      log("WARNING", `getDevices fehlgeschlagen: ${e.message}`);
    }
  }

  const geraet = await navigator.bluetooth.requestDevice({
    filters: KONFIG.namensPraefixe.map((p) => ({ namePrefix: p })),
    optionalServices: [UUID.dienst],
  });
  auswahlErzwingen = false;
  gemerktesGeraet = geraet;
  speicherSchreiben(SPEICHER_GERAET, geraet.id);
  log("INFO", `Gerät gewählt: ${geraet.name || "unbenannt"}`);
  return [geraet, false];
}

/** Übersetzt typische Chrome-Bluetooth-Meldungen in verständlichen Text. */
function meldungKlartext(text) {
  const t = String(text || "");
  if (/unknown reason/i.test(t)) return "Bluetooth-Fehler ohne nähere Angabe (GATT Error Unknown)";
  if (/no longer in range/i.test(t)) return "Shelly nicht in Reichweite";
  if (/GATT Server is disconnected/i.test(t)) return "Verbindung vom Shelly getrennt";
  if (/Connection attempt failed/i.test(t)) return "Verbindungsaufbau gescheitert";
  if (/not paired|insufficient (authentication|encryption)/i.test(t)) return "Handy nicht (mehr) gekoppelt – neu koppeln";
  if (/already in progress/i.test(t)) return "Bluetooth noch mit vorigem Vorgang beschäftigt";
  if (/invalid attribute length/i.test(t)) return "Shelly lehnt die Länge der Daten ab (invalid attribute length)";
  return t;
}

function fehlerUebersetzen(fehler) {
  const name = fehler && fehler.name;
  const text = fehler && fehler.message;
  if (/not paired|insufficient (authentication|encryption)/i.test(text || "")) {
    return "Handy ist nicht (mehr) mit dem Shelly gekoppelt. Kopplung am Shelly und in den Android-Bluetooth-Einstellungen erneuern.";
  }
  if (name === "NotFoundError") return "Kein Gerät ausgewählt.";
  if (name === "NotAllowedError") return "Bluetooth-Zugriff wurde nicht erlaubt.";
  if (name === "NetworkError") return "Verbindung fehlgeschlagen. Näher ans Tor gehen und nochmal tippen.";
  if (name === "SecurityError") return "Seite muss über HTTPS geöffnet werden.";
  return (fehler && fehler.message) || "Unbekannter Fehler";
}

/**
 * Öffnet das Tor per Impuls.
 * @param {(meldung:string)=>void} statusMelden Callback für Zwischenstände
 * @returns {Promise<[boolean, string]>}
 */
async function torOeffnen(statusMelden) {
  log("INFO", "=== Aktion gestartet: Tor öffnen ===");
  let rpc = null;
  try {
    if (!navigator.bluetooth) {
      return [false, "Dieser Browser unterstützt kein Bluetooth. Bitte Chrome verwenden."];
    }

    statusMelden("Verbinde …");
    const [geraet, ausGespeichert] = await geraetErmitteln(statusMelden);
    rpc = new ShellyBleRpc(geraet);
    const params = { id: KONFIG.schalterId, on: true, toggle_after: KONFIG.impulsSekunden };
    let antwort = null;
    let letzterFehler = null;
    for (let versuch = 1; versuch <= KONFIG.verbindungsVersuche; versuch++) {
      try {
        if (versuch > 1) {
          statusMelden(`Verbinde … (Versuch ${versuch})`);
          await warten(KONFIG.pauseZwischenVersuchenMs * (versuch - 1));
        }
        await rpc.verbinden();
        statusMelden("Sende Befehl …");
        antwort = await rpc.aufrufen("Switch.Set", params);
        letzterFehler = null;
        if (versuch > 1) log("INFO", `Erfolgreich im Versuch ${versuch}`);
        break;
      } catch (e) {
        letzterFehler = e;
        log("WARNING", `Versuch ${versuch}/${KONFIG.verbindungsVersuche} fehlgeschlagen bei „${rpc.schritt}“: ${meldungKlartext(e.message)} (${e.name || "Fehler"})`);
        rpc.trennen();
        if (rpc.datenBegonnen) {
          log("WARNING", "Befehl war bereits unterwegs, keine Wiederholung (Schutz vor Doppelimpuls)");
          return [false, "Unklar, ob das Tor reagiert hat. Bitte schauen und bei Bedarf nochmal tippen."];
        }
      }
    }
    if (letzterFehler) {
      if (ausGespeichert) {
        auswahlErzwingen = true;
        return [false, "Tor nicht erreicht. Nochmal tippen und Gerät auswählen."];
      }
      throw letzterFehler;
    }
    let neuerZugang = null;

    const herausforderung = herausforderungLesen(antwort);
    if (herausforderung) {
      log("DEBUG", "Shelly verlangt Authentifizierung");
      const zugang = speicherLesen(SPEICHER_ZUGANG);
      let ha1 = zugang && zugang.realm === herausforderung.realm ? zugang.ha1 : null;
      if (!ha1) {
        if (!einrichtungsPasswort) {
          return [false, "EINRICHTUNG"];
        }
        ha1 = await ha1Berechnen(herausforderung.realm, einrichtungsPasswort);
        neuerZugang = { realm: herausforderung.realm, ha1 };
      }
      antwort = await rpc.aufrufen("Switch.Set", params, await authObjektErstellen(herausforderung, ha1));
    }

    if (antwort.error) {
      if (antwort.error.code === 401) {
        speicherLoeschen(SPEICHER_ZUGANG);
        einrichtungsPasswort = null;
        log("WARNING", "Authentifizierung abgelehnt, gespeicherte Zugangsdaten verworfen");
        return [false, "EINRICHTUNG_FALSCH"];
      }
      return [false, `Shelly meldet Fehler ${antwort.error.code}: ${antwort.error.message}`];
    }

    if (neuerZugang) {
      const [ok, meldung] = speicherSchreiben(SPEICHER_ZUGANG, neuerZugang);
      log(ok ? "INFO" : "WARNING", `Zugangsdaten: ${meldung}`);
    }
    einrichtungsPasswort = null;
    log("INFO", "Impuls erfolgreich gesendet");
    return [true, "Tor wird geöffnet"];
  } catch (fehler) {
    log("ERROR", `Tor öffnen fehlgeschlagen: ${fehler.name || ""} ${fehler.message || fehler}`);
    return [false, fehlerUebersetzen(fehler)];
  } finally {
    if (rpc) rpc.trennen();
    log("INFO", "=== Aktion abgeschlossen: Tor öffnen ===");
  }
}

function geraeteInfo() {
  const ua = navigator.userAgent || "";
  const android = (ua.match(/Android [\d.]+/) || ["?"])[0];
  const modell = (ua.match(/Android [\d.]+; ([^;)]+)/) || [])[1] || "unbekanntes Gerät";
  const chrome = (ua.match(/Chrome\/([\d]+)/) || [])[1] || "?";
  return `${modell}, ${android}, Chrome ${chrome}`;
}

async function protokollTeilen() {
  const text = `Tor-Steuerung ${APP_VERSION} – ${geraeteInfo()}\n\n${logPuffer.join("\n")}`;
  try {
    if (navigator.share) { await navigator.share({ title: "Tor-Steuerung Protokoll", text }); return [true, "Geteilt"]; }
    await navigator.clipboard.writeText(text);
    return [true, "Protokoll in die Zwischenablage kopiert"];
  } catch (e) {
    return [false, `Teilen nicht möglich: ${e.message}`];
  }
}

// ---------------------------------------------------------------------------
// Oberfläche
// ---------------------------------------------------------------------------
function oberflaecheStarten() {
  const $ = (id) => document.getElementById(id);
  const btnTor = $("btnTor");
  const statusEl = $("status");
  const einrichtung = $("einrichtung");
  const pwFeld = $("passwort");
  let laeuft = false;

  debugModus = new URLSearchParams(location.search).has("debug");
  if (debugModus) $("details").open = true;
  $("version").textContent = APP_VERSION;

  const status = (text, art = "") => {
    statusEl.textContent = text;
    statusEl.dataset.art = art;
  };

  const einrichtungZeigen = (hinweis) => {
    einrichtung.hidden = false;
    status(hinweis, "warnung");
    pwFeld.focus();
  };

  btnTor.addEventListener("click", async () => {
    if (laeuft) return;
    laeuft = true;
    btnTor.disabled = true;
    btnTor.dataset.zustand = "laeuft";
    const [ok, meldung] = await torOeffnen((m) => status(m));
    if (meldung === "EINRICHTUNG") {
      einrichtungZeigen("Einmalig das Gerätepasswort eingeben.");
    } else if (meldung === "EINRICHTUNG_FALSCH") {
      einrichtungZeigen("Passwort falsch. Bitte neu eingeben.");
    } else {
      status(meldung, ok ? "ok" : "fehler");
      if (ok && navigator.vibrate) navigator.vibrate(150);
    }
    btnTor.dataset.zustand = ok ? "ok" : "";
    btnTor.disabled = false;
    laeuft = false;
    if (ok) setTimeout(() => { btnTor.dataset.zustand = ""; }, 3000);
  });

  $("btnPasswortUebernehmen").addEventListener("click", () => {
    const wert = pwFeld.value;
    pwFeld.value = "";
    if (!wert) { status("Bitte Passwort eingeben.", "warnung"); return; }
    einrichtungsPasswort = wert;
    einrichtung.hidden = true;
    status("Passwort übernommen. Jetzt „Tor öffnen“ tippen.", "");
    log("INFO", "Passwort für die Einrichtung übernommen (nur Arbeitsspeicher)");
  });

  $("btnPasswortSetzen").addEventListener("click", () => {
    einrichtungZeigen("Gerätepasswort eingeben.");
  });

  $("btnGeraetNeu").addEventListener("click", () => {
    auswahlErzwingen = true;
    gemerktesGeraet = null;
    speicherLoeschen(SPEICHER_GERAET);
    status("Beim nächsten Tippen wird das Gerät neu gewählt.");
    log("INFO", "Geräteauswahl zurückgesetzt");
  });

  $("btnTeilen").addEventListener("click", async () => {
    const [ok, meldung] = await protokollTeilen();
    if (!ok) status(meldung, "fehler");
  });

  $("btnZuruecksetzen").addEventListener("click", () => {
    speicherLoeschen(SPEICHER_ZUGANG);
    speicherLoeschen(SPEICHER_GERAET);
    gemerktesGeraet = null;
    einrichtungsPasswort = null;
    status("Alle gespeicherten Daten gelöscht.");
    log("INFO", "Zugangsdaten und Geräteauswahl gelöscht");
  });

  if (!navigator.bluetooth) {
    status("Bluetooth wird von diesem Browser nicht unterstützt. Bitte Chrome verwenden.", "fehler");
  }

  if ("serviceWorker" in navigator) {
    navigator.serviceWorker.register(`sw.js?v=${APP_VERSION}`, { updateViaCache: "none" }).then(
      () => log("DEBUG", "Offline-Zwischenspeicher aktiv"),
      (e) => log("WARNING", `Offline-Zwischenspeicher nicht aktiv: ${e.message}`)
    );
  }
  log("INFO", `Tor-Steuerung ${APP_VERSION} gestartet (${geraeteInfo()})`);
  if (navigator.bluetooth) {
    const [merkbar, hinweis] = geraetMerkenVerfuegbar();
    log(merkbar ? "INFO" : "WARNING", hinweis);
    const el = $("merkHinweis");
    if (el) { el.textContent = merkbar ? "Gerät merken: aktiv" : "Gerät merken: nicht aktiv (Chrome-Flag fehlt)"; }
  }
}

if (typeof document !== "undefined") {
  document.addEventListener("DOMContentLoaded", oberflaecheStarten);
}

// Export nur für Tests unter Node.js
if (typeof module !== "undefined") {
  module.exports = { torOeffnen, ha1Berechnen, authObjektErstellen, sha256Hex, KONFIG, UUID, APP_VERSION,
    _intern: { setzePasswort: (p) => { einrichtungsPasswort = p; } } };
}
