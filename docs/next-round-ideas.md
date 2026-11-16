# Runda următoare — idei, ordonate, cu recomandare

16 noiembrie 2026, după runda RC-15…RC-18 (vezi `tracker.csv`). Aici sunt doar
lucruri **nefăcute**, fiecare cu efortul estimat, de ce merită și ce comandă l-ar
verifica. Ordinea este a recomandării, nu a dimensiunii.

Contextul care schimbă prioritățile față de raportul din 15 noiembrie:

- **eIDAS 2.0 are termen**: Regulamentul (UE) 2024/1183 obligă fiecare stat membru
  să ofere un portofel de identitate digitală până la sfârșitul lui 2026, iar în
  2026 există deja literatură peer-reviewed despre tranziția post-cuantică în
  eIDAS 2.0. Un jurnal de dispozitive cu transparență verificabilă este exact
  structura cerută de schemele de key transparency, deci ideea 4 devine oportună,
  nu doar disponibilă.
- **Witnessii devin o rețea publică**: C2SP publică `tlog-witness`, iar Rekor v2
  din Sigstore este construit să consume exact acele cosemnături, cu politica de
  martori distribuită prin TUF și cu o rețea publică de martori planificată. Un
  prag de martori care sunt martorii altcuiva este singurul prag care contează.
- **PRF pe passkey-uri este suportat** pe platformele și browserele majore
  (situație verificată 2025–2026), deci „secret ținut de hardware” nu mai cere
  livrarea unui driver.

## 1. (recomandarea principală) A doua implementare, care nu e a noastră

**Criteriul 3 din `stability.md` pentru 1.0 cere două implementări independente**
care trec tot setul de vectori. Azi există una (crate-urile Rust) plus
verificatorul Node scris în același repo de aceiași autori — iar raportul spune
singur de ce acesta nu contează. Harness-ul de conformitate e gata (RC-11); îi
lipsește exact implementarea.

Ce livrez, concret, în două feluri care nu se exclud:

1. **un kit de conformitate** — harness-ul, vectorii, `compliance.json` și un
   contract de adaptor de o pagină, astfel încât oricine poate revendica și
   dovedi conformitatea fără să ne citească codul;
2. **o cale de referință independentă**, scrisă din biblioteci care nu ating
   HIDE: `x-wing`/`ml-kem` din RustCrypto + `hpke` + un decoder CBOR generic,
   adică un cititor de container care nu importă niciun `hide-*`. Este singura
   rută realistă la criteriul 3 fără să aștepți un străin.

De ce întâi: este singurul element care mișcă un criteriu de 1.0, și este și
singurul care transformă „avem vectori congelați” dintr-o afirmație într-o probă.
Efort: mediu-mare (cititorul de container + transcriptul, fără criptografie nouă).
Verifică: `node conformance/harness/run.mjs --command '<cale independentă>' --require-complete`
trebuie să iasă 0, cu zero vectori NEVERIFICAȚI.

## 2. (de decis înainte de 1.0, ieftin acum, scump după) Protecția hardware a cheii

`TRACKER.md` listează „no hardware key protection”. Diferența dintre acum și
după înghețare este că un seed ținut de hardware are nevoie de un **scop nou de
cheie** în fișierul de cheie (`KeyPurpose::Hardware`) — iar fișierele de cheie
nu sunt încă declarate înghețate, containerele sunt. Două variante:

- **OS keychain** (DPAPI/NCrypt, Keychain, Secret Service): portabil, dar
  secretul e doar „la fel de protejat ca sesiunea”;
- **FIDO2 `hmac-secret`** printr-o bibliotecă CTAP: hard real, cu refuz
  documentat când autentificatorul lipsește.

Recomand a doua, livrată ca scop nou + un test care dovedește refuzul fără
autentificator. Efort: mediu.

## 3. (ieftin, hardening de poartă — aș face-o în orice rundă)

- **`cargo-semver-checks` în CI.** 0.10.0 a schimbat API public (coduri de eroare
  noi, `SpentNonces::new`, `validate_device_credential`). Poarta ar fi prins-o și,
  mai important, va prinde următoarea schimbare accidentală înainte de 1.0.
- **F-15**: `verifyCheckpoint` în WASM întoarce doar rădăcina, nu și dimensiunea
  arborelui; Rust, C ABI și SDK-urile o întorc pe amândouă, deci suprafața WASM
  e singura inconsistentă. Are ripple în `crates/hide-wasm`, build-ul wasm și
  verificarea cross-surface.
- **Țintă de fuzz pentru scriitor** (calea de criptare). Invariantul „scriitorul
  nu emite niciodată ce cititorul refuză” e azi acoperit doar de fuzz-ul
  diferențial Rust↔Node; un target care duce metadata și plaintext fuzzate prin
  encrypt→decrypt ar prinde bug-uri de canonicalitate pe partea de scriere.
- **Poartă de performanță**: niciun job nu măsoară debitul de criptare/decriptare,
  deci o regresie de 5 % trece nevăzută. Un benchmark cu prag, în CI.

## 4. (adopție ieftină, valoare mare) Witnessii Sigstore

HIDE verifică deja cosemnături C2SP. Rekor v2 planifică o rețea publică de
martori cu politica distribuită prin TUF. Ideea: consumăm **formatul de politică
și cheile** lor, astfel încât un checkpoint HIDE să poată fi cosemnat de
martorii pe care îi folosește și Sigstore. Fără criptografie nouă — doar
formatul de politică și un test cu o cheie de martor din politică. Efort: mic.

## 5. (de decis) Jurnalul de identitate ca director KT

Publicăm un artefact `directory.json` (rădăcină + checkpoint + dovadă de
includere per dispozitiv) plus un verificator independent, fără să pretindem
conformitate cu eIDAS. Toate primitivele există (§16). Efort: mediu. Merită doar
dacă vrei ca HIDE să fie *consumabil* de un portofel, nu doar corect.

## 6. (extern — nu pot închide nimic din cod) Audit terț

Rămâne singurul element pe care niciun commit nu-l poate închide. Ce pot livra
eu: **pachetul de audit** — scop propus, extras din threat model, lista exactă de
comenzi de poartă cu ieșirea lor, cele două advisory-uri publice, limitările
cunoscute și „ce vrem să fie contestat”. Apoi tu ceri 2–3 oferte; intervalele
tipice pentru un audit focalizat de format de fișier și criptografie sunt de
câteva săptămâni și de ordinul zecilor de mii de euro, dar nu am o sursă
verificată pentru cifre — de aceea: oferte, nu estimări.

## 7. (de urmărit, nu de făcut) Mesagerie de grup post-cuantică

Blocat de `draft-ietf-mls-pq-ciphersuites`: niciun provider Rust nu implementează
ciphersuite-ul PQ (verificat din nou; draftul nu e final). Nu e o sarcină, e un
declanșator: când un provider Rust îl implementează, `hide-mls` are deja forma
potrivită (`PQ_STATUS` spune adevărul în API).

## 8. (rămase, cu linia de cod în raport) P2-urile din secțiunea 6

`S-08`…`S-23`, `B-08`…`B-27`, `CLI-06`…`CLI-19`, `F-17`…`F-26`,
`SRE-F-14`…`SRE-F-22`, `FE-01`…`FE-07`, `A11Y-01`…`A11Y-06`. Fiecare are linia
de cod și reparația propusă în raportul fazei. Recomandarea mea: pe grupuri, cu
cele de securitate primele, nu una câte una.

## Recomandarea, într-o frază

**Runda următoare: punctul 1 (a doua implementare independentă) ca lucru mare,
plus grupul 3 ca hardening ieftin de poartă — și decide punctul 2 (scopul
hardware) înainte de 1.0, pentru că după înghețare devine o schimbare de format
în fișierele de cheie.**

## 9. (găsit de această rundă) 15 alerte dependabot deschise pe ramura implicită

La împingerea commitului `46ed2d6`, GitHub raportează **15 vulnerabilități
deschise: 3 high, 10 moderate, 2 low**. Este o suprafață pe care raportul din
15 noiembrie nu a citit-o: a citit *PR-urile* dependabot, nu *alertele*, iar cele
două sunt liste diferite. Cineva care citește doar „0 issues, N PR-uri” crede că
depozitul e curat.

| alerte | pachet | unde | verdict |
| --- | --- | --- | --- |
| 1 (medium) | `serde_with` GHSA-7gcf-g7xr-8hxj | `apps/hide-desktop/src-tauri/Cargo.lock` | **rezolvată de această rundă**: intervalul vulnerabil este `>= 2.3.0, < 3.21.0`, iar lock-ul are acum 3.24.0 (RC-18). Alerta se închide la următoarea scanare |
| 1 (medium) | `glib` GHSA-wrw7-89jp-8q8g | `apps/hide-desktop/src-tauri/Cargo.lock` | **deja documentată și acceptată**: intervalul este `>= 0.15.0, < 0.20.0` fără versiune reparată, adică exact `RUSTSEC-2024-0429`, pe care `apps/hide-desktop/src-tauri/.cargo/audit.toml` îl listează cu motivul scris (linia GTK3, fix-ul cere o versiune de Tauri care nu există) |
| 3 (1 high, 1 low, 1 medium × 2) | `vite` | `apps/hide-desktop/package.json` + `pnpm-lock.yaml` | unealtă de **build/dev**, nu cod livrat: riscul cere un `vite dev` local sau un `preview` expus. Fix = bump de vite |
| 1 (high) | `source-map-js` | `apps/hide-desktop/pnpm-lock.yaml` | dependență tranzitivă a lui vite, tot dev |

Recomandare, în ordine:

1. **Nu le trata ca echivalentul lui `cargo audit` / `cargo deny`**: acelea rulează
  pe codul livrat, iar 14 din 15 alerte sunt în unelte de build sau în linia
  GTK3 pe care proiectul a decis deja să o accepte. Aici e vorba de un post de
  lucru de dezvoltator, nu de octeți pe care îi deschide un utilizator.
2. **Lasă bump-ul de `vite`/`source-map-js` în seama dependabot** — dar verifică
  că deschide PR-ul: după ce vite a sărit la 8.2.4, alertele sunt încă deschise,
  deci versiunea care repară nu e în lock.
3. **Pentru `glib`, corelează alerta cu lista de ignorări**: fie o închizi cu
  motivul documentat, fie adaugi un pas care o leagă de `.cargo/audit.toml`.
  Altfel 15 alerte deschise ascund exact următoarea alertă care contează, iar
  asta este costul real al zgomotului.
4. **Notă de efect secundar**: `conformance/cross-surface/adapters/go/go.mod` a
  adăugat o intrare nouă în graful de dependențe (workflow-ul
  „Graph Update: go_modules” a rulat și a ieșit verde). Modulul are o singură
  dependență, un `replace` local, deci nu are nimic de actualizat — dar dacă
  vrei ca dependabot să nu-l scaneze, trebuie spus explicit.
