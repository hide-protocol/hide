# Reality check HIDE — 15 noiembrie 2026

Audit complet (cod, CI, lanț de aprovizionare, documentație, registre) la `main` = `dd28b40`,
după release-ul 0.9.1 din 27 septembrie 2026. Raportul de față este artefactul de audit al
perioadei 27 sep – 15 nov 2026; rândurile corespunzătoare sunt în `tracker.csv` (faza 15).

**Metodă.** Fiecare afirmație de mai jos este marcată *VERIFIED* (am rulat comanda și am citit
ieșirea) sau *EXPECTED* (dedusă din cod sau din comportamentul unei biblioteci, nereprodusă).
Auditul de cod a fost făcut în paralel de cinci cititori read-only, pe suprafețe disjuncte
(container, identitate/epoch/transparency/MLS, aplicații, SDK/FFI, SRE/supply-chain); niciunul nu a
compilat sau modificat ceva. Reparațiile au fost verificate independent de cel care le-a scris,
prin porțile din secțiunea 1.

## 1. Porțile rulate la finalul perioadei

| Poartă | Comandă | Rezultat |
|---|---|---|
| Teste workspace | `cargo test --workspace --all-features --locked` | VERIFIED, 411 teste, 0 eșecuri |
| Teste desktop | `cargo test --manifest-path apps/hide-desktop/src-tauri/Cargo.toml` | VERIFIED, 10 + 6 (interop), 0 eșecuri |
| Lint | `cargo clippy … --all-targets --all-features -- -D warnings` (workspace, CLI, desktop, fuzz) | VERIFIED, curat |
| Formatare | `cargo fmt --all --check` + `--manifest-path fuzz/Cargo.toml --check` | VERIFIED, 0 diferențe |
| Vectori congelați | `generate_v1_vectors -- --check` | VERIFIED, „vectors consistent” |
| Vectori de subsistem | `generate_subsystem_vectors` | VERIFIED, toate reprodu-se byte-cu-byte |
| Verificator independent | `node conformance/node/verify.mjs` + `subsystems.mjs` | VERIFIED, toate verificările trec |
| Diferențial Rust↔Node | `node conformance/differential/run.mjs --iterations 1500` | VERIFIED, 0 nepotriviri |
| Cross-surface | `node conformance/cross-surface/verify.mjs` | VERIFIED, 26/26 (wasm, node, cli, ruby, dotnet; php absent local) |
| Lanț de aprovizionare | `cargo audit --deny warnings`; `cargo deny check` | VERIFIED, 0 advisories, politici curate |
| Lockfiles | `node scripts/check-lock-drift.mjs` | VERIFIED, 33 crate-uri relevante concordă între root, desktop și fuzz |
| Versiuni | `pwsh scripts/set-version.ps1 -Check` | VERIFIED, 24 câmpuri concordă pe 0.9.1 |
| Pachet LLM | `node scripts/build-llms-full.mjs --check` | VERIFIED, la zi |
| Fuzz workspace | `cargo +nightly metadata --locked --manifest-path fuzz/Cargo.toml` | VERIFIED |

## 2. Bilanțul perioadei 27 septembrie – 15 noiembrie 2026

### CI

- `ci.yml`: 80 de rulări pe ramuri în perioadă — 45 succes, 22 eșec, 13 anulate. Eșecurile sunt pe
  ramuri de PR, aproape toate dependabot, pe o bază veche; pe `main` CI a fost verde la fiecare
  împingere (ultima verificată înainte de această sesiune: 40478956086 la `527bfb1`).
- `fuzz-nightly.yml`: 50 de rulări — 46 succes, 2 eșec, 1 anulat.
- **Cele două eșecuri, explicate.** `37287290058` (5 oct, `fuzz (identity_log)`) și `39563211727`
  (21 oct, `fuzz (object_open)`): niciun pas marcat ca eșuat, niciun artefact, niciun issue deschis.
  Un finding libFuzzer lasă întotdeauna un reproducer și, prin pașii de atunci, un issue — deci
  ambele sunt **pierderi de runner** (infrastructură), nu findings. *EXPECTED*, susținut de trei
  fapte: forma eșecului, lipsa oricărui artefact, și cele 46 de rulări verzi de atunci, cu aceleași
  ținte și corpus acumulat. Cauza reală a fost vizibilitatea: pașii `if: failure()` trăiau în jobul
  pierdut, deci nu se executau. Reparat în `fuzz-nightly.yml` (job `report`, `if: always()`, care
  clasează infrastructură vs finding, etichetează `fuzz-infra` și poate re-rula o dată).
- În perioadă: 15 PR-uri fuzionate, 1 release (0.9.1), 0 issue-uri deschise.

### Advisories

- `cargo audit`: 0 vulnerabilități pe lock-ul rădăcină; lock-ul desktop (495 crate-uri, tauri/wry/webkit)
  este acum auditat separat, cu propriul `.cargo/audit.toml` în care fiecare ignorare are motivul scris.
- `RUSTSEC-2026-0385` (ctutils) rezolvat prin ctutils 0.4.4; `RUSTSEC-2026-0387` nu mai e atins după
  trecerea la `mls-rs-crypto-rustcrypto` 0.23.0, iar ignorarea lui a fost ștearsă.
- `HIDE-2026-001` (alocare Argon2 de până la 4 GiB dintr-un fișier de 95 de octeți, găsit de fuzzer,
  afecta ≥0.2.0 <0.8.0) rămâne singurul advisory public; fixat în 0.8.0.
- Seriile noi de dependențe (hpke 0.15.1, ml-dsa 0.1.2, sha2 0.11.1, mls-rs 0.57.0,
  mls-rs-crypto-rustcrypto 0.23.0) au fost integrate direct pe `main`, cu MSRV ridicat la 1.88
  declarat, și trecute prin toate porțile de mai sus; PR-urile dependabot corespunzătoare au fost
  închise de dependabot însuși cu motivul „up-to-date now”.

### Descărcări per registru (citite din API-urile registrelor, 15 nov 2026)

| Registru | Pachet | Descărcări |
|---|---|---|
| crates.io | 11 crate-uri (hide-cli 133, hide-crypto 522, hide-sign 392, hide-format 286, hide-identity 261, hide-epoch 261, hide-keyring 253, hide-object 247, hide-transparency 180, hide-ffi 128, hide-mls 98) | **2.761 total**, toate în ultimele 90 de zile |
| npm | `hide-protocol` | 71 / lună |
| npm | `@hide-protocol/wasm` | 525 / lună |
| PyPI | `hide-protocol` | 178 / lună |
| RubyGems | `hide-protocol` | 7.369 total |
| NuGet | `HideProtocol` | 1 versiune publicată |

Citirea lor a fost primul lucru făcut vreodată cu aceste API-uri în proiect: până acum tracker-ul
afirma că publicarea a reușit, fără să fi măsurat vreodată dacă cineva descarcă.

### Repo

- 0 stele, **1 fork**, 0 watchers. Un singur issue în toată istoria proiectului (#6, închis).
- 6 PR-uri dependabot deschise la finalul perioadei (față de 9 la început): vezi secțiunea 5.

## 3. P0 — găsite și reparate

| # | Suprafață | Ce era greșit | Dovadă |
|---|---|---|---|
| P0-1 | CLI `passwd` | Pe o cheie neprotejată (un master seed) reseala cei 32 de octeți ca și cheie **de criptare**, schimbând identitatea: containerele trimise la cheia publică publicată nu se mai deschideau, iar semnarea se pierdea. Pe o cheie protejată de `keygen` eșua cu `WrongPurpose`, deci nicio cheie implicită nu-și putea schimba parola. Nicio comandă nu testa `passwd`. | `main.rs` `change_passphrase` → `reseal_key` care folosește `load_key`/`unprotect_seed` și păstrează scopul; test `changing_the_passphrase_keeps_the_key_for_every_file_shape` (cheie brută, v2-identity, v1) verifică că **cheia publică e neschimbată**; `a_wrong_current_passphrase_leaves_the_file_untouched`. VERIFIED |
| P0-2 | CLI `identity-create` | Suprascria tăcut un jurnal de identitate existent, înlocuind toată istoria dispozitivelor și rădăcina, deși README-ul spune „CLI-ul nu suprascrie niciodată un fișier existent”; `epoch-init` trata deja corect acest caz. | `identity-create` folosește acum publicarea fără suprascriere; `identity-create` a doua oară pe același drum este refuzat și fișierul rămâne identic octet cu octet. VERIFIED (test de proces) |
| P0-3 | FFI / SDK-uri | `HideSpentNonces` era mutat prin `&mut` fără nicio blocare, iar documentația spunea explicit că un astfel de record se păstrează între cereri: două fire de execuție intrau simultan în `accept`. | `HideSpentNonces(Mutex<SpentNonces>)`, `lock()` cu recuperare din otrăvire; test de concurență în Go și Java. VERIFIED |
| P0-4 | FFI / Go / .NET | Un finalizer putea elibera un handle cât timp un apel nativ încă îl folosea (receiver mort după citirea handle-ului, fără `KeepAlive`/`SafeHandle`). | `runtime.KeepAlive` pe fiecare cale Go; `SafeHandle`/`Handles.cs` în .NET; teste de siguranță adăugate. VERIFIED |
| P0-5 | PHP / Python / Ruby | Handle-urile puteau fi copiate, iar copiile împărțeau același pointer nativ: două destructori eliberau aceeași memorie. | `__clone` privat (PHP), `__copy__`/`__reduce__` care ridică (Python), `initialize_copy` care ridică (Ruby); teste în fiecare suită. VERIFIED |
| P0-6 | Ruby pe arm64 | `hide_buffer_empty` întoarce o structură de 24 de octeți, dar era legată ca `void f(void*)`: corect doar pe x86-64, pentru că AAPCS64 pasează adresa rezultatului în x8. Afecta 3 din 7 gem-uri publicate. | apelul a fost eliminat (umplerea manuală cu zero exista deja); suita Ruby verde pe x86-64. EXPECTED pe arm64 (nu există runner arm64 local) |

## 4. P1 — găsite și reparate

Toate cele 6 P1 din auditul containerului, 5 din 7 din auditul identității, 9 din 11 din SDK/FFI,
11 din 12 din SRE și majoritatea celor din auditul aplicațiilor sunt închise. Cele care contează cel
mai mult, pentru că schimbă comportamentul:

- **Audiența provocării este acum legată de verificator** (`S-01`, `F-10`). Până acum, un verificator
  care lua înapoi de la client octeții provocării putea accepta un răspuns emis pentru alt serviciu:
  câmpul `audience` exista și era semnat, dar nimeni nu-l compara cu cine este verificatorul.
  `SpentNonces` se construiește acum cu numele la care răspunde, iar comparația rulează **înainte**
  de verificarea semnăturii, astfel încât un răspuns pentru altcineva să nu consume nici nonce-ul.
  Cod de eroare nou `HIDE_ERR_CHALLENGE_AUDIENCE = 11`, propagat în toate cele 8 suprafețe (C ABI,
  WASM și 7 SDK-uri), plus verificarea cross-surface care dovedește refuzul. În plus, o provocare cu
  audiență vidă sau cu `valid_for` peste 3600 este refuzată la emitere **și** la decodare. VERIFIED
- **Un dispozitiv revocat nu mai poate comite într-un grup în care se află încă** (`B-02`). MLS
  validează lista de membri la adăugare și niciodată după aceea, deci un dispozitiv revocat în
  jurnalul de identitate putea trimite un commit (de exemplu, eliminarea laptopului onest) sau putea
  lăsa o propunere prin referință pe care un client onest o îngloba în următorul lui commit. Reguli
  MLS proprii (`HideMlsRules`) refuză acum orice propunere sau commit al unui expeditor pe care
  identitatea nu-l mai consideră de încredere, iar orice commit cere un update path. Testul care
  dovedește refuzul are un martor: același commit, de la un expeditor de încredere, este aplicat.
  VERIFIED
- **ssh-agent refuză payload-urile de forma HIDE** (`AGT-01`). Aceeași cheie Ed25519 este jumătatea
  clasică a fiecărei semnături HIDE; un apelant care obținea o semnătură pe un transcript HIDE
  reducea schema hibridă la ML-DSA. Payload-urile SSH oneste sunt blob-uri SSH, care nu încep cu un
  cadru de context `HIDE/`. VERIFIED
- **Coduri de eroare corecte la granița C** (`S-05`, `F-16`): `InvalidSignature`,
  `MissingSignature`, `UnexpectedSignature` și versiunile/suite-urile nesuportate nu mai cad toate în
  `MALFORMED`; un fișier falsificat se distinge acum de unul corupt, iar un `HIDE_ERR_UNSUPPORTED`
  există separat. Fără această distincție, niciun SDK nu putea spune dacă a văzut corupere sau
  falsificare. VERIFIED
- **Nucleul nu mai poate scrie metadata pe care cititorii o refuză** (`S-03`): API-ul public de
  scriere valida prea puțin `Metadata`, deci putea emite chei de extensie (interzise scriitorilor de
  1.0) sau un container nesemnat care purta o semnătură confidențială. VERIFIED
- **Legăturile de recuperare contradictorii sunt detectate** (`B-01`): regula §16.1 nu avea cod pe
  nicio suprafață. VERIFIED
- **Argon2 își șterge intermediarii** (`S-02`): fără feature-ul `zeroize`, H0 și blocul final rămâneau
  în memoria eliberată — suficiente pentru a reconstrui KEK-ul fără parolă. VERIFIED
- **CI**: MSRV verificat cu adevărat la 1.88 (jobul rula `stable` fiindcă `rust-toolchain.toml`
  suprascria acțiunea — deci poarta de MSRV nu putea prinde niciodată nimic), `--locked` peste tot,
  lock-ul de fuzz comis și verificat, lock-ul desktop auditat, workflow săptămânal de supply-chain,
  job `report` pentru fuzz-nightly, testele WASM rulate în CI (înainte rulau 0 teste pe gazdă),
  build-ul frontend-ului desktop blocat în CI (o eroare TypeScript apărea altfel prima dată la tag).
- **Documentație**: numere și versiuni corectate peste tot (ținte de fuzz 11→12, vectori de respingere
  30→32, teste 360/397→411, MSRV 1.85→1.88, mls-rs 0.56→0.57, diagrama de crate-uri completată cu
  muchiile și crate-ul lipsă); rândul „open” al codificării jurnalului de identitate din
  `audit-status.md` era închis din 0.9.0; trimiterile la secțiunile de spec corectate; afirmația falsă
  că HIDE nu-și poate verifica propriile release-uri (Sigstore e implementat); afirmația că age are
  audit Trail of Bits retrasă, în acord cu README-ul; cifra de memorie „7 MB” eliminată din locurile
  unde era prezentată ca măsurată, fiindcă nicio comandă din repo nu o măsoară.

## 5. PR-uri dependabot — integrate sau închise, fiecare cu motiv

| PR | Ce urmărea | Decizie |
|---|---|---|
| #52, #53, #54, #55, #57 | mls-rs 0.57.0, mls-rs-crypto-rustcrypto 0.23.0, hpke 0.15.1, ml-dsa 0.1.2 | **Integrate** direct pe `main` (cu MSRV 1.88, lockfiles actualizate, toate porțile verzi); dependabot le-a închis singur cu „up-to-date now” |
| #41 | sha2 `=0.11.0` → `=0.11.1` în `/fuzz` | **Închis**: rădăcina deja fixează `=0.11.1`, deci ramura nu mai are nicio schimbare |
| #31 | `dtolnay/rust-toolchain` către commit-ul ramurii `stable` | **Închis**: ar reintroduce exact bug-ul MSRV — jobul rulează acum 1.88.0 explicit, cu `RUSTUP_TOOLCHAIN`, iar SHA-ul din PR este ramura `stable`, pe care `rust-toolchain.toml` o suprascrie |
| #62, #61, #60, #59, #56, #40 | vite, source-map-js, serde_with, Microsoft.SourceLink, grupul de acțiuni ×14, grupul npm-minor ×11 | **Rebase cerut** (`@dependabot rebase`): toate picau pe aceleași trei joburi numai pentru că erau pe o bază veche, dinaintea înăspririi CI. Se merg după ce CI e verde pe baza nouă |

## 6. Rămase deschise după această rundă

**P1 rămase, cu motiv explicit:**

- `F-08` — cross-surface nu include Python, Go și Java ca adaptoare (doar ruby/php/dotnet), deși
  README-ul afirmă că fiecare SDK dă același verdict pe aceiași octeți. Claim-ul a fost restrâns
  acolo unde era prea larg; adăugarea a trei adaptoare este muncă de următoarea rundă.
- `B-05` — țintele de fuzz lipsă pentru `hide-ffi` (17 funcții care iau octeți), armor-ul de mesaj și
  credentialul MLS. `agent_request` a fost adăugat (12 ținte acum).
- `SRE-F-09` — workflow-urile programate se auto-dezactivează după 60 de zile fără push. Singurul
  watchdog adevărat este în afara GitHub (un cron care întreabă `gh run list`); nu poate fi construit
  din acest repo.
- `SRE-F-12` — instalatoarele nu sunt semnate: consecința (SmartScreen / Gatekeeper) este acum scrisă
  în aplicație, cu calea de verificare (`gh attestation verify`). Semnarea reală cere o credențială
  pe care proiectul nu o are.
- `F-15` — `verifyCheckpoint` în WASM întoarce doar rădăcina, nu și dimensiunea arborelui.

**P2 (listă, neatinse deliberat):** `S-07` (Ed25519 `A` necanonic — teoretic, sub 34 codificări, fără
logaritm discret cunoscut), `S-08` (pre-alocări mărginite), `S-09` (vector pozitiv pentru fișierul de
cheie protejat — cea mai valoroasă lacună de test rămasă), `S-10`..`S-23`, `B-08`..`B-27`, `CLI-06`..
`CLI-19`, `F-17`..`F-26`, `SRE-F-14`..`SRE-F-22`, `FE-01`, `FE-02`, `FE-04`..`FE-07`, `A11Y-01`..`A11Y-06`.
Fiecare are, în raportul de audit al fazei, linia de cod și reparația propusă; niciunul nu este o
pierdere de invariantă demonstrată.

## 7. Idei noi, ordonate (cu surse)

1. **Witness protocol C2SP (`c2sp.org/tlog-witness`).** HIDE are deja checkpoint-uri semnate și un
   prag de martori distincți, dar offline: nu există un mod standard prin care un martor să fie
   întrebat și să cosemneze. C2SP publică atât `tlog-checkpoint`, cât și protocolul HTTP de obținere
   a cosemnăturilor, iar Sigstore/Cosign v2.4+ cere implicit un checkpoint semnat de cel puțin doi
   martori — deci diversitatea martorilor devine norma în ecosistem. HIDE ar putea fi primul
   consumator non-Sigstore al protocolului. Cost: mediu. Sursă: c2sp.org/tlog-witness, spec-ul de
   politică al C2SP, OpenSSF/Sigstore.
2. **Fixarea referinței normative: NIST IR 8547 (oct 2026) și draft-ul X-Wing (rev. sept 2026).**
   IR 8547 recomandă ML-KEM-768 ca set de parametri implicit pentru stabilirea cheilor; HIDE folosește
   exact X-Wing (X25519 + ML-KEM-768). Draft-ul X-Wing are acum o revizie citabilă. Ideea: cităm
   ambele în spec §3 și adăugăm un test de interop cu vectorii draft-ului, ceea ce transformă o
   alegere bună într-o alegere verificabilă. Cost: mic. Surse: NIST IR 8547, draft-ietf-hpke-pq.
3. **A doua implementare independentă a cititorului de container.** Criteriul 3 din `stability.md`
   pentru 1.0 cere două implementări independente care trec tot setul de vectori; cea Node este scrisă
   în același repo de aceiași autori, deci nu contează. Ideea: publicăm `manifest.json` plus un
   harness de conformitate, astfel încât oricine poate revendica și dovedi conformitatea — și invităm
   explicit o implementare terță (Go sau Python). Cost: mediu. Sursă: `docs/stability.md` §criterii,
   `conformance/README`.
4. **Direcție de identitate verificabilă: portofel eIDAS 2.0.** Regulamentul cere portofele de
   identitate digitale în UE, iar piața de identitate descentralizată este estimată la 7,4 mld USD în
   2026. Jurnalul de identitate HIDE (dispozitive, revocare, recuperare offline) este exact genul de
   structură pe care o cer schemele de key transparency. Ideea: expunem jurnalul ca director KT
   (rădăcină + checkpoint + dovadă de includere), fără să pretindem conformitate. Cost: mare.
   Surse: C2SP tlog-*, materialul de politici KT.
5. **Audit terț.** Rămâne cea mai mare lacună și singurul lucru pe care NICIUN commit nu-l poate
   închide; `audit-status.md` are deja lista a ce ar trebui să acopere. Cost: mare, extern.
6. **Adâncime de verificare formală.** `proptest` este dependență de dezvoltare în trei crate-uri și
   nu este folosit nicăieri (constatat în audit). Ideea: fie proprietăți reale pe decodoare
   (canonicalitate, idempotență), fie eliminarea dependenței; plus MIRI/Kani pe căile de parsare.
   Cost: mic-mediu. Sursă: `B-25`.
7. **Protecție hardware a cheii.** `TRACKER.md` listează „no hardware key protection”. Ideea: un seed
   derivat prin WebAuthn/FIDO2 sau un identity susținut de PKCS#11/YubiKey, care ar închide clasa
   „master seed în clar pe disc”. Cost: mare. Sursă: `docs/TRACKER.md` „What does not exist”.
8. **Mesagerie de grup post-cuantică.** Blocată de `draft-ietf-mls-pq-ciphersuites`; niciun provider
   Rust nu o implementează. Nu este o idee de făcut, ci de urmărit. Sursă: `hide_mls::PQ_STATUS`.

Decizia pe aceste idei este cerută utilizatorului în conversație; rândurile din tracker se adaugă
pentru cele aprobate.

## 8. Release

Release-ul 0.10.0 se face **numai** dacă porțile din secțiunea 1 sunt verzi pe arborele comis,
pentru că majoritatea reparațiilor de mai sus schimbă comportamentul observabil (coduri de eroare,
semnături de API, permisiuni de fișier). Formatul pe fir nu s-a schimbat: niciun octet din vectorii
congelați nu s-a modificat, iar `generate_v1_vectors -- --check` și vectorii de subsistem trec.
