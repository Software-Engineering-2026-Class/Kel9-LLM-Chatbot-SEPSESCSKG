# SEPSES CSKG Schema Report

> **PENTING — regenerasi `count` sebelum dipakai sebagai bukti deliverable.**
> Bagian _Top Classes_/_Top Predicates_/_Sample Triples_ dan kolom `count`
> diisi otomatis saat `schema_inspector.py` dijalankan terhadap data nyata:
>
> ```bash
> # Sumber utama (data nyata, lengkap): endpoint SEPSES publik
> python scripts/generate_schema_report.py --target public
>
> # Atau dari Virtuoso lokal SETELAH data/cskg_dumps dimuat (docker compose up)
> python scripts/generate_schema_report.py --target local
> ```
>
> Nama kelas di dokumen ini SUDAH diselaraskan dengan dump nyata + RML generator
> (`sepses/cyber-kg-converter`) dan dengan `backend/llm/schema_inspector.py`:
> **`cve:CVE`, `cwe:CWE`, `capec:CAPEC`, `cpe:CPE`** — BUKAN `cwe:Weakness` /
> `capec:AttackPattern` (penamaan lama yang stale, kini diperbaiki).
> Verifikasi langsung dari dump: `ns1:CWE-1021 rdf:type ns2:CWE`.

- Endpoint: `https://sepses.ifs.tuwien.ac.at/sparql`
- Graph: `(default graph)`
- Triples: _(diisi saat run)_
- Distinct subjects: _(diisi saat run)_
- Distinct objects: _(diisi saat run)_

## Verified Schema (Issue #1)

**Pola IRI sumber daya (entry-point andal, lepas dari predikat id):**

- CVE   : `http://w3id.org/sepses/resource/cve/CVE-YYYY-NNNN`
- CWE   : `http://w3id.org/sepses/resource/cwe/CWE-N`
- CAPEC : `http://w3id.org/sepses/resource/capec/CAPEC-N`

**Temuan kunci:**

- Deskripsi CVE/CWE/CAPEC memakai **`dct:description`** (Dublin Core), bukan
  `cve:description` / `cwe:description` / `capec:description`.
- Id CVE dari generator JSON terkini memakai **`dct:identifier`** (id juga selalu
  ada di IRI). Lookup CVE sebaiknya mengikat lewat **BIND IRI**, bukan `cve:id`
  (yang berasal dari generator XML lama yang sedang dipensiunkan -> bisa kosong).
- Mitigasi CAPEC = **`capec:hasMitigation`** berisi **literal teks langsung**
  (bukan `capec:mitigation`, bukan node).
- Mitigasi CWE = node via `cwe:hasPotentialMitigation` -> teks di
  `cwe:mitigationDescription`.
- Nama kelas yang benar: **`cve:CVE`, `cwe:CWE`, `capec:CAPEC`, `cpe:CPE`**.

## Key Entity Classes (Issue #1)

| class | label | catatan |
| --- | --- | --- |
| `cve:CVE` | CVE Vulnerability | Entry-point utama; diikat lewat **BIND IRI** `resource/cve/CVE-YYYY-NNNN`. |
| `cwe:CWE` | CWE Weakness | Ditautkan dari CVE via `cve:hasCWE`. |
| `capec:CAPEC` | CAPEC Attack Pattern | Ditautkan dari CWE via `cwe:hasCAPEC`. |
| `cpe:CPE` | CPE Platform | Produk/platform terdampak via `cve:hasCPE`. |
| `cvss:CVSS3BaseMetric` | CVSS v3 Base Metric | Skor via `cve:hasCVSS3BaseMetric` -> `cvss:baseScore`. |
| `cvss:CVSS2BaseMetric` | CVSS v2 Base Metric | Fallback skor lama via `cve:hasCVSS2BaseMetric`. |

## Key Object Properties (relasi antar-entitas)

| predicate | arah | catatan |
| --- | --- | --- |
| `cve:hasCWE` | CVE -> CWE | Rantai kerentanan. |
| `cve:hasCPE` | CVE -> CPE | Produk terdampak. |
| `cve:hasVulnerableConfiguration` | CVE -> CPE | Konfigurasi rentan (CPE). |
| `cve:hasCVSS3BaseMetric` | CVE -> CVSS3 | Node metrik (skor di hop berikutnya). |
| `cve:hasCVSS2BaseMetric` | CVE -> CVSS2 | Node metrik (skor di hop berikutnya). |
| `cwe:hasCAPEC` | CWE -> CAPEC | Pola serangan terkait. |
| `cwe:hasCommonConsequence` | CWE -> Consequence | Node konsekuensi (`cwe:consequenceImpact`). |
| `cwe:hasPotentialMitigation` | CWE -> Mitigation | Node -> teks via `cwe:mitigationDescription`. |
| `capec:hasMitigation` | CAPEC -> Mitigation | **Literal teks langsung** (bukan `capec:mitigation`). |

## Key Datatype Properties (atribut/teks)

| property | dipakai pada | catatan penting |
| --- | --- | --- |
| `dct:identifier` | CVE | Id CVE generator JSON terkini (id juga ada di IRI). |
| `dct:description` | **CVE, CWE, & CAPEC** | Deskripsi memakai **Dublin Core**, bukan `cve:/cwe:/capec:description`. |
| `dct:issued` / `dct:modified` | CVE | Tanggal terbit/ubah (bukan `cve:publishedDate`). |
| `cwe:id` / `cwe:name` | CWE | Id & nama weakness. |
| `cwe:consequenceImpact` | CWE Consequence | Dampak konsekuensi (pada node). |
| `cwe:mitigationDescription` | CWE Mitigation | Teks mitigasi (pada node). |
| `capec:id` / `capec:name` | CAPEC | Id & nama attack pattern. |
| `capec:likelihoodOfAttack` | CAPEC | Likelihood serangan. |
| `cvss:baseScore` | CVSS metric | Skor numerik base score. |
| `cvss:attackVector` | CVSS metric | Vektor serangan. |

## Top Classes

_(diisi saat run)_

## Top Predicates

_(diisi saat run)_

## Curated Security Classes

| class | label | count |
| --- | --- | --- |
| cve:CVE | CVE Vulnerability | _(run)_ |
| cwe:CWE | CWE Weakness | _(run)_ |
| capec:CAPEC | CAPEC Attack Pattern | _(run)_ |
| cpe:CPE | CPE Platform | _(run)_ |
| cvss:CVSS3BaseMetric | CVSS v3 Base Metric | _(run)_ |
| cvss:CVSS2BaseMetric | CVSS v2 Base Metric | _(run)_ |

## Curated Security Relations

| predicate | label | count |
| --- | --- | --- |
| cve:hasCWE | CVE -> CWE | _(run)_ |
| cve:hasCPE | CVE -> CPE | _(run)_ |
| cve:hasVulnerableConfiguration | CVE -> VulnConfig (CPE) | _(run)_ |
| cve:hasCVSS3BaseMetric | CVE -> CVSS3 | _(run)_ |
| cve:hasCVSS2BaseMetric | CVE -> CVSS2 | _(run)_ |
| cwe:hasCAPEC | CWE -> CAPEC | _(run)_ |
| cwe:hasCommonConsequence | CWE -> Consequence (node) | _(run)_ |
| cwe:hasPotentialMitigation | CWE -> Mitigation (node) | _(run)_ |

## Curated Datatype Properties

| property | label | count |
| --- | --- | --- |
| dct:identifier | CVE id via Dublin Core | _(run)_ |
| cve:id | CVE id via vocab cve (generator XML lama) | _(run)_ |
| dct:description | Deskripsi (Dublin Core) — CVE, CWE, & CAPEC | _(run)_ |
| cve:description | Deskripsi via vocab cve (generator XML lama) | _(run)_ |
| dct:issued | Tanggal terbit CVE | _(run)_ |
| dct:modified | Tanggal ubah CVE | _(run)_ |
| cwe:id | CWE id (literal) | _(run)_ |
| cwe:name | CWE name | _(run)_ |
| cwe:consequenceImpact | Dampak konsekuensi CWE | _(run)_ |
| cwe:mitigationDescription | Teks mitigasi CWE | _(run)_ |
| capec:id | CAPEC id (literal) | _(run)_ |
| capec:name | CAPEC name | _(run)_ |
| capec:hasMitigation | Mitigasi CAPEC (literal langsung) | _(run)_ |
| capec:likelihoodOfAttack | Likelihood of attack CAPEC | _(run)_ |
| cvss:baseScore | CVSS base score | _(run)_ |
| cvss:confidentialityImpact | CVSS confidentiality impact | _(run)_ |
| cvss:attackVector | CVSS attack vector | _(run)_ |

## Sample Triples

_(diisi saat run)_