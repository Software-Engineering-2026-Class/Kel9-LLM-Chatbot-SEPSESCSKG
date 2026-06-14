from __future__ import annotations

import argparse
import ssl
import sys

from SPARQLWrapper import JSON, POST, SPARQLWrapper

# SEPSES kadang memakai sertifikat rewel; lewati verifikasi SSL.
ssl._create_default_https_context = ssl._create_unverified_context

DEFAULT_ENDPOINT = "https://sepses.ifs.tuwien.ac.at/sparql"
CVE_RES = "http://w3id.org/sepses/resource/cve/"

PREFIXES = """\
PREFIX rdf:  <http://www.w3.org/1999/02/22-rdf-syntax-ns#>
PREFIX dct:  <http://purl.org/dc/terms/>
PREFIX cve:  <http://w3id.org/sepses/vocab/ref/cve#>
PREFIX cwe:  <http://w3id.org/sepses/vocab/ref/cwe#>
PREFIX cvss: <http://w3id.org/sepses/vocab/ref/cvss#>
"""


def _run(endpoint: str, query: str):
    w = SPARQLWrapper(endpoint)
    w.setReturnFormat(JSON)
    w.setMethod(POST)
    w.setTimeout(30)
    w.setQuery(query)
    res = w.query().convert()
    return res.get("results", {}).get("bindings", [])


def test_connectivity(endpoint: str) -> bool:
    print(f"[1] Konektivitas: COUNT(*) di {endpoint}")
    rows = _run(endpoint, f"{PREFIXES}\nSELECT (COUNT(*) AS ?c) WHERE {{ ?s ?p ?o }}")
    total = rows[0]["c"]["value"] if rows else "0"
    print(f"    -> total triple (perkiraan/limit server): {total}")
    return rows != []


def test_sample_cves(endpoint: str, limit: int = 5) -> bool:
    # Entry-point andal: ambil id CVE dari IRI, BUKAN dari cve:id.
    print(f"[2] Ambil {limit} CVE via IRI (tanpa cve:id)")
    query = f"""{PREFIXES}
SELECT DISTINCT ?cveId WHERE {{
  ?cve a cve:CVE .
  BIND(STRAFTER(STR(?cve), "{CVE_RES}") AS ?cveId)
  FILTER(?cveId != "")
}} LIMIT {int(limit)}"""
    rows = _run(endpoint, query)
    for r in rows:
        print(f"    - {r['cveId']['value']}")
    return len(rows) > 0


def test_lookup_log4shell(endpoint: str) -> bool:
    # Lookup satu CVE lewat BIND IRI + dct:description (cara yang dipakai backend).
    cve = "CVE-2021-44228"
    print(f"[3] Lookup {cve} via BIND IRI + dct:description")
    query = f"""{PREFIXES}
SELECT ?description ?score WHERE {{
  BIND(<{CVE_RES}{cve}> AS ?cve)
  OPTIONAL {{ ?cve dct:description ?description . }}
  OPTIONAL {{ ?cve cve:hasCVSS3BaseMetric ?m . ?m cvss:baseScore ?score . }}
}} LIMIT 1"""
    rows = _run(endpoint, query)
    if not rows:
        print("    -> tidak ada baris (CVE mungkin belum termuat di endpoint ini).")
        return False
    desc = rows[0].get("description", {}).get("value", "")
    score = rows[0].get("score", {}).get("value", "")
    if score:
        print(f"    CVSS3 baseScore : {score}")
    if desc:
        print(f"    Deskripsi       : {desc[:160]}...")
    return bool(desc or score)


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description="Uji koneksi SPARQL SEPSES (Issue #1).")
    ap.add_argument("--endpoint", default=DEFAULT_ENDPOINT, help="URL endpoint SPARQL.")
    args = ap.parse_args(argv)

    ok = True
    try:
        ok &= test_connectivity(args.endpoint)
        ok &= test_sample_cves(args.endpoint)
        # Log4Shell bisa saja belum termuat; jadikan informatif, bukan kegagalan fatal.
        test_lookup_log4shell(args.endpoint)
    except Exception as e:
        print(f"[error] {e}")
        print("Petunjuk: endpoint publik mungkin sedang down. Coba --endpoint "
              "http://localhost:8890/sparql bila Virtuoso lokal sudah dimuat.")
        return 1

    print("\nHasil:", "OK" if ok else "ADA YANG GAGAL (lihat di atas)")
    return 0 if ok else 1


if __name__ == "__main__":
    raise SystemExit(main())