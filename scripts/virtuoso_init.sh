set -uo pipefail

HOST="${VIRTUOSO_HOST:-virtuoso}"
PORT="${VIRTUOSO_PORT:-1111}"
PW="${DBA_PASSWORD:-dba}"
# Satu konvensi graph dipakai loader DAN backend. Samakan dgn SEPSES_LOCAL_GRAPH.
GRAPH="${TARGET_GRAPH:-${SEPSES_LOCAL_GRAPH:-http://sepses.local}}"
DB_DIR="${DB_DIR:-/dumps}"
ISQL="/opt/virtuoso-opensource/bin/isql"
CONN="${HOST}:${PORT}"

isql_exec() { "${ISQL}" "${CONN}" dba "${PW}" "exec=$1"; }

echo "[loader] target=${CONN} graph=${GRAPH} dir=${DB_DIR}"

# 1) Tunggu Virtuoso siap.
echo -n "[loader] menunggu Virtuoso siap"
ready=0
for _ in $(seq 1 60); do
  if isql_exec "status();" >/dev/null 2>&1; then ready=1; echo " -> siap"; break; fi
  echo -n "."; sleep 2
done
if [ "${ready}" -ne 1 ]; then
  echo ""
  echo "[loader] Virtuoso tidak merespons; load dilewati (backend pakai endpoint publik)."
  exit 0
fi

# 2) Idempoten: lewati bila graph sasaran sudah berisi triple.
count="$(isql_exec "SPARQL SELECT (COUNT(*) AS ?c) WHERE { GRAPH <${GRAPH}> { ?s ?p ?o } };" 2>/dev/null \
          | grep -Eo '^[0-9]+$' | head -1)"
count="${count:-0}"
if [ "${count}" -gt 0 ] 2>/dev/null; then
  echo "[loader] graph <${GRAPH}> sudah berisi ${count} triple; load dilewati."
  exit 0
fi

# 3) Bersihkan daftar load lama agar tidak menumpuk entri gagal/duplikat.
isql_exec "DELETE FROM DB.DBA.LOAD_LIST;" >/dev/null 2>&1 || true

# 4) Daftarkan SETIAP *.ttl secara eksplisit ke GRAPH (mengabaikan sidecar .graph).
echo "[loader] mendaftarkan *.ttl dari ${DB_DIR} -> <${GRAPH}> (sidecar .graph diabaikan) ..."
isql_exec "
  DECLARE arr ANY;
  DECLARE i INT;
  arr := sys_dirlist('${DB_DIR}', 1);
  i := 0;
  WHILE (i < length(arr)) {
    DECLARE fn VARCHAR;
    fn := arr[i];
    IF (fn LIKE '%.ttl') {
      ld_add('${DB_DIR}/' || fn, '${GRAPH}');
    }
    i := i + 1;
  }
" || {
  echo "[loader] gagal mendaftarkan file; cek isi ${DB_DIR} (harus ada *.ttl)."
}

# 5) Jalankan loader & checkpoint.
isql_exec "rdf_loader_run(); checkpoint;" || {
  echo "[loader] rdf_loader_run mengembalikan error; cek dump di data/cskg_dumps/."
}

# 6) Laporkan error loader (kosong = sukses) dan jumlah triple akhir DI GRAPH yang benar.
echo "[loader] error loader (kosong = sukses):"
isql_exec "SELECT ll_file, ll_error FROM DB.DBA.LOAD_LIST WHERE ll_error IS NOT NULL;" || true
echo "[loader] jumlah triple di <${GRAPH}>:"
isql_exec "SPARQL SELECT (COUNT(*) AS ?c) WHERE { GRAPH <${GRAPH}> { ?s ?p ?o } };" || true

echo "[loader] selesai. Endpoint lokal: http://localhost:8890/sparql (default-graph ${GRAPH})."
echo "[loader] CATATAN: cadangan lokal hanya berisi CWE/CAPEC/snortrule (cve.ttl & cpe.ttl"
echo "[loader]          tidak di-push). Pertanyaan CVE-centric tetap mengandalkan SEPSES publik,"
echo "[loader]          KECUALI subset CVE demo dimuat (lihat data/cskg_dumps/cve_demo.ttl bila ada)."
exit 0