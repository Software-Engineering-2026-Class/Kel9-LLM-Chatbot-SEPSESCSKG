"""
Evaluasi tiga use-case end-to-end (Issue #6).

Berbeda dari `run_eval.py` (yang hanya menguji jalur NL2SPARQL via kg_retrieve),
skrip ini menguji PIPELINE PENUH lewat `orchestrator.answer()` untuk tiga
use-case yang diminta proyek:
  (a) threat_intelligence  — CSKG/MITRE (CVE->CWE->CAPEC, actor, malware)
  (b) log_analysis         — vector DB log lokal (brute-force SSH, SQLi)
  (c) combined             — korelasi log + threat-intel (Log4Shell, auth fail)

Untuk tiap kasus dicatat: mode, metode NL2SPARQL (bila terpakai), sumber data
yang tersentuh, jumlah triple KG, llm yang dipakai, latency, status, dan
cuplikan jawaban. Hasil disimpan ke CSV + JSON di folder ini.

Mode jalan:
  - default            : pakai LLM betulan (panggil Gemini/Ollama via answer()).
  - --dry-run          : hanya retrieval+router (orchestrator._collect_context),
                         TANPA memanggil LLM. Berguna saat tidak ada API key.

Contoh:
  python evaluation/run_eval_usecases.py
  python evaluation/run_eval_usecases.py --model ollama:llama3.2:3b
  python evaluation/run_eval_usecases.py --dry-run
"""
from __future__ import annotations

import argparse
import json
import time
from pathlib import Path
from typing import Any, Dict, List

from backend.config import DEFAULT_MODEL
from backend.pipeline.orchestrator import _collect_context, answer
from evaluation.questions import USECASE_CASES

OUT_DIR = Path(__file__).resolve().parent
CSV_PATH = OUT_DIR / "usecase_results.csv"
JSON_PATH = OUT_DIR / "usecase_results.json"
_PREVIEW = 280


def _sources_ok(expect: str, sources: List[str]) -> bool:
    """True bila tidak ada ekspektasi, atau salah satu sumber memuat substring."""
    if not expect:
        return True
    joined = " | ".join(sources).lower()
    return expect.lower() in joined


def _evaluate_one(case: Dict[str, str], model: str, dry_run: bool) -> Dict[str, Any]:
    question = case["question"]
    mode = case.get("mode", "threat_intelligence")
    start = time.perf_counter()
    try:
        if dry_run:
            ctx = _collect_context(question, mode, model)
            latency = round(time.perf_counter() - start, 3)
            sources = ctx.get("sources", [])
            ok = bool(ctx.get("context"))
            return {
                "id": case.get("id", ""),
                "usecase": case.get("usecase", ""),
                "mode": mode,
                "question": question,
                "expect_sources": case.get("expect_sources", ""),
                "sources": ", ".join(sources),
                "sources_ok": _sources_ok(case.get("expect_sources", ""), sources),
                "method": ctx.get("method") or "",
                "triple_count": len(ctx.get("triples", [])),
                "llm_used": "(dry-run, no LLM)",
                "status": "context_ok" if ok else "no_context",
                "latency": latency,
                "sparql": (ctx.get("sparql") or "")[:_PREVIEW].replace("\n", " "),
                "answer_preview": (ctx.get("context") or "")[:_PREVIEW].replace("\n", " "),
                "error": "",
            }

        # Jalur penuh: retrieval + LLM.
        res = answer(question, mode=mode, model=model)
        latency = round(time.perf_counter() - start, 3)
        sources = res.get("sources", [])
        msg = res.get("message", "") or ""
        # Heuristik gagal-LLM: pesan diawali tanda peringatan dari _synthesize.
        llm_failed = msg.startswith("⚠️")
        return {
            "id": case.get("id", ""),
            "usecase": case.get("usecase", ""),
            "mode": mode,
            "question": question,
            "expect_sources": case.get("expect_sources", ""),
            "sources": ", ".join(sources),
            "sources_ok": _sources_ok(case.get("expect_sources", ""), sources),
            "method": res.get("method") or "",
            "triple_count": len(res.get("triples", [])),
            "llm_used": res.get("llmUsed") or model,
            "status": "llm_error" if llm_failed else ("success" if msg.strip() else "empty"),
            "latency": latency,
            "sparql": (res.get("sparql") or "")[:_PREVIEW].replace("\n", " "),
            "answer_preview": msg[:_PREVIEW].replace("\n", " "),
            "error": msg[:_PREVIEW].replace("\n", " ") if llm_failed else "",
        }
    except Exception as e:  # answer() menjaring exception, tapi tetap aman
        return {
            "id": case.get("id", ""),
            "usecase": case.get("usecase", ""),
            "mode": mode,
            "question": question,
            "expect_sources": case.get("expect_sources", ""),
            "sources": "",
            "sources_ok": False,
            "method": "",
            "triple_count": 0,
            "llm_used": model,
            "status": "failed",
            "latency": round(time.perf_counter() - start, 3),
            "sparql": "",
            "answer_preview": "",
            "error": str(e)[:_PREVIEW],
        }


def _summarize(results: List[Dict[str, Any]]) -> Dict[str, Any]:
    n = len(results) or 1
    by_usecase: Dict[str, Dict[str, int]] = {}
    for r in results:
        uc = r["usecase"] or "n/a"
        d = by_usecase.setdefault(uc, {"total": 0, "ok": 0, "sources_ok": 0})
        d["total"] += 1
        if r["status"] in ("success", "context_ok"):
            d["ok"] += 1
        if r["sources_ok"]:
            d["sources_ok"] += 1
    ok = sum(1 for r in results if r["status"] in ("success", "context_ok"))
    src_ok = sum(1 for r in results if r["sources_ok"])
    avg_latency = round(sum(r["latency"] for r in results) / n, 3)
    return {
        "total": len(results),
        "ok": ok,
        "ok_rate": round(ok / n, 3),
        "sources_ok": src_ok,
        "sources_ok_rate": round(src_ok / n, 3),
        "by_usecase": by_usecase,
        "avg_latency_sec": avg_latency,
    }


def _save(results: List[Dict[str, Any]], summary: Dict[str, Any]) -> None:
    JSON_PATH.write_text(
        json.dumps({"summary": summary, "results": results}, indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    cols = ["id", "usecase", "mode", "question", "expect_sources", "sources",
            "sources_ok", "method", "triple_count", "llm_used", "status",
            "latency", "sparql", "answer_preview", "error"]
    try:
        import pandas as pd
        pd.DataFrame(results, columns=cols).to_csv(CSV_PATH, index=False)
    except Exception:
        import csv
        with open(CSV_PATH, "w", newline="", encoding="utf-8") as f:
            w = csv.DictWriter(f, fieldnames=cols)
            w.writeheader()
            for r in results:
                w.writerow({k: r.get(k, "") for k in cols})


def evaluate(model: str = DEFAULT_MODEL, dry_run: bool = False) -> Dict[str, Any]:
    label = "DRY-RUN (tanpa LLM)" if dry_run else f"LLM={model}"
    print(f"[eval6] Tiga use-case end-to-end pada {len(USECASE_CASES)} kasus ({label})\n")
    results = [_evaluate_one(c, model, dry_run) for c in USECASE_CASES]
    for i, r in enumerate(results, 1):
        flag = "OK " if r["sources_ok"] else "!! "
        print(f"{i:>2}. [{r['status']:^11}] {flag}{r['usecase']:<20} "
              f"src=[{r['sources']}] rows={r['triple_count']} {r['latency']}s")
        print(f"     Q: {r['question']}")
        if r["answer_preview"]:
            print(f"     A: {r['answer_preview']}")
        print()

    summary = _summarize(results)
    print("=== Ringkasan Issue #6 ===")
    print(f"ok {summary['ok']}/{summary['total']} (rate {summary['ok_rate']}), "
          f"sumber sesuai {summary['sources_ok']}/{summary['total']} "
          f"(rate {summary['sources_ok_rate']})")
    for uc, d in summary["by_usecase"].items():
        print(f"  - {uc:<20} ok {d['ok']}/{d['total']}, sumber {d['sources_ok']}/{d['total']}")
    print(f"latency rata-rata : {summary['avg_latency_sec']}s")

    _save(results, summary)
    print(f"\n[eval6] Hasil ditulis ke:\n  {CSV_PATH}\n  {JSON_PATH}")
    return {"summary": summary, "results": results}


def main(argv: "list[str] | None" = None) -> int:
    ap = argparse.ArgumentParser(description="Evaluasi tiga use-case (Issue #6).")
    ap.add_argument("--model", default=DEFAULT_MODEL,
                    help="Model LLM (mis. gemini:gemini-2.5-flash, ollama:llama3.2:3b).")
    ap.add_argument("--dry-run", action="store_true",
                    help="Hanya retrieval+router, tanpa memanggil LLM.")
    args = ap.parse_args(argv)
    evaluate(model=args.model, dry_run=args.dry_run)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())