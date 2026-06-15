"""
llm_eval.py — Pipeline evaluasi utama.

Membandingkan 2 LLM (Gemini 2.5 Flash vs Ollama Llama 3.2:3b)
menggunakan orchestrator.compare() dengan 3 mode:
  1. threat_intelligence  — KG / CSKG
  2. log_analysis          — analisis log keamanan
  3. combined              — log + CSKG

Setiap jawaban diskor multi-metrik via scoring.py.
"""
from __future__ import annotations

import csv
import os
import sys
import time
from typing import Any, Dict, List

# ── Path setup ──
sys.path.insert(
    0,
    os.path.dirname(
        os.path.dirname(os.path.abspath(__file__))
    ),
)

from evaluation.questions import EVALUATION_SET
from evaluation.scoring import evaluate_answer
from backend.pipeline.orchestrator import compare


# ─────────────────────────────────────────────
# Konfigurasi
# ─────────────────────────────────────────────

MODELS = [
    "gemini-2.5-flash",
    "ollama:llama3.2:3b",
]

# Delay antar pertanyaan untuk menghindari rate-limit (detik)
DELAY_BETWEEN_QUESTIONS = 4

# Path output
OUTPUT_DIR = os.path.dirname(os.path.abspath(__file__))
RESULT_CSV = os.path.join(OUTPUT_DIR, "evaluation_result.csv")


# ─────────────────────────────────────────────
# Fungsi Evaluasi Utama
# ─────────────────────────────────────────────

def run_evaluation() -> List[Dict[str, Any]]:
    """
    Jalankan evaluasi lengkap untuk semua pertanyaan di EVALUATION_SET.

    Returns
    -------
    list[dict] — Semua hasil evaluasi per pertanyaan per model,
                 siap ditulis ke CSV atau diolah.
    """
    results: List[Dict[str, Any]] = []
    total = len(EVALUATION_SET)

    print("=" * 70)
    print("  LLM EVALUATION — Gemini 2.5 Flash vs Ollama Llama 3.2:3b")
    print("=" * 70)
    print(f"  Total pertanyaan : {total}")
    print(f"  Model            : {', '.join(MODELS)}")
    print(f"  Delay per soal   : {DELAY_BETWEEN_QUESTIONS}s")
    print("=" * 70)

    for idx, q_meta in enumerate(EVALUATION_SET, 1):
        qid = q_meta["id"]
        question = q_meta["question"]
        mode = q_meta["mode"]
        category = q_meta["category"]

        print(f"\n[{idx}/{total}] {qid}: {question}")
        print(f"  Mode: {mode} | Category: {category}")

        # ── Panggil orchestrator.compare() ──
        try:
            outputs = compare(
                question,
                models=MODELS,
                mode=mode,
            )
        except Exception as e:
            print(f"   compare() error: {e}")
            # Buat hasil error untuk semua model
            for m in MODELS:
                results.append(_error_result(q_meta, m, str(e)))
            continue

        # Ambil KG triples dari context
        kg = outputs.get("triples", [])
        sources = outputs.get("sources", [])
        sparql_used = outputs.get("sparql", "")

        print(f"  Sources: {sources}")
        print(f"  KG triples: {len(kg)}")

        # ── Skor setiap jawaban model ──
        for item in outputs.get("answers", []):
            model_name = item.get("model", "unknown")
            answer_text = item.get("message", "")
            latency = item.get("latencySec", 0.0)
            is_ok = item.get("ok", True)
            error_msg = item.get("error", "")

            # Evaluasi multi-metrik
            scores = evaluate_answer(
                answer_text,
                kg,
                q_meta,
            )

            result = {
                # Identitas pertanyaan
                "question_id": qid,
                "question": question,
                "category": category,
                "subcategory": q_meta.get("subcategory", ""),
                "mode": mode,

                # Identitas model
                "model": model_name,
                "llm_used": item.get("llmUsed", model_name),

                # Jawaban
                "answer": answer_text,

                # Skor
                "accuracy": scores["accuracy"],
                "hallucination": scores["hallucination"],
                "relevance": scores["relevance"],
                "completeness": scores["completeness"],
                "kg_grounding": scores["kg_grounding"],
                "fabricated_cves": scores["fabricated_cves"],
                "is_error": scores["is_error"],

                # Metadata
                "latency_sec": latency,
                "llm_ok": is_ok,
                "llm_error": error_msg or "",
                "kg_triple_count": len(kg),
                "sources": "; ".join(sources),
                "sparql_used": sparql_used or "",
            }

            results.append(result)

            _print_score_summary(model_name, scores, latency)

        # Rate-limit protection
        if idx < total:
            print(f"  ⏳ Delay {DELAY_BETWEEN_QUESTIONS}s...")
            time.sleep(DELAY_BETWEEN_QUESTIONS)

    return results


def _error_result(
    q_meta: Dict[str, Any],
    model: str,
    error: str,
) -> Dict[str, Any]:
    """Buat result dict untuk kasus error fatal."""
    return {
        "question_id": q_meta["id"],
        "question": q_meta["question"],
        "category": q_meta["category"],
        "subcategory": q_meta.get("subcategory", ""),
        "mode": q_meta["mode"],
        "model": model,
        "llm_used": model,
        "answer": f" FATAL ERROR: {error}",
        "accuracy": 0,
        "hallucination": 0,
        "relevance": 0,
        "completeness": 0,
        "kg_grounding": 0.0,
        "fabricated_cves": "",
        "is_error": True,
        "latency_sec": 0.0,
        "llm_ok": False,
        "llm_error": error,
        "kg_triple_count": 0,
        "sources": "",
        "sparql_used": "",
    }


def _print_score_summary(
    model: str,
    scores: Dict[str, Any],
    latency: float,
) -> None:
    """Cetak ringkasan skor ke console."""
    err_flag = "[ERROR]" if scores["is_error"] else "[OK]"
    print(
        f"  {err_flag} {model:30s} | "
        f"Acc={scores['accuracy']} "
        f"Hal={scores['hallucination']} "
        f"Rel={scores['relevance']} "
        f"Comp={scores['completeness']} "
        f"KG={scores['kg_grounding']:.0%} "
        f"| {latency:.1f}s"
    )
    if scores["fabricated_cves"]:
        print(f"     [WARN]  Fabricated CVEs: {scores['fabricated_cves']}")


# ─────────────────────────────────────────────
# CSV Writer
# ─────────────────────────────────────────────

CSV_FIELDNAMES = [
    "question_id", "question", "category", "subcategory", "mode",
    "model", "llm_used",
    "accuracy", "hallucination", "relevance", "completeness",
    "kg_grounding", "fabricated_cves", "is_error",
    "latency_sec", "llm_ok", "llm_error",
    "kg_triple_count", "sources", "sparql_used",
    "answer",
]


def save_results_csv(
    results: List[Dict[str, Any]],
    path: str = RESULT_CSV,
) -> str:
    """Tulis hasil evaluasi ke CSV."""
    if not results:
        print("Tidak ada hasil untuk ditulis ke CSV.")
        return path

    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)

    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(
            f,
            fieldnames=CSV_FIELDNAMES,
            extrasaction="ignore",
        )
        writer.writeheader()
        writer.writerows(results)

    print(f"\nHasil evaluasi ditulis ke: {path}")
    return path