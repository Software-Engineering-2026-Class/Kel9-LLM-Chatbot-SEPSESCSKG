"""
report_generator.py — Menghasilkan laporan evaluasi LLM dalam format Markdown.

Laporan mencakup:
  1. Executive Summary
  2. Tabel perbandingan skor per model
  3. Analisis per kategori (use-case)
  4. Analisis halusinasi
  5. Perbandingan waktu respons
  6. Analisis per pertanyaan
  7. Kesimpulan dan rekomendasi
"""
from __future__ import annotations

import csv
import os
from datetime import datetime
from typing import Any, Dict, List

from evaluation.scoring import aggregate_scores


# ─────────────────────────────────────────────
# Helper
# ─────────────────────────────────────────────

def _fmt(val: Any, decimals: int = 2) -> str:
    """Format angka untuk tabel markdown."""
    if isinstance(val, float):
        return f"{val:.{decimals}f}"
    return str(val)


def _bar(score: float, max_score: float = 2.0, length: int = 10) -> str:
    """Visual bar sederhana untuk markdown."""
    filled = int((score / max_score) * length) if max_score else 0
    return "█" * filled + "░" * (length - filled)


def _category_label(cat: str) -> str:
    """Label human-readable untuk kategori."""
    labels = {
        "threat_intelligence": "Threat Intelligence (CSKG)",
        "log_analysis": "Security Log Analysis",
        "combined": "Log Analysis + CSKG (Combined)",
    }
    return labels.get(cat, cat)


# ─────────────────────────────────────────────
# Report Generation
# ─────────────────────────────────────────────

def generate_report(
    results: List[Dict[str, Any]],
    models: List[str],
    output_path: str = "evaluation/evaluation_report.md",
) -> str:
    """
    Buat laporan evaluasi dalam format Markdown.

    Parameters
    ----------
    results : list[dict]
        Semua hasil evaluasi per pertanyaan per model.
    models : list[str]
        Daftar nama model yang dibandingkan.
    output_path : str
        Path file output markdown.

    Returns
    -------
    str — path file laporan yang ditulis.
    """
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines: List[str] = []

    def w(text: str = ""):
        lines.append(text)

    # ── Header ──
    w("# 📊 Laporan Evaluasi Perbandingan LLM")
    w()
    w(f"**Tanggal:** {now}  ")
    w(f"**Model yang dibandingkan:** {', '.join(models)}  ")
    w(f"**Total pertanyaan:** {len(results) // max(len(models), 1)}  ")
    w(f"**Kategori use-case:** Threat Intelligence, Log Analysis, Combined  ")
    w()
    w("---")
    w()

    # ══════════════════════════════════════════
    # 1. Executive Summary
    # ══════════════════════════════════════════
    w("## 1. Executive Summary")
    w()

    by_model = aggregate_scores(results, group_by="model")

    # Tentukan pemenang
    best_model = max(
        by_model.keys(),
        key=lambda m: by_model[m].get("composite_score", 0),
    ) if by_model else "N/A"

    w(f"**Model terbaik secara keseluruhan:** `{best_model}`  ")
    w()

    for model, agg in by_model.items():
        composite = agg.get("composite_score", 0)
        w(f"- **{model}**: Composite Score = **{_fmt(composite)}**/2.00 "
          f"| Error Rate = {_fmt(agg.get('error_rate', 0) * 100, 1)}%")
    w()
    w("---")
    w()

    # ══════════════════════════════════════════
    # 2. Tabel Perbandingan Skor per Model
    # ══════════════════════════════════════════
    w("## 2. Perbandingan Skor per Model")
    w()
    w("| Metrik | " + " | ".join(models) + " |")
    w("|--------|" + "|".join(["--------"] * len(models)) + "|")

    metric_rows = [
        ("Avg Accuracy (0–2)", "avg_accuracy"),
        ("Avg Hallucination (0–2)¹", "avg_hallucination"),
        ("Avg Relevance (0–2)", "avg_relevance"),
        ("Avg Completeness (0–2)", "avg_completeness"),
        ("Avg KG Grounding (%)", "avg_kg_grounding"),
        ("Avg Latency (sec)", "avg_latency_sec"),
        ("Error Count", "error_count"),
        ("Error Rate", "error_rate"),
        ("Fabricated CVEs", "total_fabricated_cves"),
        ("**Composite Score**", "composite_score"),
    ]

    for label, key in metric_rows:
        vals = []
        for m in models:
            v = by_model.get(m, {}).get(key, 0)
            if key == "avg_kg_grounding":
                vals.append(f"{_fmt(v * 100, 1)}%")
            elif key == "error_rate":
                vals.append(f"{_fmt(v * 100, 1)}%")
            else:
                vals.append(_fmt(v))
        w(f"| {label} | " + " | ".join(vals) + " |")

    w()
    w("> ¹ Skor hallucination: **2 = tidak ada halusinasi** (bagus), "
      "0 = banyak fabrikasi (buruk)")
    w()
    w("---")
    w()

    # ══════════════════════════════════════════
    # 3. Analisis per Kategori (Use-Case)
    # ══════════════════════════════════════════
    w("## 3. Analisis per Kategori Use-Case")
    w()

    categories = ["threat_intelligence", "log_analysis", "combined"]

    for cat in categories:
        cat_results = [r for r in results if r.get("category") == cat]
        if not cat_results:
            continue

        w(f"### 3.{categories.index(cat) + 1}. {_category_label(cat)}")
        w()

        by_model_cat = aggregate_scores(cat_results, group_by="model")

        w("| Model | Accuracy | Hallucination | Relevance | Completeness | Composite |")
        w("|-------|----------|---------------|-----------|--------------|-----------|")

        for m in models:
            agg = by_model_cat.get(m, {})
            w(f"| {m} "
              f"| {_fmt(agg.get('avg_accuracy', 0))} "
              f"| {_fmt(agg.get('avg_hallucination', 0))} "
              f"| {_fmt(agg.get('avg_relevance', 0))} "
              f"| {_fmt(agg.get('avg_completeness', 0))} "
              f"| **{_fmt(agg.get('composite_score', 0))}** |")

        w()

    w("---")
    w()

    # ══════════════════════════════════════════
    # 4. Analisis Halusinasi
    # ══════════════════════════════════════════
    w("## 4. Analisis Halusinasi")
    w()

    for m in models:
        m_results = [r for r in results if r.get("model") == m]
        fab_list = [
            r.get("fabricated_cves", "")
            for r in m_results
            if r.get("fabricated_cves")
        ]
        avg_hall = by_model.get(m, {}).get("avg_hallucination", 0)
        total_fab = by_model.get(m, {}).get("total_fabricated_cves", 0)

        w(f"### {m}")
        w(f"- Avg Hallucination Score: **{_fmt(avg_hall)}**/2.00 "
          f"{_bar(avg_hall)}")
        w(f"- Total CVE Fabrications: **{total_fab}**")
        if fab_list:
            w(f"- Fabricated CVEs: {'; '.join(fab_list)}")
        w()

    w("---")
    w()

    # ══════════════════════════════════════════
    # 5. Perbandingan Waktu Respons
    # ══════════════════════════════════════════
    w("## 5. Perbandingan Waktu Respons")
    w()
    w("| Model | Avg Latency (s) | Min (s) | Max (s) |")
    w("|-------|----------------|---------|---------|")

    for m in models:
        m_results = [r for r in results if r.get("model") == m]
        lats = [r.get("latency_sec", 0) for r in m_results if r.get("latency_sec")]
        if lats:
            w(f"| {m} | {_fmt(sum(lats)/len(lats))} "
              f"| {_fmt(min(lats))} | {_fmt(max(lats))} |")
        else:
            w(f"| {m} | N/A | N/A | N/A |")

    w()
    w("---")
    w()

    # ══════════════════════════════════════════
    # 6. Detail per Pertanyaan
    # ══════════════════════════════════════════
    w("## 6. Detail per Pertanyaan")
    w()

    # Group by question ID
    q_ids = []
    seen = set()
    for r in results:
        qid = r.get("question_id", "")
        if qid not in seen:
            q_ids.append(qid)
            seen.add(qid)

    for qid in q_ids:
        q_results = [r for r in results if r.get("question_id") == qid]
        if not q_results:
            continue

        q_text = q_results[0].get("question", "")
        q_cat = q_results[0].get("category", "")

        w(f"### {qid}: {q_text}")
        w(f"*Kategori: {_category_label(q_cat)}*")
        w()
        w("| Model | Acc | Hall | Rel | Comp | KG% | Latency | Error |")
        w("|-------|-----|------|-----|------|-----|---------|-------|")

        for r in q_results:
            kg_pct = f"{r.get('kg_grounding', 0) * 100:.0f}%"
            lat = _fmt(r.get("latency_sec", 0))
            err = "✅" if not r.get("is_error") else "❌"
            w(f"| {r.get('model', '')} "
              f"| {r.get('accuracy', 0)} "
              f"| {r.get('hallucination', 0)} "
              f"| {r.get('relevance', 0)} "
              f"| {r.get('completeness', 0)} "
              f"| {kg_pct} "
              f"| {lat}s "
              f"| {err} |")

        w()

        # Tampilkan cuplikan jawaban
        for r in q_results:
            snippet = (r.get("answer", "") or "")[:300]
            if snippet:
                w(f"<details><summary>Jawaban {r.get('model', '')} (cuplikan)</summary>")
                w()
                w(f"```")
                w(snippet)
                w(f"```")
                w()
                w("</details>")
                w()

    w("---")
    w()

    # ══════════════════════════════════════════
    # 7. Kesimpulan dan Rekomendasi
    # ══════════════════════════════════════════
    w("## 7. Kesimpulan dan Rekomendasi")
    w()

    # Hitung pemenang per kategori
    for cat in categories:
        cat_results = [r for r in results if r.get("category") == cat]
        if not cat_results:
            continue
        by_m = aggregate_scores(cat_results, group_by="model")
        winner = max(by_m.keys(), key=lambda m: by_m[m].get("composite_score", 0))
        w(f"- **{_category_label(cat)}**: Model terbaik → `{winner}` "
          f"(Composite: {_fmt(by_m[winner].get('composite_score', 0))})")

    w()
    w(f"**Overall Winner: `{best_model}`**")
    w()

    # Rekomendasi berdasarkan hasil
    w("### Rekomendasi")
    w()

    for m in models:
        agg = by_model.get(m, {})
        w(f"#### {m}")
        if agg.get("error_rate", 0) > 0.5:
            w(f"- ⚠️ Error rate tinggi ({_fmt(agg['error_rate'] * 100, 1)}%). "
              "Periksa API key, quota, atau koneksi.")
        if agg.get("avg_hallucination", 2) < 1.0:
            w("- ⚠️ Tingkat halusinasi tinggi. Model cenderung "
              "memfabrikasi data (CVE/CWE palsu).")
        if agg.get("avg_accuracy", 0) >= 1.5:
            w("- ✅ Akurasi baik — jawaban sesuai konteks KG.")
        if agg.get("avg_latency_sec", 0) > 30:
            w("- ⏱️ Latency tinggi. Pertimbangkan model lebih ringan "
              "atau optimasi prompt.")
        if agg.get("composite_score", 0) >= 1.5:
            w("- 🏆 Performa keseluruhan baik untuk production use.")
        w()

    w("---")
    w()
    w(f"*Laporan ini dihasilkan secara otomatis pada {now}*")

    # ── Tulis file ──
    report_text = "\n".join(lines)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write(report_text)

    return output_path


def generate_summary_csv(
    results: List[Dict[str, Any]],
    models: List[str],
    output_path: str = "evaluation/evaluation_summary.csv",
) -> str:
    """
    Buat CSV ringkasan agregat per model dan per kategori.
    """
    # Per model
    by_model = aggregate_scores(results, group_by="model")
    # Per category
    by_category = aggregate_scores(results, group_by="category")

    fieldnames = [
        "group_type", "group_name",
        "total_questions", "error_count", "error_rate",
        "avg_accuracy", "avg_hallucination",
        "avg_relevance", "avg_completeness",
        "avg_kg_grounding", "avg_latency_sec",
        "total_fabricated_cves", "composite_score",
    ]

    rows = []
    for model, agg in by_model.items():
        row = {"group_type": "model", "group_name": model}
        row.update(agg)
        rows.append(row)

    for cat, agg in by_category.items():
        row = {"group_type": "category", "group_name": cat}
        row.update(agg)
        rows.append(row)

    os.makedirs(os.path.dirname(output_path) or ".", exist_ok=True)
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames, extrasaction="ignore")
        writer.writeheader()
        writer.writerows(rows)

    return output_path
