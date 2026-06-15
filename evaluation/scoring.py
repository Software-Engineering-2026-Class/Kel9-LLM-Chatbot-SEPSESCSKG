"""
scoring.py — Multi-metric scoring engine untuk evaluasi LLM.

Setiap metrik menggunakan skala 0–2:
  0 = buruk / error
  1 = parsial / umum
  2 = baik / lengkap

Modul ini murni logika scoring, tidak memanggil LLM atau data source.
"""
from __future__ import annotations

import re
from typing import Any, Dict, List, Optional

# ── regex untuk mendeteksi CVE yang mungkin difabrikasi ──
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)

# CVE-ID terkenal yang dianggap valid (ground truth umum)
_WELL_KNOWN_CVES = {
    "CVE-2021-44228",  # Log4Shell
    "CVE-2021-45046",  # Log4j follow-up
    "CVE-2021-45105",  # Log4j follow-up
    "CVE-2017-0144",   # EternalBlue
    "CVE-2019-0708",   # BlueKeep
    "CVE-2014-0160",   # Heartbleed
    "CVE-2017-5638",   # Apache Struts
    "CVE-2014-6271",   # Shellshock
    "CVE-2021-34527",  # PrintNightmare
    "CVE-2020-1472",   # Zerologon
    "CVE-2022-22965",  # Spring4Shell
    "CVE-2021-26855",  # ProxyLogon
    "CVE-2021-27065",  # ProxyLogon chain
    "CVE-2023-44228",  # known
    "CVE-2021-4034",   # PwnKit
    "CVE-2022-30190",  # Follina
}


# ─────────────────────────────────────────────
# Helper Internal
# ─────────────────────────────────────────────

def _normalize(text: str) -> str:
    """Lowercase dan bersihkan whitespace berlebih."""
    return " ".join((text or "").lower().split())


def _count_keyword_hits(text: str, keywords: List[str]) -> int:
    """Hitung berapa keyword yang muncul di teks."""
    t = _normalize(text)
    return sum(1 for kw in keywords if kw.lower() in t)


def _is_error_response(answer: str) -> bool:
    """Deteksi apakah jawaban adalah pesan error dari LLM."""
    markers = [
        "gagal menjawab",
        "error code: 429",
        "resource_exhausted",
        "quota exceeded",
        "connection refused",
        "timed out",
        "model not found",
    ]
    a = _normalize(answer)
    return any(m in a for m in markers)


# ─────────────────────────────────────────────
# Scoring Functions
# ─────────────────────────────────────────────

def score_accuracy(
    answer: str,
    kg_rows: List[Dict[str, str]],
    expected_entities: List[str],
) -> int:
    """
    Skor akurasi jawaban (0–2).

    0 = error / tidak menjawab
    1 = jawaban generik tanpa data KG
    2 = menggunakan entitas KG / expected entities dengan benar
    """
    if not answer or _is_error_response(answer):
        return 0

    a = _normalize(answer)

    # Cek apakah expected entities muncul di jawaban
    entity_hits = _count_keyword_hits(answer, expected_entities)

    # Cek apakah entitas KG muncul di jawaban
    kg_hit = False
    if kg_rows:
        kg_hit = any(
            isinstance(v, str) and v.lower() in a
            for row in kg_rows
            for v in row.values()
        )

    if entity_hits >= 2 or kg_hit:
        return 2
    elif entity_hits >= 1 or len(answer.strip()) > 100:
        return 1
    else:
        return 0


def score_hallucination(
    answer: str,
    kg_rows: List[Dict[str, str]],
    ground_truth_keywords: List[str],
) -> int:
    """
    Skor hallucination (0–2). SKOR TINGGI = BAGUS (sedikit halusinasi).

    0 = banyak fabrikasi (CVE palsu, info salah)
    1 = sebagian spekulatif
    2 = tidak ada fabrikasi, grounded
    """
    if not answer or _is_error_response(answer):
        return 0

    # Deteksi CVE yang difabrikasi
    fabricated = detect_fabricated_cves(answer)
    fabricated_count = len(fabricated)

    # Cek grounding terhadap ground truth
    gt_hits = _count_keyword_hits(answer, ground_truth_keywords)
    gt_ratio = gt_hits / max(len(ground_truth_keywords), 1)

    if fabricated_count >= 2:
        return 0  # Banyak fabrikasi
    elif fabricated_count == 1 or gt_ratio < 0.2:
        return 1  # Sebagian spekulatif
    else:
        return 2  # Grounded, tidak ada fabrikasi


def score_relevance(
    answer: str,
    question: str,
    ground_truth_keywords: List[str],
) -> int:
    """
    Skor relevansi jawaban terhadap pertanyaan (0–2).

    0 = off-topic / error
    1 = sebagian relevan
    2 = langsung menjawab pertanyaan
    """
    if not answer or _is_error_response(answer):
        return 0

    # Cek keyword pertanyaan muncul di jawaban
    q_words = [w for w in question.lower().split() if len(w) > 3]
    q_hits = _count_keyword_hits(answer, q_words)
    q_ratio = q_hits / max(len(q_words), 1)

    # Cek ground truth keywords
    gt_hits = _count_keyword_hits(answer, ground_truth_keywords)
    gt_ratio = gt_hits / max(len(ground_truth_keywords), 1)

    combined = (q_ratio + gt_ratio) / 2

    if combined >= 0.4:
        return 2
    elif combined >= 0.15:
        return 1
    else:
        return 0


def score_completeness(
    answer: str,
    expected_entities: List[str],
) -> int:
    """
    Skor kelengkapan jawaban (0–2).

    0 = kosong / error
    1 = sebagian entitas tercakup
    2 = mayoritas entitas tercakup
    """
    if not answer or _is_error_response(answer):
        return 0

    hits = _count_keyword_hits(answer, expected_entities)
    ratio = hits / max(len(expected_entities), 1)

    if ratio >= 0.5:
        return 2
    elif ratio >= 0.2:
        return 1
    else:
        return 0


def compute_kg_grounding(
    answer: str,
    expected_entities: List[str],
) -> float:
    """
    Hitung persentase expected_entities yang ditemukan dalam jawaban.

    Returns: float 0.0 – 1.0
    """
    if not answer or not expected_entities:
        return 0.0

    hits = _count_keyword_hits(answer, expected_entities)
    return round(hits / len(expected_entities), 4)


def detect_fabricated_cves(answer: str) -> List[str]:
    """
    Deteksi CVE-ID dalam jawaban yang kemungkinan difabrikasi.

    Mengembalikan list CVE-ID yang TIDAK termasuk well-known CVEs.
    """
    if not answer:
        return []

    found = _CVE_RE.findall(answer)
    return [
        cve.upper()
        for cve in found
        if cve.upper() not in _WELL_KNOWN_CVES
    ]


# ─────────────────────────────────────────────
# Evaluasi Lengkap per Jawaban
# ─────────────────────────────────────────────

def evaluate_answer(
    answer: str,
    kg_rows: List[Dict[str, str]],
    question_meta: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Evaluasi lengkap satu jawaban LLM.

    Parameters
    ----------
    answer : str
        Teks jawaban dari LLM.
    kg_rows : list[dict]
        Baris triple KG dari context retrieval.
    question_meta : dict
        Metadata pertanyaan dari EVALUATION_SET, berisi:
        - expected_entities, ground_truth_keywords, question, dll.

    Returns
    -------
    dict dengan key: accuracy, hallucination, relevance, completeness,
         kg_grounding, fabricated_cves, is_error
    """
    expected = question_meta.get("expected_entities", [])
    gt_kw = question_meta.get("ground_truth_keywords", [])
    question = question_meta.get("question", "")

    is_err = _is_error_response(answer)
    fabricated = detect_fabricated_cves(answer)

    return {
        "accuracy": score_accuracy(answer, kg_rows, expected),
        "hallucination": score_hallucination(answer, kg_rows, gt_kw),
        "relevance": score_relevance(answer, question, gt_kw),
        "completeness": score_completeness(answer, expected),
        "kg_grounding": compute_kg_grounding(answer, expected),
        "fabricated_cves": ", ".join(fabricated) if fabricated else "",
        "is_error": is_err,
    }


# ─────────────────────────────────────────────
# Agregasi Skor
# ─────────────────────────────────────────────

def aggregate_scores(
    results: List[Dict[str, Any]],
    group_by: str = "model",
) -> Dict[str, Dict[str, Any]]:
    """
    Agregasi skor per group (biasanya per model atau per category).

    Parameters
    ----------
    results : list[dict]
        List of result dicts (output dari evaluate_answer + metadata).
    group_by : str
        Key untuk grouping ("model" atau "category").

    Returns
    -------
    dict[str, dict] — key = group value, value = aggregated metrics.
    """
    from collections import defaultdict

    groups: Dict[str, List[Dict[str, Any]]] = defaultdict(list)
    for r in results:
        key = r.get(group_by, "unknown")
        groups[key].append(r)

    aggregated = {}
    for key, items in groups.items():
        n = len(items)
        if n == 0:
            continue

        error_count = sum(1 for i in items if i.get("is_error", False))

        metrics = {
            "total_questions": n,
            "error_count": error_count,
            "error_rate": round(error_count / n, 4),
        }

        # Rata-rata setiap skor metrik
        for metric in ("accuracy", "hallucination", "relevance", "completeness"):
            values = [i.get(metric, 0) for i in items]
            metrics[f"avg_{metric}"] = round(sum(values) / n, 4)
            metrics[f"max_{metric}"] = max(values)
            metrics[f"min_{metric}"] = min(values)

        # KG grounding rata-rata
        kg_vals = [i.get("kg_grounding", 0.0) for i in items]
        metrics["avg_kg_grounding"] = round(sum(kg_vals) / n, 4)

        # Latency rata-rata (jika ada)
        lat_vals = [i.get("latency_sec", 0.0) for i in items if i.get("latency_sec")]
        if lat_vals:
            metrics["avg_latency_sec"] = round(sum(lat_vals) / len(lat_vals), 3)
        else:
            metrics["avg_latency_sec"] = 0.0

        # Fabricated CVE total
        fab_count = sum(
            len(i.get("fabricated_cves", "").split(", "))
            for i in items
            if i.get("fabricated_cves")
        )
        metrics["total_fabricated_cves"] = fab_count

        # Composite score (weighted average)
        # accuracy=30%, hallucination=30%, relevance=20%, completeness=20%
        composite = (
            metrics["avg_accuracy"] * 0.30
            + metrics["avg_hallucination"] * 0.30
            + metrics["avg_relevance"] * 0.20
            + metrics["avg_completeness"] * 0.20
        )
        metrics["composite_score"] = round(composite, 4)

        aggregated[key] = metrics

    return aggregated
