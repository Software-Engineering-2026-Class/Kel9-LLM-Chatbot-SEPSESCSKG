from __future__ import annotations

from typing import Dict, List

TEST_CASES: List[Dict[str, str]] = [
    {"question": "Show information about CVE-2021-44228", "category": "cve", "expect": "regex"},
    {"question": "List vulnerabilities with critical severity", "category": "severity", "expect": "regex"},
    {"question": "Find attack patterns related to SQL Injection", "category": "capec", "expect": "llm"},
    {"question": "Show malware targeting Apache servers", "category": "general", "expect": "llm"},
    {"question": "Find techniques used by ransomware groups", "category": "general", "expect": "llm"},
    {"question": "Show CAPEC attack patterns", "category": "capec", "expect": "llm"},
    {"question": "List vulnerabilities related to buffer overflow", "category": "general", "expect": "llm"},
    {"question": "Find attack techniques targeting Windows systems", "category": "general", "expect": "llm"},
    {"question": "Show all published CVEs in 2021", "category": "general", "expect": "llm"},
    {"question": "Find relationships between CVE and CWE", "category": "cwe_relation", "expect": "llm"},
]
TEST_QUESTIONS: List[str] = [c["question"] for c in TEST_CASES]


USECASE_CASES: List[Dict[str, str]] = [
    # (a) Threat-intelligence dari CSKG/MITRE -------------------------------
    {
        "id": "ti_cve_chain",
        "usecase": "threat_intelligence",
        "mode": "threat_intelligence",
        "question": "Explain CVE-2021-44228 and its CWE -> CAPEC attack chain, "
                    "including CVSS score and mitigation.",
        "expect_sources": "SEPSES",
    },
    {
        "id": "ti_actor_profile",
        "usecase": "threat_intelligence",
        "mode": "threat_intelligence",
        "question": "Profile the threat actor Lazarus Group: aliases and typical behaviour.",
        "expect_sources": "MITRE",
    },
    {
        "id": "ti_malware_invest",
        "usecase": "threat_intelligence",
        "mode": "threat_intelligence",
        "question": "Investigate the malware Cobalt Strike and the platforms it targets.",
        "expect_sources": "MITRE",
    },
    # (b) Analisis log lokal (vector DB) -----------------------------------
    {
        "id": "log_ssh_bruteforce",
        "usecase": "log_analysis",
        "mode": "log_analysis",
        "question": "Are there signs of an SSH brute-force attack in the logs? "
                    "Which source IP is responsible?",
        "expect_sources": "Log keamanan",
    },
    {
        "id": "log_sqli",
        "usecase": "log_analysis",
        "mode": "log_analysis",
        "question": "Detect any SQL injection attempts in the web access logs and "
                    "identify the tool used.",
        "expect_sources": "Log keamanan",
    },
    # (c) Gabungan log + threat-intel (combined) ---------------------------
    {
        "id": "combined_log4shell",
        "usecase": "combined",
        "mode": "combined",
        "question": "An IDS alert mentions a Log4j exploit (CVE-2021-44228). "
                    "Correlate it with the knowledge graph and recommend mitigations.",
        "expect_sources": "SEPSES",
    },
    {
        "id": "combined_correlation",
        "usecase": "combined",
        "mode": "combined",
        "question": "Correlate suspicious authentication failures in the logs with "
                    "relevant attack techniques and weaknesses.",
        "expect_sources": "Log keamanan",
    },
]
USECASE_QUESTIONS: List[str] = [c["question"] for c in USECASE_CASES]