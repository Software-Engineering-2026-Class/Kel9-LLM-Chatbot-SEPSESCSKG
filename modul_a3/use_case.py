import ssl
ssl._create_default_https_context = ssl._create_unverified_context

from modul_vulnerability import get_vuln_context
from modul_threat import get_threat_context, get_malware_context
from modul_logs import search_logs

print("USE CASE 1: Threat Intelligence & Vulnerability Analysis")

print(""" 
Skenario: Analis menerima laporan adanya serangan siber.
Tugasnya: profil threat actor, investigasi malware yang digunakan, dan analisis vulnerability yang dieksploitasi.
""")

print("[Step 1] Threat Actor Profiling (APT28)")
print(get_threat_context("APT28"))

print("[Step 2] Malware Investigation (WannaCry)")
print(get_malware_context("WannaCry"))

print("[Step 3] Vulnerability Relationship Analysis (CVE-2017-0144)")
print(get_vuln_context("CVE-2017-0144"))

print("""
[Kesimpulan Use Case 1]
APT28 (Fancy Bear) adalah kelompok APT asal Rusia yang aktif melakukan spionase siber. WannaCry adalah ransomware berbasis Windows yang mengeksploitasi CVE-2017-0144 (EternalBlue, CVSS 9.3).
Rekomendasi: patch MS17-010, block SMB port 445, monitor lateral movement.
""")

print("USE CASE 2: Security Log Analysis")

print("""
Skenario: Admin sistem melihat aktivitas tidak wajar di server.
Tugasnya: analisis log untuk menemukan pola serangan yang sedang terjadi.
""")

print("[Step 1] Deteksi aktivitas brute force...")
print(search_logs("failed password login attempt"))

print("[Step 2] Deteksi reverse shell...")
print(search_logs("reverse shell suspicious connection port 4444"))

print("[Step 3] Deteksi privilege escalation...")
print(search_logs("sudo privilege escalation unauthorized"))

print("""
[Kesimpulan Use Case 2]
Log menunjukkan 3 pola serangan aktif: brute force login, koneksi reverse shell ke port 4444, dan upaya privilege escalation via sudo.
Rekomendasi: block IP sumber, audit user sudo, tutup port 4444.
""")

print("USE CASE 3: Log Analysis + Global Threat Intelligence")
print("Skenario: Tim SOC menemukan log mencurigakan dan ingin mengkaitkan dengan threat intelligence global untuk memahami konteks serangan.")

print("[Step 1] Cari log mencurigakan terkait malware...")
log_result = search_logs("malware detected suspicious file")
print(log_result)

print("[Step 2] Threat intelligence malware terkait...")
threat_result = get_malware_context("WannaCry")
print(threat_result)

print("[Step 3] CVE yang mungkin dieksploitasi...")
vuln_result = get_vuln_context("CVE-2017-0144")
print(vuln_result)

print("""
[Kesimpulan Use Case 3]
Log deteksi malware di sistem berkorelasi dengan pola WannaCry. CVE-2017-0144 (CVSS 9.3) adalah vektor eksploitasi utama.
Rekomendasi: isolasi host, scan jaringan, patch segera.
""")

print("USE CASE 4: Threat Hunting (Korelasi Log + ATT&CK + CVE)")

print("""
Skenario: SOC analyst menemukan aktivitas mencurigakan di server.
Tugasnya: identifikasi apakah log ini terkait dengan threat actor yang diketahui dan cari CVE yang mungkin dieksploitasi.
""")

print("[Step 1] Temukan log anomali...")
log1 = search_logs("failed ssh login brute force")
log2 = search_logs("unauthorized access privilege escalation")
print(log1)
print(log2)

print("[Step 2] Threat actor yang dikenal pakai teknik ini...")
print(get_threat_context("Lazarus"))

print("[Step 3] CVE yang sering dieksploitasi teknik serupa...")
print(get_vuln_context("CVE-2018-12015"))

print("""
[Kesimpulan Use Case 4]
Log menunjukkan pola brute force SSH dan privilege escalation. Teknik ini konsisten dengan TTPs Lazarus Group. CVE-2018-12015 (path traversal, CVSS 6.4) bisa menjadi vektor masuk.
Rekomendasi: block IP mencurigakan, patch CVE, monitor sudo activity.
""")

print("USE CASE 5: Incident Response (Malware Outbreak Investigation)")

print("""
Skenario: Tim IR menerima laporan malware terdeteksi di jaringan.
Tugasnya: investigasi malware, cari log terkait, identifikasi vulnerability yang dieksploitasi, dan susun langkah respons.
""")

print("[Step 1] Investigasi malware yang terdeteksi...")
print(get_malware_context("WannaCry"))

print("[Step 2] Cari log terkait aktivitas malware di sistem...")
log3 = search_logs("malware signature detected suspicious file")
log4 = search_logs("reverse shell connection outbound port")
print(log3)
print(log4)

print("[Step 3] CVE yang dieksploitasi WannaCry...")
print(get_vuln_context("CVE-2017-0144"))

print("[Step 4] Threat actor yang mengoperasikan WannaCry...")
print(get_threat_context("Lazarus"))

print("""
[Kesimpulan Use Case 5]
Malware WannaCry terdeteksi mengeksploitasi CVE-2017-0144 (EternalBlue, CVSS 9.3).
Log menunjukkan koneksi reverse shell dan file mencurigakan di system32.
Lazarus Group (Korea Utara) diketahui mengoperasikan kampanye WannaCry.
Rekomendasi: isolasi host yang terinfeksi, patch MS17-010, block SMB port 445, scan seluruh jaringan untuk lateral movement.
""")