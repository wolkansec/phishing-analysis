# Phishing Analiz Adımları (Workflow)

---

<details>
<summary><strong>Adım 1: Hazırlık ve Güvenlik</strong></summary>
<ul>
<li>Analizin izole bir sanal makinede yapılması.</li>
<li>Gerekli araçlara (VT, AbuseIPDB, sandbox vs.) erişimin olması.</li>
<li>E-postanın ".eml" veya ".msg" formatında alınması.</li>
</ul>
</details>

---

<details>
<summary><strong>Adım 2: İlk Analiz / Görsel İnceleme</strong></summary>
<ul>
<li>"Gönderen" Adres tanıdık mı? Eşleşme var mı?</li>
<li>"Konu" Beklenmedik, acil veya tehditkar mı?</li>
<li>İçerik Kısmında yazım hataları, acele ettirme gibi belirtiler var mı?</li>
<li>"Bağlantılar" Farenin üstüne gelerek (tıklamadan) gerçek URL’nin görülmesi.</li>
</ul>
</details>

---

<details>
<summary><strong>Adım 3: Header Analizi</strong></summary>
<ul>
<li>Başlıkların çıkarılıp MxToolbox / Google Messageheader veya manuel olarak analiz edilmesi.</li>
<li>"Received" Satırlarını alttan üste izlemek ve kaynak IP’nin bulunması.</li>
<li>IP'nin AbuseIPDB, VT veya OTX ile kontrol edilmesi.</li>
<li>SPF, DKIM, DMARC sonuçlarının incelenmesi.</li>
<li>From / Reply-To / Return-Path alanlarının karşılaştırılması.</li>
</ul>
</details>

---

<details>
<summary><strong>Adım 4: Mesaj İçeriği Analizi</strong></summary>
<ul>
<li>Sosyal mühendislik belirtilerinin tespit edilmesi.</li>
<li>Bilgi taleplerinin belirlenmesi.</li>
<li>Tüm URL’lerin çıkarılması.</li>
</ul>
</details>

---

<details>
<summary><strong>Adım 5: URL Analizi</strong></summary>
<ul>
<li>Tüm bağlantıların listelenip, defang edilmesi.</li>
<li>URL / domain'lerin VT, URLhaus, OTX üzerinden kontrol edilmesi.</li>
<li>Kısaltılmış linklerin açığa çıkarılması (expander).</li>
<li>URLScan.io ile sayfanın ekran görüntüsünün alınması.</li>
</ul>
</details>

---

<details>
<summary><strong>Adım 6: Attachment Analizi</strong></summary>
<ul>
<li>Kesinlikle doğrudan açılmamalı!</li>
<li>Dosyanın <code>MD5</code> / <code>SHA256</code> hash değerinin hesaplanması.</li>
<li>Hash'in VT veya OTX üzerinden kontrol edilmesi.</li>
<li>Gerekirse statik analizin yapılması veya sandbox ortamında çalıştırılması (Any.Run, Triage).</li>
</ul>
</details>

---

<details>
<summary><strong>Adım 7: IoC Çıkarma ve Sonuç</strong></summary>
<ul>
<li>Toplanılacak IoC'ler:
    <ul>
        <li>Kötü amaçlı IP'ler</li>
        <li>Alan adları / URL'ler</li>
        <li>Dosya hashleri</li>
        <li>E-posta adresleri</li>
        <li>Konu başlıkları</li>
    </ul>
</li>
<li>E-postanın nihai durumunun belirlenmesi: <code>Malicious</code> / <code>Suspicious</code> / <code>Legitimate</code></li>
<li>Kısa bir özet yazılması: neden bu sonuca vardığı ile ilgili.</li>
</ul>
</details>

---

<details>
<summary><strong>Adım 8: Raporlama ve Dokümantasyon</strong></summary>
<ul>
<li>Tespit edilen IoC'lerin düzenli şekilde belgelenmesi.</li>
<li>Kurum prosedürüne göre raporlanması veya engelleme işlemlerinin başlatılması.</li>
</ul>
</details>
