# Phishing Analizi (Oltalama Analizi)

Phishing (Oltalama), saldırganların ağlara ilk erişimi sağlamak, kimlik bilgilerini çalmak veya kötü amaçlı yazılım yaymak için kullandığı en yaygın sosyal mühendislik tekniklerinden biridir.  
Bir siber güvenlik analisti olarak, şüpheli e-postaları, bağlantıları (URL) ve ekleri analiz etme yeteneği, temel becerilerden biridir.

Phishing analizinin temel amacı, e-postanın kötü amaçlı olup olmadığını belirlemek ve eğer öyleyse, IoC verilerini çıkartmaktır.

---

## İncelenmesi Gereken Ana Unsurlar

Phishing analizi yaparken bir e-postanın aşağıdaki bölümleri incelenir:

### 1. E-posta Başlıkları (Headers)

E-posta başlıkları, e-postanın kimden geldiği, hangi sunuculardan geçtiği ve kimlik doğrulama sonuçları gibi önemli meta verileri içerir.

Dikkat edilmesi gereken başlıca alanlar:

- **`From:`** Kim e-postayı göndermiş görünüyor? Kolaylıkla sahte olabilir (spoofing).
- **`Reply-To:`** Yanıtların gönderileceği adres. Zararlı emaillerde genellikle `From` kısmından farklıdır.
- **`Return-Path:`** Teslim edilemeyen e-postaların döndüğü adres. Gerçek kaynağı gösterebilir.
- **`Received:`** E-postanın geçtiği sunucuların sıralı listesi (alttan üste doğru okunur).
- **`Authentication-Results:`** SPF, DKIM ve DMARC doğrulama sonuçlarını gösterir.

**SPF / DKIM / DMARC Nedir?**
- **SPF (Sender Policy Framework):** Gönderen IP’nin yetkili olup olmadığını kontrol eder. `FAIL` büyük bir uyarıdır.
- **DKIM (DomainKeys Identified Mail):** Mesajın değiştirilip değiştirilmediğini doğrular. `FAIL` manipülasyon ihtimalidir.
- **DMARC:** SPF veya DKIM başarısız olduğunda ne yapılacağını belirler (`reject`, `quarantine`, `none`). `FAIL` → genellikle sahte e-posta.

Ayrıca, `Received` satırlarında geçen kaynak IP adresi tespit edilip reputation testi yapılmalıdır.

---

### 2. 💬 E-posta İçeriği (Body)

E-postanın görünür kısmıdır. Aşağıdaki belirtiler genellikle oltalama belirtisidir:

- **Acil / Tehditkar İfadeler:** “Hesabınız kilitlenecek”, “Acil işlem gerekli”.
- **Yazım veya dilbilgisi hataları.**
- **Genel hitaplar:** “Değerli müşterimiz” gibi.
- **Olağandışı talepler:** Kimlik bilgisi, ödeme, dosya isteme.
- **Farklı tarz / biçim:** Gerçek kurumsal dilden farklı e-postalar.
- **Şüpheli bağlantılar (URLs):** Sonraki adımda analiz edilir.

---

### 3. 🔗 Bağlantılar (URLs)

Bağlantılar oltalama e-postalarının en kritik unsurlarındandır. Her zaman gerçek yönlendirme adresi kontrol edilmelidir.

Dikkat edilmesi gerekenler:
- **Aldatıcı alan adları:** `paypaI.com` (büyük “I”) gibi benzer yazımlar.
- **Alt alan adlarıyla kandırma:** `paypal.security-update.com`
- **Kısaltılmış linkler:** Bitly, TinyURL gibi servisler gerçek URL’yi gizleyebilir.
- **Direkt IP adresleri:** Gerçek servisler genelde IP ile link vermez.
- **Defanging (zararsız hale getirme):** Şüpheli linkleri paylaşırken `http` → `hxxp`, `.` → `[.]` ile değiştir.  
  Örnek: `hxxp://malicious-site[.]com/`

---

### 4. 📎 Ekler (Attachments)

E-postalardaki ekler kötü amaçlı yazılım taşımak için sıkça kullanılır.

Dikkat edilmesi gereken dosya türleri:
- **Tehlikeli uzantılar:** `.exe`, `.bat`, `.js`, `.ps1`, `.vbs`
- **Makro içeren Office dosyaları:** `.docm`, `.xlsm`, `.pptm` Uzantının sonunda `m` ifadesi olması içerisine makro kodunun eklendiğini belirtir!
- **Çift uzantı:** `invoice.pdf.exe`
- **Parola korumalı veya Arşiv dosyaları:** Genellikle antivirüsten kaçmak için kullanılır.
- **Analiz yöntemleri:** Şüpheli dosya asla doğrudan açılmamalı, hash değerlerinin çıkarılıpi sandbox ortamında analiz edilmesi gerekilir.

---

## 💡 IoC (İhlal Göstergeleri)

Analiz sonucunda elde edilebilecek IoC türleri:

- **IP Adresleri:** Kaynak veya kötü amaçlı sunucu.
- **Alan adları / URL’ler:** E-postada geçen veya yönlendiren bağlantılar.
- **Dosya hashleri:** MD5 / SHA1 / SHA256
- **E-posta adresleri:** `From`, `Reply-To`, `Return-Path`

---

## 🧰 Phishing Analizi İçin Gerekli Araçlar

Aşağıdaki araçlar, e-posta, URL, IP ve dosyaların güvenli bir şekilde analiz edilmesini sağlar.

### 🌐 İtibar Servisleri
- **[VirusTotal](https://www.virustotal.com/):** URL, IP, domain ve dosya hash analizi.
- **[URLhaus](https://urlhaus.abuse.ch/):** Zararlı bağlantı veri tabanı.
- **[AbuseIPDB](https://www.abuseipdb.com/):** IP adreslerinin kötüye kullanım kayıtları. IP Reputation için kullanılabilir.
- **[AlienVault OTX](https://otx.alienvault.com/):** Tehdit istihbaratı platformu (IoC, MITRE ATT&CK ilişkisi).

---

### 🔬 Sandbox Ortamları (Dinamik Analiz)
- **[Any.Run](https://any.run/):** Gerçek zamanlı etkileşimli analiz.
- **[Hybrid Analysis](https://www.hybrid-analysis.com/):** Statik + dinamik analiz, PCAP ve ekran görüntüsü sağlar.
- **[Triage](https://tria.ge/):** MITRE ATT&CK eşleşmeleriyle raporlama sağlar.
- **[Joe Sandbox](https://www.joesandbox.com/):** Gelişmiş davranış analizi.

---

### ✉️ Header Analizi Araçları
- **[MxToolbox Header Analyzer](https://mxtoolbox.com/EmailHeaders.aspx)**
- **[Google Admin Toolbox – Messageheader](https://toolbox.googleapps.com/apps/messageheader/)**

---

### 🔗 URL Analiz Araçları
- **[URLScan.io](https://urlscan.io/):** Bağlantıyı tıklamadan önizleme ve analiz.
- **URL Expander’lar:** Kısaltılmış bağlantıların gerçek adresini gösterir.
- **Sandbox Tarayıcılar:** Browserling veya VM kullanarak güvenli şekilde bağlantı açma.

---

# Phishing Analizi Adımları (Workflow)

---

<details>
<summary><strong>Adım 1: Hazırlık ve Güvenlik</strong></summary>
<ul>
<li>Analizin izole bir sanal makinede yapılması.</li>
<li>Gerekli araçlara (VT, AbuseIPDB, sandbox vs.) erişimin olması.</li>
<li>E-postanın `.eml` veya `.msg` formatında alınması.</li>
</ul>
</details>

---

<details>
<summary><strong>Adım 2: İlk Analiz / Görsel İnceleme</strong></summary>
<ul>
<li><b>Gönderen:</b> Adres tanıdık mı? Eşleşme var mı?</li>
<li><b>Konu:</b> Beklenmedik, acil veya tehditkar mı?</li>
<li><b>İçerik:</b> Yazım hataları, acele ettirme var mı?</li>
<li><b>Bağlantılar:</b> Farenin üstüne gelerek (tıklamadan) gerçek URL’nin görülmesi.</li>
</ul>
</details>

---

<details>
<summary><strong>Adım 3: Header Analizi</strong></summary>
<ul>
<li>Başlıkların çıkarılıp MxToolbox / Google Messageheader veya manuel olarak analiz edilmesi.</li>
<li><b>Received:</b> Satırlarını alttan üste izlemek ve kaynak IP’nin bulunması.</li>
<li>IP’nin AbuseIPDB, VT veya OTX ile kontrol edilmesi.</li>
<li><b>SPF, DKIM, DMARC</b> sonuçlarının incelenmesi.</li>
<li><b>From / Reply-To / Return-Path</b> alanlarının karşılaştırılması.</li>
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
<li>Dosyanın <code>MD5 / SHA256</code> hash değerinin hesaplanması.</li>
<li>Hash'in VT veya OTX üzerinden kontrol edilmesi.</li>
<li>Gerekirse sandbox ortamında çalıştırılması (Any.Run, Triage).</li>
</ul>
</details>

---

<details>
<summary><strong>Adım 7: IoC Çıkarma ve Sonuç</strong></summary>
<ul>
<li>Topla:
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

---

## Sonuç

Bu rehber, e-postalarının güvenli, sistematik ve etkili şekilde analiz edilmesi için bir temel sunar.  
