# 🎣 Phishing Analizi (Oltalama Analizi)

**Phishing (Oltalama)**, saldırganların ağlara ilk erişimi sağlamak, kimlik bilgilerini çalmak veya kötü amaçlı yazılım yaymak için kullandığı en yaygın **sosyal mühendislik tekniklerinden biridir**.  
Bir **siber güvenlik analisti** olarak, şüpheli e-postaları, bağlantıları (URL) ve ekleri analiz etme yeteneğin, savunma hattının en önemli becerilerinden biridir.

Phishing analizinin temel amacı, bir e-postanın kötü amaçlı olup olmadığını belirlemek ve eğer öyleyse, **IoC (Indicator of Compromise – İhlal Göstergesi)** verilerini çıkartmaktır. Bu göstergeler, tespit, engelleme ve tehdit istihbaratında kullanılabilir.

---

## 🔎 İncelenmesi Gereken Ana Unsurlar

Phishing analizi yaparken bir e-postanın aşağıdaki bölümleri incelenir:

### 1. ✉️ E-posta Başlıkları (Headers)

E-posta başlıkları, e-postanın kimden geldiği, hangi sunuculardan geçtiği ve kimlik doğrulama sonuçları gibi önemli **meta verileri** içerir.

Dikkat edilmesi gereken başlıca alanlar:

- **`From:` (Gönderen):** Kim e-postayı göndermiş görünüyor? Kolaylıkla sahte olabilir (spoofing).
- **`Reply-To:`** Yanıtların gönderileceği adres. Genellikle `From` kısmından farklıdır.
- **`Return-Path:`** Teslim edilemeyen e-postaların döndüğü adres. Gerçek kaynağı gösterebilir.
- **`Received:`** E-postanın geçtiği sunucuların sıralı listesi (alttan üste doğru okunur).
- **`Authentication-Results:`** SPF, DKIM ve DMARC doğrulama sonuçlarını gösterir.

**SPF / DKIM / DMARC Nedir?**
- **SPF (Sender Policy Framework):** Gönderen IP’nin yetkili olup olmadığını kontrol eder. `FAIL` büyük bir uyarıdır.
- **DKIM (DomainKeys Identified Mail):** Mesajın değiştirilip değiştirilmediğini doğrular. `FAIL` → manipülasyon ihtimali.
- **DMARC:** SPF veya DKIM başarısız olduğunda ne yapılacağını belirler (`reject`, `quarantine`, `none`). `FAIL` → genellikle sahte e-posta.

Ayrıca, `Received` satırlarında geçen **kaynak IP adresi** tespit edilip güvenilirlik kontrolü yapılmalıdır.

---

### 2. 💬 E-posta İçeriği (Body)

E-postanın görünür kısmıdır. Aşağıdaki belirtiler genellikle oltalama emaresidir:

- **Acil / Tehditkar İfadeler:** “Hesabınız kilitlenecek”, “Acil işlem gerekli”.
- **Yazım veya dilbilgisi hataları.**
- **Genel hitaplar:** “Değerli müşterimiz” gibi.
- **Olağandışı talepler:** Kimlik bilgisi, ödeme, dosya isteme.
- **Farklı tarz / biçim:** Gerçek kurumsal e-postalardan farklı.
- **Şüpheli bağlantılar (URLs):** Sonraki adımda analiz edilir.

---

### 3. 🔗 Bağlantılar (URLs)

Bağlantılar oltalama e-postalarının en kritik unsurlarındandır.  
**Asla görünen bağlantıya güvenme!** Her zaman gerçek yönlendirme adresini kontrol et.

Dikkat edilmesi gerekenler:
- **Aldatıcı alan adları:** `paypaI.com` (büyük “I”) gibi benzer yazımlar.
- **Alt alan adlarıyla kandırma:** `paypal.security-update.com`
- **Kısaltılmış linkler:** Bitly, TinyURL gibi servisler gerçek URL’yi gizleyebilir.
- **Direkt IP adresleri:** Gerçek servisler genelde IP ile link vermez.
- **Defanging (zararsız hale getirme):** Şüpheli linkleri paylaşırken `http` → `hxxp`, `.` → `[.]` ile değiştir.  
  Örnek: `hxxp://malicious-site[.]com/login.php`

---

### 4. 📎 Ekler (Attachments)

E-postalardaki ekler kötü amaçlı yazılım taşımak için sıkça kullanılır.

Dikkat edilmesi gereken dosya türleri:
- **Tehlikeli uzantılar:** `.exe`, `.bat`, `.js`, `.ps1`, `.vbs`
- **Makro içeren Office dosyaları:** `.docm`, `.xlsm`, `.pptm`
- **Çift uzantı:** `invoice.pdf.exe`
- **Parola korumalı dosyalar:** Genellikle antivirüsten kaçmak için kullanılır.
- **Analiz yöntemleri:** Şüpheli dosyayı **asla doğrudan açma!** Hash değerlerini çıkar ve sandbox ortamında analiz et.

---

## 💡 IoC (İhlal Göstergeleri)

Analiz sonucunda elde edilebilecek IoC türleri:

- **IP Adresleri:** Kaynak veya kötü amaçlı sunucu.
- **Alan adları / URL’ler:** E-postada geçen veya yönlendiren bağlantılar.
- **Dosya hashleri:** MD5 / SHA1 / SHA256
- **E-posta adresleri:** `From`, `Reply-To`, `Return-Path`
- **Konu başlıkları:** Tespit kurallarında kullanılabilir.

---

## 🧰 Phishing Analizi İçin Gerekli Araçlar

Aşağıdaki araçlar, e-posta, URL, IP ve dosyaları **güvenli bir şekilde** analiz etmeni sağlar.

### 🌐 İtibar Servisleri
- **[VirusTotal](https://www.virustotal.com/):** URL, IP, domain ve dosya hash analizi.
- **[URLhaus](https://urlhaus.abuse.ch/):** Zararlı bağlantı veri tabanı.
- **[AbuseIPDB](https://www.abuseipdb.com/):** IP adreslerinin kötüye kullanım kayıtları.
- **[AlienVault OTX](https://otx.alienvault.com/):** Tehdit istihbaratı platformu (IoC, MITRE ATT&CK ilişkisi).

---

### 🔬 Sandbox Ortamları (Dinamik Analiz)
- **[Any.Run](https://any.run/):** Gerçek zamanlı etkileşimli analiz.
- **[Hybrid Analysis](https://www.hybrid-analysis.com/):** Statik + dinamik analiz, PCAP ve ekran görüntüsü sağlar.
- **[Triage](https://tria.ge/):** MITRE ATT&CK eşleşmeleriyle detaylı raporlama.
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

### 🛠️ Diğer Yararlı Araçlar
- **[PhishTool](https://www.phishtool.com/):** Otomatik phishing analizi platformu (ücretsiz ve ücretli planlar mevcut).

---

## ⚠️ Güvenlik Notu

- **Asla** şüpheli linke tıklama veya ekleri kendi sisteminde açma.  
- Her zaman **izole (sandbox/VM)** bir ortamda analiz yap.  
- **Gizlilik** konusunda dikkatli ol: VirusTotal gibi platformlara gizli dosya yükleme!

---

# 🧭 Phishing Analizi Adımları (Workflow)

Phishing analizini sistematik bir biçimde yürütmek, verimli ve güvenli çalışmanı sağlar.  
Aşağıdaki adımlar önerilen genel süreçtir:

---

<details>
<summary><strong>🛡️ Adım 1: Hazırlık ve Güvenlik</strong></summary>
<ul>
<li>Analizi izole bir sanal makinede yap.</li>
<li>Gerekli araçlara (VT, AbuseIPDB, sandbox vs.) erişimin olsun.</li>
<li>E-postayı mümkünse `.eml` veya `.msg` formatında al.</li>
</ul>
</details>

---

<details>
<summary><strong>👀 Adım 2: İlk Görsel İnceleme</strong></summary>
<ul>
<li><b>Gönderen:</b> Adres tanıdık mı? Eşleşme var mı?</li>
<li><b>Konu:</b> Beklenmedik, acil veya tehditkar mı?</li>
<li><b>İçerik:</b> Yazım hataları, acele ettirme, genel hitap var mı?</li>
<li><b>Bağlantılar:</b> Farenin üstüne gelerek (tıklamadan) gerçek URL’yi gör.</li>
</ul>
</details>

---

<details>
<summary><strong>✉️ Adım 3: Header Analizi</strong></summary>
<ul>
<li>Başlıkları çıkar ve MxToolbox / Google Messageheader ile analiz et.</li>
<li><b>Received:</b> Satırlarını alttan üste izle, kaynak IP’yi bul.</li>
<li>IP’yi AbuseIPDB, VT veya OTX ile kontrol et.</li>
<li><b>SPF, DKIM, DMARC</b> sonuçlarını incele.</li>
<li><b>From / Reply-To / Return-Path</b> alanlarını karşılaştır.</li>
</ul>
</details>

---

<details>
<summary><strong>🧾 Adım 4: Mesaj İçeriği Analizi</strong></summary>
<ul>
<li>Sosyal mühendislik belirtilerini tespit et.</li>
<li>Duyarlı bilgi taleplerini belirle.</li>
<li>Tüm URL’leri çıkar.</li>
</ul>
</details>

---

<details>
<summary><strong>🔗 Adım 5: URL Analizi (Güvenli Modda)</strong></summary>
<ul>
<li>Tüm bağlantıları listele, <b>defang</b> et (ör. <code>hxxp://example[.]com</code>).</li>
<li>URL / domain’i VT, URLhaus, OTX üzerinde kontrol et.</li>
<li>Kısaltılmış linkleri açığa çıkar (expander kullan).</li>
<li>URLScan.io ile sayfanın ekran görüntüsünü al.</li>
</ul>
</details>

---

<details>
<summary><strong>📎 Adım 6: Ek Analizi (Güvenli Modda)</strong></summary>
<ul>
<li><b>Kesinlikle doğrudan açma!</b></li>
<li>Dosyanın <code>MD5 / SHA256</code> hash değerini hesapla.</li>
<li>Hash’i VT veya OTX üzerinde kontrol et.</li>
<li>Gerekirse sandbox ortamında çalıştır (Any.Run, Triage).</li>
</ul>
</details>

---

<details>
<summary><strong>✅ Adım 7: IoC Çıkarma ve Sonuç</strong></summary>
<ul>
<li>Topla:
    <ul>
        <li>Kötü amaçlı IP’ler</li>
        <li>Alan adları / URL’ler</li>
        <li>Dosya hashleri</li>
        <li>E-posta adresleri</li>
        <li>Konu başlıkları</li>
    </ul>
</li>
<li>E-postanın durumunu belirle: <code>Malicious</code> / <code>Suspicious</code> / <code>Legitimate</code></li>
<li>Kısa bir özet yaz: neden bu sonuca vardığını belirt.</li>
</ul>
</details>

---

<details>
<summary><strong>📝 Adım 8: Raporlama ve Dokümantasyon</strong></summary>
<ul>
<li>Tespit ettiğin IoC’leri düzenli şekilde belgele.</li>
<li>Kurum prosedürüne göre raporla veya engelleme işlemini başlat.</li>
</ul>
</details>

---

## 📚 Sonuç

Bu rehber, phishing e-postalarını **güvenli, sistematik ve etkili** şekilde analiz etmen için kapsamlı bir temel sunar.  
Bu repo, örnek e-postalar, analiz çıktıları, hash ve URL kontrol senaryoları içerecektir.

> 🧠 “Bir analistin en güçlü silahı, dikkat ve metodolojidir.”

---

**Hazırlayan:** Volkan Özdemir  
**Kategori:** Siber Güvenlik / Phishing Analizi  
**Lisans:** MIT  
