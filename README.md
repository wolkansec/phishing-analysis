# Phishing Analizi

Phishing (Oltalama), saldırganların ağlara ilk erişimi sağlamak, kimlik bilgilerini çalmak veya kötü amaçlı yazılım yaymak için kullandığı en yaygın sosyal mühendislik tekniklerinden biridir.  

Bir siber güvenlik analisti olarak, şüpheli e-postaları, bağlantıları (URL) ve ekleri analiz etme yeteneği, temel becerilerden biridir.
Phishing analizinin temel amacı, e-postanın kötü amaçlı olup olmadığını belirlemek ve eğer öyleyse, IoC verilerini çıkartmaktır.

Bu rehber ise e-postalarının güvenli, sistematik ve etkili şekilde analiz edilmesi için bir temel sunar.  

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
- **DMARC:** SPF veya DKIM başarısız olduğunda ne yapılacağını belirler (`reject`, `quarantine`, `none`). `FAIL` genellikle sahte e-posta.

Ayrıca, `Received` satırlarında geçen kaynak IP adresi tespit edilip reputation testi yapılmalıdır.

---

### 2. E-posta İçeriği (Body)

E-postanın görünür kısmıdır. Aşağıdaki belirtiler genellikle oltalama belirtisidir:

- **Acil / Tehditkar İfadeler:** "Hesabınız kilitlenecek", "Acil işlem gerekli".
- **Yazım veya dilbilgisi hataları**
- **Olağandışı talepler:** Kimlik bilgisi, ödeme, dosya isteme.
- **Farklı tarz / biçim:** Gerçek kurumsal dilden farklı e-postalar.
- **Şüpheli bağlantılar (URLs):** Sonraki adımda analiz edilir.

---

### 3. Bağlantılar (URLs)

Bağlantılar oltalama e-postalarının en kritik unsurlarındandır. Her zaman gerçek yönlendirme adresi kontrol edilmelidir.

Dikkat edilmesi gerekenler:
- **Aldatıcı alan adları:** `paypaI.com` (büyük "I") gibi benzer yazımlar.
- **Alt alan adlarıyla kandırma:** `paypal.security-update.com`
- **Kısaltılmış linkler:** Bitly, TinyURL gibi servisler gerçek URL’yi gizleyebilir.
- **Direkt IP adresleri:** Gerçek servisler genelde IP ile link vermez.
- **Defanging (zararsız hale getirme):** Şüpheli linkleri paylaşırken `http` > `hxxp`, `.` > `[.]` ile değiştirilmelidir.
  Örnek: `hxxp://malicious-site[.]com/`

---

### 4. Ekler (Attachments)

E-postalardaki ekler kötü amaçlı yazılım taşımak için sıkça kullanılır.

Dikkat edilmesi gereken dosya türleri:
- **Tehlikeli uzantılar:** `.exe`, `.bat`, `.js`, `.ps1`, `.vbs`
- **Makro içeren Office dosyaları:** `.docm`, `.xlsm`, `.pptm` Uzantının sonunda `m` ifadesi olması içerisine makro kodunun eklendiğini belirtir!
- **Çift uzantı:** `secret.pdf.exe`
- **Parola korumalı veya Arşiv dosyaları:** Genellikle antivirüsten kaçmak için kullanılır.
- **Analiz yöntemleri:** Şüpheli dosya asla doğrudan açılmamalı, hash değerlerinin çıkarılıp sandbox ortamında analiz edilmesi gerekilir.

---

## IoC (İhlal Göstergeleri)

Analiz sonucunda elde edilebilecek IoC türleri:

- **IP Adresleri:** Kaynak veya kötü amaçlı sunucu.
- **Alan adları / URL'ler:** E-postada geçen veya yönlendiren bağlantılar.
- **Dosya hashleri:** MD5 / SHA1 / SHA256
- **E-posta adresleri:** `From`, `Reply-To`, `Return-Path`

---
