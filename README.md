# End-to-End Incident Response: Spear Phishing & Ransomware Infection
*Turkish translation is available below / Türkçe çevirisi aşağıdadır.*

## 🇬🇧 English - Objective
The objective of this lab is to conduct a complete **Incident Response (IR)** lifecycle on a sophisticated Spear Phishing attack. The scenario involves a socially engineered email targeting a specific user with a hidden, Base64-encoded malicious payload. The investigation goes beyond simply identifying the malicious email; it correlates **Email Gateway** logs with **Firewall** traffic to definitively prove system compromise (infection).

### Phase 1: Triage & Payload Extraction (Email Gateway)
During routine log triage, a suspicious email masquerading as an urgent Microsoft Teams update was detected. The embedded URL contained a suspicious parameter. Using Splunk's SPL (`rex` command), I dynamically extracted the Base64 encoded payload from the raw logs for analysis.
* **SPL Query:** `index="phishing" "EMAIL_GATEWAY" "payload=" | rex field=_raw "payload=(?<Base64_Sifresi>[A-Za-z0-9+/=]+)" | table _time, FROM, TO, SUBJECT, Base64_Sifresi`
* **Decoding Analysis:** Decoding the extracted Base64 string (`aHR0cDovL21hbGljaW91cy1jMi5jb20vcmFuc29td2FyZS5leGU=`) revealed the true malicious intent: `http://malicious-c2.com/ransomware.exe`

<img src="1-phishing-email-detected.png">

### Phase 2: Infection Verification (Firewall Correlation)
Identifying a phishing email is only half the battle. To determine if the user fell victim to the attack, I pivoted to the network **Firewall logs**. By querying the decoded malicious URL, I discovered that the user clicked the link and the firewall permitted (`ACTION=Allowed`) the download of the 4MB ransomware executable, confirming a full endpoint compromise.
* **SPL Query:** `index="phishing" "FIREWALL" "ransomware.exe"`

<img src="2-firewall-infection-confirmed.png">

---

## 🇹🇷 Türkçe - Amacımız
Bu laboratuvarın amacı, karmaşık bir **Spear Phishing** saldırısı üzerinde uçtan uca bir **Incident Response** yaşam döngüsü yürütmektir. Senaryo, spesifik bir kullanıcıyı hedef alan ve içinde Base64 ile encode edilmiş zararlı bir **payload** barındıran sosyal mühendislik e-postasını içermektedir. Bu analiz sadece zararlı e-postayı tespit etmekle kalmaz; sistemin **compromise** edildiğini (enfekte olduğunu) kesin olarak kanıtlamak için **Email Gateway** loglarını **Firewall** trafiği ile korele eder.

### 1. Aşama: Triage ve Payload Extraction (Email Gateway)
Rutin log analizi (triage) sırasında, acil bir Microsoft Teams güncellemesi gibi görünen şüpheli bir e-posta tespit edilmiştir. İlgili URL şüpheli bir parametre içeriyordu. Splunk SPL (`rex` komutu) kullanılarak, analiz edilmek üzere raw logların içindeki Base64 şifreli **payload** dinamik olarak extract edilmiştir.
* **SPL Sorgusu:** `index="phishing" "EMAIL_GATEWAY" "payload=" | rex field=_raw "payload=(?<Base64_Sifresi>[A-Za-z0-9+/=]+)" | table _time, FROM, TO, SUBJECT, Base64_Sifresi`
* **Decoding:** Extract edilen Base64 string'inin decode edilmesi, asıl zararlı niyeti (malicious intent) ortaya çıkarmıştır: `http://malicious-c2.com/ransomware.exe`

<img src="1-phishing-email-detected.png">

### 2. Aşama: Infection Doğrulaması (Firewall Korelasyonu)
Bir phishing e-postasını tespit etmek işin sadece yarısıdır. Kullanıcının saldırıya kurban gidip gitmediğini belirlemek için ağın **Firewall loglarına** pivot edilmiştir. Decode edilen zararlı URL sorgulanarak, kullanıcının bağlantıya tıkladığı ve firewall'un 4MB'lık **ransomware** (fidye yazılımı) indirilmesine izin verdiği (`ACTION=Allowed`) keşfedilmiştir. Bu durum, endpoint'in tamamen **compromise** edildiğini doğrulamaktadır.

## Conclusion / Sonuç
Etkili bir Incident Response süreci, çapraz platform log korelasyonu gerektirir. Sadece email loglarına güvenmek kör noktalar yaratır. Tehdidi delivery (teslimat) aşamasından execution (çalıştırma) aşamasına kadar takip ederek, olayın kesin bir timeline'ı başarıyla oluşturulmuştur.
