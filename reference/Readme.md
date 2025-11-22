#**Model Bağlam Protokolü (MCP) Ekosisteminin Eleştirel Güvenlik İncelemesi**

### Özet
Model Bağlam Protokolü (MCP), Büyük Dil Modelleri (LLM) ile harici araçlar ve kaynaklar arasındaki çift yönlü, şema tabanlı iletişimi ve dinamik keşif süreçlerini standartlaştırmaktadır. Bu protokol, entegrasyon parçalanmasını (fragmentation) azaltmayı hedeflerken; araç zehirleme (tool poisoning), istem enjeksiyonu (prompt injection), sunucu ifşası ve yapılandırma hataları gibi yeni risk vektörlerini de beraberinde getirmektedir. Literatürde, MCP sunucu yaşam döngüsü —oluşturma, dağıtım, işletim ve bakım— 16 temel faaliyet ve bunlara karşılık gelen 16 tehdit senaryosu üzerinden sınıflandırılmaktadır. 1.899 sunucu üzerinde yapılan taramalarda, sunucuların %7,2’sinde genel güvenlik açıkları, %5,5’inde araç zehirleme riski ve %66’sında "kod kokusu" (code smell) olarak nitelendirilen yapısal sorunlar tespit edilmiştir.

### 1. Mimari Bileşenler ve Sınırlar
- **Host/Client (İstemci):** LLM’i barındıran, araç ve kaynak keşfini yöneten ve harici veriye erişim sağlayan yüzeydir.
- **Server (Sunucu):** Araçları ve kaynakları JSON-RPC protokolü üzerinden sunar. Bu bileşende kimlik doğrulama ve izolasyon kalitesi güvenlik açısından kritiktir.
- **Tools (Araçlar):** Harici işlevleri temsil eder. Tanımlama (description) alanları, istem enjeksiyonuna ve araç zehirleme saldırılarına karşı savunmasız olabilir.
- **Taşıma Katmanı (Transport):** İletişim StdIO veya HTTPS/SSE üzerinden sağlanır. Şifreleme standartları ile OAuth/mTLS uygulamaları, saldırı yüzeyinin genişliğini belirleyen temel faktörlerdir.

### 2. Tehdit Taksonomisi (4 Aktör, 16 Senaryo)
- **Kötü Niyetli Geliştirici:** Araç zehirleme, gölge sunucu (shadow server) oluşturma ve isim çakışması (namespace collision) yoluyla saldırılar düzenler.
- **Dış Saldırgan:** Dolaylı istem enjeksiyonu, kurulum sahtekârlığı ve açık sunucu istismarı gibi yöntemleri kullanır.
- **Kötü Niyetli Kullanıcı:** STAC (ardışık düşük riskli araçlarla yüksek etkili eylem zinciri oluşturma), sanal alan (sandbox) kaçışı ve oturumun yeniden kullanımı (session reuse) gibi tekniklere başvurur.
- **Yazılım/Konfigürasyon Hataları:** Kimlik bilgisi sızıntıları, komut enjeksiyonları ve zayıf TLS/OAuth yapılandırmalarından kaynaklanan zafiyetlerdir.

### 3. Ampirik Bulgular
- Hasan ve ark. (2025) tarafından 1.899 açık kaynak MCP sunucusu üzerinde yapılan analizde; %7,2 oranında genel açık, %5,5 oranında araç zehirleme riski, %66 oranında kod kokusu ve %14,4 oranında hata kalıbı tespit edilmiştir.
- Geleneksel statik analiz yöntemlerinin MCP'ye özgü açıkları tespit etmekte yetersiz kaldığı, dolayısıyla MCP odaklı tarama araçlarına ihtiyaç duyulduğu vurgulanmıştır.

### 4. Performans ve Kıyaslamalar (Benchmarks)
- **MCPGAUGE:** MCP entegrasyonunun her senaryoda mutlak fayda sağlamadığı; bazı durumlarda düşük proaktiviteye ve yüksek maliyet/gider oranına yol açtığı gözlemlenmiştir.
- **MCP-Universe, LiveMCP-101:** Gerçek sunucular üzerinde yapılan testlerde, öncü (frontier) modellerin başarı oranının %60'ın altında kaldığı, özellikle uzun bağlam (long-context) ve bilinmeyen araç hatalarının belirginleştiği raporlanmıştır.
- **MCPToolBench++:** 4.000'den fazla sunucuyu kapsayan bu çalışmada, format çeşitliliği ve bağlam penceresi kısıtlarının önemli bir darboğaz oluşturduğu belirlenmiştir.
- **Red Teaming (Kırmızı Takım):** AutoMalTool gibi araçların mevcut savunmaları aşabildiği, ancak çok katmanlı tespit mekanizması kullanan MCP-Guard'ın %96 doğruluk oranına ulaştığı görülmüştür.

### 5. Savunma Stratejileri
- **Bilgi Akış Kontrolü (IFC) ve Leke Takibi (Taint-tracking):** Zehirli girdilerin kritik eylemleri tetiklemesini engellemek amacıyla kullanılmalıdır.
- **Sandboxing (Yalıtma):** Araç erişimleri dosya, ağ ve sistem komutları düzeyinde sınırlandırılmalı; dağıtıma özel profiller oluşturulmalıdır.
- **Kimlik ve Taşıma Güvenliği:** TLS/mTLS, OAuth 2.1 ve kaynak göstergeleri (resource indicators) standartlaştırılmalı; kapsamı daraltılmış (scoped) ve kısa ömürlü token'lar tercih edilmelidir.
- **Gözlemlenebilirlik:** Plan tabanlı testler (LiveMCP-101), detaylı günlükleme (logging), anomali takibi ve periyodik kırmızı takım tatbikatları uygulanmalıdır.
- **Tedarik Zinciri Güvenliği:** İmzalı paketler, sürüm sabitleme (version pinning), SBOM kullanımı ve açıklama/şema bütünlük doğrulamaları süreçlere dahil edilmelidir.

### 6. Öneriler
1.  **CI/CD Entegrasyonu:** Açıklama zehirleme, şema tutarlılığı ve anlamsal tespitleri içeren MCP'ye özgü taramalar CI/CD boru hatlarına eklenmelidir.
2.  **Paket Güvenliği:** İmzalı paket dağıtımı, sürüm sabitleme, SBOM üretimi ve her yayın sürümünde bütünlük doğrulaması standart hale getirilmelidir.
3.  **İnsan Onayı ve Kısıtlamalar:** Yüksek etkili eylemlerde koruma (guard) modelleri ve insan onayı şart koşulmalı; araç başına kapsam/kota sınırları ve kapsamı daraltılmış kimlik bilgileri kullanılmalıdır.
4.  **Stres Testleri:** Canlı ortama geçiş öncesinde plan tabanlı stres testleri ve AutoMalTool benzeri otomatik kırmızı takım senaryoları koşturulmalıdır.
5.  **Otomasyon:** Manuel kopyala-yapıştır hatalarını minimize etmek ve spesifikasyon kalitesini artırmak için OpenAPI'den otomatik sunucu üretimi teşvik edilmelidir.

### Kaynakça (18 Çalışma)
*(Atıflar: Hou 2025; Krishnan 2025; Ehtesham 2025; Hasan 2025; Flotho 2025; Mastouri 2025; Fan 2025; Xing 2025; Song 2025; Luo 2025; Yin 2025; Chhetri 2025; Tokal 2025; He 2025; Singh 2025; Bhandarwar 2025; Coppolino 2025; Korinek 2025.)*

---

## MCP ve İlgili Çalışmalar – Literatür Özeti

**1) Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions** (2025, arXiv:2503.23278) – Hou, X. ve ark.
* **Özet:** Çalışma, MCP'nin dört aşamalı yaşam döngüsünü ve 16 senaryodan oluşan tehdit modelini ortaya koymaktadır. Kötü niyetli geliştirici/kullanıcı, dış saldırgan ve kod hatalarından kaynaklanan riskler analiz edilmekte; her faz için uygulanabilir savunma stratejileri ve gelecek araştırma alanları sunulmaktadır.

**2) Advancing Multi-Agent Systems Through Model Context Protocol: Architecture, Implementation, and Applications** (2025, arXiv:2504.21030) – Krishnan, N.
* **Özet:** Çoklu ajan (multi-agent) senaryolarında, MCP ile standartlaştırılmış bağlam ve araç paylaşımının verimliliği incelenmiştir. Farklı alanlardaki vaka analizleri üzerinden performans kazanımları ve yeni araştırma fırsatları raporlanmaktadır.

**3) A survey of agent interoperability protocols: MCP, ACP, A2A, ANP** (2025, arXiv:2505.02279) – Ehtesham, A. ve ark.
* **Özet:** Dört farklı protokol (MCP, ACP, A2A, ANP) birlikte çalışabilirlik ve güvenlik özellikleri açısından kıyaslanmıştır. Çalışma; araç erişimi, yapılandırılmış mesajlaşma, yetki devri ve merkeziyetsiz pazar adımlarını içeren aşamalı bir benimseme yol haritası önermektedir.

**4) Model Context Protocol (MCP) at First Glance: Studying the Security and Maintainability of MCP Servers** (2025, arXiv:2506.13538) – Hasan, M. M. ve ark.
* **Özet:** Geniş ölçekli bir tarama ile MCP sunucularının barındırdığı yeni saldırı yüzeyleri (özgün zafiyetler, araç zehirleme) ve bakım sorunları analiz edilmiştir. Çalışma, MCP’ye özgü tespit araçlarının geliştirilmesi gerektiğini vurgulamaktadır.

**5) MCPmed: A Call for MCP-Enabled Bioinformatics Web Services for LLM-Driven Discovery** (2025, arXiv:2507.08055) – Flotho, M. ve ark.
* **Özet:** Biyoinformatik API’lerinin MCP katmanı ile zenginleştirilmesi önerilmektedir. Bu yaklaşımın, LLM tabanlı ajanların veri keşfi yeteneklerini ve çalışmaların yeniden üretilebilirliğini (reproducibility) artıracağı savunulmakta ve entegrasyon için hafif geçiş şablonları sunulmaktadır.

**6) Making REST APIs Agent-Ready: From OpenAPI to MCP Servers for Tool-Augmented LLMs** (2025, arXiv:2507.16044) – Mastouri, M. ve ark.
* **Özet:** MCP sunucu kurulum maliyetlerini düşürmek amacıyla OpenAPI spesifikasyonlarından otomatik üretim yöntemi önerilmiştir. Başarısızlıkların büyük ölçüde sözleşme kalitesinden kaynaklandığı belirtilmiş ve MCP ekosistemi için otomasyonun uygulanabilirliği kanıtlanmıştır.

**7) MCPToolBench++: A Large Scale AI Agent Model Context Protocol MCP Tool Use Benchmark** (2025, arXiv:2508.07575) – Fan, S. ve ark.
* **Özet:** Gerçek MCP araçlarını içeren büyük ölçekli bir test seti sunulmuştur. Ajanların çok adımlı araç çağrılarındaki başarı oranları ve bağlam sınırı (context window) problemleri deneysel olarak ortaya konmuştur.

**8) MCP-Guard: A Defense Framework for Model Context Protocol Integrity in Large Language Model Applications** (2025, arXiv:2508.10991) – Xing, W. ve ark.
* **Özet:** MCP araç etkileşimlerini istem enjeksiyonu ve zehirlemeye karşı koruyan üç aşamalı bir mimari ile geniş kapsamlı bir saldırı testi (benchmark) sunulmuştur. Önerilen sistemin yüksek doğrulukla tespit sağladığı raporlanmıştır.

**9) Help or Hurdle? Rethinking Model Context Protocol-Augmented Large Language Models** (2025, arXiv:2508.12566) – Song, W. ve ark.
* **Özet:** Kapsamlı bir kıyaslama testi ile MCP entegrasyonunun her zaman performans artışı sağlamadığı; proaktif kullanım eksikliği ve maliyet aşımı gibi sorunlara yol açabildiği gösterilmiştir.

**10) MCP-Universe: Benchmarking Large Language Models with Real-World Model Context Protocol Servers** (2025, arXiv:2508.14704) – Luo, Z. ve ark.
* **Özet:** Gerçek MCP sunucularıyla yapılan testlerde, LLM ajanlarının uzun bağlam ve tanımsız araçlar nedeniyle zorlandığı ve başarı oranlarının beklenenin altında kaldığı tespit edilmiştir.

**11) LiveMCP-101: Stress Testing and Diagnosing MCP-enabled Agents on Challenging Queries** (2025, arXiv:2508.15760) – Yin, M. ve ark.
* **Özet:** Gerçekçi görev senaryoları ile MCP ajanları stres testine tabi tutulmuş; planlama/koordinasyon hataları ve token verimsizliği gibi sorunlar ortaya çıkarılarak hata modları sınıflandırılmıştır.

**12) Model Context Protocols in Adaptive Transport Systems: A Survey** (2025, arXiv:2508.19239) – Chhetri, G. ve ark.
* **Özet:** Adaptif ulaşım sistemlerinde parçalı yapıların, MCP'nin sağladığı bağlam farkındalığı ve standart entegrasyon ile birleştirilebileceği tartışılmış ve bu alanda bir araştırma yol haritası sunulmuştur.

**13) AgentX: Towards Orchestrating Robust Agentic Workflow Patterns with FaaS-hosted MCP Services** (2025, arXiv:2509.07595) – Tokal, S. S. K. A. ve ark.
* **Özet:** MCP araçlarının Hizmet Olarak Fonksiyon (FaaS) mimarisinde barındırılmasıyla çok aşamalı ajan iş akışlarının iyileştirilmesi hedeflenmiştir. Başarı, gecikme süresi (latency) ve maliyet analizleri üzerinden fırsatlar ve zorluklar değerlendirilmiştir.

**14) Automatic Red Teaming LLM-based Agents with Model Context Protocol Tools** (2025, arXiv:2509.21011) – He, P. ve ark.
* **Özet:** MCP araç zehirlemesine karşı otomatik bir kırmızı takım çerçevesi geliştirilmiştir. Deneyler, yaygın kullanılan ajanların manipüle edilebildiğini ve mevcut savunma mekanizmalarının yetersiz kaldığını göstermiştir.

**15) Asset Discovery in Critical Infrastructures: An LLM-Based Approach** (2025, Electronics 14(16):3267) – Coppolino, L. ve ark.
* **Özet:** Kritik Altyapılarda (CI) siber güvenlik için hayati önem taşıyan varlık envanteri yönetimini ele alır. Çalışma, geleneksel deterministik yöntemlerin yetersiz kaldığı heterojen ortamlarda, yapılandırılmamış verilerden (loglar, konfigürasyon dosyaları vb.) varlık bilgilerini çıkarmak için "Uzmanların Karışımı" (Mixture of Experts) modeline dayalı LLM tabanlı bir mimari önerir. Önerilen yaklaşımın, manuel eforu azalttığı ve varlık görünürlüğünü artırarak siber güvenlik duruşunu güçlendirdiği deneysel olarak kanıtlanmıştır.

**16) Integrating Generative AI and Model Context Protocol (MCP) with Applied Machine Learning for Advanced Agentic AI Systems** (2025, Int. J. of Computer Trends and Technology) – Bhandarwar, N.
* **Özet:** Üretken Yapay Zeka (GenAI) ve Uygulamalı Makine Öğrenimi modellerini Model Bağlam Protokolü (MCP) aracılığıyla entegre eden hibrit bir mimari sunar. Makale, MCP'nin farklı AI modelleri arasında standart bir iletişim katmanı sağlayarak, bağlam-farkında (context-aware) karar verebilen ve dinamik ortamlara uyum sağlayabilen otonom "Ajan Yapay Zeka" (Agentic AI) sistemlerinin geliştirilmesini nasıl mümkün kıldığını teknik bir çerçevede inceler.

**17) A Survey of the Model Context Protocol (MCP): Standardizing Context to Enhance Large Language Models (LLMs)** (2025, Preprints 202504.0245) – Singh, A. ve ark.
* **Özet:** MCP, standart bir bağlam katmanı olarak değerlendirilmiş; birlikte çalışabilirlik kazanımları ile uzun vadeli performans belirsizlikleri vurgulanmıştır. Farklı sektörler için fırsat ve riskler analiz edilmiştir.

**18) AI Agents for Economic Research** (2025, NBER Working Paper 34202) – Korinek, A.
* **Özet:** Yapay zeka sistemlerinin basit sohbet botlarından, planlama yapabilen ve çok adımlı görevleri yürütebilen otonom ajanlara evrimini ekonomi araştırmaları perspektifinden inceler. Çalışma, iktisatçıların programlama uzmanlığına ihtiyaç duymadan literatür taraması, veri analizi ve ekonometrik kodlama yapabilen kendi araştırma ajanlarını nasıl oluşturabileceklerini gösterir; bu ajanların "proaktif araştırma ortakları" olarak verimliliği nasıl dönüştürdüğünü ve insan denetiminin gerekliliğini tartışır.
