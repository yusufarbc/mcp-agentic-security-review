## Model Bağlam Protokolü (MCP) Ekosisteminin Eleştirel Güvenlik İncelemesi

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
