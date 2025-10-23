# MCP Araştırma Raporu


## Özet
- MCP (Model Context Protocol) mimarisi, istemci–sunucu ayrımı ve JSON‑RPC tabanlı araç/ kaynak keşfi ile birlikte çalışabilirliği artırır.
- Kullanım alanları; asistan entegrasyonu, otomasyon (tasarımdan koda), kurumsal veri erişimi ve cihaz kontrolünü kapsar.
- Güvenlikte temel riskler: araç zehirleme, prompt enjeksiyonu, açık sunucular, tedarik zinciri ve RCE vakaları; savunmada sandboxing, en az yetki ve denetlenebilirlik öne çıkar.
- Standartlaşma ve yönetişim eksikleri ile performans/maliyet konuları, gelecek çalışmaların odağıdır.

Not: Ayrıntılar için Rapor bölümüne geçiniz.

## İçindekiler
- [Özet](#özet)
- [Rapor](#rapor)
- [Ek A: Literatür](#ek-a-literatür)
- [Ek B: Google Scholar ve Sentez](#ek-b-google-scholar-ve-sentez)
- [Ek C: Güncel Olaylar](#ek-c-güncel-olaylar)
- [Ek D: Genişletilmiş Analiz](#ek-d-genişletilmiş-analiz)

## Rapor

### Giriş

**Model Context Protocol (MCP)**, Anthropic şirketi tarafından açık kaynak olarak geliştirilmiş bir protokoldür ve büyük dil modellerini (Large Language Models - *LLM*) harici veri kaynakları ve araçlarla entegre etmeyi amaçlar. Bir bakıma, yapay zeka uygulamaları için **USB-C standardı** gibi çalışarak LLM tabanlı uygulamaların dış sistemlerle bağlanması için standart bir yol sağlar. Bu araştırmanın amacı, MCP protokolünün teknik mimarisi ile ağ içi işleyiş modelini inceleyerek yazılım geliştirme süreçlerindeki kullanım biçimlerini ortaya koymak ve protokolün siber güvenlik bağlamında oluşturabileceği potansiyel riskleri değerlendirmektir.

<img width="1207" height="799" alt="resim" src="https://github.com/user-attachments/assets/bdf1510b-66f6-427b-9562-f8653e73d66e" />


### MCP Protokolünün Amacı ve Kullanım Alanları

MCP protokolünün temel amacı, LLM tabanlı yapay zeka uygulamaları ile harici araçlar, veri kaynakları ve hizmetler arasında **standart bir bağlamsal iletişim** sağlamaktır. Bu sayede bir yapay zeka modeli, kısıtlı kendi bilgi havuzunun ötesine geçerek güncel verilere erişebilir, çeşitli eylemleri tetikleyebilir veya harici uygulamalardan sonuçlar alabilir. Örneğin GitHub Copilot gibi bir kod yardımı aracı, MCP üzerinden GitHub’ın kendi hizmetleriyle veya üçüncü parti araçlarla entegre olarak daha ileri işlemler yapabilmektedir. Anthropic’in Claude modeli gibi bir LLM de MCP sayesinde harici “araçlar” kullanarak ide ortamında dosya sistemine erişmek veya bir hata izleme (sentry) platformundan veri çekmek gibi eylemlere girişebilir.

<img width="960" height="540" alt="resim" src="https://github.com/user-attachments/assets/ac7686e8-9c5d-4a30-be7c-9fa1f7328325" />

MCP protokolü, geniş bir yelpazedeki kullanım senaryolarını mümkün kılarak yapay zekâ uygulamalarının yeteneklerini artırır. Aşağıda MCP’nin sağlayabildiği bazı olanaklar listelenmiştir:

* **Kişisel Asistan Entegrasyonu:** Yapay zekâ “agent”ları kullanıcıların Google Takvimi veya Notion hesaplarına bağlanarak daha kişiselleştirilmiş asistanlar gibi davranabilir. Örneğin, takvimden randevuları okuma veya yeni notlar oluşturma gibi işlemleri gerçekleştirebilir.
* **Tasarım'dan Koda Otomasyon:** Claude Code gibi bir AI aracı, MCP aracılığıyla bir Figma tasarımını analiz ederek komple bir web uygulamasını otomatik olarak oluşturabilir. Bu, tasarım ve geliştirme süreçlerini hızlandıran bir entegrasyon örneğidir.
* **Kurumsal Veri Erişimi:** Kurum içindeki bir sohbet botu, MCP üzerinden organizasyonun farklı veritabanlarına aynı anda bağlanabilir ve kullanıcının doğal dilde sorduğu sorulara dayanarak gerçek zamanlı veri analizi yapabilir. Bu sayede tek bir arayüz üzerinden birden çok veri kaynağı taranabilir.
* **Fiziksel Cihaz Kontrolü:** Bir yapay zekâ modeli, MCP ile Blender gibi bir 3D tasarım aracına ve bir 3B yazıcıya bağlanarak, doğal dil komutlarla 3D model tasarlayıp bunu yazıcıdan basabilir.

Yukarıdaki örnekler MCP’nin **genel amaçlı bir entegrasyon altyapısı** olarak ne denli esnek kullanılabildiğini göstermektedir. Son kullanıcı açısından bu, yapay zekâ destekli uygulamaların kendi verilerine erişip gerekirse kullanıcı adına eyleme geçebilen daha yetenekli asistanlar haline gelmesi demektir. Geliştiriciler için ise MCP, bir yapay zekâ uygulamasına entegrasyon noktaları eklerken zaman kazandıran ve karmaşıklığı azaltan standart bir arayüz sunmaktadır.

### MCP'nin Mimari Yapısı ve Veri İletim Mekanizması


<img width="840" height="328" alt="resim" src="https://github.com/user-attachments/assets/ba600697-942e-426f-ad1c-839875ef9772" />


MCP istemci ve sunucularının LLM ile etkileşimini gösteren örnek bir akış diagramı. Kullanıcı isteği, istemci tarafından LLM'ye iletilir; LLM uygun aracı seçerek sunucuya çağrı yapar ve sonuç yine LLM üzerinden kullanıcıya döner.*

MCP protokolü, istemci-sunucu modeline dayalı **iki katmanlı bir mimariye** sahiptir. Katmanlardan ilki **veri katmanı** (*data layer*) olup istemci ile sunucu arasındaki mesajların yapısını ve anlamını tanımlayan bir JSON-RPC 2.0 tabanlı protokoldür. Bu katmanda bağlantının başlatılması, sürdürülmesi ve sonlandırılması gibi yaşam döngüsü yönetimi; sunucunun sağlayabileceği *araçlar* (tools) ve *kaynaklar* (resources) gibi işlevler; istemcinin LLM'den çıktı üretmesini talep etme veya kullanıcı girdisi isteme gibi kabiliyetler ve uyarı/iletişim amaçlı *bildirimler* yer alır. İkinci katman olan **taşıma katmanı** (*transport layer*), veri alışverişinin hangi iletişim kanalları üzerinden ve nasıl yapılacağını tanımlar; bağlantı kurulumu, mesaj çerçeveleri ve taraflar arasında kimlik doğrulama bu katmanda ele alınır. MCP’nin tasarımında mevcut iki taşıma yöntemi şunlardır:

* **STDIO Taşıması:** İstemci ve sunucunun aynı makinede yerel olarak çalıştığı durumlarda standart girdi/çıktı akışı üzerinden iletişim kurulabilir. Bu yöntem, herhangi bir ağ protokolü kullanmadığı için ek gecikme veya ağ trafiği oluşturmaz; dolayısıyla maksimum performans sağlar ve özellikle bir IDE içinde çalıştırılan yerel araçlar için idealdir.
* **Akış Destekli HTTP Taşıması:** İstemci ile sunucu arasında HTTP üzerinden iletişim kurulmasını sağlar. İstemci, sunucuya JSON tabanlı isteklerini HTTP POST ile gönderirken; sunucu gerektiğinde **Server-Sent Events (SSE)** kullanarak istemciye akan (*streaming*) yanıtlar iletebilir. Bu yöntem uzaktaki (bulut veya internet üzerindeki) MCP sunucularına bağlanmak için kullanılır ve standart HTTP kimlik doğrulama mekanizmalarını destekler (taşıyıcı jetonlar, API anahtarları veya özel başlıklar gibi). Uzaktan iletişimde verinin gizliliği ve bütünlüğü için MCP üzerinden **HTTPS (TLS şifrelemesi)** kullanılması önerilmektedir.

Yukarıdaki mimari sayesinde MCP, birden fazla sunucuya aynı anda bağlanabilen esnek bir istemci-çoklu sunucu topolojisi oluşturur. Bu yapıda **MCP İstemcisi**, LLM barındıran uygulamanın içinde çalışarak her bir MCP sunucusuyla birebir bağlantı kuran bileşendir. **MCP Sunucusu** ise harici bağlam bilgisini sağlayan bağımsız bir süreçtir; dosya sistemi, veritabanı, harici API gibi kaynaklara erişebilir ve bunları istemciye bir “araç” arayüzüyle sunar. Örneğin Visual Studio Code editörü bir MCP **host** uygulaması olarak düşünülebilir; VS Code, Sentry hata izleme sistemi için bir MCP sunucusuna bağlandığında (uzak bir sunucu), aynı anda yerel dosya sistemi erişimi sunan başka bir MCP sunucusuna da bağlanabilir. Bu durumda VS Code içinde her sunucu bağlantısı için ayrı bir MCP istemci nesnesi çalışır ve her biri ilgili sunucusundan veri çeker.

<img width="836" height="512" alt="resim" src="https://github.com/user-attachments/assets/d0cdaa6e-aff0-4d03-ab74-bbd6107c5ff1" />

**Veri iletim mekanizması**, istemci, sunucu ve LLM arasındaki etkileşimle gerçekleşir. Bu akışı adım adım incelemek gerekirse:

1. **Kullanıcı isteği:** Son kullanıcı, MCP entegrasyonuna sahip AI uygulamasından (örneğin bir sohbet arayüzü veya IDE) bir talepte bulunur. Bu talep doğal dilde bir komut, soru veya görev tanımı olabilir ve öncelikle **MCP istemcisi** tarafından ele alınır.
2. **LLM ile planlama:** MCP istemcisi, bağlı olduğu MCP sunucularının hangi araçları sağladığı bilgisini elinde tutar. Kullanıcının isteğini alır almaz istemci, sunuculardan aldığı bu yetenek bilgilerini de **LLM’ye aktarır**. Başka bir deyişle, LLM’ye *“şu şu araçlar mevcut”* bilgisini vererek kullanıcı talebini çözümler. LLM, verilen görevi yerine getirmek için hangi araca ihtiyaç olduğunu ve bu araca hangi parametrelerle çağrı yapılacağını kararlaştırır ve istemciye bir yanıt üretir.
3. **Sunucuya istek:** LLM’nin yanıtına göre MCP istemcisi, ilgili aracı barındıran MCP **sunucusuna** bir istek gönderir. Bu istek, belirli bir aracı çalıştırma komutunu ve gerekli parametreleri içerir. İletişim, yerel sunucu ise STDIO üzerinden, uzak sunucu ise HTTP istekleri ile gerçekleşir.
4. **Sunucu işlemi ve yanıt:** MCP sunucusu, kendisine iletilen komutu gerçekleştirir. Örneğin bir dosya okuma aracına parametre olarak bir dosya yolu verildiyse, sunucu dosyayı okuyup içeriğini döndürür. Sunucu, işlemin sonucunu (ya da hata çıktıysa hata bilgisini) MCP istemcisine geri gönderir.
5. **LLM'nin sonuç üretmesi:** MCP istemcisi sunucudan aldığı ham sonucu tekrar LLM’ye iletir (veya LLM zaten önceki adımda bu sonucu bekliyor olabilir). LLM, sunucudan gelen veriyi kullanarak kullanıcıya verilecek nihai cevabı oluşturur. Örneğin, dosya içeriği istenmişse bunu kullanıcıya uygun biçimde sunan bir metin cevabı üretir.
6. **Kullanıcıya sunum:** Son olarak MCP istemcisi, LLM’nin ürettiği cevabı alır ve uygulama arayüzü üzerinden kullanıcıya gösterir. Kullanıcı, talebinin sonucunu insan tarafından yazılmışçasına doğal bir dilde almış olur.

Bu işlem döngüsü, MCP sayesinde LLM tabanlı bir sistemin **etkin bir araç kullanıcısına** dönüşmesini sağlamaktadır. Önemle vurgulanmalıdır ki MCP, LLM ile araçlar arasında doğrudan bir bağlantı kurmaz; bunun yerine istemci ve sunucu aracılığıyla kontrollü bir entegrasyon gerçekleştirir. İstemci tarafı LLM ile konuşmaktan sorumlu iken, sunucu tarafı gerçek dünya araçlarını çalıştırma görevini üstlenir. Bu ayrım, güvenlik ve kontrol açısından da önemlidir çünkü LLM’nin her şeye doğrudan erişimi olmaz; sadece istemcinin sunduğu arayüz dahilinde eylem yapabilir.

### Protokolün Katman Seviyesi ve Avantajları

MCP protokolü **uygulama katmanında** çalışan bir protokoldür. Yani OSI modeline göre bakıldığında, TCP/IP gibi taşıma katmanı protokollerinin üzerinde konumlanır ve uygulamalar arası veri alışverişinin anlamını tanımlar. Bu yüksek seviyeli konum, MCP’ye önemli avantajlar kazandırmaktadır. Öncelikle, uygulama katmanı protokolü olduğu için MCP mesajları **insan tarafından okunabilir JSON** formatında tanımlanmıştır ve bu sayede dil agnostik bir şekilde birden fazla programlama dilinde kolaylıkla uygulanabilir (nitekim halihazırda MCP için Python, TypeScript, Java, C#, Go, Rust gibi farklı dillerde SDK’lar mevcuttur). Protokol mesajlarının JSON-RPC standardını kullanması, yapılandırılmış bir iletişim sağlayarak hem istemci hem sunucu tarafında uygulanmasını ve hata ayıklamasını kolaylaştırır.

MCP’nin taşıma bağımsız bir üst düzey protokol olarak tasarlanmış olması, **esneklik** ve **uyumluluk** avantajı sağlar. Protokol, altında yatan taşıma katmanını soyutlayabildiği için aynı veri yapısını ister yerel ister uzak senaryolarda iletebilir. Örneğin, bir geliştirici MCP sunucusunu başlangıçta yerel STDIO modunda çalıştırıp test edebilir; daha sonra minimal değişiklikle aynı sunucuyu uzak bir HTTP servis olarak dağıtabilir. Bu sayede protokol, gelişen ihtiyaçlara göre ölçeklenebilir bir yapı sunar. Ayrıca MCP, doğrudan IP seviyesinde yeni bir protokol icat etmeyip HTTP gibi yaygın bir uygulama protokolünü opsiyon olarak kullandığı için mevcut altyapılarla **uyumludur** – güvenlik duvarları, yük dengeleyiciler veya HTTPS şifrelemesi gibi halihazırda oturmuş mekanizmaları tekrar keşfetmeye gerek kalmadan kullanabilir.

Taşıma katmanının soyutlanmasıyla gelen bir diğer avantaj, **güvenli iletişim ve kimlik doğrulama konusunda standartların yeniden kullanılmasıdır**. MCP, uzak sunucularla haberleşirken HTTPS üzerinden çalışarak TLS şifrelemesini devreye sokabilmekte ve HTTP’nin oturmuş kimlik doğrulama yöntemlerini (OAuth erişim tokenları, API anahtarları, vb.) aynen kullanabilmektedir. Bu, protokolün güvenlik konusunda güvenilir ve test edilmiş yöntemlerden faydalanmasını sağlar. Örneğin, Anthropic varsayılan olarak MCP yetkilendirmesi için OAuth 2.0 tabanlı bir token mekanizmasını öngörmüştür. Son kullanıcı açısından, MCP trafikleri tıpkı bir web trafiği gibi güvenli kanaldan akabildiği için ağ dinlemesi veya benzeri riskler azaltılmaktadır. Öte yandan yerel taşıma seçeneği (STDIO), ağ üzerinden veri geçirmediği için özellikle tek makine üzerinde çalışan senaryolarda **azami performans ve güvenlik** (dış saldırı yüzeyinin olmaması nedeniyle) sunar.

Özetle, MCP’nin uygulama katmanında konumlanması ve altındaki taşıma katmanını esnek tutması protokolü geniş bir kullanım yelpazesinde pratik hale getirmektedir. Bu sayede hem *platform bağımsızlığı* hem de *güvenlik ve performans* açısından geliştiricilere önemli kolaylıklar sağlar.

### MCP'nin Açık Kaynak Yapısının Güvenliğe Etkileri

MCP protokolünün **açık kaynak** olması, güvenlik açısından çift yönlü etkilere sahiptir. Olumlu tarafta, protokolün kaynak kodu ve spesifikasyonlarının açık olması, geniş bir topluluk tarafından incelenebilmesini ve katkı yapılabilmesini mümkün kılar. Nitekim MCP hızla popülerlik kazanırken, çeşitli güvenlik araştırmacıları ve şirketler de protokolü mercek altına almıştır. Bu kolektif inceleme sayesinde protokoldeki potansiyel zayıflıklar erken aşamada tespit edilip düzeltilebilmektedir. Topluluk üyeleri mevcut yetkilendirme mekanizmasının kurumsal uygulamalarla çelişen noktalarını fark etmiş ve yetkilendirme spesifikasyonunun iyileştirilmesi için girişimde bulunmuştur. Bu sayede, protokol geliştikçe güvenlik boyutunda da güncel en iyi uygulamalarla uyumlu hale gelmesi sağlanmaktadır.

Açık kaynağın bir diğer avantajı, *güvenlikte şeffaflık* sağlamasıdır. MCP ekosistemindeki istemci ve sunucu uygulamaları açık kaynak kodlu olduğu için, geliştiriciler veya kurumlar bu kodları inceleyerek içlerinde zararlı bir işlev olup olmadığını denetleyebilir. Kapalı kutu bir yazılıma kıyasla, açık kodlu bir MCP sunucusunun ne yaptığı görülebilir olduğu için sürpriz istenmeyen davranışlar riski teorik olarak daha düşüktür. Dahası, ekosistemdeki popüler MCP bileşenleri genellikle dijital imza ile yayınlanmakta veya bütünlük kontrolüne tabi tutulmaktadır; bu da koda dışarıdan zararlı bir müdahale yapılmadığını doğrulamayı mümkün kılar. Geliştiricilerin de kendi yayınladıkları MCP sunucularını imzalamaları ve kullanıcıların bu imzaları doğrulamaları tavsiye edilmektedir.

Öte yandan, açık kaynak olmanın getirdiği bazı **güvenlik riskleri** de vardır. Her şeyden önce, MCP protokolü tamamen açık bir ekosistem olduğundan, kötü niyetli aktörler de protokolü kullanarak zararlı MCP sunucuları geliştirebilir ve bunları topluluk içinde paylaşabilir. Örneğin, bir saldırgan ilk bakışta yararlı görünen bir MCP sunucusu (belki bir hava durumu aracı veya takvim aracı) yayınlayıp kullanıcıları bunu kurmaya ikna edebilir; ancak daha sonra bir güncelleme ile bu sunucuya gizlice hassas bilgileri toplayan veya yetkisiz komutlar çalıştıran işlevler ekleyebilir. Bu tür **“araç enjeksiyonu”** diyebileceğimiz senaryolarda, açık kaynak kod başlangıçta temiz olsa bile ileride kasıtlı olarak suistimal edilebilir hale getirilebilir. Benzer şekilde, sunucunun tanıttığı araçların ismini ve tanımını yanıltıcı seçmek de mümkün olduğundan, kötü niyetli bir geliştirici masum görünen bir aracı aslında farklı ve tehlikeli işler yapmak için tasarlayabilir. Açık kaynak dünyasında kullanıcıların her buldukları projeye güvenmemeleri, özellikle de MCP gibi *kod çalıştırma yeteneği olan* sunucular söz konusuysa, son derece kritiktir.

Açık kaynağın bir diğer zorluğu da **tedarik zinciri güvenliği** ile ilgilidir. MCP istemci ve sunucuları da sonuçta yazılım bileşenleridir ve paket yönetim sistemleri üzerinden dağıtılır. Saldırganlar popüler MCP paketlerinin isimlerini taklit eden (typosquatting) zararlı paketler yayınlayabilir veya geliştiricilerin hesaplarını ele geçirip zararlı güncellemeler çıkarabilir. Bu risk, genel olarak tüm açık kaynak projelerinde mevcuttur ve MCP de bir istisna değildir. Nitekim, MCP bileşenlerinin güvenliği için tavsiye edilen uygulamalar arasında *Statik Kod Analizi (SAST)* ve *Yazılım Bileşeni Analizi (SCA)* araçlarının kullanılması, bağımlılıkların bilinen zafiyetlere karşı taranması gibi süreçler sayılmaktadır. Proje geliştirme süreçlerinde bu tür güvenlik denetimlerinin uygulanması, açık kaynak olmanın getirdiği riskleri azaltmaya yardımcı olur.

Sonuç olarak, MCP’nin açık kaynak yapısı güvenlikte hem bir **imkan** hem de bir **sorumluluk** doğurmaktadır. Doğru yönetildiğinde, geniş bir katılımcı kitlesinin katkısıyla daha güvenli bir protokol gelişimi mümkün olmakta; ancak bu açıklık aynı zamanda suistimale açık bir ekosistem yarattığı için, kullanıcıların ve geliştiricilerin güvenlik farkındalığının yüksek olması gerekmektedir.

### Potansiyel Saldırı Senaryoları

MCP protokolü ve onu kullanan uygulamalar, tasarım itibariyle çeşitli saldırı türlerine maruz kalabilir. Bu bölümde, özellikle **Ortadaki Adam (Man-in-the-Middle)**, **Replay (Yeniden Oynatma)** ve **Enjeksiyon** saldırı vektörleri üzerinde durulacaktır:

* **Ortadaki Adam Saldırısı (MITM):** Bir MITM saldırısında, saldırgan istemci ile sunucu arasındaki trafiği gizlice dinleyip değiştirebilir. MCP, uzak sunucu bağlantılarında HTTP tabanlı iletişim kullandığı için, **şifrelenmemiş bir bağlantı (HTTP)** üzerinden iletişim kurulursa ciddi bir MITM riski oluşur. Örneğin, yerel ağda bir saldırgan MCP istemcisinin sunucuya giden trafiğini yakalayıp başka bir sunucuya yönlendirebilir veya içerik enjeksiyonu yapabilir. Bu nedenle MCP kullanımında **TLS şifrelemesi (HTTPS)** şarttır; aksi halde oturum açılış bilgilerinden, iletilen bağlam verisine kadar her şey üçüncü şahıslarca görülebilir veya değiştirilebilir. MITM sadece gizli dinleme değil, aynı zamanda istemci ile sunucu arasına girerek sahte yanıtlar verme veya istemciden gelen isteği bloklama gibi etkiler de yaratabilir. Uzak sunucularla iletişimde HTTPS kullanmak ve sunucu sertifikasını doğrulamak, bu tür saldırıların önlenmesinde temel önlemdir.

* **Replay Saldırıları:** Replay (yeniden oynatma) saldırısında, ağ trafiğini yakalayan bir saldırgan daha sonra bu trafiği tekrar göndererek sistemi kandırmaya çalışır. MCP protokolünde istemci-sunucu mesajları genellikle belirli bir isteğe yanıt ilişkisi içinde olduğundan ve protokol durumsal bir oturum yapısı barındırdığından, klasik anlamda replay yapmanın etkisi sınırlı olabilir. Ancak özellikle kimlik doğrulama veya yetki bilgilerinin tekrar kullanılması riski her zaman vardır. Örneğin bir saldırgan, bir MCP isteğini üzerindeki OAuth erişim jetonu ile birlikte ele geçirirse, bu isteği değiştirip yeniden göndermek suretiyle istenmeyen işlemler yaptırabilir. MCP spesifikasyonunda versiyon pazarlığı ve oturum başlatma mekanizmaları olsa da, **anti-replay için özel bir nonce veya zaman damgası kullandığına dair** açık bir bilgi olmayabilir. Dolayısıyla replay riskinin esasen **taşıma katmanının güvenliği** ile bertaraf edildiğini varsayabiliriz (örn. TLS içindeki oturum kimliği ve kısa ömürlü token kullanımı). Yine de, MCP sunucularının kritik işlemler için isteklerin tekilliğini kontrol etmesi veya aynı token’ın art arda kullanımını kısıtlaması gibi önlemler düşünülebilir. Sonuç itibariyle, replay saldırılarına karşı **en iyi savunma**, trafiğin şifrelenmesi ve geçerlilik süresi sınırlı, tek seferlik yetkilendirme jetonları kullanılmasıdır.

* **Enjeksiyon Saldırıları:** MCP ekosisteminde *enjeksiyon* kavramı birden fazla boyutta karşımıza çıkar:

  * **Komut Enjeksiyonu:** Birçok MCP sunucusu, alt seviyede kabuk komutları veya sistem çağrıları çalıştırarak görevlerini yerine getirir (özellikle yerel sunucular). Eğer sunucu, kullanıcıdan veya LLM’den gelen girdileri uygun şekilde filtrelemez ve doğrudan bir komut satırına aktarırsa, saldırganlar bu durumu **komut enjeksiyonu** için kullanabilir. Örneğin, bazı MCP sunucu kodlarında, kullanıcı bildirim başlığı oluşturulurken gelen değerin doğrudan `notify-send` komutuna parametre verildiği görülebilir; burada yeterli denetim olmadığından potansiyel bir komut enjeksiyonu açıklığı oluşabilir. Kötü niyetli bir aktör, özel hazırlanmış girdilerle bu açığı tetikleyerek sunucunun yetkileriyle rastgele komutlar çalıştırabilir. Bu tür vakalar, özellikle yerel MCP sunucularının kullanıcı hesabı haklarıyla çalıştığı senaryolarda **tam sistem tehlikeye atılması** ile sonuçlanabilir. Dolayısıyla MCP sunucusu geliştiricilerinin, çalıştırdıkları komutları ve bu komutlara verdikleri argümanları çok sıkı şekilde denetlemeleri, gerekirse girilen değerleri beyaz liste yöntemiyle filtrelemeleri kritiktir. Ayrıca, yerel sunucuların bir **sandbox (korunaklı ortam)** içinde, erişim izinleri kısıtlanmış şekilde çalıştırılması önerilmektedir.
  * **Prompt Enjeksiyonu:** Bu saldırı türü doğrudan protokolün teknik altyapısını değil, LLM’nin zafiyetini hedef alır ancak MCP bağlamında özel bir önem kazanır. MCP, LLM’nin dış araçları kullanmasına olanak sağladığı için, kötü niyetli bir yönlendirme (prompt) ile LLM’yi tehlikeli bir aracı çalıştırmaya ikna etmek mümkün hale gelebilir. Örneğin, bir saldırgan kullanıcıyı kandırarak MCP istemcisine girdiği komutun içine gizlenmiş zararlı bir talimat koydurabilir. LLM bu girdiyle çalışırken, görünürde masum görünen isteği gerçekleştirmenin yanında saldırganın arzusuyla ek bir işlem de başlatabilir (örneğin, “talep edilen yeni kullanıcı hesabını oluşturmanın” yanı sıra bir de saldırgan için yüksek yetkili bir hesap oluşturma). Bu tür prompt enjeksiyonları, özellikle LLM yanıtlarına koşulsuz güvenilip kullanıcı onayı aranmadan eyleme döküldüğünde ciddi hasarlara yol açabilir. Bu nedenle, MCP istemcileri kritik işlemleri gerçekleştirmeden önce mümkün olduğunca **kullanıcıdan onay almalıdır** veya LLM'nin yapabileceklerini kısıtlayacak politikalar uygulamalıdır.
  * **Araç (Tool) Enjeksiyonu:** Yukarıda açık kaynak riskleri kısmında değinilen senaryonun bir parçası olarak, MCP sunucularının tanıttığı araçlar suistimal edilebilir. Bu saldırı, bir bakıma *supply chain* sorunuyla birleşir; bir saldırgan, sağladığı aracın masum fonksiyonunu daha sonra güncelleyerek kullanıcıya zarar verecek hale getirebilir. Örneğin, başlangıçta sadece hava durumu bilgisini döndüren bir araç, ileride güncellemeyle kullanıcı verilerini çalan bir kod parçasına dönüştürülebilir. LLM, aracın açıklamasına güvenerek onu kullanacağı için, bu durumda saldırgan arka planda kötü faaliyetine devam ederken, kullanıcı ve istemci tarafı yalnızca aracın normal çıktısını görüp aldatılabilir. Bu nedenle, MCP istemcilerinin kurulu sunucuların kod veya davranış değişikliklerini izleyebilmesi, versiyon kilitleme (*pinning*) yaparak beklenmedik güncellemeleri engellemesi ve kullanıcıyı bilgilendirmesi önemli bir koruma yöntemidir.

Yukarıdaki saldırı türleri MCP protokolünün farklı bileşenlerini hedef almakla birlikte, ortak nokta olarak *MCP kullanımında güvenlik bilincinin önemini* ortaya koymaktadır. Gerek altyapısal (ör. MITM, replay) gerek uygulama seviyesinde (enjeksiyon) olsun, protokolü kullanırken uygun önlemler alınmadığı takdirde istenmeyen sonuçlarla karşılaşmak olasıdır.

### MCP Protokolündeki Mevcut Güvenlik Önlemleri ve Değerlendirmesi

Anthropic (soruda bahsedilen adıyla *Antopic*), MCP protokolünü tasarlarken bazı temel güvenlik önlemlerini dahil etmiştir. Bunların başında, protokolün **kimlik doğrulama ve yetkilendirme mekanizması** gelir. MCP, uzak sunucular için OAuth 2.0 tabanlı erişim token’ları kullanılmasını önererek, her istemci-sunucu bağlantısının bir yetki kontrolüne tabi olmasını sağlamaya çalışır. Bu sayede, her MCP sunucusu eylemini bir kullanıcı veya uygulama adına gerçekleştirecekse, önceden alınmış bir erişim iznine sahip olması beklenir. Ancak burada önemli bir nokta, mevcut spesifikasyondaki OAuth kullanım detaylarının her senaryoya uymayabileceğinin ortaya çıkmış olmasıdır. Topluluktan gelen geri bildirimlere göre MCP’nin ilk yetkilendirme tanımı, kurumsal ortamlardaki bazı modern uygulamalarla çelişmektedir ve bu konuda resmi spesifikasyonun güncellenmesi gündemdedir. Bu durum, protokolün yetkilendirme boyutunda henüz tam olgunlaşmadığını ve geliştirilmeye açık yanlar olduğunu göstermektedir.

Bir diğer yerleşik güvenlik önlemi, **iletişimin şifrelenmesi** ile ilgilidir. Her ne kadar MCP doğrudan “şifreleme zorunluluğu”nu kendi içinde dayatmasa da (zira bu genellikle taşıma katmanının sorumluluğudur), dokümantasyon ve topluluk rehberlerinde uzak bağlantılar için TLS destekli HTTPS kullanılmasının altı çizilir. Özellikle GitHub gibi MCP kullanan platformlar, kendi sunucuları ile istemci arasındaki etkileşimlerde güvenlik için ek mekanizmalar uygulamıştır. Örneğin GitHub’ın MCP sunucusu (Copilot ile entegrasyon amaçlı), paylaşılan depo verilerinde gizli anahtarların açığa çıkmasını önlemek için “push protection” adlı bir güvenlik filtresi kullanır; bu filtre sayesinde MCP üzerinden gerçekleştirilen eylemlerde hassas verilerin sızması engellenir. Bu tür önlemler MCP protokolünün parçası olmasa da, onu kullanan hizmetlerin kendi güvenlik katmanlarını eklediğini göstermektedir.

Anthropic’in MCP için geliştirdiği referans sunucularda da bazı güvenlik düşünceleri mevcuttur. Örneğin, yerel dosya sistemi sunucusu belli bir dizin altında erişime izin vererek bir tür *sandbox* yaratmayı hedefler. Ancak yapılan bağımsız güvenlik analizleri, bu yaklaşımın kusursuz olmadığını ortaya koymuştur. Bazı güvenlik araştırmaları, resmi dosya sistemi MCP sunucusunda dizin atlama veya sembolik bağ (symlink) yoluyla kısıtlamaların atlatılabildiğini ve bunun sunucunun çalıştığı sistemde daha geniş erişimlere yol açabildiğini göstermiştir. Bu bulgular, Anthropic’in koyduğu güvenlik önlemlerinin (dizin kısıtlaması gibi) tek başına yeterli olmadığını göstermiştir. Özellikle LLM tabanlı araçların çoğunlukla geliştirici rahatlığı için yüksek ayrıcalıklarla (örn. kullanıcı oturumunda veya bazen yönetici haklarıyla) çalıştırıldığı düşünülürse, bu tip açıklar kötüye kullanıldığında **sistem bütünlüğünü ciddi şekilde tehlikeye atmaktadır**.

Bununla birlikte, olumlu tarafından bakıldığında Anthropic ve genel olarak MCP topluluğu güvenlik açıklarına oldukça hızlı reaksiyon vermektedir. Örneğin bazı projelerde bildirilmiş uzaktan kod çalıştırma açıkları, proje geliştiricileri tarafından kısa sürede yamanmıştır. Aynı şekilde çeşitli sandbox kaçışı sorunlarına karşı da ilgili yamalar ve kullanıcılara yönelik uyarılar yayınlanmıştır. Bu durum, MCP ekosisteminin güvenlik konusunu ciddiye aldığını ve proaktif iyileştirmelere gittiğini göstermektedir. Yine de, henüz genç sayılabilecek bu protokol için mevcut güvenlik önlemlerinin *“yeterli”* olduğunu söylemek zordur. Ortaya çıkan her yeni kullanım senaryosu veya sunucu uygulaması, kendine özgü güvenlik açıkları barındırabilir. Anthropic’in başlangıçta protokole dahil ettiği temel güvenlik kavramları (OAuth ile yetkilendirme, JSON-RPC ile yapılandırılmış ileti vb.) önemli bir zemin sağlasa da, gerçek dünyadaki saldırı senaryoları bu önlemlerin etrafından dolaşmanın yollarını bulmuştur. Özetle, **MCP’nin güvenliği hala evrim geçirmektedir**; mevcut önlemler bazı tehditleri azaltmakla birlikte, protokolün tam anlamıyla güvenli kabul edilebilmesi için sürekli gözden geçirme, test etme ve güncelleme gerekmektedir.

### Geliştiriciler ve Kurumlar İçin Güvenli MCP Uygulama Önerileri

MCP protokolünü güvenli bir biçimde uygulamak ve kullanmak isteyen geliştiriciler ile kurumlar, aşağıdaki önlemleri göz önünde bulundurmalıdır:

* **Güvenli İletişim ve Sertifika Doğrulaması:** Uzak MCP sunucularıyla haberleşirken daima HTTPS protokolü kullanın ve sunucu sertifikasının doğrulandığından emin olun. Şifrelenmemiş HTTP üzerinden asla hassas veri iletmeyin; aksi halde MITM saldırılarına açık hale gelirsiniz. Gerekirse istemci tarafında, sunucu URL’sinin `https://` ile başlamadığını fark edince bağlantıyı reddeden kontroller ekleyin.
* **Güçlü Kimlik Doğrulama ve Yetkilendirme:** MCP sunucularına erişim için mümkünse OAuth 2.0 gibi ispatlanmış yöntemlerle alınan erişim token’ları kullanın. Her sunucunun erişim token’ına sadece gerekli asgari yetkileri (scopeları) tanıyın (örneğin bir dosya sistemi sunucusuna salt okunur erişim izni vermek gibi). “En az ayrıcalık” ilkesini gözetin; bir MCP sunucusunun kullanıcı adına yapabileceği işlemleri kısıtlayın. Ayrıca, bir istemci bir sunucuya erişirken tek oturumluk veya kısa ömürlü token’lar kullanmayı, bunları düzenli olarak yenilemeyi ihmal etmeyin.
* **Güvenilmeyen Sunuculara Karşı Tedbir:** Yalnızca güvendiğiniz kaynaklardan gelen MCP sunucularını yükleyin veya bağlanın. Topluluk tarafından pek incelenmemiş, rastgele depolardan gelen sunucu uygulamalarını kullanmak risklidir. Kurum içinde MCP kullanılacaksa, **onaylı bir sunucu listesi** oluşturarak kullanıcıların sadece bu sunuculara bağlanmasına izin verin. MCP istemci uygulamanız, bağlanılan sunucunun kimliğini (örneğin dijital imza veya hash doğrulaması ile) kontrol edebiliyorsa bu özelliği etkinleştirin.
* **Kod Bütünlüğü ve Güncellemeler:** MCP sunucu ve istemci yazılımlarınızın bütünlüğünü ve güncelliğini koruyun. Kendi geliştirdiğiniz MCP sunucularını dijital olarak imzalayın ve kullanıcıların indirdiği kodun bu imzayla eşleştiğini doğrulayın. Kullandığınız MCP bileşenlerinde çıkan güvenlik güncellemelerini yakından takip edin ve gecikmeden uygulayın. Standart bir **zafiyet yönetimi** süreci dahilinde, MCP ile ilgili kütüphaneleri ve araçları belirli aralıklarla tarayıp bilinen açıklar için yamaları geçirin.
* **Güvenli Kod Geliştirme Prensipleri:** Bir MCP sunucusu geliştiriyorsanız, kullanıcılardan veya LLM’den alacağınız her girdiğin potansiyel olarak zararlı olabileceğini varsayın. Özellikle komut satırı çağrıları, dosya erişimleri gibi işlemleri gerçekleştirirken girdi validasyonuna önem verin. Parametreleri sistem komutlarına iletmeden önce boşluk, noktalı virgül, ampersand gibi komut ayrıştırıcı karakterlerden arındırın veya bu karakterlere izin vermeyin. SQL sorguları, kabuk komutları veya işletim sistemi API’leri çağrıları yapıyorsanız **enjeksiyon karşıtı** güvenlik kalıplarını uygulayın (örn. parametreli sorgular, sabit argüman listeleri vb.). Ayrıca, derleme ve CI süreçlerinize statik kod analizi araçları entegre ederek zayıflıkları daha kod yazım aşamasında yakalamaya çalışın.
* **Sandbox ve Ayırılmış Haklar:** Mümkün olan her durumda, MCP sunucularını izole bir ortama hapsedin. Örneğin bir dosya sistemi MCP sunucusu, sadece belli bir klasör altında okuma/yazma yapabilecek şekilde *chroot/jail* ortamında veya konteyner içinde çalıştırılmalıdır. İşletim sistemi seviyesinde bu sunuculara ayrı kullanıcı hesapları tahsis etmek ve bu hesaplara minimum yetkileri vermek etkili bir yöntemdir. Böylece, olası bir saldırıda sunucunun yapabilecekleri kısıtlanmış olacaktır ve sistem geneline yayılması engellenir.
* **Kullanıcı Onayı ve Denetim Mekanizmaları:** MCP istemcisi tarafında, LLM’nin tetiklediği yüksek riskli eylemler için mutlaka kullanıcının onayını alacak bir adım ekleyin. Örneğin, dosya silme, yeni kullanıcı oluşturma, para transferi gibi kritik bir işlem bir araç ile yapılacaksa, LLM bunu istese dahi kullanıcıdan “Onaylıyor musunuz?” şeklinde bir geri bildirim almadan yürütmeyin. Bu, olası prompt enjeksiyonu vakalarında istenmeyen sonuçları önlemek için son savunma hattıdır. Benzer şekilde, MCP istemciniz gerçekleştirilen işlemleri kullanıcıya özetleyebiliyorsa (görev tamamlandığında “Sunucu X şu işlemi gerçekleştirdi” gibi), bu şeffaflık kullanıcıyı güvende tutmaya yardımcı olacaktır.
* **Kayıt ve İzleme:** MCP sunucularının yaptığı işlemleri merkezi bir günlük (log) sistemine kaydetmesi veya en azından yerel olarak log tutması çok önemlidir. Böylece, geriye dönük bir inceleme gerektiğinde hangi komutların çalıştırıldığı, hangi kaynaklara erişildiği tespit edilebilir. Kurumlar, MCP aracılığıyla gerçekleştirilen bütün hareketleri SIEM gibi güvenlik izleme sistemlerine besleyerek anormal bir durum olup olmadığını denetleyebilirler. Örneğin, normalde bir araç günde birkaç kez çalışırken aniden yüzlerce kez çalışmaya başlamışsa, bu bir kompromize işareti olabilir ve loglar sayesinde görülebilir.
* **Sürüm Kilitleme ve Doğrulama:** Üçüncü parti MCP sunucularını uygulamanıza entegre ediyorsanız, belirli güvenilir bir sürüme kilitleyin ve bu sunucunun kodunda sonradan bir değişiklik olup olmadığını izleyin. Otomatik güncellemeler yerine manuel inceleme sonrası güncelleme yapma yaklaşımını benimseyin. Bu sayede, bir araç güncellendiğinde içine eklenmiş olası zararlı bir kod parçasını fark etme şansınız olur.

Yukarıdaki önlemler, MCP protokolünün getirdiği esneklik ve güç ile beraber gelen riskleri azaltmaya yöneliktir. Gerek bireysel geliştiriciler, gerekse MCP’yi altyapılarında kullanmayı planlayan kurumlar, **“güvenliği en baştan tasarlama”** ilkesini uygulamalıdır. Bu, protokolün kendi sağladığı güvenlik özellikleri kadar, kullanım ortamındaki operasyonel güvenlik tedbirlerini de içerir.

### Sonuç

“Antopic” (Anthropic) tarafından geliştirilen açık kaynak MCP protokolü, yapay zekâ uygulamalarının yeteneklerini artıran yenilikçi bir mimari ve standart getirmiştir. Bu çalışma kapsamında MCP’nin mimari yapısı ve işleyişi detaylı bir şekilde incelenmiş; protokolün LLM’lerle araçlar arasında nasıl bir **bağlamsal köprü** kurduğu ortaya konmuştur. Elde edilen bulgular, MCP’nin sağladığı faydalar kadar, göz ardı edilmemesi gereken güvenlik boyutunu da vurgulamaktadır. Özellikle protokolün açık kaynak doğası sayesinde henüz geliştirme aşamasındayken çeşitli güvenlik açıkları tespit edilmiş ve paylaşılmıştır. Bu sayede geliştiriciler ve kullanıcılar, protokolü üretim ortamlarına taşımadan önce riskleri görme ve önlem alma fırsatı yakalamıştır.

Yapılan değerlendirmeler göstermektedir ki MCP üzerindeki bazı güvenlik açıklarının **önceden belirlenmesi ve giderilmesi**, ileride yaşanabilecek ciddi ihlallerin önüne geçebilecektir. Bu raporda dile getirilen potansiyel saldırı vektörleri ve gerçek dünyada karşılaşılan zafiyetler, protokolün uygulanması esnasında nelere dikkat edilmesi gerektiğine dair somut bir farkındalık yaratır. Gerek Anthropic’in resmi iyileştirmeleri, gerekse bağımsız araştırmacıların bulguları ışığında, MCP’nin güvenlik mimarisi sürekli evrilmektedir. Dolayısıyla bu çalışma, hem MCP geliştiricilerine hem de protokolü kendi sistemlerinde kullanmayı düşünen kurumlara yönelik proaktif bir uyarı niteliğindedir.

Teknik literatüre katkı anlamında, MCP protokolünün mimarisi ve işlevselliğine dair derinlemesine bir bakış sunulmuştur. Bu, henüz yeni sayılabilecek bir standart hakkında derli toplu bir bilgi birikimi sağlaması açısından değerlidir. Ayrıca **açık kaynak protokollerin güvenliği** konusunda genel çıkarımlar yapma imkânı da doğmuştur: Şeffaflık ve kolektif katkı sayesinde güvenlik açıklarını hızla bulup düzeltmek mümkün olsa da, açık ekosistemde güvenin tesis edilmesi ve sürdürülmesi ayrı bir çaba gerektirmektedir. Sonuç olarak, MCP protokolü özelinde elde edilen deneyimler, benzer şekilde geliştirilen diğer açık kaynak projelerde de güvenlik odaklı yaklaşımın önemini pekiştirmektedir.

MCP protokolü doğru uygulandığında yapay zekâ dünyasında verimlilik ve yetenek artışı sağlayan bir araçtır; ancak güvenlik prensipleri ikinci plana atılmadan, “önce güvenlik” yaklaşımıyla ele alınmalıdır. Bu denge sağlandığında, MCP gibi protokoller inovasyon ile emniyeti bir arada götürebilecek, hem geliştiriciler hem de kullanıcılar için büyük kazanımlar sunacaktır.

### Kaynaklar

* Anthropic — Model Context Protocol (MCP) GitHub projesi ve resmi belgeler
* GitHub Docs — Model Context Protocol (MCP) hakkında dokümantasyon
* Bağımsız güvenlik raporları ve analizler (örnek güvenlik araştırma raporları, CVE bildirileri, proje yamaları)

---

## Ek A: Literatür

### Akademik Makaleler

- **Konu Başlığı:** Model Context Protocol (MCP): Landscape, Security Threats, and Future Research Directions
  **Kaynak/Kurum & Tarih:** arXiv, 2025-03
  **Bağlantı:** [https://arxiv.org/abs/2503.23278](https://arxiv.org/abs/2503.23278)
  **Türkçe Özet:** MCP’nin mimari ve güvenlik boyutlarını inceleyen çalışma, dört evre ve 16 faaliyet adımından oluşan bir yaşam döngüsü modeli sunar. 16 senaryoluk bir tehdit taksonomisi oluşturur ve MCP’nin mevcut endüstri benimsenmesini değerlendirir. Protokolün güçlü yönleri ile yaygın kullanımını sınırlayan eksikler belirlenir ve gelecekteki araştırma yönleri tanımlanır.

- **Konu Başlığı:** MCP-Universe: Benchmarking Large Language Models with Real-World Model Context Protocol Servers
  **Kaynak/Kurum & Tarih:** arXiv, 2025-08
  **Bağlantı:** [https://arxiv.org/abs/2508.14704](https://arxiv.org/abs/2508.14704)
  **Türkçe Özet:** Gerçek MCP sunucularıyla etkileşimli görevlerden oluşan *MCP-Universe* adlı kıyaslama paketi tanıtılır. GPT-5, Grok-4 ve Claude-4.0-Sonnet gibi modeller test edilmiştir. Uzun-bağlam ve bilinmeyen araç sorunları tespit edilmiştir. Çalışma, MCP-tabanlı değerlendirme ekosisteminin açık kaynak altyapısını sağlar.

- **Konu Başlığı:** Automatic Red Teaming LLM-based Agents with Model Context Protocol Tools
  **Kaynak/Kurum & Tarih:** arXiv, 2025-09
  **Bağlantı:** [https://arxiv.org/abs/2509.21011](https://arxiv.org/abs/2509.21011)
  **Türkçe Özet:** MCP araçlarının **araç zehirleme saldırılarına** açık olduğu belirtilir. Önerilen *AutoMalTool* sistemi, LLM ajanlarını kötü niyetli MCP araçlarıyla otomatik olarak test eder. Bulgular, mevcut MCP güvenlik önlemlerinin yetersiz olduğunu ve sistematik kırmızı takım yaklaşımına ihtiyaç duyulduğunu gösterir.

- **Konu Başlığı:** Advancing Multi-Agent Systems Through Model Context Protocol
  **Kaynak/Kurum & Tarih:** arXiv, 2025-04
  **Bağlantı:** [https://arxiv.org/abs/2504.21030](https://arxiv.org/abs/2504.21030)
  **Türkçe Özet:** Çok etmenli yapay zekâ sistemlerinde bağlam paylaşımını standartlaştıran MCP mimarisi açıklanır. Kurumsal bilgi yönetimi ve dağıtık problem çözme senaryolarında performans artışı sağladığı gösterilir. MCP’nin koordinasyon verimliliğini ve bağlam farkındalığını artırdığı vurgulanır.

- **Konu Başlığı:** Model Context Protocol (MCP) at First Glance: Studying the Security and Maintainability of MCP Servers
  **Kaynak/Kurum & Tarih:** arXiv, 2025-06
  **Bağlantı:** [https://arxiv.org/abs/2506.13538](https://arxiv.org/abs/2506.13538)
  **Türkçe Özet:** 1.899 açık kaynak MCP sunucusu incelenmiş ve sekiz güvenlik açığı tespit edilmiştir. Sunucuların %7,2’sinde genel güvenlik, %5,5’inde araç zehirleme riski görülür. MCP’ye özgü zafiyet tarama teknikleri önerilir.

- **Konu Başlığı:** MCP-Guard: A Defense Framework for Model Context Protocol Integrity in LLM Applications
  **Kaynak/Kurum & Tarih:** arXiv, 2025-08
  **Bağlantı:** [https://arxiv.org/abs/2508.10991](https://arxiv.org/abs/2508.10991)
  **Türkçe Özet:** MCP-Guard adlı çok katmanlı savunma mimarisi önerilir. Statik analiz, derin öğrenme tabanlı dedektör ve LLM “hakem” modülü ile tehditler %96 doğrulukla tespit edilir. *MCP-AttackBench* veri seti 70 000’den fazla saldırı örneği içerir.

- **Konu Başlığı:** A Survey of the Model Context Protocol (MCP): Standardizing Context to Enhance LLMs
  **Kaynak/Kurum & Tarih:** Preprints.org, 2025-04
  **Bağlantı:** [https://www.preprints.org/manuscript/202504.0245/v1](https://www.preprints.org/manuscript/202504.0245/v1)
  **Türkçe Özet:** MCP’nin mimarisi, istemci-sunucu modeli ve dinamik araç keşfi mekanizmaları incelenir. Protokolün ajan sistemlerinde birlikte çalışabilirliği artırdığı, ancak güvenlik ve benimsenme sorunlarının devam ettiği vurgulanır.

- **Konu Başlığı:** A Survey of Agent Interoperability Protocols: MCP, ACP, A2A, and ANP
  **Kaynak/Kurum & Tarih:** arXiv, 2025-05
  **Bağlantı:** [https://arxiv.org/abs/2505.02279](https://arxiv.org/abs/2505.02279)
  **Türkçe Özet:** MCP, ACP, A2A ve ANP protokolleri karşılaştırılır. MCP’nin JSON-RPC tabanlı güvenli araç çağrısı sağladığı; ACP ve A2A’nın mesajlaşma ve görev devri sağladığı açıklanır. MCP’nin birlikte çalışabilir sistemler için temel adım olduğu sonucuna varılır.

- **Konu Başlığı:** Model Context Protocols in Adaptive Transport Systems: A Survey
  **Kaynak/Kurum & Tarih:** arXiv, 2025-08
  **Bağlantı:** [https://arxiv.org/abs/2508.19239](https://arxiv.org/abs/2508.19239)
  **Türkçe Özet:** Akıllı ulaşım sistemlerinde bağlam paylaşımı için MCP’nin potansiyeli analiz edilir. MCP’nin anlamsal birlikte çalışabilirlik sağladığı ve dinamik veri alışverişinde avantaj sunduğu belirtilir. Geleceğin uyarlanabilir ulaşım mimarilerinde MCP’nin temel rol oynayabileceği öngörülür.

---

### Sektörel Raporlar ve Bloglar

- **Konu Başlığı:** Introducing the Model Context Protocol
  **Kaynak/Kurum & Tarih:** Anthropic, 2024-11
  **Bağlantı:** [https://www.anthropic.com/news/model-context-protocol](https://www.anthropic.com/news/model-context-protocol)
  **Türkçe Özet:** Anthropic, MCP’yi yapay zekâ asistanları ile veri kaynakları arasında güvenli bağlantı kuran açık standart olarak tanıtmıştır. SDK’lar ve örnek MCP sunucuları açık kaynak paylaşılmıştır. MCP, farklı sistemler arasında bağlamı koruyarak veri erişimini sadeleştirir.

- **Konu Başlığı:** Microsoft Build 2025 – The Age of AI Agents
  **Kaynak/Kurum & Tarih:** Microsoft Official Blog, 2025-05
  **Bağlantı:** [https://blogs.microsoft.com/blog/2025/05/19/microsoft-build-2025-the-age-of-ai-agents-and-building-the-open-agentic-web/](https://blogs.microsoft.com/blog/2025/05/19/microsoft-build-2025-the-age-of-ai-agents-and-building-the-open-agentic-web/)
  **Türkçe Özet:** Microsoft, MCP’yi GitHub, Copilot Studio, Dynamics 365 ve Azure AI Foundry gibi ürünlerde entegre etmiştir. MCP Yürütme Komitesi’ne katılarak protokolün güvenli standardizasyonunu desteklemiştir. OAuth 2.1 tabanlı yeni kimlik doğrulama sistemi geliştirilmiştir.

- **Konu Başlığı:** Introducing the Data Commons MCP Server
  **Kaynak/Kurum & Tarih:** Google Developers Blog, 2025-09
  **Bağlantı:** [https://developers.googleblog.com/en/datacommonsmcp/](https://developers.googleblog.com/en/datacommonsmcp/)
  **Türkçe Özet:** Google, kamu veri setlerini MCP sunucusu üzerinden AI ajanlarına açmıştır. Bu yaklaşım, LLM’lerin güvenilir verilere erişmesini ve halüsinasyon oranının azalmasını sağlar. Data Commons MCP sunucusu Gemini CLI ve Cloud Agent Kit ile entegre çalışır.

- **Konu Başlığı:** A New Frontier for Network Engineers
  **Kaynak/Kurum & Tarih:** Cisco Blogs, 2025-05
  **Bağlantı:** [https://blogs.cisco.com/learning/a-new-frontier-for-network-engineers-agentic-ai-that-understands-your-network](https://blogs.cisco.com/learning/a-new-frontier-for-network-engineers-agentic-ai-that-understands-your-network)
  **Türkçe Özet:** MCP, ağ mühendisliğinde AI asistanlarının gerçek ağ topolojisine uygun çözümler üretmesini sağlar. JSON formatında bağlamsal ağ verisi LLM’e aktarılır, böylece model kurumun özgün altyapısına uyumlu yapılandırmalar üretir.

- **Konu Başlığı:** What is Model Context Protocol (MCP)?
  **Kaynak/Kurum & Tarih:** IBM Think Blog, 2025-05
  **Bağlantı:** [https://www.ibm.com/think/topics/model-context-protocol](https://www.ibm.com/think/topics/model-context-protocol)
  **Türkçe Özet:** IBM, MCP’yi AI ile harici servisler arasında evrensel bağlantı katmanı olarak tanımlar. LLM’lerin eğitim verisi sınırını aşarak API ve veri tabanlarına güvenli erişmesini sağlar. MCP, USB-C benzeri bir “standart arayüz” olarak görülür.

- **Konu Başlığı:** WTF is Model Context Protocol (MCP) and why should publishers care?
  **Kaynak/Kurum & Tarih:** Digiday, 2025-09
  **Bağlantı:** [https://digiday.com/media/wtf-is-model-context-protocol-mcp-and-why-should-publishers-care/](https://digiday.com/media/wtf-is-model-context-protocol-mcp-and-why-should-publishers-care/)
  **Türkçe Özet:** Yayıncılık sektörü için MCP’nin “AI çağının robots.txt dosyası” olabileceği vurgulanır. Yayıncılar MCP sunucuları üzerinden hangi içeriklerin AI ajanlarına açılacağını belirleyebilir. Bu sayede hem veri gizliliği hem gelir modelleri kontrol altına alınır.

---

### Alanlara Göre Yoğunluk Analizi

- **En Yoğun Alanlar:** Yapay zekâ, bilgi teknolojileri, güvenlik
- **Gelişmekte Olan Alanlar:** Ağ mühendisliği, veri bilimi, dijital medya
- **Potansiyel Alanlar:** Savunma, biyoteknoloji (henüz erken aşama)

MCP’nin en çok AI altyapısı, yazılım entegrasyonu ve güvenlik konularında ele alındığı görülür. Cisco, Google ve IBM gibi şirketler kendi alanlarında MCP’yi uygulamaya başlamış; akademi ise özellikle güvenlik, standardizasyon ve çok-etmenli koordinasyon boyutlarını araştırmaktadır.

---

### Genel Değerlendirme

Model Context Protocol (MCP), 2024 sonunda tanıtılmasından bu yana AI ajanlarının dış dünyayla güvenli ve standart bir biçimde iletişim kurmasını sağlamıştır.
2025 itibarıyla MCP, **Anthropic**, **OpenAI**, **Microsoft**, **Google**, **IBM** ve **Cisco** gibi büyük oyuncular tarafından benimsenmiş, çok sayıda akademik çalışma da protokolün güvenlik ve performans yönlerini ele almıştır.
Protokol, AI ajan ekosistemini “tek tip bağlantı standardı” altında birleştirirken, aynı zamanda yeni güvenlik risklerini de beraberinde getirmiştir.
Akademik çözümler (ör. MCP-Guard, MCP-AttackBench) bu riskleri azaltmaya yöneliktir.
Gelecekte MCP’nin tıpkı **USB-C** veya **HTTP** gibi evrensel bir altyapı standardına dönüşmesi beklenmektedir; bu da yapay zekâ sistemlerinin bağlam farkındalığını, güvenliğini ve birlikte çalışabilirliğini köklü biçimde geliştirecektir.

---

---


## Ek B: Google Scholar ve Sentez

> Not: Bu bölümdeki giriş ve mimari özetler Rapor bölümüyle örtüşür. Tekrarı azaltmak için odak; makale özetleri, tematik sentez ve ek kaynaklardır.


Büyük Dil Modellerinin (LLM) evrimi, yapay zekâ alanında temel bir paradigma değişimini temsil eder ve modelleri pasif metin üretiminin ötesine, gerçek dünyadaki görevleri yerine getirebilen aktif, otonom bir **ajansa** doğru taşır. Bu ajans dönüşümü, **harici araçların çağrılması** için sağlam ve ölçeklenebilir mekanizmalar gerektirir. [1]
Tarihsel olarak, LLM'lerin harici yeteneklerle entegrasyonu, **entegrasyon zorluğu** nedeniyle engellenmiştir. Bu senaryoda LLM platformları, mevcut harici araçların veya API'lerin her biri için **özel, sabit kodlu bağlamalar** gerektiriyordu. Bu da farklı entegrasyon yollarına yol açarak **yüksek bakım maliyetleri**, yinelemeler ve ekosistem ölçeklendirilmesinde engellere neden oluyordu. [2]

**Model Bağlam Protokolü (MCP)**, bu entegrasyon darboğazını çözmek için geliştirilmiştir. Protokol, çerçeveye özgü, uygulama merkezli araç bağlamalarından; **birleştirilebilir ve dinamik olarak keşfedilebilir ağ hizmetleri**nden oluşan, birlikte çalışabilir bir ekosisteme geçişi öngörür. [2] LLM ile dış dünya arasındaki arayüzü **standartlaştırarak**, MCP yinelenen bakım çabalarını azaltır ve **araç destekli yapay zekâ** için paylaşımlı, ölçeklenebilir bir ekosistem oluşturur. [2]


Anthropic tarafından 2024 yılının sonlarında tanıtılan **Model Context Protocol (MCP)**, AI sistemlerinin temel model sınırlarının dışındaki harici verilere, API’lere ve araçlara erişmesi için **tutarlı bir mekanizma** sağlayan, **açık kaynaklı**, **şema odaklı** bir standarttır. [1]
Genellikle AI için **“evrensel konektör”** olarak nitelendirilen MCP, **gerçek zamanlı karar verme** için tasarlanmıştır ve **ölçeklenebilir, akıllı ajan iş akışları** oluşturmanın temelini oluşturur. [3]

MCP’nin mimarisi, çekirdek LLM akıl yürütme alanı (**istemci**) ile aracın yürütme ortamı (**sunucu**) arasında **katı bir ayrım** uygular. [4] Bu ayrıştırma, mimari esneklik ve modülerlik sağlar: **müşteri/ajan kodunu değiştirmeden** yeni araçlar eklenebilir veya güncellenebilir; LLM’ler talep üzerine yeni sunuculara bağlanarak işlevselliklerini esnek biçimde genişletebilir. [2]

### İncelemenin Yapısı ve Kapsamı

Bu inceleme, **2024 sonrası** yayınlanan akademik çalışmalardan elde edilen bulguları sentezlemekte ve **yalnızca MCP’nin mimarisi, benimsenme dinamikleri, ampirik performansı** ve **güvenlik/yönetişim** zorluklarını ele alan kaynaklara odaklanmaktadır. Sonraki bölümlerde, mimari bileşenler ayrıntılandırılacak; uygulama otomasyonundaki atılımlar, uygulama alanları, performans bulguları ve **açık araştırma boşlukları** tartışılacaktır.

---

### Önemli Akademik Makaleler

Aşağıdaki özetler, MCP’nin geliştirilmesi, uygulanması ve **ampirik değerlendirmesine** odaklanarak, protokolün anlaşılmasını yönlendiren çekirdek literatürü temsil eder.

- **Özet 1:** Büyük Dil Modelleri (LLM’ler) pasif metin üreticilerinden **aktif ajanlara** evrilmektedir… **[Kaynak: 2]**
- **Özet 5:** **Araç çağırma**, AI ajanlarının gerçek dünyayla etkileşimi ve karmaşık sorunları çözmesi için kritik bir yetenektir… **[Kaynak: 6]**
- **Özet (Bulguların Özeti) 2:** MCP için gelecekteki araştırma yönleri; **standardizasyon**, **güven sınırları** ve **sürdürülebilir büyüme**yi güçlendirmeye odaklanır. Güvenlik, ölçeklenebilirlik ve yönetişim sorunları öne çıkar. Dağıtık **sunucu yönetimi**, merkezi bir uyumluluk otoritesinin yokluğunda **yama tutarsızlıkları** ve **yapılandırma sapmaları**na yol açabilir… **[Kaynak: 2]**
- **Özet 6:** LLM’lerin yetenekleri, çeşitli veri kaynakları veya API sonuçlarını entegre etmek için **işlev çağrıları** ile genişletilir… **[Kaynak: 6]**
- **Özet (Ekonomik Araştırma Uygulaması) 4:** Bu makale; planlama, araç kullanımı vb. işlevleri yerine getiren otonom **LLM tabanlı sistemleri (AI ajanlarını)** anlaşılır kılar… **[Kaynak: 4]**

---

### Tematik Özet

### Temel Tanım ve Mimari

#### Mimari Temeller: İstemci-Sunucu Modeli ve Protokol Tasarımı
MCP, temel bir **istemci–sunucu** mimarisi kurar:
- **MCP İstemcileri (ajan/uygulama):** Sunuculara bağlanır, **yetkinlikleri keşfeder**, çağırır ve sonuçları LLM bağlamına entegre eder. [4]
- **MCP Sunucuları:** Harici veri kaynaklarıyla **gerçek API etkileşimlerini yürütür**, kimlik doğrulama ve yürütmeyi yönetir. [4]

Protokol, **JSON-RPC 2.0** standardına dayanır; bu seçim **güçlü tipleme**, açık istek/yanıt yaşam döngüsü, **izin katmanları** ve istemci-sunucu **akış mekanizmaları** gibi güvenlik-öncelikli özellikleri kolaylaştırır. [3]

#### Temel Bileşenler ve Şema Bağımlılığı
MCP, LLM tarafından dinamik keşif ve çağırma için **harici araçların şema ile tanımlanmasına** dayanır. [1] Akademik literatür, bu şemalar için **OpenAPI 2.0/3.0** kullanılmasının etkili olduğunu doğrular. [1]

**LLM**, aracı doğru entegre etmek için **parametreler/girdiler/çıktılar**ın ayrıntılı tanımına ihtiyaç duyar; **MCP sunucusu** bu tanımları kaydeder ve LLM’nin **dosya sistemleri, web tarayıcıları, finansal veriler** gibi özelliklere erişmesini sağlar. [6]

**Tablo 3.1 – MCP Mimari Bileşenleri ve İşlevleri**

| Bileşen                     | Rolü                                                                 | Temel İşlev                                  | Standart/Protokol  | Anahtar Özellik/Kısıtlama                                                                 |
|----------------------------|----------------------------------------------------------------------|----------------------------------------------|--------------------|-------------------------------------------------------------------------------------------|
| **MCP İstemcisi (Ajan)**   | Araçları keşfeder/çağırır; çıktılarını LLM bağlamına entegre eder    | Planlama ve bağlam yönetimi                  | JSON-RPC 2.0       | Bağlam penceresi sınırlıdır; **araç numaralandırma** belirteç uzunluğunu yönetmelidir. [6] |
| **MCP Sunucusu**           | Dış yetenekleri ortaya çıkarır; yürütme ve kimlik doğrulamayı yönetir | Kaynak/araç barındırma                       | OpenAPI-türevi     | Yüksek kaliteli şema gerekir; başlangıçta **manuel iskele** darboğazları görülebilir. [1] |
| **Protokol Tasarımı**      | Standartlaştırılmış araç tanımı ve etkileşimi                         | Birlikte çalışabilir arayüz                   | JSON-RPC 2.0       | Modülerlik, izinler ve **ölçeklenebilir optimizasyon** (önbellek, toplu işleme). [3]      |

### Uygulama, Ölçeklenebilirlik ve Benimseme Dinamikleri

#### Manuel Sunucu Geliştirme Darboğazının Nicelendirilmesi
MCP’nin yayınından sonraki 6 ayda oluşturulan **22.000+ MCP etiketli repo**nun analizinde, **%5’ten azının** işlevsel sunucu uygulamaları içerdiği raporlanmıştır. [1] Birçok proje **tek bakımcı**, **elle şema/kimlik doğrulama** gibi tekrar eden çabalar içerir. [1]

#### Otomasyon: AutoMCP ve OpenAPI'nin Rolü
**AutoMCP derleyici**, OpenAPI sözleşmelerinden **tam MCP sunucuları** üretebilmektedir. 50 gerçek dünya API’sinde (10+ alan, 5.066 uç nokta) yapılan değerlendirmede:
- 1.023 araç çağrısından **%76,5**’i ilk denemede başarılı,
- Küçük düzeltmeler (API başına ~**19 satır** değişiklik) sonrası başarı **%99,9**’a yükselmiştir. [1]

#### Yeni Benimseme Engeli: Spesifikasyon Kalitesi
Otomasyonun başarısı, zorluğun artık **kod üretimi** değil, **OpenAPI sözleşme kalitesi** olduğunu gösterir. Kuruluşlar **API yönetişimine** ve **dokümantasyon doğruluğuna** öncelik vermelidir. [1]

### Uygulama Alanları ve Örnekler

#### Genel Ajan İş Akışları ve Ekosistem Büyümesi
Binlerce bağımsız MCP sunucusu; **GitHub, Slack** gibi hizmetlere erişim sağlar. **MCPToolBench++**, 4.000+ MCP sunucusundan oluşan pazarda veri analizi, dosya işlemleri, finansal hesaplama vb. geniş uygulama alanını doğrular. [6]

#### Özel Alan: Ekonomik ve Kurumsal Araştırma
MCP, ajanların **kurumsal veritabanlarına** (ör. merkez bankası/özel veri) bağlanıp **sürdürülebilir bağlantılar** kurmasını sağlar; literatür incelemeleri, ekonometrik kodlama ve **özel veri analizi** gibi **özerk araştırma iş akışları** mümkün olur. [4]

### Performans: Karşılaştırma ve Analiz

#### Son Teknoloji Benchmark'lar
- **LiveMCP-101:** 101 gerçek dünya sorgusu, çok-adımlı planlar ve koordinasyon gerektirir. [5]
- **MCPToolBench++:** Farklı yanıt biçimleri ve araç başarı oranı değişkenliğini adresler; çok alanlı çerçeve sunar. [6]

#### Bulgular: Araç Koordinasyon Eksikliği
En gelişmiş LLM’ler bile **karmaşık çok-adımlı** görevlerde **%60’ın altında** başarı göstermiştir. [5] MCP, erişimi standartlaştırsa da **güvenilir yürütme** için yeterli değildir; sınırlama **planlama/koordinasyon** yeteneklerindedir.

#### Arıza Modları ve Kaynak Kısıtları

**Tablo 3.2 – MCP Etkin Ajan Yürütmede Gözlemlenen Arıza Modları (LiveMCP-101)**

| Hata Kategorisi        | Örnek Arıza Modu                          | Açıklama                                                                                 | Kaynak |
|------------------------|--------------------------------------------|------------------------------------------------------------------------------------------|--------|
| Araç Koordinasyonu     | **Düşük Başarı**                           | Çok-adımlı eylemlerde başarısızlık; karmaşık koordinasyon gereksinimleri                | [5]    |
| Araç Koordinasyonu     | **Aşırı özgüvenli iç çözüm**               | Ajan, temelli MCP aracını atlayıp iç muhakemeye güvenir; halüsinasyon/erken bitiş       | [5]    |
| Araç Koordinasyonu     | **Gereksinimi göz ardı**                   | Açık gereksinim atlanır; ilgili araç seçilmez                                            | [5]    |
| Uygulama               | **Parametre hataları**                     | Girdi parametreleri yanlış biçimlenir/atlanır                                            | [5]    |
| Ölçeklenebilirlik/Bağlam| **Token verimsizlikleri/sınırları**        | Şema envanteri bağlam penceresini tüketir; planlama/akıl yürütme için alan daralır      | [5,6]  |

---

### Sonuç ve Araştırma Boşlukları

### Mevcut Durumun Özeti
MCP, **araç etkileşimini standartlaştırma** hedefini büyük ölçüde başarmış; **OpenAPI tabanlı** otomatik sunucu oluşturma ile geliştirici engellerini azaltmıştır. [1] Ekosistem büyümüş; ancak iki kritik alan açık kalmıştır:
1) **Ajans güvenilirliği** (çok-adımlı görevlerde düşük başarı),
2) **Ekosistem yönetişimi** (güvenlik/uyumluluk). [2]

### Çözülmemiş Zorluklar ve Gelecek Yönelimler

#### Güvenlik Açıkları ve Güven Sınırları
Dağıtık sunucu yönetimi, merkezi uyumluluk yokluğunda **heterojen uygulamalar** ve **yama tutarsızlıkları**na yol açar. **Zorunlu konfigürasyon doğrulaması**, **otomatik sürüm kontrolü** ve **bütünlük denetimi** gibi teknik yönetişim çözümleri öncelik olmalıdır. [2]

#### Ölçeklenebilirlik, Parçalanma ve Yönetişim
Bağlam penceresi kısıtı, **araç envanteri** ↔ **akıl yürütme derinliği** arasında ödünleşim yaratır. **Dinamik, bağlamsal araç keşfi** ve **şema sıkıştırma** araştırmaları önceliklidir. [6] Düşük güvenilirlik, yüksek riskli kurumsal alanlarda etik, güvenlik ve yasal sonuçları büyütür; **adalet**, **veri sızıntısı savunması** ve **hesap verebilirlik** odaklı yönetişim şarttır. [2,4]

### Kaynaklar
1. **Making REST APIs Agent-Ready: From OpenAPI to MCP** – arXiv (13 Eki 2025) → https://arxiv.org/abs/2507.16044
2. **Model Bağlam Protokolü (MCP): Manzara, Güvenlik Tehditleri…** – arXiv (13 Eki 2025) → https://arxiv.org/pdf/2503.23278
3. **Model Bağlam Protokolü (MCP) Nedir | Nasıl Çalışır** – Kodexo Labs (13 Eki 2025) → https://kodexolabs.com/what-is-model-context-protocol-mcp/
4. **AI Agents for Economic Research** – NBER Working Paper (13 Eki 2025) → https://www.nber.org/system/files/working_papers/w34202/w34202.pdf
5. **LiveMCP-101: Stress-Testing MCP-Enabled Systems** – arXiv (13 Eki 2025) → https://arxiv.org/abs/2508.15760
6. **MCPToolBench++: A Large-Scale AI Agent MCP Benchmark** – arXiv (13 Eki 2025) → https://arxiv.org/abs/2508.07575

## Ek D: Genişletilmiş Analiz
### Model Bağlam Protokolü (MCP): LLM Entegrasyonu, Ajans Sistemleri ve Araç Kullanımı Standardizasyonunda Rolünün Uzman Analizi

### Otonom Yapay Zekâ için Temel Katman Olarak MCP
LLM’lerin harici kaynaklar ve araçlarla **dinamik arayüz** oluşturması için standart, güvenilir bir yöntem eksikti. **MCP**, AI modelleri ile harici kaynak/araçlar arasında **birleşik, çift yönlü iletişim katmanı** tanımlayarak bu boşluğu doldurur. MCP, **parçalanmayı** azaltır ve **pasif işlev açıklamalarını** **aktif bağlam kaynaklarına** dönüştürür. 2025’teki yayın kümeleri, MCP’nin **acil bir endüstri tepkisi** olarak olgunlaştığını gösterir. [2]

### Mimari Gereklilik: Dağıtım Modelleri ve Gelişmiş Sistem Entegrasyonu

#### FaaS ile Barındırılan MCP Hizmetleri
**AgentX** çalışması, MCP sunucularının **FaaS** üzerinde barındırılmasının başarı, gecikme ve maliyet açısından avantajlarını gösterir; **patlama** tarzı kullanım profilleriyle doğal uyum sağlar. [9]

#### MoE Mimarilerinde MCP
**Uzman Karışımı (MoE)** senaryolarında MCP, **MITRE ATT&CK, MISP, CVE** gibi tehdit istihbaratı kaynaklarını bağlayarak **semantik bağlam farkındalığı** sağlar; endüstriyel ortamlarda uyarlanabilir karar vermeyi güçlendirir.

**Tablo 1 – Temel MCP Araştırmaları (2025 Kümesi): Zaman Çizelgesi ve Odak**

| Çalışma (Kısaltma)                                   | Yayın (Yaklaşık) | Birincil Tema            | Ana Mimari Kavramı                              |
|------------------------------------------------------|------------------|--------------------------|--------------------------------------------------|
| MCP – Manzara & Güvenlik (Hou ve ark.)               | 2025-03          | Tanım & Güvenlik         | Tam Sunucu Yaşam Döngüsü; Tehdit Sınıflandırması |
| MCPmed – Biyoinformatik Çağrısı                      | 2025-07          | Alan Uzmanlığı           | FAIR-uyumlu makine-okunur katman                 |
| Help or Hindrance? (MCPGAUGE)                        | 2025-08          | Ampirik Değerlendirme    | Proaktiflik/Genel Gider Analizi                  |
| AgentX – FaaS üzerinde MCP                            | 2025-09          | İş Akışı Düzenleme       | FaaS-barındırmalı MCP Hizmetleri                 |

### Yörünge: Proaktif Güvenlik Tasarımı ve Tehdit Sınıflandırması
MCP ile **çift yönlü iletişim**, yeni saldırı yüzeyleri getirir. Literatür, 4 saldırgan türü ve **16 tehdit senaryosu** ile kapsamlı bir **tehdit modeli** sunar ve yaşam döngüsü-özgü **uygulanabilir önlemler** önerir. [2]

### Yörünge: Performans Doğrulama ve Araç Kullanımının Engeli
**MCPGAUGE**, 160 prompt/25 veri seti/≈20k API çağrısı ile 6 ticari LLM ve 30 MCP araç paketinde 4 boyutta ölçüm yapar: **Proaktiflik, Uyum, Etkinlik, Genel Gider**. Bulgular, MCP’nin mimari yararlarının **otomatik performans artışı** garantilemediğini; **uyum/proaktiflik** düşüklüğü ve **ek yük** sorunlarının kritik olduğunu gösterir. (LLM eğitimi ve ince ayarlarının MCP-uyumlu optimizasyonu önerilir.)

**Tablo 2 – MCP Entegrasyonu: Avantajlar, Riskler ve Performans Boyutları**

| Kategori     | Gözlemlenen Fayda                                           | Risk/Sınırlama                                  | İlgili Boyut     |
|--------------|--------------------------------------------------------------|--------------------------------------------------|------------------|
| Mimari       | Birleşik/dinamik araç keşfi; FaaS ölçeklenebilirliği; MoE    | Tam yaşam döngüsü yönetimi (16 faaliyet)         | **Etkinlik**     |
| İşlevsel     | Anlamsal bağlam; dinamik veri yorumlama; özerklik            | Uyum eksikliği; düşük proaktiflik                | **Proaktiflik/ Uyumluluk** |
| Operasyonel  | Tekrarlanabilirlik; müdahalesiz varlık yönetimi               | Hesaplama maliyeti ve gecikme                    | **Genel Gider**  |
| Güvenlik     | Dış tehdit istihbaratı entegrasyonu                           | 16 tehdit senaryosuna maruziyet                  | —                |

### Yörünge: Gelişmiş Ajan İş Akışı Düzenleme
**AgentX** modeli (sahne tasarımcısı, planlayıcı, yürütücü) ile **FaaS-barındırmalı MCP** araçları; pratik uygulamalarda **başarı, gecikme, maliyet** açısından avantaj sağlar. **GenAI + MCP + Applied ML** birlikteliği, sağlık/finans/robotik gibi alanlarda **bağlam duyarlı otonomi** için temel sunar. [6,9]

### Yörünge: Alanlar Arası Uzmanlaşma ve Standardizasyon

#### MCPmed: Biyomedikal Araştırmada FAIR İlkeleri
GEO, STRING, UCSC Cell Browser gibi **insan-merkezli** web sunucularının **LLM-okunabilirliğini** MCP ile artırma çağrısı; **yapılandırılmış, makine-işlenebilir katman** ile otomasyon/tekrarlanabilirlik/birlikte çalışabilirlik kazancı. [7]

#### Kritik Altyapı Varlık Keşfi
ICS’de **deterministik araçların** sınırlamalarına karşı; MoE + MCP ile **tehdit istihbaratı** (MITRE ATT&CK, MISP, CVE) entegrasyonu ve **bağlam zenginleştirme** üzerinden uyarlanabilir keşif ve güvenlik duruşu güçlendirme. [11]

**Tablo 3 – Alan Spesifik Zorluklarda MCP’nin Rolü**

| Etki Alanı              | MCP Öncesi Sınırlama                                   | MCP Çözümü/Çerçevesi                               | Temel MCP İşlevi                              |
|-------------------------|---------------------------------------------------------|-----------------------------------------------------|-----------------------------------------------|
| Biyoinformatik/Araştırma| LLM-okunabilirliğini sınırlayan insan-merkezli sunucular| **MCPmed**; hafif “breadcrumb” ve şablonlar         | FAIR uyumlu **makine-işlenebilir erişim** [7] |
| Kritik Altyapı (ICS)    | Bağlamsal muhakemeden yoksun deterministik araçlar     | MoE + MCP ile tehdit istihbaratı entegrasyonu       | **Bağlam enjeksiyonu** (MISP/CVE bağlama)     |

### Google Scholar Özet Koleksiyonu (Markdown)

- **Model Bağlam Protokolü (MCP): Genel Durum, Güvenlik Tehditleri ve Gelecek Yönelimler** — *Hou ve ark.*
  **Özet:** MCP, birleşik, çift yönlü… **[Kaynak: 2]**

- **AgentX: FaaS-Barındırılan MCP Hizmetleri ile Sağlam Ajan İş Akışları** — *Tokal ve ark.*
  **Özet:** GenAI çeşitli alanları dönüştürmüştür… **[Kaynak: 9]**

- **Help or Hindrance? Rethinking LLMs Empowered with MCP** — *Song ve ark.*
  **Özet:** MCP, LLM’lerin erişimini sağlar… **[Kaynak: 10]**

- **MCPmed: LLM-Odaklı Keşif için MCP-Destekli Biyoinformatik Web Hizmetleri Çağrısı** — *Flotho ve ark.*
  **Özet:** Biyoinformatik web sunucuları… **[Kaynak: 7]**

- **Integrating GenAI & MCP with Applied ML for Advanced Agentic AI Systems** — *Bhandarwar*
  **Özet:** GenAI, MCP ve Uygulamalı ML… **[Kaynak: 12]**

### Sentez ve Gelecekteki Standardizasyon Zorlukları

MCP, birinci nesil ajan sistemlerinin **ölçeklenebilirlik** ve **bağlam yönetimi** sınırlarını aşmak için gerekli mimari olgunluğu sağlar; **otomasyon** (AutoMCP), **FaaS dağıtımı** (AgentX) ve **alan-özgü adaptasyonlar** (MCPmed) bunu destekler.
Kalıcı iki zorunluluk:
- **Güvenlik Riski Yönetimi:** 16 tehdit senaryosu ve 4 saldırgan türü; yaşam döngüsü-özgü önlemler, **politika yönetimi** ve **denetim izleri** şart. [2]
- **Verimlilik ve Model Uyumluluğu:** MCPGAUGE, **uyum/proaktiflik** ve **ek yük** sorunlarına işaret eder; **MCP-uyumlu eğitim** ve **etkileşim maliyeti azaltımı** önceliklidir. [10]

**Sürdürülebilir Büyüme:** MCPmed ve ICS örnekleri, protokolün **uyarlanabilirliğini** gösterir. Gelecek çalışmalar, **standardizasyonun güçlendirilmesi**, **güven sınırlarının iyileştirilmesi** ve **LLM performansının MCP’ye optimize edilmesi**ne odaklanmalıdır.

### Ek Kaynaklar

7. **MCPmed: A Call for MCP-Enabled Bioinformatics Web Services** – arXiv → https://arxiv.org/abs/2507.08055
8. **MCPmed (HTML sürüm)** – arXiv → https://arxiv.org/html/2507.08055v1
9. **AgentX: Toward Robust Agent Workflow with FaaS-Hosted MCP Services** – arXiv → https://arxiv.org/abs/2509.07595
10. **Help or Hindrance? Rethinking LLMs Empowered with MCP** – arXiv → https://arxiv.org/abs/2508.12566
11. **Asset Discovery in Critical Infrastructures: An LLM-Based Approach** – MDPI → https://www.mdpi.com/2079-9292/14/16/3267
12. **Integrating Generative AI & MCP with Applied ML…** – ResearchGate → (PDF bağlantısı kullanıcı paylaşımlı)

> **Not:** Bazı bağlantılar üçüncü taraf barındırıcılar üzerinde olabilir ve erişim kısıtları/URL değişimleri içerebilir.


---
## Ek C: Güncel Olaylar

### MCP'de Araç Zehirleme Saldırıları (Tool Poisoning Attacks)
MCP sunucularında araç tanımlarına gizli zararlı talimatlar enjekte edilerek AI asistanlarının manipüle edilmesi, SSH anahtarları ve API anahtarları gibi hassas verilerin sızdırılmasına yol açan kritik bir tehdit. Saldırılar, kullanıcı onayı altında gizli eylemler gerçekleştirerek veri dışa aktarımı veya yetkisiz erişim sağlıyor. Geniş çapta tartışılan bu saldırı türü, MCP'nin tedarik zinciri risklerini vurguluyor.

İlgili X postları:
- https://x.com/Graham_dePenros/status/1976216281033408741
- https://x.com/lbeurerkellner/status/1907075048118059101
- https://x.com/akshay_pachaar/status/1947246782221816087
- https://x.com/akshay_pachaar/status/1946926773918429249
- https://x.com/Graham_dePenros/status/1976252021645959302
- https://x.com/OpenCodeMission/status/1976251957108248856
- https://x.com/OpenCodeMission/status/1976245247685316721
- https://x.com/theagentangle/status/1976018568413405335

### MCP Üst 25 Zafiyet Raporu (Top 25 Vulnerabilities Report)
MCP'de tespit edilen 25 kritik zafiyetin 18'i kolay sömürülebilir olarak sınıflandırılıyor; prompt enjeksiyonu, komut enjeksiyonu ve eksik kimlik doğrulaması gibi temel güvenlik hataları, web geliştirme standartlarının gerisinde kalıyor. Rapor, AI ajanlarının veritabanı ve dosya sistemi erişimlerinde input doğrulama eksikliğini vurgulayarak üretim ortamlarında acil güvenlik disiplini gerekliliğini belirtiyor.

İlgili X postları:
- https://x.com/rryssf_/status/1970524674439422444
- https://x.com/kakarot_ai/status/1975599529681690820
- https://x.com/lbeurerkellner/status/1907075048118059101 (bağlantılı tartışma)

### Açıkta Kalan MCP Sunucuları (Exposed MCP Servers)
Trend Micro tarafından tespit edilen 492 açık MCP sunucusu, kimlik doğrulaması veya şifreleme olmadan çevrimiçi erişime maruz; %90'ı doğal dil sorguları ile hassas verilere (bulut kaynakları, müşteri bilgileri) doğrudan okuma erişimi sağlıyor. KQL sorguları ile bu sunucuların avlanması öneriliyor, ciddi veri sızıntısı riski taşıyor.

İlgili X postları:
- https://x.com/0x534c/status/1956999290863370481

### Figma MCP Sunucusu Uzak Kod Yürütme Zafiyeti (Figma MCP RCE Vulnerability)
Figma'nın MCP sunucusunda (CVE-2025-53967) tespit edilen kritik zafiyet, zararlı API istekleri yoluyla uzak kod yürütmeye izin veriyor; AI prompt enjeksiyonu ve DNS rebinding ile sömürülebilir. v0.6.3 sürümüne güncelleme zorunlu, aksi halde sistemsel uzlaşma mümkün.

İlgili X postları:
- https://x.com/freedomhack101/status/1976288100243607552
- https://x.com/shah_sheikh/status/1975889172872286316
- https://x.com/TweetThreatNews/status/1975997613221572728

### Sahte npm Paketi Arka Kapı Olayı (Fake npm Package Backdoor - postmark-mcp)
postmark-mcp adlı sahte npm paketi, her e-postayı gizlice BCC ile saldırgana yönlendirerek 1.600 indirmeden sonra kaldırıldı; faturalar ve şifre sıfırlamaları gibi verileri sızdırdı. MCP tedarik zinciri saldırılarını yansıtıyor, imzalı kayıtlar ve sandbox izinleri öneriliyor.

İlgili X postları:
- https://x.com/TheHackersNews/status/1972581724992528746
- https://x.com/theagentangle/status/1976018568413405335
- https://x.com/iamKierraD/status/1975226041309299085

### MCP Güvenlik Kontrol Listesi (MCP Security Checklist)
SlowMist tarafından yayınlanan MCP güvenlik rehberi, ana bilgisayar, istemci ve sunucu katmanlarında riskleri kapsıyor; çoklu MCP ve kripto para entegrasyonlarında özel tehditler vurgulanıyor. AI ve blockchain ekosistemlerinin güvenli entegrasyonu için temel önlemler sunuyor.

İlgili X postları:
- https://x.com/SlowMist_Team/status/1911678320531607903

### MCP Yığınlarında %92 Sömürü Olasılığı (92% Exploit Probability in MCP Stacks)
MCP eklenti yığınlarında %92 sömürü olasılığı, kurumsal güvenlik kör noktalarını artırıyor; CVEs analizi ve savunma stratejileri, erişim sıkılaştırması ve zayıf noktaları tespit etmeyi öneriyor. Eklenti zincirleri büyük ölçekli sömürülere yol açabiliyor.

İlgili X postları:
- https://x.com/jfrog/status/1976719975881617553
- https://x.com/LouisColumbus/status/1976393986156941725

### MCP Tehditlerinin Sistematik Çalışması (Systematic Study of MCP Threats)
MCP yaşam döngüsünde 16 tehdit senaryosu tanımlayan çalışma, kötü niyetli geliştiriciler, kullanıcılar ve dış saldırganları kapsıyor; gerçek dünya vakalarıyla desteklenen faz bazlı güvenlik önlemleri öneriliyor. Interoperabilite için güvenli benimseme yol haritası sunuyor.

İlgili X postları:
- https://x.com/jiqizhixin/status/1976109107804270655
- https://x.com/vlruso/status/1977603410690977952 (bağlantılı tartışma)

### MCP Prompt Enjeksiyonu ve Ajan Güvenliği (MCP Prompt Injection and Agent Security)
MCP'de prompt enjeksiyonu, güvenilmeyen girdilere maruz kalan araçlardan kaynaklanıyor; özellikle yerel ajanlarda (Cursor, Claude Code) risk yüksek. Bağlayıcılar ve bellek özellikleriyle birleşince veri sızıntısı artıyor, araçları sandbox'lama öneriliyor.

İlgili X postları:
- https://x.com/simonw/status/1909955640107430226
- https://x.com/karpathy/status/1934657940155441477
- https://x.com/Rajan_Medhekar/status/1977601624110768573
- https://x.com/liran_tal/status/1976362229294387584
- https://x.com/UndercodeUpdate/status/1977524734230229026

### MCP Sunucularında Kötüye Kullanım ve Kripto Entegrasyonu Tehditleri (MCP Plugin Abuse and Crypto Integration Risks)
MCP eklenti kötüye kullanımı ve kripto entegrasyonları, yeni güvenlik riskleri getiriyor; A2A (ajan-ajan) etkileşimlerinde çoğaltıcı tehdit yüzeyi oluşuyor. AI odaklı savunmalar ve sıfır güven mimarisi zorunlu.

İlgili X postları:
- https://x.com/DarkScorpionAI/status/1977435023147163737
- https://x.com/vietjovi/status/1977369607015956574
- https://x.com/eddy_crypt409/status/1915771464764076441


- **Güvenlik Endişeleri Tartışmaları Domine Ediyor**: Araştırmalar, MCP'nin araç zehirleme saldırılarına karşı savunmasız olduğunu gösteriyor. Bu saldırılarda, kötü niyetli sunucular araç açıklamalarına zararlı komutlar yerleştirerek veri sızdırılmasına veya yetkisiz eylemlere yol açabiliyor. Kanıtlar, yüksek istismar olasılıklarına işaret ediyor. Raporlar, eklenti yığınlarında %92'ye varan risk olduğunu gösteriyor, ancak tarayıcılar ve kontrol listeleri gibi savunma araçları ortaya çıkmaya başlıyor.
- **Son Zamanlarda Ortaya Çıkan Güvenlik Açıkları ve Sömürüler**: Prompt enjeksiyonu ve eksik kimlik doğrulama gibi kritik kusurların, sahte npm paketlerinin e-postalara arka kapı açması gibi gerçek senaryolarda sömürüldüğü muhtemel görünüyor. Topluluk analizleri, eski web güvenlik uygulamalarıyla paralellikler kurarak, bu kusurların kolayca sömürülebilir olduğunu vurguluyor.
- **Yamalar, Düzeltmeler ve Güncellemeler**: Gelişmeler, yeni spesifikasyonlar (örneğin, yetkilendirmeyi geliştiren 2025-06-18 sürümü) ve zehirleme veya rug pull'ları tespit eden MCP tarayıcıları gibi güvenlik araçları dahil olmak üzere, devam eden iyileştirmelere işaret etmektedir. Claude, Cursor ve ChatGPT gibi platformlarla entegrasyonlar, işlevselliği genişletirken riskleri azaltmayı amaçlamaktadır.
- **Güncel Gelişmeler ve Entegrasyonlar**: Protokol, Spring AI, MuleSoft ve blok zinciri platformları (ör. Rootstock, Cardano) gibi ekosistemlerde desteklenerek AI ajanları için yaygın olarak benimsenmektedir. Bu, birlikte çalışabilirliği teşvik etmekte ancak açık sunucular ve kimlik doğrulama boşlukları konusunda endişeleri artırmaktadır.
- **Topluluk ve Resmi Tartışmalar**: Tartışmalar, araştırmacıların ve şirketlerin faydalar ve riskler konusunda dengeli görüşleri vurgulayan analizleriyle, heyecan ve ihtiyatın karışımı bir havayı yansıtmaktadır. Resmi duyurular, AI araç bağlantıları için standardizasyona odaklanırken, tartışmalar AI tabanlı ekonomilerin potansiyelini kabul etmekle birlikte, test edilmemiş uygulamalar konusunda uyarıda bulunmaktadır.
### MCP'ye Genel Bakış
Model Context Protocol (MCP), AI modelleri ve harici araçlar arasında çift yönlü iletişim için açık bir standart görevi görür ve parçalanmış AI ekosistemlerini birleştirir. Claude Desktop ve Cursor gibi uygulamalarda uygulanır ve sorunsuz entegrasyonlar sağlar, ancak eklenti kötüye kullanımı gibi yeni riskler getirir. Son zamanlarda yayınlanan yazılar, ajanların veri kaynaklarına zahmetsizce bağlandığı ajans AI'daki rolünü vurgulamaktadır, ancak bu durum güvenlik kör noktalarını artırmaktadır.
### Önemli Güvenlik Açıkları
Araç zehirlenmesi kritik bir sorun olarak öne çıkmaktadır: Kötü niyetli MCP sunucuları, kullanıcı onaylarını atlayarak ve zararsız görünüm altında zararlı eylemler gerçekleştirerek gizli komutlar enjekte edebilir. Diğer açıklar arasında, açıkta kalan sunucular (çevrimiçi olarak 492 tane bulunmuştur), komut enjeksiyonu ve bozuk kimlik doğrulama yer almaktadır ve bunlar genellikle “kolay” olarak değerlendirilmektedir. Sahte npm paketinin e-postaları çalması gibi gerçek hayattaki olaylar, bu konunun aciliyetini vurgulamaktadır.
### Savunmadaki Gelişmeler
Tehditlere karşı koyma çabaları arasında, ana bilgisayar, istemci ve sunucu katmanlarını kapsayan güvenlik kontrol listeleri ve saldırıları tespit etmek için özel tarayıcılar bulunmaktadır. Yamalar, Figma'nın MCP sunucusunda uzaktan kod yürütülmesine izin veren gibi belirli güvenlik açıklarını giderir. Vulnerablemcp[.]info gibi topluluk kaynakları, saldırıları anlamaya ve önlemeye yardımcı olmak için saldırı özetleri sunar.

### Ekosistem Büyümesi

MCP, blok zincirinden (ör. DeMCP_AI pazarı) geliştirici araçlarına (ör. tarayıcı kontrolü için Chrome DevTools) kadar çeşitli platformlarla entegre olmaktadır. Güncellemeler, güvenli ölçeklendirme için daha iyi yetkilendirme gibi kurumsal özellikleri geliştirir. Ancak tartışmalar, mevcut API'lerle uyumsuzluk ve uzaktan kurulumlarda kimlik doğrulama zorlukları gibi sınırlamaları vurgulamaktadır.


Model Context Protocol (MCP), AI alanında önemli bir açık standart olarak ortaya çıkmış ve büyük dil modelleri (LLM'ler) ile harici araçlar veya veri kaynakları arasında kesintisiz çift yönlü iletişimi kolaylaştırmıştır. AI ekosistemlerindeki parçalanmayı gidermek için tasarlanan MCP, tak ve çalıştır entegrasyonlarını mümkün kılarak AI ajanlarının gerçek zamanlı verilere erişmesine, eylemleri gerçekleştirmesine ve özel kodlama olmadan çeşitli sistemlerle etkileşime girmesine olanak tanır. Genellikle AI için TCP/IP'ye benzetilen bu protokol, masaüstü ortamlarındaki uygulamaları (ör. Claude Desktop, Cursor), blok zinciri pazarlarını ve kurumsal yığınları destekleyerek geliştirme karmaşıklığını azaltır ve modüler AI iş akışlarının önünü açar. Ancak, hızlı benimsenmesi önemli güvenlik sorunlarını gündeme getirmiştir. Geçtiğimiz yıl yapılan tartışmalar, umut verici düzeltmeler, güncellemeler ve topluluk odaklı analizlerin yanı sıra, erken web geliştirme tuzaklarını anımsatan güvenlik açıklarını ortaya çıkarmıştır.
### Evrim ve Teknik Temeller
MCP'nin temel mimarisi üç katman etrafında döner: model (işlemlerin ve verilerin standart temsilleri), bağlam (ağ parametreleri gibi çevresel ayrıntılar) ve protokol (eylemleri oluşturma ve gönderme mantığı). Bu modülerlik, OpenAI, Anthropic ve Google gibi sağlayıcıların LLM'leri arasında birlikte çalışabilirliği destekler. 2025-06-18 güncellemesi gibi son spesifikasyonlar, kurumsal kullanım için geliştirilmiş yetkilendirme, elde etme mekanizmaları ve kaynak bağlantıları gibi iyileştirmeler getirerek güvenli, ölçeklenebilir AI sistemleri oluşturmayı kolaylaştırmıştır. Teknik tartışmalar, MCP'nin yerel bir masaüstü protokolü (kamu trafiği için SSE ile stdio üzerinde çalışan) olarak ortaya çıkışını vurgulamaktadır. Bu, kimlik doğrulama engellerini (başlıklar veya çerezler için yerel destek eksikliği) ve bunları gidermek için AI API ağ geçitlerinin yükselişini açıklamaktadır. Entegrasyonlar, blok zincirine (ör. zincir üzerinde geliştirme için Rootstock MCP Sunucusu, işlem oluşturma için Cardano) ve geliştirme araçlarına (ör. tarayıcı hata ayıklama için Chrome DevTools, AI'nın DOM'u incelemesine, UI testleri çalıştırmasına ve ekran görüntüleri ile düzeltmeleri doğrulamasına olanak tanır) kadar uzanmaktadır. Kurumsal bağlamlarda, Spring AI ve MuleSoft MCP gibi çerçeveler HTTP, zamanlama ve hata toleransı için bildirimsel API'leri desteklerken, Amazon Bedrock AgentCore dakikalar içinde üretime hazır AI ajanları sağlar.

### Güvenlik Açıkları ve Güvenlik Kusurları

Güvenlik tartışmaları MCP ile ilgili içeriği domine ederken, araç zehirlenmesi kritik bir tehdit olarak ortaya çıkmaktadır. Bu saldırılarda, kötü niyetli sunucular araç açıklamalarına zararlı talimatlar yerleştirir ve AI asistanları bunları komut istemlerine dahil eder, böylece kullanıcılar görünüşte zararsız talepleri onaylarken veri sızıntıları (ör. SSH anahtarları, API anahtarları) gibi yetkisiz eylemler gerçekleşir. Sistematik bir çalışma, kötü niyetli geliştiriciler, kullanıcılar veya dış saldırganların dahil olduğu, oluşturulmasından bakımına kadar MCP yaşam döngüsü boyunca 16 tehdit senaryosu belirlemiştir. Açığa çıkan sunucular başka bir risk oluşturmaktadır: Trend Micro, kimlik doğrulama veya şifreleme olmadan 492 çevrimiçi örnek bildirmiştir. Bu örnekler, doğal dil sorguları yoluyla bulut kaynakları gibi hassas verilere doğrudan okuma erişimi sağlamaktadır. Komut istemine enjeksiyon, komut enjeksiyonu ve eksik kimlik doğrulama — 25 en önemli güvenlik açığından 18'inde “kolay” olarak değerlendirilen kusurlar — yıllar önce web geliştirmede çözülen sorunları yansıtmaktadır, ancak cömert izinlere sahip AI ajanlarında hala devam etmektedir. Gerçek dünyadaki istismarlar arasında, saldırganlara e-postaları gizli kopya olarak gönderen ve kaldırılmadan önce 1.600 kez indirilen sahte bir npm paketi (“postmark-mcp”) ve uzaktan kod yürütmeyi mümkün kılan bir Figma MCP kusuru bulunmaktadır. Analizler, eklenti yığınlarında %92 istismar olasılığı olduğu konusunda uyarıda bulunarak, küçük zayıflıkları büyük ölçekli ihlallere dönüştürmektedir. Hızlı enjeksiyon, MCP'ye özgü değildir, ancak araçların güvenilmeyen girdilere maruz kalmasından kaynaklanır ve ajanlar arası (A2A) etkileşimlerde riskleri artırır.
| Güvenlik Açığı Türü     | Açıklama                                                   | Sömürü Kolaylığı | Etki                          | Tartışmalardan Örnekler                                               |
|-------------------------|-------------------------------------------------------------|------------------|-------------------------------|------------------------------------------------------------------------|
| Araç Zehirlenmesi       | Araç açıklamalarında gizlenmiş kötü amaçlı talimatlar       | Kolay            | Veri sızdırma, yetkisiz eylemler | MCP sunucuları üzerinden düşmanca saldırılar; SSH/API anahtarlarının sızdırılması |
| Açığa Çıkmış Sunucular  | Kimlik doğrulaması yapılmamış çevrimiçi örnekler            | Önemsiz          | Hassas verilere arka kapı     | 492 sunucu bulundu; %90'ı doğal dil erişimine izin veriyor            |
| Komut/Emir Enjeksiyonu  | Giriş doğrulamasını atlama                                  | Kolay            | Sistem güvenliğinin ihlali    | İlk 25 rapor: 18/25 istismar edilebilir; yamalanmamış PHP ile paralellikler |
| Eksik Kimlik Doğrulama  | Başlık/çerez desteği yok                                    | Orta             | Yetkisiz erişim               | Uzaktan kurulumlar savunmasız; rug pull/çapraz kaynak sorunlarına yol açar |
| Eklenti Kötüye Kullanımı| Yığınlarda tehlikeye atılmış eklentiler                    | Yüksek (%92 olasılık) | Kurumsal çapta istismarlar | E-postaları çalan sahte npm paketleri; Figma uzaktan kod yürütme      |

### Yamalar, Düzeltmeler ve Azaltma Stratejileri
Tehditlere karşı alınan önlemler arasında Figma'nın güvenlik açığı düzeltmesi gibi belirli kusurlar için yamalar ve SlowMist gibi firmaların çoklu MCP ve kripto para senaryolarını kapsayan kapsamlı kontrol listeleri bulunmaktadır. Güvenlik tarayıcıları, Claude ve Cursor gibi araçları destekleyerek araç zehirlenmesi, rug pull (hash yoluyla) ve çapraz kaynak ihlallerini tespit eder. Vulnerablemcp[.]info gibi kaynaklar, daha iyi savunma için saldırı vektörlerini ayrıntılı olarak açıklar. En iyi uygulamalar, kötü amaçlı yazılım gibi sunucuları incelemeyi, kapsamları sınırlandırmayı, güvenilir sağlayıcıları kullanmayı ve güncellemelerden sonra MCP'leri yeniden onaylamayı vurgular. KQL sorguları, Microsoft Sentinel gibi ortamlarda maruz kalan sunucuları bulmaya yardımcı olur. Daha geniş savunma önlemleri arasında AI destekli güvenlik önlemleri, aşama özel korumalar ve sohbetlerdeki UI öğeleri için MCP-UI gibi standartlar bulunur.
### Güncel Gelişmeler ve Entegrasyonlar
MCP'nin büyümesi, ChatGPT Geliştirici Modu, VS Code (GitHub MCP kayıt defteri ile v1.105) ve n8n iş akışları için TypingMind gibi platformlarda tam desteği içerir. DeMCP_AI'nin AI hesaplama için Web3 pazarı ve TaironAI'nin Oracle Katmanı gibi blok zinciri entegrasyonları, zincir üzerinde güvenlik ve modüler araçlar için MCP'yi kullanır. Otto MCP ve Briq'in Otonom İş Gücü Platformu gibi kurumsal araçlar, MCP'yi AI için “açık an” olarak konumlandırarak ajanların özerkliğini sağlar. Helidon 4.3.0 ve Hugging Face MCP Sunucusu gibi açık kaynak çabaları, yönetim API paritesi ve UI desteği gibi özellikler ekler. Katalizör önerileri, MCP aracılığıyla Cardano işlemlerini AI ile desteklemeyi amaçlamaktadır.
### Topluluk Tartışmaları ve Analizleri
Analizler dengeli görüşleri vurgulamaktadır: MCP verimliliği artırır (örneğin, ajanlarda %97,3 araç çağırma güvenilirliği) ancak “pahalı dersler”den kaçınmak için disiplin gerektirir. Reddit ve Zenn.dev gibi platformlarda yapılan tartışmalar Japon bağlamındaki riskleri ele alırken, makaleler yükselen güvenlik manzaralarını incelemektedir. Topluluk, Jenova.ai'nin MCP'ye özel ajanı ve içerik yönetimi için Umbraco CMS MCP Beta gibi yeniliklere dikkat çekiyor. Tartışmalar arasında MCP'nin OpenAPI şemalarıyla uyumsuzluğu ve Story Protocol gibi entegrasyonlar yoluyla AI'nın sahip olduğu IP potansiyeli yer alıyor.
### Resmi Duyurular ve Gelecekteki Yönelimler
Anthropic, OpenAI ve Google gibi kuruluşların duyuruları, MCP'nin AI arama alıntıları ve geliştirme araçlarındaki rolünü vurgulamaktadır. Devoxx gibi etkinliklerde MCP Java SDK ile ilgili uygulamalı oturumlar düzenlenmektedir. Gelecekteki beklentiler, AI API ağ geçitleri, ajanlar arası iletişim ve MCP-UI gibi standartların kullanılabilirliği artırırken eksiklikleri gidermesini öngörmektedir. Genel olarak, MCP'nin gidişatı yenilikçilik ile güvenlik gereklilikleri arasında bir denge kurarak, onu AI'nın bir sonraki aşaması için vazgeçilmez bir unsur haline getirmektedir.
**Önemli Alıntılar:**
- [Graham_dePenros, Araç Zehirleme Saldırıları hakkında](https://x.com/Graham_dePenros/status/1976216281033408741)
- [lbeurerkellner, Kritik Kusur Keşfi](https://x.com/lbeurerkellner/status/1907075048118059101)
- [jfrog, Sömürü Olasılığı hakkında](https://x.com/jfrog/status/1976719975881617553)
- [SlowMist_Team, Güvenlik Kontrol Listesi hakkında](https://x.com/SlowMist_Team/status/1911678320531607903)
- [rryssf_ En Önemli 25 Güvenlik Açığı](https://x.com/rryssf_/status/1970524674439422444)
- [LouisColumbus, Eklenti Riskleri hakkında](https://x.com/LouisColumbus/status/1976393986156941725)
- [rez0__, Güvenlik Açığı Kaynağı hakkında](https://x.com/rez0__/status/1922381770588053669)
- [liran_tal, Güvenlik Ortamı hakkında](https://x.com/liran_tal/status/1976362229294387584)
- [jiqizhixin, Sistematik Çalışma Güncellemesi](https://x.com/jiqizhixin/status/1976109107804270655)
- [0x534c, Açığa Çıkmış Sunucular hakkında](https://x.com/0x534c/status/1956999290863370481)
- [simonw, Hızlı Enjeksiyon Sorunları hakkında](https://x.com/simonw/status/1909955640107430226)
- [Chikor_Zi, Şema Sınırlamaları hakkında](https://x.com/Chikor_Zi/status/1939362725630562592)
- [TheHackersNews, Arka Kapı Olayı hakkında](https://x.com/TheHackersNews/status/1972581724992528746)
- [dsp_, Yeni Spesifikasyon hakkında](https://x.com/dsp_/status/1935740870680363328)
- [kakarot_ai, Korkunç Güvenlik Açıkları hakkında](https://x.com/kakarot_ai/status/1975599529681690820)
- [lbeurerkellner, Güvenlik Tarayıcısı hakkında](https://x.com/lbeurerkellner/status/1910379084758343827)
- [MCP_Community, Ürün Özeti hakkında](https://x.com/MCP_Community/status/1951369789685084254)
- [nutrientdocs, MCP Sunucularının Tedavisi hakkında](https://x.com/nutrientdocs/status/1976707785548030101)
- [GoogleCloudTech, Gemini CLI Entegrasyonu hakkında](https://x.com/GoogleCloudTech/status/1973493121250902040)
- [rootstock_io, Rootstock MCP Sunucusu hakkında](https://x.com/rootstock_io/status/1975656743799902686)
- [nowitnesslabs, Catalyst Önerisi hakkında](https://x.com/nowitnesslabs/status/1972563255479459990)
- [BriqHQ, OTTO MCP Duyurusu hakkında](https://x.com/BriqHQ/status/1972723699016183888)
- [evalstate, HF MCP Sunucusu hakkında](https://x.com/evalstate/status/1975188323124519293)
- [100xDarren, TAIRO Güncellemesi hakkında](https://x.com/100xDarren/status/1973515775593029886)
- [KrekhovetsRZ, Story Protocol Entegrasyonu hakkında](https://x.com/KrekhovetsRZ/status/1975278135961702515)
- [helidon_project, Helidon 4.3.0 Sürümü hakkında](https://x.com/helidon_project/status/1973727994742239401)
- [ChromiumDev, DevTools MCP hakkında](https://x.com/ChromiumDev/status/1976422660880875687)
- [christzolov, Devoxx Talk hakkında](https://x.com/christzolov/status/1976209066423947619)
- [Bedrock AgentCore'da awsdevelopers](https://x.com/awsdevelopers/status/1974900254349603273)
- [lilyraynyc, AI Search Citations hakkında](https://x.com/lilyraynyc/status/1973044734206628353)
- [HexawareGlobal, MuleSoft Desteği hakkında](https://x.com/HexawareGlobal/status/1975546653667963028)
- [umbraco, CMS MCP Beta hakkında](https://x.com/umbraco/status/1975463678733414582)
- [VS Code Sürümünde code](https://x.com/code/status/1976332459886182627)
- [n8n Entegrasyonunda TypingMindApp](https://x.com/TypingMindApp/status/1973767427872772513)

### AI Ajanları Güvenlik Protokolleri

Araştırmalar, AI ajanlarının (otonom görevleri yerine getiren AI sistemleri) güvenlik risklerinin yüksek olduğunu gösteriyor; prompt enjeksiyonu, veri sızıntısı ve kötüye kullanım gibi tehditler yaygın. Ancak, katmanlı savunmalar ve en iyi uygulamalarla bu riskler yönetilebilir.

- **Temel Riskler**: AI ajanları, LLM'lerin (büyük dil modelleri) açıklıklarından etkilenerek veri zehirlenmesi, jailbreak ve araç zehirlenmesi gibi saldırılara maruz kalır; bu, gizlilik ve bütünlük ihlallerine yol açabilir.
- **Ana Savunmalar**: En az yetki ilkesi, giriş/çıkış doğrulaması ve sandboxing gibi geleneksel yöntemler, AI'ye özgü guard modelleri ve davranış sertifikaları ile birleştirilerek etkili koruma sağlar.
- **Potansiyel Tartışmalar**: Bazı uzmanlar, AI ajanlarının tam özerkliğinin riskleri artırdığını savunurken, diğerleri katı protokollerle dengelenebileceğini belirtiyor; ancak, standartlaşma eksikliği genel bir endişe kaynağı.

#### Giriş Doğrulaması ve Sandboxing
Girişlerin sıkı doğrulanması (örneğin, JSON formatı ve regex filtreleri) ve ajanların izole ortamlarda (sandbox) çalıştırılması, prompt enjeksiyonu gibi saldırıları önler. Bu, ajanların yalnızca gerekli kaynaklara erişmesini sağlar.

#### Şifreleme ve İzleme
Tüm verilerin uçtan uca şifrelenmesi (TLS 1.3, AES-256) ve davranış izlemesi (OpenTelemetry gibi araçlarla), anormallikleri erken tespit eder. Rate limiting, DoS saldırılarını sınırlayarak ajanların kullanılabilirliğini korur.

#### Protokol Spesifik Yaklaşımlar
A2AS gibi çerçeveler, davranış sertifikaları ve bağlam bütünlüğü ile ajan-ajan iletişimini güvence altına alır. MCP (Model Context Protocol) için araç zehirlenmesi tarayıcıları önerilir.

---

AI ajanları, büyük dil modelleri (LLM'ler) üzerine kurulu otonom sistemler olarak, çeşitli güvenlik tehditleriyle karşı karşıya kalır. Bu tehditler, geleneksel yazılım güvenlik sorunlarından farklı olarak, ajanların karar alma ve eylem yürütme yeteneklerinden kaynaklanır. Araştırmalar, ajanların gizlilik, bütünlük ve kullanılabilirlik açısından risk taşıdığını vurgular; örneğin, prompt enjeksiyonu yoluyla zararlı eylemler tetiklenebilir veya veri sızıntıları meydana gelebilir. Bu kapsamlı inceleme, son bir yıldaki web ve X (eski Twitter) kaynaklarından derlenen bilgileri temel alır, tehdit modellerini, saldırı vektörlerini ve savunma stratejilerini detaylandırır. Geleneksel ve AI'ye özgü yöntemler bir araya getirilerek katmanlı bir yaklaşım önerilir.

#### Tehdit Modelleri ve Saldırı Vektörleri
AI ajanlarının tehdit modeli, metin tabanlı giriş/çıkışa dayanır; güvenli bir sunucuda barındırılırken, kullanıcı erişimi API ile sınırlıdır. Ancak, LLM'lerin ürettiği eylemler, sistem açıklıklarını istismar edebilir. Ana vektörler şöyle:

1. **Oturum Yönetimi Açıkları**: Çok kullanıcılı ajanlarda oturum izolasyonu eksikliği, bilgi sızıntısına (gizlilik ihlali) veya yanlış eylem atamasına (bütünlük ihlali) yol açar. Kaynak yoğun sorgularla DoS saldırıları mümkün olur.
2. **Model Kirlenmesi ve Gizlilik Sızıntıları**: Kullanıcı sohbet geçmişleriyle ince ayarlanmış modeller, veri zehirlenmesine açıktır. Hassas veriler (SSN, hesap numaraları) LLM'lerde saklanarak çıkarılabilir; örnek olarak Samsung'un ChatGPT yasağı verilebilir.
3. **Ajan Programı Açıkları**:
   - **Sıfır Atış Eylemleri**: Halüsinasyonlar veya jailbreak'ler, istenmeyen komutlar üretir; araç belgelerine gömülü prompt'lar veri sızıntısına neden olur.
   - **Bilişsel Planlama**: ReAct veya Tree-of-Thoughts gibi yöntemler, her adımda yan etkiler yaratır; kaynak tüketimiyle kullanılabilirlik etkilenir.
   Deneyler (BashAgent ile 95 güvenlik görevi), kısıtsız ortamlarda %96 gizlilik, %85.7 bütünlük ve %62.9 kullanılabilirlik saldırılarının başarılı olduğunu gösterir.

X tartışmalarında, araç zehirlenmesi (tool poisoning) ve plan enjeksiyonu gibi yeni saldırılar öne çıkar; örneğin, ajan hafızasına gizli talimatlar eklenerek kalıcı zarar verilebilir.

Türkçe kaynaklarda, MCP (Model Context Protocol) gibi protokollerde araç zehirlenmesi ve ajan-ajan (A2A) iletişim riskleri vurgulanır; kötü niyetli sunucular, gizli talimatlarla veri dışa aktarımı sağlar.

#### Savunma Stratejileri
Savunmalar, bileşen düzeyinde odaklanır; izolasyon, şifreleme ve resmi modelleme ile uygulanır.

1. **Oturum Yönetimi**: Benzersiz oturum kimlikleri ve KVDB ile tarihçeyi izole edin; durum dönüştürücü monadlar (state transformer monads) ile doğrulanabilir hesaplamalar sağlayın.
2. **Model Koruması**:
   - **Oturumsuz Modeller**: Özel verileri filtreleyin; FPETS (Format-Preserving Encryption for Text Slicing) ile şifreleme, başarı oranlarını %38-89 korur. FHE (Fully Homomorphic Encryption) hesaplamalara izin verir.
   - **Oturum Farkındalığı**: Prompt tuning ile kullanıcıya özgü parametreler ekleyin, temel LLM'yi dondurun.
3. **Sandboxing**: Kaynak sınırlamaları ve Docker gibi izole ortamlar; kısıtlı BashAgent, tüm saldırıları engeller. Beyaz/siyah listeler ve rate limiting, uzak erişimi korur.

Jit.io'nun 7 ipucu:
- Giriş doğrulama ve çıkış sanitizasyonu (Rebuff gibi araçlarla).
- Yetki kısıtlaması ve izolasyon (en az yetki ilkesi).
- Kod ve bağımlılık taraması (Semgrep, Jit ajanları).
- Uçtan uca şifreleme (TLS 1.3, AES-256).
- Davranış izleme ve rate limiting (OpenTelemetry).
- Just-in-Time güvenlik (dinamik erişim).
- Gerçek zamanlı yanıt ve kurtarma (SIEM entegrasyonu).

Google Cloud'un katmanlı yaklaşımı: Kimlik doğrulama, yetkilendirme, denetlenebilirlik ve güvenli geliştirme ile geleneksel; guard modelleri ve advers訓練 ile AI'ye özgü.

A2AS Çerçevesi: BASIC modeli (Behavior Certificates, Authenticated Prompts, Security Boundaries, In-Context Defenses, Codified Policies) ile ajan güvenliğini sağlar; bağlam penceresinde çalışır, prompt enjeksiyonunu önler.

OWASP Tabanlı Kontrol Listesi: 15 kategoride 163 öğe; AI yönetişimi, güvenli tasarım, prompt güvenliği, ajan aracı güvenliği gibi alanlar kapsar.

### En İyi Uygulamalar ve Çerçeveler
- **Guard Modelleri**: Yüksek etkili eylemleri denetler.
- **Advers Eğitim**: Simüle saldırılarla dayanıklılık artırılır.
- **SLSA Çerçevesi**: Yazılım tedarik zinciri güvenliği için SBOM ile kullanılır.
- **A2A Protokolü**: Ajanlar arası iletişimde sandboxing ve giriş sanitizasyonu.
- **MCP Güvenliği**: Araç zehirlenmesi tarayıcıları ve checklist'ler.

Türkçe bağlamda, IBM Güvenlik Doğrulama AI Ajanı gibi entegrasyonlar, otomasyon ve zeki karar alma için vurgulanır; yapay zeka siber güvenlik teknolojilerini şekillendirirken, log toplama ve regex gibi protokoller entegre edilir.

### Risk ve Savunma Tablosu

| Tehdit Türü | Açıklama | Savunma Stratejisi | Kaynak |
|-------------|----------|---------------------|--------|
| Prompt Enjeksiyonu | Zararlı girişlerle ajan manipülasyonu | Giriş sanitizasyonu, guard modelleri | , , [post:28] |
| Veri Zehirlenmesi | Eğitim verilerine müdahale | Veri bütünlüğü doğrulaması, diferansiyel gizlilik | ,  |
| Araç Zehirlenmesi | Araç tanımlarında gizli talimatlar | Tarayıcılar ve beyaz listeler | [post:18],  |
| DoS Saldırıları | Kaynak tüketimi | Rate limiting, kaynak sınırlamaları | ,  |
| Gizlilik Sızıntıları | Hassas veri ifşası | Şifreleme (FPETS, FHE) | ,  |
| Ajan-Ajan Enfeksiyonu | Çok ajanlı sistemlerde bulaşma | A2AS gibi protokoller | , [post:22] |

### Gelecek Yönelimler
AI ajan güvenliği, standartlaşma (A2AS gibi) ve blockchain entegrasyonuyla evrilir; örneğin, Theoriq protokolü katkı kanıtı ve ceza mekanizmalarıyla güven sağlar. Çok ajanlı sistemlerde (multi-agent AI), dağıtılmış yapı güvenlik artırır. Ancak, token kullanım yükü ve model sapmaları gibi sınırlamalar devam eder.

Bu inceleme, AI ajanlarının dengeli kullanımını teşvik eder; riskler yönetilebilir olsa da, sürekli izleme ve güncelleme şarttır.

**Ana Kaynaklar:**
- [Security of AI Agents - arXiv](https://arxiv.org/pdf/2406.08689.pdf)
- [7 Proven Tips to Secure AI Agents - Jit.io](https://www.jit.io/resources/devsecops/7-proven-tips-to-secure-ai-agents-from-cyber-attacks)
- [AI Agent Security - Google Cloud](https://cloud.google.com/transform/ai-agent-security-how-to-protect-digital-sidekicks-and-your-business)
- [A2AS Framework PDF](https://hmdhiqqomsdmtwjq.public.blob.vercel-storage.com/a2as-framework-1.0.pdf)
- [AI Security Checklist - OWASP](https://shivang0.github.io/index.html)
- [AI Agent Security: MCP Security - Medium](https://alican-kiraz1.medium.com/ai-agent-security-mcp-security-0516cb41e800)
- [SynthaMan on A2AS Framework](https://x.com/SNXified/status/1975304303398035528)
- [AISecHub on Agentic AI Runtime Security](https://x.com/AISecHub/status/1975932208985637126)
- [Vercel on Prompt Injection](https://x.com/vercel/status/1932115736841068681)
- [Het Mehta on AI Security Checklist](https://x.com/hetmehtaa/status/1953901455523635208)

---


