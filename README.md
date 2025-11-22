# MCP-Agentic-Security-Review

https://yusufarbc.github.io/MCP-Agentic-Security-Review/

Bu repo, Model Context Protocol (MCP) ekosisteminin mimari ve güvenlik boyutlarını inceleyen akademik çalışmayı, kullanılan görsel/video materyallerini ve literatür referanslarını bir araya getirir.

- `paper/` — IEEE formatında LaTeX makale taslağı ve derlenmiş PDF.
- `media/` — Makale ve sunumlarda kullanılan infografikler ve video.
- `reference/` — MCP ve ajan sistemleri üzerine derlenmiş akademik makaleler.

## Hızlı Bakış

- **Odak:** MCP’nin mimarisi, tehdit modeli, agentic güvenlik yönetişimi ve ekosistem literatürü.
- **Çıktı:** IEEE konferans formatında akademik makale (`paper/paper.pdf`).
- **Veri kaynağı:** 2024–2025 arası MCP odaklı  akademik yayınlar ve endüstriyel raporlar (`reference/` klasörü).

## Makale (paper/)

`paper/` dizini, IEEEtran şablonunu kullanan ana raporu içerir:

- `paper.tex` — LaTeX kaynak dosyası (Türkçe ve İngilizce özet, mimari, tehdit modeli, savunma çerçeveleri vb.).
- `paper.pdf` — Derlenmiş sürüm.
- `protocol.png` — Makalede kullanılan MCP istemci–sunucu mimarisi şeması.

Derleme (MiKTeX / TeX Live):

```bash
cd paper
pdflatex paper.tex
bibtex   paper   
pdflatex paper.tex
pdflatex paper.tex
```

## Medya (media/)

`media/` dizini, makale ve sunumlarda yeniden kullanılabilecek görsel ve video dosyalarını içerir:

![MCP Ekosistemi ve Tehdit Modeli](media/infografik.png)

![MCP Mimarisi / Ekosistemi](media/MCP.png)

- `infografik.png` — MCP ekosistemi ve tehdit taksonomisini özetleyen infografik.
- `MCP.png` — MCP mimarisi / ekosistemi görseli.
- `Yapay_Zeka_Ajanlari.mp4` — “Yapay Zeka Ajanları için MCP” video demosunun yerel kopyası.
- YouTube: [Yapay Zeka Ajanları için MCP](https://www.youtube.com/watch?v=MgGM5rkxL0c)



## Referanslar (reference/)

`reference/` dizini, MCP ekosistemiyle ilgili temel akademik çalışmaları PDF formatında içerir. Dosya adları, makale başlığı ve kısa konusunu yansıtacak biçimde numaralandırılmıştır. Örnekler:

- `01 - Model Context Protocol (MCP) - Landscape, Security Threats, and Future Research Directions.pdf`
- `04 - Model Context Protocol (MCP) at First Glance - Studying the Security and Maintainability of MCP Servers.pdf`
- `08 - MCP-Guard - A Defense Framework for Model Context Protocol Integrity in Large Language Model Applications.pdf`

Bu dosyalar, hem makale yazımı sırasında hem de gelecekteki sunum / rapor çalışmalarında doğrudan kaynak olarak kullanılabilir.


