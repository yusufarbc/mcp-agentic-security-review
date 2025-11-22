# MCP-Agentic-Security-Review

![MCP architecture and measurements](media/MCP.png)

This repository collects an IEEE-style paper, media kit, 18-paper reference library, and a landing page (`index.html`)
to document the architecture, threat landscape, and defenses of the Model Context Protocol (MCP) ecosystem.

## What is MCP and why this study exists?

Model Context Protocol is the "universal adaptor" layer that lets LLM-based agents talk to tools, APIs, data stores, and
devices through a single schema. Our study focuses on:

- **Threat taxonomy** – 4 actors, 16 scenarios (tool poisoning, prompt injection, sandbox escape, etc.).
- **Benchmark evidence** – MCPGAUGE, MCPToolBench++, MCP-Universe, LiveMCP-101, AutoMalTool findings (e.g. 7.2% general
  exposure, 5.5% tool poisoning risk, 66% code smell rate on 1,899 servers).
- **Defense stack** – IFC + taint tracking, OAuth/mTLS, guard models, FPETS/FHE, plan-based stress tests, OpenAPI → AutoMCP.
- **Ecosystem radar** – Community discussions, enterprise rollouts, future-ready tooling ideas.

### Deep-dive snapshot from the paper

- **Architecture boundaries:** the MCP host/client orchestrates discovery and routes LLM plans to JSON-RPC servers; each
  server exposes tools/resources while transport (STDIO vs HTTPS/SSE) and identity controls (OAuth, mTLS, scoped tokens)
  define how much of the external surface becomes reachable.
- **Four actor classes:** malicious developers (shadow servers, namespace collisions), external attackers (indirect prompt
  injection, setup fraud), malicious users (STAC chains, sandbox escape, session reuse), and software/config errors
  (credential leaks, command injection, weak TLS/OAuth baselines).
- **Empirical findings:** scanning 1,899 open MCP servers revealed 7.2% general exposure, 5.5% tool poisoning risk,
  66% code smell prevalence, and 14.4% recurring bug patterns—underscoring the need for MCP-specific scanners beyond
  generic static analysis.
- **Benchmark lessons:** MCPGAUGE shows integration isn’t universally positive; MCP-Universe/LiveMCP-101 demonstrate
  <60% success on real servers due to long-context and unknown tool behaviors; MCPToolBench++ highlights format diversity
  bottlenecks; AutoMalTool can bypass defenses while MCP-Guard’s multi-layered detection reaches 96% accuracy.
- **Mitigation priorities:** IFC + taint tracking, sandbox profiles, TLS/mTLS + OAuth 2.1 resource indicators, scoped
  short-lived tokens, plan-based testing + anomaly logging, red-team drills, signed packages, SBOMs, and schema integrity
  validation. Recommended ops steps include CI/CD MCP scanners, guard-model+human approvals for high-impact actions, and
  OpenAPI-driven automatic server generation to reduce manual errors.

## Repository map

| Path           | Summary                                                                                                       |
| -------------- | ------------------------------------------------------------------------------------------------------------- |
| `index.html`   | New landing page; outlines repo structure, security panorama, media gallery, and living roadmap.             |
| `paper/`       | IEEEtran LaTeX sources (`paper.tex`), compiled PDF, log files, and the `protocol.png` figure.                 |
| `media/`       | Infographics, architecture posters, threat diagrams, notebook renders, and the demo video.                   |
| `reference/`   | 18 numbered PDFs covering MCP architecture, benchmark suites, AutoMalTool, MCP-Guard, Bioinformatics MCP…    |
| root files     | `.editorconfig`, `.gitattributes`, `.gitignore`, and this README for documentation continuity.                |

## Media showcase (`media/`)

`media/README.md` describes each asset plus the YouTube embed for the demo. Highlights:

![Agent protocol challenges vs solutions](media/infografik.png)
![How to build MCP servers in Python](media/model.png)
![MCP host, protocol layer, and threat vectors](media/post.jpeg)
![LLM, MCP client, and multi-server tool flow](media/diagram.png)
![MCP as standardized protocol between apps and tools](media/protocol.png)

- `Yapay_Zeka_Ajanlari.mp4` – Local demo (YouTube mirror: https://www.youtube.com/watch?v=MgGM5rkxL0c).
- `index.html` renders each asset as a card so presentations and reports can link directly to the raw files.

## Reference library (`reference/`)

- PDFs `01`–`18` cover topics from MCP-Guard and AutoMalTool to MCPmed, AgentX, A2AS, and AI Agents for Economic Research.
- `reference/Readme.md` provides bilingual abstracts; when adding a paper, number it (`19 - ...`) and append a short note.

## Building the paper (`paper/`)

```bash
cd paper
pdflatex paper.tex
bibtex paper
pdflatex paper.tex
pdflatex paper.tex
```

`paper.log` helps with troubleshooting and `protocol.png` is the architecture figure referenced inside the manuscript.

## How to work with this repo

1. Open `index.html` to understand the overall story (structure, security themes, roadmap).
2. Run the LaTeX build steps above whenever the paper changes; keep `paper.tex`, `paper.bib`, and figures in sync.
3. Update `media/README.md` plus the landing page gallery when new visuals or videos are added.
4. Extend the reference library by dropping PDFs into `reference/` and citing them inside the paper and README.
5. Capture new threat data (e.g., LiveMCP-101 reruns) under `paper/` or a dedicated `reports/` folder for reproducibility.

## Roadmap ideas

- Publish OAuth/mTLS reference configs for MCP servers under `docs/`.
- Version control AutoMalTool and MCP-Guard experiments, including prompts and logs.
- Add new diagrams explaining A2AS, BASIC model, and guard-model pipelines to `media/`.
- Generate SBOM/metadata for `reference/` via a small script and keep it evergreen.

This README plus `index.html` form the high-level documentation for MCP-Agentic-Security-Review; keep them updated as the
research evolves.
