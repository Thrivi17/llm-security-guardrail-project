# LLM Security Guardrail & Shield Microservice Technical Documentation

### 1. System Overview
The LLM Security Guardrail & Shield Project is a dual-tier security microservice with an optional web UI. The primary purpose of the project is to intercept and filter malicious LLM prompts before they are dispatched to downstream LLMs (such as ChatGPT, LLaMA, Claude, etc.). It provides preventative defense mechanisms against prompt injection, data exfiltration, and jailbreaks via a FastAPI backend and an intuitive interactive tool through the Streamlit frontend.

---

### 2. Core Security Engine (main.py)
Our defensive architecture utilizes a hybrid method combining deterministic rule-based techniques with probabilistic similarity. The following defenses are implemented:

* **Regex Heuristic Analysis:** Involves comparing submitted LLM prompts with regex patterns specifically crafted to detect violations across the Top 10 vulnerabilities documented by OWASP:
  * **LLM01: Prompt Injection:** Pattern matching against common prompt injection terms (e.g., commands for reinterpreting instructions, adopting developer personas, etc.).
  * **LLM02: Sensitive Data Disclosure:** Patterns matching common expressions indicating exposure of sensitive string information including API keys, bearer tokens, passwords, and credentials.
  * **LLM06: Excessive Agency / Jailbreaks:** Pattern matching to mitigate common techniques used to exploit prompt manipulation for executable code generation by LLMs.
* **Semantic Vector Distance Matching:** Employs the `sentence-transformers` architecture to generate sentence embeddings from user prompts using the `all-MiniLM-L6-v2` model. This generated vector is then compared with pre-configured anchor strings of known malicious prompts to evaluate if the submitted prompt aligns semantically with known jailbreak variations.

---

### 3. API Specification & Interceptor
Our service exposes an extensive API layer through FastAPI enabling integration into existing systems via the following interface:

* **Endpoint:** `POST /v1/guardrail/scan`
* **Request Schema:**
  ```json
  {
    "prompt": "A string value that will be analyzed for potential vulnerabilities"
  }
