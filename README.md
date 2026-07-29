# LLM Security Guardrail & Shield Project

An enterprise-grade, multi-layered security microservice and interactive web application designed to detect, intercept, and mitigate vulnerabilities mapped to the **OWASP Top 10 for LLM Applications** and semantic jailbreak vectors.

🌐 **Live Demo:** [View Live Streamlit App](https://your-app-name.streamlit.app)

---

## 🛡️ Architecture & Features

* **Multi-Layered Detection Engine (`main.py`):** Combines ultra-fast regex heuristics with advanced semantic vector distance matching.
* **OWASP Coverage:** Targets critical attack vectors including Prompt Injection (`LLM01`), Sensitive Data Disclosure (`LLM02`), and Excessive Agency / Jailbreaks (`LLM06`).
* **Semantic Similarity Matching:** Powered by `sentence-transformers` (`all-MiniLM-L6-v2`) to capture sophisticated, obfuscated prompt bypasses using cosine similarity thresholds.
* **FastAPI Backend:** Provides robust programmatic microservice endpoints (`/v1/guardrail/scan`) for payload analysis.
* **Interactive Frontend:** Built with Streamlit for real-time security auditing and instant guardrail testing.

---

## 📂 Repository Structure

```text
llm-security-guardrail-project/
├── main.py               # Core FastAPI backend & LLM security engine
├── streamlit_app.py      # Streamlit web interface integration
├── requirements.txt      # Project dependency list
├── documents/            # Technical documentation and assets
└── notebook/             # Jupyter experimentation notebooks
    └── llm-security-guardrail.ipynb

## 🚀 Getting Started Locally

### 1. Clone the Repository
git clone [https://github.com/Thrivi17/llm-security-guardrail-project.git](https://github.com/Thrivi17/llm-security-guardrail-project.git)
cd llm-security-guardrail-project

### 2. Install Dependencies
pip install -r requirements.txt

### 3. Run the Streamlit Application
streamlit run streamlit_app.py
