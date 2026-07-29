import streamlit as st
from fastapi.testclient import TestClient

# Import your FastAPI app instance
try:
    from app import app
except ImportError:
    from main import app

client = TestClient(app)

st.set_page_config(page_title="LLM Shield Guardrail", page_icon="🛡️", layout="centered")

st.title("🛡️ LLM Shield Security Guardrail")
st.write("Test your prompt injection defenses and security guardrail microservice in real time.")

prompt_text = st.text_area("Enter Prompt to Scan", placeholder="Type a prompt to test for injections...")

if st.button("Scan Prompt", type="primary"):
    if prompt_text.strip():
        with st.spinner("Analyzing prompt safety..."):
            response = client.post("/v1/guardrail/scan", json={"prompt": prompt_text})
            
        if response.status_code == 200:
            st.success("Scan Complete")
            st.json(response.json())
        else:
            st.error(f"Error {response.status_code}: {response.text}")
    else:
      st.warning("Please enter a prompt first.")
