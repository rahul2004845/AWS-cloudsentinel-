# 🛡️ CloudSentinel: Real-Time Cloud Security & Threat Detection

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python) 
![FastAPI](https://img.shields.io/badge/FastAPI-0.100%2B-009688?style=for-the-badge&logo=fastapi)
![React](https://img.shields.io/badge/React-18.2-61DAFB?style=for-the-badge&logo=react)
![MongoDB](https://img.shields.io/badge/MongoDB-Cloud_Native-47A248?style=for-the-badge&logo=mongodb)
![Scikit-Learn](https://img.shields.io/badge/Machine_Learning-Scikit_Learn-F7931E?style=for-the-badge&logo=scikit-learn)

> **Notice to the Admissions Committee:** 
> *This code has been published and pushed to GitHub explicitly for university admission and evaluation purposes. It serves as both my final year engineering project and the foundation for an academic research paper, demonstrating proficiency in cloud security paradigms, applied machine learning, and systems architecture.*

---

## 📖 Project Abstract
**CloudSentinel** is an end-to-end telemetry ingestion and threat detection framework designed to monitor cloud environments (such as AWS CloudTrail logs) in real time. By continuously parsing log sequences, the system correlates behavioral metrics using both deterministic security heuristics and an unsupervised state-of-the-art **Isolation Forest** machine learning model. This hybrid approach significantly reduces false positives while actively detecting **Brute Force Attacks, Data Exfiltration, and Anomalous Access Patterns**.

## 🚀 Key Features

* **Real-Time Telemetry Ingestion (FastAPI):** High-performance asynchronous APIs capable of handling high-throughput log streams. 
* **Hybrid Automated Threat Detection Engine:**
  * *Rule-Based Heuristics:* Deterministic detection for known attack vectors (e.g., threshold-based failure spikes).
  * *Unsupervised Machine Learning:* **Scikit-learn Isolation Forests** for contextual anomaly detection, establishing baseline behaviors, and identifying nuanced deviations.
* **Intelligent Threat Simulation:** Included `simulator.py` generates stochastic cloud traffic interspersed with highly realistic multi-vector attack scenarios.
* **Persistent Event Storage:** Leverages MongoDB as a NoSQL datastore to handle flexible log schemas and long-term historical analysis.
* **Dynamic Intelligence Dashboard:** Built on React and Vite, utilizing Glassmorphism design principles to render an interactive, real-time threat analysis UI with automated PDF incidence reporting.

## 🧠 System Architecture

1. **Log Simulation / Extraction:** Simulates or fetches IAM/EC2/S3 event payloads natively mapped to AWS CloudTrail schemas.
2. **Detection Core:** 
    - The *Ingestion Node* parses incoming JSON streams and securely stores them. 
    - The *Analytic Node* simultaneously evaluates the streams against rolling state windows and ML baselines.
3. **Alerting Pipeline:** Automatically triggers severity-based protocols (Critical/High/Medium/Low), simulating SES/SMTP email dispatch on critical infrastructure breaches.
4. **Command Center:** The visual interface queries the FastAPI backend periodically, rendering interactive graphs constructed with Chart.js.

## 🛠️ Technology Stack Rationale
- **Python / FastAPI:** Chosen for its asynchronous speed and native Pydantic validation mapping which strictly guarantees log schema integrity.
- **Scikit-Learn:** Employs the `IsolationForest` ML algorithm, specifically utilized because security anomalies are typically "few and different", which Isolation Forests natively isolate better than standard clustering techniques.
- **MongoDB:** Real-world cloud telemetry (like CloudTrail) is often semi-structured nested JSON. A NoSQL data layer was strictly required to absorb diverse event log schemas seamlessly.
- **React + TailWindCSS/Vite:** Ensures optimal frontend performance and a modular component design resulting in an exceptionally responsive analytic dashboard.

---

## 💻 Local Sandbox Deployment

*To successfully run the localized simulation sandbox, 3 sequential services must be started in three separate terminal instances.*

### 1. The Inference Core (Backend)
```bash
# Initialize Virtual Environment
python3 -m venv venv
source venv/bin/activate

# Install Dependencies
pip install fastapi uvicorn scikit-learn faker pydantic pymongo

# Launch Asynchronous Engine
cd backend
uvicorn app:app --reload --port 8000
```
*(Confirms engine initialization and trains the baseline ML model.)*

### 2. The Adversary Network (Simulator)
```bash
# In a new terminal window
source venv/bin/activate
cd backend
python simulator.py
```
*(Initiates background noise logs while synchronously injecting Brute-Force and Exfiltration events into the Inference pipeline.)*

### 3. The Security Operations Center (Frontend)
```bash
# In a final terminal window
cd frontend
npm install
npm run dev
```
*(Launch the dashboard at the provided `localhost` link to observe the ML Engine actively mitigating the simulated attacks in real time.)*

---

## 🔮 Future Upgrades
The architecture is designed to be fully decoupled and cloud-native. Future iterations allow for:
* **Direct AWS Integration:** Retiring the simulator core and subscribing the ingestion endpoint directly to an **AWS EventBridge** rule that captures real CloudTrail events.
* **Containerization:** Complete Dockerization of the application stack utilizing `docker-compose`.

---
*Created meticulously to bridge the gap between Cloud Infrastructure and Data Science.*
# Cloud-Security-Monitoring-System
