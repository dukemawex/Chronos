# Chronos: Autonomous AI Threat Hunting SDK

### 🚨 The Problem Statement
Modern Security Operations Centers (SOCs) are drowning in logs. Standard rule-based detection systems (SIEMs) excel at catching known patterns but fail to identify **"Low and Slow"** Advanced Persistent Threats (APTs) that mimic legitimate user behavior over extended periods. Manual correlation of logs across multiple days is computationally expensive for humans and leads to "Alert Fatigue."

### 🎯 The Solution: Chronos-SDK
Chronos is a defensive AI package designed to flip the attacker's advantage. It leverages **Long-Context LLMs** (via OpenRouter/Gemini 2.0) to autonomously perform temporal log correlation, identity-aware anomaly detection, and forensic reporting.

### 🛠️ Key Features
* **Autonomous Correlation:** Links discrete events (e.g., a VPN login at 2 AM and an S3 bucket access at 4 AM) into a single "Threat Story."
* **Persona Baseling:** Learns the standard command-line and API velocity of users to detect identity-based deviations.
* **Zero-Config Integration:** A "Plug-and-Play" SDK for Python and Node.js environments.
* **Forensic Output:** Generates structured JSON and Markdown reports compatible with MITRE ATT&CK frameworks.

### 🏗️ Architecture
- **Brain:** DeepSeek-R1 / Gemini-2.0-Flash (via OpenRouter)
- **Runtime:** Vercel Edge Functions / Python 3.11+
- **Input:** AWS CloudTrail, Linux Auth, Nginx, and Custom Application Logs.

