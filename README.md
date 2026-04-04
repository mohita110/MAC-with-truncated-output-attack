# MAC with Truncated Output Attack

## 🎯 Project Overview

This project demonstrates the **Birthday Attack vulnerability** on truncated Message Authentication Codes (MACs) and shows how using full-length MACs provides effective prevention. The system implements different MAC algorithms and visualizes the dramatic security improvement when moving from truncated (32-bit) to full-length (128-bit) MAC tags.

### 📊 Key Demonstration Results

| Phase | MAC Type | Attack Success Rate | Security Status |
|-------|----------|---------------------|-----------------|
| **Before Prevention** | Truncated (32-bit) | **90-100%** | 🔴 VULNERABLE |
| **After Prevention** | Full (128-bit) | **<5%** | 🟢 SECURE |

---

## 🔬 Security Concepts Demonstrated

1. **Birthday Paradox Attack**  
   For an n-bit MAC, only ~2^(n/2) attempts are needed for a 50% success probability.

2. **Truncation Vulnerability**  
   Reducing MAC length drastically weakens security exponentially.

3. **Birthday Bound**  
   With 32-bit truncation, collisions become highly probable in a short time.

4. **Full MAC Security**  
   A 128-bit MAC provides ~2^64 security, making attacks practically infeasible.

---

## 📋 Prerequisites

### System Requirements
- **Python 3.7+** (3.8+ recommended)
- **Operating System**: Windows / Linux / macOS
- **RAM**: Minimum 4GB (8GB recommended)
- **Disk Space**: 500MB free
- **Network**: Localhost (no internet required after setup)

### Required Python Packages
- cryptography >= 41.0.7
- matplotlib >= 3.7.2
- numpy >= 1.24.3

---

## 🚀 Installation Guide

### Step 1: Install Python

#### Windows
1. Download Python from: https://www.python.org/downloads/
2. Run installer
3. ✅ Check **"Add Python to PATH"**
4. Click **Install Now**

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install python3 python3-pip python3-tk
```

---

### Step 2: Install Required Packages

```bash
pip install cryptography matplotlib numpy
```

---

### Step 3: Clone or Download the Project

```bash
git clone <your-repo-link>
cd <project-folder>
```

---

## ▶️ Execution Process

### Step 1: Start the Server

Run the server script:

```bash
python server.py
```

Expected output:
```
Server started on port XXXX
Waiting for client connection...
```

---

### Step 2: Run the Client

Open a **new terminal** and execute:

```bash
python client.py
```

---

### Step 3: Attack Simulation

The client will:

- Connect to the server
- Send multiple messages
- Attempt to find MAC collisions
- Display attack statistics

---

## 🔁 Execution Phases

### 🔴 Phase 1: Truncated MAC (32-bit)

- High collision probability
- Fast attack success
- Output shows:
  - Number of attempts
  - Collision found
  - Success rate (~90–100%)

---

### 🟢 Phase 2: Full-Length MAC (128-bit)

- Very low collision probability
- Strong security
- Output shows:
  - No or very rare collisions
  - Success rate <5%

---

## 📊 Visualization

If enabled, matplotlib will display:

- Attack success comparison
- Attempts vs collision probability
- Security difference between MAC lengths

---

## 🛑 Stopping the Program

Press:

```
CTRL + C
```

in the terminal to stop server/client.

---

## ⚠️ Troubleshooting

### ❌ Port Already in Use
- Change port number in `server.py`

### ❌ Module Not Found
```bash
pip install -r requirements.txt
```

### ❌ Client Not Connecting
- Ensure server is running first
- Verify host and port match

---

## 📁 Project Structure

```
project/
│── server.py
│── client.py
│── utils.py
│── requirements.txt
│── README.md
```

---

## ✅ Summary

- Demonstrates weakness of **truncated MACs**
- Shows **birthday attack feasibility**
- Validates **full-length MAC security**
- Provides **real-time attack simulation**

---

## 🧠 Learning Outcome

This project clearly illustrates:

- Why truncating cryptographic outputs is dangerous
- How collision probability grows exponentially
- Importance of using **full-length secure MACs** in real systems

---

## 📌 Future Enhancements

- Add GUI dashboard
- Support more MAC algorithms
- Real-time attack visualization
- Network-based remote attack simulation
