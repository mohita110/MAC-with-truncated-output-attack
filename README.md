# MAC-with-truncated-output-attack

## 🎯 Project Overview

This project demonstrates the **Birthday Attack vulnerability** on truncated Message Authentication Codes (MACs) and shows how using full-length MACs provides effective prevention. The system implements three different MAC algorithms and visualizes the dramatic security improvement when moving from truncated (32-bit) to full-length (128-bit) MAC tags.

### 📊 Key Demonstration

- **Before Prevention (Truncated MAC)**: Attack success rate **90-100%** - System is VULNERABLE
- **After Prevention (Full MAC)**: Attack success rate **<5%** - System is SECURE

### 🔬 Security Concepts Demonstrated

1. **Birthday Paradox Attack**: For n-bit MAC, only ~2^(n/2) attempts needed for 50% success probability
2. **Truncation Vulnerability**: Reducing MAC length exponentially decreases security
3. **Birthday Bound**: With 32-bit truncation, collisions become highly probable
4. **Full MAC Security**: 128-bit MAC provides 2^64 security level (practically impossible to break)

---

## 📋 Prerequisites

### System Requirements
- **Python 3.7+** (3.8+ recommended)
- **Operating System**: Windows, Linux, or macOS
- **Network**: Localhost connection (no internet required)

### Required Python Packages

```bash
pip install cryptography==41.0.7
pip install matplotlib==3.7.2
pip install numpy==1.24.3
