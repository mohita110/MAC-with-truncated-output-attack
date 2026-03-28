# MAC-with-truncated-output-attack

## 🎯 Project Overview

This project demonstrates the **Birthday Attack vulnerability** on truncated Message Authentication Codes (MACs) and shows how using full-length MACs provides effective prevention. The system implements three different MAC algorithms and visualizes the dramatic security improvement when moving from truncated (32-bit) to full-length (128-bit) MAC tags.

### 📊 Key Demonstration Results

| Phase | MAC Type | Attack Success Rate | Security Status |
|-------|----------|---------------------|-----------------|
| **Before Prevention** | Truncated (32-bit) | **90-100%** | 🔴 VULNERABLE |
| **After Prevention** | Full (128-bit) | **<5%** | 🟢 SECURE |

### 🔬 Security Concepts Demonstrated

1. **Birthday Paradox Attack**: For n-bit MAC, only ~2^(n/2) attempts needed for 50% success probability
2. **Truncation Vulnerability**: Reducing MAC length exponentially decreases security
3. **Birthday Bound**: With 32-bit truncation, collisions become highly probable
4. **Full MAC Security**: 128-bit MAC provides 2^64 security level (practically impossible to break)

---

## 📋 Prerequisites

### System Requirements
- **Python 3.7+** (3.8+ recommended)
- **Operating System**: Windows 10/11, Linux (Ubuntu 18.04+), or macOS 10.15+
- **RAM**: Minimum 4GB (8GB recommended)
- **Network**: Localhost connection (no internet required after installation)
- **Disk Space**: 500MB free space

### Required Python Packages
- cryptography >= 41.0.7
- matplotlib >= 3.7.2
- numpy >= 1.24.3

---

## 🚀 Installation Guide

### Step 1: Install Python

#### Windows
1. Download Python 3.8+ from [python.org](https://www.python.org/downloads/)
2. Run installer → **CHECK** "Add Python to PATH"
3. Click "Install Now"

#### Linux (Ubuntu/Debian)
```bash
sudo apt update
sudo apt install python3 python3-pip python3-tk
