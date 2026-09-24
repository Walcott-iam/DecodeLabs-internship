# DecodeLabs-internships

# 🛡️ Password Strength Checker (Project 1)
**DecodeLabs Industrial Training Kit | Batch 2026**
**Track:** Cyber security

## 📖 Project Overview
This project is the foundational milestone for the Cybersecurity Analyst track at DecodeLabs. The goal is to build a robust **Password Strength Checker** that evaluates risk using pure string handling and conditional logic.

According to the **Verizon DBIR**, **81% of hacking-related breaches leverage weak or stolen passwords**. This tool acts as the "Gatekeeper" to ensure that only strong, high-entropy credentials are passed on to the encryption/hashing phase (Project 2).

## 🎯 Key Requirements & Policy
The program evaluates passwords based on the following "Zero Point" policy:
*   **Length Verification:** Minimum 8 characters (`< 8 = Immediate Fail` due to exponential brute force risk).
*   **Pattern Recognition:** Mandatory checks for:
    *   Lowercase letters `[a-z]`
    *   Uppercase letters `[A-Z]`
    *   Digits `[0-9]`
    *   Symbols (e.g., `!@#$%^&*`)
*   **Complexity:** Calculates estimated entropy (bits) based on character pool size (ASCII vs. Unicode).
*   **Unicode Bonus:** Rewards the use of non-ASCII characters (emoji, accents) as they expand the search space from 95 (ASCII) to **143,000+ (Unicode)**.
*   **Common Password Check:** Validates against a list of known "leaked" passwords.
*   **Output Classification:** Displays a clear result: **Weak**, **Medium**, or **Strong**, along with actionable suggestions.

## ✨ Features (Implementation Highlights)
*   **Pythonic Elegance:** Utilizes `any()` with short-circuit execution rather than verbose manual loops for faster, cleaner validation.
*   **Gatekeeper Rule:** Implements the logic *"You cannot hash what is weak. Filter entropy before Argon2id."*
*   **Linear Time Complexity:** Designed to validate in `O(n)` (Linear Scan) to prevent exponential time growth.
*   **Security Best Practices:**
    *   Uses hidden input (`getpass`) to prevent shoulder-surfing.
    *   Demonstrates awareness of RAM scraping (trap) and timing attacks (via constant-time comparison concepts).
*   **Detailed Feedback:** Provides a checklist and specific suggestions for improving the password.

## 🧪 Test Cases & Results

The following test cases demonstrate the scoring logic (out of 6 checks):

| Password | Length | Score | Classification | Verdict |
| :--- | :--- | :--- | :--- | :--- |
| `abc` | 3 | **1/6** | 🔴 **Weak** | FAIL – Too short, missing variety |
| `Abcdefg1` | 8 | **4/6** | 🟡 **Medium** | FAIL – Missing symbols & Unicode bonus |
| `Abcdef1!` | 8 | **5/6** | 🟢 **Strong** | PASS – Gatekeeper validated |

### Scoring Breakdown
Each password is checked against 6 criteria. The classification is derived as follows:

*   **Weak (0–2 checks):** Immediate fail. Short passwords fall to brute force exponentially faster.
*   **Medium (3–4 checks):** Meets minimum length but lacks complexity (symbols/special chars). Too weak to hash safely.
*   **Strong (5–6 checks):** High entropy, includes mixed case, digits, and symbols. Safe to proceed to hashing/encryption.

## 🖥️ Terminal Outputs (Testing Screenshots)

### 1. Weak Password (Fail)
**Input:** `abc` (Length: 3)
*Result: 1/6 checks passed. Immediate fail due to length.*

![weak-password.png](https://github.com/Walcott-iam/TASK-1-Oresanya-khaleed-walcott/blob/3fe4b7922fff52ad27f182cdf1a9d19bd9c21561/weak-password.png)

### 2. Medium Password (Fail – Fix First)
**Input:** `Abcdefg1` (Length: 8)
*Result: 4/6 checks passed. Missing symbols and Unicode bonus. Meets minimum length but is too predictable.*
![medium-password.png](https://github.com/Walcott-iam/TASK-1-Oresanya-khaleed-walcott/blob/3fe4b7922fff52ad27f182cdf1a9d19bd9c21561/medium-%20password.png)

### 3. Strong Password (Pass – Gatekeeper Validated)
**Input:** `Abcdef1!` (Length: 8, Mixed Case, Number, Symbol)
*Result: 5/6 checks passed. High entropy, safe to proceed to hashing/encryption.*
![strong-password.png](https://github.com/Walcott-iam/TASK-1-Oresanya-khaleed-walcott/blob/3fe4b7922fff52ad27f182cdf1a9d19bd9c21561/strong-password.png)

## 🚀 How to Run
1.  Ensure you have **Python 3.x** installed.
2.  Clone this repository or download the `password_checker.py` file.
3.  Open your terminal/command prompt.
4.  Run the script:
    ```bash
    python3 password_checker.py
    ```
5.  Enter a password when prompted (input is hidden for security).

## 🧠 Key Skills Demonstrated
*   **String Handling:** Iterating and analyzing character types.
*   **Conditional Checks:** Multi-factor logic (Length + Variety + Pattern).
*   **Security Basics:** Entropy estimation, brute-force resistance, and defensive logic.
*   **Professional Code Structure:** Clear I/O, readable output, and inline documentation.
