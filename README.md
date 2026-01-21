# DOCXHUNT Sensitive Data Scanner

A **security-focused DOCX analysis tool** that scans Microsoft Word (.docx) files for **sensitive information**, secrets, and credentials while safely handling malformed or parser-hostile documents.

This tool is designed for **security testing, audits, bug bounty research, and document hygiene checks**.

<p align="center">
  <img src="assets/banner.png" alt="DOCX Sensitive Data Scanner" width="100%">
</p>

## :rocket: What This Tool Does

* Downloads DOCX files from URLs
* Safely parses Word documents
* Detects sensitive data using built-in and custom regex patterns
* Handles **large / malformed DOCX files** without crashing
* Scores findings by **severity** (LOW → CRITICAL)
* Skips unsafe or unparsable documents securely

---

## 🔥 Features

* ✅ Email, phone, ID, and credential detection
* ✅ API keys, tokens, JWTs, cloud secrets detection
* ✅ High-entropy string detection
* ✅ Context-aware severity boosting
* ✅ Template detection & false-positive reduction
* ✅ Safe failure on corrupted or oversized DOCX
* ✅ Verbose logging & skip reports

---

## 🧬 Why This Tool Exists

This tool was created to scan DOCX files for sensitive information such as credentials, secrets, and personal data while handling parsing issues safely.

---

## 📦 Installation

### Requirements

* Python 3.8+
* Linux / macOS (Windows supported with Python)

### Install dependencies

```bash
git clone https://github.com/Infiniteim23/docxhunt.git
cd docxhunt
chmod u+x docxhunt.py
pip install -r requirement.txt
python3 docxhunt.py --help
```

---

## 🚀 Usage

### Basic scan

```bash
python3 docxhunt.py -i urls.txt
```

### Verbose mode

```bash
python3 docxhunt.py -i urls.txt -v
```

### Save output to file

```bash
python3 docxhunt.py -i urls.txt -o report.txt
```

### Save skipped files list

```bash
python3 docxhunt.py -i urls.txt --skip-show
```

---

## 📄 Input Format

`urls.txt`

```text
https://example.com/file1.docx
https://example.com/file2.docx
```

---

## 🧪 What Gets Detected

* Emails
* Phone numbers
* Aadhaar / PAN / SSN
* Credit cards / IBAN
* Passwords & credentials
* JWT tokens
* Bearer tokens
* AWS / Google / Azure secrets
* Database connection strings
* SSH private keys
* High-entropy secrets

---

## 🚦 Severity Levels

| Level    | Meaning                        |
| -------- | ------------------------------ |
| LOW      | Low-risk data                  |
| MED      | Sensitive personal data        |
| HIGH     | Credentials or internal access |
| CRITICAL | Private keys, cloud secrets    |

---

## 🛡️ Safety & Error Handling

* Files larger than **200MB** are skipped
* Non-DOCX URLs are ignored
* Malformed XML triggers **safe skip**
* No code execution or macros are run

This makes the tool safe for **untrusted documents**.

---

## ⚠️ Known Limitations

* Does not support legacy `.doc` files
* Some OCR-heavy DOCX files may be skipped
* Formatting is ignored (text-only analysis)

---

## 🔐 Security Note

This tool is intended for **authorized testing only**.
Do not scan documents without proper permission.

---

## 📌 Use Cases

* Bug bounty research
* Internal security audits
* Document leak detection
* Compliance checks
* Red team reconnaissance

---

## 🧩 Future Improvements

* Fallback XML text extraction
* PDF support

---

## 📜 License

MIT License

---

## 👤 Author

Developed for security research and document safety analysis.

---

**Scan smart. Fail safe. Find leaks.**

