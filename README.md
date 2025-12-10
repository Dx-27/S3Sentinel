# S3Sentinel ☁️🔒

CloudGuard Analyzer is a compact Streamlit app that scans an AWS account's S3 buckets for common misconfigurations and generates a quick PDF audit. It focuses on three core checks per bucket:
- Public access block configuration
- Server-side encryption
- Versioning status

> Built for authorized, defensive audits and learning. Do not scan accounts you do not own or have explicit permission to test.

---

## Features
- ✅ Lists all S3 buckets in the configured AWS account
- 🔍 Checks Public Access Block configuration (detects missing or permissive settings)
- 🔐 Detects whether default bucket encryption is enabled
- 🗂 Checks if versioning is enabled
- 📈 Risk scoring and per-bucket "DANGER" / "SAFE" classification
- 📄 Generates a summarized PDF report (`CloudGuard.pdf`)
- 🧾 Simple Streamlit UI with progress and expandable per-bucket details

---

## Quick Start

### 1. Clone the repo
```bash
git clone https://github.com/Dx-27/S3Sentinel.git
cd S3Sentinel
```

### 2. Create & activate a virtual environment
```bash
python -m venv venv
# macOS / Linux
source venv/bin/activate
# Windows (PowerShell)
venv\Scripts\Activate.ps1
```

### 3. Install dependencies
```bash
pip install -r requirements.txt
```

### 4. Run the app
```bash
streamlit run app.py
# or the filename you saved the script as (for example cloudguard.py)
```

Open the URL Streamlit prints (usually `http://localhost:8501`).

---

## Usage & UI notes
- Enter your **AWS Access Key ID** and **AWS Secret Access Key** in the sidebar along with the AWS region, and click **Start Cloud Scan**.
- The app will use the provided credentials locally to list buckets and perform the checks.
- Results are shown as metrics and an expandable list with remediation suggestions for insecure buckets.
- Click **Generate PDF Report** to download a snapshot of the findings.

---

## Security & privacy
- **Local only:** The app does not persist your AWS credentials; they are used to create a local boto3 session only. Still, avoid running this on untrusted/shared machines.
- **Least privilege:** For safety, run this with an IAM user/role that has minimal permissions required, e.g.:
  - `s3:ListAllMyBuckets`
  - `s3:GetBucketPublicAccessBlock`
  - `s3:GetBucketEncryption`
  - `s3:GetBucketVersioning`
- **Authorized use only:** Always have permission to scan the target AWS account.

---

## What the scanner considers risky
The app assigns a simple risk score based on missing controls:
- Missing or misconfigured Public Access Block → +50 risk
- Missing encryption → +20 risk
- Missing versioning → +10 risk

Buckets with score >= 30 are labeled **DANGER**. This is a conservative, educational heuristic — adapt scoring to fit your org's policy.

---

## Limitations & caveats
- This is **not** a full security assessment. It checks only a small set of S3 security controls.
- Does not inspect object ACLs or bucket policies in detail.
- Relies on AWS API calls and will be impacted by API throttling or permissions errors.
- PDF output is basic and intended as a quick export for reporting — not compliance-grade documentation.

---

## Extending CloudGuard
Ideas to improve the tool:
- Inspect bucket policies and object ACLs for public grants
- Check for MFA Delete, lifecycle rules, and replication settings
- Integrate with AWS Config / Security Hub for centralized findings
- Add authentication for the Streamlit app and redact sensitive outputs
- Produce CSV/JSON exports and aggregate dashboards

---

## Troubleshooting
- `ClientError` authentication: confirm credentials and IAM permissions.
- If `get_bucket_encryption` raises errors for buckets with no encryption, the script treats that as "Missing Encryption".
- Run the app in a network environment that can reach AWS endpoints for the selected region.


## License
Pick a license (MIT recommended). Add a `LICENSE` file to the repo if you plan to publish.
