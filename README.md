# Secure Cloud Storage

A secure cloud storage web application built with **Streamlit**, **AWS S3**, and **AES-256-GCM authenticated encryption**.

This project demonstrates secure client-side file segmentation, cryptographic key derivation, block-level authenticated encryption, and private object storage on AWS.

---

## Architecture & Security Model

```
+-----------------------------------------------------------------------------------+
| Streamlit Application (Local / Client-Side)                                       |
|                                                                                   |
|  [ Original File ]                                                                |
|         │                                                                         |
|         ▼                                                                         |
|  [ 1 MB Chunks ] ──► [ HKDF-SHA256 Key Derivation ] (Master Key + File Salt)      |
|         │                        │                                                |
|         ▼                        ▼                                                |
|  [ AES-256-GCM Encrypt ] ◄── [ Derived File Key ]                                 |
|    (Unique 12-byte nonce per chunk)                                               |
+────────────────────────────────────────┬──────────────────────────────────────────+
                                         │ Boto3 Encrypted Upload
                                         ▼
+-----------------------------------------------------------------------------------+
| AWS S3 Private Storage (eu-north-1)                                              |
|                                                                                   |
|  bucket/                                                                          |
|  └── files/                                                                       |
|      └── <file_id>/                                                               |
|          ├── metadata.json       (File name, size, salt, chunk nonces)             |
|          ├── block_0000.bin      (AES-256-GCM ciphertext + auth tag)              |
|          ├── block_0001.bin                                                       |
|          └── ...                                                                  |
+-----------------------------------------------------------------------------------+
```

### Key Security Features
- **Client-Side Encryption:** Plaintext files are never transmitted to S3. Encryption occurs locally before upload.
- **AES-256-GCM Authenticated Encryption:** Protects both confidentiality and data integrity; detects any tampering.
- **HKDF-SHA256 Key Derivation:** A distinct 256-bit encryption key is derived for each file using a persistent master key and a unique random 16-byte salt.
- **Unique Nonces:** Every 1 MB chunk receives a dedicated, cryptographically secure 12-byte nonce (`os.urandom(12)`).
- **Private S3 Objects:** AWS S3 Block Public Access is maintained; no public URLs or buckets are exposed.
- **Credential Isolation:** AWS keys and the master encryption key reside strictly in Streamlit Secrets and are never stored in S3 or committed to git.

---

## Project Structure

```text
SecureCloudStorage/
│
├── app.py                     # Streamlit frontend & application workflow
├── encryption.py              # Chunking, HKDF key derivation, AES-256-GCM
├── storage.py                 # AWS S3 Boto3 integration (upload, download, list)
├── requirements.txt           # Python dependencies
├── .gitignore                 # Git ignore rules for secrets, virtualenv, cache
├── README.md                  # Project documentation & setup guide
│
└── .streamlit/
    └── secrets.toml.example   # Configuration template for AWS and master key
```

---

## Prerequisites

- **Python 3.10+**
- **AWS Account** with an S3 bucket created in region `eu-north-1` (Europe/Stockholm).
- **IAM User / Credentials** with permissions:
  - `s3:PutObject`
  - `s3:GetObject`
  - `s3:ListBucket`

---

## Setup & Local Installation

### 1. Clone or Open the Project
Open a terminal in the `SecureCloudStorage` project folder:

```bash
cd SecureCloudStorage
```

### 2. Create and Activate a Virtual Environment

**Windows (PowerShell):**
```powershell
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**macOS / Linux:**
```bash
python3 -m venv venv
source venv/bin/activate
```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

### 4. Configure Streamlit Secrets

1. Copy the example secrets file:
   - On Windows (PowerShell):
     ```powershell
     Copy-Item .streamlit\secrets.toml.example .streamlit\secrets.toml
     ```
   - On macOS/Linux:
     ```bash
     cp .streamlit/secrets.toml.example .streamlit/secrets.toml
     ```

2. Generate a 256-bit random Master Encryption Key (64 hex characters):
   ```bash
   python -c "import secrets; print(secrets.token_hex(32))"
   ```

3. Open `.streamlit/secrets.toml` and fill in your settings:
   ```toml
   [aws]
   aws_access_key_id = "YOUR_ACTUAL_AWS_ACCESS_KEY_ID"
   aws_secret_access_key = "YOUR_ACTUAL_AWS_SECRET_ACCESS_KEY"
   region_name = "eu-north-1"
   bucket_name = "your-actual-s3-bucket-name"

   [security]
   master_key = "PASTE_THE_64_HEX_CHARACTERS_GENERATED_ABOVE"
   ```

4. *(Optional)* Set your GitHub profile or repository URL:
   Open `app.py` and replace the placeholder URL on line 25:
   ```python
   GITHUB_URL = "https://github.com/your-username/SecureCloudStorage"
   ```

---

## Running the Application

Launch the Streamlit app:

```bash
streamlit run app.py
```

Streamlit will start local server (usually at `http://localhost:8501`).

---

## Application Usage

1. **Upload File:**
   - Choose any file (text, PDF, image, video, binary, or empty file).
   - Review calculated chunk count.
   - Click **"Encrypt & Upload to S3"**.
   - Chunks are encrypted sequentially and uploaded with their metadata.

2. **Download & Decrypt File:**
   - Select **"Download & Decrypt File"** from the sidebar menu.
   - Choose a file from the list of files stored in S3.
   - Click **"Download, Decrypt & Reconstruct"**.
   - Chunks are downloaded, authenticated, decrypted in order, and reconstructed.
   - Click the download button to save the original file to your machine.

3. **GitHub:**
   - Click **"Open GitHub"** in the sidebar to view the project repository.
