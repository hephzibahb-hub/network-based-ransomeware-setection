# Ransomware Detection System — Transfer Package

## Project Overview
A machine learning-based ransomware detection system that analyzes network traffic (Zeek conn logs / PCAPs) and classifies it as benign or ransomware using a Random Forest model and a Deep Learning model.

---

## Folder Structure

```
finalyear_project_transfer/
├── app/
│   ├── __init__.py
│   ├── api/                        # FastAPI backend
│   │   ├── server.py               # Main API server
│   │   ├── email_alert.py          # SMTP email alerting
│   │   └── smtp_config.py          # SMTP configuration
│   └── web/
│       └── index.html              # Frontend dashboard (SENTINEL UI)
│
├── src/
│   ├── inference/                  # Model inference scripts
│   │   ├── predict.py              # RF model prediction
│   │   ├── predict_dl.py           # DL model prediction
│   │   ├── zeek_runner.py          # Zeek PCAP processing
│   │   └── ...
│   ├── preprocessing/              # Dataset building scripts
│   │   ├── parse_connlogs.py
│   │   ├── build_full_dataset.py
│   │   └── ...
│   └── training/                   # Model training scripts
│       ├── train_model.py          # RF training
│       └── train_final_model.py    # RF final training
│
├── data/
│   ├── models/                     # Random Forest model (production)
│   │   ├── ransomware_detector_final.pkl
│   │   └── label_encoder_final.pkl
│   └── dl_models/                  # Deep Learning model (production)
│       ├── ransomware_dl_model.h5
│       ├── dl_preprocessor.pkl
│       └── dl_label_encoder.pkl
│
├── docs/
│   ├── architecture_diagram.png    # System architecture
│   └── report/                     # Charts and report assets
│
├── train_dl.py                     # Root DL training script
├── test_smtp.py                    # SMTP email test utility
└── requirements.txt                # All Python dependencies
```

---

## Setup on New Machine

### 1. Install Python
Requires **Python 3.10+**. Download from https://www.python.org/downloads/

### 2. Install Zeek (for PCAP analysis)
Download from https://zeek.org/get-zeek/

### 3. Create Virtual Environment & Install Dependencies
```bash
python -m venv venv

# Windows
venv\Scripts\activate

# Linux/Mac
source venv/bin/activate

pip install -r requirements.txt
```

### 4. Configure SMTP (for email alerts)
Edit `app/api/smtp_config.py` with your Gmail credentials:
```python
SMTP_HOST = "smtp.gmail.com"
SMTP_PORT = 587
SMTP_USER = "your_email@gmail.com"
SMTP_PASS = "your_app_password"
```

### 5. Run the Application
```bash
# From the project root
python app/api/server.py
```
Then open your browser at: **http://localhost:8000**

---

## Model Files

| File | Size | Purpose |
|------|------|---------|
| `ransomware_detector_final.pkl` | ~4 GB | Random Forest classifier |
| `label_encoder_final.pkl` | ~1 KB | RF label encoder |
| `ransomware_dl_model.h5` | ~7.4 GB | Deep Learning model (TensorFlow/Keras) |
| `dl_preprocessor.pkl` | ~25 MB | DL scaler/preprocessor |
| `dl_label_encoder.pkl` | ~1 KB | DL label encoder |

> **Note:** The DL model requires a machine with adequate RAM (16 GB+ recommended).

---

## What Was Excluded (Not Needed to Run)
- `venv/` — Python virtual environment (must be recreated)
- `data/raw/` — Raw PCAP files (several GB, used only during training)
- `data/processed/` — Empty directory
- `pcaps/` — Test/duplicate PCAP files
- `data/models/ransomware_detector.pkl` / `_v2.pkl` — Old model versions (superseded by `_final.pkl`)
- `__pycache__/` — Python bytecode cache (auto-generated)
- `.git/` — Git history
- `._*` files — macOS metadata artifacts

---

## Requirements
- Python 3.10+
- TensorFlow / Keras (for DL model)
- scikit-learn (for RF model)
- FastAPI + Uvicorn (backend)
- Zeek (network log processing)
