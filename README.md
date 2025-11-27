# 🔐 Hybrid Post-Quantum File Encryption (Kyber512 + AES-256)
This repository contains the implementation of a hybrid post-quantum file encryption system that combines:
- 🚀 Kyber512 (Post-Quantum KEM) – secure quantum-resistant key encapsulation
- ⚡ AES-256 – high-speed symmetric encryption for large files
This project accompanies the research paper:
"Hybrid Post-Quantum File Encryption using Kyber512 and AES: Performance Evaluation and Scalability Analysis"
(📄 ArXiv link will be added after publication)

## ✨ Features
- 🔒 Quantum-safe key exchange using Kyber512
- ⚙️ Fast file encryption & decryption using AES-256
- 📁 Supports large file sizes (1MB – 1GB)
- 📊 Includes benchmarking scripts
- 🧩 Modular code structure
- 🆓 MIT License (free to use & modify)

## 📂 Project Structure
```bash
FileEncryption_Post-quantum_Cryptography/
│
├── src/
│   ├── encrypt.py
│   ├── decrypt.py
│   └── benchmark.py
│
├── samples/
│   ├── sample.txt
│   ├── sample.enc
│   └── sample_dec.txt
│
├── requirements.txt
├── README.md
└── LICENSE
```

## 🛠 Installation
1️⃣ Clone the repository:
git clone https://github.com/Suyashtiwari-7/FileEncryption_Post-quantum_Cryptography
cd FileEncryption_Post-quantum_Cryptography

2️⃣ Install Python dependencies:
```bash
pip install -r requirements.txt
```

3️⃣ Install liboqs (required for Kyber512) (Ubuntu / Linux):
```bash
sudo apt update
sudo apt install libssl-dev cmake
git clone https://github.com/open-quantum-safe/liboqs.git
cd liboqs
mkdir build && cd build
cmake .. && make -j
sudo make install
```

## 🔧 Usage
🔒 Encrypt a file:
```
python src/encrypt.py --input secret.txt --output secret.enc
```

🔓 Decrypt a file:
```bash
python src/decrypt.py --input secret.enc --output secret_decrypted.txt
```

📊 Run benchmarks:
python src/benchmark.py

## 📈 Benchmark Environment (Used in Paper)
- 💻 CPU: Intel Core i7
- 🧠 RAM: 16 GB
- 🐧 OS: Ubuntu 22.04
- 📦 Libraries: PyCryptodome, PQClean/liboqs
- 📁 Tested file sizes: 1MB, 100MB, 1GB

## 📁 Sample Files Included
The samples/ directory contains:
- sample.txt – example file
- sample.enc – encrypted output
- sample_dec.txt – decrypted file

## 🧪 Reproducibility
Environment:
Python 3.10+
Ubuntu 22.04+
liboqs latest stable build
Benchmarking includes:
- ⏱ Key generation time
- 🔐 Encryption/decryption time
- 💾 Memory usage
- 📊 Scalability on large files

## 🎓 Citation
If you use this code in research, please cite:
Tiwari, S. J. (2024). Hybrid Post-Quantum File Encryption using Kyber512 and AES: Performance Evaluation and Scalability Analysis. arXiv:XXXX.XXXXX.

## 👤 Author
Suyash Jagdish Tiwari
📧 Email: suyashjtiwari@outlook.com
