


# Neural Network-Based Intrusion Detection and Prevention System (DNN-IDPS)

## DISCLAIMER

This project is intended STRICTLY for **academic, research, and educational purposes**. It includes functionality for live packet sniffing and intrusion detection, which may interact with network traffic in real time.

**You MUST only use this code in a controlled, isolated virtual environment (e.g., VMs on an internal & isolated network), and never on a live, public, or production network without explicit and definitive permission.**

Unauthorised monitoring or interception of network traffic may violate privacy laws and could be considered illegal in your jurisdiction.

I, the author of this repository **accept no responsibility or liability** for any misuse of the code, or any legal consequences arising from its deployment in environments not explicitly permitted or authorised.

By using this code, you agree to take full responsibility for ensuring your use complies with all applicable laws and ethical guidelines.


## Project Overview

This project implements a Deep Neural Network (DNN)-based Intrusion Detection and Prevention System (IDPS) designed to secure medical networks and databases. It leverages a two-tier classification approach: a binary classifier to distinguish between benign and malicious network traffic, and a multi-class classifier to categorise specific types of attacks. The system integrates with a firewall to provide real-time threat detection and automated blocking of malicious IP addresses.

The motivation behind this project stems from the increasing digitisation of healthcare systems, which has made medical databases prime targets for cyber-attacks. Traditional Intrusion Detection Systems (IDS) often struggle with evolving and zero-day threats. This DNN-IDPS aims to address these shortcomings by providing a more adaptive and robust solution for protecting sensitive patient data.

---

## Project Structure

The project consists of several Python scripts and pre-trained models:

- `datasetFilter.py`: Handles data preprocessing, filtering, and balancing of the raw network traffic dataset. It generates `binary_filtered_dataset.csv` and `malicious_filtered_dataset.csv`.
- `binaryClassifier.py`: Trains and evaluates the binary classification model (benign vs. malicious) using the `binary_filtered_dataset.csv`. It saves the trained binary model and its `StandardScaler`.
- `multiclassMetrics.py`: Trains and evaluates the multi-class classification model (specific attack types) using the `malicious_filtered_dataset.csv`. It saves the trained multi-class model, its `StandardScaler`, and the `LabelEncoder`.
- `DNNIDPS.py`: The main script for live packet capture, feature extraction, and real-time intrusion detection and prevention. It loads the pre-trained binary and multi-class models and integrates with the Windows Firewall to block malicious IPs.

Additional Files and Folders:

- `binary_classifier/`: Folder containing the saved Keras model for binary classification.
- `multiclass_classifier/`: Folder containing the saved Keras model for multi-class classification.
- `binary_scaler.pkl`: Pickled `StandardScaler` object used by the binary classifier.
- `multiclass_scaler.pkl`: Pickled `StandardScaler` object used by the multi-class classifier.
- `label_encoder.pkl`: Pickled `LabelEncoder` object used by the multi-class classifier.
- `binary_filtered_dataset.csv`: Processed dataset for binary classification.
- `malicious_filtered_dataset.csv`: Processed dataset containing only malicious traffic for multi-class classification.
- `Cameron Riley Dissertation.pdf`: The full dissertation providing detailed context, methodology, and results.

---

## Features

### Two-Tier Classification

- **Binary Classifier**: Efficiently identifies network traffic as either "benign" or "malicious".
- **Multi-Class Classifier**: Further categorises detected malicious traffic into specific attack types (e.g., DoS, DDoS, Reconnaissance, Spoofing, MQTT-based attacks).

### Real-time Packet Capture

- Utilises `pyshark` to sniff live network traffic from a specified interface.

### Automated IP Blocking

- Integrates with Windows Firewall to automatically block source IP addresses of detected malicious packets.

### Scalable DNN Models

- Built with TensorFlow/Keras, allowing for future retraining and adaptation to new threats.

### Synthetic Data for Ethical Testing

- Employs a synthetic medical database for testing, ensuring no real patient data is compromised.

---

## Setup and Installation

### Prerequisites

- Python 3.8+
- `pip` (Python package installer)
- Wireshark (required for `pyshark`)
- `tshark` (usually installed with Wireshark)
- Windows Operating System (for firewall integration)

### Recommended Environment

Set up a virtualised environment using **Oracle VirtualBox**:

#### HospitalServer VM (Windows 11)

- Install Python, Wireshark, and project dependencies.
- Deploy `DNNIDPS.py` and pre-trained models.

#### AttackHost VM (Kali Linux)

- Install attack tools: `hping3`, `nmap`, `ettercap`, `metasploit-framework`, `mqtt-pwn`.

> Both VMs should be on an isolated internal network.

---

## Project Setup

1. **Clone the repository** or extract files:

```bash
git clone <repository_url>
cd <project_directory>
```

2. **Install dependencies**:

```bash
pip install pandas numpy tensorflow scikit-learn pyshark matplotlib seaborn
pip install Faker  # Only if you need to regenerate the synthetic database
```

3. **Install Wireshark**

- Download from: [https://www.wireshark.org/](https://www.wireshark.org/)

---

## Training the Models (Optional)

Pre-trained models are included, but you can retrain if desired.

### 1. Data Preprocessing

Ensure `combined_train_dataset.csv` is in `D:\DNNIDPS2\`, then run:

```bash
python datasetFilter.py
```

Generates:

- `binary_filtered_dataset.csv`
- `malicious_filtered_dataset.csv`

### 2. Train Binary Classifier

```bash
python binaryClassifier.py
```

Saves model to `binary_classifier/` and scaler to `binary_scaler.pkl`.

### 3. Train Multi-Class Classifier

```bash
python multiclassMetrics.py
```

Saves model to `multiclass_classifier/`, scaler to `multiclass_scaler.pkl`, and label encoder to `label_encoder.pkl`.

---

## Running the DNN-IDPS System

Ensure all model files and scalers are in the correct paths:

- `binary_classifier/`
- `binary_scaler.pkl`
- `multiclass_classifier/`
- `multiclass_scaler.pkl`
- `label_encoder.pkl`

### Modify Network Interface

In `DNNIDPS.py`:

```python
interfaceName = "WiFi"  # Change this to your actual interface name
```

Use `ipconfig` (Windows) or `ifconfig` (Linux/macOS) to find the correct name.

### Run the system

Run as administrator:

```bash
python DNNIDPS.py
```

The system will begin live packet sniffing and take action against malicious traffic by blocking IPs via Windows Firewall.

---

## Synthetic Medical Database

The synthetic database is used as a safe attack target during testing.

To generate it:

```bash
python create_synthetic_medical_records.py
```

> (Script is provided in the dissertation appendix.)

---

## Testing and Evaluation

The project was tested in a virtual machine setup simulating:

- DoS
- DDoS
- Reconnaissance
- Spoofing
- MQTT-based attacks

Refer to:

- Chapter 5.3: *Testing Implementation & Set Up*
- Chapter 6: *Results Analysis*

See `Cameron Riley Dissertation.pdf` for full documentation.

---

## Acknowledgements

This project is a culmination of research and development for a Year 4 Dissertation.

**Special thanks** to Prof. Oleksandr Letychevskyi for supervision and guidance.

---
