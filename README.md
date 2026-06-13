# Real-Time Intrusion Detection & Response System (RTIDS)

## Overview

The Real-Time Intrusion Detection & Response System (RTIDS) is a Machine Learning-based cybersecurity project designed to detect and respond to Denial of Service (DoS) attacks in real time. The system analyzes network traffic using trained machine learning models and automatically performs response actions such as IP blocking, email notifications, attack logging, and dashboard monitoring.

This project was developed as a Final Year BCA Project and demonstrates the integration of Machine Learning, Cybersecurity, and Web Technologies into a unified intrusion detection platform.

---

## Key Features

* Real-time DoS attack detection using Machine Learning
* XGBoost as the primary detection model
* Decision Tree for prediction verification
* Automated IP blocking mechanism
* Real-time email alert notifications
* Attack logging and monitoring
* Flask-based web dashboard
* Live attack visualization and statistics
* Geographic attack source visualization
* Security event tracking and reporting

---

## Technologies Used

### Programming & Frameworks

* Python
* Flask

### Machine Learning

* XGBoost
* Decision Tree
* Scikit-Learn
* Pandas
* NumPy

### Cybersecurity

* Intrusion Detection System (IDS)
* Real-Time Threat Detection
* Automated Incident Response

### Frontend

* HTML
* CSS
* JavaScript

## Dataset

This project uses the **NSL-KDD Dataset**, a widely used benchmark dataset for evaluating intrusion detection systems.

### Download Dataset

* NSL-KDD Official Repository: https://www.unb.ca/cic/datasets/nsl.html
* Kaggle Dataset: https://www.kaggle.com/datasets/hassan06/nslkdd

After downloading, place the dataset files in the project directory:

```text
KDDTrain.csv
KDDTest.csv
```

The dataset is not included in this repository to reduce repository size and simplify project distribution.

## System Architecture

NSL-KDD Dataset → Data Preprocessing → Model Training → Real-Time Detection Engine → IP Blocking & Email Alerts → Dashboard Monitoring & Logging

---

## Machine Learning Models Evaluated

* XGBoost
* Decision Tree
* Random Forest
* LightGBM
* CatBoost
* AdaBoost

### Best Performing Model

**XGBoost**

### Accuracy Achieved

**98.13%**

---

## Project Components

### Detection Engine

Analyzes incoming network traffic and classifies events as Normal or DoS attacks.

### Automated Response

Blocks malicious IP addresses and generates alert notifications.

### Email Alert System

Sends real-time security alerts when attacks are detected.

### Dashboard

Provides visualization of attacks, logs, statistics, and blocked IP addresses.

### Logging Module

Maintains attack records for monitoring and analysis.

---

## Installation

### Clone Repository

```bash
git clone https://github.com/cyberlordAkki/RTIDS.git
cd RTIDS
```

### Install Dependencies

```bash
pip install -r requirements.txt
```

### Run Application

```bash
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

---

## Dataset

This project uses the NSL-KDD dataset for training and evaluation.

Dataset files are not included in this repository. Download the NSL-KDD dataset separately and place the files in the project directory before running the application.

---

## Screenshots

Add screenshots inside the `screenshots/` folder and display:

* Dashboard Overview
* Attack Distribution
* Live Monitoring Map
* Blocked IP Panel
* Email Alert System
* Attack Logs

---

## Future Improvements

* Support additional attack categories
* Live packet capture integration
* Advanced anomaly detection models
* Cloud deployment
* SIEM integration

---

## License

This project is licensed under the MIT License.

---

## Author

**Akhilesh Kumar**

Bachelor of Computer Applications (BCA)

Cybersecurity | Machine Learning | Python
