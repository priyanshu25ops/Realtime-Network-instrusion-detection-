# 🛡️ Network Intrusion Detection in Cybersecurity Logs

## 👨‍🏫 Faculty
**Dr. S. Prabhakaran**

## 👥 Team Members
- Ayush (RA2311028010089)  
- Priyanshu (RA2311028010087)

---

## 📘 Introduction
- Online news platforms publish **millions of cybersecurity events daily**, but only a few are actual attacks.  
- Detecting these real threats in real time is crucial for **security monitoring and forensic analysis**.  
- **Dataset:** High-volume network logs simulating raw cybersecurity data with **20 different attack types**.  
- **Goal:** Build a **scalable, real-time machine learning pipeline** using AWS (SageMaker, Lambda, S3) to detect cyberattacks.  
- **Challenge:** Handle large log volumes, ensure low latency, and maintain continuous model retraining.  

---

## ⚙️ Problem and Solution

### 🔍 Problem — Why It Matters
- Traditional rule-based systems are **slow and outdated** for modern, large-scale threats.  
- They cannot adapt to **new or unknown attacks (zero-day threats)** or handle huge data volumes efficiently.  

### 🎯 Objective
- Build a **highly scalable ML pipeline** capable of analyzing massive network logs in real time.  
- Accurately **detect and classify 20 types of attacks**, going beyond simple “attack vs normal” systems.  

### 💡 Value
- Provides **low-latency, actionable threat insights** for faster incident response.  
- Enables **proactive and automated** security management.  

---

## 🧠 Methodology

### 🧩 AWS Components
- **Amazon S3:** Stores raw network logs.  
- **AWS Glue / Athena:** Cleans and catalogs the data.  
- **Amazon SageMaker:** Trains and deploys the ML model.  
- **AWS Lambda:** Serves the trained model for real-time inference.  
- **AWS Amplify:** Delivers predictions to the frontend.  

### 🤖 Machine Learning Approach
- **Algorithm:** XGBoost (fast, efficient, and great for structured data).  
- **Task:** Multi-class classification across 20 attack categories.  
- **Innovation:** Continuous retraining pipeline using SageMaker to avoid model drift and adapt to new threats.  

---

## 🧹 Data Pre-Processing

1. **Data Ingestion:** Loaded the UNSW_NB15 dataset from Amazon S3 (`network-intrusion` bucket) using `boto3`.  
2. **Cleaning:** Removed unnecessary columns like `id` and `attack_cat`.  
3. **Outlier Handling:**  
   - Compared each numeric feature’s **Max vs Median**.  
   - If `Max > 10 × Median`, capped extreme values at the **95th percentile**.  
4. **Verification:** Checked with `df.describe()` to confirm clean, stable data.  
5. **Model Readiness:** The dataset is ready for **scaling, encoding**, and **training in SageMaker**.  

---

## 📊 Results
- Built a **real-time cyberattack detection model** using XGBoost.  
- Achieved **multi-class classification** for 20 attack types.  
- Enabled **real-time inference** via AWS Lambda and **auto-retraining** using SageMaker pipelines.  
- Demonstrated a **fully automated, scalable, cloud-based solution** for network intrusion detection.  


