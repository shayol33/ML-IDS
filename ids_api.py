from flask import Flask, request, jsonify
import joblib
import numpy as np
import pandas as pd
from sklearn.preprocessing import StandardScaler
import re
import time
import json
from collections import defaultdict

app = Flask(__name__)

# Load the trained IDS model
model = joblib.load('trained_ids_model.joblib')

# Load the scaler (or create a new one if missing)
try:
    scaler = joblib.load('scaler.joblib')
except Exception:
    scaler = StandardScaler()

# Brute-force tracking
failed_attempts = defaultdict(list)

def extract_ip(log_entry):
    """Extracts IP address from SSH log entry."""
    match = re.search(r'(\d+\.\d+\.\d+\.\d+)', log_entry)
    return match.group(1) if match else None

def detect_bruteforce():
    """Detects brute-force attacks from /var/log/auth.log."""
    global failed_attempts
    with open('/var/log/auth.log', 'r') as log:
        for line in log:
            if "Failed password" in line or "Failed keyboard-interactive/pam" in line:
                ip = extract_ip(line)
                if ip:
                    current_time = time.time()
                    failed_attempts[ip].append(current_time)

                    # Keep only attempts from the last 60 seconds
                    failed_attempts[ip] = [t for t in failed_attempts[ip] if current_time - t < 60]

                    # Flag as malicious if more than 5 failed attempts in 60 seconds
                    if len(failed_attempts[ip]) > 5:
                        return {"ip": ip, "status": "MALICIOUS"}
    return {"status": "BENIGN"}

def preprocess(data_dict):
    """Preprocess input data for the IDS model."""
    df = pd.DataFrame([data_dict])
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan)

    expected_features = [
        "Destination Port", "Flow Duration", "Total Fwd Packets", "Total Backward Packets",
        "Total Length of Fwd Packets", "Total Length of Bwd Packets", "Fwd Packet Length Max",
        "Fwd Packet Length Min", "Fwd Packet Length Mean", "Fwd Packet Length Std",
        "Bwd Packet Length Max", "Bwd Packet Length Min", "Bwd Packet Length Mean", "Bwd Packet Length Std",
        "Flow Bytes/s", "Flow Packets/s", "Flow IAT Mean", "Flow IAT Std", "Flow IAT Max", "Flow IAT Min",
        "Fwd IAT Total", "Fwd IAT Mean", "Fwd IAT Std", "Fwd IAT Max", "Fwd IAT Min",
        "Bwd IAT Total", "Bwd IAT Mean", "Bwd IAT Std", "Bwd IAT Max", "Bwd IAT Min",
        "Fwd PSH Flags", "Bwd PSH Flags", "Fwd URG Flags", "Bwd URG Flags",
        "Fwd Header Length", "Bwd Header Length", "Fwd Packets/s", "Bwd Packets/s",
        "Min Packet Length", "Max Packet Length", "Packet Length Mean", "Packet Length Std",
        "Packet Length Variance", "FIN Flag Count", "SYN Flag Count", "RST Flag Count",
        "PSH Flag Count", "ACK Flag Count", "URG Flag Count", "CWE Flag Count",
        "ECE Flag Count", "Down/Up Ratio", "Average Packet Size", "Avg Fwd Segment Size",
        "Avg Bwd Segment Size", "Fwd Header Length.1", "Fwd Avg Bytes/Bulk",
        "Fwd Avg Packets/Bulk", "Fwd Avg Bulk Rate", "Bwd Avg Bytes/Bulk",
        "Bwd Avg Packets/Bulk", "Bwd Avg Bulk Rate", "Subflow Fwd Packets",
        "Subflow Fwd Bytes", "Subflow Bwd Packets", "Subflow Bwd Bytes",
        "Init_Win_bytes_forward", "Init_Win_bytes_backward", "act_data_pkt_fwd",
        "min_seg_size_forward", "Active Mean", "Active Std", "Active Max",
        "Active Min", "Idle Mean", "Idle Std", "Idle Max", "Idle Min"
    ]

    df_numeric = df.select_dtypes(include=[np.number]).copy()

    for feat in expected_features:
        if feat not in df_numeric.columns:
            df_numeric[feat] = 0

    df_numeric = df_numeric[expected_features]
    df_numeric = df_numeric.fillna(df_numeric.mean())

    if not hasattr(scaler, "mean_"):
        scaler.fit(df_numeric)

    return scaler.transform(df_numeric)

def log_prediction(result):
    """Logs IDS predictions to prediction.log."""
    with open("prediction.log", "a") as log_file:
        log_file.write(json.dumps(result) + "\n")

@app.route('/predict', methods=['POST'])
def predict():
    """Handles IDS prediction and brute-force detection."""
    try:
        data = request.get_json()
        processed = preprocess(data)
        prediction = model.predict(processed)

        # Detect SSH brute-force attacks
        brute_force_result = detect_bruteforce()

        result = {
            'prediction': prediction.tolist(),
            'brute_force_status': brute_force_result
        }
        
        log_prediction(result)  # Log every prediction

        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
