# ids_api.py
from flask import Flask, request, jsonify
import joblib
import numpy as np
from sklearn.preprocessing import StandardScaler
import pandas as pd

app = Flask(__name__)
# Load your model (and scaler if saved separately)
model = joblib.load('trained_ids_model.joblib')
try:
    scaler = joblib.load('scaler.joblib')
except Exception as e:
    scaler = StandardScaler()

def preprocess(data_dict):
    # Convert the input dictionary to a DataFrame
    df = pd.DataFrame([data_dict])
    df.columns = df.columns.str.strip()
    df = df.replace([np.inf, -np.inf], np.nan)
    
    # Get expected features from the model or define them manually
    if hasattr(model, "feature_names_in_"):
        expected_features = list(model.feature_names_in_)
    else:
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
    
    # Keep only numeric data from the input
    df_numeric = df.select_dtypes(include=[np.number]).copy()
    
    # For each expected feature, if it's missing, add it with a default value of 0
    for feat in expected_features:
        if feat not in df_numeric.columns:
            df_numeric[feat] = 0
    
    # Restrict the DataFrame to the expected features in the correct order
    df_numeric = df_numeric[expected_features]
    
    # Fill missing numeric values with column means
    df_numeric = df_numeric.fillna(df_numeric.mean())
    
    # Fit the scaler if it hasn't been fitted already (in production, use a pre-fitted scaler)
    if not hasattr(scaler, "mean_"):
        scaler.fit(df_numeric)
    
    return scaler.transform(df_numeric)

@app.route('/predict', methods=['POST'])
def predict():
    try:
        data = request.get_json()
        processed = preprocess(data)
        prediction = model.predict(processed)
        return jsonify({'prediction': prediction.tolist()})
    except Exception as e:
        return jsonify({'error': str(e)}), 400

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
