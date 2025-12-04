import pandas as pd
import numpy as np
import pickle
import warnings
from urllib.parse import urlparse
import re

warnings.filterwarnings('ignore')

# --- 1. CONFIGURATION & MODEL LOADING ---
print("Initializing inference pipeline...")
MODEL_PATH = 'best_cybersecurity_model.pkl'

# Load the trained model pipeline
try:
    with open(MODEL_PATH, 'rb') as f:
        model_pipeline = pickle.load(f)
    print(f"Model '{MODEL_PATH}' loaded successfully.")
except FileNotFoundError:
    print(f"FATAL ERROR: Model file not found at '{MODEL_PATH}'.")
    print("Please ensure you have run the 'model_development_pipeline.py' script first.")
    exit()

# This mapping is crucial to translate the model's output back to human-readable actions.
ACTION_MAPPING = {
    0: 'MANAGED_CHALLENGE',
    1: 'CHALLENGE',
    2: 'BLOCK',
    3: 'JSCHALLENGE'
}
print("Inference pipeline ready.")


# --- 2. FEATURE ENGINEERING FUNCTIONS ---
# These functions MUST EXACTLY MATCH the ones used in the original 'data_preprocessing.py' script.
# This ensures that the data fed to the model for prediction is identical in structure to the training data.

def extract_ip_features(ip):
    features = {}
    ip_str = str(ip)
    features['is_ipv6'] = ':' in ip_str
    features['ip_length'] = len(ip_str)
    features['is_private_range'] = (
        ip_str.startswith('192.168.') or 
        ip_str.startswith('10.') or 
        ip_str.startswith('172.16.') or
        ip_str.startswith('127.')
    )
    return pd.Series(features)

def extract_endpoint_features(endpoint):
    features = {}
    endpoint_str = str(endpoint)
    features['endpoint_length'] = len(endpoint_str)
    features['endpoint_depth'] = endpoint_str.count('/')
    features['has_query_params'] = '?' in endpoint_str
    features['has_file_extension'] = '.' in endpoint_str.split('/')[-1]
    suspicious_patterns = [
        'wp-login', 'admin', 'config', '.env', 'php', 'sql',
        'wp-admin', 'login', 'upload', 'temp', 'backup'
    ]
    features['suspicious_keywords'] = sum(1 for pattern in suspicious_patterns if pattern.lower() in endpoint_str.lower())
    try:
        parsed = urlparse(endpoint_str)
        features['has_path'] = len(parsed.path) > 1
        features['path_length'] = len(parsed.path)
    except:
        features['has_path'] = False
        features['path_length'] = 0
    return pd.Series(features)

def extract_ua_features(ua):
    features = {}
    ua_str = str(ua).lower()
    features['ua_length'] = len(ua_str)
    features['is_unknown'] = ua_str == 'unknown'
    features['is_chrome'] = 'chrome' in ua_str
    features['is_firefox'] = 'firefox' in ua_str
    features['is_safari'] = 'safari' in ua_str and 'chrome' not in ua_str
    features['is_edge'] = 'edge' in ua_str
    features['is_ie'] = 'msie' in ua_str or 'trident' in ua_str
    features['is_mobile'] = any(x in ua_str for x in ['mobile', 'android', 'iphone', 'ipad'])
    features['is_windows'] = 'windows' in ua_str
    features['is_mac'] = 'mac' in ua_str
    features['is_linux'] = 'linux' in ua_str
    features['is_bot'] = any(x in ua_str for x in ['bot', 'crawler', 'spider', 'scraper'])
    features['is_automated'] = any(x in ua_str for x in ['python', 'go-http', 'curl', 'wget', 'perl'])
    return pd.Series(features)

def create_country_risk_score(country):
    country_risk_scores = {
        'CN': 3, 'RU': 3, 'KP': 3, 'IR': 3,
        'US': 1, 'CA': 1, 'GB': 1, 'DE': 1, 'FR': 1,
        'IN': 2, 'BR': 2, 'TR': 2, 'VN': 2,
    }
    return country_risk_scores.get(country, 2) # Default to medium risk


# --- 3. THE CORE INFERENCE FUNCTION ---
def predict_threat(raw_data_dict):
    """
    Takes a dictionary of raw log data, processes it into a feature vector,
    and returns the model's prediction.

    Args:
        raw_data_dict (dict): A dictionary representing a single log entry.
                              Must contain keys: 'IP', 'Endpoint', 'User-Agent', 'Country', 'Date'.

    Returns:
        dict: A dictionary containing the predicted action and probability scores.
    """
    print(f"\nProcessing new request: {raw_data_dict}")

    # Create a DataFrame from the input dictionary
    df = pd.DataFrame([raw_data_dict])

    # --- Feature Creation (must match training) ---
    # 1. Datetime features
    df['Date_datetime'] = pd.to_datetime(df['Date'])
    df['hour'] = df['Date_datetime'].dt.hour
    df['day_of_week'] = df['Date_datetime'].dt.dayofweek
    df['is_weekend'] = df['Date_datetime'].dt.dayofweek.isin([5, 6]).astype(int)

    # Note: time_diff_seconds and behavioral features (like ip_request_count)
    # cannot be calculated from a single data point in real-time. We will impute them.
    # A production system might use a database to calculate these over a time window.
    df['time_diff_seconds'] = 0
    df['ip_request_count'] = 1
    df['ip_unique_endpoints'] = 1
    df['ip_hourly_requests'] = 1

    # 2. IP, Endpoint, and User-Agent features
    df = pd.concat([df, df['IP'].apply(extract_ip_features)], axis=1)
    df = pd.concat([df, df['Endpoint'].apply(extract_endpoint_features)], axis=1)
    df = pd.concat([df, df['User-Agent'].apply(extract_ua_features)], axis=1)

    # 3. Country risk score
    df['country_risk_score'] = df['Country'].apply(create_country_risk_score)
    
    # --- Align Columns ---
    # Ensure the dataframe has the exact same columns in the same order as the training data.
    # The model's preprocessor (imputer, scaler) is very strict about this.
    training_features = model_pipeline.steps[0][1].get_feature_names_out()
    for col in training_features:
        if col not in df.columns:
            df[col] = 0 # Add missing columns and fill with a neutral value
    
    df = df[training_features] # Order columns correctly

    # --- THIS IS THE FIX ---
    # Enforce all feature columns are float64 to match the dtype during training.
    df = df.astype(np.float64)
    # ----------------------

    # --- Prediction ---
    prediction_code = model_pipeline.predict(df)[0]
    prediction_proba = model_pipeline.predict_proba(df)[0]
    
    predicted_action = ACTION_MAPPING.get(prediction_code, "Unknown Action")
    
    # Format probabilities for easy reading
    probabilities = {ACTION_MAPPING[i]: f"{prob:.2%}" for i, prob in enumerate(prediction_proba)}

    result = {
        'predicted_action': predicted_action,
        'prediction_code': int(prediction_code),
        'confidence_scores': probabilities
    }
    
    print(f"-> Prediction complete. Result: {result}")
    return result


# --- 4. EXAMPLE USAGE ---
if __name__ == '__main__':
    print("\n" + "="*50)
    print("Running Inference Examples...")
    print("="*50)

    # Example 1: A suspicious request
    suspicious_request = {
        'IP': '185.191.171.12', # High-risk IP range often
        'Endpoint': '/wp-admin/config.php?action=edit',
        'User-Agent': 'python-requests/2.25.1', # Automated tool
        'Country': 'RU', # High-risk country
        'Date': '2024-10-01 03:15:00'
    }
    predict_threat(suspicious_request)

    # Example 2: A seemingly normal request
    normal_request = {
        'IP': '73.16.24.110',
        'Endpoint': '/products/new-arrivals',
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36',
        'Country': 'US', # Low-risk country
        'Date': '2024-10-01 14:30:00'
    }
    predict_threat(normal_request)

    # Example 3: A scanning bot
    scanner_request = {
        'IP': '45.146.165.137',
        'Endpoint': '/.env',
        'User-Agent': 'curl/7.68.0',
        'Country': 'DE',
        'Date': '2024-10-01 05:00:00'
    }
    predict_threat(scanner_request)

