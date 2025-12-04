import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import re
import hashlib
from urllib.parse import urlparse
import warnings
warnings.filterwarnings('ignore')

# Load the dataset
print("Loading and preprocessing cybersecurity dataset...")
df = pd.read_csv('details.csv')

print(f"Original dataset shape: {df.shape}")

# 1. Handle missing values
df.to_csv('preprocessed_cybersecurity_data.csv', index=False)
print("Preprocessed data saved to output/preprocessed_cybersecurity_data.csv")
# Fill missing User-Agent with 'Unknown'
df['User-Agent'] = df['User-Agent'].fillna('Unknown')
# Fill missing Country with 'Unknown'
df['Country'] = df['Country'].fillna('Unknown')

# 2. Parse datetime columns
print("Parsing datetime columns...")
df['Added_datetime'] = pd.to_datetime(df['Added'])
df['Date_datetime'] = pd.to_datetime(df['Date'])

# Extract time-based features
df['hour'] = df['Date_datetime'].dt.hour
df['day_of_week'] = df['Date_datetime'].dt.dayofweek
df['is_weekend'] = df['day_of_week'].isin([5, 6]).astype(int)

# Calculate time difference between Added and Date
df['time_diff_seconds'] = (df['Added_datetime'] - df['Date_datetime']).dt.total_seconds()

# 3. IP Address Analysis
print("Extracting IP features...")
def extract_ip_features(ip):
    features = {}
    # Check if IPv6
    features['is_ipv6'] = ':' in str(ip)
    # IP length
    features['ip_length'] = len(str(ip))
    # Check if private IP range (simplified)
    ip_str = str(ip)
    features['is_private_range'] = (
        ip_str.startswith('192.168.') or 
        ip_str.startswith('10.') or 
        ip_str.startswith('172.16.') or
        ip_str.startswith('127.')
    )
    return features

ip_features = df['IP'].apply(extract_ip_features)
ip_df = pd.DataFrame(ip_features.tolist())
df = pd.concat([df, ip_df], axis=1)

# 4. Endpoint Analysis
print("Extracting endpoint features...")
def extract_endpoint_features(endpoint):
    features = {}
    features['endpoint_length'] = len(str(endpoint))
    features['endpoint_depth'] = str(endpoint).count('/')
    features['has_query_params'] = '?' in str(endpoint)
    features['has_file_extension'] = '.' in str(endpoint).split('/')[-1]
    
    # Check for suspicious patterns
    suspicious_patterns = [
        'wp-login', 'admin', 'config', '.env', 'php', 'sql',
        'wp-admin', 'login', 'upload', 'temp', 'backup'
    ]
    features['suspicious_keywords'] = sum(1 for pattern in suspicious_patterns if pattern.lower() in str(endpoint).lower())
    
    # Parse URL structure
    try:
        parsed = urlparse(str(endpoint))
        features['has_path'] = len(parsed.path) > 1
        features['path_length'] = len(parsed.path)
    except:
        features['has_path'] = False
        features['path_length'] = 0
    
    return features

endpoint_features = df['Endpoint'].apply(extract_endpoint_features)
endpoint_df = pd.DataFrame(endpoint_features.tolist())
df = pd.concat([df, endpoint_df], axis=1)

# 5. User-Agent Analysis
print("Extracting User-Agent features...")
def extract_ua_features(ua):
    features = {}
    ua_str = str(ua).lower()
    
    # Basic features
    features['ua_length'] = len(ua_str)
    features['is_unknown'] = ua_str == 'unknown'
    
    # Browser detection
    features['is_chrome'] = 'chrome' in ua_str
    features['is_firefox'] = 'firefox' in ua_str
    features['is_safari'] = 'safari' in ua_str and 'chrome' not in ua_str
    features['is_edge'] = 'edge' in ua_str
    features['is_ie'] = 'msie' in ua_str or 'trident' in ua_str
    
    # Device detection
    features['is_mobile'] = any(x in ua_str for x in ['mobile', 'android', 'iphone', 'ipad'])
    features['is_windows'] = 'windows' in ua_str
    features['is_mac'] = 'mac' in ua_str
    features['is_linux'] = 'linux' in ua_str
    
    # Bot detection
    features['is_bot'] = any(x in ua_str for x in ['bot', 'crawler', 'spider', 'scraper'])
    
    # Automated tools
    features['is_automated'] = any(x in ua_str for x in ['python', 'go-http', 'curl', 'wget', 'perl'])
    
    # Browser version extraction
    version_match = re.search(r'(?:chrome|firefox|version)/([\d.]+)', ua_str)
    features['browser_version'] = version_match.group(1) if version_match else 'unknown'
    
    return features

ua_features = df['User-Agent'].apply(extract_ua_features)
ua_df = pd.DataFrame(ua_features.tolist())
df = pd.concat([df, ua_df], axis=1)

# 6. Country Analysis
print("Extracting country features...")
# Create country risk score (simplified)
country_risk_scores = {
    'CN': 3, 'RU': 3, 'KP': 3, 'IR': 3,  # High risk
    'US': 1, 'CA': 1, 'GB': 1, 'DE': 1, 'FR': 1,  # Low risk
    'IN': 2, 'BR': 2, 'TR': 2, 'VN': 2,  # Medium risk
}

df['country_risk_score'] = df['Country'].map(country_risk_scores).fillna(2)

# 7. Encode target variable
print("Encoding target variable...")
target_mapping = {
    'MANAGED_CHALLENGE': 0,
    'CHALLENGE': 1, 
    'BLOCK': 2,
    'JSCHALLENGE': 3
}

df['target_encoded'] = df['Action taken'].map(target_mapping)

# 8. Create additional security features
print("Creating security features...")
# Request frequency per IP (simplified - count in dataset)
ip_counts = df['IP'].value_counts()
df['ip_request_count'] = df['IP'].map(ip_counts)

# Unique endpoints per IP
ip_endpoint_counts = df.groupby('IP')['Endpoint'].nunique()
df['ip_unique_endpoints'] = df['IP'].map(ip_endpoint_counts)

# Time-based clustering (requests within short time windows)
df['time_window'] = df['Date_datetime'].dt.floor('1H')
ip_time_counts = df.groupby(['IP', 'time_window']).size()
df['ip_hourly_requests'] = df.set_index(['IP', 'time_window']).index.map(ip_time_counts).fillna(1)

print(f"Final preprocessed dataset shape: {df.shape}")
print(f"New features added: {df.shape[1] - 8} additional features")

# Save preprocessed data
df.to_csv('preprocessed_cybersecurity_data.csv', index=False)
print("Preprocessed data saved to preprocessed_cybersecurity_data.csv")

# Display feature summary
print("\nFeature summary:")
print(f"Target distribution: {df['Action taken'].value_counts()}")
print(f"Numeric features: {df.select_dtypes(include=[np.number]).shape[1]}")
print(f"Categorical features: {df.select_dtypes(include=['object']).shape[1]}")