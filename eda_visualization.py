import pandas as pd
import numpy as np
import matplotlib.pyplot as plt
import seaborn as sns
from datetime import datetime
import plotly.express as px
import plotly.graph_objects as go
from plotly.subplots import make_subplots
import plotly.io as pio
import warnings
import os

warnings.filterwarnings('ignore')

# Load preprocessed data
try:
    df = pd.read_csv('preprocessed_cybersecurity_data.csv')
except FileNotFoundError:
    df = pd.read_csv('output/preprocessed_cybersecurity_data.csv')

# --- THIS IS THE FIX ---
# Force the 'Date_datetime' column to a proper datetime format, handling any mixed formats.
df['Date_datetime'] = pd.to_datetime(df['Date_datetime'], format='mixed', errors='coerce')
# ---------------------

# Set up matplotlib style for cybersecurity theme
plt.style.use('dark_background')
cyber_colors = ['#00D4FF', '#FF6B6B', '#4ECDC4', '#45B7D1', '#96CEB4', '#FFEAA7']

# Create a directory for the output images if it doesn't exist
output_dir = 'eda_visualizations'
os.makedirs(output_dir, exist_ok=True)


print("Creating comprehensive EDA visualizations...")

# 1. Target Distribution
fig, axes = plt.subplots(2, 2, figsize=(15, 12))
fig.suptitle('Cybersecurity Threat Detection - Exploratory Data Analysis', fontsize=20, color='#00D4FF')

# Target distribution
target_counts = df['Action taken'].value_counts()
axes[0,0].pie(target_counts.values, labels=target_counts.index, autopct='%1.1f%%', 
              colors=cyber_colors, startangle=90)
axes[0,0].set_title('Distribution of Security Actions', color='#00D4FF', fontsize=14)

# Hourly attack patterns
hourly_attacks = df.groupby('hour')['target_encoded'].count()
axes[0,1].bar(hourly_attacks.index, hourly_attacks.values, color=cyber_colors[0])
axes[0,1].set_title('Attack Patterns by Hour', color='#00D4FF', fontsize=14)
axes[0,1].set_xlabel('Hour of Day')
axes[0,1].set_ylabel('Number of Requests')

# Top countries by attacks
top_countries = df['Country'].value_counts().head(10)
axes[1,0].barh(top_countries.index, top_countries.values, color=cyber_colors[1])
axes[1,0].set_title('Top 10 Countries by Request Count', color='#00D4FF', fontsize=14)
axes[1,0].set_xlabel('Number of Requests')
axes[1,0].invert_yaxis()

# IP request distribution
ip_request_dist = df['ip_request_count'].value_counts().sort_index().head(20)
axes[1,1].plot(ip_request_dist.index, ip_request_dist.values, color=cyber_colors[2], marker='o')
axes[1,1].set_title('IP Request Count Distribution (First 20)', color='#00D4FF', fontsize=14)
axes[1,1].set_xlabel('Requests per IP')
axes[1,1].set_ylabel('Number of IPs')
axes[1,1].set_yscale('log')

plt.tight_layout(rect=[0, 0.03, 1, 0.95])
plt.savefig(os.path.join(output_dir, 'eda_overview.png'), dpi=300, bbox_inches='tight', 
            facecolor='#2C3E50', edgecolor='none')
plt.close()

# 2. Create interactive Plotly visualizations
print("Creating interactive visualizations...")

# The .dt accessor will now work correctly
daily_threats = df.groupby([df['Date_datetime'].dt.date, 'Action taken']).size().unstack(fill_value=0)

fig_timeline = go.Figure()
for action in daily_threats.columns:
    fig_timeline.add_trace(go.Scatter(
        x=daily_threats.index,
        y=daily_threats[action],
        mode='lines+markers',
        name=action,
        line=dict(width=2)
    ))

fig_timeline.update_layout(
    title='Cybersecurity Threat Timeline',
    xaxis_title='Date',
    yaxis_title='Number of Requests',
    template='plotly_dark',
    font=dict(color='#00D4FF'),
    paper_bgcolor='#2C3E50',
    plot_bgcolor='#34495E'
)

fig_timeline.write_html(os.path.join(output_dir, 'threat_timeline.html'))

# Interactive country threat map
country_threats = df.groupby(['Country', 'Action taken']).size().unstack(fill_value=0)
country_threats['total_threats'] = country_threats.sum(axis=1)
country_threats = country_threats.reset_index()

fig_map = px.choropleth(
    country_threats,
    locations='Country',
    locationmode='country names',
    color='total_threats',
    hover_name='Country',
    hover_data=['BLOCK', 'CHALLENGE', 'MANAGED_CHALLENGE', 'JSCHALLENGE'],
    color_continuous_scale='Reds',
    template='plotly_dark',
    title='Global Cybersecurity Threat Distribution'
)

fig_map.update_layout(
    font=dict(color='#00D4FF'),
    paper_bgcolor='#2C3E50'
)

fig_map.write_html(os.path.join(output_dir, 'threat_map.html'))

# 3. Feature correlation analysis
print("Creating correlation analysis...")
numeric_features = df.select_dtypes(include=[np.number])
correlation_matrix = numeric_features.corr()

plt.figure(figsize=(20, 16))
mask = np.triu(np.ones_like(correlation_matrix, dtype=bool))
sns.heatmap(correlation_matrix, mask=mask, annot=False, cmap='RdBu_r', center=0,
            square=True, linewidths=.5, cbar_kws={"shrink": .8})
plt.title('Feature Correlation Matrix - Cybersecurity Dataset', 
          fontsize=16, color='#00D4FF', pad=20)
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'correlation_matrix.png'), dpi=300, bbox_inches='tight',
            facecolor='#2C3E50', edgecolor='none')
plt.close()

# 4. Suspicious endpoint analysis
print("Analyzing suspicious endpoints...")
suspicious_endpoints = df[df['suspicious_keywords'] > 0]['Endpoint'].value_counts().head(15)

plt.figure(figsize=(12, 8))
bars = plt.barh(suspicious_endpoints.index, suspicious_endpoints.values, 
                color='#FF6B6B')
plt.xlabel('Number of Suspicious Requests')
plt.title('Top 15 Suspicious Endpoints', color='#00D4FF', fontsize=16)
plt.gca().invert_yaxis()

# Add value labels on bars
for bar in bars:
    width = bar.get_width()
    plt.text(width + 5, bar.get_y() + bar.get_height()/2, 
             f'{int(width)}', ha='left', va='center', color='#00D4FF')

plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'suspicious_endpoints.png'), dpi=300, bbox_inches='tight',
            facecolor='#2C3E50', edgecolor='none')
plt.close()

# 5. Browser and device analysis
print("Analyzing browser and device patterns...")
fig, axes = plt.subplots(2, 2, figsize=(16, 12))
fig.suptitle('Browser and Device Analysis', fontsize=20, color='#00D4FF')

# Browser distribution
browser_cols = ['is_chrome', 'is_firefox', 'is_safari', 'is_edge', 'is_ie']
browser_counts = df[browser_cols].sum().sort_values(ascending=True)
browser_names = [col.replace('is_', '').title() for col in browser_counts.index]
axes[0,0].barh(browser_names, browser_counts.values, color=cyber_colors[0])
axes[0,0].set_title('Browser Distribution', color='#00D4FF', fontsize=14)
axes[0,0].set_xlabel('Number of Requests')

# Device type distribution
device_cols = ['is_mobile', 'is_windows', 'is_mac', 'is_linux']
device_counts = df[device_cols].sum().sort_values(ascending=True)
device_names = [col.replace('is_', '').title() for col in device_counts.index]
axes[0,1].barh(device_names, device_counts.values, color=cyber_colors[1])
axes[0,1].set_title('Device Type Distribution', color='#00D4FF', fontsize=14)
axes[0,1].set_xlabel('Number of Requests')

# Automated vs legitimate traffic
automated = df['is_automated'].sum()
bot = df['is_bot'].sum()
total_non_human = automated + bot
human = len(df) - total_non_human
axes[1,0].pie([total_non_human, human], labels=['Automated/Bot', 'Potentially Human'], 
              autopct='%1.1f%%', colors=[cyber_colors[2], cyber_colors[3]], startangle=90)
axes[1,0].set_title('Traffic Type Distribution', color='#00D4FF', fontsize=14)

# IPv4 vs IPv6 usage
ipv6 = df['is_ipv6'].sum()
ipv4 = len(df) - ipv6
axes[1,1].pie([ipv4, ipv6], labels=['IPv4', 'IPv6'], 
              autopct='%1.1f%%', colors=[cyber_colors[4], cyber_colors[5]], startangle=90)
axes[1,1].set_title('IP Version Distribution', color='#00D4FF', fontsize=14)

plt.tight_layout(rect=[0, 0.03, 1, 0.95])
plt.savefig(os.path.join(output_dir, 'browser_device_analysis.png'), dpi=300, bbox_inches='tight',
            facecolor='#2C3E50', edgecolor='none')
plt.close()

# 6. 🚀 NEXT-LEVEL STEP: Feature Distribution by Target
print("Analyzing feature distributions by target action...")
plt.figure(figsize=(14, 8))
sns.violinplot(data=df, x='Action taken', y='ip_request_count', palette=cyber_colors)
plt.yscale('log') # Use a log scale due to high variance in request counts
plt.title('IP Request Count Distribution by Security Action', color='#00D4FF', fontsize=16)
plt.xlabel('Security Action Taken')
plt.ylabel('Requests per IP (Log Scale)')
plt.tight_layout()
plt.savefig(os.path.join(output_dir, 'feature_distribution_by_target.png'), dpi=300, bbox_inches='tight',
            facecolor='#2C3E50', edgecolor='none')
plt.close()


# 7. 🚀 NEXT-LEVEL STEP: Hypothesis Testing
print("\n" + "="*50)
print("HYPOTHESIS TEST")
print("="*50)
print("Hypothesis: Automated traffic is responsible for the majority of requests targeting suspicious endpoints.")

# Isolate suspicious requests
suspicious_df = df[df['suspicious_keywords'] > 0]
total_suspicious_requests = len(suspicious_df)

if total_suspicious_requests > 0:
    # Count how many of those are automated
    automated_suspicious_requests = suspicious_df['is_automated'].sum()
    
    # Calculate percentage
    percentage = (automated_suspicious_requests / total_suspicious_requests) * 100
    
    print(f"\nTotal requests targeting suspicious endpoints: {total_suspicious_requests}")
    print(f"Suspicious requests from automated tools: {automated_suspicious_requests}")
    print(f"Percentage: {percentage:.2f}%")
    
    print("\nCONCLUSION:")
    if percentage > 50:
        print("The hypothesis is STRONGLY SUPPORTED. The vast majority of probes to sensitive endpoints are from automated scripts.")
    else:
        print("The hypothesis is NOT SUPPORTED. A significant amount of suspicious traffic is not flagged as automated.")
else:
    print("\nNo requests with suspicious keywords were found in the dataset.")

print("\n" + "="*50)


print("\nAll EDA visualizations created successfully!")
print("Files saved in 'eda_visualizations' folder:")
print("- eda_overview.png")
print("- threat_timeline.html") 
print("- threat_map.html")
print("- correlation_matrix.png")
print("- suspicious_endpoints.png")
print("- browser_device_analysis.png")
print("- feature_distribution_by_target.png")