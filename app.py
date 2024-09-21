import streamlit as st
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import requests
import re
from datetime import datetime
import whois

# Load the trained model
model = joblib.load('best_modelLGBM_pipeline.joblib')

# Feature extraction functions
def extract_features(url):
    features = {}
    
    # Basic URL features
    features['length_url'] = len(url)
    parsed_url = urlparse(url)
    features['length_hostname'] = len(parsed_url.netloc)
    
    # IP address
    features['ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.netloc) else 0
    
    # Counting features
    features['nb_dots'] = url.count('.')
    features['nb_qm'] = url.count('?')
    features['nb_eq'] = url.count('=')
    features['nb_slash'] = url.count('/')
    features['nb_www'] = url.lower().count('www')
    
    # Ratio features
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url)
    features['ratio_digits_host'] = sum(c.isdigit() for c in parsed_url.netloc) / len(parsed_url.netloc)
    
    # TLD and domain features
    features['tld_in_subdomain'] = 1 if parsed_url.netloc.count('.') > 1 else 0
    features['prefix_suffix'] = 1 if '-' in parsed_url.netloc else 0
    
    # Word-based features
    words_raw = re.findall(r'\w+', url.lower())
    features['length_words_raw'] = len(words_raw)
    features['shortest_word_host'] = min(len(word) for word in re.findall(r'\w+', parsed_url.netloc.lower()))
    features['longest_words_raw'] = max(len(word) for word in words_raw)
    features['longest_word_path'] = max(len(word) for word in re.findall(r'\w+', parsed_url.path.lower())) if parsed_url.path else 0
    features['avg_word_host'] = sum(len(word) for word in re.findall(r'\w+', parsed_url.netloc.lower())) / len(re.findall(r'\w+', parsed_url.netloc.lower()))
    features['avg_word_path'] = sum(len(word) for word in re.findall(r'\w+', parsed_url.path.lower())) / len(re.findall(r'\w+', parsed_url.path.lower())) if parsed_url.path else 0
    
    # Placeholder for more complex features
    # You'll need to implement these based on your original feature extraction logic
    features['phish_hints'] = 0  # Placeholder
    features['nb_hyperlinks'] = 0  # Placeholder
    features['ratio_intHyperlinks'] = 0  # Placeholder
    features['links_in_tags'] = 0  # Placeholder
    features['ratio_intMedia'] = 0  # Placeholder
    features['safe_anchor'] = 0  # Placeholder
    features['empty_title'] = 0  # Placeholder
    features['domain_in_title'] = 0  # Placeholder
    features['domain_with_copyright'] = 0  # Placeholder
    
    # Domain age (simplified)
    try:
        domain_info = whois.whois(parsed_url.netloc)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        features['domain_age'] = (datetime.now() - creation_date).days
    except:
        features['domain_age'] = -1  # Unable to determine
    
    # Google index and page rank (simplified)
    features['google_index'] = 1  # Placeholder
    features['page_rank'] = 0  # Placeholder
    
    return features

# Streamlit app
st.title('Website Legitimacy Checker')

url = st.text_input('Enter a website URL:')

if url:
    # Extract features
    features = extract_features(url)
    
    # Create a DataFrame with the extracted features
    df = pd.DataFrame([features])
    
    # Ensure the DataFrame has all required features in the correct order
    required_features = ['length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_qm', 'nb_eq',
                         'nb_slash', 'nb_www', 'ratio_digits_url', 'ratio_digits_host',
                         'tld_in_subdomain', 'prefix_suffix', 'length_words_raw',
                         'shortest_word_host', 'longest_words_raw', 'longest_word_path',
                         'avg_word_host', 'avg_word_path', 'phish_hints', 'nb_hyperlinks',
                         'ratio_intHyperlinks', 'links_in_tags', 'ratio_intMedia', 'safe_anchor',
                         'empty_title', 'domain_in_title', 'domain_with_copyright', 'domain_age',
                         'google_index', 'page_rank']
    
    for feature in required_features:
        if feature not in df.columns:
            df[feature] = 0  # Add missing features with a default value
    
    df = df[required_features]  # Reorder columns to match the model's expected input
    
    # Make prediction
    prediction = model.predict(df)
    probability = model.predict_proba(df)
    
    # Display result
    if prediction[0] == 1:
        st.error('This website may be fraudulent.')
        st.write(f'Probability of being fraudulent: {probability[0][1]:.2%}')
    else:
        st.success('This website appears to be legitimate.')
        st.write(f'Probability of being legitimate: {probability[0][0]:.2%}')
    
    # Display extracted features
    st.subheader('Extracted Features:')
    st.write(df)

st.write('Note: This is a basic implementation and may not catch all fraudulent websites. Always exercise caution when browsing.')