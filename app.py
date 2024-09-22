import streamlit as st
import pandas as pd
import numpy as np
import joblib
from urllib.parse import urlparse
import re
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import socket
import ssl
import tldextract

# Load the trained model
model = joblib.load('optimized_lgbm_model.joblib')

def extract_features(url):
    features = {}
    
    # URL parsing
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    path = parsed_url.path
    
    # 1. length_url
    features['length_url'] = len(url)
    
    # 2. length_hostname
    features['length_hostname'] = len(domain)
    
    # 3. ip
    features['ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", domain) else 0
    
    # 4. nb_dots
    features['nb_dots'] = url.count('.')
    
    # 5. nb_qm
    features['nb_qm'] = url.count('?')
    
    # 6. nb_eq
    features['nb_eq'] = url.count('=')
    
    # 7. nb_slash
    features['nb_slash'] = url.count('/')
    
    # 8. nb_www
    features['nb_www'] = 1 if 'www' in domain else 0
    
    # 9. ratio_digits_url
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url)
    
    # 10. ratio_digits_host
    features['ratio_digits_host'] = sum(c.isdigit() for c in domain) / len(domain) if len(domain) > 0 else 0
    
    # 11. tld_in_subdomain
    tld = tldextract.extract(url).suffix
    features['tld_in_subdomain'] = 1 if tld in domain.split('.')[:-1] else 0
    
    # 12. prefix_suffix
    features['prefix_suffix'] = 1 if '-' in domain else 0
    
    # 13, 15, 16, 17, 18. Word-based features
    words_raw = re.findall(r'\w+', url)
    words_host = re.findall(r'\w+', domain)
    words_path = re.findall(r'\w+', path)
    
    features['length_words_raw'] = len(words_raw)
    features['shortest_word_host'] = min(len(word) for word in words_host) if words_host else 0
    features['longest_words_raw'] = max(len(word) for word in words_raw) if words_raw else 0
    features['longest_word_path'] = max(len(word) for word in words_path) if words_path else 0
    features['avg_word_host'] = sum(len(word) for word in words_host) / len(words_host) if words_host else 0
    features['avg_word_path'] = sum(len(word) for word in words_path) / len(words_path) if words_path else 0
    
    # Content-based features
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        # 19. phish_hints
        phish_words = ['login', 'signin', 'verify', 'bank', 'account', 'update', 'confirm']
        features['phish_hints'] = sum(1 for word in phish_words if word in url.lower() or word in str(soup).lower())
        
        # 20, 21, 22, 23. Link-based features
        all_links = soup.find_all('a', href=True)
        internal_links = sum(1 for link in all_links if urlparse(link['href']).netloc == '' or urlparse(link['href']).netloc == domain)
        features['nb_hyperlinks'] = len(all_links)
        features['ratio_intHyperlinks'] = internal_links / len(all_links) if len(all_links) > 0 else 0
        features['links_in_tags'] = sum(1 for link in all_links if link.parent.name in ['meta', 'script', 'link', 'iframe'])
        media_links = soup.find_all(['audio', 'video', 'source', 'img'])
        internal_media = sum(1 for media in media_links if urlparse(media.get('src', '')).netloc == '' or urlparse(media.get('src', '')).netloc == domain)
        features['ratio_intMedia'] = internal_media / len(media_links) if len(media_links) > 0 else 0
        
        # 24. safe_anchor
        features['safe_anchor'] = 0 if soup.find('a', text='#') else 1
        
        # 25, 26. Title-based features
        title = soup.title.string if soup.title else ''
        features['empty_title'] = 1 if not title else 0
        features['domain_in_title'] = 1 if domain.lower() in title.lower() else 0
        
        # 27. domain_with_copyright
        features['domain_with_copyright'] = 1 if re.search(r'©.*' + re.escape(domain), str(soup)) else 0
        
    except:
        features['phish_hints'] = -1
        features['nb_hyperlinks'] = -1
        features['ratio_intHyperlinks'] = -1
        features['links_in_tags'] = -1
        features['ratio_intMedia'] = -1
        features['safe_anchor'] = -1
        features['empty_title'] = -1
        features['domain_in_title'] = -1
        features['domain_with_copyright'] = -1
    
    # 28. domain_age
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        features['domain_age'] = (datetime.now() - creation_date).days
    except:
        features['domain_age'] = -1
    
    # 29, 30. Google index and Page Rank
    # Note: These features typically require access to Google's API or third-party services.
    # For this example, we'll use placeholder values. In a real-world scenario, you'd need to
    # implement proper checks for these features.
    features['google_index'] = -1  # Placeholder
    features['page_rank'] = -1  # Placeholder
    
    return features

def preprocess_input(url):
    features = extract_features(url)
    df = pd.DataFrame([features])
    return df

# Streamlit app
st.title('Phishing Website Detection')

url = st.text_input('Enter the website URL:')

if st.button('Check Website'):
    if url:
        # Preprocess the input
        input_df = preprocess_input(url)
        
        # Make prediction
        prediction = model.predict(input_df)[0]
        probability = model.predict_proba(input_df)[0][1]  # Probability of being fraudulent
        
        # Display result
        if prediction == 1:
            st.error(f'This website is likely fraudulent (Confidence: {probability:.2f})')
        else:
            st.success(f'This website appears to be legitimate (Confidence: {1-probability:.2f})')
        
        # Display feature values
        st.subheader('Feature Values:')
        st.write(input_df)
    else:
        st.warning('Please enter a URL')