# import streamlit as st
# import joblib
# import pandas as pd
# import numpy as np
# from urllib.parse import urlparse
# import requests
# import re
# from datetime import datetime
# import whois

# # Load the trained model
# model = joblib.load('best_modelLGBM_pipeline.joblib')

# # Feature extraction functions
# def extract_features(url):
#     features = {}
    
#     # Basic URL features
#     features['length_url'] = len(url)
#     parsed_url = urlparse(url)
#     features['length_hostname'] = len(parsed_url.netloc)
    
#     # IP address
#     features['ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.netloc) else 0
    
#     # Counting features
#     features['nb_dots'] = url.count('.')
#     features['nb_qm'] = url.count('?')
#     features['nb_eq'] = url.count('=')
#     features['nb_slash'] = url.count('/')
#     features['nb_www'] = url.lower().count('www')
    
#     # Ratio features
#     features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url)
#     features['ratio_digits_host'] = sum(c.isdigit() for c in parsed_url.netloc) / len(parsed_url.netloc)
    
#     # TLD and domain features
#     features['tld_in_subdomain'] = 1 if parsed_url.netloc.count('.') > 1 else 0
#     features['prefix_suffix'] = 1 if '-' in parsed_url.netloc else 0
    
#     # Word-based features
#     words_raw = re.findall(r'\w+', url.lower())
#     features['length_words_raw'] = len(words_raw)
#     features['shortest_word_host'] = min(len(word) for word in re.findall(r'\w+', parsed_url.netloc.lower()))
#     features['longest_words_raw'] = max(len(word) for word in words_raw)
#     features['longest_word_path'] = max(len(word) for word in re.findall(r'\w+', parsed_url.path.lower())) if parsed_url.path else 0
#     features['avg_word_host'] = sum(len(word) for word in re.findall(r'\w+', parsed_url.netloc.lower())) / len(re.findall(r'\w+', parsed_url.netloc.lower()))
#     features['avg_word_path'] = sum(len(word) for word in re.findall(r'\w+', parsed_url.path.lower())) / len(re.findall(r'\w+', parsed_url.path.lower())) if parsed_url.path else 0
    
#     # Placeholder for more complex features
#     # You'll need to implement these based on your original feature extraction logic
#     features['phish_hints'] = 0  # Placeholder
#     features['nb_hyperlinks'] = 0  # Placeholder
#     features['ratio_intHyperlinks'] = 0  # Placeholder
#     features['links_in_tags'] = 0  # Placeholder
#     features['ratio_intMedia'] = 0  # Placeholder
#     features['safe_anchor'] = 0  # Placeholder
#     features['empty_title'] = 0  # Placeholder
#     features['domain_in_title'] = 0  # Placeholder
#     features['domain_with_copyright'] = 0  # Placeholder
    
#     # Domain age (simplified)
#     try:
#         domain_info = whois.whois(parsed_url.netloc)
#         creation_date = domain_info.creation_date
#         if isinstance(creation_date, list):
#             creation_date = creation_date[0]
#         features['domain_age'] = (datetime.now() - creation_date).days
#     except:
#         features['domain_age'] = -1  # Unable to determine
    
#     # Google index and page rank (simplified)
#     features['google_index'] = 1  # Placeholder
#     features['page_rank'] = 0  # Placeholder
    
#     return features

# # Streamlit app
# st.title('Website Legitimacy Checker')

# url = st.text_input('Enter a website URL:')

# if url:
#     # Extract features
#     features = extract_features(url)
    
#     # Create a DataFrame with the extracted features
#     df = pd.DataFrame([features])
    
#     # Ensure the DataFrame has all required features in the correct order
#     required_features = ['length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_qm', 'nb_eq',
#                          'nb_slash', 'nb_www', 'ratio_digits_url', 'ratio_digits_host',
#                          'tld_in_subdomain', 'prefix_suffix', 'length_words_raw',
#                          'shortest_word_host', 'longest_words_raw', 'longest_word_path',
#                          'avg_word_host', 'avg_word_path', 'phish_hints', 'nb_hyperlinks',
#                          'ratio_intHyperlinks', 'links_in_tags', 'ratio_intMedia', 'safe_anchor',
#                          'empty_title', 'domain_in_title', 'domain_with_copyright', 'domain_age',
#                          'google_index', 'page_rank']
    
#     for feature in required_features:
#         if feature not in df.columns:
#             df[feature] = 0  # Add missing features with a default value
    
#     df = df[required_features]  # Reorder columns to match the model's expected input
    
#     # Make prediction
#     prediction = model.predict(df)
#     probability = model.predict_proba(df)
    
#     # Display result
#     if prediction[0] == 1:
#         st.error('This website may be fraudulent.')
#         st.write(f'Probability of being fraudulent: {probability[0][1]:.2%}')
#     else:
#         st.success('This website appears to be legitimate.')
#         st.write(f'Probability of being legitimate: {probability[0][0]:.2%}')
    
#     # Display extracted features
#     st.subheader('Extracted Features:')
#     st.write(df)

# st.write('Note: This is a basic implementation and may not catch all fraudulent websites. Always exercise caution when browsing.')


import streamlit as st
import joblib
import pandas as pd
import numpy as np
from urllib.parse import urlparse
import requests
import re
from datetime import datetime
import whois
from bs4 import BeautifulSoup

# Load the trained model
model = joblib.load('best_modelLGBM_pipeline.joblib')

# Feature extraction functions
def extract_features(url):
    features = {}
    
    # Basic URL features
    features['length_url'] = len(url)
    parsed_url = urlparse(url)
    features['length_hostname'] = len(parsed_url.netloc)
    
    # IP address detection
    features['ip'] = 1 if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", parsed_url.netloc) else 0
    
    # Counting features
    features['nb_dots'] = url.count('.')
    features['nb_qm'] = url.count('?')
    features['nb_eq'] = url.count('=')
    features['nb_slash'] = url.count('/')
    features['nb_www'] = url.lower().count('www')
    
    # Ratio of digits in URL and hostname
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
    
    # Phishing hint detection
    features['phish_hints'] = detect_phish_hints(url)
    
    # Hyperlink features
    html_content = fetch_html(url)
    features['nb_hyperlinks'], features['ratio_intHyperlinks'], features['links_in_tags'] = count_hyperlinks(html_content, parsed_url.netloc)
    
    # Media and anchor features
    features['ratio_intMedia'], features['safe_anchor'] = compute_media_and_anchor(html_content, parsed_url.netloc)
    
    # Title features
    features['empty_title'], features['domain_in_title'] = detect_title_features(html_content, parsed_url.netloc)
    
    # Copyright check
    features['domain_with_copyright'] = detect_copyright_in_domain(html_content)
    
    # Domain age (using WHOIS data)
    try:
        domain_info = whois.whois(parsed_url.netloc)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        features['domain_age'] = (datetime.now() - creation_date).days
    except:
        features['domain_age'] = -1  # Unable to determine domain age
    
    # Google index and page rank (placeholder logic)
    features['google_index'] = check_google_index(url)
    features['page_rank'] = compute_page_rank(url)
    
    return features

# Helper functions

def detect_phish_hints(url):
    # Check for common phishing keywords
    phishing_keywords = ['login', 'signin', 'bank', 'secure', 'account', 'update', 'verify']
    return 1 if any(keyword in url.lower() for keyword in phishing_keywords) else 0

def fetch_html(url):
    # Fetch HTML content from the URL
    try:
        response = requests.get(url, timeout=5)
        if response.status_code == 200:
            return response.text
    except requests.RequestException:
        return ""
    return ""

def count_hyperlinks(html, domain):
    # Parse the HTML content and count hyperlinks
    if html:
        soup = BeautifulSoup(html, 'html.parser')
        all_links = soup.find_all('a')
        nb_hyperlinks = len(all_links)
        int_links = 0
        links_in_tags = 0
        
        for link in all_links:
            href = link.get('href', '')
            if href.startswith('/') or domain in href:
                int_links += 1
            if link.parent.name in ['div', 'span', 'p']:
                links_in_tags += 1
        
        ratio_intHyperlinks = int_links / nb_hyperlinks if nb_hyperlinks > 0 else 0
        return nb_hyperlinks, ratio_intHyperlinks, links_in_tags
    return 0, 0, 0

def compute_media_and_anchor(html, domain):
    # Parse HTML for media and anchor tag analysis
    if html:
        soup = BeautifulSoup(html, 'html.parser')
        
        # Media links (e.g., images, videos)
        media_links = soup.find_all(['img', 'video', 'source'])
        int_media = sum(1 for media in media_links if domain in media.get('src', ''))
        ratio_intMedia = int_media / len(media_links) if media_links else 0
        
        # Safe anchors
        anchors = soup.find_all('a')
        safe_anchors = sum(1 for anchor in anchors if anchor.get('href', '#') != '#')
        safe_anchor_ratio = safe_anchors / len(anchors) if anchors else 0
        
        return ratio_intMedia, safe_anchor_ratio
    return 0, 0

def detect_title_features(html, domain):
    # Check if the title tag is empty and if the domain appears in the title
    if html:
        soup = BeautifulSoup(html, 'html.parser')
        title = soup.find('title')
        if title:
            title_text = title.text.strip()
            empty_title = 0 if title_text else 1
            domain_in_title = 1 if domain.lower() in title_text.lower() else 0
            return empty_title, domain_in_title
    return 1, 0

def detect_copyright_in_domain(html):
    # Check if the domain has copyright symbols in the content
    if html:
        return 1 if '©' in html or 'copyright' in html.lower() else 0
    return 0

def check_google_index(url):
    # Placeholder logic for checking Google index (could use an API or search engine)
    # This function should ideally check if the site is indexed by Google
    return 1  # Assume indexed for now

def compute_page_rank(url):
    # Placeholder logic for page rank calculation
    return 0  # Placeholder

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

st.write('Note: This is a basic implementation and may not catch all fraudulent websites. Always use caution when browsing online.')
