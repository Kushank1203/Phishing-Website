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
import tldextract
import ssl
import socket
from urllib.request import urlopen

# Load the trained model
@st.cache_resource
def load_model():
    return joblib.load('best_modelLGBM_pipeline.joblib')

model = load_model()

def get_domain(url):
    return tldextract.extract(url).domain + '.' + tldextract.extract(url).suffix

def is_ip_address(url):
    try:
        socket.inet_aton(urlparse(url).netloc)
        return 1
    except socket.error:
        return 0

def extract_features(url):
    features = {}
    parsed_url = urlparse(url)
    domain = get_domain(url)
    
    # 1. length_url
    features['length_url'] = len(url)
    
    # 2. length_hostname
    features['length_hostname'] = len(parsed_url.netloc)
    
    # 3. ip
    features['ip'] = is_ip_address(url)
    
    # 4. nb_dots
    features['nb_dots'] = url.count('.')
    
    # 5. nb_qm
    features['nb_qm'] = url.count('?')
    
    # 6. nb_eq
    features['nb_eq'] = url.count('=')
    
    # 7. nb_slash
    features['nb_slash'] = url.count('/')
    
    # 8. nb_www
    features['nb_www'] = url.lower().count('www')
    
    # 9. ratio_digits_url
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
    
    # 10. ratio_digits_host
    features['ratio_digits_host'] = sum(c.isdigit() for c in parsed_url.netloc) / len(parsed_url.netloc) if len(parsed_url.netloc) > 0 else 0
    
    # 11. tld_in_subdomain
    features['tld_in_subdomain'] = 1 if tldextract.extract(parsed_url.netloc).suffix in tldextract.extract(parsed_url.netloc).subdomain else 0
    
    # 12. prefix_suffix
    features['prefix_suffix'] = 1 if '-' in parsed_url.netloc else 0
    
    # 13. length_words_raw
    words_raw = re.findall(r'\w+', url.lower())
    features['length_words_raw'] = len(words_raw)
    
    # 14. shortest_word_host
    host_words = re.findall(r'\w+', parsed_url.netloc.lower())
    features['shortest_word_host'] = min(len(word) for word in host_words) if host_words else 0
    
    # 15. longest_words_raw
    features['longest_words_raw'] = max(len(word) for word in words_raw) if words_raw else 0
    
    # 16. longest_word_path
    path_words = re.findall(r'\w+', parsed_url.path.lower())
    features['longest_word_path'] = max(len(word) for word in path_words) if path_words else 0
    
    # 17. avg_word_host
    features['avg_word_host'] = sum(len(word) for word in host_words) / len(host_words) if host_words else 0
    
    # 18. avg_word_path
    features['avg_word_path'] = sum(len(word) for word in path_words) / len(path_words) if path_words else 0
    
    # Fetch webpage content
    try:
        response = requests.get(url, timeout=5, verify=False)
        soup = BeautifulSoup(response.content, 'html.parser')
    except:
        soup = None

    # 19. phish_hints
    phish_words = ['secure', 'account', 'webscr', 'login', 'ebayisapi', 'signin', 'banking', 'confirm']
    features['phish_hints'] = sum(word in url.lower() for word in phish_words)
    
    if soup:
        # 20. nb_hyperlinks
        hyperlinks = soup.find_all('a', href=True)
        features['nb_hyperlinks'] = len(hyperlinks)
        
        # 21. ratio_intHyperlinks
        internal_links = sum(get_domain(link['href']) == domain for link in hyperlinks if link['href'].startswith('http'))
        features['ratio_intHyperlinks'] = internal_links / features['nb_hyperlinks'] if features['nb_hyperlinks'] > 0 else 0
        
        # 22. links_in_tags
        features['links_in_tags'] = sum(link.parent.name in ['meta', 'script', 'link'] for link in hyperlinks)
        
        # 23. ratio_intMedia
        media_links = soup.find_all(['img', 'audio', 'video', 'source'], src=True)
        internal_media = sum(get_domain(media['src']) == domain for media in media_links if media['src'].startswith('http'))
        features['ratio_intMedia'] = internal_media / len(media_links) if len(media_links) > 0 else 0
        
        # 24. safe_anchor
        features['safe_anchor'] = 0 if soup.find('a', href='#') else 1
        
        # 25. empty_title
        features['empty_title'] = 1 if not soup.title or not soup.title.string.strip() else 0
        
        # 26. domain_in_title
        features['domain_in_title'] = 1 if soup.title and domain.lower() in soup.title.string.lower() else 0
        
        # 27. domain_with_copyright
        features['domain_with_copyright'] = 1 if soup.find(text=re.compile(r'©.*' + re.escape(domain), re.IGNORECASE)) else 0
    else:
        features['nb_hyperlinks'] = features['ratio_intHyperlinks'] = features['links_in_tags'] = 0
        features['ratio_intMedia'] = features['safe_anchor'] = features['empty_title'] = 0
        features['domain_in_title'] = features['domain_with_copyright'] = 0
    
    # 28. domain_age
    try:
        domain_info = whois.whois(domain)
        creation_date = domain_info.creation_date
        if isinstance(creation_date, list):
            creation_date = creation_date[0]
        features['domain_age'] = (datetime.now() - creation_date).days
    except:
        features['domain_age'] = -1  # Unable to determine
    
    # 29. google_index
    try:
        query = f"site:{domain}"
        url = f"https://www.google.com/search?q={query}"
        response = requests.get(url, headers={'User-Agent': 'Mozilla/5.0'})
        features['google_index'] = 1 if "did not match any documents" not in response.text else 0
    except:
        features['google_index'] = -1  # Unable to determine
    
    # 30. page_rank (Note: Actual PageRank requires access to Google's API, which is not freely available)
    # For this example, we'll use a simplified heuristic based on HTTPS and domain age
    features['page_rank'] = 1 if parsed_url.scheme == 'https' and features['domain_age'] > 365 else 0
    
    return features

# Streamlit app
st.title('Website Legitimacy Checker')

url = st.text_input('Enter a website URL:')

if url:
    with st.spinner('Analyzing the website...'):
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
        if prediction[0] == 0:  # Assuming 0 is legitimate and 1 is fraudulent
            st.success('This website appears to be legitimate.')
            st.write(f'Probability of being legitimate: {probability[0][0]:.2%}')
        else:
            st.error('This website may be fraudulent.')
            st.write(f'Probability of being fraudulent: {probability[0][1]:.2%}')
        
        # Display extracted features
        st.subheader('Extracted Features:')
        st.write(df)

        # Display feature importances
        if hasattr(model, 'feature_importances_'):
            st.subheader('Feature Importances:')
            importances = model.feature_importances_
            feature_imp = pd.DataFrame({'feature': required_features, 'importance': importances})
            feature_imp = feature_imp.sort_values('importance', ascending=False)
            st.bar_chart(feature_imp.set_index('feature')['importance'])

st.write('Note: This tool provides an estimate based on the available information. Always exercise caution when browsing unfamiliar websites.')