
# import streamlit as st
# import pandas as pd
# import joblib
# import numpy as np
# from sklearn.ensemble import RandomForestClassifier
# from sklearn.model_selection import train_test_split
# from sklearn.preprocessing import StandardScaler

# # Load your dataset here
# def load_model():
#     return joblib.load('best_model_pipeline.joblib')
# # For this example, we'll create a dummy dataset
# def create_dummy_dataset():
#     np.random.seed(42)
#     n_samples = 1000
#     features = ['ratio_digits_host', 'web_traffic', 'links_in_tags', 'nb_slash', 'length_url', 
#                 'ratio_extHyperlinks', 'longest_word_path', 'length_words_raw', 'page_rank', 
#                 'length_hostname', 'domain_in_title', 'nb_www', 'ratio_extRedirection', 
#                 'domain_registration_length', 'google_index', 'shortest_word_host', 'phish_hints', 
#                 'nb_dots', 'avg_word_host', 'nb_hyperlinks', 'ratio_intHyperlinks', 
#                 'shortest_word_path', 'ratio_digits_url', 'safe_anchor', 'avg_words_raw', 
#                 'nb_hyphens', 'char_repeat', 'domain_age', 'avg_word_path', 'longest_words_raw']
    
#     X = np.random.rand(n_samples, len(features))
#     y = np.random.randint(2, size=n_samples)
    
#     return pd.DataFrame(X, columns=features), pd.Series(y)

# # Train the model
# def train_model(X, y):
#     X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
#     scaler = StandardScaler()
#     X_train_scaled = scaler.fit_transform(X_train)
    
#     model = RandomForestClassifier(n_estimators=100, random_state=42)
#     model.fit(X_train_scaled, y_train)
    
#     return model, scaler

# # Make prediction
# def predict(model, scaler, input_data):
#     input_scaled = scaler.transform(input_data)
#     prediction = model.predict(input_scaled)
#     probability = model.predict_proba(input_scaled)
#     return prediction[0], probability[0][1]

# # Streamlit app
# def main():
#     st.title("Website Phishing Detection")
    
#     # Load and train the model
#     X, y = create_dummy_dataset()
#     model, scaler = train_model(X, y)
    
#     # Create input fields for features
#     st.header("Enter Website Features:")
    
#     feature_inputs = {}
#     for feature in X.columns:
#         feature_inputs[feature] = st.number_input(f"Enter {feature}", value=0.0, format="%.2f")
    
#     if st.button("Check Website"):
#         input_data = pd.DataFrame([feature_inputs])
#         prediction, probability = predict(model, scaler, input_data)
        
#         st.header("Result:")
#         if prediction == 1:
#             st.error(f"The website is likely MALICIOUS (Probability: {probability:.2f})")
#         else:
#             st.success(f"The website is likely LEGITIMATE (Probability: {1-probability:.2f})")
        
#         st.write("Note: This is a simplified model and should not be used as the sole method for determining website legitimacy.")

# if __name__ == "__main__":
#     main()








import streamlit as st
import pandas as pd
import numpy as np
import joblib
import re
from urllib.parse import urlparse
import tldextract
import requests
from bs4 import BeautifulSoup
import whois
from datetime import datetime
import itertools

# Load the pre-trained model pipeline
model_pipeline = joblib.load('best_model_pipeline.joblib')

def extract_features(url):
    features = {}
    parsed_url = urlparse(url)
    domain = tldextract.extract(url).domain + '.' + tldextract.extract(url).suffix

    # 1. ratio_digits_host
    features['ratio_digits_host'] = sum(c.isdigit() for c in parsed_url.netloc) / len(parsed_url.netloc) if len(parsed_url.netloc) > 0 else 0

    # 2. web_traffic (simplified version)
    try:
        response = requests.get(f"http://data.alexa.com/data?cli=10&dat=snbamz&url={domain}")
        features['web_traffic'] = int(re.search(r"<REACH[^>]*RANK=\"(\d+)\"", response.text).group(1))
    except:
        features['web_traffic'] = 0

    # 3. links_in_tags
    # 4. nb_slash
    features['nb_slash'] = url.count('/')

    # 5. length_url
    features['length_url'] = len(url)

    # 6. ratio_extHyperlinks
    # 7. longest_word_path
    path_words = re.findall(r'\w+', parsed_url.path)
    features['longest_word_path'] = len(max(path_words, key=len, default=''))

    # 8. length_words_raw
    # 9. page_rank (simplified)
    features['page_rank'] = features['web_traffic']

    # 10. length_hostname
    features['length_hostname'] = len(parsed_url.netloc)

    # 11. domain_in_title
    # 12. nb_www
    features['nb_www'] = url.count('www')

    # 13. ratio_extRedirection
    # 14. domain_registration_length
    try:
        domain_info = whois.whois(domain)
        if domain_info.creation_date:
            creation_date = domain_info.creation_date[0] if isinstance(domain_info.creation_date, list) else domain_info.creation_date
            features['domain_registration_length'] = (datetime.now() - creation_date).days
        else:
            features['domain_registration_length'] = 0
    except:
        features['domain_registration_length'] = 0

    # 15. google_index (simplified)
    features['google_index'] = 1  # Assume indexed by default

    # 16. shortest_word_host
    host_words = re.findall(r'\w+', parsed_url.netloc)
    features['shortest_word_host'] = len(min(host_words, key=len, default=''))

    # 17. phish_hints
    phish_words = ['login', 'signin', 'verify', 'bank', 'account', 'update', 'security', 'password']
    features['phish_hints'] = sum(1 for word in phish_words if word in url.lower())

    # 18. nb_dots
    features['nb_dots'] = url.count('.')

    # 19. avg_word_host
    features['avg_word_host'] = sum(len(word) for word in host_words) / len(host_words) if host_words else 0

    # 20. nb_hyperlinks
    # 21. ratio_intHyperlinks
    # 22. shortest_word_path
    features['shortest_word_path'] = len(min(path_words, key=len, default=''))

    # 23. ratio_digits_url
    features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url)

    # 24. safe_anchor
    # 25. avg_words_raw
    # 26. nb_hyphens
    features['nb_hyphens'] = url.count('-')

    # 27. char_repeat
    features['char_repeat'] = max(len(list(group)) for _, group in itertools.groupby(url))

    # 28. domain_age
    features['domain_age'] = features['domain_registration_length']

    # 29. avg_word_path
    features['avg_word_path'] = sum(len(word) for word in path_words) / len(path_words) if path_words else 0

    # 30. longest_words_raw
    
    # Try to fetch and parse the webpage content for remaining features
    try:
        response = requests.get(url, timeout=5)
        soup = BeautifulSoup(response.content, 'html.parser')
        
        features['links_in_tags'] = len(soup.find_all('a', href=True))
        
        external_links = sum(1 for link in soup.find_all('a', href=True) if tldextract.extract(link['href']).domain != domain)
        features['ratio_extHyperlinks'] = external_links / features['links_in_tags'] if features['links_in_tags'] > 0 else 0
        
        features['length_words_raw'] = len(soup.get_text())
        
        title = soup.title.string if soup.title else ''
        features['domain_in_title'] = int(domain.lower() in title.lower()) if title else 0
        
        features['ratio_extRedirection'] = features['ratio_extHyperlinks']  # Simplification
        
        features['nb_hyperlinks'] = features['links_in_tags']
        
        features['ratio_intHyperlinks'] = 1 - features['ratio_extHyperlinks']
        
        features['safe_anchor'] = 1  # Assume safe by default
        
        words = soup.get_text().split()
        features['avg_words_raw'] = sum(len(word) for word in words) / len(words) if words else 0
        
        features['longest_words_raw'] = len(max(words, key=len, default=''))
        
    except Exception as e:
        st.warning(f"Could not fetch webpage content. Some features may be inaccurate. Error: {str(e)}")
        # Set default values for features that rely on webpage content
        for feature in ['links_in_tags', 'ratio_extHyperlinks', 'length_words_raw', 'domain_in_title', 
                        'ratio_extRedirection', 'nb_hyperlinks', 'ratio_intHyperlinks', 'safe_anchor', 
                        'avg_words_raw', 'longest_words_raw']:
            features[feature] = 0

    return features

def predict_phishing(url):
    # Extract features from the URL
    features = extract_features(url)
    
    # Create a DataFrame with the features
    df = pd.DataFrame([features])
    
    # Make prediction using the pipeline
    prediction = model_pipeline.predict(df)
    probability = model_pipeline.predict_proba(df)
    
    return prediction[0], probability[0]

def main():
    st.title("URL Phishing Detection")
    
    st.header("Enter Website URL:")
    url = st.text_input("URL")
    
    if st.button("Check Website"):
        if url:
            try:
                prediction, probability = predict_phishing(url)
                
                st.header("Result:")
                if prediction == 1:
                    st.error(f"The website is likely MALICIOUS (Probability: {probability[1]:.2f})")
                else:
                    st.success(f"The website appears to be LEGITIMATE (Probability: {probability[0]:.2f})")
                
                st.write("Note: While this prediction is based on a machine learning model, it should not be used as the sole method for determining website legitimacy.")
                
                st.subheader("Extracted Features:")
                features = extract_features(url)
                st.write(features)
                
                # If your model pipeline has feature importances (e.g., if it's a tree-based model)
                if hasattr(model_pipeline.named_steps['classifier'], 'feature_importances_'):
                    st.subheader("Feature Importance:")
                    feature_importance = pd.DataFrame({
                        'feature': features.keys(),
                        'importance': model_pipeline.named_steps['classifier'].feature_importances_
                    }).sort_values('importance', ascending=False)
                    st.bar_chart(feature_importance.set_index('feature'))
                
            except Exception as e:
                st.error(f"An error occurred: {str(e)}")
        else:
            st.warning("Please enter a URL.")

if __name__ == "__main__":
    main()