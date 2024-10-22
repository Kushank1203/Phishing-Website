import streamlit as st
import pandas as pd
import numpy as np
import re
from urllib.parse import urlparse
# import lightgbm as lgbm
import joblib
from tld import get_tld
import whois
from datetime import datetime
import requests
from bs4 import BeautifulSoup
import socket
import dns.resolver
import tldextract
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class FeatureAlignmentHandler:
    def __init__(self, model_path):
        """Initialize with model and get training features"""
        try:
            self.model = joblib.load(model_path)
            # Try to load features list if saved
            try:
                self.expected_features = joblib.load('model_features.joblib')
            except:
                # If features file not found, use a predefined list of expected features
                self.expected_features = self._get_default_features()
            st.info(f"Model loaded successfully. Expected features: {len(self.expected_features)}")
        except Exception as e:
            st.error(f"Error initializing model: {str(e)}")
            self.model = None
            self.expected_features = None

    def _get_default_features(self):
        """Get the default list of expected features"""
        # Add any additional features that might be missing in your current implementation
        return [

            'length_url', 'length_hostname', 'ip', 'nb_dots', 'nb_hyphens',
            'nb_at', 'nb_qm', 'nb_and', 'nb_or', 'nb_eq', 'nb_underscore',
            'nb_tilde', 'nb_percent', 'nb_slash', 'nb_star', 'nb_colon', 'nb_comma',
            'nb_semicolumn', 'nb_dollar', 'nb_space', 'nb_www', 'nb_com',
            'nb_dslash', 'http_in_path', 'https_token', 'ratio_digits_url',
            'ratio_digits_host', 'punycode', 'port', 'tld_in_path',
            'tld_in_subdomain', 'abnormal_subdomain', 'nb_subdomains',
            'prefix_suffix', 'random_domain', 'shortening_service',
            'path_extension', 'nb_redirection', 'nb_external_redirection',
            'length_words_raw', 'char_repeat', 'shortest_words_raw',
            'shortest_word_host', 'shortest_word_path', 'longest_words_raw',
            'longest_word_host', 'longest_word_path', 'avg_words_raw',
            'avg_word_host', 'avg_word_path', 'phish_hints', 'domain_in_brand',
            'brand_in_subdomain', 'brand_in_path', 'suspecious_tld',
            'statistical_report', 'nb_hyperlinks', 'ratio_intHyperlinks',
            'ratio_extHyperlinks', 'ratio_nullHyperlinks', 'nb_extCSS',
            'ratio_intRedirection', 'ratio_extRedirection', 'ratio_intErrors',
            'ratio_extErrors', 'login_form', 'external_favicon', 'links_in_tags',
            'submit_email', 'ratio_intMedia', 'ratio_extMedia', 'sfh', 'iframe',
            'popup_window', 'safe_anchor', 'onmouseover', 'right_clic',
            'empty_title', 'domain_in_title', 'domain_with_copyright',
            'whois_registered_domain', 'domain_registration_length', 'domain_age',
            'web_traffic', 'dns_record', 'google_index', 'page_rank'
        ]

    def align_features(self, features_dict):
        """Align input features with model's expected features"""
        # Convert dictionary to DataFrame
        df = pd.DataFrame([features_dict])
        
        if self.expected_features is not None:
            missing_features = set(self.expected_features) - set(df.columns)
            extra_features = set(df.columns) - set(self.expected_features)
            
            # Add missing columns with default values
            for feature in missing_features:
                df[feature] = 0
                st.warning(f"Missing feature '{feature}' was added with default value 0")
            
            # Remove extra columns
            if extra_features:
                df = df.drop(columns=list(extra_features))
                st.warning(f"Removed extra features: {extra_features}")
            
            # Reorder columns to match expected features
            df = df[self.expected_features]
            
            # Ensure all features are numeric
            for col in df.columns:
                df[col] = pd.to_numeric(df[col], errors='coerce').fillna(0)
        
        return df

    def predict(self, features_dict):
        """Align features and make prediction"""
        if self.model is None:
            st.error("Model not properly initialized")
            return None
            
        try:
            aligned_features = self.align_features(features_dict)
            return self.model.predict(aligned_features)[0]
        except Exception as e:
            st.error(f"Prediction error: {str(e)}")
            return None

def extract_features_from_url(url):
    features = {}
    
    try:
        # Parse URL
        parsed = urlparse(url)
        extract_res = tldextract.extract(url)
        domain = extract_res.domain + '.' + extract_res.suffix
        
        # Basic URL features
        features['length_url'] = len(url)
        features['length_hostname'] = len(parsed.netloc)
        
        # Check for IP
        features['ip'] = 1 if re.match(r'^(?:\d{1,3}\.){3}\d{1,3}$', parsed.netloc) else 0
        
        # Character counts
        features['nb_dots'] = url.count('.')
        features['nb_hyphens'] = url.count('-')
        features['nb_at'] = url.count('@')
        features['nb_qm'] = url.count('?')
        features['nb_and'] = url.count('&')
        features['nb_or'] = url.count('|')
        features['nb_eq'] = url.count('=')
        features['nb_underscore'] = url.count('_')
        features['nb_tilde'] = url.count('~')
        features['nb_percent'] = url.count('%')
        features['nb_slash'] = url.count('/')
        features['nb_star'] = url.count('*')
        features['nb_colon'] = url.count(':')
        features['nb_comma'] = url.count(',')
        features['nb_semicolumn'] = url.count(';')
        features['nb_dollar'] = url.count('$')
        features['nb_space'] = url.count(' ')
        features['nb_www'] = 1 if 'www' in parsed.netloc.lower() else 0
        features['nb_com'] = 1 if '.com' in url.lower() else 0
        features['nb_dslash'] = url.count('//')
        
        # URL token features
        features['http_in_path'] = 1 if 'http' in parsed.path.lower() else 0
        features['https_token'] = 1 if url.lower().startswith('https') else 0
        
        # Digit ratios
        features['ratio_digits_url'] = sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
        features['ratio_digits_host'] = sum(c.isdigit() for c in parsed.netloc) / len(parsed.netloc) if len(parsed.netloc) > 0 else 0
        
        # Punycode and port
        features['punycode'] = 1 if 'xn--' in parsed.netloc.lower() else 0
        features['port'] = 1 if parsed.port else 0
        
        # TLD analysis
        tld = extract_res.suffix
        features['tld_in_path'] = 1 if tld in parsed.path.lower() else 0
        features['tld_in_subdomain'] = 1 if tld in extract_res.subdomain.lower() else 0
        
        # Subdomain analysis
        features['abnormal_subdomain'] = 1 if extract_res.subdomain.count('.') > 2 else 0
        features['nb_subdomains'] = len(extract_res.subdomain.split('.')) if extract_res.subdomain else 0
        
        # Domain analysis
        features['prefix_suffix'] = 1 if '-' in extract_res.domain else 0
        features['random_domain'] = 1 if len(extract_res.domain) > 12 else 0
        
        # URL shortening services
        shortening_services = ['bit.ly', 'goo.gl', 't.co', 'tinyurl.com', 'is.gd']
        features['shortening_service'] = 1 if any(service in parsed.netloc.lower() for service in shortening_services) else 0
        
        # Path analysis
        features['path_extension'] = 1 if re.search(r'\.(html|php|asp|jsp|htm)$', parsed.path.lower()) else 0
        
        try:
            response = requests.get(url, timeout=5, verify=False)
            soup = BeautifulSoup(response.content, 'html.parser')
            
            # Hyperlink analysis
            all_links = soup.find_all('a')
            features['nb_hyperlinks'] = len(all_links)
            
            internal_links = sum(1 for link in all_links if link.get('href') and (domain in link.get('href') or link.get('href').startswith('/')))
            external_links = sum(1 for link in all_links if link.get('href') and not (domain in link.get('href') or link.get('href').startswith('/')))
            
            features['ratio_intHyperlinks'] = internal_links / len(all_links) if len(all_links) > 0 else 0
            features['ratio_extHyperlinks'] = external_links / len(all_links) if len(all_links) > 0 else 0
            features['ratio_nullHyperlinks'] = sum(1 for link in all_links if not link.get('href')) / len(all_links) if len(all_links) > 0 else 0
            
            # CSS and redirections
            features['nb_extCSS'] = len(soup.find_all('link', rel='stylesheet'))
            
            # Redirect analysis
            features['nb_redirection'] = len(response.history)
            features['nb_external_redirection'] = sum(1 for r in response.history if domain not in r.url)
            features['ratio_intRedirection'] = (features['nb_redirection'] - features['nb_external_redirection']) / features['nb_redirection'] if features['nb_redirection'] > 0 else 0
            features['ratio_extRedirection'] = features['nb_external_redirection'] / features['nb_redirection'] if features['nb_redirection'] > 0 else 0
            
            # Word analysis
            raw_words = re.findall(r'\w+', url)
            host_words = re.findall(r'\w+', parsed.netloc)
            path_words = re.findall(r'\w+', parsed.path) if parsed.path else []
            
            features['length_words_raw'] = len(raw_words)
            features['char_repeat'] = sum(1 for char in url if url.count(char) > 2)
            features['shortest_words_raw'] = min(len(word) for word in raw_words) if raw_words else 0
            features['shortest_word_host'] = min(len(word) for word in host_words) if host_words else 0
            features['shortest_word_path'] = min(len(word) for word in path_words) if path_words else 0
            features['longest_words_raw'] = max(len(word) for word in raw_words) if raw_words else 0
            features['longest_word_host'] = max(len(word) for word in host_words) if host_words else 0
            features['longest_word_path'] = max(len(word) for word in path_words) if path_words else 0
            features['avg_words_raw'] = sum(len(word) for word in raw_words) / len(raw_words) if raw_words else 0
            features['avg_word_host'] = sum(len(word) for word in host_words) / len(host_words) if host_words else 0
            features['avg_word_path'] = sum(len(word) for word in path_words) / len(path_words) if path_words else 0
            
            # Suspicious features
            features['phish_hints'] = sum(1 for word in ['login', 'signin', 'verify', 'bank', 'account', 'secure'] if word in url.lower())
            features['domain_in_brand'] = 1 if extract_res.domain in url.replace(parsed.netloc, '') else 0
            features['brand_in_subdomain'] = 1 if extract_res.domain in extract_res.subdomain else 0
            features['brand_in_path'] = 1 if extract_res.domain in parsed.path else 0
            features['suspecious_tld'] = 1 if tld in ['tk', 'ml', 'ga', 'cf', 'gq'] else 0
            
            # Statistical report
            features['statistical_report'] = 1 if any(service in url.lower() for service in ['googledocs', 'dropbox', 'drive']) else 0
            
            # Media and errors
            features['ratio_intMedia'] = len(soup.find_all(['img', 'video', 'audio'])) / features['nb_hyperlinks'] if features['nb_hyperlinks'] > 0 else 0
            features['ratio_extMedia'] = len(soup.find_all(['img', 'video', 'audio'], src=re.compile(r'^https?://'))) / features['nb_hyperlinks'] if features['nb_hyperlinks'] > 0 else 0
            
            # Form and iframe analysis
            features['login_form'] = 1 if soup.find('form') else 0
            features['external_favicon'] = 1 if soup.find('link', rel='icon', href=re.compile(r'^https?://')) else 0
            features['links_in_tags'] = len(soup.find_all(['link', 'script', 'img'])) / features['nb_hyperlinks'] if features['nb_hyperlinks'] > 0 else 0
            features['submit_email'] = 1 if soup.find('input', {'type': 'email'}) else 0
            features['sfh'] = 1 if soup.find('form', action=re.compile(r'^https?://')) else 0
            features['iframe'] = 1 if soup.find('iframe') else 0
            features['popup_window'] = 1 if 'window.open' in str(soup) else 0
            features['safe_anchor'] = len(soup.find_all('a', href='#')) / features['nb_hyperlinks'] if features['nb_hyperlinks'] > 0 else 0
            features['onmouseover'] = 1 if 'onmouseover' in str(soup) else 0
            features['right_clic'] = 1 if 'preventDefault' in str(soup) else 0
            features['empty_title'] = 1 if not soup.title or not soup.title.string else 0
            features['domain_in_title'] = 1 if (soup.title and soup.title.string and domain.lower() in soup.title.string.lower()) else 0


            
        except Exception as e:
            # Set default values for features that require webpage access
            features.update({
                'nb_hyperlinks': 0, 'ratio_intHyperlinks': 0, 'ratio_extHyperlinks': 0,
                'ratio_nullHyperlinks': 0, 'nb_extCSS': 0, 'nb_redirection': 0,
                'nb_external_redirection': 0, 'ratio_intRedirection': 0,
                'ratio_extRedirection': 0, 'ratio_intMedia': 0, 'ratio_extMedia': 0,
                'login_form': 0, 'external_favicon': 0, 'links_in_tags': 0,
                'submit_email': 0, 'sfh': 0, 'iframe': 0, 'popup_window': 0,
                'safe_anchor': 0, 'onmouseover': 0, 'right_clic': 0,
                'empty_title': 1, 'domain_in_title': 0
            })
        
        # Domain age and registration
        try:
            domain_info = whois.whois(domain)
            creation_date = domain_info.creation_date
            expiration_date = domain_info.expiration_date
            
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            
            features['domain_registration_length'] = (expiration_date - creation_date).days if creation_date and expiration_date else 0
            features['domain_age'] = (datetime.now() - creation_date).days if creation_date else 0
            features['whois_registered_domain'] = 1 if creation_date else 0
        except:
            features['domain_registration_length'] = 0
            features['domain_age'] = 0
            features['whois_registered_domain'] = 0
        
        # DNS and domain analysis
        try:
            dns_record = dns.resolver.resolve(domain, 'A')
            features['dns_record'] = 1
        except:
            features['dns_record'] = 0
        
        # Web traffic and ranking (simplified)
        features['web_traffic'] = 0  # Would need API access to Alexa/similar
        features['google_index'] = 0  # Would need API access to Google
        features['page_rank'] = 0  # Would need API access to page ranking service
        
    except Exception as e:
        st.error(f"Error extracting features: {str(e)}")
        return None
    
    return features

def main():
    st.title("Spoof Safe")
    st.write("**Safeguard your one click**")
    st.write("Enter a URL to check if it's legitimate or potentially phishing")
    
    # Load the trained model
    try:
        # model = joblib.load('optimized_lgbm.joblib')
        handler = FeatureAlignmentHandler('optimized_lgbm.joblib')
    except:
        st.error("Error: Model file not found. Please ensure the model is properly saved.")
        return
    
    # URL input
    url = st.text_input("Enter the website URL:")
    
    if st.button("Check Website"):
        if url:
            with st.spinner("Analyzing the website..."):
                try:
                    # Extract features
                    features = extract_features_from_url(url)
                    
                    if features:
                        # Convert features to DataFrame
                        feature_df = pd.DataFrame([features])
                        
                        # Make prediction
                        # prediction = model.predict(feature_df)[0]
                        prediction = handler.predict(features)
                        
                        # Display result
                        if prediction == 1:
                            st.error("⚠️ Warning: This website is likely a PHISHING website!")
                            st.write("Please be cautious and avoid entering any personal information.")
                        else:
                            st.success("✅ This website appears to be LEGITIMATE.")
                            st.write("However, always exercise caution when sharing personal information online.")
                        
                        # Display feature importance
                        if st.checkbox("Show detailed analysis"):
                            st.write("Key features analyzed:")
                            
                            # Create tabs for different feature categories
                            tab1, tab2, tab3 = st.tabs(["URL Structure", "Content Analysis", "Security Indicators"])
                            
                            with tab1:
                                st.write("URL Structure Features:")
                                url_features = {
                                    'URL Length': features['length_url'],
                                    'Number of Dots': features['nb_dots'],
                                    'Number of Hyphens': features['nb_hyphens'],
                                    'Has IP Address': features['ip'],
                                    'Uses HTTPS': features['https_token'],
                                    'Domain Length': features['length_hostname'],
                                    'Number of Subdomains': features['nb_subdomains'],
                                    'Uses Shortening Service': features['shortening_service'],
                                    'Has Suspicious TLD': features['suspecious_tld']
                                }
                                
                                for name, value in url_features.items():
                                    st.metric(name, value)
                            
                            with tab2:
                                st.write("Website Content Analysis:")
                                content_features = {
                                    'Number of Links': features['nb_hyperlinks'],
                                    'External Links Ratio': f"{features['ratio_extHyperlinks']:.2%}",
                                    'Internal Links Ratio': f"{features['ratio_intHyperlinks']:.2%}",
                                    'Has Login Form': 'Yes' if features['login_form'] else 'No',
                                    'Has iFrame': 'Yes' if features['iframe'] else 'No',
                                    'Has Pop-up': 'Yes' if features['popup_window'] else 'No',
                                    'Empty Title': 'Yes' if features['empty_title'] else 'No',
                                    'Domain in Title': 'Yes' if features['domain_in_title'] else 'No'
                                }
                                
                                col1, col2 = st.columns(2)
                                for i, (name, value) in enumerate(content_features.items()):
                                    if i % 2 == 0:
                                        col1.metric(name, value)
                                    else:
                                        col2.metric(name, value)
                            
                            with tab3:
                                st.write("Security Indicators:")
                                security_features = {
                                    'Domain Age (days)': features['domain_age'],
                                    'Registration Length (days)': features['domain_registration_length'],
                                    'Has DNS Record': 'Yes' if features['dns_record'] else 'No',
                                    'Right Click Disabled': 'Yes' if features['right_clic'] else 'No',
                                    'Uses External Favicon': 'Yes' if features['external_favicon'] else 'No',
                                    'Suspicious Form Handler': 'Yes' if features['sfh'] else 'No',
                                    'Mouse Over Effects': 'Yes' if features['onmouseover'] else 'No'
                                }
                                
                                col1, col2 = st.columns(2)
                                for i, (name, value) in enumerate(security_features.items()):
                                    if i % 2 == 0:
                                        col1.metric(name, value)
                                    else:
                                        col2.metric(name, value)
                            
                            # Show raw features
                            if st.checkbox("Show all raw features"):
                                st.write("All extracted features:")
                                st.dataframe(feature_df)
                        
                        # Add explanations
                        with st.expander("How does this detection work?"):
                            st.write("""
                            This phishing detection system analyzes various aspects of the website:
                            
                            1. **URL Structure**: Examines the website address for suspicious patterns
                            2. **Content Analysis**: Analyzes the webpage content for phishing indicators
                            3. **Technical Checks**: Verifies domain registration and security features
                            4. **Link Analysis**: Examines internal and external links
                            5. **Security Features**: Checks for suspicious security settings
                            
                            The system uses machine learning to combine all these factors and make a final determination.
                            """)
                            
                        with st.expander("What should I do if a website is flagged as phishing?"):
                            st.write("""
                            If a website is flagged as potentially phishing:
                            
                            1. ⚠️ Do not enter any personal information
                            2. 🔒 Do not login or provide credentials
                            3. 💳 Never provide payment information
                            4. 📧 Report the website to relevant authorities
                            5. 🔍 Access the intended website directly through official channels
                            """)
                    
                except Exception as e:
                    st.error(f"An error occurred while analyzing the URL: {str(e)}")
        else:
            st.warning("Please enter a URL to analyze.")

if __name__ == "__main__":
    st.set_page_config(
        page_title="Phishing Website Detector",
        page_icon="🔒",
        layout="wide",
        initial_sidebar_state="expanded"
    )
    
    # Add sidebar with additional information
    with st.sidebar:
        st.title("About")
        st.write("""
        This tool uses machine learning to detect potential phishing websites.
        It analyzes various features of the website including URL structure,
        content, and security indicators to make its determination.
        """)
        
        st.write("---")
        st.write("Features analyzed:")
        st.write("- URL structure and patterns")
        st.write("- Domain information")
        st.write("- Content analysis")
        st.write("- Security indicators")
        st.write("- Link relationships")
        
        st.write("---")
        st.write("Created with Streamlit and LightGBM")
    
    main()