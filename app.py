# import streamlit as st
# import joblib
# import numpy as np

# # Load the model
# @st.cache_resource
# def load_model():
#     return joblib.load('best_model_pipeline.joblib')

# pipeline = load_model()


import streamlit as st
import pandas as pd
import joblib
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler

# Load your dataset here
def load_model():
    return joblib.load('best_model_pipeline.joblib')
# For this example, we'll create a dummy dataset
def create_dummy_dataset():
    np.random.seed(42)
    n_samples = 1000
    features = ['ratio_digits_host', 'web_traffic', 'links_in_tags', 'nb_slash', 'length_url', 
                'ratio_extHyperlinks', 'longest_word_path', 'length_words_raw', 'page_rank', 
                'length_hostname', 'domain_in_title', 'nb_www', 'ratio_extRedirection', 
                'domain_registration_length', 'google_index', 'shortest_word_host', 'phish_hints', 
                'nb_dots', 'avg_word_host', 'nb_hyperlinks', 'ratio_intHyperlinks', 
                'shortest_word_path', 'ratio_digits_url', 'safe_anchor', 'avg_words_raw', 
                'nb_hyphens', 'char_repeat', 'domain_age', 'avg_word_path', 'longest_words_raw']
    
    X = np.random.rand(n_samples, len(features))
    y = np.random.randint(2, size=n_samples)
    
    return pd.DataFrame(X, columns=features), pd.Series(y)

# Train the model
def train_model(X, y):
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)
    
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    
    model = RandomForestClassifier(n_estimators=100, random_state=42)
    model.fit(X_train_scaled, y_train)
    
    return model, scaler

# Make prediction
def predict(model, scaler, input_data):
    input_scaled = scaler.transform(input_data)
    prediction = model.predict(input_scaled)
    probability = model.predict_proba(input_scaled)
    return prediction[0], probability[0][1]

# Streamlit app
def main():
    st.title("Website Phishing Detection")
    
    # Load and train the model
    X, y = create_dummy_dataset()
    model, scaler = train_model(X, y)
    
    # Create input fields for features
    st.header("Enter Website Features:")
    
    feature_inputs = {}
    for feature in X.columns:
        feature_inputs[feature] = st.number_input(f"Enter {feature}", value=0.0, format="%.2f")
    
    if st.button("Check Website"):
        input_data = pd.DataFrame([feature_inputs])
        prediction, probability = predict(model, scaler, input_data)
        
        st.header("Result:")
        if prediction == 1:
            st.error(f"The website is likely MALICIOUS (Probability: {probability:.2f})")
        else:
            st.success(f"The website is likely LEGITIMATE (Probability: {1-probability:.2f})")
        
        st.write("Note: This is a simplified model and should not be used as the sole method for determining website legitimacy.")

if __name__ == "__main__":
    main()