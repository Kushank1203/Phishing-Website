import streamlit as st
import joblib
import numpy as np

# Load the model
@st.cache_resource
def load_model():
    return joblib.load('best_model_pipeline.joblib')

pipeline = load_model()
