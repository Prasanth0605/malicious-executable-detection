from flask import Flask, render_template, request, jsonify, redirect, url_for
import os
import pickle
import numpy as np
import pandas as pd
from werkzeug.utils import secure_filename
from feature_extractor import extract_features

app = Flask(__name__)
app.config['UPLOAD_FOLDER'] = 'uploads'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024 
app.config['SECRET_KEY'] = 'your-secret-key-here'

ALLOWED_EXTENSIONS = {'exe', 'dll', 'bin', 'apk'}
MODEL_PATH = 'models/malware_detector.pkl'

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/')
def index():
    model_exists = os.path.exists(MODEL_PATH)
    return render_template('index.html', model_trained=model_exists)

@app.route('/upload', methods=['POST'])
def upload_file():
    if 'file' not in request.files:
        return jsonify({'error': 'No file uploaded'}), 400
    
    file = request.files['file']
    
    if file.filename == '':
        return jsonify({'error': 'No file selected'}), 400
    
    if not allowed_file(file.filename):
        return jsonify({'error': 'Invalid file type. Only .exe, .dll, .bin, .apk files allowed'}), 400
    
    # Check if model exists
    if not os.path.exists(MODEL_PATH):
        return jsonify({'error': 'Model not trained yet. Please train the model first.'}), 400
    
    try:
        # Save uploaded file
        filename = secure_filename(file.filename)
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(filepath)
        
        # Extract features from the file
        features = extract_features(filepath)
        
        # Load the trained model
        with open(MODEL_PATH, 'rb') as f:
            model_data = pickle.load(f)
            model = model_data['model']
            scaler = model_data.get('scaler', None)
        
        # Prepare features for prediction
        features_array = np.array(features).reshape(1, -1)
        
        # Scale features if scaler exists
        if scaler:
            features_array = scaler.transform(features_array)
        
        # Make prediction
        prediction = model.predict(features_array)[0]
        probability = model.predict_proba(features_array)[0]
        
        # Clean up uploaded file
        os.remove(filepath)
        
        result = {
            'filename': filename,
            'prediction': 'Malicious' if prediction == 1 else 'Benign',
            'confidence': float(max(probability) * 100),
            'malicious_probability': float(probability[1] * 100) if len(probability) > 1 else 0,
            'benign_probability': float(probability[0] * 100)
        }
        
        return render_template('result.html', result=result)
    
    except Exception as e:
        # Clean up file if it exists
        if os.path.exists(filepath):
            os.remove(filepath)
        return jsonify({'error': f'Error processing file: {str(e)}'}), 500

@app.route('/train_status')
def train_status():
    """Check if model is trained"""
    model_exists = os.path.exists(MODEL_PATH)
    return jsonify({'trained': model_exists})

@app.route('/about')
def about():
    return render_template('about.html')

if __name__ == '__main__':
    # Create necessary directories
    os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)
    os.makedirs('models', exist_ok=True)
    
    print("=" * 50)
    print("Malicious Executable Detector - Flask Application")
    print("=" * 50)
    
    if os.path.exists(MODEL_PATH):
        print("✓ Model found and loaded successfully")
    else:
        print("⚠ Model not found. Please train the model first using:")
        print("  python train_model.py --dataset <path_to_dataset>")
    
    print("\nStarting Flask server...")
    print("Access the application at: http://127.0.0.1:5000")
    print("=" * 50)
    
    app.run(debug=True, host='0.0.0.0', port=5000)
