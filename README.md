# 🛡️ Malicious Executable Detector

A machine learning-powered web application for detecting malicious executables using Random Forest Classifier. This project features a modern Flask web interface that allows users to upload executable files (.exe, .dll, .bin, .apk) for real-time malware analysis.

![Python](https://img.shields.io/badge/Python-3.8+-blue.svg)
![Flask](https://img.shields.io/badge/Flask-3.0.0-green.svg)
![Scikit-learn](https://img.shields.io/badge/Scikit--learn-1.3.2-orange.svg)
![License](https://img.shields.io/badge/License-MIT-yellow.svg)

## 🌟 Features

- **Machine Learning Detection**: Uses Random Forest Classifier with 50+ static features
- **Modern Web Interface**: Beautiful, responsive Flask UI with drag-and-drop file upload
- **Real-time Analysis**: Instant malware detection with confidence scores
- **Detailed Reports**: Comprehensive analysis results with probabilities and recommendations
- **Multiple File Support**: Supports .exe, .dll, .bin, and .apk files
- **Visual Analytics**: Feature importance and confusion matrix visualizations
- **Cross-validation**: Robust model evaluation with 5-fold cross-validation

## 📋 Prerequisites

- Python 3.8 or higher
- pip package manager
- Dataset for training (CSV format with features and labels)

## 🚀 Installation

1. **Clone or navigate to the project directory**:
   ```bash
   cd /home/prasanth/Desktop/ML_PROJECT
   ```

2. **Create a virtual environment** (recommended):
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install required packages**:
   ```bash
   pip install -r requirements.txt
   ```

## 📊 Dataset Requirements

Your dataset should be a CSV file with:
- **Features**: Static characteristics extracted from executables (numerical values)
- **Target Column**: Label indicating malicious (1) or benign (0)
  - Supported column names: `label`, `class`, `target`, `malicious`, `legitimate`
  - Can be numeric (0/1) or categorical (benign/malicious)

Example dataset structure:
```
feature1,feature2,feature3,...,label
123.45,67.89,234.56,...,0
456.78,123.45,678.90,...,1
...
```

## 🎯 Usage

### Step 1: Train the Model

Before using the application, you need to train the model with your dataset:

```bash
python train_model.py --dataset path/to/your/dataset.csv
```

**Optional parameters**:
- `--test_size`: Test set proportion (default: 0.2)
- `--n_estimators`: Number of trees in Random Forest (default: 100)
- `--random_state`: Random seed for reproducibility (default: 42)

**Example**:
```bash
python train_model.py --dataset malware_data.csv --n_estimators 200 --test_size 0.25
```

The training script will:
- ✅ Load and preprocess your dataset
- ✅ Split data into training and testing sets
- ✅ Train the Random Forest model
- ✅ Evaluate performance with multiple metrics
- ✅ Save the trained model to `models/malware_detector.pkl`
- ✅ Generate visualization plots (feature importance, confusion matrix)

### Step 2: Run the Flask Application

After training the model, start the web application:

```bash
python app.py
```

The application will be available at: **http://127.0.0.1:5000**

### Step 3: Analyze Files

1. Open your web browser and navigate to `http://127.0.0.1:5000`
2. Upload an executable file using the drag-and-drop interface or file selector
3. Click "Analyze File" to get instant results
4. View detailed analysis including:
   - Malicious or Benign classification
   - Confidence score
   - Probability breakdown
   - Recommended actions

## 🏗️ Project Structure

```
ML_PROJECT/
│
├── app.py                      # Flask web application
├── train_model.py              # Model training script
├── feature_extractor.py        # Feature extraction module
├── requirements.txt            # Python dependencies
├── README.md                   # Project documentation
│
├── templates/                  # HTML templates
│   ├── index.html             # Main page
│   └── result.html            # Results page
│
├── static/                     # Static files
│   └── css/
│       └── style.css          # Styling
│
├── models/                     # Trained models
│   ├── malware_detector.pkl   # Saved model
│   ├── feature_importance.png # Feature plot
│   └── confusion_matrix.png   # Confusion matrix
│
└── uploads/                    # Temporary file storage
```

## 🔍 Feature Extraction

The application extracts 50+ static features from executables:

### Categories:
1. **File Characteristics**: Size, entropy, byte statistics
2. **Hash Features**: MD5, SHA1, SHA256 fingerprints
3. **Byte Distribution**: Null bytes, printable characters, high bytes
4. **Pattern Detection**: MZ/PE headers, section markers
5. **API Calls**: Suspicious API usage patterns
6. **String Analysis**: URLs, file extensions, system paths
7. **PE Structure**: PE-specific characteristics
8. **Statistical Features**: Variance, unique byte ratio, n-grams

## 📈 Model Performance

After training, the model provides:
- **Training Accuracy**: Performance on training data
- **Testing Accuracy**: Performance on unseen data
- **ROC-AUC Score**: Area under the curve metric
- **Cross-validation**: 5-fold CV with mean and standard deviation
- **Classification Report**: Precision, recall, F1-score
- **Confusion Matrix**: True/False positives and negatives

## 🔒 Security Notes

- Files are temporarily stored during analysis
- All uploaded files are automatically deleted after processing
- Analysis is performed locally - no data is sent externally
- The model uses static analysis only

## ⚙️ Configuration

You can modify settings in `app.py`:

```python
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # Max file size (16MB)
app.config['UPLOAD_FOLDER'] = 'uploads'              # Upload directory
ALLOWED_EXTENSIONS = {'exe', 'dll', 'bin', 'apk'}    # Allowed file types
```

## 🛠️ Troubleshooting

### Model not trained error
- Run `python train_model.py --dataset <path>` first
- Ensure the model file exists at `models/malware_detector.pkl`

### Import errors
- Activate your virtual environment
- Run `pip install -r requirements.txt`

### File upload errors
- Check file size (must be under 16MB)
- Verify file extension (.exe, .dll, .bin, .apk)

### Low accuracy
- Try more training data
- Increase `n_estimators` parameter
- Check dataset quality and balance

## 📝 Requirements

```
Flask==3.0.0
Werkzeug==3.0.1
pandas==2.1.4
numpy==1.26.2
scikit-learn==1.3.2
matplotlib==3.8.2
seaborn==0.13.0
```

## 🤝 Contributing

Contributions are welcome! Feel free to:
- Report bugs
- Suggest new features
- Submit pull requests
- Improve documentation

## 📄 License

This project is licensed under the MIT License.

## 👨‍💻 Author

Created as a machine learning project for malware detection.

## 🙏 Acknowledgments

- Flask framework for the web interface
- Scikit-learn for machine learning capabilities
- Random Forest algorithm for classification

## 📞 Support

If you encounter any issues or have questions:
1. Check the troubleshooting section
2. Review the error messages in the terminal
3. Ensure all dependencies are installed correctly

---

**⚠️ Disclaimer**: This tool is for educational and research purposes. Always use multiple security tools and layers for production malware detection. This static analysis tool should not be your only line of defense.

**Happy Malware Hunting! 🎯**
