import os
import pandas as pd
import numpy as np
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
from feature_extractor import extract_features, get_feature_names
import glob

def collect_files_and_features(malware_dir, benign_dir):
    """
    Collect all executable files and extract features
    """
    print("=" * 60)
    print("Collecting Executable Files and Extracting Features")
    print("=" * 60)
    
    data = []
    labels = []
    filenames = []
    
    # Process malware files
    print(f"\n[1/2] Processing malware files from: {malware_dir}")
    malware_files = glob.glob(os.path.join(malware_dir, "*.exe")) + \
                    glob.glob(os.path.join(malware_dir, "*.dll"))
    
    for filepath in malware_files:
        try:
            print(f"   Extracting features from: {os.path.basename(filepath)}")
            features = extract_features(filepath)
            data.append(features)
            labels.append(1)  # 1 = malicious
            filenames.append(os.path.basename(filepath))
        except Exception as e:
            print(f"   ✗ Error processing {filepath}: {e}")
    
    print(f"   ✓ Processed {len([l for l in labels if l == 1])} malware files")
    
    # Process benign files
    print(f"\n[2/2] Processing benign files from: {benign_dir}")
    benign_files = glob.glob(os.path.join(benign_dir, "*.exe")) + \
                   glob.glob(os.path.join(benign_dir, "*.dll"))
    
    for filepath in benign_files:
        try:
            print(f"   Extracting features from: {os.path.basename(filepath)}")
            features = extract_features(filepath)
            data.append(features)
            labels.append(0)  # 0 = benign
            filenames.append(os.path.basename(filepath))
        except Exception as e:
            print(f"   ✗ Error processing {filepath}: {e}")
    
    print(f"   ✓ Processed {len([l for l in labels if l == 0])} benign files")
    
    # Create DataFrame
    feature_names = get_feature_names()
    df = pd.DataFrame(data, columns=feature_names)
    df['label'] = labels
    df['filename'] = filenames
    
    print(f"\n✓ Total samples collected: {len(df)}")
    print(f"   - Benign: {(df['label'] == 0).sum()}")
    print(f"   - Malicious: {(df['label'] == 1).sum()}")
    
    return df

def train_model_from_files(malware_dir, benign_dir, test_size=0.2, n_estimators=100):
    """
    Train Random Forest model using actual executable files
    """
    print("\n" + "=" * 60)
    print("Training Malware Detection Model from Executable Files")
    print("=" * 60)
    
    # Collect features
    df = collect_files_and_features(malware_dir, benign_dir)
    
    if len(df) < 4:
        print("\n⚠ Warning: Not enough samples for proper train/test split.")
        print("   Need at least 4 samples. Consider adding more files.")
        return
    
    # Separate features and labels
    print(f"\n[3/6] Preparing data...")
    feature_cols = [col for col in df.columns if col not in ['label', 'filename']]
    X = df[feature_cols]
    y = df['label']
    
    print(f"   ✓ Features: {X.shape[1]}")
    print(f"   ✓ Samples: {X.shape[0]}")
    
    # Split data
    print(f"\n[4/6] Splitting dataset...")
    if len(df) < 10:
        # Too few samples for proper train/test split, use all for training
        print(f"   ⚠ Only {len(df)} samples - using all for training (no test split)")
        X_train = X
        y_train = y
        X_test = X  # Use training data for testing too
        y_test = y
    elif min((y == 0).sum(), (y == 1).sum()) >= 2:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42, stratify=y
        )
        print(f"   ✓ Training samples: {len(X_train)}")
        print(f"   ✓ Testing samples: {len(X_test)}")
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=42
        )
        print(f"   ✓ Training samples: {len(X_train)}")
        print(f"   ✓ Testing samples: {len(X_test)}")
    
    # Scale features
    print(f"\n[5/6] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print(f"   ✓ Features scaled")
    
    # Train model
    print(f"\n[6/6] Training Random Forest Classifier...")
    print(f"   ℹ Number of estimators: {n_estimators}")
    
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=42,
        max_depth=20,
        n_jobs=-1
    )
    
    model.fit(X_train_scaled, y_train)
    print(f"   ✓ Model training completed")
    
    # Evaluate
    print(f"\n{'='*60}")
    print("Model Evaluation")
    print(f"{'='*60}")
    
    train_pred = model.predict(X_train_scaled)
    test_pred = model.predict(X_test_scaled)
    
    train_acc = accuracy_score(y_train, train_pred)
    test_acc = accuracy_score(y_test, test_pred)
    
    print(f"\n✓ Training Accuracy: {train_acc * 100:.2f}%")
    print(f"✓ Testing Accuracy: {test_acc * 100:.2f}%")
    
    if len(set(y_test)) > 1:
        test_proba = model.predict_proba(X_test_scaled)[:, 1]
        roc_auc = roc_auc_score(y_test, test_proba)
        print(f"✓ ROC-AUC Score: {roc_auc:.4f}")
    
    print(f"\nClassification Report:")
    print("-" * 60)
    print(classification_report(y_test, test_pred, target_names=['Benign', 'Malicious']))
    
    print(f"\nConfusion Matrix:")
    print(confusion_matrix(y_test, test_pred))
    
    # Save model
    print(f"\n{'='*60}")
    print("Saving Model")
    print(f"{'='*60}")
    
    model_data = {
        'model': model,
        'scaler': scaler,
        'feature_names': feature_cols,
        'metrics': {
            'train_accuracy': train_acc,
            'test_accuracy': test_acc,
            'n_features': len(feature_cols)
        }
    }
    
    os.makedirs('models', exist_ok=True)
    model_path = 'models/malware_detector.pkl'
    
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)
    
    print(f"✓ Model saved to: {model_path}")
    print(f"✓ Feature count: {len(feature_cols)}")
    
    print(f"\n{'='*60}")
    print("Training Complete!")
    print(f"{'='*60}")
    print(f"\nYou can now run the Flask application:")
    print(f"  python app.py")
    print(f"{'='*60}")

if __name__ == '__main__':
    import argparse
    
    parser = argparse.ArgumentParser(description='Train malware detection model from executable files')
    parser.add_argument('--malware-dir', type=str, default='MALWARE', 
                        help='Directory containing malware files')
    parser.add_argument('--benign-dir', type=str, default='WINDOWS EXE', 
                        help='Directory containing benign files')
    parser.add_argument('--test-size', type=float, default=0.2, 
                        help='Test set size (default: 0.2)')
    parser.add_argument('--n-estimators', type=int, default=100, 
                        help='Number of trees (default: 100)')
    
    args = parser.parse_args()
    
    train_model_from_files(
        malware_dir=args.malware_dir,
        benign_dir=args.benign_dir,
        test_size=args.test_size,
        n_estimators=args.n_estimators
    )
