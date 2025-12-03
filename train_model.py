import pandas as pd
import numpy as np
import pickle
import argparse
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split, cross_val_score
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score, roc_auc_score
import matplotlib.pyplot as plt
import seaborn as sns
import os

def train_malware_detector(dataset_path, test_size=0.2, n_estimators=100, random_state=42):
    """
    Train a Random Forest classifier for malware detection
    
    Args:
        dataset_path: Path to the CSV dataset
        test_size: Proportion of dataset to use for testing
        n_estimators: Number of trees in the random forest
        random_state: Random seed for reproducibility
    """
    
    print("=" * 60)
    print("Malicious Executable Detection - Model Training")
    print("=" * 60)
    
    # Load dataset
    print(f"\n[1/7] Loading dataset from: {dataset_path}")
    try:
        df = pd.read_csv(dataset_path)
        print(f"   ✓ Dataset loaded successfully")
        print(f"   ✓ Total samples: {len(df)}")
        print(f"   ✓ Features: {df.shape[1] - 1}")
    except Exception as e:
        print(f"   ✗ Error loading dataset: {e}")
        return
    
    # Check for target column (common names: 'label', 'class', 'target', 'malicious', 'legitimate')
    target_col = None
    possible_targets = ['label', 'class', 'target', 'malicious', 'legitimate', 'Label', 'Class', 'Target']
    
    for col in possible_targets:
        if col in df.columns:
            target_col = col
            break
    
    # Separate features and target
    print(f"\n[2/7] Preparing data...")
    
    if target_col is None:
        # Check if 'Name' column exists and create labels from it
        if 'Name' in df.columns:
            print(f"   ℹ Creating labels from 'Name' column (VirusShare = malicious)")
            y = df['Name'].astype(str).str.contains('VirusShare', case=False, na=False).astype(int)
            X = df.drop(columns=['Name'])
        else:
            # Assume last column is target
            target_col = df.columns[-1]
            print(f"   ℹ Using '{target_col}' as target column")
            X = df.drop(columns=[target_col])
            y = df[target_col]
    else:
        X = df.drop(columns=[target_col])
        y = df[target_col]
    
    # Handle categorical target if needed
    if y.dtype == 'object':
        print(f"   ℹ Converting categorical labels to numeric")
        y = y.map({'benign': 0, 'malicious': 1, 'Benign': 0, 'Malicious': 1, 'legitimate': 0, 'malware': 1})
    
    print(f"   ✓ Features shape: {X.shape}")
    print(f"   ✓ Target distribution:")
    print(f"      - Benign: {(y == 0).sum()} ({(y == 0).sum() / len(y) * 100:.2f}%)")
    print(f"      - Malicious: {(y == 1).sum()} ({(y == 1).sum() / len(y) * 100:.2f}%)")
    
    # Split dataset
    print(f"\n[3/7] Splitting dataset (train: {(1-test_size)*100}%, test: {test_size*100}%)")
    
    # Check if we have enough samples for stratification
    min_class_count = min((y == 0).sum(), (y == 1).sum())
    if min_class_count < 2:
        print(f"   ⚠ Warning: Class imbalance detected. Splitting without stratification.")
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state
        )
    else:
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=test_size, random_state=random_state, stratify=y
        )
    print(f"   ✓ Training samples: {len(X_train)}")
    print(f"   ✓ Testing samples: {len(X_test)}")
    
    # Scale features
    print(f"\n[4/7] Scaling features...")
    scaler = StandardScaler()
    X_train_scaled = scaler.fit_transform(X_train)
    X_test_scaled = scaler.transform(X_test)
    print(f"   ✓ Features scaled using StandardScaler")
    
    # Train Random Forest model
    print(f"\n[5/7] Training Random Forest Classifier...")
    print(f"   ℹ Number of estimators: {n_estimators}")
    print(f"   ℹ Random state: {random_state}")
    
    model = RandomForestClassifier(
        n_estimators=n_estimators,
        random_state=random_state,
        max_depth=20,
        min_samples_split=5,
        min_samples_leaf=2,
        n_jobs=-1,
        verbose=1
    )
    
    model.fit(X_train_scaled, y_train)
    print(f"   ✓ Model training completed")
    
    # Evaluate model
    print(f"\n[6/7] Evaluating model performance...")
    
    # Training accuracy
    train_pred = model.predict(X_train_scaled)
    train_accuracy = accuracy_score(y_train, train_pred)
    print(f"   ✓ Training Accuracy: {train_accuracy * 100:.2f}%")
    
    # Testing accuracy
    test_pred = model.predict(X_test_scaled)
    test_accuracy = accuracy_score(y_test, test_pred)
    print(f"   ✓ Testing Accuracy: {test_accuracy * 100:.2f}%")
    
    # ROC-AUC Score
    test_proba = model.predict_proba(X_test_scaled)[:, 1]
    roc_auc = roc_auc_score(y_test, test_proba)
    print(f"   ✓ ROC-AUC Score: {roc_auc:.4f}")
    
    # Cross-validation
    cv_scores = cross_val_score(model, X_train_scaled, y_train, cv=5, scoring='accuracy')
    print(f"   ✓ Cross-validation Accuracy: {cv_scores.mean() * 100:.2f}% (±{cv_scores.std() * 100:.2f}%)")
    
    # Classification Report
    print(f"\n   Classification Report:")
    print("   " + "-" * 50)
    report = classification_report(y_test, test_pred, target_names=['Benign', 'Malicious'])
    for line in report.split('\n'):
        print(f"   {line}")
    
    # Confusion Matrix
    cm = confusion_matrix(y_test, test_pred)
    print(f"\n   Confusion Matrix:")
    print(f"   {cm}")
    
    # Feature Importance
    feature_importance = pd.DataFrame({
        'feature': X.columns,
        'importance': model.feature_importances_
    }).sort_values('importance', ascending=False)
    
    print(f"\n   Top 10 Most Important Features:")
    for idx, row in feature_importance.head(10).iterrows():
        print(f"   {row['feature']:30s}: {row['importance']:.4f}")
    
    # Save model
    print(f"\n[7/7] Saving model...")
    model_data = {
        'model': model,
        'scaler': scaler,
        'feature_names': list(X.columns),
        'metrics': {
            'train_accuracy': train_accuracy,
            'test_accuracy': test_accuracy,
            'roc_auc': roc_auc,
            'cv_mean': cv_scores.mean(),
            'cv_std': cv_scores.std()
        }
    }
    
    os.makedirs('models', exist_ok=True)
    model_path = 'models/malware_detector.pkl'
    
    with open(model_path, 'wb') as f:
        pickle.dump(model_data, f)
    
    print(f"   ✓ Model saved to: {model_path}")
    
    # Save feature importance plot
    plt.figure(figsize=(10, 8))
    top_features = feature_importance.head(20)
    plt.barh(range(len(top_features)), top_features['importance'])
    plt.yticks(range(len(top_features)), top_features['feature'])
    plt.xlabel('Importance')
    plt.title('Top 20 Feature Importance')
    plt.tight_layout()
    plt.savefig('models/feature_importance.png', dpi=300, bbox_inches='tight')
    print(f"   ✓ Feature importance plot saved to: models/feature_importance.png")
    
    # Save confusion matrix plot
    plt.figure(figsize=(8, 6))
    sns.heatmap(cm, annot=True, fmt='d', cmap='Blues', xticklabels=['Benign', 'Malicious'], 
                yticklabels=['Benign', 'Malicious'])
    plt.ylabel('True Label')
    plt.xlabel('Predicted Label')
    plt.title('Confusion Matrix')
    plt.tight_layout()
    plt.savefig('models/confusion_matrix.png', dpi=300, bbox_inches='tight')
    print(f"   ✓ Confusion matrix plot saved to: models/confusion_matrix.png")
    
    print("\n" + "=" * 60)
    print("Training completed successfully!")
    print("=" * 60)
    print(f"\nModel Summary:")
    print(f"  • Accuracy: {test_accuracy * 100:.2f}%")
    print(f"  • ROC-AUC: {roc_auc:.4f}")
    print(f"  • Model file: {model_path}")
    print(f"\nYou can now run the Flask application:")
    print(f"  python app.py")
    print("=" * 60)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Train malware detection model')
    parser.add_argument('--dataset', type=str, required=True, help='Path to the dataset CSV file')
    parser.add_argument('--test_size', type=float, default=0.2, help='Test set size (default: 0.2)')
    parser.add_argument('--n_estimators', type=int, default=100, help='Number of trees (default: 100)')
    parser.add_argument('--random_state', type=int, default=42, help='Random seed (default: 42)')
    
    args = parser.parse_args()
    
    train_malware_detector(
        dataset_path=args.dataset,
        test_size=args.test_size,
        n_estimators=args.n_estimators,
        random_state=args.random_state
    )
