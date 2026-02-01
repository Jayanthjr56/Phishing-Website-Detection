"""
Model Trainer Module
Trains machine learning models for phishing detection
"""

import os
import pandas as pd
import numpy as np
from sklearn.model_selection import train_test_split, cross_val_score, StratifiedKFold
from sklearn.preprocessing import StandardScaler
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix, roc_auc_score, precision_recall_curve
from sklearn.feature_selection import SelectFromModel
import joblib
from tqdm import tqdm
import warnings
warnings.filterwarnings('ignore')

try:
    from xgboost import XGBClassifier
    HAS_XGBOOST = True
except ImportError:
    HAS_XGBOOST = False
    print("[WARNING] XGBoost not installed. Using alternative models.")

import config
from data_collector import DataCollector
from feature_extractor import FeatureExtractor


class PhishingModelTrainer:
    """
    Trains and evaluates machine learning models for phishing detection
    """
    
    def __init__(self):
        self.feature_extractor = FeatureExtractor()
        self.scaler = StandardScaler()
        self.model = None
        self.feature_names = None
        self.feature_importance = None
        
    def prepare_dataset(self, df=None, max_samples=None):
        """
        Prepare dataset by extracting features from URLs
        
        Args:
            df: DataFrame with 'url' and 'label' columns
            max_samples: Maximum samples to process (for faster testing)
        
        Returns:
            X: Feature matrix
            y: Labels
        """
        print("\n" + "="*60)
        print("PREPARING DATASET - EXTRACTING FEATURES")
        print("="*60 + "\n")
        
        if df is None:
            # Load existing dataset
            if os.path.exists(config.PROCESSED_DATA_FILE):
                df = pd.read_csv(config.PROCESSED_DATA_FILE)
            else:
                collector = DataCollector()
                df = collector.create_training_dataset()
        
        if df is None:
            raise ValueError("No dataset available")
        
        # Sample if needed
        if max_samples and len(df) > max_samples:
            df = df.sample(n=max_samples, random_state=42)
            print(f"[INFO] Sampled {max_samples} URLs for processing")
        
        # Check if features already extracted
        if os.path.exists(config.FEATURE_FILE):
            print(f"[INFO] Loading pre-extracted features from {config.FEATURE_FILE}")
            features_df = pd.read_csv(config.FEATURE_FILE)
            
            # Verify it matches current dataset size
            if len(features_df) == len(df):
                X = features_df.drop(['url', 'label'], axis=1, errors='ignore')
                y = df['label'].values
                self.feature_names = list(X.columns)
                return X.values, y
        
        # Extract features for each URL
        features_list = []
        failed_urls = 0
        
        print(f"[INFO] Extracting features from {len(df)} URLs...")
        
        for idx, row in tqdm(df.iterrows(), total=len(df), desc="Extracting features"):
            try:
                features = self.feature_extractor.extract_all_features(row['url'])
                features['url'] = row['url']
                features['label'] = row['label']
                features_list.append(features)
            except Exception as e:
                failed_urls += 1
                continue
        
        print(f"[INFO] Successfully extracted features from {len(features_list)} URLs")
        print(f"[INFO] Failed to extract features from {failed_urls} URLs")
        
        # Create features DataFrame
        features_df = pd.DataFrame(features_list)
        
        # Save features for future use
        features_df.to_csv(config.FEATURE_FILE, index=False)
        print(f"[SUCCESS] Features saved to {config.FEATURE_FILE}")
        
        # Prepare X and y
        X = features_df.drop(['url', 'label'], axis=1)
        y = features_df['label'].values
        
        # Handle any remaining NaN values
        X = X.fillna(0)
        
        self.feature_names = list(X.columns)
        
        return X.values, y
    
    def train_model(self, X, y, model_type='ensemble'):
        """
        Train the phishing detection model
        
        Args:
            X: Feature matrix
            y: Labels (0=legitimate, 1=phishing)
            model_type: 'rf', 'xgb', 'ensemble'
        
        Returns:
            Trained model
        """
        print("\n" + "="*60)
        print("TRAINING PHISHING DETECTION MODEL")
        print("="*60 + "\n")
        
        # Split data
        X_train, X_test, y_train, y_test = train_test_split(
            X, y, test_size=0.2, random_state=42, stratify=y
        )
        
        print(f"[INFO] Training set size: {len(X_train)}")
        print(f"[INFO] Test set size: {len(X_test)}")
        print(f"[INFO] Training set balance: {sum(y_train==0)} legitimate, {sum(y_train==1)} phishing")
        
        # Scale features
        X_train_scaled = self.scaler.fit_transform(X_train)
        X_test_scaled = self.scaler.transform(X_test)
        
        # Select model type
        if model_type == 'rf':
            self.model = self._train_random_forest(X_train_scaled, y_train)
        elif model_type == 'xgb' and HAS_XGBOOST:
            self.model = self._train_xgboost(X_train_scaled, y_train)
        else:
            self.model = self._train_ensemble(X_train_scaled, y_train)
        
        # Evaluate on test set
        print("\n" + "-"*40)
        print("MODEL EVALUATION ON TEST SET")
        print("-"*40 + "\n")
        
        y_pred = self.model.predict(X_test_scaled)
        y_pred_proba = self.model.predict_proba(X_test_scaled)[:, 1]
        
        # Classification report
        print("Classification Report:")
        print(classification_report(y_test, y_pred, target_names=['Legitimate', 'Phishing']))
        
        # Confusion matrix
        cm = confusion_matrix(y_test, y_pred)
        print("\nConfusion Matrix:")
        print(f"                 Predicted")
        print(f"                 Legit  Phish")
        print(f"Actual Legit    {cm[0][0]:5d}  {cm[0][1]:5d}")
        print(f"Actual Phish    {cm[1][0]:5d}  {cm[1][1]:5d}")
        
        # ROC AUC Score
        roc_auc = roc_auc_score(y_test, y_pred_proba)
        print(f"\nROC AUC Score: {roc_auc:.4f}")
        
        # Cross-validation
        print("\n[INFO] Performing 5-fold cross-validation...")
        cv_scores = cross_val_score(self.model, X_train_scaled, y_train, cv=5, scoring='roc_auc')
        print(f"[INFO] Cross-validation ROC AUC: {cv_scores.mean():.4f} (+/- {cv_scores.std()*2:.4f})")
        
        # Feature importance
        self._calculate_feature_importance()
        
        return self.model
    
    def _train_random_forest(self, X_train, y_train):
        """Train a Random Forest classifier"""
        print("[INFO] Training Random Forest classifier...")
        
        model = RandomForestClassifier(
            n_estimators=200,
            max_depth=20,
            min_samples_split=5,
            min_samples_leaf=2,
            max_features='sqrt',
            n_jobs=-1,
            random_state=42,
            class_weight='balanced'
        )
        
        model.fit(X_train, y_train)
        return model
    
    def _train_xgboost(self, X_train, y_train):
        """Train an XGBoost classifier"""
        print("[INFO] Training XGBoost classifier...")
        
        # Calculate scale_pos_weight for imbalanced classes
        scale_pos_weight = sum(y_train == 0) / sum(y_train == 1) if sum(y_train == 1) > 0 else 1
        
        model = XGBClassifier(
            n_estimators=200,
            max_depth=10,
            learning_rate=0.1,
            subsample=0.8,
            colsample_bytree=0.8,
            scale_pos_weight=scale_pos_weight,
            use_label_encoder=False,
            eval_metric='logloss',
            random_state=42,
            n_jobs=-1
        )
        
        model.fit(X_train, y_train)
        return model
    
    def _train_ensemble(self, X_train, y_train):
        """Train an ensemble of classifiers"""
        print("[INFO] Training Ensemble classifier (RF + GB + LR)...")
        
        # Random Forest
        rf = RandomForestClassifier(
            n_estimators=150,
            max_depth=15,
            min_samples_split=5,
            n_jobs=-1,
            random_state=42,
            class_weight='balanced'
        )
        
        # Gradient Boosting
        gb = GradientBoostingClassifier(
            n_estimators=100,
            max_depth=8,
            learning_rate=0.1,
            random_state=42
        )
        
        # Logistic Regression
        lr = LogisticRegression(
            max_iter=1000,
            C=1.0,
            class_weight='balanced',
            random_state=42
        )
        
        # Voting ensemble
        ensemble = VotingClassifier(
            estimators=[
                ('rf', rf),
                ('gb', gb),
                ('lr', lr)
            ],
            voting='soft',
            n_jobs=-1
        )
        
        ensemble.fit(X_train, y_train)
        return ensemble
    
    def _calculate_feature_importance(self):
        """Calculate and display feature importance"""
        if self.feature_names is None:
            return
        
        print("\n" + "-"*40)
        print("TOP 20 MOST IMPORTANT FEATURES")
        print("-"*40 + "\n")
        
        try:
            # Try to get feature importance from the model
            if hasattr(self.model, 'feature_importances_'):
                importance = self.model.feature_importances_
            elif hasattr(self.model, 'estimators_'):
                # For ensemble, use first estimator with feature importance
                for name, est in self.model.named_estimators_.items():
                    if hasattr(est, 'feature_importances_'):
                        importance = est.feature_importances_
                        break
            else:
                print("[INFO] Feature importance not available for this model type")
                return
            
            # Create feature importance DataFrame
            self.feature_importance = pd.DataFrame({
                'feature': self.feature_names,
                'importance': importance
            }).sort_values('importance', ascending=False)
            
            # Display top 20
            print(self.feature_importance.head(20).to_string(index=False))
            
        except Exception as e:
            print(f"[WARNING] Could not calculate feature importance: {e}")
    
    def save_model(self):
        """Save the trained model and scaler"""
        if self.model is None:
            print("[ERROR] No model to save")
            return
        
        # Save model
        joblib.dump(self.model, config.MODEL_FILE)
        print(f"[SUCCESS] Model saved to {config.MODEL_FILE}")
        
        # Save scaler
        joblib.dump(self.scaler, config.SCALER_FILE)
        print(f"[SUCCESS] Scaler saved to {config.SCALER_FILE}")
        
        # Save feature names
        joblib.dump(self.feature_names, config.FEATURE_NAMES_FILE)
        print(f"[SUCCESS] Feature names saved to {config.FEATURE_NAMES_FILE}")
        
        # Save feature importance if available
        if self.feature_importance is not None:
            importance_file = os.path.join(config.MODEL_DIR, 'feature_importance.csv')
            self.feature_importance.to_csv(importance_file, index=False)
            print(f"[SUCCESS] Feature importance saved to {importance_file}")
    
    def load_model(self):
        """Load a trained model and scaler"""
        if not os.path.exists(config.MODEL_FILE):
            print("[ERROR] No saved model found")
            return False
        
        self.model = joblib.load(config.MODEL_FILE)
        self.scaler = joblib.load(config.SCALER_FILE)
        self.feature_names = joblib.load(config.FEATURE_NAMES_FILE)
        
        print("[SUCCESS] Model loaded successfully")
        return True


def train_full_pipeline(max_samples=None):
    """
    Complete training pipeline
    
    Args:
        max_samples: Maximum number of samples to use (None for all)
    """
    print("\n" + "="*60)
    print("PHISHING DETECTION MODEL TRAINING PIPELINE")
    print("="*60)
    
    # Initialize trainer
    trainer = PhishingModelTrainer()
    
    # Prepare dataset
    X, y = trainer.prepare_dataset(max_samples=max_samples)
    
    print(f"\n[INFO] Dataset shape: {X.shape}")
    print(f"[INFO] Number of features: {X.shape[1]}")
    
    # Train model
    trainer.train_model(X, y, model_type='ensemble')
    
    # Save model
    trainer.save_model()
    
    print("\n" + "="*60)
    print("TRAINING COMPLETE")
    print("="*60)
    
    return trainer


if __name__ == "__main__":
    # Train with a subset for faster initial testing
    # Set max_samples=None for full training
    trainer = train_full_pipeline(max_samples=10000)
