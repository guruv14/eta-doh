import os
import joblib
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.metrics import classification_report, confusion_matrix, accuracy_score

# --- Configuration ---

DATA_DIR = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), 'data')
MODEL_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'models')
BENIGN_FILE = os.path.join(DATA_DIR, 'benign.csv')
MALICIOUS_FILE = os.path.join(DATA_DIR, 'malicious.csv')
MODEL_FILE = os.path.join(MODEL_DIR, 'rf_doh_model.pkl')


FEATURE_MAP = {
    'PacketTimeMean': 'mean_iat',
    'PacketTimeVariance': 'variance_iat',
    'PacketTimeSkewFromMedian': 'skewness_iat'
}

class ModelTrainer:
    def __init__(self):
        self.df = None
        self.model = None
        self.X_test = None
        self.y_test = None

    def load_and_clean_data(self):
        print("[-] Loading datasets...")
        print(f"Data directory: {DATA_DIR}")
        if not os.path.exists(BENIGN_FILE) or not os.path.exists(MALICIOUS_FILE):
            raise FileNotFoundError("CSV files not found in /data folder!")

        #
        # load the columns {only needed}
        cols_to_keep = list(FEATURE_MAP.keys())
        
        df_benign = pd.read_csv(BENIGN_FILE, usecols=cols_to_keep)
        df_malicious = pd.read_csv(MALICIOUS_FILE, usecols=cols_to_keep)

        #  labels
        df_benign['label'] = 0  # Benign
        df_malicious['label'] = 1  # Malicious

        print(f"    - Benign Samples: {len(df_benign)}")
        print(f"    - Malicious Samples: {len(df_malicious)}")

        #  balancing (downsampling Malicious to match Benign)
        target_count = len(df_benign)
        print(f"[-] Balancing dataset to {target_count} samples per class...")
        
        df_malicious_balanced = df_malicious.sample(n=target_count, random_state=42)
        
        # combine
        self.df = pd.concat([df_benign, df_malicious_balanced], axis=0)
        
        # shuffle
        self.df = self.df.sample(frac=1, random_state=42).reset_index(drop=True)
        
        # rename columns
        self.df.rename(columns=FEATURE_MAP, inplace=True)
        print("[-] Data loaded and balanced successfully.")

    def train(self):
        #  X (Features) and y (Labels)
        X = self.df[['mean_iat', 'variance_iat', 'skewness_iat']]
        y = self.df['label']

        # split 80-20
        print("[-] Splitting data (80/20)...")
        X_train, self.X_test, y_train, self.y_test = train_test_split(X, y, test_size=0.2, random_state=42)


        print("[-] Training Random Forest Classifier...")
        self.model = RandomForestClassifier(n_estimators=100, max_depth=10, random_state=42)
        self.model.fit(X_train, y_train)
        print("[-] Training complete.")

    def evaluate(self):
        print("\n" + "="*40)
        print("       MODEL EVALUATION REPORT")
        print("="*40)
        
        #  predictions on the test set
        y_pred = self.model.predict(self.X_test)
        
        #
        acc = accuracy_score(self.y_test, y_pred)
        print(f"Accuracy: {acc * 100:.2f}%\n")
        
        print("Confusion Matrix:")
        cm = confusion_matrix(self.y_test, y_pred)
        print(f" [ TN {cm[0][0]} | FP {cm[0][1]} ]")
        print(f" [ FN {cm[1][0]} | TP {cm[1][1]} ]")
        print("\n(TN=Benign Correct, TP=Malicious Correct)\n")
        
        print("Detailed Report:")
        print(classification_report(self.y_test, y_pred, target_names=['Benign', 'Malicious']))

    def save(self):
        if not os.path.exists(MODEL_DIR):
            os.makedirs(MODEL_DIR)
            
        print(f"[-] Saving model to {MODEL_FILE}...")
        joblib.dump(self.model, MODEL_FILE)
        print("[+] Model saved successfully.")

if __name__ == "__main__":
    try:
        trainer = ModelTrainer()
        trainer.load_and_clean_data()
        trainer.train()
        trainer.evaluate()
        trainer.save()
    except Exception as e:
        print(f"\n[!] Error during training: {e}")
