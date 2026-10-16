import os
import joblib
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import classification_report, f1_score
from sklearn.model_selection import train_test_split

from preprocess import (
    build_feature_matrix,
    download_and_load_raw,
    map_attack_categories,
)

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DATA_DIR = os.path.join(BASE_DIR, "data")
MODELS_DIR = os.path.join(BASE_DIR, "models")


def run_pipeline():
  print("📥 Descargando y cargando dataset...")
  df = download_and_load_raw(DATA_DIR)

  print("⚙️ Procesando características y mapeando variables objetivo...")
  y = map_attack_categories(df)
  X = build_feature_matrix(df)

  print("✂️ Particionando conjunto de datos (Train / Val / Test)...")
  train_X, test_X, train_y, test_y = train_test_split(
      X, y, test_size=0.2, random_state=1337, stratify=y
  )

  multi_train_X, multi_val_X, multi_train_y, multi_val_y = train_test_split(
      train_X, train_y, test_size=0.3, random_state=1337, stratify=train_y
  )

  print("🚀 Entrenando modelo Random Forest...")
  rf = RandomForestClassifier(random_state=1337, n_jobs=-1)
  rf.fit(multi_train_X, multi_train_y)

  print("\n=== EVALUACIÓN EN TEST FINAL ===")
  test_preds = rf.predict(test_X)
  target_names = ["Normal", "DoS", "Probe", "Privilege", "Access"]
  print(classification_report(test_y, test_preds, target_names=target_names))

  os.makedirs(MODELS_DIR, exist_ok=True)
  model_path = os.path.join(MODELS_DIR, "network_anomaly_detection_model.joblib")
  joblib.dump(rf, model_path)
  print(f"💾 Modelo guardado exitosamente en: '{model_path}'")


if __name__ == "__main__":
  run_pipeline()