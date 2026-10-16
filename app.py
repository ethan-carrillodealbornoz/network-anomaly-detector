import os
import joblib
import pandas as pd
import streamlit as st

st.set_page_config(
    page_title="Network Anomaly Detector", page_icon="🛡️", layout="wide"
)

MODEL_PATH = os.path.join("models", "network_anomaly_detection_model.joblib")


@st.cache_resource
def load_model():
  if not os.path.exists(MODEL_PATH):
    st.error("❌ No se encontró el modelo. Ejecuta `python src/train.py` primero.")
    st.stop()
  return joblib.load(MODEL_PATH)


model = load_model()

st.title("🛡️ Sistema de Detección de Anomalías de Red (IDS)")
st.write(
    "Demostración interactiva de clasificación de tráfico mediante **Random"
    " Forest**."
)

CLASS_LABELS = {
    0: ("✅ Tráfico Normal", "st.success"),
    1: ("🚨 DoS (Denegación de Servicio)", "st.error"),
    2: ("🔍 Probe (Escaneo / Reconocimiento - ej. Nmap)", "st.warning"),
    3: ("⚠️ Privilege Escalation (U2R)", "st.error"),
    4: ("🔑 Unauthorized Access (R2L)", "st.error"),
}

# =========================================================
# BARRA LATERAL: AJUSTE MANUAL COMPLETO
# =========================================================
st.sidebar.header("⚙️ Ajuste Manual de Parámetros")

custom_duration = st.sidebar.number_input(
    "Duración (segundos)", min_value=0, value=0
)
custom_src_bytes = st.sidebar.number_input(
    "Bytes Origen (src_bytes)", min_value=0, value=0
)
custom_dst_bytes = st.sidebar.number_input(
    "Bytes Destino (dst_bytes)", min_value=0, value=0
)
custom_count = st.sidebar.number_input(
    "Conexiones al mismo host (count)", min_value=0, value=400
)
custom_srv_count = st.sidebar.number_input(
    "Conexiones al mismo servicio (srv_count)", min_value=0, value=400
)

# Control crucial para detectar DoS
custom_serror_rate = st.sidebar.slider(
    "Tasa de Errores SYN (serror_rate)",
    min_value=0.0,
    max_value=1.0,
    value=1.0,  # 1.0 = DoS SYN Flood
    step=0.1,
)

custom_protocol = st.sidebar.selectbox(
    "Tipo de Protocolo", ["tcp", "udp", "icmp"]
)
custom_service = st.sidebar.selectbox(
    "Servicio de Red", ["private", "http", "eco_i", "ftp", "smtp"]
)

# =========================================================
# PANEL PRINCIPAL: SELECCIÓN DE MODO
# =========================================================
st.subheader("🧪 Simulación de Tráfico de Red")

SIMULATED_SAMPLES = {
    "Navegación Web Legítima (Normal)": {
        "duration": 0,
        "src_bytes": 215,
        "dst_bytes": 4500,
        "count": 1,
        "srv_count": 1,
        "serror_rate": 0.0,
        "rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "dst_host_count": 10,
        "protocol_type": "tcp",
        "service": "http",
    },
    "Ataque SYN Flood (DoS - Neptune)": {
        "duration": 0,
        "src_bytes": 0,
        "dst_bytes": 0,
        "count": 250,
        "srv_count": 250,
        "serror_rate": 1.0,
        "rerror_rate": 0.0,
        "same_srv_rate": 1.0,
        "dst_host_count": 255,
        "protocol_type": "tcp",
        "service": "private",
    },
    "Escaneo de Puertos (Probe - Nmap)": {
        "duration": 0,
        "src_bytes": 0,
        "dst_bytes": 0,
        "count": 150,
        "srv_count": 1,
        "serror_rate": 0.0,
        "rerror_rate": 1.0,
        "same_srv_rate": 0.01,
        "dst_host_count": 255,
        "protocol_type": "icmp",
        "service": "eco_i",
    },
}

mode = st.radio(
    "Modo de Inferencia:",
    ["Usar Perfil Predefinido", "Usar Valores Manuales de la Barra Lateral"],
)

if mode == "Usar Perfil Predefinido":
  preset_choice = st.selectbox(
      "Seleccionar Perfil:", list(SIMULATED_SAMPLES.keys())
  )
  sample_data = SIMULATED_SAMPLES[preset_choice]
else:
  sample_data = {
      "duration": custom_duration,
      "src_bytes": custom_src_bytes,
      "dst_bytes": custom_dst_bytes,
      "count": custom_count,
      "srv_count": custom_srv_count,
      "serror_rate": custom_serror_rate,
      "rerror_rate": 0.0,
      "same_srv_rate": 1.0,
      "dst_host_count": 255,
      "protocol_type": custom_protocol,
      "service": custom_service,
  }

# =========================================================
# BOTÓN DE EJECUCIÓN E INFERENCIA
# =========================================================
if st.button("🔍 Analizar Tráfico"):
  feature_names = model.feature_names_in_
  input_df = pd.DataFrame(0.0, index=[0], columns=feature_names)

  for col, val in sample_data.items():
    if col in input_df.columns:
      input_df.at[0, col] = float(val)

  proto_col = f"protocol_type_{sample_data['protocol_type']}"
  serv_col = f"service_{sample_data['service']}"

  if proto_col in input_df.columns:
    input_df.at[0, proto_col] = 1.0
  if serv_col in input_df.columns:
    input_df.at[0, serv_col] = 1.0

  prediction = model.predict(input_df)[0]
  probs = model.predict_proba(input_df)[0]

  label_text, alert_type = CLASS_LABELS[prediction]

  st.divider()
  if alert_type == "st.success":
    st.success(f"**Resultado:** {label_text}")
  elif alert_type == "st.warning":
    st.warning(f"**Resultado:** {label_text}")
  else:
    st.error(f"**Resultado:** {label_text}")

  prob_df = pd.DataFrame(
      {
          "Categoría": ["Normal", "DoS", "Probe", "Privilege", "Access"],
          "Probabilidad": probs,
      }
  )
  st.bar_chart(prob_df.set_index("Categoría"))