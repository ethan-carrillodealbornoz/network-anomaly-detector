import io
import zipfile
import pandas as pd
import requests

DATASET_URL = "https://cdn.services-k8s.prod.aws.htb.systems/content/modules/292/KDD_dataset.zip"

COLUMNS = [
    "duration",
    "protocol_type",
    "service",
    "flag",
    "src_bytes",
    "dst_bytes",
    "land",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "logged_in",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "is_host_login",
    "is_guest_login",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
    "attack",
    "level",
]

NUMERIC_FEATURES = [
    "duration",
    "src_bytes",
    "dst_bytes",
    "wrong_fragment",
    "urgent",
    "hot",
    "num_failed_logins",
    "num_compromised",
    "root_shell",
    "su_attempted",
    "num_root",
    "num_file_creations",
    "num_shells",
    "num_access_files",
    "num_outbound_cmds",
    "count",
    "srv_count",
    "serror_rate",
    "srv_serror_rate",
    "rerror_rate",
    "srv_rerror_rate",
    "same_srv_rate",
    "diff_srv_rate",
    "srv_diff_host_rate",
    "dst_host_count",
    "dst_host_srv_count",
    "dst_host_same_srv_rate",
    "dst_host_diff_srv_rate",
    "dst_host_same_src_port_rate",
    "dst_host_srv_diff_host_rate",
    "dst_host_serror_rate",
    "dst_host_srv_serror_rate",
    "dst_host_rerror_rate",
    "dst_host_srv_rerror_rate",
]

DOS_ATTACKS = {
    "apache2",
    "back",
    "land",
    "neptune",
    "mailbomb",
    "pod",
    "processtable",
    "smurf",
    "teardrop",
    "udpstorm",
    "worm",
}
PROBE_ATTACKS = {"ipsweep", "mscan", "nmap", "portsweep", "saint", "satan"}
PRIVILEGE_ATTACKS = {
    "buffer_overflow",
    "loadmdoule",
    "loadmodule",
    "perl",
    "ps",
    "rootkit",
    "sqlattack",
    "xterm",
}
ACCESS_ATTACKS = {
    "ftp_write",
    "guess_passwd",
    "httptunnel",
    "http_tunnel",
    "imap",
    "multihop",
    "named",
    "phf",
    "sendmail",
    "snmpgetattack",
    "snmpguess",
    "spy",
    "warezclient",
    "warezmaster",
    "xclock",
    "xsnoop",
}


def download_and_load_raw(data_dir: str) -> pd.DataFrame:
  """Descarga y carga el dataset comprimido NSL-KDD."""
  response = requests.get(DATASET_URL)
  response.raise_for_status()

  with zipfile.ZipFile(io.BytesIO(response.content)) as z:
    z.extractall(data_dir)

  df = pd.read_csv(f"{data_dir}/KDD+.txt", names=COLUMNS)
  return df


def map_attack_categories(df: pd.DataFrame) -> pd.Series:
  """Convierte la columna 'attack' en clases multiclase numéricas (0 a 4)."""
  cleaned_attack = df["attack"].astype(str).str.strip().str.lower()

  def _map_fn(name):
    if name == "normal":
      return 0
    elif name in DOS_ATTACKS:
      return 1
    elif name in PROBE_ATTACKS:
      return 2
    elif name in PRIVILEGE_ATTACKS:
      return 3
    elif name in ACCESS_ATTACKS:
      return 4
    else:
      return 1

  return cleaned_attack.apply(_map_fn)


def build_feature_matrix(df: pd.DataFrame) -> pd.DataFrame:
  """Aplica One-Hot Encoding y une las variables cuantitativas."""
  features_to_encode = ["protocol_type", "service"]
  encoded = pd.get_dummies(df[features_to_encode], dtype=int)
  X = encoded.join(df[NUMERIC_FEATURES])
  return X