import pandas as pd
import numpy as np
import os
from typing import Dict, Tuple, Optional

CSV_FILE_PATH = "risks.csv"

KEYWORD_MAP: Dict[str, Tuple[int, int]] = {
    "data breach": (4, 5),
    "phishing": (3, 4),
    "ransomware": (5, 5),
    "insider threat": (3, 4),
    "system failure": (2, 3),
}

def load_df() -> pd.DataFrame:
    """Load risks from CSV or return an empty DataFrame."""
    if os.path.exists(CSV_FILE_PATH):
        return pd.read_csv(CSV_FILE_PATH)
    else:
        columns = [
            "risk_id", "risk_name", "risk_description",
            "likelihood", "impact", "risk_score",
            "risk_cell", "owner", "mitigation", "timestamp"
        ]
        return pd.DataFrame(columns=columns)

def save_record(record: Dict) -> None:
    """Append a dictionary record to 'risks.csv'."""
    df = load_df()
    new_df = pd.DataFrame([record])
    df = pd.concat([df, new_df], ignore_index=True)
    df.to_csv(CSV_FILE_PATH, index=False)

def score_risk(likelihood: int, impact: int) -> int:
    """Calculate risk score."""
    return likelihood * impact

def auto_assign(description: str) -> Optional[Tuple[int, int]]:
    """Auto-assign likelihood and impact based on keywords."""
    desc = description.lower().strip()
    for keyword, values in KEYWORD_MAP.items():
        if keyword in desc:
            return values
    return None

def build_matrix(df: pd.DataFrame) -> np.ndarray:
    """Build 5x5 matrix of risks by likelihood/impact."""
    matrix = np.zeros((5, 5), dtype=int)
    for _, row in df.iterrows():
        try:
            likelihood = int(row["likelihood"]) - 1
            impact = int(row["impact"]) - 1
            if 0 <= likelihood < 5 and 0 <= impact < 5:
                matrix[4 - impact, likelihood] += 1
        except (ValueError, KeyError, TypeError):
            continue
    return matrix
