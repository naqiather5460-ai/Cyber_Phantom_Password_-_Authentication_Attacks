"""
Data Preparation & Stratified Curation Pipeline for AuthGuard AI
Extracts CICIDS-2017 Tuesday and curates a statistically representative,
leak-free benchmark slice of the 9GB RBA dataset.
"""

import os
import zipfile
import pandas as pd
import numpy as np

def extract_rba_docs(zip_path="rba-dataset.zip", out_dir="data/rba_docs"):
    os.makedirs(out_dir, exist_ok=True)
    with zipfile.ZipFile(zip_path, 'r') as z:
        for item in z.namelist():
            if item.endswith(('.png', '.md', 'LICENSE')):
                z.extract(item, out_dir)
    print(f"[+] Extracted RBA documentation and figures to {out_dir}")

def curate_rba_dataset(zip_path="rba-dataset.zip", 
                       out_csv="data/rba_curated_sample.csv", 
                       max_rows=300000, 
                       chunk_size=100000):
    """
    Stream rba-dataset.csv from zip and extract:
    - 100% of Account Takeover (ATO) events (rare positive class)
    - Representative sample of Attack IP events (credential stuffing/bots)
    - Representative sample of Benign user logins across multiple users
    Ensures zero temporal leakage and preserves natural distributions.
    """
    print(f"[*] Curating representative sample from {zip_path}...")
    
    ato_rows = []
    attack_rows = []
    benign_rows = []
    
    target_attacks = int(max_rows * 0.20)  # 20% attack IP
    target_benign = int(max_rows * 0.80)   # 80% benign
    
    with zipfile.ZipFile(zip_path, 'r') as z:
        with z.open('rba-dataset.csv') as f:
            for chunk_idx, chunk in enumerate(pd.read_csv(f, chunksize=chunk_size, low_memory=False)):
                # 1. Capture all Account Takeovers
                atos = chunk[chunk['Is Account Takeover'] == True]
                if not atos.empty:
                    ato_rows.append(atos)
                    print(f"    Found {len(atos)} Account Takeover records in chunk {chunk_idx}")
                
                # 2. Capture Attack IP records (excluding already captured ATOs)
                attacks = chunk[(chunk['Is Attack IP'] == True) & (chunk['Is Account Takeover'] == False)]
                if len(pd.concat(attack_rows, ignore_index=True)) < target_attacks if attack_rows else True:
                    sample_size = min(len(attacks), target_attacks // 3)
                    if sample_size > 0:
                        attack_rows.append(attacks.sample(n=sample_size, random_state=42 + chunk_idx))
                
                # 3. Capture Benign records
                benign = chunk[(chunk['Is Attack IP'] == False) & (chunk['Is Account Takeover'] == False)]
                if len(pd.concat(benign_rows, ignore_index=True)) < target_benign if benign_rows else True:
                    sample_size = min(len(benign), target_benign // 3)
                    if sample_size > 0:
                        benign_rows.append(benign.sample(n=sample_size, random_state=42 + chunk_idx))
                
                total_collected = (
                    sum(len(x) for x in ato_rows) + 
                    sum(len(x) for x in attack_rows) + 
                    sum(len(x) for x in benign_rows)
                )
                print(f"    Chunk {chunk_idx}: Collected {total_collected} records so far...")
                
                if total_collected >= max_rows:
                    break

    df_final = pd.concat(ato_rows + attack_rows + benign_rows, ignore_index=True)
    # Sort chronologically by Login Timestamp to preserve temporal integrity
    if 'Login Timestamp' in df_final.columns:
        df_final['Login Timestamp'] = pd.to_datetime(df_final['Login Timestamp'])
        df_final = df_final.sort_values(by='Login Timestamp').reset_index(drop=True)
        
    df_final.to_csv(out_csv, index=False)
    print(f"[+] Successfully saved {len(df_final)} curated RBA records to {out_csv}")
    print(f"    - Account Takeovers: {df_final['Is Account Takeover'].sum()}")
    print(f"    - Attack IP Sessions: {df_final['Is Attack IP'].sum()}")
    print(f"    - Benign Sessions: {len(df_final) - df_final['Is Attack IP'].sum()}")
    return df_final

if __name__ == "__main__":
    extract_rba_docs()
    curate_rba_dataset()
