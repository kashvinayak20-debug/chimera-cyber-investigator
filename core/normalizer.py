"""
CHIMERA Log Normalizer & Temporal Sorter
Handles heterogeneous, out-of-order enterprise security logs (JSON / CSV),
parses timestamps to standard UTC, resolves entity types, and sorts chronologically.
"""

import pandas as pd
import json
import re
from datetime import datetime

class LogNormalizer:
    @staticmethod
    def load_and_normalize(source_data):
        """
        Accepts either a file path (str), a list of dicts, or a pandas DataFrame.
        Returns a sorted, normalized pandas DataFrame and metadata.
        """
        if isinstance(source_data, str):
            if source_data.endswith('.json'):
                with open(source_data, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                df = pd.DataFrame(data)
            elif source_data.endswith('.csv'):
                df = pd.read_csv(source_data)
            else:
                raise ValueError("Unsupported file format. Please provide .json or .csv")
        elif isinstance(source_data, list):
            df = pd.DataFrame(source_data)
        elif isinstance(source_data, pd.DataFrame):
            df = source_data.copy()
        else:
            raise ValueError("Input must be a file path, list of dicts, or pandas DataFrame")

        # Normalize column names to lowercase
        df.columns = [c.lower().strip() for c in df.columns]

        # Identify timestamp column
        time_cols = ['timestamp', 'time', 'datetime', 'timecreated', '@timestamp', 'event_time']
        found_time_col = None
        for col in time_cols:
            if col in df.columns:
                found_time_col = col
                break
        
        if not found_time_col:
            raise KeyError("No timestamp column detected in input logs.")

        # Parse timestamp to UTC datetime
        df['parsed_time'] = pd.to_datetime(df[found_time_col], utc=True, errors='coerce')
        
        # Track initial disorder
        is_initially_sorted = df['parsed_time'].is_monotonic_increasing
        out_of_order_count = 0
        if not is_initially_sorted:
            # Count events whose arrival is earlier than prior event in raw sequence
            diffs = df['parsed_time'].diff()
            out_of_order_count = int((diffs < pd.Timedelta(seconds=0)).sum())

        # Sort chronologically by true event timestamp (Pillar 2: Temporal Reasoning)
        df = df.sort_values(by='parsed_time').reset_index(drop=True)

        # Standardize mandatory fields
        if 'source_entity' not in df.columns:
            df['source_entity'] = df.get('source', df.get('src_ip', df.get('user', 'UNKNOWN_SRC')))
        if 'target_entity' not in df.columns:
            df['target_entity'] = df.get('target', df.get('dest_ip', df.get('host', 'UNKNOWN_DST')))
        if 'action' not in df.columns:
            df['action'] = df.get('event_type', df.get('activity', 'EVENT'))
        if 'log_id' not in df.columns:
            df['log_id'] = [f"LOG-RAW-{i:05d}" for i in range(len(df))]
        if 'details' not in df.columns:
            df['details'] = df['action'].astype(str) + " from " + df['source_entity'].astype(str) + " to " + df['target_entity'].astype(str)

        # Classify entity categories
        df['src_type'] = df['source_entity'].apply(LogNormalizer._classify_entity)
        df['dst_type'] = df['target_entity'].apply(LogNormalizer._classify_entity)

        metadata = {
            "total_logs": len(df),
            "start_time": df['parsed_time'].min().isoformat() if not df.empty else None,
            "end_time": df['parsed_time'].max().isoformat() if not df.empty else None,
            "was_out_of_order": not is_initially_sorted,
            "out_of_order_inversions": out_of_order_count,
            "unique_sources": df['source_entity'].nunique(),
            "unique_targets": df['target_entity'].nunique()
        }

        return df, metadata

    @staticmethod
    def _classify_entity(entity_val):
        entity = str(entity_val).strip()
        # IP Address check
        if re.match(r'^(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?:/[0-9]{1,2})?$', entity):
            if entity.startswith("10.") or entity.startswith("192.168.") or entity.startswith("172.16."):
                return "INTERNAL_IP"
            return "EXTERNAL_IP"
        # Process check (.exe, .sh, .bin)
        if entity.lower().endswith(('.exe', '.dll', '.bin', '.sh', '.py')):
            return "PROCESS"
        # Critical Infrastructure Hosts
        if any(h in entity.upper() for h in ["DC-", "FS-", "DB-", "DOMAIN_CONTROLLER"]):
            return "CRITICAL_SERVER"
        # Workstations
        if "WS-" in entity.upper():
            return "WORKSTATION"
        # Service Accounts
        if "SVC-" in entity.lower() or "admin" in entity.lower():
            return "PRIVILEGED_ACCOUNT"
        # User accounts (e.g. name.surname or standard username)
        if "." in entity or "alice" in entity or "bob" in entity or "user" in entity:
            return "USER"
        return "GENERIC_ASSET"
