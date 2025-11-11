# backend/parallel_analyzer.py
from mpi4py import MPI
import os, re, csv, json, pandas as pd
from io import StringIO

comm = MPI.COMM_WORLD
rank = comm.Get_rank()
size = comm.Get_size()

IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"

def load_data(file_path):
    ext = os.path.splitext(file_path)[1].lower()
    try:
        if ext == ".csv":
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.rstrip("\n") for line in f if line.strip()]
        elif ext in [".xlsx", ".xls"]:
            df = pd.read_excel(file_path)
            return ["\t".join(map(str, row.values)) for _, row in df.iterrows() if not row.isnull().all()]
        elif ext == ".json":
            with open(file_path, "r", encoding="utf-8") as f:
                data = json.load(f)
                if isinstance(data, list):
                    return [str(item) for item in data]
                elif isinstance(data, dict):
                    return [f"{k}: {v}" for k, v in data.items()]
                else:
                    return [str(data)]
        elif ext in [".log", ".txt"]:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                return [line.rstrip("\n") for line in f if line.strip()]
        else:
            raise ValueError(f"Unsupported file type: {ext}")
    except Exception as e:
        raise RuntimeError(f"Error loading file {file_path}: {e}")


def sniff_delimiter(sample_text):
    """
    Try csv.Sniffer to detect a delimiter; fallback to common choices.
    """
    try:
        sniffer = csv.Sniffer()
        dialect = sniffer.sniff(sample_text[:4096])
        return dialect.delimiter
    except Exception:
        # fallback decisions
        if "\t" in sample_text:
            return "\t"
        if ";" in sample_text:
            return ";"
        if "," in sample_text:
            return ","
        # default: whitespace (one or more spaces)
        return r"\s+"


def find_src_col(df):
    cols = [str(c).lower() for c in df.columns]
    # try name-based
    for name in cols:
        if any(k in name for k in ("src", "source", "sip", "src_ip", "source_ip")):
            return df.columns[cols.index(name)]
    # try to find a column with many IP-like values
    for col in df.columns:
        sample = df[col].astype(str).head(200)
        ip_count = sample.str.count(IP_REGEX).sum()
        if ip_count >= max(1, min(10, len(sample)//10)):
            return col
    # fallback: first column
    return df.columns[0]


def find_attack_col(df):
    cols = [str(c).lower() for c in df.columns]
    for name in cols:
        if any(k in name for k in ("attack", "label", "cat", "class")):
            return df.columns[cols.index(name)]
    # scan last few columns for non-numeric textual labels (like 'Exploits')
    tail_cols = df.columns[-6:]
    for col in reversed(tail_cols):
        # check proportion of non-numeric / textual entries
        sample = df[col].astype(str).fillna("").head(500)
        non_numeric = sample.str.match(r"^-?\d+(\.\d+)?$").apply(lambda x: not x).sum()
        if non_numeric >= 1:  # at least some textual entries
            return col
    return None


def analyze_logs(log_chunk):
    suspicious_ips = {}

    # quick check: is this tabular-like (has commas/tabs/semicolons or many columns)?
    sample = "\n".join(log_chunk[:10])
    is_tabular = any(d in sample for d in [",", "\t", ";"]) or re.search(r"\s{2,}", sample)

    if is_tabular:
        try:
            sep = sniff_delimiter(sample)
            # Use pandas to parse; allow regex sep for whitespace
            if sep == r"\s+":
                df = pd.read_csv(StringIO("\n".join(log_chunk)), sep=r"\s+", engine="python", header=0)
            else:
                df = pd.read_csv(StringIO("\n".join(log_chunk)), sep=sep, engine="python", header=0)
            # normalize cols
            df.columns = [str(c).strip() for c in df.columns]

            # If header looks numeric (no header present), set generic headers
            if all(str(c).strip().isdigit() for c in df.columns):
                df.columns = [f"col{i}" for i in range(len(df.columns))]

            src_col = find_src_col(df)
            attack_col = find_attack_col(df)

            # iterate rows
            for _, row in df.iterrows():
                src_val = str(row.get(src_col, "")).strip() if src_col in df.columns else ""
                if not src_val or src_val.lower() == "nan":
                    continue
                # if attack column exists, prefer it
                if attack_col and str(row.get(attack_col, "")).strip():
                    attack_val = str(row.get(attack_col, "")).strip().lower()
                    # treat numeric-like or empty as non-attack
                    if attack_val not in ("0", "-", "normal", "benign", "none", ""):
                        suspicious_ips[src_val] = suspicious_ips.get(src_val, 0) + 1
                else:
                    # fallback: if row has any textual labels in trailing columns, count it
                    tail = row.iloc[-6:].astype(str).str.strip().str.lower().tolist()
                    if any(t and not re.match(r"^-?\d+(\.\d+)?$", t) for t in tail):
                        suspicious_ips[src_val] = suspicious_ips.get(src_val, 0) + 1

            # final fallback: if nothing found but df has many rows, count frequency of src_ip
            if not suspicious_ips and src_col:
                freqs = df[src_col].astype(str).value_counts().to_dict()
                # keep only those with count > 1 to avoid noise
                for ip, cnt in freqs.items():
                    if re.match(IP_REGEX, str(ip)) and cnt > 1:
                        suspicious_ips[ip] = cnt

        except Exception as e:
            # parsing failed, fallback to regex IP extraction
            print(f"[WARN] tabular parse failed: {e}")
            for line in log_chunk:
                for ip in re.findall(IP_REGEX, line):
                    suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

    else:
        # plain log lines, use existing pattern
        pattern = r"Failed password for.*from (" + IP_REGEX + r")"
        for line in log_chunk:
            m = re.search(pattern, line)
            if m:
                ip = m.group(1)
                suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1
            else:
                # also catch any IPs (for datasets that don't use the 'Failed password' phrase)
                for ip in re.findall(IP_REGEX, line):
                    suspicious_ips[ip] = suspicious_ips.get(ip, 0) + 1

    return suspicious_ips


def main():
    log_path = os.environ.get("LOG_FILE_PATH")
    if not log_path:
        log_path = os.path.join(os.path.dirname(__file__), "..", "sample_logs", "auth.log")

    if rank == 0:
        logs = load_data(log_path)
        if not logs:
            print("No readable data found in file.")
            return
        # debug print (only on root)
        print(f"[DEBUG] Loaded {len(logs)} lines from {log_path}")
        chunks = [logs[i::size] for i in range(size)]
    else:
        chunks = None

    log_chunk = comm.scatter(chunks, root=0)
    result = analyze_logs(log_chunk)
    all_results = comm.gather(result, root=0)

    if rank == 0:
        final = {}
        for r in all_results:
            for ip, c in r.items():
                final[ip] = final.get(ip, 0) + c

        if not final:
            final = {"message": "No suspicious IPs or attack patterns detected."}

        os.makedirs(os.path.join(os.path.dirname(__file__), "results"), exist_ok=True)
        result_path = os.path.join(os.path.dirname(__file__), "results", "analysis_result.json")
        with open(result_path, "w", encoding="utf-8") as f:
            json.dump(final, f, indent=4, ensure_ascii=False)

        print("Analysis complete. Results saved at:", result_path)


if __name__ == "__main__":
    main()
