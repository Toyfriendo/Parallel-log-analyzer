# Parallel Log Analyzer

> **Blazing-fast, MPI-powered log/CSV analyzer with a minimal Flask UI and a clean CLI.**

<p align="left">
  <a href="https://www.python.org/"><img alt="Python" src="https://img.shields.io/badge/Python-3.9%20%7C%203.10%20%7C%203.11-blue"></a>
  <a href="#"><img alt="MPI" src="https://img.shields.io/badge/MPI-mpi4py%20%7C%20OpenMPI%2FMPICH-purple"></a>
  <a href="https://flask.palletsprojects.com/"><img alt="Flask" src="https://img.shields.io/badge/Web-Flask-lightgrey"></a>
  <a href="#"><img alt="Status" src="https://img.shields.io/badge/status-active-success"></a>
</p>

---

## ✨ Overview

Parallel Log Analyzer scans large **log** or **CSV** datasets **in parallel** using [MPI](https://www.mpi-forum.org/) via `mpi4py`. It extracts and aggregates indicators (e.g., **IP addresses**, failed auth attempts), then outputs a **JSON report** and a **bar chart**. Use it either from the **CLI** or via a simple **Flask web UI**.

- **Why parallel?** Splitting the workload across processes helps you chew through multi-GB logs much faster than a single process.
- **Outputs**
  - `backend/results/analysis_result.json` – aggregated counts (e.g., IP → count)
  - `backend/results/chart.png` – bar chart of top offenders
- **Sample data** lives in `sample_logs/`

---

## 🗂️ Project Structure

```
Log_analyser/
├─ backend/
│  ├─ app.py                   # Flask app (upload → parallel analyze → display results/chart)
│  ├─ parallel_analyzer.py     # MPI workers: split work, parse, aggregate, reduce
│  ├─ utils/
│  │  └─ parser.py             # (optional) custom parsers for specific formats
│  ├─ templates/
│  │  └─ index.html            # Upload/Results page (Bootstrap)
│  ├─ static/
│  │  └─ style.css
│  └─ results/                 # Created at runtime (JSON + chart)
├─ frontend/                   # (placeholder for future UI work)
└─ sample_logs/
   ├─ auth.log
   ├─ Linux_2k.log
   ├─ UNSW-NB15_4.csv
   ├─ UNSW_NB15_testing-set.csv
   └─ UNSW_NB15_training-set.csv
```

> Tip: The repository snapshot may include a local virtual environment folder. You **don’t need** that—create your own fresh venv instead.

---

## ⚙️ Prerequisites

| Component | Required | Notes |
|---|---|---|
| Python | 3.9–3.11 | Other recent 3.x may work |
| MPI runtime | OpenMPI / MPICH / MSMPI | `mpiexec` must be in your `PATH` |
| Python pkgs | `mpi4py`, `flask`, `matplotlib`, `pandas` | Install after MPI runtime |

**Install MPI (examples)**  
- **Ubuntu/Debian**: `sudo apt-get install -y libopenmpi-dev openmpi-bin`  
- **macOS (Homebrew)**: `brew install open-mpi`  
- **Windows**: Install Microsoft MPI or use WSL2 with OpenMPI.

---

## 🚀 Quick Start

### 1) Create & activate a virtual environment
```bash
# Linux/macOS
python3 -m venv .venv
source .venv/bin/activate

# Windows PowerShell
python -m venv .venv
.venv\Scripts\Activate.ps1
```

### 2) Install dependencies
```bash
pip install mpi4py flask matplotlib pandas
```

### 3A) Run the **CLI** analyzer
```bash
cd Log_analyser/backend
mpiexec -n 4 python parallel_analyzer.py ../sample_logs/auth.log
# Results:
#   backend/results/analysis_result.json
#   (Chart will be created by the web UI or by a plotting step in the app)
```

### 3B) Run the **Web UI**
```bash
cd Log_analyser/backend
python app.py
# Open http://127.0.0.1:5000 in your browser
# 1) Upload a .log or .csv
# 2) Click "Analyze File"
# 3) See the results table and the chart
```

---

## 🧰 Usage

### CLI
```bash
mpiexec -n <NUM_WORKERS> python backend/parallel_analyzer.py <PATH_TO_FILE>
```
- Accepts `.log` and `.csv` files.
- Splits input across ranks, extracts indicators (e.g., IPs), aggregates counts, and writes JSON.

### Web UI (Flask)
- Upload a file on `/` (home page).
- On submit, the server spawns `mpiexec` to run the analyzer.
- After completion, it loads the JSON and renders a bar chart (served at `/chart`).

**CLI vs Web (at a glance)**

| Mode | Best for | Pros | Trade-offs |
|---|---|---|---|
| CLI | Automation, batch runs, CI | Scriptable, fast, minimal deps | No built-in chart unless you run the plotting step |
| Web | Ad-hoc analysis, demos | Simple upload UI, chart preview | Requires running Flask, spawn permissions for `mpiexec` |

---

## 🔌 Configuration & Customization

Open `backend/parallel_analyzer.py` and adjust:

- **IP regex** (IPv4 example):
  ```python
  IP_REGEX = r"(?:\d{1,3}\.){3}\d{1,3}"
  ```
- **Event heuristics**: Count what matters to you (e.g., `"Failed password for"` in auth logs, firewall `DROP`, etc.).
- **Top-N visualization**: Limit how many offenders to show on the chart.

For specialized formats, add helpers in `backend/utils/parser.py`:
```python
def parse_syslog_line(line: str) -> dict:
    # return {"ip": "...", "is_failed": True/False, ...}
```

**CSV support**: The analyzer detects `.csv` and uses `pandas`. Update column names (e.g., `srcip`, `label`) per dataset.

---

## 🧪 Examples

```bash
# Analyze a Linux auth log with 8 workers
cd Log_analyser/backend
mpiexec -n 8 python parallel_analyzer.py ../sample_logs/Linux_2k.log

# Start the web UI
cd Log_analyser/backend
python app.py
```

Outputs:

- `backend/results/analysis_result.json`
- `backend/results/chart.png`

---

## 🩺 Troubleshooting

| Symptom | Likely Cause | Fix |
|---|---|---|
| `mpiexec: command not found` | MPI not installed / not on PATH | Install OpenMPI/MPICH (Linux/macOS) or MSMPI (Windows) |
| `ModuleNotFoundError: mpi4py` | Missing dependency | Install MPI runtime, then `pip install mpi4py` |
| Flask shows no chart | Chart not rendered yet | Ensure analysis ran; confirm `results/` is writable |
| Empty or sparse results | Regex / heuristics too strict | Loosen patterns; add more event rules in analyzer/parser |
| CSV loads but no counts | Wrong column names | Update CSV parsing logic to match your dataset |

---

## 🧱 Security & Deployment Notes

- Avoid `debug=True` for production deployments.
- Use a WSGI server (e.g., `gunicorn`) and a process manager (`supervisor`, `systemd`).
- Ensure the Flask process can spawn `mpiexec` and has write access to `backend/results/`.
- If containerized, mount a persistent volume for `uploads/` and `results/`.

---

## 📦 Roadmap (Nice-to-haves)

- `requirements.txt` and `Dockerfile`
- Gzip support (`.gz` logs)
- Time-window filters and Top-N control in UI
- Export CSV/NDJSON alongside JSON
- Pluggable YAML rules for attack signatures

---

## 🤝 Contributing

Issues and PRs are welcome! Please include:
- Reproducible steps and minimal datasets for parsing issues
- Clear descriptions of heuristics or formats you’re adding

---

## 📜 License

Add a license of your choice (e.g., MIT) and include a `LICENSE` file in the repo.

---

## 🧭 TL;DR

- Install MPI + Python deps
- Run **CLI** with `mpiexec -n N python backend/parallel_analyzer.py <file>`
- Or start **Web UI** with `python backend/app.py`, upload, analyze, view chart
- Results land in `backend/results/analysis_result.json` and `chart.png`

**Takeaways:** Parallel processing makes large log analysis fast; the project is customizable, scriptable, and ships with a simple UI for visualization.
