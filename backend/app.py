from flask import Flask, request, render_template, send_file
import subprocess, os, sys, json
import matplotlib
matplotlib.use('Agg')  # Use non-interactive backend (no Tkinter)
import matplotlib.pyplot as plt

from datetime import datetime

app = Flask(__name__)

# === PATH SETUP ===
BASE_DIR = os.path.dirname(__file__)
RESULTS_DIR = os.path.join(BASE_DIR, "results")
SAMPLE_LOG_DIR = os.path.join(BASE_DIR, "..", "sample_logs")
os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(SAMPLE_LOG_DIR, exist_ok=True)


# === HOME PAGE ===
@app.route("/")
def home():
    return render_template("index.html")


# === ANALYZE FILE ===
@app.route("/analyze", methods=["POST"])
def analyze():
    try:
        file = request.files.get("logfile")
        if not file:
            return render_template("index.html", error="Please upload a file to analyze (log, csv, json, or Excel).")

        # Save uploaded file
        file_path = os.path.join(SAMPLE_LOG_DIR, file.filename)
        file.save(file_path)

        # Prepare environment
        python_path = sys.executable
        analyzer_path = os.path.abspath(os.path.join(BASE_DIR, "parallel_analyzer.py"))
        env = os.environ.copy()
        env["LOG_FILE_PATH"] = file_path

        # Run MPI Analyzer
        cmd = ["mpiexec", "-n", "4", python_path, analyzer_path]
        subprocess.run(cmd, check=True, env=env)

        # Load results
        result_file = os.path.join(RESULTS_DIR, "analysis_result.json")
        if not os.path.exists(result_file):
            raise FileNotFoundError("No results were generated from the analysis.")

        with open(result_file, "r", encoding="utf-8") as f:
            data = json.load(f)

        # === Safety net: Always fresh results ===
        chart_path = os.path.join(RESULTS_DIR, "chart.png")
        if os.path.exists(chart_path):
            os.remove(chart_path)

        # === Handle empty or message-only results ===
        if not data or "message" in data:
            return render_template(
                "index.html",
                results={"message": "No suspicious IPs or attacks detected in this file."},
                chart=None,
            )

        # === Generate chart ===
        ips = list(data.keys())
        counts = list(data.values())
        if ips:
            plt.figure(figsize=(9, 4))
            plt.bar(ips, counts, color="#007BFF")
            plt.xlabel("IP Address")
            plt.ylabel("Suspicious Activity Count")
            plt.title("Parallel Log Analyzer Results")
            plt.xticks(rotation=25)
            plt.tight_layout()
            plt.savefig(chart_path)
            plt.close()

        # === Add metadata ===
        meta_info = {
            "file_name": file.filename,
            "analyzed_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        }

        return render_template("index.html", results=data, meta=meta_info, chart="chart.png")


    except subprocess.CalledProcessError as e:
        return render_template("index.html", error=f"Error during MPI execution: {str(e)}")

    except Exception as e:
        return render_template("index.html", error=f"Unexpected Error: {str(e)}")


# === CHART ROUTE ===
@app.route("/chart")
def chart():
    chart_path = os.path.join(RESULTS_DIR, "chart.png")
    if os.path.exists(chart_path):
        return send_file(chart_path, mimetype='image/png')
    return "No chart available", 404


# === MAIN ===
if __name__ == "__main__":
    app.run(debug=True)
