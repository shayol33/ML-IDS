from flask import Flask, render_template_string
import json

app = Flask(__name__)

LOG_FILE = "prediction.log"

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>IDS Log Viewer</title>
    <style>
        body { font-family: Arial, sans-serif; background-color: #f4f4f4; text-align: center; padding: 20px; }
        .log-container { width: 80%; margin: auto; background: white; padding: 20px; border-radius: 10px; box-shadow: 0 0 10px #aaa; }
        table { width: 100%; border-collapse: collapse; margin-top: 10px; }
        th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }
        th { background-color: #343a40; color: white; }
        .benign { background-color: #d4edda; color: #155724; }
        .malicious { background-color: #f8d7da; color: #721c24; }
    </style>
    <script>
        setTimeout(() => { window.location.reload(); }, 500000);
    </script>
</head>
<body>
    <div class="log-container">
        <h2>Intrusion Detection System Logs</h2>
        <table>
            <tr>
                <th>Prediction</th>
                <th>IP Address</th>
                <th>Status</th>
            </tr>
            {% for log in logs %}
            <tr class="{{ 'malicious' if log.brute_force_status['status'] == 'MALICIOUS' else 'benign' }}">
                <td>{{ log.prediction[0] }}</td>
                <td>{{ log.brute_force_status['ip'] if log.brute_force_status['ip'] else 'N/A' }}</td>
                <td>{{ log.brute_force_status['status'] }}</td>
            </tr>
            {% endfor %}
        </table>
    </div>
</body>
</html>
"""

def read_logs():
    """Reads prediction.log and returns all log entries."""
    try:
        with open(LOG_FILE, "r") as file:
            log_entries = [json.loads(log.strip()) for log in file.readlines() if log.strip()]
            return log_entries
    except FileNotFoundError:
        return []

@app.route('/')
def index():
    logs = read_logs()
    return render_template_string(HTML_TEMPLATE, logs=logs)

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5001, debug=True)
