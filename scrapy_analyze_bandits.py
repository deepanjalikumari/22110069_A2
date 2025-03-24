import json
import os
import re
import csv

RESULTS_DIR = "bandit_result"

COMMIT_REGEX = re.compile(r"bandit_scrapy_([a-f0-9]+)\.json")

def analyze_bandit_file(file_path):
    """Extracts security issue statistics from a Bandit JSON output file."""
    with open(file_path, 'r') as f:
        data = json.load(f)

    results = data.get("results", [])

    confidence_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0}
    unique_cwes = set()

    for issue in results:
        # Count confidence levels
        confidence = issue.get("issue_confidence", "UNKNOWN")
        if confidence in confidence_counts:
            confidence_counts[confidence] += 1

        severity = issue.get("issue_severity", "UNKNOWN")
        if severity in severity_counts:
            severity_counts[severity] += 1

        cwe_data = issue.get("issue_cwe", {})  # <-- Fix: Use `issue_cwe`
        if isinstance(cwe_data, dict):
            cwe_id = cwe_data.get("id")
            if cwe_id:
                unique_cwes.add(cwe_id)

    return {
        "Confidence Counts": confidence_counts,
        "Severity Counts": severity_counts,
        "Unique CWE IDs": sorted(unique_cwes) if unique_cwes else ["None"]
    }

all_results = {}

for file_name in sorted(os.listdir(RESULTS_DIR)):
    match = COMMIT_REGEX.match(file_name)
    if match:
        commit_id = match.group(1)
        file_path = os.path.join(RESULTS_DIR, file_name)
        all_results[commit_id] = analyze_bandit_file(file_path)

for commit_id, summary in all_results.items():
    print(f"\n📌 **Analysis for Commit {commit_id}:**")
    print(json.dumps(summary, indent=4))

csv_file = "bandit_summary.csv"
with open(csv_file, "w", newline="") as f:
    writer = csv.writer(f)
    writer.writerow(["Commit", "High Confidence", "Medium Confidence", "Low Confidence",
                     "High Severity", "Medium Severity", "Low Severity", "Unique CWE IDs"])
    
    for commit_id, summary in all_results.items():
        writer.writerow([
            commit_id,
            summary["Confidence Counts"]["HIGH"],
            summary["Confidence Counts"]["MEDIUM"],
            summary["Confidence Counts"]["LOW"],
            summary["Severity Counts"]["HIGH"],
            summary["Severity Counts"]["MEDIUM"],
            summary["Severity Counts"]["LOW"],
            "; ".join(map(str, summary["Unique CWE IDs"])) if summary["Unique CWE IDs"] else "None"
        ])

print(f"\n✅ Summary saved to `{csv_file}`")
