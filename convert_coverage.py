import json
import pandas as pd

with open("coverage_report.json", "r") as f:
    data = json.load(f)

coverage_data = []
for filename, details in data["files"].items():
    coverage_data.append({
        "File": filename,
        "Executed Lines": len(details["executed_lines"]),
        "Missing Lines": len(details["missing_lines"]),
        "Excluded Lines": len(details["excluded_lines"]),
        "Line Coverage (%)": details["summary"]["percent_covered"],
    })
df = pd.DataFrame(coverage_data)
df.to_csv("coverage_report.csv", index=False)

print("Coverage report saved as coverage_report.csv")
