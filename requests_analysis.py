import pandas as pd
import matplotlib.pyplot as plt
import seaborn as sns

# Load Bandit summary data for Requests
csv_file = "bandit_summary3.csv"  # Updated file name for Requests analysis
df = pd.read_csv(csv_file)

# Convert severity columns to numeric (handling missing values)
severity_cols = ["High Confidence", "Medium Confidence", "Low Confidence", 
                 "High Severity", "Medium Severity", "Low Severity"]
df[severity_cols] = df[severity_cols].apply(pd.to_numeric, errors='coerce').fillna(0)

# Replace commit hash with numerical index for better visualization
df['Commit Index'] = range(1, len(df) + 1)

# RQ1: Timeline analysis for High Severity Vulnerabilities (Requests)
plt.figure(figsize=(12, 6))
sns.lineplot(data=df, x='Commit Index', y='High Severity', marker='o', linestyle='-')
plt.xlabel("Commits (Index)")
plt.ylabel("High Severity Issues")
plt.title("Requests: Timeline of High Severity Vulnerability Introduction and Fixes")
plt.tight_layout()
plt.savefig("requests_rq1_high_severity_timeline.png")  # Updated file name
plt.close()

# RQ2: Patterns of vulnerability introduction and elimination (Requests)
plt.figure(figsize=(12, 6))
df_melted = df.melt(id_vars=['Commit Index'], value_vars=['High Severity', 'Medium Severity', 'Low Severity'], 
                     var_name='Severity Level', value_name='Count')
sns.lineplot(data=df_melted, x='Commit Index', y='Count', hue='Severity Level', marker='o', linestyle='-')
plt.xlabel("Commits (Index)")
plt.ylabel("Number of Issues")
plt.title("Requests: Patterns of Different Severity Levels over Commits")
plt.legend(title='Severity Level')
plt.tight_layout()
plt.savefig("requests_rq2_severity_patterns.png")  # Updated file name
plt.close()

# RQ3: Most Frequent CWEs across Requests repository
df["Unique CWE IDs"] = df["Unique CWE IDs"].astype(str)
cwe_series = df["Unique CWE IDs"].str.split("; ").explode()
cwe_counts = cwe_series.value_counts().head(10)

plt.figure(figsize=(10, 5))
sns.barplot(x=cwe_counts.index, y=cwe_counts.values, hue=cwe_counts.index, dodge=False, legend=False, palette="viridis")
plt.xlabel("CWE ID")
plt.ylabel("Frequency")
plt.title("Requests: Top 10 Most Frequent CWEs")
plt.xticks(rotation=45)
plt.tight_layout()
plt.savefig("requests_rq3_cwe_frequencies.png")  # Updated file name
plt.close()

print("✅ Requests research analysis completed. Check the generated plots!")
