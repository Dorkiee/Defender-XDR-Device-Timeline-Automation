Author: Kehinde Oduyeye
# Defender-XDR-Device-Timeline-Automation.py

Device Timeline Automation is a threat-enrichment automation script designed for Security Operations Centers (SOC).
It ingests IP addresses and URLs from endpoint/network event logs, enriches them through multiple threat-intel sources, and produces a structured, high-fidelity output for triage, hunting, and incident investigation.

Blog post that goes into more details, can be found here: https://www.kehinde-oduyeye.dev/#/blog/1

This tool dramatically reduces repetitive analyst work by automating:

✔ VirusTotal IP/URL enrichment

✔ AlienVault OTX indicator lookups

✔ Scamalytics fraud risk scoring

✔ Azure Table Storage intelligence caching

✔ API deduplication (skip re-enriching observables for 7 days)

✔ Styled DataFrame review & CSV export

## Architecture
TBA

## Features
This script automates multi-source threat-intelligence enrichment for both IP addresses and URLs, combining VirusTotal, AlienVault OTX, and Scamalytics into a single streamlined workflow. It retrieves ASN details, geolocation, malicious vendor detections, OTX pulse associations, and fraud-risk scoring, then aggregates and scores this intelligence for fast analyst review. To optimize performance, it uses Azure Table Storage as a caching layer, preventing repeated lookups for observables seen within the last seven days. The script also enhances SOC usability by automatically generating new enrichment columns, filtering out clean indicators, sorting by threat severity, styling the final DataFrame for readability, and exporting results into a CSV file for reporting or case documentation.

## Repository Structure
├── Analyse Device Timeline.py      # Main enrichment engine
├── README.md                       # Documentation
└── output/
      └── IPV6_Analysis.csv         # Auto-generated result set

## Requirements
Python 3.8+

Install dependencies:

<code> pip install pandas requests azure-data-tables ipython </code>

| Service             | Variable              |
| ------------------- | --------------------- |
| VirusTotal          | `api_key` / `API_KEY` |
| OTX                 | `otx_api_key`         |
| Scamalytics         | `SCAM_api_key`        |
| Azure Table Storage | `table_client`        |

## Configuration
1. Insert Keys
   api_key = "YOUR_VIRUSTOTAL_KEY"
   otx_api_key = "YOUR_OTX_KEY"
   SCAM_api_key = "YOUR_SCAMALYTICS_KEY"
   
2. Initialize Azure Table client
from azure.data.tables import TableClient

table_client = TableClient.from_connection_string(
    conn_str="YOUR_CONNECTION_STRING",
    table_name="ThreatIntelCache"
)

3. Ensure your DataFrame contains:

    RemoteIP
    
    RemoteUrl

New enrichment columns populate automatically.

## Example Output (Truncated)
| RemoteIP       | RemoteUrl        | IP ASN   | IP Country | IP VT Positives | URL ASN | URL Country | URL VT Positives | SA Score | OTX Pulses | Total Positives |
| -------------- | ---------------- | -------- | ---------- | --------------- | ------- | ----------- | ---------------- | -------- | ---------- | --------------- |
| 187.220.101.7  | tor-exit.example | AS200013 | DE         | 12              | AS14061 | US          | 3                | 95       | 7          | 15              |
| 44.151.105.243 | malicious.site   | AS4808   | RU         | 4               | AS13335 | US          | 0                | 60       | 1          | 4               |
| 13.42.25.34    | —                | AS397703 | US         | 2               | —       | —           | —                | 0        | 0          | 2               |


## Console Output Example
Data for URL malicious.site not found, making API call.
IP address 187.220.101.7 - from the country DE, with 12 VT positives detected...
IP address 44.151.105.243 was not observed to be malicious.
Entity upserted successfully: {'PartitionKey': 'IP', 'RowKey': '187.220.101.7', ... }
IP Details:
Saving results to IPV6_Analysis.csv...

## What I Learned While Building This
I gained deep insight into how threat-intelligence pipelines function within real SOC environments and how important efficiency and data consistency are during investigations. I learned the significance of implementing API caching to avoid rate limits and unnecessary overhead, especially when working with platforms like VirusTotal and OTX that can be queried frequently during active incidents. Normalizing URLs for VirusTotal required precise Base64 handling, which emphasized the importance of correct preprocessing when dealing with external threat-intel APIs. I also saw firsthand how different providers return varied and sometimes incomplete schemas, reinforcing the need for defensive coding and robust error handling. Most importantly, I learned how powerful automated enrichment can be in reducing analyst workload—the addition of scoring, filtering, and well-structured outputs dramatically improves the speed and clarity of investigations, helping SOC teams quickly identify meaningful indicators without drowning in noise.

## Contributions
Contributions are welcome!
