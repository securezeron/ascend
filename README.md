
# Ascend

Ascend is a comprehensive vulnerability intelligence and scoring engine designed to help security analysts, researchers, and defenders prioritize CVEs effectively. By integrating data from various sources—NVD, EPSS, ZDI, CISA KEV, Google Project Zero, and InTheWild—Ascend computes a final, weighted score for each CVE, enabling informed risk-based decisions.

## Features

- **Multi-Source Data Integration**: Automatically fetch CVE details from:
  - **NVD**: CVSS scoring and vulnerability metadata
  - **EPSS**: Exploit prediction scores and percentiles
  - **ZDI**: Zero Day Initiative advisories
  - **CISA KEV**: Known Exploited Vulnerabilities
  - **Google Project Zero**: Advanced research advisories
  - **InTheWild**: Real-world exploit detections

- **Risk Calculation & Prioritization**:  
  Leverages multiple factors like exploitability, impact scores, CWE and CPE presence, and advisories to produce a tailored “Ascend Score.” This score helps determine which CVEs demand immediate attention.

- **Modular & Extensible**:  
  Built with a modular architecture, Ascend’s underlying fetchers and scoring functions can be easily extended with new data sources or scoring methodologies.

- **Configurable & Scalable**:  
  Supports parallel data fetching for large CVE sets and configurable sorting options (ascending/descending) for result prioritization.

## Getting Started

### Prerequisites

- **Python**: 3.7+
- Ensure that all referenced `src/*_fetcher.py` modules are available and correctly implemented.
- Data directories and files (e.g., `cisa_kev/known_exploited_vulnerabilities.json`, `zdi_rss_feeds`, `inthewild` directory) should be structured as expected by the script.

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/securezeron/Ascend.git
   cd Ascend
   ```

2. **Install dependencies** (if any external packages are required):
   ```bash
   pip install -r requirements.txt
   ```

3. **Prepare data sources**:
   Place CISA KEV JSON, ZDI RSS feeds, and InTheWild data into the specified `base_dir` directory.

### Usage

```bash
python3 cve_processing.py \
    --base_dir /path/to/base_dir \
    --cve_list "CVE-2023-1234,CVE-2023-5678" \
    --nvd_threads 10 \
    --outfile results.json
```

**Common Arguments**:

- `--base_dir <path>`: **(Required)** The directory containing data and auxiliary files.
- `--cve_list <CVE,...>`: A comma-separated list of CVEs to analyze.
- `--cve_file <file_path>`: Load CVEs from a JSON or text file.
- `--cve_dir <dir_path>`: Load CVEs from all compatible files in a specified directory.
- `--sort_order <ascending|descending>`: Sort final results by score. Default is `descending`.
- `--config <config_file>`: Load configuration from a JSON config file.
- `--write_config <config_file>`: Write the current configuration to a file for future use.
- `--outfile <filename>`: Specify the output JSON file for results. Default: `results.json`.
- `--nvd_threads <int>`: Number of threads to speed up NVD fetching. Required.

### Examples

- **Direct CVE Input**:
  ```bash
  python3 main.py --base_dir ./data \
                            --cve_list "CVE-2023-1234,CVE-2022-0987" \
                            --nvd_threads 5
  ```

- **From File**:
  ```bash
  python3 cve_processing.py --base_dir ./data \
                            --cve_file ./cves.txt \
                            --nvd_threads 10
  ```

- **From Directory**:
  ```bash
  python3 cve_processing.py --base_dir ./data \
                            --cve_dir ./cve_inputs \
                            --nvd_threads 10
  ```

- **From Config File**:
  ```bash
  python3 cve_processing.py --config ./config.json \
                            --nvd_threads 10
  ```

### Configuration Files

You can store and load configurations to streamline runs:

```json
{
  "base_dir": "/path/to/base_dir",
  "cves": ["CVE-2023-1234", "CVE-2022-0987"],
  "sort_order": "descending"
}
```

Use `--write_config config.json` to generate this file from your current arguments.

## Output

Ascend produces a JSON output listing each CVE with comprehensive data:

```json
[
  {
    "CVE_ID": "CVE-2023-1234",
    "Status": "Success",
    "Exploitability_Sub_Score": ...,
    "Temporal_Score": ...,
    "Impact_Sub_Score": ...,
    "EPSS_Score": ...,
    "EPSS_Percentile": ...,
    "ZDI_Presence": true,
    "KEV_Presence": true,
    "Google_Project_Zero_Presence": false,
    "In_The_Wild": true,
    "CPE_Impact": 0.5,
    "CWE_Impact": 0.75,
    "Advisories_Impact": 0.9,
    "Final_Score": 123.45
  },
  ...
]
```

This structured output can be easily integrated into dashboards, pipelines, or reporting tools.

## Contributing

Pull requests are welcome! For significant changes, please open an issue first to discuss what you’d like to modify.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/my-enhancement`)
3. Commit your changes (`git commit -m 'Add feature'`)
4. Push to the branch (`git push origin feature/my-enhancement`)
5. Open a Pull Request

## License

[MIT](LICENSE)

---
