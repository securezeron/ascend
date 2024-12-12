
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
  Leverages multiple factors such as exploitability, impact scores, CWE and CPE presence, and advisories to produce a tailored “Ascend Score.” This helps you identify which CVEs should be addressed first.

- **Modular & Extensible**:  
  Easily extend Ascend’s data sources and scoring logic.

- **Configurable & Scalable**:  
  Utilize multiple threads to fetch NVD data for large CVE sets, and sort results as needed.

## Getting Started

### Prerequisites

- **Python**: 3.7+
- Ensure that all referenced `src/*_fetcher.py` modules are present and correctly implemented.

### Creating the Base Directory

Use the `src/*_updater.py` scripts provided to create and populate your `base_dir` with the necessary data:

```bash
python3 cisa_kev_updater.py --base_dir /path/to/base_dir
python3 zdi_updater.py --base_dir /path/to/base_dir
python3 inthewild_updater.py --base_dir /path/to/base_dir
```

After running these updater scripts, your `base_dir` might look like this:

```bash
/path/to/base_dir/
├─ cisa_kev/
│  └─ known_exploited_vulnerabilities.json
├─ zdi_rss_feeds/
│  └─ ... (ZDI feed files)
└─ inthewild/
   └─ ... (InTheWild data files)
```

### Installation

1. **Clone the repository**:
   ```bash
   git clone https://github.com/securezeron/Ascend.git
   cd Ascend
   ```

2. **Install dependencies** (if required):
   ```bash
   pip install -r requirements.txt
   ```

3. **Prepare data sources**:
   Ensure `base_dir` is properly structured as noted above.

### Usage (JSON Input and Output Only)

Ascend accepts CVE input strictly from a JSON file. This JSON file should contain an array of CVE strings. For example:

```json
["CVE-2023-1234", "CVE-2023-5678"]
```

Run Ascend with:
```bash
python3 main.py \
    --base_dir /path/to/base_dir \
    --cve_file cves.json \
    --nvd_threads 10 \
    --outfile results.json
```

**Required Arguments**:

- `--base_dir <path>`: **(Required)** The directory containing data and auxiliary files.
- `--cve_file <file_path>`: JSON file containing an array of CVE strings.
- `--outfile <filename>`: Specify the output JSON file for results. Default: `results.json`.
- `--nvd_threads <int>`: Number of threads to speed up NVD fetching. Required.

**Optional Arguments**:

- `--config <config_file>`: Load configuration (including CVEs) from a JSON config file.
- `--write_config <config_file>`: Write the current configuration to a file for future use.
- `--sort_order <ascending|descending>`: Sort final results by score. Default is `descending`.

### Examples

- **From a CVE JSON File**:
  ```bash
  python3 main.py --base_dir ./data \
                            --cve_file ./cves.json \
                            --nvd_threads 10 \
                            --outfile results.json
  ```

- **From a Config File**:
  Create a `config.json`:
  ```json
  {
    "base_dir": "./data",
    "cves": ["CVE-2023-1234", "CVE-2022-0987"],
    "sort_order": "descending"
  }
  ```
  Run:
  ```bash
  python3 main.py --config ./config.json \
                            --nvd_threads 10 \
                            --outfile results.json
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

## Output (JSON Only)

Ascend produces a JSON file containing a list of CVEs with their details:

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

You can then ingest this JSON output into dashboards, pipelines, or security tools.

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

Elevate your vulnerability management with Ascend—let actionable insights guide you to swift and effective remediation.
