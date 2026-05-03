# Passive Subdomain Scanner

A simple, fast, and modular **passive subdomain enumeration tool** that aggregates results from multiple external recon tools concurrently.

## Features

* Passive subdomain enumeration (no direct interaction with target)
* Concurrent execution of multiple tools
* Deduplicated results
* Select specific tools or run all
* Clean output saved to file

---

## Supported Tools

* `subfinder`
* `assetfinder`
* `waymore`

> These tools must be installed and available in your `$PATH`.

---

## Installation

### 1. Clone the repository

```bash
git clone https://github.com/bncodug/sub-passive.git
cd sub-passive
```

### 2. Install dependencies

This script uses only the Python standard library.

Make sure you have:

* Python 3.7+

### 3. Install external tools

Example (Go-based tools):

```bash
go install github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install github.com/tomnomnom/assetfinder@latest
```

For `waymore`, follow its official installation instructions:
https://github.com/xnl-h4ck3r/waymore

---

## Usage

```bash
python sub_passive.py [-h] [-o OUTPUT_DIR] [-t {subfinder,assetfinder,waymore} [{subfinder,assetfinder,waymore} ...]] domain
```

### Arguments

| Argument           | Description                                   |
| ------------------ | --------------------------------------------- |
| `domain`           | Target domain (e.g. example.com)              |
| `-o, --output-dir` | Output directory (default: current directory) |
| `-t, --tools`      | One or more tools to use                      |

---

## Examples

### Run all tools (default)

```bash
python sub_passive.py example.com
```

### Use specific tools

```bash
python sub_passive.py example.com -t subfinder assetfinder
```

### Save output to a directory

```bash
python sub_passive.py example.com -o results/
```

---

## Output

Results are saved as:

```bash
<domain>-subdomains-YYYY-MM-DD.txt
```

Example:

```bash
example.com-subdomains-2026-05-03.txt
```

---

## How It Works

1. Selected tools are executed concurrently
2. Each tool returns discovered subdomains
3. Results are aggregated and deduplicated
4. Final list is written to an output file

---

## Notes

* This tool performs **passive reconnaissance only**
* Accuracy depends on the external tools used
* Ensure all tools are installed before running

---

## Disclaimer

This tool is intended for **educational and authorized security testing only**.
Do not use it against systems you do not own or have permission to test.


---

## License

MIT License