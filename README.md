# Installer Analysis Toolkit

A set of scripts to safely analyze macOS installers, especially those that may contain hidden payloads or obfuscated shell scripts. This toolkit was primarily developed to investigate suspicious job-related software installers (e.g., Solus, Vironect) and does **not execute any malicious binaries**.

> ⚠️ Disclaimer: These scripts are provided for educational and research purposes only.
The author takes no responsibility for any consequences of using them.
Always run in a safe test environment, not on your primary machine.


### Scripts Overview

- `extract.py` – Extracts and resolves shell variables from installer scripts. Decodes simple Base64 payloads.
- `extract2.py` – Extended extractor for obfuscated installers with complex variable interdependencies.
- `extract_macho_payloads.py` – Identifies and extracts potential embedded payloads from Mach-O binaries.
- `auto_full_installer_scan.py` – Orchestrates automated analysis:
  - Prompts user for installer folder or searches `/Volumes/` for connected installer drives.
  - Copies and prepares hidden installer scripts.
  - Calls the extraction scripts in proper order.
  - Saves decoded payloads for further inspection in `output/`.

---

## Getting Started

1. **Clone the repository:**

```bash
git clone https://github.com/kirillkott/macos-installer-analysis-toolkit.git
cd installer-analysis-toolkit
chmod +x *.sh
```
> Ensure Python 3.11+ is installed on your Mac (M1/M2 compatible).
> chmod necessary to run scripts and perform analysis

Place the installer in a known folder or connect the volume with the installer.

Run the automated analysis:

```bash
bash auto_full_installer_scan.sh
```
You will be prompted to:

Provide a folder path (e.g., /Volumes/Installer)

Or automatically scan for connected installer volumes.

The script will:

Copy hidden installer files to /tmp/

Prepare them for safe static analysis

Call extract.py, extract2.py, and extract_macho_payloads.py in order

Output decoded payloads and logs into output/

# Output
The output folder contains:

payloads/ – Base64-decoded installer payloads

logs/ – Analysis logs with safe variable resolutions

summary.txt – Key insights from the analysis

No binaries are executed during this process. Only shell scripts are parsed and decoded.

# Best Practices
Always use a disposable VM or test Mac when working with unknown installers.

Inspect logs before executing any further steps.

Avoid opening binaries directly on your main environment.

# Contribution
Feel free to fork the repository and extend the scripts for additional installer formats or analysis heuristics. Keep in mind the security-first approach.

# License
MIT License – safe usage for educational and research purposes only.
