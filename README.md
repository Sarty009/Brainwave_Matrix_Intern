# Phishing Link Scanner

A powerful command-line tool to detect phishing links using heuristic analysis and API-based scanning.

## Features
- **Single URL Scanning** – Scan a single URL for potential phishing threats.
- **Automated Scanning** – Scan multiple URLs from a file.
- **VirusTotal & Google Safe Browsing API Integration** – Check URLs against threat databases.
- **Heuristic Analysis** – Detect phishing links based on common phishing patterns.
- **Report Generation** – Save results in JSON, CSV, or database.
- **GUI Support (Optional)** – Simple graphical interface using Tkinter or PyQt.
- **Docker & Installation Script** – Easily deploy the tool on different systems.

## Installation

### Clone the Repository
```sh
git clone https://github.com/Sarty009/phiscan.git
cd phiscan
```

### Install Dependencies
```sh
pip install -r requirements.txt
```

### Set Up API Keys
1. Create a `.env` file in the project directory.
2. Add the following lines and replace with your actual API keys:
```sh
VIRUSTOTAL_API_KEY=your_virustotal_api_key
GOOGLE_SAFE_BROWSING_API_KEY=your_google_safe_browsing_api_key
```

## Usage

### Scan a Single URL
```sh
python phiscanner.py <URL>
```
Example:
```sh
python phiscanner.py https://example.com
```

### Scan Multiple URLs from a File
```sh
python phiscanner.py -f urls.txt
```

### Save Scan Results
- **JSON Format:**
```sh
python phiscanner.py -f urls.txt -o results.json
```
- **CSV Format:**
```sh
python phiscanner.py -f urls.txt -o results.csv
```

### Run the GUI (Optional)
```sh
python phiscanner.py --gui
```

## Running the Tool

### 1️⃣ Open Your Project Folder
```sh
cd phiscan
```

### 2️⃣ Ensure Dependencies Are Installed
```sh
pip install -r requirements.txt
```

### 3️⃣ Run the Scanner
- **Scan a single URL:**
  ```sh
  python phiscanner.py https://example.com
  ```
- **Scan multiple URLs from a file:**
  ```sh
  python phiscanner.py -f urls.txt
  ```
- **Save scan results (JSON/CSV):**
  ```sh
  python phiscanner.py -f urls.txt -o results.json
  ```

### 4️⃣ (Optional) Run the GUI
```sh
python phiscanner.py --gui
```

### 5️⃣ (Optional) Run with Docker
```sh
docker build -t phiscanner .
docker run --rm -v $(pwd):/app phiscanner python phiscanner.py https://example.com
```

## Contributing
Feel free to fork this repository, make improvements, and submit a pull request!

## License
This project is licensed under the MIT License.
