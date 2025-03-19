# LinkGuardian

A powerful asynchronous website crawler and link checker that helps you identify broken links, orphaned pages, and analyze your website's link structure.

Created by [Farhan Ansari](https://github.com/fxrhan)

## Features

- 🔄 Asynchronous crawling for faster performance
- 🌐 Cross-platform support (Windows, macOS, Linux)
- 🎨 Beautiful terminal output with color coding
- 📊 Link analysis and reporting
- 🔍 Smart caching system for efficient crawling
- 🛡️ Rate limiting and robots.txt compliance
- 📝 CSV reports for broken and all links
- 🔒 SSL/TLS support
- 🎯 Configurable crawl depth and page limits

## Prerequisites

- Python 3.7 or higher
- pip (Python package installer)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/fxrhan/LinkGuardian.git
cd LinkGuardian
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

## Usage

### Basic Usage

```bash
python linkcheck.py --url https://example.com
```

### Advanced Options

```bash
python linkcheck.py --url https://example.com --workers 20 --rate 0.5 --max-pages 200 --max-depth 4 --ignore-robots
```

### Command Line Arguments

- `--url`: Base URL to crawl (default: https://example.com)
- `--workers`: Number of concurrent workers (default: 10)
- `--rate`: Rate limit in seconds between requests (default: 0.5)
- `--max-pages`: Maximum number of pages to crawl (default: 100)
- `--max-depth`: Maximum crawl depth (default: 3)
- `--cache-dir`: Custom directory for cache files (optional)
- `--ignore-robots`: Ignore robots.txt rules (optional, by default robots.txt rules are respected)

## Output Structure

The tool creates a `.linkguardian` directory in your home folder with the following structure:

```
~/.linkguardian/
├── cache/          # Cache files for each domain
├── logs/           # Log files
└── output/         # Crawl results
    └── {domain}_{timestamp}/
        ├── broken_links.csv
        └── all_links.csv
```

### Cache System

The tool implements a smart caching system that:
- Stores visited pages and checked links
- Handles JSON serialization of complex data types
- Automatically manages cache files per domain
- Preserves crawl progress between sessions

### Error Handling

The tool includes comprehensive error handling for:
- Network connectivity issues
- SSL/TLS certificate problems
- Timeout errors
- HTTP errors
- JSON serialization errors
- Platform-specific path issues
- Keyboard interrupts

## Output Files

### broken_links.csv
Contains information about broken links:
- Broken Link URL
- Source Page URL
- Status Code
- Error Category
- Timestamp

### all_links.csv
Contains information about all discovered links:
- Link URL
- Source Page URL
- Status Code
- Link Type (Internal/External)
- Depth
- Is Orphaned
- Timestamp

## Error Categories

The tool categorizes errors into the following types:
- Connection errors
- Timeout errors
- SSL/TLS errors
- HTTP errors
- Parsing errors
- Validation errors
- Unknown errors

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Support

If you encounter any issues or have questions, please open an issue on the GitHub repository. 