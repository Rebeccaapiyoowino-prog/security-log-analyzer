# Security Log Analyzer

A Python based cybersecurity utility for analyzing Linux SSH authentication logs and identifying suspicious login activity.

## Overview

The Security Log Analyzer reviews authentication log files and summarizes both failed and successful SSH login attempts. It can also flag IP addresses that exceed a configurable threshold of failed login attempts, which can help identify possible brute force activity.

This project demonstrates practical skills in:

- Python scripting
- Security log analysis
- Pattern matching with regular expressions
- Basic threat detection logic
- Automated testing
- Technical documentation

## Features

- Detects failed SSH login attempts
- Detects successful SSH logins
- Counts login attempts by IP address
- Flags IP addresses that exceed a failed login threshold
- Supports configurable detection thresholds
- Handles missing log files with clear errors
- Includes automated unit tests

## Project Structure

```text
security-log-analyzer/
├── analyzer.py
├── sample_logs/
│   └── auth.log
├── tests/
│   └── test_analyzer.py
├── README.md
├── .gitignore
└── LICENSE
