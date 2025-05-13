# MD5 brute-force cracking with arbitrary combinations
# Swallow MD5 Hash Cracker 🐦⚡

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![License](https://img.shields.io/badge/License-Free-green)
![Multiprocessing](https://img.shields.io/badge/Threads-30~120-red)

An MD5 hash collision cracking tool accelerated by multi-processing. It quickly matches the target hash value by brute-forcing and enumerating all possible character combinations.

## Features

- 🚀 Multi-processing acceleration (supports up to 120 threads)
- 🔍 Supports custom character sets and password length ranges
- 📊 Real-time progress display (based on tqdm)
- ⚡ Intelligent batch processing (handles up to 2 million combinations at a time)
- 🛡️ Secure interruption handling (stops immediately when Ctrl+C is pressed)

## Installation and Usage

### Dependent Environment
```bash
Python 3.8+ 
pip install tqdm
``` 
