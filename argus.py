#!/usr/bin/env python3
"""
Argus - The All-Seeing Port Scanner

A high-performance, asynchronous port scanner with SSL/TLS support,
smart banner grabbing, and built-in honeypot detection.

Usage:
    python argus.py -t example.com -p 1-1000
    python argus.py -t example.com -p 80,443 -sV
"""

from argus.main import main

if __name__ == "__main__":
    main()
