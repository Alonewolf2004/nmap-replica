# Contributing to Argus

Thank you for your interest in contributing to Argus! 🎉

## Ways to Contribute

### 1. Add to Community Databases

The easiest way to contribute is by adding to our JSON databases:

#### `argus/data/honeypot_ips.json`
Add known honeypot IP ranges with evidence.

#### `argus/data/service_patterns.json`
Add suspicious service combinations you've observed.

#### `argus/data/os_fingerprints.json`
Add OS detection patterns from service banners.

### 2. Report Bugs

Open an issue with:
- Steps to reproduce
- Expected vs actual behavior
- Your environment (OS, Python version)

### 3. Submit Code

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/my-feature`
3. Make your changes
4. Run tests: `pytest tests/ -v`
5. Submit a Pull Request

## Code Style

- Follow PEP 8
- Add docstrings to functions and classes
- Keep functions focused and small
- Add tests for new features

## Running Tests

```bash
pytest tests/ -v
```

## Questions?

Open an issue or start a discussion!
