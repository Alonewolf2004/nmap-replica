# Argus Tests

This directory contains unit tests for the Argus port scanner.

## Running Tests

```bash
# Install pytest if you haven't
pip install pytest pytest-cov pytest-asyncio

# Run all tests
pytest tests/ -v

# Run with coverage report
pytest tests/ -v --cov=argus --cov-report=html

# Run specific test file
pytest tests/test_argus.py -v

# Run specific test class
pytest tests/test_argus.py::TestBannerAnalyzer -v

# Run specific test
pytest tests/test_argus.py::TestBannerAnalyzer::test_trie_lookup_ssh -v
```

## Coverage Report

After running with `--cov-report=html`, open `htmlcov/index.html` in your browser to see detailed coverage.

## Test Structure

- `test_argus.py` - Main test file covering:
  - **BannerAnalyzer**: Trie lookup, probe generation, banner analysis
  - **Analyzer Plugins**: SSH, HTTP, Database analyzers
  - **Registry**: Plugin dispatcher
  - **Utilities**: Port parser, Bloom filter, rate limiter, cache
  - **Config**: Pydantic validation
