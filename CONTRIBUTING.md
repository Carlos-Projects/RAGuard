# Contributing to RAGuard

Thank you for your interest in contributing to RAGuard! This document provides guidelines for contributing to the project.

## Development Setup

1. **Clone the repository:**
   ```bash
   git clone https://github.com/Carlos-Projects/RAGuard.git
   cd RAGuard
   ```

2. **Create a virtual environment:**
   ```bash
   python -m venv .venv
   source .venv/bin/activate  # On Windows: .venv\Scripts\activate
   ```

3. **Install dependencies:**
   ```bash
   pip install -e ".[dev]"
   ```

## Code Style

- **Linting:** We use `ruff` for linting and formatting.
  ```bash
  ruff check .
  ruff format .
  ```

- **Type hints:** All functions should have type hints.
- **Docstrings:** All public functions should have docstrings.
- **Line length:** Maximum 120 characters.

## Testing

- **Run tests:**
  ```bash
  python -m pytest tests/ -v
  ```

- **Run with coverage:**
  ```bash
  python -m pytest tests/ -v --cov=raguard
  ```

- **Test requirements:**
  - All new features must include tests.
  - Aim for >80% code coverage.
  - Tests should be in `tests/` directory following the existing structure.

## Pull Request Process

1. **Fork the repository** and create your branch from `main`.
2. **Make your changes** following the code style guidelines.
3. **Add tests** for any new functionality.
4. **Run the test suite** and ensure all tests pass.
5. **Run the linter** and fix any issues.
6. **Submit a pull request** with a clear description of your changes.

## Commit Messages

Follow conventional commits format:
```
type(scope): description

feat: add Milvus target implementation
fix: handle timeout errors in HTTP client
docs: update README with new detector docs
test: add tests for data poisoning detector
```

## Reporting Issues

- Use GitHub Issues to report bugs or request features.
- Include steps to reproduce for bug reports.
- Include RAGuard version and Python version.

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
