# Contributing to YAVS

Thank you for your interest in contributing to YAVS!

## Getting Started

1. Fork the repository
2. Clone your fork: `git clone https://github.com/YOUR-USERNAME/yavs`
3. Create a branch: `git checkout -b feature/your-feature-name`
4. Make your changes
5. Run tests: `pytest`
6. Commit your changes: `git commit -am "Add new feature"`
7. Push to your fork: `git push origin feature/your-feature-name`
8. Create a Pull Request

## Development Setup

```bash
# Install development dependencies
pip install -e ".[dev]"

# Install pre-commit hooks (if configured)
pre-commit install

# Run tests
pytest

# Run tests with coverage
pytest --cov=yavs
```

## Code Style

- Follow PEP 8
- Use type hints where appropriate
- Add docstrings for public functions and classes
- Keep functions focused and modular

## Testing

- Write tests for new features
- Ensure all tests pass before submitting PR
- Maintain or improve code coverage

## Pull Request Guidelines

- Provide a clear description of changes
- Reference related issues
- Include tests for new functionality
- Update documentation as needed

## Questions?

Open an issue or reach out to the maintainers.
