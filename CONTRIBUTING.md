# Contributing to Infino SDK

Thank you for your interest in contributing to the Infino Python SDK! We welcome contributions from the community.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Making Changes](#making-changes)
- [Testing](#testing)
- [Submitting Changes](#submitting-changes)
- [Code Style](#code-style)
- [Documentation](#documentation)

## Code of Conduct

We are committed to providing a welcoming and inclusive experience for everyone. Please be respectful and considerate in all interactions.

## Getting Started

1. **Fork the repository** on GitHub
2. **Clone your fork** locally:
   ```bash
   git clone https://github.com/YOUR_USERNAME/infino-sdk-python.git
   cd infino-sdk-python
   ```

3. **Add the upstream repository**:
   ```bash
   git remote add upstream https://github.com/infinohq/infino-sdk-python.git
   ```

## Development Setup

### Prerequisites

- Python 3.8 or higher
- pip and virtualenv

### Install Development Dependencies

```bash
# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install development dependencies
pip install -r requirements-dev.txt

# Install package in editable mode
pip install -e .
```

### Development Dependencies

The SDK uses the following tools for development:

- **pytest** - Testing framework
- **pytest-asyncio** - Async test support
- **pytest-cov** - Code coverage
- **pytest-mock** - Mocking support
- **flake8** - Linting
- **black** - Code formatting
- **mypy** - Static type checking
- **isort** - Import sorting

## Making Changes

### Branch Naming

Create a descriptive branch for your changes:

```bash
git checkout -b feature/add-new-method
git checkout -b fix/handle-timeout-error
git checkout -b docs/improve-readme
```

### Commit Messages

Follow conventional commit format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

Types:
- `feat`: New feature
- `fix`: Bug fix
- `docs`: Documentation changes
- `style`: Code style changes (formatting, etc.)
- `refactor`: Code refactoring
- `test`: Adding or updating tests
- `chore`: Maintenance tasks

Examples:
```
feat(search): add support for fuzzy matching

Implements fuzzy matching in search queries using the match_phrase
query type with fuzziness parameter.

Closes #123
```

```
fix(auth): handle expired credentials gracefully

Previously, expired credentials would cause an unhandled exception.
Now we catch the error and return a more user-friendly message.
```

### Code Changes

1. **Write tests first** (TDD approach preferred)
2. **Implement your changes**
3. **Ensure all tests pass**
4. **Update documentation** if needed
5. **Add examples** for new features

## Testing

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=infino_sdk --cov-report=html

# Run specific test file
pytest tests/test_search.py

# Run specific test
pytest tests/test_search.py::test_basic_search

# Run with verbose output
pytest -v

# Run async tests
pytest -v tests/test_async.py
```

### Writing Tests

Tests should be placed in the `tests/` directory with the naming convention `test_*.py`.

Example test:

```python
import pytest
from infino_sdk import InfinoSDK, InfinoError


@pytest.mark.asyncio
async def test_search_basic(mock_sdk):
    """Test basic search functionality"""
    sdk = await mock_sdk
    
    result = await sdk.search("test_index", '{"query": {"match_all": {}}}')
    
    assert "hits" in result
    assert isinstance(result["hits"], dict)


@pytest.mark.asyncio
async def test_search_not_found(mock_sdk):
    """Test search with non-existent index"""
    sdk = await mock_sdk
    
    with pytest.raises(InfinoError) as exc_info:
        await sdk.search("nonexistent", '{"query": {"match_all": {}}}')
    
    assert exc_info.value.status_code() == 404
```

### Test Coverage

We aim for >90% test coverage. Check coverage with:

```bash
pytest --cov=infino_sdk --cov-report=term-missing
```

## Submitting Changes

### Before Submitting

1. **Run the full test suite**:
   ```bash
   pytest
   ```

2. **Check code style**:
   ```bash
   flake8 infino_sdk tests
   black --check infino_sdk tests
   isort --check-only infino_sdk tests
   ```

3. **Run type checker**:
   ```bash
   mypy infino_sdk
   ```

4. **Fix any issues**:
   ```bash
   black infino_sdk tests
   isort infino_sdk tests
   ```

### Creating a Pull Request

1. **Push your changes** to your fork:
   ```bash
   git push origin feature/your-feature-name
   ```

2. **Create a Pull Request** on GitHub

3. **Fill out the PR template** with:
   - Description of changes
   - Related issues (use "Closes #123")
   - Testing performed
   - Screenshots (if applicable)

4. **Wait for review** - maintainers will review your PR and may request changes

### PR Requirements

- All tests must pass
- Code coverage should not decrease
- Code must pass linting checks
- Documentation must be updated
- Examples should be added for new features

## Code Style

### Python Style Guide

We follow PEP 8 with some modifications:

- **Line length**: 100 characters (not 79)
- **Strings**: Use double quotes `"` for strings
- **Imports**: Organized with `isort`
- **Formatting**: Automated with `black`

### Type Hints

All public functions should have type hints:

```python
async def search(self, index: str, query: str) -> Dict[str, Any]:
    """Execute a search query"""
    ...
```

### Docstrings

Use Google-style docstrings:

```python
async def complex_function(param1: str, param2: int) -> bool:
    """Brief description of function.
    
    Longer description if needed, explaining the purpose
    and behavior of the function.
    
    Args:
        param1: Description of param1
        param2: Description of param2
        
    Returns:
        Description of return value
        
    Raises:
        InfinoError: When something goes wrong
        
    Example:
        >>> result = await sdk.complex_function("test", 123)
        >>> print(result)
        True
    """
    ...
```

### Error Handling

Always handle errors appropriately:

```python
try:
    result = await self.request("GET", url)
    return result
except InfinoError as e:
    if e.status_code() == 404:
        logger.warning(f"Resource not found: {url}")
    raise
```

## Documentation

### Updating Documentation

- Update `README.md` for user-facing changes
- Add docstrings to new functions/classes
- Create examples for new features in `examples/`
- Update API reference if needed

### Documentation Style

- Be clear and concise
- Include code examples
- Explain the "why", not just the "what"
- Use proper markdown formatting

### Adding Examples

New features should include working examples in the `examples/` directory:

1. Create a new file: `examples/your_feature.py`
2. Include comprehensive comments
3. Show error handling
4. Add to `examples/README.md`

## Questions?

- 💬 Join our [Discord community](https://discord.gg/infino)
- 📧 Email: dev@infino.ai
- 🐛 [Open an issue](https://github.com/infinohq/infino-sdk-python/issues)

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
