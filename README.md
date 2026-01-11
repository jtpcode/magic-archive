# Magic Archive

[![CI](https://github.com/jtpcode/ot-harjoitustyo/actions/workflows/main.yml/badge.svg)](https://github.com/jtpcode/ot-harjoitustyo/actions/workflows/main.yml)
[![codecov](https://codecov.io/gh/jtpcode/ot-harjoitustyo/graph/badge.svg?token=YRY6AKKYRG)](https://codecov.io/gh/jtpcode/ot-harjoitustyo)

The application is designed to manage Magic: The Gathering cards. It allows users to maintain a digital archive of their physical cards. Cards are retrieved from the Scryfall.com API. The application supports multiple users, each of whom must register to access the system.

![](./Documentation/pics/card_view.png)

## Note on Python Version

The application's functionality has been tested with Python version `3.13`. Issues may arise, when using older Python versions.

## Documentation

- [Requirements Specification](./Documentation/requirements_specification.md)
- [Architecture Description](./Documentation/architecture.md)
- [Changelog](./Documentation/changelog.md)
- [Testing documentation](./Documentation/testing.md)
- [Manual](./Documentation/manual.md)

## Releases

- [Latest release](https://github.com/jtpcode/ot-harjoitustyo/releases)

## Installation

1. Install dependencies with the following command:

```bash
poetry install --no-root
```

2. Initialize application database with:

```bash
poetry run invoke build
```

3. Start the application with:

```bash
poetry run invoke start
```

## Command Line Functions

### Running the Application

The application can be started with:

```bash
poetry run invoke start
```

### Testing

Tests can be run with the following command:

```bash
poetry run invoke test
```

### Test Coverage

A test coverage report can be generated with:

```bash
poetry run invoke coverage-report
```

The report will be generated in the *htmlcov* directory.

### Linting

Linting can be done with:

```bash
poetry run invoke lint
```

## License
MIT License. See [LICENSE](LICENSE) for details.
