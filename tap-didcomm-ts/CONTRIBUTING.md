# Contributing to tap-didcomm-ts

We love your input! We want to make contributing to tap-didcomm-ts as easy and transparent as possible, whether it's:

- Reporting a bug
- Discussing the current state of the code
- Submitting a fix
- Proposing new features
- Becoming a maintainer

## Development Process

We use GitHub to host code, to track issues and feature requests, as well as accept pull requests.

1. Fork the repo and create your branch from `main`.
2. If you've added code that should be tested, add tests.
3. If you've changed APIs, update the documentation.
4. Ensure the test suite passes.
5. Make sure your code lints.
6. Issue that pull request!

## Any contributions you make will be under the MIT Software License

In short, when you submit code changes, your submissions are understood to be under the same [MIT License](http://choosealicense.com/licenses/mit/) that covers the project. Feel free to contact the maintainers if that's a concern.

## Report bugs using GitHub's [issue tracker](https://github.com/notabene/tap-didcomm/issues)

We use GitHub issues to track public bugs. Report a bug by [opening a new issue](https://github.com/notabene/tap-didcomm/issues/new); it's that easy!

## Write bug reports with detail, background, and sample code

**Great Bug Reports** tend to have:

- A quick summary and/or background
- Steps to reproduce
  - Be specific!
  - Give sample code if you can.
- What you expected would happen
- What actually happens
- Notes (possibly including why you think this might be happening, or stuff you tried that didn't work)

## Development Setup

1. Install dependencies:
   ```bash
   pnpm install
   ```

2. Build WASM modules:
   ```bash
   pnpm run build:wasm
   ```

3. Run tests:
   ```bash
   pnpm test
   pnpm test:browser
   ```

## Testing

We use several testing frameworks:

- **Vitest** for unit and integration tests
- **Playwright** for browser testing
- **Node.js** native test runner for Node.js-specific tests

### Running Tests

```bash
# Run all tests
pnpm test

# Run browser tests
pnpm test:browser

# Run with coverage
pnpm test:coverage

# Run in watch mode
pnpm test:watch
```

## Code Style

We use ESLint and Prettier to maintain code quality and consistency:

```bash
# Run linter
pnpm run lint

# Fix linting issues
pnpm run lint:fix

# Format code
pnpm run format
```

## Documentation

Please update the documentation when you make changes:

- Update the README.md if you change public APIs
- Update JSDoc comments for functions and types
- Add examples for new features
- Update CHANGELOG.md with your changes

## Pull Request Process

1. Update the README.md with details of changes to the interface
2. Update the CHANGELOG.md with notes on your changes
3. The PR will be merged once you have the sign-off of at least one maintainer

## License

By contributing, you agree that your contributions will be licensed under its MIT License. 