# Justfile for CROP - Cryptographic Routines, Operations & Primitives

# Default recipe: list all available commands
default:
    @just --list

# Install development tools
install-tools:
    @echo "Installing golangci-lint..."
    @curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(go env GOPATH)/bin latest
    @echo "golangci-lint installed successfully"
    @golangci-lint --version

# Run golangci-lint
lint:
    @echo "Running golangci-lint..."
    @golangci-lint run --timeout=5m

# Run tests
test:
    @echo "Running tests..."
    @go test -v ./...

# Run tests with coverage
test-coverage:
    @echo "Running tests with coverage..."
    @go test -v -coverprofile=coverage.out ./...
    @go tool cover -html=coverage.out -o coverage.html
    @echo "Coverage report generated: coverage.html"

# Build the project
build:
    @echo "Building..."
    @go build ./...

# Format code
fmt:
    @echo "Formatting code..."
    @go fmt ./...

# Tidy dependencies
tidy:
    @echo "Tidying dependencies..."
    @go mod tidy

# Clean build artifacts
clean:
    @echo "Cleaning..."
    @rm -f coverage.out coverage.html

# Run all checks (format, lint, test)
check: fmt lint test
    @echo "All checks passed!"
