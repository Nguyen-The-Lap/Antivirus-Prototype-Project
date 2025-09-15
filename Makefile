.PHONY: install test lint format type-check clean docker-build docker-run docker-test

# Variables
PYTHON = python3
PIP = pip3
DOCKER = docker
DOCKER_COMPOSE = docker-compose

# Install dependencies
install:
	$(PIP) install -e .[dev]

# Run tests
test:
	pytest tests/ -v --cov=antivirus --cov-report=term-missing

# Lint code
lint:
	black --check --diff .
	isort --check-only --diff .
	flake8
	mypy .

# Format code
format:
	black .
	isort .

# Run type checking
type-check:
	mypy .

# Clean up
clean:
	find . -type d -name "__pycache__" -exec rm -r {} +
	find . -type d -name ".pytest_cache" -exec rm -r {} +
	find . -type d -name ".mypy_cache" -exec rm -r {} +
	docker system prune -f

# Docker commands
docker-build:
	$(DOCKER) build -t antivirus .

docker-run:
	$(DOCKER) run -it --rm -v $(PWD)/data:/app/data antivirus

docker-test:
	$(DOCKER_COMPOSE) -f docker-compose.test.yml up --build --abort-on-container-exit

# Documentation
docs:
	cd docs && make html

# Run the application
run:
	$(PYTHON) -m src.main

# Start development server
dev:
	uvicorn src.api.app:app --reload --host 0.0.0.0 --port 8000

# Update dependencies
update-deps:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

# Security scan
security-scan:
	bandit -r src/
	safety check

# Run all checks
check: lint test type-check security-scan
