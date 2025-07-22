# Makefile for Web-Toolkit Pro
PYTHON = python3
PIP = pip3
VENV = venv
REQUIREMENTS = requirements.txt

.PHONY: help install test clean dev-install format lint type-check all-checks run-tests

help: ## Show this help message
	@echo "Web-Toolkit Pro - Available commands:"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-20s\033[0m %s\n", $$1, $$2}'

install: ## Install dependencies
	$(PIP) install --user -r $(REQUIREMENTS)
	@echo "✅ Dependencies installed successfully"

install-venv: ## Create virtual environment and install dependencies
	$(PYTHON) -m venv $(VENV)
	./$(VENV)/bin/pip install -r $(REQUIREMENTS)
	@echo "✅ Virtual environment created and dependencies installed"

dev-install: ## Install development dependencies
	$(PIP) install --user -r $(REQUIREMENTS)
	$(PIP) install --user pytest black flake8 mypy coverage bandit safety
	@echo "✅ Development dependencies installed"

test: ## Run unit tests
	$(PYTHON) tests/test_web_toolkit.py

test-coverage: ## Run tests with coverage report
	coverage run tests/test_web_toolkit.py
	coverage report -m
	coverage html

format: ## Format code with black
	black modules/ tests/ *.py --line-length 88
	@echo "✅ Code formatted successfully"

lint: ## Run linting with flake8
	flake8 modules/ tests/ *.py --max-line-length=88 --ignore=E203,W503
	@echo "✅ Linting completed"

type-check: ## Run type checking with mypy
	mypy modules/ --ignore-missing-imports --disable-error-code=import
	@echo "✅ Type checking completed"

security-check: ## Run security checks
	bandit -r modules/ -f json -o bandit-report.json || true
	safety check --json --output safety-report.json || true
	@echo "✅ Security checks completed - see *-report.json files"

all-checks: format lint type-check security-check test ## Run all code quality checks
	@echo "✅ All quality checks completed"

check-tools: ## Check availability of external tools
	$(PYTHON) web-toolkit-pro.py --check-tools

install-tools: ## Install missing external tools (requires sudo)
	$(PYTHON) web-toolkit-pro.py --install-tools

demo-scan: ## Run a demo scan on a safe target
	$(PYTHON) web-toolkit-pro.py --scan httpbin.org --type quick --format html

benchmark: ## Run performance benchmarks
	time $(PYTHON) web-toolkit-pro.py --scan scanme.nmap.org --type quick

clean: ## Clean up temporary files and cache
	find . -type f -name "*.pyc" -delete
	find . -type d -name "__pycache__" -delete
	find . -type f -name "*.log" -delete
	find . -type f -name "*-report.*" -delete
	rm -rf htmlcov/
	rm -rf .coverage
	rm -rf .pytest_cache/
	rm -rf .mypy_cache/
	rm -rf build/
	rm -rf dist/
	rm -rf *.egg-info/
	@echo "✅ Cleaned up temporary files"

build: ## Build distribution packages
	$(PYTHON) setup.py sdist bdist_wheel
	@echo "✅ Distribution packages built"

docs: ## Generate documentation
	@echo "📚 Generating documentation..."
	@echo "Documentation available in DOCUMENTATION.md"

install-system: ## Install web-toolkit system-wide (requires sudo)
	sudo chmod +x web-toolkit-pro.py
	sudo cp web-toolkit-pro.py /usr/local/bin/web-toolkit-pro
	sudo cp -r modules/ /usr/local/share/web-toolkit-modules/
	@echo "✅ Web-Toolkit Pro installed system-wide"
	@echo "You can now run: web-toolkit-pro --scan example.com"

uninstall-system: ## Remove system-wide installation (requires sudo)
	sudo rm -f /usr/local/bin/web-toolkit-pro
	sudo rm -rf /usr/local/share/web-toolkit-modules/
	@echo "✅ Web-Toolkit Pro removed from system"

docker-build: ## Build Docker image
	docker build -t web-toolkit-pro:latest .
	@echo "✅ Docker image built: web-toolkit-pro:latest"

docker-run: ## Run in Docker container
	docker run --rm -it web-toolkit-pro:latest --help

update-templates: ## Update Nuclei templates
	nuclei -update-templates || echo "Nuclei not found - install with: make install-tools"

backup-config: ## Backup configuration files
	cp config.ini config.ini.backup.$(shell date +%Y%m%d_%H%M%S)
	@echo "✅ Configuration backed up"

restore-config: ## Restore latest configuration backup
	@latest=$$(ls -t config.ini.backup.* 2>/dev/null | head -1); \
	if [ -n "$$latest" ]; then \
		cp "$$latest" config.ini; \
		echo "✅ Configuration restored from $$latest"; \
	else \
		echo "❌ No configuration backup found"; \
	fi

stats: ## Show project statistics
	@echo "📊 Web-Toolkit Pro Statistics:"
	@echo "  Python files: $$(find . -name '*.py' | wc -l)"
	@echo "  Lines of code: $$(find . -name '*.py' -exec cat {} \; | wc -l)"
	@echo "  Configuration files: $$(find . -name '*.ini' -o -name '*.conf' | wc -l)"
	@echo "  Test files: $$(find tests/ -name '*.py' | wc -l)"
	@echo "  Modules: $$(find modules/ -name '*.py' | wc -l)"

quick-start: install check-tools demo-scan ## Quick start: install, check tools, and run demo
	@echo "🚀 Quick start completed!"
	@echo "Next steps:"
	@echo "  1. Run: make install-tools (to install missing tools)"
	@echo "  2. Scan a target: $(PYTHON) web-toolkit-pro.py --scan your-target.com"
