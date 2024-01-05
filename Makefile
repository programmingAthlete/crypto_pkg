PROJECT_NAME = crypto_pkg

SHELL_DOT = $(shell printf "\033[34;1m▶\033[0m")


.DEFAULT_GOAL := help

.PHONY: help
help:
	@echo "Available targets:"
	@echo "$(SHELL_DOT) help          - Display this help message"
	@echo "$(SHELL_DOT) setup         - Install package"
	@echo "$(SHELL_DOT) deps          - Install dependencies"
	@echo "$(SHELL_DOT) tests         - Run tests"
	@echo "$(SHELL_DOT) coverage      - Run coverage tests"
	@echo "$(SHELL_DOT) lint          - Run flake8 for linting"

.PHONY: tests
tests:
	@$(info $(SHELL_DOT) testing package...)
	@pip install -e . > /dev/null && pip install pytest > /dev/null
	@python -m pytest tests

.PHONY: coverage
coverage:
	@$(info $(SHELL_DOT) coverage testing package...)
	pip install -e . > /dev/null && pip install pytest pytest-cov > /dev/null
	python -m pytest tests --cov=$(PROJECT_NAME) --cov-fail-under=0

.PHONY: deps
deps:
	@$(info $(SHELL_DOT) install required packages...)
	pip install -r requirements.txt

.PHONY: setup
setup:
	@$(info $(SHELL_DOT) Install packge)
	pip install -e .


.PHONY: lint
lint:
	@$(info $(M) coverage testing package...)
	pip install -e . > /dev/null && pip install flake8 > /dev/null
	flake8 src/$(PROJECT_NAME)

