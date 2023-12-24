PROJECT_NAME = crypto_pkg

SHELL_DOT = $(shell printf "\033[34;1m▶\033[0m")

.PHONY: tests
tests: $(info $(SHELL_DOT) testing package...)
	@pip install -e . > /dev/null && pip install pytest > /dev/null
	@python -m pytest tests

.PHONY: coverage
coverage: $(info $(SHELL_DOT) coverage testing package...)
	pip install -e . > /dev/null && pip install pytest pytest-cov > /dev/null
	python -m pytest tests --cov=$(PROJECT_NAME) --cov-fail-under=0

.PHONY: deps
deps: $(info $(SHELL_DOT) install required packages...)
	pip install -r requirements.txt

.PHONY: setup
setup: $(info $(SHELL_DOT) Install packge)
	pip install -e .

.PHONY: build
build: $(info $(SHELL_DOT) build package)
	rm -rf dist
	python -m build

.PHONY: publishtest
publishtest: $(info $(SHELL_DOT) Publish package to test PyPI)
	python -m twine upload --repository testpypi dist/*

.PHONY: publish
publish: $(info $(SHELL_DOT) Publish package to PyPI)
	python -m twine upload dist/*
