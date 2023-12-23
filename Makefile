PROJECT_NAME = crypto_pkg

PYTHON = python

.PHONY: tests
tests:  $(info $(M) testing package...)
	pip install -e . > /dev/null && pip install pytest > /dev/null
	python -m pytest tests

.PHONY: coverage
coverage: $(info $(M) coverage testing package...)  ## test coverage package
	pip install -e . > /dev/null && pip install pytest pytest-cov > /dev/null
	python -m pytest tests --cov=$(PROJECT_NAME) --cov-fail-under=0

.PHONY: deps
deps: $(info $(M) install required packages...)
	pip install -r requirements.txt

.PHONY: setup
deps: $(info $(M) install required packages...)
	pip install -e .

.PHONY: build
build: $(info $(M) install required packages...)
	python -m build

.PHONY: publishtest
publishtest: $(info $(M) install required packages...)
	python -m twine upload --repository testpypi dist/*

.PHONY: publish
publish: $(info $(M) install required packages...)
	python -m twine upload dist/*
