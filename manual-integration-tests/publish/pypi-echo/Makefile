PYTHON ?= python3
VPYTHON := .venv/bin/python3
VPIP := .venv/bin/pip
PYPI_UPLOAD_URL := http://localhost:8081/repository/pypi-a/

.PHONY: build publish setup

build: setup
	$(VPYTHON) -m build

publish: build
	$(VPYTHON) -m twine upload --repository-url "$(PYPI_UPLOAD_URL)" dist/*

.venv:
	$(PYTHON) -m venv .venv

setup: .venv
	$(VPIP) install -e '.[publish]'
