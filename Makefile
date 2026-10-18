PYTHON ?= .venv/bin/python

.PHONY: install link run smoke shots headless clean

install:
	uv venv && uv pip install -e .

link:
	ln -sf $(CURDIR)/.venv/bin/sunder $(HOME)/.local/bin/sunder

run:
	$(PYTHON) -m sunder

smoke:
	$(PYTHON) scripts/smoke.py

shots:
	$(PYTHON) scripts/shots.py

headless:
	$(PYTHON) -m sunder example.com

clean:
	rm -rf .venv build dist src/*.egg-info
