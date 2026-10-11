# One-command entry points. `make up` starts the local stack.
.PHONY: up down test

up:
	@test -f observability/.env || cp .env.example observability/.env
	cd observability && docker compose up -d --build

down:
	cd observability && docker compose down

test:
	@test -x .venv/bin/pytest || (python3 -m venv .venv && .venv/bin/pip install -r requirements-dev.txt)
	.venv/bin/pytest -q
