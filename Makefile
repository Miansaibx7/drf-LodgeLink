.PHONY: help install sync update \
        run migrate makemigrations showmigrations \
        superuser shell check \
        test test-app \
        lint format format-check \
        collectstatic \
        clean

# Project Configuration
PYTHON := uv run python
MANAGE := $(PYTHON) manage.py
RUFF := uv run ruff
PYTEST := uv run pytest

# Help
help:
	@echo ""
	@echo "Django REST Framework Project"
	@echo "============================="
	@echo ""
	@echo "Setup:"
	@echo "  make install          Install project dependencies"
	@echo "  make sync             Synchronize environment with uv.lock"
	@echo "  make update           Update dependencies"
	@echo ""
	@echo "Development:"
	@echo "  make run              Start Django development server"
	@echo "  make shell            Open Django shell"
	@echo "  make check            Run Django system checks"
	@echo ""
	@echo "Database:"
	@echo "  make makemigrations   Create migrations"
	@echo "  make migrate          Apply migrations"
	@echo "  make showmigrations   Show migration status"
	@echo "  make superuser        Create Django superuser"
	@echo ""
	@echo "Testing:"
	@echo "  make test             Run test suite"
	@echo "  make test-app         Run tests for a specific app"
	@echo ""
	@echo "Code Quality:"
	@echo "  make lint             Check Python code"
	@echo "  make format           Format Python code"
	@echo "  make format-check     Check formatting without changing files"
	@echo ""
	@echo "Production:"
	@echo "  make collectstatic    Collect static files"
	@echo ""
	@echo "Maintenance:"
	@echo "  make clean            Remove Python cache files"
	@echo ""


# Environment & Dependencies
install:
	uv sync
	
sync:
	uv sync --locked

update:
	uv lock --upgrade
	uv sync


# Development
run:
	$(MANAGE) runserver

shell:
	$(MANAGE) shell

check:
	$(MANAGE) check


# Database
makemigrations:
	$(MANAGE) makemigrations

migrate:
	$(MANAGE) migrate

showmigrations:
	$(MANAGE) showmigrations

superuser:
	$(MANAGE) createsuperuser


# Testing
test:
	$(PYTEST)

test-app:
	$(PYTEST) $(APP)


# Code Quality
lint:
	$(RUFF) check .

format:
	$(RUFF) format .

format-check:
	$(RUFF) format --check .


# Production
collectstatic:
	$(MANAGE) collectstatic --noinput


# Maintenance
clean:
	@echo "Removing Python cache files..."
	find . -type d -name "__pycache__" -prune -exec rm -rf {} \;
	find . -type f -name "*.pyc" -delete
	find . -type f -name "*.pyo" -delete
	@echo "Clean completed."