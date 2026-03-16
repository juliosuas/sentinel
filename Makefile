.PHONY: run run-syslog run-filewatcher test clean setup docker-up docker-down

setup:
	python -m venv venv
	. venv/bin/activate && pip install -r requirements.txt
	cp -n .env.example .env 2>/dev/null || true

run:
	PYTHONPATH=. python -m backend.server

run-syslog:
	PYTHONPATH=. python -c "from collectors.syslog import SyslogCollector; s = SyslogCollector(); s.start()"

run-filewatcher:
	PYTHONPATH=. python -c "from collectors.file_watcher import FileWatcher; f = FileWatcher(); f.start()"

test:
	PYTHONPATH=. python -m pytest tests/ -v

clean:
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
	rm -f sentinel.db
	rm -rf data/

docker-up:
	docker-compose up -d --build

docker-down:
	docker-compose down
