.PHONY: test run

run: db.db
	./handlers.py

db.db: createTables
	./createTables

test:
	python3 -m unittest
