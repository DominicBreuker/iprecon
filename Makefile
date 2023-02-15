.PHONY: dev-install
dev-install:
	pip3 install -e .

.PHONY: test
test:
	PYTHONPATH='./src' pytest

.PHONY: bump-minor
bump-minor:
	bumpver update --minor

.PHONY: build
build:
	python3 -m build
	twine check dist/*

.PHONY: publish
publish:
	twine upload dist/*

