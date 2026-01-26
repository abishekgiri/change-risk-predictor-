.PHONY: test verify phase6 clean

test:
	pytest

verify:
	python3 scripts/verify_features.py

# Phase 6: Enterprise UX & Trust Verification
phase6:
	./scripts/run_phase6.sh

clean:
	rm -rf __pycache__
	rm -rf .pytest_cache
	rm -rf compliancebot/__pycache__
