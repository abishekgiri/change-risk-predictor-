.PHONY: test verify phase6 demo validate-policy-bundle validate-jira-config clean

test:
	pytest

verify:
	python3 scripts/verify_features.py

# Phase 6: Enterprise UX & Trust Verification
phase6:
	./scripts/run_phase6.sh

demo:
	python3 scripts/demo_block_override_export.py

validate-policy-bundle:
	python3 -m releasegate.cli validate-policy-bundle

validate-jira-config:
	python3 -m releasegate.cli validate-jira-config

clean:
	rm -rf __pycache__
	rm -rf .pytest_cache
	rm -rf releasegate/__pycache__
