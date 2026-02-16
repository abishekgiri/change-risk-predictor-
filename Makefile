.PHONY: test verify phase6 demo demo-json golden validate-policy-bundle validate-jira-config clean

GOLDEN_ENV=COMPLIANCE_DB_PATH=out/golden/releasegate_golden.db RELEASEGATE_STORAGE_BACKEND=sqlite RELEASEGATE_TENANT_ID=golden-demo RELEASEGATE_STRICT_MODE=true RELEASEGATE_CHECKPOINT_SIGNING_KEY=golden-demo-checkpoint-signing-key RELEASEGATE_CHECKPOINT_SIGNING_KEY_ID=golden-demo-key

test:
	pytest

verify:
	python3 scripts/verify_features.py

# Phase 6: Enterprise UX & Trust Verification
phase6:
	./scripts/run_phase6.sh

demo:
	RELEASEGATE_TENANT_ID=$${RELEASEGATE_TENANT_ID:-demo} python3 scripts/demo_block_override_export.py

demo-json:
	@RELEASEGATE_TENANT_ID=$${RELEASEGATE_TENANT_ID:-demo} python3 scripts/demo_block_override_export.py --format json

golden:
	mkdir -p out/golden
	$(GOLDEN_ENV) python3 -m releasegate.cli db-migrate
	$(GOLDEN_ENV) python3 -m releasegate.cli validate-policy-bundle
	$(GOLDEN_ENV) python3 -m releasegate.cli validate-jira-config --transition-map tests/fixtures/golden/jira_transition_map.yaml --role-map tests/fixtures/golden/jira_role_map.yaml
	$(GOLDEN_ENV) python3 scripts/golden.py

validate-policy-bundle:
	python3 -m releasegate.cli validate-policy-bundle

validate-jira-config:
	python3 -m releasegate.cli validate-jira-config

clean:
	rm -rf __pycache__
	rm -rf .pytest_cache
	rm -rf releasegate/__pycache__
