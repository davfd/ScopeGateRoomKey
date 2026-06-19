PYTHON ?= python3
RECEIPT ?= receipts/live-band-demo-20260618T185330Z.json

.PHONY: test verify-receipt judge-proof secret-scan integrity-check banned-claims site-check submit-check demo-local demo-band-live

test:
	PYTHONPATH=src $(PYTHON) -m pytest -q

verify-receipt:
	PYTHONPATH=src $(PYTHON) -m roomkey.cli verify $(RECEIPT)

judge-proof:
	PYTHONPATH=src $(PYTHON) scripts/judge_proof.py $(RECEIPT)

secret-scan:
	$(PYTHON) scripts/secret_scan.py

integrity-check:
	$(PYTHON) scripts/integrity_check.py

banned-claims:
	$(PYTHON) scripts/site_check.py --banned-claims README.md docs site src tests scripts

site-check:
	$(PYTHON) scripts/site_check.py site/index.html site/evidence.json

submit-check:
	$(PYTHON) scripts/submit_check.py

demo-local:
	PYTHONPATH=src $(PYTHON) -m roomkey.cli demo local --case samples/vendor_wire_sensitive.json --out receipts/local-demo.json

demo-band-live:
	PYTHONPATH=src $(PYTHON) -m roomkey.cli band demo --room $${BAND_ROOM_ID:?set BAND_ROOM_ID} --case samples/vendor_wire_sensitive.json --out receipts/live-band-demo-new.json
