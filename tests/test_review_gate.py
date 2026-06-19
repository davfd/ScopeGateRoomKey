from __future__ import annotations

from roomkey.demo_scenarios import run_local_demo


def test_three_reviewer_gate_deposits_are_independent_and_scoped(sample_case_path, tmp_path):
    receipt = run_local_demo(sample_case_path, out=tmp_path / "receipt.json")

    deposits = receipt["reviewer_deposits"]
    assert len(deposits) == 3
    assert {deposit["reviewer"] for deposit in deposits} == {"ReviewerA", "ReviewerB", "ReviewerC"}
    assert all(deposit["verdict"] in {"ALLOW", "BOUNCE", "HUMAN_ESCALATE"} for deposit in deposits)
    assert all(deposit["received_context_keys"] for deposit in deposits)
    assert all(deposit["independent"] is True for deposit in deposits)
    assert receipt["review_gate"]["reviewer_count"] == 3
    assert receipt["review_gate"]["final_outcome"] in {"ALLOW", "BOUNCE", "HUMAN_ESCALATE"}


def test_reviewer_receipts_do_not_expose_unscoped_payload(sample_case_path, sample_case_dict, tmp_path):
    receipt = run_local_demo(sample_case_path, out=tmp_path / "receipt.json")
    forbidden = sample_case_dict["protected_payload"]["bank_account"]
    canary = sample_case_dict["secret_canary"]

    assert forbidden not in str(receipt["reviewer_deposits"])
    assert canary not in str(receipt["reviewer_deposits"])
