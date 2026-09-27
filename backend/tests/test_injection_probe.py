"""The injection probe (eval/injection_corpus.yaml) in CI: the tuned corpus
must stay fully caught with no false positives on any real demo-config line,
and no attack line in either set may reach the AI (gate + free-text rule).
The held-out catch rate is reported, not asserted - it is the honest
generalization number and is never tuned against."""
from eval.injection_probe import run


def test_injection_probe():
    r = run()
    assert r["missed"] == [] and r["false_positives"] == [] and r["planted_missed"] == []
    assert r["held_out_false_positives"] == []
    assert r["reach_the_ai"] == 0, r["reaching_lines"]
