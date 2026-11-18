import scoring

def test_zero():            assert scoring.compute_score(0, 0, 0) == 0
def test_max():             assert scoring.compute_score(0, 0, 10) == 100
def test_nul():             assert scoring.compute_score(10, 0, 0) == 0
def test_a_verifier():      assert scoring.compute_score(0, 10, 0) == 50
def test_melange():         assert scoring.compute_score(1, 1, 2) == 62
def test_bandes():
    assert scoring.score_band(39)["key"] == "crit"
    assert scoring.score_band(40)["key"] == "warn"
    assert scoring.score_band(74)["key"] == "warn"
    assert scoring.score_band(75)["key"] == "ok"
def test_jauge():
    assert scoring.gauge_dasharray(0) == 0 and scoring.gauge_dasharray(100) == 251.3
