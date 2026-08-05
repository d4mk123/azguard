from azguard.charts import donut_chart, severity_bar_chart


def test_donut_chart_returns_data_uri():
    result = donut_chart({"pass": 5, "fail": 3, "manual": 2})
    assert result.startswith("data:image/png;base64,")
    assert len(result) > 100


def test_donut_chart_empty():
    result = donut_chart({})
    assert result.startswith("data:image/png;base64,")


def test_donut_chart_zero_counts():
    result = donut_chart({"pass": 0, "fail": 0, "manual": 0})
    assert result.startswith("data:image/png;base64,")


def test_donut_chart_partial_counts():
    result = donut_chart({"pass": 10, "fail": 0, "manual": 0})
    assert result.startswith("data:image/png;base64,")


def test_severity_bar_chart_returns_data_uri():
    result = severity_bar_chart({"Critical": 2, "High": 1, "Medium": 3, "Low": 0})
    assert result.startswith("data:image/png;base64,")
    assert len(result) > 100


def test_severity_bar_chart_empty():
    result = severity_bar_chart({})
    assert result.startswith("data:image/png;base64,")


def test_severity_bar_chart_single_severity():
    result = severity_bar_chart({"Critical": 5})
    assert result.startswith("data:image/png;base64,")
