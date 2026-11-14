"""Smoke-tests every Streamlit page with streamlit.testing (no browser needed)."""
import pytest
from streamlit.testing.v1 import AppTest

from forensic.pipeline import run_on_samples
from tests.conftest import ROOT

PAGES = ["app.py", "pages/1_Upload.py", "pages/2_Timeline.py", "pages/3_Graph.py", "pages/4_Investigation_Report.py"]


@pytest.mark.parametrize("page", PAGES)
def test_page_renders_without_exception(page):
    at = AppTest.from_file(str(ROOT / page), default_timeout=60)
    at.session_state["result"] = run_on_samples()
    at.run()
    assert not at.exception, at.exception


def test_pages_handle_missing_result():
    at = AppTest.from_file(str(ROOT / "pages/2_Timeline.py"), default_timeout=60)
    at.run()
    assert not at.exception
