import sys
from pathlib import Path

import pytest

APPS_FIXED = Path(__file__).resolve().parent.parent / "apps" / "fixed"
if str(APPS_FIXED) not in sys.path:
    sys.path.insert(0, str(APPS_FIXED))

from sentinel_fixed import create_app  # noqa: E402


@pytest.fixture
def app(tmp_path):
    flask_app = create_app(log_dir=tmp_path)
    flask_app.config.update(TESTING=True)
    return flask_app


@pytest.fixture
def client(app):
    return app.test_client()


APPS_VULN = Path(__file__).resolve().parent.parent / "apps" / "vulnerable"
if str(APPS_VULN) not in sys.path:
    sys.path.insert(0, str(APPS_VULN))

from sentinel_vuln import create_app as create_vuln_app  # noqa: E402


@pytest.fixture
def vuln_client(tmp_path):
    flask_app = create_vuln_app(log_dir=tmp_path)
    flask_app.config.update(TESTING=True)
    return flask_app.test_client()
