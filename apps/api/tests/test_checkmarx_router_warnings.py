from __future__ import annotations

import importlib
import os
import sys
import warnings

os.environ.setdefault("DATABASE_URL", "sqlite+pysqlite:///:memory:")


def test_checkmarx_router_import_has_no_regex_deprecation_warning() -> None:
    module_name = "app.api.routers.checkmarx"
    sys.modules.pop(module_name, None)

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always", DeprecationWarning)
        importlib.import_module(module_name)

    assert not any(
        "`regex` has been deprecated" in str(warning.message)
        for warning in caught
        if issubclass(warning.category, DeprecationWarning)
    )
