"""Tests ensuring credential replay clients and verb helpers are completely removed (Gate 1)."""

import importlib
import pytest


def test_client_module_removed():
    """Verify that motim.client and motim.db_client modules cannot be imported."""
    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("motim.client")

    with pytest.raises(ModuleNotFoundError):
        importlib.import_module("motim.db_client")


def test_package_exports_no_clients():
    """Verify motim package does not export any active network clients or verb helpers."""
    import motim

    for symbol in (
        "Client",
        "AsyncClient",
        "DBClient",
        "get",
        "post",
        "put",
        "delete",
        "patch",
        "request",
    ):
        assert not hasattr(motim, symbol), f"motim should not export {symbol}"
        assert symbol not in getattr(motim, "__all__", ()), f"{symbol} should not be in __all__"

