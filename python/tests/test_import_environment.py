"""Guard against running the suite against a stale installed wheel."""

from pathlib import Path

import agent_manifest


def test_tests_import_the_checkout_source_tree() -> None:
    package_path = Path(agent_manifest.__file__).resolve()
    source_tree = (Path(__file__).parents[1] / "src").resolve()

    assert package_path.is_relative_to(source_tree), (
        f"tests imported agent_manifest from {package_path}, not {source_tree}"
    )
