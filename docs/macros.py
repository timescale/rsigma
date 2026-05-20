"""MkDocs macros hook that reads package metadata from the workspace Cargo.toml.

Keeps docs variables ({{ rsigma.version }}, {{ rsigma.msrv }}, etc.) in sync
with the source of truth automatically, so vars.yml never drifts.
"""

from pathlib import Path

try:
    import tomllib
except ModuleNotFoundError:
    import tomli as tomllib  # Python < 3.11


def define_env(env):
    cargo_toml = Path(env.project_dir) / "Cargo.toml"
    with cargo_toml.open("rb") as f:
        cargo = tomllib.load(f)

    pkg = cargo["workspace"]["package"]

    env.variables["rsigma"]["version"] = pkg["version"]
    env.variables["rsigma"]["edition"] = pkg["edition"]
    env.variables["rsigma"]["msrv"] = pkg["rust-version"]
    env.variables["rsigma"]["license"] = pkg["license"]
