//! Load line-oriented pattern fixture files.

pub fn fixture_lines(name: &str) -> Vec<String> {
    let path = format!("tests/fixtures/pattern/{name}");
    std::fs::read_to_string(&path)
        .unwrap_or_else(|e| panic!("read fixture {name}: {e}"))
        .lines()
        .filter(|line| !line.trim().is_empty() && !line.trim_start().starts_with('#'))
        .map(str::trim)
        .map(str::to_owned)
        .collect()
}
