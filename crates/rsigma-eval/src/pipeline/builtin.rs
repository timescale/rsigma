use super::Pipeline;
use super::parsing::parse_pipeline;
use crate::error::Result;

const ECS_WINDOWS_YAML: &str = include_str!("../../pipelines/ecs_windows.yml");
const SYSMON_YAML: &str = include_str!("../../pipelines/sysmon.yml");

/// Builtin pipeline entries: (name, yaml_content).
const BUILTIN_PIPELINES: &[(&str, &str)] =
    &[("ecs_windows", ECS_WINDOWS_YAML), ("sysmon", SYSMON_YAML)];

/// Resolve a pipeline name to a parsed `Pipeline`.
///
/// Returns `Some(pipeline)` if the name matches a builtin pipeline,
/// `None` if the name is not a known builtin (caller should try as a file path).
pub fn resolve_builtin(name: &str) -> Option<Result<Pipeline>> {
    BUILTIN_PIPELINES
        .iter()
        .find(|(n, _)| *n == name)
        .map(|(_, yaml)| parse_pipeline(yaml))
}

/// Return the list of available builtin pipeline names.
pub fn builtin_names() -> &'static [&'static str] {
    &["ecs_windows", "sysmon"]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ecs_windows_parses_successfully() {
        let pipeline = resolve_builtin("ecs_windows").unwrap().unwrap();
        assert_eq!(pipeline.name, "ecs_windows");
        assert_eq!(pipeline.priority, 20);
        assert!(!pipeline.transformations.is_empty());
    }

    #[test]
    fn sysmon_parses_successfully() {
        let pipeline = resolve_builtin("sysmon").unwrap().unwrap();
        assert_eq!(pipeline.name, "sysmon");
        assert_eq!(pipeline.priority, 10);
        assert!(!pipeline.transformations.is_empty());
    }

    #[test]
    fn unknown_name_returns_none() {
        assert!(resolve_builtin("nonexistent").is_none());
    }

    #[test]
    fn builtin_names_lists_all() {
        let names = builtin_names();
        assert!(names.contains(&"ecs_windows"));
        assert!(names.contains(&"sysmon"));
    }
}
