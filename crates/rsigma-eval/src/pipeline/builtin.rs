use super::Pipeline;
use super::parsing::parse_pipeline;
use crate::error::Result;

const ECS_WINDOWS_YAML: &str = include_str!("../../pipelines/ecs_windows.yml");
const ECS_LINUX_YAML: &str = include_str!("../../pipelines/ecs_linux.yml");
const FIBRATUS_WINDOWS_YAML: &str = include_str!("../../pipelines/fibratus_windows.yml");
const SYSMON_YAML: &str = include_str!("../../pipelines/sysmon.yml");

/// Builtin pipeline entries: (name, yaml_content).
const BUILTIN_PIPELINES: &[(&str, &str)] = &[
    ("ecs_windows", ECS_WINDOWS_YAML),
    ("ecs_linux", ECS_LINUX_YAML),
    ("fibratus_windows", FIBRATUS_WINDOWS_YAML),
    ("sysmon", SYSMON_YAML),
];

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
    &["ecs_windows", "ecs_linux", "fibratus_windows", "sysmon"]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::pipeline::{RuleCondition, Transformation};
    use rsigma_parser::SigmaValue;

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
    fn fibratus_windows_parses_successfully() {
        let pipeline = resolve_builtin("fibratus_windows").unwrap().unwrap();
        assert_eq!(pipeline.name, "fibratus_windows");
        assert_eq!(pipeline.priority, 20);
        assert!(!pipeline.transformations.is_empty());
    }

    #[test]
    fn ecs_linux_parses_successfully() {
        let pipeline = resolve_builtin("ecs_linux").unwrap().unwrap();
        assert_eq!(pipeline.name, "ecs_linux");
        assert_eq!(pipeline.priority, 20);
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
        assert!(names.contains(&"ecs_linux"));
        assert!(names.contains(&"fibratus_windows"));
        assert!(names.contains(&"sysmon"));
    }

    fn event_ids(values: &[SigmaValue]) -> Vec<i64> {
        values
            .iter()
            .filter_map(|v| match v {
                SigmaValue::Integer(n) => Some(*n),
                _ => None,
            })
            .collect()
    }

    fn sysmon_eventid_route(category: &str) -> Option<Vec<i64>> {
        let pipeline = resolve_builtin("sysmon").unwrap().unwrap();
        pipeline.transformations.iter().find_map(|item| {
            if let Transformation::AddCondition { conditions, .. } = &item.transformation
                && let Some(evts) = conditions.get("EventID")
                && let Some(rule_cond) = item.rule_conditions.conditions.first()
                && let RuleCondition::Logsource {
                    category: Some(cat),
                    ..
                } = &rule_cond.condition
                && cat == category
            {
                return Some(event_ids(evts));
            }
            None
        })
    }

    #[test]
    fn sysmon_builtin_routes_new_categories() {
        assert_eq!(sysmon_eventid_route("sysmon_status").unwrap(), vec![4, 16]);
        assert_eq!(
            sysmon_eventid_route("registry_event").unwrap(),
            vec![12, 13, 14]
        );
        assert_eq!(sysmon_eventid_route("wmi_event").unwrap(), vec![19, 20, 21]);
        assert_eq!(
            sysmon_eventid_route("file_block_shredding").unwrap(),
            vec![28]
        );
        assert_eq!(sysmon_eventid_route("pipe_created").unwrap(), vec![17, 18]);
        assert_eq!(sysmon_eventid_route("sysmon_error").unwrap(), vec![255]);
    }

    #[test]
    fn sysmon_builtin_eventid_order() {
        let pipeline = resolve_builtin("sysmon").unwrap().unwrap();
        let routes: Vec<Vec<i64>> = pipeline
            .transformations
            .iter()
            .filter_map(|item| {
                if let Transformation::AddCondition { conditions, .. } = &item.transformation
                    && let Some(evts) = conditions.get("EventID")
                {
                    let nums = event_ids(evts);
                    if !nums.is_empty() {
                        return Some(nums);
                    }
                }
                None
            })
            .collect();

        for pair in routes.windows(2) {
            let prev_min = pair[0].iter().copied().min().unwrap();
            let next_min = pair[1].iter().copied().min().unwrap();
            assert!(
                prev_min <= next_min,
                "sysmon routing: {:?} (min {prev_min}) is not before {:?} (min {next_min})",
                pair[0],
                pair[1]
            );
        }
    }
}
