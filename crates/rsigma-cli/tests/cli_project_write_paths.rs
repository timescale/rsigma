//! Paths that project config files (`./rsigma.yaml`, `.rsigmarc`) name for
//! rsigma to write must stay inside the project, and commands that rewrite a
//! tree only touch entries physically inside it.
//!
//! Each test lays out `<root>/project` and `<root>/outside` so a `../`
//! escape lands in a directory the test owns.

use crate::common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use common::rsigma_isolated as rsigma;
use serde_json::Value;

const RULE: &str = r#"title: Whoami
id: aaaaaaaa-0000-4000-8000-000000000001
status: test
description: Detects whoami.
author: Test Author
date: 2025-01-01
level: low
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
tags:
    - attack.discovery
    - attack.t1033
"#;

const VICTIM: &str = "operator data\n";

struct Layout {
    _root: tempfile::TempDir,
    project: PathBuf,
    outside: PathBuf,
    xdg: PathBuf,
}

fn layout() -> Layout {
    let root = tempfile::tempdir().unwrap();
    let project = root.path().join("project");
    let outside = root.path().join("outside");
    let xdg = root.path().join("xdg");
    for dir in [&project, &outside, &xdg] {
        fs::create_dir_all(dir).unwrap();
    }
    fs::create_dir_all(project.join("rules")).unwrap();
    fs::write(project.join("rules/whoami.yml"), RULE).unwrap();
    Layout {
        _root: root,
        project,
        outside,
        xdg,
    }
}

fn run(layout: &Layout, args: &[&str]) -> Output {
    rsigma()
        .current_dir(&layout.project)
        .env("XDG_CONFIG_HOME", &layout.xdg)
        .args(args)
        .output()
        .expect("run rsigma")
}

fn stderr(output: &Output) -> String {
    String::from_utf8_lossy(&output.stderr).into_owned()
}

fn json_stdout(output: &Output) -> Value {
    serde_json::from_slice(&output.stdout).unwrap_or_else(|error| {
        panic!(
            "stdout is not JSON ({error}): {}",
            String::from_utf8_lossy(&output.stdout)
        )
    })
}

/// A YAML scalar for `path`, quoted so Windows backslashes survive.
fn yaml_path(path: &Path) -> String {
    format!("'{}'", path.display())
}

fn convert_config(groups: &[(&str, &str)]) -> String {
    let mut body = String::from("rulesets:\n  local:\n    sources: [rules]\nconvert:\n  groups:\n");
    for (name, output) in groups {
        body.push_str(&format!(
            "    {name}:\n      ruleset: local\n      target: test\n      output: {output}\n"
        ));
    }
    body
}

fn ignored_keys(envelope: &Value) -> Vec<String> {
    envelope["ignored_keys"]
        .as_array()
        .unwrap_or_else(|| panic!("no ignored_keys in {envelope}"))
        .iter()
        .map(|entry| entry["key"].as_str().unwrap().to_string())
        .collect()
}

fn entries(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = fs::read_dir(dir)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    names.sort();
    names
}

/// Link `link` to the directory `target`: a symlink on Unix, a junction on
/// Windows (which needs no privilege).
fn link_dir(target: &Path, link: &Path) {
    #[cfg(unix)]
    std::os::unix::fs::symlink(target, link).unwrap();
    #[cfg(windows)]
    {
        let status = std::process::Command::new("cmd")
            .arg("/C")
            .arg("mklink")
            .arg("/J")
            .arg(link)
            .arg(target)
            .output()
            .unwrap();
        assert!(status.status.success(), "mklink /J failed: {status:?}");
    }
}

/// Link `link` to the file `target`. Returns false where the platform does
/// not let this process create file symlinks (Windows without developer
/// mode).
fn link_file(target: &Path, link: &Path) -> bool {
    #[cfg(unix)]
    {
        std::os::unix::fs::symlink(target, link).unwrap();
        true
    }
    #[cfg(windows)]
    {
        std::os::windows::fs::symlink_file(target, link).is_ok()
    }
}

#[test]
fn project_convert_outputs_outside_the_project_are_ignored() {
    let layout = layout();
    let absolute = yaml_path(&layout.outside.join("absolute.txt"));
    let config = convert_config(&[
        ("absolute", &absolute),
        ("parent", "../outside/parent.txt"),
        ("nested", "build/../../outside/nested.txt"),
    ]);
    fs::write(layout.project.join("rsigma.yaml"), config).unwrap();

    let output = run(&layout, &["backend", "build"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    let err = stderr(&output);
    for group in ["absolute", "parent", "nested"] {
        assert!(
            err.contains(&format!(
                "warning: ignoring 'convert.groups.{group}.output' from project config"
            )),
            "{err}"
        );
        assert!(
            err.contains(&format!("group '{group}': no output is set")),
            "{err}"
        );
    }
    assert!(entries(&layout.outside).is_empty());

    let validate = run(&layout, &["config", "validate", "--format", "json"]);
    let envelope = json_stdout(&validate);
    assert_eq!(
        ignored_keys(&envelope),
        [
            "convert.groups.absolute.output",
            "convert.groups.nested.output",
            "convert.groups.parent.output",
        ]
    );
    assert!(
        envelope["ignored_keys"][0]["file"]
            .as_str()
            .unwrap()
            .ends_with("rsigma.yaml")
    );

    let show = run(&layout, &["config", "show", "--format", "json"]);
    assert!(show.status.success(), "{}", stderr(&show));
    let envelope = json_stdout(&show);
    assert_eq!(ignored_keys(&envelope).len(), 3);
    assert!(
        envelope["config"]["convert"]["groups"]["parent"]["output"].is_null(),
        "{envelope}"
    );
    let text = run(&layout, &["config", "show"]);
    assert!(
        stderr(&text).contains("warning: ignoring 'convert.groups.parent.output'"),
        "{}",
        stderr(&text)
    );
}

#[test]
fn project_convert_default_output_outside_the_project_is_ignored() {
    let layout = layout();
    let body = format!(
        "rulesets:\n  local:\n    sources: [rules]\nconvert:\n  defaults:\n    output: {}\n  groups:\n    only:\n      ruleset: local\n      target: test\n",
        yaml_path(&layout.outside.join("default.txt"))
    );
    fs::write(layout.project.join(".rsigmarc"), body).unwrap();

    let output = run(&layout, &["backend", "build"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("warning: ignoring 'convert.defaults.output' from project config"),
        "{}",
        stderr(&output)
    );
    assert!(entries(&layout.outside).is_empty());
}

#[test]
fn project_convert_output_through_a_linked_directory_is_ignored() {
    let layout = layout();
    link_dir(&layout.outside, &layout.project.join("build"));
    let config = convert_config(&[
        ("linked", "build/linked.txt"),
        ("missing", "build/new/dirs/missing.txt"),
    ]);
    fs::write(layout.project.join("rsigma.yaml"), config).unwrap();

    let output = run(&layout, &["backend", "build"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("ignoring 'convert.groups.linked.output'"),
        "{}",
        stderr(&output)
    );
    assert!(
        stderr(&output).contains("ignoring 'convert.groups.missing.output'"),
        "{}",
        stderr(&output)
    );
    assert!(entries(&layout.outside).is_empty());
}

#[test]
fn project_convert_output_whose_manifest_is_linked_outside_is_ignored() {
    let layout = layout();
    let victim = layout.outside.join("victim.json");
    fs::write(&victim, VICTIM).unwrap();
    fs::create_dir_all(layout.project.join("build")).unwrap();
    if !link_file(
        &victim,
        &layout.project.join("build/queries.txt.manifest.json"),
    ) {
        return;
    }
    let config = convert_config(&[("queries", "build/queries.txt")]);
    fs::write(layout.project.join("rsigma.yaml"), config).unwrap();

    let output = run(&layout, &["backend", "build"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("ignoring 'convert.groups.queries.output'"),
        "{}",
        stderr(&output)
    );
    assert_eq!(fs::read_to_string(&victim).unwrap(), VICTIM);
    assert!(!layout.project.join("build/queries.txt").exists());
}

#[test]
fn project_convert_outputs_inside_the_project_are_written() {
    let layout = layout();
    let absolute_inside = yaml_path(&layout.project.join("out/absolute.txt"));
    let config = convert_config(&[
        ("relative", "build/deep/nested/relative.txt"),
        ("absolute", &absolute_inside),
        ("dotted", "./build/../build/dotted.txt"),
    ]);
    fs::write(layout.project.join("rsigma.yaml"), config).unwrap();

    let output = run(&layout, &["backend", "build"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(!stderr(&output).contains("ignoring"), "{}", stderr(&output));
    for path in [
        "build/deep/nested/relative.txt",
        "build/deep/nested/relative.txt.manifest.json",
        "out/absolute.txt",
        "out/absolute.txt.manifest.json",
        "build/dotted.txt",
        "build/dotted.txt.manifest.json",
    ] {
        assert!(layout.project.join(path).is_file(), "{path} not written");
    }
}

#[test]
fn project_convert_output_replaces_an_in_project_symlink_instead_of_following_it() {
    let layout = layout();
    let target = layout.project.join("kept.txt");
    fs::write(&target, VICTIM).unwrap();
    fs::create_dir_all(layout.project.join("build")).unwrap();
    let link = layout.project.join("build/queries.txt");
    if !link_file(&target, &link) {
        return;
    }
    fs::write(
        layout.project.join("rsigma.yaml"),
        convert_config(&[("queries", "build/queries.txt")]),
    )
    .unwrap();

    let output = run(&layout, &["backend", "build"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(fs::read_to_string(&target).unwrap(), VICTIM);
    assert!(
        !fs::symlink_metadata(&link)
            .unwrap()
            .file_type()
            .is_symlink()
    );
}

#[test]
fn explicit_config_output_outside_the_project_is_written() {
    let layout = layout();
    let config = layout.outside.join("operator.yaml");
    let body = format!(
        "rulesets:\n  local:\n    sources: [{}]\nconvert:\n  groups:\n    operator:\n      ruleset: local\n      target: test\n      output: {}\n",
        yaml_path(&layout.project.join("rules")),
        yaml_path(&layout.outside.join("operator/queries.txt")),
    );
    fs::write(&config, body).unwrap();

    let output = run(
        &layout,
        &["backend", "build", "--config", config.to_str().unwrap()],
    );
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(layout.outside.join("operator/queries.txt").is_file());
    assert!(
        layout
            .outside
            .join("operator/queries.txt.manifest.json")
            .is_file()
    );
}

#[test]
fn user_config_output_outside_the_project_is_written() {
    let layout = layout();
    fs::create_dir_all(layout.xdg.join("rsigma")).unwrap();
    let body = format!(
        "rulesets:\n  local:\n    sources: [{}]\nconvert:\n  defaults:\n    output: {}\n  groups:\n    user:\n      ruleset: local\n      target: test\n",
        yaml_path(&layout.project.join("rules")),
        yaml_path(&layout.outside.join("user.txt")),
    );
    fs::write(layout.xdg.join("rsigma/config.yaml"), body).unwrap();

    let output = run(&layout, &["backend", "build"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(layout.outside.join("user.txt").is_file());
}

#[test]
fn project_ruleset_output_outside_the_project_is_ignored() {
    let layout = layout();
    let body = format!(
        "rulesets:\n  absolute:\n    sources: [rules]\n    output: {}\n  parent:\n    sources: [rules]\n    output: ../outside/parent\n  inside:\n    sources: [rules]\n    output: build/inside\n",
        yaml_path(&layout.outside.join("absolute"))
    );
    fs::write(layout.project.join("rsigma.yaml"), body).unwrap();

    for name in ["absolute", "parent"] {
        let output = run(&layout, &["ruleset", "build", name]);
        assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
        let err = stderr(&output);
        assert!(
            err.contains(&format!(
                "warning: ignoring 'rulesets.{name}.output' from project config"
            )),
            "{err}"
        );
        assert!(err.contains("has no output directory"), "{err}");
    }
    assert!(entries(&layout.outside).is_empty());

    let output = run(&layout, &["ruleset", "build", "inside"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert!(
        layout
            .project
            .join("build/inside/ruleset.lock.json")
            .is_file()
    );

    let validate = run(&layout, &["config", "validate", "--format", "json"]);
    assert_eq!(
        ignored_keys(&json_stdout(&validate)),
        ["rulesets.absolute.output", "rulesets.parent.output"]
    );
}

#[test]
fn project_backtest_findings_outside_the_project_are_ignored() {
    let layout = layout();
    let body = format!(
        "backtest:\n  findings: {}\n",
        yaml_path(&layout.outside.join("findings.ndjson"))
    );
    fs::write(layout.project.join("rsigma.yaml"), body).unwrap();

    let validate = run(&layout, &["config", "validate", "--format", "json"]);
    assert_eq!(ignored_keys(&json_stdout(&validate)), ["backtest.findings"]);
}

#[test]
fn ruleset_build_refuses_a_linked_subdirectory() {
    let layout = layout();
    let out = layout.project.join("build");
    fs::create_dir_all(&out).unwrap();
    fs::write(out.join("ruleset.lock.json"), "{}\n").unwrap();
    link_dir(&layout.outside, &out.join("rules"));
    fs::write(
        layout.project.join("rsigma.yaml"),
        "rulesets:\n  local:\n    sources: [rules]\n    output: build\n",
    )
    .unwrap();

    let output = run(&layout, &["ruleset", "build", "local"]);
    assert_eq!(output.status.code(), Some(3), "{}", stderr(&output));
    assert!(
        stderr(&output).contains("refusing to write through"),
        "{}",
        stderr(&output)
    );
    assert!(entries(&layout.outside).is_empty());
}

#[test]
fn ruleset_build_replaces_linked_files_instead_of_following_them() {
    let layout = layout();
    let out = layout.project.join("build");
    fs::create_dir_all(out.join("rules")).unwrap();
    let victim = layout.outside.join("victim.yml");
    let lock_victim = layout.outside.join("lock.json");
    fs::write(&victim, VICTIM).unwrap();
    fs::write(&lock_victim, VICTIM).unwrap();
    let generated = out.join("rules/aaaaaaaa-0000-4000-8000-000000000001.yml");
    if !link_file(&victim, &generated) || !link_file(&lock_victim, &out.join("ruleset.lock.json")) {
        return;
    }
    fs::write(
        layout.project.join("rsigma.yaml"),
        "rulesets:\n  local:\n    sources: [rules]\n    output: build\n",
    )
    .unwrap();

    let output = run(&layout, &["ruleset", "build", "local", "--force"]);
    assert!(output.status.success(), "{}", stderr(&output));
    assert_eq!(fs::read_to_string(&victim).unwrap(), VICTIM);
    assert_eq!(fs::read_to_string(&lock_victim).unwrap(), VICTIM);
    for path in [&generated, &out.join("ruleset.lock.json")] {
        let metadata = fs::symlink_metadata(path).unwrap();
        assert!(metadata.is_file(), "{} is still a link", path.display());
    }
}
