//! Pins the disposition-source recipe fixtures embedded in the
//! disposition-recipes guide.
//!
//! Each recipe under `tests/fixtures/disposition_recipes/` is the exact
//! `--disposition-source` sources file the guide shows. This test parses each
//! with the real loader, runs its jq `extract` over a canned sample of that
//! case system's API response (swapping the HTTP transport for a `File` source
//! over the sample, since the `extract` and `format` are what the recipe
//! actually pins), and asserts the reshaped output validates as disposition
//! records with the expected verdicts and identities. Docs that embed the exact
//! tested files therefore cannot drift from what the engine accepts.

use std::path::{Path, PathBuf};
use std::time::Duration;

use rsigma_eval::pipeline::sources::{DynamicSource, ErrorPolicy, RefreshPolicy, SourceType};
use rsigma_runtime::dispositions::{Disposition, Verdict, parse_dispositions};
use rsigma_runtime::sources::{DefaultSourceResolver, SourceResolver};

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/disposition_recipes")
}

/// Parse a recipe sources file and return its single source.
fn parse_recipe(recipe: &str) -> DynamicSource {
    let sources = rsigma_eval::parse_sources_file(&fixture_dir().join(recipe))
        .expect("recipe sources file parses");
    assert_eq!(sources.len(), 1, "{recipe} declares exactly one source");
    sources.into_iter().next().unwrap()
}

/// Every recipe polls an HTTP source on a 5-minute interval with an env-scoped
/// auth header. This pins the source-file schema each recipe documents so a
/// silently-dropped key (a bad `refresh`, a missing `method`/`body`) is caught.
#[test]
fn recipes_declare_the_documented_schema() {
    for (recipe, auth_header, auth_ref) in [
        ("github.yml", "Authorization", "${GITHUB_TOKEN}"),
        ("jira.yml", "Authorization", "${JIRA_BASIC_AUTH}"),
        ("thehive.yml", "Authorization", "${THEHIVE_API_KEY}"),
    ] {
        let source = parse_recipe(recipe);
        assert_eq!(
            source.refresh,
            RefreshPolicy::Interval(Duration::from_secs(300)),
            "{recipe} polls on a 5m interval"
        );
        let SourceType::Http {
            headers, extract, ..
        } = &source.source_type
        else {
            panic!("{recipe} must declare an http source");
        };
        assert!(extract.is_some(), "{recipe} carries an extract");
        assert!(
            headers
                .get(auth_header)
                .is_some_and(|v| v.contains(auth_ref)),
            "{recipe} authenticates with the {auth_ref} environment reference"
        );
    }

    // TheHive 5 searches cases with a POST body; the others are GET polls.
    let SourceType::Http { method, body, .. } = parse_recipe("thehive.yml").source_type else {
        unreachable!()
    };
    assert_eq!(method.as_deref(), Some("POST"), "thehive uses POST /query");
    assert!(
        body.as_deref().is_some_and(|b| b.contains("listCase")),
        "thehive carries the listCase query body"
    );
}

/// Parse the recipe sources file, then resolve its `extract` over the canned
/// sample by swapping the HTTP source for a `File` source with the same
/// `format` and `extract`.
async fn resolve_recipe(recipe: &str, sample: &str) -> serde_json::Value {
    let dir = fixture_dir();
    let sources =
        rsigma_eval::parse_sources_file(&dir.join(recipe)).expect("recipe sources file parses");
    assert_eq!(sources.len(), 1, "{recipe} declares exactly one source");

    let (format, extract) = match &sources[0].source_type {
        SourceType::Http {
            format, extract, ..
        } => (*format, extract.clone()),
        other => panic!("{recipe} must declare an http source, got {other:?}"),
    };
    assert!(
        extract.is_some(),
        "{recipe} must carry an extract expression"
    );

    let file_source = DynamicSource {
        id: "recipe".to_string(),
        source_type: SourceType::File {
            path: dir.join(sample),
            format,
            extract,
        },
        refresh: RefreshPolicy::Once,
        timeout: None,
        on_error: ErrorPolicy::Fail,
        required: true,
        default: None,
    };

    DefaultSourceResolver::new()
        .resolve(&file_source)
        .await
        .expect("extract resolves over the sample payload")
        .data
}

/// Resolve the recipe, parse the reshaped output as disposition records, and
/// validate each, returning `(rule_id, verdict, incident_id)` tuples sorted for
/// stable comparison.
async fn recipe_dispositions(recipe: &str, sample: &str) -> Vec<(String, Verdict, Option<String>)> {
    let value = resolve_recipe(recipe, sample).await;
    let text = serde_json::to_string(&value).expect("reshaped output serializes");

    let raws = parse_dispositions(&text).expect("reshaped output parses as dispositions");
    let mut out: Vec<(String, Verdict, Option<String>)> = raws
        .into_iter()
        .map(|raw| {
            let d = Disposition::from_raw(raw, 0).expect("reshaped record validates");
            (
                d.rule_id.expect("detection scope carries a rule_id"),
                d.verdict,
                d.incident_id,
            )
        })
        .collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    out
}

#[tokio::test]
async fn github_recipe_reshapes_closed_issues() {
    let got = recipe_dispositions("github.yml", "github_sample.json").await;
    assert_eq!(
        got,
        vec![
            (
                "proc-injection".to_string(),
                Verdict::FalsePositive,
                Some("7f3c9a2b".to_string()),
            ),
            (
                "susp-powershell".to_string(),
                Verdict::TruePositive,
                Some("a1b2c3d4".to_string()),
            ),
        ],
        "the pull request and the verdict-less issue are dropped; the two \
         labeled issues reshape to disposition records"
    );
}

#[tokio::test]
async fn jira_recipe_reshapes_resolved_issues() {
    let got = recipe_dispositions("jira.yml", "jira_sample.json").await;
    assert_eq!(
        got,
        vec![
            (
                "proc-injection".to_string(),
                Verdict::FalsePositive,
                Some("7f3c9a2b".to_string()),
            ),
            (
                "susp-powershell".to_string(),
                Verdict::TruePositive,
                Some("a1b2c3d4".to_string()),
            ),
        ],
        "the null-resolution issue and the unmapped \"Done\" resolution are \
         dropped; the two verdict resolutions reshape to disposition records"
    );
}

#[tokio::test]
async fn thehive_recipe_reshapes_resolved_cases() {
    let got = recipe_dispositions("thehive.yml", "thehive_sample.json").await;
    assert_eq!(
        got,
        vec![
            (
                "proc-injection".to_string(),
                Verdict::FalsePositive,
                Some("7f3c9a2b".to_string()),
            ),
            (
                "susp-powershell".to_string(),
                Verdict::TruePositive,
                Some("a1b2c3d4".to_string()),
            ),
        ],
        "the Indeterminate case is dropped; TruePositive and FalsePositive \
         reshape to disposition records"
    );
}
