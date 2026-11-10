//! Runs the platform's conformance vectors (`tests/vectors/*.json`, copied from
//! `crates/policy/tests/vectors` at the commit in `VECTORS_COMMIT`) against the embedded reference
//! evaluator, as the gate standard asks of every gate (section 8). The format is in the vectors'
//! README.

use std::collections::BTreeMap;
use std::net::IpAddr;
use std::path::{Path, PathBuf};

use policy::Compiled;
use policy::eval::{self, CounterUnavailable, Decision, Request, Step};
use policy::spec::Verdict;
use serde::Deserialize;
use serde_json::{Value, json};

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    #[allow(dead_code)]
    description: String,
    policy: Option<Compiled>,
    cases: Vec<Case>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    name: String,
    request: Request,
    #[serde(default)]
    transport: Option<Transport>,
    #[serde(default)]
    no_policy: Option<Verdict>,
    #[serde(default)]
    counts: Option<Vec<u64>>,
    #[serde(default)]
    counter_error: bool,
    expected: Expected,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Transport {
    remote_addr: Option<IpAddr>,
    headers: BTreeMap<String, String>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Expected {
    #[serde(default)]
    counted: Option<Value>,
    decision: Value,
}

fn run(file: &File, case: &Case) -> Result<(), String> {
    let Some(policy) = &file.policy else {
        let decision = eval::no_policy(case.no_policy.ok_or("no_policy is missing")?);
        return compare("decision", &json!(decision), &case.expected.decision);
    };
    let mut request = case.request.clone();
    if let Some(transport) = &case.transport {
        request.client_ip = eval::client_ip(
            policy,
            |name| transport.headers.get(name).map(String::as_str),
            transport.remote_addr,
        );
    }
    match eval::select(policy, &request) {
        Step::Done(decision) => {
            if case.expected.counted.is_some() {
                return Err("expected a count, but the request was decided without one".into());
            }
            compare("decision", &json!(decision), &case.expected.decision)
        }
        Step::Count(counted) => {
            let found: Vec<Value> = counted
                .counters
                .iter()
                .map(|counter| {
                    json!({
                        "rule": counted.rule.id,
                        "limit": counter.limit,
                        "key": counter.key,
                        "reset_s": counter.reset_s,
                    })
                })
                .collect();
            let found = Value::Array(found);
            let expected = case
                .expected
                .counted
                .as_ref()
                .ok_or_else(|| format!("expected no count, but counted {found}"))?;
            compare("counted", &found, expected)?;
            let counts: Vec<Result<u64, CounterUnavailable>> =
                match (&case.counts, case.counter_error) {
                    (Some(counts), false) if counts.len() == counted.counters.len() => {
                        counts.iter().copied().map(Ok).collect()
                    }
                    (None, true) => vec![Err(CounterUnavailable); counted.counters.len()],
                    _ => {
                        return Err(
                            "give one count per counter, or counter_error, but not both".into()
                        );
                    }
                };
            let decision = eval::decide(policy, &counted, &counts);
            compare("decision", &json!(decision), &case.expected.decision)
        }
    }
}

fn compare(what: &str, found: &Value, expected: &Value) -> Result<(), String> {
    (found == expected)
        .then_some(())
        .ok_or_else(|| format!("{what}:\n  expected {expected}\n  found    {found}"))
}

fn vector_files() -> Vec<PathBuf> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/vectors");
    let mut paths: Vec<_> = std::fs::read_dir(&dir)
        .unwrap()
        .map(|entry| entry.unwrap().path())
        .filter(|path| path.extension().is_some_and(|ext| ext == "json"))
        .collect();
    paths.sort();
    paths
}

#[test]
fn every_vector_passes() {
    let paths = vector_files();
    let mut failures = Vec::new();
    let mut cases = 0;
    for path in &paths {
        let text = std::fs::read_to_string(path).unwrap();
        let file: File = serde_json::from_str(&text)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
        for case in &file.cases {
            cases += 1;
            if let Err(error) = run(&file, case) {
                let name = path.file_name().unwrap().to_string_lossy();
                failures.push(format!("{name}: {}: {error}", case.name));
            }
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
    assert!(cases >= 25, "only {cases} cases");
}

/// Every vector's policy is one the gateway's own validation accepts, so the vendored vectors
/// also exercise `validate`.
#[test]
fn every_vector_policy_validates() {
    for path in vector_files() {
        let text = std::fs::read_to_string(&path).unwrap();
        let value: Value = serde_json::from_str(&text).unwrap();
        if value["policy"].is_null() {
            continue;
        }
        let project = value["policy"]["project_id"]
            .as_str()
            .unwrap()
            .parse()
            .unwrap();
        let body = serde_json::to_vec(&value["policy"]).unwrap();
        radius_gateway::policy::validate(&body, project)
            .unwrap_or_else(|error| panic!("{}: {error}", path.display()));
    }
}

#[test]
fn decisions_read_back_as_written() {
    for path in vector_files() {
        let file: File = serde_json::from_str(&std::fs::read_to_string(&path).unwrap()).unwrap();
        for case in &file.cases {
            let expected = &case.expected.decision;
            let decision: Decision = serde_json::from_value(expected.clone())
                .unwrap_or_else(|error| panic!("{}: {error}", case.name));
            assert_eq!(&json!(decision), expected, "{}", case.name);
        }
    }
}
