use flate2::read::GzDecoder;
use serde::Deserialize;
use serde_json::Value;

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ReplayEvidence {
    cases: Vec<ReplayCase>,
}

#[derive(Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ReplayCase {
    name: String,
    plan: Value,
    rows: Vec<Value>,
    expected: Value,
}

fn equal(actual: &Value, expected: &Value, path: &str) {
    match (actual, expected) {
        (Value::Number(a), Value::Number(b)) => {
            let (a, b) = (a.as_f64().unwrap(), b.as_f64().unwrap());
            assert!(
                (a - b).abs() <= 1e-12 * a.abs().max(b.abs()).max(1.),
                "{path}: {a} != {b}"
            );
        }
        (Value::Array(a), Value::Array(b)) => {
            assert_eq!(a.len(), b.len(), "{path}");
            for (i, (a, b)) in a.iter().zip(b).enumerate() {
                equal(a, b, &format!("{path}[{i}]"));
            }
        }
        (Value::Object(a), Value::Object(b)) => {
            assert_eq!(a.len(), b.len(), "{path}: field counts");
            for (key, b) in b {
                equal(
                    a.get(key)
                        .unwrap_or_else(|| panic!("{path}: missing {key}")),
                    b,
                    &format!("{path}.{key}"),
                );
            }
        }
        _ => assert_eq!(actual, expected, "{path}"),
    }
}

#[test]
fn historical_v1_v2_replay_matches_frozen_legacy_assessments() {
    let fixture: ReplayEvidence = serde_json::from_reader(GzDecoder::new(
        include_bytes!("fixtures/legacy-evidence.json.gz").as_slice(),
    ))
    .unwrap();
    assert!(!fixture.cases.is_empty());
    for case in fixture.cases {
        let actual = zapret_core::legacy_comparison::assess(&case.plan, &case.rows);
        equal(&actual, &case.expected, &case.name);
    }
}
