use super::*;

fn level(row: &Value, clean: &BTreeMap<String, f64>) -> u8 {
    if row["state"] != "OK"
        || (row["url"]
            .as_str()
            .is_some_and(|url| url.starts_with("https://"))
            && row["certificate_validated"] != true)
    {
        return 0;
    }
    if row["group"] == "Clean" {
        let key = if row["url"]
            .as_str()
            .is_some_and(|url| url.starts_with("http://"))
        {
            "tcp_ms"
        } else {
            "tls_ms"
        };
        if clean
            .get(row["name"].as_str().unwrap_or(""))
            .is_some_and(|ms| {
                row["code"].as_str().is_some_and(|s| !s.starts_with('2'))
                    || row[key]
                        .as_f64()
                        .is_none_or(|current| current <= 0. || current > ms + 500.)
            })
        {
            return 0;
        }
    }
    if crate::selection_latency::stable(row) {
        2
    } else {
        1
    }
}

fn corresponding<'a>(rows: &'a [Value], target: &Value) -> Option<&'a Value> {
    rows.iter().find(|r| {
        r["group"] == target["group"] && r["name"] == target["name"] && r["url"] == target["url"]
    })
}

pub(super) fn improvements(
    before: &[Value],
    after: &[Value],
    clean: &BTreeMap<String, f64>,
    panel: Panel,
) -> BTreeSet<String> {
    after
        .iter()
        .filter(|r| {
            panel == Panel::All || crate::selection_latency::service(r) || r["group"] == "Clean"
        })
        .filter(|r| corresponding(before, r).is_some_and(|b| level(r, clean) > level(b, clean)))
        .filter_map(|r| {
            Some(format!(
                "{}|{}|{}",
                r["group"].as_str()?,
                r["name"].as_str()?,
                r["url"].as_str()?
            ))
        })
        .collect()
}

pub(super) fn verify(
    tested: &BTreeSet<String>,
    forward: &BTreeSet<String>,
    targets: &[Target],
    clean: &BTreeMap<String, f64>,
    panel: Panel,
    mut measure: impl FnMut(&[Target], bool) -> Result<Vec<Value>>,
) -> Result<Value> {
    let selected: Vec<_> = targets
        .iter()
        .filter(|t| tested.contains(&t.key()))
        .cloned()
        .collect();
    let labels = |keys: &BTreeSet<String>| {
        selected
            .iter()
            .filter(|t| keys.contains(&t.key()))
            .map(|t| format!("{}/{}", t.group, t.name))
            .collect::<Vec<_>>()
    };
    let mut confirmed = BTreeSet::new();
    // The full working runs were primary then candidate. Reverse only the disputed probes.
    if !selected.is_empty() && !tested.is_disjoint(forward) {
        let disputed: Vec<_> = selected
            .iter()
            .filter(|t| forward.contains(&t.key()))
            .cloned()
            .collect();
        let challenger = measure(&disputed, false)?;
        let incumbent = measure(&disputed, true)?;
        let repeated = improvements(&incumbent, &challenger, clean, panel);
        confirmed = tested
            .intersection(forward)
            .filter(|k| repeated.contains(*k))
            .cloned()
            .collect();
    }
    Ok(json!({"screening":labels(tested),"working":labels(forward),"confirmed":labels(&confirmed)}))
}

pub(super) fn reason(
    checks: &BTreeMap<String, Value>,
    best: &str,
    primary: &str,
    names: &BTreeMap<String, String>,
) -> Option<String> {
    let display = |id: &str| names.get(id).cloned().unwrap_or_else(|| id.to_owned());
    if best != primary {
        let restored = checks.get(best)?["confirmed"].as_array()?;
        if let Some(target) = restored.first().and_then(Value::as_str) {
            return Some(format!(
                "{} стабильно лучше на {target}. Подтверждено в обоих порядках.",
                display(best)
            ));
        }
    } else if let Some((id, check)) = checks.iter().find(|(_, c)| {
        c["confirmed"].as_array().is_some_and(Vec::is_empty)
            && c["screening"].as_array().is_some_and(|a| !a.is_empty())
    }) {
        let target = check["screening"]
            .as_array()
            .and_then(|v| v.first())
            .and_then(Value::as_str);
        let service = target.map_or(String::new(), |t| format!(" на {t}"));
        return Some(format!(
            "Преимущество {}{service} перед {} не подтвердилось.",
            display(id),
            display(primary)
        ));
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn one_retry_does_not_replace_working_primary_and_only_matching_repairs_count() {
        let target: Target = serde_json::from_value(
            json!({"group":"YouTube","name":"web","url":"https://yt.test/"}),
        )
        .unwrap();
        let good = json!({"group":target.group,"name":target.name,"url":target.url,"state":"OK","certificate_validated":true,"tries":1});
        let mut flaky = good.clone();
        flaky["tries"] = json!(2);
        flaky["flaky"] = json!(true);
        let clean = BTreeMap::new();
        let gains = improvements(&[flaky.clone()], &[good.clone()], &clean, Panel::Services);
        let targets = [target];
        let tied = verify(
            &gains,
            &BTreeSet::new(),
            &targets,
            &clean,
            Panel::Services,
            |_, _| panic!("first working pair already tied"),
        )
        .unwrap();
        assert_eq!(tied["confirmed"], json!([]));
        for (primary, expected) in [(good.clone(), json!([])), (flaky, json!(["YouTube/web"]))] {
            let mut order = Vec::new();
            let proof = verify(
                &gains,
                &gains,
                &targets,
                &clean,
                Panel::Services,
                |jobs, old| {
                    assert_eq!(jobs.len(), 1);
                    order.push(old);
                    Ok(vec![if old { primary.clone() } else { good.clone() }])
                },
            )
            .unwrap();
            assert_eq!(order, [false, true]);
            assert_eq!(proof["confirmed"], expected);
        }
    }
}
