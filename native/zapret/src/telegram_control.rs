use crate::App;
use anyhow::Result;
use serde_json::{Value, json};

impl App {
    pub(crate) fn telegram(&self, action: &str, port: Option<u16>) -> Result<Value> {
        execute(action, port, self.json, |name, arguments| {
            self.platform(name, arguments)
        })
    }
}

fn execute(
    action: &str,
    port: Option<u16>,
    machine_output: bool,
    mut platform: impl FnMut(&str, Value) -> Result<Value>,
) -> Result<Value> {
    let name = if action == "supervise" { "run" } else { action };
    let mut state = platform(&format!("telegram-{name}"), json!({"port":port}))?;
    if action != "start" || machine_output {
        return Ok(state);
    }
    let link = state["active_link"].as_str().filter(|link| {
        !link.is_empty()
            && state["running"] == true
            && state["current"] == true
            && state["requires_restart"] != true
            && state["ownership_error"].is_null()
    });
    let opened = match link {
        Some(link) => platform("telegram-open-link", json!({"link":link})),
        None => anyhow::bail!("Не удалось подтвердить ссылку работающего моста Telegram"),
    };
    match opened {
        Ok(value) if value["opened"] == true => state["link_opened"] = json!(true),
        result => {
            state["link_opened"] = json!(false);
            state["link_open_error"] = json!(match result {
                Err(error) => format!("{error:#}"),
                _ => "Windows не подтвердила открытие ссылки Telegram".into(),
            });
        }
    }
    Ok(state)
}

#[cfg(test)]
mod tests {
    use super::*;
    const LINK: &str =
        "tg://proxy?server=127.0.0.1&port=1443&secret=dd0123456789abcdef0123456789abcdef";

    fn ready() -> Value {
        json!({"running":true,"current":true,"requires_restart":false,"ownership_error":null,
            "active_port":1443,"configured_port":2443,"active_link":LINK,"configured_link":"stale-link"})
    }

    #[test]
    fn explicit_start_opens_the_confirmed_active_link_after_the_bridge_is_ready() {
        let mut calls = Vec::new();
        let state = execute("start", Some(1443), false, |name, args| {
            calls.push(name.to_owned());
            match name {
                "telegram-start" => {
                    assert_eq!(args["port"], 1443);
                    Ok(ready())
                }
                "telegram-open-link" => {
                    assert_eq!(args["link"], LINK);
                    Ok(json!({"opened":true}))
                }
                _ => panic!("Unexpected operation"),
            }
        })
        .unwrap();
        assert_eq!(calls, ["telegram-start", "telegram-open-link"]);
        assert_eq!(state["link_opened"], true);
        assert_eq!(state["running"], true);
    }

    #[test]
    fn machine_and_background_or_observation_commands_do_not_open_telegram() {
        for (action, machine, expected) in [
            ("start", true, "telegram-start"),
            ("supervise", false, "telegram-run"),
            ("status", false, "telegram-status"),
            ("stop", false, "telegram-stop"),
            ("config", false, "telegram-config"),
        ] {
            let mut calls = Vec::new();
            let state = execute(action, None, machine, |name, _| {
                calls.push(name.to_owned());
                Ok(ready())
            })
            .unwrap();
            assert_eq!(calls, [expected]);
            assert!(state.get("link_opened").is_none());
        }
    }

    #[test]
    fn an_open_failure_keeps_the_ready_bridge_and_the_manual_link_available() {
        let state = execute("start", None, false, |name, _| match name {
            "telegram-start" => Ok(ready()),
            "telegram-open-link" => anyhow::bail!("No registered Telegram handler"),
            _ => panic!("Unexpected operation"),
        })
        .unwrap();
        assert_eq!(state["running"], true);
        assert_eq!(state["active_link"], LINK);
        assert_eq!(state["link_opened"], false);
        assert!(
            state["link_open_error"]
                .as_str()
                .unwrap()
                .contains("handler")
        );
    }

    #[test]
    fn a_failed_start_or_unconfirmed_active_link_never_opens_the_client() {
        let mut calls = Vec::new();
        assert!(
            execute("start", None, false, |name, _| {
                calls.push(name.to_owned());
                anyhow::bail!("Bridge did not start")
            })
            .is_err()
        );
        assert_eq!(calls, ["telegram-start"]);
        for (key, value) in [
            ("active_link", Value::Null),
            ("running", json!(false)),
            ("current", json!(false)),
            ("requires_restart", json!(true)),
            ("ownership_error", json!("Unknown owner")),
        ] {
            let mut state = ready();
            state[key] = value;
            let mut calls = Vec::new();
            assert!(
                execute("start", None, false, |name, _| {
                    calls.push(name.to_owned());
                    Ok(state.clone())
                })
                .is_err()
            );
            assert_eq!(calls, ["telegram-start"]);
        }
    }
}
