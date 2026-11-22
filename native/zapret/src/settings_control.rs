use crate::App;
use anyhow::{Result, ensure};
use serde_json::{Value, json};

impl App {
    pub fn toggle_startup(&self) -> Result<Value> {
        let _guard = zapret_platform::ControlGuard::acquire(&self.root, "startup-toggle")?;
        let state = self.platform("service-status", json!({}))?;
        ensure!(
            state["known"] == true && (state["installed"] == false || state["owned"] == true),
            "Принадлежность службы не подтверждена; автозапуск не изменён"
        );
        self.game_check("Изменить автозапуск во время игры")?;
        self.platform(
            "service-autostart",
            json!({"enabled":state["start_type"] != 2,"game_approved":true}),
        )
    }

    pub fn toggle_task(&self, kind: &str) -> Result<Value> {
        let _guard = zapret_platform::ControlGuard::acquire(&self.root, "task-toggle")?;
        let state = self.platform("task-status", json!({"kind":kind}))?;
        ensure!(
            state["known"] == true && (state["exists"] == false || state["owned"] == true),
            "Принадлежность задачи не подтверждена; настройка не изменена"
        );
        let enabled = !(state["exists"] == true && state["enabled"] == true);
        self.game_check("Изменить фоновую задачу во время игры")?;
        self.platform(
            "task-configure",
            json!({"kind":kind,"enabled":enabled,"game_approved":true}),
        )
    }
}
