use clap::{Args, Parser, Subcommand};
use std::path::PathBuf;

#[derive(Parser)]
#[command(name = "zapret-rust", version = crate::VERSION, about = "Нативное управление zapret-rust")]
pub struct Cli {
    #[arg(long, global = true)]
    pub root: Option<PathBuf>,
    #[arg(long, global = true)]
    pub json: bool,
    #[arg(long, global = true)]
    pub yes: bool,
    #[command(subcommand)]
    pub action: Option<Action>,
}

#[derive(Subcommand)]
pub enum Action {
    Menu,
    /// Подготовить списки и проверить совместимость этой установки.
    FirstRun,
    /// Safe presentation-only preview; does not read or change machine state.
    #[command(hide = true)]
    MenuPreview {
        #[arg(long, default_value = "main", value_parser = ["main", "settings", "tools", "test", "notifications"])]
        screen: String,
        #[arg(long)]
        width: Option<usize>,
        #[arg(long)]
        height: Option<usize>,
        #[arg(long)]
        wait: bool,
        /// Export the actual styled frame to PNG without initializing the package.
        #[arg(long, conflicts_with = "wait")]
        png: Option<PathBuf>,
    },
    Status,
    Start,
    Stop,
    Restart,
    Strategies,
    Settings {
        key: Option<String>,
        value: Option<String>,
    },
    Compose {
        #[arg(long)]
        alt: Option<String>,
        #[arg(long)]
        no_auto: bool,
        #[arg(long)]
        ipset: Option<String>,
        #[arg(long)]
        dry_run: bool,
        #[arg(long)]
        validate: bool,
        #[arg(long)]
        debug_file: Option<PathBuf>,
    },
    Integrity,
    Probe {
        #[arg(long, default_value_t = 16)]
        parallel: usize,
        #[arg(long, default_value_t = 30000)]
        deadline_ms: u64,
        #[arg(long)]
        ca_file: Option<PathBuf>,
        #[arg(long)]
        post_file: Option<PathBuf>,
    },
    Test(TestArgs),
    /// Лаборатория вариантов из файлов .queue.
    Lab(LabArgs),
    ComparisonReport {
        #[arg(conflicts_with = "plan_file", required_unless_present = "plan_file")]
        file: Option<PathBuf>,
        #[arg(long, requires = "journal_file")]
        plan_file: Option<PathBuf>,
        #[arg(long, requires = "plan_file")]
        journal_file: Option<PathBuf>,
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Autotune {
        #[arg(long)]
        force: bool,
    },
    ConnectionCheck(NetworkArgs),
    Webcheck(NetworkArgs),
    /// Play a public YouTube video and measure presented frames.
    YoutubeCheck,
    Voicecheck(NetworkArgs),
    Latency(NetworkArgs),
    /// Полный подбор в режиме отчёта с сохранением основной стратегии.
    ProviderCheck(NetworkArgs),
    /// Только провайдер и IP, без запуска тестовых стратегий.
    ProviderInfo(NetworkArgs),
    Track {
        #[arg(long, default_value = "NBA2K*")]
        process: String,
        #[arg(long, default_value_t = 60)]
        seconds: u64,
    },
    Scan {
        #[arg(long, default_value = "")]
        process: String,
        #[arg(long, default_value_t = 60)]
        seconds: u64,
        #[arg(long)]
        apply: bool,
    },
    Exclude {
        #[arg(long)]
        apply: bool,
    },
    Report {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Lists {
        #[arg(long)]
        update: bool,
    },
    Update {
        #[arg(long)]
        install: bool,
        #[arg(long)]
        from: Option<PathBuf>,
        #[arg(long)]
        sha256: Option<String>,
        #[arg(long)]
        recover: bool,
    },
    Package {
        #[arg(long)]
        output: PathBuf,
        /// Keep the legacy engine manifests for controllers that require Cygwin.
        #[arg(long)]
        compatibility: bool,
    },
    Service {
        #[arg(default_value = "status")]
        action: String,
    },
    Task {
        #[arg(default_value = "status")]
        action: String,
        #[arg(default_value = "autotune")]
        kind: String,
    },
    Telegram {
        #[arg(default_value = "status")]
        action: String,
        #[arg(long)]
        port: Option<u16>,
    },
    /// Owned Rust Telegram transport worker; started by the supervisor.
    #[command(hide = true)]
    TelegramCore {
        #[arg(long)]
        config: PathBuf,
        #[arg(long)]
        config_sha256: String,
    },
    Hosts {
        #[arg(default_value = "status")]
        action: String,
        #[arg(long)]
        args: Option<String>,
    },
    System {
        action: String,
        #[arg(long)]
        args: Option<String>,
    },
    DirectRules {
        #[arg(long)]
        output: Option<PathBuf>,
    },
    Diag {
        #[arg(long)]
        run: bool,
        #[arg(long, default_value_t = 60)]
        seconds: u64,
    },
    Notify {
        #[arg(long)]
        watch: bool,
    },
    Watch,
    Uninstall,
    #[command(hide = true)]
    PlatformWorker {
        action: String,
        #[arg(long)]
        arguments_json: String,
    },
}

#[derive(Args)]
pub struct LabArgs {
    #[arg(long)]
    pub dir: PathBuf,
    #[arg(long)]
    pub extra_blobs: Option<PathBuf>,
    #[arg(long, default_value_t = 40)]
    pub max_minutes: u64,
    #[arg(long, default_value_t = 10)]
    pub idle_minutes: u64,
    #[arg(long, default_value_t = 5)]
    pub timeout_sec: u64,
    #[arg(long, default_value_t = 16)]
    pub parallel: usize,
    #[arg(long)]
    pub plan_only: bool,
}

#[derive(Args, Clone)]
pub struct NetworkArgs {
    pub urls: Vec<String>,
    #[arg(long, default_value_t = 5000)]
    pub timeout_ms: u64,
    #[arg(long)]
    pub args: Option<String>,
}

#[derive(Args, Clone, Debug)]
pub struct TestArgs {
    /// Показать сохранённый результат без запуска проверки.
    #[arg(long, conflicts_with_all = ["full", "report_only", "keep_primary", "plan_only", "webcheck", "compare_a", "compare_b", "seed"])]
    pub last: bool,
    /// Сохранить лучший подтверждённый вариант без дополнительного вопроса.
    #[arg(long, conflicts_with_all = ["last", "report_only", "keep_primary"])]
    pub apply: bool,
    /// Выводить подробности каждого прохода и повторов.
    #[arg(long)]
    pub details: bool,
    #[arg(long)]
    pub full: bool,
    #[arg(long)]
    pub report_only: bool,
    #[arg(long)]
    pub keep_primary: bool,
    #[arg(long)]
    pub plan_only: bool,
    #[arg(long)]
    pub webcheck: bool,
    #[arg(long, default_value_t = 1)]
    pub rounds: usize,
    /// Одновременные запросы. По умолчанию 32 в полном подборе и 16 в остальных режимах.
    #[arg(long)]
    pub parallel: Option<usize>,
    #[arg(long, default_value_t = 5000)]
    pub timeout_ms: u64,
    #[arg(long)]
    pub seed: Option<u64>,
    #[arg(long)]
    pub compare_a: Option<String>,
    #[arg(long)]
    pub compare_b: Option<String>,
    #[arg(long, default_value_t = 4)]
    pub compare_blocks: usize,
}

impl TestArgs {
    pub(crate) const QUICK_PARALLEL: usize = 16;
    pub(crate) const QUICK_RETRY_PARALLEL: usize = 4;
    const FULL_PARALLEL: usize = 32;

    pub fn parallel(&self) -> usize {
        self.parallel.unwrap_or(if self.is_full_selection() {
            Self::FULL_PARALLEL
        } else {
            Self::QUICK_PARALLEL
        })
    }

    pub fn retry_parallel(&self) -> usize {
        let parallel = self.parallel();
        let limit = if self.is_full_selection() && parallel >= Self::FULL_PARALLEL {
            8
        } else {
            Self::QUICK_RETRY_PARALLEL
        };
        parallel.min(limit)
    }

    fn is_full_selection(&self) -> bool {
        self.full && self.compare_a.is_none() && self.compare_b.is_none()
    }
}

impl Default for TestArgs {
    fn default() -> Self {
        Self {
            last: false,
            apply: false,
            details: false,
            full: false,
            report_only: false,
            keep_primary: false,
            plan_only: false,
            webcheck: false,
            rounds: 1,
            parallel: None,
            timeout_ms: 5000,
            seed: None,
            compare_a: None,
            compare_b: None,
            compare_blocks: 4,
        }
    }
}
