use serde::{Deserialize, Serialize};

pub struct ReferenceDownload {
    pub url: &'static str,
    pub bytes: usize,
    pub sha256: &'static str,
}

pub const NBA_CDN_HOST: &str = "nba-cdn3.2ksports.com";
pub const EPIC_API_HOST: &str = "api.epicgames.dev";
pub const EPIC_JWKS_URL: &str = "https://api.epicgames.dev/epic/oauth/v2/.well-known/jwks.json";
pub const JWKS_MAX_BYTES: usize = 65536;
pub const NBA_STORE_IMAGE: ReferenceDownload = ReferenceDownload {
    url: "https://nba-cdn3.2ksports.com/2k27/store/image/35/swags_hoodies_512x512_8_17.jHvTERq0BSA_g4D-lgVoiA",
    bytes: 91315,
    sha256: "2c073e9176cd934933b5914534017ffe89607b91a4966fea392291026b0eb7f5",
};
pub const DISCORD_MEDIA_FILE: ReferenceDownload = ReferenceDownload {
    url: "https://media.discordapp.net/stickers/781291442961383434.png",
    bytes: 229034,
    sha256: "8dbecf7b6d7da8a9c761ad89a73066838d89f3cda4a1313976c9533ac88a3fb3",
};

impl ReferenceDownload {
    pub fn for_url(url: &str) -> Option<&'static Self> {
        [&NBA_STORE_IMAGE, &DISCORD_MEDIA_FILE]
            .into_iter()
            .find(|file| file.url == url)
    }

    pub fn matches(&self, status: Option<u64>, bytes: Option<u64>, digest: Option<&str>) -> bool {
        status == Some(200) && bytes == Some(self.bytes as u64) && digest == Some(self.sha256)
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub enum ProbeState {
    Ok,
    Fail,
    Freeze,
    Na,
}
pub fn transfer_state(
    code: &str,
    exit: Option<i32>,
    up: f64,
    down: f64,
    post: bool,
    target_reached: bool,
) -> ProbeState {
    let Some(exit) = exit else {
        return ProbeState::Fail;
    };
    if exit == 6 {
        return ProbeState::Na;
    }
    let valid_code = code.len() == 3
        && code.as_bytes()[0].is_ascii_digit()
        && code.as_bytes()[0] != b'0'
        && code.bytes().all(|b| b.is_ascii_digit());
    if valid_code && (exit == 0 || (target_reached && [0, 23, 28].contains(&exit))) {
        return ProbeState::Ok;
    }
    if exit == 28 && (down > 0. || (post && up > 0.)) {
        return ProbeState::Freeze;
    }
    ProbeState::Fail
}
