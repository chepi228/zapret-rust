use super::Cdp;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::time::Instant;

const POLL_GROUP: &str = "playback-snapshot";
const START_GROUP: &str = "playback-start";

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Document {
    pub node_id: i64,
    pub backend_node_id: i64,
    #[serde(rename = "documentURL")]
    pub url: String,
}

#[derive(Default)]
pub(super) struct Player {
    pub status: Option<String>,
    pub video_id: Option<String>,
    pub classes: String,
    pub object: Option<String>,
}

impl Player {
    pub(super) fn issue(&self) -> Option<&'static str> {
        match self.status.as_deref() {
            Some("LOGIN_REQUIRED" | "AGE_CHECK_REQUIRED") => Some("InteractionRequired"),
            Some("UNPLAYABLE" | "ERROR") => Some("PlayerUnavailable"),
            _ if self.has_class("ytp-error") => Some("PlayerUnavailable"),
            _ => None,
        }
    }

    fn has_class(&self, class: &str) -> bool {
        self.classes.split_ascii_whitespace().any(|c| c == class)
    }

    pub(super) fn shows(&self, id: &str) -> bool {
        self.video_id.as_deref() == Some(id)
            && !self.has_class("ad-showing")
            && !self.has_class("ad-interrupting")
    }
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
pub(super) struct Media {
    pub current_src: String,
    pub current_time: f64,
    pub playback_rate: f64,
    pub video_width: u32,
    pub paused: bool,
    pub ended: bool,
    pub seeking: bool,
    pub error: Option<Value>,
}

#[derive(Deserialize)]
#[serde(rename_all = "camelCase")]
struct Quality {
    total_video_frames: u64,
    dropped_video_frames: u64,
}

pub(super) enum PlayStatus {
    Pending,
    Settled,
    Blocked,
}

pub(super) struct Reader<'a> {
    cdp: &'a mut Cdp,
    frame: &'a str,
    deadline: Instant,
    media_world: Option<i64>,
}

impl<'a> Reader<'a> {
    pub(super) fn new(cdp: &'a mut Cdp, frame: &'a str, deadline: Instant) -> Self {
        Self {
            cdp,
            frame,
            deadline,
            media_world: None,
        }
    }

    pub(super) fn forget_world(&mut self) {
        self.media_world = None;
    }

    async fn rpc(&mut self, method: &str, params: Value) -> Result<Value> {
        // Background network traffic must not fill the navigation event queue during playback.
        self.cdp.rpc(method, params, self.deadline, false).await
    }

    async fn runtime(&mut self, method: &str, params: Value) -> Result<Value> {
        let mut reply = self.rpc(method, params).await?;
        ensure!(
            reply.get("exceptionDetails").is_none(),
            "browser playback API raised an exception in {method}"
        );
        Ok(reply["result"].take())
    }

    pub(super) async fn document(&mut self) -> Result<Document> {
        let mut doc = self.rpc("DOM.getDocument", json!({"depth":0})).await?;
        Ok(serde_json::from_value(doc["root"].take())?)
    }

    async fn query(&mut self, document: i64, selector: &str) -> Result<Option<i64>> {
        let found = self
            .rpc(
                "DOM.querySelector",
                json!({"nodeId":document,"selector":selector}),
            )
            .await?;
        let node = found["nodeId"].as_i64().context("missing DOM node ID")?;
        Ok((node != 0).then_some(node))
    }

    async fn resolve(&mut self, node: i64, world: Option<i64>) -> Result<String> {
        let mut args = json!({"nodeId":node,"objectGroup":POLL_GROUP});
        if let Some(context) = world {
            args["executionContextId"] = context.into();
        }
        let resolved = self.rpc("DOM.resolveNode", args).await?;
        Ok(resolved["object"]["objectId"]
            .as_str()
            .context("missing DOM handle")?
            .to_owned())
    }

    async fn property(&mut self, object: &str, name: &str) -> Result<Value> {
        self.call(
            object,
            "Reflect.get",
            json!([{"objectId":object},{"value":name}]),
            POLL_GROUP,
        )
        .await
    }

    async fn optional_method(&mut self, object: &str, name: &str, group: &str) -> Result<Value> {
        let method = self.property(object, name).await?;
        if method["type"] != "function" {
            return Ok(Value::Null);
        }
        let handle = method["objectId"]
            .as_str()
            .context("missing browser method")?;
        self.call(
            handle,
            "Function.prototype.call",
            json!([{"objectId":object}]),
            group,
        )
        .await
    }

    pub(super) async fn youtube_player(&mut self, document: i64) -> Result<Player> {
        // Page-specific metadata lives in the site's world. Frame counters are read in the media world.
        let response = self
            .runtime(
                "Runtime.evaluate",
                json!({
                    "expression":"globalThis.ytInitialPlayerResponse", "objectGroup":POLL_GROUP
                }),
            )
            .await?;
        let mut player = Player::default();
        if let Some(object) = response["objectId"].as_str() {
            let info: Value = self
                .fields(object, &["playabilityStatus", "status"])
                .await?;
            player.status = info["playabilityStatus"]["status"]
                .as_str()
                .map(str::to_owned);
        }
        if player.issue().is_none()
            && let Some(node) = self.query(document, "#movie_player").await?
        {
            let object = self.resolve(node, None).await?;
            let class = self.property(&object, "className").await?;
            player.classes = class["value"].as_str().unwrap_or_default().to_owned();
            if player.issue().is_none() {
                let data = self
                    .optional_method(&object, "getVideoData", POLL_GROUP)
                    .await?;
                if let Some(info) = data["objectId"].as_str() {
                    let id = self.property(info, "video_id").await?;
                    player.video_id = id["value"].as_str().map(str::to_owned);
                }
            }
            player.object = Some(object);
        }
        Ok(player)
    }

    pub(super) async fn video(
        &mut self,
        document: i64,
        selector: &str,
    ) -> Result<Option<(i64, String)>> {
        let Some(node) = self.query(document, selector).await? else {
            return Ok(None);
        };
        let description = self
            .rpc("DOM.describeNode", json!({"nodeId":node,"depth":0}))
            .await?;
        let backend = description["node"]["backendNodeId"]
            .as_i64()
            .context("missing video identity")?;
        // Read the browser's media APIs in their own world, independent of page-defined properties.
        if self.media_world.is_none() {
            let world = self
                .rpc(
                    "Page.createIsolatedWorld",
                    json!({"frameId":self.frame, "worldName":"zapret-playback"}),
                )
                .await?;
            self.media_world = Some(
                world["executionContextId"]
                    .as_i64()
                    .context("missing media context")?,
            );
        }
        Ok(Some((backend, self.resolve(node, self.media_world).await?)))
    }

    async fn call(
        &mut self,
        object: &str,
        function: &str,
        arguments: Value,
        group: &str,
    ) -> Result<Value> {
        self.runtime(
            "Runtime.callFunctionOn",
            json!({"objectId":object,"functionDeclaration":function,
            "arguments":arguments,"objectGroup":group,"userGesture":group == START_GROUP}),
        )
        .await
    }

    async fn fields<T: DeserializeOwned>(&mut self, object: &str, names: &[&str]) -> Result<T> {
        // The native serializer's property list reads just these Web API fields, including inherited getters.
        let result = self
            .call(
                object,
                "JSON.stringify",
                json!([{"objectId":object},{"value":names}]),
                POLL_GROUP,
            )
            .await?;
        Ok(serde_json::from_str(
            result["value"]
                .as_str()
                .context("missing browser properties")?,
        )?)
    }

    pub(super) async fn media(&mut self, video: &str) -> Result<Media> {
        self.fields(
            video,
            &[
                "currentSrc",
                "currentTime",
                "playbackRate",
                "videoWidth",
                "paused",
                "ended",
                "seeking",
                "error",
            ],
        )
        .await
    }

    pub(super) async fn presented_frames(&mut self, video: &str) -> Result<Option<u64>> {
        let quality = self
            .optional_method(video, "getVideoPlaybackQuality", POLL_GROUP)
            .await?;
        let Some(object) = quality["objectId"].as_str() else {
            return Ok(None);
        };
        let quality: Quality = self
            .fields(object, &["totalVideoFrames", "droppedVideoFrames"])
            .await?;
        Ok(quality
            .total_video_frames
            .checked_sub(quality.dropped_video_frames))
    }

    pub(super) async fn start(
        &mut self,
        video: &str,
        player: Option<&str>,
    ) -> Result<Option<String>> {
        self.release_start().await?;
        self.call(
            video,
            "Reflect.set",
            json!([{"objectId":video},{"value":"muted"},{"value":true}]),
            START_GROUP,
        )
        .await?;
        if let Some(player) = player {
            self.optional_method(player, "playVideo", START_GROUP)
                .await?;
        }
        let play = self
            .call(
                video,
                "HTMLMediaElement.prototype.play",
                json!([]),
                START_GROUP,
            )
            .await?;
        Ok(play["objectId"].as_str().map(str::to_owned))
    }

    pub(super) async fn play_status(&mut self, promise: &str) -> Result<PlayStatus> {
        // Waiting on play() itself could consume the whole visit when a stream never starts.
        let reply = self
            .rpc(
                "Runtime.getProperties",
                json!({"objectId":promise,"ownProperties":true}),
            )
            .await?;
        let internals = reply["internalProperties"]
            .as_array()
            .context("missing play promise")?;
        let property = |name: &str| {
            internals
                .iter()
                .find(|p| p["name"] == name)
                .map(|p| &p["value"])
        };
        match property("[[PromiseState]]").and_then(|s| s["value"].as_str()) {
            Some("pending") => Ok(PlayStatus::Pending),
            Some("fulfilled") => Ok(PlayStatus::Settled),
            Some("rejected") => {
                if let Some(error) =
                    property("[[PromiseResult]]").and_then(|r| r["objectId"].as_str())
                {
                    let details: Value = self.fields(error, &["name"]).await?;
                    if details["name"] == "NotAllowedError" {
                        return Ok(PlayStatus::Blocked);
                    }
                }
                Ok(PlayStatus::Settled)
            }
            _ => bail!("invalid browser play promise state"),
        }
    }

    pub(super) async fn release_poll(&mut self) -> Result<()> {
        self.rpc(
            "Runtime.releaseObjectGroup",
            json!({"objectGroup":POLL_GROUP}),
        )
        .await?;
        Ok(())
    }

    pub(super) async fn release_start(&mut self) -> Result<()> {
        self.rpc(
            "Runtime.releaseObjectGroup",
            json!({"objectGroup":START_GROUP}),
        )
        .await?;
        Ok(())
    }
}
