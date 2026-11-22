use crate::{diagnostic as d, http};
use anyhow::{Context, Result, bail};
use serde_json::{Value, json};
use std::{net::IpAddr, path::Path};
use tokio::task::JoinSet;

fn string(value: &Value) -> String {
    value
        .as_str()
        .unwrap_or("")
        .chars()
        .filter(|c| !c.is_control())
        .take(1024)
        .collect()
}
fn masked(address: IpAddr) -> String {
    match address {
        IpAddr::V4(ip) => {
            let b = ip.octets();
            format!("{}.{}.{}.x", b[0], b[1], b[2])
        }
        IpAddr::V6(ip) => {
            let b = ip.segments();
            format!("{:x}:{:x}:{:x}:...", b[0], b[1], b[2])
        }
    }
}
fn parse(value: &Value, primary: bool) -> Result<Value> {
    if primary && value["success"] != true {
        bail!("provider endpoint did not return success")
    }
    let address: IpAddr = value["ip"]
        .as_str()
        .context("provider response has no IP address")?
        .parse()
        .context("provider response contains invalid IP address")?;
    let code = string(&value[if primary { "country_code" } else { "country" }]);
    if code.len() != 2 || !code.chars().all(|c| c.is_ascii_alphabetic()) {
        bail!("provider response has no country code")
    }
    let org = if primary {
        string(&value["connection"]["org"])
    } else {
        string(&value["org"])
    };
    let isp = if primary {
        string(&value["connection"]["isp"])
    } else {
        org.split_once(' ')
            .filter(|(a, _)| a.starts_with("AS") && a[2..].chars().all(|c| c.is_ascii_digit()))
            .map_or(org.clone(), |(_, name)| name.into())
    };
    let asn = if primary {
        let n = &value["connection"]["asn"];
        format!(
            "AS{} {}",
            n.as_str()
                .map(str::to_owned)
                .unwrap_or_else(|| if n.is_number() {
                    n.to_string()
                } else {
                    String::new()
                }),
            org
        )
        .trim()
        .to_owned()
    } else {
        org.clone()
    };
    let loc = string(&value["loc"]);
    let coords: Vec<_> = loc.split(',').collect();
    let lat = if primary {
        value["latitude"].as_f64()
    } else {
        coords.first().and_then(|n| n.parse::<f64>().ok())
    }
    .filter(|n| n.is_finite() && (-90.0..=90.).contains(n));
    let lon = if primary {
        value["longitude"].as_f64()
    } else {
        coords.get(1).and_then(|n| n.parse::<f64>().ok())
    }
    .filter(|n| n.is_finite() && (-180.0..=180.).contains(n));
    Ok(
        json!({"ip":address,"masked_ip":masked(address),"country_code":code.to_ascii_uppercase(),"country":if primary{string(&value["country"])}else{code.clone()},"city":string(&value["city"]),"isp":isp,"org":org,"as":asn,"lat":lat,"lon":lon,"is_russia":code.eq_ignore_ascii_case("RU")}),
    )
}
pub(crate) fn run(root: &Path, args: &Value) -> Result<Value> {
    let timeout_ms = d::duration_ms(args, 8000, 30000)?;
    let ca = d::ca_file(args)?;
    let mut ips = if let Some(values) = args["ips"].as_array().filter(|a| !a.is_empty()) {
        values
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_owned)
                    .context("provider ips must be strings")
            })
            .collect::<Result<Vec<_>>>()?
    } else {
        vec![args["ip"].as_str().unwrap_or("").into()]
    };
    ips.sort();
    ips.dedup();
    if ips.len() > 32 {
        bail!("at most 32 provider IP addresses")
    }
    for ip in &ips {
        if !ip.is_empty() {
            ip.parse::<IpAddr>()
                .context("invalid provider IP address")?;
        }
    }
    let primary = args["primary_url"].as_str().map(str::to_owned);
    let fallback = args["fallback_url"].as_str().map(str::to_owned);
    for url in primary.iter().chain(fallback.iter()) {
        http::checked_url(url, false)?;
    }
    let rows = crate::runtime(async {
        let mut pending = JoinSet::new();
        for ip in ips {
            let primary = primary.clone();
            let fallback = fallback.clone();
            let ca = ca.clone();
            pending.spawn(async move{
            let urls=[primary.unwrap_or_else(||format!("https://ipwho.is/{ip}?lang=ru")),fallback.unwrap_or_else(||format!("https://ipinfo.io/{}json",if ip.is_empty(){String::new()}else{format!("{ip}/")}))];
            let mut observations=Vec::new();let mut provider=None;
            for (index,url) in urls.into_iter().enumerate(){
                let started=std::time::Instant::now();let result=async{let bytes=http::fetch_async(&url,65536,timeout_ms,ca.as_deref()).await?;let value=serde_json::from_slice::<Value>(&bytes).context("invalid provider JSON")?;parse(&value,index==0)}.await;
                match result{Ok(value)=>{observations.push(json!({"url":url,"state":"OK","elapsed_ms":started.elapsed().as_secs_f64()*1000.}));provider=Some(value);break},Err(e)=>{observations.push(json!({"url":url,"state":"UNKNOWN","reason":"ProviderUnconfirmed","error":format!("{e:#}"),"elapsed_ms":started.elapsed().as_secs_f64()*1000.}));}}
            }
            json!({"query_ip":ip,"state":if provider.is_some(){"Observed"}else{"Unknown"},"provider":provider,"observations":observations})
        });
        }
        let mut rows = Vec::new();
        while let Some(row) = pending.join_next().await {
            rows.push(row?)
        }
        Ok(rows)
    })?;
    Ok(
        json!({"schema":1,"kind":"Provider","proxy_mode":"Direct","rows":rows,"network_context":d::context(root),"route_claim":"External service observation; OS VPN/TUN/routes still apply"}),
    )
}
