//! Disabled conntrack shortcut through the real no-driver Windows CLI.
use super::engine_case;
use anyhow::{Result, ensure};
use std::path::Path;
pub(super) fn check(bin: &Path, logs: &Path) -> Result<usize> {
    for (name, flag, disabled) in [
        ("default", None, false),
        ("enabled", Some("--ctrack-disable=0"), false),
        ("disabled", Some("--ctrack-disable=1"), true),
        ("implicit", Some("--ctrack-disable"), true),
    ] {
        let script = format!(
            "local function two(...) assert(select('#',...)==2);local a,b=...;assert(a==nil and b==nil) end;local disabled={disabled};local trap=setmetatable({{}},{{__index=function()error('disabled conntrack performed lookup')end}});if disabled then two(conntrack_feed(42,trap));two(conntrack_feed(trap,trap));two(conntrack_feed('short',false)) else local ok,e=pcall(conntrack_feed,42,false);assert(not ok and e:find('invalid packet data type',1,true));ok,e=pcall(conntrack_feed,{{}},false);assert(not ok and e:find('table expected',1,true));two(conntrack_feed('short',false)) end;local ok,e=pcall(conntrack_feed);assert(not ok and e:find('expect from',1,true));print('ok packet dispatch {name} shortcut and arity');os.exit(0)"
        );
        let mut args = vec!["--intercept=0".into(), "--wf-dup-check=0".into()];
        if let Some(flag) = flag {
            args.push(flag.into());
        }
        args.push(format!("--lua-init={script}").into());
        let text = engine_case(bin, &args, 0, &[])?;
        ensure!(
            text.contains(&format!("ok packet dispatch {name} shortcut and arity")),
            "Real disabled tracking fixture did not finish: {name}"
        );
        zapret_core::atomic_write(
            &logs.join(format!("lua-packet-dispatch-{name}.log")),
            text.as_bytes(),
        )?;
    }
    Ok(4)
}
