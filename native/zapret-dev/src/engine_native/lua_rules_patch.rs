//! Keep native VM operations in C and obtain each rule from Rust.
use anyhow::{Context, Result, ensure};
use std::{fs, path::Path};

fn bounds(source: &str, first: &str, last: &str) -> Result<std::ops::Range<usize>> {
    let start = source
        .find(first)
        .with_context(|| format!("Missing Lua anchor {first:?}"))?;
    let end = start
        + source[start..]
            .find(last)
            .with_context(|| format!("Missing Lua boundary {last:?}"))?;
    ensure!(end > start, "Empty Lua selection block");
    Ok(start..end)
}

pub(super) fn apply(nfq: &Path) -> Result<()> {
    let path = nfq.join("desync.c");
    let mut source = fs::read_to_string(&path)?;
    let start = source
        .find("static bool desync_get_result(")
        .context("Lua verdict position")?;
    let end = source[start..]
        .find("#include \"play_prolog_windows.inc\"")
        .context("Lua handler end")?
        + start;
    let mut handler = source[start..end].to_owned();
    let old =
        "lua_Integer lv = lua_tointeger(params.L, -1);\n\t\t\tif (lv & ~VERDICT_MASK_VALID_LUA)";
    ensure!(
        handler.matches(old).count() == 1,
        "Pinned Lua verdict conversion changed"
    );
    handler = handler.replace(
        old,
        "int32_t lv = zapret_lua_verdict(lua_tointeger(params.L, -1));\n\t\t\tif (lv < 0)",
    );
    handler = handler.replace("bool b, b_cutoff_all, b_unwanted_payload;", "bool b;");
    handler = handler.replace(
        "struct packet_range *range;",
        "const struct packet_range *range;",
    );
    let direction = bounds(
        &handler,
        "\tif (ctrack)\n\t{\n\t\t// fast way not to do anything",
        "\tLUA_STACK_GUARD_ENTER(params.L)",
    )?;
    handler.replace_range(direction, concat!(
        "\tzapret_rule_direction direction;\n",
        "\tif (!zapret_lua_rule_direction(ctrack, tpos, bIncoming, params.server, &direction))\n",
        "\t{\n\t\tDLOG(bIncoming ? \"lua in cutoff\\n\" : \"lua out cutoff\\n\");\n\t\treturn verdict;\n\t}\n",
        "\ttpos = direction.positions;\n\tpos = direction.current;\n\trpos = direction.opposite;\n\n",
    ));
    let preflight = bounds(
        &handler,
        "\t\tb_cutoff_all = b_unwanted_payload = true;",
        "\t\t{\n\t\t\t// create arg table",
    )?;
    handler.replace_range(preflight, concat!(
        "\t\tuint32_t gate = lua_rules_preflight(ctx, &direction, l7payload, bIncoming, instance, sizeof(instance));\n",
        "\t\tif (gate == 0)\n\t\t\tDLOG(\"all %s desync functions reached cutoff condition\\n\", sDirection);\n",
        "\t\telse if (gate == 1)\n\t\t\tDLOG(\"all %s desync functions do not want `%s` payload\\n\", sDirection, l7payload_str(l7payload));\n",
        "\t\telse\n",
    ));
    let invocation = bounds(
        &handler,
        "\t\t\tctx->func_n = 1;\n\t\t\tLIST_FOREACH(func, &dp->lua_desync, next)",
        "\n\t\t}\n\n\t\tif ((verdict & VERDICT_MASK)",
    )?;
    let old = &handler[invocation.clone()];
    let first = old
        .find("\t\t\t\tif (!lua_instance_cutoff_check")
        .context("Pinned Lua invoke predicate")?;
    let rest = old[first..]
        .replace(
            "range = bIncoming ? &func->range_in : &func->range_out;",
            "range = step.range;",
        )
        .replace("check_pos_range(pos, range)", "step.in_range")
        .replace(
            "l7_payload_match(l7payload, func->payload_type)",
            "step.accepts_payload",
        )
        .replace("\n\t\t\t\tctx->func_n++;", "");
    handler.replace_range(invocation, &format!(
        concat!(
            "\t\t\tzapret_rule_cursor cursor = lua_rule_cursor(dp, pos, bIncoming, l7payload);\n",
            "\t\t\tzapret_rule_step step;\n",
            "\t\t\twhile (zapret_lua_invoke_next(&cursor, &step, !ctrack && !params.debug))\n",
            "\t\t\t{{\n\t\t\t\tfunc = step.rule;\n",
            "\t\t\t\tlua_rule_instance(ctx, &step, instance, sizeof(instance));\n",
            "{rest}"
        ),
        rest = rest,
    ));
    ensure!(
        !handler.contains("LIST_FOREACH(func, &dp->lua_desync, next)"),
        "C still owns a Lua rule iteration"
    );
    source.replace_range(
        start..end,
        &format!("#include \"lua_rules_windows.inc\"\n\n{handler}"),
    );
    fs::write(path, source)?;
    Ok(())
}
