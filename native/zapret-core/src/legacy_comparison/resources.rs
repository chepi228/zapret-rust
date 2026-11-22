use super::*;

fn sample(frame: &Value) -> Value {
    let mut sample = json!({"Schema":1,"ResourceStatus":frame["ResourceStatus"],"ProcessStartKey":frame.get("ProcessStartKey").filter(|value|!value.is_null()).map(|_|string(frame,"ProcessStartKey"))});
    sample["ProcessId"] = metric(frame, "ProcessId").map_or(Value::Null, |id| json!(id as u64));
    for name in [
        "ObservedMs",
        "ReadDurationMs",
        "CpuTotalMs",
        "PrivateBytes",
        "WorkingSetBytes",
        "OsPeakWorkingSetBytes",
    ] {
        sample[name] = json!(metric(frame, name));
    }
    sample
}

pub(super) fn assess(plan: &Value, slots: &[Value], rows: &[Value]) -> Evidence<Value> {
    let frames = rows
        .iter()
        .filter(|row| row["Stage"] == "comparison-resource")
        .collect::<Vec<_>>();
    require(
        frames.len() == 3 * slots.len(),
        "incomplete-resource-matrix",
    )?;
    let mut index = BTreeMap::new();
    for frame in frames {
        let slot = number(frame, "ComparisonSlot")?;
        require(
            slot >= 1. && slot <= slots.len() as f64 && slot.fract() == 0.,
            "invalid-resource-slot",
        )?;
        require(
            same_context(plan, frame) && metric(frame, "ResourceSchema") == Some(1.),
            "mixed-resource-context",
        )?;
        require(
            same_slot(frame, &slots[slot as usize - 1]),
            "mixed-resource-identity",
        )?;
        let phase = string(frame, "ResourcePhase");
        let status = string(frame, "ResourceStatus");
        require(
            ["Ready", "Warm", "End"].contains(&phase.as_str())
                && ["Ready", "Unavailable"].contains(&status.as_str()),
            "invalid-resource-state",
        )?;
        for name in ["ObservedMs", "ReadDurationMs"] {
            require(number(frame, name)? >= 0., "invalid-resource-clock")?;
        }
        let pid = metric(frame, "ProcessId");
        let start = frame
            .get("ProcessStartKey")
            .filter(|value| !value.is_null())
            .map(|_| string(frame, "ProcessStartKey"));
        if let Some(pid) = pid {
            require(
                pid >= 1. && pid <= i32::MAX as f64 && pid.fract() == 0.,
                "invalid-resource-process",
            )?;
        }
        if let Some(start) = start.as_ref() {
            require(
                start.len() == 18 && ascii_digits(start),
                "invalid-resource-process",
            )?;
        }
        if status == "Ready" {
            require(pid.is_some() && start.is_some(), "missing-resource-process")?;
            for name in [
                "CpuTotalMs",
                "PrivateBytes",
                "WorkingSetBytes",
                "OsPeakWorkingSetBytes",
            ] {
                require(number(frame, name)? >= 0., "invalid-resource-counter")?;
            }
        }
        require(
            index.insert((slot as usize, phase), frame).is_none(),
            "duplicate-resource-phase",
        )?;
    }
    let mut windows = Vec::new();
    let mut previous = None;
    for (i, slot) in slots.iter().enumerate() {
        let frames = ["Ready", "Warm", "End"].map(|phase| {
            index
                .get(&(i + 1, phase.into()))
                .copied()
                .ok_or("missing-resource-phase")
        });
        let [ready, warm, end] = frames;
        let frames = [ready?, warm?, end?];
        let times =
            frames.map(|frame| metric(frame, "ObservedMs").expect("validated resource clock"));
        require(
            times[0] < times[1] && times[1] < times[2],
            "reversed-resource-clock",
        )?;
        require(
            previous.is_none_or(|last| times[0] > last),
            "overlapping-resource-launches",
        )?;
        previous = Some(times[2]);
        let ids = frames
            .iter()
            .filter_map(|frame| metric(frame, "ProcessId"))
            .map(|id| id.to_bits())
            .collect::<BTreeSet<_>>();
        let starts = frames
            .iter()
            .filter_map(|frame| {
                frame
                    .get("ProcessStartKey")
                    .filter(|value| !value.is_null())
                    .map(|_| string(frame, "ProcessStartKey"))
            })
            .collect::<BTreeSet<_>>();
        require(
            ids.len() <= 1 && starts.len() <= 1,
            "resource-process-reused",
        )?;
        for probe in rows.iter().filter(|row| {
            matches!(
                string(row, "Stage").as_str(),
                "comparison" | "comparison-warmup"
            ) && metric(row, "ComparisonSlot") == Some((i + 1) as f64)
        }) {
            let (lo, hi) = if probe["Stage"] == "comparison" {
                (times[1], times[2])
            } else {
                (times[0], times[1])
            };
            require(
                number(probe, "StartedMs")? >= lo && number(probe, "ObservedMs")? <= hi,
                "probe-outside-resource-window",
            )?;
        }
        let samples = frames.map(sample);
        let warm = crate::resource_window(&samples[..2]);
        let measured = crate::resource_window(&samples[1..]);
        require(
            warm["Status"] != "Invalid" && measured["Status"] != "Invalid",
            "invalid-resource-window",
        )?;
        windows.push(json!({"Slot":i+1,"Kind":slot["Kind"],"Arm":slot["Arm"],"StrategyId":slot["StrategyId"],"Warmup":warm,"Measured":measured}));
    }
    let expected = number(plan, "Blocks")? as usize * 2;
    let mut result = json!({"Schema":1,"Status":"Unavailable","Scope":"CompareMeasured","A":null,"B":null,"Windows":windows});
    let mut known = 0;
    for arm in ["A", "B"] {
        let matches = windows
            .iter()
            .filter(|row| {
                row["Kind"] == "Compare"
                    && row["Arm"] == arm
                    && row["Measured"]["Status"] == "Ready"
            })
            .collect::<Vec<_>>();
        known += matches.len();
        let mut summary = json!({"WindowsKnown":matches.len(),"WindowsExpected":expected,"CpuTimeMsSum":null,"ElapsedMsSum":null,"CpuPercentOneCoreWeighted":null,
            "PrivateBytesEndMedian":null,"ObservedMaxPrivateBytes":null,
            "FirstAttempts":rows.iter().filter(|row|row["Stage"]=="comparison" && row["ComparisonKind"]=="Compare" && row["ComparisonArm"]==arm && metric(row,"Attempt")==Some(1.)).count(),
            "RetryAttempts":rows.iter().filter(|row|row["Stage"]=="comparison" && row["ComparisonKind"]=="Compare" && row["ComparisonArm"]==arm && metric(row,"Attempt")==Some(2.)).count()});
        if !matches.is_empty() {
            let cpu = matches
                .iter()
                .map(|row| row["Measured"]["CpuTimeMs"].as_f64().expect("ready CPU"))
                .sum::<f64>();
            let elapsed = matches
                .iter()
                .map(|row| {
                    row["Measured"]["ElapsedMs"]
                        .as_f64()
                        .expect("ready elapsed")
                })
                .sum::<f64>();
            let percent = 100. * (cpu / elapsed);
            require(
                [cpu, elapsed, percent].iter().all(|n| n.is_finite()),
                "resource-aggregate-overflow",
            )?;
            summary["CpuTimeMsSum"] = json!(cpu);
            summary["ElapsedMsSum"] = json!(elapsed);
            summary["CpuPercentOneCoreWeighted"] = json!(percent);
            summary["PrivateBytesEndMedian"] = json!(median(
                matches
                    .iter()
                    .map(|row| row["Measured"]["PrivateBytesEnd"]
                        .as_f64()
                        .expect("ready private bytes"))
                    .collect()
            ));
            summary["ObservedMaxPrivateBytes"] = json!(
                matches
                    .iter()
                    .map(|row| row["Measured"]["ObservedMaxPrivateBytes"]
                        .as_f64()
                        .expect("ready maximum"))
                    .fold(0., f64::max)
            );
        }
        result[arm] = summary;
    }
    result["Status"] = json!(if known == 2 * expected {
        "Ready"
    } else if known > 0 {
        "Partial"
    } else {
        "Unavailable"
    });
    Ok(result)
}
