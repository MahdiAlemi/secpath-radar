use crate::prelude::*;

pub(crate) fn apply_iran_relevance_sort(brief: &mut Value) {
    let Some(items) = brief.get_mut("iran_radar").and_then(|v| v.as_array_mut()) else {
        return;
    };
    if !items.iter().any(|item| {
        item.get("iran_relevance")
            .and_then(|v| v.as_f64())
            .is_some()
    }) {
        return;
    }
    items.sort_by(|a, b| {
        let ar = a
            .get("iran_relevance")
            .and_then(|v| v.as_f64())
            .unwrap_or(-1.0);
        let br = b
            .get("iran_relevance")
            .and_then(|v| v.as_f64())
            .unwrap_or(-1.0);
        br.partial_cmp(&ar)
            .unwrap_or(std::cmp::Ordering::Equal)
            .then_with(|| {
                let arisk = a.get("risk_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
                let brisk = b.get("risk_score").and_then(|v| v.as_f64()).unwrap_or(0.0);
                brisk
                    .partial_cmp(&arisk)
                    .unwrap_or(std::cmp::Ordering::Equal)
            })
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn apply_iran_relevance_sort_orders_by_relevance_then_risk() {
        let mut brief = json!({
            "iran_radar": [
                { "title": "a", "iran_relevance": 20, "risk_score": 9 },
                { "title": "b", "iran_relevance": 90, "risk_score": 4 },
                { "title": "c", "risk_score": 8 }
            ]
        });
        apply_iran_relevance_sort(&mut brief);
        let items = brief["iran_radar"].as_array().expect("items");
        assert_eq!(items[0]["title"], json!("b"));
        assert_eq!(items[1]["title"], json!("a"));
        assert_eq!(items[2]["title"], json!("c"));
    }

    #[test]
    fn apply_iran_relevance_sort_skips_when_no_scores() {
        let mut brief = json!({
            "iran_radar": [
                { "title": "x", "risk_score": 2 },
                { "title": "y", "risk_score": 9 }
            ]
        });
        apply_iran_relevance_sort(&mut brief);
        assert_eq!(brief["iran_radar"][0]["title"], json!("x"));
    }
}
