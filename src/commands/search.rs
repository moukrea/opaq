// opaq: search command implementation

use crate::error::Result;
use crate::search::fuzzy_search;
use crate::store::load_store;

pub fn execute(query: String, json: bool) -> Result<()> {
    let entries = load_store()?;
    let results = fuzzy_search(&query, &entries);

    if results.is_empty() {
        println!("No secrets found matching \"{}\".", query);
        println!("Tip: add secrets with `opaq add`.");
        return Ok(());
    }

    if json {
        print_json(&results)?;
    } else {
        print_text(&query, &results);
    }

    Ok(())
}

fn print_text(query: &str, results: &[crate::search::SearchResult]) {
    let count = results.len();
    if count == 1 {
        println!("Found 1 secret matching \"{}\":", query);
    } else {
        println!("Found {} secrets matching \"{}\":", count, query);
    }

    // Calculate column width based on longest name (including {{ }})
    let max_name_len = results
        .iter()
        .map(|r| r.name.len() + 4) // +4 for {{ and }}
        .max()
        .unwrap_or(0);

    for result in results {
        let placeholder = format!("{{{{{}}}}}", result.name);
        let padding = max_name_len - placeholder.len() + 4;
        println!(
            "  {}{}{}",
            placeholder,
            " ".repeat(padding),
            result.description
        );
    }
}

fn print_json(results: &[crate::search::SearchResult]) -> Result<()> {
    let json_results: Vec<serde_json::Value> = results
        .iter()
        .map(|r| {
            serde_json::json!({
                "name": r.name,
                "description": r.description,
                "tags": r.tags,
                "placeholder": format!("{{{{{}}}}}", r.name),
            })
        })
        .collect();

    let output = serde_json::to_string_pretty(&json_results)
        .map_err(|e| crate::error::OpaqError::Serialization(e.to_string()))?;
    println!("{}", output);
    Ok(())
}
