// opaq: fuzzy search (nucleo-based matching against names, tags, descriptions)

use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher};

use crate::model::SecretEntry;

const NAME_WEIGHT: u32 = 3;
const TAGS_WEIGHT: u32 = 3;
const DESCRIPTION_WEIGHT: u32 = 1;

pub struct SearchResult {
    pub name: String,
    pub description: String,
    pub tags: Vec<String>,
    pub score: u32,
}

pub fn fuzzy_search(query: &str, entries: &[SecretEntry]) -> Vec<SearchResult> {
    let mut matcher = Matcher::new(Config::DEFAULT);
    let pattern = Pattern::parse(query, CaseMatching::Ignore, Normalization::Smart);

    let mut results: Vec<SearchResult> = entries
        .iter()
        .filter_map(|entry| {
            let name_score = pattern
                .match_list(std::iter::once(&entry.name), &mut matcher)
                .first()
                .map(|(_, s)| *s)
                .unwrap_or(0)
                * NAME_WEIGHT;

            let tags_score = entry
                .tags
                .iter()
                .filter_map(|tag| {
                    pattern
                        .match_list(std::iter::once(tag), &mut matcher)
                        .first()
                        .map(|(_, s)| *s)
                })
                .max()
                .unwrap_or(0)
                * TAGS_WEIGHT;

            let desc_score = pattern
                .match_list(std::iter::once(&entry.description), &mut matcher)
                .first()
                .map(|(_, s)| *s)
                .unwrap_or(0)
                * DESCRIPTION_WEIGHT;

            let total = name_score + tags_score + desc_score;
            if total > 0 {
                Some(SearchResult {
                    name: entry.name.clone(),
                    description: entry.description.clone(),
                    tags: entry.tags.clone(),
                    score: total,
                })
            } else {
                None
            }
        })
        .collect();

    results.sort_by(|a, b| b.score.cmp(&a.score));
    results
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_entry(name: &str, desc: &str, tags: &[&str]) -> SecretEntry {
        SecretEntry::new(
            name.to_string(),
            desc.to_string(),
            tags.iter().map(|s| s.to_string()).collect(),
            vec![],
        )
        .unwrap()
    }

    #[test]
    fn search_by_name() {
        let entries = vec![
            make_entry("SONARQUBE_TOKEN", "API token for SonarQube", &["sonar"]),
            make_entry("GITHUB_TOKEN", "GitHub personal access token", &["github"]),
        ];

        let results = fuzzy_search("sonar", &entries);
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "SONARQUBE_TOKEN");
    }

    #[test]
    fn search_by_tag() {
        let entries = vec![
            make_entry("MY_TOKEN", "Some token", &["ci", "sonarqube"]),
            make_entry("OTHER_TOKEN", "Other token", &["github"]),
        ];

        let results = fuzzy_search("sonar", &entries);
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "MY_TOKEN");
    }

    #[test]
    fn search_by_description() {
        let entries = vec![
            make_entry("API_KEY", "Key for SonarQube quality gateway", &["ci"]),
            make_entry("DB_PASS", "Database password", &["db"]),
        ];

        let results = fuzzy_search("sonar", &entries);
        assert!(!results.is_empty());
        assert_eq!(results[0].name, "API_KEY");
    }

    #[test]
    fn no_match_returns_empty() {
        let entries = vec![make_entry(
            "GITHUB_TOKEN",
            "GitHub access token",
            &["github"],
        )];

        let results = fuzzy_search("kubernetes", &entries);
        assert!(results.is_empty());
    }

    #[test]
    fn results_sorted_by_score() {
        let entries = vec![
            make_entry("DB_PASSWORD", "Database password", &["db"]),
            make_entry(
                "SONARQUBE_TOKEN",
                "API token for SonarQube",
                &["sonar", "sonarqube"],
            ),
            make_entry("SONAR_URL", "SonarQube URL", &["sonar"]),
        ];

        let results = fuzzy_search("sonar", &entries);
        assert!(results.len() >= 2);
        // Scores should be descending
        for window in results.windows(2) {
            assert!(window[0].score >= window[1].score);
        }
    }
}
