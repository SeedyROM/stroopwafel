use crate::{Result, StroopwafelError};
use std::collections::HashMap;

/// Operators supported in predicates
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Operator {
    /// Equality (=)
    Equal,
    /// Inequality (!=)
    NotEqual,
    /// Less than (<)
    LessThan,
    /// Greater than (>)
    GreaterThan,
    /// Less than or equal (<=)
    LessThanOrEqual,
    /// Greater than or equal (>=)
    GreaterThanOrEqual,
    /// Glob match (~): supports `*` (any sequence) and `?` (any single char)
    Matches,
    /// Glob not-match (!~)
    NotMatches,
}

impl Operator {
    /// Parse an operator from a string
    pub fn parse(s: &str) -> Option<Self> {
        match s.trim() {
            "=" => Some(Operator::Equal),
            "!=" => Some(Operator::NotEqual),
            "<" => Some(Operator::LessThan),
            ">" => Some(Operator::GreaterThan),
            "<=" => Some(Operator::LessThanOrEqual),
            ">=" => Some(Operator::GreaterThanOrEqual),
            "~" => Some(Operator::Matches),
            "!~" => Some(Operator::NotMatches),
            _ => None,
        }
    }

    /// Evaluate the operator on two string values
    pub fn evaluate(&self, left: &str, right: &str) -> bool {
        match self {
            Operator::Equal => left == right,
            Operator::NotEqual => left != right,
            Operator::LessThan => left < right,
            Operator::GreaterThan => left > right,
            Operator::LessThanOrEqual => left <= right,
            Operator::GreaterThanOrEqual => left >= right,
            Operator::Matches => glob_match(right, left),
            Operator::NotMatches => !glob_match(right, left),
        }
    }

    /// Evaluate the operator on two numeric values
    pub fn evaluate_numeric(&self, left: f64, right: f64) -> bool {
        match self {
            Operator::Equal => (left - right).abs() < f64::EPSILON,
            Operator::NotEqual => (left - right).abs() >= f64::EPSILON,
            Operator::LessThan => left < right,
            Operator::GreaterThan => left > right,
            Operator::LessThanOrEqual => left <= right,
            Operator::GreaterThanOrEqual => left >= right,
            // Glob matching doesn't apply to numerics — fall through to string form
            Operator::Matches | Operator::NotMatches => {
                self.evaluate(&left.to_string(), &right.to_string())
            }
        }
    }
}

/// Match `value` against a glob `pattern`.
///
/// Supported wildcards:
/// - `*` — matches zero or more characters
/// - `?` — matches exactly one character
///
/// All other characters match literally.
pub fn glob_match(pattern: &str, value: &str) -> bool {
    glob_match_bytes(pattern.as_bytes(), value.as_bytes())
}

fn glob_match_bytes(pattern: &[u8], value: &[u8]) -> bool {
    match (pattern, value) {
        // Both exhausted — full match
        ([], []) => true,
        // `*` matches zero remaining chars
        ([b'*', rest_p @ ..], _) => {
            glob_match_bytes(rest_p, value)
                || (!value.is_empty() && glob_match_bytes(pattern, &value[1..]))
        }
        // `?` matches any single char
        ([b'?', rest_p @ ..], [_, rest_v @ ..]) => glob_match_bytes(rest_p, rest_v),
        // Literal match
        ([p, rest_p @ ..], [v, rest_v @ ..]) if p == v => glob_match_bytes(rest_p, rest_v),
        _ => false,
    }
}

/// A parsed predicate with key, operator, and value
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Predicate {
    /// The key (e.g., "account", "time", "action")
    pub key: String,
    /// The comparison operator
    pub operator: Operator,
    /// The value to compare against
    pub value: String,
}

impl Predicate {
    /// Parse a predicate from a string
    ///
    /// Format: "key operator value"
    /// Examples:
    /// - "account = alice"
    /// - "time < 2025-12-31T23:59:59Z"
    /// - "count >= 10"
    pub fn parse(s: &str) -> Result<Self> {
        // Try to find an operator (longer tokens first to avoid prefix ambiguity)
        let operators = ["<=", ">=", "!=", "!~", "=", "<", ">", "~"];

        for op_str in &operators {
            if let Some(pos) = s.find(op_str) {
                let key = s[..pos].trim().to_string();
                let value = s[pos + op_str.len()..].trim().to_string();

                if key.is_empty() || value.is_empty() {
                    return Err(StroopwafelError::InvalidFormat(format!(
                        "Invalid predicate format: '{s}'"
                    )));
                }

                let operator = Operator::parse(op_str).ok_or_else(|| {
                    StroopwafelError::InvalidFormat(format!("Unknown operator: '{op_str}'"))
                })?;

                return Ok(Predicate {
                    key,
                    operator,
                    value,
                });
            }
        }

        Err(StroopwafelError::InvalidFormat(format!(
            "No operator found in predicate: '{s}'"
        )))
    }

    /// Evaluate this predicate against a context
    ///
    /// The context is a map of key-value pairs representing the current state.
    pub fn evaluate(&self, context: &HashMap<String, String>) -> bool {
        let actual_value = match context.get(&self.key) {
            Some(v) => v,
            None => return false, // Key not in context
        };

        // Try numeric comparison first
        if let (Ok(actual_num), Ok(expected_num)) =
            (actual_value.parse::<f64>(), self.value.parse::<f64>())
        {
            return self.operator.evaluate_numeric(actual_num, expected_num);
        }

        // Fall back to string comparison
        self.operator.evaluate(actual_value, &self.value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_equal() {
        let pred = Predicate::parse("account = alice").unwrap();
        assert_eq!(pred.key, "account");
        assert_eq!(pred.operator, Operator::Equal);
        assert_eq!(pred.value, "alice");
    }

    #[test]
    fn test_parse_not_equal() {
        let pred = Predicate::parse("status != banned").unwrap();
        assert_eq!(pred.key, "status");
        assert_eq!(pred.operator, Operator::NotEqual);
        assert_eq!(pred.value, "banned");
    }

    #[test]
    fn test_parse_less_than() {
        let pred = Predicate::parse("time < 2025-12-31").unwrap();
        assert_eq!(pred.key, "time");
        assert_eq!(pred.operator, Operator::LessThan);
        assert_eq!(pred.value, "2025-12-31");
    }

    #[test]
    fn test_parse_greater_than_or_equal() {
        let pred = Predicate::parse("count >= 10").unwrap();
        assert_eq!(pred.key, "count");
        assert_eq!(pred.operator, Operator::GreaterThanOrEqual);
        assert_eq!(pred.value, "10");
    }

    #[test]
    fn test_parse_with_whitespace() {
        let pred = Predicate::parse("  key  =  value  ").unwrap();
        assert_eq!(pred.key, "key");
        assert_eq!(pred.value, "value");
    }

    #[test]
    fn test_parse_invalid_no_operator() {
        let result = Predicate::parse("just some text");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_empty_key() {
        let result = Predicate::parse("= value");
        assert!(result.is_err());
    }

    #[test]
    fn test_parse_invalid_empty_value() {
        let result = Predicate::parse("key =");
        assert!(result.is_err());
    }

    #[test]
    fn test_evaluate_string_equal() {
        let pred = Predicate::parse("account = alice").unwrap();
        let mut context = HashMap::new();
        context.insert("account".to_string(), "alice".to_string());

        assert!(pred.evaluate(&context));
    }

    #[test]
    fn test_evaluate_string_not_equal() {
        let pred = Predicate::parse("account = alice").unwrap();
        let mut context = HashMap::new();
        context.insert("account".to_string(), "bob".to_string());

        assert!(!pred.evaluate(&context));
    }

    #[test]
    fn test_evaluate_numeric_less_than() {
        let pred = Predicate::parse("count < 100").unwrap();
        let mut context = HashMap::new();
        context.insert("count".to_string(), "50".to_string());

        assert!(pred.evaluate(&context));

        context.insert("count".to_string(), "150".to_string());
        assert!(!pred.evaluate(&context));
    }

    #[test]
    fn test_evaluate_numeric_greater_than_or_equal() {
        let pred = Predicate::parse("age >= 18").unwrap();
        let mut context = HashMap::new();

        context.insert("age".to_string(), "18".to_string());
        assert!(pred.evaluate(&context));

        context.insert("age".to_string(), "25".to_string());
        assert!(pred.evaluate(&context));

        context.insert("age".to_string(), "17".to_string());
        assert!(!pred.evaluate(&context));
    }

    #[test]
    fn test_evaluate_string_comparison() {
        let pred = Predicate::parse("name < bob").unwrap();
        let mut context = HashMap::new();

        context.insert("name".to_string(), "alice".to_string());
        assert!(pred.evaluate(&context)); // "alice" < "bob"

        context.insert("name".to_string(), "charlie".to_string());
        assert!(!pred.evaluate(&context)); // "charlie" > "bob"
    }

    #[test]
    fn test_evaluate_missing_key() {
        let pred = Predicate::parse("account = alice").unwrap();
        let context = HashMap::new();

        assert!(!pred.evaluate(&context)); // Missing key should fail
    }

    #[test]
    fn test_evaluate_time_comparison() {
        let pred = Predicate::parse("time < 2025-12-31T23:59:59Z").unwrap();
        let mut context = HashMap::new();

        context.insert("time".to_string(), "2025-01-01T00:00:00Z".to_string());
        assert!(pred.evaluate(&context));

        context.insert("time".to_string(), "2026-01-01T00:00:00Z".to_string());
        assert!(!pred.evaluate(&context));
    }

    #[test]
    fn test_operator_precedence() {
        // Make sure <= is matched before <
        let pred = Predicate::parse("x <= 5").unwrap();
        assert_eq!(pred.operator, Operator::LessThanOrEqual);
    }

    #[test]
    fn test_parse_matches() {
        let pred = Predicate::parse("resource ~ /api/*").unwrap();
        assert_eq!(pred.key, "resource");
        assert_eq!(pred.operator, Operator::Matches);
        assert_eq!(pred.value, "/api/*");
    }

    #[test]
    fn test_parse_not_matches() {
        let pred = Predicate::parse("resource !~ /internal/*").unwrap();
        assert_eq!(pred.key, "resource");
        assert_eq!(pred.operator, Operator::NotMatches);
        assert_eq!(pred.value, "/internal/*");
    }

    #[test]
    fn test_glob_star_wildcard() {
        assert!(glob_match("*", "anything"));
        assert!(glob_match("*", ""));
        assert!(glob_match("/api/*", "/api/users"));
        assert!(glob_match("/api/*", "/api/users/123"));
        assert!(!glob_match("/api/*", "/other/users"));
    }

    #[test]
    fn test_glob_question_wildcard() {
        assert!(glob_match("v?", "v1"));
        assert!(glob_match("v?", "v2"));
        assert!(!glob_match("v?", "v"));
        assert!(!glob_match("v?", "v10"));
    }

    #[test]
    fn test_glob_combined() {
        assert!(glob_match("/api/v?/*", "/api/v1/users"));
        assert!(glob_match("/api/v?/*", "/api/v2/orders/123"));
        assert!(!glob_match("/api/v?/*", "/api/v10/users"));
    }

    #[test]
    fn test_glob_literal() {
        assert!(glob_match("/exact/path", "/exact/path"));
        assert!(!glob_match("/exact/path", "/other/path"));
    }

    #[test]
    fn test_evaluate_matches_predicate() {
        let pred = Predicate::parse("resource ~ /docs/*").unwrap();
        let mut context = HashMap::new();

        context.insert("resource".to_string(), "/docs/readme".to_string());
        assert!(pred.evaluate(&context));

        context.insert("resource".to_string(), "/admin/secret".to_string());
        assert!(!pred.evaluate(&context));
    }

    #[test]
    fn test_evaluate_not_matches_predicate() {
        let pred = Predicate::parse("resource !~ /internal/*").unwrap();
        let mut context = HashMap::new();

        context.insert("resource".to_string(), "/public/page".to_string());
        assert!(pred.evaluate(&context));

        context.insert("resource".to_string(), "/internal/secret".to_string());
        assert!(!pred.evaluate(&context));
    }
}
