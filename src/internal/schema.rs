//! JSON Schema violation rendering.

use jsonschema::ValidationError;

/// One violation, naming where it sits unless that is the document root.
///
/// The instance path is a JSON Pointer, and the root's pointer is empty:
/// an unexpected key in the top-level mapping reports there.  `subject`
/// names the document, or is empty when the caller supplies context.
///
/// ```text
///   ("values", /mapping)   values at /mapping: ...
///   ("values", root)       values: ...
///   ("", /mapping)         at /mapping: ...
///   ("", root)             ...
/// ```
pub(crate) fn violation(subject: &str, err: &ValidationError<'_>) -> String {
    let path = err.instance_path();

    if path.is_empty() {
        if subject.is_empty() {
            return err.to_string();
        }
        return format!("{subject}: {err}");
    }

    if subject.is_empty() {
        return format!("at {}: {err}", path.as_str());
    }
    format!("{subject} at {}: {err}", path.as_str())
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    /// Every violation of a closed mapping with one string field.
    fn violations(subject: &str, value: &serde_json::Value) -> Vec<String> {
        let schema = json!({
            "type": "object",
            "properties": { "mapping": { "type": "string" } },
            "additionalProperties": false,
        });
        let validator = jsonschema::validator_for(&schema).expect("compiles");

        validator
            .iter_errors(value)
            .map(|err| violation(subject, &err))
            .collect()
    }

    #[test]
    fn root_omits_location() {
        let found = violations("values", &json!({ "extra": 1 }));

        assert_eq!(found.len(), 1);
        assert!(found[0].starts_with("values: "), "{}", found[0]);
    }

    #[test]
    fn root_without_subject_bare() {
        let found = violations("", &json!({ "extra": 1 }));

        assert_eq!(found.len(), 1);
        assert!(
            found[0].starts_with("Additional properties"),
            "{}",
            found[0]
        );
    }

    #[test]
    fn nested_names_location() {
        let found = violations("values", &json!({ "mapping": 1 }));

        assert_eq!(found.len(), 1);
        assert!(found[0].starts_with("values at /mapping: "), "{}", found[0]);
    }

    #[test]
    fn nested_without_subject() {
        let found = violations("", &json!({ "mapping": 1 }));

        assert_eq!(found.len(), 1);
        assert!(found[0].starts_with("at /mapping: "), "{}", found[0]);
    }
}
