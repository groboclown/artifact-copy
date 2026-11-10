//! Rendering a template, and merging what it rendered with what the user
//! wrote.

use handlebars::{Handlebars, handlebars_helper, no_escape};
use serde_json::{Map, Value};

use super::keys::{AUTHENTICATION, ON_STATUS, REPOSITORIES, VALUES};

/// What a template sees of its server: everything but the repositories and
/// the credentials, plus its alias.
pub(super) fn server_context(alias: &str, body: &Map<String, Value>) -> Value {
    let mut context = body.clone();

    context.remove(REPOSITORIES);
    context.remove(AUTHENTICATION);
    context.remove(VALUES);
    context.insert("alias".to_owned(), Value::String(alias.to_owned()));

    Value::Object(context)
}

/// A template's retry with the user's over it.  The user's `on-status`
/// rules add codes, or replace the template's rule for the same code.
pub(super) fn merge_retry(template: Option<Value>, user: Option<&Value>) -> Option<Value> {
    let Some(user) = user else {
        return template;
    };

    let (Some(Value::Object(mut merged)), Value::Object(fields)) = (template, user) else {
        return Some(user.clone());
    };

    for (key, value) in fields {
        if let (ON_STATUS, Some(Value::Object(base)), Value::Object(rules)) =
            (key.as_str(), merged.get_mut(ON_STATUS), value)
        {
            for (code, rule) in rules {
                base.insert(code.clone(), rule.clone());
            }

            continue;
        }

        merged.insert(key.clone(), value.clone());
    }

    Some(Value::Object(merged))
}

/// Deep-merge `over` onto `base`, `over` winning.  Mappings merge by key;
/// anything else is replaced whole.
pub(super) fn overlay(base: &mut Value, over: Value) {
    let (Value::Object(fields), Value::Object(more)) = (&mut *base, &over) else {
        *base = over;
        return;
    };

    for (key, value) in more {
        match fields.get_mut(key) {
            Some(existing) => overlay(existing, value.clone()),
            None => {
                fields.insert(key.clone(), value.clone());
            }
        }
    }
}

handlebars_helper!(yaml: |value: Json| serde_json::to_string(value).unwrap_or_default());

handlebars_helper!(concat: |*args| args
    .iter()
    .map(|arg| match arg {
        Value::String(text) => text.clone(),
        other => other.to_string(),
    })
    .collect::<String>());

/// Strict, so a missing variable is an error; unescaped, since the output
/// is YAML and not HTML.
///
/// `yaml` quotes a value as a YAML scalar: `{{yaml repository.name}}`.
/// `concat` joins values: `{{yaml (concat "repository/" repository.name)}}`.
pub(super) fn renderer() -> Handlebars<'static> {
    let mut renderer = Handlebars::new();

    renderer.set_strict_mode(true);
    renderer.register_escape_fn(no_escape);
    renderer.register_helper("yaml", Box::new(yaml));
    renderer.register_helper("concat", Box::new(concat));

    renderer
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn retry_merge_replaces_same_status() {
        let template = serde_json::json!({"on-status": {"429": {"honor-retry-after": true}}});
        let user = serde_json::json!({"on-status": {"429": {"retry": false}}});

        let merged = merge_retry(Some(template), Some(&user)).expect("merged");

        assert_eq!(
            merged["on-status"]["429"],
            serde_json::json!({"retry": false})
        );
    }
}
