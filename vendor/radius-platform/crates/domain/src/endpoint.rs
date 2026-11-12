//! Endpoints: what identifies a request, its HTTP methods and a path pattern, under a name. What
//! happens to matching requests is the project's policy (the `policy` crate), which names
//! endpoints by their slug. This module holds the one validator for endpoint input.

use crate::matching::{HttpMethod, MethodMatch, PathPattern, overlaps};
use crate::validation::FieldErrors;

pub const MAX_NAME_CHARS: usize = 100;

/// The methods as sent: every method, or a list.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MethodsDraft {
    Any,
    List(Vec<String>),
}

/// A whole endpoint as sent on create, or as it would be after an update.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EndpointDraft {
    pub name: String,
    pub methods: MethodsDraft,
    pub path: String,
}

/// Another endpoint of the same project, for the name and overlap checks.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Sibling {
    pub name: String,
    pub methods: MethodMatch,
    pub path: PathPattern,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ValidEndpoint {
    pub name: String,
    pub methods: MethodMatch,
    pub path: PathPattern,
}

/// Checks a whole endpoint against the project's other endpoints (on update, without the one
/// being changed). Errors are keyed `name`, `methods` and `path`.
pub fn validate_endpoint(
    draft: &EndpointDraft,
    siblings: &[Sibling],
) -> Result<ValidEndpoint, FieldErrors> {
    let mut errors = FieldErrors::new();
    let name = errors.check(
        "name",
        validate_name(&draft.name).and_then(|name| {
            if siblings.iter().any(|sibling| sibling.name == name) {
                Err("Another endpoint in this project has this name. Choose another".to_owned())
            } else {
                Ok(name)
            }
        }),
    );
    let methods = errors.check("methods", validate_methods(&draft.methods));
    let path = errors.check("path", PathPattern::parse(&draft.path));
    if let (Some(methods), Some(path)) = (&methods, &path)
        && let Some(sibling) = siblings
            .iter()
            .find(|sibling| overlaps((methods, path), (&sibling.methods, &sibling.path)))
    {
        errors.add(
            "path",
            format!(
                "{} already handles {} on this path. Change the path or methods",
                sibling.name,
                describe_overlap(methods, &sibling.methods)
            ),
        );
    }
    match (name, methods, path) {
        (Some(name), Some(methods), Some(path)) if errors.is_empty() => Ok(ValidEndpoint {
            name,
            methods,
            path,
        }),
        _ => Err(errors),
    }
}

fn validate_name(name: &str) -> Result<String, String> {
    let name = name.trim();
    if name.is_empty() {
        return Err("Enter a name".to_owned());
    }
    if name.chars().count() > MAX_NAME_CHARS {
        return Err(format!("Use at most {MAX_NAME_CHARS} characters"));
    }
    Ok(name.to_owned())
}

fn validate_methods(methods: &MethodsDraft) -> Result<MethodMatch, String> {
    match methods {
        MethodsDraft::Any => Ok(MethodMatch::Any),
        MethodsDraft::List(list) => {
            let parsed = list
                .iter()
                .map(|text| {
                    HttpMethod::parse(text).ok_or_else(|| {
                        format!(
                            "{text:?} isn't a supported method. Use GET, POST, PUT, PATCH or DELETE"
                        )
                    })
                })
                .collect::<Result<Vec<_>, _>>()?;
            MethodMatch::only(parsed)
                .ok_or_else(|| "Choose at least one method, or any method".to_owned())
        }
    }
}

fn describe_overlap(a: &MethodMatch, b: &MethodMatch) -> String {
    match (a, b) {
        (MethodMatch::Any, MethodMatch::Any) => "every method".to_owned(),
        (MethodMatch::Only(only), MethodMatch::Any)
        | (MethodMatch::Any, MethodMatch::Only(only)) => join_methods(only.iter()),
        (MethodMatch::Only(a), MethodMatch::Only(b)) => join_methods(a.intersection(b)),
    }
}

fn join_methods<'a>(methods: impl Iterator<Item = &'a HttpMethod>) -> String {
    methods.map(|m| m.as_str()).collect::<Vec<_>>().join(", ")
}

#[cfg(test)]
mod tests {
    use super::*;
    use HttpMethod::*;

    fn draft() -> EndpointDraft {
        EndpointDraft {
            name: " Transaction ".to_owned(),
            methods: MethodsDraft::List(vec!["GET".to_owned()]),
            path: "/tx/:hash".to_owned(),
        }
    }

    fn error(draft: &EndpointDraft, siblings: &[Sibling], field: &str) -> String {
        let errors = validate_endpoint(draft, siblings).unwrap_err();
        errors
            .get(field)
            .unwrap_or_else(|| panic!("no error for {field}: {errors:?}"))
            .to_owned()
    }

    #[test]
    fn accepts_an_endpoint() {
        let valid = validate_endpoint(&draft(), &[]).unwrap();
        assert_eq!(valid.name, "Transaction");
        assert_eq!(valid.methods, MethodMatch::only([Get]).unwrap());
        assert_eq!(valid.path.to_string(), "/tx/:hash");
    }

    #[test]
    fn rejects_overlapping_methods_on_the_same_path() {
        let siblings = [Sibling {
            name: "Lookup".to_owned(),
            methods: MethodMatch::only([Get, Post]).unwrap(),
            path: PathPattern::parse("/tx/:id").unwrap(),
        }];
        assert_eq!(
            error(&draft(), &siblings, "path"),
            "Lookup already handles GET on this path. Change the path or methods"
        );
        let mut any = draft();
        any.methods = MethodsDraft::Any;
        assert_eq!(
            error(&any, &siblings, "path"),
            "Lookup already handles GET, POST on this path. Change the path or methods"
        );
        let mut delete = draft();
        delete.methods = MethodsDraft::List(vec!["DELETE".to_owned()]);
        assert!(validate_endpoint(&delete, &siblings).is_ok());
    }

    #[test]
    fn rejects_a_name_another_endpoint_has() {
        let siblings = [Sibling {
            name: "Transaction".to_owned(),
            methods: MethodMatch::only([Post]).unwrap(),
            path: PathPattern::parse("/submit").unwrap(),
        }];
        assert_eq!(
            error(&draft(), &siblings, "name"),
            "Another endpoint in this project has this name. Choose another"
        );
    }

    #[test]
    fn rejects_bad_names_methods_and_paths() {
        let mut d = draft();
        d.name = " ".to_owned();
        d.methods = MethodsDraft::List(Vec::new());
        d.path = "tx/:hash".to_owned();
        let errors = validate_endpoint(&d, &[]).unwrap_err();
        assert_eq!(errors.get("name"), Some("Enter a name"));
        assert_eq!(
            errors.get("methods"),
            Some("Choose at least one method, or any method")
        );
        assert_eq!(errors.get("path"), Some("Start the path with /"));
        d.methods = MethodsDraft::List(vec!["HEAD".to_owned()]);
        assert_eq!(
            error(&d, &[], "methods"),
            "\"HEAD\" isn't a supported method. Use GET, POST, PUT, PATCH or DELETE"
        );
    }
}
