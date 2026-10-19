//! The add/edit entry form: which rows it has, and converting between an
//! [`Entry`] and the form.
//!
//! Row order (login-only rows are hidden for secure notes):
//!
//! ```text
//! Type · Title · Username* · Password* · URLs* · TOTP* · Tags · Favourite
//! [Field name · Value · Hidden] per custom field · + Add custom field · Notes
//! ```
//!
//! A custom field whose name and value are both left empty is dropped on
//! save; that's how custom fields are removed.

use zeroize::{Zeroize, Zeroizing};

use super::form::{Form, Row, RowId};
use crate::vault::{CustomField, Entry, EntryKind};

/// Choice options for the Type row, in [`kind_index`] order.
const KINDS: &[&str] = &["Login", "Secure note"];

/// Rows only shown for logins.
const LOGIN_ROWS: [RowId; 4] = [RowId::Username, RowId::Password, RowId::Urls, RowId::Totp];

fn kind_index(kind: EntryKind) -> usize {
    match kind {
        EntryKind::Login => 0,
        EntryKind::Note => 1,
    }
}

fn kind_from_index(i: usize) -> EntryKind {
    if i == 1 {
        EntryKind::Note
    } else {
        EntryKind::Login
    }
}

/// Build the form for `entry`, or for a new login if `None`.
#[must_use]
pub fn build(entry: Option<&Entry>) -> Form {
    let blank = Entry::new(EntryKind::Login, "");
    let e = entry.unwrap_or(&blank);

    let mut rows = vec![
        Row::choice(RowId::Kind, "Type", KINDS, kind_index(e.kind)),
        Row::text(RowId::Title, "Title", &e.title).with_placeholder("required"),
        Row::text(RowId::Username, "Username", &e.username),
        Row::secret(RowId::Password, "Password", &e.password),
        Row::multiline(RowId::Urls, "URLs", &Zeroizing::new(e.urls.join("\n")))
            .with_placeholder("one per line"),
        Row::secret(RowId::Totp, "TOTP", &e.totp).with_placeholder("secret or otpauth:// URI"),
        Row::text(RowId::Tags, "Tags", &Zeroizing::new(e.tags.join(", ")))
            .with_placeholder("comma-separated"),
        Row::toggle(RowId::Favorite, "Favourite", e.favorite),
    ];
    for (i, field) in e.custom_fields.iter().enumerate() {
        rows.extend(custom_rows(i, field));
    }
    rows.push(Row::button(RowId::AddCustom, "+ Add custom field"));
    rows.push(Row::multiline(RowId::Notes, "Notes", &e.notes));

    let mut form = Form::new(rows);
    show_rows_for(&mut form, e.kind);
    // Start on the title: the type is rarely what you want to change.
    form.focus_row(RowId::Title);
    form
}

/// The three rows for custom field number `i`.
fn custom_rows(i: usize, field: &CustomField) -> [Row; 3] {
    let value = if field.hidden {
        Row::secret(RowId::CustomValue(i), "  Value", &field.value)
    } else {
        Row::text(RowId::CustomValue(i), "  Value", &field.value)
    };
    [
        Row::text(RowId::CustomName(i), "Field name", &field.name)
            .with_placeholder("leave name and value empty to remove"),
        value,
        Row::toggle(RowId::CustomHidden(i), "  Hidden", field.hidden),
    ]
}

/// Number of custom fields currently in the form.
fn custom_count(form: &Form) -> usize {
    form.rows()
        .iter()
        .filter(|r| matches!(r.id, RowId::CustomName(_)))
        .count()
}

/// Add an empty custom field and focus its name.
pub fn add_custom_field(form: &mut Form) {
    let i = custom_count(form);
    let blank = CustomField {
        name: String::new(),
        value: String::new(),
        hidden: false,
    };
    form.insert_before(RowId::AddCustom, custom_rows(i, &blank).into());
    form.focus_row(RowId::CustomName(i));
    form.dirty = true;
}

/// React to a changed row: switching the type shows or hides the login
/// rows, and the "Hidden" toggle masks its value.
pub fn on_change(form: &mut Form, id: RowId) {
    match id {
        RowId::Kind => show_rows_for(form, kind_from_index(form.choice(RowId::Kind))),
        RowId::CustomHidden(i) => form.set_secret(RowId::CustomValue(i), form.toggle(id)),
        _ => {}
    }
}

fn show_rows_for(form: &mut Form, kind: EntryKind) {
    // Values in hidden rows are kept, so switching back loses nothing.
    for id in LOGIN_ROWS {
        form.set_hidden(id, kind == EntryKind::Note);
    }
}

/// The trimmed title, or `None` if it's empty (titles are required).
#[must_use]
pub fn title(form: &Form) -> Option<String> {
    let title = form.text(RowId::Title).trim().to_owned();
    (!title.is_empty()).then_some(title)
}

/// Write the form's values into `entry`. Doesn't touch `id` or timestamps.
///
/// Every old value is wiped before it is replaced, and every intermediate
/// copy is a [`Zeroizing`] one: `entry` is usually a clone that the vault
/// keeps (see `Vault::update`), so plain assignment would free the previous
/// password, notes and so on without wiping them.
pub fn apply(form: &Form, entry: &mut Entry) {
    entry.kind = kind_from_index(form.choice(RowId::Kind));
    replace(&mut entry.title, form.text(RowId::Title).trim());
    replace(&mut entry.username, &form.text(RowId::Username));
    replace(&mut entry.password, &form.text(RowId::Password));
    replace_list(&mut entry.urls, form.text(RowId::Urls).lines());
    replace(&mut entry.totp, form.text(RowId::Totp).trim());
    replace_list(&mut entry.tags, form.text(RowId::Tags).split(','));
    entry.favorite = form.toggle(RowId::Favorite);
    // `CustomField` wipes itself on drop, so the old list can simply go.
    entry.custom_fields = (0..custom_count(form))
        .filter_map(|i| {
            let name = form.text(RowId::CustomName(i));
            let name = name.trim();
            let value = form.text(RowId::CustomValue(i));
            if name.is_empty() && value.is_empty() {
                return None;
            }
            Some(CustomField {
                name: if name.is_empty() { "Field" } else { name }.to_owned(),
                value: value.as_str().to_owned(),
                hidden: form.toggle(RowId::CustomHidden(i)),
            })
        })
        .collect();
    replace(&mut entry.notes, &form.text(RowId::Notes));
}

/// Wipe `dst`, then copy `new` into it. If `new` is longer, the buffer that
/// `clone_into` gives up has already been wiped.
fn replace(dst: &mut String, new: &str) {
    dst.zeroize();
    new.clone_into(dst);
}

/// Wipe `dst`, then fill it with the trimmed, non-empty `items`.
fn replace_list<'a>(dst: &mut Vec<String>, items: impl Iterator<Item = &'a str>) {
    dst.zeroize();
    *dst = items
        .map(str::trim)
        .filter(|s| !s.is_empty())
        .map(str::to_owned)
        .collect();
}

#[cfg(test)]
mod tests {
    use super::*;

    fn full_entry() -> Entry {
        let mut e = Entry::new(EntryKind::Login, "Mail");
        e.username = "alice".into();
        e.password = "pw".into();
        e.urls = vec!["https://a.example".into(), "imap.a.example".into()];
        e.totp = "JBSWY3DP".into();
        e.tags = vec!["work".into(), "email".into()];
        e.favorite = true;
        e.custom_fields = vec![
            CustomField {
                name: "PIN".into(),
                value: "1234".into(),
                hidden: true,
            },
            CustomField {
                name: "Plan".into(),
                value: "Pro".into(),
                hidden: false,
            },
        ];
        e.notes = "line 1\nline 2".into();
        e
    }

    #[test]
    fn build_then_apply_round_trips() {
        let original = full_entry();
        let form = build(Some(&original));
        let mut copy = original.clone();
        copy.title.clear();
        copy.custom_fields.clear();
        apply(&form, &mut copy);
        assert_eq!(copy, original);
        assert!(!form.dirty);
    }

    #[test]
    fn urls_and_tags_are_cleaned_up() {
        let mut e = Entry::new(EntryKind::Login, "x");
        e.urls = vec!["  https://a  ".into(), String::new(), "b".into()];
        e.tags = vec![" one ".into(), "two".into()];
        let form = build(Some(&e));
        apply(&form, &mut e);
        assert_eq!(e.urls, ["https://a", "b"]);
        assert_eq!(e.tags, ["one", "two"]);
    }

    #[test]
    fn empty_custom_fields_are_dropped_and_unnamed_ones_get_a_name() {
        let mut form = build(None);
        add_custom_field(&mut form);
        add_custom_field(&mut form);
        assert_eq!(form.focused_id(), Some(RowId::CustomName(1)));

        let mut e = Entry::new(EntryKind::Login, "t");
        e.custom_fields = vec![
            CustomField {
                name: String::new(),
                value: String::new(),
                hidden: false,
            },
            CustomField {
                name: String::new(),
                value: "v".into(),
                hidden: false,
            },
        ];
        let form = build(Some(&e));
        apply(&form, &mut e);
        assert_eq!(e.custom_fields.len(), 1);
        assert_eq!(e.custom_fields[0].name, "Field");
    }

    #[test]
    fn notes_hide_login_rows_but_keep_their_values() {
        let original = full_entry();
        let mut form = build(Some(&original));
        form.focus_row(RowId::Kind);
        form.input(crossterm::event::KeyEvent::from(
            crossterm::event::KeyCode::Right,
        ));
        on_change(&mut form, RowId::Kind);

        let hidden: Vec<_> = form
            .rows()
            .iter()
            .filter(|r| r.hidden)
            .map(|r| r.id)
            .collect();
        assert_eq!(hidden, LOGIN_ROWS);

        let mut e = original.clone();
        apply(&form, &mut e);
        assert_eq!(e.kind, EntryKind::Note);
        assert_eq!(e.password, "pw", "switching type doesn't throw data away");
    }

    #[test]
    fn title_is_required() {
        let form = build(None);
        assert_eq!(title(&form), None);
        let form = build(Some(&Entry::new(EntryKind::Login, "  Bank ")));
        assert_eq!(title(&form).as_deref(), Some("Bank"));
    }
}
