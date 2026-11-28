//! The SELECT list built from a rule's `fields` entries.
//!
//! An entry is `*`, a field, or an aggregate call over `*` or a field, and a
//! field or call may carry an `AS alias`. Anything else, such as another
//! function, a nested call, a sub-select, an operator, a comment, or a quote,
//! fails conversion, so rule content never reaches the query as SQL.

#[cfg(test)]
mod tests;

use super::{PostgresBackend, is_field_key, validate_sql_identifier};
use crate::error::{ConvertError, Result};
use crate::state::ConversionState;

/// The aggregate functions a `fields` entry may call.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Aggregate {
    Count,
    Sum,
    Avg,
    Min,
    Max,
}

impl Aggregate {
    fn from_name(name: &str) -> Option<Self> {
        [
            ("count", Self::Count),
            ("sum", Self::Sum),
            ("avg", Self::Avg),
            ("min", Self::Min),
            ("max", Self::Max),
        ]
        .into_iter()
        .find(|(n, _)| name.eq_ignore_ascii_case(n))
        .map(|(_, a)| a)
    }
}

#[derive(Debug, PartialEq, Eq)]
enum Token<'a> {
    Word(&'a str),
    Open,
    Close,
    Star,
}

/// A parsed `fields` entry.
#[derive(Debug, PartialEq, Eq)]
enum SelectItem<'a> {
    Star,
    Field {
        field: &'a str,
        alias: Option<&'a str>,
    },
    Call {
        /// The function name as written, which is one of [`Aggregate`].
        name: &'a str,
        func: Aggregate,
        /// `None` for `*`.
        arg: Option<&'a str>,
        alias: Option<&'a str>,
    },
}

fn is_word_char(c: char) -> bool {
    c.is_ascii_alphanumeric() || matches!(c, '_' | '$' | '@' | '.' | '-' | '[' | ']')
}

fn tokenize(entry: &str) -> std::result::Result<Vec<Token<'_>>, String> {
    let mut tokens = Vec::new();
    let mut rest = entry;
    while let Some(c) = rest.chars().next() {
        if c.is_whitespace() {
            rest = &rest[c.len_utf8()..];
            continue;
        }
        let token = match c {
            '(' => Token::Open,
            ')' => Token::Close,
            '*' => Token::Star,
            c if is_word_char(c) => {
                let end = rest.find(|c| !is_word_char(c)).unwrap_or(rest.len());
                tokens.push(Token::Word(&rest[..end]));
                rest = &rest[end..];
                continue;
            }
            other => return Err(format!("unexpected character {other:?}")),
        };
        tokens.push(token);
        rest = &rest[1..];
    }
    Ok(tokens)
}

fn is_as(token: &Token<'_>) -> bool {
    matches!(token, Token::Word(w) if w.eq_ignore_ascii_case("as"))
}

fn parse_alias<'a>(rest: &[Token<'a>]) -> std::result::Result<Option<&'a str>, String> {
    match rest {
        [] => Ok(None),
        [kw, Token::Word(alias)] if is_as(kw) => Ok(Some(alias)),
        _ => Err("only `AS alias` may follow a field or call".to_string()),
    }
}

fn parse_select_field(entry: &str) -> std::result::Result<SelectItem<'_>, String> {
    let tokens = tokenize(entry)?;
    match tokens.as_slice() {
        [] => Err("the entry is empty".to_string()),
        [Token::Star] => Ok(SelectItem::Star),
        [Token::Word(field), rest @ ..] if !matches!(rest.first(), Some(Token::Open)) => {
            Ok(SelectItem::Field {
                field,
                alias: parse_alias(rest)?,
            })
        }
        [Token::Word(name), Token::Open, arg, Token::Close, rest @ ..] => {
            let func = Aggregate::from_name(name).ok_or_else(|| {
                format!("`{name}` is not an allowed function (count, sum, avg, min, max)")
            })?;
            let arg = match arg {
                Token::Star if func == Aggregate::Count => None,
                Token::Word(field) => Some(*field),
                _ => {
                    return Err(format!(
                        "`{name}` takes a field{}",
                        if func == Aggregate::Count {
                            " or `*`"
                        } else {
                            ""
                        }
                    ));
                }
            };
            Ok(SelectItem::Call {
                name,
                func,
                arg,
                alias: parse_alias(rest)?,
            })
        }
        _ => Err("expected `*`, a field, or a call such as `count(*)` or `max(field)`".to_string()),
    }
}

/// A field name as a flat column: dotted [`is_field_key`] segments, such as
/// `userIdentity.arn` and `c-uri`.
fn is_flat_field(field: &str) -> bool {
    field.split('.').all(is_field_key)
}

/// One rendered SELECT list item.
#[derive(Debug, PartialEq, Eq)]
pub(super) enum SelectColumn {
    Star,
    /// A field, with the expression a GROUP BY repeats.
    Field {
        sql: String,
        expr: String,
    },
    Aggregate(String),
}

impl SelectColumn {
    fn sql(&self) -> &str {
        match self {
            Self::Star => "*",
            Self::Field { sql, .. } | Self::Aggregate(sql) => sql,
        }
    }
}

impl PostgresBackend {
    /// The SELECT list and `GROUP BY` suffix for a detection rule's `fields`.
    ///
    /// Aggregate calls group by every field in the list. `timescaledb` and
    /// `continuous_aggregate` lead with an hourly `bucket`, which an aggregate
    /// query also groups by. A continuous aggregate must aggregate, so it
    /// counts the matching events as `event_count` when `fields` has no
    /// aggregate call of its own.
    pub(super) fn select_list(
        &self,
        fields: &[String],
        output_format: Option<&str>,
        state: &ConversionState,
    ) -> Result<(String, String)> {
        let columns = fields
            .iter()
            .map(|f| Ok((f.as_str(), self.format_select_field(f, state)?)))
            .collect::<Result<Vec<_>>>()?;
        let continuous = output_format == Some("continuous_aggregate");
        let bucketed = continuous || output_format == Some("timescaledb");
        let aggregates = columns
            .iter()
            .any(|(_, c)| matches!(c, SelectColumn::Aggregate(_)));
        if (aggregates || continuous)
            && let Some((entry, _)) = columns.iter().find(|(_, c)| *c == SelectColumn::Star)
        {
            return Err(ConvertError::InvalidSelectField {
                entry: entry.to_string(),
                reason: if aggregates {
                    "`*` cannot be combined with an aggregate call".to_string()
                } else {
                    "a continuous aggregate groups rows, so it cannot select `*`".to_string()
                },
            });
        }

        let mut items = Vec::new();
        let mut group_by = Vec::new();
        if bucketed {
            let bucket = format!("time_bucket('1 hour', {})", self.timestamp_column()?);
            items.push(format!("{bucket} AS bucket"));
            group_by.push(bucket);
        }
        for (_, column) in &columns {
            items.push(column.sql().to_string());
            if let SelectColumn::Field { expr, .. } = column {
                group_by.push(expr.clone());
            }
        }
        if continuous && !aggregates {
            items.push("count(*) AS event_count".to_string());
        } else if columns.is_empty() {
            items.push("*".to_string());
        }
        let group_by = if (aggregates || continuous) && !group_by.is_empty() {
            format!(" GROUP BY {}", group_by.join(", "))
        } else {
            String::new()
        };
        Ok((items.join(", "), group_by))
    }

    /// Render one `fields` entry as a SELECT list item.
    fn format_select_field(&self, entry: &str, state: &ConversionState) -> Result<SelectColumn> {
        let invalid = |reason: String| ConvertError::InvalidSelectField {
            entry: entry.to_string(),
            reason,
        };
        let item = parse_select_field(entry).map_err(invalid)?;
        let field = |field: &str| -> Result<()> {
            if self.json_field.is_none() && !is_flat_field(field) {
                return Err(invalid(format!("`{field}` is not a valid field name")));
            }
            Ok(())
        };
        let alias = |alias: &str| -> Result<String> {
            validate_sql_identifier(alias)
                .map_err(|_| invalid(format!("`{alias}` is not a valid alias")))?;
            self.quote_column(alias)
        };
        let with_alias = |expr: String, name: Option<String>| match name {
            Some(name) => format!("{expr} AS {name}"),
            None => expr,
        };
        let in_field = |e: ConvertError| invalid(e.to_string());

        Ok(match item {
            SelectItem::Star => SelectColumn::Star,
            SelectItem::Field { field: f, alias: a } => {
                field(f)?;
                let expr = self.field_expr(f).map_err(in_field)?;
                // A JSONB extraction has no column name of its own.
                let name = match a {
                    Some(a) => Some(alias(a)?),
                    None if self.json_field.is_some() => Some(self.quote_column(f)?),
                    None => None,
                };
                SelectColumn::Field {
                    sql: with_alias(expr.clone(), name),
                    expr,
                }
            }
            SelectItem::Call {
                name,
                func,
                arg,
                alias: a,
            } => {
                let arg = match arg {
                    None => "*".to_string(),
                    Some(f) => {
                        field(f)?;
                        match func {
                            Aggregate::Sum | Aggregate::Avg => self.numeric_expr(f, state),
                            Aggregate::Count | Aggregate::Min | Aggregate::Max => {
                                self.field_expr(f)
                            }
                        }
                        .map_err(in_field)?
                    }
                };
                SelectColumn::Aggregate(with_alias(
                    format!("{name}({arg})"),
                    a.map(&alias).transpose()?,
                ))
            }
        })
    }
}
