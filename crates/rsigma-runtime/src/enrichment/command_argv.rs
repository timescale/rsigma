//! Static checks on a `command` enricher's argv.
//!
//! The enricher runs its argv directly, with no shell, so every rendered
//! element is one argument. That keeps an event value from splitting into
//! several arguments, but not from becoming code when the program treats an
//! argument as a program of its own: the script after `sh -c`, the command
//! line after `cmd /c`, the code after `python -c`, an `awk` or `jq`
//! program, or the command a wrapper such as `env` or `timeout` runs.
//! [`command_argv_problem`] finds a `${detection.*}` or `${correlation.*}`
//! reference in such a position, for the shells, interpreters, and wrappers
//! listed here, so the config loader can reject it.

use std::collections::HashMap;

use super::template::{TemplateRef, template_refs};

/// Why `argv` would let a rendered event value become a program or code,
/// or `None` when it does not, as far as the programs known here go.
pub(crate) fn command_argv_problem(
    argv: &[String],
    env: &HashMap<String, String>,
) -> Option<String> {
    check(argv, 0, env)
}

fn check(argv: &[String], offset: usize, env: &HashMap<String, String>) -> Option<String> {
    let first = argv.first()?;
    if has_result_ref(first) {
        return Some(format!(
            "command[{offset}] is the program to run and cannot use a ${{detection.*}} or ${{correlation.*}} reference"
        ));
    }
    let program = program_name(&resolve_env(first));
    let args = &argv[1..];
    let at = |i: usize| offset + 1 + i;
    let code_problem = |i: usize| {
        format!(
            "command[{}] is code that {program} runs, so it cannot use a ${{detection.*}} or ${{correlation.*}} reference; pass the value as a separate argument or an environment variable the code reads",
            at(i)
        )
    };

    match classify(&program, args) {
        Kind::Plain => None,
        Kind::Code(indexes) => {
            if let Some(&i) = indexes.iter().find(|&&i| has_result_ref(&args[i])) {
                return Some(code_problem(i));
            }
            if program == "cmd" {
                return cmd_env_problem(args, &indexes, env).map(|name| {
                    format!(
                        "cmd expands %{name}% before it parses the command line, and {name} uses a ${{detection.*}} or ${{correlation.*}} reference; use delayed expansion (!{name}! with /V:ON) or pass the value as an argument"
                    )
                });
            }
            None
        }
        Kind::Wraps(start) => check(&args[start..], at(start), env),
    }
}

enum Kind {
    /// The program takes its arguments as data.
    Plain,
    /// These argument indexes hold code or a script path.
    Code(Vec<usize>),
    /// The program runs the command that starts at this argument index.
    Wraps(usize),
}

fn classify(program: &str, args: &[String]) -> Kind {
    let s = |v: &[&'static str]| v.to_vec();
    match program {
        "sh" | "bash" | "rbash" | "dash" | "zsh" | "ksh" | "ksh93" | "mksh" | "pdksh" | "ash"
        | "yash" | "fish" | "csh" | "tcsh" => Kind::Code(shell_code(args)),
        "cmd" => Kind::Code(
            args.iter()
                .position(|a| matches!(a.to_ascii_lowercase().as_str(), "/c" | "/k"))
                .map_or_else(Vec::new, |i| (i + 1..args.len()).collect()),
        ),
        "powershell" | "powershell_ise" | "pwsh" => Kind::Code(powershell_code(args)),
        p if p.starts_with("python") || p.starts_with("pypy") => Kind::Code(interpreter_code(
            args,
            &Interpreter {
                code_flags: s(&["-c", "-m"]),
                value_flags: s(&["-W", "-X", "-Q"]),
                code_ends_options: true,
            },
        )),
        "perl" | "ruby" | "lua" | "luajit" | "osascript" | "rscript" => {
            Kind::Code(interpreter_code(
                args,
                &Interpreter {
                    code_flags: s(&["-e", "-E"]),
                    value_flags: s(&["-I", "-r"]),
                    code_ends_options: false,
                },
            ))
        }
        "node" | "nodejs" | "bun" => Kind::Code(interpreter_code(
            args,
            &Interpreter {
                code_flags: s(&["-e", "--eval", "-p", "--print"]),
                value_flags: s(&["-r", "--require", "--import", "--loader"]),
                code_ends_options: true,
            },
        )),
        "deno" => match args.first().map(String::as_str) {
            Some("eval") => Kind::Code((1..args.len()).collect()),
            Some("run") => Kind::Code(
                interpreter_code(
                    &args[1..],
                    &Interpreter {
                        code_flags: s(&[]),
                        value_flags: s(&[]),
                        code_ends_options: true,
                    },
                )
                .into_iter()
                .map(|i| i + 1)
                .collect(),
            ),
            _ => Kind::Plain,
        },
        "php" => Kind::Code(interpreter_code(
            args,
            &Interpreter {
                code_flags: s(&["-r", "-f", "-B", "-R", "-F", "-E"]),
                value_flags: s(&["-c", "-d", "-z"]),
                code_ends_options: false,
            },
        )),
        "tclsh" | "wish" | "expect" => Kind::Code(interpreter_code(
            args,
            &Interpreter {
                code_flags: s(&["-c"]),
                value_flags: s(&[]),
                code_ends_options: true,
            },
        )),
        "awk" | "gawk" | "mawk" | "nawk" | "original-awk" => Kind::Code(program_operand_code(
            args,
            &["-f", "--file", "-e", "--source"],
            &["-v", "--assign", "-F", "--field-separator"],
            &[],
        )),
        "sed" | "gsed" => Kind::Code(program_operand_code(
            args,
            &["-e", "--expression", "-f", "--file"],
            &["-l", "--line-length"],
            &[],
        )),
        "jq" | "jaq" | "gojq" | "yq" => Kind::Code(program_operand_code(
            args,
            &["-f", "--from-file"],
            &["--indent", "-L"],
            &["--arg", "--argjson", "--slurpfile", "--rawfile"],
        )),
        "env" => wrapped(
            args,
            &["-u", "--unset", "-C", "--chdir"],
            0,
            true,
            &["-S", "--split-string"],
        ),
        "nice" => wrapped(args, &["-n", "--adjustment"], 0, false, &[]),
        "nohup" | "setsid" | "unbuffer" | "caffeinate" => wrapped(args, &[], 0, false, &[]),
        "timeout" | "gtimeout" => wrapped(
            args,
            &["-s", "--signal", "-k", "--kill-after"],
            1,
            false,
            &[],
        ),
        "stdbuf" => wrapped(args, &["-i", "-o", "-e"], 0, false, &[]),
        "time" => wrapped(args, &["-f", "--format", "-o", "--output"], 0, false, &[]),
        "ionice" => wrapped(args, &["-c", "--class", "-n", "--classdata"], 0, false, &[]),
        "chrt" | "taskset" | "flock" | "chroot" => wrapped(args, &[], 1, false, &[]),
        "sudo" => wrapped(
            args,
            &["-u", "-g", "-C", "-D", "-h", "-p", "-r", "-t", "-U", "-T"],
            0,
            false,
            &[],
        ),
        "doas" => wrapped(args, &["-u", "-C"], 0, false, &[]),
        "xargs" => wrapped(
            args,
            &[
                "-a",
                "-d",
                "-E",
                "-I",
                "-L",
                "-n",
                "-P",
                "-s",
                "--arg-file",
                "--delimiter",
            ],
            0,
            false,
            &[],
        ),
        "busybox" => Kind::Wraps(0),
        "su" | "runuser" => Kind::Code(
            args.iter()
                .enumerate()
                .filter_map(|(i, a)| match a.as_str() {
                    "-c" | "--command" => Some(i + 1),
                    a if a.starts_with("--command=") => Some(i),
                    _ => None,
                })
                .filter(|&i| i < args.len())
                .collect(),
        ),
        _ => Kind::Plain,
    }
}

/// The first operand of a POSIX-style shell: the script after `-c`, or the
/// path of the script to run.
fn shell_code(args: &[String]) -> Vec<usize> {
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            i += 1;
            break;
        }
        if matches!(arg, "-o" | "+o" | "-O" | "+O" | "--rcfile" | "--init-file") {
            i += 2;
            continue;
        }
        if arg.len() > 1 && (arg.starts_with('-') || arg.starts_with('+')) {
            i += 1;
            continue;
        }
        break;
    }
    if i < args.len() { vec![i] } else { Vec::new() }
}

/// PowerShell runs the argument after `-File` as a script and binds the
/// rest as parameters; otherwise it joins every argument into a command.
fn powershell_code(args: &[String]) -> Vec<usize> {
    match args
        .iter()
        .position(|a| matches!(a.to_ascii_lowercase().as_str(), "-file" | "-f"))
    {
        Some(i) => vec![i + 1]
            .into_iter()
            .filter(|&j| j < args.len())
            .collect(),
        None => (0..args.len()).collect(),
    }
}

struct Interpreter {
    /// Flags whose value is code (or a script or module to run).
    code_flags: Vec<&'static str>,
    /// Flags whose value is data.
    value_flags: Vec<&'static str>,
    /// Whether the arguments after the code are the program's own.
    code_ends_options: bool,
}

/// The code arguments of an interpreter: the values of its code flags, or,
/// without one, its first operand (the script path).
fn interpreter_code(args: &[String], interp: &Interpreter) -> Vec<usize> {
    let mut code = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            if code.is_empty() && i + 1 < args.len() {
                code.push(i + 1);
            }
            break;
        }
        if interp.code_flags.contains(&arg) {
            if i + 1 < args.len() {
                code.push(i + 1);
            }
            if interp.code_ends_options {
                break;
            }
            i += 2;
            continue;
        }
        let attached = interp.code_flags.iter().any(|f| {
            (f.len() == 2 && arg.starts_with(*f) && arg.len() > 2)
                || (f.starts_with("--") && arg.starts_with(&format!("{f}=")))
        });
        if attached {
            code.push(i);
            if interp.code_ends_options {
                break;
            }
            i += 1;
            continue;
        }
        if interp.value_flags.contains(&arg) {
            i += 2;
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            i += 1;
            continue;
        }
        if code.is_empty() {
            code.push(i);
        }
        break;
    }
    code
}

/// The program of a tool that takes it as its first operand unless a
/// program flag gives it: `awk`, `sed`, `jq`.
fn program_operand_code(
    args: &[String],
    program_flags: &[&str],
    value_flags: &[&str],
    two_value_flags: &[&str],
) -> Vec<usize> {
    let mut code = Vec::new();
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();
        if arg == "--" {
            if code.is_empty() && i + 1 < args.len() {
                code.push(i + 1);
            }
            break;
        }
        if program_flags.contains(&arg) {
            if i + 1 < args.len() {
                code.push(i + 1);
            }
            i += 2;
            continue;
        }
        if program_flags
            .iter()
            .any(|f| f.len() == 2 && arg.starts_with(*f) && arg.len() > 2)
        {
            code.push(i);
            i += 1;
            continue;
        }
        if value_flags.contains(&arg) {
            i += 2;
            continue;
        }
        if two_value_flags.contains(&arg) {
            i += 3;
            continue;
        }
        if matches!(arg, "--args" | "--jsonargs") {
            break;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            i += 1;
            continue;
        }
        if code.is_empty() {
            code.push(i);
        }
        break;
    }
    code
}

/// Where the command a wrapper runs starts, after its options, the values
/// of `value_flags`, `operands` leading operands (a `timeout` duration),
/// and, for `env`, `NAME=VALUE` assignments. A `code_flags` value is a
/// command line the wrapper splits itself.
fn wrapped(
    args: &[String],
    value_flags: &[&str],
    operands: usize,
    assignments: bool,
    code_flags: &[&str],
) -> Kind {
    let mut i = 0;
    let mut operands_left = operands;
    while i < args.len() {
        let arg = args[i].as_str();
        if code_flags.contains(&arg) {
            return Kind::Code(
                vec![i + 1]
                    .into_iter()
                    .filter(|&j| j < args.len())
                    .collect(),
            );
        }
        if arg == "--" {
            i += 1;
            break;
        }
        if value_flags.contains(&arg) {
            i += 2;
            continue;
        }
        if arg.starts_with('-') && arg.len() > 1 {
            i += 1;
            continue;
        }
        if assignments && arg.contains('=') {
            i += 1;
            continue;
        }
        if operands_left > 0 {
            operands_left -= 1;
            i += 1;
            continue;
        }
        break;
    }
    while operands_left > 0 && i < args.len() {
        operands_left -= 1;
        i += 1;
    }
    if i < args.len() {
        Kind::Wraps(i)
    } else {
        Kind::Plain
    }
}

/// An `env` entry that uses a result reference and that a `cmd` command
/// line expands as `%NAME%`.
fn cmd_env_problem(
    args: &[String],
    code: &[usize],
    env: &HashMap<String, String>,
) -> Option<String> {
    let line: String = code
        .iter()
        .map(|&i| args[i].to_ascii_lowercase())
        .collect::<Vec<_>>()
        .join(" ");
    let mut names: Vec<&String> = env
        .iter()
        .filter(|(_, value)| has_result_ref(value))
        .map(|(name, _)| name)
        .collect();
    names.sort();
    names
        .into_iter()
        .find(|name| line.contains(&format!("%{}%", name.to_ascii_lowercase())))
        .cloned()
}

/// The program's file name, lowercased, without a directory or a Windows
/// executable extension.
fn program_name(path: &str) -> String {
    let base = path
        .rsplit(['/', '\\'])
        .next()
        .unwrap_or(path)
        .to_ascii_lowercase();
    for ext in [".exe", ".com"] {
        if let Some(stem) = base.strip_suffix(ext) {
            return stem.to_string();
        }
    }
    base
}

/// `text` with its `${ENV_VAR}` references expanded and every other
/// reference kept as written.
fn resolve_env(text: &str) -> String {
    let mut out = String::new();
    let mut pos = 0;
    for (range, reference) in template_refs(text) {
        out.push_str(&text[pos..range.start]);
        match reference {
            TemplateRef::Env(name) => out.push_str(&std::env::var(name).unwrap_or_default()),
            TemplateRef::Result(_) => out.push_str(&text[range.clone()]),
        }
        pos = range.end;
    }
    out.push_str(&text[pos..]);
    out
}

pub(crate) fn has_result_ref(text: &str) -> bool {
    template_refs(text).any(|(_, r)| matches!(r, TemplateRef::Result(_)))
}

/// Whether `template` starts with a result reference, so its rendered value
/// controls the argument's first character.
pub(crate) fn starts_with_result_ref(template: &str) -> bool {
    template_refs(template)
        .next()
        .is_some_and(|(range, r)| range.start == 0 && matches!(r, TemplateRef::Result(_)))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn problem(argv: &[&str]) -> Option<String> {
        let argv: Vec<String> = argv.iter().map(|s| s.to_string()).collect();
        command_argv_problem(&argv, &HashMap::new())
    }

    const V: &str = "${detection.fields.Host}";

    #[test]
    fn arguments_to_ordinary_programs_are_data() {
        assert!(problem(&["/usr/local/bin/check-ip-rep", V]).is_none());
        assert!(problem(&["whois", "--", V]).is_none());
        assert!(problem(&["/bin/echo", &format!("host={V}")]).is_none());
    }

    #[test]
    fn the_program_cannot_come_from_a_result() {
        assert!(problem(&[V]).unwrap().contains("command[0]"));
        assert!(problem(&["/opt/${detection.fields.Tool}/run"]).is_some());
        assert!(problem(&["env", "A=1", V]).unwrap().contains("command[2]"));
        assert!(
            problem(&["timeout", "5", V, "x"])
                .unwrap()
                .contains("command[2]")
        );
        // SAFETY: the variable name is unique to this test.
        unsafe { std::env::set_var("RSIGMA_TEST_ARGV_TOOL", "/usr/bin/lookup") };
        assert!(problem(&["${RSIGMA_TEST_ARGV_TOOL}", V]).is_none());
    }

    #[test]
    fn shell_scripts_cannot_use_results() {
        for argv in [
            vec!["sh", "-c", "lookup ${detection.fields.Host}"],
            vec!["/bin/bash", "-ec", "lookup '${detection.fields.Host}'"],
            vec!["bash", "-o", "pipefail", "-c", "x ${detection.fields.Host}"],
            vec!["zsh", "${detection.fields.Host}"],
            vec!["env", "FOO=1", "sh", "-c", "echo ${detection.fields.Host}"],
            vec![
                "timeout",
                "-s",
                "KILL",
                "5",
                "sh",
                "-c",
                "echo ${detection.fields.Host}",
            ],
            vec![
                "sudo",
                "-u",
                "nobody",
                "bash",
                "-c",
                "echo ${detection.fields.Host}",
            ],
            vec!["busybox", "sh", "-c", "echo ${detection.fields.Host}"],
            vec!["cmd.exe", "/C", "echo", "${detection.fields.Host}"],
            vec![
                "C:\\Windows\\System32\\cmd.exe",
                "/s",
                "/c",
                "tool ${detection.fields.Host}",
            ],
            vec![
                "pwsh",
                "-NoProfile",
                "-Command",
                "Write-Output ${detection.fields.Host}",
            ],
            vec!["powershell", "${detection.fields.Host}"],
            vec!["env", "-S", "sh -c ${detection.fields.Host}"],
            vec!["su", "nobody", "-c", "id ${detection.fields.Host}"],
        ] {
            assert!(problem(&argv).is_some(), "{argv:?}");
        }
    }

    #[test]
    fn shell_positional_parameters_are_data() {
        assert!(problem(&["sh", "-c", "lookup \"$1\"", "sh", V]).is_none());
        assert!(problem(&["bash", "-ec", "lookup \"$1\"", "--", V]).is_none());
        assert!(problem(&["pwsh", "-File", "/opt/lookup.ps1", "-Host", V]).is_none());
    }

    #[test]
    fn interpreter_code_cannot_use_results() {
        for argv in [
            vec!["python3", "-c", "print('${detection.fields.Host}')"],
            vec!["python3", "-cprint('${detection.fields.Host}')"],
            vec!["python3", "-m", "${detection.fields.Host}"],
            vec!["python3", "${detection.fields.Host}"],
            vec!["perl", "-w", "-e", "print qq(${detection.fields.Host})"],
            vec!["ruby", "-e", "puts '${detection.fields.Host}'"],
            vec!["node", "--eval", "console.log('${detection.fields.Host}')"],
            vec!["node", "--eval=console.log('${detection.fields.Host}')"],
            vec!["php", "-r", "echo '${detection.fields.Host}';"],
            vec![
                "osascript",
                "-e",
                "display dialog \"${detection.fields.Host}\"",
            ],
            vec!["awk", "-F", ",", "/${detection.fields.Host}/"],
            vec!["sed", "-n", "-e", "s/${detection.fields.Host}//p"],
            vec!["sed", "s/${detection.fields.Host}//"],
            vec!["jq", "--arg", "h", "x", ".[\"${detection.fields.Host}\"]"],
        ] {
            assert!(problem(&argv).is_some(), "{argv:?}");
        }
    }

    #[test]
    fn interpreter_arguments_are_data() {
        assert!(problem(&["python3", "/opt/lookup.py", V]).is_none());
        assert!(problem(&["python3", "-c", "import sys; print(sys.argv[1])", V]).is_none());
        assert!(problem(&["perl", "-e", "print $ARGV[0]", V]).is_none());
        assert!(problem(&["node", "/opt/lookup.js", V]).is_none());
        assert!(problem(&["awk", "-v", &format!("h={V}"), "$1 == h", "/var/db"]).is_none());
        assert!(problem(&["jq", "-n", "--arg", "h", V, "$h"]).is_none());
        assert!(problem(&["jq", "-n", "$ARGS.positional[0]", "--args", V]).is_none());
        assert!(problem(&["sed", "-e", "s/a/b/", V]).is_none());
    }

    #[test]
    fn cmd_cannot_expand_a_result_from_the_environment() {
        let argv: Vec<String> = ["cmd", "/c", "echo %HOST%"].map(String::from).to_vec();
        let env = HashMap::from([("HOST".to_string(), V.to_string())]);
        assert!(
            command_argv_problem(&argv, &env)
                .unwrap()
                .contains("%HOST%")
        );
        let argv: Vec<String> = ["cmd", "/V:ON", "/c", "echo !HOST!"]
            .map(String::from)
            .to_vec();
        assert!(command_argv_problem(&argv, &env).is_none());
    }

    #[test]
    fn a_leading_result_reference_is_detected() {
        assert!(starts_with_result_ref("${detection.fields.Host}"));
        assert!(starts_with_result_ref("${detection.fields.Host}.example"));
        assert!(!starts_with_result_ref("--host=${detection.fields.Host}"));
        assert!(!starts_with_result_ref("${HOME}/x"));
    }
}
