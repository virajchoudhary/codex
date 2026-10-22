use crate::command_safety::powershell_tree_sitter::try_parse_powershell_commands;
use once_cell::sync::Lazy;
use regex::Regex;
use shlex::split as shlex_split;
use tree_sitter::Node;
use tree_sitter::Parser;
use url::Url;

pub fn is_dangerous_command_windows(command: &[String]) -> bool {
    // Prefer structured parsing for PowerShell/CMD so we can spot URL-bearing
    // invocations of ShellExecute-style entry points before falling back to
    // simple argv heuristics.
    if is_dangerous_powershell(command) {
        return true;
    }

    if is_dangerous_cmd(command) {
        return true;
    }

    is_direct_gui_launch(command)
}

fn is_dangerous_powershell(command: &[String]) -> bool {
    let Some((exe, rest)) = command.split_first() else {
        return false;
    };
    if !is_powershell_executable(exe) {
        return false;
    }
    let Some(parsed) = parse_powershell_invocation(rest) else {
        return false;
    };

    if let Some(script) = parsed.script
        && let Some(commands) = try_parse_powershell_commands(script)
        && powershell_commands_are_independent(script, &commands)
    {
        return commands
            .iter()
            .any(|words| is_dangerous_powershell_literal_words(words));
    }
    is_dangerous_powershell_words(&parsed.tokens)
}

/// Whether strictly lowered commands can be classified independently of the rest of the script.
pub fn powershell_commands_are_independent(script: &str, commands: &[Vec<String>]) -> bool {
    // Deliberately keep even quoted pipes and `||` chains on the existing path. Do not
    // model pipeline data, command rebinding, or strings that may execute using script state.
    !script.contains('|')
        && commands.iter().all(|words| {
            !matches!(
                words
                    .first()
                    .and_then(|word| executable_basename(word))
                    .as_deref(),
                Some(
                    "set-alias"
                        | "sal"
                        | "new-alias"
                        | "nal"
                        | "set-item"
                        | "si"
                        | "new-item"
                        | "ni"
                )
            ) && !words.iter().skip(1).any(|word| {
                let word = word.to_ascii_lowercase();
                [
                    "start-process",
                    "invoke-item",
                    "shellexecute",
                    "shell.application",
                ]
                .iter()
                .any(|marker| word.contains(marker))
            })
        })
}

enum PowerShellCommandKind {
    Opaque,
    IndependentLiteral,
}

pub(crate) fn is_dangerous_powershell_words(words: &[String]) -> bool {
    classify_powershell_words(words, PowerShellCommandKind::Opaque)
}

pub(crate) fn is_dangerous_powershell_literal_words(words: &[String]) -> bool {
    // Shell and terminal wrappers can interpret later words as commands, including `start`.
    let kind = if words.first().is_some_and(|word| {
        is_powershell_executable(word)
            || matches!(
                executable_basename(word).as_deref(),
                Some("cmd" | "cmd.exe" | "wt" | "wt.exe")
            )
    }) {
        PowerShellCommandKind::Opaque
    } else {
        PowerShellCommandKind::IndependentLiteral
    };
    classify_powershell_words(words, kind)
}

fn classify_powershell_words(words: &[String], kind: PowerShellCommandKind) -> bool {
    let tokens_lc: Vec<String> = words
        .iter()
        .map(|t| t.trim_matches('\'').trim_matches('"').to_ascii_lowercase())
        .collect();
    let has_url = args_have_url(words);

    if has_url
        && tokens_lc.iter().enumerate().any(|(index, t)| {
            ((index == 0 || matches!(kind, PowerShellCommandKind::Opaque))
                && matches!(
                    t.as_str(),
                    "start-process" | "start" | "saps" | "invoke-item" | "ii"
                ))
                || t.contains("start-process")
                || t.contains("invoke-item")
        })
    {
        return true;
    }

    if has_url
        && tokens_lc
            .iter()
            .any(|t| t.contains("shellexecute") || t.contains("shell.application"))
    {
        return true;
    }

    if let Some(first) = tokens_lc.first() {
        // Legacy ShellExecute path via url.dll
        if first == "rundll32"
            && tokens_lc
                .iter()
                .any(|t| t.contains("url.dll,fileprotocolhandler"))
            && has_url
        {
            return true;
        }
        if first == "mshta" && has_url {
            return true;
        }
        if is_browser_executable(first) && has_url {
            return true;
        }
        if matches!(first.as_str(), "explorer" | "explorer.exe") && has_url {
            return true;
        }
    }

    // Check for force delete operations (e.g., Remove-Item -Force)
    has_force_delete_cmdlet(&tokens_lc)
}

fn is_dangerous_cmd(command: &[String]) -> bool {
    let Some((exe, rest)) = command.split_first() else {
        return false;
    };
    let Some(base) = executable_basename(exe) else {
        return false;
    };
    if base != "cmd" && base != "cmd.exe" {
        return false;
    }

    let mut iter = rest.iter();
    for arg in iter.by_ref() {
        let lower = arg.to_ascii_lowercase();
        match lower.as_str() {
            "/c" | "/r" | "-c" => break,
            _ if lower.starts_with('/') => continue,
            // Unknown tokens before the command body => bail.
            _ => return false,
        }
    }

    let remaining: Vec<String> = iter.cloned().collect();
    if remaining.is_empty() {
        return false;
    }

    let cmd_tokens: Vec<String> = match remaining.as_slice() {
        [only] => shlex_split(only).unwrap_or_else(|| vec![only.clone()]),
        _ => remaining,
    };

    // Refine tokens by splitting concatenated CMD operators (e.g. "echo hi&del")
    let tokens: Vec<String> = cmd_tokens
        .into_iter()
        .flat_map(|t| split_embedded_cmd_operators(&t))
        .collect();

    const CMD_SEPARATORS: &[&str] = &["&", "&&", "|", "||"];
    tokens
        .split(|t| CMD_SEPARATORS.contains(&t.as_str()))
        .any(|segment| {
            let Some(cmd) = segment.first() else {
                return false;
            };

            // Classic `cmd /c ... start https://...` ShellExecute path.
            if cmd.eq_ignore_ascii_case("start") && args_have_url(segment) {
                return true;
            }
            // Force delete: del /f, erase /f
            if (cmd.eq_ignore_ascii_case("del") || cmd.eq_ignore_ascii_case("erase"))
                && has_force_flag_cmd(segment)
            {
                return true;
            }
            // Recursive directory removal: rd /s /q, rmdir /s /q
            if (cmd.eq_ignore_ascii_case("rd") || cmd.eq_ignore_ascii_case("rmdir"))
                && has_recursive_flag_cmd(segment)
                && has_quiet_flag_cmd(segment)
            {
                return true;
            }
            false
        })
}

fn is_direct_gui_launch(command: &[String]) -> bool {
    let Some((exe, rest)) = command.split_first() else {
        return false;
    };
    let Some(base) = executable_basename(exe) else {
        return false;
    };

    // Explorer/rundll32/mshta or direct browser exe with a URL anywhere in args.
    if matches!(base.as_str(), "explorer" | "explorer.exe") && args_have_url(rest) {
        return true;
    }
    if matches!(base.as_str(), "mshta" | "mshta.exe") && args_have_url(rest) {
        return true;
    }
    if (base == "rundll32" || base == "rundll32.exe")
        && rest.iter().any(|t| {
            t.to_ascii_lowercase()
                .contains("url.dll,fileprotocolhandler")
        })
        && args_have_url(rest)
    {
        return true;
    }
    if is_browser_executable(&base) && args_have_url(rest) {
        return true;
    }

    false
}

fn split_embedded_cmd_operators(token: &str) -> Vec<String> {
    // Split concatenated CMD operators so `echo hi&del` becomes `["echo hi", "&", "del"]`.
    // Handles `&`, `&&`, `|`, `||`. Best-effort (CMD escaping is weird by nature).
    let mut parts = Vec::new();
    let mut start = 0;
    let mut it = token.char_indices().peekable();

    while let Some((i, ch)) = it.next() {
        if ch == '&' || ch == '|' {
            if i > start {
                parts.push(token[start..i].to_string());
            }

            // Detect doubled operator: && or ||
            let op_len = match it.peek() {
                Some(&(j, next)) if next == ch => {
                    it.next(); // consume second char
                    (j + next.len_utf8()) - i
                }
                _ => ch.len_utf8(),
            };

            parts.push(token[i..i + op_len].to_string());
            start = i + op_len;
        }
    }

    if start < token.len() {
        parts.push(token[start..].to_string());
    }

    parts.retain(|s| !s.trim().is_empty());
    parts
}

fn has_force_delete_cmdlet(tokens: &[String]) -> bool {
    const DELETE_CMDLETS: &[&str] = &["remove-item", "ri", "rm", "del", "erase", "rd", "rmdir"];

    // Hard separators that end a command segment (so -Force must be in same segment)
    const SEG_SEPS: &[char] = &[';', '|', '&', '\n', '\r', '\t'];

    // Soft separators: punctuation that can stick to tokens (blocks, parens, brackets, commas, etc.)
    const SOFT_SEPS: &[char] = &['{', '}', '(', ')', '[', ']', ',', ';'];

    // Build rough command segments first
    let mut segments: Vec<Vec<String>> = vec![Vec::new()];
    for tok in tokens {
        // If token itself contains segment separators, split it (best-effort)
        let mut cur = String::new();
        for ch in tok.chars() {
            if SEG_SEPS.contains(&ch) {
                let s = cur.trim();
                if let Some(msg) = segments.last_mut()
                    && !s.is_empty()
                {
                    msg.push(s.to_string());
                }
                cur.clear();
                if let Some(last) = segments.last()
                    && !last.is_empty()
                {
                    segments.push(Vec::new());
                }
            } else {
                cur.push(ch);
            }
        }
        let s = cur.trim();
        if let Some(segment) = segments.last_mut()
            && !s.is_empty()
        {
            segment.push(s.to_string());
        }
    }

    // Now, inside each segment, normalize tokens by splitting on soft punctuation
    segments.into_iter().any(|seg| {
        let atoms = seg
            .iter()
            .flat_map(|t| t.split(|c| SOFT_SEPS.contains(&c)))
            .map(str::trim)
            .filter(|s| !s.is_empty());

        let mut has_delete = false;
        let mut has_force = false;

        for a in atoms {
            if DELETE_CMDLETS.iter().any(|cmd| a.eq_ignore_ascii_case(cmd)) {
                has_delete = true;
            }
            if a.eq_ignore_ascii_case("-force")
                || a.get(..7)
                    .is_some_and(|p| p.eq_ignore_ascii_case("-force:"))
            {
                has_force = true;
            }
        }

        has_delete && has_force
    })
}

/// Check for /f or /F flag in CMD del/erase arguments.
fn has_force_flag_cmd(args: &[String]) -> bool {
    args.iter().any(|a| a.eq_ignore_ascii_case("/f"))
}

/// Check for /s or /S flag in CMD rd/rmdir arguments.
fn has_recursive_flag_cmd(args: &[String]) -> bool {
    args.iter().any(|a| a.eq_ignore_ascii_case("/s"))
}

/// Check for /q or /Q flag in CMD rd/rmdir arguments.
fn has_quiet_flag_cmd(args: &[String]) -> bool {
    args.iter().any(|a| a.eq_ignore_ascii_case("/q"))
}

fn args_have_url(args: &[String]) -> bool {
    args.iter().any(|arg| looks_like_url(arg))
}

fn looks_like_url(token: &str) -> bool {
    // Strip common PowerShell punctuation around inline URLs (quotes, parens, trailing semicolons).
    // Capture the middle token after trimming leading quotes/parens/whitespace and trailing semicolons/closing parens.
    static RE: Lazy<Option<Regex>> =
        Lazy::new(|| Regex::new(r#"^[ "'\(\s]*([^\s"'\);]+)[\s;\)]*$"#).ok());
    // If the token embeds a URL alongside other text (e.g., Start-Process('https://...'))
    // as a single shlex token, grab the substring starting at the first URL prefix.
    let lowercase_token = token.to_ascii_lowercase();
    let urlish = lowercase_token
        .find("https://")
        .or_else(|| lowercase_token.find("http://"))
        .map(|idx| &token[idx..])
        .unwrap_or(token);

    let candidate = RE
        .as_ref()
        .and_then(|re| re.captures(urlish))
        .and_then(|caps| caps.get(1))
        .map(|m| m.as_str())
        .unwrap_or(urlish);
    let Ok(url) = Url::parse(candidate) else {
        return false;
    };
    matches!(url.scheme(), "http" | "https")
}

fn executable_basename(exe: &str) -> Option<String> {
    let name = exe
        .rsplit(['/', '\\'])
        .next()
        .filter(|name| !name.is_empty())?;
    let name = match name.as_bytes() {
        [drive, b':', ..] if drive.is_ascii_alphabetic() => &name[2..],
        _ => name,
    };
    (!name.is_empty()).then(|| name.to_ascii_lowercase())
}

fn is_powershell_executable(exe: &str) -> bool {
    matches!(
        executable_basename(exe).as_deref(),
        Some("powershell") | Some("powershell.exe") | Some("pwsh") | Some("pwsh.exe")
    )
}

fn is_browser_executable(name: &str) -> bool {
    matches!(
        name,
        "chrome"
            | "chrome.exe"
            | "msedge"
            | "msedge.exe"
            | "firefox"
            | "firefox.exe"
            | "iexplore"
            | "iexplore.exe"
    )
}

struct ParsedPowershell<'a> {
    tokens: Vec<String>,
    script: Option<&'a str>,
}

fn powershell_script_words(script: &str, allow_inert_diagnostic: bool) -> Option<Vec<String>> {
    let words = shlex_split(script)?;
    if !allow_inert_diagnostic
        || !args_have_url(&words)
        || !words
            .iter()
            .any(|word| word.to_ascii_lowercase().contains("useshellexecute"))
    {
        return Some(words);
    }

    let mut parser = Parser::new();
    if parser
        .set_language(&tree_sitter_powershell::LANGUAGE.into())
        .is_err()
    {
        return Some(words);
    }
    let Some(tree) = parser.parse(script, None) else {
        return Some(words);
    };
    let source = script.as_bytes();
    let root = tree.root_node();
    if root.has_error() || !is_inert_process_start_info_diagnostic(root, source) {
        return Some(words);
    }

    let mut sanitized = source.to_vec();
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        let mut cursor = node.walk();
        if let Some(member) = literal_false_shell_execute_member(node, source)
            .or_else(|| direct_shell_execute_read_member(node, source).map(|(_, member)| member))
        {
            sanitized[member.byte_range()].fill(b'_');
        }
        stack.extend(node.named_children(&mut cursor));
    }

    std::str::from_utf8(&sanitized)
        .ok()
        .and_then(shlex_split)
        .or(Some(words))
}

fn is_inert_process_start_info_diagnostic(root: Node<'_>, source: &[u8]) -> bool {
    if root.kind() != "program"
        || root.named_child_count() != 1
        || root
            .named_child(0)
            .is_none_or(|node| node.kind() != "statement_list")
    {
        return false;
    }
    let Some(statement_list) = root.named_child(0) else {
        return false;
    };
    let mut statement_cursor = statement_list.walk();
    let statements: Vec<_> = statement_list
        .named_children(&mut statement_cursor)
        .collect();
    if statements.len() != 4
        || statements[..3].iter().any(|statement| {
            statement.kind() != "pipeline"
                || statement.named_child_count() != 1
                || statement
                    .named_child(0)
                    .is_none_or(|expression| expression.kind() != "assignment_expression")
        })
    {
        return false;
    }
    let Some((shell_execute_read_variable, _)) =
        direct_shell_execute_read_member(statements[3], source)
    else {
        return false;
    };

    let mut diagnostic_variable = None;
    let mut shell_execute_variable = None;
    let mut arguments_variable = None;
    let mut constructor_offset = None;
    let mut shell_execute_offset = None;
    let mut arguments_offset = None;
    let mut assignment_count = 0;
    let mut invocation_count = 0;
    let mut stack = vec![root];
    while let Some(node) = stack.pop() {
        if !is_inert_diagnostic_node_kind(node.kind()) {
            return false;
        }

        match node.kind() {
            "assignment_expression" => {
                assignment_count += 1;
                if let Some(variable) = process_start_info_constructor_variable(node, source) {
                    if diagnostic_variable.replace(variable).is_some() {
                        return false;
                    }
                    constructor_offset = Some(node.start_byte());
                } else if let Some(variable) = literal_false_shell_execute_variable(node, source) {
                    if shell_execute_variable.replace(variable).is_some() {
                        return false;
                    }
                    shell_execute_offset = Some(node.start_byte());
                } else if let Some(variable) = literal_url_arguments_variable(node, source) {
                    if arguments_variable.replace(variable).is_some() {
                        return false;
                    }
                    arguments_offset = Some(node.start_byte());
                } else {
                    return false;
                }
            }
            "invokation_expression" => {
                invocation_count += 1;
                if !is_process_start_info_constructor_invocation(node, source) {
                    return false;
                }
            }
            "comment"
                if node.utf8_text(source).ok().is_some_and(|comment| {
                    comment
                        .trim_start()
                        .to_ascii_lowercase()
                        .starts_with("#requires")
                }) =>
            {
                return false;
            }
            _ => {}
        }

        let mut cursor = node.walk();
        stack.extend(node.named_children(&mut cursor));
    }

    let (Some(diagnostic_variable), Some(shell_execute_variable), Some(arguments_variable)) = (
        diagnostic_variable,
        shell_execute_variable,
        arguments_variable,
    ) else {
        return false;
    };
    let (Some(constructor_offset), Some(shell_execute_offset), Some(arguments_offset)) =
        (constructor_offset, shell_execute_offset, arguments_offset)
    else {
        return false;
    };
    let read_offset = statements[3].start_byte();

    assignment_count == 3
        && invocation_count == 1
        && diagnostic_variable.eq_ignore_ascii_case(&shell_execute_variable)
        && diagnostic_variable.eq_ignore_ascii_case(&arguments_variable)
        && diagnostic_variable.eq_ignore_ascii_case(&shell_execute_read_variable)
        && constructor_offset < shell_execute_offset
        && shell_execute_offset < arguments_offset
        && arguments_offset < read_offset
}

fn is_inert_diagnostic_node_kind(kind: &str) -> bool {
    matches!(
        kind,
        "program"
            | "statement_list"
            | "pipeline"
            | "pipeline_chain"
            | "empty_statement"
            | "comment"
            | "assignment_expression"
            | "left_assignment_expression"
            | "assignement_operator"
            | "logical_expression"
            | "bitwise_expression"
            | "comparison_expression"
            | "additive_expression"
            | "multiplicative_expression"
            | "format_expression"
            | "range_expression"
            | "array_literal_expression"
            | "unary_expression"
            | "variable"
            | "member_access"
            | "member_name"
            | "simple_name"
            | "invokation_expression"
            | "type_literal"
            | "type_name"
            | "type_spec"
            | "type_identifier"
            | "argument_list"
            | "string_literal"
            | "verbatim_string_characters"
    )
}

fn direct_shell_execute_read_member<'tree>(
    node: Node<'tree>,
    source: &[u8],
) -> Option<(String, Node<'tree>)> {
    if node.kind() != "pipeline" || node.named_child_count() != 1 {
        return None;
    }
    let pipeline_chain = node.named_child(0)?;
    if pipeline_chain.kind() != "pipeline_chain" || pipeline_chain.named_child_count() != 1 {
        return None;
    }

    let mut expression = pipeline_chain.named_child(0)?;
    while expression.kind() != "member_access" {
        if !matches!(
            expression.kind(),
            "logical_expression"
                | "bitwise_expression"
                | "comparison_expression"
                | "additive_expression"
                | "multiplicative_expression"
                | "format_expression"
                | "range_expression"
                | "array_literal_expression"
                | "unary_expression"
        ) || expression.named_child_count() != 1
        {
            return None;
        }
        expression = expression.named_child(0)?;
    }

    if expression.named_child_count() != 2 || expression.child(1)?.kind() != "." {
        return None;
    }
    let receiver = simple_variable_text(expression.named_child(0)?, source)?;
    let member = expression.named_child(1)?;
    if member.kind() != "member_name"
        || member.named_child_count() != 1
        || member.named_child(0)?.kind() != "simple_name"
        || !member
            .utf8_text(source)
            .ok()?
            .eq_ignore_ascii_case("UseShellExecute")
    {
        return None;
    }
    Some((receiver, member))
}

fn assignment_parts<'tree>(node: Node<'tree>, source: &[u8]) -> Option<(Node<'tree>, Node<'tree>)> {
    if node.kind() != "assignment_expression" {
        return None;
    }
    let mut cursor = node.walk();
    let mut children = node
        .named_children(&mut cursor)
        .filter(|child| child.kind() != "comment");
    let mut left = children.next()?;
    let operator = children.next()?;
    let value = children.next()?;
    if left.kind() != "left_assignment_expression"
        || operator.kind() != "assignement_operator"
        || operator.utf8_text(source).ok()? != "="
        || children.next().is_some()
    {
        return None;
    }
    while !matches!(left.kind(), "member_access" | "variable") && left.named_child_count() == 1 {
        left = left.named_child(0)?;
    }
    Some((left, value))
}

fn assignment_member_target<'tree>(
    node: Node<'tree>,
    source: &[u8],
) -> Option<(String, Node<'tree>, Node<'tree>)> {
    let (target, value) = assignment_parts(node, source)?;
    if target.kind() != "member_access"
        || target.named_child_count() != 2
        || target.child(1)?.kind() != "."
    {
        return None;
    }
    let receiver = simple_variable_text(target.named_child(0)?, source)?;
    let member = target.named_child(1)?;
    if member.kind() != "member_name" || member.named_child(0)?.kind() != "simple_name" {
        return None;
    }
    Some((receiver, member, value))
}

fn simple_variable_text(node: Node<'_>, source: &[u8]) -> Option<String> {
    if node.kind() != "variable" {
        return None;
    }
    let text = node.utf8_text(source).ok()?;
    let name = text.strip_prefix('$')?;
    let mut characters = name.chars();
    if !characters
        .next()
        .is_some_and(|character| character.is_ascii_alphabetic() || character == '_')
        || !characters.all(|character| character.is_ascii_alphanumeric() || character == '_')
    {
        return None;
    }
    Some(text.to_string())
}

fn process_start_info_constructor_variable(node: Node<'_>, source: &[u8]) -> Option<String> {
    let (target, value) = assignment_parts(node, source)?;
    let variable = simple_variable_text(target, source)?;
    let invocation = unwrap_single_named_node(value, "invokation_expression")?;
    is_process_start_info_constructor_invocation(invocation, source).then_some(variable)
}

fn is_process_start_info_constructor_invocation(node: Node<'_>, source: &[u8]) -> bool {
    if node.kind() != "invokation_expression" || node.named_child_count() != 3 {
        return false;
    }
    let Some(type_literal) = node.named_child(0) else {
        return false;
    };
    let Some(member) = node.named_child(1) else {
        return false;
    };
    let Some(arguments) = node.named_child(2) else {
        return false;
    };
    type_literal.kind() == "type_literal"
        && node
            .child(1)
            .is_some_and(|operator| operator.kind() == "::")
        && type_literal
            .utf8_text(source)
            .is_ok_and(|value| value.eq_ignore_ascii_case("[System.Diagnostics.ProcessStartInfo]"))
        && member.kind() == "member_name"
        && member
            .utf8_text(source)
            .is_ok_and(|value| value.eq_ignore_ascii_case("new"))
        && member
            .named_child(0)
            .is_some_and(|name| name.kind() == "simple_name")
        && arguments.kind() == "argument_list"
        && arguments.named_child_count() == 0
}

fn literal_false_shell_execute_variable(node: Node<'_>, source: &[u8]) -> Option<String> {
    literal_false_shell_execute_member(node, source)?;
    assignment_member_target(node, source).map(|(receiver, _, _)| receiver)
}

fn literal_url_arguments_variable(node: Node<'_>, source: &[u8]) -> Option<String> {
    let (receiver, member, value) = assignment_member_target(node, source)?;
    if !member
        .utf8_text(source)
        .ok()?
        .eq_ignore_ascii_case("Arguments")
    {
        return None;
    }
    let literal = unwrap_single_named_node(value, "string_literal")?;
    if literal.named_child_count() != 1
        || literal.named_child(0)?.kind() != "verbatim_string_characters"
    {
        return None;
    }
    let words = shlex_split(literal.utf8_text(source).ok()?)?;
    (words.len() == 1 && args_have_url(&words)).then_some(receiver)
}

fn unwrap_single_named_node<'tree>(
    mut node: Node<'tree>,
    expected_kind: &str,
) -> Option<Node<'tree>> {
    while node.kind() != expected_kind {
        if node.named_child_count() != 1 {
            return None;
        }
        node = node.named_child(0)?;
    }
    Some(node)
}

fn literal_false_shell_execute_member<'tree>(
    node: Node<'tree>,
    source: &[u8],
) -> Option<Node<'tree>> {
    let (_, member, value) = assignment_member_target(node, source)?;
    if !member
        .utf8_text(source)
        .ok()?
        .eq_ignore_ascii_case("UseShellExecute")
        || !value.utf8_text(source).ok()?.eq_ignore_ascii_case("$false")
    {
        return None;
    }
    Some(member)
}

fn parse_powershell_invocation(args: &[String]) -> Option<ParsedPowershell<'_>> {
    if args.is_empty() {
        return None;
    }
    let allow_inert_diagnostic = is_no_profile_command_envelope(args);

    let mut idx = 0;
    while idx < args.len() {
        let arg = &args[idx];
        let lower = arg.to_ascii_lowercase();
        match lower.as_str() {
            "-command" | "/command" | "-c" => {
                let script = args.get(idx + 1)?;
                if idx + 2 != args.len() {
                    return None;
                }
                let tokens = powershell_script_words(script, allow_inert_diagnostic)?;
                return Some(ParsedPowershell {
                    tokens,
                    script: Some(script),
                });
            }
            _ if lower.starts_with("-command:") || lower.starts_with("/command:") => {
                if idx + 1 != args.len() {
                    return None;
                }
                let (_, script) = arg.split_once(':')?;
                let tokens = powershell_script_words(script, allow_inert_diagnostic)?;
                return Some(ParsedPowershell {
                    tokens,
                    script: Some(script),
                });
            }
            "-nologo" | "-noprofile" | "-noninteractive" | "-mta" | "-sta" => {
                idx += 1;
            }
            _ if lower.starts_with('-') => {
                idx += 1;
            }
            _ => {
                let rest = args[idx..].to_vec();
                return Some(ParsedPowershell {
                    tokens: rest,
                    script: None,
                });
            }
        }
    }

    None
}

fn is_no_profile_command_envelope(args: &[String]) -> bool {
    let Some(command_index) = args.len().checked_sub(2) else {
        return false;
    };
    let mut has_no_profile = false;
    let mut has_non_interactive = false;
    for arg in &args[..command_index] {
        if arg.eq_ignore_ascii_case("-NoProfile") && !has_no_profile {
            has_no_profile = true;
        } else if arg.eq_ignore_ascii_case("-NonInteractive") && !has_non_interactive {
            has_non_interactive = true;
        } else {
            return false;
        }
    }
    has_no_profile
        && (args[command_index].eq_ignore_ascii_case("-Command")
            || args[command_index].eq_ignore_ascii_case("-c"))
}

#[cfg(test)]
mod tests {
    use super::is_dangerous_command_windows;

    fn vec_str(items: &[&str]) -> Vec<String> {
        items.iter().map(std::string::ToString::to_string).collect()
    }

    #[test]
    fn powershell_start_process_url_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-NoLogo",
            "-Command",
            "Start-Process 'https://example.com'"
        ])));
    }

    #[test]
    fn powershell_start_process_url_with_trailing_semicolon_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Start-Process('https://example.com');"
        ])));
    }

    #[test]
    fn powershell_start_process_mixed_case_urls_are_dangerous() {
        for script in [
            "Start-Process('HTTP://example.com');",
            "Start-Process('hTtPs://example.com');",
        ] {
            assert!(
                is_dangerous_command_windows(&vec_str(&["powershell", "-Command", script])),
                "{script}"
            );
        }
    }

    #[test]
    fn powershell_start_process_local_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Start-Process notepad.exe"
        ])));
    }

    #[test]
    fn powershell_no_profile_inert_diagnostic_with_direct_shell_execute_read_is_not_dangerous() {
        let script = "$diagnostic = [System.Diagnostics.ProcessStartInfo]::new()\n\
            $diagnostic.UseShellExecute = $false\n\
            $diagnostic.Arguments = 'https://example.com'\n\
            $diagnostic.UseShellExecute";
        for flags in [
            &["-NonInteractive", "-NoProfile", "-Command"][..],
            &["-NoProfile", "-c"][..],
        ] {
            let command = [vec_str(&["powershell"]), vec_str(flags), vec_str(&[script])].concat();
            assert!(
                !is_dangerous_command_windows(&command),
                "{command:?} should be non-dangerous"
            );
        }
    }

    #[test]
    fn powershell_diagnostic_requires_full_no_profile_and_no_commands() {
        let assignments = "$diagnostic = [System.Diagnostics.ProcessStartInfo]::new()\n\
            $diagnostic.UseShellExecute = $false\n\
            $diagnostic.Arguments = 'https://example.com'";
        for (flags, final_statement) in [
            (&["-Command"][..], "$diagnostic.UseShellExecute"),
            (
                &["-Command"][..],
                "Write-Output 'Diagnostic only: no process was started and no network request was made.'",
            ),
            (
                &["-NoProfile", "-Command"][..],
                "Write-Output 'Diagnostic only: no process was started and no network request was made.'",
            ),
            (
                &["-NoProfile", "-Command"][..],
                "Microsoft.PowerShell.Utility\\Write-Output 'Diagnostic only: no process was started and no network request was made.'",
            ),
            (
                &["-NoP", "-Command"][..],
                "Write-Output 'Diagnostic only: no process was started and no network request was made.'",
            ),
        ] {
            let script = format!("{assignments}\n{final_statement}");
            let command = [vec_str(&["pwsh"]), vec_str(flags), vec_str(&[&script])].concat();
            assert!(
                is_dangerous_command_windows(&command),
                "{command:?} should remain dangerous"
            );
        }
    }

    #[test]
    fn powershell_no_profile_diagnostic_rejects_other_startup_options() {
        let script = "$diagnostic = [System.Diagnostics.ProcessStartInfo]::new()\n\
            $diagnostic.UseShellExecute = $false\n\
            $diagnostic.Arguments = 'https://example.com'\n\
            $diagnostic.UseShellExecute";
        for flags in [
            &["-NoProfile", "-NoLogo", "-Command"][..],
            &["-NoProfile", "-ExecutionPolicy", "Bypass", "-Command"][..],
        ] {
            let command = [vec_str(&["pwsh"]), vec_str(flags), vec_str(&[script])].concat();
            assert!(
                is_dangerous_command_windows(&command),
                "{command:?} should remain dangerous"
            );
        }
    }

    #[test]
    fn powershell_no_profile_diagnostic_rejects_dotted_constructor() {
        let script = "$diagnostic = [System.Diagnostics.ProcessStartInfo].new()\n\
            $diagnostic.UseShellExecute = $false\n\
            $diagnostic.Arguments = 'https://example.com'\n\
            $diagnostic.UseShellExecute";
        assert!(is_dangerous_command_windows(&vec_str(&[
            "pwsh",
            "-NoProfile",
            "-Command",
            script,
        ])));
    }

    #[test]
    fn powershell_unused_url_diagnostic_with_dynamic_execution_remains_dangerous() {
        let diagnostic = "$diagnostic = [System.Diagnostics.ProcessStartInfo]::new()\n\
            $diagnostic.UseShellExecute = $false\n\
            $diagnostic.Arguments = 'https://example.com'\n\
            Write-Output 'Diagnostic only: no process was started and no network request was made.'";
        for suffix in [
            "& ('Start-' + 'Process') 'https://example.com'",
            ". $scriptPath 'https://example.com'",
            "Set-Alias -Name go -Value ('Start-' + 'Process'); go 'https://example.com'",
            "New-Alias -Name go -Value ('Start-' + 'Process'); go 'https://example.com'",
            "Invoke-Expression ('Start-' + 'Process https://example.com')",
            "iex ('Start-' + 'Process https://example.com')",
        ] {
            let script = format!("{diagnostic}\n{suffix}");
            assert!(
                is_dangerous_command_windows(&vec_str(&["pwsh", "-Command", &script])),
                "{script}"
            );
        }
    }

    #[test]
    fn powershell_call_operator_after_false_assignment_remains_dangerous() {
        let script = "$p.UseShellExecute = $false; $cmd = 'Start-' + 'Process'; & $cmd 'https://example.com'";
        assert!(
            is_dangerous_command_windows(&vec_str(&["pwsh", "-Command", script])),
            "{script}"
        );
    }

    #[test]
    fn powershell_dot_source_after_false_assignment_remains_dangerous() {
        let script = "$p.UseShellExecute = $false; . $scriptPath 'https://example.com'";
        assert!(
            is_dangerous_command_windows(&vec_str(&["pwsh", "-Command", script])),
            "{script}"
        );
    }

    #[test]
    fn powershell_alias_rebinding_after_false_assignment_remains_dangerous() {
        let script = "$p.UseShellExecute=$false; Set-Alias -Name go -Value ('Start-' + 'Process'); go 'https://example.com'";
        assert!(
            is_dangerous_command_windows(&vec_str(&["pwsh", "-Command", script])),
            "{script}"
        );
    }

    #[test]
    fn powershell_dynamic_expression_after_false_assignment_remains_dangerous() {
        for command in ["Invoke-Expression", "iex"] {
            let script = format!(
                "$p.UseShellExecute=$false; $expr='Start-'+'Process https://example.com'; {command} $expr"
            );
            assert!(
                is_dangerous_command_windows(&vec_str(&["pwsh", "-Command", &script])),
                "{script}"
            );
        }
    }

    #[test]
    fn powershell_literal_false_shell_execute_preserves_dangerous_cases() {
        for script in [
            "$p.UseShellExecute=$false; Start-Process 'https://example.com'",
            "$p.UseShellExecute=$false; Invoke-Item 'https://example.com'",
            "$p.UseShellExecute=$false; $p.FileName='https://example.com'; [Diagnostics.Process]::Start($p)",
            "$p.UseShellExecute=$false; $shell.ShellExecute('https://example.com')",
            "$p.UseShellExecute=$enabled; $url='https://example.com'",
            "$p.UseShellExecute=$false; $url='https://example.com'; if (",
            "$p.UseShellExecute=$false; $url='https://example.com'; Remove-Item test -Force",
        ] {
            assert!(
                is_dangerous_command_windows(&vec_str(&["pwsh", "-Command", script])),
                "{script}"
            );
        }
    }

    #[test]
    fn cmd_start_with_url_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "start",
            "https://example.com"
        ])));
    }

    #[test]
    fn msedge_with_url_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "msedge.exe",
            "https://example.com"
        ])));
    }

    #[test]
    fn explorer_with_directory_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "explorer.exe",
            "."
        ])));
    }

    // Force delete tests for PowerShell

    #[test]
    fn powershell_remove_item_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Remove-Item test -Force"
        ])));
    }

    #[test]
    fn powershell_remove_item_recurse_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Remove-Item test -Recurse -Force"
        ])));
    }

    #[test]
    fn powershell_ri_alias_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "pwsh",
            "-Command",
            "ri test -Force"
        ])));
    }

    #[test]
    fn powershell_remove_item_without_force_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Remove-Item test"
        ])));
    }

    // Force delete tests for CMD
    #[test]
    fn cmd_del_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "del", "/f", "test.txt"
        ])));
    }

    #[test]
    fn cmd_erase_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "erase", "/f", "test.txt"
        ])));
    }

    #[test]
    fn cmd_del_without_force_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "del", "test.txt"
        ])));
    }

    #[test]
    fn cmd_rd_recursive_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "rd", "/s", "/q", "test"
        ])));
    }

    #[test]
    fn cmd_rd_without_quiet_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "rd", "/s", "test"
        ])));
    }

    #[test]
    fn cmd_rmdir_recursive_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "rmdir", "/s", "/q", "test"
        ])));
    }

    // Test exact scenario from issue #8567
    #[test]
    fn powershell_remove_item_path_recurse_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Remove-Item -Path 'test' -Recurse -Force"
        ])));
    }

    #[test]
    fn powershell_remove_item_force_with_semicolon_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Remove-Item test -Force; Write-Host done"
        ])));
    }

    #[test]
    fn powershell_remove_item_force_inside_block_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "if ($true) { Remove-Item test -Force}"
        ])));
    }

    #[test]
    fn powershell_remove_item_force_inside_brackets_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "[void]( Remove-Item test -Force)]"
        ])));
    }

    #[test]
    fn cmd_del_path_containing_f_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "del",
            "C:/foo/bar.txt"
        ])));
    }

    #[test]
    fn cmd_rd_path_containing_s_is_not_flagged() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "rd",
            "C:/source"
        ])));
    }

    #[test]
    fn cmd_bypass_chained_del_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "echo", "hello", "&", "del", "/f", "file.txt"
        ])));
    }

    #[test]
    fn powershell_chained_no_space_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Write-Host hi;Remove-Item -Force C:\\tmp"
        ])));
    }

    #[test]
    fn powershell_comma_separated_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "del,-Force,C:\\foo"
        ])));
    }

    #[test]
    fn cmd_echo_del_is_not_dangerous() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "echo", "del", "/f"
        ])));
    }

    #[test]
    fn cmd_del_single_string_argument_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "del /f file.txt"
        ])));
    }

    #[test]
    fn cmd_del_chained_single_string_argument_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "echo hello & del /f file.txt"
        ])));
    }

    #[test]
    fn cmd_chained_no_space_del_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "echo hi&del /f file.txt"
        ])));
    }

    #[test]
    fn cmd_chained_andand_no_space_del_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "echo hi&&del /f file.txt"
        ])));
    }

    #[test]
    fn cmd_chained_oror_no_space_del_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "echo hi||del /f file.txt"
        ])));
    }

    #[test]
    fn cmd_start_url_single_string_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "start https://example.com"
        ])));
    }

    #[test]
    fn cmd_chained_no_space_rmdir_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            "echo hi&rmdir /s /q testdir"
        ])));
    }

    #[test]
    fn cmd_del_force_uppercase_flag_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd", "/c", "DEL", "/F", "file.txt"
        ])));
    }

    #[test]
    fn cmdexe_r_del_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd.exe", "/r", "del", "/f", "file.txt"
        ])));
    }

    #[test]
    fn cmd_start_quoted_url_single_string_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            r#"start "https://example.com""#
        ])));
    }

    #[test]
    fn cmd_start_title_then_url_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "cmd",
            "/c",
            r#"start "" https://example.com"#
        ])));
    }

    #[test]
    fn powershell_rm_alias_force_is_dangerous() {
        assert!(is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "rm test -Force"
        ])));
    }

    #[test]
    fn powershell_benign_force_separate_command_is_not_dangerous() {
        assert!(!is_dangerous_command_windows(&vec_str(&[
            "powershell",
            "-Command",
            "Get-ChildItem -Force; Remove-Item test"
        ])));
    }
}
