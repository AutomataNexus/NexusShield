// ============================================================================
// File: sql_firewall.rs
// Description: AST-level SQL injection detection using sqlparser semantic analysis
// Author: Andrew Jewell Sr. - AutomataNexus
// Updated: March 24, 2026
//
// DISCLAIMER: This software is provided "as is", without warranty of any kind,
// express or implied. Use at your own risk. AutomataNexus and the author assume
// no liability for any damages arising from the use of this software.
// ============================================================================
//! SQL Firewall — AST-level SQL injection detection.
//!
//! Unlike regex-based approaches, this module parses SQL into an Abstract Syntax Tree
//! using `sqlparser` and performs semantic analysis to detect injection patterns,
//! dangerous functions, system table access, and tautology-based attacks.

use crate::config::SqlFirewallConfig;
use sqlparser::ast::*;
use sqlparser::dialect::GenericDialect;
use sqlparser::parser::Parser;

/// Result of analyzing a SQL query for security threats.
#[derive(Debug)]
pub struct SqlAnalysis {
    /// Whether the query is considered safe to execute.
    pub allowed: bool,
    /// Risk score from 0.0 (safe) to 1.0 (definitely malicious).
    pub risk_score: f64,
    /// Specific violations detected.
    pub violations: Vec<SqlViolation>,
}

#[derive(Debug, Clone)]
pub enum SqlViolation {
    /// Statement is not SELECT (INSERT, UPDATE, DELETE, DROP, etc.)
    NonSelectStatement(String),
    /// Multiple statements separated by semicolons.
    StackedQueries(usize),
    /// Dangerous function call (LOAD_FILE, xp_cmdshell, etc.)
    DangerousFunction(String),
    /// Access to system catalog tables (information_schema, pg_catalog, etc.)
    SystemTableAccess(String),
    /// Always-true condition suggesting injection (1=1, 'a'='a', OR TRUE).
    Tautology(String),
    /// UNION-based injection pattern.
    UnionInjection,
    /// SELECT INTO / INTO OUTFILE / INTO DUMPFILE.
    IntoOutfile,
    /// SQL comments that may be used to bypass filters.
    CommentInjection,
    /// Hex-encoded payload with SQL keywords.
    HexEncodedPayload,
    /// CHAR()/CHR() encoding to bypass string filters.
    CharEncoding,
    /// Query exceeds maximum allowed length.
    QueryTooLong(usize),
    /// Subquery nesting exceeds maximum depth.
    ExcessiveNesting(u32),
    /// Query could not be parsed (suspicious).
    Unparseable(String),
}

/// Dangerous SQL functions that indicate exploitation attempts.
const DANGEROUS_FUNCTIONS: &[&str] = &[
    // MySQL file operations
    "load_file",
    "into_outfile",
    "into_dumpfile",
    // PostgreSQL file operations
    "pg_read_file",
    "pg_read_binary_file",
    "pg_ls_dir",
    "pg_stat_file",
    "lo_import",
    "lo_export",
    "pg_file_write",
    // PostgreSQL command execution
    "pg_execute_server_program",
    // SQL Server command execution
    "xp_cmdshell",
    "sp_oacreate",
    "sp_oamethod",
    // MySQL UDF
    "sys_exec",
    "sys_eval",
    // Time-based blind injection
    "sleep",
    "benchmark",
    "waitfor",
    "pg_sleep",
    // XML-based injection
    "extractvalue",
    "updatexml",
    // SQLite attach (can create/modify files)
    "load_extension",
];

/// System schemas/catalogs that should not be queried by external users.
const SYSTEM_SCHEMAS: &[&str] = &[
    "information_schema",
    "pg_catalog",
    "pg_temp",
    "pg_toast",
    "sys",
    "mysql",
    "performance_schema",
    "sqlite_master",
    "sqlite_schema",
    "sqlite_temp_master",
    "master",
    "tempdb",
    "msdb",
    "model",
];

/// Analyze a SQL query string for injection patterns and security threats.
pub fn analyze_query(sql: &str, config: &SqlFirewallConfig) -> SqlAnalysis {
    let mut violations = Vec::new();
    let mut risk_score: f64 = 0.0;

    // Pre-parse length check
    if sql.len() > config.max_query_length {
        violations.push(SqlViolation::QueryTooLong(sql.len()));
        risk_score += 0.5;
    }

    let lower = sql.to_lowercase();

    // Pre-parse: comment injection
    if !config.allow_comments && (lower.contains("/*") || contains_line_comment(&lower)) {
        violations.push(SqlViolation::CommentInjection);
        risk_score += 0.3;
    }

    // Pre-parse: hex-encoded payloads combined with SQL keywords
    if lower.contains("0x") && has_sql_keywords_near_hex(&lower) {
        violations.push(SqlViolation::HexEncodedPayload);
        risk_score += 0.4;
    }

    // Pre-parse: CHAR()/CHR() encoding bypass
    if lower.contains("char(") || lower.contains("chr(") || lower.contains("concat(") {
        // Only flag if combined with injection-like patterns
        if lower.contains("union") || lower.contains("select") || lower.contains("from") {
            violations.push(SqlViolation::CharEncoding);
            risk_score += 0.3;
        }
    }

    // Pre-parse: INTO OUTFILE / INTO DUMPFILE
    if lower.contains("into outfile") || lower.contains("into dumpfile") {
        violations.push(SqlViolation::IntoOutfile);
        risk_score += 1.0;
    }

    // Parse the SQL
    let dialect = GenericDialect {};
    let statements = match Parser::parse_sql(&dialect, sql) {
        Ok(stmts) => stmts,
        Err(e) => {
            violations.push(SqlViolation::Unparseable(e.to_string()));
            return SqlAnalysis {
                allowed: false,
                risk_score: 1.0,
                violations,
            };
        }
    };

    if statements.is_empty() {
        return SqlAnalysis {
            allowed: false,
            risk_score: 1.0,
            violations: vec![SqlViolation::Unparseable("Empty query".into())],
        };
    }

    // Stacked queries (multiple statements)
    if statements.len() > 1 {
        violations.push(SqlViolation::StackedQueries(statements.len()));
        risk_score += 0.8;
    }

    for stmt in &statements {
        match stmt {
            Statement::Query(query) => {
                let mut depth = 0;
                analyze_query_body(
                    &query.body,
                    config,
                    &mut violations,
                    &mut risk_score,
                    &mut depth,
                );
            }
            other => {
                let kind = format!("{}", statement_kind(other));
                violations.push(SqlViolation::NonSelectStatement(kind));
                risk_score += 1.0;
            }
        }
    }

    // Check additional blocked functions from config
    for func_name in &config.blocked_functions {
        if lower.contains(&func_name.to_lowercase()) {
            violations.push(SqlViolation::DangerousFunction(func_name.clone()));
            risk_score += 0.6;
        }
    }

    // Check additional blocked schemas from config
    for schema_name in &config.blocked_schemas {
        if lower.contains(&schema_name.to_lowercase()) {
            violations.push(SqlViolation::SystemTableAccess(schema_name.clone()));
            risk_score += 0.6;
        }
    }

    SqlAnalysis {
        allowed: violations.is_empty() && risk_score < 0.5,
        risk_score: risk_score.min(1.0),
        violations,
    }
}

fn analyze_query_body(
    body: &SetExpr,
    config: &SqlFirewallConfig,
    violations: &mut Vec<SqlViolation>,
    risk_score: &mut f64,
    depth: &mut u32,
) {
    *depth += 1;
    if *depth > config.max_subquery_depth {
        violations.push(SqlViolation::ExcessiveNesting(*depth));
        *risk_score += 0.4;
        return;
    }

    match body {
        SetExpr::Select(select) => {
            analyze_select(select, config, violations, risk_score, depth);
        }
        SetExpr::SetOperation {
            op, left, right, ..
        } => {
            if matches!(op, SetOperator::Union) {
                violations.push(SqlViolation::UnionInjection);
                *risk_score += 0.6;
            }
            analyze_query_body(left, config, violations, risk_score, depth);
            analyze_query_body(right, config, violations, risk_score, depth);
        }
        SetExpr::Query(query) => {
            analyze_query_body(&query.body, config, violations, risk_score, depth);
        }
        _ => {}
    }
}

fn analyze_select(
    select: &Select,
    config: &SqlFirewallConfig,
    violations: &mut Vec<SqlViolation>,
    risk_score: &mut f64,
    depth: &mut u32,
) {
    // Check SELECT INTO
    if select.into.is_some() {
        violations.push(SqlViolation::IntoOutfile);
        *risk_score += 1.0;
    }

    // Check FROM clauses for system tables
    for table in &select.from {
        check_table_factor(&table.relation, violations, risk_score);
        for join in &table.joins {
            check_table_factor(&join.relation, violations, risk_score);
        }
    }

    // Check SELECT projection for dangerous functions
    for item in &select.projection {
        match item {
            SelectItem::UnnamedExpr(expr) | SelectItem::ExprWithAlias { expr, .. } => {
                walk_expr(expr, config, violations, risk_score, depth);
            }
            _ => {}
        }
    }

    // Check WHERE clause for tautologies and dangerous functions
    if let Some(ref where_clause) = select.selection {
        check_for_tautologies(where_clause, violations, risk_score);
        walk_expr(where_clause, config, violations, risk_score, depth);
    }

    // Check HAVING clause
    if let Some(ref having) = select.having {
        walk_expr(having, config, violations, risk_score, depth);
    }
}

fn check_table_factor(tf: &TableFactor, violations: &mut Vec<SqlViolation>, risk_score: &mut f64) {
    match tf {
        TableFactor::Table { name, .. } => {
            for ident in &name.0 {
                let lower = ident.value.to_lowercase();
                for sys_schema in SYSTEM_SCHEMAS {
                    if lower == *sys_schema {
                        violations.push(SqlViolation::SystemTableAccess(lower.clone()));
                        *risk_score += 0.7;
                    }
                }
            }
        }
        TableFactor::Derived { subquery, .. } => {
            let mut depth = 1;
            analyze_query_body(
                &subquery.body,
                &SqlFirewallConfig::default(),
                violations,
                risk_score,
                &mut depth,
            );
        }
        TableFactor::NestedJoin {
            table_with_joins, ..
        } => {
            check_table_factor(&table_with_joins.relation, violations, risk_score);
            for join in &table_with_joins.joins {
                check_table_factor(&join.relation, violations, risk_score);
            }
        }
        _ => {}
    }
}

/// Recursively walk an expression tree checking for dangerous functions and subqueries.
fn walk_expr(
    expr: &Expr,
    config: &SqlFirewallConfig,
    violations: &mut Vec<SqlViolation>,
    risk_score: &mut f64,
    depth: &mut u32,
) {
    match expr {
        Expr::Function(func) => {
            let func_name = func
                .name
                .0
                .last()
                .map(|i| i.value.to_lowercase())
                .unwrap_or_default();
            if DANGEROUS_FUNCTIONS.contains(&func_name.as_str()) {
                violations.push(SqlViolation::DangerousFunction(func_name));
                *risk_score += 0.8;
            }
        }
        Expr::BinaryOp { left, right, .. } => {
            walk_expr(left, config, violations, risk_score, depth);
            walk_expr(right, config, violations, risk_score, depth);
        }
        Expr::UnaryOp { expr: inner, .. } => {
            walk_expr(inner, config, violations, risk_score, depth);
        }
        Expr::Nested(inner) => {
            walk_expr(inner, config, violations, risk_score, depth);
        }
        Expr::Subquery(query) => {
            analyze_query_body(&query.body, config, violations, risk_score, depth);
        }
        Expr::InSubquery {
            expr: inner,
            subquery,
            ..
        } => {
            walk_expr(inner, config, violations, risk_score, depth);
            analyze_query_body(&subquery.body, config, violations, risk_score, depth);
        }
        Expr::Exists { subquery, .. } => {
            analyze_query_body(&subquery.body, config, violations, risk_score, depth);
        }
        Expr::Between {
            expr: inner,
            low,
            high,
            ..
        } => {
            walk_expr(inner, config, violations, risk_score, depth);
            walk_expr(low, config, violations, risk_score, depth);
            walk_expr(high, config, violations, risk_score, depth);
        }
        Expr::Case {
            operand,
            conditions,
            results,
            else_result,
        } => {
            if let Some(op) = operand {
                walk_expr(op, config, violations, risk_score, depth);
            }
            for cond in conditions {
                walk_expr(cond, config, violations, risk_score, depth);
            }
            for res in results {
                walk_expr(res, config, violations, risk_score, depth);
            }
            if let Some(el) = else_result {
                walk_expr(el, config, violations, risk_score, depth);
            }
        }
        Expr::Cast { expr: inner, .. } => {
            walk_expr(inner, config, violations, risk_score, depth);
        }
        _ => {}
    }
}

/// Detect tautology patterns indicating SQL injection (1=1, 'a'='a', OR TRUE).
fn check_for_tautologies(expr: &Expr, violations: &mut Vec<SqlViolation>, risk_score: &mut f64) {
    match expr {
        Expr::BinaryOp { left, op, right } => {
            if matches!(op, BinaryOperator::Eq) {
                // Literal = Literal tautology (1=1, 'a'='a')
                if is_literal(left) && is_literal(right) {
                    let left_str = format!("{left}");
                    let right_str = format!("{right}");
                    if left_str == right_str {
                        violations
                            .push(SqlViolation::Tautology(format!("{left_str} = {right_str}")));
                        *risk_score += 0.5;
                    }
                }
            }
            if matches!(op, BinaryOperator::Or) {
                if is_always_true(right) || is_always_true(left) {
                    violations.push(SqlViolation::Tautology("OR always-true".into()));
                    *risk_score += 0.5;
                }
            }
            // Recurse into both sides
            check_for_tautologies(left, violations, risk_score);
            check_for_tautologies(right, violations, risk_score);
        }
        Expr::Nested(inner) => {
            check_for_tautologies(inner, violations, risk_score);
        }
        _ => {}
    }
}

fn is_literal(expr: &Expr) -> bool {
    matches!(expr, Expr::Value(_) | Expr::UnaryOp { .. })
}

fn is_always_true(expr: &Expr) -> bool {
    match expr {
        Expr::Value(Value::Boolean(true)) => true,
        Expr::Value(Value::Number(n, _)) if n == "1" => true,
        Expr::BinaryOp {
            left,
            op: BinaryOperator::Eq,
            right,
        } => {
            let l = format!("{left}");
            let r = format!("{right}");
            l == r && is_literal(left) && is_literal(right)
        }
        Expr::Nested(inner) => is_always_true(inner),
        _ => false,
    }
}

fn contains_line_comment(s: &str) -> bool {
    // Match -- but not inside strings. Simple heuristic: check if -- appears
    // outside of quoted sections.
    let mut in_single_quote = false;
    let mut prev = ' ';
    for ch in s.chars() {
        if ch == '\'' && prev != '\\' {
            in_single_quote = !in_single_quote;
        }
        if !in_single_quote && ch == '-' && prev == '-' {
            return true;
        }
        prev = ch;
    }
    false
}

fn has_sql_keywords_near_hex(s: &str) -> bool {
    let keywords = [
        "select", "union", "insert", "update", "delete", "drop", "exec",
    ];
    let has_hex = s.contains("0x");
    has_hex && keywords.iter().any(|k| s.contains(k))
}

fn statement_kind(stmt: &Statement) -> &'static str {
    match stmt {
        Statement::Insert { .. } => "INSERT",
        Statement::Update { .. } => "UPDATE",
        Statement::Delete { .. } => "DELETE",
        Statement::Drop { .. } => "DROP",
        Statement::CreateTable { .. } => "CREATE TABLE",
        Statement::AlterTable { .. } => "ALTER TABLE",
        Statement::Truncate { .. } => "TRUNCATE",
        Statement::Grant { .. } => "GRANT",
        Statement::Revoke { .. } => "REVOKE",
        _ => "NON-SELECT",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> SqlFirewallConfig {
        SqlFirewallConfig::default()
    }

    #[test]
    fn allows_simple_select() {
        let result = analyze_query("SELECT * FROM sensors WHERE id = 1", &default_config());
        assert!(
            result.allowed,
            "Simple SELECT should be allowed: {:?}",
            result.violations
        );
    }

    #[test]
    fn allows_select_with_functions() {
        let result = analyze_query(
            "SELECT AVG(temperature), MAX(humidity) FROM readings WHERE timestamp > '2026-01-01'",
            &default_config(),
        );
        assert!(result.allowed);
    }

    #[test]
    fn blocks_drop_table() {
        let result = analyze_query("DROP TABLE users", &default_config());
        assert!(!result.allowed);
        assert!(
            result
                .violations
                .iter()
                .any(|v| matches!(v, SqlViolation::NonSelectStatement(_)))
        );
    }

    #[test]
    fn blocks_stacked_queries() {
        let result = analyze_query("SELECT * FROM sensors; DROP TABLE users", &default_config());
        assert!(!result.allowed);
        assert!(
            result
                .violations
                .iter()
                .any(|v| matches!(v, SqlViolation::StackedQueries(_)))
        );
    }

    #[test]
    fn blocks_union_injection() {
        let result = analyze_query(
            "SELECT name FROM sensors UNION SELECT password FROM users",
            &default_config(),
        );
        assert!(!result.allowed);
        assert!(
            result
                .violations
                .iter()
                .any(|v| matches!(v, SqlViolation::UnionInjection))
        );
    }

    #[test]
    fn blocks_tautology_injection() {
        let result = analyze_query(
            "SELECT * FROM sensors WHERE id = 1 OR 1 = 1",
            &default_config(),
        );
        assert!(!result.allowed);
        assert!(
            result
                .violations
                .iter()
                .any(|v| matches!(v, SqlViolation::Tautology(_)))
        );
    }

    #[test]
    fn blocks_information_schema() {
        let result = analyze_query("SELECT * FROM information_schema.tables", &default_config());
        assert!(!result.allowed);
        assert!(
            result
                .violations
                .iter()
                .any(|v| matches!(v, SqlViolation::SystemTableAccess(_)))
        );
    }

    #[test]
    fn blocks_dangerous_functions() {
        let result = analyze_query(
            "SELECT LOAD_FILE('/etc/passwd') FROM dual",
            &default_config(),
        );
        assert!(!result.allowed);
        assert!(
            result
                .violations
                .iter()
                .any(|v| matches!(v, SqlViolation::DangerousFunction(_)))
        );
    }

    #[test]
    fn blocks_sleep_based_blind() {
        let result = analyze_query(
            "SELECT * FROM sensors WHERE id = 1 AND SLEEP(5)",
            &default_config(),
        );
        assert!(!result.allowed);
        assert!(
            result
                .violations
                .iter()
                .any(|v| matches!(v, SqlViolation::DangerousFunction(f) if f == "sleep"))
        );
    }

    #[test]
    fn blocks_into_outfile() {
        let result = analyze_query(
            "SELECT * FROM sensors INTO OUTFILE '/tmp/dump.csv'",
            &default_config(),
        );
        assert!(!result.allowed);
    }

    #[test]
    fn blocks_comment_injection() {
        let result = analyze_query(
            "SELECT * FROM sensors WHERE id = 1 /* AND is_admin = 1 */",
            &default_config(),
        );
        assert!(!result.allowed);
        assert!(
            result
                .violations
                .iter()
                .any(|v| matches!(v, SqlViolation::CommentInjection))
        );
    }

    #[test]
    fn allows_legitimate_complex_query() {
        let result = analyze_query(
            "SELECT timestamp, supply_temp, return_temp, AVG(supply_temp) OVER (ORDER BY timestamp ROWS BETWEEN 10 PRECEDING AND CURRENT ROW) as moving_avg FROM sensor_readings WHERE location = 'Warren' AND unit = 'AHU-1' AND timestamp >= '2026-01-01' ORDER BY timestamp LIMIT 10000",
            &default_config(),
        );
        assert!(
            result.allowed,
            "Legitimate complex query should pass: {:?}",
            result.violations
        );
    }
}
