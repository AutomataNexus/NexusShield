# NexusShield Threat Pattern Reference

Complete reference of all threat patterns detected by the NexusShield SQL firewall. All detection is performed at the **AST level** using the `sqlparser` crate -- not regex. Queries are parsed into an Abstract Syntax Tree and walked recursively to detect injection patterns semantically.

---

## How AST-Level Detection Works

NexusShield parses every SQL query into an Abstract Syntax Tree using `sqlparser`'s `GenericDialect` parser. If the query fails to parse, it is immediately flagged as `Unparseable` with a risk score of 1.0. For parseable queries, NexusShield walks the entire AST recursively, inspecting every node for security-relevant patterns.

### AST Nodes Inspected

| AST Node | What Is Checked |
|----------|----------------|
| `Statement` | Only `Query` (SELECT) statements allowed. All others (INSERT, UPDATE, DELETE, DROP, ALTER, TRUNCATE, GRANT, REVOKE) blocked. |
| `SetExpr::SetOperation` | UNION operations detected when `op = SetOperator::Union` |
| `SetExpr::Select` | INTO clause, FROM tables, projection expressions, WHERE, HAVING |
| `TableFactor::Table` | Table/schema names checked against system schemas list |
| `TableFactor::Derived` | Subqueries recursively analyzed |
| `TableFactor::NestedJoin` | Join targets recursively checked |
| `Expr::Function` | Function name checked against dangerous functions list |
| `Expr::BinaryOp` | Tautology detection (equality + OR always-true) |
| `Expr::Subquery` | Recursive depth tracking + analysis |
| `Expr::InSubquery` | Both expression and subquery analyzed |
| `Expr::Exists` | Subquery analyzed |
| `Expr::Between` | All three expressions analyzed |
| `Expr::Case` | Operand, conditions, results, else analyzed |
| `Expr::Cast` | Inner expression analyzed |
| `Expr::Nested` | Inner expression analyzed |
| `Expr::UnaryOp` | Inner expression analyzed |

### Pre-Parse String Checks

Before AST parsing, the raw SQL string is checked for patterns that may not appear in the AST:

1. **Comment injection** -- `/*` block comments and `--` line comments (respecting quoted strings)
2. **Hex-encoded payloads** -- `0x` combined with SQL keywords (`select`, `union`, `insert`, `update`, `delete`, `drop`, `exec`)
3. **CHAR()/CHR() bypass** -- `char(`, `chr(`, or `concat(` combined with `union`, `select`, or `from`
4. **INTO OUTFILE/DUMPFILE** -- `into outfile` or `into dumpfile` (case-insensitive)

### Risk Score Calculation

Risk scores from individual violations are summed and capped at 1.0. A query is **allowed** only when:

1. There are **zero violations**, AND
2. The cumulative risk score is **below 0.5**

If either condition fails, the query is blocked.

---

## Detection Categories

### 1. Non-SELECT Statements

**Violation:** `NonSelectStatement`
**Risk Score:** +1.0
**Detection:** Any `Statement` variant other than `Statement::Query`

| Blocked Statement | AST Variant | Example |
|-------------------|-------------|---------|
| INSERT | `Statement::Insert` | `INSERT INTO admin VALUES ('hacker')` |
| UPDATE | `Statement::Update` | `UPDATE users SET role = 'admin'` |
| DELETE | `Statement::Delete` | `DELETE FROM audit_log` |
| DROP | `Statement::Drop` | `DROP TABLE users` |
| CREATE TABLE | `Statement::CreateTable` | `CREATE TABLE backdoor (...)` |
| ALTER TABLE | `Statement::AlterTable` | `ALTER TABLE users ADD COLUMN pwned TEXT` |
| TRUNCATE | `Statement::Truncate` | `TRUNCATE TABLE sessions` |
| GRANT | `Statement::Grant` | `GRANT ALL ON *.* TO 'root'` |
| REVOKE | `Statement::Revoke` | `REVOKE SELECT ON users FROM 'app'` |
| All others | Catch-all | Any non-SELECT statement |

---

### 2. Stacked Queries

**Violation:** `StackedQueries(count)`
**Risk Score:** +0.8
**Detection:** `Parser::parse_sql()` returns more than 1 statement

Stacked queries (piggyback injection) append a destructive statement after the original query using a semicolon delimiter.

**Examples:**

```sql
SELECT * FROM sensors; DROP TABLE users
SELECT 1; INSERT INTO admin VALUES ('hacker', 'password')
SELECT * FROM data; UPDATE users SET admin = true; DELETE FROM logs
```

---

### 3. UNION Injection

**Violation:** `UnionInjection`
**Risk Score:** +0.6
**Detection:** `SetExpr::SetOperation` with `op = SetOperator::Union`

UNION-based injection appends a second SELECT to extract data from a different table. Detected at the AST level in the `SetExpr` node, catching both `UNION` and `UNION ALL`.

**Examples:**

```sql
SELECT name FROM sensors UNION SELECT password FROM users
SELECT id, email FROM customers UNION ALL SELECT 1, credit_card FROM payments
```

---

### 4. Dangerous Function Calls

**Violation:** `DangerousFunction(name)`
**Risk Score:** +0.8
**Detection:** `Expr::Function` nodes where the last identifier in the function name matches the dangerous functions list (case-insensitive)

#### Complete Dangerous Functions List (30+)

**MySQL File Operations:**

| Function | Purpose |
|----------|---------|
| `load_file` | Read arbitrary files from the server filesystem |
| `into_outfile` | Write query results to a file on the server |
| `into_dumpfile` | Write binary data to a file on the server |

**PostgreSQL File Operations:**

| Function | Purpose |
|----------|---------|
| `pg_read_file` | Read server files as text |
| `pg_read_binary_file` | Read server files as binary |
| `pg_ls_dir` | List directory contents on the server |
| `pg_stat_file` | Get file metadata (size, timestamps) |
| `lo_import` | Import a file into a PostgreSQL large object |
| `lo_export` | Export a large object to a file on the server |
| `pg_file_write` | Write data to a file on the server |

**PostgreSQL Command Execution:**

| Function | Purpose |
|----------|---------|
| `pg_execute_server_program` | Execute an OS command on the PostgreSQL server |

**SQL Server Command Execution:**

| Function | Purpose |
|----------|---------|
| `xp_cmdshell` | Execute arbitrary OS commands on MSSQL server |
| `sp_oacreate` | Create OLE Automation objects for command execution |
| `sp_oamethod` | Call methods on OLE Automation objects |

**MySQL User-Defined Functions:**

| Function | Purpose |
|----------|---------|
| `sys_exec` | Execute system commands via MySQL UDF |
| `sys_eval` | Evaluate system commands and return output via UDF |

**Time-Based Blind Injection:**

| Function | Database | Purpose |
|----------|----------|---------|
| `sleep` | MySQL | Delay response by N seconds |
| `benchmark` | MySQL | CPU-intensive operation for timing side-channel |
| `waitfor` | SQL Server | Delay execution for timing attacks |
| `pg_sleep` | PostgreSQL | Delay response by N seconds |

**XML Injection:**

| Function | Purpose |
|----------|---------|
| `extractvalue` | Extract data via XPath expression (MySQL error-based injection) |
| `updatexml` | Modify XML and extract data through error messages (MySQL) |

**SQLite:**

| Function | Purpose |
|----------|---------|
| `load_extension` | Load a shared library into SQLite (code execution) |

**Example attacks:**

```sql
-- File read
SELECT LOAD_FILE('/etc/passwd') FROM dual
SELECT pg_read_file('/etc/shadow')

-- Command execution
EXEC xp_cmdshell 'whoami'
SELECT pg_execute_server_program('id')

-- Time-based blind
SELECT * FROM sensors WHERE id = 1 AND SLEEP(5)
SELECT * FROM users WHERE id = 1 AND pg_sleep(10)
SELECT BENCHMARK(10000000, SHA1('test'))

-- Error-based extraction
SELECT EXTRACTVALUE(1, CONCAT(0x7e, (SELECT user())))
SELECT UPDATEXML(1, CONCAT(0x7e, version()), 1)
```

---

### 5. System Table / Schema Access

**Violation:** `SystemTableAccess(name)`
**Risk Score:** +0.7
**Detection:** `TableFactor::Table` identifiers matched (case-insensitive) against the system schemas list

#### Complete System Schemas List

| Schema | Database(s) | Purpose |
|--------|-------------|---------|
| `information_schema` | MySQL, PostgreSQL, SQL Server | Standard SQL metadata catalog (tables, columns, constraints) |
| `pg_catalog` | PostgreSQL | PostgreSQL system catalog |
| `pg_temp` | PostgreSQL | Temporary table schema |
| `pg_toast` | PostgreSQL | TOAST (oversized attribute storage) schema |
| `sys` | SQL Server | SQL Server system views |
| `mysql` | MySQL | MySQL system database (users, grants) |
| `performance_schema` | MySQL | MySQL performance metrics |
| `sqlite_master` | SQLite | SQLite schema table |
| `sqlite_schema` | SQLite | SQLite schema table (alias) |
| `sqlite_temp_master` | SQLite | SQLite temporary object schema |
| `master` | SQL Server | MSSQL master database |
| `tempdb` | SQL Server | MSSQL temporary database |
| `msdb` | SQL Server | MSSQL agent/job database |
| `model` | SQL Server | MSSQL template database |

**Example attacks:**

```sql
SELECT * FROM information_schema.tables
SELECT * FROM information_schema.columns WHERE table_name = 'users'
SELECT tablename FROM pg_catalog.pg_tables
SELECT name FROM sqlite_master WHERE type = 'table'
SELECT * FROM mysql.user
SELECT * FROM sys.objects WHERE type = 'U'
```

---

### 6. Tautology Detection

**Violation:** `Tautology(description)`
**Risk Score:** +0.5
**Detection:** Recursive analysis of `BinaryOp` expressions in WHERE clauses

#### Literal Equality Tautology

Detected when a `BinaryOp::Eq` has both operands as literals (`Expr::Value` or `Expr::UnaryOp`) and their string representations are identical.

```sql
-- Detected:
WHERE id = 1 OR 1 = 1
WHERE name = 'admin' OR 'a' = 'a'
WHERE 1 = 1
```

#### OR Always-True

Detected when a `BinaryOp::Or` has either operand that evaluates to always-true via the `is_always_true()` function.

The `is_always_true()` function recognizes:
- `Expr::Value(Boolean(true))` -- literal TRUE
- `Expr::Value(Number("1", _))` -- literal 1
- `BinaryOp::Eq` with identical literal operands -- e.g., `1 = 1`
- `Expr::Nested(inner)` -- parenthesized always-true expression

```sql
-- Detected:
WHERE id = 5 OR TRUE
WHERE name = 'x' OR 1 = 1
WHERE active = false OR (1 = 1)
```

#### Recursive Detection

Tautology checks recurse into both sides of `BinaryOp` expressions and into `Nested` expressions. This catches tautologies buried inside complex WHERE clauses:

```sql
-- Detected (tautology inside nested condition):
WHERE (status = 'active' AND (id = 1 OR 1 = 1))
```

---

### 7. INTO OUTFILE / DUMPFILE

**Violation:** `IntoOutfile`
**Risk Score:** +1.0 (maximum)
**Detection:** Two methods:

1. **Pre-parse string scan:** Case-insensitive check for `"into outfile"` or `"into dumpfile"` in the raw SQL string
2. **AST check:** `Select.into.is_some()` detects `SELECT INTO` constructs

```sql
-- Blocked:
SELECT * FROM sensors INTO OUTFILE '/tmp/dump.csv'
SELECT * FROM users INTO DUMPFILE '/var/www/shell.php'
SELECT 'malicious code' INTO OUTFILE '/var/www/html/backdoor.php'
```

---

### 8. Comment Injection

**Violation:** `CommentInjection`
**Risk Score:** +0.3
**Detection:** Pre-parse scan (only when `allow_comments = false`)

- **Block comments:** Presence of `/*` in the SQL string
- **Line comments:** Presence of `--` outside single-quoted strings (tracked by a state machine that toggles on unescaped `'` characters)

```sql
-- Blocked:
SELECT * FROM sensors WHERE id = 1 /* AND is_admin = 1 */
SELECT * FROM users WHERE name = 'admin' -- AND password = 'check'
SELECT * FROM data WHERE 1=1/**/UNION/**/SELECT/**/password/**/FROM/**/users
```

---

### 9. Hex-Encoded Payloads

**Violation:** `HexEncodedPayload`
**Risk Score:** +0.4
**Detection:** Pre-parse scan for `0x` combined with any SQL keyword

Keywords checked: `select`, `union`, `insert`, `update`, `delete`, `drop`, `exec`

```sql
-- Blocked:
SELECT * FROM users WHERE name = 0x61646D696E UNION SELECT 1
SELECT 0x41414141 FROM dual
```

---

### 10. CHAR() / CHR() Encoding Bypass

**Violation:** `CharEncoding`
**Risk Score:** +0.3
**Detection:** Pre-parse scan for `char(`, `chr(`, or `concat(` combined with `union`, `select`, or `from`

Only flagged when encoding functions appear alongside SQL keywords, reducing false positives from legitimate use of CHAR() in non-injection contexts.

```sql
-- Blocked:
SELECT * FROM users WHERE name = CHAR(97,100,109,105,110) UNION SELECT 1
SELECT CONCAT(CHAR(83),CHAR(69),CHAR(76)) FROM dual
```

---

### 11. Query Too Long

**Violation:** `QueryTooLong(length)`
**Risk Score:** +0.5
**Detection:** `sql.len() > config.max_query_length`
**Default threshold:** 10,000 bytes

Excessively long queries may indicate buffer overflow attempts, obfuscated injection payloads, or data exfiltration.

---

### 12. Excessive Nesting

**Violation:** `ExcessiveNesting(depth)`
**Risk Score:** +0.4
**Detection:** Subquery depth counter exceeds `config.max_subquery_depth` during recursive AST walk
**Default threshold:** 3 levels

Deep nesting is used to hide injection payloads inside subqueries that simpler scanners cannot reach.

```sql
-- Blocked at depth > 3:
SELECT * FROM (
  SELECT * FROM (
    SELECT * FROM (
      SELECT * FROM (
        SELECT password FROM admin
      )
    )
  )
)
```

---

### 13. Unparseable Queries

**Violation:** `Unparseable(error_message)`
**Risk Score:** 1.0 (maximum)
**Detection:** `Parser::parse_sql()` returns `Err`

Queries that cannot be parsed as valid SQL are treated as maximally suspicious. This catches:
- Deliberately malformed SQL designed to confuse parsers
- Binary or encoded payloads injected into SQL fields
- Truncated queries from failed injection attempts
- Non-SQL content submitted to SQL endpoints

An empty query (zero statements parsed) is also treated as unparseable.

---

## Configurable Extensions

### Additional Blocked Functions

The built-in dangerous functions list can be extended:

```rust
let mut config = SqlFirewallConfig::default();
config.blocked_functions.push("dbms_pipe".to_string());
config.blocked_functions.push("utl_http".to_string());
config.blocked_functions.push("dbms_java".to_string());
```

Additional functions are checked via case-insensitive string matching on the lowercased query text (not AST-level), adding +0.6 risk score per match.

### Additional Blocked Schemas

```rust
config.blocked_schemas.push("dba_users".to_string());
config.blocked_schemas.push("v$session".to_string());
```

Additional schemas are also checked via string matching, adding +0.6 risk score per match.

---

## Risk Score Summary Table

| Violation | Risk Score | Detection Level |
|-----------|-----------|----------------|
| `NonSelectStatement` | +1.0 | AST (Statement type) |
| `StackedQueries` | +0.8 | AST (Statement count) |
| `UnionInjection` | +0.6 | AST (SetOperation node) |
| `DangerousFunction` | +0.8 | AST (Function node) |
| `SystemTableAccess` | +0.7 | AST (TableFactor node) |
| `Tautology` | +0.5 | AST (BinaryOp analysis) |
| `IntoOutfile` | +1.0 | Pre-parse + AST |
| `CommentInjection` | +0.3 | Pre-parse (string scan) |
| `HexEncodedPayload` | +0.4 | Pre-parse (string scan) |
| `CharEncoding` | +0.3 | Pre-parse (string scan) |
| `QueryTooLong` | +0.5 | Pre-parse (length check) |
| `ExcessiveNesting` | +0.4 | AST (depth counter) |
| `Unparseable` | 1.0 | Parser error |
| Additional blocked function | +0.6 | String match |
| Additional blocked schema | +0.6 | String match |
