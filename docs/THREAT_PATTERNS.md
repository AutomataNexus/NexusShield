# NexusShield Threat Pattern Reference

Complete reference of all 38 SQL injection detection patterns used by the `SqlInjectionDetector`. Each pattern is a pre-compiled regex that runs against every SQL query submitted through the shield.

## How Scoring Works

When a query is analyzed, it is tested against all 38 patterns. Each matching pattern contributes its score. Scores are summed using saturating addition and then capped at 100. A query that matches multiple patterns will receive a higher combined score, reflecting the increased likelihood of malicious intent.

- **Score 0**: Clean query, no patterns matched
- **Score 1-39**: Low suspicion (Info/Low threat level)
- **Score 40-69**: Medium suspicion (Medium threat level)
- **Score 70-89**: High suspicion (High threat level)
- **Score 90-100**: Critical suspicion (Critical threat level)

---

## Pattern #1: `union_select`

**Category:** UNION / Subquery Injection
**Score:** 90
**Regex:** `(?i)\bUNION\s+(ALL\s+)?SELECT\b`
**Description:** UNION SELECT injection

**Example Malicious Input:**
```sql
SELECT name FROM users WHERE id=1 UNION SELECT password FROM admins
```

**Why It's Dangerous:** UNION SELECT injection allows an attacker to append an entirely new query result set to a legitimate query. This can expose data from any table in the database, including credentials, personal information, and system metadata. The attacker controls which columns and tables are read, enabling full data exfiltration.

---

## Pattern #2: `or_always_true`

**Category:** Tautology / Always-True Conditions
**Score:** 85
**Regex:** `(?i)\bOR\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?`
**Description:** OR always-true condition

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE username='admin' OR 1=1
```

**Why It's Dangerous:** Injecting `OR 1=1` (or any always-true condition) bypasses WHERE clause filtering entirely. Every row in the table is returned. This is the most common SQL injection pattern and is often the first technique an attacker tries. It can bypass authentication checks (`WHERE username='x' AND password='y' OR 1=1`) and expose all records.

---

## Pattern #3: `stacked_drop`

**Category:** Stacked Queries (Piggyback Injection)
**Score:** 95
**Regex:** `(?i);\s*DROP\s+`
**Description:** Stacked queries with DROP

**Example Malicious Input:**
```sql
SELECT 1; DROP TABLE users
```

**Why It's Dangerous:** Stacked queries allow an attacker to terminate the original query and execute a completely separate destructive command. `DROP TABLE` permanently destroys a table and all its data. This is one of the most severe injection attacks because data loss is immediate and potentially unrecoverable.

---

## Pattern #4: `stacked_delete`

**Category:** Stacked Queries (Piggyback Injection)
**Score:** 95
**Regex:** `(?i);\s*DELETE\s+`
**Description:** Stacked queries with DELETE

**Example Malicious Input:**
```sql
SELECT 1; DELETE FROM users WHERE 1=1
```

**Why It's Dangerous:** A stacked `DELETE` command can remove all rows from a table. Unlike `DROP`, the table structure survives, but all data is erased. Combined with `WHERE 1=1`, it wipes the entire table. This can cause data loss and service disruption.

---

## Pattern #5: `stacked_insert`

**Category:** Stacked Queries (Piggyback Injection)
**Score:** 90
**Regex:** `(?i);\s*INSERT\s+`
**Description:** Stacked queries with INSERT

**Example Malicious Input:**
```sql
SELECT 1; INSERT INTO admins (username, password) VALUES ('hacker', 'password123')
```

**Why It's Dangerous:** Stacked `INSERT` allows an attacker to create new records, including admin accounts, backdoor users, or malicious data. This can grant persistent unauthorized access to the system even after the original vulnerability is patched.

---

## Pattern #6: `stacked_update`

**Category:** Stacked Queries (Piggyback Injection)
**Score:** 90
**Regex:** `(?i);\s*UPDATE\s+`
**Description:** Stacked queries with UPDATE

**Example Malicious Input:**
```sql
SELECT 1; UPDATE users SET role='admin' WHERE username='attacker'
```

**Why It's Dangerous:** Stacked `UPDATE` allows an attacker to modify existing data, such as escalating their own privileges, changing passwords, or corrupting records. The changes are persistent and may go unnoticed.

---

## Pattern #7: `comment_dash`

**Category:** Comment Injection
**Score:** 60
**Regex:** `--\s*$`
**Description:** Trailing comment injection (--)

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE username='admin'--
```

**Why It's Dangerous:** Trailing `--` comments out the rest of the original SQL query. This is used to remove trailing conditions like `AND password='...'`, effectively bypassing authentication. It is almost always combined with other injection techniques to neutralize protective WHERE clauses.

---

## Pattern #8: `comment_block`

**Category:** Comment Injection
**Score:** 60
**Regex:** `/\*.*?\*/`
**Description:** Block comment injection

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE id=1 /* AND status='active' */
```

**Why It's Dangerous:** Block comments (`/* ... */`) can be used to selectively remove parts of a query, bypass WAF filters, or obfuscate malicious SQL. They can also be used inline to split keywords across comment boundaries (`UN/**/ION SEL/**/ECT`), evading simple string-matching detection.

---

## Pattern #9: `comment_hash`

**Category:** Comment Injection
**Score:** 60
**Regex:** `#\s*$`
**Description:** Hash comment injection

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE username='admin'#
```

**Why It's Dangerous:** The `#` character is a valid comment marker in MySQL. Like `--`, it comments out everything after it on the same line. Attackers targeting MySQL databases use this to strip trailing query conditions. Some WAFs only check for `--` and miss `#`.

---

## Pattern #10: `nested_comment`

**Category:** Comment Injection
**Score:** 65
**Regex:** `/\*.*?/\*`
**Description:** Nested comment injection

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE id=1 /* nested /* comment */ bypass */
```

**Why It's Dangerous:** Nested comments are used as an evasion technique. Some databases handle nested comments differently, and attackers exploit this inconsistency to bypass security filters that only handle single-level comments. This pattern indicates deliberate obfuscation.

---

## Pattern #11: `sleep_fn`

**Category:** Time-Based Blind Injection
**Score:** 80
**Regex:** `(?i)\bSLEEP\s*\(`
**Description:** SLEEP-based timing attack

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE id=1 AND SLEEP(5)
```

**Why It's Dangerous:** Time-based blind SQL injection uses `SLEEP()` to determine whether conditions are true or false based on response time. The attacker asks the database "is the first character of the admin password 'a'?" and measures whether the response takes 5 seconds. This allows complete data extraction without any visible output, one character at a time.

---

## Pattern #12: `benchmark_fn`

**Category:** Time-Based Blind Injection
**Score:** 80
**Regex:** `(?i)\bBENCHMARK\s*\(`
**Description:** BENCHMARK-based timing attack

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE id=1 AND BENCHMARK(5000000, SHA1('test'))
```

**Why It's Dangerous:** MySQL's `BENCHMARK()` function executes an expression a specified number of times. Attackers use it as an alternative to `SLEEP()` for time-based blind injection when `SLEEP()` is blocked. It can also cause significant CPU load on the database server, functioning as a denial-of-service attack.

---

## Pattern #13: `waitfor_delay`

**Category:** Time-Based Blind Injection
**Score:** 80
**Regex:** `(?i)\bWAITFOR\s+DELAY\b`
**Description:** WAITFOR DELAY timing attack

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE id=1; WAITFOR DELAY '0:0:5'
```

**Why It's Dangerous:** `WAITFOR DELAY` is the Microsoft SQL Server equivalent of MySQL's `SLEEP()`. It pauses execution for the specified duration. Attackers use it for time-based blind injection against MSSQL databases. Its presence in a query is almost never legitimate in application code.

---

## Pattern #14: `load_file`

**Category:** File System Access
**Score:** 90
**Regex:** `(?i)\bLOAD_FILE\s*\(`
**Description:** LOAD_FILE file read attempt

**Example Malicious Input:**
```sql
SELECT LOAD_FILE('/etc/passwd')
```

**Why It's Dangerous:** `LOAD_FILE()` reads a file from the server's file system and returns its contents as a string. An attacker can read configuration files (`/etc/passwd`, database config files, application source code, private keys), gaining information for further attacks or direct credential theft.

---

## Pattern #15: `into_outfile`

**Category:** File System Access
**Score:** 90
**Regex:** `(?i)\bINTO\s+(OUT|DUMP)FILE\b`
**Description:** INTO OUTFILE/DUMPFILE write attempt

**Example Malicious Input:**
```sql
SELECT '<?php system($_GET["cmd"]); ?>' INTO OUTFILE '/var/www/html/shell.php'
```

**Why It's Dangerous:** `INTO OUTFILE` and `INTO DUMPFILE` write query results to a file on the server. Attackers use this to write web shells (PHP, JSP), SSH keys, or cron jobs to the server, achieving remote code execution. This can lead to complete server compromise.

---

## Pattern #16: `char_obfuscation`

**Category:** String Obfuscation / Encoding Evasion
**Score:** 70
**Regex:** `(?i)\bCHAR\s*\(\s*\d+(\s*,\s*\d+)+\s*\)`
**Description:** CHAR() string obfuscation

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE username=CHAR(97,100,109,105,110)
```

**Why It's Dangerous:** `CHAR()` converts numeric ASCII codes to characters. Attackers use it to construct strings without using quotes, bypassing WAF rules that look for quoted string patterns like `'admin'`. The example above produces the string `admin`. This obfuscation technique makes pattern detection harder.

---

## Pattern #17: `concat_obfuscation`

**Category:** String Obfuscation / Encoding Evasion
**Score:** 70
**Regex:** `(?i)\bCONCAT\s*\(`
**Description:** CONCAT() string obfuscation

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE username=CONCAT('adm','in')
```

**Why It's Dangerous:** `CONCAT()` joins string fragments together. Attackers split malicious strings across multiple arguments to evade detection: `CONCAT('DR','OP T','ABLE')` produces `DROP TABLE`. Simple keyword filters miss this because no single argument contains the complete dangerous keyword.

---

## Pattern #18: `hex_encoding`

**Category:** String Obfuscation / Encoding Evasion
**Score:** 75
**Regex:** `0x[0-9a-fA-F]{8,}`
**Description:** Hex-encoded string attack

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE username=0x61646D696E
```

**Why It's Dangerous:** Hex-encoded values (`0x61646D696E` = "admin") bypass string-based detection completely. No quotes are needed, and the actual content is invisible to simple text scanning. Attackers encode entire payloads in hex to evade WAFs and input validation.

---

## Pattern #19: `boolean_and`

**Category:** Tautology / Always-True Conditions
**Score:** 70
**Regex:** `(?i)\bAND\s+['"]?\d+['"]?\s*=\s*['"]?\d+['"]?`
**Description:** Boolean-based blind injection (AND x=x)

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE id=1 AND 1=1
```

**Why It's Dangerous:** Boolean-based blind injection uses always-true (`AND 1=1`) and always-false (`AND 1=2`) conditions to determine if a query returns different results. By observing whether the page changes, the attacker can extract data one bit at a time. Unlike time-based attacks, this is faster and harder to detect in logs.

---

## Pattern #20: `string_termination`

**Category:** Stacked Queries (Piggyback Injection)
**Score:** 90
**Regex:** `['"]\s*;\s*(DROP|DELETE|INSERT|UPDATE|ALTER|CREATE|EXEC)\b`
**Description:** String termination followed by SQL command

**Example Malicious Input:**
```sql
'; DROP TABLE users
```

**Why It's Dangerous:** This pattern detects the classic injection technique: close the current string literal with a quote, terminate the statement with a semicolon, and execute a destructive command. This is the most common real-world injection pattern and covers the widest range of attacks. The regex matches the complete attack sequence.

---

## Pattern #21: `exec_proc`

**Category:** Stored Procedure / Command Execution
**Score:** 90
**Regex:** `(?i)\bEXEC(UTE)?\s+(xp_|sp_)`
**Description:** EXEC stored procedure call

**Example Malicious Input:**
```sql
EXEC sp_addlogin 'hacker', 'password123'
```

**Why It's Dangerous:** Calling stored procedures (`sp_` = system stored procedures, `xp_` = extended stored procedures) can create new database logins, modify server configuration, read/write the file system, or execute operating system commands. On Microsoft SQL Server, this is a primary vector for privilege escalation and lateral movement.

---

## Pattern #22: `xp_cmdshell`

**Category:** Stored Procedure / Command Execution
**Score:** 95
**Regex:** `(?i)\bxp_cmdshell\b`
**Description:** xp_cmdshell command execution

**Example Malicious Input:**
```sql
EXEC xp_cmdshell 'net user hacker password123 /add'
```

**Why It's Dangerous:** `xp_cmdshell` executes an arbitrary operating system command on the SQL Server host. This is the most dangerous stored procedure in MSSQL because it provides direct OS-level access. An attacker can add users, download malware, establish reverse shells, or exfiltrate data. Its presence in any query is almost certainly malicious.

---

## Pattern #23: `information_schema`

**Category:** Metadata / Schema Extraction
**Score:** 75
**Regex:** `(?i)\bINFORMATION_SCHEMA\b`
**Description:** INFORMATION_SCHEMA metadata access

**Example Malicious Input:**
```sql
SELECT table_name FROM INFORMATION_SCHEMA.TABLES
```

**Why It's Dangerous:** `INFORMATION_SCHEMA` is a standard SQL metadata catalog that lists all tables, columns, data types, and constraints in the database. Attackers query it to map the database schema before launching targeted data extraction. It is the first reconnaissance step in most SQL injection attacks.

---

## Pattern #24: `pg_sleep`

**Category:** Time-Based Blind Injection
**Score:** 80
**Regex:** `(?i)\bpg_sleep\s*\(`
**Description:** pg_sleep timing attack

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE id=1 AND pg_sleep(5)=''
```

**Why It's Dangerous:** `pg_sleep()` is PostgreSQL's equivalent of MySQL's `SLEEP()`. It pauses the database connection for the specified number of seconds. Attackers use it for time-based blind injection against PostgreSQL databases. Its appearance in application-submitted queries is almost never legitimate.

---

## Pattern #25: `having_injection`

**Category:** Clause Injection
**Score:** 70
**Regex:** `(?i)\bHAVING\s+\d+\s*=\s*\d+`
**Description:** HAVING clause injection

**Example Malicious Input:**
```sql
SELECT * FROM users GROUP BY id HAVING 1=1
```

**Why It's Dangerous:** `HAVING` clause injection is used when the `WHERE` clause is not injectable. By adding a `HAVING` condition with a tautology, the attacker can force the query to return all grouped results. On some databases, `HAVING` errors also reveal column names and table structure in error messages, aiding further injection.

---

## Pattern #26: `order_by_enum`

**Category:** Clause Injection
**Score:** 60
**Regex:** `(?i)\bORDER\s+BY\s+\d{2,}`
**Description:** ORDER BY column enumeration

**Example Malicious Input:**
```sql
SELECT * FROM users ORDER BY 99
```

**Why It's Dangerous:** Attackers use `ORDER BY` with incrementing column numbers to determine how many columns a table has. When `ORDER BY 5` works but `ORDER BY 6` throws an error, the table has 5 columns. This information is critical for constructing a valid `UNION SELECT` injection with the correct number of columns.

---

## Pattern #27: `group_by_having`

**Category:** Clause Injection
**Score:** 50
**Regex:** `(?i)\bGROUP\s+BY\s+.+\bHAVING\b`
**Description:** GROUP BY with HAVING injection

**Example Malicious Input:**
```sql
SELECT username, COUNT(*) FROM users GROUP BY username HAVING COUNT(*) > 0
```

**Why It's Dangerous:** Combining `GROUP BY` with `HAVING` in injected queries can force error messages that reveal column names. On MSSQL, an invalid `GROUP BY` error message includes the first column name not in the GROUP BY clause, allowing schema enumeration through repeated injections.

---

## Pattern #28: `xml_extract`

**Category:** XML / Function Injection
**Score:** 85
**Regex:** `(?i)\b(EXTRACTVALUE|UPDATEXML)\s*\(`
**Description:** XML function injection

**Example Malicious Input:**
```sql
SELECT EXTRACTVALUE(1, CONCAT(0x7e, (SELECT password FROM admins LIMIT 1)))
```

**Why It's Dangerous:** `EXTRACTVALUE()` and `UPDATEXML()` are MySQL XML functions that generate error messages containing the evaluated expression. Attackers exploit this to extract data through error messages (error-based injection). The database evaluates the subquery and includes the result in the error output.

---

## Pattern #29: `convert_cast`

**Category:** XML / Function Injection
**Score:** 40
**Regex:** `(?i)\b(CONVERT|CAST)\s*\(.+\bAS\b.+\)`
**Description:** CONVERT/CAST type coercion

**Example Malicious Input:**
```sql
SELECT CAST((SELECT password FROM admins LIMIT 1) AS INT)
```

**Why It's Dangerous:** `CONVERT` and `CAST` can force type conversion errors that reveal data. When a string value (like a password) is cast to an integer, the error message often includes the original string value. This is an error-based data extraction technique. The lower score (40) reflects that CAST/CONVERT have many legitimate uses.

---

## Pattern #30: `double_encode`

**Category:** String Obfuscation / Encoding Evasion
**Score:** 75
**Regex:** `%25(27|22|3[bB])`
**Description:** Double URL encoding attack

**Example Malicious Input:**
```
%2527 OR 1=1
```

**Why It's Dangerous:** Double URL encoding (`%25` = `%`, so `%2527` = `%27` = `'`) bypasses input validation that only decodes URL encoding once. The first decode produces `%27`, which looks harmless. The second decode (by the database or a later processing stage) produces a single quote, enabling injection. This is a common WAF bypass technique.

---

## Pattern #31: `unicode_encode`

**Category:** String Obfuscation / Encoding Evasion
**Score:** 75
**Regex:** `\\u0027|\\u0022|%u0027|%u0022`
**Description:** Unicode encoding attack

**Example Malicious Input:**
```
SELECT * FROM users WHERE name=\u0027admin\u0027
```

**Why It's Dangerous:** Unicode-encoded characters (`\u0027` = single quote, `\u0022` = double quote) bypass filters that check for literal quote characters. Some application layers and databases interpret Unicode escapes, converting them back to quotes at a later processing stage. This enables injection through layers of encoding.

---

## Pattern #32: `into_var`

**Category:** Other
**Score:** 70
**Regex:** `(?i)\bINTO\s+@`
**Description:** INTO variable assignment

**Example Malicious Input:**
```sql
SELECT password FROM admins INTO @pw
```

**Why It's Dangerous:** `INTO @variable` stores query results into user-defined session variables. Attackers use this to capture sensitive data and then exfiltrate it through other channels (e.g., inserting the variable value into a visible table, or using it in subsequent injected queries). This indicates a multi-step attack.

---

## Pattern #33: `alter_table`

**Category:** Stacked Queries (Piggyback Injection)
**Score:** 90
**Regex:** `(?i);\s*ALTER\s+TABLE\b`
**Description:** Stacked ALTER TABLE

**Example Malicious Input:**
```sql
SELECT 1; ALTER TABLE users ADD COLUMN backdoor TEXT
```

**Why It's Dangerous:** A stacked `ALTER TABLE` command can modify the database schema: adding columns, removing constraints, changing data types, or renaming tables. An attacker might add a column to store backdoor data, remove security constraints, or disrupt the application by changing the expected schema.

---

## Pattern #34: `create_stacked`

**Category:** Stacked Queries (Piggyback Injection)
**Score:** 90
**Regex:** `(?i);\s*CREATE\s+(TABLE|DATABASE|USER)\b`
**Description:** Stacked CREATE statement

**Example Malicious Input:**
```sql
SELECT 1; CREATE USER 'backdoor'@'%' IDENTIFIED BY 'password123'
```

**Why It's Dangerous:** Stacked `CREATE` commands allow an attacker to create new tables (for data staging), new databases (for persistent storage), or new user accounts (for persistent access). Creating a database user is especially dangerous because it provides a legitimate login that survives application-level patches.

---

## Pattern #35: `shutdown_cmd`

**Category:** Stored Procedure / Command Execution
**Score:** 95
**Regex:** `(?i)\bSHUTDOWN\b`
**Description:** SHUTDOWN command

**Example Malicious Input:**
```sql
SHUTDOWN WITH NOWAIT
```

**Why It's Dangerous:** The `SHUTDOWN` command (supported by MSSQL and some other databases) immediately stops the database server. This is a denial-of-service attack that takes down the entire database, affecting all connected applications. Recovery requires manual intervention by a database administrator.

---

## Pattern #36: `tautology_string`

**Category:** Tautology / Always-True Conditions
**Score:** 85
**Regex:** `(?i)['"]?\s*OR\s+['"][^'"]+['"]\s*=\s*['"][^'"]+['"]`
**Description:** String tautology (OR 'a'='a')

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE username='admin' OR 'x'='x'
```

**Why It's Dangerous:** String tautologies (`OR 'a'='a'`) serve the same purpose as numeric tautologies (`OR 1=1`) but use string comparison. Some WAFs only check for numeric patterns and miss string-based tautologies. This pattern catches the string variant, which is equally effective at bypassing WHERE clause filtering.

---

## Pattern #37: `if_blind`

**Category:** XML / Function Injection
**Score:** 70
**Regex:** `(?i)\bIF\s*\(.+,.+,.+\)`
**Description:** IF-based blind injection

**Example Malicious Input:**
```sql
SELECT IF(SUBSTRING(password,1,1)='a', SLEEP(5), 0) FROM admins
```

**Why It's Dangerous:** The `IF()` function enables conditional blind injection. The attacker creates a condition that, when true, triggers a detectable side effect (a time delay, a different response, or an error). This is the foundation of all blind injection techniques and allows full data extraction without direct output.

---

## Pattern #38: `like_wildcard`

**Category:** Other
**Score:** 30
**Regex:** `(?i)\bLIKE\s+['"]%['"]`
**Description:** LIKE wildcard abuse

**Example Malicious Input:**
```sql
SELECT * FROM users WHERE password LIKE '%'
```

**Why It's Dangerous:** `LIKE '%'` matches every non-NULL value, effectively returning all rows. While less severe than tautology injection (it only matches non-NULL values), it can still be used to bypass filtering. The low score (30) reflects that `LIKE '%'` has some legitimate uses in application code, but its presence in user-submitted queries is suspicious.

---

## Summary by Category

| Category | Pattern Count | Score Range |
|----------|:------------:|:-----------:|
| UNION / Subquery Injection | 1 | 90 |
| Tautology / Always-True | 3 | 70-85 |
| Stacked Queries | 7 | 90-95 |
| Comment Injection | 4 | 60-65 |
| Time-Based Blind | 4 | 80 |
| File System Access | 2 | 90 |
| String Obfuscation / Encoding | 5 | 70-75 |
| Stored Procedure / Command Execution | 3 | 90-95 |
| Metadata Extraction | 1 | 75 |
| Clause Injection | 3 | 50-70 |
| XML / Function Injection | 3 | 40-85 |
| Other | 2 | 30-70 |
| **Total** | **38** | **30-95** |
