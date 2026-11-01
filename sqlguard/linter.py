from dataclasses import dataclass
import re
import sqlparse
from sqlparse.sql import Statement, Where


@dataclass
class Violation:
    rule_id: str
    severity: str
    message: str
    line: int
    snippet: str


def _has_where_clause(statement: Statement) -> bool:
    return any(isinstance(token, Where) for token in statement.tokens)


def _extract_join_columns(cleaned_sql: str) -> list[str]:
    pattern = re.compile(
        r"\bJOIN\s+\w+(?:\s+AS\s+\w+|\s+\w+)?\s+ON\s+([\w\.]+)\s*=\s*([\w\.]+)",
        re.IGNORECASE,
    )
    columns: list[str] = []
    for left_col, right_col in pattern.findall(cleaned_sql):
        columns.extend([left_col.lower(), right_col.lower()])
    return columns


def lint_sql(
    sql_text: str, indexed_columns: set[str] | None = None
) -> list[Violation]:
    violations: list[Violation] = []
    normalized_indexes = (
        {col.strip().lower() for col in indexed_columns if col.strip()}
        if indexed_columns
        else set()
    )

    statements = sqlparse.parse(sql_text)
    current_char_pos = 0

    for stmt in statements:
        raw_stmt = str(stmt)
        stmt_start = sql_text.find(raw_stmt, current_char_pos)
        if stmt_start == -1:
            stmt_start = current_char_pos
        line_number = sql_text.count("\n", 0, stmt_start) + 1
        current_char_pos = stmt_start + len(raw_stmt)

        cleaned = sqlparse.format(
            raw_stmt, strip_comments=True, keyword_case="upper"
        ).strip()
        if not cleaned:
            continue

        single_line = " ".join(cleaned.split())
        snippet = single_line[:75] + ("..." if len(single_line) > 75 else "")
        stmt_type = stmt.get_type()

        if stmt_type in ("DELETE", "UPDATE") and not _has_where_clause(stmt):
            violations.append(
                Violation(
                    rule_id="SG001",
                    severity="CRITICAL",
                    message=f"Unsafe {stmt_type} statement without a WHERE clause.",
                    line=line_number,
                    snippet=snippet,
                )
            )

        if stmt_type == "SELECT" and re.search(r"\bSELECT\s+\*", cleaned):
            violations.append(
                Violation(
                    rule_id="SG002",
                    severity="WARNING",
                    message="SELECT * detected; specify explicit columns to allow index-only scans.",
                    line=line_number,
                    snippet=snippet,
                )
            )

        if re.search(r"\bLIKE\s+['\"]%", cleaned, re.IGNORECASE):
            violations.append(
                Violation(
                    rule_id="SG003",
                    severity="WARNING",
                    message="Leading wildcard in LIKE '%...' prevents B-tree index usage (full-table scan).",
                    line=line_number,
                    snippet=snippet,
                )
            )

        if re.search(r"\bJOIN\b", cleaned):
            if not re.search(r"\bJOIN\b[\s\S]*?\b(ON|USING)\b", cleaned):
                violations.append(
                    Violation(
                        rule_id="SG004",
                        severity="CRITICAL",
                        message="JOIN missing ON or USING clause; causes accidental Cartesian product.",
                        line=line_number,
                        snippet=snippet,
                    )
                )
            elif normalized_indexes:
                join_cols = _extract_join_columns(cleaned)
                unindexed = [
                    col
                    for col in join_cols
                    if col not in normalized_indexes
                    and col.split(".")[-1] not in normalized_indexes
                ]
                if unindexed:
                    missing_str = ", ".join(sorted(set(unindexed)))
                    violations.append(
                        Violation(
                            rule_id="SG004",
                            severity="WARNING",
                            message=f"Unindexed JOIN column(s) detected: {missing_str}",
                            line=line_number,
                            snippet=snippet,
                        )
                    )

    return violations
