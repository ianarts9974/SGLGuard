from sqlguard.linter import lint_sql


def test_destructive_delete_and_update_flagged():
    sql = "DELETE FROM sessions; UPDATE accounts SET active = 0;"
    issues = lint_sql(sql)
    assert len(issues) == 2
    assert all(i.rule_id == "SG001" and i.severity == "CRITICAL" for i in issues)


def test_safe_delete_with_where_passes():
    sql = "DELETE FROM sessions WHERE expired_at IS NOT NULL;"
    assert lint_sql(sql) == []


def test_select_star_and_leading_wildcard_flagged():
    sql = "SELECT * FROM customers WHERE email LIKE '%@gmail.com';"
    issues = lint_sql(sql)
    rule_ids = {i.rule_id for i in issues}
    assert "SG002" in rule_ids
    assert "SG003" in rule_ids


def test_unindexed_join_columns_flagged():
    sql = (
        "SELECT u.id, o.total FROM users u "
        "JOIN orders o ON u.id = o.unindexed_ref;"
    )
    issues = lint_sql(sql, indexed_columns={"u.id", "o.user_id"})
    assert len(issues) == 1
    assert issues[0].rule_id == "SG004"
    assert "o.unindexed_ref" in issues[0].message