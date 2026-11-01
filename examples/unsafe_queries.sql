-- Triggers SG002 (SELECT *) and SG003 (Leading wildcard LIKE)
SELECT * FROM users WHERE username LIKE '%admin';

-- Triggers SG001 (Unsafe DELETE missing WHERE)
DELETE FROM audit_logs;

-- Triggers SG004 when o.legacy_user_ref is not in --indexes
SELECT u.id, o.amount
FROM users u
JOIN orders o ON u.id = o.legacy_user_ref
WHERE o.amount = 500;