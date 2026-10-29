GRANT USAGE ON SCHEMA public TO auth_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO auth_app;
REVOKE ALL ON flyway_schema_history FROM auth_app;
REVOKE UPDATE,DELETE ON security_audit_records FROM auth_app;
