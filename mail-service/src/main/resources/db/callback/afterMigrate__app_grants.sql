GRANT USAGE ON SCHEMA public TO mailer_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO mailer_app;
REVOKE ALL ON flyway_schema_history FROM mailer_app;
