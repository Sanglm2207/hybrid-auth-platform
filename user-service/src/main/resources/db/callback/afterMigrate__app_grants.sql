GRANT USAGE ON SCHEMA public TO profiles_app;
GRANT SELECT,INSERT,UPDATE,DELETE ON ALL TABLES IN SCHEMA public TO profiles_app;
REVOKE ALL ON flyway_schema_history FROM profiles_app;
