\getenv auth_password AUTH_APP_PASSWORD
\getenv auth_migration_password AUTH_MIGRATION_PASSWORD
\getenv profile_password PROFILE_DB_PASSWORD
\getenv profile_app_password PROFILE_APP_PASSWORD
\getenv mail_password MAIL_APP_PASSWORD
\getenv mail_migration_password MAIL_MIGRATION_PASSWORD
SELECT format('CREATE ROLE auth_migrator LOGIN PASSWORD %L', :'auth_migration_password') WHERE NOT EXISTS(SELECT FROM pg_roles WHERE rolname='auth_migrator')\gexec
SELECT format('CREATE ROLE auth_app LOGIN NOINHERIT PASSWORD %L', :'auth_password') WHERE NOT EXISTS(SELECT FROM pg_roles WHERE rolname='auth_app')\gexec
SELECT format('CREATE ROLE profiles LOGIN PASSWORD %L', :'profile_password') WHERE NOT EXISTS(SELECT FROM pg_roles WHERE rolname='profiles')\gexec
SELECT format('CREATE ROLE profiles_app LOGIN NOINHERIT PASSWORD %L', :'profile_app_password') WHERE NOT EXISTS(SELECT FROM pg_roles WHERE rolname='profiles_app')\gexec
SELECT format('CREATE ROLE mailer_migrator LOGIN PASSWORD %L', :'mail_migration_password') WHERE NOT EXISTS(SELECT FROM pg_roles WHERE rolname='mailer_migrator')\gexec
SELECT format('CREATE ROLE mailer_app LOGIN NOINHERIT PASSWORD %L', :'mail_password') WHERE NOT EXISTS(SELECT FROM pg_roles WHERE rolname='mailer_app')\gexec
ALTER ROLE auth_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
ALTER ROLE profiles_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
ALTER ROLE mailer_app NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT;
SELECT 'CREATE DATABASE userdb OWNER profiles' WHERE NOT EXISTS(SELECT FROM pg_database WHERE datname='userdb')\gexec
SELECT 'CREATE DATABASE maildb OWNER mailer_migrator' WHERE NOT EXISTS(SELECT FROM pg_database WHERE datname='maildb')\gexec
ALTER DATABASE authdb OWNER TO auth_migrator;
REVOKE ALL ON DATABASE authdb FROM PUBLIC;
REVOKE ALL ON DATABASE userdb FROM PUBLIC;
REVOKE ALL ON DATABASE maildb FROM PUBLIC;
GRANT CONNECT ON DATABASE authdb TO auth_migrator,auth_app;
GRANT CONNECT ON DATABASE userdb TO profiles,profiles_app;
GRANT CONNECT ON DATABASE maildb TO mailer_migrator,mailer_app;
\connect authdb
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
DO $$DECLARE t record; BEGIN FOR t IN SELECT tablename FROM pg_tables WHERE schemaname='public' LOOP EXECUTE format('ALTER TABLE public.%I OWNER TO auth_migrator',t.tablename); END LOOP; END$$;
GRANT USAGE ON SCHEMA public TO auth_app;
ALTER DEFAULT PRIVILEGES FOR ROLE auth_migrator IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO auth_app;
\connect userdb
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO profiles_app;
ALTER DEFAULT PRIVILEGES FOR ROLE profiles IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO profiles_app;
\connect maildb
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO mailer_app;
ALTER DEFAULT PRIVILEGES FOR ROLE mailer_migrator IN SCHEMA public GRANT SELECT,INSERT,UPDATE,DELETE ON TABLES TO mailer_app;
