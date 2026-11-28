-- Plan 40: custom claims per session and client. Cookie mode already exists.
ALTER TABLE sessions ADD COLUMN userinfo_claims LONGTEXT NULL;
