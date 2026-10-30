-- Application login route used for organization invitation links.
ALTER TABLE clients ADD COLUMN initiate_login_uri TEXT NOT NULL DEFAULT '';
