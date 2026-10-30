-- Application login route used for organization invitation links.
ALTER TABLE clients ADD COLUMN initiate_login_uri VARCHAR(2048) NOT NULL DEFAULT '';
