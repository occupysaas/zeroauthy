package sqlstore

import (
	"context"
	"database/sql"
	"errors"
	"slices"
	"strings"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

type connections struct{ s *Store }

func (s *Store) Connections() store.Connections { return connections{s} }

const connectionCols = `tenant_id, id, name, strategy, enabled_clients, disable_signup, requires_username,
 password_options, created_at,
 enabled_database_customization, import_mode, custom_scripts, configuration_sealed, set_user_root_attributes, is_domain_connection,
 brute_force_protection, username_min, username_max, origin, extra`

func (r connections) Create(ctx context.Context, c *store.Connection) error {
	args, err := connectionArgs(c)
	if err != nil {
		return err
	}
	_, err = r.s.write(ctx, nil, `INSERT INTO connections (`+connectionCols+`) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, args...)
	return r.s.conflict(err)
}

func (r connections) Get(ctx context.Context, tenantID, id string) (*store.Connection, error) {
	c, err := scanConnection(r.s.queryRow(ctx, `SELECT `+connectionCols+` FROM connections WHERE tenant_id = ? AND id = ?`, tenantID, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return c, err
}

func (r connections) GetByName(ctx context.Context, tenantID, name string) (*store.Connection, error) {
	c, err := scanConnection(r.s.queryRow(ctx, `SELECT `+connectionCols+` FROM connections WHERE tenant_id = ? AND name = ?`, tenantID, name))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, store.ErrNotFound
	}
	return c, err
}

func (r connections) Update(ctx context.Context, c *store.Connection) error {
	args, err := connectionArgs(c)
	if err != nil {
		return err
	}
	res, err := r.s.write(ctx, nil, `UPDATE connections SET name=?, strategy=?, enabled_clients=?, disable_signup=?, requires_username=?,
 password_options=?, created_at=?,
 enabled_database_customization=?, import_mode=?, custom_scripts=?, configuration_sealed=?, set_user_root_attributes=?, is_domain_connection=?,
 brute_force_protection=?, username_min=?, username_max=?, origin=?, extra=?
 WHERE tenant_id=? AND id=?`, append(slices.Clone(args[2:]), c.TenantID, c.ID)...)
	if err != nil {
		return r.s.conflict(err)
	}
	return expectRow(res)
}

func (r connections) List(ctx context.Context, tenantID string, f store.ConnectionFilter, p store.Page) ([]*store.Connection, int, error) {
	where, args := []string{"tenant_id = ?"}, []any{tenantID}
	if f.Name != "" {
		where = append(where, "name = ?")
		args = append(args, f.Name)
	}
	if len(f.Strategies) > 0 {
		where = append(where, "strategy IN ("+strings.TrimSuffix(strings.Repeat("?,", len(f.Strategies)), ",")+")")
		for _, st := range f.Strategies {
			args = append(args, st)
		}
	}
	cond := strings.Join(where, " AND ")
	var total int
	if err := r.s.queryRow(ctx, `SELECT COUNT(*) FROM connections WHERE `+cond, args...).Scan(&total); err != nil {
		return nil, 0, err
	}
	// LOWER(name) then id, both in byte order, so the order is the same on
	// every database. Offset and limit are integers built here, never
	// caller text. SQLite and MySQL want a LIMIT with an OFFSET, so "no
	// limit" is the largest BIGINT.
	q := `SELECT ` + connectionCols + ` FROM connections WHERE ` + cond +
		` ORDER BY LOWER(name)` + r.s.d.byteOrder + `, id` + r.s.d.byteOrder
	q += pageClause(p)
	rows, err := r.s.query(ctx, q, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	var out []*store.Connection
	for rows.Next() {
		c, err := scanConnection(rows)
		if err != nil {
			return nil, 0, err
		}
		out = append(out, c)
	}
	return out, total, rows.Err()
}

// Delete removes the connection, then its users and what hangs off them.
// The users are those whose own identity is on the connection; a user with
// only linked identities on it loses those identities and keeps the rest
// (D-0043). Both are found by reading the identities of the tenant's users
// (the identities are JSON, so no index helps).
func (r connections) Delete(ctx context.Context, tenantID, id string) error {
	return r.s.atomicRetry(ctx, nil, func(tx *Store) error {
		var name string
		err := tx.queryRow(ctx, `SELECT name FROM connections WHERE tenant_id = ? AND id = ?`+tx.d.forUpdate, tenantID, id).Scan(&name)
		if errors.Is(err, sql.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		gone, stripped, err := usersOnConnection(ctx, tx, tenantID, name)
		if err != nil {
			return err
		}
		for _, uid := range gone {
			if err := deleteUser(ctx, tx, tenantID, uid); err != nil {
				return err
			}
		}
		for _, u := range stripped {
			u.WithoutLinkedOn(name)
			ids, err := toJSON(u.Identities)
			if err != nil {
				return err
			}
			if _, err := tx.exec(ctx, `UPDATE users SET identities=?, version=version+1 WHERE tenant_id=? AND user_id=?`, ids, tenantID, u.UserID); err != nil {
				return err
			}
			if err := putLogins(ctx, tx, u, true); err != nil {
				return err
			}
		}
		if _, err := tx.exec(ctx, `UPDATE tenants SET default_directory = '' WHERE id = ? AND default_directory = ?`, tenantID, name); err != nil {
			return err
		}
		_, err = tx.exec(ctx, `DELETE FROM connections WHERE tenant_id = ? AND id = ?`, tenantID, id)
		return err
	})
}

// usersOnConnection returns, for the connection called name, the IDs of the
// tenant's users whose own identity is on it (gone) and the users that only
// have linked identities on it (stripped), in user_id order.
func usersOnConnection(ctx context.Context, tx *Store, tenantID, name string) (gone []string, stripped []*store.User, err error) {
	rows, err := tx.query(ctx, `SELECT `+userCols+` FROM users WHERE tenant_id = ? ORDER BY user_id`+tx.d.byteOrder, tenantID)
	if err != nil {
		return nil, nil, err
	}
	defer rows.Close() // also on the early returns; SQLite has one connection
	for rows.Next() {
		u, err := scanUser(rows)
		if err != nil {
			return nil, nil, err
		}
		switch del, strip := u.ConnectionDeleteEffect(name); {
		case del:
			gone = append(gone, u.UserID)
		case strip:
			stripped = append(stripped, u)
		}
	}
	return gone, stripped, rows.Err()
}

func scanConnection(row scanner) (*store.Connection, error) {
	var c store.Connection
	var enabled string
	var created int64
	var scripts string
	var sealed []byte
	var options, extra string
	if err := row.Scan(&c.TenantID, &c.ID, &c.Name, &c.Strategy, &enabled, &c.DisableSignup, &c.RequiresUsername,
		&options, &created,
		&c.EnabledDatabaseCustomization, &c.ImportMode, &scripts, &sealed, &c.SetUserRootAttributes, &c.IsDomainConnection,
		&c.BruteForceProtection, &c.UsernameMin, &c.UsernameMax, &c.Origin, &extra); err != nil {
		return nil, err
	}
	var po passwordOptionsJSON
	if err := fromJSON(options, &po); err != nil {
		return nil, err
	}
	c.PasswordOptions = po.toStore()
	if err := fromJSON(extra, &c.Extra); err != nil {
		return nil, err
	}
	if err := fromJSON(scripts, &c.CustomScripts); err != nil {
		return nil, err
	}
	if len(sealed) > 0 {
		c.ConfigurationSealed = sealed
	}
	if err := fromJSON(enabled, &c.EnabledClients); err != nil {
		return nil, err
	}
	c.CreatedAt = fromMicros(created)
	return &c, nil
}

func connectionArgs(c *store.Connection) ([]any, error) {
	enabled, err := toJSON(c.EnabledClients)
	if err != nil {
		return nil, err
	}
	scripts, err := toJSON(c.CustomScripts)
	if err != nil {
		return nil, err
	}
	options, err := toJSON(passwordOptionsToJSON(c.PasswordOptions))
	if err != nil {
		return nil, err
	}
	extra, err := toJSON(c.Extra)
	if err != nil {
		return nil, err
	}
	var sealed any // SQL NULL when there is no sealed configuration
	if len(c.ConfigurationSealed) > 0 {
		sealed = c.ConfigurationSealed
	}
	return []any{c.TenantID, c.ID, c.Name, c.Strategy, enabled, c.DisableSignup, c.RequiresUsername,
		options, micros(c.CreatedAt),
		c.EnabledDatabaseCustomization, c.ImportMode, scripts, sealed, c.SetUserRootAttributes, c.IsDomainConnection,
		c.BruteForceProtection, c.UsernameMin, c.UsernameMax, c.Origin, extra}, nil
}

// passwordOptionsJSON is the stored form of store.PasswordOptions (the
// password_options column). Its keys are Auth0's; migration 0013 writes the
// same keys. A key that is absent reads as the zero value; lists keep the
// difference between null and [].
type passwordOptionsJSON struct {
	Complexity struct {
		MinLength            int      `json:"min_length"`
		CharacterTypes       []string `json:"character_types"`
		CharacterTypeRule    string   `json:"character_type_rule"`
		IdenticalCharacters  string   `json:"identical_characters"`
		SequentialCharacters string   `json:"sequential_characters"`
		MaxLengthExceeded    string   `json:"max_length_exceeded"`
		MinCharacterClasses  int      `json:"min_character_classes"`
	} `json:"complexity"`
	History struct {
		Active bool `json:"active"`
		Size   int  `json:"size"`
	} `json:"history"`
	Dictionary struct {
		Active  bool     `json:"active"`
		Default string   `json:"default"`
		Custom  []string `json:"custom"`
	} `json:"dictionary"`
	ProfileData struct {
		Active        bool     `json:"active"`
		BlockedFields []string `json:"blocked_fields"`
	} `json:"profile_data"`
}

func passwordOptionsToJSON(o store.PasswordOptions) passwordOptionsJSON {
	var j passwordOptionsJSON
	j.Complexity.MinLength = o.Complexity.MinLength
	j.Complexity.CharacterTypes = o.Complexity.CharacterTypes
	j.Complexity.CharacterTypeRule = o.Complexity.CharacterTypeRule
	j.Complexity.IdenticalCharacters = o.Complexity.IdenticalCharacters
	j.Complexity.SequentialCharacters = o.Complexity.SequentialCharacters
	j.Complexity.MaxLengthExceeded = o.Complexity.MaxLengthExceeded
	j.Complexity.MinCharacterClasses = o.Complexity.MinCharacterClasses
	j.History.Active, j.History.Size = o.History.Active, o.History.Size
	j.Dictionary.Active, j.Dictionary.Default, j.Dictionary.Custom = o.Dictionary.Active, o.Dictionary.Default, o.Dictionary.Custom
	j.ProfileData.Active, j.ProfileData.BlockedFields = o.ProfileData.Active, o.ProfileData.BlockedFields
	return j
}

func (j passwordOptionsJSON) toStore() store.PasswordOptions {
	return store.PasswordOptions{
		Complexity: store.PasswordComplexity{
			MinLength:            j.Complexity.MinLength,
			CharacterTypes:       j.Complexity.CharacterTypes,
			CharacterTypeRule:    j.Complexity.CharacterTypeRule,
			IdenticalCharacters:  j.Complexity.IdenticalCharacters,
			SequentialCharacters: j.Complexity.SequentialCharacters,
			MaxLengthExceeded:    j.Complexity.MaxLengthExceeded,
			MinCharacterClasses:  j.Complexity.MinCharacterClasses,
		},
		History:     store.PasswordHistory{Active: j.History.Active, Size: j.History.Size},
		Dictionary:  store.PasswordDictionary{Active: j.Dictionary.Active, Default: j.Dictionary.Default, Custom: j.Dictionary.Custom},
		ProfileData: store.PasswordProfileData{Active: j.ProfileData.Active, BlockedFields: j.ProfileData.BlockedFields},
	}
}
