package connrules

import (
	"fmt"
	"slices"

	"github.com/zeroauthy/zeroauthy/internal/store"
)

// defaultMinLength is the minimum password length of an API-created
// connection (D-0042, observed). A seeded connection that names none keeps
// zeroauthy's own default, which the store keeps as zero.
const defaultMinLength = 15

// defaultHistorySize is the history size Auth0 reports for an inactive rule.
const defaultHistorySize = 3

// DefaultBlockedFields are the profile_data.blocked_fields of a new
// connection (D-0042, observed).
var DefaultBlockedFields = []string{
	"name", "username", "nickname", "email", "phone_number",
	"user_metadata.name", "user_metadata.first", "user_metadata.last",
}

// PasswordOptions is options.password_options, the password model zeroauthy
// stores. A nil part is not named: the seed leaves it alone, and
// NormalizeAPI fills it with the defaults.
type PasswordOptions struct {
	Complexity  *Complexity  `json:"complexity,omitempty" yaml:"complexity"`
	History     *History     `json:"history,omitempty" yaml:"history"`
	Dictionary  *Dictionary  `json:"dictionary,omitempty" yaml:"dictionary"`
	ProfileData *ProfileData `json:"profile_data,omitempty" yaml:"profile_data"`
}

// Complexity is password_options.complexity. Zero strings mean the default.
type Complexity struct {
	MinLength            int      `json:"min_length" yaml:"min_length"`
	CharacterTypes       []string `json:"character_types" yaml:"character_types"`
	CharacterTypeRule    string   `json:"character_type_rule,omitempty" yaml:"character_type_rule"`
	IdenticalCharacters  string   `json:"identical_characters,omitempty" yaml:"identical_characters"`
	SequentialCharacters string   `json:"sequential_characters,omitempty" yaml:"sequential_characters"`
	MaxLengthExceeded    string   `json:"max_length_exceeded,omitempty" yaml:"max_length_exceeded"`
	// MinCharacterClasses is zeroauthy's own: the seed's
	// require_character_classes of 1 or 2 (store.PasswordComplexity). It is
	// not part of Auth0's wire shape or of the seed's password_options.
	MinCharacterClasses int `json:"-" yaml:"-"`
}

// History is password_options.history.
type History struct {
	Active bool `json:"active" yaml:"active"`
	Size   int  `json:"size" yaml:"size"`
}

// Dictionary is password_options.dictionary.
type Dictionary struct {
	Active  bool     `json:"active" yaml:"active"`
	Default string   `json:"default,omitempty" yaml:"default"`
	Custom  []string `json:"custom" yaml:"custom"`
}

// ProfileData is password_options.profile_data.
type ProfileData struct {
	Active        bool     `json:"active" yaml:"active"`
	BlockedFields []string `json:"blocked_fields" yaml:"blocked_fields"`
}

// The legacy password fields of options (Auth0's old model).
type (
	// LegacyComplexity is password_complexity_options.
	LegacyComplexity struct {
		MinLength int `json:"min_length"`
	}
	// LegacyHistory is password_history.
	LegacyHistory struct {
		Enable bool `json:"enable"`
		Size   int  `json:"size,omitempty"`
	}
	// LegacyDictionary is password_dictionary.
	LegacyDictionary struct {
		Enable     bool     `json:"enable"`
		Dictionary []string `json:"dictionary,omitempty"`
	}
	// LegacyEnable is password_no_personal_info.
	LegacyEnable struct {
		Enable bool `json:"enable"`
	}
)

// legacyLevels are the passwordPolicy levels, mapped onto complexity from
// Auth0's description of password strength levels:
// https://auth0.com/docs/authenticate/database-connections/password-strength
//
//	none      at least 1 character
//	low       at least 6 characters
//	fair      at least 8, with lower case, upper case and numbers
//	good      at least 8, with three of lower case, upper case, numbers and
//	          special characters
//	excellent at least 10, no more than 2 identical characters in a row,
//	          with lower case, upper case, numbers and special characters
//
// An explicit password_complexity_options.min_length overrides the level's
// length.
var legacyLevels = map[string]Complexity{
	"none": {MinLength: 1},
	"low":  {MinLength: 6},
	"fair": {MinLength: 8, CharacterTypes: []string{
		store.CharacterTypeLowercase, store.CharacterTypeUppercase, store.CharacterTypeNumber}},
	"good": {MinLength: 8, CharacterTypes: store.CharacterTypes, CharacterTypeRule: store.CharacterTypeRuleThreeOfFour},
	"excellent": {MinLength: 10, CharacterTypes: store.CharacterTypes,
		IdenticalCharacters: store.PasswordBlock},
}

// mapLegacy turns the legacy password fields into a PasswordOptions and
// clears them.
func mapLegacy(o *Options) (*PasswordOptions, []error) {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }
	po := &PasswordOptions{}

	var cx *Complexity
	if o.PasswordPolicy != "" {
		lvl, ok := legacyLevels[o.PasswordPolicy]
		if !ok {
			fail("passwordPolicy %q must be none, low, fair, good or excellent", o.PasswordPolicy)
		} else {
			lvl.CharacterTypes = slices.Clone(lvl.CharacterTypes)
			cx = &lvl
		}
	}
	if lc := o.PasswordComplexity; lc != nil {
		if lc.MinLength < 1 || lc.MinLength > 128 {
			fail("password_complexity_options.min_length must be 1 to 128")
		} else if lc.MinLength > 72 {
			fail("password_complexity_options.min_length above 72 cannot be met: passwords are limited to 72 characters")
		}
		if cx == nil {
			cx = &Complexity{}
		}
		cx.MinLength = lc.MinLength
	}
	po.Complexity = cx
	if h := o.PasswordHistory; h != nil {
		po.History = &History{Active: h.Enable, Size: h.Size}
	}
	if d := o.PasswordDictionary; d != nil {
		po.Dictionary = &Dictionary{Active: d.Enable, Custom: slices.Clone(d.Dictionary)}
	}
	if p := o.PasswordNoPersonalInfo; p != nil {
		po.ProfileData = &ProfileData{Active: p.Enable}
	}
	o.PasswordPolicy, o.PasswordComplexity, o.PasswordHistory = "", nil, nil
	o.PasswordDictionary, o.PasswordNoPersonalInfo = nil, nil
	return po, errs
}

func normalizePasswords(o *Options, api bool) []error {
	var errs []error
	fail := func(format string, args ...any) { errs = append(errs, fmt.Errorf(format, args...)) }

	legacy := o.PasswordPolicy != "" || o.PasswordComplexity != nil || o.PasswordHistory != nil ||
		o.PasswordDictionary != nil || o.PasswordNoPersonalInfo != nil
	switch {
	case legacy && o.PasswordOptions != nil:
		fail("password_options cannot be combined with passwordPolicy, password_complexity_options, password_history, password_dictionary or password_no_personal_info")
		return errs
	case legacy:
		po, lerrs := mapLegacy(o)
		errs = append(errs, lerrs...)
		o.PasswordOptions = po
	}
	if o.PasswordOptions == nil && api {
		o.PasswordOptions = &PasswordOptions{}
	}
	po := o.PasswordOptions
	if po == nil {
		return errs
	}

	if po.Complexity == nil && api {
		po.Complexity = &Complexity{}
	}
	if c := po.Complexity; c != nil {
		max := maxMinLength(api)
		switch {
		case c.MinLength == 0 && api:
			c.MinLength = defaultMinLength
		case c.MinLength < 0 || c.MinLength > max:
			fail("password_options.complexity.min_length must be 1 to %d", max)
		}
		for i, t := range c.CharacterTypes {
			if !slices.Contains(store.CharacterTypes, t) {
				fail("character_types %q must be any of %v", t, store.CharacterTypes)
			} else if slices.Contains(c.CharacterTypes[:i], t) {
				fail("character_types lists %q twice", t)
			}
		}
		if c.CharacterTypes == nil {
			c.CharacterTypes = []string{}
		}
		setDefault(&c.CharacterTypeRule, store.CharacterTypeRuleAll)
		setDefault(&c.IdenticalCharacters, store.PasswordAllow)
		setDefault(&c.SequentialCharacters, store.PasswordAllow)
		setDefault(&c.MaxLengthExceeded, store.MaxLengthError)
		switch c.CharacterTypeRule {
		case store.CharacterTypeRuleAll:
		case store.CharacterTypeRuleThreeOfFour:
			if len(c.CharacterTypes) != len(store.CharacterTypes) {
				fail("character_type_rule three_of_four needs all four character_types")
			}
		default:
			fail("character_type_rule %q must be %s or %s", c.CharacterTypeRule,
				store.CharacterTypeRuleAll, store.CharacterTypeRuleThreeOfFour)
		}
		for name, v := range map[string]string{"identical_characters": c.IdenticalCharacters, "sequential_characters": c.SequentialCharacters} {
			if v != store.PasswordAllow && v != store.PasswordBlock {
				fail("%s %q must be %s or %s", name, v, store.PasswordAllow, store.PasswordBlock)
			}
		}
		if c.MaxLengthExceeded != store.MaxLengthError && c.MaxLengthExceeded != store.MaxLengthTruncate {
			fail("max_length_exceeded %q must be %s or %s", c.MaxLengthExceeded, store.MaxLengthError, store.MaxLengthTruncate)
		}
		if c.MinCharacterClasses < 0 || c.MinCharacterClasses > 2 {
			fail("min character classes must be 0 to 2")
		}
	}

	if po.History == nil && api {
		po.History = &History{}
	}
	if h := po.History; h != nil {
		if h.Size == 0 {
			h.Size = defaultHistorySize
		}
		if h.Size < 1 || h.Size > 24 {
			fail("password_options.history.size must be 1 to 24")
		}
	}

	if po.Dictionary == nil && api {
		po.Dictionary = &Dictionary{}
	}
	if d := po.Dictionary; d != nil {
		setDefault(&d.Default, store.DictionaryEn100k)
		if d.Default != store.DictionaryEn10k && d.Default != store.DictionaryEn100k {
			fail("dictionary.default %q must be %s or %s", d.Default, store.DictionaryEn10k, store.DictionaryEn100k)
		}
		if d.Custom == nil {
			d.Custom = []string{}
		}
	}

	if po.ProfileData == nil && api {
		po.ProfileData = &ProfileData{}
	}
	if p := po.ProfileData; p != nil && p.BlockedFields == nil {
		p.BlockedFields = slices.Clone(DefaultBlockedFields)
	}
	return errs
}

func setDefault(field *string, def string) {
	if *field == "" {
		*field = def
	}
}

// applyPasswords copies the parts of in that are named into the stored
// options. Empty lists are stored as nil.
func applyPasswords(in *PasswordOptions, out *store.PasswordOptions) {
	if in == nil {
		return
	}
	if c := in.Complexity; c != nil {
		out.Complexity = store.PasswordComplexity{
			MinLength:            c.MinLength,
			CharacterTypes:       nilIfEmpty(c.CharacterTypes),
			CharacterTypeRule:    c.CharacterTypeRule,
			IdenticalCharacters:  c.IdenticalCharacters,
			SequentialCharacters: c.SequentialCharacters,
			MaxLengthExceeded:    c.MaxLengthExceeded,
			MinCharacterClasses:  c.MinCharacterClasses,
		}
	}
	if h := in.History; h != nil {
		out.History = store.PasswordHistory{Active: h.Active, Size: h.Size}
	}
	if d := in.Dictionary; d != nil {
		out.Dictionary = store.PasswordDictionary{Active: d.Active, Default: d.Default, Custom: nilIfEmpty(d.Custom)}
	}
	if p := in.ProfileData; p != nil {
		out.ProfileData = store.PasswordProfileData{Active: p.Active, BlockedFields: nilIfEmpty(p.BlockedFields)}
	}
}

// fromPasswords renders stored options in Auth0's terms: zero values read
// as the defaults they mean (zeroauthy's minimum length of 8 when unset).
func fromPasswords(in *store.PasswordOptions) *PasswordOptions {
	c := in.Complexity
	cx := &Complexity{
		MinLength:            c.MinLength,
		CharacterTypes:       orEmpty(c.CharacterTypes),
		CharacterTypeRule:    c.CharacterTypeRule,
		IdenticalCharacters:  c.IdenticalCharacters,
		SequentialCharacters: c.SequentialCharacters,
		MaxLengthExceeded:    c.MaxLengthExceeded,
		MinCharacterClasses:  c.MinCharacterClasses,
	}
	if cx.MinLength == 0 {
		cx.MinLength = 8
	}
	setDefault(&cx.CharacterTypeRule, store.CharacterTypeRuleAll)
	setDefault(&cx.IdenticalCharacters, store.PasswordAllow)
	setDefault(&cx.SequentialCharacters, store.PasswordAllow)
	setDefault(&cx.MaxLengthExceeded, store.MaxLengthError)

	h := &History{Active: in.History.Active, Size: in.History.Size}
	if h.Size == 0 {
		h.Size = defaultHistorySize
	}
	d := &Dictionary{Active: in.Dictionary.Active, Default: in.Dictionary.Default, Custom: orEmpty(in.Dictionary.Custom)}
	setDefault(&d.Default, store.DictionaryEn100k)
	p := &ProfileData{Active: in.ProfileData.Active, BlockedFields: orEmpty(in.ProfileData.BlockedFields)}
	if len(p.BlockedFields) == 0 {
		p.BlockedFields = slices.Clone(DefaultBlockedFields)
	}
	return &PasswordOptions{Complexity: cx, History: h, Dictionary: d, ProfileData: p}
}
