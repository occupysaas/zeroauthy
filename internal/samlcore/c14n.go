package samlcore

import (
	dsig "github.com/zeroauthy/zeroauthy/internal/third_party/goxmldsig"
	"github.com/zeroauthy/zeroauthy/internal/third_party/etree"
)

// Canonicalize returns the Exclusive XML Canonicalization 1.0 form of el,
// with or without comments. el is copied first; the caller's tree is never
// modified.
func Canonicalize(el *etree.Element, withComments bool) ([]byte, error) {
	if el == nil {
		return nil, ErrMalformed
	}
	var c dsig.Canonicalizer
	if withComments {
		c = dsig.MakeC14N10ExclusiveWithCommentsCanonicalizerWithPrefixList("")
	} else {
		c = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	}
	out, err := c.Canonicalize(el.Copy())
	if err != nil {
		return nil, errorf("canonicalization failed")
	}
	return out, nil
}
