package api

import (
	"fmt"

	"github.com/supabase-community/scim-go/pkg/filter"
	"github.com/supabase-community/scim-go/pkg/protocol"
	"github.com/supabase-community/scim-go/pkg/scimerrors"
	"github.com/supabase/auth/internal/models"
)

type scimEqFilter struct {
	name string
}

func (f scimEqFilter) Compare(attribute *protocol.Attribute, op filter.Operator, value any) (models.SCIMFilter, error) {
	text, isString := value.(string)
	isEquals := op == filter.OpEquals
	isTopLevel := attribute.Parent == nil
	if !isEquals || !isTopLevel || !isString {
		return f.unsupported()
	}
	switch attribute.Definition.Name {
	case f.name:
		return models.SCIMFilter{Name: &text}, nil
	case "externalId":
		return models.SCIMFilter{ExternalID: &text}, nil
	}
	return f.unsupported()
}

func (f scimEqFilter) Present(*protocol.Attribute) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimEqFilter) And(models.SCIMFilter, models.SCIMFilter) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimEqFilter) Or(models.SCIMFilter, models.SCIMFilter) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimEqFilter) Not(models.SCIMFilter) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimEqFilter) ValuePath(*protocol.Attribute, func() (models.SCIMFilter, error)) (models.SCIMFilter, error) {
	return f.unsupported()
}

func (f scimEqFilter) unsupported() (models.SCIMFilter, error) {
	return models.SCIMFilter{}, scimerrors.ErrInvalidFilter(fmt.Sprintf(`only "%s eq" and "externalId eq" filters are supported`, f.name))
}
