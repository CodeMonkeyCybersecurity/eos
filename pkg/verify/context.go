// pkg/verify/context.go

package verify

func NewContext() *Context {
	return &Context{}
}

func (v *Context) ValidateAll(schema string, obj interface{}) error {
	if err := ValidateStructWithGoPlayground(obj); err != nil {
		return err
	}
	if err := ValidateStructWithCUE(schema, obj); err != nil {
		return err
	}
	if err := EvaluateOPA(schema+".rego", obj); err != nil {
		return err
	}
	return nil
}
