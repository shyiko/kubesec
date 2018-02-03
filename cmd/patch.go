package cmd

import "encoding/base64"

type PatchOpt struct {
	Name                  string
	ClearTextDataMutation map[string][]byte
	KeySetMutation        KeySetMutation
	Rotate                bool
}

func Patch(resource []byte, opt PatchOpt) ([]byte, error) {
	rs, ctx, err := decrypt(resource, false)
	if err != nil {
		return nil, err
	}
	if !ctx.IsEmpty() {
		if err := validateMAC(rs, *ctx); err != nil {
			return nil, err
		}
	}
	// mutate metadata
	if opt.Name != "" {
		metadata, ok := rs["metadata"].(map[interface{}]interface{})
		if !ok {
			metadata = make(map[interface{}]interface{})
			rs["metadata"] = metadata
		}
		metadata["name"] = opt.Name
	}
	// mutate data
	data := rs.data()
	if data == nil {
		data = make(map[string]string)
	}
	for key, value := range opt.ClearTextDataMutation {
		if value == nil {
			delete(data, key)
		} else {
			data[key] = base64.StdEncoding.EncodeToString(value)
		}
	}
	rs.setData(data)
	// mutate keyset
	opt.KeySetMutation.applyTo(ctx)
	// force DEK rotation if requested
	if opt.Rotate {
		ctx.RotateDEK()
	}
	output, err := marshal(rs)
	if err != nil {
		return nil, err
	}
	return EncryptWithContext(output, *ctx)
}
