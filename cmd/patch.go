package cmd

import "encoding/base64"

type PatchOpt struct {
	Metadata              map[string]string
	Annotations           map[string]string
	Labels                map[string]string
	ClearTextDataMutation map[string][]byte
	StringDataMutation    map[string][]byte
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
	metadata := extractMap(rs, "metadata")
	for key, value := range opt.Metadata {
		metadata[key] = value
	}
	if len(opt.Annotations) > 0 {
		annotations := extractMap(metadata, "annotations")
		for key, value := range opt.Annotations {
			annotations[key] = value
		}
	}
	if len(opt.Labels) > 0 {
		labels := extractMap(metadata, "labels")
		for key, value := range opt.Labels {
			labels[key] = value
		}
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
	// mutate stringData
	stringData := rs.stringData()
	if stringData == nil {
		stringData = make(map[string]string)
	}
	for key, value := range opt.StringDataMutation {
		if value == nil {
			delete(stringData, key)
		} else {
			stringData[key] = string(value)
		}
	}
	rs.setStringData(stringData)
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

func extractMap(m map[interface{}]interface{}, key string) map[interface{}]interface{} {
	n, ok := m[key].(map[interface{}]interface{})
	if !ok {
		n = make(map[interface{}]interface{})
		m[key] = n
	}
	return n
}
