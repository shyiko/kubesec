package cmd

import (
	"errors"
)

func Merge(source []byte, target []byte) ([]byte, error) {
	if !IsEncrypted(source) {
		return nil, errors.New("[source] must be encrypted")
	}
	if IsEncrypted(target) {
		return nil, errors.New("[target] must not be encrypted")
	}
	targetRS, err := unmarshal(target)
	if err != nil {
		return nil, err
	}
	var ctx *EncryptionContext
	var decryptedSource []byte
	decryptedSource, ctx, err = Decrypt(source)
	if err != nil {
		return nil, err
	}
	sourceRS, err := unmarshal(decryptedSource)
	if err != nil {
		return nil, err
	}
	targetRS.mergeDataFrom(sourceRS)
	rs, err := marshal(targetRS)
	if err != nil {
		return nil, err
	}
	return EncryptWithContext(rs, *ctx)
}

func (rs resource) containsAllDataOf(other resource) bool {
	otherData := other.data()
	for key := range rs.data() {
		if _, ok := otherData[key]; !ok {
			return false
		}
	}
	return true
}

func (rs resource) mergeDataFrom(other resource) {
	otherData := other.data()
	m := make(map[string]string)
	for key, value := range rs.data() {
		if otherValue, ok := otherData[key]; ok {
			m[key] = otherValue
		} else {
			m[key] = value
		}
	}
	rs.setData(m)
}
