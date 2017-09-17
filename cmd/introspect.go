package cmd

import (
	"errors"
	"fmt"
	"github.com/shyiko/kubesec/gpg"
	"strings"
)

func Introspect(resource []byte) ([]byte, error) {
	if !IsEncrypted(resource) {
		return nil, errors.New("Not encrypted")
	}
	ctx, err := reconstructEncryptionContext(resource, false, false)
	if err != nil {
		return nil, err
	}
	var res []string
	for _, keyType := range KeyTypes {
		list, err := listKeysByKeyType(ctx, keyType)
		if err != nil {
			return nil, err
		}
		if len(list) != 0 {
			var header string
			switch keyType {
			case KTPGP:
				header = "# PGP fingerprint(s)"
			case KTGCPKMS:
				header = "# GCP KMS key(s)"
			case KTAWSKMS:
				header = "# AWS KMS key(s)"
			default:
				panic(fmt.Sprintf("Unexpected Key.Type %v", keyType))
			}
			res = append(res, header)
			res = append(res, list...)
		}
	}
	return []byte(strings.Join(res, "\n")), nil
}

func listKeysByKeyType(ctx *EncryptionContext, keyType KeyType) ([]string, error) {
	switch keyType {
	case KTPGP:
		return listPGPKeys(ctx)
	case KTGCPKMS:
		return listGCPKMSKeys(ctx)
	case KTAWSKMS:
		return listAWSKMSKeys(ctx)
	default:
		panic(fmt.Sprintf("Unexpected Key.Type %v", keyType))
	}
}

func listPGPKeys(ctx *EncryptionContext) ([]string, error) {
	fpList, err := keyIds(ctx, KTPGP)
	if err != nil {
		return nil, err
	}
	if len(fpList) == 0 {
		return nil, nil
	}
	knownKeys, err := gpg.ListKeys()
	if err != nil {
		return nil, err
	}
	uidByFP := make(map[string]string)
	for _, key := range knownKeys {
		uidByFP[key.Fingerprint] = strings.Join(key.UserId, ", ")
	}
	var res []string
	//var unknownFPs []string
	for _, fp := range fpList {
		uid, ok := uidByFP[fp]
		if !ok {
			uid = "UNKNOWN"
		}
		//unknownFPs = append(unknownFPs, fp)
		res = append(res, fp+" "+uid)
	}
	//if len(unknownFPs) > 0 {
	//	res = append(res, "# use `gpg --recv-keys " + strings.Join(unknownFPs, " ") + "` to import missing key(s)")
	//}
	return res, nil
}

func listGCPKMSKeys(ctx *EncryptionContext) ([]string, error) {
	list, err := keyIds(ctx, KTGCPKMS)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	var res []string
	res = append(res, list...)
	return res, nil
}

func listAWSKMSKeys(ctx *EncryptionContext) ([]string, error) {
	list, err := keyIds(ctx, KTAWSKMS)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, nil
	}
	var res []string
	res = append(res, list...)
	return res, nil
}

func keyIds(ctx *EncryptionContext, keyType KeyType) ([]string, error) {
	var res []string
	for _, key := range ctx.Keys {
		if key.Type == keyType {
			res = append(res, key.Id)
		}
	}
	return res, nil
}
