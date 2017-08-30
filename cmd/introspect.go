package cmd

import (
	"errors"
	"github.com/shyiko/kubesec/gpg"
	"strings"
)

func Introspect(resource []byte) ([]byte, error) {
	if !IsEncrypted(resource) {
		return nil, errors.New("Not encrypted")
	}
	ctx, err := reconstructEncryptionContext(resource, false)
	if err != nil {
		return nil, err
	}
	var res []string
	for _, fn := range []func(*EncryptionContext) ([]string, error){
		listPGPKeys, listGCPKMSKeys, listAWSKMSKeys,
	} {
		list, err := fn(ctx)
		if err != nil {
			return nil, err
		}
		res = append(res, list...)
	}
	return []byte(strings.Join(res, "\n")), nil
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
	res = append(res, "# PGP fingerprint(s)")
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
	res = append(res, "# GCP KMS key(s)")
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
	res = append(res, "# AWS KMS key(s)")
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
