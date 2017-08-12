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
	fpList, err := listPGPFP(resource)
	if err != nil {
		return nil, err
	}
	if len(fpList) == 0 {
		return []byte{}, nil
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
	return []byte(strings.Join(res, "\n")), nil
}

func listPGPFP(resource []byte) ([]string, error) {
	ctx, err := reconstructEncryptionContext(resource, false)
	if err != nil {
		return nil, err
	}
	var fps []string
	for _, key := range ctx.Keys {
		fps = append(fps, key.Fingerprint)
	}
	return fps, nil
}
