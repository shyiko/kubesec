SHELL := /bin/bash -o pipefail
VERSION := $(shell git describe --tags --abbrev=0)

fetch:
	go get \
	github.com/mitchellh/gox \
	github.com/Masterminds/glide \
	github.com/modocache/gover \
	github.com/aktau/github-release && \
	glide install

clean:
	rm -f ./kubesec
	rm -rf ./build

fmt:
	gofmt -l -s -w `find . -type f -name '*.go' -not -path "./vendor/*" -not -path "./.tmp/*"`

test:
	KUBESEC_TEST_AWS_KMS_KEY= KUBESEC_TEST_GCP_KMS_KEY= make .test

test-integration:
	test -n "$(KUBESEC_TEST_AWS_KMS_KEY)" # $$KUBESEC_TEST_AWS_KMS_KEY must be set
	test -n "$(KUBESEC_TEST_GCP_KMS_KEY)" # $$KUBESEC_TEST_GCP_KMS_KEY must be set
	make .test

.test:
	go vet `go list ./... | grep -v /vendor/`
	SRC=`find . -type f -name '*.go' -not -path "./vendor/*" -not -path "./.tmp/*"` && \
		gofmt -l -s $$SRC | read && gofmt -l -s -d $$SRC && exit 1 || true
	go test -v `go list ./... | grep -v /vendor/` | grep -v "=== RUN"

test-coverage:
	go list ./... | grep -v /vendor/ | xargs -L1 -I{} sh -c 'go test -coverprofile `basename {}`.coverprofile {}' && \
	gover && \
	go tool cover -html=gover.coverprofile -o coverage.html && \
	rm -f *.coverprofile

build:
	go build -ldflags "-X main.version=${VERSION}"

build-release:
	gox -verbose \
	-ldflags "-X main.version=${VERSION}" \
	-osarch="windows/amd64 linux/amd64 darwin/amd64" \
	-output="release/{{.Dir}}-${VERSION}-{{.OS}}-{{.Arch}}" .

sign-release:
	for file in $$(ls release/kubesec-${VERSION}-*); do gpg --detach-sig --sign -a $$file; done

publish: clean build-release sign-release
	test -n "$(GITHUB_TOKEN)" # $$GITHUB_TOKEN must be set
	github-release release --user shyiko --repo kubesec --tag ${VERSION} \
	--name "${VERSION}" --description "${VERSION}" && \
	github-release upload --user shyiko --repo kubesec --tag ${VERSION} \
	--name "kubesec-${VERSION}-windows-amd64.exe" --file release/kubesec-${VERSION}-windows-amd64.exe; \
	github-release upload --user shyiko --repo kubesec --tag ${VERSION} \
	--name "kubesec-${VERSION}-windows-amd64.exe.asc" --file release/kubesec-${VERSION}-windows-amd64.exe.asc; \
	for qualifier in darwin-amd64 linux-amd64 ; do \
		github-release upload --user shyiko --repo kubesec --tag ${VERSION} \
		--name "kubesec-${VERSION}-$$qualifier" --file release/kubesec-${VERSION}-$$qualifier; \
		github-release upload --user shyiko --repo kubesec --tag ${VERSION} \
		--name "kubesec-${VERSION}-$$qualifier.asc" --file release/kubesec-${VERSION}-$$qualifier.asc; \
	done

build-docker-image:
	rm -rf /tmp/kubesec-playground && \
	mkdir /tmp/kubesec-playground && \
	docker run --rm -v $$(pwd):/workdir -v /tmp/kubesec-playground:/tmp -w /workdir node:8.2.1 \
		bash -c $$' \
		    npm --no-package-lock i gfm-code-blocks mkdirp 1>/dev/null 2>/tmp/npm.log && \
			NODE_PATH=/usr/local/lib/node_modules/ node -e \'require("gfm-code-blocks")(require("fs").readFileSync("README.md", "utf8")).filter(({lang, code}) => lang === "yml" && code.includes("\\n# snippet:")).forEach(({code}) => { const f = code.match("# snippet:(\\\\S+)")[1]; require("mkdirp").sync(`/tmp/README.md/$${require("path").dirname(f)}`); fs.writeFileSync(`/tmp/README.md/$${f}`, code) })\' && \
			chmod -R a+rw /tmp/README.md' && \
	cp -r .ci /tmp/kubesec-playground/ && \
	cp kubesec-playground.dockerfile /tmp/kubesec-playground/Dockerfile && \
	KUBETPL_VERSION=0.1.0 bash -c 'cd /tmp/kubesec-playground && docker build --build-arg KUBETPL_VERSION=$$KUBETPL_VERSION --build-arg KUBESEC_VERSION=${VERSION} -t shyiko/kubesec-playground:${VERSION}-with-kubetpl-$$KUBETPL_VERSION .'

push-docker-image:
	KUBETPL_VERSION=0.1.0 bash -c 'docker push shyiko/kubesec-playground:${VERSION}-with-kubetpl-$$KUBETPL_VERSION'


