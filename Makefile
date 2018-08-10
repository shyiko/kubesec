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
	env CGO_ENABLED=0 gox -verbose \
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
	sh .deploy-to-homebrew

build-docker-image:
	docker build -f kubesec-playground.dockerfile --build-arg KUBESEC_VERSION=${VERSION} -t shyiko/kubesec-playground:${VERSION} .

push-docker-image: build-docker-image
	docker push shyiko/kubesec-playground:${VERSION}


