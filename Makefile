.PHONY: all local docker-build-release

all: local

local:
	CGO_ENABLED=0 go build -o ./bin/olm

docker-build-release:
	@if [ -z "$(tag)" ]; then \
		echo "Error: tag is required. Usage: make docker-build-release tag=<tag>"; \
		exit 1; \
	fi
	docker buildx build . \
		--platform linux/arm/v7,linux/arm64,linux/amd64 \
		-t fosrl/olm:latest \
		-t fosrl/olm:$(tag) \
		-f Dockerfile \
		--push

.PHONY: go-build-release \
        go-build-release-linux-arm64 go-build-release-linux-arm32-v7 \
        go-build-release-linux-arm32-v6 go-build-release-linux-amd64 \
        go-build-release-linux-riscv64 go-build-release-darwin-arm64 \
        go-build-release-darwin-amd64 go-build-release-windows-amd64

go-build-release: \
    go-build-release-linux-arm64 \
    go-build-release-linux-arm32-v7 \
    go-build-release-linux-arm32-v6 \
    go-build-release-linux-amd64 \
    go-build-release-linux-riscv64 \
    go-build-release-darwin-arm64 \
    go-build-release-darwin-amd64 \
    go-build-release-windows-amd64 \

go-build-release-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/olm_linux_arm64

go-build-release-linux-arm32-v7:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=7 go build -o bin/olm_linux_arm32

go-build-release-linux-arm32-v6:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm GOARM=6 go build -o bin/olm_linux_arm32v6

go-build-release-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/olm_linux_amd64

go-build-release-linux-riscv64:
	CGO_ENABLED=0 GOOS=linux GOARCH=riscv64 go build -o bin/olm_linux_riscv64

go-build-release-darwin-arm64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/olm_darwin_arm64

go-build-release-darwin-amd64:
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/olm_darwin_amd64

go-build-release-windows-amd64:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/olm_windows_amd64.exe
