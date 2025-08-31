
all: go-build-release 

docker-build-release:
	@if [ -z "$(tag)" ]; then \
		echo "Error: tag is required. Usage: make docker-build-release tag=<tag>"; \
		exit 1; \
	fi
	docker buildx build --platform linux/arm/v7,linux/arm64,linux/amd64 -t fosrl/olm:latest -f Dockerfile --push .
	docker buildx build --platform linux/arm/v7,linux/arm64,linux/amd64 -t fosrl/olm:$(tag) -f Dockerfile --push .

local: 
	CGO_ENABLED=0 go build -o olm

build:
	docker build -t fosrl/olm:latest .

go-build-release:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/olm_linux_arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/olm_linux_amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/olm_darwin_arm64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/olm_darwin_amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/olm_windows_amd64.exe
	
clean:
	rm olm