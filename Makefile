
all: go-build-release 

local: 
	CGO_ENABLED=0 go build -o olm

go-build-release:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/olm_linux_arm64
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/olm_linux_amd64
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o bin/olm_darwin_arm64
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/olm_darwin_amd64
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/olm_windows_amd64.exe
	
clean:
	rm olm