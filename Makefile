.PHONY: build test run clean deps lint

APP_NAME=samlguard
BUILD_DIR=bin

build:
	@echo "Building $(APP_NAME)..."
	go build -o $(BUILD_DIR)/$(APP_NAME) ./cmd/samlguard

test:
	@echo "Running tests..."
	go test -v ./...

run: build
	@echo "Running $(APP_NAME)..."
	./$(BUILD_DIR)/$(APP_NAME)

clean:
	@echo "Cleaning up..."
	rm -rf $(BUILD_DIR)

deps:
	@echo "Tidying dependencies..."
	go mod tidy

lint:
	@echo "Linting..."
	golangci-lint run
