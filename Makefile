IMAGE_NAME=mitigationtool
DOCKER_COMPOSE_COMMAND := docker-compose up -d

.PHONY: build run stop clean

build:
	@echo "Building Docker image $(IMAGE_NAME)"
	docker build -t $(IMAGE_NAME) .

run:
	@echo "Starting project's main container"
	$(DOCKER_COMPOSE_COMMAND) 
	
stop:
	@echo "Stopping Docker image with name $(IMAGE_NAME)"
	docker-compose down

clean:
	@echo "Removing Docker image with name $(IMAGE_NAME)"
	docker rmi $(IMAGE_NAME)