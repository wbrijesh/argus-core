docker-build:
	docker build -t brijeshwawdhane/argus-core:0.1.1-alpha.1 .

docker-push:
	docker push brijeshwawdhane/argus-core:0.1.1-alpha.1

k-deployment-reapply:
	kubectl delete -f k8s/deployment.yaml
	kubectl apply -f k8s/deployment.yaml

k-rbac-reapply:
	kubectl delete -f k8s/rbac.yaml
	kubectl apply -f k8s/rbac.yaml

k-service-reapply:
	kubectl delete -f k8s/service.yaml
	kubectl apply -f k8s/service.yaml

watch:
	@if command -v air > /dev/null; then \
            air; \
            echo "Watching...";\
        else \
            read -p "Go's 'air' is not installed on your machine. Do you want to install it? [Y/n] " choice; \
            if [ "$$choice" != "n" ] && [ "$$choice" != "N" ]; then \
                go install github.com/air-verse/air@latest; \
                air; \
                echo "Watching...";\
            else \
                echo "You chose not to install air. Exiting..."; \
                exit 1; \
            fi; \
        fi

.PHONY: docker-build docker-push k-deployment-reapply k-rbac-reapply k-service-reapply watch
