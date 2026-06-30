#!/bin/bash
echo "Running E2E tests..."
docker compose up -d
sleep 5
docker compose down
