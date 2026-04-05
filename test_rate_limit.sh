#!/bin/bash

echo "Testing rate limiting on /auth/login..."
echo "Sending 6 rapid requests..."

for i in {1..6}; do
    echo "Request $i:"
    curl -s -o /dev/null -w "HTTP Status: %{http_code}\n" \
      -X POST http://localhost:3000/auth/login \
      -H "Content-Type: application/json" \
      -d '{"username":"nonexistent","password":"wrong","pin":"123456"}'
    sleep 0.5
done
