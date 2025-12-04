#!/bin/bash
# Stop backend (Flask/Redis) and frontend (React)
docker compose down
if [ -f frontend.pid ]; then
	kill $(cat frontend.pid) && rm frontend.pid
	echo "Stopped React dev server."
else
	echo "No React dev server PID file found."
fi
