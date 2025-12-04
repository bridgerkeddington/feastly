#!/bin/bash
# Start backend (Flask/Redis) and frontend (React)
docker compose up --build -d
cd frontend && npm start &
echo $! > ../frontend.pid
cd ..
