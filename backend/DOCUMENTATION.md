# Water Quality Monitor – Backend Authentication

## Overview
This module implements secure user authentication for the Water Quality Monitor application.

## Features Implemented
- User registration (signup)
- User login with JWT token generation
- Protected profile endpoint
- Token-based authentication using Authorization header

## Tech Stack
- FastAPI
- SQLModel
- SQLite
- JWT (PyJWT)
- Uvicorn

## Authentication Flow
1. User signs up using /signup
2. User logs in using /login and receives JWT accessToken
3. Client sends token in Authorization header
4. Protected routes validate token before returning data

## Status
Milestone 1 backend authentication completed and tested successfully.
