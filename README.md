# Fotogram: Backend Project

Backend and database university project developed for a social-network-style application focused on image sharing.

## Overview

This project was developed as part of a university course and includes the backend and database design for a social media platform.  
The application supports core features such as user authentication, profile management, post handling and other social interaction functionalities.

The project also includes API documentation and database design materials.

## Technologies

- Node.js
- Express
- PostgreSQL
- SQL
- JWT
- Swagger

## Main Features

- User authentication and authorization
- REST API development
- Profile and post management
- Database interaction with PostgreSQL
- API documentation with Swagger

## Project Structure

- `index.js` – main entry point of the application
- `endpoints.js` – API routes and endpoint logic
- `swagger.js` – Swagger configuration
- `swaggerFile.json` – generated Swagger documentation
- `package.json` – project dependencies and scripts 
- `resources/` – additional project resources
- `doc/` – project documentation, assignment PDF and ER diagrams
- `sql/` – SQL scripts for database creation and structure

## Documentation

The repository also contains:
- project documentation
- ER diagrams
- database-related files
- the original project assignment

## How to run the project

1. Clone the repository

   git clone <repository-url>
   cd <repository-folder>

2. Install dependencies

    npm install

3. Set up the PostgreSQL database

    Create a local PostgreSQL database and run the SQL script contained in the sql/ folder to create and populate the required tables

4. Configure the database connection

    Update the database connection settings in 'endpoints.js' according to your local PostgreSQL configuration (for example: host, user, password, database name, port)

5. Start the server

    npm start

6. Access the API / Swagger documentation

    Once the server is running, the API and Swagger documentation can be accessed locally through the configured server port 
    (for example: localhost:3000/doc/)

## Notes

This repository was created to showcase an academic backend project and its related database design work.

## Author

Matteo Pelle