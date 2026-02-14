# Infino API Documentation

This folder contains the OpenAPI specification for the Infino API and SDK documentation.

## Files

- `openapi.yaml` - OpenAPI 3.1.0 specification
- [connectors.md](connectors.md) - Connectors: supported sources, SDK usage, and how to find required configs

## Viewing the API Documentation Locally

### Option 1: Swagger Editor (No Setup Required)

1. Go to [Swagger Editor](https://editor.swagger.io)
2. Click **File → Import File**
3. Select `openapi.yaml` from this folder

### Option 2: Local Server + Swagger UI

1. Start a local HTTP server from the project root:

   ```bash
   npx http-server docs -p 8080 --cors
   ```

2. Open [Swagger UI](https://petstore.swagger.io)

3. In the explore bar at the top, enter:

   ```
   http://localhost:8080/openapi.yaml
   ```

4. Click **Explore** to view the documentation

5. To stop the server, press `Ctrl+C` in the terminal
