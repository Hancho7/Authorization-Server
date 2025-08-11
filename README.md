# OAuth2 Authorization Server

A comprehensive OAuth2/OpenID Connect Authorization Server built with Spring Boot and Spring Security OAuth2 Authorization Server. This server provides secure authentication and authorization services with support for multiple OAuth2 flows and custom JWT token generation.

## 🚀 Features

- **Complete OAuth2/OpenID Connect Support**: Authorization Code, Client Credentials, Refresh Token, and Device Code flows
- **Custom JWT Token Generation**: Enhanced tokens with custom claims and user information
- **Persistent Storage**: PostgreSQL-backed storage for clients, authorizations, and consent
- **User Management**: Built-in user management with role-based access control
- **Admin Interface**: RESTful APIs for OAuth client management
- **Beautiful UI**: Modern, responsive login and consent pages
- **Docker Support**: Containerized deployment with Docker Compose
- **Production Ready**: Comprehensive security configurations and optimizations

## 🏗️ Architecture

The server is built with a modular architecture:

- **Security Layer**: OAuth2 Authorization Server configuration with custom components
- **Persistence Layer**: JPA entities for clients, authorizations, consent, and users
- **Service Layer**: Business logic for client management and token customization
- **Web Layer**: Controllers for client management and consent handling
- **Configuration**: JWT token customization and Thymeleaf templating

## 📋 Prerequisites

- Java 21 or higher
- PostgreSQL 15+
- Maven 3.8+
- Docker & Docker Compose (optional)

## 🚀 Quick Start

### Local Development

1. **Clone the repository**
   ```bash
   git clone <repository-url>
   cd authorization-server
   ```

2. **Set up PostgreSQL**
   ```bash
   # Using Docker
   docker run -d \
     --name auth-postgres \
     -e POSTGRES_DB=auth-service \
     -e POSTGRES_USER=authorization-server \
     -e POSTGRES_PASSWORD=auth@123 \
     -p 5433:5432 \
     postgres:15-alpine
   ```

3. **Configure application properties**
   ```properties
   # Database Configuration
   spring.datasource.url=jdbc:postgresql://localhost:5433/auth-service
   spring.datasource.username=authorization-server
   spring.datasource.password=auth@123
   ```

4. **Run the application**
   ```bash
   ./mvnw spring-boot:run
   ```

### Docker Deployment

```bash
# Start all services
docker-compose up -d

# Check service health
docker-compose ps
```

## 🔑 Default Users

The application automatically creates default users on startup:

| Username | Password | Roles |
|----------|----------|-------|
| `admin` | `admin123` | ADMIN, USER |
| `user` | `user123` | USER |
| `testuser` | `test123` | USER |

## 🌐 API Endpoints

### OAuth2/OpenID Connect Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /oauth2/authorize` | Authorization endpoint |
| `POST /oauth2/token` | Token endpoint |
| `GET /oauth2/jwks` | JSON Web Key Set |
| `GET /userinfo` | UserInfo endpoint |
| `GET /.well-known/openid_configuration` | OpenID Connect Discovery |
| `GET /oauth2/consent` | Consent page |
| `POST /oauth2/consent` | Consent submission |

### Authentication Endpoints

| Endpoint | Description |
|----------|-------------|
| `GET /login` | Login page |
| `POST /login` | Login form submission |
| `POST /logout` | Logout endpoint |

### Client Management API (Admin Only)

| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/admin/oauth-clients` | List all clients (paginated) |
| `GET` | `/admin/oauth-clients/{id}` | Get client by ID |
| `GET` | `/admin/oauth-clients/by-client-id/{clientId}` | Get client by client ID |
| `POST` | `/admin/oauth-clients` | Create new client |
| `PUT` | `/admin/oauth-clients/{id}` | Update existing client |
| `DELETE` | `/admin/oauth-clients/{id}` | Delete client |
| `GET` | `/admin/oauth-clients/search` | Search clients |

### Health & Monitoring

| Endpoint | Description |
|----------|-------------|
| `GET /` | Server information |
| `GET /actuator/health` | Health check |
| `GET /actuator/info` | Application info |

## 📝 Client Registration

### Create a Client (Admin Required)

**POST** `/admin/oauth-clients`

```json
{
  "clientId": "my-webapp",
  "clientName": "My Web Application",
  "clientSecret": "secret123",
  "authorizationGrantTypes": ["authorization_code", "refresh_token"],
  "clientAuthenticationMethods": ["client_secret_basic"],
  "redirectUris": ["http://localhost:3000/callback"],
  "scopes": ["openid", "profile", "email"],
  "requireAuthorizationConsent": true,
  "requireProofKey": false,
  "accessTokenTimeToLive": 3600,
  "refreshTokenTimeToLive": 86400
}
```

### Authorization Code Flow Example

1. **Authorization Request**
   ```
   GET /oauth2/authorize?
     response_type=code&
     client_id=my-webapp&
     redirect_uri=http://localhost:3000/callback&
     scope=openid profile email&
     state=random-state-value
   ```

2. **Token Exchange**
   ```bash
   curl -X POST http://localhost:8080/oauth2/token \
     -H "Content-Type: application/x-www-form-urlencoded" \
     -d "grant_type=authorization_code" \
     -d "code=AUTHORIZATION_CODE" \
     -d "redirect_uri=http://localhost:3000/callback" \
     -d "client_id=my-webapp" \
     -d "client_secret=secret123"
   ```

3. **Token Response**
   ```json
   {
     "access_token": "eyJhbGciOiJSUzI1NiJ9...",
     "refresh_token": "eyJhbGciOiJSUzI1NiJ9...",
     "id_token": "eyJhbGciOiJSUzI1NiJ9...",
     "token_type": "Bearer",
     "expires_in": 3600,
     "scope": "openid profile email"
   }
   ```

## 🔧 Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DB_HOST` | PostgreSQL host | `localhost` |
| `DB_PORT` | PostgreSQL port | `5432` |
| `DB_NAME` | Database name | `auth-service` |
| `DB_USERNAME` | Database username | `authorization-server` |
| `DB_PASSWORD` | Database password | `auth@123` |
| `SPRING_PROFILES_ACTIVE` | Active Spring profile | `development` |

### Custom JWT Claims

The server adds custom claims to JWT tokens:

**Access Token Claims:**
- `authorities`: User authorities/roles
- `client_id`: OAuth2 client identifier
- `client_name`: OAuth2 client name
- `grant_type`: OAuth2 grant type used
- `scope`: Authorized scopes

**ID Token Claims:**
- `preferred_username`: Username
- `email`: User email (if email scope granted)
- `given_name`, `family_name`: User names
- `picture`: Profile picture URL
- `updated_at`: Profile update timestamp

## 🛡️ Security Features

- **PKCE Support**: Proof Key for Code Exchange for enhanced security
- **Consent Management**: User consent tracking and management
- **Session Management**: Configurable session policies
- **CSRF Protection**: Cross-Site Request Forgery protection
- **Security Headers**: Comprehensive security headers
- **Password Encoding**: BCrypt password encoding
- **JWT Security**: RSA256 signed JWT tokens

## 🔍 Testing

### Health Check
```bash
curl http://localhost:8080/actuator/health
```

### Discovery Endpoint
```bash
curl http://localhost:8080/.well-known/openid_configuration
```

### JWKS Endpoint
```bash
curl http://localhost:8080/oauth2/jwks
```

## 📊 Database Schema

The application uses the following main tables:

- `users` - User accounts and profiles
- `user_roles` - User role assignments
- `oauth_clients` - OAuth2 client registrations
- `oauth_authorization` - OAuth2 authorization codes and tokens
- `oauth_authorization_consent` - User consent records

## 🐳 Production Deployment

### Docker Compose
```bash
# Production deployment
docker-compose up -d

# Check logs
docker-compose logs -f authorization-server

# Scale if needed
docker-compose up -d --scale authorization-server=2
```

### Environment Setup
1. Configure proper database credentials
2. Set up SSL/TLS certificates
3. Configure reverse proxy (nginx/Apache)
4. Set up monitoring and logging
5. Configure backup strategies

## 🤝 Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature/amazing-feature`
3. Commit changes: `git commit -m 'Add amazing feature'`
4. Push to branch: `git push origin feature/amazing-feature`
5. Open a Pull Request


## 👨‍💻 Author

**Jose Jefferson**
- GitHub: [@Jose Jefferson](https://github.com/Hancho7)
- LinkedIn: [Jose Jefferson](https://www.linkedin.com/in/jose-jefferson-litoro-2b52a0216/)

## 🙏 Acknowledgments

- Spring Security OAuth2 Authorization Server team
- Spring Boot community
- Contributors and testers

---

For more detailed information, please refer to the [Spring Authorization Server documentation](https://docs.spring.io/spring-authorization-server/reference/overview.html).