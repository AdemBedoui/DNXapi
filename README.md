# Domain Information Checker API

A Flask-based REST API for comprehensive domain information checking, including DNS records, SSL certificates, WHOIS data, and more.

## Features

- **Domain Resolution**: Check if a domain is registered and get its IP address
- **DNS Records**: Retrieve A, MX, NS, TXT records
- **Email Security**: Check SPF, DKIM, and DMARC records
- **SSL Certificate**: Validate SSL certificates and get expiration information
- **WHOIS Data**: Parse registration dates and domain status
- **Reverse DNS**: Get reverse DNS lookup for IP addresses
- **Multiple Domains**: Check multiple domains in a single request
- **Comprehensive Logging**: Detailed logging for debugging and monitoring
- **Special .tn Domain Support**: Enhanced parsing for Tunisian domains with registrar, registrant, and admin contact information

## Installation

1. Clone the repository:
```bash
git clone <repository-url>
cd dnx
```

2. Create a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Run the application:
```bash
python app.py
```

The API will be available at `http://localhost:5000`

## API Endpoints

### 1. Check Single Domain

**POST** `/api/check-domain`

Check comprehensive information for a single domain.

**Request Body:**
```json
{
    "domain": "example.com"
}
```

**Response:**
```json
{
    "domain": "example.com",
    "status": "Registered",
    "ip_address": "93.184.216.34",
    "A": ["93.184.216.34"],
    "MX": ["example.com."],
    "SPF": ["v=spf1 -all"],
    "DMARC": ["v=dmarc1; p=reject; rua=mailto:dmarc@example.com"],
    "reverse_dns": "example.com",
    "registration_date": "1995-08-14",
    "registrar_name": "ICANN",
    "nameservers": ["a.iana-servers.net", "b.iana-servers.net"],
    "ssl": {
        "status": "Valid",
        "issuer": "DigiCert Inc",
        "valid_from": "2023-01-01",
        "valid_until": "2024-01-01",
        "days_until_expiry": 30
    }
}
```

**For .tn domains, additional fields are included (only if available):**
```json
{
    "domain": "example.tn",
    "status": "Registered",
    "ip_address": "192.168.1.1",
    "registrar_name": "ATI (Agence Tunisienne d'Internet)",
    "registrant": "Example Organization",
    "admin_contact": "admin@example.tn",
    "registration_date": "2020-01-01",
    // ... other standard fields
}
```

### 2. Check Multiple Domains

**POST** `/api/check-multiple-domains`

Check multiple domains in a single request (maximum 10 domains).

**Request Body:**
```json
{
    "domains": ["example.com", "google.com", "github.com"]
}
```

**Response:**
```json
{
    "results": [
        {
            "domain": "example.com",
            "status": "Registered",
            // ... same structure as single domain response
        },
        {
            "domain": "google.com",
            "status": "Registered",
            // ... same structure as single domain response
        }
    ],
    "total_checked": 2
}
```

### 3. Health Check

**GET** `/api/health`

Check the API health status.

**Response:**
```json
{
    "status": "healthy",
    "version": "1.0.0"
}
```

## Error Handling

The API returns appropriate HTTP status codes:

- `200`: Success
- `400`: Bad Request (missing or invalid parameters)
- `500`: Internal Server Error

Error responses include a descriptive message:
```json
{
    "error": "Domain is required"
}
```

## Configuration

### Environment Variables

You can configure the following environment variables:

- `FLASK_ENV`: Set to `production` for production deployment
- `FLASK_DEBUG`: Set to `False` in production

### Logging

The application uses Python's built-in logging module. Logs are output to stdout with INFO level by default.

## Security Considerations

- The API includes rate limiting for multiple domain requests (max 10 domains per request)
- Input validation is performed on all domain names
- SSL certificate validation uses secure defaults
- WHOIS queries have timeout limits to prevent hanging

## Dependencies

- **Flask**: Web framework
- **Flask-CORS**: Cross-origin resource sharing
- **dnspython**: DNS record resolution
- **python-whois**: WHOIS data retrieval
- **cryptography**: SSL certificate handling

## Development

### Running Tests

```bash
python -m pytest tests/
```

### Code Style

The code follows PEP 8 style guidelines and includes type hints for better maintainability.

### Adding New Features

1. Add new functions with proper type hints and docstrings
2. Update the API endpoints as needed
3. Add appropriate error handling
4. Update this README with new endpoint documentation

## License

This project is licensed under the MIT License.

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests if applicable
5. Submit a pull request

## Support

For issues and questions, please open an issue on the GitHub repository. 