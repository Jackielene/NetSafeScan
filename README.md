# NetSafeScan

NetSafeScan is a comprehensive web security scanning tool that helps identify and analyze potential security vulnerabilities in web applications. It provides real-time scanning capabilities and detailed security reports to help developers and security professionals maintain secure web applications.

## Features

- **URL Security Analysis**: Scans URLs for potential security threats and vulnerabilities
- **Real-time Scanning**: Provides immediate feedback on security issues
- **Detailed Reports**: Generates comprehensive security reports with actionable insights
- **User Authentication**: Secure user authentication system
- **Database Integration**: PostgreSQL database for storing scan results and user data
- **API Integration**: RESTful API endpoints for seamless integration

## Tech Stack

### Frontend
- React.js
- Material-UI
- Axios for API calls
- React Router for navigation

### Backend
- Node.js
- Express.js
- PostgreSQL database
- Passport.js for authentication
- JWT for secure token management

## Prerequisites

Before you begin, ensure you have the following installed:
- Node.js (v14 or higher)
- PostgreSQL (v12 or higher)
- npm or yarn package manager

## Installation

1. Clone the repository:
```bash
git clone https://github.com/Jackielene/NetSafeScan.git
cd NetSafeScan
```

2. Install server dependencies:
```bash
cd server
npm install
```

3. Install client dependencies:
```bash
cd ../client
npm install
```

4. Set up environment variables:
   - Create a `.env` file in the server directory
   - Add the following variables:
```
DB_USER=your_db_user
DB_PASSWORD=your_db_password
DB_HOST=localhost
DB_PORT=5432
DB_DATABASE=netsafescan
JWT_SECRET=your_jwt_secret
GOOGLE_CLIENT_ID=your_google_client_id
GOOGLE_CLIENT_SECRET=your_google_client_secret
```

5. Set up the database:
```bash
# Connect to PostgreSQL and create the database
createdb netsafescan
```

## Running the Application

1. Start the server:
```bash
cd server
npm start
```

2. Start the client:
```bash
cd client
npm start
```

The application will be available at `http://localhost:3000`

## API Endpoints

### Authentication
- `POST /api/auth/register` - Register a new user
- `POST /api/auth/login` - Login user
- `GET /api/auth/google` - Google OAuth authentication
- `GET /api/auth/google/callback` - Google OAuth callback

### URL Scanning
- `POST /api/scan` - Scan a URL for security vulnerabilities
- `GET /api/scan/history` - Get scan history
- `GET /api/scan/:id` - Get specific scan results

## Contributing

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## Security

This project implements various security measures:
- JWT-based authentication
- Password hashing
- Input validation
- CORS protection
- Rate limiting
- SQL injection prevention

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Contact

For any queries or support, please open an issue in the GitHub repository.

## Acknowledgments

- Thanks to all contributors who have helped shape this project
- Special thanks to the open-source community for their invaluable tools and libraries 