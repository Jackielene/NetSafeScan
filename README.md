<<<<<<< HEAD
This is a [Next.js](https://nextjs.org) project bootstrapped with [`create-next-app`](https://nextjs.org/docs/app/api-reference/cli/create-next-app).

## Getting Started

First, run the development server:

```bash
npm run dev
# or
yarn dev
# or
pnpm dev
# or
bun dev
```

Open [http://localhost:3000](http://localhost:3000) with your browser to see the result.

You can start editing the page by modifying `app/page.tsx`. The page auto-updates as you edit the file.

This project uses [`next/font`](https://nextjs.org/docs/app/building-your-application/optimizing/fonts) to automatically optimize and load [Geist](https://vercel.com/font), a new font family for Vercel.

## Learn More

To learn more about Next.js, take a look at the following resources:

- [Next.js Documentation](https://nextjs.org/docs) - learn about Next.js features and API.
- [Learn Next.js](https://nextjs.org/learn) - an interactive Next.js tutorial.

You can check out [the Next.js GitHub repository](https://github.com/vercel/next.js) - your feedback and contributions are welcome!

## Deploy on Vercel

The easiest way to deploy your Next.js app is to use the [Vercel Platform](https://vercel.com/new?utm_medium=default-template&filter=next.js&utm_source=create-next-app&utm_campaign=create-next-app-readme) from the creators of Next.js.

Check out our [Next.js deployment documentation](https://nextjs.org/docs/app/building-your-application/deploying) for more details.
=======
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
>>>>>>> 5edc93ed9df56463bc5e363c451e2af9e3a10b01
