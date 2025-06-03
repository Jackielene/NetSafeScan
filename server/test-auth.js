const axios = require('axios');

const API_URL = 'http://localhost:8080/api/auth';

async function testAuth() {
  try {
    // Test registration
    console.log('Testing registration...');
    const registerResponse = await axios.post(`${API_URL}/register`, {
      email: 'test@example.com',
      password: 'testpassword123',
      fullName: 'Test User'
    }, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    console.log('Registration successful:', registerResponse.data);

    // Test login
    console.log('\nTesting login...');
    const loginResponse = await axios.post(`${API_URL}/login`, {
      email: 'test@example.com',
      password: 'testpassword123'
    }, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    console.log('Login successful:', loginResponse.data);

    // Test get current user
    console.log('\nTesting get current user...');
    const meResponse = await axios.get(`${API_URL}/me`, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    console.log('Current user:', meResponse.data);

    // Test logout
    console.log('\nTesting logout...');
    const logoutResponse = await axios.post(`${API_URL}/logout`, {}, {
      withCredentials: true,
      headers: {
        'Content-Type': 'application/json'
      }
    });
    console.log('Logout successful:', logoutResponse.data);

  } catch (error) {
    if (error.response) {
      // The request was made and the server responded with a status code
      // that falls out of the range of 2xx
      console.error('Error response:', {
        status: error.response.status,
        data: error.response.data,
        headers: error.response.headers
      });
    } else if (error.request) {
      // The request was made but no response was received
      console.error('No response received:', error.request);
    } else {
      // Something happened in setting up the request that triggered an Error
      console.error('Error setting up request:', error.message);
    }
  }
}

// Add a small delay before starting the test to ensure the server is ready
setTimeout(testAuth, 2000); 