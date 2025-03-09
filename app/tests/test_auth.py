import unittest
import requests

BASE_URL = "http://127.0.0.1:5000/auth"  # Change this to your API URL if different

class AuthAPITestCase(unittest.TestCase):
    """Unit tests for authentication API endpoints."""

    def test_register(self):
        """Test registrasi pengguna, menangani kasus sudah terdaftar"""
        payload = {
            "email": "testuser@example.com",
            "password": "testpassword",
            "name": "Test User"
        }
        response = requests.post(f"{BASE_URL}/register", json=payload)

        # Ensure response is in JSON format
        try:
            response_data = response.json()
        except ValueError:
            self.fail("Response is not valid JSON")

        # Pastikan status code adalah 201 (registrasi sukses) atau 400 (sudah terdaftar)
        self.assertIn(response.status_code, [201, 400])

        # Validasi pesan respons
        if response.status_code == 201:
            self.assertIn("User registered successfully", response_data.get("message", ""))
        elif response.status_code == 400:
            self.assertIn("Email already exists", response_data.get("message", ""))  # ✅ Fixed Key


    def test_login_success(self):
        """Test successful user login."""
        payload = {
            "email": "newuser@example.com",
            "password": "newpassword"
        }
        response = requests.post(f"{BASE_URL}/login", json=payload)
        self.assertEqual(response.status_code, 200)
        self.assertIn("Login successful", response.json()["message"])
        self.assertTrue("Set-Cookie" in response.headers)  # Ensure JWT is stored in cookies

    def test_login_invalid_password(self):
        """Test login failure due to incorrect password."""
        payload = {
            "email": "newuser@example.com",
            "password": "wrongpassword"
        }
        response = requests.post(f"{BASE_URL}/login", json=payload)
        self.assertEqual(response.status_code, 401)
        self.assertIn("Invalid credentials", response.json()["message"])

    def test_login_nonexistent_user(self):
        """Test login failure with an unregistered email."""
        payload = {
            "email": "nonexistent@example.com",
            "password": "testpassword"
        }
        response = requests.post(f"{BASE_URL}/login", json=payload)
        self.assertEqual(response.status_code, 401)
        self.assertIn("Invalid credentials", response.json()["message"])

    def test_google_login_invalid_token(self):
        """Test Google login failure with an invalid token."""
        payload = {"token": "invalid_google_token"}
        response = requests.post(f"{BASE_URL}/google-login", json=payload)
        self.assertEqual(response.status_code, 401)
        self.assertIn("Invalid Google Token", response.json()["message"])

    def test_logout(self):
        """Test logout functionality (JWT should be cleared)."""
        login_payload = {
            "email": "newuser@example.com",
            "password": "newpassword"
        }
        session = requests.Session()
        login_response = session.post(f"{BASE_URL}/login", json=login_payload)
        self.assertEqual(login_response.status_code, 200)
        self.assertTrue("Set-Cookie" in login_response.headers)  # Ensure JWT is stored

        logout_response = session.post(f"{BASE_URL}/logout")
        self.assertEqual(logout_response.status_code, 200)
        self.assertIn("Logged out successfully", logout_response.json()["message"])

if __name__ == "__main__":
    unittest.main()
