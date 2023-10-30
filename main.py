# Bouthasone Rajasombat

from http.server import BaseHTTPRequestHandler, HTTPServer
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from urllib.parse import urlparse, parse_qs
import base64
import json
import jwt
import datetime
import sqlite3

hostName = "localhost"
serverPort = 8080

# Database Setup
conn = sqlite3.connect('totally_not_my_privateKeys.db')
cursor = conn.cursor()
cursor.execute('''
CREATE TABLE IF NOT EXISTS keys(
    kid TEXT PRIMARY KEY,
    key TEXT NOT NULL,
    exp INTEGER NOT NULL
)
''')
conn.commit()

# RSA Key Generation
private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
expired_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

pem = private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)
expired_pem = expired_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.TraditionalOpenSSL,
    encryption_algorithm=serialization.NoEncryption()
)

# Store the keys in the database
cursor.execute("INSERT OR REPLACE INTO keys (kid, key, exp) VALUES (?, ?, ?)",
               ("goodKID", pem.decode('utf-8'), int((datetime.datetime.utcnow() + datetime.timedelta(hours=1)).timestamp())))
cursor.execute("INSERT OR REPLACE INTO keys (kid, key, exp) VALUES (?, ?, ?)",
               ("expiredKID", expired_pem.decode('utf-8'), int((datetime.datetime.utcnow() - datetime.timedelta(hours=1)).timestamp())))
conn.commit()

def int_to_base64(value):
    """Convert an integer to a Base64URL-encoded string"""
    value_hex = format(value, 'x')
    if len(value_hex) % 2 == 1:
        value_hex = '0' + value_hex
    value_bytes = bytes.fromhex(value_hex)
    encoded = base64.urlsafe_b64encode(value_bytes).rstrip(b'=')
    return encoded.decode('utf-8')

class MyServer(BaseHTTPRequestHandler):
    def do_POST(self):
        parsed_path = urlparse(self.path)
        params = parse_qs(parsed_path.query)
        if parsed_path.path == "/auth":
            cursor.execute("SELECT key, exp FROM keys WHERE kid=?", ("expiredKID" if 'expired' in params else "goodKID",))
            result = cursor.fetchone()
            if not result:
                self.send_response(404)
                self.end_headers()
                return
            key, exp = result

            headers = {"kid": "expiredKID" if 'expired' in params else "goodKID"}
            token_payload = {
                "user": "username",
                "exp": datetime.datetime.fromtimestamp(exp)
            }
            encoded_jwt = jwt.encode(token_payload, key, algorithm="RS256", headers=headers)

            self.send_response(200)
            self.end_headers()
            self.wfile.write(bytes(encoded_jwt, "utf-8"))
            return

        self.send_response(405)
        self.end_headers()
        return

    def do_GET(self):
        if self.path == "/.well-known/jwks.json":
            try:
                cursor.execute("SELECT kid, key, exp FROM keys WHERE exp > ?", (int(datetime.datetime.utcnow().timestamp()),))
                keys_from_db = cursor.fetchall()

                keys = {"keys": []}
                for kid, key, exp in keys_from_db:
                    current_key = serialization.load_pem_private_key(key.encode('utf-8'), password=None)
                    current_numbers = current_key.private_numbers()
                    keys["keys"].append({
                        "alg": "RS256",
                        "kty": "RSA",
                        "use": "sig",
                        "kid": kid,
                        "n": int_to_base64(current_numbers.public_numbers.n),
                        "e": int_to_base64(current_numbers.public_numbers.e)
                    })

                self.send_response(200)
                self.send_header("Content-type", "application/json")
                self.end_headers()
                self.wfile.write(bytes(json.dumps(keys), "utf-8"))
                return

            except Exception as e:
                self.send_response(500)
                self.send_header("Content-type", "text/plain")
                self.end_headers()
                self.wfile.write(bytes(f"Internal server error: {e}", "utf-8"))
                return

        self.send_response(405)
        self.end_headers()
        return

if __name__ == "__main__":
    webServer = HTTPServer((hostName, serverPort), MyServer)
    try:
        webServer.serve_forever()
    except KeyboardInterrupt:
        pass

    webServer.server_close()
    conn.close()
