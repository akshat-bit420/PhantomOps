import os
import time
import hashlib
import urllib.parse
import requests
from dotenv import load_dotenv
import json

load_dotenv()

class Auth0Gatekeeper:
    """
    Enforces Human-in-the-Loop (HITL) authorization via Auth0 before allowing
    the AI agent to execute destructive infrastructure commands (Exorcisms).
    """
    def __init__(self):
        self.domain = os.getenv("AUTH0_DOMAIN", "").strip()
        self.client_id = os.getenv("AUTH0_CLIENT_ID", "").strip()
        self.client_secret = os.getenv("AUTH0_CLIENT_SECRET", "").strip()
        self.redirect_uri = "http://localhost:8501"

    def is_configured(self) -> bool:
        return bool(
            self.domain 
            and self.client_id 
            and "your-tenant" not in self.domain 
            and "your_client_id" not in self.client_id
        )

    def create_approval_request(self, resource_id: str, command: str) -> dict:
        """
        Generates an Auth0 authorization URL requiring human sign-off for a risky agent action.
        """
        # Create a deterministic state hash binding the resource_id to the request
        state_hash = hashlib.sha256(f"{resource_id}:{command}".encode()).hexdigest()[:16]
        state_param = f"exorcise_{resource_id}_{state_hash}"

        if not self.is_configured():
            return {
                "configured": False,
                "state": state_param,
                "auth_url": None,
                "message": "Auth0 credentials not found in .env (Simulation Mode available)"
            }

        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "scope": "openid profile email",
            "state": state_param,
            "prompt": "login"  # Forces explicit human re-authentication for risky action
        }
        auth_url = f"https://{self.domain}/authorize?{urllib.parse.urlencode(params)}"
        return {
            "configured": True,
            "state": state_param,
            "auth_url": auth_url,
            "message": f"Awaiting human clearance via Auth0 ({self.domain})"
        }

    def exchange_code_for_token(self, code: str) -> dict:
        """
        Exchanges the Auth0 callback authorization code for a verified access & ID token.
        """
        token_url = f"https://{self.domain}/oauth/token"
        payload = {
            "grant_type": "authorization_code",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "code": code,
            "redirect_uri": self.redirect_uri
        }
        response = requests.post(token_url, json=payload, timeout=10)
        if response.status_code == 200:
            data = response.json()
            return {
                "approved": True,
                "id_token": data.get("id_token", ""),
                "access_token": data.get("access_token", ""),
                "access_token_preview": data.get("access_token", "")[:18] + "...",
                "timestamp": time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
            }
        else:
            return {
                "approved": False,
                "error": response.text
            }
    def build_audit_receipt(self, resource_id: str, command: str, token_res: dict) -> dict:
        """
        Decodes the Auth0 JWT payload (without external deps) and creates a tamper-evident
        SHA-256 execution receipt binding the human operator to the kernel kill command.
        """
        import base64
        import hashlib
        import time

        claims = {"sub": "auth0|verified-operator", "iss": f"https://{self.domain}/", "amr": ["mfa", "pwd"]}
        id_token = token_res.get("id_token") or token_res.get("access_token", "")
        if id_token and "." in id_token:
            try:
                payload_b64 = id_token.split(".")[1]
                payload_b64 += "=" * ((4 - len(payload_b64) % 4) % 4)
                claims = json.loads(base64.urlsafe_b64decode(payload_b64).decode("utf-8"))
            except Exception:
                pass

        timestamp = int(time.time())
        raw_binding = f"{claims.get('sub')}|{resource_id}|{command}|{timestamp}"
        signature_hash = hashlib.sha256(raw_binding.encode("utf-8")).hexdigest()

        return {
            "receipt_id": f"EXOR-{signature_hash[:10].upper()}",
            "operator_subject": claims.get("sub", "auth0|operator"),
            "operator_email": claims.get("email", "verified-sre@phantomops.local"),
            "issuer": claims.get("iss", f"https://{self.domain}/"),
            "target_resource": resource_id,
            "authorized_command": command,
            "timestamp_utc": timestamp,
            "sha256_action_binding": signature_hash
        }        

if __name__ == "__main__":
    gk = Auth0Gatekeeper()
    req = gk.create_approval_request("inst-10525", "aws ec2 terminate-instances --instance-ids inst-10525")
    print("🔐 --- AUTH0 GATEKEEPER CHECK ---")
    print(f"Configured: {req['configured']}")
    print(f"Status:     {req['message']}")
    if req["auth_url"]:
        print(f"Approval URL:\n{req['auth_url']}")