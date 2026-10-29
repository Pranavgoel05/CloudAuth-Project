"""Optional AWS/Moto integrations with safe local fallbacks for development."""
import base64
import json
import os
import secrets
from pathlib import Path
from typing import Any

REGION = os.getenv("AWS_DEFAULT_REGION", "us-east-1")
PROJECT_DIR = Path(os.getenv("AUTH_RUNTIME_DIR", "."))


def _simulation_enabled() -> bool:
    # Deliberately disabled by default to avoid accidentally calling a real AWS account.
    return os.getenv("CLOUD_SIMULATION", "false").lower() == "true"


def _aws_client(service: str):
    import boto3
    return boto3.client(service, region_name=REGION)


def get_jwt_signing_key() -> str:
    """Read the JWT key from simulated Secrets Manager, env, or a private local key file."""
    if _simulation_enabled():
        try:
            return _aws_client("secretsmanager").get_secret_value(SecretId="auth/jwt-signing-key")["SecretString"]
        except Exception:
            # The service remains runnable even if a simulated resource was not initialized.
            pass
    env_key = os.getenv("AUTH_JWT_SECRET")
    if env_key:
        if len(env_key) < 32:
            raise RuntimeError("AUTH_JWT_SECRET must contain at least 32 characters")
        return env_key
    path = PROJECT_DIR / ".local_jwt_secret"
    if path.exists():
        return path.read_text(encoding="utf-8").strip()
    key = secrets.token_urlsafe(48)
    path.write_text(key, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return key


def _fernet_cipher():
    """Build a stable Fernet cipher for persistent application secrets.

    Hosted instances must receive AUTH_ENCRYPTION_KEY via private environment settings.
    Local demonstrations generate a key file ignored by Git. A Moto KMS key is intentionally
    not used to encrypt database-persisted MFA secrets because Moto's KMS state is in-memory
    and would be lost on process restart.
    """
    from cryptography.fernet import Fernet
    env_key = os.getenv("AUTH_ENCRYPTION_KEY", "").strip()
    if env_key:
        key = env_key.encode("ascii")
        # Validate early, producing a clear setup error if a bad key was copied into settings.
        Fernet(key)
        return Fernet(key)
    key_path = PROJECT_DIR / ".local_encryption.key"
    if key_path.exists():
        key = key_path.read_bytes().strip()
    else:
        key = Fernet.generate_key()
        key_path.parent.mkdir(parents=True, exist_ok=True)
        key_path.write_bytes(key)
        try:
            key_path.chmod(0o600)
        except OSError:
            pass
    return Fernet(key)


def encrypt_sensitive_value(value: str) -> str:
    """Encrypt a value with a persistent application key for safe restart behavior.

    The cloud adapter's simulated KMS is verified separately as an integration demo. The
    stored MFA secret uses this stable key so ciphertext remains decryptable after an app
    restart or a free-host cold start.
    """
    return "fernet:" + _fernet_cipher().encrypt(value.encode("utf-8")).decode("ascii")


def decrypt_sensitive_value(value: str) -> str:
    """Decrypt persistent application values; retain support for older local KMS values."""
    if value.startswith("kms:"):
        if not _simulation_enabled():
            raise RuntimeError("Legacy KMS-encrypted value requires the same live cloud KMS key")
        ciphertext = base64.b64decode(value[4:].encode("ascii"))
        plain = _aws_client("kms").decrypt(CiphertextBlob=ciphertext)["Plaintext"]
        return plain.decode("utf-8")
    if value.startswith("fernet:"):
        return _fernet_cipher().decrypt(value[7:].encode("ascii")).decode("utf-8")
    raise ValueError("Unsupported encrypted value format")


def _verify_simulated_kms() -> None:
    """Perform a KMS encrypt/decrypt round trip against Moto, for integration evidence only."""
    client = _aws_client("kms")
    sample = b"cloud-auth-kms-self-test"
    encrypted = client.encrypt(KeyId="alias/auth-data-key", Plaintext=sample)["CiphertextBlob"]
    decrypted = client.decrypt(CiphertextBlob=encrypted)["Plaintext"]
    if decrypted != sample:
        raise RuntimeError("KMS encryption round-trip did not match")


def emit_cloud_audit(event: dict[str, Any]) -> None:
    """Best-effort CloudWatch/S3 export; database audit logging remains authoritative."""
    if not _simulation_enabled():
        return
    try:
        import time
        client = _aws_client("logs")
        group = "/auth-service/audit"
        stream = "login-events"
        groups = client.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])
        if not any(item["logGroupName"] == group for item in groups):
            client.create_log_group(logGroupName=group)
        streams = client.describe_log_streams(logGroupName=group, logStreamNamePrefix=stream).get("logStreams", [])
        if not any(item["logStreamName"] == stream for item in streams):
            client.create_log_stream(logGroupName=group, logStreamName=stream)
        client.put_log_events(logGroupName=group, logStreamName=stream,
                              logEvents=[{"timestamp": int(time.time() * 1000), "message": json.dumps(event, sort_keys=True)}])
    except Exception:
        pass
    try:
        import time
        bucket = "auth-audit-logs"
        key = f"events/{int(time.time() * 1000)}-{secrets.token_hex(4)}.json"
        _aws_client("s3").put_object(Bucket=bucket, Key=key, Body=json.dumps(event).encode("utf-8"), ContentType="application/json")
    except Exception:
        pass


def get_cloud_status() -> dict[str, Any]:
    """Report simulation configuration and resource availability without exposing secrets."""
    status: dict[str, Any] = {"simulation_mode": _simulation_enabled(), "secrets_manager": False,
                              "kms": False, "cloudwatch_logs": False, "s3_archive": False, "iam_role": False}
    if not _simulation_enabled():
        return status
    checks = {
        "secrets_manager": lambda: _aws_client("secretsmanager").get_secret_value(SecretId="auth/jwt-signing-key"),
        "kms": _verify_simulated_kms,
        "cloudwatch_logs": lambda: _aws_client("logs").describe_log_groups(logGroupNamePrefix="/auth-service/audit"),
        "s3_archive": lambda: _aws_client("s3").head_bucket(Bucket="auth-audit-logs"),
        "iam_role": lambda: _aws_client("iam").get_role(RoleName="CloudAuthDemoAuditRole"),
    }
    for name, check in checks.items():
        try:
            check()
            status[name] = True
        except Exception:
            status[name] = False
    return status


def _local_signing_key() -> str:
    """Return a persistent local development key without consulting AWS."""
    env_key = os.getenv("AUTH_JWT_SECRET")
    if env_key:
        if len(env_key) < 32:
            raise RuntimeError("AUTH_JWT_SECRET must contain at least 32 characters")
        return env_key
    path = PROJECT_DIR / ".local_jwt_secret"
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if len(value) >= 32:
            return value
    value = secrets.token_urlsafe(48)
    path.write_text(value, encoding="utf-8")
    try:
        path.chmod(0o600)
    except OSError:
        pass
    return value


def initialize_simulated_cloud() -> None:
    """Create the Moto-backed resources needed by a local classroom demo.

    This function must be called only while `moto.mock_aws()` is active.
    It never provisions real AWS resources.
    """
    os.environ.setdefault("AWS_ACCESS_KEY_ID", "testing")
    os.environ.setdefault("AWS_SECRET_ACCESS_KEY", "testing")
    os.environ.setdefault("AWS_SESSION_TOKEN", "testing")
    os.environ.setdefault("AWS_DEFAULT_REGION", REGION)
    secrets_client = _aws_client("secretsmanager")
    signing_key = _local_signing_key()
    secret_id = "auth/jwt-signing-key"
    try:
        secrets_client.get_secret_value(SecretId=secret_id)
    except Exception:
        secrets_client.create_secret(Name=secret_id, SecretString=signing_key,
                                     Description="Demo JWT signing key; Moto simulation only")

    kms = _aws_client("kms")
    try:
        key_id = kms.describe_key(KeyId="alias/auth-data-key")["KeyMetadata"]["KeyId"]
    except Exception:
        key_id = kms.create_key(Description="Demo sensitive-field key; Moto simulation only")["KeyMetadata"]["KeyId"]
        kms.create_alias(AliasName="alias/auth-data-key", TargetKeyId=key_id)

    logs = _aws_client("logs")
    group = "/auth-service/audit"
    if not any(row["logGroupName"] == group for row in logs.describe_log_groups(logGroupNamePrefix=group).get("logGroups", [])):
        logs.create_log_group(logGroupName=group)
    stream = "login-events"
    if not any(row["logStreamName"] == stream for row in logs.describe_log_streams(logGroupName=group, logStreamNamePrefix=stream).get("logStreams", [])):
        logs.create_log_stream(logGroupName=group, logStreamName=stream)

    s3 = _aws_client("s3")
    bucket = "auth-audit-logs"
    try:
        s3.head_bucket(Bucket=bucket)
    except Exception:
        s3.create_bucket(Bucket=bucket)

    iam = _aws_client("iam")
    role_name = "CloudAuthDemoAuditRole"
    try:
        iam.get_role(RoleName=role_name)
    except Exception:
        iam.create_role(RoleName=role_name,
                        AssumeRolePolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [{
                            "Effect": "Allow", "Principal": {"Service": "ec2.amazonaws.com"},
                            "Action": "sts:AssumeRole"}]}),
                        Description="Example least-privilege role for the simulated student project")
        iam.put_role_policy(RoleName=role_name, PolicyName="CloudAuthAuditDemoPolicy",
                            PolicyDocument=json.dumps({"Version": "2012-10-17", "Statement": [
                                {"Effect": "Allow", "Action": ["logs:CreateLogStream", "logs:PutLogEvents"],
                                 "Resource": "*"},
                                {"Effect": "Allow", "Action": ["s3:PutObject"],
                                 "Resource": "arn:aws:s3:::auth-audit-logs/events/*"},
                                {"Effect": "Allow", "Action": ["kms:Encrypt", "kms:Decrypt"],
                                 "Resource": "*"},
                                {"Effect": "Allow", "Action": ["secretsmanager:GetSecretValue"],
                                 "Resource": "*"}
                            ]}))
