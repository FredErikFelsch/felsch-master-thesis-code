"""Where credentials come from, as one seam the gateway owns.

A credential can live in a dict (tests), in the process environment (a developer's setup)
or in OpenBao (the cluster). Neither the executor nor the adapters should know which, so
all of them sit behind this protocol and the choice is made once, where the gateway is built.

Some properties do not depend on the source: the agent does not read a secret, the runner
pod has `automountServiceAccountToken: false` and cannot authenticate at all, and a
credential is not put into a payload, a fact, an error message or a log line. OpenBao
replaces the storage, not the boundary. This is why the source is a constructor argument,
and switching to OpenBao needs no other change.
"""
from __future__ import annotations

import os
import pathlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Protocol

from .world import Credentials

# The environment variables the live worlds read when secrets come from the environment.
SERPAPI_ENV = "SERPAPI_KEY"
DUFFEL_ENV = "DUFFEL_TOKEN"


class SecretUnavailable(RuntimeError):
    """The store could not be asked, which differs from a secret that is not there.

    The distinction matters at start-up. A secret that does not exist is a
    configuration question with an obvious fix. A store that cannot be reached is an
    outage, and reporting it as "credential not set" would send someone to edit a
    manifest that is already correct.
    """


class SecretSource(Protocol):
    """Read one credential by name.

    Returns None when the secret is not held here, and raises `SecretUnavailable` when
    the answer could not be obtained. An implementation returns no placeholder and does
    not log the value, because a credential that reaches a log has left the boundary it
    was put behind.
    """

    def read(self, name: str) -> str | None: ...


@dataclass(frozen=True)
class EnvSecrets:
    """Credentials from the process environment, for a developer's local setup."""

    def read(self, name: str) -> str | None:
        """Return the trimmed environment variable `name`, or None when unset or empty."""
        value = os.environ.get(name, "").strip()
        return value or None


@dataclass(frozen=True)
class MappingSecrets:
    """Credentials from an explicit mapping, for tests."""

    values: Mapping[str, str] = field(default_factory=dict)

    def read(self, name: str) -> str | None:
        """Return the mapped value for `name`, or None when absent or empty."""
        return self.values.get(name) or None


def credentials(source: SecretSource) -> Credentials:
    """Read every credential the live worlds may need, once, where the gateway is built.

    The result is passed on as a value, so no adapter reads a secret on its own and there
    is one place to point at OpenBao.
    """
    return Credentials(serpapi_key=source.read(SERPAPI_ENV),
                       duffel_token=source.read(DUFFEL_ENV))


# --- OpenBao ---------------------------------------------------------------------

#: Where a projected ServiceAccount token is mounted by default. A dedicated projected
#: token with a short lifetime is preferable to the pod's default one, which is why this
#: is a parameter rather than a constant baked into the call.
SA_TOKEN_PATH = "/var/run/secrets/kubernetes.io/serviceaccount/token"

DEFAULT_MOUNT = "secret"
DEFAULT_KUBERNETES_MOUNT = "kubernetes"


class BaoSecrets:
    """Credentials from OpenBao, over its HTTP API.

    There are two ways to authenticate. A direct token is for a developer with a dev
    server. Kubernetes auth is what the cluster uses: the pod presents its ServiceAccount
    token, OpenBao asks Kubernetes whether it is genuine, and answers with a client token
    for the role. The gateway's ServiceAccount is the only one bound to that role, and the
    runner cannot try, because it has no token to present. A given token takes precedence
    over the role.

    This class does not mediate provider calls. It is read once, when the gateway is built,
    and the credential then stays in the gateway's memory. The audit log therefore shows one
    secret read per gateway start, not one per Duffel call.

    The HTTP client is injectable, so the whole path is testable without a server.
    """

    def __init__(self, address: str, *, mount: str = DEFAULT_MOUNT, path: str = "agent",
                 token: str | None = None, role: str | None = None,
                 kubernetes_mount: str = DEFAULT_KUBERNETES_MOUNT,
                 sa_token_path: str = SA_TOKEN_PATH, timeout_s: float = 10.0,
                 verify: bool | str = True, http: Any = None) -> None:
        if not address:
            raise ValueError("an OpenBao address is required")
        if not token and not role:
            raise ValueError("either a token (development) or a role (Kubernetes auth)")
        self.address = address.rstrip("/")
        self.mount, self.path = mount, path
        self.role, self.kubernetes_mount = role, kubernetes_mount
        self.sa_token_path = sa_token_path
        self.timeout_s, self.verify = timeout_s, verify
        self._http = http
        self._token = token            # a client token, however it was obtained
        self._auth = "token" if token else f"kubernetes role {role!r}"
        self._cache: dict | None = None

    # -- transport ---------------------------------------------------------------
    def _request(self, method: str, url: str, *, headers=None, json_body=None):
        if self._http is not None:
            return self._http.request(method, url, headers=headers, json_body=json_body)
        import requests
        response = requests.request(method, url, headers=dict(headers or {}),
                                    json=json_body, timeout=self.timeout_s,
                                    verify=self.verify, allow_redirects=False)
        try:
            return response.status_code, response.json()
        except ValueError:
            return response.status_code, {}

    def _call(self, method: str, url: str, **kwargs) -> tuple[int, Any]:
        """Send one request, reporting every transport failure as `SecretUnavailable`."""
        try:
            return self._request(method, url, **kwargs)
        except SecretUnavailable:
            raise
        except Exception as exc:
            raise SecretUnavailable(
                f"OpenBao at {self.address} could not be reached: {type(exc).__name__}"
            ) from None       # from None: an exception chain can carry a request body

    # -- authentication ----------------------------------------------------------
    def _login(self) -> str:
        """Exchange the pod's ServiceAccount token for a client token."""
        try:
            jwt = pathlib.Path(self.sa_token_path).read_text().strip()
        except OSError as exc:
            raise SecretUnavailable(
                f"no ServiceAccount token at {self.sa_token_path} ({exc.__class__.__name__}); "
                f"a pod with automountServiceAccountToken disabled cannot authenticate"
            ) from None
        if not jwt:
            raise SecretUnavailable(f"the ServiceAccount token at {self.sa_token_path} is empty")

        url = f"{self.address}/v1/auth/{self.kubernetes_mount}/login"
        status, body = self._call("POST", url, json_body={"role": self.role, "jwt": jwt})
        if status >= 400:
            raise SecretUnavailable(
                f"OpenBao refused the Kubernetes login for role {self.role!r}: http {status}")
        client_token = (body or {}).get("auth", {}).get("client_token")
        if not client_token:
            raise SecretUnavailable("OpenBao's login reply carried no client token")
        return client_token

    def _authenticated(self) -> str:
        if self._token is None:
            self._token = self._login()
        return self._token

    # -- reading -----------------------------------------------------------------
    def _load(self) -> dict:
        """Read the KV-v2 secret at `mount/path` once and keep it.

        One read serves all credentials, because the gateway needs its few values at
        start-up and holds them, so asking again per name would only add failure modes.
        """
        if self._cache is not None:
            return self._cache
        url = f"{self.address}/v1/{self.mount}/data/{self.path}"
        status, body = self._call("GET", url,
                                  headers={"X-Vault-Token": self._authenticated()})
        if status == 404:
            self._cache = {}
            return self._cache
        if status >= 400:
            raise SecretUnavailable(
                f"OpenBao refused to read {self.mount}/{self.path}: http {status}")
        data = ((body or {}).get("data") or {}).get("data")
        if not isinstance(data, dict):
            raise SecretUnavailable(
                f"OpenBao's reply for {self.mount}/{self.path} has no KV-v2 data object")
        self._cache = data
        return self._cache

    def read(self, name: str) -> str | None:
        """Return the trimmed secret `name`, or None when OpenBao does not hold it.

        Raises:
            SecretUnavailable: when the store cannot be reached or the value is not a usable string.
        """
        value = self._load().get(name)
        if value is None:
            return None
        if not isinstance(value, str) or not value.strip():
            raise SecretUnavailable(
                f"the value of {name!r} in {self.mount}/{self.path} is not a usable string")
        return value.strip()

    def __repr__(self) -> str:
        """Name the address, the path and the way of authentication, without a token or a value.

        A repr ends up in logs sooner or later.
        """
        return f"BaoSecrets(address={self.address!r}, path={self.mount}/{self.path}, auth={self._auth})"


def secret_source_from_env() -> SecretSource:
    """Choose the source this process uses, once, from the environment.

    With `BAO_ADDR` unset the environment itself holds the credentials, which is the
    developer's setup and the default. Setting it changes nothing else in the system.
    """
    address = os.environ.get("BAO_ADDR", "").strip()
    if not address:
        return EnvSecrets()
    return BaoSecrets(address,
                      mount=os.environ.get("BAO_MOUNT", DEFAULT_MOUNT),
                      path=os.environ.get("BAO_PATH", "agent"),
                      token=os.environ.get("BAO_TOKEN") or None,
                      role=os.environ.get("BAO_ROLE") or None,
                      sa_token_path=os.environ.get("BAO_SA_TOKEN_PATH", SA_TOKEN_PATH))
