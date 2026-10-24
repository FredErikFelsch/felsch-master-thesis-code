"""OpenBao behind the SecretSource seam, without an OpenBao.

Run:
    python3 -m booking_live.tests_secrets

The seam claims that swapping the storage changes nothing else. The gateway still reads
its credentials once where it is built, the agent does not see one, and everything
downstream takes a value rather than reading a store itself.

These tests therefore cover the OpenBao client itself, and then the same `verify_world`
call that the cluster gateway makes, with OpenBao underneath instead of the environment.

Two distinctions are pinned because getting them wrong is expensive at start-up:

    secret is not there   ->  None, a configuration question
    store cannot be asked ->  SecretUnavailable, an outage

Reporting the second as the first would send someone to edit a manifest that is already
correct.
"""
from __future__ import annotations

import os
import tempfile
import unittest
from dataclasses import dataclass, field

from .secrets import (BaoSecrets, DUFFEL_ENV, EnvSecrets, MappingSecrets, SERPAPI_ENV,
                      SecretUnavailable, credentials, secret_source_from_env)
from .startup import ConfigurationRefused, verify_world

ADDRESS = "https://bao.agent-system.svc:8200"
TOKEN = "duffel_test_" + "t" * 20
KEY = "serpapi_" + "k" * 20


@dataclass
class FakeHttp:
    """A scripted OpenBao that records what was asked and answers what the case says."""

    answers: dict
    seen: list = field(default_factory=list)
    raises: Exception | None = None

    def request(self, method: str, url: str, *, headers=None, json_body=None):
        """Record the request, then raise, or answer by the first matching URL pattern."""
        self.seen.append((method, url, dict(headers or {}), json_body))
        if self.raises is not None:
            raise self.raises
        for pattern, answer in self.answers.items():
            if pattern in url:
                return answer
        return 404, {}

    @property
    def tokens_used(self) -> list:
        """Return the client tokens presented, in order."""
        return [h.get("X-Vault-Token") for _m, _u, h, _b in self.seen if h.get("X-Vault-Token")]


def kv(**values) -> tuple:
    """Build a KV-v2 read reply holding `values`."""
    return 200, {"data": {"data": dict(values), "metadata": {"version": 1}}}


def login_ok(client_token="s.clienttoken") -> tuple:
    """Build a successful Kubernetes login reply."""
    return 200, {"auth": {"client_token": client_token, "lease_duration": 3600}}


class ReadingWithADirectToken(unittest.TestCase):
    """The developer's setup: a dev server and a token in hand."""

    def _bao(self, answers, **kwargs):
        return BaoSecrets(ADDRESS, token="s.dev", http=FakeHttp(answers), **kwargs)

    def test_it_reads_a_kv_v2_secret(self):
        bao = self._bao({"/v1/secret/data/agent": kv(**{DUFFEL_ENV: TOKEN})})
        self.assertEqual(bao.read(DUFFEL_ENV), TOKEN)

    def test_it_reads_the_configured_mount_and_path(self):
        bao = self._bao({"/v1/kv/data/agents/gateway": kv(**{DUFFEL_ENV: TOKEN})},
                        mount="kv", path="agents/gateway")
        self.assertEqual(bao.read(DUFFEL_ENV), TOKEN)

    def test_a_missing_name_is_none_not_an_error(self):
        bao = self._bao({"/v1/secret/data/agent": kv(**{DUFFEL_ENV: TOKEN})})
        self.assertIsNone(bao.read(SERPAPI_ENV))

    def test_a_missing_secret_is_none_not_an_error(self):
        bao = self._bao({"/v1/secret/data/agent": (404, {"errors": []})})
        self.assertIsNone(bao.read(DUFFEL_ENV))

    def test_it_reads_the_store_once_for_several_names(self):
        http = FakeHttp({"/v1/secret/data/agent": kv(**{DUFFEL_ENV: TOKEN, SERPAPI_ENV: KEY})})
        bao = BaoSecrets(ADDRESS, token="s.dev", http=http)
        creds = credentials(bao)
        self.assertEqual(creds.duffel_token, TOKEN)
        self.assertEqual(creds.serpapi_key, KEY)
        self.assertEqual(len(http.seen), 1, "one read, not one per credential")

    def test_values_are_stripped_and_an_empty_one_is_refused(self):
        bao = self._bao({"/v1/secret/data/agent": kv(**{DUFFEL_ENV: "  " + TOKEN + "  "})})
        self.assertEqual(bao.read(DUFFEL_ENV), TOKEN)
        empty = self._bao({"/v1/secret/data/agent": kv(**{DUFFEL_ENV: "   "})})
        with self.assertRaises(SecretUnavailable):
            empty.read(DUFFEL_ENV)


class AuthenticatingAsThePod(unittest.TestCase):
    """The cluster's way in: the pod proves who it is, OpenBao answers with a token."""

    def setUp(self):
        fh = tempfile.NamedTemporaryFile("w", suffix=".jwt", delete=False)
        fh.write("the.pods.jwt")
        fh.close()
        self.jwt_path = fh.name

    def _bao(self, http, **kwargs):
        return BaoSecrets(ADDRESS, role="gateway", sa_token_path=self.jwt_path,
                          http=http, **kwargs)

    def test_it_logs_in_and_then_reads_with_the_client_token(self):
        http = FakeHttp({"/v1/auth/kubernetes/login": login_ok(),
                         "/v1/secret/data/agent": kv(**{DUFFEL_ENV: TOKEN})})
        bao = self._bao(http)
        self.assertEqual(bao.read(DUFFEL_ENV), TOKEN)
        method, url, _h, body = http.seen[0]
        self.assertEqual(method, "POST")
        self.assertIn("auth/kubernetes/login", url)
        self.assertEqual(body, {"role": "gateway", "jwt": "the.pods.jwt"})
        self.assertEqual(http.tokens_used, ["s.clienttoken"])

    def test_it_logs_in_once(self):
        http = FakeHttp({"/v1/auth/kubernetes/login": login_ok(),
                         "/v1/secret/data/agent": kv(**{DUFFEL_ENV: TOKEN, SERPAPI_ENV: KEY})})
        credentials(self._bao(http))
        logins = [u for _m, u, _h, _b in http.seen if "login" in u]
        self.assertEqual(len(logins), 1)

    def test_a_pod_without_a_service_account_token_cannot_authenticate(self):
        """This is the runner's situation, and the message has to say so."""
        http = FakeHttp({})
        bao = BaoSecrets(ADDRESS, role="gateway", sa_token_path="/nowhere/token", http=http)
        with self.assertRaises(SecretUnavailable) as caught:
            bao.read(DUFFEL_ENV)
        self.assertIn("automountServiceAccountToken", str(caught.exception))
        self.assertEqual(http.seen, [], "nothing was asked of OpenBao")

    def test_a_refused_login_is_an_outage_not_a_missing_secret(self):
        http = FakeHttp({"/v1/auth/kubernetes/login": (403, {"errors": ["permission denied"]})})
        with self.assertRaises(SecretUnavailable) as caught:
            self._bao(http).read(DUFFEL_ENV)
        self.assertIn("gateway", str(caught.exception))

    def test_a_login_reply_without_a_token_is_refused(self):
        http = FakeHttp({"/v1/auth/kubernetes/login": (200, {"auth": {}})})
        with self.assertRaises(SecretUnavailable):
            self._bao(http).read(DUFFEL_ENV)


class FailuresAreNamedNotSwallowed(unittest.TestCase):
    """Every failure of the store surfaces as `SecretUnavailable` without leaking a request."""

    def test_a_refused_read_is_an_outage(self):
        http = FakeHttp({"/v1/secret/data/agent": (403, {"errors": ["permission denied"]})})
        with self.assertRaises(SecretUnavailable) as caught:
            BaoSecrets(ADDRESS, token="s.dev", http=http).read(DUFFEL_ENV)
        self.assertIn("secret/agent", str(caught.exception))

    def test_an_unreachable_store_is_an_outage(self):
        http = FakeHttp({}, raises=TimeoutError("connect timed out"))
        with self.assertRaises(SecretUnavailable) as caught:
            BaoSecrets(ADDRESS, token="s.dev", http=http).read(DUFFEL_ENV)
        self.assertIn(ADDRESS, str(caught.exception))

    def test_a_reply_without_kv_v2_shape_is_refused(self):
        """A KV-v1 mount answers differently, and guessing would read the wrong thing."""
        http = FakeHttp({"/v1/secret/data/agent": (200, {"data": {DUFFEL_ENV: TOKEN}})})
        with self.assertRaises(SecretUnavailable) as caught:
            BaoSecrets(ADDRESS, token="s.dev", http=http).read(DUFFEL_ENV)
        self.assertIn("KV-v2", str(caught.exception))

    def test_the_failure_chain_carries_no_request(self):
        """`raise ... from None`: an exception chain can end up in a log with a body."""
        http = FakeHttp({}, raises=RuntimeError(f"posting {TOKEN} failed"))
        try:
            BaoSecrets(ADDRESS, token="s.dev", http=http).read(DUFFEL_ENV)
        except SecretUnavailable as unavailable:
            self.assertIsNone(unavailable.__cause__)
            self.assertNotIn(TOKEN, str(unavailable))
        else:
            self.fail("expected SecretUnavailable")

    def test_the_repr_carries_no_token(self):
        text = repr(BaoSecrets(ADDRESS, token="s.supersecret", path="agent"))
        self.assertNotIn("supersecret", text)
        self.assertIn("secret/agent", text)

    def test_the_repr_names_the_token_when_a_token_and_a_role_are_given(self):
        """The token takes precedence over the role, and the repr says which one is used."""
        text = repr(BaoSecrets(ADDRESS, token="s.supersecret", role="gateway"))
        self.assertIn("auth=token", text)
        self.assertNotIn("supersecret", text)


class TheSeamIsTheOnlyThingThatChanges(unittest.TestCase):
    """With OpenBao underneath, everything downstream works unchanged."""

    def test_the_gateway_check_works_with_openbao_underneath(self):
        http = FakeHttp({"/v1/auth/kubernetes/login": login_ok(),
                         "/v1/secret/data/agent": kv(**{DUFFEL_ENV: TOKEN})})
        fh = tempfile.NamedTemporaryFile("w", suffix=".jwt", delete=False)
        fh.write("the.pods.jwt")
        fh.close()
        bao = BaoSecrets(ADDRESS, role="gateway", sa_token_path=fh.name, http=http)
        cfg = verify_world("duffel", bao)
        self.assertEqual(cfg.world, "duffel")
        self.assertTrue(callable(cfg.executor))

    def test_an_empty_store_is_refused_the_same_way_an_empty_environment_is(self):
        http = FakeHttp({"/v1/secret/data/agent": (404, {})})
        bao = BaoSecrets(ADDRESS, token="s.dev", http=http)
        for source in (bao, MappingSecrets({})):
            with self.assertRaises(ConfigurationRefused) as caught:
                verify_world("duffel", source)
            self.assertIn(DUFFEL_ENV, str(caught.exception))

    def test_an_outage_is_not_reported_as_a_missing_credential(self):
        """The distinction survives all the way up to the start-up check."""
        http = FakeHttp({}, raises=TimeoutError("connect timed out"))
        bao = BaoSecrets(ADDRESS, token="s.dev", http=http)
        with self.assertRaises(SecretUnavailable):
            verify_world("duffel", bao)


class ChoosingTheSource(unittest.TestCase):
    """`BAO_ADDR` decides between the environment and OpenBao."""

    def setUp(self):
        self._saved = {k: os.environ.get(k) for k in ("BAO_ADDR", "BAO_ROLE", "BAO_TOKEN")}
        for k in self._saved:
            os.environ.pop(k, None)

    def tearDown(self):
        for k, v in self._saved.items():
            os.environ.pop(k, None)
            if v is not None:
                os.environ[k] = v

    def test_without_an_address_the_environment_holds_the_credentials(self):
        self.assertIsInstance(secret_source_from_env(), EnvSecrets)

    def test_with_an_address_openbao_does(self):
        os.environ["BAO_ADDR"] = ADDRESS
        os.environ["BAO_ROLE"] = "gateway"
        source = secret_source_from_env()
        self.assertIsInstance(source, BaoSecrets)
        self.assertEqual(source.role, "gateway")


if __name__ == "__main__":
    unittest.main(verbosity=1)
