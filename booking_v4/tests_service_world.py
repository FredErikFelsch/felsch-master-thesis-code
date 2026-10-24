"""Tests that both booking_v4 entry points mean the same thing by "live".

`booking_v4.durable.ExternalWorld` defaults to the booking_v2 catalogue, which keeps every
recorded run reproducible. That default is also the risky one: a process configured for a
real counterparty that built the default instead would come up, answer and look like a live
one. These tests pin the opposite: a world that is not the catalogue either yields a live
executor or the process refuses to start, and a durable world store wraps the live executor
rather than replacing it.
"""
from __future__ import annotations

import json
import pathlib
import tempfile
import unittest

from booking_live.secrets import MappingSecrets
from booking_live.tests_live import Call, FixtureTransport

from .service_world import DEFAULT_WORLD, WorldRefused, gateway_executor, live_executor_for

REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
FIXTURES = REPO_ROOT / "booking_live" / "fixtures"
CREDS = MappingSecrets({"DUFFEL_TOKEN": "duffel_test_fixture", "SERPAPI_KEY": "serp_fixture"})


def duffel_search_transport() -> FixtureTransport:
    """One recorded Duffel answer, so the live path can be exercised without a network."""
    body = json.loads((FIXTURES / "duffel_offer_request.json").read_text())
    return FixtureTransport(answers=[(200, body)])


class CatalogueTests(unittest.TestCase):
    """The catalogue needs no executor of its own and is not a live world."""

    def test_the_catalogue_needs_no_executor(self):
        """"mock" means the gateway keeps its own default, which is the booking_v2 catalogue."""
        self.assertIsNone(gateway_executor(DEFAULT_WORLD))

    def test_the_catalogue_is_not_a_live_world(self):
        with self.assertRaises(WorldRefused) as raised:
            live_executor_for(DEFAULT_WORLD)
        self.assertIn("catalogue", str(raised.exception))

    def test_a_world_store_on_the_catalogue_still_answers(self):
        with tempfile.TemporaryDirectory() as d:
            executor = gateway_executor(DEFAULT_WORLD, str(pathlib.Path(d, "w.db")))
            self.assertIsNotNone(executor)


class RefusalTests(unittest.TestCase):
    """A live world that cannot be served is refused before anything is opened."""

    def test_a_live_world_without_a_credential_refuses(self):
        """The failure mode this module exists for: a refusal, not a fallback."""
        with self.assertRaises(WorldRefused) as raised:
            gateway_executor("duffel", source=MappingSecrets({}))
        self.assertIn("DUFFEL_TOKEN", str(raised.exception))

    def test_an_unknown_world_refuses(self):
        with self.assertRaises(WorldRefused) as raised:
            gateway_executor("skyscanner", source=CREDS)
        self.assertIn("skyscanner", str(raised.exception))

    def test_a_refusal_happens_before_any_store_is_opened(self):
        """No world store is created for a configuration that cannot be served."""
        with tempfile.TemporaryDirectory() as d:
            db = pathlib.Path(d, "w.db")
            with self.assertRaises(WorldRefused):
                gateway_executor("duffel", str(db), source=MappingSecrets({}))
            self.assertFalse(db.exists(), "the store was created for a refused configuration")


class LiveWiringTests(unittest.TestCase):
    """The executor that comes back reaches the counterparty."""

    def test_a_live_world_reaches_the_transport(self):
        transport = duffel_search_transport()
        executor = gateway_executor("duffel", source=CREDS, transport=transport)
        executor(Call("search", origin="JFK", destination="EWR", date="2026-10-01"))
        self.assertTrue(transport.seen, "the live executor never reached the counterparty")
        self.assertIn("api.duffel.com", transport.seen[0][1])

    def test_a_world_store_wraps_the_live_executor_and_does_not_replace_it(self):
        """The regression that would otherwise go unnoticed: a durable world store with the catalogue underneath."""
        transport = duffel_search_transport()
        with tempfile.TemporaryDirectory() as d:
            executor = gateway_executor("duffel", str(pathlib.Path(d, "w.db")),
                                        source=CREDS, transport=transport)
            executor(Call("search", origin="JFK", destination="EWR", date="2026-10-01"))
        self.assertTrue(transport.seen, "the world store silently served the catalogue")
        self.assertIn("api.duffel.com", transport.seen[0][1])


class EntryPointTests(unittest.TestCase):
    """Both process entry points wire their world through `service_world` and build none themselves."""

    ENTRY_POINTS = ("service_process.py", "service_process_tcp.py")

    def source(self, name: str) -> str:
        """Return the source text of one entry point."""
        return (pathlib.Path(__file__).resolve().parent / name).read_text()

    def test_neither_entry_point_builds_a_world_itself(self):
        for name in self.ENTRY_POINTS:
            with self.subTest(name):
                self.assertNotIn("ExternalWorld", self.source(name))

    def test_both_entry_points_use_the_one_wiring_path(self):
        for name in self.ENTRY_POINTS:
            with self.subTest(name):
                s = self.source(name)
                self.assertIn("from .service_world import", s)
                self.assertIn("gateway_executor(args.world, args.world_db, args.idempotent)", s)

    def test_both_entry_points_refuse_to_start_on_a_refused_world(self):
        for name in self.ENTRY_POINTS:
            with self.subTest(name):
                s = self.source(name)
                self.assertIn("except WorldRefused as refused:", s)
                self.assertIn("refusing to start:", s)
                self.assertIn("return 4", s)

    def test_both_entry_points_default_to_the_catalogue(self):
        """Every recorded run keeps its behaviour: the default is and stays "mock"."""
        for name in self.ENTRY_POINTS:
            with self.subTest(name):
                self.assertIn('parser.add_argument("--world", default=DEFAULT_WORLD,',
                              self.source(name))


if __name__ == "__main__":
    unittest.main(verbosity=2)
