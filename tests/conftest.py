import pytest

from aisoc import pipeline


@pytest.fixture(scope="session")
def learning():
    return pipeline.run("learning")


@pytest.fixture(scope="session")
def baseline():
    return pipeline.run("baseline")


def case(run, tenant, incident):
    return next(c for c in run.tenants[tenant].cases if c.incident.id == incident)
