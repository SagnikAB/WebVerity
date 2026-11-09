"""Database migration tests for existing SQLite schemas."""

from backend.app.database.connection import _apply_phase2_migrations
from sqlalchemy import create_engine, inspect, text


def test_phase2_migration_adds_column_and_is_idempotent():
    test_engine = create_engine("sqlite:///:memory:")
    with test_engine.begin() as connection:
        connection.execute(text('CREATE TABLE scans ("id" VARCHAR(36) PRIMARY KEY)'))
        connection.execute(
            text('INSERT INTO scans ("id") VALUES (:id)'),
            {"id": "existing"},
        )

    _apply_phase2_migrations(test_engine)
    _apply_phase2_migrations(test_engine)

    columns = {column["name"] for column in inspect(test_engine).get_columns("scans")}
    assert "security_posture_score" in columns
    with test_engine.connect() as connection:
        value = connection.execute(
            text('SELECT "security_posture_score" FROM scans WHERE id = :id'),
            {"id": "existing"},
        ).scalar_one()
    assert value == 100
