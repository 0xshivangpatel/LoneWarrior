
import pytest
import os
import sqlite3
from lonewarrior.storage.database import Database
from lonewarrior.storage.models import Event, EventType

class TestDatabase:
    @pytest.fixture
    def db_path(self, tmp_path):
        return str(tmp_path / "test.db")

    @pytest.fixture
    def db(self, db_path):
        return Database(db_path)

    def test_schema_init(self, db):
        """Test that schema is initialized correctly"""
        with db.get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            assert "events" in tables
            assert "detections" in tables
            assert "actions" in tables

    def test_insert_get_event(self, db):
        """Test inserting and retrieving events"""
        event = Event(
            event_type=EventType.PROCESS_NEW.value,
            source="test_collector",
            data={"pid": 1234},
            baseline_phase=0
        )
        
        event_id = db.insert_event(event)
        assert event_id is not None
        
        events = db.get_events(limit=1)
        assert len(events) == 1
        assert events[0].data['pid'] == 1234
