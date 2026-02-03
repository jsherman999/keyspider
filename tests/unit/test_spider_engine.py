"""Tests for the spider engine."""

import pytest

from keyspider.core.spider_engine import SpiderProgress


class TestSpiderProgress:
    def test_initial_state(self):
        progress = SpiderProgress()
        assert progress.servers_scanned == 0
        assert progress.keys_found == 0
        assert progress.events_parsed == 0
        assert progress.unreachable_found == 0
        assert progress.current_depth == 0
        assert len(progress.visited) == 0
        assert len(progress.queue) == 0

    def test_visited_tracking(self):
        progress = SpiderProgress()
        progress.visited.add("10.0.0.1:22")
        progress.visited.add("10.0.0.2:22")
        assert len(progress.visited) == 2
        assert "10.0.0.1:22" in progress.visited

    def test_queue_management(self):
        progress = SpiderProgress()
        progress.queue.append(("10.0.0.1", 22, 0))
        progress.queue.append(("10.0.0.2", 22, 1))
        assert len(progress.queue) == 2
        host, port, depth = progress.queue.pop(0)
        assert host == "10.0.0.1"
        assert depth == 0
