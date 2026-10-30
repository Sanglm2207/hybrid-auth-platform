#!/usr/bin/env python3
"""Enforce aggregate line coverage, including libraries exercised by service tests."""
from pathlib import Path
import xml.etree.ElementTree as ET

report = Path(__file__).resolve().parents[2] / 'coverage-report/target/site/jacoco-aggregate/jacoco.xml'
root = ET.parse(report).getroot()  # Missing/malformed report must fail CI.
counter = root.find("counter[@type='LINE']")
if counter is None:
    raise SystemExit('No line coverage data in aggregate report')
covered, missed = int(counter.attrib['covered']), int(counter.attrib['missed'])
ratio = covered / (covered + missed) if covered + missed else 0
print(f'Aggregate line coverage: {ratio:.2%} ({covered}/{covered + missed})')
if ratio < .70:
    raise SystemExit('Aggregate line coverage is below 70%')
