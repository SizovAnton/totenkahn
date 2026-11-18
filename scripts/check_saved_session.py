from pathlib import Path
import json
import argparse
from handlers.file_handlers import load_sigma_rule

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--rule', required=True, type=Path)
    args = parser.parse_args()
    script_path = Path(__file__).resolve()
    project_dir = script_path.parents[1]
    events_path = project_dir / 'correlation-check' / 'events.json'

    with events_path.open('r', encoding='utf-8') as file:
        events = json.load(file)

    rule_path = args.rule
    rule = load_sigma_rule(rule_path)
    print('Event count:', len(events))

if __name__ == '__main__':
    main()
