import yaml
import argparse
import json
import os
import sys
import logging
from jinja2 import Environment, FileSystemLoader
from datetime import datetime

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data

def report(report_dir, yara_data=[], pattern_data={}):
    env = Environment(loader=FileSystemLoader("./"))
    template = env.get_template("templates/report.html")
    html = template.render(
        pattern_result=pattern_data,
        yara_result=yara_data
    )

    with open(os.path.join(report_dir, "report.html"), "w") as f:
        f.write(html)

def validate_config(args, config):
    if args.capture and not args.interfaces and config['modules']['capture']['enable_network']:
        print("-if / --interfaces is required when using --capture and network capturing is enabled in configuration")
        sys.exit(1)
    if (args.pattern or args.yara) and not args.target_path:
        print("-tp / --target-path is required with --yara and --pattern")
        sys.exit(1)

def main(args):
    config = load_config(args.config)
    validate_config(args, config)
    outdir = os.path.join(config['outdir'], datetime.now().strftime("%Y%m%d_%H%M%S"))
    os.makedirs(outdir, exist_ok=True)
    pattern_result = []
    yara_result = []
    if args.capture:
        logging.info("Running capture module")
        import modules.mod_capture as mcap
        mod_capture = config['modules']['capture']
        if mod_capture['enable_memory']:
            mcap.memory(outdir, mod_capture['memory'])
        if mod_capture['enable_network']:
            mcap.network_interfaces(outdir, int(mod_capture['network_timeout']), args.interfaces.strip().split(','))
    if args.collect:
        logging.info("Running collect module")
        import modules.mod_collect as mc
        mod_collect = config['modules']['collect']
        if mod_collect['enable_commnds']:
            mc.commands(outdir, mod_collect['commands'])
        if mod_collect['enable_luks']:
            mc.find_luks_devices(outdir)
        if mod_collect['enable_checksums']:
            mc.checksums(outdir, mod_collect['checksums'])
        if mod_collect['enable_files_and_dirs']:
            mc.files_and_dirs(outdir, mod_collect['files_and_dirs'])
    if args.pattern:
        logging.info("Running pattern module")
        import modules.mod_pattern as mp
        mod_pattern = config['modules']['pattern']
        pattern_result = mp.search(mod_pattern['patterns_dir'], args.target_path)
        print(json.dumps(pattern_result, indent=2))
    if args.yara:
        logging.info("Running yara module")
        import modules.mod_yara as my
        mod_yara = config['modules']['yara']
        yara_result = my.search(mod_yara['rules_dir'], args.target_path)
        print(json.dumps(yara_result, indent=2))
    report(outdir, yara_data=yara_result, pattern_data=pattern_result)

def parse_args():
    parser = argparse.ArgumentParser(
        description="PyTriage"
    )
    parser.add_argument(
        "-c", "--config",
        required=True,
        help="Path to the YAML configuration file"
    )

    parser.add_argument(
        "-tp", "--target-path",
        required=False,
        help="Target file/directory for pattern matching"
    )

    parser.add_argument(
        "--yara",
        action='store_true',
        help="Enable yara module"
    )

    parser.add_argument(
        "--pattern",
        action='store_true',
        help="Enable pattern module"
    )

    parser.add_argument(
        "--collect",
        action='store_true',
        help="Enable collect module"
    )

    parser.add_argument(
        "--capture",
        action='store_true',
        help="Enable capture module"
    )

    parser.add_argument(
        "-if", "--interfaces",
        required=False,
        help="Interfaces for capture module. Multiple interfaces can be seperated with comma"
    )

    args = parser.parse_args()
    return args

if __name__ == "__main__":
    args = parse_args()
    main(args)
