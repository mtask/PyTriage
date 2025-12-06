import yaml
import argparse
import json
import os
import sys
import logging
from jinja2 import Environment, FileSystemLoader

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

def load_config(path):
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)
    return data

def report(yara_data=[], pattern_data={}):
    os.makedirs("output", exist_ok=True)
    env = Environment(loader=FileSystemLoader("./"))
    template = env.get_template("templates/report.html")
    html = template.render(
        pattern_result=pattern_data,
        yara_result=yara_data
    )

    with open("output/report.html", "w") as f:
        f.write(html)


def main(args):
    config = load_config(args.config)
    pattern_result = []
    yara_result = []
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
    if args.collect:
        logging.info("Running collect module")
        import modules.mod_collect as mc
        mod_collect = config['modules']['collect']
        mc.commands(mod_collect['outdir'], mod_collect['commands'])
        mc.find_luks_devices(mod_collect['outdir'])
        mc.checksums(mod_collect['outdir'], mod_collect['checksums'])
        mc.files_and_dirs(mod_collect['outdir'], mod_collect['files_and_dirs'])
    #report(yara_data=yara_result, pattern_data=pattern_result)

def parse_args():
    parser = argparse.ArgumentParser(
        description="Example script that loads a YAML config file."
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

    args = parser.parse_args()
    return args


if __name__ == "__main__":
    args = parse_args()
    main(args)
