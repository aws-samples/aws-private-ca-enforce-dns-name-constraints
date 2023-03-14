# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: MIT-0

import base64
import argparse
import json
import logging

from cryptography.x509 import NameConstraints, DNSName


def main():
    """
    Summary:
        This function takes a list of permitted/excluded domain subtrees and prints them to an API passthrough file
    Example:
        # Create name constraints file for example.com's dev and test subdomains but exclude prod.dev subdomain.
        python name-constraints-encoder.py -p .dev.example.com,.test.example.com -e .prod.dev.example.com
    Notes:
        If there is an existing file at the target output location, this script will overwrite it.
        Do not include spaces in the input subtree list.
    """
    logging.basicConfig(level=logging.INFO)  # DEBUG to debug
    # Initialize Argument Parser
    parser = argparse.ArgumentParser()

    # Adding Arguments
    parser.add_argument(
        "-p",
        "--Permitted",
        help="Permitted Subtree List (e.g. .test.example.com,.dev.example.com). "
             + "Do not include spaces in the subtree list.",
    )

    parser.add_argument(
        "-e",
        "--Excluded",
        help="Excluded Subtree List (e.g. .prod.dev.example.com,.production.dev.example.com). "
             + "Any name matching a restriction in the excludedSubtrees field is "
             + "invalid regardless of information appearing in the permittedSubtrees. "
             + "Do not include spaces in the subtree list.",
    )

    # Read arguments from command line
    args = parser.parse_args()

    permitted_subtrees = []
    excluded_subtrees = None

    if (not args.Permitted) and (not args.Excluded):
        raise ValueError(
            "You didn't provide any permitted or excluded name constraints in your arguments.\r\n"
            + "Run this script again with at least one permitted or excluded subtree argument.",
        )

    # Permitted Subtrees
    if args.Permitted:
        for permit in args.Permitted.split(","):
            permitted_subtrees.append(DNSName(permit))

    # Excluded Subtrees will override Permitted Subtrees
    if args.Excluded:
        excluded_subtrees = []
        for exclude in args.Excluded.split(","):
            excluded_subtrees.append(DNSName(exclude))

    logging.info(f"Permitted Subtrees: {permitted_subtrees}")
    logging.info(f"Excluded Subtrees: {excluded_subtrees}")

    encode_name_constraints(permitted_subtrees, excluded_subtrees)


def encode_name_constraints(permitted_subtrees, excluded_subtrees):
    name_constraint = NameConstraints(permitted_subtrees, excluded_subtrees)
    name_constraint_bytes = name_constraint.public_bytes()
    encoded = base64.b64encode(name_constraint_bytes)
    logging.info("Successfully Encoded Name Constraints. Writing to file...")
    create_api_passthrough_json(encoded)


def create_api_passthrough_json(encoded, output_file_name="api_passthrough_config.json"):
    data_json = {
        "Extensions": {
            "CustomExtensions": [
                {
                    "ObjectIdentifier": "2.5.29.30",
                }
            ]
        }
    }

    data_json["Extensions"]["CustomExtensions"][0]["Value"] = encoded.decode("utf-8")
    data_json["Extensions"]["CustomExtensions"][0]["Critical"] = True

    file = open(output_file_name, "w")
    json.dump(data_json, file, indent=4)  # include indent for pretty-print
    file.close()

    logging.info(f"API Passthrough File Created: {output_file_name}")


if __name__ == "__main__":
    main()
