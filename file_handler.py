import logging
import json
import os


def read_file(file_path):
    logging.info(f'Reading file {file_path}')
    with open(file_path, 'r') as f:
        content = f.readlines()
    return content


def append_file(outfile, content):
    with open(outfile, 'a') as f:
        for line in content:
            f.write(str(line))


def save_json(outfile, content):
    """ Generic function to save dictionary data to a JSON file"""
    logging.info(f"Written JSON as {outfile}")
    with open(outfile, 'w') as f:
        json.dump(content, f, indent=4)


def get_json(file_name):
    """ Generic function to retrieve data from JSON file"""
    with open(file_name) as f:
        data = json.load(f)
        return data


def get_file_paths(root_path):
    files = []

    dirlist = [root_path]

    while len(dirlist) > 0:
        for (dirpath, dirnames, filenames) in os.walk(dirlist.pop()):
            dirlist.extend(dirnames)
            files.extend(map(lambda n: os.path.join(*n), zip([dirpath] * len(filenames), filenames)))
    return files