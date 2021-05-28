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


def get_process_files(args):
    """ Getting the list of files from the command line argument"""
    file_list = []

    if args.directory is not None:
        base_dir = args.directory
        files = os.listdir(base_dir)
        logging.info(f'Setting root to: {args.directory}')

        for file in files:
            full_path = base_dir + '\\' + file
            file_list.append(full_path)

    elif args.file is not None:
        file_list.append(args.file)
        logging.info(f'Starting single file scan on {args.file}')
    else:
        print(f"No vaild input was supplied, exiting program, use -h / -? for help.")
        exit(1)

    return file_list
