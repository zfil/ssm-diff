#!/usr/bin/env python
import argparse
import logging
import os
import sys
import traceback

from states import *

root = logging.getLogger()
root.setLevel(logging.INFO)

handler = logging.StreamHandler(sys.stdout)
handler.setLevel(logging.INFO)
formatter = logging.Formatter('%(name)s - %(message)s')
handler.setFormatter(formatter)
root.addHandler(handler)


def configure_endpoints(args):
    # configure() returns a DiffBase class (whose constructor may be wrapped in `partial` to pre-configure it)
    diff_class = DiffBase.get_plugin(args.engine).configure(args)
    return storage.ParameterStore(args.profile, diff_class, paths=args.paths, no_secure=args.no_secure,
                                  no_decrypt=args.no_decrypt), \
           storage.YAMLFile(args.filename, root_path=args.yaml_root, paths=args.paths, no_secure=args.no_secure,
                            no_decrypt=args.no_decrypt)


def clone(args):
    """Create a local YAML file from the SSM Parameter Store (per configs in args)"""
    remote, local = configure_endpoints(args)
    if not args.force and local.exists():
        raise ValueError('File already exists, use `pull` instead')
    local.save(remote.clone())


def pull(args):
    """Update local YAML file with changes in the SSM Parameter Store (per configs in args)"""
    remote, local = configure_endpoints(args)
    if not local.exists():
        raise ValueError('File does not exist, use `clone` instead')
    local.save(remote.pull(local.get()))


def push(args):
    """Apply local changes to the SSM Parameter Store"""
    remote, local = configure_endpoints(args)
    if not local.exists():
        raise ValueError('File does not exist.  Adjust the target file using `-f` or get started using `clone`.')
    print("\nPushing changes...")
    try:
        remote.push(local.get())
    except Exception as e:
        print("Failed to push changes to remote:", e)
        traceback.print_exc(10)
    print("Done.")


def plan(args):
    """Print a representation of the changes that would be applied to SSM Parameter Store if applied (per config in args)"""
    remote, local = configure_endpoints(args)
    if not local.exists():
        raise ValueError('File does not exist.  Adjust the target file using `-f` or get started using `clone`.')
    print(DiffBase.describe_diff(remote.dry_run(local.get())))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('-f', help='local state yml file', action='store', dest='filename')
    parser.add_argument('--engine', '-e', help='diff engine to use when interacting with SSM', action='store',
                        dest='engine', default='DiffResolver')
    parser.add_argument('--profile', help='AWS profile name', action='store', dest='profile')
    subparsers = parser.add_subparsers(title='commands', dest='command', help='commands', required=True)

    parser_clone = subparsers.add_parser('clone', help='create a local copy of the remote storage')
    parser_clone.set_defaults(command=clone)
    parser_clone.add_argument('--force', help='overwrite local changes', action='store_true', dest='force')

    parser_pull = subparsers.add_parser('pull', help='pull changes from remote state')
    parser_pull.set_defaults(command=pull)
    parser_pull.add_argument('--force', help='overwrite local changes', action='store_true', dest='force')

    parser_plan = subparsers.add_parser('plan', help='display changes between local and remote states')
    parser_plan.set_defaults(command=plan)

    parser_push = subparsers.add_parser('push', help='push changes to the remote storage')
    parser_push.set_defaults(command=push)

    args = parser.parse_args()

    args.no_secure = os.environ.get('SSM_NO_SECURE', 'false').lower() in ['true', '1']
    args.no_decrypt = os.environ.get('SSM_NO_DECRYPT', 'false').lower() in ['true', '1']
    args.yaml_root = os.environ.get('SSM_YAML_ROOT', '/')
    args.paths = os.environ.get('SSM_PATHS', None)
    if args.paths is not None:
        args.paths = args.paths.replace(';', ':').split(':')
    else:
        # this defaults to '/'
        args.paths = [args.yaml_root]

    # root filename
    if args.filename is not None:
        filename = args.filename
    elif args.yaml_root != '/':
        filename = args.yaml_root.replace('/', '~')
    elif args.profile:
        filename = args.profile
    elif 'AWS_PROFILE' in os.environ:
        filename = os.environ['AWS_PROFILE']
    else:
        filename = 'parameters'

    # remove extension (will be restored by storage classes)
    if filename[-4:] == '.yml':
        filename = filename[:-4]
    args.filename = filename

    args.command(args)


if __name__ == "__main__":
    main()
