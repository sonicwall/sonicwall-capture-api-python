# -*- coding: utf-8 -*-
import json
import hashlib
import click

from capture_api import CaptureAPI

class CLI(object):

    def __init__(self, server, sn, key):
        self.api = CaptureAPI(server, sn, key)

    def call_method(self, method_name, *args):
        _, resp = getattr(self.api, method_name)(*args)
        click.echo(json.dumps(resp, indent=2))


@click.group()
@click.argument('server')
@click.argument('sn')
@click.argument('key')
@click.pass_context
def cli(ctx, server, sn, key):
    ctx.obj = CLI(server, sn, key)


pass_helper = click.make_pass_decorator(CLI)


@cli.command()
@click.argument("hash_type", type=click.Choice(["md5", "sha1", "sha256"]))
@click.argument("input_file", type=click.File("rb"))
def file_hash(hash_type, input_file):
    hash_obj = hashlib.new(hash_type)
    while True:
        chunk = input_file.read(8192)
        if not chunk:
            break
        hash_obj.update(chunk)
    click.echo(hash_obj.hexdigest())


@cli.command()
@click.argument("input_file")
@pass_helper
def file_scan(helper, input_file):
    helper.call_method("file_scan", input_file)


@cli.command()
@click.argument("resource")
@click.option('--all_info', is_flag=True)
@pass_helper
def file_report(helper, resource, all_info):
    helper.call_method("file_report", resource, all_info)


@cli.command()
@click.option("--after", default=None, type=click.INT)
@click.option("--before", default=None, type=click.INT)
@click.option("--page_size", default=None, type=click.INT)
@click.option("--page_index", default=None, type=click.INT)
@pass_helper
def file_list(helper, after, before, page_size, page_index):
    helper.call_method("file_list", after, before, page_size, page_index)


@cli.command()
@click.argument("sha256")
@pass_helper
def file_artifact(helper, sha256):
    helper.call_method("file_artifact", sha256)


@cli.command()
@click.argument("sha256")
@click.argument("engine")
@click.argument("env")
@click.argument("type")
@click.argument("save_dir")
@pass_helper
def file_download(helper, sha256, engine, env, type, save_dir):
    helper.call_method("file_download", sha256, engine, env, type, save_dir)


if __name__ == "__main__":
    cli()