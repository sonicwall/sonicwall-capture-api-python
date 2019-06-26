# -*- coding: utf-8 -*-
import os
import json
import hashlib
try:
    from urllib.parse import urljoin
except:
    from urlparse import urljoin

import requests

def file_hash(hash_type, file_path):
    if not os.path.isfile(file_path):
        raise Exception("not a valid file_path")
    try:
        hash_obj = hashlib.new(hash_type)
    except ValueError as e:
        raise e
    with open(file_path, "rb") as file_obj:
        while True:
            chunk = file_obj.read(8192)
            if not chunk:
                break
            hash_obj.update(chunk)
    return hash_obj.hexdigest()

class CaptureAPI(object):
    def __init__(self, server, sn, api_key, base_path="/external/v1"):
        self.server = server
        self.base_path = base_path
        self.session = requests.session()
        self.session.verify = False
        self.session.auth = (sn, api_key)

    def __del__(self):
        self.session.close()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.session.close()

    def _send_request(self, method, path, files=None, timeout=10, stream=False):
        url = urljoin(self.server, self.base_path + path)
        resp = self.session.request(
            method, url, files=files, timeout=timeout, stream=stream)
        if resp.headers["Content-Type"] == "application/json":
            return resp.status_code, resp.json()
        return resp.status_code, resp

    def file_scan(self, file_path):
        if not os.path.isfile(file_path):
            raise Exception("invalid file path")
        with open(file_path, "rb") as file_obj:
            status_code, data = self._send_request(
                "POST", "/file/scan", files={"filestream": file_obj})
        return status_code, data

    def file_report(self, resource, all_info=False):
        allinfo = "true" if all_info is True else "false"
        path = "/file/report?resource={}&all_info={}".format(resource, allinfo)
        resp = self._send_request("GET", path)
        return resp

    def file_list(self, after=None, before=None, page_size=None, page_index=None):
        query_strs = list()
        if after is not None:
            query_strs.append("after={}".format(after))
        if before is not None:
            query_strs.append("before={}".format(before))
        if page_size is not None:
            query_strs.append("page_size={}".format(page_size))
        if page_index is not None:
            query_strs.append("page_index={}".format(page_index))
        path = "/file/list"
        if query_strs:
            path += "?"+"&".join(query_strs)
        resp = self._send_request("GET", path)
        return resp

    def file_artifact(self, sha256):
        path = "/file/artifact?sha256={}".format(sha256)
        return self._send_request("GET", path)

    def file_download(self, sha256, engine, env, type_name, save_dir):
        path = "/file/download?sha256={}&engine={}&env={}&type={}".format(
            sha256, engine, env, type_name)
        status_code, resp = self._send_request("GET", path, stream=True)
        if status_code != 200:
            return status_code, resp
        content_disposition = resp.headers.get("Content-Disposition", "")
        file_name = content_disposition[content_disposition.find("=")+1:]
        if os.path.isdir(save_dir):
            file_path = os.path.join(save_dir, file_name)
            with open(file_path, 'wb') as f:
                for chunk in resp.iter_content(chunk_size=8192):
                    if chunk:
                        f.write(chunk)
            return status_code, file_path
        else:
            raise Exception("invalid directory")
