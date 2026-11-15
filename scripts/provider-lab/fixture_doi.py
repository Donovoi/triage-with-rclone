"""Anonymous DOI resolver + Dataverse, InvenioRDM and Zenodo read fixtures."""
import hashlib
import posixpath
import re

from fixture_read_api import ReadState, ReadHandler, serve_read_api

DOI = "10.0000/zenodo.123"
MISSING_DOI = "10.0000/missing-synthetic"
FORMATS = ("dataverse", "invenio", "zenodo")
STAMP = "2024-01-01T00:00:00Z"


class DoiState(ReadState):
    def __init__(self, provider):
        if provider not in FORMATS:
            raise ValueError("invalid_doi_provider")
        super().__init__()
        self.provider = provider
        self.ids = {str(101 + index): name for index, name in enumerate(sorted(self.files))}
        self.resolver_denied = 0


class DoiHandler(ReadHandler):
    def catalog(self, origin):
        state = self.server.state
        state.events.append(("catalog", state.provider))
        if state.provider == "dataverse":
            files = [{"directoryLabel": posixpath.dirname(name), "dataFile": {
                "id": int(key), "filename": posixpath.basename(name), "filesize": len(state.files[name]),
                "contentType": "application/octet-stream", "md5": hashlib.md5(state.files[name]).hexdigest()}}
                for key, name in state.ids.items()]
            return {"status": "OK", "data": {"latestVersion": {"lastUpdateTime": STAMP, "files": files}}}
        return {"entries": [{"key": name, "checksum": "md5:" + hashlib.md5(state.files[name]).hexdigest(),
                             "size": len(state.files[name]), "updated": STAMP, "mimetype": "application/octet-stream",
                             "links": {"content": origin + "/content/" + key}}
                            for key, name in state.ids.items()]}

    def dispatch(self):
        with self.server.state.lock:
            request = self.wire()
            if request is None:
                return
            path, query = request
            state = self.server.state
            origin = f"http://127.0.0.1:{self.server.server_address[1]}"
            prefix = "/api/access/datafile/" if state.provider == "dataverse" else "/content/"
            match = re.fullmatch(re.escape(prefix) + r"([0-9]{1,6})", path)
            payload_query = {"format": "original"} if state.provider == "dataverse" else {}
            if (self.headers.get("Authorization") is not None
                    or self.command not in ("GET", "DELETE")
                    or self.headers.get("Range") is not None and (not match or self.command != "GET")
                    or self.command == "DELETE" and (not match or query != payload_query)):
                self.reject()
                return
            if match:
                if query != payload_query:
                    self.reject()
                    return
                name = state.ids.get(match[1])
                if name is None:
                    state.missing += 1
                    self.json_reply(404, {"error": "synthetic object missing"})
                elif self.command == "DELETE":
                    self.write_denial(name)
                else:
                    self.payload(name)
                return
            if self.command != "GET":
                self.reject()
                return
            if path.startswith("/resolver/handles/") and query == {"index": "1"}:
                doi = path.removeprefix("/resolver/handles/")
                if doi == MISSING_DOI:
                    state.resolver_denied += 1
                    state.events.append(("resolver_denied", state.provider))
                    self.json_reply(200, {"responseCode": 100, "values": []})
                    return
                if doi != DOI:
                    self.reject()
                    return
                state.events.append(("resolver", state.provider))
                target = (origin + "/dataset.xhtml?persistentId=doi:" + DOI if state.provider == "dataverse"
                          else origin + "/records/123")
                self.json_reply(200, {"responseCode": 1, "handle": DOI, "values": [
                    {"index": 1, "type": "URL", "data": {"format": "string", "value": target}}]})
            elif (state.provider == "dataverse" and path == "/api/datasets/:persistentId/"
                  and query == {"persistentId": "doi:" + DOI}):
                self.json_reply(200, self.catalog(origin))
            elif state.provider in ("invenio", "zenodo") and path == "/records/123" and not query:
                state.events.append(("landing", state.provider))
                self.reply(200, b"synthetic record", {"Content-Type": "text/html"})
            elif state.provider in ("invenio", "zenodo") and path == "/api/records/123" and not query:
                state.events.append(("record", state.provider))
                self.json_reply(200, {"links": {"self": origin + "/api/records/123"}})
            elif state.provider in ("invenio", "zenodo") and path == "/api/records/123/files" and not query:
                self.json_reply(200, self.catalog(origin))
            else:
                self.reject()

    do_GET = dispatch
    do_HEAD = dispatch
    do_POST = dispatch
    do_PUT = dispatch
    do_DELETE = dispatch


def serve_doi(state):
    return serve_read_api(state, DoiHandler)
