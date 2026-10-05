"""Pure, bounded observation export; never a Maven effective-model evaluator.

The caller owns tar validation and binds selected_runtime to actual JAR bytes.
No input is fetched, executed, extracted or written by this module. Public POM
URLs are derived coordinate locators, not assertions that Central was contacted.
Source contract: dependency-plugin 3.11.0 JsonDependencyNodeVisitor and
dependency-tree 3.3.0 VerboseDependencyNode/SerializingDependencyNodeVisitor.
"""

import copy
import hashlib
import json
import re
import xml.etree.ElementTree as ET

CENTRAL = "https://repo.maven.apache.org/maven2/"
MAX_POM = 4 * 1024 * 1024
MAX_POMS_BYTES = 32 * 1024 * 1024
MAX_GRAPH = 8 * 1024 * 1024
MAX_NODES = 8192
MAX_DEPTH = 64
MAX_ELEMENTS = 20000
# The observed Maven dependency cache exceeds 100,000 POM elements.
# Retain per-file elements, file/aggregate bytes, depth and output bounds.
MAX_TOTAL_ELEMENTS = 500000
MAX_OUTPUT = 32 * 1024 * 1024
TOKEN = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.+-]{0,127}\Z")
SCOPES = {"", "compile", "runtime", "provided", "test", "system", "import"}
COORD_KEYS = {"group", "artifact", "version", "classifier", "type"}
ROOT = {"group": "org.example.synthetic", "artifact": "hdfs-normal-runtime-resolution",
        "version": "1.0.0", "classifier": "", "type": "pom"}
CODES = {"input_invalid", "input_limit", "coordinate_invalid", "json_invalid",
         "tree_invalid", "tree_mismatch", "text_invalid", "classpath_mismatch",
         "pom_invalid", "pom_hash_mismatch", "duplicate_pom", "output_limit"}
POM_REASON_CODES = {
    **{reason: "pom_invalid" for reason in (
        "doctype", "entity", "processing_instruction", "utf8_decode", "xml_parse", "project_root",
        "element_tag", "namespace", "element_name", "model_version", "coordinate_mismatch",
        "duplicate_field", "exclusion_shape", "dependency_shape", "dependency_management_shape",
        "plugin_shape", "extension_shape", "profile_shape")},
    "content_bounds": "input_limit", "pom_element_limit": "input_limit",
    "aggregate_element_limit": "input_limit", "pom_depth_limit": "input_limit",
}
SOURCES = [
    "https://raw.githubusercontent.com/apache/maven-dependency-plugin/maven-dependency-plugin-3.11.0/src/main/java/org/apache/maven/plugins/dependency/tree/JsonDependencyNodeVisitor.java",
    "https://raw.githubusercontent.com/apache/maven-dependency-tree/maven-dependency-tree-3.3.0/src/main/java/org/apache/maven/shared/dependency/graph/internal/VerboseDependencyNode.java",
    "https://raw.githubusercontent.com/apache/maven-dependency-tree/maven-dependency-tree-3.3.0/src/main/java/org/apache/maven/shared/dependency/graph/traversal/SerializingDependencyNodeVisitor.java",
    "https://maven.apache.org/ref/3.9.16/maven-model/maven.html",
]


class ExportError(ValueError):
    def __init__(self, code, *, pom_reason=None):
        super().__init__(code if code in CODES else "input_invalid")
        self.code = str(self)
        if pom_reason is not None and (type(pom_reason) is not str
                                       or POM_REASON_CODES.get(pom_reason) != self.code):
            raise ValueError("invalid_pom_reason")
        self.pom_reason = pom_reason
        self.pom_diagnostic = None


def need(value, code):
    if not value:
        raise ExportError(code)


def pom_need(value, reason):
    if not value:
        raise ExportError(POM_REASON_CODES[reason], pom_reason=reason)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def token(value, empty=False):
    return (type(value) is str and ((empty and value == "") or
            bool(TOKEN.fullmatch(value)) and value not in {".", ".."}))


def version_token(value):
    return token(value) and not any(x in value.upper() for x in ("SNAPSHOT", "LATEST", "RELEASE"))


def coordinate(value):
    need(type(value) is dict and set(value) == COORD_KEYS, "coordinate_invalid")
    need(all(token(v, k == "classifier") for k, v in value.items()), "coordinate_invalid")
    need(version_token(value["version"]), "coordinate_invalid")
    need(all(token(p) for p in value["group"].split(".")), "coordinate_invalid")
    return dict(value)


def validate_pom_diagnostic(value):
    """Validate closed public failure data; return a defensive copy, never raw XML."""
    keys = {"schema_version", "scope", "code", "reason", "coordinate", "size", "sha256"}
    need(type(value) is dict and set(value) == keys, "input_invalid")
    need(type(value["schema_version"]) is int and value["schema_version"] == 1
         and type(value["scope"]) is str and value["scope"] == "hdfs_pom_rejection"
         and type(value["code"]) is str and value["code"] in {"pom_invalid", "input_limit"}
         and type(value["reason"]) is str and POM_REASON_CODES.get(value["reason"]) == value["code"]
         and type(value["size"]) is int and 0 < value["size"] <= MAX_POM
         and type(value["sha256"]) is str and re.fullmatch(r"[0-9a-f]{64}", value["sha256"]), "input_invalid")
    c = coordinate(value["coordinate"])
    need(c["type"] == "pom" and c["classifier"] == "", "input_invalid")
    return copy.deepcopy(value)


def pom_failure_diagnostic(error):
    """Only export a well-formed diagnostic attached to our matching typed failure."""
    if type(error) is not ExportError:
        return None
    try:
        result = validate_pom_diagnostic(error.pom_diagnostic)
        need(type(error.code) is str and error.code == result["code"]
             and type(error.pom_reason) is str and error.pom_reason == result["reason"], "input_invalid")
    except (ExportError, AttributeError, TypeError, ValueError):
        return None
    return result


def coord_key(value):
    return tuple(value[k] for k in ("group", "artifact", "version", "classifier", "type"))


def pom_coord(value):
    return dict(value, type="pom", classifier="")


def locator(value):
    value = coordinate(value)
    need(value["type"] == "pom" and value["classifier"] == "", "coordinate_invalid")
    return CENTRAL + value["group"].replace(".", "/") + "/" + value["artifact"] + "/" + value["version"] + "/" + value["artifact"] + "-" + value["version"] + ".pom"


def unique(pairs):
    result = {}
    for key, value in pairs:
        need(key not in result, "json_invalid")
        result[key] = value
    return result


def bounded_json(data):
    need(type(data) is bytes and 0 < len(data) <= MAX_GRAPH, "input_limit")
    # Check nesting before invoking the recursive standard decoder.
    depth, quoted, escaped = 0, False, False
    for byte in data:
        if quoted:
            if escaped:
                escaped = False
            elif byte == 92:
                escaped = True
            elif byte == 34:
                quoted = False
        elif byte == 34:
            quoted = True
        elif byte in (91, 123):
            depth += 1
            need(depth <= MAX_DEPTH * 2 + 2, "input_limit")
        elif byte in (93, 125):
            depth -= 1
            need(depth >= 0, "json_invalid")
    need(depth == 0 and not quoted, "json_invalid")
    try:
        return json.loads(data.decode("utf-8"), object_pairs_hook=unique,
                          parse_constant=lambda _: (_ for _ in ()).throw(ExportError("json_invalid")))
    except (ValueError, UnicodeError, RecursionError) as exc:
        if isinstance(exc, ExportError):
            raise
        raise ExportError("json_invalid") from None


def json_nodes(data):
    tree = bounded_json(data)
    result = []
    pending = [(tree, None, 0)]
    required = {"groupId", "artifactId", "version", "type", "scope", "classifier", "optional"}
    while pending:
        node, parent, depth = pending.pop()
        need(len(result) < MAX_NODES and depth <= MAX_DEPTH, "input_limit")
        need(type(node) is dict and required <= set(node) <= required | {"children"}, "tree_invalid")
        c = coordinate({"group": node["groupId"], "artifact": node["artifactId"],
                        "version": node["version"], "type": node["type"], "classifier": node["classifier"]})
        need(type(node["scope"]) is str and node["scope"] in SCOPES
             and type(node["optional"]) is str and node["optional"] in {"true", "false"}, "tree_invalid")
        if parent is None:
            need(c == ROOT and node["scope"] == "" and node["optional"] == "false", "tree_invalid")
        else:
            need(node["scope"] in {"compile", "runtime"}, "tree_invalid")
        children = node.get("children", [])
        need(type(children) is list and len(children) <= MAX_NODES, "tree_invalid")
        index = len(result)
        result.append({"id": index, "parent": parent, "coordinate": c,
                       "scope": node["scope"], "optional": node["optional"] == "true"})
        pending.extend((child, index, depth + 1) for child in reversed(children))
    return result


def text_coordinate(text, root=False):
    fields = text.split(":")
    need(len(fields) == (4 if root else 5) or not root and len(fields) == 6, "text_invalid")
    group, artifact, kind = fields[:3]
    if root:
        classifier, version, scope = "", fields[3], ""
    else:
        classifier, version, scope = ("", fields[3], fields[4]) if len(fields) == 5 else fields[3:]
    need(scope in SCOPES, "text_invalid")
    return coordinate({"group": group, "artifact": artifact, "version": version,
                       "classifier": classifier, "type": kind}), scope


def text_nodes(data):
    need(type(data) is bytes and 0 < len(data) <= MAX_GRAPH, "input_limit")
    try:
        text = data.decode("ascii")
    except UnicodeError:
        raise ExportError("text_invalid") from None
    need("\r" not in text.replace("\r\n", "") and text.endswith("\n"), "text_invalid")
    lines = text.splitlines()
    need(1 <= len(lines) <= MAX_NODES and all(0 < len(x) <= 4096 for x in lines), "input_limit")
    rows, stack = [], []
    for index, line in enumerate(lines):
        if index == 0:
            depth, body = 0, line
        else:
            match = re.fullmatch(r"((?:\|  |   )*)(?:\+- |\\- )(.+)", line)
            need(match is not None, "text_invalid")
            depth, body = len(match[1]) // 3 + 1, match[2]
        need(depth <= MAX_DEPTH and depth <= len(stack), "text_invalid")
        parent = stack[depth - 1] if depth else None
        omitted, clauses = body.startswith("("), []
        if omitted:
            need(body.endswith(")") and " - " in body, "text_invalid")
            value, tail = body[1:-1].split(" - ", 1)
            clauses = tail.split("; ")
        elif " (" in body:
            need(body.endswith(")"), "text_invalid")
            value, tail = body[:-1].split(" (", 1)
            clauses = tail.split("; ")
        else:
            value = body
        c, scope = text_coordinate(value, root=index == 0)
        management, reason, winner = [], None, None
        for clause in clauses:
            if clause == "omitted for duplicate":
                need(reason is None, "text_invalid")
                reason, winner = "duplicate", c["version"]
            elif clause.startswith("omitted for conflict with "):
                need(reason is None, "text_invalid")
                reason, winner = "conflict", clause[len("omitted for conflict with "):]
                need(version_token(winner) and winner != c["version"], "text_invalid")
            else:
                matched = False
                for prefix, kind in (("version managed from ", "version_managed_from"),
                                     ("scope managed from ", "scope_managed_from"),
                                     ("scope updated from ", "scope_updated_from"),
                                     ("scope not updated to ", "scope_not_updated_to")):
                    if clause.startswith(prefix):
                        raw = clause[len(prefix):]
                        need(version_token(raw) if kind == "version_managed_from" else raw in SCOPES - {""}, "text_invalid")
                        need(not any(m["kind"] == kind for m in management), "text_invalid")
                        management.append({"kind": kind, "value": raw})
                        matched = True
                        break
                need(matched, "text_invalid")
        need(omitted == (reason is not None) and (index != 0 or not clauses), "text_invalid")
        rows.append({"parent": parent, "coordinate": c, "scope": scope,
                     "resolution": "omitted" if omitted else "included",
                     "omission_reason": reason, "winner_version": winner, "management": management})
        stack = stack[:depth] + [index]
    return rows


def element_hash(element):
    return digest(ET.tostring(element, encoding="utf-8"))


def value(element, issues):
    """Literal coordinate field or redacted unresolved expression; never env values."""
    if element is None:
        return {"kind": "unspecified"}
    raw = (element.text or "").strip()
    if len(element) == 0 and (version_token(raw) if element.tag == "version" else token(raw)):
        return {"kind": "literal", "value": raw}
    issues.add("unresolved_declaration_values")
    return {"kind": "redacted", "sha256": element_hash(element)}


def children(element, name):
    return [child for child in element if child.tag == name]


def one(element, name):
    found = children(element, name)
    pom_need(len(found) <= 1, "duplicate_field")
    return found[0] if found else None


def declaration(element, issues, kind):
    allowed = {"groupId", "artifactId", "version", "type", "classifier", "scope", "optional", "exclusions"}
    fields = {key: value(one(element, key), issues) for key in
              ("groupId", "artifactId", "version", "type", "classifier", "scope", "optional")}
    exclusions = []
    node = one(element, "exclusions")
    if node is not None:
        for exclusion in node:
            pom_need(exclusion.tag == "exclusion", "exclusion_shape")
            exclusions.append({k: value(one(exclusion, k), issues) for k in ("groupId", "artifactId")})
            if any(c.tag not in {"groupId", "artifactId"} for c in exclusion):
                issues.add("unsupported_pom_elements")
    extra = [c for c in element if c.tag not in allowed]
    if extra:
        issues.add("unsupported_pom_elements")
    return {"kind": kind, "fields": fields, "exclusions": exclusions,
            "canonical_element_sha256": element_hash(element), "unsupported_element_count": len(extra)}


def pom_semantics(content, c, issues, budget):
    pom_need(type(content) is bytes and 0 < len(content) <= MAX_POM, "content_bounds")
    upper = content.upper()
    pom_need(b"<!DOCTYPE" not in upper, "doctype")
    pom_need(b"<!ENTITY" not in upper, "entity")
    pom_need(content.count(b"<?") <= int(content.lstrip().startswith(b"<?xml ")), "processing_instruction")
    try:
        text = content.decode("utf-8")
    except UnicodeError:
        raise ExportError("pom_invalid", pom_reason="utf8_decode") from None
    try:
        root = ET.fromstring(text)
    except (UnicodeError, ET.ParseError, ValueError):
        raise ExportError("pom_invalid", pom_reason="xml_parse") from None
    ns = "{http://maven.apache.org/POM/4.0.0}"
    https_ns = "{https://maven.apache.org/POM/4.0.0}"
    pom_need(root.tag in {"project", ns + "project", https_ns + "project"}, "project_root")
    pending, count = [(root, 0)], 0
    while pending:
        element, depth = pending.pop()
        count += 1
        budget[0] += 1
        pom_need(count <= MAX_ELEMENTS, "pom_element_limit")
        pom_need(budget[0] <= MAX_TOTAL_ELEMENTS, "aggregate_element_limit")
        pom_need(depth <= MAX_DEPTH, "pom_depth_limit")
        pom_need(type(element.tag) is str, "element_tag")
        if element.tag.startswith(ns):
            element.tag = element.tag[len(ns):]
        elif element.tag.startswith(https_ns):
            element.tag = element.tag[len(https_ns):]
            issues.add("noncanonical_https_pom_namespace")
        pom_need("{" not in element.tag, "namespace")
        pom_need(len(element.tag) <= 128, "element_name")
        if element.attrib:
            issues.add("uninterpreted_xml_attributes")
        pending.extend((child, depth + 1) for child in element)
    pom_need(one(root, "modelVersion") is not None and one(root, "modelVersion").text == "4.0.0", "model_version")
    parent = one(root, "parent")
    parent_ref = None if parent is None else declaration(parent, issues, "parent")
    if parent is not None and one(parent, "relativePath") is not None:
        issues.add("relative_parent_path_not_followed")
    # Coordinate binding is the cache path, not an invented effective POM model.
    for field, key in (("groupId", "group"), ("artifactId", "artifact"), ("version", "version")):
        declared = value(one(root, field), issues)
        if declared["kind"] == "literal":
            pom_need(declared["value"] == c[key], "coordinate_mismatch")
    def body(element):
        rows, plugins, extensions, properties, repos = [], [], [], [], []
        deps = one(element, "dependencies")
        if deps is not None:
            pom_need(all(child.tag == "dependency" for child in deps), "dependency_shape")
            rows.extend(declaration(child, issues, "dependency") for child in deps)
        dm = one(element, "dependencyManagement")
        if dm is not None:
            deps = one(dm, "dependencies")
            if deps is not None:
                pom_need(all(child.tag == "dependency" for child in deps), "dependency_management_shape")
                rows.extend(declaration(child, issues, "dependency_management") for child in deps)
        props = one(element, "properties")
        if props is not None:
            issues.add("properties_redacted_not_evaluated")
            properties = [{"index": i, "canonical_element_sha256": element_hash(p)} for i, p in enumerate(props)]
        for repo_kind in ("repositories", "pluginRepositories"):
            container = one(element, repo_kind)
            if container is not None:
                issues.add("repository_declarations_not_enforced")
                for i, repo in enumerate(container):
                    u = one(repo, "url")
                    raw = "" if u is None else (u.text or "").strip()
                    repos.append({"kind": repo_kind, "index": i, "central_literal": raw in {CENTRAL, CENTRAL.rstrip("/")},
                                  "canonical_element_sha256": element_hash(repo)})
        build = one(element, "build")
        if build is not None:
            for context, container in (("build", build), ("plugin_management", one(build, "pluginManagement"))):
                if container is None:
                    continue
                container = one(container, "plugins")
                if container is not None:
                    pom_need(all(p.tag == "plugin" for p in container), "plugin_shape")
                    plugins.extend(dict(declaration(p, issues, "plugin"), context=context) for p in container)
            container = one(build, "extensions")
            if container is not None:
                pom_need(all(p.tag == "extension" for p in container), "extension_shape")
                extensions.extend(declaration(p, issues, "build_extension") for p in container)
            issues.add("plugin_execution_and_build_model_not_evaluated")
        return {"declarations": rows, "plugins": plugins, "build_extensions": extensions,
                "properties": properties, "repositories": repos}
    result = body(root)
    result["parent"] = parent_ref
    result["profiles"] = []
    profiles = one(root, "profiles")
    if profiles is not None:
        issues.add("profile_activation_not_evaluated")
        for index, profile in enumerate(profiles):
            pom_need(profile.tag == "profile", "profile_shape")
            activation = one(profile, "activation")
            activation_record = None
            if activation is not None:
                supported = {"activeByDefault", "jdk", "os", "property", "file"}
                kinds = sorted({x.tag for x in activation} & supported)
                activation_record = {"kinds": kinds, "canonical_element_sha256": element_hash(activation),
                                     "unsupported_element_count": sum(x.tag not in supported for x in activation)}
            result["profiles"].append(dict(body(profile), index=index,
                canonical_element_sha256=element_hash(profile), activation=activation_record))
    known = {"modelVersion", "parent", "groupId", "artifactId", "version", "packaging", "name", "description",
             "url", "inceptionYear", "organization", "licenses", "developers", "contributors", "mailingLists",
             "prerequisites", "modules", "scm", "issueManagement", "ciManagement", "distributionManagement",
             "properties", "dependencyManagement", "dependencies", "repositories", "pluginRepositories", "build",
             "reports", "reporting", "profiles"}
    ignored = {"name", "description", "url", "inceptionYear", "organization", "licenses", "developers",
               "contributors", "mailingLists", "scm", "issueManagement", "ciManagement", "distributionManagement"}
    result["redacted_metadata_element_count"] = sum(x.tag in ignored for x in root)
    result["unsupported_element_count"] = sum(x.tag not in known for x in root)
    if result["unsupported_element_count"] or any(x.tag in {"reports", "reporting", "modules", "prerequisites"} for x in root):
        issues.add("unsupported_pom_elements")
    return result


def export_semantics(json_bytes, text_bytes, poms, selected_runtime):
    """Return quarantined observations or a finite ExportError; no side effects.

    poms: exact dictionaries coordinate/size/sha256/content. selected_runtime:
    exact five-field JAR coordinates, already bound to bytes by the caller.
    All material must come from one bounded, preserved discovery archive.
    """
    issues = {"effective_model_not_evaluated", "plugin_dependency_closure_not_classified",
              "central_refetch_and_hash_verification_required", "graph_semantics_not_reviewed"}
    need(type(poms) is list and len(poms) <= 4096 and type(selected_runtime) is list
         and 1 <= len(selected_runtime) <= 2048, "input_limit")
    nodes, text = json_nodes(json_bytes), text_nodes(text_bytes)
    need(len(nodes) == len(text), "tree_mismatch")
    for n, t in zip(nodes, text):
        need(all(n[k] == t[k] for k in ("parent", "coordinate", "scope")), "tree_mismatch")
        n.update({k: t[k] for k in ("resolution", "omission_reason", "winner_version", "management")})
        n["reachable_included"] = n["resolution"] == "included" and (n["parent"] is None or nodes[n["parent"]]["reachable_included"])
    for n in nodes:
        n["winner_occurrence_ids"] = []
        if n["resolution"] == "omitted":
            winner = dict(n["coordinate"], version=n["winner_version"])
            n["winner_occurrence_ids"] = [v["id"] for v in nodes
                if v["reachable_included"] and v["coordinate"] == winner]
            need(bool(n["winner_occurrence_ids"]), "tree_mismatch")
    selected = [coordinate(c) for c in selected_runtime]
    need(all(c["type"] == "jar" for c in selected), "classpath_mismatch")
    keys = {coord_key(c) for c in selected}
    need(len(keys) == len(selected), "classpath_mismatch")
    actual = set()
    for n in nodes[1:]:
        if not n["reachable_included"]:
            continue
        c = n["coordinate"]
        need(c["type"] in {"jar", "pom"}, "classpath_mismatch")
        if c["type"] == "jar":
            actual.add(coord_key(c))
    need(actual == keys, "classpath_mismatch")
    records, seen, total, budget = [], set(), 0, [0]
    for entry in poms:
        need(type(entry) is dict and set(entry) == {"coordinate", "size", "sha256", "content"}, "pom_invalid")
        c = coordinate(entry["coordinate"])
        need(c["type"] == "pom" and c["classifier"] == "", "pom_invalid")
        need(coord_key(c) not in seen, "duplicate_pom")
        seen.add(coord_key(c))
        b = entry["content"]
        need(type(b) is bytes and type(entry["size"]) is int and entry["size"] == len(b)
             and 0 < len(b) <= MAX_POM, "input_limit")
        total += len(b)
        need(total <= MAX_POMS_BYTES, "input_limit")
        need(type(entry["sha256"]) is str and entry["sha256"] == digest(b), "pom_hash_mismatch")
        local_issues = set()
        try:
            semantics = pom_semantics(b, c, local_issues, budget)
        except ExportError as error:
            if error.pom_reason is not None:
                error.pom_diagnostic = validate_pom_diagnostic({
                    "schema_version": 1, "scope": "hdfs_pom_rejection", "code": error.code,
                    "reason": error.pom_reason, "coordinate": c, "size": len(b), "sha256": digest(b),
                })
            raise
        records.append({"coordinate": c, "size": len(b), "sha256": entry["sha256"],
                        "central_refetch_url": locator(c), "origin": "unverified_private_cache",
                        "semantics": semantics, "incomplete_reasons": sorted(local_issues)})
        issues.update(local_issues)
    missing = sorted({coord_key(pom_coord(n["coordinate"])) for n in nodes[1:]} - seen)
    if missing:
        issues.add("graph_pom_bytes_missing")
    for n in nodes:
        n["pom_bytes_present"] = coord_key(pom_coord(n["coordinate"])) in seen
        n["selected_classpath"] = coord_key(n["coordinate"]) in keys
    result = {"schema_version": 1, "scope": "hdfs_dependency_semantic_observations",
              "ledger_eligible": False, "review_status": "quarantined", "semantics_complete": False,
              "graph_semantics_reviewed": False, "publisher_audit_completed": False,
              "offline_reproduced": False, "daemon_accepted": False,
              "repository_policy_is_os_egress_confinement": False,
              "source_contract": {"plugin_version": "3.11.0", "tree_library_version": "3.3.0", "urls": SOURCES},
              "input_sha256": {"runtime_tree_json": digest(json_bytes), "runtime_tree_text": digest(text_bytes)},
              "processed_pom_totals": {"poms": len(records), "bytes": total, "elements": budget[0]},
              "nodes": nodes, "edges": [{"parent": n["parent"], "child": n["id"]} for n in nodes if n["parent"] is not None],
              "poms": sorted(records, key=lambda r: coord_key(r["coordinate"])),
              "missing_graph_pom_count": len(missing), "incomplete_reasons": sorted(issues)}
    need(len(json.dumps(result, sort_keys=True, ensure_ascii=True).encode()) <= MAX_OUTPUT, "output_limit")
    return result
