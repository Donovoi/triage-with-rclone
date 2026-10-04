"""Synthetic offline contract tests; no Maven, network, filesystem extraction."""
import copy
import hashlib
import importlib.util
import json
from pathlib import Path
import unittest
from unittest import mock

spec = importlib.util.spec_from_file_location("graph_export", Path(__file__).with_name("graph_export.py"))
g = importlib.util.module_from_spec(spec)
exec(compile(Path(spec.origin).read_bytes(), spec.origin, "exec"), g.__dict__)


def coord(a, version="1", kind="jar", group="org.example"):
    return {"group": group, "artifact": a, "version": version, "classifier": "", "type": kind}


def node(c, children=(), scope="compile", optional="false"):
    result = {"groupId": c["group"], "artifactId": c["artifact"], "version": c["version"],
              "classifier": c["classifier"], "type": c["type"], "scope": scope, "optional": optional}
    if children:
        result["children"] = list(children)
    return result


def pom(c, extra=""):
    c = dict(c, type="pom", classifier="")
    content = (f'<project xmlns="http://maven.apache.org/POM/4.0.0"><modelVersion>4.0.0</modelVersion>'
               f'<groupId>{c["group"]}</groupId><artifactId>{c["artifact"]}</artifactId>'
               f'<version>{c["version"]}</version>{extra}</project>').encode()
    return {"coordinate": c, "content": content, "size": len(content), "sha256": hashlib.sha256(content).hexdigest()}


class GraphExportTests(unittest.TestCase):
    def setUp(self):
        self.native = mock.patch("subprocess.Popen", side_effect=AssertionError("native_forbidden")).start()
        self.addCleanup(mock.patch.stopall)
        self.a, self.b = coord("a"), coord("b", "2")
        # b1 is omitted for conflict; repeated b2 is omitted for duplicate.
        self.tree = node(g.ROOT, [node(self.a, [node(self.b), node(coord("b"))]), node(self.b)], scope="")
        self.text = ("org.example.synthetic:hdfs-normal-runtime-resolution:pom:1.0.0\n"
                     "+- org.example:a:jar:1:compile\n"
                     "|  +- org.example:b:jar:2:compile (version managed from 1; scope managed from runtime)\n"
                     "|  \\- (org.example:b:jar:1:compile - omitted for conflict with 2)\n"
                     "\\- (org.example:b:jar:2:compile - omitted for duplicate)\n").encode()
        self.poms = [pom(self.a), pom(self.b), pom(coord("b"))]

    def export(self, **kwargs):
        args = {"json_bytes": json.dumps(self.tree).encode(), "text_bytes": self.text,
                "poms": self.poms, "selected_runtime": [self.a, self.b]}
        args.update(kwargs)
        return g.export_semantics(**args)

    def reject(self, code, **kwargs):
        with self.assertRaises(g.ExportError) as e:
            self.export(**kwargs)
        self.assertEqual(str(e.exception), code)

    def rejected_pom(self, content, expected_reason, *, expected_code="pom_invalid", c=None):
        identity = dict(self.a, type="pom") if c is None else c
        record = {"coordinate": identity, "content": content, "size": len(content),
                  "sha256": hashlib.sha256(content).hexdigest()}
        with self.assertRaises(g.ExportError) as caught:
            self.export(poms=[record])
        error = caught.exception
        self.assertEqual((str(error), error.code, error.pom_reason),
                         (expected_code, expected_code, expected_reason))
        result = g.pom_failure_diagnostic(error)
        self.assertEqual(result, {"schema_version": 1, "scope": "hdfs_pom_rejection", "code": expected_code,
                                 "reason": expected_reason, "coordinate": identity, "size": len(content),
                                 "sha256": hashlib.sha256(content).hexdigest()})
        return error

    def test_selected_omitted_occurrence_edges_reasons_and_management(self):
        result = self.export()
        self.assertEqual(result["edges"], [{"parent": 0, "child": 1}, {"parent": 1, "child": 2},
                                          {"parent": 1, "child": 3}, {"parent": 0, "child": 4}])
        self.assertEqual([n["omission_reason"] for n in result["nodes"]], [None, None, None, "conflict", "duplicate"])
        self.assertEqual([n["reachable_included"] for n in result["nodes"]], [True, True, True, False, False])
        self.assertEqual(result["nodes"][2]["management"], [
            {"kind": "version_managed_from", "value": "1"}, {"kind": "scope_managed_from", "value": "runtime"}])
        self.assertEqual(result["nodes"][3]["winner_version"], "2")
        self.assertEqual(result["nodes"][3]["winner_occurrence_ids"], [2])
        self.assertEqual(result["nodes"][4]["winner_occurrence_ids"], [2])

    def test_all_credit_flags_remain_false_and_source_provenance_exact(self):
        result = self.export()
        for flag in ("ledger_eligible", "semantics_complete", "graph_semantics_reviewed", "publisher_audit_completed",
                     "offline_reproduced", "daemon_accepted", "repository_policy_is_os_egress_confinement"):
            self.assertIs(result[flag], False)
        self.assertEqual(result["review_status"], "quarantined")
        self.assertEqual(result["poms"][0]["central_refetch_url"], "https://repo.maven.apache.org/maven2/org/example/a/1/a-1.pom")
        self.assertEqual(result["poms"][0]["sha256"], self.poms[0]["sha256"])
        self.assertEqual(result["input_sha256"]["runtime_tree_text"], hashlib.sha256(self.text).hexdigest())

    def test_json_strings_not_bool_optional_and_closed_node_fields(self):
        for value in (True, False, 1, None, "yes"):
            tree = copy.deepcopy(self.tree)
            tree["children"][0]["optional"] = value
            self.reject("tree_invalid", json_bytes=json.dumps(tree).encode())
        tree = dict(self.tree, omitted="PRIVATE_CANARY")
        self.reject("tree_invalid", json_bytes=json.dumps(tree).encode())

    def test_duplicate_json_keys_and_nonfinite_rejected(self):
        self.reject("json_invalid", json_bytes=b'{"groupId":"a","groupId":"b"}')
        self.reject("json_invalid", json_bytes=b'{"a":NaN}')

    def test_graph_topology_and_scope_disagreement_rejected(self):
        tree = copy.deepcopy(self.tree)
        tree["children"][0]["children"][0]["scope"] = "runtime"
        self.reject("tree_mismatch", json_bytes=json.dumps(tree).encode())
        self.reject("tree_mismatch", text_bytes=self.text.replace(b"|  +- org.example:b", b"+- org.example:b"))

    def test_unknown_omission_prose_never_exported(self):
        self.reject("text_invalid", text_bytes=self.text.replace(b"omitted for duplicate", b"omitted PRIVATE_CANARY"))
        self.reject("text_invalid", text_bytes=self.text.replace(b"omitted for conflict with 2", b"omitted for conflict with https://private.invalid"))

    def test_omission_winner_must_exist_in_included_graph(self):
        self.reject("tree_mismatch", text_bytes=self.text.replace(b"omitted for conflict with 2", b"omitted for conflict with 9"))

    def test_source_coordinate_values_reject_urls_paths_ranges_and_dynamic_versions(self):
        for value in ("user@example.test", "https://example.test", "../private", "${env.TOKEN}", "LATEST", "1-SNAPSHOT", "[1,2)"):
            tree = copy.deepcopy(self.tree)
            tree["children"][0]["version"] = value
            self.reject("coordinate_invalid", json_bytes=json.dumps(tree).encode())

    def test_fixed_release_plugin_artifact_name_is_not_a_dynamic_version(self):
        c = coord("maven-release-plugin", "3.2.0", group="org.apache.maven.plugins")
        result = self.export(poms=[*self.poms, pom(c)])
        record = next(p for p in result["poms"] if p["coordinate"]["artifact"] == "maven-release-plugin")
        self.assertEqual(record["coordinate"]["version"], "3.2.0")
        self.assertEqual(record["central_refetch_url"],
                         "https://repo.maven.apache.org/maven2/org/apache/maven/plugins/maven-release-plugin/3.2.0/maven-release-plugin-3.2.0.pom")
        tree = node(g.ROOT, [node(c)], scope="")
        text = b"org.example.synthetic:hdfs-normal-runtime-resolution:pom:1.0.0\n\\- org.apache.maven.plugins:maven-release-plugin:jar:3.2.0:compile\n"
        self.export(json_bytes=json.dumps(tree).encode(), text_bytes=text, poms=[pom(c)], selected_runtime=[c])
        self.reject("text_invalid", text_bytes=self.text.replace(b"omitted for conflict with 2", b"omitted for conflict with LATEST"))
        self.reject("text_invalid", text_bytes=self.text.replace(b"version managed from 1", b"version managed from 1-SNAPSHOT"))

    def test_classpath_missing_extra_duplicate_wrong_type_rejected(self):
        for selected in ([self.a], [self.a, self.b, coord("unexpected")], [self.a, self.b, self.b], [dict(self.a, type="pom"), self.b]):
            self.reject("classpath_mismatch", selected_runtime=selected)

    def test_omitted_only_artifact_cannot_be_promoted_by_classpath(self):
        self.reject("classpath_mismatch", selected_runtime=[self.a, self.b, coord("b")])

    def test_pom_actual_bytes_and_size_binding_and_no_unknown_record_fields(self):
        for change, code in (({"sha256": "0" * 64}, "pom_hash_mismatch"), ({"size": True}, "input_limit"),
                             ({"source": "PRIVATE_CANARY"}, "pom_invalid")):
            poms = copy.deepcopy(self.poms)
            poms[0].update(change)
            self.reject(code, poms=poms)
        self.reject("duplicate_pom", poms=self.poms + [self.poms[0]])

    def test_pom_declaration_must_not_disagree_with_cache_coordinate(self):
        p = pom(coord("other"))
        p["coordinate"] = dict(self.a, type="pom")
        self.reject("pom_invalid", poms=[p])

    def test_parent_bom_dependency_optional_exclusion_plugin_and_extension_records(self):
        extra = '''<parent><groupId>org.example</groupId><artifactId>parent</artifactId><version>9</version><relativePath/></parent>
        <dependencies><dependency><groupId>org.example</groupId><artifactId>dep</artifactId><version>1</version>
          <optional>true</optional><exclusions><exclusion><groupId>org.example</groupId><artifactId>omit</artifactId></exclusion></exclusions>
        </dependency></dependencies><dependencyManagement><dependencies><dependency><groupId>org.example</groupId><artifactId>bom</artifactId>
          <version>7</version><type>pom</type><scope>import</scope></dependency></dependencies></dependencyManagement>
        <build><plugins><plugin><groupId>org.example</groupId><artifactId>plugin</artifactId><version>2</version>
          <configuration><secret>PRIVATE_CANARY</secret></configuration></plugin></plugins><extensions><extension>
          <groupId>org.example</groupId><artifactId>ext</artifactId><version>3</version></extension></extensions></build>'''
        result = self.export(poms=[pom(self.a, extra), *self.poms[1:]])
        p = result["poms"][0]["semantics"]
        self.assertEqual(p["parent"]["fields"]["artifactId"], {"kind": "literal", "value": "parent"})
        self.assertEqual(p["declarations"][1]["fields"]["scope"], {"kind": "literal", "value": "import"})
        self.assertEqual(p["declarations"][0]["fields"]["optional"]["value"], "true")
        self.assertEqual(p["declarations"][0]["exclusions"][0]["artifactId"]["value"], "omit")
        self.assertEqual(p["plugins"][0]["fields"]["artifactId"]["value"], "plugin")
        self.assertEqual(p["build_extensions"][0]["fields"]["artifactId"]["value"], "ext")
        self.assertNotIn("PRIVATE_CANARY", json.dumps(result))

    def test_profile_properties_activation_personal_metadata_urls_are_redacted_not_silent(self):
        extra = '''<name>PRIVATE_NAME</name><developers><developer><email>private@example.test</email></developer></developers>
        <properties><env.PRIVATE_NAME>PRIVATE_VALUE</env.PRIVATE_NAME></properties>
        <profiles><profile><id>PRIVATE_PROFILE</id><activation><property><name>env.PRIVATE_TOKEN</name><value>PRIVATE_VALUE</value></property>
        <file><exists>/private/home/file</exists></file></activation><dependencies><dependency><groupId>org.example</groupId>
        <artifactId>dep</artifactId><version>${env.PRIVATE_VERSION}</version></dependency></dependencies></profile></profiles>
        <repositories><repository><id>PRIVATE_ID</id><url>https://user:pass@private.invalid/repo</url></repository></repositories>'''
        result = self.export(poms=[pom(self.a, extra)])
        encoded = json.dumps(result)
        for canary in ("PRIVATE_", "private@example", "private.invalid", "/private/home", "user:pass"):
            self.assertNotIn(canary, encoded)
        self.assertIn("properties_redacted_not_evaluated", result["incomplete_reasons"])
        self.assertIn("profile_activation_not_evaluated", result["incomplete_reasons"])
        self.assertIn("unresolved_declaration_values", result["incomplete_reasons"])
        self.assertEqual(result["poms"][0]["semantics"]["profiles"][0]["activation"]["kinds"], ["file", "property"])

    def test_unknown_pom_element_is_explicitly_incomplete_and_never_copied(self):
        result = self.export(poms=[pom(self.a, '<privateThing><value>PRIVATE_CANARY</value></privateThing>')])
        self.assertIn("unsupported_pom_elements", result["incomplete_reasons"])
        self.assertEqual(result["poms"][0]["semantics"]["unsupported_element_count"], 1)
        self.assertNotIn("privateThing", json.dumps(result))

    def test_comments_accepted_but_entities_doctype_foreign_namespace_and_pi_rejected(self):
        self.export(poms=[pom(self.a, '<!-- PRIVATE_CANARY -->')])
        for extra in ('<!DOCTYPE project>', '<!ENTITY x "secret">', '<?external value?>', '<bad xmlns="https://private.invalid"/>'):
            self.reject("pom_invalid", poms=[pom(self.a, extra)])

    def test_pom_encoding_preflight_xml_and_root_failures_have_finite_reasons(self):
        for content, reason in (
                (b"\xffPRIVATE_ENCODING_CANARY", "utf8_decode"),
                (b"<project><PRIVATE_XML_CANARY>", "xml_parse"),
                (b'<!DOCTYPE project [<!ENTITY test "PRIVATE_CANARY">]><project/>', "doctype"),
                (b'<!ENTITY test "PRIVATE_CANARY"><project/>', "entity"),
                (b'<?private PRIVATE_CANARY?><project/>', "processing_instruction"),
                (b'<PRIVATE_ROOT_CANARY/>', "project_root")):
            with self.subTest(reason=reason):
                error = self.rejected_pom(content, reason)
                self.assertNotIn("PRIVATE", json.dumps(g.pom_failure_diagnostic(error)))

    def test_pom_namespace_model_and_coordinate_rejections_remain_bound_to_actual_bytes(self):
        source = pom(self.a)["content"]
        cases = [
            (pom(self.a, '<x xmlns="https://PRIVATE_CANARY.invalid"/>')["content"], "namespace"),
            (pom(self.a, '<' + 'x' * 129 + '/>')["content"], "element_name"),
            (source.replace(b'<modelVersion>4.0.0</modelVersion>', b''), "model_version"),
            (source.replace(b'<modelVersion>4.0.0</modelVersion>', b'<modelVersion> 4.0.0 </modelVersion>'), "model_version"),
            (pom(coord("different"))["content"], "coordinate_mismatch"),
            (pom(self.a, '<version>1</version>')["content"], "duplicate_field"),
        ]
        for content, reason in cases:
            with self.subTest(reason=reason):
                self.rejected_pom(content, reason)

    def test_pom_structural_reasons_do_not_export_offending_element_names(self):
        for extra, reason in (
                ('<dependencies><PRIVATE_CANARY/></dependencies>', "dependency_shape"),
                ('<dependencyManagement><dependencies><PRIVATE_CANARY/></dependencies></dependencyManagement>',
                 "dependency_management_shape"),
                ('<dependencies><dependency><exclusions><PRIVATE_CANARY/></exclusions></dependency></dependencies>',
                 "exclusion_shape"),
                ('<build><plugins><PRIVATE_CANARY/></plugins></build>', "plugin_shape"),
                ('<build><extensions><PRIVATE_CANARY/></extensions></build>', "extension_shape"),
                ('<profiles><PRIVATE_CANARY/></profiles>', "profile_shape")):
            with self.subTest(reason=reason):
                error = self.rejected_pom(pom(self.a, extra)["content"], reason)
                self.assertNotIn("PRIVATE_CANARY", json.dumps(g.pom_failure_diagnostic(error)))

    def test_pom_element_budget_failure_remains_input_limit_with_diagnostic(self):
        with mock.patch.object(g, "MAX_ELEMENTS", 2):
            self.rejected_pom(pom(self.a)["content"], "element_bounds", expected_code="input_limit")

    def test_diagnostic_is_unavailable_before_identity_and_byte_validation(self):
        for change, expected_code in (
                ({"coordinate": dict(self.a, type="pom", artifact="private@example.test")}, "coordinate_invalid"),
                ({"coordinate": dict(self.a)}, "pom_invalid"),
                ({"size": True}, "input_limit"), ({"size": 1}, "input_limit"),
                ({"content": "PRIVATE_TEXT_CANARY"}, "input_limit"),
                ({"sha256": "a" * 64}, "pom_hash_mismatch"),
                ({"extra": "PRIVATE_CANARY"}, "pom_invalid")):
            with self.subTest(expected_code=expected_code, fields=list(change)):
                record = pom(self.a)
                record.update(change)
                with self.assertRaises(g.ExportError) as caught:
                    self.export(poms=[record])
                self.assertEqual(caught.exception.code, expected_code)
                self.assertIsNone(g.pom_failure_diagnostic(caught.exception))
        with self.assertRaises(g.ExportError) as caught:
            self.export(poms=[*self.poms, self.poms[0]])
        self.assertEqual(caught.exception.code, "duplicate_pom")
        self.assertIsNone(g.pom_failure_diagnostic(caught.exception))

    def test_pom_diagnostic_validator_closes_types_fields_code_reason_and_coordinates(self):
        error = self.rejected_pom(b"<project><PRIVATE_CANARY>", "xml_parse")
        good = g.pom_failure_diagnostic(error)
        for field, value in (
                ("schema_version", True), ("schema_version", 2), ("scope", "PRIVATE_CANARY"),
                ("code", "input_limit"), ("code", "PRIVATE_CANARY"), ("reason", "PRIVATE_CANARY"),
                ("reason", None), ("reason", "element_bounds"), ("size", True), ("size", 0),
                ("size", -1), ("size", g.MAX_POM + 1), ("size", 1.5),
                ("sha256", "A" * 64), ("sha256", "PRIVATE_PATH"), ("sha256", None),
                ("coordinate", dict(good["coordinate"], type="jar")),
                ("coordinate", dict(good["coordinate"], classifier="sources")),
                ("coordinate", dict(good["coordinate"], group="user@example.test")),
                ("coordinate", dict(good["coordinate"], version="${env.SECRET}")),
                ("coordinate", dict(good["coordinate"], version="LATEST")),
                ("coordinate", dict(good["coordinate"], artifact=True)),
                ("coordinate", dict(good["coordinate"], path="PRIVATE_PATH")),
                ("raw_xml", "PRIVATE_CANARY")):
            with self.subTest(field=field, value=value):
                changed = copy.deepcopy(good)
                changed[field] = value
                with self.assertRaises(g.ExportError) as caught:
                    g.validate_pom_diagnostic(changed)
                self.assertNotIn("PRIVATE", str(caught.exception))
                error.pom_diagnostic = changed
                self.assertIsNone(g.pom_failure_diagnostic(error))
        for changed in (None, [], {}, {k: v for k, v in good.items() if k != "scope"}):
            with self.assertRaises(g.ExportError):
                g.validate_pom_diagnostic(changed)

    def test_pom_diagnostic_accessor_rejects_foreign_errors_and_mismatched_binding(self):
        error = self.rejected_pom(b"<project><PRIVATE_CANARY>", "xml_parse")
        good = g.pom_failure_diagnostic(error)
        foreign = ValueError("PRIVATE_EXCEPTION_CANARY")
        foreign.pom_diagnostic, foreign.code, foreign.pom_reason = good, "pom_invalid", "xml_parse"
        self.assertIsNone(g.pom_failure_diagnostic(foreign))
        for code, reason in (("input_limit", "element_bounds"), ("pom_invalid", "model_version"),
                             ("pom_invalid", None)):
            typed = g.ExportError(code, pom_reason=reason)
            typed.pom_diagnostic = copy.deepcopy(good)
            self.assertIsNone(g.pom_failure_diagnostic(typed))
        for value in (None, "PRIVATE_PATH", {"content": "PRIVATE_XML"}):
            error.pom_diagnostic = value
            self.assertIsNone(g.pom_failure_diagnostic(error))

    def test_pom_diagnostic_copies_are_defensive_and_public_output_is_private(self):
        content = b'<project><!-- user@example.test C:\\PRIVATE_PATH https://private.invalid -->'
        error = self.rejected_pom(content, "xml_parse")
        public = g.pom_failure_diagnostic(error)
        serialized = json.dumps(public)
        for canary in ("user@example.test", "PRIVATE_PATH", "private.invalid", "<project", str(content)):
            self.assertNotIn(canary, serialized)
        public["coordinate"]["artifact"] = "modified"
        self.assertEqual(g.pom_failure_diagnostic(error)["coordinate"]["artifact"], "a")
        validated = g.validate_pom_diagnostic(error.pom_diagnostic)
        validated["coordinate"]["group"] = "modified"
        self.assertEqual(error.pom_diagnostic["coordinate"]["group"], "org.example")

    def test_later_rejected_pom_reports_only_that_artifact_and_returns_no_partial_graph(self):
        rejected = pom(self.b, '<version>2</version>')
        with self.assertRaises(g.ExportError) as caught:
            self.export(poms=[self.poms[0], rejected, self.poms[2]])
        result = g.pom_failure_diagnostic(caught.exception)
        self.assertEqual(result["coordinate"], dict(self.b, type="pom"))
        self.assertEqual(result["sha256"], hashlib.sha256(rejected["content"]).hexdigest())
        self.assertEqual(result["reason"], "duplicate_field")
        self.assertEqual(set(result), {"schema_version", "scope", "code", "reason", "coordinate", "size", "sha256"})

    def test_duplicate_model_fields_rejected(self):
        self.reject("pom_invalid", poms=[pom(self.a, '<version>1</version>')])

    def test_missing_poms_explicit_and_no_origin_assertion(self):
        result = self.export(poms=[])
        self.assertIn("graph_pom_bytes_missing", result["incomplete_reasons"])
        self.assertEqual(result["missing_graph_pom_count"], 3)
        self.assertFalse(any(n["pom_bytes_present"] for n in result["nodes"]))
        self.assertTrue(all(p["origin"] == "unverified_private_cache" for p in self.export()["poms"]))

    def test_byte_count_node_count_depth_output_and_aggregate_limits(self):
        for attr, value, code in (("MAX_GRAPH", 8, "input_limit"), ("MAX_NODES", 2, "input_limit"),
                                  ("MAX_DEPTH", 1, "input_limit"), ("MAX_POM", 8, "input_limit"),
                                  ("MAX_POMS_BYTES", 16, "input_limit"), ("MAX_ELEMENTS", 2, "input_limit"),
                                  ("MAX_TOTAL_ELEMENTS", 2, "input_limit"), ("MAX_OUTPUT", 8, "output_limit")):
            with self.subTest(attr=attr), mock.patch.object(g, attr, value):
                self.reject(code)

    def test_scope_updated_ignored_and_crlf_are_supported_without_reordering(self):
        text = self.text.replace(b"version managed from 1; scope managed from runtime",
                                 b"scope updated from runtime; scope not updated to provided")
        result = self.export(text_bytes=text.replace(b"\n", b"\r\n"))
        self.assertEqual(result["nodes"][2]["management"], [
            {"kind": "scope_updated_from", "value": "runtime"}, {"kind": "scope_not_updated_to", "value": "provided"}])

    def test_three_real_candidate_root_coordinates_need_no_plugin_specific_fiction(self):
        selected = [coord(a, "3.5.0", group="org.apache.hadoop") for a in
                    ("hadoop-common", "hadoop-hdfs-client", "hadoop-hdfs")]
        tree = node(g.ROOT, [node(c) for c in selected], scope="")
        text = "org.example.synthetic:hdfs-normal-runtime-resolution:pom:1.0.0\n"
        for i, c in enumerate(selected):
            text += ("\\- " if i == 2 else "+- ") + f'org.apache.hadoop:{c["artifact"]}:jar:3.5.0:compile\n'
        result = self.export(json_bytes=json.dumps(tree).encode(), text_bytes=text.encode(),
                             poms=[pom(c) for c in selected], selected_runtime=selected)
        self.assertEqual(len(result["nodes"]), 4)
        self.assertEqual(result["missing_graph_pom_count"], 0)
        self.assertIs(result["semantics_complete"], False)


if __name__ == "__main__":
    unittest.main()
