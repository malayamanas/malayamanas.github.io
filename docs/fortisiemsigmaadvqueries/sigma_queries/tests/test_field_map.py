"""Tests for field_map.py — Sigma field → FSM expression mapping."""
import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..', 'scripts'))

import pytest
from converter.field_map import get_field, apply_modifier


class TestGetField:
    """Test Sigma field → (fsm_expression, tier) mapping."""

    def test_tier1_image(self):
        expr, tier = get_field("Image")
        assert expr == "procName"
        assert tier == "1"

    def test_tier1_user(self):
        expr, tier = get_field("User")
        assert expr == "user"
        assert tier == "1"

    def test_tier1_event_id(self):
        expr, tier = get_field("EventID")
        assert expr == "winEventId"
        assert tier == "1"

    def test_tier1_destination_ip(self):
        expr, tier = get_field("DestinationIp")
        assert expr == "destIpAddrV4"
        assert tier == "1"

    def test_tier1_source_ip(self):
        expr, tier = get_field("SourceIp")
        assert expr == "srcIpAddrV4"
        assert tier == "1"

    def test_tier1_destination_port(self):
        expr, tier = get_field("DestinationPort")
        assert expr == "destIpPort"
        assert tier == "1"

    def test_tier1_data_maps_to_raw_event_msg(self):
        expr, tier = get_field("Data")
        assert expr == "rawEventMsg"
        assert tier == "1"

    def test_tier1_keywords(self):
        expr, tier = get_field("keywords")
        assert expr == "rawEventMsg"
        assert tier == "1"

    def test_tier2_commandline(self):
        expr, tier = get_field("CommandLine")
        assert "metrics_string" in expr
        assert "command" in expr
        assert tier == "2"

    def test_tier2_parent_image(self):
        expr, tier = get_field("ParentImage")
        assert "parentProcName" in expr
        assert tier == "2"

    def test_tier2_target_object(self):
        expr, tier = get_field("TargetObject")
        assert "regKey" in expr
        assert tier == "2"

    def test_tier2_script_block_text(self):
        expr, tier = get_field("ScriptBlockText")
        assert "script" in expr
        assert tier == "2"

    def test_tier2_initiated(self):
        expr, tier = get_field("Initiated")
        assert "initiated" in expr
        assert tier == "2"

    # --- Missing Tier 1 fields ---

    def test_tier1_target_user(self):
        expr, tier = get_field("TargetUser")
        assert expr == "targetUser"
        assert tier == "1"

    def test_tier1_process_id(self):
        expr, tier = get_field("ProcessId")
        assert expr == "procId"
        assert tier == "1"

    def test_tier1_logon_type(self):
        expr, tier = get_field("LogonType")
        assert expr == "winLogonType"
        assert tier == "1"

    def test_tier1_service_name(self):
        expr, tier = get_field("ServiceName")
        assert expr == "serviceName"
        assert tier == "1"

    def test_tier1_domain(self):
        expr, tier = get_field("Domain")
        assert expr == "domain"
        assert tier == "1"

    def test_tier1_source_port(self):
        expr, tier = get_field("SourcePort")
        assert expr == "srcIpPort"
        assert tier == "1"

    def test_unmapped_field_falls_back_to_rawmsg(self):
        expr, tier = get_field("SomeUnknownField")
        assert expr == "rawEventMsg"
        assert tier == "1"

    # --- Missing Tier 2 fields ---

    def test_tier2_parent_commandline(self):
        expr, tier = get_field("ParentCommandLine")
        assert "parentCommand" in expr
        assert tier == "2"

    def test_tier2_subject_user_name(self):
        expr, tier = get_field("SubjectUserName")
        assert "subjectUsername" in expr
        assert tier == "2"

    def test_tier2_target_user_name(self):
        expr, tier = get_field("TargetUserName")
        assert "targetUser" in expr
        assert tier == "2"

    def test_tier2_destination_hostname(self):
        expr, tier = get_field("DestinationHostname")
        assert "destHostName" in expr
        assert tier == "2"

    def test_tier2_target_filename(self):
        expr, tier = get_field("TargetFilename")
        assert "fileName" in expr
        assert tier == "2"

    def test_tier2_details(self):
        expr, tier = get_field("Details")
        assert "regValue" in expr
        assert tier == "2"

    def test_tier2_hashes(self):
        expr, tier = get_field("Hashes")
        assert "hashMD5" in expr
        assert tier == "2"

    def test_tier2_image_loaded(self):
        expr, tier = get_field("ImageLoaded")
        assert "imageLoaded" in expr
        assert tier == "2"

    def test_tier2_original_file_name(self):
        expr, tier = get_field("OriginalFileName")
        assert "originalFileName" in expr
        assert tier == "2"

    def test_tier2_product(self):
        expr, tier = get_field("Product")
        assert "product" in expr
        assert tier == "2"

    def test_tier2_company(self):
        expr, tier = get_field("Company")
        assert "company" in expr
        assert tier == "2"

    def test_tier2_pipe_name(self):
        expr, tier = get_field("PipeName")
        assert "pipeName" in expr
        assert tier == "2"

    def test_tier2_provider_name(self):
        expr, tier = get_field("Provider_Name")
        assert "provider" in expr
        assert tier == "2"

    def test_tier2_channel(self):
        expr, tier = get_field("Channel")
        assert "channel" in expr
        assert tier == "2"

    def test_tier2_target_user_grp(self):
        expr, tier = get_field("TargetUserGrp")
        assert "targetUserGrp" in expr
        assert tier == "2"

    def test_tier2_current_directory(self):
        expr, tier = get_field("CurrentDirectory")
        assert "currentDirectory" in expr
        assert tier == "2"

    def test_tier2_integrity_level(self):
        expr, tier = get_field("IntegrityLevel")
        assert "integrityLevel" in expr
        assert tier == "2"

    def test_tier2_signature(self):
        expr, tier = get_field("Signature")
        assert "signature" in expr
        assert tier == "2"

    def test_tier2_signature_status(self):
        expr, tier = get_field("SignatureStatus")
        assert "signatureStatus" in expr
        assert tier == "2"


class TestApplyModifier:
    """Test modifier → SQL fragment translation."""

    # --- Tier 1 field tests ---
    def test_no_modifier_single_value_tier1(self):
        sql, comments = apply_modifier("procName", "1", None, ["powershell.exe"])
        assert "procName = 'powershell.exe'" in sql
        assert comments == []

    def test_no_modifier_multi_value_tier1_uses_in(self):
        sql, comments = apply_modifier("procName", "1", None, ["cmd.exe", "powershell.exe"])
        assert "procName IN ('cmd.exe', 'powershell.exe')" in sql

    def test_contains_tier1(self):
        sql, comments = apply_modifier("procName", "1", "contains", ["powershell"])
        assert "procName LIKE '%powershell%'" in sql

    def test_endswith_tier1(self):
        sql, comments = apply_modifier("procName", "1", "endswith", ["\\powershell.exe"])
        assert "procName LIKE '%\\\\powershell.exe'" in sql

    def test_startswith_tier1(self):
        sql, comments = apply_modifier("procName", "1", "startswith", ["C:\\Windows"])
        assert "procName LIKE 'C:\\\\Windows%'" in sql

    def test_re_modifier_tier1(self):
        sql, comments = apply_modifier("procName", "1", "re", [".*powershell.*"])
        assert "match(procName, '.*powershell.*')" in sql

    # --- Tier 2 field tests (must include indexOf guard) ---
    def test_no_modifier_tier2_includes_guard(self):
        expr = "metrics_string.value[indexOf(metrics_string.name,'command')]"
        sql, comments = apply_modifier(expr, "2", None, ["whoami"])
        assert "indexOf(metrics_string.name, 'command') > 0" in sql
        assert expr in sql

    def test_contains_tier2_includes_guard(self):
        expr = "metrics_string.value[indexOf(metrics_string.name,'command')]"
        sql, comments = apply_modifier(expr, "2", "contains", ["-nop"])
        assert "indexOf(metrics_string.name, 'command') > 0" in sql
        assert "LIKE '%-nop%'" in sql

    # --- windash modifier ---
    def test_windash_produces_four_variants(self):
        expr = "metrics_string.value[indexOf(metrics_string.name,'command')]"
        sql, comments = apply_modifier(expr, "2", "windash", ["-nop"])
        assert "% -nop%" in sql   # space-prefixed
        assert "%-nop%" in sql    # dash
        # windash: space-val, -val, /val, en-dash-val
        assert sql.count("LIKE") == 4

    # --- base64offset modifier ---
    def test_base64offset_produces_match_with_three_variants(self):
        expr = "metrics_string.value[indexOf(metrics_string.name,'script')]"
        sql, comments = apply_modifier(expr, "2", "base64offset|contains", ["IEX"])
        assert "match(" in sql
        assert "|" in sql   # variants joined by pipe in regex

    # --- cidr modifier ---
    def test_cidr_modifier(self):
        expr = "destIpAddrV4"
        sql, comments = apply_modifier(expr, "1", "cidr", ["192.168.0.0/16"])
        assert "isIPAddressInRange" in sql
        assert "192.168.0.0/16" in sql

    # --- numeric comparisons ---
    def test_lt_modifier(self):
        sql, comments = apply_modifier("winLogonType", "1", "lt", ["3"])
        assert "winLogonType < 3" in sql

    def test_lte_modifier(self):
        sql, comments = apply_modifier("winLogonType", "1", "lte", ["3"])
        assert "winLogonType <= 3" in sql

    def test_gt_modifier(self):
        sql, comments = apply_modifier("winLogonType", "1", "gt", ["3"])
        assert "winLogonType > 3" in sql

    def test_gte_modifier(self):
        sql, comments = apply_modifier("winLogonType", "1", "gte", ["3"])
        assert "winLogonType >= 3" in sql

    # --- exists modifier ---
    def test_exists_true(self):
        sql, comments = apply_modifier("procName", "1", "exists|true", [True])
        assert "IS NOT NULL" in sql
        assert "!= ''" in sql

    def test_exists_false(self):
        sql, comments = apply_modifier("procName", "1", "exists|false", [False])
        assert "IS NULL" in sql or "= ''" in sql

    # --- unknown modifier fallback ---
    def test_unknown_modifier_fallback(self):
        sql, comments = apply_modifier("procName", "1", "zz_unknown", ["value"])
        assert "rawEventMsg LIKE '%value%'" in sql
        assert any("UNSUPPORTED_MODIFIER" in c for c in comments)

    # --- unmapped field comment ---
    def test_unmapped_field_generates_comment(self):
        expr, tier = get_field("SomeUnknownField")
        sql, comments = apply_modifier(expr, tier, "contains", ["test"], sigma_field="SomeUnknownField")
        assert any("UNMAPPED_FIELD" in c for c in comments)

    # --- _like_escape: percent and underscore are escaped ---
    def test_like_escape_percent_in_contains(self):
        # A literal % in a value (e.g. %AppData%) must not act as a wildcard.
        sql, _ = apply_modifier("procName", "1", "contains", ["%AppData%"])
        assert "LIKE '%\\%AppData\\%%'" in sql

    def test_like_escape_underscore_in_contains(self):
        # A literal _ in a value must not match any single character.
        sql, _ = apply_modifier("procName", "1", "contains", ["some_value"])
        assert "LIKE '%some\\_value%'" in sql

    def test_like_escape_backslash_still_doubled(self):
        # Backslash escaping still works correctly alongside % and _ escaping.
        sql, _ = apply_modifier("procName", "1", "contains", ["C:\\path"])
        assert "LIKE '%C:\\\\path%'" in sql

    def test_like_escape_combined_path_with_percent(self):
        # Registry path like %AppData%\\something exercises all three escapes.
        sql, _ = apply_modifier("procName", "1", "startswith", ["%AppData%\\sub"])
        assert "LIKE '\\%AppData\\%\\\\sub%'" in sql

    # --- empty values guard ---
    def test_empty_values_returns_noop(self):
        sql, comments = apply_modifier("procName", "1", None, [])
        assert sql == "1=1"
        assert comments == []

    def test_empty_values_contains_returns_noop(self):
        sql, comments = apply_modifier("procName", "1", "contains", [])
        assert sql == "1=1"

    def test_empty_values_tier2_returns_noop(self):
        expr = "metrics_string.value[indexOf(metrics_string.name,'command')]"
        sql, comments = apply_modifier(expr, "2", "contains", [])
        assert sql == "1=1"
