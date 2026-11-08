import java.nio.charset.StandardCharsets;

/** Bounded JSON interpretation only; no processes, filesystem or network access. */
final class HdfsTransferJson {
    private HdfsTransferJson() {}
    private static com.fasterxml.jackson.databind.ObjectMapper jsonMapper() {
        return new com.fasterxml.jackson.databind.ObjectMapper()
            .enable(com.fasterxml.jackson.core.JsonParser.Feature.STRICT_DUPLICATE_DETECTION)
            .enable(com.fasterxml.jackson.databind.DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    }
    static void selfCheck(String expected) throws Exception {
        String goodHash = "{\"hashType\":\"sha256\",\"hash\":\"" + expected + "\"}";
        String goodMissing = "{\"error\":\"loopback: call failed: object not found\",\"path\":\"operations/hashsumfile\",\"status\":500}";
        if (!hash(goodHash.getBytes(StandardCharsets.UTF_8), expected)
            || !missingObject(goodMissing.getBytes(StandardCharsets.UTF_8)))
            throw new IllegalArgumentException("json_control_failed");
        for (String value : new String[]{"null", "[]", "{}", goodHash+"{}",
            goodHash.replace(expected, "0".repeat(64)), goodHash.replace("sha256", "md5"),
            goodHash.replace("\"hashType\":", "\"extra\":true,\"hashType\":"),
            goodHash.replace("\"hashType\":", "\"hashType\":\"sha256\",\"hashType\":"),
            goodHash.replace("\"hash\":\""+expected+"\"", "\"hash\":true")}) {
            boolean accepted = false;
            try { accepted = hash(value.getBytes(StandardCharsets.UTF_8), expected); }
            catch (Exception rejected) { }
            if (accepted) throw new IllegalArgumentException("json_control_failed");
        }
        for (String value : new String[]{"null", "[]", "{}", goodMissing+"{}",
            goodMissing.replace("object not found", "directory not found"),
            goodMissing.replace("object not found", "permission denied"),
            goodMissing.replace("500", "404"), goodMissing.replace("500", "\"500\""),
            goodMissing.replace("500", "500.0"), goodMissing.replace("500", "true"),
            goodMissing.replace("operations/hashsumfile", "operations/list"),
            goodMissing.replace("\"status\":", "\"extra\":true,\"status\":"),
            goodMissing.replace("\"status\":", "\"status\":500,\"status\":" )}) {
            boolean accepted = false;
            try { accepted = missingObject(value.getBytes(StandardCharsets.UTF_8)); }
            catch (Exception rejected) { }
            if (accepted) throw new IllegalArgumentException("json_control_failed");
        }
    }
    static boolean hash(byte[] raw, String expected) throws Exception {
        var value = jsonMapper().readTree(raw);
        return value != null && value.isObject() && value.size() == 2
            && value.path("hashType").isTextual() && value.path("hashType").asText().equals("sha256")
            && value.path("hash").isTextual() && value.path("hash").asText().equals(expected);
    }
    static boolean missingObject(byte[] raw) throws Exception {
        var value = jsonMapper().readTree(raw);
        return value != null && value.isObject() && value.size() == 3
            && value.path("error").isTextual()
            && value.path("error").asText().equals("loopback: call failed: object not found")
            && value.path("path").isTextual() && value.path("path").asText().equals("operations/hashsumfile")
            && value.path("status").isIntegralNumber() && value.path("status").asLong() == 500;
    }
	static String rcloneFailure(byte[] raw) {
	if (raw.length == 0) return "empty";
	String text = new String(raw, StandardCharsets.UTF_8);
	if (text.contains("runtime: failed to create new OS thread") && text.contains("fatal error: newosproc")) return "runtime_thread_limit";
	if (text.contains("panic:")) {
		if (text.contains("github.com/jcmturner/gokrb5/v8/credentials.")) return "panic_credential_cache";
		if (text.contains("github.com/jcmturner/gokrb5/v8/config.")) return "panic_kerberos_config";
		if (text.contains("github.com/jcmturner/gokrb5/v8/client.")) return "panic_kerberos_client";
		return "go_panic";
	}
	if (text.contains("fatal error:")) return "go_runtime_fatal";
	try {
		var value = jsonMapper().readTree(raw);
		if (value != null && value.isObject() && value.path("msg").isTextual()) {
			String message = value.path("msg").asText();
			if (message.contains("problem with kerberos authentication:")) {
				if (message.contains("TGT not found in CCache")) return "cache_tgt_missing";
				if (message.contains("TGT bytes in cache are not valid:") || message.contains("cache entry ticket bytes are not valid:")) return "cache_ticket_invalid";
				return "kerberos_initialization";
			}
			if (message.startsWith("Failed to create file system for ")) return "backend_creation";
			if (message.contains("no available cipher among choices:")) return "data_cipher_unavailable";
			if (message.contains("negotiating data protection:")) return "data_qop_mismatch";
			if (message.contains("rspauth")) return "data_rspauth_invalid";
			if (message.contains("HMAC check failed")) return "data_hmac_invalid";
			if (message.contains("bad response length")) return "data_response_length";
			if (message.contains("no available datanodes")) return "data_nodes_unavailable";
			if (message.contains("read failed:")) return "data_read_status";
			if (message.contains("EOF")) return "data_io_eof";
			if (message.contains("connection reset by peer")) return "data_connection_reset";
			if (message.contains("broken pipe")) return "data_broken_pipe";
			if (message.contains("connection refused")) return "data_connection_refused";
			if (message.contains("i/o timeout")) return "data_io_timeout";
			if (message.contains("unsupported checksum type:")) return "data_checksum_unsupported";
			if (message.contains("cannot parse invalid wire-format data")) return "data_protobuf_invalid";
			if (message.contains("invalid checksum")) return "data_checksum_invalid";
			if (message.contains("invalid response from datanode")) return "data_response_invalid";
			if (message.startsWith("Failed to open:")) return "cat_open";
			if (message.startsWith("Failed to send to output:")) return "cat_output";
			if (message.startsWith("error listing:")) return "cat_listing";
			return "json_message";
		}
	} catch (Exception ignored) { }
	return "unclassified";
	}
}
