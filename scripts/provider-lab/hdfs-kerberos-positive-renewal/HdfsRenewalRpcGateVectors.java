import java.util.Arrays;
import java.util.HexFormat;
final class HdfsRenewalRpcGateVectors {
    private static byte[] bytes(String hex) { return HexFormat.of().parseHex(hex); }
    private static void check(boolean value) { if (!value) throw new IllegalStateException("rpc_gate_vector_failed"); }
    static int checkAll() throws Exception {
        int count = 0;
        {
            byte[] frame = bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
                check(request.kind == HdfsRenewalRpcGate.Kind.LISTING && request.callId == 7);
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000731c0802100018feffffff0f221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
                check(request.kind == HdfsRenewalRpcGate.Kind.LISTING && request.callId == 2147483647);
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000005a1808021000180e221066697874757265636c69656e743030313f0a0b67657446696c65496e666f122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c180100");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
                check(request.kind == HdfsRenewalRpcGate.Kind.FILE_INFO && request.callId == 7);
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000591808021000180e221066697874757265636c69656e743030313e0a0a72656e65774c65617365122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c180100");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
                check(request.kind == HdfsRenewalRpcGate.Kind.LEASE && request.callId == 7);
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000003218080210001805221066697874757265636c69656e7430303118505249564154455f53594e5448455449435f43414e415259");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
                check(request.kind == HdfsRenewalRpcGate.Kind.CONTROL && request.callId == -3);
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000003218080210001841221066697874757265636c69656e7430303118505249564154455f53594e5448455449435f43414e415259");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
                check(request.kind == HdfsRenewalRpcGate.Kind.CONTROL && request.callId == -33);
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("00000000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("ffffffff00");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0001000100");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d707479120018");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d7074791200180000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000191808021000180e221066697874757265636c69656e74303031");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000701808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d7074791200180000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000037f0000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000480000000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("00000007ffffffff7f0000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000006f18080210001800221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000001a18080210001807221066697874757265636c69656e7430303100");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000006f18080210001841221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000581808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000006e1708021000180e220f66697874757265636c69656e7430303e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000006f1808011000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000006f1808021001180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000711a08021000180e221066697874757265636c69656e74303031180e3e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000711a08021000180e221066697874757265636c69656e7430303128013e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000711a08021000180e221066697874757265636c69656e7430303158013e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("00000070190882001000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000761808021000180e221066697874757265636c69656e74303031450a11676574426c6f636b4c6f636174696f6e73122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000591808021000180e221066697874757265636c69656e74303031280a0a6765744c697374696e671218505249564154455f53594e5448455449435f43414e4152591801160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1802160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000007b1808021000180e221066697874757265636c69656e743030314a0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c18010a0a6765744c697374696e67160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000711808021000180e221066697874757265636c69656e74303031400a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c18012001160a102f73796e7468657469632f656d70747912001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f6f7468657212001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000731808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c18011a0a102f73796e7468657469632f656d70747912046974656d1800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001801");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000711808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801180a102f73796e7468657469632f656d707479120018002001");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000006b1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801120a102f73796e7468657469632f656d707479");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000811808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801280a102f73796e7468657469632f656d707479120018000a102f73796e7468657469632f656d707479");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(frame)) {
                accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408071000040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000001c16080710003a1066697874757265636c69656e74303031040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000c06080710001809040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000c06080710004001040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408081000040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000e0808dfffffff0f1000040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408071001040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408071002040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000241e080710002a18505249564154455f53594e5448455449435f43414e415259040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000c06080710003001040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000001c16080710003a1030303030303030303030303030303030040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000c06080710001808040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000c06080710004002040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000150f0807100048ffffffffffffffffff01040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000120c0807100052066f7061717565040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000c06080710005800040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000c06080710000807040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000050408071000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("00000006040807100000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408071000040a021001");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000c0408071000060a0410001800");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000b0408071000040a02100000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408071000040a0210");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408071000040a02100000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408071000040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000005a1808021000180e221066697874757265636c69656e743030313f0a0b67657446696c65496e666f122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c180100"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408071000040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000001a18080210001841221066697874757265636c69656e7430303100"))) {
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408071000040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try (var request = HdfsRenewalRpcGate.request(bytes("0000006f1808021000180e221066697874757265636c69656e743030313e0a0a6765744c697374696e67122e6f72672e6170616368652e6861646f6f702e686466732e70726f746f636f6c2e436c69656e7450726f746f636f6c1801160a102f73796e7468657469632f656d70747912001800"))) {
                request.close();
                try { HdfsRenewalRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }
                catch (HdfsRenewalRpcGate.Rejected rejected) {
                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
                }
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408071000040a021000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
                check(call == 7);
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0808dfffffff0f100000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
                check(call == -33);
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0808fdffffff0f100000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
                check(call == -3);
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000050408071001");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
                check(call == 7);
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000050408071002");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
                check(call == 7);
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000001f1e080710012a18505249564154455f53594e5448455449435f43414e415259");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
                check(call == 7);
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == true);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("00000006040800100000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0808ffffffff0f100000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000402100000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000402080700");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000050408071000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("00000006040807100100");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000704080710000000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000080608071000580000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("000000080608071000080700");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408071000040a0210");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000a0408071000040a02100000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        {
            byte[] frame = bytes("0000000705088700100000");
            byte[] before = frame.clone();
            boolean accepted = false;
            try { int call = HdfsRenewalRpcGate.responseCallId(frame); accepted = true;
            } catch (HdfsRenewalRpcGate.Rejected rejected) {
                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));
            }
            check(accepted == false);
            check(Arrays.equals(frame, before)); count++;
        }
        check(count == 85);
        return count;
    }
    public static void main(String[] args) throws Exception {
        System.out.println("rpc_gate_vectors_passed=" + checkAll());
    }
}
