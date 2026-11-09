"""Build inert, wire-level native conformance cases from the pinned RPC schemas.

This generator does not compile or execute Java. Its output will be included in
the future contained cancellation probe and must pass there before qualification.
"""
import json
import struct
import sys
from pathlib import Path


def guard(event, args):
    if event.startswith(('socket.', 'subprocess.', 'os.exec', 'os.spawn')) or event in {
        'os.system', 'os.posix_spawn', 'os.fork', 'os.forkpty', 'pty.spawn', 'ctypes.dlopen'
    }:
        raise RuntimeError('native_network_operation_denied')


sys.addaudithook(guard)
sys.dont_write_bytecode = True
ROOT = Path(__file__).parent
CLIENT = b'fixtureclient001'
assert len(CLIENT) == 16
PROTOCOL = b'org.apache.hadoop.hdfs.protocol.ClientProtocol'
TARGET = b'/synthetic/empty'


def varint(value):
    assert type(value) is int and 0 <= value < 2**64
    result = bytearray()
    while value > 127:
        result.append((value & 127) | 128)
        value >>= 7
    result.append(value)
    return bytes(result)


def number(field, value):
    return varint(field << 3) + varint(value)


def data(field, value):
    return varint((field << 3) | 2) + varint(len(value)) + value


def frame(*messages):
    body = b''.join(varint(len(m)) + m for m in messages)
    return struct.pack('>I', len(body)) + body


def header(call=7, client=CLIENT, kind=2, operation=0):
    assert -(2**31) <= call < 2**31
    zigzag = (call << 1) ^ (call >> 31)
    return number(1, kind) + number(2, operation) + number(3, zigzag) + data(4, client)


def engine(method=b'getListing', protocol=PROTOCOL, version=1):
    return data(1, method) + data(2, protocol) + number(3, version)


def listing(target=TARGET, after=b'', location=0):
    return data(1, target) + data(2, after) + number(3, location)


def response_header(call=7, status=0):
    return number(1, call) + number(2, status)


BASE_REQUEST = frame(header(), engine(), listing())
BASE_RESPONSE = frame(response_header(), data(1, number(2, 0)))
# Independent hand-written wire oracle: call 7 / SUCCESS, empty DirectoryListing.
assert BASE_RESPONSE.hex() == '0000000a0408071000040a021000'
assert varint(14) == b'\x0e' and header(-3)[4:6] == b'\x18\x05'
request_cases = []
response_cases = []


def req(name, value, kind=None, call=7):
    request_cases.append(dict(name=name, hex=value.hex(), kind=kind, call=call))


def res(name, value, accepted=False, request=BASE_REQUEST, closed=False):
    response_cases.append(dict(name=name, hex=value.hex(), accepted=accepted,
                               request=request.hex(), closed=closed))


req('owned_listing', BASE_REQUEST, 'LISTING')
req('largest_positive_call', frame(header(2**31-1), engine(), listing()), 'LISTING', 2**31-1)
req('file_info_not_listing', frame(header(), engine(b'getFileInfo'), b''), 'FILE_INFO')
req('lease_not_listing', frame(header(), engine(b'renewLease'), b''), 'LEASE')
for call in (-3, -33):
    req('control_' + str(-call), frame(header(call), b'PRIVATE_SYNTHETIC_CANARY'), 'CONTROL', call)
for name, value in (
    ('empty', b''), ('truncated_prefix', b'\0\0\0'),
    ('zero_length', b'\0\0\0\0'), ('negative_length', b'\xff\xff\xff\xff\0'),
    ('oversized_declared', b'\0\1\0\1\0'),
    ('truncated_frame', BASE_REQUEST[:-1]), ('trailing_byte', BASE_REQUEST+b'\0'),
    ('one_message', frame(header())), ('four_messages', frame(header(), engine(), listing(), b'')),
    ('length_outside_frame', struct.pack('>I', 3)+b'\x7f\x00\x00'),
    ('overlong_length', struct.pack('>I', 4)+b'\x80\x00\x00\x00'),
    ('overflow_length', struct.pack('>I', 7)+b'\xff\xff\xff\xff\x7f\x00\x00'),
    ('zero_call', frame(header(0), engine(), listing())),
    ('unknown_control', frame(header(-4), b'')),
    ('control_with_engine', frame(header(-33), engine(), listing())),
    ('missing_request_body', frame(header(), engine())),
    ('short_client', frame(header(client=CLIENT[:-1]), engine(), listing())),
    ('wrong_rpc_kind', frame(header(kind=1), engine(), listing())),
    ('wrong_rpc_operation', frame(header(operation=1), engine(), listing())),
    ('duplicate_call', frame(header()+number(3,14), engine(), listing())),
    ('optional_retry_outside_sender_contract', frame(header()+number(5,1), engine(), listing())),
    ('unknown_header_field', frame(header()+number(11,1), engine(), listing())),
    ('noncanonical_header_varint', frame(b'\x08\x82\x00'+header()[2:], engine(), listing())),
    ('unknown_method', frame(header(), engine(b'getBlockLocations'), listing())),
    ('wrong_protocol', frame(header(), engine(protocol=b'PRIVATE_SYNTHETIC_CANARY'), listing())),
    ('wrong_version', frame(header(), engine(version=2), listing())),
    ('duplicate_method', frame(header(), engine()+data(1,b'getListing'), listing())),
    ('unknown_engine_field', frame(header(), engine()+number(4,1), listing())),
    ('wrong_target', frame(header(), engine(), listing(target=b'/synthetic/other'))),
    ('pagination_not_initial', frame(header(), engine(), listing(after=b'item'))),
    ('locations_not_requested', frame(header(), engine(), listing(location=1))),
    ('unknown_listing_field', frame(header(), engine(), listing()+number(4,1))),
    ('missing_listing_fields', frame(header(), engine(), data(1,TARGET))),
    ('duplicate_listing_target', frame(header(), engine(), listing()+data(1,TARGET))),
):
    req(name, value)

res('matching_empty_directory', BASE_RESPONSE, True)
res('matching_explicit_client', frame(response_header()+data(7,CLIENT), data(1,number(2,0))), True)
res('matching_ipc_version', frame(response_header()+number(3,9), data(1,number(2,0))), True)
res('matching_explicit_retry', frame(response_header()+number(8,1), data(1,number(2,0))), True)
for name, value in (
    ('wrong_call', frame(response_header(8), data(1,number(2,0)))),
    ('control_call', frame(response_header(2**32-33), data(1,number(2,0)))),
    ('rpc_error', frame(response_header(status=1), data(1,number(2,0)))),
    ('rpc_fatal', frame(response_header(status=2), data(1,number(2,0)))),
    ('error_text_on_success', frame(response_header()+data(5,b'PRIVATE_SYNTHETIC_CANARY'), data(1,number(2,0)))),
    ('error_detail_on_success', frame(response_header()+number(6,1), data(1,number(2,0)))),
    ('wrong_response_client', frame(response_header()+data(7,b'0'*16), data(1,number(2,0)))),
    ('wrong_ipc_version', frame(response_header()+number(3,8), data(1,number(2,0)))),
    ('unexpected_retry', frame(response_header()+number(8,2), data(1,number(2,0)))),
    ('negative_state', frame(response_header()+number(9,2**64-1), data(1,number(2,0)))),
    ('router_state', frame(response_header()+data(10,b'opaque'), data(1,number(2,0)))),
    ('unknown_response_field', frame(response_header()+number(11,0), data(1,number(2,0)))),
    ('duplicate_response_call', frame(response_header()+number(1,7), data(1,number(2,0)))),
    ('missing_body', frame(response_header())),
    ('missing_directory', frame(response_header(), b'')),
    ('unfinished_directory', frame(response_header(), data(1,number(2,1)))),
    ('unknown_directory_field', frame(response_header(), data(1,number(2,0)+number(3,0)))),
    ('extra_part', frame(response_header(), data(1,number(2,0)), b'')),
    ('truncated_response', BASE_RESPONSE[:-1]), ('trailing_response', BASE_RESPONSE+b'\0'),
):
    res(name, value)
res('file_info_cannot_match', BASE_RESPONSE, request=frame(header(), engine(b'getFileInfo'), b''))
res('control_cannot_match', BASE_RESPONSE, request=frame(header(-33), b''))
res('closed_request_cannot_match', BASE_RESPONSE, closed=True)

response_header_cases = [
    ('positive_success', BASE_RESPONSE, 7),
    ('sasl_success', frame(response_header(2**32-33), b''), -33),
    ('context_success', frame(response_header(2**32-3), b''), -3),
    ('header_only_error', frame(response_header(status=1)), 7),
    ('header_only_fatal', frame(response_header(status=2)), 7),
    ('header_only_error_message', frame(response_header(status=1)+data(5,b'PRIVATE_SYNTHETIC_CANARY')), 7),
    ('zero_call', frame(response_header(0), b''), None),
    ('unowned_negative_call', frame(response_header(2**32-1), b''), None),
    ('missing_call', frame(number(2,0), b''), None),
    ('missing_status', frame(number(1,7), b''), None),
    ('missing_success_body', frame(response_header()), None),
    ('error_with_body', frame(response_header(status=1), b''), None),
    ('extra_part', frame(response_header(), b'', b''), None),
    ('unknown_header', frame(response_header()+number(11,0), b''), None),
    ('duplicate_call', frame(response_header()+number(1,7), b''), None),
    ('truncated', BASE_RESPONSE[:-1], None),
    ('trailing', BASE_RESPONSE+b'\0', None),
    ('overlong_call_varint', frame(b'\x08\x87\x00\x10\x00', b''), None),
]

assert len({v['name'] for v in request_cases}) == len(request_cases)
assert len({v['name'] for v in response_cases}) == len(response_cases)
manifest = dict(schema=1, native_qualified=False, request_cases=request_cases, response_cases=response_cases,
                response_header_cases=[dict(name=n, hex=v.hex(), call=c) for n,v,c in response_header_cases])
(ROOT/'rpc-gate-vectors.json').write_text(json.dumps(manifest, indent=2)+'\n')

lines = ['import java.util.Arrays;', 'import java.util.HexFormat;',
         'final class HdfsCancellationRpcGateVectors {',
         '    private static byte[] bytes(String hex) { return HexFormat.of().parseHex(hex); }',
         '    private static void check(boolean value) { if (!value) throw new IllegalStateException("rpc_gate_vector_failed"); }',
         '    static int checkAll() throws Exception {', '        int count = 0;']
for value in request_cases:
    lines += ['        {', f'            byte[] frame = bytes("{value["hex"]}");',
              '            byte[] before = frame.clone();', '            boolean accepted = false;',
              '            try (var request = HdfsCancellationRpcGate.request(frame)) {',
              '                accepted = true;']
    if value['kind'] is not None:
        lines += [f'                check(request.kind == HdfsCancellationRpcGate.Kind.{value["kind"]} && request.callId == {value["call"]});']
    lines += ['            } catch (HdfsCancellationRpcGate.Rejected rejected) {',
              '                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));', '            }',
              f'            check(accepted == {str(value["kind"] is not None).lower()});',
              '            check(Arrays.equals(frame, before)); count++;', '        }']
for value in response_cases:
    lines += ['        {', f'            byte[] frame = bytes("{value["hex"]}");',
              '            byte[] before = frame.clone();', '            boolean accepted = false;',
              f'            try (var request = HdfsCancellationRpcGate.request(bytes("{value["request"]}"))) {{']
    if value['closed']:
        lines += ['                request.close();']
    lines += ['                try { HdfsCancellationRpcGate.matchingEmptyListingResponse(frame, request); accepted = true; }',
              '                catch (HdfsCancellationRpcGate.Rejected rejected) {',
              '                    check(rejected.getMessage().equals("rpc_gate_frame_rejected"));', '                }',
              '            }', f'            check(accepted == {str(value["accepted"]).lower()});',
              '            check(Arrays.equals(frame, before)); count++;', '        }']
for name, frame_bytes, call in response_header_cases:
    lines += ['        {', f'            byte[] frame = bytes("{frame_bytes.hex()}");',
              '            byte[] before = frame.clone();', '            boolean accepted = false;',
              '            try { int call = HdfsCancellationRpcGate.responseCallId(frame); accepted = true;']
    if call is not None:
        lines += [f'                check(call == {call});']
    lines += ['            } catch (HdfsCancellationRpcGate.Rejected rejected) {',
              '                check(rejected.getMessage().equals("rpc_gate_frame_rejected"));', '            }',
              f'            check(accepted == {str(call is not None).lower()});',
              '            check(Arrays.equals(frame, before)); count++;', '        }']
lines += [f'        check(count == {len(request_cases)+len(response_cases)+len(response_header_cases)});', '        return count;', '    }',
          '    public static void main(String[] args) throws Exception {',
          '        System.out.println("rpc_gate_vectors_passed=" + checkAll());', '    }', '}']
(ROOT/'HdfsCancellationRpcGateVectors.java').write_text('\n'.join(lines)+'\n')
print(json.dumps(dict(request_cases=len(request_cases), response_cases=len(response_cases),
                     response_header_cases=len(response_header_cases), native_executions=0, native_qualified=False)))
