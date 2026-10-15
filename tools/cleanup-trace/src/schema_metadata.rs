//! One bounded schema lookup, never a payload decoder or attribution source.
use std::{
    mem::{offset_of, size_of},
    ptr,
};
use windows_sys::{core::GUID, Win32::System::Diagnostics::Etw::*};

pub const BUFFER_BYTES: usize = 65536;
const MAX_PROPERTIES: usize = 16;

#[derive(Clone, Copy)]
struct Property {
    name: [u8; 64],
    name_len: usize,
    flags: u32,
    input: u16,
    output: u16,
    count: u16,
    length: u16,
}
impl Default for Property {
    fn default() -> Self {
        Self {
            name: [0; 64],
            name_len: 0,
            flags: 0,
            input: 0,
            output: 0,
            count: 0,
            length: 0,
        }
    }
}

#[derive(Clone, Copy)]
pub struct Observation {
    descriptor: EVENT_DESCRIPTOR,
    flags: u16,
    reason: &'static str,
    calls: u8,
    status: Option<u32>,
    bytes: Option<u32>,
    provider: Option<bool>,
    descriptor_match: Option<bool>,
    source: Option<i32>,
    count: usize,
    properties: [Property; MAX_PROPERTIES],
}

pub struct Capture {
    // u64 gives TRACE_EVENT_INFO and its descriptors sufficient alignment.
    buffer: Vec<u64>,
    pub observation: Option<Observation>,
}

impl Capture {
    pub fn new() -> Self {
        let mut buffer = Vec::new();
        if buffer.try_reserve_exact(BUFFER_BYTES / 8).is_ok() {
            buffer.resize(BUFFER_BYTES / 8, 0);
        }
        Self {
            buffer,
            observation: None,
        }
    }

    /// EVENT_RECORD is borrowed only during the existing consumer callback.
    pub unsafe fn observe(&mut self, event: *const EVENT_RECORD) {
        if self.observation.is_some() {
            return;
        }
        let header = &(*event).EventHeader;
        let mut result = Observation {
            descriptor: header.EventDescriptor,
            flags: header.Flags,
            reason: "buffer_unavailable",
            calls: 0,
            status: None,
            bytes: None,
            provider: None,
            descriptor_match: None,
            source: None,
            count: 0,
            properties: [Property::default(); MAX_PROPERTIES],
        };
        // Latch before TDH. Never retry, resize, retain event data, or query properties.
        self.observation = Some(result);
        if self.buffer.len() * 8 != BUFFER_BYTES {
            return;
        }
        result.calls = 1;
        let mut bytes = BUFFER_BYTES as u32;
        let status = TdhGetEventInformation(
            event,
            0,
            ptr::null(),
            self.buffer.as_mut_ptr().cast(),
            &mut bytes,
        );
        result.status = Some(status);
        result.bytes = Some(bytes);
        result.reason = if status != 0 {
            "tdh_failed"
        } else {
            let raw = std::slice::from_raw_parts(self.buffer.as_ptr().cast::<u8>(), BUFFER_BYTES);
            parse(raw, bytes as usize, header.ProviderId, &mut result)
                .err()
                .unwrap_or("none")
        };
        if result.reason != "none" {
            result.source = None;
            result.count = 0;
            result.properties = [Property::default(); MAX_PROPERTIES];
        }
        self.buffer.fill(0); // Retain only the closed projection after this callback.
        self.observation = Some(result);
    }
}

fn guid_equal(a: GUID, b: GUID) -> bool {
    a.data1 == b.data1 && a.data2 == b.data2 && a.data3 == b.data3 && a.data4 == b.data4
}

fn descriptor_equal(a: EVENT_DESCRIPTOR, b: EVENT_DESCRIPTOR) -> bool {
    a.Id == b.Id
        && a.Version == b.Version
        && a.Channel == b.Channel
        && a.Level == b.Level
        && a.Opcode == b.Opcode
        && a.Task == b.Task
        && a.Keyword == b.Keyword
}

fn wide_end(raw: &[u8], offset: u32, floor: usize) -> Result<usize, &'static str> {
    let start = offset as usize;
    if start < floor || !start.is_multiple_of(2) || start >= raw.len() {
        return Err("metadata_bounds");
    }
    for (i, pair) in raw[start..].chunks_exact(2).enumerate() {
        if pair == [0, 0] {
            return Ok(start + i * 2);
        }
    }
    Err("metadata_bounds")
}

fn parse(
    raw: &[u8],
    used: usize,
    provider: GUID,
    result: &mut Observation,
) -> Result<(), &'static str> {
    if used > raw.len() || used < size_of::<TRACE_EVENT_INFO>() {
        return Err("metadata_bounds");
    }
    let raw = &raw[..used];
    // Layouts/offsets come only from pinned windows-sys 0.61.2 SDK declarations.
    let info = unsafe { ptr::read_unaligned(raw.as_ptr().cast::<TRACE_EVENT_INFO>()) };
    result.provider = Some(guid_equal(provider, info.ProviderGuid));
    result.descriptor_match = Some(descriptor_equal(result.descriptor, info.EventDescriptor));
    if result.provider != Some(true) || result.descriptor_match != Some(true) {
        return Err("identity_mismatch");
    }
    if info.DecodingSource != DecodingSourceXMLFile && info.DecodingSource != DecodingSourceWbem {
        return Err("decoding_source");
    }
    if info.PropertyCount == 0
        || info.PropertyCount as usize > MAX_PROPERTIES
        || info.TopLevelPropertyCount != info.PropertyCount
    {
        return Err("property_bound");
    }
    if unsafe { info.Anonymous3.Flags } != 0 {
        return Err("metadata_flags");
    }
    let begin = offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray);
    let end = begin + info.PropertyCount as usize * size_of::<EVENT_PROPERTY_INFO>();
    if end > raw.len() {
        return Err("metadata_bounds");
    }
    // Validate even discarded offset-bearing metadata; never copy messages/names/XML.
    let offsets = [
        info.ProviderNameOffset,
        info.LevelNameOffset,
        info.ChannelNameOffset,
        info.KeywordsNameOffset,
        info.TaskNameOffset,
        info.OpcodeNameOffset,
        info.EventMessageOffset,
        info.ProviderMessageOffset,
        unsafe { info.Anonymous1.EventNameOffset },
        unsafe { info.Anonymous2.EventAttributesOffset },
    ];
    for offset in offsets {
        if offset != 0 {
            wide_end(raw, offset, end)?;
        }
    }
    if (info.BinaryXMLOffset == 0) != (info.BinaryXMLSize == 0)
        || (info.BinaryXMLOffset != 0
            && ((info.BinaryXMLOffset as usize) < end
                || (info.BinaryXMLOffset as usize)
                    .checked_add(info.BinaryXMLSize as usize)
                    .is_none_or(|n| n > raw.len())))
    {
        return Err("metadata_bounds");
    }
    for index in 0..info.PropertyCount as usize {
        let at = begin + index * size_of::<EVENT_PROPERTY_INFO>();
        let property =
            unsafe { ptr::read_unaligned(raw.as_ptr().add(at).cast::<EVENT_PROPERTY_INFO>()) };
        let flags = property.Flags;
        let allowed = PropertyParamLength
            | PropertyParamCount
            | PropertyParamFixedLength
            | PropertyParamFixedCount;
        if flags & !allowed != 0
            || flags & PropertyParamLength != 0 && flags & PropertyParamFixedLength != 0
            || flags & PropertyParamCount != 0 && flags & PropertyParamFixedCount != 0
            || unsafe { property.Anonymous4.Reserved } != 0
        {
            return Err("property_shape");
        }
        let values = unsafe { property.Anonymous1.nonStructType };
        // Maps/custom/struct/tag semantics require separate review, not guessed unions.
        if values.MapNameOffset != 0 {
            return Err("property_shape");
        }
        let count = unsafe { property.Anonymous2.count };
        let length = unsafe { property.Anonymous3.length };
        if flags & PropertyParamCount != 0 && count as u32 >= info.PropertyCount
            || flags & PropertyParamLength != 0 && length as u32 >= info.PropertyCount
        {
            return Err("property_shape");
        }
        let start = property.NameOffset as usize;
        let stop = wide_end(raw, property.NameOffset, end)?;
        if stop <= start || (stop - start) / 2 > 64 {
            return Err("property_name");
        }
        let mut value = Property {
            flags: flags as u32,
            input: values.InType,
            output: values.OutType,
            count,
            length,
            ..Property::default()
        };
        for pair in raw[start..stop].chunks_exact(2) {
            let ch = u16::from_le_bytes([pair[0], pair[1]]);
            if ch > 127
                || !(ch as u8 == b'_' || (ch as u8).is_ascii_alphanumeric())
                || value.name_len == 0 && (ch as u8).is_ascii_digit()
            {
                return Err("property_name");
            }
            value.name[value.name_len] = ch as u8;
            value.name_len += 1;
        }
        if result.properties[..index]
            .iter()
            .any(|p| p.name[..p.name_len] == value.name[..value.name_len])
        {
            return Err("property_name");
        }
        result.properties[index] = value;
    }
    result.source = Some(info.DecodingSource);
    result.count = info.PropertyCount as usize;
    Ok(())
}

pub fn json(observation: Option<Observation>, collection_complete: bool, runtime: &str) -> String {
    let number = |v: Option<u32>| v.map_or_else(|| "null".into(), |x| x.to_string());
    let boolean = |v: Option<bool>| v.map_or_else(|| "null".into(), |x| x.to_string());
    let observation = collection_complete.then_some(observation).flatten();
    let reason = observation.map_or(
        if collection_complete {
            "not_observed"
        } else {
            "collection_unavailable"
        },
        |o| o.reason,
    );
    let header = observation.map_or_else(|| "null".into(), |o| format!(
        "{{\"id\":{},\"version\":{},\"channel\":{},\"level\":{},\"opcode\":{},\"task\":{},\"keyword\":{},\"header_flags\":{}}}",
        o.descriptor.Id, o.descriptor.Version, o.descriptor.Channel, o.descriptor.Level,
        o.descriptor.Opcode, o.descriptor.Task, o.descriptor.Keyword, o.flags));
    let properties = if reason == "none" {
        let o = observation.unwrap();
        let mut values = String::from("[");
        for (i, p) in o.properties[..o.count].iter().enumerate() {
            if i > 0 {
                values.push(',');
            }
            let name = std::str::from_utf8(&p.name[..p.name_len]).unwrap_or("");
            values.push_str(&format!("{{\"name\":\"{}\",\"flags\":{},\"in_type\":{},\"out_type\":{},\"count\":{},\"length\":{}}}",
                name, p.flags, p.input, p.output, p.count, p.length));
        }
        values.push(']');
        values
    } else {
        "null".into()
    };
    format!("{{\"schema\":1,\"scope\":\"unsupported_fileio_schema\",\"availability\":\"{}\",\"reason\":\"{}\",\"runtime_sha256\":\"{}\",\"call_count\":{},\"header\":{},\"tdh_status\":{},\"buffer_bytes\":{},\"provider_matched\":{},\"descriptor_matched\":{},\"decoding_source\":{},\"properties\":{}}}",
        if reason == "none" { "available" } else { "unavailable" }, reason, runtime,
        number(if collection_complete { Some(observation.map_or(0, |o| o.calls as u32)) } else { None }),
        header, number(observation.and_then(|o| o.status)), number(observation.and_then(|o| o.bytes)),
        boolean(observation.and_then(|o| o.provider)), boolean(observation.and_then(|o| o.descriptor_match)),
        number(observation.and_then(|o| o.source).map(|v| v as u32)), properties)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn input() -> (Vec<u64>, usize, Observation) {
        let mut data = vec![0u64; BUFFER_BYTES / 8];
        let end =
            offset_of!(TRACE_EVENT_INFO, EventPropertyInfoArray) + size_of::<EVENT_PROPERTY_INFO>();
        let mut info = TRACE_EVENT_INFO {
            ProviderGuid: FileIoGuid,
            EventDescriptor: EVENT_DESCRIPTOR {
                Opcode: 84,
                Version: 3,
                ..Default::default()
            },
            DecodingSource: DecodingSourceWbem,
            PropertyCount: 1,
            TopLevelPropertyCount: 1,
            ..Default::default()
        };
        info.EventPropertyInfoArray[0].NameOffset = end as u32;
        info.EventPropertyInfoArray[0].Anonymous1.nonStructType = EVENT_PROPERTY_INFO_0_0 {
            InType: 16,
            OutType: 0,
            MapNameOffset: 0,
        };
        info.EventPropertyInfoArray[0].Anonymous2.count = 1;
        unsafe {
            ptr::write(data.as_mut_ptr().cast::<TRACE_EVENT_INFO>(), info);
            let raw = std::slice::from_raw_parts_mut(data.as_mut_ptr().cast::<u8>(), BUFFER_BYTES);
            for (i, ch) in b"IrpPtr".iter().enumerate() {
                raw[end + i * 2] = *ch;
            }
        }
        let observation = Observation {
            descriptor: info.EventDescriptor,
            flags: 832,
            reason: "none",
            calls: 1,
            status: Some(0),
            bytes: Some((end + 14) as u32),
            provider: None,
            descriptor_match: None,
            source: None,
            count: 0,
            properties: [Property::default(); MAX_PROPERTIES],
        };
        (data, end + 14, observation)
    }

    fn read(data: &[u64], used: usize, result: &mut Observation) -> Result<(), &'static str> {
        let raw = unsafe { std::slice::from_raw_parts(data.as_ptr().cast::<u8>(), BUFFER_BYTES) };
        parse(raw, used, FileIoGuid, result)
    }

    #[test]
    fn valid_schema_is_metadata_only_and_teardown_discards_it() {
        let (data, used, mut result) = input();
        assert_eq!(read(&data, used, &mut result), Ok(()));
        let value = json(Some(result), true, &"a".repeat(64));
        assert!(value.len() <= 8192);
        assert!(value.contains("\"name\":\"IrpPtr\""));
        assert!(!value.contains("pid"));
        assert!(!value.contains("counts"));
        let rejected = json(Some(result), false, &"a".repeat(64));
        assert!(rejected.contains("\"reason\":\"collection_unavailable\""));
        assert!(!rejected.contains("IrpPtr"));
    }

    #[test]
    fn every_offset_and_descriptor_bound_is_closed() {
        let (data, used, result) = input();
        for length in [0, size_of::<TRACE_EVENT_INFO>() - 1, BUFFER_BYTES + 1] {
            let mut check = result;
            assert_eq!(read(&data, length, &mut check), Err("metadata_bounds"));
        }
        for offset in [0, 1, 2, used as u32, u32::MAX] {
            let (mut data, used, mut result) = input();
            unsafe {
                (*data.as_mut_ptr().cast::<TRACE_EVENT_INFO>()).EventPropertyInfoArray[0]
                    .NameOffset = offset;
            }
            assert!(read(&data, used, &mut result).is_err());
        }
        let (mut data, used, mut result) = input();
        unsafe {
            (*data.as_mut_ptr().cast::<TRACE_EVENT_INFO>())
                .EventDescriptor
                .Opcode = 85;
        }
        assert_eq!(read(&data, used, &mut result), Err("identity_mismatch"));
    }

    #[test]
    fn unknown_flags_structures_and_name_text_are_unavailable() {
        for flags in [1, 8, 18, 36, 64, 128, 256, -1] {
            let (mut data, used, mut result) = input();
            unsafe {
                (*data.as_mut_ptr().cast::<TRACE_EVENT_INFO>()).EventPropertyInfoArray[0].Flags =
                    flags;
            }
            assert_eq!(read(&data, used, &mut result), Err("property_shape"));
        }
        for ch in [b'/', b'\\', b'"', b'1', 0xFF] {
            let (mut data, used, mut result) = input();
            let end = used - 14;
            unsafe {
                *data.as_mut_ptr().cast::<u8>().add(end) = ch;
            }
            assert_eq!(read(&data, used, &mut result), Err("property_name"));
        }
        let (mut data, used, mut result) = input();
        unsafe {
            (*data.as_mut_ptr().cast::<TRACE_EVENT_INFO>()).PropertyCount = 17;
        }
        assert_eq!(read(&data, used, &mut result), Err("property_bound"));
    }
}
