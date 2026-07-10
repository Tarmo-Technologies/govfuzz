// SPDX-License-Identifier: Apache-2.0

pub mod cdr;
pub mod giop;
pub mod idl_args;

#[cfg(test)]
mod tests {
    use super::cdr::{CdrError, CdrReader, Endianness};
    use super::giop::{
        parse_header, parse_message, parse_message_1_2, parse_message_typed, parse_messages_1_2,
        read_cancel_request, read_fragment_1_2, read_iiop_profile_body, read_locate_reply_1_2,
        read_locate_request_1_2, read_message_1_2, read_message_typed, read_reply_1_0,
        read_reply_1_1, read_reply_1_2, read_request_1_0, read_request_1_1, read_request_1_2,
        read_service_context_list, reassemble_messages_1_2, CompletionStatus, GiopError,
        GiopReassemblyError, Ior, IorAddressingInfo, LocateStatus, MessageHeader, MessageType,
        ParsedGiop, ParsedGiop10, ParsedGiop11, ParsedGiop12, ParsedGiop12Message,
        ParsedLocateReplyBody12, ParsedReplyBody12, ReplyStatus, ServiceContext, TaggedComponent,
        TaggedProfile, TargetAddress, Version, TAG_INTERNET_IOP,
    };
    use super::idl_args::{
        decode_request_arguments, DecodedArgumentValue, IdlArgumentDecodeError, IdlOperationCatalog,
    };

    #[test]
    fn parses_giop_1_2_little_endian_request_header() {
        let header = parse_header(&[b'G', b'I', b'O', b'P', 1, 2, 0x01, 0, 16, 0, 0, 0])
            .expect("valid GIOP header");

        assert_eq!(header.version.major, 1);
        assert_eq!(header.version.minor, 2);
        assert_eq!(header.endian, Endianness::Little);
        assert_eq!(header.message_type, MessageType::Request);
        assert!(!header.fragmented);
        assert_eq!(header.body_len, 16);
    }

    #[test]
    fn rejects_bad_magic_and_truncated_giop_header() {
        assert_eq!(
            parse_header(b"bad").unwrap_err(),
            GiopError::TruncatedHeader { len: 3 }
        );
        assert_eq!(
            parse_header(&[b'N', b'O', b'P', b'E', 1, 2, 0, 0, 0, 0, 0, 0]).unwrap_err(),
            GiopError::BadMagic([b'N', b'O', b'P', b'E'])
        );
    }

    #[test]
    fn rejects_unsupported_giop_versions() {
        assert_eq!(
            parse_header(&[b'G', b'I', b'O', b'P', 9, 0, 0, 0, 0, 0, 0, 0]).unwrap_err(),
            GiopError::UnsupportedVersion(super::giop::Version { major: 9, minor: 0 })
        );
    }

    #[test]
    fn rejects_invalid_giop_1_0_byte_order_values() {
        assert_eq!(
            parse_header(&[b'G', b'I', b'O', b'P', 1, 0, 2, 0, 0, 0, 0, 0]).unwrap_err(),
            GiopError::InvalidFlags {
                version: super::giop::Version { major: 1, minor: 0 },
                flags: 2,
            }
        );
    }

    #[test]
    fn rejects_reserved_giop_1_1_and_1_2_flag_bits() {
        assert_eq!(
            parse_header(&[b'G', b'I', b'O', b'P', 1, 1, 0x04, 0, 0, 0, 0, 0]).unwrap_err(),
            GiopError::InvalidFlags {
                version: super::giop::Version { major: 1, minor: 1 },
                flags: 0x04,
            }
        );
        assert_eq!(
            parse_header(&[b'G', b'I', b'O', b'P', 1, 2, 0x80, 0, 0, 0, 0, 0]).unwrap_err(),
            GiopError::InvalidFlags {
                version: super::giop::Version { major: 1, minor: 2 },
                flags: 0x80,
            }
        );
    }

    #[test]
    fn parses_giop_message_frame_and_preserves_remaining_bytes() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0x01, 0, 4, 0, 0, 0, 1, 2, 3, 4, 0xff,
        ])
        .expect("valid GIOP frame");

        assert_eq!(frame.header.message_type, MessageType::Request);
        assert_eq!(frame.header.body_len, 4);
        assert_eq!(frame.body, &[1, 2, 3, 4]);
        assert_eq!(frame.remaining, &[0xff]);
    }

    #[test]
    fn rejects_truncated_giop_message_body() {
        assert_eq!(
            parse_message(&[b'G', b'I', b'O', b'P', 1, 2, 0x01, 0, 4, 0, 0, 0, 1, 2,]).unwrap_err(),
            GiopError::TruncatedBody {
                declared: 4,
                available: 2,
            }
        );
    }

    #[test]
    fn message_body_reader_aligns_to_giop_message_origin() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 0, 0, 0, 0, 12, 0, 0, 0, 0, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08,
        ])
        .expect("valid GIOP frame");
        let mut reader = frame.body_reader();

        assert_eq!(reader.read_u32().unwrap(), 0);
        assert_eq!(reader.read_u64().unwrap(), 0x0102_0304_0506_0708);
        assert_eq!(reader.position(), 12);
    }

    #[test]
    fn cdr_reader_aligns_and_reads_little_endian_primitives() {
        let mut reader =
            CdrReader::new(&[0xaa, 0, 0, 0, 0x78, 0x56, 0x34, 0x12], Endianness::Little);

        assert_eq!(reader.read_octet().unwrap(), 0xaa);
        assert_eq!(reader.read_u32().unwrap(), 0x1234_5678);
        assert_eq!(reader.position(), 8);
    }

    #[test]
    fn cdr_reader_reads_encapsulation_with_own_byte_order_and_alignment() {
        let mut reader = CdrReader::from_encapsulation(&[
            1, // little-endian encapsulation
            0xaa, 0xbb, // two octet values
            0,    // padding before u32, aligned relative to encapsulation start
            0x78, 0x56, 0x34, 0x12,
        ])
        .expect("valid CDR encapsulation");

        assert_eq!(reader.read_octet().unwrap(), 0xaa);
        assert_eq!(reader.read_octet().unwrap(), 0xbb);
        assert_eq!(reader.read_u32().unwrap(), 0x1234_5678);
        assert_eq!(reader.position(), 7);
    }

    #[test]
    fn cdr_reader_reads_big_endian_string_with_nul_terminator() {
        let mut reader = CdrReader::new(&[0, 0, 0, 4, b'a', b'b', b'c', 0], Endianness::Big);

        assert_eq!(reader.read_string().unwrap(), "abc");
        assert_eq!(reader.position(), 8);
    }

    #[test]
    fn cdr_reader_reads_borrowed_octet_sequence() {
        let mut reader = CdrReader::new(&[0, 0, 0, 3, 1, 2, 3, 0xff], Endianness::Big);

        assert_eq!(reader.read_octet_sequence().unwrap(), &[1, 2, 3]);
        assert_eq!(reader.position(), 7);
        assert_eq!(reader.read_octet().unwrap(), 0xff);
    }

    #[test]
    fn cdr_reader_rejects_invalid_boolean_octets() {
        let mut reader = CdrReader::new(&[2, 0xff], Endianness::Big);

        assert_eq!(
            reader.read_bool().unwrap_err(),
            CdrError::InvalidBoolean {
                offset: 0,
                value: 2,
            }
        );
        assert_eq!(
            reader.read_bool().unwrap_err(),
            CdrError::InvalidBoolean {
                offset: 1,
                value: 0xff,
            }
        );
    }

    #[test]
    fn parses_giop_service_context_list() {
        let input = [
            0, 0, 0, 2, // list length
            0, 0, 0, 1, // context_id
            0, 0, 0, 2, // context_data length
            0xaa, 0xbb, // context_data
            0, 0, // padding before next ServiceContext
            0, 0, 0, 2, // context_id
            0, 0, 0, 0, // empty context_data
        ];
        let mut reader = CdrReader::new(&input, Endianness::Big);

        assert_eq!(
            read_service_context_list(&mut reader).unwrap(),
            vec![
                ServiceContext {
                    context_id: 1,
                    data: &[0xaa, 0xbb],
                },
                ServiceContext {
                    context_id: 2,
                    data: &[],
                },
            ]
        );
        assert_eq!(reader.position(), input.len());
    }

    #[test]
    fn parses_giop_1_2_request_header_with_key_addr_target() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 0, 0, 0, 0, 53, // GIOP header
            0, 0, 0, 42,   // request_id
            0x03, // response_flags
            0, 0, 0, // reserved
            0, 0, // KeyAddr discriminator
            0, 0, // padding before object key sequence length
            0, 0, 0, 3, // object key length
            0xde, 0xad, 0xbe, // object key
            0,    // padding before operation string
            0, 0, 0, 5, // operation string length including NUL
            b'p', b'i', b'n', b'g', 0, // operation
            0, 0, 0, // padding before service context count
            0, 0, 0, 1, // service context count
            0, 0, 0, 7, // context_id
            0, 0, 0, 2, // context_data length
            0xaa, 0xbb, // context_data
            0, 0, 0, 0, 0, 0,    // argument padding
            0x55, // first octet argument
        ])
        .expect("valid GIOP frame");

        let request = read_request_1_2(&frame).expect("valid GIOP 1.2 request");

        assert_eq!(
            request.service_contexts,
            vec![ServiceContext {
                context_id: 7,
                data: &[0xaa, 0xbb],
            }]
        );
        assert_eq!(request.request_id, 42);
        assert_eq!(request.response_flags, 0x03);
        assert_eq!(request.target, TargetAddress::KeyAddr(&[0xde, 0xad, 0xbe]));
        assert_eq!(request.operation, "ping");
        assert_eq!(request.arguments, &[0x55]);

        let mut arguments = request.arguments_reader();
        assert_eq!(arguments.read_octet().unwrap(), 0x55);
        assert_eq!(arguments.position(), 1);
    }

    #[test]
    fn parses_giop_1_0_request_header_with_object_key_and_principal() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 0, 0, 0, 0, 0, 0, 38, // GIOP header
            0, 0, 0, 0, // service context count
            0, 0, 0, 42, // request_id
            1,  // response_expected
            0, 0, 0, // implicit alignment before object key sequence
            0, 0, 0, 3, // object key length
            0xde, 0xad, 0xbe, // object key
            0,    // padding before operation string
            0, 0, 0, 5, // operation length including NUL
            b'p', b'i', b'n', b'g', 0, // operation
            0, 0, 0, // padding before requesting_principal sequence
            0, 0, 0, 2, // principal length
            0xaa, 0xbb, // principal
        ])
        .expect("valid GIOP frame");

        let request = read_request_1_0(&frame).expect("valid GIOP 1.0 request");

        assert_eq!(request.service_contexts, Vec::<ServiceContext<'_>>::new());
        assert_eq!(request.request_id, 42);
        assert!(request.response_expected);
        assert_eq!(request.object_key, &[0xde, 0xad, 0xbe]);
        assert_eq!(request.operation, "ping");
        assert_eq!(request.requesting_principal, &[0xaa, 0xbb]);
        assert_eq!(request.arguments, &[]);
    }

    #[test]
    fn parses_giop_1_1_request_header_with_reserved_bytes() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 1, 0, 0, 0, 0, 0, 37, // GIOP header
            0, 0, 0, 0, // service context count
            0, 0, 0, 43, // request_id
            0,  // response_expected
            0, 0, 0, // reserved
            0, 0, 0, 2, // object key length
            0xca, 0xfe, // object key
            0, 0, // padding before operation string
            0, 0, 0, 5, // operation length including NUL
            b'p', b'o', b'n', b'g', 0, // operation
            0, 0, 0, // padding before requesting_principal sequence
            0, 0, 0, 1,    // principal length
            0xcc, // principal
        ])
        .expect("valid GIOP frame");

        let request = read_request_1_1(&frame).expect("valid GIOP 1.1 request");

        assert_eq!(request.request_id, 43);
        assert!(!request.response_expected);
        assert_eq!(request.reserved, [0, 0, 0]);
        assert_eq!(request.object_key, &[0xca, 0xfe]);
        assert_eq!(request.operation, "pong");
        assert_eq!(request.requesting_principal, &[0xcc]);
    }

    #[test]
    fn parses_giop_1_0_and_1_1_reply_headers_with_service_contexts_first() {
        for minor in [0, 1] {
            let input = [
                b'G', b'I', b'O', b'P', 1, minor, 0, 1, 0, 0, 0, 29, // GIOP header
                0, 0, 0, 1, // service context count
                0, 0, 0, 7, // context_id
                0, 0, 0, 1,    // context_data length
                0xaa, // context_data
                0, 0, 0, // padding before request_id
                0, 0, 0, 42, // request_id
                0, 0, 0, 0, // NO_EXCEPTION
                0, 0, 0, 0,    // reply body padding
                0x44, // first reply body octet
            ];
            let frame = parse_message(&input).expect("valid GIOP frame");

            let reply = if minor == 0 {
                read_reply_1_0(&frame).expect("valid GIOP 1.0 reply")
            } else {
                read_reply_1_1(&frame).expect("valid GIOP 1.1 reply")
            };

            assert_eq!(reply.request_id, 42);
            assert_eq!(reply.status, ReplyStatus::NoException);
            assert_eq!(
                reply.service_contexts,
                vec![ServiceContext {
                    context_id: 7,
                    data: &[0xaa],
                }]
            );
            assert_eq!(reply.body, &[0x44]);
        }
    }

    #[test]
    fn rejects_nonzero_giop_1_1_request_reserved_bytes() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 1, 0, 0, 0, 0, 0, 12, // GIOP header
            0, 0, 0, 0, // service context count
            0, 0, 0, 1, // request_id
            1, // response_expected
            0, 1, 0, // reserved
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_request_1_1(&frame).unwrap_err(),
            GiopError::InvalidRequestReserved {
                offset: 9,
                reserved: [0, 1, 0],
            }
        );
    }

    #[test]
    fn dispatches_typed_giop_1_0_1_1_and_1_2_messages() {
        let giop10 = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 0, 0, 0, 0, 0, 0, 36, // Request
            0, 0, 0, 0, // service context count
            0, 0, 0, 42, // request_id
            0,  // response_expected
            0, 0, 0, // implicit alignment
            0, 0, 0, 1,    // object key length
            0xaa, // object key
            0, 0, 0, // padding before operation
            0, 0, 0, 5, // operation length including NUL
            b'p', b'i', b'n', b'g', 0, // operation
            0, 0, 0, // padding before principal
            0, 0, 0, 0, // principal length
        ])
        .expect("valid GIOP 1.0 frame");
        let giop11 = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 1, 0, 1, 0, 0, 0, 12, // Reply
            0, 0, 0, 0, // service context count
            0, 0, 0, 7, // request_id
            0, 0, 0, 0, // NO_EXCEPTION
        ])
        .expect("valid GIOP 1.1 frame");
        let giop12 = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 2, 0, 0, 0, 4, // CancelRequest
            0, 0, 0, 77,
        ])
        .expect("valid GIOP 1.2 frame");

        assert!(matches!(
            read_message_typed(&giop10).unwrap(),
            ParsedGiop::Giop10(ParsedGiop10::Request(_))
        ));
        assert!(matches!(
            read_message_typed(&giop11).unwrap(),
            ParsedGiop::Giop11(ParsedGiop11::Reply(_))
        ));
        assert!(matches!(
            read_message_typed(&giop12).unwrap(),
            ParsedGiop::Giop12(ParsedGiop12::CancelRequest(_))
        ));
    }

    #[test]
    fn parses_typed_giop_message_and_preserves_remaining_bytes() {
        let parsed = parse_message_typed(&[
            b'G', b'I', b'O', b'P', 1, 1, 0, 1, 0, 0, 0, 12, // Reply
            0, 0, 0, 0, // service context count
            0, 0, 0, 7, // request_id
            0, 0, 0, 0, // NO_EXCEPTION
            0xff,
        ])
        .expect("valid typed GIOP message");

        assert_eq!(parsed.header.version, Version { major: 1, minor: 1 });
        assert!(matches!(
            parsed.message,
            ParsedGiop::Giop11(ParsedGiop11::Reply(_))
        ));
        assert_eq!(parsed.remaining, &[0xff]);
    }

    #[test]
    fn parses_giop_1_2_request_header_with_profile_addr_target() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 0, 0, 0, 0, 40, // GIOP header
            0, 0, 0, 42,   // request_id
            0x03, // response_flags
            0, 0, 0, // reserved
            0, 1, // ProfileAddr discriminator
            0, 0, // padding before TaggedProfile tag
            0, 0, 0, 99, // profile tag
            0, 0, 0, 3, // profile_data length
            0xaa, 0xbb, 0xcc, // profile_data
            0,    // padding before operation string
            0, 0, 0, 5, // operation string length including NUL
            b'p', b'i', b'n', b'g', 0, // operation
            0, 0, 0, // padding before service context count
            0, 0, 0, 0, // service context count
        ])
        .expect("valid GIOP frame");

        let request = read_request_1_2(&frame).expect("valid GIOP 1.2 request");

        assert_eq!(request.service_contexts, Vec::<ServiceContext<'_>>::new());
        assert_eq!(request.request_id, 42);
        assert_eq!(request.response_flags, 0x03);
        assert_eq!(
            request.target,
            TargetAddress::ProfileAddr(TaggedProfile {
                tag: 99,
                profile_data: &[0xaa, 0xbb, 0xcc],
            })
        );
        assert_eq!(request.operation, "ping");
        assert_eq!(request.arguments, &[]);
    }

    #[test]
    fn decodes_giop_1_2_request_arguments_from_idl_operation_metadata() {
        let idl = idl_parser::parse_idl(
            r#"
            interface Echo {
              void submit(
                in long Count,
                in string Label,
                in sequence<octet> Data,
                in Object Ref
              );
            };
            "#,
        )
        .expect("IDL parses");
        let catalog = IdlOperationCatalog::from_idl_file(&idl);
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 0, 0, 0, 0, 84, // GIOP header
            0, 0, 0, 42,   // request_id
            0x03, // response_flags
            0, 0, 0, // reserved
            0, 1, // ProfileAddr discriminator
            0, 0, // padding before TaggedProfile tag
            0, 0, 0, 99, // profile tag
            0, 0, 0, 3, // profile_data length
            0xaa, 0xbb, 0xcc, // profile_data
            0,    // padding before operation string
            0, 0, 0, 7, // operation string length including NUL
            b's', b'u', b'b', b'm', b'i', b't', 0, // operation
            0, // padding before service context count
            0, 0, 0, 0, // service context count
            0, 0, 0, 0, // padding before arguments
            0xff, 0xff, 0xff, 0xf9, // Count : long = -7
            0, 0, 0, 3, b'o', b'k', 0, // Label : string = "ok"
            0, // padding before Data sequence length
            0, 0, 0, 2, 0xde, 0xad, // Data : sequence<octet>
            0, 0, // padding before Ref IOR type_id
            0, 0, 0, 12, // IOR type_id length including NUL
            b'I', b'D', b'L', b':', b'O', b'b', b'j', b':', b'1', b'.', b'0', 0, 0, 0, 0,
            0, // zero IOR profiles
        ])
        .expect("valid GIOP frame");
        let request = read_request_1_2(&frame).expect("valid GIOP 1.2 request");

        let decoded = decode_request_arguments(&request, &catalog)
            .expect("request arguments decode from IDL metadata");

        assert_eq!(decoded.interface, "Echo");
        assert_eq!(decoded.operation, "submit");
        assert_eq!(decoded.raw_arguments, request.arguments);
        assert_eq!(decoded.arguments.len(), 4);
        assert_eq!(decoded.arguments[0].name, "Count");
        assert_eq!(decoded.arguments[0].span, 0..4);
        assert_eq!(decoded.arguments[0].value, DecodedArgumentValue::Long(-7));
        assert_eq!(decoded.arguments[1].name, "Label");
        assert_eq!(decoded.arguments[1].span, 4..11);
        assert_eq!(
            decoded.arguments[1].value,
            DecodedArgumentValue::String("ok".to_owned())
        );
        assert_eq!(decoded.arguments[2].name, "Data");
        assert_eq!(decoded.arguments[2].span, 11..18);
        assert_eq!(
            decoded.arguments[2].value,
            DecodedArgumentValue::Sequence(vec![
                DecodedArgumentValue::Octet(0xde),
                DecodedArgumentValue::Octet(0xad)
            ])
        );
        assert_eq!(decoded.arguments[3].name, "Ref");
        assert_eq!(decoded.arguments[3].span, 18..40);
        assert_eq!(
            decoded.arguments[3].value,
            DecodedArgumentValue::ObjectReference {
                type_id: "IDL:Obj:1.0".to_owned(),
                profile_count: 0,
            }
        );
    }

    #[test]
    fn idl_operation_catalog_looks_up_by_repository_id_and_interface_scope() {
        let idl = idl_parser::parse_idl(
            r#"
            #pragma prefix "acme.example"
            module Demo {
              #pragma version Echo 2.1
              interface Echo {
                void submit(in long Count);
              };
            };
            "#,
        )
        .expect("IDL parses");
        let catalog = IdlOperationCatalog::from_idl_file(&idl);

        let by_repository = catalog
            .lookup_operation_by_repository_id("IDL:acme.example/Demo/Echo:2.1", "submit")
            .expect("operation is keyed by repository ID");
        let by_interface = catalog
            .lookup_operation_by_interface(&["Demo", "Echo"], "submit")
            .expect("operation is keyed by scoped interface");

        assert_eq!(by_repository, by_interface);
        assert_eq!(by_repository.interface, "Echo");
        assert_eq!(
            by_repository.repository_id.as_deref(),
            Some("IDL:acme.example/Demo/Echo:2.1")
        );
    }

    #[test]
    fn idl_argument_decode_unknown_operation_preserves_raw_payload() {
        let idl = idl_parser::parse_idl(
            r#"
            interface Echo {
              void known(in long Count);
            };
            "#,
        )
        .expect("IDL parses");
        let catalog = IdlOperationCatalog::from_idl_file(&idl);
        let input = giop_1_2_request_bytes("missing", &[0, 0, 0, 7]);
        let frame = parse_message(&input).expect("valid GIOP frame");
        let request = read_request_1_2(&frame).expect("valid GIOP 1.2 request");

        let error = decode_request_arguments(&request, &catalog).unwrap_err();

        assert_eq!(
            error,
            IdlArgumentDecodeError::UnknownOperation {
                operation: "missing".to_owned(),
                raw_arguments: vec![0, 0, 0, 7],
            }
        );
    }

    #[test]
    fn idl_argument_decode_unsupported_type_preserves_raw_payload() {
        let idl = idl_parser::parse_idl(
            r#"
            interface Echo {
              void submit(in any Value);
            };
            "#,
        )
        .expect("IDL parses");
        let catalog = IdlOperationCatalog::from_idl_file(&idl);
        let input = giop_1_2_request_bytes("submit", &[0xca, 0xfe]);
        let frame = parse_message(&input).expect("valid GIOP frame");
        let request = read_request_1_2(&frame).expect("valid GIOP 1.2 request");

        let error = decode_request_arguments(&request, &catalog).unwrap_err();

        assert_eq!(
            error,
            IdlArgumentDecodeError::UnsupportedType {
                operation: "submit".to_owned(),
                parameter: "Value".to_owned(),
                ty: idl_parser::TypeRef::Primitive(idl_parser::PrimitiveType::Any),
                raw_arguments: vec![0xca, 0xfe],
            }
        );
    }

    #[test]
    fn parses_giop_1_2_reply_header_and_aligns_body() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 29, // GIOP header
            0, 0, 0, 42, // request_id
            0, 0, 0, 0, // NO_EXCEPTION
            0, 0, 0, 1, // service context count
            0, 0, 0, 7, // context_id
            0, 0, 0, 1,    // context_data length
            0xaa, // context_data
            0, 0, 0, 0, 0, 0, 0,    // reply body padding
            0x44, // first octet body value
        ])
        .expect("valid GIOP frame");

        let reply = read_reply_1_2(&frame).expect("valid GIOP 1.2 reply");

        assert_eq!(reply.request_id, 42);
        assert_eq!(reply.status, ReplyStatus::NoException);
        assert_eq!(
            reply.service_contexts,
            vec![ServiceContext {
                context_id: 7,
                data: &[0xaa],
            }]
        );
        assert_eq!(reply.body, &[0x44]);
        assert_eq!(reply.forwarded_ior().unwrap(), None);
        assert_eq!(reply.forwarded_iiop_profiles().unwrap(), Vec::new());
        assert_eq!(reply.addressing_disposition().unwrap(), None);
        assert_eq!(reply.user_exception().unwrap(), None);

        let mut body = reply.body_reader();
        assert_eq!(body.read_octet().unwrap(), 0x44);
        assert_eq!(body.position(), 1);
    }

    #[test]
    fn decodes_giop_1_2_reply_location_forward_ior_body() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 44, // GIOP header
            0, 0, 0, 42, // request_id
            0, 0, 0, 3, // LOCATION_FORWARD
            0, 0, 0, 0, // service context count
            0, 0, 0, 10, // IOR type_id string length including NUL
            b'I', b'D', b'L', b':', b'Y', b':', b'1', b'.', b'0', 0, // type_id
            0, 0, // padding before profile sequence count
            0, 0, 0, 1, // profile count
            0, 0, 0, 0, // TAG_INTERNET_IOP
            0, 0, 0, 4, // profile_data length
            0xaa, 0xbb, 0xcc, 0xdd, // profile_data
        ])
        .expect("valid GIOP frame");

        let reply = read_reply_1_2(&frame).expect("valid GIOP 1.2 reply");

        assert_eq!(reply.status, ReplyStatus::LocationForward);
        assert_eq!(
            reply.forwarded_ior().unwrap(),
            Some(Ior {
                type_id: "IDL:Y:1.0".to_owned(),
                profiles: vec![TaggedProfile {
                    tag: 0,
                    profile_data: &[0xaa, 0xbb, 0xcc, 0xdd],
                }],
            })
        );
    }

    #[test]
    fn decodes_giop_1_2_reply_location_forward_iiop_profiles() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 61, // GIOP header
            0, 0, 0, 42, // request_id
            0, 0, 0, 3, // LOCATION_FORWARD
            0, 0, 0, 0, // service context count
            0, 0, 0, 10, // IOR type_id string length including NUL
            b'I', b'D', b'L', b':', b'Y', b':', b'1', b'.', b'0', 0, // type_id
            0, 0, // padding before profile sequence count
            0, 0, 0, 1, // profile count
            0, 0, 0, 0, // TAG_INTERNET_IOP
            0, 0, 0, 21, // profile_data length
            0,  // big-endian profile encapsulation
            1, 0, // IIOP version 1.0
            0, // padding before host string length
            0, 0, 0, 5, // host string length including NUL
            b'n', b'o', b'd', b'e', 0, // host
            0, // padding before port
            0x1f, 0x90, // port 8080
            0, 0, 0, 1,    // object key length
            0xef, // object key
        ])
        .expect("valid GIOP frame");

        let reply = read_reply_1_2(&frame).expect("valid GIOP 1.2 reply");

        let profiles = reply.forwarded_iiop_profiles().unwrap();

        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].host, "node");
        assert_eq!(profiles[0].port, 8080);
        assert_eq!(profiles[0].object_key, &[0xef]);
    }

    #[test]
    fn decodes_giop_1_2_reply_needs_addressing_mode_body() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 14, // GIOP header
            0, 0, 0, 42, // request_id
            0, 0, 0, 5, // NEEDS_ADDRESSING_MODE
            0, 0, 0, 0, // service context count
            0, 2, // AddressingDisposition body
        ])
        .expect("valid GIOP frame");

        let reply = read_reply_1_2(&frame).expect("valid GIOP 1.2 reply");

        assert_eq!(reply.status, ReplyStatus::NeedsAddressingMode);
        assert_eq!(reply.addressing_disposition().unwrap(), Some(2));
        assert_eq!(
            reply.reply_body().unwrap(),
            ParsedReplyBody12::NeedsAddressingMode(2)
        );
    }

    #[test]
    fn decodes_giop_1_2_reply_system_exception_body() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 36, // GIOP header
            0, 0, 0, 42, // request_id
            0, 0, 0, 2, // SYSTEM_EXCEPTION
            0, 0, 0, 0, // service context count
            0, 0, 0, 10, // exception_id string length including NUL
            b'I', b'D', b'L', b':', b'X', b':', b'1', b'.', b'0', 0, // exception_id
            0, 0, // padding before minor_code_value
            0, 0, 0, 42, // minor_code_value
            0, 0, 0, 1, // COMPLETED_NO
        ])
        .expect("valid GIOP frame");

        let reply = read_reply_1_2(&frame).expect("valid GIOP 1.2 reply");
        let system_exception = reply.system_exception().unwrap().expect("system exception");

        assert_eq!(reply.status, ReplyStatus::SystemException);
        assert_eq!(system_exception.exception_id, "IDL:X:1.0");
        assert_eq!(system_exception.minor_code, 42);
        assert_eq!(
            system_exception.completion_status,
            CompletionStatus::CompletedNo
        );
    }

    #[test]
    fn decodes_giop_1_2_reply_user_exception_body() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 28, // GIOP header
            0, 0, 0, 42, // request_id
            0, 0, 0, 1, // USER_EXCEPTION
            0, 0, 0, 0, // service context count
            0, 0, 0, 10, // exception_id string length including NUL
            b'I', b'D', b'L', b':', b'E', b':', b'1', b'.', b'0', 0, // exception_id
            0xaa, 0xbb, // encoded exception member payload
        ])
        .expect("valid GIOP frame");

        let reply = read_reply_1_2(&frame).expect("valid GIOP 1.2 reply");
        let user_exception = reply.user_exception().unwrap().expect("user exception");

        assert_eq!(reply.status, ReplyStatus::UserException);
        assert_eq!(user_exception.exception_id, "IDL:E:1.0");
        assert_eq!(user_exception.remaining, &[0xaa, 0xbb]);
        assert_eq!(
            reply.reply_body().unwrap(),
            ParsedReplyBody12::UserException(super::giop::UserExceptionBody {
                exception_id: "IDL:E:1.0".to_owned(),
                remaining: &[0xaa, 0xbb],
            })
        );
    }

    #[test]
    fn decodes_typed_giop_1_2_reply_system_exception_body() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 36, // GIOP header
            0, 0, 0, 42, // request_id
            0, 0, 0, 2, // SYSTEM_EXCEPTION
            0, 0, 0, 0, // service context count
            0, 0, 0, 10, // exception_id string length including NUL
            b'I', b'D', b'L', b':', b'X', b':', b'1', b'.', b'0', 0, // exception_id
            0, 0, // padding before minor_code_value
            0, 0, 0, 42, // minor_code_value
            0, 0, 0, 1, // COMPLETED_NO
        ])
        .expect("valid GIOP frame");
        let reply = read_reply_1_2(&frame).expect("valid GIOP 1.2 reply");

        assert_eq!(
            reply.reply_body().unwrap(),
            ParsedReplyBody12::SystemException(super::giop::SystemExceptionBody {
                exception_id: "IDL:X:1.0".to_owned(),
                minor_code: 42,
                completion_status: CompletionStatus::CompletedNo,
            })
        );
    }

    #[test]
    fn decodes_typed_giop_1_2_reply_location_forward_body() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 44, // GIOP header
            0, 0, 0, 42, // request_id
            0, 0, 0, 3, // LOCATION_FORWARD
            0, 0, 0, 0, // service context count
            0, 0, 0, 10, // IOR type_id string length including NUL
            b'I', b'D', b'L', b':', b'Y', b':', b'1', b'.', b'0', 0, // type_id
            0, 0, // padding before profile sequence count
            0, 0, 0, 1, // profile count
            0, 0, 0, 0, // TAG_INTERNET_IOP
            0, 0, 0, 4, // profile_data length
            0xaa, 0xbb, 0xcc, 0xdd, // profile_data
        ])
        .expect("valid GIOP frame");
        let reply = read_reply_1_2(&frame).expect("valid GIOP 1.2 reply");

        assert_eq!(
            reply.reply_body().unwrap(),
            ParsedReplyBody12::LocationForward(Ior {
                type_id: "IDL:Y:1.0".to_owned(),
                profiles: vec![TaggedProfile {
                    tag: 0,
                    profile_data: &[0xaa, 0xbb, 0xcc, 0xdd],
                }],
            })
        );
    }

    #[test]
    fn preserves_raw_typed_giop_1_2_reply_bodies() {
        let no_exception = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 13, // GIOP header
            0, 0, 0, 42, // request_id
            0, 0, 0, 0, // NO_EXCEPTION
            0, 0, 0, 0,    // service context count
            0xaa, // reply body
        ])
        .expect("valid GIOP frame");
        let unknown = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 14, // GIOP header
            0, 0, 0, 42, // request_id
            0, 0, 0, 99, // unknown reply status
            0, 0, 0, 0, // service context count
            0xbb, 0xcc, // reply body
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_reply_1_2(&no_exception).unwrap().reply_body().unwrap(),
            ParsedReplyBody12::NoException(&[0xaa])
        );
        assert_eq!(
            read_reply_1_2(&unknown).unwrap().reply_body().unwrap(),
            ParsedReplyBody12::Unknown {
                status: 99,
                body: &[0xbb, 0xcc],
            }
        );
    }

    #[test]
    fn maps_giop_1_2_reply_status_values() {
        let statuses = [
            (0, ReplyStatus::NoException),
            (1, ReplyStatus::UserException),
            (2, ReplyStatus::SystemException),
            (3, ReplyStatus::LocationForward),
            (4, ReplyStatus::LocationForwardPerm),
            (5, ReplyStatus::NeedsAddressingMode),
            (99, ReplyStatus::Unknown(99)),
        ];

        for (raw_status, expected_status) in statuses {
            let input = [
                b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 12, // GIOP header
                0, 0, 0, 42, // request_id
                0, 0, 0, raw_status, // reply_status
                0, 0, 0, 0, // service context count
            ];
            let frame = parse_message(&input).expect("valid GIOP frame");

            assert_eq!(read_reply_1_2(&frame).unwrap().status, expected_status);
        }
    }

    #[test]
    fn parses_giop_1_2_locate_request_header_with_key_addr_target() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 3, 0, 0, 0, 15, // GIOP header
            0, 0, 0, 77, // request_id
            0, 0, // KeyAddr discriminator
            0, 0, // padding before object key sequence length
            0, 0, 0, 3, // object key length
            0xab, 0xcd, 0xef, // object key
        ])
        .expect("valid GIOP frame");

        let request = read_locate_request_1_2(&frame).expect("valid GIOP 1.2 locate request");

        assert_eq!(request.request_id, 77);
        assert_eq!(request.target, TargetAddress::KeyAddr(&[0xab, 0xcd, 0xef]));
    }

    #[test]
    fn parses_giop_1_2_locate_request_header_with_reference_addr_target() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 3, 0, 0, 0, 42, // GIOP header
            0, 0, 0, 77, // request_id
            0, 2, // ReferenceAddr discriminator
            0, 0, // padding before selected_profile_index
            0, 0, 0, 1, // selected_profile_index
            0, 0, 0, 10, // IOR type_id string length including NUL
            b'I', b'D', b'L', b':', b'X', b':', b'1', b'.', b'0', 0, // type_id
            0, 0, // padding before profile sequence count
            0, 0, 0, 1, // profile count
            0, 0, 0, 123, // profile tag
            0, 0, 0, 2, // profile_data length
            0xde, 0xad, // profile_data
        ])
        .expect("valid GIOP frame");

        let request = read_locate_request_1_2(&frame).expect("valid GIOP 1.2 locate request");

        assert_eq!(request.request_id, 77);
        assert_eq!(
            request.target,
            TargetAddress::ReferenceAddr(IorAddressingInfo {
                selected_profile_index: 1,
                ior: Ior {
                    type_id: "IDL:X:1.0".to_owned(),
                    profiles: vec![TaggedProfile {
                        tag: 123,
                        profile_data: &[0xde, 0xad],
                    }],
                },
            })
        );
    }

    #[test]
    fn parses_iiop_1_0_profile_body_encapsulation() {
        let profile = read_iiop_profile_body(&[
            0, // big-endian encapsulation
            1, 0, // IIOP version 1.0
            0, // padding before host string length
            0, 0, 0, 10, // host string length including NUL
            b'l', b'o', b'c', b'a', b'l', b'h', b'o', b's', b't', 0, // host
            0x1f, 0x90, // port 8080
            0, 0, 0, 3, // object key length
            0xde, 0xad, 0xbe, // object key
        ])
        .expect("valid IIOP profile body");

        assert_eq!(profile.version, Version { major: 1, minor: 0 });
        assert_eq!(profile.host, "localhost");
        assert_eq!(profile.port, 8080);
        assert_eq!(profile.object_key, &[0xde, 0xad, 0xbe]);
        assert_eq!(profile.components, Vec::<TaggedComponent<'_>>::new());
        assert_eq!(profile.remaining, &[]);
    }

    #[test]
    fn parses_iiop_1_2_profile_body_components() {
        let profile = read_iiop_profile_body(&[
            1, // little-endian encapsulation
            1, 2, // IIOP version 1.2
            0, // padding before host string length
            5, 0, 0, 0, // host string length including NUL
            b'n', b'o', b'd', b'e', 0, // host
            0, // padding before port
            0x34, 0x12, // port 0x1234
            2, 0, 0, 0, // object key length
            0xde, 0xad, // object key
            0, 0, // padding before tagged component count
            1, 0, 0, 0, // tagged component count
            5, 0, 0, 0, // component tag
            1, 0, 0, 0,    // component_data length
            0xcc, // component_data
        ])
        .expect("valid IIOP profile body");

        assert_eq!(profile.version, Version { major: 1, minor: 2 });
        assert_eq!(profile.host, "node");
        assert_eq!(profile.port, 0x1234);
        assert_eq!(profile.object_key, &[0xde, 0xad]);
        assert_eq!(
            profile.components,
            vec![TaggedComponent {
                tag: 5,
                component_data: &[0xcc],
            }]
        );
        assert_eq!(profile.remaining, &[]);
    }

    #[test]
    fn tagged_profile_decodes_tag_internet_iop_profile_body() {
        let profile_data = [
            0, // big-endian encapsulation
            1, 0, // IIOP version 1.0
            0, // padding before host string length
            0, 0, 0, 5, // host string length including NUL
            b'h', b'o', b's', b't', 0, // host
            0, // padding before port
            0x12, 0x34, // port
            0, 0, 0, 2, // object key length
            0xab, 0xcd, // object key
        ];
        let tagged = TaggedProfile {
            tag: TAG_INTERNET_IOP,
            profile_data: &profile_data,
        };

        let profile = tagged.iiop_profile().unwrap().expect("internet profile");

        assert_eq!(profile.version, Version { major: 1, minor: 0 });
        assert_eq!(profile.host, "host");
        assert_eq!(profile.port, 0x1234);
        assert_eq!(profile.object_key, &[0xab, 0xcd]);
    }

    #[test]
    fn ior_extracts_only_tag_internet_iop_profiles() {
        let profile_data = [
            0, // big-endian encapsulation
            1, 0, // IIOP version 1.0
            0, // padding before host string length
            0, 0, 0, 5, // host string length including NUL
            b'n', b'o', b'd', b'e', 0, // host
            0, // padding before port
            0x1f, 0x90, // port 8080
            0, 0, 0, 1,    // object key length
            0xef, // object key
        ];
        let ior = Ior {
            type_id: "IDL:Node:1.0".to_owned(),
            profiles: vec![
                TaggedProfile {
                    tag: 99,
                    profile_data: &[0x00, 0x01],
                },
                TaggedProfile {
                    tag: TAG_INTERNET_IOP,
                    profile_data: &profile_data,
                },
            ],
        };

        let profiles = ior.iiop_profiles().unwrap();

        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].host, "node");
        assert_eq!(profiles[0].port, 8080);
        assert_eq!(profiles[0].object_key, &[0xef]);
    }

    #[test]
    fn parses_giop_1_2_locate_reply_header_and_body() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 4, 0, 0, 0, 10, // GIOP header
            0, 0, 0, 77, // request_id
            0, 0, 0, 5, // LOC_NEEDS_ADDRESSING_MODE
            0, 2, // AddressingDisposition body
        ])
        .expect("valid GIOP frame");

        let reply = read_locate_reply_1_2(&frame).expect("valid GIOP 1.2 locate reply");

        assert_eq!(reply.request_id, 77);
        assert_eq!(reply.status, LocateStatus::NeedsAddressingMode);
        assert_eq!(reply.body, &[0, 2]);
        assert_eq!(reply.forwarded_ior().unwrap(), None);
        assert_eq!(reply.forwarded_iiop_profiles().unwrap(), Vec::new());
        assert_eq!(reply.addressing_disposition().unwrap(), Some(2));
        assert_eq!(
            reply.reply_body().unwrap(),
            ParsedLocateReplyBody12::NeedsAddressingMode(2)
        );

        let mut body = reply.body_reader();
        assert_eq!(body.read_i16().unwrap(), 2);
        assert_eq!(body.position(), 2);
    }

    #[test]
    fn decodes_giop_1_2_locate_reply_object_forward_ior_body() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 4, 0, 0, 0, 38, // GIOP header
            0, 0, 0, 77, // request_id
            0, 0, 0, 2, // OBJECT_FORWARD
            0, 0, 0, 10, // IOR type_id string length including NUL
            b'I', b'D', b'L', b':', b'Z', b':', b'1', b'.', b'0', 0, // type_id
            0, 0, // padding before profile sequence count
            0, 0, 0, 1, // profile count
            0, 0, 0, 1, // profile tag
            0, 0, 0, 2, // profile_data length
            0x01, 0x02, // profile_data
        ])
        .expect("valid GIOP frame");

        let reply = read_locate_reply_1_2(&frame).expect("valid GIOP 1.2 locate reply");

        assert_eq!(reply.status, LocateStatus::ObjectForward);
        assert_eq!(
            reply.forwarded_ior().unwrap(),
            Some(Ior {
                type_id: "IDL:Z:1.0".to_owned(),
                profiles: vec![TaggedProfile {
                    tag: 1,
                    profile_data: &[0x01, 0x02],
                }],
            })
        );
        assert_eq!(
            reply.reply_body().unwrap(),
            ParsedLocateReplyBody12::ObjectForward(Ior {
                type_id: "IDL:Z:1.0".to_owned(),
                profiles: vec![TaggedProfile {
                    tag: 1,
                    profile_data: &[0x01, 0x02],
                }],
            })
        );
    }

    #[test]
    fn decodes_giop_1_2_locate_reply_object_forward_iiop_profiles() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 4, 0, 0, 0, 57, // GIOP header
            0, 0, 0, 77, // request_id
            0, 0, 0, 2, // OBJECT_FORWARD
            0, 0, 0, 10, // IOR type_id string length including NUL
            b'I', b'D', b'L', b':', b'Z', b':', b'1', b'.', b'0', 0, // type_id
            0, 0, // padding before profile sequence count
            0, 0, 0, 1, // profile count
            0, 0, 0, 0, // TAG_INTERNET_IOP
            0, 0, 0, 21, // profile_data length
            0,  // big-endian profile encapsulation
            1, 0, // IIOP version 1.0
            0, // padding before host string length
            0, 0, 0, 5, // host string length including NUL
            b'e', b'd', b'g', b'e', 0, // host
            0, // padding before port
            0x23, 0x82, // port 9090
            0, 0, 0, 1,    // object key length
            0xcd, // object key
        ])
        .expect("valid GIOP frame");

        let reply = read_locate_reply_1_2(&frame).expect("valid GIOP 1.2 locate reply");

        let profiles = reply.forwarded_iiop_profiles().unwrap();

        assert_eq!(profiles.len(), 1);
        assert_eq!(profiles[0].host, "edge");
        assert_eq!(profiles[0].port, 9090);
        assert_eq!(profiles[0].object_key, &[0xcd]);
    }

    #[test]
    fn decodes_giop_1_2_locate_reply_system_exception_body() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 4, 0, 0, 0, 32, // GIOP header
            0, 0, 0, 77, // request_id
            0, 0, 0, 4, // LOC_SYSTEM_EXCEPTION
            0, 0, 0, 10, // exception_id string length including NUL
            b'I', b'D', b'L', b':', b'Z', b':', b'1', b'.', b'0', 0, // exception_id
            0, 0, // padding before minor_code_value
            0, 0, 0, 7, // minor_code_value
            0, 0, 0, 2, // COMPLETED_MAYBE
        ])
        .expect("valid GIOP frame");

        let reply = read_locate_reply_1_2(&frame).expect("valid GIOP 1.2 locate reply");
        let system_exception = reply.system_exception().unwrap().expect("system exception");

        assert_eq!(reply.status, LocateStatus::SystemException);
        assert_eq!(system_exception.exception_id, "IDL:Z:1.0");
        assert_eq!(system_exception.minor_code, 7);
        assert_eq!(
            system_exception.completion_status,
            CompletionStatus::CompletedMaybe
        );
        assert_eq!(
            reply.reply_body().unwrap(),
            ParsedLocateReplyBody12::SystemException(super::giop::SystemExceptionBody {
                exception_id: "IDL:Z:1.0".to_owned(),
                minor_code: 7,
                completion_status: CompletionStatus::CompletedMaybe,
            })
        );
    }

    #[test]
    fn preserves_raw_typed_giop_1_2_locate_reply_bodies() {
        let object_here = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 4, 0, 0, 0, 9, // GIOP header
            0, 0, 0, 77, // request_id
            0, 0, 0, 1,    // OBJECT_HERE
            0xaa, // unexpected body bytes preserved
        ])
        .expect("valid GIOP frame");
        let unknown = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 4, 0, 0, 0, 10, // GIOP header
            0, 0, 0, 77, // request_id
            0, 0, 0, 99, // unknown locate status
            0xbb, 0xcc, // reply body
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_locate_reply_1_2(&object_here)
                .unwrap()
                .reply_body()
                .unwrap(),
            ParsedLocateReplyBody12::ObjectHere(&[0xaa])
        );
        assert_eq!(
            read_locate_reply_1_2(&unknown)
                .unwrap()
                .reply_body()
                .unwrap(),
            ParsedLocateReplyBody12::Unknown {
                status: 99,
                body: &[0xbb, 0xcc],
            }
        );
    }

    #[test]
    fn maps_giop_1_2_locate_status_values() {
        let statuses = [
            (0, LocateStatus::UnknownObject),
            (1, LocateStatus::ObjectHere),
            (2, LocateStatus::ObjectForward),
            (3, LocateStatus::ObjectForwardPerm),
            (4, LocateStatus::SystemException),
            (5, LocateStatus::NeedsAddressingMode),
            (99, LocateStatus::Unknown(99)),
        ];

        for (raw_status, expected_status) in statuses {
            let input = [
                b'G', b'I', b'O', b'P', 1, 2, 0, 4, 0, 0, 0, 8, // GIOP header
                0, 0, 0, 77, // request_id
                0, 0, 0, raw_status, // locate_status
            ];
            let frame = parse_message(&input).expect("valid GIOP frame");

            assert_eq!(
                read_locate_reply_1_2(&frame).unwrap().status,
                expected_status
            );
        }
    }

    #[test]
    fn parses_giop_cancel_request_header() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 2, 0, 0, 0, 4, // GIOP header
            0, 0, 0, 77, // request_id
        ])
        .expect("valid GIOP frame");

        let cancel = read_cancel_request(&frame).expect("valid GIOP cancel request");

        assert_eq!(cancel.request_id, 77);
    }

    #[test]
    fn dispatches_giop_1_2_cancel_request_message() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 2, 0, 0, 0, 4, // GIOP header
            0, 0, 0, 77, // request_id
        ])
        .expect("valid GIOP frame");

        let message = read_message_1_2(&frame).expect("valid GIOP 1.2 message");

        assert_eq!(
            message,
            ParsedGiop12::CancelRequest(super::giop::ParsedCancelRequest { request_id: 77 })
        );
    }

    #[test]
    fn dispatches_giop_1_2_message_error_control_message() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 6, 0, 0, 0, 0, // MessageError
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_message_1_2(&frame).unwrap(),
            ParsedGiop12::MessageError
        );
    }

    #[test]
    fn parses_and_dispatches_giop_1_2_message_frame() {
        let parsed = parse_message_1_2(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 2, 0, 0, 0, 4, // GIOP header
            0, 0, 0, 77,   // request_id
            0xff, // remaining byte after this frame
        ])
        .expect("valid GIOP 1.2 message");

        assert_eq!(
            parsed,
            ParsedGiop12Message {
                header: MessageHeader {
                    version: Version { major: 1, minor: 2 },
                    endian: Endianness::Big,
                    fragmented: false,
                    message_type: MessageType::CancelRequest,
                    body_len: 4,
                },
                message: ParsedGiop12::CancelRequest(super::giop::ParsedCancelRequest {
                    request_id: 77,
                }),
                remaining: &[0xff],
            }
        );
    }

    #[test]
    fn rejects_non_giop_1_2_for_parse_and_dispatch() {
        assert_eq!(
            parse_message_1_2(&[
                b'G', b'I', b'O', b'P', 1, 1, 0, 6, 0, 0, 0, 0, // GIOP 1.1 MessageError
            ])
            .unwrap_err(),
            GiopError::UnsupportedVersion(Version { major: 1, minor: 1 })
        );
    }

    #[test]
    fn iterates_giop_1_2_message_frames() {
        let input = [
            b'G', b'I', b'O', b'P', 1, 2, 0, 2, 0, 0, 0, 4, // CancelRequest
            0, 0, 0, 77, // request_id
            b'G', b'I', b'O', b'P', 1, 2, 0, 6, 0, 0, 0, 0, // MessageError
        ];

        let messages = parse_messages_1_2(&input)
            .collect::<Result<Vec<_>, _>>()
            .expect("valid GIOP 1.2 messages");

        assert_eq!(messages.len(), 2);
        assert_eq!(
            messages[0].message,
            ParsedGiop12::CancelRequest(super::giop::ParsedCancelRequest { request_id: 77 })
        );
        assert_eq!(messages[0].remaining, &input[16..]);
        assert_eq!(messages[1].message, ParsedGiop12::MessageError);
        assert_eq!(messages[1].remaining, &[]);
    }

    #[test]
    fn stops_giop_1_2_message_iteration_after_error() {
        let mut messages = parse_messages_1_2(b"bad");

        assert_eq!(
            messages.next().unwrap().unwrap_err(),
            GiopError::TruncatedHeader { len: 3 }
        );
        assert!(messages.next().is_none());
    }

    #[test]
    fn rejects_unknown_giop_1_2_message_type_for_dispatch() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 99, 0, 0, 0, 0, // unknown message type
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_message_1_2(&frame).unwrap_err(),
            GiopError::UnsupportedMessageType(MessageType::Unknown(99))
        );
    }

    #[test]
    fn parses_giop_1_2_fragment_header_and_data() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 7, 0, 0, 0, 8, // GIOP header
            0, 0, 0, 77, // request_id
            0x01, 0x02, 0x03, 0x04, // fragment data
        ])
        .expect("valid GIOP frame");

        let fragment = read_fragment_1_2(&frame).expect("valid GIOP 1.2 fragment");

        assert_eq!(fragment.request_id, 77);
        assert_eq!(fragment.data, &[0x01, 0x02, 0x03, 0x04]);

        let mut data = fragment.data_reader();
        assert_eq!(data.read_u32().unwrap(), 0x0102_0304);
        assert_eq!(data.position(), 4);
    }

    #[test]
    fn reassembles_fragmented_giop_1_2_request_body() {
        let input = [
            b'G', b'I', b'O', b'P', 1, 2, 0x02, 0, 0, 0, 0, 6, // fragmented Request
            0, 0, 0, 77, // request_id
            0xaa, 0xbb, // initial body bytes
            b'G', b'I', b'O', b'P', 1, 2, 0, 7, 0, 0, 0, 7, // final Fragment
            0, 0, 0, 77, // request_id
            0xcc, 0xdd, 0xee, // fragment data bytes
        ];

        let messages = reassemble_messages_1_2(&input).expect("fragments reassemble");

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].header.message_type, MessageType::Request);
        assert_eq!(messages[0].header.body_len, 9);
        assert!(!messages[0].header.fragmented);
        assert_eq!(
            messages[0].body,
            vec![0, 0, 0, 77, 0xaa, 0xbb, 0xcc, 0xdd, 0xee]
        );
        assert_eq!(messages[0].frame_ranges.len(), 2);
        assert_eq!(messages[0].frame_ranges[0].offset, 0);
        assert_eq!(messages[0].frame_ranges[1].offset, 18);
    }

    #[test]
    fn reassembly_passes_through_non_fragmented_messages() {
        let input = [
            b'G', b'I', b'O', b'P', 1, 2, 0, 2, 0, 0, 0, 4, // CancelRequest
            0, 0, 0, 77, // request_id
        ];

        let messages = reassemble_messages_1_2(&input).expect("message reassembles");

        assert_eq!(messages.len(), 1);
        assert_eq!(messages[0].header.message_type, MessageType::CancelRequest);
        assert_eq!(messages[0].body, vec![0, 0, 0, 77]);
        assert_eq!(messages[0].frame_ranges.len(), 1);
        assert_eq!(messages[0].frame_ranges[0].len, input.len());
    }

    #[test]
    fn reassembly_rejects_fragment_without_initial_message() {
        let input = [
            b'G', b'I', b'O', b'P', 1, 2, 0, 7, 0, 0, 0, 5, // Fragment
            0, 0, 0, 77,   // request_id
            0xaa, // fragment data
        ];

        assert_eq!(
            reassemble_messages_1_2(&input).unwrap_err(),
            GiopReassemblyError::FragmentWithoutInitial {
                request_id: 77,
                offset: 0,
            }
        );
    }

    #[test]
    fn reassembly_rejects_duplicate_initial_fragmented_message() {
        let input = [
            b'G', b'I', b'O', b'P', 1, 2, 0x02, 0, 0, 0, 0, 4, // fragmented Request
            0, 0, 0, 77, // request_id
            b'G', b'I', b'O', b'P', 1, 2, 0x02, 0, 0, 0, 0, 4, // another fragmented Request
            0, 0, 0, 77, // request_id
        ];

        assert_eq!(
            reassemble_messages_1_2(&input).unwrap_err(),
            GiopReassemblyError::DuplicateInitial {
                request_id: 77,
                offset: 16,
            }
        );
    }

    #[test]
    fn reassembly_rejects_unfinished_fragmented_message() {
        let input = [
            b'G', b'I', b'O', b'P', 1, 2, 0x02, 0, 0, 0, 0, 4, // fragmented Request
            0, 0, 0, 77, // request_id
        ];

        assert_eq!(
            reassemble_messages_1_2(&input).unwrap_err(),
            GiopReassemblyError::UnfinishedFragmentedMessage { request_id: 77 }
        );
    }

    #[test]
    fn rejects_non_request_messages_for_request_header_decoding() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 0, // Reply message
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_request_1_2(&frame).unwrap_err(),
            GiopError::UnexpectedMessageType {
                expected: MessageType::Request,
                actual: MessageType::Reply,
            }
        );
    }

    #[test]
    fn rejects_non_reply_messages_for_reply_header_decoding() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 0, 0, 0, 0, 0, // Request message
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_reply_1_2(&frame).unwrap_err(),
            GiopError::UnexpectedMessageType {
                expected: MessageType::Reply,
                actual: MessageType::Request,
            }
        );
    }

    #[test]
    fn rejects_non_locate_request_messages_for_locate_request_decoding() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 0, 0, 0, 0, 0, // Request message
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_locate_request_1_2(&frame).unwrap_err(),
            GiopError::UnexpectedMessageType {
                expected: MessageType::LocateRequest,
                actual: MessageType::Request,
            }
        );
    }

    #[test]
    fn rejects_non_locate_reply_messages_for_locate_reply_decoding() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 0, // Reply message
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_locate_reply_1_2(&frame).unwrap_err(),
            GiopError::UnexpectedMessageType {
                expected: MessageType::LocateReply,
                actual: MessageType::Reply,
            }
        );
    }

    #[test]
    fn rejects_non_cancel_request_messages_for_cancel_request_decoding() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 0, 0, 0, 0, 0, // Request message
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_cancel_request(&frame).unwrap_err(),
            GiopError::UnexpectedMessageType {
                expected: MessageType::CancelRequest,
                actual: MessageType::Request,
            }
        );
    }

    #[test]
    fn rejects_non_fragment_messages_for_fragment_decoding() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 1, 0, 0, 0, 0, // Reply message
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_fragment_1_2(&frame).unwrap_err(),
            GiopError::UnexpectedMessageType {
                expected: MessageType::Fragment,
                actual: MessageType::Reply,
            }
        );
    }

    #[test]
    fn rejects_non_giop_1_2_request_headers() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 1, 0, 0, 0, 0, 0, 0, // Request message
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_request_1_2(&frame).unwrap_err(),
            GiopError::UnsupportedVersion(super::giop::Version { major: 1, minor: 1 })
        );
    }

    #[test]
    fn rejects_non_giop_1_2_reply_headers() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 1, 0, 1, 0, 0, 0, 0, // Reply message
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_reply_1_2(&frame).unwrap_err(),
            GiopError::UnsupportedVersion(super::giop::Version { major: 1, minor: 1 })
        );
    }

    #[test]
    fn rejects_non_giop_1_2_locate_request_headers() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 1, 0, 3, 0, 0, 0, 0, // LocateRequest message
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_locate_request_1_2(&frame).unwrap_err(),
            GiopError::UnsupportedVersion(super::giop::Version { major: 1, minor: 1 })
        );
    }

    #[test]
    fn rejects_non_giop_1_2_locate_reply_headers() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 1, 0, 4, 0, 0, 0, 0, // LocateReply message
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_locate_reply_1_2(&frame).unwrap_err(),
            GiopError::UnsupportedVersion(super::giop::Version { major: 1, minor: 1 })
        );
    }

    #[test]
    fn rejects_non_giop_1_2_fragment_headers() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 1, 0, 7, 0, 0, 0, 0, // Fragment message
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_fragment_1_2(&frame).unwrap_err(),
            GiopError::UnsupportedVersion(super::giop::Version { major: 1, minor: 1 })
        );
    }

    #[test]
    fn rejects_nonzero_giop_1_2_request_reserved_bytes() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 0, 0, 0, 0, 12, // GIOP header
            0, 0, 0, 1, // request_id
            0, // response_flags
            0, 1, 0, // reserved
            0, 0, 0, 0, // trailing bytes are not reached
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_request_1_2(&frame).unwrap_err(),
            GiopError::InvalidRequestReserved {
                offset: 5,
                reserved: [0, 1, 0],
            }
        );
    }

    #[test]
    fn rejects_unknown_giop_1_2_target_address_dispositions() {
        let frame = parse_message(&[
            b'G', b'I', b'O', b'P', 1, 2, 0, 0, 0, 0, 0, 10, // GIOP header
            0, 0, 0, 1, // request_id
            0, // response_flags
            0, 0, 0, // reserved
            0, 9, // unknown target address discriminator
        ])
        .expect("valid GIOP frame");

        assert_eq!(
            read_request_1_2(&frame).unwrap_err(),
            GiopError::UnsupportedTargetAddress { disposition: 9 }
        );
    }

    #[test]
    fn rejects_service_context_counts_that_cannot_fit_remaining_bytes() {
        let mut no_contexts = CdrReader::new(&[0xff, 0xff, 0xff, 0xff], Endianness::Big);
        assert_eq!(
            read_service_context_list(&mut no_contexts).unwrap_err(),
            CdrError::SequenceLengthExceedsRemaining {
                offset: 0,
                declared: u32::MAX,
                remaining: 0,
                element_min_size: 8,
            }
        );

        let mut partial_context =
            CdrReader::new(&[0xff, 0xff, 0xff, 0xff, 0, 0, 0, 1], Endianness::Big);
        assert_eq!(
            read_service_context_list(&mut partial_context).unwrap_err(),
            CdrError::SequenceLengthExceedsRemaining {
                offset: 0,
                declared: u32::MAX,
                remaining: 4,
                element_min_size: 8,
            }
        );
    }

    #[test]
    fn cdr_reader_rejects_non_nul_terminated_string() {
        let mut reader = CdrReader::new(&[0, 0, 0, 4, b'a', b'b', b'c', b'd'], Endianness::Big);

        assert_eq!(
            reader.read_string().unwrap_err(),
            CdrError::InvalidStringTerminator { offset: 7 }
        );
    }

    #[test]
    fn cdr_reader_rejects_truncated_alignment_padding() {
        let mut reader = CdrReader::new(&[0xaa, 0xbb], Endianness::Little);

        assert_eq!(reader.read_octet().unwrap(), 0xaa);
        assert_eq!(
            reader.read_u32().unwrap_err(),
            CdrError::UnexpectedEof {
                offset: 1,
                needed: 4,
                remaining: 1,
            }
        );
    }

    fn giop_1_2_request_bytes(operation: &str, arguments: &[u8]) -> Vec<u8> {
        const HEADER_LEN: usize = 12;

        let mut body = Vec::new();
        body.extend_from_slice(&42_u32.to_be_bytes());
        body.push(0x03);
        body.extend_from_slice(&[0, 0, 0]);
        body.extend_from_slice(&0_i16.to_be_bytes());
        pad_body_to(&mut body, 4, HEADER_LEN);
        body.extend_from_slice(&1_u32.to_be_bytes());
        body.push(0xaa);
        pad_body_to(&mut body, 4, HEADER_LEN);
        body.extend_from_slice(&((operation.len() + 1) as u32).to_be_bytes());
        body.extend_from_slice(operation.as_bytes());
        body.push(0);
        pad_body_to(&mut body, 4, HEADER_LEN);
        body.extend_from_slice(&0_u32.to_be_bytes());
        if !arguments.is_empty() {
            pad_body_to(&mut body, 8, HEADER_LEN);
            body.extend_from_slice(arguments);
        }

        let mut frame = Vec::new();
        frame.extend_from_slice(b"GIOP");
        frame.extend_from_slice(&[1, 2, 0, 0]);
        frame.extend_from_slice(&(body.len() as u32).to_be_bytes());
        frame.extend_from_slice(&body);
        frame
    }

    fn pad_body_to(body: &mut Vec<u8>, alignment: usize, header_len: usize) {
        while !(header_len + body.len()).is_multiple_of(alignment) {
            body.push(0);
        }
    }
}
