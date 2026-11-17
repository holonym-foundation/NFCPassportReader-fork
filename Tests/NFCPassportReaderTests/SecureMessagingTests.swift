//
//  SecureMessagingTests.swift
//  NFCPassportReaderTests
//
//  Secure messaging (ICAO 9303-11 section 9.8) against published and cross-checked
//  vectors, and the ways a response must be refused.
//

import XCTest
import CoreNFC

@testable import NFCPassportReader

private struct Exchange {
    let plainCommand: [UInt8]
    let protectedCommand: [UInt8]
    /// DO'87' / DO'99' / DO'8E' as the chip sent them, without the trailing status word.
    let protectedResponse: [UInt8]
    let sw1: UInt8
    let sw2: UInt8
    let plainResponse: [UInt8]

    var response: ResponseAPDU { ResponseAPDU(data: protectedResponse, sw1: sw1, sw2: sw2) }
}

private struct Session {
    let algorithm: SecureMessagingSupportedAlgorithms
    let ksEnc: [UInt8]
    let ksMac: [UInt8]
    let initialSSC: UInt64
    var exchanges: [Exchange] = []

    var name: String { "\(algorithm == .AES ? "AES" : "3DES")-\(ksEnc.count * 8) SSC \(String(initialSSC, radix: 16))" }

    /// A session positioned just before exchange `index`'s response (its command already sent).
    func secureMessaging(beforeResponse index: Int, ksMac: [UInt8]? = nil, sscOffset: UInt64 = 0) -> SecureMessaging {
        let ssc = initialSSC + UInt64(2 * index + 1) + sscOffset
        return SecureMessaging(
            encryptionAlgorithm: algorithm,
            ksenc: ksEnc,
            ksmac: ksMac ?? self.ksMac,
            ssc: withUnsafeBytes(of: ssc.bigEndian, Array.init)
        )
    }
}

private func parseSessions(_ text: String) -> [Session] {
    var sessions: [Session] = []
    for line in text.split(separator: "\n") {
        let fields = line.split(separator: " ").map(String.init)
        if fields[0] == "S" {
            sessions.append(Session(
                algorithm: fields[1] == "aes" ? .AES : .DES,
                ksEnc: hexRepToBin(fields[2]),
                ksMac: hexRepToBin(fields[3]),
                initialSSC: UInt64(fields[4], radix: 16)!
            ))
        } else {
            let response = hexRepToBin(fields[3])
            sessions[sessions.count - 1].exchanges.append(Exchange(
                plainCommand: fields[1] == "-" ? [] : hexRepToBin(fields[1]),
                protectedCommand: hexRepToBin(fields[2]),
                protectedResponse: [UInt8](response.dropLast(2)),
                sw1: response[response.count - 2],
                sw2: response[response.count - 1],
                plainResponse: fields[4] == "-" ? [] : hexRepToBin(fields[4])
            ))
        }
    }
    return sessions
}

/// Builds a command APDU from its bytes with the response length stated explicitly, as the
/// reader's own commands are built. (`NFCISO7816APDU(data:)` reports no response length for
/// a command that carries both data and Le.)
private func commandAPDU(_ bytes: [UInt8]) -> NFCISO7816APDU {
    var data: [UInt8] = []
    var le = -1
    if bytes.count == 5 {
        le = bytes[4] == 0 ? 256 : Int(bytes[4])
    } else if bytes.count > 5, bytes[4] != 0 {
        let lc = Int(bytes[4])
        data = [UInt8](bytes[5 ..< 5 + lc])
        if bytes.count == 5 + lc + 1 {
            le = bytes[5 + lc] == 0 ? 256 : Int(bytes[5 + lc])
        }
    } else if bytes.count > 7 {
        let lc = Int(bytes[5]) << 8 | Int(bytes[6])
        data = [UInt8](bytes[7 ..< 7 + lc])
        if bytes.count == 7 + lc + 2 {
            let value = Int(bytes[7 + lc]) << 8 | Int(bytes[8 + lc])
            le = value == 0 ? 65536 : value
        }
    }
    return NFCISO7816APDU(
        instructionClass: bytes[0], instructionCode: bytes[1], p1Parameter: bytes[2], p2Parameter: bytes[3],
        data: Data(data), expectedResponseLength: le
    )
}

/// The fields of a command APDU, for comparing a protected command with the expected bytes.
private func describe(_ apdu: NFCISO7816APDU) -> String {
    let header = [apdu.instructionClass, apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter]
    return "\(binToHexRep(header)) \(binToHexRep([UInt8](apdu.data ?? Data()))) Le=\(apdu.expectedResponseLength)"
}

private func assertThrows(
    _ expected: NFCPassportReaderError,
    _ message: String = "",
    file: StaticString = #filePath,
    line: UInt = #line,
    _ expression: () throws -> ResponseAPDU
) {
    do {
        let response = try expression()
        XCTFail(
            "accepted (sw \(binToHexRep([response.sw1, response.sw2])), \(response.data.count) data bytes), expected \(expected.value). \(message)",
            file: file, line: line
        )
    } catch let error as NFCPassportReaderError {
        XCTAssertEqual(error.value, expected.value, message, file: file, line: line)
    } catch {
        XCTFail("unexpected error \(error). \(message)", file: file, line: line)
    }
}

final class SecureMessagingTests: XCTestCase {

    private lazy var bsiSessions = parseSessions(bsiWorkedExampleSessions)
    private lazy var jmrtdSessions = parseSessions(jmrtdCrossCheckedSessions)
    private var allSessions: [Session] { bsiSessions + jmrtdSessions }

    // MARK: - The MAC primitive

    /// AES-CMAC, RFC 4493 section 4 / NIST SP 800-38B appendix D.1 examples (AES-128).
    func testAESCMACPublishedExamples() {
        let key = hexRepToBin("2B7E151628AED2A6ABF7158809CF4F3C")
        let message = hexRepToBin(
            "6BC1BEE22E409F96E93D7E117393172AAE2D8A571E03AC9C9EB76FAC45AF8E51"
                + "30C81C46A35CE411E5FBC1191A0A52EFF69F2445DF4F9B17AD2B417BE66C3710"
        )
        let expected: [(Int, String)] = [
            (0, "BB1D6929E95937287FA37D129B756746"),
            (16, "070A16B46B4D4144F79BDD9DD04A287C"),
            (40, "DFA66747DE9AE63030CA32611497C827"),
            (64, "51F0BEBF7E3B9D92FC49741779363CFE"),
        ]
        for (length, mac) in expected {
            XCTAssertEqual(binToHexRep(aesMAC(key: key, msg: [UInt8](message[0..<length]))), mac, "message length \(length)")
        }
    }

    // MARK: - Whole sessions

    func testVectorSetsAreComplete() {
        XCTAssertEqual(bsiSessions.count, 4)
        XCTAssertEqual(bsiSessions.map { $0.exchanges.count }, [21, 4, 21, 4])
        XCTAssertEqual(jmrtdSessions.count, 12)
        XCTAssertEqual(Set(jmrtdSessions.map { "\($0.algorithm == .AES ? "AES" : "3DES")-\($0.ksEnc.count)" }),
                       ["3DES-16", "AES-16", "AES-24", "AES-32"])
        XCTAssertTrue(jmrtdSessions.allSatisfy { $0.exchanges.count == 7 })
    }

    /// Runs each session from its first command, so the send sequence counter is carried
    /// through every command and response as it is on a chip.
    private func replay(_ sessions: [Session], file: StaticString = #filePath, line: UInt = #line) throws {
        for session in sessions {
            let sm = SecureMessaging(
                encryptionAlgorithm: session.algorithm,
                ksenc: session.ksEnc,
                ksmac: session.ksMac,
                ssc: withUnsafeBytes(of: session.initialSSC.bigEndian, Array.init)
            )
            for (index, exchange) in session.exchanges.enumerated() {
                let context = "\(session.name) exchange \(index)"
                let protected = try sm.protect(apdu: commandAPDU(exchange.plainCommand))
                let expected = try XCTUnwrap(NFCISO7816APDU(data: Data(exchange.protectedCommand)), context, file: file, line: line)
                XCTAssertEqual(describe(protected), describe(expected), "command, \(context)", file: file, line: line)

                let response = try sm.unprotect(rapdu: exchange.response)
                XCTAssertEqual(binToHexRep(response.data), binToHexRep(exchange.plainResponse), "response data, \(context)", file: file, line: line)
                XCTAssertEqual([response.sw1, response.sw2], [0x90, 0x00], "status, \(context)", file: file, line: line)
            }
        }
    }

    /// BSI TR-03110 EAC2 worked example: AES-128 after PACE and after Chip Authentication.
    func testBSIWorkedExampleSessions() throws {
        try replay(bsiSessions)
    }

    /// 3DES and AES-128/192/256, cross-checked against JMRTD.
    func testJMRTDCrossCheckedSessions() throws {
        try replay(jmrtdSessions)
    }

    // MARK: - Responses that must be refused

    /// Every single-bit change to the checksum is refused, in every vector.
    func testTamperedChecksumIsRefused() {
        for session in allSessions {
            for (index, exchange) in session.exchanges.enumerated() {
                let macStart = exchange.protectedResponse.count - 8
                for position in macStart..<exchange.protectedResponse.count {
                    var tampered = exchange.protectedResponse
                    tampered[position] ^= 0x01
                    assertThrows(.InvalidResponseChecksum, "\(session.name) exchange \(index) MAC byte \(position - macStart)") {
                        try session.secureMessaging(beforeResponse: index)
                            .unprotect(rapdu: ResponseAPDU(data: tampered, sw1: 0x90, sw2: 0x00))
                    }
                }
            }
        }
    }

    /// A changed cryptogram (DO'87') is refused, in every vector that carries data.
    func testTamperedCryptogramIsRefused() {
        var checked = 0
        for session in allSessions {
            for (index, exchange) in session.exchanges.enumerated() where exchange.protectedResponse[0] == 0x87 {
                // The last cryptogram byte sits just before DO'99' (4 bytes) and DO'8E' (10 bytes).
                // Seven bytes before it is still inside the last cipher block for 3DES and AES.
                for position in [exchange.protectedResponse.count - 15, exchange.protectedResponse.count - 15 - 7] {
                    var tampered = exchange.protectedResponse
                    tampered[position] ^= 0x80
                    assertThrows(.InvalidResponseChecksum, "\(session.name) exchange \(index) byte \(position)") {
                        try session.secureMessaging(beforeResponse: index)
                            .unprotect(rapdu: ResponseAPDU(data: tampered, sw1: 0x90, sw2: 0x00))
                    }
                    checked += 1
                }
            }
        }
        XCTAssertGreaterThan(checked, 100)
    }

    /// A changed protected status word (DO'99') is refused, in every vector.
    func testTamperedStatusObjectIsRefused() {
        for session in allSessions {
            for (index, exchange) in session.exchanges.enumerated() {
                var tampered = exchange.protectedResponse
                // DO'99' is the four bytes before DO'8E'; its last byte is SW2.
                tampered[tampered.count - 11] ^= 0x01
                assertThrows(.InvalidResponseChecksum, "\(session.name) exchange \(index)") {
                    try session.secureMessaging(beforeResponse: index)
                        .unprotect(rapdu: ResponseAPDU(data: tampered, sw1: 0x90, sw2: 0x00))
                }
            }
        }
    }

    /// A response checked under the wrong counter or the wrong MAC key is refused.
    func testWrongCounterOrKeyIsRefused() {
        for session in allSessions {
            for (index, exchange) in session.exchanges.enumerated() {
                for offset: UInt64 in [1, 2] {
                    assertThrows(.InvalidResponseChecksum, "\(session.name) exchange \(index) SSC +\(offset)") {
                        try session.secureMessaging(beforeResponse: index, sscOffset: offset).unprotect(rapdu: exchange.response)
                    }
                }
                var otherKey = session.ksMac
                otherKey[otherKey.count - 1] ^= 0x10
                assertThrows(.InvalidResponseChecksum, "\(session.name) exchange \(index) wrong key") {
                    try session.secureMessaging(beforeResponse: index, ksMac: otherKey).unprotect(rapdu: exchange.response)
                }
            }
        }
    }

    /// A response replayed from an earlier exchange in the same session is refused.
    func testReplayedResponseIsRefused() {
        for session in allSessions {
            for index in 1..<session.exchanges.count {
                assertThrows(.InvalidResponseChecksum, "\(session.name) exchange \(index)") {
                    try session.secureMessaging(beforeResponse: index).unprotect(rapdu: session.exchanges[index - 1].response)
                }
            }
        }
    }

    /// DO'8E' is mandatory: a response without it, or with a short one, is refused.
    func testMissingOrShortChecksumIsRefused() {
        for session in allSessions {
            for (index, exchange) in session.exchanges.enumerated() {
                let withoutChecksum = [UInt8](exchange.protectedResponse.dropLast(10))
                assertThrows(.MissingMandatoryFields, "\(session.name) exchange \(index) no DO'8E'") {
                    try session.secureMessaging(beforeResponse: index)
                        .unprotect(rapdu: ResponseAPDU(data: withoutChecksum, sw1: 0x90, sw2: 0x00))
                }
                for length in [0, 1, 4, 7] {
                    let mac = exchange.protectedResponse.suffix(8).prefix(length)
                    let shortChecksum = withoutChecksum + [0x8E, UInt8(length)] + mac
                    assertThrows(.MissingMandatoryFields, "\(session.name) exchange \(index) \(length)-byte DO'8E'") {
                        try session.secureMessaging(beforeResponse: index)
                            .unprotect(rapdu: ResponseAPDU(data: shortChecksum, sw1: 0x90, sw2: 0x00))
                    }
                }
                // DO'8E' announced but cut off.
                assertThrows(.MissingMandatoryFields, "\(session.name) exchange \(index) truncated DO'8E'") {
                    try session.secureMessaging(beforeResponse: index)
                        .unprotect(rapdu: ResponseAPDU(data: [UInt8](exchange.protectedResponse.dropLast(3)), sw1: 0x90, sw2: 0x00))
                }
            }
        }
    }

    /// A "9000" answer that carries no protected status word is refused, whatever else it holds.
    func testResponseWithoutStatusObjectIsRefused() {
        let session = bsiSessions[0]
        let unprotected: [[UInt8]] = [
            [],                                         // bare 9000
            [0x30],
            [0x30, 0x82, 0x07, 0xE7],                   // plaintext data in place of the data objects
            [0x60, 0x16, 0x90, 0x00, 0x5F],             // bytes 2-3 read as a status word by the old parser
            [0x99, 0x03, 0x90, 0x00, 0x00, 0x8E, 0x08, 1, 2, 3, 4, 5, 6, 7, 8], // DO'99' of the wrong length
            [0x99, 0x02, 0x90],                         // DO'99' cut off
            [0x99],
            [0x8E, 0x08, 1, 2, 3, 4, 5, 6, 7, 8],       // checksum only
        ]
        for data in unprotected {
            assertThrows(.MissingMandatoryFields, binToHexRep(data)) {
                try session.secureMessaging(beforeResponse: 0).unprotect(rapdu: ResponseAPDU(data: data, sw1: 0x90, sw2: 0x00))
            }
        }
    }

    /// A malformed DO'87' is refused without reading past the end of the response.
    func testMalformedCryptogramObjectIsRefused() {
        let session = bsiSessions[0]
        let malformed: [[UInt8]] = [
            [0x87],
            [0x87, 0x81],
            [0x87, 0x82, 0x01],
            [0x87, 0x83, 0x00, 0x00, 0x11],             // unsupported length form
            [0x87, 0x00],                               // no padding-content indicator
            [0x87, 0x11, 0x01, 0x00],                   // length runs past the end
            [0x87, 0x11, 0x02] + [UInt8](repeating: 0, count: 16), // wrong padding-content indicator
            [0x87, 0x01, 0x01, 0x99, 0x02, 0x90, 0x00, 0x8E, 0x08, 1, 2, 3, 4, 5, 6, 7, 8], // empty cryptogram
            [0x87, 0x06, 0x01, 1, 2, 3, 4, 5, 0x99, 0x02, 0x90, 0x00, 0x8E, 0x08, 1, 2, 3, 4, 5, 6, 7, 8], // not whole blocks
        ]
        for data in malformed {
            assertThrows(.D087Malformed, binToHexRep(data)) {
                try session.secureMessaging(beforeResponse: 0).unprotect(rapdu: ResponseAPDU(data: data, sw1: 0x90, sw2: 0x00))
            }
        }
    }

    /// A status word other than 9000 is not protected. It is passed on as an error, and
    /// none of the bytes that came with it are returned as response data.
    func testUnprotectedErrorStatusCarriesNoData() throws {
        let session = bsiSessions[0]
        let plaintext: [UInt8] = [0x61, 0x5B, 0x5F, 0x1F]
        for (sw1, sw2): (UInt8, UInt8) in [(0x69, 0x88), (0x69, 0x87), (0x6A, 0x00), (0x63, 0x00), (0x62, 0x82), (0x00, 0x00)] {
            let response = try session.secureMessaging(beforeResponse: 0)
                .unprotect(rapdu: ResponseAPDU(data: plaintext, sw1: sw1, sw2: sw2))
            XCTAssertEqual(response.data, [], "status \(binToHexRep([sw1, sw2]))")
            XCTAssertEqual([response.sw1, response.sw2], [sw1, sw2])
        }
    }

    /// A refused response still advances the counter, so the next exchange stays in step.
    func testCounterAdvancesAfterRefusedResponse() throws {
        let session = bsiSessions[0]
        let sm = session.secureMessaging(beforeResponse: 0)
        var tampered = session.exchanges[0].protectedResponse
        tampered[tampered.count - 1] ^= 0x01
        XCTAssertThrowsError(try sm.unprotect(rapdu: ResponseAPDU(data: tampered, sw1: 0x90, sw2: 0x00)))
        _ = try sm.protect(apdu: commandAPDU(session.exchanges[1].plainCommand))
        let response = try sm.unprotect(rapdu: session.exchanges[1].response)
        XCTAssertEqual([response.sw1, response.sw2], [0x90, 0x00])
    }

    // MARK: - ICAO 9303-11 appendix D.4 (3DES)

    private let icaoKSenc = hexRepToBin("979EC13B1CBFE9DCD01AB0FED307EAE5")
    private let icaoKSmac = hexRepToBin("F1CB1F1FB5ADF208806B89DC579DC1F8")

    /// Appendix D.4, READ BINARY of the first four bytes of EF.COM: the response the
    /// appendix lists is accepted, and the same response with a changed checksum,
    /// cryptogram or status object is refused.
    func testICAOAppendixD4Response() throws {
        let ssc = hexRepToBin("887022120C06C229")
        let response = hexRepToBin("8709019FF0EC34F9922651990290008E08AD55CC17140B2DED")
        func secureMessaging() -> SecureMessaging { SecureMessaging(ksenc: icaoKSenc, ksmac: icaoKSmac, ssc: ssc) }

        let unprotected = try secureMessaging().unprotect(rapdu: ResponseAPDU(data: response, sw1: 0x90, sw2: 0x00))
        XCTAssertEqual(binToHexRep(unprotected.data), "60145F01")
        XCTAssertEqual([unprotected.sw1, unprotected.sw2], [0x90, 0x00])

        for position in [3, 10, 14, 17, response.count - 1] {
            var tampered = response
            tampered[position] ^= 0x04
            assertThrows(.InvalidResponseChecksum, "byte \(position)") {
                try secureMessaging().unprotect(rapdu: ResponseAPDU(data: tampered, sw1: 0x90, sw2: 0x00))
            }
        }
        assertThrows(.MissingMandatoryFields) {
            try secureMessaging().unprotect(rapdu: ResponseAPDU(data: [UInt8](response.dropLast(10)), sw1: 0x90, sw2: 0x00))
        }
    }
}
