//
//  SecureMessaging.swift
//  NFCTest
//
//  Created by Andy Qua on 09/06/2019.
//  Copyright © 2019 Andy Qua. All rights reserved.
//

import Foundation
import OSLog

public enum SecureMessagingSupportedAlgorithms {
    case DES
    case AES
}

#if !os(macOS)
import CoreNFC


/// This class implements the secure messaging protocol.
/// The class is a new layer that comes between the reader and the iso7816.
/// It gives a new transmit method that takes an APDU object formed by the iso7816 layer,
/// ciphers it following the doc9303 specification, sends the ciphered APDU to the reader
/// layer and returns the unciphered APDU.
@available(iOS 13, *)
public class SecureMessaging {
    private var ksenc : [UInt8]
    private var ksmac : [UInt8]
    private var ssc : [UInt8]
    private let algoName : SecureMessagingSupportedAlgorithms
    private let padLength : Int
        
    public init( encryptionAlgorithm : SecureMessagingSupportedAlgorithms = .DES, ksenc : [UInt8], ksmac : [UInt8], ssc : [UInt8]) {
        self.ksenc = ksenc
        self.ksmac = ksmac
        self.ssc = ssc
        self.algoName = encryptionAlgorithm
        self.padLength = algoName == .DES ? 8 : 16
    }

    /// Protect the apdu following the doc9303 specification
    func protect(apdu : NFCISO7816APDU, useExtendedMode: Bool = false ) throws -> NFCISO7816APDU {
    
        Logger.secureMessaging.debug("\t\tSSC: \(binToHexRep(self.ssc))")
        self.ssc = self.incSSC()
        let paddedSSC = algoName == .DES ? self.ssc : [UInt8](repeating: 0, count: 8) + ssc
        Logger.secureMessaging.debug("\tIncrement SSC with 1")
        Logger.secureMessaging.debug("\t\tSSC: \(binToHexRep(self.ssc))")


        let cmdHeader = self.maskClassAndPad(apdu: apdu)
        var do87 : [UInt8] = []
        var do97 : [UInt8] = []
        
        var tmp = "Concatenate CmdHeader"
        if apdu.data != nil {
            tmp += " and DO87"
            do87 = try self.buildD087(apdu: apdu)
        }
        
        let isMSE = apdu.instructionCode == 0x22
        if apdu.expectedResponseLength > 0 && (isMSE ? apdu.expectedResponseLength < 256 : true) {
            tmp += " and DO97"
            do97 = try self.buildD097(apdu: apdu)
        }
        
        let M = cmdHeader + do87 + do97
        Logger.secureMessaging.debug("\(tmp)")
        Logger.secureMessaging.debug("\tM: \(binToHexRep(M))")
        
        Logger.secureMessaging.debug("Compute MAC of M")
        
        let N = pad(paddedSSC + M, blockSize:padLength)
        Logger.secureMessaging.debug("\tConcatenate SSC and M and add padding")
        Logger.secureMessaging.debug("\t\tN: \(binToHexRep(N))")

        var CC = mac(algoName: algoName, key: self.ksmac, msg: N)
        if CC.count > 8 {
            CC = [UInt8](CC[0..<8])
        }
        Logger.secureMessaging.debug("\tCompute MAC over N with KSmac")
        Logger.secureMessaging.debug("\t\tCC: \(binToHexRep(CC))")
        
        let do8e = self.buildD08E(mac: CC)
        
        // If dataSize > 255 then it will be encoded in 3 bytes with the first byte being 0x00
        // otherwise its a single byte of size
        let size = do87.count + do97.count + do8e.count
        var dataSize: [UInt8]
        if size > 255 || (useExtendedMode && apdu.expectedResponseLength > 231) {
            dataSize = [0x00] + intToBin(size, pad: 4)
        } else {
            dataSize = intToBin(size)
        }
        var protectedAPDU = [UInt8](cmdHeader[0..<4]) + dataSize
        protectedAPDU += do87 + do97 + do8e
            
        // If the data is more that 255, specify the we are using extended length (0x00, 0x00)
        // Thanks to @filom for the fix!
        if size > 255 || (useExtendedMode && apdu.expectedResponseLength > 231) {
            protectedAPDU += [0x00,0x00]
        } else {
            protectedAPDU += [0x00]
        }
        Logger.secureMessaging.debug("Construct and send protected APDU")
        Logger.secureMessaging.debug("\tProtectedAPDU: \(binToHexRep(protectedAPDU))")
        
        let newAPDU = NFCISO7816APDU(data:Data(protectedAPDU))!
        return newAPDU
    }

    /// Unprotect the response APDU (ICAO 9303-11 section 9.8.4).
    ///
    /// A response is returned as successful only when it carries DO'99' and an 8-byte
    /// DO'8E', and the checksum computed over SSC, DO'87' and DO'99' with KSmac equals
    /// DO'8E'. Anything else throws: `InvalidResponseChecksum` for a wrong checksum,
    /// `MissingMandatoryFields` for an absent or malformed DO'99' or DO'8E', and
    /// `D087Malformed` for a malformed DO'87'. Nothing is decrypted before the checksum
    /// has been verified.
    func unprotect(rapdu : ResponseAPDU ) throws -> ResponseAPDU {
        self.ssc = self.incSSC()
        let paddedSSC = algoName == .DES ? self.ssc : [UInt8](repeating: 0, count: 8) + ssc

        // A status word other than 9000 is the chip reporting an error outside secure
        // messaging. It is not authenticated, so pass on the status word only and never
        // the bytes that came with it.
        if rapdu.sw1 != 0x90 || rapdu.sw2 != 0x00 {
            return ResponseAPDU(data: [], sw1: rapdu.sw1, sw2: rapdu.sw2)
        }

        let body = rapdu.data
        var offset = 0

        // DO'87': mandatory if data is returned, otherwise absent.
        var do87 : [UInt8] = []
        var do87Data : [UInt8] = []
        if body.first == 0x87 {
            guard let (length, lengthSize) = SecureMessaging.berLength(body, at: 1) else {
                throw NFCPassportReaderError.D087Malformed
            }
            let valueStart = 1 + lengthSize
            // The value is the padding-content indicator (01) and whole cipher blocks.
            guard length > 1,
                  (length - 1) % padLength == 0,
                  valueStart + length <= body.count,
                  body[valueStart] == 0x01 else {
                throw NFCPassportReaderError.D087Malformed
            }
            do87 = [UInt8](body[0 ..< valueStart + length])
            do87Data = [UInt8](body[valueStart + 1 ..< valueStart + length])
            offset = valueStart + length
        }

        // DO'99': mandatory. It is absent only when the chip reports a secure messaging
        // error, and then the status word is not 9000 (handled above).
        guard body.count >= offset + 4, body[offset] == 0x99, body[offset + 1] == 0x02 else {
            throw NFCPassportReaderError.MissingMandatoryFields
        }
        let do99 = [UInt8](body[offset ..< offset + 4])
        let sw1 = do99[2]
        let sw2 = do99[3]
        offset += 4

        // DO'8E': mandatory, and always 8 bytes.
        guard body.count >= offset + 10, body[offset] == 0x8E, body[offset + 1] == 0x08 else {
            throw NFCPassportReaderError.MissingMandatoryFields
        }
        let CC = [UInt8](body[offset + 2 ..< offset + 10])

        // The checksum is the MAC over the padded SSC || DO'87' || DO'99', truncated to
        // 8 bytes (AES-CMAC is 16 bytes long; the 3DES retail MAC is already 8).
        let K = pad(paddedSSC + do87 + do99, blockSize: padLength)
        let computed = mac(algoName: algoName, key: self.ksmac, msg: K)
        guard computed.count >= 8,
              SecureMessaging.constantTimeEquals([UInt8](computed[0 ..< 8]), CC) else {
            throw NFCPassportReaderError.InvalidResponseChecksum
        }

        var data : [UInt8] = []
        if do87Data.count > 0 {
            let dec : [UInt8]
            if algoName == .DES {
                dec = tripleDESDecrypt(key: self.ksenc, message: do87Data, iv: [0,0,0,0,0,0,0,0])
            } else {
                // for AES the IV is the ssc with AES/EBC/NOPADDING
                let iv = AESECBEncrypt(key: ksenc, message: paddedSSC)
                dec = AESDecrypt(key: self.ksenc, message: do87Data, iv: iv)
            }
            guard dec.count == do87Data.count else {
                throw NFCPassportReaderError.UnableToUnprotectAPDU
            }
            data = try SecureMessaging.removePadding(dec)
        }

        return ResponseAPDU(data: data, sw1: sw1, sw2: sw2)
    }

    /// Removes ISO/IEC 7816-4 padding (80 then zero bytes). Like `unpad`, plaintext that
    /// does not end in padding is returned as it is; unlike `unpad`, plaintext that is
    /// all zero bytes throws instead of reading before the start of the buffer.
    static func removePadding(_ padded : [UInt8]) throws -> [UInt8] {
        guard let last = padded.lastIndex(where: { $0 != 0x00 }) else {
            throw NFCPassportReaderError.UnableToUnprotectAPDU
        }
        return padded[last] == 0x80 ? [UInt8](padded[0 ..< last]) : padded
    }

    /// Reads a BER length at `index`: (length, number of bytes the length field takes).
    /// Nil when the field is cut off or uses a form secure messaging never needs.
    static func berLength(_ bytes : [UInt8], at index : Int) -> (Int, Int)? {
        guard index < bytes.count else { return nil }
        let first = bytes[index]
        if first < 0x80 {
            return (Int(first), 1)
        }
        if first == 0x81, index + 1 < bytes.count {
            return (Int(bytes[index + 1]), 2)
        }
        if first == 0x82, index + 2 < bytes.count {
            return (Int(bytes[index + 1]) << 8 | Int(bytes[index + 2]), 3)
        }
        return nil
    }

    /// Compares two byte strings in time that depends only on their length.
    static func constantTimeEquals(_ a : [UInt8], _ b : [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var difference : UInt8 = 0
        for i in 0 ..< a.count {
            difference |= a[i] ^ b[i]
        }
        return difference == 0
    }

    func maskClassAndPad(apdu : NFCISO7816APDU ) -> [UInt8] {
        Logger.secureMessaging.debug("Mask class byte and pad command header")
        let res = pad([0x0c, apdu.instructionCode, apdu.p1Parameter, apdu.p2Parameter], blockSize: padLength)
        Logger.secureMessaging.debug("\tCmdHeader: \(binToHexRep(res))")
        return res
    }
    
    func buildD087(apdu : NFCISO7816APDU) throws -> [UInt8] {
        let cipher = [0x01] + self.padAndEncryptData(apdu)
        let res = try [0x87] + toAsn1Length(cipher.count) + cipher
        Logger.secureMessaging.debug("Build DO'87")
        Logger.secureMessaging.debug("\tDO87: \(binToHexRep(res))")
        return res
    }
    
    func padAndEncryptData(_ apdu : NFCISO7816APDU) -> [UInt8] {
        // Pad the data, encrypt data with KSenc and build DO'87
        let data = [UInt8](apdu.data!)
        let paddedData = pad( data, blockSize: padLength )
        
        let enc : [UInt8]
        if algoName == .DES {
            enc = tripleDESEncrypt(key: self.ksenc, message: paddedData, iv: [0,0,0,0,0,0,0,0])
        } else {
            // for AES the IV is the ssc with AES/EBC/NOPADDING
            let paddedssc = [UInt8](repeating: 0, count: 8) + ssc
            let iv = AESECBEncrypt(key: ksenc, message: paddedssc)
            enc = AESEncrypt(key: self.ksenc, message: paddedData, iv: iv)
        }
        
        Logger.secureMessaging.debug("Pad data")
        Logger.secureMessaging.debug("\tData: \(binToHexRep(paddedData))")
        Logger.secureMessaging.debug("Encrypt data with KSenc")
        Logger.secureMessaging.debug("\tEncryptedData: \(binToHexRep(enc))")
        return enc
    }
    
    func incSSC() -> [UInt8] {
        let val = binToHex(self.ssc) + 1
        
        // This needs to be fully zero padded - to 8 bytes = i.e. if SSC is 1 it should return [0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x1]
        // NOT [0x1]
        return withUnsafeBytes(of: val.bigEndian, Array.init)
    }
    
    func buildD08E(mac : [UInt8]) -> [UInt8] {
        let res : [UInt8] = [0x8E, UInt8(mac.count)] + mac
        Logger.secureMessaging.debug("Build DO'8E")
        Logger.secureMessaging.debug("\tDO8E: \(binToHexRep(res))" )
        return res
    }

    func buildD097(apdu : NFCISO7816APDU) throws -> [UInt8] {
        let le = apdu.expectedResponseLength
        var binLe = intToBin(le)
        if (le == 256 || le == 65536) {
            binLe = [0x00] + (le > 256 ? [0x00] : [])
        }
        
        let res : [UInt8] = try [0x97] + toAsn1Length(binLe.count) + binLe
        Logger.secureMessaging.debug("Build DO'97")
        Logger.secureMessaging.debug("\tDO97: \(res)")
        return res
    }
    
}
#endif
