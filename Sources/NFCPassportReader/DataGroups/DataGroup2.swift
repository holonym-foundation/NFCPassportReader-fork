//
//  DataGroup2.swift
//
//  Created by Andy Qua on 01/02/2021.
//

import Foundation

#if !os(macOS)
import UIKit
#endif

@available(iOS 13, macOS 10.15, *)
public class DataGroup2 : DataGroup {
    public private(set) var nrImages : Int = 0
    public private(set) var versionNumber : Int = 0
    public private(set) var lengthOfRecord : Int = 0
    public private(set) var numberOfFacialImages : Int = 0
    public private(set) var facialRecordDataLength : Int = 0
    public private(set) var nrFeaturePoints : Int = 0
    public private(set) var gender : Int = 0
    public private(set) var eyeColor : Int = 0
    public private(set) var hairColor : Int = 0
    public private(set) var featureMask : Int = 0
    public private(set) var expression : Int = 0
    public private(set) var poseAngle : Int = 0
    public private(set) var poseAngleUncertainty : Int = 0
    public private(set) var faceImageType : Int = 0
    public private(set) var imageDataType : Int = 0
    public private(set) var imageWidth : Int = 0
    public private(set) var imageHeight : Int = 0
    public private(set) var imageColorSpace : Int = 0
    public private(set) var sourceType : Int = 0
    public private(set) var deviceType : Int = 0
    public private(set) var quality : Int = 0
    public private(set) var imageData : [UInt8] = []

    public override var datagroupType: DataGroupId { .DG2 }

#if !os(macOS)
func getImage() -> UIImage? {
        if imageData.count == 0 {
            return nil
        }
        
        let image = UIImage(data:Data(imageData) )
        return image
    }
#endif

    required init( _ data : [UInt8] ) throws {
        try super.init(data)
    }

    override func parse(_ data: [UInt8]) throws {
        var tag = try getNextTag()
        try verifyTag(tag, equals: 0x7F61)
        _ = try getNextLength()
        
        // Tag should be 0x02
        tag = try getNextTag()
        try verifyTag(tag, equals: 0x02)
        nrImages = try Int(getNextValue()[0])
        
        // Next tag is 0x7F60
        tag = try getNextTag()
        try verifyTag(tag, equals: 0x7F60)
        _ = try getNextLength()
        
        // Next tag is 0xA1 (Biometric Header Template) - don't care about this
        tag = try getNextTag()
        try verifyTag(tag, equals: 0xA1)
        _ = try getNextValue()
        
        // Now we get to the good stuff - next tag is either 5F2E or 7F2E
        tag = try getNextTag()
        try verifyTag(tag, oneOf: [0x5F2E, 0x7F2E])
        let value = try getNextValue()
        
        try parseISO19794_5( data:value )
    }
    
    func parseISO19794_5( data : [UInt8] ) throws {
        // Validate header - 'F', 'A' 'C' 0x00 - 0x46414300
        if data[0] != 0x46 && data[1] != 0x41 && data[2] != 0x43 && data[3] != 0x00 {
            throw NFCPassportReaderError.InvalidResponse(
                dataGroupId: datagroupType,
                expectedTag: 0x46,
                actualTag: Int(data[0])
            )
        }
        
        var offset = 4
        versionNumber = binToInt(data[offset..<offset+4])
        offset += 4
        lengthOfRecord = binToInt(data[offset..<offset+4])
        offset += 4
        numberOfFacialImages = binToInt(data[offset..<offset+2])
        offset += 2
        
        facialRecordDataLength = binToInt(data[offset..<offset+4])
        offset += 4
        nrFeaturePoints = binToInt(data[offset..<offset+2])
        offset += 2
        gender = binToInt(data[offset..<offset+1])
        offset += 1
        eyeColor = binToInt(data[offset..<offset+1])
        offset += 1
        hairColor = binToInt(data[offset..<offset+1])
        offset += 1
        featureMask = binToInt(data[offset..<offset+3])
        offset += 3
        expression = binToInt(data[offset..<offset+2])
        offset += 2
        poseAngle = binToInt(data[offset..<offset+3])
        offset += 3
        poseAngleUncertainty = binToInt(data[offset..<offset+3])
        offset += 3
        
        // Features (not handled). There shouldn't be any but if for some reason there were,
        // then we are going to skip over them
        // The Feature block is 8 bytes
        offset += nrFeaturePoints * 8
        
        faceImageType = binToInt(data[offset..<offset+1])
        offset += 1
        imageDataType = binToInt(data[offset..<offset+1])
        offset += 1
        imageWidth = binToInt(data[offset..<offset+2])
        offset += 2
        imageHeight = binToInt(data[offset..<offset+2])
        offset += 2
        imageColorSpace = binToInt(data[offset..<offset+1])
        offset += 1
        sourceType = binToInt(data[offset..<offset+1])
        offset += 1
        deviceType = binToInt(data[offset..<offset+2])
        offset += 2
        quality = binToInt(data[offset..<offset+2])
        offset += 2
        
        
        // Make sure that the image data at least has a valid header.
        // ICAO 9303 / ISO-IEC 19794-5 DG2 face images are JPEG or JPEG2000.
        //
        // JPEG is identified by the 3-byte SOI + marker prefix (FF D8 FF) —
        // NOT by a full JFIF/APP0 header. Conformant encoders may emit a bare
        // JPEG that begins directly with a quantization-table segment
        // (FF D8 FF DB), or with EXIF/Adobe segments (FF D8 FF E1 / FF D8 FF EE),
        // none of which carry the "JFIF" APP0 marker. Matching the full
        // 10-byte JFIF header rejected those real-world images with
        // UnknownImageFormat. JPEG2000 arrives either as the JP2 box format
        // (00 00 00 0C 6A 50 …) or as a raw codestream (FF 4F FF 51).
        let jpegSOI : [UInt8] = [0xff,0xd8,0xff]
        let jpeg2000BitmapHeader : [UInt8] = [0x00,0x00,0x00,0x0c,0x6a,0x50,0x20,0x20,0x0d,0x0a]
        let jpeg2000CodestreamBitmapHeader : [UInt8] = [0xff,0x4f,0xff,0x51]

        // Capture up to 16 bytes of the image-data region so the
        // caller can identify the actual format (PNG, WSQ, raw, …).
        // These bytes are file-format magic + ISO 19794-5 header —
        // structural metadata, not pixel content.
        let prefixEnd = min(offset + 16, data.count)
        let prefix = offset < data.count ? [UInt8](data[offset..<prefixEnd]) : []

        // Each signature is bounds-checked independently: a record too short
        // to contain a given signature simply does not match it (rather than
        // crashing on an out-of-range slice, which the previous fixed-length
        // guard allowed for lengths between the shortest and longest header).
        func imageHasPrefix(_ signature: [UInt8]) -> Bool {
            guard offset + signature.count <= data.count else { return false }
            return [UInt8](data[offset..<offset+signature.count]) == signature
        }

        if !imageHasPrefix(jpegSOI) &&
            !imageHasPrefix(jpeg2000BitmapHeader) &&
            !imageHasPrefix(jpeg2000CodestreamBitmapHeader) {
            throw NFCPassportReaderError.UnknownImageFormat(rawPrefix: prefix)
        }

        imageData = [UInt8](data[offset...])
    }
}
