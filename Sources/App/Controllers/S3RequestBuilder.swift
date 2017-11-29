//
//  S3RequestBuilder.swift
//  aws-signingPackageDescription
//
//  Created by Dalton Claybrook on 11/28/17.
//

import Crypto
import Foundation
import HTTP
import Vapor

struct S3Request {
    let method: HTTP.Method
    let uri: String
    let headers: [HeaderKey: String]
    let body: BodyRepresentable?
}

fileprivate struct CanonicalRequestInfo {
    let requestString: String
    let signedHeaders: String
}

struct S3RequestBuilder {
    static private let longDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd'T'HHmmss'Z'"
        return formatter
    }()
    static private let shortDateFormatter: DateFormatter = {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyyMMdd"
        return formatter
    }()
    
    private let accessKeyId: String
    private let secretAccessKey: String
    private let s3Bucket: String
    private let region: String
    
    init(accessKeyId: String, secretAccessKey: String, s3Bucket: String, region: String) {
        self.accessKeyId = accessKeyId
        self.secretAccessKey = secretAccessKey
        self.s3Bucket = s3Bucket
        self.region = region
    }
    
    // MARK: Public
    
    func generateRequest(forMethod method: HTTP.Method,
                         path: String,
                         body: Bytes?,
                         headers: [HeaderKey: String] = [:]) throws -> S3Request {
        let date = Date()
        let longDateString = S3RequestBuilder.longDateFormatter.string(from: date)
        let shortDateString = S3RequestBuilder.shortDateFormatter.string(from: date)
        let bytesToHash = body ?? "".makeBytes()
        let contentHash = try Hash.make(.sha256, bytesToHash).hexString
        
        let service = "s3"
        let host = "\(s3Bucket).\(service).amazonaws.com"
        var updatedHeaders = updateHeaders(headers,
                                           withHost: host,
                                           dateString: longDateString,
                                           contentHash: contentHash)
        let canonicalRequestInfo = generateCanonicalRequestInfo(method: method,
                                                        host: host,
                                                        path: path,
                                                        query: "",
                                                        headers: updatedHeaders,
                                                        hashedPayload: contentHash)
        let scope = generateScope(shortDateString: shortDateString,
                                  region: region,
                                  service: service)
        let stringToSign = try generateStringToSign(dateString: longDateString,
                                                    scope: scope,
                                                    canonicalRequestString: canonicalRequestInfo.requestString)
        let signingKey = try generateSigningKey(secretKey: secretAccessKey,
                                                shortDateString: shortDateString,
                                                region: region,
                                                service: service)
        let signature = try generateSignature(signingKey: signingKey,
                                              stringToSign: stringToSign)
        updatedHeaders[.authorization] = generateAuthorizationHeaderString(withAccessKeyId: accessKeyId,
                                                                          scope: scope,
                                                                          signedHeaders: canonicalRequestInfo.signedHeaders,
                                                                          signature: signature)
        
        let uri = "https://\(host)\(path)"
        let responseBody = body.flatMap { Body.data($0) }
        return S3Request(method: method,
                                 uri: uri,
                                 headers: updatedHeaders,
                                 body: responseBody)
    }
    
    // MARK: Private
    
    private func updateHeaders(_ headers: [HeaderKey: String], withHost host: String, dateString: String, contentHash: String) -> [HeaderKey: String] {
        var headers = headers
        headers["X-Amz-Date"] = dateString
        headers["X-Amz-Content-SHA256"] = contentHash
        headers["Host"] = host
        return headers
    }
    
    private func generateCanonicalRequestInfo(method: HTTP.Method,
                                          host: String,
                                          path: String,
                                          query: String,
                                          headers: [HeaderKey: String],
                                          hashedPayload: String) -> CanonicalRequestInfo {
        let sortedHeaderKeys = headers.keys.sorted { $0.description < $1.description }
        let headerString = sortedHeaderKeys.map {
            let value = headers[$0]?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
            let key = $0.description.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
            return key + ":" + value
        }
        .joined(separator: "\n")
        let signedHeadersString = sortedHeaderKeys
            .map { $0.description.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
            .joined(separator: ";")
        let requestString = [
            method.description,
            path.addingPercentEncoding(withAllowedCharacters: .urlPathAllowed)!,
            query.addingPercentEncoding(withAllowedCharacters: .urlQueryAllowed)!,
            headerString,
            "",
            signedHeadersString,
            hashedPayload
        ]
        .joined(separator: "\n")
        return CanonicalRequestInfo(requestString: requestString, signedHeaders: signedHeadersString)
    }
    
    private func generateScope(shortDateString: String, region: String, service: String) -> String {
        return "\(shortDateString)/\(region)/\(service)/aws4_request"
    }
    
    private func generateStringToSign(dateString: String, scope: String, canonicalRequestString: String) throws -> String {
        let hashedRequest = try Hash.make(.sha256, canonicalRequestString.makeBytes()).hexString
        return [
            "AWS4-HMAC-SHA256",
            dateString,
            scope,
            hashedRequest
        ]
        .joined(separator: "\n")
    }
    
    private func generateSigningKey(secretKey: String, shortDateString: String, region: String, service: String) throws -> Bytes {
        let secretKeyBytes = "AWS4\(secretKey)".makeBytes()
        let dateKey = try HMAC.make(.sha256, shortDateString.makeBytes(), key: secretKeyBytes)
        let regionKey = try HMAC.make(.sha256, region.makeBytes(), key: dateKey)
        let serviceKey = try HMAC.make(.sha256, service.makeBytes(), key: regionKey)
        let signingKey = try HMAC.make(.sha256, "aws4_request".makeBytes(), key: serviceKey)
        return signingKey
    }
    
    private func generateSignature(signingKey: Bytes, stringToSign: String) throws -> String {
        return try HMAC.make(.sha256, stringToSign.makeBytes(), key: signingKey).hexString
    }
    
    private func generateAuthorizationHeaderString(withAccessKeyId accessKeyId: String, scope: String, signedHeaders: String, signature: String) -> String {
        return "AWS4-HMAC-SHA256 Credential=\(accessKeyId)/\(scope), SignedHeaders=\(signedHeaders), Signature=\(signature)"
    }
}
