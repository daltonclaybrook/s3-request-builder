import HTTP
import Vapor

extension Droplet {
    func setupRoutes() throws {
        self.post("/", handler: handleRequest)
    }
    
    // Routes
    
    private func handleRequest(_ request: Request) throws -> ResponseRepresentable {
        guard let formData = request.formData,
            let file = formData["file"],
            let filename = file.filename else {
            throw Abort.badRequest
        }
        
        let accessKeyId = "<AWS access key id>"
        let secretAccessKey = "<AWS secret access key>"
        let bucket = "<s3 bucket>"
        let region = "us-east-1"
        let builder = S3RequestBuilder(accessKeyId: accessKeyId,
                                       secretAccessKey: secretAccessKey,
                                       s3Bucket: bucket,
                                       region: region)
        
        let method = Method.put
        let path = "/files/\(filename)"
        let request = try builder.generateRequest(forMethod: method, path: path, body: file.part.body)
        return try self.client.request(method, request.uri, request.headers, request.body)
    }
}
