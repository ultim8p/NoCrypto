import XCTest
@testable import NoCrypto

final class NoCryptoTests: XCTestCase {
    func testExample() throws {
        // This is an example of a functional test case.
        // Use XCTAssert and related functions to verify your tests produce the correct
        // results.
        XCTAssertEqual(NoCrypto().text, "Hello, World!")
    }
}
