// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "argon2-swift",
    platforms: [
        .iOS(.v15),
        .macOS(.v12),
    ],
    products: [
        .library(name: "Argon2", targets: ["Argon2"]),
    ],
    targets: [
        .target(
            name: "Argon2"
        ),
        .testTarget(
            name: "Argon2Tests",
            dependencies: ["Argon2"]
        ),
    ]
)