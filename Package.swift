// swift-tools-version:5.5
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "TBKeychain",
    platforms: [
        .macOS(.v11),
        .iOS(.v14),
        .watchOS(.v7)
    ],
    products: [
        // Products define the executables and libraries a package produces, and make them visible to other packages.
        .library(
            name: "TBKeychain",
            targets: ["TBKeychain"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/attaswift/BigInt.git",
            .branch("master")
        )
    ],
    targets: [
        // Targets are the basic building blocks of a package. A target can define a module or a test suite.
        // Targets can depend on other targets in this package, and on products in packages this package depends on.
        .target(
            name: "TBKeychain",
            dependencies: ["BigInt"]),
        .testTarget(
            name: "TBKeychainTests",
            dependencies: ["TBKeychain"]),
    ]
)
