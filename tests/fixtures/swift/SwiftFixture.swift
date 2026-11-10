// Small Swift-heavy library used as an open-source stand-in for Apple's Swift frameworks
// (generics, protocol witnesses, Codable, enums with payloads, closures, an actor).
// Built twice by build.sh; FIXTURE_NEW selects the "patched" version.

public protocol Shape {
    var area: Double { get }
    func describe() -> String
}

public struct Circle: Shape, Codable, Hashable {
    public var radius: Double
    public init(radius: Double) { self.radius = radius }
    public var area: Double { Double.pi * radius * radius }
    public func describe() -> String { "circle r=\(radius)" }
}

public struct Rect: Shape, Codable, Hashable {
    public var width: Double
    public var height: Double
    public init(width: Double, height: Double) { self.width = width; self.height = height }
    public var area: Double { width * height }
    public func describe() -> String { "rect \(width)x\(height)" }
}

public enum Token: Codable, Equatable {
    case word(String)
    case number(Int)
    case pair(Int, Int)
    case end
}

public final class Inventory<Item: Hashable & Codable>: Codable {
    public private(set) var items: [Item: Int] = [:]
    public init() {}

    public func add(_ item: Item, count: Int = 1) {
        items[item, default: 0] += count
    }

    public func total(where predicate: (Item) -> Bool) -> Int {
        items.filter { predicate($0.key) }.reduce(0) { $0 + $1.value }
    }
}

public actor Counter {
    private var value = 0
    public init() {}
    public func increment(by step: Int = 1) -> Int {
        value += step
        return value
    }
}

@inline(never)
public func totalArea(_ shapes: [any Shape]) -> Double {
    shapes.map(\.area).reduce(0, +)
}

@inline(never)
public func tokenize(_ text: String) -> [Token] {
    var out: [Token] = []
    for word in text.split(separator: " ") {
        if let n = Int(word) {
            out.append(.number(n))
        } else {
            out.append(.word(String(word)))
        }
    }
    out.append(.end)
    return out
}

// Same-size change: only the scan bound differs (72 -> 36), as in a partition-name length fix.
// ghidriff skips such a pair by size/refcount; the p-code gate should surface it.
@inline(never)
public func scanName(_ bytes: UnsafePointer<UInt8>, _ count: Int) -> Int {
#if FIXTURE_NEW
    let limit = min(count, 36)
#else
    let limit = min(count, 72)
#endif
    var i = 0
    while i < limit {
        if bytes[i] == 0 {
            return i
        }
        i += 1
    }
    return limit
}

// Size change: the new version adds a bounds check before an unchecked load.
@inline(never)
public func readRecord(_ buf: UnsafeRawBufferPointer, at offset: Int) -> UInt32 {
#if FIXTURE_NEW
    guard offset >= 0, offset + 4 <= buf.count else {
        return 0
    }
#endif
    return buf.loadUnaligned(fromByteOffset: offset, as: UInt32.self)
}
