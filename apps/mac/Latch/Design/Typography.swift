//  Typography.swift
//  Two voices. SF Pro for UI (the system default, so nothing to declare), and
//  SF Mono for the content voice: paths, fingerprints, process chains,
//  timestamps, grant keys. Anything technical and tabular is mono.

import SwiftUI

extension Font {
    /// SF Mono at a given size/weight. `.monospaced()` on the system font
    /// resolves to SF Mono on Apple platforms.
    static func mono(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .system(size: size, weight: weight, design: .monospaced)
    }
}

extension View {
    /// Mono content voice with tabular figures so countdowns and columns align.
    func monoContent(_ size: CGFloat = 12, weight: Font.Weight = .regular) -> some View {
        self.font(.mono(size, weight: weight))
            .monospacedDigit()
    }
}

/// A run of SF Mono text, the content voice. Used for every path, fingerprint,
/// process chain, and timestamp so they read as "machine truth" not prose.
struct MonoText: View {
    let text: String
    var size: CGFloat = 12
    var color: Color = .primary
    var weight: Font.Weight = .regular

    init(_ text: String, size: CGFloat = 12, color: Color = .primary, weight: Font.Weight = .regular) {
        self.text = text
        self.size = size
        self.color = color
        self.weight = weight
    }

    var body: some View {
        Text(text)
            .font(.mono(size, weight: weight))
            .monospacedDigit()
            .foregroundStyle(color)
            .textSelection(.enabled)
    }
}
