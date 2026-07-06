//  Palette.swift
//  The identity budget is four items on native foundations: one cobalt accent,
//  three semantic state colors, and a voice. No logo system. Colors are the
//  brief's "harbor at dusk" oklch values, converted once to sRGB here so the
//  source of truth stays the brief.
//
//  oklch -> sRGB (D65) conversions, from docs/design/latch-design-brief.html:
//    cobalt   oklch(0.45 0.086 230)  -> rgb(11, 93, 124)   #0B5D7C
//    brass    oklch(0.72 0.11  75)   -> rgb(205, 154, 80)  #CD9A50
//    seagreen oklch(0.56 0.095 165)  -> rgb(50, 134, 102)  #328666
//    rust     oklch(0.53 0.15  25)   -> rgb(178, 64, 61)   #B2403D
//    ink      oklch(0.175 0.014 245) -> rgb(11, 17, 22)    #0B1116

import SwiftUI

extension Color {
    /// Build an sRGB color from 0-255 components (the conversion output above).
    init(srgb r: Double, _ g: Double, _ b: Double) {
        self.init(.sRGB, red: r / 255, green: g / 255, blue: b / 255, opacity: 1)
    }
}

/// The whole palette. State colors carry semantic meaning fixed by the brief;
/// they are never used decoratively.
enum Palette {
    /// App tint / accent. The canonical dusk cobalt.
    static let cobalt = Color(srgb: 11, 93, 124)
    /// A lighter cobalt for text/glyphs on dark grounds, matching the CLI's
    /// on-ink accent (style.rs COBALT). Used only where the deep cobalt would
    /// fail legibility on the ink terminal ground.
    static let cobaltOnDark = Color(srgb: 92, 166, 224)

    /// Pending. The gauge, the brass dial catching the last light.
    static let brass = Color(srgb: 205, 154, 80)
    /// Approved.
    static let seaGreen = Color(srgb: 50, 134, 102)
    /// Denied and lockdown. Oxidized rust.
    static let rust = Color(srgb: 178, 64, 61)

    /// Terminal ground, used behind mono content wells (history, provenance).
    static let ink = Color(srgb: 11, 17, 22)
}

/// The fixed state vocabulary. Every user-facing status maps to exactly one of
/// these; the strings here are the only spellings allowed (brief voice section).
enum StateTone {
    case armed       // solid, requests will route
    case pending     // a decision is waiting
    case approved
    case denied
    case expired
    case lockedDown
    case neutral     // idle / informational
    case warn        // needs attention, not yet failed

    var color: Color {
        switch self {
        case .armed, .approved: return Palette.seaGreen
        case .pending: return Palette.brass
        case .denied, .lockedDown: return Palette.rust
        case .warn: return Palette.brass
        case .neutral, .expired: return Color.secondary
        }
    }

    /// The one-word label, fixed spelling. Never localized away from these.
    var word: String {
        switch self {
        case .armed: return "Armed"
        case .pending: return "Pending"
        case .approved: return "Approved"
        case .denied: return "Denied"
        case .expired: return "Expired"
        case .lockedDown: return "Locked down"
        case .neutral: return "Idle"
        case .warn: return "Attention"
        }
    }
}
